(babashka.pods/load-pod 'huahaiy/datalevin "0.10.7")

(ns iam-datalevin
  "Datalevin schema for AWS IAM relationship and blast-radius analysis.

  Primary design goal: answer permission relationship questions quickly. Keep
  original AWS Config/IAM documents available for provenance, but normalize the
  relationship edges that explain access:

  - Which principals can assume this role?
  - Which policies are attached to, embedded in, or used as a permissions
    boundary for a role?
  - Which roles are affected by an action/resource/condition?
  - Which AWS Config item last supplied this fact?"
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [pod.huahaiy.datalevin :as d])
  (:import [java.net URLDecoder]
           [java.time Instant LocalDateTime ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.nio.charset StandardCharsets]))

;; Datalevin schema notes:
;;
;; - Use stable identity attributes from AWS whenever possible:
;;   ARN, roleId, policyId, Config resource key, or a deterministic derived key.
;; - Store relationships as refs. This keeps IAM as a traversable graph instead
;;   of a collection of nested JSON blobs.
;; - Store raw JSON-like maps as idocs on snapshot/document entities. That
;;   gives us lossless provenance without forcing every AWS shape into columns.
;; - Policy statements are modeled as first-class entities because statements are
;;   where the meaningful permission edges live.

(def role-transition-actions
  {:assume-role "sts:assumerole"
   :pass-role "iam:passrole"})

(def data-perimeter-condition-keys
  "Condition-key catalog entries that matter first for data perimeter analysis.
  These are source facts about IAM request context keys, not findings."
  [{:condition-key/name "aws:PrincipalAccount"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalArn"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :arn
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalOrgID"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalOrgPaths"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalIsAWSService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :boolean
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalServiceName"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalServiceNamesList"
    :condition-key/category :service-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalTag/tag-key"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:ResourceAccount"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceOrgID"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceOrgPaths"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceTag/tag-key"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:SourceIp"
    :condition-key/category :network-perimeter
    :condition-key/value-type :ip
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpcSourceIp"
    :condition-key/category :network-perimeter
    :condition-key/value-type :ip
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpc"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpcArn"
    :condition-key/category :network-perimeter
    :condition-key/value-type :arn
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpce"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceAccount"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceOrgID"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceOrgPaths"
    :condition-key/category :network-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:CalledVia"
    :condition-key/category :service-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:CalledViaFirst"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:CalledViaLast"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ViaAWSService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :boolean
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:RequestedRegion"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:RequestTag/tag-key"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:TagKeys"
    :condition-key/category :request-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceAccount"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceArn"
    :condition-key/category :request-perimeter
    :condition-key/value-type :arn
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceOrgID"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceOrgPaths"
    :condition-key/category :request-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SecureTransport"
    :condition-key/category :network-perimeter
    :condition-key/value-type :boolean
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}

   {:condition-key/name "iam:PassedToService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:AssociatedResourceArn"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :arn
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:PermissionsBoundary"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :arn
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:ResourceTag/${TagKey}"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? true
    :condition-key/source :iam-service-reference}

   {:condition-key/name "sts:ExternalId"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:RoleSessionName"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:SourceIdentity"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:TransitiveTagKeys"
    :condition-key/category :session-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :sts-service-reference}])

(def schema
  {:entity/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :aws/account-id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :aws/partition
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :aws/region
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :aws/arn
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :aws/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :aws/path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :aws/tags
   {:db/valueType :db.type/idoc
    :db/cardinality :db.cardinality/one}

   ;; AWS Config configuration item snapshots.
   :config/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :config/resource-id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config/resource-name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config/resource-type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :config/capture-time
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :config/status
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config/raw
   {:db/valueType :db.type/idoc
    :db/cardinality :db.cardinality/one}

   :config/describes
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   ;; IAM principals: users, groups, roles, services, accounts, federated ids.
   :principal/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :principal/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :principal/value
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   ;; IAM roles.
   :role/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :role/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/create-date
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :role/max-session-duration
   {:db/valueType :db.type/long
    :db/cardinality :db.cardinality/one}

   :role/last-used-date
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :role/last-used-region
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/trust-policy
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role/attached-policy
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :role/inline-policy
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :role/permissions-boundary
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role/instance-profile
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

    ;; IAM policies.
   :policy/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :policy/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :policy/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :policy/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :policy/document
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :policy/attachment-target
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   ;; Source provenance for CRDT-robust per-file reloads.
   :source/path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :source/imported-at
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   ;; Policy documents and statements.
   :document/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :document/source
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :document/kind
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :document/version
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :document/statement
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :statement/sid
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :statement/effect
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :statement/action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/not-action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/resource
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/not-resource
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/principal
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/not-principal
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/condition
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/source-document
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   ;; Permission atoms.
   :action/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :action/service
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :action/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :action/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :action/expanded-from
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :action/source
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :action/description
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :action/access-level
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :action/resource-type
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :action/condition-key
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :action/dependent-action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :resource/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :resource/arn
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :resource/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :resource/source
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :resource/service
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :resource/config-type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :condition/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :condition/catalog-key
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :condition/operator
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :condition/field
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :condition/value
   {:db/valueType :db.type/idoc
    :db/cardinality :db.cardinality/one}

   :condition/perimeter?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :condition-key/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :condition-key/category
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :condition-key/value-type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :condition-key/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :condition-key/multivalued?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :condition-key/source
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :condition-key/service
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   ;; Role transitions are no longer materialized; trust/pass edges are derived
   ;; from policy documents at query time via role-chain-rules. See
   ;; (def role-chain-rules) below.

   :account/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   ;; Instance profiles.
   :instance-profile/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :instance-profile/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :instance-profile/arn
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   ;; AWS service authorization reference.
   :service/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :service/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/raw
   {:db/valueType :db.type/idoc
    :db/cardinality :db.cardinality/one}

   :service/source-file
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/source-url
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/imported-at
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :service/version
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :service/resource-type
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :service/condition-key
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :service-resource/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :service-resource/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service-resource/service
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :service-resource/arn-format
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/many}

   :service-resource/condition-key
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}})

(def relationship-model
  "Named relationship edges that should stay stable across import iterations."
  {:role-trusts-principal
   {:from :role/id
    :via [:role/trust-policy :document/statement :statement/principal]
    :to :principal/key}

   :role-has-managed-policy
   {:from :role/id
    :via [:role/attached-policy]
    :to :policy/key}

   :role-has-inline-policy
   {:from :role/id
    :via [:role/inline-policy]
    :to :policy/key}

   :role-has-permissions-boundary
   {:from :role/id
    :via [:role/permissions-boundary]
    :to :policy/key}

   ;; The following relationships are derived at query time from policy
   ;; documents (see role-chain-rules) rather than via materialized edges:
   ;;   - principal/role can-assume role  (via target's :role/trust-policy)
   ;;   - principal can-pass-role-to service (via :role/inline-policy /
   ;;     :role/attached-policy with iam:PassRole + iam:PassedToService)

   :policy-allows-action-on-resource
   {:from :policy/key
    :via [:policy/document
          :document/statement
          [:statement/effect :allow]
          :statement/action
          :statement/resource]
    :to [:action/key :resource/key]}

   :config-item-describes-resource
   {:from :config/key
    :via [:config/describes]
    :to [:role/id :policy/key]}})

(def sample-queries
  {:admin-like-role-policy-edges
   '[:find ?role ?policy ?edge
     :where
     (or-join [?role ?policy ?edge]
              (and [?role :role/attached-policy ?policy]
                   [(ground :attached-managed) ?edge])
              (and [?role :role/inline-policy ?policy]
                   [(ground :inline) ?edge]))]

   :admin-like-roles
   '[:find ?role-id ?role-name ?role-arn ?policy-name ?sid
     :where
     [?star-action :action/key "*"]
     [?star-resource :resource/key "*"]
     [?stmt :statement/effect :allow]
     [?stmt :statement/action ?star-action]
     [?stmt :statement/resource ?star-resource]
     [?stmt :statement/sid ?sid]
     [?doc :document/statement ?stmt]
     [?policy :policy/document ?doc]
     [?policy :policy/name ?policy-name]
     (or [?role :role/attached-policy ?policy]
         [?role :role/inline-policy ?policy])
     [?role :role/id ?role-id]
     [?role :role/name ?role-name]
     [?role :aws/arn ?role-arn]]

   :roles-assumable-by-principal
   '[:find ?role-name ?role-arn
     :in $ ?principal-key
     :where
     [?principal :principal/key ?principal-key]
     [?stmt :statement/principal ?principal]
     [?doc :document/statement ?stmt]
     [?role :role/trust-policy ?doc]
     [?role :role/name ?role-name]
     [?role :aws/arn ?role-arn]]

   :role-policy-attachments
   '[:find ?role-name ?policy-name ?edge
     :where
     [?role :role/name ?role-name]
     (or-join [?role ?policy ?edge]
              (and [?role :role/attached-policy ?policy]
                   [(ground :attached-managed) ?edge])
              (and [?role :role/inline-policy ?policy]
                   [(ground :inline) ?edge])
              (and [?role :role/permissions-boundary ?policy]
                   [(ground :permissions-boundary) ?edge]))
     [?policy :policy/name ?policy-name]]

   :roles-allowing-action
   '[:find ?role-name ?policy-name ?resource
     :in $ ?action-key
     :where
     [?action :action/key ?action-key]
     [?stmt :statement/action ?action]
     [?stmt :statement/effect :allow]
     [?stmt :statement/resource ?resource-e]
     [?resource-e :resource/key ?resource]
     [?doc :document/statement ?stmt]
     [?policy :policy/document ?doc]
     [?policy :policy/name ?policy-name]
     (or [?role :role/attached-policy ?policy]
         [?role :role/inline-policy ?policy])
     [?role :role/name ?role-name]]

   :assume-role-transitions
   '[:find ?source-arn ?target-name ?target-arn ?statement-key
     :where
     [?source :role/id _]
     [?source :aws/arn ?source-arn]
     [?target :role/trust-policy ?doc]
     [?target :role/name ?target-name]
     [?target :aws/arn ?target-arn]
     [?doc :document/statement ?statement]
     [?statement :statement/effect :allow]
     [?statement :statement/action ?action]
     [?action :action/key ?action-key]
     [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
     [?statement :statement/principal ?principal]
     [?principal :principal/value ?source-arn]
     [?statement :statement/key ?statement-key]]

   :assume-role-reachability-to-admin-like-role
   '[:find ?source-name ?admin-name
     :in $ % [?admin-id ...]
     :where
     [?admin :role/id ?admin-id]
     (can-assume ?source ?admin)
     [?source :role/name ?source-name]
     [?admin :role/name ?admin-name]]

   :pass-role-delegations
   '[:find ?source-arn ?target-arn ?statement-key
     :where
     [?source :role/id _]
     [?source :aws/arn ?source-arn]
     (or [?source :role/inline-policy ?policy]
         [?source :role/attached-policy ?policy])
     [?policy :policy/document ?doc]
     [?doc :document/statement ?statement]
     [?statement :statement/effect :allow]
     [?statement :statement/action ?action]
     [?action :action/key ?action-key]
     [(contains? #{"iam:passrole" "iam:*" "*"} ?action-key)]
     [?statement :statement/resource ?resource]
     [?resource :resource/arn ?target-arn]
     [?target :aws/arn ?target-arn]
     [?target :role/id _]
     [?statement :statement/key ?statement-key]]

   :role-effective-allow-statements
   '[:find ?policy-name ?sid ?action ?resource ?condition
     :in $ ?role-id
     :where
     [?role :role/id ?role-id]
     (or [?role :role/attached-policy ?policy]
         [?role :role/inline-policy ?policy])
     [?policy :policy/name ?policy-name]
     [?policy :policy/document ?doc]
     [?doc :document/statement ?stmt]
     [?stmt :statement/effect :allow]
     [?stmt :statement/sid ?sid]
     [?stmt :statement/action ?action-e]
     [?action-e :action/key ?action]
     [?stmt :statement/resource ?resource-e]
     [?resource-e :resource/key ?resource]
     (or-join [?stmt ?condition]
              (and [?stmt :statement/condition ?condition-e]
                   [?condition-e :condition/key ?condition])
              (and [(ground :none) ?condition]))]

   :config-provenance-for-role
   '[:find ?config-key ?capture-time ?status
     :in $ ?role-id
     :where
     [?role :role/id ?role-id]
     [?ci :config/describes ?role]
     [?ci :config/key ?config-key]
     [?ci :config/capture-time ?capture-time]
     [?ci :config/status ?status]]

   :statements-with-data-perimeter-conditions
   '[:find ?sid ?field ?operator ?category ?value
     :where
     [?stmt :statement/sid ?sid]
     [?stmt :statement/condition ?condition]
     [?condition :condition/perimeter? true]
     [?condition :condition/field ?field]
     [?condition :condition/operator ?operator]
     [?condition :condition/value ?value]
     [?condition :condition/catalog-key ?catalog-key]
     [?catalog-key :condition-key/category ?category]]})

(def role-chain-rules
  "Datalog rules deriving role-to-role transitions directly from policy
  documents. No materialized :role-transition/* facts are required; queries
  walk :role/trust-policy, :role/inline-policy, :role/attached-policy and the
  statement structure they reference.

  Rules:

  - (trust-edge ?source-role ?target-role ?statement) — ?target-role's trust
    policy names ?source-role (by ARN) as a principal allowed to assume.
  - (pass-edge ?source-role ?target-role ?statement) — ?source-role's identity
    policy allows iam:PassRole for ?target-role. Datalog covers explicit ARN
    matches; wildcard ARN patterns require host-language pattern matching and
    are handled in `pass-role-edges`, not in this rule.
  - (can-assume ?source ?target) — transitive closure over trust-edge."
  '[[(trust-edge ?source-role ?target-role ?statement)
     [?source-role :role/id _]
     [?source-role :aws/arn ?source-arn]
     [?target-role :role/trust-policy ?doc]
     [?doc :document/statement ?statement]
     [?statement :statement/effect :allow]
     [?statement :statement/action ?action]
     [?action :action/key ?action-key]
     [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
     [?statement :statement/principal ?principal]
     [?principal :principal/value ?source-arn]]

    [(pass-edge ?source-role ?target-role ?statement)
     [?source-role :role/id _]
     (or [?source-role :role/inline-policy ?policy]
         [?source-role :role/attached-policy ?policy])
     [?policy :policy/document ?doc]
     [?doc :document/statement ?statement]
     [?statement :statement/effect :allow]
     [?statement :statement/action ?action]
     [?action :action/key ?action-key]
     [(contains? #{"iam:passrole" "iam:*" "*"} ?action-key)]
     [?statement :statement/resource ?resource]
     [?resource :resource/arn ?target-arn]
     [(clojure.string/includes? ?target-arn "*") ?wild?]
     [(not ?wild?)]
     [?target-role :aws/arn ?target-arn]
     [?target-role :role/id _]]

    [(can-assume ?source ?target)
     (trust-edge ?source ?target ?statement)]
    [(can-assume ?source ?target)
     (trust-edge ?source ?middle ?statement)
     (can-assume ?middle ?target)]])

(defn action-key
  "Canonical key for an IAM action or wildcard action pattern."
  [action]
  (str/lower-case action))

(defn resource-key
  "Canonical key for an IAM Resource/NotResource value."
  [resource]
  resource)

(defn condition-key-name
  "IAM condition key names are case-insensitive; preserve source field text on
  :condition/field and use this normalized name for lookup."
  [field]
  (str/lower-case field))

(defn perimeter-condition-key?
  [field]
  (contains? (into #{} (map (comp condition-key-name :condition-key/name))
                   data-perimeter-condition-keys)
             (condition-key-name field)))

(defn principal-key
  "Canonical key for Principal/NotPrincipal values.

  Principal type examples: :aws, :service, :federated, :canonical-user, :star."
  [principal-type principal-value]
  (str (name principal-type) ":" principal-value))

(defn inline-policy-key
  [owner-arn policy-name]
  (str owner-arn "/inline-policy/" policy-name))

(defn trust-policy-key
  [role-arn]
  (str role-arn "/trust-policy"))

(defn config-key
  "Stable key for one AWS Config CI snapshot."
  [{:keys [accountId awsRegion resourceType resourceId configurationStateId]}]
  (str accountId "/" awsRegion "/" resourceType "/" resourceId "/"
       configurationStateId))

(defn parse-json
  [s]
  (json/parse-string s true))

(defn read-json-file
  [path]
  (parse-json (slurp (io/file path))))

(defn parse-jsonl-record
  [file idx line]
  (try
    {:line (inc idx)
     :value (parse-json line)}
    (catch Exception e
      (throw (ex-info "Invalid JSONL line"
                      {:file file :line (inc idx) :text line}
                      e)))))

(defn- url-decode
  [s]
  (URLDecoder/decode s (.name StandardCharsets/UTF_8)))

(defn parse-jsonish
  "Parse AWS CLI JSON values that may already be decoded maps, JSON strings, or
  IAM URL-encoded JSON policy documents."
  [x]
  (cond
    (map? x) x
    (vector? x) x
    (string? x)
    (let [trimmed (str/trim x)]
      (if (or (str/starts-with? trimmed "{")
              (str/starts-with? trimmed "["))
        (parse-json trimmed)
        (try
          (let [decoded (url-decode trimmed)]
            (if (or (str/starts-with? decoded "{")
                    (str/starts-with? decoded "["))
              (parse-json decoded)
              x))
          (catch Exception _ x))))
    :else x))

(def aws-console-date-format
  (DateTimeFormatter/ofPattern "MMMM d, yyyy h:mm:ss a" java.util.Locale/US))

(defn parse-aws-instant
  "Coerce AWS CLI/API date values into java.util.Date for Datalevin instant attrs."
  [x]
  (cond
    (nil? x) nil
    (instance? java.util.Date x) x
    (instance? Instant x) (java.util.Date/from x)
    (string? x) (let [s (str/trim x)]
                  (or
                   (try
                     (java.util.Date/from (Instant/parse s))
                     (catch Exception _ nil))
                   (try
                     (java.util.Date/from
                      (.toInstant (.atZone (LocalDateTime/parse s aws-console-date-format)
                                           ZoneOffset/UTC)))
                     (catch Exception _ nil))))
    :else nil))

(defn ensure-vector
  [x]
  (cond
    (nil? x) []
    (vector? x) x
    (sequential? x) (vec x)
    :else [x]))

(defn first-present
  [m ks]
  (when (map? m)
    (some #(when (contains? m %) (get m %)) ks)))

(def entity-type-marker-attrs
  {:role :role/id
   :policy :policy/key
   :document :document/key
   :statement :statement/key
   :action :action/key
   :resource :resource/key
   :principal :principal/key
   :condition :condition/key
   :condition-key :condition-key/name
   :config-item :config/key
   :service :service/key
   :service-resource :service-resource/key
   :instance-profile :instance-profile/id
   :source :source/path})

(defn entity-type-for-entity
  [entity]
  (when (map? entity)
    (some (fn [[entity-type marker-attr]]
            (when (contains? entity marker-attr)
              entity-type))
          entity-type-marker-attrs)))

(defn inject-entity-type
  [entity]
  (if (and (map? entity) (not (contains? entity :entity/type)))
    (if-let [entity-type (entity-type-for-entity entity)]
      (assoc entity :entity/type entity-type)
      entity)
    entity))

(defn inject-entity-types
  [tx-data]
  (mapv inject-entity-type tx-data))

(defn clean-entity
  [m]
  (inject-entity-type (into {} (remove (comp nil? val) m))))

(defn aws-resource-type
  [resource-type]
  (case resource-type
    "AWS::IAM::Role" :aws.config/iam-role
    "AWS::IAM::Policy" :aws.config/iam-policy
    "AWS::IAM::User" :aws.config/iam-user
    "AWS::IAM::Group" :aws.config/iam-group
    "AWS::KMS::Key" :aws.config/kms-key
    "AWS::Lambda::Function" :aws.config/lambda-function
    "AWS::SQS::Queue" :aws.config/sqs-queue
    "AWS::SecretsManager::Secret" :aws.config/secretsmanager-secret
    "AWS::SNS::Topic" :aws.config/sns-topic
    "AWS::S3::Bucket" :aws.config/s3-bucket
    (keyword "aws.config" (-> resource-type
                              (str/replace #"^AWS::" "")
                              (str/replace #"::" "-")
                              str/lower-case))))

(defn normalize-config-item
  [ci]
  (let [configuration (parse-jsonish (:configuration ci))]
    (assoc ci
           :configuration configuration
           :resourceType (or (:resourceType ci)
                             (:resourceType configuration)))))

(defn aws-config-items
  "Extract AWS Config configuration items from common AWS CLI output shapes:
  get-resource-config-history, batch-get-resource-config, Config rule events,
  select-resource-config Results, a single CI object, or a vector of CI objects."
  [json-value]
  (let [v (parse-jsonish json-value)]
    (cond
      (vector? v)
      (mapcat aws-config-items v)

      (:configurationItems v)
      (map normalize-config-item (:configurationItems v))

      (:baseConfigurationItems v)
      (map normalize-config-item (:baseConfigurationItems v))

      (:configurationItem v)
      [(normalize-config-item (:configurationItem v))]

      (:invokingEvent v)
      (aws-config-items (parse-jsonish (:invokingEvent v)))

      (:Results v)
      (mapcat #(aws-config-items (parse-jsonish %)) (:Results v))

      (and (:resourceType v) (:configuration v))
      [(normalize-config-item v)]

      :else [])))

(defn config-item-entity
  [ci target-ref]
  (clean-entity
   {:config/key (config-key ci)
    :config/resource-id (:resourceId ci)
    :config/resource-name (:resourceName ci)
    :config/resource-type (aws-resource-type (:resourceType ci))
    :config/capture-time (parse-aws-instant (:configurationItemCaptureTime ci))
    :config/status (:configurationItemStatus ci)
    :config/raw ci
    :config/describes target-ref}))

(defn principal-entity
  [principal-type value]
  (clean-entity
   {:principal/key (principal-key principal-type value)
    :principal/type principal-type
    :principal/value value}))

(defn role-entity-from-config
  [ci]
  (let [c (:configuration ci)
        arn (or (:arn c) (:arn ci))
        role-id (or (:roleId c) (:resourceId ci))
        role-name (or (:roleName c) (:resourceName ci))]
    (clean-entity
     {:role/id role-id
      :role/name role-name
      :aws/arn arn
      :aws/account-id (:accountId ci)
      :aws/path (:path c)
      :aws/tags (when-let [tags (:tags c)] {:tags tags})
      :role/create-date (parse-aws-instant (:createDate c))
      :role/last-used-date (parse-aws-instant (get-in c [:roleLastUsed :lastUsedDate]))
      :role/last-used-region (get-in c [:roleLastUsed :region])})))

(defn policy-key-from-config-policy
  [policy]
  (or (:policyArn policy) (:arn policy) (:policyName policy)))

(defn policy-shell
  [policy-key policy-name policy-type]
  (clean-entity
   {:policy/key policy-key
    :policy/name policy-name
    :policy/type policy-type}))

(defn action-entity
  [action]
  (let [k (action-key action)
        [svc name] (if (= "*" action)
                     ["*" "*"]
                     (str/split action #":" 2))]
    (clean-entity
     {:action/key k
      :action/service (some-> svc str/lower-case)
      :action/name name
      :action/pattern? (str/includes? action "*")
      :action/source [:policy]})))

(defn resource-entity
  [resource]
  (clean-entity
   {:resource/key (resource-key resource)
    :resource/arn resource
    :resource/pattern? (str/includes? resource "*")
    :resource/source :policy
    :resource/service (second (re-matches #"arn:[^:]+:([^:]+):.*" resource))}))

(defn condition-key-entity
  [field]
  (let [normalized (condition-key-name field)
        catalog (some #(when (= normalized (condition-key-name (:condition-key/name %))) %)
                      data-perimeter-condition-keys)]
    (clean-entity
     (merge {:condition-key/name normalized
             :condition-key/source [:policy-document]
             :condition-key/pattern? false}
            (when catalog
              (-> catalog
                  (assoc :condition-key/name normalized)
                  (update :condition-key/source #(vec (ensure-vector %)))))))))

(defn condition-entities
  [statement-key condition-map]
  (mapcat
   (fn [[operator fields]]
     (map (fn [[field value]]
            (let [normalized (condition-key-name (name field))]
              (inject-entity-type
               {:condition/key (str statement-key "/condition/" operator "/" normalized)
                :condition/catalog-key [:condition-key/name normalized]
                :condition/operator (name operator)
                :condition/field (name field)
                :condition/value {:value value}
                :condition/perimeter? (perimeter-condition-key? (name field))})))
          fields))
   condition-map))

(defn principal-values
  [principal]
  (cond
    (nil? principal) []
    (= "*" principal) [[:star "*"]]
    (string? principal) [[:aws principal]]
    (map? principal)
    (vec
     (for [[k v] principal
           :let [principal-type (case k
                                  :AWS :aws
                                  :Service :service
                                  :Federated :federated
                                  :CanonicalUser :canonical-user
                                  (keyword (str/lower-case (name k))))]
           value (ensure-vector v)]
       [principal-type value]))
    :else []))

(defn role-arn?
  [value]
  (boolean
   (and (string? value)
        (re-matches #"arn:[^:]+:iam::\d{12}:role/.+" value))))

(defn extract-role-arn
  [resource]
  (when (role-arn? resource)
    resource))

(defn role-stub-entity
  [role-arn]
  (when (role-arn? role-arn)
    {:aws/arn role-arn}))

(defn wildcard-matches?
  [pattern value]
  (let [regex (->> pattern
                   (map #(if (= \* %)
                           ".*"
                           (java.util.regex.Pattern/quote (str %))))
                   (apply str)
                   re-pattern)]
    (boolean (re-matches regex value))))

(defn action-pattern-matches?
  [pattern action]
  (let [pattern-key (action-key pattern)]
    (or (= pattern-key action)
        (and (str/includes? pattern-key "*")
             (wildcard-matches? pattern-key action)))))

(defn statement-allows-action?
  [statement action]
  (and (= :allow (some-> (:Effect statement) str/lower-case keyword))
       (not (contains? statement :NotAction))
       (some #(action-pattern-matches? % action)
             (map str (ensure-vector (first-present statement [:Action]))))))

(defn condition-refs-for-statement
  [statement-key statement]
  (mapv #(vector :condition/key (:condition/key %))
        (condition-entities statement-key (:Condition statement))))

(defn- canonicalize-statement
  "Recursively canonicalize a statement map for content hashing: maps become
  sorted-by-key, sequences become sorted-by-stringification (so order-insignificant
  fields like Action/Resource/Principal lists hash the same regardless of input order)."
  [v]
  (cond
    (map? v)        (into (sorted-map)
                          (map (fn [[k x]] [(name (if (keyword? k) k (str k)))
                                            (canonicalize-statement x)]))
                          v)
    (sequential? v) (vec (sort-by pr-str (map canonicalize-statement v)))
    (keyword? v)    (name v)
    (string? v)     v
    :else           v))

(defn- sha-256-hex
  [^String s]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")
        b  (.digest md (.getBytes s "UTF-8"))
        sb (StringBuilder.)]
    (doseq [^byte x b]
      (.append sb (format "%02x" (bit-and x 0xff))))
    (.toString sb)))

(defn statement-content-hash
  "Stable 16-hex-char content fingerprint for an IAM statement map."
  [statement]
  (-> statement canonicalize-statement pr-str sha-256-hex (subs 0 16)))

(defn statement-tx
  [document-key idx statement]
  (let [content-hash (statement-content-hash statement)
        sid (or (:Sid statement) (str "Statement" idx))
        statement-key (str "stmt-" content-hash)
        actions (map str (ensure-vector (first-present statement [:Action])))
        not-actions (map str (ensure-vector (first-present statement [:NotAction])))
        resources (map str (ensure-vector (or (first-present statement [:Resource]) "*")))
        not-resources (map str (ensure-vector (first-present statement [:NotResource])))
        principals (principal-values (:Principal statement))
        not-principals (principal-values (:NotPrincipal statement))
        conditions (vec (condition-entities statement-key (:Condition statement)))]
    {:phase-1 (concat
               (map action-entity (concat actions not-actions))
               (map resource-entity (concat resources not-resources))
               (map (fn [[principal-type value]]
                      (principal-entity principal-type value))
                    (concat principals not-principals))
               (map condition-key-entity (map :condition/field conditions)))
     :phase-2 conditions
     :phase-3 [(clean-entity
                {:statement/key statement-key
                 :statement/sid sid
                 :statement/effect (some-> (:Effect statement) str/lower-case keyword)
                 :statement/action (mapv #(vector :action/key (action-key %)) actions)
                 :statement/not-action (mapv #(vector :action/key (action-key %)) not-actions)
                 :statement/resource (mapv #(vector :resource/key (resource-key %)) resources)
                 :statement/not-resource (mapv #(vector :resource/key (resource-key %)) not-resources)
                 :statement/principal (mapv #(vector :principal/key (apply principal-key %)) principals)
                 :statement/not-principal (mapv #(vector :principal/key (apply principal-key %)) not-principals)
                 :statement/condition (mapv #(vector :condition/key (:condition/key %)) conditions)})]}))

(declare merge-phases)

(defn policy-document-tx
  [document-key document-kind raw-document]
  (let [parsed     (parse-jsonish raw-document)
        document   (if (map? parsed) parsed {})
        statements (mapv (fn [idx statement]
                           (statement-tx document-key idx statement))
                         (range)
                         (ensure-vector (:Statement document)))]
    [(into [] (mapcat :phase-1) statements)
     (into [] (mapcat :phase-2) statements)
     (into [] (mapcat :phase-3) statements)
     [(clean-entity
       {:document/key document-key
        :document/kind document-kind
        :document/version (:Version document)
        :document/statement (into []
                                  (comp (mapcat :phase-3)
                                        (map #(vector :statement/key (:statement/key %))))
                                  statements)})]]))

(defn role-config-tx-phases
  [ci]
  (let [c (:configuration ci)
        role (role-entity-from-config ci)
        role-id (:role/id role)
        role-arn (:aws/arn role)
        trust-doc (:assumeRolePolicyDocument c)
        trust-key (trust-policy-key role-arn)
        attached (ensure-vector (:attachedManagedPolicies c))
        inline (ensure-vector (:rolePolicyList c))
        boundary (:permissionsBoundary c)
        attached-policy-refs (mapv #(vector :policy/key (policy-key-from-config-policy %)) attached)
        inline-policy-refs (mapv #(vector :policy/key (inline-policy-key role-arn (:policyName %))) inline)
        boundary-ref (when-let [arn (:permissionsBoundaryArn boundary)]
                       [:policy/key arn])
        inline-doc-phases (mapv (fn [p]
                                  (policy-document-tx
                                   (str (inline-policy-key role-arn (:policyName p)) "/document")
                                   :inline-policy
                                   (:policyDocument p)))
                                inline)
        inline-policy-final-entities
        (mapv (fn [p]
                (let [pkey (inline-policy-key role-arn (:policyName p))]
                  {:policy/key pkey
                   :policy/document [:document/key (str pkey "/document")]}))
              inline)
        trust-phases (when trust-doc
                       (policy-document-tx trust-key :trust-policy trust-doc))]
    (apply merge-phases
           [(vec (concat
                  [role
                   (principal-entity :aws role-arn)]
                  (map #(policy-shell (policy-key-from-config-policy %)
                                      (:policyName %)
                                      :managed)
                       attached)
                  (map #(policy-shell (inline-policy-key role-arn (:policyName %))
                                      (:policyName %)
                                      :inline)
                       inline)
                  (when boundary-ref
                    [(policy-shell (second boundary-ref)
                                   (:permissionsBoundaryArn boundary)
                                   :permissions-boundary)])))
            []
            []
            []
            (vec (concat
                  [(clean-entity
                    {:role/id role-id
                     :role/attached-policy attached-policy-refs
                     :role/inline-policy inline-policy-refs
                     :role/permissions-boundary boundary-ref
                     :role/trust-policy (when trust-doc [:document/key trust-key])})
                   (config-item-entity ci [:role/id role-id])]
                  inline-policy-final-entities))]
           (concat
            (when trust-phases [trust-phases])
            inline-doc-phases))))

(defn managed-policy-config-tx-phases
  [ci]
  (let [c (:configuration ci)
        pkey (or (:arn c) (:arn ci))
        versions (ensure-vector (:policyVersionList c))
        default-version (or (some #(when (:isDefaultVersion %) %) versions)
                            (first versions))
        doc-key (str pkey "/document")
        doc (or (first (:document default-version)) (:document default-version))
        doc-phases (policy-document-tx doc-key :managed-policy doc)]
    [(vec [(policy-shell pkey (:policyName c) :managed)])
     (nth doc-phases 0)
     (nth doc-phases 1)
     (nth doc-phases 2)
     (nth doc-phases 3)
     [(clean-entity
       {:policy/key pkey
        :policy/id (:policyId c)
        :policy/name (:policyName c)
        :policy/type :managed
        :policy/document [:document/key doc-key]})
      (config-item-entity ci [:policy/key pkey])]]))

(defn config-item-tx-phases
  [ci]
  (case (:resourceType ci)
    "AWS::IAM::Role" (role-config-tx-phases ci)
    "AWS::IAM::Policy" (managed-policy-config-tx-phases ci)
    [[] [] [] [] [] [(config-item-entity ci nil)]]))

(defn merge-phases
  [& phase-colls]
  (let [n (apply max 0 (map count phase-colls))]
    (mapv (fn [idx] (vec (mapcat #(nth % idx []) phase-colls)))
          (range n))))

(defn config-json-tx-phases
  [json-value]
  (apply merge-phases (mapv config-item-tx-phases (aws-config-items json-value))))

(defn iam-policy-json->tx-phases
  "Build tx phases from common IAM AWS CLI outputs. Options:
  :policy-arn, :policy-name, :policy-type, :version-id, :default?."
  [json-value opts]
  (let [v (parse-jsonish json-value)
        policy-version (or (:PolicyVersion v) (:policyVersion v) (:policy-version v))
        policy (or (:Policy v) (:policy v))
        role (or (:Role v) (:role v))
        document (or (:Document policy-version)
                     (:document policy-version)
                     (:PolicyDocument v)
                     (:policyDocument v)
                     (:Document v)
                     (:document v)
                     (:AssumeRolePolicyDocument role)
                     (:assumeRolePolicyDocument role)
                     (when (:Statement v) v))
        policy-arn (or (:policy-arn opts) (:policyArn opts) (:PolicyArn opts)
                       (:policyArn v) (:PolicyArn v) (:Arn policy) (:arn policy) (:Arn role) (:arn role))
        policy-name (or (:policy-name opts) (:policyName opts) (:PolicyName opts)
                        (:policyName v) (:PolicyName v) (:PolicyName policy) (:policyName policy)
                        (:RoleName role) (:roleName role) policy-arn)
        policy-type (or (:policy-type opts) (if role :trust-policy :managed))
        pkey (if role
               (trust-policy-key (or (:Arn role) (:arn role)))
               policy-arn)
        doc-key (str pkey "/document")
        doc-phases (policy-document-tx doc-key policy-type document)]
    (when-not pkey
      (throw (ex-info "IAM policy import requires :policy-arn or a JSON file containing Policy.Arn or Role.Arn"
                      {:opts opts})))
    (merge-phases
     [[(policy-shell pkey policy-name policy-type)]
      []
      []
      []
      [{:policy/key pkey
        :policy/name policy-name
        :policy/type policy-type
        :policy/document [:document/key doc-key]}]]
     doc-phases)))

(defn service-key
  [service-reference]
  (str/lower-case (:Name service-reference)))

(defn service-resource-key
  [service-prefix resource-name]
  (str (str/lower-case service-prefix) ":" (str/lower-case resource-name)))

(defn service-action-key
  [service-prefix action-name]
  (action-key (str service-prefix ":" action-name)))

(defn service-condition-key
  [condition-name]
  (condition-key-name condition-name))

(defn service-reference-value-type
  [type-name]
  (case type-name
    "ARN" :arn
    "ArrayOfARN" :array-of-arn
    "ArrayOfString" :array-of-string
    "ArrayOfLong" :array-of-long
    "ArrayOfInteger" :array-of-integer
    "ArrayOfBoolean" :array-of-boolean
    "Bool" :boolean
    "Boolean" :boolean
    "Date" :date
    "IPAddress" :ip
    "String" :string
    (some-> type-name
            str
            (str/replace #"([a-z])([A-Z])" "$1-$2")
            str/lower-case
            keyword)))

(defn service-reference-access-level
  [action]
  (let [props (get-in action [:Annotations :Properties])]
    (cond
      (:IsPermissionManagement props) :permissions-management
      (:IsTaggingOnly props) :tagging
      (:IsList props) :list
      (:IsWrite props) :write
      (:IsRead props) :read
      :else nil)))

(defn supported-by?
  [action label]
  (get-in action [:SupportedBy label]))

(defn service-condition-entity
  [service-prefix condition]
  (let [condition-name (:Name condition)]
    (clean-entity
     {:condition-key/name (service-condition-key condition-name)
      :condition-key/value-type (some-> (first (:Types condition)) service-reference-value-type)
      :condition-key/source [:service-reference]
      :condition-key/pattern? (str/includes? condition-name "$")
      :condition-key/service [[:service/key service-prefix]]})))

(defn service-resource-entity
  [service-prefix resource]
  (let [resource-name (:Name resource)]
    (clean-entity
     {:service-resource/key (service-resource-key service-prefix resource-name)
      :service-resource/name resource-name
      :service-resource/service [:service/key service-prefix]
      :service-resource/arn-format (vec (ensure-vector (:ARNFormats resource)))})))

(defn service-resource-relationship-entity
  [service-prefix resource]
  (let [resource-name (:Name resource)]
    (clean-entity
     {:service-resource/key (service-resource-key service-prefix resource-name)
      :service-resource/condition-key (mapv #(vector :condition-key/name (service-condition-key %))
                                            (ensure-vector (:ConditionKeys resource)))})))

(defn service-action-entity
  [service-prefix action]
  (let [action-name (:Name action)]
    (clean-entity
     {:action/key (service-action-key service-prefix action-name)
      :action/service service-prefix
      :action/name action-name
      :action/description (:Description action)
      :action/access-level (service-reference-access-level action)
      :action/pattern? false
      :action/source [:service-reference]})))

(defn service-dependent-action-entity
  [dependent-action]
  (clean-entity
   {:action/key (action-key dependent-action)
    :action/source [:service-reference]}))

(defn service-action-relationship-entity
  [service-prefix action]
  (let [action-name (:Name action)]
    (clean-entity
     {:action/key (service-action-key service-prefix action-name)
      :action/resource-type (mapv #(vector :service-resource/key
                                           (service-resource-key service-prefix (:Name %)))
                                  (ensure-vector (:Resources action)))
      :action/condition-key (mapv #(vector :condition-key/name (service-condition-key %))
                                  (ensure-vector (:ActionConditionKeys action)))
      :action/dependent-action (mapv #(vector :action/key (action-key %))
                                     (ensure-vector (:DependentActions action)))})))

(defn service-reference-json->tx-phases
  "Build tx phases for the current AWS service authorization reference JSON."
  [json-value opts]
  (let [v (parse-jsonish json-value)
        service-prefix (service-key v)
        actions (ensure-vector (:Actions v))
        resources (ensure-vector (or (:ResourceTypes v) (:Resources v)))
        conditions (ensure-vector (:ConditionKeys v))
        action-condition-names (set (mapcat #(ensure-vector (:ActionConditionKeys %)) actions))
        resource-condition-names (set (mapcat #(ensure-vector (:ConditionKeys %)) resources))
        dependent-action-names (set (mapcat #(ensure-vector (:DependentActions %)) actions))
        ;; Some upstream service-reference files omit resources that their
        ;; own actions reference (e.g. verifiedpermissions:policy-store-alias).
        ;; Auto-vivify a stub resource entity for every action-referenced name
        ;; so phase-2 lookup-refs always resolve.
        declared-resource-names (set (map :Name resources))
        action-referenced-resource-names
        (set (->> actions
                  (mapcat #(ensure-vector (:Resources %)))
                  (map :Name)
                  (remove nil?)))
        undeclared-resources
        (mapv (fn [rname] {:Name rname})
              (sort (remove declared-resource-names action-referenced-resource-names)))
        all-resources (vec (concat resources undeclared-resources))
        known-condition-names (set (map (comp service-condition-key :Name) conditions))
        referenced-condition-entities
        (mapv (fn [condition-name]
                (clean-entity
                 {:condition-key/name (service-condition-key condition-name)
                  :condition-key/source [:service-reference]
                  :condition-key/pattern? (str/includes? condition-name "$")
                  :condition-key/service [[:service/key service-prefix]]}))
              (sort (remove #(contains? known-condition-names (service-condition-key %))
                            (concat action-condition-names resource-condition-names))))
        service-entity
        (clean-entity
         {:service/key service-prefix
          :service/name (:Name v)
          :service/version (:Version v)
          :service/raw v
          :service/source-file (:source-file opts)
          :service/source-url (:source-url opts)
          :service/imported-at (parse-aws-instant (:imported-at opts))})
        service-relationship-entity
        (clean-entity
         {:service/key service-prefix
          :service/action (mapv #(vector :action/key (service-action-key service-prefix (:Name %))) actions)
          :service/resource-type (mapv #(vector :service-resource/key
                                                (service-resource-key service-prefix (:Name %)))
                                       all-resources)
          :service/condition-key (mapv #(vector :condition-key/name (service-condition-key (:Name %)))
                                       conditions)})]
    [[service-entity]
     (vec (concat
           (map #(service-condition-entity service-prefix %) conditions)
           referenced-condition-entities
           (map #(service-action-entity service-prefix %) actions)
           (map service-dependent-action-entity dependent-action-names)
           (map #(service-resource-entity service-prefix %) all-resources)))
     (vec (concat
           [service-relationship-entity]
           (map #(service-action-relationship-entity service-prefix %) actions)
           (map #(service-resource-relationship-entity service-prefix %) all-resources)))]))

(defn transact-phases!
  "Transact `phases` sequentially. Within a single source file the catalog
  phases (e.g. action/resource/condition-key entities) must commit before
  relationship phases reference them as top-level lookup-ref values:
  Datalevin only resolves a top-level lookup-ref to an already-committed
  datom or to an upsert peer reachable via a nested map within the same
  entity map. Each phase is one `d/transact!` call. Returns aggregate
  counters for the whole batch."
  [conn phases]
  (let [reports (mapv (fn [phase]
                        (when (seq phase)
                          (d/transact! conn (inject-entity-types phase))))
                      phases)]
    {:phase-count (count phases)
     :entities (reduce + 0 (map count phases))
     :datoms (reduce + 0 (map #(count (:tx-data %)) (remove nil? reports)))}))

(defn get-conn
  [db-path]
  (d/get-conn db-path schema))

(defn- attach-document-source
  "Walk tx phases and attach :document/source [:source/path source-path] to
  every document entity. Pure decoration; tx builders stay source-agnostic."
  [phases source-path]
  (if-not source-path
    phases
    (mapv (fn [phase]
            (mapv (fn [e]
                    (if (and (map? e) (:document/key e))
                      (assoc e :document/source [:source/path source-path])
                      e))
                  phase))
          phases)))

(defn- with-source-entity-phase
  "Prepend a source entity (so the lookup-ref [:source/path P] resolves) to the
  first non-empty phase of `phases`. No-op if `source-path` is nil."
  [phases source-path imported-at]
  (if-not source-path
    phases
    (let [src (clean-entity
               {:source/path source-path
                :source/imported-at (or imported-at (java.util.Date.))})
          phases (vec phases)]
      (if (empty? phases)
        [[src]]
        (assoc phases 0 (vec (cons src (nth phases 0))))))))

(defn- decorate-phases
  [phases {:keys [source-file imported-at]}]
  (-> phases
      (attach-document-source source-file)
      (with-source-entity-phase source-file imported-at)))

(defn reload-source!
  "Retract every document previously imported from `source-path` (and its
  source entity). Idempotent and safe when the source has never been seen."
  [conn source-path]
  (when source-path
    (let [db (d/db conn)
          owned-docs (d/q '[:find [?d ...]
                            :in $ ?p
                            :where
                            [?s :source/path ?p]
                            [?d :document/source ?s]]
                          db source-path)
          source-eid (d/q '[:find ?s .
                            :in $ ?p
                            :where [?s :source/path ?p]]
                          db source-path)
          retractions (cond-> (mapv #(vector :db/retractEntity %) owned-docs)
                        source-eid (conj [:db/retractEntity source-eid]))]
      (when (seq retractions)
        (d/transact! conn retractions))
      {:retracted-documents (count owned-docs)
       :retracted-source (boolean source-eid)})))

(defn- maybe-reload-source!
  "Retract previously-imported docs for `:source-file` when `:reload?` is set.\n  Bulk loaders leave `:reload?` falsy so re-runs are pure upsert."
  [conn {:keys [reload? source-file]}]
  (when (and reload? source-file)
    (reload-source! conn source-file)))

(defn load-config-json!
  "Upsert all entities derived from a single AWS Config JSON document.
  Map-form entities + `:db.unique/identity` make this idempotent: re-loading
  unchanged content writes zero new datoms. Pass `:reload? true` to first
  retract every document previously imported from `:source-file` (used by
  the single-file CLI entry points; bulk loaders default to upsert-only)."
  ([conn json-value] (load-config-json! conn json-value nil))
  ([conn json-value opts]
   (maybe-reload-source! conn opts)
   (transact-phases! conn (decorate-phases (config-json-tx-phases json-value) opts))))

(defn load-iam-policy-json!
  "Upsert IAM policy/policy-version JSON. See `load-config-json!` for the
  `:reload?` semantics."
  [conn json-value opts]
  (maybe-reload-source! conn opts)
  (transact-phases! conn (decorate-phases (iam-policy-json->tx-phases json-value opts) opts)))

(defn load-service-reference-json!
  "Upsert AWS service-authorization-reference JSON. See `load-config-json!`
  for the `:reload?` semantics."
  [conn json-value opts]
  (maybe-reload-source! conn opts)
  (transact-phases! conn (decorate-phases (service-reference-json->tx-phases json-value opts) opts)))

(defn close-conn!
  [conn]
  (d/close conn))

;; Read API

(def stats-entity-markers
  {:roles :role/id
   :policies :policy/key
   :documents :document/key
   :statements :statement/key
   :actions :action/key
   :resources :resource/key
   :principals :principal/key
   :conditions :condition/key
   :condition-keys :condition-key/name
   :config-items :config/key
   :services :service/key
   :service-resources :service-resource/key
   :instance-profiles :instance-profile/id
   :sources :source/path})

(defn- stats-value
  [value]
  (cond
    (keyword? value) (str value)
    (nil? value) nil
    :else (str value)))

(defn- stats-rows
  [db query & args]
  (apply d/q query db args))

(defn- stats-result-count
  [db query & args]
  (count (apply stats-rows db query args)))

(defn- stats-scalar
  [db query & args]
  (or (ffirst (apply stats-rows db query args)) 0))

(defn- attr-entity-count
  [db attr]
  (stats-result-count db '[:find ?entity
                           :in $ ?attr
                           :where [?entity ?attr _]]
                      attr))

(defn- attr-datom-count
  [db attr]
  (stats-scalar db '[:find (count ?entity)
                     :in $ ?attr
                     :where [?entity ?attr ?value]]
                attr))

(defn- attr-distinct-value-count
  [db attr]
  (stats-result-count db '[:find ?value
                           :in $ ?attr
                           :where [_ ?attr ?value]]
                      attr))

(defn- attr-group-counts
  [db attr]
  (->> (stats-rows db '[:find ?value (count ?entity)
                        :in $ ?attr
                        :where [?entity ?attr ?value]]
                   attr)
       (map (fn [[value count]] {:value (stats-value value) :count count}))
       (sort-by (juxt (comp - :count) :value))
       vec))

(defn- top-counts
  [db query n]
  (->> (stats-rows db query)
       (map (fn [[value count]] {:value (stats-value value) :count count}))
       (sort-by (juxt (comp - :count) :value))
       (take n)
       vec))

(defn- datom-summary
  [db]
  (let [{:keys [datoms entities max-eid]}
        (reduce (fn [{:keys [datoms entities max-eid]} [entity-id _ _]]
                  {:datoms (inc datoms)
                   :entities (conj entities entity-id)
                   :max-eid (max max-eid entity-id)})
                {:datoms 0 :entities #{} :max-eid 0}
                (d/datoms db :eav))]
    {:datoms datoms
     :entities (count entities)
     :max-eid max-eid}))

(defn db-file-stats
  [db-path]
  (let [files (if (fs/exists? db-path)
                (->> (fs/glob db-path "**")
                     (filter fs/regular-file?)
                     vec)
                [])
        bytes (reduce + 0 (map fs/size files))]
    {:path (str db-path)
     :files (count files)
     :bytes bytes
     :mib (double (/ bytes 1048576))}))

(defn db-stats
  "Return a compact reporting summary for an IAM Datalevin graph. Marker counts
  work for existing databases; :entity/type counts appear after a reload with
  the typed schema."
  [db]
  {:database (datom-summary db)
   :schema {:attrs (count schema)}
   :entities {:by-type (attr-group-counts db :entity/type)
              :markers (into {}
                             (map (fn [[label attr]]
                                    [label (attr-entity-count db attr)]))
                             stats-entity-markers)}
   :config {:resource-type (attr-group-counts db :config/resource-type)
            :status (attr-group-counts db :config/status)}
   :roles {:accounts (attr-distinct-value-count db :aws/account-id)
           :top-accounts (top-counts db '[:find ?account-id (count ?role)
                                          :where
                                          [?role :role/id _]
                                          [?role :aws/account-id ?account-id]]
                                     10)
           :with-trust-policy (stats-result-count db '[:find ?role
                                                       :where [?role :role/trust-policy _]])
           :with-attached-policy (stats-result-count db '[:find ?role
                                                          :where [?role :role/attached-policy _]])
           :with-inline-policy (stats-result-count db '[:find ?role
                                                        :where [?role :role/inline-policy _]])
           :with-permissions-boundary (stats-result-count db '[:find ?role
                                                               :where [?role :role/permissions-boundary _]])
           :with-tags (stats-result-count db '[:find ?role
                                               :where
                                               [?role :role/id _]
                                               [?role :aws/tags _]])
           :with-last-used-date (stats-result-count db '[:find ?role
                                                         :where
                                                         [?role :role/id _]
                                                         [?role :role/last-used-date _]])
           :attached-policy-links (attr-datom-count db :role/attached-policy)
           :inline-policy-links (attr-datom-count db :role/inline-policy)
           :permissions-boundary-links (attr-datom-count db :role/permissions-boundary)}
   :policies {:by-type (attr-group-counts db :policy/type)
              :with-document (stats-result-count db '[:find ?policy
                                                      :where
                                                      [?policy :policy/key _]
                                                      [?policy :policy/document _]])
              :managed-attached-to-roles (stats-result-count db '[:find ?policy
                                                                  :where [?role :role/attached-policy ?policy]])
              :inline-linked-to-roles (stats-result-count db '[:find ?policy
                                                               :where [?role :role/inline-policy ?policy]])}
   :documents {:by-kind (attr-group-counts db :document/kind)
               :by-version (attr-group-counts db :document/version)}
   :statements {:by-effect (attr-group-counts db :statement/effect)
                :with-action (stats-result-count db '[:find ?statement
                                                      :where [?statement :statement/action _]])
                :with-not-action (stats-result-count db '[:find ?statement
                                                          :where [?statement :statement/not-action _]])
                :with-resource (stats-result-count db '[:find ?statement
                                                        :where [?statement :statement/resource _]])
                :with-not-resource (stats-result-count db '[:find ?statement
                                                            :where [?statement :statement/not-resource _]])
                :with-principal (stats-result-count db '[:find ?statement
                                                         :where [?statement :statement/principal _]])
                :with-not-principal (stats-result-count db '[:find ?statement
                                                             :where [?statement :statement/not-principal _]])
                :with-condition (stats-result-count db '[:find ?statement
                                                         :where [?statement :statement/condition _]])
                :wildcard-action (stats-result-count db '[:find ?statement
                                                          :where
                                                          [?statement :statement/action ?action]
                                                          [?action :action/key "*"]])
                :wildcard-resource (stats-result-count db '[:find ?statement
                                                            :where
                                                            [?statement :statement/resource ?resource]
                                                            [?resource :resource/key "*"]])
                :action-refs (attr-datom-count db :statement/action)
                :not-action-refs (attr-datom-count db :statement/not-action)
                :resource-refs (attr-datom-count db :statement/resource)
                :not-resource-refs (attr-datom-count db :statement/not-resource)
                :principal-refs (attr-datom-count db :statement/principal)
                :not-principal-refs (attr-datom-count db :statement/not-principal)
                :condition-refs (attr-datom-count db :statement/condition)}
   :actions {:by-access-level (attr-group-counts db :action/access-level)
             :by-source (attr-group-counts db :action/source)
             :pattern-actions (stats-result-count db '[:find ?action
                                                       :where
                                                       [?action :action/key _]
                                                       [?action :action/pattern? true]])
             :with-resource-types (stats-result-count db '[:find ?action
                                                           :where [?action :action/resource-type _]])
             :with-condition-keys (stats-result-count db '[:find ?action
                                                           :where [?action :action/condition-key _]])
             :with-dependent-actions (stats-result-count db '[:find ?action
                                                              :where [?action :action/dependent-action _]])
             :top-services (top-counts db '[:find ?service (count ?action)
                                            :where [?action :action/service ?service]]
                                       15)}
   :resources {:by-source (attr-group-counts db :resource/source)
               :pattern-resources (stats-result-count db '[:find ?resource
                                                           :where
                                                           [?resource :resource/key _]
                                                           [?resource :resource/pattern? true]])
               :top-services (top-counts db '[:find ?service (count ?resource)
                                              :where [?resource :resource/service ?service]]
                                         15)}
   :principals {:by-type (attr-group-counts db :principal/type)
                :by-origin (let [inv (count (d/q '[:find ?p
                                                   :where
                                                   [?p :principal/type :aws]
                                                   [?p :principal/value ?arn]
                                                   [?r :aws/arn ?arn]
                                                   [?r :role/id _]]
                                                 db))
                                 ref (count (d/q '[:find ?p
                                                   :where
                                                   (or [_ :statement/principal ?p]
                                                       [_ :statement/not-principal ?p])]
                                                 db))]
                             [{:value :inventory :count inv}
                              {:value :policy-reference :count ref}])
                :by-internal (let [t (count (d/q '[:find ?p
                                                   :where
                                                   [?p :principal/type :aws]
                                                   [?p :principal/value ?arn]
                                                   [?r :aws/arn ?arn]
                                                   [?r :role/id _]]
                                                 db))
                                   total (count (d/q '[:find ?p
                                                       :where [?p :principal/key _]]
                                                     db))]
                               [{:value true :count t}
                                {:value false :count (- total t)}])}
   :conditions {:by-operator (attr-group-counts db :condition/operator)
                :perimeter-conditions (stats-result-count db '[:find ?condition
                                                               :where
                                                               [?condition :condition/key _]
                                                               [?condition :condition/perimeter? true]])
                :key-category (attr-group-counts db :condition-key/category)
                :key-source (attr-group-counts db :condition-key/source)}})

(defn role-all-policies
  "All trust, inline, attached, and boundary policies reachable from a role ARN."
  [db role-arn]
  (d/q '[:find ?policy-key ?policy-name ?policy-type ?edge
         :keys policy-key policy-name policy-type edge
         :in $ ?role-arn
         :where
         [?role :aws/arn ?role-arn]
         (or-join [?role ?policy ?edge]
                  (and [?role :role/attached-policy ?policy]
                       [(ground :attached-managed) ?edge])
                  (and [?role :role/inline-policy ?policy]
                       [(ground :inline) ?edge])
                  (and [?role :role/permissions-boundary ?policy]
                       [(ground :permissions-boundary) ?edge]))
         [?policy :policy/key ?policy-key]
         [?policy :policy/name ?policy-name]
         [?policy :policy/type ?policy-type]]
       db role-arn))

(defn role-allowed-actions
  "All Allow action keys granted to a role through inline or attached policies."
  [db role-arn]
  (->> (d/q '[:find [?action ...]
              :in $ ?role-arn
              :where
              [?role :aws/arn ?role-arn]
              (or [?role :role/attached-policy ?policy]
                  [?role :role/inline-policy ?policy])
              [?policy :policy/document ?doc]
              [?doc :document/statement ?statement]
              [?statement :statement/effect :allow]
              [?statement :statement/action ?action-entity]
              [?action-entity :action/key ?action]]
            db role-arn)
       sort
       vec))

(defn policy-attachments
  "All managed-policy to role attachment pairs."
  [db]
  (d/q '[:find ?policy-key ?policy-name ?role-arn ?role-name
         :keys policy-key policy-name role-arn role-name
         :where
         [?role :role/attached-policy ?policy]
         [?policy :policy/key ?policy-key]
         [?policy :policy/name ?policy-name]
         [?role :aws/arn ?role-arn]
         [?role :role/name ?role-name]]
       db))

(defn policies-by-action
  "Managed policies that Allow an action key or action-prefix string."
  [db action-prefix]
  (d/q '[:find ?policy-key ?policy-name ?action
         :keys policy-key policy-name action
         :in $ ?prefix
         :where
         [?policy :policy/type :managed]
         [?policy :policy/key ?policy-key]
         [?policy :policy/name ?policy-name]
         [?policy :policy/document ?doc]
         [?doc :document/statement ?statement]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action-entity]
         [?action-entity :action/key ?action]
         [(clojure.string/starts-with? ?action ?prefix)]]
       db action-prefix))

(defn roles-that-can-assume
  "Principals listed in a target role's trust policy."
  [db target-role-arn]
  (d/q '[:find ?source-type ?source-value ?target-name ?target-arn ?statement-key
         :keys source-type source target target-arn statement
         :in $ ?target-role-arn
         :where
         [?target :aws/arn ?target-role-arn]
         [?target :role/trust-policy ?doc]
         [?doc :document/statement ?statement]
         [?statement :statement/key ?statement-key]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action]
         [?action :action/key ?action-key]
         [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
         [?statement :statement/principal ?principal]
         [?principal :principal/type ?source-type]
         [?principal :principal/value ?source-value]
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]]
       db target-role-arn))

(defn roles-that-can-be-assumed-by
  "Roles whose trust policies include the source role or principal ARN."
  [db source-arn]
  (d/q '[:find ?target-name ?target-arn ?statement-key
         :keys target target-arn statement
         :in $ ?source-arn
         :where
         [?principal :principal/value ?source-arn]
         [?statement :statement/principal ?principal]
         [?doc :document/statement ?statement]
         [?target :role/trust-policy ?doc]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action]
         [?action :action/key ?action-key]
         [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
         [?statement :statement/key ?statement-key]
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]]
       db source-arn))

(defn roles-assumable-by-service
  "Roles whose trust policies allow a service principal, e.g. lambda.amazonaws.com."
  [db service-principal]
  (d/q '[:find ?target-name ?target-arn ?statement-key
         :keys target target-arn statement
         :in $ ?service-principal
         :where
         [?principal :principal/type :service]
         [?principal :principal/value ?service-principal]
         [?statement :statement/principal ?principal]
         [?doc :document/statement ?statement]
         [?target :role/trust-policy ?doc]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action]
         [?action :action/key ?action-key]
         [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
         [?statement :statement/key ?statement-key]
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]]
       db service-principal))

(defn assume-role-graph
  "All trust-policy AssumeRole edges derived from policy documents."
  [db]
  (d/q '[:find ?source-type ?source-value ?target-name ?target-arn ?statement-key
         :keys source-type source target target-arn statement
         :where
         [?target :role/trust-policy ?doc]
         [?doc :document/statement ?statement]
         [?statement :statement/key ?statement-key]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action]
         [?action :action/key ?action-key]
         [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
         [?statement :statement/principal ?principal]
         [?principal :principal/type ?source-type]
         [?principal :principal/value ?source-value]
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]]
       db))

(defn assume-role-reachable
  "Known role-to-role trust reachability from a source role ARN."
  [db source-role-arn]
  (d/q '[:find ?target-name ?target-arn
         :keys target target-arn
         :in $ % ?source-role-arn
         :where
         [?source :aws/arn ?source-role-arn]
         [?source :role/id _]
         (can-assume ?source ?target)
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]]
       db role-chain-rules source-role-arn))

(defn admin-like-roles
  "Roles with an Allow statement that grants Action * on Resource * through an
  inline or attached identity policy. Permissions boundaries are excluded
  because they do not grant access by themselves."
  [db]
  (d/q '[:find ?role ?role-name ?role-arn ?role-account ?policy-name ?policy-type ?edge ?statement-key
         :keys role role-name role-arn role-account policy-name policy-type edge statement
         :where
         [?star-action :action/key "*"]
         [?star-resource :resource/key "*"]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?star-action]
         [?statement :statement/resource ?star-resource]
         [?statement :statement/key ?statement-key]
         [?document :document/statement ?statement]
         [?policy :policy/document ?document]
         [?policy :policy/name ?policy-name]
         [?policy :policy/type ?policy-type]
         (or-join [?role ?policy ?edge]
                  (and [?role :role/attached-policy ?policy]
                       [(ground :attached-managed) ?edge])
                  (and [?role :role/inline-policy ?policy]
                       [(ground :inline) ?edge]))
         [?role :role/name ?role-name]
         [?role :aws/arn ?role-arn]
         [?role :aws/account-id ?role-account]]
       db))

(defn trust-role-assume-edges
  "Explicit role-to-role AssumeRole trust edges, derived from trust policies."
  [db]
  (d/q '[:find ?source ?source-name ?source-arn ?source-account
                ?target ?target-name ?target-arn ?target-account ?statement-key
         :keys source source-name source-arn source-account
               target target-name target-arn target-account trust-statement
         :where
         [?source :role/id _]
         [?source :role/name ?source-name]
         [?source :aws/arn ?source-arn]
         [?source :aws/account-id ?source-account]
         [?target :role/trust-policy ?doc]
         [?target :role/name ?target-name]
         [?target :aws/arn ?target-arn]
         [?target :aws/account-id ?target-account]
         [?doc :document/statement ?statement]
         [?statement :statement/effect :allow]
         [?statement :statement/action ?action]
         [?action :action/key ?action-key]
         [(contains? #{"sts:assumerole" "sts:*" "*"} ?action-key)]
         [?statement :statement/principal ?principal]
         [?principal :principal/value ?source-arn]
         [?statement :statement/key ?statement-key]]
       db))

(defn- role-node
  [role-name role-arn account-id]
  {:name role-name :arn role-arn :account-id account-id})

(defn- role-nodes-by-eid
  [admin-roles edges]
  (into {}
        cat
        [(for [{:keys [role role-name role-arn role-account]} admin-roles]
           [role (role-node role-name role-arn role-account)])
         (for [{:keys [source source-name source-arn source-account
                       target target-name target-arn target-account]} edges
               entry [[source (role-node source-name source-arn source-account)]
                      [target (role-node target-name target-arn target-account)]]]
           entry)]))

(defn- account-scoped-admin-roles
  [admin-roles account]
  (cond->> admin-roles
    account (filter #(= account (:role-account %)))
    true vec))

(defn- account-scoped-trust-edges
  "Restrict role-to-role edges to those wholly inside `account` (both
  endpoints). Returns a vector regardless of whether `account` is supplied."
  [edges account]
  (cond->> edges
    account (filter #(and (= account (:source-account %))
                          (= account (:target-account %))))
    true vec))

(def ^:private account-scoped-pass-role-edges
  "PassRole edges have the same source/target account shape as trust edges,
  so their account-scoping rule is the same."
  account-scoped-trust-edges)

(defn- role-chain-paths-to-target
  [incoming-by-target max-depth target]
  (loop [frontier [{:nodes [target] :edges []}]
         paths []]
    (if-let [{:keys [nodes edges]} (first frontier)]
      (let [seen (set nodes)
            current (first nodes)
            next-paths (if (< (count edges) max-depth)
                         (->> (get incoming-by-target current)
                              (remove #(contains? seen (:source %)))
                              (map (fn [edge]
                                     {:nodes (cons (:source edge) nodes)
                                      :edges (cons edge edges)})))
                         [])]
        (recur (concat (rest frontier) next-paths)
               (into paths next-paths)))
      paths)))

(defn- max-depth-value
  [value]
  (let [depth (cond
                (nil? value) 8
                (integer? value) value
                :else (parse-long (str value)))]
    (when-not (and depth (pos? depth))
      (throw (ex-info "--max-depth must be positive" {:max-depth value})))
    depth))

(defn- max-results-value
  [value]
  (when (some? value)
    (let [n (if (integer? value) value (parse-long (str value)))]
      (when-not (and n (pos? n))
        (throw (ex-info "--max-results must be positive" {:max-results value})))
      n)))

(defn admin-role-chain-paths
  "Role-to-role AssumeRole paths that can elevate into admin-like roles.
  Returns every simple path up to max-depth, including intermediate sources."
  ([db]
   (admin-role-chain-paths db {}))
  ([db {:keys [max-depth account max-results]}]
   (let [max-depth (max-depth-value max-depth)
         max-results (max-results-value max-results)
         account (some-> account str)
         admin-roles (account-scoped-admin-roles (admin-like-roles db) account)
         edges (account-scoped-trust-edges (trust-role-assume-edges db) account)
         incoming-by-target (group-by :target edges)
         nodes-by-eid (role-nodes-by-eid admin-roles edges)
         paths (cond->>
                (->> (for [{:keys [role role-name role-arn policy-name policy-type edge statement]} admin-roles
                           {:keys [nodes edges]} (role-chain-paths-to-target incoming-by-target max-depth role)]
                       {:source (get nodes-by-eid (first nodes))
                        :admin {:name role-name
                                :arn role-arn
                                :policy {:name policy-name
                                         :type policy-type
                                         :edge edge
                                         :statement statement}}
                        :hop-count (count edges)
                        :path (mapv nodes-by-eid nodes)
                        :trust-statements (mapv :trust-statement edges)})
                     (sort-by (juxt #(get-in % [:admin :name])
                                    :hop-count
                                    #(get-in % [:source :arn])
                                    #(mapv :arn (:path %)))))
                max-results (take max-results)
                  true vec)]
     {:admin-targets (count admin-roles)
      :trust-role-edges (count edges)
      :elevation-paths (count paths)
      :source-roles (count (set (map #(get-in % [:source :arn]) paths)))
      :max-depth max-depth
      :account account
      :results paths})))

(defn- statement-passed-to-services
  "Extract iam:PassedToService values from a statement entity. Returns nil when
  the statement has no such condition (caller treats this as :any-service)."
  [db statement-eid]
  (let [conds (d/q '[:find ?field ?value-doc
                     :in $ ?statement
                     :where
                     [?statement :statement/condition ?cond]
                     [?cond :condition/field ?field]
                     [?cond :condition/value ?value-doc]]
                   db statement-eid)
        services (->> conds
                      (filter (fn [[field _]]
                                (= "iam:passedtoservice"
                                   (some-> field str/lower-case))))
                      (mapcat (fn [[_ value-doc]]
                                (let [v (or (:value value-doc) value-doc)]
                                  (map str (ensure-vector v))))))]
    (when (seq services)
      (vec (distinct services)))))

(defn- pass-role-edges
  "Identity-policy iam:PassRole edges between inventory roles, derived from
  policy statements. Returns one row per (source, target, statement, service);
  when a statement has no iam:PassedToService condition it emits :any-service.

  Two branches:
  - explicit ARN: `Resource` lists target ARNs that resolve to inventory roles
  - wildcard ARN (contains `*`): expanded to every inventory role in the
    source's same AWS account whose ARN matches the wildcard pattern."
  [db]
  (let [explicit (d/q '[:find ?source ?source-name ?source-arn ?source-account
                              ?target ?target-name ?target-arn ?target-account
                              ?statement ?statement-key
                        :keys source source-name source-arn source-account
                              target target-name target-arn target-account
                              statement permission-statement
                        :where
                        [?source :role/id _]
                        (or [?source :role/inline-policy ?policy]
                            [?source :role/attached-policy ?policy])
                        [?policy :policy/document ?doc]
                        [?doc :document/statement ?statement]
                        [?statement :statement/key ?statement-key]
                        [?statement :statement/effect :allow]
                        [?statement :statement/action ?action]
                        [?action :action/key ?action-key]
                        [(contains? #{"iam:passrole" "iam:*" "*"} ?action-key)]
                        [?statement :statement/resource ?resource]
                        [?resource :resource/arn ?target-arn]
                        [(clojure.string/includes? ?target-arn "*") ?wild?]
                        [(not ?wild?)]
                        [?target :aws/arn ?target-arn]
                        [?target :role/id _]
                        [?source :role/name ?source-name]
                        [?source :aws/arn ?source-arn]
                        [?source :aws/account-id ?source-account]
                        [?target :role/name ?target-name]
                        [?target :aws/account-id ?target-account]]
                      db)
        ;; Wildcard branch: bind (source, statement, resource-pattern); expand
        ;; to same-account inventory targets matching the pattern in Clojure.
        wild-tuples (d/q '[:find ?source ?source-name ?source-arn ?source-account
                                 ?statement ?statement-key ?resource-arn
                           :keys source source-name source-arn source-account
                                 statement permission-statement resource-arn
                           :where
                           [?source :role/id _]
                           (or [?source :role/inline-policy ?policy]
                               [?source :role/attached-policy ?policy])
                           [?policy :policy/document ?doc]
                           [?doc :document/statement ?statement]
                           [?statement :statement/key ?statement-key]
                           [?statement :statement/effect :allow]
                           [?statement :statement/action ?action]
                           [?action :action/key ?action-key]
                           [(contains? #{"iam:passrole" "iam:*" "*"} ?action-key)]
                           [?statement :statement/resource ?resource]
                           [?resource :resource/arn ?resource-arn]
                           [(clojure.string/includes? ?resource-arn "*")]
                           [?source :role/name ?source-name]
                           [?source :aws/arn ?source-arn]
                           [?source :aws/account-id ?source-account]]
                         db)
        roles-by-account (->> (d/q '[:find ?role ?name ?arn ?account
                                     :keys target target-name target-arn target-account
                                     :where
                                     [?role :role/id _]
                                     [?role :role/name ?name]
                                     [?role :aws/arn ?arn]
                                     [?role :aws/account-id ?account]]
                                   db)
                              (group-by :target-account))
        wildcard (for [{:keys [source-account resource-arn] :as tup} wild-tuples
                       :let [base (-> tup
                                      (dissoc :resource-arn)
                                      (assoc :target-account source-account))]
                       role (get roles-by-account source-account)
                       :when (wildcard-matches? resource-arn (:target-arn role))]
                   (merge base role))
        base (concat explicit wildcard)
        rows (for [{:keys [statement] :as row} base
                   :let [services (statement-passed-to-services db statement)
                         row (dissoc row :statement)]
                   svc (if (seq services) services [:any-service])]
               (assoc row :service svc))]
    (vec rows)))

(defn- target-trust-service-principals
  "Service principals (e.g. lambda.amazonaws.com) listed as Allow/AssumeRole
  principals in `target-role-arn`'s trust policy. Empty when the role only
  trusts AWS account / role principals."
  [db target-role-arn]
  (let [pulled (d/pull db
                       '[{:role/trust-policy
                          [{:document/statement
                            [:statement/effect
                             {:statement/action [:action/key]}
                             {:statement/principal [:principal/type :principal/value]}]}]}]
                       [:aws/arn target-role-arn])]
    (->> (get-in pulled [:role/trust-policy :document/statement])
         (filter #(= :allow (:statement/effect %)))
         (filter (fn [s]
                   (some #(contains? #{"sts:assumerole" "sts:assumerolewithsaml"
                                       "sts:assumerolewithwebidentity" "sts:*" "*"}
                                     (:action/key %))
                         (:statement/action s))))
         (mapcat :statement/principal)
         (filter #(= :service (:principal/type %)))
         (map :principal/value)
         distinct
         sort
         vec)))

(defn- pass-role-passable-service-principals
  "Concrete service principals the target role can be passed to for this edge.
  `:any-service` expands to the target role's trust-policy services; a specific
  delegated service is retained only when the target role trusts that service."
  [delegated-service trust-services]
  (let [trust-service-set (set trust-services)]
    (cond
      (contains? #{:any-service "any-service"} delegated-service) (vec trust-services)
      (contains? trust-service-set delegated-service) [delegated-service]
      :else [])))

(defn- pass-role-elevatable-by-service?
  "True iff the delegated service is consistent with the target role's trust
  policy. `:any-service` is consistent with any non-empty service-principal
  set; a specific service must appear verbatim."
  [delegated-service trust-services]
  (boolean (seq (pass-role-passable-service-principals delegated-service trust-services))))

(defn admin-pass-role-paths
  "iam:PassRole edges that can elevate into admin-like roles. Each result is
  augmented with the target role's trust-policy service principals
  (`:target-trust-services`), the concrete service principals the admin role
  can be passed to (`:passable-service-principals`), and a boolean
  `:elevatable-by-service?` flag derived from that concrete list."
  ([db]
   (admin-pass-role-paths db {}))
  ([db {:keys [account max-results]}]
   (let [max-results (max-results-value max-results)
         account (some-> account str)
         admin-roles (account-scoped-admin-roles (admin-like-roles db) account)
         edges (account-scoped-pass-role-edges (pass-role-edges db) account)
         edges-by-target (group-by :target edges)
         nodes-by-eid (role-nodes-by-eid admin-roles edges)
         trust-services-by-arn (into {}
                                     (map (fn [{:keys [role-arn]}]
                                            [role-arn
                                             (target-trust-service-principals db role-arn)]))
                                     admin-roles)
         paths (cond->>
                (->> (for [{:keys [role role-name role-arn policy-name policy-type edge statement]} admin-roles
                           {:keys [source service permission-statement]} (get edges-by-target role)
                           :let [trust-services (get trust-services-by-arn role-arn [])
                                 passable-services (pass-role-passable-service-principals
                                                    service trust-services)]]
                       {:source (get nodes-by-eid source)
                        :admin {:name role-name
                                :arn role-arn
                                :policy {:name policy-name
                                         :type policy-type
                                         :edge edge
                                         :statement statement}}
                        :hop-count 1
                        :path [(get nodes-by-eid source)
                               (get nodes-by-eid role)]
                        :delegated-service service
                        :permission-statement permission-statement
                        :target-trust-services trust-services
                        :passable-service-principals passable-services
                        :elevatable-by-service? (pass-role-elevatable-by-service?
                                                 service trust-services)})
                     (sort-by (juxt #(get-in % [:admin :name])
                                    #(get-in % [:source :arn])
                                    :delegated-service
                                    :permission-statement)))
                max-results (take max-results)
                  true vec)]
     {:admin-targets (count admin-roles)
      :pass-role-edges (count edges)
      :elevation-paths (count paths)
      :elevatable-by-service-paths (count (filter :elevatable-by-service? paths))
      :source-roles (count (set (map #(get-in % [:source :arn]) paths)))
      :account account
      :results paths})))

(defn- statement-action-keys
  [db statement-key]
  (->> (d/q '[:find [?action-key ...]
              :in $ ?statement-key
              :where
              [?statement :statement/key ?statement-key]
              [?statement :statement/action ?action]
              [?action :action/key ?action-key]]
            db statement-key)
       sort
       vec))

(defn- statement-resource-keys
  [db statement-key]
  (->> (d/q '[:find [?resource-key ...]
              :in $ ?statement-key
              :where
              [?statement :statement/key ?statement-key]
              [?statement :statement/resource ?resource]
              [?resource :resource/key ?resource-key]]
            db statement-key)
       sort
       vec))

(defn- statement-condition-rows
  [db statement-key]
  (->> (d/q '[:find ?field ?operator
              :keys field operator
              :in $ ?statement-key
              :where
              [?statement :statement/key ?statement-key]
              [?statement :statement/condition ?condition]
              [?condition :condition/field ?field]
              [?condition :condition/operator ?operator]]
            db statement-key)
       (mapv #(assoc % :condition-key (condition-key-name (:field %))))))

(defn- service-reference-action
  [db action-key]
  (when-let [[action service name]
             (first
              (d/q '[:find ?action ?service ?name
                     :in $ ?action-key
                     :where
                     [?action :action/key ?action-key]
                     [?action :action/source :service-reference]
                     [?action :action/service ?service]
                     [?action :action/name ?name]]
                   db action-key))]
    (cond-> {:service service :name name}
      (:action/access-level (d/pull db [:action/access-level] action))
      (assoc :access-level (:action/access-level (d/pull db [:action/access-level] action))))))

(defn- service-reference-action-id
  [db action-key]
  (ffirst
   (d/q '[:find ?action
          :in $ ?action-key
          :where
          [?action :action/key ?action-key]
          [?action :action/source :service-reference]]
        db action-key)))

(defn- service-reference-action-keys
  [db]
  (d/q '[:find [?action-key ...]
         :where
         [?action :action/key ?action-key]
         [?action :action/source :service-reference]
         [?action :action/service _]]
       db))

(defn- validate-action-key
  [db action-key]
  (cond
    (str/includes? action-key "*")
    (let [match-count (count (filter #(action-pattern-matches? action-key %)
                                     (service-reference-action-keys db)))]
      {:action action-key
       :status :wildcard
       :matches match-count
       :valid? (pos? match-count)})

    :else
    (if-let [service-action (service-reference-action db action-key)]
      (assoc service-action
             :action action-key
             :status :supported
             :valid? true)
      {:action action-key
       :status :unsupported
       :valid? false})))

(defn- action-resource-types
  [db action-key]
  (if-let [action (service-reference-action-id db action-key)]
    (vec
     (for [resource (d/q '[:find [?resource ...]
                           :in $ ?action
                           :where [?action :action/resource-type ?resource]]
                         db action)
           [resource-key resource-name arn-format]
           (d/q '[:find ?resource-key ?resource-name ?arn-format
                  :in $ ?resource
                  :where
                  [?resource :service-resource/key ?resource-key]
                  [?resource :service-resource/name ?resource-name]
                  [?resource :service-resource/arn-format ?arn-format]]
                db resource)]
       {:resource-key resource-key
        :resource-type resource-name
        :arn-format arn-format}))
    []))

(defn- placeholder-regex
  [placeholder]
  (case (str/lower-case placeholder)
    "${partition}" "[^:]+"
    "${account}" "(\\d{12}|\\*)"
    "${region}" "[^:]*"
    "[^:]+"))

(defn- arn-format-regex
  [arn-format]
  (let [parts (str/split arn-format #"\$\{[^}]+\}" -1)
        placeholders (re-seq #"\$\{[^}]+\}" arn-format)]
    (re-pattern
     (str "^"
          (apply str
                 (concat
                  (for [[part placeholder] (map vector parts placeholders)
                        x [(java.util.regex.Pattern/quote part)
                           (placeholder-regex placeholder)]]
                    x)
                  [(java.util.regex.Pattern/quote (last parts))]))
          "$"))))

(defn- arn-format-matches?
  [arn-format arn]
  (boolean (re-matches (arn-format-regex arn-format) arn)))

(defn- validate-target-resource-arn
  [db action-key target-arn]
  (when target-arn
    (let [resource-types (action-resource-types db action-key)
          matches (filter #(arn-format-matches? (:arn-format %) target-arn) resource-types)]
      {:action action-key
       :arn target-arn
       :status (cond
                 (str/includes? action-key "*") :wildcard-action
                 (empty? resource-types) :no-resource-types
                 (seq matches) :supported
                 :else :unsupported)
       :valid? (boolean (or (str/includes? action-key "*")
                            (and (seq resource-types) (seq matches))))
       :matched-resource-types (vec (distinct (map :resource-type matches)))
       :supported-resource-types (vec (distinct (map :resource-type resource-types)))})))

(defn- validate-statement-resource
  [db action-key resource]
  (cond
    (str/includes? action-key "*")
    {:action action-key :resource resource :status :wildcard-action :valid? true}

    (= "*" resource)
    {:action action-key :resource resource :status :wildcard-resource :valid? true}

    (str/includes? resource "*")
    {:action action-key :resource resource :status :resource-pattern :valid? true}

    (str/starts-with? resource "arn:")
    (let [resource-types (action-resource-types db action-key)
          matches (filter #(arn-format-matches? (:arn-format %) resource) resource-types)]
      {:action action-key
       :resource resource
       :status (if (seq matches) :supported :unsupported)
       :valid? (boolean (seq matches))
       :matched-resource-types (vec (distinct (map :resource-type matches)))
       :supported-resource-types (vec (distinct (map :resource-type resource-types)))})

    :else
    {:action action-key :resource resource :status :non-arn-resource :valid? true}))

(defn- condition-key-pattern-regex
  [pattern]
  (let [parts (str/split pattern #"\$\{[^}]+\}" -1)
        placeholders (re-seq #"\$\{[^}]+\}" pattern)]
    (re-pattern
     (str "^"
          (apply str
                 (concat
                  (for [[part _] (map vector parts placeholders)
                        x [(java.util.regex.Pattern/quote part) ".+"]]
                    x)
                  [(java.util.regex.Pattern/quote (last parts))]))
          "$"))))

(defn- condition-key-pattern-matches?
  [pattern condition-key]
  (let [pattern (condition-key-name pattern)
        condition-key (condition-key-name condition-key)]
    (or (= pattern condition-key)
        (and (str/includes? pattern "${")
             (boolean (re-matches (condition-key-pattern-regex pattern) condition-key))))))

(defn- action-condition-key-patterns
  [db action-key]
  (if-let [action (service-reference-action-id db action-key)]
    (let [action-conditions (d/q '[:find [?condition ...]
                                   :in $ ?action
                                   :where [?action :action/condition-key ?condition]]
                                 db action)
          resource-conditions (->> (d/q '[:find [?resource ...]
                                          :in $ ?action
                                          :where [?action :action/resource-type ?resource]]
                                        db action)
                                   (mapcat #(d/q '[:find [?condition ...]
                                                   :in $ ?resource
                                                   :where [?resource :service-resource/condition-key ?condition]]
                                                 db %)))
          condition-name (fn [condition]
                           (ffirst (d/q '[:find ?condition-key
                                          :in $ ?condition
                                          :where [?condition :condition-key/name ?condition-key]]
                                        db condition)))]
      (->> (concat action-conditions resource-conditions)
           (keep condition-name)
           distinct
           vec))
    []))

(defn- validate-condition-key
  [db action-key {:keys [condition-key] :as condition}]
  (let [patterns (action-condition-key-patterns db action-key)
        matches (filter #(condition-key-pattern-matches? % condition-key) patterns)
        global? (str/starts-with? condition-key "aws:")]
    (assoc condition
           :action action-key
           :status (cond
                     global? :aws-global
                     (seq matches) :supported
                     :else :unsupported)
           :valid? (boolean (or global? (seq matches)))
           :matched-condition-keys (vec matches)
           :supported-condition-keys patterns)))

(defn- statement-action-allows?
  [actions expected-action]
  (boolean (some #(action-pattern-matches? % expected-action) actions)))

(defn- validate-statement-context
  [db {:keys [statement-key expected-action target-resource-arn] :as context}]
  (let [actions (statement-action-keys db statement-key)
        resources (statement-resource-keys db statement-key)
        conditions (statement-condition-rows db statement-key)
        validation-actions (cond
                             expected-action [expected-action]
                             (seq actions) actions
                             :else [])]
    (assoc context
           :actions actions
           :resources resources
           :conditions conditions
           :action-checks (mapv #(validate-action-key db %) actions)
           :expected-action-check (when expected-action
                                    {:action expected-action
                                     :covered? (statement-action-allows? actions expected-action)
                                     :valid? (statement-action-allows? actions expected-action)})
           :target-resource-check (when expected-action
                                    (validate-target-resource-arn db expected-action target-resource-arn))
           :resource-checks (vec
                             (for [action validation-actions
                                   resource resources]
                               (validate-statement-resource db action resource)))
           :condition-checks (vec
                              (for [action validation-actions
                                    condition conditions]
                                (validate-condition-key db action condition))))))

(defn- validation-issue
  [context issue-type check]
  (merge {:severity :error
          :query (:query context)
          :context (:context context)
          :statement (:statement-key context)
          :type issue-type}
         check))

(defn- validation-context-issues
  [context]
  (vec
   (concat
    (for [check (:action-checks context)
          :when (false? (:valid? check))]
      (validation-issue context :unsupported-action check))
    (when-let [check (:expected-action-check context)]
      (when (false? (:valid? check))
        [(validation-issue context :expected-action-not-covered check)]))
    (when-let [check (:target-resource-check context)]
      (when (false? (:valid? check))
        [(validation-issue context :unsupported-target-resource check)]))
    (for [check (:resource-checks context)
          :when (false? (:valid? check))]
      (validation-issue context :unsupported-statement-resource check))
    (for [check (:condition-checks context)
          :when (false? (:valid? check))]
      (validation-issue context :unsupported-condition-key check)))))

(defn- distinct-validation-contexts
  [contexts]
  (->> contexts
       (reduce (fn [acc context]
                 (let [k (select-keys context [:context :statement-key :expected-action :target-resource-arn])]
                   (if (contains? (:seen acc) k)
                     acc
                     (-> acc
                         (update :seen conj k)
                         (update :contexts conj context)))))
               {:seen #{} :contexts []})
       :contexts))

(defn- admin-role-chain-validation-contexts
  [report]
  (mapcat
   (fn [result]
     (concat
      [{:query :admin-role-chain-paths
        :context :admin-policy
        :statement-key (get-in result [:admin :policy :statement])}]
      (map (fn [statement target]
             {:query :admin-role-chain-paths
              :context :trust-policy
              :statement-key statement
              :expected-action (:assume-role role-transition-actions)
              :target-resource-arn (:arn target)})
           (:trust-statements result)
           (rest (:path result)))))
   (:results report)))

(defn- admin-pass-role-validation-contexts
  [report]
  (mapcat
   (fn [result]
     [{:query :admin-pass-role-paths
       :context :admin-policy
       :statement-key (get-in result [:admin :policy :statement])}
      {:query :admin-pass-role-paths
       :context :pass-role-permission
       :statement-key (:permission-statement result)
       :expected-action (:pass-role role-transition-actions)
       :target-resource-arn (get-in result [:admin :arn])}])
   (:results report)))

(defn- path-report-summary
  [report edge-key]
  (select-keys report [:admin-targets edge-key :elevation-paths :source-roles :max-depth :account]))

(defn validate-admin-path-entities
  "Validate admin path query evidence against loaded service-reference metadata."
  ([db]
   (validate-admin-path-entities db {}))
  ([db {:keys [max-depth account]}]
   (let [opts {:max-depth max-depth :account account}
         role-chain-report (admin-role-chain-paths db opts)
         pass-role-report (admin-pass-role-paths db {:account account})
         contexts (distinct-validation-contexts
                   (concat (admin-role-chain-validation-contexts role-chain-report)
                           (admin-pass-role-validation-contexts pass-role-report)))
         checked-contexts (mapv #(validate-statement-context db %) contexts)
         issues (mapcat validation-context-issues checked-contexts)]
     {:summary {:queries {:admin-role-chain-paths (path-report-summary role-chain-report :trust-role-edges)
                          :admin-pass-role-paths (path-report-summary pass-role-report :pass-role-edges)}
                :checked-contexts (count checked-contexts)
                :checked-statements (count (set (map :statement-key checked-contexts)))
                :checked-actions (reduce + (map #(count (:action-checks %)) checked-contexts))
                :checked-resources (reduce + (map #(count (:resource-checks %)) checked-contexts))
                :checked-conditions (reduce + (map #(count (:condition-checks %)) checked-contexts))
                :issues (count issues)
                :valid? (empty? issues)}
      :issues (vec issues)
      :contexts checked-contexts})))

;; ---------------------------------------------------------------------------
;; Pull-API validation of AssumeRole elevation paths
;; ---------------------------------------------------------------------------

(defn- pulled-condition->map
  "Project a pulled `:statement/condition` entity into the public report
  shape used by every pull-based validator."
  [{:condition/keys [field operator value catalog-key]}]
  {:field field
   :operator operator
   :catalog-key (:condition-key/name catalog-key)
   :value value})

(def ^:private trust-statement-pull-pattern
  "Datalevin pull pattern that materializes a trust statement plus the role
  attributes needed to verify a single AssumeRole hop in one round-trip."
  [:statement/key
   :statement/sid
   :statement/effect
   {:statement/action [:action/key]}
   {:statement/resource [:resource/arn]}
   {:statement/principal [:principal/type :principal/value]}
   {:statement/not-principal [:principal/type :principal/value]}
   {:statement/condition [:condition/field :condition/operator :condition/value
                          {:condition/catalog-key [:condition-key/name]}]}])

(def ^:private role-trust-pull-pattern
  [:role/id
   :role/name
   :aws/arn
   :aws/account-id
   {:role/trust-policy
    [:document/key
     :document/kind
     {:document/statement [:statement/key]}]}])

(defn- trust-statement-belongs-to?
  [pulled-target-role statement-key]
  (->> (get-in pulled-target-role [:role/trust-policy :document/statement])
       (some #(= statement-key (:statement/key %)))
       boolean))

(def ^:private assume-role-action-keys
  #{"sts:assumerole" "sts:assumerolewithsaml" "sts:assumerolewithwebidentity"
    "sts:*" "*"})

(defn- statement-allows-assume-role?
  [pulled-statement]
  (and (= :allow (:statement/effect pulled-statement))
       (boolean (some #(contains? assume-role-action-keys (:action/key %))
                      (:statement/action pulled-statement)))))

(defn- statement-principal-arns
  [pulled-statement]
  (->> (:statement/principal pulled-statement)
       (filter #(= :aws (:principal/type %)))
       (map :principal/value)
       set))

(defn- principal-allows-source?
  "True iff `pulled-statement` grants assume to `source-arn` either via an
  exact ARN principal or via a `:star` principal (Principal: \"*\"`)."
  [pulled-statement source-arn]
  (let [principals (:statement/principal pulled-statement)
        star? (some #(= :star (:principal/type %)) principals)
        aws-arns (statement-principal-arns pulled-statement)]
    (boolean (or star?
                 (contains? aws-arns source-arn)
                 ;; account-root principal grants any role in that account
                 (some #(re-matches #"arn:aws:iam::\d+:root" %) aws-arns)))))

(defn- validate-assume-role-hop
  [db source-arn target-arn statement-key]
  (let [stmt (d/pull db trust-statement-pull-pattern [:statement/key statement-key])
        target (d/pull db role-trust-pull-pattern [:aws/arn target-arn])
        effect (:statement/effect stmt)
        actions (mapv :action/key (:statement/action stmt))
        principal-arns (vec (statement-principal-arns stmt))
        belongs? (trust-statement-belongs-to? target statement-key)
        action-ok? (statement-allows-assume-role? stmt)
        principal-ok? (principal-allows-source? stmt source-arn)
        checks {:effect-allow? (= :allow effect)
                :action-covers-assume-role? action-ok?
                :principal-includes-source? principal-ok?
                :statement-attached-to-target-trust-policy? belongs?}
        valid? (every? true? (vals checks))]
    {:source-arn source-arn
     :target-arn target-arn
     :statement statement-key
     :effect effect
     :actions actions
     :resources (mapv :resource/arn (:statement/resource stmt))
     :principal-arns principal-arns
     :principal-types (vec (distinct (map :principal/type (:statement/principal stmt))))
     :conditions (mapv pulled-condition->map (:statement/condition stmt))
     :checks checks
     :valid? valid?}))

(defn validate-admin-role-chain-paths-with-pull
  "Validate every AssumeRole hop in admin elevation paths using the Datalevin
  pull API. For each hop pulls the trust statement and the target role's
  trust policy in a single round-trip, then asserts:
    * statement effect is :allow
    * an action key on the statement covers sts:AssumeRole (incl. wildcards)
    * the source role's ARN appears in the statement's principals
      (account-root and `Principal: \"*\"` are accepted)
    * the statement is referenced by the target role's trust policy

  Returns a per-path / per-hop report plus aggregate counters."
  ([db] (validate-admin-role-chain-paths-with-pull db {}))
  ([db opts]
   (let [report (admin-role-chain-paths db opts)
         results (mapv
                  (fn [{:keys [source admin path trust-statements] :as p}]
                    (let [arns (mapv :arn path)
                          hops (mapv (fn [src tgt stmt]
                                       (validate-assume-role-hop db src tgt stmt))
                                     (butlast arns)
                                     (rest arns)
                                     trust-statements)
                          path-valid? (every? :valid? hops)]
                      (-> p
                          (select-keys [:source :admin :hop-count :path])
                          (assoc :hops hops :valid? path-valid?))))
                  (:results report))
         all-hops (mapcat :hops results)]
     {:summary {:admin-targets (:admin-targets report)
                :elevation-paths (:elevation-paths report)
                :valid-paths (count (filter :valid? results))
                :invalid-paths (count (remove :valid? results))
                :hops (count all-hops)
                :valid-hops (count (filter :valid? all-hops))
                :invalid-hops (count (remove :valid? all-hops))
                :max-depth (:max-depth report)
                :account (:account report)}
      :results results
      :invalid-hops (vec (remove :valid? all-hops))})))

;; ---------------------------------------------------------------------------
;; Pull-API validation of iam:PassRole elevation paths
;; ---------------------------------------------------------------------------

(def ^:private pass-role-statement-pull-pattern
  "Statement plus owning role/policy chain, materialized in one round-trip."
  [:statement/key
   :statement/sid
   :statement/effect
   {:statement/action [:action/key]}
   {:statement/resource [:resource/arn]}
   {:statement/condition [:condition/field :condition/operator :condition/value
                          {:condition/catalog-key [:condition-key/name]}]}])

(def ^:private pass-role-source-pull-pattern
  [:role/id
   :role/name
   :aws/arn
   :aws/account-id
   {:role/inline-policy
    [:policy/key :policy/name :policy/type
     {:policy/document
      [:document/key {:document/statement [:statement/key]}]}]}
   {:role/attached-policy
    [:policy/key :policy/name :policy/type
     {:policy/document
      [:document/key {:document/statement [:statement/key]}]}]}])

(def ^:private pass-role-action-keys
  #{"iam:passrole" "iam:*" "*"})

(defn- statement-allows-pass-role?
  [pulled-statement]
  (and (= :allow (:statement/effect pulled-statement))
       (boolean (some #(contains? pass-role-action-keys (:action/key %))
                      (:statement/action pulled-statement)))))

(defn- resource-arn-covers-target?
  [resource-arn target-arn]
  (cond
    (= resource-arn target-arn) true
    (str/includes? resource-arn "*") (wildcard-matches? resource-arn target-arn)
    :else false))

(defn- statement-resources-cover-target?
  [pulled-statement target-arn]
  (boolean (some #(resource-arn-covers-target? (:resource/arn %) target-arn)
                 (:statement/resource pulled-statement))))

(defn- statement-passed-to-services-from-pulled
  [pulled-statement]
  (->> (:statement/condition pulled-statement)
       (filter (fn [c]
                 (= "iam:passedtoservice"
                    (some-> (:condition/field c) str/lower-case))))
       (mapcat (fn [c]
                 (let [v (:condition/value c)
                       v (or (:value v) v)]
                   (map str (ensure-vector v)))))
       distinct
       vec))

(defn- pulled-source-statement-keys
  "Set of statement keys reachable via the source role's identity policies."
  [pulled-source-role]
  (->> (concat (:role/inline-policy pulled-source-role)
               (:role/attached-policy pulled-source-role))
       (mapcat #(get-in % [:policy/document :document/statement]))
       (map :statement/key)
       set))

(defn- service-claim-consistent?
  [pulled-statement delegated-service]
  (let [services (statement-passed-to-services-from-pulled pulled-statement)
        ;; reports serialize :any-service as keyword in Clojure or "any-service" via JSON
        any? (or (= :any-service delegated-service)
                 (= "any-service" delegated-service))]
    (cond
      (empty? services) any?
      any?              false
      :else             (contains? (set services) (str delegated-service)))))

(defn- validate-pass-role-hop
  [db source-arn target-arn statement-key delegated-service]
  (let [stmt   (d/pull db pass-role-statement-pull-pattern
                       [:statement/key statement-key])
        source (d/pull db pass-role-source-pull-pattern
                       [:aws/arn source-arn])
        owns?  (contains? (pulled-source-statement-keys source) statement-key)
        action-ok?   (statement-allows-pass-role? stmt)
        resource-ok? (statement-resources-cover-target? stmt target-arn)
        service-ok?  (service-claim-consistent? stmt delegated-service)
        checks {:effect-allow?                                (= :allow (:statement/effect stmt))
                :action-covers-pass-role?                     action-ok?
                :resource-covers-target?                      resource-ok?
                :statement-attached-to-source-identity-policy? owns?
                :delegated-service-consistent?                service-ok?}
        valid? (every? true? (vals checks))]
    {:source-arn         source-arn
     :target-arn         target-arn
     :statement          statement-key
     :delegated-service  delegated-service
     :effect             (:statement/effect stmt)
     :actions            (mapv :action/key (:statement/action stmt))
     :resources          (mapv :resource/arn (:statement/resource stmt))
     :passed-to-services (statement-passed-to-services-from-pulled stmt)
     :conditions         (mapv pulled-condition->map (:statement/condition stmt))
     :checks             checks
     :valid?             valid?}))

(defn validate-admin-pass-role-paths-with-pull
  "Validate iam:PassRole elevation paths via the Datalevin pull API. For each
  path pulls the permission statement and the source role's identity policies
  in one round-trip, then asserts:
    * statement effect is :allow
    * an action key on the statement covers iam:PassRole (incl. wildcards)
    * a Resource ARN on the statement covers the admin target ARN (explicit
      or wildcard pattern)
    * the statement is attached to the source role's inline or attached policy
    * the reported delegated-service agrees with the statement's
      iam:PassedToService condition (or :any-service when none)."
  ([db] (validate-admin-pass-role-paths-with-pull db {}))
  ([db opts]
   (let [report (admin-pass-role-paths db opts)
         results (mapv
                  (fn [{:keys [source admin permission-statement delegated-service] :as p}]
                    (let [hop (validate-pass-role-hop db
                                                      (:arn source)
                                                      (:arn admin)
                                                      permission-statement
                                                      delegated-service)]
                      (-> p
                          (select-keys [:source :admin :hop-count :path
                                        :delegated-service :permission-statement])
                          (assoc :hops [hop] :valid? (:valid? hop)))))
                  (:results report))
         all-hops (mapcat :hops results)]
     {:summary {:admin-targets   (:admin-targets report)
                :pass-role-edges (:pass-role-edges report)
                :elevation-paths (:elevation-paths report)
                :valid-paths     (count (filter :valid? results))
                :invalid-paths   (count (remove :valid? results))
                :hops            (count all-hops)
                :valid-hops      (count (filter :valid? all-hops))
                :invalid-hops    (count (remove :valid? all-hops))
                :account         (:account report)}
      :results results
      :invalid-hops (vec (remove :valid? all-hops))})))

;; ---------------------------------------------------------------------------
;; Backwards (target-anchored) traversal via reverse-ref pull
;; ---------------------------------------------------------------------------
;;
;; Datalevin pull supports reverse navigation through ref attributes by
;; prefixing the relationship segment with `_` (e.g. `:document/_statement`
;; pulls every document that references a given statement). This lets us
;; anchor at an admin role and walk upstream to discover sources without
;; running an additional Datalog query.

(def ^:private admin-trust-backwards-pull-pattern
  "Anchored at an admin role; pulls inbound trust statements + the principals
  they grant, materializing every immediate predecessor in one round-trip."
  [:role/name :aws/arn :aws/account-id
   {:role/trust-policy
    [:document/key
     :document/kind
     {:document/statement
      [:statement/key
       :statement/effect
       {:statement/action [:action/key]}
       {:statement/principal [:principal/type :principal/value]}
       {:statement/condition
        [:condition/field :condition/operator :condition/value
         {:condition/catalog-key [:condition-key/name]}]}]}]}])

(defn- backwards-trust-edge-from-statement
  [target-role-arn pulled-statement]
  (when (statement-allows-assume-role? pulled-statement)
    (->> (:statement/principal pulled-statement)
         (filter #(= :aws (:principal/type %)))
         (map (fn [p]
                {:source-arn (:principal/value p)
                 :target-arn target-role-arn
                 :statement (:statement/key pulled-statement)
                 :effect (:statement/effect pulled-statement)
                 :actions (mapv :action/key (:statement/action pulled-statement))
                 :conditions (mapv pulled-condition->map
                                   (:statement/condition pulled-statement))})))))

(defn admin-trust-predecessors-via-pull
  "Backwards walk: for an admin role ARN, pull its trust-policy and report
  every (source-arn, statement) pair that grants AssumeRole into it. One
  pull per admin; no Datalog query needed."
  [db admin-role-arn]
  (let [pulled (d/pull db admin-trust-backwards-pull-pattern
                       [:aws/arn admin-role-arn])
        statements (get-in pulled [:role/trust-policy :document/statement])
        edges (into [] (mapcat #(backwards-trust-edge-from-statement admin-role-arn %))
                    statements)]
    {:admin (select-keys pulled [:role/name :aws/arn :aws/account-id])
     :trust-policy-key (get-in pulled [:role/trust-policy :document/key])
     :trust-statements (mapv :statement/key statements)
     :predecessors edges}))

(defn validate-admin-role-chain-paths-with-pull-backwards
  "Reverse-direction validator. For every admin-like role pulls its trust
  policy, materializes inbound (source -> admin) edges from
  `:role/trust-policy → :document/statement → :statement/principal`, then
  filters to inventory-role sources (joined by ARN) and compares the source
  set with the forward `admin-role-chain-paths` result."
  ([db] (validate-admin-role-chain-paths-with-pull-backwards db {}))
  ([db {:keys [account] :as opts}]
   (let [account (some-> account str)
         admins (account-scoped-admin-roles (admin-like-roles db) account)
         inventory-arns (set (d/q '[:find [?arn ...]
                                    :where [?r :role/id _] [?r :aws/arn ?arn]]
                                  db))
         per-admin (mapv
                    (fn [{:keys [role-arn]}]
                      (let [{:keys [predecessors] :as info}
                            (admin-trust-predecessors-via-pull db role-arn)
                            inventory-edges (filterv #(contains? inventory-arns
                                                                 (:source-arn %))
                                                     predecessors)]
                        (assoc info
                               :inventory-predecessor-count (count inventory-edges)
                               :inventory-predecessors inventory-edges)))
                    admins)
         all-edges (mapcat :inventory-predecessors per-admin)
         backwards-source-set (set (map :source-arn all-edges))
         forward (admin-role-chain-paths db (assoc opts :max-depth 1))
         forward-source-set (set (map #(get-in % [:source :arn])
                                      (:results forward)))]
     {:summary {:admin-targets (count admins)
                :backwards-immediate-edges (count all-edges)
                :backwards-source-roles (count backwards-source-set)
                :forward-source-roles (count forward-source-set)
                :sources-only-backwards (count (clojure.set/difference
                                                backwards-source-set forward-source-set))
                :sources-only-forward (count (clojure.set/difference
                                              forward-source-set backwards-source-set))
                :sources-match? (= backwards-source-set forward-source-set)
                :account account}
      :per-admin per-admin
      :only-backwards (vec (sort (clojure.set/difference
                                  backwards-source-set forward-source-set)))
      :only-forward (vec (sort (clojure.set/difference
                                forward-source-set backwards-source-set)))})))

(def ^:private admin-pass-role-backwards-pull-pattern
  "Anchored at a permission statement; reverse-walks document → policy → role
  to recover every source role that owns this iam:PassRole grant."
  [:statement/key
   :statement/effect
   {:statement/action [:action/key]}
   {:statement/resource [:resource/arn]}
   {:statement/condition
    [:condition/field :condition/operator :condition/value
     {:condition/catalog-key [:condition-key/name]}]}
   {:document/_statement
    [:document/key :document/kind
     {:policy/_document
      [:policy/key :policy/name :policy/type
       {:role/_inline-policy [:role/id :role/name :aws/arn :aws/account-id]}
       {:role/_attached-policy [:role/id :role/name :aws/arn :aws/account-id]}]}]}])

(defn- pass-role-statement-keys-covering-target
  "Datalog-side filter: every Allow/iam:PassRole statement whose resource
  either equals `target-arn` exactly or is a wildcard pattern that may match.
  Wildcard match is rechecked in Clojure to avoid regex in Datalog."
  [db target-arn]
  (let [explicit (d/q '[:find [?stmt-key ...]
                        :in $ ?target-arn
                        :where
                        [?stmt :statement/effect :allow]
                        [?stmt :statement/action ?a]
                        [?a :action/key ?ak]
                        [(contains? #{"iam:passrole" "iam:*" "*"} ?ak)]
                        [?stmt :statement/resource ?r]
                        [?r :resource/arn ?target-arn]
                        [?stmt :statement/key ?stmt-key]]
                      db target-arn)
        wildcard-rows (d/q '[:find ?stmt-key ?resource-arn
                             :where
                             [?stmt :statement/effect :allow]
                             [?stmt :statement/action ?a]
                             [?a :action/key ?ak]
                             [(contains? #{"iam:passrole" "iam:*" "*"} ?ak)]
                             [?stmt :statement/resource ?r]
                             [?r :resource/arn ?resource-arn]
                             [(clojure.string/includes? ?resource-arn "*")]
                             [?stmt :statement/key ?stmt-key]]
                           db)
        wildcard-matching (->> wildcard-rows
                               (filter (fn [[_ rarn]]
                                         (wildcard-matches? rarn target-arn)))
                               (mapv first))]
    (vec (distinct (concat explicit wildcard-matching)))))

(defn admin-pass-role-predecessors-via-pull
  "Backwards walk: for an admin role ARN, finds every iam:PassRole permission
  statement whose Resource covers that ARN (Datalog), then a single pull per
  statement reverse-walks `:document/_statement → :policy/_document →
  :role/_inline-policy / :role/_attached-policy` to recover the source roles
  that own the grant. One DB round-trip per matching statement."
  [db admin-role-arn]
  (let [stmt-keys (pass-role-statement-keys-covering-target db admin-role-arn)
        pulled (mapv #(d/pull db admin-pass-role-backwards-pull-pattern
                              [:statement/key %])
                     stmt-keys)
        edges (for [stmt   pulled
                    doc    (:document/_statement stmt)
                    policy (:policy/_document doc)
                    owner  (concat (:role/_inline-policy policy)
                                   (:role/_attached-policy policy))
                    :let [edge-kind (if (some #(= (:role/id %) (:role/id owner))
                                              (:role/_inline-policy policy))
                                      :inline
                                      :attached)]]
                {:source-arn (:aws/arn owner)
                 :source-name (:role/name owner)
                 :source-account (:aws/account-id owner)
                 :target-arn admin-role-arn
                 :statement (:statement/key stmt)
                 :resource-arns (mapv :resource/arn (:statement/resource stmt))
                 :policy-key (:policy/key policy)
                 :edge-kind edge-kind
                 :passed-to-services (statement-passed-to-services-from-pulled stmt)})]
    {:admin-arn admin-role-arn
     :statements stmt-keys
     :predecessors (vec edges)}))

(defn validate-admin-pass-role-paths-with-pull-backwards
  "Reverse-direction validator for iam:PassRole. For every admin role finds
  permission statements whose Resource covers its ARN, then per-statement
  reverse-pulls owners. Restricts to same-account source roles to mirror the
  forward expansion semantics, and compares source/target sets with the
  forward `admin-pass-role-paths` result."
  ([db] (validate-admin-pass-role-paths-with-pull-backwards db {}))
  ([db {:keys [account] :as opts}]
   (let [account (some-> account str)
         admins (account-scoped-admin-roles (admin-like-roles db) account)
         per-admin (mapv
                    (fn [{:keys [role-arn role-account]}]
                      (let [{:keys [predecessors] :as info}
                            (admin-pass-role-predecessors-via-pull db role-arn)
                            same-account
                            (filterv #(= role-account (:source-account %))
                                     predecessors)]
                        (assoc info
                               :same-account-predecessor-count (count same-account)
                               :same-account-predecessors same-account)))
                    admins)
         backwards-pairs (set
                          (for [a per-admin
                                p (:same-account-predecessors a)]
                            [(:source-arn p) (:target-arn p)]))
         forward (admin-pass-role-paths db opts)
         forward-pairs (set (map #(vector (get-in % [:source :arn])
                                          (get-in % [:admin :arn]))
                                 (:results forward)))]
     {:summary {:admin-targets (count admins)
                :backwards-edges (count (mapcat :same-account-predecessors per-admin))
                :backwards-source-target-pairs (count backwards-pairs)
                :forward-source-target-pairs (count forward-pairs)
                :pairs-only-backwards (count (clojure.set/difference
                                              backwards-pairs forward-pairs))
                :pairs-only-forward (count (clojure.set/difference
                                            forward-pairs backwards-pairs))
                :pairs-match? (= backwards-pairs forward-pairs)
                :account account}
      :per-admin per-admin
      :only-backwards (vec (sort (clojure.set/difference
                                  backwards-pairs forward-pairs)))
      :only-forward (vec (sort (clojure.set/difference
                                forward-pairs backwards-pairs)))})))

(defn pass-role-graph
  "All identity-policy iam:PassRole edges with role ARN resources, derived from
  policy documents."
  [db]
  (->> (pass-role-edges db)
       (map (fn [{:keys [source-name source-arn target-name target-arn service]}]
              {:source source-name
               :source-arn source-arn
               :target target-name
               :target-arn target-arn
               :service service}))
       distinct
       vec))

(defn roles-with-pass-role-to
  "Roles with identity-policy iam:PassRole permission to the target role ARN."
  [db target-role-arn]
  (->> (pass-role-edges db)
       (filter #(= target-role-arn (:target-arn %)))
       (map (fn [{:keys [source-name source-arn target-name target-arn service permission-statement]}]
              {:source source-name
               :source-arn source-arn
               :target target-name
               :target-arn target-arn
               :service service
               :statement permission-statement}))
       distinct
       vec))

(defn require-cli-option!
  [opts k]
  (when-not (seq (str (get opts k)))
    (throw (ex-info (str "--" (name k) " is required") {:option k :opts opts}))))

(defn print-json!
  [value]
  (println (json/generate-string value {:pretty true})))

(defn envelope
  "Stable JSON shape for every read-side `bb -x` subcommand.

  Inputs:
    opts     CLI opts map (must contain :db).
    command  Subcommand name, e.g. \"iam/admin-role-chain-paths\".
    result   Either:
               - a map with `:results` key — its other keys become `:summary`;
               - a coll — becomes `:results` with `:summary {:count N}`;
               - any other value — becomes `:results [value]` with `:summary {:count 1}`.

  Returns a map of the shape `{:command :db :summary :results}`."
  [opts command result]
  (let [base {:command command :db (:db opts)}]
    (cond
      (and (map? result) (contains? result :results))
      (assoc base
             :summary (dissoc result :results)
             :results (vec (:results result)))

      (coll? result)
      (assoc base :summary {:count (count result)} :results (vec result))

      :else
      (assoc base :summary {:count 1} :results [result]))))

(defn print-envelope!
  [opts command result]
  (print-json! (envelope opts command result)))

(defn with-db-value
  [opts f]
  (require-cli-option! opts :db)
  (let [conn (get-conn (:db opts))]
    (try
      (f (d/db conn))
      (finally
        (close-conn! conn)))))

(def read-cli-spec
  {:db {:ref "<path>" :desc "Datalevin database path." :require true}
   :arn {:ref "<arn>" :desc "Role ARN."}
   :account {:ref "<account-id>" :desc "Limit role-chain search to one AWS account."}
   :service {:ref "<service-principal>" :desc "AWS service principal."}
   :max-depth {:ref "<n>" :desc "Maximum AssumeRole hops for path queries." :coerce :long}
   :max-results {:ref "<n>" :desc "Cap on returned paths (after deterministic sort)." :coerce :long}
   :prefix {:ref "<action-prefix>" :desc "IAM action key prefix."}})

(defn who-can-assume!
  "Print principals that can assume a target role from trust-policy edges."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! (assoc opts :arn arn) "iam/who-can-assume"
                      (roles-that-can-assume % arn))))

(defn who-can-be-assumed!
  "Print roles whose trust policies include the source role/principal ARN."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! opts "iam/who-can-be-assumed"
                      (roles-that-can-be-assumed-by % arn))))

(defn assumable-by-service!
  "Print roles assumable by a service principal."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [service] :as opts}]
  (require-cli-option! opts :service)
  (with-db-value opts
    #(print-envelope! opts "iam/assumable-by-service"
                      (roles-assumable-by-service % service))))

(defn assume-role-graph!
  "Print all materialized trust-policy AssumeRole edges."
  {:org.babashka/cli {:spec read-cli-spec}}
  [opts]
  (with-db-value opts
    #(print-envelope! opts "iam/assume-role-graph" (assume-role-graph %))))

(defn assume-role-reachable!
  "Print transitive role-to-role trust reachability from a role ARN."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! opts "iam/assume-role-reachable"
                      (assume-role-reachable % arn))))

(defn admin-role-chain-paths!
  "Print role-to-role AssumeRole paths into admin-like roles."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [max-depth account max-results] :as opts}]
  (with-db-value opts
    #(print-envelope! opts "iam/admin-role-chain-paths"
                      (admin-role-chain-paths % {:max-depth max-depth
                                                 :account account
                                                 :max-results max-results}))))

(defn admin-pass-role-paths!
  "Print iam:PassRole paths into admin-like roles."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [account max-results] :as opts}]
  (with-db-value opts
    #(print-envelope! opts "iam/admin-pass-role-paths"
                      (admin-pass-role-paths % {:account account
                                                :max-results max-results}))))

(defn validate-admin-path-entities!
  "Validate admin path evidence against service-reference metadata."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [max-depth account] :as opts}]
  (with-db-value opts
    (fn [db]
      (let [report (validate-admin-path-entities db {:max-depth max-depth
                                                     :account account})]
        (print-envelope! opts "iam/validate-admin-path-entities"
                         (-> report
                             (assoc :results (:issues report))
                             (dissoc :issues)))))))

(defn validate-admin-role-chain-paths-with-pull!
  "Validate AssumeRole elevation paths via the Datalevin pull API."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [max-depth account max-results] :as opts}]
  (with-db-value opts
    #(print-envelope!
      opts "iam/validate-admin-role-chain-paths-with-pull"
      (validate-admin-role-chain-paths-with-pull
       % {:max-depth max-depth :account account :max-results max-results}))))

(defn validate-admin-pass-role-paths-with-pull!
  "Validate iam:PassRole elevation paths via the Datalevin pull API."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [account max-results] :as opts}]
  (with-db-value opts
    #(print-envelope!
      opts "iam/validate-admin-pass-role-paths-with-pull"
      (validate-admin-pass-role-paths-with-pull
       % {:account account :max-results max-results}))))

(defn validate-admin-role-chain-paths-with-pull-backwards!
  "Backwards (target-anchored) AssumeRole validator using reverse-ref pull."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [account] :as opts}]
  (with-db-value opts
    #(print-envelope!
      opts "iam/validate-admin-role-chain-paths-with-pull-backwards"
      (validate-admin-role-chain-paths-with-pull-backwards
       % {:account account}))))

(defn validate-admin-pass-role-paths-with-pull-backwards!
  "Backwards (target-anchored) iam:PassRole validator using reverse-ref pull."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [account] :as opts}]
  (with-db-value opts
    #(print-envelope!
      opts "iam/validate-admin-pass-role-paths-with-pull-backwards"
      (validate-admin-pass-role-paths-with-pull-backwards
       % {:account account}))))

(defn pass-role-graph!
  "Print all materialized iam:PassRole edges."
  {:org.babashka/cli {:spec read-cli-spec}}
  [opts]
  (with-db-value opts
    #(print-envelope! opts "iam/pass-role-graph" (pass-role-graph %))))

(defn roles-with-pass-role-to!
  "Print source roles that can PassRole the target role ARN."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! opts "iam/roles-with-pass-role-to"
                      (roles-with-pass-role-to % arn))))

(defn role-policies!
  "Print all policies reachable from a role ARN."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! opts "iam/role-policies" (role-all-policies % arn))))

(defn role-actions!
  "Print Allow action keys granted to a role ARN."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [arn] :as opts}]
  (require-cli-option! opts :arn)
  (with-db-value opts
    #(print-envelope! opts "iam/role-actions" (role-allowed-actions % arn))))

(defn policy-attachments!
  "Print all managed-policy attachment pairs."
  {:org.babashka/cli {:spec read-cli-spec}}
  [opts]
  (with-db-value opts
    #(print-envelope! opts "iam/policy-attachments" (policy-attachments %))))

(defn policies-by-action!
  "Print managed policies that allow actions with an action-prefix."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [prefix] :as opts}]
  (require-cli-option! opts :prefix)
  (with-db-value opts
    #(print-envelope! opts "iam/policies-by-action" (policies-by-action % prefix))))

(defn stats!
  "Print a complete summary of the IAM Datalevin graph."
  {:org.babashka/cli {:spec read-cli-spec}}
  [{:keys [db] :as opts}]
  (require-cli-option! opts :db)
  (let [conn (get-conn db)]
    (try
      (let [stats (update (db-stats (d/db conn)) :database merge (db-file-stats db))]
        (print-envelope! opts "iam/stats"
                         {:results [stats]
                          :counts (select-keys stats [:roles :policies :statements
                                                      :actions :resources :conditions])}))
      (finally
        (close-conn! conn)))))

(defn jsonl-records
  "Return a streaming reducible of parsed non-blank JSONL records."
  [source reader]
  (eduction
   (keep-indexed (fn [idx line]
                   (parse-jsonl-record source idx line)))
   (line-seq reader)))

(defn with-jsonl-records
  "Continuation-passing wrapper that owns the reader lifetime for JSONL streams."
  [source input k]
  (with-open [reader (io/reader input)]
    (k (jsonl-records source reader))))

(defn load-config!
  "Load one AWS CLI JSON file containing Config configuration item output."
  {:org.babashka/cli
   {:args->opts [:file]
    :spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :file {:ref "<file.json>" :desc "Positional AWS Config JSON file." :alias :f :require true}}}}
  [{:keys [db file]}]
  (require-cli-option! {:db db :file file} :db)
  (require-cli-option! {:db db :file file} :file)
  (let [conn (get-conn db)]
    (try
      {:file file
       :result (load-config-json! conn (read-json-file file)
                                  {:source-file file
                                   :imported-at (java.util.Date.)
                                   :reload? true})}
      (finally
        (close-conn! conn)))))

(defn load-policy!
  "Load one AWS CLI JSON file containing an IAM policy document or policy-version output."
  {:org.babashka/cli
   {:args->opts [:file]
    :spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :file {:ref "<file.json>" :desc "Positional IAM policy JSON file." :alias :f :require true}
           :policy-arn {:ref "<arn>" :desc "Policy ARN when the file does not contain one."}
           :policy-name {:ref "<name>" :desc "Policy name override."}
           :policy-type {:ref "<kind>" :desc "Policy type keyword." :coerce :keyword}
           :version-id {:ref "<id>" :desc "Policy version id override."}
           :default {:desc "Mark this policy version as default." :coerce :boolean}}}}
  [{:keys [db file] :as opts}]
  (require-cli-option! opts :db)
  (require-cli-option! opts :file)
  (let [conn (get-conn db)]
    (try
      {:file file
       :result (load-iam-policy-json! conn (read-json-file file)
                                      (assoc opts
                                             :source-file file
                                             :imported-at (java.util.Date.)
                                             :reload? true))}
      (finally
        (close-conn! conn)))))

(defn load-service-reference!
  "Load one current AWS service authorization reference JSON file."
  {:org.babashka/cli
   {:args->opts [:file]
    :spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :file {:ref "<file.json>" :desc "Positional service-reference JSON file." :alias :f :require true}
           :source-url {:ref "<url>" :desc "Source URL for provenance."}}}}
  [{:keys [db file] :as opts}]
  (require-cli-option! opts :db)
  (require-cli-option! opts :file)
  (let [conn (get-conn db)]
    (try
      {:file file
       :result (load-service-reference-json! conn
                                             (read-json-file file)
                                             (assoc opts
                                                    :source-file file
                                                    :imported-at (java.util.Date.)
                                                    :reload? true))}
      (finally
        (close-conn! conn)))))

(defn- json-files-in
  "Recursively list .json files under dir, sorted by path."
  [dir]
  (->> (fs/glob dir "**")
       (filter fs/regular-file?)
       (filter #(str/ends-with? (str/lower-case (str (fs/file-name %))) ".json"))
       (sort-by str)
       (mapv fs/file)))

(defn- load-dir!
  "Iterate JSON files under dir, calling (f conn file) per file. Errors are
  caught and reported per file so a single bad CI does not abort the import."
  [conn dir per-file]
  (let [files (json-files-in dir)
        n     (count files)]
    (loop [files files, i 0, ok 0, errors []]
      (if-let [file (first files)]
        (let [fname (fs/file-name file)
              [ok' err]
              (try (per-file conn file) [(inc ok) nil]
                   (catch Exception e
                     (binding [*out* *err*]
                       (println (format "[%d/%d] SKIP %s: %s"
                                        (inc i) n fname (ex-message e))))
                     [ok {:file (str file) :error (ex-message e)}]))]
          (when (nil? err)
            (println (format "[%d/%d] %s" (inc i) n fname)))
          (recur (rest files) (inc i) ok' (if err (conj errors err) errors)))
        {:dir dir :total n :loaded ok :errors errors}))))

(defn- phases->entities
  "Flatten decorated tx phases into a single entity vector. Used only when
  ordering across phases is not required."
  [phases]
  (vec (mapcat identity phases)))

(defn- config-phases-for-source
  [json-value source-file imported-at]
  (let [opts {:source-file source-file :imported-at imported-at}]
    (decorate-phases (config-json-tx-phases json-value) opts)))

(defn- service-reference-phases-for-source
  [json-value source-file imported-at extra-opts]
  (let [opts (assoc extra-opts :source-file source-file :imported-at imported-at)]
    (decorate-phases (service-reference-json->tx-phases json-value opts) opts)))

(defn- transact-phase-batch!
  "Transact one phase's accumulated entities. On failure, fall back to
  per-file txes for that phase to localize the offender. Returns metrics."
  [conn phase-idx ents per-file-meta]
  (when (seq ents)
    (try
      (let [report (d/transact! conn (inject-entity-types ents))]
        {:phase phase-idx
         :entities (count ents)
         :datoms (count (:tx-data report))
         :files (count per-file-meta)
         :fallback? false})
      (catch Exception e
        (binding [*out* *err*]
          (println (format "PHASE %d BATCH FAIL (%d entities, %d files): %s — falling back to per-file"
                           phase-idx (count ents) (count per-file-meta) (ex-message e))))
        (let [salvaged (atom 0)]
          (doseq [{:keys [file entities]} per-file-meta]
            (when (seq entities)
              (try
                (d/transact! conn (inject-entity-types entities))
                (swap! salvaged inc)
                (catch Exception e2
                  (binding [*out* *err*]
                    (println (format "  SKIP %s phase %d: %s" file phase-idx (ex-message e2))))))))
          {:phase phase-idx
           :entities (count ents)
           :files (count per-file-meta)
           :files-salvaged @salvaged
           :fallback? true})))))

(defn- flush-phase-buffers!
  "Flush phase buffers in ascending phase order so within-file dependencies
  (relationship phases referencing catalog phases via lookup-refs) are
  satisfied. Cross-file dependencies are unconstrained because shared
  catalog entities are upserted via `:db.unique/identity`."
  [conn buffers metas]
  (vec
   (keep identity
         (map-indexed (fn [idx ents]
                        (transact-phase-batch! conn idx ents (nth metas idx)))
                      buffers))))

(defn- load-dir-batched!
  "Iterate JSON files under `dir`, build each file's *phases* via
  `(build-phases json-value source-file)`, and accumulate them into
  per-phase-index buffers. Once the total accumulated entity count crosses
  `:batch-datoms`, flush all buffers in phase order in a small number of
  large `d/transact!` calls (1 per non-empty phase)."
  [conn dir build-phases {:keys [batch-datoms] :or {batch-datoms 50000}}]
  (let [files (json-files-in dir)
        n (count files)
        n-phases (atom 0)
        buffers (atom [])
        metas (atom [])
        ok (volatile! 0)
        errors (volatile! [])
        flushes (volatile! [])
        ensure-size! (fn [k]
                       (when (< @n-phases k)
                         (let [pad (- k @n-phases)]
                           (swap! buffers into (repeat pad []))
                           (swap! metas into (repeat pad []))
                           (reset! n-phases k))))
        total-size (fn [] (reduce + 0 (map count @buffers)))
        flush! (fn []
                 (when (pos? (total-size))
                   (vswap! flushes into (flush-phase-buffers! conn @buffers @metas))
                   (reset! buffers (vec (repeat @n-phases [])))
                   (reset! metas (vec (repeat @n-phases [])))))]
    (doseq [[idx file] (map-indexed vector files)]
      (let [fname (fs/file-name file)]
        (try
          (let [phases (build-phases (read-json-file file) (str file))
                k (count phases)
                ent-count (reduce + 0 (map count phases))]
            (ensure-size! k)
            (doseq [[i phase] (map-indexed vector phases)]
              (swap! buffers update i into phase)
              (swap! metas update i conj {:file (str file) :entities phase}))
            (vswap! ok inc)
            (println (format "[%d/%d] %s (%d phases, +%d entities, buf=%d)"
                             (inc idx) n fname k ent-count (total-size)))
            (when (>= (total-size) batch-datoms)
              (flush!)))
          (catch Exception e
            (binding [*out* *err*]
              (println (format "[%d/%d] SKIP %s: %s" (inc idx) n fname (ex-message e))))
            (vswap! errors conj {:file (str file) :error (ex-message e)})))))
    (flush!)
    {:dir dir
     :total n
     :loaded @ok
     :errors @errors
     :batches (vec @flushes)}))

(defn load-specs-dir!
  "Bulk-load every AWS service-reference JSON file under a directory."
  {:org.babashka/cli
   {:spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :dir {:ref "<dir>" :desc "Service-reference dir. Defaults to $IAM_RESOURCE_SPEC."}
           :batch-datoms {:ref "<n>" :desc "Entities per phase tx batch (default 50000)." :coerce :long}}}}
  [{:keys [db dir batch-datoms] :as opts}]
  (require-cli-option! opts :db)
  (let [dir (or dir (System/getenv "IAM_RESOURCE_SPEC"))]
    (when-not dir
      (throw (ex-info "--dir required (or set $IAM_RESOURCE_SPEC)" {})))
    (let [conn (get-conn db)
          now  (java.util.Date.)
          extra-opts (dissoc opts :db :dir :batch-datoms)]
      (try
        (load-dir-batched!
         conn dir
         (fn [json-value source-file]
           (service-reference-phases-for-source json-value source-file now extra-opts))
         {:batch-datoms (or batch-datoms 50000)})
        (finally (close-conn! conn))))))

(defn load-config-dir!
  "Bulk-load every AWS Config CI JSON file under a directory tree."
  {:org.babashka/cli
   {:spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :dir {:ref "<dir>" :desc "Config CI dir. Defaults to $IAM_RESOURCE_DATA."}
           :batch-datoms {:ref "<n>" :desc "Entities per phase tx batch (default 50000)." :coerce :long}}}}
  [{:keys [db dir batch-datoms] :as opts}]
  (require-cli-option! opts :db)
  (let [dir (or dir (System/getenv "IAM_RESOURCE_DATA"))]
    (when-not dir
      (throw (ex-info "--dir required (or set $IAM_RESOURCE_DATA)" {})))
    (let [conn (get-conn db)
          now  (java.util.Date.)]
      (try
        (load-dir-batched!
         conn dir
         (fn [json-value source-file]
           (config-phases-for-source json-value source-file now))
         {:batch-datoms (or batch-datoms 50000)})
        (finally (close-conn! conn))))))

(defn load-all!
  "Load specs ($IAM_RESOURCE_SPEC) then config CIs ($IAM_RESOURCE_DATA)."
  {:org.babashka/cli
   {:spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :specs-dir {:ref "<dir>" :desc "Override $IAM_RESOURCE_SPEC."}
           :config-dir {:ref "<dir>" :desc "Override $IAM_RESOURCE_DATA."}}}}
  [{:keys [db specs-dir config-dir] :as opts}]
  (require-cli-option! opts :db)
  {:specs  (load-specs-dir!  {:db db :dir specs-dir})
   :config (load-config-dir! {:db db :dir config-dir})})

(defn policy-line-opts
  [batch-opts value]
  (merge batch-opts
         (when (map? value)
           (select-keys value [:policy-arn :policyArn :PolicyArn
                               :policy-name :policyName :PolicyName
                               :policy-type :version-id :versionId :VersionId
                               :default :default? :create-date]))))

(def batch-cli-spec
  {:db {:ref "<path>" :desc "Datalevin database path."}
   :file {:ref "<file.jsonl>" :desc "Optional jq-preprocessed JSONL input file. Reads stdin when omitted." :alias :f}
   :policy-arn {:ref "<arn>" :desc "Policy ARN fallback for policy JSONL rows."}
   :policy-name {:ref "<name>" :desc "Policy name fallback for policy JSONL rows."}
   :policy-type {:ref "<kind>" :desc "Policy type keyword." :coerce :keyword}
   :version-id {:ref "<id>" :desc "Policy version fallback."}
   :default {:desc "Mark imported policy versions as default." :coerce :boolean}
   :source-url {:ref "<url>" :desc "Source URL for service-reference provenance."}
   :help {:desc "Show help." :alias :h :coerce :boolean}})

(defn usage
  []
  (str "Usage:\n"
       "  bb -x iam-datalog/load-config! --db DB_PATH FILE.json\n"
       "  bb -x iam-datalog/load-policy! --db DB_PATH --policy-arn ARN FILE.json\n"
       "  bb -x iam-datalog/load-service-reference! --db DB_PATH aws/aws-service-reference-s3.json\n"
       "\n"
       "  bb -m iam-datalog load-config --db DB_PATH [FILE.jsonl]\n"
       "  bb -m iam-datalog load-policy --db DB_PATH --policy-arn ARN [FILE.jsonl]\n"
       "  bb -m iam-datalog load-service-reference --db DB_PATH [FILE.jsonl]\n"
       "\n"
       "  bb -x iam-datalog/load-specs-dir!  --db DB_PATH [--dir DIR]   ; defaults to $IAM_RESOURCE_SPEC\n"
       "  bb -x iam-datalog/load-config-dir! --db DB_PATH [--dir DIR]   ; defaults to $IAM_RESOURCE_DATA\n"
       "  bb -x iam-datalog/load-all!        --db DB_PATH               ; specs then config\n"
       "  bb -x iam-datalog/stats!           --db DB_PATH               ; graph stats\n"
       "  bb -x iam-datalog/admin-role-chain-paths! --db DB_PATH [--max-depth N] [--account ACCOUNT_ID]\n"
       "  bb -x iam-datalog/admin-pass-role-paths! --db DB_PATH [--account ACCOUNT_ID]\n"
       "  bb -x iam-datalog/validate-admin-path-entities! --db DB_PATH [--max-depth N] [--account ACCOUNT_ID]\n"
       "\n"
       "  bb -m iam-datalog stats --db DB_PATH\n"
       "\n"
       "Single JSON loads are function calls. -m iam-datalog batch commands expect JSONL rows preprocessed by jq; omit FILE.jsonl to read stdin.\n\n"
       (cli/format-opts {:spec batch-cli-spec
                         :order [:db :file :policy-arn :policy-name :policy-type :version-id :default :source-url :help]})))

(defn batch-load!
  [kind {:keys [db file] :as opts}]
  (require-cli-option! opts :db)
  (let [conn (get-conn db)]
    (try
      (let [file (when (seq (str file)) file)
            source (or file "stdin")
            input (if file (io/file file) *in*)]
        (with-jsonl-records source input
          #(doseq [{:keys [line value]} %]
             (println
              {:file   source
               :line   line
               :result (case kind
                         :config            (load-config-json! conn value)
                         :policy            (load-iam-policy-json! conn value (policy-line-opts opts value))
                         :service-reference (load-service-reference-json! conn value
                                                                          (assoc opts
                                                                                 :source-file source
                                                                                 :imported-at (java.util.Date.))))}))))
      (finally
        (close-conn! conn)))))

(defn batch-dispatch-opts
  [{:keys [opts args]}]
  (when (seq args)
    (throw (ex-info "Only one input file is supported; omit it to read JSONL from stdin"
                    {:args args :opts opts})))
  opts)

(defn batch-load-config!
  [dispatch-opts]
  (batch-load! :config (batch-dispatch-opts dispatch-opts)))

(defn batch-load-policy!
  [dispatch-opts]
  (batch-load! :policy (batch-dispatch-opts dispatch-opts)))

(defn batch-load-service-reference!
  [dispatch-opts]
  (batch-load! :service-reference (batch-dispatch-opts dispatch-opts)))

(defn print-help!
  [_]
  (println (usage)))

(def dispatch-table
  [{:cmds ["load-config"] :fn batch-load-config! :args->opts [:file]}
   {:cmds ["load-policy"] :fn batch-load-policy! :args->opts [:file]}
   {:cmds ["load-service-reference"] :fn batch-load-service-reference! :args->opts [:file]}
   {:cmds ["load-specs-dir"]  :fn (fn [{:keys [opts]}] (load-specs-dir! opts))}
   {:cmds ["load-config-dir"] :fn (fn [{:keys [opts]}] (load-config-dir! opts))}
   {:cmds ["load-all"]        :fn (fn [{:keys [opts]}] (load-all! opts))}
   {:cmds ["stats"]           :fn (fn [{:keys [opts]}] (stats! opts))}
   {:cmds [] :fn print-help!}])

(defn -main
  [& args]
  (try
    (cli/dispatch dispatch-table args {:spec batch-cli-spec})
    (catch clojure.lang.ExceptionInfo e
      (binding [*out* *err*]
        (println (ex-message e))
        (println)
        (println (usage)))
      (System/exit 2))))
