#?(:bb (babashka.pods/load-pod 'huahaiy/datalevin "0.10.7"))

(ns iam
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
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            #?@(:bb [[pod.huahaiy.datalevin :as d]]
                :clj [[datalevin.core :as d]]))
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

(def design-goals
  {:primary :relationship-analysis
   :secondary :lossless-provenance
   :state-model :current-state-plus-provenance
   :principal-model :known-identities-plus-synthetic-policy-principals
   :action-model :raw-patterns-plus-derived-expansion
   :resource-model :raw-patterns-plus-derived-resource-matches
   :authorization-model :analysis-graph-not-full-evaluator
   :non-iam-resource-import :access-analyzer-or-rcp-supported-only
   :rcp-model :first-class-policy-with-organization-attachments
   :condition-key-model :perimeter-catalog-plus-policy-occurrences
   :role-transition-model :assume-role-and-pass-role-as-distinct-edges
   :not-optimized-for :exact-aws-document-reconstruction
   :historical-timeline :defer-until-needed
   :core-questions
   [:who-can-assume-this-role?
    :which-policies-affect-this-role?
    :which-roles-can-perform-this-action?
    :which-config-item-produced-this-relationship?]
   :out-of-scope
   [:final-authorization-decision
    :complete-request-context-evaluation
    :service-specific-authorization-behavior
    :derived-findings]})

(def datalevin-design-notes
  {:use-materialized-edges
   "Recursive role-chain queries should run over :role-transition/* edges, not
   over raw policy-document structure. Datalevin has an efficient recursive rule
   engine, but the base relation should still be the smallest relationship fact
   that answers the graph question."

   :query-shape
   "Prefer many simple indexed attributes and refs. Datalevin has a cost-based
   optimizer, AVE is enabled for all datoms, and clause order is not the tuning
   knob; modeling selective relationship facts is more important."

   :raw-documents
   "Keep raw AWS documents in :db.type/idoc attributes for provenance and path
   search, but do not make raw idoc parsing part of hot role-chain queries."

   :history
   "Datalevin does not keep Datomic-style immutable history, so current-state
   edges plus explicit AWS Config provenance are the right model unless we add a
   separate temporal timeline."})

(def role-transition-actions
  {:assume-role "sts:assumerole"
   :pass-role "iam:passrole"})

(def data-perimeter-condition-keys
  "Condition-key catalog entries that matter first for data perimeter analysis.
  These are source facts about IAM request context keys, not findings."
  [{:condition-key/name "aws:PrincipalAccount"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalArn"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :arn
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalOrgID"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalOrgPaths"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalIsAWSService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :boolean
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalServiceName"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalServiceNamesList"
    :condition-key/category :service-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:PrincipalTag/tag-key"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:ResourceAccount"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceOrgID"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceOrgPaths"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ResourceTag/tag-key"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:SourceIp"
    :condition-key/category :network-perimeter
    :condition-key/value-type :ip
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpcSourceIp"
    :condition-key/category :network-perimeter
    :condition-key/value-type :ip
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpc"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpcArn"
    :condition-key/category :network-perimeter
    :condition-key/value-type :arn
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceVpce"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceAccount"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceOrgID"
    :condition-key/category :network-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:VpceOrgPaths"
    :condition-key/category :network-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:CalledVia"
    :condition-key/category :service-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:CalledViaFirst"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:CalledViaLast"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:ViaAWSService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :boolean
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}

   {:condition-key/name "aws:RequestedRegion"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:RequestTag/tag-key"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:TagKeys"
    :condition-key/category :request-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceAccount"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceArn"
    :condition-key/category :request-perimeter
    :condition-key/value-type :arn
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceOrgID"
    :condition-key/category :request-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? true
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SourceOrgPaths"
    :condition-key/category :request-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :aws-global-doc}
   {:condition-key/name "aws:SecureTransport"
    :condition-key/category :network-perimeter
    :condition-key/value-type :boolean
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :aws-global-doc}

   {:condition-key/name "iam:PassedToService"
    :condition-key/category :service-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:AssociatedResourceArn"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :arn
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:PermissionsBoundary"
    :condition-key/category :identity-perimeter
    :condition-key/value-type :arn
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :iam-service-reference}
   {:condition-key/name "iam:ResourceTag/${TagKey}"
    :condition-key/category :resource-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? true
    :condition-key/source :iam-service-reference}

   {:condition-key/name "sts:ExternalId"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:RoleSessionName"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:SourceIdentity"
    :condition-key/category :session-perimeter
    :condition-key/value-type :string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/source :sts-service-reference}
   {:condition-key/name "sts:TransitiveTagKeys"
    :condition-key/category :session-perimeter
    :condition-key/value-type :array-of-string
    :condition-key/sensitive? false
    :condition-key/pattern? false
    :condition-key/multivalued? true
    :condition-key/source :sts-service-reference}])

(def access-analyzer-supported-resource-types
  "AWS resource types supported by IAM Access Analyzer external/internal access
  analyzers. Keep this list in sync with AWS docs before production imports."
  #{:aws.config/s3-bucket
    :aws.config/s3-directory-bucket
    :aws.config/iam-role
    :aws.config/kms-key
    :aws.config/lambda-function
    :aws.config/lambda-layer
    :aws.config/sqs-queue
    :aws.config/secretsmanager-secret
    :aws.config/sns-topic
    :aws.config/ebs-volume-snapshot
    :aws.config/rds-db-snapshot
    :aws.config/rds-db-cluster-snapshot
    :aws.config/ecr-repository
    :aws.config/efs-file-system
    :aws.config/dynamodb-stream
    :aws.config/dynamodb-table})

(def rcp-supported-services
  "AWS services currently listed by AWS Organizations as supporting Resource
  Control Policies. This is service-level because RCPs apply to authorized
  resources for supported service actions."
  #{"s3"
    "sts"
    "kms"
    "sqs"
    "secretsmanager"
    "cognito"
    "logs"
    "dynamodb"
    "ecr"
    "aoss"})

(def import-scope
  {:iam-resources :always
   :non-iam-resources :access-analyzer-or-rcp-supported-only
   :resource-capability-flags
   [:resource/access-analyzer-supported?
    :resource/rcp-supported?
    :resource/import-reason]})

(def schema
  {:aws/account-id
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

   :principal/origin
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :principal/internal?
   {:db/valueType :db.type/boolean
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

   ;; IAM policies and versions.
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

   :policy/default-version
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :policy/version
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :policy/attachable?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :policy/attachment-count
   {:db/valueType :db.type/long
    :db/cardinality :db.cardinality/one}

   :policy/document
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :policy/attachment-target
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :policy-version/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :policy-version/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :policy-version/default?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :policy-version/create-date
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :policy-version/document
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   ;; Policy documents and statements.
   :document/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :document/kind
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :document/version
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :document/raw
   {:db/valueType :db.type/idoc
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

   :statement/expanded-action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/not-action
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/resource
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :statement/matched-resource
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

   :action/access-analyzer-supported?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :action/last-accessed-supported?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

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

   :resource/import-reason
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :resource/access-analyzer-supported?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :resource/rcp-supported?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :resource/matches
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

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

   :condition-key/operator-family
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :condition-key/sensitive?
   {:db/valueType :db.type/boolean
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

   ;; Role transitions are normalized relationship candidates with source
   ;; evidence. They are not persisted findings or final authorization results.
   :role-transition/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :role-transition/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :role-transition/source-principal
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/source-role
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/target-role
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/delegated-service
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/associated-resource
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :role-transition/permission-statement
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/trust-statement
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :role-transition/condition
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :role-transition/evidence
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   ;; AWS Organizations scope for Resource Control Policies.
   :org/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :org/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :org/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :org/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :org/parent
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :org/account
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :org/attached-policy
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :account/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :account/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :account/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :account/org-node
   {:db/valueType :db.type/ref
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

   :principal-can-assume-role
   {:from :principal/key
    :via [:role-transition/source-principal]
    :to :role/id
    :type :assume-role}

   :role-can-assume-role
   {:from :role/id
    :via [:role-transition/source-role]
    :to :role/id
    :type :assume-role}

   :principal-can-pass-role-to-service
   {:from :principal/key
    :via [:role-transition/source-principal
          :role-transition/target-role
          :role-transition/delegated-service]
    :to [:role/id :principal/key]
    :type :pass-role}

   :org-scope-has-resource-control-policy
   {:from :org/key
    :via [:org/attached-policy]
    :to :policy/key}

   :resource-in-account-affected-by-rcp
   {:from :resource/key
    :via [:aws/account-id :account/id :account/org-node :org/attached-policy]
    :to :policy/key}

   :policy-allows-action-on-resource
   {:from :policy/key
    :via [:policy/default-version
          :policy-version/document
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
            [(identity :attached-managed) ?edge])
       (and [?role :role/inline-policy ?policy]
            [(identity :inline) ?edge]))]

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
     [?version :policy-version/document ?doc]
     [?policy :policy/default-version ?version]
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
            [(identity :attached-managed) ?edge])
       (and [?role :role/inline-policy ?policy]
            [(identity :inline) ?edge])
       (and [?role :role/permissions-boundary ?policy]
            [(identity :permissions-boundary) ?edge]))
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
     [?version :policy-version/document ?doc]
     [?policy :policy/default-version ?version]
     [?policy :policy/name ?policy-name]
     (or [?role :role/attached-policy ?policy]
         [?role :role/inline-policy ?policy])
     [?role :role/name ?role-name]]

   :assume-role-transitions
   '[:find ?source-principal ?source-role ?target-role ?permission-stmt ?trust-stmt
     :where
     [?transition :role-transition/type :assume-role]
     [?transition :role-transition/target-role ?target]
     [?target :role/name ?target-role]
     [?transition :role-transition/permission-statement ?permission]
     [?permission :statement/key ?permission-stmt]
     [?transition :role-transition/trust-statement ?trust]
     [?trust :statement/key ?trust-stmt]
     (or-join [?transition ?source-principal ?source-role]
       (and [?transition :role-transition/source-principal ?principal]
            [?principal :principal/key ?source-principal]
            [(identity :none) ?source-role])
       (and [?transition :role-transition/source-role ?role]
            [?role :role/name ?source-role]
            [(identity :none) ?source-principal]))]

   :assume-role-reachability-to-admin-like-role
   '[:find ?source-name ?admin-name
     :in $ % [?admin-id ...]
     :where
     [?admin :role/id ?admin-id]
     (can-assume ?source ?admin)
     [?source :role/name ?source-name]
     [?admin :role/name ?admin-name]]

   :pass-role-delegations
   '[:find ?source-principal ?target-role ?delegated-service ?associated-resource ?stmt
     :where
     [?transition :role-transition/type :pass-role]
     [?transition :role-transition/source-principal ?principal]
     [?principal :principal/key ?source-principal]
     [?transition :role-transition/target-role ?role]
     [?role :role/name ?target-role]
     [?transition :role-transition/permission-statement ?statement]
     [?statement :statement/key ?stmt]
     (or-join [?transition ?delegated-service]
       (and [?transition :role-transition/delegated-service ?service]
            [?service :principal/key ?delegated-service])
       (and [(identity :unknown) ?delegated-service]))
     (or-join [?transition ?associated-resource]
       (and [?transition :role-transition/associated-resource ?resource]
            [?resource :resource/key ?associated-resource])
       (and [(identity :any) ?associated-resource]))]

   :pass-role-delegations-to-admin-like-role
   '[:find ?source-name ?target-name ?delegated-service ?associated-resource ?stmt
     :in $ [?admin-id ...]
     :where
     [?target :role/id ?admin-id]
     [?target :role/name ?target-name]
     [?transition :role-transition/type :pass-role]
     [?transition :role-transition/target-role ?target]
     [?transition :role-transition/source-role ?source]
     [?source :role/name ?source-name]
     [?transition :role-transition/delegated-service ?service-principal]
     [?service-principal :principal/value ?delegated-service]
     [?transition :role-transition/associated-resource ?resource]
     [?resource :resource/key ?associated-resource]
     [?transition :role-transition/permission-statement ?statement]
     [?statement :statement/key ?stmt]]

   :role-effective-allow-statements
   '[:find ?policy-name ?sid ?action ?resource ?condition
     :in $ ?role-id
     :where
     [?role :role/id ?role-id]
     (or [?role :role/attached-policy ?policy]
         [?role :role/inline-policy ?policy])
     [?policy :policy/name ?policy-name]
     [?policy :policy/default-version ?version]
     [?version :policy-version/document ?doc]
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
       (and [(identity :none) ?condition]))]

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
  '[[(can-assume ?source ?target)
     [?transition :role-transition/type :assume-role]
     [?transition :role-transition/source-role ?source]
     [?transition :role-transition/target-role ?target]]
    [(can-assume ?source ?target)
     [?transition :role-transition/type :assume-role]
     [?transition :role-transition/source-role ?source]
     [?transition :role-transition/target-role ?middle]
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

(defn importable-non-iam-resource?
  "True when a non-IAM resource is in scope for the analysis graph."
  [{:resource/keys [access-analyzer-supported? rcp-supported?]}]
  (boolean (or access-analyzer-supported? rcp-supported?)))

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

(defn policy-version-key
  [policy-key version-id]
  (str policy-key "/version/" version-id))

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

(defn clean-entity
  [m]
  (into {} (remove (comp nil? val) m)))

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
  [principal-type value origin internal?]
  (clean-entity
   {:principal/key (principal-key principal-type value)
    :principal/type principal-type
    :principal/value value
    :principal/origin origin
    :principal/internal? internal?}))

(defn role-entity-from-config
  [ci]
  (let [c (:configuration ci)
        arn (:arn c)
        role-id (:roleId c)
        role-name (:roleName c)]
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
             :condition-key/pattern? false
             :condition-key/sensitive? false}
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
              {:condition/key (str statement-key "/condition/" operator "/" normalized)
               :condition/catalog-key [:condition-key/name normalized]
               :condition/operator (name operator)
               :condition/field (name field)
               :condition/value {:value value}
               :condition/perimeter? (perimeter-condition-key? (name field))}))
          fields))
   condition-map))

(defn principal-values
  [principal]
  (cond
    (nil? principal) []
    (= "*" principal) [[:star "*"]]
    (string? principal) [[:aws principal]]
    (map? principal)
    (mapcat (fn [[k v]]
              (let [principal-type (case k
                                     :AWS :aws
                                     :Service :service
                                     :Federated :federated
                                     :CanonicalUser :canonical-user
                                     (keyword (str/lower-case (name k))))]
                (map #(vector principal-type %) (ensure-vector v))))
            principal)
    :else []))

(defn statement-tx
  [document-key idx statement]
  (let [sid (or (:Sid statement) (str "Statement" idx))
        statement-key (str document-key "/statement/" idx)
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
                      (principal-entity principal-type value :policy-reference false))
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
  (let [document (parse-jsonish raw-document)
        statements (mapv (fn [idx statement]
                           (statement-tx document-key idx statement))
                         (range)
                         (ensure-vector (:Statement document)))]
    [(vec (mapcat :phase-1 statements))
     (vec (mapcat :phase-2 statements))
     (vec (mapcat :phase-3 statements))
     [{:document/key document-key
       :document/kind document-kind
       :document/version (:Version document)
       :document/raw document
       :document/statement (mapv #(vector :statement/key (:statement/key %))
                                 (mapcat :phase-3 statements))}]]))

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
        inline-version-entities
        (mapv (fn [p]
                (let [pkey (inline-policy-key role-arn (:policyName p))
                      version-key (policy-version-key pkey "inline")
                      doc-key (str pkey "/document")]
                  (clean-entity
                   {:policy-version/key version-key
                    :policy-version/id "inline"
                    :policy-version/default? true
                    :policy-version/document [:document/key doc-key]})))
              inline)
        inline-policy-final-entities
        (mapv (fn [p]
                (let [pkey (inline-policy-key role-arn (:policyName p))
                      version-key (policy-version-key pkey "inline")]
                  {:policy/key pkey
                   :policy/default-version [:policy-version/key version-key]
                   :policy/version [[:policy-version/key version-key]]}))
              inline)
        trust-phases (when trust-doc
                       (policy-document-tx trust-key :trust-policy trust-doc))]
    (apply merge-phases
           [(vec (concat
                  [role
                   (principal-entity :aws role-arn :inventory true)]
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
            inline-version-entities
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
        pkey (:arn c)
        versions (ensure-vector (:policyVersionList c))
        version-phases
        (mapv (fn [v]
                (let [version-id (:versionId v)
                      version-key (policy-version-key pkey version-id)
                      doc-key (str version-key "/document")
                      doc (or (first (:document v)) (:document v))]
                  {:doc-phases (policy-document-tx doc-key :managed-policy doc)
                   :version (clean-entity
                             {:policy-version/key version-key
                              :policy-version/id version-id
                              :policy-version/default? (:isDefaultVersion v)
                              :policy-version/create-date (parse-aws-instant (:createDate v))
                              :policy-version/document [:document/key doc-key]})}))
              versions)
        default-version (some #(when (:isDefaultVersion %) %) versions)]
    [(vec [(policy-shell pkey (:policyName c) :managed)])
     (vec (mapcat #(nth (:doc-phases %) 0) version-phases))
     (vec (mapcat #(nth (:doc-phases %) 1) version-phases))
     (vec (mapcat #(nth (:doc-phases %) 2) version-phases))
     (vec (mapcat #(nth (:doc-phases %) 3) version-phases))
     (vec (map :version version-phases))
     [(clean-entity
       {:policy/key pkey
        :policy/id (:policyId c)
        :policy/name (:policyName c)
        :policy/type :managed
        :policy/attachable? (:isAttachable c)
        :policy/attachment-count (:attachmentCount c)
        :policy/default-version (when default-version
                                  [:policy-version/key (policy-version-key pkey (:versionId default-version))])
        :policy/version (mapv #(vector :policy-version/key (policy-version-key pkey (:versionId %)))
                              versions)})
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
        version-id (or (:version-id opts) (:versionId opts) (:VersionId opts)
                       (:versionId v) (:VersionId v) (:VersionId policy-version)
                       (:versionId policy-version) "v1")
        pkey (if role
               (trust-policy-key (or (:Arn role) (:arn role)))
               policy-arn)
        doc-key (str pkey "/version/" version-id "/document")
        doc-phases (policy-document-tx doc-key policy-type document)
        version-key (policy-version-key pkey version-id)]
    (when-not pkey
      (throw (ex-info "IAM policy import requires :policy-arn or a JSON file containing Policy.Arn or Role.Arn"
                      {:opts opts})))
    (merge-phases
     [[(policy-shell pkey policy-name policy-type)]
      []
      []
      []
      [(clean-entity
        {:policy-version/key version-key
         :policy-version/id version-id
         :policy-version/default? (boolean (or (:default? opts) (:default opts)
                                               (:IsDefaultVersion policy-version)
                                               (:isDefaultVersion policy-version)))
         :policy-version/create-date (parse-aws-instant (or (:CreateDate policy-version)
                                                            (:createDate policy-version)
                                                            (:create-date opts)))
         :policy-version/document [:document/key doc-key]})]
      [{:policy/key pkey
        :policy/name policy-name
        :policy/type policy-type
        :policy/default-version [:policy-version/key version-key]
        :policy/version [[:policy-version/key version-key]]}]]
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
      :action/source [:service-reference]
      :action/access-analyzer-supported? (supported-by? action "IAM Access Analyzer Policy Generation")
      :action/last-accessed-supported? (supported-by? action "IAM Action Last Accessed")})))

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
                                       resources)
          :service/condition-key (mapv #(vector :condition-key/name (service-condition-key (:Name %)))
                                       conditions)})]
     [[service-entity]
      (vec (concat
            (map #(service-condition-entity service-prefix %) conditions)
            referenced-condition-entities
            (map #(service-action-entity service-prefix %) actions)
            (map service-dependent-action-entity dependent-action-names)
            (map #(service-resource-entity service-prefix %) resources)))
      (vec (concat
            [service-relationship-entity]
            (map #(service-action-relationship-entity service-prefix %) actions)
            (map #(service-resource-relationship-entity service-prefix %) resources)))]))

(defn transact-phases!
  [conn phases]
  (doseq [phase phases
          :when (seq phase)]
    (d/transact! conn phase))
  {:phase-count (count phases)
   :datom-groups (mapv count phases)})

(defn get-conn
  [db-path]
  (d/get-conn db-path schema))

(defn load-config-json!
  [conn json-value]
  (transact-phases! conn (config-json-tx-phases json-value)))

(defn load-iam-policy-json!
  [conn json-value opts]
  (transact-phases! conn (iam-policy-json->tx-phases json-value opts)))

(defn load-service-reference-json!
  [conn json-value opts]
  (transact-phases! conn (service-reference-json->tx-phases json-value opts)))

(defn close-conn!
  [conn]
  (d/close conn))

(defn require-cli-option!
  [opts k]
  (when-not (seq (str (get opts k)))
    (throw (ex-info (str "--" (name k) " is required") {:option k :opts opts}))))

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
       :result (load-config-json! conn (read-json-file file))}
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
       :result (load-iam-policy-json! conn (read-json-file file) opts)}
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
                                                    :imported-at (java.util.Date.)))}
      (finally
        (close-conn! conn)))))

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
       "  bb -x iam/load-config! --db DB_PATH FILE.json\n"
       "  bb -x iam/load-policy! --db DB_PATH --policy-arn ARN FILE.json\n"
       "  bb -x iam/load-service-reference! --db DB_PATH aws/aws-service-reference-s3.json\n"
       "\n"
       "  bb -m iam load-config --db DB_PATH [FILE.jsonl]\n"
       "  bb -m iam load-policy --db DB_PATH --policy-arn ARN [FILE.jsonl]\n"
       "  bb -m iam load-service-reference --db DB_PATH [FILE.jsonl]\n"
       "\n"
       "Single JSON loads are function calls. -m iam batch commands expect JSONL rows preprocessed by jq; omit FILE.jsonl to read stdin.\n\n"
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
