(babashka.pods/load-pod 'replikativ/datahike "0.8.1678")

(ns iam-datahike-test
  (:require [babashka.process :as process]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.set]
            [clojure.test :refer [deftest is run-tests testing]]
            [clojure.string :as str]
            [datahike.pod :as d]
            [iam-datahike :as iam]))

(def account-id "123456789012")
(def role-id "AROADATAHIKETEST")
(def role-name "DatahikeTestRole")
(def role-arn (str "arn:aws:iam::" account-id ":role/" role-name))
(def policy-arn (str "arn:aws:iam::" account-id ":policy/DatahikeManagedPolicy"))

(def skill-dir
  (io/file (.getParent (io/file *file*))))

(defn role-config
  [{:keys [state-id capture-time role-name tags]
    :or {role-name role-name
         tags [{:key "env" :value "dev"}]}}]
  {:configurationItems
   [{:accountId account-id
     :awsRegion "us-east-1"
     :resourceType "AWS::IAM::Role"
     :resourceId role-id
     :resourceName role-name
     :configurationStateId state-id
     :configurationItemCaptureTime capture-time
     :configurationItemStatus "OK"
     :configuration
     {:arn role-arn
      :roleId role-id
      :roleName role-name
      :path "/"
      :tags tags
      :createDate "2026-04-24T10:00:00Z"
      :assumeRolePolicyDocument
      {:Version "2012-10-17"
       :Statement [{:Sid "TrustRoot"
                    :Effect "Allow"
                    :Principal {:AWS (str "arn:aws:iam::" account-id ":root")}
                    :Action "sts:AssumeRole"}]}}}]})

(defn with-memory-conn
  [f]
  (let [conn (iam/get-conn (iam/memory-config))]
    (try
      (f conn)
      (finally
        (iam/close-conn! conn)))))

(defn temp-db-path
  []
  (str "/private/tmp/iam-datahike-test-" (random-uuid)))

(defn bbm!
  [& args]
  (let [{:keys [exit out err cmd]} (apply process/shell
                                          {:dir (str skill-dir)
                                           :out :string
                                           :err :string}
                                          "bb" "-cp" "." "-m" "iam-datahike" args)]
    (when-not (zero? exit)
      (throw (ex-info "bb -m iam-datahike failed" {:cmd cmd :exit exit :out out :err err})))
    out))

(deftest arn-parser-preserves-general-syntax-and-resource_shapes
  (is (= {:arn/partition "aws"
          :arn/service "iam"
          :arn/region ""
          :arn/account-id "123456789012"
          :arn/resource "role/team/Admin"
          :arn/resource-type "role"
          :arn/resource-path "team/"
          :arn/resource-id "Admin"
          :arn/pattern? false}
         (iam/parse-arn "arn:aws:iam::123456789012:role/team/Admin")))
  (is (= {:arn/partition "aws"
          :arn/service "s3"
          :arn/region ""
          :arn/account-id ""
          :arn/resource "my-bucket/prefix/*"
          :arn/resource-id "my-bucket/prefix/*"
          :arn/pattern? true}
         (iam/parse-arn "arn:aws:s3:::my-bucket/prefix/*")))
  (is (= {:arn/partition "aws"
          :arn/service "lambda"
          :arn/region "us-east-1"
          :arn/account-id "123456789012"
          :arn/resource "function:my-fn:$LATEST"
          :arn/resource-type "function"
          :arn/resource-id "my-fn"
          :arn/resource-qualifier "$LATEST"
          :arn/pattern? false}
         (iam/parse-arn "arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST")))
  (is (nil? (iam/parse-arn "*"))))

(deftest config-role-observation-loads-current-role-and-provenance
  (with-memory-conn
    (fn [conn]
      (testing "loading a role config produces a current role and a resource observation"
        (let [result (iam/load-config-json!
                      conn
                      (role-config {:state-id "state-1"
                                    :capture-time "2026-04-24T10:00:00.000Z"})
                      {:source-path "memory://role-state-1.json"})]
          (is (pos? (:phase-count result)))
          (is (pos? (:entities result)))
          (is (pos? (:datoms result))))
        (is (= {:role/id role-id
                :role/name role-name
                :role/arn role-arn
                :arn/partition "aws"
                :arn/service "iam"
                :arn/region ""
                :arn/account-id account-id
                :arn/resource "role/DatahikeTestRole"
                :arn/resource-type "role"
                :arn/resource-id "DatahikeTestRole"
                :arn/pattern? false}
               (select-keys (iam/role-by-arn (d/db conn) role-arn)
                            [:role/id :role/name :role/arn
                             :arn/partition :arn/service :arn/region :arn/account-id
                             :arn/resource :arn/resource-type :arn/resource-id
                             :arn/pattern?])))
        (is (= [{:config/key (str account-id "/us-east-1/AWS::IAM::Role/" role-id "/state-1")
                 :config/status "OK"
                 :config/source-path "memory://role-state-1.json"}]
               (mapv #(select-keys % [:config/key :config/status :config/source-path])
                     (iam/resource-observations (d/db conn) role-arn))))))))

(deftest config-load-is-idempotent-for-identical-observation
  (with-memory-conn
    (fn [conn]
      (let [sample (role-config {:state-id "state-1"
                                 :capture-time "2026-04-24T10:00:00.000Z"})
            opts {:source-path "memory://same-role.json"}]
        (iam/load-config-json! conn sample opts)
        (let [before (iam/stats (d/db conn))
              imported-at-before (:config/imported-at
                                  (first (iam/resource-observations (d/db conn) role-arn)))]
          (iam/load-config-json! conn sample opts)
          (is (= before (iam/stats (d/db conn))))
          (is (= 1 (count (iam/resource-observations (d/db conn) role-arn))))
          (is (= imported-at-before
                 (:config/imported-at
                  (first (iam/resource-observations (d/db conn) role-arn))))))))))

(deftest config-role-observations-use-datahike-history-for-prior-resource-state
  (with-memory-conn
    (fn [conn]
      (testing "new observations update current state while as-of can read the previous state"
        (let [state-1-load (iam/load-config-json!
                            conn
                            (role-config {:state-id "state-1"
                                          :capture-time "2026-04-24T10:00:00.000Z"
                                          :tags [{:key "env" :value "dev"}]})
                            {:source-path "memory://role-state-1.json"})
              state-1-time (:tx-instant state-1-load)]
          (iam/load-config-json!
           conn
           (role-config {:state-id "state-2"
                         :capture-time "2026-04-24T11:00:00.000Z"
                         :tags [{:key "env" :value "prod"}]})
           {:source-path "memory://role-state-2.json"})
          (is (= {:tags [{:key "env" :value "prod"}]}
                 (select-keys (iam/role-by-arn (d/db conn) role-arn)
                              [:tags])))
          (is (= {:tags [{:key "env" :value "dev"}]}
                 (select-keys (iam/resource-state-at conn role-arn state-1-time)
                              [:tags])))
          (is (= #{:role/tags :tags}
                 (set (mapv :attribute (iam/resource-changes-since conn role-arn state-1-time))))))
        (is (= ["state-1" "state-2"]
               (mapv #(last (str/split (:config/key %) #"/"))
                     (iam/resource-observations (d/db conn) role-arn))))))))

(defn managed-policy-config
  [{:keys [state-id default-version action]}]
  {:configurationItems
   [{:accountId account-id
     :awsRegion "global"
     :resourceType "AWS::IAM::Policy"
     :resourceId "ANPADATAHIKETEST"
     :resourceName "DatahikeManagedPolicy"
     :configurationStateId state-id
     :configurationItemCaptureTime "2026-04-24T10:00:00.000Z"
     :configurationItemStatus "OK"
     :arn policy-arn
     :configuration
     {:arn policy-arn
      :policyId "ANPADATAHIKETEST"
      :policyName "DatahikeManagedPolicy"
      :policyVersionList
      [{:versionId "v1"
        :isDefaultVersion (= default-version "v1")
        :createDate "2026-04-24T10:00:00Z"
        :document
        {:Version "2012-10-17"
         :Statement [{:Sid "Default"
                      :Effect "Allow"
                      :Action action
                      :Resource "*"}]}}
       {:versionId "v2"
        :isDefaultVersion (= default-version "v2")
        :createDate "2026-04-24T11:00:00Z"
        :document
        {:Version "2012-10-17"
         :Statement [{:Sid "Default"
                      :Effect "Allow"
                      :Action "s3:GetObject"
                      :Resource "*"}]}}]}}]})

(deftest managed-policy-default-version-uses-datahike-history
  (with-memory-conn
    (fn [conn]
      (let [state-1 (iam/load-config-json!
                     conn
                     (managed-policy-config {:state-id "policy-state-1"
                                             :default-version "v1"
                                             :action "s3:ListBucket"})
                     {:source-path "memory://policy-state-1.json"})
            state-1-time (:tx-instant state-1)]
        (iam/load-config-json!
         conn
         (managed-policy-config {:state-id "policy-state-2"
                                 :default-version "v2"
                                 :action "s3:ListBucket"})
         {:source-path "memory://policy-state-2.json"})
        (is (= "v2" (:policy-version/id
                     (iam/policy-default-version (d/db conn) policy-arn))))
        (is (= "v1" (:policy-version/id
                     (iam/policy-default-version-at conn policy-arn state-1-time))))
        (is (seq (iam/policy-version-changes-since conn policy-arn state-1-time)))
        (is (= ["v1" "v2"]
               (mapv :policy-version/id (iam/policy-document-history conn policy-arn))))
        (is (seq (filter #(= :policy/default-version (:a %))
                         (iam/history-datoms-since conn state-1-time))))))))

(defn role-with-passrole-config
  []
  (role-config
   {:state-id "passrole-source"
    :capture-time "2026-04-24T10:00:00.000Z"
    :role-name "DatahikeTestRole"}))

(deftest derived-pass-role-transition-uses_statement_graph
  (with-memory-conn
    (fn [conn]
      (let [source-arn (str "arn:aws:iam::" account-id ":role/PassRoleSource")
            target-arn role-arn
            source-config
            (assoc-in
             (role-config {:state-id "passrole-source"
                           :capture-time "2026-04-24T10:00:00.000Z"
                           :role-name "PassRoleSource"})
             [:configurationItems 0 :configuration :rolePolicyList]
             [{:policyName "CanPassTarget"
               :policyDocument
               {:Version "2012-10-17"
                :Statement [{:Sid "PassTarget"
                             :Effect "Allow"
                             :Action "iam:PassRole"
                             :Resource target-arn
                             :Condition {:StringEquals
                                         {"iam:PassedToService" "lambda.amazonaws.com"}}}]}}])
            source-config (assoc-in source-config [:configurationItems 0 :configuration :arn] source-arn)
            source-config (assoc-in source-config [:configurationItems 0 :configuration :roleId] "AROAPASSROLESOURCE")
            source-config (assoc-in source-config [:configurationItems 0 :resourceId] "AROAPASSROLESOURCE")
            source-config (assoc-in source-config [:configurationItems 0 :resourceName] "PassRoleSource")]
        (iam/load-config-json!
         conn
         (assoc-in
          (role-config {:state-id "passrole-target"
                        :capture-time "2026-04-24T09:00:00.000Z"
                        :role-name role-name})
          [:configurationItems 0 :configuration :assumeRolePolicyDocument :Statement 0 :Principal]
          {:Service "lambda.amazonaws.com"})
         {:source-path "memory://target.json"})
        (iam/load-config-json! conn source-config {:source-path "memory://source.json"})
        (is (= [{:action/key "iam:passrole"
                 :resource/arn target-arn}]
               (mapv #(select-keys % [:action/key :resource/arn])
                     (iam/role-effective-allow (d/db conn) source-arn))))
        (is (= [{:transition/type :pass-role
                 :source-role source-arn
                 :target-role target-arn
                 :action "iam:passrole"
                 :delegated-service "lambda.amazonaws.com"}]
               (mapv #(select-keys % [:transition/type :source-role :target-role :action :delegated-service])
                     (iam/role-transitions (d/db conn)))))))))

(deftest derived-assume-role-transition-uses-trust-policy-statement
  (with-memory-conn
    (fn [conn]
      (let [source-arn (str "arn:aws:iam::" account-id ":role/AssumeSource")
            target-arn role-arn
            source-config (-> (role-config {:state-id "assume-source"
                                            :capture-time "2026-04-24T08:00:00.000Z"
                                            :role-name "AssumeSource"})
                              (assoc-in [:configurationItems 0 :configuration :arn] source-arn)
                            (assoc-in [:configurationItems 0 :configuration :roleId] "AROAASSUMESOURCE")
                            (assoc-in [:configurationItems 0 :resourceId] "AROAASSUMESOURCE")
                            (assoc-in [:configurationItems 0 :resourceName] "AssumeSource"))
            source-config (assoc-in source-config
                                    [:configurationItems 0 :configuration :rolePolicyList]
                                    [{:policyName "CanAssumeTarget"
                                      :policyDocument
                                      {:Version "2012-10-17"
                                       :Statement [{:Sid "AssumeTarget"
                                                    :Effect "Allow"
                                                    :Action "sts:AssumeRole"
                                                    :Resource target-arn}]}}])
            target-config (assoc-in
                           (role-config {:state-id "assume-target"
                                         :capture-time "2026-04-24T09:00:00.000Z"
                                         :role-name role-name})
                           [:configurationItems 0 :configuration :assumeRolePolicyDocument :Statement 0 :Principal]
                           {:AWS source-arn})]
        (iam/load-config-json! conn source-config {:source-path "memory://assume-source.json"})
        (iam/load-config-json! conn target-config {:source-path "memory://assume-target.json"})
        (is (= [{:transition/type :assume-role
                 :source-role source-arn
                 :target-role target-arn
                 :action "sts:assumerole"}]
               (mapv #(select-keys % [:transition/type :source-role :target-role :action])
                     (iam/role-transitions (d/db conn)))))))))

(deftest generated-aws-docs-roles-and-policies-drive-role-transitions
  (with-memory-conn
    (fn [conn]
      (let [sample (iam/read-json-file "samples/aws-config/role-transition/aws-docs-assume-and-passrole.json")
            source-arn "arn:aws:iam::123456789012:role/AwsDocsTransitionSource"
            target-arn "arn:aws:iam::123456789012:role/AwsDocsTransitionTarget"]
        (iam/load-config-json! conn sample {:source-path "samples/aws-config/role-transition/aws-docs-assume-and-passrole.json"})
        (let [transitions (set (map #(select-keys % [:transition/type :source-role :target-role :action :delegated-service])
                                    (iam/role-transitions (d/db conn))))]
          (is (clojure.set/subset?
               #{{:transition/type :assume-role
                  :source-role source-arn
                  :target-role target-arn
                  :action "sts:assumerole"}
                 {:transition/type :pass-role
                  :source-role source-arn
                  :target-role target-arn
                  :action "iam:passrole"
                  :delegated-service "cloudwatch.amazonaws.com"}}
               transitions)))))))

(deftest pass-role-transition-requires_target_service_trust_compatibility
  (with-memory-conn
    (fn [conn]
      (let [source-arn "arn:aws:iam::123456789012:role/PassRoleSource"
            target-arn role-arn
            source-config
            (-> (role-config {:state-id "passrole-source-mismatch"
                              :capture-time "2026-04-24T10:00:00.000Z"
                              :role-name "PassRoleSource"})
                (assoc-in [:configurationItems 0 :configuration :arn] source-arn)
                (assoc-in [:configurationItems 0 :configuration :roleId] "AROAPASSROLEMISMATCH")
                (assoc-in [:configurationItems 0 :resourceId] "AROAPASSROLEMISMATCH")
                (assoc-in [:configurationItems 0 :resourceName] "PassRoleSource")
                (assoc-in [:configurationItems 0 :configuration :rolePolicyList]
                          [{:policyName "PassRoleLambdaOnly"
                            :policyDocument
                            {:Version "2012-10-17"
                             :Statement [{:Sid "PassTarget"
                                          :Effect "Allow"
                                          :Action "iam:PassRole"
                                          :Resource target-arn
                                          :Condition {:StringEquals
                                                      {"iam:PassedToService" "lambda.amazonaws.com"}}}]}}]))
            target-config
            (assoc-in
             (role-config {:state-id "passrole-target-mismatch"
                           :capture-time "2026-04-24T09:00:00.000Z"
                           :role-name role-name})
             [:configurationItems 0 :configuration :assumeRolePolicyDocument :Statement 0 :Principal]
             {:Service "ec2.amazonaws.com"})]
        (iam/load-config-json! conn target-config {:source-path "memory://target-mismatch.json"})
        (iam/load-config-json! conn source-config {:source-path "memory://source-mismatch.json"})
        (is (empty? (filter #(= :pass-role (:transition/type %))
                            (iam/role-transitions (d/db conn)))))))))

(deftest pass-role-without_passed-to-service_expands_to_target_trust_services
  (with-memory-conn
    (fn [conn]
      (let [source-arn "arn:aws:iam::123456789012:role/PassRoleAnyServiceSource"
            target-arn role-arn
            source-config
            (-> (role-config {:state-id "passrole-source-any-service"
                              :capture-time "2026-04-24T10:00:00.000Z"
                              :role-name "PassRoleAnyServiceSource"})
                (assoc-in [:configurationItems 0 :configuration :arn] source-arn)
                (assoc-in [:configurationItems 0 :configuration :roleId] "AROAPASSROLEANY")
                (assoc-in [:configurationItems 0 :resourceId] "AROAPASSROLEANY")
                (assoc-in [:configurationItems 0 :resourceName] "PassRoleAnyServiceSource")
                (assoc-in [:configurationItems 0 :configuration :rolePolicyList]
                          [{:policyName "PassRoleAnyService"
                            :policyDocument
                            {:Version "2012-10-17"
                             :Statement [{:Sid "PassTarget"
                                          :Effect "Allow"
                                          :Action "iam:PassRole"
                                          :Resource target-arn}]}}]))
            target-config
            (assoc-in
             (role-config {:state-id "passrole-target-any-service"
                           :capture-time "2026-04-24T09:00:00.000Z"
                           :role-name role-name})
             [:configurationItems 0 :configuration :assumeRolePolicyDocument :Statement 0 :Principal]
             {:Service ["lambda.amazonaws.com" "ec2.amazonaws.com"]})]
        (iam/load-config-json! conn target-config {:source-path "memory://target-any-service.json"})
        (iam/load-config-json! conn source-config {:source-path "memory://source-any-service.json"})
        (is (= #{"ec2.amazonaws.com" "lambda.amazonaws.com"}
               (set (map :delegated-service
                         (filter #(= :pass-role (:transition/type %))
                                 (iam/role-transitions (d/db conn)))))))))))

(deftest action-pattern-expansion_uses_catalog_for_narrow_wildcards
  (with-memory-conn
    (fn [conn]
      (iam/load-service-reference-json!
       conn
       (iam/read-json-file "samples/iam-policy/service-reference/iam.json")
       {:source-url "samples/iam-policy/service-reference/iam.json"})
      (is (= {:pattern "iam:*"
              :expanded? false
              :actions ["iam:*"]}
             (iam/expand-action-pattern (d/db conn) "iam:*")))
      (is (= {:pattern "*"
              :expanded? false
              :actions ["*"]}
             (iam/expand-action-pattern (d/db conn) "*")))
      (is (= {:pattern "iam:PassRole"
              :expanded? false
              :actions ["iam:passrole"]}
             (iam/expand-action-pattern (d/db conn) "iam:PassRole")))
      (let [expanded (iam/expand-action-pattern (d/db conn) "iam:*Role")]
        (is (:expanded? expanded))
        (is (contains? (set (:actions expanded)) "iam:passrole")))
      (is (= {:pattern "iam:Get*"
              :expanded? false
              :actions ["iam:get*"]}
             (iam/expand-action-pattern (d/db conn) "iam:Get*"))))))

(deftest narrow-action-wildcard_requires_loaded_service_catalog
  (with-memory-conn
    (fn [conn]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Service catalog missing"
                            (iam/expand-action-pattern (d/db conn) "iam:*Role"))))))

(deftest iam-policy-grammar-not-action-and-not-resource-are-preserved
  (with-memory-conn
    (fn [conn]
      (iam/load-iam-policy-json!
       conn
       (iam/read-json-file "samples/iam-policy/s3_deny-except-bucket.json")
       {:policy-arn "arn:aws:iam::123456789012:policy/aws-docs/s3_deny-except-bucket"
        :policy-name "s3_deny-except-bucket"
        :default true})
      (let [statements (iam/policy-statements
                        (d/db conn)
                        "arn:aws:iam::123456789012:policy/aws-docs/s3_deny-except-bucket")
            deny-statement (first (filter #(= :deny (:statement/effect %)) statements))]
        (is (= ["s3:*"] (:statement/not-action deny-statement)))
        (is (= ["arn:aws:s3:::bucket-name" "arn:aws:s3:::bucket-name/*"]
               (:statement/not-resource deny-statement)))
        (is (= [] (:statement/resource deny-statement)))))))

(deftest principal-schema-classifies-iam-principal-types-at-inject-time
  (with-memory-conn
    (fn [conn]
      (let [policy
            {:Version "2012-10-17"
             :Statement
             [{:Sid "RootUserRoleGroup"
               :Effect "Allow"
               :Principal {:AWS ["arn:aws:iam::123456789012:root"
                                  "arn:aws:iam::123456789012:user/alice"
                                  "arn:aws:iam::123456789012:role/Admin"
                                  "arn:aws:iam::123456789012:group/Developers"
                                  "*"]}
               :Action "sts:AssumeRole"
               :Resource "*"}
              {:Sid "Sessions"
               :Effect "Allow"
               :Principal {:AWS ["arn:aws:sts::123456789012:assumed-role/Admin/session"
                                  "arn:aws:sts::123456789012:federated-user/bob"]}
               :Action "sts:AssumeRole"
               :Resource "*"}
              {:Sid "ServicesAndFederation"
               :Effect "Allow"
               :Principal {:Service "ec2.amazonaws.com"
                           :Federated ["cognito-identity.amazonaws.com"
                                       "arn:aws:iam::123456789012:saml-provider/Okta"]}
               :Action "sts:AssumeRole"
               :Resource "*"}
              {:Sid "Anonymous"
               :Effect "Allow"
               :Principal "*"
               :Action "s3:GetObject"
               :Resource "*"}]}]
        (iam/load-iam-policy-json!
         conn
         policy
         {:policy-arn "arn:aws:iam::123456789012:policy/principal-schema"
          :policy-name "principal-schema"
          :default true})
        (let [principals (->> (d/q '[:find ?principal ?type ?value
                                      :keys db/id principal/type principal/value
                                      :where
                                      [?principal :principal/type ?type]
                                      [?principal :principal/value ?value]]
                                    (d/db conn))
                              (sort-by (juxt :principal/type :principal/value))
                              vec)]
          (is (every? :db/id principals))
          (is (= [{:principal/type :account-root
                   :principal/value "arn:aws:iam::123456789012:root"}
                  {:principal/type :assumed-role-session
                   :principal/value "arn:aws:sts::123456789012:assumed-role/Admin/session"}
                  {:principal/type :federated
                   :principal/value "arn:aws:iam::123456789012:saml-provider/Okta"}
                  {:principal/type :federated
                   :principal/value "cognito-identity.amazonaws.com"}
                  {:principal/type :federated-user-session
                   :principal/value "arn:aws:sts::123456789012:federated-user/bob"}
                  {:principal/type :iam-group
                   :principal/value "arn:aws:iam::123456789012:group/Developers"}
                  {:principal/type :iam-role
                   :principal/value "arn:aws:iam::123456789012:role/Admin"}
                  {:principal/type :iam-user
                   :principal/value "arn:aws:iam::123456789012:user/alice"}
                  {:principal/type :service
                   :principal/value "ec2.amazonaws.com"}
                  {:principal/type :wildcard-any-principal
                   :principal/value "*"}
                  {:principal/type :wildcard-authenticated-aws
                   :principal/value "*"}]
                 (mapv #(dissoc % :db/id) principals))))
        (is (= [[{:principal/type :wildcard-any-principal
                  :principal/value "*"}]]
               (->> (iam/policy-statements (d/db conn) "arn:aws:iam::123456789012:policy/principal-schema")
                    (filter #(= "Anonymous" (:statement/sid %)))
                    (mapv (fn [statement]
                            (mapv #(dissoc % :db/id) (:statement/principal statement)))))))
        (is (= [{:principal/type :account-root
                 :principal/value "arn:aws:iam::123456789012:root"
                 :arn/service "iam"
                 :arn/account-id "123456789012"
                 :arn/resource "root"
                 :arn/resource-id "root"}
                {:principal/type :iam-role
                 :principal/value "arn:aws:iam::123456789012:role/Admin"
                 :arn/service "iam"
                 :arn/account-id "123456789012"
                 :arn/resource "role/Admin"
                 :arn/resource-type "role"
                 :arn/resource-id "Admin"}]
               (->> (d/q '[:find [(pull ?principal [:principal/type :principal/value
                                                     :arn/service :arn/account-id
                                                     :arn/resource :arn/resource-type
                                                     :arn/resource-id]) ...]
                           :where
                           [?principal :principal/type ?type]
                           [(contains? #{:account-root :iam-role} ?type)]]
                         (d/db conn))
                    (sort-by (juxt :principal/type :principal/value))
                    vec)))
        (is (every? :db/id
                    (->> (iam/policy-statements (d/db conn) "arn:aws:iam::123456789012:policy/principal-schema")
                         (mapcat :statement/principal))))))))

(deftest policy-resource-patterns-store_arn_facets
  (with-memory-conn
    (fn [conn]
      (iam/load-iam-policy-json!
       conn
       {:Version "2012-10-17"
        :Statement [{:Sid "ObjectAccess"
                     :Effect "Allow"
                     :Action "s3:GetObject"
                     :Resource "arn:aws:s3:::my-bucket/prefix/?"
                     :Condition {:ArnEquals
                                 {"aws:SourceArn" "arn:aws:sns:us-east-1:123456789012:my-topic"}}}
                    {:Sid "LambdaVersion"
                     :Effect "Allow"
                     :Action "lambda:InvokeFunction"
                     :Resource "arn:aws:lambda:*:123456789012:function:my-fn:$LATEST"}]}
       {:policy-arn "arn:aws:iam::123456789012:policy/resource-facets"
        :policy-name "resource-facets"
        :default true})
      (is (= [{:resource/arn "arn:aws:lambda:*:123456789012:function:my-fn:$LATEST"
               :resource/pattern? true
               :arn/service "lambda"
               :arn/region "*"
               :arn/account-id "123456789012"
               :arn/resource-type "function"
               :arn/resource-id "my-fn"
               :arn/resource-qualifier "$LATEST"
               :arn/pattern? true}
              {:resource/arn "arn:aws:s3:::my-bucket/prefix/?"
               :resource/pattern? true
               :arn/service "s3"
               :arn/region ""
               :arn/account-id ""
               :arn/resource-id "my-bucket/prefix/?"
               :arn/pattern? true}]
             (->> (d/q '[:find [(pull ?resource [:resource/arn :resource/pattern?
                                                 :arn/service :arn/region :arn/account-id
                                                 :arn/resource-type :arn/resource-id
                                                 :arn/resource-qualifier :arn/pattern?]) ...]
                         :where
                         [?resource :resource/arn]
                         [?resource :arn/service]]
                       (d/db conn))
                  (sort-by :resource/arn)
                  vec)))
      (is (= [{:condition/field "aws:SourceArn"
               :condition/operator "ArnEquals"
               :arn/service "sns"
               :arn/region "us-east-1"
               :arn/account-id "123456789012"
               :arn/resource-id "my-topic"
               :arn/pattern? false}]
             (->> (d/q '[:find [(pull ?condition [:condition/field :condition/operator
                                                  :arn/service :arn/region :arn/account-id
                                                  :arn/resource-id :arn/pattern?]) ...]
                         :where
                         [?condition :condition/field "aws:SourceArn"]]
                       (d/db conn))
                  (sort-by :condition/field)
                  vec)))
      (is (iam/resource-pattern-matches? "arn:aws:s3:::my-bucket/prefix/?" "arn:aws:s3:::my-bucket/prefix/a"))
      (is (not (iam/resource-pattern-matches? "arn:aws:s3:::my-bucket/prefix/?" "arn:aws:s3:::my-bucket/prefix/ab")))
      (is (not (iam/resource-pattern-matches? "arn:aws:lambda:*:123456789012:function:*"
                                               "arn:aws:s3:::my-bucket/prefix/a"))))))

(def service-reference-json
  {:Name "iam"
   :Version "2026-05-02"
   :Actions [{:Name "PassRole"
              :ActionConditionKeys ["iam:PassedToService"]
              :Resources [{:Name "role"}]
              :Annotations {:Properties {:IsWrite true
                                          :IsPermissionManagement true}}
              :SupportedBy {"IAM Access Analyzer Policy Generation" true
                            "IAM Action Last Accessed" false}}]
   :Resources [{:Name "role"
                :ARNFormats ["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]
                :ConditionKeys ["iam:ResourceTag/${TagKey}"]}]
   :ConditionKeys [{:Name "iam:PassedToService"
                    :Types ["String"]}
                   {:Name "iam:ResourceTag/${TagKey}"
                    :Types ["String"]}]})

(deftest service-reference-loads-actions-resources-and-condition-keys
  (with-memory-conn
    (fn [conn]
      (testing "service reference JSON becomes queryable catalog facts"
        (let [result (iam/load-service-reference-json!
                      conn
                      service-reference-json
                      {:source-url "https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json"})]
          (is (pos? (:entities result)))
          (is (= [{:action/key "iam:passrole"
                   :action/name "PassRole"
                   :action/access-level :permissions-management
                   :resource-types ["iam:role"]
                   :condition-keys ["iam:passedtoservice"]}]
                 (iam/service-actions (d/db conn) "iam"))))))))

(deftest downloaded-service-reference-sample-loads
  (with-memory-conn
    (fn [conn]
      (let [sample (iam/read-json-file "samples/iam-policy/service-reference/iam.json")
            result (iam/load-service-reference-json!
                    conn sample
                    {:source-url "https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json"})
            pass-role (first (filter #(= "iam:passrole" (:action/key %))
                                     (iam/service-actions (d/db conn) "iam")))]
        (is (= 3 (:phase-count result)))
        (is (<= 200 (:entities result)))
        (is (= {:action/key "iam:passrole"
                :action/name "PassRole"
                :action/access-level :write
                :resource-types ["iam:role"]
                :condition-keys ["iam:associatedresourcearn" "iam:passedtoservice"]}
               pass-role))))))

(deftest preload-service-reference-loads_directory
  (with-memory-conn
    (fn [conn]
      (let [result (iam/preload-service-reference! conn {:dir "samples/iam-policy/service-reference"})]
        (is (<= 2 (:services result)))
        (is (seq (iam/service-actions (d/db conn) "iam")))))))

(deftest downloaded-config-resource-schema-sample-loads
  (with-memory-conn
    (fn [conn]
      (let [sample (iam/read-json-file "samples/aws-config-resource-schema/AWS-IAM-Role.properties.json")
            result (iam/load-config-resource-schema-json!
                    conn
                    "AWS::IAM::Role"
                    sample
                    {:source-url "https://github.com/awslabs/aws-config-resource-schema"})]
        (is (= 2 (:phase-count result)))
        (is (= 43 (:entities result)))
        (is (= {:config-property/path "configuration.roleName"
                :config-property/type :string}
               (first (filter #(= "configuration.roleName" (:config-property/path %))
                              (iam/config-resource-properties (d/db conn) "AWS::IAM::Role")))))))))

(deftest github-aws-config-sample-loads-as-role-observation
  (with-memory-conn
    (fn [conn]
      (let [sample (iam/read-json-file "samples/aws-config/github-actions-trust-check-role.json")]
        (iam/load-config-json! conn sample {:source-path "samples/aws-config/github-actions-trust-check-role.json"})
        (is (= "github-actions-role"
               (:role/name (iam/role-by-arn
                            (d/db conn)
                            "arn:aws:iam::12345678910:role/github-actions-role"))))))))

(deftest batch-load-config-jsonl-and-correction-cli
  (let [db-path (temp-db-path)
        jsonl (io/file "/private/tmp" (str "iam-datahike-jsonl-" (random-uuid) ".jsonl"))]
    (spit jsonl (str (json/generate-string (role-config {:state-id "jsonl-state"
                                                         :capture-time "2026-04-24T10:00:00.000Z"}))
                     "\n"))
    (bbm! "batch-load-config" "--db" db-path "--file" (str jsonl))
    (let [stats-before (json/parse-string (bbm! "stats" "--db" db-path) true)]
      (is (= 1 (get-in stats-before [:results 0 :roles])))
      (bbm! "retract-source" "--db" db-path "--source-path" (str jsonl))
      (let [stats-after (json/parse-string (bbm! "stats" "--db" db-path) true)]
        (is (= 0 (get-in stats-after [:results 0 :config-items])))))))

(deftest config-load-order-fuzz-keeps-logical-state
  (with-memory-conn
    (fn [baseline]
      (let [items [(role-config {:state-id "fuzz-1"
                                 :capture-time "2026-04-24T10:00:00.000Z"
                                 :tags [{:key "order" :value "one"}]})
                   (role-config {:state-id "fuzz-2"
                                 :capture-time "2026-04-24T11:00:00.000Z"
                                 :tags [{:key "order" :value "two"}]})]]
        (doseq [[idx item] (map-indexed vector items)]
          (iam/load-config-json! baseline item {:source-path (str "memory://baseline-" idx ".json")}))
        (let [expected (select-keys (iam/stats (d/db baseline)) [:roles :documents :statements :config-items])]
          (doseq [trial (range 12)]
            (with-memory-conn
              (fn [conn]
                (doseq [[idx item] (map-indexed vector (shuffle items))]
                  (iam/load-config-json! conn item {:source-path (str "memory://trial-" trial "-" idx ".json")}))
                (is (= expected
                       (select-keys (iam/stats (d/db conn))
                                    [:roles :documents :statements :config-items])))))))))))

(defn -main
  [& _]
  (let [{:keys [fail error]} (run-tests 'iam-datahike-test)]
    (when (pos? (+ fail error))
      (System/exit 1))))
