#?(:bb (do
         (require '[babashka.pods :as pods])
         (pods/load-pod 'huahaiy/datalevin "0.10.7")))

(ns iam-loader-test
  (:require [cheshire.core :as json]
            [clojure.test :refer [deftest is run-tests testing]]
            [iam :as iam]
            [pod.huahaiy.datalevin :as d]))

(def account-id "123456789012")
(def policy-arn (str "arn:aws:iam::" account-id ":policy/LoaderAdminPolicy"))
(def role-id "AROALOADERADMIN")
(def role-name "LoaderAdminRole")
(def role-arn (str "arn:aws:iam::" account-id ":role/" role-name))

(def role-config-json
  {:configurationItems
   [{:accountId account-id
     :awsRegion "us-east-1"
     :resourceType "AWS::IAM::Role"
     :resourceId role-id
     :resourceName role-name
     :configurationStateId "loader-state-1"
     :configurationItemCaptureTime "2026-04-24T10:00:00.000Z"
     :configurationItemStatus "OK"
     :configuration
     {:arn role-arn
      :roleId role-id
      :roleName role-name
      :path "/"
      :createDate "2026-04-24T10:00:00Z"
      :assumeRolePolicyDocument
      {:Version "2012-10-17"
       :Statement [{:Sid "TrustRoot"
                    :Effect "Allow"
                    :Principal {:AWS (str "arn:aws:iam::" account-id ":root")}
                    :Action "sts:AssumeRole"}]}
      :attachedManagedPolicies
      [{:policyName "LoaderAdminPolicy"
        :policyArn policy-arn}]}}]})

(def admin-policy-json
  {:policyArn policy-arn
   :policyName "LoaderAdminPolicy"
   :versionId "v1"
   :default true
   :Document {:Version "2012-10-17"
              :Statement [{:Sid "AdminAll"
                           :Effect "Allow"
                           :Action "*"
                           :Resource "*"}]}})

(def service-reference-json
  {:Name "example"
   :Version "v1"
   :Actions [{:Name "GetThing"
              :ActionConditionKeys ["example:ThingId"]
              :DependentActions ["iam:PassRole"]
              :Annotations {:Properties {:IsRead true}}
              :Resources [{:Name "thing"}]
              :SupportedBy {"IAM Access Analyzer Policy Generation" true
                            "IAM Action Last Accessed" false}}]
   :Resources [{:Name "thing"
                :ARNFormats ["arn:${Partition}:example:${Region}:${Account}:thing/${ThingId}"]
                :ConditionKeys ["aws:ResourceTag/${TagKey}"]}]
   :ConditionKeys [{:Name "example:ThingId"
                    :Types ["String"]}
                   {:Name "aws:ResourceTag/${TagKey}"
                    :Types ["String"]}]})

(defn get-conn []
  (d/get-conn (str "/tmp/iam-loader-test-" (random-uuid)) iam/schema))

(defn temp-db-path [prefix]
  (str "/tmp/" prefix "-" (random-uuid)))

(defn jsonl [value]
  (str (json/generate-string value) "\n"))

(defn temp-jsonl-file [value]
  (doto (java.io.File/createTempFile "iam-batch" ".jsonl")
    (spit (jsonl value))
    (.deleteOnExit)))

(defn close! [conn]
  (d/close conn))

(defn db [conn]
  (d/db conn))

(defn q [query db & args]
  (apply d/q query db args))

(defn load-role! [conn]
  (iam/load-config-json! conn role-config-json))

(defn load-policy! [conn]
  (iam/load-iam-policy-json! conn admin-policy-json {}))

(defn load-service-reference! [conn]
  (iam/load-service-reference-json! conn service-reference-json {:source-file "memory://example"}))

(defn graph-summary [conn]
  (let [db-value (db conn)]
    {:roles (q '[:find [?name ...]
                 :where [_ :role/name ?name]]
               db-value)
     :policies (q '[:find [?name ...]
                    :where [_ :policy/name ?name]]
                  db-value)
     :role-policy-relations (q '[:find ?role-name ?policy-name
                                 :where
                                 [?role :role/name ?role-name]
                                 [?role :role/attached-policy ?policy]
                                 [?policy :policy/name ?policy-name]]
                               db-value)
     :admin-like-roles (q (:admin-like-roles iam/sample-queries) db-value)
     :entity-counts (into {}
                          (map (fn [attr]
                                 [attr (q '[:find (count ?e) .
                                            :in $ ?attr
                                            :where [?e ?attr]]
                                          db-value attr)]))
                          [:role/id
                           :policy/key
                           :policy-version/key
                           :document/key
                           :statement/key
                           :action/key
                           :resource/key
                           :principal/key
                           :config/key])}))

(defn load-sequence-summary [loaders]
  (let [conn (get-conn)]
    (try
      (doseq [load! loaders]
        (load! conn))
      (graph-summary conn)
      (finally
        (close! conn)))))

(deftest role-policy-load-order-is-commutative
  (testing "Loading the Role before the Policy yields the same graph as loading the Policy before the Role"
    (is (= (load-sequence-summary [load-role! load-policy!])
           (load-sequence-summary [load-policy! load-role!])))))

(deftest role-policy-loads-are-idempotent
  (testing "Repeating the same Role and Policy loads does not duplicate entities or relationships"
    (is (= (load-sequence-summary [load-role! load-policy!])
           (load-sequence-summary [load-role! load-policy! load-role! load-policy!])))))

(deftest service-reference-load-normalizes-current-catalog
  (testing "Service reference JSON stores raw provenance and normalized action/resource/condition relationships"
    (let [conn (get-conn)]
      (try
        (load-service-reference! conn)
        (let [db-value (db conn)]
          (is (= #{["example" "v1" "memory://example"]}
                 (q '[:find ?service ?version ?source-file
                      :where
                      [?s :service/key ?service]
                      [?s :service/version ?version]
                      [?s :service/source-file ?source-file]]
                    db-value)))
          (is (= #{["GetThing" :read "example:thing" "example:thingid" "iam:passrole"]}
                 (q '[:find ?action-name ?access-level ?resource ?condition ?dependent
                      :where
                      [?a :action/key "example:getthing"]
                      [?a :action/name ?action-name]
                      [?a :action/access-level ?access-level]
                      [?a :action/resource-type ?resource-entity]
                      [?resource-entity :service-resource/key ?resource]
                      [?a :action/condition-key ?condition-entity]
                      [?condition-entity :condition-key/name ?condition]
                      [?a :action/dependent-action ?dependent-entity]
                      [?dependent-entity :action/key ?dependent]]
                    db-value)))
          (is (= #{["arn:${Partition}:example:${Region}:${Account}:thing/${ThingId}"
                    "aws:resourcetag/${tagkey}"]}
                 (q '[:find ?arn-format ?condition
                      :where
                      [?resource :service-resource/key "example:thing"]
                      [?resource :service-resource/arn-format ?arn-format]
                      [?resource :service-resource/condition-key ?condition-entity]
                      [?condition-entity :condition-key/name ?condition]]
                    db-value)))
          (is (true?
               (q '[:find ?has-raw .
                    :where
                    [?s :service/key "example"]
                    [?s :service/raw ?raw]
                    [(boolean ?raw) ?has-raw]]
                  db-value))))
        (finally
          (close! conn))))))

(deftest batch-load-reads-one-input-file
  (let [db-path (temp-db-path "iam-batch-file-test")
        file (temp-jsonl-file role-config-json)]
    (with-out-str
      (iam/batch-load! :config {:db db-path :file (.getPath file)}))
    (let [conn (d/get-conn db-path iam/schema)]
      (try
        (is (= #{[role-name]}
               (q '[:find ?name
                    :where [_ :role/name ?name]]
                  (db conn))))
        (finally
          (close! conn))))))

(deftest batch-load-reads-stdin-when-input-file-is-omitted
  (let [db-path (temp-db-path "iam-batch-stdin-test")]
    (with-in-str (jsonl admin-policy-json)
      (with-out-str
        (iam/batch-load! :policy {:db db-path})))
    (let [conn (d/get-conn db-path iam/schema)]
      (try
        (is (= #{["LoaderAdminPolicy"]}
               (q '[:find ?name
                    :where [_ :policy/name ?name]]
                  (db conn))))
        (finally
          (close! conn))))))

(deftest batch-cli-rejects-extra-input-files
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"Only one input file is supported"
       (iam/batch-load-config! {:opts {:db "/tmp/unused" :file "one.jsonl"}
                                :args ["two.jsonl"]}))))

(defn -main [& _]
  (let [{:keys [fail error]} (run-tests 'iam-loader-test)]
    (when (pos? (+ fail error))
      (System/exit 1))))
