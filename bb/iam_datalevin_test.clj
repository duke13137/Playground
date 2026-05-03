(ns iam-datalevin-test
  (:require [babashka.process :as process]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is run-tests testing]]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [iam-datalog :as iam]
            [pod.huahaiy.datalevin :as d])
  (:import [java.nio.charset StandardCharsets]
           [java.security MessageDigest]))

(def account-id "123456789012")
(def hub-arn (str "arn:aws:iam::" account-id ":role/HubOrchestratorRole"))
(def worker-a-arn (str "arn:aws:iam::" account-id ":role/WorkerNodeRole-A"))
(def worker-b-arn (str "arn:aws:iam::" account-id ":role/WorkerNodeRole-B"))
(def worker-c-arn (str "arn:aws:iam::" account-id ":role/WorkerNodeRole-C"))

(def skill-dir
  (io/file (.getParent (io/file *file*))))

(def sample-dir
  (io/file skill-dir "samples"))

(def sample-files
  ["HubOrchestratorRole.json"
   "WorkerNodeRole-A.json"
   "WorkerNodeRole-B.json"
   "WorkerNodeRole-C.json"
   "OneSidedAssumerRole.json"
   "ExternalTrustDanglingRole.json"])

(defn sample-json
  [file-name]
  (iam/read-json-file (io/file sample-dir file-name)))

(defn temp-db-path
  []
  (str "/tmp/iam-analyzer-test-" (random-uuid)))

(defn delete-recursive!
  [path]
  (let [root (io/file path)]
    (when (.exists root)
      (doseq [file (reverse (file-seq root))]
        (io/delete-file file true)))))

(defn bbx!
  [& args]
  (let [{:keys [exit out err cmd]} (apply process/shell
                                          {:dir (str skill-dir)
                                           :out :string
                                           :err :string}
                                          "bb"
                                          "-x"
                                          args)]
    (when-not (zero? exit)
      (throw (ex-info "bb -x command failed"
                      {:cmd cmd
                       :exit exit
                       :out out
                       :err err})))
    out))

(defn bbx-json!
  "Run a bb -x command and unwrap the stable envelope ({:command :db :summary :results})
  back into a legacy flat map: `(merge summary {:results results})`. Useful for
  tests that pre-date the envelope and assert against summary fields at top level."
  [& args]
  (let [env (json/parse-string (apply bbx! args) true)]
    (merge (:summary env) (select-keys env [:results]))))

(defn bbx-stats
  [db-path]
  (-> (bbx-json! "iam-datalog/stats!" "--db" db-path)
      :results
      first))

(def logical-stat-keys
  [:database
   :schema
   :entities
   :config
   :roles
   :policies
   :documents
   :statements
   :actions
   :resources
   :principals
   :conditions
   :transitions])

(defn logical-stats
  [stats]
  (-> (select-keys stats logical-stat-keys)
      (update :database select-keys [:datoms :entities])))

(defn count-rows->map
  [rows]
  (into {} (map (juxt :value :count)) rows))

(defn stats-summary
  [stats]
  {:database (select-keys (:database stats) [:datoms :entities :max-eid])
   :by-type (count-rows->map (get-in stats [:entities :by-type]))
   :markers (get-in stats [:entities :markers])
   :transition-type (count-rows->map (get-in stats [:transitions :by-type]))
   :transition-origin (count-rows->map (get-in stats [:transitions :by-origin]))})

(defn compare-stats
  [before after]
  {:before (stats-summary before)
   :after (stats-summary after)})

(defn sample-path
  [file-name]
  (str (io/file sample-dir file-name)))

(defn load-sample-via-bbx!
  [db-path file-name]
  (bbx! "iam-datalog/load-config!" "--db" db-path (sample-path file-name)))

(defn stats-after-each-bbx-load!
  [db-path file-names]
  (loop [remaining file-names
         snapshots [{:label :before
                     :stats (bbx-stats db-path)}]]
    (if-let [file-name (first remaining)]
      (do
        (load-sample-via-bbx! db-path file-name)
        (recur (rest remaining)
               (conj snapshots {:label file-name
                                :stats (bbx-stats db-path)})))
      snapshots)))

(defn summarize-snapshots
  [snapshots]
  (mapv (fn [{:keys [label stats]}]
          {:label label
           :summary (stats-summary stats)})
        snapshots))

(defn seed-admin-chain-db!
  [db-path]
  (let [source-arn "arn:aws:iam::123456789012:role/SourceRole"
        admin-arn "arn:aws:iam::123456789012:role/AdminRole"
        other-source-arn "arn:aws:iam::210987654321:role/OtherSourceRole"
        other-admin-arn "arn:aws:iam::210987654321:role/OtherAdminRole"
        service "lambda.amazonaws.com"
        service-principal-key (iam/principal-key :service service)
        source-principal-key (iam/principal-key :aws source-arn)
        other-source-principal-key (iam/principal-key :aws other-source-arn)
        conn (d/get-conn db-path iam/schema)]
    (try
      (iam/transact-phases!
       conn
       [[{:role/id "source-id"
          :role/name "SourceRole"
          :aws/arn source-arn
          :aws/account-id "123456789012"}
         {:role/id "admin-id"
          :role/name "AdminRole"
          :aws/arn admin-arn
          :aws/account-id "123456789012"}
         {:role/id "other-source-id"
          :role/name "OtherSourceRole"
          :aws/arn other-source-arn
          :aws/account-id "210987654321"}
         {:role/id "other-admin-id"
          :role/name "OtherAdminRole"
          :aws/arn other-admin-arn
          :aws/account-id "210987654321"}
         {:action/key "*"
          :action/service "*"
          :action/name "*"
          :action/pattern? true
          :action/source [:policy]}
         {:resource/key "*"
          :resource/arn "*"
          :resource/pattern? true
          :resource/source :policy}
         {:resource/key admin-arn
          :resource/arn admin-arn
          :resource/pattern? false
          :resource/source :policy}
         {:resource/key other-admin-arn
          :resource/arn other-admin-arn
          :resource/pattern? false
          :resource/source :policy}
         {:service-resource/key "iam:role"
          :service-resource/name "role"
          :service-resource/arn-format ["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]}
         {:service-resource/key "sts:role"
          :service-resource/name "role"
          :service-resource/arn-format ["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]}
         {:service/key "iam"
          :service/name "iam"}
         {:service/key "sts"
          :service/name "sts"}
         {:condition-key/name "iam:passedtoservice"
          :condition-key/source [:service-reference]
          :condition-key/pattern? false
          :condition-key/service [[:service/key "iam"]]}
         {:action/key "iam:passrole"
          :action/service "iam"
          :action/name "PassRole"
          :action/access-level :write
          :action/pattern? false
          :action/source [:service-reference]
          :action/resource-type [[:service-resource/key "iam:role"]]
          :action/condition-key [[:condition-key/name "iam:passedtoservice"]]}
         {:action/key "sts:assumerole"
          :action/service "sts"
          :action/name "AssumeRole"
          :action/access-level :write
          :action/pattern? false
          :action/source [:service-reference]
          :action/resource-type [[:service-resource/key "sts:role"]]}
         {:principal/key source-principal-key
          :principal/type :aws
          :principal/value source-arn}
         {:principal/key other-source-principal-key
          :principal/type :aws
          :principal/value other-source-arn}
         {:principal/key service-principal-key
          :principal/type :service
          :principal/value service}
         {:statement/key "admin-statement"
          :statement/effect :allow
          :statement/action [[:action/key "*"]]
          :statement/resource [[:resource/key "*"]]}
         {:statement/key "other-admin-statement"
          :statement/effect :allow
          :statement/action [[:action/key "*"]]
          :statement/resource [[:resource/key "*"]]}
         {:statement/key "trust-source-admin"
          :statement/effect :allow
          :statement/action [[:action/key "sts:assumerole"]]
          :statement/resource [[:resource/key "*"]]
          :statement/principal [[:principal/key source-principal-key]]}
         {:statement/key "trust-other-source-admin"
          :statement/effect :allow
          :statement/action [[:action/key "sts:assumerole"]]
          :statement/resource [[:resource/key "*"]]
          :statement/principal [[:principal/key other-source-principal-key]]}
         {:condition/key "pass-source-admin/condition/StringEquals/iam:passedtoservice"
          :condition/catalog-key [:condition-key/name "iam:passedtoservice"]
          :condition/operator "StringEquals"
          :condition/field "iam:PassedToService"
          :condition/value {:value service}}
         {:condition/key "pass-other-source-admin/condition/StringEquals/iam:passedtoservice"
          :condition/catalog-key [:condition-key/name "iam:passedtoservice"]
          :condition/operator "StringEquals"
          :condition/field "iam:PassedToService"
          :condition/value {:value service}}
         {:statement/key "pass-source-admin"
          :statement/effect :allow
          :statement/action [[:action/key "iam:passrole"]]
          :statement/resource [[:resource/key admin-arn]]
          :statement/condition [[:condition/key "pass-source-admin/condition/StringEquals/iam:passedtoservice"]]}
         {:statement/key "pass-other-source-admin"
          :statement/effect :allow
          :statement/action [[:action/key "iam:passrole"]]
          :statement/resource [[:resource/key other-admin-arn]]
          :statement/condition [[:condition/key "pass-other-source-admin/condition/StringEquals/iam:passedtoservice"]]}
         {:document/key "admin-document"
          :document/statement [[:statement/key "admin-statement"]]}
         {:document/key "other-admin-document"
          :document/statement [[:statement/key "other-admin-statement"]]}
         {:document/key "admin-trust"
          :document/kind :trust-policy
          :document/statement [[:statement/key "trust-source-admin"]]}
         {:document/key "other-admin-trust"
          :document/kind :trust-policy
          :document/statement [[:statement/key "trust-other-source-admin"]]}
         {:document/key "source-pass-document"
          :document/kind :inline-policy
          :document/statement [[:statement/key "pass-source-admin"]]}
         {:document/key "other-source-pass-document"
          :document/kind :inline-policy
          :document/statement [[:statement/key "pass-other-source-admin"]]}
         {:policy/key "admin-policy"
          :policy/name "AdminPolicy"
          :policy/type :inline
          :policy/document [:document/key "admin-document"]}
         {:policy/key "other-admin-policy"
          :policy/name "OtherAdminPolicy"
          :policy/type :inline
          :policy/document [:document/key "other-admin-document"]}
         {:policy/key "source-pass-policy"
          :policy/name "SourcePassPolicy"
          :policy/type :inline
          :policy/document [:document/key "source-pass-document"]}
         {:policy/key "other-source-pass-policy"
          :policy/name "OtherSourcePassPolicy"
          :policy/type :inline
          :policy/document [:document/key "other-source-pass-document"]}]
        [{:role/id "admin-id"
          :role/inline-policy [[:policy/key "admin-policy"]]
          :role/trust-policy [:document/key "admin-trust"]}
         {:role/id "other-admin-id"
          :role/inline-policy [[:policy/key "other-admin-policy"]]
          :role/trust-policy [:document/key "other-admin-trust"]}
         {:role/id "source-id"
          :role/inline-policy [[:policy/key "source-pass-policy"]]}
         {:role/id "other-source-id"
          :role/inline-policy [[:policy/key "other-source-pass-policy"]]}]])
      (finally
        (d/close conn)))))

(defn with-sample-db
  [f]
  (let [conn (d/get-conn (temp-db-path) iam/schema)]
    (try
      (doseq [file-name sample-files]
        (iam/load-config-json! conn (sample-json file-name)))
      (f (d/db conn))
      (finally
        (d/close conn)))))

(defn group-value-count
  [rows value]
  (some #(when (= value (:value %)) (:count %)) rows))

(deftest schema-removes-unused-version-and-speculative-attrs
  (testing "policy versions and unused attrs are not in the new schema"
    (is (not-any? #(= "policy-version" (namespace %)) (keys iam/schema)))
    (is (not-any? #(= "role-transition" (namespace %)) (keys iam/schema)))
    (is (not-any? #(contains? iam/schema %)
                  [:policy/default-version
                   :policy/version
                   :policy/attachable?
                   :policy/attachment-count
                   :resource/matches
                   :statement/expanded-action
                   :statement/matched-resource
                   :role-transition/origin
                   :role-transition/key
                   :document/raw
                   :condition-key/operator-family]))
    (is (contains? iam/schema :entity/type))
    (is (contains? iam/schema :policy/document))))

(deftest role-config-tx-derives-trust-from-documents
  (let [txs (mapcat identity (iam/role-config-tx-phases (sample-json "HubOrchestratorRole.json")))
        roles (filter :role/id txs)
        documents (filter :document/key txs)
        statements (filter :statement/key txs)]
    (is (seq roles))
    (is (some #(= :trust-policy (:document/kind %)) documents))
    (is (seq statements))
    (is (not-any? #(= :role-transition (:entity/type %)) txs))
    (is (not-any? #(contains? % :role-transition/key) txs))))

(deftest transact-phases-injects-entity-types
  (let [conn (d/get-conn (temp-db-path) iam/schema)]
    (try
      (iam/transact-phases! conn [[{:policy/key "policy-1"
                                    :policy/name "PolicyOne"
                                    :policy/type :managed}]])
      (is (= #{:policy}
             (set (map first (d/q '[:find ?type
                                    :where [_ :entity/type ?type]]
                                  (d/db conn))))))
      (finally
        (d/close conn)))))

(deftest bbx-load-config-is-idempotent-by-logical-stats
  (let [db-path (temp-db-path)]
    (try
      (let [before (bbx-stats db-path)
            _ (load-sample-via-bbx! db-path "HubOrchestratorRole.json")
            after-first (bbx-stats db-path)
            _ (load-sample-via-bbx! db-path "HubOrchestratorRole.json")
            after-second (bbx-stats db-path)]
        (is (not= (logical-stats before) (logical-stats after-first))
            (pr-str (compare-stats before after-first)))
        (is (= (logical-stats after-first) (logical-stats after-second))
            (pr-str (compare-stats after-first after-second))))
      (finally
        (delete-recursive! db-path)))))

(deftest bbx-load-config-is-commutative-by-logical-stats
  (let [forward-db (temp-db-path)
        reverse-db (temp-db-path)
        file-names ["HubOrchestratorRole.json" "WorkerNodeRole-A.json"]]
    (try
      (let [forward-snapshots (stats-after-each-bbx-load! forward-db file-names)
            reverse-snapshots (stats-after-each-bbx-load! reverse-db (reverse file-names))
            forward-final (logical-stats (:stats (last forward-snapshots)))
            reverse-final (logical-stats (:stats (last reverse-snapshots)))]
        (is (= forward-final reverse-final)
            (pr-str {:forward (summarize-snapshots forward-snapshots)
                     :reverse (summarize-snapshots reverse-snapshots)})))
      (finally
        (delete-recursive! forward-db)
        (delete-recursive! reverse-db)))))

(deftest bbx-admin-role-chain-paths-reports-elevation-paths
  (let [db-path (temp-db-path)]
    (try
      (seed-admin-chain-db! db-path)
      (let [unscoped-report (bbx-json! "iam-datalog/admin-role-chain-paths!" "--db" db-path "--max-depth" "3")
            report (bbx-json! "iam-datalog/admin-role-chain-paths!"
                              "--db" db-path
                              "--max-depth" "3"
                              "--account" "123456789012")
            result (first (:results report))]
        (is (= 2 (:admin-targets unscoped-report)))
        (is (= 2 (:elevation-paths unscoped-report)))
        (is (= 1 (:admin-targets report)))
        (is (= 1 (:trust-role-edges report)))
        (is (= 1 (:elevation-paths report)))
        (is (= 1 (:source-roles report)))
        (is (= "123456789012" (:account report)))
        (is (= ["SourceRole" "AdminRole"] (mapv :name (:path result))))
        (is (= ["123456789012" "123456789012"] (mapv :account-id (:path result))))
        (is (= "SourceRole" (get-in result [:source :name])))
        (is (= "AdminRole" (get-in result [:admin :name])))
        (is (= "AdminPolicy" (get-in result [:admin :policy :name])))
        (is (= ["trust-source-admin"] (:trust-statements result))))
      (finally
        (delete-recursive! db-path)))))

(deftest pass-role-passable-service-principals-derive-concrete-services
  (let [trust-services ["ecs-tasks.amazonaws.com" "lambda.amazonaws.com"]]
    (is (= trust-services
           (#'iam/pass-role-passable-service-principals :any-service trust-services)))
    (is (= ["lambda.amazonaws.com"]
           (#'iam/pass-role-passable-service-principals "lambda.amazonaws.com" trust-services)))
    (is (= []
           (#'iam/pass-role-passable-service-principals "ec2.amazonaws.com" trust-services)))))

(deftest bbx-admin-pass-role-paths-reports-elevation-paths
  (let [db-path (temp-db-path)]
    (try
      (seed-admin-chain-db! db-path)
      (let [unscoped-report (bbx-json! "iam-datalog/admin-pass-role-paths!" "--db" db-path)
            report (bbx-json! "iam-datalog/admin-pass-role-paths!"
                              "--db" db-path
                              "--account" "123456789012")
            ;; AdminRole's `*`/`*` admin statement also covers iam:PassRole
            ;; with wildcard Resource, expanding to same-account targets;
            ;; explicit non-admin source still appears as a SourceRole→AdminRole
            ;; elevation path. Filter to that semantically interesting case.
            non-admin-result (->> (:results report)
                                  (filter #(= "SourceRole" (get-in % [:source :name])))
                                  first)]
        (is (= 2 (:admin-targets unscoped-report)))
        (is (= 6 (:pass-role-edges unscoped-report)))
        (is (= 4 (:elevation-paths unscoped-report)))
        (is (= 1 (:admin-targets report)))
        (is (= 3 (:pass-role-edges report)))
        (is (= 2 (:elevation-paths report)))
        (is (= 2 (:source-roles report)))
        (is (= "123456789012" (:account report)))
        (is (some? non-admin-result))
        (is (= ["SourceRole" "AdminRole"] (mapv :name (:path non-admin-result))))
        (is (= ["123456789012" "123456789012"] (mapv :account-id (:path non-admin-result))))
        (is (= "SourceRole" (get-in non-admin-result [:source :name])))
        (is (= "AdminRole" (get-in non-admin-result [:admin :name])))
        (is (= "AdminPolicy" (get-in non-admin-result [:admin :policy :name])))
        (is (= "lambda.amazonaws.com" (:delegated-service non-admin-result)))
        (is (= [] (:passable-service-principals non-admin-result)))
        (is (= "pass-source-admin" (:permission-statement non-admin-result))))
      (finally
        (delete-recursive! db-path)))))

(deftest bbx-validate-admin-path-entities-checks-service-reference
  (let [db-path (temp-db-path)]
    (try
      (seed-admin-chain-db! db-path)
      (let [report (bbx-json! "iam-datalog/validate-admin-path-entities!"
                               "--db" db-path
                               "--max-depth" "3"
                               "--account" "123456789012")
            contexts (:contexts report)
            ;; The seed admin statement (Action=*, Resource=*) also satisfies
            ;; iam:PassRole and now produces an extra pass-role-permission
            ;; context for the AdminRole self-elevation. Pick the original
            ;; SourceRole→AdminRole context with the iam:passedtoservice
            ;; condition for assertions.
            pass-context (some #(when (and (= "pass-role-permission" (:context %))
                                           (seq (:condition-checks %))) %)
                               contexts)
            trust-context (some #(when (= "trust-policy" (:context %)) %) contexts)]
        (is (true? (get-in report [:summary :valid?])))
        (is (zero? (get-in report [:summary :issues])))
        (is (= 4 (get-in report [:summary :checked-contexts])))
        (is (= "iam:passrole" (get-in pass-context [:expected-action-check :action])))
        (is (true? (get-in pass-context [:expected-action-check :covered?])))
        (is (= "supported" (get-in pass-context [:target-resource-check :status])))
        (is (= "supported" (get-in (first (:condition-checks pass-context)) [:status])))
        (is (= "sts:assumerole" (get-in trust-context [:expected-action-check :action])))
        (is (= "supported" (get-in trust-context [:target-resource-check :status]))))
      (finally
        (delete-recursive! db-path)))))

(deftest sample-trust-graph-queries-derive-from-documents
  (with-sample-db
    (fn [db]
      (let [worker-a-sources (set (map :source (iam/roles-that-can-assume db worker-a-arn)))
            hub-targets (set (map :target-arn (iam/roles-that-can-be-assumed-by db hub-arn)))
            reachable-from-hub (set (map :target-arn (iam/assume-role-reachable db hub-arn)))]
        (is (contains? worker-a-sources hub-arn))
        (is (contains? worker-a-sources worker-c-arn))
        (is (contains? hub-targets worker-a-arn))
        (is (contains? hub-targets worker-b-arn))
        (is (contains? reachable-from-hub worker-a-arn))
        (is (contains? reachable-from-hub worker-c-arn))))))

(deftest sample-policy-queries-use-direct-policy-document
  (with-sample-db
    (fn [db]
      (is (contains? (set (iam/role-allowed-actions db hub-arn))
                     "lambda:invokefunction"))
      (is (seq (iam/role-all-policies db hub-arn)))
      (is (empty? (iam/roles-with-pass-role-to db hub-arn))))))

(deftest sample-db-stats-are-available-without-ad-hoc-queries
  (with-sample-db
    (fn [db]
      (let [stats (iam/db-stats db)]
        (is (pos? (get-in stats [:database :datoms])))
        (is (= (count sample-files) (get-in stats [:entities :markers :roles])))
        (is (= (count sample-files)
               (group-value-count (get-in stats [:entities :by-type]) ":role")))
        (is (= (count sample-files) (get-in stats [:roles :with-trust-policy])))))))

(defn -main
  [& _]
  (let [{:keys [fail error]} (run-tests 'iam-test)]
    (when (pos? (+ fail error))
      (System/exit 1))))

;; ---------------------------------------------------------------------------
;; Regression fingerprinting (for refactor safety; see PLAN.md "Regression Test
;; Plan"). Lives here rather than in iam-datalog so production code stays slim.

(defn- sha256-hex
  [^String s]
  (let [md (MessageDigest/getInstance "SHA-256")
        bs (.digest md (.getBytes s StandardCharsets/UTF_8))
        sb (StringBuilder.)]
    (doseq [b bs]
      (.append sb (format "%02x" (bit-and (long b) 0xff))))
    (.toString sb)))

(defn- count+sha
  "Returns {:count N :sha hex} for a coll. Sorts by pr-str so output is
  deterministic regardless of internal ordering."
  [coll]
  (let [items (sort (mapv pr-str coll))]
    {:count (count items)
     :sha   (sha256-hex (str/join "\n" items))}))

(defn- schema-fingerprint
  "Sorted seq of [attr {keys-set}] for declared schema attrs."
  []
  (->> iam/schema
       (map (fn [[k v]]
              [k (select-keys v [:db/valueType :db/cardinality :db/unique
                                 :db/index :db/isComponent :db/tupleAttrs
                                 :db/tupleType :db/tupleTypes :db/fulltext])]))
       (sort-by first)
       vec))

(defn- role-fingerprint-block
  [db role-arn]
  {:role-arn               role-arn
   :role-allowed-actions   (count+sha (map :action (iam/role-allowed-actions db role-arn)))
   :roles-that-can-assume  (count+sha (map :source-arn (iam/roles-that-can-assume db role-arn)))
   :roles-with-pass-role-to (count+sha (map :source-arn (iam/roles-with-pass-role-to db role-arn)))})

(defn regression-fingerprint
  "Deterministic fingerprint of a Datalevin IAM graph for regression testing.
  Returns a map of small {:count :sha} summaries plus :stats and :schema."
  [db {:keys [smoke-roles] :or {smoke-roles []}}]
  (let [admins   (iam/admin-like-roles db)
        trust-es (iam/trust-role-assume-edges db)
        pass-es  (iam/pass-role-graph db)
        chain    (iam/admin-role-chain-paths db)
        passes   (iam/admin-pass-role-paths db)]
    {:schema (count+sha (schema-fingerprint))
     :stats  (iam/db-stats db)
     :edges  {:assume-role-trust (count+sha (map (juxt :source-arn :target-arn) trust-es))
              :pass-role         (count+sha (map (juxt :source-arn :target-arn :service) pass-es))}
     :admin  {:admin-like-roles (count+sha (map :role-arn admins))}
     :paths  {:admin-role-chain
              {:admin-targets    (:admin-targets chain)
               :trust-role-edges (:trust-role-edges chain)
               :elevation-paths  (:elevation-paths chain)
               :source-roles     (:source-roles chain)
               :sha (-> (mapv (fn [{:keys [source admin hop-count path]}]
                                [(:arn source) (:arn admin) hop-count
                                 (mapv :arn path)])
                              (:results chain))
                        sort
                        (->> (str/join "\n"))
                        sha256-hex)}
              :admin-pass-role
              {:admin-targets    (:admin-targets passes)
               :pass-role-edges  (:pass-role-edges passes)
               :elevation-paths  (:elevation-paths passes)
               :source-roles     (:source-roles passes)
               :sha (-> (mapv (fn [{:keys [source admin delegated-service]}]
                                [(:arn source) (:arn admin) delegated-service])
                              (:results passes))
                        sort
                        (->> (str/join "\n"))
                        sha256-hex)}}
     :smoke-roles (mapv #(role-fingerprint-block db %) smoke-roles)}))

(def ^:private default-smoke-roles
  ["arn:aws:iam::928390949214:role/ais-prod-mgmt-partner-comp"])

(defn regression-fingerprint!
  "CLI: compute a deterministic regression fingerprint of an IAM Datalevin
  graph. Capture a baseline before refactor and diff after.

  Usage: bb -x iam-test/regression-fingerprint! --db DB [--out FILE] [--smoke-role ARN]"
  {:org.babashka/cli
   {:spec {:db {:ref "<path>" :desc "Datalevin database path." :require true}
           :out {:ref "<file>" :desc "Optional output file (default stdout)." :alias :o}
           :smoke-role {:ref "<arn>" :desc "Smoke-test role ARN. Repeatable." :coerce []}}}}
  [{:keys [db out smoke-role] :as opts}]
  (when-not (seq (str db))
    (throw (ex-info "--db is required" {:opts opts})))
  (let [conn   (iam/get-conn db)
        smokes (cond
                 (nil? smoke-role) default-smoke-roles
                 (string? smoke-role) [smoke-role]
                 :else (vec smoke-role))]
    (try
      (let [fp      (regression-fingerprint (d/db conn) {:smoke-roles smokes})
            out-str (json/generate-string fp {:pretty true})]
        (if (seq (str out))
          (do (io/make-parents out)
              (spit out (str out-str "\n"))
              (println (str "wrote " out)))
          (println out-str)))
      (finally
        (iam/close-conn! conn)))))
(def baseline-fingerprint-path
  (io/file skill-dir "regression" "baseline.json"))

(defn read-baseline-fingerprint
  []
  (when (.exists baseline-fingerprint-path)
    (with-open [r (io/reader baseline-fingerprint-path)]
      (json/parse-stream r true))))

(defn- fingerprint-diff
  "Return paths where actual differs from expected. Stable, small output."
  [expected actual]
  (let [diffs (atom [])
        walk (fn walk [path e a]
               (cond
                 (and (map? e) (map? a))
                 (doseq [k (sort (set (concat (keys e) (keys a))))]
                   (walk (conj path k) (get e k) (get a k)))
                 (= e a) nil
                 :else (swap! diffs conj {:path path :expected e :actual a})))]
    (walk [] expected actual)
    @diffs))

(deftest real-data-fingerprint-matches-baseline
  ;; Gated: runs only when caller has a real graph DB and explicitly opts in.
  (when (= "1" (System/getenv "IAM_GRAPHDB_REAL"))
    (let [db-path (or (System/getenv "IAM_GRAPHDB_PATH")
                      (str skill-dir "/iam.dtlv"))
          baseline (read-baseline-fingerprint)]
      (is (some? baseline)
          (str "missing baseline fingerprint at " baseline-fingerprint-path
               " — run: bb -x iam-test/regression-fingerprint! --db "
               db-path " --out " baseline-fingerprint-path))
      (when baseline
        (let [conn (iam/get-conn db-path)
              smokes (or (some-> baseline :smoke-roles (->> (mapv :role-arn)))
                         default-smoke-roles)]
          (try
            (let [actual (regression-fingerprint (d/db conn) {:smoke-roles smokes})
                  ;; cheshire round-trip baseline+actual through json so types
                  ;; and key ordering are comparable.
                  norm   #(json/parse-string (json/generate-string %) true)
                  diffs  (fingerprint-diff (norm baseline) (norm actual))]
              (is (empty? diffs)
                  (str "fingerprint diverged from baseline at "
                       (count diffs) " path(s): "
                       (pr-str (take 5 diffs)))))
            (finally
              (iam/close-conn! conn))))))))

;; ===========================================================================
;; Property-style tests
;;
;; Three families of properties:
;;   1. CRDT loader algebra (idempotence, commutativity, associativity)
;;      across shuffled sample-file load orders.
;;   2. Relational-algebra invariants on derived edges and paths — every
;;      reported path is a witness over real Datalevin edges.
;;   3. Graph algorithm properties on `admin-role-chain-paths` /
;;      `admin-pass-role-paths` — simple paths, length identity, account
;;      monotonicity, forward/backward symmetry, max-depth monotonicity.
;;
;; The graph properties run only when ./iam.dtlv exists (real production DB).
;; The CRDT loader properties always run; they use bb -x with sample fixtures.
;; ===========================================================================

(def real-db-path "./iam.dtlv")

(defn- bbx-stats-shape
  "Logical-stats shape used by CRDT loader properties. Robust to physical
  storage differences."
  [db-path]
  (let [env (json/parse-string (bbx! "iam-datalog/stats!" "--db" db-path) true)
        s (-> env :results first)]
    {:by-type (into (sorted-map)
                    (map (juxt :value :count))
                    (get-in s [:entities :by-type]))
     :counts (select-keys s [:roles :policies :statements :actions
                             :resources :principals :conditions])
     :datoms (get-in s [:database :datoms])}))

(defn- load-into-fresh-db!
  "Seed a fresh DB by loading `files` in given order via bb -x. Returns the
  DB path; caller must delete-recursive!."
  [files]
  (let [db (temp-db-path)]
    (doseq [f files] (load-sample-via-bbx! db f))
    db))

(defn- with-real-db
  "Run f against the shared real DB at ./iam.dtlv if present; else skip with
  an informative message."
  [f]
  (if-not (.exists (io/file real-db-path))
    (println "[iam-test] skipping graph properties — no" real-db-path)
    (let [conn (d/get-conn real-db-path iam/schema)]
      (try (f (d/db conn))
           (finally (d/close conn))))))

(defn- unique-permutations
  "Up to k unique permutations of xs, deterministic by index."
  [xs k]
  (->> (gen/sample (gen/shuffle xs) (* 4 k))
       distinct
       (take k)
       vec))

;; ---------------------------------------------------------------------------
;; CRDT / loader algebra
;; ---------------------------------------------------------------------------

(deftest loader-idempotence-property
  (testing "loading the same file N times == loading once (logical stats)"
    (doseq [f sample-files
            n [2 3 5]]
      (let [once (load-into-fresh-db! [f])
            many (load-into-fresh-db! (repeat n f))]
        (try
          (is (= (bbx-stats-shape once) (bbx-stats-shape many))
              (str "idempotence violated for " f " ×" n))
          (finally
            (delete-recursive! once)
            (delete-recursive! many)))))))

(deftest loader-commutativity-property
  (testing "loader is commutative across orderings of the same file set"
    (let [orderings (unique-permutations sample-files 4)
          stats (mapv (fn [order]
                        (let [db (load-into-fresh-db! order)]
                          (try (bbx-stats-shape db)
                               (finally (delete-recursive! db)))))
                      orderings)
          ref (first stats)]
      (doseq [[order s] (map vector orderings stats)]
        (is (= ref s)
            (str "commutativity broken for order " (vec order)))))))

(deftest loader-associativity-property
  (testing "splitting load batches at any pivot yields the same logical state"
    (doseq [pivot (range 1 (count sample-files))]
      (let [[a b] (split-at pivot sample-files)
            one (load-into-fresh-db! sample-files)
            ab (let [db (temp-db-path)]
                 (doseq [f a] (load-sample-via-bbx! db f))
                 (doseq [f b] (load-sample-via-bbx! db f))
                 db)]
        (try
          (is (= (bbx-stats-shape one) (bbx-stats-shape ab))
              (str "associativity broken at pivot " pivot))
          (finally
            (delete-recursive! one)
            (delete-recursive! ab)))))))

;; ---------------------------------------------------------------------------
;; Graph algorithm properties — AssumeRole role-chain paths
;; ---------------------------------------------------------------------------

(defn- path-arns [p] (mapv :arn (:path p)))

(defn- trust-edge-index
  "Index trust-role edges by (source-arn, target-arn) for O(1) connectivity
  lookup. Value is a set of statement keys connecting that pair."
  [db]
  (->> (iam/trust-role-assume-edges db)
       (reduce (fn [m {:keys [source-arn target-arn trust-statement]}]
                 (update m [source-arn target-arn] (fnil conj #{}) trust-statement))
               {})))

(deftest assume-paths-are-simple
  (with-real-db
    (fn [db]
      (let [report (iam/admin-role-chain-paths db)]
        (doseq [p (:results report)
                :let [arns (path-arns p)]]
          (is (= (count arns) (count (set arns)))
              (str "non-simple path (cycle): " arns)))))))

(deftest assume-path-length-identity
  (with-real-db
    (fn [db]
      (let [report (iam/admin-role-chain-paths db)]
        (doseq [{:keys [hop-count path trust-statements] :as p} (:results report)]
          (is (= hop-count (dec (count path)))
              (str "hop-count ≠ |path|-1 for " (path-arns p)))
          (is (= hop-count (count trust-statements))
              (str "hop-count ≠ |trust-statements| for " (path-arns p))))))))

(deftest assume-path-edges-are-witnesses
  (testing "every (path[i], path[i+1], stmt[i]) triple is a real trust edge"
    (with-real-db
      (fn [db]
        (let [report (iam/admin-role-chain-paths db)
              idx (trust-edge-index db)
              missing (atom [])]
          (doseq [{:keys [path trust-statements]} (:results report)
                  :let [arns (mapv :arn path)]
                  [src tgt stmt] (map vector
                                      (butlast arns)
                                      (rest arns)
                                      trust-statements)]
            (let [stmts (get idx [src tgt])]
              (when-not (and stmts (contains? stmts stmt))
                (swap! missing conj {:src src :tgt tgt :stmt stmt
                                     :known stmts}))))
          (is (empty? @missing)
              (str "missing-witness edges: " (take 5 @missing))))))))

(deftest assume-path-endpoints
  (with-real-db
    (fn [db]
      (let [report (iam/admin-role-chain-paths db)]
        (doseq [{:keys [source admin path]} (:results report)]
          (is (= (:arn source) (:arn (first path))))
          (is (= (:arn admin) (:arn (last path)))))))))

(deftest assume-account-scoping-is-monotone
  (testing "filtering by account yields a subset of the unfiltered result"
    (with-real-db
      (fn [db]
        (let [unfiltered (set (map (juxt #(get-in % [:source :arn])
                                         #(get-in % [:admin :arn])
                                         path-arns)
                                   (:results (iam/admin-role-chain-paths db))))
              accounts (->> unfiltered
                            (mapcat (fn [[_ _ arns]]
                                      (keep (fn [arn]
                                              (when-let [m (re-find #":(\d+):role/" arn)]
                                                (second m)))
                                            arns)))
                            distinct)]
          (doseq [acct (take 5 accounts)]
            (let [scoped (set (map (juxt #(get-in % [:source :arn])
                                         #(get-in % [:admin :arn])
                                         path-arns)
                                   (:results (iam/admin-role-chain-paths
                                              db {:account acct}))))]
              (is (set/subset? scoped unfiltered)
                  (str "account-scoped not subset for acct=" acct
                       " extra=" (set/difference scoped unfiltered))))))))))

;; ---------------------------------------------------------------------------
;; Graph algorithm properties — PassRole paths
;; ---------------------------------------------------------------------------

(deftest pass-role-paths-are-single-hop
  (with-real-db
    (fn [db]
      (let [report (iam/admin-pass-role-paths db)]
        (doseq [p (:results report)]
          (is (= 1 (:hop-count p)))
          (is (= 2 (count (:path p))))
          (is (= (get-in p [:source :arn]) (:arn (first (:path p)))))
          (is (= (get-in p [:admin :arn])  (:arn (last  (:path p))))))))))

(deftest pass-role-permission-statement-resolves
  (testing "every :permission-statement is a real :allow iam:PassRole stmt"
    (with-real-db
      (fn [db]
        (let [report (iam/admin-pass-role-paths db)
              keys-seen (set (keep :permission-statement (:results report)))]
          (doseq [k keys-seen]
            (let [stmt (d/pull db
                               '[:statement/effect
                                 {:statement/action [:action/key]}]
                               [:statement/key k])
                  action-keys (set (map :action/key (:statement/action stmt)))]
              (is (= :allow (:statement/effect stmt))
                  (str "non-allow permission-statement: " k))
              (is (some #(contains? #{"iam:passrole" "iam:*" "*"} %)
                        action-keys)
                  (str "no PassRole-covering action on " k
                       " actions=" action-keys)))))))))

;; ---------------------------------------------------------------------------
;; Forward / backward symmetry (relational equality of derived sets)
;; ---------------------------------------------------------------------------

(deftest assume-forward-equals-backward-immediate
  (testing "depth=1 AssumeRole sources via forward query == reverse-pull set"
    (with-real-db
      (fn [db]
        (let [v (iam/validate-admin-role-chain-paths-with-pull-backwards db)]
          (is (get-in v [:summary :sources-match?])
              (pr-str (:summary v))))))))

(deftest pass-role-forward-equals-backward
  (testing "PassRole (source, admin) pairs match between forward and pull-back"
    (with-real-db
      (fn [db]
        (let [v (iam/validate-admin-pass-role-paths-with-pull-backwards db)]
          (is (get-in v [:summary :pairs-match?])
              (pr-str (:summary v))))))))

;; ---------------------------------------------------------------------------
;; Pull-validator / forward-report cross-check
;; ---------------------------------------------------------------------------

(deftest pull-validator-hop-count-matches-forward
  (with-real-db
    (fn [db]
      (let [v (iam/validate-admin-role-chain-paths-with-pull db)]
        (doseq [r (:results v)]
          (is (= (:hop-count r) (count (:hops r)))
              (str "hop count mismatch for path " (mapv :arn (:path r)))))
        (let [s (:summary v)]
          (is (= (:hops s) (+ (:valid-hops s) (:invalid-hops s)))
              (pr-str s)))))))

(deftest pass-role-pull-validator-one-hop
  (with-real-db
    (fn [db]
      (let [v (iam/validate-admin-pass-role-paths-with-pull db)]
        (doseq [r (:results v)]
          (is (= 1 (count (:hops r))))
          (is (= (:valid? r) (:valid? (first (:hops r))))))))))

;; ---------------------------------------------------------------------------
;; Generative property — random max-depth monotonicity
;; ---------------------------------------------------------------------------

(deftest assume-paths-monotone-in-max-depth
  (testing "paths are monotone non-decreasing as max-depth increases"
    (with-real-db
      (fn [db]
        (let [result
              (tc/quick-check
               20
               (prop/for-all
                [d1 (gen/choose 1 6)
                 delta (gen/choose 0 4)]
                (let [d2 (+ d1 delta)
                      pair-set (fn [d]
                                 (set (map (juxt #(get-in % [:source :arn])
                                                 #(get-in % [:admin :arn]))
                                           (:results (iam/admin-role-chain-paths
                                                      db {:max-depth d})))))]
                  (set/subset? (pair-set d1) (pair-set d2)))))]
          (is (:result result) (pr-str result)))))))
