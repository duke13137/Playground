(do (require '[babashka.pods :as pods])
    (pods/load-pod 'huahaiy/datalevin "0.10.7"))

(ns iam-loader-fuzz-test
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is run-tests]]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [iam :as iam]
            [pod.huahaiy.datalevin :as d]))

(def account-id "123456789012")
(def region "us-east-1")
(def root-arn (str "arn:aws:iam::" account-id ":root"))
(def fuzz-trials
  (or (some-> (System/getenv "IAM_FUZZ_TRIALS") parse-long)
      20))
(def fuzz-failure-root "/tmp/iam-fuzz-failures")

(def inert-actions
  ["s3:GetObject"
   "ec2:DescribeInstances"
   "logs:CreateLogStream"
   "lambda:GetFunction"])

(def policy-shape-gen
  (gen/frequency [[5 (gen/return :direct-lower)]
                  [2 (gen/return :policy-version-with-opts)]
                  [2 (gen/return :policy-and-version-upper)]]))

(def bool-gen
  (gen/elements [false true]))

(defn role-name
  [idx]
  (str "FuzzRole" idx))

(defn role-id
  [idx]
  (format "AROAFUZZ%06d" idx))

(defn role-arn
  [idx]
  (str "arn:aws:iam::" account-id ":role/" (role-name idx)))

(defn managed-policy-name
  [idx]
  (str "FuzzManagedPolicy" idx))

(defn managed-policy-arn
  [idx]
  (str "arn:aws:iam::" account-id ":policy/" (managed-policy-name idx)))

(defn inline-policy-name
  [role-idx inline-idx]
  (str (role-name role-idx) "-InlinePolicy" inline-idx))

(defn inert-statement
  [sid action]
  {:Sid sid
   :Effect "Allow"
   :Action action
   :Resource "*"})

(defn admin-statement
  [sid]
  {:Sid sid
   :Effect "Allow"
   :Action "*"
   :Resource "*"})

(defn policy-document-spec
  [prefix idx admin? inert-actions*]
  (let [admin-sids (if admin?
                     [(str prefix "-Admin-" idx)]
                     [])
        inert-actions* (vec inert-actions*)
        inert-actions* (if (and (not admin?) (empty? inert-actions*))
                         [(first inert-actions)]
                         inert-actions*)
        inert-statements (map-indexed (fn [stmt-idx action]
                                        (inert-statement (str prefix "-Allow-" idx "-" stmt-idx) action))
                                      inert-actions*)]
    {:admin? admin?
     :admin-sids admin-sids
     :document {:Version "2012-10-17"
                :Statement (vec (concat (map admin-statement admin-sids)
                                        inert-statements))}}))

(defn trust-policy-document
  [trusted-arns]
  {:Version "2012-10-17"
   :Statement [{:Sid "TrustGeneratedPrincipals"
                :Effect "Allow"
                :Principal {:AWS (vec trusted-arns)}
                :Action "sts:AssumeRole"}]})

(defn ensure-some-admin-path
  [graph]
  (if (seq (for [role (:roles graph)
                 :let [managed-by-arn (into {} (map (juxt :arn identity) (:managed-policies graph)))
                       managed-admin? (some #(-> managed-by-arn (get %) :doc :admin?) (:attached-policy-arns role))
                       inline-admin? (some #(get-in % [:doc :admin?]) (:inline-policies role))]
                 :when (or managed-admin? inline-admin?)]
             (:name role)))
    graph
    (-> graph
        (update-in [:managed-policies 0 :doc] (fn [_] (policy-document-spec "managed" 0 true [])))
        (update-in [:roles 0 :attached-policy-arns]
                   (fn [arns]
                     (vec (distinct (cons (managed-policy-arn 0) (or arns []))))))
        (update-in [:roles 0 :attached-policies]
                   (fn [policies]
                     (vec (distinct (conj (vec (or policies []))
                                          {:arn (managed-policy-arn 0)
                                           :name (managed-policy-name 0)}))))))))

(defn normalize-role-groups
  [roles cut-flags]
  (let [groups (loop [current [(first roles)]
                      remaining (rest roles)
                      cuts cut-flags
                      acc []]
                 (if-let [role (first remaining)]
                   (if (first cuts)
                     (recur [role] (rest remaining) (rest cuts) (conj acc current))
                     (recur (conj current role) (rest remaining) (rest cuts) acc))
                   (conj acc current)))]
    (if (and (> (count roles) 1)
             (every? #(= 1 (count %)) groups))
      (vec (cons (vec (take 2 roles))
                 (mapv vector (drop 2 roles))))
      (vec groups))))

(defn role-config-item
  [role]
  {:accountId account-id
   :awsRegion region
   :resourceType "AWS::IAM::Role"
   :resourceId (:id role)
   :resourceName (:name role)
   :configurationStateId (str "fuzz-state-" (:index role))
   :configurationItemCaptureTime "2026-04-24T10:00:00.000Z"
   :configurationItemStatus "OK"
   :configuration {:arn (:arn role)
                   :roleId (:id role)
                   :roleName (:name role)
                   :path "/"
                   :createDate "2026-04-24T10:00:00Z"
                   :assumeRolePolicyDocument (trust-policy-document (:trusted-arns role))
                   :attachedManagedPolicies (mapv (fn [policy-arn]
                                                    {:policyName (->> (:attached-policies role)
                                                                      (filter #(= (:arn %) policy-arn))
                                                                      first
                                                                      :name)
                                                     :policyArn policy-arn})
                                                  (:attached-policy-arns role))
                   :rolePolicyList (mapv (fn [inline-policy]
                                           {:policyName (:name inline-policy)
                                            :policyDocument (get-in inline-policy [:doc :document])})
                                         (:inline-policies role))}})

(defn config-doc-events
  [roles groups]
  (mapv (fn [group-idx grouped-roles]
          {:event/type :config
           :event/id (str "config-" group-idx)
           :json {:configurationItems (mapv role-config-item grouped-roles)}})
        (range)
        groups))

(defn policy-json-shape
  [policy shape]
  (let [document (get-in policy [:doc :document])]
    (case shape
      :direct-lower
      {:json {:policyArn (:arn policy)
              :policyName (:name policy)
              :versionId "v1"
              :default true
              :Document document}
       :opts {}}

      :policy-version-with-opts
      {:json {:PolicyVersion {:VersionId "v1"
                              :IsDefaultVersion true
                              :Document document}}
       :opts {:policy-arn (:arn policy)
              :policy-name (:name policy)
              :default true}}

      :policy-and-version-upper
      {:json {:Policy {:Arn (:arn policy)
                       :PolicyName (:name policy)}
              :PolicyVersion {:VersionId "v1"
                              :IsDefaultVersion true
                              :Document document}}
       :opts {}}

      {:json {:policyArn (:arn policy)
              :policyName (:name policy)
              :versionId "v1"
              :default true
              :Document document}
       :opts {}})))

(defn policy-events
  [managed-policies shapes]
  (mapv (fn [policy shape]
          (merge {:event/type :policy
                  :event/id (str "policy-" (:index policy))}
                 (policy-json-shape policy shape)))
        managed-policies
        shapes))

(defn expand-shuffled-events
  [{:keys [canonical-events duplicate-flags shuffle-keys]}]
  (let [expanded (mapcat (fn [event duplicate?]
                           (if duplicate?
                             [event event]
                             [event]))
                         canonical-events
                         duplicate-flags)]
    (->> (map vector shuffle-keys expanded)
         (sort-by first)
         (mapv second))))

(defn attr-value
  [db-value eid attr]
  (d/q '[:find ?v .
         :in $ ?e ?attr
         :where [?e ?attr ?v]]
       db-value
       eid
       attr))

(defn admin-like-query-result
  [db-value]
  (let [rows (d/q (:admin-like-roles iam/sample-queries) db-value)]
    {:rows (into #{} rows)
     :count (count rows)}))

(defn role-policy-attachments-query-result
  [db-value]
  (let [rows (d/q (:role-policy-attachments iam/sample-queries) db-value)]
    {:rows (into #{} rows)
     :count (count rows)}))

(defn raw-role-policy-edge-query-result
  [db-value]
  (let [rows (d/q (:admin-like-role-policy-edges iam/sample-queries) db-value)
        normalized (into #{}
                         (map (fn [[role-eid policy-eid edge]]
                                [(attr-value db-value role-eid :role/name)
                                 (attr-value db-value policy-eid :policy/name)
                                 edge]))
                         rows)]
    {:rows normalized
     :count (count normalized)}))

(defn derived-admin-role-policy-edge-query-result
  [db-value]
  (let [admin-role-names (into #{} (map second) (:rows (admin-like-query-result db-value)))
        raw-edges (:rows (raw-role-policy-edge-query-result db-value))
        admin-edges (into #{} (filter (fn [[role-name _ _]]
                                        (contains? admin-role-names role-name)))
                          raw-edges)]
    {:rows admin-edges
     :count (count admin-edges)}))

(defn query-results
  [db-value]
  {:admin-like (admin-like-query-result db-value)
   :attachments (role-policy-attachments-query-result db-value)
   :raw-edges (raw-role-policy-edge-query-result db-value)
   :derived-admin-edges (derived-admin-role-policy-edge-query-result db-value)})

(defn attachment-rows-for-role
  [managed-by-arn role]
  (let [managed-rows (map (fn [policy-arn]
                            (let [policy (get managed-by-arn policy-arn)]
                              [(:name role) (:name policy) :attached-managed]))
                          (:attached-policy-arns role))
        inline-rows (map (fn [inline-policy]
                           [(:name role) (:name inline-policy) :inline])
                         (:inline-policies role))]
    (into #{} (concat managed-rows inline-rows))))

(defn admin-like-rows-for-role
  [managed-by-arn role]
  (let [managed-rows (for [policy-arn (:attached-policy-arns role)
                           :let [policy (get managed-by-arn policy-arn)]
                           sid (get-in policy [:doc :admin-sids])]
                       [(:id role) (:name role) (:arn role) (:name policy) sid])
        inline-rows (for [inline-policy (:inline-policies role)
                          sid (get-in inline-policy [:doc :admin-sids])]
                      [(:id role) (:name role) (:arn role) (:name inline-policy) sid])]
    (into #{} (concat managed-rows inline-rows))))

(defn oracle-results
  [graph]
  (let [managed-by-arn (into {} (map (juxt :arn identity) (:managed-policies graph)))
        attachments (apply set/union #{} (map #(attachment-rows-for-role managed-by-arn %) (:roles graph)))
        admin-like (apply set/union #{} (map #(admin-like-rows-for-role managed-by-arn %) (:roles graph)))
        admin-role-names (into #{} (map second) admin-like)
        derived-admin-edges (into #{} (filter (fn [[role-name _ _]]
                                                (contains? admin-role-names role-name)))
                                  attachments)]
    {:admin-like {:rows admin-like
                  :count (count admin-like)}
     :attachments {:rows attachments
                   :count (count attachments)}
     :raw-edges {:rows attachments
                 :count (count attachments)}
     :derived-admin-edges {:rows derived-admin-edges
                           :count (count derived-admin-edges)}}))

(defn get-conn
  []
  (d/get-conn (str "/tmp/iam-loader-fuzz-test-" (random-uuid)) iam/schema))

(defn close!
  [conn]
  (d/close conn))

(defn load-event!
  [conn event]
  (case (:event/type event)
    :config (iam/load-config-json! conn (:json event))
    :policy (iam/load-iam-policy-json! conn (:json event) (:opts event))))

(defn run-event-stream
  [events]
  (let [conn (get-conn)]
    (try
      (doseq [event events]
        (load-event! conn event))
      {:results (query-results (d/db conn))}
      (catch Throwable t
        {:error {:class (.getName (class t))
                 :message (.getMessage t)
                 :data (ex-data t)}})
      (finally
        (close! conn)))))

(defn compare-result-slices
  [label actual expected]
  (cond
    (not= (:rows actual) (:rows expected))
    {:label label
     :kind :row-mismatch
     :expected (:rows expected)
     :actual (:rows actual)}

    (not= (:count actual) (:count expected))
    {:label label
     :kind :count-mismatch
     :expected (:count expected)
     :actual (:count actual)}

    :else nil))

(defn case-failure
  [graph]
  (let [oracle (oracle-results graph)
        canonical-events (:canonical-events graph)
        shuffled-events (expand-shuffled-events graph)
        canonical-run (run-event-stream canonical-events)
        shuffled-run (run-event-stream shuffled-events)]
    (cond
      (:error canonical-run)
      {:kind :canonical-load-error
       :error (:error canonical-run)}

      (:error shuffled-run)
      {:kind :shuffled-load-error
       :error (:error shuffled-run)}

      :else
      (let [canonical (:results canonical-run)
            shuffled (:results shuffled-run)]
        (or
         (compare-result-slices :canonical-admin-like
                                (:admin-like canonical)
                                (:admin-like oracle))
         (compare-result-slices :canonical-attachments
                                (:attachments canonical)
                                (:attachments oracle))
         (compare-result-slices :canonical-raw-edges
                                (:raw-edges canonical)
                                (:raw-edges oracle))
         (compare-result-slices :canonical-derived-admin-edges
                                (:derived-admin-edges canonical)
                                (:derived-admin-edges oracle))
         (compare-result-slices :shuffled-admin-like
                                (:admin-like shuffled)
                                (:admin-like oracle))
         (compare-result-slices :shuffled-attachments
                                (:attachments shuffled)
                                (:attachments oracle))
         (compare-result-slices :shuffled-raw-edges
                                (:raw-edges shuffled)
                                (:raw-edges oracle))
         (compare-result-slices :shuffled-derived-admin-edges
                                (:derived-admin-edges shuffled)
                                (:derived-admin-edges oracle))
         (compare-result-slices :admin-like-order-stability
                                (:admin-like shuffled)
                                (:admin-like canonical))
         (compare-result-slices :attachments-order-stability
                                (:attachments shuffled)
                                (:attachments canonical))
         (compare-result-slices :raw-edges-order-stability
                                (:raw-edges shuffled)
                                (:raw-edges canonical))
         (compare-result-slices :derived-admin-edges-order-stability
                                (:derived-admin-edges shuffled)
                                (:derived-admin-edges canonical)))))))

(defn write-json!
  [path value]
  (io/make-parents path)
  (spit path (json/generate-string value {:pretty true})))

(defn persist-failing-case!
  [graph failure result]
  (let [dir (io/file fuzz-failure-root (str (System/currentTimeMillis) "-" (random-uuid)))
        canonical-events (:canonical-events graph)
        shuffled-events (expand-shuffled-events graph)]
    (.mkdirs dir)
    (spit (io/file dir "manifest.edn")
          (pr-str {:seed (:seed result)
                   :num-tests (:num-tests result)
                   :failure failure}))
    (spit (io/file dir "oracle.edn")
          (pr-str (oracle-results graph)))
    (spit (io/file dir "graph.edn")
          (pr-str (dissoc graph :canonical-events :duplicate-flags :shuffle-keys)))
    (doseq [[idx event] (map-indexed vector canonical-events)]
      (case (:event/type event)
        :config
        (write-json! (io/file dir "canonical" (format "config-%02d.json" idx))
                     (:json event))

        :policy
        (do
          (write-json! (io/file dir "canonical" (format "policy-%02d.json" idx))
                       (:json event))
          (spit (io/file dir "canonical" (format "policy-%02d-opts.edn" idx))
                (pr-str (:opts event))))))
    (doseq [[idx event] (map-indexed vector shuffled-events)]
      (case (:event/type event)
        :config
        (write-json! (io/file dir "shuffled" (format "config-%02d.json" idx))
                     (:json event))

        :policy
        (do
          (write-json! (io/file dir "shuffled" (format "policy-%02d.json" idx))
                       (:json event))
          (spit (io/file dir "shuffled" (format "policy-%02d-opts.edn" idx))
                (pr-str (:opts event))))))
    (.getAbsolutePath dir)))

(defn graph-case-from-components
  [managed-policies roles cut-flags policy-shapes duplicate-flags shuffle-keys]
  (let [base-graph (ensure-some-admin-path {:managed-policies managed-policies
                                            :roles roles})
        groups (normalize-role-groups (:roles base-graph) cut-flags)
        canonical-events (vec (concat (config-doc-events (:roles base-graph) groups)
                                      (policy-events (:managed-policies base-graph) policy-shapes)))]
    (assoc base-graph
           :duplicate-flags duplicate-flags
           :shuffle-keys shuffle-keys
           :canonical-events canonical-events)))

(defn role-generator
  [role-idx role-count managed-policy-count]
  (gen/let [attachment-flags (gen/vector bool-gen managed-policy-count)
            inline-count (gen/choose 0 3)
            inline-admin-flags (gen/vector bool-gen inline-count)
            inline-inert-actions (gen/vector (gen/vector (gen/elements inert-actions) 0 2) inline-count)
            trust-flags (gen/vector bool-gen role-count)]
    (let [attached-policy-arns (->> attachment-flags
                                    (keep-indexed (fn [idx attached?]
                                                    (when attached?
                                                      (managed-policy-arn idx))))
                                    vec)
          trusted-arns (->> trust-flags
                            (keep-indexed (fn [idx trusted?]
                                            (when trusted?
                                              (role-arn idx))))
                            (cons root-arn)
                            distinct
                            vec)
          inline-policies (mapv (fn [inline-idx admin? actions]
                                  {:name (inline-policy-name role-idx inline-idx)
                                   :doc (policy-document-spec (str "inline-" role-idx)
                                                              inline-idx
                                                              admin?
                                                              actions)})
                                (range inline-count)
                                inline-admin-flags
                                inline-inert-actions)]
      {:index role-idx
       :id (role-id role-idx)
       :name (role-name role-idx)
       :arn (role-arn role-idx)
       :attached-policy-arns attached-policy-arns
       :attached-policies (mapv (fn [policy-arn]
                                  {:arn policy-arn
                                   :name (some->> (re-find #"policy/(.+)$" policy-arn) second)})
                                attached-policy-arns)
       :trusted-arns trusted-arns
       :inline-policies inline-policies})))

(def graph-case-gen
  (gen/let [role-count (gen/choose 2 6)
            managed-policy-count (gen/choose 1 8)
            managed-admin-flags (gen/vector bool-gen managed-policy-count)
            managed-inert-actions (gen/vector (gen/vector (gen/elements inert-actions) 0 2)
                                              managed-policy-count)
            roles (apply gen/tuple
                         (map #(role-generator % role-count managed-policy-count)
                              (range role-count)))
            cut-flags (gen/vector bool-gen (max 0 (dec role-count)))
            policy-shapes (gen/vector policy-shape-gen managed-policy-count)]
    (let [managed-policies (mapv (fn [idx admin? actions]
                                   {:index idx
                                    :arn (managed-policy-arn idx)
                                    :name (managed-policy-name idx)
                                    :doc (policy-document-spec "managed" idx admin? actions)})
                                 (range managed-policy-count)
                                 managed-admin-flags
                                 managed-inert-actions)
          roles (vec roles)
          base-graph (ensure-some-admin-path
                      {:managed-policies managed-policies
                       :roles roles})
          canonical-events (vec (concat (config-doc-events (:roles base-graph)
                                                           (normalize-role-groups (:roles base-graph) cut-flags))
                                        (policy-events (:managed-policies base-graph) policy-shapes)))
          duplicate-flags-gen (gen/vector bool-gen (count canonical-events))]
      (gen/bind duplicate-flags-gen
                (fn [duplicate-flags]
                  (gen/let [shuffle-keys (gen/vector (gen/large-integer* {:min 0 :max 1000000})
                                                    (+ (count canonical-events)
                                                       (count (filter true? duplicate-flags))))]
                    (graph-case-from-components (:managed-policies base-graph)
                                                (:roles base-graph)
                                                cut-flags
                                                policy-shapes
                                                duplicate-flags
                                                shuffle-keys)))))))

(defn fuzz-result
  []
  (tc/quick-check fuzz-trials
                  (prop/for-all [graph graph-case-gen]
                    (nil? (case-failure graph)))))

(deftest generated-loader-and-query-fuzz
  (let [result (fuzz-result)]
    (if (:pass? result)
      (is true (str "Passed " (:num-tests result) " generative loader/query cases"))
      (let [graph (first (get-in result [:shrunk :smallest]))
            failure (case-failure graph)
            fixture-dir (persist-failing-case! graph failure result)]
        (is false
            (str "Generative fuzz failure after "
                 (:num-tests result)
                 " tests, seed "
                 (:seed result)
                 ", fixtures persisted at "
                 fixture-dir
                 "\n"
                 (pr-str failure)))))))

(defn -main [& _]
  (let [{:keys [fail error]} (run-tests 'iam-loader-fuzz-test)]
    (when (pos? (+ fail error))
      (System/exit 1))))
