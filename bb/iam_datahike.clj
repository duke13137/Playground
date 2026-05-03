(babashka.pods/load-pod 'replikativ/datahike "0.8.1678")

(ns iam-datahike
  (:require [babashka.cli :as cli]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datahike.pod :as d]))

(def schema
  {:arn/partition
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/service
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/region
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/account-id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/resource
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/resource-type
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/resource-id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/resource-path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/resource-qualifier
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :arn/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :role/arn
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :role/account-id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/tags
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/id
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/value}

   :role/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :role/create-date
   {:db/valueType :db.type/instant
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

   :config/imported-at
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :config/status
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config/source-path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config/describes
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

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

   :policy/default-version
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :policy/version
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

   :document/json
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :document/source-path
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
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config-resource-type/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :config-resource-type/name
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :config-resource-type/source-url
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config-resource-type/imported-at
   {:db/valueType :db.type/instant
    :db/cardinality :db.cardinality/one}

   :config-property/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :config-property/path
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :config-property/type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :config-property/resource-type
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/one}

   :service/key
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :service/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/version
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/source-url
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one}

   :service/imported-at
   {:db/valueType :db.type/instant
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
    :db/cardinality :db.cardinality/many}

   :condition-key/name
   {:db/valueType :db.type/string
    :db/cardinality :db.cardinality/one
    :db/unique :db.unique/identity}

   :condition-key/value-type
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :condition-key/source
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :condition-key/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :condition-key/service
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

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

   :action/access-level
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/one}

   :action/pattern?
   {:db/valueType :db.type/boolean
    :db/cardinality :db.cardinality/one}

   :action/source
   {:db/valueType :db.type/keyword
    :db/cardinality :db.cardinality/many}

   :action/resource-type
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}

   :action/condition-key
   {:db/valueType :db.type/ref
    :db/cardinality :db.cardinality/many}})

(defn schema-tx
  []
  (mapv (fn [[ident attr]]
          (assoc attr :db/ident ident))
        schema))

(defn memory-config
  []
  {:store {:backend :memory
           :id (random-uuid)}
   :keep-history? true
   :schema-flexibility :write
   :initial-tx (schema-tx)})

(defn stable-db-id
  [db-path]
  (java.util.UUID/nameUUIDFromBytes
   (.getBytes (.getAbsolutePath (io/file db-path)) "UTF-8")))

(defn db-config
  [db-path]
  {:store {:backend :file
           :path db-path
           :id (stable-db-id db-path)}
   :keep-history? true
   :schema-flexibility :write
   :initial-tx (schema-tx)})

(defn ensure-database!
  [config]
  (when-not (d/database-exists? config)
    (d/create-database config))
  config)

(defn get-conn
  [config]
  (let [conn (d/connect (ensure-database! config))]
    (d/transact conn (schema-tx))
    conn))

(defn close-conn!
  [conn]
  (d/release conn))

(defn parse-json
  [s]
  (json/parse-string s true))

(defn read-json-file
  [path]
  (parse-json (slurp (io/file path))))

(defn parse-jsonish
  [x]
  (cond
    (map? x) x
    (vector? x) x
    (string? x) (let [trimmed (str/trim x)]
                  (if (or (str/starts-with? trimmed "{")
                          (str/starts-with? trimmed "["))
                    (parse-json trimmed)
                    (try
                      (let [decoded (java.net.URLDecoder/decode trimmed "UTF-8")]
                        (if (or (str/starts-with? decoded "{")
                                (str/starts-with? decoded "["))
                          (parse-json decoded)
                          x))
                      (catch Exception _ x))))
    :else x))

(defn parse-aws-instant
  [x]
  (cond
    (nil? x) nil
    (instance? java.util.Date x) x
    (instance? java.time.Instant x) (java.util.Date/from x)
    (string? x) (try
                  (java.util.Date/from (java.time.Instant/parse x))
                  (catch Exception _ nil))
    :else nil))

(defn ensure-vector
  [x]
  (cond
    (nil? x) []
    (vector? x) x
    (sequential? x) (vec x)
    :else [x]))

(defn clean-entity
  [m]
  (into {} (remove (comp nil? val) m)))

(defn first-present
  [m ks]
  (some #(when (contains? m %) (get m %)) ks))

(defn action-key
  [action]
  (str/lower-case (str action)))

(defn resource-key
  [resource]
  (str resource))

(defn condition-key-name
  [field]
  (str/lower-case (name field)))

(defn principal-key
  [principal-type value]
  (str (name principal-type) ":" value))

(def arn-slash-resource-types
  #{"accesspoint"
    "alias"
    "assumed-role"
    "certificate"
    "group"
    "instance-profile"
    "mfa"
    "oidc-provider"
    "policy"
    "role"
    "saml-provider"
    "server-certificate"
    "user"})

(defn- split-path-id
  [s]
  (let [parts (str/split (str s) #"/")
        resource-id (last parts)
        resource-path (when (< 1 (count parts))
                        (str (str/join "/" (butlast parts)) "/"))]
    {:arn/resource-id resource-id
     :arn/resource-path resource-path}))

(defn- parse-arn-resource
  [service resource]
  (cond
    (str/includes? resource ":")
    (let [[resource-type rest] (str/split resource #":" 2)
          [resource-id qualifier] (str/split rest #":" 2)]
      {:arn/resource-type resource-type
       :arn/resource-id resource-id
       :arn/resource-qualifier qualifier})

    (str/includes? resource "/")
    (let [[head tail] (str/split resource #"/" 2)]
      (if (contains? arn-slash-resource-types head)
        (merge {:arn/resource-type head}
               (split-path-id tail))
        {:arn/resource-id resource}))

    :else
    {:arn/resource-id resource}))

(defn parse-arn
  [arn]
  (let [arn (str arn)
        parts (str/split arn #":" 6)]
    (when (and (= 6 (count parts))
               (= "arn" (first parts)))
      (let [[_ partition service region account-id resource] parts]
        (clean-entity
         (merge {:arn/partition partition
                 :arn/service service
                 :arn/region region
                 :arn/account-id account-id
                 :arn/resource resource
                 :arn/pattern? (or (str/includes? arn "*")
                                    (str/includes? arn "?"))}
                (parse-arn-resource service resource)))))))

(defn arn-facets
  ([arn] (arn-facets arn {}))
  ([arn {:keys [include-arn?]}]
   (when-let [parsed (parse-arn arn)]
     (cond-> parsed
       include-arn? (assoc :role/arn (str arn))))))

(defn inline-policy-key
  [owner-arn policy-name]
  (str owner-arn "/inline-policy/" policy-name))

(defn trust-policy-key
  [role-arn]
  (str role-arn "/trust-policy"))

(defn policy-version-key
  [policy-key version-id]
  (str policy-key "/version/" version-id))

(defn document-key
  [policy-version-key]
  (str policy-version-key "/document"))

(defn sha-256-hex
  [s]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")
        bytes (.digest md (.getBytes (str s) "UTF-8"))]
    (apply str (map #(format "%02x" (bit-and % 0xff)) bytes))))

(defn canonical-value
  [v]
  (cond
    (map? v) (into (sorted-map)
                   (map (fn [[k x]] [(name k) (canonical-value x)]))
                   v)
    (sequential? v) (vec (sort-by pr-str (map canonical-value v)))
    (keyword? v) (name v)
    :else v))

(defn statement-content-hash
  [statement]
  (subs (sha-256-hex (pr-str (canonical-value statement))) 0 16))

(defn principal-values
  [principal]
  (cond
    (nil? principal) []
    (= "*" principal) [[:star "*"]]
    (string? principal) [[:aws principal]]
    (map? principal) (vec
                      (for [[k v] principal
                            :let [ptype (case k
                                          :AWS :aws
                                          :Service :service
                                          :Federated :federated
                                          :CanonicalUser :canonical-user
                                          (keyword (str/lower-case (name k))))]
                            value (ensure-vector v)]
                        [ptype value]))
    :else []))

(defn principal-type
  [principal-source value]
  (let [value (str value)]
    (case principal-source
      :star :wildcard-any-principal
      :service :service
      :federated :federated
      :canonical-user :canonical-user
      :aws (cond
             (= "*" value) :wildcard-authenticated-aws
             (re-matches #"^arn:[^:]+:iam::\d{12}:root$" value) :account-root
             (re-matches #"^arn:[^:]+:iam::\d{12}:user/.+$" value) :iam-user
             (re-matches #"^arn:[^:]+:iam::\d{12}:role/.+$" value) :iam-role
             (re-matches #"^arn:[^:]+:iam::\d{12}:group/.+$" value) :iam-group
             (re-matches #"^arn:[^:]+:sts::\d{12}:assumed-role/.+/.+$" value) :assumed-role-session
             (re-matches #"^arn:[^:]+:sts::\d{12}:federated-user/.+$" value) :federated-user-session
             :else :unknown-aws)
      :unknown)))

(defn action-entity
  [action]
  (let [[svc name] (if (= "*" (str action))
                     ["*" "*"]
                     (str/split (str action) #":" 2))]
    (clean-entity
     {:action/key (action-key action)
      :action/service (some-> svc str/lower-case)
      :action/name name
      :action/pattern? (str/includes? (str action) "*")
      :action/source [:policy]})))

(defn resource-entity
  [resource]
  (clean-entity
   (merge (arn-facets resource)
          {:resource/key (resource-key resource)
           :resource/arn (str resource)
           :resource/pattern? (or (str/includes? (str resource) "*")
                                  (str/includes? (str resource) "?"))
           :resource/source :policy})))

(defn principal-entity
  [[principal-source value]]
  (let [ptype (principal-type principal-source value)]
    (clean-entity
     (merge (arn-facets value)
            {:principal/key (principal-key ptype value)
             :principal/type ptype
             :principal/value value}))))

(defn condition-entity
  [statement-key operator field value]
  (let [field-name (name field)
        normalized (condition-key-name field-name)]
    (clean-entity
     (merge (when (string? value)
              (arn-facets value))
            {:condition/key (str statement-key "/condition/" (name operator) "/" normalized)
             :condition/catalog-key [:condition-key/name normalized]
             :condition/operator (name operator)
             :condition/field field-name
             :condition/value (json/generate-string value)}))))

(defn condition-key-entity
  [field]
  (clean-entity
   {:condition-key/name (condition-key-name field)
    :condition-key/source [:policy-document]
    :condition-key/pattern? (str/includes? (name field) "$")}))

(defn statement-conditions
  [statement-key condition-map]
  (vec
   (mapcat (fn [[operator fields]]
             (map (fn [[field value]]
                    (condition-entity statement-key operator field value))
                  fields))
           condition-map)))

(defn statement-tx
  [document-key idx statement]
  (let [statement-key (str document-key "/statement/" (statement-content-hash statement))
        actions (map str (ensure-vector (first-present statement [:Action])))
        not-actions (map str (ensure-vector (first-present statement [:NotAction])))
        resources (map str (ensure-vector
                            (cond
                              (contains? statement :Resource) (:Resource statement)
                              (contains? statement :NotResource) nil
                              :else "*")))
        not-resources (map str (ensure-vector (first-present statement [:NotResource])))
        principals (principal-values (:Principal statement))
        not-principals (principal-values (:NotPrincipal statement))
        conditions (statement-conditions statement-key (:Condition statement))]
    [(vec (concat
           (map action-entity (concat actions not-actions))
           (map resource-entity (concat resources not-resources))
           (map principal-entity (concat principals not-principals))
           (map condition-key-entity (map :condition/field conditions))))
     conditions
     [(clean-entity
       {:statement/key statement-key
        :statement/sid (or (:Sid statement) (str "Statement" idx))
        :statement/effect (some-> (:Effect statement) str/lower-case keyword)
        :statement/action (mapv #(vector :action/key (action-key %)) actions)
        :statement/not-action (mapv #(vector :action/key (action-key %)) not-actions)
        :statement/resource (mapv #(vector :resource/key (resource-key %)) resources)
        :statement/not-resource (mapv #(vector :resource/key (resource-key %)) not-resources)
        :statement/principal (mapv (fn [[principal-source value]]
                                     [:principal/key (principal-key (principal-type principal-source value) value)])
                                   principals)
        :statement/not-principal (mapv (fn [[principal-source value]]
                                         [:principal/key (principal-key (principal-type principal-source value) value)])
                                       not-principals)
        :statement/condition (mapv #(vector :condition/key (:condition/key %)) conditions)})]]))

(defn merge-phases
  [& phases-colls]
  (let [n (apply max 0 (map count phases-colls))]
    (mapv (fn [idx] (vec (mapcat #(nth % idx []) phases-colls)))
          (range n))))

(defn policy-document-tx
  [doc-key kind raw-document]
  (let [doc (parse-jsonish raw-document)
        doc (if (map? doc) doc {})
        statements (mapv #(statement-tx doc-key %1 %2)
                         (range)
                         (ensure-vector (:Statement doc)))]
    (apply merge-phases
           [[] [] []
            [(clean-entity
              {:document/key doc-key
               :document/kind kind
               :document/version (:Version doc)
               :document/json (json/generate-string doc)
               :document/statement
               (mapv #(vector :statement/key (:statement/key %))
                     (mapcat #(nth % 2) statements))})]]
           statements)))

(defn aws-resource-type
  [resource-type]
  (case resource-type
    "AWS::IAM::Role" :aws.config/iam-role
    "AWS::IAM::Policy" :aws.config/iam-policy
    (keyword "aws.config" (-> resource-type
                              (str/replace #"^AWS::" "")
                              (str/replace #"::" "-")
                              str/lower-case))))

(defn config-key
  [{:keys [accountId awsRegion resourceType resourceId configurationStateId]}]
  (str accountId "/" awsRegion "/" resourceType "/" resourceId "/"
       configurationStateId))

(defn normalize-config-item
  [ci]
  (let [configuration (parse-jsonish (:configuration ci))]
    (assoc ci
           :configuration configuration
           :resourceType (or (:resourceType ci)
                             (:resourceType configuration)))))

(defn aws-config-items
  [json-value]
  (let [v (parse-jsonish json-value)]
    (cond
      (vector? v) (mapcat aws-config-items v)
      (:configurationItems v) (map normalize-config-item (:configurationItems v))
      (:baseConfigurationItems v) (map normalize-config-item (:baseConfigurationItems v))
      (:configurationItem v) [(normalize-config-item (:configurationItem v))]
      (:invokingEvent v) (aws-config-items (parse-jsonish (:invokingEvent v)))
      (:Results v) (mapcat #(aws-config-items (parse-jsonish %)) (:Results v))
      (and (:resourceType v) (:configuration v)) [(normalize-config-item v)]
      :else [])))

(defn role-entity-from-config
  [ci]
  (let [c (:configuration ci)
        arn (or (:arn c) (:arn ci))
        role-id (or (:roleId c) (:resourceId ci))
        role-name (or (:roleName c) (:resourceName ci))]
    (clean-entity
     (merge (arn-facets arn {:include-arn? true})
            {:role/id role-id
             :role/name role-name
             :role/account-id (:accountId ci)
             :role/path (:path c)
             :role/tags (some-> (:tags c) json/generate-string)
             :role/create-date (parse-aws-instant (:createDate c))}))))

(defn policy-key-from-config-policy
  [policy]
  (or (:policyArn policy) (:arn policy) (:policyName policy)))

(defn policy-shell
  [policy-key policy-name policy-type]
  (clean-entity
   {:policy/key policy-key
    :policy/name policy-name
    :policy/type policy-type}))

(defn config-item-entity
  [ci target-ref opts]
  (clean-entity
   {:config/key (config-key ci)
    :config/resource-id (:resourceId ci)
    :config/resource-name (:resourceName ci)
    :config/resource-type (aws-resource-type (:resourceType ci))
    :config/capture-time (parse-aws-instant (:configurationItemCaptureTime ci))
    :config/imported-at (or (parse-aws-instant (:imported-at opts))
                            (java.util.Date.))
    :config/status (:configurationItemStatus ci)
    :config/source-path (or (:source-path opts) (:source-file opts))
    :config/describes target-ref}))

(defn role-config-tx-phases
  [ci opts]
  (let [c (:configuration ci)
        role (role-entity-from-config ci)
        role-id (:role/id role)
        role-arn (:role/arn role)
        trust-doc (:assumeRolePolicyDocument c)
        trust-key (trust-policy-key role-arn)
        attached (ensure-vector (:attachedManagedPolicies c))
        inline (ensure-vector (:rolePolicyList c))
        attached-policy-refs (mapv #(vector :policy/key (policy-key-from-config-policy %)) attached)
        inline-policy-refs (mapv #(vector :policy/key (inline-policy-key role-arn (:policyName %))) inline)
        trust-phases (when trust-doc (policy-document-tx trust-key :trust-policy trust-doc))
        inline-phases (mapv (fn [p]
                              (policy-document-tx
                               (document-key (inline-policy-key role-arn (:policyName p)))
                               :inline-policy
                               (:policyDocument p)))
                            inline)
        inline-policy-entities
        (mapv (fn [p]
                (let [pkey (inline-policy-key role-arn (:policyName p))]
                  (clean-entity
                   {:policy/key pkey
                    :policy/name (:policyName p)
                    :policy/type :inline
                    :policy/document [:document/key (document-key pkey)]})))
              inline)]
    (apply merge-phases
           [[(principal-entity [:aws role-arn])
             role]
            []
            []
            []
            (vec (concat
                  (map #(policy-shell (policy-key-from-config-policy %)
                                      (:policyName %)
                                      :managed)
                       attached)
                  inline-policy-entities))
            [(clean-entity
              {:role/arn role-arn
               :role/id role-id
               :role/attached-policy attached-policy-refs
               :role/inline-policy inline-policy-refs
               :role/trust-policy (when trust-doc [:document/key trust-key])})
             (config-item-entity ci [:role/arn role-arn] opts)]]
           (concat (when trust-phases [trust-phases])
                   inline-phases))))

(defn managed-policy-config-tx-phases
  [ci opts]
  (let [c (:configuration ci)
        pkey (or (:arn c) (:arn ci))
        versions (ensure-vector (:policyVersionList c))
        default-version (or (some #(when (:isDefaultVersion %) %) versions)
                            (first versions))
        version-phases
        (mapv (fn [version]
                (let [vkey (policy-version-key pkey (:versionId version))
                      doc-key (document-key vkey)
                      doc (or (first (:document version)) (:document version))]
                  (merge-phases
                   (policy-document-tx doc-key :managed-policy doc)
                   [[] [] [] []
                    [(clean-entity
                      {:policy-version/key vkey
                       :policy-version/id (:versionId version)
                       :policy-version/default? (boolean (:isDefaultVersion version))
                       :policy-version/create-date (parse-aws-instant (:createDate version))
                       :policy-version/document [:document/key doc-key]})]])))
              versions)
        version-refs (mapv #(vector :policy-version/key (policy-version-key pkey (:versionId %))) versions)]
    (apply merge-phases
           [[(policy-shell pkey (:policyName c) :managed)]
            []
            []
            []
            []
            [(clean-entity
              {:policy/key pkey
               :policy/id (:policyId c)
               :policy/name (:policyName c)
               :policy/type :managed
               :policy/version version-refs
               :policy/default-version (when default-version
                                         [:policy-version/key
                                          (policy-version-key pkey (:versionId default-version))])
               :policy/document (when default-version
                                  [:document/key
                                   (document-key (policy-version-key pkey (:versionId default-version)))])})
             (config-item-entity ci [:policy/key pkey] opts)]]
           version-phases)))

(defn config-item-tx-phases
  [ci opts]
  (case (:resourceType ci)
    "AWS::IAM::Role" (role-config-tx-phases ci opts)
    "AWS::IAM::Policy" (managed-policy-config-tx-phases ci opts)
    [[(config-item-entity ci nil opts)]]))

(defn config-json-tx-phases
  [json-value opts]
  (apply merge-phases
         (mapv #(config-item-tx-phases % opts)
               (aws-config-items json-value))))

(defn config-property-value-type
  [type-name]
  (case type-name
    "boolean" :boolean
    "cidr_block" :cidr-block
    "date" :date
    "float" :float
    "integer" :integer
    "ip" :ip
    "string" :string
    (some-> type-name str/lower-case keyword)))

(defn config-resource-schema-phases
  [resource-type json-value opts]
  (let [properties (parse-jsonish json-value)
        resource-type-key resource-type
        resource-type-ref [:config-resource-type/key resource-type-key]]
    [[(clean-entity
       {:config-resource-type/key resource-type-key
        :config-resource-type/name (aws-resource-type resource-type)
        :config-resource-type/source-url (:source-url opts)
        :config-resource-type/imported-at (or (parse-aws-instant (:imported-at opts))
                                              (java.util.Date.))})]
     (->> properties
          (map (fn [[path type-name]]
                 (clean-entity
                  {:config-property/key (str resource-type-key "/" (name path))
                   :config-property/path (name path)
                   :config-property/type (config-property-value-type type-name)
                   :config-property/resource-type resource-type-ref})))
          vec)]))

(defn transact-phases!
  [conn phases]
  (let [reports (mapv #(when (seq %) (d/transact conn %)) phases)]
    {:phase-count (count phases)
     :entities (reduce + 0 (map count phases))
     :datoms (reduce + 0 (map #(count (:tx-data %)) (remove nil? reports)))
     :tx-instant (some #(get-in % [:tx-meta :db/txInstant]) (reverse reports))}))

(defn decorate-source-path
  [phases source-path]
  (if-not source-path
    phases
    (mapv (fn [phase]
            (mapv (fn [entity]
                    (if (and (map? entity) (:document/key entity))
                      (assoc entity :document/source-path source-path)
                      entity))
                  phase))
          phases)))

(defn existing-config-imported-at
  [db config-key]
  (d/q '[:find ?imported-at .
         :in $ ?config-key
         :where
         [?config :config/key ?config-key]
         [?config :config/imported-at ?imported-at]]
       db config-key))

(defn preserve-existing-config-imported-at
  [db phases]
  (mapv (fn [phase]
          (mapv (fn [entity]
                  (if-let [config-key (:config/key entity)]
                    (if-let [imported-at (existing-config-imported-at db config-key)]
                      (assoc entity :config/imported-at imported-at)
                      entity)
                    entity))
                phase))
        phases))

(defn prepare-phases
  [conn phases opts]
  (->> (decorate-source-path phases (:source-path opts))
       (preserve-existing-config-imported-at (d/db conn))))

(defn service-key
  [service-reference]
  (str/lower-case (:Name service-reference)))

(defn service-resource-key
  [service-prefix resource-name]
  (str (str/lower-case service-prefix) ":" (str/lower-case resource-name)))

(defn service-action-key
  [service-prefix action-name]
  (str/lower-case (str service-prefix ":" action-name)))

(defn service-condition-key
  [condition-name]
  (str/lower-case condition-name))

(defn service-reference-value-type
  [type-name]
  (case type-name
    "ARN" :arn
    "ArrayOfARN" :array-of-arn
    "ArrayOfString" :array-of-string
    "Bool" :boolean
    "Boolean" :boolean
    "String" :string
    (some-> type-name str/lower-case keyword)))

(defn service-reference-access-level
  [action]
  (let [props (get-in action [:Annotations :Properties])]
    (cond
      (:IsPermissionManagement props) :permissions-management
      (:IsTaggingOnly props) :tagging
      (:IsWrite props) :write
      (:IsRead props) :read
      (:IsList props) :list
      :else nil)))

(defn service-condition-entity
  [service-prefix condition]
  (let [condition-name (:Name condition)]
    (clean-entity
     {:condition-key/name (service-condition-key condition-name)
      :condition-key/value-type (some-> (first (:Types condition)) service-reference-value-type)
      :condition-key/source [:service-reference]
      :condition-key/pattern? (str/includes? condition-name "$")})))

(defn service-resource-entity
  [service-prefix resource]
  (let [resource-name (:Name resource)]
    (clean-entity
     {:service-resource/key (service-resource-key service-prefix resource-name)
      :service-resource/name resource-name
      :service-resource/service [:service/key service-prefix]
      :service-resource/arn-format (vec (ensure-vector (:ARNFormats resource)))})))

(defn service-action-entity
  [service-prefix action]
  (let [action-name (:Name action)]
    (clean-entity
     {:action/key (service-action-key service-prefix action-name)
      :action/service service-prefix
      :action/name action-name
      :action/access-level (service-reference-access-level action)
      :action/source [:service-reference]
      :action/resource-type (mapv #(vector :service-resource/key
                                           (service-resource-key service-prefix (:Name %)))
                                  (ensure-vector (:Resources action)))
      :action/condition-key (mapv #(vector :condition-key/name (service-condition-key %))
                                  (ensure-vector (:ActionConditionKeys action)))})))

(defn service-reference-json->phases
  [json-value opts]
  (let [v (parse-jsonish json-value)
        service-prefix (service-key v)
        actions (ensure-vector (:Actions v))
        resources (ensure-vector (or (:Resources v) (:ResourceTypes v)))
        conditions (ensure-vector (:ConditionKeys v))]
    [[(clean-entity
       {:service/key service-prefix
        :service/name (:Name v)
        :service/version (:Version v)
        :service/source-url (:source-url opts)
        :service/imported-at (or (parse-aws-instant (:imported-at opts))
                                 (java.util.Date.))})]
     (vec (concat
           (map #(service-condition-entity service-prefix %) conditions)
           (map #(service-resource-entity service-prefix %) resources)))
     (vec (map #(service-action-entity service-prefix %) actions))]))

(defn iam-policy-json->phases
  [json-value opts]
  (let [v (parse-jsonish json-value)
        policy-version (or (:PolicyVersion v) (:policyVersion v))
        policy (or (:Policy v) (:policy v))
        document (or (:Document policy-version)
                     (:document policy-version)
                     (:PolicyDocument v)
                     (:policyDocument v)
                     (:Document v)
                     (:document v)
                     (when (:Statement v) v))
        pkey (or (:policy-arn opts) (:policyArn opts) (:PolicyArn opts)
                 (:PolicyArn v) (:policyArn v) (:Arn policy) (:arn policy))
        policy-name (or (:policy-name opts) (:policyName opts) (:PolicyName opts)
                        (:PolicyName policy) (:policyName policy) pkey)
        version-id (or (:version-id opts) (:VersionId opts) (:versionId opts)
                       (:VersionId policy-version) (:versionId policy-version) "v1")
        default? (if (contains? opts :default)
                   (:default opts)
                   (boolean (or (:IsDefaultVersion policy-version)
                                (:isDefaultVersion policy-version)
                                (:default? opts))))
        vkey (policy-version-key pkey version-id)
        doc-key (document-key vkey)]
    (when-not pkey
      (throw (ex-info "IAM policy import requires --policy-arn or Policy.Arn" {:opts opts})))
    (merge-phases
     [[(policy-shell pkey policy-name :managed)]]
     (policy-document-tx doc-key :managed-policy document)
     [[] [] [] []
      [(clean-entity
        {:policy-version/key vkey
         :policy-version/id version-id
         :policy-version/default? default?
         :policy-version/create-date (parse-aws-instant
                                      (or (:CreateDate policy-version)
                                          (:createDate policy-version)
                                          (:create-date opts)))
         :policy-version/document [:document/key doc-key]})]
      [(clean-entity
        {:policy/key pkey
         :policy/name policy-name
         :policy/type :managed
         :policy/version [[:policy-version/key vkey]]
         :policy/default-version (when default? [:policy-version/key vkey])
         :policy/document (when default? [:document/key doc-key])})]])))

(defn load-config-json!
  ([conn json-value] (load-config-json! conn json-value nil))
  ([conn json-value opts]
   (transact-phases! conn (prepare-phases conn (config-json-tx-phases json-value opts) opts))))

(defn load-iam-policy-json!
  ([conn json-value] (load-iam-policy-json! conn json-value nil))
  ([conn json-value opts]
   (transact-phases! conn (prepare-phases conn (iam-policy-json->phases json-value opts) opts))))

(defn load-config-resource-schema-json!
  ([conn resource-type json-value]
   (load-config-resource-schema-json! conn resource-type json-value nil))
  ([conn resource-type json-value opts]
   (let [phases (config-resource-schema-phases resource-type json-value opts)
         reports (mapv #(when (seq %) (d/transact conn %)) phases)]
     {:phase-count (count phases)
      :entities (reduce + 0 (map count phases))
      :datoms (reduce + 0 (map #(count (:tx-data %)) (remove nil? reports)))
      :tx-instant (some #(get-in % [:tx-meta :db/txInstant]) (reverse reports))})))

(defn load-config-resource-schema-file!
  [conn resource-type path]
  (load-config-resource-schema-json!
   conn resource-type (read-json-file path) {:source-url path}))

(defn load-service-reference-json!
  [conn json-value opts]
  (let [phases (service-reference-json->phases json-value opts)
        reports (mapv #(when (seq %) (d/transact conn %)) phases)]
    {:phase-count (count phases)
     :entities (reduce + 0 (map count phases))
     :datoms (reduce + 0 (map #(count (:tx-data %)) (remove nil? reports)))
     :tx-instant (some #(get-in % [:tx-meta :db/txInstant]) (reverse reports))}))

(defn fetch-json
  [url]
  (parse-json (slurp url)))

(defn load-service-reference-url!
  [conn url]
  (load-service-reference-json! conn (fetch-json url) {:source-url url}))

(def service-reference-base-url
  "https://servicereference.us-east-1.amazonaws.com/v1/")

(defn service-reference-dir
  [dir]
  (io/file (or dir "samples/iam-policy/service-reference")))

(defn service-reference-list-url
  []
  (str service-reference-base-url "service-list.json"))

(defn service-reference-all-dir
  [dir]
  (io/file (service-reference-dir dir) "all"))

(defn prefetch-service-reference!
  [{:keys [dir]}]
  (let [root (service-reference-dir dir)
        all-dir (service-reference-all-dir dir)
        service-list-file (io/file root "service-list.json")]
    (.mkdirs root)
    (.mkdirs all-dir)
    (spit service-list-file (slurp (service-reference-list-url)))
    (let [service-list (read-json-file service-list-file)
          services (ensure-vector (:services service-list))]
      (doseq [{:keys [service url]} services]
        (let [target (io/file all-dir (str service ".json"))]
          (spit target (slurp url))))
      {:services (count services)
       :dir (.getPath root)
       :all-dir (.getPath all-dir)
       :service-list (.getPath service-list-file)})))

(defn service-reference-files
  [dir]
  (let [root (service-reference-dir dir)
        all-dir (service-reference-all-dir dir)
        candidate-dir (if (.exists all-dir) all-dir root)]
    (->> (file-seq candidate-dir)
         (filter #(.isFile %))
         (filter #(str/ends-with? (.getName %) ".json"))
         (remove #(= "service-list.json" (.getName %)))
         (remove #(= "manifest.json" (.getName %)))
         (sort-by #(.getName %))
         vec)))

(defn preload-service-reference!
  [conn {:keys [dir]}]
  (let [files (service-reference-files dir)
        reports (mapv (fn [file]
                        (load-service-reference-json!
                         conn
                         (read-json-file file)
                         {:source-url (.getPath file)
                          :source-path (.getPath file)}))
                      files)]
    {:services (count files)
     :entities (reduce + 0 (map :entities reports))
     :datoms (reduce + 0 (map :datoms reports))}))

(defn sync-service-reference!
  [{:keys [db dir]}]
  (let [prefetch (prefetch-service-reference! {:dir dir})
        conn (get-conn (db-config db))]
    (try
      (merge prefetch (preload-service-reference! conn {:dir dir}))
      (finally
        (close-conn! conn)))))

(defn- decode-json-field
  [x]
  (cond
    (nil? x) nil
    (string? x) (parse-json x)
    :else x))

(defn- present-role
  [role]
  (when role
    (cond-> role
      (:role/tags role) (assoc :tags (decode-json-field (:role/tags role))))))

(defn role-by-arn
  [db role-arn]
  (some->> (d/q '[:find ?role .
                  :in $ ?role-arn
                  :where [?role :role/arn ?role-arn]]
                db role-arn)
           (d/pull db '[*])
           present-role))

(defn resource-state-at
  [conn resource-arn tx]
  (role-by-arn (d/as-of (d/db conn) tx) resource-arn))

(defn db-as-of
  [conn tx]
  (d/as-of (d/db conn) tx))

(defn resource-changes-since
  [conn resource-arn tx]
  (let [before (resource-state-at conn resource-arn tx)
        after (role-by-arn (d/db conn) resource-arn)
        ks (sort (set (concat (keys before) (keys after))))]
    (->> ks
         (keep (fn [k]
                 (when (not= (get before k) (get after k))
                   {:attribute k
                    :before (get before k)
                    :after (get after k)})))
         vec)))

(defn resource-observations
  [db resource-arn]
  (->> (d/q '[:find ?config
              :in $ ?resource-arn
              :where
              [?resource :role/arn ?resource-arn]
              [?config :config/describes ?resource]]
            db resource-arn)
       (map first)
       (map #(d/pull db '[*] %))
       (sort-by :config/capture-time)
       vec))

(defn config-resource-properties
  [db resource-type]
  (->> (d/q '[:find ?path ?type
              :keys config-property/path config-property/type
              :in $ ?resource-type
              :where
              [?rt :config-resource-type/key ?resource-type]
              [?property :config-property/resource-type ?rt]
              [?property :config-property/path ?path]
              [?property :config-property/type ?type]]
            db resource-type)
       (sort-by :config-property/path)
       vec))

(defn policy-default-version
  [db policy-key]
  (some->> (d/q '[:find ?version .
                  :in $ ?policy-key
                  :where
                  [?policy :policy/key ?policy-key]
                  [?policy :policy/default-version ?version]]
                db policy-key)
           (d/pull db '[*])))

(defn policy-default-version-at
  [conn policy-key tx]
  (policy-default-version (db-as-of conn tx) policy-key))

(defn policy-version-changes-since
  [conn policy-key tx]
  (let [current (policy-default-version (d/db conn) policy-key)
        prior (policy-default-version-at conn policy-key tx)]
    (cond-> []
      (not= (:policy-version/key current) (:policy-version/key prior))
      (conj current))))

(defn policy-document-history
  [conn policy-key]
  (->> (d/q '[:find ?version-id ?json
              :keys policy-version/id document/json
              :in $ ?policy-key
              :where
              [?policy :policy/key ?policy-key]
              [?policy :policy/version ?version]
              [?version :policy-version/id ?version-id]
              [?version :policy-version/document ?doc]
              [?doc :document/json ?json]]
            (d/history (d/db conn)) policy-key)
       (sort-by :policy-version/id)
       vec))

(defn history-datoms-since
  [conn tx]
  (->> (d/q '[:find ?e ?a ?v ?instant ?added
              :keys e a v tx-instant added?
              :in $ ?since
              :where
              [?e ?a ?v ?tx ?added]
              [?tx :db/txInstant ?instant]
              [(compare ?instant ?since) ?cmp]
              [(pos? ?cmp)]]
            (d/history (d/db conn)) tx)
       (sort-by (juxt :tx-instant :e :a))
       vec))

(defn role-effective-allow
  [db role-arn]
  (let [rows-for (fn [policy-attr]
                   (d/q '[:find ?policy-key ?action-key ?resource-arn
                          :keys policy/key action/key resource/arn
                          :in $ ?role-arn ?policy-attr
                          :where
                          [?role :role/arn ?role-arn]
                          [?role ?policy-attr ?policy]
                          [?policy :policy/key ?policy-key]
                          [?policy :policy/document ?doc]
                          [?doc :document/statement ?statement]
                          [?statement :statement/effect :allow]
                          [?statement :statement/action ?action]
                          [?action :action/key ?action-key]
                          [?statement :statement/resource ?resource]
                          [?resource :resource/arn ?resource-arn]]
                        db role-arn policy-attr))]
    (->> (concat (rows-for :role/inline-policy)
                 (rows-for :role/attached-policy))
         (sort-by (juxt :policy/key :action/key :resource/arn))
         vec)))

(defn role-effective-allow-at
  [conn role-arn tx]
  (role-effective-allow (db-as-of conn tx) role-arn))

(defn wildcard-matches?
  [pattern value]
  (let [regex (->> (str pattern)
                   (map #(if (= \* %)
                           ".*"
                           (if (= \? %)
                             "."
                             (java.util.regex.Pattern/quote (str %)))))
                   (apply str)
                   re-pattern)]
    (boolean (re-matches regex (str value)))))

(defn action-pattern-parts
  [pattern]
  (let [[service action-name] (str/split (str pattern) #":" 2)]
    [(some-> service str/lower-case) (some-> action-name str/lower-case)]))

(def read-only-action-prefixes #{"get*" "list*" "describe*"})

(defn read-only-action-wildcard?
  [pattern]
  (let [[_ action-name] (action-pattern-parts pattern)]
    (contains? read-only-action-prefixes action-name)))

(defn service-wildcard?
  [pattern]
  (let [[_ action-name] (action-pattern-parts pattern)]
    (= "*" action-name)))

(defn service-action-keys
  [db service-prefix]
  (vec (sort (d/q '[:find [?action-key ...]
                    :in $ ?service
                    :where
                    [?action :action/service ?service]
                    [?action :action/key ?action-key]
                    [?action :action/source :service-reference]]
                  db service-prefix))))

(defn service-catalog-loaded?
  [db service-prefix]
  (boolean
   (d/q '[:find ?service-entity .
          :in $ ?service
          :where [?service-entity :service/key ?service]]
        db service-prefix)))

(defn expand-action-pattern
  [db pattern]
  (let [pattern-str (str pattern)
        normalized (action-key pattern-str)
        [service action-name] (action-pattern-parts pattern-str)]
    (cond
      (= "*" pattern-str)
      {:pattern pattern-str :expanded? false :actions ["*"]}

      (not (str/includes? pattern-str "*"))
      {:pattern pattern-str :expanded? false :actions [normalized]}

      (service-wildcard? pattern-str)
      {:pattern pattern-str :expanded? false :actions [normalized]}

      (read-only-action-wildcard? pattern-str)
      {:pattern pattern-str :expanded? false :actions [normalized]}

      (not (service-catalog-loaded? db service))
      (throw (ex-info "Service catalog missing"
                      {:error :service-catalog/missing
                       :service service
                       :pattern pattern-str}))

      :else
      {:pattern pattern-str
       :expanded? true
       :actions (->> (service-action-keys db service)
                     (filter #(wildcard-matches? normalized %))
                     sort
                     vec)})))

(defn statement-action-patterns
  [db statement-id]
  {:action (vec (sort (d/q '[:find [?action-key ...]
                             :in $ ?statement
                             :where
                             [?statement :statement/action ?action]
                             [?action :action/key ?action-key]]
                           db statement-id)))
   :not-action (vec (sort (d/q '[:find [?action-key ...]
                                 :in $ ?statement
                                 :where
                                 [?statement :statement/not-action ?action]
                                 [?action :action/key ?action-key]]
                               db statement-id)))})

(defn action-pattern-covers?
  [db pattern action]
  (let [target (action-key action)
        expanded (expand-action-pattern db pattern)]
    (or (contains? #{"*" (str (first (action-pattern-parts action)) ":*")} (action-key pattern))
        (contains? (set (:actions expanded)) target)
        (and (not (:expanded? expanded))
             (str/includes? (action-key pattern) "*")
             (wildcard-matches? (action-key pattern) target)))))

(defn statement-covers-action?
  [db statement-id target-action]
  (let [{action-patterns :action
         not-action-patterns :not-action} (statement-action-patterns db statement-id)]
    (cond
      (seq action-patterns) (boolean (some #(action-pattern-covers? db % target-action) action-patterns))
      (seq not-action-patterns) (not-any? #(action-pattern-covers? db % target-action) not-action-patterns)
      :else false)))

(defn statement-allows-action?
  [db statement-id action]
  (and (= :allow (d/q '[:find ?effect .
                        :in $ ?statement
                        :where [?statement :statement/effect ?effect]]
                      db statement-id))
       (statement-covers-action? db statement-id action)))

(defn policy-statements
  [db policy-key]
  (letfn [(refs [attr statement]
            (vec (sort (d/q '[:find [?value ...]
                              :in $ ?statement ?attr ?value-attr
                              :where
                              [?statement ?attr ?entity]
                              [?entity ?value-attr ?value]]
                            db statement attr
                            (case attr
                              :statement/action :action/key
                              :statement/not-action :action/key
                              :statement/resource :resource/arn
                              :statement/not-resource :resource/arn
                              :statement/principal :principal/value
                              :statement/not-principal :principal/value)))))
          (principal-refs [attr statement]
            (->> (d/q '[:find ?principal ?type ?value
                        :keys db/id principal/type principal/value
                        :in $ ?statement ?attr
                        :where
                        [?statement ?attr ?principal]
                        [?principal :principal/type ?type]
                        [?principal :principal/value ?value]]
                      db statement attr)
                 (sort-by (juxt :principal/type :principal/value :db/id))
                 vec))]
    (->> (d/q '[:find ?statement ?sid ?effect
                :keys statement statement/sid statement/effect
                :in $ ?policy-key
                :where
                [?policy :policy/key ?policy-key]
                [?policy :policy/document ?doc]
                [?doc :document/statement ?statement]
                [?statement :statement/effect ?effect]
                [?statement :statement/sid ?sid]]
              db policy-key)
         (map (fn [{:keys [statement] :as row}]
                (-> row
                    (dissoc :statement)
                    (assoc :statement/action (refs :statement/action statement)
                           :statement/not-action (refs :statement/not-action statement)
                           :statement/resource (refs :statement/resource statement)
                           :statement/not-resource (refs :statement/not-resource statement)
                           :statement/principal (principal-refs :statement/principal statement)
                           :statement/not-principal (principal-refs :statement/not-principal statement)))))
         (sort-by :statement/sid)
         vec)))

(defn resource-pattern-matches?
  [pattern resource-arn]
  (let [pattern-arn (parse-arn pattern)
        resource (parse-arn resource-arn)
        compatible? (or (nil? pattern-arn)
                        (nil? resource)
                        (every? (fn [k]
                                  (let [pattern-value (get pattern-arn k)
                                        resource-value (get resource k)]
                                    (or (nil? pattern-value)
                                        (str/includes? pattern-value "*")
                                        (str/includes? pattern-value "?")
                                        (= pattern-value resource-value))))
                                [:arn/partition :arn/service :arn/region :arn/account-id]))]
    (and compatible?
         (or (= pattern resource-arn)
             (and (or (str/includes? (str pattern) "*")
                      (str/includes? (str pattern) "?"))
                  (wildcard-matches? pattern resource-arn))))))

(defn role-arns
  [db]
  (d/q '[:find ?arn
         :keys role/arn
         :where
         [?role :role/id _]
         [?role :role/arn ?arn]]
       db))

(defn- condition-values
  [db statement-id]
  (->> (d/q '[:find ?field ?value
              :in $ ?statement
              :where
              [?statement :statement/condition ?condition]
              [?condition :condition/field ?field]
              [?condition :condition/value ?value]]
            db statement-id)
       (map (fn [[field value]]
              [field (parse-json value)]))
       (into {})))

(defn- condition-values-for-field
  [db statement-id field-name]
  (let [target (str/lower-case field-name)]
    (->> (condition-values db statement-id)
         (filter (fn [[field _]] (= target (str/lower-case field))))
         (mapcat (fn [[_ value]] (ensure-vector value)))
         (map str)
         distinct
         sort
         vec)))

(def trust-service-action-keys
  #{"sts:assumerole"
    "sts:assumerolewithsaml"
    "sts:assumerolewithwebidentity"
    "sts:*"
    "*"})

(defn target-trust-service-principals
  [db target-role-arn]
  (->> (d/q '[:find ?service-principal
              ?action-key
              :in $ ?target-role-arn
              :where
              [?target :role/arn ?target-role-arn]
              [?target :role/trust-policy ?doc]
              [?doc :document/statement ?statement]
              [?statement :statement/effect :allow]
              [?statement :statement/action ?action]
              [?action :action/key ?action-key]
              [?statement :statement/principal ?principal]
              [?principal :principal/type :service]
              [?principal :principal/value ?service-principal]]
            db target-role-arn)
       (filter (fn [[_ action-key]]
                 (contains? trust-service-action-keys action-key)))
       (map first)
       sort
       vec))

(defn pass-role-passable-service-principals
  [delegated-services trust-services]
  (let [trust-set (set trust-services)
        delegated (vec delegated-services)]
    (if (seq delegated)
      (vec (sort (filter trust-set delegated)))
      (vec trust-services))))

(defn- pass-role-transition-rows
  [db role-policy-attr]
  (let [target-arns (mapv :role/arn (role-arns db))
        rows (d/q '[:find ?source-arn ?resource-arn ?action-key ?statement
                    :keys source-role resource-pattern action statement
                    :in $ ?role-policy-attr
                    :where
                    [?source :role/arn ?source-arn]
                    [?source ?role-policy-attr ?policy]
                    [?policy :policy/document ?doc]
                    [?doc :document/statement ?statement]
                    [?statement :statement/effect :allow]
                    [?statement :statement/action ?action]
                    [?action :action/key ?action-key]
                    [?statement :statement/resource ?resource]
                    [?resource :resource/arn ?resource-arn]]
                  db role-policy-attr)]
    (vec
     (for [row rows
           target-arn target-arns
           :when (resource-pattern-matches? (:resource-pattern row) target-arn)]
       (assoc row :target-role target-arn)))))

(defn- assume-role-identity-rows
  [db role-policy-attr]
  (let [target-arns (mapv :role/arn (role-arns db))
        rows (d/q '[:find ?source-arn ?resource-arn ?action-key ?statement
                    :keys source-role resource-pattern action statement
                    :in $ ?role-policy-attr
                    :where
                    [?source :role/arn ?source-arn]
                    [?source ?role-policy-attr ?policy]
                    [?policy :policy/document ?doc]
                    [?doc :document/statement ?statement]
                    [?statement :statement/effect :allow]
                    [?statement :statement/action ?action]
                    [?action :action/key ?action-key]
                    [?statement :statement/resource ?resource]
                    [?resource :resource/arn ?resource-arn]]
                  db role-policy-attr)]
    (vec
     (for [row rows
           target-arn target-arns
           :when (resource-pattern-matches? (:resource-pattern row) target-arn)]
       (assoc row :target-role target-arn)))))

(defn- trust-role-rows
  [db]
  (d/q '[:find ?source-arn ?target-arn ?statement
         :keys source-role target-role statement
         :where
         [?target :role/arn ?target-arn]
         [?target :role/trust-policy ?doc]
         [?doc :document/statement ?statement]
         [?statement :statement/effect :allow]
         [?statement :statement/principal ?principal]
         [?principal :principal/value ?source-arn]]
       db))

(defn role-transitions
  [db]
  (let [trusted? (set (map #(select-keys % [:source-role :target-role])
                           (filter #(statement-allows-action? db (:statement %) "sts:AssumeRole")
                                   (trust-role-rows db))))]
    (->> (concat
          (map (fn [row]
                 (-> row
                     (dissoc :statement :resource-pattern)
                     (assoc :transition/type :assume-role)))
               (filter #(and (statement-allows-action? db (:statement %) "sts:AssumeRole")
                             (trusted? (select-keys % [:source-role :target-role])))
                       (concat (assume-role-identity-rows db :role/inline-policy)
                               (assume-role-identity-rows db :role/attached-policy))))
          (mapcat (fn [{:keys [statement target-role] :as row}]
                    (let [delegated-services (condition-values-for-field db statement "iam:PassedToService")
                          trust-services (target-trust-service-principals db target-role)]
                      (for [service (pass-role-passable-service-principals delegated-services trust-services)]
                        (-> row
                            (dissoc :statement :resource-pattern)
                            (assoc :transition/type :pass-role)
                            (assoc :delegated-service service)
                            (assoc :target-trust-services trust-services)
                            (assoc :passable-service-principals [service])))))
                  (filter #(statement-allows-action? db (:statement %) "iam:PassRole")
                          (concat (pass-role-transition-rows db :role/inline-policy)
                                  (pass-role-transition-rows db :role/attached-policy)))))
         (sort-by (juxt :source-role :target-role :action))
         vec)))

(defn service-actions
  [db service-prefix]
  (let [actions (d/q '[:find ?action ?action-key ?action-name ?access-level
                       :keys action action/key action/name action/access-level
                       :in $ ?service
                       :where
                       [?action :action/service ?service]
                       [?action :action/key ?action-key]
                       [?action :action/name ?action-name]
                       [?action :action/access-level ?access-level]]
                     db service-prefix)]
    (->> actions
         (map (fn [{:keys [action] :as row}]
                (assoc (dissoc row :action)
                       :resource-types
                       (vec (sort (d/q '[:find [?resource-key ...]
                                         :in $ ?action
                                         :where
                                         [?action :action/resource-type ?resource]
                                         [?resource :service-resource/key ?resource-key]]
                                       db action)))
                       :condition-keys
                       (vec (sort (d/q '[:find [?condition-key ...]
                                         :in $ ?action
                                         :where
                                         [?action :action/condition-key ?condition]
                                         [?condition :condition-key/name ?condition-key]]
                                       db action))))))
         (sort-by :action/key)
         vec)))

(def stats-markers
  {:roles :role/id
   :policies :policy/key
   :policy-versions :policy-version/key
   :documents :document/key
   :statements :statement/key
   :actions :action/key
   :resources :resource/key
   :principals :principal/type
   :conditions :condition/key
   :config-items :config/key
   :services :service/key
   :service-resources :service-resource/key
   :config-resource-types :config-resource-type/key
   :config-properties :config-property/key})

(defn entity-count
  [db attr]
  (d/q '[:find (count ?e) .
         :in $ ?attr
         :where [?e ?attr _]]
       db attr))

(defn stats
  [db]
  (into {}
        (map (fn [[k attr]] [k (or (entity-count db attr) 0)]))
        stats-markers))

(defn stats!
  [{:keys [db]}]
  (let [conn (get-conn (db-config db))]
    (try
      (println (json/generate-string {:results [(stats (d/db conn))]}))
      (finally
        (close-conn! conn)))))

(defn load-json-file!
  [kind {:keys [db file source-url resource-type] :as opts}]
  (let [conn (get-conn (db-config db))
        value (read-json-file file)
        source-opts (assoc opts :source-path file :source-url source-url)]
    (try
      (case kind
        :config (load-config-json! conn value source-opts)
        :policy (load-iam-policy-json! conn value source-opts)
        :service-reference (load-service-reference-json! conn value source-opts)
        :config-resource-schema (load-config-resource-schema-json! conn resource-type value source-opts))
      (finally
        (close-conn! conn)))))

(defn load-config!
  [{:keys [file] :as opts}]
  (load-json-file! :config opts))

(defn load-policy!
  [{:keys [file] :as opts}]
  (load-json-file! :policy opts))

(defn load-policy-file!
  [opts]
  (load-policy! opts))

(defn load-service-reference!
  [{:keys [file] :as opts}]
  (load-json-file! :service-reference opts))

(defn load-config-resource-schema!
  [{:keys [file resource-type] :as opts}]
  (when-not resource-type
    (throw (ex-info "--resource-type required" {:opts opts})))
  (load-json-file! :config-resource-schema opts))

(defn jsonl-records
  [reader]
  (keep-indexed (fn [idx line]
                  (let [s (str/trim line)]
                    (when (seq s)
                      {:line (inc idx)
                       :value (parse-json s)})))
                (line-seq reader)))

(defn batch-load!
  [kind {:keys [db file] :as opts}]
  (let [conn (get-conn (db-config db))
        rdr (if file (io/reader (io/file file)) *in*)]
    (try
      (doseq [{:keys [line value]} (jsonl-records rdr)]
        (println
         (json/generate-string
          {:line line
           :result (case kind
                     :config (load-config-json! conn value (assoc opts :source-path file))
                     :policy (load-iam-policy-json! conn value (assoc opts :source-path file))
                     :service-reference (load-service-reference-json! conn value (assoc opts :source-path file)))})))
      (finally
        (when file (.close rdr))
        (close-conn! conn)))))

(defn retract-source!
  [{:keys [db source-path]}]
  (let [conn (get-conn (db-config db))]
    (try
      (let [dbv (d/db conn)
            config-eids (d/q '[:find [?config ...]
                               :in $ ?source-path
                               :where [?config :config/source-path ?source-path]]
                             dbv source-path)
            document-eids (d/q '[:find [?doc ...]
                                 :in $ ?source-path
                                 :where [?doc :document/source-path ?source-path]]
                               dbv source-path)
            tx-data (mapv #(vector :db.fn/retractEntity %) (concat config-eids document-eids))
            report (when (seq tx-data) (d/transact conn tx-data))]
        {:retracted-config-items (count config-eids)
         :retracted-documents (count document-eids)
         :datoms (count (:tx-data report))})
      (finally
        (close-conn! conn)))))

(def cli-spec
  {:db {:ref "<path>" :desc "Datahike database path"}
   :file {:ref "<file>" :desc "Input JSON/JSONL file" :alias :f}
   :policy-arn {:ref "<arn>" :desc "Managed policy ARN"}
   :policy-name {:ref "<name>" :desc "Managed policy name"}
   :version-id {:ref "<id>" :desc "Policy version id"}
   :default {:desc "Imported policy version is default" :coerce :boolean}
   :source-url {:ref "<url>" :desc "Source URL"}
   :source-path {:ref "<path>" :desc "Source path for correction/retraction"}
   :resource-type {:ref "<type>" :desc "AWS Config resource type"}
   :dir {:ref "<dir>" :desc "Directory for AWS service-reference catalog files"}
   :help {:desc "Show help" :alias :h :coerce :boolean}})

(defn usage
  []
  (str "Usage:\n"
       "  bb -m iam-datahike load-config --db DB --file config.json\n"
       "  bb -m iam-datahike load-policy --db DB --policy-arn ARN --file policy.json\n"
       "  bb -m iam-datahike load-service-reference --db DB --file iam.json\n"
       "  bb -m iam-datahike prefetch-service-reference --dir samples/iam-policy/service-reference\n"
       "  bb -m iam-datahike preload-service-reference --db DB --dir samples/iam-policy/service-reference\n"
       "  bb -m iam-datahike sync-service-reference --db DB --dir samples/iam-policy/service-reference\n"
       "  bb -m iam-datahike load-config-resource-schema --db DB --resource-type AWS::IAM::Role --file role.properties.json\n"
       "  bb -m iam-datahike batch-load-config --db DB --file rows.jsonl\n"
       "  bb -m iam-datahike retract-source --db DB --source-path rows.jsonl\n"
       "  bb -m iam-datahike stats --db DB\n\n"
       (cli/format-opts {:spec cli-spec
                         :order [:db :file :policy-arn :policy-name :version-id
                                 :default :source-url :source-path :resource-type :dir :help]})))

(defn require-opts!
  [opts ks]
  (doseq [k ks]
    (when-not (seq (str (get opts k)))
      (throw (ex-info (str "Missing required option " (name k)) {:opts opts})))))

(def dispatch-table
  [{:cmds ["load-config"] :fn (fn [{:keys [opts]}]
                                (require-opts! opts [:db :file])
                                (println (json/generate-string (load-config! opts))))}
   {:cmds ["load-policy"] :fn (fn [{:keys [opts]}]
                                (require-opts! opts [:db :file])
                                (println (json/generate-string (load-policy! opts))))}
   {:cmds ["load-service-reference"] :fn (fn [{:keys [opts]}]
                                           (require-opts! opts [:db :file])
                                           (println (json/generate-string (load-service-reference! opts))))}
   {:cmds ["prefetch-service-reference"] :fn (fn [{:keys [opts]}]
                                               (println (json/generate-string
                                                         (prefetch-service-reference! opts))))}
   {:cmds ["preload-service-reference"] :fn (fn [{:keys [opts]}]
                                             (require-opts! opts [:db])
                                             (let [conn (get-conn (db-config (:db opts)))]
                                               (try
                                                 (println (json/generate-string
                                                           (preload-service-reference! conn opts)))
                                                 (finally
                                                   (close-conn! conn)))))}
   {:cmds ["sync-service-reference"] :fn (fn [{:keys [opts]}]
                                           (require-opts! opts [:db])
                                           (println (json/generate-string
                                                     (sync-service-reference! opts))))}
   {:cmds ["load-config-resource-schema"] :fn (fn [{:keys [opts]}]
                                                (require-opts! opts [:db :file :resource-type])
                                                (println (json/generate-string
                                                          (load-config-resource-schema! opts))))}
   {:cmds ["batch-load-config"] :fn (fn [{:keys [opts]}]
                                      (require-opts! opts [:db])
                                      (batch-load! :config opts))}
   {:cmds ["batch-load-policy"] :fn (fn [{:keys [opts]}]
                                      (require-opts! opts [:db])
                                      (batch-load! :policy opts))}
   {:cmds ["batch-load-service-reference"] :fn (fn [{:keys [opts]}]
                                                 (require-opts! opts [:db])
                                                 (batch-load! :service-reference opts))}
   {:cmds ["retract-source"] :fn (fn [{:keys [opts]}]
                                   (require-opts! opts [:db :source-path])
                                   (println (json/generate-string (retract-source! opts))))}
   {:cmds ["stats"] :fn (fn [{:keys [opts]}]
                          (require-opts! opts [:db])
                          (stats! opts))}
   {:cmds [] :fn (fn [_] (println (usage)))}])

(defn -main
  [& args]
  (try
    (cli/dispatch dispatch-table args {:spec cli-spec})
    (catch clojure.lang.ExceptionInfo e
      (binding [*out* *err*]
        (println (ex-message e))
        (println)
        (println (usage)))
      (System/exit 2))))
