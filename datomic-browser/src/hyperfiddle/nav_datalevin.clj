(ns hyperfiddle.nav-datalevin
  "Pure Clojure layer for Datalevin navigation."
  (:require
   [clojure.string :as str]
   [datalevin.core :as dl]
   [dustingetz.check :refer [check]]
   [hyperfiddle.datalevin :as dx]
   [dustingetz.str :refer [pprint-str]]
   [hyperfiddle0 :as hf0]
   [hyperfiddle.hfql2 :as hfql :refer [hfql hfql-resolve]]
   [hyperfiddle.hfql2.protocols :refer [-hfql-resolve]]
   [hyperfiddle.navigator6.rendering :as rendering]
   [hyperfiddle.navigator6.search :refer [*local-search]]))

(defonce ^:dynamic *target* nil)
(defonce ^:dynamic *db-name* nil)
(defonce ^:dynamic *conn* nil)
(defonce ^:dynamic *db* nil)

(defn databases []
  (when (some? *target*)
    (list (dx/db-name-from-target *target*))))

(defn db-name [db]
  (if (string? db) db (:name db)))

(defn db-counts [db]
  {:attribute-count (count (dx/query-schema db))
   :datom-count (dl/count-datoms (dx/raw-db db) nil nil nil)
   :entity-count (count (dx/all-entity-ids db))})

(defn route-stats-doc [sym]
  (when (and *db*
          (#{'attributes 'databases 'entities 'query } sym))
    (let [{:keys [attribute-count datom-count entity-count]} (db-counts *db*)]
      (str "attributes " attribute-count
        ", datoms " datom-count
        ", entities " entity-count))))

(defn install-route-stats-docs! []
  (let [default-resolve-var-doc @#'hf0/resolve-var-doc]
    (alter-var-root #'hf0/resolve-var-doc
      (fn [resolve-var-doc]
        (if (::datalevin-route-stats-docs (meta resolve-var-doc))
          resolve-var-doc
          (with-meta
            (fn [sym]
              (or (route-stats-doc sym)
                (default-resolve-var-doc sym)))
            {::datalevin-route-stats-docs true}))))))

(install-route-stats-docs!)

(defn attributes
  ([] (attributes (check *db*)))
  ([db]
   (->> (dx/query-schema db)
     (map #(dx/attribute db (:db/ident %)))
     (hfql/navigable (fn [_index attr] attr)))))

(defn attribute-count [!e]
  (dl/count-datoms (dx/raw-db *db*) nil (:db/ident !e) nil))

(defn fulltext-attribute? [db ident]
  (true? (:db/fulltext (dx/query-schema db ident))))

(defn- prefix-match? [search datom]
  (str/starts-with? (str (dx/datom-v datom)) search))

(defn- scan-attribute-datoms [raw-db ident search]
  (cond->> (dl/search-datoms raw-db nil ident nil)
    search (filter #(prefix-match? search %))))

(defn attribute-datoms
  ([db ident] (attribute-datoms db ident nil))
  ([db ident search]
   (let [raw-db (dx/raw-db db)
         search (not-empty (str/trim (str search)))]
     (cond
       (nil? search)
       (dl/search-datoms raw-db nil ident nil)

       (fulltext-attribute? db ident)
       (try
         (filter #(= ident (dx/datom-a %))
           (dl/fulltext-datoms raw-db search))
         (catch Throwable _
           (scan-attribute-datoms raw-db ident search)))

       :else
       (try
         (->> (dl/index-range raw-db ident search nil)
           (take-while #(prefix-match? search %)))
         (catch Throwable _
           (scan-attribute-datoms raw-db ident search)))))))

(defn summarize-attr [db k]
  (->> (dx/easy-attr db k) (remove nil?) (map name) (str/join " ")))

(defn summarize-attr* [?!a]
  (when ?!a (summarize-attr *db* (:db/ident ?!a))))

(defn attribute-detail [!e]
  (let [ident (:db/ident !e)
        search (not-empty (str/trim (str *local-search)))
        entids (->> (attribute-datoms *db* ident search)
                 (map dx/datom-e)
                 distinct)]
    (->> entids
      (hfql/filtered)
      (hfql/navigable (fn [_index ?e] (dx/entity *db* ?e))))))

(defn entities
  ([] (entities (check *db*)))
  ([db]
   (->> (dx/all-entity-ids db)
     (map #(dx/entity db %))
     (hfql/navigable (fn [_index ?e] ?e)))))

(def entity-detail identity)
(def attribute-entity-detail identity)

(defn query-args [query-map]
  (map #(if (dx/db? %) (dx/raw-db %) %) (:args query-map)))

(defn- schema-ident-query? [query]
  (= '[:find ?e ?a :where [?e :db/ident ?a]]
    (if (seq? query) (vec query) query)))

(defn- schema-ident-query-result [db]
  (mapv (fn [{:db/keys [ident]}] [ident ident])
    (dx/query-schema db)))

(defn query [query-map]
  (let [db (first (:args query-map))]
    (dx/normalize-datalog-query-result query-map
      (if (and (dx/db? db) (schema-ident-query? (:query query-map)))
        (schema-ident-query-result db)
        (apply dl/q (:query query-map) (query-args query-map))))))

(defn query-form-defaults [{:syms [query-map]}]
  {'query-map (or query-map
                 '{:query [:find ?e ?a :where [?e :db/ident ?a]]
                   :args [*db*]})})

(defn entity-exists? [db eid]
  (and (some? eid) (seq (dl/datoms (dx/raw-db db) :eav eid))))

(defn- coerce-eid [eid]
  (cond
    (integer? eid) eid
    (string? eid) (parse-long eid)
    (symbol? eid) (parse-long (name eid))
    :else eid))

(defn- resolve-entity [eid]
  (let [eid (coerce-eid eid)]
    (when (entity-exists? *db* eid)
      (dx/entity *db* eid))))

(defmethod -hfql-resolve `dx/db [[_ db-name]]
  (when (= db-name *db-name*)
    *db*))

(defmethod -hfql-resolve 'dx/db [[_ db-name]]
  (hfql-resolve `(dx/db ~db-name)))

(defmethod -hfql-resolve `db [[_ db-name]]
  (hfql-resolve `(dx/db ~db-name)))

(defmethod -hfql-resolve `dx/entity [[_ eid]]
  (resolve-entity eid))

(defmethod -hfql-resolve 'dx/entity [[_ eid]]
  (resolve-entity eid))

(defmethod -hfql-resolve `dx/attribute [[_ ident]]
  (dx/attribute *db* ident))

(defmethod -hfql-resolve 'dx/attribute [[_ ident]]
  (dx/attribute *db* ident))

(defmethod -hfql-resolve `dx/datom [[_ e a v]]
  (some->> (dl/datoms (dx/raw-db *db*) :eav e a v)
    first
    (dx/datom *db*)))

(defmethod -hfql-resolve 'dx/datom [[_ e a v]]
  (hfql-resolve `(dx/datom ~e ~a ~v)))

(defn attr-ident-name [attr]
  (some-> attr :db/ident str))

(def sitemap
  {'databases
   (hfql {(databases) {* [^{::hfql/link ['. [`(~'Inject ~'%v) 'attributes]]}
                           db-name]}})

   'attributes
   (hfql {(attributes)
          {* ^{::hfql/select '(attribute-entity-detail %)}
           [^{::hfql/link '(attribute-detail %)
              ::hfql/Tooltip `hyperfiddle.navigator6.rendering/FnTooltip}
             attr-ident-name
             attribute-count
             summarize-attr*]}})

   'entities
   (hfql {(entities)
          {* [^{::hfql/link '(entity-detail %)
                ::hfql/Tooltip `hyperfiddle.navigator6.rendering/FnTooltip}
              #(:db/id %)
              *]}})

   'query (hfql ^{::hfql/form-defaults query-form-defaults} (query query-map))

   'attribute-entity-detail
   (hfql {attribute-entity-detail ^{::hfql/Tooltip `hyperfiddle.navigator6.rendering/FnTooltip}
          [#(:db/id %)
           attribute-count
           summarize-attr*
           *]})

   'attribute-detail
   (hfql {attribute-detail
          {* ^{::hfql/Tooltip `hyperfiddle.navigator6.rendering/FnTooltip}
           [^{::hfql/link '(entity-detail %)}
            #(:db/id %)]}})

   'entity-detail
   (hfql {entity-detail ^{::hfql/Tooltip `hyperfiddle.navigator6.rendering/FnTooltip}
          [#(:db/id %)
           *]})})

(defn make-setup-fn [target]
  (fn
    ([]
     (let [db (dx/connect-db target)
           db-name (:name db)]
       {#'*target* target
        #'*db-name* db-name
        #'*conn* (:conn db)
        #'*db* db
        #'rendering/*server-pretty
        {hyperfiddle.datalevin.DatalevinAttribute
         (fn [attr] (str "Attribute[" (:db/ident attr) "]"))
         hyperfiddle.datalevin.DatalevinEntity
         (fn [entity] (str "Entity[" (dx/best-human-friendly-identity entity) "]"))}
        #'rendering/*tooltip-fn*
        (fn [_entity _edge value]
          (cond
            (instance? hyperfiddle.datalevin.DatalevinAttribute value)
            (pprint-str (dx/query-schema *db* (:db/ident value)) :print-length 20 :print-level 2)
            (instance? hyperfiddle.datalevin.DatalevinEntity value)
            (pprint-str (into {} (dl/touch (dl/entity (dx/raw-db (.-db value)) (:db/id value))))
              :print-length 10 :print-level 2)))}))
    ([db-name]
     (let [db (dx/connect-db target)]
       (when (= db-name (:name db))
         {#'*target* target
          #'*db-name* db-name
          #'*conn* (:conn db)
          #'*db* db})))))
