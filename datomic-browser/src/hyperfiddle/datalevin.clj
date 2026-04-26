(ns hyperfiddle.datalevin
  (:require [clojure.string :as str]
            [datalevin.core :as dl]
            [dustingetz.data :refer [unqualify realize]]
            [hyperfiddle.hfql2 :as hfql :refer [hfql]]
            [hyperfiddle.hfql2.protocols :as hfqlp :refer [Identifiable Suggestable Navigable ComparableRepresentation]]))

(defrecord DatalevinDb [name target conn db])

(declare wrap-value)

(defn- db-wrapper-map? [x]
  (and (map? x)
       (contains? x :name)
       (contains? x :target)
       (contains? x :conn)
       (contains? x :db)))

(defn db? [x]
  (or (instance? DatalevinDb x)
      (db-wrapper-map? x)))

(defn raw-db [db]
  (if (db? db)
    (:db db)
    db))

(defn raw-conn [db]
  (when (db? db)
    (:conn db)))

(defn datom-e [datom]
  (or (:e datom) (nth datom 0 nil)))

(defn datom-a [datom]
  (or (:a datom) (nth datom 1 nil)))

(defn datom-v [datom]
  (let [v (:v datom)]
    (if (some? v) v (nth datom 2 nil))))

(defn db-name-from-target [target]
  (let [s (str target)
        trimmed (str/replace s #"/+$" "")
        leaf (last (str/split trimmed #"/"))]
    (or (not-empty leaf) s)))

(defn connect-db [target]
  (let [conn (dl/get-conn target)]
    (->DatalevinDb (db-name-from-target target) target conn (dl/db conn))))

(defn db-placeholder [target]
  (->DatalevinDb (db-name-from-target target) target nil nil))

(defn current-db [db]
  (if-let [conn (raw-conn db)]
    (assoc db :db (dl/db conn))
    db))

(deftype DatalevinAttribute [db ident schema]
  clojure.lang.ILookup
  (valAt [_ k]
    (case k
      :db/id ident
      :db/ident ident
      (get schema k)))
  (valAt [this k not-found]
    (let [v (.valAt this k)]
      (if (nil? v) not-found v))))

(deftype DatalevinEntity [db eid]
  clojure.lang.ILookup
  (valAt [_ k]
    (case k
      :db/id eid
      (let [raw-entity (dl/entity (raw-db db) eid)]
        (wrap-value db (get raw-entity k)))))
  (valAt [this k not-found]
    (let [v (.valAt this k)]
      (if (nil? v) not-found v))))

(deftype DatalevinDatom [db e a v]
  clojure.lang.ILookup
  (valAt [_ k]
    (case k
      :e e
      :a a
      :v v
      nil))
  (valAt [this k not-found]
    (let [v (.valAt this k)]
      (if (nil? v) not-found v))))

(defn entity-like? [x]
  (and (some? x)
       (try
         (some? (:db/id x))
         (catch Throwable _ false))))

(defn wrap-value [db v]
  (cond
    (instance? DatalevinEntity v) v
    (entity-like? v) (DatalevinEntity. db (:db/id v))
    (set? v) (set (map #(wrap-value db %) v))
    (and (sequential? v) (not (string? v))) (map #(wrap-value db %) v)
    :else v))

(defn entity
  [db eid]
  (when (some? eid)
    (cond
      (instance? DatalevinEntity eid) eid
      (entity-like? eid) (DatalevinEntity. db (:db/id eid))
      (dl/entity (raw-db db) eid) (DatalevinEntity. db eid))))

(defn datom [db raw-datom]
  (DatalevinDatom. db (datom-e raw-datom) (datom-a raw-datom) (wrap-value db (datom-v raw-datom))))

(defn schema-map [db]
  (if-let [conn (raw-conn db)]
    (dl/schema conn)
    {}))

(defn all-attr-idents [db]
  (into (set (keys (schema-map db)))
    (map datom-a)
    (dl/datoms (raw-db db) :eav)))

(defn all-entity-ids [db]
  (->> (dl/datoms (raw-db db) :eav)
    (map datom-e)
    (distinct)
    (sort)))

(defn query-schema
  ([db]
   (let [schema (schema-map db)]
     (mapv #(assoc (get schema % {}) :db/ident %) (sort (all-attr-idents db)))))
  ([db a]
   (when a
     (assoc (get (schema-map db) a {}) :db/ident a))))

(defn attribute [db ident]
  (when ident
    (DatalevinAttribute. db ident (query-schema db ident))))

(defn easy-attr [db a]
  (when a
    (let [schema (query-schema db a)]
      [(unqualify (:db/valueType schema))
       (unqualify (:db/cardinality schema))
       (unqualify (:db/unique schema))
       (if (:db/isComponent schema) :component)
       (if (:db/index schema) :indexed)
       (if (:db/fulltext schema) :fulltext)])))

(defn entity-attrs
  ([entity] (entity-attrs (.-db entity) (:db/id entity)))
  ([db eid]
   (->> (dl/datoms (raw-db db) :eav eid)
     (map datom-a)
     (distinct)
     (into #{}))))

(defn reverse-attr [?kw]
  (if ?kw
    (keyword (namespace ?kw)
      (let [s (name ?kw)]
        (case (.charAt s 0)
          \_ (subs s 1)
          (str "_" s))))))

(defn reverse-attribute? [attribute]
  {:pre [(qualified-keyword? attribute)]}
  (str/starts-with? (name attribute) "_"))

(defn invert-attribute [attribute]
  {:pre [(qualified-keyword? attribute)]}
  (let [nom (name attribute)]
    (keyword (namespace attribute) (if (reverse-attribute? attribute) (subs nom 1) (str "_" nom)))))

(defn ref? [db a]
  (= :db.type/ref (:db/valueType (query-schema db a))))

(defn reverse-refs
  ([db target] (reverse-refs db target false))
  ([db target _include-system-refs?]
   (let [eid (if (instance? DatalevinEntity target) (:db/id target) target)]
     (->> (query-schema db)
       (keep :db/ident)
       (filter #(ref? db %))
       (mapcat (fn [attr]
                 (map (fn [datom] [attr (datom-e datom)])
                   (dl/datoms (raw-db db) :ave attr eid))))))))

(defn back-references [db eid]
  (reduce
    (fn [acc [attr source-eid]]
      (update acc (invert-attribute attr) (fnil conj #{}) (entity db source-eid)))
    {}
    (reverse-refs db eid)))

(defn best-human-friendly-identity [!e]
  (or (:db/ident !e) (:db/id !e)))

(defn- datalog-var? [x]
  (and (symbol? x) (str/starts-with? (name x) "?")))

(defn- normalize-datalog-query [query]
  (let [q (if (and (map? query) (:query query)) (:query query) query)]
    (if (map? q) q
      (let [m (->> (partition-by keyword? q)
                (partition 2)
                (reduce (fn [m [[k] clauses]] (assoc m k (vec clauses))) {}))]
        (assert (:find m) (str "Datalog query missing :find clause: " (pr-str query)))
        m))))

(defn- datalog-identity-bindings [query unique-identity?]
  (letfn [(find-vars [find-spec]
            (let [elements (if (and (= 1 (count find-spec)) (vector? (first find-spec)))
                             (first find-spec)
                             find-spec)]
              (->> elements
                (remove #{'... '.})
                (mapcat (fn [x]
                          (cond
                            (datalog-var? x) [x]
                            (seq? x) (filter datalog-var? x)
                            :else [])))
                set)))
          (walk-where [clauses]
            (reduce
              (fn [ids clause]
                (cond
                  (and (vector? clause)
                       (>= (count clause) 2)
                       (not (list? (first clause))))
                  (let [[e a v] clause]
                    (cond-> ids
                      (datalog-var? e) (conj e)
                      (and (some? v)
                           (datalog-var? v)
                           (keyword? a)
                           (unique-identity? a)) (conj v)))
                  (sequential? clause)
                  (into ids (walk-where (filter sequential? (rest clause))))
                  :else ids))
              #{}
              clauses))]
    (let [q (normalize-datalog-query query)]
      (set (filter (walk-where (:where q)) (find-vars (:find q)))))))

(defn- reshape-datalog-query-result [raw-ret find-spec where-clauses id-keys]
  (letfn [(element->key [element]
            (cond
              (datalog-var? element) element
              (seq? element) (realize element)
              :else element))
          (find-type [find-spec]
            (cond
              (and (= 1 (count find-spec)) (vector? (first find-spec)))
              (if (= '... (last (first find-spec))) :collection :tuple)
              (= '. (last find-spec)) :scalar
              :else :relation))
          (var-origins [clauses]
            (reduce
              (fn [origins clause]
                (cond
                  (and (vector? clause)
                       (>= (count clause) 2)
                       (not (list? (first clause))))
                  (let [[_e a v] clause]
                    (cond-> origins
                      (and (some? v) (datalog-var? v) (keyword? a)) (assoc v a)))
                  (sequential? clause)
                  (merge origins (var-origins (filter sequential? (rest clause))))
                  :else origins))
              {}
              clauses))]
    (let [raw-elements (let [elements (if (and (= 1 (count find-spec)) (vector? (first find-spec)))
                                        (first find-spec)
                                        find-spec)]
                         (vec (remove #{'... '.} elements)))
          vars (mapv element->key raw-elements)
          origins (var-origins where-clauses)
          vars (mapv (fn [v elem]
                       (let [inner-var (if (datalog-var? elem)
                                         elem
                                         (first (filter datalog-var? (flatten elem))))
                             attr (get origins inner-var)]
                         (cond-> v
                           attr (vary-meta assoc ::source-attribute attr)
                           (contains? id-keys v)
                           (vary-meta assoc `hfqlp/-identify
                             (fn [eid] (list `entity eid))))))
                     vars raw-elements)]
      (case (find-type find-spec)
        :collection (mapv #(array-map (first vars) %) raw-ret)
        :relation (mapv #(zipmap vars %) raw-ret)
        :tuple [(zipmap vars raw-ret)]
        :scalar [(array-map (first vars) raw-ret)]))))

(defn normalize-datalog-query-result [query-map raw-ret]
  (let [q (normalize-datalog-query (:query query-map))
        db (first (:args query-map))
        id-keys (if (db? db)
                  (datalog-identity-bindings (:query query-map)
                    #(= :db.unique/identity (:db/unique (query-schema db %))))
                  #{})]
    (reshape-datalog-query-result raw-ret (:find q) (:where q) id-keys)))

(extend-type DatalevinDb
  Identifiable
  (-identify [db] (when-let [nm (:name db)] (list `dx/db nm)))
  ComparableRepresentation
  (-comparable [db] (:name db)))

(extend-type DatalevinAttribute
  Identifiable
  (-identify [attribute] (list `dx/attribute (.-ident attribute)))
  Suggestable
  (-suggest [_] (hfql [:db/id :db/ident :db/valueType :db/cardinality :db/unique :db/isComponent :db/index :db/fulltext]))
  Navigable
  (-nav [attribute k _]
    (case k
      :db/id attribute
      :db/ident attribute
      (.valAt attribute k)))
  ComparableRepresentation
  (-comparable [attribute] (.-ident attribute)))

(extend-type DatalevinEntity
  Identifiable
  (-identify [entity] (list `dx/entity (:db/id entity)))
  Suggestable
  (-suggest [entity]
    (let [db (.-db entity)
          attributes (cons :db/id (entity-attrs entity))
          reverse-attributes (->> (reverse-refs db (:db/id entity))
                               (map first) (distinct) (map invert-attribute))]
      (hfql/build-hfql (vec (concat attributes reverse-attributes)))))
  Navigable
  (-nav [entity k v]
    (let [db (.-db entity)]
      (cond
        (= :db/id k) (:db/id entity)
        (= :db/ident k) entity
        (keyword? k) (wrap-value db (or v (.valAt entity k))))))
  ComparableRepresentation
  (-comparable [entity] (str (best-human-friendly-identity entity))))

(extend-type DatalevinDatom
  Identifiable
  (-identify [datum] (list `dx/datom (:e datum) (:a datum) (:v datum)))
  Navigable
  (-nav [datum k _]
    (case k
      :e (entity (.-db datum) (:e datum))
      :a (attribute (.-db datum) (:a datum))
      :v (:v datum)))
  Suggestable
  (-suggest [_] (hfql [:e :a :v]))
  ComparableRepresentation
  (-comparable [datum] [(:e datum) (:a datum) (:v datum)]))
