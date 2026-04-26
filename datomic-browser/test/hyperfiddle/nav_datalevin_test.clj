(ns hyperfiddle.nav-datalevin-test
  (:require
   [clojure.java.io :as io]
   [clojure.test :refer [deftest is testing]]
   [datalevin.core :as dl]
   [hyperfiddle.datalevin :as dx]
   [hyperfiddle.nav-datalevin :as nav]))

(def schema
  {:item/name {:db/valueType :db.type/string}
   :item/rank {:db/valueType :db.type/long}
   :item/tag {:db/valueType :db.type/string
              :db/cardinality :db.cardinality/many}})

(defn with-db [f]
  (let [path (str (doto (io/file "target" "datalevin-browser-test-dbs")
                    (.mkdirs))
               "/" (random-uuid))
        conn (dl/get-conn path schema)]
    (try
      (dl/transact! conn [{:item/name "alpha"
                           :item/rank 1
                           :item/tag ["a" "common"]}
                          {:item/name "beta"
                           :item/rank 2
                           :item/tag ["b" "common"]}])
      (f (dx/->DatalevinDb "test" path conn (dl/db conn)))
      (finally
        (dl/close conn)))))

(deftest attributes-can-be-counted-and-filtered-by-prefix
  (with-db
    (fn [db]
      (testing "attribute counts include all datoms for cardinality-many attrs"
        (binding [nav/*db* db]
          (is (= 4 (nav/attribute-count (dx/attribute db :item/tag))))))

      (testing "attribute detail supports prefix search through the public helper"
        (is (= [1]
              (mapv dx/datom-e
                (nav/attribute-datoms db :item/name "alp"))))))))

(deftest entity-browse-data-is-schema-generic
  (with-db
    (fn [db]
      (let [entity (dx/entity db 1)]
        (is (= #{:item/name :item/rank :item/tag}
              (dx/entity-attrs entity)))))))
