(ns jolt.guardrails.add-deps-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.guardrails.bootstrap :as bootstrap]
            [com.fulcrologic.guardrails.core :as guardrails]
            [taoensso.truss :as truss]))

(deftest deps-edn-loads-guardrails-and-truss
  (testing "the Guardrails dependency exposes its macro API"
    (is (true? (:macro (meta #'guardrails/>defn)))))
  (testing "the requested Truss dependency is usable"
    (is (= "loaded" (truss/have string? "loaded")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (truss/have string? 42)))))
