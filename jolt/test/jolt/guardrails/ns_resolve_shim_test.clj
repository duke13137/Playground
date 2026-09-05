(ns jolt.guardrails.ns-resolve-shim-test
  (:require [clojure.test :refer [deftest is]]
            [jolt.guardrails.ns-resolve-shim]))

(deftest three-arity-ns-resolve-honors-the-macro-environment
  (is (= #'clojure.core/map
         (ns-resolve *ns* {} 'map)))
  (is (nil? (ns-resolve *ns* {'map :local-binding} 'map))))
