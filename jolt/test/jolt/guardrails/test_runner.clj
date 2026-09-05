(ns jolt.guardrails.test-runner
  (:require [clojure.test :as test]
            [jolt.guardrails.bootstrap]))

;; Keep bootstrap and the ns-resolve shim ahead of upstream macro expansion.
 (require 'jolt.guardrails.add-deps-test
         'jolt.guardrails.ns-resolve-shim-test
         'jolt.guardrails.fulcro-spec-shim-test
         'com.fulcrologic.guardrails.config-spec
         'com.fulcrologic.guardrails.core-spec
         'com.fulcrologic.guardrails.impl.externs-spec
         'com.fulcrologic.guardrails.impl.parser-spec
         'com.fulcrologic.guardrails.malli.core-spec
         'com.fulcrologic.guardrails.malli.fulcro-spec-helpers-spec
         'com.fulcrologic.guardrails.utils-spec
         'taoensso.truss-tests)

(def test-namespaces
  '[jolt.guardrails.add-deps-test
    jolt.guardrails.ns-resolve-shim-test
    jolt.guardrails.fulcro-spec-shim-test
    com.fulcrologic.guardrails.config-spec
    com.fulcrologic.guardrails.core-spec
    com.fulcrologic.guardrails.impl.externs-spec
    com.fulcrologic.guardrails.impl.parser-spec
    com.fulcrologic.guardrails.malli.core-spec
    com.fulcrologic.guardrails.malli.fulcro-spec-helpers-spec
    com.fulcrologic.guardrails.utils-spec
    taoensso.truss-tests])

(defn -main [& _]
  (let [{:keys [fail error]} (apply test/run-tests test-namespaces)]
    (System/exit (if (zero? (+ fail error)) 0 1))))
