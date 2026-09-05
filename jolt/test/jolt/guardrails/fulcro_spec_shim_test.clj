(ns jolt.guardrails.fulcro-spec-shim-test
  (:require [clojure.test :refer [deftest]]
            [fulcro-spec.core :refer [=throws=> assertions]]))

(deftest throws-assertions-accept-jolt-class-tokens
  (assertions
    (throw (ex-info "expected failure" {})) =throws=> #"expected failure"))
