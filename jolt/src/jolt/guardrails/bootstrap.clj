(ns jolt.guardrails.bootstrap
  "Sets Guardrails properties and installs test-time compatibility shims."
  (:require [clojure.walk :as walk]
            [fulcro-spec.assertions :as assertions]
            [jolt.guardrails.ns-resolve-shim]))

(defonce ^:private fulcro-triple->assertion
  assertions/triple->assertion)

(defn- symbolic-throwable [form]
  (if (= Throwable form)
    'java.lang.Throwable
    form))

(alter-var-root
  #'assertions/triple->assertion
  (fn [_]
    (fn [cljs? triple]
      (walk/postwalk symbolic-throwable
                     (fulcro-triple->assertion cljs? triple)))))

;; Match Guardrails' upstream JVM test invocation.
(System/setProperty "guardrails.config" "guardrails-test.edn")
(System/setProperty "guardrails.enabled" "true")
