(ns jolt.guardrails.ns-resolve-shim
  "Adds Clojure's three-arity ns-resolve contract to Jolt 0.8.1.")

(defonce ^:private jolt-ns-resolve clojure.core/ns-resolve)

(alter-var-root
  #'clojure.core/ns-resolve
  (fn [_]
    (fn
      ([ns sym]
       (jolt-ns-resolve ns sym))
      ([ns env sym]
       (when-not (contains? env sym)
         (jolt-ns-resolve ns sym))))))
