(ns datalevin-browser.main
  "Datalevin Browser - self-contained single process.

   Usage:
     clj -M -m datalevin-browser.main datalevin-uri /path/to/db
     clj -M -m datalevin-browser.main datalevin-uri dtlv://user:pass@host/db
     clj -M -m datalevin-browser.main datalevin-uri /path/to/db http-port 9090"
  (:require [hyperfiddle.navigator-agent :as agent]
            [hyperfiddle.nav-datalevin :as nav]))

(defn -main [& args]
  (let [positional-target (when (= 1 (count args)) (first args))
        args (if (even? (count args)) args (butlast args))
        {:strs [datalevin-uri datalevin-dir http-port]} (apply hash-map args)
        port (or (some-> http-port parse-long) 8080)
        target (or datalevin-uri datalevin-dir positional-target "state/datalevin")]
    (agent/serve! nav/sitemap (nav/make-setup-fn target) :port port)))
