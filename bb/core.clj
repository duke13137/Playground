#!/usr/bin/env bb
(ns core 
  (:require 
    [cheshire.core :as json]
    [hiccup2.core :as h]
    [org.httpkit.server]
    [ring.middleware.params :refer [wrap-params]]
    [clj-simple-router.core :as router]
    [selmer.parser :refer [render-file]]
    [starfederation.datastar.clojure.api :as d*]
    [starfederation.datastar.clojure.adapter.http-kit2 :as hk]
    [todoapp]))

(comment

  'comment)

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Config
;;;;;;;;;;;;;;;;;;;;;;;;;;

(def port 3000)

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;

(def sse-connections (atom #{}))

(defn use-sse [handler]
  (fn [req]
    (hk/->sse-response req
      {hk/on-open
       (fn [sse]
         (swap! sse-connections conj sse)
         (d*/with-open-sse sse
           (handler req sse)))
       hk/on-close
       (fn [sse status]
         (swap! sse-connections disj sse)
         (println status))
       hk/on-exception
       (fn [e]
         (println e))})))

(defn html [h]
  (str (h/html h)))

(defn parse-json [s]
  (json/parse-string s true))

(defn get-signals [req]
  (-> req d*/get-signals parse-json))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Handlers
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn index [req]
  {:status 200
   :body (render-file "index.html" {})})

(defn js [req]
  {:status 200
   :body (render-file "client.cljs" {})})

(def message "Hello from server!")

(defn update-hello [req sse]
  (let [d (-> req get-signals :delay int)]
    (dotimes [i (count message)]
      (d*/patch-elements! sse
        (html [:h1 {:id "message"}
               (subs message 0 (inc i))]))
      (Thread/sleep d))
    (d*/console-log! sse message)))

(import '[java.time LocalTime]
        '[java.time.format DateTimeFormatter])

(def dt-format (DateTimeFormatter/ofPattern "HH:mm:ss"))

(defn now []
  (.format (LocalTime/now) dt-format))

(defn update-clock [req sse]
  (d*/patch-elements! sse
    (html [:h1 {:id "clock"
                :data-on-interval__duration.1s (d*/sse-get "/clock-sse")}
           (now)])))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes
;;;;;;;;;;;;;;;;;;;;;;;;;;
(def routes (merge {"GET /" index
                    "GET /client.cljs" js
                    "GET /hello-sse" (use-sse #'update-hello)
                    "GET /clock-sse" (use-sse #'update-clock)}
                   todoapp/routes))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Server
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn -main [& args]
  (let [url (str "http://localhost:" port "/")]
    (def srv (org.httpkit.server/run-server
              (-> (router/router routes)
                  (wrap-params)
                  (hk/wrap-start-responding))
              {:port port}))
    (println "serving" url)))

(require '[sci.nrepl.browser-server :as browser])
(require '[babashka.nrepl.server :as nrepl])
(when (= *file* (System/getProperty "babashka.file"))
  (browser/start! {:nrepl-port 3339 :websocket-port 3340})
  (nrepl/start-server! {:host "127.0.0.1" :port 3333})
  ;; (srv)
  (-main)
  @(promise))
