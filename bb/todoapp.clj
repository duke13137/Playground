(ns todoapp ;; Datastar Todo App
  (:require
   [clojure.string :as str]
   [hiccup2.core :as h]
   [cheshire.core :as json]
   [selmer.parser :refer [render-file]]
   [starfederation.datastar.clojure.api :as d*]
   [starfederation.datastar.clojure.adapter.http-kit2 :as hk]))

(require '[datalevin.core :as d])
;; (require '[babashka.pods :as pods])
;; (pods/load-pod 'huahaiy/datalevin "0.10.7")
;; (require '[pod.huahaiy.datalevin :as d])

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Datalevin
;;;;;;;;;;;;;;;;;;;;;;;;;;

(def schema
  {:todo/name {:db/valueType :db.type/string}
   :todo/done {:db/valueType :db.type/boolean}})

(def conn (d/get-conn "/tmp/bb-todos" schema))

(defn db []
  (d/db conn))

(defn todo-ids []
  (d/q '[:find [?e ...] :where [?e :todo/name _]] (db)))

(defn pull-todo [id]
  (d/pull (db) [:db/id :todo/name :todo/done] id))

(defn ->todo
  "Convert Datalevin pull result to component-friendly map."
  [m]
  {:id (:db/id m) :name (:todo/name m) :done (boolean (:todo/done m))})

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; CRUD
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn add-todo! [name]
  (d/transact! conn [{:todo/name name :todo/done false}]))

(defn toggle-todo! [id]
  (let [done (:todo/done (d/pull (db) [:todo/done] id))]
    (d/transact! conn [[:db/add id :todo/done (not done)]])))

(defn update-todo-name! [id name]
  (d/transact! conn [[:db/add id :todo/name name]]))

(defn remove-todo! [id]
  (d/transact! conn [[:db/retractEntity id]]))

(defn remove-all-completed! []
  (let [completed-ids (->> (todo-ids)
                           (map #(d/pull (db) [:db/id :todo/done] %))
                           (filter :todo/done)
                           (map :db/id))]
    (when (seq completed-ids)
      (d/transact! conn (mapv #(vector :db/retractEntity %) completed-ids)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Queries
;; NOTE: Boolean Datalog queries are broken in Datalevin pod
;; (e.g. [?e :todo/done false] matches true). Use pull + Clojure filter.
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn get-all-todos []
  (->> (todo-ids)
       (map #(->todo (pull-todo %)))
       (sort-by :id)))

(defn filtered-todos [filter-name]
  (let [all (get-all-todos)]
    (case filter-name
      "active"    (remove :done all)
      "completed" (filter :done all)
      all)))

(defn get-todo [id]
  (->todo (pull-todo id)))

(defn get-items-left []
  (count (remove :done (get-all-todos))))

(defn todos-completed []
  (count (filter :done (get-all-todos))))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn html [hiccup]
  (str (h/html hiccup)))

(defn patch-signals! [sse m]
  (d*/patch-signals! sse (json/generate-string m)))

(defn get-signals [req]
  (let [raw (d*/get-signals req)]
    (when raw
      (json/parse-string (if (string? raw) raw (slurp raw)) true))))

(defn path-id [req]
  (parse-long (first (:path-params req))))

(def streams (atom {}))
(def editing-users (atom {}))

(defn start-editing! [todo-id cid]
  (swap! editing-users assoc todo-id cid))

(defn stop-editing! [todo-id]
  (swap! editing-users dissoc todo-id))

(defn remove-stream-by-sse! [sse]
  (swap! streams (fn [m]
                   (into {} (remove (fn [[_ v]] (= sse (:sse v))) m)))))

(defn update-stream-filter! [cid filter-name]
  (when (and cid (seq cid))
    (swap! streams update cid assoc :filter (or filter-name "all"))))

(defn remove-stream-by-cid! [cid]
  (swap! streams dissoc cid))

(defn sse-response [handler & {:keys [on-close]}]
  (fn [req]
    (hk/->sse-response req
      {hk/on-open
       (fn [sse]
         (d*/with-open-sse sse
           (handler req sse)))
       hk/on-close
       (fn [sse status]
         (when on-close
           (on-close sse status))
         (println status))
       hk/on-exception
       (fn [e]
         (println e))})))

(defn use-sse [handler]
  (sse-response handler))

(defn use-sse-stream [handler]
  (sse-response handler :on-close (fn [sse _] (remove-stream-by-sse! sse))))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Components
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn todo-item [{:keys [id name done]}]
  [:li {:id (str "todo-" id)
        :class (when done "completed")}
   [:div.view
    [:input.toggle {:type "checkbox"
                    :checked done
                    :data-on:click (str "@patch('/todos/sse/done/" id "')")}]
    [:label {:data-on:dblclick (str "@get('/todos/sse/edit/" id "')")}
     name]
    [:button.destroy
     {:data-on:click (str "@delete('/todos/sse/" id "')")}]]])

(defn todo-edit-form [id name]
  [:li {:id (str "todo-" id) :class "editing"}
   [:input.edit {:data-bind:edittext ""
                 :data-on:keydown (str "evt.key === 'Enter' && @patch('/todos/sse/name/" id "')")
                 :data-on:blur (str "@patch('/todos/sse/name/" id "')")
                 :autofocus true}]])

(defn todo-list [todos]
  (map todo-item todos))

(defn item-count []
  (let [n (get-items-left)]
    [:span#todo-count.todo-count
     [:strong n] (if (= 1 n) " item left" " items left")]))

(defn clear-completed-button []
  [:button#clear-completed.clear-completed
   {:data-on:click "@delete('/todos/sse/clear')"
    :class (when-not (pos? (todos-completed)) "hidden")}
   "Clear completed"])

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Patch helper
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn patch-all! [sse filter-name]
  (let [todos (filtered-todos (or filter-name "all"))]
    (d*/patch-elements! sse (html [:ul#todo-list.todo-list (todo-list todos)]))
    (d*/patch-elements! sse (html (item-count)))
    (d*/patch-elements! sse (html (clear-completed-button)))))

(defn broadcast! []
  (doseq [[cid {:keys [sse filter]}] @streams]
    (try
      (patch-all! sse filter)
      (catch Exception _
        (swap! streams dissoc cid)))))

(defn respond! [sse filter & {:keys [broadcast? signals]}]
  (patch-all! sse filter)
  (when broadcast? (broadcast!))
  (when signals (patch-signals! sse signals))
  (d*/close-sse! sse))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSE Handlers
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn list-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [filter cid]} signals
        filter (or filter "all")]
    (update-stream-filter! cid filter)
    (respond! sse filter)))

(defn add-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [todo filter]} signals
        filter (or filter "all")]
    (when-not (str/blank? todo)
      (add-todo! todo))
    (respond! sse filter :broadcast? true :signals {:todo ""})))

(defn edit-todo [req sse]
  (let [signals (or (get-signals req) {})
        id (path-id req)
        todo (get-todo id)]
    (patch-signals! sse {:edittext (:name todo)})
    (d*/patch-elements! sse (html (todo-edit-form id (:name todo))))
    (d*/close-sse! sse)))

(defn save-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [edittext filter]} signals
        filter (or filter "all")
        id (path-id req)]
    (when-not (str/blank? edittext)
      (update-todo-name! id edittext))
    (respond! sse filter :broadcast? true)))

(defn toggle-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [filter]} signals
        filter (or filter "all")
        id (path-id req)]
    (toggle-todo! id)
    (respond! sse filter :broadcast? true)))

(defn delete-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [filter]} signals
        filter (or filter "all")
        id (path-id req)]
    (remove-todo! id)
    (respond! sse filter :broadcast? true)))

(defn clear-todo [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [filter]} signals
        filter (or filter "all")]
    (remove-all-completed!)
    (respond! sse filter :broadcast? true)))

(defn stream-todos [req sse]
  (let [signals (or (get-signals req) {})
        {:keys [filter cid]} signals
        filter (or filter "all")]
    (when (and cid (seq cid))
      (swap! streams assoc cid {:sse sse :filter filter}))
    (patch-all! sse filter)))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Page handler
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn app-index [req]
  (let [todos (get-all-todos)]
    {:status 200
     :body (render-file "todo.html"
                        {:initial-todos (html (todo-list todos))
                         :item-count (html (item-count))
                         :clear-completed (html (clear-completed-button))
                         :client-id (str (java.util.UUID/randomUUID))})}))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes
;;;;;;;;;;;;;;;;;;;;;;;;;;

(def routes
   {"GET /todos"               app-index
    "GET /todos/sse"           (use-sse-stream #'stream-todos)
    "POST /todos/sse"          (use-sse #'add-todo)
    "GET /todos/sse/edit/*"    (use-sse #'edit-todo)
    "PATCH /todos/sse/name/*"  (use-sse #'save-todo)
    "PATCH /todos/sse/done/*"  (use-sse #'toggle-todo)
    "DELETE /todos/sse/clear"  (use-sse #'clear-todo)
    "DELETE /todos/sse/*"      (use-sse #'delete-todo)})
