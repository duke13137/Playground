(ns todoapp ;; Datastar Todo App
  (:require
   [clojure.string :as str]
   [hiccup2.core :as h]
   [cheshire.core :as json]
   [selmer.parser :refer [render-file]]
   [starfederation.datastar.clojure.api :as d*]
   [starfederation.datastar.clojure.adapter.http-kit2 :as hk]))

#?(:bb  (do (require '[babashka.pods :as pods])
            (pods/load-pod 'huahaiy/datalevin "0.10.7")
            (require '[pod.huahaiy.datalevin :as d]))
   :clj (require '[datalevin.core :as d]))

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Datalevin
;;;;;;;;;;;;;;;;;;;;;;;;;;

(def schema
  {:todo/name {:db/valueType :db.type/string}
   :todo/name-key {:db/valueType :db.type/string
                   :db/unique :db.unique/value}
   :todo/done {:db/valueType :db.type/boolean}})

(def db-path (or (System/getenv "BB_TODOS_DB_PATH") "/tmp/bb-todos"))

(def conn (d/get-conn db-path schema))

(defn db []
  (d/db conn))

(declare get-all-todos)

(defn todo-ids []
  (d/q '[:find [?e ...] :where [?e :todo/name _]] (db)))

(defn pull-todo [id]
  (d/pull (db) [:db/id :todo/name :todo/done] id))

(defn ->todo
  "Convert Datalevin pull result to component-friendly map."
  [m]
  {:id (:db/id m) :name (:todo/name m) :done (boolean (:todo/done m))})

(defn normalize-todo-name [name]
  (some-> name str/trim not-empty))

(defn todo-name-key [name]
  (some-> name normalize-todo-name str/lower-case))

(defn find-duplicate-todo [name & {:keys [exclude-id]}]
  (when-let [candidate (todo-name-key name)]
    (some (fn [{:keys [id name] :as todo}]
            (when (and (not= id exclude-id)
                       (= candidate (todo-name-key name)))
              todo))
          (get-all-todos))))

(defn duplicate-name-error? [e]
  (= :transact/unique (:error (ex-data e))))

(defn transact-todo! [tx-data]
  (try
    (d/transact! conn tx-data)
    true
    (catch Exception e
      (if (duplicate-name-error? e)
        false
        (throw e)))))

(defn ensure-todo-name-keys! []
  (doseq [id (todo-ids)
          :let [todo (d/pull (db) [:db/id :todo/name :todo/name-key] id)
                name-key (todo-name-key (:todo/name todo))]
          :when (and name-key (not= name-key (:todo/name-key todo)))]
    (try
      (d/transact! conn [[:db/add id :todo/name-key name-key]])
      (catch Exception e
        (when-not (duplicate-name-error? e)
          (throw e))))))

(ensure-todo-name-keys!)

;;;;;;;;;;;;;;;;;;;;;;;;;;
;; CRUD
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn add-todo! [name]
  (if-let [name (normalize-todo-name name)]
    (transact-todo! [{:todo/name name
                      :todo/name-key (todo-name-key name)
                      :todo/done false}])
    false))

(defn toggle-todo! [id]
  (let [done (:todo/done (d/pull (db) [:todo/done] id))]
    (d/transact! conn [[:db/add id :todo/done (not done)]])))

(defn update-todo-name! [id name]
  (if-let [name (normalize-todo-name name)]
    (transact-todo! [[:db/add id :todo/name name]
                     [:db/add id :todo/name-key (todo-name-key name)]])
    false))

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

(defn flash-todo-script [id]
  (str "(() => { "
       "const el = document.getElementById('todo-" id "'); "
       "if (!el) return; "
       "el.classList.remove('duplicate-flash'); "
       "void el.offsetWidth; "
       "el.classList.add('duplicate-flash'); "
       "el.scrollIntoView({block: 'nearest', behavior: 'smooth'}); "
       "setTimeout(() => el.classList.remove('duplicate-flash'), 900); "
       "})()"))

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
    [:label {:data-on:dblclick
             (str "@get('/todos/sse/edit/" id "'); "
                  "(() => { let tries = 0; const focusEdit = () => { "
                  "const input = document.querySelector('#todo-" id " .edit'); "
                  "if (input) { input.focus(); input.select(); } "
                  "else if (tries < 10) { tries += 1; requestAnimationFrame(focusEdit); } "
                  "}; requestAnimationFrame(focusEdit); })()")}
     name]
    [:button.destroy
      {:data-on:click (str "@delete('/todos/sse/" id "')")}]]])

(defn todo-edit-form [id name]
  [:li {:id (str "todo-" id) :class "editing"}
   [:input.edit {:data-bind:edittext ""
                 :data-on:keydown "evt.key === 'Enter' && (evt.preventDefault(), evt.target.blur())"
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

(defn respond! [sse filter & {:keys [broadcast? signals script]}]
  (patch-all! sse filter)
  (when broadcast? (broadcast!))
  (when signals (patch-signals! sse signals))
  (when script (d*/execute-script! sse script))
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
    (let [created? (add-todo! todo)
          duplicate-id (:id (when-not created?
                              (find-duplicate-todo todo)))]
      (respond! sse filter
                :broadcast? created?
                :signals (when created? {:todo ""})
                :script (when duplicate-id (flash-todo-script duplicate-id))))))

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
    (let [saved? (update-todo-name! id edittext)
          duplicate-id (:id (when-not saved?
                              (find-duplicate-todo edittext :exclude-id id)))]
      (respond! sse filter
                :broadcast? saved?
                :signals (when saved? {:edittext ""})
                :script (when duplicate-id (flash-todo-script duplicate-id))))))

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
