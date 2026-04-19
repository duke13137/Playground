(ns todoapp
  (:require
   [clojure.string :as str]
   [hiccup2.core :as h]
   [selmer.parser :refer [render-file]])
  (:import
   [java.lang Exception]))

#?(:bb  (do (babashka.pods/load-pod 'huahaiy/datalevin "0.10.7")
            (require '[pod.huahaiy.datalevin :as d]))
   :clj (require '[datalevin.core :as d]))

(def schema
  {:todo/name {:db/valueType :db.type/string}
   :todo/name-key {:db/valueType :db.type/string
                   :db/unique :db.unique/value}
   :todo/done {:db/valueType :db.type/boolean}})

(def db-path (or (System/getenv "BB_TODOS_DB_PATH") "/tmp/bb-todos"))
(def conn (d/create-conn db-path schema {:wal? false}))
(defn db [] (d/db conn))

(declare get-all-todos)

(defn todo-ids []
  (d/q '[:find [?e ...] :where [?e :todo/name _]] (db)))

(defn pull-todo [id]
  (d/pull (db) [:db/id :todo/name :todo/done] id))

(defn ->todo
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

(defn add-todo! [name]
  (if-let [name (normalize-todo-name name)]
    (if (find-duplicate-todo name)
      false
      (transact-todo! [{:todo/name name
                        :todo/name-key (todo-name-key name)
                        :todo/done false}]))
    false))

(defn toggle-todo! [id]
  (let [done (:todo/done (d/pull (db) [:todo/done] id))]
    (d/transact! conn [[:db/add id :todo/done (not done)]])))

(defn update-todo-name! [id name]
  (if-let [name (normalize-todo-name name)]
    (if (find-duplicate-todo name :exclude-id id)
      false
      (transact-todo! [[:db/add id :todo/name name]
                       [:db/add id :todo/name-key (todo-name-key name)]]))
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

(defn get-all-todos []
  (->> (todo-ids)
       (map #(->todo (pull-todo %)))
       (sort-by :id)))

(defn todo-matches-query? [query {:keys [name]}]
  (if-let [query (todo-name-key query)]
    (str/includes? (todo-name-key name) query)
    true))

(defn filtered-todos
  ([filter-name]
   (filtered-todos filter-name nil))
  ([filter-name query]
   (let [all (get-all-todos)]
     (->> (case filter-name
            "active"    (remove :done all)
            "completed" (filter :done all)
            all)
          (filter #(todo-matches-query? query %))))))

(defn get-todo [id]
  (->todo (pull-todo id)))

(defn get-items-left []
  (count (remove :done (get-all-todos))))

(defn todos-completed []
  (count (filter :done (get-all-todos))))

(defn html [hiccup]
  (str (h/html hiccup)))

(defn get-param [req k]
  (let [v (get (:params req) k)]
    (if (sequential? v) (first v) v)))

(defn get-id [req]
  (parse-long (get-in req [:path-params 0])))

(def list-state-include "#todo-list-form, #todo-input")

(defn get-filter-name [req]
  (or (get-param req "filter") "all"))

(defn get-search-query [req]
  (get-param req "title"))

(defn todo-item [{:keys [id name done]} & {:keys [highlight-id]}]
  [:li {:id (str "todo-" id)
        :class (cond-> (when done "completed")
                (= id highlight-id) (str " duplicate-flash"))}
   [:div.view
    [:input.toggle {:type "checkbox"
                    :checked done
                    :hx-patch (str "/todos/" id)
                    :hx-include list-state-include
                    :hx-target "#todo-list"
                    :hx-swap "outerHTML"}]
    [:label {:hx-get (str "/todos/" id "/edit")
             :hx-trigger "dblclick"
             :hx-target (str "#todo-" id)
             :hx-swap "outerHTML"}
     name]
    [:button.destroy
      {:hx-delete (str "/todos/" id)
       :hx-include list-state-include
       :hx-target "#todo-list"
       :hx-swap "outerHTML"}]]])

(defn todo-edit-form [id name]
  [:li {:id (str "todo-" id) :class "editing"}
   [:form {:hx-put (str "/todos/" id)
           :hx-include list-state-include
           :hx-target "#todo-list"
           :hx-swap "outerHTML"}
    [:input.edit {:type "text"
                  :name "edit-title"
                  :value name
                  :autofocus true
                  :required true}]]])

(defn todo-add-form []
  [:form {:id "add-form"
          :hx-post "/todos"
          :hx-target "#add-form"
          :hx-swap "outerHTML"
          :hx-include "#todo-list-form input[name='filter']"}
   [:input#todo-input.new-todo {:type "text"
                                :aria-label "New todo"
                                :name "title"
                                :placeholder "What needs to be done?"
                                :autocomplete "off"
                                :required true
                                :autofocus true
                                :hx-get "/todos/list"
                                :hx-trigger "input changed delay:500ms"
                                :hx-include "#todo-list-form input[name='filter']"
                                :hx-target "#todo-list"
                                :hx-swap "outerHTML"
                                :hx-sync "closest form:abort"}]])

(defn todo-count-label [n]
  (str (if (= 1 n) "item" "items") " left"))

(defn filter-link [filter-name label current-filter]
  [:li
   [:a (cond-> {:href "#"
                :hx-get (str "/todos/list?filter=" filter-name)
                :hx-include "#todo-input"
                :hx-target "#todo-list"
                :hx-swap "outerHTML"}
         (= filter-name current-filter) (assoc :class "selected"))
    label]])

(defn todo-list-section [todos filter-name {:keys [highlight-id oob?]}]
  [:div (cond-> {:id "todo-list"}
          oob? (assoc :hx-swap-oob "outerHTML"))
   [:form {:id "todo-list-form"}
    [:input {:type "hidden" :name "filter" :value filter-name}]
    [:section.main
     [:input#toggle-all.toggle-all {:type "checkbox"
                                    :checked (and (seq todos)
                                                  (every? :done todos))}]
     [:label {:for "toggle-all"} "Mark all as complete"]
     [:ul.todo-list
      (map #(todo-item % :highlight-id highlight-id) todos)]]
    [:footer.footer
     [:span.todo-count
      [:strong (get-items-left)] " " (todo-count-label (get-items-left))]
     [:ul.filters
      (filter-link "all" "All" filter-name)
      (filter-link "active" "Active" filter-name)
      (filter-link "completed" "Completed" filter-name)]
     (when (pos? (todos-completed))
       [:button.clear-completed
        {:hx-post "/todos/clear"
         :hx-include list-state-include
         :hx-target "#todo-list"
         :hx-swap "outerHTML"}
        "Clear completed"])]]])

(defn list-todos [req]
  (let [filter-name (get-filter-name req)
        query (get-search-query req)
        highlight-id (get-param req "highlight-id")
        todos (filtered-todos filter-name query)]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-list-section todos filter-name {:highlight-id highlight-id}))}))

(defn add-todo-handler [req]
  (let [title (get-param req "title")
        filter-name (get-filter-name req)
        created? (add-todo! title)
        highlight-id (:id (when-not created? (find-duplicate-todo title)))]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (str (html (todo-add-form))
                (html (todo-list-section (filtered-todos filter-name)
                                         filter-name
                                         {:highlight-id highlight-id
                                          :oob? true})))}))

(defn toggle-todo-handler [req]
  (let [id (get-id req)
        filter-name (get-filter-name req)
        query (get-search-query req)]
    (toggle-todo! id)
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-list-section (filtered-todos filter-name query)
                                    filter-name
                                    {}))}))

(defn delete-todo-handler [req]
  (let [id (get-id req)
        filter-name (get-filter-name req)
        query (get-search-query req)]
    (remove-todo! id)
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-list-section (filtered-todos filter-name query)
                                    filter-name
                                    {}))}))

(defn edit-todo-handler [req]
  (let [id (get-id req)
        todo (get-todo id)]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-edit-form id (:name todo)))}))

(defn save-todo-handler [req]
  (let [id (get-id req)
        title (or (get-param req "edit-title")
                  (get-param req "title"))
        filter-name (get-filter-name req)
        query (get-search-query req)
        saved? (update-todo-name! id title)
        highlight-id (:id (when-not saved? (find-duplicate-todo title :exclude-id id)))]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-list-section (filtered-todos filter-name query)
                                    filter-name
                                    {:highlight-id highlight-id}))}))

(defn clear-todo-handler [req]
  (let [filter-name (get-filter-name req)
        query (get-search-query req)]
    (remove-all-completed!)
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (html (todo-list-section (filtered-todos filter-name query)
                                    filter-name
                                    {}))}))

(defn app-index [_req]
  {:status 200
   :body (render-file "todo.html" {:initial-list (html (todo-list-section (get-all-todos) "all" {}))})})

(def routes
  {"GET /todos"         app-index
   "GET /todos/list"    list-todos
   "POST /todos"        add-todo-handler
   "PATCH /todos/*"     toggle-todo-handler
   "DELETE /todos/*"    delete-todo-handler
   "GET /todos/*/edit"  edit-todo-handler
   "PUT /todos/*"       save-todo-handler
   "POST /todos/clear"  clear-todo-handler})
