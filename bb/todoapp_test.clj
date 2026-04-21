(ns todoapp-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [todoapp :as sut]))

(defn cleanup-test-todos! [prefix]
  (doseq [{:keys [id name]} (sut/get-all-todos)
          :when (str/starts-with? name prefix)]
    (sut/remove-todo! id)))

(deftest test-add-todo-creates
  (testing "Adding todo increments list"
    (let [prefix (str "test-add-" (random-uuid))
          name (str prefix "-todo")
          initial-count (count (sut/get-all-todos))]
      (try
        (sut/add-todo! name)
        (is (= (inc initial-count) (count (sut/get-all-todos))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-filtered-todos-by-completion
  (testing "Filter returns correct subset"
    (let [prefix (str "test-filter-" (random-uuid))]
      (sut/add-todo! (str prefix "-active"))
      (sut/add-todo! (str prefix "-completed"))
      (let [all-todos (sut/get-all-todos)
            completed (first (filter (fn [t] (= (str prefix "-completed") (:name t))) all-todos))]
        (when completed
          (sut/toggle-todo! (:id completed))))
      (is (some? (sut/filtered-todos "active")))
      (cleanup-test-todos! prefix))))

(deftest test-filtered-todos-by-search-query
  (testing "Search query narrows todos by name"
    (let [prefix (str "test-search-" (random-uuid))
          alpha (str prefix "-Alpha")
          beta (str prefix "-Beta")]
      (try
        (sut/add-todo! alpha)
        (sut/add-todo! beta)
        (is (= [alpha]
               (->> (sut/filtered-todos "all" " alpha ")
                    (map :name)
                    (filter #(str/starts-with? % prefix)))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-todo-list-section-contains-footer
  (testing "Rendered section includes list-state container and footer"
    (let [markup (sut/html (sut/todo-list-section [] "all" {}))]
      (is (str/includes? markup "todo-list-form"))
      (is (str/includes? markup "<div id=\"todo-list-form\""))
      (is (str/includes? markup "name=\"filter\""))
      (is (str/includes? markup "class=\"main\""))
      (is (str/includes? markup "id=\"toggle-all\""))
      (is (str/includes? markup "footer"))
      (is (str/includes? markup "todo-count"))
      (is (str/includes? markup "class=\"filters\""))
      (is (str/includes? markup "class=\"selected\"")))))

(deftest test-todo-add-form-uses-htmx-submit
  (testing "Add form submits directly with htmx"
    (let [markup (sut/html (sut/todo-add-form))]
      (is (str/includes? markup "hx-post=\"/todos\""))
      (is (str/includes? markup "hx-target=\"#add-form\""))
      (is (str/includes? markup "hx-include=\"#todo-list-form input[name=&apos;filter&apos;]\""))
      (is (str/includes? markup "hx-get=\"/todos/list\""))
      (is (str/includes? markup "hx-trigger=\"input changed delay:500ms\""))
      (is (str/includes? markup "hx-target=\"#todo-list\""))
      (is (str/includes? markup "hx-swap=\"outerMorph\""))
      (is (str/includes? markup "hx-sync=\"closest form:abort\""))
      (is (str/includes? markup "name=\"title\""))
      (is (not (str/includes? markup "class=\"add-todo\"")))
      (is (str/includes? markup "required")))))

(deftest test-add-handler-clears-form-and-swaps-list-oob
  (testing "Add response clears the input form and updates the list out of band"
    (let [prefix (str "test-add-handler-" (random-uuid))
          name (str prefix "-todo")]
      (try
        (let [response (sut/add-todo-handler {:params {"title" name
                                                       "filter" "all"}})
              body (:body response)]
          (is (= 200 (:status response)))
          (is (str/includes? body "id=\"add-form\""))
          (is (str/includes? body "hx-swap-oob=\"outerMorph\""))
          (is (str/includes? body name)))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-edit-form-has-autofocus
  (testing "Edit form has autofocus attribute"
    (let [markup (sut/html (sut/todo-edit-form 1 "test"))]
      (is (str/includes? markup "autofocus"))
      (is (str/includes? markup "hx-put"))
      (is (str/includes? markup "hx-swap=\"outerMorph\""))
      (is (str/includes? markup "name=\"edit-title\""))
      (is (str/includes? markup "id=\"todo-edit-1\""))
      (is (str/includes? markup "hx-include=\"#todo-list-form, #todo-input:not(:invalid)\""))
      (is (str/includes? markup "todo-1")))))

(deftest test-list-mutations-include-search-input
  (testing "Mutating controls include the live search input"
    (let [item-markup (sut/html (sut/todo-item {:id 1 :name "test" :done false}))
          list-markup (sut/html (sut/todo-list-section
                                  [{:id 1 :name "test" :done true}]
                                  "all"
                                  {}))]
      (is (str/includes? item-markup "hx-include=\"#todo-list-form, #todo-input:not(:invalid)\""))
      (is (str/includes? list-markup "hx-include=\"#todo-list-form, #todo-input:not(:invalid)\"")))))

(deftest test-toggle-preserves-search-query
  (testing "Toggle response remains narrowed by the active search"
    (let [prefix (str "test-toggle-search-" (random-uuid))
          alpha (str prefix "-alpha")
          beta (str prefix "-beta")]
      (try
        (sut/add-todo! alpha)
        (sut/add-todo! beta)
        (let [alpha-id (:id (first (filter #(= alpha (:name %)) (sut/get-all-todos))))
              body (:body (sut/toggle-todo-handler
                           {:path-params [(str alpha-id)]
                            :params {"filter" "all"
                                     "title" alpha}}))]
          (is (str/includes? body alpha))
          (is (not (str/includes? body beta))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-delete-preserves-search-query
  (testing "Delete response remains narrowed by the active search"
    (let [prefix (str "test-delete-search-" (random-uuid))
          alpha (str prefix "-alpha")
          beta (str prefix "-beta")]
      (try
        (sut/add-todo! alpha)
        (sut/add-todo! beta)
        (let [alpha-id (:id (first (filter #(= alpha (:name %)) (sut/get-all-todos))))
              body (:body (sut/delete-todo-handler
                           {:path-params [(str alpha-id)]
                            :params {"filter" "all"
                                     "title" alpha}}))]
          (is (not (str/includes? body alpha)))
          (is (not (str/includes? body beta))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-save-preserves-search-query
  (testing "Save response uses edit-title for the edit and title for search"
    (let [prefix (str "test-save-search-" (random-uuid))
          alpha (str prefix "-alpha")
          renamed (str prefix "-alpha-renamed")
          beta (str prefix "-beta")]
      (try
        (sut/add-todo! alpha)
        (sut/add-todo! beta)
        (let [alpha-id (:id (first (filter #(= alpha (:name %)) (sut/get-all-todos))))
              body (:body (sut/save-todo-handler
                           {:path-params [(str alpha-id)]
                            :params {"filter" "all"
                                     "title" "alpha"
                                     "edit-title" renamed}}))]
          (is (str/includes? body renamed))
          (is (str/includes? body sut/focus-todo-input-script))
          (is (not (str/includes? body beta))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-save-duplicate-keeps-inline-edit-focused
  (testing "Duplicate edit rejection keeps the edited item in edit mode"
    (let [prefix (str "test-save-dup-focus-" (random-uuid))
          sleep-name (str prefix "-sleep")
          walk-name (str prefix "-walk")
          duplicate-input (str " " (str/upper-case sleep-name) " ")]
      (try
        (sut/add-todo! sleep-name)
        (sut/add-todo! walk-name)
        (let [todos (filter #(str/starts-with? (:name %) prefix) (sut/get-all-todos))
              sleep-id (:id (first (filter #(= sleep-name (:name %)) todos)))
              walk-id (:id (first (filter #(= walk-name (:name %)) todos)))
              body (:body (sut/save-todo-handler
                           {:path-params [(str walk-id)]
                            :params {"filter" "all"
                                     "edit-title" duplicate-input}}))]
          (is (str/includes? body (str "id=\"todo-" walk-id "\"")))
          (is (str/includes? body "class=\"editing\""))
          (is (str/includes? body "name=\"edit-title\""))
          (is (str/includes? body (str "value=\"" duplicate-input "\"")))
          (is (str/includes? body (str "id=\"todo-" sleep-id "\"")))
          (is (str/includes? body "duplicate-flash"))
          (is (str/includes? body (sut/focus-edit-input-script walk-id)))
          (is (not (str/includes? body sut/focus-todo-input-script))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-clear-completed-preserves-search-query
  (testing "Clear completed response remains narrowed by the active search"
    (let [prefix (str "test-clear-search-" (random-uuid))
          alpha (str prefix "-alpha")
          beta (str prefix "-beta")]
      (try
        (sut/add-todo! alpha)
        (sut/add-todo! beta)
        (let [beta-id (:id (first (filter #(= beta (:name %)) (sut/get-all-todos))))]
          (sut/toggle-todo! beta-id))
        (let [body (:body (sut/clear-todo-handler
                           {:params {"filter" "all"
                                     "title" alpha}}))]
          (is (str/includes? body alpha))
          (is (not (str/includes? body beta))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-duplicate-item-has-flash-class
  (testing "Highlighted duplicate item has flash class"
    (let [markup (sut/html (sut/todo-item {:id 1 :name "test" :done false} :highlight-id 1))]
      (is (str/includes? markup "duplicate-flash")))))

(deftest test-add-todo-rejects-duplicate-name
  (testing "Add rejects duplicate names after normalization"
    (let [prefix (str "test-dup-add-" (random-uuid))
          name (str prefix "-sleep")]
      (try
        (is (true? (sut/add-todo! name)))
        (is (false? (sut/add-todo! (str "  " (str/upper-case name) "  "))))
        (is (= [name]
               (->> (sut/get-all-todos)
                    (map :name)
                    (filter #(str/starts-with? % prefix)))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-update-todo-name-rejects-duplicate-name
  (testing "Edit rejects renaming a todo to another todo's name"
    (let [prefix (str "test-dup-edit-" (random-uuid))
          sleep-name (str prefix "-sleep")
          walk-name (str prefix "-walk")]
      (try
        (sut/add-todo! sleep-name)
        (sut/add-todo! walk-name)
        (let [todos (filter #(str/starts-with? (:name %) prefix) (sut/get-all-todos))
              sleep-id (:id (first (filter #(= sleep-name (:name %)) todos)))
              walk-id (:id (first (filter #(= walk-name (:name %)) todos)))]
          (is (true? (sut/update-todo-name! sleep-id sleep-name)))
          (is (false? (sut/update-todo-name! walk-id (str " " (str/upper-case sleep-name) " "))))
          (is (= [sleep-name walk-name]
                 (sort (map :name (filter #(str/starts-with? (:name %) prefix)
                                          (sut/get-all-todos)))))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-find-duplicate-todo-matches-normalized-name
  (testing "Duplicate lookup finds the existing todo to flash"
    (let [prefix (str "test-dup-find-" (random-uuid))
          name (str prefix "-sleep")]
      (try
        (sut/add-todo! name)
        (is (= name
               (:name (sut/find-duplicate-todo (str "  " (str/upper-case name) "  ")))))
        (finally
          (cleanup-test-todos! prefix))))))
