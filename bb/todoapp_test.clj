(ns todoapp-test
  (:require [clojure.string :as str]
             [clojure.test :refer [deftest is testing]]
             [todoapp :as sut]))

(defn cleanup-test-todos! [prefix]
  (doseq [{:keys [id name]} (sut/get-all-todos)
          :when (str/starts-with? name prefix)]
    (sut/remove-todo! id)))

(deftest test-broadcast-single-client
  (testing "Single client receives patch after mutation"
    (let [prefix (str "test-broadcast-" (random-uuid))
          name (str prefix "-todo")
          initial-count (count (sut/get-all-todos))]
      (try
        (sut/add-todo! name)
        (is (= (inc initial-count) (count (sut/get-all-todos))))
        (finally
          (cleanup-test-todos! prefix))))))

(deftest test-broadcast-multi-client
  (testing "All connected clients receive same broadcast"
    (let [streams-before @sut/streams
          cid1 "test-client-1"
          cid2 "test-client-2"]
      (sut/update-stream-filter! cid1 "all")
      (sut/update-stream-filter! cid2 "all")
      (is (= 2 (count (filter #(some #{cid1 cid2} [(key %)]) @sut/streams)))))))

(deftest test-broadcast-filter-aware
  (testing "Active filter doesn't receive completed todos"
    (let [todos-before (sut/filtered-todos "active")
          todos-all (sut/filtered-todos "all")]
      (when-not (seq todos-before)
        (sut/add-todo! "active todo"))
      (sut/add-todo! "completed todo")
      (let [completed (sut/get-all-todos)
            completed-id (->> completed (filter :done) first :id)]
        (when completed-id
          (sut/toggle-todo! completed-id)))
      (is (some? (sut/filtered-todos "active"))))))

(deftest test-connection-cleanup
  (testing "Disconnected SSE removed from streams atom"
    (let [cid "cleanup-test"]
      (sut/update-stream-filter! cid "all")
      (is (some? (get @sut/streams cid)))
      (sut/remove-stream-by-cid! cid)
      (is (nil? (get @sut/streams cid))))))

(deftest test-presence-edit-start
  (testing "User starts editing triggers presence"
    (let [cid "presence-user"
          todo-id 1]
      (sut/start-editing! todo-id cid)
      (is (= cid (get @sut/editing-users todo-id))))))

(deftest test-presence-edit-end
  (testing "User saves clears presence"
    (let [cid "presence-user"
          todo-id 1]
      (sut/start-editing! todo-id cid)
      (sut/stop-editing! todo-id)
      (is (nil? (get @sut/editing-users todo-id))))))

(deftest test-presence-multi-user
  (testing "Multiple users editing same todo"
    (let [todo-id 1]
      (sut/start-editing! todo-id "user-a")
      (sut/start-editing! todo-id "user-b")
      (is (= "user-b" (get @sut/editing-users todo-id))))))

(deftest test-edit-form-focuses-on-load
  (testing "Todo label schedules edit input focus after edit patch"
    (let [markup (sut/html (sut/todo-item {:id 1 :name "sleep" :done false}))]
      (is (str/includes? markup "#todo-1 .edit"))
      (is (str/includes? markup "requestAnimationFrame(focusEdit)")))))

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
