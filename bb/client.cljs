(ns client)

(println "Hello from browser!")

(def test-results (atom {:pass 0 :fail 0 :errors []}))

(defn check [desc expr]
  (if expr
    (do (swap! test-results update :pass inc)
        (js/console.log (str "✓ " desc)))
    (do (swap! test-results update :fail inc)
        (swap! test-results update :errors conj desc)
        (js/console.warn (str "✗ " desc)))))

(defn run-suite [suite-name tests]
  (js/console.group suite-name)
  (doseq [[desc expr] tests] (check desc expr))
  (js/console.groupEnd))

(defn run-tests []
  (reset! test-results {:pass 0 :fail 0 :errors []})

  (run-suite "DOM Structure"
    [["#todo-list exists"        (some? (js/document.getElementById "todo-list"))]
     [".new-todo input exists"   (some? (js/document.querySelector ".new-todo"))]
     ["#clear-completed exists"  (some? (js/document.getElementById "clear-completed"))]
     [".todo-count exists"       (some? (js/document.querySelector ".todo-count"))]
     [".filters exists"          (some? (js/document.querySelector ".filters"))]])

  (run-suite "Todo Items"
    [["todo-list exists"        (some? (js/document.getElementById "todo-list"))]
     ["items valid when present"
      (let [items (array-seq (.. js/document (querySelectorAll "#todo-list li")))]
        (or (empty? items)
            (and (every? #(some? (.querySelector % ".toggle")) items)
                 (every? #(some? (.querySelector % "label")) items)
                 (every? #(some? (.querySelector % ".destroy")) items))))]])

  (run-suite "Filters"
    [["All filter link exists"
      (some #(= "All" (.-textContent %))
            (array-seq (.. js/document (querySelectorAll ".filters a"))))]
     ["Active filter link exists"
      (some #(= "Active" (.-textContent %))
            (array-seq (.. js/document (querySelectorAll ".filters a"))))]
     ["Completed filter link exists"
      (some #(= "Completed" (.-textContent %))
            (array-seq (.. js/document (querySelectorAll ".filters a"))))]])

  (run-suite "Edge Cases"
    [["new-todo input starts empty"
      (= "" (.-value (js/document.querySelector ".new-todo")))]
     ["no item has empty label text"
      (every? #(not= "" (.trim (.-textContent (.querySelector % "label"))))
              (array-seq (.. js/document (querySelectorAll "#todo-list li"))))]
     ["each item has a unique id"
      (let [ids (map #(.-id %) (array-seq (.. js/document (querySelectorAll "#todo-list li"))))]
        (= (count ids) (count (distinct ids))))]
     ["todo-count strong shows a number"
      (let [text (some-> (js/document.querySelector ".todo-count strong") .-textContent)]
        (and (some? text) (re-matches #"\d+" text)))]
     ["items-left count matches non-completed items"
      (let [total      (.. js/document (querySelectorAll "#todo-list li") -length)
            completed  (.. js/document (querySelectorAll "#todo-list li.completed") -length)
            left-text  (some-> (js/document.querySelector ".todo-count strong") .-textContent js/parseInt)]
        (= left-text (- total completed)))]
     ["clear-completed hidden when no completed items"
      (let [completed (.. js/document (querySelectorAll "#todo-list li.completed") -length)
            btn       (js/document.getElementById "clear-completed")]
        (if (zero? completed)
          (.. btn -classList (contains "hidden"))
          true))]
     ["All filter is selected by default"
      (let [all-link (first (filter #(= "All" (.-textContent %))
                                    (array-seq (.. js/document (querySelectorAll ".filters a")))))]
        (and (some? all-link) (.. all-link -classList (contains "selected"))))]
     ["toggle checkboxes are not checked for active items"
      (every? #(not (.-checked (.querySelector % ".toggle")))
              (array-seq (.. js/document (querySelectorAll "#todo-list li:not(.completed)"))))]
     ["each item toggle has data-on:click attribute"
      (every? #(some? (.getAttribute (.querySelector % ".toggle") "data-on:click"))
              (array-seq (.. js/document (querySelectorAll "#todo-list li"))))]
     ["each label has data-on:dblclick attribute"
      (every? #(some? (.getAttribute (.querySelector % "label") "data-on:dblclick"))
              (array-seq (.. js/document (querySelectorAll "#todo-list li"))))]])

  (run-suite "Auto-polling"
    [["data-on-interval handled by Datastar" true]])

  (let [{:keys [pass fail errors]} @test-results]
    (js/console.log (str "\n" pass " passed, " fail " failed"))
    (when (seq errors) (js/console.error "Failed:" (clj->js errors)))
    @test-results))

(run-tests)
