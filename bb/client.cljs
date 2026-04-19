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

(defn qs [selector]
  (.querySelector js/document selector))

(defn qsa [selector]
  (array-seq (.. js/document (querySelectorAll selector))))

(defn todo-items []
  (qsa "#todo-list .todo-list li"))

(defn selected-filter []
  (qs ".filters a.selected"))

(defn visible-todo-count []
  (.. js/document (querySelectorAll "#todo-list .todo-list li") -length))

(defn completed-todo-count []
  (.. js/document (querySelectorAll "#todo-list .todo-list li.completed") -length))

(defn rect [selector]
  (some-> (qs selector) .getBoundingClientRect))

(defn within [n lo hi]
  (and (<= lo n) (<= n hi)))

(defn run-tests []
  (reset! test-results {:pass 0 :fail 0 :errors []})

  (run-suite "DOM Structure"
    [["#todo-list exists"        (some? (js/document.getElementById "todo-list"))]
     [".new-todo input exists"   (some? (qs ".new-todo"))]
     [".main exists"             (some? (qs "#todo-list .main"))]
     ["#toggle-all exists"       (some? (js/document.getElementById "toggle-all"))]
     [".todo-count exists"       (some? (qs ".todo-count"))]
     [".filters exists once"     (= 1 (.. js/document (querySelectorAll ".filters") -length))]
     ["add icon button removed"  (nil? (qs ".add-todo"))]])

  (run-suite "Todo Items"
    [["todo-list exists"        (some? (js/document.getElementById "todo-list"))]
     ["items valid when present"
      (let [items (todo-items)]
        (or (empty? items)
            (and (every? #(some? (.querySelector % ".toggle")) items)
                 (every? #(some? (.querySelector % "label")) items)
                 (every? #(some? (.querySelector % ".destroy")) items))))]])

  (run-suite "Filters"
    [["All filter link exists"
      (some #(= "All" (.-textContent %)) (qsa ".filters a"))]
     ["Active filter link exists"
      (some #(= "Active" (.-textContent %)) (qsa ".filters a"))]
     ["Completed filter link exists"
      (some #(= "Completed" (.-textContent %)) (qsa ".filters a"))]
     ["one filter is selected"
      (= 1 (.. js/document (querySelectorAll ".filters a.selected") -length))]
     ["selected filter matches hidden filter"
      (let [hidden-filter (some-> (qs "#todo-list-form input[name='filter']") .-value)
            selected-text (some-> (selected-filter) .-textContent)]
        (= selected-text
           (case hidden-filter
             "active" "Active"
             "completed" "Completed"
             "All")))]])

  (run-suite "Edge Cases"
    [["new-todo input starts empty"
      (= "" (.-value (qs ".new-todo")))]
     ["new-todo live search fetches todo list"
      (= "/todos/list" (.getAttribute (qs ".new-todo") "hx-get"))]
     ["new-todo live search waits for input changes"
      (= "input changed delay:500ms" (.getAttribute (qs ".new-todo") "hx-trigger"))]
     ["new-todo live search aborts on submit"
      (= "closest form:abort" (.getAttribute (qs ".new-todo") "hx-sync"))]
     ["new-todo does not send hx-vals"
      (nil? (.getAttribute (qs ".new-todo") "hx-vals"))]
     ["no item has empty label text"
      (every? #(not= "" (.trim (.-textContent (.querySelector % "label"))))
              (todo-items))]
     ["each item has a unique id"
      (let [ids (map #(.-id %) (todo-items))]
        (= (count ids) (count (distinct ids))))]
     ["todo-count strong shows a number"
      (let [text (some-> (qs ".todo-count strong") .-textContent)]
        (and (some? text) (re-matches #"\d+" text)))]
     ["items-left count matches non-completed items"
      (let [total      (visible-todo-count)
            completed  (completed-todo-count)
            left-text  (some-> (qs ".todo-count strong") .-textContent js/parseInt)]
        (= left-text (- total completed)))]
     ["clear-completed absent when no completed items"
      (let [completed (completed-todo-count)
            btn       (qs ".clear-completed")]
        (if (zero? completed)
          (nil? btn)
          (some? btn)))]
     ["toggle checkboxes are not checked for active items"
      (every? #(not (.-checked (.querySelector % ".toggle")))
              (qsa "#todo-list .todo-list li:not(.completed)"))]
     ["each item toggle has hx-patch"
      (every? #(some? (.getAttribute (.querySelector % ".toggle") "hx-patch"))
              (todo-items))]
     ["each label opens edit form on double click"
      (every? #(and (some? (.getAttribute (.querySelector % "label") "hx-get"))
                    (= "dblclick" (.getAttribute (.querySelector % "label") "hx-trigger")))
              (todo-items))]
     ["each destroy button has hx-delete"
      (every? #(some? (.getAttribute (.querySelector % ".destroy") "hx-delete"))
              (todo-items))]])

  (run-suite "TodoMVC Layout"
    [["todoapp card has TodoMVC width"
      (let [r (rect ".todoapp")]
        (and (some? r) (within (.-width r) 300 650)))]
     ["input row sits above list"
      (let [input-r (rect ".new-todo")
            main-r  (rect "#todo-list .main")]
        (and (some? input-r)
             (some? main-r)
             (<= (.-bottom input-r) (+ 2 (.-top main-r)))))]
     ["footer sits below main list"
      (let [main-r   (rect "#todo-list .main")
            footer-r (rect "#todo-list .footer")]
        (and (some? main-r)
             (some? footer-r)
             (<= (.-bottom main-r) (+ 2 (.-top footer-r)))))]
     ["filters render inside todo-list footer"
      (some? (qs "#todo-list .footer .filters"))]
     ["toggle-all label is positioned in input row"
      (let [label-r (rect "#todo-list .toggle-all + label")
            input-r (rect ".new-todo")]
        (and (some? label-r)
             (some? input-r)
             (<= (js/Math.abs (- (.-top label-r) (.-top input-r))) 6)))]])

  (let [{:keys [pass fail errors]} @test-results]
    (js/console.log (str "\n" pass " passed, " fail " failed"))
    (when (seq errors) (js/console.error "Failed:" (clj->js errors)))
    @test-results))

(js/console.log "hello from nvim")
