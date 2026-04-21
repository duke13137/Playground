#!/usr/bin/env bash
set -euo pipefail

TODOAPP_URL="${TODOAPP_URL:-http://localhost:3000/todos}"
PREFIX="codex-spel-$(date +%s%N)"

cleanup() {
  brepl -p 3333 <<EOF >/dev/null
(require 'todoapp :reload)
(require '[clojure.string :as str])
(doseq [{:keys [id name]} (todoapp/get-all-todos)
        :when (str/starts-with? name "$PREFIX")]
  (todoapp/remove-todo! id))
EOF
}

trap cleanup EXIT

timeout 90s spel eval-sci "
(do
  (def url \"$TODOAPP_URL\")
  (def prefix \"$PREFIX\")
  (def first-name (str prefix \"-sleep\"))
  (def second-name (str prefix \"-walk\"))
  (def renamed-name (str second-name \"-renamed\"))
  (def duplicate-caret-pos 7)

  (defn fail! [message data]
    (throw (ex-info message data)))

  (defn js [expr]
    (spel/evaluate expr))

  (defn assert-js [message expr]
    (when-not (js expr)
      (fail! message {:expr expr :state (js \"({activeId: document.activeElement?.id, activeClass: document.activeElement?.className, activeValue: document.activeElement?.value, labels: Array.from(document.querySelectorAll('.todo-list label')).map(el => el.textContent)})\")})))

  (defn label-exists-expr [text]
    (str \"Array.from(document.querySelectorAll('.todo-list label')).some(el => el.textContent === '\" text \"')\"))

  (defn add-todo! [title]
    (spel/fill \"#todo-input\" title)
    (spel/press \"#todo-input\" \"Enter\")
    (spel/wait-for-function (label-exists-expr title)))

  (spel/navigate url)
  (spel/wait-for-load-state :load)
  (assert-js \"htmx did not load\" \"!!window.htmx\")
  (assert-js \"todo input should start focused\" \"document.activeElement?.id === 'todo-input'\")

  (add-todo! first-name)
  (add-todo! second-name)

  (spel/dblclick (str \"text=\" second-name))
  (spel/wait-for-selector \".todo-list li.editing input.edit\")
  (assert-js \"double-click should focus inline edit input\" \"document.activeElement?.className === 'edit'\")

  (spel/fill \".todo-list li.editing input.edit\" renamed-name)
  (spel/press \".todo-list li.editing input.edit\" \"Enter\")
  (spel/wait-for-function (str \"document.querySelectorAll('.todo-list li.editing').length === 0 && \" (label-exists-expr renamed-name) \" && document.activeElement?.id === 'todo-input'\"))

  (spel/dblclick (str \"text=\" renamed-name))
  (spel/wait-for-selector \".todo-list li.editing input.edit\")
  (spel/fill \".todo-list li.editing input.edit\" first-name)
  (assert-js \"inline edit should use outerMorph swap\" \"document.querySelector('.todo-list li.editing form')?.getAttribute('hx-swap') === 'outerMorph'\")
  (assert-js \"inline edit should have stable id for morph preservation\" \"!!document.querySelector('.todo-list li.editing input.edit[id^=todo-edit-]')\")
  (js (str \"(() => { const el = document.querySelector('.todo-list li.editing input.edit'); el.setSelectionRange(\" duplicate-caret-pos \", \" duplicate-caret-pos \"); return true })()\"))
  (spel/press \".todo-list li.editing input.edit\" \"Enter\")
  (spel/wait-for-function (str \"document.querySelectorAll('.todo-list li.editing').length === 1 && document.querySelectorAll('.todo-list li.duplicate-flash').length === 1 && document.activeElement?.className === 'edit' && document.activeElement?.selectionStart === \" duplicate-caret-pos))
  (assert-js \"duplicate rejection should preserve attempted duplicate text\" (str \"document.querySelector('.todo-list li.editing input.edit')?.value === '\" first-name \"'\"))
  (assert-js \"duplicate rejection should preserve cursor position\" (str \"document.activeElement?.selectionStart === \" duplicate-caret-pos \" && document.activeElement?.selectionEnd === \" duplicate-caret-pos))
  (assert-js \"duplicate rejection should not focus add input\" \"document.activeElement?.id !== 'todo-input'\")

  (println \"todoapp spel regression passed\" {:prefix prefix
	                                               :successful-edit-focus \"#todo-input\"
	                                               :duplicate-edit-focus \".todo-list li.editing input.edit\"
	                                               :duplicate-caret-pos duplicate-caret-pos}))"
