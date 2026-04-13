---
name: scittle
description: Debug and test browser-side ClojureScript running under Scittle, including DOM inspection, event handling, and browser REPL workflows. Use when working with `application/x-scittle`, `client.cljs`, browser nREPL/brepl sessions, or when validating live browser behavior from ClojureScript.
---

# Scittle

## Quick start

Scittle runs ClojureScript in the browser through `scittle.js` and a script tag like:

```html
<script src="client.cljs" type="application/x-scittle"></script>
```

For browser REPL work, use `brepl` against the browser port and follow the `brepl` skill first.

```bash
brepl -p 3339 <<'EOF'
js/location.href
EOF
```

## Use this skill for

- Inspecting live browser DOM from ClojureScript
- Testing HTMX or UI behavior through the actual rendered page
- Debugging event wiring, async timing, and browser state
- Working with Scittle source files such as `client.cljs`

## Workflow

1. Confirm you are in a Scittle app.
   Look for `scittle.js`, `application/x-scittle`, or `.cljs` browser scripts.
2. Connect to the browser REPL with `brepl -p <port>`.
3. Inspect the live page before changing code.
   Query `js/location.href`, `js/document.title`, `querySelector`, and `querySelectorAll`.
4. Prefer small stepwise probes over one large async script.
   Browser DOM and HTMX updates are timing-sensitive.
5. After each meaningful action, read the DOM again and compare actual state to expected state.

## Reliable patterns

### Read DOM state

```bash
brepl -p 3339 <<'EOF'
{:title js/document.title
 :count (.. js/document (querySelectorAll "#todo-list li") -length)}
EOF
```

### Trigger user-visible behavior

Prefer driving the real element in the page instead of calling internal functions.

```bash
brepl -p 3339 <<'EOF'
(let [input (.querySelector js/document "#todo-input")
      form (.closest input "form")]
  (set! (.-value input) "alpha")
  (.requestSubmit form))
EOF
```

### Debug events

Attach listeners to the actual page and log what fires.

```bash
brepl -p 3339 <<'EOF'
(.addEventListener js/document.body "htmx:beforeRequest"
  (fn [evt]
    (js/console.log "htmx beforeRequest" (.. evt -detail -pathInfo -requestPath))))
EOF
```

### Handle async timing

Use `js/setTimeout` or promise chains and then re-read DOM state.

## Rules

1. Load the `brepl` skill before using `brepl`.
2. Use heredoc for all `brepl` evaluations.
3. Test behavior through the live DOM, not only by fetching endpoints.
4. Prefer `querySelector` and `querySelectorAll` over assumptions about markup.
5. When a one-shot browser script gets flaky, switch to step-by-step probing.
6. For assertions, normalize rendered text because controls like delete buttons can add extra glyphs.

## Notes

- Synthetic events may not behave exactly like real user interaction for every library.
- Browser state can change after HTMX swaps, so stale element references are common.
- When checking text, inspect the current HTML first and derive selectors from the live page.

## Resources

- https://babashka.org/scittle/
- https://github.com/babashka/scittle
