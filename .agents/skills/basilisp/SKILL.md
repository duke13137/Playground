---
name: basilisp
description: Basilisp REPL work — probing Python package APIs and debugging program state from .lpy code via brepl. Use when the agent needs to inspect importable Python modules/classes/functions, probe runtime values in a running Basilisp nREPL, or debug Basilisp/Python interop.
---

# Basilisp

## Core Model

Clojure-shaped syntax on the Python VM: imports, packaging, host interop, async, exceptions, regexes, deployment, and runtime resolution follow Python rules.

## Runbook

1. Inspect the runtime shape before probing.
   Check `pyproject.toml`, `basilisp.edn`, `.lpy` files, source roots, test roots, `.nrepl-port`, Python entrypoints that call `basilisp.main.init()` or `basilisp.main.bootstrap()`, and the Python package/module/class/function under inspection.
   Completion criterion: project commands, source roots, test roots, nREPL availability, and target Python API names are known.

2. Probe through the running Basilisp/Python process.
   Import target Python modules/classes in Basilisp, require REPL/reflect helpers, inspect signatures/docs/source/attributes. One heredoc: setup, construction, introspection, and the failing or confirming call together.
   Completion criterion: callable shape, argument names, and return type are confirmed in the live process — not inferred from docs or source.

3. Evaluate only through `brepl`.
   Load and follow `$brepl` before any `brepl` use. Use quoted heredocs:

   ```bash
   brepl <<'EOF'
   (+ 1 2 3)
   EOF
   ```

   Use `brepl -p <port>` when `.nrepl-port` is absent or the target server uses a non-discoverable port. Do not use `basilisp run -c`, `basilisp run <file>`, or similar CLI execution as an ad hoc REPL substitute.
   Completion criterion: focused forms have been evaluated in a known namespace/session, with setup and assertions in the same heredoc.

4. Validate changed or diagnosed behavior.
   Reload changed namespaces through `brepl` with `require` and `:reload` or `:reload-all`, then run the project's normal test command when available. A Basilisp test runner is valid for tests, but not as a substitute for focused REPL probing.
   Completion criterion: changed snippets load in `brepl`, relevant tests or smoke checks have run, and skipped validation is reported.

## API Exploration

Use Basilisp as a Python-aware probe before guessing Python package APIs — one heredoc per session.

```bash
brepl <<'EOF'
(require '[basilisp.repl :refer [doc source print-doc print-source]])
(require '[basilisp.reflect :refer [reflect]])
(import inspect)
(import [target.package :as pkg])

(print-doc pkg/some-member)
(println (inspect/signature pkg/some-member))
(-> (reflect pkg/SomeClass)
    (select-keys [:name :methods :properties :bases]))
EOF
```

- Prefer package/module aliases over `:refer` while exploring; referred Python names can lose to existing Basilisp names during symbol resolution.
- Use `print-doc`, `source`, `inspect/signature`, `python/dir`, `python/getattr`, and `basilisp.reflect/reflect` to discover callable shape before writing wrappers.
- For runtime member names, dunder methods, or dotted attributes that do not fit Basilisp symbol syntax, use `(python/getattr obj name)`.
- When a probe returns Python dicts/lists/tuples/sets, convert once at the boundary with `py->lisp` if Basilisp collection operations will clarify the result.

## Program-State Debugging

- Probe state in the same nREPL process that has the bug when possible; reloads, registries, singletons, and already-instantiated objects can diverge from a fresh process.
- Use `ns-publics`, `ns-resolve`, `var`, `deref`, `meta`, and direct Var calls to inspect Basilisp namespace state.
- Use `python/type`, `python/id`, `(.-attr obj)`, `python/getattr`, and `reflect` for Python object state.
- Use `ex-message`, `ex-data`, `ex-cause`, and `basilisp.stacktrace` when exceptions are wrapped through `ex-info` or Python exceptions.
- Treat namespace reloads as partial updates. Reloading redefs current Vars but does not remove deleted Vars, rebind already captured function/object references, or update already-instantiated `deftype`/`defrecord` objects.
- If stale behavior appears, reload the namespace, recreate long-lived objects, avoid old `def` captures, and restart the nREPL process when reload state becomes ambiguous.
- Treat runtime Var mutation carefully. With direct linking, use `^:dynamic` or `^:redef` when runtime redefinition must be observed.

## Python Interop

### Imports

| Task | Pattern | Example |
|---|---|---|
| Import module | `(import module)` | `(import os)` |
| Import alias | `(import [module :as alias])` | `(import [os.path :as path])` |
| Import names | `(import [module :refer [name1 name2]])` | `(import [math :refer [sqrt pi]])` |
| Namespace import | `(:import [os] [json])` | `(ns app.core (:import [os] [json]))` |

Namespaces are Python modules. Prefer `:import` in `ns` for Python modules/classes used by a file.

### Calls And Members

- **IMPORTANT** Reference Python top-level module members as `module/member`. For members defined on a class, treat the class name as part of the qualified namespace and replace only the final `.` with `/`: `(import src.boo)` then `src.boo/top-level-fn`, `src.boo.BooClass/class-var`, and `(src.boo.BooClass/class-method ...)`.
- Do not call dotted class names as bare symbols. `(datetime.datetime 2026 7 3)` fails because bare Basilisp symbols may not contain `.`, and `(datetime/datetime.now)` fails for the same reason. For constructors, import the class name and call it directly: `(import [pathlib :refer [Path]])` then `(Path "/tmp/x")`. For class members, keep the full dotted class path before `/`: `(datetime.datetime/now)`, `(pathlib.Path/home)`.
- `:refer` imports make a class callable as a local symbol, but they do not make class members slash-resolvable. After `(import [pathlib :refer [Path]])`, `(Path "/tmp/x")` works, but `Path/home` does not; use `(pathlib.Path/home)` or `(python/getattr Path "home")`.
- Prefer `(.method obj ...)` for known methods on ordinary Python objects.
- Use `(.-attr obj)` for known attributes. In `brepl` heredocs, avoid `(. obj attr)` when a bare string return can confuse wrappers.
- Use `(python/getattr obj name)` when the member name is runtime data or when the exact Python attribute name would be changed by Basilisp symbol normalization. Examples: `(.-attr-name obj)` looks for `attr_name`, `(.-class obj)` looks for `class_`, and `(.call-me obj)` looks for `call_me`; use `(python/getattr obj "attr-name")`, `(python/getattr obj "class")`, or `((python/getattr obj "call-me") ...)` for exact names.
- Unknown module members such as `math/nope` are rejected during Basilisp analysis, while unknown members on a resolved Python class such as `datetime.datetime/nope` raise Python `AttributeError`. If the member may or may not exist, probe with `python/hasattr`, `python/getattr`, `python/dir`, or `basilisp.reflect/reflect` instead of writing a static qualified symbol first.
- Python classes are called directly; do not use `Classname/new` or Java constructor syntax.
- Prefer `python.type/fn` for builtin type methods such as `python.str/split`, `python.int/from-bytes`, `python.list/append`, and `python.dict/get`.
- Use `(apply-kw f args... kwargs-map)` and `(apply-method-kw obj method args... kwargs-map)` for dynamic Python keyword arguments.
- When Python calls a Basilisp callback with keyword arguments, annotate single-arity functions with `^{:kwargs :apply}` for rest-arg destructuring or `^{:kwargs :collect}` to receive a final kwargs map.
- Use `aget`, `aset`, and `alength` for Python-style indexed access and mutation. Use `aslice` for Python slices.
- Use `lisp->py` / `py->lisp` at API boundaries, not repeatedly in hot loops. For environment maps, use `py->lisp {:keywordize-keys false}` and `lisp->py` so variable names stay strings.
- Convert Python generators and other single-use iterables with `iterator-seq` before applying multiple sequence operations such as `count` and `first`.

### Host-Boundary Idioms

- Use protocols plus `extend-protocol` for host-boundary APIs that must accept multiple Python/Basilisp types. Keep public functions thin and route concrete behavior through protocol methods.
- Normalize option maps before crossing into Python. Validate incompatible modes early, fill Python defaults explicitly, then call Python with `**`, `apply-kw`, or `lisp->py`.
- Prefer `ex-info` with a data map for invalid host-boundary states such as unreadable streams, wrong file modes, unsupported input types, or options supplied for already-open files.
- Use `with-open` for readers/writers and `with` for Python context managers. Wrap path-like values in context managers at the boundary; pass already-open file objects through without taking ownership.
- Use `pathlib.Path` for filesystem coercion and resolve subprocess working directories before passing them to Python.
- For subprocesses, prefer `communicate` over direct `stdin`/`stdout`/`stderr` stream reads to avoid deadlocks.

### Async

- Define Python `async def` functions with `defasync`, not `async defn`.
- Use `(await expr)` only inside an async context such as a `defasync` body; top-level `(await ...)` is a compile-time error.
- In nREPL sessions that already run an event loop, `asyncio/run` raises `RuntimeError`. To smoke-test a coroutine from `brepl`, use the project's async test harness or run `asyncio/run` from a separate Python thread.

```bash
brepl <<'EOF'
(import asyncio concurrent.futures)

(defasync fetch-value [] 123)
(defasync add-one [] (+ 1 (await (fetch-value))))

(def executor (concurrent.futures/ThreadPoolExecutor ** :max_workers 1))
(def fut (.submit executor (fn [] (asyncio/run (add-one)))))
(println (.result fut))
(.shutdown executor)
EOF
```

## Basilisp Semantics For Debugging

| Area | Basilisp behavior | Probe |
|---|---|---|
| Runtime | Python VM; no JVM `clojure-version` | `*python-version*`; `(clojure-version)` fails |
| Equality | `=` follows Python equality; `==` aliases `=` | `(= 1 1.0)` and `(== 1 1.0)` are true |
| Core coercions | `int` and `float` coerce strings using Python-like parsing | `(int "10")`; `(float "1.5")` |
| Numeric readers | `N` int no-op, `M` Decimal, `J` complex, ratios are `fractions.Fraction` | `(decimal? 1.5M)`, `(complex? 1J)`, `(ratio? 22/7)` |
| Character reader | Character literals are 1-character Python strings | `(python/type \a)` returns `str`; `(char? \a)` is true |
| Python literals | `#py []`, `#py ()`, `#py {}`, `#py #{}` read native Python list/tuple/dict/set | `#py [1 2]` is a Python list |
| Extra readers | `#b"..."` bytes, `#f"..."` Python f-string, reader feature `:lpy` | `#?(:clj "clj" :lpy "lpy")` selects `"lpy"` |
| References | Atoms, futures, promises, delays, volatiles are supported; refs/STM and agents are not | `(atom 0)`, `(future ...)`, `(promise)` |
| Core libs | Ported `clojure.*` namespaces are auto-aliased to `basilisp.*` equivalents for compatibility | Prefer `basilisp.string`, `basilisp.set`, `basilisp.test` in new code |
| Printing/format | `format` uses Python `%` formatting | `(format "%04d" 12)` returns `"0012"` |
| Type hints | `:tag` metadata can become Python annotations but is not used by the compiler for optimization | Use tags for Python introspection only |

### Requiring Code Dynamically

The Basilisp compiler verifies Var and Python module member existence during analysis by introspecting the runtime environment. Requiring a namespace inside a dynamic context (e.g. inside a function body) and immediately referencing symbols from it raises a compile-time error:

```clojure
((fn []
  (require 'basilisp.set)
  (basilisp.set/difference #{:b} #{:a})))
;; => error occurred during macroexpansion:
;;    unable to resolve symbol 'basilisp.set/difference' in this context
```

Use `requiring-resolve` to dynamically require and resolve the Var in one call:

```clojure
((fn []
  ((requiring-resolve 'basilisp.set/difference) #{:b} #{:a})))
;; => #{:b}
```

Prefer `requiring-resolve` whenever a require and its referenced symbols live inside a dynamic context such as a `fn`, `defn`, `defasync`, or `let`.

- Treat persistent collections as immutable values. Use transients only inside tight local update loops, and return persistent values at API boundaries.
- Remember seqs are lazy. At the REPL or when crossing into mutable Python iterables, realize with `doall`, `vec`, or another concrete collection when timing, side effects, or source mutation matters.
- Keep atom `swap!` functions side-effect free because compare-and-set retry loops may call them more than once. Use validators to reject invalid states and watches only for observation.
- Use protocols for single-argument type dispatch and host-extension points. Use multimethods when dispatch needs arbitrary runtime values, hierarchies, or multiple arguments.
- Use `deftype` for reusable Python classes and `reify` for one-off interface/protocol implementations. `deftype` fields are immutable by default; mark fields `^:mutable` only when Python interop requires mutation.
- Use `defrecord` for map-like domain values that should participate naturally in Basilisp map operations.
- Reach for functions before macros. Macros run at compile time, receive unevaluated forms, and must return legal Basilisp code with resolvable symbols.
- Metadata is runtime data and does not affect equality or hashes. Use it for compiler/runtime hints and attached context, not semantic identity.



