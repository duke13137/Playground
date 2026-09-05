# Guardrails and Truss on Jolt

This example declares `com.fulcrologic/guardrails` 1.3.3 and
`com.taoensso/truss` 2.5.1 in `deps.edn`, then runs their migrated tests under
Jolt. Guardrails tests come from upstream tag
[`guardrails-1.3.3`](https://github.com/fulcrologic/guardrails/tree/guardrails-1.3.3)
(commit `bcaca53295667aa5215ab8f92d2eb8f30fc90e23`).

Run:

```sh
jolt test
```

Expected result: `Ran 50 tests. 384 assertions passed, 0 failures, 0 errors.`

## Enabling Guardrails

Current Jolt does not accept JVM-style `-Dguardrails.enabled=true` on its
command line. It has no JVM, and its documented `-J` compatibility option is
[accepted but ignored](https://github.com/jolt-lang/jolt/blob/1462939ebdef86c7a68aad2cd2986a5738f405f8/jolt-core/jolt/main.clj#L773-L774).
Jolt does implement `System/getProperty` and `System/setProperty`, so
`bootstrap.clj` sets `guardrails.enabled` to `"true"` before requiring any
Guardrails namespace.

## Compatibility layer

Guardrails depends on Clojure 1.12.5, so `deps.edn` explicitly supplies that
release's `spec.alpha` 0.5.238 and `core.specs.alpha` 0.4.74 artifacts. This
follows Jolt's source-based [Maven dependency model](https://jolt-lang.net/docs/building-and-deps.html#whats-supported).
fulcro-spec is test-only (`:aliases :test :extra-deps`) and excludes its older
transitive Guardrails and Malli copies; Malli 0.20.1 is pinned directly to
match Guardrails 1.3.3.

Two project-local shims run before the upstream test namespaces load:

- `ns-resolve` gains the advertised `[ns env sym]` arity. Its behavior mirrors
  [Clojure 1.12.5](https://github.com/clojure/clojure/blob/clojure-1.12.5/src/clj/clojure/core.clj): an environment binding shadows global resolution.
- fulcro-spec 3.2.9's generated `Throwable` class token is converted back to a
  fully-qualified symbol before Jolt analyzes `=throws=>` assertions.

The seven files under `test/com/fulcrologic/guardrails` and Truss's upstream
`test/taoensso/truss_tests.cljc` are copied unchanged (apart from the
documented Jolt branches in the Truss file). Jolt's
[time provider](https://jolt-lang.net/docs/api/time.html)
supplies `DateTimeFormatter` for the test dependency graph.

Guardrails' separate `src/test-clj-kondo` suite is not a runtime-library test
and is not included: clj-kondo reaches Cheshire/Jackson's JVM-only
`JsonFactory`, which is outside Jolt's documented pure-CLJ/CLJC dependency
boundary.
