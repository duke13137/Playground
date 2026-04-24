# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Babashka (bb) web application using Datastar for real-time SSE-driven UI updates. The server runs on http-kit with Ring middleware and serves HTML pages that use Datastar's client-side reactive framework.

## Architecture

- **bb.edn** (symlinked as `deps.edn`): Babashka project config with deps and pods
- **core.clj**: Main server — http-kit + Ring + clj-simple-router. Routes defined as `{"METHOD /path" handler}` map. SSE handlers use the `sse` wrapper which sets up Datastar SSE responses via http-kit adapter
- **index.html**: Datastar-powered page with SSE streaming and Scittle (ClojureScript-in-browser via SCI) page with browser nREPL support
- **client.cljs**: Scittle source served as `application/x-scittle`, evaluated in-browser

## Key Libraries

- **Datastar** (`starfederation.datastar.clojure`): @Datastar.md
- **Selmer**: Template rendering (`render-file`)
- **Promesa**: Async primitives and CSP channels
- **Specter**: Data navigation/transformation
- **Portal**: Dev inspection tool (`portal.console/info`)
- Datalevin is available as a Babashka pod
- **Guardrails/Playback/scope-capture**: Dev-time debugging tools

## Conventions

- HTML files are served via Selmer's `render-file` (templates from project root)
- SSE handlers take `[req sse]` and are wrapped with the `sse` function

## Running

- Server is auto-reloaded when .clj files are changed.

```bash
fd -e clj |& entr -r bb -Dguardrails.enabled=true core.clj
```

- To **test http requests**

```bash
curl 127.0.0.1:3000/
```

## Clojure Parenthesis Repair

**IMPORTANT:** Do NOT try to manually repair parenthesis errors.
If you encounter unbalanced delimiters, run `brepl balance` on the file
instead of attempting to fix them yourself. If the tool doesn't work,
report to the user that they need to fix the delimiter error manually.

- To **evaluate clojure expressions** via `brepl`

`brepl` tries ports in order: `.nrepl-port` file, then 9999 (clojure default), then 1666 (bb server). Always prefer `brepl` without `-p` unless targeting a specific REPL.

```bash
# auto-detect port (tries .nrepl-port → 9999 → 3333)
brepl '(println "hello")'

# send to browser nrepl (always explicit)
brepl -p 3339 '(println "browser")'
```

## Testing

**NEVER use `clj -M:test`.** Run tests with bb or brepl only:

```bash
# bb direct (runs all tests including property-based via test.check)
bb -cp . -m iam-oracle-test

# or via Clojure JVM nREPL
brepl -p 9999 '(require (quote iam-oracle-test) :reload)(clojure.test/run-tests (quote iam-oracle-test))'
```
