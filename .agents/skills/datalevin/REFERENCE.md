# Datalevin Reference

## Contents

- [Design Philosophy](#design-philosophy)
- [Babashka Pod and .cljc](#babashka-pod-and-cljc)
- [Codex MCP Config](#codex-mcp-config)
- [Core API](#core-api)
- [Extended Features](#extended-features)
- [Common Gotchas](#common-gotchas)
- [Performance Tips](#performance-tips)
- [Resources](#resources)

## Design Philosophy

- **ACID semantics** — behaves like a normal database
- **Schema-optional** with declared special attributes
- **Cost-based query optimizer** — use `d/explain` and docs when tuning
- **Recursive rules** — supported and useful for graph-style traversals
- **No temporal history** — deleted data is gone (intentional)
- **No time travel** — no `as-of`/`since`/`history`

**Mental model:** "Datalog-powered SQLite" NOT "lightweight Datomic"

## Babashka Pod and .cljc

### Loading the Pod

```clojure
(require '[babashka.pods :as pods])

;; Prefer this when the dtlv executable is on PATH:
(pods/load-pod "dtlv")

;; Or load a registered pod version from the pod registry:
(pods/load-pod 'huahaiy/datalevin "0.10.22")

(require '[pod.huahaiy.datalevin :as d])
```

Not every Datalevin release is necessarily registered as a Babashka pod. Check cljdoc and the pod registry before pinning a version.

### Reader Conditionals in .cljc Files

Use `.cljc` files when the same Datalevin code must run in Babashka and JVM Clojure. Reader conditionals are read-time expressions; standard conditionals use `#?`, and namespace declarations are a primary use case.

The Babashka pod namespace is `pod.huahaiy.datalevin`; the JVM library namespace is `datalevin.core`.

```clojure
(ns my-app.db
  (:require
   #?(:bb  [pod.huahaiy.datalevin :as d]
      :clj [datalevin.core :as d])))

(def schema
  {:todo/id {:db/unique :db.unique/identity}
   :todo/name {:db/valueType :db.type/string
               :db/cardinality :db.cardinality/one}})

(defn open-conn [path]
  (d/get-conn path schema))

(defn names [conn]
  (d/q '[:find [?name ...]
         :where [_ :todo/name ?name]]
       (d/db conn)))
```

Put `:bb` before `:clj` because Babashka supports both reader features and uses the first matching branch.

### clj-kondo Config for .cljc

In `.clj-kondo/config.edn`:

```edn
{:config-in-ns
 {my-app
  {:linters {:unresolved-namespace {:exclude [d]}}}}}
```

---

## Codex MCP Config

Datalevin can run as a local MCP stdio server with `dtlv mcp`. Add it to a project's `.codex/config.toml` when the project should expose Datalevin tools to Codex.

Read-only mode is the default and should be preferred first:

```toml
[mcp_servers.datalevin]
command = "dtlv"
args = ["mcp"]
enabled = true
```

Enable write tools only when the task really needs Datalevin mutations:

```toml
[mcp_servers.datalevin]
command = "dtlv"
args = ["--allow-writes", "mcp"]
enabled = true
```

Notes from Datalevin's MCP docs:

- The server is a local `stdio` adapter over Datalevin APIs.
- It can open local databases by `dir` and remote Datalevin targets by `dtlv://...` URI.
- Writes are disabled unless `--allow-writes` is passed at startup.
- Use `structuredContent` as the authoritative tool result payload.
- Query with explicit limits when possible; MCP responses are capped and may include `meta.truncated`.

Source: https://github.com/datalevin/datalevin/blob/master/doc/mcp.md

---

## Core API

### Connection & Lifecycle

```clojure
(def schema
  {:todo/name {:db/valueType :db.type/string
               :db/cardinality :db.cardinality/one}
   :todo/tags {:db/cardinality :db.cardinality/many}
   :user/email {:db/unique :db.unique/identity}})

(def conn (d/get-conn "/path/to/db" schema))
(def db (d/db conn))  ;; immutable snapshot
(d/close conn)
```

- Schema NOT transacted — passed at connection time
- Connection is local path (embedded) or `dtlv://host/db` (server)

### Transactions

```clojure
;; Create — prefer identity attributes for stable upserts
(d/transact! conn
  [{:todo/id (str (random-uuid)) :todo/name "Buy milk" :todo/done false}])

;; Update
(d/transact! conn [[:db/add entity-id :todo/done true]])

;; Upsert via identity attribute
(d/transact! conn [{:todo/id "existing-uuid" :todo/name "Updated"}])

;; Delete
(d/transact! conn [[:db/retractEntity entity-id]])

;; Async (2.5x+ throughput)
(d/transact-async! conn [{:todo/name "Async task"}])
```

### Queries (Datalog)

```clojure
;; Basic
(d/q '[:find ?name :where [?e :todo/name ?name]] db)
;; => #{["Buy milk"]}

;; With params
(d/q '[:find ?e :in $ ?name :where [?e :todo/name ?name]] db "Buy milk")

;; Single result
(d/q '[:find ?e . :where [?e :todo/name "Buy milk"]] db)
;; => 1

;; Collection result
(d/q '[:find [?e ...] :where [?e :todo/name _]] db)
;; => [1 2 3]

;; Aggregation
(d/q '[:find (count ?e) :where [?e :todo/done false]] db)

;; Order & limit (v0.9.12+)
(d/q '{:find [?name]
       :where [[?e :todo/name ?name]]
       :order-by [[?name :desc]]
       :limit 10} db)
```

### Pull API

```clojure
(d/pull db [:db/id :todo/name :todo/done] entity-id)
;; => {:db/id 1 :todo/name "Buy milk" :todo/done false}

(d/pull db [*] entity-id)  ;; all attributes

(d/pull db [:user/name {:user/friends [:db/id :user/name]}] user-id)  ;; nested
```

### Rules

```clojure
(def rules
  '[;; Simple rule
    [(service-actions ?svc ?e) [?e :action/service ?svc]]

    ;; Two heads = OR
    [(readonly-action ?e) [?e :action/access-level "Read"]]
    [(readonly-action ?e) [?e :action/access-level "List"]]

    ;; Recursive
    [(reachable ?a ?b) [?a :role/trusts ?b]]
    [(reachable ?a ?b) [?a :role/trusts ?mid] (reachable ?mid ?b)]])

(d/q '[:find [?id ...] :in $ %
       :where (service-actions "s3" ?e) (readonly-action ?e)]
     db rules)
```

Use `d/explain` and small fixtures to verify rule behavior and query plans before assuming performance.

### Predicates & Bindings

```clojure
;; Predicate — filter rows
(d/q '[:find ?id :in $ ?svc
       :where [?e :action/service ?svc]
       [?e :action/name ?name]
       [(clojure.string/starts-with? ?name "Get")]]
     db "s3")

;; Binding — transform
(d/q '[:find ?wildcard
       :where [?e :action/service ?svc]
       [(str ?svc ":*") ?wildcard]]
     db)
```

**Pod query rules:**

| What                 | Works          | Example                         |
| -------------------- | -------------- | ------------------------------- |
| Full namespace       | YES            | `clojure.string/starts-with?`   |
| Alias                | NO             | Use full ns                     |
| clojure.core         | YES            | `str`, `>`, `<`                 |
| Comparison built-ins | YES            | `(< ?a ?b)`                     |
| User-defined bb fns  | USE `defpodfn` | Define pod functions explicitly |

```clojure
(d/defpodfn custom-fn [n] (str "hello " n))
(d/q '[:find ?greeting :where [(custom-fn "world") ?greeting]])
```

---

## Extended Features

### Vector Search

```clojure
(add-vec db-conn {:id "doc1" :embedding [0.1 0.2 0.3]})
(search-vec db-conn [0.1 0.2 0.3] {:limit 10})
```

### Full-Text Search

```clojure
(new-search-engine {:index-position? true})
(add-doc search-engine doc-ref "searchable text content")
(search search-engine "query" {:display [:refs :text]})
```

### Key-Value Mode

```clojure
(def kv-db (d/open-kv "/path/to/kvdb"))
(d/transact-kv kv-db [[:put "table" :key "value"]])
(d/get-value kv-db "table" :key)
```

---

## Common Gotchas

| Issue               | Solution                              |
| ------------------- | ------------------------------------- |
| Schema format       | Use map of maps, NOT vector           |
| No temporal queries | Design for current state              |
| Deleted data gone   | Add soft-delete flags                 |
| Upserts/references  | Prefer identity attrs and lookup refs |

### Pod-Specific Gotchas

| Issue                    | Workaround                                    |
| ------------------------ | --------------------------------------------- |
| Alias in predicates      | Always use full namespace                     |
| User fns in predicates   | Use `defpodfn`, pull + filter, or JVM Clojure |
| Reader conditional order | Put `:bb` BEFORE `:clj`                       |

---

## Performance Tips

- Use recursive rules — optimizer handles them well
- Batch transactions instead of transacting one fact at a time
- Consider async transactions for throughput-sensitive writes
- Declare `:db/unique` — enforces constraints efficiently
- Use `d/explain` when a query is unexpectedly slow

---

## Resources

- **Docs:** <https://cljdoc.org/d/datalevin/datalevin/>
- **GitHub:** <https://github.com/datalevin/datalevin>
- **Query Guide:** <https://github.com/datalevin/datalevin/blob/master/doc/query.md>
- **Rules Guide:** <https://github.com/datalevin/datalevin/blob/master/doc/rules.md>
