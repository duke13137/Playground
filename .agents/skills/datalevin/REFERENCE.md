# Datalevin Reference

## Design Philosophy

- **ACID semantics** — behaves like a normal database
- **Schema-optional** with declared special attributes
- **Cost-based query optimizer** — 2.4x faster than PostgreSQL
- **Fast recursive rules** — orders of magnitude faster than Datomic
- **No temporal history** — deleted data is gone (intentional)
- **No time travel** — no `as-of`/`since`/`history`

**Mental model:** "Datalog-powered SQLite" NOT "lightweight Datomic"

---

### Reader Conditionals in .cljc Files

The pod namespace is `pod.huahaiy.datalevin`, NOT `datalevin.core`.

```clojure
(ns my-app
  (:require
   #?(:bb  [pod.huahaiy.datalevin :as d]
      :clj [datalevin.core :as d])))
```

**CRITICAL: `:bb` must come BEFORE `:clj`!** Babashka supports BOTH — first match wins.

### kondo Config for .cljc

In `.clj-kondo/config.edn`:

```edn
{:config-in-ns
 {my-app
  {:linters {:unresolved-namespace {:exclude [d]}}}}}
```

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
;; Create — use identity attributes
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

**Performance:** Semi-naive fix-point + magic-set rewrite — orders of magnitude faster than Datomic.

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

**Pod rules:**

| What                 | Works | Example                       |
| -------------------- | ----- | ----------------------------- |
| Full namespace       | YES   | `clojure.string/starts-with?` |
| Alias                | NO    | Use full ns                   |
| clojure.core         | YES   | `str`, `>`, `<`               |
| Comparison built-ins | YES   | `(< ?a ?b)`                   |
| User-defined bb fns  | NO    | Use pull + Clojure filter     |

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

| Issue               | Solution                    |
| ------------------- | --------------------------- |
| Schema format       | Use map of maps, NOT vector |
| No temporal queries | Design for current state    |
| Deleted data gone   | Add soft-delete flags       |
| Use identity attrs  | NOT negative temp IDs       |

### Pod-Specific Gotchas

| Issue                    | Workaround                                     |
| ------------------------ | ---------------------------------------------- |
| Boolean index bug        | Use string enums instead: `"Read"` not `false` |
| Negative temp ID crash   | Use identity + lookup refs                     |
| Alias in predicates      | Always use full namespace                      |
| User fns in predicates   | Use pull + Clojure filter                      |
| Reader conditional order | Put `:bb` BEFORE `:clj`                        |

**Boolean workaround:**

```clojure
;; BAD — pod boolean bug
:action/is-write {:db/valueType :db.type/boolean}

;; GOOD
:action/access-level {:db/valueType :db.type/string} ; "Read"|"Write"
```

---

## Performance Tips

- Use recursive rules — optimizer handles them well
- Batch transactions — 100K+ datoms in <1s
- Enable async mode — 2.5x+ throughput
- Declare `:db/unique` — enforces constraints efficiently
- Complex queries are cheap — cost-based optimizer

---

## Resources

- **Docs:** <https://cljdoc.org/d/datalevin/datalevin/>
- **GitHub:** <https://github.com/datalevin/datalevin>
- **Query Guide:** <https://github.com/datalevin/datalevin/blob/master/doc/query.md>
- **Rules Guide:** <https://github.com/datalevin/datalevin/blob/master/doc/rules.md>
