---
name: datalevin
description: "Embedded Datalog database with ACID semantics, fast recursive rules, cost-based optimizer. Use when working with Datalevin, Datalog queries, embedded databases, Datomic migration, or LMDB-backed storage."
---

# Datalevin

## Use babashka datalevin pod to evaluate clojure code in **HEREDOC**

```bash

bb <<'CLJ'
(require '[babashka.pods :as pods])
(pods/load-pod 'huahaiy/datalevin "0.10.7")
(require '[pod.huahaiy.datalevin :as d])

;; Schema (map of maps!)
(def schema {:todo/name {:db/valueType :db.type/string
                         :db/cardinality :db.cardinality/one}})

;; Connect (creates DB if missing)
(def conn (d/get-conn "/tmp/todos" schema))

;; Transact (use identity attributes, NOT negative temp IDs!)
(d/transact! conn [{:todo/id (str (random-uuid)) :todo/name "Buy milk"}])

;; Query
(d/q '[:find ?name :where [?e :todo/name ?name]] (d/db conn))
;; => #{["Buy milk"]}

(d/close conn)
CLJ
```

## Workflows

### Connect & Basic CRUD

1. **Define schema** - map of maps with `:db/valueType`, `:db/cardinality`, `:db/unique`
2. **Get connection** - `d/get-conn` with path or `dtlv://` for server mode
3. **Transact** - use identity attributes for upserts, never negative temp IDs
4. **Query** - Datalog with rules, predicates, aggregations
5. **Close** - `d/close conn` when done

### Query with Rules

```clojure
(def rules '[[(my-filter ?e ?val) [?e :item/type ?val]]])

(d/q '[:find [?id ...] :in $ %
       :where (my-filter ?e "task") [?e :item/id ?id]]
     db rules)
```

### Migrating from Datomic

Key differences:

- Schema passed at connection (not transacted)
- No `as-of`/`since`/history — design for current state
- Fast recursive rules (not slow like Datomic)
- Use identity attributes + lookup refs instead of temp IDs

---

See [REFERENCE.md](REFERENCE.md) for detailed API docs, gotchas, and performance tips.
