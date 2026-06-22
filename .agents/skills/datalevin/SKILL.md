---
name: datalevin
description: Work with Datalevin as an embedded or client/server Datalog database, including Babashka pod usage, schemas, transactions, queries, pull, rules, and Datomic/DataScript-style migrations. Use when the user mentions Datalevin, datalevin.core, pod.huahaiy.datalevin, dtlv, LMDB-backed Datalog, durable Datalog storage, or debugging Datalevin queries/transactions.
---

# Datalevin

## Quick Start

Use a single-quoted heredoc for reproducible Babashka pod checks. Prefer `pods/load-pod "dtlv"` when the `dtlv` binary is already installed; otherwise load a registered pod version from the pod registry.

```bash
bb <<'CLJ'
(require '[babashka.pods :as pods])
(pods/load-pod "dtlv")
(require '[pod.huahaiy.datalevin :as d])

(def schema {:todo/name {:db/valueType :db.type/string
                         :db/cardinality :db.cardinality/one}})
(def conn (d/get-conn "/tmp/todos" schema))

(try
  (d/transact! conn [{:todo/id (str (random-uuid))
                     :todo/name "Buy milk"}])
  (prn (d/q '[:find ?name :where [?e :todo/name ?name]] (d/db conn)))
  (finally
    (d/close conn)))
CLJ
```

## Workflows

### Choose Runtime

- Use `datalevin.core` in JVM Clojure projects.
- Use `pod.huahaiy.datalevin` from Babashka for scripts and local automation.
- Use `dtlv` for MCP, backups, import/export, and ad hoc query/transaction execution.
- For project MCP setup in `.codex/config.toml`, run Datalevin as local stdio with `dtlv mcp`; see [REFERENCE.md](REFERENCE.md#codex-mcp-config).
- For shared `.cljc` code that must run in both Babashka and JVM Clojure, use reader conditionals; see [REFERENCE.md](REFERENCE.md#reader-conditionals-in-cljc-files).

### Connect, Transact, Query

1. Define schema as a map of attribute keys to option maps when attributes need type, cardinality, uniqueness, refs, or search/vector behavior.
2. Open with `d/get-conn` using a local path or `dtlv://...` server URI.
3. Transact maps or tx vectors with `d/transact!`; prefer stable identity attributes for upserts.
4. Query immutable snapshots from `(d/db conn)` with `d/q`.
5. Use `d/pull` / `d/pull-many` for entity-shaped results.
6. Close connections with `d/close`, ideally in `finally`.

```clojure
(d/transact! conn [{:user/email "a@example.com" :user/name "Ada"}])
(d/q '[:find ?name .
       :in $ ?email
       :where [?e :user/email ?email]
              [?e :user/name ?name]]
     (d/db conn) "a@example.com")
```

### Rules and Predicates

```clojure
(def rules '[[(my-filter ?e ?val) [?e :item/type ?val]]])

(d/q '[:find [?id ...] :in $ %
       :where (my-filter ?e "task") [?e :item/id ?id]]
     db rules)
```

Use fully-qualified function names in query predicates when alias resolution is not available. For custom Babashka pod query functions, use the Datalevin pod's `defpodfn`.

### Migration Notes

- Datalevin schema is supplied when opening/updating the connection, not transacted like Datomic schema data.
- Datalevin does not provide Datomic history/time-travel APIs such as `as-of`, `since`, or `history`; model audit data explicitly when needed.
- Prefer identity attributes and lookup refs for stable upserts and references.
- Verify Datomic/DataScript assumptions around tempids, transaction functions, and entity APIs against Datalevin docs before porting.

## Lookup

- Use cljdoc for current API docs: https://cljdoc.org/d/datalevin/datalevin/
- Check installation and pod details before pinning versions; cljdoc may show an older documented release while the current release badge is newer.
- Use the GitHub docs for deeper topics: query engine, rules, transactions, MCP, server/client, full-text search, vector search, and limitations.

See [REFERENCE.md](REFERENCE.md) for API examples, gotchas, and feature notes.
