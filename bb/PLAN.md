# Migrate IAM Graph Loader From Datalevin To Datahike

## Summary

Migrate `bb/iam_datalevin.cljc` into `bb/iam_datahike.clj` as a Babashka-first Datahike implementation while preserving the IAM relationship model, CLI workflows, load-order/idempotence behavior, and existing query vocabulary. Use Datahike's retained transaction history to make policy-version and graph-state time travel a first-class capability instead of the current Datalevin current-state-only model.

This plan is based on the current Datalevin implementation, loader tests, fuzz tests, and Datahike docs/examples:

- Datahike file stores require `:store {:backend :file :id ... :path ...}`.
- `:keep-history?` controls historical storage and should remain enabled.
- `as-of`, `since`, and `history` query historical states and changes.
- The Babashka pod exposes `connect`, `create-database`, `database-exists?`, `db`, `transact`, `q`, `pull`, `history`, `as-of`, `since`, `with-db`, `release-db`, and `release`.
- Datahike schema flexibility is fixed at database creation; schema-on-write catches data-shape errors earlier.
- Datahike configuration is fixed at database creation; changing backend, history, or schema-flexibility means migrating to a new database.

## Design Options And Decisions

- **Role Transition model**: derive transitions at query time from **Statements**.
  - Options considered: persist `:role-transition/*` entities, or derive transition rows from source policy/trust documents.
  - Decision: derive. This matches `bb/CONTEXT.md` and the updated Datalevin tests, avoids duplicated relationship state, and lets Datahike `as-of` derive transitions against any historical database state.

- **Policy Version model**: persist **Policy Version** as a domain entity for managed policies.
  - Options considered: keep the simplified direct `:policy/document` model, or restore `:policy-version/*` with `:policy/default-version`.
  - Decision: restore for Datahike. AWS policy versions are domain facts; Datahike history is transaction history. Keeping both avoids conflating "AWS has version v2" with "our database used to point at a different document."

- **Trust and inline policy version convention**: keep direct `:policy/document` for trust and inline policies unless AWS inventory provides a real version identifier.
  - Options considered: synthetic one-version entities for all policies, or version entities only where AWS exposes versions.
  - Decision: use real versions only. Managed policies get **Policy Version** entities; trust and inline policies remain direct documents because their lifecycle is tied to the owning role configuration item.

- **Schema mode**: use schema-on-write.
  - Options considered: `:schema-flexibility :read` for loose imports, or `:schema-flexibility :write` with initial schema transaction.
  - Decision: schema-on-write. The IAM graph depends on refs, identities, and cardinalities being correct, and Datahike docs call schema-on-write the safer production default.

- **History mode**: keep history enabled.
  - Options considered: `:keep-history? false` for smaller/faster writes, or `:keep-history? true` for time travel.
  - Decision: enabled. Temporal questions around policy defaults, source imports, and blast-radius deltas are part of the migration goal.

- **Storage backend**: use file backend for the Babashka migration.
  - Options considered: memory for tests, file for durable local CLI usage, LMDB for higher local write churn, or distributed backends for multi-reader deployments.
  - Decision: file for the initial Babashka loader because it needs no extra dependency and fits single-machine CLI workflows. Keep tests on memory or temporary file stores; revisit LMDB if write churn dominates.

- **Babashka pod risk**: isolate Datahike calls behind small wrapper helpers.
  - Options considered: call pod API directly throughout the loader, or centralize connect/transact/db/history calls.
  - Decision: centralize. The Datahike docs mark the pod as beta, so a thin local boundary reduces migration risk if pod behavior differs from JVM Datahike.

- **Config resource versioning**: model each import as a **Resource Observation** transaction.
  - Options considered: destructively reload a source file, overwrite only current resource entities, or store separate resource-version entities.
  - Decision: use Datahike history for resource-state versioning. Each Config load transacts immutable **Configuration Item** provenance plus upserts to the current resource entities. The current graph is just `d/db`; prior resource states come from `d/as-of`; deltas come from `d/since` or `d/history`.

- **Source reload behavior**: do not purge or retract prior observations during normal Datahike ingest.
  - Options considered: keep Datalevin-style source retraction, purge old source data, or append/upsert observations and let history retain changes.
  - Decision: append/upsert. Normal reloads should be idempotent for identical **Configuration Items** and should create a new transaction for changed observations. Retraction is only for explicit correction commands; purging is reserved for compliance removal because it erases history.

## Key Changes

- Replace the Datalevin pod dependency with `replikativ/datahike` and require `[datahike.pod :as d]`.
- Make `bb/iam_datahike.clj` the real IAM loader namespace, not the current sample script.
- Keep the public loader API stable where possible: `schema`, `get-conn`, `load-config-json!`, `load-iam-policy-json!`, `load-service-reference-json!`, `batch-load!`, `batch-load-config!`, `batch-load-policy!`, `batch-load-service-reference!`, `usage`, and `-main`.
- Change database configuration from a bare Datalevin path to a Datahike config map built from the CLI `--db` path:
  - `{:store {:backend :file :path db-path :id stable-db-uuid} :schema-flexibility :write :keep-history? true :initial-tx schema-tx}`
  - Derive `stable-db-uuid` deterministically from the absolute DB path so repeated CLI invocations reconnect to the same store.
  - Create the database only when `d/database-exists?` is false.
- Convert the existing Datalevin schema map into Datahike initial transaction entities with `:db/ident`, `:db/valueType`, `:db/cardinality`, and `:db/unique` where present.
- Replace `d/get-conn`, `d/transact!`, `d/db`, and `d/close` usage with Datahike pod equivalents: `d/connect`, `d/transact`, `d/db`, and `d/release`.
- Keep transaction phases. Each phase remains one `d/transact` call so Datahike transaction boundaries are meaningful for `as-of`, `since`, and `history`.
- Use `d/with-db` for short-lived CLI reads where practical, and call `d/release-db` for any explicitly retained DB value.
- Keep derived **Role Transition** queries. Do not reintroduce `:role-transition/*` attributes during the Datahike port.
- Restore managed-policy version attributes for the Datahike schema: `:policy/default-version`, `:policy/version`, `:policy-version/key`, `:policy-version/id`, `:policy-version/default?`, `:policy-version/create-date`, and `:policy-version/document`.
- Add resource-observation attributes for Datahike provenance:
  - `:config/key` remains unique per AWS Config `configurationStateId`.
  - `:config/imported-at` records loader ingest time.
  - `:config/source-path` or `:config/source` records input provenance without owning/retracting documents by source.
  - `:config/describes` points to the current resource entity that the observation updated.
- Keep current resource entities stable by AWS identity attributes such as `:role/id`, `:policy/key`, and `:aws/arn`. A later **Resource Observation** upserts the same entity, so Datahike creates transaction history for changed facts.

## Temporal Model

- Keep **Policy Version** as a domain entity. Do not rely on Datahike history as the only representation of AWS policy versions.
- Treat Datahike transaction history as the **Historical Timeline** of imported graph states:
  - `d/db conn` answers current-state questions.
  - `d/as-of db instant-or-tx` answers "what did the IAM graph look like at this import time?"
  - `d/since db instant-or-tx` answers "what changed after this import?"
  - `d/history db` supports audit queries across all asserted and retracted facts.
- Treat **Resource Observation** as source provenance, not as the current resource state:
  - **Configuration Item** entities are immutable import facts keyed by AWS Config state id.
  - **Role**, **Policy**, and other resource entities are stable current-state identities.
  - Importing a newer observation updates the stable resource entity and creates a Datahike historical state for the old values.
  - Importing the same observation again is idempotent because the same `:config/key` and same resource identity attributes upsert to the same datoms.
- Add small query helpers after the base migration:
  - `db-as-of` returns a historical DB value from a conn and time point.
  - `policy-default-version-at` returns the default **Policy Version** for a policy at a time point.
  - `role-effective-allow-at` runs the existing effective-allow query against an `as-of` DB.
  - `policy-version-changes-since` queries `history` or `since` for default-version changes.
  - `resource-observations` returns **Configuration Items** for a resource ordered by capture time.
  - `resource-state-at` resolves the stable resource identity against an `as-of` DB.
  - `resource-changes-since` joins current DB identity attributes with `d/since` changed datoms.
- Add transaction metadata for import provenance when the pod accepts tx metadata. At minimum, keep existing **Configuration Item**, **Policy Document**, and service-reference provenance as domain entities so the graph is explainable even without tx metadata.

## Implementation Steps

1. Replace the sample Datahike script with the IAM loader implementation.
2. Port the namespace and imports from `iam-datalevin` to `iam-datahike`, dropping reader conditionals unless JVM Clojure support is still required.
3. Add Datahike config helpers: `stable-db-id`, `db-config`, `schema-tx`, `ensure-database!`, `get-conn`, and `close-conn!`.
4. Port all pure parsing and transaction-shaping functions unchanged first: JSON parsing, AWS date parsing, key builders, policy document normalization, Config item extraction, service-reference normalization, relationship model, sample queries, and role-chain rules.
5. Replace Datalevin source reload semantics with Datahike observation ingest:
  - remove default `reload-source!` from normal load functions.
  - preserve explicit correction/retraction as a separate command if still needed.
  - attach source path and imported-at to **Configuration Item** observations.
6. Update transaction execution only after pure code is moved: `transact-phases!` should call `d/transact` once per non-empty phase and return the same summary shape as today.
7. Update CLI text from "Datalevin database path" to "Datahike database path" and keep existing `bb -x` and `bb -m` command semantics.
8. Update tests to require `iam-datahike` and `datahike.pod`; keep fixture data and assertions intact before adding temporal tests.
9. Add temporal tests using two imports of the same managed policy with different defaults/documents:
  - current query returns the latest default version.
  - `as-of` before the second import returns the original default version.
  - `since` after the first import exposes the default-version change.
  - `history` shows both old and new policy-document facts.
10. Add Config resource temporal tests using two observations of the same role with different tags, trust policy, or attached policies:
  - current query returns the latest role state.
  - `as-of` before the second observation returns the original state.
  - both **Configuration Items** remain queryable as provenance.
  - `resource-changes-since` reports only facts changed after the first observation.
11. Run the existing loader tests and fuzz tests with `bb` from the `bb` directory, keeping generated fuzz failures under `/tmp`.

## Test Plan

- Smoke test the Datahike pod sample path with `bb bb/iam_datahike.clj` until it only contains the real loader and no sample top-level side effects.
- Run loader tests for load-order commutativity, idempotence, service-reference normalization, JSONL file loading, stdin loading, and extra-file rejection.
- Run fuzz tests with the default `IAM_FUZZ_TRIALS` and at least one higher local value after the basic port passes.
- Add focused temporal regression tests for `as-of`, `since`, and `history` around managed policy default-version changes.
- Add focused temporal regression tests for AWS Config resource observations of the same role across two capture times.
- Manually verify CLI help and one batch load command against a temporary Datahike file store.

## Assumptions

- `bb/CONTEXT.md` is the canonical IAM context for the Babashka loader; `hs/*.md` documents an unrelated Haskell Todo migration and should not define IAM vocabulary.
- Babashka remains the target runtime for this loader.
- Datahike `0.8.1678` is the target pod version because it is current in the pod registry and already runs locally.
- The migrated loader should preserve current graph semantics before adding temporal query helpers, except for restoring managed **Policy Version** entities needed by the temporal model.
- Full IAM authorization evaluation remains out of scope; the model continues to answer relationship, blast-radius, provenance, and temporal graph questions.

## Completion Notes

Implemented in `bb/iam_datahike.clj`:

- Datahike pod loader with `:schema-flexibility :write`, `:keep-history? true`, memory configs for tests, and deterministic file configs for CLI use.
- Datahike schema for Roles, Managed Policies, Policy Versions, Policy Documents, Statements, Principals, Actions, Resources, Conditions, Configuration Items, service-reference catalog facts, and AWS Config resource schemas.
- AWS Config loaders for IAM Roles and Managed Policies, including Resource Observation provenance through `:config/*` entities.
- Managed Policy Version model with `:policy/default-version`, `:policy/version`, and historical default-version queries.
- Derived Role Transition query for `iam:PassRole` from source Statements. No `:role-transition/*` facts are materialized.
- Service authorization reference loader for downloaded `servicereference.us-east-1.amazonaws.com` JSON.
- AWS Config resource schema loader for `awslabs/aws-config-resource-schema` IAM property files.
- Temporal helpers: `db-as-of`, `policy-default-version-at`, `policy-version-changes-since`, `policy-document-history`, `role-effective-allow-at`, `resource-observations`, `resource-state-at`, and `resource-changes-since`.
- History/audit helper: `history-datoms-since`.
- CLI/API surface: `load-config-json!`, `load-iam-policy-json!`, `load-service-reference-json!`, `load-config-resource-schema-json!`, `load-config!`, `load-policy!`, `load-service-reference!`, `load-config-resource-schema!`, `batch-load!`, `retract-source!`, `stats!`, `usage`, and `-main`.
- Derived Role Transition queries for both `sts:AssumeRole` and `iam:PassRole`.
- JSONL batch-load test coverage, idempotent same-observation reload behavior, source correction/retraction command coverage, and load-order fuzz coverage.
- Sample manifest under `bb/samples/SOURCES.md`.

Verified:

- `bb -cp . -m iam-datahike-test`
- CLI smoke loads for Config Role sample, service-reference IAM sample, Config resource schema sample, managed policy-version sample, and `stats`.

Deferred beyond this migration:

- Full deny/boundary/session-aware IAM authorization evaluation.
- Exhaustive Datalevin admin-path report parity beyond the role-transition and effective-allow tracer bullets.
