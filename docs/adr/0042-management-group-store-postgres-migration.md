# ADR-0042: ManagementGroupStore → PostgreSQL (Wave 2.2)

- **Status:** Accepted (governance-resolved 2026-08-02)
- **Date:** 2026-08-01
- **Deciders:** pg workstream; security-guardian + architect + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, **ADR-0017**
  (management-group confinement / `authorize_list_read`); conventions from ADR-0036–0041 (esp.
  `sanitize_pg_text`, fail-closed boot, mandatory-backfill-with-flag-preservation, the RbacStore
  ADR-0041 fail-closed-authz-reads precedent this store feeds).

## Context

`ManagementGroupStore` (`management_groups.db` today, `server/core/src/management_group_store.{hpp,cpp}`,
~1k LOC) holds the **management-group hierarchy**: group definitions (static + dynamic
scope-expression), the parent/child tree, group membership (agents), and group→role assignments.
It is the **confinement substrate** — RbacStore's `authorize_list_read` (ADR-0017 World A) and
`resolve_perm_groups` resolve an operator's visible agent set through this store's
`get_agent_groups` / `get_ancestor_ids` / `get_descendant_ids` / `get_assignments_for_principal`
/ `get_member_agents_in_subtrees` / `get_visible_agents`. Wave 2.2, after RbacStore (ADR-0041).

**The security-critical property (why this is not a routine port):** the confinement-feeding
reads return plain `std::vector` today, so a query error is indistinguishable from a genuinely
empty result — and the two confinement directions fail in OPPOSITE ways:

- An **allow-set** read (`get_member_agents_in_subtrees(allow_groups)`, `get_agent_groups`,
  `get_visible_agents`) degrading to empty → the operator sees *fewer* agents → **fail-closed**
  (safe, over-restrictive).
- A **deny-set** read (`get_member_agents_in_subtrees(deny_groups)`) degrading to empty → *nothing
  is denied* → the operator sees *more* than their confinement allows → **fail-OPEN** (a
  cross-management-group disclosure — exactly the class ADR-0017 exists to prevent).

Under SQLite's single-writer this was mostly moot (a local file rarely "degrades"); under a
pooled PostgreSQL connection a pool-acquire timeout / query error is a real runtime state, so the
deny-set fail-open becomes reachable. ADR-0017 already mandates `authorize_list_read` yield
`DenyAll` on "any mgmt-store error" — but it can only honour that if this store's reads *report*
the error instead of returning a silent empty.

## Decision

Migrate to PostgreSQL schema **`management_group_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server PgPool. `sqlite3_changes()` → `RETURNING`/`PQcmdTuples`
(#1033). `SqliteTxn`/`SqliteStmt` deleted; PG concurrency replaces the single-writer.

### Schema

`management_groups` (id, name, parent_id, scope_expression, …), `management_group_members`
(group_id, agent_id, …), `management_group_roles` (group_id, principal_type, principal_id,
role_name — the legacy table name is kept as-is, byte-identical to the SQLite schema, to keep the
backfill mapping 1:1) port column-for-column; the parent/child tree stays a `parent_id`
self-reference (FK `DEFERRABLE INITIALLY DEFERRED` so the backfill can bulk-insert in any order).
All indexes carry over.

### Reads — degrade-distinguishable on the confinement path (the load-bearing decision)

The reads that feed a confinement/authz decision become **degrade-distinguishable**
(`std::optional<std::vector<...>>` / `std::expected`, `nullopt`/`unexpected` on
store-not-open / pool-acquire-timeout / query error, NEVER a silent empty):
`get_agent_groups`, `get_ancestor_ids`, `get_descendant_ids`, `get_member_agents_in_subtrees`,
`get_assignments_for_principal`, `get_visible_agents`. RbacStore's `authorize_list_read` /
`resolve_perm_groups` consume the `nullopt` as **`DenyAll`** (fail-closed) — closing the deny-set
fail-open above. Non-confinement reads (`list_groups`, `get_group`, `get_children`, counts, the
dashboard CRUD surface) may stay plain-optional/container (deny-or-benign display class), per the
ResultSetStore precedent (playbook "authoritative reads must be type-distinguishable").

**Cross-PR coupling (RbacStore #2703 / ADR-0041):** `authorize_list_read` lives in RbacStore,
which is being migrated to PG in #2703 in parallel. This PR branches from `dev` (SQLite RbacStore),
so it updates that `authorize_list_read`/`resolve_perm_groups` to consume the new
degrade-distinguishable mgmt reads fail-closed; whichever of #2703 / this PR merges second
reconciles the seam. The invariant both must preserve: a mgmt-store degrade → `DenyAll`, never a
silent under-deny.

### Hierarchy traversal

`get_ancestor_ids` / `get_descendant_ids` / `get_member_agents_in_subtrees` become **recursive
CTEs** (`WITH RECURSIVE`) with a `depth < kMaxHierarchyDepth` bound + `DISTINCT`/`id <> seed`
cycle guard (a corrupt parent cycle terminates and drops phantom IDs) rather than the SQLite
app-side BFS. Both cycle termination and the depth bound are asserted in tests.

**Over-deep trees are guarded at BACKFILL, not at read (governance-resolved).** A tree deeper
than `kMaxHierarchyDepth` would be silently truncated by the read CTEs → a mis-confining partial
set (the deny-ward direction is a fail-OPEN). The write path caps depth at 5, so this is only
reachable by backfilling a corrupt / pre-cap legacy DB. A read-side cap-hit detector was rejected
because it cannot distinguish a genuine deep chain from a cycle (which the `DISTINCT` guard
already handles correctly) — it false-positives on cycles. Instead `migrate_from_sqlite`
validates the legacy parent-chain over distinct nodes (explicit cycle detection) and **refuses
the backfill fail-closed** if any tree exceeds the bound, so an over-deep tree never lands.

### Backfill (ADR-0009) — MANDATORY

Management groups + membership + role assignments are authoritative operator-authored config that
**cannot be re-derived** (losing them silently drops every operator's confinement scope → a
fail-open the moment RBAC is on). One-time streamed, idempotent, resumable, reconciled,
**fail-CLOSED** backfill from the legacy `management_groups.db` (the ADR-0040/0041 shape); legacy
moved aside after a verified backfill. Dynamic-group membership is re-derivable (scope engine), so
only the static/authoritative rows are the mandatory set. `sanitize_pg_text` on free-text columns
(incl. the backfill path).

### Lifecycle

`rbac_enabled_probe_` (the borrowed `std::function<bool()>`) is re-wired post-construction as
today. `stop()` unwires from consumers then resets before `pg_pool_`; store in `/readyz` AND
`/healthz`. Construction fail-closed.

## Considered and rejected

- **Keep plain-vector confinement reads**: rejected — the deny-set fail-open is reachable under a
  pooled PG connection; the reads must report degrade so `authorize_list_read` can `DenyAll`.
- **App-side BFS for ancestors**: rejected in favour of a bounded recursive CTE (fewer round-trips,
  cycle-guarded in one statement).
- **Skippable backfill**: rejected — confinement scope is irreducible operator intent.

## Consequences

- A degraded confinement substrate now denies (fail-closed) instead of risking a silent
  cross-group over-disclosure; management-group config preserved across the cutover.
- RbacStore's `authorize_list_read` gains a mgmt-store-degrade `DenyAll` path (coordinated with
  #2703).
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"mgmtgroupstore"` `PgTestTemplate`; backfill /
  fresh-DB tests use plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- Wave 2 continues with `PolicyStore` next.

## Update (2026-09-03) — `migrate_from_sqlite()` retired

**Filename correction:** this ADR's Context/Backfill sections above name the legacy file
`management_groups.db` (underscore); the actual filename the store has always used, both in
`server.cpp`'s construction site and in `docs/user-manual/upgrading.md`, is
`management-groups.db` (hyphen). Noted here rather than silently edited into the original text.

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production Yuzu
fleet has ever run a pre-Postgres build of any store — the mandatory, streamed, fail-closed
backfill this ADR designed (including the over-deep-tree refusal at backfill time) was real,
working code that never had real legacy data to protect.

`ManagementGroupStore::migrate_from_sqlite()` and its private helpers (`legacy_has_table`,
`sqlite_text`, `kBackfillTxnTimeout`) are removed (`chore/retire-migrate-from-sqlite-batch-a`,
tracking issue #3623). `mgmt_group_meta` — whose entire purpose was the backfill idempotency
marker — is dropped via a version-bumped `{2, "DROP TABLE IF EXISTS mgmt_group_meta;"}`
migration, appended after the already-shipped v1 rather than edited in place: this store IS
constructed in production, so v1 has actually run against real dev/UAT databases. `server.cpp`'s
boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows` over `management_groups`/
`management_group_members`/`management_group_roles` instead of the backfill — WARN-only (never
refuse-boot) on a real legacy row found, the same posture as every other store in this
retirement batch. The over-deep-tree guard this ADR's "Hierarchy traversal" section describes as
a backfill-time refusal has no remaining trigger — with the backfill gone, a corrupt/over-deep
tree can only arise via the write path, which already caps depth at 5.
