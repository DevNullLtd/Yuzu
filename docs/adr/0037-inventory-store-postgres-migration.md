---
status: accepted
date: 2026-07-25
owner: platform (Postgres substrate migration)
deciders: engineering (per-store migration, ADR-0006 ladder Wave 1)
scope: server — the generic `InventoryStore` (per-source inventory blob store), its cutover
  from SQLite to PostgreSQL, and its first-boot backfill from the legacy `inventory.db`
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract), ADR-0016 (agent daily-sync framework —
  `SoftwareInventoryStore`, the typed sibling this ADR explicitly does NOT touch)
related: docs/postgres-migration-ladder.md (Wave 1 → Done); docs/postgres-store-playbook.md
---

# 0037 — `InventoryStore` (generic per-source blob) Postgres migration

## Context

`InventoryStore` (`server/core/src/inventory_store.{hpp,cpp}`) is the sync-framework's generic
`(agent_id, plugin) -> data_json` blob store — the catch-all home for every inventory source
that has NOT been promoted to its own typed Postgres projection. It backs the scope-walking
`kInventoryQuery` source and the inventory eval engine (`inventory_eval.hpp`), and is read by
the generic `/api/inventory/*`, `/api/v1/inventory/*`, and MCP `query_inventory` /
`list_inventory_tables` / `get_agent_inventory` surfaces. It has been SQLite (`inventory.db`)
since Issue 7.17.

**This is a distinct store from `SoftwareInventoryStore`** (ADR-0016, schema
`software_inventory_store`), which is the typed, normalized projection for exactly one
source (`installed_software`). The typed sources (`installed_software`, `app_perf`,
`device_ci`, `software_licensing`) are already skipped by the generic ingest loop
(`is_typed_inventory_source`) so their rows never land in the generic store; every OTHER
plugin's blob still does. `docs/postgres-migration-ladder.md`'s Wave 1 entry for
`InventoryStore` explicitly called this out as "the generic store's own migration, still
pending" while `SoftwareInventoryStore` was already Done — this ADR closes that gap. The two
stores continue to coexist after this migration; neither routes into the other.

ADR-0006 commits every server store to Postgres; this store carries pre-existing SQLite data
(agents' last-reported inventory for every non-typed source), so ADR-0009's standard
first-boot backfill mechanism applies (unlike, e.g., `ApiTokenStore`'s ADR-0030 fresh-start
override — there is no secrets-at-rest reason to discard this data, and losing an agent's
last-reported custom-plugin inventory on upgrade would be a regression the fresh-start
argument does not justify here).

## Decision

**Migrate `InventoryStore` to PostgreSQL as schema `inventory_store`, table
`inventory_data`, with a standard ADR-0009 first-boot backfill from the legacy
`inventory.db`.**

### Schema

- Schema name `inventory_store` (ADR-0008 Update naming rule:
  `snake_case(FullClassName)` including the `Store` suffix).
- Table `inventory_data` carries the existing columns unchanged in meaning and type mapping
  (SQLite `TEXT` → Postgres `TEXT`, SQLite `INTEGER` → Postgres `BIGINT`, epoch **seconds**
  unchanged): `agent_id`, `plugin`, `data_json`, `collected_at`, primary key
  `(agent_id, plugin)` (an upsert target, unchanged). The two SQLite secondary indexes
  (`plugin`, `collected_at`) carry over as Postgres indexes on the same columns.
- A second table, `backfill_state` (single sentinel row, `id = 1`), records that the
  first-boot backfill has run — see "Backfill" below.
- Generic plugins must not emit credentials or secret material: `data_json` is plaintext and
  its sensitivity is otherwise plugin-dependent. A plugin that needs secret-at-rest storage
  must use an ADR-0010 envelope-backed store rather than this generic blob channel.

### Posture (ADR-0012 §1), split by operation class

- **Ingest (`upsert`): FAIL-SOFT.** A transient lease/query failure is logged and the call
  returns without throwing — it must never block the gRPC/gateway ingest thread. The agent's
  next changed/full report re-sends the same blob (bounded by the weekly full floor), so a
  dropped write self-heals. This mirrors
  `SoftwareInventoryStore`'s ingest posture exactly.

  **Stale-overwrite guard + agent-clock clamp (governance H2, 2026-07-29).** The Postgres
  upsert adds a conflict predicate the SQLite implementation did not have:
  `... DO UPDATE SET ... WHERE EXCLUDED.collected_at >= inventory_data.collected_at`, so a
  reordered/duplicate OLDER report can never clobber a newer row. Because that predicate
  compares the **agent-supplied** `collected_at`, the incoming value is first **clamped to
  server receipt time** (`min(collected_at, now)`, with `0 → now` as before) — without the
  clamp, one future-skewed or hostile report pins its row forever while every later honest
  report silently updates zero rows (the exact defect the sibling `SoftwareInventoryStore`
  fixed in #1685 / ADR-0016 Update 2026-06-27, and the standing clock-guard rule: on an
  endpoint the user controls, a quiet reset IS the bypass). A conflict-predicate suppression
  (zero rows updated on a genuinely-older report) is observable: it bumps
  `yuzu_inventory_ingest_dropped_total{reason="stale"}` and a debug log — never a silent
  success. Rows written by a pre-clamp deployment drain naturally as their stored
  `collected_at` ages past `now`; no PostgreSQL-to-PostgreSQL migration clamp is needed because
  this store ships the guard and clamp together. The one-time SQLite backfill does clamp legacy
  future-skewed timestamps to migration receipt time, preventing a pre-cutover row from pinning
  later honest reports; this deliberately changes only invalid future ordering values.
- **Reads (`list_tables`, `get`, `query`, `get_agent_inventory`, `count`): AUTHORITATIVE.** A
  store/pool/query failure is reported as a degrade — `std::nullopt` for the list/count reads,
  `std::unexpected(InventoryReadError::kDegraded)` for the single-record `get` (mirroring
  `DeviceInventoryStore::CiReadError`'s three-state `get_device_ci` exactly, since `get` has a
  genuine found/absent/degraded three-state contract that a plain `std::optional` cannot
  express without conflating "not found" and "could not read") — **never a silent empty**. An
  empty *value* is a genuine zero-row result; a degrade means the store could not be read at
  all. Every REST (`/api/inventory/*`, `/api/v1/inventory/*`) and MCP
  (`query_inventory`/`list_inventory_tables`/`get_agent_inventory`) call site was updated to
  surface a degrade as a 503 / internal-error response rather than folding it into an empty
  200/success — closing the exact fail-open anti-pattern the playbook forbids
  ("An authoritative store that returns an empty result on a DB error").
  Query materialisation is bounded by both row count and an 8 MiB aggregate payload budget;
  either cap raises the same truncation signal, and targeting-set creation refuses it with 503.
- **`delete_agent`**: erases PostgreSQL and, during the rollback window, the retained SQLite
  copy. It returns true only when both backing deletes commit, so `AgentDecommission` records
  Failed rather than allowing rollback to resurrect an erased device.

### Backfill (ADR-0009) — standard, mandatory, idempotent, fail-closed

`migrate_from_sqlite(legacy_db_path)` runs once at server startup, before serving, inside the
`if (pg_pool_ && !startup_failed_)` construction block in `server.cpp`, right after the store
opens:

- **Idempotency**: a single-row `backfill_state` table (`id = 1`, stamped with
  `migrated_at`, inserted-row count (`legacy_rows`), total `source_rows`, conflicts, blank-key
  skips, typed-source skips, and `skipped_bad`). A completed stamp with `skipped_bad > 0` means
  rows exceeded the explicit 8 MiB pre-copy legacy-blob bound or were filed as malformed on
  SQLSTATE class 22 (data), 23 (integrity), or 54 (a row-specific program limit). Every
  other/unknown SQLSTATE aborts the backfill unstamped, so an infrastructure retry is never
  lost silently. Every later boot is a cheap lookup; the legacy SQLite file is not re-read
  once stamped.
  The full reconciliation identity for an auditor is
  `source_rows = inserted (legacy_rows) + conflicts + skipped_bad + skipped_blank_key +
  skipped_typed`; every term is durable in `backfill_state`.

  **Operator recovery when the backfill fails closed** (Gate 4 UP-1/UP-2): a legacy row
  failing with a non-row-data SQLSTATE aborts the backfill unstamped and the server
  refuses to boot on every restart until resolved. The escape hatch is moving the legacy
  `inventory.db` aside — the missing-file path stamps `legacy_rows = 0` and boots. Treat the
  moved file as an operator-managed personal-data backup: restrict access, retain it no longer
  than the one-release rollback window, delete a decommissioned subject from it manually, and
  purge it after repair/manual import with that action recorded as erasure evidence. Live
  gateway-connected agents re-push generic blobs on their next changed/full report (bounded by
  the weekly full floor), not necessarily the next hash-only cycle. The direct
  `ReportInventory` path currently carries typed sources only, so direct-connected,
  decommissioned, and offline agents' generic rows require manual import from the retained
  legacy file if needed.
- **Typed-source isolation**: legacy `installed_software`, `app_perf`, `device_ci`, and
  `software_licensing` blobs are not copied into the generic store. Their typed stores have
  distinct securables; preserving the old generic duplicate would expose them through
  `Infrastructure:Read` after upgrade.
- **Never clobbers a live row**: every backfilled row is inserted
  `ON CONFLICT (agent_id, plugin) DO NOTHING` — if a live agent has already re-reported for
  that `(agent_id, plugin)` pair since this boot sequence started (a race the boot-time
  ordering makes possible only in the narrow window between store-open and backfill-run), the
  live row wins, never the stale legacy copy.
- **Fails CLOSED**: any legacy-open/read error, transaction/control-statement error, or
  non-row-data PostgreSQL write error returns `false`; only SQLSTATE classes 22/23/54 are
  skipped as malformed row data. `server.cpp` treats `false` as a fatal startup error
  (`startup_failed_ = true`) — the server refuses to serve half-migrated inventory data,
  exactly as ADR-0009 requires.
- **Rollback-copy access**: backfill opens legacy `inventory.db` read-only. It is retained for
  exactly one release, but a successful device decommission deletes that agent's rows from
  both copies; this narrow mutation preserves the stronger erasure invariant across rollback.
- **Lease discipline note**: the idempotency check and the backfill-insert transaction each
  acquire their own single connection and release it before the other begins — holding two
  connections concurrently from this one call would deadlock a size-1 pool (e.g. a test
  pool), which the implementation avoids by construction (see the doc comment on
  `migrate_from_sqlite` in `inventory_store.hpp`). The insert transaction intentionally remains
  open while SQLite is stepped so all inserts and the reconciliation stamp commit atomically.
  This is ADR-0012's narrow one-time exception: it runs fail-closed before this server serves,
  streams at most one capped blob, and never applies to a runtime request.
- **Cost**: the backfill streams one SQLite row at a time through one PostgreSQL transaction,
  so peak process memory is bounded to one legacy blob (8 MiB maximum) rather than total
  legacy-store size.
  Inserts remain one statement per row under SAVEPOINT; batching is a future throughput
  optimization, not a memory-safety prerequisite.

## Considered and rejected

- **Fresh-start, no backfill** (the ADR-0030 `ApiTokenStore` pattern). Rejected: unlike a
  bearer token (cheap, self-service to re-mint), an agent's last-reported custom-plugin
  inventory is not something an operator can trivially regenerate on demand — the agent must
  re-collect and re-report it, and until it does, the fleet's inventory view for that plugin
  is silently incomplete. The standard ADR-0009 backfill is cheap here (no secret-material
  transform needed, unlike `auth`/`webhooks`), so there is no complexity reason to skip it
  either.
- **Splitting `get`'s degrade signal into a plain `std::optional<InventoryRecord>`** (folding
  degrade and not-found into one `nullopt`). Rejected — this is exactly the fail-open
  ambiguity `DeviceInventoryStore::CiReadError` was introduced to close; a caller cannot tell
  "no inventory reported yet" (safe to render as empty) from "the store could not be read"
  (must render a degrade banner / 503) without the three-state `std::expected` shape.
- **Merging this store into `SoftwareInventoryStore`** (one schema for all inventory). Rejected
  — out of scope and explicitly disclaimed by `docs/postgres-migration-ladder.md`; the two
  stores serve different shapes (generic untyped blob vs. typed normalized rows for one
  source) and different query patterns, and merging them would be a product change, not a
  substrate migration.

## Consequences

- `InventoryStore` moves from `sqlite3*` to `pg::PgPool&`. Construction follows the standard
  born-on-PG idiom (a pinned `pool_.acquire()` lease + `PgMigrationRunner::run(lease, kStoreName,
  migrations())` + `open_ = true`) and is wired into `server.cpp` inside the
  `if (pg_pool_ && !startup_failed_)` guard, immediately followed by the
  `migrate_from_sqlite()` call — both failure paths (`!is_open()` and a failed backfill) flip
  `startup_failed_`. Declared after `pg_pool_` in the member list, so it destructs before the
  pool (`server.cpp`'s existing declaration-order convention).
- All runtime statements schema-qualify `inventory_store.inventory_data` (and
  `inventory_store.backfill_state`); every mutate-and-return path checks the `PgResult`
  status directly rather than `sqlite3_changes()` (#1033) — none of this store's mutators
  needed `RETURNING` specifically (no caller consumes an affected-row count), but the
  `sqlite3_changes()` anti-pattern itself does not carry over regardless.
- Every REST (legacy `/api/inventory/*` in `server.cpp`; `/api/v1/inventory/*` in
  `rest_api_v1.cpp`, including the `evaluate` and `from-inventory-query` result-set-producer
  routes) and MCP (`mcp_server.cpp`) call site was updated for the new
  `std::optional`/`std::expected` return shapes, surfacing a degrade as 503 /
  `kInternalError` rather than an empty success response.
- `docs/postgres-migration-ladder.md`'s `InventoryStore` row moves from Wave 1 to Done, citing
  this ADR.
- The legacy `inventory.db` stays on disk for one release per ADR-0009; backfill opens it
  read-only, while wired device erasure may delete rows so rollback cannot resurrect data. Its
  removal is a follow-up for the release after this one ships.

## Follow-ups and accepted risks

- **Backfill is row-by-row, not batched.** Acceptable for a one-time boot cost at today's
  scale (see "Cost" above); a batched `unnest()` insert is the follow-up if a fleet's legacy
  table ever proves large.
- **Pre-existing, harmless dead wiring noticed while touching this code**: `server.cpp`'s
  early "wire up store pointers for AgentServiceImpl" block calls
  `agent_service_.set_inventory_store(inventory_store_.get())` BEFORE `inventory_store_` is
  constructed later in the same constructor, so that call always sets a null pointer in
  practice. This is harmless: `AgentServiceImpl::inventory_store_` (the setter's target) is
  never actually READ anywhere in `agent_service_impl.cpp` — the direct `ReportInventory` path
  intentionally does not upsert generic (non-typed) sources into the generic store (documented
  gov architect A-1 / consistency S1 asymmetry: only the gateway path threads generic sources
  through today). Predates this migration; left unchanged here since fixing the ordering would
  be the first step toward a behavior change (wiring a currently-unused seam) beyond this
  substrate migration's scope — flagged for whoever picks up that generic-source direct-path
  work.
- **No new row-cap was previously enforced on `query()`'s caller-supplied `limit`**; this
  migration adds a defensive hard ceiling (`kQueryRowCap`, matching the sibling stores'
  pattern) independent of the callers' existing 1000-row REST-level caps, purely as
  belt-and-braces against a future uncapped caller.

## Update (2026-09-03) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production Yuzu
fleet has ever run a pre-Postgres build of any store — the one-time first-boot backfill this ADR
designed was real, working code that never had real legacy data to protect. This also disposes
of the "Backfill is row-by-row, not batched" follow-up above and the "legacy `inventory.db`
stays on disk... removal is a follow-up" line in "Consequences" — there is no backfill left to
batch, and nothing left reading the legacy file at all.

`InventoryStore::migrate_from_sqlite()` is removed (`chore/retire-migrate-from-sqlite-batch-a`,
tracking issue #3623) — this store had no separate legacy-introspection helper functions (unlike
RbacStore/QuarantineStore/ManagementGroupStore); its SQLite reading logic was entirely inline in
the one function. `backfill_state` — whose entire purpose was the backfill idempotency stamp —
is dropped via a version-bumped `{5, "DROP TABLE IF EXISTS backfill_state;"}` migration, appended
after the already-shipped v1-v4 rather than edited in place: this store IS constructed in
production, so v1-v4 have actually run against real dev/UAT databases.

**`delete_agent()`'s retained-legacy-file erasure branch is also retired**, along with the
`legacy_db_path_` member that fed it (its sole writer was `migrate_from_sqlite`). This is a
deliberate, explicit decision, not an oversight: a leftover legacy `inventory.db` is now never
read and never scrubbed by this store. Unlike the protective-control stores in this same
retirement batch (Rbac/ManagementGroup/Quarantine), a stale row here is recoverable inventory
data, not lost security state — an operator who needs it gone must delete the file manually. See
`docs/user-manual/upgrading.md`'s new InventoryStore section for the operator-facing note.

`server.cpp`'s boot path now runs `legacy_sqlite_probe::warn_if_legacy_rows` over
`inventory_data` instead of the backfill — WARN-only, never refuse-boot, same posture as every
other store in this retirement batch. No dedicated backfill metric or alert existed for this
store, so none is removed.
