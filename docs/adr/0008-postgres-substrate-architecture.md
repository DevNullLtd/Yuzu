---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-09
scope: platform — the shared server Postgres substrate layer (server/core/src/pg/)
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend)
---

# 0008 — Postgres substrate architecture: libpq + in-house RAII, shared pool, schema-per-store

## Context

ADR-0006/0007 commit the server to a single PostgreSQL backend. Before any store is written or
migrated, the shared substrate layer must be specified: the client library, the connection
model, the schema-migration mechanism, and how the one database is namespaced. The existing
SQLite layer sets the idioms to mirror: per-store `sqlite3*` handles guarded by a
`shared_mutex`, the `SqliteTxn`/`SqliteStmt` RAII owners (`server/core/src/sqlite_raii.hpp`),
the `MigrationRunner` (numbered `{version, sql}` migrations + a per-store `schema_meta` row,
`server/core/src/migration_runner.hpp`), the `RETURNING`/#1033 atomic-mutate idiom, and one
existing shared-connection pool (`InstructionDbPool`). The Windows build is a hard constraint:
the MSVC triplet forces **static** linkage (the #375 gRPC static-link saga).

## Decision

The substrate (new `server/core/src/pg/`) is:

- **Client library: raw `libpq` wrapped in in-house RAII** (`PgConn` owns `PGconn*`/`PQfinish`,
  `PgResult` owns `PGresult*`/`PQclear`, `PgTxn` is a direct port of `SqliteTxn`, plus a
  prepared-statement helper). Chosen over `libpqxx`: `libpq` is pure C with an OpenSSL-only
  dependency (we already static-link OpenSSL), giving the **lowest Windows MSVC static-link
  risk**, and it maps almost 1:1 onto the existing per-store `sqlite3*` idiom. We already
  hand-write RAII, so `libpqxx`'s ergonomics buy little and add a second C++ static-link surface.
- **Connection model: one shared in-process `PgPool`** (bounded set of `PgConn`, checkout-per-
  operation, pin-per-transaction), injected into every store in place of the per-store handle.
  This generalizes `InstructionDbPool` to the whole server, exploits Postgres's real
  concurrency (the per-store `shared_mutex` serialization goes away), and bounds backend
  processes. Synchronous `libpq` + a thread-safe pool fits the current thread model; no async.
- **Migrations: `PgMigrationRunner`**, a port of `MigrationRunner` — numbered `{version, sql}`
  migrations registered in C++ next to each store, applied against a shared
  `schema_meta(store, version, upgraded_at)` table. No external migration tool, no new runtime
  dependency, migrations stay co-located with store code exactly as today.
- **Namespacing: one Postgres SCHEMA per store** (`response`, `audit`, `guardian`,
  `vuln_graph`, …). Preserves the logical "29 separate stores" isolation and each store's own
  migration lineage, and turns the vuln-graph scoring join (`vuln_graph.edges ⨝
  guardian.state`) into a real qualified-name SQL join instead of an application-layer stitch.
- **No virtual backend interface.** Single-backend (ADR-0007) ⇒ stores stay concrete classes
  over `PgPool`; the only shared base is an optional thin ctor helper, not a polymorphic seam.

A **Windows static-link canary** (libpq linked on the MSVC static triplet running `SELECT 1`)
is built and verified **before** the substrate timeline is committed — the #375 lesson.

## Considered and rejected

- **`libpqxx`** — ergonomic C++ transactions/typed rows, but a second C++ static-link surface
  on the platform that produced the gRPC LNK2038/LNK2005 saga, duplicating RAII we own anyway.
- **Per-store dedicated connection** (1:1 with today's `sqlite3*`) — simplest mechanical port,
  but 29+ idle backend processes per server and it keeps the per-store mutex serialization.
- **An external migration tool (Flyway/Liquibase/sqitch)** — standard versioned-SQL tooling,
  but a heavy foreign dependency (JVM for Flyway/Liquibase), a separate file format, and
  out-of-process runs — alien to the in-C++ embedded-migration idiom and the Meson build.
- **Single shared `public` schema with table-name prefixes** — simpler `search_path`, but
  weaker isolation and noisier naming than schema-per-store.

## Consequences

- The substrate is a small, well-bounded set of new files (`pg_raii.hpp`, `pg_pool.{hpp,cpp}`,
  `pg_migration_runner.{hpp,cpp}`) that every later store builds on. Getting their ownership and
  exception-safety right (cpp-safety review) is load-bearing for the whole program.
- `RETURNING` is the mandated mutate-and-return idiom (the #1033 anti-pattern becomes moot per
  migrated store but the discipline carries over).
- `vcpkg.json` gains `libpq`; `meson.build` wires a `libpq_dep` with `include_type: 'system'`.
  The Windows static-link result from the canary can still reshape the timeline (fallback:
  dynamic libpq / dynamic Windows server) — which is exactly why the canary is first.

## Correction (2026-06-10) — Windows linkage is dynamic, and that was already the norm

The F0 canary (PR #1331, #1317) surfaced a false premise in this ADR's Context and Decision:
`triplets/x64-windows.cmake` does **not** force static linkage globally — its base is
`VCPKG_LIBRARY_LINKAGE dynamic`, with a static override scoped to the gRPC stack only
(`abseil|grpc|protobuf|upb|re2|c-ares|utf8-range`, the #375 fix). OpenSSL and sqlite3 are
already DLLs on Windows, bundled into the release zip by the vcpkg-bin DLL sweep
(`release.yml` packaging step). "We already static-link OpenSSL" above is therefore wrong
for Windows, and "the MSVC triplet forces static linkage" describes only the gRPC stack.

What the canary actually proved — and what the #375 lesson actually requires — is that
libpq **builds at the pinned baseline and links on MSVC with no LNK2005/LNK2038-class
errors**. It does, as a DLL + import lib, consistent with the existing Windows shipping
model: `libpq.dll` rides the same release-zip DLL sweep as `sqlite3.dll` and the OpenSSL
DLLs. **Decision consequence: the substrate proceeds with dynamic libpq on Windows.** If a
future requirement forces static libpq (e.g. single-file server distribution), add `libpq`
to the triplet's static-override regex and re-run the canary — the meson wiring already
lists the static closure (pgcommon/pgport + system libs) so no build-graph change is needed.
Linux/macOS remain fully static as assumed.

## Update (2026-06-22) — schema naming, non-transactional migrations, thin construction helper

Three refinements from the grill-with-docs session that fixed the author-facing store contract
(ADR-0012):

- **Schema name = `snake_case(FullClassName)`, the `Store` suffix included.** A store's Postgres
  schema is the snake_case of its full C++ class name *including* `Store`: `OfflineEndpointStore`
  → `offline_endpoint_store`, `ResponseStore` → `response_store`, `ApiTokenStore` →
  `api_token_store`. The rule is **rigorous equality** — the schema reads straight back to the
  class for troubleshooting — not the shorter purpose-names the Decision above illustrated
  (`response`, `audit`, `guardian`, `vuln_graph`); **treat those as `*_store` now.** Acronyms are
  single words (PascalCase already collapses them: `RbacStore` → `rbac_store`, `CaStore` →
  `ca_store`); all-caps acronyms are **forbidden** in store class names so the mapping stays
  one-to-one. The `PgMigrationRunner` identifier regex / reserved-name check is unchanged and
  remains the runtime backstop. The one shipped schema that predates this rule, `endpoint_state`,
  is **renamed to `offline_endpoint_store`** (implementation follow-up; safe pre-alpha — its data
  reconstructs from heartbeats).

  **Extension (2026-08-28, ADR-0062) — non-`*Store`-suffixed classes.** The 7-component "Wave 4"
  ladder blind spot found 2026-08-27 (`docs/postgres-migration-ladder.md`) includes components
  whose C++ class was never `*Store`-suffixed (`PatchManager`, `UpdateRegistry`,
  `WorkflowEngine`, …). For these, the rule above does not add a suffix that was never there: the
  schema is the name already passed to `MigrationRunner::run` in the pre-migration SQLite code
  (`PatchManager` → `patch_manager`, not `patch_manager_store`) — `snake_case(FullClassName)`,
  literally, with no suffix to append because none exists on the class.

- **Migrations stay transactional; the non-transactional kind is deferred, its rule pinned.** The
  Future-evolution note in `pg_migration_runner.hpp` stands: statements that cannot run in a
  transaction (`CREATE INDEX CONCURRENTLY`, `VACUUM`, `ALTER TYPE ADD VALUE`) cannot be a
  `PgMigration` today, and the non-transactional migration kind is **not built speculatively** (no
  store needs it). Rule for authors: initial DDL on a new/empty table uses normal transactional
  migrations (a plain `CREATE INDEX` on an empty table is fine); an index/DDL added to an
  **already-large** table during a live rolling upgrade requires the non-transactional kind, which
  **must be built (self-schema-qualifying, outside a txn) before that migration ships**. Do not
  weaken the transactional default to sneak one in.

- **The "optional thin ctor helper" becomes mandatory before the fan-out.** The Decision above
  left a thin non-polymorphic helper optional. With *all* stores migrating (ADR-0006 Update) over
  a uniform construction-fail-closed contract, the helper — `open_with_migrations(pool, schema,
  migrations)` plus a `server.cpp` construction helper that flips `startup_failed_` on
  `!is_open()` — is extracted **once** before the 28-store fan-out, so the fail-closed wiring is
  not hand-written 28 times. Non-virtual, no backend abstraction (ADR-0007/0008 compliant). This
  is an implementation follow-up.
