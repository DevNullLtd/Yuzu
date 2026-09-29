# ADR-0061: UpdateRegistry → PostgreSQL

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** pg workstream (ladder Wave 4 — non-`*Store` SQLite owners, #1328/#1325/#3653)
- **Parents:** ADR-0006/0007/0008 (+Correction) (Postgres substrate, fail-closed, schema-per-store
  naming), ADR-0009 (including its 2026-08-25 fresh-start-by-default amendment), ADR-0012
  (substrate/store contract); `docs/postgres-store-playbook.md`; `docs/postgres-migration-ladder.md`.
  Template-proving migration for the Wave 4 non-`*Store` SQLite owners (`PatchManager`,
  `DirectorySync`, `WorkflowEngine`, the `ExecutionTracker`/`ApprovalManager`/`ScheduleEngine`
  trio) — this PR's `legacy_sqlite_probe.hpp` helper is written here and reused by all of them.

## Context

`UpdateRegistry` (`server/core/src/update_registry.{hpp,cpp}`) is the OTA agent-update catalog:
one table (`update_packages`, PK `(platform, arch, version)`) recording each uploaded package's
sha256, filename, mandatory flag, and rollout percentage. It backs the gRPC `CheckForUpdate`/
`DownloadUpdate` handlers (`agent_service_impl.cpp`) and the admin "Settings → Updates" surface
(`settings_routes.cpp`). It was never enumerated on `docs/postgres-migration-ladder.md` — that
ladder only ever tracked `*Store` classes plus the auth DB — because it predates the `Store`
naming convention; found alongside six siblings on 2026-08-27 (#1328/#1325/#3653).

This is the smallest and lowest-risk of the seven: one table, five DB-touching methods
(`upsert_package`/`update_rollout_checked`/`remove_package`/`list_packages`/`latest_for`), no
cross-table joins, no secrets, no background thread. It is deliberately ordered first as the template-proving
migration for the batch.

## Decision

### Schema

Postgres schema `update_registry` — **no `Store` suffix**, per this ladder's Wave 4 naming
extension: ADR-0008's rule (`snake_case(FullClassName)` including `Store`) was written for
`*Store` classes; the six Wave 4 components are not named that way, so the schema keeps the exact
name already passed to `MigrationRunner::run` in the SQLite era (`"update_registry"`) rather than
inventing an artificial `update_registry_store`. One table:

```sql
CREATE TABLE update_packages (
    platform    TEXT    NOT NULL,
    arch        TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    filename    TEXT    NOT NULL,
    mandatory   BOOLEAN NOT NULL DEFAULT FALSE,
    rollout_pct INTEGER NOT NULL DEFAULT 100,
    uploaded_at TEXT    NOT NULL DEFAULT '',
    file_size   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (platform, arch, version)
);
```

`uploaded_at` stays **TEXT** (ISO-8601), not `TIMESTAMPTZ` — a byte-identical round-trip with the
pre-migration column, so no caller on either the write side (`settings_routes.cpp`'s upload
handler, which never actually sets it today — it defaults to empty string, unchanged) or the read
side needs to change. `mandatory` becomes a real `BOOLEAN` (was `INTEGER DEFAULT 0` in SQLite) —
an internal representation change with no wire-visible effect, since the struct field was already
`bool`.

### Posture (ADR-0012 §1)

**Construction is fail-closed** whenever OTA is enabled — a posture upgrade. `cfg_.ota_enabled`
defaults **`true`** (opt-out via `--no-ota`, not an opt-in flag). `ca_store`/`scim_store`'s own
fail-closed construction is already unconditional on every deployment with a live `pg_pool_`
(only their `/readyz`/`/health` *checks* are flag-gated, on `using_default_certs`/`scim_enable`
respectively — `using_default_certs` is itself typically true for an ordinary out-of-box
self-signed deployment, not an "off by default" case) — `UpdateRegistry` is the only one of the
three whose *construction itself* has an opt-out at all. So this now applies to the ordinary
default deployment, not a minority who opted in. The SQLite constructor had **no `is_open()`
check at all** at its `server.cpp` call
site: an open/migration failure left `update_registry_` pointing at a store whose every method
silently no-opped (`if (!db_) return;`), and the server served normally with OTA silently dead.
Now, `!is_open()` sets `startup_failed_` — a reachable database whose `update_registry` schema
can't be created/opened is a fatal startup error, same as every other migrated store. When
`--no-ota` is passed, `update_registry_` stays null exactly as before — unchanged behaviour.

**Runtime reads/writes deliberately keep their pre-migration fail-SOFT shape** — bare
`bool`/`optional<UpdatePackage>`/`vector<UpdatePackage>`, no `std::expected` widening. This is a
conscious application of the playbook's "deny-or-benign" carve-out (ADR-0036), stated explicitly
here per that rule's own requirement: applying the reviewer test to every read/write —

- `latest_for` (feeds `CheckForUpdate`/`DownloadUpdate`): a degraded read returns `nullopt`,
  which the gRPC handler reads as "no update available this cycle". An agent that misses an
  update this heartbeat asks again on the next one (agents poll continuously) — nothing is
  granted, targeted, enforced, or inverted by a false negative here; it is a missed opportunity,
  self-healing on retry.
- `list_packages` (feeds the admin Updates page and the delete route's package lookup): a
  degraded read returns an empty vector, which an admin reads as "no packages configured" and can
  re-check. No downstream branch treats an empty list as an authorization or enforcement signal.
  The **rollout route is the exception and no longer reads through this method** (#3692): it audits
  its outcome, so an empty-on-degrade read would assert in the evidence record that a package which
  exists did not. It calls `update_rollout_checked` instead, which reports a degraded store as
  distinct from absence — and, because the audited `from=` names the value the write replaced, does
  its read and write in ONE row-locked transaction rather than two autocommit statements.
- `upsert_package`/`remove_package`: already fire-and-forget in the SQLite era (no return value,
  errors logged only) — unchanged.

None of the four methods gate a grant, a target-selection, an enforcement decision, or a `NOT`
inversion, so this store does not fall under the mandatory-widening rule — it stays in the
explicitly-deferred "deny-or-benign" bucket alongside `OffloadTargetStore::fire_event`'s scan.

### No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment)

No `migrate_from_sqlite()`, no legacy-table-reading code. The legacy `update_packages.db` is
**never read for data** — no production Yuzu fleet has ever run a pre-Postgres build of this
store. Construction logs a one-time `UpdateRegistry initialized (schema update_registry) — fresh
start, no legacy backfill` line. `update_packages` holds no secret material (`sha256` is a public
content hash, not credential data), so there is no 0600-hardening obligation on the legacy file —
unlike `RuntimeConfigStore`/`WebhookStore`/`OffloadTargetStore`.

`server.cpp` calls the new shared `legacy_sqlite_probe::warn_if_legacy_rows(cfg_.db_dir() /
"update_packages.db", "UpdateRegistry", {"update_packages"})` right after a successful
construction: exists+non-empty check → read-only open → row count → `spdlog::warn` only when the
legacy file genuinely holds rows (silent otherwise, including the ordinary fresh-install case).
This is the FIRST use of `server/core/src/legacy_sqlite_probe.hpp`, a new shared helper
generalizing `RuntimeConfigStore::warn_if_legacy_data_present`'s single-table logic to an
arbitrary table list — written here specifically so the two Wave 4 siblings authored in parallel
(`PatchManager`/ADR-0062, `DirectorySync`/ADR-0063) can call it directly instead of each hand-
rolling a copy. Its interface takes no store-specific knowledge (path, store name for the log
line, table-name list) and does no 0600/secret hardening, since none of the Wave 4 non-`*Store`
components hold secret columns.

### Binaries stay node-local (pre-existing fact, not addressed here)

Only package **metadata** moves to shared Postgres. `update_dir_` — where uploaded package
binaries actually land on disk (`cfg_.update_dir`, default `db_dir()/agent-updates`) and what
`binary_path()`/the upload/download handlers read and write — stays a plain node-local filesystem
path, unchanged. On today's single-server design
(`docs/adr/2002-high-availability-architecture.md`: "Yuzu today is a single-server design") this
is a non-issue: metadata and binaries live on the same node either way. It becomes a real
consideration only if/when the server runs multi-replica, at which point ADR-2002's
fenced-leader/outbox model (already scoped there as a separate future workstream) is the right
place to resolve a shared-metadata/node-local-binary split — not something this migration
attempts to solve.

### Public API — unchanged

`upsert_package`/`remove_package`/`list_packages`/`latest_for`/`is_open`/`binary_path` keep
call-site-compatible pre-migration signatures (see "Posture" above for why the read/write shapes
are not widened) — `is_open()` additionally gained `[[nodiscard]] noexcept` and moved header-inline,
a source-compatible strengthening, not a byte-identical carry-over. `is_eligible` (static, pure)
and `binary_path` (pure) are untouched — no DB involved.
Both consumers (`agent_service_impl.cpp`'s gRPC OTA handlers, `settings_routes.cpp`'s Updates
admin routes) needed zero changes beyond the constructor call site in `server.cpp` — verified by
grep before this PR closed.

## Considered and rejected

- **Widening `latest_for`/`list_packages` to `std::expected`/`optional<vector<...>>`** (the
  `OffloadTargetStore`/`DeviceTokenStore` shape). Rejected per the Posture section above — neither
  read feeds a grant/target/enforce/skip/invert decision, so ADR-0036's deny-or-benign carve-out
  applies and the mandatory-widening rule does not bind here. Revisit if a future caller starts
  making a security-relevant decision from either read's emptiness.
- **`TIMESTAMPTZ` for `uploaded_at`.** Rejected — no caller benefits from a typed timestamp today
  (the column is set once at upload and never queried by range), and TEXT avoids any parse/format
  round-trip risk for zero-benefit churn.
- **A per-store `warn_if_legacy_data_present` static method** (the `RuntimeConfigStore` shape).
  Rejected in favor of the shared `legacy_sqlite_probe.hpp` free function — this store is the
  first of three Wave 4 migrations that need the identical detect-and-warn shape, and a shared
  generic helper (parameterized on table list) is a smaller total diff than three hand-rolled
  copies, with one reviewed implementation instead of three.

## Consequences

- **Any OTA package configured against a pre-Postgres build is lost on upgrade** — the operator
  re-uploads it via the Settings → Updates page (`POST /api/settings/updates/upload`). Package
  binaries already on disk under `update_dir_` are untouched by the cutover (only the metadata row
  is gone), so a re-upload of the same file reproduces the identical `sha256`/`file_size`.
- **OTA silently going dark at STARTUP is now loud — runtime degrade is unchanged.** Pre-migration,
  a broken `update_packages.db` open degraded every OTA check to "no update available" with no
  operator-visible signal beyond a log line. Post-migration, the equivalent failure AT
  CONSTRUCTION (a reachable Postgres whose `update_registry` schema can't migrate) refuses to
  start the server at all — an intentional behaviour change, consistent with every other migrated
  store's posture. A *runtime* degrade after a clean boot (a transient lease timeout or query
  error) is exactly as quiet as pre-migration by design (ADR-0036 deny-or-benign, see "Runtime
  reads/writes" above) — the loud-at-boot change does not extend to it. Gate 6 sre's own review
  round added `yuzu_server_update_registry_{read,write}_degrade_total{reason}` counters (mirroring
  `InstructionStore`'s convention) precisely because this runtime gap was otherwise the sole
  unalertable degrade path for this store — see `set_metrics` in `update_registry.hpp`.
- `security-guardian` + `docs-writer` review is structural for this PR (routed-concern row: any
  auth/RBAC-adjacent surface change — none here beyond the standard PG construction pattern — plus
  the standing docs-writer Gate 2 requirement on every change).

## Follow-ups

- `legacy_sqlite_probe.hpp` is reused, not modified, by `PatchManager`/ADR-0062 and
  `DirectorySync`/ADR-0063 — if either sibling needs a shape this helper doesn't support (per-row
  detail beyond a count, for example), extend the shared helper rather than forking it.
- The node-local-binaries-vs-shared-metadata split noted above is `docs/adr/2002-high-availability-architecture.md`'s
  concern once/if multi-replica ships — no action item here.
