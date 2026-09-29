# ADR-0044: DiscoveryStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** pg workstream; security-guardian + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from ADR-0040/0041/0042
  (esp. `sanitize_pg_text`, fail-closed boot, mandatory-backfill-with-fingerprint-verification, the
  RbacStore ADR-0041 sourceless-fingerprint precedent this store ports).

## Context

`DiscoveryStore` (`discovery.db` today, `server/core/src/discovery_store.{hpp,cpp}`, ~250 lines)
holds network-discovered devices (Issue 7.18): raw scan results agents report before an operator
promotes a device to a managed agent. Single table (`discovered_devices`), three indexes, no
foreign keys, no secret-bearing columns. Tracked under issue #1328 (Postgres ladder 4c, leaf-store
batch).

The `managed` flag on a discovered device is operator-set state — an operator has looked at a
discovered IP and confirmed "yes, this is my enrolled agent." That confirmation, along with
first-seen discovery provenance (`discovered_at`/`discovered_by`), is real state that cannot be
re-derived from a re-scan. This is Wave 2's "operator state that cannot be lost" framing, not
purely ephemeral telemetry — backfill is therefore mandatory, matching `RbacStore`/`ManagementGroupStore`,
not `ResponseStore`'s unconditional-skip precedent.

## Decision

Migrate to PostgreSQL schema **`discovery_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. `sqlite3_changes()` (used by the legacy
`mark_managed`) is retired in favor of `RETURNING` (#1033). The SQLite `shared_mutex` is retired —
Postgres's real per-connection concurrency replaces the single-writer serialization.

### Schema

`discovered_devices` (id BIGSERIAL, ip_address UNIQUE, mac_address, hostname, managed BOOLEAN,
agent_id, discovered_by, discovered_at, last_seen, subnet) ports column-for-column from the
legacy SQLite schema, with `managed` becoming a native `BOOLEAN` (was SQLite `INTEGER`). A new
`discovery_meta` k/v table carries the one-time backfill marker + source fingerprint (see below).

### Reads — authoritative, type-distinguishable

Per the 2026-07-25 program policy (`docs/postgres-store-playbook.md` "Authoritative reads must be
type-distinguishable"), every read whose result could feed a fleet-visibility decision is
type-distinguishable from "no rows": `list_devices` returns `std::optional<std::vector<...>>`
(`nullopt` = degraded, empty vector = genuinely no devices); `get_device` returns
`std::expected<std::optional<DiscoveredDevice>, std::string>` (`unexpected` = degraded, a value
holding `nullopt` = genuinely absent). `GET /api/discovery/results` (`discovery_routes.cpp`) checks
for `nullopt` and returns 503 rather than rendering an empty device list — closing the fail-open
that a silently-empty discovered-device list would otherwise represent (an operator scanning for
rogue/unmanaged devices on the network must not be told "nothing found" when the real answer is
"could not ask").

### ON CONFLICT semantics (verified against the legacy implementation)

`upsert_device`'s `ON CONFLICT (ip_address) DO UPDATE` preserves the legacy SQLite behavior
exactly: `mac_address`/`last_seen`/`subnet` always refresh (most-recent-seen); `hostname`
refreshes only when the new value is non-empty (a scan that could not resolve a hostname does not
blank out a previously known one); `discovered_at`/`discovered_by`/`managed`/`agent_id` are NOT
touched by the conflict branch — a re-scan cannot silently un-manage an already-managed device or
overwrite first-seen provenance. `managed`/`agent_id` ARE part of the INSERT column list, so a
fresh insert honors caller-supplied values; the "untouched by a re-scan" guarantee applies only to
an already-existing row.

### Backfill (ADR-0009) — MANDATORY, fingerprint-verified

One-time, idempotent, fail-closed backfill from the legacy `discovery.db`, ported from the
`RbacStore`/#2703 sourceless-fingerprint mechanism (ADR-0040/0041 shape) and scaled down to one
table. The marker (`backfill_complete`) and a SHA-256 fingerprint of the migrated content
(`backfill_source_fingerprint`) are stamped together in one transaction — this closes the
"local source absence never creates terminal migration state on its own" hazard
(`docs/postgres-store-playbook.md`): a replica finding no local `discovery.db` cannot distinguish
"genuine fresh install" from "a sibling replica holds the real file," so a sourceless stamp is a
promotable sentinel, never a terminal fact. A later boot that still holds its own legacy file
verifies its fingerprint against the stored one before trusting the marker, refusing (fail-closed)
on a mismatch or an unreadable file. A 0-byte legacy file is checked in BOTH branches, but not the
same way, because "nothing to lose" is only actually true under different conditions in each:

- **First-ever migration for this fleet** (no marker yet): a genuine fresh install never has a file
  at this path at all (the old store only ever created one on first open), so a 0-byte file here —
  which SQLite opens as a valid empty database, indistinguishable downstream from the legitimate
  no-`discovered_devices`-table case — is always a truncated real database. Refused unconditionally.
- **A real migration has already completed for this fleet** (marker present, stored fingerprint
  real): a 0-byte file reappearing on this replica (e.g. a backup restore or container rebuild
  leaving an empty placeholder) is safe — the real content, wherever it came from, is already
  durable in Postgres — so the pre-existing "this replica's own file has nothing to lose" skip
  applies and boot is NOT refused.
- **The marker is present but stamped SOURCELESS** (no real migration has EVER completed for this
  fleet) AND this replica's own file is 0 bytes: still refused. This is the same ambiguity as the
  first case — a 0-byte file cannot be distinguished from "this replica's real content was
  truncated before this boot ever read it" — reachable here because a sourceless marker means
  nobody has migrated real content yet, so this replica's file is the only candidate for it.

Both new-in-this-fold refusals (the managed/agent_id reconciliation below, and the 0-byte guard)
trade a narrow new fail-closed-boot/availability risk for closing a silent-data-loss hole — the same
tradeoff already accepted for RbacStore/AuditStore/ManagementGroupStore's mandatory backfills. The
managed/agent_id case is reachable only by an actor already holding `Infrastructure:Write`
(Administrator/ITServiceOwner) during the narrow multi-replica migration window, with foreknowledge
of legacy managed IPs — not an anytime-equivalent-damage actor, since `managed` is protected from
live-scan overwrite post-migration (`upsert_device`'s `ON CONFLICT` never touches it).

Reconciliation after the insert transaction is two-layered. Row-count reconciliation alone is a
weak backstop (it can only catch an out-of-band concurrent delete between commit and count, not a
partial insert — the per-statement status check inside the transaction already aborts the whole
transaction on any INSERT failure) and, critically, cannot see a same-IP row that already existed
in Postgres: a legacy row that loses its `ON CONFLICT DO NOTHING` slot to a pre-existing row (e.g.
a fileless sibling replica that already stamped its own sourceless marker and started serving live
scans before this replica's backfill reached that IP) is invisible to a count that still balances.
A second, content-aware pass re-reads every conflict-skipped row this replica's legacy snapshot
recorded as `managed=true` and/or with a non-empty `agent_id` — the two fields `mark_managed`
always writes together as one atomic operator action — and refuses the marker if the row already
in Postgres does not carry the SAME value for both. `discovered_at`/`discovered_by` are
deliberately excluded from this check: `upsert_device`'s own `ON CONFLICT` clause already treats
whichever write lands first as authoritative for those two on every ordinary re-scan, so the
backfill does not need to hold them to a stricter standard than live traffic already does.

### Lifecycle

Construction moves inside `server.cpp`'s `if (pg_pool_ && !startup_failed_)` guard; a failed
migration or backfill sets `startup_failed_` (fail-closed boot, never serve on top of
partially-migrated discovery data). Added to both the `/healthz` and `/readyz` check lists.

## Considered and rejected

- **Skippable backfill** (the `ResponseStore` precedent): rejected — the operator-set `managed`
  flag is irreducible operator intent, not regenerable telemetry.
- **Plain marker-only backfill idempotency** (no fingerprint): rejected in favor of the
  fingerprint-verified shape — a marker-only scheme cannot distinguish "this replica's own
  completed migration" from "a different replica's migration this replica's data was never part
  of," which is exactly the multi-replica hazard `docs/postgres-store-playbook.md` documents as a
  measured defect class (RbacStore's own first port missed it).

## Consequences

- Discovered-device inventory, including the operator-set `managed` flag, is preserved across the
  cutover.
- `GET /api/discovery/results` gains a new 503 branch on a degraded read (previously: SQLite's
  local-file reads essentially never failed short of file corruption, so this failure mode was not
  practically reachable).
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"discoverystore"` `PgTestTemplate`
  (`tests/unit/server/test_discovery_store.cpp`); construction-fail-closed and backfill tests use
  plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- `mark_managed`/`clear_results` have no REST route today (only `upsert_device` via
  `POST /api/discovery/scan` and `list_devices` via `GET /api/discovery/results` are reachable) —
  pre-existing, unrelated to this migration.
- ~~`POST /api/discovery/scan`'s handler always responds `200`/audits `"success"` even when every
  individual `upsert_device` call fails~~ — **resolved** (fjarvis's PR #3064 re-review, in two
  stages: commit `1ef811b7f` made the handler track per-device failures and return `503` on total
  failure / `"status":"partial"` on a mixed batch, auditing `"success"`/`"partial_failure"`/
  `"failure"`; a follow-on commit renamed the audit outcome to `"partial"` to match this
  codebase's established convention, so the final state audits
  `"success"`/`"partial"`/`"failure"`). Remaining gap in the same area, still open: no write-side
  Prometheus degrade counter (unlike the read
  path's `yuzu_server_discovery_read_degrade_total`) — tracked as a follow-up issue.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory
fingerprint-verified backfill this ADR ported from `RbacStore` was real, working code
that never had real legacy data to protect.

`DiscoveryStore::migrate_from_sqlite()` and its private helpers (`sha256_hex`,
`legacy_has_table`, `sqlite_text`, `read_legacy_snapshot`, `append_field`,
`canonicalize_legacy_snapshot`, `fingerprint_legacy_snapshot`,
`legacy_discovery_fingerprint`, and the `LDevice` type) are removed
(`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623). `discovery_meta`
— whose entire purpose was the backfill idempotency marker — is dropped via a
version-bumped `{2, "DROP TABLE IF EXISTS discovery_meta;"}` migration, not edited into
v1: this store IS constructed in production, so v1 has actually run against real
dev/UAT databases. `server.cpp`'s boot path now runs
`legacy_sqlite_probe::warn_if_legacy_rows` over `discovered_devices` instead — silent
unless real rows are found, never blocks boot.
