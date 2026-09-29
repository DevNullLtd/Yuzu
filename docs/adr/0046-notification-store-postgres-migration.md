---
status: accepted
date: 2026-08-12
owner: platform (Postgres substrate migration)
deciders: engineering (per-store migration, ADR-0006 ladder Wave 2)
scope: server — `NotificationStore` (the dashboard toast/badge feed), its cutover from
  SQLite to PostgreSQL, and its first-boot backfill from the legacy `notifications.db`
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 2 → Done); docs/postgres-store-playbook.md
---

# 0046 — `NotificationStore` Postgres migration

## Context

`NotificationStore` (`server/core/src/notification_store.{hpp,cpp}`) is the small operator
notification feed behind `/api/notifications` — the dashboard's "Agent Enrolled", "Execution
Failed" toast/badge list. One flat table, no foreign keys, no secret-bearing columns. It has
been SQLite (`notifications.db`) since its introduction.

ADR-0006 commits every server store to Postgres. `docs/postgres-migration-ladder.md` classifies
this store under Wave 2 ("authoritative config / reference — operator state that cannot be
lost"), and the ladder's own Wave 2 section header applies no skippable-backfill carve-out to
it (unlike `ResponseStore`'s explicit ADR-0009 update for purely-TTL'd telemetry) — unread/
dismissed state is treated as real, if lower-stakes, operator-relevant state, not expendable
history.

## Decision

**Migrate `NotificationStore` to PostgreSQL as schema `notification_store`, table
`notifications`, with a mandatory, idempotent ADR-0009 first-boot backfill from the legacy
`notifications.db`.**

### Schema

- Schema name `notification_store` (ADR-0008 Update naming rule: `snake_case(FullClassName)`
  including the `Store` suffix).
- Table `notifications`: `id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY`, `ts_ms BIGINT`
  (epoch **milliseconds** — the SQLite predecessor's `timestamp` column was also milliseconds
  despite its unqualified name; renamed to `ts_ms` on the Postgres side to make the unit
  unambiguous, values unchanged), `level TEXT`, `title TEXT`, `message TEXT`, `read BOOLEAN`,
  `dismissed BOOLEAN`. Two indexes: `(read, ts_ms)` for the unread-feed query, and
  `(ts_ms DESC, id DESC)` matching `list_all`'s `ORDER BY` so pagination over a growing history
  does not force a runtime sort.
- A second table, `notification_meta` (key/value), records the one-time backfill completion
  marker and source fingerprint — see "Backfill" below.
- No secret-bearing columns. `level`/`title`/`message` are plain free text; no column requires
  `SecretCodec` (ADR-0010) or a verify-only hash.

### Posture (ADR-0012 §1), split by operation class

- **Construction and `migrate_from_sqlite`: AUTHORITATIVE / fail-closed.** A Postgres store
  that cannot open its schema, or a mandatory backfill that cannot complete, is a fatal startup
  error (`startup_failed_` in `server.cpp`) — the server refuses to serve on top of a
  partially-migrated schema, matching every other Wave 2 store's construction contract.
- **Runtime reads/writes (`create`/`list_unread`/`list_all`/`mark_read`/`dismiss`/
  `count_unread`): plain container/bool/void returns, never `std::expected`.** None of these
  feed an authorization, targeting, enforcement, or skip decision — the whole surface backs a
  dashboard badge and a display list. A transient DB error degrades the display (an empty
  list, a stale unread count, a toast that never persisted); it never silently grants, targets,
  or suppresses anything. This is the reviewer test from
  `docs/postgres-store-playbook.md` § "Authoritative reads must be type-distinguishable" applied
  and answered "no" — recorded here per that section's requirement that the split be argued
  explicitly, not just asserted in a header comment.

### Backfill (ADR-0009, mandatory)

One-time, idempotent `migrate_from_sqlite()`, right-sized from `RbacStore`'s (#2703)
post-hardening reference shape for this store's small, single-table, single-shot legacy
dataset:

- **Holder-side fingerprint verification.** The completion marker and a SHA-256 fingerprint of
  the migrated content are always stamped together, in the same transaction. A later boot that
  still holds a local legacy file re-fingerprints it and refuses to trust a pre-existing marker
  unless the fingerprints match (`docs/postgres-store-playbook.md` § "Local source absence never
  creates terminal migration state on its own", #2697) — closing the class of bug where a
  fileless replica's fresh-install stamp would let a sibling replica's real legacy data be
  silently skipped. **Consolidation semantic (chaos-review, Gate 5):** if N previously-independent
  server instances, each with genuinely different local `notifications.db` content, are pointed at
  one shared Postgres for the first time, whichever migrates first becomes the fleet's sole
  notification history — the other N-1 fail closed permanently (holder-side fingerprint mismatch)
  on every subsequent boot until an operator manually reconciles which legacy file is authoritative
  (move the losing replicas' files aside by hand once their content is confirmed disposable). This
  is the intended fail-loud behavior, not a defect — but there is no automated merge path, so an
  operator planning a multi-instance-to-shared-Postgres consolidation should expect to do this
  reconciliation by hand, one replica at a time.
- **Sourceless sentinel.** A legacy file that is absent, or present with no `notifications`
  table, stamps a `"sourceless"` fingerprint rather than being skipped outright — so a later
  replica that DOES hold real content can still tell the difference and refuse to be waved
  through by another replica's empty-handed marker.
- **Id-preserving, sequence-advanced insert.** Legacy row ids are preserved via
  `OVERRIDING SYSTEM VALUE` (the dashboard's `mark_read`/`dismiss` reference them by id), and
  the Postgres identity sequence is advanced past the migrated max id in the SAME transaction as
  the row inserts, so a post-backfill `create()` cannot collide with a backfilled row.
- **Insert-landed verification.** Each row insert uses `RETURNING id` and requires exactly one
  row back, rather than trusting `PGRES_COMMAND_OK` on `ON CONFLICT (id) DO NOTHING` (that
  status is true whether the row inserted or silently no-opped on a pre-existing conflicting
  id — `docs/postgres-store-playbook.md` anti-pattern). An explicit pre-backfill emptiness check
  inside the same transaction additionally refuses to backfill over any row this pass did not
  itself write, since `migrate_from_sqlite` only reaches the insert transaction when no
  completion marker exists yet — a non-empty table at that point cannot be this store's own
  prior successful backfill.
- **Backfill-transaction `statement_timeout`.** The transaction sets its own
  `SET LOCAL statement_timeout` to the backfill's own timeout constant (60s) as its first
  statement — the pool-wide connection default (30s) otherwise silently governs execution
  regardless of what timeout constant the caller passes to `with_txn_for` (that parameter only
  bounds the pool-ACQUIRE wait; `docs/postgres-store-playbook.md` anti-pattern "Assuming a
  per-operation timeout parameter bounds statement execution").
- **Windows-safe move-aside.** The legacy SQLite read handle is closed before the file is moved
  aside on both the real-content and sourceless-empty paths (`SqliteDb::close()` before
  `move_legacy_aside`) — Windows refuses to rename a file with an open handle
  (`ERROR_SHARING_VIOLATION`); this is the same fix `RbacStore`/`AuditStore` carry.
- **Rollback window**: the legacy file is retained until a successful move-aside (one release,
  per ADR-0009); backfill never mutates it.

## Consequences

- `NotificationStore` joins the fail-closed `pg_pool_ && !startup_failed_` construction block in
  `server.cpp`, alongside the other Wave 2 stores.
- No secrets-at-rest work is required (ADR-0010 out of scope for this store).
- `docs/postgres-migration-ladder.md`'s `NotificationStore` row moves from the Wave 2 table to
  the Done table, schema `notification_store`, posture `authoritative` (construction/backfill)
  with display-only runtime reads/writes.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory,
holder-side-fingerprint-verified backfill this ADR ported from `RbacStore` was real,
working code that never had real legacy data to protect.

`NotificationStore::migrate_from_sqlite()`/`migrate_from_sqlite_impl()` and their private
helpers/types (`sha256_hex`, `legacy_has_table`, `sqlite_text`, `read_legacy_snapshot`,
`append_field`, `canonicalize_legacy_snapshot`, `fingerprint_legacy_snapshot`,
`legacy_notification_fingerprint`, `LegacyNotification`, `LegacySnapshot`, `now_secs`) are
removed (`chore/retire-migrate-from-sqlite-batch-b`, tracking issue #3623).
`notification_meta` — whose entire purpose was the backfill idempotency marker — is
dropped via a version-bumped `{2, "DROP TABLE IF EXISTS notification_meta;"}` migration,
not edited into v1: this store IS constructed in production, so v1 has actually run
against real dev/UAT databases. `set_metrics()` and the `metrics_` member are also
removed — this store's ONLY metrics consumer was the backfill-result counter
(`yuzu_server_notification_backfill_total`), unlike sibling stores that also emit a
read-degrade counter through the same pointer. `server.cpp`'s boot path now runs
`legacy_sqlite_probe::warn_if_legacy_rows` over `notifications` instead — silent unless
real rows are found, never blocks boot. This store's runtime reads/writes were already
plain container/bool (deny-or-benign, never an authorization/targeting/enforcement
decision — see the header doc), so unlike an authoritative store, losing old
unread/dismissed history on a hypothetical real-data environment was always an
acceptable outcome, never a promotion of this change's actual risk.
