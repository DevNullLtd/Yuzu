---
status: accepted
date: 2026-08-19
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 batch-5 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2)
scope: server — `ProductPackStore` (operator-installed product packs), its cutover from SQLite to
  PostgreSQL, its ADR-0009 backfill, and its `install()` lease-discipline restructure
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract), ADR-0036 (authoritative-read type-distinguishability)
related: docs/postgres-migration-ladder.md (Wave 2 -> Done); docs/adr/0048-license-store-postgres-migration.md
  (closest precedent for the two-table fingerprinted backfill shape); ADR-0036 (`ResultSetStore`,
  the closest precedent for a real internal FK between two migrated tables)
---

# 0054 — `ProductPackStore` Postgres migration (authoritative, with backfill)

## Context

`ProductPackStore` (`server/core/src/product_pack_store.{hpp,cpp}`) persists operator-installed
product packs — multi-document YAML bundles that install into the `InstructionStore`/
`PolicyStore`/`WorkflowEngine` catalogs via a caller-supplied `ItemInstallFn`/`ItemUninstallFn`
(`docs/Instruction-Engine.md`: `InstructionDefinition -> InstructionSet -> ProductPack`). It is a
Wave 2 store on `docs/postgres-migration-ladder.md`. It was previously a SQLite store
(`product-packs.db`), guarded by a single `shared_mutex`.

Two tables, one real internal foreign key: `product_pack_items.pack_id -> product_packs(id) ON
DELETE CASCADE`. `install`/`uninstall` already returned `std::expected<..., std::string>`
pre-migration (#802/W7.4 signed-pack hardening); `list`/`get` were plain container/`optional`
returns.

**Coupling note:** `InstructionStore` references only `ProductPackStore::verify_signature` (a
static, storage-independent method) — not the store instance. No caller sweep was needed there.
The real callers are `workflow_routes.cpp` (`POST/GET/DELETE /api/product-packs*`, the sole
production install/uninstall/list/get call sites) and `server.cpp` (construction + wiring).

## Decision

### Schema

`product_pack_store`, per ADR-0008's `snake_case(FullClassName)` rule.

### Secrets (ADR-0010)

None. Verified against `docs/Instruction-Engine.md` and `docs/yaml-dsl-spec.md`: neither defines
a secret-typed or credential-bearing YAML field. The only crypto-adjacent fields are the pack's
`signature`/`publicKey` pair, which are public Ed25519 material, not secrets — `SecretCodec` does
not apply.

### Posture

AUTHORITATIVE / fail-hard (ADR-0012 §1), both construction and runtime. Packs are
operator-installed content (build-time-seeded packs plus operator additions), not a cache or
derived aggregate — a silently-empty `list`/`get` on a DB blip would misreport the installed
catalog. `install`/`uninstall` kept their pre-migration `std::expected` shape; `list`/`get` are
widened to `std::expected` (ADR-0036) — `get` returns `std::expected<std::optional<ProductPack>,
std::string>`, matching `LicenseStore`/`ResultSetStore`'s `get` shape exactly, so a genuine DB
error is never collapsed into "no packs installed" / "not found".

None of these reads feed an authorization/targeting/enforcement decision (unlike
`ResultSetStore`'s `member_set_owned` or `TagStore`'s `get_values_for_keys`) — a degraded read
here degrades a dashboard/REST catalog view, not a `NOT`-invertible scope match. The widening is
still done, both for `std::expected`-return consistency with `install`/`uninstall` on the same
class, and because `workflow_routes.cpp`'s REST handlers can now return an honest 503 instead of
rendering an empty pack list / a false 404 on a DB blip.

### `install()` lease discipline (the one behavioral restructure)

The pre-migration SQLite version wrapped the *entire* install — the pack-metadata `INSERT` and
every per-document `install_fn` call into `InstructionStore`/`PolicyStore`/`WorkflowEngine` — in
one `BEGIN IMMEDIATE` on `db_`. Under the Postgres substrate that shape is forbidden
(`docs/postgres-store-playbook.md`: "never call another store while holding a lease" — those
sibling stores draw from the SAME shared `PgPool`, so holding our own lease while they try to
acquire theirs risks starving a saturated pool).

This was never a genuine cross-store transaction, even pre-migration: `install_fn`'s callees
write to THEIR OWN `db_`/pool, never ours, so a rollback of the SQLite transaction never undid an
already-succeeded sibling install from an earlier loop iteration either. The migration makes that
existing atomicity boundary explicit instead of accidentally-shaped:

1. `install_fn` is called for every document with **no `pool_` lease of ours held** — it is free
   to call its own sibling stores without risking pool starvation.
2. Once every document is resolved (installed or errored), if `installed_count == 0` the method
   returns `unexpected(...)` **without ever touching Postgres** — no rollback needed, because
   nothing was written.
3. Otherwise the pack row and every successfully-installed item row are written in **one**
   `pool_` transaction, parent-before-child (`product_packs` before `product_pack_items`,
   satisfying the FK).

One behavioral tightening falls out of this restructure: the pre-migration `store_item()` helper
silently swallowed a prepare/insert failure (no error path at all) — a duplicate `item_id` within
one bundle was silently dropped rather than surfaced. The migrated version's item `INSERT` runs
inside the same transaction as the pack row; any failure (including a genuine PK collision on
`(pack_id, item_id)`) now rolls back the whole write and `install()` returns a
`kProductPackDbErrorPrefix`-prefixed error. This matches this migration wave's "write paths
surface failures — no bool-swallowing" convention; it was never intentional pre-migration
behavior worth preserving.

### Concurrency (`mtx_` dropped)

The pre-migration `shared_mutex` is dropped — Postgres's MVCC plus the pool's own
connection-level concurrency replace the SQLite single-writer mutex, matching every other
migrated store on the ladder. Accepted, recorded trade-off: two concurrent `uninstall(id, ...)`
calls for the SAME id can both pass the `get(id)` existence check and both invoke `uninstall_fn`
on the sibling stores before either's delete transaction runs. The sibling-store uninstalls are
themselves tolerant of a missing item (a `false` return, logged, not fatal), and the final
Postgres `DELETE ... WHERE id=$1` is harmless if the row is already gone. A small race window, not
a security boundary — `ResultSetStore`'s per-owner quota/pin-limit soft-enforcement (ADR-0036) is
the ladder's precedent for recording this class of trade explicitly.

### `/readyz` / `/healthz`

Already wired pre-migration (`server.cpp`'s combined `/livez`/`/readyz`/`/health` handler,
`{"product_pack_store", product_pack_store_ && product_pack_store_->is_open()}`) — unchanged by
this migration; `is_open()` never flips post-construction, so this stays belt-and-braces.

### Backfill (ADR-0009)

Mandatory — packs are irreducible operator intent, not expendable telemetry. Content-fingerprinted
(SHA-256 over both tables' canonicalized rows, or a `"sourceless"` sentinel), not a single
fleet-wide completion flag — `LicenseStore`'s two-table backfill (ADR-0048) is the closest
reference:

- **Half-schema detection.** The shipped pre-migration binary always creates `product_packs` and
  `product_pack_items` together in one migration step (schema v1) — a legacy file holding exactly
  one of the two is not producible by any released version and is treated as corrupt/hand-edited,
  fail-closed.
- **Pre-7.13 `verified`-column vintage.** The pre-migration SQLite constructor ran a raw `ALTER
  TABLE product_packs ADD COLUMN verified ...` on every boot, *outside* the migration list, to
  backfill the column onto pre-7.13 databases (v1's `CREATE TABLE IF NOT EXISTS` is a no-op on an
  already-existing table). This migration folds `verified` into schema v1 directly — the Postgres
  schema is born fresh, so the raw-`ALTER` shim has no reason to exist. `migrate_from_sqlite`
  still reads a pre-7.13 legacy file correctly: it probes `product_packs` for a `verified` column
  (`pragma_table_info`) before selecting it, and defaults `verified=false` for that vintage — the
  same default the pre-migration shim's `DEFAULT 0` produced. Both vintages of otherwise-identical
  data therefore fingerprint identically.
- **No IDENTITY/LIFECYCLE conflict split.** Unlike `LicenseStore` (whose `status`/`acknowledged`
  columns mutate post-insert) or `DeploymentStore` (status-machined), **no runtime method on
  `ProductPackStore` ever `UPDATE`s a `product_packs` or `product_pack_items` row after
  `install()` inserts it** — `verified` is set once, at insert time, from the signature-check
  result, and never revisited. Every column on both tables is therefore write-once/immutable, so
  a backfill conflict has only one legitimate cause (a cloned/restored legacy file backfilled on
  more than one replica against `id`, a 128-bit random surrogate — not an independent-generation
  collision) and only one correct response: read back and require full-row equality, fail closed
  on any mismatch. This is simpler than `LicenseStore`'s IDENTITY/LIFECYCLE partition by
  construction, not by omission — there is no lifecycle column to partition.
- **Ordering.** `product_pack_items.pack_id` references `product_packs.id` (a real FK, not a soft
  reference like `LicenseStore`'s `license_alerts.license_id`) — every legacy pack row is inserted
  before any legacy item row in the single backfill transaction, satisfying the FK trivially
  (parent and child are different tables here, unlike `ResultSetStore`'s self-referencing
  `parent_id`, which needed row-level topological order within one table).
- Legacy `product-packs.db` retained read-only for one release, per the standard rollback window.

**Update (2026-08-23, erasure consistency — governance Gate 8, ADR-0009 update note):** the
above did not originally address what stops a redeployed or newly-joined replica's own
(untouched) legacy file from resurrecting a pack that was legitimately uninstalled elsewhere —
`migrate_from_sqlite` re-checks its content-fingerprint marker on *every* boot, not just the
fleet's first migration, so this is reachable on an ordinary rolling redeploy, not only a
contrived scenario. Closed via a `deleted_pack_ids(pack_id, deleted_at)` tombstone table:
`uninstall()` stamps a row into it in the same transaction as its deletes; the first time a
given legacy file's exact content is seen (its whole-file fingerprint has no prior marker),
`migrate_from_sqlite` checks the tombstone before treating an unmatched legacy pack id as
fresh content, skipping both the pack row and its item rows together (avoids a
`product_pack_items -> product_packs` FK violation against a never-inserted parent) — a
later pass against byte-identical content is a safe no-op fingerprint-skip, not a repeat
tombstone check, because that content was already fully reconciled in the transaction that
stamped its marker. Both writers coordinate through a
`pg_advisory_xact_lock` (`kErasureCoordLockSql`, mirroring `RbacStore`'s
`kRevokeCoordLockSql`/CHAOS-1 fix for the identical check-then-insert race shape) taken as the
first statement in each transaction — without it, a concurrent `uninstall()` committing between
one replica's tombstone SELECT and its subsequent pack INSERT is invisible to that SELECT's
already-taken READ COMMITTED snapshot. `deleted_pack_ids` is never pruned, by design (mirrors
`revoked_seed_defaults`); low-cardinality operator-driven content makes unbounded retention a
non-issue at realistic scale, and pruning would reopen the exact hazard this table exists to
close. Full reasoning for the deliberate scope of this fix — and what it does NOT close (a
rollback to the pre-migration binary, which never queries Postgres) — is recorded in ADR-0009's
`ProductPackStore`/ADR-0054 update note; that residual is accepted as store-scoped, not a
general precedent.

## Considered and rejected

- **Keeping the SQLite-era whole-install transaction (metadata insert + `install_fn` calls) under
  one `pool_` lease.** Rejected outright — forbidden by `docs/postgres-store-playbook.md`'s
  never-hold-a-lease-across-another-store-call rule, and unnecessary: the transaction never
  actually spanned the sibling stores' own writes even pre-migration (see Decision above).
- **A LIFECYCLE partition mirroring `LicenseStore`'s backfill conflict handling.** Rejected — no
  runtime method mutates a row after insert, so there is no lifecycle state to partition against
  identity. Building the machinery anyway would be complexity with nothing to protect.
- **Silently keeping `store_item()`'s pre-migration swallow-on-failure behavior.** Rejected —
  contradicts this wave's "write paths surface failures" convention (ADR-0043 lesson, repeated on
  every subsequent Wave 2 store); a duplicate item silently vanishing from an installed pack is a
  correctness bug, not a feature worth preserving.

## Consequences

- `list()`/`get()` callers (`workflow_routes.cpp`'s `GET /api/product-packs`/`GET
  /api/product-packs/:id`) now handle a `std::expected` failure and return 503 on a genuine DB
  error, rather than an empty list / a bare "not found" that conflated a DB blip with an honest
  negative result.
- `uninstall()`'s `"not_found: "` prefix is a REST contract change on `DELETE
  /api/product-packs/:id` — a missing id now returns 404 instead of the pre-migration 400
  (`workflow_routes.cpp`'s `product_pack_error_status` classifies `"not_found:"` -> 404,
  `kProductPackDbErrorPrefix` -> 503, else -> 400, mirroring `rest_api_v1.cpp`'s
  `license_error_status`).
- A duplicate `item_id` within one install bundle now fails the whole install with a DB error
  instead of silently dropping the duplicate item (see Decision — a deliberate fix, not a
  regression).
- No change to the `#802`/W7.4 signed-pack enforcement semantics, the Ed25519 verify path, or the
  `--allow-unsigned-packs` operator flag — all pure/storage-independent and ported unchanged.

## Update (2026-09-02) — `migrate_from_sqlite()` retired

ADR-0009's fresh-start-by-default amendment (2026-08-25) establishes that no production
Yuzu fleet has ever run a pre-Postgres build of any store — the mandatory,
fingerprint-verified backfill this ADR designed (with its `deleted_pack_ids`
cross-replica-resurrection guard, Gate-8-reviewed as F035) was real, working code that
never had real legacy data to protect.

`ProductPackStore::migrate_from_sqlite()` and its private helpers/types (`sqlite_table_exists`,
`sqlite_column_exists`, `LegacyPackRow`, `LegacyItemRow`, `sha256_hex`, `append_field`,
`canonicalize_legacy`, `safe`) are removed (`chore/retire-migrate-from-sqlite-batch-b`,
tracking issue #3623). `sqlite_backfill_source` — whose entire purpose was the backfill
idempotency marker — is dropped via a version-bumped `{3, "DROP TABLE IF EXISTS
sqlite_backfill_source;"}` migration, appended after the already-shipped `{2, ...}`
idempotency-key `ALTER TABLE` rather than reusing its slot — an earlier revision of this
removal renumbered v2 to v3 instead of appending, which would have re-applied the ALTER
on any database already at v2 and failed the store closed on boot (caught in adversarial
review, fixed before merge). Not edited into v1: this store IS constructed in
production, so v1 has actually run against real dev/UAT databases. `server.cpp`'s boot
path now runs `legacy_sqlite_probe::warn_if_legacy_rows` over `product_packs`/
`product_pack_items` instead — silent unless real rows are found, never blocks boot.

**Deliberately NOT touched, scoped out of this removal:** `deleted_pack_ids` and
`kErasureCoordLockSql` both existed specifically to prevent a stale replica's
`migrate_from_sqlite` from resurrecting an uninstalled pack — with that consumer gone,
both are candidates for their own removal, but `uninstall()` still writes to them today
and stripping them is a materially different, riskier change (touches a live write path
and an advisory lock, not just dead code) than this mechanical retirement. Left for a
separate, explicit follow-up decision. The dedicated `yuzu_server_product_pack_backfill_total`
metric and its `YuzuProductPackBackfillNotCompleted` Prometheus alert are removed —
neither can fire again with no backfill outcome to report.
