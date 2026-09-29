# ADR-0063: DirectorySync → PostgreSQL

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** pg workstream (migration-programme PR 3 of the 7-store SQLite→Postgres ladder,
  #1328/#1325/#3653)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009 (including its 2026-08-25
  fresh-start-by-default amendment), ADR-0012 (substrate/store contract); ADR-0059
  (`OffloadTargetStore` → PostgreSQL — the canonical acquire→migrate→release ctor shape this ADR
  follows, minus the ADR-0010 secrets seam, which does not apply here); `docs/postgres-store-
  playbook.md`; `docs/postgres-migration-ladder.md`.

## Context

`DirectorySync` (`server/core/src/directory_sync.{hpp,cpp}`, Phase 7 AD/Entra integration) syncs
users, groups, and group memberships from Microsoft Entra ID via the Graph API, and lets an
operator map a directory group to an RBAC role. It was one of 7 production-wired SQLite components
missed by the original migration ladder, which only ever enumerated `*Store` classes + the auth DB
(found 2026-08-27, tracked #1328/#1325/#3653). Only the ~111 SQL-touching lines migrate here; the
OAuth2 token flow and the WinHTTP/httplib transport are untouched, verbatim — the ONE exception is
`fetch_paginated` (see "Follow-ups"), new client-side pagination logic a security review round found
necessary once this port's own stale-row deletion made an unfollowed `@odata.nextLink` dangerous,
not merely incomplete.

This is the riskiest of the three leaf stores in this batch (`UpdateRegistry`/ADR-0061,
`PatchManager`/ADR-0062, this one) — it shipped with no tests, a real pre-existing self-deadlock,
and a clear-then-repopulate write pattern that cannot translate directly onto a single Postgres
transaction, all found and verified directly against the code during planning (external review via
`/codex opine`, 2026-08-28).

### Pre-existing self-deadlock (fixed independent of the storage backend)

`sync_entra` (`directory_sync.cpp:580` on `origin/dev`) took `std::unique_lock lock(mtx_)`
(exclusive) and, still inside that scope, called `get_group_role_mappings()` (`:592`), which itself
took `std::shared_lock lock(mtx_)` (`:1003`) on the SAME non-recursive `std::shared_mutex` —
undefined behavior on `std::shared_mutex`, deadlocking in practice. No test exercised this path.

## Decision

### Deadlock fix

`mtx_` is deleted entirely, not reordered. `DirectorySync` carries no in-memory state beyond what
now lives in Postgres — the per-store `shared_mutex` existed only to serialize SQLite access, and
the PG connection pool's own concurrency model fully replaces it (per-store recipe step 3). This
makes the specific hazard class (a non-recursive lock re-entered on the same thread) structurally
impossible rather than merely avoided by a careful call ordering.

The role-mapping-preservation behavior the buggy nested call was reaching for — "keep a group's
existing RBAC role mapping across a re-sync, since Entra doesn't know about it" — is resolved by
**removing the denormalization entirely**: `directory_groups` carries no `mapped_role` column at
all; `get_synced_groups()` resolves it via `LEFT JOIN directory_group_role_mappings` at read time.

**This was not the first design tried, and the first one was wrong.** An earlier revision denormalized
`mapped_role` onto `directory_groups` and resolved it via a `COALESCE` subselect against
`directory_group_role_mappings` inside the group-upsert statement (both in the `INSERT`'s `VALUES`
and the `ON CONFLICT ... DO UPDATE`'s `SET`), reasoning that one statement execution has no
read-then-write window for a concurrent `configure_group_role_mapping`/`remove_group_role_mapping`
call to race. **Adversarial review (Kimi + Codex, 2026-08-28) disproved this empirically**: under
PostgreSQL READ COMMITTED, if a concurrent mapping-mutator transaction commits its write to
`directory_group_role_mappings` (and, in that earlier design, to `directory_groups` too) *after* the
upsert statement's snapshot was taken but *before* the upsert acquires the `directory_groups` row
lock, PostgreSQL's EvalPlanQual retry re-checks the specific conflicting row but does **not**
re-snapshot the subquery against the other table — so the subquery still returns its pre-commit
(empty) result, and the upsert silently writes `mapped_role=''`, clobbering the concurrent write once
it commits last. Both reviewers reproduced this independently with two-connection libpq tests; I
reproduced it a third time myself with a from-scratch standalone repro against the exact SQL shape
before accepting the finding. This is exactly the class of "atomic within one statement, not
serialized against another transaction's commit" bug the original nested-lock code also had no
answer for — the fix moved the hazard, it did not remove it. Removing the denormalized column instead
removes it structurally: there is no second copy of the value that can go stale, so there is nothing
left to race.

Regression coverage: `tests/unit/server/test_directory_sync.cpp` friends a
`DirectorySyncTestAccess` (mirroring `RbacStoreTestAccess`'s existing precedent) to reach the
private `apply_entra_sync` — where this logic now lives — directly, without a live/stubbed Graph
HTTP endpoint. "Group role mapping survives a re-sync" pins the correct behavior: configure a
mapping, apply a first sync, apply a second sync with a changed group `display_name`, and assert the
mapping is still present and the JOIN-derived read still agrees. This is a behavior-correctness
test, not a literal deadlock reproduction, and not a concurrency test either — it doesn't need to be
one, because the JOIN has no concurrent-writer race to exercise in the first place.

### Schema

Postgres schema `directory_sync` (ADR-0008 naming rule, extended per the ladder's Wave 4 note for
non-`Store`-suffix class names), five tables, names unchanged from the SQLite era:

```sql
CREATE TABLE directory_users (
    id           TEXT    PRIMARY KEY,
    display_name TEXT    NOT NULL DEFAULT '',
    email        TEXT    NOT NULL DEFAULT '',
    upn          TEXT    NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    synced_at    BIGINT  NOT NULL DEFAULT 0
);
CREATE TABLE directory_groups (
    id           TEXT    PRIMARY KEY,
    display_name TEXT    NOT NULL DEFAULT '',
    description  TEXT    NOT NULL DEFAULT '',
    synced_at    BIGINT  NOT NULL DEFAULT 0
);
CREATE TABLE directory_memberships (
    user_id  TEXT NOT NULL REFERENCES directory_users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE TABLE directory_group_role_mappings (
    group_id  TEXT PRIMARY KEY,
    role_name TEXT NOT NULL
);
CREATE TABLE directory_sync_status (
    provider     TEXT    PRIMARY KEY,
    status       TEXT    NOT NULL DEFAULT 'idle',
    last_sync_at BIGINT  NOT NULL DEFAULT 0,
    next_sync_at BIGINT  NOT NULL DEFAULT 0,
    user_count   INTEGER NOT NULL DEFAULT 0,
    group_count  INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_dir_users_email ON directory_users(email);
CREATE INDEX idx_dir_users_upn ON directory_users(upn);
CREATE INDEX idx_dir_memberships_group ON directory_memberships(group_id);
```

`directory_memberships` gets real foreign keys with `ON DELETE CASCADE` — the SQLite era had none
(a hand-emulated `clear_memberships()` sweep was the only thing keeping it consistent).
`directory_group_role_mappings.role_name` stays a **soft reference** into `RbacStore` — no
cross-schema FK, per ADR-0012 §3 (cross-store SQL is forbidden; a role rename/delete in `RbacStore`
is this store's problem to notice via its own read path, not a DB-level constraint).

### Transaction shape for `sync_entra`

`sync_entra`'s SQLite-era clear-then-repopulate cannot be one short Postgres transaction end to end,
because live external Microsoft Graph HTTP calls happen in between fetching users, fetching groups,
and fetching each group's membership (ADR-0012 §2 forbids holding a lease across external work).

**Chosen: fetch the complete remote snapshot first, then apply it in one short transaction**
(`apply_entra_sync`). `sync_entra` now performs every Graph HTTP call with NO lease held, building a
private `EntraSyncData{users, groups, memberships}` value; only once that snapshot is complete does
it call `apply_entra_sync`, which acquires one connection and, inside one `with_txn_for`: **deletes
every `directory_users`/`directory_groups` row not named in the new snapshot**, upserts every
user/group the snapshot does name, clears `directory_memberships`, and bulk-repopulates it.

**The deletion step was missing from the first version of this PR** (adversarial review, Codex +
Kimi, 2026-08-28, both independently): the transaction originally only upserted users/groups and
never removed one Entra had deleted, so a user/group removed from the tenant stayed queryable
through `DirectorySync` forever. I checked the base-commit SQLite implementation
(`git show ac7cc4fa8:server/core/src/directory_sync.cpp`) and confirmed this gap is pre-existing, not
a regression this port introduced — but this ADR's own "complete snapshot" / "either the whole
snapshot lands or none of it does" framing overclaimed what the code delivered, and DirectorySync
feeds the SOC 2 CC6.2 access-review email enrichment (`access_review_model.cpp`), where a deleted
identity silently staying "synced" is a real correctness gap worth closing now rather than carrying
forward under inflated prose. Fixed by a straightforward `DELETE ... WHERE NOT (id =
ANY($1::text[]))` against both tables (via `pg::to_text_array`), before the upserts, in the same
transaction; `ON DELETE CASCADE` removes the deleted rows' memberships.

Rejected alternative: **staging rows under a sync generation, atomically promoted**. This is the
right shape for a store whose external fetch is itself incremental/paginated at a scale where
holding the whole snapshot in memory would be a problem. `DirectorySync` isn't, even after the
pagination fix below: `fetch_paginated` follows `@odata.nextLink` to exhaustion but is bounded at
`kMaxGraphPages = 500` pages of `$top=999` — worst case ~500K objects per collection, still small
enough to hold as plain `std::vector`s (low hundreds of MB at most, on an operator-triggered, rare
path — not a hot loop). The staging-generation shape would add a sixth table and a promotion step
for no observable benefit at this scale; simpler wins.

**Improved atomicity as an intentional side effect, not a preserved behavior.** The SQLite era wrote
users to the database immediately as they were fetched (autocommit, no transaction), so a
subsequent groups-fetch failure left a fresh set of users next to a STALE set of groups/memberships
from the last successful sync — an observably inconsistent mixed state. Fetch-then-apply makes a
failed sync leave the store completely untouched: either the whole snapshot lands, or none of it
does. This is a real behavior change, recorded here rather than silently inherited.

**Non-user membership filter.** Microsoft Graph's `/groups/{id}/members` endpoint returns
`directoryObject`s, not exclusively users — it can include devices, service principals, and nested
groups. The SQLite era had no FK on `directory_memberships` and simply never surfaced those ids at
read time (the `JOIN` against `directory_users` filtered them out silently). The FK added by this
port makes that filtering happen at WRITE time instead: `apply_entra_sync` computes the set of
fetched user ids and drops any membership pair whose `user_id` isn't in it, before the bulk insert.
Without this, a single non-user member in any group would raise a foreign-key violation, fail the
whole transaction, and permanently fail `sync_entra` for that tenant — this was found and fixed
during implementation review, not discovered in production.

**The users/groups fetch-error asymmetry is now closed, not preserved.** The SQLite era treated a
malformed/unexpected Graph *users* response (no `"value"` array) as a hard sync error, but the
identical shape for the *groups* response as silently "zero groups" (no `else` branch at all) —
harmless there, since nothing downstream was ever deleted on a zero-groups outcome. Once deletion
was added (above), that asymmetry became actively dangerous: an empty `data.groups` from a
transient/malformed fetch — not a genuine "this tenant has zero groups" — would delete every
previously-synced group. The groups-fetch block now mirrors the users block exactly: a malformed
response is a hard error, `update_status("failed", ...)`, and `sync_entra` returns before
`apply_entra_sync` is ever called, leaving the store untouched. `apply_entra_sync` can therefore
trust that an empty `data.groups`/`data.users` it does see means the tenant genuinely has zero of
that kind, never a fetch failure masquerading as one.

### Read-path N+1 fix

`get_synced_users` resolved each returned user's group list with a separate per-user `JOIN` query in
the SQLite era (a store-side N+1, independent of the Graph-call-per-group loop above, which is an
external API shape, not a store defect). This port replaces it with one bulk query —
`SELECT ... WHERE m.user_id = ANY($1::text[])` using `pg::to_text_array` (the array-parameter helper
`pg_array.hpp` already documents as its intended use) — so the group-resolution cost is one extra
round trip regardless of how many users matched, not one per user.

### Posture (ADR-0012 §1)

Construction is fail-**closed** — a posture upgrade from the SQLite era, which was fail-**open**
(`server.cpp` never checked `is_open()` at all before this migration). Query methods
(`get_synced_users`, `get_user`, `get_synced_groups`, `get_status`, `get_group_role_mappings`) and
the mutators (`configure_group_role_mapping`, `remove_group_role_mapping`) keep their SQLite-era
plain-container/void signatures — empty vector/map, default `SyncStatus`, `nullopt` — never a
distinguished degraded-vs-not-found signal. This is a **deliberate non-upgrade**, not an oversight:

- `discovery_routes.cpp` already gates every `/api/directory/*` route on `is_open()` before
  calling any query method, returning 503 on a closed store — the same file the sibling
  `PatchManager`/ADR-0062 PR also touches, and outside this PR's blast radius (per the migration
  programme's "one PR per store" decision).
- `access_review_model.cpp`'s `build_email_index` already treats a null/closed `DirectorySync*` as
  "no enrichment available", never an error — see "Consumers" below.

A typed-degrade read contract (the `OffloadTargetStore`/`std::expected<T, WriteError>` shape) is
therefore structurally unavailable to this store's existing callers without also editing files
outside this PR's scope, not merely declined for convenience.

### Consumers (unchanged call sites, unchanged public API)

- `discovery_routes.cpp` (`/api/directory/sync`, `/api/directory/users`,
  `/api/directory/status`, `/api/directory/group-mappings`) — untouched; already correctly gates on
  `is_open()`.
- `access_review_model.cpp`'s `build_access_review` (MCP `export_access_review` +
  `GET /api/v1/access-reviews/.../export`, a SOC 2 CC6.2 evidence path) — untouched.
  `build_email_index` already treats `dirsync == nullptr || !dirsync->is_open()` as "no enrichment",
  builds an empty UPN→email index, and the export proceeds with every `owner_or_email` left blank
  for rows it would have resolved. This was already true before this migration (the store was
  fail-open, so "closed" essentially never happened; now it's fail-closed, so "closed" is a real,
  reachable state at boot if Postgres is unreachable) — the behavior on that path does not change: a
  directory-sync outage still degrades this export to missing emails, never a hard failure of the
  whole export, and it does not newly and silently drop an email that WOULD otherwise have resolved
  (the enrichment index is simply empty, same as "directory sync was never configured").

### `/readyz` and `/healthz`

Added to both (`server.cpp`'s `StoreCheck` vector and the `health_handler` lambda's
`directory_sync_ok`) — absent from both before this migration, the exact "readyz-vs-healthz drift"
class several sibling rows in this file already document. `directory_sync_` is declared after
`pg_pool_` in `ServerImpl` (destructs first); no explicit `stop()`-time reset was added, following
the majority-precedent pattern of plain synchronous stores with no background thread or detached
work (`baseline_store_`, `product_pack_store_`, etc.) — `DirectorySync` has neither; every Graph HTTP
call happens synchronously on the REST-handler thread that issued it.

### No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment)

No `migrate_from_sqlite`, no legacy-table-reading code. The legacy `directory-sync.db` is never read
for data, unconditionally, same posture as `ResponseStore`/`OffloadTargetStore`. Construction logs a
one-time `DirectorySync initialized (schema directory_sync) — fresh start, no legacy backfill` line.
`server.cpp` calls the new shared `legacy_sqlite_probe::warn_if_legacy_rows()` helper
(`server/core/src/legacy_sqlite_probe.hpp`, authored here ahead of the migration programme's PR 1
which was originally meant to introduce it — reconcile if PR 1 lands a different shape) once at
boot, naming all five legacy tables, to warn (never fail, never block boot) if the legacy file still
holds rows an operator upgrading from a pre-Postgres build might want to reapply via the API.

## Considered and rejected

- **Staging rows under a sync generation, atomically promoted.** See "Transaction shape" above —
  rejected as unneeded complexity at this store's Graph-page-capped scale (≤500 pages of `$top=999`
  per collection, `kMaxGraphPages`, after the pagination fix under "Follow-ups").
- **Preserving the exact SQLite-era partial-failure behavior** (users committed immediately,
  groups/memberships left stale on a later failure). Rejected — fetch-then-apply's all-or-nothing
  atomicity is strictly better and costs nothing extra to get.
- **A separate `KeyProvider`/`SecretCodec` seam.** N/A — `DirectorySync` has never persisted a
  secret (Entra `client_secret` is per-request, supplied on every `POST /api/directory/sync` call,
  never stored). No ADR-0010 work applies to this migration.
- **Cross-schema FK from `directory_group_role_mappings.role_name` into `RbacStore`.** Rejected —
  ADR-0012 §3 forbids cross-store SQL; the soft reference is unchanged from the SQLite era.
- **A denormalized `mapped_role` column on `directory_groups`, resolved via a `COALESCE` subselect
  in the group-upsert statement.** Tried first, rejected after adversarial review empirically
  disproved its race-freedom claim (see "Deadlock fix" above) — replaced with a `LEFT JOIN` at read
  time, which has no denormalized copy to race on.
- **A `pg_advisory_xact_lock` serializing `apply_entra_sync`'s group upserts against the mapping
  mutators** (the `RbacStore` pattern for its own revoke/reseed races) — considered as an alternative
  fix for the same race. Rejected in favor of removing the denormalized column: a lock only prevents
  the two writers from interleaving, which is strictly more moving parts than having nothing left to
  serialize.

## Consequences

- **Any directory sync state from a pre-Postgres build is lost on upgrade** (synced users/groups/
  memberships and any configured group→role mappings). The operator re-runs
  `POST /api/directory/sync` and re-applies `PUT /api/directory/group-mappings`. Documented in
  `docs/user-manual/upgrading.md`.
- **A directory-sync outage now surfaces at `/readyz` and `/healthz`** where it was previously
  invisible (the SQLite era never checked `is_open()` at all). This is a monitoring-visibility
  improvement, not a new failure mode — `/api/directory/*` already 503'd correctly on a closed
  store; operators/dashboards just could not see it as a store-health signal before.
- **`configure_group_role_mapping`/`remove_group_role_mapping` stay void**, matching the SQLite era
  — a write failure is logged (`spdlog::error`) but not surfaced to the caller. Not upgraded to a
  typed return in this PR (see "Posture" above); tracked as a natural follow-up if
  `discovery_routes.cpp` is ever revisited by the `PatchManager` sibling PR or a later pass.
- **A user/group Entra has deleted now actually disappears from `DirectorySync` on the next
  successful sync** — a genuine, deliberate behavior change from BOTH the SQLite era and this PR's
  own first draft (see "Transaction shape" above), not merely a storage-backend swap. Operators
  relying on a stale synced identity remaining queryable after removal from Entra (there is no known
  such reliance, but none was verified against either) will see it disappear starting with the first
  sync after this ships.
- **A malformed/unexpected Microsoft Graph groups response is now a hard sync failure**, where the
  SQLite era silently treated it as "zero groups" and proceeded. This closes the danger the deletion
  fix above introduced (an empty snapshot from a fetch problem would otherwise wipe every synced
  group) but is itself an observable behavior change: a tenant hitting this Graph response shape
  previously got a silently-empty group sync; it now gets a failed sync with `last_error` set.

## Follow-ups

- `discovery_routes.cpp`'s mutators could surface a write failure to the caller (currently
  silent-on-error, matching the SQLite era) — out of scope for this PR (file shared with the
  `PatchManager`/ADR-0062 sibling PR; the migration programme's "one PR per store" decision keeps
  route-file edits out of both).
- ~~The Graph users/groups fetch still does not follow `@odata.nextLink`~~ — **fixed** (security
  review, 2026-08-29, HIGH/BLOCKING): a tenant with >999 users, >999 groups, or any group with
  >999 members only ever synced the first page, and this ADR's own deletion fix above then treated
  every entity past page 1 as "deleted in Entra" on every sync — a deterministic, unauthenticated
  (E0) data-loss trigger for any realistically-sized enterprise tenant, feeding the SOC 2
  access-review email enrichment. `fetch_paginated` now follows `@odata.nextLink` to exhaustion for
  all three collection fetches (users, groups, each group's members), accumulating every page into
  one complete `EntraSyncData` before `apply_entra_sync` runs — never a per-page delete-then-upsert,
  which would have treated each page as if it were the whole snapshot. Bounded at 500 pages against
  a runaway/malicious `nextLink` chain. A per-group members-fetch failure (previously logged and
  `continue`d, silently wiping that group's real memberships once deletion existed) now also
  hard-errors the whole sync, matching the users/groups fetch-error handling. **A follow-on C++
  review (2026-08-30) found the first cut of this fix still conflated two distinct outcomes**: a
  malformed-but-*present* `@odata.nextLink` (e.g. a number, not a string) took the same "no more
  pages" success path as a legitimately *absent* one — the identical silent-truncation channel this
  fix exists to close, just narrower. Tightened to hard-error specifically on "present but not a
  string", distinct from "absent" (legitimate end of pagination); a third regression test covers
  this shape. **A further unhappy-path review (2026-08-30) found a second, more severe gap in the
  same fetch path (HIGH/BLOCKING)**: `on_item`'s field accessors (`.value<T>(key, default)`) throw
  `nlohmann::json::type_error` on a *present-but-null* or wrong-typed field — e.g. a guest/unlicensed
  Entra user's `"mail": null`, empirically confirmed to throw, not merely common but near-certain
  against any real tenant. Uncaught, this escaped `fetch_paginated`/`sync_entra` entirely, through
  the route handler (caught only as a bare HTTP 500 by httplib's own top-level dispatch), skipping
  every `update_status(..., "failed", ...)` call site — `directory_sync_status` was left stuck at
  `"running"` with `last_error=""` forever, identically on every retry, with no reader able to tell
  the sync had ever failed. Fixed by wrapping the per-item `on_item` call in a
  `catch (const nlohmann::json::exception&)`, routing the failure through the same
  `std::unexpected` channel as every other fetch failure. The same review also flagged, as a
  non-blocking MEDIUM defense-in-depth gap, that a followed `@odata.nextLink` was never checked
  against the initial request's own host — fixed by pinning every subsequent page's scheme+host to
  match page 1's (a forged nextLink would need the same TLS-verified-channel control an attacker
  would already need to forge the rest of the response, so the marginal capability gained was
  assessed as near-nil, hence MEDIUM rather than HIGH — but cheap to close outright). **A chaos-injector
  pass (2026-08-30) found a third, distinct HIGH/BLOCKING gap in the same area**: `kMaxGraphPages`
  bounds each individual `fetch_paginated` call, but the per-group membership loop makes ONE such
  call per group, and every group's members accumulate into the same `EntraSyncData` before a
  single row is written — so a legitimately large tenant's group×membership graph (the exact scale
  this feature targets) is unbounded by `kMaxGraphPages` alone and could exhaust the whole
  `yuzu-server` process's memory, not just this store's, an ordinary-use OOM risk against the
  shared control plane rather than a rare or adversarial one. Fixed by a running
  `kMaxTotalMemberships = 5,000,000` cap across the membership loop, aborting (store untouched) with
  a clear error before an unbounded accumulation could occur. Left untested at the exact threshold
  (same accepted precedent as `kMaxGraphPages`'s own untested bound — driving 5M synchronous fetch
  items through a local test server is disproportionate to what this defensive-only bound needs).
  Two smaller, non-blocking items from the same pass: `scheme_host()`'s host comparison is
  case-sensitive with no port normalization (speculative — no legitimate Graph response is known to
  vary case, not itself a chaos target); and a concurrent-sync interleave (already tracked below)
  can leave `directory_sync_status`'s counts describing a different sync than the one whose data
  actually committed last, an unexercised sub-case of the already-accepted risk, not new severity.
- A completed sync whose final `update_status("entra", "completed", ...)` write fails (pool
  exhaustion, a dropped connection at exactly that moment) leaves `directory_sync_status.status`
  stuck at `"running"` even though the data landed — `update_status` is void and only logs on
  failure, matching the SQLite-era contract and `configure_group_role_mapping`'s/
  `remove_group_role_mapping`'s own void posture (adversarial review, both reviewers, LOW,
  non-blocking: the next successful sync repairs it, and the failure is logged). Not fixed here;
  the fix (surface the failure from `update_status`, or fold the status write into
  `apply_entra_sync`'s own transaction) is the same shape as the `discovery_routes.cpp`
  typed-return follow-up above.
- **Deleting `mtx_` removed the (buggy) serialization of concurrent `sync_entra` calls**, not just
  the deadlock (security review, 2026-08-29, MEDIUM, non-blocking — requires an authenticated
  `Directory:Write` operator triggering two overlapping syncs, E2). Two concurrent
  `POST /api/directory/sync` calls can now interleave fetch-then-apply, letting a stale snapshot
  transiently resurrect an Entra-deleted identity, or one call's `apply_entra_sync` abort on a
  Postgres lock conflict with the other's. Self-heals on the next sync; not fixed here. The fix is
  a `pg_advisory_xact_lock` on a store-scoped key at the top of `apply_entra_sync`
  (`RuntimeConfigStore` precedent) — tracked as a follow-up, not required for this PR's scope.
- **`directory_group_role_mappings` has no FK/cascade to `directory_groups`, and stale-row deletion
  never cleans it** (C++ review, 2026-08-30, LOW, non-blocking — confirmed no live RBAC grant path:
  `mapped_role`/`get_group_role_mappings()` are read only for display/config in `discovery_routes.cpp`,
  never to grant a role at login). A group deleted from Entra leaves its role mapping orphaned
  forever, surfaced unfiltered by `GET /api/directory/status`. Not fixed here — simply adding a
  cascade would break the existing (deliberately unvalidated) ability to configure a mapping for a
  group_id before its first sync, so this is a store-owner design call (explicit stale-mapping
  cleanup inside `apply_entra_sync`'s transaction, vs. documenting mappings as intentionally
  sync-independent), not a mechanical fix.
- **A large tenant's total fetch wall-clock can now exceed the OAuth access token's TTL mid-sync**
  (chaos-injector review, 2026-08-30, MEDIUM, non-blocking). Real pagination (see above) makes total
  sync time scale with tenant size for the first time — the pre-fix single-page code was fast but
  wrong. A tenant large enough that the full users+groups+per-group-members fetch exceeds the
  token's ~60-90 min TTL will have every sync attempt fail via a 401 partway through — safely (fetch
  precedes any write, so the store is never left inconsistent), but the sync can never *complete*
  until token refresh is added. Not fixed here; tracked as a follow-up (mid-fetch token refresh in
  `fetch_paginated`/`sync_entra`).
- **`http_get` has no response body size cap** (unhappy-path review, 2026-08-30, MEDIUM,
  non-blocking — same trust precondition as the nextLink-host-pinning fix above: a single huge
  page is unbounded memory, but only from a host already pinned to `graph.microsoft.com`, a
  TLS-verified channel the token transits on every request regardless). `kMaxGraphPages` bounds
  page *count*, not page *bytes*. Not fixed here — both platform transports (`WinHTTP` and
  `httplib::Client`) would need touching to add a cap, which is a larger surface than this finding
  warrants given the file header's "untouched, verbatim" scope for everything except
  `fetch_paginated` itself; tracked as a follow-up.
