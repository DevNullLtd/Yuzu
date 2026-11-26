# Bulk device-CI read: the `changed_since` delta filter, decisions and residuals

**Date:** 2026-11-24
**Change:** `GET /api/v1/hardware-ci` and the MCP tool `list_hardware_ci_records` gain a `changed_since`
filter, a per-row `changed_at` and a `next_changed_since` on the first response of a walk (PR 1 of 2; PR 2 is the removal feed).
**Status:** implemented, NOT merged, and its residuals are NOT yet owner-accepted. The design was reviewed
(Fable) and approved by the owner before implementation, and the governance round that followed changed it in
one respect: the watermark is returned on the first response of a walk only (owner ruling 2026-11-24, decision 5
below). Migration v6 was added on 2026-11-26 to mitigate HWCI-DELTA-PLAN-FLIP and the runtime index check now
covers `device_ci_changed_at_idx` too (HWCI-DELTA-INDEX-NO-WARN, closed); see "Migration v6" under "Measured query
plans". Residuals that need an explicit owner ruling BEFORE this merges: HWCI-DELTA-PLAN-FLIP (what remains of it after
v6),
HWCI-DELTA-MARGIN-ESTIMATE (including the clock-step and long-commit cases added below),
HWCI-DELTA-MIXED-BUILDS, HWCI-DELTA-NO-REMOVALS, HWCI-DELTA-REPARSE, HWCI-DELTA-HOT-LOSS and
HWCI-DELTA-AUDIT-NO-MARKER (the last two are not mitigated and no owner acceptance is recorded for either; the
plan-flip `retry_after_ms` hint also needs the waived-A5 ledger entry described under "Unchanged contract"). Residuals recorded as design
consequences, which this record does not ask the owner to waive: HWCI-DELTA-SCOPED-REFUSED,
HWCI-DELTA-LAST-SEEN-STALE and HWCI-DELTA-ENTER-SCOPE. Tracking issues and owners are to be filed at push. This
record is additive: it does not edit
`docs/security-reviews/hardware-ci-bulk-read-bounds-2026-11.md`, which stays authoritative for the
concurrency cap, the byte bound and their residuals, and all of which this change keeps.

## Why

The bulk read had no way to ask what changed, so each ServiceNow (CMDB) pull re-read every row.
`ci.last_seen` cannot serve: every hash-skip daily sync bumps it, so it moves on every device every day.
A real change marker and a delta filter close that.

## Design decisions

1. **A new column, `device_ci.changed_at BIGINT NOT NULL`** (migration v5), in epoch seconds, the unit of
   `first_seen` and `last_seen`. It is set only in the one content upsert: on insert, and on conflict only
   when `content_hash` differs from the stored one. The hash-skip touch does not write it, and it is not
   part of the canonical hash. A full payload whose hash is unchanged reaches the upsert and leaves it alone.
2. **Stamped from the database clock, in SQL** (`EXTRACT(EPOCH FROM clock_timestamp())::bigint`), never the
   replica's `now_secs()`. Under active-active replicas a replica clock that runs behind would stamp a row
   earlier than a watermark another replica already handed out, and the next delta would skip it. One clock
   (the database's) orders every writer and every watermark, for a single primary: a clock step, an NTP
   correction or a failover to a node whose clock is skewed breaks that (HWCI-DELTA-MARGIN-ESTIMATE). `changed_at`
   is on the database clock while `first_seen` and `last_seen` are on the replica clock
   (HWCI-DELTA-CLOCK-DOMAINS).
3. **Backfill by default value, metadata only.** `ADD COLUMN ... DEFAULT (EXTRACT(EPOCH FROM now()))::bigint`
   is a stable (not volatile) default, which PostgreSQL 11 and later apply without rewriting the table.
   Existing rows therefore read as changed at migration time, and the first delta pull returns the fleet
   once. The index is built in the same migration under the `SET LOCAL lock_timeout` and `statement_timeout`
   pattern that migration v4 uses.
4. **Filter `changed_at >= $n`**, so delivery is at-least-once: a row exactly at the boundary is served again
   rather than lost. The client upserts by `agent_id`. With no filter the SQL text and parameters are
   byte-identical to before.
5. **Watermark `next_changed_since` = database clock minus 300 s** (`kChangedSinceMarginSecs`), returned on the
   FIRST response of a walk ONLY (owner ruling 2026-11-24): a bulk response that carries no `cursor` and no
   `agent_id`. Cursor pages and `agent_id` point reads omit the key entirely (absent, not null, not 0), so they
   take no second pool lease and gain no new `503` dependency. A failed watermark read on a first page is a
   definitive `503` (`retry_after_ms` 5000), never a guessed value. A first page does hold a second pool lease for the
   watermark read while its bulk-read slot is held, so its worst-case slot hold is longer than a cursor page's: the sums
   of the bounds in the source (`kQueryAcquireTimeout` in `device_inventory_store.cpp`, the pool defaults in `pg_pool.hpp`,
   `kWriteTimeout` in `audit_store.cpp`) are about 62 s for a REST cursor page and about 80 s for a first page, and about
   106 s and about 124 s on MCP, which writes two audit rows. They are sums of bounds, not measurements, and they assume
   `BEGIN` and the `SET LOCAL statement_timeout` answer promptly: those two statements run before the 5 s cap exists,
   under the pool's 30 s default, and are not separately capped (HWCI-DELTA-FIRST-PAGE-TIMING). The client keeps that first value. The
   guarantee is "stamped within 300 s before the clock that minted the value", not "200 s before the value": a
   write whose transaction was open (or whose commit was delayed) when the walk began commits with a
   `changed_at` earlier than the watermark yet becomes visible only after the read, and the margin covers it. It
   is an estimate of that lag, not a bound on it (HWCI-DELTA-MARGIN-ESTIMATE). A client that kept the LAST
   page's value, or one derived from `max(changed_at)` or its own clock, silently misses changes behind the
   cursor on a long walk, which is why the first-response-only rule exists and why the manual says to keep that
   value and nothing else. A first response without the key means the filter was not applied (a replica that
   predates the feature): the client must not advance its watermark.
6. **A delta needs a global-read credential.** A scope-confined caller (management group or service scoped)
   who sends `changed_since` gets a definitive refusal that names no device and no count (message `changed_since needs a credential with global read; a scope-confined credential cannot use a delta pull`, remediation `use a credential holding a fleet-wide Inventory:Read grant (a management-group or service-scoped token cannot), or omit changed_since and walk the full set`). On MCP the refusal writes both audit rows (the domain row and the generic row), and on REST its best-effort `denied` row can carry `Sec-Audit-Failed: true`, like the scope-over-10,000 refusal. A device that
   enters a caller's scope does not change its record, so `changed_at` does not move and a scoped delta
   would silently omit it. Pushing the scope into the delta SQL does not make it safe: it would be a
   query that looks complete and is not. The scope-confined caller keeps the full walk.
7. **Validation.** A malformed or negative value is `400` (MCP `-32602`) with `invalid changed_since (expected epoch seconds as a non-negative integer)`; a value past `now + 60 s` on the replica's wall clock is `400` /
   `-32602` with `invalid changed_since (it is in the future, or this server's clock is behind the database clock)`, the precedent of `hardware_routes.cpp` for `limit`. The accepted range is therefore 0 up to the
   server's current time plus 60 seconds (the MCP schema's static maximum is coarser; the server check is the one
   that applies). The 60 s absorbs clock skew between a client and a replica. The value is bound into the cursor
   filter fingerprint; the no-filter fingerprint is byte-identical to before, so a cursor issued before this
   change still decodes (the `h1` format is frozen). The cursor is bound to `agent_id` AND `changed_since`.
8. **Upgrade safety.** The store constructor's projection probes include `changed_at`, so an old schema
   fails closed the way v2 to v4 do. Migration v5 also checks, after `ADD COLUMN IF NOT EXISTS`, that an
   existing `changed_at` is `bigint NOT NULL` and raises an exception when it is not (a pre-existing column of
   another type would otherwise be skipped by `IF NOT EXISTS`, and every upsert and delta would then fail at run
   time). The v5 `ALTER` takes `ACCESS EXCLUSIVE`, held through the index build, so reads and writes of
   `device_ci` are blocked for the migration (about 0.2 to 0.7 s per million rows on 18.4); it waits up to 30 s
   for the lock and then fails, and a failed v5 migration refuses to start the server on every restart until
   the lock holder is gone (`docs/user-manual/upgrading.md`). v5 is forward-only: there is no rollback. A development or UAT
   database that applied the unreleased pre-guard v5 text records a different hash for v5 and refuses to start; the
   recovery recipe in `docs/user-manual/upgrading.md` deletes that one recorded row and is pinned to the SHA-256 of the
   pre-guard text (`c2c3ca704946929d0d0d1bba87840cc2f67a30e967d9738580091f50c9cdce6b`), so a database that recorded any other v5 text deletes nothing (`DELETE 0`) and
   is sent to the maintainers rather than to the generic reset. The recipe is valid only for databases built by that
   pre-guard text.
9. **Data classification.** `changed_at` is stored in `device_ci` and served on every row to whoever may read the
   row; it is in the same behavioural-PII tier as the rest of the record (ADR-0016). Only the
   `changed_since` filter is restricted to global-read credentials. The watermark is not: it is returned on every FIRST
   response, including to a scope-confined caller (a known caveat: that caller's first page without `changed_since` still
   reads and returns it; it is a clock value, not device data, and a scope-confined first walk's value must not be used
   for a later global delta, see HWCI-DELTA-SCOPED-WALK-WATERMARK). It lives and dies with the
   `device_ci` row: a decommission deletes it and its index entry.

## Unchanged contract

The 4 MiB REST and 1 MiB MCP byte bounds, the `BulkReadSlots` cap held through the audit write, the
collation gate refusal, the A5 MCP annotations, the fail-closed `inventory.devices.ci` audit row and the
byte-ordered (`COLLATE "C"`) keyset are untouched.

One claim of the A5 checklist does NOT stay untouched: the honest `retry_after_ms`. A delta whose query plan
flips (HWCI-DELTA-PLAN-FLIP; after migration v6 only when the keyset index is missing or invalid, which the server
warns about at start, or the planner still chooses badly) answers a deterministic statement-timeout `503` /
`kInternalError` that carries the generic store-fault hint `retry_after_ms` 5000, and a retry reaches the same page
and the same error, so that hint is NOT honest advice for it. The retry-hint cause discriminator is not built; this is disclosed here and in the
manual. A waived-A5 ledger row in `docs/agentic-first-principle.md` (surface `list_hardware_ci_records`, waived item
the honest `retry_after_ms` on a deterministic statement-timeout error of the bulk read, whatever its cause, with an issue number and a revisit-by date) is required and is to
be added at push time, when the issue exists; this change does not edit that file.

## Measured query plans

Measured on PostgreSQL 18.4 (`postgres:18.4-bookworm`, one container), with wide rows,
by `EXPLAIN (ANALYZE, BUFFERS)` of the real `device_ci_keyset_statement()` at limit 1001. The raw logs
are the author's scratch files and are not kept in the repository; the figures below are the record.

**Backfill is metadata-only.** `ALTER TABLE ... ADD COLUMN changed_at BIGINT NOT NULL DEFAULT
(EXTRACT(EPOCH FROM now()))::bigint` took 0.6 ms at 300k and at 1M rows. The table's `relfilenode` was
identical before and after (1M rows: 617,062,400 bytes before and after), and a control with a volatile
default (`clock_timestamp()`) did change it, so the check does detect a rewrite. The whole v5 migration
through the store (ALTER, index build, projection probes) took 107 ms at 300k and 684 ms at 1M rows. The
index is about 7 MB at 1M rows.

| Case at 1M rows | Plan | Execution |
|---|---|---|
| Sparse, 0.1% scattered, first page | `device_ci_changed_at_idx` + top-N sort | 6.1 ms |
| Sparse, 0.1% scattered, mid-walk page | `device_ci_changed_at_idx` + top-N sort | 0.9 ms |
| Sparse, 0.1% clustered at the tail | `device_ci_changed_at_idx` + top-N sort | 5.7 ms |
| 2% clustered at the tail, first page | `device_ci_changed_at_idx` | 92 ms |
| 5% scattered | `device_ci_agent_id_c_idx` with filter | 91 ms first page, 48 ms mid-walk |
| Dense, 90% scattered | `device_ci_agent_id_c_idx` with filter | 6.6 ms |
| All rows (the state right after migration) | `device_ci_agent_id_c_idx` with filter | 7.5 ms |
| No filter (reference) | `device_ci_agent_id_c_idx` | 2.7 ms |

Whole walks at 1M rows: the sparse delta took 2 pages and 9.3 ms in total; the dense delta took 900 pages,
13.5 ms at most per page and 8.2 s in total, against 8.7 s for the unfiltered walk.

**The slow case (HWCI-DELTA-PLAN-FLIP).** The earlier version of this record described one slow case, a
5% delta clustered at the tail, at 2.2 s a page and an extrapolated limit breach at about 2.5M rows. The governance
round measured it again at 1M rows and the figure was understated. The planner flips from the
`device_ci_changed_at_idx` plan to an `agent_id` index scan with a filter at roughly 2 to 3% density, and the
filter then scans most of the table before it finds a page. The result is slow for ANY clustered delta of 3% or
more on its first page, on its final page, or after a gap in the middle of a walk. (The governance round's
performance review took these figures on PostgreSQL 18.4 at 1M rows; like the rest of this section, the raw logs
were not retained, so the numbers are a record of that review, not reproducible from the repository.) The worst case measured is a
5% delta clustered at the head of `agent_id` order, whose terminal page took 3.6 to 3.8 s at 1M rows in that review's
measurement (NOT reproduced: the re-measure under "Migration v6" below took 262 to 268 ms for the same shape, and which
figure describes a real fleet is unresolved). On the review's figure that breaches the 5 s statement limit at about
1.3M rows on a warm cache, and earlier on a cold one; on the re-measure, by linear extrapolation, at about 19M rows. A page that
exceeds the limit answers `503` with `retry_after_ms` 5000, but the same `changed_since` reaches the same page
again, so the answer is deterministic: a retry gets the same `503` and the walk wedges. The `5000` hint is wrong
advice for it, because nothing about the retry changes. The mitigation for a client is conditional and capped: fall back only when the same delta page has
failed with the generic failure (REST `503` with `retry_after_ms` 5000 and no `Sec-Audit-Failed`; MCP `-32603` with
`retry_after_ms` 5000 and not the audit-subsystem message) at least 3 times over at least 60 s while unfiltered pages succeed. Every other hint is honoured and
never triggers it (2000 read capacity, 60000 collation, an audit failure). Then drop `changed_since` and run ONE full walk
(a full walk does not run the delta filter), at most once per walk and not as the answer to every scheduled run. If that
walk's first page also fails (it reads the watermark too), the cause is not the delta plan: stop and alert, do not loop;
fallbacks that recur run after run mean the delta plan is slow, to be raised with the operator. A composite index `(agent_id COLLATE "C",
changed_at)` was measured by that review to take the worst page from 3.7 s to 44 ms, and it was built as
migration v6 (next subsection), REPLACING `device_ci_agent_id_c_idx`. The reason to replace and not add is that the
composite serves every query v4's index served (v4's key is its first column), so v4's index is a strict prefix:
kept, it costs about 56 MB per million rows and a write per update for nothing. (An earlier draft of this record
gave the runtime check's exact-key test as the reason; that check cannot influence the planner, and no measurement
with both indexes present was recorded.) The earlier claim in this record that a composite `(changed_at, agent_id)` index does not change the plan
choice was about a different key order and does not describe the built index.

**Migration v6 (2026-11-26): the composite keyset index.** v6, in one transaction, drops any index named
`device_ci_agent_id_c_changed_idx`, builds it on `device_ci (agent_id COLLATE "C", changed_at)` and then drops v4's
`device_ci_agent_id_c_idx`. The drop-first order is deliberate (a 2026-11-26 external opinion): a bare `IF NOT
EXISTS` build would be skipped over a same-named index left invalid or differently defined by a cancelled hand
build, and the drop of v4's index would then leave no usable keyset index; a test runs v6 over such leftovers
(a separate migration, not an edit of v5, so a database that already ran v5 needs no hash-drift recipe). The
planner can then test `changed_at` INSIDE the index (an `Index Cond:` line) where it used to test it on each heap row
(a `Filter:` line). A unit test pins that plan shape (`a clustered delta's terminal page tests changed_at inside the
keyset index, not row by row`).

Re-measured on PostgreSQL 18.4 (`postgres:18.4-bookworm`, one container), 1M synthetic rows of about 726 MB
(`agent_id` a 36-character uuid, 17 text columns), `EXPLAIN (ANALYZE)` of the keyset statement shape at limit 1001, second
run. A = v4's index plus `device_ci_changed_at_idx` (before v6); B = the composite plus `device_ci_changed_at_idx`
(what ships); C = the composite alone (not shipped, to show why the changed_at index stays).

| Case at 1M rows | A, before v6 | B, as shipped | C, composite only |
|---|---|---|---|
| Sparse, 0.1% scattered, first page | 5.1 ms | 5.0 ms | 27.8 ms |
| 2% clustered at the tail, first page | 11.0 ms | 22.6 ms | 22.5 ms |
| 3% clustered in the middle, first page | 15.5 ms | 12.5 ms | 12.5 ms |
| 5% clustered at the head, first page | 0.9 ms | 0.9 ms | 0.9 ms |
| 5% clustered at the head, terminal page | 262 ms | 22 ms | 22 ms |
| 5% scattered, first page | 7.8 ms | 2.0 ms | 2.1 ms |
| All rows (right after migration) | 1.0 ms | 1.0 ms | 1.0 ms |
| No filter (reference) | 1.0 ms | 0.9 ms | 0.9 ms |

The terminal-page row was repeated in a container capped at 700 MB of memory with PostgreSQL's default
`shared_buffers` (128 MB): A 268 ms, B 24 ms. Index sizes: v4's index 56 MB, the composite 65 MB (a net +9 MB when it
replaces v4's; the earlier "+65 MB" figure was the size of the composite, which is only paid in full if v4's index is
kept), `device_ci_changed_at_idx` 6.8 MB. The v6 swap (build the composite, drop v4's) took 0.58 s.

The first table above and this one come from different rigs, and the gap is systematic, not confined to the worst
case: the same pre-v6 shapes cost 92 ms (2% clustered at the tail), 91 ms (5% scattered), 7.5 ms (all rows) and
2.7 ms (no filter) in the first table against 11 ms, 7.8 ms, 1.0 ms and 1.0 ms here. A plan that makes one heap fetch per
non-matching row, as the pre-v6 plan does, is very sensitive to the heap order against `agent_id` order and to the cache
state (a likely cause, not tested), and the new plan is not. So the first table's absolute figures and this one's must
not be mixed, and the "11 ms to 23 ms regression" below holds on this faster rig only.

After v6 the terminal page of a clustered delta is still a linear walk of the keyset index: the composite removes the
heap fetches, not the index walk. At about 22 ms per million entries (this rig), the 5 s statement limit is roughly
200 million rows away by linear extrapolation, which was not measured beyond 1M.

What this re-measure does NOT reproduce: the governance review's 3.6 to 3.8 s for A's worst page. This synthetic
table gave 262 to 268 ms for the same shape (a 5% delta at the head, the page after it), and the difference is
unexplained (row width, data distribution, cache state or load on the review's machine are candidates). The
shape of the plan is the same in both (A tests `changed_at` per heap row; B tests it in the index), and B is about
12 times faster than A on this table and was about 85 times faster in the review's own run, but the absolute
figures for A should be read as "between 0.26 s and 3.8 s depending on conditions nobody has pinned down". Two
regressions are visible in the table and are small in absolute terms: the 2% clustered-tail first page moves from
11 ms to 23 ms (the planner now takes the composite instead of the `changed_at` index plus a top-N sort), and C shows
why `device_ci_changed_at_idx` stays (a sparse delta without it is 28 ms instead of 5 ms).

## Residuals

None of these is accepted by this record; each is stated so a client, a reviewer and the owner can plan around
it. "Ruling needed" means the owner must decide before merge; "design consequence" means the behaviour follows
from a recorded design decision and is stated, not waived. Owner and tracking issue are **to be filed at push**
for every row (no issue numbers exist yet).

| Id | Residual | Mitigation | Status | Owner / issue |
|---|---|---|---|---|
| HWCI-DELTA-MARGIN-ESTIMATE | The 300 s margin is an estimate of how late a committed write can become visible to a walk that began earlier, not a bound. Three ways a row ends up below a watermark that was already handed out, so that a later delta misses it: (1) a transaction held open longer than the margin; (2) a long commit: an ingest transaction whose `COMMIT` is delayed past the margin (a network blackhole, with no `idle_in_transaction_session_timeout`); (3) the database clock stepped backward by more than the margin (an NTP step, a VM resume, or a failover to a skewed node), so new stamps land below watermarks already issued. A replica clock more than about 360 s behind the database clock can also `400` a value the server itself issued (the future check uses the replica clock, the watermark the database clock). | The documented backstop is a periodic full walk (weekly and after an upgrade). The margin is a named constant, not a flag. Mitigations NOT built: (a) stamping `GREATEST(clock_timestamp(), max(changed_at))` for the clock-step case was examined on 2026-11-26 and REJECTED as a fix, so it is no longer a candidate: it lifts a new stamp only to the newest earlier STAMP, but a watermark is the clock minus 300 s at the moment a first page is served, so after any quiet stretch (no content change for more than 300 s, normal for a delta) the newest stamp is already below the watermark and the new stamp still lands under it; and after a forward clock excursion it pins every new stamp at the excursion's value until real time catches up. Closing the case with stamps alone needs a persisted high-water of the watermarks handed out, which puts a write on a read path. A second option the 2026-11-26 external opinion raised, NOT built and not tested: pair GREATEST stamping with a data-capped watermark, `LEAST(clock - 300, max(changed_at))`, so every issued watermark is at or below the current maximum stamp and every later stamp is at or above it, which covers the quiet-stretch case without a write on the read path. Its residuals, by analysis only: decommissioning the row that holds the maximum lowers the cap (closing that needs a one-row high-water written on the write path), a forward excursion pins stamps so the pinned rows are redelivered until real time catches up (at-least-once still holds), the newest second's rows are redelivered on every quiet delta, and it costs one index-end probe per content upsert and per first page. It changes the watermark value clients see, so it is a design item for the owner, not a small SQL edit. (b) a pre-`COMMIT` check that `clock - stamp` is still inside the margin for the long-commit case. Operators: run NTP on every replica and the database host. | Ruling needed (including the two new cases) | to be filed at push |
| HWCI-DELTA-SCOPED-REFUSED | A scope-confined caller cannot use `changed_since` and is refused. A device entering a scope does not bump `changed_at`, and the delta cannot see it. | Use a global-read credential for a delta, or a full walk. A caller holding only group-scoped grants is refused even when its groups cover every device, because the scope is engaged either way. A scoped delta is a follow-up only if it can include scope-entry events. The refusal carries a remediation naming the credential it needs. | Design consequence | to be filed at push |
| HWCI-DELTA-LAST-SEEN-STALE | `ci.last_seen` moves on the daily sync that finds nothing new and `changed_at` does not, so a CMDB fed only by delta pulls holds a stale `last_seen` for an unchanged device. | Documented in the manual: read `last_seen` from a full walk or `?agent_id=` if it is used as a staleness signal. | Design consequence | to be filed at push |
| HWCI-DELTA-NO-REMOVALS | A delta has no removal signal: a decommissioned device simply stops appearing. Erasure: `changed_at` and its index live and die with the `device_ci` row, but a CMDB copy of the serial, MAC or UUID is NOT erased by a decommission, and until PR 2 a delta consumer gets no signal to erase it. | PR 2 (a removals feed of tombstones carrying `agent_id` and `removed_at`) is planned, no date. The tombstones will need a retention rule under the clock-guarded-retention row (`docs/clock-guarded-retention.md`) and a data classification. Until then: confirm absence with `?agent_id=` (without `changed_since`) and retire only through the client's own decommission process. | Ruling needed | to be filed at push |
| HWCI-DELTA-REPARSE | If a server upgrade changes how stored records are interpreted without changing `content_hash`, `changed_at` does not move, and a CMDB holding the old reading is not told. No re-parse-on-upgrade code was found by the reviewers, so this is a conditional, not a present behaviour. | Run a full walk after every server upgrade (stated in the manual and the upgrade note). | Ruling needed | to be filed at push |
| HWCI-DELTA-ENTER-SCOPE | The same mechanism as HWCI-DELTA-SCOPED-REFUSED seen from the data side: any consumer that filters by a scope it computes itself (a management group or a tag) and then uses a delta will miss a device that joined that scope without a content change. | Recompute the scope membership on a full walk, or filter after the pull. | Design consequence | to be filed at push |
| HWCI-DELTA-PLAN-FLIP | See "The slow case" above. The planner flips at roughly 2 to 3% density; any clustered delta of 3% or more on its first page, final page or a mid-walk gap is slow; the worst case in the governance review's measurement (5% clustered at the head) took 3.6 to 3.8 s on its terminal page at 1M rows and breaches the 5 s statement limit at about 1.3M rows warm, earlier cold (a later re-measure of the same shape took 262 to 268 ms and did not reproduce it; see "Migration v6"). The `503` it produces is deterministic (the same `changed_since` hits the same page), carries `retry_after_ms` 5000, and wedges the walk. | Client: fall back only for the generic failure (REST `503` / MCP `-32603` with `retry_after_ms` 5000, no `Sec-Audit-Failed`, not the audit-subsystem message) when the same delta page has failed at least 3 times over at least 60 s while unfiltered pages succeed: ONE full walk, at most once per walk and not on every scheduled run; every other hint (2000, 60000, an audit failure) is honoured and never triggers it; if the fallback also fails, stop and alert; recurring fallbacks mean the delta plan is slow, to be raised with the operator. Server: mitigated by migration v6, the composite `(agent_id COLLATE "C", changed_at)` index that replaces v4's (see "Migration v6": the measured clustered cases drop to 12 to 24 ms; net +9 MB at 1M rows). What remains: a missing or invalid keyset index (the server now warns at start), and the fact that the walk is still linear in the table (the composite removes the heap fetches, not the index walk; about 22 ms per million entries on the re-measure rig, unmeasured beyond 1M). Not built: a retry-hint cause discriminator, so a deterministic `503` could stop advising a retry. | Mitigated for the measured shapes; ruling needed on the rest | to be filed at push |
| HWCI-DELTA-MIXED-BUILDS | An older binary running against the new schema only warns, and writes device-CI rows without maintaining `changed_at`: a new row gets the column default (the insert time), but a content update of an existing row leaves the old value. The miss is PERMANENT for that row, not a transient one: every later delta skips it, because the stamp is already behind every watermark. | Procedural, not enforced: this is a fresh-deployment contract, not a rolling or mixed-version procedure (`docs/user-manual/upgrading.md`). After the LAST earlier-build replica is gone, do a full walk and take a fresh watermark. v5 is forward-only. | Ruling needed | to be filed at push |
| HWCI-DELTA-PITR-RESTORE | A point-in-time restore or a restore from backup leaves `changed_at` stamps older than watermarks that clients already hold, so a delta will not show a row whose stored state the restore rolled back. | A full walk after any restore. | Residual | to be filed at push |
| HWCI-DELTA-HASH-FLAPPING | An agent whose collector output changes nondeterministically (the content hash flaps) bumps `changed_at` on every full send, so that device is re-served on every delta. | Harmless to correctness (at-least-once), a cost only; fix the agent's nondeterminism. | Residual | to be filed at push |
| HWCI-DELTA-HOT-LOSS | A content update now rewrites an indexed column, so it loses the heap-only-tuple (HOT) update path: about +29% cost per content update, a figure from the governance round's performance review on PostgreSQL 18.4 (raw logs not retained, so it is a recorded measurement, not a reproducible one). The hash-skip path is untouched. Migration v6 does not change the index count (the composite replaces v4's, and `changed_at` already forced the non-HOT path), but its entries are 8 bytes wider; that was not re-measured. | Not mitigated; no owner acceptance recorded. | Ruling needed | to be filed at push |
| HWCI-DELTA-V5-LOCK | The v5 `ALTER` takes `ACCESS EXCLUSIVE` held through the index build and queues behind any long read or write on `device_ci` for up to 30 s, during which every new access queues behind it; then it fails and the server refuses to start on every restart until the holder is gone. v6 has the same 30 s bound and failure mode, with a `SHARE` lock for its build (writes wait) and `ACCESS EXCLUSIVE` locks for its two `DROP INDEX` statements. That is a lock upgrade inside one transaction (the first drop takes the strong lock up front when the composite pre-exists, otherwise the build's `SHARE` is upgraded), which can deadlock against a session that holds `ACCESS SHARE` and then writes; no such transaction was found in this store (ingest upserts the parent first, the hash-only read is autocommit) and the hard-cutover contract excludes other writers, so it is recorded and not changed. | Documented with the log line and recovery in `docs/user-manual/upgrading.md`; the migration is idempotent. | Residual | to be filed at push |
| HWCI-DELTA-SCOPED-WALK-WATERMARK | A first page returns `next_changed_since` to any admitted caller, including a scope-confined one whose first page carries no `changed_since` (such a caller is refused only when it SENDS `changed_since`). A client that takes its first watermark from a scope-confined full walk holds a value that is correct as a clock reading but whose walk did not cover the whole fleet, so a later global delta started from it never delivers the devices that walk did not read. | Documented: run the first full walk under the SAME global credential that will run the deltas (the credential checklist in `rest-api.md`, the MCP tool description and `mcp.md`). Not built: refusing a watermark to a scope-confined caller (it would add a second scope branch to the first-page path). | Design consequence (LOW) | to be filed at push |
| HWCI-DELTA-THROW-NO-AUDIT | An exception that escapes the watermark provider (a `bad_alloc`-class throw is the only realistic one: the provider returns `nullopt` for every database failure) is not converted to the `503`/`kInternalError` answer. It reaches httplib's default handler as a bare `500` with no audit row and no A4 body. The bulk-read slot is freed by unwinding (an RAII member of the page held in the failed read), so nothing leaks. | Informational: not mitigated, no change planned. | Informational | to be filed at push |
| HWCI-DELTA-WATERMARK-OBSERVABILITY | A failed watermark read on a first page is indistinguishable from a failed page read in the audit row and in the `503` counters (both are a store failure with `retry_after_ms` 5000). | Not mitigated. The degrade is counted under `yuzu_inventory_read_degrade_total{source="device_ci"}` with the same `reason` labels a page read uses, so the counter does not tell the two apart either. | Residual | to be filed at push |
| HWCI-DELTA-AUDIT-NO-MARKER | A served delta page writes the same `inventory.devices.ci` `success` row as a full page, with no delta marker, so the audit trail cannot tell a delta read from a full read. Not built: a `delta=1` token in the detail. | Documented in `audit-log.md`. Not mitigated; no owner acceptance recorded. | Ruling needed | to be filed at push |
| HWCI-DELTA-FIRST-PAGE-TIMING | A first page takes a second pool lease for the watermark read, so its worst-case bulk-read slot hold is longer than a cursor page's (REST about 80 s against about 62 s; MCP about 124 s against about 106 s), and the client timeout advice (at least about 90 s) covers the 80 s bound plus a typical authorization read but not a stalled authorization read. The figures are sums of source constants, not measurements, and exclude `BEGIN` and the `SET LOCAL` (uncapped by the 5 s statement cap, under the pool's 30 s default). | Documented in `rest-api.md` (client loop, step 5) and `server-admin.md` ("Slot hold time"). Not mitigated: no separate bound on `BEGIN`/`SET LOCAL`. | Residual | to be filed at push |
| HWCI-DELTA-INDEX-NO-WARN | The runtime check at open used to WARN only for v4's `device_ci_agent_id_c_idx`; nothing warned when `device_ci_changed_at_idx` was missing. A delta stays correct without it. | Closed on 2026-11-26: one generic check now covers both read indexes (the v6 keyset index and `device_ci_changed_at_idx`), judging name, validity, readiness, predicate and the exact printed key list, and each WARN names its own cost and the statement to run (unit tests for each way an index can be wrong). | Closed | n/a |
| HWCI-DELTA-CLOCK-DOMAINS | `changed_at` is stamped from the database clock, while `first_seen` and `last_seen` are stamped from the replica clock. The three are not comparable to better than the replica-to-database skew. | Documented; run NTP on every replica and the database host. | Residual | to be filed at push |

## Where to read more

Client recipe: `docs/user-manual/rest-api.md` (`GET /api/v1/hardware-ci`, "Delta sync"). MCP twin:
`docs/user-manual/mcp.md` (`list_hardware_ci_records`). Upgrade note: `docs/user-manual/upgrading.md`.
Concurrency, byte bound and their residuals: `docs/security-reviews/hardware-ci-bulk-read-bounds-2026-11.md`.
