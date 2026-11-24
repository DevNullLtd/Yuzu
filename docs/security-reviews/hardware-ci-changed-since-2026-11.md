# Bulk device-CI read: the `changed_since` delta filter, decisions and residuals

**Date:** 2026-11-24
**Change:** `GET /api/v1/hardware-ci` and the MCP tool `list_hardware_ci_records` gain a `changed_since`
filter, a per-row `changed_at` and a per-page `next_changed_since` (PR 1 of 2; PR 2 is the removal feed).
**Status:** implemented, not merged. The design was reviewed (Fable) and approved by the owner before
implementation. This record is additive: it does not edit
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
   (the database's) orders every writer and every watermark.
3. **Backfill by default value, metadata only.** `ADD COLUMN ... DEFAULT (EXTRACT(EPOCH FROM now()))::bigint`
   is a stable (not volatile) default, which PostgreSQL 11 and later apply without rewriting the table.
   Existing rows therefore read as changed at migration time, and the first delta pull returns the fleet
   once. The index is built in the same migration under the `SET LOCAL lock_timeout` and `statement_timeout`
   pattern that migration v4 uses.
4. **Filter `changed_at >= $n`**, so delivery is at-least-once: a row exactly at the boundary is served again
   rather than lost. The client upserts by `agent_id`. With no filter the SQL text and parameters are
   byte-identical to before.
5. **Watermark `next_changed_since` = database clock minus 300 s** (`kChangedSinceMarginSecs`), on every
   page. The client keeps the FIRST page's value of a walk. The margin covers a write whose transaction was
   open (or whose commit was delayed) when the walk began: such a row commits with a `changed_at` earlier
   than the watermark yet becomes visible only after the read. It is an estimate of that lag, not a bound
   on it (HWCI-DELTA-MARGIN-ESTIMATE).
6. **A delta needs a global-read credential.** A scope-confined caller (management group or service scoped)
   who sends `changed_since` gets a definitive refusal that names no device and no count. A device that
   enters a caller's scope does not change its record, so `changed_at` does not move and a scoped delta
   would silently omit it. Pushing the scope into the delta SQL does not make it safe: it would be a
   query that looks complete and is not. The scope-confined caller keeps the full walk.
7. **Validation.** A malformed, negative or future-dated value is `400` (MCP `-32602`), the precedent of
   `hardware_routes.cpp` for `limit`. The value is bound into the cursor filter fingerprint; the no-filter
   fingerprint is byte-identical to before, so a cursor issued before this change still decodes (the `h1`
   format is frozen).
8. **Upgrade safety.** The store constructor's projection probes include `changed_at`, so an old schema
   fails closed the way v2 to v4 do.

## Unchanged contract

The 4 MiB REST and 1 MiB MCP byte bounds, the `BulkReadSlots` cap held through the audit write, the
collation gate refusal, the A5 MCP annotations and honest `retry_after_ms`, the fail-closed
`inventory.devices.ci` audit row and the byte-ordered (`COLLATE "C"`) keyset are untouched.

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

**The one slow case (HWCI-DELTA-PLAN-FLIP).** When about 5% of the rows changed AND they cluster at the end
of `agent_id` order, the planner picks the `agent_id` index with a filter and scans most of the table
before it finds a page. At 1M rows that took 2,203 ms for the first page (2,172 ms the worst page of the
walk), under the 5 s statement limit; by extrapolation the limit is reached at roughly 2.5M rows or more
(an estimate, not a measurement). Random ids scatter changes and do not trigger it; sequential ids with a
block of the newest devices changing would.

## Residuals

None of these is accepted by this record; each is stated so a client and a reviewer can plan around it.

| Id | Residual | Mitigation and owner |
|---|---|---|
| HWCI-DELTA-MARGIN-ESTIMATE | The 300 s margin is an estimate of how late a committed write can become visible to a walk that began earlier. A transaction held open longer than the margin can commit a row stamped before the watermark that was already handed out, and a later delta then misses it. | The documented backstop: a periodic full walk (the manual says weekly and after an upgrade). The margin is a named constant, not a flag. |
| HWCI-DELTA-SCOPED-REFUSED | A scope-confined caller cannot use `changed_since` and is refused. A device entering a scope does not bump `changed_at`, and the delta cannot see it. | Use a global-read credential for a delta, or a full walk. A caller holding only group-scoped grants is refused even when its groups cover every device, because the scope is engaged either way. A scoped delta is a follow-up only if it can include scope-entry events. |
| HWCI-DELTA-LAST-SEEN-STALE | `ci.last_seen` moves on the daily sync that finds nothing new and `changed_at` does not, so a CMDB fed only by delta pulls holds a stale `last_seen` for an unchanged device. | Documented in the manual: read `last_seen` from a full walk or `?agent_id=` if it is used as a staleness signal. |
| HWCI-DELTA-NO-REMOVALS | A delta has no removal signal: a decommissioned device simply stops appearing. | PR 2 (a removals feed) is planned, no date. Until then: confirm absence with `?agent_id=` and retire only through the client's own decommission process. |
| HWCI-DELTA-REPARSE-NOT-SIGNALLED | A server upgrade that re-parses stored records (a new parser version) does not change `content_hash` and so does not bump `changed_at`. A CMDB holding the old parse is not told. | Run a full walk after every server upgrade (stated in the manual and the upgrade note). |
| HWCI-DELTA-ENTER-SCOPE | The same mechanism as HWCI-DELTA-SCOPED-REFUSED seen from the data side: any consumer that filters by a scope it computes itself (a management group or a tag) and then uses a delta will miss a device that joined that scope without a content change. | Recompute the scope membership on a full walk, or filter after the pull. |
| HWCI-DELTA-PLAN-FLIP | A delta of about 5% of the rows, clustered at the tail of `agent_id` order, plans as an `agent_id` index scan with a filter: 2.2 s a page at 1M rows, and an estimated 5 s statement-limit breach at about 2.5M rows or more (a page then answers 503). | Not mitigated in this change; measured only up to 1M rows. Follow-up: a capped pre-count of the delta that picks an index-driven form for a small delta. A composite `(changed_at, agent_id)` index was considered and does not change the plan choice by itself. |
| HWCI-DELTA-MIXED-BUILDS | An older binary running against the new schema only warns, and writes device-CI rows without maintaining `changed_at` (a new row gets the column default, the insert time; an update of an existing row leaves the old value). A delta taken while one is running can miss its changes. | Hard cutover: every replica on the new build before delta pulls are relied on (see `docs/user-manual/upgrading.md`). Procedural, not enforced. |

## Where to read more

Client recipe: `docs/user-manual/rest-api.md` (`GET /api/v1/hardware-ci`, "Delta sync"). MCP twin:
`docs/user-manual/mcp.md` (`list_hardware_ci_records`). Upgrade note: `docs/user-manual/upgrading.md`.
Concurrency, byte bound and their residuals: `docs/security-reviews/hardware-ci-bulk-read-bounds-2026-11.md`.
