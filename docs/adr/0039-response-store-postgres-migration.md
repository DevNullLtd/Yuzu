# ADR-0039: ResponseStore → PostgreSQL (Wave 1.2)

- **Status:** Accepted — shipped PR #2691, merged 2026-08-09; `response_store.cpp` is PG-native
  (`PgPool`/`pg_exec`), zero live `sqlite3_` calls (comments only), re-verified 2026-09-07.
- **Date:** 2026-07-31
- **Deciders:** pg workstream; security-guardian + docs-writer (Gate 2)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0036 (ResultSetStore), ADR-0037 (InventoryStore), ADR-0038 (GuaranteedStateStore).

## Context

`ResponseStore` (`responses.db` today) persists agentic command/instruction **responses** —
two tables: `responses` (per-agent result rows: status, output, error, plugin,
`execution_id`, `ttl_expires_at`) and `response_facets` (denormalised column values powering
the dashboard's facet filters). High-write (every command result from every agent), TTL'd
(default 90-day retention via a background cleanup thread), a `/tar`- and executions-drawer
read source. Read surface is compact: `query` / `query_by_execution` / `get_by_instruction`
/ `query_by_ids`, `aggregate` / `distinct_agent_ids` / `facet_values` / `facet_agent_ids` /
`facet_response_ids`.

Next after ADR-0038 on the ladder. (The ladder's prior Wave-1.2 entry, FleetTopologyStore,
is **not** a SQLite store — it is an in-memory topology cache built `(fetcher, nvd)` with no
persistence, so it is out of ADR-0006 scope; the ladder row is corrected in this PR.)

## Decision

Migrate to PostgreSQL schema **`response_store`** (ADR-0008), construction fail-closed
(ADR-0012 §1), on the shared server PgPool. `sqlite3_changes()` (delete_by_instruction) →
`RETURNING`/`PQcmdTuples` (#1033). `mtx_` deleted; PG concurrency replaces the single-writer.

### Schema

`responses` + `response_facets` port column-for-column (INTEGER→BOOLEAN/BIGINT as apt; TEXT
timestamps/output stay TEXT — behavior-preserving). All indexes carry over incl. the partial
`idx_resp_ttl WHERE ttl_expires_at > 0` the reaper uses.

`plugin_result_status` (the ABI3→4 typed plugin-result column, `dev`'s `12b97f5f`/`d103ac54`)
lands as **migration v2** (`ALTER TABLE responses ADD COLUMN plugin_result_status INTEGER NOT
NULL DEFAULT 0`), not folded into v1's `CREATE TABLE` — `PgMigrationRunner` stamps
`schema_meta(store, version)` once per numbered migration and never replays an edited one, so
changing v1 in place would silently no-op on any database that already ran it.

### Posture (ADR-0012 §1)

- **Response ingest (`store`): FAIL-SOFT** (ADR-0037 shape) — a dropped result row is
  re-derivable operational telemetry (the executions ladder tracks the command; the agent's
  result is best-effort persisted for the drawer/TAR). Ingest must never block the gRPC
  thread. Drops counted (`yuzu_server_response_ingest_dropped_total{reason}`, kReason*
  constants). `store()` runs the full insert-plus-facet-batch body through
  `PgPool::with_txn_for` rather than a hand-rolled `PgTxn`/lease pair (Doomgoose finding #1) —
  `with_txn_for` already refuses to `COMMIT` and rolls back instead when the transaction isn't
  `PQTRANS_INTRANS`, so sharing it closes the aborted-txn-silently-committed gap without a
  second copy of that check. **Bounded**: output/error_detail are truncated to
  `kMaxIngestBytes` (2 MiB, matches the agent's own `kCaptureMaxBytes`) before sanitize, and a
  response's facet count is capped at `kMaxFacetsPerResponse` (5000) — an unbounded row or an
  unbounded facet fan-out from one command result no longer pressures the shared pool that auth
  reads also share (Doomgoose finding #4).
- **Reads (`query`/`query_by_execution`/`aggregate`/facets/…): degrade-distinguishable at
  the store seam** (`std::optional<vector>` nullopt-on-degrade + `yuzu_server_response_read_
  degrade_total{reason}` + sampled logs). For the executions drawer / TAR dashboard / dashboard
  results table these feed a **display**, not an enforce/target/authz decision, so per the
  playbook's deny-or-benign carve-out those consumers may render degraded (503 on the REST
  twin, empty+degrade-banner on the dashboard) — but the seam MUST distinguish empty from
  degraded so a consumer can't misread a blip as "no responses." The #1634 group-scoped-read
  seam (`ResponseQuery{.agent_id}`) is preserved exactly.

  **Correction (2026-08-08, #2691 finding 10):** the "not an enforce/target/authz decision"
  framing above does NOT extend to `/auto` Pre-flight — `preflight_eval.cpp`'s
  `collect_check_responses()` reads this same seam, and the grid it builds IS what
  `deployment_routes.cpp` reads to select `/auto` Deploy's go-cohort. A degrade there is
  gate-adjacent, not display-only, and both the background runner and the live result poll
  now check `any_check_degraded()` before persisting or completing a run — a degraded tick
  skips persisting entirely (retry next tick/poll) rather than collapsing to empty and
  silently downgrading an already-resolved device's verdict. See
  `docs/user-manual/preflight.md` + `docs/executions-history-ladder.md`.
- **Writes other than store** (`delete_by_instruction`): fail-hard (`RETURNING` count).

### Backfill (ADR-0009) — SKIPPABLE

Responses are TTL'd 90-day operational data, not authoritative config and not compliance
evidence — losing pre-cutover responses degrades only historical drawer/TAR views, which
self-refill as new commands run. So **no backfill** (the ADR-0009 skippable class, the
`ResponseStore` precedent the ladder cites): the legacy `responses.db` is not read on upgrade;
a one-time loud "response history reset on Postgres cutover" boot log. (Matches
`ApiTokenStore`'s fresh-start precedent in spirit — no legacy read, no marker table needed.)
Rationale recorded here so it is a deliberate decision, not an omission.

### Retention (clock-guarded)

The cleanup thread's bare wall-clock TTL delete ports to the #2496 `gc_sweep` shape
(the routed-concern requires it; #2508): shared `gc_meta` reading + advisory
`pg_try_advisory_xact_lock('response_store:reap', 0)` (single sweeper) +
`audit_retention::classify` decline-once + unconditional per-pass cap (10 000,
substrate-tuned to response write volume) + `yuzu_server_response_reap_passes_total{result}`.
Reaped from the maintenance tick (like GS/ResultSetStore); the in-process cleanup thread goes
away.

The implausibly-ahead bound is **DERIVED from the store's own `retention_days` at 2×
(floored ~120 d)**, not a fixed constant — `response_retention_days` is operator-configurable
and unclamped, so a fixed bound would silently reintroduce the ADR-0038 false-decline class
the moment retention passed it (every live row's honest `ttl_expires_at` would land past the
bound → excluded from `datable` → `would_wipe` trips → perpetual decline → the table never
reaps). "Size to THIS store's retention, NOT copied" (the ADR-0038 lesson) is taken literally:
the bound tracks the horizon rather than a magic number.

The per-pass cap is observable: a pass that deletes the full cap records
`result="capped"` (distinct from `swept`), so on-call can tell a healthy fully-draining reaper
from one whose 10 000/pass ceiling is being outrun by ingest on this high-write store — the
`AuditStore` cap-reached signal, ported.

**Clock source (2026-08-08, #2691):** the first cut of this reaper decided `has_expired` /
`would_wipe` / `big_step` from the process's own clock, and had no `bootstrap_settled` anchor —
the exact pre-ADR-0038-round-2 shape `GuaranteedStateStore` shipped and then had to fix twice
(FortitudeEtc's original review, then fjarvis's H1). Fixed to match: every decision-driving read
switches from `now_epoch()` to `pg_now` (`SELECT EXTRACT(EPOCH FROM now())::bigint`, read inside
the advisory-locked transaction, after the lock) — a fast/skewed replica can no longer sweep a
row that is still live by Postgres's own clock. `bootstrap_settled` joins the `gc_meta` read;
`no_anchor` in the `Facts` literal declines the very first pass on a missing anchor with partial
expiry rather than draining immediately, settling the marker only after `classify()` reaches a
verdict (never before an early return, so an early return rolls the whole transaction back). The
process clock's only remaining job is its own independent `> kMaxPlausibleNow` decline check
before the transaction opens — it does not feed the horizon. `facts_ser` carries a 5th char
(`b`) for `bootstrap_settled`; `outcome="declined_no_anchor"` is a new label on
`yuzu_server_response_reap_passes_total{result}`.

The anomaly probe (Doomgoose finding #5) is `EXISTS(...)`-based, not `count(*) FILTER` —
`count(*) FILTER` has no statement-level `WHERE`, so even with the partial index eligible it
still counts every positive-TTL row (most of the table in steady state), which is a full scan in
practice, not O(1). Two booleans instead: any-expired (`EXISTS`) and any-datable-survivor
(`(SELECT 1 ... ORDER BY ttl_expires_at LIMIT 1) IS NOT NULL`, deliberately not a second bare
`EXISTS` — a plan-independence argument against Seq-Scan-vs-Index-Scan planner drift on a wide
retention window). `kResponseRetentionProbeSql` is the reference shape; `AuditStore`'s probe is
the sibling that motivated it.

The capped DELETE itself (Doomgoose finding #6) is chunked (`kReapDeleteChunkRows=500`) under a
wall-clock budget (`kReapDeleteBudget=2000ms`), not one unbounded cascading statement — a wide
facet fan-out on a single response row makes the CASCADE to `response_facets` expensive per row,
and an unbounded statement has no way to yield mid-delete. The chunk loop reuses the existing
capped/swept/backlog-probe reporting logic; `budget_exhausted` is a distinct reason from the
row-count cap.

**Correction (2026-08-09, Gate 5 chaos-injector, empirically measured):** chunking the
*parent-row count* alone does not bound the CASCADE's own latency — `response_facets` has no
row-count limit of its own, so a single chunk of 500 parent rows, each carrying up to
`kMaxFacetsPerResponse=5000` facets, can still cascade up to 2,500,000 child-row deletes in
ONE implicit statement. Measured live against PostgreSQL 18.4, an idle uncontended database:
~1929ms for exactly that shape — already consuming nearly the entire `kReapDeleteBudget` in one
statement, with none of the concurrent-write contention a real deployment adds. Past the
connection's `statement_timeout`, that single statement fails outright, `with_txn_for` rolls the
whole pass back (every earlier chunk in it too), and the deterministic `ORDER BY` re-selects the
identical backlog next pass — a self-sustaining wedge on exactly the backlog that most needs to
drain. Fixed: `response_facets` for each chunk's ids is now pre-deleted explicitly, in its own
`kReapFacetDeleteBatchRows=5000`-row LIMIT-bounded batches (the same subquery-`ctid`-`IN`-LIMIT
idiom the parent-row delete already used), deadline-checked between batches, BEFORE the
parent-row delete runs — so by the time the parent `DELETE` executes, its CASCADE has nothing
left to do and its latency no longer depends on how many facets happened to land in one chunk.
A `YuzuResponseReapFailing` alert (`increase(result="failed")>=2` in 3h) was added alongside
this fix: a repeating-wedge condition still increments the labeled counter, so it is invisible
to `YuzuResponseReapNotRunning`'s liveness check — the counter IS moving, just onto the wrong
label.

### Lifecycle

`stop()` unwires from the ingest service(s) then resets before `pg_pool_`; store in `/readyz`
AND `/healthz`. Reap piggybacks the existing maintenance thread (respecting each store's own
is_open gate — the ADR-0038 JC-6 decoupling pattern).

### Untrusted byte columns (UTF-8)

`output` and `error_detail` are agent-supplied plugin bytes, not server-authored text — a
plugin can legitimately emit non-UTF-8 content (binary data, a mis-decoded code page, a raw
`0xff`). SQLite's permissive `TEXT` affinity stored those bytes as-is; Postgres `TEXT` requires
valid server-encoding (UTF8) and rejects an invalid sequence outright at `INSERT` time
(SQLSTATE 22021). Left unhandled, that turns governance #1593's guarantee — "malformed plugin
output must still render, defanged, never 500" — into a silent **drop**: the fail-soft ingest
path would count it as an ordinary transient failure and the row would simply never land,
which is a regression, not a preserved behaviour.

Fix: `store()` sanitizes `output` and `error_detail` to U+FFFD (the replacement character) via
the shared `sanitize_utf8_strict` helper (`utf8_sanitize.hpp` — the same implementation the
inventory and app_perf ingest seams already use for their own untrusted text) **before**
binding the `INSERT`. `finalize_terminal_status` applies the identical sanitize to the
agent-supplied `error_detail` it binds — otherwise a non-UTF-8 byte would fail the terminal-frame
`UPDATE` (SQLSTATE 22021), leaving the RUNNING row never finalized and no fallback frame, which
is the #1593 gap reopened on the finalize path rather than the ingest path. The row still lands; byte-for-byte fidelity is not required for
expendable, TTL'd operational telemetry (consistent with the store's overall fail-soft/
skippable-backfill posture). This also removes a class of render-time risk at the source —
invalid bytes never reach `aggregate_to_json`/any downstream JSON serializer in the first
place, rather than relying on every consumer to defend against them independently. `status` is server/enum-controlled and is NOT sanitized. `plugin` (agent-supplied
plugin name), `instruction_id` (the agent-echoed command id), and `execution_id` DO arrive on
the wire, so a hostile agent could emit non-UTF-8 there — but a malformed value simply
fail-soft-drops the whole row at INSERT (a garbage/hostile response defangs to a counted drop,
by design), which is NOT the #1593 legitimate-output-must-surface case. Sanitization is applied
only to the two free-text RESULT columns (`output`, `error_detail`) where dropping a real
result would be the regression #1593 guards against.

**Correction (2026-08-08, Gate 4 unhappy-path finding UP-5):** the "fail-soft-drops the whole
row at INSERT" claim above is true for invalid UTF-8 (SQLSTATE 22021) but was FALSE for an
embedded NUL specifically: NUL is valid UTF-8, so it does not fail the `INSERT` — and because
`pg::exec_params` binds every parameter as a NUL-terminated C string (`paramLengths=nullptr`),
libpq silently **truncated** an unsanitized `instruction_id`/`execution_id`/`plugin` at the
first NUL instead of rejecting it. Since `agent_service_impl.cpp`'s
`sr.instruction_id = resp.command_id()` is agent-controlled and unsanitized, a
compromised/malicious agent could send a `command_id` like `"victim-id\0junk"` and have it
land, truncated, as a response indistinguishable from a genuine one for the shorter real
`instruction_id "victim-id"` — a forgery via truncation, not the documented fail-soft-drop.
Fixed: `store()` now explicitly rejects (counted via
`yuzu_server_response_ingest_dropped_total{reason="malformed_identity_field"}`, never
truncates) any row whose `instruction_id`/`execution_id`/`plugin`/`agent_id` contains an
embedded NUL, *before* binding — restoring the fail-soft-drop guarantee this paragraph always
intended for malformed identity fields. `agent_id` was widened in during Gate 8 re-review
(security-guardian): it shares the identical mechanism (`AgentServiceImpl::Register()`
validates length and non-emptiness but not embedded-NUL), so a maliciously-enrolled device's
responses could otherwise land, truncated, under a shorter real device's `agent_id`. Six sibling stores (`auth_db`, `audit_store`, `instruction_store`,
`instruction_yaml`, `guaranteed_state_store`, `scim_json`, `vuln_finding_store`) already guard
their own identity-bearing fields this same way (`s.find('\0') != npos`); this store simply
hadn't been given the guard. The mechanism is not new to this migration — the SQLite-era store
had the identical truncate-at-NUL behaviour (`sqlite3_bind_text(..., -1, ...)` is also
strlen-bound) — but this ADR's own posture claim was the first place the gap was written down
as if it didn't exist, which is why it gates here rather than being filed as a standalone
pre-existing-bug follow-up.

One more byte the plain scrub does NOT catch, for the two free-text RESULT columns
(`output`/`error_detail`) — distinct from the identity fields above, which are REJECTED on an
embedded NUL rather than repaired: **NUL (U+0000)**. `sanitize_utf8_strict` treats
it as a valid ASCII byte and keeps it, but PostgreSQL `TEXT` cannot store an embedded NUL and
libpq's text-format bind C-string-**truncates** the value at the first NUL — silently dropping
everything after it (the same "real output vanishes" regression, on any binary/mis-decoded
result carrying a `0x00`, which is exactly the ADR's motivating case). So a thin store-local
wrapper `sanitize_pg_text` runs `sanitize_utf8_strict` and then replaces any remaining NUL with
U+FFFD too. `utf8_sanitize.hpp` itself is NOT edited — it is byte-identical with the agent's
installed_software copy (the canonical-hash invariant); NUL handling is a PG-bind concern local
to this store. Facets derive from the same `sanitize_pg_text` output, so a stored `output` and
its facet values never diverge across a NUL.

### Facet ingest — one savepoint, not one-per-facet

Facets are written as a **single batched multi-row `INSERT` under ONE `SAVEPOINT`**, not the
per-facet-savepoint loop the first cut used. The savepoint still delivers the ADR-0038
guarantee (a facet-batch failure rolls back to the savepoint and the response row still
commits — Postgres aborts the whole txn on any failed statement, unlike SQLite's silent skip),
but one savepoint mints **one** subtransaction XID regardless of facet cardinality. The
per-facet loop minted a subxid per distinct value, so a wide tabular output (>64 distinct facet
values — a routine process/vuln list) **suboverflowed** the ingest txn's snapshot and forced
cluster-wide `pg_subtrans` SLRU lookups on the SHARED server pool (a blast radius beyond this
store). The batch is chunked so `3 + 3·chunk` params stay under libpq's 65 535-param ceiling.

**Generalises**: any future store migrating an untrusted-byte `TEXT` column from SQLite to
Postgres needs the same UTF-8 **and NUL** treatment — `AuditStore` is the next store on the
ladder with agent-supplied free text and should sanitize the same way rather than rediscovering
#1593 the hard way. Any store porting SQLite's "tolerate one bad sub-insert" behaviour to PG
should reach for one batch-under-one-savepoint, not a savepoint per row (subxid suboverflow).

## Considered and rejected

- **Mandatory backfill**: rejected — responses are expendable TTL'd telemetry (ADR-0009
  skippable); a mandatory multi-GB backfill of a high-write table would add boot latency and
  OOM risk (cf. #2661) for data that self-refills.
- **Catastrophic-read type-distinguishable everywhere**: unnecessary for the display consumers
  (executions drawer / TAR / dashboard results) — the seam stays degrade-distinguishable but
  those consumers may render degraded (the ResultSetStore `list_by_owner` precedent). The
  `/auto` Pre-flight consumer is the exception (see the Posture correction above): its two
  callers check the seam's `degraded` signal explicitly and decline to persist rather than
  rendering degraded, because what they'd persist is a go-cohort input, not a display.

## Consequences

- Response history is reset on the Postgres cutover (skippable backfill) — a CHANGELOG
  "Changed" note + `docs/user-manual` mention; operationally invisible after one command
  cycle. Executions drawer / TAR read fleet-consistent across replicas afterward.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"responsestore"` `PgTestTemplate`;
  migration/fresh-DB tests keep plain `YUZU_REQUIRE_PG_DB`.
- `plugin_result_status` (ABI3→4) round-trips through `ResponseStore` unchanged — a caller
  that reads it back after this migration sees the same value it wrote before.
- `BundleOrchestrator::collate()` returns `std::expected<BundleAggregate, CollateError>`
  instead of `std::optional` (Doomgoose finding #3) — its two REST/MCP callers
  (`GET /api/v1/bundles/{id}`, `get_bundle_result`) now 503/`kInternalError` a degraded
  `ResponseStore` read distinctly from a genuine not-found/denied 404, instead of both
  collapsing to the same audit row and status code.
- A degraded `/auto` Pre-flight tick no longer completes a run or overwrites a resolved
  device's verdict (see the Posture correction above) — an operator watching a run through a
  transient Postgres blip now sees an honest "temporarily unavailable, retrying" state instead
  of devices silently flipping from a real Pass to Incomplete.

## Follow-ups

- #2634-parity reap counters land here from day one.
- The #1634 management-group-scoped response read (already threaded via `ResponseQuery`)
  stays defense-in-depth; no change.
- **Partially resolved (#2691, 2026-08-08):** the accepted limitation this bullet originally
  recorded named three scalars. Two are fixed: `facet_agent_count` / `facet_line_count` now
  return `std::optional<int64_t>`, `nullopt` on degrade, empty-filter `0` returned first so it
  can never be mistaken for a degrade. **Not yet wired to `yuzu_server_response_read_degrade_
  total`** — unlike the `query`/`aggregate`/facet-listing readers, these two don't route through
  the shared degrade-aware-read helper, so a degrade here is visible at the render layer but not
  counted on that metric; promoting them to the shared helper is a small follow-up, not done
  here. The dashboard group-creation path (`/fragments/create-group-form`, the results-table
  agent count, `/api/dashboard/group-from-results`) threads the `nullopt` distinction through: a
  degraded count renders "count unavailable (store degraded)" instead of a false `0`, and the
  write-adjacent group-creation POST 503s with an honest message instead of misreporting
  "no agents match the current filters." **`total_count` is unchanged** — still a plain `0` on
  degrade — because it has **no caller anywhere in the codebase** today; widening a dead
  function was out of this round's scope. If a caller is added, promote it the same way before
  wiring it up, not after.
- **Accepted residual, not fixed (#2691):** `compute_ttl_epoch()` (ingest-time default TTL
  stamp) still reads `now_epoch()`, the process clock, not `pg_now`. A slow/skewed replica can
  therefore stamp a subset of rows with an early default `ttl_expires_at` at INSERT time. Once
  the reap-side clock-guard fix above lands, those rows read to the guarded reaper as ordinary
  partial expiry — no `would_wipe`/`big_step`/`no_anchor` anomaly trips, they simply drain on
  their (slightly early) schedule. Lower stakes than the reap-side bug this ADR fixes (ingest-time
  skew shifts *when* an already-expendable, TTL'd row ages out by at most the clock's drift, not
  a delete-time false verdict on a row that should have survived), and bounded by the retention
  window itself. Recorded as a deliberate accepted residual rather than left silent; revisit if
  `response_retention_days` is ever tightened enough for ordinary clock drift to matter.
