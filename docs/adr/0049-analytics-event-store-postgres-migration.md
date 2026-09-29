# ADR-0049: AnalyticsEventStore → PostgreSQL (Wave 2, batch 3)

- **Status:** Accepted
- **Date:** 2026-08-14
- **Deciders:** pg workstream; security-guardian + docs-writer (Gate 2) — construction-posture
  divergence confirmed by Dave, 2026-08-20 (directed in session following the Codex/Sol + Fable
  correction, a314c5f22, which he authored; see "Construction posture" below).
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; closest posture precedent
  ADR-0039 (ResponseStore) — fail-soft ingest, expendable telemetry, skippable backfill. Drain
  claim pattern extends the single-sweeper advisory lease shipped in `audit_store.cpp` /
  `result_set_store.cpp` / `software_inventory_store.cpp` (ADR-0040).

## Context

`AnalyticsEventStore` (`analytics.db` today, `server/core/src/analytics_event_store.{hpp,cpp}`)
is an **outbox/spool**, not operator state: `emit()` inserts a JSON-serialized `AnalyticsEvent`
into `analytics_buffer`; a background thread (default 10s interval, batch 100) drains undrained
rows to registered `AnalyticsEventSink`s (JSONL file, ClickHouse HTTP) and marks them drained.
Writers include the auth/SCIM routes (login/MFA/OIDC/SAML/role-elevation events) and the
agent/gateway service handlers (command lifecycle events) — roughly 15 call sites, all already
null-guarding the store. The auth/SCIM routes hold `ServerImpl`'s own `analytics_store_`
(`if (analytics_store_) { ... }`, a `shared_ptr` — see "Teardown" below); the 15 agent/gateway
service handler sites hold a `weak_ptr` and lock it per-call
(`if (auto analytics_store = analytics_store_.lock()) { ... }`).

Public API: `emit(AnalyticsEvent)`, `query_recent(limit)`, `pending_count()`, `total_emitted()`,
`add_sink()`, `start_drain()`, `stop_drain()`, `is_open()`.

Wave 2 batch 3 on the ladder. The ladder row said `authoritative?` with "may suit a
TTL/ephemeral posture" — this ADR settles it.

## Decision

Migrate to PostgreSQL schema **`analytics_event_store`** (ADR-0008), on the shared server
`PgPool`.

### Schema

Single table, collapsed to v1 (the SQLite original had no later migrations to carry forward):

```sql
CREATE TABLE analytics_buffer (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_json TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    drained    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX analytics_buffer_pending_idx ON analytics_buffer (id) WHERE NOT drained;
```

**Partial index, not the SQLite original's plain `(drained, id)`.** The retention decision below
keeps drained rows forever, so the working set the drain claim and `pending_count()` actually
scan is only the undrained rows — indexing the whole ever-growing table would waste space on
entries neither query ever touches. Precedented (`idx_audit_ttl_id`, `idx_resp_ttl`).

### Posture (ADR-0012 §1)

- **Ingest (`emit`): FAIL-SOFT.** A dropped analytics event must never fail the operation that
  emitted it — writers include the auth/SCIM routes, so a hard-failing emit would put analytics
  availability in the auth path. `emit()` stays `void`; every drop is counted
  (`yuzu_server_analytics_emit_dropped_total{reason}`, reasons `store_not_open` /
  `pool_acquire_timeout` / `query_error` / `serialize_error`) and logged at debug — fail-soft
  means the caller continues, never that the failure is invisible (lesson from the merged wave
  PRs). Bounded acquire is short (250ms) since this runs on hot request paths.
- **Reads (`query_recent`, `pending_count`): degrade-distinguishable at the seam.**
  `std::optional<T>`, `nullopt` on a DB error (store not open / pool timeout / query error) —
  distinct from a genuinely empty buffer. Both feed only diagnostics (`/api/analytics/status`,
  `/api/analytics/recent` — operator-facing display, not a grant/target/enforce/skip decision),
  so per the playbook's deny-or-benign carve-out the REST handlers 503 on a degraded read rather
  than rendering a false `pending_count: 0` — honest-degraded, not fail-open.
- **`total_emitted()`: changed from a `COUNT(*)` query to an in-process atomic counter**,
  incremented on every successful insert. The SQLite original's own doc comment already said
  "since store was opened" — an atomic counter is a more literal match for that contract than a
  full-table `COUNT(*)`, and it sidesteps the playbook's counting-aggregate anti-pattern
  (`AuditStore`'s ADR-0040 finding: an unqualified count visits every row, including the
  ever-growing drained set this store's own retention decision below keeps around forever).

### Backfill (ADR-0009) — SKIPPABLE

The spool is transient by design and a **drained row is already delivered** — losing it costs
nothing. The honest exception is **undrained rows at cutover**: in healthy operation that's
bounded by the drain interval (≤10s of events), but if sinks were failing pre-upgrade it could be
up to whatever backlog had accumulated. Recorded as a deliberate, bounded loss, not assumed by
analogy to ResponseStore: no backfill, the legacy `analytics.db` is never read on upgrade.
**Correction (adversarial review, 2026-08-14):** the boot log recording this is a steady-state
`info` line on every successful open, not a one-time warning — the ResponseStore precedent this
originally matched has the identical shape (a `warn` that fires on every restart, not just the
actual cutover boot), and copying it uncorrected would have shipped the same doc/code mismatch
here. There is no cheap way to distinguish "this is the actual cutover boot" from "the 400th boot
since," so the log is phrased as an ongoing fact (server.cpp's actual line: "[PG] analytics spool
on Postgres (schema analytics_event_store) — legacy analytics.db is not migrated ..."), not a
one-time event notification.

### Secrets — none in `attributes`/`payload`; one found and fixed in `session_id`

Grepped every `emit()` call site's `attributes`/`payload` construction (auth_routes.cpp,
scim_routes.cpp, agent_service_impl.cpp, gateway_service_impl.cpp): usernames, source IPs, reason
strings, method/status labels, durations, byte/exit-code counts. No plaintext password, TOTP
code, or API token fragment is ever assigned into those two fields. Plain columns, no
`SecretCodec` needed there.

**Correction (governance Gate 2, 2026-08-16, security-guardian):** the first pass of this audit
covered `attributes`/`payload` and missed a THIRD field — `AnalyticsEvent::session_id`, set
separately at `auth_routes.cpp`'s `emit_event()`. That line (pre-existing, not introduced by this
migration) assigned the RAW `yuzu_session` cookie value — the exact bearer token
`AuthManager::validate_session()` accepts — verbatim. Read-only on SQLite, this was a
narrow-blast-radius wart; migrated onto the shared Postgres substrate under this ADR's own
unbounded drained-row retention (see Retention below) and readable by any `Infrastructure:Read`
holder via `/api/analytics/recent` (a broad, non-session-management permission), it became a
durable, widely-readable session-hijack vector — including hijacking an admin's session via
`role.elevation.granted` events. Fixed in this PR: `emit_event()` now stores
`AuthManager::sha256_hex(extract_session_cookie(req))` — a one-way hash, still useful as a
same-session correlator, never a redeemable credential. `AuditStore`'s `session_id` field
(`auth_routes.cpp`'s `make_audit_event`/`audit_log_for_principal`, two other call sites of the
same `extract_session_cookie()`) has the identical raw-value pattern but feeds a different,
already-migrated, out-of-scope store — not fixed here; flagged as a follow-up (its read-permission
gating may already be adequately restrictive, not established either way by this review).

### Untrusted bytes (UTF-8) — handled at serialization, not at bind

Event fields (hostname, agent_version, correlation_id, error text, ...) are agent- or
client-supplied and can carry invalid UTF-8. Unlike `ResponseStore`/`AuditStore`, this store
serializes the whole event to a JSON string via `nlohmann::json::dump()` *before* binding —
`dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)` substitutes U+FFFD for invalid
UTF-8 instead of throwing (the `bundle_service.cpp`/`preflight_eval.cpp`/`dex_event.cpp` idiom),
so a malformed field degrades a fail-soft emit to "logged and dropped," never an exception into
the caller's request path. `dump()` also unconditionally escapes control characters (including
NUL) as `\uXXXX`, so the emitted JSON text carries no raw `0x00` byte — no separate
`sanitize_pg_text`/embedded-NUL guard is needed on the bind, unlike `ResponseStore`/`AuditStore`'s
raw untrusted columns.

### Retention — deliberately unchanged (growth caveat, not fixed here)

The SQLite original never deleted drained rows. This migration **keeps that behavior exactly**
rather than adding a clock-driven cleanup pass, per the kickoff hazard: any bulk delete keyed off
wall-clock age is a clock-guarded retention pass (the full #2360/#2508 shape — routed concern),
and building that machinery for a store whose growth has never been measured against production
volume is out of scope here. Caveat, sharper on Postgres than it was on SQLite: growth now lands
on the **shared substrate** (disk, autovacuum, backups), not an isolated per-process
`analytics.db` file. Tracked as a follow-up (#2508-adjacent) rather than solved in this PR.

### Drain — single-sweeper claim, then send with no lease held, then revert on failure

The AuditStore/ResultSetStore advisory-lease pattern (`pg_try_advisory_xact_lock`) doesn't port
unmodified: a pure reap pass does all its work inside one transaction, but this store's "reap"
step is `sink->send()` — network I/O (a ClickHouse HTTP POST) — and ADR-0012 §5 forbids holding a
lease across external work. So the drain pass is three phases, never overlapping a lease with
sink I/O:

1. **CLAIM** — one transaction: `pg_try_advisory_xact_lock('analytics_event_store:drain')`
   (exactly one replica drains per tick fleet-wide) then
   `UPDATE analytics_buffer SET drained = true WHERE id IN (SELECT id FROM analytics_buffer
   WHERE NOT drained ORDER BY id LIMIT $1) RETURNING id, event_json`. Committing releases the
   lock.
2. **SEND** — `sink->send()` for every registered sink, **no lease held**. All sinks must
   succeed for the batch to count delivered (preserves the SQLite original's `all_ok` gate).
3. **REVERT** — only on a partial/total sink failure: a separate, later transaction sets
   `drained = false` back on the claimed ids so the next tick retries them.

**Delivery semantics, stated explicitly:**
- **At-most-once on a crash between phases 1 and 2** — rows are already committed
  `drained = true` but never sent. Accepted: expendable, best-effort telemetry, and the same
  class of loss the SQLite original had on an unclean shutdown mid-batch.
- **At-least-once on a sink that fails then recovers** — phase 3 un-claims for retry, same
  outcome as the SQLite original's `all_ok` gate.
- **A batch row whose JSON fails to parse is claimed in phase 1 but never added to the
  send/revert sets, so it drains exactly once and is dropped.** This is a deliberate improvement
  over the SQLite original, which re-selected (and re-failed to parse) a poison-pill row every
  tick, forever.
- **A revert that itself fails to acquire a connection or errors** is logged at error level
  naming the stuck id count; those rows stay `drained = true` without confirmed delivery
  (silent-loss risk on a already-rare double-failure path — sink down AND pool exhausted in the
  same tick — accepted for expendable telemetry, not counted on a dedicated metric today).

Single-sweeper via the advisory lock means `FOR UPDATE SKIP LOCKED` inside the claim's subquery
would be redundant — no second replica ever reaches that SELECT concurrently.

### Construction posture — a deliberate, recorded divergence

The playbook's default: "a Postgres store that cannot open is a fatal startup error," applied
uniformly to `OfflineEndpointStore`/`PreflightRunStore`/`DeploymentRunStore`/etc. This store
diverges: **on a migration/open failure, `server.cpp` logs and leaves the feature degraded for the
run — the store stays constructed and wired with `is_open() == false` — rather than setting
`startup_failed_`.** Reasoning:

- `--no-analytics` defaults **off** (analytics collection is on by default) — so this is not a
  low-blast-radius opt-in feature where "just don't turn it on" is the escape hatch; most
  deployments carry it.
- Every one of the ~15 call sites already treats `analytics_store_` as optional (null-guarded
  or, for the agent/gateway service handlers, `weak_ptr::lock()`-guarded — see "Teardown"
  below) — nothing downstream is load-bearing on it existing. The
  store's own posture bundle (fail-soft ingest, degrade-distinguishable reads, skippable
  backfill) is "this data is expendable" end to end; gating the whole server's boot — auth, RBAC,
  every other store — on this one non-critical table's migration succeeding would contradict
  that posture at the one point that matters most (whether the server starts at all).

`/readyz` still surfaces the distinction Pattern E governance has repeatedly flagged (a
not-open-but-should-be-open store silently reads as healthy): `!cfg_.analytics_enabled ||
(analytics_store_ && analytics_store_->is_open())` reports true when the feature is off, false
when it's on but dead — visible to on-call without gating the rest of the fleet's readiness on a
non-critical telemetry store.

**Correction (governance Gate 2, 2026-08-16, security-guardian):** the first cut of this row
shipped in the SAME `checks` vector as every other, mandatory-gating store — so a migration
failure here flipped the WHOLE node's `/readyz` to 503, pulling it out of LB/orchestrator
rotation on a non-critical table's hiccup, exactly contradicting the paragraph above (and the
comment that used to sit on that row). Fixed: the row now lives in a separate `notices` list that
surfaces in the `/readyz` body (`"degraded":["analytics_event_store"]`) but never contributes to
the gating `failed_stores` list or the response's HTTP status.

**Correction (independent Codex/Sol + Fable architect review, 2026-08-19):** the first cut of this
divergence DID `.reset()` the store object on a failed open, which turned out to be a regression
against the SQLite predecessor rather than a neutral design choice — checked against the
predecessor's construction code at branch point `a661cb06a`, which constructs the object
unconditionally when enabled and only gates sink registration/`start_drain()` on `is_open()`,
never dropping the object itself. The `.reset()` collapsed two materially different states into
one nullptr: "disabled by `--no-analytics`" and "enabled but failed to open." That broke the
degrade-distinguishable-reads claim earlier in this ADR at exactly the seam meant to prevent it —
`/api/analytics/status` and `/api/analytics/recent` both key off `if (analytics_store_)`, so a
construction failure rendered identically to intentional disablement, and the four analytics
Prometheus metric families were only `describe()`/pre-seeded inside the successful-open branch, so
they never existed at all on a failed open — absence-based alerting couldn't tell "off" from
"broken" either. Fixed: the object is no longer reset on a failed open (every method already
internally fail-softs on `is_open()` — `emit()` counts `store_not_open` and returns; reads return
`nullopt` — so keeping it alive costs nothing and was the only piece missing), and metrics
registration is unconditional rather than gated on a successful open. `/readyz`'s notices-row logic
(`analytics_store_ && analytics_store_->is_open()`) was already written to expect a possibly-
not-open-but-non-null object and needed no change.

**This is the one point in this migration that isn't a straight port of an existing pattern.**
Confirmed by Dave, 2026-08-20, per the kickoff doc's governance checkpoint — closes COMP-MERGE /
SEC-3 / ARCH-2 (`governance.d/analytics-event-store-postgres-migration.8XBNVK.jsonl`).

### Teardown — object lifetime vs. the detached-thread reader

A second, separate divergence from the sibling PG-backed stores, found and closed during PR
#3350 review (2026-08-20): `analytics_store_` is the only ingest-service-wired store owned as
`shared_ptr`/observed as `weak_ptr` rather than `unique_ptr`/raw pointer.

- **SEC-5** (governance, 2026-08-16): `analytics_store_` was never `.reset()` in `stop()` before
  `pg_pool_.reset()`, unlike every sibling PG-backed store — a dangling `PgPool&` risk. Fixed by
  adding an explicit `analytics_store_.reset()` to `stop()`, matching sibling discipline.
- **FJARVIS-UAF** (PR #3350 CHANGES_REQUESTED review, fjarvis, 2026-08-20; independently
  confirmed by security-guardian): that fix raced `forward_gateway_pending()`'s untracked,
  unjoined detached thread (up to ~900s lifetime across its 3 retries), which reads
  `AgentServiceImpl`/`GatewayServiceImpl`'s `analytics_store_` with no synchronization and calls
  `emit()` on it — a reachable use-after-free. Declaration-order reasoning alone (destructing the
  object via implicit member destruction rather than an explicit `stop()`-time reset) bought no
  meaningful wall-clock margin against a thread that can outlive `stop()` by hundreds of seconds.
- **Fix**: `analytics_store_` converted to `shared_ptr` (owned by `ServerImpl`, constructed via
  `make_shared`); `AgentServiceImpl`/`GatewayServiceImpl` hold it as `weak_ptr`, locked per-call
  at all 15 call sites (`if (auto analytics_store = analytics_store_.lock()) { ... }`) — a caller
  that successfully locks holds a real `shared_ptr` keeping the object alive for the duration of
  its own call, regardless of `stop()`'s teardown timing. This closes the object-lifetime vector
  structurally rather than by timing margin. The complementary `pg_pool_`-borrow vector (the
  object staying alive doesn't mean `pool_` does) is closed by an internal `shutting_down_` latch
  on `AnalyticsEventStore` itself, set first-thing in `stop_drain()` (called well before
  `pg_pool_.reset()` in `stop()`'s sequence) and checked before any `pool_` access in `emit()`
  and (sticky-stop) `start_drain()` — the two paths reachable from an untracked thread or able to
  spin up a fresh pool-touching one. `query_recent()`/`pending_count()` are deliberately NOT
  gated on it (a first cut did gate them too; see the correction below).
- **The weak_ptr members themselves must never be written after wiring** (architect review, PR
  #3350, 2026-08-20): the first cut of this fix kept the siblings' unwire-then-reset habit,
  calling `set_analytics_store({})` in `stop()` to clear the `weak_ptr`. That's a plain,
  unsynchronized write to the same `weak_ptr` instance a detached-thread caller may concurrently
  `.lock()` — a genuine data race (confirmed under TSan on a minimal reproducer of this exact
  shape), not merely theoretical. Fixed by deleting those two calls: a `weak_ptr` needs no
  explicit clearing, since `analytics_store_.reset()` (the owning `shared_ptr`) already expires
  the shared control block atomically for every locker, which is precisely what that machinery
  is built for. The wiring calls at construction are this member's only write, ever, before any
  concurrent reader exists — write-once-before-concurrency, race-free by construction.
- **Reads must stay answerable after `stop_drain()`** (fjarvis, PR #3350, 2026-08-20; correcting
  the bullet above): the fix that added the `shutting_down_` latch initially gated
  `query_recent()`/`pending_count()` on it too, for symmetry. That broke this store's own drain
  tests, which call `stop_drain()` then read `pending_count()` to observe final state — the
  intended, established usage, not a test bug. Root cause was never actually reachable for these
  two methods: their sole production callers are `web_server_->Get(...)` HTTP handlers, and
  `server.cpp`'s `web_thread_` join (with its own bounded wait/`_Exit` escalation) completes
  strictly before `pg_pool_.reset()` runs — every httplib worker thread, including any in-flight
  analytics handler, is already joined by then. That's a join ordering, not a timing margin.
  The gate was defense-in-depth for a caller that doesn't exist on these two paths; removed. This
  first surfaced on CI's initial real `[pg]` execution (these tests skip locally without
  `YUZU_TEST_ENABLE_PG`) — verified by hand against a real local Postgres before re-pushing.
- **Residual, deliberately not fixed here**: `forward_gateway_pending()`'s detached thread itself
  outliving `stop()`, generally, is the pre-existing #3279 class — Dave has already deferred that
  for the sibling stores (`response_store_`/`webhook_store_`/`offload_target_store_`, commit
  `4c070b484`). This fix does not extend, and was not asked to extend, that deferral's scope; it
  makes `analytics_store_` specifically no longer reachable through the UAF vector at all,
  independent of whether #3279 is ever resolved for the siblings.
- **Deliberate inconsistency, not an oversight**: `analytics_store_` is now the only ingest-wired
  store on this ownership model — siblings remain raw-pointer/`unique_ptr`, unmodified. This was
  an explicit scope choice (Dave, 2026-08-20, choosing this over extending the #3279 deferral to
  analytics_store_ by name, or doing the full #3279 root fix — joining/tracking the detached
  threads — for every affected store). The dividing line, sharpened: a new store wired into
  `AgentServiceImpl`/`GatewayServiceImpl` but NOT reached by `forward_gateway_pending()`'s
  detached thread should default to the sibling raw-pointer pattern (matching the majority, and
  #3279's still-open scope) — that thread's reach is what turns the generic #3279 exposure into
  a concrete UAF, so a store outside it doesn't inherit the risk this fix closes. A new store
  that IS reached by that thread inherits the identical concrete risk `analytics_store_` had and
  should get this same treatment (or #3279's eventual root fix, once one exists) rather than the
  raw-pointer default. A future change attempting to "fix" the inconsistency by reverting
  `analytics_store_` to raw-pointer should read this section first.

## Considered and rejected

- **Mandatory backfill**: rejected — the buffer is a transient spool; a drained row is already
  delivered and undrained rows are, by design, in flight rather than durable state.
- **Fatal construction failure (the uniform playbook default)**: rejected for the reasons above —
  recorded as the divergence, not silently applied by copying `OfflineEndpointStore`.
- **`FOR UPDATE SKIP LOCKED` in the claim query**: redundant given the advisory-lock
  single-sweeper — no second replica ever reaches the claim SELECT concurrently.
- **Retention/cleanup of drained rows in this PR**: rejected — no measured production growth
  rate to size a clock-guarded pass against yet; the kickoff hazard is explicit that any cleanup
  here means committing to the full #2360 shape. Deferred, tracked as a follow-up.

## Consequences

- Any events undrained at Postgres cutover are lost (bounded by the drain interval in healthy
  operation) — a steady-state boot `info` log (not a one-time event, see the Backfill section's
  correction above) + `changelog.d/` "Changed" fragment + a `docs/user-manual`/`docs/upgrading.md`
  note record the deliberate reset.
- `total_emitted()` semantics narrow slightly: an in-process atomic (matches the store's own
  documented "since opened" contract) rather than a durable `COUNT(*)` — a value that used to
  survive a process restart (by re-querying SQLite) now resets to 0 on restart, same as
  `ResponseStore`'s analogous in-memory-only pieces.
- `query_recent`/`pending_count` callers (the two `/api/analytics/*` diagnostics routes) now
  503 on a degraded read instead of silently rendering an empty/zero result.
- Drained-row growth is unbounded (deliberately, per the retention decision above) — now a
  shared-substrate concern, not an isolated file; flagged, not fixed.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + the shared `"analytics"` `PgTestTemplate`. The store's own
  `test_analytics_event.cpp` and eight of the ten other fixture files that construct it as a
  secondary dependency use the new `test_analytics_pg_helper.hpp` `AnalyticsEventStorePg`
  bundle, sharing the same template key so the migration is paid once per suite run.
  **Correction (governance Gate 4, 2026-08-16):** `test_schedule_routes.cpp` and
  `test_scim_routes.cpp` do NOT use the bundle or the `"analytics"` template — each constructs
  `AnalyticsEventStore` directly against a `PgPool` an earlier fixture member already owns
  (`rbac_pool` / `auth_db.pool()`), per that store's own migration, not the shared one. An
  earlier revision of this bullet claimed all ten used the bundle; it did not.

## Follow-ups

- Drained-row retention/cleanup — needs production growth data before sizing a #2360-class
  clock-guarded pass; tracked adjacent to #2508.
- A revert-phase failure (pool exhausted or a query error while un-claiming a failed batch)
  leaves the affected rows `drained = true` without confirmed delivery and is logged but not
  separately counted on a metric — small blast radius (requires sink-down AND pool-exhausted in
  the same tick) but not yet observable in Prometheus.
- `docs/user-manual`/settings UI: the settings page's "Enabled"/"Disabled" analytics status
  label reads `cfg_.analytics_enabled` directly, so it can show "Enabled" even when construction
  silently disabled the feature (migration failure). Cosmetic accuracy gap, not fixed here.
- `AuditStore`'s `session_id` field (`auth_routes.cpp`'s `make_audit_event`/
  `audit_log_for_principal`, two call sites of the same `extract_session_cookie()`) has the
  identical raw-bearer-cookie pattern this ADR fixed for `AnalyticsEvent.session_id` (see
  §Secrets above) — a separate, already-migrated, out-of-scope store. Not established either way
  whether its narrower read-permission gating already makes this a non-issue there; needs its own
  assessment, not assumed safe by silence.
- `/health`'s store-aggregate check never included `analytics_store_`, before or after this PR
  (governance Gate 8 re-review, 2026-08-16) — pre-existing gap, same "readyz-vs-healthz drift"
  class this file documents for several sibling stores. `/readyz`'s new `degraded` field already
  covers on-call visibility; not fixed here.
- The new `/readyz` `degraded` field has no dedicated test coverage (governance Gate 8
  re-review, 2026-08-16) — worth a `[readyz]`-tagged regression test asserting the JSON shape
  for all four ready/degraded combinations.
