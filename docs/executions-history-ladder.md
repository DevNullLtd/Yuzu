# Executions-history ladder — invariants

Reference for the executions-history ladder PRs (PR 2 `responses.execution_id`
correlation and PR 3 SSE live updates). CLAUDE.md keeps a one-line pointer; this
document holds the hard invariants every successor PR in the ladder must check.

## PR 2 — `command_id → execution_id` mapping

`responses.execution_id` is populated at write time by resolving the
`command_id` against `ExecutionTracker`'s PG-backed `command_execution` table
(HA WS-1(1b), ADR-2002 section 5 — migrated off the former in-process
`AgentServiceImpl::cmd_execution_ids_` map, which was replica-local and could
not resolve a response landing on a different server instance than the one
that dispatched it). `ExecutionTracker::record_command_execution` /
`::lookup_execution_id` are the store's write/read entry points;
`AgentServiceImpl::record_execution_id` / `::resolve_execution_id` are the
corresponding `AgentServiceImpl`-side wrappers, with `resolve_execution_id`
the single chokepoint every response-receipt read goes through. The mapping is registered at dispatch
time INSIDE `cmd_dispatch` BEFORE any RPC is sent — closes the FAST-agent race
where a sub-millisecond loopback agent could reply before a post-dispatch
registration. The `CommandDispatchFn` typedef carries `execution_id` as its
sixth parameter; pass empty to opt out (out-of-band dispatch / no-tracker
callers).

### Known coverage gap (every PR in this ladder must check this)

Only `/api/instructions/:id/execute` (`workflow_routes.cpp`) creates an
execution row AND threads `execution_id` into `cmd_dispatch`. The following
dispatch surfaces produce `execution_id=''` responses, falling back to the
legacy timestamp-window join in the executions detail drawer:

- Workflow-step dispatch (`/api/workflows/:id/execute` step `cmd_dispatch`
  callback at `workflow_routes.cpp` line ~925)
- Schedule / approval-triggered dispatch
- Rerun (`/api/executions/:id/rerun` via `create_rerun` — does not currently
  dispatch a command, so the gap is structural, not a wiring bug)

(MCP `execute_instruction` was on this list; it is a tracked-execution
producer since #1088 — see `docs/user-manual/mcp.md`.) Closing each remaining
gap is the scope of PR 2.x follow-ups. **When adding any new
dispatch path that creates an execution row, it MUST thread `execution_id`
into `cmd_dispatch`** — failure produces silent empty-string tagging with
no error or warning.

### Multi-agent fan-out invariant

A single `command_id` is dispatched to N agents; each agent sends its own
response with the same `command_id`. Terminal-status branches in
`agent_service_impl.cpp` do NOT delete the `command_execution` row — deleting
on the first agent's terminal would leave agents 2..N stamping empty
`execution_id`. The row ages out via
`ExecutionTracker::reap_command_execution_mappings` instead (HA WS-1(1b)) — a
clock-guarded retention sweep on a ~60m cadence
(`yuzu_exec_correlation_reap_total` / `_reap_clock_anomaly_total` /
`_store_degrade_total`), not an unbounded in-process leak. The dispatch-time
write (`record_command_execution`, single attempt, no retry — deliberately
bounded to `kWriteTimeout` since it sits on the synchronous pre-RPC dispatch
path) has its own counter on failure, `yuzu_exec_correlation_write_degrade_total`,
distinct from the reap counters above.

Regression pin: `tests/unit/server/test_agent_service_impl.cpp` (9 cases /
47 assertions) drives `process_gateway_response` end-to-end into a real
`ResponseStore` and pins the no-erase rule (HF-1 fan-out across 4 agents
with mixed terminal statuses), the RUNNING/terminal stamping branches,
and the `__timing__|...` sentinel early-return. The
`test_workflow_routes.cpp:814` sibling case covers the response-store
level only.

### Server restart / cross-replica behaviour

The mapping is PG-backed (HA WS-1(1b)), so it survives a server restart and
resolves identically regardless of which server replica's `AgentServiceImpl`
receives the response — the property the migration off the in-process map
exists to deliver (WS-9 scenario: `test_execution_tracker.cpp`'s
"a command_execution mapping written on one instance resolves on a SEPARATE
instance"). A mapping still does not survive its own retention window (see
the fan-out section above) or a degraded/unreachable Postgres — either
produces a response tagged `execution_id=''` that uses the legacy
timestamp-window fallback in the drawer, the same degrade path an unmapped
out-of-band dispatch already takes.

### Non-tracked correlation-id prefixes (`polchk-`, `bundle-`, `preflight-`, `deployment-`)

`notify_exec_tracker` skips four server-minted correlation-id prefixes that ride
the `execution_id` column on `responses` (so their rows are retrievable via
`ResponseStore::query_by_execution`) but are **NOT operator executions** —
creating a tracker row for them would publish a phantom `agent-transition` SSE
event and leave an orphan `agent_exec_status` row that the executions drawer /
`/api/v1/events` would surface:

- **`polchk-`** — minted by `PolicyEvaluator`; compliance-check responses only.
- **`bundle-`** — minted by `BundleOrchestrator` (ADR-0011); the N ordinary
  command responses of one live-query bundle. A bundle is N commands to ONE
  agent, so the agent-counted tracker would mark it complete after the first
  step — collate (`received`/`succeeded` vs `expected`) is the bundle's sole
  completion authority, deliberately outside this ladder.
- **`preflight-`** — minted by `PreflightRoutes` / `PreflightRunner` as
  `preflight-<run_id>-<check_key>`; the `/auto` pre-flight checks. A run
  re-dispatches each check under the same per-check id so `query_by_execution`
  unions the re-dispatches per agent. There is no `ExecutionTracker` row —
  `PreflightRunStore` is the run's completion authority, deliberately outside
  this ladder.
- **`deployment-`** — minted by the deployment engine as
  `deployment-<deployment_id>-stage` / `-exec`; the `/auto` DEPLOY stage's
  content_dist stage + execute_staged commands. The engine reads each phase's
  responses back via `query_by_execution` to advance the per-device state machine;
  `DeploymentRunStore` is the run's completion authority. (Unlike the read-only
  `preflight-` checks, the execute phase MUTATES — but that safety lives in the
  store's claim-before-dispatch CAS, not here; this ladder only keeps the phantom
  tracker rows out.)

All ids are **server-minted, never caller-supplied** into `notify_exec_tracker`,
and their namespaces are disjoint from real tracker ids (32-hex, no prefix), so a
caller cannot collide a real execution into the skip. **Any new correlation-id
prefix that stamps `responses` for internal retrieval but is not an operator
execution must be added here and guard `notify_exec_tracker` the same way.**

### Terminal-frame finalize invariant (UAT 2026-05-06)

A `CommandResponse` with `status` ∈ {`SUCCESS`,`FAILURE`,`TIMEOUT`,`REJECTED`}
and **empty output** does NOT create a new `responses` row. Both
`Subscribe()` and `process_gateway_response()` call
`ResponseStore::finalize_terminal_status(instr, agent, status, err, exec_id)`,
which UPDATEs every existing RUNNING (status=0) row scoped to
`(instruction_id, agent_id, execution_id)`. A terminal frame WITH output
still inserts (rare; the data is the result). A terminal frame whose
finalize updates zero rows (no preceding RUNNING under that
execution_id — typically a re-mapped command_id retry) falls through to
insert.

Why: pre-fix, every command produced **two** rows per agent — a RUNNING
row carrying the streamed output, plus an empty terminal sentinel. The
dashboard rendered both, sorted newest-first, and operators read the
non-zero `status` enum value (1=SUCCESS, 2=FAILURE, …) on the empty row
as a failure exit code that "happened before" the data row. Now there
is exactly one logical response row per (instruction, agent, execution),
carrying the data and the terminal status.

Regression pins: `test_agent_service_impl.cpp` "terminal SUCCESS folds
into existing RUNNING rows" and "terminal frame WITH output still
inserts" cover the two branches; the re-mapping case is pinned by
"re-mapping a command_id updates the stamp" (terminal under the new
exec_id falls through to insert because no RUNNING row exists there).

### Partial-index planner contract

`idx_resp_execution_ts ON responses(execution_id, timestamp) WHERE
execution_id != ''` requires the WHERE clause to syntactically subsume the
partial-index predicate. Every query against this index must include
`AND execution_id != ''` redundantly, or SQLite falls back to a full table
scan. See `query_by_execution`'s SQL in `response_store.cpp` for the
canonical form.

**Management-group scope is now applied BEFORE the LIMIT, in the SQL (#1634,
ADR-0017 INV-3).** The MCP `query_responses` collect path — and the legacy REST
`/api/responses/{id}/export` and catch-all list — resolve the caller's visible-agent
set (`ResponseStore::distinct_agent_ids`/`distinct_agent_ids_by_execution`) and push
it into `ResponseStore::query`/`query_by_execution` as SQL `agent_id = ANY(...)`
**before** `ORDER BY ... LIMIT`, via a new optional scope parameter (mirroring
`aggregate()`'s existing `AggregateScope`). This closes a real defect the first
#1634 migration pass shipped: filtering *after* `LIMIT` meant an execution that
fans out wider than the row cap and spans both in- and out-of-scope agents could
have the cap consumed entirely by out-of-scope rows, handing a confined caller a
short or empty page despite visible rows existing further back — found by an
adversarial review (Kimi + Codex) citing this exact INV-3 text. `result_truncated_by_cap:true`
now signals that the CALLER'S OWN scoped query hit the cap, not a raw-then-filtered
cap hit that could fire entirely inside another operator's rows. The gate itself
(`require_fleet_read`/`fleet_read_fn_`) replaced the old flat `Response:Read` check
these readers sat behind, so a management-group-confined operator is admitted and
narrowed rather than 403'd outright. **NOT true of every reader (correction, PR review
2026-09-01):** the executions-drawer detail fragment (`workflow_routes.cpp`, `limit=500`)
and the dashboard's `/fragments/results` (`dashboard_routes.cpp`, `limit=10000`) both
predate #1634 and still call `query_by_execution`/`query` with no scope argument,
post-fetch-filtering the raw (capped) result instead — the same INV-3 shape this
paragraph describes as closed elsewhere. Isolation still holds (under-display only,
never over-disclosure: a confined caller can see fewer in-scope rows than exist past
the cap, never an out-of-scope row), so this is not a security regression, but it is
not migrated onto the SQL-pushdown pattern above. Not the same surfaces as #3789/#3526;
tracked separately as #3805.

**#3789 (closed):** the legacy pre-v1 `/api/executions*` route family (`execution_routes.cpp` as
of #2542 PR-7, extracted from `server.cpp` onto the `HttpRouteSink` seam) — the one
execution-reading surface with NO confinement of any kind, not even a post-fetch filter — is now
on `require_fleet_read`, and its LIST route uses the SQL-pushdown pattern this paragraph describes
(a correlated `EXISTS` over `agent_exec_status`, since `executions` carries no per-row `agent_id`
column). Full design: `docs/auth-architecture.md`'s "Fourth migration (#3789)" /
`docs/adr/0017-management-group-confinement-list-reads.md`'s "Executions (legacy pre-v1 routes)"
bullet.

## PR 3 — SSE live updates

`ExecutionEventBus` (`server/core/src/execution_event_bus.{hpp,cpp}`) is the
per-execution SSE bus that backs `GET /sse/executions/{id}`. Owned by
`ServerImpl`, declared BEFORE `execution_tracker_` in the member list so the
bus outlives the tracker (the tracker borrows the bus pointer via
`set_event_bus`). On the explicit shutdown path the order is also tracker
first, then bus.

### Publisher invariant

Three `ExecutionTracker` mutators publish onto the bus when set:

- `update_agent_status` → `agent-transition` (one event per agent state
  change; payload is the `AgentExecStatus` JSON).
- `refresh_counts` → `execution-progress` (counts snapshot) AND, when the
  recompute crosses the all-agents-responded threshold, a terminal
  `execution-completed` (status=succeeded|completed). The progress event
  precedes the terminal event so an SSE client receives counts then status.
- `mark_cancelled` → terminal `execution-completed` (status=cancelled).

### Bounded ring buffer

Per execution: `kBufferCap=1000` events FIFO, ~30 s window in practice.
Replay walks events with `id > Last-Event-ID` on reconnect. Channels marked
terminal are GC'd by `gc_terminal_channels` once
`kRetentionAfterTerminalSec=60` elapses AND no live subscribers remain. GC
runs opportunistically from `publish` so no separate timer thread is
required.

### GC lock-ordering invariant (#1198)

`channels_` holds the only `shared_ptr` to each idle channel, and each
`Channel` carries its own `std::mutex`. **A `Channel` must never be
destroyed — via `erase` or any other `channels_` mutation — while any lock
on that channel's mutex is alive.** The required pattern, used by
`gc_terminal_channels`:

1. Pin the victim with a local `shared_ptr` copy *before* locking its mutex.
2. Erase the map entry — the local copy keeps the `Channel` alive.
3. Park the copy in a container declared *outside* the lock scopes (the
   `dead` vector), so `~Channel` runs only after the per-channel guard and
   the `map_mu_` write lock are both released.

Violating this is UB on every toolchain and a hard server-wide abort on
MSVC ("unlock of unowned mutex"). The Linux sanitizers cannot see a
regression here (the bad unlock executes inside uninstrumented libpthread,
and libstdc++/libc++ `~mutex` is trivial, so TSan gets no destroy hook) —
the MSVC test legs are the enforcement point, via the `set_clock_fn`
regression test in `test_execution_event_bus.cpp` (`[gc]` tag). Any
successor PR that restructures `gc_terminal_channels` or adds a new path
that erases from `channels_` while holding a channel mutex must preserve
this ordering. Lock hierarchy is `map_mu_` → `ch->mu`, never reversed.

### Terminal-visit primitive (#2409)

`ExecutionEventBus::unsubscribe_and_visit_terminal(execution_id, sub_id, f)`
runs a caller-supplied claim callback `f` under a **single hold of one
channel's mutex**, then erases the listener **iff `f` claimed**. It is the
MCP progress bridge's fix for a race where the sweep could unsubscribe a
parked streamed record and then synthesize a spurious `-32014`
terminal-unavailable frame over an execution that had actually completed —
because a terminal published into the unsubscribe→re-check window was never
latched. Three invariants a successor PR must not break:

- **The verdict keys on `Channel::first_terminal_id`, not an event-type
  scan.** `refresh_counts` publishes a terminal-flagged `execution-progress`
  *before* `execution-completed` (two publishes, `ch->mu` released between),
  so the *first* terminal-flagged event is a progress event; a scan for
  `event_type == "execution-completed"` misclassifies. A marker that has
  aged out of the ring is `kTerminalKnownLost` → the caller's safe
  success-shaped fallback ("fetch by execution_id"); it deliberately does
  **not** recover a later buffered `execution-completed`, which could be a
  spurious `mark_cancelled` terminal (#2409 UP-1).

- **The claimed teardown owns THREE resources.** A claimed record must
  settle its `records_` entry, its streamed admission charge, **and** its
  bus subscription. Erasing the map entry while the subscription survives
  strands the listener permanently: the listener holds a `shared_ptr` to
  the record, so the erase frees nothing, `shutdown()` can no longer reach
  it, and channel GC never reaps the channel because it requires
  `listeners.empty()`. `torn_down` (set once, never cleared) excludes the
  record from every *ordinary* sweep claim - but an incomplete teardown
  IS retried, from a later sweep tick, up to `Config::teardown_retry_max`
  times via the record's own `teardown_retry_claimable` flag (#2513);
  `shutdown()` remains the reclaimer of last resort, for a record whose
  retry budget is exhausted or that shutdown races before a retry pass
  gets to it. A step that cannot complete must leave the record reachable
  by a later retry (or, failing that, `shutdown()`) and say so, rather
  than erase around a live listener (#2487).
- **`f` runs under `ch->mu` and must never call back into the bus** (a bus
  call taking `map_mu_` would invert the `map_mu_` → `ch->mu` order above)
  and must be erase-only-on-claim: every *defer* keeps the listener, so a
  deferred terminal channel is never listener-less and never GC-eligible
  out from under the record. The full contract lives on the method in
  `execution_event_bus.hpp`.

### Client-side bootstrap is data-attribute-driven

The list-row markup carries `data-execution-id` and
`data-execution-status`; the drawer's KPI strip carries
`id="exec-kpi-{id}"`; per-agent table rows carry
`id="per-agent-row-{exec_id}-{agent_id}"`; per-agent status badges carry
`.per-agent-status` and `.per-agent-exit-code` classes. **Every PR that
touches drawer markup MUST keep these stamps stable** — they are the
client SSE listener's binding contract. Renaming any of them is a silent
regression: the listener falls back to no-op and the drawer freezes
mid-execution with no error.

### Audit policy

`execution.live_subscribe` audits on first connect per session-per-execution
(deduped). SSE auto-reconnect inside the dedup window does NOT re-audit.
The forensic-grade audit on read remains on
`/fragments/executions/{id}/detail`'s `execution.detail.view`.

### Hard predecessor for PR 3

PR 2.5 (#670) replaced the 16-arg `WorkflowRoutes::register_routes` with a
`WorkflowRoutes::Deps` struct. **Do not regress that signature** — adding
new dependencies to the workflow routes goes through the struct, not new
positional arguments.

### Second consumer (sprint W5.1, 2026-05-18)

`GET /api/v1/events?execution_id=<id>` is the agentic-first sibling of
`GET /sse/executions/{id}` — both subscribe to the same per-execution
channel from the same `ExecutionEventBus`. The dashboard route emits raw
`ev.data` (the browser already knows the channel from the URL path); the
agentic route wraps every event in
`{execution_id, event_id, timestamp_ms, type, payload}` so a worker
subscribed to one channel can still discriminate events without out-of-
band context.

**Three consumers, one bus, one set of publisher invariants** - the
publisher list above (`update_agent_status` / `refresh_counts` /
`mark_cancelled` → `agent-transition` / `execution-progress` /
`execution-completed`) is the single taxonomy every consumer reads. The
three live consumers are (1) the dashboard SSE route
(`execution.live_subscribe`), (2) the agentic route
(`api.v1.events.subscribe`, `GET /api/v1/events`), and (3) the **MCP
progress bridge** (track 2f, `McpStreamBridge`), a *consumer-side
projection only*: it maps the same bus events onto an MCP session as
`notifications/progress` + a final JSON-RPC response, adds **no bus event
type** and renames no step. Which wire carries those frames is a per-request
client choice and changes nothing here — the session's `GET` stream (PR 3a)
or the `tools/call` POST response held open as SSE (PR 3b) — because both
read the same subscription off the same bus. The bridge subscribes via
`ExecutionEventBus::subscribe_and_replay` (atomic install-then-replay,
closing the `replay_since`+`subscribe` race the two older siblings still
carry - tracked for migration in #2410). A new event type must be added
on the bus side first; every consumer picks it up transparently. **Do not
add a consumer-specific event type** - that would split the taxonomy and
break the A3 invariant that a single deterministic step name appears on
every channel.

The agentic route's audit verb is `api.v1.events.subscribe` (separate
from `execution.live_subscribe` so SIEM filters can distinguish browser
vs agentic consumers). Same no-dedup deferral applies (#700 Deferred-5).
The A3 envelope shape and the A4 error envelope live in
`server/core/src/rest_a4_envelope.hpp` as testable contracts — future
discovery / MCP surfaces consuming the same bus reuse the helpers there
rather than re-implementing the envelope.

**Hardening invariants (sprint W5.1 R1):** the agentic handler exposes
ring-buffer loss and per-connection backpressure to the client rather
than letting them go silent.

- **Replay-gap signal.** If the bus's ring buffer has already evicted
  events with id ≤ `since_id`, the handler emits a synthetic
  `replay-gap` envelope as the first frame
  (`{execution_id, type:"replay-gap", missing_from, missing_to}`) so the
  worker knows state may be inconsistent rather than silently observing
  an `event_id` jump. Counted in
  `yuzu_server_sse_api_replay_gap_total`. The dashboard sibling does
  NOT emit this — adding it there is a follow-up.
- **Per-connection queue cap.** `SseSinkState::queue` is bounded at
  `kPerConnectionQueueCapDefault=500` (event_bus.hpp) with drop-oldest
  semantics. Drops accumulate in `SseSinkState::dropped_total` and the
  content provider emits one `events-dropped` envelope per batch on the
  next wake, then resets the counter. The dashboard sibling does NOT
  enforce a cap currently — same follow-up.
- **Restart loss.** The bus is in-process and in-memory. On server
  restart the buffer is empty; clients that reconnect with
  `Last-Event-ID` after a restart will not receive events that occurred
  before the restart regardless of the `since` value. Agentic workers
  should fall back to `GET /api/v1/executions/<id>` for terminal state
  recovery. This is the same characteristic the dashboard drawer
  already lives with; it is documented here for agentic-client authors
  who write reconnect logic against the executions ladder rather than
  the dashboard's bootstrap path.
- **Cross-replica live delivery (HA WS-2a-2).** Each server replica runs
  a ~2s poll (`ExecutionTracker::poll_event_outbox_once`) that drains the
  durable `event_outbox` for events which originated on OTHER replicas
  and re-publishes them onto the local in-memory bus, so a subscriber
  sees live progress driven from any replica. The poll cursors on a
  Postgres commit-settle horizon (`w_xid < pg_snapshot_xmin(...)`) — its
  live forward delivery is gapless, at-least-once, and skips this
  replica's own already-published rows. Its horizon is initialized at
  ExecutionTracker CONSTRUCTION (before SSE admission), so events that
  commit during the boot→first-poll window are delivered, not ceded. A
  long-running transaction anywhere on the substrate pins the horizon and
  DELAYS (never drops) cross-replica delivery until it commits.
  Single-replica deployments are a no-op here (nothing foreign to deliver).
- **The live bus `id` is the per-channel counter, not the durable id
  (HA WS-2a-2 Option A).** The durable global `event_outbox.event_id`
  (a fleet-wide Postgres IDENTITY) is kept in the outbox — it drives the
  poll's settle-horizon cursor and the later durable failover replay — but
  it is deliberately NOT used as the live SSE `id`. Assigning it at INSERT
  and publishing post-commit would let two concurrent same-execution
  transitions invert id-vs-publish order and strand a committed event from
  a cursor-based (`ev.id > since_id`) subscriber on a SINGLE replica. So
  the bus id stays the per-channel counter assigned in publish order under
  the channel mutex (buffer order == id order, reconnect-safe), and the
  cross-replica poll re-publishes foreign events through the same path
  (they too get a monotonic local counter id).
- **Reconnect across replicas is NOT yet loss-free (WS-2a-2 slice
  boundary).** Single-replica reconnect is safe (ring order == id order).
  But a subscriber that fails over to a DIFFERENT replica holds a
  `Last-Event-ID` that is that replica's LOCAL counter — meaningless on
  the new one. Loss-free cross-replica reconnect needs the durable outbox
  replay, served by `execution_id ORDER BY event_id`, with the durable
  `event_id` becoming the cross-replica cursor (and delivered in id order
  to avoid the commit-inversion skip). That is the WS-2a-2 follow-up slice
  and a precondition for enabling a second replica (ADR-2002 "no committed
  event lost across failover"). Until it ships, cross-replica failover
  reconnect is not covered.

## Catastrophic invariants (routed-concern detail)

These are the clauses `.claude/routed-concerns.md` routes here (#1634, PR #3793 review).

**(a) Admission grants VISIBILITY, never a redaction bypass.** Dispatcher/owner admission on a
management-group-confined execution read grants visibility only — it never bypasses the confined-
projection redaction (`scope_expression`, `parameter_values`, counts) applied to every OTHER confined
caller. A new admission path — dispatcher ownership, a future service-token carve-out — that skips
this redaction reopens the exact class of leak found in PR #3793's review, where the dashboard
`/fragments/executions/{id}/detail` sidebar rendered `scope_expression`/`parameter_values`
unconditionally with no `gate.scope` check at all.

**(b) Every bus consumer sanitizes.** Every `ExecutionEventBus` consumer reachable by a confinable
principal — REST `/api/v1/events`, the dashboard `/sse/executions/{id}`, and any future consumer —
MUST route every event through `execution_event_scope.hpp`'s
`classify_execution_event_for_scope` / `sanitize_execution_event_for_scope`. A consumer that reads
the bus directly without this call leaks agent-transition and progress events to an out-of-scope
subscriber.

Both call sites are pinned by source-tripwire tests
(`tests/unit/server/test_response_execution_scope_authz.cpp`) that fail if either call is deleted.
**A NEW bus consumer needs its own tripwire** — never an assumption that the existing ones cover it.
## HA WS-2a — durable event outbox (ADR-2002 §5)

The "Restart loss" characteristic above is what WS-2a closes. `ExecutionTracker`
gains a durable, append-only `event_outbox` table (migration v4) that shadows
every event `ExecutionEventBus` fans out in-memory. The bus stays the *local*
fan-out; the outbox is the durable, cross-replica feed. **2a-1 lands the outbox
and its atomic write only — there is no consumer yet** (the in-memory bus still
serves live SSE exactly as before). A later slice (2a-2) drives a
LISTEN/NOTIFY-plus-cursor-poll loop from it.

- **Atomic-write invariant (§5 invariant 1).** Each event is appended
  (`append_event_outbox`, `execution_tracker.cpp`) on the **caller's live
  transaction connection**, inside the same `with_txn_for` as the state
  mutation that produced it — the `agent_exec_status` upsert
  (`upsert_agent_status_once`), the aggregate recompute / terminal transition
  (`refresh_counts_once`), and the cancel (`mark_cancelled`). A failed append
  returns false, which rolls the whole transaction back, so the store can never
  hold state without its event or an event without its state. The append takes
  no lease of its own (nesting a pool acquire inside an open `with_txn` would
  deadlock). It is decoupled from `event_bus_`: the durable append happens
  regardless of whether a local SSE bus is attached; only the post-commit
  in-memory fan-out is bus-gated.
- **Durable monotonic ids.** `event_id` is a global `BIGINT` IDENTITY,
  replacing the per-process ring-buffer counter. `created_at` is authored from
  Postgres `now()` in-SQL so the retention cutoff and the row share one DB clock
  domain.
- **ID-ORDERING CONTRACT for future consumers.** An IDENTITY id is assigned at
  INSERT but the row is visible only at COMMIT, so a transaction holding a lower
  id can commit *after* one holding a higher id, and rolled-back appends/state
  writes leave permanent id gaps. A cross-execution forward poll (2a-2) **MUST
  NOT** use a bare `event_id > cursor ORDER BY event_id`, or it silently skips a
  slower-committing lower id forever. **A trailing `created_at` time-lookback is
  NOT a sufficient fix** and must not be specified as one: `created_at` is
  authored from `now()`, which in Postgres is TRANSACTION-START time, so it does
  not linearize COMMIT order — a late-starting transaction can commit a higher id
  before an early-starting transaction commits a lower one, and no finite time
  window closes that straddle. The two sound approaches (algorithm left to the
  2a-2 design) are: **(a)** an id-gap-pending advance — never step past a missing
  id until it is proven committed OR proven rolled back (aborted-txn gaps are
  permanent); or **(b)** a txid/snapshot-horizon cursor — poll only rows whose
  inserting xid is below the database's all-committed xmin horizon
  (`pg_snapshot_xmin(pg_current_snapshot())`). The per-execution `Last-Event-ID`
  reconnect replay (`execution_id = $1 AND event_id > $since`) is safe with a
  bare id cursor — those rows are long-committed by reconnect time; the hazard is
  the live-edge forward poll. The authoritative statement of this contract lives
  at `append_event_outbox`.
- **No FK, deliberately.** `event_outbox` carries no foreign key to
  `executions(id)` and no UNIQUE/CHECK beyond the PK — `execution_id`
  legitimately holds non-`executions` ids (`polchk-`/`preflight-`/…), and a
  constraint would turn a benign append into an unrecoverable, differential
  failure of the paired state write.
- **Retention.** `reap_event_outbox` is a clock-guarded sweep (24h window,
  `reap_meta` key `event_outbox_reap_anchor`) mirroring
  `reap_command_execution_mappings`: advisory-lock single-writer, one in-SQL DB
  `now()` read, sanitised persisted anchor, forward/backward-anomaly decline,
  unconditional cap, and the same would-wipe + fact-set-dedup carve-outs.
  Missing anchor **PROCEEDs** (an outbox row is a regenerable live-update frame,
  not compliance evidence; the reap never touches authoritative state). Metrics:
  `yuzu_exec_outbox_reap_total`, `yuzu_exec_outbox_reap_clock_anomaly_total`,
  `yuzu_exec_outbox_store_degrade_total`.
