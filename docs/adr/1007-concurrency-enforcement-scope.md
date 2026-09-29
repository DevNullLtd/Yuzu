# ADR-1007: Concurrency enforcement — real-usage scope, not the documented 5 modes

- **Status:** Accepted
- **Date:** 2026-08-31
- **Authors:** Dave Rae
- **Parents:** `docs/yaml-dsl-spec.md` §12 / `docs/Instruction-Engine.md` §10 (concurrency modes,
  now corrected by this ADR), ADR-0065 (`ExecutionTracker` → PostgreSQL, the store this ADR adds
  to), ADR-0012 (substrate/store contract), `docs/postgres-migration-ladder.md` (records
  `ConcurrencyManager`'s deletion), `.claude/routed-concerns.md` "Dispatch targeting" (the
  chokepoint this ADR's gate sits upstream of).

## Context

`docs/roadmap.md` marked "Concurrency Enforcement (5 Modes)" (issue #206) **Done**. It was not.
Investigation against `origin/dev` (2026-08-31) established:

- `InstructionDefinition::concurrency_mode` is fully wired through YAML parsing, Postgres storage,
  JSON import/export, and the dashboard UI — but was never read anywhere in the dispatch path.
- `ConcurrencyManager` (`server/core/src/concurrency_manager.{hpp,cpp}`) — the class that would
  have enforced the two documented server-side modes — was constructed nowhere in `server.cpp`.
  Already flagged as dead code in `docs/postgres-migration-ladder.md` and ADR-0065.
- The agent-side modes (`per-device`, `per-set`) had no implementation in `agents/core` either —
  no in-memory active-set tracking, no rejection logic. Error code `3003 kConcurrencyBlocked`
  (`error_codes.hpp`) was registered in the taxonomy and emitted by nothing.
- The roadmap's own implementation citation was false on its face: it named
  `execution_tracker.cpp` as one of three files implementing this feature; that file had zero
  concurrency references before this ADR.

### Real-usage audit

`content/definitions/*.yaml` (the shipped instruction library, not hypothetical DSL examples) was
audited for every distinct `concurrency:` value actually in use:

| Value | Count | Plugin ownership |
|---|---:|---|
| `per-device` | 191 | 100% real `agents/plugins/` names (`tar`, `filesystem`, `registry`, `hardware`, `windows_updates`, `vuln_scan`, `antivirus`, …) |
| `per-definition` | 21 | 100% `plugin: server`/`server_internal`/`_server` |
| `global` | 17 | 100% `plugin: server`/`server_internal`/`_server` |
| `global-singleton` | 4 | 100% `plugin: server`/`server_internal`/`_server` |
| `per-set` | 0 | — |

Two findings this table does not show on its own:

1. **`global`/`global-singleton` are not the documented `global:<N>` syntax.** No validation exists
   anywhere in the load/CRUD path — any string is accepted verbatim into `concurrency_mode`.
2. **The 42 `plugin: server`/`server_internal`/`_server` definitions are catalog/discovery
   metadata, not live execution artifacts.** `policy_management.yaml`'s own header comment says so
   ("used by the management API and dashboard UI"). No agent plugin named
   `server`/`server_internal`/`_server` exists. The real functionality (`directory_sync_entra`,
   `create_deployment_job`, `policy.create`, `inventory_query`, `notifications.list`) is
   implemented by dedicated REST routes calling dedicated C++ objects directly
   (`discovery_routes.cpp` → `DirectorySync::sync_entra`, etc.) — never consulting
   `concurrency_mode`. The generic `POST /api/instructions/:id/execute` route
   (`workflow_routes.cpp`) does not reject these plugin values, so a caller CAN send one of these
   42 definitions toward real agents today and get an unknown-plugin failure back — a real,
   separate validation gap, not fixed by this ADR.
3. **`per-set` has no defined grouping mechanism.** Neither `docs/yaml-dsl-spec.md` §12 nor
   `docs/Instruction-Engine.md` §10 names a concrete "set" identifier field.
   `InstructionDefinition` does carry `instruction_set_id` (a real, populated field via
   `InstructionSet`), a plausible-but-never-referenced-for-concurrency candidate key — the honest
   framing is "unused and semantically unspecified," not "no grouping data exists at all."

The real bug behind the `per-definition`/`global`/`global-singleton` definitions' *intent* is
independent of the DSL: `DirectorySync::sync_entra` had no re-entrancy guard at all — two
concurrent `/api/directory/sync` calls raced for real, unrelated to any DSL field. (The
pre-existing `sync_entra`/`get_group_role_mappings` self-deadlock noted in ADR-0063 was already
fixed by that port; this ADR only adds the missing whole-operation guard.)

### Second-opinion review

A first draft of the design below (server-side enforcement via a naive `agent_exec_status` query)
was reviewed by an independent model (`gpt-5.6-sol`, `/codex opine`) before implementation. Its
core objection was verified correct by reading `origin/dev` directly:
`ExecutionTracker::create_execution` inserts only the parent `executions` row —
`agent_exec_status` rows are written later, by `upsert_agent_status_once`
(`agent_service_impl.cpp`, called when a `CommandResponse` actually arrives). There is no row at
dispatch time, so a naive join could not see "already running" during the entire
dispatch-to-first-response window — precisely the window a same-device duplicate lands in. Its
`WHERE NOT EXISTS` alternative was also correctly flagged as non-race-free under `READ COMMITTED`
without a backing unique constraint. Both objections shaped the design below. (The review also
claimed `docs/roadmap.md`'s "Done" status was not present on `origin/dev`; that claim was checked
and found wrong — it had only read the issue-detail section, not the roadmap table row — and is
recorded here as a caution against accepting any single reviewer's claim, including this ADR's
own, without checking the source.)

## Decision

Ship the narrow, real scope: real `per-device` enforcement (below), a direct re-entrancy guard on
`DirectorySync::sync_entra`, deletion (not migration) of `ConcurrencyManager`, and doc corrections.
Explicitly **not** in scope: DSL-level enforcement for `per-definition`/`global`/`global-singleton`
(would require first making the 42 catalog-only definitions actually route through a live dispatch
path — a real architecture change, declined); a grouping mechanism for `per-set`; any wait-queue
(the spec's "enters a wait queue" claim had zero backing implementation anywhere — replaced with
the established `REJECTED`/retry idiom, matching `kApprovalRequired`'s shape).

### Per-device enforcement: server-side, not agent-side

The docs describe `per-device` as agent-side: the agent maintains an in-memory active-set and
locally rejects. This ADR deviates from that, for reasons verified against the actual code:

- `CommandRequest` (`proto/yuzu/agent/v1/agent.proto`) carries no `definition_id` field — only
  `command_id`/`plugin`/`action`/`parameters`/etc. Building agent-side dedup would require adding
  one, cascading into mirroring `gateway/priv/proto/*/agent.proto` and regenerating `agent_pb.erl`
  (gpb silently drops unmirrored fields). `(plugin, action)` is not a safe proxy key: real
  duplicate pairs exist in shipped content (`antivirus/status`, `filesystem/replace`,
  `filesystem/get_version_info`, several `tar/sql` definitions) — `instruction_definitions` has no
  `UNIQUE(plugin, action)` constraint.
- The agent has no existing in-flight-execution tracking usable for this. `command_dedup_`
  (`agent.cpp`) is keyed on `command_id` for replay protection (HA WS-0) — a different problem
  (same command redelivered vs. two different commands for the same definition).
- Precedent for enforcing this class of check server-side, pre-dispatch, already exists:
  `kApprovalRequired` (3002) is enforced exactly this way, before the command ever reaches an
  agent. `kConcurrencyBlocked` (3003) sits next to it in the taxonomy and fits the same shape.
- An agent-side design has its own crash/restart problem symmetric to the server's (an agent's
  in-memory set is lost on its own restart too) — moving authority to the agent buys no
  compensating correctness benefit once the server-side design below is made properly race-free
  and self-healing.

### Mechanism — a dedicated claim table

Not a reuse of `agent_exec_status` (mixing durable execution history with short-lived-while-open
concurrency claims was rejected as the wrong shape) or of the deleted `ConcurrencyManager`'s
`concurrency_locks` design. A new table inside `execution_tracker`'s existing Postgres schema —
only the OPEN rows are short-lived; released rows are retained indefinitely, see "Retention" below:

```sql
CREATE TABLE concurrency_claims (
    definition_id  TEXT    NOT NULL,
    agent_id       TEXT    NOT NULL,
    execution_id   TEXT    NOT NULL,
    command_id     TEXT    NOT NULL,
    claimed_at     BIGINT  NOT NULL,
    expires_at     BIGINT  NOT NULL,
    released_at    BIGINT
);
CREATE UNIQUE INDEX ux_concurrency_claims_open ON concurrency_claims
    (definition_id, agent_id) WHERE released_at IS NULL;
CREATE UNIQUE INDEX ux_concurrency_claims_command ON concurrency_claims
    (command_id, agent_id);
```

`command_id` and its unique index were added in the UP-1/UP-2 fix round (see "CLOSED: a server
restart mid-flight..." below) — the initial design shipped without them.

The partial unique index is the actual atomicity guarantee — DB-enforced, race-free under any
isolation level, not an app-level check. `claim_concurrency_slots(definition_id, execution_id,
candidates, expires_at)` batch-inserts via `INSERT ... SELECT ... FROM unnest($N::text[]) ...
ON CONFLICT (definition_id, agent_id) WHERE released_at IS NULL DO NOTHING RETURNING agent_id` —
one round trip regardless of candidate-list size (matching this codebase's `#881` "ONE store
operation per dispatch, never per-agent" discipline), returning the subset actually cleared to
dispatch. Agents not returned already hold an open claim and are excluded from the send.

**Release** hooks into the existing terminal-status write path
(`ExecutionTracker::update_agent_status`, called whenever a real `CommandResponse` arrives) for
the per-agent terminal set (`success`/`failure`/`timeout`/`rejected` — NOT `running`). A `running`
response instead **renews** the claim's `expires_at` by another full TTL window
(`ExecutionTracker::renew_concurrency_claim`, CHAOS-TTL-1 fix) — its trigger is not plugin
cooperation (a plugin's own output volume or progress-reporting calls proved unreliable, see
"CLOSED (agent-core keepalive)" below) but a dedicated agent-core keepalive thread, independent of
what any given plugin does.
**`mark_cancelled` deliberately does NOT release claims** — an earlier draft of this mechanism did
bulk-release on cancel, but there is no gRPC cancel/kill RPC to the agent, so releasing immediately
would admit a duplicate dispatch to the same still-executing agent (Gate 4 unhappy-path UP-1,
BLOCKING, fixed before this ADR's first merge). Cancellation is server-side bookkeeping only; a
cancelled execution's claims still release only via a genuine terminal `CommandResponse` or the
stale-claim reconciler below.

**Stale-claim reconciliation** bounds an orphaned claim (agent crash, connection loss mid-execution,
or a cancelled-but-still-running agent per the previous paragraph — never a terminal response)
against the claim's own `expires_at`, which mirrors the dispatched command's real wire expiry
(`CommandRequest.expires_at`, millis→seconds) when the caller set one, clamped to at most one hour
from claim time (`std::clamp(wire_expiry, now, now + kConcurrencyClaimDefaultTtlSeconds)` —
`dispatch_scope_ladder.hpp`; a bound was added after review flagged the original design as
accepting an unbounded caller-supplied lease), or the same one-hour default when the caller set no
wire expiry at all (`has_expires_at() == false` genuinely means "run until finished" on the wire,
but the claim itself still needs a finite bound for the reconciler to key on — no code path in this
codebase currently populates `CommandRequest.expires_at` at all, so today this clamp's caller-supplied
branch is dead code and every claim uses the one-hour default in practice; the clamp exists so a
future caller that starts populating it inherits a bound rather than an unbounded lease — bounding
the INITIAL claim, not the total time a legitimately-progressing execution can hold it, which is
what the renewal above handles instead). This is a
clock-guarded bulk operation and adopts the actual shared decision rule
(`common/include/yuzu/audit_retention_rules.hpp::classify` + its `Facts`/`Anomaly` types —
`AuditStore::cleanup_once`'s own reference implementation, extracted for exactly this kind of
reuse) rather than a hand-rolled reimplementation of CLAUDE.md's seven-part discipline. One input
is deliberately never set true — see "Considered and rejected" below for why, and for the earlier
draft this ADR corrects.

**Insertion point:** `resolve_and_dispatch_confined` (`dispatch_scope_ladder.hpp`), immediately
before each arm's resolved candidate list becomes a `ConfinedDispatchTargets` field — the one place
that already has each arm's pre-authz, pre-quarantine candidate list in hand. `dispatch_confined_arms`
itself is left untouched: it is deliberately pure (no store access, "the seam the confinement tests
bind" per its own doc comment) and a per-id store call there would also violate the `#881`
discipline. The gate is wired via a new optional `ConcurrencyClaimFn` (default `nullptr` = no gate
— most dispatches are not definition-driven, so a nullable default is the correct un-set state,
unlike `ContainmentGate`'s deliberately non-default-constructible design, which always applies).

**Covered arms:** Group, Scope, and explicit Ids. **Not covered:** Broadcast and None (fleet-wide
dispatch resolves its candidate set inside the sink, not in `resolve_and_dispatch_confined`).
**This is the primary collision case for many real `per-device` definitions, not an edge case** —
Gate 3 architect review (2026-08-31) correctly pushed back on this ADR's first draft, which had
characterized it as a narrow exception. A substantial share of the 191 real `per-device`
definitions are exactly the kind of operation (`tar.fleet_snapshot`, scheduled scans, patch
inventory refresh) that operators legitimately dispatch fleet-wide via Broadcast, not to a hand-picked
group — so a repeated fleet-wide dispatch of one of these definitions in quick succession is the
realistic way a same-device double-dispatch happens in production, not a corner case. Extending
the claim gate to the Broadcast arm is deferred (see Follow-ups) because its candidate set is
resolved inside the sink rather than in `resolve_and_dispatch_confined`, requiring a different
insertion point that this ADR's scope did not budget time to design and test — not because the
scenario is rare. **Not covered at all:** raw MCP `execute_instruction` and any raw REST command
dispatch, which carry no `definition_id` and cannot be gated by this mechanism — a real, deliberate,
documented gap (`docs/mcp-server.md`), not an oversight.

### Residual gap: a device quarantined MID-FLIGHT still holds its claim until TTL

Gate 3 architect review also flagged that quarantine and this claim table don't talk to each other.
If a device is claimed for a `per-device` dispatch and is then quarantined before it responds
(`#881`'s `ContainmentGate`, inside the still-pure `dispatch_confined_arms`), its open claim is
untouched — quarantine has no hook into `release_concurrency_claim`. The device is already excluded
from all future dispatch by the containment gate itself, so this is not a dispatch-correctness bug,
but the claim row sits open until the stale-claim reconciler force-releases it at `expires_at`, same
as a genuine crash. If the device is later released from quarantine before that TTL elapses, it is
still correctly excluded from a repeat `per-device` dispatch of the same definition until the claim
ages out — a real, minor over-exclusion window, not a safety gap. Not fixed in this change; noted
so it isn't rediscovered as a surprise.

**CLOSED (fix round responding to PR #3784 external review, important-finding-#1): the sibling
case — a device already quarantined BEFORE dispatch even starts still winning a claim — is now
fixed**, and the same review also caught a second variant of the identical root cause that this
ADR's first draft did not name: an id whose `sink.send_to()` itself fails (not quarantined, just
undeliverable) had the identical leak. Both are fixed the same way. Claiming happens in
`resolve_and_dispatch_confined` (`dispatch_scope_ladder.hpp`), strictly BEFORE
`dispatch_confined_arms`'s containment gate runs — confirmed against `dispatch_confined_arms.hpp`'s
own doc comment describing the gate as "a SECOND, orthogonal filter applied AFTER" scope resolution.
So a device that is already quarantined at the moment a `per-device` definition is dispatched — an
entirely normal, working-as-intended system state, not a fault — still passes the pre-claim
visibility filter and still wins a claim, as does an id whose send later fails outright.
`ArmDispatchResult` (`dispatch_confined_arms.hpp`) now collects both as `not_sent`
(send-failed) alongside the pre-existing `denied_quarantined`; `dispatch_confined_arms` itself stays
store-pure (collection only, per its own doc contract) — `wire_and_dispatch_confined`, the seam that
built `claim_fn` in the first place, releases both sets right after dispatch completes. **Residual,
unchanged:** under `ContainmentGate::fail_closed` the ids are deliberately never collected into
`denied_quarantined` (a fleet-sized allocation on an already-degraded path — `ArmDispatchResult`'s
own doc comment), so those claims still age out at `expires_at` rather than releasing immediately;
this is the same conservative trade-off as the mid-flight case above, not a new gap.

### CLOSED (agent-core keepalive): a flat TTL could force-release a still-running claim, admitting a real concurrent second dispatch

Gate 5 chaos analysis (PR #3784 fix round, finding CHAOS-TTL-1) found a second, more directly
reachable non-conservative gap than the one below, requiring no connection failure, no gateway, and
no quarantine event at all: since the wire-supplied expiry branch above is dead code in production,
every claim used the flat one-hour default, and the reconciler force-released any claim past
`expires_at` with **no way to distinguish "agent crashed" from "agent is still legitimately
executing and simply hasn't finished yet."**

`update_agent_status` renews the claim's `expires_at` by another full TTL window on every
non-terminal (`running`) `CommandResponse` it receives (see "Release" above) — but two rounds of
verification found no real plugin cooperation could be trusted to trigger that renewal reliably:
buffered-output auto-flush (`CommandContextImpl::flush_output_locked`, 64KB threshold) is a
plugin's own output volume, not a designed liveness signal, and `yuzu_ctx_report_progress`
(`sdk/include/yuzu/plugin.h`) was a **local no-op** with no wire traffic at all. The verified real
trigger — found by external-model review (`/codex opine`, gpt-5.6-sol) after a first citation
(`content_dist.execute_staged`) turned out wrong (it carries its own real 30-minute deadline and
cannot reach the one-hour boundary) — is **`device.script_exec.*`** (`content/definitions/script_exec.yaml`,
`concurrency: per-device`): MUTATING (an operator-named program or authored script that can hold
real state — a partially-written file, an in-flight package-manager transaction), with an
operator-configurable timeout of up to 3600s. A quiet invocation producing little stdout could
legitimately run to that ceiling with no wire signal to renew its claim, at which point the
reconciler would force-release it and a second, overlapping mutation could be dispatched — an `I2`
(data/state corruption) impact that derives HIGH/BLOCKING on its own, independent of any "false
assurance" argument.

**Fixed with a plugin-cooperation-independent keepalive** (`agents/core/src/agent.cpp`): a single,
per-connection background thread — not one thread per command — that sends a periodic bare
`RUNNING` (output sentinel `__keepalive__`) for every command still in `in_flight_ids_`, a set
populated the instant a command is accepted onto the bounded dispatch queue (so it covers
queue-wait time, not just time inside a plugin's `execute()`) and erased at the single chokepoint
every terminal write already passes through (`record_command_terminal`), so it can never diverge
from the set of commands this agent still owes a response for. The interval (5 minutes) is well
under the server's one-hour default TTL. The server recognizes the sentinel on both the
direct-Subscribe and gateway-streamed `RUNNING` paths (`agent_service_impl.cpp`) and routes it
straight to `notify_exec_tracker` — renewing the claim — without storing a response row, publishing
an SSE output line, or counting an analytics event, matching the existing `__timing__` frame's own
intercept pattern exactly. Tested end-to-end: `test_execution_tracker.cpp` proves the server-side
renewal mechanism; `test_agent_service_impl.cpp` proves the sentinel reaches
`ExecutionTracker::update_agent_status` and is excluded from `ResponseStore`.

This closes CHAOS-TTL-1 for every `per-device` definition, not just the ones already producing
enough output to cross the 64KB threshold — including quiet `script_exec` runs, and any future or
third-party plugin that never calls a progress-reporting API at all.

**A side effect worth stating plainly** (happy-path Gate 4 finding, NICE): "without... publishing
an SSE output line" above is about the per-output-row dashboard stream specifically (the keepalive
never becomes a `ResponseStore` row or a live output line) — it is NOT SSE-silent overall.
`notify_exec_tracker` → `update_agent_status` → `upsert_agent_status_once` publishes an
`agent-transition` event on every call, keepalive included, and sets `first_response_at` on the
first `RUNNING` write for an `(execution_id, agent_id)` pair the same way a real plugin-produced
`running` update always has. So on the normal (non-workflow-step) path, `first_response_at` now
usually reflects the keepalive's first tick (up to 5 minutes after dispatch) rather than the
plugin's first genuine progress signal, whenever a quiet plugin produces no output of its own
before then. This is an intended consequence of the keepalive existing at all, not a defect — but
it changes what `first_response_at` means in practice for quiet, long-running commands, which
wasn't called out anywhere before this note.

**Hardened after a targeted follow-on review** of this new agent-core thread/wire-behavior code
(requested given its scope — a new thread, new synchronization, a new agent→server message type —
before treating the fix as final), which found and closed two further defects, both now fixed and
tested (governance ledger `pass_ordinal: 6`):
- **A stale keepalive ping could flip an already-terminal execution row back to `running`.** The
  keepalive thread's periodic snapshot-then-write has no re-check against a command completing
  mid-sweep — an ordinary race, no attacker required — so a `__keepalive__` response could legitimately
  arrive at the server strictly after that command's real terminal response. `upsert_agent_status_once`'s
  upsert now makes terminal status sticky (a `running` write is a no-op on every column once a row is
  terminal) and publishes the SSE `agent-transition` event from the actual post-write row
  (`RETURNING`), not the caller-supplied value verbatim, so a rejected stale write can't publish a
  misleading event either.
- **An exception escaping the per-connection scope could use-after-free `sub_ctx`.** The manual
  teardown that stops+joins `keepalive_thread_` is plain sequential code, not itself exception-safe;
  an exception unwinding past it reaches `sub_slot`'s destructor (which only retracts `subscribe_ctx_`,
  never cancels) and then destroys `sub_ctx` while the keepalive thread might still be inside
  `stream->Write()`. Closed with a scope-order RAII guard declared after `stream`/`sub_slot`/`sub_ctx`
  so it destructs FIRST on any unwind, guaranteeing the thread stops touching the stream/context
  before either goes away.

### Residual gap: `not_sent` release trades a false-negative for availability

Every other residual gap in this section is over-exclusion (a claim held longer than strictly
necessary — "conservative, never under"). This one is the opposite, and is worth naming plainly so
a reader pattern-matching the rest of this section doesn't assume it too.

For a directly-connected (non-gateway) agent, `send_to()` returns the raw
`grpc::ServerReaderWriter::Write()` result (`agent_registry.cpp:647`,
`session->stream->Write(cmd.wire(), grpc::WriteOptions())`). gRPC's own C++ streaming contract
documents `false` as "the call is dead" — a terminal state for the whole stream, not a per-message
maybe. Combined with HTTP/2 framing (a `CommandRequest` travels as one or more length-prefixed DATA
frames; a connection torn down mid-write leaves an incomplete frame the peer cannot reassemble into
a valid message), the failure mode this residual gap worries about — bytes reached the agent despite
a local `false` — does not have an available mechanism to occur for a single, sub-frame-sized
`CommandRequest` under gRPC/HTTP2's own framing rules. This is reasoned from the documented gRPC
contract and HTTP/2's framing invariants, not verified by fault-injecting a real mid-write connection
reset against this codebase, so it is recorded as `likely`, not `verified` — but it is a real,
citable protocol-level argument, not a proportionality guess. It is the basis for treating this as a
documented residual rather than a code-blocking defect (see the governance ledger for this PR's
fix round for the full derivation).

This is not new exposure created by loosening a stronger guarantee: `send_to()==true` never
guaranteed delivery either (a gateway-routed agent returns `true` the instant a command is queued
onto `gw_pending_`, with zero delivery proof — see the next residual gap). So the feature's actual
guarantee was always "no double-dispatch given a truthful transport signal," not
delivery-confirmed exactly-once — this fix narrows the set of cases where a `false` signal is
*trusted*, it does not weaken a guarantee the mechanism ever actually held. Two fix shapes exist and
neither shipped here: (a) don't release on `not_sent` at all (reverts the leak this same round's
external review asked to close), or (b) teach `send_to()` — and its callers throughout
`agent_registry.cpp` — to distinguish a definite pre-transport failure from an ambiguous one, which
is a contract change to a function with dozens of callers well beyond this feature, not proportionate
to this round. Documented here rather than fixed; a real fix is (b), scoped as its own change.

### Residual gap: a gateway-routed agent's claim is never captured by `not_sent`

`send_to()` for a gateway-routed agent returns `true` the moment the command is queued onto
`gw_pending_` — before the gateway has forwarded it, let alone before the agent has received it.
So a claim taken for a gateway-routed agent behind a dead or unreachable gateway is never counted
as `not_sent` by the fix above (the dispatcher sees `sent=true`) and depends entirely on the
stale-claim reconciler's `expires_at` TTL, same as before this fix round. This is not a regression
introduced here — gateway-queued "success" has never meant confirmed delivery, for this feature or
any other dispatch path — but it does mean the fix's own framing ("releases claims that were taken
but never delivered") is accurate only for the synchronous, directly-connected-agent failure case,
not the gateway-routed one. Worth stating explicitly so this round's fix isn't read as closing more
than it does.

### CLOSED (was: "Workflow-step claims never see the fast-release path"): now released/renewed via the by-command fallback, not TTL-only

The workflow-step dispatch closure (`workflow_routes.cpp`, the `dispatch_fn` used by
`WorkflowEngine`, distinct from the `/api/instructions/:id/execute` route) passes `execution_id=""`
to `cmd_dispatch_concurrency` — a pre-existing gap (CONSIST-2/sec-M2, tracked "PR 2.x will close"
in that file, predating this ADR) where workflow-step dispatch never wires real execution-id
correlation at all. `claim_concurrency_slots` therefore stores the claim row under
`execution_id=""`. This section originally documented the consequence as "release-by-TTL-only" —
the terminal response arrives, but `agent_service_impl::record_execution_id` never populates
`cmd_execution_ids_` for an empty `execution_id`, so `notify_exec_tracker` could not resolve one and
`update_agent_status`/`release_concurrency_claim` were never reached.

**Closed by the UP-1/UP-2 fix round below**, as a side effect rather than the original target: the
`(command_id, agent_id)` by-command fallback `notify_exec_tracker` now falls back to on an
unresolvable `execution_id` fires for EVERY workflow-step response, not just a post-restart one —
so a workflow-step `per-device` claim now releases on the agent's real terminal response and renews
on its keepalive, the same as the `/api/instructions/:id/execute` route and `ScheduleRunner`. The
underlying correlation gap (CONSIST-2/sec-M2 — no real `execution_id` for a workflow step, so the
executions drawer still can't show per-agent progress for these) is UNCHANGED and still tracked
separately; only the concurrency-claim consequence closes here.

### CLOSED: the shared empty `execution_id` above could let one workflow-step definition's failed-send release a DIFFERENT definition's genuinely-open claim

Gate 2 security-guardian review (PR #3784 fix round) found that the `not_sent`/`denied_quarantined`
fast-release path (`wire_and_dispatch_confined`, see "Fixed" above) and the terminal-response
release path (`update_agent_status`) both originally matched a claim to release by
`(execution_id, agent_id)` alone — `release_concurrency_claim`/`release_concurrency_claims`, and
`renew_concurrency_claim` on the renewal side. That is unsafe precisely because of the section
above: every workflow-step dispatch shares the literal empty string as `execution_id`, for EVERY
`per-device` definition it dispatches. Two different definitions can each hold a genuinely open
claim on the same agent under that same empty `execution_id` at the same time — the table's real
uniqueness key is `(definition_id, agent_id)`, not `(execution_id, agent_id)`.

Concretely: workflow step A dispatches definition X to agent Z (claim taken, delivered, X now
genuinely executing on Z). A separate, unrelated workflow step B dispatches a different definition
Y to a candidate set that includes Z; Y's claim on Z is taken (succeeds — different `definition_id`,
no conflict), but the actual send to Z fails or Z is quarantined. Y's own fast-release fires
`release_concurrency_claims(execution_id="", agent_ids=[Z,...])` — with no `definition_id` in the
WHERE clause, this UPDATE matched **any** open claim row with `execution_id=""` and `agent_id=Z`,
including X's still-legitimately-open claim. X's claim was released while X was still executing,
admitting a genuine concurrent duplicate dispatch of X to Z — precisely the race this whole feature
exists to prevent. The same unscoped-match shape affected `renew_concurrency_claim` on the renewal
side (a keepalive/progress signal for one definition could renew — or, more precisely, indiscriminately
touch — every open claim row sharing the same collided `execution_id` and `agent_id`, not just its
own).

**Fixed**: `release_concurrency_claim`, `release_concurrency_claims`, and `renew_concurrency_claim`
all now require `definition_id` in their WHERE clause (`(definition_id, execution_id, agent_id)`,
matching the table's actual uniqueness key). The fast-release call site
(`wire_and_dispatch_confined`) already had `definition_id` in scope, so this was a direct
parameter-threading fix with no new store round trip. The terminal-response path
(`update_agent_status`, called from `notify_exec_tracker` with only `execution_id` in hand) gained
a new indexed primary-key lookup, `ExecutionTracker::definition_id_for_execution`, fired only on a
terminal (or `running`) status transition — not per poll — so the added round trip is negligible.
That caller was never actually exploitable in practice (a real `create_execution`-minted
`execution_id` is globally unique and 1:1 with exactly one `definition_id` by construction, and
`notify_exec_tracker` already refuses to call `update_agent_status` at all when `execution_id` is
empty) — the fix was applied there anyway for API consistency and defense-in-depth, not because
that specific call site was reachable. Regression test:
`test_execution_tracker.cpp`, "release_concurrency_claim/s do NOT cross-release a different
definition's open claim when execution_id collides."

### CLOSED: a server restart mid-flight silently dropped claim release/renewal for any command still in progress (UP-1/UP-2)

**2026-09-02 addendum — written pre-reconciliation, `cmd_execution_ids_` references below are now
historical.** This section describes the state of the world as it existed when UP-1/UP-2 were fixed,
BEFORE this branch was reconciled onto 140 commits of `origin/dev` that included HA WS-1(1b)
(ADR-2002 section 5): a PG-backed `command_id -> execution_id` correlation table
(`ExecutionTracker::record_command_execution`/`lookup_execution_id`) that fully REPLACED
`cmd_execution_ids_` — the in-process map named throughout this section no longer exists in the
shipped code. The by-command fallback this section introduces is still live and still needed, but
its role narrowed: HA WS-1(1b)'s persisted, replica-safe lookup now handles the restart-survival
case described below on its own; the fallback's remaining genuine triggers are workflow-step
dispatch (still empty `execution_id`, CONSIST-2/sec-M2, unaffected by HA WS-1(1b)) and a degrade on
the correlation table's own write/read side — see the current doc comments on
`release_concurrency_claim_by_command`/`renew_concurrency_claim_by_command`
(`execution_tracker.hpp`) and `notify_exec_tracker` (`agent_service_impl.{hpp,cpp}`) for the
accurate, current framing. The "Gate 8 re-review (reconciliation)" section further below has the
full account of what changed and why.

`cmd_execution_ids_` (`agent_service_impl.hpp`) was a plain in-memory `command_id -> execution_id`
map, never persisted. `notify_exec_tracker` resolved `execution_id` through it and, on a miss,
previously just returned — doing nothing. A server restart while a `per-device`-gated command is in
flight wipes that map entirely. The agent has no idea the server restarted: its keepalive thread
(the "CLOSED (agent-core keepalive)" section above) keeps sending periodic `RUNNING` pings, and the
eventual real terminal response, both still carrying the original `command_id` — but the server
could no longer resolve either to `execution_id`/`definition_id`, so every renewal was silently
dropped and the terminal response never released the claim. The claim just sat until the stale-claim
reconciler's TTL (up to one hour) force-released it — *while the agent might still be genuinely
executing*, reopening the double-dispatch race this whole feature exists to prevent. Unlike a
genuinely crashed/orphaned agent (silence is the correct inference there), this is silence caused by
the SERVER discarding a signal the agent is actively sending — a materially worse failure mode than
the accepted crash case, not an equivalent one; an internal review that initially proposed treating
it as equivalent and downgrading it was corrected on exactly this point (unhappy-path Gate 4,
finding UP-1, derived HIGH/BLOCKING).

A related, smaller finding (UP-2): `ExecutionTracker::update_agent_status` decided whether to
release or renew a claim by branching on the CALLER-SUPPLIED status string, not on what
`upsert_agent_status_once`'s sticky-terminal `CASE` actually persisted. If a claim's terminal
release independently failed (pool exhaustion) and a stale, reordered `running` response then
arrived, the old code would renew the claim based on the reordered response's literal status,
extending a dead command's claim rather than retrying its release.

**Fixed**:
- `concurrency_claims` gained a `command_id` column (folded into the still-unshipped migration v3 —
  this table has zero production rows on any deployed release; originally authored as v2, renumbered
  during the HA WS-1(1b) reconciliation since that feature's own new table claimed v2 first on
  `origin/dev` — see the "Gate 8 re-review (reconciliation)" section below). `command_id` rides on
  every `CommandResponse`, including `__keepalive__`, independent of the server's in-memory cache,
  and is minted fresh per dispatch — so `(command_id, agent_id)` needs no `definition_id` scoping the
  way `execution_id` does.
- Two new `ExecutionTracker` methods, `release_concurrency_claim_by_command`/
  `renew_concurrency_claim_by_command`, match purely on `(command_id, agent_id)`.
  `notify_exec_tracker` calls them whenever `cmd_execution_ids_` misses, instead of returning
  early — restoring release/renewal for both the restart case above AND, as a side effect, the
  workflow-step case (see the section above this one). Post-reconciliation, the restart case is
  additionally covered by HA WS-1(1b)'s persisted correlation table on its own — this fallback stays
  the sole path for the workflow-step case regardless (see the 2026-09-02 addendum above).
- `upsert_agent_status_once` now returns the row's actually-persisted status (`std::optional
  <std::string>`, from its own `RETURNING` clause) instead of `bool`; `update_agent_status` gates
  release-vs-renew on that, never on the caller-supplied value (UP-2).
- The executions-history-drawer/SSE side of the restart gap is UNCHANGED and still accepted: losing
  `cmd_execution_ids_` also means the drawer legitimately has nothing to update for a correlation it
  lost. Only the concurrency-claim safety property is restored, not drawer/audit fidelity.

**Adversarial review (Sol `gpt-5.6-sol` opine + Fable `claude-fable-5` opine, both 2026-09-01)
surfaced a real gap in the fix above**, which is also now closed: `command_id`'s uniqueness was
*probabilistic* (8 random bytes = 64 bits) and *unenforced* — nothing in the schema or code stopped
two rows from ever sharing a `(command_id, agent_id)` pair, and a doc comment on the by-command
methods overclaimed "cannot collide" without a constraint backing it. Neither reviewer found an
actual reachable trigger in today's code (each dispatch mints a fresh id; no legitimate redispatch
path reuses one), but the mechanism's own safety argument rested entirely on that unenforced
assumption, which is exactly the shape of gap this codebase's claim-discipline norms exist to catch.
Fixed:
- `command_id` generation (`dispatch_confined`, `server.cpp`) bumped from `random_bytes(8)` to
  `random_bytes(16)` (128 bits).
- `concurrency_claims` gained a real `UNIQUE` index, `ux_concurrency_claims_command
  (command_id, agent_id)` — full-table, not partial, since the invariant (one dispatch mints one
  command_id, ever) holds for a row's whole lifetime, not just while open.
- `claim_concurrency_slots`'s INSERT now uses a targetless `ON CONFLICT DO NOTHING`, so a
  `(command_id, agent_id)` conflict fails that candidate CLOSED (excluded from the dispatch) exactly
  like an "already busy" conflict, rather than erroring the whole batch or silently succeeding.
- `claim_concurrency_slots` also now rejects an empty `command_id` outright (Fable finding: the
  release/renew-by-command methods already guarded against empty, but the claim side didn't — an
  asymmetry that would have made an empty-command claim silently un-releasable-by-command).
- Regression tests added: same-agent/different-command_id discrimination (proves the match key's
  `agent_id` half doesn't accidentally cover for a missing `command_id` scope), and a direct
  `(command_id, agent_id)` reuse test proving the new unique index fails the second claim closed.

**Deliberately NOT done, with reasoning** (both reviewers raised further points; recorded here
rather than silently dropped):
- **Fable**: the by-command fallback still decides release-vs-renew from the raw wire status, with
  no persisted "ground truth" to check against (there is no `agent_exec_status` row when
  `execution_id` was never resolved) — the same class of gap UP-2 fixed for the mapped path, but
  here there's no equivalent row to consult. Sol raised the identical point independently. Both
  characterized the actual failure mode as *conservative over-retention* (a stale reordered
  `running` can re-extend a claim whose terminal release transiently failed), never an unsafe early
  release — the claim still self-heals via the reconciler, same fallback as every other best-effort
  failure in this file. Accepted as a residual, not fixed, because closing it fully would mean
  adding new durable per-command_id state purely to track "have I already released this," which is
  disproportionate to a bounded, self-healing, non-corrupting outcome.
- **Sol**: after a long outage, the agent's keepalive thread waits a full 5-minute interval after
  reconnecting before its first post-reconnect ping (`agent.cpp`), and the server's reconciler tick
  runs on the same ~5-minute cadence — so a claim that has already exceeded its TTL during the
  outage can be force-released by the reconciler just before the agent's first liveness signal
  lands, even though the agent reconnected and the command may still genuinely be running. This is
  the SAME accepted TTL/liveness tradeoff the whole feature already makes for a genuinely crashed
  agent (silence past the TTL self-heals via force-release), not a new gap this fix round
  introduced — narrowed only by how long the specific outage was. A cheap hardening (reasserting
  `in_flight_ids_` immediately on reconnect, before the first sleep) would shrink this window
  further; tracked as a follow-up, not implemented in this round.
- **Fable**: since the claim row now durably carries `execution_id`/`definition_id` alongside
  `command_id`, the by-command path could in principle become the UNIVERSAL release/renew mechanism
  (not just the fallback), which would let `definition_id_for_execution`'s second per-tick lease be
  retired and could recover drawer/SSE fidelity after a restart instead of accepting CONSIST-2 for
  that case too. Real, but a larger refactor than this fix round's scope — noted here as a future
  direction, not undertaken now.
- A `command_id`-prefix skip (`__guard__-`) was added to avoid a wasted write-pool lease on every
  guard push/reconcile response (Fable's load finding — the fallback turns every unmatched response
  into a lease + UPDATE). The same optimization was deliberately NOT extended to `tar-`: `tar` is
  also a real agent plugin name, and nothing in the code (only today's content library) guarantees a
  `per-device`-gated `tar` definition could never exist — a string-prefix skip there would risk
  silently skipping a legitimate release if that ever changes.

Regression tests: `test_execution_tracker.cpp`, search for "UP-1", "UP-2", "Fable adversarial-review
finding", and "Sol/Fable adversarial-review finding".

### Gate 4 unhappy-path risk register (UP-3 through UP-8) — triaged

UP-1 and UP-2 are closed above. The remaining six findings from the same review, triaged:

**UP-3 (reported SHOULD) — a burst of force-releases right after an extended PostgreSQL outage.**
The reviewer's framing was "the instant PG recovers, the next tick force-releases the whole batch
at once." Traced against the actual reconciler code (`reconcile_stale_concurrency_claims`,
`execution_tracker.cpp`), this is not quite what happens: the clock-guard's `big_step` check
(`kConcurrencyReconcileBigStepFloorSeconds` = 1 hour) compares `now` against the PERSISTED
`last_pass_now` anchor, which stops advancing the moment PG becomes unreachable (no pass can even
run). The FIRST reconcile pass after PG recovers therefore sees a large jump since that anchor,
classifies as `Anomaly::Step`, and DECLINES — no release at all on that pass (verified by reading
`classify()`, `common/include/yuzu/audit_retention_rules.hpp:120-130`, and the transaction body's
`if (anomaly != Anomaly::None) { ...; declined = true; return true; }` early-out). The anchor is
re-stamped to `now` regardless (fail-closed re-anchoring, part of the seven-part discipline), so the
VERY NEXT pass (one reconciler tick later, ~5 minutes) sees a small step, proceeds normally, and
releases the accumulated stale claims — capped at `kConcurrencyReconcileCapPerPass` (5000) per pass
regardless of how many accumulated. So the real behavior is: one tick's grace period, then a
capped, gradual drain — not an instantaneous, unbounded mass-release. The underlying concern (many
claims force-releasing together after a real outage, concentrating duplicate-dispatch risk more
than an isolated single-claim leak) is still real, just meaningfully smaller than reported. Not
fixed further: the existing big_step decline + cap were built for exactly this class of event
(they predate this finding) and no evidence suggests the residual one-tick/5000-cap window is
operationally material. Tracked as a follow-up for revisiting if it ever proves otherwise.

**UP-4 (SHOULD) — retry-loop amplification of the never-pruned claim table.** A tight retry loop
against a persistently-unreachable single agent can claim+release repeatedly (the `not_sent` fast
path is cheap), appending one permanently-retained row per attempt for one `(definition_id,
agent_id)` pair — real, and not accounted for in the "Retention" section's growth model below,
which reasons about organic dispatch volume, not a pathological retry pattern. No rate limit exists
at this layer. Not fixed here: building a rate limiter is a materially larger scope than this ADR's
enforcement mechanism, and the existing no-prune design (see "Retention" below) already accepts
unbounded-but-slow growth as a deliberate tradeoff — this just means the growth rate has a
higher ceiling than assumed. Filed as a follow-up rather than designed and built in this round.

**UP-5 (NICE, verified) — terminal-to-terminal reordering can regress audit fields cosmetically.**
The sticky-terminal `CASE` (`upsert_agent_status_once`) only special-cases terminal-over-terminal
in ONE direction: it blocks a `running` write from overwriting a terminal row, but a SECOND terminal
write with a different outcome (a redelivered/reordered `success` after `failure`, or vice versa)
always overwrites — `completed_at`/`exit_code`/`error_detail` can regress to an earlier wall-clock
value with no sequence number to order by. This is pre-existing, accepted behavior, not something
this PR introduced: the sticky-CASE's own comment already documents "a legitimate second/replayed
terminal write, e.g. HA WS-0 redelivery, may overwrite" as intentional. Confirmed no dead-end state
(no write is ever permanently rejected) — cosmetic audit-trail confusion only. Not fixed: adding a
sequence/ordering key to resolve this is a real improvement but belongs to the general
terminal-response-redelivery design, not a concurrency-claim-specific patch. Gate 5 designed a
matching chaos scenario (CH-6: replay out-of-order terminal frames, confirm the claim itself stays
released and only audit fields regress) — P2/nightly, not filed as its own issue given the low
severity and that this is already an accepted characteristic, not an open question.

**UP-6 (NICE, speculative) — a narrower quarantine/claim ordering gap than the one already
documented.** `claim_fn` runs against a `ContainmentGate` snapshot taken earlier in the same call
chain; a quarantine action landing in the gap between that snapshot and the claim INSERT could let
a claim be taken for a device quarantined moments before send. Distinct from, and strictly narrower
than, the "Residual gap: a device quarantined MID-FLIGHT still holds its claim until TTL" section
above (which covers quarantine AFTER a claim is already held and dispatched) — this one covers
quarantine landing inside a single request's synchronous call chain, which the reviewer
characterized as low-likelihood and could not name a concrete trigger for beyond "a narrow window
on a single request thread." No action — reported `speculative`, which this codebase's governance
framework exempts from gating (no code path or trigger nameable, only a hypothesis). Gate 5 designed
a matching chaos scenario (CH-7: breakpoint-sleep between snapshot and claim INSERT, issue a
concurrent quarantine) — P2/nightly, lowest priority, not filed as its own issue given the
speculative status.

**UP-7 / UP-8 (NICE, verified-safe) — no defect found.** UP-7: a claim-INSERT racing the
reconciler's force-release is safe — Postgres blocks the INSERT on the partial unique index until
the reconciler's transaction resolves, and a rollback yields only a transient, self-healing "busy"
report, never a double-claim. UP-8: `agent_id`/`definition_id` are server/registry-sourced (never
free-form external input), and Postgres text handling rejects embedded NULs outright, failing the
INSERT closed via existing error paths — no plausible way to defeat `ux_concurrency_claims_open`
via input crafting. Both confirmed by reading the actual insertion/locking code, not assumed.

### CLOSED: `get_agent_statistics` counted a still-running execution as a completed success, routinely amplified by the keepalive

Gate 4 consistency-auditor review found `ExecutionTracker::get_agent_statistics`'s SQL (a
pre-existing capability-1.9 query, not something this ADR added) counted a `running` row as a
`success`: its old success `CASE` was `exit_code = 0 AND status != 'pending'`, and a genuinely
in-flight command's `exit_code` defaults to 0 on the wire (unset until a real terminal response
sets it) — so `running` satisfied the condition just as readily as an actual `success`. The
`WHERE` clause only excluded `'pending'`/`'dispatched'`, not `'running'`, so the row wasn't
filtered out upstream either. Before this ADR, this only manifested for a plugin whose output
happened to cross the 64KB auto-flush threshold (a rare, incidental `running` write) or the
never-implemented `yuzu_ctx_report_progress`. This ADR's own agent-core keepalive
(`agents/core/src/agent.cpp`, "CLOSED (agent-core keepalive)" above) turned that from rare into
**routine**: every `per-device` command running past 5 minutes now sends a `RUNNING`
(`__keepalive__`) update that reaches this exact query, transiently misreporting a still-executing
command as a completed success on a live, REST-exposed statistics surface for as long as it's in
flight.

**Fixed**: `'running'` added to the `WHERE` exclusion (alongside `'pending'`/`'dispatched'`); the
success `CASE` tightened from `status != 'pending'` to the explicit `status = 'success'`, which
also incidentally closes a second, previously-unreported latent double-count (a `timeout`/`failure`
row with `exit_code` still at its unset default of 0 satisfied both the old success CASE *and* the
failure CASE simultaneously — now only `status = 'success'` can ever satisfy success). The
vestigial `'error'` value in the failure `CASE`'s status list was also dropped — no code path in
`agent_service_impl.cpp`'s status switch (`update_agent_status`'s `AgentExecStatus.status` values)
ever writes `'error'`; it was dead weight left over from an earlier fix's stated intent
("status values actually set by `update_agent_status`") that the code no longer matched.
Regression test: `test_execution_statistics.cpp`, "a 'running' (in-flight) execution is excluded
from success/failure/total, not counted as a success."

### Gate 5 chaos test design (2026-09-02)

Since Gate 4's unhappy-path review produced findings, Gate 5 (chaos-injector) synthesized the risk
register above into seven executable chaos scenarios (CH-1 through CH-7) rather than authoring
scenarios for the already-closed UP-1/UP-2/consistency-auditor findings. **Scope decision: nothing
in this PR needs to block push to origin** — every remaining finding derives SHOULD/NICE or is
speculative; none reaches CRITICAL/HIGH or hits a policy floor. Filed as tracked follow-up work
rather than run inline:

- **CH-1** (issue #3823, P1) — end-to-end restart-mid-flight verification of the UP-1 by-command
  fallback against a live stack, closing the gap between this round's unit-test coverage and
  real-system behavior.
- **CH-5** (issue #3824, P1) — ASan/TSan proof for the keepalive thread's `ScopeExit`/`cancel_ctx`
  teardown ordering under a connection-break race, closing this session's own earlier
  self-assessment gap ("no TSan run despite cpp-safety explicitly recommending it").
- **CH-2** (issue #3825, P2) — measures the reconnect-vs-reconciler race window (Follow-ups,
  "Reconnect-vs-reconciler race after a long outage" above) empirically rather than only by trace.
- **CH-3, CH-4** — attached as evidence-gathering scenarios to issues #3819 (UP-3) and #3820 (UP-4)
  respectively, compounding a PG outage with retry amplification.
- **CH-6, CH-7** — noted directly on UP-5/UP-6 above; not filed separately given their low severity
  and already-accepted disposition.

### CLOSED: three operator-facing docs still claimed workflow-step claims were release-by-TTL-only after the code that made that true was fixed in this same PR

Gate 6 enterprise-readiness review found a self-inflicted contradiction: the UP-1/UP-2 fix round
(above) correctly updated this ADR's own "Workflow-step claims" section to CLOSED, but
`docs/user-manual/upgrading.md`, `docs/user-manual/instructions.md`, and `docs/yaml-dsl-spec.md`
all still carried the ORIGINAL "release-by-TTL-only even on ordinary success — expect the full
one-hour window" claim, written before that fix landed. An operator or integrator reading any of
those three docs (the ADR itself is not typically what an operator reads) would be told the
opposite of what the shipped code now does — and, worse, a genuinely stuck claim (a real
regression) would read as documented-normal-behavior rather than something worth investigating.
Derived HIGH (I3 wrong-result-presented-as-correct, and I4's "conceals the real state" clause) —
BLOCKING, but a trivial fix given the correct wording already existed in this ADR. **Fixed**: all
three files corrected to state workflow-step claims release-on-terminal-response and renew-on-
keepalive like any other dispatch path, with the separate (unaffected) executions-drawer
correlation gap called out explicitly so the two are not conflated.

### CLOSED: the Instruction Editor's Concurrency Mode dropdown silently discarded `global`/`global-singleton` on Form-mode save

Gate 6 enterprise-readiness review found `instruction_ui.cpp`'s Form-mode `<select
name="concurrency_mode">` offers exactly four options (`unlimited`/`per-device`/`per-definition`/
`per-set`); `server.cpp`'s dropdown pre-fill selects one via a four-way string match against
`def.concurrency_mode`. The real content library ships `global` (17 definitions) and
`global-singleton` (4 definitions) — this ADR's own real-usage audit documents both as real,
accepted-but-unenforced values (see "Real-usage audit" above) — neither of which matches any of
the four options, so neither is ever marked `selected`; the browser defaults to displaying the
first option, "Unlimited". Using the Form tab's "Convert to YAML" button then bakes the
*displayed* (wrong) value into the generated YAML, and Save silently persists it — overwriting one
of those 21 definitions' real `concurrency_mode` with no warning. Pre-existing (this PR did not
change the option list or the matching logic), and not mechanically amplified by this PR's diff
the way `CA-STATS-RUNNING-COUNTED-SUCCESS` was — but derives HIGH (I2 data corruption, E3 any
Administrator/PlatformEngineer on an ordinary edit-and-save) by the same strict rules as everything
else in this review, and the fix was cheap enough to make in-round rather than defer. **Fixed**: a
fifth, dynamically-emitted `<option>` now carries the actual stored value (selected) whenever it
doesn't match one of the four known modes, so Form-mode round-tripping never discards it. No
regression test added — this route (`GET /fragments/instructions/editor`) has zero existing test
coverage of any kind, and building route-level test infrastructure from scratch for it is out of
proportion to this one fix; verified by direct code trace and a clean compile only. A follow-up for
full `TestRouteSink` coverage of this route is worth filing separately from this ADR's own scope.

### Gate 6 operational review (2026-09-02)

compliance-officer, sre, and enterprise-readiness all returned **PASS** — no finding from any of
the three derived CRITICAL or HIGH, and no policy floor was tripped. Two BLOCKING-derived findings
did surface (both HIGH by strict derivation, both fixed in-round rather than deferred): enterprise-
readiness's stale "workflow-step release-by-TTL-only" claim surviving in three operator-facing docs
after this same PR's own fix made it false (independently confirmed by sre), and its separate find
that the Instruction Editor's Concurrency Mode dropdown silently discards `global`/`global-
singleton` on Form-mode save (pre-existing, not amplified by this diff, but cheap enough to fix
in-round). See the two "CLOSED" sections immediately above this one for both.

Non-blocking findings, all documented or deferred: compliance-officer's changelog-completeness gap
(fixed — see the changelog fragment) and its `release_reason`-column evidentiary gap (documented
below, in "Retention"); sre's observability-parity gap (gauge + alert family + runbook, filed as
issue #3830) and its undisclosed rolling-upgrade residual for the keepalive (fixed — see
`docs/user-manual/upgrading.md`'s new "Rolling-upgrade behaviour" paragraph). One finding
(enterprise-readiness's claim about a missing `⚠️` header marker) was checked against the file's
actual convention and found FALSE — `⚠️` is reserved for Breaking/Security headers specifically,
and this entry is correctly classified as an ordinary Behaviour-change header; no change made.

Also closed a related record-completeness gap compliance-officer raised: the Sol/Fable adversarial-
review findings that hardened the UP-1/UP-2 fix (command_id entropy/uniqueness, the empty-
command_id claim-side asymmetry) existed only in ADR prose and code comments, not as their own
governance-ledger rows — added retroactively (`pass_ordinal: 3`) for future auditors relying on the
ledger alone.

### Gate 8 re-review (reconciliation onto `origin/dev`, 2026-09-02)

Between Gate 6 and this point, `origin/dev` was discovered to have moved 140 commits ahead of this
branch's merge-base, including a change in the exact subsystem ADR-1007 touches: HA WS-1(1b) (ADR-2002
section 5) shipped a PG-backed `command_id -> execution_id` correlation table
(`ExecutionTracker::record_command_execution`/`lookup_execution_id`/`reap_command_execution_mappings`)
that fully replaced the in-process `cmd_execution_ids_` map ADR-1007's UP-1 fix was built around. This
branch's 15 commits were reconciled onto `origin/dev` as a single squashed patch (operator decision,
given the same conflict shape would otherwise recur across most of those 15 commits) — see the
reconciliation commit's own message for the mechanical decisions (migration renumbering,
by-command-fallback role narrowing, tick-loop restructuring). Full server suite green post-
reconciliation: 6121/6124 test cases (3 pre-existing skips), 112694/112694 assertions.

Eight agents re-reviewed the reconciliation diff (`git diff origin/dev..HEAD`, one commit):
**security-guardian, docs-writer, cpp-expert, cpp-safety, sre, compliance-officer, architect,
consistency-auditor. All eight returned PASS — no CRITICAL/HIGH, no policy floor.** Findings:

- **security-guardian**: confirmed the new `origin/dev` catastrophic-if-violated clause on the
  executions-history-ladder routed-concern row (#1634, confined-projection redaction + `ExecutionEventBus`
  consumer sanitization) is untouched — the by-command fallback only ever mutates `concurrency_claims`
  rows, never reaches an execution-content read, and every file that #1634 gates
  (`execution_event_scope.hpp`, `execution_event_bus.*`, `rest_a4_envelope.*`, `mcp_stream_bridge.*`)
  is byte-identical to `origin/dev` — absent from this diff entirely.
- **consistency-auditor**: verified, not just likely, on all five completeness axes (migration DDL,
  method declarations, `notify_exec_tracker`'s prefix-skip chain, test-case count arithmetic, tick-loop
  wiring) — nothing from either feature was dropped, duplicated, or cross-wired. One forward-looking
  note (not a defect): the four correlation-ID prefix families that `notify_exec_tracker` skips
  (`polchk-`/`bundle-`/`preflight-`/`deployment-`) return before ever reaching a concurrency-claim
  release — safe today only because none of their callers dispatch through a `per-device`-gated path;
  worth a comment if that ever changes.
- **docs-writer + architect + sre** (converging on the same finding, independently): this ADR's own
  UP-1/UP-2 section (above) still described `cmd_execution_ids_` in the present tense and cited
  "migration v2" after the reconciliation moved it to v3 — unlike the code comments, which were
  correctly updated during the reconciliation itself. **Fixed**: the 2026-09-02 addendum and the
  v2→v3 correction above. docs-writer additionally found two more sites with the identical pattern —
  **fixed**: the migration-DDL comment in `execution_tracker.cpp` (was present-tense, now reads
  historically, matching the corrected text two lines below it) and a new test comment in
  `test_execution_tracker.cpp` (was present-tense AND cited the pre-hardening `random_bytes(8)`
  instead of the shipped `random_bytes(16)` — both fixed).
- **cpp-expert + sre** (converging): a dev/UAT rig that already booted the *pre-reconciliation*
  ADR-1007 branch against a persisted Postgres volume will fail closed (loudly, not silently) on the
  reconciled build, since `schema_meta` would record version 2 as already-applied under the OLD
  meaning. Verified this doesn't apply to any state this session created (every local test run used
  an ephemeral `PgTestTemplate` database, dropped at run end) — INFO, worth one line in the eventual
  PR description, not a code fix.
- **cpp-safety**: SHOULD — the by-command fallback's decision logic (the RUNNING/terminal switch and
  the `__guard__-` skip in `notify_exec_tracker`) is unit-tested only at the `ExecutionTracker` level,
  not through `AgentServiceImpl`/`process_gateway_response` end-to-end. **Fixed**: added
  `test_agent_service_impl.cpp` coverage driving an unresolved-`execution_id` `CommandResponse`
  through the real dispatch path.
- **compliance-officer**: recommendation (not a finding) — record this Gate 8 re-review as its own
  ledger row(s) citing the reconciled commit SHA, since none of the 34 existing rows referenced it.
  **Done** — see the governance ledger.
- **docs-writer** (non-blocking completeness note): the by-command fallback's "two remaining cases"
  enumeration undercounted a real third trigger — `reap_command_execution_mappings` ages a
  `command_execution` row out on a fixed 24h window independent of a concurrency claim's own
  keepalive-renewed TTL, so a legitimately still-running command past 24h reaches the fallback via a
  genuine reap, not just workflow-step dispatch or a degrade. Behavior was already correct either way;
  folded into the doc comments while touching them for the other fixes above.

### Retention: released claims are never pruned (deliberate, for now)

`concurrency_claims` rows are never deleted — a claim's `released_at` is set, but the row stays.
This means the table grows without bound, proportional to total `per-device` dispatch volume over
the server's lifetime, not to concurrent load. This is a deliberate scope cut, not an oversight:
the table carries no compliance-evidentiary value analogous to the audit log or an access-review
campaign (contrast the Periodic Access Review "deliberate no-prune" rule, which is load-bearing
*because* a closed campaign IS the evidence) — a released concurrency claim is exhausted
operational bookkeeping the moment it's released, with no retention requirement pulling the other
way. Building a correct age-based prune pass (this store's own instance of CLAUDE.md's
clock-guarded-retention discipline, on top of the reconciler this ADR already builds one of) was
judged out of proportion to ship alongside the enforcement mechanism itself, given the table's real
near-term row count (dispatch volume of 191 real definitions, not the full fleet catalog) is not
expected to be operationally material for a long time. `idx_concurrency_claims_claimed_at` is added
now, while the table is empty, specifically so that pass can be added later without a
`CREATE INDEX CONCURRENTLY` against a live table. Tracked as a follow-up, not shipped here.

**Related gap, same "add it while the table is free" logic** (Gate 6 compliance-officer finding,
LOW): a force-released row and a normal terminal-response-released row are indistinguishable in the
durable table today — both just set `released_at`, with no `release_reason` column. An investigator
later asking "did this device run this definition twice because its claim was force-released while
still genuinely executing" has only the reconciler's `spdlog::warn` line to go on, which is not
queryable audit evidence. Not required to merge — the mechanism functions correctly either way,
this is an evidentiary-completeness gap, not a control failure — but worth doing in the same future
round that builds the prune pass, since adding a column gets structurally harder once real rows
exist.

**Wired call sites:** `workflow_routes.cpp`'s `POST /api/instructions/:id/execute` and its
workflow-step dispatch closure (both already resolve `InstructionDefinition` before dispatching),
and `ScheduleRunner::dispatch_tracked` (a second `get_definition()` read there rather than
threading `concurrency_mode` through `fire_with_approval`'s signature — schedule fires are not a
hot path). Each was wired via a **sibling** closure type (`ConcurrencyDispatchFn`), not a widening
of the existing shared `CommandDispatchFn`/`DispatchFn` family — that family is bound from one
`command_dispatch_caller_fn` lambda into REST v1, dashboard, MCP, and workflow wiring
simultaneously in `server.cpp`; widening it would have rippled into every one of those for a gate
that applies to two files. `ServerImpl::dispatch_confined` itself gained two trailing
default-empty parameters instead (zero changes needed at its many existing call sites).

**Reporting skipped agents:** a structured `spdlog::info` line at claim time
(`ExecutionTracker::claim_concurrency_slots`), not a `DispatchFn`/`ConfinedDispatchOutcome`
signature change — that shared type's `(command_id, int)` return shape is used by 18+ call sites
(`bundle_orchestrator.hpp`, `dashboard_routes.hpp`, `deployment_engine.hpp`, `dex_routes.hpp`,
`mcp_server.hpp`, `policy_evaluator.hpp`, `preflight_routes.hpp`/`preflight_runner.hpp`,
`quarantine_containment_reconciler.hpp`, `rest_api_v1.hpp`, `schedule_runner.hpp`,
`tar_tree_routes.hpp`, `workflow_routes.hpp`), so threading per-target skip reasons through it is
out of proportion here. Six Prometheus signals ARE shipped in this change, via the existing
post-construction `set_metrics(MetricsRegistry*)` setter (the idiom 20+ other stores already use —
an earlier draft of this ADR incorrectly claimed this would require a constructor parameter, which
would indeed have been disproportionate; the setter needs no such threading). Five on
`ExecutionTracker`: `yuzu_server_dispatch_concurrency_skipped_total` (a claim excluded some
candidates because they were genuinely busy), `yuzu_server_concurrency_claim_unavailable_total`
(Gate 3 sre finding, this fix round — a claim attempt failed CLOSED on Postgres pool exhaustion or
a query error and excluded every candidate regardless of real state; without this the skip counter
alone can't distinguish "candidates really are busy" from "the store is degraded," which matters
because both read identically as "dispatch was partial" to an operator watching only the skip
counter), `yuzu_server_concurrency_reconcile_last_pass_unixtime` (an unconditional liveness
gauge, every reconciler pass — set unconditionally so it self-heals within one tick of boot and
needs no VALUE pre-seed, though it still gets its own `describe()` call for HELP/TYPE
registration, same as the `yuzu_server_audit_retention_last_pass_unixtime` sibling),
`yuzu_server_concurrency_reconcile_declined_total` (a pass declined per the clock-guard's anomaly
classification), and `yuzu_server_concurrency_claim_force_released_total` (a stale claim
force-released by the reconciler) — the four counters pre-seeded to 0 at server construction
(`server.cpp`, alongside the `set_metrics()` call) so an operator's `absent()` alert distinguishes
"never wired" from "wired, zero occurrences," per `docs/observability-conventions.md`. A sixth, on
`ScheduleRunner`: `yuzu_schedule_concurrency_mode_lookup_failed_total`, covering the UP-5 fail-open
case below — also pre-seeded to 0 at construction (`server.cpp`), same rationale as the four above. An operator or agentic caller can also see a partial dispatch after the fact via the
`yuzu_server_dispatch_concurrency_skipped_total` counter and the structured `spdlog::info` line
`ExecutionTracker::claim_concurrency_slots` emits at claim time — a count (how many of this
dispatch's candidates were already busy), not individual device ids — NOT via a "targeted
vs. claimed" comparison on the executions API: `agents_targeted` is set from the post-claim SENT
count (`set_agents_targeted`'s callers all pass the already-filtered `sent` value), so it never
diverges from what was actually claimed and there is nothing to compare it against. This is still
the same "lost-scope device is skipped, never run, re-checked next tick" shape this codebase
already uses for Preflight/Deployment — the visibility mechanism is metrics + logs, not a second
executions-API field.

**Fail-open vs. fail-closed, deliberately different, for two different failure modes.**
`claim_concurrency_slots` fails CLOSED on Postgres pool exhaustion — every candidate is excluded
from that dispatch rather than let through unchecked, because the alternative is silently
unenforced concurrency on a definition that asked for it. `ScheduleRunner::dispatch_tracked`'s
second `get_definition()` read (needed to learn `concurrency_mode`) fails OPEN — logs, increments
`yuzu_schedule_concurrency_mode_lookup_failed_total`, and still dispatches ungated — because the
alternative, skipping the fire entirely, is worse for a `'once'` schedule: a schedule that fires
exactly once and then disables itself would permanently lose that run rather than dispatch it
ungated for one occurrence. Both directions are deliberate, loud, and counted; neither is a silent
default.

### DirectorySync::sync_entra guard

An `std::atomic<bool>` CAS at entry, RAII-reset on every exit path (the function has several
early `return std::unexpected(...)`s). A busy call returns `"sync already in progress"`
immediately — no queueing, no blocking; `discovery_routes.cpp` maps this specific error string to
HTTP 409 (not the blanket 500 every other `sync_entra` failure gets), with the normal audit
treatment. `std::atomic<bool>` only protects one server process — fine on today's single-server
design (`docs/adr/2002-high-availability-architecture.md` already treats multi-replica coordination
as a separate future workstream; this store's fleet-wide-limits HA criterion is removed from that
ADR's list as part of this change, since the class of store it described — `ConcurrencyManager` —
no longer exists).

### `ConcurrencyManager` deletion

`server/core/src/concurrency_manager.{hpp,cpp}` and `tests/unit/server/test_concurrency_manager.cpp`
are deleted, not migrated — migrating it would have built Postgres infrastructure for a mechanism
that cannot fire under the current architecture (see the real-usage audit above).
`docs/postgres-migration-ladder.md` and this ADR's own citation in ADR-0065 are updated to record
the deletion.

## Considered and rejected

- **Building DSL-level enforcement for the 42 catalog-only definitions.** Rejected: they never
  dispatch through the agent path at all — a gate at `dispatch_confined` would faithfully guard a
  path these operations don't take. Would first require making them route through a live dispatch
  path, a real architecture change outside this ADR's scope.
- **Inventing a grouping mechanism for `per-set`.** Rejected: zero real usage, no defined key
  anywhere in the docs or code. Deferred until a real need names one.
- **A wait-queue for at-limit dispatches.** Rejected: zero backing implementation anywhere
  (agent or server) to build on; the spec's prose describing one was aspirational. Replaced with
  immediate rejection + retry, matching the codebase's existing `REJECTED`/`kApprovalRequired`
  idiom rather than inventing new queueing infrastructure.
- **A hand-rolled reimplementation of the clock-guard discipline, instead of adopting the shared
  `audit_retention::classify` decision rule** (an earlier draft — a real defect this ADR corrects,
  not a design note). The first implementation built its own ad hoc backward/forward-jump booleans
  and its own binary anomaly flag, unaware that `common/include/yuzu/audit_retention_rules.hpp`
  already exists as a pure, reusable `Facts`→`Anomaly` function extracted specifically so agent and
  server stores can adopt it without forking it (#2549) — the exact reuse this store needed. The
  shipped design uses it directly: `Facts::has_expired`/`big_step`
  (`audit_retention::moved_at_least`, direction-agnostic against one floor, replacing the earlier
  draft's separate and asymmetric backward/forward checks — a real correctness fix, since the draft
  treated ANY backward drift as an anomaly, which a routine sub-second NTP correction would trip
  on every pass) /`prev_unusable`/`no_anchor` feed `classify()`, and `serialize_concurrency_facts`
  mirrors `AuditStore::serialize_facts`'s exact compact encoding for the dedup key.
  `Facts::would_wipe` is the one input deliberately never set true — not a rejection of the shared
  rule, but the SAME documented non-adoption `api_token_store.cpp` already recorded for its own
  100%-routine-expiry population (routed-concerns "Clock-guarded retention" row, part 6):
  `audit_store`'s table accumulates continuously and always has a healthy mix of recent and old
  rows in ordinary operation, so "literally everything looks expired" is a strong wrong-clock
  signal there; `concurrency_claims`'s entirely ordinary steady state is a handful of open claims
  from currently in-flight per-device dispatches, and it is completely routine for all of them to
  be past their `expires_at` on a given reconciler pass (nothing else was in flight) — a real
  would-wipe signal here would decline the reconciler's own routine job on its most common input,
  caught by a test that failed on exactly this case before the earlier draft's ad hoc version of
  the check was corrected.
- **`WHERE NOT EXISTS`-guarded insert as the claim primitive** (an earlier draft). Rejected: not
  race-free under `READ COMMITTED` without a backing unique constraint — two concurrent
  transactions can both observe no matching row and both insert. The partial unique index +
  `ON CONFLICT DO NOTHING` design replaces it.
- **Widening the shared `CommandDispatchFn`/`DispatchFn` typedef family** to carry
  `definition_id`/`concurrency_mode` universally. Rejected: that family is bound from ONE lambda
  into REST v1, dashboard, MCP, and workflow wiring simultaneously — widening it breaks every one
  of those assignments for a gate two files need. Sibling `ConcurrencyDispatchFn` types instead.

## Consequences

- Per-device concurrency is now enforced for the one mode with real, present-day usage (191 shipped
  definitions), closing a silent gap that existed since the feature was first documented — including
  the long-running-quiet-command case (a `per-device` definition whose plugin runs longer than the
  claim's flat one-hour TTL, e.g. `device.script_exec.*`, a MUTATING instruction with an
  operator-configurable timeout) via the CHAOS-TTL-1 agent-core keepalive fix (see "CLOSED
  (agent-core keepalive)" above).
- `per-definition`/`global`/`global-singleton`/`per-set` remain accepted YAML values (unvalidated)
  that carry no live enforcement — documented as such rather than silently broken. A future ADR is
  required before any of them gain real enforcement.
- `DirectorySync::sync_entra` is now safe against concurrent invocation; other `plugin:
  server`-class handlers were not individually audited for the same class of gap beyond this one
  finding (follow-up, not blocking).
- Raw MCP/REST dispatch (no `definition_id`) and fleet-broadcast dispatch of a `per-device`
  definition remain unenforced — both documented, not hidden. Broadcast is the primary, not the
  edge-case, way this shows up in practice (see "Covered arms" above); it is deferred rather than
  dismissed.
- A device quarantined while holding an open claim is not fast-released — bounded correctly by the
  reconciler's TTL, but a real (minor) over-exclusion window on quarantine release (see "Residual
  gap" above).
- A `per-device` definition dispatched via a workflow step now releases on the agent's real
  terminal response and renews on its keepalive, via the by-command fallback (see "CLOSED (was:
  'Workflow-step claims never see the fast-release path')" above) — no longer release-by-TTL-only.
  The underlying `execution_id` correlation gap (CONSIST-2/sec-M2) is unchanged; only its
  concurrency-claim consequence closed.
- `concurrency_claims` grows without bound (no prune pass ships in this change) and is not yet
  ADR-2002 multi-replica-safe (tracked under #2508 alongside its siblings) — both deliberate,
  documented deferrals, not oversights (see "Retention" above).
- `docs/roadmap.md` Issue 2.9 no longer claims "Done"; it reflects the real, narrower scope this
  ADR ships.

## Follow-ups

- CHAOS-TTL-1's keepalive is a sparse liveness ping (5-minute interval), not jittered or made
  reconnect-aware in the sense of reasserting active commands ahead of a fresh Subscribe stream
  before it accepts new work — the per-connection stop/join at reconnect (mirroring the heartbeat
  thread's own teardown) is sufficient for correctness (the new connection's own keepalive thread
  picks up `in_flight_ids_` immediately, since that set is a member surviving reconnect, not
  per-connection state), but a large fleet reconnecting simultaneously after a server restart could
  produce a synchronized keepalive burst across many agents. Jitter (matching the stagger/delay
  pattern already used for command dispatch, `execute_command_task`) is a follow-up if this proves
  operationally material — not built here since the burst is bounded (5-minute period, empty-output
  frames) and no evidence of it mattering has been observed.
- **Reconnect-vs-reconciler race after a long outage** (Sol adversarial-review finding, PR #3784 fix
  round): the keepalive thread sleeps its full 5-minute interval before its FIRST ping on every
  (re)connect — it does not fire immediately on establishing the stream. If an outage (network
  partition, agent restart) already exceeded a claim's TTL by the time the agent reconnects, the
  server's own ~5-minute reconciler tick can force-release that claim just before the agent's first
  post-reconnect ping would have renewed it — even though the agent is back and the command may
  still genuinely be running. This is the same accepted TTL/liveness tradeoff the whole feature
  already makes for any silence exceeding the TTL (see "CLOSED (agent-core keepalive)" above), not a
  gap introduced by the UP-1/UP-2 fix — only sharpened by exactly how the reconnect and reconciler
  cadences interact. Reasserting `in_flight_ids_` with an immediate ping on (re)connect, before the
  first sleep, would shrink this window; not built here since it requires touching the same
  keepalive-thread-lifecycle code the CHAOS-TTL-1 round already hardened carefully (`ScopeExit`
  unwind ordering, `cancel_ctx`), and no evidence of this mattering in practice has been observed.
- `yuzu_ctx_report_progress` (`sdk/include/yuzu/plugin.h`, implemented `agent.cpp:524`) remains a
  local no-op — the keepalive closes CHAOS-TTL-1 without needing to make this call meaningful, but
  the SDK's own documented contract is still not honest about what it does today. A real wire
  emission (throttled, reusing the keepalive's sentinel-intercept machinery) would let a
  cooperative plugin report finer-grained progress than the keepalive's fixed interval, which is a
  real UX improvement (a slow-scan plugin could surface percent-complete) but not a correctness
  requirement now that the keepalive exists independently.
- Route validation gap: `POST /api/instructions/:id/execute` does not reject `plugin: server`/
  `server_internal`/`_server` definitions before attempting agent dispatch (they fail as
  unknown-plugin today, which is safe but not deliberate).
- Broadcast/None-arm coverage for the per-device claim (currently out of scope — see "Mechanism"
  above).
- **UP-3** (unhappy-path Gate 4 finding, PR #3784 fix round): the reconciler's `big_step` decline +
  5000/pass cap already bound a post-outage claim-release burst to a one-tick delay plus gradual
  draining rather than an instant unbounded release — see "Gate 4 unhappy-path risk register"
  above for the verified trace. If an extended PG outage with many concurrently-open per-device
  claims ever proves operationally material in practice, revisit whether that residual window
  needs narrowing further (e.g. spreading the post-decline drain across more than one tick).
  Tracked as issue #3819.
- **UP-4** (unhappy-path Gate 4 finding, PR #3784 fix round): no rate limit bounds how fast a
  caller can claim+release the same `(definition_id, agent_id)` pair via the `not_sent` fast-release
  path, so a tight retry loop against a persistently-unreachable agent amplifies
  `concurrency_claims`' already-unbounded (never-pruned) row growth beyond the organic-dispatch-volume
  model the "Retention" section below assumes. A rate limiter is out of scope for this ADR; revisit
  alongside whichever future ADR eventually builds the age-based prune pass this table's schema
  (`idx_concurrency_claims_claimed_at`) is already prepared for. Tracked as issue #3820.
- **SEC-CLAIM-NO-LIFETIME-CEILING** (security-guardian Gate 2 finding, PR #3784 fix round):
  `renew_concurrency_claim`/`renew_concurrency_claim_by_command` extend a claim's `expires_at`
  indefinitely on every `running`/keepalive signal, with no cap on total renewal count or total
  held time. A stuck agent, a runaway plugin, or the keepalive thread itself for a genuinely
  never-terminating command can hold a `(definition_id, agent_id)` slot open forever — self-limited
  (only that one slot is affected, not the fleet), which is why this is MEDIUM/SHOULD rather than
  blocking, but real. Not fixed in this ADR's scope. Tracked as issue #3817.
- **QE-DIRECTORYSYNC-409-ROUTE-UNTESTED** (quality-engineer Gate 3 finding, PR #3784 fix round):
  the `DirectorySync` busy-rejection 409 is tested at the store layer (`sync_entra`'s return value)
  but not at the route layer (`discovery_routes.cpp`'s HTTP status/body/audit-call mapping) — a
  regression in the route-level branch specifically would ship undetected. Tracked as issue #3818.
- Fast-release a claim when its owning agent is quarantined MID-FLIGHT, after a successful send but
  before the agent responds (see "Residual gap" above — the claimed-before-dispatch and
  failed-send variants are CLOSED as of the PR #3784 review fix round; this mid-flight case is the
  one still open, since nothing in this dispatch call observes a quarantine that happens later).
- Fast-release the claims in `outcome.denied_quarantined` under `ContainmentGate::fail_closed`
  too — currently deliberately excluded (see "Residual gap" above) because collecting ids on an
  already-degraded path costs a fleet-sized allocation; if that trade-off is ever revisited, the
  chokepoint is the same `wire_and_dispatch_confined` release call, just needs the ids collected
  under fail-closed too (a COUNT-only signal today, per `ArmDispatchResult::denied_quarantined_count`).
- A regression test for the fix-round ordering guarantee that `claim_fn` only ever sees the
  authz-filtered candidate list, not the raw one (a restrictive `VisibleSet` combined with a live
  `claim_fn`, asserting an out-of-scope id never reaches it) — the current integration tests in
  `test_dispatch_confined_arms.cpp` only exercise an unfiltered `VisibleSet`.
- An audit of other `plugin: server`-class handlers (deployment job creation, policy CRUD) for the
  same class of missing re-entrancy guard `DirectorySync::sync_entra` had.
- ~~Workflow-step per-device dispatch claims with `execution_id=""`~~ — CLOSED this round (see
  "CLOSED (was: 'Workflow-step claims never see the fast-release path')" above): the by-command
  fallback releases/renews these claims correctly now. The pre-existing CONSIST-2/sec-M2
  execution-id-correlation gap itself (tracked as "PR 2.x will close" in `workflow_routes.cpp`) is
  UNCHANGED and still open — it just no longer has a concurrency-claim consequence riding on it.
- Bring `concurrency_claims`'s reconciler to the ADR-2002 HA multi-replica clock-guard shape
  (shared reading/dedup state under an ADR-0012 advisory lock) before a second server replica
  exists — tracked under #2508 alongside its siblings (see ADR-2002 finding 4).
- An age-based prune pass for released `concurrency_claims` rows, if the table's unbounded growth
  ever becomes operationally material — see "Retention" below for why this isn't shipped now.
- Give `AgentRegistry::send_to()` (and its callers) a result that distinguishes a definite
  pre-transport failure from an ambiguous one, so the `not_sent` release (above) stops trusting an
  ambiguous `false` — fix shape (b) in the "`not_sent` release trades a false-negative for
  availability" residual gap. Out of scope here: dozens of non-concurrency callers share
  `send_to()`'s current contract.
- Delivery confirmation for gateway-routed dispatch (today `send_to()` returns `true` on queueing,
  not on confirmed forward) — would close the "gateway-routed agent's claim is never captured by
  `not_sent`" residual gap above, and is a gateway-protocol change well beyond this ADR's scope.
