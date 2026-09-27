---
status: draft
date: 2026-07-17
owner: Dave Rae
scope: agent — Guardian detection cutover onto SparkEngine; server — spark/guard health surface
adr: 0021 (Sparks as sole detection layer); amends Decisions 3 & 11
tracks: #1939 (Stage-2 readiness checklist), #2011, #2014, #1938, #1929, #1933, #1936, #2015
governance:
  - original design - 9-agent /governance pipeline, 2026-07-11 (report local, not committed to git); hardening round folded all findings into the sections below.
  - rung 9a addition (the §Rung-2 decision record + inner ladder) - 4-agent pipeline (security-guardian, docs-writer, architect, consistency-auditor), 2026-07-17; every embedded code-claim verified against origin/dev; security MEDIUMs on the F3 blast radius and intra-class lane exhaustion folded in.
  - rung 9c addition (§Async-arm acknowledgment / R5) - the design itself went through six external review rounds (Astra/Codex ×4, Fable ×multiple, Kimi K3 ×2), 2026-09-07, against the plan document, not this doc directly; a seventh round (round 7, 2026-09-07) then adversarially reviewed this PR-0 write-up itself (Kimi + Codex, two HIGH findings against the transcription, folded in - see A3's Epistemic cell and the H-section citation fix); a full `/governance` pass then ran on this PR-0 commit (2026-09-07: Gate 2 security-guardian+docs-writer, Gate 3 architect+cpp-safety, Gate 4 happy-path+unhappy-path+consistency-auditor, Gate 6 compliance-officer+sre+enterprise-readiness - 10 agents total; Gate 5 chaos-injector skipped, no executable-chaos-shaped findings). No BLOCKING findings anywhere; ~25 non-blocking findings folded in directly (citation fixes, an "episode"/"expired" terminology clarification, telemetry-tag gauge-semantics guidance, a restart-remediation caveat cross-referencing this doc's own F3 crash-loop finding, an acknowledged-≠-compliant callout, a changelog fragment). One finding is a genuine, still-open design ambiguity rather than a wording fix: whether a queued-waiter's congestion-only "expired" outcome should count toward decision 7's K-bound the same as a genuine wedge - the plan's own decision-7 headline and its D3 mechanism disagree, unnoticed across all six prior review rounds; recorded as an explicit open question (R5.2) for PR-1/PR-2's own design pass, not resolved here.
history:
  - 2026-07-11 - initial design; 2 governance rounds; landed as PR #2051.
  - 2026-07-17 - rung 9a - §Rung-2 decision record (R1-R4) + the inner-ladder
    decomposition of rung 2 into the §Implementation PR ladder (rungs 1-7 merged as
    PR #2224; the 7.7a/7.7b/8/10/11/12 remainder). Records what was previously held
    only in commit messages and a local plan; the full as-built rewrite is rung 9b,
    after 7.7b.
  - 2026-09-07 - rung 9c - §Async-arm acknowledgment (R5): decouples Guardian's rearm
    window (`apply_rules`) from OS-watch confirmation, closing the ~55ms spark-vs-legacy
    gap the #3990 diagnostic measured. Independent of 9b; sequenced after PR-2c (#3848)
    and before the `prefer_spark` flip (PR-5). Matching rows added to
    `docs/spark-legacy-delta-registry.md` (A3) and `docs/spark-flip-gate.md`.
  - 2026-09-08 - rung 9c PR-1 doc pass (no design change, corrections only): ruling 14
    recorded in R5.2/R5.3 as settled design (congestion-only outcomes excluded from K;
    late results apply by current desired state; #2012/#3840 pulled forward into rung
    9c's own ladder); "expired" split into three named outcomes (admission rejection /
    queue-wait expiry / dispatched-operation timeout) with wedged vs
    congestion-expired stated side by side; F3's orphan-grace binding pinned to the
    PHYSICAL alive-worker count and the ceiling value pinned (#4147); R5.2(a)/R5.3/A3
    made mutually consistent (#4148); R5.4's timing split into staging /
    acknowledgment / persistence to match the PR-1 implementation. Reviewed by Astra
    (`/codex opine`) against the PR-1 plan before the edits.
  - 2026-09-13 - status sweep (no design change): PR-B3 (#2012/#3840, Service) recorded
    as merged 2026-09-12 (PR #4302, closing #2012/#3840/#4181), superseding several
    "in review as of 2026-09-11" mentions; `CloseServiceHandle`'s teardown call
    corrected from "not a blocking call" to its actual disclosed status (same LRPC
    transport as `OpenServiceW`, unverified against hanging - governance review found
    no evidence it cannot hang under a wedged SCM; the #4181 non-applicability argument
    was re-grounded on `unwatch()` releasing `mu_` before teardown runs, since it can
    no longer rest on the retracted not-blocking claim); rung 9c PR-2 recorded as merged
    2026-09-13 (PR #4318) in `docs/spark-flip-gate.md` and
    `docs/spark-legacy-delta-registry.md` (this doc's own R5.2-R5.4 "as implemented"
    stamps already reflected PR-2 from PR #4318's own commits, so only the two
    cross-referencing docs needed the update).
  - 2026-09-14 - rung 9c PR-4.5 (no design change, terminology only): renamed R5.3's
    dispatched-and-timed-out key state "quarantined" to "wedged" ("quarantine" to
    "wedge"/"wedge marking") throughout this doc, `docs/spark-flip-gate.md`, registry
    row A3, and five agent code comments (`guardian_arm_ack.{cpp,hpp}`,
    `guardian_arm_heartbeat.hpp`, `guardian_io_executor.hpp`,
    `guardian_spark_runtime.hpp`), resolving the collision with Guardian's real
    operator-facing network-isolation quarantine (v1.1 §11.7), the shipped
    `quarantine` plugin/`QuarantineStore`/`quarantine_device` MCP tool, and the
    `mech_quarantined_total` SparkEngine fault counter - all three left unchanged.
    Earlier entries above now read "wedged" for this state; they said "quarantined"
    when written. Full `/governance` pass (commit 9256f6189): security-guardian,
    docs-writer, cpp-expert, cpp-safety, architect, happy-path, unhappy-path,
    consistency-auditor, chaos-injector, compliance-officer, sre,
    enterprise-readiness - no BLOCKING findings; this history entry and a
    `guardian_io_executor.hpp` reword (the sentence's physical-stuck clause moved
    off the word "wedge", leaving "wedge marking" its only wedge-rooted term)
    folded in directly as a same-round hardening commit.
  - 2026-09-21 - #4659, R5.7 consumer preconditions - (b) records the inert overlay on
    `subscription_establishment()`, its two stale windows and the first reader's counter rule;
    (c) replaces "not verified" with the measured rename, move, remove and SMB outcomes (the
    resolution is tracked in #4676; raw probe transcripts in
    `docs/spark-rebuild-baselines/raw/4659-file-rename-probe.txt`); (e), (f) and (g) verified
    already consistent with the corrected (b) and left unchanged (an earlier draft of (b),
    written before #4658 landed on this branch, narrowed the check to Registry-only and
    contradicted them — caught and fixed in adversarial review before merge, see the counter
    rule's `pass_failed` fix too).
  - 2026-09-XX - #4704, R5.7 (g)(4) - the Registry sweeper's three pass-outcome lines (`pass
    failed`, `failing persistently`, `pass recovered`) now use File's `PassOutcome` /
    `log_pass_outcome()` shape and are written after `mu_` is released (they ran under `mu_`
    before, stalling `arm()`/`disarm()` on a blocked sink). (g)(4)'s blocked-sink bullet
    rewritten from "the two mechanisms are not the same shape" to the shared shape, with
    Registry's remaining under-`mu_` per-key warn sites named as the residual (#4999); (g)(3)'s
    deadline-stamp bullet gains the matching clause. The operator manual's "Diagnosing an inert
    File worker or Registry sweeper" bullet is corrected the same way; `docs/spark-flip-gate.md`
    gains a closed-by-fix #4704 entry in section 5 and section 7's #4704 precondition is marked
    fixed. PR #5004 (open, not yet merged), full `/governance` (Spark row).
---

# Spark Stage 2 — Guardian as the first SparkEngine consumer

## Context

ADR-0021 makes SparkEngine the agent's only detection layer and Guardian, DEX,
and Reflex its sovereign consumers. Stage 1 (PR #1927) shipped SparkEngine plus
the File, Registry, and Service mechanisms; the pre-Stage-2 hardening batch
(PR #2019) landed the resource/latency fixes. Both are merged to `dev`, green,
and **entirely unconsumed** — nothing in `agent.cpp` instantiates `SparkEngine`.

Guardian still runs its own detection: one dedicated OS thread per armed rule,
built by `GuardianEngine::start_guard_for_rule_locked()`
(`agents/core/src/guardian_engine.cpp`) into
`std::unordered_map<std::string, std::unique_ptr<IGuard>> guards_`
(`agents/core/include/yuzu/agent/guardian_engine.hpp:170`). Stage 2 begins the
cutover away from that per-rule-thread detection (both paths stay compiled through
rung 4; the `IGuard` files are deleted only at rung 5) and
re-homes all three guard types onto the shared, multiplexed mechanisms —
Guardian's first real use of SparkEngine, and the point at which the old and
new detection worlds first coexist on a running agent.

This document is the design; implementation follows as a governed PR ladder
(bottom of this doc). It also carries two ADR-0021 amendments — Decision 3
(§Enforce path) and Decision 11 (§Parity, §24, and gates).

## Scope

**In:** File + Registry + Service guard detection moves from per-rule `IGuard`
threads onto `SparkEngine` mechanisms; Guardian becomes a queued consumer that
keeps all of its meaning-assignment (assertions, compliance verdicts, event
shaping) on top of raw `SparkEvent`s. Agent-side kill-switch. Spark/guard health
surfaced on heartbeat metrics **and** the per-rule REST + MCP status surface.

**Out (unchanged, later stages, or other consumers):**
- Wire protocol: `GuaranteedStatePush`, the `__guard__` event channel, the
  `__guardian__` KV enforce cache, and census semantics stay byte-compatible.
  The compiled per-device policy wire (ADR-0021 Decision 8) is a **later stage**.
- DEX collectors, TriggerEngine watchers, and Reflex — separate consumer
  cutovers, separate stages.
- `PolicyEvaluator` (server-polled instruction compliance) — untouched,
  ADR-0021 Decision 12.

## Rung-2 decision record (rung 9a)

Four questions that rung 2's inner ladder depends on, settled 2026-07-17. They are
recorded here because they were previously settled only in conversation, and rung 7.7's
shape is undefined without them. Each states the ruling, the reason that decided it, and
what it costs.

### R1 - Backend selection: `--spark-disable` is the only switch

`prefer_spark` is set from the existing kill-switch, at the single production
construction site:

```cpp
guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
                                             /*prefer_spark=*/!cfg_.spark_disable);
```

This lands in rung 7.7b, and **7.7b is therefore the cutover**. No second flag is added.

The problem it solves: `GuardianEngine`'s ctor takes `bool prefer_spark = false` and
production passed only two arguments, so the only `prefer_spark=true` in the tree was a
unit test. Spark was unreachable in any production configuration, which would have made
every pre-cutover gate measure the legacy path or a test constructor.

A temporary opt-in selector (`--guardian-spark`, staged cohort, removed later) was
considered and **rejected**: Yuzu is installed only in small labs, so a staged rollout has
no value, and a hard cutover is acceptable (owner decision, 2026-07-17). This matches the
rung-2 posture this document already specifies (detect-only by default; `--spark-disable`
keeps the enforcing legacy path), so **no ADR amendment is required**.

Behaviour, traced through `reconcile_rule_locked`:

| `--spark-disable` | `prefer_spark_` | `SparkAvailability` | Guardian backend |
|---|---|---|---|
| set | `false` | `SparkDisabled` | legacy - **enforcement intact** (escape hatch) |
| unset | `true` | `Available` | spark |
| unset, spark boot threw | `true` | `SparkFailed` | **errored - never a silent legacy fallback** |

`--spark-disable` carries three jobs from 7.7b on: the kill-switch, the resource gate's
legacy comparison arm, and the enforcement escape hatch.

**Fail-visible is fail-closed-for-protection, and that has a correlated-outage tail.** The
`SparkFailed` → errored path is the right posture (a boot failure must be loud, never a
silent restore of legacy enforcement), but note the residual risk it commits to: a
*correlated* spark boot failure - a bad release that throws on every agent - withdraws
every Guardian rule fleet-wide until an operator sets `--spark-disable`. The rung-11 alert
group must therefore alert on `SparkFailed` *prevalence* (a fleet-wide spike), not only
per-agent, so this failure mode is caught in minutes rather than discovered as silent
non-enforcement.

**Accepted cost:** Guardian enforcement is absent from 7.7b until rung 3, because rung-2
posture is detect-but-do-not-enforce. The enforce gap was already accepted (rung 3 follows
immediately, no extended burn-in); the hard cutover makes it start at 7.7b rather than at
a later flip. `--spark-disable` restores enforcement if that is not tolerable on a given
box.

**Consequences for the ladder:** the separate "default flip" rung dissolves into 7.7b; its
residue is the boot WARN, the `yuzu_fleet_spark_enforce_active` gauge, the `changelog.d`
fragment and the `guaranteed-state.md` upgrade note. Rung 4 no longer gates the cutover,
because R4 brings the `unsupported` telemetry forward into 7.7b (only `guard_healthy`
waits for rung 4).

**Note for any future flag:** unknown CLI flags are **fatal** (`main.cpp`'s `CLI11_PARSE`
does not set `allow_extras`). Adding a flag to a fleet agent and later removing it would
refuse to start every device whose service definition still carries it. Any flag
retirement must be staged: accepted-and-ignored with a warning for at least one release.
This applies to `--spark-disable`'s semantic change at rung 5.

### R2 - Mutual exclusion is per-agent, not per-rule

On a spark-preferred agent, `RulePlacement::Unsupported` routes to the distinct
`unsupported` state (§Platform-rejection). It **never** falls through to legacy. ADR-0021
Decision 11's "the flag selects one path" stands unamended.

What decided it: **rung 5 forces this regardless.** When the legacy backend is deleted
there is nothing to fall through to, so `Unsupported` must become a distinct terminal
state then. Keeping the fallthrough means implementing the same outcome twice, and
teaching the parity suite, the telemetry, and the operator model two behaviours.

Verified safe to change now:
- **Enforcement behaviour is identical for the File/Registry case.** The legacy
  File/Registry guards already return false from `start()` off-Windows: a silent
  no-op, no `guards_` entry. Nothing enforces either way. What changes is reporting,
  from silence to an explicit state. This is scoped to File/Registry, not a blanket
  guarantee across every mechanism: the Service guard's legacy path (`guard_systemd.cpp`)
  opens its own independent D-Bus connection, so a spark-side registration failure or
  registered-but-inert mechanism (a containerised host with no systemd bus, per
  `guaranteed-state.md`'s own worked example) can in principle diverge from legacy's
  outcome on that one mechanism - see `reconcile_rule_locked`'s own comment on the
  `Unsupported` branch (enterprise-readiness governance finding, F7/#2298; by
  inspection, the one documented inert case shows no delta - legacy fails identically
  there too - but the guarantee is narrower than this bullet's original wording
  implied). A runtime-inert File worker or Registry sweeper (R5.7 (b)/(g), #4658) is a
  second inert case and it DOES show a delta: the legacy File guard does not depend on
  Spark's `inert`, while under `prefer_spark_` a rule reconciled during the episode is
  classified `Unsupported` and stays disarmed after recovery until the next reconcile or
  restart (R5.7 (g)(1)).
- **Nothing server-side breaks.** The Guardian status surface is still mock/placeholder
  (§Health/status surface), so no server code validates status tokens yet. This is the
  cheapest moment to introduce one; rung 4 owns its wiring.

**Consequences to book:**
1. **The existing reconcile tests assert the old semantics.** `test_guardian_engine_spark_reconcile.cpp`
   contains `TEST_CASE("an unsupported type falls through to legacy, never attempted on spark")`
   and a same-id replace case that assumes legacy is reachable on a spark agent. They are
   rewritten in the same PR as the code change, or the suite goes red on a deliberate
   change and the next person "fixes" it back.
2. **Parity needs an intentional-delta registry.** Legacy silently no-ops where spark
   reports `unsupported`. Zero-tolerance parity cannot be literal across that dimension;
   rung 10's gate artifact must carry the documented delta list, or the gate fails
   spuriously and gets quietly weakened until it means nothing. **Shipped (F12,
   #3386):** `docs/spark-legacy-delta-registry.md`.
3. **macOS under spark preference is all-unsupported.** Both mechanism factories return
   nullptr off their platforms, so every rule on a spark-preferred macOS agent classifies
   `Unsupported`. That matches today's macOS enforcement reality, but the macOS CI leg
   must assert exactly that posture or it passes by testing nothing.

**Landed (F7, #2298):** `reconcile_rule_locked` gives `RulePlacement::Unsupported` a
distinct terminal-state branch - withdraws from both backends, tracks the rule_id in a
new `unsupported_rules_` map (per-outcome erase/insert at every other return path, swept
against the actual push contents on `full_sync`, cleared in `stop()`). All three
consequences above are addressed: (1) the reconcile tests were rewritten in the same PR,
plus a real macOS-factory test asserting the all-unsupported posture directly (not (3),
which is a rung-10 parity-gate item, still open); (2) **shipped (F12, #3386)** -
`docs/spark-legacy-delta-registry.md`. Also shipped in **the F7 PR**: the `mech_unsupported_total`
per-mechanism fleet gauge and `yuzu.guardian_backend` heartbeat tag (§Platform-rejection,
§Fleet metrics, items 8-9 below).

### R3 - I/O executor quota semantics

**Ruled:** the per-class bulkheads must be exact. `GuardianIoExecutor`'s class quotas
(File 4, Registry 3, Service 3) sum to 10 against `total_quota{8}`, and admission is
first-come-first-served against the two caps with no per-class floor - so File and
Registry at their own limits starve Service to 1 of its 3 slots with nothing wedged,
contradicting the header's own guarantee that "a dead mount saturating the file lane never
starves a healthy service reconcile".

The governing algebra: **if `sum(class_quota) <= total_quota`, the total can never be the
binding constraint.** Admitting class `c` requires `class_inflight[c] <= quota[c]-1`, and
every other class is bounded by its own cap, so `total_inflight <= sum(quota) - 1 < sum <=
total_quota`. The total check cannot fire while any class has room; when every class is at
cap the class caps reject anyway. So the choice is binary: exact bulkheads with a
structurally inert total, or oversubscription plus reserved floors.

Oversubscription-plus-floors is **rejected**: it buys 8 versus 10 concurrent
spawn-per-read *detached* workers (not resident threads), which does not justify new
admission logic on a safety-critical path.

**Open at time of writing:** whether to satisfy the invariant by setting `total_quota = 10`
with a constructor-time check, or to remove `total_quota` from `Config` and derive the
bound from the class quotas. Deriving cannot desynchronise; an explicit total plus an
invariant check is a tripwire that forces a conscious decision when a fourth `IoClass` is
added. A synthesis - derive the bound, and `static_assert` the default quotas against an
explicit `kMaxProcessIoWorkers` - gets both, and is the current preference. Note the check
cannot be `static_assert` alone: `Config` is runtime-injectable, so the defaults are
statically asserted and injected values runtime-checked. **Resolve when implementing;
the semantics above are settled either way.** Whichever is chosen, the `total_quota{8}`
field comment ("< sum(class quotas) so it actually binds") states the intent this ruling
*reverses* and must be corrected in the same rung, or a future reader trusts a stale intent.

**Intra-class exhaustion is a separate, unsettled axis (settle it in 7.7a).** The bulkhead
ruling above is about *cross*-class starvation only. Within a class, keyed single-flight
plus `class_quota{File:4}` means four distinct wedged file targets saturate the file lane
and silently kill detection for every file rule - at runtime, with no F3 trip and no crash.
The load-bearing question the record must pin, not leave to implementer judgement: **when a
per-class deadline elapses, the admission slot is freed immediately** (the wedged read's
orphan thread lives on under the F3 count, but the lane recovers), so a wedged target
degrades to skip-and-continue rather than holding its slot until the orphan returns. Lane
availability must be decoupled from orphan-thread liveness.

### R4 - Observability contract

**Constraint:** the agent has no `/metrics` endpoint. `spark_heartbeat.hpp` → status_tags
→ the server-side rollup is the only metric path, and rung 1 already shipped that rail, so
this is an increment on working rails. `GuardianIoExecutor` already computes per-class
`Counters{timed_out, rejected_capacity, rejected_key}`, but `stats()` has no production
caller - they are write-only today, so routing them is new wiring rather than a relabel.

**Standing rule: log state transitions and sampled failures only.** Never per-event or
per-convergence-read. A chatty file watcher at fleet scale is a self-inflicted denial of
service on the log pipeline. This rule governs the initial logging pass itself: write this
set once, rather than a "stopgap" that a later rung has to rip out.

**7.7a (threads live, no rules placed) - logs:** wiring outcome and selected backend;
scheduler and drain-worker thread start/stop; active I/O workers at shutdown, including
whether the F3 hard-exit path fired.

**7.7b (rules flow) - logs:** arm/disarm failure transitions, unsupported classification,
mechanism liveness transitions. **Heartbeat tags:** the executor's per-class counters;
outbox occupancy, oldest-entry age and drops; scheduler lag; and `yuzu.guardian_backend`,
without which the server cannot tell which backend a device is running or distinguish
`SparkFailed` from `Unsupported`.

**The F3 hard-exit signal cannot be a live heartbeat.** `hard_exit()` skips teardown by
design; the process is gone before anything could be sent. It is a best-effort marker
persisted before the exit, then read, reported and cleared on the next boot.

## Async-arm acknowledgment (rung 9c)

Sequenced after PR-2c (#3848) and before the `prefer_spark` flip (PR-5) — lands dormant
behind `prefer_spark_=false`, same posture as every other pre-flip PR in this document.
Settled 2026-09-07 after six external review rounds (Astra/Codex ×4, Fable ×multiple,
Kimi K3 ×2) against the plan document, transcribed into this doc as §R5, into the
registry as row A3, and into the flip-gate as §3a - plus a seventh round, an
adversarial review of this doc's own committed PR-0 transcription (not the plan),
which found and fixed real transcription defects (**corrected round, 2026-09-07**:
an earlier version of this sentence collapsed the split, reading as if all seven
rounds reviewed the plan document - contradicted its own round-7 parenthetical in the
same sentence; see the front-matter `governance:` entry above for the precise split).

### R5 - Accepted is not acknowledged: `apply_rules` never waits for an OS watch

**Ruled:** `GuardianEngine::apply_rules()` and `GuardianSparkRuntime::attach_rule()`/
`detach_all()` stop blocking on the real backend OS call (`CreateFileW`,
`RegOpenKeyExW`, the SCM enqueue). Acceptance and acknowledgment become two distinct
events: `apply_rules()` returns as soon as a push is *accepted* (queued for arming),
and the policy generation reported to the server on `yuzu.guardian_generation` only
*advances* once every accepted rule's arm has actually resolved.

**Motivation.** The #3990 diagnostic measured Guardian's synchronous rearm window
(window B: from "full_sync cleared N prior rule(s)" to "apply_rules ok") on a 62-rule
cohort: legacy median 70-86 ms, spark 127-140 ms — both figures are the diagnostic's
own committed measurand (`b_ms` in `fullsync-blackout-results.jsonl`). A teardown-vs-
rearm-span sub-split (**corrected governance round, 2026-09-07**: an earlier version
of this sentence gave specific millisecond figures for that split — spark 39 ms
teardown / legacy 11-13 ms, spark 85-92 ms rearm / legacy 59-71 ms — attributed to the
#3990 diagnostic itself; verified directly against the diagnostic's own committed run
doc and raw results file, neither of which records any teardown/rearm sub-split at
all, only the single `B` window quoted above. The split figures traced to an
uncommitted local review brief's own log-timestamp analysis during the #3990 run, not
to the diagnostic's committed measurand — removed here rather than misattributed)
is not restated as a measured fact; the root cause below explains where within B the
gap plausibly sits, without claiming a specific measured split. Root cause:
`attach_rule()` already dispatches each rule's
`backend->arm()` onto a detached `GuardianIoExecutor` worker, but the caller blocks on
`cv.wait_until` for the result while `apply_rules()` holds `mtx_`, and `detach_all()`
blocks the same way per disarm. Legacy's guards return as soon as their own thread is
spawned; spark pays the full OS-watch establishment cost inside the window legacy
never does. The requirement is that the rearm window returns fast, not that
time-to-watch-live shrinks — those are different quantities, and this design closes
the gap between them by decoupling the two, not by making the underlying OS calls
faster.

**Warrant: zero wire-protocol change.** ADR-0021 Decision 8 states the generation
counter is a reconcile trigger only, never a compliance signal — deferring
acknowledgment past `apply_rules()`'s own return is therefore consistent with the
counter's designed meaning, not a reinterpretation of it. Two further facts confirm no
new wire surface is needed: `GuardianEngine::get_status()` is dead in production
(never dispatched; a fallback that reports every rule `errored`), and a solicited
`__guard__` reply on the direct agent-to-server path is dropped by the server on
arrival (gateway-connected agents' solicited replies ARE correlated and answered
server-side — a different path, unaffected by this design either way).
`yuzu.guardian_generation` was already the only channel a client's arm state reaches
the server's *reconcile/acknowledgment* logic through (the server separately ingests an
unsolicited `guard.armed` lifecycle stream, a different channel, D2 in the delta
registry) — reporting the *acknowledged* value on the existing reconcile tag is a
purely internal change.

**R5.1 - Executor: a non-waiting dispatch form.** `GuardianIoExecutor` gains a
`submit()` overload alongside the existing `run()`: the backend call still executes on
a detached worker, but the caller does not block for the result — it is handed to a
completion callback on the worker thread instead, with the admission-time quota/
single-flight-key checks (`Stopped`/`AlreadyRunning`/`CapacityExhausted`) unchanged and
still synchronous. Today's quota/`active_worker_count()` accounting conflates "holds a
quota slot" with "counts toward the orphan-exit grace"; those become two independent
counts. **The quota slot and single-flight key release when the backend call (`fn()`)
itself returns — before the completion callback runs, not after.** A worker wedged
*inside* the real OS call therefore still holds its slot and key for as long as it
stays wedged; the existing dead-target bulkhead against a hung backend call is
unaffected by this change. The window this design actually widens is *after* `fn()`
returns but before the worker thread fully exits — while the completion callback runs
— since a non-waiting call can dispatch a fresh operation on completion, and that
refill must not itself be starved by its own predecessor's still-unreleased slot. **A slow or wedged completion callback frees its
quota slot while its thread stays alive, so quota alone no longer bounds the total
count of simultaneously-alive detached workers** — `GuardianIoExecutor` therefore also
enforces a separate physical ceiling on total alive workers (strictly greater than the
sum of all quotas; exact value pinned in the implementing PR's description, per this
document's own §7.7b item 5, which already required this for any two-count split):
admission is refused once that ceiling is reached, regardless of quota availability.
**Accepted consequence, named (governance pass-3 ar-7 / up-3):** a completion callback may
itself dispatch (the compensating disarm, a refill), and when the executor refuses that
nested dispatch the runtime falls back to a direct backend call on the same worker, which
holds no quota and is bounded only by this ceiling; a wedged direct call therefore
accumulates alive workers up to the per-instance ceiling, after which the instance refuses
every admission until a worker exits. Until PR-5's deadline/wedge mechanism, the ceiling is the
only bound on that loop; it is recorded as a PR-5 acceptance criterion in
`docs/spark-flip-gate.md` §3a. A
new `GuardianDetachedWorkerRole` thread-local marker extends the existing
`WorkerHostileMutex` tripwire (`guardian_engine.cpp`'s `abort_if_worker_thread()`) to
executor worker threads, so nothing dispatched this way can ever take
`GuardianEngine::mtx_` — enforced in debug/sanitizer builds, not only by review.

**Two counts, one F3 binding (#4147, pinned in the PR-1 doc pass, 2026-09-08).** After
the split, `GuardianIoExecutor` keeps two counts: a *quota-held* count (per class and
total, checked against the class quotas at admission) and a *physical alive* count
(every detached worker whose payload has not yet been destroyed, including one that has
already returned from `fn()` and is running its completion callback while holding no
quota). `GuardianIoExecutor::active_worker_count()` reports the PHYSICAL count, released
in `TicketCore`'s destructor when the trampoline destroys the worker's payload
(`guardian_io_executor.hpp`): the latest point a detached worker can self-observe before
its OS thread exits. The uncounted tail after that release is the `State` handle release,
a `notify_all`, the payload deallocation, the trampoline epilogue and the CRT thread
exit: it runs only process-lifetime runtime code (the C++ standard library, libc /
pthread or the CRT), never the Guardian, OpenSSL, libsystemd or Win32-RPC code F3
exists to keep out of DSO teardown. No grace covers that tail (`wait_for_workers_to_drain`
returns on the first zero it reads, and `main.cpp` / `service_win.cpp` skip the wait when
the initial sample is zero, `hard_exit.hpp`); the exposure is identical for every `run()`
worker since rung 7 and is accepted as such. A self-decremented count cannot certify its
own thread's exit, so the release point is stated as what it is rather than as
"OS-thread exit" (adversarial review rounds 1-3). That count is
the count `GuardianEngine::active_io_workers()` (`guardian_engine.cpp`) sums for the
F3 orphan-exit grace; F3 never binds to the early-releasing quota count.
`GuardianDetachedWorkerRole` workers are in that sum by construction, callback phase
included. The physical ceiling is `kMaxAliveIoWorkers = kAliveCeilingFactor *
kMaxProcessIoWorkers` = 2 x 10 = 20 per executor instance, derived from the instance's
clamped quota total rather than exposed as a `Config` knob (an injected ceiling at or
below the quota sum would recreate the R3 starvation). A hit is reported as
`IoFailure::CeilingExhausted`, distinct from `CapacityExhausted` because the remediation
differs: quota-full means a backend call is stuck inside `fn()`; ceiling-hit means
workers are outstanding past `fn()` with quota free (slow or wedged completion
callbacks, delayed ticket release), possibly all of one mechanism type. The factor is a
policy allowance, not a structural bound: successive submissions can reuse released
quota while earlier callbacks are still alive, so it is a per-instance backstop that
can impose cross-class back-pressure. Two disarms behave differently under a refusal:
the caller-driven R5.2 disarm claim (`submit_disarm_off_lock`) is RETAINED at the head
of its key entry and re-driven by the next same-key event, never dropped; the drain's
own compensating disarm (a subscription nobody adopted) runs as a bounded `run()` on
the worker and, on a non-timeout refusal at admission, falls back to a direct
`backend_->disarm` call on that worker: alive-counted for F3, outside the class
bulkhead, never a retained claim (`guardian_spark_runtime.cpp`, `on_arm_complete`).

**R5.2 - Runtime: a per-key claim/queue state machine.** Each spark key gets a single
entry tracking its current claim (an in-flight arm or disarm, or none) and a FIFO queue
of siblings waiting behind it. A key that is already wedged (see R5.3) rejects a
new claim immediately, before any backend call is attempted. A second rule attaching to
a key that is mid-arm queues behind the in-flight owner rather than issuing a redundant
backend call; on the owner's success every queued sibling commits inline against the
same subscription (Guardian's existing shared-watcher reuse, unchanged); on the owner's
genuine failure every sibling fails with it, since the underlying key genuinely
couldn't be armed. A disarm claim is retained until it actually executes or is
terminally superseded — never silently dropped for capacity reasons — which is what
makes "a key's disarm completes before its own rearm dispatches" true by construction
rather than by a separately-maintained ordering rule. Each claim also records a
facts-only `ClaimEnd` (how it ended: committed, backend refused, worker threw, admission
rejected, withdrawn, waiter timed out while queued or while dispatched, stopped, commit
threw, disarm done, or dead subscription: a Disarm whose subscription id was already reported dead, completed without a backend call, rung 9c PR-1) as the plug point PR-5's wedge / K-bound / `arm_failed`
classification reads; PR-1 carries no classification logic on it - the only reads are
bookkeeping guards (a committed claim is a `rules_` entry, never a pending one).

**Three distinct non-success outcomes, named once (PR-1 doc pass, 2026-09-08; an
earlier version of this section used "expired" for two of them).** (1) **Admission
rejection**: the executor refuses the operation synchronously (`CapacityExhausted`,
`CeilingExhausted`, `AlreadyRunning`, `LaunchFailed`); no backend call was attempted.
(2) **Queue-wait expiry**: a queued sibling's own wait ends before its key's in-flight
claim resolves; it was never dispatched. (3) **Dispatched-operation timeout**: a
dispatched operation has not returned by its deadline, location unknown - it may be
inside the real OS call, or parked on `SparkEngine`'s per-type lock (`arm_impl()`
takes `mech_ops_mu_by_type_` before `watch_guarded()`, `spark_engine.cpp`), and the
runtime cannot tell which. Only (3) is bounded by a deadline and marks the key
**wedged**; every waiter on a wedged key fails without a further backend
attempt until the original worker's call completes (if ever) and clears the marker.
The two stuck states, side by side so they are never conflated: **wedged** =
dispatched, timed out, K-waivable (R5.3), recoverable when its late result arrives
(ruling 14(b) below); **congestion-expired** = outcome (1) or (2), never dispatched,
NOT K-waivable (ruling 14(a) below), recovers only on the next successful re-apply.
This
per-key wedge marker is distinct from — and not wired to — the existing
per-mechanism `mech_quarantined_total` counter (a fleet-alerting signal expected to
stay at 0); this design's wedge is the ordinary, K-bounded, non-alerting outcome
of a single wedged key, not a mechanism-wide fault.

**Resolved (ruling 14, 2026-09-08 - routed to Astra via `/codex opine`, then Fable as
advisor, ruled by Dave; previously flagged open by round 7's adversarial review; closes
#4148):** (a) **Congestion-only outcomes are EXCLUDED from K.** Neither a queued
waiter's own expiry nor an admission-time `CapacityExhausted` (a push that never
reached the per-key queue) is K-qualifying; only a dispatched-and-timed-out operation
whose claim is still retained is. Both congestion outcomes therefore hold the
acknowledgment, exactly as R5.3's "genuine refusal" list already did for "arm queue
full" - the two sections now agree. Accepted cost, stated as a load consequence rather
than a silent side effect: sustained same-type mechanism contention
(`mech_ops_mu_by_type_`, #2012/#3840) holds a generation's acknowledgment indefinitely
and drives repeated 25 s `full_sync` re-applies for the congestion's duration; it
self-heals once the contention clears, and it can never K-waive a healthy sibling
whose backend call was never attempted. (b) **Late results apply by CURRENT DESIRED
STATE, not by acknowledgment status.** A late success on a still-wanted rule commits
normally (subscription retained, `yuzu.guardian_arm_failed` cleared for that rule, its
"armed" record staged per R5.4); a late success on a withdrawn, replaced, or stopping
rule is disarmed - no leak either way. **Narrower carve-out, governance-adjudicated
(architect, rung 9c PR-5d /governance run):** when a DIFFERENT rule_id already shares
the wedged claim's key and is LIVE at the moment the late success lands, the wedged
claim's own subscription is not independently adopted - the live sibling's ordinary
commit path handles the key (one shared watcher), and the wedged claim's own distinct
assertion is not evaluated again until the next full-sync Reapply (~25 s), not
immediately. This is a real, bounded gap in "commits normally," not a leak (no
subscription is lost or duplicated) - see R5.3 as implemented below for the exact
`live.empty()` guard. This is not a reversal of #3816 (PR #3979):
#3816's invariant (exactly-once result delivery, no leaked subscription) survives
intact; what changes is that `on_abandoned`'s disarm goes from unconditional to
conditional on "rule no longer wanted", because R5 removes the synchronous-wait model
in which "the caller gave up" was the only trigger. PR-5 implements both; PR-1 records
them here so the implementing PR reads settled design. The plan record of the ruling
(`~/.claude/plans/let-s-take-a-step-jazzy-jellyfish.md`, operator-local) is provenance
only; this section is the durable statement.

**What stays deferred, and what was pulled forward (ruling 14(c), 2026-09-08):**
same-type mechanism serialization (`mech_ops_mu_by_type_`, #2012/#3840) is unchanged by
this design, and a single stalled `watch()` can still delay sibling arms of the same
type. It is no longer deferred to the post-flip mechanism-hardening package: because
ruling 14(a)'s accepted cost (unbounded `full_sync` churn under sustained same-type
contention) is only cheap while same-type stalls are rare, the #2012/#3840 fix lands
inside rung 9c's own ladder, between PR-1 and PR-2 (kickoff:
`~/.claude/plans/spark-2012-3840-mechanism-walkoffmu-KICKOFF.md`, operator-local; that
PR appends its own landed-in line here). #2011 (lock granularity) and #2014 stay in the
post-flip package. **Consequence under ruling 14(a), stated explicitly:** a same-type
stall can no longer K-waive healthy sibling keys, because admission congestion is not
K-qualifying; the consequence is instead that the affected generation's acknowledgment
is HELD, with the server's 25 s `full_sync` retry re-applying the whole push until the
contention clears. `yuzu.guardian_arm_failed` therefore carries a reason/phase
(admission-expiry / admission-rejection / dispatched-timeout, R5.3), so an operator
paged on it can tell a genuinely dead target from a key queued behind a slow sibling of
the same mechanism type. PR-B1 (#2012/#3840, Registry) and PR-B2 (#2012/#3840, File) have since landed - see the landed-in notes below. **PR-B3 (Service) merged 2026-09-12 as PR #4302, closing this series** (corrected 2026-09-13, superseding the prior "in review" wording) - **with one correction found during PR-B3's own delivery**: Service never actually had the per-type-lock stall this paragraph describes (`watch()`/`unwatch()` were already O(1) queue pushes before any of PR-B1/B2/B3). Service's real, structurally different gap was `OpenServiceW` running head-of-line on its own dedicated worker thread, stalling sibling watches sharing that thread rather than the engine-wide per-type lock. #3840's issue text carries the full correction. PR-B3 isolates `OpenServiceW` onto a probe-only lane; `NotifyServiceStatusChangeW`'s registration stays on the mechanism thread by design (Win32 thread-affinity requirement) - an accepted residual, not a gap this fix claims to close.

**R5.2 as implemented (rung 9c PR-2 Unit 2/6).** `GuardianSparkRuntime` exposes the
non-waiting counterpart directly: `attach_rule(NonWaiting{}, rule_id, spec, assertion,
emit_compliant_edge)` returns `ArmOutcome{kind, generation, receipt}` -
`kind == Armed` for exactly the synchronous outcomes the blocking overload already
produced (an inline type, an already-committed shared watcher, or a claim observed
already-terminal before this call returns), `kind == Accepted` for everything the
blocking overload used to wait on via `wait_for_claim()`. Both overloads share
`attach_core()`; the non-waiting one simply never calls `wait_for_claim()`. The
deadline this section's "dispatched-operation timeout" bullet (3) describes is
therefore no longer discovered by a blocked waiter's own timeout - nothing is
blocked to notice it - but by `expire_overdue_claims()`, a registry-locked
transition callable directly: it does exactly what `wait_for_claim()`'s timeout
branch always did (`abandon_claim_locked()` every live Arm claim whose deadline has
passed), just relocated out of a waiter, never removed. `GuardianEngine::
reconcile_rule_locked()` is the production caller of the non-waiting overload as of
Unit 6; `GuardianArmAckLedger::drain_locked()` (R5.3) is the production caller of
`expire_overdue_claims()`, from `journal_maintenance_tick()`'s own heartbeat cadence.

**Structural consequence, found during Unit 6's own regression-test design:**
`attach_core()`'s only synchronous `Failed` return is the `stopping_` guard, and
`GuardianEngine::stop()` holds `mtx_` across `spark_runtime_->begin_stop()` -
`apply_rules()` can never observe it. Post-cutover, a genuine per-rule synchronous
`ReconcileOutcome::Failed` for a File/Registry/Service rule is therefore
unreachable outside engine shutdown; every real backend arm failure now surfaces
only asynchronously, through the ledger's drain (R5.3 below).

**R5.3 - Ack model: accepted vs. acknowledged.** **Acknowledged ≠ compliant/enforced,
stated explicitly (Gate 6 compliance-officer) — mirroring this codebase's own
"flag ≠ revoke" precedent for a similarly-named-but-distinct signal** (Periodic Access
Reviews, `docs/security-reviews/access-reviews-2026-07-21.md`): a K-waived
acknowledgment (below) means the server stops re-pushing this generation, NOT that
every rule in it is actually enforced — a wedged rule inside an acknowledged
generation is not armed, and `yuzu.guardian_arm_failed>0` (not the acknowledged
generation number itself) is the only durable signal that distinction is visible on.
"Accepted" means `reconcile_rule_locked()` returned `Accepted` specifically — the async-arm outcome, as
opposed to `Armed` (an inline type or already-committed shared watcher, resolved
synchronously with no ack tracking needed), `Failed`, or `Inert` (a legacy-guard rule,
unrelated to spark). An `Inert` outcome never enters the pending-arm set at all, exactly
as it does not today — the ack predicate is structurally blind to it, so a push whose
rules are entirely `Inert` (all legacy) satisfies the predicate immediately, with
nothing to wait on. `apply_rules()` tracks, per accepted
rule, whether its arm has resolved. The policy generation advances (and is persisted)
only once every rule accepted under it has either armed or been wedged per the
K-bound below — never on acceptance alone. An **episode**, here, is one accepted
rule's not-yet-resolved arm attempt under a given generation — a rule that has already
armed has no episode left to be pending, so it does not count against the condition
below. A same-generation re-push (the server's 25 s `full_sync=true` heartbeat retry)
is a no-op while every *outstanding* episode for that generation is still genuinely
pending and within its deadline — including the ordinary case where SOME rules in the
push have already armed and the rest are still resolving, the common shape of a
retry landing mid-drain (R5.3's own bounded drain, below, routinely spans several
ticks) — and only triggers a full re-apply once something has actually failed,
expired, or the push's content has changed underneath it.
**A wedged key is K-bounded, not held forever** (only a dispatched-and-timed-out
key qualifies; a congestion-expired or admission-rejected rule never does, ruling
14(a)): after three identical same-generation re-applies whose only unresolved rules
are already-wedged, the generation acknowledges anyway, leaving
`yuzu.guardian_arm_failed>0` as the durable fleet signal — a wedged key stays
wedged until its own worker returns or the agent restarts (**restart is a
remediation only for a *transient* wedge — for a *permanently* wedged target, restart
re-arms the same rule against the same dead target and re-wedges, matching this
document's own F3 × `Restart=always` crash-loop finding above, "a security finding,
not only an ops one"; an operator paged on this tag should not treat restart as a
default first action without first checking whether the target is transient or
permanently dead**); a later policy change re-evaluates the rule but cannot by itself
re-attempt the arm. A genuine refusal
(a DISPATCHED call that returned a failure - backend refused or worker threw - or an
admission rejection such as `CapacityExhausted`, where no call was attempted) or a
queue-wait expiry is a different case and holds the acknowledgment indefinitely - K
only bounds the wedged case, never a live refusal and never a congestion-only
outcome. **K is not a generation-wide liveness bound** (ruling 14(a)): a single wedged
worker that exhausts its class quota pushes its siblings into non-K-qualifying
`CapacityExhausted`, and those held rules keep the generation unacknowledged past the
wedged key's own K; do not read K as a promise that every generation acknowledges
within three re-applies. **Zero-accepted push:** a push whose every rule is refused at
admission has nothing pending and nothing armed; its generation does NOT advance
vacuously - it stays behind and the 25 s retry re-applies it, because an
admission-rejected rule counts as accepted-and-unresolved for the predicate.
**Completion ownership survives K:** a K-waived rule's dispatched operation still has
an owner (its retained per-key claim, R5.2), and its eventual result is applied under
ruling 14(b); acknowledging the generation never discards or orphans that completion.
**Three separate transitions, never collapsed:** wedge-release (the wedged
worker's call returns and clears the marker), arm-recovery (a still-wanted rule's late
success commits and clears its `arm_failed` entry), and policy-acknowledgment (the
generation advances) each have their own trigger; none implies another.
`yuzu.guardian_arm_failed` carries a reason/phase per rule - admission-expiry,
admission-rejection, dispatched-refusal (backend refused or worker threw), or
dispatched-timeout - and only the last bears on whether an
agent restart is sane remediation (see the restart caveat above). **Commit timing
under the implementation (PR-1, commit-in-callback):** the runtime commits a resolved
arm on the completion callback's own thread, immediately when the backend call
returns - `commit_new_generation_locked()` (`guardian_spark_runtime.cpp`) stages the
"armed" lifecycle record right there. The heartbeat-bounded drain below is the
ACKNOWLEDGMENT bookkeeping (PR-2); durable persistence of the lifecycle journal stays
the engine layer's job; three timings, not one. The drain that resolves pending arms
against incoming results is bounded
per tick, matching the existing lifecycle-journal's 4-batch/1024-record shape, so a
large outstanding batch drains over several heartbeat ticks rather than risking a
heartbeat-thread stall.

**R5.3 as implemented (rung 9c PR-2 Unit 5/6).** `GuardianArmAckLedger` is the
concrete per-application tracker this section's "apply_rules() tracks, per accepted
rule, whether its arm has resolved" describes. `begin_application(generation,
content_id, full_sync, applied)` opens ONE current application, never a history -
a receipt from a superseded application resolving later is simply no longer in any
ledger's pending set, safe by construction since an `ArmReceipt` is an OBSERVATION
handle, never an owning one. `add_pending()` registers each `Accepted` rule's
receipt. `drain_locked()` - called every `journal_maintenance_tick()`, bounded
(`kAckDrainMaxPerTick`) - sweeps `expire_overdue_claims()` (R5.2) first, then
resolves as many still-pending receipts as its bound allows via
`GuardianSparkRuntime::receipt_status()`. `can_advance()` is what the
generation-hold gate reads: true only with a current application, nothing pending,
and nothing resolved to anything but Committed - and, deliberately, ALSO true for a
current application with an empty pending set because every one of its rules
resolved synchronously (Armed/Inert, nothing Accepted) - matching this document's
own "an `Inert` outcome... satisfies the predicate immediately" language above,
never the "zero-accepted push" vacuous-advance case this section separately warns
against (that case is refused AT ADMISSION and never reaches the ledger as a
receipt at all). `decide_retry(generation, content_id, full_sync, runtime)` is this
section's own same-generation-retry suppression (the paragraph above, "is a no-op
while every outstanding episode... is still genuinely pending"): it consults the
runtime directly, not just its own resolved-failure count, since `drain_locked()`'s
per-tick bound means a receipt past one call's cap can already be resolved without
yet being retired from `pending`. `apply_rules()` calls `decide_retry()` before
anything else, including its own full_sync teardown - REQUIRED, not an
optimization: without it, every same-generation `full_sync` heartbeat retry while
an episode is still genuinely pending would re-run the whole teardown+re-arm, and
an arm slower than the 25 s retry interval would never converge.

**R5.3 correction (governance hardening round, rung 9c PR-2 gate; sec-1/arch-1,
five independently-confirming reviewers): `decide_retry()` must Reapply, never
Suppress, whenever `pending` is EMPTY.** The paragraph above's "is a no-op while
every outstanding episode ... is still genuinely pending" was under-specified: it
never stated what happens when there is NOTHING outstanding at all - the ordinary
case at `prefer_spark_=false` (today's production default), where `Accepted`
never occurs and `pending` is therefore always empty. The dedup this section
describes exists ONLY to protect a claim that is genuinely still in flight from a
spurious re-teardown+re-arm; with nothing pending there is nothing to protect,
and Suppressing anyway also swallowed the one thing `apply_rules()`'s own tail
gate still needed to do on an identical retry: retry a `persist_generation_locked()`
write that failed on the prior call. Before this correction, an empty `pending`
map reached a vacuous Suppress and that retry never ran - the server's own
25 s `full_sync` heartbeat resend (exactly the retry this section's REQUIRED
ordering exists to serve) was therefore unable to recover a stuck generation by
itself; only an agent restart could. This is corrected in
`GuardianArmAckLedger::decide_retry()`: an empty `pending` map returns `Reapply`
immediately, restoring exactly the pre-PR-2 behavior for that case - a full
re-run, NOT a free one (correction, Gate 8: three independent reviewers caught
an earlier draft of this paragraph claiming the reapply "costs nothing" -
`attach_core()` rebuilds eval state from scratch on every push, identical
re-push included, so a `full_sync` retry still pays the same real
teardown+re-arm cycle it always paid before this ledger existed; what changes
is that the retry runs AT ALL again, not that it becomes cheap). Two further
precision fixes landed alongside it: (a) a
`content_id` that is not a real 64-hex-char SHA-256 digest (the `start_local()`
boot placeholder, or `guardian_push_content_id()`'s own throw fallback) is now
NEVER trusted as a content match, even against an identical sentinel from a
different push, since neither sentinel means "this content" in the first place;
(b) `guardian_push_content_id()`'s canonicalization was not block-boundary-
injective - two rules with different `(spark, assertion)` splits of the same
flat field sequence could hash identically, which `decide_retry()`'s content
comparison depends on being collision-resistant.

**R5.3 as implemented (rung 9c PR-5d, "Three separate transitions" - arm-recovery
and wedge-release).** The "arm-recovery (a still-wanted rule's late success
commits and clears its `arm_failed` entry)" transition named above is built as
two genuinely separate mechanisms, matching the two concerns ruling 14(b) folds
together in prose but which do not share one signal in code:

- **Adoption (does the late arm's subscription get committed).**
  `claims_` is the sole source of pending wedge adoption candidacy (#4508).
  `is_wedge_candidate_locked(c)` means `is_retained_wedge(c) && c.rg &&
  c.rg->active && !generation_committed_locked(c)`. `is_retained_wedge`, defined
  in `guardian_spark_runtime.cpp`, accepts both Dispatching and Dispatched Arm
  claims with `waiter_abandoned` and `end == WaiterTimedOutDispatched`.
  Receipt history stays sticky-Wedged even after recovery: it records the
  original timeout, not current desired state or current enforcement.

  **W0 (ownership):** no candidacy writer changes `active` on a generation
  owned by `rules_`. Adoption commits `rg` by shared ownership, so a retained,
  unpublished claim can alias the live generation during publication failure.
  `generation_committed_locked` compares the exact generation in `rules_`;
  all four publication, receipt-recovery, recovery-status and fallback-outcome
  sites share it. No independent adopted bit or completion locator is needed.
  Ordinary commitment moves `rg` into a by-value parameter: a null claim `rg`
  means commit was attempted, whether it succeeded or threw, and leaves no
  generation eligible for adoption on that claim.

  **W1 (uniqueness):** at most one candidate per rule_id, the most recently
  attached or re-observed. Three allocation-free writer sites preserve it:
  withdrawal sweeps matching candidates; hoisted Reobserved restore sweeps
  other candidates before setting its own desire; abandonment deactivates its
  incoming uncommitted generation if another candidate already exists. That
  other candidate became desired after the incoming claim was created. A
  timeout itself provides no fresh desired-state signal. Re-observation is
  decided before ordinary attach withdrawal, and a committed generation is
  excluded even when its retained claim is re-observed.

  `detach_rule_locked` constructs its debug postcondition guard first, sweeps
  candidates second, then calls `withdraw_rule_after_wedge_sweep_locked`.
  Thus Case 0's early return and every throwing withdrawal path follow the
  sweep. `detach_all` constructs the global guard and sweeps once immediately
  after locking, then calls the same pre-swept helper in both its claimed-rule
  and committed-rule loops. The postcondition checks absence of candidates,
  including during unwind. The helper cannot create candidacy under that lock.

  Completion ends candidacy through commitment or removal from `claims_`.
  A receipt can retain a popped, refused claim with all candidate fields still
  set, so its test accessor checks FIFO-front identity membership as well as
  the predicate. The existing late-adoption policy remains: the runtime must
  not be stopping, the claim must be desired, no live follower may take the
  subscription, and `rules_` must not already contain that rule_id. Refusal
  increments `wedge_adopt_stale_refused` and compensates the stale subscription
  without touching the live generation. A re-observation after another key
  commits can reach this refusal during ordinary desired-state churn.

  **Cost:** let N be the total FIFO population, C the rule_ids with claims,
  R the committed rules, f the largest FIFO, and R_idx/K_idx the ordered
  index's rule/key counts. Each added global candidacy walk is linear in N,
  with average O(1) hash work for relevant retained wedges. `detach_rule_locked`
  adds one sweep and one debug walk; A attaches add O(A*N) work. Abandonment
  adds O(N) per expiring wedge, on top of maintenance's existing O(N) collection.
  `detach_all` adds two global walks, retaining the existing withdrawal cost:
  O(N) + (C+R)*(f + log R_idx) + existing confirmed-path work. Case 0 scans a
  key's FIFO for committed rules too; the (C+R)*f term is pre-existing.
  `index_` uses ordered maps: rule lookups cost O(log R_idx), key lookups
  O(log K_idx), and inner set lookups O(log S_k), where S_k is the number of
  rules sharing the key. Under the index invariant those latter terms are
  absorbed by O(log R_idx). Runtime maps use average O(1) hash lookups.
  Retained-wedge heads satisfy W <= 10 + D, where D counts retained-wedge
  heads awaiting compensation reservation, including heads in collected refill
  batches. D has no bound supplied by the permit pool, executor quota, or
  concurrent caller count. Executor quota is released before completion drain;
  the ten compensation permits persist through it. Neither pool bounds N:
  same-key followers and retained Disarm heads can accumulate. This trades
  constant-time locator reads for linear candidacy walks without another cache.
- **Arm-recovery telemetry (does the CURRENT application's `arm_failed`
  clear).** `GuardianArmAckLedger` retains the `ArmReceipt` for any receipt
  `drain_locked()` resolves to `Wedged` specifically (`Application::
  failed_receipts`, rule_id -> receipt - the only failure status a later
  adoption can retroactively recover), because `drain_locked()`'s own erase
  from `pending` otherwise discards the per-rule identity needed to notice a
  recovery later. Each subsequent `drain_locked()` call re-checks every
  retained failure via `GuardianSparkRuntime::receipt_recovered()` (does
  `rules_` currently carry this EXACT (rule_id, generation) incarnation, not
  merely SOME generation of the rule) and, on a match, decrements
  `resolved_failed` and drops the entry - clearing `can_advance()`'s block for
  that application without ever decrementing the cumulative, fleet-visible
  `arm_failures_` counter (`failed_out` is untouched on recovery; that counter
  answers "how many arm failures have ever happened", a different question
  from "does the current application still have one outstanding").

Both mechanisms are **scoped to the current application/claim only** - neither
is the durable, cross-application "last known arm outcome for every currently-
desired rule" gauge a fleet-wide dashboard would need.

**R5.3 as implemented (rung 9c PR-5e, #4221, K-bound closeout, decision 1).**
The K=3 wedge waiver this section names above ("A wedged key is K-bounded, not
held forever... after three identical same-generation re-applies whose only
unresolved rules are already-wedged, the generation acknowledges anyway") is
now built, narrower in scope than this section's original assignment - see the
explicit narrowing below.

- **Mechanism.** `Application::reapply_count` (`guardian_arm_ack.hpp`), a
  saturating counter (capped at `kReapplyWaiverThreshold == 3`) per
  application-SEQUENCE, not per-rule credit: `begin_application()` compares the
  incoming `(generation, content_id, full_sync)` against the OUTGOING
  application (the same identity comparison `decide_retry()` already uses,
  including the `is_sha256_hex()` sentinel guard) and carries the saturated
  count forward only on an exact match; any distinct identity, or no prior
  application at all, resets to 0.
- **A specific rule's own wedge can therefore be waived on its very first
  observation, if the sequence counter was already primed by an unrelated,
  now-cleared failure (governance Gate 4, unhappy-path finding, confirmed
  against decision 1's own framing - not a defect).** Because the counter
  tracks identical-PUSH-CONTENT re-observations rather than any one rule's
  own persistence, a sibling rule's ordinary `CongestionExpired`/
  `AdmissionRejected`/genuine-refusal failure on reapplies 1-2 - which holds
  the generation unconditionally while it lasts, per "K is not a
  generation-wide liveness bound" above - still counts toward
  `reapply_count` once it clears, even though that specific failure was
  never Wedged and never entered `failed_receipts`. If a DIFFERENT rule then
  wedges for the first time on reapply 3, with the sibling now resolved,
  `resolved_failed == failed_receipts.size()` holds for that one rule and
  `reapply_count` is already at K - waiving a wedge this ledger has only
  ever observed once. This is the direct, reviewed consequence of decision
  1 rejecting a finer-grained per-rule/per-episode retry-credit ledger as
  more invasive than the `Application` struct supports (see "Does not add
  per-rule/per-episode retry-credit accounting" in this PR's delivery plan)
  - `reapply_count` measures "how many times has the operator re-sent this
  exact content," not "how many times has this specific wedge itself been
  independently reconfirmed." The single safety invariant K-waiver must
  never violate - a waived receipt is, AT THE MOMENT OF WAIVER, still
  genuinely Wedged and still its key's FIFO-front claim - holds regardless
  of how `reapply_count` reached its threshold; what this consequence
  affects is only how MANY of the operator's own retries a freshly-wedged
  rule is guaranteed before that can happen, not whether the waiver itself
  is sound.
- **The K-eligibility gap the original design language did not anticipate.**
  A naive predicate ("every remaining `resolved_failed` entry is present in
  `failed_receipts`") is necessary but NOT sufficient: `ClaimEnd::
  WaiterTimedOutDispatched` ("Wedged") is sticky by design (§R5.2), but the
  underlying episode it describes is not always SETTLED at the instant it is
  observed - (1) a caller-side timeout can stamp it while the claim is still
  mid-dispatch, racing `dispatch_arm_off_lock()`'s own re-lock, which (on a
  synchronous admission refusal) corrects the REAL outcome via
  `reclassify_dispatching_race_locked()` (§R5.2/PR-5c) - but only while
  `dispatch` is still `Dispatching`; (2) a genuinely-dispatched claim's backend
  call can LATER resolve to a real refusal, popping the claim from its key's
  FIFO while `end` stays stuck at Wedged (the sticky-Wedged contract, PR-5d) -
  the "still-claimed" requirement this doc's own §A row already named in
  prose. `GuardianSparkRuntime::receipt_wedge_k_eligible()` closes both: `end
  == WaiterTimedOutDispatched && dispatch == Dispatched &&` the claim is still
  its key's FIFO front, evaluated under `registry_mu_` at TWO points -
  `GuardianArmAckLedger::drain_locked()`'s primary per-pending loop (never
  insert an unsettled classification into `failed_receipts` even for one
  tick), and its existing recovery-scan loop (re-validate every RETAINED entry
  every tick, pruning one whose eligibility has since settled to false -
  `resolved_failed` itself is untouched; only K-eligible-set MEMBERSHIP
  changes). Both loops need the SAME atomicity property - one `registry_mu_`
  acquisition producing both the status and the eligibility bit together -
  and each has its own combined accessor for it, not a shared one, since they
  read different status shapes: the recovery-scan loop calls
  `GuardianSparkRuntime::receipt_recovery_status()`, the atomic combination of
  `receipt_wedge_k_eligible()` with `receipt_recovered()` under ONE
  `registry_mu_` acquisition (adversarial-review fix: the two-separate-calls
  version could drop a genuine concurrent recovery in the gap between them);
  the primary per-pending loop calls `GuardianSparkRuntime::
  receipt_status_wedge_aware()`, the same-shaped atomic combination of the
  ordinary `receipt_status()` classification with `receipt_wedge_k_eligible()`
  (governance Gate 3/cpp-safety fix: an earlier version of this loop made the
  identical two-separate-calls mistake the adversarial review had already
  caught in the OTHER loop - a genuine claim adoption landing in the gap
  between the two calls would misclassify the receipt as an ordinary failure
  while never retaining it in `failed_receipts`, permanently desyncing
  `resolved_failed` from `failed_receipts.size()` for that application). Both
  accessors route their shared eligibility predicate through one private
  helper, `is_wedge_k_eligible_locked()`, so the predicate itself has exactly
  one definition despite three public call sites.
  `can_advance()` stays a cheap, runtime-free ledger query: `every
  resolved_failed entry counted in failed_receipts` AND `reapply_count >= K`.
  `latched_failure` still blocks unconditionally either way, never folded into
  the K-waiver branch.
- **K-waiver never touches the runtime.** No failed receipt is erased, no
  failure telemetry decremented, no application retired, no rule withdrawn, no
  claim or compensation permit released, no failed rule represented as armed -
  matching "Completion ownership survives K" and "Three separate transitions,
  never collapsed" above exactly. `arm_stats().failed` stays correctly nonzero
  through a K-waived advance and still clears on a genuine subsequent recovery
  (PR-5d's existing mechanism, unchanged).
- **K-eligibility linearizes at the drain-time read, explicitly (adversarial
  review finding, Kimi K3 + Codex Sol - Codex's initial HIGH withdrawn to LOW
  once this sentence's own reasoning was put to it in cross-examination).**
  `drain_locked()` samples eligibility under `registry_mu_` per receipt;
  `can_advance()` reads the resulting ledger membership afterward with no lock
  held across the gap, by design (it stays a cheap, runtime-free query, per the
  scope narrowing above). A completion that lands in that sub-tick gap - after
  the eligibility read, before `can_advance()`/`persist_generation_locked()` -
  does NOT revoke the current tick's decision: the eligibility read IS the
  linearization point, not generation persistence. This produces the SAME end
  state "Completion ownership survives K" already sanctions for the ordinary
  case (a completion landing one tick AFTER acknowledgment) - the gap does not
  make a new state reachable, only an earlier one. Do not "fix" this into a
  runtime-owned waiver-permit latch: the same sub-tick window would simply
  reopen between permit consumption and persistence, or during the interval
  before the server observes the acknowledgment - no achievable linearization
  point eliminates it, so moving it is not a correctness gain.
- **Explicit narrowing (Fable-reviewed decision, not a silent default): this PR
  delivers ONLY the K-bound retry-then-waive policy.** The durable,
  cross-application "last known arm outcome for every currently-desired rule"
  gauge, and `arm_failed`'s reason/phase breakdown, both named as rung 9c
  PR-5e's scope in this section's original text, remain UNBUILT - narrowed out
  of this PR's actual scope rather than silently dropped. A reader must not
  infer either stronger semantic was delivered here; track them as a separate,
  explicit follow-up if a fleet-wide dashboard later needs them.
- **#4472 reassessment under K-waiver.** Traced directly against the current
  implementation (not assumed): #4472's own race (an operator withdraw
  immediately followed by a re-add of the identical rule, racing the original
  claim's still-in-flight `on_arm_complete`) is driven entirely by
  OPERATOR-INITIATED pushes and the runtime's own internal I/O-completion
  timing (`finalize_arm_compensation()`'s unconditional FIFO pop) - neither
  depends on the SERVER's routine 25s retry cadence, which is the only thing
  K-waiver suppresses (once acknowledged, `server.cpp`'s heartbeat-reconcile
  stops resending because `agent_gen` no longer trails `current`). A repeat,
  IDENTICAL server retry was never what un-wedges a key in the first place -
  up-2's Reobserved path re-observes the SAME existing claim without touching
  the stuck worker at all ("a wedged key stays wedged until its own worker
  returns or the agent restarts" - unchanged by K-waiver). #4472's residual is
  therefore UNCHANGED and UNAFFECTED by K-waiver: its mechanism, its healing
  timeline (bounded by the compensating disarm's own I/O completion, not the
  25s cadence), and its acceptance criteria all stand exactly as recorded
  below, with no additional K-specific caveat needed.

**Known accepted residual (governance Gate 4/8, rung 9c PR-5d /governance run,
independently traced and REFUTED as permanent):** a withdraw immediately
followed by a re-add of the identical (rule_id, spec) can race the still-
in-flight original claim's own eventual `on_arm_complete` - if the withdrawal's
`rg->active = false` is observed by `on_arm_complete`'s adopt-check BEFORE the
immediate re-add's Reobserved-restore runs, the restore reactivates a claim
whose disposal is already decided (a compensating disarm is owed). This is
NOT permanent: the disarm is bounded by the same I/O-completion class as the
original `arm()` call, `finalize_arm_compensation()` unconditionally pops the
claim from its key's FIFO once that disarm completes regardless of
`rg->active`'s value, and the re-add caller receives the ORIGINAL wedge's own
already-decided outcome synchronously (never blocks, never silently succeeds)
- so the practical effect is a bounded window in which one re-add attempt on
that key returns a stale answer instead of triggering a fresh arm. External
review precision correction (PR #4485, fjarvis): the healing clock is NOT a
flat ~25s cadence - it starts at the compensating disarm's own I/O completion,
which is bounded by each mechanism's own `watch()`/`unwatch()` contract
(`spark_mechanism.hpp`'s per-type-serialised, CATASTROPHIC-tier "must bound
blocking OS work" invariant - unchanged and unweakened by this PR), not by the
25s full-sync interval itself; the next full-sync Reapply is simply what
eventually re-desires the key once that disarm has landed, on whatever cadence
already governs this codebase's pre-existing disarm path. Tracked as #4472 (a
regression test pinning this exact interleaving, and a decision on whether it
becomes a named Spark-flip-ladder precondition), not a merge blocker.

**A late FAILURE (refusal, not success) on a still-desired wedged rule is a
no-op by construction, not a third mechanism**: the claim was already terminal
(`Wedged`) at abandonment, `armed_live` is false when the backend eventually
answers with a failure, and the adoption branch above requires a live
subscription to commit - nothing new is armed, nothing new fails, and
`arm_failed` correctly stays set (there is nothing to recover from a failure).

**Telemetry-tag semantics, flagged not specified (SHOULD, Gate 6 sre):**
`yuzu.guardian_arm_pending`/`yuzu.guardian_arm_failed` (introduced here, wired in
PR-3) need their gauge-vs-counter semantics stated before PR-3 implements them, not
left to be inferred by analogy. **Label axis (governance pass-3 sre-2):** these tags and
every `GuardianIoExecutor` counter PR-3 exports carry a per-executor-INSTANCE label - the
state reader and the arm/disarm executor admit independently, each against its own
per-instance ceiling (`kMaxAliveIoWorkers` is per instance, not process-wide) - so a fleet
gauge never folds two instances' ceilings into one figure. R5.2's open question (b) above already implies
`arm_failed` must be a **re-statable gauge** (able to return to 0 on a late success),
but this row's own table placement sits next to the C1/D1-style rows in
`docs/spark-legacy-delta-registry.md`, whose tags are the OPPOSITE
pattern — monotonic per-sweep counters summed into a fleet gauge, `docs/
observability-conventions.md`'s own stated "monitor-only: neither `>0` nor
`increase()` is sound" shape. Copying that adjacent pattern by analogy would silently
break the K-bound safety argument this whole mechanism rests on (a cleared wedge
would never be reflected). PR-3 must specify these as gauges matching the age-tag
pattern (`observability-conventions.md`'s `emit_guardian_journal_age_tags`), not the
counter-rollup pattern, and should carry the same five fields this doc's own
risk-accept register uses elsewhere (`docs/spark-flip-gate.md`'s detection-signal /
operator-action / owner / milestone / revisit-condition shape) rather than a bare tag
name. The physical-orphan ceiling (R5.1) similarly has no named observability today —
a repeated ceiling hit (outstanding workers past `fn()` while quota is free: slow or
wedged completion callbacks, possibly all of one mechanism type, structurally different
from ordinary per-class quota pressure) should be independently alert-worthy, not
folded silently into the same signal as ordinary contention
(`IoFailure::CeilingExhausted` is the distinct outcome PR-1 gives it; PR-3 names the
tag).

**AS IMPLEMENTED (PR-3, 2026-09-13)** - three decisions this paragraph left open,
settled via Astra (codex opine) + Fable (advisor) review, both checked against
`origin/dev` code, then ruled by Dave (full history:
`~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md`):

1. **`yuzu.guardian_arm_pending`/`yuzu.guardian_arm_failed` are re-statable gauges off
   `GuardianArmAckLedger`'s CURRENT application** (`GuardianArmAckLedger::arm_stats()`,
   `GuardianEngine::arm_stats()`) - NOT `GuardianEngine::arm_failures_`, which is
   confirmed cumulative-forever and unsuitable (several `fetch_add` sites, never
   decrements, and counts causes beyond a currently-failed rule). Absence is gated on
   FOUR conditions, not one - governance fix, adversarial review CODEX-1/K1
   (`bb9c643d3`): `GuardianEngine::arm_stats()` originally gated only on
   `prefer_spark_`, which left `stopped_` and `spark_availability_ != Available`
   (Unwired/SparkFailed/SparkDisabled) emitting a false-present-healthy `{0,0}` pair.
   The corrected gate is `!prefer_spark_ || stopped_ || spark_availability_ !=
   Available`, layered on `GuardianArmAckLedger::arm_stats()`'s own `nullopt` when
   there is no current application at all - PR-2's `apply_rules()` calls
   `begin_application()` unconditionally regardless of `prefer_spark_`, so a legacy
   (non-spark) agent has a live, empty Application on every push - gating on the
   Application's existence alone would make every non-spark agent in the fleet emit
   `arm_pending=0`/`arm_failed=0`, read by a fleet consumer as "spark arming, healthy"
   on agents not running spark at all. **As implemented (rung 9c PR-5d, concern 2,
   arm-recovery)**: `arm_failed` now decrements in place within one application for
   exactly ONE case - a Wedged receipt whose exact (rule_id, generation) incarnation
   is later ADOPTED by the runtime (PR-5d's own concern 1) is detected by
   `drain_locked()`'s own recovery scan (`GuardianSparkRuntime::receipt_recovered()`)
   and its contribution is cleared; every OTHER non-Committed status (Failed,
   CongestionExpired, Withdrawn, Stopped) still only ever increments it within one
   application, exactly as before PR-5d. It also still resets to 0 whenever
   `decide_retry()` returns `Reapply` on a generation that previously failed, which
   begins a FRESH application - that Reapply path is driven by the existing ~25s
   `full_sync` retry cadence and predates PR-5d. Recovery is scoped to THIS
   application's own bookkeeping only (`Application::failed_receipts`) - a durable,
   cross-application "last known outcome for every currently-desired rule" gauge
   remains 5e's own scope, not delivered here.
2. **The physical-orphan ceiling (R5.1) ships as a plain, monitor-only counter now**
   (`yuzu.guardian_io_arm_disarm_rejected_ceiling`, off
   `GuardianIoExecutor::Counters::rejected_ceiling`, summed across IO classes for the
   arm/disarm executor instance via `GuardianSparkRuntime::io_ceiling_rejections()`) -
   **not** the windowed "currently under repeated pressure" detector one reviewer
   proposed. Dave ruled against baking an unmeasured threshold (a candidate 2-hits/
   5-minute window was proposed and rejected) into shipped code before a later rung has
   real fleet data to size it; that detector is explicitly deferred to rung 9c PR-6.
3. **#3415** (`GuardianIoExecutor`'s general per-class fault-counter egress -
   `timed_out`/`rejected_capacity`/`rejected_key`/`launch_failures`/
   `worker_exceptions`/`abandoned`/`abandonment_cleanup_failures`/
   `completed_after_stop`/`completion_failures`) stays a **separate follow-up**
   ("PR-3a"), scheduled after PR-3 and before PR-5's fault-validation work - this PR's
   `rejected_ceiling` counter is one narrow, separately-motivated signal (R5.1's own
   ask), not the start of #3415's general wiring. See
   `docs/spark-legacy-delta-registry.md` row D10.

Fleet-side rollup: `server/core/src/guardian_arm_fleet_tags.hpp` (SUM of current
values, unlabelled, its own reporting/tag_rejected meta pair) and
`server/core/src/guardian_io_ceiling_fleet_tags.hpp` (SUM of a genuinely cumulative
counter - the ordinary monitor-only shape, correct for THIS signal specifically).
**Correction to this paragraph's own "C1/D1-style" shorthand above**: too broad -
`docs/spark-legacy-delta-registry.md` row C1 already documents `unsupported` as a
live, current-value gauge that can legally decrease, the SAME re-statable pattern PR-3
needs, not the thing to avoid. The pattern to avoid is specifically the counter-rollup
shape (monotonic per-sweep counters summed into a fleet gauge) - `rejected_ceiling`
above is correctly that shape; the arm-ledger pair above is correctly not.

**R5.4 - Audit and durability.** The "armed" audit record is still staged only on a
real, confirmed backend commit — never on acceptance alone, matching today's contract
exactly. What changes is timing, in three separate steps (corrected in the PR-1 doc
pass, 2026-09-08; an earlier version described a single heartbeat-bounded delay):
(1) STAGING is immediate on completion - the runtime's completion callback commits the
arm and stages the "armed" lifecycle record on the worker thread the moment the backend
call returns (`commit_new_generation_locked()`, `guardian_spark_runtime.cpp`),
asynchronously relative to `apply_rules()`'s own return; (2) ACKNOWLEDGMENT of the
generation is what the heartbeat-bounded drain governs (R5.3): at least one heartbeat
tick (~30 s) after acceptance and, for a completion queued behind the per-tick drain
cap, however many additional ticks the drain needs to reach it (not a flat one-tick
bound for every rule in a large push, only for one selected on its first tick);
(3) DURABLE persistence of the lifecycle journal stays at the engine layer on its
existing cadence. A refused (admission-rejected), withdrawn, queue-wait-expired, or
dispatched-and-timed-out arm produces no "armed" record at that time - silence on
failure is unchanged - but a SUBSEQUENT late success on a still-wanted rule does stage
its "armed" record when it commits under ruling 14(b): expiry silences the failure, not
the eventual success.

**R5.4 as implemented (rung 9c PR-2 Unit 6).** `journal_maintenance_tick()` is the
one heartbeat-cadence caller for BOTH (2) and (3) above - EXTENDED, not a second
method, since both were already "periodic maintenance under `mtx_`,
`prefer_spark_`-gated, firewalled." It runs its own persist step (3) BEFORE the
ledger's drain step (2) - an arbitrary, harmless ordering as far as either step's
OWN result is concerned (neither reads the other's) - but it has one consequence
for durability timing that this section's "three timings, not one" principle
already permits and should not be mistaken for a bug: staging (1) lands on the
detached worker's own schedule, independent of the tick loop, including possibly
exactly between one tick's persist (3) and its drain (2) - so the very tick whose
drain step FIRST observes a receipt as Committed may already have run ITS OWN
persist attempt against a `pending_journal_` that still predated the staging.
Durable persistence of that record is therefore not guaranteed within the SAME
tick that resolves the ack - only within the next one, on the engine's existing
cadence, exactly as this section already promises. No data is lost under ordinary
operation (each tick's persist re-snapshots `pending_journal_` fresh, and `persist()`
erases only what it durably wrote), only delayed by up to one additional tick beyond
ack-observation - a delay this section's own multi-tick tolerance for a large
outstanding batch already covers, and one the test suite accounts for directly
(`SparkReconcileFixture::apply()`'s settle loop runs one extra
`journal_maintenance_tick()` after observing ack settlement, specifically for this
reason). **Correction (rung 9c PR-4)**: this stamp previously read "no data is ever
lost" - an overstatement. The one exception is sustained persist failure:
`stage_pending_locked()` (`guardian_spark_runtime.cpp:2419-2434`) caps staging at
`kMaxPendingJournalRecords` and drops the OLDEST record once that ceiling is hit,
counted via `journal_stage_dropped_` (not silently) - a real, if narrow, durability
gap the original wording did not disclose.

**R5.5 - Shutdown.** `GuardianEngine::stop()` no longer parks under `mtx_` waiting on an
in-flight arm, since `apply_rules()` itself no longer blocks there either — a hung
backend call can no longer delay agent shutdown the way it can today. In-flight workers
finish on their own schedule after `stop()` returns; a late-arriving success is
disarmed rather than left live. Queued (not yet dispatched) work is dropped with a
counted total. The existing F3 hard-exit contract (`active_io_workers()`, orphan grace)
is unchanged — this design's non-waiting dispatch path is covered by the same
accounting the state-read and existing arm/disarm executors already use, and that
accounting is the PHYSICAL alive-worker count (R5.1, #4147):
`GuardianEngine::active_io_workers()` sums each
`GuardianIoExecutor::active_worker_count()`, released when the worker's payload is
destroyed in the trampoline (the latest self-observable point before OS-thread exit; the
uncounted tail after it and why no grace covers it are stated in R5.1), never the
early-releasing quota count, so a worker that has returned from `fn()` and is still
inside its completion callback holds the process open exactly as a worker still inside
the OS call does. `GuardianEngine::stop()` also retires the ack ledger (Unit 6,
`GuardianArmAckLedger::retire()`) - belt-and-suspenders, since `journal_maintenance_
tick()` already no-ops after `stopped_`, but it also stops watching receipts whose
claims `begin_stop()` is tearing down; `start_local()` opens a defensive application
at the already-loaded `policy_generation_` before its own boot re-arm walk, so a
receipt accepted during that walk is tracked too - not exercised by
`SparkReconcileFixture` (`test_guardian_engine_spark_reconcile.cpp`), which wires
`start_local()` BEFORE `wire_spark_engine()` (the reverse of production's
`agent.cpp` order), so `spark_availability_` is still `Unwired` during its boot
walk and the walk never reaches the spark path at all in that fixture.

**R5.5 as implemented (rung 9c PR-4; existing mechanics from PR-1/PR-2).**
`GuardianEngine::reconcile_rule_locked()` selects `GuardianSparkRuntime::attach_rule
(NonWaiting{}, ...)` (`guardian_engine.cpp:1910`); that overload
(`guardian_spark_runtime.cpp:1258`) never calls `wait_for_claim()`. The blocking
overload that does (`guardian_spark_runtime.cpp:1214`, via `wait_for_claim()` at
`:272`) still exists but has no production caller left - PR-2 removed the last one,
leaving only test code. This closes the specific hazard this section
originally described: `stop()` can no longer be delayed by a hung backend arm/OS
call. It does NOT make `stop()` prompt in general - overstating that was #4322's own
defect (see below). `GuardianEngine::stop()` (`guardian_engine.cpp:613`) and
`apply_rules()` (`:1001`) share `mtx_`, and `apply_rules()` still does real
synchronous work under that lock: a full_sync's KV sweep and
`spark_runtime_->detach_all()` (`:1176`, scales with the rule count being torn down -
`detach_all()` itself, `guardian_spark_runtime.cpp:1647`, reserves and iterates
`rule_ids.size()`), the per-rule reconcile loop, and an unbounded lifecycle-journal
persist via `GuardianRollback`'s destructor on every exit. `apply_rules()` is not the
only holder that can delay `stop()` this way: the boot-time `start_local()` (`:453`) /
`wire_spark_engine()` (`:1996`) calls do their own synchronous work under the same
lock unconditionally. `journal_maintenance_tick()` (`:766`, every heartbeat tick) is a
fourth holder but a different shape - bounded per tick
(`kJournalPersistMaxBatchesPerTick`/`kAckDrainMaxPerTick`) and `prefer_spark_`-gated
(`:767`): it no-ops immediately after taking `mtx_` while `prefer_spark_` is `false`,
which is production's default today, so it is not currently a real contributor to
`stop()`'s wait the way the other three unconditionally are. `stop()` itself also
persists the journal unbounded, once before `begin_stop()` and once after
(`guardian_engine.cpp:639`/`:667`). `GuardianSparkRuntime::begin_stop()`
(`guardian_spark_runtime.cpp:2806-2849`) drops every Queued claim with a counted
total (`claims_dropped_at_stop_`), leaves Dispatching/Dispatched claims for their own
completion callback, and disarms a late-arriving success rather than leaving it live.
`GuardianEngine::stop()`'s `ack_ledger_->retire()` call is bookkeeping only (resets
what the ledger is watching), not resource cleanup - the disarm guarantee above is
what actually tears down a live claim. Two known callers of `begin_stop()` outside
`stop()`: `~GuardianSparkRuntime()` (`guardian_spark_runtime.cpp:92-97`) calls it too,
but its own comment argues this is a defensive idempotent no-op - no in-flight pass
can be running by the time the destructor runs, since a pass keeps the runtime alive
through the handler's captured `shared_ptr`. The other,
`rollback_spark_wiring_locked()` (`guardian_engine.cpp:2166`, single call
site at `:2048`, a boot-time wiring-failure path), resets `spark_runtime_` without
first waiting for `active_backend_op_workers()==0` - tracked as **#3811** (filed
during the #2233 governance sweep, confirmed OPEN 2026-09-14 via `gh issue view 3811`;
`docs/spark-flip-gate.md`'s own §3 row 3 already rules it does not gate the Spark
flip, unlike its sibling #3816).
**Detection signal: none today**, same as #3816's own entry notes for its gap -
`GuardianEngine::active_io_workers()` (`:2199`) sums via `if (spark_runtime_)`
(`:2214`), so any worker `active_backend_op_workers()` still counted at reset time
drops out of that sum the instant `spark_runtime_.reset()` runs, not when the worker
itself finishes - whether a worker can actually outlive the reset here is not
established either way by this note. Cited here, not re-investigated or re-fixed by
this PR. `#4322` (the stale
`begin_stop()` comment claiming `apply_rules()` could still park in a bounded backend
wait) is fixed in the same PR that adds this stamp.

**R5.6 - Legacy asymmetry.** Legacy acknowledges synchronously and unconditionally,
including a rule whose guard failed to start — that rule is silently stranded `Inert`,
logged but not held against the generation. Spark's acknowledgment holds on a genuine
refusal, and is K-bounded (never unconditional) on a wedged key only - a
congestion-expired or admission-rejected rule holds it (ruling 14(a)). This is a
deliberate, documented delta (`docs/spark-legacy-delta-registry.md` row A3), not an
oversight to reconcile — spark's stricter acknowledgment is the point of this design,
and legacy's asymmetry pre-dates it and is out of scope to change here.

**R5.7 - Re-measurement methodology.** Window B (`T1 - T0`, the existing #3990
measurement) remains valid for direct comparison with prior runs, but it is a
log-to-log interval, not proof of `apply_rules()`'s actual return latency:
`apply_rules()` constructs a rollback guard whose destructor performs unbounded
lifecycle-journal persistence on scope exit, and that destructor runs *after* the T1
log line — so under this design, a smaller B does not by itself prove a faster actual
function return, since work can now be staged asynchronously before T1 while the
destructor's own persistence work still happens after it. Re-measurement must add a
second timestamp, T2, taken from the runtime's own arm-confirmation commit (a new log
line) — not from `SparkEngine`'s own "armed" log, which fires before the real OS call
completes and is not a valid proxy for it. The diagnostic script's completeness check
(confirming every expected arm actually happened) must also exclude a no-op re-push's
own log line from that count, since a no-op returns the same `rules_size()` figure
without a single real arm occurring.

**Rung 9c PR-6 item 1 — an establishment-signal channel now exists (Service first;
Registry and File followed under #4340), 2026-09-18.** R5.7 above still needs its own T2
arm-confirmation timestamp from the runtime, but the raw fact it would need to read from is
no longer entirely missing at the mechanism layer: `SparkEngine::subscription_establishment(id)`
is a pull query returning `armed_at` / an optional `established_at` (first Notification-coverage
report for the subscription's CURRENT incarnation, never re-stamped by a later recovery) /
the mechanism's current tri-state `SparkCoverage` (`None`/`Notification`/`Poll`). Wired
first for Service (both platforms: Linux sd-bus, Windows SCM); Registry and File followed
under #4340 (Windows only). A Service watch's `watch()` call returning success carries zero
information about establishment (its `NotifyServiceStatusChangeW`/`PropertiesChanged`
registration is what this channel actually observes), so it was the mechanism with the most
acute gap.
**Registry and File: implemented under #4340 (2026-09-20).** Both mechanisms
override `watch_incarnation()`/`set_established_sink()` the way Service does. They follow
Service's shape (seal the sink first in `start()`, mark coverage transitions under `mu_`, stage
in the sweep visit, dispatch in `run_off_lock()` with `mu_` released, established reports
before that pass's emits/faults) minus these differences: no `key_epoch` (the staged
incarnation is the identity check); no `Poll` state (Service only); no worker-death
invalidation (Service invalidates every key to `None` when its worker throws; the Registry
sweeper and the File worker survive an exception); a per-call try/catch plus an
`established_failed` counter around the sink (Service has no per-call catch, so a throwing
sink there reaches its `run()` catch); no Service-style `fired` guard on adoption (Registry
re-reports the watch's raw coverage, so an adoption landing between the OS signal and
`on_fire()` taking `mu_` can briefly report `Notification` for a watch that has already
fired, with `None` following); and File keeps a per-KEY incarnation over per-DIRECTORY
coverage.
One asymmetry the two do NOT share with each other, load-bearing for any consumer comparing
their `coverage` streams: Registry's `RegNotifyChangeKeyValue` is one-shot, so coverage
genuinely FLAPS `Notification -> None -> Notification` on every consumed Target-mode fire (a
real notify-then-rearm cycle, not a bug; Target mode means the watch sits on the requested key
itself, Ancestor mode means the key is absent so the watch sits on its nearest existing
ancestor until the key appears); a deletion fire ends at `None` (Target -> Ancestor, no
`Notification` until the key reappears). File's `ReadDirectoryChangesW` reissue is
synchronous on an ordinary fire, so its coverage stays `Notification` across it and only
drops on a genuine backend failure (a failed read completion, reissue or re-probe) or loss of
the watched (parent) directory; never on `unwatch()` or an orderly `stop()`, which are
deliberately unreported (see R4). A consumer that assumes the two mechanisms' `coverage`
streams mean the same thing is wrong without accounting for this.
**established_at is per-INCARNATION, not per-key, carried forward for R5.7's own
future use of this channel (and for any future detect-latency measurement built on it,
#4606):** a fire-triggered re-arm on the SAME incarnation (Registry's ordinary fire path
above) never re-stamps `established_at`, and `subscription_establishment()` is a pull query
that is not guaranteed to observe the transient `None` mid-flap — Registry's `None`
and the re-arm's `Notification` land on consecutive sweep passes when the re-arm
probe resolves promptly (the sweep drains the `None` marker before it commits the
re-arm, and the commit's own `Notification` marker is only picked up by the next
pass, never the same one), and may then be too close together for a pull query to
observe the transient `None`. A consumer that needs to observe "coverage was lost and
regained across a re-arm cycle" must install a mechanism-direct `set_established_sink()`
observer in its own harness — do not build that on polling `subscription_establishment()`
for the re-arm half. Do not build it on disarm+arm either: a disarm of the LAST subscriber
followed by an arm mints a fresh incarnation (a dedup arm onto an already-armed key shares
the existing one), and when a concurrent re-arm lands before the engine's `unwatch()` the
engine skips it and the mechanism ADOPTS the live watch under the new incarnation,
re-reporting its CURRENT coverage stamped `now()` — a re-baseline, not an observation of
loss and regain.
**Timestamp semantics:** `established_at` is the mechanism's commit time, EXCEPT adoption
and join reports (Registry adoption in `watch_incarnation()`; File join or coalesce onto an
already-established directory), which are stamped `now()` at the adoption or join, so a
first-wins `established_at` cannot predate its own incarnation's `armed_at`. For such a key the
stamp is later than the watch's original establishment by up to the watch's whole age (not by
one sweep pass), and arm-to-established reads about zero, because the stamp is taken during the
arm itself, whatever the real establishment latency was. A latency measurement must therefore
not use adopted or joined keys.
**Ordering:** within ONE dispatch pass the establishment reports are delivered before that
pass's own emits/faults. That is all it guarantees. A commit stages its synthetic Emit in the
same visit but re-marks its `Notification` after that visit's drain, so the `Notification` is
staged one pass AFTER the Emit; Registry's immediate emit from `on_fire()` is not covered
either. It is not a general "the report is visible before any event" guarantee.
**Ancestor mode:** the watch is on the nearest existing ancestor (the target is absent) and
WILL detect the target's appearance, yet `coverage` is `None` — a stable NON-loss. An absent
target's `established_at` therefore stays unset; a latency criterion must censor such
subscriptions, not read them as deaf.
**Latency caveat, carried forward for R5.7's own future use of this channel:**
`established_at` is stamped by the MECHANISM at the point it commits successful
notification coverage (adoption and join excepted, above), not at the moment
`report_established` is dispatched to a consumer. All three slow paths poll on a 50 ms
cadence (`kServicePollCadence`, `kRegSweepCadence`, `kFileSweepCadence`): each is a wait CAP
the mechanism's own wait clamps to whenever a probe is outstanding (Pending) — not a fixed
delay; a nudge (Registry, File) or a command or APC (Service) wakes it earlier. Dispatch of a
report is bounded the same way on all three mechanisms.
**Windows live-registration-retry blind spot, carried forward for R5.7's own
future use of this channel:** on a live-registration failure that occurs
AFTER a successful resolve (`NotifyServiceStatusChangeW` itself failing
post-`OpenServiceW`), Windows's `begin_probe`→`resolve_probe` retry loop has
no status-poll fallback — it only re-learns the service's real state from a
future successful Notify callback. Linux's equivalent failure
(`sd_bus_match_signal` post-`LoadUnit`) DOES fall back to `read_state()` via
its backstop reconcile. A service can flip Running↔Stopped **undetected** on
Windows during this narrow retry window; it cannot on Linux. This asymmetry
predates this channel (confirmed against the pre-PR base commit `7ff742f19`
— the fallback was already absent) — this channel only made the gap
OBSERVABLE (staging `SparkCoverage::None`, honestly, rather than leaving it
invisible). A future R5.7 consumer treating Windows's `None` in this
specific window as "confirmed absent" rather than "not yet re-confirmed"
would be wrong; do not conflate the two without a discriminating signal
Spark does not currently have (see also the `SparkCoverage::None` ambiguity
note for Registry/File, implemented under #4340 — Registry's `None` is very often a
genuine one-shot-notify-consumed flap rather than a Service-style "not yet
re-confirmed" gap; a consumer must not conflate the two without checking
which mechanism produced the report, per the asymmetry noted above).
**R4 (stale-after-stop), carried forward from the delivery plan's own residual list:**
after `SparkEngine::stop()`, `subscription_establishment(id)` keeps returning the
subscription's LAST-KNOWN values — stop() does not clear or invalidate them. A future
R5.7 consumer that cares whether the engine is still live checks `is_running()` itself
(the query's own doc comment, `spark_engine.hpp`, states this directly); do not read a
post-stop `established_at`/`coverage` pair as current live coverage.

**Consumer preconditions and known residuals (Registry and File, #4340).** (a) `coverage` is the
LAST DELIVERED value, not an authoritative live state. (b) It can go stale with no signal a
consumer can read. A dropped report (the sink threw; the production engine sink takes only the
engine lock and cannot realistically throw) is not detectable by a consumer at all:
`subscription_health()` reads `armed_.faulted`, which only a Fault report sets (a mechanism's
Fault callback, or the engine's own pre-start replay failure), so
once a deleted target's re-arm has resolved to the ancestor the watch is Healthy, `inert` is
false, and the cache can still read `Notification` if the `None` report was dropped (the
Registry test that characterises exactly this drops every `None` and deletes the target). A
Registry sweeper or File worker in persistent failure also leaves a stale `Notification`,
unflagged until it flips `inert` after `kSweeperInertAfterFailures` / `kFileWorkerInertAfterFailures`
(3 for either, the latter added by #4658 — see (g)) consecutive failed passes. Checking
`!stats_by_type()[type].inert` alongside `subscription_health() == Healthy` narrows the Registry
sweeper-failure and File worker-failure cases, and only once the flag has flipped for either; it
does not cover a dropped report. `subscription_establishment()` itself reports
`coverage = None` while the type's mechanism `stats().inert` is true; `established_at` is left
untouched. That overlay is a conservative snapshot, not a coherent one: `inert` is read beside the
cached value, so `None` can coexist with a newer staged `Notification`, and a stale `Notification`
can be read once `inert` has cleared. It leaves two windows open. Before the flip, at the default
50 ms sweep cadence, Registry retries back off 50 ms then 100 ms and `inert` flips on the third
consecutive failed pass, so a stale `Notification` can be read for that long plus the pass
durations. After recovery, `inert` clears on the first good pass but each sweep pass visits a
bounded subset of watches, so a cached value can stay stale until its watch is next visited. The
first reader closes both with a counter rule (decided 2026-09-21): it snapshots the mechanism's
debug counters (`sweep_pass_failed` and `established_failed` for Registry, `pass_failed` and
`established_failed` for File — `pass_failed` is the complete File failure detector per (g)
below; `established_failed` alone misses an alternating failure/success pattern that never flips
`inert`) and `stats().inert` before arming, requires `inert` to be false, and re-reads them when the
measurement ends (any movement, or `inert`, invalidates the sample, recorded as a per-attempt
reliability failure and never silently excluded); it uses fresh keys
in isolated directories (no adopted or joined keys, no writes to a File watch's directory during
an episode); it censors Ancestor-mode subscriptions; it reads only while `is_running()`; and it
runs in-process, because the counters are `_for_test` accessors that exist on Windows only
(`nullopt` elsewhere). Log lines are diagnostic only, never the closure. (c) `Notification`
means the mechanism holds the
watch and issued the read (Registry: the key exists and the notify is armed; File: the parent
directory handle is watched, even when the file itself is absent). It is a probe result, NOT an
end-to-end detection guarantee. A standalone probe that opens the directory as File does measured
its handle-based watch on 2026-09-21 (Windows 11 Pro 25H2 build 26200.9457, local NTFS, three
runs per case, 30 s windows). A rename or move of the watched directory gives no completion: the
read follows the directory object, writes under the new path are detected, and writes under a
recreated original path are not. `RemoveDirectory` gives an immediate failed completion
(`ERROR_ACCESS_DENIED`, `STATUS_DELETE_PENDING`), which is the mechanism's `!ok` branch. A rename
of the PARENT is refused while the watch handle is open. A change to the watched directory itself
is not reported. On an SMB share (Samba 4.23.10 in a container, not a Windows file server; the
silent-drop case was not measured), a hung server fails the read after about 64 s
(`STATUS_IO_TIMEOUT`, one run) and a gone server fails it at once
(`STATUS_CONNECTION_DISCONNECTED`, one run). A server-side rename of the watched directory gives
no completion in 30 s, and a server-side delete gives only the child's REMOVED record, no failed
completion in 30 s. After a failed completion the old handle stays dead until reopened. The real
File mechanism was not run against a rename: its outcome is inferred from these results and
`process_completion_locked`. So a local rename or move, and a rename or delete on a share, leave
coverage at `Notification` while the target path is unwatched; #4676 tracks the resolution. Until
it lands, a reader must treat File `Notification` as unconfirmed for a target that could be
renamed, and a post-establishment write to the original path is only a point-in-time liveness
check. Raw transcripts: `docs/spark-rebuild-baselines/raw/4659-file-rename-probe.txt`. (d)
`coverage == None` with `established_at` unset
means never confirmed (an absent target, a pending arm or a failed arm; NOT necessarily deaf).
With `established_at` set it means one of: the Registry one-shot flap (brief, on the order of
one re-arm); a Registry target that has since been deleted (Target -> Ancestor: the watch now
sits on the nearest existing ancestor and will detect the key's reappearance, which restores
`Notification`; a stable `None`, not a deaf watch); or a genuine loss (a failed read completion,
reissue or re-probe on File; a failed re-arm on Registry). The discriminators that exist are
`subscription_health() == Faulted`, the age of `armed_at` (which bounds how long the
subscription has existed; there is no last-transition timestamp, so telling a brief flap from a
stable `None` means sampling `coverage` over time), and `nullopt` from
`subscription_establishment()`, which means an unknown or already-disarmed subscription id (not
an engine `stop()`: after `stop()` the query keeps returning last-known values, see R4 above).
(e) The first
production consumer, the detect-latency measurement tracked in #4606 (precondition list: #4659), must
re-derive the stale-cache severity and cover these residuals itself: the check in (b) narrows only
the Registry and File worker-failure cases, so there is no complete guard to copy. (f) There is no
operator surface: a dropped report is counted in the `established_failed` debug counter (a test
seam) and logged once (the first drop only). (g) File now has (b)'s narrowing (#4658): its
worker counts each failed pass (test-visible only), backs off (doubling from `sweep_cadence`, 30 s
cap), logs at failures 1, 2, 4, 8, ... and flips `inert` after three consecutive failed passes,
clearing on the next success. Two residuals remain: a real directory notification during an
episode still runs a (failing) pass, so the pass rate is bounded by the kernel's notification rate
rather than the backoff; and a single poison obligation fails the whole pass, starving the others
until it clears (same as Registry). A third, the Guardian re-reconcile gap, is KNOWN and open
(#4685). The list below sets out that gap, the contract a consumer of `inert` needs and two
further recorded limits.

**R5.7 (g), continued: the File worker-failure contract (#4658).**

1. KNOWN open gap, a precondition for the F14 flip. Tracked as issue #4685, with an entry in the
   flip-gate risk-accept register (`docs/spark-flip-gate.md` section 5). While File is
   runtime-inert, a Guardian reconcile (a full-sync policy push, for example) builds its capability
   set without File (`GuardianEngine::reconcile_rule_locked()`), so `classify()` places every File
   rule it touches `Unsupported`. That branch (`RulePlacement::Unsupported`) also DETACHES a rule
   already armed through Spark and withdraws its legacy guard, and a full sync tears both backends
   down first (`stop_all_guards_locked()` and `spark_runtime_->detach_all()` in `apply_rules()`).
   Live File rules are therefore disarmed for the episode. Clearing `inert` notifies no consumer, so
   they stay disarmed (enforced by neither backend, recorded in `unsupported_rules_`) until the next
   reconcile or an agent restart. Dormant while `prefer_spark_` is false. A Registry sweeper flip
   has the same shape and predates #4658. `guardian_engine.cpp` is unchanged by #4658, so it is
   cited by symbol.
2. `inert` is a polled bit, not an event. Read it through `stats_by_type()`: it is not latched,
   nothing announces a flip or a clear, and a heartbeat only sees an episode it happens to sample.
   `SparkMechanismStats` cannot tell a boot-time inert (`start()` could not bind its OS facility,
   so every `watch()` is refused) from a runtime one (watches are accepted but cannot be served
   until a pass succeeds).
3. File and Registry differ:
   - Retry wake. File's wake IS its retry: an open episode always has a retry scheduled, at the
     backoff deadline or at once if that deadline has already passed, so an otherwise idle worker
     still retries. Registry waits out its backoff, then re-derives its next wake from the
     obligations then due (`next_wake_locked()`, whose idle ceiling is one hour).
   - Deadline stamp. File stamps the deadline in `note_pass_outcome_locked()`, before the pass's
     off-lock tail (the log line and `FilePassWork` destruction), so it can already be stale when
     the wait is computed; `wait_timeout_locked()` treats a passed deadline as retry-due-now.
     Registry starts its backoff wait after its tail (since #4704 the same tail as File's: the
     pass-outcome line, then `SweepWork` destruction).
   - Completion passes. A File pass run for a real IOCP completion counts toward the three
     failures and is never throttled or absorbed; a successful one ends the episode.
   - Clearing `inert`. File clears it on the first successful pass with no equivalent of
     Registry's `if (core_)` check (Registry clears it only while its thread pool exists). The
     File worker is the only writer of `inert` while it runs, so a recovery cannot clear a
     boot-time inert.
4. Latency and limits, at the default 50 ms cadence:
   - `inert` flips after three consecutive failed passes, about 150 ms of backoff (50 ms, then
     100 ms) after the first failure, and clears at the next successful pass. After the cause is
     removed a quiet directory waits for the current backoff deadline, up to the 30 s cap; a real
     notification in any watched directory runs a pass at once.
   - A `watch()`/`unwatch()` control wake is absorbed until the deadline, but `watch()` does its
     work inline: a directory that resolves within `kFileCallerWaitBudget` (50 ms) has its
     directory read armed before `watch()` returns. What waits for a pass is that watch's
     establishment report and its health and Fault edges, a probe that outlives the budget, and a
     Deferred watch.
   - The `worker pass failed (consecutive #1)` and `recovered` lines are logged on every episode;
     the 1, 2, 4, 8 gate bounds only an unbroken one, so intermittent failure while directories
     churn is not rate-limited across episodes (#4686).
   - Only an exception that ESCAPES a pass counts: a throwing emit or fault sink is caught inside
     the pass, counted in `emit_failed`/`fault_failed`, and does not count toward the three.
   - Known limit: a retry pass that finds nothing due counts as a SUCCESS (it clears the failure
     count, the backoff and `inert`) even when the cause persists, for example when an admission
     attempt escalated past the deadline, or an unrelated real completion succeeds between
     failures. An alternating failure/success pattern therefore never flips `inert`. Movement of
     `pass_failed`, not `inert`, is the complete failure detector, and the #4606 harness must
     read it.
   - Known limit: a blocked or slow log sink stalls the mechanism's own worker thread while it
     runs, for as long as the sink blocks; only agent shutdown is bounded (the 20 s
     `ShutdownDeadlineGuard`, `kShutdownDeadlineGrace`, armed in `AgentImpl::stop()` and in
     `run()`'s teardown, ends in `hard_exit(4)` rather than an indefinite hang). Since #4704 the
     two mechanisms share one shape for their pass-outcome lines (`pass failed`, `failing
     persistently`, `pass recovered`): each is written OFF `mu_`, after the pass's bookkeeping
     has released the lock. File: `log_pass_outcome()` (`spark_file.cpp:2928-2943`), called
     after `lk.unlock()` at `:3303-3304` and `:3358-3359`. Registry: its own `PassOutcome` /
     `log_pass_outcome()` (`spark_registry.cpp:1888-1903`), called after the `lk.unlock()` on
     each of `sweeper_main()`'s two branches (recovery, and failure with the inert transition).
     Before #4704 those three Registry lines ran while `mu_` was held, so a stalled sink there
     also stalled every other `mu_` caller (`arm()`, `disarm()`, `apply_test_controls()`), a
     strictly worse consequence than File's; the fix mirrored File's shape, not a shared async
     primitive (ruled 2026-09-24). What a stalled sink still stalls, on either mechanism, is
     that worker's own loop (File: IOCP draining; Registry: the next sweeper pass and any
     re-arm or establishment report it owes) and the worker join in `stop()`;
     `arm()`/`disarm()`/`stats()` keep working for a stall on one of the three pass-outcome
     lines above. Registry's per-key `warn` lines (`fail_backend_locked()`,
     `resolve_probe_locked()`, `park_lost_locked()`) are still written under `mu_`; they were
     outside #4704's ruled scope and are tracked as #4999 (amended post-filing to correct a
     stale citation and add `publish_locked()`'s own two sites, 5 total). File has its own
     analogous per-key sites still under its own lock (e.g.
     `defer_backend_retry_locked()`/`fail_backend_locked()` reached from `watch_incarnation()`),
     tracked separately as #5002. Both issues are currently E6-capped by the same
     `prefer_spark_=false` compensating control and are likely superseded once #4666's async log
     hand-off is wired in as the process's default logger (#4666's own PR-2, already a blocking
     F14 precondition here for unrelated reasons) - re-check whether either issue's fix is still
     needed once that lands, rather than assuming per-site surgery is still required.
5. The `pass_failed`, `pass_failures_consecutive` and `pass_backoff_ms` counters are readable only
   through the test seam (`file_debug_counters_for_test`, Windows only). The operator-visible
   signals are the log lines `spark_file: worker pass failed (consecutive #N) - retrying in M ms`,
   `spark_file: worker failing persistently - file sparks reported inert until a pass succeeds`
   and `spark_file: worker pass recovered after N failure(s)`, and the exclusion of `file` from
   `yuzu.spark_mechs`. The fleet series cannot tell a boot-time inert from a runtime one, and no
   alert on `yuzu_fleet_spark_mechanisms` ships today. A per-OS, per-mechanism alert is an F14
   precondition: it needs a `for:` hold of at least two heartbeats so a self-clearing episode does
   not fire it, a paging alert wants at least 10 minutes, tuned on fleet data, and it compares
   `_reporting` with the one mechanism's series, not the sum over mechanisms (see
   `docs/user-manual/metrics.md`).

**R5.7 as implemented (rung 9c PR-6 item 2, 2026-09-19)**: the re-measurement this section
calls for is built and run. T2 is a new runtime-side log line at the LAST statement of
`GuardianSparkRuntime::commit_new_generation_locked()` - never
`subscription_establishment()` (that channel still has zero production callers) and never
`SparkEngine`'s own "armed" log (fires before the OS watch call even runs, exactly as this
section already says not to use it). Membership across repeated `#3990` diagnostic full_syncs
is decided by an explicit APPLICATION FENCE, not by timestamp order: `detach_all()` stamps a
monotonic `detach_epoch_` (bumped first, before any of its own mutation) and logs it in a new
`Guardian spark: detach_all complete (epoch=, incarnation_floor=, ...)` line as its LAST
statement; every T2 line then carries that epoch, so a stale in-flight commit from a PREVIOUS
full_sync (which can land between the new `full_sync cleared` line and `detach_all()`, since
both run under `registry_mu_`, not the engine's own `mtx_`) is rejected by epoch identity
rather than by an insufficient timestamp check - a real gap an Astra adversarial review found
in this item's own first design round, before implementation. `--spark-disable` never
constructs `spark_runtime_` at all (`wire_spark_engine()`'s `spark_disabled_by_config` branch
returns before that point) - legacy needs no fence in the first place, since its arms are
synchronous on the same thread as T0/T1. Result: Phase B (baseline re-deploy) reached a
pre-registered PASS on the current NonWaiting attach model; Phase B2 (bare rule-create,
`#3990`'s own literal shape) is FAIL-RELIABILITY - a genuine spark arm failure on repeat 3
(`applied=61, failed=1`, one rule) was initially misclassified as an instrument-invalid void by
a driver bug (`/adversarial-review` found and fixed same-session; see the run doc's own
"Correction" note under its Phase B2 section) and, once corrected, breaks the reliability gate
outright regardless of the separate 2/3 floor miss. Full detail: `docs/spark-rebuild-baselines/
3990-fullsync-blackout-run.md`'s own "R5.7 T2 re-run results" section; `docs/spark-flip-gate.md`'s
`#3990` entry for the flip-gate framing.

## 7.7b split — pre-cutover hardening (settled 2026-07-18)

7.7b was first planned as one PR folding the #2237 send-path items and #2238 test
seams into the flip. Three independent reviews — Sol/Codex (opine), Claude
(adjudication, every claim verified against code), and Fable (advisor) — converged on:
**the flip is unsafe in one PR; split into an inert-hardening PR-1 and a thin-cutover
PR-2, with the `prefer_spark` flip as the last commit either way.** Every finding below
was verified against the worktree at `origin/dev` (b09cdd19).

**"Inert" is placement-inert, not behaviour-inert.** PR-1 changes *no* detection or
enforcement *placement* (`prefer_spark` stays false), but it is not a no-op: the shared
builder refactors the live legacy emit path (`guardian_engine.cpp:500`), the
`apply_rules` firewall changes live per-push failure semantics (`guardian_engine.cpp:326`),
and the telemetry ships new heartbeat tags every beat. State this in the PR so a gate
reviews it as a live-path change, not a rubber-stamp of a false "inert" premise.

### The cutover-blocking finding (Fable M1): `guard.unhealthy` re-emission flood

The read-failure path calls `unhealthy()` **unconditionally** on every `!read.known`
(`guardian_rule_eval.cpp:63/111/132`) — there is **no into-unknown edge guard**; only
*recovery* is edge-forced (`pack()`'s `recovered` bit). `build_entries` then pushes a
**fresh-`event_id`** health entry on every `Unhealthy` (`GuardianSparkRuntime::build_entries`, `guardian_spark_runtime.cpp`).
An unhealthy rule stays in `pending_initial` (`:357`), which the priority lane re-sweeps
every ~5 s (`ConvergenceScheduler::Config::priority_poll_ms`, default 5000 - the
`guardian_convergence_scheduler.hpp:60` line-ref this paragraph originally cited has
since drifted; cite the symbol, not a line number, for exactly this reason). Net: one
mundane unreadable target (ACL-denied file, missing hive path) emits **~17 k
`guard.unhealthy`/day/rule/agent**, each its own server-side insert transaction. Legacy
has no health stream, so this traffic class switches on **at the flip** — a self-inflicted
fleet ingest DoS. **The `guardian_rule_eval.cpp:15` comment "edge-triggered
guard.unhealthy" is false.** Fix (send-path, flag-gated inert → PR-1, flip unsafe
without it): transition-edge health emission (emit on the false→true unknown edge + a
slow periodic refresh only) + evict never-Known rules from the 5 s priority lane to
their normal lane cadence.

**SUPERSEDED 2026-08-18 (F11, #2298) - the fix above has since shipped, in two parts,
and the ~17k/day figure is the PRE-fix number.** Transition-edge emission shipped first
(`b30e93cfd`, 2026-07-20, "edge-guard into-unknown to stop unhealthy-event flood") -
this alone removed the per-sweep flood this paragraph describes; every committed
repeat-Unknown became silent (edge-only, `unhealthy_suppressed_`) rather than a
fresh-`event_id` re-emission on every ~5s sweep. F5 (PR #3005, merged 2026-08-11) then
*added back* a deliberate, bounded, nonzero steady state on top of edge-only silence:
`errored_refresh_ms` (default 300s) re-emits a stale-but-still-errored rule so a
lost/coalesced edge cannot leave the server's view stale forever, and
`pending_demote_sweeps`/`pending_demote_ms` evict a never-Known rule off the 5s
priority lane onto its normal type-lane cadence - exactly the mechanism this
paragraph's "Fix" bullet called for. **F5 did not reduce the ~17k/day figure - edge
emission already had, to zero steady-state wire traffic; F5 set the new nonzero
ceiling on top of that silence, by design (a lost-edge backstop, not free).** The
measured ceiling (fake-clock Catch2 cases at production Config defaults,
`tests/unit/test_guardian_spark_runtime.cpp`, "F11 flood: ..." - see
`docs/spark-rebuild-baselines/f11-flood-measurement-run.md` for the full derivation and
a live-rig confirmation): **1 edge + 288 refreshes/day/rule/agent** on a 60s-cadence
lane (service/registry - refresh recurs exactly every `errored_refresh_ms`, first
landing at t=300s post-edge), **1 edge + 180 refreshes/day/rule/agent** on the 600s
file lane, accounting for the scheduler's default +/-20% jitter (every post-demotion
sweep refreshes, since even the jitter-minimum 480s spacing already exceeds the 300s
floor; 144/day is the exact-no-jitter figure, 180/day is the true production ceiling
- corrected 2026-08-18 after an adversarial review caught the original doc's false
"jitter never shortens a sweep" claim). Both corrected figures are roughly 60-95x
below the pre-fix ~17k/day this paragraph documents.

**M1's fix covers the health (Unknown) stream only.** This paragraph's flood analysis and
fix scope never mention the Known/drift path - `guardian_emit_decider.hpp`'s `decide_emit`
has no equivalent terminal-state dedup on the Drift branch, so a persistently-drifted rule
still re-emits `drift.detected` on every convergence sweep (no fix landed for it here).
Tracked as delta-registry row D3 and issue #3388 (F12, #3386) - ruled 2026-08-23 (interim
fix: a sweep-cadence-aware debounce default), fix drafted but not yet merged; see D3's
own Ruling cell for the current state.

**Landed (PARTIAL) 2026-07-20, commit `b30e93cf`:** the **transition-edge emission** + a
**counted, sparse-heartbeat suppression signal** (`yuzu.guardian_unhealthy_suppressed`) shipped.

**Landed (F5, #2298):** (a) the **slow periodic refresh** - `GuardianSparkRuntime::Config::
errored_refresh_ms` (default 300 000 ms; 0 disables) re-emits `guard.unhealthy` for a still-
errored rule at that cadence, carrying the CURRENT read-error detail (not the stale first-
episode string), counted on its own `yuzu.guardian_unhealthy_refreshed` heartbeat tag - so a
lost/coalesced edge can no longer leave the server's errored view stale forever
(unhappy-path UP-1/2/4/11 closed); and (b) the **priority-lane eviction** -
`pending_demote_sweeps`/`pending_demote_ms` (defaults 12 sweeps / 120 000 ms) demote a
still-pending-initial rule off the 5 s priority lane to its normal type-lane cadence
(service/registry ~60 s, file ~600 s) once EITHER threshold is crossed on a
Convergence-reason Unknown READ (committed or outbox-rejected; the elapsed-time arm is
checked on every Unknown pass regardless of reason or enqueue outcome - #2992), counted
on `yuzu.guardian_priority_demoted` - closing the *read* flood (UP-6) the edge-only fix
left open. Demotion is per-rule, not per-key (a key with a
mixed demoted/non-demoted pending set still pays the read cost via its non-demoted sibling);
the demoted rule keeps converging (and keeps re-arming errored_refresh_ms) at the slower
cadence, so (a) backstops (b)'s resulting wire staleness. Both land in
`guardian_spark_runtime.{hpp,cpp}` only - zero scheduler code change (the scheduler's
existing type-lane sweeps already re-drive a demoted key's `evaluate_key`).

Still OPEN and still gating the `prefer_spark` flip (folded into #2298 gate 6):
(c) **DONE (F6).** The **server-side rollup/consumer** for the suppression/refresh/demotion
tags now exists two ways: an unlabelled fleet-sum gauge family (`yuzu_fleet_guardian_unhealthy_
suppressed`/`_refreshed`/`_priority_demoted`, `guardian_health_fleet_tags.hpp`, mirroring the
guardian-journal pattern), and `/status.errored_rules` / `/status/{agent_id}.errored_rules` are
now real, derived from the `guardian_agent_rule_status` census (the same no-TTL current-state
view the dashboard reads) rather than the former hardcoded placeholder `0`. `compliant_rules`/
`drifted_rules` remain placeholder `0` - full status ingest (`action=="status"`) is a separate,
later rung. **(d) the four-artefact egress for
`arm_race_unwatch_failures_total` AND `disarm_unwatch_failures_total` (#2270)** - both heartbeat
tags ship and both keys are registered in `spark_fleet_tags.hpp`, but no rollup consumes either,
there is no `docs/user-manual/metrics.md` row and no alert rule, and no REST route or dashboard
renders raw `status_tags` - so an orphaned OS watch is not fleet-detectable and is not per-device
queryable either; the value reaches the server and is read by nothing. Same class as (c) and same
reason it matters: the residual either counter reports is a leaked watch in the agent's sole
detection primitive, and reclamation is mechanism-dependent, not simply OS-dependent - a File
watch (Windows-only mechanism) is never reclaimed short of a process restart, so for that
mechanism the cost is permanent and cumulative rather than self-healing; a Service watch (Linux or
Windows) is reclaimed the next time `stop()` runs; a Registry watch (Windows-only mechanism)
cannot fail this way at all. The census edge-record still depends
on the sole production `attach_rule` hardcoding `emit_compliant_edge=true` - do NOT sever that.

### PR-1 hardening items (commit order 1→2→3→4→7→5→6→9→8)

1. **Shared drift-event builder.** Extract `apply_drift_to_event`; legacy build at
   `guardian_engine.cpp:500`, spark at `guardian_spark_send.cpp:43` — extract, not just
   a cross-check test (a cross-check leaves two drifting impls).
2. **OutboxEntry guard_type/rule_name for Health/Lifecycle** (empty today,
   `guardian_spark_send.cpp:76`).
3. **attach_rule + live `apply_rules` exception firewall (Fable M3 — harder than #2237
   item 2).** `index_->add()` runs *before* `rollback.fn` is assigned
   (`guardian_spark_runtime.cpp:108` vs `:129`); a **throwing** `arm()` leaves a ghost
   `by_rule_` entry → the next sibling attach's `keys_.at(key)` throws `out_of_range`
   (`:143`) through the un-firewalled `apply_rules`. And `SparkKeyRuleIndex::add`'s
   emplace-throw (`spark_key_rule_index.hpp:92`) leaves an *empty set* → a false 0→1
   edge on the next add → double-arm → **untracked live subscription leak on a success
   path**. Requires a strong-guarantee/noexcept `SparkKeyRuleIndex::add` + fault
   injection of a throwing `arm()`; wrapping callers is not enough.
4. **Drain-without-lock.** `GuardianSparkRuntime::drain()` holds `outbox_mu_`
   (`:441`) across `send_guardian_outbox_entry`'s synchronous gRPC `Write()`
   (`agent.cpp:2700`); the stall cascade is `Write` → `outbox_mu_` → `evaluate_key`
   commit under `registry_mu_` → `apply_rules` under engine `mtx_` → heartbeat/status.
   Restructure to peek/copy → unlock → send → conditional-remove by `event_id` alone
   (globally unique per enqueue — `agent_id`+boot-nonce+`rule_id`+ms+seq — so it pins the
   exact sent node with no separate generation check; as implemented, `pop_front_if`).
   Sub-contracts: `drain_once()` is public/off-thread-callable → keep a drain-in-progress
   guard; the lifecycle log has no index (`guardian_outbox.hpp:294`) → conditional-remove
   needs a front-`event_id` check; a coalesce during the unlocked send replaces the node
   with a new `event_id` (`:151`) → remove-by-`event_id` handles it, write the test.
   **Drain order fix (M6):** send lifecycle *before* compliance (currently `:443-444`
   sends compliance first) so a rule's "armed" audit entry never arrives after its first
   drift event.
5. **Two-count executor + physical-orphan ceiling (Fable M4).** Before rung 9c PR-1 the
   inflight counters freed only when the worker payload was destroyed inside the thread
   trampoline (`~TicketCore`, `guardian_io_executor.hpp`), so `kMaxProcessIoWorkers=10` was a
   real physical bound; that is still true for `run()` workers, but `submit()` (R5.1) frees
   its quota slot at `fn()` return, so the physical bound on an instance is now
   `kMaxAliveIoWorkers=20` (the alive-worker ceiling below), not the quota sum. Freeing the *logical* admission slot on the run() deadline
   requires a **separate physical-orphan ceiling strictly > sum(quotas)** (else 10 wedged
   orphans re-create the exact cross-class starvation R3 eliminated) + same-key
   single-flight retained until orphan exit + an exactly-once logical-vs-physical
   decrement handshake (a double-decrement inflates quota). Pin the ceiling **value** in
   the PR description (R3's own lesson).
6. **F3 KV marker** (R4): best-effort marker persisted before `hard_exit()`, read/reported/
   cleared next boot.
7. **Lifecycle-audit durability.** `GuardianLifecycleLog` is in-memory, reject-new+count-
   on-full, never-evict (`guardian_outbox.hpp:263`), and the send drops on `Write()==true`
   (queued ≠ acked) → at-most-once + capacity-lossy + crash-lossy = **not audit-grade**.
   Compliance drift stays documented best-effort telemetry; **lifecycle
   (`guard.armed/disarmed/errored`) becomes durable**: a retention-bounded journal +
   replay on boot **and every reconnect**, leaning on the server's existing `event_id`
   idempotency (PK rollback at `guaranteed_state_store.cpp:670` absorbs replay dups;
   boot-nonce'd `event_id`s). Delete-on-`Write()==true` alone re-inherits the hole — the
   entry leaves the journal only after replay-safe confirmation. **Substrate: reuse
   `KvStore`/`kv_store.db`** (already open, WAL, Guardian writes rules there) — not a new
   file. Constraints: `get()` truncates at NUL (`kv_store.cpp:178`) → payload is JSON not
   raw proto; no txn API, each `set()` is a commit+fsync → a 500-rule `full_sync` = ~1000
   fsyncs → **batch/persist-per-push, not per-entry**; do **not** journal inside
   `enqueue_lifecycle_locked` (under `registry_mu_`+`outbox_mu_`) or it recreates the
   coupling item 4 removes — journal at the engine layer under `mtx_`.
8. **Test seams + TSan** (#2238): the re-arm-throw degrade fault hook, the prefer_spark
   thread-start introspection, and a concurrent start-drain-then-stop TSan test with the
   real `this`-capturing send callback.
9. **R4 telemetry as a producer+consumer contract**, not just agent tags: each field
   needs an agent writer + `agent_registry.cpp:1323` server parser + family-clear +
   reset-handling + bounded labels + current-vs-cumulative semantics + a writer/reader
   cross-pin test; both outbox domains reported separately; the F3 marker included. The
   `SparkFailed`-prevalence alert ships here reporting the inactive posture, and needs a
   **paired `reporting`-drop condition** (a correlated crash-loop manifests as
   `yuzu_fleet_spark_reporting` dropping, not `failed` rising, because a fast loop dies
   before heartbeating).

Also folded into PR-1: the **R2 `unsupported` terminal state + rung-8 telemetry +
reconcile-test rewrites**. Verified flag-gated inert — the whole Arm/Unsupported branch
is under `if (prefer_spark_ && Available)` (`guardian_engine.cpp:845`; the legacy
fallthrough it replaces is `:882-885`) and the reconcile tests already construct
`prefer_spark=true` (`test_guardian_engine_spark_reconcile.cpp:160`). Moving it here
pulls the largest piece of unspecified new semantics off the flip PR.

### PR-2 (thin cutover)

`prefer_spark = !cfg_.spark_disable` (`agent.cpp:~579`, R1) as the **final commit**; the
**intentional-delta registry** (R2 consequence 2 — pulled forward from rung 10 because
7.7b changes the behaviour parity classifies; **shipped ahead of the flip, F12/#3386:
`docs/spark-legacy-delta-registry.md`**); **production-order cached-KV
restart/upgrade tests** (the current fixture runs `start_local()` before
`wire_spark_engine()`, the reverse of production `agent.cpp:962` vs `990`, with an empty
KV — it masks the rehydration path); parity + resource + **3-OS/gateway** evidence
(Linux File/Service/inert-systemd; Windows File/Registry/Service + shared-watcher
refcount; macOS all-unsupported + `--spark-disable` legacy-restore; slow/stalled-`Write`;
long pre-connect/outage; reconnect-during-drain; a server-side reconnect-storm
events/sec ingest figure); and the **grep-enumerated stale-prose sweep** (`"legacy
IGuard"`/`"unaffected"`/`"remediated"` — false after the flip at `guardian_engine.cpp:264`,
`agent.cpp:934-984`, `guaranteed-state.md:344`).

### Two decisions settled 2026-07-18

- **M2 — one-legged recovery.** `event_state_from_type` maps `guard.unhealthy`→errored
  but `guard.healthy`→`nullptr` (`guaranteed_state_store.cpp:64-67`); recovery clears
  `errored` only via a paired *compliance* event, which works solely because the prod
  attach hardcodes `emit_compliant_edge=true` (`guardian_engine.cpp:861`). **Ruled:** add
  a **cross-pin test** in PR-1 that fails if any attach uses `edge=false`; the real
  server-side `guard.healthy` census mapping lands with the health surface at **rung 4**.
- **Flap detector** (design-mandated, §Kill-switch / F3 notes): **deferred to rung 11**
  alongside the `SparkFailed`-prevalence alert (both server-side fleet-signal work),
  recorded here so the deferral is explicit rather than silent.

## Consumer architecture

Guardian becomes a SparkEngine client. The seam:

- **One queued consumer.** `GuardianEngine` calls `register_consumer(name,
  handler, queue_cap)` (`SparkEngine::register_consumer`'s declaration) once at
  startup, and `arm(consumer, SparkSpec)` (`SparkEngine::arm`'s declaration) once
  per enabled rule — replacing the per-rule guard
  construction in `start_guard_for_rule_locked()`. Arming is deduped by
  `spark_key`, so two rules watching the same unit/key share one watcher.
- **Guardian keeps its meaning layer.** Everything that made a guard *Guardian's*
  — assertion evaluation, `GuardDrift`, event-debounce/`collapsed_count`,
  compliant-edge suppression, and `emit_guard_event` → `GuaranteedStateEvent`
  (event-id minting, `event_type` mapping) — moves out of the per-guard classes
  into the **consumer handler**, operating on `SparkEvent`s. The `IGuard`
  classes' pure decision logic (`service_classify_edge`, `systemd_decide_emit`,
  the File hash-compare, the Registry value-compare) is lifted verbatim; only the
  detection plumbing underneath it is replaced.
- **Event payloads.** Service `SparkEvent`s carry `ServiceSparkData{ServiceRunState}`
  (`spark.hpp:189/199`) — the consumer reads run-state directly. File and Registry
  events are `std::monostate`; the handler re-reads the on-box state (file hash,
  registry value) to evaluate assertions.
- **Fault channel.** `SparkFaultFn` reports (a watcher that armed then went deaf —
  bus/SCM collapse) map to the existing `guard.unhealthy` event type
  (`event_state_from_type` → census state `errored`) and to the per-rule health
  field (§Health surface). The fault callback must be **non-blocking and must
  never call Guardian's meaning layer inline** on the mechanism thread (see
  §Enforce path, #2014 corollary) — it enqueues to the consumer like any event.

### spark_key → rule index and shared-watcher lifetime

Dedup-by-`spark_key` creates a structural difference from today's one-guard-per-rule
model that the meaning layer must absorb. A `SparkEvent` carries only its `key`
(`spark.hpp:202`) — no `SubscriptionId` or rule_id reaches the handler — and N
rules with different assertions may share one watcher. The consumer therefore owns
a **`spark_key → {rule_id…}` index**, populated at `arm()` and consulted on every
event/fault delivery to resolve which assertion(s) to evaluate and which rule's
remediation to run. Shared watchers are **refcounted**: disarm/redeploy of one
rule decrements; the underlying `disarm()` fires only at zero, so disarming rule A
never blinds rule B on the same unit. (Register-of-record for UP-11 / happy-path
Issue 2.)

### Re-arm and initial-evaluation contract

Today's continuity on restart comes from each `IGuard` doing an **explicit initial
evaluate at arm time** — `guard_file.cpp` `eval_now()`, `guard_registry.cpp`
`reconcile()` — so a rule that drifted while the agent was offline is caught (and,
if enforce, remediated) the instant the guard starts, with no external trigger.
The mechanisms do **not** uniformly reproduce this, and the two failure modes are
opposite:

- **File / Registry are edge-only.** `spark_registry.cpp:197` states outright a
  registry spark "fires on a CHANGE, so there is no initial emit"; the File
  mechanism only emits from an actual `ReadDirectoryChangesW` completion. Without
  intervention a pre-existing offline drift is **invisible and unremediated until
  the next on-box change** — a silent regression from today. (happy-path Issue 1.)
- **Service re-emits initial state on every arm** (`spark.hpp:186-188`). A
  `start_local()` re-arm therefore re-fires the current run-state as a fresh edge,
  risking a **duplicate GuardDrift and a re-enforce storm on every restart**.
  (architect S1.)

Resolution — the consumer owns an explicit re-arm contract, not the mechanism.
For **every** rule, at arm time the handler runs a **synthetic initial evaluate**:
re-read on-box state (file hash / registry value; for Service the arm-time seed
event `spark.hpp:186-188` supplies it) and run the full assertion → enforce path.
The `__guardian__` cache is consulted **only** to suppress a duplicate *event
emission* / reset `collapsed_count` — it does **not** short-circuit the assertion
evaluation. This keeps Service identical to File/Registry: a rule whose cached
terminal state was itself a persistent unremediated drift (a prior enforce failed,
or the rule is observe-mode) is **still re-evaluated and re-enforced** on restart,
never silently suppressed because "the state matches the cache" (architect Gate-8).
The synthetic initial evaluate is **per-rule and unconditional** — when rule B arms
onto an already-armed shared watcher the mechanism `arm()` is a dedup no-op, but the
consumer still runs B's initial evaluate, so B's offline drift is never missed
(the engine holds the watcher refcount via `sub_keys_`/`armed_`; the consumer's
`spark_key→rule` index drives the per-rule evaluate).

**Cache-read failure is fail-closed-per-rule.** If the `__guardian__` cache is
unreadable, format-skewed, or a rule's `arm()` returns a typed rejection mid-loop,
that rule is marked `errored` (surfaced on the health surface) and re-arm continues
with the next rule — never a silent skip that leaves the rule armed-but-unevaluated,
never a whole-startup abort (UP-4). `start_local()` re-arms sparks from the same
`__guardian__` KV cache; a cross-format round-trip test gates the cutover. The
"identical continuity" property is a property of this contract, verified as a
rung-2 parity assertion — not assumed from the mechanism's edge behavior.

## Enforce path (ADR-0021 Decision 3 amendment)

**Once the rung-3 enforce cutover lands, all Guardian enforce runs on the queued-consumer thread, not inline** (rung 2 is observe-only — see §Kill-switch for what enforces during the rung-2 window).

Today, service remediation (`StartServiceW`/`ControlService` on Windows; systemd
is observe-only today) runs synchronously on the guard's own per-unit watch
thread — a blocking SCM/systemd call is milliseconds-class, and it only blocks
*that unit's* detection. On the shared mechanism a blocking call on the watcher
thread would stall detection for **every** unit that mechanism multiplexes — the
exact hazard tracked by **#2014** (a blocking inline consumer wedges the Windows
IOCP worker's reap loop, refusing all new file watches fleet-wide).

Decision: Guardian enforce is a **queued** consumer. The mechanism watcher emits
the edge; the Guardian consumer thread performs remediation. This resolves #2014
by policy — **no blocking inline consumers on any mechanism**, and the emit-enqueue
and `SparkFaultFn` paths are non-blocking and never re-enter the meaning layer on
a watcher thread. Latency class is unchanged or *better*: today's Windows enforce
already blocks its own detection thread under an enforce storm, whereas the queued
path keeps detection flowing while remediation drains separately. Resilience
(`ResilienceStrategy::decide`), enforce-gating, and the ACCESS_DENIED query-only
fallback are preserved in the consumer.

**Enforce is never *silently* dropped.** The queued tier drops **oldest** on
overflow (`kDefaultQueueCap=1024`) — for the *observe* stream that is acceptable
lossy telemetry, but a silently-dropped **enforce** edge is a skipped remediation,
a compliance regression versus today's never-drop per-unit thread. Guardian
separates a **bounded enforce lane** from the observe lane with a precise overflow
contract (not literally unbounded, which would risk agent-RSS OOM under an enforce
storm — the storm today's per-unit thread survives): on enforce-lane pressure the
affected rule flips to `errored` and emits a queue-drop fault (§Health) — a **loud,
operator-visible** degradation, never a silent oldest-drop. So an enforce edge is
either delivered or converted to a visible `errored`, never discarded unseen.
(UP-3, sre F1, security-guardian, unhappy-path Gate-8.)

**Per-`spark_key` FIFO delivery + bounded coalesce (enforce correctness, not
telemetry).** Edges for one `spark_key` are delivered to the consumer in FIFO
order; a burst is **coalesced to the latest terminal state per key**, never
reordered. This is load-bearing for Service: `service_classify_edge` depends on
running→stopped→running ordering, and a reordered stop-then-start under queue
pressure could re-enforce a stale run-state (the dequeue re-gate below re-checks
local deployment/enforce-arm state, not *edge recency*). Coalesce-to-latest also gives the enforce
lane something to collapse against under a storm, bounding growth. (UP-12.)

**Enforce is re-gated at dequeue, not enqueue.** An edge can sit queued while the
rule is undeployed, its Baseline un-pushed, or its scope revoked. The agent
consumer re-checks the gate **at dequeue** against an **in-memory snapshot of the
deployed-rule set** (rule_id → `enabled`/`enforcement_mode`) that the consumer
maintains, refreshed write-through on every `GuaranteedStatePush` (the push write
and the dequeue read are synchronized under the consumer's `mtx_` — the discipline
`apply_rules` already uses — but the lock is read → copy the enforce decision →
**released before** the blocking SCM/systemd call, never held across it, or a slow
remediation would head-of-line-block the very disarm push meant to stop it; the
resulting sub-ms read-to-enforce TOCTOU is the same residual window as approval
withdrawal below). **This is an
in-memory read, never a per-edge SQLite hit:** the `__guardian__` KvStore is the
durable backing for the snapshot (persisted **before** the in-memory update — the
same persist-before-arm order `apply_rules` uses, so a crash rebuilds from the
persisted set, never a stale snapshot; read once at start/re-arm for restart continuity),
never queried per dequeued edge — a synchronous DB read on the enforce-dequeue path
would, under an enforce storm, let `__guardian__` lock/disk latency throttle the
consumer and inflate `queued_dropped_total`, converting an *authorized* enforce into
a spurious "loud degradation" (sre, UP-6). A stale queued edge for a rule the
snapshot no longer shows as deployed-and-enforce-armed is dropped, never enforced.
If the snapshot cannot be built at start/re-arm (corrupt/format-skewed `__guardian__`),
the affected rule fails **closed** — marked `errored`, never enforced off a stale or
absent snapshot, never silently skipped (UP-4, mirroring the arm-time posture above).

The server-side gates — `deployed_member_rule_ids()` (deployed snapshot),
`dangerous_enforce_in_spec`, and the Decision-9 digest-bound approval — are validated
**at push time on the server** (all three symbols are server-only; `agents/` links
none of them), and their result is what the pushed rule set encodes. **Approval
withdrawn *after* the last push** reaches the agent only via a fresh
`GuaranteedStatePush` that disarms the rule (server-mediated) — the pushed
`GuaranteedStateRule` carries no approval digest (its integrity fields are
`enforcement_mode` + a *deferred* `signature` only), so the agent **cannot** re-check
post-push approval-withdrawal at dequeue without a new proto field. **Trigger
contract (LOAD-BEARING, rung 3):** because `Push` is a human-gated step distinct from
`Write` (Baseline model), withdrawal is NOT auto-propagated — the enforce-cutover rung
MUST make approval-withdrawal *enqueue* a disarm push that **reconciles the agent's
armed set + snapshot** — today only a `full_sync` reconciles (it calls
`stop_all_guards_locked()` then re-arms); a *delta* `enabled=false` currently
persists the rule but `apply_rules`→`start_guard_for_rule_locked` re-arms it
unconditionally (no `enabled()` gate on the delta path), so the `enabled=false`
route needs a **new per-rule teardown-on-delta in `apply_rules`** at this rung.
Either way it must not merely re-gate
future dequeues (a rule with a live watcher but no queued edge would otherwise enforce
on its next drift). Until that lands, the residual window (a de-authorized rule keeps
enforcing until the next push/reconcile) is the **same window today's per-rule
`IGuard` already has** — not a Stage-2 regression — but unbounded absent the
disarm-on-withdrawal contract. The permanent close (an on-agent, dequeue-time approval
check) needs the deferred approval-digest proto field, tracked as a Guardian-wide
follow-up issue; adding it now is **out of scope for Stage 2** — the wire stays
byte-compatible (§Scope). (security-guardian, architect, compliance, unhappy-path
UP-1/2/13.)

**ADR-0021 Decision 3 wording** described the inline tier as the home of Guardian
enforce with a "µs-bounded" guarantee. As shipped (spark.hpp header, owner
decision 2026-07-06, #1938) the tier is **median-µs, not hard-bounded**, and
Stage-2 enforce is **not** an inline occupant. The amendment restates the inline
tier as **reserved for future genuinely-µs enforce**, admitted only behind the
narrow enforce-capability handler signature (no dispatcher, no plugin host — a
plugin call is a compile error, per Decision 3) *and* watchdog-histogram evidence
that a given enforce action stays inside budget. Registry write-back is the
plausible first candidate; it is **not** promoted in Stage 2.

Pre-Stage-3 dependency, **UPDATED 2026-09-13**: File's `watch()` blocking for its OS-call
duration under the ops lock is now closed (PR-B2, landed). Service's SCM open/notify running
head-of-line on its worker is now PARTIALLY closed (**PR-B3, merged 2026-09-12 as PR #4302**,
`OpenServiceW` isolated onto a probe-only lane; `NotifyServiceStatusChangeW`'s registration
stays on the mechanism thread by Win32 thread-affinity requirement, an accepted residual)
(`mech_ops_mu_by_type_`'s member comment, corrected in PR-B1; the earlier
"entirely UNCHARACTERISED" wording is superseded for all three mechanisms now, whose
establishment latencies are measured in
`docs/spark-rebuild-baselines/stage2-watch-establish-latency.md`, including the PR-B3 addendum's
end-to-end Service figures - ~65ms arm-to-first-observed-state, dominated by
`kServicePollCadence`, not OS call cost); #2011's per-mechanism-type lock (rung 0) removes only
*cross-mechanism* coupling. Gate rung 3 satisfied - PR-B3 landed 2026-09-12 (the measured
ceiling this paragraph asked for now exists for all three mechanisms). (architect S4.)

**#2233 item 3 (landed)** bounds the wall-clock a *caller* of `GuardianSparkRuntime`
waits for one File/Registry/Service arm/disarm - a dedicated `GuardianIoExecutor`
instance runs the actual backend call off `registry_mu_`, bounded by
`Config::backend_op_deadline` (5s default) - up to 2x that on a same-key redeploy
of an already-armed rule (the prior generation's disarm and the new arm run
sequentially, each individually bounded, not concurrently). `GuardianEngine::apply_rules()` and
`GuardianEngine::stop()` no longer wedge on a hung watch; a hung watch degrades to
one rule left un-armed and retried, while every other rule and shutdown proceed.
This does **not** restructure `mech_ops_mu_by_type_` itself: a hung SCM/Registry
call inside `backend_->arm()` can still block a sibling arm/disarm of the SAME
mechanism type at the `SparkEngine` layer until this caller's own deadline elapses.
The Pre-Stage-3 dependency above is otherwise unchanged by this landing.

**#3816 (landed)**: item 3's bounded-wait deadline left a residual - a backend arm
that succeeds just after its caller gives up can mint a live subscription nothing
tracks. `GuardianIoExecutor::run()` now delivers every result `fn()` returns
normally exactly once, to either the caller's return value or an
`on_abandoned(T&&)` callback (a thrown `fn()`/`WorkerThrew` has no `T` to
deliver and correctly reaches neither), so
`GuardianSparkRuntime`'s arm consumer can disarm a late success instead of leaking
it; the state reader needs no callback (a late read is wasted work, nothing
escapes). See `docs/spark-flip-gate.md` §3 row 3.

**#2012/#3840 PR-B1 (landed, Registry only)**: the Registry mechanism's `watch()` now
reserves under its own lock, runs the key open / notify / nearest-ancestor walk on a
detached F3-counted worker, waits at most `kRegCallerWaitBudget` (50 ms) on the
control path and otherwise publishes the probe to the mechanism's own sweeper thread;
`unwatch()` hands the blocking callback drain to a detached worker and returns in
microseconds. The per-type lock hold for Registry is therefore bounded by that budget,
which also removes the #4181 same-type reentrant disarm deadlock on the Registry path
(the issue stays open pending File/Service confirmation - both now confirmed clean, see
the PR-B3 entry below, but #4181 itself closes at merge, not here). Costs recorded in
`docs/spark-legacy-delta-registry.md` D12: a consumed Target-mode notification is two
emit submissions (immediate + synthetic on re-arm commit), an establishment that misses
the 50 ms health grace produces a Faulted/Recovered pair, and an Ancestor->Target
appearance is emitted at commit rather than inline. File (PR-B2) and Service (PR-B3)
remain the open half of this dependency.

**#2012/#3840 PR-B2 (landed, File added)**: the File mechanism's `watch()` now follows
the same shape as Registry above - reserves under its own lock, runs the discovery
probe (target open / nearest-ancestor walk) on a detached F3-counted worker, waits at
most `kFileCallerWaitBudget` (50 ms) on the control path and otherwise publishes the
probe to the mechanism's own IOCP-driven sweeper. `unwatch()` was already O(1) (no
blocking callback drain to hand off, unlike Registry). The #4181 same-type reentrant
disarm deadlock is closed on the File path; Service (PR-B3, below - merged 2026-09-12,
closing #4181 itself) was the last piece needed. Costs mirror Registry's: a consumed target completion
is covered by a synthetic resync fire rather than redelivering the lost notification, a
shared ancestor's fan-out uses whole-batch retry (never per-key debt, Dave's decision #4),
and an Ancestor->Target appearance is emitted via the same commit-time resync path.

**#2012/#3840 PR-B3 (merged 2026-09-12 as PR #4302, Service added, closes the series)**: Service's
`watch()`/`unwatch()` needed no restructuring - unlike Registry and File, they were
already O(1) queue pushes before this series (confirmed by direct code read and by
`spark_mechanism.hpp`'s own mechanism-contract comment; #3840's issue text, originally
wrong about this, has been corrected in place). The actual gap: `OpenServiceW`
establishment ran head-of-line on Service's single dedicated mechanism thread, delaying
every *other* watched service's establishment, retries, and APC dispatch while one was
in flight - a stall on that shared worker thread, not on the engine-wide per-type lock
Registry/File had. PR-B3 isolates `OpenServiceW` onto a probe-only `SparkDetachedLane`,
mirroring Registry's probe half. **Deliberately no drain-lane twin**: the design
rationale was that Service's teardown (`CloseServiceHandle` + a zero-timeout
`SleepEx(0,TRUE)` APC pump) doesn't have Registry's documented cross-thread
reclamation-ownership problem - the thing a drain lane would exist to isolate.

**Corrected 2026-09-13**: an earlier version of this paragraph overstated that
rationale as "is not a blocking call." The real disclosure (governance review,
round 3) is more cautious: `CloseServiceHandle` is the same LRPC transport as
`OpenServiceW` and is UNVERIFIED either way - no evidence found that it cannot
itself hang under the same wedged-SCM condition #3840 exists to fix.
`CloseServiceHandle` and `NotifyServiceStatusChangeW`'s registration both stay on the
mechanism thread regardless (the latter by Win32 thread-affinity requirement, not a
shortcut; the former by this design decision).

The #4181 same-type reentrant disarm deadlock does not apply to Service at all - and
this argument no longer rests on the retracted "not a blocking call" claim above: its
`unwatch()` releases `mu_` before teardown runs, so the disarmer is never blocked
holding the per-type lock waiting on a callback the way the deadlock's diagram
requires (confirmed by direct code read; only Registry ever had that shape, contrary
to this design's own earlier assumption that Registry and Service shared the hazard).
This holds independently of whether `CloseServiceHandle` itself can hang - a
dedicated subprocess-boundary T6-analogue regression test was added anyway, as
insurance. End-to-end establishment latency (arm to
first observed state) measures ~65ms on real hardware, dominated by
`kServicePollCadence` (50ms) rather than OS call cost - see
`docs/spark-rebuild-baselines/stage2-watch-establish-latency.md`'s PR-B3 addendum.

## Health / status surface — the #1939 checklist

Per ADR-1005 (headless platform) a new capability lands on REST **and** MCP, or
records an exception. The spark/guard health signal lands on both, carries the A4
error envelope and A2/A3 discovery metadata (enumerable via `/api/v1/openapi.json`
and MCP `tools/list`), and enforces RBAC + audit at the API layer — not a
dashboard fragment. This section ticks every #1939 item.

### Fleet metrics (agent heartbeat → Prometheus)
- **`arm_race_unwatch_failures_total` / `disarm_unwatch_failures_total` (#2270 — agent
  side SHIPPED, fleet rollup DEFERRED):** two counters, both counting mechanism
  `unwatch()` calls that THREW, where the throw is contained rather than propagated —
  `arm_race_unwatch_failures_` during `arm_impl`'s consumer-race teardown
  (`teardown_arm_race`), `disarm_unwatch_failures_` during `disarm()`. Emitted as the
  sparse heartbeat tags `yuzu.spark_arm_race_unwatch_failures` and
  `yuzu.spark_disarm_unwatch_failures`. **Scope is in the names and is deliberately not
  fleet-wide:** the two together cover `teardown_arm_race` and `disarm()` only.
  `unregister_consumer()`'s unwatch site is not a peer of these two — it still
  propagates UNCONTAINED, and the consequence is worse than an uncounted orphaned
  watch: escaping a void function there permanently strands the consumer's dispatch
  thread (tracked as #2814). Two zeros do not mean "no orphaned watches", and say
  nothing about #2814 at all. The `{os}` rollup, the `docs/user-manual/metrics.md`
  row and an alert rule are **deferred to the
  `prefer_spark` flip** on the same grounds as `retiring`/`retiring_cap`
  (`spark_fleet_tags.hpp`): with `prefer_spark_` false nothing arms, so the gauges
  would be structurally absent fleet-wide and unfalsifiable. Tracked as item (d) of the
  flip gate above.
- **Agent:** emit `SparkEngineStats` as `yuzu.spark_*` heartbeat `status_tags`.
  `SparkEngineStats` (`spark_engine.hpp`, the `SparkEngineStats` struct) carries `armed_faulted`,
  `watch_faults_total`, `mech_watch_rejected_total`, `mech_quarantined_total`,
  `mech_slow_op_total` (the #2011 counters already exist in the struct, not yet
  emitted) **plus** `queued_dropped_total`, `consumer_errors_total`, and the
  inline-watchdog fields — the queue-drop/consumer-error counters are load-bearing
  for the never-drop-enforce guarantee and must be surfaced, not just the mech
  counters (sre F1). **Add `mech_unsupported_total{os,mechanism}` (new — not in
  `SparkEngineStats` yet):** a platform-rejected rule never arms, so none of the
  fault/watch counters count it; this dedicated counter backs the `unsupported`-state
  never-silent guarantee at rungs 2–3 (§Platform-rejection) and gives the denominator
  to distinguish "no rules of this type deployed" from "rules deployed, rejected by
  platform" (sre, consistency, happy-path). **Shape (rung-1, sre):** the agent
  exports flat key→value heartbeat tags (`kNetTag*`-style scalars), and every sibling
  `SparkEngineStats` counter is a flat scalar summed across mechanisms — so the
  `{os,mechanism}` breakdown is realized as **separate per-type scalar counters**
  (file / registry / service), not a single labelled series. **Corrected as built
  (rung 1):** these are emitted **SPARSELY — omitted when 0, never pre-seeded** (an
  earlier draft of this bullet said "pre-seeded to 0", which contradicted this same
  doc's §Server and the `yuzu_fleet_net_*` precedent). The server clears each gauge
  family per sweep, so an absent series means "no agent reported it", never a
  fabricated 0 — the absent-not-zero rule in `docs/observability-conventions.md`.
  Sparse emit also keeps a quiescent agent's heartbeat at two tags rather than ~15.
  Also emit `yuzu.spark_enforce_active` (rung 2, the detect-only-vs-enforcing signal,
  §Kill-switch).

  > **RUNG-2 TELEMETRY CONTRACT — read this before touching the counters (#2083).**
  > The obvious rung-2 move — "counter-type the `yuzu_fleet_spark_*` sums so `increase()`
  > works" — is **UNIMPLEMENTABLE**, and an earlier draft of this doc and of
  > `docs/prometheus/yuzu-alerts.yml` both said to do it. A fleet **SUM over a churning
  > agent population is not a valid counter**: it DECREASES whenever an agent ages out of
  > the staleness window or restarts (its cumulative counters reset to 0), Prometheus reads
  > any decrease in a counter as a RESET, and `increase()` then manufactures a false spike
  > out of an agent merely going away. `clear_gauge_family()` makes it worse — series go
  > absent and reappear.
  >
  > The correct design: the **agent keeps shipping the cumulative absolute value**
  > (idempotent under a duplicated or lost heartbeat — an agent-side delta is NOT: a
  > duplicate double-counts and a loss is gone forever), and the **server** holds
  > last-seen-per-agent and does `counter.inc(max(0, new − old))` with reset detection
  > (`new < old → inc(new)`). Server state is ~10k × 11 × 8B ≈ 1 MB. That single change
  > also fixes the **`absent == 0` reader contract**, which today forecloses change-gated
  > emit and forces every agent to re-ship unchanged counters on every heartbeat
  > (~68 B → ~556 B at rung 2; ~16 GB/day fleet-wide at 10k agents). Same root, both ends.

  **Rung-1 task:** introduce `kSparkTag*` tag-key constants
  (none exist yet) and pin them with a `static_assert` in a new `test_spark_*`
  test, mirroring the `kNetTag*` pin precedent (`test_network_perf_model.cpp`) —
  this doc does not reuse the net pin's own location. Omit the
  tags entirely when the kill-switch is set, so fleet rollups reflect genuine state
  (the `--dex-disable` posture).
- **Server:** mirror the net-gauge block in `AgentHealthStore::recompute_metrics`
  (`agent_registry.cpp:1290`) into `yuzu_fleet_spark_*` gauges. Use the
  `clear_gauge_family` → repopulate idiom (`:1300`) so an unreported metric goes
  **absent, not fake-zero**. Carry an **`os` label** (Registry and File are
  **Windows-only** — non-Windows `make_*_mechanism()` returns `nullptr`; Service is
  Windows-SCM **+** Linux-systemd, the only two-platform mechanism; **macOS has zero
  working mechanisms today** — so an unlabelled aggregate
  conflates "healthy, nothing armed on this OS" with "mechanism never connected",
  `docs/observability-conventions.md`) and a `yuzu_fleet_spark_reporting`
  denominator gauge mirroring `yuzu_fleet_net_reporting`. The `yuzu_fleet_spark_*`
  family includes `yuzu_fleet_spark_unsupported` (from the per-type
  `mech_unsupported_total`) and `yuzu_fleet_spark_enforce_active` (the rung-2
  detect-only-vs-enforcing signal, §Kill-switch). (sre F2.)
- **Alerts (#2011 + sre F1):** `mech_watch_rejected_total` rate > 0
  (denial-of-detection), `mech_quarantined_total > 0` (page-worthy, should stay 0),
  `mech_slow_op_total` rate (stalled watcher), an `armed_faulted` gauge, and a
  `queued_dropped_total` rate > 0 on the Guardian consumer (dropped enforce = a
  silent compliance failure). The last two ship with rung 1/3, not deferred to the
  per-rule surface. Alert expressions **must preserve the `os` label** (never
  `sum without(os)`) — a cross-OS aggregate is meaningless when a mechanism is
  single-platform, mirroring the gauge rationale above (sre).

### Per-rule health (the REST + MCP surface)
- **Ingest:** implement the `action == "status"` branch in
  `ingest_guardian_response` (`server/core/src/guardian_ingest.cpp:146`, currently
  a debug-and-drop TODO). Parse `GuaranteedStateStatus`, persist the per-rule
  `GuaranteedStateRuleStatus.guard_healthy` (proto field 8 — **defined today,
  never ingested**) plus fault counts.
- **Trust boundary (LOAD-BEARING).** Agent-reported `guard_healthy` is a **claim,
  not ground truth** — a skewed or hostile agent can self-report healthy while its
  Guardian is dead, hiding a dark endpoint (#1685 lesson). The authoritative "is
  this agent actually enforcing" signal stays **server-side report freshness**
  (heartbeat/receipt-time liveness, never agent `collected_at`); per-rule health
  goes **absent, not fake-healthy** when reports stop. Corroborate self-reported
  health against the agent-granularity mechanism-liveness tags (§Fleet metrics) —
  e.g. an agent reporting all-healthy while its Service mechanism reports inert or
  `armed_faulted` — not against per-rule event silence (a steady compliant rule is
  legitimately silent, per the mechanism-level liveness rule above).
- **Presume-dead-until-proven-live — liveness is a property of the MECHANISM, not
  the rule.** A watch that armed and then went silently deaf (bus/SCM collapse with
  no failing op) may never fire a `SparkFaultFn`. Detection is therefore **presumed
  dead absent positive mechanism liveness**: each mechanism proves liveness at the
  *connection/registration* level (sd-bus connection alive + match registered; SCM
  handle alive; IOCP port serviced), and when a mechanism's liveness lapses **all
  rules it carries** flip to `errored`. Liveness is explicitly **not** keyed on
  per-rule event cadence — a steady-state compliant File/Registry rule that nothing
  ever changes produces no events and has no periodic self-check, so a rule-cadence
  staleness bound would false-trip healthy quiescence to `errored` (independently
  flagged by both happy-path and unhappy-path at Gate-8). Likewise the trust-boundary
  corroboration (below) reads *mechanism* liveness + report freshness, not rule
  silence. (UP-5, UP-8, security-guardian — the single mitigation covering the
  widest silent-failure blast radius.)
- **Storage:** extend `guardian_agent_rule_status` (`guaranteed_state_store`) with
  a health/fault dimension beyond the current 3-way `compliant|drifted|errored`
  verdict, under the same older-event-can't-regress-newer guard as the verdict
  upsert; migration default = **unknown, never healthy**; write via `RETURNING`
  (avoid the `sqlite3_changes()`-after-`step()` hazard, #1033); the column inherits
  the parent table's retention policy (state one line, per the data-store-change
  requirement). **PG-migration interaction:** `GuaranteedStateStore` is SQLite
  today *and* on the Postgres ladder (`docs/postgres-migration-ladder.md`, "ALL
  existing server stores migrate", ADR-0006 Update 2026-06-22). Land the column in
  the store's PG-target schema, or coordinate with that store's PG author so the
  health dimension is carried across the cutover rather than stranded. (architect
  S2, UP-9, consistency, compliance.)
- **REST:** fill the zero-stub fleet + per-agent status routes
  (`rest_api_v1.cpp:7313` `/guaranteed-state/status`, `:7328`
  `/status/{agent_id}` — both hardcode zeros with a "lands in Guardian PR 4"
  note). The working `/device-compliance` route (`:7346`, scoped-perm +
  fail-closed `guardian.device.view` audit via `emit_behavioral_audit`) is the
  template — reuse its A4 envelope + audit posture.
- **MCP:** add a `get_guardian_status` tool alongside `get_guardian_schemas`
  (`mcp_server.cpp:352` def table, `:760` security `{GuaranteedState, Read}`,
  `:2922` dispatch), honoring the tier-check-before-RBAC ordering, kill-switch
  coverage (`--mcp-disable`/`--mcp-read-only`), **and audit coverage of the status
  read** — via the MCP audit path (`try_persist_audit`, **set-and-proceed**), NOT
  REST's fail-closed `emit_behavioral_audit`/503; the failure posture is deliberately
  per-surface (CLAUDE.md: REST fail-closed 503, MCP set-and-proceed), so the MCP tool
  must not copy REST's fail-closed branch — that `docs/mcp-server.md` requires,
  with `JObj`/`JArr` output. **Align with the UCE workstream's planned full MCP SSE
  streaming — this is a request/response status read, not a new streaming surface;
  live health streams ride the UCE stream when it lands, not a parallel channel
  built here.**

### Platform-rejection surfacing
**Any rule whose mechanism is unavailable on the host** — not just Service. Per the
corrected os-matrix (§Fleet metrics): Registry and File rules reject on **Linux and
macOS** (both Windows-only), Service rules reject on **macOS / Linux-without-libsystemd**,
and **every** mechanism rejects on **macOS**. In each case the factory returns
`nullptr` and `arm()` returns a typed `std::expected` rejection. Such a rule surfaces
as a **distinct terminal state — `unsupported`, NOT reason-tagged `errored`** (one
status token, not two): `errored` already means "failed to arm/evaluate" and feeds
the page-worthy `mech_quarantined`/`armed_faulted` alerts, whereas a cross-platform
Baseline reaching a host that structurally lacks the mechanism is a *routine,
expected* condition — tagging it `errored` would light up health alerts for benign
cross-platform deploys (architect S3, cross-platform, reversing the earlier draft's
recommendation). **Discriminator (not string-matching):** `unsupported` vs `errored`
is decided by *whether a mechanism is registered for the rule's type on this host* (a
pre-arm capability check), never by pattern-matching the `arm()` rejection string —
`arm()` returns an untyped `std::expected<…, std::string>`, so the consumer must not
parse the message to classify the terminal state. Likewise a
`mech_watch_rejected` (watch-cap) rule surfaces per-rule `errored`, not only a
fleet-rate alert (UP-14). **Sequencing (UP-6):** the terminal *state* is reached at
**rung 2** — arming begins there and rung 2 ships the platform-rejection state
(§ladder) — and is operator-visible from rung 2 via the **rung-1 fleet gauge**
`mech_unsupported_total{os,mechanism}` (§Fleet metrics) — deliberately NOT
`armed_faulted`/`errored`, which the paragraph above keeps the `unsupported` state
out of. The **per-rule REST + MCP status surface** that makes each rule's state
individually queryable lands at **rung 4** (§ladder); through rungs 2–3 the "never a
silent never-evaluate" guarantee is carried by the fleet metrics, not per-rule
REST/MCP — i.e. **fleet-loud but per-rule-silent**: an operator sees the aggregate
count ("N unsupported on macOS") but cannot identify *which* rule on *which* device
until the per-rule surface lands at rung 4 (unhappy-path). **Vocabulary wiring
(rung-4 task):** `unsupported` is a *new* terminal
token — a new string *value* in the existing `status` field, not a new proto field
(byte-compat holds). Until the status vocabulary is extended (the
`guaranteed_state.proto` status comment, the `guaranteed_state_store` vocab, the
OpenAPI enum, the MCP output schema, the ingest parser branch, and a fold-guard
test), the REST route folds any unrecognized state
to `pending` (`rest_api_v1.cpp:7555-7563`), so `unsupported` would surface
indistinguishably from a genuinely-unreported rule. Wire the token in the same rung
that fills the surface.

### Inert-mechanism distinguishability
A mechanism whose bus/SCM connection never opened at `start()` (non-systemd host,
container without a system bus) is today indistinguishable from "no Service sparks
configured." A mechanism-up gauge (or an `inert` reason on the fault channel)
distinguishes them; **owned by rung 1** (observe-only), not left open. (sre F3.)

> **SHIPPED IN RUNG 1 — the 2026-07-12 deferral below was WRONG and is withdrawn.**
> The rung-1 governance re-run (2026-07-13) had three agents independently reach the
> same conclusion — cross-platform, sre (which explicitly *rebutted* the deferral), and
> Gate-4 consistency. The deferral rested on "inert liveness needs arming to carry
> signal." It does not: **inertness is known at `start()`**, no arming required, and all
> three mechanisms already log it there. Worse, deferring it shipped a live
> misreport — `Dockerfile.agent` installs `libsystemd0` but a container has **no system
> bus**, so *every containerised Linux agent* advertised a `service` capability whose
> every `watch()` would be refused: "looks healthy, can detect nothing".
>
> Rung 1 therefore ships an `inert` bit on `SparkMechanismStats`, set at `start()` by
> each mechanism (File and Registry can also raise it at runtime, R5.7 (b)), and
> **excludes inert mechanisms from the `yuzu.spark_mechs` capability
> CSV** — so `yuzu_fleet_spark_mechanisms{os,mechanism}` now counts only mechanisms that
> are registered **and functional**. Inert mechanisms still report their counters;
> inertness suppresses the capability *claim*, not the telemetry.
>
> Still genuinely deferred to rung 2 (#2084): the **armed-but-deaf** liveness signal (a
> watcher that died after arming) and `mech_unsupported_total` (an arm-rejection counter
> — nothing arms at rung 1, so it is structurally 0). Those really do need arming.

### Not-running distinguishability (rung 1)
A spark-capable agent reports exactly one of four postures, and each is distinguishable
on the wire: **RUNNING** (`spark_running=1` + capability CSV), **FAILED** (`=0`, no
`spark_disabled` key — enabled, but boot-time instantiation threw), **DISABLED** (`=0`
plus `spark_disabled=1`), and **ABSENT** (no `yuzu.spark_*` key at all — a pre-rung-1
agent, or a dead one). Rolled up as `yuzu_fleet_spark_{reporting,failed,disabled}{os}`.

As first built, the FAILED path emitted *nothing*, making it byte-identical to DISABLED
and to ABSENT — so a fleet where spark failed to boot on 30% of endpoints was
**unobservable**, which defeats rung 1's entire stated purpose ("prove the engine runs
and reports at rest"). The DEX sibling already had this right, emitting
`dex_observer_armed=0` when enabled-but-deaf rather than going quiet. Alert on `failed`;
never on `disabled`, which is an operator decision. (Gate-4 consistency + UP-10.)

### Audit-on-arm
The arming path (Guardian's `apply_rules` / `start_local` calling
`arm(Service, …)`) emits an audit event at the Guardian layer, matching the
existing Guardian audit convention (verb + evidence-continuity mapping). Because
arming first runs for real at **rung 2**, audit-on-arm ships **at rung 2**, not
rung 4 — otherwise rungs 2–3 arm and enforce in production with no audit trail, a
control gap in the exact window enforcement first moves (compliance BLOCKING,
UP-13). Enforce-action audit verbs are lifted verbatim into the consumer and
covered by the evidence-continuity gate, not just arm.

## Kill-switch

`--spark-disable` / `YUZU_AGENT_SPARK_DISABLE`, mirroring `--dex-disable`
(`agent.hpp:56`, `agents/core/src/main.cpp:199`): a `Config` bool, CLI flag with
`envname`, read **at construction — boot-time only**. Like `--dex-disable` it is a
deploy-time opt-out requiring a restart to take effect; a live change is
**ignored-with-audit**, never a partial-path teardown (UP-1, sre F5 — the earlier
draft's "config-pushable, not a redeploy" phrasing overstated this and is
corrected). During the cutover window (rungs 2–4) both detection paths are compiled
in and the flag selects **exactly one** at instantiation.

The "never both drive enforcement at once" property (which the Decision-11
amendment leans on) requires the flag to be the single source of truth at **both
the instantiation site and the `start_local`/`apply_rules` arm sites**, plus a
central mutual-exclusion keyed on rule_id/unit so no unit is ever watched by both
an `IGuard` and a spark (invariant test: no unit appears in both `guards_` and the
spark arm set). (UP-2, security-guardian LOW-4.) The final rung deletes the legacy
guards and the switch becomes a hard on/off for spark detection.

*Rung numbers in the paragraph below (not this one, nor the rung 2-4 cutover-window
paragraph above it) predate the implementation ladder's later resequencing: "rung 2"
there is impl-rung-7 (the `prefer_spark` flip, rung 7.7); "rung 3"/"rung 5" are the
P3 enforce cutover / P5 legacy deletion in the post-flip programme. Current gate
state: `docs/spark-flip-gate.md`.*

`--spark-disable` default posture: **observe rung (2)** defaults to the spark path
(safe, detection-only); the **enforce and deletion rungs (3, 5)** default to the
legacy path until burn-in, so a first-customer fleet is not switched onto new
enforcement by default (enterprise-readiness). The default is recorded explicitly
in each rung's PR. **What enforces during the rung-2 default window:** with the
spark path selected in observe-only mode and the legacy `IGuard` not instantiated,
Guardian at rung 2 **detects but does not enforce** (spark enforce arrives at
rung 3). An operator who needs continued enforcement during rung-2 burn-in flips to
`--spark-disable`, selecting the legacy path (which still enforces). This is a
deliberate, greenfield-acceptable detect-only burn-in window, not an accidental
enforcement gap. **This window MUST be operator-visible, not doc-only (UP-7,
compliance, enterprise-readiness):** the agent emits a boot log naming the active
detection path and its enforcement posture — at rung 1 the legacy `IGuard` path
still enforces (no consumer yet) so it simply names the active path, and from
rung 2's spark-observe-only default it WARNs that enforcement is suppressed (e.g.
"Guardian: spark path OBSERVE-ONLY — enforcement suppressed for spark-managed rules;
--spark-disable restores the enforcing legacy path"). Rung 2 also emits a distinct fleet signal
(`yuzu_fleet_spark_enforce_active` gauge / heartbeat tag) separating "configured
enforce, actually enforcing" from "configured enforce, downgraded to observe" — the
same "loud, never silent" bar the enforce-lane drop already holds (§Enforce path).
A rung-2 build also ships a `changelog.d` fragment + `docs/user-manual/guaranteed-state.md`
upgrade note for this enforcement-posture default change (not deferred to rung 5).

## Dependencies & issue dispositions

- **#2011 (HARD gate, rung 0) — LANDED (lock half).** The engine-wide
  `mech_ops_mu_` (introduced by #1994's M2 fix) is downgraded to per-mechanism-type
  `mech_ops_mu_by_type_` (`std::map<SparkType, std::mutex>`), so a slow `watch()`
  on one mechanism can no longer block arm/disarm on another. Cross-mechanism
  coupling is closed; the residual same-type stall (an unbounded `watch()` still
  blocks its own type's queue) is the walk-off-`mu_` follow-up, landed for Registry
  in PR-B1 (#2012/#3840, bounded at 50 ms on the control path) and File in PR-B2
  (same shape). **Service (PR-B3) never actually had this same-type-lock stall** -
  its `watch()`/`unwatch()` were already O(1) queue pushes before this series; its
  real, structurally different gap (`OpenServiceW` head-of-line on Service's own
  worker thread, not the per-type lock) is addressed by PR-B3 (merged 2026-09-12 as
  PR #4302) - see the PR-B3 entry above for the full correction. The observability half of #2011 (per-type
  `SparkEngineStats` emission + alerts) is DEFERRED to rung 1, where SparkEngine
  is first instantiated.
- **#2014 (BLOCKING-before-Stage-2):** resolved by the no-blocking-inline-consumer
  policy + never-drop enforce lane (§Enforce). Whether to *additionally* decouple
  the Windows file mechanism's emit-delivery from its completion-reap loop
  (option (b)) is recommended as rung-3 defence-in-depth given the fault path also
  rides the reap thread (UP-7) — decide at the enforce-cutover rung.
- **#1938:** closed by the Decision 3 wording amendment (median-µs, inline
  reserved). GitHub issue closed post-merge.
- **#1929** (fault severity tiering + Linux Subscribe-degrade signal) informs the
  health surface's fault mapping. **Deferred (tracked, not Stage-2 blockers):**
  #1933 (Registry re-arm retry timer), #1936 (fault-flap debounce unification),
  #2015 (promote hardcoded timing/cap constants to `Config`).

## Parity, §24, and gates (ADR-0021 Decision 11 amendment)

ADR-0021 Decision 11 specified a long-lived integration branch merged to `dev`
atomically after parity + resource + evidence gates. Stage 1 merged to `dev`
directly (unwired, so no interleave risk), de-facto departing from that posture.
Stage 2 is where old and new detection first coexist on a running agent.

**Amendment: incremental per-consumer cutover on `dev`, behind the kill-switch,
with the three gates applied per rung.** The kill-switch guarantees old and new
never *both drive enforcement* on one agent at once (the flag picks one — the
mutual-exclusion invariant above makes this airtight), which is the property
Decision 11's "never ship interleaved" protected. Because Yuzu is still greenfield
(no customer mid-fleet), this trade is safe now; it is **not** asserted as the
posture once a pilot customer is deployed — from the first customer, protocol and
cutover changes must support rolling upgrade. The wire protocol staying unchanged
(§Scope) keeps a mixed-version fleet safe across the multi-week ladder. **Each rung
runs the full 8-gate `/governance` pipeline** (not an abbreviated review); each
rung's report is retained as change-management evidence (SOC 2 Workstream F) by
posting it as a **GitHub PR review (`gh pr review`) on that rung's PR** — a durable
artifact mapping onto Workstream F's "PR review records" category, never a bare git
commit hash (which can orphan, as this doc's own prior `bbe55cc9` did).

**A PR can orphan too — the rule above is necessary but not sufficient.** Rung 1 proved
it. PR #2082 carried a complete governance review and GitHub reported it **MERGED** — but
its base was `fix/2011-spark-mech-ops-per-type`, a sibling branch that had *itself* merged
to `dev` the day before. GitHub did not retarget it, so the merge (and the code, and the
review) landed on a dangling ref and **never reached `dev`**. The rule was satisfied and
the evidence orphaned anyway, because it never checked where the PR's *base* pointed. An
auditor tracing "what review authorised the code running in production" would have found
nothing that resolves to `dev`.

Two corrections, both binding from rung 2 on:

1. **Every rung PR bases directly on `dev`.** Never on a sibling feature/fix branch, even
   one still open — that branch may merge to `dev` first and silently strand the second
   merge off-trunk. If a rung genuinely must stack, it is rebased onto `dev` and
   re-targeted *before* merge, not after.
2. **A PR is valid Workstream-F evidence only once its merge commit is reachable from
   `dev`** — verified with `git merge-base --is-ancestor <merge-sha> origin/dev`, **not**
   by trusting the GitHub "Merged" badge, which was true for #2082 the entire time.

Gates, applied at the marked rungs:
- **Parity:** Guardian §24 invariants verbatim — `Push` seed stays Guardian-only,
  the `__guard__` load-time + dispatch-time dual intercept both remain,
  `dangerous_enforce_in_spec` stays the single enforce-safety chokepoint (extend,
  never fork — a Linux service-enforce path must extend
  `dangerous_enforce_service_stop`), the enforced set stays sourced from
  `BaselineStore::deployed_member_rule_ids()` (deployed snapshot, not live
  members), and Guardian wire payloads stay gateway-safe (no raw proto bytes in
  the `map<string,string>` the Erlang gateway re-encodes). Event-stream
  equivalence on scripted scenarios uses tolerance bands **only for observe/debounce
  noise**; enforce-class and dangerous-drift `event_type`s require **zero-tolerance
  exact match** — a tolerance band would let a real enforce divergence pass (UP-10).
- **Resource:** detection threads drop O(rules) → O(mechanisms); idle CPU,
  wakeups/sec, **real OS thread count** (not the `watcher_units` gauge, which is a
  pool count, not `ps -T`, architect N1), and RSS old-vs-new via `/test` perf. This
  headline win is established at **rung 2** (Guardian becomes the consumer,
  replacing per-rule threads), so the resource gate runs at rung 2, not only 3/5
  (sre F4).
- **Evidence continuity:** capture an explicit **audit-verb + metric-label
  snapshot** before rung 3 and diff against it, so SOC 2 evidence automation drift
  is provably absent, not asserted absent (compliance). Verbs/labels preserved or
  explicitly remapped.

## Implementation PR ladder

Each rung is an independently-governed PR on `dev`, run through the full
`/governance` pipeline.

0. **#2011 gate — LANDED (lock half).** Per-mechanism-type `mech_ops_mu_by_type_`.
   Pure engine-internal refactor; acceptance tests: a blocking `watch()` on
   mechanism A does not delay `unwatch()` on mechanism B (cross-type decoupling),
   and a blocking `watch()` DOES still serialise a second arm of the same type
   (per-type control). Observability half (per-type stats + alerts) deferred to
   rung 1.
1. **Instantiate + observe — LANDED.** SparkEngine constructed in `agent.cpp` behind
   `--spark-disable`; `yuzu.spark_*` heartbeat tags (queue-drop/consumer-error +
   per-type mech counters) + `yuzu_fleet_spark_*` os-labelled gauges + reporting
   denominator + the capability signal `yuzu_fleet_spark_mechanisms{os,mechanism}` +
   a reviewed alert group shipped **commented out**, and the boot log naming the active
   detection path (legacy `IGuard` still enforcing at rung 1). No consumer yet;
   proves the engine runs and reports at rest. Guards against a boot exception (thread
   exhaustion) by degrading to no-spark.

   **Shipped beyond the original rung-1 scope**, both added by the rung-1 governance
   rounds — the ladder must not be read as still deferring them:
   - **The `inert` bit** (§Inert-mechanism distinguishability). A mechanism that started
     but could not bind its OS facility is excluded from the capability CSV (File and
     Registry can also raise it at runtime, R5.7 (b)). The earlier
     deferral to rung 2 was WITHDRAWN: inertness is known at `start()`, needs no arming,
     and deferring it shipped a live misreport on every containerised Linux agent
     (`libsystemd0` is installed, but a container has no system bus).
   - **The four-posture wire contract** (§Not-running distinguishability): RUNNING /
     FAILED / DISABLED / ABSENT, rolled up as
     `yuzu_fleet_spark_{reporting,failed,disabled}{os}`. Without it a fleet-wide spark
     boot failure was invisible — a failed agent emitted nothing, identical to a
     deliberate opt-out.

   **Genuinely still deferred to rung 2** (#2084): the ARMED-BUT-DEAF liveness signal (a
   watcher that dies after arming) and `mech_unsupported_total{os,mechanism}` — both need
   arming to carry signal. The alert group is enabled at rung 2 (#2083), and NOT by
   "counter-typing the fleet sums" — see §Fleet metrics for why that does not work.
2. **Guardian detection consumer** — the queued consumer + arm-per-rule (with the
   `spark_key→rule` index, refcounted shared watchers, and the re-arm/initial-eval
   contract), detection only (observe mode), behind the switch, both paths compiled
   in. **Ships audit-on-arm, platform-rejection state, the mutual-exclusion
   invariant, the `yuzu_fleet_spark_enforce_active` enforce-suppressed signal, and a
   `changelog.d` fragment + `guaranteed-state.md` upgrade note for the rung-2
   enforcement-posture default change** (detect-only by default; `--spark-disable`
   keeps the enforcing legacy path). Gates: event-stream equivalence parity + the resource gate.

   **Rung 2 is delivered as an inner ladder of its own** - the surface is too large
   for one governed PR, and ADR-0021 Decision 11 (as amended) requires the parity,
   resource, and evidence-continuity gates **per rung**, not once at the end. This
   inner ladder was previously recorded only in commit messages and a local plan
   file, which is what caused PR #2224's Gate-1 scoping error (the range was written
   against a memory-recalled merge-base and inner rungs 2-6 went in ungoverned).
   It is written down here so a gate can be scoped against it.

   Inner rungs 1-7 **merged as PR #2224** (~45 files), all pure/against-fakes
   agent-internal code with no production call site - the subsystem is compiled but
   unreachable (`wire_spark_engine()` has zero callers):
   - **1.** Tri-state + snapshot reshape of `guardian_rule_eval` (`ReadResult<Snapshot>`
     → `EvalOutcome{Silent|Emit|Unhealthy}`; Unknown never mutates the emit-decider).
   - **2.** `guardian_outbox` (header-only, pure): FIFO drain, retain-on-failure,
     coalescing domains, generation purge, cap ⇒ reject-new-key backpressure.
   - **3.** `GuardianSparkRuntime` core against fakes: registry mutex, per-rule
     generations, per-key eval mutex, one `evaluate_key` for all paths, detach-safe
     `shared_ptr` capture. TSan + ASan detached-handler checkpoint.
   - **4.** Convergence scheduler: per-type lanes, jitter, size+mtime precheck before
     re-hash, byte budget, non-droppable pending-initial priority.
   - **5.** Platform `StateReaders` (file handle-scoped #807 hashers, registry
     `RegOpenKeyExW`, service SCM/sd-bus, absent→Stopped), **plus F3** - the
     bounded/cancellable I/O executor (spawn-per-read detached workers, per-class
     deadlines, keyed single-flight, the executor's `active_worker_count()` - surfaced to
     the engine as `active_io_workers()` - for the orphan-exit count).
   - **6.** `enabled()` fix (own commit, a legacy behaviour change): a disabled rule
     in `apply_rules` no longer arms, and an already-armed rule pushed disabled is
     stopped.
   - **7.** `GuardianEngine` integration: `reconcile_rule_locked()` as the sole
     arm/disarm chokepoint, `wire_spark_engine()` as a rollback-on-failure transaction,
     the `SparkAvailability` state, decl-order/stop-order prep, and the F3 orphan-exit
     enforcement (`hard_exit()` when an I/O worker outlives the grace).

   Remaining inner rungs (this program):
   - **9a.** This decision record + the inner ladder + the gates-per-rung note.
     Docs-only; precedes 7.7 because 7.7's shape depends on R1-R4. **(this change.)**
   - **7.7a.** Lifecycle-only wiring. Reorder boot to **construct → register
     mechanisms → `SparkEngine::start()` → `wire_spark_engine()` → `start_local()`**
     (the header requires wiring before `start_local()`, and the capability set
     `reconcile` reads is only correct after `start()`; whether `arm()` before
     `start()` is safe per mechanism must be **pinned, not discovered**). Extend the
     boot latch across object publication and wiring; prove every early-return and
     concurrent-`stop()` path; exercise wiring rollback. `prefer_spark` hardcoded
     `false` - **zero placement behaviour change.** Ships R4's 7.7a log set.
     Qualifies shutdown and the F3 hard-exit path, **including its interaction with
     `Restart=always`** (see below).
   - **7.7b — SPLIT into two governed PRs (settled 2026-07-18, §7.7b split below).**
     Three reviewers (Sol/Codex, Claude, Fable) found the send/placement path is not
     yet safe to make live in one PR. The flip is the **last commit** either way.

     **PR-1 is itself landed as two governed PRs (decided 2026-07-18) so each is
     reviewable as one unit and item 9's counters land before their consumers:**
     - **PR-1a** = the send/exception/drain cluster: items 1 (shared drift builder),
       2 (guard_type/rule_name), 3 (exception firewall), 4 (drain-without-lock), plus
       their two Sol/Fable hardening folds and this governance round. Behaviourally
       inert (`prefer_spark` false), but item 3's `apply_rules` firewall is a **live
       legacy-path** crash-prevention fix (see the changelog fragment).
     - **PR-1b** = items 5 (two-count executor + orphan ceiling), 6 (F3 marker),
       7 (KV lifecycle journal), 9 (R4 telemetry + the heartbeat wiring for the
       PR-1a counters), 8 (test seams), **M1 (the transition-edge health-emission
       fix)**, and the R2 `unsupported` terminal state.
     - **FLIP GATE — ELEVEN items gate PR-2**, each detailed in the bullets below: M1,
       item 9's heartbeat wiring, #2270, the lifecycle-audit journal, #2797, #2818,
       #2819, #2813, #2839, and two residues that own no issue, (a) and (b). **The
       `prefer_spark` flip must not ship while any is open.** The first four land in
       PR-1b except #2270, which ships as its own PR against `dev` ahead of it. M1 in
       particular is a fleet ingest-DoS if the flip precedes it, so it is not enough
       that it is "in PR-1" — it is specifically in PR-1b, after PR-1a.
     - **#2797 gates PR-2 as well, and is the only gate whose headline defect is
       already live pre-flip.** `apply_rules` discards
       `reconcile_rule_locked`'s bool
       (`guardian_engine.cpp:634`; the surrounding catch counts a THROW only), so a
       RETURNED arm failure leaves `reconcile_failures` at 0, the generation
       advances, the server stops re-pushing, and the rule stays persisted-but-
       unarmed. The flip raises the rate rather than creating the defect: a returned
       failure is the ordinary spark-backend arm error, whereas a legacy guard arm
       rarely throws (#2278). #2797 is the reconcile-side half split out of #2270 -
       #2270 itself closes only the strong-guarantee half, so closing #2270 does not
       discharge this gate.
     - **#2818 gated PR-2 too, now FIXED (PR-2d).** At the time this was written, the engine tore down a whole spark key
       (`SparkEngine::drop_key_locked`) while `GuardianSparkRuntime` arms one shared
       subscription per key on the 0->1 edge (`attach_rule`'s `index_->add` edge, `guardian_spark_runtime.cpp`),
       and nothing tells the consumer its subscription died: Guardian goes on
       believing it holds a live subscription, `backend_->disarm(sub)` is a no-op,
       and nothing is enforced for any rule on that key. It is an ENFORCEMENT gap,
       not a false-assurance one - `GuardianEngine::get_status()` is fail-closed
       (`guardian_engine.cpp:684-686`, every rule reported errored), so the
       originating findings' "get_status reports N rules armed" premise is false at
       this tip and is corrected in #2818. Dormant while `prefer_spark` is false
       because legacy `IGuard` is the live detection path - the flip is what makes
       it a live enforcement hole. #2797 removes the `apply_rules` self-heal that
       otherwise bounds it, so the two gates compound and neither alone closes the
       exposure.
     - **#2819 gates PR-2 as well — same dormancy test as #2818, applied
       consistently.** An earlier revision of this block dismissed it as "a
       shutdown-availability defect ... does not gate the flip". That was wrong:
       availability-vs-enforcement is not the criterion this list uses, dormancy is,
       and #2819 satisfies it. #2819 reaches a blocking `unwatch()`
       by TWO routes — `arm_impl`'s `teardown_arm_race`, and the ordinary withdraw
       path through `SparkEngine::disarm` — and both are dormant, for the same
       reason. `attach_rule` runs only at `guardian_engine.cpp:1153`, inside
       `try_spark = prefer_spark_ && spark_availability_ == SparkAvailability::Available`
       (`guardian_engine.cpp:1139`), and Guardian is the sole registered consumer
       (`guardian_engine.cpp:1244` is the only PRODUCTION `register_consumer`
       caller). `detach_rule` itself IS reached pre-flip — three of its five sites
       (`:1095`, `:1124`, `:1182`) sit outside the `try_spark` block, which spans
       `:1140-1179` — but it reaches `backend_->disarm` only when
       `index_->remove_rule` returns a key (`detach_rule_locked`, `guardian_spark_runtime.cpp`),
       and pre-flip nothing was ever attached, so `keys_` is empty. Both routes are
       therefore dormant TRANSITIVELY, on the absence of a prior arm, and the wedge
       is created by the flip exactly as #2818's hole is. Its terminal outcome is a
       stalled agent shutdown whose F3 backstop is structurally unreachable, on a
       trigger that correlates fleet-wide during an OTA wave. #2819 also carries a
       related `service_win.cpp` instance that is live TODAY and needs no spark
       involvement — see its Related section.
     - **#2813 gates PR-2 on the same dormancy profile**, and is listed here rather
       than left silent. Its sink is NOT #2819's, which is a lock wedge: #2813's
       residue is a live OS watch whose `armed_` entry is gone, so its firings are
       silently dropped.
     - **#2839 gates PR-2 on the same dormancy profile.** A throwing
       `push_retiring()` (`spark_file.cpp:331-336`) frees a `DirWatch` with a live,
       uncompleted kernel I/O — not merely a leak — and separately leaves
       `dirs_[dirkey]` half-erased (key present, `unique_ptr` null/moved-from,
       since `dirs_.erase(di)` never runs after the throw). `SparkEngine::stop()`'s
       later, unrelated `cancel(*w)` sweep (`spark_file.cpp:241-246`) dereferences
       that null pointer with no check — #2270's containment is what makes this
       survivable-but-silent rather than an immediate crash near the OOM event,
       deferring and decontextualizing the eventual failure. File-mechanism-only
       (Windows), OOM-triggered. First found by round-4's own `xp-1`/`UP-1`
       (`governance.d/2270-arm-window-round4.4c0PeP.jsonl`, pass 1); the
       stop()-time null-deref consequence specifically was surfaced later, by
       this branch's own final `/governance` run's Gate 4 unhappy-path pass, and
       Gate 5 chaos-injector then synthesized two test scenarios for it — do
       NOT cite those scenarios as `CH-1`/`CH-2`, which are already distinct,
       unrelated finding_ids in the round-4 ledger file (the stranded
       consumer-dispatch-thread finding and the stop()-does-not-drain finding,
       both deferred to #2814/#2815).
     - **Two residues gate PR-2 and own no issue**, recorded here because a gate list
       that enumerates only issue-backed items reads as complete when it is not.
       (a) CLOSED by `5858844c` (`SparkEngine::disarm`'s in-lock teardown made
       allocation-free) and `444c2458` (disarm's trailing `unwatch()` contained and
       counted, matching `teardown_arm_race`) — the allocating prologue this residue
       used to describe no longer allocates. Ledger `CH8-2`/`UP8-1` were adjudged
       discharged on the merits by security-guardian after the fix (pass-10 evidence
       row owed); `UP-4` deduped separately. A narrower residual remains, different in
       kind: two ops between the (now allocation-free) bookkeeping and the
       contained `unwatch()` still propagate uncontained — `disarm()`'s two
       `std::lock_guard` constructions ahead of the released-`mu_` unwatch call,
       `ops(mech_ops_mu_by_type_.at(unwatch_type))` and `lk(mu_)` (mutex
       acquisition can raise `std::system_error`). The `.at(unwatch_type)` call
       inside the first does NOT: the map is populated in lockstep with
       `mechanisms_` at registration and frozen after `start()`, so the lookup
       key is always present (`disarm()`'s declaration comment; implemented at
       `SparkEngine::register_mechanism`'s lock-first `try_emplace` block). By
       this point `disarm`'s OWN bookkeeping (`armed_`/`sub_keys_`) is already
       committed, so a throw here does not desync the engine's own state the way
       the old defect did — the consequence is narrower: the `unwatch()` is never
       attempted, so neither counter increments and the OS watch is never even
       asked to release. `teardown_arm_race` documents the same residual on its
       own declaration; `disarm`'s declaration now does too. (b) The `{os}` fleet
       rollup, the `metrics.md` row and the alert rule for BOTH
       `arm_race_unwatch_failures` and `disarm_unwatch_failures` —
       `spark_fleet_tags.hpp:82` defers all three to this flip IN CODE, so the flip
       makes an agent-side resource leak measurable at the endpoint and invisible at
       the fleet. Ledger `arch8-2`.

     - **PR-1 (inert hardening, `prefer_spark` stays false — zero change to
       detection/enforcement *placement*).** The shared drift-event builder;
       OutboxEntry guard_type/rule_name for Health/Lifecycle; attach_rule + live
       `apply_rules` exception firewall (strong-guarantee `SparkKeyRuleIndex::add`);
       **drain-without-lock** (transport outside `outbox_mu_`); the two-count executor
       + a **physical-orphan ceiling strictly > sum(quotas)**; the F3 KV marker;
       **lifecycle-audit durability** (KV-backed journal, replay on boot+reconnect);
       the **transition-edge health-emission fix** (see §7.7b split M1 — the flip is a
       fleet ingest-DoS without it); the `unsupported` terminal state (R2) + rung-8
       telemetry + reconcile-test rewrites (flag-gated inert, so they land here not on
       the flip); R4 telemetry producers+consumers + the `SparkFailed`-prevalence
       alert, all reporting the *inactive* posture; the #2238 test seams + TSan.
     - **PR-2 (thin cutover).** `prefer_spark = !cfg_.spark_disable`; the
       intentional-delta registry (R2 consequence 2, pulled forward from rung 10 since
       7.7b changes the behaviour it classifies; **shipped ahead of the flip, F12/#3386:
       `docs/spark-legacy-delta-registry.md`**); production-order cached-KV
       restart/upgrade tests; parity + resource + **3-OS/gateway** evidence; the
       grep-enumerated stale-prose sweep; the flip as the **final commit**. **This is
       where detection moves to spark and legacy enforcement stops** (until rung 3).
   - **8.** `mech_unsupported_total` + `yuzu_fleet_spark_unsupported` - **folded into
     7.7b PR-1** per R2 (unsupported must be loud the moment a rule can land on spark);
     current-gauge vs cumulative-counter split per §7.7b split.
     **Landed (F7, #2298),** together with R2's terminal-state code and the
     `yuzu.guardian_backend` heartbeat tag (#2240 item 1 - the server-side flap/dark-
     device detector, #2240 item 2, remains open).
   - **10.** Parity + durability + integration matrix. Semantic ports land **before**
     7.7b where possible; live/equivalence after. Carries the **intentional-delta
     registry** (R2 consequence 2, **shipped ahead of schedule, F12/#3386:
     `docs/spark-legacy-delta-registry.md`**) so zero-tolerance parity survives the legacy-no-op
     vs `unsupported` difference.
   - **11.** The `yuzu-fleet-spark` alert group (#2083) enabled + promtool CI lint,
     including the `SparkFailed`-prevalence alert (R1 correlated-outage note).
   - **12.** Dissolved into 7.7b per R1. Residue only: boot WARN, `enforce_active`
     gauge, `changelog.d` fragment, `guaranteed-state.md` upgrade note.
   - **9b.** The full as-built rewrite of this §Rung-2 decision record and the ladder
     against the shipped 7.7a/7.7b/10 code, folding R3's resolved mechanism and R2's
     `unsupported`-vocab reconciliation. Docs-only; lands after 7.7b.
   - **9c.** §Async-arm acknowledgment (R5) - decouples Guardian's rearm window from
     OS-watch confirmation. Independent of 9b; sequenced after PR-2c (#3848) and before
     the `prefer_spark` flip (PR-5), lands dormant. Own PR ladder, PR-0 (this docs
     change) through PR-6 - see `docs/spark-flip-gate.md` for the ladder slot between
     PR-2d and the flip. **Ordering inside the ladder (ruling 14(c), 2026-09-08):** PR-0 ->
     PR-1 -> [the #2012/#3840 same-type-serialization fix, pulled forward from the post-flip
     mechanism-hardening package and landing as three PRs sharing one primitive (PR-A/#4190,
     PR-B1 Registry, PR-B2 File, PR-B3 Service - not the two originally planned; see the
     corrected PR-B3 entry above)] -> PR-2 -> PR-3 -> PR-4 -> PR-5 ->
     PR-6 -> flip. **Interim cost between PR-1 and PR-5, stated (governance pass-3
     ar-8 / up-2):** with PR-1's claim queue and no deadline yet, a re-push onto a wedged key
     queues behind the abandoned head and waits the full `backend_op_deadline` under the
     engine's `mtx_` on every 25 s re-apply, where the base code fail-fasted through the
     executor's `AlreadyRunning`; PR-5's wedge mechanism restores an immediate refusal. Accepted
     while dormant; it re-derives HIGH at the flip (or any `prefer_spark` knob PR) and is
     a named PR-5 acceptance criterion in `docs/spark-flip-gate.md` §3a.

   **F3 × `Restart=always` (must be answered in 7.7a).** `deploy/systemd/yuzu-agent.service`
   sets `Restart=always` + `RestartSec=10` and **no `StartLimitIntervalSec`/`StartLimitBurst`**,
   so systemd's default burst limit (5 restarts / 10s) can never trip when restarts are
   spaced ≥10s apart. The F3 `hard_exit()` fires when an I/O worker is wedged past the
   grace. Against a *permanently* wedged target (dead NFS mount, hung SCM call) this is a
   10-second crash loop: exit → restart → arm the same rule → wedge → exit. Windows SCM
   recovery policy is the equivalent.

   **This is a security finding, not only an ops one.** Anyone who can wedge a read on a
   watched target inside a Baseline's scope (a black-holed NFS/SMB mount, a hung SCM or
   registry call) gets a **whole-agent** denial-of-service primitive: the crash loop downs
   every plugin, the heartbeat, and every other rule, not just the offending one.

   So the two candidate answers are **not** equivalent, and 7.7a must not treat them as an
   implementer coin-flip:
   - **Primary: degrade-and-skip-that-rule.** A wedged read isolates to its own rule and
     the agent keeps running everything else. This bounds the blast radius to one rule and
     is the required default. (It is the same "free the admission slot on deadline"
     property R3's intra-class note pins - the two findings share one mechanism.)
   - **`hard_exit()` is reserved for a genuinely uncancellable orphan** (a worker that
     cannot be cancelled and would otherwise run through static teardown - F3's original
     purpose), never as the routine answer to a wedged target. Bound it with a per-boot
     F3-trip cap.
   - **Belt-and-braces backstop:** add `StartLimitIntervalSec`/`StartLimitBurst` to the
     unit so any regression that still loops enters `failed` (paged) instead of restarting
     forever, and pair it with a **server-side flap detector** (repeated short-lived
     sessions from one agent) - a fast crash loop may exit before the heartbeat rail is
     even wired, so the agent cannot always self-report, and the F3 KV marker (R4) can go
     unreported.

   The F3 trip should page - a wedged read in the kernel is not routine.
3. **Enforce cutover** — Service/Registry remediation on the consumer thread;
   never-drop enforce lane; dequeue-time re-gate; the withdrawal disarm-push trigger
   contract (reconcile the armed set — `full_sync` today, or a new per-rule
   teardown-on-delta in `apply_rules`; §Enforce path); #2014 policy enforced;
   resilience preserved; Service-arm-latency ceiling met. Parity (zero-tolerance for
   enforce event types) + resource + evidence-continuity gates.
4. **Health surface** — `action == "status"` ingest, `guard_healthy` persistence
   (unknown-default, PG-ladder-coordinated), REST status stubs filled,
   `get_guardian_status` MCP tool (audited via the MCP set-and-proceed path, not REST
   fail-closed — §Health/MCP), presume-dead liveness,
   trust-boundary corroboration, **and the `unsupported` status-token wiring** (proto
   comment, store vocab, OpenAPI enum, MCP output schema, ingest parser, fold-guard
   test — §Platform-rejection). Doc: rewrite the `docs/user-manual/guaranteed-state.md`
   "the `/status` endpoint returns placeholder zeros — do not consume" caveat, and add
   `unsupported` to the published status vocab in `docs/user-manual/rest-api.md` +
   `guaranteed-state.md`, now that it is live (enterprise-readiness, docs-writer).
5. **Legacy deletion** — remove `guard_service.cpp` / `guard_systemd.cpp` /
   `guard_registry.cpp` / `guard_file.cpp` and the `guards_` map; the switch
   becomes hard on/off. Ships a `changelog.d` **"Breaking"** fragment (the flag
   changes from a routing selector to a hard kill-switch) + final resource-gate
   evidence.

## Doc / CLAUDE.md follow-ups

- Add a Guardian-spark routed-concern pointer to CLAUDE.md → ADR-0021 + this doc.
  Stage 1 code is in-tree, unconsumed, with no pointer today (docs-writer SHOULD).
  Deferred to **rung 1** (when SparkEngine is first instantiated in `agent.cpp`,
  the natural trigger) because CLAUDE.md is already over its own 40k-char budget
  (42,991) — trim it in the same rung before adding the row.
- `docs/user-manual/mcp.md` carries a pre-existing gap (missing `get_guardian_schemas`);
  rung 4 documents `get_guardian_status` and closes both.
- **Rung 1:** document `--spark-disable` / `YUZU_AGENT_SPARK_DISABLE` (the per-rung
  default table + the boot-restart requirement) in `docs/user-manual/guaranteed-state.md`
  — a CLI flag is `--help`-discoverable but the posture/defaults are customer-facing
  (enterprise-readiness).
- **Rung 2:** add an interim caveat to `docs/user-manual/guaranteed-state.md` — a
  cross-platform Baseline against an unsupported mechanism (macOS; Linux-without-libsystemd
  for Service; any non-Windows host for File/Registry) shows `pending` through rung 3;
  disambiguate from a non-reporting agent via the fleet gauge / audit-on-arm trail,
  not device liveness (enterprise-readiness).
- **Rung 4:** add `unsupported` to the published status vocab in
  `docs/user-manual/rest-api.md` (`/status`, `/status/{agent_id}`, `/device-compliance`
  `guards[].status`) and `docs/user-manual/guaranteed-state.md`, alongside the
  placeholder-zeros caveat rewrite already noted in the ladder (docs-writer).

## Verification

- Rung acceptance tests as listed; full agent suite green on Linux, Windows
  (DGRHP), **and macOS/Darwin** after each rung. The Darwin suite is mandatory
  (`docs/darwin-compat.md`) because Stage 2 adds macOS-specific behaviour — the
  no-mechanism `unsupported` path (§Platform-rejection — all three mechanisms are
  absent on macOS, so File/Registry/Service rules all reject there) and the
  `--spark-disable` selection — so a macOS-only regression in exactly that path must
  not pass the per-rung gate.
- Parity: Guardian §24 invariant tests pass unchanged; scripted-scenario event
  streams within tolerance (zero-tolerance for enforce types). The
  re-arm/initial-eval contract is a rung-2 parity assertion (offline-drift-caught,
  no restart re-enforce storm).
- Resource: `/test` perf shows the O(rules)→O(mechanisms) real-OS-thread drop at
  rung 2.
- Health surface: `yuzu_fleet_spark_*` os-labelled gauges visible in UAT
  `recompute_metrics`; REST `/guaranteed-state/status[/{agent_id}]` and the
  `get_guardian_status` MCP tool return real per-rule health; a
  `service-status-change` rule (and, being Windows-only, a File/Registry rule) on
  macOS surfaces as `unsupported`, not silent; a killed system bus flips its rules to
  `errored` within the liveness bound.
