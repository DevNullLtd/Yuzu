**D is a credible freeze-sized fix, with two qualifications: compensation-aware suppression needs a small runtime classification change, and a forced full reapply still carries the baseline-recapture risk.** Removing the waiver closes the three described #5459 paths while the generation remains behind the server. It does not provide recovery independent of generation tracking.

I read `origin/dev` at **`4f701cb7821dd03cc20d1a836d4b7af53a5ca577`**, which contains `c9ffc9087`, and the supplied repro branch. All citations below refer to those revisions, not the stale working tree. This is source-read analysis: **no edits, builds, tests, network calls, or governance run**. The reported red/green repro results are your evidence, not executions I performed.

**1. The suppress predicate must validate the entire unresolved set, before applying the empty-pending fallback.**

The current ordering cannot accommodate D: `pending.empty()` returns Reapply before identity checks, and `resolved_failed > 0` returns Reapply before runtime inspection. Both need restructuring. Identity and latched-failure checks remain unconditional exclusions. [guardian_arm_ack.cpp:429](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:429)

For the narrow, genuinely outstanding wedge case, I recommend this shape. `wedge_suppress_count` is a proposed new Application member; everything else uses existing members/accessors:

```cpp
RetryDecision decide_retry(...) { // recommend removing const
    using S = GuardianSparkRuntime::ReceiptStatus;

    if (!current_)
        return Reapply;

    auto& a = *current_;

    if (a.generation != generation ||
        !is_sha256_hex(a.content_id) ||
        !is_sha256_hex(content_id) ||
        a.content_id != content_id ||
        a.full_sync != full_sync)
        return Reapply;

    if (a.latched_failure)
        return Reapply;

    // Every counted failure must have an individually inspectable receipt.
    if (a.resolved_failed != a.failed_receipts.size())
        return Reapply;

    bool has_outstanding_wedge = false;

    for (const auto& [rule_id, receipt] : a.failed_receipts) {
        const auto s = runtime.receipt_status_wedge_aware(receipt);
        if (s.status != S::Wedged || !s.wedge_eligible)
            return Reapply;
        has_outstanding_wedge = true;
    }

    for (const auto& [rule_id, receipt] : a.pending) {
        const auto s = runtime.receipt_status_wedge_aware(receipt);
        if (s.status == S::Pending || s.status == S::Committed)
            continue;
        if (s.status == S::Wedged && s.wedge_eligible) {
            has_outstanding_wedge = true;
            continue;
        }
        return Reapply;
    }

    if (!has_outstanding_wedge) {
        // Preserve the existing empty-application persist-retry escape.
        return a.pending.empty() ? Reapply : Suppress;
    }

    if (a.wedge_suppress_count >= 10)
        return Reapply;

    ++a.wedge_suppress_count;
    return Suppress;
}
```

The Pending loop deliberately also accepts a **live-eligible Wedged receipt not yet drained**. Otherwise the bounded drain would create avoidable full reapplies simply because the wedge still resides in `pending`. The existing loop already consults runtime state for precisely this bounded-drain reason. [guardian_arm_ack.cpp:260](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:260), [guardian_arm_ack.cpp:474](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:474)

The resulting cases are:

| State after identity checks | Decision |
|---|---|
| Empty `pending`; every counted failure is a live outstanding wedge | Suppress, subject to bound |
| Outstanding wedges plus Pending/Committed receipts | Suppress, subject to bound |
| Eligible Wedged receipts still in `pending` | Suppress, subject to bound |
| Wedge plus a drained ordinary failure | Reapply: count/map equality fails |
| Wedge plus an undrained ordinary failure | Reapply: Pending loop detects it |
| Latched application failure | Reapply |
| No pending receipts and no failures | Reapply, preserving persist recovery |
| Changed generation, content, `full_sync`, or invalid digest | Reapply |

These distinctions follow from the existing failure accounting, identity checks, and empty-pending persist-recovery guard. [guardian_arm_ack.cpp:225](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:225), [guardian_arm_ack.cpp:329](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:329), [guardian_arm_ack.cpp:434](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:434)

**The equality is necessary, not sufficient.** With the current map-maintenance contract, `resolved_failed == failed_receipts.size()` means no counted failure lacks a retained candidate receipt. It does **not** prove those candidates remain eligible now. The recovery drain erases Blocking receipts without decrementing `resolved_failed`; consequently a genuine non-wedge failure breaks the equality. Every retained receipt still needs the combined live check. [guardian_arm_ack.cpp:216](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:216), [guardian_spark_runtime.cpp:2333](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2333)

A late-failed, popped claim is not suppressed even **before the next drain**: its sticky status may still say Wedged, but the exact FIFO-front test fails. After the drain, its removal from `failed_receipts` makes the equality fail instead. A completion occurring **after** its live check can cost one additional suppressed push; it cannot permanently stop retries because Suppress does not acknowledge anything. [guardian_spark_runtime.cpp:2307](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2307), [guardian_arm_ack.cpp:232](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:232), [guardian_engine.cpp:1377](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1377)

**Compensation should also qualify for retry suppression, but must remain ineligible for acknowledgement.** The existing accessors cannot distinguish “retained and compensating” from all other Blocking states. Moreover, the current recovery drain destroys the ledger’s receipt handle for that case. Therefore compensation coverage cannot be achieved solely by moving the old predicate. [guardian_spark_runtime.hpp:1518](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1518), [guardian_arm_ack.cpp:245](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:245)

My recommended small extension is:

- Extend existing `WedgeAwareStatus` with `compensation_pending`.
- Extend existing `RecoveryStatus` with `CompensationPending`.
- Compute both classifications through one private helper under `registry_mu_`.
- Retain both outstanding wedges and compensating wedges in `failed_receipts`, in both drain loops.
- In the pseudocode, replace `s.wedge_eligible` with `s.wedge_eligible || s.compensation_pending`.

The proposed compensation predicate is:

```cpp
claim &&
claim->end == ClaimEnd::WaiterTimedOutDispatched &&
claim->dispatch == ClaimDispatch::Dispatched &&
exact_fifo_front(claim) &&
!claim->compensation_finished
```

This extends the existing combined observations rather than adding independent accessors or exposing claim internals to the ledger. `Recovered` must retain first priority in `receipt_recovery_status()`. The compensation marker already becomes false in the completion callback’s first critical section; completion sets it true together with pop or the exceptional Queued hand-back. [guardian_spark_runtime.cpp:1433](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1433), [guardian_spark_runtime.cpp:1317](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1317), [guardian_spark_runtime.cpp:2360](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2360)

With that extension, equality means **all counted failures have retained retry-deferral candidates**, not “all failures are K-eligible.” Rename the documentation accordingly. Do not remove the `compensation_finished` exclusion from the old eligibility predicate and accidentally restore waiver semantics.

**2. Acknowledgement comes from genuine recovery or a fresh successful application.**

Delete the waiver branch entirely:

```cpp
return current_ &&
       current_->pending.empty() &&
       !current_->latched_failure &&
       current_->resolved_failed == 0;
```

That is the existing conservative branch without the K escape. [guardian_arm_ack.cpp:369](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:369)

**Late success, adopted:** the runtime commits the original claim’s generation into `rules_`; its receipt can remain sticky Wedged. `receipt_recovery_status()` detects the exact committed incarnation and returns Recovered. The recovery drain decrements `resolved_failed` and erases the retained receipt. It deliberately does not decrement cumulative failure telemetry. Once other pending work and failures are gone, `can_advance()` becomes true. [guardian_spark_runtime.cpp:1615](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1615), [guardian_spark_runtime.cpp:2238](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2238), [guardian_spark_runtime.cpp:2366](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2366), [guardian_arm_ack.cpp:218](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:218)

The heartbeat maintenance tick then persists the generation **before** publishing it in memory. Failed persistence leaves it behind and is retried on a later tick. `agent.cpp` runs maintenance before reading `yuzu.guardian_generation`, so successful advancement can appear on that heartbeat. [guardian_engine.cpp:1077](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1077), [agent.cpp:2605](/home/dgr/Yuzu/agents/core/src/agent.cpp:2605), [agent.cpp:2635](/home/dgr/Yuzu/agents/core/src/agent.cpp:2635)

There is a conservative extra-reapply case: adoption can occur before the receipt is first drained, or before a retry reads a previously retained receipt. Sticky Wedged plus no live eligibility then fails the suppression test. That can cause unnecessary rearming, but preserves progress. The current primary drain does not translate already-adopted Wedged receipts directly into success. [guardian_arm_ack.cpp:278](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:278), [guardian_arm_ack.cpp:303](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:303)

**Late failure:** the claim pops without recovery. The old application’s `resolved_failed` remains positive, correctly. The next push returns Reapply, and `begin_application()` replaces the entire application, resetting its accounting. The normal reconcile path arms again; success then permits acknowledgement through the apply tail or heartbeat drain. [guardian_spark_runtime.cpp:1798](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1798), [guardian_arm_ack.cpp:144](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:144), [guardian_engine.cpp:1397](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1397), [guardian_engine.cpp:1700](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1700)

Thus **a positive failure count is not inherently permanent**. It is permanent within that failed application until recovery or replacement. I found no new counter-based strand in these paths, assuming full retries continue, the transient fault clears, and persistence eventually succeeds. Permanent backend failure, permanent compensation hang, or continuing persistence failure can still hold the generation indefinitely.

The supplied probe explicitly supplies a fresh push after the late failure and checks a second watch and one correct live subscription. I read that test, but did not rerun it. [repro test:4558](/home/dgr/yuzu-5459/tests/unit/test_guardian_engine_spark_reconcile.cpp:4558)

**3. I recommend a bound of ten wedge/compensation Suppress decisions per Application, then Reapply.**

This is a proposed safety bound, not an empirically tuned value:

- Store `std::size_t wedge_suppress_count{0}` in `Application`.
- Increment only when taking the new wedge/compensation suppression branch.
- After ten such decisions, the next otherwise-suppressible push returns Reapply.
- Reset through successful `begin_application()` replacement or `retire()`.
- Do not reset on heartbeat drains, another suppressed push, or individual sibling recovery.

Application already persists across suppressed pushes because the early return precedes `begin_application()`. Both retry decisions and heartbeat drains run under the engine mutex. [guardian_engine.cpp:1324](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1324), [guardian_engine.cpp:1377](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1377), [guardian_engine.cpp:1048](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1048)

I would make `decide_retry()` non-const to state its new behavior honestly. No atomic is needed under that locking contract. Technically, `const` on the ledger does not make the object behind its `unique_ptr<Application>` const, so `mutable` is not strictly required; relying on that would nevertheless obscure the mutation. [guardian_arm_ack.hpp:326](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.hpp:326), [guardian_arm_ack.hpp:391](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.hpp:391)

At evenly spaced server retries, ten suppressions followed by a forced eleventh retry means roughly **275 seconds at 25-second spacing, or 330 seconds at the default 30-second heartbeat**, measured from the preceding application. This is a decision-count bound, not an offline wall-clock guarantee. Ordinary Pending-only suppression retains its existing behavior. [server.cpp:5816](/home/dgr/Yuzu/server/core/src/server.cpp:5816), [agent.hpp:19](/home/dgr/Yuzu/agents/core/include/yuzu/agent/agent.hpp:19)

A forced full reapply performs the real KV sweep, teardown and rearm of the entire pushed set. It can regenerate lifecycle/compliance events and recapture unpersisted Spark baselines. The identical wedged rule ordinarily returns the **existing claim** through Reobserved; forcing Reapply does not cancel, restart, or unstick its worker. [guardian_engine.cpp:1441](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1441), [guardian_engine.cpp:1551](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1551), [guardian_spark_runtime.cpp:2977](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2977)

Therefore this valve bounds dependence on ledger suppression. It is **not** a recovery guarantee against a runtime classifier that indefinitely misidentifies a dead claim.

**4. Delete waiver machinery, preserve recovery accounting, and adapt tests around behavior.**

Production changes should include:

- Delete `kReapplyWaiverThreshold`, the carry-forward/cap logic, `Application::reapply_count`, its test accessor, and the waiver branch.
- Keep `failed_receipts` and genuine-recovery decrementing. With compensation coverage, broaden its retention contract as described above.
- Preserve `arm_stats().failed`, Pending accounting, and cumulative `arm_failures_`. Suppression must not erase failure evidence.
- Update stale comments describing empty `pending` as invariably Reapply or every failure as requiring immediate Reapply.

The relevant definitions and accounting are at [guardian_arm_ack.hpp:85](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.hpp:85), [guardian_arm_ack.hpp:375](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.hpp:375), [guardian_arm_ack.cpp:129](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:129), [guardian_arm_ack.cpp:401](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:401), and [guardian_arm_ack.cpp:411](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:411).

The existing test disposition should be:

| Test | Disposition |
|---|---|
| `decide_retry(): identical ... while every receipt is still pending is Suppressed`, `test_guardian_arm_ack.cpp:326` | Keep identity, sentinel and Pending coverage |
| `decide_retry(): once a pending receipt resolves to a failure ... Reapply`, `:368` | Keep ordinary-failure coverage; distinguish eligible wedges in naming |
| `decide_retry(): an EMPTY pending map is always Reapply`, `:459` | Adapt title to “no pending or retained outstanding work”; preserve its persist-retry assertion |
| `drain_locked(): ... ADOPTS its late success ...`, `:742` | Keep; add acknowledgement after repeated suppressed pushes |
| `drain_locked(): ... later WITHDRAWN ...`, `:805` | Keep accounting behavior; adapt eligibility terminology |
| `can_advance(): K-bound waives ...`, `:960` | Replace with “never acknowledges an outstanding wedge,” including beyond the old K |
| `can_advance(): a non-Wedged failure blocks K-waiver ...`, `:1040` | Adapt into mixed-failure Reapply and no-ack test |
| `can_advance(): reapply_count funded by an unrelated ... failure ...`, `:1122` | Delete obsolete funding characterization |
| `begin_application(): reapply_count resets ...`, `:1224` | Remove K assertions; retain fresh-accounting isolation and add suppression-budget reset coverage |
| `drain_locked(): ... later resolves to a real backend refusal ...`, `:1324` | Keep; add Reapply **before** another drain |
| `can_advance(): latch_failure() blocks ...`, `:1387` | Keep unconditional block; remove K setup |
| `can_advance(): K-eligibility linearizes at the drain-time read ...`, `:1437` | Replace permissive waiver expectation with no-ack and eventual-Reapply assertions |
| `receipt_status_wedge_aware(): a real concurrent poller ...`, `:1498` | Keep; extend for compensation classification |
| Engine `rung 9c PR-5e ... K-bound waives ...`, `test_guardian_engine_spark_reconcile.cpp:4096` | Replace with held-generation plus no-teardown suppression test |
| Engine `#4472 ... outstanding ...` and control, `:3421`, `:3427` | Keep end-state requirements; adapt setup and assert compensation-period suppression |

These are existing test names/locations in [test_guardian_arm_ack.cpp](/home/dgr/Yuzu/tests/unit/test_guardian_arm_ack.cpp:326) and [test_guardian_engine_spark_reconcile.cpp](/home/dgr/Yuzu/tests/unit/test_guardian_engine_spark_reconcile.cpp:3421).

There is additional cleanup outside the two files named in the brief: the runtime test rig asserts the K counter; its compensation recovery test expects Blocking plus receipt erasure; and its accepted-cost characterization expects inherited K credit. Adapt the rig and compensation test, delete the funding characterization, and preserve the compensation marker/age/stop/tripwire tests. [test_guardian_spark_runtime.cpp:14258](/home/dgr/Yuzu/tests/unit/test_guardian_spark_runtime.cpp:14258), [test_guardian_spark_runtime.cpp:14480](/home/dgr/Yuzu/tests/unit/test_guardian_spark_runtime.cpp:14480), [test_guardian_spark_runtime.cpp:14850](/home/dgr/Yuzu/tests/unit/test_guardian_spark_runtime.cpp:14850), [test_guardian_spark_runtime.cpp:14890](/home/dgr/Yuzu/tests/unit/test_guardian_spark_runtime.cpp:14890)

New red-first coverage should establish:

- Empty-pending outstanding wedge suppression, and undrained Wedged suppression.
- Wedge plus Pending/Committed siblings; multiple wedges.
- Mixed ordinary failures, both drained and undrained.
- Late pop before retry without an intervening drain.
- Pop racing the live read: at most a delayed retry, never acknowledgement.
- Compensation beginning before first drain and after receipt retention; both remain tracked and suppressed until pop.
- Suppression bound and resets.
- Healthy sibling watch/unwatch counts, lifecycle events, and baseline remain unchanged during suppressed pushes.
- Late refusal, throw, failed adoption with compensation, and successful adoption through the real engine.
- Legacy empty-application failed-generation-persist recovery remains intact.

The repro’s existing “no further push” expectation must change for D. Its own harness explicitly anticipates replacing the K-established precondition. Drive a server-like push **only while reported generation is behind**, then assert actual correct subscription ownership and eventual persisted acknowledgement. Merely changing `require_k_established()` would leave the tests testing C’s recovery contract. [repro test:4336](/home/dgr/yuzu-5459/tests/unit/test_guardian_engine_spark_reconcile.cpp:4336), [repro test:4399](/home/dgr/yuzu-5459/tests/unit/test_guardian_engine_spark_reconcile.cpp:4399)

Documentation needs coordinated changes in R5.3, the flip gate’s waiver/#5459/funding/accepted-cost rows, the A3 delta-registry entries, and the operator manual. The cross-rule K-funding ruling becomes **moot because its mechanism is deleted**, not accepted by default. [spark-stage2-guardian-consumer-design.md:900](/home/dgr/Yuzu/docs/spark-stage2-guardian-consumer-design.md:900), [spark-flip-gate.md:911](/home/dgr/Yuzu/docs/spark-flip-gate.md:911), [spark-flip-gate.md:984](/home/dgr/Yuzu/docs/spark-flip-gate.md:984), [spark-legacy-delta-registry.md:145](/home/dgr/Yuzu/docs/spark-legacy-delta-registry.md:145), [guaranteed-state.md:462](/home/dgr/Yuzu/docs/user-manual/guaranteed-state.md:462)

**5. D reduces endpoint churn, but retains server traffic and several recovery limits.**

**Wrongly persistent suppression** can arise from checking sticky Wedged alone, trusting stale map membership, accepting equality vacuously, ignoring unmatched failures, accepting Dispatching rather than Dispatched, or confusing a held compensation permit with an outstanding compensation. The combined classification and whole-set checks above address those specific mistakes. [guardian_spark_runtime.cpp:2307](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2307), [guardian_arm_ack.cpp:263](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:263)

**Server cost remains.** Suppress happens after the server has read generation, listed rules, resolved deployed membership, filtered/built the push, and sent it. A successful audited send writes `guaranteed_state.reconcile`. “At least two PG reads plus an audit row” is a lower bound; deployed-membership and scope work add cost. Also, the generation read occurs **before** rate limiting. [server.cpp:5796](/home/dgr/Yuzu/server/core/src/server.cpp:5796), [server.cpp:5844](/home/dgr/Yuzu/server/core/src/server.cpp:5844), [server.cpp:5888](/home/dgr/Yuzu/server/core/src/server.cpp:5888), [server.cpp:5985](/home/dgr/Yuzu/server/core/src/server.cpp:5985)

At the default heartbeat, an indefinitely held endpoint still produces approximately 2,880 reconciles/day; 10,000 held endpoints imply roughly 333 pushes and audit rows/second. These are cadence calculations, not measured throughput. The existing cost analysis records the same scale. [spark-flip-gate.md:959](/home/dgr/Yuzu/docs/spark-flip-gate.md:959)

I would **exclude escalating server backoff from the freeze patch**. A 300-second ceiling could materially reduce push, rule-read and audit work, but would not remove the pre-throttle generation read. Without a new completion signal, it also delays rearming after late failure by up to approximately that retry interval, plus heartbeat scheduling and arm time. A later server change should reset backoff on policy changes and define restart/session behavior explicitly.

**Partial pushes need two distinctions.**

- Switching between delta and full sync changes identity, so it correctly forces Reapply.
- A delta that omits a still-desired, previously unresolved rule can replace the sole Application and lose that rule’s acknowledgement obligation. A newer successful application could then advance generation and stop full-sync recovery.

That second issue is an existing limitation of whole-Application replacement, not solved by D. The protocol permits delta merge, while `begin_application()` retains no prior receipts. The normal server builder reads the applicable deployed inventory, so I have **not established a current production route emitting the specific omitting delta**. It nevertheless belongs in the recovery contract and a targeted test. [guaranteed_state.proto:54](/home/dgr/Yuzu/proto/yuzu/guardian/v1/guaranteed_state.proto:54), [guardian_arm_ack.cpp:144](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:144), [server.cpp:19557](/home/dgr/Yuzu/server/core/src/server.cpp:19557)

**Multiple hung rules** are handled by universal receipt checks. One popped failure forces Reapply even if others remain wedged. Multiple compensations can exhaust a type’s capacity; resulting congestion expiries are ordinary failures and must force Reapply. Thus D does not eliminate full-sync churn in mixed wedge/congestion-failure applications. [guardian_arm_ack.cpp:332](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:332), [spark-flip-gate.md:993](/home/dgr/Yuzu/docs/spark-flip-gate.md:993)

**A never-returning arm holds generation forever.** That is the intended replacement for waiver, not evidence of progress. The existing Pending/Failed tags expose current Application accounting, but are not durable per-rule recovery status. Forced Reapply resets them, potentially producing sampled dips. [guardian_arm_heartbeat.hpp:29](/home/dgr/Yuzu/agents/core/src/guardian_arm_heartbeat.hpp:29)

**AC-1, #5403 and #5404:** compensation-aware suppression reduces AC-1’s endpoint churn without ending its hold. Preserve compensation age/deadline signals, ordinary Disarm age/deadline signals, and claim-lifecycle counters. Ordinary Disarm age does not describe an Arm claim awaiting compensation; the compensation gauges are separate for that reason. These signals observe stuck work; they do not release it. [guardian_health_heartbeat.hpp:68](/home/dgr/Yuzu/agents/core/src/guardian_health_heartbeat.hpp:68), [guardian_health_heartbeat.hpp:126](/home/dgr/Yuzu/agents/core/src/guardian_health_heartbeat.hpp:126), [spark-flip-gate.md:952](/home/dgr/Yuzu/docs/spark-flip-gate.md:952)

**Restart gap remains.** Boot loads the persisted generation and opens a boot application at that value. Failure cannot lower it. If it already equals the server’s current generation, server reconcile returns without a push. D therefore does not repair boot rearm failure or retroactively revoke an acknowledgement written by the old waiver implementation. [guardian_engine.cpp:664](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:664), [guardian_engine.cpp:672](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:672), [server.cpp:5806](/home/dgr/Yuzu/server/core/src/server.cpp:5806)

**Baseline relaundering is avoided on suppressed pushes, not eliminated.** The early return precedes teardown and rearm. However, required and safety-valve Reapply still rebuild evaluation state. The remaining #4045 case is specifically a Spark-captured baseline without a persisted legacy seed or explicit expected hash; it is not every no-expected rule. [guardian_engine.cpp:1377](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1377), [guardian_engine.cpp:166](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:166), [guardian_engine.cpp:2450](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2450), [guardian_rule_eval.cpp:94](/home/dgr/Yuzu/agents/core/src/guardian_rule_eval.cpp:94)

**6. The proposed D preserves the Spark row invariants and removes the waiver-specific drain-to-persist hazard.**

For the implementation described here:

- All actual rearming still passes through `reconcile_rule_locked()`.
- The Spark branch still withdraws legacy ownership before attaching.
- Arm failure still returns Failed; it does not fall back.
- Stopped engines still reject pushes.
- Suppression neither cancels workers nor releases claims, subscriptions, or compensation permits.
- Runtime observations take `registry_mu_` from the existing engine-owned path; no completion callback gains an engine-mutex acquisition.
- F3 physical-worker accounting remains unchanged.

These conclusions follow from the proposed change boundary and the existing chokepoints, rather than executed invariant tests. [guardian_engine.cpp:1324](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1324), [guardian_engine.cpp:1598](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1598), [guardian_engine.cpp:2500](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2500), [guardian_engine.cpp:2536](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2536), [guardian_spark_runtime.cpp:1365](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1365), [yuzu-guardian-design-v1.1.md:2471](/home/dgr/Yuzu/docs/yuzu-guardian-design-v1.1.md:2471)

The three #5459 subclasses resolve as follows:

| Subclass | Effect of D |
|---|---|
| Hung arm later refuses or throws | No waiver; after pop the next retry reapplies |
| Late success cannot be adopted | Generation remains held through compensation; after pop the next retry reapplies |
| Failure between eligibility drain and generation persistence | Counted failure prevents `can_advance()` entirely; there is no waiver-derived persist to race |

For the third, **the specific gap is genuinely removed, not relocated**. A drain-time eligibility observation no longer authorizes acknowledgement. A counted wedge keeps `resolved_failed > 0`; only recorded recovery or a new successful Application removes that obstacle. A retry-check/completion race can delay one push, but cannot publish a false advancement. [guardian_arm_ack.cpp:218](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:218), [guardian_arm_ack.cpp:369](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:369), [guardian_engine.cpp:1081](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1081)

My severity assessment for the original defect on the Spark-enabled path is:

- **Trigger:** dispatched timed-out arm is waived, then fails, fails adoption, or completes unsuccessfully in the waiver-to-persist window.
- **Impact:** I1 when the desired rule is a security control; I5 for the permanently stranded recovery state machine. I5(c) independently raises that state-machine wedge to HIGH.
- **Exposure:** E4 for current non-default Spark enforcement; E5 for the hang/failure/interleaving; ordinary operator deployment and automatic heartbeat/completion processing introduce no demonstrated E1/E2 escalation.
- **Epistemic status:** **likely**, based on code read. Your repro supplies additional reported execution evidence.
- **Derived band:** HIGH for the enabled-path defect. E4/E5 do not discount it.

The derivation rules explicitly distinguish source reasoning from executed verification and make state-machine wedges HIGH. I would not add I3 solely because generation was acknowledged: the documented old contract explicitly allowed acknowledgement without enforcement. [governance severity rules:193](/home/dgr/Yuzu/.claude/skills/governance/SKILL.md:193), [governance severity rules:238](/home/dgr/Yuzu/.claude/skills/governance/SKILL.md:238), [governance severity rules:255](/home/dgr/Yuzu/.claude/skills/governance/SKILL.md:255), [spark-stage2-guardian-consumer-design.md:651](/home/dgr/Yuzu/docs/spark-stage2-guardian-consumer-design.md:651)

D removes those triggers under the held-generation/full-retry assumptions. That is a design conclusion, **not a finding-closure or merge-readiness claim**. Restart and omitted-delta obligations need separate treatment.

**7. The likely size is a few days, but not a two-line deletion.**

My planning estimate, excluding prose and fixture reuse variability:

| Scope | Production code added/changed | Tests added/adapted |
|---|---:|---:|
| Wedge-only D with bound | 50-100 lines | 350-600 lines |
| Recommended compensation-aware D | 100-180 lines | 600-1,000 lines |
| Waiver cleanup | Additional deletions and comment updates | Remove obsolete funding assertions/cases |

The extra compensation scope is concentrated in the existing combined status types, two drain loops, retry classification, and their tests. No new thread, scheduler, durable recovery store, or arm entry point is required by this proposal. [guardian_spark_runtime.hpp:1433](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1433), [guardian_spark_runtime.hpp:1523](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1523), [guardian_arm_ack.cpp:216](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:216)

**Estimate: three to five engineering days including tests, documentation and review corrections; medium confidence.** Cross-platform validation and governance scheduling can extend elapsed time. I would not promise two days including governance.

I would recommend C instead if the acceptance criteria require any of:

- Recovery without a server connection.
- Recovery after previously acknowledged boot rearm failures.
- Recovery across arbitrary partial-application replacement.
- Rearming only failed rules, without healthy-rule teardown or baseline recapture.
- Bounded recovery despite unacceptable full-push fleet cost.
- A durable per-desired-rule recovery owner rather than generation-based retry ownership.

**8. Three points in the framing need explicit correction.**

First, “move the waiver predicate” understates the compensation work. Keeping the current pruning behavior loses exactly the handles needed to suppress during compensation. The runtime/ledger classification extension must be part of the design, or compensation churn must be an explicitly retained limitation. [guardian_arm_ack.cpp:245](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:245)

Second, “suppression avoids baseline relaundering” is true **per suppressed push**. A mandatory periodic Reapply intentionally reintroduces that exposure. That cost should be recorded beside the safety-valve decision, not hidden under a generic retry-cost statement. [guardian_engine.cpp:166](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:166)

Third, acknowledgement still does not mean every desired rule is enforced: Inert/Unsupported outcomes remain outside accepted-arm failure accounting. D removes the dispatched-wedge waiver; it does not redefine all generation semantics. [guardian_engine.cpp:1609](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1609)

My confidence is **high** in the core counter/retry/acknowledgement trace, **medium-high** in the compensation extension as specified, and **medium** in the delivery estimate. The remaining proof obligation is executed coverage of the live-read races, compensation retention, healthy-sibling preservation, and all three adapted #5459 scenarios.