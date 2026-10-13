**Recommendation: fix before the freeze that enables the hard cutover. Start with the red-first reproduction, then implement C narrowly around these failed episodes. I would not accept A as proposed, or treat B as a safe decrement-and-retry patch.** B can work, but making it reliable introduces a recovery lifecycle that substantially erodes its apparent simplicity.

This is source-read analysis, not execution evidence. `gh issue view 5459 --repo DevNullLtd/Yuzu` failed to connect. I used your issue summary and `git show origin/dev:<path>` at **`f79ba8d13222fce1097ca984c63b1ee85d5e7180`**. No files were modified, tests run, or governance pipeline invoked. All line references below refer to that snapshot, not the stale working tree.

**A. The mechanism is real, with qualifications about production reachability. Confidence: high on the state transitions; medium on which current real mechanism could supply the initial prolonged call.**

The acknowledgement chain is explicit:

1. `begin_application()` inherits and increments the counter only for identical generation/content/full-sync identity, saturating at three. Normally this means the original application plus three reapplications. [`guardian_arm_ack.cpp:129–158`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L129)
2. K eligibility requires `WaiterTimedOutDispatched`, `Dispatched`, no outstanding compensation, and the exact claim still at its key’s FIFO front. [`guardian_spark_runtime.cpp:2307–2330`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L2307)
3. The ledger permits advancement when there are no pending receipts or latched failures, and every counted failure belongs to the sampled K-eligible set with sufficient reapplications. [`guardian_arm_ack.cpp:369–386`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L369)
4. The heartbeat tick persists and publishes the higher generation. Subsequent server reconciliation returns immediately when `agent_gen >= current`. [`guardian_engine.cpp:1077–1093`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1077), [`server.cpp:5796–5807`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/server/core/src/server.cpp#L5796)

The three subclasses behave as follows.

| Subclass | Source-read conclusion | Required conditions |
|---|---|---|
| Late backend refusal or worker exception | No subscription is available to adopt. The completed claim is popped; no replacement arm is created. | A genuinely dispatched, overdue operation that was K-waived, followed by failure. |
| Late success whose adoption fails | Allocation/index/commit failure leaves the subscription owned by compensation. Compensation eventually publishes/pops the claim without recreating the desired rule. | The same K premise, plus an ordinary failure such as allocation pressure during adoption. |
| Completion between eligibility sampling and persistence | The tick can acknowledge using its earlier eligibility snapshot. The next tick recognizes the blocking failure but does not undo the acknowledged generation. | The same eligible-wedge premise, plus ordinary callback/tick interleaving. No additional mechanism violation is needed for the gap itself. |

There is a significant terminology correction in the first row: **a late refusal does not necessarily change the receipt to `BackendRefused`, and a late exception does not necessarily change it to `WorkerThrew`.** The wedged head is already terminal. With no live followers, `live.empty()` selects the earlier branch; publication skips an existing outcome. Its observable receipt remains `Wedged`, while its claim disappears. That is why recovery must not depend on observing a new `ReceiptStatus::Failed`. [`guardian_spark_runtime.cpp:1495–1498, 1656–1695`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L1656), [`guardian_spark_runtime.cpp:1222–1255`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L1222)

The runtime tests already characterize both late returned failure and late throw as leaving zero rules, no recovery, and a sticky `Wedged` receipt. They do not establish end-to-end K acknowledgement or autonomous repair. [`test_guardian_spark_runtime.cpp:12468–12486`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_spark_runtime.cpp#L12468)

For adoption failure, the production branch contains real fallible operations: `index_->add`, allocation, map insertion, and `commit_new_generation_locked`. Fault point 12 exercises that branch; it does not manufacture an otherwise unreachable cleanup path. The catch leaves compensation responsible for the subscription. [`guardian_spark_runtime.cpp:1589–1646`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L1589) `finalize_arm_compensation()` publishes the finished claims and drives any existing follower; it does not manufacture a fresh desired-rule claim. [`guardian_spark_runtime.cpp:1305–1362`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L1305)

For the sampling gap, the existing test explicitly releases a refusal after `drain_locked()`, observes that `can_advance()` remains true, then observes it become false only after another drain. The engine’s persistence follows that same decision. This is source-supported, not merely a hypothetical race. [`test_guardian_arm_ack.cpp:1437–1495`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_arm_ack.cpp#L1437)

**Reachability qualification:** a mechanism actually blocking inside `watch()`/`unwatch()` through the usual K retry period violates the documented bounded-call contract. I have not demonstrated such a violation in a currently shipped real mechanism. All three scenarios nevertheless use production control paths once that fault exists. The subsequent refusal, allocation failure, and sampling interleaving require no test-only index corruption. [`spark_mechanism.hpp:211–235`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/spark_mechanism.hpp#L211)

Nor does K eligibility prove that a mechanism itself is stuck: it observes dispatch/claim state. Backend calls can wait on Spark’s per-type serialization, and the backend-return-to-completion-lock window remains observable as eligible. Thus I would not claim “every occurrence proves a hung bounded syscall.” [`spark_engine.cpp:940–962`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/spark_engine.cpp#L940), [`spark-flip-gate.md:997–1000`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-flip-gate.md#L997)

Also, a mechanism throw normally becomes a **returned backend failure** through `watch_guarded()`. A true executor `WorkerThrew` requires an exception escaping the backend body, not merely `throw_next_watch()`. The production adapter permits propagation, but the relevant escaping cases are narrower. [`spark_engine.cpp:134–158, 727–734`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/spark_engine.cpp#L134), [`guardian_io_executor.hpp:680–704`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_io_executor.hpp#L680)

**B. Acknowledged-but-unarmed is a stable end state without an external recovery trigger. Confidence: high.**

I found these possible recovery paths:

| Path | Does it repair this state? |
|---|---|
| Late successful adoption | Yes, when adoption succeeds for the correct incarnation. This is a different outcome from the failed cases. |
| Ledger recovery scan | Updates accounting for a recovered incarnation. For a blocking outcome it removes the eligible receipt while leaving `resolved_failed` counted. It does not arm anything. |
| Convergence lanes | No. They evaluate keys already present in the runtime and pending initial evaluations on those keys. |
| Parked-arm and retained-disarm redrives | No, after this claim has been popped. They operate on retained/queued claims, not persisted desired rules. |
| Heartbeat reaper/orphan pass | No. It releases terminal queued claims, drives existing followers, and disarms orphan watchers. |
| Subscription-health polling | No. It detects and detaches dead subscriptions; it does not reconstruct missing desired rules. |
| Reconnection | No by itself. `sync_with_server()` logs state; reconciliation still depends on reported generation lag. |
| A subsequent applicable push | Can repair it, once the old operation/compensation permits another arm. Identical content is sufficient if a push actually arrives. |
| Process restart | Attempts to re-arm cached rules. It is not guaranteed repair if the underlying failure persists. |

The relevant implementation boundaries are explicit: ledger recovery only changes bookkeeping; convergence enumerates runtime keys; redrive enumerates claims; orphan cleanup creates **Disarm** claims. [`guardian_arm_ack.cpp:216–255`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L216), [`guardian_convergence_scheduler.cpp:123–159`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_convergence_scheduler.cpp#L123), [`guardian_spark_runtime.cpp:923–944, 2669–2711`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L2669)

I found only two production callers of `reconcile_rule_locked()`: the startup walk and `apply_rules()`. The heartbeat tick contains no desired-rule reconciliation pass. [`guardian_engine.cpp:789, 1031–1110, 1598`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L789)

Two qualifications matter:

- “Until a **distinct** push” is overly restrictive. `decide_retry()` returns `Reapply` when pending is empty or a failure is counted. An explicitly delivered identical push can therefore recover it. What is absent is the automatic delivery trigger. [`guardian_arm_ack.cpp:455–473`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L455)
- Restart can make one fresh attempt, but startup loads the persisted generation and opens its application at that same generation. If startup rearming fails, the server can still see “caught up.” Restart is an attempted remediation, not a guaranteed retry owner. [`guardian_engine.cpp:664–697, 789–818`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L664)

I verified the orphan-pass behavior directly. I could not establish its association with issue **#5405** from this snapshot; the implementation and nearby documentation attribute that work to **#5322**.

**C. Reopening the generation is feasible, but the suggested minimal forms are incomplete. Confidence: high on the identified hazards; medium on the comparative implementation cost.**

**Lowering `policy_generation_` is not inherently an immediate ordering violation**, because `apply_rules()` does not reject a push merely for having an equal or lower generation. The `>` condition gates acknowledgement advancement, not application of the rules. A same-generation replay can therefore arm the rule. [`guardian_engine.cpp:1323–1398, 1700–1703`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1323)

But a bare decrement is not a complete mechanism:

- **Persistence:** decrementing only memory disagrees with the durable marker. Persisting the decrement changes the current monotonic acknowledgement model and needs its own failure handling. The existing persist-before-publish guarantee concerns advancement; a failed invalidation must not silently suppress recovery. [`guardian_engine.cpp:1083–1093, 1882–1884`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1083)
- **Re-advancement:** lowering the value while the old sampled ledger still permits advancement allows a later tick to restore it without a new arm. You must invalidate or track the acknowledgement decision, not just alter the integer. [`guardian_arm_ack.cpp:369–386`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L369)
- **Delivery:** reporting lag for only the next heartbeat loses the request if rate-limited, disconnected, or followed by a degraded store read/send failure. The server claims its 25-second slot before checking the session and building/sending the push. [`server.cpp:5810–5848, 5967–5970`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/server/core/src/server.cpp#L5810)
- **Repeated failures:** clearing the request when a push arrives strands the rule again if that attempt fails. Clearing it at synchronous `apply_rules()` success is also wrong because accepted arms settle asynchronously. [`guardian_engine.cpp:1620–1634`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1620)
- **Multiple rules and concurrent pushes:** repeated `--generation` operations are wrong. Recovery must coalesce obligations and distinguish policy generation, application identity, and runtime rule incarnation. `begin_application()` replaces the whole current ledger; a later partial push can otherwise erase the only observation of an older unresolved rule. [`guardian_arm_ack.cpp:129–158`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L129)

A defensible **B′** would instead have this contract:

1. Keep the persisted acknowledged high-water generation unchanged.
2. Retain an identity-bound recovery obligation when a waived episode becomes unadopted.
3. While repair is due, repeatedly report a capped reconciliation generation, such as `min(high_water, affected_generation - 1)`, rather than decrementing repeatedly.
4. Transfer that obligation to the replacing application only when that application actually covers the affected desired rule. Retire it on demonstrated recovery or authoritative withdrawal/supersession, not mere push receipt.
5. Handle reboot explicitly: persist the obligation or reconstruct equivalent recovery ownership during startup. Handle generation zero explicitly; unsigned subtraction cannot request reconciliation below zero.

That would touch:

- `GuardianArmAckLedger::drain_locked()`, `begin_application()`, and new acknowledgement/recovery bookkeeping in `guardian_arm_ack.{hpp,cpp}`.
- `GuardianEngine::journal_maintenance_tick()`, `apply_rules()`, `start_local()`, `stop()`, and a dedicated reconciliation-generation accessor.
- The heartbeat tag emission at `agent.cpp:2635`.
- A runtime status accessor capable of distinguishing compensation still outstanding from completed-unadopted failure.

The last item is necessary because today’s `RecoveryStatus::Blocking` deliberately combines withdrawal, settled refusal, and outstanding compensation. Treating all three as “retry now” would reintroduce churn during compensation. [`guardian_spark_runtime.hpp:1500–1524`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.hpp#L1500)

**Ledger accounting needs explicit ownership transfer.** Simply adding a fresh pending receipt leaves the old `resolved_failed` contribution behind. Simply retaining it in `failed_receipts` incorrectly labels a settled failure K-eligible. There is no current `retire_failure(rule_id)` operation: `retire()` discards the entire application. A new retirement operation should be guarded by episode/application identity, so an old completion cannot clear a newer failure. [`guardian_arm_ack.cpp:232–255, 329–336, 488–491`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L232)

Starting a fresh application alone also does nothing to dispatch an arm. Moreover, with its generation equal to the already acknowledged generation, the tick’s `gen > policy_generation_` condition does nothing to restore server retries. [`guardian_engine.cpp:1081–1093`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1081)

Finally, **“one push per late failure” is a successful-case estimate, not a guarantee**. B′ requires retries until delivery and settlement, and each server repair is a full sync that tears down and rebuilds the applicable set. Several failures can coalesce into one push; one persistent failure can cause many. [`server.cpp:5953–5958`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/server/core/src/server.cpp#L5953), [`guardian_engine.cpp:1551–1554`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_engine.cpp#L1551)

**D. The derived band is HIGH for the enabled behavior. Accepting A is not my recommendation. Confidence: high.**

The derivation is:

- **Trigger:** a desired rule’s genuinely outstanding arm is K-waived; its completion subsequently fails or cannot be adopted; no covering push or restart follows.
- **Impact:** I5(c), a desired-state machine stranded without a retry transition, raises to **HIGH**. For a security-enforcing rule, I1 independently supplies **HIGH**.
- **Exposure:** environmental failure/race is E5 and supplies no downgrade. An authorized deployment supplies no downgrade either. I have not established an E1/E2 escalation that would justify CRITICAL.
- **Epistemic status:** **likely**, meaning reasoned from source actually read. Under the stated framework that gates normally; it is not `verified`.

Those classifications follow the impact, exposure, and epistemic definitions directly. [`governance/SKILL.md:193–211, 238–269`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/.claude/skills/governance/SKILL.md#L193)

I would not add I3 merely because the generation is acknowledged: the documented contract explicitly says acknowledgement is not enforcement/compliance. The loss of recovery is enough to derive HIGH without overstating what the acknowledgement claims. [`spark-stage2-guardian-consumer-design.md:651–658`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-stage2-guardian-consumer-design.md#L651)

Zero current rules and no production fleet reduce immediate exposure; they do not prove the enabled wrong outcome impossible. Under your hard-cutover ruling they provide no E6 argument. The governance policy also says a derived HIGH is fixed or the enabling change withdrawn/re-cut; a risk-register entry alone is not a waiver. [`governance/SKILL.md:287–291, 1232–1235`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/.claude/skills/governance/SKILL.md#L1232)

The flip document explicitly leaves the operator’s decision open. My advice is **choose recovery**. “Revisit before first production rollout” is too weak when that revisit would occur after a freeze covering every place the repair might need to land. If recovery cannot be completed, postpone/re-cut the enabling cutover rather than describe the remaining HIGH as resolved.

**E. C costs more local machinery, but B′ changes more protocol semantics. Confidence: medium on effort; high on the architectural distinction.**

| Dimension | Sound B′ | Narrow C |
|---|---|---|
| Recovery owner | Agent obligation plus server reconciliation | Agent tick |
| Repair scope | Full applicable rule set | Affected desired rule |
| Network dependency | Required | None for locally cached desired state |
| New complexity | Revocable reporting, delivery/settlement tracking, restart semantics | Per-rule work retention, backoff, budget, accounting |
| Existing generation semantics | Must be extended | Can remain unchanged |
| Persistent ordinary refusal | Repeated full sync unless additionally controlled | Bounded local attempts with backoff |

These follow from the full-sync server path and the existing sole arm chokepoint. [`server.cpp:5922–5953`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/server/core/src/server.cpp#L5922), [`.claude/routed-concerns.md:25`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/.claude/routed-concerns.md#L25)

**I recommend C limited to identified failed episodes, not a new periodic scan of every KV rule.** Its minimum sound shape is:

- Retain a recovery candidate across the loss of K eligibility.
- Wait until the original arm/compensation has settled safely.
- Under `GuardianEngine::mtx_`, reread current desired state and reconcile through `reconcile_rule_locked()`.
- Keep ownership through subsequent refusal, with deduplication, backoff, and a per-tick budget.
- Retire the matching failure contribution on replacement/recovery without clearing unrelated application failures.
- Cancel obsolete work on withdrawal/supersession and honor sticky stop.

The natural touchpoints are `drain_locked()` and its bookkeeping, `receipt_recovery_status()` or a separate recovery snapshot, `journal_maintenance_tick()`, `apply_rules()`, `stop()`, and the existing `reconcile_rule_locked()`. Completion callbacks must remain free of `GuardianEngine::mtx_`; that prohibition protects shutdown and detached-worker lifetime. [`yuzu-guardian-design-v1.1.md:2471–2481, 2519–2528`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/yuzu-guardian-design-v1.1.md#L2471)

**Do not defer C’s recovery ownership past the flip merely because B looks smaller.** If a fully tested B′ genuinely closes the same cases, C can become a later efficiency improvement. On the source evidence available here, narrow C is the cleaner pre-freeze choice.

**F. Minimal red-first test and false-green traps. Confidence: high on test structure; execution remains outstanding.**

Use two layers.

**Engine regression:**

1. Build on the existing engine K-waiver test with `prefer_spark=true`, a positive generation, one enabled supported rule, and a backend/mechanism gate.
2. Prove the first arm entered its real call and remains outstanding.
3. Expire it, then deliver the three identical reapplications and heartbeat drains. Assert the generation stays behind before K and becomes acknowledged at K; assert it was persisted.
4. Only after acknowledgement, release the call into failure.
5. Make subsequent attempts succeed.
6. Drive the permitted maintenance paths. Require the correct rule and desired target/incarnation to have a live subscription, with failure accounting retired appropriately.

The existing engine test supplies steps 1–3 but ends while the call remains parked. Extending that test is materially different from rerunning #4472’s compensation-before-waiver scenario. [`test_guardian_engine_spark_reconcile.cpp:4096–4159`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_engine_spark_reconcile.cpp#L4096)

**There is a specification conflict to settle in the test contract:** literal “no extra server push after acknowledgement” is appropriate for C and necessarily fails B. For B, permit no **manual or unconditional** push; model the server predicate/rate limit, and allow a repair push only after the agent’s changed report actually triggers it. Add dropped/rate-limited/degraded attempts so a one-shot flag cannot pass accidentally.

**Runtime/ledger variants:**

- `BackendRefused`: release a hung `FakeBackend` with `fail_arm=true`.
- `WorkerThrew`: release it with `throw_arm=true`. Both flags are checked after the gate. [`test_guardian_spark_runtime.cpp:237–261`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_spark_runtime.cpp#L237)
- Adoption failure: obtain K first, return success with fault point 12 armed, park compensation independently, prove no premature replacement, release compensation, then require recovery.
- Drain/persist gap: extend the existing ledger interleaving with an engine-level seam after eligibility sampling and before persistence. The existing runtime `drain_gap_hook` is a different gap: it runs before compensation submission, not between ledger sampling and generation persistence. [`guardian_spark_runtime.hpp:775–782`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.hpp#L775)

`set_io_executor_fail_launch_for_test` tests admission refusal/fallback. It does **not** produce a late `WorkerThrew`: launch refusal dispatches no operation. Use it for recovery-attempt failure coverage after establishing the genuine K episode. [`guardian_spark_runtime.hpp:770–774`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.hpp#L770)

False-green traps include:

- Returning failure before the hang. The engine fixture’s `fail_next_watch_` does exactly that; its throw seam is after the gate but becomes `BackendRefused` through `watch_guarded()`. [`test_guardian_engine_spark_reconcile.cpp:185–230`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_engine_spark_reconcile.cpp#L185)
- Starting compensation before K, thereby testing #5497’s already-fixed exclusion.
- Unconditionally issuing another push or restarting the engine.
- Checking only `can_advance`, `rule_count`, zero workers, or receipt retirement. None proves the desired rule has a live correct subscription.
- Accepting a watcher for a sibling or stale incarnation.
- Leaving the failure injection enabled forever, so the intended transient-recovery test can never turn green.
- Testing only runtime+ledger while claiming that the engine owns recovery.
- Using the fixture’s default generation-zero push, which cannot demonstrate the required positive-generation acknowledgement transition. [`test_guardian_engine_spark_reconcile.cpp:538–543`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/tests/unit/test_guardian_engine_spark_reconcile.cpp#L538)

Before considering the fix complete, add focused cases for withdrawal, replacement, stop, two failed rules, repeated recovery failure, and completion during the acknowledgement gap.

**G. Additional framing points. Confidence: high except the unavailable issue-number association noted above.**

- **The dial has a third position: acknowledge while retaining recovery ownership.** K can stop remote churn during a genuine hang without giving up the obligation to reconcile after the call settles. C provides that separation. It does not cancel or safely resolve a teardown that never returns; AC-1 remains a separate held-resource cost until deliberately changed. [`spark-stage2-guardian-consumer-design.md:707–720`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-stage2-guardian-consumer-design.md#L707)
- **The age gauges do not diagnose the stranded state.** They observe outstanding teardown. A plain late refusal owes no teardown, and completed compensation disappears from the age gauge even while the desired rule remains unarmed. There is no shipped alert rule in the accepted-cost note. [`guardian_spark_runtime.hpp:1738–1747`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.hpp#L1738), [`spark-flip-gate.md:978`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-flip-gate.md#L978)
- **`arm_failed` is not a durable cross-application census.** It stays positive in the unchanged application, but `begin_application()` replaces that bookkeeping. The design explicitly says the stronger per-desired-rule census remains unbuilt. A’s observability premise therefore needs qualification. [`guardian_arm_ack.cpp:152–158, 411–417`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_arm_ack.cpp#L411), [`spark-stage2-guardian-consumer-design.md:1021–1027`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-stage2-guardian-consumer-design.md#L1021)
- **K is not a per-rule elapsed-time guarantee.** Compensation holds and sibling failures can fund the shared counter, allowing a fresh wedge to waive on its first drain. Recovery deduplication must consequently use episode identity, not “we have already spent three retries on this rule.” [`spark-flip-gate.md:984–991`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-flip-gate.md#L984)
- **#5401 and #5402 are adjacent, not substitutes for #5459.** The snapshot identifies #5401 with last-attach-wins/stale adoption, and #5402 with a handed-back head failing to promptly drive its existing follower. #5459 remains reproducible with one unchanged desired rule and no follower. Its fix must respect incarnation/supersession and survive congestion, but need not reopen S1 versus S2. [`spark-flip-gate.md:715–721`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/docs/spark-flip-gate.md#L715)
- **There is a broader acknowledged-state recovery gap already documented for lost subscriptions.** Health polling detaches a dead watcher and leaves recovery to unrelated policy change or restart. Keep #5459’s patch scoped, but do not claim it establishes universal desired-state convergence. [`guardian_spark_runtime.cpp:3723–3744`](https://github.com/DevNullLtd/Yuzu/blob/f79ba8d13222fce1097ca984c63b1ee85d5e7180/agents/core/src/guardian_spark_runtime.cpp#L3723)

My confidence is **high that the recovery hole exists**, **high that A leaves a HIGH enabled defect**, and **medium that narrow C will cost less overall than a correctly implemented B′**. The unresolved empirical work is the red-first engine reproduction and the repair’s concurrency/failure tests.