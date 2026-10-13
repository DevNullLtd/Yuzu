**Recommendation: design C, but hold the flip through this freeze.** Narrow C is implementable without a callback queue or a periodic KV scan. It still introduces a recovery lifecycle spanning runtime claims, desired content, application replacement, accounting, and restart. I would budget **roughly 1-2 engineering weeks including tests and review iterations**, with moderate confidence, rather than promise completion in a few days.

If the flip must proceed before that work, **D is the smaller implementation change**, with an explicitly accepted endpoint-wide disruption cost. I would not describe D as low operational risk.

I read the locally available `origin/dev` at **`c9ffc9087c9ac0eca757ce11dcbb2382c82a8d3e`**. All source citations below refer to that revision; the linked working-tree files may differ. No files were changed, no tests were run, and no governance pipeline was run. The mechanisms below are design proposals, not executed proof.

**1. Episode identity and ownership**

The recovery candidate should represent **an outstanding obligation to restore one currently desired rule**, initially created because acknowledgment is about to waive its hung arm. Its physical arm attempt can change while that obligation remains.

Put the owner in a small **engine-owned `GuardianArmRecovery` module**, separate from `GuardianArmAckLedger::Application`. The ledger explicitly replaces its application wholesale; retaining candidates inside it would reproduce the ownership gap on the next push. An `ArmReceipt` already retains an observation handle without taking over cancellation or operation ownership. [Application replacement](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:129), [receipt ownership](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1361).

Proposed record:

```text
RecoveryObligation
  obligation_id                 process-local, never reused
  rule_id
  desired_revision              process-local revision, not policy generation
  desired_content_identity      canonical per-rule structured content
  origin_policy_generation      diagnostic only
  current_receipt               exact runtime claim being observed, if any
  current_attempt_id
  application_failure_token     optional, exact accounting contribution
  phase                         Watching / Cleanup / Ready / Attempting / Blocked
  consecutive_failures
  next_attempt_at                steady_clock
```

Use three distinct identities:

- **Desired identity:** rule ID, enabled flag, name, version, enforcement mode, and canonical Spark/assertion/remediation blocks.
- **Physical episode:** the retained claim identity and its runtime incarnation.
- **Accounting identity:** a new application serial plus an episode/slot serial.

Do not use policy generation alone: identical generation numbers can carry different content, and repeated applications of the same generation are different accounting lifetimes. Do not use Spark key alone: it identifies shared detection machinery, not the complete rule. Existing canonicalization provides the sorted-map, length-prefixed machinery; include `name` in the new per-rule identity because the bridge consumes it. [Canonicalization](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:96), [rule-name consumption](/home/dgr/Yuzu/agents/core/src/guardian_spark_bridge.hpp:193).

**Create the obligation before granting the waiver, not when the failure eventually arrives.** Capture desired identity alongside the receipt when reconciliation returns `Accepted`. At the waiver gate, copy every waived episode into the recovery owner before persisting the generation. Allocation or identity-construction failure means **no waiver this tick**. A completion between eligibility sampling and registration remains observable through the retained receipt. The insertion point is immediately before the current tick’s advance/persist block. [Accepted registration](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2540), [advance gate](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1077).

Lifecycle:

| Event | Proposed treatment |
|---|---|
| K-waiver prepared | Create/deduplicate obligation before acknowledgment. |
| Late refusal, throw, or unadopted completion | Existing obligation becomes ready once runtime cleanup is finished. |
| Late success adopted | Retire only after confirming the exact desired incarnation is committed with its subscription. |
| Identical push re-observes the claim | Preserve obligation and backoff; update its current application association. |
| Partial push omits the rule | Preserve obligation unchanged. |
| Push replaces the rule’s content | Retire the old episode identity; transfer the obligation to the new desired revision until the replacement succeeds. |
| Push successfully arms the desired replacement | Retire obligation and its matching accounting contribution. |
| Explicit disable or omission from an accepted full-sync desired set | Cancel obligation; never resurrect from a stale receipt. |
| `stop()` | Clear engine recovery ownership; runtime retains responsibility for outstanding cleanup. |
| Process restart | Reconstruct ownership from startup arm attempts, as discussed below. |

The transfer on replacement matters even when the new push uses an already acknowledged generation. Merely deleting the old candidate and assuming “the server now owns retry” is unsafe when the server’s generation comparison will still suppress retries. [Server comparison](/home/dgr/Yuzu/server/core/src/server.cpp:5805).

**2. Detection: use receipt polling, not a callback queue**

I recommend a new allocation-free runtime accessor:

```cpp
EpisodeProgress inspect_episode(const ArmReceipt&) const;
```

It takes `registry_mu_` once and distinguishes:

```text
CommittedExact
RuntimeOwned           // queued, dispatching, dispatched, retained tombstone
CompensationOutstanding
SettledUnadopted        // no remaining claim ownership, no outstanding compensation
Stopped
Invalid
```

This is a richer query alongside the existing `RecoveryStatus`, whose `Blocking` deliberately combines refusal, withdrawal, popped-unadopted completion, and outstanding compensation. That existing enum cannot drive retry safely. [Current classification](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1500).

**The exact producer hooks already exist:**

- No-compensation completion publishes and pops through `publish_arm_verdicts_locked()` inside `on_arm_complete()`.
- Compensation completion publishes/pops and sets `compensation_finished` in `finalize_arm_compensation()`.
- Exceptional retained tombstones remain owned until the existing reaper removes them.

The new accessor observes those transitions; it does not need callbacks to enqueue anything. [Ordinary completion](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1798), [compensation completion](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1305), [tombstone reaping](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2557).

Two load-bearing details:

- **“Not FIFO front” is insufficient.** A recovery successor may be queued behind another claim. Check exact membership in that key’s FIFO.
- **`compensation_finished == true` is insufficient.** It defaults true while an arm is genuinely running. Require the appropriate ownership/completion state as well. [Default and transitions](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1243).

Semantic withdrawal belongs to the engine’s desired-state record, not to `claim.withdrawn` alone. That field also represents internal tombstone handling, and full-sync deliberately withdraws before re-adding still-desired rules. [Claim fields](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.hpp:1188), [full-sync withdrawal](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:3321).

No completion callback takes `GuardianEngine::mtx_`, captures the engine, or receives a new engine-lifetime dependency. Existing callbacks already prohibit that lock acquisition. [Callback contract](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1365).

**3. Recovery action and scheduling**

Add `recover_failed_episodes_locked(now)` to `journal_maintenance_tick()`, after runtime expiration/accounting maintenance and before acknowledgment publication. It runs under the existing engine mutex and only visits recovery obligations. There is **no periodic `rule:` namespace walk**. [Tick and locking](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1031).

Concrete initial budgets:

- Inspect at most **64 candidate records per tick**, using a rotating cursor.
- Attempt at most **one rule reconciliation per tick**, selecting ready candidates fairly.
- First retry: next eligible tick after settled failure.
- Subsequent failures: **30, 60, 120, 240, then 300 seconds**, capped there.
- Keep retrying at the cap while the rule remains desired. A maximum attempt count would recreate abandonment.
- Do not reset backoff on an identical push or re-observation.

These are proposed defaults, not measured capacity figures. They bound new recovery work by count. They do **not** establish a hard heartbeat-latency bound: KV operations can wait, and reconciliation includes baseline lookup. The SQLite busy timeout is currently five seconds. [KV timeout](/home/dgr/Yuzu/agents/core/src/kv_store.cpp:117), [baseline lookup](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2450).

For each ready obligation:

1. Confirm engine active, Spark selected and available, and obligation still current.
2. Read precisely `rule:<rule_id>` using **`KvStore::get_entry()`**.
3. Parse and validate the rule, including matching its embedded ID to the requested key.
4. Confirm enabled state and exact desired identity/revision.
5. Confirm the tracked prior attempt has settled sufficiently for retry.
6. Invoke **`reconcile_rule_locked()`**, preserving validation, baseline seeding, backend selection, and error behavior.
7. Publish the returned attempt identity into the already allocated recovery record.
8. Settle accounting only on genuine recovery or explicit cancellation.

Use `get_entry()`, not `get()`: the latter returns `nullopt` for both absence and read errors. A read failure must retain the obligation and back off; it must not be treated as withdrawal. [Ambiguous getter](/home/dgr/Yuzu/agents/core/src/kv_store.cpp:184), [fallible getter](/home/dgr/Yuzu/agents/core/src/kv_store.cpp:435).

Refactor the private reconcile result to carry `{outcome, receipt/incarnation}` and let its caller select the accounting destination. Today reconciliation unconditionally registers `Accepted` in whichever application is open; a local recovery must not accidentally become a member of an unrelated partial push. Allocate the recovery destination before attachment so receipt handoff cannot fail after dispatch merely because a map insertion allocates. [Current coupling](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:2542).

Result handling:

| Result | Action |
|---|---|
| Correct `Armed` | Clear obligation and matching failure contribution. |
| `Accepted` | Retain obligation, observe this exact successor receipt, dispatch no duplicate. |
| Refusal or throw | Keep obligation, count this attempt once, advance backoff. |
| Successor hangs | Keep observing its runtime-owned claim; do not start another arm. |
| Successor late success | Retire on exact correct commitment. |
| Successor late failure | Retry again after cleanup and backoff. |
| Unexpected `Inert` | Block observably unless explained by confirmed withdrawal/disable; do not report recovery. |

**Recovery attempts do not need to re-enter K.** K governs permission to acknowledge an application. This obligation already owns continued recovery independently. Local attempts do not call `begin_application()` or increment `reapply_count`. If a real push adopts the attempt into a new application, normal application acknowledgment rules apply, while recovery ownership survives.

**Push interaction:** tick and `apply_rules()` already serialize on `mtx_`. Stage changes to affected recovery records before destructive full-sync work. Preserve same-content obligations across `detach_all()`; update them from the subsequent reconcile results. Cancel omitted records from the accepted full-sync intent, not from an intermediate empty KV cache. If a full-sync fails halfway, leave affected records explicitly cache-unconfirmed/blocked rather than resurrecting stale content or pretending recovery completed. [Push lock](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1323), [teardown and persistence failure paths](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1538).

The server’s **25 seconds is a minimum reconcile interval, not a local recovery clock**. After acknowledgment it sends nothing for that generation; before acknowledgment its push may supersede a local attempt through the same serialized engine path. [Rate limit](/home/dgr/Yuzu/server/core/src/server.cpp:5810).

**4. Accounting: retain identity after K eligibility is lost**

A retire-by-rule-ID operation is insufficient. Use:

```text
FailureToken = application_serial + rule_id + failure_slot_serial
```

Add a keyed failure-contribution record for every drained failure. Keep `failed_receipts` as the **K-eligible subset**, not the sole record identifying counted failures.

Today `Blocking` erases the receipt from `failed_receipts` without decrementing `resolved_failed`. After that, a new owner cannot safely identify which count it should clear. [Current pruning](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:216), [application fields](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.hpp:338).

Proposed operations:

```text
retire_failure(token, Recovered | Cancelled)
bind_recovery(token, obligation_id)
```

Rules:

- Insert the contribution successfully before incrementing its count or erasing its pending receipt.
- Retiring first checks application serial, then exact slot identity.
- A matching counted slot is erased once and decrements `resolved_failed` once.
- Its K-subset entry is removed only if it refers to that same episode.
- Repeating retirement is a no-op.
- Retirement after `begin_application()` replaced the application is a no-op.
- An old token can never clear a newer failure for the same rule.
- Local retry does not clear the original unresolved failure merely by starting.
- Success of the correct replacement clears the original contribution through its explicit obligation link.

This establishes the proposed invariant:

```text
resolved_failed == number of counted failure-contribution records
```

It gives a structural no-underflow argument; `if (count > 0) --count` alone does not establish correct attribution.

`can_advance()` retains its existing meaning: no pending work or latched failure, and either no counted failure or an entirely eligible K subset with sufficient reapply credit. Add the requirement that **every failure being waived has a registered recovery owner**. Local recovery success may discharge a contribution; local recovery failure does not manufacture waiver credit. [Current predicate](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:369).

Keep `arm_failures_` cumulative. Never decrement it on recovery. Give each local attempt one failure-accounting owner so the recovery module and application drain cannot both charge it. Existing application re-observations can already count the same physical wedge in different applications; do not silently redefine that historical counter as unique physical failures. [Existing drain accounting](/home/dgr/Yuzu/agents/core/src/guardian_arm_ack.cpp:286), [engine counter update](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1072).

For `arm_stats()` I recommend an explicit, narrow semantic extension:

- `failed`: current application failure contributions **plus outstanding recovery obligations not already represented by those contributions**.
- `pending`: current application pending attempts **plus local recovery attempts not already represented there**.
- A retry may be pending while its original recovery obligation remains failed. Document that the two gauges are not a partition.

Calculate the overlap by identity, never by arithmetic guesswork. This preserves a visible failure through an unrelated partial push without implementing a general inventory of every desired rule. It requires updating both agent comments and server HELP text, which currently promise current-application-only semantics. [Agent gauge contract](/home/dgr/Yuzu/agents/core/src/guardian_arm_heartbeat.hpp:29), [server HELP text](/home/dgr/Yuzu/server/core/src/guardian_arm_fleet_tags.hpp:79).

**5. Restart and generation zero**

**Do not persist runtime receipts, incarnation IDs, or backoff timestamps.** Startup already walks cached enabled rules and reconciles them, using the loaded acknowledgment generation. [Startup generation](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:664), [startup walk](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:764).

However, “startup re-arms everything” is not a complete restart proof. If that fresh arm fails, the loaded acknowledgment can still suppress server retry. The startup ledger deliberately cannot advance or lower the already loaded generation. [Boot application semantics](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:672).

Choose explicitly between:

- Persisting the narrow obligation identities, with corresponding write-ordering and crash-recovery work; or
- **My recommendation:** register startup arm attempts as recovery-owned when replaying the cached desired set. Successful attempts retire immediately; failed attempts use the same bounded retry machinery.

The latter slightly broadens enrollment to **identified startup attempts**, but still performs no recurring KV scan and adds no recovery persistence format. Without either choice, C has a restart-sized hole.

Generation zero must be a valid value, never “no candidate.” Use optional/token presence. Recovery must run even when target generation equals the reported generation, including zero. The existing `gen > policy_generation_` condition governs persistence only. [Persistence condition](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1091).

**6. Required race behavior and invariants**

| Scenario | Required outcome |
|---|---|
| Stop wins engine mutex | Recovery performs no subsequent reconcile; clearing its receipts does not cancel runtime cleanup. |
| Withdrawal wins mutex | Obligation is cancelled before tick can act; late completion cannot recreate it. |
| Tick wins before withdrawal | Its attempt is subsequently withdrawn through the existing runtime path. |
| Repeated refusal | One obligation survives; backoff saturates; no duplicate dispatch or counter charge. |
| Two failed rules | Independent obligations and accounting tokens; fair scheduling prevents one from monopolizing retries. |
| Late failure during a push | Receipt survives independently; push completion transfers/cancels ownership under the engine lock. |
| Recovery and genuine push target same rule | Serialize; push receives ownership of the resulting current attempt or replaces it. |
| Compensation still outstanding | Observe and wait; never reclaim the permit, pop the claim, or dispatch replacement ahead of cleanup. |
| Tombstone retained after cleanup | Wait for existing runtime reaper; do not treat terminal receipt status as completed ownership release. |
| Recovery bookkeeping allocation fails | Preserve old ownership; before acknowledgment, refuse waiver. |

The existing stop/runtime contracts support this shape: stop retires the ledger and begins runtime shutdown under the engine mutex, while dispatched claims finish through their callbacks. [Engine stop](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:843), [runtime stop](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:4783).

**Drain-to-persist gap:** a final candidate check may avoid some acknowledgments, but it cannot close the race. Completion can occur immediately after that check or while the generation write runs. Do not hold `registry_mu_` across KV persistence.

The correctness condition should instead be:

> Every episode whose failure is waived already has a recovery owner before acknowledgment can become durable.

Then failure just before persistence and failure just after it both converge. The current test intentionally permits the first ordering; C should extend it with eventual recovery rather than pretend acknowledgment became atomic with completion. [Gap test](/home/dgr/Yuzu/tests/unit/test_guardian_arm_ack.cpp:1437).

The Spark invariants are preserved by:

- Calling only `reconcile_rule_locked()` for engine-driven recovery.
- Keeping Spark failures visible, with no legacy fallback.
- Respecting sticky stop.
- Adding no worker-to-engine mutex acquisition.
- Leaving subscription compensation, executor quota, and physical worker accounting with their existing owners.
- Retaining sticky receipt history separately from current desired-state recovery.

These are the actual routed invariants, not optional implementation preferences. [Spark row](/home/dgr/Yuzu/.claude/routed-concerns.md:25).

**7. An additional content-identity issue must be handled**

The current re-observation branch matches **rule ID plus Spark spec**, then restores the old claim’s desire and returns its receipt. It does not compare the incoming assertion. The incoming `RuleGeneration` has already been constructed but is discarded on that return. [Incoming assertion](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2903), [re-observation](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2977).

Therefore a same-target assertion/remediation change cannot be treated as successful transfer merely because the returned receipt is later adopted.

For C, pass the canonical desired identity into the runtime and retain it with the claim/incarnation. Require it at **both** re-observation checks. For mismatching content on a hung key, use the conservative withdrawal/refusal path and retain recovery ownership until a correct fresh attempt can run. Do not label the old incarnation as the new content. [Second check and refusal path](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:3089).

This is a **source-derived concern, not a reproduced bug report**. It deserves a targeted test before anyone claims the end state is “live correct subscription.”

**8. Size, tests, and freeze decision**

Estimated implementation footprint:

| File/function | Proposed work | Approximate new/changed production lines |
|---|---|---:|
| New `guardian_arm_recovery.hpp/.cpp` | Obligations, transfer, backoff, fair selection | 200-350 |
| `guardian_engine.hpp/.cpp` | Typed reconcile result, waiver registration, push/boot/stop/tick integration | 180-300 |
| `guardian_arm_ack.hpp/.cpp` | Application serials, retained contribution identity, exact retirement | 120-220 |
| `guardian_spark_runtime.hpp/.cpp` | Progress inspection, desired identity and re-observation checks | 80-150 |
| Arm telemetry headers | Explicit overlap and semantic documentation | 40-80 |

**Total estimate: 620-1,100 production lines, plus roughly 1,000-2,000 test lines and documentation.** These are planning estimates, not measured diffs. New sources belong in [agents/core/meson.build:85](/home/dgr/Yuzu/agents/core/meson.build:85); new test files belong alongside the existing Guardian tests in [tests/meson.build:312](/home/dgr/Yuzu/tests/meson.build:312).

Required tests beyond the separately written end-state repro:

1. K-waived late refusal and worker throw recover without another server push.
2. Adoption failure compensates first, then recovers; hung compensation never permits premature retry.
3. Late success adoption produces no unnecessary replacement attempt.
4. Failure between eligibility sampling and generation persistence still recovers.
5. `begin_application()` replacement and unrelated partial push preserve ownership.
6. Same-content full sync transfers ownership; omission and disable cancel it.
7. Same Spark spec with changed assertion/remediation never counts the stale incarnation as recovery.
8. Recovery successor refuses repeatedly, hangs again, later succeeds, or loses admission.
9. Two obligations with different outcomes: fairness, isolation, bounded attempts.
10. Push/recovery and withdrawal/recovery interleavings, including full-sync’s teardown/re-add interval.
11. Exact retirement twice, after application replacement, and against a newer same-rule failure.
12. Candidate-allocation failure before waiver; receipt-registration failure after attachment.
13. KV absent versus read failure versus malformed/mismatched row.
14. Production-order restart, failed startup replay, and generation zero.
15. Sticky stop, late callbacks, unchanged compensation/worker accounting.
16. Telemetry overlap and continuity through partial pushes.
17. End state checks actual subscription identity/content and event delivery, not merely rule count or acknowledgment.

The runtime test asserting “late failure leaves zero rules” should remain valid at runtime-only scope: recovery belongs to the engine. Its engine-level counterpart should establish eventual restoration. [Existing runtime characterization](/home/dgr/Yuzu/tests/unit/test_guardian_spark_runtime.cpp:12468).

**Assessment:** a prototype may fit in a few days. A defensible implementation covering these ownership and exception paths, followed by the required reviews and cross-platform validation, should not be scheduled on that assumption. **Confidence: high in feasibility; moderate in the 1-2 week estimate; high that a days-away freeze is an unsuitable commitment.**

A refusal-only C subset saves little: application survival, accounting, scheduling, restart, and desired identity remain necessary, while adoption/compensation failures still strand rules. It is useful as an implementation slice, not a complete disposition of #5459.

Likewise, synthesizing a push through existing `apply_rules()` is not automatically a shortcut. The public method locks `mtx_`, replaces the application, and may tear down the entire rule set. Calling it under the tick lock deadlocks; calling it later without a revalidation fence risks replaying stale content. [Application entry](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1323), [application replacement](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1397).

**The smallest sound pre-freeze change is D, if its cost is accepted. My preferred pre-freeze action is holding the flip.**

**9. C versus D, and the revocable-ack hybrid**

| Dimension | Narrow C | D: remove wedged-arm waiver |
|---|---|---|
| Implementation risk | New recovery/accounting lifecycle | Small acknowledgment-policy change |
| Runtime disruption | Failed rule and its shared key | Every rule on the affected endpoint during full-sync retry |
| Permanently hung arm | Remains owned and observable; no duplicate local retry while hung | Holds generation and sustains server re-pushes |
| Late failure | Local owner retries after cleanup | Next eligible server push retries |
| Healthy sibling rules | No recovery-driven teardown | Repeated teardown/re-arm and evaluation-state reset |
| Server load | No additional recovery pushes | Repeated rule reads, push construction, dispatch, and audit |
| Primary correctness risk | Lost/stale obligation or premature cleanup crossing | Dependence on continued reconciliation; repeated disruption of healthy coverage |

D does not repeatedly restart the original wedged operation itself: identical re-observation returns the existing claim. Its damaging repetition is the surrounding **full-agent rule teardown/rebuild**. The source explicitly documents no diff-skip. [Re-observation](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:2977), [rebuild behavior](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:3018), [full-sync teardown](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1542).

D is also not an unconditional desired-state guarantee. Removing future waivers does not retract acknowledgments already persisted, and it does not independently solve failed startup replay at an already acknowledged generation. Those qualifications matter if cached rules survive the hard cutover. [Loaded generation](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:664), [server early return](/home/dgr/Yuzu/server/core/src/server.cpp:5805).

**Revocable acknowledgment is not a cheap hybrid.**

Once generation `G` is reported, making `can_advance()` false does nothing: the server still sees `agent_gen >= current`. Lowering the advertised generation would require specifying durable versus advertised state, restart behavior, concurrent higher-generation pushes, and generation-zero behavior. There is no unsigned predecessor below zero. [Monotonic publication](/home/dgr/Yuzu/agents/core/src/guardian_engine.cpp:1091), [server comparison](/home/dgr/Yuzu/server/core/src/server.cpp:5805).

A clean hybrid would add an explicit recovery-needed revision/token to heartbeat reconciliation. That requires server work, retry-clearing semantics, and the same reliable late-failure ownership C needs. It then recovers by disrupting every rule. It is a separate protocol design, not the smallest freeze-window fix.

**Other limits the framing should retain**

- “Compensation finished” currently includes **best-effort-failed teardown**. C must not claim proof that the OS subscription was removed merely from that flag. Repeated recovery can amplify an existing teardown-failure residual. [Fallback](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1291), [finalization semantics](/home/dgr/Yuzu/agents/core/src/guardian_spark_runtime.cpp:1322).
- Recovery on `journal_maintenance_tick()` is only live while that tick runs. Its production driver is the heartbeat thread; this design does not establish an independent offline recovery clock. [Heartbeat driver](/home/dgr/Yuzu/agents/core/src/agent.cpp:2372), [maintenance call](/home/dgr/Yuzu/agents/core/src/agent.cpp:2592).
- Zero rules at cutover reduces immediate exposure, but says nothing about the first deployed rule encountering the defect. The repository already records #5459 as an explicit operator decision before the flip. [Flip precondition](/home/dgr/Yuzu/docs/spark-flip-gate.md:911).