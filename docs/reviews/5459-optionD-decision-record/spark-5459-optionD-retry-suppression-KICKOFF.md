# Kickoff: #5459 option D - replace the K-waiver with retry suppression

Ruled by Dave 2026-10-06 (Ruling 21). Reverses ruling 14 decision 1 (PR-5e K-bound) and
accepts that recovery after a late failure depends on the next server re-push. Freeze
covers all C++; this is the pre-freeze fix for #5459. Repo DevNullLtd/Yuzu. Step 0:
re-verify every citation against current origin/dev (git show origin/dev:<path>).

FULL REVIEW (read first): ~/.claude/plans/spark-5459-astra-d-suppress-opinion.md (Astra,
source-read, no code run), plus the earlier ~/.claude/plans/spark-5459-astra-c-design-opinion.md
(why C, the recovery engine, was rejected for the freeze: 620-1100 prod lines, 1-2 weeks).
Repro: /home/dgr/yuzu-5459 branch test/5459-k-waive-late-failure-repro (tests [5459a]
late refusal, [5459b] adoption failure after K, [5459c] drain-to-persist gap, [5459probe]
one re-push arms the rule; [5459control]). Do NOT push anything without governance and
Dave's go. Suggested owner: the "SPARK 5459 Repro" session (has the fixtures).

## The change in one paragraph
The K-waiver acknowledges a generation while an arm is genuinely hung, which makes the
server stop re-pushing, so a later late failure strands the rule. Delete the waiver so the
generation stays honestly HELD; the server's existing full_sync re-push (25 s min interval)
keeps retrying. To stop each held re-push costing a full teardown+re-arm of ALL the agent's
rules (no diff-skip; healthy rules re-emit guard.compliant; Spark rules with no expected
hash recapture their baseline, #4045), move the waiver's predicate from the ACK gate
(`GuardianArmAckLedger::can_advance()`, guardian_arm_ack.cpp ~L358-386) to the RETRY gate
(`decide_retry()`, ~L429-489): Suppress an identical retry whose only unresolved items are
outstanding wedges (or wedges with a compensating teardown outstanding). When the wedged
claim pops (late success or late failure) the live check stops holding, the next push is a
Reapply, and the rule re-arms (the probe proved one re-push arms it).

## Design (Astra; adjust only with evidence)
1. `decide_retry` restructure (drop const; identity checks BEFORE the empty-pending
   fallback): Reapply if !current_, generation/content_id/full_sync differ or either
   content_id not sha256; Reapply if latched_failure; Reapply if
   `resolved_failed != failed_receipts.size()` (some counted failure has no retained
   candidate = a genuine non-wedge failure); for EVERY failed_receipts entry call the LIVE
   `runtime.receipt_status_wedge_aware(receipt)` and require Wedged && (wedge_eligible ||
   compensation_pending), else Reapply (never trust the stale map); for EVERY pending entry
   accept Pending/Committed, or a live-eligible Wedged not yet drained (otherwise the
   bounded drain causes avoidable reapplies), else Reapply; if no outstanding wedge was
   found keep the old result (`pending.empty() ? Reapply : Suppress`, preserving the
   persist-retry escape); else apply the safety valve then Suppress. A late-failed popped
   claim must NOT suppress even before the next drain (the exact-FIFO-front check fails).
2. COMPENSATION-AWARE (not free; "just move the predicate" understates it): #5497 made a
   claim with a compensating teardown outstanding NOT K-eligible, and the recovery drain
   currently erases that receipt from failed_receipts. Without work, held pushes during a
   compensation would still pay the full teardown (AC-1). Extend `WedgeAwareStatus` with
   `compensation_pending` and `RecoveryStatus` with `CompensationPending`, computed via ONE
   private helper under registry_mu_ (claim && end==WaiterTimedOutDispatched &&
   dispatch==Dispatched && exact FIFO front && !compensation_finished; `Recovered` keeps
   first priority in receipt_recovery_status), retain compensating wedges in
   failed_receipts in BOTH drain loops. Suppression may include compensation; ACKNOWLEDGEMENT
   must never (can_advance no longer has any wedge escape at all). Do not remove the
   compensation_finished exclusion from the old eligibility predicate.
3. `can_advance()` becomes the conservative branch only: current_ && pending.empty() &&
   !latched_failure && resolved_failed == 0 (guardian_arm_ack.cpp ~L369).
4. SAFETY VALVE: `Application::wedge_suppress_count`, incremented only on the new
   wedge/compensation Suppress branch, max 10 then Reapply (~275 s at 25 s spacing, ~330 s
   at the 30 s heartbeat; a decision-count bound, not wall-clock), reset only by
   begin_application()/retire(). Cost to record: a forced Reapply re-arms everything and
   reintroduces the #4045 baseline-recapture exposure for unpersisted Spark baselines about
   every 5 min while a hang persists; it does NOT unstick the wedged claim (identical
   re-observation returns the existing claim). It bounds dependence on the suppress check;
   it is NOT a recovery guarantee against a classifier that misidentifies a dead claim.
5. EXCLUDED from this patch: escalating server back-off (server.cpp ~5810-5830). It would
   cut push/PG/audit cost ~12x but delays post-failure recovery by up to its interval and
   does not remove the pre-throttle generation read; a later server change should reset it
   on policy changes. Cost to record: held agent = ~2880 reconciles/day (~333/s per 10,000
   held endpoints, cadence arithmetic not measured).

## Delete / adapt (production)
Delete kReapplyWaiverThreshold, the carry-forward/cap logic in begin_application
(~L129-158, cap ~L142), Application::reapply_count + its test accessor, the waiver branch.
KEEP failed_receipts and genuine-recovery decrementing; keep arm_stats and cumulative
arm_failures_ (suppression must not erase failure evidence). Update stale comments (empty
pending is no longer invariably Reapply; failures no longer all require immediate Reapply).
The open reapply_count cross-rule funding ruling becomes MOOT (mechanism deleted).

## Tests (Astra's disposition; line numbers at origin/dev c9ffc9087, re-verify)
test_guardian_arm_ack.cpp: KEEP :326, :368 (rename to distinguish eligible wedges), :742,
:805 (add ack after repeated suppressed pushes), :1324 (add Reapply before the next drain),
:1387 (remove K setup), :1498 (extend for compensation classification); ADAPT :459 (title
"no pending or retained outstanding work", keep the persist-retry assertion), :1040 (mixed
failure => Reapply and no ack), :1224 (drop K assertions, keep fresh-accounting isolation,
add suppression-budget reset); REPLACE :960 ("never acknowledges an outstanding wedge,
including beyond the old K"), :1437 (no-ack + eventual Reapply); DELETE :1122 (funding).
test_guardian_engine_spark_reconcile.cpp: REPLACE ~:4096 K-bound case with held-generation +
no-teardown suppression; ADAPT #4472 cases ~:3421/:3427 (assert compensation-period
suppression). test_guardian_spark_runtime.cpp: adapt the rig K counter (~:14258), the
compensation recovery test (~:14480), delete the K-funding characterization (~:14890),
keep the compensation marker/age/stop/tripwire tests.
NEW red-first: empty-pending outstanding wedge suppress; undrained Wedged suppress; wedge +
Pending/Committed siblings; multiple wedges; mixed ordinary failure drained AND undrained;
late pop before retry with no intervening drain; pop racing the live read (at most a delayed
retry, NEVER an acknowledgement); compensation before first drain and after receipt
retention (tracked and suppressed until pop); valve bound and resets; healthy-sibling
watch/unwatch counts, lifecycle events and baseline UNCHANGED during suppressed pushes;
late refusal/throw/failed-adoption/successful-adoption through the real engine; legacy
empty-application failed-generation-persist recovery intact.
REPRO ADAPTATION: the repro's "K established + acked" precondition (require_k_established)
fails by design under D. Do NOT just delete the precondition: restate it as "generation is
HELD; drive a server-like push ONLY while the reported generation is behind; then assert a
LIVE CORRECT subscription (rule, key, assertion content once the content-identity bug is
fixed) and eventual persisted acknowledgement"; otherwise the tests test C's contract.
Keep [5459probe]. Waits event-driven (spin_until, tight bounds).

## Docs
spark-stage2-guardian-consumer-design.md R5.3 decision 1 (+ the late-failure and
"Completion ownership survives K" paragraphs), spark-flip-gate.md (#5459 precondition ->
RESOLVED by D with the cost recorded, AC-1, reapply_count funding row, accepted-cost rows),
spark-legacy-delta-registry.md A3 (~L145), docs/user-manual/guaranteed-state.md (~L462
K-bound paragraph).

## Known limits D does NOT fix (record, file separately, do not widen scope)
Restart gap (boot application opens at the loaded acked generation and cannot lower it, so
a failed boot re-arm at an acked generation has no retry owner; also a previously
persisted waiver ack is not revoked); a delta push that omits a still-desired unresolved
rule can replace the sole Application and lose its obligation (no current production route
established); mixed wedge + congestion-expiry failures still force Reapply (churn); a
never-returning arm holds the generation forever (intended; signals = yuzu.guardian_arm_
pending/failed and the #5403/#5404 age gauges, which are Application-scoped and dip on a
forced Reapply); #4045 baseline relaunder on any required Reapply; the content-identity
bug (re-observation matches rule_id + spec only, guardian_spark_runtime.cpp ~L2978/~L3100);
recovery still needs a live connection (the maintenance tick runs on the per-connection
heartbeat thread, so C had the same dependency).

## Governance and sizing
Spark row CATASTROPHIC-IF-VIOLATED (reconcile_rule_locked stays the sole arm chokepoint; no
legacy fallback; sticky stop; F3 accounting; no mtx_ in completion callbacks): security-
guardian + cpp-safety + architect + sre + quality-engineer; full /governance; Gate 8 per fix
round; TSan/ASan/UBSan; Windows (weecolin) + macOS (mini-colin) runs. Severity of the
original defect derived HIGH (I5(c), I1 for security rules, E4/E5 no downgrade, epistemic
likely); D closes all three sub-classes (the drain-to-persist gap is removed outright: no
waiver, no stale-eligibility ack). Astra's estimate: 100-180 prod lines, 600-1000 test lines,
3-5 engineering days incl. review rounds, medium confidence; choose C instead only if
recovery without a server connection, durable per-rule ownership, failed-rule-only rearm or
recovery after previously acked boot failures become requirements. Run Astra then Fable on
any deviation from this design BEFORE code (ask your user first); changelog fragment needs
the PR number; one PR; no stacked branches.
