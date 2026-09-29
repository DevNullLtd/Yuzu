# #3990 - full_sync blackout diagnostic, recorded run

Captured 2026-09-06/07, rig DGRHP (`C:\yuzu-devrig2`, server + agent, data dir `C:\rigA`).
Authority: Dave's 2026-09-06 ruling on #3850 (the third comment on that issue) - CH-5-UAT
excludes rule-mutation churn from its own sampling windows, paired with a required,
non-gating diagnostic: "one baseline deploy on each backend, blackout duration recorded"
before #3990 can be cited in `docs/spark-flip-gate.md` §5 as accepted-neutral. The ruling
specifies nothing beyond that sentence - no measurand, sample size, or neutrality criterion.
Everything below that isn't a direct quote of the ruling is this run's own definition, stated
as such rather than attributed to source.

**Headline result, read this first, CORRECTED THREE TIMES since this doc's own first draft**
(see "Retraction" below the fold in "The driver's T1-detection gap" for the first correction,
"Decision rule and outcome" for the second and third - all kept in-doc rather than silently
edited away, since each wrong version was briefly the working conclusion): the 2026-09-06/07
attempt could not complete the intended legacy-vs-spark comparison at the pre-registered sample
size (a flush-lag gap in the agent's own `--log-file` output, since root-caused). A 2026-09-07
re-run collected enough samples to compute the numeric B comparison, but a separate,
never-wired-up functional-validity check meant none of those samples satisfied the full
pre-registered decision rule - formal outcome INCONCLUSIVE/INVALID BY COHORT DESIGN.

**2026-09-07, same day, third correction: a genuine pre-registered PASS.** Both bugs behind the
inconclusive result were fixed - `cmd_run()`'s `functional_valid` check wired into
`void_reason` (it was computed but never gated on), and 5 of 20 service-watch cohort rules
swapped for services confirmed live as Running+Automatic (`LSM`/`DcomLaunch`/`RpcEptMapper`/
`nsi`/`SamSs`, replacing `Spooler`/`Themes`/`BITS`/`wuauserv`/`W32Time`, which were confirmed
Stopped). A clean re-run (devrig2 reset to the same base commit, full clean rebuild after the
build directory was shared with an unrelated session in between - see "Decision rule and
outcome" for that incident) reached the pre-registered K=5/K=3 floor on every phase/backend,
with **every one of the 16 counted repeats independently satisfying `failed=0` AND
functional-validity** - the full rule, not a partial check. Both phases land within the
predeclared non-inferiority margin. This is this diagnostic's first genuine pass against its
own pre-registered rule - see "Decision rule and outcome" for the full record, including the
two prior wrong conclusions kept visible.

## What was measured, and how

**Measurand: B = T1 - T0, the synchronous `full_sync` apply-window proxy** - NOT a claim of
end-to-end detection blackout. T0 = `Guardian: full_sync cleared N prior rule(s)`
(`guardian_engine.cpp:658` as of `65f2938156a19`, agent log, logged immediately before
`stop_all_guards_locked()`/`detach_all()`); T1 = `Guardian: apply_rules ok (applied=N, failed=0,
full_sync=true, ...)` (`guardian_engine.cpp:768`, same build). Both citations are a point-in-time
forensic record for the build in "Build" below - the log statements have since moved and the T1
format has gained a `pending=` field on later `origin/dev`; do not re-grep current `origin/dev`
for these line numbers. `apply_rules` holds `mtx_` for the whole call and runs inline on
the agent's run() thread, so [T0,T1] is strictly all-guards-down-then-all-back-up on both
backends. Excluded from B: push transit, OS-watch re-establishment (legacy `FileGuard::start()`
returns before the watch exists; spark's `attach_rule` returns after the blocking
`GuardianIoExecutor::run`, so B is a closer approximation to spark's real blackout than to
legacy's - legacy's true blackout is understated by an unmeasured amount), first evaluation,
server ingest.

**Secondary, report-only: D**, the per-rule time to a fresh `guard.compliant` event after T0
(deadline = max(2B, 30s)). Used only as a functional-validity precondition for a repeat to
count - never an input to the numeric decision on B. In practice D could only be evaluated for
the handful of non-void repeats; not enough data to say anything general about it.

**Instrument**: `fullsync_blackout_diag.py` (this directory), a new committed driver reusing
`generate_resgate_load.py`'s HTTP/baseline helpers. Subcommands: `inventory`, `purge`,
`ensure`, `run`, `report`, `teardown-cohort`. See that file for the full mechanism; this doc is
the record of what it measured, not a restatement of how. The complete raw per-repeat output
is committed as `fullsync-blackout-results.jsonl` in this directory - every field this doc's
tables summarize, including the void repeats, is there in full; its `t0`/`t1` fields are the
driver's own raw timestamps and carry the UTC-mislabeling defect described in correction #2
below (harmless for the B values themselves, a same-host subtraction; do not trust their
absolute `+00:00` tag as real UTC).

**Build**: agent core AND all plugins rebuilt at `origin/dev@65f2938156a19` plus the single
flip one-liner at `agents/core/src/agent.cpp:836`. This build predates rung 9c PR-2's async-arm
rework - `GuardianSparkRuntime::attach_rule()` here is the blocking (non-`NonWaiting`) overload,
what `docs/spark-flip-gate.md`'s `#3990` §5 entry calls "the WAITING attach model" when scoping
this result against later re-measurements under the newer NonWaiting model:
```diff
-        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
+        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
+                                                     /*prefer_spark=*/!cfg_.spark_disable);
```
`yuzu-agent --version` = `0.13.1+7899 (65f2938156a19)`; `git diff` against the clean checkout
confirmed this is the ONLY local change. Server binary stayed at the pre-existing
`7c3c7d3fa`-era build (proto unchanged in that range) - accepted specifically because B is
agent-local (both T0 and T1 read the agent's own clock/log); the server side only matters for
the B2 trigger's reconcile audit-row cross-check, noted as a caveat there.

## Methodology corrections found live

Three real bugs were found and fixed DURING this run, all folded back into the plan
(`~/.claude/plans/let-s-pick-up-this-indexed-perlis.md`) and into `fullsync_blackout_diag.py`
itself. None of them invalidate the B values actually reported below (each B is a same-host,
same-clock subtraction that cancels out every one of these bugs) - they only affected which
repeats were correctly recognized as valid versus wrongly voided, which is exactly why the
early attempts under-counted valid samples so badly.

1. **Partial-plugin rebuild crash (rig ops, not a product defect).** The first rebuild
   compiled only the `yuzu-agent` target, leaving `agents/plugins/tar/tar.dll` at its stale
   pre-rebuild build. The mismatched core-vs-plugin vintage crashed the agent deterministically
   ~16s after boot - momentarily misdiagnosed as a regression in the just-merged PR #4017
   (power-capture source) before an empirical rebuild-and-retest (rebuilding `tar` too)
   disproved that and reproduced a stable agent past the crash point. No GitHub issue filed.
   Corrected instruction: a rebuild that moves to a new `origin/dev` tip must rebuild the FULL
   plugin set, not just the agent target.
2. **UTC mislabeling.** spdlog's `%Y-%m-%d %H:%M:%S.%e` pattern logs DGRHP's LOCAL time (BST,
   UTC+1 on the days this ran), but the driver's log parser tagged every timestamp
   `tzinfo=timezone.utc` for convenience. Harmless for any same-host comparison (B = T1-T0
   cancels the constant offset), but wrong for two cross-host uses: the driver's own
   "since-now" window-start marker, and the D-lookup's comparison against `event_id`'s embedded
   `system_clock` epoch ms (which IS real UTC, unaffected by display timezone). The first
   symptom was every early Phase B repeat falsely reporting a "second full_sync" (`
   double_full_sync`) that turned out to be the tool re-finding up to an hour of old history,
   not a genuine second trigger.
3. **Cross-host clock drift (the deeper bug once #2 was fixed).** The fix for #2 computed the
   window-start marker as "this driver host's true UTC now, plus DGRHP's known UTC offset" -
   correct only if the driver host's and DGRHP's system clocks are perfectly synchronized. They
   are not: measured ~0.2-1s of drift between the two machines, small in absolute terms but
   larger than a 62-rule `full_sync`'s own ~55ms duration. That was enough for a repeat's own
   window-start marker to occasionally land chronologically AFTER its own trigger's T0 line,
   making every fast, healthy repeat misreport as `t0_not_found`. Fixed by reading DGRHP's own
   clock directly for the window marker (one extra ssh round trip per repeat) instead of doing
   cross-host arithmetic - eliminates the drift by construction, at the cost of a small,
   deliberate backward safety margin (2s) to also absorb the round-trip itself.
4. **B2 rule-id collision across separate CLI invocations.** The `hbr_counter` used to name
   each Phase B2 trigger rule (`blackout-hbr-NN`) restarts at 1 on every fresh `run` invocation.
   Since legacy's B2 run and spark's B2 run were separate invocations, spark's run tried to
   recreate the SAME ten rule_ids legacy's run had already created - each `POST` hit a 409
   (already exists, correctly treated as idempotent success by `generate_resgate_load.py`'s
   convention) and so never bumped `policy_generation`, meaning the heartbeat-reconcile trigger
   Phase B2 depends on never fired at all. This produced spark B2's initial 0/3-with-all-
   `t0_not_found` result, which is a driver bug, not a backend defect - confirmed by re-running
   with deliberately-unique ids (`blackout-hbr-101`, `-110`, `-120`), which DID trigger
   correctly (see below). Not re-fixed in the script itself (a one-time run does not need
   cross-invocation counter persistence); flagged here so nobody re-runs this tool across two
   backends without knowing to bump the starting counter.

## Catalogue

- **Phase A (as-is, uncontrolled)**: the rig's pre-existing leftover catalogue from an earlier
  campaign - 8108 `riga-*` rules across 36 deployed baselines (~5652 armed at the time of
  measurement, after this session's own `ensure` had already added 61 rules on top of the
  original ~5591). No purge, no deliberate trigger.
- **Phase B / B2 (clean)**: after purging every `riga-*` rule/baseline (`dgrhp-drift-test-file`
  and baseline `0c953d48d94c` explicitly preserved throughout - both confirmed present before
  and after), a clean cohort: `blackout-cohort` baseline (20 file / 20 registry / 20 service
  rules, `enforcement_mode=audit`, `remediation=alert-only`) + a separate 1-rule
  `blackout-trigger` baseline (one file rule) whose re-deploy is the measured trigger for
  Phase B. **N=62, not 61** - the pre-existing `dgrhp-drift-test-file` rule (in its own
  permanently-deployed baseline `0c953d48d94c`) is also part of the deployed union and gets
  torn down/rearmed by every full_sync alongside the 61 cohort/trigger rules; the plan's
  original N=61 estimate didn't account for that always-present third baseline. Phase B2 uses
  a bare `POST /api/v1/guaranteed-state/rules` for a fresh rule in NO baseline as its trigger -
  `#3990`'s own literal shape (a rule-store mutation, amplified via heartbeat reconcile, not
  baseline-deploy's own protocol-necessary full_sync).

**Purge record**: pre-purge `riga_rules=8108`, `riga_baselines=36`. Both protected artifacts
(`dgrhp-drift-test-file` rule, `DGRHP File Drift Test` baseline `0c953d48d94c`) confirmed
present in a fresh inventory both immediately before and immediately after. `purge --apply`
took **14m14s** wall-clock (36 fragment-delete calls + 8108 individual REST DELETE calls, each
a synchronous local HTTP round-trip through the tunnel) with **zero failed deletes**; a
post-purge inventory confirmed `riga_rules=0`, `riga_baselines=0`, `clean=True`.

## Phase A - storm-observed, uncontrolled (context only, NOT verdict-bearing)

Passive observation: no deliberate trigger. `full_sync` windows recurred naturally on this
catalogue at an irregular cadence (roughly 5s-90s apart depending on how recently other
activity had occurred) via a mechanism this session did NOT fully diagnose - `failed=0` and
`applied=total` throughout every observed window, so this is NOT the "failed rules hold the
generation" mechanism the original plan text assumed (that assumption is corrected here: no
persistently-failing rule was present in this catalogue at measurement time). The likeliest
explanation is that this "ambient storm" was itself residue from this same session's own
preceding test activity (the `ensure` call and earlier smoke-test deploys, plus genuine
heartbeat-reconcile pushes - the server-side audit log for this window shows real
`guaranteed_state.reconcile` rows, not just deploy-triggered pushes) still draining, not a
truly independent, permanently-recurring mechanism - not confirmed either way, left as an
open question.

| Backend | window | B (ms) | applied | failed | total |
|---|---|---|---|---|---|
| spark  | 1 | 7583 | 5652 | 0 | 5652 |
| spark  | 2 | 7764 | 5652 | 0 | 5652 |
| spark  | 3 | 7492 | 5652 | 0 | 5652 |
| legacy | 1 | 7766 | 5652 | 0 | 5652 |
| legacy | 2 | 7636 | 5652 | 0 | 5652 |
| legacy | 3 | 7868 | 5652 | 0 | 5652 |

Both backends land in the same ~7.5-7.9s band at N=5652 - no material difference observed at
this uncontrolled scale, for this specific measurand.

**A separate, real effect found at this catalogue size, worth recording even though it isn't
part of B**: on restart into the **legacy** backend at N=5652, the agent registered with the
server successfully but then produced NO further log output (Guardian OR the unrelated TAR
triggers) for **~6 minutes**, while `(Get-Process yuzu-agent).CPU` grew by under 1.5s of CPU
time across that whole window (near-idle, not a busy spin) and the process held **~5683
threads / ~28,500 OS handles** - roughly one thread and five handles per armed legacy guard.
The server's own `yuzu_agents_connected` gauge read `1` throughout, so the heartbeat/Subscribe
path itself was not down - only the agent's own further activity was stalled. It recovered on
its own. This is the real-world shape of the risk the original plan's own "Risks/open" section
anticipated ("Phase A legacy at N~5800 may exhaust threads/handles ... that is itself a
recorded effect, not a void of Phase B") - recorded here as a genuine, if uncharacterized,
resource-contention effect specific to legacy's one-thread-per-guard design at this scale, not
present (by construction) under spark. **Correction**: an earlier draft of this doc speculated
this might be "a special case of the same broader phenomenon" as a clean-cohort pile-up effect
described further below - that downstream effect was retracted (see "The driver's
T1-detection gap"), so this N=5652 legacy silence stands as its own, separate, still-real
observation with no established connection to anything at the clean N=62 scale.

## The driver's T1-detection gap (why so few clean-cohort repeats counted)

**Retraction.** This section originally claimed a "queueing/pile-up effect" causing 80-90% of
clean-cohort triggers to take minutes to resolve on both backends, and framed that as this
diagnostic's real headline finding. That claim did not survive verification against the
complete evidence and is withdrawn. It is documented here, rather than silently deleted,
because the wrong conclusion was briefly the working state of this doc and a future reader
tracing history should be able to see what was claimed, why it looked plausible at the time,
and exactly what evidence disproved it.

**What the void reasons actually were**, from the driver's own raw per-repeat output
(`fullsync-blackout-results.jsonl`, committed alongside this doc):

| Phase | Backend | Attempts | Valid | `double_full_sync` | `t0_not_found` | `t1_not_found` |
|---|---|---|---|---|---|---|
| A  | spark  | 6  | 3 | 3  | 0  | 0 |
| A  | legacy | 3  | 3 | 0  | 0  | 0 |
| B  | legacy | 30 | 2 | 10 | 10 | 8 |
| B  | spark  | 10 | 1 | 0  | 0  | 9 |
| B2 | legacy | 10 | 2 | 0  | 0  | 8 |
| B2 | spark  | 14 | 0 | 0  | 11 | 3 |

(Phase B/legacy's 30 attempts are three separate `run` invocations - the driver was fixed and
re-run twice after its first two attempts came back 0/10 valid; corrections #2-#4 below explain
why. Phase B2/spark's 14 include the 10-attempt id-collision batch, correction #4.)

**Correlating every one of these against the complete agent log (not a sample) settles the
question.** `agent.log` for this session runs from 19:37:36 on 2026-09-06 (before this
diagnostic's own rebuild) through to teardown at ~01:14 on 2026-09-07, 345,343 lines,
containing every `full_sync` this agent process (across all its restarts) ever handled: **87
`Guardian: full_sync cleared` (T0) lines, 84 matching `Guardian: apply_rules ok ...
full_sync=true` (T1) completions.** Pairing each T0 with its next same-thread T1 gives a
**maximum observed gap of 8.261 seconds, and a median of 0.1ms**, across the ENTIRE session -
the large gaps (7.5-8.3s) are exclusively the six Phase A windows at N=5652; every clean-cohort
(N=62) pair completed in under 100ms. The 3 T0s with no matching T1 all fall exactly at the
three points this session restarted the agent to switch phase/backend - the in-flight request
died with the process, not with a stall. **There is no gap anywhere in the complete log
approaching even one minute**, on either backend, at any point in this session. The doc's
original claim of "several that took 3-6+ minutes" cannot be reproduced from the evidence that
was supposedly the basis for it, and is now believed to have been an unverified inference,
not a checked observation, despite being written as though it were checked.

**Conclusion: every `double_full_sync`, `t0_not_found`, and `t1_not_found` void in this run was
a false positive of the driver's own trigger-detection logic, not a real system delay.**
`double_full_sync` is already explained by correction #2 below (UTC-mislabeled timestamps
causing the tool to "re-find" up to an hour of old history as a spurious second trigger) - a
direct global scan for genuinely overlapping full_syncs (a second `full_sync cleared` with no
intervening completion, ANYWHERE in the whole log, any thread) found **zero** real
occurrences; the only three T0-after-T0 sequences found are the same three restart-boundary
artifacts already accounted for above. `t0_not_found`/`t1_not_found` persisting even in the
corrected (post-#2/#3/#4) runs means at least one further driver bug in the T0/T1 log-window
or polling logic was never identified in THIS session - **root-caused the following day, see
"T1 detection: the real root cause" below.**

**The valid (non-void) B values, on both backends and both trigger kinds, are all in the same
tight 55-82ms band** - legacy 55, 56, 57, 63ms (4 samples); spark 82ms (1 sample). This is
consistent with, not evidence against, the "no real delay" conclusion above: a healthy trigger
was always fast, on both backends, every time one was correctly detected.

## T1 detection: the real root cause, and the 2026-09-07 re-run reaching K=5

Picked up the next day per Dave's instruction ("fix the driver bug and re-run to reach K=5").
Root-caused by deliberate live reproduction against the running rig, not by further log
archaeology: triggered one Phase B repeat, watched the driver's own `_fetch_window` poll loop
return the IDENTICAL 93 matched events (the cumulative window contents, not new lines) for 16
consecutive polls across 61 seconds, then checked the raw agent log directly (independent of
the driver, two fresh SSH calls 5s apart) and found the file's `Length` and `LastWriteTime`
genuinely frozen for the same window - not a client-side caching artifact, the file had not
grown. **Correction**: an earlier version of this paragraph also called the eventual burst "~15
lines," conflating it with the 93-event window total above without saying what either number
actually counted - the 93 is the poll loop's cumulative matched-event count across the whole
search window; the smaller figure was this one attempt's own new arm/apply lines within that
burst, not independently re-verified against the raw log before this correction, and is left
out rather than restated as a precise number it wasn't checked to be. What IS directly
confirmed: ~2 minutes after the freeze, a burst of new lines appeared at once, ending in
`apply_rules ok`, every line in the burst timestamped within
the SAME real-world second (`06:46:29.6xx`) despite arriving on disk roughly two minutes late.

**Root cause for the flush lag ITSELF, confirmed against the vendored spdlog source, not
assumed**: `agents/core/src/main.cpp`'s `--log-file` sink setup (`:651-669`) never calls
`logger->flush_on(...)`. spdlog's own default `flush_level_` is `level::off`
(`spdlog/logger.h:311`), and `should_flush_()` (`spdlog/logger-inl.h:166-168`) only forces a
sink flush when a message's level meets that (never-raised) threshold - so nothing in this
process ever asks the sink to flush explicitly. A log line's embedded timestamp is recorded at
message-construction time (accurate), but the underlying bytes can sit in the sink's buffered
`ofstream` for an unpredictable period - observed live anywhere from ~2 seconds to ~108
seconds under this rig's ambient log volume - before becoming visible to ANY external reader,
this diagnostic's own polling included.

**Correction (Sol/`gpt-5.6-sol` opine, 2026-09-07)**: "this was never a bug in the driver's
window/timestamp-matching logic" and "only its timeout was too short" overstate what was
actually established. The flush-lag mechanism is real and is a strong explanation for MANY of
the residual `t1_not_found` voids - but the committed evidence does not prove it explains
EVERY historical one: the original run's `t0_not_found` batch on Phase B2/spark had its own,
separately-confirmed cause (the rule-id collision, correction #4, which meant there was
genuinely no trigger to find, nothing to do with flushing); and even after widening the
timeout to 240s, 3 of 8 legacy Phase B attempts in the re-run still voided `t1_not_found` -
consistent with flush lag occasionally exceeding 240s, but not independently confirmed to be
that specific cause each time (the underlying complete-log correlation that grounded the
retraction above was itself a one-time analysis of the FIRST attempt's log, not repeated for
every void in the re-run). Read "flush lag" as the established, dominant, and most likely
explanation for the residual gap - not as a proven, exhaustively-attributed one.

**Fix - more precisely, a bounded workaround for THIS one-time measurement, not a general
fix**: widened `ROOT_CAUSED_T0_TIMEOUT`/`ROOT_CAUSED_T1_TIMEOUT` to 240s each. No change to
the search/matching logic itself. Verified with a small 3-repeat controlled test before
trusting it for the full re-run - **2 of those 3 STILL voided `t1_not_found` even at 240s**,
a roughly 33% hit rate on that pilot, versus 5/8 (63%) on the actual legacy Phase B re-run;
neither rate is "comfortably" anything, and 240s does not reliably outlast the phenomenon it's
compensating for - it only outlasted it often enough, within a generous 10-attempt cap, to
reach the sample counts this run needed. Deliberately NOT changing the agent daemon's own
flush policy for this diagnostic - that would alter the executable being measured and risk
perturbing a sub-100ms measurand; unlike the functional-validity precondition below (a gap in
THIS diagnostic's own driver, fair game to fix and re-run), the flush policy lives in the
agent binary under test, and touching it here would invalidate the very B numbers this run
exists to produce. The underlying observability gap (no flush policy makes `--log-file`
unreliable for any near-real-time external tailing, not just this driver) is real and worth
its own product fix, but is explicitly OUT OF SCOPE for this diagnostic to carry - flagged
below rather than left as an implied someone-else's-problem (filed as
[#4608](https://github.com/Tr3kkR/Yuzu/issues/4608); see the "Status update" note near the end
of this document).

**Re-run results, 2026-09-07, same rig/build/cohort as the retracted run (agent untouched
since - `0.13.1+7899 (65f2938156a19)`, spark flip one-liner unchanged), fresh `ensure` after
the previous run's teardown**:

| Phase | Backend | Attempts | Valid | B min (ms) | B median (ms) | B max (ms) |
|---|---|---|---|---|---|---|
| B  | spark  | 5 | 5/5 | 73.0 | 77.0 | 91.0 |
| B  | legacy | 8 | 5/5 | 50.0 | 53.0 | 56.0 |
| B2 | spark  | 3 | 3/3 | 69.0 | 74.0 | 83.0 |
| B2 | legacy | 3 | 3/3 | 65.0 | 66.0 | 72.0 |

Both backends reached the driver's own SAMPLE-COUNT floor (K=5 for Phase B, K=3 for Phase B2)
on the first attempt at the fix - `failed=0`, `applied=total=62`, `n_arm_lines=62` on every
single counted repeat, both backends, every phase. **Correction, found on a second review of
this doc (Sol/`gpt-5.6-sol` opine, 2026-09-07) and confirmed by reading the driver's own
code**: "reached the pre-registered floor" overclaims what the code actually enforces.
`fullsync_blackout_diag.py`'s `run_repeat()` computes `functional_valid` and returns it in
every result row, but `cmd_run()`'s counting loop only checks `void_reason` - `functional_valid`
is written to the output and never read by anything that decides whether a repeat counts. So
the "5/5"/"3/3" tallies below only enforce `failed=0`/`applied=total`/arm-count/push-counter
matching - NOT the functional-validity precondition the pre-registered rule (below) also
requires. See "Decision rule and outcome" for what this means for the actual outcome; treat
every "N/N valid" claim in this section as "N/N by the driver's partial check," not by the
full pre-registered rule.

Raw per-repeat data for this re-run is appended to `fullsync-blackout-results.jsonl` (the
retracted run's 73 rows, then this re-run's 19 rows - rows carry no `run_id`/date field, and
the field SCHEMA does not reliably distinguish them either, since the retracted run's own later
Phase B/B2 rows already used the same fields; the correct, verified distinguisher is the `t0`
timestamp - the retracted run's valid rows all fall in `2026-09-06T21:47` to `2026-09-07T00:16`;
this re-run's valid rows all fall in `2026-09-07T07:12` to `08:22`, with no overlap; the
retracted run's rows, appended first, are clearly the earlier, smaller-sample block by position
in the file). **Also confirmed by the same review**: `cmd_report`'s grouping key is
`(label, backend, phase)` only - both runs used `label="clean"` for Phase B/B2, so re-running
`report` against the combined committed file would silently pool the retracted run's few rows
together with this re-run's, and would NOT reproduce the medians in this doc. Do not run
`report` against the combined file and trust its output; use the by-hand `t0`-range split above,
or filter the file first.

**A second, separate gap found while checking functional-validity (D), not a backend defect
either, but the claim below was itself corrected on review**: `functional_valid` came back
`False` on all 16 valid (by the partial check above) repeats. The ORIGINAL version of this
paragraph claimed all five of `blackout-svc-01/02/04/05/15` were "genuinely Stopped ... in
every repeat." **That is only true for THREE of the five** - checked directly against the raw
per-repeat `compliant_restored_ms_by_rule` data, not re-asserted: `svc-01` and `svc-02` and
`svc-15` show `not_observed` in all 16/16 repeats (consistent with a target that is simply
never in the asserted state); `svc-04` shows `not_observed` in 14/16 (observed compliant in
repeats `B/spark#3`, `B/spark#5`); `svc-05` shows `not_observed` in 11/16 (observed compliant
in 5 of 16, spread across both backends). These two rules' target services (per
`generate_resgate_load.py`'s `SERVICE_NAMES` list, watching Windows services **BITS** and
**wuauserv** for `service-running`) were evidently started and stopped by something else
during the run - Windows' own background servicing/update activity is the obvious candidate,
not confirmed - not held in one fixed state throughout. The blanket claim that these rules
"can never reach `guard.compliant` on ANY backend, at ANY full_sync speed" is true for
`svc-01/02/15` and NOT established for `svc-04/05`, which sometimes did. This does not change
which backend was affected (both, comparably, per repeat-count) but it does mean the
functional-validity gap is smaller and less structurally fixed than first claimed - a cohort
using a service list confirmed running AND held stable for the run's duration would likely
still leave `svc-01/02/15` failing, but might not leave `svc-04/05` failing every time. B
itself is unaffected either way - it measures the `apply_rules` lock window, not rule
compliance state, and every repeat's `applied=total=62`/`n_arm_lines=62` confirms the re-arm
itself was normal for all 20 service rules regardless of their eventual compliance state.
**The pre-registered decision rule's functional-validity precondition is not met by any of the
16 repeats** - for `svc-01/02/15`, for a reason unrelated to what B measures; for `svc-04/05`,
for a reason that is not yet fully characterized. Reported in "Decision rule and outcome" below
as what it actually is: an unmet precondition, not a relaxable technicality.

## Phase B - clean cohort, baseline re-deploy trigger

**2026-09-06/07 attempt (retracted-void-rate run)**: legacy 2/5 valid (56, 57ms; median
56.5ms), spark 1/5 valid (82ms; no median - a single sample) - inconclusive against the K=5
floor, for the driver flush-lag reason documented above.

**2026-09-07 re-run (fixed flush-timeout, see "T1 detection: the real root cause" above)**:
**legacy 5/5 valid in 8 attempts** (50, 50, 53, 54, 56ms; median 53ms), **spark 5/5 valid in 5
attempts, first try** (73, 76, 77, 80, 91ms; median 77ms) - by the driver's partial check
(`failed=0`/`applied=total`/arm-count/push-counter). `n_arm_lines=62` on every one of the 10
counted repeats too. **None of these 10 also satisfy functional-validity** - see "Decision
rule and outcome": the pre-registered K=5 floor, taken in full, was NOT reached.

**2026-09-07 clean re-run (`functional_valid` wiring + corrected service targets, label
`clean-v2`, commit `53929ee2c` + this doc's update)**: **legacy 5/5 valid, first try** (73, 70,
68, 67, 96ms; median 70ms), **spark 5/5 valid, first try** (127, 130, 119, 136, 120ms; median
127ms) - every repeat `failed=0`, `applied=total=62`, `n_arm_lines=62`, AND
`functional_valid=True` (the full rule, not the partial check above). Raw data appended to
`fullsync-blackout-results.jsonl` under `label="clean-v2"`, independently re-derived from that
file (not taken on the executing agent's word) before being recorded here.

## Phase B2 - clean cohort, bare rule-create trigger (#3990's literal shape)

**2026-09-06/07 attempt**: legacy 2/3 valid (55, 63ms; median 59ms), spark 0/3 valid on the
corrected (unique-id) runs - inconclusive against the K=3 floor, same driver flush-lag cause.

**2026-09-07 re-run**: **legacy 3/3 valid in 3 attempts, first try** (65, 66, 72ms; median
66ms), **spark 3/3 valid in 3 attempts, first try** (69, 74, 83ms; median 74ms) - by the
driver's partial check, same caveat as Phase B above; `n_arm_lines=62` on every one of the 6
counted repeats too, and none of the 6 also satisfy functional-validity. Create-to-T0 lag
(informational, cross-host, non-verdict-bearing per the plan) was not specifically re-examined
in the re-run - not load-bearing for the decision rule either way.

**2026-09-07 clean re-run (label `clean-v2`)**: **legacy 3/3 valid, first try** (70, 86, 89ms;
median 86ms), **spark 3/3 valid in 6 attempts** (140, 143, 120ms; median 140ms - 3 prior
attempts voided `t0_not_found`, an ordinary trigger-not-yet-visible timeout, not a
functional-validity or push-counter failure; well inside the driver's own 10-attempt cap).
Every counted repeat: `failed=0`, `applied=total=62`, `functional_valid=True`.

## Decision rule and outcome

Pre-registered before the clean-cohort runs (this session's own choice, not derived from any
SLO): spark median B <= legacy median B + max(1000 ms, legacy median B); every counted repeat
independently satisfies `failed=0` and functional-validity (D observed for all 60 cohort
rules).

**2026-09-06/07: Outcome INCONCLUSIVE** - neither backend reached the K=5 floor (driver flush
lag, since root-caused and fixed; see above). Superseded by the 2026-09-07 re-run below.

**2026-09-07 re-run: both backends reached the driver's own sample-count floor** (Phase B:
legacy 5/5, spark 5/5; Phase B2: legacy 3/3, spark 3/3, all by the partial check described
above - `failed=0`/`applied=total`/arm-count/push-counter only, NOT functional-validity, which
the code never actually gates on). The numeric B comparison, computed from those samples:

| | legacy median | spark median | margin (max(1000, legacy median)) | threshold | numeric result |
|---|---|---|---|---|---|
| B  | 53.0 ms | 77.0 ms | 1000 ms | 1053.0 ms | 77.0 <= 1053.0 -> within margin |
| B2 | 66.0 ms | 74.0 ms | 1000 ms | 1066.0 ms | 74.0 <= 1066.0 -> within margin |

**Second correction to this section (Sol/`gpt-5.6-sol` opine, 2026-09-07, confirmed against
the code and data before accepting it)**: an earlier version of this section treated "within
margin" as the outcome, framing the unmet functional-validity precondition as a relaxable
judgment call. That is procedurally unsound, for two reasons found on review, not just one:

1. **Pre-registration exists specifically to prevent exactly this** - deciding, after seeing
   data that looks fine, that a precondition set in advance doesn't really need to apply this
   time. A well-argued relaxation is still a relaxation decided post hoc; writing it down
   transparently doesn't restore its status as a pre-registered pass.
2. **The "5/5"/"3/3" counts themselves never enforced functional-validity in the first place**
   - not because it was judged unmeetable and consciously waived at decision time, but because
   `cmd_run()`'s own counting loop only checks `void_reason`, and `void_reason` is never set
   from `functional_valid`. So even setting aside point 1, the correct count of repeats
   satisfying the FULL pre-registered rule (as written: `failed=0` AND functional-validity) is
   **0 of 16**, not 5/5 or 3/3 under any reading.

**Correct statement of the outcome, in three separately-labeled parts, per that review**:
- **Numeric observation** (informational, not a decision): the B values that were collected
  land within the predeclared margin on both phases, table above.
- **Formal pre-registered decision**: **INCONCLUSIVE / INVALID BY COHORT DESIGN.** Zero repeats
  satisfy the rule as written. This is not the same failure mode as the 2026-09-06/07 attempt
  (which failed to collect enough samples at all) - samples exist and are usable as
  observations, but none of them satisfy the full pre-registered criteria for a decision.
- **Accepted-neutral status for §5**: **not established by this document.** Citing #3990 as
  accepted-neutral on the strength of the numeric observation alone would require Dave to
  explicitly waive the functional-validity precondition as a recorded protocol deviation -
  that is his call to make, not a conclusion this document reaches on its own.

**2026-09-07, same day, clean re-run (Dave: "Fix cmd_run's functional_valid wiring and
re-run"), commit `53929ee2c`: genuine pre-registered PASS.** Both defects behind the
INCONCLUSIVE outcome above were fixed at the source: `run_repeat()` now folds
`functional_valid` into `void_reason` itself for phases B/B2 (the counting loop in `cmd_run()`
needed no change - the bug was that the precondition was computed but never fed into the one
field the loop reads), and 5 of the cohort's 20 service-watch targets were replaced
(`Spooler`/`Themes`/`BITS`/`wuauserv`/`W32Time`, confirmed Stopped on DGRHP via live
`Get-Service`, swapped for `LSM`/`DcomLaunch`/`RpcEptMapper`/`nsi`/`SamSs`, confirmed
Running+Automatic and not already used elsewhere in the cohort). Wiring the check alone would
not have been enough - the prior 5 services were confirmed Stopped, not merely slow to
observe, so `functional_valid` was unsatisfiable by cohort design regardless of the wiring fix.

Executing the re-run surfaced a real, unplanned rig-state conflict, resolved before any
measurement ran: devrig2 (the same checkout this diagnostic builds from) was found at a
different git HEAD with an uncommitted 36-line scratch diff and a recent unrelated test
rebuild - traced, via `SendMessage` coordination with every other active session on the
machine, to an already-finished live-diagnosis session for an unrelated Windows CI flake
(PR #4077/#2818), which explicitly confirmed the state was disposable. devrig2 was reset to
this diagnostic's own base commit (`65f2938156a19`) and the one-line flip patch reapplied
(verified via `git diff --stat`: 1 file, 1 insertion, 1 deletion, and a raw UTF-8 byte check
after a first patch attempt was found to have corrupted non-ASCII characters via an
unencoded PowerShell read/write round-trip - caught before it was trusted, reverted, redone
with explicit UTF-8 encoding). Because the shared build directory had briefly held another
session's differently-configured build, a full clean rebuild (wipe + reconfigure, not
incremental) was done rather than trust an incremental compile - consistent with this
document's own earlier "Execution correction" lesson about partial rebuilds leaving stale
binaries. None of this touched the measurement itself; it is recorded here because it
materially changed how much to trust "same rig/build" continuity across this document's
rounds - the agent binary for this round is a distinct build from the 2026-09-07 INCONCLUSIVE
round above, at the same source commit + patch but not bit-identical.

**Results** (raw data in `fullsync-blackout-results.jsonl`, `label="clean-v2"`, independently
recomputed from that file - medians and per-repeat `failed`/`applied`/`total`/
`functional_valid` values all re-derived directly, not taken from any report):

| | legacy median | spark median | margin (max(1000, legacy median)) | threshold | numeric result |
|---|---|---|---|---|---|
| B  | 70.0 ms | 127.0 ms | 1000 ms | 1070.0 ms | 127.0 <= 1070.0 -> within margin |
| B2 | 86.0 ms | 140.0 ms | 1000 ms | 1086.0 ms | 140.0 <= 1086.0 -> within margin |

**Correct statement of the outcome, in the same three-part framing used for the INCONCLUSIVE
round above, since this round did not just meet the numeric margin but also the precondition
that round failed on**:
- **Numeric observation**: both phases land within the predeclared non-inferiority margin,
  table above.
- **Formal pre-registered decision**: **PASS.** All 16 counted repeats (5+3 legacy, 5+3 spark)
  independently satisfy `failed=0` AND functional-validity - the full rule as written, not a
  partial check and not a relaxation. This is the diagnostic's first round to actually meet its
  own pre-registered criteria.
- **Accepted-neutral status for §5**: a pre-registered non-inferiority pass on one rig, one
  cohort, two trigger shapes, is evidence FOR citing #3990 as accepted-neutral in §5 under this
  document's own margin - but whether that's sufficient, and how to word the §5 entry, is still
  Dave's call, not one this document makes unilaterally. The scope limits below ("Does NOT
  claim") still apply in full: this is one rig, not fleet scale; two specific triggers, not
  every mutation kind; B as defined here, not end-to-end detection blackout.

**Status update (2026-09-19)** on the two items above: (2) is resolved; (1) is NOT resolved,
and this note does not claim it is - whether this pass is sufficient to cite #3990 as
accepted-neutral in §5 remains Dave's call, per the paragraph immediately above and per the
`#3990` §5 entry's own closing line, both unchanged. What DID happen: `docs/spark-flip-gate.md`'s
`#3990` §5 entry now carries this result scoped explicitly to the pre-rung-9c-PR-2 WAITING
attach model, alongside a later, separate re-measurement under the current NonWaiting model -
so the sufficiency question, when Dave does make it, has both results in front of him rather
than just this one.

(2) The agent `--log-file` flush-policy gap (no `flush_on` call, `spdlog` default
`flush_level_=off`, `main.cpp`) - filed
as [#4608](https://github.com/Tr3kkR/Yuzu/issues/4608), after a later re-measurement round on
this same diagnostic's methodology hit the identical gap a second time. Fixing it here remained
out of scope (it would alter the executable under measurement).

## Does NOT claim

- End-to-end detection blackout duration (B is a lower bound on legacy's, closer to spark's).
- Behavior at fleet scale, on non-Windows platforms, or under any mutation kind other than the
  two triggers exercised here.
- That the Phase A "as-is" catalogue matches the ORIGINAL campaign's leftover state exactly -
  this session's own `ensure` call added 61 always-passing rules to it before Phase A ran,
  disclosed above.
- That the recurring "ambient storm" observed passively in Phase A is mechanistically
  identical to #3990's own described trigger (a rule mutation amplified via heartbeat
  reconcile) - plausibly related (both involve reconcile-driven pushes), not confirmed either
  way.
- **A queueing/pile-up effect under repeated triggers - this was claimed in an earlier draft
  of this document and is explicitly retracted above, with the evidence that disproved it.**
  Do not cite this document as evidence of such an effect.
- A neutrality finding in the sense the original CH-5-UAT ruling text explicitly disclaimed
  ("NOT a finding that #3990 is neutral ... in effect, only in mechanism") - the clean-v2
  round's PASS (see "Decision rule and outcome") is a pre-registered non-inferiority result on
  ONE rig under this document's own margin, not a claim that #3990's underlying mechanism (a
  fleet-wide storm from any rule mutation) is absent or safe in general; whether it's enough
  for the §5 accepted-neutral citation is Dave's call, stated as open above, not decided here.
- That the agent's `--log-file` flush-lag finding (up to ~108s observed) has been measured
  systematically, characterized as a distribution, fully attributed as the SOLE cause of every
  historical void, or reproduced on a differently-loaded rig - one deliberate live reproduction
  plus the 2026-09-07 re-run's attempt/void pattern are the only evidence; no minimum/maximum/
  typical lag is established beyond what was observed, and 3 of 8 legacy Phase B attempts still
  voided even after the timeout was widened to 240s.
- That the "5/5"/"3/3" sample counts under `label="clean"` (the 2026-09-07 re-run BEFORE the
  wiring fix) represent a pass against the pre-registered decision rule - they do not; they
  represent the driver's own PARTIAL check from that round (`failed=0`/`applied=total`/
  arm-count/push-counter only), since `cmd_run()` didn't yet wire `functional_valid` into its
  counting logic at that point. This does NOT apply to `label="clean-v2"`'s 5/5"/"3/3" counts
  (the fixed re-run, below) - those genuinely do satisfy the full rule, verified directly.
- That `blackout-svc-01/02/04/05/15` (as configured under `label="clean"`, the pre-fix cohort)
  were all equally and consistently non-compliant - only `svc-01/02/15` were (16/16 repeats);
  `svc-04/05` were intermittent (14/16 and 11/16). This describes that cohort's ORIGINAL
  service targets only - `label="clean-v2"`'s cohort uses different underlying services at
  those same rule_ids (see "Decision rule and outcome"), all confirmed live and consistently
  compliant.
- That `cmd_report`'s output can be trusted if re-run against the combined
  `fullsync-blackout-results.jsonl` as committed without first checking labels - its grouping
  key does not distinguish two runs sharing the SAME label (e.g. two separate attempts both
  run with `label="clean"`, which is why the clean-v2 round used a distinct label instead of
  reusing "clean" - a real, if narrow, mitigation of this known bug, not a fix to the code).
- The N=5652 legacy-only ~6-minute silence observed in Phase A (see that section) as anything
  more than a single, unreplicated, uncharacterized observation - it was not investigated
  further and no connection to any other finding in this document is established.

## Teardown

`teardown-cohort` removed both baselines (`blackout-cohort`, `blackout-trigger`, fleet
reconciled on each delete) and all cohort/trigger rules; ten additional `blackout-hbr-*` rules
left over from the Phase B2 id-collision correction (ids 04-10, 101, 110, 120) were deleted
individually since the driver's own teardown loop only covers ids 1-3 by default. A final
inventory confirmed exactly one rule (`dgrhp-drift-test-file`) and one baseline (`DGRHP File
Drift Test`, `0c953d48d94c`, deployed) remain - the untouched protected artifacts, and nothing
else. Scratch files/registry keys under `C:\rigA\blackout-scratch` and
`HKCU:\SOFTWARE\YuzuBlackout` were removed by the same teardown call. The agent was left
running on **spark** (the pre-run default, no `--spark-disable`, launched via the box's own
unmodified `run_agent2.ps1` with `--log-file`) - PID confirmed alive at teardown time. devrig2
is left at `origin/dev@65f2938156a19` + the flip one-liner (not reverted) - this is now the
rig's new baseline state, recorded here rather than restored to the pre-diagnostic
`7c3c7d3fa`-era build. `run_agent_legacy.ps1` (a scratch copy used for the legacy-backend
phases) is left on-box alongside the pre-existing scratch scripts; not committed.

**2026-09-07 clean re-run (`clean-v2`) teardown**: same `teardown-cohort` call. The spark
Phase B2 run's 3 voided `t0_not_found` attempts consumed `hbr-01..03` before its 3 valid
repeats landed on `hbr-04..06` - outside the driver's teardown loop's default `1-3` id range
(a known limitation, not newly discovered). Found via a raw REST rule listing after the
default teardown (`blackout-hbr-04/05/06` still present alongside the protected rule) and
deleted individually. Final `inventory`, independently re-run by the orchestrator (not taken
on the executing fork's word): `total_rules=1`, `riga_rules=0`, `riga_baselines=0`, both
protected artifacts present. Agent stopped and relaunched on **spark** via WMI Create
(`run_agent2.ps1`, unmodified, `--log-file`); confirmed alive (PID 17136, boot line `detection
backend = spark` at 10:39:47) both by the fork and independently by the orchestrator reading
the raw agent log directly. devrig2 unchanged from the state above (`65f2938156a19` + flip
one-liner) - this round's build is a distinct compile of that same source state, not a source
change.

**2026-09-07 re-run teardown**: same `teardown-cohort` call (baselines + cohort/trigger rules,
no `blackout-hbr-*` collision this time - each backend's B2 `hbr-01..03` ids were explicitly
deleted before switching backends, confirmed via a fresh `inventory` beforehand that no stray
ids survived the previous run's teardown). Post-teardown `inventory`: `total_rules=1`,
`riga_rules=0`, `riga_baselines=0`, both protected artifacts present - re-verified directly,
not assumed. Agent stopped and relaunched on **spark** (no `--spark-disable`, unmodified
`run_agent2.ps1`, `--log-file`) via WMI Create; confirmed alive, responding, and the
`detection backend = spark` boot line present (PID 21788). `run_agent_legacy.ps1` (new this
round, adds `--spark-disable` to the existing script) left on-box, not committed. Server and
Postgres tunnel untouched throughout this session.

## R5.7 T2 re-measurement - pre-registration (2026-09-19, rung 9c PR-6 item 2)

Everything above this section describes the **clean-v2 PASS** measured on the WAITING attach
model (`origin/dev@65f2938156a19` + the flip one-liner, pre-dating rung 9c PR-2). That result
stands as recorded - it is not edited or retroactively reinterpreted here. This section
pre-registers a SEPARATE re-measurement under the current NonWaiting attach model
(`reconcile_rule_locked()` -> `attach_rule(GuardianSparkRuntime::NonWaiting{}, ...)`), per
`docs/spark-stage2-guardian-consumer-design.md` "R5.7 - Re-measurement methodology" and its
"Rung 9c PR-6 item 1" follow-on paragraph. Committed BEFORE any rig time, per this diagnostic's
own established discipline: define the measurand and pass/fail criterion first, never relax
an unmet precondition after the fact.

**Why a re-measurement is needed at all**: on current `origin/dev`, `apply_rules ok` gained a
`pending=` field (rung 9c PR-2), which alone breaks the existing driver's `T1_RE`. More
substantively, T1 no longer waits for every rule's arm to commit under the NonWaiting model, so
Window B (`T1 - T0`) no longer brackets synchronous arm completion the way it did for the
waiting-model clean-v2 result. A runtime-side confirmation independent of `apply_rules`'s own
return is required - see `docs/spark-stage2-guardian-consumer-design.md`'s R5.7 section for the
full reasoning this implements.

**Estimand.** Time from the existing `full_sync cleared` marker (T0) to confirmation of the
current application's expected runtime commits - spark: the 62 epoch-member T2 lines
(`Guardian spark: arm committed for rule ...`, epoch-identity-filtered against that
application's own `detach_all()` teardown); legacy: the 62 `guard armed for rule` lines after
that same teardown's `Guardian spark: detach_all complete (...)` marker (T0d - logged on both
backends, since `spark_runtime_` is wired unconditionally regardless of which backend is
selected for arming). This is a **commit-latency proxy on both backends**, not a claim of
end-to-end detection blackout or notification-establishment coverage: for spark, `arm()`
returning success does not itself prove the OS watch/subscription is established for any of the
three cohort mechanism types (file/registry/service - see the design doc's establishment-limit
discussion), and for legacy `FileGuard::start()` similarly returns before its watch exists. The
comparison is not claimed to be conservative in either direction.

**Primary measurand: C = T2_last - T0** (spark) / legacy's equivalent last-arm-line - T0. This
is the HEADLINE number this re-run decides on.

**Continuity measurand: B = T1 - T0**, reported alongside C, NOT decision-bearing. Under the
NonWaiting model B no longer brackets synchronous arm completion, so a drop in B relative to
clean-v2's 127-140ms spark figures is a MODEL CHANGE, not a speed improvement, and must be
reported as such rather than as evidence of anything getting faster.

**Hypotheses, recorded before running (none of these bears on the pass/fail verdict - each is
reported confirmed or refuted after the run):**
  (i) spark B on the NonWaiting binary lands below clean-v2's 127-140ms figures;
  (ii) spark `t1_to_t2_last_ms > 0` on most repeats, with T2 lines observed in all three
      positions relative to T1 (before/tie/after) across the sample;
  (iii) spark C falls in the 100-200ms range, legacy C within ~3ms of its own B;
  (iv) `n_reobserved_adopt == 0` and the `repush_confound` void rate stays under 5%.

**Cohort, triggers, order.** Unchanged cohort composition from clean-v2: 60 cohort rules (20
file + 20 registry + 20 service, `BLACKOUT_SVC_OVERRIDE` unchanged) + the trigger rule + the
pre-existing protected rule = 62 expected rule_ids per full_sync. Phase B = baseline re-deploy
trigger; Phase B2 = bare rule-create trigger (`run_id`-scoped ids this round, closing the
existing trigger-ID-reuse trap documented above). Pre-registered invocation order: **legacy B,
spark B, spark B2, legacy B2** - alternating at the invocation level (not full ABBA within a
phase; each phase's two backend cells still run once each, in this fixed order). One binary per
backend switch (`--spark-disable` selects at relaunch); the run-order confound this introduces
(backend is not randomized against phase) is not eliminated, only stated.

**Sample floor.** K = 5 counted repeats per cell for Phase B, K = 3 for Phase B2, within the
driver's existing attempt cap (2K, minimum 10). A cell that does not reach its floor is
INCONCLUSIVE for that cell - never relaxed after the fact, per this diagnostic's own prior
rounds' hard-learned lesson (Sol's round-3 catch, see the retraction above).

**A repeat counts (is "valid") iff ALL of:** `failed == 0`; `total == 62`
(`cohort_composition` void otherwise); `detached_rules == 62` on spark / `== 0` on legacy
(`teardown_size_mismatch` void otherwise); `applied == total`; every one of the 62 expected
rule_ids has an eligible epoch-member confirmation line found within the 240s visibility
deadline, with no intervening next-application `T0d` (`t2_incomplete` / `double_full_sync`
void otherwise, `t2_incomplete` rows get one further look via the post-invocation sweep before
their final classification); `fence_violation == 0`; the existing push-counter deltas match;
functional validity (`guard.compliant` observed for all 60 cohort rules within `max(2C, 30s)`
of T0, polled with a 60s ingestion grace). `pending > 0` at T1 and any nonzero
`n_reobserved_adopt` / `repush_confound` are RECORDED on the row, never voids by themselves
(`repush_confound` from an in-window push command IS its own void reason, separate from these).

**Verdict per phase - a ONE-RIG EMPIRICAL ACCEPTANCE GATE, explicitly NOT a statistical
non-inferiority demonstration** (no uncertainty criterion, small K, the order confound noted
above):
1. *Latency gate*: spark median C <= legacy median C + max(1000ms, legacy median C), computed
   on counted (valid) repeats only. The 1000ms floor on the margin is carried unchanged from
   clean-v2's own acceptance choice (see "Decision rule and outcome" above) - permissive
   relative to the historical numbers, not derived from any SLO.
2. *Reliability gate*: zero genuine-failure attempts (`failed_gt_0`, `arm_never_confirmed`,
   `functional_invalid`, `fence_violation`) across BOTH backend cells of the phase, counting
   EVERY attempt, not just counted repeats. Any genuine failure fails the phase regardless of
   what the latency gate would otherwise say, and is filed as its own product finding separate
   from this diagnostic. Instrument-invalid voids never fail a phase on their own; if they
   exceed 50% of a cell's attempts that cell is INCONCLUSIVE instead.

PASS requires both gates to hold, at floor, in both cells of the phase. FAIL-LATENCY /
FAIL-RELIABILITY name which gate failed. INCONCLUSIVE otherwise (floor not reached, or void
rate too high to interpret). Every attempt - valid or voided - is reported in the raw JSONL and
in `report`'s per-cell breakdown; nothing is silently dropped.

**Build under measurement.** One `origin/dev`-merged branch SHA (`feat/3990-r57-t2-remeasure`)
plus the single `agent.cpp:853` flip one-liner for the spark half only
(`/*prefer_spark=*/!cfg_.spark_disable`); `git diff` against that branch tip must show nothing
else. `yuzu-agent --version` and the `detection backend = <x>` boot line recorded per relaunch.

**Fields to fill in before/during the actual run** (literal placeholders below, replaced when
the rig run happens - Commit 1's C++ instrumentation must land and be built into the agent
binary first):
- Build SHA under measurement: `TBD-before-run`
- DGRHP heartbeat interval / rig settings (H12 in the delivery plan): `TBD-before-run`
- Actual invocation order executed (confirm matches the pre-registered order above):
  `TBD-before-run`
- `comparison_id` used to group the four invocations: `TBD-before-run`

This section's own commit hash is the pre-registration timestamp; results are appended as a new
section below it once the run completes, never edited into this section.

## R5.7 T2 re-run results (2026-09-19) - Phase B PASS, Phase B2 FAIL-RELIABILITY

**Read this first: the headline changes for Phase B; Phase B2 is FAIL-RELIABILITY - a genuine
spark arm failure (`failed_gt_0`, repeat 3) was initially misclassified as an instrument-invalid
void by a driver bug found via `/adversarial-review` and fixed same-session (see the "Correction"
note under Phase B2 below); the corrected verdict is worse than what this section first
reported, not better.** All numbers below are recomputed directly from the committed
`fullsync-blackout-results.jsonl` (rows appended this round, `label="t2-v1"`), not from any
executing agent's own printout.

**Build under measurement**: branch `feat/3990-r57-t2-remeasure` @ `0a4a605d6f159c2e30fd70a5fd4e5b3913d29d79`
(origin/dev merged through `f0f07d4d8`) + the single `agents/core/src/agent.cpp:853` one-liner
(`/*prefer_spark=*/!cfg_.spark_disable`) for the spark leg; `git diff` on devrig2 showed only
that one line throughout. Confirmed via `yuzu-agent --version`: `0.13.1+9739 (0a4a605d6f)`, both
legs (one binary, backend chosen by `--spark-disable` at relaunch). Server built from the same
tree, same SHA. `--heartbeat` not overridden - default 30s (confirmed live: "Heartbeat thread
started (interval=30s)" both legs). DGRHP devrig2, server `C:\rigA`, Postgres
`postgresql://yuzu:yuzu@127.0.0.1:15436/yuzu_rigc`.

**Two real driver bugs surfaced live during this run and were fixed same-session** (commit
`5a833f4ff`, see that commit message and the branch's own CHANGELOG fragment for the full
account): (1) legacy never gets a T0d line at all (`--spark-disable` short-circuits
`wire_spark_engine()` before `spark_runtime_` is even constructed) - the driver was changed to
synthesize `t0d = t0` for legacy rather than wait on a line that can never appear; (2)
`build_verdict_lines()` was pairing legacy/spark on `run_id`, which differs by construction
between the two backends' separate `cmd_run()` invocations - every verdict silently read
INCONCLUSIVE regardless of the underlying data until this was fixed to pair on
`(comparison_id, label, phase)` only. Both were caught by generating a real report against live
data (Phase B was 5/5 valid on both backends and still showed INCONCLUSIVE), not by inspection.

**A rig-environment fact unrelated to any code change**: DGRHP's Hyper-V/WSL2 stack had
reserved TCP ports `50000-50369` as excluded ranges (`netsh int ipv4 show excludedportrange`)
since the last time this branch's own diagnostic ran on this rig - the rig's `run_server.ps1` /
`run_agent2.ps1` / `run_agent_legacy.ps1` scripts (previously `127.0.0.1:50081` for the agent
gRPC listener, default `0.0.0.0:50052` for management) were updated in place to
`127.0.0.1:50400`/`127.0.0.1:50410`, both confirmed outside every excluded range. This is a
rig-ops fact, not a driver or runtime defect; recorded here so a future round on this same rig
doesn't re-diagnose it from scratch.

### Phase B - baseline re-deploy trigger

| Backend | Attempted | Valid | Floor | B median (ms) | C median (ms) | Void breakdown |
|---|---|---|---|---|---|---|
| legacy | 5 | 5 | Y | 75.0 | 74.0 | - |
| spark | 5 | 5 | Y | 97.0 | 98.0 | - |

Legacy C values: 74.0, 65.0, 68.0, 75.0, 96.0 ms. Spark C values: 92.0, 99.0, 91.0, 106.0, 98.0 ms.
Zero voids on either backend - all 10 attempts valid, zero genuine-failure rows.

**Verdict: PASS.** Latency gate: spark median C (98.0) <= legacy median C (74.0) + max(1000,
74.0) = 1074.0 - holds comfortably. Reliability gate: zero genuine-failure attempts on either
backend across all attempts - holds. Both gates satisfied at floor in both cells.

### Phase B2 - bare rule-create trigger (#3990's literal shape)

**Correction (2026-09-19, post-`/adversarial-review`).** This section originally reported
INCONCLUSIVE with "zero genuine-failure rows" on spark. Both independent reviewers (Kimi K3,
Codex Sol) found, and cross-examination confirmed, that the driver checked a collection-stage
void `reason` (here, `double_full_sync`) BEFORE the T1-reported `failed>0` check, so a real
arm failure recorded on spark B2 repeat 3 (`applied=61, failed=1`, committed data unchanged)
was laundered into an instrument-invalid void instead of counting against the reliability gate.
Driver fixed (`genuine_t1_failure()`, hoisted ahead of the collection-stage check); the one
affected row's `void_class`/`void_reason` corrected from `instrument`/`double_full_sync` to
`genuine`/`failed_gt_0` in `fullsync-blackout-results.jsonl` (every other field on that row,
including its 61 committed `t2_selected` entries, is unchanged - only the derived classification
was wrong). The table, verdict, and analysis below reflect the corrected classification.

| Backend | Attempted | Valid | Floor | B median (ms) | C median (ms) | Void breakdown |
|---|---|---|---|---|---|---|
| legacy | 3 | 3 | Y | 67.0 | 66.0 | - |
| spark | 10 | 2 | N | 89.0 | 90.0 | `failed_gt_0`=1 (genuine), `t1_not_found`=7 |

Legacy C values: 66.0, 82.0, 65.0 ms - clean, no voids, matches Phase B's legacy figures
closely. Spark reached its 10-attempt cap with only 2 valid repeats (C = 92.0, 88.0 ms, both
consistent with Phase B's spark C figures where they did land). Of the other 8 attempts: 7
(`t1_not_found`, governance `sre` finding, this run: the same known `--log-file` flush-lag
mechanism documented above for the earlier 2026-09-06/07 round, not a new cause - worth finally
filing that deferred product issue given it has now cost two separate measurement rounds real
rig time) never reached T1 and carry no T2 evidence either way; the 8th (repeat 3)
**did** reach T1 and **did** commit 61 of its 62 expected arms (`t2_selected` has 61 entries),
but `apply_rules()` itself reported `failed=1` for the one remaining rule, `blackout-file-03` -
a genuine, backend-self-reported arm failure, not an absence of evidence.

**Temporal note, not a full root cause.** Repeat 3's T1 fired 86ms after its T0
(04:23:40.529 -> 04:23:40.615), reporting `failed=1` already at that point. The event that
produced this row's `double_full_sync` void classification pre-fix - an unrelated
`__guard__`-reconcile push (`push_cmd_lines_in_window`) - landed at 04:24:11.326, **~30.7
seconds later**. The confound cannot be the cause of a failure already reported 30+ seconds
earlier; they are temporally and causally independent events that happened to fall in the same
observation window. Why `blackout-file-03`'s arm itself failed is NOT established here - the
DGRHP rig was unreachable by the time this was found (SSH session had already ended), so the
raw `agent.log` line for that specific failure (which would name the underlying error) could
not be pulled. Recorded as an open, unresolved product-level finding per the pre-registered
rule ("any genuine failure... is filed as its own product finding separate from this
diagnostic") - not root-caused, not dismissed as instrumentation. **Filed as
[#4607](https://github.com/Tr3kkR/Yuzu/issues/4607).** **Observability gap,
noted here for whoever picks this up (governance `sre` finding, this run)**: `yuzu.guardian_arm_failed`
(`yuzu_fleet_guardian_arm_failed`) is an existing production metric that would have counted
exactly this failure, but no alert rule exists on it in `docs/prometheus/yuzu-alerts.yml` today -
worth adding one alongside the root-cause investigation, since the plumbing already exists.

**Verdict: FAIL-RELIABILITY.** The reliability gate is "zero genuine-failure attempts... counting
EVERY attempt" (not just counted repeats); repeat 3's `failed_gt_0` breaks it outright, and per
the pre-registered rule this holds "regardless of what the latency gate would otherwise say."
The floor-miss (2/3 valid) and the >50% instrument-invalid rate among the remaining 7 attempts
are both still true but are no longer the controlling fact - reliability fails before either is
reached. Not relaxed, and not inflated: the corrected verdict is worse than what was first
reported, stated exactly as the pre-registered rule requires.

### Hypotheses (i)-(iv), stated in the pre-registration - each resolved against the data

- **(i) "spark B on the NonWaiting binary lands below clean-v2's 127-140ms figures"**:
  **CONFIRMED.** Spark Phase B's own B (`T1-T0`) median is 97.0 ms, well below the waiting-model
  clean-v2 figures (127-140 ms). This is a model-change effect (T1 no longer waits for every
  arm), not a speed improvement - stated in those words, per the pre-registration.
- **(ii) "spark `t1_to_t2_last_ms > 0` on most repeats, with T2 lines observed in all three
  positions relative to T1"**: **PARTIALLY REFUTED.** `t1_to_t2_last_ms` was positive on all 5
  Phase B spark repeats (+1 ms each), so the first half holds. The second half does not: per
  repeat, 61 of the 62 T2 commits landed BEFORE T1 and exactly 1 landed after (the one that
  produces the +1 ms figure); zero ties were observed. The real behavior is "T1 fires after
  nearly all arms have already committed, with the single straggler landing a millisecond
  later" - not an even spread across before/tie/after as the hypothesis anticipated.
- **(iii) "spark C in 100-200ms range, legacy C within ~3ms of its own B"**: **legacy part
  CONFIRMED** (every legacy Phase B repeat's C sits exactly 1 ms below its own B, well within
  3 ms). **spark part narrowly REFUTED**: spark Phase B's C median is 98.0 ms, just under the
  predicted 100-200 ms floor (individual repeats ranged 91.0-106.0 ms, mostly below 100).
- **(iv) "`n_reobserved_adopt == 0` and `repush_confound` rate < 5%"**: **CONFIRMED.** Zero
  reobserved-adopt commits and zero `repush_confound` voids across every counted repeat in both
  phases.

### What this does and does not establish

Confirms the round-2 plan's central redesign point: C (the epoch-fenced runtime-commit
measurand) is measurable and well-behaved on current `origin/dev`, and spark's Phase B
non-inferiority holds under the pre-registered rule on this rig. Does NOT establish
non-inferiority for the bare rule-create trigger shape (#3990's own literal reproduction) -
that cell FAILS the reliability gate outright on a genuine, unroot-caused spark arm failure
(`blackout-file-03`, repeat 3) and needs both a follow-up investigation into that failure and a
re-run before any verdict can be reached for this trigger shape. Does NOT reopen or restate the
clean-v2 waiting-model result above, which stands as its own record for that build.

This section's own commit is the results record; see the driver-fix commits (`5a833f4ff`,
`2dbb9c7d1`), the T2 instrumentation commit (`0a4a605d6`), and this section's own correction
commit (`a8d37feac`) for the code and the classification fix these results depend on -
`5a833f4ff` alone still reproduces the retracted INCONCLUSIVE verdict (`2dbb9c7d1` is what fixes
the precedence bug that caused it).
