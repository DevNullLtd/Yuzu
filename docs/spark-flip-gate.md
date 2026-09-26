# Spark flip gate - `prefer_spark` cutover readiness (ADR-0021 rung 7.7)

This is the canonical, committed record of what gates flipping `prefer_spark` true
(`agents/core/src/agent.cpp:835`). It supersedes #2298 (closed 2026-08-11 with stale
checkboxes, not backfilled) and retires the local-only plan file that stranded these
criteria outside the repo - #3438's exact complaint. Do not maintain a parallel
local plan once this doc exists; update this file instead.

**A structural warning up front, discovered while writing this doc**: #2233 (the
rung-7.7 activation-readiness checklist this document's §2 tracks) was
auto-closed on 2026-09-02 by the repo's `close-linked-issues` workflow because
PR #3821's body said "closes #2233" - but PR #3821 only completed item 3 of the
issue's 10-item checklist. Items 1, 4, 5, 6, 7, 8, 9, 10 were still literally
unchecked `[ ]` in the issue body at time of writing. This is the identical
failure mode #2298 suffered and that this gate doc exists to stop repeating,
now reproduced by automation on its successor issue. §3 below tracks the real
state from the checklist content, not the issue's `CLOSED` state.

**Resolved (Dave, 2026-09-02):** #2233 is replaced, not reopened. Its genuinely
open items were re-filed fresh as **#3847** (items 1/4/6 - items 1 and 6 DONE via
#3884, merged 2026-09-03; item 4 DONE via #3961, merged 2026-09-04T15:20:25Z -
**#3847 itself is now CLOSED**, its residuals tracked at #3953/#3966, see §3 row 4)
and **#3848** (item 9) - every one of §3's 10 rows below carries its
actual disposition. #2233 itself stays closed; recorded on #3438. The underlying
automation gap (a checklist issue auto-closing on a partial-scope PR) is tracked
separately as **#3849**.

## 1. Status header

| | |
|---|---|
| Gate state | **OPEN** - 1 of 9 flip-green criteria evidenced |
| Shipped posture today | `prefer_spark=false`: legacy `IGuard` is the sole live *detection/enforcement* path. Spark itself is **not** dormant - `SparkEngine` is constructed and runs observe-only from boot (`agent.cpp:1207/1225-1226`, logging "instantiated OBSERVE-ONLY"), attempting to register all three mechanisms (`:1222-1224`), though registration is platform-gated and silently no-ops off-platform (`spark_mechanism.hpp:25-31`): all three succeed on Windows, only Service succeeds on Linux-with-libsystemd, and none succeed on macOS or Linux without libsystemd. A Guardian consumer (`guardian-spark`) **is** registered with `SparkEngine` at every boot that instantiates it (not under `--spark-disable`, §6, nor after a boot-time construction failure), independent of `prefer_spark_` (`guardian_engine.cpp:1406`) - what's actually absent is any *armed* rule: `reconcile_rule_locked`'s `try_spark = prefer_spark_ && spark_availability_ == Available` gate (`guardian_engine.cpp:1244`) is always false in production, so the registered consumer's handler is never invoked. This is the fact that determines today's blast radius if `prefer_spark_` were ever flipped outside the documented process: the consumer plumbing is already live, so such a flip would take effect immediately with no additional wiring step in the way - not a safety margin. (Three pre-existing code sites - `agent.cpp:1194/1226`, `:3935-3936` - still say "no consumer at rung 1" in comments/log text; that's now stale relative to the corrected claim above, tracked as a separate doc/code drift, not fixed in this PR.) Nothing in this doc describes current production *enforcement* behavior - it is a readiness gate for a future flip (this document's own top-level PR-5, the flip PR itself - genuinely still not yet written as of this update. **Disambiguation (PR #4529 review round, 2026-09-18): this is NOT the same "PR-5" as §3a's async-arm-acknowledgment track's own internal fault-wiring sub-ladder**, which as of this update has 4 of its 5 pieces merged (5a-5d) and 5e open as PR #4529 - see §3a for that ladder's real status. This row's "not yet written" claim is about the flip PR itself, unaffected by §3a's progress). |
| Evidence commit | _(placeholder - filled by PR-6, the evidence closeout PR)_ |
| Sign-off | _(blank - filled by PR-6 once every §2 criterion is green **AND** every §3 row not at a terminal disposition (RULED closed / DONE with no residual / Moved to P3 / Fixed) is itself resolved or explicitly risk-accepted - §2 alone is not the whole gate. Row 4 (#3847) is now fully DONE (items 1/6 via #3884, item 4 via #3961) - superseded by its own residuals, **#3953** and **#3966**, both RESOLVED via `fix/3953-3966-outbox-hardening`, **merged as PR #3982** (`1e7a5346c`, 2026-09-05T18:09:10Z; verified 2026-09-06 via `gh pr view 3982`, not carried forward stale); five of #3953's six items fixed directly, item 5 filed separately as #3972 - **not** risk-accepted, see §5's entry for why. Row 3's #3816 residual is now DONE via **PR-2e** (`fix/3816-guardian-io-executor-abandonment-signal`, merged to `dev` ahead of PR #3982) - #3831, row 3's other residual, was already DONE via #3884. As of this PR the remaining gating items are #3972 plus the three PR-2d follow-up items recorded in §5's own register - `guard.errored` census recognition (C-1), the three sre observability gaps, and the `yuzu.guardian_backend` server-side-reader gap (compliance-officer) - row 9 (#3848/#2818) is fully DONE, both merged (PR-2c merged; PR-2d merged as **PR #4075**, `2026-09-07T13:41:24Z`, closing #2818 the same run - **corrected round, 2026-09-07, superseding this cell's own earlier "not yet pushed" wording**, verified live via `gh pr view 4075`/`gh issue view 2818`; see §3a) - checked here, not folded into a 10th criterion. **Non-gating but tracked** (pre-existing production defects unrelated to `prefer_spark`, named here so none exits this ledger by omission, per compliance-officer's Gate 6 finding): **#4020** (P0, `AuthManager` has no AuthDB fallback on a cache miss) and **#4021** (P0/security, Guardian's baseline-on-arm rebaselining silently reclassifies a still-drifted no-`expected` rule as compliant on any unrelated fleet mutation) - both found during this PR's own criterion-5 evidence-gathering (see §2 criterion 5). **#4252** (task, `guardian_enforced_on_platform()`/`StateRollup::total()` double-count a Linux Service rule's real status row against its `notimpl` bucket at BOTH `guardian_routes.cpp:421-423` and `:1699-1703` - not just the first site - live today via legacy, RULED non-gating - see §8's tenth-round paragraph) has a different provenance: split out of **#4044** in the tenth round below, not from criterion-5 work. **#4044 itself: RULED (2026-09-10).** Deliberate - (a), see §8's ruling paragraph. **Still open, not risk-accepted-away** - its own action item, the `guaranteed-state.md:15` doc edit, is deferred to PR-5 per the pre-existing Scope note (also now a named §7 checklist item, not just recorded here) rather than applied in this doc-only PR; its double-counting risk is CONFIRMED (not dormant) and now tracked independently as #4252, not gating #4044's own resolution_ |
| This PR | PR-1 of 7: PR-1 (this doc) → **PR-2a (#2233 items 1/6/7 → #3847's original 1/6 slice + #2993; + #3831 batch) - DONE, merged as #3884, 2026-09-03** → **#2233 item 4, #3847 narrowed to this alone - DONE, merged as #3961, 2026-09-04T15:20:25Z - fixed the drain worker's stalled-sink hazard: `drain_bounded()`'s injected `send` now runs on a detached `GuardianOutboxSendExecutor` (guardian_outbox_send_executor.hpp) - one single-flight instance per lane (lifecycle, compliance/health) - instead of the worker's own joined thread, so a stalled sink no longer wedges journal maintenance or the next drain tick; covered by the orphan-exit contract (`GuardianEngine::active_io_workers()`), same as the existing state-reader/arm-disarm executors** → **PR-2c (fault-injection seams + item-9 TSan rerun, #3848) - DONE for #2815/#2833/#2839, merged to `dev`** → **PR-2d (the #2818 fix, `fix/2818-subscription-death-notification`) - DONE, see §5** → **PR-4 (promtool CH-2/CH-5-PROM) - DONE, merged as #3858, 2026-09-02T13:00:49Z** → **PR-2e (#3816's design PR) - `GuardianIoExecutor` abandonment-signal API, shared by `GuardianSparkRuntime` + `GuardianStateReader` - DONE, merged to `dev`** (filed 2026-09-01, predating this doc, missing from this doc's first draft and added only after a PR review caught the omission; see §3 row 3 for the fix itself) → **#3953/#3966's fix - DONE, merged as PR #3982 (`1e7a5346c`, 2026-09-05T18:09:10Z) - closes row 4's residuals, item 5 filed separately as #3972** → PR-5 (the flip) → PR-6 (evidence closeout). Sequencing note for §8: PR-4 landed independently of #3816 (neither blocked the other), so Rig A/B provisioning (which follows PR-2a/PR-2c per §8) was never delayed by #3816. PR-3 (#2233 item 8) was dropped before this doc was written - item 8 moved to the P3 lane (§3 row 8). PR-2b (item 5) is dropped by this doc (§3 row 5). |
| Re-verified against | `origin/dev @ bd387afec` (2026-09-02); the kickoff plan's citations were pinned to `880900f1e1` - every file:line citation below was re-checked against the newer HEAD, not copied blind. Drift is called out inline where found. |
| Last full re-verification | 2026-09-02, this PR, against `origin/dev @ e333b6cb2` post-rebase (no cited file changed between `bd387afec` and `e333b6cb2` - checked directly). Two later fix rounds (same date) added content re-verified against the same base: #3816 itself (§3 row 3, citing `guardian_spark_runtime.cpp:379-389`, `guardian_io_executor.hpp:376-388`, and `guardian_state_reader.cpp:59-71`), plus independent review nits folded into the same rounds (the "Shipped posture" rewrite citing `agent.cpp:1207/1222-1226`, `guardian_engine.cpp:1244/1406`, `spark_mechanism.hpp:25-31`; the §6 em-dash fix at `agent.cpp:1196`; the §5 "unbounded" addition at `spark_engine.hpp:540-543`). A third round, this PR's own PR-4-merged update, re-based this branch on `origin/dev` post-#3857-merge and re-verified its new citations (`tests/prometheus/yuzu-guardian-journal-extracted.test.yml`'s CH-2a/b/c and CH-5-PROM cases 1-6, `docs/prometheus/yuzu-alerts.yml`'s `TelemetryDark` rule expression) directly against `origin/dev` at that later point, not against `e333b6cb2`. A future reader should treat any citation as unverified past this point until re-run; there is no automated staleness check on this doc. A fourth round, this PR's own item-4 fix, re-based this branch on `origin/dev` post-#3884-merge (`c7febf76a`) and re-verified §3 rows 1/6/7 and row 3's #3831 sub-clause against #3884's actual merged content (`gh pr view 3884`, merge commit `282c3b58a`) rather than the peer-session summary that first reported it - directly, not by re-derivation from the earlier citations above. A fifth round, this PR's own governance fix-up (two BLOCKING concurrency defects found independently by two Gate 2/3 reviewers in the fix's first draft, both fixed; a new direct-coverage test file added), re-based this branch a SECOND time onto `origin/dev` at `e2f745606` (an unrelated ccache/CI PR, #3917, had merged in between) and re-verified every row-4 file:line citation against the post-fix-round tree directly. A sixth round, a fresh doc-only follow-up PR after #3961 merged (`acd83bd48`, 2026-09-04), fixed row 4's stale "awaiting merge" status, its `wrapped_send()` line-number drift (`:389`→`:408`), a self-contradiction where the row still stated a residual count the same PR's own synthesis doc claimed had been dropped, updated the §1 Sign-off row to point at #3953 and #3966 (superseding row 4/#3847 as the gating items, item 4 now DONE), and folded #3966 (a post-merge external adversarial review's admission-race finding, not fixed by anything in this branch) into row 4's own body text as well. This round went through its OWN governance (Gate 2 security-guardian+docs-writer, Gate 4 happy-path+unhappy-path+consistency-auditor, Gate 6 compliance-officer+sre+enterprise-readiness) after an earlier ungoverned push of the same PR was caught and corrected; that review found and fixed three more instances of the identical staleness class in locations the first pass missed - §1's "This PR" ladder row (still framed item 4 as in-flight), a §0 intro-paragraph clause with the same problem, and an overstated "same bounded-by-join reasoning" claim about #3966 relative to the row's other, dormancy-bounded residuals - plus a #3966/#3953 scope-conflation defect the first commit introduced and a markdown bold-span break caught before commit via a bold-marker-count check. Verified directly against `origin/dev @ acd83bd48` - the merge commit itself, not a peer-session summary. **Separately, PR-2e** (a later, distinct PR on branch `fix/3816-guardian-io-executor-abandonment-signal`, built off `origin/dev @ 6d40b3993`) re-verified and fixed row 3's stale `#3816` citations (`guardian_spark_runtime.cpp:379-389` had drifted to `:487-506` pre-fix; row 3's `guardian_io_executor.hpp:376-388`/`:386`/`:387` citations were rewritten to describe the post-fix code, which no longer has that structure) and shipped the fix those citations were tracking - see row 3's own closing paragraph. **Separately, PR-2c** (this PR, #3848, branch `test/3848-spark-fault-injection-matrix`) added §5's #2815/#2818/#2833/#2839 register in three rounds: an initial pass (`6dec4c379`) against the tree at that time; a correction (`792eab501`) after adversarial review (Kimi+Codex) found stale #2839 Windows-evidence wording; and this round (`1fcd82499` + this edit), after governance Gate 4 (consistency-auditor) found the §1 status ladder had fallen out of sync with §5's own PR-2d escalation, and Gate 6 (compliance-officer) found the #2839 entry's "4/4 stable" Windows-hardware sentence had narrowed in scope without being reworded, once two later commits (`1a2855e43`, `0cdd6bb2a`) added further Windows-only production code after it was written - closed with a second real DGRHP hardware round covering both, see the #2839 entry above. **Separately again, this doc-only follow-up** (branch `docs/spark-flip-gate-ch5-findings`, built off `origin/dev @ 57ec64433`, 2026-09-05): records the DGRHP exploratory CH-5-UAT pass (§4, §8) and its two production-defect findings, re-verified directly against this same base - `spark_registry.cpp`'s watcher-callback path and `guardian_spark_runtime.cpp`'s `build_entries()` for the event_id-timestamp semantics (§4), `agent.cpp:2269/:2643` for the Heartbeat deadline claim and its subsequent retraction via a live bounded repro on the DGRHP rig itself (not a citation-only check), and `spark_mechanism.hpp:25-31` for the BigColin platform-blocker citation (§8). Not a numbered PR-1..PR-6 slot - this is evidence toward the CH-5-UAT driver step in §4's own PR-sequence paragraph, which sits outside that ladder. **A seventh round, this same doc-only PR's own `/governance` pass** (Gate 2 security-guardian+docs-writer, a discretionary Gate 3 `authdb` review given the section's falsifiable AuthManager/AuthDB claims): corrected an already-wrong-once root-cause claim's remaining incompleteness (the "not against Postgres" framing omitted the post-password `is_active` check; filed **#4020** for a distinct, more serious cold-cache gap it surfaced), replaced an unresolved "arm-on-spark not independently confirmed" hedge with direct log evidence (`agent.log`'s `detection backend = spark` line, same restart, same second, verified against `agent.cpp`'s own comment that it shares the heartbeat tag's derivation function), connected the baseline-on-arm observation to the already-filed `#3990` and filed **#4021** for the compounding gap, corrected a wrong constant attribution for the ~5-minute periodic cadence (`kGuardianFileLaneCadenceMs`, not `errored_refresh_ms` - the latter structurally cannot re-fire on a persisting divergence), fixed a "twice" vs "three times" self-contradiction, and fixed a cross-reference claiming content was "recorded in §4/§8 below" that was never actually added there. Verified directly against `origin/dev @ a7b47ebda` (fetched and merged fresh into this branch before the review started). **An eighth round, Gate 4 of the same `/governance` pass** (happy-path+unhappy-path+consistency-auditor): found the dashboard-edge claim (`guardian_routes.cpp`'s `render_events_fragment`, `guardian_ui.cpp`'s `.et-drift_detected` class) was source-traced but never actually observed - fixed by fetching `GET /fragments/guardian/events` live against DGRHP and citing the real rendered response; found the "three times, in ONE arm window" header still contradicted the "two arm windows" summary after the seventh round's own fix (the header, not the summary, was wrong); found PR #3982 was cited as "not yet merged" in three places (§1 rows, §3 row 4) when `gh pr view 3982` shows it merged 2026-09-05T18:09:10Z as `1e7a5346c`, predating even the eighth round's own base; found a §3-vs-§4 cross-reference misattribution for the #3989 retraction; and found #4021 (but not #4020, judged out of this doc's own spark/guardian tracking scope) needed a §5 cross-reference next to the existing #3990 entry it compounds with. Verified directly against `origin/dev @ a7b47ebda`, same base as the seventh round - no new upstream commits landed during Gate 2-4's run. **A ninth round, a separate live Linux Service-type drift session on Rig B/BigColin** (branch re-based onto `origin/dev @ c926a171d`, 44 commits ahead of the eighth round's base by this point - the branch had gone stale again in the interim): added the sudoers-grant/Baseline-deploy/`guard.compliant` content in §8, re-verified directly against this new base - `guardian_engine.cpp`'s `attach_rule`/`emit_compliant_edge` call, `guardian_routes.cpp`'s "not deployed" badge and baseline create/deploy fragment routes, `docs/user-manual/guaranteed-state.md`'s Linux service compliant-edge limitation, `docs/os-capability-matrix.md`'s Linux service enforcement-deferred note. This round's own `/governance` pass (Gate 2/3 security-guardian+docs-writer+architect, Gate 4 happy-path+unhappy-path+consistency-auditor) found and fixed: an overclaim ("no error anywhere" - the dashboard actually shows a badge), an unfiled ADR-1005 gap (cross-referenced to the existing duplicate **#3266** instead of filing new), the `guard.compliant`-on-Linux discrepancy (filed **#4044**), a closing-summary overclaim implying dashboard-confirmation parity between DGRHP's and Rig B's evidence when DGRHP's own text disclaims catching its own rule's event, a citation-fidelity nit (a truncated quote), and this ledger row's own staleness (no ninth-round entry existed until this sentence). **Separately, PR-2d** (this PR, branch `fix/2818-subscription-death-notification`, built off `origin/dev` after both PR-2c/#3985 and #3982 had merged) fixed #2818 itself - see the #2818 entry above for the full shape - and updated this row's own §1 Sign-off/"This PR" ladder lines and Owner/Milestone/Revisit-trigger fields to reflect that all four issues in this register row are now resolved. Verified directly against the tree at that branch point, not a peer-session summary. **A tenth round, this PR** (branch `docs/4044-linux-compliant-edge-doc`, built off `origin/dev @ cf34e345a`): rules #4044 as (a) - deliberate - with fresh direct-code citations (`guardian_emit_decider.hpp`'s doc comment, `guardian_rule_eval.cpp:165-167`'s `eval_service` comment, and the introducing commit `97ece94d0`'s own message), independently confirming D4 in `docs/spark-legacy-delta-registry.md` rather than superseding it. Re-verified the Scope note immediately above still applies and left `guaranteed-state.md` untouched per it. Confirmed the Gate 6 `sre` double-counting finding in code (`guardian_push_builder.cpp:87`, `guardian_routes.cpp:260-261/398-424`) rather than treating it as still-dormant, and split it out as **#4252**. Verified directly against `origin/dev @ cf34e345a` - the merge commit itself. **An eleventh round, rung 9c PR-6 item 2** (branch `feat/3990-r57-t2-remeasure`, R5.7 T2 re-measurement, 2026-09-19): added this file's `#3990` R5.7 §5 sub-entry and the WAITING-attach-model qualifier on the `clean-v2` entry above it. Went through a genuine, independently-dispatched (not self-reviewed) full `/governance` pass on the whole branch diff - Gate 2 security-guardian+docs-writer, Gate 3 cpp-expert+cpp-safety+quality-engineer, Gate 4 happy-path+unhappy-path+consistency-auditor, Gate 6 compliance-officer+sre+enterprise-readiness, 11 agents total - which found and fixed one BLOCKING defect in the R5.7 measurement driver itself (a fence-violation classification bug in `sweep_incomplete()`, independently re-discovered by three of the eleven agents after two EARLIER self-review passes had incorrectly recorded it as fixed - see that finding's own superseded ledger rows), plus three more real correctness gaps in the same driver (a concurrent-writer content-blind race, a `run_id` second-granularity collision, a missing tail-truncation guard on the post-run reclassification sweep) and one exception-message truncation gap that kept the sensitive half of an SSH error string instead of discarding it. The one finding against this file (a margin→threshold fix in the new R5.7 §5 entry) is applied in this same commit; no pre-existing content was touched. Verified directly against `origin/dev @ 98b8bbe98` (this branch's own merge base at governance time). **A twelfth round, still this same branch**, covers three further rounds the eleventh round's own entry never recorded (consistency-auditor Gate-4 finding, PR #4614 full-mandatory-set review, 2026-09-19). Round-2 (`b81b29448`, Gate 8 re-review of the eleventh round's own fix) closed a second SSH-exception leak site `ssh_ps()`'s first fix had missed, a fixture-coverage gap in F22 (single-row-only, closed with a mixed-batch Case D), and a dropped residual-risk comment. Round-3 (`5fd6e3f33`, a further Gate 8 pass) fixed a self-contradiction in this entry's OWN eleventh-round text (the "no finding touched this file's own content directly" clause, corrected above) and narrowed an older changelog fragment's now-false "fixed via X" claim. Then PR #4614 (this branch's own push, `a1b6cbf94`..`4bea81a43`, 8 commits) responded to an external bot review ("Doomgoose") plus six further internal scoped-governance rounds (unhappy-path, docs-writer, cpp-safety+quality-engineer, then a full mandatory-set pass: security-guardian, cpp-expert, happy-path, consistency-auditor, compliance-officer, sre, enterprise-readiness) that together found and fixed: two real correctness gaps in the cohort-fetch fix itself (ever-succeeded vs. last-attempt fetch tracking; a single tainted rule voiding a whole cohort's genuine evidence, inverted from this file's own asymmetric-cost doctrine); a false-assurance gap in the new race test's own docstring (claimed protection against an in-lock-reordering regression no runtime test can detect - proven by a reproduced mutant passing 3000/3000 runs under a real TSan build); a missing RAII join guard and an under-specified error check on that same test; a literally-false persisted evidence label; a BLOCKING Resource Ledger policy-floor omission; and the governance-ledger completeness gap this very twelfth-round entry is itself evidence of correcting. No file:line citation in rows 1-11 above was touched by any twelfth-round finding - they all landed in `fullsync_blackout_diag.py`, `test_guardian_spark_runtime.cpp`, changelog fragments, and the governance ledger itself, not in this doc. Verified directly against the branch's own commit history. Not yet pushed as of this entry - 8 commits ahead of `origin/feat/3990-r57-t2-remeasure`. |

## 2. Flip-green criteria (1)–(9)

All start unchecked. Each gets its evidence link recorded here by PR-6.

- [ ] **1. Full `/test`, including previous-release upgrade, with `prefer_spark` active post-upgrade.**
- [ ] **2. TSan/ASan clean** - the item-9 focused rerun (§3 row 9) plus PR-2c's per-issue
      fault-injection scenario matrix (§5). **Both halves BUILT in PR-2c (#3848)**; the
      checkbox stays open until PR-6 records the run against the flip tree.
      **EVIDENCE SOURCE IS A LOCAL TSan BUILD, and must be stated as such wherever this
      criterion is signed off.** The new checkpoint is tagged `[tsan-heavy]`, which
      `tests/meson.build` filters out whenever `b_sanitize == none` - so it runs on NO PR
      and NO push CI leg - and the nightly TSan job runs against `main`, not `dev`. There
      is therefore no CI artefact for this criterion and there will not be one before the
      flip: whoever signs it off must run
      `meson setup build-linux-tsan -Db_sanitize=thread` themselves and paste the output,
      not link a workflow. The ASan half has the same shape with one extra step - the
      stock `x64-linux` vcpkg tree cannot run ASan at all (abseil poisons unused
      flat_hash_map slots at protobuf static-init time and trips a spurious
      `use-after-poison` before any test runs), so it needs the `x64-linux-asan` triplet
      built first; `triplets/x64-linux-asan.cmake`'s own header documents this.
- [ ] **3. 3-OS matrix**, written concretely: per-OS `yuzu.guardian_backend` heartbeat tag +
      `spark_running`/`spark_disabled` posture-key evidence captured, for:
      - Linux - Service mechanism on spark; File/Registry unsupported (left unregistered, per
        `agent.cpp`'s per-mechanism factory pattern).
      - Windows - all three mechanisms armed (File/Registry/Service).
      - macOS - all-unsupported, agent healthy (this is a tested pass state, not a skip).

      Evidence source, re-verified current: the backend-derivation log block is
      `agents/core/src/agent.cpp:1260–1286` (the `switch (avail)` over
      `GuardianEngine::SparkAvailability`, deriving the log line from the same function the
      `yuzu.guardian_backend` heartbeat tag uses - F7's anti-drift fix). `spark_failed_os`
      is computed at `server/core/src/agent_registry.cpp:2124` (incremented) /
      `:2296` (rolled up per-OS); its map is declared at `:1799`. (The kickoff plan cited a
      single line, `:1799` - that's the declaration; the actual per-event increment and
      rollup happen later in the same file, at `:2124`/`:2296` already cited just above -
      added here for precision.)
- [ ] **4. Gateway path evidence** - spark detection/heartbeat data surviving a gateway-proxied
      agent, not just direct-connect.
- [x] **5. UAT smoke**: arm on spark → induced drift → dashboard edge; `--spark-disable` rollback
      drill restores legacy enforcement (procedure in §6); journal gauges live (two
      `GET /metrics` reads against Rig B, 2026-09-06, ~15 min apart: `_pages` advanced
      124 → 154, confirming genuine progression, not just a non-zero snapshot;
      `_sent_labels`/`_batch_count`/`_batches_written` stayed flat between the two reads,
      consistent with their own metric descriptions - activity-triggered, not continuously
      incrementing - so only `_pages`'s progression is cited as proof of "live"; distinct
      from §4's CH-5-PROM alerting-rule logic); `/status`
      reports real `errored_rules` (this is PR #3175's fix - confirmed shipped, see "#2298
      sub-item confirmation" below). **The rollback-drill half was DONE 2026-09-04/05 (Rig B on
      BigColin, §6, §8)** - `--spark-disable` restart confirmed to restore legacy enforcement in
      ~8.6s, with a subsequent 14-hour clean run showing zero spark-state leak. **The
      arm-on-spark → induced-drift → dashboard-edge half is now ALSO DONE (2026-09-06, DGRHP,
      Windows, `file-change` mechanism)** - root-caused and fixed the two blockers the prior
      attempt left open, then attempted the full path three times across two arm windows (a
      second data point on Linux/`service-status-change` followed the same day, Rig B/BigColin -
      see §8's later update for that half): the
      first (corroborating-only - its `Emit` fired but was lost to an outbox stall before
      reaching the server, so it doesn't close the loop on its own) in the first window; the
      second and third (no restart between them) in the second window, each closing the full
      arm-to-dashboard loop:
      - **Root cause of the prior blocker, not just a retry** (corrected 2026-09-06: an
        earlier draft of this section attributed the stale login to `AuthDB`'s seed-once
        bootstrap making cfg edits inert; a peer session ("Rig Test", reviewing this PR
        before push) traced the opposite on the same build, and re-reading the source
        confirms that reading): `main.cpp` calls `auth_mgr.load_config(cfg_path)`
        unconditionally on every boot, populating `AuthManager`'s in-memory `users_` map
        straight from the cfg file's `username:role:salt_hex:hash_hex` line -
        `verify_password()`/`authenticate()` (`auth.cpp`) check the PASSWORD against *that*
        map, not against Postgres. So a cfg edit + a full server restart genuinely does
        reset a stale login, no `auth.users` touch needed - **but only for an admin row that
        already exists and is active; this recipe does NOT generalize to every account** (see
        the fenced scope below and #4020). That said, "not against Postgres" is
        narrower than it may read: both functions still make a live `auth_db_->get_user()`
        call AFTER the password check to confirm the account is still active
        (`auth.cpp` - "verify user is still active in DB (could have been soft-deleted)"),
        so a deactivated (not merely stale-password) admin row would still fail login with
        the identical generic 401 even after a correct cfg edit - only the credential check
        itself, not the whole login decision, bypasses Postgres. (Filed **#4020** for a
        related, more serious gap this review surfaced: `authenticate()`/`verify_password()`
        have no AuthDB fallback on a `users_` cache miss at all, so a dashboard-created user
        - never in the cfg file - can't log in after a fresh process restart; out of scope
        for this doc-only PR.) `AuthDB::seed_admin_if_empty()` is a separate, one-time
        Postgres bootstrap (seeds `auth.users` only when empty, for role/MFA lookups) and
        plays no part in either check above. The actual blocker in this session was the
        `/login` request shape below; a `DELETE FROM auth.users` + restart done along the
        way was not the fix and is not needed to reset this rig's admin login - a cfg edit
        + restart suffices. Separately, `/login` takes
        `application/x-www-form-urlencoded` (`extract_form_value`), not JSON - the wrong
        content-type alone produces the same generic 401 as a bad password, which is what
        actually cost the time here. The prior attempt's broken agent log capture (bare WMI
        `Win32_Process.Create`, no redirect) is fixed for good by launching with
        `yuzu-agent.exe`'s own `--log-file` flag - redirect-independent, survives any future
        WMI-launched restart.
      - **Live repro across two arm windows (no restart between the second and third edit)**:
        armed rule `dgrhp-drift-test-file` (`file-hash-equals` on
        `C:\rigA\drift-test.txt`, spark type `file-change`) confirmed armed via
        `/api/v1/guaranteed-state/rules` (armed at 2026-09-06T10:21:05Z, per the
        `guard.armed`/`guard.compliant` pair at that timestamp in the events log - the file's
        content at that instant became the new baseline `expected_value`. Whether that
        auto-rebaselining is correct for a rule with no explicit configured `expected`
        value is itself an open question this session didn't resolve - and a governance
        review of this doc found it compounds with an already-known trigger, **#3990**'s
        fleet-wide `full_sync` re-arm: any UNRELATED rule mutation anywhere in the fleet can
        silently reclassify a genuinely-still-drifted no-`expected` rule as compliant,
        with no remediation having happened. Filed **#4021** to track the fix; not
        addressed in this doc-only PR). DGRHP is one of this workstream's designated
        `prefer_spark` test rigs (§6 step 1's own procedure opens with "confirm ... agent
        running with `prefer_spark` active, spark armed" before any of this applies - the
        "Shipped posture today" row above is about the production default, not these rigs),
        and this is now directly confirmed rather than inferred from the `RIGA-DEBUG` log
        prefix alone (a locally-patched debug line, not present in this repo's source tree,
        so not by itself proof of which code path it instruments): the SAME agent restart
        that re-armed the rule at 10:21:05Z also logged, in the SAME second,
        `Guardian: spark path WIRED (prefer_spark=true); detection backend = spark` -
        `agent.cpp`'s own comment states this line is derived from the identical function
        (`guardian_backend_from_state`) the `yuzu.guardian_backend` heartbeat tag uses, "so
        this log and the tag can never drift apart" - so it is not merely circumstantial.
        This also closes a governance-review concern that the legacy Windows file guard
        (`guard_file.cpp`, `ReadDirectoryChangesW`) is itself event-driven, so an `Emit`
        firing "in the same second" cannot by itself discriminate spark from legacy - this
        log line can, and does. This confirmation is boot-scoped (it proves the backend at
        the 10:21:05Z restart, not independently re-checked at each later edit) - but
        `prefer_spark_` is set once at `GuardianEngine` construction and never reassigned
        anywhere in this codebase (no live-reload/toggle call site exists, confirmed by
        grep), and no further agent or server restart happened before the third edit, so the
        boot-time confirmation holds for the whole window. Separately, `reconcile_rule_locked`
        is the sole per-rule arm/disarm chokepoint enforcing mutual exclusion between the
        legacy and spark paths, and errors an arm failure rather than silently falling back
        (CLAUDE.md's routed-concerns spark row; not re-derived from this doc's own text),
        which rules out "backend is spark but this specific rule fell back to legacy
        anyway." First induced edit (2026-09-06T10:18:19Z, before the
        10:21:05Z re-arm above) fired an agent-side `Emit` in the SAME SECOND (`agent.log`),
        confirming the IOCP path fires immediately - but the resulting entry never reached
        the server (see the outbox finding below), so it doesn't count as a demonstration on
        its own. After restarting the agent and confirming a clean 0-pending outbox, a SECOND
        induced edit (2026-09-06T10:25:37Z) fired `Emit` in the same second again, and a
        `drift.detected` event carrying that same detection timestamp was visible via
        `GET /api/v1/guaranteed-state/events?rule_id=dgrhp-drift-test-file` when checked
        roughly 8 minutes later - `{"event_type":"drift.detected","detected_value":
        "80517dbd...","expected_value":"5584d13c...","timestamp":"2026-09-06T10:25:37Z"}`, a
        real hash mismatch, not a coincidental compliant re-arm (server-side ingest latency
        was not separately measured). A THIRD induced edit (2026-09-06T10:52:02Z), with NO
        agent or server restart since the second edit, produced a fresh `Emit` in the agent
        log at the same second (`11:52:02.118` local, PID `31856` - the same event-driven
        worker PID as the second edit, distinct from the periodic re-verification loop's PID
        `15844` seen re-flagging the still-unremediated second divergence every ~5 minutes in
        between - the convergence scheduler's file lane, `kGuardianFileLaneCadenceMs`
        [10-minute default, halved locally on this rig for this testing only, per §8's own
        note] - NOT `errored_refresh_ms`, which only re-fires on an Unhealthy/read-error
        state and structurally cannot be what's re-flagging a persisting compliant-vs-drifted
        divergence) and a NEW `drift.detected` event at `2026-09-06T10:52:02Z` - confirmed via
        REST within seconds this time. Its `detected_value` was the empty-file SHA-256
        (`e3b0c442...`), not the marker text's hash - the write raced the eval (PowerShell's
        `Out-File` truncates before it writes content, and the IOCP callback fired on the
        truncate), a real but benign timing artifact of the test method, not the mechanism -
        the divergence was still real and still detected. **Caveat this session didn't rule
        out**: if `ReadDirectoryChangesW`/the IOCP layer coalesces the truncate and the
        content write into a single notification rather than firing on the truncate alone,
        the persisted event's `e3b0c442...` value could be a permanent, misleading record of
        a state the file was never actually left in (post-write content never separately
        evaluated until the next periodic tick) - not re-investigated here since it doesn't
        change this criterion's own conclusion (a real divergence was detected end-to-end
        either way), but worth flagging for anyone citing this specific event later.
        **Dashboard-edge evidence,
        actually observed, not just source-traced** (a governance review caught that the
        first draft of this paragraph asserted the render path from source alone -
        `GuardianRoutes::render_events_fragment` in `guardian_routes.cpp` calling the same
        `GuaranteedStateStore::query_events()` the REST handler reads, and `guardian_ui.cpp`'s
        `.et-drift_detected` CSS class for the `drift.detected` type - without ever actually
        fetching the page; that source trace still stands, but it's plausibility, not
        observation, and the checklist item literally says "dashboard edge"): a live,
        authenticated `GET /fragments/guardian/events?type=drift.detected` against DGRHP
        (2026-09-06T12:10:12Z, after this paragraph's own review) returned real rendered
        rows, e.g. `<div class="event-item">...<span class="event-type
        et-drift_detected">drift.detected</span>...<strong>riga-reg-0800</strong> on
        <strong>ba901a98-...</strong></div>` - confirming the render mechanism live. The
        specific rows returned were from a different (registry-type, `riga-reg-*`) rule
        family, not `dgrhp-drift-test-file` itself - the fragment has no `rule_id`/`agent_id`
        filter and returns only the most recent 20 fleet-wide, and this rig had a large
        burst of other rules' drift events between this criterion's own edits and the later
        fetch. The mechanism is now directly observed; this specific rule's own row was not
        re-captured before being pushed out of the top-20 window.
      - **Retires an open campaign question, not just closes the checklist item**: the
        "one-shot registry/file watch" observation from the prior CH-5-UAT exploratory
        campaign (a second divergence in the same arm-window going undetected - not itself
        folded into this doc's own §3/§4/§8 before now, only into that campaign's own session
        record) was flagged there as possibly an artifact of outbox congestion rather than a
        real mechanism limit, never cleanly isolated. This
        session produced a SECOND and a THIRD distinct divergence inside the same arm-window
        (the third with no restart at all since the second, and a confirmed-healthy 0-pending
        outbox throughout), and both were detected immediately - the one-shot theory does not
        hold under clean conditions for the `file-change` mechanism; downgrade it from
        "unresolved" to "disproven as a general defect for file-change, was congestion-shaped."
        The original observation was on a registry-type rule, not re-tested here (Registry
        mechanism is also Windows-only File/Registry-class, same watcher family) - scoping the
        retraction to what was actually re-tested rather than the whole family. Not re-opening
        it as an issue.
      - **Also reproduces, live, a related-but-separate existing finding - not new, no issue
        filed**: after the server restart done during the login-fix sequence above (the
        `DELETE FROM auth.users` + restart step; agent process itself untouched at that
        point), the outbox `pending` count
        climbed from 787 to 1088 over several minutes and never drained, mirroring the
        `#2049`-shaped "Subscribe doesn't reliably reconnect after a server-only restart"
        symptom this workstream already has open threads on (§3 row 4's #3953/#3966 family;
        §4's retracted #3989 causal chain). The FIRST induced edit's `Emit` was almost certainly
        lost into this exact stall (its entry never surfaced server-side); the agent restart
        that unblocked the SECOND edit is the same documented workaround, not a new fix.
        Recorded here as corroborating evidence for the existing tracked gap, not filed
        separately.
- [ ] **6. Legacy-vs-spark parity capture**, any diff fully explained by
      `docs/spark-legacy-delta-registry.md`.
- [ ] **7. Resource evidence** vs `docs/spark-rebuild-baselines/`.
- [ ] **8. External gates green**: #2340 CH-2 + CH-5-PROM (promtool) - **done**, PR-4 merged as
      **#3858** (2026-09-02T13:00:49Z), still needs CH-5-UAT (UAT rig, Rig A - §8) before this
      criterion is fully green. CH-11 does **not** gate this criterion (ruled 2026-09-01 - see
      §4).
- [ ] **9. Rung-3-implementation-ready sign-off** + the enforcement-gap budget recorded. Already
      ruled 2026-08-23: the flip's enforcement gap (§3 row 2) is temporary with no fixed
      remediation budget attached - stated here, not re-litigated. (This ruling is recorded
      only in the delivery-plan draft this doc supersedes, not restated in any other committed
      doc - the substance is inlined here rather than cited by a bare decision label, to avoid
      colliding with `docs/spark-legacy-delta-registry.md`'s own differently-scoped decision
      labels of the same shape.)

## 3. #2233 item table

Re-pulled live (`gh issue view 2233 --json body`) on 2026-09-02, not transcribed blind from
the kickoff plan. The issue is `CLOSED` (auto-closed by PR #3821's "closes #2233", see the
warning at the top of this doc) but its checklist body is the source of truth here, and 8 of
10 items are still unchecked in that body. Every citation below was re-grepped against
`origin/dev @ bd387afec` - several of the issue's own citations have drifted (the file has
grown substantially, largely from PR #3821's rework); drift is called out per row.

| # | Item | State | Evidence (re-verified 2026-09-02) |
|---|---|---|---|
| 1 | Boot ordering | **DONE - both halves of the issue's bar now tested** | `guardian_->start_local()` runs at `agent.cpp:1292`, after `wire_spark_engine()` (call at `:1254`) and after `SparkEngine` construction (`:1207`) + `start()` (`:1225`) - ordering confirmed correct. #3884 (merged 2026-09-03, `282c3b58a`) added two tests in `test_guardian_engine_spark_reconcile.cpp`: `"PRODUCTION boot order: wire_spark_engine before start_local"` (`:1431`) proves the behavioral half - the issue's own bar verbatim, "test a non-empty cached KV policy armed during pre-network startup" - in the real production call order; `"source tripwire: Agent::run() calls guardian start_local() before opening the Subscribe stream (#2233 item 1, the pre-network property)"` (`:1558`) closes the half the behavioral test cannot reach (there is no Agent-level mocked-gRPC test harness): it asserts, by reading `agent.cpp`'s own source text, that `guardian_->start_local()` appears before `stub->Subscribe(&sub_ctx)` - a textual ordering guarantee, not a runtime one, but one that fails loudly if a future edit reorders them. Line numbers verified against THIS PR's own tree (this PR's own edits to the same file - the item-4 death-test rewrite and a comment fix, both in §3 row 4's scope - net to the same line count as #3884's original `282c3b58a`, so the citations happen to match both, but that is this tree's state, not a claim about `282c3b58a` in isolation), not from #3884's own PR description alone. |
| 2 | Enforcement posture | **RULED, closed** | Dave, 2026-08-28 (issue comment): hard flip, no enforcement preservation, no operator warning required, no `spark_enforce_active` signal required. |
| 3 | Arm/disarm liveness | **DONE - the liveness wedge, the #3831 residual, and #3816 are all fixed (#3816 by PR-2e, merged to `dev`)** | PR #3821, merged 2026-09-02. Routes File/Registry/Service arm/disarm off `registry_mu_` onto `GuardianIoExecutor`; fixes a `policy_generation_` undercount via a new 3-state `ReconcileOutcome`. A scoped Gate-8 re-review on the PR itself found and fixed 2 more guard-arming gaps of the same shape; one more (`arming_rollback`) deferred as **#3831** (title: "attach_rule's arming_rollback is armed after its own protected mutation"). **Fixed in code by #3884** (merged 2026-09-03, `282c3b58a`): `arming_rollback` is now promoted to function scope (`guardian_spark_runtime.cpp:225`, `.committed = true` at `:503`) - the same idiom PR #3821 already used for the other three guards it fixed, mirroring `prior_disarm_rollback` - relying on C++ stack-unwind ordering as the safety argument. Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. **Tracking gap, not a code gap**: `gh issue view 3831` still reports **OPEN** as of this PR's re-verification - #3884's body lists #3831 among what it addressed but did not use a closing keyword, and nothing has closed it since; a future PR or a manual close should reconcile this, but the fix itself is confirmed shipped. *(Pre-PR-2e history, kept for context only - every claim in this paragraph through "flagged here so the full set is visible rather than #3816 alone" below describes code PR-2e has since removed; see the "#3816 fixed by PR-2e" paragraph at the end of this cell for the current state.)* A second, distinct residual was #3816 (filed OPEN - "GuardianIoExecutor has no abandonment-signal API - a late-succeeding arm/read ... can leak a live subscription/handle"; this row narrows that title-level framing - see below): a backend arm that succeeds just after its caller has timed out and abandoned it could leak a live subscription. `attach_rule`'s generation-based self-check (formerly `guardian_spark_runtime.cpp:379-389` pre-PR-2e; that self-check no longer exists on this tree, see below) narrowed this to a rare scheduling race on the caller's bounded-timeout path, but the code's own comment stated plainly "this is NOT airtight." A second, distinct trigger for the same leak was found later (`FortitudeEtc`, #3816 comment, 2026-09-02, during the #3831-batch Gate 8 review): `GuardianIoExecutor::run()`'s post-launch `cv.wait_until` wait (`guardian_io_executor.hpp:376-388`) sits outside `run()`'s own try/catch (which covers only admission/launch, `:294-372`); if that lock construction throws (a rare `std::mutex::lock()` failure, not a timeout - derived SHOULD/MEDIUM, E5 rare/near-E6), the caller-side exception can unwind before the erase that would make `still_wanted` return false, so the same leak can fire without any caller timeout at all. Neither trigger is fixed today. `submit_disarm_off_lock` (the disarm side) and `GuardianStateReader` (state reads) have no equivalent self-check at all - but their late-completion cost is narrower than a leak: a disarm or a state read that lands late simply completes with no caller left to consume it (`GuardianStateReader`'s blocking read helpers return by value with their OS handles - `FdGuard`/`HandleGuard`/`RegKeyGuard`/etc. - scoped as function-locals that close before return, per `guardian_state_reader.cpp:59-71`'s own comment: "the reader opens and closes within one call; nothing escapes") - wasted work, not a leaked handle. This narrows #3816's own title ("arm/read ... can leak a live subscription/handle") to arm-only; the issue's body agrees with this row, only the title is broader. The abandonment-signal API gap is shared by all three call sites; only the arm case actually leaks. Different defect class from #3831 (a mutation-ordering bug in the rollback path) - not subsumed by it or by anything else in this row. **Detection signal: none today** - `GuardianIoExecutor::Stats.counters[..].timed_out` (incremented at `guardian_io_executor.hpp:386`, one line before the discard-comment return at `:387`) and `GuardianSparkRuntime::backend_op_timeouts()` are both read only by unit tests, never wired to a heartbeat tag, log line, or metric; a real occurrence would be invisible fleet-side. #3816's own filed text states it "should gate the `prefer_spark_` flip (F14)", per the governance disposition that raised it (`ent-1`, `governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`); no ruling exists overriding that, so this doc treats it as **gating PR-5 only** (not PR-4, which is independent - see §1). A fully airtight fix needs `GuardianIoExecutor` extended with an abandonment-signal API shared by both `GuardianSparkRuntime` and `GuardianStateReader` - a design change, not a line-count fix, so it does not fit PR-2a's mechanical batch alongside #3831/#3847; no PR slot is assigned yet (§1). PR-5 cannot proceed until #3816 is either fixed or explicitly risk-accepted by a future ruling - it is deliberately NOT added to §5's risk-accept register here, since #3816's own text asks not to "silently ride along unaddressed." **Siblings, not ruled on here**: #2233 item 3's governance run (`governance.d/2233-arm-disarm-liveness-M.4BNt5t.jsonl`) produced seven open follow-up issues in total - #3816 and #3831 (both discussed above) plus five more, all confirmed OPEN: #3810 (backend-op-deadline config override, self-described as "dormant today ... becomes live at the F14 flip" - not a self-declared gate), #3811 (`rollback_spark_wiring_locked()` doesn't wait for `active_backend_op_workers()==0`, shares #3816's orphaned-worker shape, its own text corrects an earlier "fully dormant" assumption since `wire_spark_engine()`'s wiring/rollback path runs at boot lifecycle-only - but does not itself claim to gate the flip), #3812/#3813/#3814 (status-visibility and counter-precision gaps, no gating language found in any of the three). Of the seven, only #3816 self-declares flip-gating; whether any of the other five (#3831 is DONE in code, per above) should is not this row's call - flagged here so the full set is visible rather than #3816 alone. **#3816 fixed by PR-2e** (branch `fix/3816-guardian-io-executor-abandonment-signal`, merged to `dev`): `GuardianIoExecutor::run()` now delivers every result `fn()` returns normally exactly once - either to the caller's return value, or (if the caller already decided Timeout/Stopped) to a new `on_abandoned(T&&)` callback (a thrown `fn()`/`WorkerThrew` has no `T` to deliver and correctly reaches neither destination), both decisions serialized on the SAME wait-side lock (constructed once, held across `spawn_detached`, reused for `cv.wait_until` - no lock is ever constructed after launch). `attach_rule`'s old `still_wanted` self-check against `arming_keys_` (the "NOT airtight" mitigation this row previously described) is removed entirely - the executor itself now owns the decision, closing both triggers named above: the caller-timeout race (trigger 1) is closed architecturally by the exactly-once contract, and the wait-path exception (trigger 2, `FortitudeEtc`'s finding) no longer has a catchable post-launch failure to speak of - a `std::mutex::lock()` failure on the wait-side lock now happens strictly pre-launch and folds into the existing `IoFailure::LaunchFailed` (no new enumerator; `set_throw_before_wait_lock_for_test` is the regression seam, closing `#saf3821-5`). `attach_rule`'s `on_abandoned` disarms a late-succeeding arm and counts it separately (`GuardianSparkRuntime::backend_op_late_arms()`, #3813's distinction kept at the source); `submit_disarm_off_lock` and `GuardianStateReader` are unchanged (a late disarm/read still costs nothing to discard, per this row's own earlier analysis). Mutation-verified: the rewritten regression test (`test_guardian_spark_runtime.cpp`, formerly "C1/c1") asserts `FakeBackend`'s exact armed/disarmed id vectors match, not just balanced counts, and goes red when the `on_abandoned` wiring is removed. **Detection signal: still none today** - the new `Counters::abandoned` (executor) and `backend_op_late_arms_` (runtime) counters exist and are test-asserted, but neither is wired to a heartbeat tag; #3415 (OPEN) already owns that egress and should point at these new counters rather than a new issue being filed. Deliberately does not overlap #2818's engine-level "subscription death" gap (a related but separable defect the sibling `#3848` fault-injection work owns) - #3816's fix touches only the executor/runtime abandonment contract, not `SparkEngine`'s whole-key teardown. |
| 4 | Stalled sink cannot freeze the runtime | **DONE - PR #3961, merged 2026-09-04T15:20:25Z (`acd83bd48`); #3953/#3966 residuals RESOLVED - merged as PR #3982 (`1e7a5346c`, 2026-09-05T18:09:10Z) - item 5 tracked separately at #3972** | Confirmed the hazard exactly as the previous re-verification narrowed it: `drain_mu_` (`guardian_spark_runtime.cpp:1353`, `lock_guard` held for the whole `drain_bounded()` call) has one production caller chain, `GuardianOutboxDrainWorker::drain_bounded()`, and the worker thread was wedged for the duration of a stalled `send()` with nothing else progressing until it unwedged. #3847's own acceptance bar is explicit that dropping `drain_mu_` around `send()` is NOT sufficient (a no-op with one production caller - the worker thread is still inside `Write()` either way); it requires "the drain worker's next tick proceeds while a prior send is artificially stalled." Fixed by detaching the call: a new `GuardianOutboxSendExecutor` (`agents/core/src/guardian_outbox_send_executor.hpp`, new file) runs `send` on a single-flight detached worker (mirroring `guardian_io_executor.hpp`'s spawn-per-attempt shape, NOT its `run()` - `run()` discards a late result on timeout, which is correct for an idempotent read and wrong for a send: a discarded `Sent` would drop the entry without ever retrying it). `GuardianOutboxDrainWorker::wrapped_send()` (`guardian_outbox_drain_worker.hpp:408`) bounds the worker's own wait to `kGuardianSendOfferWait` (200ms) and retains the head if the real send hasn't finished by then, letting journal maintenance and the next tick proceed; the send itself keeps running detached until it completes. Single-flight by construction (one gRPC stream write in flight at a time), keyed on `OutboxEntry::event_id` (the existing wire-idempotency key) so a generation-supersede purge mid-send is detected rather than misapplied. Covered by the orphan-exit contract already established for the state-reader and arm/disarm executors: `active_send_workers()` (`guardian_outbox_drain_worker.hpp:380`) sums into `GuardianEngine::active_io_workers()` (`guardian_engine.cpp:1551`), so `send`'s capture of `AgentImpl` state stays safe under `hard_exit.hpp`'s existing grace-then-kill contract exactly as it did before, just via a different mechanism (previously: synchronous join; now: the orphan-exit sum). **Not fixed**: `stream_write_mu_` contention (`agent.cpp`) - a detached send still holds that mutex for the stall's duration, so another sender sharing the same stream (a response, a DEX signal) still blocks on it; this narrows the drain WORKER's own availability, not the shared stream's. The send path remains unreachable in production today (`prefer_spark_` is false at rung 7.7a), so this is pre-flip hardening, not a live-traffic fix. Tests: `test_guardian_outbox_drain_worker.cpp` gained two new cases proving journal maintenance keeps advancing and the send stays single-flight while artificially stalled (CV-gated, not a real network stall), plus a strengthened CH-1 proving `stop()` now decouples from an 800ms send entirely (previously only asserted a bound that happened to be looser than the send). The existing role-marker test and the `test_guardian_engine_spark_reconcile.cpp` mtx_-abort death test both needed updating: `send` no longer runs on the thread `stop()` joins, so `on_guardian_joined_thread()` correctly now reads false inside it - the death test's hostile call was moved to a directly-spawned thread wearing the same marker, since it no longer has a live vehicle through `send`. **Governance found and fixed FOUR BLOCKING concurrency defects across four review rounds before this PR was pushed** - BLOCKING and SHOULD findings are recorded here in full rather than only the final clean state, since that is what a future flip-readiness auditor needs (LOW/INFO residuals are NOT all repeated here - `governance.d/3847-outbox-send-executor.rGvKq2.jsonl` is the complete ledger; its deferred LOW/INFO residuals are consolidated and tracked at #3953, acceptance criteria: each resolved or explicitly risk-accepted before the F14 flip - see #3953 itself for the current count, not a number restated here; a later adversarial-review pass's own findings are in `governance.d/3847-adversarial-review-synthesis.md`): **(1)** `launch()` wrote its bookkeeping (`in_flight`/`done`) AFTER `spawn_detached()` instead of before, so a fast-completing send could have its published `done=true` clobbered back to `false` by the launcher's own write, silently wedging that one entry forever (cpp-expert, empirically reproduced ~1-in-1000 in a standalone harness). **(2)** `offer()`'s mismatch branch (the head changed under a stalled send - an ORDINARY coalesce/withdrawal, not a rare race) never reclaimed the slot once the orphaned worker finished, so `in_flight` stayed permanently true against an `event_id` that could never recur again - wedging the ENTIRE outbox for the life of the process, not just one entry (security-guardian and cpp-safety, independently). **(3)** A single shared `GuardianOutboxSendExecutor` instance served BOTH the lifecycle log and the compliance/health log (`drain_bounded()` calls `drain_log_unlocked` once per log, `guardian_spark_runtime.cpp:1442/1454`) - a merely-slow-but-succeeding lifecycle send made the compliance call hit the SAME executor's mismatch-orphan branch and return Retain WITHOUT the compliance send ever being invoked, silently starving an entire Guardian audit lane for as long as lifecycle stayed busy (unhappy-path finding UP-1; security-guardian separately flagged this as I1 audit-control-failure, not merely I5 availability). Fixed by giving each lane its OWN executor instance (`lifecycle_send_exec_` / `compliance_send_exec_`, `guardian_outbox_drain_worker.hpp:442-443`), routed by `OutboxEntry::domain` (`:409-410`). **(4)** Round (1)'s own fix placed the `in_flight_event_id` string-copy bookkeeping one statement BEFORE the try/catch meant to guard allocation failures, so a `bad_alloc` on that specific copy reopened defect (1)'s wedge class (cpp-safety, re-review). All four fixed and independently re-confirmed by follow-up governance passes; direct regression coverage added in `tests/unit/test_guardian_outbox_send_executor.cpp` (defect 2, mutation-verified RED) and `tests/unit/test_guardian_outbox_drain_worker.cpp`'s `"item 4 regression: a stalled lifecycle send does not starve compliance delivery"` test (defect 3, mutation-verified RED against the pre-fix single-executor code - a first draft of that test used a bounded 400ms stall and passed on BOTH pre- and post-fix code, since a bounded stall only DELAYS compliance rather than skipping it; the test had to stall lifecycle indefinitely to actually discriminate the two designs). **Two SHOULD-level optimizations were built, wired, and deliberately REVERTED**: waking a parked `offer()` call early on `stop()` (would have shaved up to `kGuardianSendOfferWait` off shutdown latency) and a completion-waker firing the drain worker's cadence on every finished send - each broke a different pre-existing, load-bearing timing test in this file (a `stop()`-join durability-ordering test; a refill-rearm-without-external-wake test) when tried; both were reverted rather than redesigning either pre-existing test under this PR's time budget. The second revert leaves a real cadence regression versus pre-fix behavior, not merely a missed optimization (sre finding): pre-fix, a 300ms send blocked the loop inline and the next tick started as soon as it returned; post-fix, a send that runs longer than `kGuardianSendOfferWait` (200ms) but still succeeds hits `offer()`'s Retain path and isn't re-checked until the next enqueue or the periodic backstop (`kDefaultPeriodicBoundMs`, 5s in production) - e.g. a 300ms send waits out roughly 16x its own duration before the next check, up to roughly 25x for a send finishing just past the 200ms threshold, shrinking toward 1x as it approaches the 5s backstop. Both trade-offs are left as documented notes on `GuardianOutboxSendExecutor::offer()`'s `wait_until` call and `stop()`. **Open, deliberately not fixed here** (sre, Gate 6): no heartbeat tag/counter/log exists for "a send has been stalled for N seconds" - a loud pre-fix hang traded for a silent post-fix slow-drain with no operator-visible signal once this ships live; tracked at #3953, recommended before the F14 flip, the same way row 3 tracks #3816's "Detection signal: none today." A TOCTOU fix landed in a later commit on this same branch closed a related admission-race defect inside `GuardianOutboxSendExecutor::launch()` (adversarial-review finding, `governance.d/3847-adversarial-review-synthesis.md`) and found a structurally identical, deeper residual one call frame out in `GuardianOutboxDrainWorker::stop()`'s own non-atomic shutdown sequencing - also tracked at #3953, not fixed in this row. **Post-merge**: an independent `/pr-review` adversarial pass (Kimi K2.7 + Codex, fully dynamic, dedicated 200k/30k-round race harnesses) found a THIRD, related admission-race that all prior review rounds on this row - including the PR's own author-run adversarial pass - missed: `launch()`'s `AliveTicket` (the sole source `active_worker_count()` reports) is armed in a second, independent lock acquisition released and re-acquired after the `stopping`-recheck block the TOCTOU fix added, so `stop()` can return with `stopping=true` already set while `active_worker_count()` still transiently reads 0, even though admission is already committed - deviates from `GuardianIoExecutor`'s own precedent of arming its ticket inside the single admission lock. Non-blocking today because `GuardianOutboxDrainWorker::stop()`'s unconditional `thread_.join()` plus `GuardianEngine`'s shared mutex between `stop()` and `active_io_workers()` means no caller can observe the gap - a DIFFERENT, more durable safety argument than the rest of this row's residuals, most of which are bounded only by `prefer_spark_=false` and stop being safe the moment F14 flips it: this one is a property of the call graph, independent of that flag (sre, Gate 6 re-review). Filed **#3966** with the fix already spelled out (arm the ticket inside the existing lock); tracked as a sibling to #3953, not yet folded into it. **Resolved**: `fix/3953-3966-outbox-hardening` (PR #3982) arms `AliveTicket` inside the same admission lock (closing #3966), closes both lane executors before publishing `sig_->stopping` (closing #3953 item 6, the structurally identical residual one call frame out), adds an internal wait-clamp so a stalled send is re-checked within ~200ms instead of riding out the periodic backstop (item 3), counts+logs orphan exceptions and send stalls with both surfaced on the heartbeat (items 1+2), and asserts the Lifecycle-vs-Compliance/Health domain split (item 4). Item 5 (cross-lane wire reordering) is filed separately as #3972 rather than folded in here, since its watertight fix (merge-drain by global sequence) is real follow-on work, not a same-PR fix. A second governance run on PR #3982 itself (Gate 8 re-review of its own fix round) also filed **#3980**: a deeper, unbounded stall-undercounting case on a lane whose log empties while its orphan is still in flight - needs new API surface, deliberately out of scope for #3982. |
| 5 | Firewall both teardown scope guards, make them noncopyable | **DONE - confirmed via commit archaeology; PR-2b is dropped from the delivery plan** | The issue cites two copyable guards with implicitly-noexcept destructors at `guardian_engine.cpp:66–79` / `guardian_spark_runtime.cpp:31–44`. `git show 25f73e231` (2026-07-18, part of **PR #2283**, "Guardian spark PR-1a: send-path + exception-safety + drain hardening, items 1-4", merged 2026-07-18 - a full 6 weeks before #3821) deletes the identical `struct ScopeExit { std::function<void()> fn; bool committed{false}; ~ScopeExit() { if (!committed && fn) fn(); } };` from each of `guardian_engine.cpp` (old hunk `@@ -64,20 +65,11 @@`, struct at old lines ~67-79, matching the issue's `66-79` citation almost exactly) and `guardian_spark_runtime.cpp` (old hunk `@@ -28,21 +29,6 @@`, struct within old lines 28-48, containing the issue's `31-44` citation) - copyable, implicitly-noexcept destructor invoking a throwing `std::function`, the exact shape item 5 describes, at the exact lines item 5 cites. The commit's own body states it explicitly: "B3: the two Guardian ScopeExit guards are replaced by one terminate-safe GuardianRollback (guardian_scope_guard.*): its dtor swallows a cleanup throw (which would std::terminate the agent mid-unwind) and counts it." `GuardianRollback` (`agents/core/src/guardian_scope_guard.hpp`) is noncopyable (copy/assign deleted) and its destructor never propagates (`try { fn(); } catch (...) { count + best-effort log }`) - now used 3× in `guardian_engine.cpp` (lines 242, 623, 1384) and 6× in `guardian_spark_runtime.cpp` (lines 216, 265, 288, 321, 424, 547) - counted by direct `grep -nE '^\s*GuardianRollback [a-z_]+;'`, cross-checked by two independent governance reviewers. Confirmed as part of **PR #2283** (`gh pr view 2283 --json mergeCommit` + `git merge-base --is-ancestor 25f73e231 <that commit>` both check out), merged 2026-07-18 - one day after #2233's creation timestamp (2026-07-17), and a full 6 weeks before #3821. Because the issue's own citations match the pre-fix code exactly, item 5's text was accurate at the time it was written and simply never updated once PR #2283 landed - not a case of speculative or drifted citations. **PR-2b in the delivery plan (item 5, "teardown-path-specific, merges immediately before item 9 runs") had no remaining work and is dropped** - confirmed by the operator 2026-09-02, recorded on #3438; the delivery plan's Lane A now runs PR-1 → PR-2a → PR-2c directly. No successor tracking issue needed. |
| 6 | Hard agent-side file-hash maximum | **DONE - scope grew to a server-side reject, single-sourced** | #3884 (merged 2026-09-03, `282c3b58a`) landed a new shared header, `common/include/yuzu/guardian_file_hash_limits.hpp` (`kMaxFileHashBytes = 1073741824` / 1 GiB), consumed on BOTH sides: the agent clamps at `guardian_engine.cpp:1057` and `guardian_spark_bridge.hpp:295` (the legacy/spark paths this row originally flagged as unclamped), and the server now REJECTS an over-ceiling authored value at authoring time in `guardian_rule_spec.cpp:152/161`, with the ceiling also published into the JSON schema (`guardian_schema_registry.cpp:177`) - a `static_assert` at `guardian_rule_spec.cpp:25` pins a human-readable error string to the same constant so the two cannot drift textually either. One accepted residual, ruled by Dave 2026-09-02 (ledger commit `5ae6e05db`): a `file-hash-equals` rule authored ABOVE 1 GiB *before* this PR shows a false `<oversize>` drift on upgrade, since the new server-side reject cannot retroactively catch an already-stored rule - mitigated via `docs/user-manual/upgrading.md`'s Version Compatibility table (pointing at `GET /api/v1/guaranteed-state/rules` to find affected rows), not a startup-time enumeration. Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. |
| 7 | Backpressure-drop surfacing (=#2993) | **DONE** | The lifecycle-log outbox capacity default is 4096 (`guardian_spark_runtime.hpp:170`, `outbox_capacity{4096}`; issue didn't cite a line). #3884 (merged 2026-09-03, `282c3b58a`) wired `outbox_backpressure_drops()` into fleet visibility: a new `uint64_t` counter field + accessor, no longer test-only-consumed. (Same PR also closed #2233 item 7, the sibling lifecycle-audit-log backpressure counter, `lifecycle_backpressure_log_fires_` - a separate counter for a separate log, not this row's own #2993 scope, but landed alongside it in the same batch.) Verified directly against `origin/dev @ 282c3b58a`, not from #3884's own PR description alone. |
| 8 | Multi-rule mixed-capability selection | **Moved to P3 lane** | Ruled 2026-09-02: the issue's own text says "harmless while spark cannot enforce ... must be enforced before spark gains enforcement" - item 2's no-enforcement-at-flip ruling removes the pre-flip premise. Now a P3 (enforce-cutover) prerequisite, not flip-gating. (This is what dropped PR-3, ~2-4 days, off the flip's critical path before this doc was even drafted.) |
| 9 | Focused TSan + shutdown/fault-injection | **Test BUILT in PR-2c (#3848); rerun still owed by PR-6** | The issue cites a single "instantaneous fake backend" TSan test at `test_guardian_spark_runtime.cpp:598–643`. The file has grown to 3551 lines and that range no longer holds a TSan test. There are now **three** TSan-checkpoint test cases (`grep TEST_CASE.*tsan`): `:1530` ("concurrent attach/detach/evaluate/drain do not race"), `:3061` ("concurrent pagers + a drainer do not race"), `:3293` ("concurrent persist + page + prune + drain do not race, QE-1"). None of the three arms `FakeBackend`'s `hang_next_arm`/`hang_next_disarm` gate (added for item 3's own fix, confirmed present and used at `:1744` onward across 10 distinct deterministic single-scenario `TEST_CASE`s) - so the issue's core finding still holds under the current code: concurrency is proven race-free only against an instantaneous fake, not against a backend that can actually block. This is the literal scope #2224's approval was conditioned on. Tracked fresh as **#3848** (PR-2c scope). PR-2c builds the deterministic per-issue scenario seams first (§5), then this rerun executes against that tree. **PR-2c status:** the missing test now exists - `"concurrent attach/detach/evaluate/drain do not race when the backend and the send callback BLOCK (TSan checkpoint, #3848)"`, tagged `[spark][runtime][liveness][tsan][tsan-heavy]`, which parks `FakeBackend`'s arm, its disarm AND the drain send callback via a `BlockingGate` built as an epoch/pulse extension of the very `hang_next_arm`/`hang_next_disarm` idiom this row names as unused by the other three. It reconciles every subscription id handed out against every id released, and requires the executor's `rejected_key`/`rejected_capacity` to be zero (via a new `GuardianSparkRuntime::io_executor_stats_for_test()`) so that reconciliation is a proof rather than a likelihood. **What it can and cannot show, stated because the framing changed under review:** `attach_rule`'s worker already self-disarms a late arm success via its `still_wanted` re-check, so a leaked subscription is NOT reachable on this tree - the census is a NO-REGRESSION check on that contract, not a leak detector. Verified by mutation: removing that self-disarm fails the census (27 live subscriptions against 6 armed keys). **This row does NOT close on PR-2c** - the criterion is the RERUN against the flip tree, and §2 criterion 2 records that its evidence can only ever be a local TSan build. |
| 10 | Doc drift | **Fixed in this PR** | `docs/spark-stage2-guardian-consumer-design.md` - the issue cited line 500; the actual current line (file has grown) was 949, still reading "observe rung (2) defaults to the spark path", stale against the re-sequenced ladder (this is impl-rung-7 in current terminology). Corrected as part of this PR - see the diff on that file. |

## 3a. Async-arm acknowledgment track (R5, rung 9c)

**Not one of #2233's 10 items above, and not part of this doc's own PR-1 → PR-2a..e →
PR-4 → PR-5 (flip) → PR-6 (evidence closeout) numbering** - a separate body of work,
recorded here because it occupies the same calendar slot this doc's own ladder tracks:
**after PR-2c/PR-2d and before PR-5 (the flip)**. Both are now DONE: PR-2c (row 9
above, #3848 merged), and PR-2d - `fix/2818-subscription-death-notification` merged as
**PR #4075** (`2026-09-07T13:41:24Z`), closing #2818 the same moment (**corrected
governance round, 2026-09-07: verified live via `gh issue view 2818` / `gh pr list`**
- the prior wording in this row, written a few hours after PR #4075 actually merged,
had not caught up and stated PR-2d as still unpushed; the Sign-off cell above carried
the identical staleness and is now corrected too, same round). This track's own
sequencing precondition ("after PR-2c/PR-2d") is therefore satisfied. Full design: `docs/spark-stage2-guardian-consumer-design.md`
§Async-arm acknowledgment (R5); intentional-delta row:
`docs/spark-legacy-delta-registry.md` A3.

Decouples `GuardianEngine::apply_rules()`'s rearm window from OS-watch confirmation -
closes the ~55 ms spark-vs-legacy gap the #3990 diagnostic measured (spark 127-140 ms
vs legacy 70-86 ms on a 62-rule cohort). Lands dormant behind `prefer_spark_=false`,
same posture as every PR tracked elsewhere in this doc. Its own ladder is **PR-0**
(this docs change) through **PR-6** (a Service-mechanism positive-initial-readiness
signal) - reviewed across seven rounds: six against the (uncommitted) plan document
(Astra/Codex ×4, Fable ×multiple, Kimi K3 ×2), then a seventh, an adversarial review
of the committed PR-0 transcription itself (this file included), 2026-09-07 -
**corrected round, 2026-09-07**: an earlier version of this sentence read as if all
seven reviewed one thing, contradicting its own round-7 parenthetical. None of the
seven review rounds is a `/governance` run - this repo's own `/governance` pipeline
runs separately, per-PR as the ladder lands, same as every other row in this
document. This PR-0 commit's own `/governance` pass ran 2026-09-07 (10 agents across
Gates 2/3/4/6, Gate 5 skipped) against the round-7-fixed transcription, before push -
no BLOCKING findings; ~25 non-blocking findings folded in directly, plus one genuine
open design question (R5.2's "expired"-vs-K-bound ambiguity) surfaced and left
unresolved for PR-1/PR-2, not silently picked.

**Why it doesn't gate on #2233 or appear in the row-3/row-9 evidence above**: this
track's own PR-5 (fault wiring) and PR-6 (the Service signal) are themselves ruled
(Dave, 2026-09-07) as prerequisites of *this document's* PR-5 (the `prefer_spark`
flip) — a ruling from this design's own review history, not yet transcribed as a
numbered decision inside the committed R5 section itself (R5 carries no numbered
decisions at all today; do not cite "decision 8" against R5 until one is added) -
both must land before the flip proceeds, the same way #3816/#3831 (row 3) and
#2818/#3848 (row 9) do. Do not read "not tracked by #2233" as "not gating" - it gates
on the same criterion (§2) through a different, newer document, not through #2233's
checklist.

**Ladder insertion (ruling 14(c), 2026-09-08, revised 2026-09-11):** the #2012/#3840
same-type-serialization fix lands between this track's PR-1 and PR-2, no longer in the
post-flip package - as **three** PRs sharing one shared primitive (PR-A/#4190), not the two
originally planned: PR-B1 (Registry, merged), PR-B2 (File, merged), **PR-B3 (Service, merged
2026-09-12, PR #4302) - the series is now fully complete**, closing #2012/#3840/#4181. See the
corrected #2012 row in §5's register for the full per-mechanism status, including the
correction that Service never actually had the hazard this row originally described, and the
re-verification (ruling 16, 2026-09-12) that unblocked this track's own PR-2.

**Ladder status, updated 2026-09-18** (this track's OWN PR-0 through PR-6, not to be
confused with the 7.7b-split's own "PR-2 (thin cutover)" a few sections up in this same
doc - two different PRs share the name; see "Why it doesn't gate on #2233" above):
**PR-0 (done, #4130)
→ PR-1 (done, #4224, 2026-09-10) → [#2012/#3840 series, done, see above] → PR-2 (done,
#4318, 2026-09-13) → PR-3 (telemetry, **done, #4329, merged 2026-09-14T08:06:02Z,
`5d470322b`**; arm_pending/arm_failed re-statable gauges + the io-ceiling monitor-only
counter, PR-3a/#3415 split out separately) → PR-4 (**done, this PR** - audit + R5.5's
remaining shutdown decoupling + legacy-note. #4322 fixed: `guardian_spark_runtime.cpp`'s
`begin_stop()` comment no longer describes `apply_rules()` as capable of parking in a
bounded backend wait - PR-2 removed the only production caller of that (see the R5.5
stamp below). R5.5's own "as implemented" stamp added to
`docs/spark-stage2-guardian-consumer-design.md` (its ack-ledger-retirement half already
shipped in PR-2 Unit 6 - the `retire()` call at `guardian_engine.cpp:650` carries that
label). **Ruled, not left open**: `stop()`
(`guardian_engine.cpp:613`) taking `mtx_` unconditionally before calling `begin_stop()`
is correct as-is - `persist_lifecycle_journal_locked`, `ack_ledger_->retire()`, and
`stop_all_guards_locked()` all need it, and PR-2 already removed the one thing that
could make that hold backend-arm-bounded (a hung device/OS call); what remains under
the lock is synchronous, rule-count-scaled local work - `apply_rules()`'s full_sync KV
sweep + `detach_all()` + per-rule reconcile loop + unbounded journal persist on scope
exit, and unconditionally the boot-time `start_local()`/`wire_spark_engine()` calls -
plus `journal_maintenance_tick()`'s own periodic drain+persist when `prefer_spark_` is
true (it no-ops immediately under the lock otherwise, which is production's default
today) - none of which this design was ever meant to make instant.
Also corrected R5.4's own "as implemented" stamp: "no data is ever lost" was an
overclaim - `stage_pending_locked()` drops the oldest staged record past
`kMaxPendingJournalRecords` under sustained persist failure, counted via
`journal_stage_dropped_` - see the design doc for the fix. **#3811** (already filed
during the #2233 item 3 governance sweep, re-surfaced while investigating this PR -
`rollback_spark_wiring_locked()` resets `spark_runtime_` without waiting for
`active_backend_op_workers()==0`) - this doc's own §3 row 3 already rules it
non-flip-gating; cited in the R5.5 stamp, not re-investigated or fixed here) →
PR-5 (fault/K-bound logic, a 5-PR sub-ladder 5a-5e, **ALL FIVE MERGED** - 5a
#4359 (up-101/cs-103), 5b #4381
(up-3/up-4/ch-1/up-5, see status paragraph below), 5c #4417 (up-2, see status
paragraph below), 5d #4485 (late-result adoption by current desired state,
R5.3's arm-recovery telemetry mechanism - see
`docs/spark-stage2-guardian-consumer-design.md`'s "as implemented (rung 9c
PR-5d)" stamp), 5e **#4529, merged 2026-09-18T13:18:55Z (`869ea6a29d14`)**
(K=3 wedge waiver / decision 1 closeout, plus #4279's
disposition below - see that doc's "as implemented (rung 9c PR-5e)" stamp) -
see acceptance criteria below) → **PR-6 item 1 (Service positive-establishment
signal) - IMPLEMENTED, not yet merged** (branch
`feat/spark-9c-pr6-item1-establishment-signal`, off `origin/dev @ 7ff742f19`):
`SparkIncarnation`/`SparkCoverage`/`SubscriptionEstablishment` (`spark.hpp`),
the additive `ISparkMechanism::watch_incarnation()`/`set_established_sink()`
seam, both Service mechanisms (Linux sd-bus, Windows SCM) wired to report
tri-state coverage at every real transition, and
`SparkEngine::subscription_establishment(id)` as the pull query. Full E1-E15
+ M1-M6 test matrix, E2/E4/E13/E14/E15/M1/M6 genuinely mutation-verified
(break the fix, confirm red, restore, confirm green) - **M6 twice**: an
initial baseline-snapshot design was itself caught as still partly vacuous
before it ever ran on real hardware (two independent race/window hazards a
subsequent review turned up), replaced with a bounded-count oracle, and
mutation-verified clean on DGRHP with zero flake across 5 baseline / 3
mutated / 3 restored repeated runs. Full DGRHP Windows/MSVC verification is
DONE, not a remaining step: `[spark]` is 718/718 test cases (15774
assertions) clean at HEAD, run repeatedly across this branch's fix history.
A two-phase adversarial review (Kimi K3 + Codex Sol, both dynamic/compiled)
found and this branch fixed 6 issues before this status was written - 2
HIGH (the Windows M4a/M4b test bugs above, and M6's own vacuous oracle, both
described above), 1 MEDIUM (a Windows-only fired-one-shot race in the
coalesce/adoption branch, `w->fired ? SparkCoverage::None : w->coverage` at
the Add-drain adoption site - NOT independently unit-tested, no test seam
currently forces the specific cross-watch APC timing; flagged as a residual
test gap), 3 LOW (a docs R4 caveat, a changelog naming convention, a
diagnostic-message reuse detail) - all fixed, see this branch's commit
history from `afbdaf0bd` onward for the exact diffs and reasoning. A
further governance run on this branch (`7ff742f19..d20aa5020`) found and
fixed two more coupled defects in commit `e5eb7dc8a` - PR-6 item 1's own
UP-1(A), an exception-safety `.at()`-throw window in the new per-key
incarnation/epoch bookkeeping, and PR-6 item 1's own UP-1(B), a
pre-existing zombie-mechanism admission gate that let a dead
Service-mechanism worker thread keep silently accepting `arm()` calls and
returning success forever - both adjudicated LOW today (capped by
`prefer_spark_` staying false in production, the sole gate on every path
to this code) but MEDIUM (A) / HIGH (B) post-flip if ever left unfixed at
that point; full adjudication in
`governance.d/4340-spark-9c-pr6-item1-establishment-signal.MwM5ht.jsonl`.
**Item
2 (a re-run of the #3990 diagnostic's methodology against the full landed
ladder, using this channel's real per-key timestamp) is a SEPARATE,
not-yet-started piece of work, depends on item 1 landing first** - do not
read "PR-6 item 1 implemented" as "PR-6 done".** PR-2 settled
§R5.3's previously-open "resolved" definition: resolved = backend `arm()` success AND
Guardian's own generation-commit, not OS-watch establishment -
`docs/spark-stage2-guardian-consumer-design.md` §R5.2-R5.4 updated to describe the
mechanism as implemented, not just designed. R5.5 now carries its own "as implemented"
stamp (PR-4) alongside R5.2-R5.4's.
**Sequencing note, not yet ruled**: since #3990's diagnostic and the CH-5-UAT
evidence campaign (§4) both measure a latency this ladder is still actively changing,
whether either should start before PR-3 through PR-6 land, or wait for the full ladder,
is an open scheduling question - not answered by this doc today.

**Rung 9c PR-5 acceptance criteria (governance pass-3, independent fan-out on PR-1, 2026-09-09).**
Three unhappy-path findings on PR-1 derive HIGH on their own facts and are capped to LOW only by
exposure E5+E6: `prefer_spark_` is a `const bool` set solely by `GuardianEngine`'s defaulted
constructor at the one production site (`agent.cpp`), with no CLI/env/config/build route, and
every cited line sits downstream of `try_spark = prefer_spark_ && Available`
(`guardian_engine.cpp`). **That cap lapses at the flip PR or any `prefer_spark` knob PR**, where
each re-derives HIGH (E0 via the 25 s `full_sync` timer). PR-5 must close every one before the
flip, with a red-first test each:
- **up-2, wedged-key re-apply cost** (`GuardianSparkRuntime::attach_rule`, the claim path and
  `wait_for_claim`): a re-push onto a wedged key queues behind the abandoned head and waits the
  full `backend_op_deadline` under engine `mtx_` on every re-apply; the base code fail-fasted via
  the executor's `AlreadyRunning`. Criterion: a wedged key refuses a new claim immediately.
- **up-2 status (rung 9c PR-5c, #4221): CLOSED.** Closed via three pieces: a dispatching-window
  race fix (`reclassify_dispatching_race_locked()`, both reachable call sites) preventing a
  claim's terminal classification from being silently overwritten by a stale value when a
  caller-side timeout raced `dispatch_arm_off_lock()`'s own admission decision; `ReceiptStatus::
  Expired` split into `CongestionExpired` (timed out merely queued - ordinary backpressure) and
  `Wedged` (timed out while dispatching/dispatched); and the actual closure, `AttachCoreState::
  Reobserved` - an identical (rule_id, spec) retry onto an already-`Wedged` key now re-observes
  the existing head's receipt directly (no new claim, no index mutation, deliberately, to avoid
  a ghost index-refcount leak), while a genuinely different claimant onto the same wedged key is
  refused IMMEDIATELY (`kSparkKeyWedged`) instead of queuing behind the doomed claim and waiting
  out `backend_op_deadline`. This PR's own full 8-gate `/governance` run found and closed one
  BLOCKING residual, independently confirmed via adjudication: **UP-1** - `attach_core()` tore
  down a retargeted rule's own prior working arm unconditionally before checking whether the new
  target key was wedged-by-someone-else, so a retarget refused onto a wedged key left the
  retargeting rule with zero live arms and no automatic recovery. Round 1 (`7c13ab269`) hoisted
  the different-rule_id refusal check to run before `detach_rule_locked()`, but was insufficient
  alone - the production caller, `GuardianEngine::reconcile_rule_locked()`, ran an unconditional
  defensive cleanup on ANY `attach_rule` failure and tore the just-preserved arm back down one
  call downstream; round 2 (`41a67dbc1`) closed it by threading a `prior_state_preserved` bit
  through the failure result so the caller only cleans up when there is genuinely something to
  clean up. A third Gate 8 re-review round (8 agents) on round 2's fix found no further blocking
  residuals. Two small non-blocking follow-ups were identified and deliberately NOT fixed here,
  tracked as #4416: the blocking (non-`NonWaiting`) `attach_rule` overload (what the `#3990`
  §5 entry below calls "the WAITING attach model") still discards the
  preservation signal, currently harmless since it has zero production callers today; and two
  pre-existing raw-API-level tests could usefully assert `prior_state_preserved`'s value directly
  for extra regression-locking. Separately, #4415 tracks the pre-existing (not introduced by this
  PR) full-ruleset teardown-storm architecture this governance run's unhappy-path review
  surfaced, confirmed a modest net improvement here rather than a regression.
- **up-3, direct compensating-disarm fallback** (`on_arm_complete`'s `run_compensating_disarm`):
  on a non-timeout executor refusal the disarm runs direct on the worker, holding no quota;
  wedged direct calls accumulate alive workers to the per-instance ceiling and the instance
  refuses everything until restart. Criterion: the fallback is bounded (deadline) and counted,
  and a ceiling hit is surfaced (PR-3 gauge).
- **up-4, double allocation fault leaving an outcome-bearing Dispatched head**
  (`on_arm_complete` step (3) and its catch): PR-1 pops a terminal head in the catch
  (governance pass-3 sg-3/ar-4/cs-5 fold); criterion: a deadline sweep also clears any head a
  double fault still leaves, so no key wedges until restart.
- **ch-1, step-(3) publish allocation seam**: PR-1 added fault point 3 (`set_drain_fault_point_for_test(3)`,
  post-verdict and pre-pop), which sits UPSTREAM of the fill-in allocation ch-1 named; that seam is still
  absent. Criterion: PR-5 adds the fill-in-allocation seam and exercises the step-(3)
  publish-allocation fault through it as a named red-first test (the pass-3 chaos-injector design
  called this scenario "CH-3"; that label lives in no committed artefact, so the criterion names the
  fault, not the label).
- **up-5, retained-disarm-no-redrive under sequential teardown** (`GuardianSparkRuntime::detach_all`,
  `submit_disarm_off_lock`): `detach_all()` submits each rule's disarm sequentially and bounded; when
  the class quota is still held by workers draining from earlier calls in the same sweep, a later
  disarm is admission-refused and RETAINED (`disarm_retained_`, no redrive timer in PR-1) rather than
  dropped - by design, but with no time-based redrive. Chaos-injector's ch-202 (governance pass-5/6
  ledger) reproduced this live under load (`disarms.load()` 57/200 and 120/200 of a 200-key
  `detach_all()`, both far below the 5 s deadline-timeout count). Post-flip consequence: a retained
  disarm leaves the real backend subscription armed indefinitely - `armed_key_count()` and
  `rule_count()` both correctly read 0 (the confirmed state IS torn down), so nothing operator-visible
  distinguishes "torn down and disarmed" from "torn down and the disarm is stuck" until the next
  same-key attach or `begin_stop()` (which drops it, counted) redrives it. **Missing telemetry
  (PR-3 gap)**: no gauge exposes `disarm_retained()`'s current (non-monotonic) count on the fleet
  heartbeat, so an operator has no signal that a torn-down key still has a live watch. Criterion:
  PR-5 either adds a bounded redrive (a periodic sweep or a convergence-lane trigger) or PR-3 exposes
  `disarm_retained()` as a fleet-visible gauge so the gap is at least observable; either closes before
  the flip. Test-side note: `tests/unit/test_guardian_spark_runtime.cpp`'s 200-key `detach_all` test
  (governance qe-303) now asserts `disarms + disarm_retained() == 200` rather than the false invariant
  `disarms == 200` this row's chaos reproduction disproved.
- **up-3/up-4/ch-1/up-5 status (rung 9c PR-5b, #4221)**: up-3 fixed via a runtime-owned
  compensating-disarm reservation reserved per claim BEFORE its arm dispatches (not routed through
  `GuardianIoExecutor`'s own admission - it has no compensation-priority `IoClass` and rejects
  everything once `Stopped`, which would have broken the Stopped-still-triggers-fallback
  requirement R5.5 depends on); sized 1:1 with the executor's own per-class quotas. up-4 fixed for
  the CONFIRMED real shape (a `Queued`, withdrawn/abandoned head with no outcome, left behind by
  the same double-fault recovery paths, reachable via a genuine allocation failure) via a new
  `expire_overdue_claims()` terminal-recovery pass; the kickoff's literal Dispatched-terminal-head
  variant was investigated and NOT implemented in this PR - a first attempt (reaping any
  `Dispatched`+outcome-bearing head) regressed a real, already-tested scenario (a caller-timeout-
  abandoned claim whose async `arm()` is still genuinely in flight; `compensation_finished`
  defaults true and does not by itself distinguish the two cases). **Correction (Fable re-review,
  2026-09-14): a safe signal is NOT structurally impossible** - a dedicated `completion_finished`
  fact (distinct from `compensation_finished`), written only by the true completion callback and
  reset at the `Queued`->`Dispatching` re-drive chokepoint, would distinguish them; it simply
  wasn't built in this PR. Separately, the literal double-fault residue this variant targets was
  independently confirmed unreachable on the current call graph (every path that could produce it
  routes through a `noexcept`-only inner catch before the pop) by three independent passes (Astra,
  Fable, and this implementation attempt) - so the risk of leaving it unbuilt is assessed as near
  nil in practice. Tracked as **#4366** (P2, defense-in-depth), not flip-gating.
  ch-1's fill-in-allocation seam added (both the ordinary and firewall-loop occurrences). up-5's
  redrive is now wired onto the convergence lane's priority loop (elapsed-time-gated, its own
  firewalled sweep); **this row's own "Missing telemetry" wording above is now WRONG** -
  `disarm_retained()` is no longer "current (non-monotonic)" but a real lifecycle count
  (an RAII `RetainedGuard` per claim, released on the claim's own successful completion or any other
  terminal removal - see the governance-hardening note below for the RAII rename) - the fleet-gauge
  alternative this row offered was itself retracted on issue #4221's own comment thread as
  insufficient (a monotonic counter cannot answer "is anything stuck right now"), so the bounded
  redrive is the only closure this criterion accepts. `redrive_retained_disarms()` walks `claims_`
  directly (never `keys_`), reaching a retained disarm even behind a torn-down key - closes the
  #4221 follow-up comment (`ar-402`) that had worried a convergence-lane trigger might enumerate the
  wrong registry and miss that case.
- **Governance hardening round (full 8-gate `/governance` pass, this run, 2026-09-14)**: this PR's
  own pre-push governance found ONE genuine BLOCKING item - cpp-safety's Gate 3 adjudication declined
  the RAII-impossibility exception for both up-3's compensating-disarm reservation pool and up-5's
  retained-disarm lifecycle count, which up to that point were plain bool-guarded manual
  acquire/release pairs (`compensation_reserved`/`retained_counted`). No live leak was found on any
  traced path, including every throw path, but the manual pairing was ruled a policy-floor contract
  violation regardless (CLAUDE.md standing rule 2's non-RAII-cleanup-in-new-C++ floor) since a
  stack-scoped guard was wrongly assumed impossible - the real fix is a move-only guard owned by the
  already-long-lived `KeyClaim` object, not a stack frame. Fixed by wrapping both in dedicated RAII
  types (`CompensationPermit`, `RetainedGuard`, `guardian_spark_runtime.hpp`) backed by
  `std::atomic` counters so the destructor is safe to run off-lock - a structural backstop against a
  future forgotten release call, not just a currently-correct one. Bundled into the same fix: the
  independently-confirmed (security-guardian, cpp-expert, cpp-safety) `noexcept`-on-a-throwing-body
  defect in `synthesize_fallback_outcome_locked` (dropped `noexcept`, added fault-injection point 9
  matching its own now-genuinely-functional catch path), and `fail_all_claims_locked` now also
  releases a compensation permit defensively (consistency-auditor finding, provably a no-op today,
  kept for future-caller safety). Two new isolated `[spark]` test cases pin the RAII types' own
  engage/move/release contract directly; a third (Gate 8 re-review follow-up, quality-engineer and
  cpp-safety independently converging on the same gap) drives fault point 9 through a genuine
  double-fault scenario and was red-first-validated - the noexcept bug was temporarily
  reintroduced, confirmed the new test crashes with `terminate called after throwing std::bad_alloc`,
  then reverted. Full agent suite (3034/3035 cases, 1 platform-skipped, 126244 assertions) and
  targeted `[spark]` suite (588/588, 14012 assertions) both green after all three fix commits;
  Gate 8 re-review (11 agents across the re-run Gate 2/3/4/6 set) found zero new BLOCKING findings
  and confirmed the RAII-floor finding CLOSED (cpp-safety's own authoritative ruling).
- **NEW (added 2026-09-13, sre finding on the #2012/#3840 doc-sweep)**: #4279's lane-cap-overshoot
  observation (`SparkDetachedLane`'s shared admission primitive, `max_active=9 > cap=8` on a real
  storm-load test, 1-in-~10 hardware runs, root cause undetermined) has no PR-5 acceptance
  criterion binding its resolution to the point where it would actually matter - the K-bound
  logic PR-5 implements is exactly what this residual could interact with under sustained
  same-type load. Criterion: PR-5 either resolves #4279 directly or explicitly re-assesses it
  against the landed K-bound logic and records the outcome here, rather than leaving it to drift
  as an unrelated open issue.
- **NEW (added 2026-09-14, discovered during rung 9c PR-5a's own cs-103 tombstone-reachability
  investigation)**: #4354, `publish_arm_verdicts_locked`'s ordinary (non-firewall) pop loop
  (`guardian_spark_runtime.cpp:580-601`) pops every claim in `finished` on outcome presence and
  fifo-front identity alone - it never checks whether that claim's index release actually
  succeeded. The one release attempt for a withdrawn sibling happens earlier, exactly once, in
  `on_arm_complete`'s own "claims that were withdrawn/abandoned while their siblings adopted"
  loop (`:911-913`); nothing retries it. A failure there (reproduced via a `[.exploratory]` test
  in `tests/unit/test_guardian_spark_runtime.cpp`, PR-5a) leaves a permanent ghost
  `SparkKeyRuleIndex` entry with no `claims_[key]` residue at all - unlike up-2/up-101's
  tombstones, no existing sweep can ever find it. Consequence, confirmed empirically: the ghost
  permanently blocks `keys_[key]`'s own erasure (even after the last real rule on that key is
  properly detached, `detach_rule_locked`'s `index_->remove_rule` keeps reporting "siblings
  remain"), leaking the real backend subscription; a LATER, unrelated rule attaching to the same
  key then silently inherits that stale, never-reverified subscription via the "reuse existing
  shared watcher" path, with no new `arm()` call. Same production-reachability status as every
  other criterion in this list - `release_claim_index_locked`'s real `erase_rule` call is
  internally noexcept/allocation-free, so this is reachable only via the
  `set_index_remove_fault_for_test` seam today, not live - but structurally real, and worse in
  consequence (a permanent leak plus silent stale-subscription reuse, not just delayed cleanup)
  than anything else named here. Criterion: give the ordinary pop loop the same release-success
  check the firewall branch already has (the cs-2 fix, `:602-620`), or an equivalent guarantee
  that a release-failed sibling is retained rather than silently popped, before the flip.
- **up-101 and cs-103 status (rung 9c PR-5a, #4221) - not previously listed as their
  own bullets in this section, added here for completeness.** up-101 (a same-rule
  re-attach behind a surviving tombstone leaking a watcher, `guardian_spark_
  runtime.cpp`/`spark_key_rule_index.hpp`): closed by making index release
  incarnation-aware (`index_->erase_rule(claim.rule_id, claim.generation)` -
  a stale, retried release now checks the generation before it can ever clobber a
  newer owner's mapping). cs-103 (the drain's refill and detach-path-sweep
  branches unexercised): closed with direct branch coverage for both (the
  refill-inside-catch admission-refusal arm, and a throwing last detach inside a
  Lost notification). Both closed by PR #4359, full governance pass, zero open
  BLOCKING findings on this PR at merge.
- **K=3 wedge waiver / decision 1 status (rung 9c PR-5e, #4221): implemented,
  pending merge as of this writing.** Full mechanism, K-eligibility settling
  requirement, and explicit scope narrowing documented in
  `docs/spark-stage2-guardian-consumer-design.md`'s "R5.3 as implemented (rung
  9c PR-5e)" stamp - not restated here. This PR is the LAST in the 5a-5e
  sub-ladder and carries `Closes #4221`; mark CLOSED here only once it merges.
- **#4279 disposition (rung 9c PR-5e, per this row's own criterion above):
  ASSESSED against the landed K-bound logic, not resolved, remains open.** The
  lane-cap-overshoot observation (`SparkDetachedLane`'s shared admission
  primitive, `max_active=9 > cap=8`, 1-in-~10 real-hardware storm-load runs,
  root cause undetermined) and K-bound are DIFFERENT mechanisms with a narrow,
  analyzed interaction, not a shared cause: K-bound counts established
  IDENTICAL applications (a policy-generation-retry concept), never lane
  occupancy, elapsed time, or retry observations - it cannot explain or fix a
  concurrency-admission overshoot in a completely separate primitive. The
  diagnostic test samples `probe_workers_active` (a diagnostic count reading
  `SparkDetachedLane::active_workers()`) at a point where admission increments
  the counter before a rejected reservation's rollback - a source-supported
  POSSIBLE explanation for the sampled overshoot, not a confirmed root cause;
  distinguishing a sampling artifact from a genuine concurrency-admission defect
  needs the real Windows/MSVC storm scenario repeated on DGRHP hardware, not
  BigColin. K-bound's only real interaction with #4279's scenario: sustained
  same-type load may delay arming or produce non-Wedged congestion/admission
  failures, and those stay non-K-waivable exactly as R5.3's "K is not a
  generation-wide liveness bound" already requires - K-bound does not widen
  #4279's exposure in any way. No code fix landed in this PR for #4279; it
  stays open, P2, tracked independently.
- **NEW precondition for the F14 flip (added 2026-09-18, PR #4529 review
  finding): K-eligibility's drain-time linearization must become a named flip
  criterion, not stay implicit in a design-doc note.** `can_advance()` reads
  only the K-eligibility membership `drain_locked()` computed at its LAST
  tick under `registry_mu_` - it never re-queries the runtime, so a worker
  completion landing in the gap between that drain read and
  `persist_generation_locked()` isn't observed until the NEXT tick. Confirmed
  safe today, independently re-verified against the true pre-PR-5e
  merge-base (`9cf3907b3`): `docs/spark-stage2-guardian-consumer-design.md`'s
  own PRE-EXISTING "Completion ownership survives K" sentence already
  tolerates a completion landing any number of ticks after acknowledgment -
  this gap only lets that already-tolerated case happen one tick EARLIER,
  never a new unsafe state (full reasoning: R5.3's own "K-eligibility
  linearizes at the drain-time read" paragraph). Non-blocking today
  (`prefer_spark_=false`). Criterion: before the flip, either re-confirm this
  reasoning still holds against whatever the runtime's shape is at flip time,
  or promote it from an implicit consequence of two design-doc sentences
  agreeing with each other into an explicit, load-bearing invariant a
  reviewer checks directly.
- **NEW precondition for the F14 flip (added 2026-09-18, PR #4529 review
  finding): the `reapply_count` cross-rule funding consequence must become a
  named flip criterion, not stay implicit in a design-doc/ledger note.** A
  rule's own wedge can be K-waived on its very first observation if an
  unrelated sibling rule's ordinary (non-Wedged, now-cleared) failure already
  funded the shared per-application-sequence counter - a direct, reviewed
  consequence of decision 1's shared-counter shape, not an exotic race (full
  mechanism: `docs/spark-stage2-guardian-consumer-design.md`'s R5.3 "as
  implemented" stamp). Does NOT violate the single safety invariant K-waiver
  must never break - a waived receipt is, at the moment of waiver, still
  genuinely Wedged and still its key's FIFO-front claim - it only affects how
  many of the OPERATOR's own retries a freshly-wedged rule is guaranteed
  before waiver becomes possible. Non-blocking today (`prefer_spark_=false`);
  recorded without a self-granted severity downgrade per the governance
  ledger's own independence rule
  (`governance.d/4221-spark-9c-pr5e-kbound-closeout.JdLKyl.jsonl`). Criterion:
  before the flip, an explicit decision - accept this tradeoff as-shipped, or
  add the per-rule wedge-observation floor decision 1 deliberately rejected
  as too invasive for this PR - rather than letting it ride on dormancy
  alone.

## 4. #2340 scenario contract

Canonical home for this contract as of this PR - a local (uncommitted) delivery-plan draft
(Sol draft + Fable corrections, 2026-08-31/09-01) is now superseded by this section and can be
discarded once this doc lands.

**Veto semantics (ruled 2026-09-01; recorded Dave, 2026-09-02, #2340 comment)**: CH-11 vetoes **alert-enablement only, not the flip**.
The flip gates on CH-2 + CH-5-PROM + CH-5-UAT only. CH-11, its 500-agent rig requirement, and
#2336 (per-agent attribution axis) move to the post-flip P11 lane (§7). This resolves the
ambiguity the delivery-plan draft flagged: Sol's original reading ("the flip may proceed only
after the veto scenarios pass," all three) would have transitively gated the flip on #2336 -
weeks of prerequisite work. The issue's own veto sentence is alert-scoped ("if any fails, the
alert group stays commented out and the counters stay monitor-only"), the rules file's own
REASON 2 already plans for loss alerts staying disabled post-flip pending #2336, and
`docs/guardian-c0-thread-reloc-design.md` item 7 singles out CH-5-UAT alone as "the flip's
genuine go/no-go." Against: the issue's own title/body do say "cutover gates" (plural,
unscoped) - genuine internal ambiguity in the source issue, not a clean misreading. This
doc's ruling stands regardless.

**CH-2 verdict (Dave, 2026-09-02, #2340 comment): fires-then-resolves.** The issue's literal wording
("assert zero alerts") reads as inverted against the rule's own design intent.
`YuzuGuardianJournalIntegrityGap`'s doc comment states: "No `for:` clause on purpose - the 90s
staleness window means an agent that reports a loss then dies is visible for less than one
`for:` period" - i.e. the rule is deliberately built to **fire** in exactly CH-2's scenario.
The strongest CH-2 test therefore asserts **both**: (a) the rule fires once while the loss
series is present (proving the no-`for:` design works - a future accidental `for:` addition
should turn this red), and (b) it resolves once the reporting agent goes stale, **while the
underlying loss stays unhealed**. That gap - healthy-looking alert state hiding an unhealed
loss - is the actual characterized defect CH-2 exists to demonstrate, not literal "zero
alerts, ever." This unblocked PR-4 (now merged, see §1/§4 below).

**CH-5-PROM vs CH-5-UAT - same scenario ID, two different documents, two different meanings.
Do not conflate them:**
- **CH-5-PROM** (this doc + PR-4): promtool synthetic time-series proving the currently-shipped
  metric-family set is absent for 7 days, and `YuzuGuardianJournalTelemetryDark` fires within 15
  minutes while nothing else does. **DONE - PR-4 merged as #3858** (2026-09-02T13:00:49Z):
  `tests/prometheus/yuzu-guardian-journal-extracted.test.yml` implements 6 CH-5-PROM cases. The
  actual 7-day-metric-family-absent scenario this bullet describes is case 2 ("reporting dark
  sustained for 7 days stays firing" - `_reporting` modeled present-at-zero for 168h alongside a
  healthy fleet, the rest of the metric-family set absent by omission). Cases 1 ("reporting dark with a
  healthy fleet") and 3 ("reporting dark with zero healthy agents stays quiet") are a related but
  distinct property - the exact `_reporting`-exclusion scoping this doc flagged, exercising the
  two halves of the `yuzu_fleet_guardian_journal_reporting == 0 and on()
  yuzu_fleet_agents_healthy > 0` guard directly. Together the three confirm the "metric-family
  set absent" case does not mis-fire on `_reporting`'s own steady-state 0 reading. Per-case
  discrimination (this doc's original PR-4 scoping note: "mutation-red evidence required, not
  whole-suite") was verified manually at authorship time per the test file's own header comment
  (`:45-58`), not automated in CI - a scope decision, not a gap. CH-2 is also DONE in the same
  PR: cases CH-2a/CH-2b implement the ruled fires-then-resolves verdict (§4 above), plus a CH-2c
  refinement (a never-healing loss fires only within its first 15 minutes, found via adversarial
  review) not anticipated when this doc was first written.
- **CH-5-UAT** (design-doc item 7, `docs/guardian-c0-thread-reloc-design.md`): a live UAT-rig
  load/timing gate holding the journal at its hard ceiling (2000 batches / 64 MiB - resolved
  2026-08-18, not reopened here), measuring live-event latency under KV contention, including a
  forced-blocking sanity stage (`headroom_blocked_seconds` has never fired outside unit tests -
  a 0 reading is ambiguous without this stage). **OPEN: no latency pass/fail threshold is defined
  anywhere** - no percentile, sample-size, or platform-matrix target exists in the design doc or
  any other committed source, despite this being "the flip's genuine go/no-go" per that doc's
  own item 7. Tracked as **#3850** (filed while writing this doc, still OPEN) - the exploratory
  pass below deliberately did not propose a threshold from a 12-30 sample run; this update does
  not resolve #3850.

  **Exploratory pass run (2026-09-04/05, DGRHP - Windows, not BigColin; see §8 for why),
  Sol (`gpt-5.6-sol`) + Fable reviewed, all findings independently re-verified against code
  before being recorded here.** Found the "hold at the hard ceiling" premise above is not
  mechanically achievable under sustained load: `prune_locked_` resets the journal fully to the
  soft cap (1000 batches) every single 120s pass regardless of delivery/sent-label status, so
  occupancy above 1000 can only exist transiently within a single 120s window - the hard ceiling
  (2000/64MiB) is a backstop for a "chronically-failing prune" per its own doc comment, not a
  load-reachable steady state. Reaching it needs a burst (>1000 net-new batches within one
  120s window) or a prune-fail injection; neither was attempted this pass. **The design doc's
  own item 7 wording ("holding the journal at its hard ceiling") needs the same correction** -
  flagged here, not yet fixed in that doc. The achievable organic/moderate-load regime found on
  this rig was ~550-750 batches (~24-27 batches/120s churn ceiling - more parallelism made
  things worse past ~24 lanes, likely a server-side per-client limit).

  A 30-sample stratified latency probe taken in that regime (churn-paused window, fresh agent
  restart, ms-precision via `event_id`'s embedded wall-clock - NOT `updated_at`, which truncates
  to whole seconds before reaching Postgres) measured **6.6-7.0s (mean 6837ms)**. Label this
  **detection-to-server-ingest latency, not stimulus-to-detection**: tracing the registry
  watcher path confirms `event_id`'s embedded timestamp is minted in
  `GuardianSparkRuntime::build_entries()` at evaluation-completion time (post OS-notification
  callback, pre-outbox-enqueue, on the consumer thread per ADR-0021's queued tier) - not the raw
  instant the underlying value changed. The figure most likely reflects the downstream
  outbox/transport/Postgres-write path rather than registry-notification lag, but that was never
  isolated by direct measurement. No pass/fail threshold is proposed from these samples; this
  feeds #3850, it does not resolve it.

  **Two real production defects surfaced, neither flip-blocking on its own but both worth
  folding into flip-readiness review**: (1) `GuardianOutbox` (4096-entry capacity) can stall
  completely when its drain worker's send target is dead - confirmed via a dedicated stall test
  (`pending_` climbed to 4096 and pinned there, `backpressure_drops()` climbed into the tens of
  thousands, and the backlog drained instantly the moment a live stream reopened - a
  head-of-line block, not a capacity fill from cumulative churn, which was separately ruled out).
  Commented on the existing **#2993** (no telemetry consumer for this counter) with this
  real-world reproduction. (2) The stall's root cause was initially attributed to the Heartbeat
  RPC having no client-side deadline (filed **#3989**), but a follow-up isolated repro
  **retracted that causal claim**: a clean server stop/restart detects the dead session and
  recovers within one heartbeat tick regardless of the missing deadline (still worth fixing as
  defensive hygiene, matching `Register`/`ReportInventory`'s convention - correction comment
  posted on #3989). **#2049** (`TryCancel()` not reliably unblocking a transport-stalled
  Subscribe read) is the likelier primary mechanism for the actual stall instead - now two
  independent occurrences on that issue, commented there. Separately, a single global
  `policy_generation` counter means ANY rule mutation anywhere triggers a fleet-wide `full_sync`
  teardown+rearm on every agent's next heartbeat - not only a persistently-failing rule as
  **#2278** originally scoped. Split out as its own sibling issue, **#3990**, since the two are
  different triggers (one-shot burst per mutation vs. a standing retry loop) sharing the same
  root counter - a follow-up on #2278 records the distinction and points there.

Both gate the flip independently; neither substitutes for the other.

**PR sequence for this track** (from the delivery plan): PR-1 (this doc, scenario contract) →
**PR-4 (promtool CH-2 + CH-5-PROM) - DONE, merged as #3858** → the CH-5-UAT driver (Rig A, §8,
still open, blocked on #3850's missing latency threshold) → cutover evidence record (compact
Markdown, hashed/artifact-ID raw data, not raw logs inline).

## 5. Risk-accept register

Every deferred defect below is recorded with a compensating control AND the fields Sol's
review required - detection signal, operator action, owner, milestone, revisit condition -
so "restart acceptable with no fleet" never stands alone as if it were a control by itself.
Where the source material (issues, the delivery plan) does not specify one of these fields,
that is stated explicitly rather than inferred or invented.

**#2469 + #2278 + #2279** (drain death / retry churn / poison head - one package)
- Detection signal: staleness gauges (already live) going stale/alerting.
- Operator action: not specified in source beyond "restart acceptable with no production
  fleet" - read as "operator restarts the affected agent"; not confirmed as a documented
  runbook step.
- Compensating control: staleness gauges live; restart is acceptable **only** because there is
  no production fleet today. **Explicit: the fix must land before ANY production fleet, not
  deferred indefinitely.**
- Owner: not assigned in source material - needs an owner before hardening package 1 starts.
- Milestone: hardening package 1, immediately post-P3.
- Revisit trigger: before alert-enablement AND before any production fleet.
- **Related finding, not itself risk-accepted here (2026-09-04/05, DGRHP exploratory pass,
  §4/§8)**: a single global `policy_generation` counter makes ANY rule mutation fleet-wide
  trigger the same full-teardown/rebuild storm #2278 describes, not only a persistently-failing
  rule - filed as sibling issue **#3990**. Widens how often this package's #2278 half is
  actually exercised in practice; worth re-weighing this row's milestone/priority once #3990 is
  triaged, not assumed unchanged. **A second, distinct compounding finding (2026-09-06,
  criterion 5's own governance review, see §2)**: because a no-`expected`-value hash rule
  captures the CURRENT target content as its baseline on every arm, and `#3990`'s `full_sync`
  re-arms every rule unconditionally on any unrelated mutation, a genuinely-still-drifted such
  rule can be silently reclassified as compliant with no remediation having happened - filed
  as **#4021**, also not risk-accepted here. See the new **#3990** entry immediately below for
  the ruling-13 diagnostic this package's own milestone re-weighing should be read alongside.

**#3990** (fleet-wide `full_sync` storm on any rule mutation - legacy-vs-spark blackout
diagnostic, ruling-13 on #3850)
- Detection signal: not specified in source; `yuzu_server_guardian_pushes_dispatched_total`
  rate and agent `full_sync=true` log frequency are the closest existing signals, neither
  purpose-built for this.
- Operator action: not specified in source; not established by this diagnostic either - no
  system-side effect was found for a mitigation to target.
- Compensating control: this diagnostic (`docs/spark-rebuild-baselines/
  3990-fullsync-blackout-run.md`), run 2026-09-06/07 on DGRHP, re-run 2026-09-07, clean re-run
  same day. **Corrected THREE times on review before landing here** - first a fabricated
  "pile-up effect" claim (retracted: every `full_sync` actually confirmed to run completed in
  8.3s or less, most under 100ms at the clean cohort; the real cause of the low first-attempt
  sample count was an agent `--log-file` flush-lag interacting with the driver's polling
  timeout), then an overclaimed "reached the pre-registered floor / within margin" framing on
  the first 2026-09-07 re-run (an external review found the driver computed `functional_valid`
  but never gated its sample count on it - confirmed by reading the code; formal outcome
  corrected to INCONCLUSIVE/INVALID BY COHORT DESIGN). **Current, accurate state: a genuine
  pre-registered PASS.** Both defects behind the INCONCLUSIVE outcome were fixed at the source
  (the `functional_valid` wiring, and 5 of 20 service-watch cohort targets swapped for services
  confirmed live and stable, replacing ones confirmed permanently or intermittently Stopped on
  the rig) and the diagnostic re-run clean. Every one of the 16 counted repeats (5+3 legacy,
  5+3 spark) independently satisfies `failed=0` AND functional-validity - the full
  pre-registered rule, not a partial check. Numeric result: Phase B legacy median 70.0ms vs
  spark 127.0ms (threshold 1070.0ms); Phase B2 legacy 86.0ms vs spark 140.0ms (threshold
  1086.0ms) - both within the predeclared non-inferiority margin. Full detail, all three
  corrections, and the raw per-repeat data for every round (`fullsync-blackout-results.jsonl`,
  the clean pass under `label="clean-v2"`) are in the run doc, not restated here. **This
  `clean-v2` PASS was measured on the WAITING attach model** (`origin/dev@65f2938156a19`,
  pre-rung-9c-PR-2) and stands unedited as its own record for that build.
- **R5.7 T2 re-measurement (2026-09-19, rung 9c PR-6 item 2), a SEPARATE, LATER pass under the
  CURRENT NonWaiting attach model** - `origin/dev@f0f07d4d8`-merged branch
  `feat/3990-r57-t2-remeasure`. `clean-v2`'s own Window-B measurand no longer brackets spark's
  arm completion under NonWaiting (T1 no longer waits for every arm), so this round adds an
  epoch-fenced runtime-commit measurand (C = T2_last - T0, `docs/spark-stage2-guardian-consumer-
  design.md` §R5.7) as the headline instead. **Phase B (baseline re-deploy trigger): PASS** -
  legacy C median 74.0ms vs spark 98.0ms (threshold 1074.0ms), 5/5 valid both backends, zero voids
  either side. **Phase B2 (bare rule-create trigger, #3990's own literal shape): FAIL-RELIABILITY** -
  legacy 3/3 valid (C median 66.0ms); spark reached only 2/3 valid across its full 10-attempt
  budget, and one of the remaining 8 attempts (repeat 3) recorded a genuine arm failure
  (`applied=61, failed=1`, one rule, `blackout-file-03`) that this round's own
  `/adversarial-review` (Kimi K3 + Codex Sol, both independently) found had been misclassified
  as an instrument-invalid void by a driver bug (a collection-stage void reason was checked
  before the T1-reported `failed>0` check) - fixed same-session, the committed row's
  classification corrected, and the phase's true verdict is FAIL-RELIABILITY, not the
  INCONCLUSIVE first reported. That arm failure is itself unroot-caused (the rig was
  unreachable by the time the misclassification was found, so the underlying `agent.log`
  error line for `blackout-file-03` could not be pulled) - an open product-level finding,
  filed as [#4607](https://github.com/Tr3kkR/Yuzu/issues/4607), not
  dismissed as instrumentation. Full detail, hypothesis resolution, and raw per-repeat data
  (same `fullsync-blackout-results.jsonl`, `label="t2-v1"`) are in the run doc's own "R5.7 T2
  re-run results" section, not restated here. **Do not read this entry's PASS as reopening or
  superseding the `clean-v2` entry above - they measure different builds under different
  attach models**, and #3990's own Phase B2 shape now has a genuine, unroot-caused reliability
  failure under the current model, not merely a floor miss - a re-run needs the underlying
  arm-failure finding investigated first, not just repeated.
- Owner: not assigned in source material.
- Milestone: not specified. Nothing found by this diagnostic changes this row's own
  #2278/#2469/#2279 package - the two are not shown to be related.
- Revisit trigger: before the PR-5 flip head re-run (CH-5-UAT's own driver, once its threshold
  work lands) - this diagnostic's pass is on one rig, one cohort, two trigger shapes, not fleet
  scale; before this diagnostic's "accepted-neutral" citation is relied upon for a flip decision.
- The pre-registered pass above is mixed evidence for #3990's §5 "accepted-neutral" citation:
  Phase B PASS argues for it, but Phase B2's corrected FAIL-RELIABILITY - a genuine,
  unroot-caused spark arm failure on #3990's own literal reproduction shape, not merely a floor
  miss - argues against treating this diagnostic as settled. Whether "accepted-neutral" still
  holds, and how to word the citation given both results, is Dave's call to make, not a
  conclusion reached by this entry.

**#2815 + #2818 + #2833 + #2839** (teardown UAF-class; #2797's legacy half and #2012/#2011
tracked separately below)
- Detection signal: not specified in source for a production occurrence - the compensating
  control here is chiefly *pre-flip verification* (below), not fleet-side detection. A
  production occurrence would most plausibly surface as an unexplained agent crash/restart
  with no dedicated telemetry pointing at these specifically today.
- Operator action: not specified in source.
- Compensating control: item 9's literal TSan rerun **plus** a per-issue deterministic
  fault-injection scenario matrix (PR-2c, real engineering, not "run TSan and see").
  **THE MATRIX HAS NOW RUN (PR-2c, #3848), AND ALL FOUR WERE CONFIRMED.** None was ruled
  out; the risk acceptance recorded above is superseded per-issue below. TSan turned out
  to be secondary for all four, not only #2818: every one was demonstrated by a
  deterministic seam, and none needed a race to be caught.
- **#2815 - CONFIRMED and FIXED in PR-2c.** The engine had FOUR call sites that resolve a
  raw mechanism pointer under `mu_`, release `mu_`, then call into the mechanism
  (`disarm`, `teardown_arm_race`, `unregister_consumer`, and the live arm path in
  `arm_impl` - the fourth was missed by the original analysis and found in review).
  `stop()` waited on none of them and neither did `~SparkEngine`, so the engine could be
  freed under a parked caller. Demonstrated, not argued: a plain debug build SIGSEGVs, and
  ASan names it `heap-use-after-free ... in SparkEngine::disarm` at the
  `mech_ops_mu_by_type_.at()` dereference. Fixed with a function-scoped lease armed as the
  last statement of the same `mu_` block that resolves the mechanism; `stop()` waits
  BOUNDED and proceeds on expiry (counting a new `teardown_join_timeouts_total`),
  `~SparkEngine` waits UNBOUNDED - the unbounded one is what actually closes the UAF. Note
  the shipped agent was never exposed: F3's `OrphanExitGuard` `hard_exit()`s before
  `~Agent` while any Guardian I/O worker is live. Any other embedder, and every test, was.
- **#2818 - CONFIRMED and FIXED in PR-2d** (`fix/2818-subscription-death-notification`,
  branched off `origin/dev` after PR-2c/#3985 and #3982 had both merged). A second
  consumer that dedups onto a key whose watch is still in flight was handed a success id;
  when that watch failed, `drop_key_locked` erased every subscription on the key and told
  nobody - the engine-level and Guardian-level PIN tests from PR-2c (`test_spark_
  mechanism.cpp`, `test_guardian_engine_spark_reconcile.cpp`) both flip from asserting the
  gap to asserting the fix in this PR.
  - **Fix shape: push, plus a poll backstop.** `SparkEvent` gained `SparkEventKind{Fired,
    Lost, Faulted, Recovered}` plus a per-recipient `subscription_id` and a `detail`
    string. `drop_key_locked`'s sole call site (`arm_impl`'s failed-watch teardown) now
    snapshots every live subscriber before erasing the key and delivers a `Lost` event
    through the SAME Inline/Queued dispatch channel `deliver()` already uses for an
    ordinary fire - no new registration surface, and a defensive `mech->unwatch(key)`
    (verified a safe no-op on all three real mechanisms for a never/partially-registered
    key) closes the orphan-reclamation gap the original issue also named.
    `report_fault`'s existing B1 health-toggle edge got the same treatment
    (`Faulted`/`Recovered`), closing the milder "armed but not watching, and the
    consumer is never told" gap in the same PR, per Dave's scope call (2026-09-06) to
    fold both into one PR rather than split a PR-2e.
  - On the Guardian side: `GuardianSparkRuntime::on_subscription_lost` detaches every
    rule on the dead key as `"errored"` (guardian_outbox.hpp's existing lifecycle
    vocabulary, not `"disarmed"` - the rule didn't withdraw, its enforcement broke),
    staleness-guarded against `PerKey::subscription` so a fresh re-arm racing the async
    notification wins. **No self-heal in this PR** (Dave's call: smaller, safer diff, no
    new blocking-retry policy). **Recovery path, corrected (governance Gate 4
    unhappy-path UP-4 - an earlier version of this row overclaimed "the next
    server-issued PushRules")**: a subscription death is local to the agent and never
    changes the server's policy generation, so `server.cpp`'s heartbeat reconcile gate
    (which re-pushes only when the server's generation has moved past what the agent
    last reported) is NOT triggered by this event on its own. An errored rule recovers
    only via an UNRELATED rule/policy edit bumping the server generation, or an agent
    restart (whose boot re-arm calls `reconcile_rule_locked` unconditionally) - absent
    either, it can sit un-enforced for the deployment's lifetime with no proactive
    operator signal beyond the "errored" audit entry itself. Tracked as a pre-PR-5
    hardening candidate (see the risk-accept register addendum below). **Scope residual
    (Gate 5 chaos-injector CH-7):** `Lost` is structurally reachable only from
    `drop_key_locked`'s sole call site - a brand-new key's FIRST watch failing. A
    previously-healthy, already-armed watch that later dies completely (not merely
    faults) has no `Lost` path today; it surfaces only via a sustained `Faulted` if the
    mechanism itself calls `report_fault`, or not at all. Deliberate scope per #2818's
    own text, not a defect - recorded here as an undocumented-until-now residual rather
    than left implicit.
    `on_subscription_faulted` mirrors this for the
    health-toggle edge without touching `keys_`/`rules_` (the key is still armed).
  - **Poll backstop, folded into the same PR** (Dave's call): a full Queued consumer
    channel drops entries under backpressure (`queued_dropped_total`), so a push-only fix
    leaves a residual, probabilistic version of the same silent-death failure. A new
    `ISparkBackend::subscription_health()` (non-pure, default `Healthy` - zero changes to
    any pre-existing test double) plus `GuardianSparkRuntime::revalidate_
    subscriptions()` are wired into `ConvergenceScheduler`'s existing ~5s priority lane
    (no new thread) and report/detach a `Dead` subscription exactly as a delivered `Lost`
    would, whether or not one was ever actually delivered. Scoped to `Dead` only - a
    missed `Faulted`/`Recovered` toggle is health-reporting-only, lower severity, not
    backstopped here.
  - **Verification**: full `[spark]` suite (plain, TSan `[tsan]`+`[tsan-heavy]`, and real
    ASan against the `x64-linux-asan` instrumented triplet - the stock `x64-linux` tree
    reproduces exactly the phantom protobuf-static-init `use-after-poison` §2 criterion 2
    already documents) all clean, with one exception stated plainly: `test_guardian_
    engine_spark_reconcile.cpp` has a pre-existing, ASan-only flake affecting roughly
    18-29 assertions per run, confirmed present on completely unmodified `origin/dev`
    too. A dedicated re-verification pass (run separately, after this branch had merged
    a further-advanced `origin/dev`) root-caused it precisely: `spark_spec_from_rule()`'s
    Service-type `service_name` param lookup (`guardian_spark_bridge.hpp:146-150`)
    intermittently reads back empty under ASan only (10/10 clean on a plain build, ~1/3
    failure under ASan), reproduces identically on an untouched sibling test, and never
    triggers an actual `ERROR: AddressSanitizer` report across dozens of runs - a
    logic-level race ASan's overhead makes more likely to surface, not memory corruption
    ASan itself would catch. This PR's own new test in that file uses a bare `CHECK` (not
    `spin_until` - an earlier draft of this fix speculatively wrapped it in
    `spin_until`, which only turned a fast flaky failure into a slow one without curing
    it, and was reverted once the real cause was found) and flakes at exactly the same
    rate as its siblings, for the same reason - not a new correctness defect introduced
    by this PR. Filed as **#4067**; not fixed here, out of PR-2d's scope. The `arm_impl`
    alloc-budget test's failed-watch-path literal
    (`test_spark_alloc_budget.cpp`) was re-measured, not guessed, per that file's own
    methodology: 2 -> 6, the four new allocations named in its own updated comment.
  - **Re-verification round (governance Gate 3, cpp-safety): this "Verification"
    paragraph was written before a real BLOCKING finding, and describes the pre-fix
    tree.** cpp-safety found `report_fault()`'s new `deliver()` call reachable from
    `start()`'s pre-start-replay loop while that loop's own `mech_ops_mu_by_type_`
    guard was still held - a self-deadlock class this PR's own audit had covered for
    `arm_impl`'s Lost-delivery path but missed on this pre-existing call site. Fixed by
    scoping the lock to just the staleness-check + `watch_guarded()` call. Confirmed
    empirically, not just by lock-order reasoning: a new regression test genuinely
    hung (killed by a 12s timeout, zero output) with the fix reverted, and passed
    clean with it restored. The full `[spark]` suite (plain/TSan/ASan) was re-run
    against the corrected tree above and remains clean under the same terms.
  - **`PR-2d was NOT gated on PR-2e (#3816) landing`** (already merged as PR #3979
    before this PR started) - confirmed correct in hindsight: #3816 supplied an
    executor-level caller-abandonment signal, #2818 needed an engine-level
    consumer-death notification. Different primitives, different layers, no ordering
    constraint materialized.
- **#2833 - CONFIRMED but DOMINATED; accepted by documentation, no code change.** The
  unwatch-failure counters do increment during shutdown **on the `dirs_`/direct-unwatch
  path** — the ancestor-teardown path (`arm_ancestor()`/`release_ancestor()`'s own
  zombie-drain/throw-containment, #2839 follow-up) has no counter at all: those
  `catch(...)` blocks have no `SparkEngine` frame above them to report a failure to
  (governance Gate 8 cross-platform finding). A `bad_alloc` there is silently dropped
  regardless of shutdown state, not just during it — a narrower, Windows-only,
  ancestor-path-only gap than this row's original scope, disclosed rather than fixed
  here (see the code comment at `arm_ancestor()`'s zombie-drain block).

  On the `dirs_`/direct-unwatch path the counters DO increment, but nothing carries
  them off the box: the agent's heartbeat composer emits NOTHING once `stop_requested_` is set
  (`agent.cpp:2582` / `:3311`) — independently of whichever order the two shutdown
  paths' spark-stop and heartbeat-join calls happen to interleave in, since
  `emit_spark_heartbeat_tags()`'s own `!running` early-return suppresses it too. A
  `spark_heartbeat.hpp` change would be inert on the wire; the gate
  that would have to move is the agent's, and it is deliberate (STOPPED is not FAILED - a
  cleanly-stopping agent must not page on-call). **Operator consequence, and the reason
  this is written down rather than closed silently: shutdown-window increments are
  journal-only (`spdlog::error` at each increment site), never heartbeat-visible, so a
  zero reading for `yuzu.spark_arm_race_unwatch_failures` or
  `yuzu.spark_disarm_unwatch_failures` during a shutdown is NOT evidence that nothing was
  orphaned.** Pinned in PR-2c and disclosed on both counters and on
  `emit_spark_heartbeat_tags` itself.

  **Considered and deferred (governance Gate 6 sre finding O2, PR-2c):** a
  persist-and-report-next-boot alternative — write these counters (plus the new
  `teardown_join_timeouts_total`, #2815) to `kv_` at Guardian stop, the same store
  `GuardianLifecycleJournal` already borrows, and surface them as a
  `yuzu.spark_last_shutdown_*` tag on the FIRST post-restart heartbeat. This would give
  fleet-scale visibility into a recurring dirty-shutdown pattern one boot later, without
  touching the live-shutdown STOPPED-not-FAILED gate at all. Not implemented in PR-2c —
  recorded here as a real, deliberately-not-yet-taken option so "journal-only forever" is
  a decision PR-5's sign-off can revisit, not an unexamined default. Today, absent this,
  the local rotating log file (`main.cpp`'s `rotating_file_sink_mt`) is the only egress
  for these counters, forever, unless a customer's own log-shipping tails it.
- **#2839 - CONFIRMED and FIXED in PR-2c; Windows evidence CAPTURED (corrected 2026-09-04;
  further corrected 2026-09-05/06: ASan-infeasibility claim retracted and real Windows ASan
  evidence verified clean in isolated repro on `dev` HEAD - the CI dispatch itself timed out,
  #4018).** `push_retiring` took the owning `unique_ptr` by
  value and pushed before
  allocating, so a `bad_alloc` destroyed a `DirWatch` whose `ReadDirectoryChangesW` was
  still outstanding. Review found three further gaps beyond the original reorder: the
  gauge-crossing log runs after the transfer and can itself throw, `release_ancestor` is a
  second call site with the identical pattern, and all THREE `stop()` cancel loops
  dereferenced their `unique_ptr` unguarded. All four fixed, with a
  `set_file_retire_fault_hook_for_test` seam to aim the allocation failure. **Verified on
  real Windows hardware (DGRHP, commit `95ca9f8e2`)**: the committed test's own
  discriminating power was checked on real MSVC-compiled code first - an earlier version
  had zero discriminating power (its "still not wedged" follow-up watch collided with the
  first watch's directory key and silently repaired the pre-fix corruption before `stop()`'s
  cancel loop ever ran, so it passed identically whether the fix was present or reverted) -
  then corrected (a genuine sibling directory) and re-verified: a real SIGSEGV
  (`0xC0000005 STATUS_ACCESS_VIOLATION`, in `mech->stop()`) pre-fix, a real clean pass
  post-fix, 4/4 stable.

  **A second Windows-hardware round (DGRHP, 2026-09-05, commit `0cdd6bb2a`) covers the two
  fixes that landed AFTER `95ca9f8e2`**: the zombie-`DirWatch`-reattachment guard in
  `watch()`/`arm_ancestor()` (`1a2855e43`, security-guardian Gate 2) and the
  `release_ancestor()` exception-containment fix (folded into `0cdd6bb2a`, cpp-expert Gate
  3) — both landed with only compile-clean/structural verification on Linux at the time,
  which compliance-officer's Gate 6 review correctly flagged as a stale evidence-scope gap
  (the earlier "4/4 stable" sentence above described `95ca9f8e2` only, not these two later
  commits). Closed the same way as the first round: `spark_file.cpp` reverted to the
  pre-`1a2855e43` parent (`1123ce320f`) with the rest of the tree at HEAD, so the fix's own
  regression tests are the discriminator, not a wholesale old checkout. RED (reverted): the
  `watch()`/`dirs_` test fails at `stats().retiring == 1` (actual 0, the zombie silently
  reattaches); the `arm_ancestor()`/`ancestors_` test fails the same way AND
  `CHECK_NOTHROW(mech->unwatch("k2"))` throws `bad_alloc` uncontained (the
  `release_ancestor()` gap). GREEN (HEAD, `0cdd6bb2a`): both 13/13 and 15/15 assertions
  clean. Each state run twice (8 runs total), zero variance, no crash, no flake — the same
  wedge-idiom determinism the first DGRHP round established (an earlier, un-wedged version
  of these two tests had raced non-deterministically against the mechanism's own worker
  thread, per quality-engineer's Gate 3 finding, independently confirmed 11/11 times on
  this same hardware before the wedge-idiom rewrite). Worktree left at
  `C:/Users/daver/yuzu-3848-zombie` for reuse.

  **Correction (2026-09-05): the INFEASIBLE claim below is false - retracted.** It was written
  from a one-off scratch build's 1266 `LNK2038` link failures and concluded MSVC ASan could not
  be made to work at all under this toolchain. That conclusion does not hold: a working,
  coverage-limited Windows ASan CI leg has existed and run green since 2026-07-08
  (`.github/workflows/nightly.yml`'s `windows-asan` job). It reuses the standard,
  non-instrumented `x64-windows` vcpkg triplet and passes `-D_DISABLE_STRING_ANNOTATION
  -D_DISABLE_VECTOR_ANNOTATION` - the documented MSVC workaround for exactly the LNK2038 class
  the scratch build hit - and its own header comment records: "spiked 2026-07-08 on DGRHP: full
  agent suite green, zero ASan reports, both with and without this flag pair changing anything
  except making the link succeed." This leg DOES catch heap/stack-buffer-overflow and
  use-after-free - the exact class `#2839`'s defect is (a `DirWatch` UAF while Windows still
  owns an outstanding `ReadDirectoryChangesW`) - so `#2839`'s own test
  (`tests/unit/test_spark_mechanism.cpp`, inside the `_WIN32` section) is already part of
  `yuzu_agent_tests`, the exact binary this job builds and runs, and needed no new wiring. It
  does NOT catch STL container-overflow, because the annotation-disable flags turn that
  checking off globally, not just for the vendored deps - that gap is `#2016`'s separate,
  correctly-deferred, from-source-instrumented-triplet project, and is irrelevant to `#2839`'s
  UAF-class defect. Root cause of the scratch build's failure confirmed directly (its worktree
  was still on disk at `C:/Users/daver/yuzu-2839-asan-check`, `build-windows-asan-addr`): its
  meson configure log shows `b_sanitize=address` set but **no** `cpp_args` entry at all - the
  `-D_DISABLE_STRING_ANNOTATION -D_DISABLE_VECTOR_ANNOTATION` workaround was simply never
  passed - and its compile log's 1268 `LNK2038` lines (close to, though not identical to, the
  retracted claim's cited 1266 - both are exact counts, not a rounding artifact, and the
  2-line gap is unexplained)
  are all `mismatch detected for 'annotate_string'/'annotate_vector': value '0' doesn't match
  value '1'` - exactly the container-annotation mismatch those flags exist to suppress. Not "a
  different build config" as speculated originally: the one thing that would have fixed it was
  omitted. The recipe's own nightly history independently confirms it links and passes on
  `main`; the real run recorded immediately below confirms it also passes on `dev` HEAD in
  isolation from CI. The CI dispatch's own 240s timeout is a separate, unresolved finding
  recorded below - not attributed here to the recipe itself. Original (retracted) text,
  kept for the record:

  > MSVC `/fsanitize=address` was separately confirmed INFEASIBLE under this repo's current
  > toolchain (a real, general finding, not specific to this PR): an ASan-instrumented build
  > compiles clean but fails to LINK, 1266 `LNK2038` mismatches, because vcpkg's binary-cache
  > grpc/protobuf/abseil aren't ASan-instrumented and no triplet rebuilds them with matching
  > instrumentation - a substantial, separate, not-yet-scoped prerequisite if Windows ASan is
  > ever wanted. So the evidence above is real MSVC-compiled, real-kernel-I/O red/green
  > verification, genuinely NOT ASan proof, described honestly as such.

  **Real Windows ASan evidence for #2839 (2026-09-05/06) - clean pass on `dev` HEAD, after
  a CI-only timeout that does not reproduce in isolation.** The commits, run URL, timings and
  SHAs below are a 2026-09-05/06 point-in-time snapshot - re-verify against current CI history
  before relying on them if reading this much later. Dispatched `nightly.yml` via `workflow_dispatch`
  against `origin/dev`
  HEAD (`1e7a5346c70a3b6d85f6c1924a6fb4858ebb4265`, at/after the required `8355d4cb2b8`):
  <https://github.com/Tr3kkR/Yuzu/actions/runs/33997171977>. This is the **first-ever
  `windows-asan` execution against `dev`**: checking `nightly.yml`'s full run history (143 runs
  via the GitHub API, not just the most recent page) shows only three runs ever targeted `dev` -
  two on 2026-05-15, both before the `windows-asan` job existed (added 2026-07-08, confirmed
  absent from those two runs' job lists) - and this dispatch. So the established "green since
  2026-07-08" history is entirely against `main` (currently `88f9397d355ef18794da3f7d8c7ca1b47ded8742`,
  confirmed still green on the very next regularly-scheduled nightly, 2026-09-06T06:22Z) - it
  proves the disable-macro recipe links and runs clean on `main`'s code, not that `dev`'s
  current, larger HEAD passes under it.

  The job's `Test` step **timed out at 240.16s** (meson's 240s ceiling for this suite, chosen
  per `tests/meson.build`'s own comment on the `agent` suite's `timeout:` (line number drifts;
  search for "is ~8x headroom") as ~8x the plain, non-ASan-instrumented,
  `[tsan-heavy]`-excluded baseline of ~28s - but that 8x is headroom over the PLAIN baseline,
  not the ASan-instrumented one; the DGRHP reruns below put a clean ASan run at ~135-139s on
  dedicated, uncontended hardware, so the real headroom this ceiling gives an ASan run is only
  ~1.7-1.8x even there, not 8x - and the one data point actually observed on the shared,
  contended Wee Tam pool is this same run, which didn't finish inside it at all)
  with `Ok: 0, Fail: 0, Timeout: 1`, so this run gives
  **no** pass/fail signal for `#2839`'s own tests specifically. Downloaded the complete,
  non-truncated `meson-testlog-windows-asan` artifact (`testlog.txt` - meson's own
  `--print-errorlogs` dump shows only the last 100 lines in GitHub's log view; the full artifact
  has the same content, confirming it isn't a truncation artifact) to check whether this is a
  genuine stall or a suite that now legitimately runs past 240s. Correlating the binary's own
  spdlog timestamps against the step's GHA-UTC timestamps (first app log line `23:55:35.988`
  local against the step's `22:55:35.858Z` launch - a clean +1h offset, i.e. the runner's local
  clock, not a divergent one) puts the last captured line
  (`KvStore opened: ...yuzu_test_page-..._367`) at UTC `22:58:34.049`, then **~61.9 seconds of
  complete silence** before the forced kill at `22:59:35.962`. That line is from the `PageRig`
  fixture (`test_guardian_spark_runtime.cpp:412-413`; verified absent from `main` via
  `git show origin/main:tests/unit/test_guardian_spark_runtime.cpp` - the file doesn't exist
  there at all, so this is `dev`-only code, added for item 7 PR-Ag C5 Guardian-outbox-paging).
  This build's Catch2 defaults to `--order rand` (confirmed via `--help`, not assumed) - test
  execution order is reshuffled every run from a fresh seed, so which specific `TEST_CASE` was
  executing could not be identified from CI's log alone; the order-matched repro below pins it
  down: `_366` and `_367` are the two store-opening `PageRig`-fixture `TEST_CASE`s in that
  stretch of the run order (`test_guardian_spark_runtime.cpp`; five silent, non-store-opening
  tests run between them, so "consecutive" means consecutive stores, not consecutive tests) -
  `"page_into_window prunes an expired batch before replaying (boot barrier)"` (line 3534) at
  `_366`, then `"concurrent persist + page + prune + drain do not race (TSan checkpoint,
  QE-1)"` (line 3864, tagged `[tsan][tsan-heavy]`) at `_367`, the last thing CI's log shows.
  Going completely silent for over a minute looked like a stall rather than ordinary slowness,
  but resolving contention-vs-code needed an isolated repro away from the shared, 4-runner-per-box
  Wee Tam pool - including, since order is seed-dependent, one attempt using the SAME seed CI's
  own run printed, so as to run under CI's own order rather than a merely different random one.

  **Isolated repro on dedicated hardware (2026-09-06, DGRHP)**, same commit and recipe as the
  CI job (`--buildtype=debugoptimized -Db_sanitize=address -Dcpp_args="-D_DISABLE_STRING_ANNOTATION
  -D_DISABLE_VECTOR_ANNOTATION"`, `x64-windows` triplet, `ASAN_OPTIONS=halt_on_error=1`),
  `yuzu_agent_tests.exe` run directly with a 20-minute cap instead of meson's 240s one (running
  an ASan-instrumented binary directly, outside `meson test`'s wrapper, needs the MSVC toolchain's
  `bin\Hostx64\x64` dir on `PATH` for `clang_rt.asan_dynamic-x86_64.dll`, in addition to the
  usual `agents\core` DLL-dependency dir).
  First pass, default `--order rand` (a fresh, different seed from CI's): completed cleanly in
  ~139s, exit code 0 - a real result, but a weaker one on its own, since a different random
  shuffle could simply have avoided whatever CI's specific order hit. Second and third passes
  both used `--rng-seed 1414877821` (the exact seed CI's own run printed, `testlog.txt` line 12,
  confirmed echoed back correctly: "Randomness seeded to: 1414877821"), which - per Catch2's
  order mechanism below - means both ran under CI's own order, not just CI's seed value. Second
  pass: also completed cleanly, exit code 0, ~136s (this pass's own output capture was lossy -
  a PowerShell `Register-ObjectEvent`/`BeginOutputReadLine` async stdout capture raced its own
  writer and lost most lines - so only the exit code and a handful of surviving lines are from
  this run specifically). Third pass, same seed again,
  this time with a synchronous `*>` redirect to get a complete, correctly-ordered capture: **also
  completed cleanly, ~135s, exit code 0** ("All tests passed (52387 assertions in 2636 test
  cases)") - and this complete capture is what lets the order match be checked directly rather
  than assumed.
  Verified Catch2 v3.13.0's `--order rand` mechanism from its own source
  (`src/catch2/internal/catch_test_case_registry_impl.cpp` + `catch_test_case_info_hasher.cpp`,
  tag `v3.13.0`): it computes an FNV-1a hash of each test's `name` + `className` + tags XORed
  with the seed, then sorts by that hash - registration order and cross-TU link order play no
  role except as an exact-hash-collision tie-break - so an identical set of registered tests
  (same commit, same recipe here) plus an identical seed should deterministically produce an
  identical order. Confirmed this empirically too, not just by trusting the mechanism: diffed
  this third pass's complete `KvStore opened: ...` sequence against CI's `testlog.txt`,
  normalizing away the per-process PID and the SYSTEM-vs-`daver` temp-dir username. **All 242 of
  CI's opens match, in the same order, with the same fixture-type-and-counter value at every
  position** - not a sample, the full set. Both start identically too: `SparkEngine stopped` x2,
  the same `Trigger 'does-not-exist' not found` warning, then `KvStore opened` for
  `guardian_reconcile` at global counter `_1`. **This is the same test order as CI's run, not
  merely the same seed value.**

  Past CI's last logged event is where the two runs diverge. CI went silent for the ~61.9s
  described above and was killed at the 240s timeout. DGRHP's order-matched third pass shows
  what ran in that exact window, and got through all of it in ~136ms with no delay: the `_367`
  test itself - `"concurrent persist + page + prune + drain do not race (TSan checkpoint,
  QE-1)"` - is the most obvious candidate on its own description alone (a multi-threaded
  concurrency stress test, explicitly a TSan checkpoint, running on a box shared 4-ways with
  other CI jobs competing for the same CPUs is a plausible place for contention to bite even
  though it finished instantly here). After it, before the next KvStore opens at `_369` at
  `12:18:32.399` (~136ms after `_367` at `12:18:32.263`), the log shows a trigger
  register/unregister, a `disk_actions` plugin load, a `SparkEngine` file-watch arm/fault/recover/
  stop cycle, a `sync: software_licensing` HMAC-persist warning, a skipped `http_client`
  descriptor test (DLL not present in this build), and a `TriggerEngine` start/stop - lower on
  suspicion than the concurrency test but not ruled out, since which of these actually stalled on
  Wee Tam cannot be determined from CI's log, which recorded nothing after `_367`. The whole
  suite finished clean roughly 12s after `_367` (`_367` at `12:18:32.263`, last KvStore `_417` at
  `12:18:44.326`; total wall time for the full 2636-case run was ~135s end to end). This narrows
  CI's silent window to a named `TEST_CASE` and a short, named list of what follows it, rather
  than leaving it at an unidentified "position 367."

  **Conclusion: running the SAME test order as CI's own run, on dedicated hardware, sails
  straight through the exact point CI stalled at, with no slowdown. This does NOT resolve #4018
  - it stays open, and neither it nor #4019 blocks #2839** (see the closing summary below for
  the full statement of that). This is materially
  stronger than "a different random order also passed" - it rules out the possibility that
  DGRHP's clean runs just got lucky with an order that happened to avoid whatever CI's order hit,
  since this run used CI's own order and still didn't hit anything. It does not identify what
  Wee Tam-specific factor caused the 240s timeout (contention from the shared 4-runner pool is
  the leading candidate given CLAUDE.md's documented always-shared-box architecture - both
  self-hosted CI pools run 4 runner agents as one shared OS identity on one box - and the
  concurrency-stress-test candidate named above, but it wasn't directly observed - no process
  inventory was captured on Wee Tam at the time), and a single clean pass under CI's order
  cannot rule out a rare intermittent race independent of environment; this dispatch is also the
  FIRST-EVER `windows-asan` execution against `dev` (established above), so there is no
  recurrence-rate data yet to say whether this was a one-off or something that fails on some
  fraction of future `dev` runs. But three clean runs on
  the same commit and recipe - one under a different random order, two under CI's own seed and
  therefore CI's own order (the third of the three confirmed by a complete capture matching all
  242 of CI's opens) - is strong evidence against a reliably-reproducing, order-dependent
  code-level hang, and is the practical limit of what an isolated repro without Wee Tam's own
  process-level telemetry can establish.

  The same dispatch's Linux `sanitize-asan` and `sanitize-tsan` legs also failed, but this is a
  separate finding, not corroboration of the above: both failed in the SAME two files
  (`test_guardian_engine_spark_reconcile.cpp`, `test_subprocess_runner.cpp`; not
  `test_guardian_spark_runtime.cpp`/`PageRig`) with the SAME assertion lines under both
  independent sanitizers - a deterministic signature, not sanitizer flakiness - but neither
  file is `[tsan-heavy]`-tagged and `ci.yml`'s plain (non-sanitizer) build was green at this
  exact commit, so these are real but narrower in scope: something specific to running under
  sanitizer instrumentation (e.g. `test_subprocess_runner.cpp`'s `run_bounded_subprocess` case
  got `termination_reason == 4` where `exited (0)` was expected - a spawned child behaving
  differently, or being killed, under instrumentation). A deterministic cross-sanitizer failure
  is at least as consistent with a genuine defect the plain build's coverage happens to miss as
  with instrumentation-only fragility - #4019 does not presume which, and root
  causing it is exactly what that issue is for. Not a `dev` merge regression and not
  the same failure as today's `main` nightly's unrelated Linux ASan failure (a `server`-binary
  test, different file, different exit code). Filed as **#4019**, separate from `#2839`
  and from the Windows finding above (filed as **#4018**). (A concurrent, unrelated macOS runner-inventory drift,
  `#2301`, also surfaced while checking CI history and is noted only to rule it out - it does
  not touch Wee Tam or Big Tam.)

  `#2839`'s specific tests now pass clean under real Windows ASan on `dev` HEAD (three DGRHP
  isolated runs above, two under CI's own seed/order, one confirmed by a complete 242-open
  capture match). The "genuinely NOT ASan proof" caveat from the original claim no longer
  applies. What caused the specific CI timeout
  remains unidentified but narrowed to a named `TEST_CASE` - `"concurrent persist + page + prune
  + drain do not race (TSan checkpoint, QE-1)"`, the test whose `KvStore` open was CI's last
  logged line - and a short, named list of what runs immediately after it (leading theory for
  the environment factor: Wee Tam pool contention, not directly observed) - filed as **#4018**,
  as is the separate Linux sanitizer-environment finding whose own root cause (genuine defect
  vs. instrumentation artifact) is undetermined (**#4019**) - neither is a `#2839` blocker, and
  neither is resolved by anything in this entry: this dispatch is the first-ever `windows-asan`
  run against `dev`, so recurrence rate is unknown, and this ASan coverage - real, but limited
  to heap/stack-overflow and UAF, not STL container-overflow, and not yet demonstrated to run to
  completion in CI against `dev` even once (it has run green against `main` since 2026-07-08,
  per the retraction above) - is not a complete safety net against future Windows-specific
  defects in this code.
- Owner: not assigned in source material.
- Milestone: PR-2c DONE for #2815 / #2833 / #2839; **PR-2d DONE for #2818**.
- Revisit trigger: fired, and resolved. All four of this row's issues are now fixed or
  accepted-by-documentation.

**PR-2d follow-up hardening (governance Gates 3/4/5/6, filed 2026-09-06)** - findings from
PR-2d's own review, none blocking (all SHOULD; most are OOM/backpressure-only, dormant-
until-flip, or bounded by the ~5s poll backstop - QE-2 below is the one exception, a
test-coverage-only gap), tracked here rather than re-litigated as new #2815-class entries
since they're hardening ON TOP OF an already-correct #2818 fix, not a defect in it:
- **#4051** (P1) - the dedup-race window named in `revalidate_subscriptions()`'s own doc
  comment: a Lost notification can be discarded as stale by `on_subscription_lost`'s
  staleness guard if it's processed before the sibling arm's own commit lands, stranding
  a dead subscription for up to the poll backstop's ~5s cadence instead of catching it
  instantly. Needs a new pre-commit test seam to reproduce deterministically - real but
  small design work, not rushed into PR-2d.
- **#4052** (P2) - `revalidate_subscriptions()`'s sweep has no per-key throw isolation
  (`firewalled_sweep` aborts the WHOLE pass on one key's throw) and a `bad_alloc` mid-
  detach can strand a `keys_` row with no self-heal path. Both require allocation
  failure to trigger.
- **#4053** (P2) - `guardian_outbox`'s `enqueue_all` all-or-nothing semantics can drop an
  entire multi-rule Health batch under backpressure, with larger fan-out (more rules
  sharing a key) making total loss MORE likely exactly when blast radius is biggest.
- **QE-2 (quality-engineer Gate 3), non-gating, tracked here rather than filed standalone** -
  `on_subscription_faulted`'s `OutboxEntry` content (`rule_id`, `generation`, `healthy`,
  `detail`) has no direct Guardian-layer test; only the engine-level Faulted/Recovered
  delivery is covered. Health-only path, no state-machine risk, bounded blast radius -
  a genuine but small coverage gap, worth closing alongside any future work that already
  touches `guardian_spark_runtime.cpp` rather than its own PR.
- **C-1, folded here rather than filed standalone** (consistency-auditor,
  dormant-until-flip, PRE-PR-5 GATING) - `server/core/src/guaranteed_state_store.cpp`'s
  `event_state_from_type` does not recognize the new `guard.errored` wire event (falls
  through to "no census change", identically to the pre-existing `armed`/`disarmed`
  events). A rule detached as errored keeps showing its LAST PRIOR compliance verdict
  (e.g. "compliant") on the dashboard/REST census even though it is no longer armed or
  evaluated - a real, customer-visible staleness gap once `prefer_spark_` flips, though
  inert today. Not filed as its own issue (chaos-injector's recommendation): it lands
  squarely on the Guardian routed-concern row (`security-guardian` + `docs-writer`
  trigger on any `guaranteed_state*` change) regardless of when it's picked up, and
  belongs with this doc's own pre-PR-5 checklist rather than a freestanding ticket that
  could drift out of sync with it. **Must be resolved (or explicitly re-risk-accepted)
  before PR-5's sign-off** - added to this doc's own gating surface, not merely noted.
- **Journal-quarantine finding (enterprise-readiness Gate 6) - FOUND AND FIXED IN PR-2d
  ITSELF, not deferred.** `guardian_lifecycle_journal.cpp`'s replay-validation allowlist
  only recognized `"armed"`/`"disarmed"` - the exact same class of gap as C-1 above, but
  more severe: a `guard.errored` record surviving a crash/restart before it drained live
  would have been silently QUARANTINED as tampered, destroying the very audit record
  #2818 exists to produce, in the exact scenario (durability across a restart) it's meant
  to survive. Fixed by widening the allowlist to include `"errored"`, with a new
  regression test that empirically proved red (the record was genuinely quarantined,
  `records_paged==0`) before the fix and green after. Kept here as a record that this
  class of gap was checked and closed for `"errored"` specifically, not just C-1's
  narrower census-display symptom.
- **Observability gaps (sre Gate 6), PRE-PR-5 GATING, not fixed here** - three related
  findings, none new resource cost, all folded into this checklist rather than filed
  standalone since they're small additions to existing telemetry surfaces, not new
  designs: (1) the new `subscription_lost_total` stat joins the already-known-dark
  `SparkEngineStats` set - `spark_heartbeat.hpp` is untouched by this PR, so nothing
  polls it; **a future "just add the heartbeat tag" fix must also account for the poll
  backstop path**, which calls `on_subscription_lost` directly and never increments this
  counter at all, so a naive fix would under-report exactly the population the backstop
  exists to catch. (2) `revalidate_subscriptions()`'s own tick has no liveness/repair
  telemetry - no counter/log distinguishes "ticked, found nothing" from "ticked, repaired
  N" from "didn't tick" (the nearest signal, `ConvergenceScheduler`'s shared
  `sweep_exceptions_`, is shared across five call sites and can't attribute a throw to
  this sweep specifically). (3) an errored rule has no age/duration gauge, breaking house
  convention (`GuardianJournalAgeStats`'s AGE-gauge pattern, flip item 6/#2364, is the
  established shape for "a single stuck instance is the fleet signal" and has no
  equivalent here) - combined with C-1, an on-call engineer has zero signal short of
  reading the per-agent lifecycle journal file directly.
- **Dormant-claim verifiability (compliance-officer Gate 6), PRE-PR-5 GATING, cross-PR scope** -
  every "dormant while `prefer_spark_=false`" disposition in this row (and elsewhere in
  this doc) rests on a code-reading assertion, not an auditor-checkable per-deployment
  signal. The wire-level tag already exists (`kGuardianBackendTag`/`yuzu.guardian_backend`,
  correctly distinguishing legacy vs. spark enforcement per agent) and is ingested
  server-side into the per-agent `status_tags` map, but **no server code reads it** - no
  REST field, no dashboard surface. Not specific to #2818 (it's a general PR-5-readiness
  gap), so not filed as its own #2818-scoped issue; recorded here since several of this
  PR's own non-blocking dispositions depend on it.
- Owner: not assigned for any item above.
- Milestone: pre-PR-5 hardening package (#4051/#4052/#4053) + three pre-PR-5 GATING items
  (guard.errored census recognition; the three sre observability gaps; the
  yuzu.guardian_backend server-side-reader gap) - no issue numbers, tracked here.
- Revisit trigger: before PR-5's sign-off, everything above re-checked; #4051 specifically
  re-checked before any production fleet (dedup races become far more frequent under
  real load than in this PR's own governance testing).

**#2012 + #2011 + #3840** (+#2014, confirm at execution)
- Detection signal: **none today**, named explicitly in the source ruling - a stuck
  `arm_ancestor` walk (File, #2012) or a stuck `CreateThreadpoolWait`/`RegNotifyChangeKeyValue`
  (Registry) has no fleet-visible symptom until it starves the owning mechanism type's per-type
  arm/disarm queue. **Corrected 2026-09-11 for Service:** a stuck `OpenServiceW` has no
  fleet-visible symptom either, but it starves *sibling watches sharing Service's own worker
  thread*, not the per-type arm/disarm queue - see the Milestone entry below for the full
  correction (Service's `watch()`/`unwatch()` were never actually gated by the per-type lock).
- Operator action: none today (no detection signal to act on); would require a restart once
  discovered by other means (e.g. operator-reported unresponsiveness) - not a documented
  runbook step yet.
- Compensating control: the standing downgrade of this pair from a hard pre-Stage-2 gate to
  early-post-flip hardening, **with the gap recorded honestly** - the shutdown watchdog
  (#3737) bounds hang-**at-exit** only; it does **not** bound an unbounded stall **during
  normal operation**, which is #2012's actual hazard class (Sol opine, verified - confirmed
  untouched by PR #3821, a different layer: #3821 bounds Guardian's synchronous wait on
  SparkEngine, not the File mechanism's own internal unbounded walk under its own lock).
  **The basis for deferring is NOT "no regression vs. legacy" - direct code comparison shows
  the opposite for the File mechanism.** Legacy's own hang (`guard_file.cpp:96` launches the
  per-rule thread; the unbounded `fs::is_directory` walk itself is at `:288` and `:299`, inside
  that thread, with no shared lock) stalls exactly
  the one affected rule, permanently, but does not block any other rule. Under spark
  (`spark_engine.hpp:536-548`), the identical class of hang holds the File mechanism's
  per-type lock, stalling arm/disarm for **every** File-type rule for the hang's duration -
  and that duration is not meaningfully bounded either: the code's own comment calls it
  "unbounded" (`spark_engine.hpp:540-543`), the same class of hang as legacy's. The real
  difference is blast radius (one rule vs. every File-type rule), not duration - a broader
  blast radius than legacy's single-rule stall, held by a coarser per-type lock rather than
  legacy's per-rule isolation. The real basis for
  deferring is legacy-twin #2189 parity for the Service mechanism specifically (a macOS
  launchd whole-engine `mtx_` seizure, `stop_all_guards_locked`) plus the absence of any
  production fleet today - not a blanket "no regression" claim across all three mechanisms.
  #3840 (filed 2026-09-02, `spark_engine.hpp:536–548`) was originally described as the
  identical "walk-off-`mu_`" hazard shape for Registry's `TP_WAIT` / Service's Windows SCM
  query - **corrected below (2026-09-11): that was only ever true for Registry.**
- Owner: for the remaining #2011/#2014 piece, the mechanism-hardening package (File + Registry +
  Service together, one restructure, reviewed once) - no individual named in source; the pulled-forward
  #2012/#3840 piece is owned by its rung 9c kickoff (Milestone below).
- Milestone: **split by ruling 14(c) (2026-09-08), revised 2026-09-11** - the #2012/#3840
  same-type-serialization piece was pulled forward into rung 9c's own ladder, between its PR-1
  and PR-2. It landed as **three** PRs sharing one primitive, not the two originally planned:
  PR-A (#4190, shared `SparkDetachedLane` primitive), PR-B1 (Registry, #4225, merged), PR-B2
  (File, #4284, merged), **PR-B3 (Service, #4302, merged 2026-09-12 - corrected 2026-09-13,
  superseding the prior "in review, not yet merged" wording here)**. **Status per mechanism,
  corrected against the actual landed code, not the original plan:**
  - **File:** the per-type-lock stall this row originally described is closed (PR-B2). File's
    teardown does not block the way Registry's does, so PR-B2 built a probe-only lane, not a
    two-lane restructure.
  - **Registry:** the per-type-lock stall is closed (PR-B1) via a two-lane (`probe_lane_`/
    `drain_lane_`) restructure - Registry's teardown (`WaitForThreadpoolWaitCallbacks(...,
    TRUE)`) is a genuine blocking call, so isolating it too was warranted here specifically.
  - **Service:** **never actually had this hazard** - `watch()`/`unwatch()` were already O(1)
    queue pushes before this whole series (confirmed by direct code read and by
    `spark_mechanism.hpp`'s own mechanism-contract comment; #3840's Service bullet has been
    corrected in place, 2026-09-11, to reflect this). The real, structurally different gap:
    `OpenServiceW` ran head-of-line on Service's own single dedicated worker thread, stalling
    *sibling watches sharing that thread* - not the engine-wide per-type lock this row
    describes. PR-B3 isolates that specific call onto a probe-only lane. `NotifyServiceStatusChangeW`'s
    registration stays on the mechanism thread by design (Win32 thread-affinity requirement) -
    an accepted, explicitly-documented residual, not a gap PR-B3 claims to close.
  - **Service pre-flip follow-ups (governance review, PR-B3, consolidated here so they are
    not lost one hop away in a PR/issue instead of this gating register):** tracked in
    **#4218** - (a) the ~50-65 ms establishment-latency figure above is dominated by
    `kServicePollCadence`, not raw API cost, and the constants governing it
    (`kServiceProbeLaneCap=16`, `kServiceHealthGrace`, the admission-backoff pair) are copied
    from Registry's already-reviewed values, not measured against Service's own capacity -
    retune after a real synthetic-storm measurement before flip; (b) at >16 simultaneous
    Service watches (boot/reconnect), the admission backoff and health-grace windows can
    collide and produce a transient false-fault-then-recover flicker indistinguishable from a
    genuine SCM outage, with no fleet-visible counter to disambiguate the two causes (adjudged
    MEDIUM/non-blocking for PR-B3 itself, since the feature is dormant); (c) Service's
    `stats()` folds none of its new probe-lane counters (`probe_admission_rejected_`,
    `probe_backend_failed_`, `health_edges_`) into `SparkMechanismStats` at all - not even the
    coarse tier Registry/File already populate for the equivalent gap (tracked separately for
    those two at #4218/#4279) - so today Service has no operator-visible signal beyond a raw
    log line if any of the above occurs; (d) `teardown_watch()` never cancels an in-flight
    establishment probe, so a watch retired while `Pending` keeps its `probe_lane_` slot until
    the real `OpenServiceW` call returns - sustained watch/unwatch churn faster than the
    `retiring_` reap window, combined with backend latency exceeding it, can starve new
    admissions. **Corroborated empirically, not just theoretically**, by this same session's
    real-hardware verification: File's sibling mechanism, sharing the identical
    `SparkDetachedLane` admission primitive, was observed exceeding its configured lane cap by
    one under real storm load (`max_active=9 > kTestLaneCap=8`, 1-in-~10 real-hardware runs -
    see #4279's corresponding note) - raising this above "spec says it can't happen."; (e)
    **NEW, added to #4218 2026-09-12**: `CloseServiceHandle`'s own hang potential is disclosed
    but unverified, not yet measured or given a synthetic-storm test - same LRPC transport as
    `OpenServiceW`, governance found no evidence it cannot hang under a wedged SCM, and four
    routine paths call it with a live handle. This was previously mis-described elsewhere as
    "not a blocking call" (corrected in place, both here and in
    `docs/spark-stage2-guardian-consumer-design.md`, 2026-09-13) - split into its own item so it
    isn't silently read as settled.
  #2011 (lock granularity) and #2014 stay early post-flip in the named package, unaffected by
  the correction above.
- Revisit trigger: for the remaining #2011/#2014 piece, **escalate to flip-gating if a production
  fleet materializes before it lands**; the #2012/#3840 piece is already pre-flip by ruling 14(c).
  **Re-verification DONE, 2026-09-12 (superseding the prior "re-verify before treating PR-2 as
  unconditionally unblocked" open item above)**: ruling 14(c)'s own "sustained same-type stall
  holding a generation's acknowledgment indefinitely" framing was re-checked against Service's
  actual (corrected) stall shape - routed to Astra (opine) then Fable (advisor) for independent
  review, both concurred. Finding: the underlying concern (same-type contention causing genuine
  admission congestion, not just delay) is addressed for all three mechanisms, though not
  eliminated outright - the #4279 lane-cap-overshoot observation is a tracked, characterized
  residual. **Corrected 2026-09-13**: an earlier version of this cell leaned toward "most likely
  a transient admission-counter artifact" - the issue's own static read (a single atomic
  fetch-add-then-compare-then-rollback, no obvious TOCTOU) and Astra's independent derivation
  both point the same direction but neither confirms it; the issue's own words are the accurate
  ones - "root cause undetermined... not confirmed either way." Either way, not a reopening of the
  original hazard. **Ruling 16 (2026-09-12): rung 9c's PR-2 is unblocked** - also corrects
  ruling 14(c)'s own rationale, since the K-bound/wedge classification logic actually lives
  in PR-5, not PR-2, so the accepted cost this hold existed to protect against was never live at
  PR-2 in the first place. **PR-2 has since merged** (PR #4318, `a27ec4549baa`,
  2026-09-13T14:46:02Z) - see `docs/spark-legacy-delta-registry.md` row A3 for its "Verify at"
  update. #4181 (the related same-type reentrant-deadlock issue, T6) is CLOSED - verified against
  the landed code that Service's `watch()`/`unwatch()` release `mu_` before teardown runs, so the
  two-thread cycle that issue describes cannot occur for Service (independent of whether
  `CloseServiceHandle` itself can hang, a separate, disclosed, still-open uncertainty tracked at
  #4218).

**#2570 + #2578** (macOS spark-test flakes)
- Detection signal: CI red on the macOS leg for these two specific named tests.
- Operator action: not yet defined - building the "explicit rerun rule" the source calls for
  is itself part of the test-debt package's job, not something that exists today.
- Compensating control: narrowly scoped - **not** a blanket "don't chase to green." The design
  doc mandates the full agent suite green on Linux/Windows/macOS as a real cutover path
  (all-unsupported is a tested pass state, §2 criterion 3). Only these two named flakes get
  the (to-be-built) explicit rerun rule + tracking; the mandatory 3-OS-green gate stays in
  force for everything else.
- Owner: test-debt package - no individual named in source.
- Milestone: test-debt package post-flip, for these two specifically.
- Revisit trigger: N/A beyond the milestone above - these do not gate the flip or escalate.

**#3360 + #3392** (test gaps)
- Detection signal: N/A - coverage gaps, not a runtime hazard.
- Operator action: N/A.
- Compensating control: manual UAT rollback drill (§6) provides equivalent flip evidence for
  what automated coverage here would otherwise show.
- Owner / milestone: test-debt package post-flip.
- Revisit trigger: N/A.

**#3416** (+#3415, #3485, #3486)
- Detection signal: already shipped and live - per-OS `yuzu.guardian_backend` heartbeat tag +
  posture keys (`agent_registry.cpp:2124`/`:2296` computes `spark_failed_os`, confirmed in §2
  criterion 3).
- Operator action: N/A - already mitigated by the above.
- Compensating control: the shipped heartbeat/posture-key surface itself.
- Owner / milestone: P4 lane; recheck cost at P4 start.
- Revisit trigger: N/A - not currently expected to need escalation.

**#3972** (cross-lane wire reordering, #3953 item 5)
- Detection signal: none dedicated - a same-pass compliance/health event landing between two
  lifecycle entries on the wire has no counter/log distinguishing it from ordinary delivery;
  `GuardianSparkRuntime::drain_bounded()`'s own doc comment names the mechanism but nothing
  observes an actual occurrence.
- Operator action: N/A - no action exists to take on today's disclosed best-effort ordering.
- Compensating control: best-effort ordering is a documented non-guarantee (drain()'s and
  drain_bounded()'s own comments, corrected in `fix/3953-3966-outbox-hardening` to name the
  same-pass mechanism accurately rather than only the sequential/next-pass cases previously
  disclosed); no consumer today depends on strict cross-lane wire ordering.
- Owner: not assigned in source material.
- Milestone: #3972 itself ("Guardian outbox: cross-lane wire reordering - merge-drain by
  global sequence") - no PR slot assigned yet.
- Revisit trigger: before the F14 flip. **Not risk-accepted** - #3972 is a real, filed,
  still-open issue and remains a §1 gating item until it is fixed or closed; this register
  entry records the disclosure (the corrected `drain()`/`drain_bounded()` comments above) and
  the compensating control only. Matches row 3's own precedent (#3816) of declining to treat a
  real, undisproven residual as accepted risk: the original `p3-up11-cross-lane-wire-reordering`
  ledger row claimed drain()'s comment "already discloses this exact residual" - it did not
  (only the sequential/next-pass cases, not this same-pass mechanism) - so filing #3972 rather
  than a ledger `rejected` disposition was the deliberate correction, not a formality.

**#4665** (agent log lines print operator-authored rule ids and Spark keys as authored, #4606 / PR #4657)
- Detection signal: none - a forged physical line is indistinguishable from a real one in the agent
  log; the R5.7 driver keeps the first line per rule and its closed `expected_rule_ids()` set is the
  only filter.
- Operator action: run benchmarks with harness-generated rule ids only (the driver's closed set) and
  do not present an agent-only latency figure as criterion-10 evidence until #4665 is resolved.
- Compensating control: the server-authored `Guardian T_server` line (neutralised on the server) is
  the authoritative half of the join; no shipped consumer reads agent-log lines; the operator manual
  (`docs/user-manual/server-admin.md`, Upgrade Notes) states which lines print ids as authored.
- **CONFIRMED and FIXED, branch `feat/4665-log-injection-neutralisation` (starting `2ef5b8d3c`;
  not yet merged to `dev` as of this entry).** The fix went through three further rounds after
  its initial 10 commits (`2ef5b8d3c`..`ebb6600db`) landed: doc corrections (`a3388bf1a`), an
  `/adversarial-review` (Kimi + Codex) fix round (`1ecfa6899`) that found and closed a real,
  previously-unwrapped forgery sink in `guard_registry.cpp`'s registry assertion values
  (`cfg_.expected`/`detected`, CDX-01/K5), and a full `/governance` 8-gate run afterward that
  found and closed two more sibling-field misses (`guard_registry.cpp`'s `cfg_.value_type`,
  `guaranteed_state_store.cpp`'s `agent_id`) plus a server-side push-builder gap: a legacy
  non-conforming `rule_id` was excluded from `apply_rules()`'s validation reach but NOT from
  `guardian_push_builder.cpp::build_agent_push`, so a single such row could wedge whole-push
  delivery to every agent in its scope with no server-side signal — now filtered out at the
  builder (`yuzu_guardian_push_rule_excluded_total{reason="invalid_rule_id"}`), matching the
  existing depth-guard exclusion pattern. `common/include/yuzu/log_token.hpp`
  gained `log_key_token()` (a path/service-name/
  registry-key/free-text neutraliser for a `'...'`-quoted log fragment - preserves spaces and
  non-ASCII bytes, unlike the pre-existing `log_id_token()`) and `is_valid_rule_id()` (the shared
  REST/MCP/agent-ingest validation predicate: non-empty, `[A-Za-z0-9._-]+`, <= 256 bytes). Every raw
  rule_id/key/path/hive/service-name/unit-name print site across the Guardian/Spark subsystem is now
  wrapped - the legacy file, registry and service guards; `SparkEngine`; the Guardian engine's arm,
  baseline and rule-parsing messages; the Spark runtime's own watched-key lines; the server's
  Guardian push enforce-downgrade warning; and the event store's own error lines - closing every
  category the operator manual referenced by the Compensating control field above used to list as
  still printing raw (`docs/user-manual/server-admin.md`'s Upgrade Notes, updated in the same
  series). `GuardianEngine::apply_rules()` now pre-validates every `rule_id` in a push and rejects the WHOLE push on the first
  invalid id, rather than silently dropping just that one rule while still advancing the generation.
  REST `POST /api/v1/guaranteed-state/rules` and MCP `create_guardian_rule` now enforce
  `is_valid_rule_id()` at create (400/error + an audit row on reject, previously empty-only and
  REST didn't audit the reject at all), with real JSON-Schema `pattern`/`maxLength` constraints, not
  prose alone. A separate, more subtle vulnerability the same review surfaced was closed alongside
  it: the R5.7 driver's (`fullsync_blackout_diag.py`) six evidence regexes used unanchored
  `.search()`, so a forged benchmark line embedded inside an unrelated log statement's free-text
  field (no newline needed) could be extracted as real evidence - all anchored to `.match()` now. A
  new regression-net tripwire (`tests/test_guardian_spark_log_injection_tripwire.py`) fails the
  build on any future unwrapped `spdlog::` call in this subsystem; it found 7 real sites the manual
  sweep missed on its first run, now also fixed. Windows-only code verified on real MSVC 19.44. No
  stored-data migration needed (fresh-build-only fleet; confirmed no production fleet exists yet).
  **A fourth round followed PR #4979's collaborator adversarial review (fjarvis, Codex+Kimi-K3
  panel, 2026-09-25):** a real BLOCKING finding — the push-builder exclusion fix from the third
  round, combined with `full_sync`'s unconditional teardown-and-rebuild-from-the-push semantics,
  meant a previously-armed legacy non-conforming rule was silently and permanently DISARMED on the
  next `full_sync`, not "frozen at its last-applied state" as that round's own doc text claimed
  (Codex empirically observed `full_sync cleared N prior rule(s)` on this exact path). Operator
  decision (Dave, mid-review): accept this as a deliberate **hard cutover**, not a migration — no
  preserve-and-re-arm mechanism was built. `docs/user-manual/upgrading.md` and
  `docs/user-manual/guaranteed-state.md` rewritten to state the true disarm behaviour and its
  pre-upgrade detection query honestly, and `apply_rules()`'s full_sync sweep now logs the
  disarm-in-progress explicitly (`Guardian: full_sync is disarming N rule(s)...`) rather than
  silently. Two further non-blocking findings from the same review also fixed: `guardian_routes.cpp`'s
  `note_platform_matrix_stale` used the weaker `log_safe()` helper (control-bytes-only) on a
  `k=v`-shaped line, missing the same same-line field-forgery threat this whole issue exists to
  close — switched to `audit_token()` (folds space/`=`/`,` too); and `guardian_engine.cpp`'s "failed
  spark validation" diagnostic printed `rule.spark().type()` (and, via `assertion.error()`, three
  more operator-authored fields from `guardian_spark_bridge.hpp`'s own error strings) raw — now
  wrapped at the sink with one `log_key_token()` call covering all four producers.
- Owner: fixed ahead of PR-5 by the author of the #4665 fix series, not deferred to the PR-5 (F14
  flip) author as this entry originally assumed.
- Milestone: #4665 itself - fix landed on `feat/4665-log-injection-neutralisation`; merge to `dev`
  still pending as of this entry.
- Revisit trigger: fired, and resolved. Criterion-10 sign-off and the F14 flip are no longer blocked
  by this entry once the branch above merges.

**#4685** (Guardian: Unsupported rules not re-reconciled after a File/Registry episode, #4658)
- Detection signal: none dedicated. The fleet query and the agent log below are hints, not proof,
  and no alert ships (last bullet).
  - Fleet (aggregate: the gauges are server-side sums and cannot name a host). The query below
    returns a series while `yuzu_fleet_spark_unsupported` for the mechanism is above zero and
    that mechanism's `yuzu_fleet_spark_mechanisms` series equals `yuzu_fleet_spark_reporting`
    (same `os` and `instance`), that is, rules stay unsupported although every reporting agent
    counts the mechanism as functional again:

    ```promql
    yuzu_fleet_spark_unsupported{os="windows",mechanism="file"} > 0
      and on(os, instance)
    (yuzu_fleet_spark_reporting{os="windows"}
      - on(os, instance) yuzu_fleet_spark_mechanisms{os="windows",mechanism="file"} == 0)
    ```

    The Registry form is a separate query with `mechanism="registry"` in both selectors. Both
    were checked with promtool against synthetic series only (the rules, the test and a
    flipped-expectation negative control are committed under
    `docs/spark-rebuild-baselines/raw/4658-windows-evidence/promql/`). Unlike the mechanism-gap recipe in
    `docs/user-manual/metrics.md`, this query is deliberately silent when the mechanism series is
    absent (an absent mechanism is not functional, so there is nothing recovered to be stuck).
    Blind spot: the query needs the two counts to be EQUAL, so a single agent that lacks the mechanism (a permanently boot-inert
    agent, or an unrelated concurrent episode) silences it fleet-wide; silence proves nothing
    while any agent lacks the mechanism. Only a sustained hold is a hint: the gauges trail the
    agent by up to about 45 s (`docs/user-manual/guaranteed-state.md`, "Fleet lag").
  - Agent log. The line
    `Guardian: rule '<id>' classified unsupported (<type> has no mechanism on this host) ...`
    (`guardian_engine.cpp`, logged only on a new or changed classification), between
    `spark_file: worker failing persistently` and
    `spark_file: worker pass recovered after N failure(s)` (Registry:
    `spark_registry: sweeper failing persistently` and
    `spark_registry: sweeper pass recovered after N failure(s)`), shows a rule was classified
    during the episode; it does not show the rule is still unsupported afterwards. Two limits:
    an empty search proves nothing because the agent log is not flushed per line (#4608), and
    the Guardian line and the `recovered` lines are logged at info level, so `--log-level warn`
    hides them (the `failing persistently` lines are error level).
  - Alerts. None ships: `docs/prometheus/yuzu-alerts.yml` deliberately has no
    `YuzuSparkUnsupported` rule and none on `yuzu_fleet_spark_mechanisms`. The per-mechanism
    alert is tracked in #2084 and must ship before the flip. An alert on the query above also
    wants the `for:` hold `docs/user-manual/metrics.md` gives for the mechanism series (at least
    two heartbeats, 60 s at the default 30 s heartbeat; a paging alert at least 10 minutes,
    tuned on fleet data).
- Operator action: none today (see the compensating control). Once Spark is live the gap does
  not announce itself: an Unsupported placement returns `ReconcileOutcome::Inert`, which by
  design does not hold `policy_generation` (`guardian_engine.cpp`, `apply_rules()`), so the
  agent reports itself converged and the server's heartbeat reconcile does not re-push
  (`agent_gen >= current`, `server.cpp`; see the recovery-path note in the
  `#2815 + #2818 + #2833 + #2839` entry above), and the Unsupported branch's own comment says
  `get_status()` is deliberately untouched; `get_status()` itself (`guardian_engine.cpp`) reports
  every stored rule as `errored` unconditionally, so it cannot tell this state from any other.
  After the mechanism has recovered, re-run the reconcile on the affected host, narrowest
  first: restart that agent (`start_local()` re-arms its cached rules through
  `reconcile_rule_locked`), or send the scoped push in `docs/user-manual/guaranteed-state.md`
  section 4 (`POST /api/v1/guaranteed-state/push` with a `scope` that selects only the affected
  hosts and `"full_sync": true`; requires `GuaranteedState:Push`). The fleet gauges cannot name a
  host and the agent log is the only per-host evidence, so an operator who cannot identify the
  affected hosts is left with the same push over a wider scope, at the cost below. Avoid the
  fleet-wide route (a
  Baseline deploy issues a fleet-wide `full_sync`, `guardian_routes.cpp`): a `full_sync` tears
  down and re-arms every rule on every in-scope agent (R5.7 (g)(1); its cost is the #3990
  blackout, `docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`) and re-classifies any
  host still in an episode. No further runbook exists: R5.7 (g)(1) and the operator manual say
  only that the rules stay disarmed until the next reconcile or an agent restart.
- Compensating control: `prefer_spark_` is false in production, so the Unsupported placement
  cannot occur today. `agent.cpp` constructs `GuardianEngine` with the two-argument form, so
  `prefer_spark` takes its default `false` (`guardian_engine.hpp`), and
  `GuardianEngine::reconcile_rule_locked` classifies only when
  `try_spark = prefer_spark_ && spark_availability_ == Available`. The gap is disclosed in R5.7
  (g)(1) of `docs/spark-stage2-guardian-consumer-design.md` and in the operator manual. `inert`
  is reached about 150 ms of backoff after the first failure at the default cadence (R5.7 (g)(4)),
  so once Spark is live an episode does not need to be long to open the window.
- **CONFIRMED and FIXED, branch `fix/4685-guardian-boot-inert-split` (not yet merged to `dev` as
  of this entry).** `SparkMechanismStats` gained an additive `boot_inert` field (declared after
  `inert` for designated-initializer order): TRUE only for the BOOT-TIME case (`start()` could not
  bind the mechanism's OS facility, every `watch()` refused), FALSE for a TRANSIENT
  runtime-degraded episode (Registry's sweeper / File's worker, three consecutive failed passes).
  `spark_file.cpp`/`spark_registry.cpp` split their single `inert_` atomic into `boot_inert_`
  (written only by `start()`) and `degraded_` (written only by the runtime worker/sweeper),
  deriving both `SparkMechanismStats` fields from one pair of local reads in `stats()`;
  `spark_service.cpp` (no runtime-inert concept) reports `.boot_inert` as the same atomic as
  `.inert`. `guardian_engine.cpp`'s `reconcile_rule_locked` now builds its capability set from
  `!ms.boot_inert` instead of `!ms.inert`, so a rule reconciled during a runtime-degraded episode
  Arms (the runtime reports it Committed, `subscription_establishment()` reports `coverage ==
  None` until the mechanism's next successful pass) instead of landing `Unsupported` - closing
  exactly the "nothing re-reconciles when `inert` clears" gap this entry's Detection
  signal/Operator action/Compensating control bullets above describe. The Unsupported branch's own
  log line now distinguishes the two remaining causes: `warn` for "registered but initialisation
  refused at start() (boot-inert)", the existing `info` for "no mechanism on this host at all" -
  `guardian_spark_bridge.hpp`'s `classify()` doc comment and `RulePlacement::Unsupported`'s own
  comment are rewritten to match (the pre-fix wording claimed the capability filter "mirrors the
  heartbeat's own inert-filtering exactly", which is now the defect this fix closes, not an
  accurate description). `boot_inert` stays agent-local only - it is never serialised onto the
  wire or into the heartbeat, so the fleet-level query and the promtool fixtures in this entry's
  Detection signal bullet remain accurate as a description of the REMAINING (boot-inert-only)
  case, and the per-mechanism alert this entry's Detection signal bullet says is missing (tracked
  in #2084) is still missing - this fix adds no new telemetry. Registry parity for every test.
- Owner: fixed ahead of PR-5 by the author of the #4685 fix series, not deferred to the PR-5 (F14
  flip) author as this entry originally assumed.
- Milestone: #4685 itself - fix landed on `fix/4685-guardian-boot-inert-split`; merge to `dev`
  still pending as of this entry.
- Revisit trigger: fired, and resolved. Criterion-10 sign-off and the F14 flip are no longer
  blocked by this entry once the branch above merges. What changed: the pre-fix "capability set
  keys off the UNION `inert`" defect (Detection signal/Operator action/Compensating control above)
  is fixed by the additive `boot_inert` split described in the paragraph above - a runtime-degraded
  episode no longer strands a rule `Unsupported` with nothing to re-reconcile it on recovery. The
  severity the #4658 governance ledger recorded (`gap-a-guardian-no-rereconcile`, LOW while
  `prefer_spark_` is false, HIGH and blocking at the F14 flip) no longer applies once this fix
  lands, since the wrong outcome it described can no longer occur regardless of `prefer_spark_`.

**Pulled out entirely, not risk-accepted here**: #2797's legacy-branch half (ruled 2026-09-02 to be tracked outside this plan) - a live
defect in currently-shipping legacy `IGuard` code, unrelated to whether the flip happens.
Needs its own fix + timeline, tracked separately. Only #2797's spark-branch half (fixed by PR
#3821) was ever flip-relevant.

## 6. `--spark-disable` rollback drill procedure

`--spark-disable` is the sole rollback lever (a standing ruling, not re-litigated here). It
is **boot-time, restart-required** - accepted with that limitation. **It does NOT fix #4252**
(the compliance-rollup double-count, §8/§1) - that defect is legacy-triggered, not
`prefer_spark`-dependent, so flipping this back does not correct a wrong fleet/by-baseline
`%compliant` figure caused by it; do not diagnose that symptom as a rollback failure. **Scope
note**: this
procedure is a UAT-drill spec, written against zero production fleet. It is single-agent
(one restart at a time) with no fleet-wide orchestration story - flipping this on N agents
during a real incident is N individual restarts, not covered here. Persistence across restarts
is the unit's `EnvironmentFile=-/etc/yuzu-agent/yuzu-agent.env` (#3851) - Linux/systemd
packages; Windows and macOS service configuration is outside this issue, tracked at #3973.
Treat this as the
drill procedure for evidence collection, not yet a production incident runbook. **Path note**:
deliberately `/etc/yuzu-agent/`, not the shared `/etc/yuzu/` - a co-installed `yuzu-server`
package re-asserts `/etc/yuzu` as `0750 yuzu:yuzu` on every install/upgrade, and that
different service account can unlink/replace a file inside it regardless of the file's own
mode; `/etc/yuzu-agent/` has no such collision.

1. Confirm current state: agent running with `prefer_spark` active, spark armed on at least one
   rule, drift/heartbeat evidence flowing (criterion 5's UAT smoke precondition).
2. Flip the flag - persist it, then restart.

   **On Rig B (the §8 drill rig, foreground)** - this is the drill path, run this on the
   shared box, not the systemd form below:
   ```bash
   YUZU_AGENT_SPARK_DISABLE=1 ./yuzu-agent ...
   ```

   **Production systemd form** (recorded here for the eventual incident runbook - do not run
   this against a shared or hands-off host):
   ```bash
   sudo mkdir -p -m 0750 /etc/yuzu-agent
   sudo touch /etc/yuzu-agent/yuzu-agent.env
   sudo chown root:root /etc/yuzu-agent/yuzu-agent.env
   sudo chmod 0600 /etc/yuzu-agent/yuzu-agent.env
   sudoedit /etc/yuzu-agent/yuzu-agent.env   # replace any existing content with exactly one line: YUZU_AGENT_SPARK_DISABLE=1
   sudo systemctl restart yuzu-agent
   ```
   Exactly one `YUZU_AGENT_SPARK_DISABLE=1` line - `sudoedit` opens existing content, so
   replace it rather than appending on a repeat drill run; no `export`, no shell syntax, no
   trailing inline comment (systemd's `EnvironmentFile=` parser does NOT strip a trailing
   `# ...` the way a shell would; the whole rest of the line becomes part of the value, which
   then fails CLI11 parsing at boot - see the recovery note below). An empty file (e.g. from
   `touch` with no `sudoedit` yet) behaves exactly like a missing one - both apply zero
   variables. Drop-in alternative: `sudo systemctl edit yuzu-agent` with `[Service]`
   `Environment=YUZU_AGENT_SPARK_DISABLE=1` (`EnvironmentFile=` overrides `Environment=` when
   both exist; an `ExecStart` override is unaffected, since the variable binds via
   `->envname`, and a CLI flag always wins over the environment). Roll-forward: remove the
   assignment and restart - not `=0` (works today, per CLI11's source, but the runbook
   shouldn't couple to that implementation detail). **Package-upgrade note**: an `.rpm`
   upgrade auto-restarts the unit (`%systemd_postun_with_restart`) and so picks up a pending
   env-file change on its own; a `.deb` upgrade only reloads the unit definition (`systemctl
   daemon-reload`) and does NOT restart the process - the env change stays pending until an
   explicit or otherwise-triggered restart. **Recovery from a malformed value**: a bad value
   (not a missing file - see above) fails CLI11 parsing at boot, and `Restart=always` +
   `StartLimitBurst=5`/`StartLimitIntervalSec=300` (top of this unit) will crash-loop the
   agent into `failed` state within ~50s. Fix or remove the offending line, then
   `sudo systemctl reset-failed yuzu-agent` before `restart` - a plain `restart` alone does
   NOT clear a `failed` state once the burst limit trips. The actual parse-error text is not
   in yuzu's own logs (it fires before yuzu logging initializes) - it's in
   `journalctl -u yuzu-agent`. Evidence it took - run the redirection inside the privileged
   shell, not the calling one:
   ```bash
   pid="$(systemctl show -p MainPID --value yuzu-agent)"
   sudo sh -c 'tr "\0" "\n" < "/proc/$1/environ" | grep -Fx "YUZU_AGENT_SPARK_DISABLE=1"' sh "$pid"
   ```
   (`systemctl show -p Environment` does not list `EnvironmentFile=`-sourced vars.) On Rig B
   (foreground, no systemd unit), substitute the shell's own PID for `MainPID`: `pid=$!`
   right after backgrounding the foreground command, or `pgrep -f yuzu-agent` if it's already
   running - `systemctl show` has no unit to query for a bare foreground process. The
   boot-time branch at `agent.cpp:1195–1197` short-circuits `SparkEngine` instantiation
   entirely when this is set - `spark_engine_` stays null, and the boot log records the
   literal string (note: an em dash, not a hyphen, at `agent.cpp:1196` - a plain-hyphen grep
   will not match it) `"SparkEngine: disabled by --spark-disable — not instantiated; Guardian
   detection path = legacy IGuard (enforcing)"`.
3. Confirm legacy enforcement resumed: the same-boot `wire_spark_engine()` call
   (`agent.cpp:1254`) records `SparkAvailability::SparkDisabled`, and the `SparkDisabled` case
   of the backend-derivation log switch (`:1269–1272`) reports `detection backend = legacy`
   regardless of `prefer_spark`'s compiled-in value - SparkDisabled always means legacy,
   unconditionally. Verify via the `yuzu.guardian_backend` heartbeat tag on the next beat.
4. Confirm no spark state leaks: both sub-checks follow directly from step 2's
   `spark_engine_` staying null - with no `SparkEngine` instance, there is nothing to hold an
   armed subscription and nothing to drain an outbox from, by construction, not by a separate
   runtime check. What IS an independent observable: `spark_running`/`spark_disabled` posture
   keys reflect the disabled state fleet-side.
5. Record the drill's timing (boot-to-legacy-enforcing latency) and any anomaly as this
   criterion's evidence (§2 criterion 5). **If legacy enforcement does NOT resume after the
   restart** (step 3's checks fail): this is not currently a documented failure path - escalate
   rather than retry silently, and treat it as a §5 risk-register candidate in its own right.

## 7. Post-flip programme order

**PR-5's own deliverable, before this programme starts**: `docs/user-manual/guaranteed-state.md:352`
already makes an operator-facing promise that spark's default posture is documented "ahead of
that flag flipping so a pilot's network monitoring is not surprised by it later; see Behaviour
changes (upgrading.md) for how you'll be told when that flag actually flips." PR-5 (the flip
itself) must close that loop: update `guaranteed-state.md`'s posture table, add the
`upgrading.md` Behaviour-changes entry, and add a `changelog.d` fragment - none of which are
named anywhere else in this doc's PR sequencing, and the promise is already live in a shipped
doc today, so it cannot be silently missed when PR-5 lands. **A second, separate deliverable,
added here so it isn't missed the same way (#4044's own resolution is recorded only in §1's
Sign-off cell and §8, neither of which this checklist otherwise references):** `guaranteed-
state.md:15`'s "Linux systemd service guard is still observe-only on the compliant edge" wording
must be edited in the SAME PR - scope it to the legacy guard and note spark's dormant parity fix
per #4044's RULED (a) - or PR-5 ships the flip while the doc still describes the pre-flip world
as current. **A third, conditional deliverable (enterprise-readiness, Gate 6):** if **#4252**
(the compliance-rollup double-count) is STILL OPEN when PR-5 ships, its `upgrading.md`
Behaviour-changes entry must also name #4252's operator-visible symptom - the fleet/by-baseline
`%compliant` figure over-counts `notimpl` for any Linux Service rule that already has a real
status row - and the workaround (the per-device drill-down is unaffected and stays accurate;
trust it over the aggregate for Linux Service until #4252 is fixed). Fleet-agnostic wording, not
pilot-only: any fleet with Linux Service rules and no prior drift history gets this as a FIRST
exposure at the flip, not a widening (§8's tenth-round paragraph). If #4252 is fixed before
PR-5 ships, this deliverable is moot and can be dropped. **A fourth deliverable (sre and chaos-injector, `/governance` on the #4606 benchmark
instrumentation), owned by the PR-5 author:** that change adds always-on `info`-level
`Guardian T_detect` / `Guardian T_wire` / `Guardian T_server` log lines. The server-side `T_server`
line and the agent's legacy drift-sink `T_wire` line are live today; `T_detect` and the Spark-outbox
`T_wire` line stay dormant until `prefer_spark`. They are benchmark diagnostics and have no kill
switch other than `--log-level`. The trigger is #4606 closing (the benchmark campaign concluding):
at that point, or no later than the PR-5 merge if that comes first, they must be retired or their
emission moved behind a bounded non-blocking hand-off; left unrecorded they ship into the flip as
permanent unconditional log volume. The retirement and the hand-off are tracked in #4666.

**NEW precondition for the F14 flip (added 2026-09-20, #4606 Gate 8 adjudication): synchronous
benchmark log writes on the detection and delivery threads must be gone or non-blocking before
`prefer_spark` goes true.** The lines are written synchronously: `T_detect` on the Spark consumer
thread (Event passes) and on the convergence lane and priority threads, and the Spark-outbox `T_wire`
on the detached send worker of its lane. The Spark runtime's own log lines are also synchronous writes
made while holding `registry_mu_` (for example the arm-committed line at every arm commit, and the
late-arm, sweep-residue, #4508, lifecycle-capacity and subscription-lost lines). They predate #4606 and
are not benchmark lines, so the same non-blocking requirement applies to them as a bounded hand-off,
not as retirement: the arm-committed line is the #3990 driver's measured contract and must stay. (The
architect adjudication below covered the `T_*` lines; the runtime lines are recorded here as the same
requirement and were not separately adjudicated.) Once Spark is live, a blocked log sink stalls
whichever of those is writing. The Gate 8 review of #4606 traced consequences that include a full
consumer queue dropping `SparkEvent`s and delayed subscription recovery (read from the code, not
reproduced), and the convergence lanes have no queue, drop or detach containment, so a fix has to cover
them and not only the consumer and send worker. Criterion: before the flip, retire the benchmark lines
or move their emission behind a bounded non-blocking hand-off, and move the Spark runtime's own lines
above behind one too; the arm-committed line is never retired. A default-off runtime flag is not sufficient by itself,
because the write is still synchronous whenever the flag is on. On the live legacy path the same
exposure is not new for `T_wire` on the guard worker (other `info` lines are already written on it),
but per the adjudication `T_server` is, at thread level: for a guardian-only agent stream it is the
first per-event `info` line in the Subscribe handler (which already writes an `info` line when a
stream opens, and one when a command completes inside its read loop). The architect Gate 8 reviewer
adjudicated ACCEPT-WITH-PRECONDITION: the live legacy path and the dormant Spark path each derive
MEDIUM for the #4606 diff, and a flip PR still carrying synchronous writes derives HIGH and is
BLOCKING. This precondition is tracked in #4666.

**Status update (2026-09-25): #4666 PR-1 and PR-2 have landed; the precondition above is
substantially addressed, with one residual gap flagged, not fully closed.** PR-1
(`agents/core/src/log_handoff.hpp/.cpp`, merged as #4970) built the bounded async log
hand-off primitive standalone, wired into nothing yet. PR-2 (`main.cpp`/`service_win.cpp`,
this doc's own #4666 references above) installs that primitive as the process's spdlog
default logger, so every bare `spdlog::` call anywhere in the process, including the
Spark runtime's own arm-committed/late-arm/sweep-residue lines and the `T_wire` line on
the legacy guard worker, now enqueues onto the bounded async queue and returns rather
than blocking on sink I/O, on Linux confirmed and Windows inferred (single spdlog
registry per process, measured directly on Linux via `tests/unit/test_log_handoff_multi_image.cpp`
and `tests/shell/test_spdlog_registry_identity.sh`). The two fixtures differ on Windows,
not agree: the shell probe has an explicit Windows leg that SKIPs outright, but the C++
fixture carries no platform gate and does run there — CI's `windows` job exercises the
same `--suite agent` binary — so its MI-1b topology verdict is written (Catch2 `WARN` +
a report file) on every Windows run; that output has simply not yet been pulled from a
CI log and reviewed to turn it into a confirmed finding, which is different from "no
Windows evidence exists." Absent that review, Windows single-registry status is still
only inferred from dynamic spdlog linkage, not confirmed. See `docs/darwin-compat.md`'s
"spdlog registry identity across images" row for the macOS result, now measured: TWO
separate registries there, with
the exe-image swap load-bearing on the teardown side only (install-side logging already
reaches the async hand-off correctly regardless, since `LogHandoff::install()` is compiled
into the core library). This is the mechanism the precondition asked for: it comes from installing
one process-wide default logger, not from touching each call site individually. What PR-2
does NOT do, despite an earlier PR-1-era header comment predicting it would: it adds no
`drain_log_bounded()` pre-abort breadcrumb calls inside `guardian_engine.cpp` or
`guardian_spark_runtime.hpp` (grep-confirmed absent as of this update). On inspection
neither file has its own `hard_exit()` call site that would need one; the only production
`hard_exit()`s near Guardian/Spark teardown are `main.cpp`'s and `service_win.cpp`'s own
F3 orphan-exit checks, and those ARE wired with a breadcrumb. The still-future `T_server`
piece (server-side, PR-4 in the #4666 ladder) is untouched by either PR-1 or PR-2 and
remains separately tracked.

**Precondition for criterion 10 sign-off and the F14 flip (added 2026-09-21, from the #4606
governance review of the rule-id neutralisation; SATISFIED 2026-09-24 by the #4665 fix landing on
`feat/4665-log-injection-neutralisation`, merge to `dev` still pending as of this entry): agent-side
`Guardian T_detect` and `T_wire` lines may be used as latency evidence only if either every
operator-authored identifier the agent logs is neutralised or rejected at one ingest chokepoint, or
the correlator takes its join set from the server-authored `T_server` line and drops any agent line
whose id is outside a benchmark-authored, charset-checked rule set.** Rule ids and Spark keys (which
embed an operator-authored path) were unvalidated, and many agent log lines still printed them as
authored, so a newline in an id let one forged physical line pose as a benchmark record; the R5.7
driver already reads agent-log lines. **#4665's own final scope turned out broader than this
paragraph originally named** - not just "the legacy file, registry and service guards ... SparkEngine;
the Guardian engine; nine Spark key sites in the runtime" (the Spark runtime's own rule-id lines
were already neutralised ahead of this, PR #4657), but every rule_id/key/path/hive/service-name/
unit-name print site across `guardian_engine.cpp`, `guardian_arm_ack.cpp`, `guardian_spark_bridge.hpp`,
`spark_engine.cpp`, `guardian_spark_runtime.cpp`, `spark_registry.cpp`, `spark_file.cpp`,
`spark_service.cpp`, `guard_file.cpp`, `guard_service.cpp`, `guard_systemd.cpp`, `guard_registry.cpp`
and `guardian_outbox_send_executor.hpp` on the agent, plus `guardian_push_builder.cpp` and
`guaranteed_state_store.cpp` on the server - closing the first branch of this precondition directly
(every operator-authored identifier is now neutralised at print time, and `rule_id` is additionally
rejected at REST/MCP create via `is_valid_rule_id()`). A separate, later-discovered vulnerability in
the SAME family was closed in the same series and was never part of this precondition's original
acceptance criteria: the R5.7 driver's own evidence regexes (`fullsync_blackout_diag.py`) were
unanchored (`.search()` not `.match()`), letting a forged benchmark line hide inside an unrelated log
statement's free-text field with no newline at all - now anchored. An agent-only latency figure may
now be presented as criterion-10 evidence; a regression-net tripwire
(`tests/test_guardian_spark_log_injection_tripwire.py`) guards against a future unwrapped call site
reopening the first branch. Tracked in #4665, which also covered the
documented-but-unenforced `rule_id` charset and pinning the arm-committed line's format for the
driver.

**NEW precondition for the F14 flip (added 2026-09-21, from the #4658 File worker governance run):
#4685 (Guardian rules classified Unsupported during a runtime-inert File or Registry episode are
not re-reconciled on recovery) is now SATISFIED - fixed on `fix/4685-guardian-boot-inert-split`
(the additive `boot_inert` field, `guardian_engine.cpp`'s capability filter narrowed to
`!boot_inert`); see its section 5 entry, now closed. The
per-mechanism fleet alert tracked in #2084 must ship before the flip as well; it is an episode
detector, not a stuck-state detector (its `for:` hold means it does not see an episode shorter than
the hold, and short episodes are the ones that leave rules stuck), and this entry tracks no alert
on the section 5 query. #4704 (a blocked log sink stalls the File worker or, worse, the Registry
sweeper's `mu_`) must be fixed or accepted as a limit before the flip as well, since the flip is
what makes these mechanism workers live.**

Two fault-injection scenarios designed at that governance run are also unowned and not yet run: a
slow or blocked log sink (on the live legacy path today, and with Spark live once `prefer_spark`
gives the Spark drain worker a live caller), and orphan attribution under outbox rejection or an
agent crash between enqueue and send. The related findings are ledgered in
`governance.d/4606-criterion10-instrumentation.uvwyxL.jsonl` (`4606-up1` through `4606-up6`,
`4606-sre-no-removal-plan` and the Gate 8 findings `4606-g8-*`).

1. **P3 - enforce cutover** (now includes #2233 item 8 as a prerequisite, ruled 2026-09-02 per
   §3 row 8). Runs
   immediately after the flip: the enforcement gap was accepted as temporary (§2 criterion 9) on the
   premise it stays temporary, and P11 has no fleet to observe yet.
2. **Hardening package 1** - #2469/#2278/#2279 (drain-death/retry-churn/poison-head), P11's own
   precondition, slots right after P3.
3. **P11 - alert chain** - #2335/#2336/#2337/#2339/#2083/#2389/#2390/#2415/#2416-runbook/#2417/
   #2418/#2338 + the CH-11 campaign + its 500-agent rig. #2336 (per-agent attribution) can start
   in parallel once P3 is staffed.
4. **P4 - health surface** - #3416 first (already has a compensating control, §5).
5. **Docs** (#2991/#3439/#2966/#3852) + test debt (the #3360/#3392/#2570/#2578 rows from §5).
6. **P5 - legacy deletion, LAST** - structural: `--spark-disable` boots legacy, so legacy code
   cannot be deleted before that lever is retired on its own separate timeline. Closes #2189 by
   deletion, not by fix.

Umbrellas #2299 ("PR-Ag lifecycle journal: perf + scale follow-ups"), #2300 ("... resilience +
test-coverage follow-ups"), #2453 ("Guardian journal: deferred findings from the #2299 O(work)
governance run"): several of §5's individually-named issues are plausibly their children, but
the umbrella numbers themselves are not cross-referenced from §5's rows. Close each umbrella as
its own children drain; do not treat §5 as already accounting for them by number.

## 8. Rig-assignment decision

Two dedicated parallel rigs on BigColin, run concurrently rather than serialized - verified
live capacity 2026-09-02: 16 cores, ~37 GB available RAM, 1.1 TB free disk (direct check, not
estimate).

| Rig | Purpose | Ports | Duration |
|---|---|---|---|
| **Rig A** | CH-5-UAT - holds the journal at the hard ceiling (2000 batches / 64 MiB) under KV-contention load | `8110` (HTTP) / `50061` (gRPC) | 4–7 days (long pole) |
| **Rig B** | UAT smoke (§2 criterion 5) + `--spark-disable` rollback drill (§6) | `8120` (HTTP) / `50071` (gRPC) | Shorter-lived |

Same port-pair shape as the existing dev-pair setup (`8090`/`8100`), just two more instances.
Each rig gets its own build dir, own local Postgres DB, own `kv_store.db`/journal path. Both
are well clear of the hands-off homeserver at `100.74.176.116:8080`/`:50051`
(Tailscale-bound - **never touch**; `start-UAT.sh`-style scripts default to those ports and
have killed it before).

**Contamination risk (not yet mitigated)**: Rig A's 4-7 day measurement window is the flip's
primary latency evidence source (once #3850's threshold is defined), sharing BigColin with the
hands-off homeserver, the existing dev-pair, and ad hoc build/CI-style load from other
sessions on the same box. A noisy neighbor during the measurement window inflates exactly the
metric the gate depends on, and no isolation (cgroup/`nice`) or concurrent-load recording
alongside samples is planned. Record this as a real gap before Rig A runs, not just a rig
capacity concern.

**Setup timing**: this is prep work, not started by this PR - begins once PR-2a/PR-2c are
close to merging (PR-2b is dropped per §3 row 5, confirmed by the operator 2026-09-02), i.e.
when this rig-dependent evidence-collection phase is actually about to begin. The capacity
numbers above are a 2026-09-02 point-in-time reading; re-verify immediately before
provisioning rather than trusting this reading weeks later.

**UPDATE (2026-09-04/05): Rig A actually ran on DGRHP (Windows), not BigColin.** BigColin's
attempt hit a platform blocker: File/Registry spark mechanisms are dead on Linux
(`spark_mechanism.hpp:25-31` - only Service registers there without libsystemd-dependent
support), so a Linux rig cannot exercise the same mechanism mix this gate needs. Moved to
DGRHP after checking coordination with a peer session already using that box. Actual duration
was one overnight exploratory pass, not the 4-7 days estimated in the table above - the "hold
at the hard ceiling" premise doesn't work mechanically under sustained load (§4's exploratory
findings), so the long-duration plan the table describes was never the right shape for what's
actually achievable; see §4 for what was measured and found instead. Cadence constants
(`kGuardianFileLaneCadenceMs`, `errored_refresh_ms`) were halved **locally on DGRHP for this
testing only, never committed or pushed**, to make the achievable regime reachable in one
night rather than several days - a testing-only acceleration, not a claim about production
cadence, and not evidence toward criterion 7 (resource evidence) at the halved rate. **Rig
debt, worth purging before the next evidence-gathering session on this rig (SRE, Gate 6,
2026-09-06)**: DGRHP still carries these halved constants AND thousands of leftover
load-test rules that rearm on every agent boot, producing large unrelated `drift.detected`
bursts (a `riga-reg-*` registry-rule burst measurably interfered with criterion 5's own
dashboard-fragment fetch - see §2). Neither is committed/pushed and neither blocks this PR,
but a successor session inheriting this rig without knowing about them will get confusing
readings the same way this one did.

**UPDATE (2026-09-05): Rig B's rollback drill ran, on BigColin as originally planned - correcting
the "has not been run yet" note above (it was already run and recorded in the rig's own logs
before this doc's first draft; not caught until re-verified this pass).** `--spark-disable`
restart confirmed legacy enforcement resumed in ~8.6s (`T0`→boot-log confirmation), followed by a
clean 14-hour run with zero spark-state leak observed. UAT smoke's arm-on-spark →
induced-drift → dashboard-edge sequence was attempted on Rig B too but blocked (Linux: no
sudo-free service-state flip, no `file-change` mechanism at all) and moved to DGRHP.

**UPDATE (2026-09-06): the induced-drift half is now ALSO DONE, on DGRHP.** See §2 criterion 5
for the full evidence (root cause of the prior login/logging blockers, the three-edit repro, the
`drift.detected` REST events, and the one-shot-watch/#2049-adjacent findings that came out of it).
Criterion 5 is fully green. Linux (Rig B / BigColin) remains structurally unable to exercise
`file-change` at all - that platform gap is unchanged.

**UPDATE (2026-09-06, later): the previously-optional Linux Service-type drift data point is
now also DONE, on Rig B/BigColin.** Dave authorized the scoped `NOPASSWD` sudoers grant
(`docs/agent-privilege-model.md`'s sudoers-construction pattern, narrowed to `dgr ALL=(root)
NOPASSWD: /usr/bin/systemctl stop yuzu-drift-test-dummy.service, /usr/bin/systemctl start
yuzu-drift-test-dummy.service` - a scratch no-op unit created for this test only, never a real
system service) and ran it himself since the assistant has no passwordless sudo on that box. The
unit file lives at the standard `/etc/systemd/system/` path, root:root-owned via `install`; both
the sudoers entry and the scratch unit were left in place after the test, narrowly scoped to
that one unit only. **Risk-accept entry, per §5's own convention rather than a bare aside**:
this is root-privilege config living on BigColin, Dave's own multi-session dev/rig box (a
different machine, and a different sharing model, from CLAUDE.md's "Big Tam"/"Wee Tam" CI
runner pools - a citation error in an earlier draft of this paragraph, corrected here) - not
equivalent to a scratch dir on a single-user Windows box (§8's own precedent for "left behind"
state elsewhere in this file) precisely because BigColin runs multiple concurrent dev sessions
and rigs day to day. Owner: Dave - he authorized and ran the grant, named here explicitly rather
than left as "unassigned." Detection signal: none (no expiry, no periodic audit of
`/etc/sudoers.d/`). Revisit trigger: before this box's next CI-relevant provisioning change, or
on a fixed schedule if one doesn't come sooner. Not filed as a GitHub issue - config-cleanup
debt, not a code defect - but recorded here as genuinely open, not resolved by "narrowly
scoped."

**Real, non-obvious blocker found and fixed along the way**: a freshly-created Guardian rule
does not arm just because it exists in the store - per CLAUDE.md's own Guardian invariant, a
**Baseline** is the deployable unit, and enforcement gates on `deployed_member_rule_ids()` from
a baseline's `deployed_snapshot`, not the live rule set. The new rule (`rigb-drift-test-dummy-
service`) sat silently un-armed through TWO agent restarts (confirmed via `Guardian engine
started (cached_rules=3, ...)` / `network-connected (..., rules=3)` never reflecting the 4th
rule) with no error via the REST create response or the agent logs - the signal an operator
debugging this WOULD find is on the dashboard itself: the Guards list shows an explicit
"not deployed" badge per rule, and the guard detail page says "not in a deployed Baseline"
(`guardian_routes.cpp`) - this session went straight to the logs/REST and didn't check there
first, so "no error anywhere" (an earlier draft's framing) overstated it. Creating the rule via
`POST /api/v1/guaranteed-state/rules` alone was never going to work regardless; it needed a new
Baseline (`POST /fragments/guardian/baselines` - no clean JSON API exists for baseline
create/deploy, HTMX-form-only, a known gap tracked at **#3266**, this session corroborated it)
containing it, then an explicit `.../deploy` call. Rig B's agent build for this whole test:
`0.13.1+7666 (7c3c7d3fa)` (`yuzu-agent --version`) - same commit as DGRHP's build earlier in
this section. Once deployed: `SparkEngine: armed 'service|29:yuzu-drift-test-dummy.service'`
confirmed via agent log, and a `guard.armed`/`guard.compliant` pair via REST at
`2026-09-06T15:44:39Z`: `{"event_type":"guard.compliant","guard_type":"service",
"detected_value":"running","expected_value":"running"}`. **This `guard.compliant` emission
itself is worth flagging**: `docs/user-manual/guaranteed-state.md` documents the LEGACY Linux
systemd service guard as "still observe-only on the compliant edge - it detects and reports
drift but does not yet emit `guard.compliant` or feed the census, so a compliant Linux service
reads as 'pending' until that parity gap closes." This rule ran the SPARK path instead
(`guardian_engine.cpp`'s `attach_rule` call passes `emit_compliant_edge=true` unconditionally,
not platform-gated the way the legacy guard is) - so this may be live evidence that spark's
Linux Service mechanism closes that documented legacy parity gap, not a discrepancy. Filed as
**#4044** to track the reconciliation (either update `guaranteed-state.md` to scope the
limitation to the legacy guard specifically, or confirm this emission is unintended) - a Gate 6
`sre` review of this same round found a real, currently-dormant consequence either way:
`guardian_routes.cpp`'s fleet and by-baseline compliance rollups don't guard against
double-counting a Linux rule that has a real status row AND still reads as platform-unsupported,
unlike the per-device drill-down, which already does; folded into #4044 rather than filed
separately, and #4044 was said here to be flagged there as gating the `prefer_spark` flip (F14),
following #3816's precedent - not resolved in this doc-only PR. (That attribution was itself
inaccurate, not just later-superseded: #4044's own issue body never actually said this -
`gh issue view 4044` carries no "F14", "gating", or "#3816" text.) **Superseded by the tenth round's own ruling
below: this "dormant"/"F14-gating" framing was itself wrong on both counts** - the bug is
CONFIRMED (not dormant, live today via legacy) and RULED non-gating (split to #4252, tracked
in §1's Sign-off row the same way as #4020/#4021, not following #3816's precedent after all).
`sudo -n systemctl
stop` (same second: `2026-09-06T15:45:06Z` for both the command and the resulting `drift.detected`
event) produced `{"event_type":"drift.detected","guard_type":"service","detected_value":
"stopped","expected_value":"running"}` - confirmed via REST AND the live dashboard fragment
(`GET /fragments/guardian/events?type=drift.detected` rendered this exact rule/event at the top
of the list, `.et-drift_detected` class, no ambiguity with another rule family this time).
Service manually restored via the same granted `systemctl start`, within seconds of the stop
(not separately timestamped - low stakes for a scratch no-op unit, but noted as the one link in
this chain without its own citation, unlike every other step above). Not Guardian remediation -
Linux service enforcement remains deferred/observe-only per `docs/os-capability-matrix.md`;
this test exercised detection only. This closes the gate doc's own explicit "genuinely
optional... not attempted here" deferral for the `service-status-change` mechanism specifically
(Rig B) - confirmed via REST AND a live dashboard-fragment fetch of THIS rule's own event,
unlike DGRHP's `file-change` mechanism (§2 criterion 5), where the dashboard fetch confirmed the
render path/mechanism live but caught a different rule's event, not `dgrhp-drift-test-file`'s
own row (that one was already pushed out of the fragment's top-20 window by the time it was
fetched). Both mechanisms have live, event-driven detection evidence; only Rig B's is also
dashboard-confirmed for its own specific event. Outbox pending count was not explicitly checked
before/after this specific test (unlike the DGRHP repro, which confirmed a clean 0-pending
window each time) - the same-second stop-to-`drift.detected` correlation is itself strong
evidence nothing stalled here, but this session doesn't claim to have positively ruled it out
the way DGRHP's did. **Scope note on #4044's eventual resolution**: if it resolves as "spark
correctly closes the legacy gap," `guaranteed-state.md`'s Linux-parity wording should NOT be
updated on that finding alone - per Gate 6 `enterprise-readiness`, the capability doesn't exist
for any real deployment until `prefer_spark` actually flips to `true` in production (PR-5), so
update that doc when the flip ships, not before. **Written before the double-counting finding
just above was split into its own issue (#4252, see the tenth round below) - that split doesn't
change this note's own scope**: this note is about the `guaranteed-state.md:15` wording only,
and #4252 is a separate code defect with its own disposition, not a second thing this note needs
to say anything about.

**#4044 RULED (2026-09-10, doc-only investigation PR): (a) - deliberate, not a bug.** The
original commit introducing the flag (`97ece94d0`, "2b per-type rule evaluators") states
outright: "emit_compliant_edge defaults true, unifying the compliant census signal across
platforms (legacy systemd was silent); the flag lets a caller keep legacy-exact silence,
pinned in parity tests." Both branches are unit-tested (`test_guardian_emit_decider.cpp`,
`test_guardian_rule_eval.cpp`, `test_guardian_spark_runtime.cpp` all pin the `false`/"systemd
parity" case) - production's `attach_rule` call site deliberately chose `true`. No enforcement-
readiness coupling found: `guaranteed_state_store.cpp`'s `event_state_from_type` maps
`guard.compliant` to a plain per-(agent,rule) status value; nothing downstream infers
enforcement-liveness from it, and enforcement-readiness (the Linux polkit gate) is orthogonal
to compliant-edge detection. (This is a distinct mechanism from #4252's `notimpl` fold, below -
that one keys off PLATFORM enforceability, not event type, and only adds to a rollup total, it
never reclassifies a compliant status as enforcement-backed - so the two don't contradict each
other despite both touching "Linux Service" and "compliance status" in the same breath.) No
per-rule double-counting from the legacy/spark mutual-exclusion
angle either: `reconcile_rule_locked` already guarantees at most one backend armed per rule
(CLAUDE.md-level invariant), and the census is a status *map*, not a counter, so a repeat
compliant edge after a backend re-arm just overwrites the same row. This independently
corroborates D4 in `docs/spark-legacy-delta-registry.md` ("Compliant-edge emission is unified
across types (a spark-side legacy-parity fix)," already verified `b16e5836d`), not new
information, just a second confirmation with the ruling now attached.
**Per the Scope note directly above, `guaranteed-state.md`'s wording is intentionally left
unchanged by this PR** - the doc-only edit scoping the observe-only limitation to legacy and
noting spark's dormant parity fix is deferred to PR-5 (the flip itself), not applied here.
**The Gate 6 `sre` double-counting finding above is CONFIRMED, not just a dormant risk, and is
split out to its own issue, #4252** - `guardian_enforced_on_platform()`
(`guardian_push_builder.cpp:87`) blanket-treats every guard type as Windows-only, but Service
arms on Linux (legacy AND spark); `guardian_routes.cpp`'s fold loop double-counts at BOTH the
fleet rollup (`:421-423`) AND the by-baseline rollup (`:1699-1703`, same unguarded shape, not
just the first site) - each adds a Linux Service rule with a real status row to `notimpl` on top
of its real bucket, and `StateRollup::total()` (`:261`) sums both additively - a live,
pre-existing defect (legacy's Linux `drift.detected` already triggers it in production today, no
`prefer_spark` needed), not gated on #4044 or the flip. Filed separately rather than folded into
#4044 because it doesn't depend on #4044's resolution either way. **#4252 is RULED non-gating**
for the flip itself, moved from §1's "flagged as gating F14" framing (now superseded, see the
ninth-round paragraph's correction above) to the "Non-gating but tracked" list alongside
#4020/#4021 in §1's Sign-off row - it is a pre-existing production defect unrelated to
`prefer_spark` (same class as those two). **This ruling has a real limit, not a blanket "already
broken so it doesn't matter" argument**: it holds for any fleet whose Linux Service rules have
already drifted at least once under legacy, which already carries the double-count today. It is
weaker for a fleet with NO drift history - compliant reads "pending" under legacy per #4044's
own subject, so that fleet's Linux Service rules own no status row yet, and the double-count
never fires for it pre-flip. Post-flip, `emit_compliant_edge=true` unconditionally gives every
such rule a real status row on arm, so for that fleet specifically the flip is this bug's FIRST
exposure, not a widening of an existing one - and a pilot fleet, PR-5's most likely first
audience, is exactly the kind of fleet likely to have a short or empty drift history. Widening
severity is not the same as flip-gating on its own, and nothing about `prefer_spark` needs to be
true for this bug to be real and fixable today - but this doc's own "no reason PR-5 must wait on
it" is this PR's judgment, not a binding one: PR-5's OWN Gate 2/4/6 pass must independently
derive TRIGGER/IMPACT/EXPOSURE against the diff it actually ships (a compliance-count defect on
a timer-driven, no-actor-required path plausibly derives HIGH under CLAUDE.md standing rule 2,
independent of this paragraph's argument) rather than treat this ruling as pre-empting that
derivation. If #4252 is still unfixed when PR-5's own governance runs, that pass decides for
itself, on its own diff, whether it gates - this doc records today's non-gating judgment, not a
waiver against tomorrow's.
**#4044 itself stays open** (not closed by this PR): the ruling is made, but its own action item
- the `guaranteed-state.md:15` edit - is scheduled for PR-5 per the Scope note (now also a named
§7 checklist item, so it isn't missed the way #2298-era criteria have been before), so closing
now would lose that forward pointer.

## Also closed out by this PR

### F2 / #2237 verify-only close-out

Checked the journal-authoritative retirement shape - the design ruling that made the lifecycle
journal, not the legacy in-process compliant-edge re-fire, the sole replay authority for outbox
delivery - for full conformance (not assumed from "substantially landed"). (This ruling itself
is recorded only in the delivery-plan draft this doc supersedes, not restated in any other
committed doc; the substance is inlined here rather than cited by a bare decision label.)

- **Sent-label written only after `Sent` on a batch's last entry** - confirmed at
  `guardian_engine.cpp:1429–1432` (drifted from an earlier `:1408–1414` citation, same content):
  `if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty() &&
  journal) journal->mark_batch_sent(e.journal_batch_key);`. **Conformant.**
- **Replay skips only sent-labelled batches** - confirmed at exactly
  `guardian_lifecycle_journal.cpp:1284–1285` (this citation did not drift), with a second,
  identical-shape check at `:1379–1380` for a different candidate set. **Conformant.**
- **Live-entry path (non-batched, no `journal_batch_key`) sent-label participation** - not
  previously checked; verified now. The wrapping comment at `guardian_engine.cpp:1420–1421`
  states explicitly: "Live / compliance / health entries carry no batch key → no-op." Confirmed
  by the guard condition above (`!e.journal_batch_key.empty()`) - a live entry's empty batch key
  means the `mark_batch_sent` branch never fires for it, by construction. This is deliberate, not
  an oversight: live entries were never part of the paged-batch journal in the first place, so
  they have no sent-label bookkeeping to conform to. **Conformant on this specific point.**
  **Stamp semantics themselves (how a live entry's `event_id`/timestamp are constructed vs. a
  replayed batch entry's, and whether the server dedups identically across both paths) were
  *not* examined this pass** - `guardian_spark_runtime.cpp`'s boot-nonce comment (~line 42,
  `make_boot_nonce()`) is the right starting point for that check, still open.

**Overall: F2/#2237's journal-authoritative sent-label write/skip/live-entry-participation shape is conformant**
for the three points checked above. Stamp-semantics equivalence is a separate, narrower claim
not yet examined and should not be read as covered by "conformant" here.

### #2298 sub-item confirmation

Checked, not assumed:

- **M1 sub-items 2/3** → **PR #3005** (merged 2026-08-11). Confirmed: implements 6b
  (errored-refresh backstop) and 6c (priority-lane demotion) - the two still-open items from
  #2298's "into-unknown flood" 3-part gate. PR's own text: "Closes #2298 items (a) and (b);
  item (c) (server-side rollup) remains open, tracked in the parent issue." **Confirmed closed.**
- **Sub-item 4 (suppressed rollup + real `/status.errored_rules`)** → **PR #3175** (merged
  2026-08-17). Confirmed: "M1 health-stream fleet gauge rollup; real
  `errored_rules`/`total_rules` on the guaranteed-state status routes (previously
  placeholder/approximate)." This is #2298 item (c), the piece #3005 left open. **Confirmed
  closed** - together, #3005 + #3175 close all of #2298's M1 checklist.
- **Item 5 (loss-table doc)** → **PR #2937** (merged 2026-08-10). Sol flagged this as the least
  self-evident of the three; looked closer. PR commits §25 of
  `docs/yuzu-guardian-design-v1.1.md` (loss-channel guarantee table) and the SOC2 data-inventory
  registration. **Confirmed closed for its stated scope**, but the PR's own body records 5
  items deliberately left open (not missed): two doc-truth disagreements between §25 and
  `docs/enterprise-readiness-soc2-first-customer.md:387`, a sign-off-status-not-in-repo gap, a
  consolidated risk-register residual, and the enterprise-readiness half of a pipeline-health
  signals gap. None of these block #2298's item 5 as scoped, but they are open follow-up debt;
  the §25 vs. SOC2-doc pair is now tracked as **#3852** and listed in the docs lane (§7).

### Item 10's doc-drift fix

Applied - see the accompanying diff to `docs/spark-stage2-guardian-consumer-design.md`. The
paragraph's rung 2/3/5 numbering is left as originally written (it's internally consistent
within that paragraph, and rewriting every occurrence risked introducing a new drift); a
single italic note now precedes it, mapping "rung 2" to impl-rung-7 and "rung 3"/"rung 5" to
P3/P5 in the current ladder, and pointing at this document for the live gate state.

### #4153 note (2026-09-08): two of row 9's three `[tsan-heavy]` checkpoints redesigned off SQLite

Dated addendum only - the row 9 / §5 evidence above (the local TSan build against real
`KvStore` I/O, the `1010s`/`never finished in 1200s` #4018 measurements, and the QE-1
discussion elsewhere in this document) describes what those tests WERE at the time it was
written and is left as historical record, not rewritten as if it had always used a fake store.

`test/4153-tsan-heavy-fake-store` (branch, not yet merged as of this note) introduces a
narrow `IJournalStore` interface (`kv_store.hpp`, implemented by `KvStore`) so
`GuardianLifecycleJournal` can be constructed against an in-memory `FakeJournalStore` test
double instead of a real on-disk `KvStore`. Two of the three `[tsan-heavy]` cases this row's
own text names - `"concurrent pagers + a drainer do not race (TSan checkpoint)"` and QE-1
`"concurrent persist + page + prune + drain do not race (TSan checkpoint, QE-1)"` - are
rewritten against that fake, with fixed per-thread iteration counts (a portable jthread-alike
- Apple Clang's libc++ lacks `std::jthread`/`std::stop_token`, so the tests use a hand-rolled
RAII thread + shared atomic-flag pair with the same join/cancel-on-unwind contract - and
`std::latch`-gated handshakes, plus bounded/stop-token-aware POLLING waits, not blocking
`std::atomic::wait`: an earlier attempt at a blocking wait/notify bridge was tried and
reverted, since `std::atomic<T>::wait(old)` re-blocks on a notify that doesn't change the
value) replacing the unbounded `while(!stop)` worker loops whose termination depended on the
main thread winning lock races against contended real SQLite access - the mechanism row 9's
own text and #2373/#2345/#4018 document as the cause of the CI stalls. One worker per test
remains a poll loop rather than a fixed iteration count -
the drainer loops `while (!<producers-done latch>.try_wait())` calling a bounded drain per
pass - because draining WHILE paging/pruning/persisting proceed is the concurrency property
these two tests are named for; a drainer that blocked until the latch released would remove
that overlap. This is not the retired pathology: every producer's work is finite, none of it
touches SQLite, and the loop's own progress never depends on winning a lock race (an
adversarial two-model review, 2026-09-08, converged on this after one reviewer initially
flagged the loop as a design contradiction). Both are retagged `[tsan]` and now run in every
build, not only sanitizer builds. The third case (`"...TSan checkpoint, #3848)"`, #3848's own liveness soak) is
UNCHANGED and remains the sole test still tagged `[tsan-heavy]` - row 9's characterisation of
it (SQLite-free, genuinely contention-dominated via a real backend deadline/watchdogs/releaser
pulse, a local-TSan-only signal) is still accurate and this note does not restate it.

This closes the test-infra half of #2373 (the CAUSE, not merely the symptom PR #4082's split
addressed) via #4153. It does not change anything about the PREFER_SPARK flip gate itself -
row 9's own criterion (a fresh rerun of the full TSan+shutdown+fault-injection matrix on the
flip tree) is still owed by PR-6, unaffected by which store backs these two checkpoints.
