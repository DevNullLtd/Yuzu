# F11 - flood measurement + token-bucket disposition, recorded run

Captured 2026-08-18, branch `feat/2298-f11-flood-measurement`. Initial measurement at
commit `fe69588ca`; **corrected after an adversarial review (Kimi + Codex, both
independently) found the original file-lane figure ignored production scheduler
jitter** - see "Adversarial review" below and the file-lane correction in Claims.
Authority: D1 ruling 2026-08-05 (port-lite: commit the harness, record
one worst-case run, replace the stale extrapolation) + `docs/adr/0021-spark-reflex-
architecture.md`. Companion doc: `stage11-resource-gate-runbook.md` (build/run
mechanics). Confirms/replaces the ~17k/day figure in
`docs/spark-stage2-guardian-consumer-design.md` (see that doc's 2026-08-18 superseding
addendum) and closes the D2 token-bucket disposition on the flip ladder
(`~/.claude/plans/carefully-look-at-the-frolicking-nova.md`).

## What was measured, and how

Two instruments, deliberately separated:

1. **THE NUMBER** - a committed, deterministic fake-clock Catch2 test
   (`tests/unit/test_guardian_spark_runtime.cpp`, cases prefixed `"F11 flood: ..."`) at
   PRODUCTION DEFAULT `GuardianSparkRuntime::Config` (no overrides): `errored_refresh_ms
   = 300'000`, `pending_demote_sweeps = 12`, `pending_demote_ms = 120'000`
   (`guardian_spark_runtime.hpp:162-184`); lane cadences `service_cadence_ms =
   registry_cadence_ms = 60'000`, `file_cadence_ms = 600'000`, `priority_poll_ms = 5'000`
   (`guardian_convergence_scheduler.hpp:68-75`). A test-driven clock advance per
   simulated scheduler tick stands in for `ConvergenceScheduler` itself, which received
   **zero code change** from F5 (`docs/spark-stage2-guardian-consumer-design.md`, the
   "zero scheduler code change" note - cite the symbol/anchor, not a line number,
   for exactly the reason this citation itself drifted once already: docs-writer
   caught it at line 312 during governance, 2026-08-18, having been 283-284 when
   written) - the real per-lane tick spacing is the scheduler's job, reproduced
   here by hand.
2. **A live DGRHP window** - spark forced active via a one-line, never-committed rig
   patch, real REST-armed errored load, real journal/outbox/heartbeat pipeline under
   wall clock. Confirms the pipeline moves the way the unit test says it should; it is
   **not** an independent measurement of the ceiling itself.

## Claims

At production Config defaults, once a never-Known rule is past demotion. **Scope note
(PR #3267 review, fjarvis):** the mechanism facts below (sweep count, refresh timing,
the 480s jitter-floor still refreshing) are literal Catch2 assertions, empirically
pinned. The daily-rate totals (288/day, 144/day, 180/day) are NOT themselves
assertions - no test asserts a per-day count - they are arithmetic derived from the
measured periods (`86,400s / period_s`): a derived bound, mechanism empirically
pinned.

- **60s-cadence lane (service/registry): 1 edge + 288 refreshes/rule/agent/day.**
  Demotion off the 5s priority lane completes in exactly 12 committed Convergence
  sweeps (60s wall time), well inside the 300s refresh floor - so demotion contributes
  zero wire messages of its own. Once on the 60s type-lane cadence, refresh recurs
  exactly every `errored_refresh_ms` (measured: first refresh lands at t=300s post-edge,
  keyed off the LAST emission, not re-armed by demotion); 300s divides 86,400s evenly
  86,400 / 300 = 288 times/day.
- **600s-cadence lane (file): 1 edge + 144 refreshes/rule/agent/day AT EXACT
  600s CADENCE (no scheduler jitter) - NOT the production ceiling; see the correction
  below.** Same demotion timing (the priority lane is type-agnostic). Once on the
  600s file-lane cadence, EVERY post-demotion sweep refreshes - the lane's own cadence
  (600s) already exceeds the 300s refresh floor, so there is no suppression window at
  all on this lane; rate = 1/lane_period = 86,400 / 600 = 144/day.
- **CORRECTION (2026-08-18, adversarial review - Kimi + Codex both found this
  independently): the true production file-lane ceiling is 1 edge + 180
  refreshes/rule/agent/day, not 144.** `ConvergenceScheduler::Config` defaults
  `jitter_pct=20` and `jittered()` draws a SYMMETRIC `base_ms + uniform(-span, +span)`
  perturbation (`guardian_convergence_scheduler.cpp:59-69`) - an earlier version of
  this doc claimed jitter "only ever pushes a sweep LATER, never earlier," which is
  flatly false; the draw is symmetric and CAN shorten the interval. The minimum
  possible file-lane sweep spacing is therefore `600s x (1-0.20) = 480s`; since 480s
  still exceeds the 300s `errored_refresh_ms` floor, every such sweep still refreshes
  (proven empirically, not just derived - see the fourth F11 Catch2 case, "file lane
  at the scheduler-jitter floor (480s)"), giving a true worst-case rate of
  `86,400 / 480 = 180/day`. The 60s-lane figure (288/day) is UNAFFECTED by this
  correction: it is bounded by the 300s refresh floor itself, not by sweep cadence, so
  shortening the already-sub-floor 60s lane's spacing changes nothing. **Use 180/day,
  not 144/day, as the file-lane production ceiling in any downstream citation
  (changelog, flip PR, fleet-ingest capacity planning).**
- Both corrected figures (288/day, 180/day) are **roughly 60-95x below the pre-fix
  ~17k/day** extrapolation in
  `docs/spark-stage2-guardian-consumer-design.md`'s "cutover-blocking finding (Fable
  M1)" section - see that doc's 2026-08-18 addendum for the corrected attribution:
  edge emission (`b30e93cfd`, 2026-07-20) already reduced the flood to zero
  steady-state before F5 shipped; F5 (PR #3005) then added the above nonzero ceiling
  back, deliberately, as a lost/coalesced-edge backstop.
- **Provenance - what's measured vs what's derived (corrected 2026-08-18, PR #3267
  review, fjarvis: the original wording here claimed the daily figures themselves were
  "the runtime's own measured output," which a grep for `288`/`180` against
  `test_guardian_spark_runtime.cpp`'s `CHECK`/`REQUIRE` lines disproves - neither
  appears in an assertion, only in comments and a test name):** the mechanism-level assertions - demotion completing in exactly
  12 committed sweeps, refresh recurring at exactly `errored_refresh_ms` after the last
  emission, the 480s jitter-floor sweep still refreshing - are the runtime's own
  measured output. The demotion-sweep-count assertion was verified red (a deliberately
  wrong pinned value, recorded below) before being set to the value the code actually
  produces. The daily-rate figures (288/day, 144/day, 180/day) are not themselves
  assertions - they are arithmetic derived from those measured periods
  (`86,400s / period_s`): a derived bound, mechanism empirically pinned, not an
  independently-measured daily count. A full `[spark][runtime]` tag run (91 cases /
  1620 assertions) passed clean on this branch's HEAD.

```
$ tests-build-agent-linux_x64/yuzu_agent_tests "F11*" --success
===============================================================================
All tests passed (39 assertions in 4 test cases)

$ tests-build-agent-linux_x64/yuzu_agent_tests "[spark][runtime]"
===============================================================================
All tests passed (1620 assertions in 91 test cases)
```

(Counts updated after the jitter-fix commit added a fourth `F11 flood:` case - re-run
verbatim against this branch's HEAD, not carried over from the pre-fix commit.)

Mutation-check (proves the assertions are not vacuous - a placeholder wrong value on
the demotion-sweep-count case, rebuilt and rerun):

```
F11 flood: production-default demotion completes in 12 sweeps @ 5s (60s) -
           before any refresh could fire (#2298)
../tests/unit/test_guardian_spark_runtime.cpp:1041: FAILED:
  CHECK( sweeps == 99 )
with expansion:
  12 == 99
```
- reverted to the correct assertion (`sweeps == 12`) immediately after, full tag rerun
green.

## D2 - file-lane token-bucket disposition

**Formally deferred to rung 5; measurement contradicts nothing.** No token bucket
exists in `guardian_convergence_scheduler.hpp` today - the code at :41-45 is a
deferral comment, not a mechanism:

> DEFERRED to rung 5 (where the real readers exist and there is a read cost to
> meter): size+mtime skip before re-hash, forced periodic full hash, and the
> file-lane byte token bucket. Against rung 4's fake instant reader there is
> nothing to budget, so wiring them here would be untested theatre; they live at
> the file StateReader / runtime boundary.

The measured post-demotion file-lane READ cadence (distinct from the wire cadence
above - `GuardianSparkRuntime::Config`'s own doc comment calls this out explicitly:
"the read flood, not the wire flood - errored_refresh_ms above already bounds the wire
side") is 1 read/600s/rule at steady state, once demoted off the 5s priority lane. That
is not a load a rate limiter would do anything useful against; nothing here motivates
building the bucket early. D2 stands as originally recommended (ladder plan,
2026-08-05): defer to rung 5, where a real file reader with a real read cost exists to
meter.

## Live DGRHP window

Rig-side patch (never committed - diff quoted here for the record, applied to
`/c/Users/daver/yuzu-pr3a` at pinned commit `0023efc33`, the same commit this
worktree's branch was cut from):

```diff
--- a/agents/core/src/agent.cpp
+++ b/agents/core/src/agent.cpp
@@ -717,7 +717,10 @@ public:
         // The engine persists rules into the KV store and answers __guard__
         // dispatches once the Subscribe stream is open. Construction is
         // safe even when KV failed to open (it degrades to in-memory only).
-        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
+        // F11 RIG PATCH - never commit. Forces spark active for the live
+        // flood-measurement window (docs/spark-rebuild-baselines/f11-flood-measurement-run.md).
+        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
+                                                     /*prefer_spark=*/true);
```

**Run executed 2026-08-18 on DGRHP.** Rig: `yuzu-pr3a` scratch worktree (detached at
`0023efc33`) + a throwaway `postgres:18` container on BigColin
(`100.74.176.116:5460`, removed after). Server and agent both ran locally on DGRHP
(loopback REST `:8080` / gRPC `:50051`), `--no-tls`/`--no-https`, seeded via the same
`yuzu-server.cfg` admin-user recipe `scripts/start-UAT.sh` uses.

**What was confirmed, with evidence:**
- **The agent boots and registers fine under `prefer_spark=true`.** An earlier
  same-session attempt looked hung (2 minutes with no new log lines, killed) - a
  controlled A/B against a rebuilt *unpatched* agent showed the SAME apparent pause
  (spdlog's file sink flushes in bursts, not per-line, so a quiet log window is not
  evidence of a stall by itself), and the retried patched agent registered
  successfully (confirmed via the `/fragments/devices/list` dashboard fragment) after
  ~4 minutes total boot-to-register. Not a defect - an artifact of an impatient first
  check, corrected before drawing any conclusion from it.
- **Spark activates.** Agent log: `SparkEngine started (0 spark(s) armed)` then
  `Guardian: spark path wired and available (consumer_id=1)`.
- **Found, in passing: a stale hardcoded log string.** The very next line,
  `Guardian: spark path WIRED (observe-only, prefer_spark=false); detection backend =
  legacy IGuard` (`agent.cpp:1115`), is a literal compile-time string, not a read of
  the actual `prefer_spark_`/backend state (`prefer_spark_` has no public getter -
  "deliberately not exposed" per `guardian_engine.hpp:189`) - so it now prints false
  information the first time this call site is ever exercised with `prefer_spark=true`
  in this codebase's history (rung 7.7a wires spark at boot but never with
  `prefer_spark_` true in any shipped build, per the routed-concerns Spark row). Minor
  (diagnostic text only, no functional effect), but worth a follow-up fix before F14
  ships this path for real - a boot log that lies about which detection backend is
  active is exactly the kind of thing an incident responder trusts.
- **The errored-load deny-ACL mechanics work as designed.** 20 deny-ACL files +
  20 deny-ACL HKLM registry keys created per the runbook's PowerShell recipe; read
  attempts AS the account actually running the agent (`daver`, an admin account on
  this rig - a `Deny Everyone` ACE blocks even an admin's ordinary read, verified
  empirically, not assumed) failed with `Access is denied` / `Requested registry
  access is not allowed` - exactly the Unknown-producing failure mode the errored
  profile needs.
- **The harness's `arm-errored` mode works end-to-end at the REST/server layer.**
  `generate_resgate_load.py arm-errored` reported `armed-errored 40/40 guards, pushed
  full_sync`; `GET /api/v1/guaranteed-state/rules` confirmed all 40 rows stored
  correctly (`os_target=windows`, correct `spec_json` paths/keys under
  `C:\YuzuResGateDenied\` and `HKLM\SOFTWARE\YuzuResGateDenied\`).

**What was NOT confirmed - a genuine gap, reported honestly rather than glossed
over:** the pushed rules never reached this agent's Guardian reconcile. Across two
`full_sync` pushes (the arm call's own, plus a manual re-push ~4 minutes into a stable
connection) and a combined ~5 minutes of polling both the agent's own log (zero
`attach_rule`/`reconcile`/`guard.unhealthy` lines - heartbeats and unrelated TAR/DEX
triggers kept firing normally throughout, so the process was not hung, just never
received the push) and the server's `/api/v1/guaranteed-state/status` route
(`errored_rules` stayed `0` throughout), no evidence surfaced that the 40 rules were
ever delivered to the agent side. Checked and ruled out as causes: OS-target mismatch
(rules say `windows`, agent reports `windows`, `os_target_matches` is case-insensitive
exact-match - fine) and scope-expression exclusion (`guardian_push_builder.cpp:119`:
an EMPTY `scope_expr`, which every generated rule has, skips the `in_scope` check
entirely - matches every agent by construction, not a targeting gap). Root cause not
isolated within the time budget spent on it - **UPDATE 2026-08-18 (re-run session):
the original guess below ("something specific to this throwaway rig") was WRONG, not
just incomplete - see forward action item 4 for the actual root causes found on
re-investigation, one of which (a dispatch kill-switch defect) is a genuine product
bug, not a rig artifact.** ~~most likely something specific to this throwaway
single-box rig's setup (a fresh admin/agent pairing with no management-group
assignment, or a push-dispatch precondition this run didn't satisfy) rather than a
product defect, given the REST/storage layer and the deny-ACL mechanics both worked
correctly in isolation.~~ **This gap does not affect the Claims section above** - that
section is entirely function of the committed Catch2 test, not this live run.
Flagged as a forward action item (below), not silently dropped.

Rig-side patch reverted, deny-ACL artifacts removed, agent/server processes stopped,
throwaway Postgres container removed. Nothing from this window was committed.

## Does NOT claim

- **No legacy-vs-spark resource A/B.** That gate stays blocked on the flip's
  `--spark-disable`, per `stage11-resource-gate-runbook.md`'s "Why not now" - this doc
  makes no resource-footprint claim (threads/handles/RSS/CPU/wakeups) of any kind.
- **No server-side ingest-cost claim.** The wire-message counts above are per-rule,
  per-agent, agent-side emission counts. What that costs a real Postgres-backed server
  at fleet scale (insert transaction cost, `guaranteed_state_store` row growth) is not
  measured here.
- **No fleet-aggregate claim.** The figures are per-rule-per-agent and linear in rule
  count (each rule tracks its own `last_unhealthy_emit`/demotion state independently,
  confirmed by the existing F5 "two rules sharing one key each refresh independently"
  test) - a fleet total is rule_count x agent_count x the per-rule daily figure, not
  measured directly at any scale here.
- **No claim about the service lane's errored path.** Per
  `agents/core/src/guardian_state_reader.cpp`, `ERROR_SERVICE_DOES_NOT_EXIST` resolves
  to `read_known(Stopped)`, not Unknown - a nonexistent service cannot enter the
  errored/flood path this doc measures at all. The service lane shares the
  registry lane's 60s cadence, so no coverage is lost by this omission, but no
  service-specific number was captured (there is nothing to capture).
- **Jitter IS now accounted for (corrected 2026-08-18, see the Claims section).** An
  earlier version of this bullet claimed jitter only stretches inter-sweep spacing
  later, never earlier - that was wrong: `jittered()`'s perturbation is symmetric
  (`base_ms + uniform(-span, +span)`), so it can shorten spacing too. 288/day (60s
  lanes) is unaffected - it is bounded by the 300s refresh floor regardless of sweep
  cadence. 180/day (file lane, corrected from the no-jitter 144/day) IS the honest
  ceiling once the symmetric jitter is accounted for, per the fourth Catch2 case.
- **No claim about the pre-demotion (0-60s) window's read cost**, only its (zero) wire
  cost. 12 priority-lane reads at 5s cadence happen regardless of lane; this doc only
  characterizes what reaches the wire.

## Adversarial review

Kimi + Codex, two-phase independent review + cross-examination, run 2026-08-18 against
this branch before push. Both converged on BLOCK. Verified findings, fixed in this
branch:

- **HIGH, found independently by both:** the file-lane "144/day" figure was presented
  as a production ceiling, but the doc's own "jitter only pushes sweeps later, never
  earlier" claim was false - `ConvergenceScheduler::jittered()` is symmetric. Fixed:
  a fourth Catch2 case (`tests/unit/test_guardian_spark_runtime.cpp`) empirically
  proves the jitter-floor (480s) case still refreshes every sweep, giving a true
  worst-case of 180/day; every doc/changelog citation of "144/day" as a ceiling is
  corrected to 180/day (144/day now stated only as the exact-no-jitter figure).
- **HIGH (Codex) / MEDIUM (Kimi), confirmed by both:** `resource_sampler.cpp` leaked
  the process `HANDLE` if `_wfopen_s` failed to open the output file (the acquire at
  `OpenProcess` preceded the fallible file-open, with `CloseHandle` only at the very
  end). Fixed: output-file open now happens before `OpenProcess`, so that failure
  path never holds an unreleased handle.
- **LOW, confirmed by both:** the runbook's 30-minute sanity-window table said "~5
  refreshes" without noting the inclusive t=1800s boundary can land a 6th, and didn't
  account for jitter on the file-lane count. Fixed: reworded.
- **LOW (Kimi only, rejected by Codex on cross-exam) - REOPENED AND CORRECTED
  post-adversarial-review, during full `/governance`:** `guardian-c0-thread-reloc-
  design.md`'s item 7/9 resolutions recorded an operator ruling ("2000/64 MiB is
  stale text") without a paired code change. Both Kimi and Codex, and my own
  synthesis, accepted the premise that no code change was needed because "the
  shipped caps already matched the derivation." **That premise was wrong.**
  Governance's `architect` reviewer found `hard_max_batches_`/`hard_max_bytes_`
  (`guardian_lifecycle_journal.hpp:682-683`) - a real, actively-enforced
  write-capacity ceiling at exactly 2000/64 MiB, shipped BEFORE the doc text this
  branch dismissed as stale, and already described correctly elsewhere in the
  same doc (item 12: "the 2x-headroom hard ceiling"). The original ruling was
  itself the error; both the adversarial review and my own first-pass synthesis
  missed it because neither actually grepped for a `hard_max_*` constant before
  accepting "no code to change" as settled. Item 7/9 reverted to the original
  (correct) 2000/64 MiB hard-ceiling instruction - see
  `guardian-c0-thread-reloc-design.md` item 7's 2026-08-18 correction note for
  the full chronology. **Lesson for future adversarial/governance runs on this
  branch's pattern:** "no code changed, so the doc-only ruling can't be
  independently verified" is not the same as "the ruling is therefore
  unfalsifiable" - a ruling ABOUT existing code is still checkable by reading the
  code, even when the PR itself doesn't touch it.
- **Withdrawn by both (already tracked, out of this branch's scope):** the
  `agent.cpp:1115` hardcoded log string - this branch doesn't touch `agent.cpp`;
  stays forward action item 3 below.

Full transcripts: Kimi/Codex phase1+phase2 reports and this synthesis are not
committed (adversarial-review workflow output, not repo content) - reproducible via
`/adversarial-review` against this branch if needed again.

## PR review (fjarvis, #3267)

External review, CHANGES_REQUESTED, two BLOCKING findings - both verified accurate
against this branch before fixing:

- **RAII policy floor applied incompletely to `resource_sampler.cpp`.** The
  governance-driven RAII pass (Gate 3, 2026-08-18) wrapped `hproc`/`out` but left
  `try_enable_debug_privilege()`'s `token` and `thread_count_for_pid()`'s `snap` on
  manual `CloseHandle`. Confirmed via grep before fixing. Fixed: `token` now uses the
  existing `UniqueProcessHandle` (its `nullptr` failure-sentinel convention matches
  `OpenProcessToken`); `snap` needed a distinct wrapper (`UniqueSnapshotHandle`) since
  `CreateToolhelp32Snapshot` fails with `INVALID_HANDLE_VALUE`, not `nullptr` -
  reusing `UniqueProcessHandle` there would have called `CloseHandle` on the sentinel
  itself on the failure path.
- **Overclaiming: the daily-rate figures were presented as measured, not derived.**
  Confirmed via grep (`288`/`180` never appear on a `CHECK`/`REQUIRE` line in
  `test_guardian_spark_runtime.cpp` - only in comments and one test name) and via a
  stale cross-reference (this doc's own transcript block already showed the correct
  91 cases/1620 assertions while a prose line above it still said "90 cases / 1610").
  Fixed: the Claims section intro, the "Provenance - what's measured vs what's
  derived" paragraph, and the ready-to-paste changelog sentence below now distinguish
  the empirically-pinned
  mechanism (sweep count, refresh timing, the jitter-floor case) from the arithmetic-
  derived daily totals - fjarvis's suggested framing, "derived bound, mechanism
  empirically pinned," adopted verbatim.

`resource_sampler.cpp`'s fix compiled clean on DGRHP (MSVC 19.44.35227, `cl.exe /EHsc
/std:c++20 /W4`, per `stage11-resource-gate-runbook.md` Step 1) - no warnings, no
diagnostics for either changed function. Stated here rather than left implicit: this
file is Windows-only and not meson-wired, so it is never CI-compiled - this was a
one-off manual verification of this specific fix, not a standing check.

## Ready-to-paste F14 flip-changelog sentence

> Guardian's `guard.unhealthy` wire traffic for a stuck-Unknown rule is bounded at
> 1 edge + 288 refreshes/rule/agent/day on 60s-cadence lanes (service/registry) and
> 1 edge + 180/day on the 600s file lane, accounting for the scheduler's default
> +/-20% jitter (mechanism empirically pinned, daily rate derived from it -
> `docs/spark-rebuild-baselines/f11-flood-measurement-run.md`),
> roughly 60-95x below an earlier ~17k/day
> pre-mitigation estimate.

## Forward action items

1. **F14's A/B** (legacy vs spark resource footprint) still needs the flip's
   `--spark-disable` - this doc's harness (`resource_sampler.cpp` +
   `generate_resgate_load.py`'s original `arm`/`teardown` profile) is ready to fire the
   moment that lands; see `stage11-resource-gate-runbook.md`.
2. **Server-side ingest cost** at the measured wire rate is unmeasured - worth a
   companion note (or its own doc) once a fleet-scale server test rig exists, if the
   #2298 checklist or an enterprise-readiness gate asks for it.
2b. **Filed #3266** (governance Gate 6, enterprise-readiness): Guardian Baseline
    create/deploy/delete has no JSON REST route - dashboard-fragment-only, which is
    why `generate_resgate_load.py`'s Baseline helpers have to scrape HTML rather than
    parse structured JSON. Out of F11's scope to fix; tracked separately.
3. **Fix the stale `prefer_spark=false` / `detection backend = legacy IGuard` boot log
   text** at `agent.cpp:1115` - it hardcodes both facts as literals rather than reading
   `guardian_`'s actual state, and is now demonstrably wrong once `prefer_spark=true`
   is ever exercised (found live this run). Wording-only, no functional effect - a
   small fix, but worth landing before F14 ships this path for real, since it is
   exactly the log line an incident responder would trust post-flip.
4. **RESOLVED IN PART, 2026-08-18 (re-run session) - the root cause is diagnosed, but
   push delivery is STILL NOT confirmed working.** The suspected cause was `arm-errored`
   never creating or deploying a Baseline for its 40 rules - `guardian_push_fn_`
   (`server/core/src/server.cpp:~17601-17640`) filters every push through
   `filter_deployed_members()`, so a rule outside any deployed Baseline is silently
   dropped. Fixed in `generate_resgate_load.py` (commit `a086d9cca`, this branch):
   `arm-errored` now creates + deploys a fixed-name Baseline covering all 40 rules;
   `teardown-errored` deletes it first. **Verified correct, twice, against a real
   server:** `POST /fragments/guardian/baselines` + `POST .../deploy` produced a
   `deployed` Baseline with all 40 Guards (confirmed via `GET
   /fragments/guardian/baselines`), matching the existing
   `test_guardian_routes.cpp` "deploy_baseline marks deployed ... and pushes
   fleet-wide" case (real Postgres, 29/29 assertions) which independently proves the
   underlying mechanism. **This fix is real and necessary, but re-running the live
   capture with it still did not deliver anything to the agent** - two SEPARATE,
   previously-unknown issues were found blocking delivery independently of the
   Baseline gate, neither of which is F11-scoped to fix:
   - **A genuine, high-severity dispatch defect (found this session, needs its own
     issue + urgent triage - NOT fixed here):** `finalize_classified_command`'s
     kill-switch gate (`server/core/src/agent_registry.hpp:280-299`) calls
     `PluginConfigStore::action_allowed(cap.plugin, cap.action)`, which calls
     `plugin_config::parse_kill_switch_scope("__guard__", "push_rules")`
     (`server/core/src/plugin_config_parsers.hpp:153-158`), which calls
     `is_valid_identifier("__guard__")` (`plugin_config_parsers.hpp:44-55`) - and
     that function requires the first character to be `a`-`z`. `__guard__` starts
     with `_`, so the scope NEVER parses, and an unparseable scope is fail-closed to
     "not allowed" (`plugin_config_store.cpp:478-479`) regardless of any row in the
     `kill_switches` table (confirmed empty on this rig - the table was never the
     issue). Net effect: **every** `__guard__:push_rules` dispatch - both call sites
     (`server.cpp:4234`, `server.cpp:17711`) - is unconditionally treated as
     kill-switched and silently dropped, with no error surfaced to the REST caller
     (`POST /api/v1/guaranteed-state/push` returns `202 {"queued":true,"agents":0}`,
     which reads as success). Confirmed live: `dispatch denied:
     __guard__:push_rules reason=kill_switched caller=system` fired on every push
     attempt this session, both before and after the Baseline fix. This is NOT
     specific to this rig or to F11's errored-load profile - it is the SAME
     `guardian_push_fn_` every real deployment's Baseline-deploy/enforcement-toggle
     path uses, and the existing unit test that exercises `deploy_baseline` never
     catches it because `TestRouteSink`'s harness stubs `push_fn_` directly, never
     routing through the real `command_dispatch_fn`/kill-switch chokepoint (the same
     class of test-vs-production gap the routed-concerns table already warns about
     for `TestRouteSink`). Whether this is reachable in a real (non-throwaway)
     deployment, or whether some other code path avoids `is_valid_identifier` for
     `__guard__` specifically, was NOT further investigated here - that determination,
     and the fix, belong to a dedicated issue, not this branch.
   - **A separate, lower-severity Windows/loopback bug (also found this session, also
     not fixed here):** connecting the test agent via `--server localhost:50051`
     resolved to IPv6 `::1` on this box, and the gRPC peer string this build produced
     was `ipv6:%5B::1%5D:PORT` - percent-encoded brackets, not literal `[`/`]`
     (confirmed via the `session.peer_mismatch` audit rows' `raw_peer` field).
     `extract_peer_ip` (`server/core/src/peer_ip.hpp:129-155`) requires a literal `[`
     immediately after `ipv6:`, so it returned empty for both the Register and
     Subscribe peer, which always fails the peer-binding check
     (`agent_service_impl.cpp:894`) and rejects every Subscribe attempt
     ("peer mismatch", `register_ip=`, `subscribe_ip=`, both empty). Switching the
     agent to an explicit `--server 127.0.0.1:50051` (forcing IPv4) worked around it -
     the Subscribe stream opened successfully after a few retries.

     **NOT a new bug - this is issue #1791**, filed against a macOS repro of the exact
     same symptom (`raw_peer=ipv6:%5B::1%5D:<port>`, empty `register_ip`/`subscribe_ip`,
     same IPv4 workaround) and already fully root-caused there: gRPC >= 1.49
     percent-encodes `[`/`]` in peer strings per RFC 3986, `extract_peer_ip`
     (`server/core/src/peer_ip.hpp:129-155`) only handles the literal-bracket form, and
     the existing unit tests only cover pre-1.49 unencoded vectors. This DGRHP
     occurrence is added as corroborating evidence there (comment 2026-08-18) -
     confirms the defect is genuinely cross-platform (any OS resolving loopback to
     IPv6 first on an affected gRPC version), not macOS-specific as the issue title
     implies. No new issue filed; see #1791 for the fix's acceptance criteria.
   - **With both worked around** (agent forced to IPv4; the kill-switch issue has no
     workaround short of a code fix, so this was NOT resolved) **delivery still did
     not happen**: a fresh `full_sync` push after the Subscribe stream opened
     returned `{"agents":0}`, and the agent log shows zero `attach_rule`/reconcile/
     `guard.unhealthy` lines across its entire run. The kill-switch defect is the
     most likely full explanation - `agents:0` in the push response is consistent
     with the dispatch being denied before ever counting a target.
   - Rig left clean: `teardown-errored` run (all 40 rules + the Baseline deleted,
     confirmed via subsequent 404s and "no baseline found"), deny-ACL files removed
     (the HKLM key resisted removal via both `Remove-Item` and `reg delete /f` -
     a pre-existing PowerShell/Windows registry-provider quirk unrelated to this
     work, matching the runbook's own accepted "clean up by hand" posture - left as
     a known leftover), rig-side patch reverted (`git diff` empty on `yuzu-pr3a`,
     restored to `0023efc33`), agent + server processes stopped, the throwaway
     `yuzu-f11-rerun-pg` Postgres container removed.
   - **Forward: a fresh rig session cannot close this on its own anymore** - the
     dispatch kill-switch defect needs an actual code fix (and review) before any
     live Guardian push, F11-related or not, can be expected to deliver anywhere.
     **Filed as #3265** (`bug`/`P0`/`reliability`/`ready-for-agent`) - fix it, THEN
     re-attempt this live capture. Not shipped in any release (the regressing
     commit is on `origin/dev` only, in no tag), so no released Yuzu build is
     affected today - but any pilot/dev-rig on dev, or a future release cut before
     #3265 lands, would be (governance Gate 6, enterprise-readiness, 2026-08-18).
5. Re-verify the F5 config defaults cited here (`errored_refresh_ms`,
   `pending_demote_sweeps`, `pending_demote_ms`) have not changed before reusing these
   numbers in a later doc - they are cited by value, not by reference, in the "Claims"
   section above, and a future retune would silently stale this doc exactly the way F5
   staled the ~17k/day figure. Item 6 below is the same protection for the scheduler's
   own jitter defaults.
6. **Considered and declined: a `jittered()` bounds test** (governance Gate 3,
   `quality-engineer` finding) - `ConvergenceScheduler::jittered()` is private with no
   test hook, so pinning its output bounds would need a new test-only accessor added
   to production `guardian_convergence_scheduler.hpp`. Declined as disproportionate
   for a SHOULD-not-blocking finding: the actual 480s-floor claim this run doc makes
   is already empirically verified by the fourth F11 Catch2 case, which drives the
   real `GuardianSparkRuntime` at that exact interval - what's undefended is only a
   FUTURE `jitter_pct`/`file_cadence_ms` retune silently staling the daily-rate
   arithmetic, which is the same class of risk item 5 above already names. Revisit if
   either constant is ever retuned.
