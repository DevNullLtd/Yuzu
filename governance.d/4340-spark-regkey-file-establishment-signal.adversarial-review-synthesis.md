## Review — approving (no CRITICAL/HIGH)

Two independent external reviewers (Kimi K3 trusted-dynamic, Codex Sol reasoning-high), each
compiling and testing in its own isolated worktree, both reached **PASS** on issue #4340
(Registry/File establishment-readiness signal, `a9984d565..2b057527b`, 5 commits). The
catastrophic ADR-0021 invariant — the new `established_` sink is called exactly once per TU,
always from `run_off_lock` with `mu_` released, never synchronously from `watch()`/
`unwatch()`/`on_fire()` — was independently verified by both via `rg -n "established_\\("` and
holds cleanly. Both judgment calls the implementing agent made under uncertainty (the RF-10
test pivot to the synthetic resync emit; leaving `docs/spark-legacy-delta-registry.md`
untouched) were checked against the actual code/doc and UPHELD by both reviewers. Three LOW
findings survive, converged after cross-examination (Codex downgraded its two from MEDIUM in
Phase 2), all independently re-verified against source by the synthesizer below.

### Minor

**File's published-pending branch never marks an initial `None` — plan §3 row F5 not
implemented.** `agents/core/src/spark_file.cpp:966-977` (the "still outstanding past the
caller budget" else-branch) stores `w->call`/`resync` fields but never calls
`mark_coverage_locked`; Registry's structurally identical branch does, at
`spark_registry.cpp:857` (`mark_coverage_locked(*w, SparkCoverage::None);`). Confirmed by
direct read of both branches — real, reproducible deviation from the plan's own transition
table (§3 F5: "Marks N"). Non-blocking because `SparkEngine`'s armed-entry cache defaults to
`SparkCoverage::None` and first-wins latches only on `Notification`
(`spark_engine.cpp:2011-2012`), so the only existing consumer (`subscription_establishment()`)
already reads the right answer either way, and no production caller exists. A direct
mechanism-level sink observer (as RF-10/FF-10 use) would see the gap. Fix: one line,
`mark_coverage_locked(*w, SparkCoverage::None);` in the branch, mirroring Registry. Found
independently by both reviewers.

**RF-10/FF-10 pin cross-batch establishment ordering, not the within-pass `established`-
before-`emit` rule §1.8 states.** `run_off_lock` genuinely dispatches `work.established`
before `work.actions` in the same pass (confirmed by reading the dispatch loops,
`spark_registry.cpp:1611-1619` / `spark_file.cpp:2553-2562`) — production behavior is correct
today. But RF-10's own construction (`tests/unit/test_spark_mechanism.cpp:5007-5108`) parks
the re-arm probe with `ProbeGate` specifically so the `None` report and the synthetic emit
land in *different* sweep passes; a hypothetical future swap of the two dispatch loops would
still pass this test, since same-pass ordering is never exercised. Kimi grades this a residual
the plan's own §5 mutation checklist silently accepted; Codex holds it's a real, if narrow,
gap against §1.8's and RF-10's own stated intent (the docstring literally says "the same fire
batch"). I side with Codex's framing but both agree LOW/non-blocking: it's a missing hardening
test, not a shipped defect. Optional fix: an ordered single-collector log across both emit and
established callbacks, plus a loop-swap mutation.

**Consumer design doc states a mechanically impossible timing.**
`docs/spark-stage2-guardian-consumer-design.md:1219` says Registry's flap `None` and the
re-arm's `Notification` "can land in the same sweep pass." Verified false by reading the
actual sequencing: `spark_registry.cpp:1490-1504` drains and clears the `due` marker *before*
the visit's `switch` at `:1505`; `commit_locked` (`:1326`) re-marks `Notification` due only
after that drain, and `next_wake_locked` (`:1384-1395`) schedules the newly-due marker for the
very next pass — not the current one. So for the single-flap cycle the sentence describes, the
two reports are structurally guaranteed to land on *consecutive* passes, never the same one.
The sentence's practical conclusion (a pull query can miss the transient `None`) still holds
via back-to-back-pass proximity — only the stated mechanism is wrong. Notably, the delivery
plan's own §10 hand-off note contains the identical wrong phrasing ("can land in one sweep
pass") — the doc update in commit 5 inherited it verbatim rather than independently. Fix:
"land on consecutive sweep passes and may be too close together for a pull query to observe
the transient `None`."

### Adjudication

No unresolved severity disagreement: Codex's two Phase-1 MEDIUM grades (the File F5 omission
and the RF-10 ordering gap) were both self-downgraded to LOW in its own Phase 2 after weighing
the same mitigations Kimi cited in Phase 1 (engine-cache masking, zero production consumers) —
both reviewers converge at LOW on all three findings. I re-derived all three directly against
source in this synthesis (cited lines above) rather than taking either report's word for it;
all three hold up exactly as described. The RF-10 framing disagreement (residual-accepted-by-
plan vs. real-gap-against-stated-intent) is a difference of emphasis, not fact — both concede
it's LOW and optional to fix.

One thing worth flagging to the plan's owner rather than to code review: the "same sweep pass"
error didn't originate in the doc commit — it's copied from the delivery plan's own §10, so the
same wording should probably be corrected there too if that plan file is kept as a durable
reference (it currently is, per Dave's decision to keep the companion flip-gate doc local-only,
though that's a separate file from this one).

### Empiricism

**Kimi** (K3, trusted-dynamic, real unsandboxed shell, its own worktree
`/home/dgr/advrev-spark-4340/tree-kimi`): Linux compile clean (8 targets relinked);
`meson test -C build-linux --suite agent --print-errorlogs` Ok 2/Fail 0 (108s);
`./build-linux/tests/yuzu_agent_tests '[established]'` 140 assertions/15 cases pass
(engine-level only — Windows RF/FF compiled out on Linux); `git diff --check` clean. Did not
attempt DGRHP. Both phases genuinely dynamic (no static-fallback warning in either run log).

**Codex** (Sol, reasoning high, `workspace-write`, its own worktree
`/home/dgr/advrev-spark-4340/tree-codex`): Linux compile clean; full agent suite 3456/3466
(8 skipped, 2 unrelated host-environment failures — `/proc/net/dev` zero-traffic and a
missing-account passwd lookup — not reproduced on Kimi's run, judged host noise);
`[spark]`-tag 656/657 passed, 15,817 assertions; `[established]` subset matches Kimi's;
`git diff --check` clean. Attempted DGRHP, blocked by its sandbox's network policy
(`Operation not permitted`) — did not create or touch any DGRHP worktree.

**Windows/MSVC runtime remains unwitnessed by both reviewers** — the implementing agent's
DGRHP self-report (0 errors across 5 commits; 254+368 `[established]` assertions; mutation
checklists 5/5 and 4/4 red-then-green) was checked for internal consistency only: both
reviewers independently confirmed the Windows case-count arithmetic is coherent with the
actual test file's structure (Kimi: Linux's 15 engine-level `[established]` cases plus 10 new
Windows-only cases = 25 for commit 2, +10 more = 35 for commit 4, matching exactly), and that
the broader-than-predicted wake-mutation failures are consistent with where the `due→now`
clause is load-bearing. Neither reviewer contradicts the DGRHP claims; neither independently
reran them. This is the one gap worth closing before merge if an independent Windows pass is
wanted — DGRHP is reachable (`ssh dgrhp`) but both reviewer sandboxes on this box block
outbound SSH.

No CI exists for this branch (local, not yet a PR).
