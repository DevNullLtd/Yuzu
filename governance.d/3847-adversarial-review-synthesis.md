# Adversarial review synthesis — #2233 item 4 / #3847 (fe9920de9)

Panel: **Claude** (empirical - Agent subagent, isolated context, ran the affected test tags on
`build-linux` and a rebuilt `build-tsan`, two seeds) + **Codex** (empirical - `codex exec`,
`workspace-write` sandbox, ran `[send_executor]` and the full `meson test --suite agent` legacy
suite). Both reviewed independently in Phase 1, then cross-examined each other's findings in
Phase 2. Orchestrator (Claude, this session) adjudicated disagreements and wrote this synthesis.

## Verdict: PASS — no CRITICAL/HIGH in either reviewer's set after cross-examination.

Not fabricated: both reviewers independently traced all four previously-fixed BLOCKING defects
(bookkeeping-write ordering, orphan-reclaim wedge, cross-lane starvation/UP-1, bad_alloc-before-try)
through the current code and confirmed each is correctly fixed, not merely claimed fixed. The
orphan-exit contract (`active_io_workers()` → `hard_exit.hpp`) was independently traced end-to-end
by Claude with no TOCTOU found in the outer join-vs-poll question. Four non-blocking findings
survived cross-examination, all confirmed by at least one reviewer with independent code-read
verification.

### Confirmed findings (both reviewers reached the same code independently, or one + adjudicated)

| ID | Finding | Severity | Provenance | Anchor | Disposition |
|---|---|---|---|---|---|
| C1 (codex) / F3 (claude, adopted) | `GuardianOutboxSendExecutor::offer()` releases `state_->mu` after deciding `need_launch=true` but before calling `launch()`; `launch()` never re-checks `state_->stopping`. A concurrent `GuardianOutboxDrainWorker::stop()` can therefore set `stopping=true` in the gap, and a new detached send is admitted anyway. Both reviewers independently confirmed reachability (distinct threads: the drain loop is the sole `offer()`/`launch()` caller; `stop()` runs on the caller's own thread and joins the loop thread). Consequence is bounded: `AliveTicket` increments `worker_count` before `spawn_detached()`, so the orphan-exit sum is never fooled — `stop()`'s subsequent `thread_.join()` correctly waits out the newly-admitted send. Not a UAF, not an unjoined thread, not a data race (a logical TOCTOU across two independently-locked sections — TSan does not and would not flag it). Worst case: one avoidable extra send admitted during shutdown, which only matters if it *also* independently stalls for the full orphan-drain grace window, on a code path that is compile-time dormant in production today (`prefer_spark_=false`). | LOW (both reviewers); ledger `severity_mapped` reclassified I5→I8/LOW at Gate 8 re-review (consistency-auditor) — bounded and orphan-exit-accounted, structurally closer to `p1-spawn-detached-bad-alloc-miscounted` than an unavailability finding in its own right, now matching both reviewers' native LOW | static-read (both); TSan clean (Claude only — orthogonal, wouldn't catch this class anyway) | `docs/cpp-conventions.md` concurrency conventions (judgment - no MUST/never clause on this exact promise); orphan-exit contract itself (`.claude/routed-concerns.md` Spark row) is NOT violated | **Fixed, operator-directed, at the `GuardianOutboxSendExecutor`/`launch()` level only** — see the scope caveat below. `launch()` now re-checks `state_->stopping` under `state_->mu` as the first statement inside its locked bookkeeping block, before any bookkeeping is published — synchronized against `stop()` via the SAME mutex, closing the window by construction (happens-before via one shared lock), not by narrowing a timing window. Codex's own concern (no test seam existed to make this deterministic) was addressed by adding a minimal test-only hook (`set_pre_launch_race_hook_for_test`, matching the established `*_hook_for_test_` pattern already used in `spark_engine.hpp`) that fires in the exact real race window and lets a test reproduce the interleave via direct call ordering on one thread, not by racing real threads. Mutation-verified RED (revert the one-line recheck → the new regression test fails at exactly the two assertions it protects: `result == Retain` and `invocations == 0`) then GREEN. Full `[guardian]` tag clean (377 cases, was 376) on `build-linux`; TSan clean on `[guardian]~[death]` (376 cases, zero races) on a rebuilt `build-tsan`. **Scope caveat found by unhappy-path at Gate 8 re-review of this fix**: the same admission-race SHAPE recurs one call frame further out, in `GuardianOutboxDrainWorker::stop()` itself, which sets its own `stopping` flag and then calls the two lane executors' `.stop()` as separate, non-atomic steps — a window exists where the drain loop's `should_stop()` reads false while a given lane's executor hasn't been told to stop yet, so THIS fix's synchronization doesn't extend to that outer gap. Bounded the same way (orphan-exit contract, compile-time-dormant path), not verified with a test seam (`epistemic_status: likely`), NOT fixed by this commit. Ledger: `p4-drainworker-stop-not-atomic-across-lanes`, `deferred-to-issue #3953`. |
| C2 (codex) / F4 (claude, adopted) | `changelog.d/3847-outbox-send-executor-detach.fixed.md` claimed the per-lane executor split means "a slow lifecycle send cannot silently delay compliance/health delivery either" — but the same PR's own code comments (`guardian_outbox_drain_worker.hpp`, `guardian_outbox_send_executor.hpp`) explicitly disclaim that the two lanes still contend on `agent.cpp`'s `stream_write_mu_`, so wall-clock delivery is not actually isolated, only the *admission* (whether compliance is ever attempted at all) is. | LOW / truth-nuance under CLAUDE.md Standing Rule 3 | static-read (both) | CLAUDE.md Standing Rule 3 (a comment/prose claim contradicted by the PR's own code is a truth finding, not wording-only) | **Fixed** — changelog fragment reworded to say the per-lane slots ensure the compliance/health attempt is admitted promptly, while shared-stream contention is unchanged and out of scope. |
| C3 (codex, confirmed after being pointed to claude's F1) | `docs/spark-flip-gate.md` §3 row 4 states governance findings are "recorded here in full," but the raw ledger (`governance.d/3847-outbox-send-executor.rGvKq2.jsonl`) contains three additional deferred LOW/INFO findings (`p2-orphan-exception-silently-discarded`, `p3-domain-log-invariant-convention-only`, `p3-up11-cross-lane-wire-reordering`) not narrated in the row. Found first by claude (F1) in Phase 1; codex did not raise it independently in its own Phase 1 pass, but re-verified it against the code/ledger itself during Phase 2 cross-examination rather than taking claude's word for it. | LOW / judgment | static-read (both, at Phase 2 for codex) | judgment (no MUST/never clause requires row 4 to mirror the ledger exhaustively) | **Fixed** — row 4 now scopes the "in full" claim to BLOCKING/SHOULD findings and points explicitly to the ledger (and this synthesis doc) for LOW/INFO residuals. |
| F2 (claude) | The orchestrator's pre-review framing (`TARGET.md`) described an "already disclosed" ~1-in-15 intermittent test failure from earlier hardening rounds; neither reviewer could locate it recorded anywhere in the branch's committed docs, commit messages, or governance ledger — it existed only in an earlier session's conversation transcript, never committed. Codex disputed this as a PR finding (`false-positive/unfair`) on the grounds that grading disclosed risk doesn't require branch provenance; the orchestrator adjudicates that both are right about different things — it is correctly *not* a code defect (codex), but it correctly identifies a real documentation gap (claude): an operationally-relevant caveat existed only in conversation, not in any durable artifact. | Informational | static-read (claude); disputed as PR-scope (codex) | N/A | **Adjudicated: valid catch, not a code defect.** Action: state the flake explicitly in the PR body (not a ledger row — it was never reproduced with a captured test name, so there is nothing concrete to track as an issue yet). |

### Reviewer asymmetries worth recording

- **Sanitizer coverage is single-reviewer.** Codex's Phase 1 ran no TSan/ASan/UBSan (`b_sanitize=[]`
  in its own RAN line). Claude rebuilt the (stale-relative-to-latest-comment-edits, not
  stale-relative-to-logic) `build-tsan` binary and ran it twice with different seeds, zero races.
  Codex adopted Claude's TSan runs as corroboration rather than re-running them itself.
- **Codex's full-suite run hit 7 unrelated failures** (`meson test --suite agent`) it attributed to
  `/tmp` being ~80% full during that run, affecting unrelated `CommandDedupStore`/`KvStore` fixtures,
  not the `[send_executor]`/`[drain]` tests this PR touches. Re-checked post-review: `/tmp` on this
  box is at 37% (`tmpfs 31G, 12G used, 20G avail`) — the constraint, if real, was transient and is not
  reproducing now. Not corroborated as a cause of the separately-observed ~1-in-15 flake (F2) but
  noted as a plausible contributing hypothesis, not a confirmed one.
- **Platform coverage.** Both reviewers ran Linux only (no Windows/macOS toolchain available in
  either sandbox) — consistent with this PR's own governance history, which was likewise Linux-only
  (no Windows-risk surface in a pure concurrency-primitive change per `docs/windows-build.md`'s own
  triggering criteria).

### What each reviewer ran
- Claude: `ninja -C build-linux tests/yuzu_agent_tests tests/yuzu_server_tests` (incremental, no
  work); `[drain],[send_executor],[reconcile]` and full `[guardian]` tag (4120 assertions/376 cases,
  including the forked-child death test) on `build-linux`, clean; rebuilt `build-tsan`'s
  `yuzu_agent_tests` and ran `[drain],[send_executor],[reconcile]~[death]` twice with different
  random seeds (2242 assertions/118 cases both times), zero TSan warnings.
- Codex: offline `meson compile -C build-linux tests/yuzu_agent_tests` (no work);
  `./build-linux/tests/yuzu_agent_tests '[send_executor]'` (5 cases, 29 assertions) PASS;
  `meson test --suite agent` (full legacy suite) — 7 failures attributed to `/tmp` pressure on
  unrelated fixtures, re-ran the new/changed cases in isolation and got green; no sanitizer build.

Full Phase 1/Phase 2 transcripts: `/tmp/yuzu-advrev-3847-item4/{claude,codex}.phase{1,2}.md`
(scratch, not committed).

## Gate 8 governance round on the C1/F3 fix itself (commit `483d0cee9`)

The TOCTOU fix is itself a real logic change (not docs/comments), so it went through a fresh
targeted Gate 8 pass rather than being pushed straight through: `cpp-safety` + `cpp-expert` +
`security-guardian` (mandatory per the Guardian routed-concerns row, unconditional on any
`guardian_*` file change) all PASS, no BLOCKING — independently re-derived the happens-before
argument for the fix rather than trusting the commit description, and independently
mutation-tested it. Two small comment-accuracy fixes were folded in from that pass (the same
"another thread" vs. "this same thread" wording error, caught convergently by both cpp-safety
and cpp-expert).

A second, broader round then re-ran the gates the fix diff's DOMAIN touches per CLAUDE.md's Gate
8 rule (docs-writer is unconditionally triggered by the same routed-concerns row; Gate 4's
happy-path/unhappy-path/consistency-auditor trio is marked mandatory in the pipeline; sre was
re-run because it holds two open findings against this exact class). All five: **PASS, no
BLOCKING**. Findings folded in:
- docs-writer + consistency-auditor (converging independently): `docs/test-coverage.md`'s row
  for `test_guardian_outbox_send_executor.cpp` was stale (the same defect class already fixed
  once for this file, `p1-test-coverage-doc-stale`) — fixed.
- docs-writer: two in-code wording nits (a "governance's adversarial-review" vs. "the
  adversarial-review pass's" attribution slip; "neither internal governance round" undercounting
  the actual three internal rounds) — fixed.
- consistency-auditor: `severity_mapped` on two of the four new `adv-*` ledger rows
  (`adv-codex-c2-changelog-overclaim`, `adv-claude-f1-ledger-completeness`) was native vocabulary
  (`LOW`) copied straight into the derived-band field instead of the value their own recorded
  `impact:["I9"]`/`exposure:["E3"]` actually derives (`INFO`, matching every other `I9` row in
  this ledger) — fixed. Also flagged (and accepted): `adv-codex-c1-toctou`'s `impact` was
  arguably `I5` when the bounded, orphan-exit-accounted consequence fits `I8` better — corrected,
  see the C1/F3 row above.
- unhappy-path: `launch()`'s own doc comment still said it "returns false only if the OS refused
  to create the thread," not updated for the new second return-false reason — fixed. More
  substantively, unhappy-path found a real, NOT-previously-identified residual: the same
  admission-race shape recurs one call frame further out, in `GuardianOutboxDrainWorker::stop()`'s
  own non-atomic shutdown of its `stopping` flag versus its two lane executors' `.stop()` calls —
  see the scope caveat on the C1/F3 row above and ledger row
  `p4-drainworker-stop-not-atomic-across-lanes`. Not fixed in this round; recorded as a fresh,
  separate operator decision rather than folded in unilaterally under the same time budget that
  already produced two "built, then reverted after breaking a test" optimizations earlier in this
  PR's history.
- sre: confirmed no interaction with its two open findings (`p2-offer-timeout-throughput-cliff`,
  `p2-no-stall-observability`) — see the issue-filing section below for their disposition.
  Confirmed the fix strictly *improves* shutdown latency and orphan-worker pressure for the race
  it closes (no wait incurred, no worker spawned) and does not introduce a new observability gap
  (the refusal folds into an already-uncounted sibling condition on a path `stop()`'s sticky
  one-shot contract makes unobservable in production regardless). One wording nit ("retry next
  tick" was imprecise for the stop-won-the-race arm, since no next tick follows — it's
  next-boot replay) — fixed.

## Gate 6 closure — compliance-officer + enterprise-readiness (operator-requested)

The original three internal governance rounds ran the full 8-gate pipeline, including
compliance-officer and enterprise-readiness — but neither had re-run against the TOCTOU fix
(`483d0cee9`) or its own Gate 8 follow-up (`2e2416b97`) specifically. Run at the operator's
explicit request to close that gap rather than leave it silently unaddressed. Both: **PASS, no
BLOCKING**.

- **enterprise-readiness**: confirmed empirically (not from the changelog fragment's own
  framing) that `prefer_spark_` is genuinely compile-time-fixed false in production — the only
  `GuardianEngine` constructor's sole production call site (`agent.cpp:835`) uses the 2-arg
  form, no CLI/config/env surface feeds it — and that the new test-only hook has zero
  production footprint (only caller anywhere in the tree is the test file; `offer()` itself is
  unreachable at today's default). One INFO finding: `docs/spark-flip-gate.md` row 4's
  ledger-completeness pointer said "three deferred LOW/INFO findings," now stale at four with
  `p4`'s addition — same staleness class the doc was fixed for once already (C3 above). Folded
  into the row-4 rewrite below.
- **compliance-officer**: verified by direct code read (not assumed) that an entry refused by
  the TOCTOU fix's `stopping` re-check stays durable in the outbox log for next-boot replay,
  same as any other `Retain` — the fix is a small audit-trail integrity improvement, not a new
  risk. Two evidence-hygiene findings on the governance ledger itself, both derived INFO,
  non-blocking: (1) the four `adv-*` rows added by `483d0cee9` all carried an impossible
  `recorded_at` (~55 minutes after the commit that recorded them, evidently local BST
  mislabelled `Z`); three were silently corrected by `2e2416b97` without the commit message
  mentioning it, one (`adv-claude-f2-flake-provenance`) was missed — the missed one is now
  fixed, and this synthesis doc records the correction explicitly (this paragraph) rather than
  leaving it to reverse-engineering. (2) `"deferred, issue not yet filed"` is not a value in
  `.claude/skills/governance/SKILL.md`'s documented disposition enum (`open` / `fixed` /
  `deferred-to-issue #N` / `roadmap-#N` / `linked-to-#N` / `split` / `re-cut` / `rejected` /
  `refuted`) — six rows in this ledger carried it. Resolved below, not left open.

## Issue filing — closing the six deferred residuals' disposition gap

Per the operator's decision ("I agree to defer and file"), filed
**Tr3kkR/Yuzu#3953** — a single consolidated issue (precedent #2148-#2156: a deliberate
consolidation over one code neighborhood, enumerating each fold-in) covering all six deferred
LOW/INFO residuals in this ledger: `p2-orphan-exception-silently-discarded`,
`p2-no-stall-observability`, `p2-offer-timeout-throughput-cliff`,
`p3-domain-log-invariant-convention-only`, `p3-up11-cross-lane-wire-reordering`, and
`p4-drainworker-stop-not-atomic-across-lanes`. Dedupe probes (all empty): `gh issue list
--search "guardian_outbox_send_executor"`, `gh search issues "outbox send executor stall"`,
`gh search issues "drain worker stop race"`. All six ledger rows' `disposition` updated from
`deferred, issue not yet filed` to `deferred-to-issue #3953`, now a conforming enum value.
`docs/spark-flip-gate.md` row 4's pointer rewritten to reference #3953 directly instead of
enumerating a count that would otherwise need updating every time this neighborhood accrues
another residual.
