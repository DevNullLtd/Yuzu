# Phase 2 — kimi cross-examination

Target: ci/2373-4018-tsan-heavy-split @ e330b0522. Peer: codex.

## 1. Cross-examination of PEER findings

| PEER-ID | label | evidence I checked | my severity |
|---|---|---|---|
| C1 | confirmed-independently | nightly.yml:630 `if: failure() || (always() && inputs.jobs == 'windows-asan')`; adjacent comment :626-628 itself states "a 90-minute job-level timeout is a CANCEL, not a failure, and that's exactly when the progress log matters most"; grep confirms sibling failure-path uploads in the SAME file already use `failure() \|\| cancelled()` (nightly.yml:384, :421), and this change's own snapshot step uses it (:618). On a scheduled/default-all run (inputs.jobs null) that is cancelled, failure() is false and the artifact is skipped. | LOW (agree) |

C1 severity adjudication: agree with LOW. It is a diagnostic gap, not a correctness failure in the split: the meson per-test budget (600s × 2 = 20 min for the heavy entry; 240s×2 for fast entries) normally converts a stall into a `failure()` well inside the 90-min job window, so `failure()` covers the realistic recurrence path; the residual hole is cancellations with origin outside meson's timeouts (build hang, runner preemption, job-level timeout from earlier slow steps). Codex's own mitigations support LOW, and the fix is a one-line `|| cancelled()`.

Codex's RAN reports two failures in `meson test --suite agent` (`test_passwd_lookup.cpp:200`, `test_net_quality_sampler.cpp:152`) — I note these are machine-state-dependent tests untouched by this diff (my direct `./tests/yuzu_agent_tests` runs passed 2768/1-skipped, and codex's own RAN shows the compile/introspection half agreeing with mine). Not a finding against the change; flagged so the orchestrator doesn't read them as regressions.

## 2. Adoption/rebuttal of PEER coverage

Codex's coverage axes (meson registration, GH `if:` guards, listener FILE* safety, Catch2/MSVC portability, CI-architecture consistency) substantially overlap mine; no axis they went deep on that I skipped. Their C1 is a net-new finding in an area I scrutinized but cleared (I verified the upload `if:` has explicit status functions — the CLAUDE.md invariant — and stopped there, missing the cancelled-vs-failure semantic for schedule-triggered job-level cancels). I adopt C1 into my set.

## 3. Defence of my Phase-1 findings

None of my Phase-1 findings is contradicted or undercut by codex's review (it simply doesn't address the changelog fragment, stale ~1500 count, include order, or the AC(b) partial-satisfaction point). All four stand unchanged. My F2's enforcement claim (guard passes without a fragment) is consistent with codex observing no gate failure.

## 4. Revised full finding list

[F1] LOW · hi · compiled — unchanged. Include order inverted (STL after catch2) in tests/unit/test_progress_listener.cpp:16-24 vs docs/cpp-conventions.md "STL → third-party → project". Fix: reorder.

[F2] LOW · hi · test-run — unchanged. No changelog.d fragment for this change (sibling CI-infra changes carry them; guard passes anyway). Fix: add fragment.

[F3] LOW · hi · test-run — unchanged. Stale "~1500 fast cases" in tests/meson.build:613 and :671; measured 2769. Fix: update or drop the figure.

[F4] MEDIUM · med · static-read — unchanged. #4018 AC(b)'s "establish one-off" and "fast-fail" legs are only partially delivered (diagnostics yes, fast-fail no, one-off deferred to recurrence telemetry). Non-blocking; commit makes no overclaim.

[F5 · new-from-cross-exam, agrees-with-codex C1] LOW · hi · static-read
Windows-asan testlog/progress upload drops the artifact on cancelled non-dispatch runs
- Location: .github/workflows/nightly.yml:630 (comment :625-629)
- Claim: `if: failure() || (always() && inputs.jobs == 'windows-asan')` omits `cancelled()`, so on a schedule-triggered or `jobs=all` run cancelled by the 90-min job-level timeout, the progress.log stall diagnostic is not uploaded — though the comment says that cancel case is "exactly when the progress log matters most".
- Evidence: quoted condition at :630; comment at :626-627; sibling steps in the same file use `failure() || cancelled()` (nightly.yml:384, :421) and this change's own snapshot step is `failure() || cancelled()` (:618).
- Scenario: scheduled nightly hits 90-min job timeout (slow vcpkg build + slot wait, or a hang outside meson's per-test timeouts) → job cancelled → failure() false, inputs.jobs null → no testlog/progress artifact; the #4018 recurrence evidence is lost for exactly the class of run the comment targets.
- Inference: meson's 20-min heavy-entry budget normally fails the job before the 90-min ceiling, so the gap is residual, hence LOW.
- Anchor: judgment (comment-vs-condition contradiction; no standing invariant violated — explicit status functions present)
- Precedent: nightly.yml:421
- Mitigations: failure-path normally reached first via meson timeout; live Actions log retains flushed stderr progress lines.
- Fix: `if: failure() || cancelled() || (always() && inputs.jobs == 'windows-asan')`.
- Falsifier: n/a (LOW)

```
VERDICT:  PASS — no CRITICAL/HIGH; five non-blocking findings (one MEDIUM hygiene, four LOW).
COVERAGE: deep on CI/workflow guard semantics, meson conditional/idempotence of the split, Catch2 listener (compiled + executed), slot namespace; skimmed security (no sensitive surface) and MSVC portability (standard C++ only, not compiler-verified). Adopted codex's C1 after independent verification; codex's two meson-test failures are pre-existing machine-state-dependent tests, not regressions.
RAN:      Read nightly.yml:590-649; grep `failure\(\) \|\| cancelled\(\)` in nightly.yml (hits :384,:421,:618 — confirms precedent and C1's gap). All empirical runs were done in Phase 1 and stand (compile warm, [tsan-heavy] 3/3 pass, ~[tsan-heavy] 2768 passed/1 skipped, introspect on plain + ASan builds).
FILES:    .github/workflows/nightly.yml (windows-asan Test/upload region + failure-path grep); /home/dgr/advrev-4018/codex.phase1.md; /home/dgr/advrev-4018/kimi.phase1.md.
```

## Delta since Phase 1

Adopted one net-new finding (F5 = codex C1, confirmed independently): the windows-asan upload `if:` at nightly.yml:630 omits `cancelled()`, contradicting its own comment for schedule-triggered job-level cancels — LOW, one-line fix. My four Phase-1 findings are uncontested and unchanged (verdict stays PASS). Codex's reported meson-test failures are unrelated machine-state tests, not regressions. No remaining disagreement with codex on severity or facts.
