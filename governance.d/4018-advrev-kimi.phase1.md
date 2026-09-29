# Phase 1 — kimi independent review

Target: ci/2373-4018-tsan-heavy-split @ e330b0522, base 02859ac1d, worktree /home/dgr/yuzu-4018.

## Findings

[F1] LOW · CONFIDENCE(hi) · PROVENANCE(compiled)
Include order inverted vs repo convention in new TU
- Location: tests/unit/test_progress_listener.cpp:16-24
- Claim: Catch2 (third-party) includes precede STL includes, inverting the mandated "STL → third-party → project" order.
- Evidence: cpp-conventions.md: "Include order: STL → third-party → project." New file lines 16-20 are catch2/*, lines 22-24 are <chrono>/<cstdio>/<cstdlib>. Sibling precedent tests/unit/server/test_pg_template_cleanup.cpp:28-35 puts STL first, then catch2.
- Scenario: none functional; purely a lint/convention drift on a file cpp-expert/cpp-safety load against.
- Inference: build passes regardless; this is style-contract only.
- Anchor: docs/cpp-conventions.md §Headers ("Include order: STL → third-party → project")
- Precedent: tests/unit/server/test_pg_template_cleanup.cpp:28-35
- Mitigations: none needed; non-blocking.
- Fix: move <chrono>/<cstdio>/<cstdlib> above the catch2 block.
- Falsifier: n/a (LOW)

[F2] LOW · CONFIDENCE(hi) · PROVENANCE(test-run)
No changelog.d fragment for a user-visible test-infra change
- Location: changelog.d/ (absent); commit e330b0522 (3 files changed, no fragment)
- Claim: Repo convention requires one fragment per PR ("PRs add uniquely-named fragment files"); recent sibling CI-infra changes carry fragments (changelog.d/2026-08-25-linux-heavy-test-slot-count-3.changed.md, 1883-ci-test-isolation.fixed.md), but this change adds none.
- Evidence: ran `python3 scripts/assemble-changelog.py --guard 02859ac1d` → "Changelog guard OK" (guard only blocks direct CHANGELOG.md edits, does not require a fragment), and `--check` passes — so this will NOT fail CI today; it is a convention gap only. changelog.d/README.md: "Exactly one new file."
- Scenario: release notes omit the windows-asan hardening + #2373 split; no CI failure.
- Inference: absence is not enforced for missing fragments, hence LOW not MEDIUM.
- Anchor: judgment (README convention; no blocking gate) — CLAUDE.md "Changelog" section cited but its enforcement mechanism (guard) demonstrably passes.
- Precedent: changelog.d/2026-08-25-linux-heavy-test-slot-count-3.changed.md (also a with-test-slot/timeout change)
- Mitigations: none enforce it; impact cosmetic.
- Fix: add changelog.d/4018-tsan-heavy-split.changed.md with one bullet.
- Falsifier: n/a (LOW)

[F3] LOW · CONFIDENCE(hi) · PROVENANCE(test-run)
Stale "~1500 fast cases" count in meson comment after the split
- Location: tests/meson.build:613 (block comment) and :671 (new entry comment "the whole ~1500-case fast suite")
- Claim: The fast agent suite actually contains 2769 test cases (measured), not ~1500; both comments understate by ~45%.
- Evidence: `./tests/yuzu_agent_tests "~[tsan-heavy]"` → "test cases: 2769 | 2768 passed | 1 skipped". Comments at tests/meson.build:613 ("timing out the other ~1500 fast cases") and :671 ("dragging the whole ~1500-case fast suite down with it").
- Scenario: none functional; comment-truth drift (docs-writer owns wording; domain agent owns truth).
- Inference: count likely grew since the comment was written; the stale figure weakens the argument's quantitative force but not its mechanism.
- Anchor: judgment
- Precedent: none found
- Mitigations: none
- Fix: update the figure or drop the count ("the fast suite").
- Falsifier: n/a (LOW)

[F4] MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read)
#4018 acceptance criterion (b) only partially satisfied — no fast-fail, one-off not yet established
- Location: .github/workflows/nightly.yml:593-620 (Test step, snapshot step); commit message e330b0522
- Claim: AC (b) asks to "establish (e.g. via process/resource telemetry captured during a live stall) that this was a one-off environmental anomaly, AND add a connect_timeout/heartbeat-style fast-fail plus diagnostic logging … so a future recurrence fails fast and classifiably instead of silently eating the full 240s budget." The change delivers the diagnostic-logging half (progress listener, per-entry 600s budget, tasklist snapshot, jobs selector enabling recurrence measurement) but no fast-fail mechanism: a future stall still burns up to 1200s (600× --timeout-multiplier 2) inside the heavy entry, and the "establish one-off" half is delegated to future dispatches, not done here.
- Evidence: nightly.yml Test step (lines 605-613) sets no connect_timeout/heartbeat env on the tests; the only new timeout-ish behaviour is the split budget itself (tests/meson.build:678 timeout: 600). gh issue view 4018 acceptance criteria verbatim above.
- Scenario: A recurrence of the Wee Tam stall on dev: the run now fails classifiably at the heavy entry's own budget with a progress trail (better than #4018's state), but it still eats up to 20 minutes of the 90-minute job and does not "fail fast"; the issue stays open pending recurrence telemetry.
- Inference: the split arguably IS the classifiability fix and the progress listener IS the diagnostic trail; one can read AC (b)'s "fast-fail" loosely (classifiable ≠ fast). The commit message makes no AC-closure claim, so this is an issue-hygiene observation, not an overclaim by the author.
- Anchor: judgment (anchored to issue #4018's own AC text, read via gh)
- Precedent: none found
- Mitigations: the jobs selector lets an operator run cheap recurrences to gather the telemetry; the heavy entry's 1200s worst case fits the 90-min job.
- Fix: none required for merge; at most, note in #4018 that AC (b)'s "establish one-off" leg remains open until recurrence runs execute.
- Falsifier: n/a (MEDIUM, non-blocking)

## Verified-clean items (scrutinize list, no findings)

- **Gated test() condition**: `get_option('b_sanitize') != 'none'` (tests/meson.build:667). `meson introspect build-linux --tests` (plain): entry ABSENT, 'agent unit tests' args `~[tsan-heavy]` timeout 240. `meson introspect build-linux-asan-check --tests` (b_sanitize=address, pre-existing warm dir): 'agent tsan-heavy checkpoints' PRESENT, cmd `[tsan-heavy]`, timeout 600, suite `yuzu:agent`. nightly legs configure with `-Db_sanitize=address,undefined` (nightly.yml:187), `thread` (:334), `address` (:589) — all != 'none'; coverage job sets only `-Db_coverage=true` (:744-748) → correctly excluded. Inverse-condition precedent spark_alloc_budget_exe block (tests/meson.build:641) confirms meson conditional idiom.
- **Listener API (Catch2 3.13.0, vcpkg)**: `Catch::EventListenerBase` ctor via IConfig const*, `testRunStarting(TestRunInfo const&)`, `testCaseStarting(TestCaseInfo const&)`, `testCaseEnded(TestCaseStats const&)` all match v3.13.0 headers (vcpkg_installed/x64-linux/include/catch2/reporters/catch_reporter_event_listener.hpp:43-49); `Catch::getSeed()` exists (catch_get_random_seed.hpp:15); `TestRunInfo::name` is a `StringRef` with size()/data() (catch_test_run_info.hpp). TU compiled (warm build, ninja "no work to do") and executed correctly.
- **Listener wiring**: added only to agent_test_exe source list (tests/meson.build:232); server test exe untouched. Precedent CATCH_REGISTER_LISTENER-in-anonymous-namespace matches tests/unit/server/test_pg_template_cleanup.cpp:49,171.
- **getenv→atoi null-safety**: `v != nullptr && std::atoi(v) != 0` (test_progress_listener.cpp:57-59) — guarded; `YUZU_TEST_PROGRESS=0`/garbage → disabled. Verified silent by default (0 progress lines with env unset).
- **Mirrored-file path**: nightly.yml:608 uses ABSOLUTE `$GITHUB_WORKSPACE/build-windows-asan/meson-logs/progress.log`; upload path (relative to workspace) matches. No double-prefix risk. Verified mirror write locally: 7 lines (RUN + 3 START + 3 END), correct test names + ms timings.
- **workflow_dispatch guards**: every changed `if:` retains an explicit status-check function where the CLAUDE.md invariant requires one: alert `!cancelled() && … && (failure() || …)` (nightly.yml:820 — has failure()+cancelled()); close-on-green `success() && …` (:905); snapshot `failure() || cancelled()` (:621); upload `failure() || (always() && …)` (:638). Job-level ifs on sanitize-asan/tsan/coverage (:82,227,645) had no status function BEFORE the change either — implicit success() is pre-existing and semantically load-bearing (needs.preflight); the added `&& inputs.jobs != 'windows-asan'` doesn't alter that. On schedule triggers `inputs.jobs` is empty → all guards evaluate exactly as before.
- **jobs=windows-asan dispatch safety**: sanitize-asan/tsan/coverage skip; alert + close-on-green guard out → no spurious nightly-broken open/close; preflight (unguarded) still runs; windows-asan itself has no jobs guard (:478) so it runs for both choices and schedule.
- **with-test-slot wrap**: `with-test-slot.sh 2 --` with `YUZU_TEST_SLOT_TIMEOUT_MIN: "30"` mirrors ci.yml's Wee Tam invocations (ci.yml:1648,1665); neither sets YUZU_TEST_SLOT_NAME → both share the default `yuzu-weetam-heavy` namespace (scripts/ci/with-test-slot.sh header) — nightly's windows-asan now genuinely joins ci.yml's gate. `tasklist //v` is correct under the job's MSYS2 bash default shell (nightly.yml:483-486).
- **No double-run / no orphan consumers**: `agent_test_args = ['~[tsan-heavy]']` unconditionally (tests/meson.build:655) — heavy tests run in exactly one entry; grep confirms no script/docs/.github consumer of the tag breaks (docs/spark-flip-gate.md references are descriptive).
- **Runtime**: `[tsan-heavy]` filter runs exactly 3 test cases (all pass, 234 assertions) — matches the "three [tsan-heavy] checkpoints" comment (#3848 added the third). Full fast suite `~[tsan-heavy]`: 2768 passed / 1 skipped, exit 0.

```
VERDICT:  PASS — no CRITICAL/HIGH; four LOW/MEDIUM non-blocking findings, none affecting the split's correctness or the nightly guards' validity.
COVERAGE: deep on CI/workflow semantics (guards, slot namespace, sanitizer-leg interplay, meson conditional), deep on the Catch2 listener (compiled + executed), deep on test-infra conventions; skimmed security/privilege (nothing sensitive — env-gated local file append, no injection surface: fprintf format strings are literals) and cross-platform (Linux verified by execution; MSVC portability is standard-C++-only and low-risk but not compiler-verified here).
RAN:      meson compile -C build-linux tests/yuzu_agent_tests (no work to do — warm build at this commit, TU already compiled); ./tests/yuzu_agent_tests "[tsan-heavy]" (3 cases pass); YUZU_TEST_PROGRESS=1 run (7 progress lines, stderr + mirror file correct); ./tests/yuzu_agent_tests "~[tsan-heavy]" (2768 passed/1 skipped, silent); meson introspect --tests on build-linux (entry absent) and build-linux-asan-check b_sanitize=address (entry present, timeout 600); python3 scripts/assemble-changelog.py --guard 02859ac1d (OK); gh issue view 4018 (AC text). No CI run exists (not pushed).
FILES:    .github/workflows/nightly.yml (full windows-asan job, alert, close-on-green, sanitize/coverage legs); tests/meson.build (region 520-700 + introspection); tests/unit/test_progress_listener.cpp; tests/unit/server/test_pg_template_cleanup.cpp (precedent); scripts/ci/with-test-slot.sh (header); docs/cpp-conventions.md; docs/ci-architecture.md (anchors via grep); changelog.d/README.md; scripts/assemble-changelog.py + scripts/hooks/changelog-fragment-guard.py; .github/workflows/ci.yml (Wee Tam slot usage); .github/workflows/sanitizer-tests.yml; vcpkg_installed Catch2 3.13.0 headers; docs/spark-flip-gate.md; vcpkg.json.
```
