# Phase 2 - codex cross-examination

## Peer Cross-Exam

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| F1 | confirmed-independently | `docs/cpp-conventions.md:17-20` mandates STL -> third-party -> project; `tests/unit/test_progress_listener.cpp:12-21` puts Catch2 before STL; `tests/unit/server/test_pg_template_cleanup.cpp:29-40` is the sibling order. | LOW, adopted as C3 |
| F2 | false-positive/unfair | `changelog.d/README.md:51-53` says pure CI plumbing and test-only changes with no operator-visible effect can skip a fragment; `git diff --name-status 02859ac1d..e330b0522 -- changelog.d CHANGELOG.md` is empty; `python3 scripts/assemble-changelog.py --guard 02859ac1d && --check` passes. | none |
| F3 | confirmed-independently | `tests/meson.build:615` and `:671` say "~1500"; `meson test -C build-linux --suite agent` reported `test cases: 2769` for `~[tsan-heavy]`; `./build-linux/tests/yuzu_agent_tests "[tsan-heavy]"` separately confirmed the split has 3 heavy cases. | LOW, adopted as C4 |
| F4 | confirmed-independently | `tests/meson.build:678-683` sets a 600s test timeout; `.github/workflows/nightly.yml:612-613` applies `--timeout-multiplier 2`; no connect/heartbeat-style fast-fail is added in `tests/unit/test_progress_listener.cpp` or the workflow. | MEDIUM, adopted as C5 |

## Peer Coverage Adopted/Rebutted

Kimi went deeper than my Phase 1 on changelog policy; I rebut F2 because the local README explicitly exempts pure CI plumbing/test-only changes unless an operator or managed agent would notice.

Kimi went deeper on code-comment truth. I adopted F3 after my own test run reproduced 2769 fast cases, but I keep it LOW because the stale count does not affect the Meson split or timeout behavior.

Kimi's include-order pass was correct but incomplete. The stronger C++ convention miss is the new `FILE*` owner with manual `fclose`, which is a resource-ownership policy finding under `docs/cpp-conventions.md:72-76` and `:125-131`.

Kimi's #4018 acceptance note is directionally right. I adopted it as a non-blocking MEDIUM because this change improves classifiability and rerun ergonomics, but does not itself establish the live-stall anomaly as one-off or add a true fast-fail.

## Own Findings Rechecked

C1 was ignored, not contradicted. Rechecked `.github/workflows/nightly.yml:625-630` against the TSan sibling at `:416-421`; the Windows ASan upload still lacks `cancelled()` for scheduled/default runs. I keep it LOW because Meson's per-test timeout should usually fail before a job-level cancel and because this is diagnostic retention only.

My Phase 1 missed the `FILE*` RAII policy floor. That changes my final verdict to BLOCK.

## Revised Findings

[C2]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
Manual `FILE*` cleanup in the new listener violates the C++ resource-ownership contract
- Location:  tests/unit/test_progress_listener.cpp:69-72
- Claim:     The new listener acquires an owning `FILE*` with `std::fopen` and releases it manually with `std::fclose`, which violates the repo rule that new C++ resource owners use RAII/smart pointers and makes the change fail the resource-ownership policy gate.
- Evidence:  `tests/unit/test_progress_listener.cpp:70-72` is `if (FILE* f = std::fopen(path, "a")) { ... std::fclose(f); }`; `docs/cpp-conventions.md:74-76` says every C++ diff must prove ownership for `FILE*` and "Manual cleanup is a governance finding unless the code documents why a wrapper is impossible or would be less safe"; `docs/cpp-conventions.md:130-131` forbids manual resource cleanup in new code.
- Scenario:  A reviewer accepts this pattern because the current block has no early return; the next edit adds a branch or throwing operation between `fopen` and `fclose`, and the env-gated progress mirror leaks a file handle during the same stalled-CI diagnostic path it is supposed to harden.
- Inference: `std::fprintf` is non-throwing in normal C I/O, so there is no observed leak today; the defect is a policy-floor and maintainability failure, not a demonstrated runtime leak in this exact revision.
- Anchor:    contract: `docs/cpp-conventions.md` "Resource ownership and lifetime" and "Forbidden in new code"; severity raised by repo precedent that manual `FILE*` in new test code was recorded as blocking policy-floor in `governance.d/custom-properties-store-pg.10A32U.jsonl`.
- Precedent: `agents/core/src/net_quality_sampler.cpp:62-68` defines a non-copyable `FileGuard`, and `agents/core/src/net_quality_sampler.cpp:193-196` wraps the `std::fopen` result before reading.
- Mitigations: format strings are literals, this code is test-only and env-gated, and there is no current early return between acquire and release; those lower impact from CRITICAL but do not satisfy the RAII policy.
- Fix:       Replace the raw owner with a local RAII owner, e.g. `std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(path, "a"), &std::fclose)`, and write through `f.get()`.
- Falsifier: A code change wraps the `std::fopen` result in an RAII owner before any operation, or the convention is amended with an explicit carve-out for this exact per-line test diagnostic.

[C6]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
The new listener also uses printf-family formatting forbidden in new C++ code
- Location:  tests/unit/test_progress_listener.cpp:63-71
- Claim:     `emit()` is built around `std::fprintf`, which violates the repo's new-code formatting convention and leaves format/type coupling in a diagnostic path that can be implemented with `std::format` plus `std::fputs`.
- Evidence:  `tests/unit/test_progress_listener.cpp:64` and `:71` call `std::fprintf`; `docs/cpp-conventions.md:127-128` says "printf-family calls (use `std::format` or spdlog)" are forbidden in new code.
- Scenario:  A future edit adds another progress field with a mismatched format specifier and the progress logger corrupts or misreports exactly when CI diagnostics are needed.
- Inference: The current calls use literal formats with matching argument types, so this is convention debt rather than an observed crash.
- Anchor:    contract: `docs/cpp-conventions.md` "Forbidden in new code".
- Precedent: `tests/unit/test_helpers.hpp:367-378` uses `std::format(...)` plus `std::fputs(...)` for stderr diagnostics.
- Mitigations: literal format strings and test-only env gating limit immediate risk.
- Fix:       Build the progress line as a `std::string` with `std::format` and pass it to `std::fputs` for stderr and the optional mirror file.
- Falsifier: n/a (LOW).

[C3]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
Include order is inverted in the new TU
- Location:  tests/unit/test_progress_listener.cpp:12-21
- Claim:     The file places third-party Catch2 includes before STL includes, contrary to the repo's header-order convention.
- Evidence:  `tests/unit/test_progress_listener.cpp:12-17` are Catch2 includes and `:19-21` are `<chrono>/<cstdio>/<cstdlib>`; `docs/cpp-conventions.md:17-20` says include order is STL -> third-party -> project.
- Scenario:  The file normalizes a different include order for future test utilities and makes local convention drift harder to review mechanically.
- Inference: This does not affect compilation.
- Anchor:    contract: `docs/cpp-conventions.md` "Headers".
- Precedent: `tests/unit/server/test_pg_template_cleanup.cpp:29-40` places STL includes before Catch2 and libpq includes.
- Mitigations: none needed; this is non-functional.
- Fix:       Move the STL includes above the Catch2 block.
- Falsifier: n/a (LOW).

[C4]  LOW · CONFIDENCE(hi) · PROVENANCE(test-run) · new-from-cross-exam
The split comments understate the fast suite size
- Location:  tests/meson.build:615 and tests/meson.build:671
- Claim:     The comments say the fast suite is "~1500" cases, but the current `~[tsan-heavy]` agent entry reports 2769 cases, so the quantitative rationale is stale.
- Evidence:  `tests/meson.build:615` and `:671` both say "~1500"; my `meson test -C build-linux --suite agent --print-errorlogs` run invoked `yuzu_agent_tests '~[tsan-heavy]'` and reported `test cases: 2769`.
- Scenario:  A maintainer sizing future timeouts or shards reads the comment and reasons from a materially stale case count.
- Inference: The split mechanism remains correct because it depends on the tag filter and timeout, not the exact count.
- Anchor:    judgment; no blocking contract beyond ordinary comment truth.
- Precedent: none found.
- Mitigations: Meson introspection and Catch2 output expose the actual command and case count.
- Fix:       Replace "~1500" with "the fast suite" or update the measured count.
- Falsifier: n/a (LOW).

[C5]  MEDIUM · CONFIDENCE(med) · PROVENANCE(static-read) · new-from-cross-exam
#4018 acceptance is improved but not fully closed by this code change
- Location:  tests/meson.build:678-683 and .github/workflows/nightly.yml:595-630
- Claim:     The change splits and instruments the heavy tests, but it does not establish the Wee Tam timeout as a one-off live anomaly and does not add a true fast-fail; a recurrence can still spend up to 1200s in the dedicated heavy entry before becoming classifiable.
- Evidence:  `tests/meson.build:683` sets `timeout: 600`; `.github/workflows/nightly.yml:612-613` runs Meson with `--timeout-multiplier 2`; `.github/workflows/nightly.yml:608-609` only enables progress logging and a mirror file.
- Scenario:  A maintainer treats this commit as closing #4018 AC(b), then a future recurrence still waits through the expanded heavy-entry timeout and the issue lacks the live telemetry needed to prove the original event was environmental.
- Inference: The code does satisfy #2373's durable split direction and substantially improves classification, so this is issue-hygiene/acceptance scope rather than a merge blocker.
- Anchor:    judgment; based on the #4018 AC text supplied in the review prompt, not a repo contract.
- Precedent: none found.
- Mitigations: `workflow_dispatch.inputs.jobs=windows-asan` enables cheap recurrence runs, progress lines identify the last test case, and the split protects the fast suite from the heavy checkpoint budget.
- Fix:       Do not close #4018 AC(b) until a windows-asan recurrence run captures the needed telemetry, or add a genuine heartbeat/connect-timeout-style fast-fail if that remains required.
- Falsifier: n/a (MEDIUM).

[C1]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
windows-asan progress/testlog upload does not cover cancelled scheduled/default runs
- Location:  .github/workflows/nightly.yml:625-630
- Claim:     The Windows ASan artifact upload still drops the progress log for a cancellation on scheduled/default-all runs, so the new stall diagnostic is complete for ordinary failures and `jobs=windows-asan` dispatches but not every cancelled run.
- Evidence:  `.github/workflows/nightly.yml:630` is `if: failure() || (always() && inputs.jobs == 'windows-asan')`; the adjacent comment says a "90-minute job-level timeout is a CANCEL" and "that's exactly when the progress log matters most" at `.github/workflows/nightly.yml:626-628`.
- Scenario:  A scheduled nightly or default `jobs=all` dispatch is cancelled during the Windows ASan leg after progress logging has begun; `failure()` is false and `inputs.jobs` is not `windows-asan`, so the progress mirror is not uploaded.
- Inference: Meson's per-test timeout and the new slot gate should usually produce an ordinary failure before a job-level cancellation, so this is a diagnostic-retention gap, not evidence that the test split is wrong.
- Anchor:    judgment; CLAUDE.md "CI architecture" failure-path invariant requires explicit status functions and this line has status functions, so this is not the blocking invariant violation.
- Precedent: `.github/workflows/nightly.yml:416-421` uses `if: failure() || cancelled()` for the analogous TSan testlog/stack-capture upload.
- Mitigations: live Actions stderr should still contain flushed progress lines; `jobs=windows-asan` clean reruns do upload the progress log.
- Fix:       Use `if: failure() || cancelled() || (always() && inputs.jobs == 'windows-asan')`.
- Falsifier: n/a (LOW).

VERDICT:  BLOCK - C2 is a HIGH resource-ownership contract violation in new C++ test code.
COVERAGE: Went deep on C++ resource/lifetime and convention checks, Meson sanitizer test registration, Catch2 listener API/runtime behavior, workflow `if:` status-function semantics, Windows test-slot wiring, acceptance scope, and test adequacy. Security/privilege was skimmed because the diff adds env-gated local test logging and CI diagnostics only; I checked for command injection/secrets exposure and found no product-auth or privilege boundary.
RAN:      `CCACHE_DIR=/tmp/yuzu-review-ccache meson compile -C /home/dgr/yuzu-4018/build-linux tests/yuzu_agent_tests` -> OK/no work. `CCACHE_DIR=/tmp/yuzu-review-ccache meson test -C /home/dgr/yuzu-4018/build-linux --suite agent --print-errorlogs` -> `spark allocation budget` OK; `agent unit tests` failed after 2760 passed / 3 failed / 6 skipped, exit 42, with failures in `test_subprocess_runner.cpp:237/241`, `test_net_quality_sampler.cpp:152`, and `test_passwd_lookup.cpp:200` unrelated to this diff. `./build-linux/tests/yuzu_agent_tests "[tsan-heavy]" --allow-running-no-tests` -> 3 cases pass. `YUZU_TEST_PROGRESS=1 YUZU_TEST_PROGRESS_FILE=/tmp/yuzu-progress-phase2.log ./build-linux/tests/yuzu_agent_tests "compare_versions: empty strings"` -> OK, progress mirror contained RUN/START/END. `CC=gcc-15 CXX=g++-15 meson setup /tmp/yuzu-phase2-asan ... -Db_sanitize=address -Dbuild_server=false -Dbuild_tests=true` -> OK configure-only. `meson introspect build-linux --tests` -> plain build has `agent unit tests` with `~[tsan-heavy]` and no heavy entry. `meson introspect /tmp/yuzu-phase2-asan --tests` -> ASan build has `agent unit tests` with `~[tsan-heavy]` and `agent tsan-heavy checkpoints` with `[tsan-heavy]`, timeout 600. `python3 scripts/assemble-changelog.py --guard 02859ac1d && python3 scripts/assemble-changelog.py --check` -> OK. `git diff --check 02859ac1d..e330b0522` -> OK. `actionlint` unavailable. CI status on PR head: no PR exists / branch not pushed per prompt, so no remote CI checked.
FILES:    `/home/dgr/advrev-4018/codex.phase1.md`; `/home/dgr/advrev-4018/kimi.phase1.md`; `CLAUDE.md`; `docs/ci-architecture.md`; `docs/cpp-conventions.md`; `changelog.d/README.md`; `scripts/assemble-changelog.py`; `scripts/hooks/changelog-fragment-guard.py`; `.github/workflows/nightly.yml`; `.github/workflows/ci.yml`; `.github/workflows/sanitizer-tests.yml`; `tests/meson.build`; `tests/unit/test_progress_listener.cpp`; `tests/unit/test_runner_main.cpp`; `tests/unit/server/test_pg_template_cleanup.cpp`; `tests/unit/test_guardian_spark_runtime.cpp`; `tests/unit/test_helpers.hpp`; `agents/core/src/net_quality_sampler.cpp`; `agents/core/src/dex_linux_collector.cpp`; `scripts/ci/with-test-slot.sh`; `build-linux/meson-logs/testlog.txt`; `governance.d/custom-properties-store-pg.10A32U.jsonl`; `governance.d/3235-tag-store.14q7IU.jsonl`.

## Delta Since Phase 1

- Verdict changed from PASS to BLOCK.
- New blocking finding C2: manual `FILE*` cleanup in new C++ violates the RAII resource-ownership contract.
- New low finding C6: the same listener uses forbidden printf-family formatting.
- Adopted Kimi F1/F3/F4 as C3/C4/C5; rebutted Kimi F2 because changelog policy exempts pure CI/test-only changes.
- C1 remains LOW and unchanged.
