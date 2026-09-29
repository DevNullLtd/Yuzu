# ClusterFuzzLite — continuous fuzzing of Yuzu's untrusted-input parsers

`cflite-pr.yml` builds this directory's `Dockerfile` + `build.sh` on any PR
touching the fuzzed compile closure — six parser families under
`server/core/src/`, plus `tests/fuzz/` and `.clusterfuzzlite/` (see the
workflow's `paths:`) — and fuzzes **what the PR changed** for a short budget
(code-change mode, ASan). Findings surface as the workflow's SARIF / crash
artifacts — file them as issues; don't fix them inside unrelated PRs.

`cflite-batch.yml` (push-to-dev on the same paths; manual dispatch once the
file reaches `main` — GitHub only offers `workflow_dispatch` for workflows on
the default branch, so the dispatch-only prune is unavailable until then)
grows a persistent corpus in batch mode, publishes the coverage report the
PR job prunes against, and (dispatch-only) prunes the corpus. State lives in GHA
artifacts (`cifuzz-corpus-<target>`, `cifuzz-coverage-latest`, 90-day
retention); a red run auto-files a `cflite-batch-broken` issue. Two accepted
limits, both candidly load-bearing: artifact consumption trusts NAMES
repository-wide, so any workflow run in this repo (including an approved
fork-PR run) could upload shadow corpus/coverage artifacts — and because
upstream's filestore untars downloads with an unguarded `tarfile.extractall`
(a standing upstream TODO), a malicious archive member (`../build-out/...`)
can overwrite a freshly-built fuzzer and execute attacker-controlled code
inside the fuzz job, bounded by the ephemeral runner and its read-scoped
token (the PR fuzz job additionally holds `security-events: write`, so a
poisoned run there could also tamper with code-scanning alerts); the
routine-case ceiling is misdirected pruning and crash noise on a
non-required check. Revisit if the check ever becomes required (tracked on
#3773/#3775). And every artifact download FAILS OPEN
(missing/expired corpus → seeds, missing coverage → keep-all), so a
degraded run is distinguishable from a corpus-fed one only by the
download-miss warnings in the job logs.

## Current targets (tests/fuzz/)

| Target | Parses | Why it's fuzzed |
|---|---|---|
| `fuzz_preflight_parse` | pipe-delimited plugin output → pre-flight verdicts | agent/plugin-controlled bytes decide go/no-go |
| `fuzz_deployment_parse` | deployment config fields + content_dist output | operator strings + agent bytes gate the mutating deploy step |
| `fuzz_yaml_scan` | the in-tree YAML-subset scanner | only runtime consumer of `yaml_source`; authorization-load-bearing since #1215 |
| `fuzz_guardian_rule_spec` | Guardian rule bodies + `dangerous_enforce_*` chokepoints | network-supplied specs gate enforce-mode promotion |

Every target is deliberately **closure-light** (STL + nlohmann only) so this
container needs no meson/vcpkg. The same sources build two ways:

- `build.sh` (here) — direct `$CXX` compile against `$LIB_FUZZING_ENGINE`.
- `tests/fuzz/meson.build` — `-Dbuild_fuzzers=true` (clang only) for local
  work, plus a deterministic seed-replay smoke in the `fuzz` meson suite.

**Adding a harness = edit both files** (each has a keep-in-sync banner),
drop 2-3 seeds in `tests/fuzz/corpus/<target>/`, and add the new sources'
family glob to BOTH workflows' `paths:` lists (`cflite-pr.yml` +
`cflite-batch.yml`) — the filters decide whether fuzzing runs at all on a
source change.

## Local loop (macOS: `brew install llvm`, Apple clang has no libFuzzer)

```bash
CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++ \
  meson setup build-fuzz -Dbuild_fuzzers=true -Dcmake_prefix_path=$PWD/vcpkg_installed/<triplet>
meson compile -C build-fuzz fuzz_yaml_scan
build-fuzz/tests/fuzz/fuzz_yaml_scan -max_total_time=300 tests/fuzz/corpus/fuzz_yaml_scan
```

Don't commit libFuzzer-generated corpus entries — only hand-named seeds live
in `tests/fuzz/corpus/`.

## Deferred (tracked follow-up)

- `scope_engine.cpp` `yuzu::scope::parse()` and `cel_eval.cpp` — the two
  highest-value remaining parsers; both link RE2 (+abseil), which needs an
  instrumented from-source build in this container. Add via pinned clones in
  the Dockerfile once the harness set has soaked.
- Dependabot watch on this Dockerfile's `base-builder` digest.

(The batch-fuzzing + corpus-pruning leg shipped as `cflite-batch.yml` —
see above.)
