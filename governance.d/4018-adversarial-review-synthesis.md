## Review — requesting changes

Reviewed `ci/2373-4018-tsan-heavy-split` @ `e330b0522` (base `02859ac1d`) — the
#2373 tsan-heavy split, the new progress-listener TU, and the windows-asan
hardening for #4018. Two independent reviewers (Kimi, dynamic; Codex,
`--reasoning high`) ran both phases empirically — compiled and ran the agent
suite, introspected both a plain and a `-Db_sanitize=address` configure to
confirm the new `test()` entry appears only under sanitizer builds, and ran
the listener directly with/without `YUZU_TEST_PROGRESS`. Both reached PASS in
Phase 1. In Phase 2, Codex found a real `FILE*` resource-ownership defect that
Kimi's Phase 2 never got to examine (the two phase-2 passes are simultaneous,
each reading only the other's Phase 1) — I verified it independently against
the code, `docs/cpp-conventions.md`, and this repo's own prior governance
ledger, and it stands. **Net verdict: BLOCK on one finding; four more should
be fixed in the same pass since they're one-line changes.**

### 🔴 Blocker

**Manual `FILE*` cleanup in the new listener violates the repo's RAII policy
floor.** `tests/unit/test_progress_listener.cpp:69-73`:
```cpp
if (FILE* f = std::fopen(path, "a")) {
    std::fprintf(f, fmt, args...);
    std::fclose(f);
}
```
`docs/cpp-conventions.md:131` lists "Manual resource cleanup (use RAII / smart
pointers)" under "Forbidden in new code" without exception, and CLAUDE.md's
standing-rules block names "non-RAII manual cleanup in new C++" as one of the
policy floors that gate as a CONTRACT violation regardless of derived
severity — deliberately not run through the normal impact/exposure
derivation. This repo has hit the identical pattern before:
`governance.d/custom-properties-store-pg.10A32U.jsonl`'s `safety-3` finding
is byte-for-byte the same defect ("a new test used raw FILE*/fopen/fclose
instead of RAII"), recorded `severity_native: BLOCKING`, trigger explicitly
`"n/a (present in new test code, no REQUIRE between fopen success and fclose
today)"` — i.e. this repo's own prior practice already established that "no
demonstrated leak path today" does not exempt the pattern. The fix mirrors an
existing sibling: `agents/core/src/net_quality_sampler.cpp:62-68`'s
`FileGuard` (non-copyable RAII wrapper, `~FileGuard() { if (f) fclose(f); }`).
Falsifier: wrap the `fopen` result in an RAII owner (e.g.
`std::unique_ptr<std::FILE, decltype(&std::fclose)>`) before any operation.

### Should fix

- **`printf`-family calls in new code are also forbidden** (same file,
  `emit()`'s two `std::fprintf` calls). `docs/cpp-conventions.md:127`: "printf-
  family calls (use `std::format` or spdlog)." `tests/unit/test_helpers.hpp`
  already does this correctly nearby (`std::format` + `std::fputs`) — reuse
  that shape when fixing the RAII issue above, since both live in the same
  `emit()` function. LOW on its own, but free to fix in the same edit.
- **The windows-asan upload step contradicts its own comment.**
  `.github/workflows/nightly.yml:630`: `if: failure() || (always() &&
  inputs.jobs == 'windows-asan')` — the adjacent comment (:626-628) says a
  90-minute job-level timeout is a CANCEL, "exactly when the progress log
  matters most," but `cancelled()` isn't in the condition. Sibling uploads in
  the same file already use `failure() || cancelled()` (nightly.yml:384,
  :421), as does this change's own new snapshot step (:618). Both reviewers
  found this independently. Fix: `if: failure() || cancelled() || (always()
  && inputs.jobs == 'windows-asan')`.
- **Include order is inverted** in the new file — Catch2 headers precede the
  `<chrono>/<cstdio>/<cstdlib>` STL includes, against `docs/cpp-
  conventions.md`'s "STL → third-party → project" and the sibling precedent
  `tests/unit/server/test_pg_template_cleanup.cpp`. One-line reorder.
- **Stale case count in two comments.** `tests/meson.build:613` and `:671`
  say "~1500" fast cases; both reviewers independently measured 2769 via
  `meson test --suite agent` / direct binary run. Doesn't affect the split's
  mechanism (the tag filter drives it, not the count), but the number is used
  as part of the rationale for keeping the fast entry's budget tight — update
  it or drop the figure.

### Minor

- **#4018 AC(b) is improved but not fully closed by this diff alone**, and
  that's fine for this PR but worth stating plainly when it's referenced:
  the split makes a stall classifiable and the progress listener narrows it
  to a `TEST_CASE`, but there's no true fast-fail (a recurrence can still
  spend up to 1200s in the heavy entry before failing), and "establish this
  was a one-off" is deferred to the post-merge recurrence dispatches, not
  established by this commit. Don't let a PR/issue comment claim AC(b) is
  closed — it's advanced, not closed.

### Adjudication

- **F2 (Kimi): no changelog.d fragment — rebutted, confirmed against the
  source.** `changelog.d/README.md`: "pure refactors, CI plumbing, and
  test-only changes with no operator-visible effect can skip it." This diff
  is exactly that (nightly.yml CI hardening + a test-only listener, no
  product-visible change). Not a finding.
- **C2/C6 were never cross-examined by Kimi** — they surfaced in Codex's own
  Phase 2 after the Phase 1 barrier, so Kimi's PASS verdict doesn't reflect
  awareness of them. I verified both directly against the code and the cited
  docs/precedent myself rather than deferring to either reviewer's say-so;
  they stand.
- Everything else both reviewers touched (the `b_sanitize` gating condition,
  the Catch2 listener API usage, the null-guarded `getenv`→`atoi`, the
  absolute progress-file path avoiding the meson-cwd-is-builddir trap, the
  `workflow_dispatch` guard semantics on `sanitize-asan`/`sanitize-tsan`/
  `coverage`/`alert`/`close-on-green`, the `with-test-slot.sh` namespace
  join) was independently compiled/run/introspected by both and matches on
  inspection — no further adjudication needed there.

**Empiricism:** Both reviewers ran dynamic (Kimi confirmed no static
fallback; Codex `--reasoning high`) against the real worktree
`/home/dgr/yuzu-4018` with a warm `build-linux`. Both compiled
`tests/yuzu_agent_tests`, ran the full agent suite and the `[tsan-heavy]`
subset directly, configured a separate `-Db_sanitize=address` build to
confirm the new `test()` entry's existence via `meson introspect`, and ran
the listener binary directly with/without `YUZU_TEST_PROGRESS` to confirm
byte-identical baseline output. Codex's `meson test --suite agent` run hit
two unrelated pre-existing failures (`test_passwd_lookup.cpp`,
`test_net_quality_sampler.cpp`) — both reviewers agree these are machine-
state-dependent and untouched by this diff, not regressions. No CI run
exists; this branch has not been pushed.
