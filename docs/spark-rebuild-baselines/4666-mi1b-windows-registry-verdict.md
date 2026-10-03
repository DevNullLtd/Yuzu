# #4666 PR-2 W3a MI-1b — Windows spdlog-registry topology: empirical verdict

Validates, as the claim stood at `f7a000fc3`, a sentence repeated across five sites in the docs
(`docs/spark-flip-gate.md`, `docs/darwin-compat.md`, `docs/user-manual/server-admin.md` ×2,
`docs/resource-ledgers/4666-log-handoff.md`): "on Windows, the agent image and
`libyuzu_agent_core` share a single spdlog registry — INFERRED from dynamic spdlog linkage, never
directly measured." The fixture that actually measures this
(`tests/unit/test_log_handoff_multi_image.cpp`, tags `[log_handoff][multi_image]`, cases MI-1,
MI-1b(a), MI-1b(b), MI-3) already runs on every Windows CI run, but nobody had read its WARN/report
output before this run. This is that reading, done on real Windows hardware against a named commit,
with linkage corroboration. The five sites above were updated from "inferred" to "confirmed" in
the same commit that added this file.

**Verdict: ONE shared registry — the inference is CONFIRMED on Windows.** All four runtime signals
(MI-1, MI-1b(a), MI-1b(b), MI-3) and the linkage corroboration (`dumpbin`) agree. This is the same
shape as Linux (confirmed) and the opposite of macOS's two-registry shape.

## Environment

- Rig: weecolin (100.96.108.95), repo `C:\Users\daver\Yuzu`, branch `dev`.
- SHA: **`f7a000fc33da5c715da133988ce986f10b01fc05`** — fast-forwarded from the box's prior HEAD
  (`3c8ac2c0c9ed1a822089a044e98eab6290462dca`, confirmed an ancestor of `origin/dev` before merging)
  via `git fetch origin dev && git merge --ff-only origin/dev`. Verified with
  `git rev-parse HEAD origin/dev` both printing `f7a000fc3...` after the fast-forward, not merely
  trusted from `git fetch`'s own output.
- MSVC: `cl` reports `Microsoft (R) C/C++ Optimizing Compiler Version 19.44.35229 for x64`, toolset
  path `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\...`
  (via `setup_msvc_env.sh`, never `vcvars64.bat`).
- spdlog: **1.17.0** (`vcpkg_installed/x64-windows/share/spdlog/spdlogConfigVersion.cmake`,
  `set(PACKAGE_VERSION "1.17.0")`).
- Build type: debug (`spdlogd.dll` naming throughout confirms this).

## Execution deviation: a fresh build directory, not `build-windows`

The normal `build-windows` directory was assumed going in. On arrival, weecolin was running a live, standing UAT rig directly out of
`build-windows`: `yuzu-server.exe` (PID 3456, via `C:\rig\run-server.ps1`) and `yuzu-agent.exe` (PID
9852, via `C:\rig\run-agent.ps1`), both launched against `build-windows\agents\core\...` binaries.
Rebuilding at the fast-forwarded SHA hit `LINK : fatal error LNK1104: cannot open file
'agents\core\yuzu_agent_core.dll'` — the running `yuzu-agent.exe` holds that DLL open.

Stopping those processes to free the lock was attempted and was **denied by this session's own
auto-mode permission classifier** ("Interfere With Workloads") — a live rig potentially in use
elsewhere, not mine to stop without the operator's explicit say. This was not retried in any
other form; the blocker is reported as-is below rather than worked around silently.

Instead: a **second, independent build directory** was configured —
`bash scripts/setup.sh --tests --builddir build-windows-mi1b` — which reuses the same
`vcpkg_installed/x64-windows` tree (no re-resolve needed) and builds entirely separate output
binaries, touching nothing in `build-windows` and never stopping, restarting, or otherwise disturbing
the live rig (confirmed still running, same PIDs, after this run). This directory is **not** one of
the three per-OS directories CLAUDE.md names (`build-windows`/`build-linux`/`build-macos`) — it is a
one-off left on the box at `C:\Users\daver\Yuzu\build-windows-mi1b` for Dave to keep or delete; it
was not cleaned up by this run.

The agent-shard test binary (`tests/yuzu_agent_tests.exe`) and its direct build dependencies
(`yuzu_agent_core.dll`, `agent_actions.dll`, the three fixture plugins) were produced by `meson
test`'s own pre-run build step. `yuzu-agent.exe` is **not** a dependency of that test and was not
built automatically; it was built separately for the linkage corroboration via
`meson compile -C build-windows-mi1b yuzu-agent` (meson target name, not the ninja path — `meson
compile -C build-windows-mi1b agents/core/yuzu-agent.exe` fails with "target not found"; worth noting
for whoever next tries this).

## Commands run

```bash
# fast-forward to origin/dev's tip
git fetch origin dev
git merge --ff-only origin/dev
git rev-parse HEAD origin/dev   # both printed f7a000fc33da5c715da133988ce986f10b01fc05

# MSVC + rig env (never vcvars64.bat)
source ./setup_msvc_env.sh
source /c/Users/daver/weecolin-env.sh

# fresh build dir (build-windows was locked by the live UAT rig, see above)
bash scripts/setup.sh --tests --builddir build-windows-mi1b

# targeted run: MI-1/MI-1b/MI-3 live in shard C (the AND-NOT complement of shards A/B,
# tags/partition rule per tests/meson.build), and --test-args is exact specifically for
# shard C (it ANDs against the whole comma-free spec there, unlike shards A/B)
meson test -C build-windows-mi1b "agent unit tests shard C" --test-args "[multi_image]" -v

# linkage corroboration
meson compile -C build-windows-mi1b yuzu-agent
dumpbin -dependents build-windows-mi1b/agents/core/yuzu-agent.exe
dumpbin -dependents build-windows-mi1b/agents/core/yuzu_agent_core.dll
dumpbin -dependents build-windows-mi1b/agents/plugins/agent_actions/agent_actions.dll
dumpbin -dependents build-windows-mi1b/tests/yuzu_agent_tests.exe
dumpbin -imports <each of the four, as above>
```

`--list-tests "[multi_image]"` against the (stale, pre-fast-forward) `build-windows` binary earlier
in this session had already shown exactly the expected 5 cases (MI-1 ×2, MI-1b(a), MI-1b(b), MI-3);
the real run reconfirmed the same 5 via the actual test execution below.

## Result: all 5 cases passed

```
All tests passed (23 assertions in 5 test cases)
1/1 agent+agent-shard - yuzu:agent unit tests shard C OK               0.13s
Ok:                1
Fail:              0
```

## WARN lines, verbatim

```
../tests/unit/test_log_handoff_multi_image.cpp(377): warning:
  MI-1b(b) verdict (before exe-image swap): a bare h->teardown() (library-only,
  no exe-image swap) ALREADY destroyed the sink - the exe-image logger swap in
  release_log_handoff_from_this_image() looks REDUNDANT (a defensive no-op) on
  this platform

../tests/unit/test_log_handoff_multi_image.cpp(331): warning:
  MI-1b(a) verdict: ONE registry (or at least this image's default-logger
  pointer already aliases the library's): LogHandoff::install() ALONE, with no
  exe-image redundant call, was enough for this image's own spdlog::info() to
  reach the sink

../tests/unit/test_log_handoff_multi_image.cpp(458): warning:
  MI-3: agent_actions's set_log_level(debug) DID change this image's installed
  LogHandoff level -- the plugin's spdlog::set_level() call reached this
  image's registered logger

../tests/unit/test_log_handoff_multi_image.cpp(236): warning:
  MI-1 finding: both the library-image probe and the test-image call reached
  the same capture sink after install_log_handoff_in_this_image() ran (does NOT
  by itself distinguish one shared registry from two separately-installed ones
  - see MI-1b)
```

## Report file, verbatim (`log_handoff_multi_image_topology.860.txt`, in `build-windows-mi1b/`)

```
#4666 PR-2 W3a MI-1b(b) measurement (the direct load-bearing-vs-no-op answer)
closed_after_bare_teardown=true
closed_after_exe_image_swap=true (REQUIRE'd above)
verdict: a bare h->teardown() (library-only, no exe-image swap) ALREADY destroyed the sink - the exe-image logger swap in release_log_handoff_from_this_image() looks REDUNDANT (a defensive no-op) on this platform
#4666 PR-2 W3a MI-1b(a) measurement
same_default_ptr=true
reached=true
verdict: ONE registry (or at least this image's default-logger pointer already aliases the library's): LogHandoff::install() ALONE, with no exe-image redundant call, was enough for this image's own spdlog::info() to reach the sink
#4666 PR-2 W3a MI-1 measurement (see MI-1b for the topology verdict)
saw_library_line=true
saw_test_line=true
finding: both the library-image probe and the test-image call reached the same capture sink after install_log_handoff_in_this_image() ran (does NOT by itself distinguish one shared registry from two separately-installed ones - see MI-1b)
raw capture (2 line(s)):
  - from library image
  - from test image
```

`same_default_ptr=true` is the decisive datum: MI-1b(a)'s raw measurement of
`spdlog::default_logger_raw() == h->logger().get()`, taken BEFORE the exe-image redundant
`set_default_logger` call ever runs, is `true` on Windows. That is a direct pointer-identity
observation, not an inference from linkage.

## Linkage corroboration (`dumpbin`)

All four images share `spdlogd.dll` (debug build) as a dependency:

| Binary | Dependencies include |
|---|---|
| `yuzu-agent.exe` | `yuzu_agent_core.dll`, `fmtd.dll`, **`spdlogd.dll`**, `sqlite3.dll`, ... |
| `yuzu_agent_core.dll` | `libssl-3-x64.dll`, `libcrypto-3-x64.dll`, `fmtd.dll`, **`spdlogd.dll`**, `sqlite3.dll`, ... |
| `agent_actions.dll` | `yuzu_agent_core.dll`, **`spdlogd.dll`**, `MSVCP140D.dll`, ... |
| `yuzu_agent_tests.exe` | `yuzu_agent_core.dll`, `libssl-3-x64.dll`, `fmtd.dll`, **`spdlogd.dll`**, `sqlite3.dll`, ... |

`dumpbin -imports` on each confirms the real analogue of macOS's `nm -m` evidence: every image
imports spdlog's **registry-wide, free-function** symbols — `?set_default_logger@spdlog@@...`,
`?default_logger_raw@spdlog@@...`, `?set_level@spdlog@@...` — from that same `spdlogd.dll`, not from
a private copy statically linked into each image. `yuzu-agent.exe`'s own import table additionally
shows `LogHandoff::install`/`::teardown`/`::create` resolving from `yuzu_agent_core.dll` (the
C++-mangled symbols), i.e. the exe genuinely calls back into the library image for the handoff
object itself, on top of sharing the library's spdlog registry.

This matches the premise in `triplets/x64-windows.cmake`: `VCPKG_LIBRARY_LINKAGE
dynamic` is the default and spdlog is not in the static-override list
(`abseil|grpc|protobuf|upb|re2|c-ares|utf8-range`); root `meson.build` builds spdlog as
`SPDLOG_COMPILED_LIB` via `spdlog_dep`, not header-only. The dynamic-linkage premise and the runtime
measurement agree; neither one is the sole evidence.

## Conclusion

**ONE shared spdlog registry on Windows — measured, not inferred, at `f7a000fc33da5c715da133988ce986f10b01fc05`.**
Every signal (MI-1, MI-1b(a), MI-1b(b), MI-3, and `dumpbin` linkage) points the same direction, with
no ambiguity or conflict between the sub-cases. This is the Linux shape, not the macOS shape — the
two-registry case `agent_log_wiring.hpp` defends against with its exe-image redundant
`set_default_logger` call does **not** arise on Windows, same as Linux. This does not change the
exit-code-5 fail-closed behavior either way — `swap_ok == false` on a failed swap still forces
`hard_exit(5)` regardless of registry topology.

The five doc sites that said "inferred... not directly measured" on Windows were updated to
"confirmed" in the same commit that adds this file.

**This is a point-in-time attestation, not a continuously-monitored control.** The fixture's
topology verdict is `WARN`-only by original design (the WARN/report mechanism predates this run
and was never meant to gate CI) — a future regression in this exact fact would not fail CI, only
show up in a Job Summary nobody is obliged to read. See "Scope and revisit triggers" below.

## Scope and revisit triggers

- **Measured on**: weecolin (a personal dev/test rig, Tailscale-reachable, distinct from the CI
  pool `yuzu-weetam-windows`/"Wee Tam" that the new CI step (`ci.yml`) surfaces this verdict on
  every run of). The first post-merge Wee Tam run reproduces this verdict on Wee Tam's own image;
  until then, "confirmed" rests on weecolin's toolchain matching Wee Tam's.
- **Build type**: debug only (`spdlogd.dll` naming). The underlying mechanism — dynamic linkage via
  `triplets/x64-windows.cmake`'s default (spdlog excluded from the static-override list) — is
  build-type-invariant by design, so this is corroboration for generalizing to release, not a
  release-build measurement itself.
- **spdlog version**: 1.17.0, pinned via the repo's vcpkg baseline at this SHA.
- **Revisit triggers**: a vcpkg baseline bump that changes spdlog's resolved version; any edit to
  `triplets/x64-windows.cmake`'s static-linkage override list that adds spdlog (the exact mechanism
  already used for grpc/protobuf/abseil, and for spdlog on macOS); a release, ASan, or TSan build of
  this fixture, none of which have been run against this specific claim; spdlog itself moving to a
  major version with a different default linkage posture.
- **Detection signal today**: none automated — the fixture's `WARN`-only design (by original intent,
  not introduced by this run) means a flip would show up only in the Windows CI job's summary.
  Giving the fixture a platform-conditional `REQUIRE`/`CHECK` on this specific claim is tracked
  separately rather than folded into this evidence file.

## Problems encountered

1. **Live UAT rig lock on `build-windows`**: not anticipated going in. Worked around with a
   second build directory (`build-windows-mi1b`, left on the box) rather than stopping the rig, which
   this session's own permission system denied. Future same-box runs should either coordinate with
   whoever owns that rig, or default straight to a side build directory.
2. **`meson compile -C <dir> <target>` wants the meson target name, not the ninja-style path** for a
   single non-default target like `yuzu-agent.exe` (built separately from the test run since it is
   not a dependency of `tests/yuzu_agent_tests.exe`): `agents/core/yuzu-agent.exe` is rejected
   ("target not found"); the bare meson target name `yuzu-agent` works.
3. Everything else in the recipe this run followed (fast-forward-then-verify SHA, `source` not pipe
   for the env scripts, Windows-native `scp` destination, dash-form `dumpbin` flags, the shard-C
   `--test-args`-is-exact claim) held exactly as expected — no other deviations.
