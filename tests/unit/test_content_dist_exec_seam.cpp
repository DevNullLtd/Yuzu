/**
 * test_content_dist_exec_seam.cpp -- BR-006 (whole-branch review round 2):
 * real end-to-end coverage of content_dist_exec_seam.hpp's
 * execute_verified_payload(), the extracted post-hash-verification logic
 * `do_execute` (content_dist_plugin.cpp) runs for `execute_staged`.
 *
 * WHY THIS FILE EXISTS: test_content_dist_actions.cpp's header comment
 * documents a real testability wall -- content_dist_plugin.cpp's `g_ctx`
 * (agent KV) is set only by the plugin's real `init()`, which the
 * LocalDispatcher test harness never calls, so no existing test could drive
 * a real, hash-verified `execute_staged` through the actual runner call.
 * That gap meant a defect in the call-site WIRING between
 * build_execution_options/run_bounded_subprocess/map_execution_result --
 * exactly the shape BR-001 (POSIX inherit_parent_env silently narrowing the
 * child's environment) turned out to be -- could ship with every existing
 * content_dist test green. execute_verified_payload() (content_dist_exec_
 * seam.hpp) is do_execute's logic minus the KV/plugin-ABI dependency, so
 * this file drives it directly against a REAL staged file: a real chmod, a
 * real fork/exec through yuzu::agent::run_bounded_subprocess, real result
 * mapping -- no plugin load, no LocalDispatcher, no g_ctx anywhere in the
 * call path.
 *
 * POSIX-only (a no-op TU on Windows via the #ifndef _WIN32 guard below),
 * same shape as test_content_dist_actions.cpp and test_users_posix_actions.cpp.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "content_dist_exec_seam.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/runner_status.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::content_dist::exec;

namespace {

#ifdef __linux__
constexpr bool kIsLinux = true;
#else
constexpr bool kIsLinux = false;
#endif

bool contains_line(const std::vector<std::string>& lines, std::string_view needle) {
    return std::any_of(lines.begin(), lines.end(),
                       [&](const std::string& l) { return l.find(needle) != std::string::npos; });
}

#ifdef __linux__
// Locate the echo_argv_fixture binary built by tests/meson.build. Same
// candidate-path convention as test_plugin_loader.cpp's
// find_fixture_plugin() (Meson launches tests with CWD=build root; the
// fixture sits alongside the test executable in tests/).
fs::path find_echo_argv_fixture() {
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "tests" / "echo_argv_fixture");
    candidates.emplace_back(fs::path{"tests"} / "echo_argv_fixture");
    candidates.emplace_back(fs::path{"."} / "echo_argv_fixture");
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}
#endif

} // namespace

TEST_CASE("execute_verified_payload runs a REAL staged native executable through the actual "
          "runner call, end to end (BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-echo";
#ifdef __linux__
    // Linux: is_linux=true below means CDX-002 would reject a shebang
    // script AND B6 exec_verify (fd-exec) is live, so the payload must be a
    // genuine native ELF -- copy the dedicated, deterministic fixture
    // binary (tests/fixtures/echo_argv_fixture.cpp), NOT the host's /bin/echo.
    // A prior version of this test copied /bin/echo directly and failed on
    // real Linux CI (2026-08-31): that host's /bin/echo is a GNU coreutils
    // multi-call binary, which dispatches by inspecting /proc/self/exe --
    // B6's fd-based execveat(fd, "", ..., AT_EMPTY_PATH) exec presents
    // /proc/self/exe as an fd-numbered path rather than a real one, so
    // coreutils tried to dispatch to a utility literally named after the fd
    // number and failed with "coreutils: unknown program '13'". The
    // dedicated fixture has no argv[0]/exe-path-sensitive dispatch to break.
    fs::path fixture = find_echo_argv_fixture();
    REQUIRE_FALSE(fixture.empty());
    std::error_code copy_ec;
    fs::copy_file(fixture, payload, fs::copy_options::overwrite_existing, copy_ec);
    REQUIRE_FALSE(copy_ec);
#else
    // macOS: copying a system binary like /bin/echo is NOT a valid fixture
    // here -- Apple's platform-binary code-signing protection SIGKILLs a
    // byte-copy at exec (verified independently of this test: `codesign -dv`
    // on the copy shows the same embedded "Platform identifier" as the
    // original, and Apple Silicon's AMFI refuses to run a platform binary's
    // signature from an unsealed path). is_linux=false on this leg anyway,
    // so CDX-002 never fires and B6 exec_verify is disabled -- a shebang
    // script is a perfectly genuine fixture here: the KERNEL handles "#!"
    // translation directly inside execve() (no shell re-exec, no PATH
    // search), so this still exercises the real argv[0]-is-the-payload
    // spawn path exactly as a native binary would.
    { std::ofstream out(payload, std::ios::binary); out << "#!/bin/sh\necho \"$@\"\n"; }
#endif

    // is_linux mirrors the ACTUAL compile target here (unlike the shebang-
    // gate test below) -- this exercises the real B6 exec_verify path on a
    // real Linux CI leg, and the real "exec_verify never enabled" path
    // everywhere else, exactly as do_execute does at its own call site.
    ExecutionOutcome outcome =
        execute_verified_payload(payload, "hello-from-test", kIsLinux, /*is_windows=*/false);

    // UNSCOPED_INFO prints unconditionally on any CHECK/REQUIRE failure
    // below in this test case -- added after a real CI-only failure here
    // (2026-08-31) that the bare CHECK expressions alone couldn't diagnose:
    // outcome.rc != 0 with none of the expected lines present, but no local
    // repro (root/non-root, plain /tmp, real code path all reproduced
    // clean) ever reproduced the same failure, meaning something about
    // this specific value set is the only lead into what differs on the
    // runner that hit it.
    UNSCOPED_INFO("outcome.rc=" << outcome.rc);
    UNSCOPED_INFO("outcome.run.has_value()=" << outcome.run.has_value());
    if (outcome.run) {
        UNSCOPED_INFO("tool_ran=" << outcome.run->tool_ran);
        UNSCOPED_INFO("run.exit_code=" << outcome.run->exit_code);
        UNSCOPED_INFO("termination_reason=" << static_cast<int>(outcome.run->termination_reason));
        UNSCOPED_INFO("spawn_errno=" << outcome.run->spawn_errno);
        UNSCOPED_INFO("raw output=[" << outcome.run->output << "]");
    }
    {
        std::string joined;
        for (auto& l : outcome.lines) {
            joined += "[";
            joined += l;
            joined += "] ";
        }
        UNSCOPED_INFO("outcome.lines=" << joined);
    }

    CHECK(outcome.rc == 0);
    REQUIRE(outcome.run.has_value());
    CHECK(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|ok"));
    CHECK(contains_line(outcome.lines, "exit_code|0"));
    // /bin/echo writes its argv back out -- proves argv assembly (payload
    // path as argv[0], split_args(args) appended) actually wired through to
    // the real spawned child, not just that SOME child ran.
    CHECK(contains_line(outcome.lines, "hello-from-test"));
}

TEST_CASE("execute_verified_payload reports a real spawn failure for a nonexistent staged path "
          "(BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::path payload = dir.path / "never-staged"; // deliberately never created

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", kIsLinux, /*is_windows=*/false);

    CHECK(outcome.rc == -1); // map_execution_result's spawn_error sentinel
    REQUIRE(outcome.run.has_value());
    CHECK_FALSE(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|error"));
    CHECK(contains_line(outcome.lines, "exit_code|-1"));
}

TEST_CASE("execute_verified_payload rejects a shebang-interpreted payload before ever reaching "
          "the runner (CDX-002, BR-006)",
          "[agent][content_dist][exec_seam]") {
    // The shebang gate is pure file-content logic (reads two bytes, no
    // exec_verify/runner call happens before it can reject) -- forcing
    // is_linux=true here exercises it on every host this suite runs on,
    // not just an actual Linux leg, exactly like
    // test_content_dist_exec_parsers.cpp's is_shebang_payload fixtures do
    // for the pure predicate this call-site gate wraps.
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-script.sh";
    {
        std::ofstream out(payload, std::ios::binary);
        out << "#!/bin/sh\necho hi\n";
    }

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", /*is_linux=*/true, /*is_windows=*/false);

    CHECK(outcome.rc == 1);
    // Rejected before the runner was ever invoked -- no SubprocessResult to
    // forward through the ABI4 result-status seam.
    CHECK_FALSE(outcome.run.has_value());
    REQUIRE(outcome.lines.size() == 1);
    CHECK(outcome.lines[0].find("script payloads (shebang) are not supported") != std::string::npos);
}

TEST_CASE("execute_verified_payload rejects args containing shell metacharacters before ever "
          "reaching the runner (BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-echo";
    std::error_code copy_ec;
    fs::copy_file("/bin/echo", payload, fs::copy_options::overwrite_existing, copy_ec);
    REQUIRE_FALSE(copy_ec);

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "hi; rm -rf /", kIsLinux, /*is_windows=*/false);

    CHECK(outcome.rc == 1);
    CHECK_FALSE(outcome.run.has_value()); // never reached the runner
    REQUIRE(outcome.lines.size() == 1);
    CHECK(outcome.lines[0].find("forbidden characters") != std::string::npos);
}

// ── ABI4 result-status forwarding (finding: content_dist's do_execute
// forward_runner_failure call has zero end-to-end coverage) ────────────────
//
// GENUINE WALL, not a shortcut: content_dist_plugin.cpp's do_execute reads
// the #808 hash-verification KV entry via `yuzu::PluginContext pctx{g_ctx};`,
// and `g_ctx` is set ONLY by the plugin's real `init()` -- which
// LocalDispatcher never calls (agent.cpp's dispatch_with_capture invokes
// `descriptor->execute` directly, per local_dispatcher.cpp's own header
// comment; there is no init-call step, unlike a plugin that needs none).
// do_stage (the only other action that could seed that KV entry) has the
// IDENTICAL g_ctx dependency PLUS a real network download, so there is no
// way to legitimately seed a real KV row through LocalDispatcher either.
// The result: content_dist's do_execute cannot be driven end-to-end through
// LocalDispatcher at all -- not just its post-hash-verification tail, which
// is exactly why content_dist_exec_seam.hpp/execute_verified_payload()
// exists (BR-006, this file's own header comment) -- the KV gate is BEFORE
// that extraction point, not inside it. A real integration/UAT-level test
// (a live agent process, real init()) is the only place this specific call
// site (`if (outcome.run) yuzu::agent::forward_runner_failure(ctx,
// *outcome.run);` in do_execute) can be driven with a real
// yuzu::CommandContext -- there is no unit-level construction path for a
// live CommandContextImpl outside agent.cpp's dispatch_with_capture shim
// (it carries gRPC-typed streaming fields, local_dispatcher.cpp's own
// comment), and asserting on it here would require exactly the kind of
// stand-in this task rules out.
//
// What IS provably closable at this level, and is added below: the DATA
// forward_runner_failure receives at content_dist's real call site is
// correct. execute_verified_payload's `outcome.run` (populated by a REAL
// run_bounded_subprocess spawn against a REAL nonexistent staged path, not
// a fixture-constructed SubprocessResult like test_runner_status.cpp uses)
// classifies through the SAME classify_runner_failure() forward_runner_
// failure calls internally to the SAME UNAVAILABLE/PARTIAL/"subprocess_
// runner:spawn_error" triplet script_exec's own spawn_error case already
// proves reaches a live CommandContextImpl end to end (test_script_exec_
// actions.cpp, "a runner-level spawn_error reaches the ABI4 result-status
// seam") via the byte-identical one-line `forward_runner_failure(ctx, run)`
// pattern every migrated mutating plugin uses (this file's own do_execute
// comment names services_plugin.cpp / network_actions_plugin.cpp /
// interaction_plugin.cpp / script_exec_plugin.cpp as the same shape). This
// closes the gap down to "does content_dist's own do_execute actually make
// the call" -- a one-line, always-executed statement immediately downstream
// of `outcome.run` being populated, gated only on the same `if (outcome.run)`
// this test already exercises via execute_verified_payload's own return
// value.
TEST_CASE("execute_verified_payload's real spawn_error outcome classifies through the SAME "
          "chokepoint forward_runner_failure uses at content_dist's do_execute call site "
          "(UNAVAILABLE/PARTIAL/subprocess_runner:spawn_error)",
          "[agent][content_dist][exec_seam][abi4]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_abi4_");
    fs::path payload = dir.path / "never-staged"; // deliberately never created

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", kIsLinux, /*is_windows=*/false);

    REQUIRE(outcome.run.has_value());
    CHECK_FALSE(outcome.run->tool_ran);
    CHECK(outcome.run->termination_reason == yuzu::agent::TerminationReason::spawn_error);

    // The exact call classify_runner_failure() makes inside
    // forward_runner_failure(ctx, *outcome.run) at content_dist's real
    // do_execute call site.
    auto classified = yuzu::agent::classify_runner_failure(*outcome.run);
    REQUIRE(classified.has_value());
    CHECK(classified->status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(classified->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(classified->provenance) == "subprocess_runner:spawn_error");
}

#endif // !_WIN32
