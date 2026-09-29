/**
 * test_content_dist_exec_seam_win.cpp -- whole-branch review round 3
 * (BR3-003): the Windows twin of test_content_dist_exec_seam.cpp (BR-006,
 * round 2), which is a `#ifndef _WIN32` TU. content_dist's Windows launcher
 * is one of the two private per-plugin spawn paths this branch replaces
 * with yuzu::agent::run_bounded_subprocess, and it had no coverage at all
 * on the changed backend -- everything below (argv assembly, the
 * `is_windows` branch of build_execution_options, and SubprocessResult ->
 * wire-line mapping) ran unexercised on Windows.
 *
 * Drives execute_verified_payload() (content_dist_exec_seam.hpp) directly
 * against a REAL staged file, same shape and same reason as the POSIX
 * suite: content_dist_plugin.cpp's `g_ctx` is set only by the plugin's real
 * `init()`, which the LocalDispatcher test harness never calls, so there is
 * no legitimate way to drive a real, hash-verified `execute_staged` through
 * the actual runner call at the plugin-ABI level. This calls the
 * post-hash-verification logic directly instead -- a real copied
 * executable payload, a real run_bounded_subprocess spawn, real result
 * mapping -- no plugin load, no LocalDispatcher, no g_ctx.
 *
 * Windows-only; a no-op TU elsewhere via this file's own #ifdef _WIN32
 * guard.
 *
 * DISCLOSED: never executed on this host (macOS) -- only the Windows CI leg
 * runs this suite, which is the actual enforcement point for a
 * Windows-only backend.
 */
#include <catch2/catch_test_macros.hpp>

#ifdef _WIN32

#include "content_dist_exec_seam.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::windows_system_directory (BR4-005)

#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::content_dist::exec;

namespace {

bool contains_line(const std::vector<std::string>& lines, std::string_view needle) {
    return std::any_of(lines.begin(), lines.end(),
                       [&](const std::string& l) { return l.find(needle) != std::string::npos; });
}

// BR4-005 (whole-branch review round 4): runtime-resolved via
// yuzu::agent::windows_system_directory() rather than a hard-coded
// "C:\\Windows\\System32\\cmd.exe" literal -- the hard-coded form fails
// every TEST_CASE below (fs::copy_file can't find the source) before ever
// exercising anything on the relocated-system (non-`C:`) configuration
// BR3-001's runtime resolution fix exists to protect.
std::string real_cmd_exe() {
    return yuzu::agent::windows_system_directory() + "\\cmd.exe";
}

} // namespace

TEST_CASE("execute_verified_payload (Windows) runs a REAL staged native executable through the "
          "actual runner call, end to end (BR3-003)",
          "[agent][content_dist][exec_seam][windows]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_win_");
    fs::create_directories(dir.path);
    // A copied real Windows executable, same technique as the POSIX suite's
    // /bin/echo copy -- unlike macOS, a copy elsewhere on disk is not
    // blocked from executing by platform code-signing (no AMFI-style
    // path-sealing on Windows), so this stages a genuine PE binary rather
    // than a fixture stand-in.
    fs::path payload = dir.path / "staged-cmd.exe";
    std::error_code copy_ec;
    fs::copy_file(real_cmd_exe(), payload, fs::copy_options::overwrite_existing,
                  copy_ec);
    REQUIRE_FALSE(copy_ec);

    // is_linux=false (this is the real, only compile target for this TU),
    // is_windows=true -- exactly build_execution_options' own contract
    // (never a runtime guess). cmd.exe's own /c reassembles the rest of
    // the runner's reconstructed command line into one command, so this
    // exercises the real argv[0]-is-the-payload spawn path plus the
    // runner's argv->command-line quoting together.
    ExecutionOutcome outcome =
        execute_verified_payload(payload, "/c echo hello-from-test", /*is_linux=*/false,
                                 /*is_windows=*/true);

    CHECK(outcome.rc == 0);
    REQUIRE(outcome.run.has_value());
    CHECK(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|ok"));
    CHECK(contains_line(outcome.lines, "exit_code|0"));
}

TEST_CASE("execute_verified_payload (Windows) reports a real spawn failure for a nonexistent "
          "staged path (BR3-003)",
          "[agent][content_dist][exec_seam][windows]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_win_");
    fs::path payload = dir.path / "never-staged.exe"; // deliberately never created

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", /*is_linux=*/false, /*is_windows=*/true);

    CHECK(outcome.rc == -1); // map_execution_result's spawn_error sentinel
    REQUIRE(outcome.run.has_value());
    CHECK_FALSE(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|error"));
    CHECK(contains_line(outcome.lines, "exit_code|-1"));
}

TEST_CASE("execute_verified_payload (Windows) rejects args containing shell metacharacters "
          "before ever reaching the runner (BR3-003)",
          "[agent][content_dist][exec_seam][windows]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_win_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-cmd.exe";
    std::error_code copy_ec;
    fs::copy_file(real_cmd_exe(), payload, fs::copy_options::overwrite_existing,
                  copy_ec);
    REQUIRE_FALSE(copy_ec);

    ExecutionOutcome outcome = execute_verified_payload(payload, "hi & del /f C:\\*",
                                                        /*is_linux=*/false, /*is_windows=*/true);

    CHECK(outcome.rc == 1);
    CHECK_FALSE(outcome.run.has_value()); // never reached the runner
    REQUIRE(outcome.lines.size() == 1);
    CHECK(outcome.lines[0].find("forbidden characters") != std::string::npos);
}

#endif // _WIN32
