/**
 * test_script_exec_actions.cpp -- script_exec's FIRST end-to-end test.
 * Loads the ACTUAL built script_exec plugin (script_exec.dylib/.so, the
 * same artifact the agent daemon loads in production) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher --
 * the same pattern test_users_posix_actions.cpp established, this plugin's
 * POSIX counterpart. Unlike test_script_exec_parsers.cpp (pure, no OS
 * calls), this exercises the real
 * yuzu::agent::run_bounded_subprocess round trip against the real
 * `/bin/echo`/`/bin/bash` binaries on the test host -- every assertion
 * below would fail if the migration's argv, mode dispatch, or wire mapping
 * were wrong.
 *
 * script_exec needs no plugin init to exercise its exec/bash actions (its
 * init() is a no-op -- no storage/g_ctx use anywhere in the migrated
 * paths), so, unlike some other LocalDispatcher suites, there is no
 * init-call step here at all.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at
// script_exec's own build output.
fs::path find_script_exec_plugin() {
    const std::string lib_name = std::string{"script_exec"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "script_exec" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "script_exec" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "script_exec" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_script_exec_plugin() {
    auto plugin_path = find_script_exec_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

} // namespace

TEST_CASE("script_exec plugin: exec streams real /bin/echo output through the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"command", "/bin/echo"}, {"args", "happy path"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    // Reverting the migration (wrong argv, a mode that never calls the
    // runner, or a broken wire mapping) would either fail this call or
    // produce a captured buffer missing one of these three lines -- this
    // only passes if the real runner-mediated argv actually ran.
    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|happy path");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    // Wire ordering contract: streamed output first, then exit_code, then
    // status — a future change reordering these should fail this test, not
    // just prove the three tokens exist somewhere in the buffer.
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin: bash runs the script as a single argv element through the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"script", "echo hi"}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|hi");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin: exec with an unresolvable bare command reports status|error "
          "without ever calling the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A bare name with no separator that resolve_executable's real PATH
    // search will not find on any normal test host -- exercises the
    // early-return path (no subprocess spawn attempted at all).
    std::vector<YuzuParam> params{{"command", "yuzu-test-definitely-missing-binary-xyz"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc == 1);
    auto status_pos = result.captured.find("status|error");
    auto exit_pos = result.captured.find("exit_code|-1");
    REQUIRE(status_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    // The early-setup-failure shape is the REVERSE of the post-runner-return
    // order above: status before exit_code (see do_exec's own comment).
    CHECK(status_pos < exit_pos);
}

TEST_CASE("script_exec plugin: a blank stdout line still streams its own stdout| wire record "
          "(A2-002 escalation, A2-006)",
          "[script_exec][actions][streaming]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // printf interprets the \n escapes; the middle one produces a completed,
    // BLANK stdout line between "a" and "b". Before the runner-level A2-006
    // fix, store_line() dropped a blank line before ever invoking on_line,
    // so the middle "stdout|" record below would be missing entirely.
    std::vector<YuzuParam> params{{"script", "printf 'a\\n\\nb\\n'"}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.rc == 0);
    // Substring match on the exact three-line block (not just each token
    // independently) so a bare "stdout|" existing only as a PREFIX of
    // "stdout|a" can't false-positive this assertion.
    CHECK(result.captured.find("stdout|a\nstdout|\nstdout|b") != std::string::npos);
    CHECK(result.captured.find("exit_code|0") != std::string::npos);
    CHECK(result.captured.find("status|ok") != std::string::npos);
}

TEST_CASE("script_exec plugin: a runner-level spawn_error reaches the ABI4 result-status seam "
          "(BR-001: forward_runner_failure must not be flattened away)",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    // A regular, executable, absolute file that resolve_executable's own
    // is_executable_probe (regular file + access(X_OK)) happily accepts --
    // so do_exec reaches run_bounded_subprocess -- but whose shebang names
    // an interpreter that cannot possibly exist. execve() itself then
    // fails (ENOENT resolving the interpreter), which the runner reports
    // as termination_reason::spawn_error / tool_ran=false, never as an
    // ordinary nonzero exit. Deterministic and immediate: no timing/sleep
    // dependency, matching this suite's no-wall-clock discipline.
    yuzu::test::TempDir dir("yuzu_test_script_exec_spawn_error_");
    // TempDir only reserves a unique path -- it does not create the
    // directory itself (test_helpers.hpp), so create it before writing
    // into it.
    REQUIRE(fs::create_directories(dir.path));
    auto script_path = dir.path / "bad-shebang.sh";
    {
        std::ofstream f(script_path);
        f << "#!/yuzu-test-definitely-nonexistent-interpreter-xyz\necho hi\n";
    }
    REQUIRE(::chmod(script_path.c_str(), 0700) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    // YuzuParam holds raw const char*, not std::string -- keep the backing
    // string alive across the dispatcher.run() call below rather than
    // binding a temporary's .c_str() into the params vector.
    const std::string script_path_str = script_path.string();
    std::vector<YuzuParam> params{{"command", script_path_str.c_str()}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc != 0);
    CHECK(result.captured.find("status|error") != std::string::npos);
    // The actual assertion this test exists for: forward_runner_failure's
    // ctx.set_result_status() call reached the SAME CommandContextImpl the
    // wire lines above came from -- not just that do_exec/run_via_runner
    // called it, which a grep could already confirm.
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "subprocess_runner:spawn_error");
}

namespace {

// RAII save/restore for a single environment variable this test mutates --
// every other TEST_CASE in this file (and the plugin's own PATH-based
// resolve_executable search, exercised elsewhere above) must never observe
// the altered environment this test deliberately constructs.
struct EnvRestore {
    std::string name;
    std::optional<std::string> saved;

    explicit EnvRestore(std::string env_name) : name(std::move(env_name)) {
        if (const char* v = std::getenv(name.c_str()))
            saved = std::string{v};
    }
    ~EnvRestore() {
        if (name.empty()) // moved-from
            return;
        if (saved)
            ::setenv(name.c_str(), saved->c_str(), 1);
        else
            ::unsetenv(name.c_str());
    }
    EnvRestore(const EnvRestore&) = delete;
    EnvRestore& operator=(const EnvRestore&) = delete;
    EnvRestore(EnvRestore&& other) noexcept : name(std::move(other.name)), saved(std::move(other.saved)) {
        other.name.clear(); // moved-from: destructor becomes a no-op restore of ""
    }
    EnvRestore& operator=(EnvRestore&&) = delete;
};

} // namespace

TEST_CASE("script_exec plugin: bash forwards the parent's POSIX 7-name env allow-list "
          "exactly -- PATH/LC_ALL forced to empty-string when unset in the parent, the "
          "other five passed through verbatim (parent_env_allowlist, run_via_runner)",
          "[script_exec][actions][env]") {
    auto plugin = load_script_exec_plugin();
    REQUIRE(plugin.has_value());

    // Save+restore every one of the seven allow-listed names around this
    // test's deliberate mutation.
    std::vector<EnvRestore> restores;
    for (const char* n : {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TZ"})
        restores.emplace_back(n);

    // PATH and LC_ALL: deliberately UNSET in the parent -- the case
    // parent_env_allowlist()'s empty-string-override branch exists for
    // (is_runner_defaulted()). The other five: set to unique, known values
    // so an accidental swap/drop between allow-list entries is caught.
    ::unsetenv("PATH");
    ::unsetenv("LC_ALL");
    ::setenv("HOME", "/yuzu-test-home", 1);
    ::setenv("USER", "yuzu-test-user", 1);
    ::setenv("LANG", "yuzu_test_LANG.UTF-8", 1);
    ::setenv("TERM", "yuzu-test-term", 1);
    ::setenv("TZ", "yuzu/Test-TZ", 1);

    yuzu::agent::LocalDispatcher dispatcher;
    // Echo all seven names, each bracketed so an EMPTY value is visibly
    // distinguishable from an OMITTED one in the captured wire text --
    // exactly the distinction this allow-list's empty-string-override
    // behaviour must preserve for PATH/LC_ALL.
    std::vector<YuzuParam> params{
        {"script", "printf 'PATH=[%s]\\nHOME=[%s]\\nUSER=[%s]\\nLANG=[%s]\\nLC_ALL=[%s]\\n"
                   "TERM=[%s]\\nTZ=[%s]\\n' \"$PATH\" \"$HOME\" \"$USER\" \"$LANG\" \"$LC_ALL\" "
                   "\"$TERM\" \"$TZ\""}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.rc == 0);
    CHECK(result.captured.find("stdout|PATH=[]") != std::string::npos);
    CHECK(result.captured.find("stdout|HOME=[/yuzu-test-home]") != std::string::npos);
    CHECK(result.captured.find("stdout|USER=[yuzu-test-user]") != std::string::npos);
    CHECK(result.captured.find("stdout|LANG=[yuzu_test_LANG.UTF-8]") != std::string::npos);
    CHECK(result.captured.find("stdout|LC_ALL=[]") != std::string::npos);
    CHECK(result.captured.find("stdout|TERM=[yuzu-test-term]") != std::string::npos);
    CHECK(result.captured.find("stdout|TZ=[yuzu/Test-TZ]") != std::string::npos);
    CHECK(result.captured.find("exit_code|0") != std::string::npos);
    CHECK(result.captured.find("status|ok") != std::string::npos);
}

TEST_CASE("script_exec plugin: bash's independent 16 MiB streaming-cap counter (on_line, "
          "run_via_runner) truncates exactly once and keeps draining the child afterward "
          "rather than hanging",
          "[script_exec][actions][streaming]") {
    auto plugin = load_script_exec_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A single 1024-byte line, repeated via `yes | head` (fast -- no
    // per-iteration bash loop overhead) well past run_via_runner's own
    // on_line byte counter (kMaxOutputBytes == 16 MiB, counted as
    // line.size()+1 per completed line -- a SEPARATE counter from the
    // runner's own output_cap_bytes, which is also 16 MiB but bounds the
    // runner's internal captured buffer, not this caller-side stream:
    // on_line sees every line "regardless of any runner-side cap" per its
    // own comment). 16500 * 1025 bytes ~= 16.9 MiB, safely over the
    // 16,777,216-byte boundary. The marker line emitted AFTER the flood
    // proves the runner kept draining the child's stdout -- and the child
    // ran all the way to its own real exit -- even once on_line started
    // suppressing every further stdout| wire record.
    std::vector<YuzuParam> params{
        {"script", "line=$(printf 'a%.0s' $(seq 1 1024)); yes \"$line\" | head -n 16500; "
                   "echo AFTER-TRUNCATION-MARKER"}};
    // LocalDispatcher's OWN capture buffer defaults to a 2 MiB cap
    // (kCaptureMaxBytes, local_dispatcher.hpp) -- a SEPARATE, unrelated cap
    // from the plugin's 16 MiB on_line counter this test exists to exercise.
    // Left at the default, LocalDispatcher would truncate the captured wire
    // text well before the plugin's own sentinel (which lands ~16.8 MiB in)
    // ever appears, hiding the very behaviour under test. Pass a generous
    // explicit cap so this test observes the plugin's OWN truncation
    // decision, not the harness's.
    auto result = dispatcher.run(plugin->descriptor, "bash", params, 32ull * 1024 * 1024);

    CHECK(result.rc == 0);
    const std::string sentinel = "stdout|[output truncated — exceeded 16 MiB limit]";
    std::size_t sentinel_count = 0;
    for (std::size_t pos = result.captured.find(sentinel); pos != std::string::npos;
        pos = result.captured.find(sentinel, pos + sentinel.size()))
        ++sentinel_count;
    // Boundary respected: the cap fires exactly once, not once per
    // over-budget line.
    CHECK(sentinel_count == 1);
    // Every line after truncation is suppressed -- the marker written after
    // the flood must never reach the captured wire text.
    CHECK(result.captured.find("AFTER-TRUNCATION-MARKER") == std::string::npos);
    // The runner kept draining the child (rather than deadlocking on a full
    // pipe once on_line stopped consuming meaningfully) all the way to its
    // real exit -- proven by the ordinary post-run wire lines still landing.
    CHECK(result.captured.find("exit_code|0") != std::string::npos);
    CHECK(result.captured.find("status|ok") != std::string::npos);
}

TEST_CASE("script_exec plugin: a short timeout triggers the runner's soft-terminate SIGTERM, "
          "the child's trap fires, and the wire maps to status|timeout with the runner's "
          "typed deadline provenance",
          "[script_exec][actions][timeout]") {
    auto plugin = load_script_exec_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // timeout=1 -> run_via_runner's opts.deadline = 1s; script_exec's own
    // fixed opts.soft_terminate_grace = 10s (run_via_runner's own comment)
    // means the runner sends SIGTERM (not SIGKILL) at the 1s deadline and
    // waits for a voluntary exit. The trap below catches it, writes a
    // marker so the wire text proves the SIGTERM actually reached the
    // child (not just that the deadline elapsed), and exits immediately --
    // so this test's real wall time is ~1s, not anywhere near the full 10s
    // grace window.
    std::vector<YuzuParam> params{
        {"script", "trap 'echo TRAP-FIRED; exit 0' TERM; sleep 30"}, {"timeout", "1"}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.captured.find("stdout|TRAP-FIRED") != std::string::npos);
    CHECK(result.captured.find("status|timeout") != std::string::npos);
    // The runner's own typed classification for this outcome
    // (classify_runner_failure, runner_status.hpp) -- proves
    // forward_runner_failure actually reached the ABI4 seam with the
    // DEADLINE reason specifically, not merely that the wire text says
    // "timeout".
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "subprocess_runner:deadline");
}

#endif // !_WIN32
