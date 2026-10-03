/**
 * test_runtimes_local_dispatcher.cpp -- loads the ACTUAL built runtimes plugin
 * (runtimes.dylib / .so / .dll) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher, exercising the real per-OS leg on the build host.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no platform guard on this TU (a
 * guarded dispatcher TU is how a sibling plugin once shipped a compiled-out
 * Windows leg and stayed green). Only the EXPECTATIONS differ per host, selected
 * with `#if` on the expectation, never on the test:
 *   Linux   -- status row first (supported or constrained, never unsupported),
 *              following rows five escape-aware fields. Mutation: removing the
 *              run_linux -> run_linux_at wiring leaves the stub `unsupported` row
 *              and fails the never-unsupported status assertion.
 *   macOS / Windows -- exactly `status|<action>|unsupported|<os>:planned`.
 * No host-specific count or name assertion for dotnet or jvm: CI runners are
 * unknown hosts where those runtimes may legitimately be absent. The populated
 * rows are asserted host-independently in test_runtimes_linux_parsers.cpp
 * (run_linux_at through a real CommandContext over the REAL CAPTURE fixture tree).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal '|' as '\|', so a
/// naive split('|') overcounts fields on any row whose text happens to contain a pipe.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the build is
/// genuinely broken and must NOT report "All tests passed".
///
/// getenv (not _dupenv_s) matches every sibling *_local_dispatcher.cpp's identical helper --
/// MSVC's C4996 is silenced locally rather than diverging from that shared idiom.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("runtimes plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("runtimes plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_runtimes_plugin() {
    const std::string lib_name = std::string{"runtimes"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "runtimes" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "runtimes" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "runtimes" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "runtimes" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_runtimes_plugin() {
    auto path = find_runtimes_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

constexpr const char* kActions[] = {"dotnet", "jvm"};

#if defined(_WIN32)
constexpr const char* kPlannedToken = "windows:planned";
#elif defined(__APPLE__)
constexpr const char* kPlannedToken = "macos:planned";
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
/// The fixed flavour vocabulary per action (runtimes_parsers.hpp banner).
bool is_flavour(const std::string& action, const std::string& f) {
    if (action == "dotnet") return f == "core" || f == "sdk" || f == "unmodelled";
    if (action == "jvm") return f == "jdk" || f == "jre" || f == "unmodelled";
    return false;
}
#endif

} // namespace

TEST_CASE("runtimes plugin: the status row is always first and well-formed",
          "[runtimes][actions]") {
    auto plugin = load_runtimes_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* a : kActions) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0); // a degraded read is never a failed command

        const auto rows = captured_rows(result.captured);
        // Every leg emits at least the status row, so a consumer never has to infer "no runtimes"
        // from silence.
        REQUIRE_FALSE(rows.empty());
        const auto st = split_fields_escape_aware(rows[0]);
        REQUIRE(st.size() == 4);
        CHECK(st[0] == "status");
        CHECK(st[1] == a);
        // No data row may precede the status row.
        for (std::size_t i = 1; i < rows.size(); ++i)
            CHECK(rows[i].rfind("status|", 0) != 0);
    }
}

TEST_CASE("runtimes plugin: an unknown action is refused, not silently ignored",
          "[runtimes][actions]") {
    auto plugin = load_runtimes_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
    // Deliberately not a data or status row: an unknown action has no status row. The
    // diagnostic is pinned. MUTATION: deleting or corrupting the `unknown action:` write in
    // runtimes_plugin.cpp, or falling through to a leg, fails here.
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");

    // The request-supplied name goes through safe_output_field: a pipe and a trailing
    // backslash can neither open a second field nor swallow the separator of what follows.
    const auto hostile = dispatcher.run(plugin->descriptor, "no|such\\");
    CHECK(hostile.rc != 0);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
    CHECK(split_fields_escape_aware(hrows[0]).size() == 1);
}

#if defined(_WIN32) || defined(__APPLE__)

TEST_CASE("runtimes plugin: the planned legs emit exactly the planned status row",
          "[runtimes][actions]") {
    auto plugin = load_runtimes_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* a : kActions) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + a + "|unsupported|" + kPlannedToken);
        // The typed status seam agrees: UNAVAILABLE / PARTIAL, the token as provenance.
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == kPlannedToken);
    }
}

#else // Linux

TEST_CASE("runtimes plugin: the Linux leg reads the host and never reports unsupported",
          "[runtimes][actions]") {
    auto plugin = load_runtimes_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* a : kActions) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto st = split_fields_escape_aware(rows[0]);
        REQUIRE(st.size() == 4);
        // The real leg is either `supported` (with `-`) or `constrained` (with reason tokens).
        // No shipped code path emits a `<os>:leg:not_implemented` placeholder: the check below is
        // the build-completeness tripwire the peripherals TU also carries.
        CHECK((st[2] == "supported" || st[2] == "constrained"));
        CHECK(rows[0].find(":leg:not_implemented") == std::string::npos);
        if (st[2] == "supported") {
            CHECK(st[3] == "-");
            CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        } else {
            CHECK_FALSE(st[3].empty());
            CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == st[3]);
        }

        for (std::size_t i = 1; i < rows.size(); ++i) {
            INFO("row: " << rows[i]);
            const auto f = split_fields_escape_aware(rows[i]);
            REQUIRE(f.size() == 5);
            CHECK(f[0] == a);
            CHECK(is_flavour(a, f[1]));
        }
    }
}

#endif
