/**
 * test_process_introspect_local_dispatcher.cpp -- loads the ACTUAL built process_introspect plugin
 * via PluginHandle::load and drives `inspect` through yuzu::agent::LocalDispatcher, so the real
 * per-OS leg executes on the build host. Modelled on test_remote_access_audit_local_dispatcher.cpp.
 *
 * UNGUARDED TU on all three platforms; only the per-OS assertions inside a test body are #if'd.
 * The Linux cases inspect the test process's OWN pid (nothing is spawned) and assert shape only,
 * never host values: which capabilities and limits a CI runner holds is unknown. Shape includes
 * the facet's row kinds and counts, and a fully readable own process answering supported: a
 * process always reads its own five /proc files, so a constrained answer there is a defect.
 *
 * Tagged [process_introspect] ONLY: a carved tag would move a case to another shard.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "pkg_inventory_test_support.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using yuzu::test::pkg_inventory_support::captured_rows;

namespace {

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("process_introspect plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("process_introspect plugin library not found -- skipping the LocalDispatcher round-trip");
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

fs::path find_plugin() {
    const std::string lib_name = std::string{"process_introspect"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "process_introspect" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "process_introspect" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "process_introspect" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "process_introspect" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_plugin() {
    auto path = find_plugin();
    if (path.empty())
        return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded)
        return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d)
        return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

yuzu::agent::LocalDispatcher::Result inspect(const LoadedPlugin& plugin, const std::string& pid,
                                             const std::string& facet,
                                             const std::string& start_time = {}) {
    std::vector<YuzuParam> params;
    params.push_back({"pid", pid.c_str()});
    if (!facet.empty())
        params.push_back({"facet", facet.c_str()});
    if (!start_time.empty())
        params.push_back({"start_time", start_time.c_str()});
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(plugin.descriptor, "inspect", params);
}

std::string own_pid() {
#if defined(__linux__)
    return std::to_string(static_cast<long>(::getpid()));
#else
    return "1";
#endif
}

} // namespace

TEST_CASE("process_introspect plugin: one action, Linux constrained, macOS and Windows planned",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    CHECK(std::string_view{plugin->descriptor->name} == "process_introspect");
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    REQUIRE(plugin->descriptor->action_descriptor_count == 1);
    const auto& d = plugin->descriptor->action_descriptors[0];
    CHECK(std::string_view{d.action} == "inspect");
    CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_PLANNED);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_PLANNED);
}

TEST_CASE("process_introspect plugin: an unknown action is refused with one non-status line",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");
}

TEST_CASE("process_introspect plugin: invalid parameters are refused with a typed token on every OS",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    struct Case {
        std::string pid, facet, start_time, token;
    };
    const Case cases[] = {
        {"abc", "caps", "", "process_introspect:invalid_pid"},
        {"", "caps", "", "process_introspect:invalid_pid"},
        {"4242", "", "", "process_introspect:invalid_facet"},
        {"4242", "all", "", "process_introspect:invalid_facet"},
        {"4242", "caps", "zz", "process_introspect:invalid_start_time"},
    };
    for (const auto& c : cases) {
        const auto r = inspect(*plugin, c.pid, c.facet, c.start_time);
        INFO(c.token);
        CHECK(r.rc == 1);
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|inspect|unavailable|" + c.token);
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    }
}

#if defined(__linux__)

TEST_CASE("process_introspect plugin (Linux): each facet of the test's own pid has the closed shape",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    static const std::regex row_shape{R"(^[a-z_]+(\|[a-z0-9_.,:-]+)*$)"};
    // Per facet: the row kind that every facet row starts with and the allowed row count.
    struct Shape {
        const char* facet;
        const char* prefix;
        std::size_t min_rows, max_rows;
    };
    const Shape shapes[] = {{"resource_limits", "limit|", 1, 16}, {"sigmasks", "sigmask|", 5, 5},
                            {"caps", "cap|", 5, 5},               {"seccomp", "seccomp|", 1, 1},
                            {"oom", "oom|", 1, 1},                {"sched", "sched|", 1, 1}};
    for (const auto& sh : shapes) {
        const std::string facet = sh.facet;
        const auto r = inspect(*plugin, own_pid(), facet);
        INFO(facet);
        CHECK(r.rc == 0);
        CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
        const auto rows = captured_rows(r.captured);
        // status row + target row + the facet's rows.
        REQUIRE(rows.size() >= 2 + sh.min_rows);
        CHECK(rows.size() <= 2 + sh.max_rows);
        CHECK(rows[0] == "status|inspect|supported|-");
        // The second row is the target row: pid, token, facet.
        const std::string expect_prefix = "target|" + own_pid() + "|";
        REQUIRE(rows[1].starts_with(expect_prefix));
        CHECK(rows[1].ends_with("|" + facet));
        for (std::size_t i = 1; i < rows.size(); ++i)
            CHECK(std::regex_match(rows[i], row_shape));
        for (std::size_t i = 2; i < rows.size(); ++i) {
            INFO("row " << i << ": " << rows[i]);
            CHECK(rows[i].starts_with(sh.prefix));
        }
    }
}

TEST_CASE("process_introspect plugin (Linux): the start_time token from one inspect guards the next",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const auto first = inspect(*plugin, own_pid(), "oom");
    const auto first_rows = captured_rows(first.captured);
    REQUIRE(first_rows.size() >= 2);
    REQUIRE(first_rows[0] == "status|inspect|supported|-");
    // target|<pid>|<token>|<facet>
    const std::string& target = first_rows[1];
    const std::size_t a = target.find('|', 7);
    REQUIRE(a != std::string::npos);
    const std::size_t b = target.find('|', a + 1);
    REQUIRE(b != std::string::npos);
    const std::string token = target.substr(a + 1, b - a - 1);

    // The matching token is accepted: same supported answer and the same target row. The oom
    // row after it is not compared, because the score moves.
    const auto same = inspect(*plugin, own_pid(), "oom", token);
    CHECK(same.rc == 0);
    CHECK(same.result_status == YUZU_RESULT_STATUS_OK);
    const auto same_rows = captured_rows(same.captured);
    REQUIRE(same_rows.size() >= 2);
    CHECK(same_rows[0] == "status|inspect|supported|-");
    CHECK(same_rows[1] == target);

    // A different, well-formed token is refused with no data row.
    const std::string other = token.substr(0, 8) == "ffffffff" ? "00000000.1" : "ffffffff.1";
    const auto reused = inspect(*plugin, own_pid(), "oom", other);
    CHECK(reused.rc == 0);
    const auto rows = captured_rows(reused.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|inspect|unavailable|linux:process_introspect:pid_reused");
    CHECK(reused.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("process_introspect plugin (Linux): a pid that cannot exist answers a typed not-found",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const auto r = inspect(*plugin, "2147483647", "caps");
    CHECK(r.rc == 0);
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1); // no data rows
    // Host-independent: a CI host may mount /proc with hidepid.
    CHECK((rows[0] == "status|inspect|unavailable|linux:process_introspect:no_such_process" ||
           rows[0] == "status|inspect|unavailable|linux:process_introspect:no_such_process_or_hidden"));
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

#else // macOS and Windows: planned

TEST_CASE("process_introspect plugin (macOS, Windows): valid parameters answer the shared planned row",
          "[process_introspect]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const auto r = inspect(*plugin, own_pid(), "caps");
    CHECK(r.rc == 0);
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
#if defined(_WIN32)
    // MUTATION: removing the report_planned call changes this row.
    CHECK(rows[0] == "status|inspect|unsupported|windows:planned");
#else
    CHECK(rows[0] == "status|inspect|unsupported|macos:planned");
#endif
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

#endif
