/**
 * test_privacy_permissions_local_dispatcher.cpp -- loads the ACTUAL built plugin and drives
 * the `permissions` action through yuzu::agent::LocalDispatcher. Unguarded (runs on all three
 * OSes). Assertions are row-shape and status invariants, never host-specific grant values: a
 * host may or may not have any camera/microphone/location/full-disk-access grant recorded.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kExt = ".dylib";
#else
constexpr const char* kExt = ".so";
#endif

std::optional<yuzu::agent::PluginHandle> load_plugin() {
    const std::string lib = std::string{"privacy_permissions"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "privacy_permissions" / lib);
    for (const char* b : {"", "..", "build-macos", "build-windows", "build-linux"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "privacy_permissions" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        auto h = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (h.has_value() && h->descriptor() != nullptr) return std::move(*h);
    }
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("privacy_permissions plugin library not found under meson test");
    WARN("privacy_permissions plugin library not found -- skipping (run via `meson test`)");
    return std::nullopt;
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string l; std::getline(ss, l);) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        if (!l.empty()) out.push_back(l);
    }
    return out;
}

std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') ++i;
        else if (row[i] == '|') ++n;
    }
    return n;
}

} // namespace

TEST_CASE("privacy_permissions: descriptor pins the single action per OS",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    const auto* d = plugin->descriptor();
    REQUIRE(d->action_descriptor_count == 1);
    const auto& a = d->action_descriptors[0];
    CHECK(std::string_view{a.action} == "permissions");
    // macOS and Windows are real, CONSTRAINED rung-1 legs. A descriptor regression to a
    // placeholder support level would otherwise pass every other test in this file, since none
    // of them read the descriptor's support level.
    CHECK(a.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(a.macos_leg.rung == 1);
    CHECK(a.windows_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(a.windows_leg.rung == 1);
}

TEST_CASE("privacy_permissions: unknown action reports rc=1 and a named row",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "not_a_real_action");
    CHECK(result.rc == 1);
    const auto rows = rows_of(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "unknown action: not_a_real_action");
}

TEST_CASE("privacy_permissions: permissions always returns at least one 8-field row",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    const auto rows = rows_of(result.captured);
    REQUIRE_FALSE(rows.empty()); // never a genuinely empty result -- see the binding contract
    for (const auto& row : rows) {
        INFO(row);
        CHECK(row.rfind("permissions|", 0) == 0);
        CHECK(field_count(row) == 8);
    }
}

TEST_CASE("privacy_permissions: no category is silently omitted -- each of the four has its "
          "own row, or a whole-source FAILURE row (category '-', denied/unreadable) stands for "
          "it; a whole-source absent row never does",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    std::vector<std::string> categories;
    bool whole_source_failure = false;
    bool whole_source_unavailable = false;
    for (const auto& row : rows_of(result.captured)) {
        // Fields 3 and 4 (0-based) are `category` and `state`; app_id (field 2) never contains an
        // unescaped '|'.
        std::size_t start = 0;
        for (int i = 0; i < 3; ++i) start = row.find('|', start) + 1;
        const auto cat_end = row.find('|', start);
        const auto category = row.substr(start, cat_end - start);
        const auto state = row.substr(cat_end + 1, row.find('|', cat_end + 1) - cat_end - 1);
        categories.push_back(category);
        if (category != "-") continue;
        if (state == "denied" || state == "unreadable") whole_source_failure = true;
        // The one whole-MECHANISM row (Linux: no session bus / no portal backend) stands for
        // every category only when the result says so.
        if (state == "unsupported" && result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE)
            whole_source_unavailable = true;
    }
    const auto has = [&](std::string_view c) {
        return std::find(categories.begin(), categories.end(), c) != categories.end();
    };
    for (const char* cat : {"camera", "microphone", "location", "full_disk_access"}) {
        INFO(cat);
        CHECK((has(cat) || whole_source_failure || whole_source_unavailable));
    }
#if defined(__APPLE__)
    CHECK(has("location")); // macOS: location is its own `unsupported` row on every collection
#endif
}

#if defined(__APPLE__)
TEST_CASE("privacy_permissions: the real macOS dispatch derives its typed status from the "
          "rows it actually emitted, and it is never the UNAVAILABLE/macos:planned "
          "placeholder result. None of the row-shape checks above read "
          "result_status/completeness/provenance at all, so a regression that quietly "
          "reverted collect_macos_permissions to the PLANNED placeholder (or hard-coded a "
          "status) would leave every other test in this file green.",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    // `state == "denied"` on the wire is NOT the same signal `select_status`'s `any_denied()`
    // acts on: it also covers an ordinary decoded "this app's grant is denied" row (a normal,
    // non-failure result -- see PermissionRow::read_denied's own doc comment), and
    // `read_denied` itself never reaches the wire. So PERMISSION_DENIED can't be derived from
    // captured rows alone without a real, deliberately-refused TCC.db on this host (covered
    // instead by the TU-inclusion fixtures in test_privacy_permissions_macos_internals.cpp,
    // which control file permissions directly). `unreadable`, in contrast, IS unambiguous --
    // it is never used for a decoded value -- so it alone proves the CONSTRAINED/OK boundary.
    bool any_unreadable = false;
    for (const auto& row : rows_of(result.captured)) {
        std::size_t start = 0;
        for (int i = 0; i < 4; ++i) start = row.find('|', start) + 1;
        const auto state = row.substr(start, row.find('|', start) - start);
        if (state == "unreadable") any_unreadable = true;
    }
    CHECK(result.result_status != YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_provenance != "macos:planned");
    if (result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED) {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else if (any_unreadable) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else {
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    }
}
#endif

#if defined(_WIN32)
TEST_CASE("privacy_permissions: the real Windows dispatch derives its typed status from what it "
          "actually read, and it is never the UNAVAILABLE/windows:planned placeholder result. "
          "The oracle admits token-only failures (a hive that would not unload, a LastUsedTime "
          "read) that carry no row, so OK/FULL is never asserted from row shape alone.",
          "[privacy_permissions][dispatcher]") {
    // CI exposure, stated plainly: this runs the REAL action, so it reads the host's real HKLM
    // ProfileList and every real profile's ConsentStore, and for a logged-off profile it mounts that
    // profile's real NTUSER.DAT (RegLoadKeyW) under the shared offline_hive_mutex. On the shared
    // 4-runner/one-identity box, concurrent jobs running registry-touching tests can collide on a
    // profile's hive file (ERROR_SHARING_VIOLATION), which surfaces as a `hive_mount_failed` row --
    // the same exposure test_registry_local_dispatcher already carries. The oracle is therefore
    // deliberately shape-level, like the macOS arm above: it asserts the status is DERIVED from the
    // rows (never the placeholder, PERMISSION_DENIED/CONSTRAINED only with their evidence), and it
    // cannot be satisfied by a hard-coded status, but it does not pin which profiles a host has or
    // whether they could be read. Value-level behaviour is covered where the inputs are controlled:
    // the injected-read cases in test_privacy_permissions_parsers.cpp and the fixture-registry and
    // TempDir cases in test_privacy_permissions_win_internals.cpp.
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    bool any_unreadable = false;
    for (const auto& row : rows_of(result.captured)) {
        std::size_t start = 0;
        for (int i = 0; i < 4; ++i) start = row.find('|', start) + 1;
        const auto state = row.substr(start, row.find('|', start) - start);
        if (state == "unreadable") any_unreadable = true;
    }
    CHECK(result.result_status != YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_provenance != "windows:planned");
    if (result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED) {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else if (any_unreadable) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else {
        const bool ok_full = result.result_status == YUZU_RESULT_STATUS_OK &&
                             result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL;
        const bool constrained_partial =
            result.result_status == YUZU_RESULT_STATUS_CONSTRAINED &&
            result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL;
        CHECK((ok_full || constrained_partial));
    }
}
#endif
