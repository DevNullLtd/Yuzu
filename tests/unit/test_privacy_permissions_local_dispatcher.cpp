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
    CHECK(std::string_view{d->action_descriptors[0].action} == "permissions");
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
    CHECK(rows.front().rfind("unknown action:", 0) == 0);
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
    // macOS: once the real leg lands (currently a PLANNED placeholder emitting one whole-source
    // row), location is its own `unsupported` row on every collection -- restore
    // `CHECK(has("location"))` under `#if defined(__APPLE__)` here (see
    // privacy_permissions_legs.hpp's "when a leg lands" checklist). The whole-source check above
    // already covers the placeholder's shape (`whole_source_unavailable`).
}

#if defined(__APPLE__) || defined(_WIN32)
TEST_CASE("privacy_permissions: the PLANNED leg's placeholder row and typed status are both "
          "pinned exactly -- one whole-source row, UNAVAILABLE/PARTIAL, provenance <os>:planned "
          "-- so an emptied/duplicated row or a status that erases the planned token (both real "
          "defects this pin has caught) fail here, not silently. Restore/replace this case per "
          "privacy_permissions_legs.hpp's checklist once the real leg lands.",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    const auto rows = rows_of(result.captured);
    REQUIRE(rows.size() == 1);
#if defined(__APPLE__)
    CHECK(rows[0] == "permissions|macos|-|-|unsupported|macos:planned|-|-");
    CHECK(result.result_provenance == "macos:planned");
#elif defined(_WIN32)
    CHECK(rows[0] == "permissions|windows|-|-|unsupported|windows:planned|-|-");
    CHECK(result.result_provenance == "windows:planned");
#endif
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    // PARTIAL, not FULL: a planned leg has not looked at all, unlike the Linux leg's own
    // "genuinely reachable mechanism, definitively no session" case (FULL, portal:unavailable
    // -- a real, complete answer). Both legs bypass the shared select_status() for exactly
    // this reason; see privacy_permissions_macos.cpp's banner.
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}
#endif
