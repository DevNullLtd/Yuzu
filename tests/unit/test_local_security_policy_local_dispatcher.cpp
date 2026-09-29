/**
 * test_local_security_policy_local_dispatcher.cpp -- loads the ACTUAL built plugin and
 * drives `password_policy`/`lockout_policy`/`audit_policy`/`sudoers` through
 * yuzu::agent::LocalDispatcher. Unguarded (runs on all three OSes). The pure parser tests
 * (test_local_security_policy_parsers.cpp) cover every decision; this file proves the real
 * compiled leg TU actually wires them up -- the class of gap the Linux leg's own real
 * sd-bus/argv-runner integration would otherwise have no discriminating test for at all.
 * Assertions are row-shape and status invariants, never host-specific policy values: a host
 * may or may not have any particular setting configured.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <unordered_set>
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
    const std::string lib = std::string{"local_security_policy"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const char* b : {"", "..", "build-macos", "build-windows", "build-linux"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        auto h = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (h.has_value() && h->descriptor() != nullptr) return std::move(*h);
    }
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("local_security_policy plugin library not found under meson test");
    WARN("local_security_policy plugin library not found -- skipping (run via `meson test`)");
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

} // namespace

TEST_CASE("local_security_policy: descriptor pins the four actions; sudoers is the only "
          "Windows-unsupported leg",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    const auto* d = plugin->descriptor();
    REQUIRE(d->action_descriptor_count == 4);
    std::vector<std::string> seen;
    for (int i = 0; d->actions[i] != nullptr; ++i) seen.emplace_back(d->actions[i]);
    CHECK(seen == std::vector<std::string>{"password_policy", "lockout_policy", "audit_policy",
                                           "sudoers"});
    for (std::size_t i = 0; i < d->action_descriptor_count; ++i) {
        const auto& a = d->action_descriptors[i];
        REQUIRE(a.action != nullptr);
        const std::string_view action{a.action};
        INFO("action: " << action);
        // Every leg is declared for every action, never left undeclared (the capability-matrix
        // generator needs a complete, stable shape).
        CHECK(a.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(a.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(a.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(a.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(a.linux_leg.rung == 1);
        CHECK(a.linux_leg.fallback != nullptr);
        CHECK(a.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(a.macos_leg.fallback != nullptr);
        if (action == "sudoers") {
            CHECK(a.macos_leg.rung == 1);
            CHECK(a.windows_leg.support == YUZU_SUPPORT_UNSUPPORTED); // no sudoers on Windows
            CHECK(a.windows_leg.rung == 0);
            CHECK(a.windows_leg.fallback == nullptr);
        } else {
            // macOS password/lockout come from pwpolicy (rung 2); audit_policy reads a file.
            CHECK(a.macos_leg.rung == (action == "audit_policy" ? 1 : 2));
            CHECK(a.windows_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(a.windows_leg.rung == 2); // secedit /export, an argv leaf
            CHECK(a.windows_leg.fallback != nullptr);
        }
    }
}

TEST_CASE("local_security_policy: an unregistered action reports rc=1 and a named row, never a "
          "silent no-op",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "bogus_action");
    CHECK(result.rc != 0);
    CHECK(result.captured.find("unknown action:") != std::string::npos);
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED); // no typed status on this path
}

TEST_CASE("local_security_policy: each real action returns at least one well-shaped row "
          "through the actual compiled leg",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"password_policy", "lockout_policy", "audit_policy", "sudoers"}) {
#if defined(_WIN32)
        if (std::string_view{action} == "sudoers") continue; // the fixed refusal row, below
#endif
        const auto result = dispatcher.run(plugin->descriptor(), action);
        const auto rows = rows_of(result.captured);
        INFO(action);
        REQUIRE_FALSE(rows.empty()); // never a genuinely empty result
        for (const auto& row : rows) {
            INFO(row);
            CHECK((row.rfind(std::string{action} + "|", 0) == 0 ||
                   row.rfind("constrained|", 0) == 0));
        }
        // apply_collected() calls CommandContext::set_result_status() on every path (Ok,
        // PermissionDenied, Constrained) -- prove that ABI4 CC-07 seam actually fired, not
        // just that a row was written. A plugin that stopped calling set_result_status would
        // leave result_status at its UNDECLARED default with every row-shape check above
        // still green.
        CHECK(result.result_status != YUZU_RESULT_STATUS_UNDECLARED);
        CHECK(result.result_completeness != YUZU_RESULT_COMPLETENESS_UNKNOWN);
    }
}

#if defined(_WIN32)
// Windows has no sudoers: the plugin short-circuits with one fixed row, UNAVAILABLE/PARTIAL and
// a named provenance -- never a read, never an empty success.
TEST_CASE("local_security_policy: sudoers refuses cleanly with a fixed row on Windows",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "sudoers");
    CHECK(result.rc == 1);
    const auto rows = rows_of(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "sudoers|-|unsupported|-|-|-|windows_has_no_sudoers");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "windows_has_no_sudoers");
}
#endif
