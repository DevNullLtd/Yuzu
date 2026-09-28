/**
 * test_local_security_policy_local_dispatcher.cpp -- loads the ACTUAL built plugin and
 * drives `password_policy`/`lockout_policy`/`audit_policy` through
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

TEST_CASE("local_security_policy: descriptor pins the three actions shipped in this PR",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    const auto* d = plugin->descriptor();
    REQUIRE(d->action_descriptor_count == 3);
    std::vector<std::string> seen;
    for (int i = 0; d->actions[i] != nullptr; ++i) seen.emplace_back(d->actions[i]);
    CHECK(seen == std::vector<std::string>{"password_policy", "lockout_policy", "audit_policy"});
}

TEST_CASE("local_security_policy: an unregistered action (unknown, or the PLANNED sudoers) "
          "reports rc=1 and a named row, never a silent no-op",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"bogus_action", "sudoers"}) {
        const auto result = dispatcher.run(plugin->descriptor(), action);
        INFO(action);
        CHECK(result.rc != 0);
        CHECK(result.captured.find("unknown action:") != std::string::npos);
    }
}

TEST_CASE("local_security_policy: each real action returns at least one well-shaped row "
          "through the actual compiled leg",
          "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"password_policy", "lockout_policy", "audit_policy"}) {
        const auto result = dispatcher.run(plugin->descriptor(), action);
        const auto rows = rows_of(result.captured);
        INFO(action);
        REQUIRE_FALSE(rows.empty()); // never a genuinely empty result
        for (const auto& row : rows) {
            INFO(row);
            CHECK((row.rfind(std::string{action} + "|", 0) == 0 ||
                   row.rfind("constrained|", 0) == 0));
        }
    }
}
