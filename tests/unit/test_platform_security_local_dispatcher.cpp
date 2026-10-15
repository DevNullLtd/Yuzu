/**
 * test_platform_security_local_dispatcher.cpp -- loads the ACTUAL built plugin and drives it
 * through yuzu::agent::LocalDispatcher (the real per-OS leg runs on the build host). No platform
 * guard on the TU. Row FAMILIES are host-keyed (Linux {secure_boot,setup_mode} + {lsm,lockdown};
 * macOS {secure_boot:unsupported} + {gatekeeper,sip}, via the real spctl / csrutil runs; Windows
 * rows are host-dependent: grammar and status contract only). No host-specific VALUE assertion:
 * an absent source is a modal host answer that adds no token.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "platform_security_legs.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::platform_security;
using Rows = std::vector<std::string>;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr std::string_view kExpectedOs = "windows";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr std::string_view kExpectedOs = "macos";
#else
constexpr const char* kPluginExt = ".so";
constexpr std::string_view kExpectedOs = "linux";
#endif

/// Escape-aware field split: safe_output_field escapes a literal '|' as '\|'.
std::vector<std::string> split_fields(const std::string& row) {
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

Rows captured_rows(const std::string& captured) {
    Rows out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// The key column (field 2) of every row, in order.
[[maybe_unused]] Rows keys_of(const Rows& rows) {
    Rows out;
    for (const auto& r : rows) out.push_back(split_fields(r).at(2));
    return out;
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv, as in every sibling *_local_dispatcher.cpp
#endif
fs::path find_plugin() {
    const std::string lib = std::string{"platform_security"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "platform_security" / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "platform_security" / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "platform_security" / lib);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "platform_security" / lib);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

/// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the build is
/// genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("platform_security plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    WARN("platform_security plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

std::optional<yuzu::agent::PluginHandle> load_plugin() {
    const auto path = find_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded || !loaded->descriptor()) return std::nullopt;
    return std::move(*loaded);
}

/// Synthetic execute(): the `action` picks which rows + accumulator feed emit_rows.
int exercise_emit(YuzuCommandContext* raw, const char* action, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PlatformRow> rows;
    const std::string_view a = action;
    if (a == "mixed") {
        rows.push_back({"code_integrity", "linux", "lsm", "apparmor", PlatformState::enabled});
        rows.push_back(failed_row("code_integrity", "linux", "lockdown", EIO, acc));
    } else if (a == "absent") {
        rows.push_back(failed_row("secure_boot", "linux", "secure_boot", ENOENT, acc));
        rows.push_back(failed_row("secure_boot", "linux", "setup_mode", ENOENT, acc));
    } else {
        rows.push_back(failed_row("secure_boot", "linux", "secure_boot", EACCES, acc));
    }
    emit_rows(ctx, rows, acc);
    return 0;
}

} // namespace

// Fails if emit_rows stops routing rows through the shared status selector: an unreadable row is
// CONSTRAINED + its token, an absent-only run stays OK/FULL with no token, a refusal is
// PERMISSION_DENIED (never CONSTRAINED).
TEST_CASE("platform_security emit_rows: status follows the rows through the dispatcher",
          "[platform_security][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_emit;
    yuzu::agent::LocalDispatcher dispatcher;

    const auto mixed = dispatcher.run(&descriptor, "mixed");
    CHECK(captured_rows(mixed.captured) == Rows{"code_integrity|linux|lsm|apparmor|enabled",
                                                "code_integrity|linux|lockdown|-|unreadable"});
    CHECK(mixed.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(mixed.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(mixed.result_provenance == "lockdown:errno_" + std::to_string(EIO));

    const auto absent = dispatcher.run(&descriptor, "absent");
    CHECK(captured_rows(absent.captured) == Rows{"secure_boot|linux|secure_boot|-|absent",
                                                 "secure_boot|linux|setup_mode|-|absent"});
    CHECK(absent.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(absent.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(absent.result_provenance.empty());

    const auto denied = dispatcher.run(&descriptor, "denied");
    CHECK(captured_rows(denied.captured) == Rows{"secure_boot|linux|secure_boot|-|unreadable"});
    CHECK(denied.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(denied.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(denied.result_provenance == "secure_boot:eacces");
}

// Fails if a leg emits a malformed row, an unknown state, a wrong OS, a value beside a "nothing
// read" state, or (non-Windows) drops/reorders its host row family; (macOS) secure_boot stops
// being the unsupported leg.
TEST_CASE("platform_security plugin: rows are <action>|os|key|raw|state, in the host family order",
          "[platform_security][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const std::string action : {"secure_boot", "code_integrity"}) {
        INFO("action: " << action);
        const auto result = dispatcher.run(plugin->descriptor(), action);
        CHECK(result.rc == 0); // a degraded read is never a failed command
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        for (const auto& r : rows) {
            INFO("row: " << r);
            const auto f = split_fields(r);
            REQUIRE(f.size() == 5);
            CHECK(f[0] == action);
            CHECK(f[1] == kExpectedOs);
            CHECK_FALSE(f[2].empty());
            CHECK(std::find(kStateTokens.begin(), kStateTokens.end(), f[4]) != kStateTokens.end());
            // "-" means "nothing was read": exactly the absent/unreadable/unsupported rows.
            CHECK((f[3] == "-") == (f[4] == "absent" || f[4] == "unreadable" || f[4] == "unsupported"));
        }
#if defined(__APPLE__)
        if (action == "secure_boot") {
            CHECK(rows == Rows{"secure_boot|macos|secure_boot|-|unsupported"});
            CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
            CHECK(result.result_provenance == "no public API; SIP reported under code_integrity");
        } else {
            CHECK(keys_of(rows) == Rows{"gatekeeper", "sip"});
        }
#elif !defined(_WIN32)
        CHECK(keys_of(rows) == (action == "secure_boot" ? Rows{"secure_boot", "setup_mode"}
                                                        : Rows{"lsm", "lockdown"}));
#endif
    }
}

// Fails if the status disagrees with the rows: OK/UNAVAILABLE exactly when no row is unreadable,
// every unreadable row is named by a `<key>:` token, an absent/unsupported row has none, and no
// retired absence token returns.
TEST_CASE("platform_security plugin: the typed status agrees with the rows; only an unreadable row is a failure",
          "[platform_security][status]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const std::string action : {"secure_boot", "code_integrity"}) {
        INFO("action: " << action);
        const auto result = dispatcher.run(plugin->descriptor(), action);
        const auto st = result.result_status;
        const bool quiet_status = st == YUZU_RESULT_STATUS_OK || st == YUZU_RESULT_STATUS_UNAVAILABLE;
        REQUIRE((quiet_status || st == YUZU_RESULT_STATUS_CONSTRAINED ||
                 st == YUZU_RESULT_STATUS_PERMISSION_DENIED));
        if (st == YUZU_RESULT_STATUS_OK) {
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
            CHECK(result.result_provenance.empty());
        } else if (!quiet_status) {
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        }
        bool any_unreadable = false;
        for (const auto& r : captured_rows(result.captured)) {
            const auto f = split_fields(r);
            REQUIRE(f.size() == 5);
            INFO("key: " << f[2]);
            const bool named = result.result_provenance.find(f[2] + ":") != std::string::npos;
            if (f[4] == "unreadable") {
                any_unreadable = true;
                CHECK(named);
            } else if (f[4] == "absent" || f[4] == "unsupported") {
                CHECK_FALSE(named);
            }
        }
        CHECK(quiet_status == !any_unreadable);
        CHECK(result.result_provenance.find(":enoent") == std::string::npos);
        CHECK(result.result_provenance.find(":not_found") == std::string::npos);
    }
}

TEST_CASE("platform_security plugin: an unknown action is refused, not silently ignored",
          "[platform_security][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin->descriptor(), "no_such_action");
    CHECK(r.rc != 0);
    CHECK(captured_rows(r.captured) == Rows{"unknown action: no_such_action"});
    // Request-supplied text in a pipe-delimited stream: the newline folds, the pipe escapes.
    CHECK(captured_rows(dispatcher.run(plugin->descriptor(), "no|such\naction").captured) ==
          Rows{"unknown action: no\\|such action"});
}
