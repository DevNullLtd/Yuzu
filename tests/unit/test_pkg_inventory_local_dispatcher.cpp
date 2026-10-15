/**
 * test_pkg_inventory_local_dispatcher.cpp — loads the ACTUAL built pkg_inventory
 * plugin (pkg_inventory.dylib / .so / .dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher, exercising the real per-OS leg on the
 * build host (modelled on test_peripherals_local_dispatcher.cpp).
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no `#ifndef _WIN32` / `#ifdef
 * __APPLE__` around the TU. A platform-guarded dispatcher TU is how a sibling
 * plugin once shipped a leg that was compiled out entirely and stayed green.
 * The per-OS expectations live INSIDE the case bodies (`#if defined(...)`), so
 * every host runs the cases and asserts what its own leg must produce.
 *
 * What is pinned per host (host-independent shape first, then per-OS):
 *  - every action returns rc 0 and emits a `status|<action>|<level>|<tokens>`
 *    row FIRST (4 fields), then only rows of the action's own kinds;
 *  - manager rows have 7 fields and package rows 5 (escape-aware split);
 *  - Linux `packages`: exactly `status|packages|unsupported|linux:owned_by_installed_apps`,
 *    ZERO `package|` rows, UNAVAILABLE/PARTIAL typed status (Linux never
 *    enumerates a package; installed_apps owns the roster). MUTATION: if the
 *    Linux leg ever emitted a package row, or the token changed, this fails;
 *  - Linux `managers`: exactly `status|managers|unsupported|linux:planned` and
 *    nothing else, UNAVAILABLE/PARTIAL typed status (the leg is a planned
 *    placeholder; the real leg follows as its own PR and replaces this case);
 *  - Windows: both actions exactly `status|<action>|unsupported|windows:planned`
 *    and nothing else (the legs are declared planned);
 *  - macOS: two tiers read from the real host: when /opt/homebrew/Cellar is a
 *    directory `managers` yields >=1 `manager|homebrew|` row, and when it also
 *    holds a well-named version directory `packages` yields >=1
 *    `package|homebrew|` row (so removing the macOS wiring fails it). No
 *    host-specific count or name is asserted (CI's macOS runner has unknown
 *    contents);
 *  - the six declared legs (2 actions x 3 OSes) are never UNDECLARED, match the
 *    values the code implements, and the host's own leg agrees with what the
 *    action actually emits;
 *  - the exception firewall (run_guarded, through a synthetic descriptor: the
 *    real plugin cannot be made to throw) turns any throw into exactly one
 *    `constrained` status row carrying the fixed token, UNAVAILABLE/PARTIAL and
 *    rc 1, never leaking the exception's text.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <cstdlib>
#include <filesystem>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal
/// '|' as '\|', so a naive split('|') overcounts fields on any row whose text
/// happens to contain a pipe.
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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means
/// the build is genuinely broken and must NOT report "All tests passed".
///
/// getenv (not _dupenv_s) matches every sibling *_local_dispatcher.cpp's
/// identical helper -- MSVC's C4996 is silenced locally rather than diverging
/// from that shared idiom.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("pkg_inventory plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("pkg_inventory plugin library not found -- skipping the LocalDispatcher round-trip");
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

fs::path find_pkg_inventory_plugin() {
    const std::string lib_name = std::string{"pkg_inventory"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "pkg_inventory" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "pkg_inventory" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "pkg_inventory" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "pkg_inventory" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_pkg_inventory_plugin() {
    auto path = find_pkg_inventory_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

constexpr const char* kActions[] = {"managers", "packages"};

bool starts_with(const std::string& s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::size_t count_rows_with_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    std::size_t n = 0;
    for (const auto& r : rows)
        if (starts_with(r, prefix)) ++n;
    return n;
}

#if defined(__APPLE__)
/// True when /opt/homebrew/Cellar holds at least one <formula>/<version>
/// directory the leg would accept (non-hidden names). Test-side check only: the
/// production walk never uses directory_iterator (symlink safety), a test may.
bool host_has_homebrew_formula() {
    std::error_code ec;
    const fs::path cellar{"/opt/homebrew/Cellar"};
    if (!fs::is_directory(cellar, ec)) return false;
    for (const auto& formula : fs::directory_iterator(cellar, ec)) {
        if (ec) return false;
        const auto name = formula.path().filename().string();
        if (name.empty() || name.front() == '.') continue;
        std::error_code sub_ec;
        // Real directories only (the leg refuses symlinks): symlink_status does not follow.
        if (fs::symlink_status(formula.path(), sub_ec).type() != fs::file_type::directory) continue;
        for (const auto& version : fs::directory_iterator(formula.path(), sub_ec)) {
            const auto v = version.path().filename().string();
            std::error_code dir_ec;
            if (!v.empty() && v.front() != '.' &&
                fs::symlink_status(version.path(), dir_ec).type() == fs::file_type::directory)
                return true;
        }
    }
    return false;
}
#endif

} // namespace

TEST_CASE("pkg_inventory plugin: status row first, then only well-formed rows of the action's kinds",
          "[pkg_inventory][actions]") {
    auto plugin = load_pkg_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;

    for (const char* action : kActions) {
        INFO("action: " << action);
        auto result = dispatcher.run(plugin->descriptor, action);
        CHECK(result.rc == 0); // a degraded read is never a failed command

        const auto rows = captured_rows(result.captured);
        // The status row is ALWAYS emitted, first: a consumer must never see
        // silence and read it as "no package managers here".
        REQUIRE_FALSE(rows.empty());
        const auto status = split_fields_escape_aware(rows[0]);
        INFO("status row: " << rows[0]);
        REQUIRE(status.size() == 4);
        CHECK(status[0] == "status");
        CHECK(status[1] == action);
        CHECK((status[2] == "supported" || status[2] == "constrained" ||
               status[2] == "unsupported"));
        CHECK_FALSE(status[3].empty()); // "-" when there are no tokens

        for (std::size_t i = 1; i < rows.size(); ++i) {
            INFO("row: " << rows[i]);
            const auto f = split_fields_escape_aware(rows[i]);
            REQUIRE_FALSE(f.empty());
            if (f[0] == "manager") {
                CHECK(std::string_view{action} == "managers");
                CHECK(f.size() == 7);
            } else if (f[0] == "package") {
                CHECK(std::string_view{action} == "packages");
                REQUIRE(f.size() == 5);
                CHECK(f[1] == "homebrew");
            } else {
                FAIL("unexpected row kind after the status row: " << f[0]);
            }
        }
    }
}

TEST_CASE("pkg_inventory plugin: every action reports through the typed status seam",
          "[pkg_inventory][status]") {
    auto plugin = load_pkg_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : kActions) {
        INFO("action: " << action);
        auto result = dispatcher.run(plugin->descriptor, action);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto status = split_fields_escape_aware(rows[0]);
        REQUIRE(status.size() == 4);

        // The typed status must agree with the status row's level (one seam,
        // two views), so a leg that forgot set_result_status fails here.
        if (status[2] == "supported") {
            CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        } else if (status[2] == "constrained") {
            CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == status[3]);
        } else {
            CHECK(status[2] == "unsupported");
            CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == status[3]);
        }
    }
}

TEST_CASE("pkg_inventory plugin: per-OS leg contract on this host", "[pkg_inventory][actions]") {
    auto plugin = load_pkg_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    using namespace yuzu::pkg_inventory;

#if defined(_WIN32)
    // Both Windows legs are declared planned: the status row and nothing else.
    for (const char* action : kActions) {
        INFO("action: " << action);
        const auto result = dispatcher.run(plugin->descriptor, action);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + action + "|unsupported|" +
                             std::string{kTokenWindowsPlanned});
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    }
#elif defined(__linux__)
    // `packages` is UNSUPPORTED by construction: installed_apps owns the Linux
    // roster, and this plugin never enumerates a package in any form.
    {
        const auto result = dispatcher.run(plugin->descriptor, "packages");
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|packages|unsupported|linux:owned_by_installed_apps");
        CHECK(rows[0] == std::string{"status|packages|unsupported|"} +
                             std::string{kTokenLinuxPackagesOwned});
        CHECK(count_rows_with_prefix(rows, "package|") == 0);
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
    // Linux `managers` is declared planned: the status row and nothing else.
    {
        const auto result = dispatcher.run(plugin->descriptor, "managers");
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|managers|unsupported|linux:planned");
        CHECK(rows[0] == std::string{"status|managers|unsupported|"} +
                             std::string{kTokenLinuxPlanned});
        CHECK(count_rows_with_prefix(rows, "manager|") == 0);
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == "linux:planned");
    }
#elif defined(__APPLE__)
    // Values read from the real host, in two tiers so an existing-but-empty or
    // unreadable Cellar is never silently skipped (no counts or names asserted:
    // CI's macOS runner has unknown contents). Removing the macOS wiring fails both.
    //  - /opt/homebrew/Cellar is a directory   -> `managers` has >=1 manager|homebrew| row
    //    (present or unavailable: a marker that exists always yields a row);
    //  - it holds a well-named formula version -> `packages` has >=1 package row.
    std::error_code cellar_ec;
    if (!fs::is_directory("/opt/homebrew/Cellar", cellar_ec)) {
        WARN("no /opt/homebrew/Cellar on this host -- only the shape cases apply");
        return;
    }
    {
        const auto result = dispatcher.run(plugin->descriptor, "managers");
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        CHECK(starts_with(rows[0], "status|managers|"));
        CHECK(count_rows_with_prefix(rows, "manager|homebrew|") >= 1);
    }
    if (!host_has_homebrew_formula()) {
        WARN("no formula under /opt/homebrew/Cellar on this host -- the package-row check does not apply");
        return;
    }
    {
        const auto result = dispatcher.run(plugin->descriptor, "packages");
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        CHECK(starts_with(rows[0], "status|packages|"));
        CHECK(count_rows_with_prefix(rows, "package|homebrew|") >= 1);
    }
#endif
}

TEST_CASE("pkg_inventory plugin: an unknown action is refused, not silently ignored",
          "[pkg_inventory][actions]") {
    auto plugin = load_pkg_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
    // Deliberately not a data or status row: an unknown action has no status row.
    const auto rows = captured_rows(result.captured);
    CHECK(count_rows_with_prefix(rows, "status|") == 0);
    // The diagnostic is pinned. MUTATION: deleting or corrupting the
    // `unknown action:` write in pkg_inventory_plugin.cpp fails here.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");

    // The request-supplied name goes through safe_output_field (X12): a pipe
    // and a trailing backslash can neither open a second field nor swallow the
    // separator of whatever follows.
    const auto hostile = dispatcher.run(plugin->descriptor, "no|such\\");
    CHECK(hostile.rc != 0);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
    CHECK(split_fields_escape_aware(hrows[0]).size() == 1);
}

TEST_CASE("pkg_inventory plugin: ABI4 descriptors declare all six legs and the host leg agrees with "
          "what the action emits",
          "[pkg_inventory][descriptors]") {
    auto plugin = load_pkg_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    REQUIRE(plugin->descriptor->action_descriptor_count == 2);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    // The declared support per leg is what the code implements TODAY (macOS Homebrew
    // wired; Linux managers and both Windows legs planned; Linux packages unsupported
    // by design). Landing a leg without flipping its descriptor, or the reverse, fails
    // here; the capability-matrix gate compares the doc to the descriptor, not the
    // descriptor to behaviour.
    struct Expected {
        const char* action;
        YuzuSupportLevel linux_leg, macos_leg, windows_leg;
    };
    const Expected expected[] = {
        {"managers", YUZU_SUPPORT_PLANNED, YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_PLANNED},
        {"packages", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_PLANNED},
    };
    yuzu::agent::LocalDispatcher dispatcher;
    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        REQUIRE(d.action != nullptr);
        CHECK(std::string_view{d.action} == expected[i].action);
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.linux_leg.support == expected[i].linux_leg);
        CHECK(d.macos_leg.support == expected[i].macos_leg);
        CHECK(d.windows_leg.support == expected[i].windows_leg);

#if defined(_WIN32)
        const auto host_support = d.windows_leg.support;
#elif defined(__linux__)
        const auto host_support = d.linux_leg.support;
#else
        const auto host_support = d.macos_leg.support;
#endif
        const auto result = dispatcher.run(plugin->descriptor, d.action);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto status = split_fields_escape_aware(rows[0]);
        REQUIRE(status.size() == 4);
        if (host_support == YUZU_SUPPORT_PLANNED || host_support == YUZU_SUPPORT_UNSUPPORTED)
            CHECK(status[2] == "unsupported");
        else
            CHECK((status[2] == "supported" || status[2] == "constrained"));
    }
}

namespace {

enum class Thrown { runtime_error, bad_alloc, non_std };
Thrown g_thrown = Thrown::runtime_error;
bool g_body_returns = false;
int g_body_rc = 0;

int guarded_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                    std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::pkg_inventory::run_guarded(ctx, "packages", [&]() -> int {
        if (g_body_returns) {
            ctx.write_output("status|packages|supported|-");
            return g_body_rc;
        }
        switch (g_thrown) {
        case Thrown::runtime_error:
            throw std::runtime_error("secret /Users/someone/path leaked by an exception");
        case Thrown::bad_alloc: throw std::bad_alloc{};
        case Thrown::non_std: throw 42;
        }
        return 0;
    });
}

yuzu::agent::LocalDispatcher::Result run_guarded_execute() {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &guarded_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(&descriptor, "packages");
}

} // namespace

TEST_CASE("pkg_inventory firewall: any throw becomes one constrained status row, UNAVAILABLE/PARTIAL and "
          "rc 1, never the exception text",
          "[pkg_inventory][firewall]") {
    g_body_returns = false;
    for (const auto kind : {Thrown::runtime_error, Thrown::bad_alloc, Thrown::non_std}) {
        g_thrown = kind;
        INFO("thrown kind: " << static_cast<int>(kind));
        const auto result = run_guarded_execute();
        CHECK(result.rc == 1);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|packages|constrained|pkg_inventory:exception");
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == "pkg_inventory:exception");
        CHECK(result.captured.find("secret") == std::string::npos);
        CHECK(result.captured.find("/Users/") == std::string::npos);
    }
}

TEST_CASE("pkg_inventory firewall: a body that returns normally is passed through untouched",
          "[pkg_inventory][firewall]") {
    g_body_returns = true;
    for (const int rc : {0, 1}) {
        g_body_rc = rc;
        INFO("body rc: " << rc);
        const auto result = run_guarded_execute();
        CHECK(result.rc == rc);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|packages|supported|-"); // no firewall row appended
    }
    g_body_returns = false;
}
