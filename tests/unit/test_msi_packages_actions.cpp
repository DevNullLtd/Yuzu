/**
 * test_msi_packages_actions.cpp -- Wave 4 PR4.3a dispatch remediation: loads
 * the ACTUAL built msi_packages plugin (msi_packages.dylib, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher, same pattern as
 * test_installed_apps_actions.cpp / test_users_posix_actions.cpp -- this
 * proves the migrated direct-argv `pkgutil --pkgs`/`--pkg-info <id>` calls
 * (replacing the prior `/bin/sh -c` hop + shell_quote()) actually reach the
 * real pkgutil binary on the test host.
 *
 * macOS and Windows only (Linux has no leg to drive) -- a no-op TU on Linux
 * via the file's own guard. The pkgutil cases are macOS-only; the Windows block
 * drives the real msi_packages.dll `list_inventory` (and checks `list` is
 * unchanged), including a live cross-check that no per-user-only product is
 * listed. The Windows cases call the Windows Installer API, which is cheap (a
 * registry read per product).
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline requires one
 * whenever a test's runtime depends on process creation):
 *   - What it costs, MEASURED on this host (macOS 26, arm64, 2026-08-24):
 *     2.25 s wall for both cases together. `list` does issue one
 *     `pkgutil --pkg-info` per receipt under the kMaxPackages (500) cap, but
 *     pkgutil is a local receipt-database read and the real cost is small.
 *     Re-measure rather than assume if that cap is ever raised.
 *   - Why a pure-function test cannot replace it: the point of the change is
 *     that the argv reaches the real pkgutil after the `/bin/sh -c` hop and
 *     shell_quote() were deleted. Feeding a fixture string to a parser
 *     exercises neither the argv construction nor the exec, and would stay
 *     green against the pre-change shell implementation.
 *   - Bound: two cases, macOS-only, no other spawning tests added here.
 */
#include <catch2/catch_test_macros.hpp>

#if defined(__APPLE__) || defined(_WIN32)

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#endif

namespace fs = std::filesystem;

namespace {

fs::path find_msi_packages_plugin() {
#if defined(_WIN32)
    const std::string lib_name = "msi_packages.dll";
#else
    const std::string lib_name = "msi_packages.dylib";
#endif

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "msi_packages" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "msi_packages" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "msi_packages" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "msi_packages" /
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

std::optional<LoadedPlugin> load_msi_packages_plugin() {
    auto plugin_path = find_msi_packages_plugin();
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

std::size_t count_non_matching_lines(const std::string& captured, std::string_view prefix) {
    std::istringstream iss(captured);
    std::string line;
    std::size_t bad = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.compare(0, prefix.size(), prefix) != 0)
            ++bad;
    }
    return bad;
}

} // namespace

std::vector<std::string> split_lines(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream iss(captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

std::size_t raw_token_count(const std::string& line) {
    std::size_t n = 1;
    for (char c : line)
        if (c == '|')
            ++n;
    return n;
}

#if defined(__APPLE__)

TEST_CASE("msi_packages plugin: the descriptor declares the three actions and macOS answers "
          "list_inventory unsupported",
          "[msi_packages][posix_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        SKIP("msi_packages plugin library not found -- cannot drive LocalDispatcher");
    }
    std::vector<std::string> names;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a)
        names.emplace_back(*a);
    CHECK(names == std::vector<std::string>{"list", "product_codes", "list_inventory"});

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_inventory");
    CHECK(result.rc == 0);
    CHECK(split_lines(result.captured) ==
          std::vector<std::string>{"status|list_inventory|unsupported|macos:owned_by_installed_apps"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("msi_packages plugin: list executes real pkgutil --pkgs/--pkg-info argv",
          "[msi_packages][posix_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        SKIP("msi_packages plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");

    // rc==0 plus every line matching `msi|...` proves the migrated argv
    // (direct pkgutil path, no shell hop, no shell_quote()) actually
    // reached the real pkgutil binary and its per-id --pkg-info loop ran
    // without error -- a reverted/broken argv would surface as a non-zero
    // rc or output that never matches the wire shape.
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());
    CHECK(count_non_matching_lines(result.captured, "msi|") == 0);
}

TEST_CASE("msi_packages plugin: product_codes executes real pkgutil --pkgs argv",
          "[msi_packages][posix_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        SKIP("msi_packages plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "product_codes");

    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());
    CHECK(count_non_matching_lines(result.captured, "product_code|") == 0);
}

#elif defined(_WIN32)

namespace {

// Enumerates one install context directly (the cross-check's independent source).
// Returns false when the walk could not complete, with the winerror in `rc_out`.
bool enumerate_codes(DWORD ctx, const wchar_t* sid, std::set<std::string>& out, UINT& rc_out) {
    wchar_t code[39]{};
    MSIINSTALLCONTEXT got{};
    for (DWORD i = 0;; ++i) {
        const UINT rc = MsiEnumProductsExW(nullptr, sid, ctx, i, code, &got, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            return true;
        if (rc != ERROR_SUCCESS) {
            rc_out = rc;
            return false;
        }
        std::string narrow;
        for (const wchar_t* c = code; *c; ++c)
            narrow.push_back(static_cast<char>(*c)); // a {GUID} is ASCII
        out.insert(narrow);
    }
}

} // namespace

TEST_CASE("msi_packages plugin: list_inventory shape on the real Windows leg",
          "[msi_packages][msi_inventory][windows_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        FAIL("msi_packages.dll not found -- the plugin did not build");
    }
    std::vector<std::string> names;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a)
        names.emplace_back(*a);
    CHECK(names == std::vector<std::string>{"list", "product_codes", "list_inventory"});

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_inventory");
    CHECK(result.rc == 0);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

    const auto lines = split_lines(result.captured);
    REQUIRE_FALSE(lines.empty());
    CHECK(lines[0] == "status|list_inventory|supported|-");
    // An empty machine-context roster is host state, not a plugin defect.
    if (lines.size() <= 1)
        SKIP("this host has no machine-context MSI products to shape-check");
    for (std::size_t i = 1; i < lines.size(); ++i) {
        CHECK(lines[i].rfind("inv|{", 0) == 0);
        CHECK(raw_token_count(lines[i]) == 5);
        const auto code_end = lines[i].find('|', 4);
        REQUIRE(code_end != std::string::npos);
        CHECK(code_end - 4 == 38); // {GUID}
        CHECK(lines[i][code_end - 1] == '}');
    }
}

TEST_CASE("msi_packages plugin: list_inventory never lists a per-user-only product",
          "[msi_packages][msi_inventory][windows_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        FAIL("msi_packages.dll not found -- the plugin did not build");
    }

    // Independent source: enumerate the machine context, then the two per-user contexts for
    // every account (S-1-1-0, admin-only). A code seen only per-user must be absent from the
    // action's output.
    std::set<std::string> machine;
    std::set<std::string> user;
    UINT rc = 0;
    REQUIRE(enumerate_codes(MSIINSTALLCONTEXT_MACHINE, nullptr, machine, rc));
    for (DWORD ctx : {static_cast<DWORD>(MSIINSTALLCONTEXT_USERUNMANAGED),
                      static_cast<DWORD>(MSIINSTALLCONTEXT_USERMANAGED)}) {
        if (!enumerate_codes(ctx, L"S-1-1-0", user, rc)) {
            SKIP("per-user enumeration needs an elevated identity (winerror " << rc << ")");
        }
    }
    std::set<std::string> per_user_only;
    for (const auto& c : user)
        if (!machine.count(c))
            per_user_only.insert(c);
    if (per_user_only.empty()) {
        SKIP("this host has no per-user-only MSI product, so absence cannot be observed");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "list_inventory");
    REQUIRE(result.rc == 0);
    for (const auto& line : split_lines(result.captured))
        for (const auto& c : per_user_only)
            CHECK(line.find(c) == std::string::npos);
}

TEST_CASE("msi_packages plugin: the legacy list action is unchanged by list_inventory",
          "[msi_packages][msi_inventory][windows_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        FAIL("msi_packages.dll not found -- the plugin did not build");
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());
    CHECK(count_non_matching_lines(result.captured, "msi|") == 0);
}

#endif // __APPLE__ / _WIN32

#endif // __APPLE__ || _WIN32
