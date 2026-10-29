/**
 * test_license_scan_actions.cpp — Wave 4 PR4.3b: loads the ACTUAL built
 * license_scan plugin (license_scan.dylib/.so) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher (test_users_posix_actions.cpp's
 * pattern), proving the plugin dispatches end to end after the Linux-leg
 * runner migration (licensing_linux.cpp) and the CONSTRAINED/rung-2
 * descriptor demotion.
 *
 * SCOPE, stated honestly: on macOS this exercises NONE of the Linux runner
 * migration -- licensing_macos.cpp's run_platform_surfaces is pure filesystem
 * glob + plist parsing with no subprocess at all. There it is a load-and-
 * dispatch smoke test: it proves the built plugin loads over the ABI and
 * answers "surfaces", nothing more. The Linux assertion below is the part that
 * covers migrated code, and it only runs on Linux (CI).
 *
 * "surfaces" always returns rc 0 by design (ADR-0024 D3: probe_status
 * reporting never fails the call), and each platform's run_platform_surfaces
 * appends at least one ProbeOutcome, so one `probe_status|` line is guaranteed
 * on every host.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_license_scan_plugin() {
    const std::string lib_name = std::string{"license_scan"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "license_scan" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "license_scan" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "license_scan" /
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

std::optional<LoadedPlugin> load_license_scan_plugin() {
    auto plugin_path = find_license_scan_plugin();
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

TEST_CASE("license_scan plugin: surfaces reports probe_status diagnostics via LocalDispatcher",
          "[license_scan]") {
    // Deliberately NOT a WARN-and-skip -- see the same note in
    // test_software_actions_actions.cpp. tests/meson.build links this plugin
    // in, so a load failure is a real defect and must go red rather than
    // pass with zero assertions.
    auto plugin = load_license_scan_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "surfaces");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("probe_status|") != std::string::npos);

    // The typed ABI4 status the dispatch reported must be the one the probe_status
    // lines imply: a refusal is PERMISSION_DENIED, any other failed surface
    // CONSTRAINED, an all-ok run leaves it UNDECLARED. Derived here from the output
    // text, independently of surface_result_status.
    //
    // What this pins: the mapping, but only on a host that actually has a refused
    // or failed surface. On a clean host (every CI runner) only the UNDECLARED arm
    // runs, which a dropped propagate_surface_status call also yields, so this does
    // not catch that deletion there. Delivery of the typed status through both the
    // list and surfaces actions is closed by the real-host refusal probe recorded
    // in the PR body, and the precedence by the pure seam in test_licensing_parsers.cpp.
    {
        INFO("full captured output: " << result.captured);
        const bool refused =
            result.captured.find("|error|cert_permission_denied") != std::string::npos;
        const bool errored = result.captured.find("|error|") != std::string::npos;
        if (refused) {
            CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == "license_scan:permission_denied");
        } else if (errored) {
            CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == "license_scan:surface_error");
        } else {
            CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
        }
    }

#ifdef __linux__
    // Only on Linux does this dispatch reach the migrated code. pkg_metadata is
    // the surface licensing_linux.cpp's runner migration rewrote, and
    // run_pkg_metadata_surface pushes its outcome on EVERY path, so its absence
    // means the migrated surface did not run at all.
    //
    // Governance Gate 4 (unhappy-path UP-9): the ORIGINAL substring check here
    // matched `probe_status|pkg_metadata|ok|...` AND
    // `probe_status|pkg_metadata|error|rpm_query_failed` equally -- so this
    // test stayed green even with the migrated argv path completely broken
    // (a reverted fix, a wrong tool path, a silently reintroduced shell hop
    // that no-ops), as long as SOME probe_status line for the surface still
    // appeared. Any dev or CI host running this suite has rpm or dpkg-query,
    // so pinning `|ok|` specifically proves the migrated argv actually
    // reached the real tool and succeeded, not merely that the surface was
    // attempted.
    INFO("full captured output: " << result.captured);
    CHECK(result.captured.find("probe_status|pkg_metadata|ok|") != std::string::npos);

    // entitlement_certs is read in-process (licensing_x509.hpp): the
    // surface always reports, the retired openssl-CLI token can never appear,
    // and on a host without /etc/pki/entitlement the line is exactly the
    // structural-empty success -- an absent directory is ENOENT, not an error.
    CHECK(result.captured.find("probe_status|entitlement_certs|") != std::string::npos);
    CHECK(result.captured.find("openssl_unavailable") == std::string::npos);
    std::error_code ec;
    if (!std::filesystem::exists("/etc/pki/entitlement", ec) && !ec) {
        CHECK(result.captured.find("probe_status|entitlement_certs|ok|0") != std::string::npos);
    }
#endif
}

TEST_CASE("license_scan plugin: capability descriptors declare each leg's support level",
          "[license_scan][descriptor]") {
    // REQUIRE, not a WARN-and-skip: a load failure or a missing descriptor is the
    // regression this test exists to catch (same reasoning as the dispatch test above).
    auto plugin = load_license_scan_plugin();
    REQUIRE(plugin.has_value());

    const auto* d = plugin->descriptor;
    REQUIRE(d->action_descriptors != nullptr);
    REQUIRE(d->action_descriptor_count == 2);

    // Both actions run the same run_platform_surfaces(), so both declare identical legs.
    bool saw_list = false;
    bool saw_surfaces = false;
    for (std::size_t i = 0; i < d->action_descriptor_count; ++i) {
        const auto& a = d->action_descriptors[i];
        REQUIRE(a.action != nullptr);
        const std::string_view name{a.action};
        INFO("action " << name);
        REQUIRE((name == "list" || name == "surfaces"));
        (name == "list" ? saw_list : saw_surfaces) = true;

        // Linux: pkg_metadata is classification-only and RHEL entitlement readability is
        // unmeasured, so CONSTRAINED -- at rung 2 because pkg_metadata still goes through
        // the bounded argv runner (the entitlement read is in-process).
        CHECK(a.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(a.linux_leg.rung == 2);
        // macOS: filesystem glob + in-process XML and bplist00 plist decoding.
        CHECK(a.macos_leg.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(a.macos_leg.rung == 1);
        // Windows: WMI + registry, unchanged.
        CHECK(a.windows_leg.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(a.windows_leg.rung == 1);
    }
    CHECK(saw_list);
    CHECK(saw_surfaces);
}

#endif // !_WIN32
