/**
 * test_sccm_win_actions.cpp -- Wave 3 PR33d remediation (code-review finding:
 * the SCM/registry/COM native migration -- the primary point of this branch
 * on Windows -- had no test that proves the real code path executes;
 * test_sccm_parsers.cpp exercises classify_service_status/select_authority_subkey/
 * interpret_sms_invoke as pure functions, never the plugin's actual
 * query_ccmexec_service_status/enumerate_authority_subkeys/call_sms_client_method
 * that call them). Loads the ACTUAL built sccm plugin (sccm.dll, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher.
 *
 * Scope, deliberately: this proves the NATIVE code path executes for real
 * against a host WITHOUT an SCCM/ConfigMgr client installed -- the honest
 * "not installed" degradation, not the "SCCM client present and answering"
 * success path. The plugin's own source comment (sccm_plugin.cpp, above
 * call_sms_client_method) already records that the success path has never
 * been exercised against a real SCCM client and none is available on any
 * dev/CI host reachable here -- that remains a genuine, disclosed
 * verification gap this test does not attempt to close. What it DOES prove:
 * client_version's service_status comes from a real OpenSCManagerW/
 * OpenServiceW/QueryServiceStatusEx round trip (not a reverted `sc query`
 * shell-out), and site's site_code/management_point come from a real
 * registry enumeration + CLSIDFromProgID/CoCreateInstance attempt (not a
 * reverted PowerShell ComObject shell-out) -- a regression back to either
 * shell-out would still produce SOME output, but the SPECIFIC honest values
 * a real Win32/COM call against an absent client produces (`not_found`/
 * `unavailable` service_status; `not_configured` site_code;
 * `unknown` management_point) are the ones this test pins.
 *
 * Windows-only; the plugin's SCM/COM code is a no-op elsewhere.
 *
 * Adversarial-review remediation (both external reviewers, independently):
 * two defects fixed. (1) A plugin the loader could not find or load used
 * to WARN-and-return here, which passed with zero assertions -- CLAUDE.md
 * floors exactly this shape ("a false-green test offered as closure
 * evidence for a blocking finding"). tests/meson.build's link_depends on
 * sccm_plugin_lib orders the plugin build ahead of this test binary, so on
 * a correctly configured Windows CI leg the plugin is ALWAYS present; its
 * absence is now a real regression, not a benign skip case, so it is a
 * REQUIRE. (2) The honest-degradation values this test file's own header
 * comment already identifies as the discriminating evidence
 * (`not_found`/`not_configured`/`unknown`) used to be checked only inside
 * a WARN, which cannot fail the test -- promoted to hard CHECKs below,
 * since every host these tests run on (CI or dev) genuinely lacks an
 * SCCM/ConfigMgr client and a `ccmexec` service/`SMS:*` registry key by
 * construction, making these values deterministic, not merely likely.
 */
#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

fs::path find_sccm_plugin() {
    const std::string lib_name = "sccm.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "sccm" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "sccm" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "sccm" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "sccm" / lib_name);

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

std::optional<LoadedPlugin> load_sccm_plugin() {
    auto plugin_path = find_sccm_plugin();
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

TEST_CASE("sccm plugin (Windows): client_version executes the real native "
          "SCM query, never a reverted sc-query shell-out",
          "[sccm][windows][actions]") {
    auto plugin = load_sccm_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch.
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "client_version");
    CHECK(result.rc == 0);
    // service_status is written from query_ccmexec_service_status()'s real
    // OpenSCManagerW/OpenServiceW/QueryServiceStatusEx round trip -- a
    // reverted `sc query ccmexec` text-parse shell-out would produce a
    // differently-shaped line (or none at all on a CI host with no shell
    // access to `sc`), never this exact prefix.
    CHECK(result.captured.find("service_status|") != std::string::npos);
    // Hard CHECK, not WARN: on every host these tests run on (CI or dev),
    // no ccmexec service exists, so query_ccmexec_service_status()'s real
    // OpenServiceW call deterministically returns ERROR_SERVICE_DOES_NOT_EXIST
    // -> not_found. This is the specific value a reverted `sc query`
    // text-parse (or a broken SCM connect reporting "unavailable" instead)
    // would NOT reliably reproduce -- the discriminating evidence this
    // test exists to pin, not merely a plausible outcome.
    CHECK(result.captured.find("service_status|not_found") != std::string::npos);
}

TEST_CASE("sccm plugin (Windows): site executes the real registry "
          "enumeration + COM attempt, never a reverted PowerShell shell-out",
          "[sccm][windows][actions]") {
    auto plugin = load_sccm_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch.
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "site");
    CHECK(result.rc == 0);
    // site_code comes from a real HKLM\SOFTWARE\Microsoft\CCM\Authority
    // registry enumeration (select_authority_subkey) falling back to a real
    // CLSIDFromProgID(Microsoft.SMS.Client) COM attempt -- never the dead
    // literal "SMS:{}" the pre-migration bug produced, and never absent.
    CHECK(result.captured.find("site_code|") != std::string::npos);
    CHECK(result.captured.find("management_point|") != std::string::npos);
    // Hard CHECKs, not WARN: on every host these tests run on, no SCCM
    // Authority registry key and no Microsoft.SMS.Client COM registration
    // exist, so the real registry enumeration + CLSIDFromProgID attempt
    // deterministically falls through to site_code|not_configured and
    // management_point|unknown -- the specific values a reverted
    // PowerShell ComObject shell-out (or the pre-migration dead-literal
    // "SMS:{}" bug) would not reliably reproduce.
    CHECK(result.captured.find("site_code|not_configured") != std::string::npos);
    CHECK(result.captured.find("management_point|unknown") != std::string::npos);
}

#endif // _WIN32
