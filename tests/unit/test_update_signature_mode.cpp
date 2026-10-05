/**
 * test_update_signature_mode.cpp — the agent's OTA update-signature posture
 * report (#5249): the mode it derives, the heartbeat tag, the YUZU_UPDATE_*
 * typo check, and the startup log lines.
 *
 * main.cpp (which emits the startup lines) and agent.cpp's heartbeat lambda are
 * in no test target, so both are thin callers of the helpers pinned here: the
 * mode tag is written through emit_update_signature_mode_tag() into the same
 * map type contract the protobuf status_tags map satisfies, and the startup
 * lines are built by build_update_signature_startup_lines().
 */

#include <yuzu/agent/update_signature_mode.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "cms_test_fixtures.hpp"
#include "scoped_env.hpp"

#ifdef _WIN32
#include <process.h> // _getpid
#else
#include <unistd.h> // getpid
#endif

using yuzu::agent::UpdateConfig;
using yuzu::agent::UpdateSignatureMode;
using namespace yuzu::test::cms;

namespace {

UpdateConfig cfg(const fs::path& bundle, bool require) {
    UpdateConfig c;
    c.signature_trust_bundle = bundle;
    c.require_signature = require;
    return c;
}

bool any_line_contains(const std::vector<yuzu::agent::UpdateSignatureStartupLine>& lines,
                       bool warning, std::string_view needle) {
    return std::any_of(lines.begin(), lines.end(), [&](const auto& l) {
        return l.warning == warning && l.text.find(needle) != std::string::npos;
    });
}

std::size_t warning_count(const std::vector<yuzu::agent::UpdateSignatureStartupLine>& lines) {
    return static_cast<std::size_t>(
        std::count_if(lines.begin(), lines.end(), [](const auto& l) { return l.warning; }));
}

} // namespace

TEST_CASE("update signature mode: off / bundle / bundle+require", "[updater][signing][5249]") {
    const fs::path bundle = "/etc/yuzu-agent/certs/update-trust-bundle.pem";
    using yuzu::agent::update_signature_mode;
    using yuzu::agent::update_signature_mode_name;

    CHECK(update_signature_mode(cfg({}, false)) == UpdateSignatureMode::kOff);
    CHECK(update_signature_mode(cfg(bundle, false)) == UpdateSignatureMode::kBundle);
    CHECK(update_signature_mode(cfg(bundle, true)) == UpdateSignatureMode::kBundleRequire);

    // require without a bundle enforces NOTHING (the updater only reads require
    // inside its bundle branch; main() refuses to start on it). Reporting it as
    // anything but off would be the lie this whole change removes.
    CHECK(update_signature_mode(cfg({}, true)) == UpdateSignatureMode::kOff);

    CHECK(update_signature_mode_name(UpdateSignatureMode::kOff) == "off");
    CHECK(update_signature_mode_name(UpdateSignatureMode::kBundle) == "bundle");
    CHECK(update_signature_mode_name(UpdateSignatureMode::kBundleRequire) == "bundle+require");
}

TEST_CASE("update signature mode: heartbeat tag carries the mode", "[updater][signing][5249]") {
    const fs::path bundle = "/etc/yuzu-agent/certs/update-trust-bundle.pem";
    CHECK(yuzu::agent::kTagOtaSignatureMode == "yuzu.ota_signature_mode");

    const struct {
        UpdateConfig c;
        const char* want;
    } cases[] = {
        {cfg({}, false), "off"},
        {cfg(bundle, false), "bundle"},
        {cfg(bundle, true), "bundle+require"},
        {cfg({}, true), "off"},
    };
    for (const auto& tc : cases) {
        std::map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux"; // a neighbouring tag must survive
        yuzu::agent::emit_update_signature_mode_tag(tags, tc.c);
        INFO("want=" << tc.want);
        REQUIRE(tags.count("yuzu.ota_signature_mode") == 1);
        CHECK(tags["yuzu.ota_signature_mode"] == tc.want);
        CHECK(tags["yuzu.os"] == "linux");
        CHECK(tags.size() == 2);
    }
}

TEST_CASE("update env check: unrecognised YUZU_UPDATE_ names are reported",
          "[updater][signing][5249]") {
    using yuzu::agent::unrecognised_update_env_names;
    const std::vector<std::string> env = {
        "PATH",
        "YUZU_UPDATE_TRUST_BUNDLE",       // recognised
        "YUZU_UPDATE_REQUIRE_SIGNATURE",  // recognised
        "YUZU_UPDATE_CHECK_INTERVAL",     // recognised
        "YUZU_UPDATE_DIR",                // the server's option: real, not a typo
        "YUZU_UPDATE_TRUST_BUNDEL",       // typo
        "YUZU_UPDATE_REQUIRE_SIGNATURES", // typo
        "YUZU_UPDATE_",                   // bare prefix
        "yuzu_update_trust_bundle",       // case variant
        "YUZU_UPDATES_TRUST_BUNDLE",      // not under the prefix (no '_' after UPDATE)
        "YUZU_PLUGIN_TRUST_BUNDLE",       // a different family entirely
        "XYUZU_UPDATE_TRUST_BUNDLE",      // prefix must be at the start
    };

    SECTION("POSIX: names are case-sensitive, so a lowercase variant is a typo") {
        const auto bad = unrecognised_update_env_names(env, /*names_case_insensitive=*/false);
        const std::vector<std::string> want = {"YUZU_UPDATE_TRUST_BUNDEL",
                                               "YUZU_UPDATE_REQUIRE_SIGNATURES", "YUZU_UPDATE_",
                                               "yuzu_update_trust_bundle"};
        CHECK(bad == want);
    }

    SECTION("Windows: names are case-insensitive, so the lowercase variant IS read") {
        const auto bad = unrecognised_update_env_names(env, /*names_case_insensitive=*/true);
        const std::vector<std::string> want = {"YUZU_UPDATE_TRUST_BUNDEL",
                                               "YUZU_UPDATE_REQUIRE_SIGNATURES", "YUZU_UPDATE_"};
        CHECK(bad == want);
    }

    SECTION("a clean environment reports nothing") {
        const std::vector<std::string> clean = {"PATH", "YUZU_UPDATE_TRUST_BUNDLE", "HOME"};
        CHECK(unrecognised_update_env_names(clean, false).empty());
        CHECK(unrecognised_update_env_names({}, false).empty());
    }
}

TEST_CASE("update env check: the process environment is enumerated by name",
          "[updater][signing][5249]") {
    // One real enumeration, to prove the platform reader returns names (never
    // values) and sees a variable set in this process. Salted with the pid and
    // restored by ScopedEnv; the environment is per-process, so this cannot
    // collide with another job on a shared runner.
#ifdef _WIN32
    const auto pid = static_cast<long>(_getpid());
#else
    const auto pid = static_cast<long>(::getpid());
#endif
    const std::string name = "YUZU_UPDATE_YUZU_TEST_PROBE_" + std::to_string(pid);
    const std::string secret_value = "value-must-not-appear-" + std::to_string(pid);
    yuzu::test::ScopedEnv env(name, secret_value);

    const auto names = yuzu::agent::process_environment_names();
    CHECK(std::find(names.begin(), names.end(), name) != names.end());
    for (const auto& n : names) {
        CHECK(n.find('=') == std::string::npos);
        CHECK(n.find(secret_value) == std::string::npos);
    }
    // And the composed check flags it as unrecognised.
    const auto bad =
        yuzu::agent::unrecognised_update_env_names(names, yuzu::agent::kEnvNamesCaseInsensitive);
    CHECK(std::find(bad.begin(), bad.end(), name) != bad.end());
}

TEST_CASE("update signature startup lines: mode, bundle path, and warnings",
          "[updater][signing][5249]") {
    using yuzu::agent::build_update_signature_startup_lines;
    const std::vector<std::string> no_env;

    SECTION("off: one info line, says signatures are not checked, no warning") {
        const auto lines = build_update_signature_startup_lines(cfg({}, false), no_env, false);
        REQUIRE(lines.size() == 1);
        CHECK_FALSE(lines[0].warning);
        CHECK(lines[0].text.find("mode: off") != std::string::npos);
        CHECK(lines[0].text.find("NOT signature-checked") != std::string::npos);
    }

    SECTION("bundle / bundle+require with a loadable bundle: info line with the path") {
        auto f = build_signing_fixtures();
        for (const bool require : {false, true}) {
            const auto lines =
                build_update_signature_startup_lines(cfg(f.trust_bundle, require), no_env, false);
            INFO("require=" << require);
            REQUIRE(lines.size() == 1);
            CHECK_FALSE(lines[0].warning);
            CHECK(lines[0].text.find(require ? "mode: bundle+require" : "mode: bundle (") !=
                  std::string::npos);
            CHECK(lines[0].text.find(f.trust_bundle.string()) != std::string::npos);
        }
    }

    SECTION("bundle set but missing: a separate warning naming the fault") {
        auto f = build_signing_fixtures();
        const auto missing = f.dir / "absent-bundle.pem";
        const auto lines = build_update_signature_startup_lines(cfg(missing, true), no_env, false);
        REQUIRE(lines.size() == 2);
        CHECK_FALSE(lines[0].warning); // the mode line is still emitted
        CHECK(lines[0].text.find("mode: bundle+require") != std::string::npos);
        CHECK(lines[1].warning);
        CHECK(lines[1].text.find("cannot be loaded") != std::string::npos);
        CHECK(lines[1].text.find("not found") != std::string::npos);
        CHECK(lines[1].text.find("bundle_unreadable") != std::string::npos);
    }

    SECTION("bundle set but not PEM: warned too") {
        auto f = build_signing_fixtures();
        const auto junk = f.dir / "junk-bundle.pem";
        std::ofstream(junk, std::ios::binary) << "junk";
        const auto lines = build_update_signature_startup_lines(cfg(junk, false), no_env, false);
        CHECK(warning_count(lines) == 1);
        CHECK(any_line_contains(lines, true, "cannot be loaded"));
    }

    SECTION("one warning per unrecognised YUZU_UPDATE_ name, names only") {
        const std::vector<std::string> env = {"YUZU_UPDATE_TRUST_BUNDEL", "PATH",
                                              "YUZU_UPDATE_REQUIRE_SIGNATURE",
                                              "YUZU_UPDATE_REQUIRE_SIG"};
        const auto lines = build_update_signature_startup_lines(cfg({}, false), env, false);
        CHECK(warning_count(lines) == 2);
        CHECK(any_line_contains(lines, true, "'YUZU_UPDATE_TRUST_BUNDEL'"));
        CHECK(any_line_contains(lines, true, "'YUZU_UPDATE_REQUIRE_SIG'"));
        CHECK_FALSE(any_line_contains(lines, true, "'YUZU_UPDATE_REQUIRE_SIGNATURE'"));
    }
}
