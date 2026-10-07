/**
 * test_update_signature_mode.cpp — the agent's OTA update-signature posture
 * report (#5249): the mode it derives, the heartbeat tag, the YUZU_UPDATE_*
 * typo check, and the startup log lines.
 *
 * main.cpp (which emits the startup lines) and agent.cpp's heartbeat lambda are
 * in no test target, so both are thin callers of the helpers pinned here: the
 * mode tag is written through emit_update_signature_mode_tag() into the same
 * map type contract the protobuf status_tags map satisfies, the startup lines
 * are built by build_update_signature_startup_lines() and emitted by
 * log_update_signature_startup_report(), and the OTA update thread's bundle
 * warning is update_trust_bundle_warning() / log_update_trust_bundle_probe().
 */

#include <yuzu/agent/update_signature_mode.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "cms_test_fixtures.hpp"
#include "scoped_env.hpp"

#ifdef _WIN32
#include <process.h> // _getpid
#else
#include <fcntl.h>    // open (FIFO unblock)
#include <sys/stat.h> // mkfifo
#include <unistd.h>   // getpid
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

    SECTION("startup lines perform no I/O: an absent bundle is not probed here") {
        // #5249 Gate 7: the bundle probe moved to the OTA update thread, so the
        // startup report (which runs before the Windows SCM hand-off) says only
        // the mode — even for a bundle that does not exist.
        auto f = build_signing_fixtures();
        const auto missing = f.dir / "absent-bundle.pem";
        const auto lines = build_update_signature_startup_lines(cfg(missing, true), no_env, false);
        REQUIRE(lines.size() == 1);
        CHECK_FALSE(lines[0].warning);
        CHECK(lines[0].text.find("mode: bundle+require") != std::string::npos);
    }

#ifndef _WIN32
    SECTION("startup lines perform no I/O: a FIFO bundle with no writer does not block") {
        // The Gate 7 blocker itself: a FIFO (or an unreachable share) as the
        // bundle blocked the old startup probe's open forever, before the SCM
        // hand-off. Bounded harness: a regression FAILs within 10s.
        auto f = build_signing_fixtures();
        const auto fifo = f.dir / "fifo-bundle.pem";
        REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
        using namespace std::chrono_literals;
        auto lines = run_bounded(
            [c = cfg(fifo, true)] {
                return build_update_signature_startup_lines(c, std::vector<std::string>{}, false);
            },
            10s,
            [fifo] {
                const int w = ::open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
                if (w >= 0)
                    ::close(w);
            });
        if (!lines)
            FAIL("build_update_signature_startup_lines blocked on a FIFO trust bundle for 10s");
        REQUIRE(lines->size() == 1);
        CHECK_FALSE((*lines)[0].warning);
    }
#endif

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

TEST_CASE("update trust bundle warning: logged by the OTA update thread, not at startup",
          "[updater][signing][5249]") {
    using yuzu::agent::update_trust_bundle_warning;
    auto f = build_signing_fixtures();

    SECTION("off: nothing to probe") {
        CHECK_FALSE(update_trust_bundle_warning(cfg({}, false)).has_value());
        CHECK_FALSE(update_trust_bundle_warning(cfg({}, true)).has_value());
    }

    SECTION("a loadable bundle: no warning in either mode") {
        CHECK_FALSE(update_trust_bundle_warning(cfg(f.trust_bundle, false)).has_value());
        CHECK_FALSE(update_trust_bundle_warning(cfg(f.trust_bundle, true)).has_value());
    }

    SECTION("a missing bundle, bundle+require: warns with the reason, no unsigned caveat") {
        const auto missing = f.dir / "absent-bundle.pem";
        const auto w = update_trust_bundle_warning(cfg(missing, true));
        REQUIRE(w.has_value());
        CHECK(w->warning);
        CHECK(w->text.find("as of this check") != std::string::npos);
        CHECK(w->text.find("not found") != std::string::npos);
        CHECK(w->text.find("reason=bundle_unreadable") != std::string::npos);
        CHECK(w->text.find("unsigned updates are still accepted") == std::string::npos);
    }

    SECTION("a missing bundle, bundle mode: says unsigned updates are still accepted") {
        const auto missing = f.dir / "absent-bundle.pem";
        const auto w = update_trust_bundle_warning(cfg(missing, false));
        REQUIRE(w.has_value());
        CHECK(w->text.find("reason=bundle_unreadable") != std::string::npos);
        CHECK(w->text.find("unsigned updates are still accepted") != std::string::npos);
    }

    SECTION("a bundle that is not PEM: warned too") {
        const auto junk = f.dir / "junk-bundle.pem";
        std::ofstream(junk, std::ios::binary) << "junk";
        const auto w = update_trust_bundle_warning(cfg(junk, false));
        REQUIRE(w.has_value());
        CHECK(w->text.find("reason=bundle_unreadable") != std::string::npos);
    }
}

// A diagnostic must never stop boot (#5249 Gate 7): both emitters are noexcept,
// so a throw inside them is caught by their own firewall, never std::terminate.
static_assert(noexcept(
    yuzu::agent::log_update_signature_startup_report(std::declval<const UpdateConfig&>())));
static_assert(
    noexcept(yuzu::agent::log_update_trust_bundle_probe(std::declval<const UpdateConfig&>())));

TEST_CASE("update signature log emitters: never throw, even on a missing bundle",
          "[updater][signing][5249]") {
    auto f = build_signing_fixtures();
    const auto missing = f.dir / "absent-bundle.pem";
    for (const bool require : {false, true}) {
        CHECK_NOTHROW(yuzu::agent::log_update_signature_startup_report(cfg(missing, require)));
        CHECK_NOTHROW(yuzu::agent::log_update_trust_bundle_probe(cfg(missing, require)));
    }
#ifdef _WIN32
    // A non-ACP path (Cyrillic) reaches the report via CLI11's UTF-8 widen; on
    // MSVC path::string() throws for it. The firewall must turn that into a
    // "report skipped" warning, not a terminated boot.
    const fs::path non_acp = L"C:\\yuzu\\\u042F\\bundle.pem";
    CHECK_NOTHROW(yuzu::agent::log_update_signature_startup_report(cfg(non_acp, true)));
    CHECK_NOTHROW(yuzu::agent::log_update_trust_bundle_probe(cfg(non_acp, true)));
#endif
}
