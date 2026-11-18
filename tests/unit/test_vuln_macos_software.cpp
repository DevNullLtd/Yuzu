/**
 * test_vuln_macos_software.cpp — WP13c: macOS software-enumeration coverage contract.
 *
 * The system_profiler call only runs under __APPLE__, so the decisions live in the portable
 * macos_software.hpp and are pinned here on every host.
 */

#include "macos_software.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::vuln;

namespace {
const std::string kSample =
    "Applications:\n"
    "\n"
    "    Safari:\n"
    "\n"
    "      Version: 17.4\n"
    "      Obtained from: Apple\n"
    "      Location: /Applications/Safari.app\n"
    "\n"
    "    Google Chrome:\n"
    "\n"
    "      Version: 122.0.6261.94\n"
    "      Kind: Intel\n";
} // namespace

TEST_CASE("macos enumeration: parses names and versions from raw system_profiler output",
          "[vuln][macos]") {
    auto e = parse_system_profiler_apps(kSample, true);
    REQUIRE(e.apps.size() == 2);
    CHECK(e.apps[0].name == "Safari");
    CHECK(e.apps[0].version == "17.4");
    CHECK(e.apps[1].name == "Google Chrome");
    CHECK(e.apps[1].version == "122.0.6261.94");
    CHECK(e.readable);
}

TEST_CASE("macos enumeration: a healthy read is CONSTRAINED for Homebrew only", "[vuln][macos]") {
    auto e = parse_system_profiler_apps(kSample, true);
    CHECK(macos_status_token(e) == "macos:vuln_scan:homebrew_not_scanned");
}

TEST_CASE("macos enumeration: empty output is unreadable, never a clean zero", "[vuln][macos]") {
    auto e = parse_system_profiler_apps("", true);
    CHECK(e.apps.empty());
    CHECK_FALSE(e.readable);
    CHECK(macos_status_token(e) == "macos:vuln_scan:system_profiler_unreadable");
}

TEST_CASE("macos enumeration: a failed command is unreadable even with partial output",
          "[vuln][macos]") {
    auto e = parse_system_profiler_apps(kSample, false);
    CHECK_FALSE(e.readable);
    CHECK(macos_status_token(e) == "macos:vuln_scan:system_profiler_unreadable");
}

TEST_CASE("macos enumeration: output with no application rows is unreadable", "[vuln][macos]") {
    auto e = parse_system_profiler_apps("Applications:\n\n", true);
    CHECK_FALSE(e.readable);
}

TEST_CASE("macos enumeration: provenance tokens match the leg-token grammar", "[vuln][macos]") {
    for (auto t : {kMacosHomebrewNotScanned, kMacosSystemProfilerUnreadable}) {
        CHECK(t.starts_with("macos:"));
        for (char c : t)
            CHECK(((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == ':'));
    }
}

TEST_CASE("macos commands: every argv[0] is an absolute path (no daemon-PATH resolution)",
          "[vuln][macos]") {
    for (auto cmd : kMacosCommands) {
        INFO(std::string(cmd));
        REQUIRE_FALSE(cmd.empty());
        CHECK(cmd.front() == '/');
    }
    CHECK(kMacosSystemProfilerCmd.starts_with("/usr/sbin/system_profiler "));
}
