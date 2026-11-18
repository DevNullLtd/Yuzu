/**
 * test_vuln_macos_software.cpp — WP13c: macOS software-enumeration coverage contract.
 *
 * The system_profiler call only runs under __APPLE__, so the decisions live in the portable
 * macos_software.hpp and are pinned here on every host.
 */

#include "config_checks.hpp"
#include "macos_software.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

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

namespace {
CoverageState state_of(const MacosEnumeration& e) {
    CoverageState c;
    c.macos_software = true;
    c.sp_readable = e.readable;
    return c;
}
} // namespace

TEST_CASE("macos enumeration: a healthy read is CONSTRAINED for Homebrew only", "[vuln][macos]") {
    auto c = state_of(parse_system_profiler_apps(kSample, true));
    CHECK(coverage_token(c) == "macos:vuln_scan:homebrew_not_scanned");
    CHECK(coverage_note(c) == "Homebrew formulae and casks are not scanned");
}

TEST_CASE("macos enumeration: empty output is unreadable, never a clean zero", "[vuln][macos]") {
    auto e = parse_system_profiler_apps("", true);
    CHECK(e.apps.empty());
    CHECK_FALSE(e.readable);
    CHECK(coverage_token(state_of(e)) == "macos:vuln_scan:system_profiler_unreadable");
}

TEST_CASE("macos enumeration: a failed command is unreadable even with partial output",
          "[vuln][macos]") {
    auto e = parse_system_profiler_apps(kSample, false);
    CHECK_FALSE(e.readable);
    CHECK(coverage_token(state_of(e)) == "macos:vuln_scan:system_profiler_unreadable");
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
    const auto cmds = macos_commands();
    CHECK(cmds.size() == 7);
    for (const Argv* argv : cmds) {
        REQUIRE_FALSE(argv->empty());
        INFO((*argv)[0]);
        REQUIRE_FALSE((*argv)[0].empty());
        CHECK((*argv)[0].front() == '/');
        // pre-split argv, no shell: no element carries a shell operator
        for (const auto& a : *argv)
            CHECK(a.find_first_of("|;&<>`$") == std::string::npos);
    }
    CHECK(kMacosSystemProfilerCmd.front() == "/usr/sbin/system_profiler");
}

TEST_CASE("macos commands: bounds are set", "[vuln][macos]") {
    CHECK(kMacosCommandDeadlineMs == 60'000);
    CHECK(kMacosCommandMaxOutput == 8u * 1024u * 1024u);
}

#if defined(__linux__) || defined(__APPLE__)
TEST_CASE("run_cmd: exit status is reported and the pipe is released", "[vuln][runcmd]") {
    bool ok = false;
    CHECK(detail::run_cmd("printf 'x\\n'", &ok) == "x");
    CHECK(ok);
    CHECK(detail::run_cmd("echo bad; exit 3", &ok) == "bad");
    CHECK_FALSE(ok);
    CHECK(detail::run_cmd("/nonexistent/yuzu_test_tool 2>/dev/null", &ok).empty());
    CHECK_FALSE(ok);
    for (int i = 0; i < 300; ++i) // a leaked FILE*/child per call would exhaust fds
        (void)detail::run_cmd("true", &ok);
    CHECK(ok);
}
#endif

// ── in-band coverage rows (the operator-visible half of the status) ──────────

TEST_CASE("coverage: rows match the existing row shapes", "[vuln][macos][coverage]") {
    auto c = state_of(parse_system_profiler_apps(kSample, true));
    CHECK(coverage_row(coverage_note(c)) ==
          "INFO|scan|Coverage|Homebrew formulae and casks are not scanned");
    CHECK(coverage_summary_row(coverage_note(c)) ==
          "summary|COVERAGE|Homebrew formulae and casks are not scanned");
    // 4 pipe-delimited fields like every cve/config row.
    const auto row = coverage_row(coverage_note(c));
    CHECK(std::count(row.begin(), row.end(), '|') == 3);
}

TEST_CASE("coverage: an unreadable software list says so in-band", "[vuln][macos][coverage]") {
    auto c = state_of(parse_system_profiler_apps("", true));
    CHECK(coverage_note(c) == kCoverageNoteUnreadable);
    CHECK(coverage_note(c) != kCoverageNoteHomebrew);
}

TEST_CASE("coverage: nothing declared where nothing is known to be missing", "[vuln][coverage]") {
    CoverageState c; // Linux / Windows / macOS config_scan with every read ok
    CHECK(coverage_token(c).empty());
    CHECK(coverage_note(c).empty());
}

TEST_CASE("coverage: token precedence is software list, then config, then Homebrew",
          "[vuln][coverage]") {
    CoverageState c;
    c.macos_software = true;
    c.config_unreadable = true;
    CHECK(coverage_token(c) == kMacosConfigUnreadable);
    c.sp_readable = false;
    CHECK(coverage_token(c) == kMacosSystemProfilerUnreadable);
    CoverageState cfg_only; // config_scan: no software list, but a failed read
    cfg_only.config_unreadable = true;
    CHECK(coverage_token(cfg_only) == kMacosConfigUnreadable);
    CHECK(coverage_note(cfg_only).empty()); // config rows carry their own INFO Unknown row
}

// ── parser edge cases ───────────────────────────────────────────────────────

TEST_CASE("parse: Version with no space after the colon keeps every digit", "[vuln][macos]") {
    auto e = parse_system_profiler_apps("    Safari:\n      Version:17.4\n", true);
    REQUIRE(e.apps.size() == 1);
    CHECK(e.apps[0].version == "17.4");
}

TEST_CASE("parse: CRLF, no trailing newline, padding", "[vuln][macos]") {
    auto e = parse_system_profiler_apps("    Safari:\r\n      Version:  17.4  \r\n    Mail:\r\n      Version: 16", true);
    REQUIRE(e.apps.size() == 2);
    CHECK(e.apps[0].version == "17.4");
    CHECK(e.apps[1].name == "Mail");
    CHECK(e.apps[1].version == "16");
}

TEST_CASE("parse: name without Version, Version before any name, duplicates", "[vuln][macos]") {
    auto e = parse_system_profiler_apps(
        "      Version: 9.9\n    NoVer:\n    Dup:\n      Version: 1\n    Dup:\n      Version: 2\n", true);
    REQUIRE(e.apps.size() == 3);
    CHECK(e.apps[0].name == "NoVer");
    CHECK(e.apps[0].version.empty());
    CHECK(e.apps[1].version == "1");
    CHECK(e.apps[2].version == "2");
}

TEST_CASE("parse: a very large application list stays linear and readable", "[vuln][macos]") {
    std::string big;
    for (int i = 0; i < 200000; ++i)
        big += "    App" + std::to_string(i) + ":\n      Version: 1." + std::to_string(i) + "\n";
    auto e = parse_system_profiler_apps(big, true);
    CHECK(e.apps.size() == 200000);
    CHECK(e.readable);
}

// ── config checks: table-driven, exact expected lines ──────────────────────

namespace {
struct Row {
    MacosCheck check;
    const char* healthy;  // output of the "good" state
    const char* bad;      // output of the "bad" state
    const char* title;
};
const Row kRows[] = {
    {MacosCheck::Gatekeeper, "assessments enabled", "assessments disabled", "Gatekeeper"},
    {MacosCheck::FileVault, "FileVault is On.", "FileVault is Off.", "FileVault Disk Encryption"},
    {MacosCheck::Sip, "System Integrity Protection status: enabled.",
     "System Integrity Protection status: disabled.", "System Integrity Protection (SIP)"},
    {MacosCheck::Firewall, "Firewall is enabled. (State = 1)", "Firewall is disabled. (State = 0)",
     "Application Firewall"},
    {MacosCheck::RemoteLogin, "Remote Login: Off", "Remote Login: On", "Remote Login (SSH)"},
    {MacosCheck::AutoUpdate, "1", "0", "Automatic Software Updates"},
};
} // namespace

TEST_CASE("macos config: good and bad states read as verdicts", "[vuln][macos][config]") {
    for (const auto& r : kRows) {
        INFO(r.title);
        auto good = macos_check_result(r.check, {r.healthy, true});
        CHECK(good.severity == "INFO");
        CHECK(good.passed);
        CHECK(good.detail != kConfigUnknownDetail);
        auto bad = macos_check_result(r.check, {r.bad, true});
        CHECK(bad.severity != "INFO");
        CHECK_FALSE(bad.passed);
    }
}

TEST_CASE("macos config: a failed or unrecognised read is INFO Unknown, never a verdict",
          "[vuln][macos][config]") {
    const CommandRead failures[] = {
        {"", false},                        // missing tool / failed to start
        {"command not found", false},       // non-zero exit
        {"", true},                         // empty output, exit 0
        {"You need administrator access to run this tool... exiting!", true}, // TCC / privilege
        {"Statut de la protection SIP : active.", true}, // localized csrutil
        {"assessments enabled", false},     // good-looking text but the command failed
    };
    for (const auto& r : kRows)
        for (const auto& f : failures) {
            INFO(r.title << " / " << f.out);
            auto res = macos_check_result(r.check, f);
            CHECK(res.severity == "INFO");
            CHECK(res.title == r.title);
            CHECK(res.detail == kConfigUnknownDetail);
            CHECK_FALSE(res.passed);
        }
}

TEST_CASE("macos config: FileVault 'Off' and 'Not On' never read as On", "[vuln][macos][config]") {
    CHECK_FALSE(macos_check_result(MacosCheck::FileVault, {"FileVault is Off.", true}).passed);
    auto not_on = macos_check_result(MacosCheck::FileVault, {"FileVault is Not On.", true});
    CHECK(not_on.detail == kConfigUnknownDetail); // unrecognised, not a green verdict
    CHECK(macos_check_result(MacosCheck::FileVault, {"FileVault is On, but needs restart.", true}).passed);
}

TEST_CASE("macos config: any_config_unreadable sees an Unknown row", "[vuln][macos][config]") {
    std::vector<ConfigCheckResult> v;
    CHECK_FALSE(any_config_unreadable(v));
    v.push_back(macos_check_result(MacosCheck::Gatekeeper, {"assessments enabled", true}));
    CHECK_FALSE(any_config_unreadable(v));
    v.push_back(macos_check_result(MacosCheck::Sip, {"", false}));
    CHECK(any_config_unreadable(v));
}
