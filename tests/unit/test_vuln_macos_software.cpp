/**
 * test_vuln_macos_software.cpp — WP13c: macOS software-enumeration coverage contract.
 *
 * The system_profiler call only runs under __APPLE__, so the decisions live in the portable
 * macos_software.hpp and are pinned here on every host.
 */

#include "config_checks.hpp"
#include "cve_rules.hpp"
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
    const auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 1);
    CHECK(notes[0].severity == "INFO");
    CHECK(notes[0].text == "Homebrew formulae and casks are not scanned");
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
    for (auto t : {kMacosHomebrewNotScanned, kMacosSystemProfilerUnreadable, kMacosConfigUnreadable}) {
        CHECK(t.starts_with("macos:"));
        for (char c : t)
            CHECK(((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == ':'));
    }
}

TEST_CASE("macos commands: every argv[0] is an absolute path (no daemon-PATH resolution)",
          "[vuln][macos]") {
    const auto cmds = macos_commands();
    CHECK(cmds.size() == 8);
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
    CHECK(kMacosToolDeadlineMs == 10'000);
    CHECK(kMacosToolDeadlineMs * 7 + kMacosCommandDeadlineMs == 130'000); // one action, nominal
    CHECK(kMacosCommandMaxOutput == 8u * 1024u * 1024u);
}

#if defined(__linux__)
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
    const auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 1);
    CHECK(coverage_row(notes[0]) ==
          "INFO|scan|Coverage|Homebrew formulae and casks are not scanned");
    CHECK(coverage_summary_row(notes[0]) ==
          "summary|COVERAGE|Homebrew formulae and casks are not scanned");
    const auto row = coverage_row(notes[0]);
    CHECK(std::count(row.begin(), row.end(), '|') == 3); // 4 fields like every cve/config row
}

TEST_CASE("coverage: an unreadable software list is an UNREADABLE row and never says 'empty'",
          "[vuln][macos][coverage]") {
    auto c = state_of(parse_system_profiler_apps("", true));
    const auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 1);
    CHECK(notes[0].severity == "UNREADABLE");
    CHECK(notes[0].text == kCoverageNoteUnreadable);
    CHECK(coverage_row(notes[0]).starts_with("UNREADABLE|scan|Coverage|"));
    // a partial read (timeout / cap) is not an empty list: the wording must not claim it is
    CHECK(kCoverageNoteUnreadable.find("empty") == std::string_view::npos);
    CHECK(kCoverageNoteUnreadable.find("not a clean result") != std::string_view::npos);
}

TEST_CASE("coverage: nothing declared where nothing is known to be missing", "[vuln][coverage]") {
    CoverageState c; // Linux / Windows / macOS config_scan with every read ok
    CHECK(coverage_token(c).empty());
    CHECK(coverage_notes(c).empty());
}

TEST_CASE("coverage: the status token is one slot with a documented precedence, the notes carry "
          "every cause",
          "[vuln][coverage]") {
    CoverageState c;
    c.macos_software = true;
    c.config_unreadable = true;
    CHECK(coverage_token(c) == kMacosConfigUnreadable);
    auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 2); // the Homebrew gap is NOT dropped by the single token slot
    CHECK(notes[0].text == kCoverageNoteHomebrew);
    CHECK(notes[1].text == kCoverageNoteConfig);
    c.sp_readable = false;
    CHECK(coverage_token(c) == kMacosSystemProfilerUnreadable);
    notes = coverage_notes(c);
    REQUIRE(notes.size() == 2);
    CHECK(notes[0].text == kCoverageNoteUnreadable);
    CHECK(notes[1].text == kCoverageNoteConfig);
}

TEST_CASE("coverage: config_scan alone gets an in-band note", "[vuln][coverage]") {
    CoverageState cfg_only;
    cfg_only.config_unreadable = true;
    CHECK(coverage_token(cfg_only) == kMacosConfigUnreadable);
    const auto notes = coverage_notes(cfg_only);
    REQUIRE(notes.size() == 1);
    CHECK(notes[0].severity == "UNREADABLE");
    CHECK(notes[0].text == kCoverageNoteConfig);
}

TEST_CASE("coverage: the note literals are pinned (README, YAML and cookbook quote them)",
          "[vuln][coverage]") {
    CHECK(kCoverageNoteHomebrew == "Homebrew formulae and casks are not scanned");
    CHECK(kCoverageNoteUnreadable ==
          "The macOS software list could not be read completely (system_profiler failed, timed out, "
          "exceeded the output cap, returned no applications, or most applications had no recognised "
          "Version line); not a clean result");
    CHECK(kCoverageNoteConfig ==
          "One or more macOS configuration checks could not be read; each is reported as an "
          "UNREADABLE row, not as a finding");
    CHECK(kConfigUnknownDetail == "Unknown (read failed)");
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

TEST_CASE("parse: a partial or failed run returns NO apps (never feeds matching)", "[vuln][macos]") {
    // truncated mid-value: "Version: 2" would compare below a CVE fix and read as vulnerable
    auto e = parse_system_profiler_apps("    Git:\n      Version: 2", false);
    CHECK(e.apps.empty());
    CHECK_FALSE(e.readable);
    auto ok = parse_system_profiler_apps(kSample, false);
    CHECK(ok.apps.empty());
}

TEST_CASE("parse: structural name and version lines", "[vuln][macos]") {
    // a name that is itself "Version: 99.0" must not become a version of the previous app
    auto e = parse_system_profiler_apps(
        "    Git:\n      Version: 2.50.1\n    Version: 99.0:\n      Version: 1.0\n    Python:\n      Version: 3.9.6\n",
        true);
    REQUIRE(e.apps.size() == 2);
    CHECK(e.apps[0].name == "Git");
    CHECK(e.apps[0].version == "2.50.1");
    CHECK(e.apps[1].name == "Python");
    CHECK(e.apps[1].version == "3.9.6");
}

TEST_CASE("parse: a four-space Version line is not a version", "[vuln][macos]") {
    const std::string pad = "    P1:\n      Version: 1\n    P2:\n      Version: 1\n    P3:\n      Version: 1\n"
                            "    P4:\n      Version: 1\n    P5:\n      Version: 1\n    P6:\n      Version: 1\n";
    auto e = parse_system_profiler_apps(pad + "    Git:\n    Version: 1.0\n      Version: 2.50.1\n", true);
    REQUIRE(e.apps.size() == 7);
    CHECK(e.apps[6].version == "2.50.1");
    CHECK(e.suspect_lines >= 1);
}

TEST_CASE("parse: only a four-space-indent line ending in ':' is a name", "[vuln][macos]") {
    // (padded with healthy apps: the odd-indent lines are suspect and must not outvote them)
    const std::string pad = "    P1:\n      Version: 1\n    P2:\n      Version: 1\n    P3:\n      Version: 1\n"
                            "    P4:\n      Version: 1\n    P5:\n      Version: 1\n    P6:\n      Version: 1\n";
    auto e = parse_system_profiler_apps(
        pad + "    A:\n      Sub:\n      Version: 1\n  Header:\n        Deep:\n   Three:\n", true);
    REQUIRE(e.apps.size() == 7);
    CHECK(e.apps[6].name == "A");
    CHECK(e.apps[6].version == "1");
}

TEST_CASE("parse: non-ASCII and punctuation-leading names are names", "[vuln][macos]") {
    auto e = parse_system_profiler_apps(
        "    \xE5\xBE\xAE\xE4\xBF\xA1:\n      Version: 9.9\n    Python:\n      Version: 3.9.6\n"
        "    (Beta) App:\n      Version: 1.2\n    \xC3\x89" "dit:\n      Version: 4\n",
        true);
    REQUIRE(e.apps.size() == 4);
    CHECK(e.apps[0].version == "9.9");
    CHECK(e.apps[1].name == "Python");
    CHECK(e.apps[1].version == "3.9.6");
    CHECK(e.apps[2].name == "(Beta) App");
    CHECK(e.apps[3].version == "4");
}

TEST_CASE("parse: the first Version under a name wins; version before a name is ignored",
          "[vuln][macos]") {
    const std::string pad = "    P1:\n      Version: 1\n    P2:\n      Version: 1\n    P3:\n      Version: 1\n"
                            "    P4:\n      Version: 1\n    P5:\n      Version: 1\n    P6:\n      Version: 1\n";
    auto e = parse_system_profiler_apps(
        "      Version: 7\n" + pad + "    A:\n      Version: 1\n      Version: 2\n", true);
    REQUIRE(e.apps.size() == 7);
    CHECK(e.apps[6].version == "1");
    CHECK(e.suspect_lines == 2); // the orphan Version and the second Version
}

TEST_CASE("fold_backslashes: a trailing backslash cannot swallow the pipe separator",
          "[vuln][macos]") {
    CHECK(fold_backslashes("Git\\") == "Git/");
    CHECK(fold_backslashes("a\\b\\") == "a/b/");
    CHECK(fold_backslashes("plain") == "plain");
}

// ── config checks: table-driven, exact expected lines ──────────────────────

TEST_CASE("macos config table: one row per check, absolute argv, exit-zero policy explicit",
          "[vuln][macos][config]") {
    REQUIRE(kMacosCheckSpecs.size() == 6);
    for (const auto& sp : kMacosCheckSpecs) {
        INFO(sp.title);
        REQUIRE(sp.argv != nullptr);
        CHECK((*sp.argv)[0].front() == '/');
        CHECK(sp.good_requires_exit_zero); // every measured good state exited 0
        CHECK(&macos_spec(sp.check) == &sp);
    }
}

namespace {
CommandRead good(std::string out) { return {std::move(out), true, true}; }
} // namespace

TEST_CASE("macos config: good and bad states read as verdicts", "[vuln][macos][config]") {
    for (const auto& sp : kMacosCheckSpecs) {
        INFO(sp.title);
        auto g = macos_check_result(sp.check, good(std::string(sp.good_line)));
        CHECK(g.severity == "INFO");
        CHECK(g.passed);
        auto b = macos_check_result(sp.check, good(std::string(sp.bad_line)));
        CHECK(b.severity == sp.bad_severity);
        CHECK_FALSE(b.passed);
    }
}

TEST_CASE("macos config: Firewall accepts the structural State suffix only", "[vuln][macos][config]") {
    const auto fw = [](const char* l) { return macos_check_result(MacosCheck::Firewall, good(l)); };
    CHECK(fw("Firewall is enabled. (State = 1)").passed);
    CHECK_FALSE(fw("Firewall is disabled. (State = 0)").passed);
    CHECK(fw("Firewall is enabled.").passed);
    for (const char* bad : {"Firewall is enabled. (State = 12)", "Firewall is enabled. (State = x)",
                            "Firewall is enabled. (State = 1) extra", "Firewall is enabledX",
                            "Firewall is enabled (State = 1)", "Firewall is enabled. (State = 1"})
        CHECK(fw(bad).severity == "UNREADABLE");
}

TEST_CASE("macos config: a failed or unrecognised read is UNREADABLE, never a verdict",
          "[vuln][macos][config]") {
    const CommandRead failures[] = {
        {"", false, false},                  // missing tool / failed to start
        {"command not found", false, true},  // non-zero exit
        {"", true, true},                    // empty output, exit 0
        {"You need administrator access to run this tool... exiting!", true, true},
        {"Statut de la protection SIP : active.", true, true}, // localized csrutil
    };
    for (const auto& sp : kMacosCheckSpecs) {
        for (const auto& f : failures) {
            INFO(sp.title << " / " << f.out);
            auto res = macos_check_result(sp.check, f);
            CHECK(res.severity == "UNREADABLE");
            CHECK(res.title == sp.title);
            CHECK(res.detail == kConfigUnknownDetail);
            CHECK_FALSE(res.passed);
        }
        // good-looking text from a run that failed (exit != 0) is unreadable while exit 0 is required
        auto res = macos_check_result(sp.check, {std::string(sp.good_line), false, true});
        CHECK(res.severity == "UNREADABLE");
    }
}

TEST_CASE("macos config: near-miss lines are NOT accepted",
          "[vuln][macos][config]") {
    struct NearMiss { MacosCheck c; const char* line; };
    const NearMiss cases[] = {
        {MacosCheck::Sip, "System Integrity Protection status: enabled (Custom Configuration)."},
        {MacosCheck::Sip, "System Integrity Protection status: unknown (Custom Configuration)."},
        {MacosCheck::Sip, "System Integrity Protection status: enabled"},
        {MacosCheck::FileVault, "FileVault is Onward"},
        {MacosCheck::FileVault, "FileVault is On, but needs restart."},
        {MacosCheck::FileVault, "FileVault is Not On."},
        {MacosCheck::Gatekeeper, "assessments enabledfoo"},
        {MacosCheck::Gatekeeper, "assessments enabled."},
        {MacosCheck::RemoteLogin, "Remote Login: Onward"},
        {MacosCheck::AutoUpdate, "10"},
    };
    for (const auto& n : cases) {
        INFO(n.line);
        CHECK(macos_check_result(n.c, good(n.line)).severity == "UNREADABLE");
    }
}

TEST_CASE("macos config: the WHOLE output is judged: one non-empty line for a good verdict",
          "[vuln][macos][config]") {
    const auto fv = [](const char* o) { return macos_check_result(MacosCheck::FileVault, good(o)); };
    CHECK(fv("  FileVault is On.  \n").passed);
    CHECK(fv("\n\nFileVault is On.\n\n").passed); // blank lines ignored
    CHECK(fv("FileVault is On.\nextra").severity == "UNREADABLE");
    CHECK(fv("extra\nFileVault is On.").severity == "UNREADABLE");
    CHECK(fv("FileVault is On.\nFileVault is On.").severity == "UNREADABLE");
    // any bad line wins over a good one (contradictory output is never a pass)
    CHECK(fv("FileVault is On.\nFileVault is Off.").severity == "HIGH");
    CHECK(fv("FileVault is Off.\nFileVault is On.").severity == "HIGH");
    CHECK(macos_check_result(MacosCheck::Gatekeeper, good("assessments enabled\nassessments disabled"))
              .severity == "HIGH");
    CHECK(macos_check_result(MacosCheck::Sip,
                             good("System Integrity Protection status: enabled.\n"
                                  "System Integrity Protection status: disabled."))
              .severity == "CRITICAL");
}

TEST_CASE("macos config: Firewall state digit must agree with the text", "[vuln][macos][config]") {
    const auto fw = [](const char* l) { return macos_check_result(MacosCheck::Firewall, good(l)); };
    CHECK(fw("Firewall is enabled. (State = 1)").passed);
    CHECK(fw("Firewall is enabled. (State = 2)").passed); // enabled digits 1 and 2: UNVERIFIED
    CHECK(fw("Firewall is disabled. (State = 0)").severity == "MEDIUM"); // measured pairing
    CHECK(fw("Firewall is enabled. (State = 0)").severity == "UNREADABLE");
    CHECK(fw("Firewall is enabled. (State = 3)").severity == "UNREADABLE");
    CHECK(fw("Firewall is disabled. (State = 1)").severity == "UNREADABLE");
    CHECK(fw("Firewall is disabled. (State = 2)").severity == "UNREADABLE");
}

TEST_CASE("macos config: a BAD line is judged from any completed run; GOOD needs exit 0",
          "[vuln][macos][config]") {
    // Bad-state exit codes are NOT measured; a bad line is a finding whatever the exit code.
    for (const auto& sp : kMacosCheckSpecs) {
        INFO(sp.title);
        auto bad = macos_check_result(sp.check, {std::string(sp.bad_line), false, true});
        CHECK(bad.severity == sp.bad_severity);
        CHECK_FALSE(bad.passed);
        // a good line from a non-zero exit is unreadable, never a pass
        auto g = macos_check_result(sp.check, {std::string(sp.good_line), false, true});
        CHECK(g.severity == "UNREADABLE");
        // a run that never completed judges nothing, even with a bad-looking line
        CHECK(macos_check_result(sp.check, {std::string(sp.bad_line), false, false}).severity ==
              "UNREADABLE");
    }
    CHECK(macos_check_result(MacosCheck::Gatekeeper, {"assessments disabled", false, true}).severity ==
          "HIGH");
}

TEST_CASE("macos config: the shipped defaults argvs (bare domain and path form) both reach the "
          "absent-key INFO",
          "[vuln][macos][config]") {
    const auto rows = run_macos_checks_table([](const Argv& a, bool) {
        if (a.size() == 4 && (a[2] == "com.apple.SoftwareUpdate" ||
                              a[2] == "/Library/Preferences/com.apple.SoftwareUpdate"))
            return CommandRead{"Error: Could not find key 'AutomaticCheckEnabled' in domain "
                               "'com.apple.SoftwareUpdate'.",
                               false, true};
        return CommandRead{};
    });
    const auto& r = rows[5];
    CHECK(r.title == "Automatic update check");
    CHECK(r.severity == "INFO");
    CHECK(r.detail == "Automatic update check: not set (macOS default applies)");
    CHECK(kMacosDefaultsCmd[2] == "com.apple.SoftwareUpdate");
    CHECK(kMacosDefaultsPathCmd[2] == "/Library/Preferences/com.apple.SoftwareUpdate");
    CHECK(macos_spec(MacosCheck::AutoUpdate).argv_alt == &kMacosDefaultsPathCmd);
    CHECK(macos_spec(MacosCheck::AutoUpdate).good_detail ==
          "Enabled (check only; install not assessed)");
}

namespace {
const char* const kAbsent =
    "Error: Could not find key 'AutomaticCheckEnabled' in domain 'com.apple.SoftwareUpdate'.";
ConfigCheckResult dual(const CommandRead& bare, const CommandRead& path) {
    return macos_check_result_dual(MacosCheck::AutoUpdate, bare, path);
}
CommandRead rd(const char* t) { return {t, true, true}; }
CommandRead absent_rd() { return {kAbsent, false, true}; } // measured: exit 1
CommandRead dead() { return {"", false, false}; }
} // namespace

TEST_CASE("macos config: the update check is read twice and the WORSE answer wins",
          "[vuln][macos][config][dual]") {
    // bare says absent/shadowed, the system plist says 0: a real finding must not be hidden
    CHECK(dual(absent_rd(), rd("0")).severity == "MEDIUM");
    CHECK(dual(rd("1"), rd("0")).severity == "MEDIUM");   // a per-user/managed 1 shadows system 0
    CHECK(dual(rd("0"), absent_rd()).severity == "MEDIUM"); // MDM-forced 0, system absent
    CHECK(dual(rd("0"), rd("0")).severity == "MEDIUM");
    CHECK(dual(rd("0"), dead()).severity == "MEDIUM");    // bad wins over an unreadable read
    CHECK(dual(dead(), rd("0")).severity == "MEDIUM");
    // INFO needs both reads good-or-absent AND agreeing
    CHECK(dual(absent_rd(), absent_rd()).severity == "INFO");
    CHECK(dual(absent_rd(), absent_rd()).detail ==
          "Automatic update check: not set (macOS default applies)");
    CHECK(dual(rd("1"), rd("1")).severity == "INFO");
    CHECK(dual(rd("1"), rd("1")).detail == "Enabled (check only; install not assessed)");
    // a good read beside an absent read is a disagreement, not a pass
    CHECK(dual(absent_rd(), rd("1")).severity == "UNREADABLE");
    CHECK(dual(rd("1"), absent_rd()).severity == "UNREADABLE");
    // either read unreadable
    CHECK(dual(dead(), absent_rd()).severity == "UNREADABLE");
    CHECK(dual(absent_rd(), dead()).severity == "UNREADABLE");
    CHECK(dual(rd("x"), absent_rd()).severity == "UNREADABLE");
    CHECK(dual(rd("1"), rd("weird")).severity == "UNREADABLE");
    CHECK(dual(dead(), dead()).severity == "UNREADABLE");
}

TEST_CASE("macos config: the standing open-port unavailability does not raise the config token",
          "[vuln][macos][config]") {
    std::vector<ConfigCheckResult> v;
    v.push_back({"UNREADABLE", "Open Ports", std::string(kOpenPortUnavailableDetail), false});
    CHECK_FALSE(any_config_unreadable(v)); // visible as an UNREADABLE row, not a CONSTRAINED token
    v.push_back(macos_check_result(MacosCheck::Sip, {"", false, false}));
    CHECK(any_config_unreadable(v));
}

TEST_CASE("macos config: a null reader fails closed", "[vuln][macos][config]") {
    const auto rows = run_macos_checks_table(MacosReader{});
    REQUIRE(rows.size() == 6);
    for (const auto& r : rows)
        CHECK(r.severity == "UNREADABLE");
    CHECK(any_config_unreadable(rows));
}

TEST_CASE("macos config: the table drives the reader with each check's own argv",
          "[vuln][macos][config]") {
    std::vector<std::string> seen;
    std::vector<bool> merged;
    const auto rows = run_macos_checks_table([&](const Argv& a, bool merge_stderr) {
        seen.push_back(a[0]);
        merged.push_back(merge_stderr);
        return CommandRead{};
    });
    CHECK(rows.size() == 6);
    CHECK(seen.size() == 7); // the update-check setting is read twice
    CHECK(seen[0] == "/usr/sbin/spctl");
    // only the two defaults reads report on stderr
    CHECK(std::count(merged.begin(), merged.end(), true) == 2);
    CHECK(merged[5]);
    CHECK(merged[6]);
}

TEST_CASE("macos config: an UNREADABLE row is counted in summary's UNREADABLE bucket",
          "[vuln][macos][config]") {
    std::vector<std::string> sev;
    for (const auto& r : run_macos_checks_table(MacosReader{}))
        sev.push_back(std::string(r.severity));
    const auto rows = summary_rows(sev);
    bool saw = false;
    for (const auto& row : rows)
        if (row == "summary|UNREADABLE|6")
            saw = true;
    CHECK(saw);
}

TEST_CASE("macos config: any_config_unreadable keys on severity", "[vuln][macos][config]") {
    std::vector<ConfigCheckResult> v;
    CHECK_FALSE(any_config_unreadable(v));
    v.push_back(macos_check_result(MacosCheck::Gatekeeper, good("assessments enabled")));
    CHECK_FALSE(any_config_unreadable(v));
    v.push_back(macos_check_result(MacosCheck::Sip, {"", false, false}));
    CHECK(any_config_unreadable(v));
}

// ── golden fixtures: REAL output measured on ONE macOS 27.0.1 host: spctl `assessments enabled`,
//    fdesetup `FileVault is On.`, csrutil `... enabled.`, systemsetup `Remote Login: Off` (each exit 0),
//    socketfilterfw `Firewall is disabled. (State = 0)` (exit 0; the DISABLED state) and the path-form
//    `defaults` key-absent line (exit 1). Unmeasured: the bare-domain defaults text, system-plist
//    shadowing, bad-state exit codes, the enabled-Firewall digit, `systemsetup` as a daemon, FDA/PPPC
//    needs and a non-English system_profiler. ─────────────────────────────────────────────────

TEST_CASE("golden macOS 27.0.1: the five status tools' real lines are accepted", "[vuln][macos][golden]") {
    // MEASURED exit codes on that host: every tool below exited 0 in the state shown, so `good()`
    // (ok = ran = true) is the real shape; bad-state exit codes are NOT measured.
    const auto r = [](MacosCheck c, const char* line) { return macos_check_result(c, good(line)); };
    auto gk = r(MacosCheck::Gatekeeper, "assessments enabled");
    CHECK(gk.severity == "INFO");
    CHECK(gk.passed);
    auto fv = r(MacosCheck::FileVault, "FileVault is On.");
    CHECK(fv.severity == "INFO");
    CHECK(fv.passed);
    auto sip = r(MacosCheck::Sip, "System Integrity Protection status: enabled.");
    CHECK(sip.severity == "INFO");
    CHECK(sip.passed);
    // the firewall on that Mac is genuinely OFF: a real finding, not an unreadable
    auto fw = r(MacosCheck::Firewall, "Firewall is disabled. (State = 0)");
    CHECK(fw.severity == "MEDIUM");
    CHECK(fw.detail == "Disabled");
    CHECK_FALSE(fw.passed);
    auto rl = r(MacosCheck::RemoteLogin, "Remote Login: Off");
    CHECK(rl.severity == "INFO");
    CHECK(rl.passed);
}

namespace {
const char* const kDefaultsAbsent =
    "Error: Could not find key 'AutomaticCheckEnabled' in domain 'com.apple.SoftwareUpdate'.";
} // namespace

TEST_CASE("golden macOS 27.0.1: an absent AutomaticCheckEnabled key is INFO, not unreadable or bad",
          "[vuln][macos][golden]") {
    // MEASURED: `defaults read` exits 1 with the key absent (ran, not ok); the verdict must not
    // depend on the exit code, so exit 0 is covered too.
    for (const CommandRead& rd : {CommandRead{kDefaultsAbsent, false, true},
                                  CommandRead{kDefaultsAbsent, true, true},
                                  CommandRead{std::string(kDefaultsAbsent) + "\n", false, true}}) {
        auto res = macos_check_result(MacosCheck::AutoUpdate, rd);
        CHECK(res.severity == "INFO");
        CHECK(res.title == "Automatic update check");
        CHECK(res.detail == "Automatic update check: not set (macOS default applies)");
        CHECK(res.passed);
    }
    // 1 good, 0 bad, anything else unknown
    CHECK(macos_check_result(MacosCheck::AutoUpdate, good("1")).passed);
    CHECK(macos_check_result(MacosCheck::AutoUpdate, good("0")).severity == "MEDIUM");
    CHECK(macos_check_result(MacosCheck::AutoUpdate, good("2")).severity == "UNREADABLE");
    CHECK(macos_check_result(MacosCheck::AutoUpdate,
                             good("Error: Could not find key 'Other' in domain 'x'."))
              .severity == "UNREADABLE");
    // the tool did not run at all: still unreadable, even with the message text
    CHECK(macos_check_result(MacosCheck::AutoUpdate, {kDefaultsAbsent, false, false}).severity ==
          "UNREADABLE");
    // other checks have no absent form
    CHECK(macos_check_result(MacosCheck::Gatekeeper, {kDefaultsAbsent, false, true}).severity ==
          "UNREADABLE");
}

TEST_CASE("golden macOS 27.0.1: the real system_profiler shape parses; property lines are not names",
          "[vuln][macos][golden]") {
    const std::string real =
        "Applications:\n"
        "\n"
        "    App Store:\n"
        "\n"
        "      Version: 3.0\n"
        "      Obtained from: Apple\n"
        "      Last Modified: 24/09/2026, 08:10\n"
        "      Kind: Apple Silicon\n"
        "      Signed by: Software Signing, Apple Code Signing Certification Authority, Apple Root CA\n"
        "      Location: /System/Applications/App Store.app\n"
        "\n"
        "    Safari:\n"
        "\n"
        "      Version: 27.0\n"
        "      Obtained from: Apple\n"
        "      Signed by:\n"
        "      Location: /Applications/Safari.app\n";
    auto e = parse_system_profiler_apps(real, true);
    REQUIRE(e.apps.size() == 2);
    CHECK(e.apps[0].name == "App Store");
    CHECK(e.apps[0].version == "3.0");
    CHECK(e.apps[1].name == "Safari");
    CHECK(e.apps[1].version == "27.0");
    CHECK(e.readable);
    // 6-space property lines (even ones ending in ':') are never names
    for (const auto& a : e.apps) {
        CHECK(a.name != "Signed by");
        CHECK(a.name != "Obtained from");
        CHECK(a.name != "Location");
    }
}

TEST_CASE("parse: a localized Version label leaves no versions, so the read is unreadable",
          "[vuln][macos]") {
    const char* const localized[] = {
        "    Safari:\n\n      Version : 17.4\n    Mail:\n      Version : 16\n", // French spacing
        "    Safari:\n\n      \xE3\x83\x90\xE3\x83\xBC\xE3\x82\xB8\xE3\x83\xA7\xE3\x83\xB3: 17.4\n", // Japanese label
        "    Safari:\n\n      Versi\xC3\xB3n: 17.4\n",                                          // Spanish
    };
    for (const char* o : localized) {
        auto e = parse_system_profiler_apps(o, true);
        CHECK(e.apps.empty()); // never name-only rows feeding a clean scan
        CHECK_FALSE(e.readable);
    }
    // one app with a version keeps the read readable
    auto mixed = parse_system_profiler_apps("    A:\n    B:\n      Version: 1\n", true);
    CHECK(mixed.readable);
    CHECK(mixed.apps.size() == 2);
}

TEST_CASE("parse: a report where most apps lack a recognised version is unreadable",
          "[vuln][macos]") {
    // mixed labels: 1 English-versioned app, 3 with a localized label -> more than half unversioned
    auto mixed = parse_system_profiler_apps(
        "    A:\n      Version: 1\n    B:\n      Versi\xC3\xB3n: 2\n    C:\n      Versi\xC3\xB3n: 3\n"
        "    D:\n      Versi\xC3\xB3n: 4\n",
        true);
    CHECK(mixed.apps.empty());
    CHECK_FALSE(mixed.readable);
    // exactly half unversioned stays readable; a minority of unversioned apps stays readable
    auto half = parse_system_profiler_apps("    A:\n      Version: 1\n    B:\n", true);
    CHECK(half.readable);
    auto minor = parse_system_profiler_apps(
        "    A:\n      Version: 1\n    B:\n      Version: 2\n    C:\n", true);
    CHECK(minor.readable);
    CHECK(minor.apps.size() == 3);
}

TEST_CASE("parse: NUL bytes are replaced and over-long names and versions are capped",
          "[vuln][macos]") {
    std::string name = "Evil";
    name.push_back('\0');
    name += "Tail";
    std::string ver = "1.";
    ver.push_back('\0');
    ver += "2";
    auto e = parse_system_profiler_apps("    " + name + ":\n      Version: " + ver + "\n", true);
    REQUIRE(e.apps.size() == 1);
    CHECK(e.apps[0].name == "Evil?Tail");
    CHECK(e.apps[0].name.find('\0') == std::string::npos);
    CHECK(e.apps[0].version == "1.?2");
    CHECK(e.apps[0].version.find('\0') == std::string::npos);

    const std::string huge(5 * 1024 * 1024, 'x'); // a >4 MiB name would be an oversize frame
    auto big = parse_system_profiler_apps("    " + huge + ":\n      Version: " + huge + "\n", true);
    REQUIRE(big.apps.size() == 1);
    CHECK(big.apps[0].name.size() == kMaxNameBytes);
    CHECK(big.apps[0].version.size() == kMaxVersionBytes);
}

// ── CVE inputs without a usable version must not read clean ─────────────────

TEST_CASE("usable_version: starts with an ASCII digit", "[vuln][macos][cveinput]") {
    CHECK(usable_version("17.0.1"));
    CHECK(usable_version("0"));
    CHECK_FALSE(usable_version(""));
    CHECK_FALSE(usable_version("Unknown"));
    CHECK_FALSE(usable_version("v100.0.1"));
    CHECK_FALSE(usable_version("\xC2\xA0" "17.0"));  // NBSP-prefixed
    CHECK_FALSE(usable_version(" 17.0"));
}

TEST_CASE("count_unusable_cve_apps: only apps matching a CVE rule product are counted",
          "[vuln][macos][cveinput]") {
    const std::vector<MacosApp> apps = {
        {"Google Chrome", ""},          // matches "chrome", unusable
        {"Firefox", "Unknown"},         // matches "firefox", unusable
        {"Safari", "17.0"},             // no rule, usable
        {"Zoom", ""},                   // no rule product, unusable but not counted
        {"Git", "v2.1"},                // matches "git", unusable
        {"Node.js", "20.1"},            // usable
    };
    CHECK(count_unusable_cve_apps(apps, kCveRules) == 3);
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{}, kCveRules) == 0);
    // ASCII case-insensitive, like the matcher
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{{"GOOGLE CHROME", ""}}, kCveRules) == 1);
    // an app is counted once even when several rules match its name
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{{"Windows Python Git", ""}}, kCveRules) == 1);
}

TEST_CASE("coverage: unusable CVE inputs raise their own token and an UNREADABLE note",
          "[vuln][macos][cveinput]") {
    CoverageState c;
    c.macos_software = true;
    c.cve_inputs_unusable = 2;
    CHECK(coverage_token(c) == "macos:vuln_scan:cve_input_incomplete");
    const auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 2); // Homebrew gap + the new note
    CHECK(notes[1].severity == "UNREADABLE");
    CHECK(notes[1].text ==
          "2 application(s) matching a built-in CVE rule had no usable version; not a clean result");
    CHECK(coverage_row(notes[1]) ==
          "UNREADABLE|scan|Coverage|2 application(s) matching a built-in CVE rule had no usable "
          "version; not a clean result");
    // precedence: an unreadable software list outranks it, it outranks the config token
    c.config_unreadable = true;
    CHECK(coverage_token(c) == kMacosCveInputIncomplete);
    c.sp_readable = false;
    CHECK(coverage_token(c) == kMacosSystemProfilerUnreadable);
    CHECK(kMacosCveInputIncomplete.starts_with("macos:"));
}

TEST_CASE("parse: the unusable-app threshold is MORE THAN HALF (3 of 6 readable, 4 of 6 not)",
          "[vuln][macos]") {
    const auto build = [](int versioned, int bare) {
        std::string o = "Applications:\n\n";
        for (int i = 0; i < versioned; ++i)
            o += "    V" + std::to_string(i) + ":\n\n      Version: 1." + std::to_string(i) + "\n\n";
        for (int i = 0; i < bare; ++i)
            o += "    B" + std::to_string(i) + ":\n\n      Obtained from: Apple\n\n";
        return o;
    };
    CHECK(parse_system_profiler_apps(build(3, 3), true).readable);   // 3 of 6: not more than half
    CHECK_FALSE(parse_system_profiler_apps(build(2, 4), true).readable); // 4 of 6
    CHECK(parse_system_profiler_apps(build(1, 1), true).readable);   // 1 of 2
    CHECK(parse_system_profiler_apps(build(2, 2), true).readable);   // 2 of 4
}

TEST_CASE("parse: reshaped lines count toward the unusable total", "[vuln][macos]") {
    // a name at indent 3 or 5, a Version before its name, and an empty Version value
    // the lost name AND its orphaned Version line both count (2 suspect among 7 total: readable)
    auto indent3 = parse_system_profiler_apps(
        "   Lost:\n      Version: 9\n    A:\n      Version: 1\n    B:\n      Version: 1\n"
        "    C:\n      Version: 1\n    D:\n      Version: 1\n",
        true);
    CHECK(indent3.suspect_lines == 2);
    CHECK(indent3.readable);
    auto before = parse_system_profiler_apps("      Version: 9\n    A:\n      Version: 1\n", true);
    CHECK(before.suspect_lines == 1);
    auto many = parse_system_profiler_apps(
        "   X:\n   Y:\n   Z:\n    A:\n      Version: 1\n", true);
    CHECK(many.suspect_lines == 3);
    CHECK_FALSE(many.readable); // 3 suspect of 4 total
    // an empty Version value does not consume the app's one version
    auto empty = parse_system_profiler_apps("    A:\n      Version:\n      Version: 2.0\n", true);
    REQUIRE(empty.apps.size() == 1);
    CHECK(empty.apps[0].version == "2.0");
    // a byte-order mark before the first name is skipped
    auto bom = parse_system_profiler_apps("\xEF\xBB\xBF    A:\n      Version: 1\n", true);
    REQUIRE(bom.apps.size() == 1);
    CHECK(bom.apps[0].name == "A");
    // the real shape has no suspect lines
    auto real = parse_system_profiler_apps(
        "Applications:\n\n    App Store:\n\n      Version: 3.0\n      Signed by:\n      Location: /x\n", true);
    CHECK(real.suspect_lines == 0);
}

TEST_CASE("end to end shape: Chrome and Firefox unversioned beside Safari and Zoom stays readable "
          "but is flagged by the CVE inputs",
          "[vuln][macos][cveinput]") {
    auto e = parse_system_profiler_apps(
        "    Google Chrome:\n      Obtained from: Apple\n    Firefox:\n      Kind: x\n"
        "    Safari:\n      Version: 17.0\n    Zoom:\n      Version: 5.0\n",
        true);
    CHECK(e.readable);
    REQUIRE(e.apps.size() == 4);
    CHECK(count_unusable_cve_apps(e.apps, kCveRules) == 2);
}

// ── reshaped profiler lines must not silently drop an application ───────────────────────────────

namespace {
// One healthy report of `n` apps in the real measured shape (4-space name, blank, 6-space props).
std::string healthy_report(int n, const char* eol = "\n") {
    std::string o = std::string("Applications:") + eol + eol;
    for (int i = 0; i < n; ++i)
        o += "    App" + std::to_string(i) + ":" + eol + eol + "      Version: 1." + std::to_string(i) + eol +
             "      Obtained from: Apple" + eol + "      Location: /Applications/App" + std::to_string(i) +
             ".app" + eol + eol;
    return o;
}
// `n` healthy apps with `line` spliced in just before the last app's name line.
std::string with_line(int n, const std::string& line) {
    std::string o = healthy_report(n - 1);
    return o + line + "\n" + "    Last:\n\n      Version: 9.9\n\n";
}
} // namespace

TEST_CASE("reshaped lines: healthy reports have no suspect lines (controls)",
          "[vuln][macos][reshaped]") {
    for (int n : {1, 30, 100, 500}) {
        const auto e = parse_system_profiler_apps(healthy_report(n), true);
        INFO(n);
        CHECK(e.suspect_lines == 0);
        CHECK(e.readable);
        CHECK(e.apps.size() == static_cast<std::size_t>(n));
    }
    const auto crlf = parse_system_profiler_apps(healthy_report(30, "\r\n"), true);
    CHECK(crlf.suspect_lines == 0);
    CHECK(crlf.apps.size() == 30);
    const auto bom = parse_system_profiler_apps("\xEF\xBB\xBF" + healthy_report(30), true);
    CHECK(bom.suspect_lines == 0);
    CHECK(bom.apps.size() == 30);
}

TEST_CASE("reshaped lines: each shape in a healthy 30-app report is counted", "[vuln][macos][reshaped]") {
    struct Shape {
        const char* what;
        std::string line;
    };
    const Shape shapes[] = {
        {"name without colon", "    Lost name"},
        {"tab after the indent", "    \tTabbed:"},
        {"name at indent 0", "Lost:"},
        {"name at indent 1", " Lost:"},
        {"name at indent 2", "  Lost:"},
        {"name at indent 3", "   Lost:"},
        {"name at indent 5", "     Lost:"},
        {"name at indent 12", "            Lost:"},
        {"NBSP indent", "\xC2\xA0\xC2\xA0\xC2\xA0\xC2\xA0Lost:"},
        {"orphan property after a blank", "\n      Version: 3.3"},
    };
    for (const auto& sh : shapes) {
        INFO(sh.what);
        const auto e = parse_system_profiler_apps(with_line(30, sh.line), true);
        CHECK(e.suspect_lines >= 1); // never silent
        CHECK(e.readable);           // one reshaped line in 30 apps keeps the list readable
    }
}

TEST_CASE("reshaped lines: a second Version in one block and a mid-file BOM are counted",
          "[vuln][macos][reshaped]") {
    const auto second = parse_system_profiler_apps(
        "    A:\n      Version: 1\n      Version: 2\n    B:\n      Version: 3\n", true);
    CHECK(second.suspect_lines == 1);
    const auto mid = parse_system_profiler_apps(
        healthy_report(5) + "\xEF\xBB\xBF    Z:\n      Version: 1\n", true);
    CHECK(mid.suspect_lines >= 1);
}

TEST_CASE("reshaped lines: the header and the real property block are not suspect",
          "[vuln][macos][reshaped]") {
    CHECK(parse_system_profiler_apps("Applications:\n\n    A:\n\n      Version: 1\n", true)
              .suspect_lines == 0);
    // the first property directly after a name's blank line is fine; contiguous props are fine
    CHECK(parse_system_profiler_apps("    A:\n\n      Version: 1\n      Kind: x\n      Signed by:\n", true)
              .suspect_lines == 0);
}

TEST_CASE("coverage: unrecognised software-list lines raise their own token and note",
          "[vuln][macos][reshaped]") {
    CoverageState c;
    c.macos_software = true;
    c.software_unrecognised = 3;
    CHECK(coverage_token(c) == kMacosSoftwareListUnrecognised);
    const auto notes = coverage_notes(c);
    REQUIRE(notes.size() == 2); // the Homebrew gap + the new note
    CHECK(notes[1].severity == "UNREADABLE");
    CHECK(notes[1].text == "3 line(s) of the software list were not recognised; applications may be "
                           "missing; not a clean result");
    // precedence: software list > cve_input_incomplete > unrecognised > config > Homebrew
    c.config_unreadable = true;
    CHECK(coverage_token(c) == kMacosSoftwareListUnrecognised);
    c.cve_inputs_unusable = 1;
    CHECK(coverage_token(c) == kMacosCveInputIncomplete);
    c.sp_readable = false;
    CHECK(coverage_token(c) == kMacosSystemProfilerUnreadable);
    CHECK(kMacosSoftwareListUnrecognised.starts_with("macos:"));
    for (char ch : kMacosSoftwareListUnrecognised)
        CHECK(((ch >= 'a' && ch <= 'z') || ch == '_' || ch == ':'));
    // order of notes: every cause present
    CoverageState all;
    all.macos_software = true;
    all.cve_inputs_unusable = 1;
    all.software_unrecognised = 1;
    all.config_unreadable = true;
    const auto n = coverage_notes(all);
    REQUIRE(n.size() == 4);
    CHECK(n[0].text == std::string(kCoverageNoteHomebrew));
    CHECK(n[1].text == cve_input_note(1));
    CHECK(n[2].text == software_unrecognised_note(1));
    CHECK(n[3].text == std::string(kCoverageNoteConfig));
}

// ── pure decisions the plugin body relies on ───────────────────────────────────────────────

TEST_CASE("want_clean_placeholder: only a fully read, fully usable list reads clean",
          "[vuln][macos][placeholder]") {
    CoverageState c; // Linux / Windows: nothing declared
    CHECK(want_clean_placeholder(c));
    c.macos_software = true;
    CHECK(want_clean_placeholder(c));
    c.sp_readable = false;
    CHECK_FALSE(want_clean_placeholder(c));
    c.sp_readable = true;
    c.cve_inputs_unusable = 1;
    CHECK_FALSE(want_clean_placeholder(c));
    c.cve_inputs_unusable = 0;
    c.software_unrecognised = 1;
    CHECK_FALSE(want_clean_placeholder(c));
    // an unreadable list on a non-macOS platform flag does not suppress
    CoverageState d;
    d.sp_readable = false;
    CHECK(want_clean_placeholder(d));
}

TEST_CASE("skip_unusable_for_compare: macOS software only", "[vuln][macos][placeholder]") {
    CHECK(skip_unusable_for_compare(true, ""));
    CHECK(skip_unusable_for_compare(true, "v100.0.1"));
    CHECK_FALSE(skip_unusable_for_compare(true, "17.0"));
    CHECK_FALSE(skip_unusable_for_compare(false, "v100.0.1")); // other platforms keep comparing
    CHECK_FALSE(skip_unusable_for_compare(false, ""));
}

TEST_CASE("update_cve_inputs: sets the count on macOS software only", "[vuln][macos][placeholder]") {
    const std::vector<MacosApp> apps = {{"Google Chrome", ""}, {"Safari", "17.0"}};
    CoverageState mac;
    mac.macos_software = true;
    update_cve_inputs(mac, apps, kCveRules);
    CHECK(mac.cve_inputs_unusable == 1);
    CoverageState other;
    update_cve_inputs(other, apps, kCveRules);
    CHECK(other.cve_inputs_unusable == 0);
    CoverageState empty_rules;
    empty_rules.macos_software = true;
    update_cve_inputs(empty_rules, apps, std::vector<CveRule>{});
    CHECK(empty_rules.cve_inputs_unusable == 0);
    CoverageState no_apps;
    no_apps.macos_software = true;
    update_cve_inputs(no_apps, std::vector<MacosApp>{}, kCveRules);
    CHECK(no_apps.cve_inputs_unusable == 0);
}

TEST_CASE("usable_version: a segment too large to compare is unusable", "[vuln][macos][cveinput]") {
    CHECK_FALSE(usable_version("1.99999999999999999999"));
    CHECK(usable_version("1.999999999999999999"));            // 18 digits fit
    CHECK_FALSE(usable_version("1.1000000000000000000"));     // 19 digits
    CHECK(usable_version("1.00000000000000000000001"));       // leading zeros do not count
    CHECK(usable_version("9"));
    CHECK(usable_version("0.1"));
    CHECK_FALSE(usable_version("/"));
    CHECK_FALSE(usable_version(":"));
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{{"Python", "3.99999999999999999999"}}, kCveRules) == 1);
}

// ── count_unusable and the matcher fold the same way ────────────────────────────────────────────

TEST_CASE("count_unusable: uppercase A and Z fold like the matcher", "[vuln][macos][cveinput]") {
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{{"APACHE HTTP Server", ""}}, kCveRules) == 1);
    CHECK(count_unusable_cve_apps(std::vector<MacosApp>{{"POSTGRESQL", ""}}, kCveRules) == 1);
}

TEST_CASE("coverage_notes: order with every cause and the token floor", "[vuln][macos][cveinput]") {
    CoverageState d;
    d.macos_software = true;
    d.config_unreadable = true;
    CHECK(coverage_token(d) == kMacosConfigUnreadable);
    d.cve_inputs_unusable = 1;
    CHECK(coverage_token(d) == kMacosCveInputIncomplete);
    CoverageState e; // not macOS software: nothing is declared for a CVE-input count alone
    CHECK(coverage_notes(e).empty());
    CHECK(coverage_token(e).empty());
}

TEST_CASE("parse: each reshaped-line class is counted exactly once", "[vuln][macos]") {
    const std::string ok = "    A:\n      Version: 1\n";
    CHECK(parse_system_profiler_apps("     Five:\n" + ok, true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("    Version:\n" + ok, true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("    Prop only\n" + ok, true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("   Prop only\n" + ok, true).suspect_lines == 0);
    CHECK(parse_system_profiler_apps("     Prop only\n" + ok, true).suspect_lines == 0);
    CHECK(parse_system_profiler_apps("      Prop: x\n" + ok, true).suspect_lines == 0);
}

TEST_CASE("parse: Version at 5 spaces is a version; a name starting 'Version' is a name",
          "[vuln][macos]") {
    auto a = parse_system_profiler_apps("    A:\n     Version: 7\n", true);
    REQUIRE(a.apps.size() == 1);
    CHECK(a.apps[0].version == "7");
    auto b = parse_system_profiler_apps("    Version Cue CS5:\n      Version: 5.5\n", true);
    REQUIRE(b.apps.size() == 1);
    CHECK(b.apps[0].name == "Version Cue CS5");
    CHECK(b.suspect_lines == 0);
}

TEST_CASE("parse: a tab after the four-space indent is suspect and never a name", "[vuln][macos]") {
    auto t = parse_system_profiler_apps("    \tTabbed:\n    A:\n      Version: 1\n", true);
    CHECK(t.apps.size() == 1);
    CHECK(t.apps[0].name == "A");
    CHECK(t.suspect_lines == 1);
}

// ── a name line lost TOGETHER with another reshape must not attach a Version to the wrong
//    application ───────────────────────────────────────────────────────────────────────────────

TEST_CASE("lost name: class X, the orphaned Version at indent 3, is counted", "[vuln][macos][reshaped]") {
    // the name line of app N is lost and its Version line sits at indent 3
    const auto e = parse_system_profiler_apps(
        healthy_report(10) + "\n   Version: 7.7\n\n    Next:\n\n      Version: 2\n\n", true);
    CHECK(e.suspect_lines >= 1);
    CHECK(e.readable);
}

TEST_CASE("lost name: class Y, an unversioned previous app plus lost blank/name/blank lines, is counted",
          "[vuln][macos][reshaped]") {
    // `Bare` has no Version; the blank, name and blank lines of the next app are lost, so its Version
    // would attach to Bare. The Version is not directly after a name line.
    const auto e = parse_system_profiler_apps(
        healthy_report(10) + "    Bare:\n\n      Obtained from: Apple\n      Version: 5.5\n\n", true);
    CHECK(e.suspect_lines >= 1);
    CHECK(e.readable);
    // the shape of a Version directly after its name is not suspect (control)
    const auto ok = parse_system_profiler_apps(healthy_report(10) + "    Fine:\n\n      Version: 5.5\n\n", true);
    CHECK(ok.suspect_lines == 0);
}

TEST_CASE("lost name: an indent-3 Version line and a first Version after another property are each counted once",
          "[vuln][macos][reshaped]") {
    const std::string ok = "    A:\n      Version: 1\n";
    CHECK(parse_system_profiler_apps("   Version: 9\n" + ok, true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("    B:\n      Kind: x\n      Version: 2\n", true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("    B:\n      Version: 2\n      Kind: x\n", true).suspect_lines == 0);
}

TEST_CASE("reshaped lines: boundary rows", "[vuln][macos][reshaped]") {
    // an indent-5 property after a blank that follows a name: not suspect; after a non-name: suspect
    const std::string pre = "    A:\n";
    CHECK(parse_system_profiler_apps(pre + "\n     Kind: x\n", true).suspect_lines == 0);
    CHECK(parse_system_profiler_apps(pre + "      Kind: y\n\n     Kind: x\n", true).suspect_lines == 1);
    // 18 digits fit, 19 do not (saturation boundary)
    CHECK(usable_version("1.999999999999999999"));
    CHECK_FALSE(usable_version("1.1000000000000000000"));
}

// ── three independent faults, and unreadable companions ─────────────────────────────────────────

TEST_CASE("lost name: a 3-space property line after a blank that follows no name is counted",
          "[vuln][macos][reshaped]") {
    // the name and Version lines are lost and `Obtained from:` is re-indented to exactly 3 spaces
    const auto e = parse_system_profiler_apps(
        healthy_report(10) + "   Obtained from: Apple\n      Kind: x\n\n", true);
    CHECK(e.suspect_lines >= 1); // the report ends with a blank line: the 3-space line follows it
    const auto after_blank = parse_system_profiler_apps(
        healthy_report(10) + "\n   Obtained from: Apple\n\n    Next:\n\n      Version: 2\n", true);
    CHECK(after_blank.suspect_lines >= 1);
    // directly after a name line, a 3-space property is not flagged by the blank rule
    const auto after_name = parse_system_profiler_apps("    A:\n\n   Obtained from: Apple\n", true);
    CHECK(after_name.suspect_lines == 0);
}

TEST_CASE("lost name: tiny reports with the lost-name shapes are unreadable, not readable",
          "[vuln][macos][reshaped]") {
    // class X in a 1-app report: 1 suspect of 2 total is not MORE than half, so still readable ...
    const auto x1 = parse_system_profiler_apps(healthy_report(1) + "\n   Version: 7.7\n", true);
    CHECK(x1.suspect_lines >= 1);
    // ... but with the majority lost the read is unreadable and returns no apps
    const auto lost = parse_system_profiler_apps("\n   Version: 7.7\n   Version: 8\n   Kind: x\n    A:\n", true);
    CHECK_FALSE(lost.readable);
    CHECK(lost.apps.empty());
    // class Y majority: unversioned app plus orphaned Versions
    const auto y = parse_system_profiler_apps(
        "    Bare:\n\n      Obtained from: Apple\n      Version: 5.5\n      Version: 6\n", true);
    CHECK(y.suspect_lines >= 1);
    CHECK_FALSE(y.readable); // the one app is unversioned (its Version is not directly after the name)
}

// ── a property value that wraps onto further lines at indent 0 ───────────────────────────────────

namespace {
// Real `system_profiler SPApplicationsDataType -detailLevel mini` text (macOS 27.0.1): the Wish
// application's Get Info String wraps onto four indent-0 lines with no blank line between, and the
// next application block follows.
const std::string kWishWrapped =
    "Applications:\n"
    "\n"
    "    Wish:\n"
    "\n"
    "      Version: 8.5.9\n"
    "      Obtained from: Apple\n"
    "      Last Modified: 24/09/2026, 08:10\n"
    "      Kind: iOS\n"
    "      Signed by: macOS Software Signing, Apple Code Signing Certification Authority, Apple Root CA\n"
    "      Location: /System/Library/Frameworks/Tk.framework/Versions/8.5/Resources/Wish.app\n"
    "      Get Info String: Wish Shell 8.5.9,\n"
    "Copyright \xC2\xA9 1989-2026 Tcl Core Team,\n"
    "Copyright \xC2\xA9 2002-2026 Daniel A. Steffen,\n"
    "Copyright \xC2\xA9 2001-2009 Apple Inc.,\n"
    "Copyright \xC2\xA9 2001-2002 Jim Ingham & Ian Reid\n"
    "\n"
    "    CinematicFramingOnboardingUI:\n"
    "\n"
    "      Version: 1.0\n";

CoverageState plugin_state(const MacosEnumeration& e) { // what get_installed_apps copies over
    CoverageState c;
    c.macos_software = true;
    c.sp_readable = e.readable;
    c.software_unrecognised = e.readable ? e.suspect_lines : 0;
    return c;
}
} // namespace

TEST_CASE("wrapped property value: the real Wish text is clean and the clean path survives",
          "[vuln][macos][wrapped]") {
    const auto e = parse_system_profiler_apps(kWishWrapped, true);
    REQUIRE(e.apps.size() == 2);
    CHECK(e.apps[0].name == "Wish");
    CHECK(e.apps[0].version == "8.5.9");
    CHECK(e.apps[1].name == "CinematicFramingOnboardingUI");
    CHECK(e.apps[1].version == "1.0");
    CHECK(e.suspect_lines == 0);
    CHECK(e.readable);
    CHECK(want_clean_placeholder(plugin_state(e)));
    CHECK(coverage_token(plugin_state(e)) == "macos:vuln_scan:homebrew_not_scanned");
}

TEST_CASE("wrapped property value: only a line directly after a property line is exempt",
          "[vuln][macos][wrapped]") {
    const std::string pre = "Applications:\n\n    A:\n\n      Version: 1\n";
    // after a blank line: counted
    CHECK(parse_system_profiler_apps(pre + "      Kind: x\n\nStray\n", true).suspect_lines == 1);
    // directly after a name line: counted
    CHECK(parse_system_profiler_apps("Applications:\n\n    A:\nStray\n", true).suspect_lines >= 1);
    // after the header, and before any block: counted
    CHECK(parse_system_profiler_apps("Applications:\nStray\n", true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps("Stray\n", true).suspect_lines == 1);
    // a tab, or indent 1 or 2, is never a wrapped value
    CHECK(parse_system_profiler_apps(pre + "      Kind: x,\n\tcont\n", true).suspect_lines >= 1);
    CHECK(parse_system_profiler_apps(pre + "      Kind: x,\n cont\n", true).suspect_lines == 1);
    CHECK(parse_system_profiler_apps(pre + "      Kind: x,\n  cont\n", true).suspect_lines == 1);
    // the exemption is not a second `Version:` window: a wrapped value then a Version is still one
    CHECK(parse_system_profiler_apps(pre + "      Kind: x,\ncont\n      Version: 2\n", true).suspect_lines >= 1);
}

// ── two or more blank lines after a name line ────────────────────────────────────────────────────

TEST_CASE("blank run: a name line followed by two blank lines then a property is counted",
          "[vuln][macos][blankrun]") {
    const std::string t3 =
        "Applications:\n\n    A:\n\n      Version: 1\n\n    B:\n\n\n      Version: 2\n";
    const auto e = parse_system_profiler_apps(t3, true);
    CHECK(e.suspect_lines == 1);
    CHECK(e.readable);
    CHECK_FALSE(want_clean_placeholder(plugin_state(e)));
    CHECK(coverage_token(plugin_state(e)) == "macos:vuln_scan:software_list_unrecognised");
}

TEST_CASE("blank run: canonical blocks, a name-only block and an intact successor are clean",
          "[vuln][macos][blankrun]") {
    const std::string t =
        "Applications:\n\n    A:\n\n      Version: 1\n      Kind: x\n\n"
        "    NameOnly:\n\n"
        "    B:\n\n      Version: 2\n";
    const auto e = parse_system_profiler_apps(t, true);
    CHECK(e.suspect_lines == 0);
    CHECK(e.apps.size() == 3);
    CHECK(want_clean_placeholder(plugin_state(e)));
    CHECK(parse_system_profiler_apps(kSample, true).suspect_lines == 0);
}
