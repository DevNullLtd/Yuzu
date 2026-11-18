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
    CHECK(kMacosToolDeadlineMs == 10'000);
    CHECK(kMacosToolDeadlineMs * 6 + kMacosCommandDeadlineMs <= 120'000); // one action's budget
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
          "exceeded the output cap or returned no applications); not a clean result");
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
    auto e = parse_system_profiler_apps("    Git:\n    Version: 1.0\n      Version: 2.50.1\n", true);
    REQUIRE(e.apps.size() == 1);
    CHECK(e.apps[0].version == "2.50.1");
}

TEST_CASE("parse: only a four-space-indent line ending in ':' is a name", "[vuln][macos]") {
    auto e = parse_system_profiler_apps(
        "    A:\n      Sub:\n      Version: 1\n  Header:\n        Deep:\n   Three:\n", true);
    REQUIRE(e.apps.size() == 1);
    CHECK(e.apps[0].name == "A");
    CHECK(e.apps[0].version == "1");
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
    auto e = parse_system_profiler_apps("      Version: 7\n    A:\n      Version: 1\n      Version: 2\n", true);
    REQUIRE(e.apps.size() == 1);
    CHECK(e.apps[0].version == "1");
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

TEST_CASE("macos config: near-miss lines are NOT accepted (prefix matches were the defect)",
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

TEST_CASE("macos config: the shipped defaults argv reaches the absent-key INFO",
          "[vuln][macos][config]") {
    // An echoing reader that prints the absent-key line only when the read names the BARE domain.
    const auto rows = run_macos_checks_table([](const Argv& a, bool) {
        if (a.size() == 4 && a[2] == "com.apple.SoftwareUpdate")
            return CommandRead{"Error: Could not find key 'AutomaticCheckEnabled' in domain "
                               "'com.apple.SoftwareUpdate'.",
                               false, true};
        return CommandRead{};
    });
    const auto& r = rows[5];
    CHECK(r.title == "Automatic update check");
    CHECK(r.severity == "INFO");
    CHECK(r.detail == "Automatic update check: not set (macOS default applies)");
    CHECK(kMacosDefaultsCmd[2] == "com.apple.SoftwareUpdate"); // never the /Library/... path form
    CHECK(macos_spec(MacosCheck::AutoUpdate).good_detail ==
          "Enabled (check only; install not assessed)");
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
    CHECK(seen.size() == 6);
    CHECK(seen[0] == "/usr/sbin/spctl");
    // only the defaults row reports on stderr
    CHECK(std::count(merged.begin(), merged.end(), true) == 1);
    CHECK(merged[5]);
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

// ── golden fixtures: REAL output, verified on macOS 27.0.1 (one Apple Silicon host; 13-15 not
//    measured; exit codes not yet captured) ────────────────────────────────────────────────────

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
