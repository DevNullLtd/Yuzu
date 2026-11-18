// Pure-parser coverage for the services plugin's systemctl/launchctl
// enumeration output (Wave-2 PR2.2a, ADR-3002 acquisition-ladder migration).
// The functions live in agents/plugins/services/src/services_parsers.hpp and
// are reachable at runtime from services_plugin.cpp's enumerate_services_linux
// / enumerate_services_macos.
//
// Fixtures below are hand-constructed-but-format-accurate: built from the
// documented `systemctl list-units --no-legend` (UNIT LOAD ACTIVE SUB
// DESCRIPTION whitespace-separated columns) and `launchctl list`
// ("PID\tStatus\tLabel" header + tab-separated rows) column layouts, not a
// live capture from a running host.
#include "services_parsers.hpp"
#include "services_set_start_mode.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/subprocess_runner.hpp>

#include <algorithm>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;
using yuzu::services::decide_set_start_mode_outcome;
using yuzu::services::is_safe_service_name;
using yuzu::services::kMaxServiceRows;
using yuzu::services::kSvcHelperPathLinux;
using yuzu::services::kSvcHelperPathMacos;
using yuzu::services::LaunchdListResult;
using yuzu::services::launchctl_set_start_mode_argv;
using yuzu::services::parse_launchctl_list;
using yuzu::services::parse_systemctl_list_units;
using yuzu::services::SystemdUnitEntry;
using yuzu::services::systemctl_set_start_mode_argv;

// ── parse_systemctl_list_units ───────────────────────────────────────────────

TEST_CASE("services: parse_systemctl_list_units parses a well-formed multi-row listing",
          "[services][linux]") {
    const std::string out =
        "cron.service                 loaded active   running Regular background program processing daemon\n"
        "ssh.service                  loaded active   running OpenBSD Secure Shell server\n"
        "bluetooth.service            loaded inactive dead    Bluetooth service\n";

    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 3);

    CHECK(entries[0].name == "cron.service");
    CHECK(entries[0].status == "running");
    CHECK(entries[0].description == "Regular background program processing daemon");

    CHECK(entries[1].name == "ssh.service");
    CHECK(entries[1].status == "running");
    CHECK(entries[1].description == "OpenBSD Secure Shell server");

    CHECK(entries[2].name == "bluetooth.service");
    CHECK(entries[2].status == "dead");
    CHECK(entries[2].description == "Bluetooth service");
}

TEST_CASE("services: parse_systemctl_list_units tolerates CRLF line endings",
          "[services][linux]") {
    const std::string out = "cron.service loaded active running Regular cron\r\n"
                             "ssh.service  loaded active running OpenBSD SSH\r\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "cron.service");
    CHECK(entries[1].name == "ssh.service");
}

TEST_CASE("services: parse_systemctl_list_units skips blank lines", "[services][linux]") {
    const std::string out = "\ncron.service loaded active running Regular cron\n\n\n"
                             "ssh.service  loaded active running OpenBSD SSH\n\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 2);
}

TEST_CASE("services: parse_systemctl_list_units trims the leading failed-unit marker column",
          "[services][linux]") {
    // Pins the parser's existing " *" leading-character trim (inherited
    // unchanged from the pre-migration inline loop, not introduced by this
    // PR) so a leading marker column never gets folded into the UNIT field.
    const std::string out = "* apparmor.service loaded failed failed Load AppArmor profiles\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "apparmor.service");
    CHECK(entries[0].status == "failed");
}

TEST_CASE("services: parse_systemctl_list_units on empty input yields no entries",
          "[services][linux]") {
    CHECK(parse_systemctl_list_units("").empty());
}

TEST_CASE("services: parse_systemctl_list_units handles a unit with no trailing description",
          "[services][linux]") {
    const std::string out = "empty.service loaded active running\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "empty.service");
    CHECK(entries[0].status == "running");
    CHECK(entries[0].description.empty());
}

// ── parse_launchctl_list ──────────────────────────────────────────────────────

TEST_CASE("services: parse_launchctl_list skips the header row and parses the rest",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.something\n"
                             "456\t-15\tcom.apple.crashy\n";
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    REQUIRE(result.services.size() == 2);
    CHECK(result.total_seen == 2);

    CHECK(result.services[0].pid == "123");
    CHECK(result.services[0].status == "0");
    CHECK(result.services[0].label == "com.apple.something");

    CHECK(result.services[1].pid == "456");
    CHECK(result.services[1].status == "-15");
    CHECK(result.services[1].label == "com.apple.crashy");
}

TEST_CASE("services: parse_launchctl_list running_only drops pid=='-' rows",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.running\n"
                             "-\t0\tcom.apple.notrunning\n";
    auto result = parse_launchctl_list(out, /*running_only=*/true);
    REQUIRE(result.services.size() == 1);
    CHECK(result.services[0].label == "com.apple.running");
    // The dropped-for-not-running row still passed the safety filter, so it
    // is honestly counted -- total_seen answers "how many qualifying rows
    // existed", not "how many made it into `services`".
    CHECK(result.total_seen == 1);
}

TEST_CASE("services: parse_launchctl_list drops an unsafe label before it reaches the result",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.ok\n"
                             "456\t0\tcom.apple|evil\n"; // '|' would corrupt the pipe protocol
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    REQUIRE(result.services.size() == 1);
    CHECK(result.services[0].label == "com.apple.ok");
    CHECK(result.total_seen == 1); // the unsafe row is never counted either
}

TEST_CASE("services: parse_launchctl_list honours a caller-supplied row_cap and still counts "
          "every qualifying row in total_seen",
          "[services][macos]") {
    std::string out = "PID\tStatus\tLabel\n";
    for (int i = 0; i < 5; ++i) {
        out += std::format("{}\t0\tcom.apple.svc{}\n", i + 1, i);
    }
    auto result = parse_launchctl_list(out, /*running_only=*/false, /*row_cap=*/2);
    CHECK(result.services.size() == 2);
    CHECK(result.total_seen == 5);
}

TEST_CASE("services: parse_launchctl_list defaults to kMaxServiceRows when no cap is given",
          "[services][macos]") {
    std::string out = "PID\tStatus\tLabel\n";
    for (std::size_t i = 0; i < kMaxServiceRows + 10; ++i) {
        out += std::format("{}\t0\tcom.apple.svc{}\n", i + 1, i);
    }
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    CHECK(result.services.size() == kMaxServiceRows);
    CHECK(result.total_seen == kMaxServiceRows + 10);
}

TEST_CASE("services: parse_launchctl_list header-only input yields no entries, not malformed",
          "[services][macos]") {
    // A real exit-0 `launchctl list` capture with genuinely zero services
    // still emits the header row -- see the next test for the zero-line
    // case, which is the opposite verdict.
    auto result = parse_launchctl_list("PID\tStatus\tLabel\n", false);
    CHECK(result.services.empty());
    CHECK_FALSE(result.malformed);
}

TEST_CASE("services: parse_launchctl_list on a truncated/zero-line capture reports "
          "malformed, never a clean \"0 services\" (CA-1, governance A0 round-4)",
          "[services][macos]") {
    // Before the convergence onto agents/shared/launchctl_list.hpp, this
    // plugin's own independent parser had no header-shape check and no
    // empty-input check at all: a truncated/zero-line capture parsed as a
    // clean "0 services" success, the identical defect class UP2-2 fixed
    // for Echo at HIGH in round 2.
    auto result = parse_launchctl_list("", false);
    CHECK(result.services.empty());
    CHECK(result.malformed);
}

TEST_CASE("services: parse_launchctl_list on a preamble/garbled header line reports "
          "malformed, not decoded from the wrong offset",
          "[services][macos]") {
    const std::string out = "launchctl: some warning banner\n"
                             "PID\tStatus\tLabel\n"
                             "1190\t0\tcom.apple.progressd\n";
    auto result = parse_launchctl_list(out, false);
    CHECK(result.services.empty());
    CHECK(result.malformed);
}

// ── is_safe_service_name ─────────────────────────────────────────────────────

TEST_CASE("services: is_safe_service_name accepts the documented character set",
          "[services]") {
    CHECK(is_safe_service_name("cron.service"));
    CHECK(is_safe_service_name("getty@tty1.service"));
    CHECK(is_safe_service_name("com.apple.something"));
    CHECK(is_safe_service_name("Some_Service-2"));
}

TEST_CASE("services: is_safe_service_name rejects the empty/oversized/unsafe-character cases",
          "[services]") {
    CHECK_FALSE(is_safe_service_name(""));
    CHECK_FALSE(is_safe_service_name(std::string(257, 'a'))); // over the 256 cap
    CHECK_FALSE(is_safe_service_name("evil|pipe"));
    CHECK_FALSE(is_safe_service_name("evil;rm -rf"));
    CHECK_FALSE(is_safe_service_name("has space"));
    CHECK_FALSE(is_safe_service_name("evil`backtick"));
}

TEST_CASE("services: is_safe_service_name permits a leading hyphen (argv callers must still "
          "separate it with an explicit \"--\")",
          "[services]") {
    // Documents the load-bearing NOTE in services_parsers.hpp: the allowlist
    // itself does not forbid a leading '-', so services_plugin.cpp's argv
    // construction is responsible for the "--" separator that keeps a name
    // like this from being parsed as a systemctl/launchctl flag.
    CHECK(is_safe_service_name("-foo"));
}

// ── decide_set_start_mode_outcome ────────────────────────────────────────
//
// Pins the CALL-SITE WIRING in do_set_start_mode_linux/_macos -- given a
// SubprocessResult, is a runner-level failure (spawn error / deadline /
// cancelled / signaled) correctly distinguished from an ordinary tool
// failure (ran, nonzero exit), and from success. classify_runner_failure
// itself already has generic coverage in test_runner_status.cpp; this pins
// that services_plugin.cpp actually WIRES the distinction through rather
// than collapsing every non-success into the same generic error string.

TEST_CASE("decide_set_start_mode_outcome: a clean zero-exit run is ok, no message",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::exited;
    res.tool_ran = true;
    res.exit_code = 0;

    auto outcome = decide_set_start_mode_outcome("systemctl", "sshd", res);
    CHECK(outcome.ok);
    CHECK_FALSE(outcome.runner_failed);
    CHECK(outcome.message.empty());
}

TEST_CASE("decide_set_start_mode_outcome: tool_ran=false (spawn error) sets runner_failed, "
         "not the generic exit-code message",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::spawn_error;
    res.tool_ran = false;

    auto outcome = decide_set_start_mode_outcome("systemctl", "sshd", res);
    CHECK_FALSE(outcome.ok);
    CHECK(outcome.runner_failed);
    CHECK(outcome.message == "error|systemctl command failed for 'sshd' (runner did not complete)");
}

TEST_CASE("decide_set_start_mode_outcome: timed_out/deadline sets runner_failed, distinguishable "
         "from an ordinary nonzero exit",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::deadline;
    res.tool_ran = true; // the child had started but was killed before a real exit
    res.timed_out = true;

    auto outcome = decide_set_start_mode_outcome("launchctl", "com.example.svc", res);
    CHECK_FALSE(outcome.ok);
    CHECK(outcome.runner_failed);
    CHECK(outcome.message ==
         "error|launchctl command failed for 'com.example.svc' (runner did not complete)");
}

TEST_CASE("decide_set_start_mode_outcome: signaled (e.g. a crash) sets runner_failed",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::signaled;
    res.tool_ran = true;

    auto outcome = decide_set_start_mode_outcome("systemctl", "sshd", res);
    CHECK_FALSE(outcome.ok);
    CHECK(outcome.runner_failed);
}

TEST_CASE("decide_set_start_mode_outcome: the tool ran and exited nonzero -- an ORDINARY "
         "failure, never reported as runner_failed",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::exited;
    res.tool_ran = true;
    res.exit_code = 1;

    auto outcome = decide_set_start_mode_outcome("systemctl", "sshd", res);
    CHECK_FALSE(outcome.ok);
    CHECK_FALSE(outcome.runner_failed);
    CHECK(outcome.message == "error|systemctl command failed for 'sshd' (exit=1)");
}

TEST_CASE("decide_set_start_mode_outcome: a nonzero exit's captured output (e.g. a sudo denial) "
         "is threaded into the message, not discarded",
         "[services]") {
    SubprocessResult res;
    res.termination_reason = TerminationReason::exited;
    res.tool_ran = true;
    res.exit_code = 1;
    res.output = "sudo: a password is required";

    auto outcome = decide_set_start_mode_outcome("systemctl", "sshd", res);
    CHECK_FALSE(outcome.ok);
    CHECK_FALSE(outcome.runner_failed);
    CHECK(outcome.message ==
         "error|systemctl command failed for 'sshd' (exit=1): sudo: a password is required");
}

// ── set_start_mode privileged argv ──────────────────────────────────────────
//
// The argv a non-root agent runs is `sudo -n -- <helper> <tool> <verb> <name>`: the sudoers file
// names the root-owned helper with no argument and no wildcard, and the helper (whose text
// tests/test_legacy_quarantine_plugin_removed_lexical.py runs against the same cases) builds the
// tool's argument list itself. A root agent has no grant to bound and runs the tool directly. The
// decision is the euid alone: no probe for the helper, no fallback to the tool.

using Argv = std::vector<std::string>;

TEST_CASE("systemctl_set_start_mode_argv: a non-root agent runs the helper under sudo, for each verb",
          "[services][sudoers]") {
    CHECK(kSvcHelperPathLinux == "/usr/local/sbin/yuzu-svc-helper");
    for (const char* verb : {"enable", "disable", "mask", "unmask"}) {
        INFO(verb);
        CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", verb, "cron.service", false) ==
              Argv{"/usr/bin/sudo", "-n", "--", "/usr/local/sbin/yuzu-svc-helper", "systemctl", verb,
                   "cron.service"});
    }
    // the tool path the plugin probed is not used by a non-root agent: the helper picks its own
    CHECK(systemctl_set_start_mode_argv("/bin/systemctl", "mask", "sshd", false) ==
          systemctl_set_start_mode_argv("/usr/bin/systemctl", "mask", "sshd", false));
}

TEST_CASE("systemctl_set_start_mode_argv: a root agent runs systemctl itself, with -- before the name",
          "[services][sudoers]") {
    for (const char* verb : {"enable", "disable", "mask", "unmask"}) {
        INFO(verb);
        CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", verb, "cron.service", true) ==
              Argv{"/usr/bin/systemctl", verb, "--", "cron.service"});
    }
    CHECK(systemctl_set_start_mode_argv("/bin/systemctl", "enable", "getty@tty1.service", true) ==
          Argv{"/bin/systemctl", "enable", "--", "getty@tty1.service"});
}

TEST_CASE("systemctl_set_start_mode_argv: a name with a leading hyphen is one argv element in both modes",
          "[services][sudoers]") {
    // The helper takes the name as its third argument and puts -- before it; the root form puts -- itself.
    CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", "enable", "-foo", false).back() == "-foo");
    CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", "enable", "-foo", true) ==
          Argv{"/usr/bin/systemctl", "enable", "--", "-foo"});
    const std::string longest(256, 'a');
    CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", "disable", longest, false).back() == longest);
}

TEST_CASE("launchctl_set_start_mode_argv: a non-root agent runs the helper under sudo, for each verb",
          "[services][sudoers]") {
    CHECK(kSvcHelperPathMacos == "/Library/PrivilegedHelperTools/yuzu-svc-helper");
    for (const char* verb : {"enable", "disable"}) {
        INFO(verb);
        // the helper adds system/ itself: it is given the bare label
        CHECK(launchctl_set_start_mode_argv("/bin/launchctl", verb, "com.example.agent", false) ==
              Argv{"/usr/bin/sudo", "-n", "--", "/Library/PrivilegedHelperTools/yuzu-svc-helper",
                   "launchctl", verb, "com.example.agent"});
    }
}

TEST_CASE("launchctl_set_start_mode_argv: a root agent runs launchctl itself on system/<label>",
          "[services][sudoers]") {
    for (const char* verb : {"enable", "disable"}) {
        INFO(verb);
        CHECK(launchctl_set_start_mode_argv("/bin/launchctl", verb, "com.example.agent", true) ==
              Argv{"/bin/launchctl", verb, "system/com.example.agent"});
    }
}

TEST_CASE("set_start_mode argv: every name is_safe_service_name admits reaches the helper whole",
          "[services][sudoers]") {
    for (const std::string_view name : {"a", "cron.service", "getty@tty1.service", "Some_Service-2", "-x",
                                         "com.apple.something"}) {
        REQUIRE(is_safe_service_name(name));
        CHECK(systemctl_set_start_mode_argv("/usr/bin/systemctl", "enable", name, false).back() == name);
        CHECK(launchctl_set_start_mode_argv("/bin/launchctl", "enable", name, false).back() == name);
    }
}

TEST_CASE("start_mode_took_effect: the read-back must match the requested mode, empty fails closed "
          "(WP13 UP11)",
          "[services][up11]") {
    using yuzu::services::start_mode_took_effect;
    CHECK(start_mode_took_effect("automatic", "enabled\n"));
    CHECK(start_mode_took_effect("automatic", "static\n"));
    CHECK_FALSE(start_mode_took_effect("automatic", "disabled\n")); // wrapper did nothing
    CHECK_FALSE(start_mode_took_effect("automatic", "masked\n"));
    CHECK(start_mode_took_effect("manual", "disabled\n"));
    CHECK_FALSE(start_mode_took_effect("manual", "enabled\n"));
    CHECK(start_mode_took_effect("disabled", "masked\n"));
    CHECK_FALSE(start_mode_took_effect("disabled", "enabled\n"));
    CHECK_FALSE(start_mode_took_effect("automatic", "")); // a 0-byte wrapper leaves nothing to read
    CHECK_FALSE(start_mode_took_effect("bogus", "enabled"));
}

TEST_CASE("start_mode_took_effect: error text and non-end states never match (closed set)",
          "[services][up11]") {
    using yuzu::services::start_mode_took_effect;
    for (const char* mode : {"automatic", "manual", "disabled"}) {
        CHECK_FALSE(start_mode_took_effect(mode, "not-found\n"));
        CHECK_FALSE(start_mode_took_effect(mode, "Failed to connect to bus: No such file or directory\n"));
        CHECK_FALSE(start_mode_took_effect(mode, "bad\n"));
        CHECK_FALSE(start_mode_took_effect(mode, "transient\n"));
        CHECK_FALSE(start_mode_took_effect(mode, "linked\n"));
        CHECK_FALSE(start_mode_took_effect(mode, "Unit foo.service not found.\n"));
    }
    for (const char* st : {"enabled", "static", "indirect", "alias", "generated"})
        CHECK(start_mode_took_effect("automatic", st));
    for (const char* st : {"disabled", "static", "indirect", "alias", "generated"})
        CHECK(start_mode_took_effect("manual", st));
    CHECK_FALSE(start_mode_took_effect("manual", "enabled-runtime"));
    CHECK_FALSE(start_mode_took_effect("disabled", "static"));
}

TEST_CASE("start_mode_took_effect: a -runtime state means the persistent verb did not act",
          "[services][up11]") {
    using yuzu::services::start_mode_took_effect;
    // enable/disable/mask are persistent: a /run-only state is what a no-op wrapper leaves.
    CHECK_FALSE(start_mode_took_effect("automatic", "enabled-runtime\n"));
    CHECK_FALSE(start_mode_took_effect("disabled", "masked-runtime\n"));
    CHECK_FALSE(start_mode_took_effect("manual", "enabled-runtime\n"));
    CHECK(start_mode_took_effect("automatic", "enabled\n"));
    CHECK(start_mode_took_effect("disabled", "masked\n"));
}

TEST_CASE("start_mode_readback: SysV redirect text is a stderr line, never part of the state",
          "[services][up11]") {
    using yuzu::services::start_mode_took_effect;
    // With stderr NOT merged (the plugin's readback), a SysV-only unit's stdout is just the state.
    CHECK(start_mode_took_effect("automatic", "enabled\n"));
    // If that text ever reached the first line the parser must refuse, not scan for a state line.
    CHECK_FALSE(start_mode_took_effect(
        "automatic",
        "crond is not a native service, redirecting to systemd-sysv-install.\nenabled\n"));
}

TEST_CASE("start_state_is_unchangeable: the states a verb cannot change", "[services][up11]") {
    using yuzu::services::start_state_is_unchangeable;
    for (const char* st : {"static\n", "indirect", "alias\n", "generated\r\n"})
        CHECK(start_state_is_unchangeable(st));
    for (const char* st : {"enabled", "disabled", "masked", "", "not-found"})
        CHECK_FALSE(start_state_is_unchangeable(st));
}

TEST_CASE("start_mode_readback_matches: a readback that did not run is not a match",
          "[services][up11]") {
    using yuzu::services::start_mode_readback_matches;
    yuzu::agent::SubprocessResult ran;
    ran.tool_ran = true;
    ran.termination_reason = yuzu::agent::TerminationReason::exited;
    ran.exit_code = 1; // is-enabled exits non-zero for `disabled`
    ran.output = "disabled\n";
    CHECK(start_mode_readback_matches("manual", ran));
    yuzu::agent::SubprocessResult not_ran = ran;
    not_ran.tool_ran = false;
    CHECK_FALSE(start_mode_readback_matches("manual", not_ran));
    yuzu::agent::SubprocessResult timed = ran;
    timed.timed_out = true;
    timed.termination_reason = yuzu::agent::TerminationReason::deadline;
    CHECK_FALSE(start_mode_readback_matches("manual", timed));
}

TEST_CASE("start_mode_needs_unmask: automatic and manual unmask first, disabled (mask) does not",
          "[services][unmask]") {
    using yuzu::services::start_mode_needs_unmask;
    CHECK(start_mode_needs_unmask("automatic")); // mask -> automatic must be able to enable
    CHECK(start_mode_needs_unmask("manual"));
    CHECK_FALSE(start_mode_needs_unmask("disabled"));
    CHECK_FALSE(start_mode_needs_unmask("bogus"));
    CHECK_FALSE(start_mode_needs_unmask(""));
}

TEST_CASE("start_mode_should_remask: a failed change after an unmask restores the mask",
          "[services][unmask]") {
    using yuzu::services::start_mode_should_remask;
    using yuzu::services::start_state_is_masked;
    CHECK(start_state_is_masked("masked\n"));
    CHECK_FALSE(start_state_is_masked("masked-runtime")); // a runtime mask is never re-created as a persistent one
    CHECK_FALSE(start_state_is_masked("disabled\n"));
    CHECK_FALSE(start_state_is_masked(""));
    CHECK_FALSE(start_state_is_masked("not-found"));
    // unit was masked, the change failed: put the mask back
    CHECK(start_mode_should_remask("automatic", true, false));
    CHECK(start_mode_should_remask("manual", true, false));
    // a unit that was NOT masked is never masked by a failure; success never remasks
    CHECK_FALSE(start_mode_should_remask("automatic", false, false));
    CHECK_FALSE(start_mode_should_remask("automatic", true, true));
    // disabled is the mask verb itself: nothing was unmasked
    CHECK_FALSE(start_mode_should_remask("disabled", true, false));
}

TEST_CASE("start_state_is_runtime_masked: only masked-runtime, which automatic and manual refuse",
          "[services][unmask]") {
    using yuzu::services::start_state_is_runtime_masked;
    CHECK(start_state_is_runtime_masked("masked-runtime\n"));
    CHECK(start_state_is_runtime_masked("masked-runtime\r\n"));
    CHECK_FALSE(start_state_is_runtime_masked("masked\n"));
    CHECK_FALSE(start_state_is_runtime_masked("enabled-runtime"));
    CHECK_FALSE(start_state_is_runtime_masked(""));
    CHECK_FALSE(start_state_is_runtime_masked("masked-runtime-x"));
    // the two masked states never both route to a re-mask
    using yuzu::services::start_mode_should_remask;
    using yuzu::services::start_state_is_masked;
    CHECK_FALSE(start_mode_should_remask("automatic", start_state_is_masked("masked-runtime"), false));
    CHECK(start_mode_should_remask("manual", start_state_is_masked("masked"), false));
}

// ── the Linux set_start_mode body, driven with a fake runner (WP13) ─────────────────────────────
// No systemd, no sudo, no subprocess: every systemctl call is answered by the fake below, and the
// output lines, the typed status and the sequence of calls are asserted. These are the behavioural
// tests the lexical gate (tests/test_services_readback_wiring_lexical.py) backs up.


namespace {

struct FakeCtx {
    std::vector<std::string> lines;
    std::vector<std::string> statuses; // "<status>/<completeness>/<provenance>"
    void write_output(std::string_view t) { lines.emplace_back(t); }
    void set_result_status(YuzuResultStatus s, YuzuResultCompleteness c, std::string_view p) {
        statuses.push_back(std::format("{}/{}/{}", static_cast<int>(s), static_cast<int>(c), p));
    }
    [[nodiscard]] bool has(std::string_view prefix) const {
        for (const auto& l : lines)
            if (l.starts_with(prefix))
                return true;
        return false;
    }
};

struct FakeSystemctl {
    // Per-verb scripted answers: exit code and stdout. is_enabled answers are consumed in order
    // (the prior read, then the readback); the last one repeats.
    std::vector<std::string> is_enabled_out;
    int enable_rc = 0, disable_rc = 0, mask_rc = 0, unmask_rc = 0;
    bool is_enabled_ran = true;
    std::vector<std::string> calls; // the verb of each call, in order
    std::size_t is_enabled_n = 0;

    SubprocessResult operator()(const std::vector<std::string>& argv, bool /*merge_stderr*/ = true) {
        SubprocessResult r;
        r.tool_ran = true;
        r.termination_reason = TerminationReason::exited;
        // root argv: {systemctl, verb, "--", name}
        const std::string& verb = argv.at(1);
        calls.push_back(verb);
        if (verb == "is-enabled") {
            if (!is_enabled_ran) {
                r.tool_ran = false;
                r.termination_reason = TerminationReason::spawn_error;
                return r;
            }
            const std::string out = is_enabled_out.empty()
                                        ? std::string{}
                                        : is_enabled_out[std::min(is_enabled_n, is_enabled_out.size() - 1)];
            ++is_enabled_n;
            r.output = out;
            r.exit_code = (out == "enabled\n" || out == "static\n") ? 0 : 1;
            return r;
        }
        r.exit_code = verb == "enable"    ? enable_rc
                      : verb == "disable" ? disable_rc
                      : verb == "mask"    ? mask_rc
                                          : unmask_rc;
        if (r.exit_code != 0)
            r.output = "Failed";
        return r;
    }
};

int drive(FakeCtx& ctx, FakeSystemctl& sys, std::string_view mode, std::string_view name = "ssh.service") {
    std::size_t forwarded = 0;
    const int rc = yuzu::services::set_start_mode_linux(
        ctx, [&sys](const std::vector<std::string>& a, bool m = true) { return sys(a, m); },
        [&forwarded](const SubprocessResult&) { ++forwarded; }, "/usr/bin/systemctl", name, mode,
        /*euid_is_root=*/true);
    (void)forwarded;
    return rc;
}

std::string joined(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v)
        s += (s.empty() ? "" : ",") + x;
    return s;
}

} // namespace

TEST_CASE("set_start_mode_linux: a clean automatic change reads the state back and reports it",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"disabled\n", "enabled\n"};
    CHECK(drive(ctx, sys, "automatic") == 0);
    CHECK(joined(sys.calls) == "is-enabled,unmask,enable,is-enabled");
    REQUIRE(ctx.lines.size() == 4);
    CHECK(ctx.lines[0] == "status|ok");
    CHECK(ctx.lines[3] == "state|enabled");
    CHECK(ctx.statuses.empty());
    CHECK_FALSE(ctx.has("error|"));
    CHECK_FALSE(ctx.has("note|"));
}

TEST_CASE("set_start_mode_linux: verbs follow the mode and disabled never unmasks or reads a prior state",
          "[services][setmode]") {
    {
        FakeCtx ctx;
        FakeSystemctl sys;
        sys.is_enabled_out = {"enabled\n", "disabled\n"};
        CHECK(drive(ctx, sys, "manual") == 0);
        CHECK(joined(sys.calls) == "is-enabled,unmask,disable,is-enabled");
    }
    {
        FakeCtx ctx;
        FakeSystemctl sys;
        sys.is_enabled_out = {"masked\n"};
        CHECK(drive(ctx, sys, "disabled") == 0);
        CHECK(joined(sys.calls) == "mask,is-enabled");
        CHECK(ctx.has("status|ok"));
    }
}

TEST_CASE("set_start_mode_linux: a masked unit whose enable fails is masked again and says so",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"masked\n"};
    sys.enable_rc = 1;
    CHECK(drive(ctx, sys, "automatic") == 1);
    CHECK(joined(sys.calls) == "is-enabled,unmask,enable,mask");
    CHECK(ctx.has("error|"));
    CHECK(ctx.has("note|remasked:"));
    CHECK_FALSE(ctx.has("note|remask_failed"));
    CHECK_FALSE(ctx.has("status|ok"));
}

TEST_CASE("set_start_mode_linux: a failed re-mask is reported as such, never as restored",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"masked\n"};
    sys.enable_rc = 1;
    sys.mask_rc = 1;
    CHECK(drive(ctx, sys, "automatic") == 1);
    CHECK(ctx.has("note|remask_failed:"));
    CHECK_FALSE(ctx.has("note|remasked:"));
}

TEST_CASE("set_start_mode_linux: a unit that was not masked is never masked by a failure",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"disabled\n"};
    sys.enable_rc = 1;
    CHECK(drive(ctx, sys, "automatic") == 1);
    CHECK(joined(sys.calls) == "is-enabled,unmask,enable");
    CHECK_FALSE(ctx.has("note|"));
}

TEST_CASE("set_start_mode_linux: a runtime-masked unit is refused up front, nothing is called",
          "[services][setmode]") {
    for (const char* mode : {"automatic", "manual"}) {
        FakeCtx ctx;
        FakeSystemctl sys;
        sys.is_enabled_out = {"masked-runtime\n"};
        CHECK(drive(ctx, sys, mode) == 1);
        CHECK(joined(sys.calls) == "is-enabled"); // no unmask, no enable/disable, no mask
        CHECK(ctx.has("error|"));
        CHECK_FALSE(ctx.has("note|remasked"));
        CHECK_FALSE(ctx.has("status|ok"));
        REQUIRE(ctx.statuses.size() == 1);
        CHECK(ctx.statuses[0] == std::format("{}/{}/services:start_mode_runtime_mask",
                                              static_cast<int>(YUZU_RESULT_STATUS_CONSTRAINED),
                                              static_cast<int>(YUZU_RESULT_COMPLETENESS_PARTIAL)));
    }
}

TEST_CASE("set_start_mode_linux: a readback that does not match the mode is a failure, not status|ok",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"disabled\n", "disabled\n"}; // enable exited 0 but acted on nothing
    CHECK(drive(ctx, sys, "automatic") == 1);
    CHECK(ctx.has("error|"));
    CHECK_FALSE(ctx.has("status|ok"));
    CHECK_FALSE(ctx.has("state|"));
}

TEST_CASE("set_start_mode_linux: a readback that did not run is a failure", "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"disabled\n"};
    // the prior read runs, the readback does not
    std::size_t is_enabled_calls = 0;
    const int rc = yuzu::services::set_start_mode_linux(
        ctx,
        [&](const std::vector<std::string>& a, bool m = true) {
            if (a.at(1) == "is-enabled" && ++is_enabled_calls == 2) {
                SubprocessResult r;
                r.tool_ran = false;
                r.termination_reason = TerminationReason::spawn_error;
                return r;
            }
            return sys(a, m);
        },
        [](const SubprocessResult&) {}, "/usr/bin/systemctl", "ssh.service", "automatic", true);
    CHECK(rc == 1);
    CHECK_FALSE(ctx.has("status|ok"));
}

TEST_CASE("set_start_mode_linux: a failed change is an error and forwards a runner failure",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"disabled\n"};
    sys.enable_rc = 1;
    CHECK(drive(ctx, sys, "automatic") == 1);
    CHECK(ctx.has("error|systemctl command failed"));
    CHECK_FALSE(ctx.has("status|ok"));
}

TEST_CASE("set_start_mode_linux: an unchangeable unit completes with a state, a note and a CONSTRAINED status",
          "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"static\n", "static\n"};
    CHECK(drive(ctx, sys, "manual") == 0);
    CHECK(ctx.has("status|ok"));
    CHECK(ctx.has("state|static"));
    CHECK(ctx.has("note|"));
    REQUIRE(ctx.statuses.size() == 1);
    CHECK(ctx.statuses[0].ends_with("/services:start_mode_unchangeable"));
}

TEST_CASE("set_start_mode_linux: an invalid mode runs nothing", "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    CHECK(drive(ctx, sys, "bogus") == 1);
    CHECK(sys.calls.empty());
    CHECK(ctx.has("error|invalid mode"));
}

TEST_CASE("set_start_mode_linux: a non-root agent calls the helper, never systemctl, for the change",
          "[services][setmode]") {
    FakeCtx ctx;
    std::vector<std::vector<std::string>> argvs;
    int is_enabled_n = 0;
    const int rc = yuzu::services::set_start_mode_linux(
        ctx,
        [&](const std::vector<std::string>& a, bool = true) {
            argvs.push_back(a);
            SubprocessResult r;
            r.tool_ran = true;
            r.termination_reason = TerminationReason::exited;
            r.exit_code = 0;
            if (a.size() > 1 && a[1] == "is-enabled") {
                r.output = ++is_enabled_n == 1 ? "disabled\n" : "enabled\n";
                r.exit_code = r.output == "enabled\n" ? 0 : 1;
            }
            return r;
        },
        [](const SubprocessResult&) {}, "/usr/bin/systemctl", "ssh.service", "automatic",
        /*euid_is_root=*/false);
    CHECK(rc == 0);
    bool saw_helper = false;
    for (const auto& a : argvs)
        for (const auto& t : a)
            if (t.find("yuzu-svc-helper") != std::string::npos)
                saw_helper = true;
    CHECK(saw_helper);
}

TEST_CASE("set_start_mode_linux: a masked unmaskable-state unit says it was unmasked", "[services][setmode]") {
    FakeCtx ctx;
    FakeSystemctl sys;
    sys.is_enabled_out = {"masked\n", "static\n"};
    CHECK(drive(ctx, sys, "automatic") == 0);
    bool said = false;
    for (const auto& l : ctx.lines)
        if (l.starts_with("note|") && l.find("was masked before this call and is now unmasked") != std::string::npos)
            said = true;
    CHECK(said);
    CHECK(joined(sys.calls) == "is-enabled,unmask,enable,is-enabled");
}
