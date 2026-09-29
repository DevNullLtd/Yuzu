/**
 * test_quarantine_argv.cpp — structural argv-shape coverage for the
 * quarantine plugin's mutating call sites (Wave-2 ADR-3002 migration,
 * quarantine package, FN-03 gap fix).
 *
 * quarantine's mutating actions run iptables/pfctl/netsh against the real
 * host firewall, so — unlike the users/services plugins' read-only actions
 * — they are deliberately NOT exercised end-to-end via LocalDispatcher here
 * (that would firewall the test host). Instead this pins the pure argv
 * CONSTRUCTION for one representative mutating call site per platform
 * (netsh_allow_in_rule_argv / iptables_accept_source_argv /
 * pfctl_load_ruleset_argv, quarantine_parsers.hpp), including — for the two
 * POSIX platforms — the caller-applied `sudo -n -- <tool> <args>` wrapping
 * (yuzu::shared::sudo_wrap, pinned independently by test_sudo_argv.cpp).
 * Proves an argument can't be silently dropped, reordered, or de-sudo'd
 * without a test failing, for the pattern every other of the 43 migrated
 * sites in this file follows. Not exhaustive over all 43 sites by design.
 */
#include "quarantine_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::quarantine;

// ── Windows: netsh ───────────────────────────────────────────────────────

TEST_CASE("netsh_allow_in_rule_argv builds the exact add-rule argv, IP threaded "
         "into both the rule name and remoteip",
         "[agent][quarantine_argv]") {
    const auto argv = netsh_allow_in_rule_argv("C:\\Windows\\System32\\netsh.exe", "10.0.0.5");
    const std::vector<std::string> expected{
        "C:\\Windows\\System32\\netsh.exe",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=YuzuQuarantine_AllowIn_10.0.0.5",
        "dir=in",
        "action=allow",
        "enable=yes",
        "remoteip=10.0.0.5",
    };
    CHECK(argv == expected);
}

TEST_CASE("netsh_set_firewall_policy_argv builds the exact set-policy argv for "
         "win_quarantine's #3284 branch-A block, using kWinFirewallPolicyBlockBoth",
         "[agent][quarantine_argv]") {
    const auto argv = netsh_set_firewall_policy_argv("C:\\Windows\\System32\\netsh.exe",
                                                      kWinFirewallPolicyBlockBoth);
    const std::vector<std::string> expected{
        "C:\\Windows\\System32\\netsh.exe", "advfirewall",   "set",
        "allprofiles",                     "firewallpolicy", "blockinbound,blockoutbound",
    };
    CHECK(argv == expected);
}

TEST_CASE("netsh_set_firewall_policy_argv builds the exact restore-policy argv "
         "win_unquarantine issues at teardown, using kWinFirewallPolicyDefault -- "
         "identical shape to the set call above, only the policy value differs",
         "[agent][quarantine_argv]") {
    const auto argv = netsh_set_firewall_policy_argv("C:\\Windows\\System32\\netsh.exe",
                                                      kWinFirewallPolicyDefault);
    const std::vector<std::string> expected{
        "C:\\Windows\\System32\\netsh.exe", "advfirewall",   "set",
        "allprofiles",                     "firewallpolicy", "blockinbound,allowoutbound",
    };
    CHECK(argv == expected);
    // The two policy constants themselves must never collide -- a typo that
    // made them equal would make win_unquarantine's restore a silent no-op.
    CHECK(kWinFirewallPolicyBlockBoth != kWinFirewallPolicyDefault);
}

// ── Linux: iptables + sudo wrap ─────────────────────────────────────────

#ifndef _WIN32
#include "sudo_argv.hpp"

TEST_CASE("iptables_accept_source_argv builds the exact per-IP ACCEPT argv, and "
         "sudo_wrap applies the canonical `sudo -n -- <tool> <args>` form on top",
         "[agent][quarantine_argv]") {
    const auto tool_argv = iptables_accept_source_argv("/usr/sbin/iptables", "10.0.0.5");
    const std::vector<std::string> expected_tool{"/usr/sbin/iptables", "-A", "yuzu-quarantine",
                                                 "-s", "10.0.0.5",     "-j", "ACCEPT"};
    CHECK(tool_argv == expected_tool);

    const auto wrapped = yuzu::shared::sudo_wrap(tool_argv, /*euid_is_root=*/false);
    REQUIRE(wrapped.size() == tool_argv.size() + 3);
    CHECK(wrapped[0] == "/usr/bin/sudo");
    CHECK(wrapped[1] == "-n");
    CHECK(wrapped[2] == "--");
    // The wrapped tail is the tool argv byte-for-byte, in order — no
    // argument silently dropped or reordered by the wrap.
    for (size_t i = 0; i < tool_argv.size(); ++i)
        CHECK(wrapped[3 + i] == tool_argv[i]);
}

TEST_CASE("iptables_accept_source_argv builds the exact per-IPv6 ACCEPT argv when "
         "called with an ip6tables path, and sudo_wrap applies the canonical form "
         "identically to the iptables case -- no cross-family leakage in the argv "
         "shape (#3282)",
         "[agent][quarantine_argv]") {
    const auto tool_argv = iptables_accept_source_argv("/usr/sbin/ip6tables", "fe80::1");
    const std::vector<std::string> expected_tool{"/usr/sbin/ip6tables", "-A", "yuzu-quarantine",
                                                 "-s", "fe80::1",       "-j", "ACCEPT"};
    CHECK(tool_argv == expected_tool);

    const auto wrapped = yuzu::shared::sudo_wrap(tool_argv, /*euid_is_root=*/false);
    REQUIRE(wrapped.size() == tool_argv.size() + 3);
    CHECK(wrapped[0] == "/usr/bin/sudo");
    CHECK(wrapped[1] == "-n");
    CHECK(wrapped[2] == "--");
    for (size_t i = 0; i < tool_argv.size(); ++i)
        CHECK(wrapped[3 + i] == tool_argv[i]);

    // No cross-family leakage: the same builder called with the iptables
    // path and an IPv4 literal never produces the ip6tables argv above (and
    // an IPv6 literal is routed by ip_family() to this path, never that
    // one) -- the family is decided entirely by the caller-supplied tool
    // path and IP, not guessed by this function.
    const auto v4_argv = iptables_accept_source_argv("/usr/sbin/iptables", "10.0.0.5");
    CHECK(v4_argv != tool_argv);
    CHECK(v4_argv[0] == "/usr/sbin/iptables");
    CHECK(ip_family("fe80::1") == IpFamily::v6);
    CHECK(ip_family("10.0.0.5") == IpFamily::v4);
}

// ── macOS: pfctl + sudo wrap ─────────────────────────────────────────────

TEST_CASE("pfctl_load_ruleset_argv builds the exact atomic-load argv, and sudo_wrap "
         "applies the canonical form on top",
         "[agent][quarantine_argv]") {
    const auto tool_argv = pfctl_load_ruleset_argv("/sbin/pfctl", "/tmp/yuzu-quarantine-abc.conf");
    const std::vector<std::string> expected_tool{"/sbin/pfctl", "-f",
                                                 "/tmp/yuzu-quarantine-abc.conf"};
    CHECK(tool_argv == expected_tool);

    const auto wrapped = yuzu::shared::sudo_wrap(tool_argv, /*euid_is_root=*/false);
    REQUIRE(wrapped.size() == tool_argv.size() + 3);
    CHECK(wrapped[0] == "/usr/bin/sudo");
    CHECK(wrapped[1] == "-n");
    CHECK(wrapped[2] == "--");
    CHECK(wrapped[3] == "/sbin/pfctl");
    CHECK(wrapped[4] == "-f");
    CHECK(wrapped[5] == "/tmp/yuzu-quarantine-abc.conf");
}

TEST_CASE("sudo_wrap skips the sudo prefix entirely when already root, for both "
         "POSIX argv builders",
         "[agent][quarantine_argv]") {
    const auto iptables_argv = iptables_accept_source_argv("/usr/sbin/iptables", "192.168.1.1");
    CHECK(yuzu::shared::sudo_wrap(iptables_argv, /*euid_is_root=*/true) == iptables_argv);

    const auto pfctl_argv = pfctl_load_ruleset_argv("/sbin/pfctl", "/tmp/x.conf");
    CHECK(yuzu::shared::sudo_wrap(pfctl_argv, /*euid_is_root=*/true) == pfctl_argv);
}

#endif // !_WIN32
