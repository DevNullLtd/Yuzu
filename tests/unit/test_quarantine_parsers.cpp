/**
 * test_quarantine_parsers.cpp — netsh/iptables/pfctl status-read parsing
 * (quarantine_parsers.hpp, Wave-2 ADR-3002 migration, quarantine package).
 *
 * Portable and unguarded — all six functions under test are pure text
 * handling (no I/O, no platform dependency), so this TU carries no platform
 * guard and runs on every leg, including a macOS-only CI runner exercising
 * the Windows/Linux parse rules it can never spawn netsh/iptables to
 * produce output for directly.
 *
 * Fixtures are hand-constructed (no live Windows/Linux host available this
 * session) but format-accurate to each tool's real captured output, based
 * on the exact strings quarantine_plugin.cpp's pre-migration code wrote and
 * grepped for.
 */
#include "quarantine_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::quarantine;

// ── is_safe_ip ───────────────────────────────────────────────────────────

TEST_CASE("is_safe_ip accepts IPv4 and IPv6 literals, rejects everything else",
         "[agent][quarantine_parsers]") {
    CHECK(is_safe_ip("10.0.0.5"));
    CHECK(is_safe_ip("::1"));
    CHECK(is_safe_ip("fe80::1"));
    CHECK_FALSE(is_safe_ip(""));
    CHECK_FALSE(is_safe_ip("10.0.0.5; rm -rf /"));
    CHECK_FALSE(is_safe_ip(std::string(46, '1'))); // over the 45-char cap
}

// ── ip_family ────────────────────────────────────────────────────────────

TEST_CASE("ip_family classifies validated IPv4/IPv6 literals and reports unknown "
         "for neither",
         "[agent][quarantine_parsers]") {
    CHECK(ip_family("10.0.0.5") == IpFamily::v4);
    CHECK(ip_family("192.168.1.1") == IpFamily::v4);
    CHECK(ip_family("::1") == IpFamily::v6);
    CHECK(ip_family("fe80::1") == IpFamily::v6);
    CHECK(ip_family("2001:db8::1") == IpFamily::v6);
    CHECK(ip_family("deadbeef") == IpFamily::unknown); // no '.' or ':' -- callers skip it
}

// ── MutationTally / status tokens ───────────────────────────────────────

TEST_CASE("MutationTally.record tallies attempts and successes, and complete() is "
         "true only at full success over at least one attempt",
         "[agent][quarantine_parsers]") {
    MutationTally empty;
    CHECK_FALSE(empty.complete()); // nothing attempted

    MutationTally mixed;
    mixed.record(true);
    mixed.record(true);
    mixed.record(false);
    CHECK(mixed.attempted == 3);
    CHECK(mixed.succeeded == 2);
    CHECK_FALSE(mixed.complete());

    MutationTally full;
    full.record(true);
    full.record(true);
    CHECK(full.complete());
}

TEST_CASE("quarantine_status_token returns failed at 0/N, quarantined_partial at "
         "K/N (0<K<N), and quarantined only at N/N",
         "[agent][quarantine_parsers]") {
    MutationTally zero_of_five;
    for (int i = 0; i < 5; ++i)
        zero_of_five.record(false);
    CHECK(quarantine_status_token(zero_of_five) == kStatusFailed);

    MutationTally three_of_five;
    for (int i = 0; i < 3; ++i)
        three_of_five.record(true);
    for (int i = 0; i < 2; ++i)
        three_of_five.record(false);
    CHECK(quarantine_status_token(three_of_five) == kStatusQuarantinedPartial);

    MutationTally five_of_five;
    for (int i = 0; i < 5; ++i)
        five_of_five.record(true);
    CHECK(quarantine_status_token(five_of_five) == kStatusQuarantined);
}

TEST_CASE("quar_status_token produces the exact five tokens", "[agent][quarantine_parsers]") {
    CHECK(quar_status_token(QuarStatus::active) == "active");
    CHECK(quar_status_token(QuarStatus::partial) == "partial");
    CHECK(quar_status_token(QuarStatus::degraded) == "degraded");
    CHECK(quar_status_token(QuarStatus::uncertain) == "uncertain");
    CHECK(quar_status_token(QuarStatus::inactive) == "inactive");
}

// ── linux_quar_status (read-side dual-family decision) ──────────────────

TEST_CASE("linux_quar_status reads a v4-only host as active, never partial, when "
         "IPv6 is genuinely off (#3282 must-not-cry-wolf requirement)",
         "[agent][quarantine_parsers]") {
    LinuxV6Env off{.tool_present = false, .stack_present = false};
    CHECK(linux_quar_status(true, true, false, false, off) == QuarStatus::active);
}

TEST_CASE("linux_quar_status never reports active when an expected jump is missing "
         "(#3260/#3282 regression: INPUT-present/OUTPUT-absent must read partial)",
         "[agent][quarantine_parsers]") {
    LinuxV6Env off{.tool_present = false, .stack_present = false};
    CHECK(linux_quar_status(true, false, false, false, off) == QuarStatus::partial);
    CHECK(linux_quar_status(false, true, false, false, off) == QuarStatus::partial);

    LinuxV6Env dual{.tool_present = true, .stack_present = true};
    CHECK(linux_quar_status(true, true, true, false, dual) == QuarStatus::partial);
}

TEST_CASE("linux_quar_status reports inactive when nothing is present, and treats "
         "v6-expected purely by tool_present -- stack_present never changes what's "
         "expected, so the read side never disagrees with linux_quarantine's own "
         "case (i) partition (#3282; H3/M1 fix-round)",
         "[agent][quarantine_parsers]") {
    LinuxV6Env off{.tool_present = false, .stack_present = false};
    CHECK(linux_quar_status(false, false, false, false, off) == QuarStatus::inactive);

    // tool absent, stack present (case iii): v6 still not expected (v4
    // alone decides) -- a real containment gap exists, but it is carried in
    // the caller's note|ipv6_unavailable text, not by degrading this
    // function's verdict below active/partial/inactive.
    LinuxV6Env gap{.tool_present = false, .stack_present = true};
    CHECK(linux_quar_status(true, true, false, false, gap) == QuarStatus::active);
    CHECK(linux_quar_status(false, false, false, false, gap) == QuarStatus::inactive);
    CHECK(linux_quar_status(true, false, false, false, gap) == QuarStatus::partial);

    // tool present, stack absent: v6 IS expected -- linux_quarantine's own
    // case (i) attempts the full v6 sequence here regardless of
    // stack_present, so the read side must judge it by the same jumps, not
    // invent an ambiguous third bucket the mutation side has no equivalent
    // for. All four jumps present reads active; none present reads inactive.
    LinuxV6Env odd{.tool_present = true, .stack_present = false};
    CHECK(linux_quar_status(true, true, true, true, odd) == QuarStatus::active);
    CHECK(linux_quar_status(false, false, false, false, odd) == QuarStatus::inactive);
}

TEST_CASE("linux_quar_status requires all four jumps for active when ip6tables is "
         "present",
         "[agent][quarantine_parsers]") {
    LinuxV6Env dual{.tool_present = true, .stack_present = true};
    CHECK(linux_quar_status(true, true, true, true, dual) == QuarStatus::active);
    CHECK(linux_quar_status(true, true, true, false, dual) == QuarStatus::partial);
    CHECK(linux_quar_status(false, false, false, false, dual) == QuarStatus::inactive);
}

// ── linux_quarantine_token (mutation-side dual-family decision) ─────────

TEST_CASE("linux_quarantine_token distinguishes all three v6 environments honestly",
         "[agent][quarantine_parsers]") {
    // (i) tool present, all v6 mutations failed -> quarantined_partial
    {
        MutationTally v4;
        MutationTally v6;
        for (int i = 0; i < 12; ++i)
            v4.record(true);
        for (int i = 0; i < 12; ++i)
            v6.record(false);
        LinuxV6Env env{.tool_present = true, .stack_present = true};
        CHECK(linux_quarantine_token(v4, v6, env) == kStatusQuarantinedPartial);
    }
    // (ii) tool absent, stack absent -> quarantined (v4-only fleet, IPv6 genuinely off)
    {
        MutationTally v4;
        MutationTally v6;
        for (int i = 0; i < 12; ++i)
            v4.record(true);
        LinuxV6Env env{.tool_present = false, .stack_present = false};
        CHECK(linux_quarantine_token(v4, v6, env) == kStatusQuarantined);
    }
    // (iii) tool absent, stack present -> quarantined_partial (real gap: ip6tables
    // missing but IPv6 traffic exists on the wire)
    {
        MutationTally v4;
        MutationTally v6;
        for (int i = 0; i < 12; ++i)
            v4.record(true);
        LinuxV6Env env{.tool_present = false, .stack_present = true};
        CHECK(linux_quarantine_token(v4, v6, env) == kStatusQuarantinedPartial);
    }
}

// ── merge_whitelist_ips ──────────────────────────────────────────────────

TEST_CASE("merge_whitelist_ips merges primary+secondary, dedupes, and preserves "
         "primary-first order -- the pure core of linux_get_whitelist's dual-family "
         "merge",
         "[agent][quarantine_parsers]") {
    std::vector<std::string> v4_ips{"10.0.0.5", "192.168.1.1"};
    std::vector<std::string> v6_ips{"fe80::1", "10.0.0.5"}; // one dup, one unique
    auto merged = merge_whitelist_ips(v4_ips, v6_ips);
    REQUIRE(merged.size() == 3);
    CHECK(merged[0] == "10.0.0.5");
    CHECK(merged[1] == "192.168.1.1");
    CHECK(merged[2] == "fe80::1");
}

// ── netsh ────────────────────────────────────────────────────────────────

TEST_CASE("netsh_matching_rule_names / netsh_whitelist_ips "
         "parse a realistic `netsh advfirewall firewall show rule` capture",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kCapture = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
Action:                               Block


Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             127.0.0.1
Protocol:                             Any
Action:                               Allow


Rule Name:                           YuzuQuarantine_AllowIn_10.0.0.5
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             10.0.0.5/32
Protocol:                             Any
Action:                               Allow


Rule Name:                           SomeOtherRule
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
RemoteIP:                             8.8.8.8
Action:                               Allow

Ok.
)";

    auto names = netsh_matching_rule_names(kCapture);
    REQUIRE(names.size() == 3);
    CHECK(names[0] == "YuzuQuarantine_BlockAllInbound");
    CHECK(names[1] == "YuzuQuarantine_AllowLoopbackIn");
    CHECK(names[2] == "YuzuQuarantine_AllowIn_10.0.0.5");
    // The non-Yuzu rule must never appear in the delete list.
    for (const auto& n : names)
        CHECK(n != "SomeOtherRule");

    auto ips = netsh_whitelist_ips(kCapture);
    // Loopback and the Block rule's "Any" are excluded; the CIDR suffix on
    // the real whitelist entry is stripped; the non-Yuzu rule's RemoteIP
    // never surfaces (its rule name doesn't start with kRulePrefix).
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "10.0.0.5");
}

TEST_CASE("netsh_whitelist_ips excludes the IPv6 loopback rule's ::1 RemoteIP "
         "the same way it excludes 127.0.0.1, alongside a real IPv6 whitelist "
         "entry which still surfaces",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kCapture = R"(
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
RemoteIP:                             ::1
Action:                               Allow

Rule Name:                           YuzuQuarantine_AllowIn_fe80::1
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
RemoteIP:                             fe80::1
Action:                               Allow
)";
    auto ips = netsh_whitelist_ips(kCapture);
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "fe80::1");
}

TEST_CASE("netsh_matching_rule_names and netsh_whitelist_ips return empty "
         "when no rule carries the Yuzu prefix",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kNoRules = R"(
Rule Name:                           Some Windows Default Rule
----------------------------------------------------------------------
Enabled:                              Yes
RemoteIP:                             Any
Action:                               Allow

Ok.
)";
    CHECK(netsh_matching_rule_names(kNoRules).empty());
    CHECK(netsh_whitelist_ips(kNoRules).empty());
}

TEST_CASE("netsh_matching_rule_names deduplicates a rule name repeated across "
         "the dir=in and dir=out captures",
         "[agent][quarantine_parsers]") {
    // win_unquarantine concatenates a dir=in and a dir=out capture before
    // parsing -- the same rule name can legitimately appear twice.
    constexpr std::string_view kDuplicated = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            In

Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            Out
)";
    auto names = netsh_matching_rule_names(kDuplicated);
    REQUIRE(names.size() == 1);
    CHECK(names[0] == "YuzuQuarantine_BlockAllInbound");
}

// ── NetshBaseRules (#3285) ──────────────────────────────────────────────

TEST_CASE("netsh_base_rules_present finds all six base rules in a combined "
         "dir=in + dir=out capture and complete() is true",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kCombined = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            In

Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Direction:                            In

Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Direction:                            In

Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Direction:                            Out

Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Direction:                            Out

Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
Direction:                            Out
)";
    auto rules = netsh_base_rules_present(kCombined);
    CHECK(rules.block_in);
    CHECK(rules.block_out);
    CHECK(rules.allow_lo_in);
    CHECK(rules.allow_lo_out);
    CHECK(rules.allow_lo_in6);
    CHECK(rules.allow_lo_out6);
    CHECK(rules.complete());
    CHECK(rules.missing_names().empty());
}

TEST_CASE("netsh_base_rules_present: a dir=in-only capture containing just "
         "BlockAllInbound never reads complete() -- the exact #3285 failure "
         "(checking only dir=in could never see BlockAllOutbound at all)",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kInboundOnly = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            In
)";
    auto rules = netsh_base_rules_present(kInboundOnly);
    CHECK(rules.block_in);
    CHECK_FALSE(rules.block_out);
    CHECK_FALSE(rules.allow_lo_in);
    CHECK_FALSE(rules.allow_lo_out);
    CHECK_FALSE(rules.allow_lo_in6);
    CHECK_FALSE(rules.allow_lo_out6);
    CHECK_FALSE(rules.complete());
}

TEST_CASE("netsh_base_rules_present: each of the six base rules missing "
         "individually is reported by name in missing_names()",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kMissingBlockIn = R"(
Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
)";
    auto missing_block_in = netsh_base_rules_present(kMissingBlockIn);
    CHECK_FALSE(missing_block_in.complete());
    CHECK(missing_block_in.missing_names() == "YuzuQuarantine_BlockAllInbound");

    constexpr std::string_view kMissingBlockOut = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
)";
    auto missing_block_out = netsh_base_rules_present(kMissingBlockOut);
    CHECK_FALSE(missing_block_out.complete());
    CHECK(missing_block_out.missing_names() == "YuzuQuarantine_BlockAllOutbound");

    constexpr std::string_view kMissingLoIn = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
)";
    auto missing_lo_in = netsh_base_rules_present(kMissingLoIn);
    CHECK_FALSE(missing_lo_in.complete());
    CHECK(missing_lo_in.missing_names() == "YuzuQuarantine_AllowLoopbackIn");

    constexpr std::string_view kMissingLoOut = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
)";
    auto missing_lo_out = netsh_base_rules_present(kMissingLoOut);
    CHECK_FALSE(missing_lo_out.complete());
    CHECK(missing_lo_out.missing_names() == "YuzuQuarantine_AllowLoopbackOut");

    constexpr std::string_view kMissingLoIn6 = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut6
----------------------------------------------------------------------
)";
    auto missing_lo_in6 = netsh_base_rules_present(kMissingLoIn6);
    CHECK_FALSE(missing_lo_in6.complete());
    CHECK(missing_lo_in6.missing_names() == "YuzuQuarantine_AllowLoopbackIn6");

    constexpr std::string_view kMissingLoOut6 = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_BlockAllOutbound
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackOut
----------------------------------------------------------------------
Rule Name:                           YuzuQuarantine_AllowLoopbackIn6
----------------------------------------------------------------------
)";
    auto missing_lo_out6 = netsh_base_rules_present(kMissingLoOut6);
    CHECK_FALSE(missing_lo_out6.complete());
    CHECK(missing_lo_out6.missing_names() == "YuzuQuarantine_AllowLoopbackOut6");
}

// ── netsh_firewall_policy / all_profiles_blocking (#3284 branch A) ──────

TEST_CASE("netsh_firewall_policy parses a realistic `netsh advfirewall show "
         "allprofiles` capture into per-profile inbound/outbound defaults, "
         "including a mixed-profile case",
         "[agent][quarantine_parsers]") {
    // Mixed: Domain and Private both blocking both directions (the #3284
    // branch-A containment state); Public still at the Windows stock
    // default (BlockInbound,AllowOutbound) -- proves the parser attributes
    // each profile's own line independently rather than assuming
    // uniformity across profiles.
    constexpr std::string_view kMixedCapture = R"(
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,BlockOutbound
LocalFirewallRules                    N/A (GPO-store only)
InboundUserNotification               Enable

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,BlockOutbound
LocalFirewallRules                    N/A (GPO-store only)

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)

Ok.
)";
    auto profiles = netsh_firewall_policy(kMixedCapture);
    REQUIRE(profiles.size() == 3);
    CHECK(profiles[0].profile == "Domain");
    CHECK(profiles[0].inbound == FirewallAction::block);
    CHECK(profiles[0].outbound == FirewallAction::block);
    CHECK(profiles[1].profile == "Private");
    CHECK(profiles[1].inbound == FirewallAction::block);
    CHECK(profiles[1].outbound == FirewallAction::block);
    CHECK(profiles[2].profile == "Public");
    CHECK(profiles[2].inbound == FirewallAction::block);
    CHECK(profiles[2].outbound == FirewallAction::allow);

    // Mixed -- Public still allows outbound -- so NOT every profile blocks.
    CHECK_FALSE(all_profiles_blocking(profiles));
}

TEST_CASE("all_profiles_blocking is true only when every profile blocks "
         "both directions, and false -- never vacuously true -- on an empty "
         "or unparseable capture",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kAllBlocking = R"(
Domain Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,BlockOutbound

Private Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,BlockOutbound

Public Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,BlockOutbound

Ok.
)";
    CHECK(all_profiles_blocking(netsh_firewall_policy(kAllBlocking)));

    constexpr std::string_view kWindowsDefault = R"(
Domain Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,AllowOutbound

Ok.
)";
    CHECK_FALSE(all_profiles_blocking(netsh_firewall_policy(kWindowsDefault)));

    // A failed/empty capture must never read as "every profile blocks" --
    // an all-of over an empty range would otherwise vacuously return true.
    CHECK(netsh_firewall_policy("").empty());
    CHECK_FALSE(all_profiles_blocking(netsh_firewall_policy("")));
}

// ── iptables ─────────────────────────────────────────────────────────────

TEST_CASE("iptables_chain_referenced detects the yuzu-quarantine jump in "
         "`iptables -L INPUT -n` output",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kInputWithJump = R"(Chain INPUT (policy ACCEPT)
target           prot opt source               destination
yuzu-quarantine  all  --  0.0.0.0/0            0.0.0.0/0
)";
    CHECK(iptables_chain_referenced(kInputWithJump));

    constexpr std::string_view kInputWithoutJump = R"(Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
)";
    CHECK_FALSE(iptables_chain_referenced(kInputWithoutJump));
}

TEST_CASE("iptables_whitelist_ips parses a realistic `iptables -L yuzu-quarantine -n` "
         "capture, excluding loopback/state/default-route rows",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kChainCapture = R"(Chain yuzu-quarantine (2 references)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            in lo
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            out lo
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
ACCEPT     all  --  10.0.0.5             0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            10.0.0.5
DROP       all  --  0.0.0.0/0            0.0.0.0/0
)";
    auto ips = iptables_whitelist_ips(kChainCapture);
    // Both the source-side and dest-side ACCEPT for the same whitelisted IP
    // collapse to one entry; the loopback/state/DROP/default-route rows
    // contribute nothing.
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "10.0.0.5");
}

TEST_CASE("iptables_whitelist_ips returns empty for a freshly-created empty chain",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kEmptyChain = R"(Chain yuzu-quarantine (0 references)
target     prot opt source               destination
)";
    CHECK(iptables_whitelist_ips(kEmptyChain).empty());
}

TEST_CASE("iptables_whitelist_ips: the loopback ACCEPT rule contributes no "
         "whitelist entry (#3260 regression guard)",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kLoopbackOnly = R"(Chain yuzu-quarantine (2 references)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            in lo
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            out lo
)";
    CHECK(iptables_whitelist_ips(kLoopbackOnly).empty());
}

TEST_CASE("iptables_whitelist_ips: a line containing the substring 'lo' elsewhere "
         "no longer suppresses a genuine whitelisted IP (#3260 regression guard)",
         "[agent][quarantine_parsers]") {
    // A line whose trailing text happens to contain "lo" (e.g. a comment or
    // interface annotation some future capture format might add) must never
    // suppress a real whitelisted IP -- the old dead substring filter would
    // have discarded this row outright even though it carries no interface
    // restriction on the parsed columns at all.
    constexpr std::string_view kWithLoSubstring = R"(Chain yuzu-quarantine (1 references)
target     prot opt source               destination
ACCEPT     all  --  10.0.0.5             0.0.0.0/0            /* deploy-lo-east */
)";
    auto ips = iptables_whitelist_ips(kWithLoSubstring);
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "10.0.0.5");
}

TEST_CASE("iptables_whitelist_ips parses a realistic `ip6tables -L yuzu-quarantine -n` "
         "capture with the SAME column layout as its iptables twin, and "
         "merge_whitelist_ips combines it with a v4 capture with no cross-family "
         "leakage (#3282 acceptance criterion 9 / H2 disproof)",
         "[agent][quarantine_parsers]") {
    // ip6tables -L -n renders the "opt" column identically to iptables
    // (literal "--", not blank/shifted) -- the shared xtables print path
    // both tools use produces this layout for every distro this plugin
    // targets. This fixture pins that so a future layout regression on
    // either tool fails a test instead of silently losing the v6 whitelist.
    constexpr std::string_view kV4Capture = R"(Chain yuzu-quarantine (2 references)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
ACCEPT     all  --  10.0.0.5             0.0.0.0/0
DROP       all  --  0.0.0.0/0            0.0.0.0/0
)";
    constexpr std::string_view kV6Capture = R"(Chain yuzu-quarantine (2 references)
target     prot opt source               destination
ACCEPT     all  --  ::/0                 ::/0                 state RELATED,ESTABLISHED
ACCEPT     all  --  2001:db8::5          ::/0
DROP       all  --  ::/0                 ::/0
)";
    auto v4_ips = iptables_whitelist_ips(kV4Capture);
    REQUIRE(v4_ips.size() == 1);
    CHECK(v4_ips[0] == "10.0.0.5");

    auto v6_ips = iptables_whitelist_ips(kV6Capture);
    REQUIRE(v6_ips.size() == 1);
    CHECK(v6_ips[0] == "2001:db8::5");

    // The v6 literal, present only in the ip6tables capture, appears in the
    // merged whitelist; a v4 literal duplicated in both would dedupe (not
    // exercised here since the two captures carry disjoint entries).
    auto merged = merge_whitelist_ips(v4_ips, v6_ips);
    REQUIRE(merged.size() == 2);
    CHECK(merged[0] == "10.0.0.5");
    CHECK(merged[1] == "2001:db8::5");
}

// ── pfctl ────────────────────────────────────────────────────────────────

TEST_CASE("pfctl_rules_blocked recognizes both the literal and pfctl-canonicalized "
         "default-deny spelling",
         "[agent][quarantine_parsers]") {
    CHECK(pfctl_rules_blocked("set skip on lo0\nblock all\n"));
    CHECK(pfctl_rules_blocked("set skip on lo0\nblock drop all\n"));
    CHECK_FALSE(pfctl_rules_blocked("set skip on lo0\npass all\n"));
}

TEST_CASE("pfctl_rules_blocked is false against a realistic macOS default ruleset "
         "(no Yuzu quarantine active)",
         "[agent][quarantine_parsers]") {
    // Approximates `pfctl -s rules` on a stock macOS box with pf enabled but
    // no quarantine loaded -- Apple's default ruleset is anchor-only, no
    // top-level default-deny.
    constexpr std::string_view kStockRuleset = R"(scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
)";
    CHECK_FALSE(pfctl_rules_blocked(kStockRuleset));
}

TEST_CASE("pfctl_whitelist_ips parses a realistic `pfctl -s rules` capture of an "
         "active quarantine ruleset",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kActiveRuleset = R"(set skip on lo0
pass quick from 10.0.0.5 to any keep state
pass quick from any to 10.0.0.5 keep state
pass quick from 192.168.1.1 to any keep state
pass quick from any to 192.168.1.1 keep state
block drop all
)";
    auto ips = pfctl_whitelist_ips(kActiveRuleset);
    REQUIRE(ips.size() == 2);
    CHECK(ips[0] == "10.0.0.5");
    CHECK(ips[1] == "192.168.1.1");
}

TEST_CASE("pfctl_whitelist_ips ignores the lo0 skip directive and returns empty "
         "when the ruleset has no pass rules",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kBlockOnly = "set skip on lo0\nblock drop all\n";
    CHECK(pfctl_whitelist_ips(kBlockOnly).empty());
}

// ── pfctl -s info / macos_quar_status (#3283) ────────────────────────────

TEST_CASE("pfctl_status_state recognizes Enabled/Disabled and reports unknown "
         "for anything else, including the empty capture a non-root read "
         "produces",
         "[agent][quarantine_parsers]") {
    CHECK(pfctl_status_state("Status: Enabled for 0 days 00:12:34\n") == PfStatus::enabled);
    CHECK(pfctl_status_state("Status: Disabled\n") == PfStatus::disabled);
    CHECK(pfctl_status_state("") == PfStatus::unknown);
    CHECK(pfctl_status_state("some unrecognisable garbage\n") == PfStatus::unknown);
}

TEST_CASE("macos_quar_status: a blocking ruleset with pf disabled reads "
         "degraded, never active -- the exact #3283 failure",
         "[agent][quarantine_parsers]") {
    // "block drop all" is the pfctl-canonicalized ruleset text
    // pfctl_rules_blocked recognizes; "Status: Disabled" is what a stock,
    // pf-off-by-default macOS host's `pfctl -s info` reports even though
    // the ruleset loaded cleanly.
    const bool rules_blocked = pfctl_rules_blocked("set skip on lo0\nblock drop all\n");
    REQUIRE(rules_blocked);
    const auto pf_status = pfctl_status_state("Status: Disabled\n");
    REQUIRE(pf_status == PfStatus::disabled);

    CHECK(macos_quar_status(rules_blocked, pf_status) == QuarStatus::degraded);
}

TEST_CASE("macos_quar_status: a blocking ruleset with an empty/unrecognisable "
         "`pfctl -s info` capture reads uncertain -- neither active nor "
         "inactive",
         "[agent][quarantine_parsers]") {
    const bool rules_blocked = pfctl_rules_blocked("set skip on lo0\nblock drop all\n");
    REQUIRE(rules_blocked);
    const auto pf_status = pfctl_status_state(""); // non-root read -> empty capture

    const auto verdict = macos_quar_status(rules_blocked, pf_status);
    CHECK(verdict == QuarStatus::uncertain);
    CHECK(verdict != QuarStatus::active);
    CHECK(verdict != QuarStatus::inactive);
}

TEST_CASE("macos_quar_status: blocked + enabled is the true positive, active",
         "[agent][quarantine_parsers]") {
    CHECK(macos_quar_status(/*rules_blocked=*/true, PfStatus::enabled) == QuarStatus::active);
}

TEST_CASE("macos_quar_status: an unblocked ruleset always reads inactive, "
         "regardless of pf's own enabled/disabled/unknown status -- no "
         "quarantine ruleset is loaded at all",
         "[agent][quarantine_parsers]") {
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::enabled) == QuarStatus::inactive);
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::disabled) == QuarStatus::inactive);
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::unknown) == QuarStatus::inactive);
}

// ── #3285 Windows: the policy set is load-bearing, never outvoted ──────────
//
// Regression guard for the gate this file's own branch shipped with: a bare
// success counter reported `quarantined` whenever ANY netsh call landed, so a
// failed containment step plus two successful loopback Allow rules read as a
// clean success on a host with nothing blocked at all.

TEST_CASE("win_quarantine_token: a failed policy set is `failed`, whatever else succeeded",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;

    // The exact #3285 shape: containment failed, both loopback Allow rules
    // landed. A flat tally would call this quarantined_partial.
    MutationTally t;
    t.record(false); // the policy set
    t.record(true);  // AllowLoopbackIn
    t.record(true);  // AllowLoopbackOut
    CHECK(win_quarantine_token(/*policy_applied=*/false, t) == kStatusFailed);
    CHECK(quarantine_status_token(t) == kStatusQuarantinedPartial); // the flat reducer's answer
}

TEST_CASE("win_quarantine_token: containment plus a missing exception is partial",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    MutationTally t;
    t.record(true);  // the policy set
    t.record(true);  // AllowLoopbackIn
    t.record(false); // AllowLoopbackOut failed — loopback half-open
    CHECK(win_quarantine_token(/*policy_applied=*/true, t) == kStatusQuarantinedPartial);
}

TEST_CASE("win_quarantine_token: `quarantined` only when every attempt succeeded",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    MutationTally t;
    for (int i = 0; i < 4; ++i)
        t.record(true);
    CHECK(win_quarantine_token(/*policy_applied=*/true, t) == kStatusQuarantined);

    MutationTally none;
    CHECK(win_quarantine_token(/*policy_applied=*/true, none) == kStatusFailed);
}

// ── #3284: the pre-quarantine profile policy must survive to release ───────
//
// The captured policy round-trips through plugin KV storage, so it re-enters
// as untrusted input and lands in an argv. Parsing is therefore strict: any
// malformed record rejects the WHOLE string, because a partial replay would
// put some profiles back and silently leave others on the quarantine policy.

TEST_CASE("profile policy round-trips through storage form", "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const std::vector<ProfilePolicy> in{
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::block, FirewallAction::block},
        {"Public", FirewallAction::allow, FirewallAction::block},
    };
    const auto s = serialize_profile_policies(in);
    CHECK(s == "Domain=block,allow;Private=block,block;Public=allow,block");

    const auto back = parse_profile_policies(s);
    REQUIRE(back.size() == 3);
    CHECK(back[1].profile == "Private");
    CHECK(back[1].inbound == FirewallAction::block);
    CHECK(back[1].outbound == FirewallAction::block);
    CHECK(back[2].inbound == FirewallAction::allow);
}

TEST_CASE("a mixed-profile host is not flattened", "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // The case a single `set allprofiles` restore would destroy.
    const auto back = parse_profile_policies("Domain=block,block;Public=block,allow");
    REQUIRE(back.size() == 2);
    CHECK(back[0].outbound == FirewallAction::block);
    CHECK(back[1].outbound == FirewallAction::allow);
}

TEST_CASE("malformed stored policy rejects wholesale, never partially",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // A good record followed by a bad one must yield NOTHING — replaying just
    // the good half would leave Public on the quarantine policy silently.
    CHECK(parse_profile_policies("Domain=block,allow;Bogus=block,allow").empty());
    CHECK(parse_profile_policies("Domain=block,allow;Public=sideways,allow").empty());
    CHECK(parse_profile_policies("Domain=block,allow;Public=block").empty());
    CHECK(parse_profile_policies("garbage").empty());
    CHECK(parse_profile_policies("").empty());
}

TEST_CASE("unknown actions are omitted from the stored form, never invented",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const std::vector<ProfilePolicy> in{
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::unknown, FirewallAction::allow},
    };
    // Private is dropped rather than serialised from a value never observed;
    // on restore it is simply left untouched.
    CHECK(serialize_profile_policies(in) == "Domain=block,allow");
}

TEST_CASE("per-profile restore argv is scoped, and refuses to half-form",
          "[agent][quarantine_argv]") {
    using namespace yuzu::quarantine;
    const auto argv = netsh_restore_profile_policy_argv(
        "C:\\Windows\\System32\\netsh.exe", {"Private", FirewallAction::block,
                                             FirewallAction::block});
    REQUIRE(argv.size() == 6);
    CHECK(argv[3] == "privateprofile"); // scoped, NOT allprofiles
    CHECK(argv[4] == "firewallpolicy");
    CHECK(argv[5] == "blockinbound,blockoutbound");

    // An unrecognised profile or an unknown action yields no argv at all —
    // the caller must never be able to spawn a partial policy write.
    CHECK(netsh_restore_profile_policy_argv("netsh.exe",
                                            {"Bogus", FirewallAction::block,
                                             FirewallAction::block})
              .empty());
    CHECK(netsh_restore_profile_policy_argv("netsh.exe",
                                            {"Domain", FirewallAction::unknown,
                                             FirewallAction::block})
              .empty());
}

// ── CDX-P1-05: a failed chain flush disqualifies its family ────────────────
//
// The flush installs no containment, so a SUCCESSFUL one must never count
// toward the tally. But a FAILED one leaves the chain holding whatever it had
// before — including a stale terminal DROP — so every rule appended after it
// lands behind that DROP and is inert, while the tally, seeing only the
// appends, reads a clean N/N. The flush result is therefore folded separately.

TEST_CASE("linux_quarantine_token: a failed v4 flush cannot be outvoted by a full tally",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    MutationTally v4, v6;
    for (int i = 0; i < 8; ++i) v4.record(true);   // every append succeeded
    for (int i = 0; i < 8; ++i) v6.record(true);
    const LinuxV6Env env{.tool_present = true, .stack_present = true};

    CHECK(linux_quarantine_token(v4, v6, env, {}) == kStatusQuarantined);          // baseline
    CHECK(linux_quarantine_token(v4, v6, env, {.v4_ok = false}) == kStatusQuarantinedPartial);
    CHECK(linux_quarantine_token(v4, v6, env, {.v6_ok = false}) == kStatusQuarantinedPartial);
}

TEST_CASE("linux_quarantine_token: a failed flush with nothing applied is `failed`",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    MutationTally v4, v6;
    for (int i = 0; i < 4; ++i) v4.record(false);
    const LinuxV6Env env{.tool_present = false, .stack_present = false};
    CHECK(linux_quarantine_token(v4, v6, env, {.v4_ok = false}) == kStatusFailed);
}

TEST_CASE("linux_quarantine_token: a v6 flush failure is ignored when v6 was never attempted",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    MutationTally v4, v6;
    for (int i = 0; i < 6; ++i) v4.record(true);
    // ip6tables absent and no v6 stack: the family was skipped, so a stale
    // v6_ok=false must not degrade an otherwise complete v4-only containment.
    const LinuxV6Env env{.tool_present = false, .stack_present = false};
    CHECK(linux_quarantine_token(v4, v6, env, {.v6_ok = false}) == kStatusQuarantined);
}

// ── CDX-P1-04: an unreadable host is `uncertain`, never `inactive` ─────────
//
// Every jump-presence flag comes from a chain listing, and a listing that
// FAILED yields exactly the same all-false input as a host with no containment
// at all. Reporting `inactive` there tells a compliance poller that a possibly
// contained host was released — the #3285 false-clean read, pointing the other
// way.

TEST_CASE("linux_quar_status: a failed read is uncertain, not inactive",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const LinuxV6Env env{.tool_present = true, .stack_present = true};

    // All-false WITH a successful read is a genuine "never quarantined".
    CHECK(linux_quar_status(false, false, false, false, env, /*reads_ok=*/true) ==
          QuarStatus::inactive);
    // All-false because the read FAILED is not an answer at all.
    CHECK(linux_quar_status(false, false, false, false, env, /*reads_ok=*/false) ==
          QuarStatus::uncertain);
}

TEST_CASE("linux_quar_status: a failed read overrides even a fully-present chain",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const LinuxV6Env env{.tool_present = true, .stack_present = true};
    // If any required listing failed, the flags that DID parse cannot be
    // trusted to describe the whole chain state.
    CHECK(linux_quar_status(true, true, true, true, env, /*reads_ok=*/false) ==
          QuarStatus::uncertain);
    CHECK(linux_quar_status(true, true, true, true, env, /*reads_ok=*/true) == QuarStatus::active);
}

TEST_CASE("linux_quar_status: reads_ok defaults true so existing callers are unchanged",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const LinuxV6Env env{.tool_present = false, .stack_present = false};
    CHECK(linux_quar_status(true, true, false, false, env) == QuarStatus::active);
}

// ── CDX-P1-03: a fragment is not a restore image ──────────────────────────
//
// Quarantine replaces the policy on ALL profiles at once, so anything less
// than all three is a fragment. Replaying one puts some profiles back and
// leaves the rest on the quarantine policy while reporting a clean release.
// `netsh_firewall_policy` legitimately returns fewer profiles on a truncated
// or localised capture, so this is a real input.

TEST_CASE("is_complete_profile_policy: all three profiles with known actions",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const std::vector<ProfilePolicy> full{
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::block, FirewallAction::allow},
        {"Public", FirewallAction::block, FirewallAction::block},
    };
    CHECK(is_complete_profile_policy(full));
}

TEST_CASE("is_complete_profile_policy: rejects every fragment shape",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // Truncated capture — the exact netsh_firewall_policy failure mode.
    CHECK_FALSE(is_complete_profile_policy({{"Domain", FirewallAction::block,
                                             FirewallAction::allow}}));
    // Two of three.
    CHECK_FALSE(is_complete_profile_policy({
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::block, FirewallAction::allow},
    }));
    // All three present but one action unknown.
    CHECK_FALSE(is_complete_profile_policy({
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::block, FirewallAction::unknown},
        {"Public", FirewallAction::block, FirewallAction::block},
    }));
    // An unrecognised profile means the capture is not what we think it is.
    CHECK_FALSE(is_complete_profile_policy({
        {"Domain", FirewallAction::block, FirewallAction::allow},
        {"Private", FirewallAction::block, FirewallAction::allow},
        {"Public", FirewallAction::block, FirewallAction::block},
        {"Bogus", FirewallAction::block, FirewallAction::block},
    }));
    CHECK_FALSE(is_complete_profile_policy({}));
}

TEST_CASE("is_complete_profile_policy: gates the storage round-trip end to end",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // A fragment that round-trips cleanly through serialize/parse is STILL
    // rejected — round-tripping proves the encoding is sound, not that the
    // image is usable.
    const std::vector<ProfilePolicy> frag{{"Domain", FirewallAction::block,
                                           FirewallAction::allow}};
    const auto s = serialize_profile_policies(frag);
    REQUIRE_FALSE(s.empty());
    const auto back = parse_profile_policies(s);
    REQUIRE(back.size() == 1);
    CHECK_FALSE(is_complete_profile_policy(back));
}

// ── Windows netsh output is CRLF, and `output` is RAW bytes ───────────────
//
// The runner strips CR only from `SubprocessResult::lines`; these parsers read
// `SubprocessResult::output`, which is the raw stream. The pre-#3285 reader
// substring-matched the rule prefix and was CR-immune; the exact comparisons
// that replaced it were not, so on a real Windows host every base-rule flag
// came back false and a CONTAINED device reported `state|inactive`, rc 0.
// No fixture in this file contained a `\r` until now, which is why it survived.

TEST_CASE("netsh parsers tolerate CRLF, as real netsh emits it",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const std::string crlf =
        "Rule Name:                            YuzuQuarantine_AllowLoopbackIn\r\n"
        "----------------------------------------------------------------------\r\n"
        "Enabled:                              Yes\r\n"
        "RemoteIP:                             127.0.0.1\r\n"
        "\r\n"
        "Rule Name:                            YuzuQuarantine_AllowLoopbackOut\r\n"
        "Enabled:                              Yes\r\n"
        "RemoteIP:                             127.0.0.1\r\n"
        "\r\n"
        "Rule Name:                            YuzuQuarantine_AllowIn_10.0.0.5\r\n"
        "RemoteIP:                             10.0.0.5\r\n";

    const auto rules = netsh_base_rules_present(crlf);
    CHECK(rules.allow_lo_in);
    CHECK(rules.allow_lo_out);

    const auto names = netsh_matching_rule_names(crlf);
    REQUIRE(names.size() == 3);
    CHECK(names[0] == "YuzuQuarantine_AllowLoopbackIn"); // no trailing \r
    CHECK(names[0].find('\r') == std::string::npos);

    const auto wl = netsh_whitelist_ips(crlf);
    REQUIRE(wl.size() == 1);
    CHECK(wl[0] == "10.0.0.5");
}

TEST_CASE("netsh parsers give identical answers for LF and CRLF",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const std::string lf =
        "Rule Name:                            YuzuQuarantine_AllowLoopbackIn\n"
        "Rule Name:                            YuzuQuarantine_AllowLoopbackOut\n";
    std::string crlf;
    for (char c : lf) {
        if (c == '\n') crlf += '\r';
        crlf += c;
    }
    const auto a = netsh_base_rules_present(lf);
    const auto b = netsh_base_rules_present(crlf);
    CHECK(a.allow_lo_in == b.allow_lo_in);
    CHECK(a.allow_lo_out == b.allow_lo_out);
    CHECK(b.allow_lo_in);
    CHECK(netsh_matching_rule_names(lf) == netsh_matching_rule_names(crlf));
}

TEST_CASE("is_complete_profile_policy: a repeated profile is not a restore image",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // Replay issues one netsh write per entry in order, so the LAST record for
    // a profile wins — this set would restore Domain to allow/allow, a policy
    // never captured, and still report a clean release.
    const auto dup = parse_profile_policies(
        "Domain=block,block;Private=block,block;Public=block,block;Domain=allow,allow");
    REQUIRE(dup.size() == 4);
    CHECK_FALSE(is_complete_profile_policy(dup));

    // The same three profiles without the duplicate remain acceptable.
    const auto ok = parse_profile_policies("Domain=block,allow;Private=block,allow;Public=block,allow");
    CHECK(is_complete_profile_policy(ok));
}

TEST_CASE("is_quarantine_shaped_policy: our own containment policy is unrestorable",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    CHECK(is_quarantine_shaped_policy(
        parse_profile_policies("Domain=block,block;Private=block,block;Public=block,block")));
    CHECK_FALSE(is_quarantine_shaped_policy(
        parse_profile_policies("Domain=block,allow;Private=block,block;Public=block,block")));
    CHECK_FALSE(is_quarantine_shaped_policy({}));
}

// ── Gate 4: the tool-present / stack-absent host, and the macOS read seam ──

TEST_CASE("v6_in_scope: an ipv6.disable=1 host with iptables installed is OUT of scope",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // The case the earlier `tool_present`-only predicate missed. A CIS/STIG
    // host booted ipv6.disable=1 still ships the stock iptables package, so
    // the tool is present and every ip6tables call fails — there is no v6
    // stack to talk to.
    CHECK_FALSE(v6_in_scope({.tool_present = true, .stack_present = false}));
    CHECK(v6_in_scope({.tool_present = true, .stack_present = true}));
    CHECK_FALSE(v6_in_scope({.tool_present = false, .stack_present = false}));
    CHECK_FALSE(v6_in_scope({.tool_present = false, .stack_present = true}));
}

TEST_CASE("linux_quarantine_token: tool present + stack absent reads quarantined, not partial",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const LinuxV6Env tool_no_stack{.tool_present = true, .stack_present = false};
    const LinuxV6Env neither{.tool_present = false, .stack_present = false};

    MutationTally v4;
    v4.attempted = 6;
    v4.succeeded = 6;
    // v6 was skipped, so its tally is empty and its flush "succeeded" in the
    // sense that none was attempted.
    MutationTally v6;

    // The defect: this host previously reported quarantined_partial forever,
    // while a host with IDENTICAL IPv6 exposure (none) that merely lacked the
    // iptables package reported a clean quarantined. Both must agree now.
    CHECK(linux_quarantine_token(v4, v6, tool_no_stack) == kStatusQuarantined);
    CHECK(linux_quarantine_token(v4, v6, neither) == kStatusQuarantined);

    // A v6 flush "failure" recorded against a skipped family must not drag the
    // verdict down either — the family was never in scope.
    CHECK(linux_quarantine_token(v4, v6, tool_no_stack, {.v4_ok = true, .v6_ok = false}) ==
          kStatusQuarantined);

    // The genuine gap case is unchanged: a live stack with no tool to contain it.
    const LinuxV6Env gap{.tool_present = false, .stack_present = true};
    CHECK(linux_quarantine_token(v4, v6, gap) == kStatusQuarantinedPartial);
}

TEST_CASE("linux_quar_status: tool present + stack absent reads active on v4 jumps alone",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    const LinuxV6Env tool_no_stack{.tool_present = true, .stack_present = false};
    // Both v4 jumps present, no v6 jumps — because none were ever installed.
    // Previously this read `partial`, and with the v6 chain listing failing it
    // read `uncertain` forever.
    CHECK(linux_quar_status(/*v4_in=*/true, /*v4_out=*/true, /*v6_in=*/false, /*v6_out=*/false,
                            tool_no_stack) == QuarStatus::active);
    // The read side must agree with the mutation side about what was expected.
    CHECK(linux_quar_status(/*v4_in=*/true, /*v4_out=*/false, /*v6_in=*/false, /*v6_out=*/false,
                            tool_no_stack) == QuarStatus::partial);
}

TEST_CASE("macos_quar_status: a FAILED read is uncertain, never inactive",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;
    // CDX-P1-04 on the macOS leg. A revoked sudoers grant makes `pfctl -s
    // rules` exit non-zero with an empty capture, which is byte-identical to a
    // clean host's — so rules_blocked=false. Reporting `inactive` there tells
    // an operator a network-isolated device is released.
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::unknown, /*reads_ok=*/false) ==
          QuarStatus::uncertain);
    // reads_ok dominates every other input: an unreadable host is never
    // reported active or inactive, whatever the (untrustworthy) capture said.
    CHECK(macos_quar_status(/*rules_blocked=*/true, PfStatus::enabled, /*reads_ok=*/false) ==
          QuarStatus::uncertain);
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::enabled, /*reads_ok=*/false) ==
          QuarStatus::uncertain);
    // A SUCCESSFUL read still answers normally — the parameter must not turn
    // every determinate answer into uncertain.
    CHECK(macos_quar_status(/*rules_blocked=*/false, PfStatus::enabled, /*reads_ok=*/true) ==
          QuarStatus::inactive);
    CHECK(macos_quar_status(/*rules_blocked=*/true, PfStatus::enabled, /*reads_ok=*/true) ==
          QuarStatus::active);
}

TEST_CASE("iptables_chain_denies: a referenced-but-empty chain is not containment",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;

    // The failure shape: release deleted nothing but flushed the chain, so the
    // jumps still point at it and it holds nothing. This read is what stops
    // `status` calling that host `active`.
    CHECK_FALSE(iptables_chain_denies("Chain yuzu-quarantine (2 references)\n"
                                      "target     prot opt source               destination\n"));

    // A real containment chain: loopback + established allows, terminal DROP.
    CHECK(iptables_chain_denies(
        "Chain yuzu-quarantine (2 references)\n"
        "target     prot opt source               destination\n"
        "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0\n"
        "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED\n"
        "ACCEPT     all  --  10.0.0.9             0.0.0.0/0\n"
        "DROP       all  --  0.0.0.0/0            0.0.0.0/0\n"));

    // Allow-only: whitelist entries applied, terminal DROP missing. Exactly the
    // partial that must not read as active.
    CHECK_FALSE(iptables_chain_denies(
        "Chain yuzu-quarantine (2 references)\n"
        "ACCEPT     all  --  10.0.0.9             0.0.0.0/0\n"));

    // Column-anchored, not a substring: DROP appearing anywhere other than the
    // target column does not count.
    CHECK_FALSE(iptables_chain_denies(
        "Chain yuzu-quarantine (2 references)\n"
        "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            /* DROP later */\n"));

    // CRLF-tolerant, and an empty capture (a failed read) never claims a deny.
    CHECK(iptables_chain_denies("DROP       all  --  ::/0                 ::/0\r\n"));
    CHECK_FALSE(iptables_chain_denies(""));
}

TEST_CASE("netsh_base_rules_present is the discriminator for 'did WE contain this host'",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;

    // Gate 8: win_quarantine asks this question before deciding whether an
    // all-block policy capture is a genuine hardened posture (store it) or its
    // own containment read back (refuse it). It previously asked netsh for the
    // rule BY NAME and treated a non-zero exit as "read failed" — but
    // `show rule name=<absent>` exits non-zero, which IS the answer "not
    // ours", so the probe could never return false and every host looked
    // already-contained. These two cases pin both answers, which is the
    // property the old shape could not have satisfied.

    // A host this plugin has contained: our loopback rule is in the listing.
    const std::string ours =
        "\r\nRule Name:                            YuzuQuarantine_AllowLoopbackIn\r\n"
        "----------------------------------------------------------------------\r\n"
        "Enabled:                              Yes\r\n"
        "Direction:                            In\r\n"
        "Action:                               Allow\r\n";
    CHECK(netsh_base_rules_present(ours).allow_lo_in);

    // A host with a real firewall and no rule of ours — including one whose
    // own rules mention the string in a different field, which a substring
    // search over the raw capture would have matched.
    const std::string not_ours =
        "\r\nRule Name:                            Core Networking - DHCP (DHCP-In)\r\n"
        "Enabled:                              Yes\r\n"
        "Grouping:                             YuzuQuarantine_AllowLoopbackIn\r\n"
        "Direction:                            In\r\n"
        "Action:                               Allow\r\n";
    CHECK_FALSE(netsh_base_rules_present(not_ours).allow_lo_in);

    // An empty capture answers "not ours" — which is why the caller must treat
    // a FAILED read separately rather than letting an empty string decide.
    CHECK_FALSE(netsh_base_rules_present("").allow_lo_in);
}

TEST_CASE("netsh_capture_usable: a truncated capture is not a usable one, and an "
          "exit code is not the question",
          "[agent][quarantine_parsers]") {
    using namespace yuzu::quarantine;

    // The distinction the four netsh parse sites depend on. `tool_ran` is TRUE
    // for a capture that overflowed the runner's ~1MB cap — the runner keeps
    // draining and the child exits normally — so a read-success test that does
    // not look at truncation reports a prefix as a complete listing. This
    // plugin's own rules are appended last, so they are what the prefix drops:
    // every parser then answers "no Yuzu rules here" about a host this plugin
    // contained.
    CHECK(netsh_capture_usable(/*tool_ran=*/true, /*timed_out=*/false,
                               /*output_truncated=*/false));

    // The case a tool_ran-only test cannot see, and the reason this exists.
    CHECK_FALSE(netsh_capture_usable(/*tool_ran=*/true, /*timed_out=*/false,
                                     /*output_truncated=*/true));

    // The two genuine failures.
    CHECK_FALSE(netsh_capture_usable(/*tool_ran=*/false, /*timed_out=*/false,
                                     /*output_truncated=*/false));
    CHECK_FALSE(netsh_capture_usable(/*tool_ran=*/true, /*timed_out=*/true,
                                     /*output_truncated=*/false));

    // Each failure is independently sufficient — no combination rescues one.
    CHECK_FALSE(netsh_capture_usable(true, true, true));

    // And the deliberate omission: there is no exit-code parameter, because a
    // read-only parse must not gate on a query's exit status. Every current
    // call site passes `name=all`, which exits 0 on any host with rules to
    // list, so the omission is close to a no-op today — it is the contract for
    // the NEXT caller, since a `name=<specific>` site reliably exits non-zero
    // on no match and would otherwise inherit a gate the contract forbids.
    static_assert(std::is_invocable_r_v<bool, decltype(&netsh_capture_usable), bool, bool, bool>,
                  "netsh_capture_usable takes exactly the three fields that can invalidate a "
                  "PARSE — adding an exit-code parameter would reintroduce the gating its own "
                  "doc comment refuses");
}
