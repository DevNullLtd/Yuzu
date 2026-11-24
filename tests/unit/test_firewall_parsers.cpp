/**
 * test_firewall_parsers.cpp — pure firewall parse helpers
 * (firewall_parsers.hpp, macOS parity 1.1).
 *
 * The popen shell-outs are the impure shell; the decision-shaped parsing of
 * `socketfilterfw --getglobalstate` and `pfctl -s info` output is header-pure
 * and pinned here on every host (the netprobe_stats.hpp pattern). Fixture
 * strings marked "real capture" were taken verbatim from a macOS 26 host;
 * older macOS releases are not yet fixture-verified — capture and add when
 * such hardware is available.
 */

#include "firewall_parsers.hpp"
#include "firewall_restore_compare.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::firewall;

TEST_CASE("alf: disabled (State = 0) — real capture", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is disabled. (State = 0)");
    CHECK(r.state == FwState::disabled);
    CHECK_FALSE(r.block_all);
}

TEST_CASE("alf: enabled (State = 1)", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is enabled. (State = 1)");
    CHECK(r.state == FwState::enabled);
    CHECK_FALSE(r.block_all);
}

TEST_CASE("alf: block-all (State = 2)", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is enabled. (State = 2)");
    CHECK(r.state == FwState::enabled);
    CHECK(r.block_all);
}

TEST_CASE("alf: the state number outranks drifted prose", "[firewall]") {
    // If a future macOS rewords the sentence, the "(State = N)" clause must
    // still decide — even when the prose says the opposite.
    auto r = parse_alf_global_state(
        "Firewall is set to block all incoming connections. (State = 2)");
    CHECK(r.state == FwState::enabled);
    CHECK(r.block_all);

    auto contradictory = parse_alf_global_state("Firewall is enabled. (State = 0)");
    CHECK(contradictory.state == FwState::disabled);
}

TEST_CASE("alf: prose fallback when the state clause is absent", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled.").state == FwState::enabled);
    CHECK(parse_alf_global_state("Firewall is disabled.").state == FwState::disabled);
    // Both words present → "disabled" wins (bias toward the answer that draws
    // an admin's attention, never toward false assurance).
    CHECK(parse_alf_global_state("enabled then disabled").state == FwState::disabled);
}

TEST_CASE("alf: unrecognised state number falls back to prose", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled. (State = 7)").state ==
          FwState::enabled);
    CHECK(parse_alf_global_state("Mystery text. (State = 7)").state == FwState::unknown);
}

TEST_CASE("alf: multi-digit or negative state numbers are unrecognised", "[firewall]") {
    // "(State = 10)" must not be misread as State 1 — the clause is
    // unrecognised and the prose decides instead.
    CHECK(parse_alf_global_state("Firewall is enabled. (State = 10)").state ==
          FwState::enabled); // via prose fallback, not the '1'
    auto r = parse_alf_global_state("Mystery text. (State = 10)");
    CHECK(r.state == FwState::unknown);
    CHECK_FALSE(r.block_all);
    CHECK(parse_alf_global_state("Mystery text. (State = -1)").state == FwState::unknown);
}

TEST_CASE("alf: truncated clause at end of output is not read past", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled. (State = ").state ==
          FwState::enabled); // prose fallback, no out-of-range read
}

TEST_CASE("alf: empty and garbage output are unknown, never false-safe", "[firewall]") {
    CHECK(parse_alf_global_state("").state == FwState::unknown);
    CHECK(parse_alf_global_state(
              "sh: /usr/libexec/ApplicationFirewall/socketfilterfw: "
              "No such file or directory")
              .state == FwState::unknown);
}

TEST_CASE("pf: enabled and disabled status lines", "[firewall]") {
    CHECK(parse_pf_status("Status: Enabled for 0 days 00:00:15           Debug: Urgent") ==
          FwState::enabled);
    CHECK(parse_pf_status("Status: Disabled for 0 days 00:01:02          Debug: Urgent") ==
          FwState::disabled);
}

TEST_CASE("pf: empty or error output is unknown — real non-root capture", "[firewall]") {
    // Non-root read: pfctl prints "pfctl: /dev/pf: Permission denied" on
    // stderr and nothing on stdout; the plugin discards stderr, so the parser
    // sees "". If anyone ever flips the shell-out to 2>&1, the error text
    // itself must still parse to unknown.
    CHECK(parse_pf_status("") == FwState::unknown);
    CHECK(parse_pf_status("pfctl: /dev/pf: Permission denied") == FwState::unknown);
}

// Real capture: `socketfilterfw --listapps` run unprivileged on this Mac
// (macOS 26, 2026-09-14) — 8 apps, all Allow. Trailing spaces after the
// header, the index/path lines, and the indentation before each
// parenthetical are verbatim from the capture, not tidied.
constexpr std::string_view kAlfListappsCapture =
    "Total number of apps = 8 \n"
    "1 : /usr/local/libexec/remotepairingdeviced \n"
    "             (Allow incoming connections)\n"
    "2 : /usr/libexec/remoted \n"
    "             (Allow incoming connections)\n"
    "3 : /usr/bin/python3 \n"
    "             (Allow incoming connections)\n"
    "4 : /usr/bin/ruby \n"
    "             (Allow incoming connections)\n"
    "5 : /usr/sbin/cupsd \n"
    "             (Allow incoming connections)\n"
    "6 : /usr/libexec/sharingd \n"
    "             (Allow incoming connections)\n"
    "7 : /usr/libexec/sshd-keygen-wrapper \n"
    "             (Allow incoming connections)\n"
    "8 : /usr/sbin/smbd \n"
    "             (Allow incoming connections)\n";

TEST_CASE("alf listapps: real 8-app capture, all allow", "[firewall]") {
    auto rows = parse_alf_listapps(kAlfListappsCapture);
    REQUIRE(rows.size() == 8);
    CHECK(rows[0].path == "/usr/local/libexec/remotepairingdeviced");
    CHECK(rows[0].decision == AlfDecision::allow);
    CHECK(rows[1].path == "/usr/libexec/remoted");
    CHECK(rows[1].decision == AlfDecision::allow);
    CHECK(rows[2].path == "/usr/bin/python3");
    CHECK(rows[2].decision == AlfDecision::allow);
    CHECK(rows[3].path == "/usr/bin/ruby");
    CHECK(rows[3].decision == AlfDecision::allow);
    CHECK(rows[4].path == "/usr/sbin/cupsd");
    CHECK(rows[4].decision == AlfDecision::allow);
    CHECK(rows[5].path == "/usr/libexec/sharingd");
    CHECK(rows[5].decision == AlfDecision::allow);
    CHECK(rows[6].path == "/usr/libexec/sshd-keygen-wrapper");
    CHECK(rows[6].decision == AlfDecision::allow);
    CHECK(rows[7].path == "/usr/sbin/smbd");
    CHECK(rows[7].decision == AlfDecision::allow);
}

TEST_CASE("alf listapps: synthetic block line", "[firewall]") {
    auto rows = parse_alf_listapps("1 : /usr/bin/synthetic \n"
                                    "             (Block incoming connections)\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].path == "/usr/bin/synthetic");
    CHECK(rows[0].decision == AlfDecision::block);
}

TEST_CASE("alf listapps: unrecognised parenthetical is unknown, not dropped",
          "[firewall]") {
    // A real emitted state (e.g. a future macOS wording change) must still
    // surface the row rather than silently disappearing it.
    auto rows = parse_alf_listapps("1 : /usr/bin/mystery \n"
                                    "             (Some future wording)\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].path == "/usr/bin/mystery");
    CHECK(rows[0].decision == AlfDecision::unknown);
}

TEST_CASE("alf listapps: empty input (unprivileged refusal) yields empty", "[firewall]") {
    CHECK(parse_alf_listapps("").empty());
}

// The two "no following parenthetical" fallback branches the header
// comment documents -- an index line immediately followed by another
// index line, and a dangling pending row at end of input -- were
// previously unexercised by any fixture (code-review r1, FV-claude-fallback-04).
TEST_CASE("alf listapps: index line immediately followed by another index line is unknown",
          "[firewall]") {
    auto rows = parse_alf_listapps("1 : /a \n"
                                    "2 : /b \n"
                                    "             (Allow incoming connections)\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].path == "/a");
    CHECK(rows[0].decision == AlfDecision::unknown);
    CHECK(rows[1].path == "/b");
    CHECK(rows[1].decision == AlfDecision::allow);
}

TEST_CASE("alf listapps: dangling pending row at end of input is unknown", "[firewall]") {
    auto rows = parse_alf_listapps("1 : /a \n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].path == "/a");
    CHECK(rows[0].decision == AlfDecision::unknown);
}

// Real capture: `pfctl -s Anchors` and `pfctl -s rules`, run as root
// (~/pf-capture.txt, 2026-09-14) — only the anchor-name / rule lines
// themselves, verbatim.
constexpr std::string_view kPfAnchorsCapture = "  NordVPN\n"
                                                "  com.apple\n";
constexpr std::string_view kPfRulesCapture =
    "scrub-anchor \"com.apple/*\" all fragment reassemble\n"
    "anchor \"com.apple/*\" all\n";

TEST_CASE("pf anchors: real capture, order preserved, whitespace trimmed", "[firewall]") {
    auto anchors = parse_pf_anchors(kPfAnchorsCapture);
    REQUIRE(anchors.size() == 2);
    CHECK(anchors[0] == "NordVPN");
    CHECK(anchors[1] == "com.apple");
}

TEST_CASE("pf anchors: empty/Permission-denied (empty stdout) yields empty",
          "[firewall]") {
    // Non-root read: "pfctl: /dev/pf: Permission denied" goes to stderr,
    // which the caller discards, so the parser sees "".
    CHECK(parse_pf_anchors("").empty());
}

TEST_CASE("pf rules: real capture line count", "[firewall]") {
    CHECK(count_pf_rules(kPfRulesCapture) == 2);
}

TEST_CASE("pf rules: empty input is 0, never nullopt — refusal is the shell's call",
          "[firewall]") {
    CHECK(count_pf_rules("") == 0);
}

TEST_CASE("fw state to_string round-trip", "[firewall]") {
    CHECK(to_string(FwState::enabled) == "enabled");
    CHECK(to_string(FwState::disabled) == "disabled");
    CHECK(to_string(FwState::unknown) == "unknown");
}

// ── Linux: ufw ───────────────────────────────────────────────────────────
//
// Synthetic fixtures matching documented `ufw` output (no live-captured ufw
// output was available in this sandbox — flagged here, not silently assumed
// verified).

TEST_CASE("ufw status: enabled/disabled — the real regression this replaces", "[firewall]") {
    // The bug this parser fixes: the old shell-out did
    // `output.find("active") != npos`, which ALSO matches inside "inactive"
    // -- misreporting a disabled ufw as active. A full-prefix check must
    // never let "Status: inactive" satisfy the active branch.
    CHECK(parse_ufw_status("Status: active\n") == FwState::enabled);
    CHECK(parse_ufw_status("Status: inactive\n") == FwState::disabled);
}

TEST_CASE("ufw status: empty or unrecognised output is unknown", "[firewall]") {
    CHECK(parse_ufw_status("") == FwState::unknown);
    CHECK(parse_ufw_status("sh: ufw: command not found") == FwState::unknown);
}

TEST_CASE("ufw rules: numbered status parses To/Action/From columns — synthetic", "[firewall]") {
    constexpr std::string_view out =
        "Status: active\n"
        "\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 2] 80,443/tcp                 ALLOW IN    192.168.1.0/24\n";
    auto rules = parse_ufw_rules(out);
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].index == "1");
    CHECK(rules[0].to == "22/tcp");
    CHECK(rules[0].action == "ALLOW IN");
    CHECK(rules[0].from == "Anywhere");
    CHECK(rules[1].index == "2");
    CHECK(rules[1].to == "80,443/tcp");
    CHECK(rules[1].action == "ALLOW IN");
    CHECK(rules[1].from == "192.168.1.0/24");
}

TEST_CASE("ufw rules: inactive ufw with zero numbered rows", "[firewall]") {
    CHECK(parse_ufw_rules("Status: inactive\n").empty());
}

TEST_CASE("ufw rules: malformed bracket line is skipped, not crashed on", "[firewall]") {
    CHECK(parse_ufw_rules("[unterminated bracket with no close\n").empty());
}

// ── Linux: iptables ─────────────────────────────────────────────────────
//
// Real capture: `iptables -S` inside a privileged Docker debian:bookworm-slim
// container with seed rules (NET_ADMIN,NET_RAW), 2026-08-14 — see
// ~/.claude/wave2-prestage/fixtures/linux/iptables_capture.out.

TEST_CASE("iptables -S: real capture — policies, new chain, appends", "[firewall]") {
    constexpr std::string_view out = "-P INPUT ACCEPT\n"
                                     "-P FORWARD ACCEPT\n"
                                     "-P OUTPUT ACCEPT\n"
                                     "-N fixture-chain\n"
                                     "-A INPUT -j fixture-chain\n"
                                     "-A fixture-chain -i lo -j ACCEPT\n"
                                     "-A fixture-chain -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                                     "-A fixture-chain -s 10.0.0.5/32 -j ACCEPT\n"
                                     "-A fixture-chain -j DROP\n";
    auto rules = parse_iptables_save(out);
    REQUIRE(rules.size() == 9);

    CHECK(rules[0].type == IptablesEntryType::policy);
    CHECK(rules[0].chain == "INPUT");
    CHECK(rules[0].spec == "ACCEPT");
    CHECK(rules[2].type == IptablesEntryType::policy);
    CHECK(rules[2].chain == "OUTPUT");
    CHECK(rules[2].spec == "ACCEPT");

    CHECK(rules[3].type == IptablesEntryType::new_chain);
    CHECK(rules[3].chain == "fixture-chain");
    CHECK(rules[3].spec.empty());

    CHECK(rules[4].type == IptablesEntryType::append);
    CHECK(rules[4].chain == "INPUT");
    CHECK(rules[4].spec == "-j fixture-chain");

    CHECK(rules[6].type == IptablesEntryType::append);
    CHECK(rules[6].chain == "fixture-chain");
    CHECK(rules[6].spec == "-m state --state RELATED,ESTABLISHED -j ACCEPT");

    CHECK(rules[8].type == IptablesEntryType::append);
    CHECK(rules[8].chain == "fixture-chain");
    CHECK(rules[8].spec == "-j DROP");
}

TEST_CASE("iptables -S: unrecognised line preserved, not dropped", "[firewall]") {
    auto rules = parse_iptables_save("-X some-chain\n");
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].type == IptablesEntryType::unknown);
    CHECK(rules[0].spec == "-X some-chain");
}

TEST_CASE("iptables -S: empty output yields zero rules, never fabricated", "[firewall]") {
    CHECK(parse_iptables_save("").empty());
}

// ── Linux: nftables (rung 1, netlink) ───────────────────────────────────
//
// No live kernel is available in this sandbox (see PR notes), so these are
// hand-built fixtures constructed directly from the documented, VERSIONED
// UAPI wire format (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nf_tables.h) rather than a captured real reply — flagged
// here, not silently assumed verified, the same discipline the ufw fixtures
// above already follow for a different reason. The builder helpers below
// exist ONLY to make the fixtures reviewable byte-by-byte instead of opaque
// hex literals; they encode the same header-field/attribute-value byte-order
// split documented in firewall_parsers.hpp (nlmsghdr/nlattr headers: host
// order; nftables numeric attribute VALUES: big-endian).

namespace {

void push_u16(std::vector<std::byte>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::byte>(v & 0xff));
    buf.push_back(static_cast<std::byte>((v >> 8) & 0xff));
}

void push_u32(std::vector<std::byte>& buf, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
}

void pad_to_align(std::vector<std::byte>& buf) {
    while (buf.size() % 4 != 0)
        buf.push_back(std::byte{0});
}

/// Appends one nlattr (header + raw value + alignment padding).
void push_attr_raw(std::vector<std::byte>& buf, std::uint16_t type,
                   std::span<const std::byte> value) {
    push_u16(buf, static_cast<std::uint16_t>(4 + value.size()));
    push_u16(buf, type);
    buf.insert(buf.end(), value.begin(), value.end());
    pad_to_align(buf);
}

void push_attr_str(std::vector<std::byte>& buf, std::uint16_t type, std::string_view s) {
    std::vector<std::byte> value;
    for (char c : s)
        value.push_back(static_cast<std::byte>(c));
    value.push_back(std::byte{0}); // NUL terminator, matching real NFTA_*_NAME encoding
    push_attr_raw(buf, type, value);
}

void push_attr_be32(std::vector<std::byte>& buf, std::uint16_t type, std::uint32_t v) {
    std::vector<std::byte> value;
    for (int i = 3; i >= 0; --i)
        value.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
    push_attr_raw(buf, type, value);
}

void push_attr_be64(std::vector<std::byte>& buf, std::uint16_t type, std::uint64_t v) {
    std::vector<std::byte> value;
    for (int i = 7; i >= 0; --i)
        value.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
    push_attr_raw(buf, type, value);
}

/// Appends a nested attribute (NLA_F_NESTED set, matching real encoding —
/// though the parser under test masks the flag bits off before comparing,
/// so this is for fixture realism, not something the parser depends on).
void push_attr_nested(std::vector<std::byte>& buf, std::uint16_t type,
                      std::span<const std::byte> nested_body) {
    constexpr std::uint16_t kNlaFNested = 0x8000;
    push_u16(buf, static_cast<std::uint16_t>(4 + nested_body.size()));
    push_u16(buf, static_cast<std::uint16_t>(type | kNlaFNested));
    buf.insert(buf.end(), nested_body.begin(), nested_body.end());
    pad_to_align(buf);
}

/// Wraps `body` (nfgenmsg + attributes, unpadded) in an nlmsghdr of the
/// given message `type` and appends it (with its own alignment padding).
void push_nlmsg(std::vector<std::byte>& out, std::uint16_t type,
                std::span<const std::byte> body, std::uint16_t flags = 0) {
    push_u32(out, static_cast<std::uint32_t>(16 + body.size()));
    push_u16(out, type);
    // flags defaults to 0 -- unread by the parse_nft_* functions under test,
    // but split_nlmsgs() still decodes it verbatim (nft_dump()'s
    // NLM_F_DUMP_INTR check reads it from that same decoded header).
    push_u16(out, flags);
    push_u32(out, 0); // seq
    push_u32(out, 0); // pid
    out.insert(out.end(), body.begin(), body.end());
    pad_to_align(out);
}

void push_done(std::vector<std::byte>& out) {
    push_nlmsg(out, nft_raw::kNlmsgDone, std::span<const std::byte>{});
}

std::vector<std::byte> make_nfgenmsg(std::uint8_t family) {
    return {static_cast<std::byte>(family), std::byte{0}, std::byte{0}, std::byte{0}};
}

} // namespace

TEST_CASE("nft: parse_nft_tables — two tables, hand-built wire shape", "[firewall]") {
    std::vector<std::byte> buf;
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaTableName, "filter");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 0), body);
    }
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoIpv4);
        push_attr_str(body, nft_raw::kNftaTableName, "nat");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 0), body);
    }
    push_done(buf);

    auto tables = parse_nft_tables(buf);
    REQUIRE(tables.size() == 2);
    CHECK(tables[0].family == nft_raw::kNfprotoInet);
    CHECK(tables[0].name == "filter");
    CHECK(tables[1].family == nft_raw::kNfprotoIpv4);
    CHECK(tables[1].name == "nat");
}

TEST_CASE("nft: parse_nft_chains — base chain (hook+policy) vs regular chain", "[firewall]") {
    std::vector<std::byte> buf;
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaChainTable, "filter");
        push_attr_str(body, nft_raw::kNftaChainName, "INPUT");
        std::vector<std::byte> hook_body;
        push_attr_be32(hook_body, nft_raw::kNftaHookHooknum, 1); // NF_INET_LOCAL_IN
        push_attr_nested(body, nft_raw::kNftaChainHook, hook_body);
        push_attr_be32(body, nft_raw::kNftaChainPolicy, nft_raw::kNftPolicyDrop);
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 3), body);
    }
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaChainTable, "filter");
        push_attr_str(body, nft_raw::kNftaChainName, "custom-jump");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 3), body);
    }
    push_done(buf);

    auto chains = parse_nft_chains(buf);
    REQUIRE(chains.size() == 2);

    CHECK(chains[0].table == "filter");
    CHECK(chains[0].name == "INPUT");
    CHECK(chains[0].is_base_chain);
    REQUIRE(chains[0].hooknum.has_value());
    CHECK(*chains[0].hooknum == 1);
    REQUIRE(chains[0].policy.has_value());
    CHECK(*chains[0].policy == nft_raw::kNftPolicyDrop);
    CHECK(nft_hook_name(chains[0].hooknum) == "input");
    CHECK(nft_policy_name(chains[0].policy) == "drop");

    CHECK(chains[1].name == "custom-jump");
    CHECK_FALSE(chains[1].is_base_chain);
    CHECK_FALSE(chains[1].hooknum.has_value());
    CHECK_FALSE(chains[1].policy.has_value());
}

TEST_CASE("nft: parse_nft_rules — handle decoded as big-endian u64", "[firewall]") {
    std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
    push_attr_str(body, nft_raw::kNftaRuleTable, "filter");
    push_attr_str(body, nft_raw::kNftaRuleChain, "INPUT");
    push_attr_be64(body, nft_raw::kNftaRuleHandle, 42);
    std::vector<std::byte> buf;
    push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 6), body);
    push_done(buf);

    auto rules = parse_nft_rules(buf);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].table == "filter");
    CHECK(rules[0].chain == "INPUT");
    REQUIRE(rules[0].handle.has_value());
    CHECK(*rules[0].handle == 42);
}

TEST_CASE("nft: has_content — accept-policy base chain with no rules is inactive", "[firewall]") {
    NftChainInfo c;
    c.is_base_chain = true;
    c.policy = nft_raw::kNftPolicyAccept;
    CHECK_FALSE(nft_has_content({c}, {}));
}

TEST_CASE("nft: has_content — drop-policy base chain counts as active even with no rules",
         "[firewall]") {
    NftChainInfo c;
    c.is_base_chain = true;
    c.policy = nft_raw::kNftPolicyDrop;
    CHECK(nft_has_content({c}, {}));
}

TEST_CASE("nft: has_content — any rule counts as active regardless of chain policy", "[firewall]") {
    CHECK(nft_has_content({}, std::vector<NftRuleInfo>(1)));
}

TEST_CASE("nft: has_content — empty ruleset is inactive, never fabricated", "[firewall]") {
    CHECK_FALSE(nft_has_content({}, {}));
}

TEST_CASE("nft: truncated buffer (shorter than one nlmsghdr) yields nothing, no crash",
         "[firewall]") {
    std::vector<std::byte> buf(10, std::byte{0});
    CHECK(parse_nft_tables(buf).empty());
}

TEST_CASE("nft: NLMSG_ERROR is skipped, never treated as data", "[firewall]") {
    std::vector<std::byte> buf;
    push_nlmsg(buf, nft_raw::kNlmsgError, std::vector<std::byte>(4, std::byte{0}));
    CHECK(parse_nft_tables(buf).empty());
}

TEST_CASE("nft: an attribute length overrunning the buffer stops the walk safely",
         "[firewall]") {
    std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
    // Corrupt attribute: declares 100 bytes of value but the message ends
    // right after this 4-byte attribute header -- must not read out of bounds.
    push_u16(body, 100);
    push_u16(body, nft_raw::kNftaTableName);
    std::vector<std::byte> buf;
    push_nlmsg(buf, nft_raw::nft_msg_type(nft_raw::kNftMsgNewtable), body);
    CHECK(parse_nft_tables(buf).empty()); // name never decoded -> table dropped, not crashed
}

TEST_CASE("nft: family/hook/policy names — known values plus fallback for unrecognised ones",
         "[firewall]") {
    CHECK(nft_family_name(nft_raw::kNfprotoInet) == "inet");
    CHECK(nft_family_name(nft_raw::kNfprotoIpv6) == "ip6");
    CHECK(nft_family_name(99) == "family99");

    CHECK(nft_hook_name(std::optional<std::uint32_t>{4}) == "postrouting");
    CHECK(nft_hook_name(std::optional<std::uint32_t>{7}) == "hook7");
    CHECK(nft_hook_name(std::nullopt) == "unknown");

    CHECK(nft_policy_name(std::optional<std::uint32_t>{nft_raw::kNftPolicyAccept}) == "accept");
    CHECK(nft_policy_name(std::optional<std::uint32_t>{5}) == "policy5");
    CHECK(nft_policy_name(std::nullopt) == "unknown");
}

TEST_CASE("nft: format_nft_chain_rule_row — exact field order/shape try_nftables_rules() emits",
         "[firewall]") {
    NftChainInfo c;
    c.family = nft_raw::kNfprotoInet;
    c.table = "filter";
    c.name = "INPUT";
    c.is_base_chain = true;
    c.hooknum = std::optional<std::uint32_t>{1};
    c.policy = std::optional<std::uint32_t>{nft_raw::kNftPolicyDrop};

    CHECK(format_nft_chain_rule_row(c) == "rule|nftables|inet|filter|INPUT|input|drop");
}

TEST_CASE("nft: format_nft_chain_rule_row sanitizes pipe/newline/CR in table and chain names",
         "[firewall]") {
    NftChainInfo c;
    c.family = nft_raw::kNfprotoIpv4;
    c.table = "fil|ter";
    c.name = "IN\nPUT\r";
    c.is_base_chain = true;
    c.hooknum = std::optional<std::uint32_t>{0};
    c.policy = std::optional<std::uint32_t>{nft_raw::kNftPolicyAccept};

    CHECK(format_nft_chain_rule_row(c) == "rule|nftables|ip|fil_ter|IN_PUT_|prerouting|accept");
}

TEST_CASE("nft: format_nft_rule_handle_row — exact field order/shape, handle present and absent",
         "[firewall]") {
    NftRuleInfo r;
    r.family = nft_raw::kNfprotoIpv6;
    r.table = "filter";
    r.chain = "FORWARD";
    r.handle = std::optional<std::uint64_t>{42};
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|ip6|filter|FORWARD|handle|42");

    r.handle = std::nullopt;
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|ip6|filter|FORWARD|handle|unknown");
}

TEST_CASE("nft: format_nft_rule_handle_row sanitizes pipe/newline/CR in table and chain names",
         "[firewall]") {
    NftRuleInfo r;
    r.family = nft_raw::kNfprotoInet;
    r.table = "na|t";
    r.chain = "chain\r\n";
    r.handle = std::optional<std::uint64_t>{7};
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|inet|na_t|chain__|handle|7");
}

TEST_CASE("nft: split_nlmsgs decodes NLM_F_DUMP_INTR on the terminating DONE message",
         "[firewall]") {
    // nft_dump() (firewall_plugin.cpp) treats a DONE message carrying this
    // flag as a torn/inconsistent dump and fails the round-trip rather than
    // trusting the partial buffer -- that branch does real socket I/O and
    // isn't unit-testable directly (no live kernel in the unit suite), but
    // split_nlmsgs() decoding the flag correctly is the testable half of
    // the same defect: an unread/miscomputed flags field would make that
    // check silently inert regardless of how nft_dump() branches on it.
    std::vector<std::byte> torn;
    push_nlmsg(torn, nft_raw::kNlmsgDone, std::span<const std::byte>{}, nft_raw::kNlmFDumpIntr);
    auto torn_msgs = nft_raw::split_nlmsgs(torn);
    REQUIRE(torn_msgs.size() == 1);
    CHECK(torn_msgs[0].hdr.type == nft_raw::kNlmsgDone);
    CHECK((torn_msgs[0].hdr.flags & nft_raw::kNlmFDumpIntr) != 0);

    std::vector<std::byte> clean;
    push_done(clean);
    auto clean_msgs = nft_raw::split_nlmsgs(clean);
    REQUIRE(clean_msgs.size() == 1);
    CHECK((clean_msgs[0].hdr.flags & nft_raw::kNlmFDumpIntr) == 0);
}

// ── nftables: nft_data_msgs exact-type filter (UP-11 #3461) ────────────────

TEST_CASE("nft: nft_data_msgs -- a mixed buffer only keeps exactly-typed messages", "[firewall]") {
    std::vector<std::byte> buf;
    // NEWCHAIN-typed body (0x0A03) where a GETTABLE reply (0x0A00) is expected.
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaChainName, "INPUT");
        push_nlmsg(buf, nft_raw::nft_msg_type(nft_raw::kNftMsgNewchain), body);
    }
    // A random, unrecognised type.
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaTableName, "filter");
        push_nlmsg(buf, 0x7777, body);
    }
    // A DONE-typed message that happens to carry a body -- still not the
    // expected data-message type.
    push_nlmsg(buf, nft_raw::kNlmsgDone, std::vector<std::byte>(4, std::byte{0}));

    CHECK(parse_nft_tables(buf).empty());
}

TEST_CASE("nft: nft_msg_type packs the nftables subsystem and message subtype", "[firewall]") {
    CHECK(nft_raw::nft_msg_type(nft_raw::kNftMsgGettable) == 0x0A01);
}

// ── nftables: split_nlmsgs/walk_attrs subtraction-form bounds guard ────────

TEST_CASE("nft: split_nlmsgs accepts an exactly-remaining-length message, rejects a +1 overrun",
         "[firewall]") {
    std::vector<std::byte> exact;
    push_nlmsg(exact, nft_raw::kNlmsgDone, std::vector<std::byte>(4, std::byte{0}));
    REQUIRE(exact.size() == 20); // 16-byte header + 4-byte payload, already 4-aligned
    auto exact_msgs = nft_raw::split_nlmsgs(exact);
    REQUIRE(exact_msgs.size() == 1);
    CHECK(exact_msgs[0].payload.size() == 4);

    // One byte short of the declared len -- must stop the walk, not read
    // past the end.
    std::vector<std::byte> overrun(exact.begin(), exact.end() - 1);
    CHECK(nft_raw::split_nlmsgs(overrun).empty());
}

TEST_CASE("nft: nlmsghdr.len shorter than the header itself is rejected safely", "[firewall]") {
    // The #3463 gap named exactly this: the existing "truncated buffer" test
    // used a 10-byte buffer, which fails the OUTER loop guard
    // (off + sizeof(hdr) <= buf.size()) and never reaches the hdr.len <
    // sizeof(NlMsgHdr) branch's own body. This buffer is a full 20 bytes --
    // large enough for the outer guard to pass and for split_nlmsgs to walk
    // straight into the wire content -- but the header's own declared `len`
    // field (8) is smaller than sizeof(NlMsgHdr) (16), so the inner guard
    // must reject it before any subspan/offset arithmetic runs.
    std::vector<std::byte> buf;
    push_u32(buf, 8); // len -- shorter than the 16-byte header, the case under test
    push_u16(buf, nft_raw::kNlmsgDone);
    push_u16(buf, 0); // flags
    push_u32(buf, 0); // seq
    push_u32(buf, 0); // pid
    buf.resize(20, std::byte{0}); // pad out to a full, plausible message size
    REQUIRE(buf.size() == 20);

    CHECK(nft_raw::split_nlmsgs(buf).empty());

    // A well-formed message immediately after the malformed one is not
    // reached either -- the walk stops at the first bad header rather than
    // guessing where the next one might start.
    std::vector<std::byte> then_good = buf;
    push_nlmsg(then_good, nft_raw::kNlmsgDone, std::vector<std::byte>(4, std::byte{0}));
    CHECK(nft_raw::split_nlmsgs(then_good).empty());
}

TEST_CASE("nft: nlattr.len shorter than the attribute header itself is rejected safely",
         "[firewall]") {
    // Same gap, the walk_attrs() half: a buffer large enough to clear the
    // outer loop guard (off + sizeof(hdr) <= data.size()) but whose declared
    // nla_len (2) is smaller than sizeof(NlAttr) (4).
    std::vector<std::byte> buf;
    push_u16(buf, 2); // nla_len -- shorter than the 4-byte attribute header
    push_u16(buf, nft_raw::kNftaTableName);
    buf.resize(8, std::byte{0}); // pad out to a full, plausible attribute-list size

    CHECK(nft_raw::walk_attrs(buf).empty());

    // A well-formed attribute right after the malformed one is not reached
    // either.
    std::vector<std::byte> then_good = buf;
    push_attr_str(then_good, nft_raw::kNftaTableName, "ab");
    CHECK(nft_raw::walk_attrs(then_good).empty());
}

TEST_CASE("nft: walk_attrs accepts an exactly-remaining-length attribute, rejects a +1 overrun",
         "[firewall]") {
    std::vector<std::byte> exact;
    push_attr_str(exact, nft_raw::kNftaTableName, "ab"); // len=7 (4 hdr + 3 value), padded to 8
    exact.resize(7); // trim the pad byte: buffer now exactly hdr.len bytes
    auto exact_attrs = nft_raw::walk_attrs(exact);
    REQUIRE(exact_attrs.size() == 1);
    CHECK(nft_raw::nla_string(exact_attrs[0].value) == "ab");

    // One byte short of the declared len -- must stop the walk, not read
    // past the end.
    std::vector<std::byte> overrun(exact.begin(), exact.end() - 1);
    CHECK(nft_raw::walk_attrs(overrun).empty());
}

// ── nftables: parse_nlmsgerr / parse_nft_done_errno ─────────────────────────

TEST_CASE("nft: parse_nlmsgerr decodes -EPERM, rejects a short payload, rejects error==0",
         "[firewall]") {
    std::vector<std::byte> realistic(24, std::byte{0}); // int error + nlmsghdr + ext-ack padding
    std::int32_t eperm = -EPERM;
    std::memcpy(realistic.data(), &eperm, sizeof(eperm));
    auto r = nft_raw::parse_nlmsgerr(realistic);
    REQUIRE(r.has_value());
    CHECK(*r == -EPERM);

    std::vector<std::byte> short_payload(3, std::byte{0xff});
    CHECK_FALSE(nft_raw::parse_nlmsgerr(short_payload).has_value());

    std::vector<std::byte> ack(4, std::byte{0}); // error == 0: never requested, so anomalous
    CHECK_FALSE(nft_raw::parse_nlmsgerr(ack).has_value());
}

TEST_CASE("nft: parse_nft_done_errno -- bare DONE is nullopt, zeroed is 0, nonzero is the exact "
         "errno",
         "[firewall]") {
    CHECK_FALSE(nft_raw::parse_nft_done_errno({}).has_value());

    std::vector<std::byte> zeroed(4, std::byte{0});
    auto z = nft_raw::parse_nft_done_errno(zeroed);
    REQUIRE(z.has_value());
    CHECK(*z == 0);

    std::vector<std::byte> errored(4, std::byte{0});
    std::int32_t eintr = -EINTR;
    std::memcpy(errored.data(), &eintr, sizeof(eintr));
    auto e = nft_raw::parse_nft_done_errno(errored);
    REQUIRE(e.has_value());
    CHECK(*e == -EINTR);
}

// ── nftables: state decision layer (#3463-2, review R8) ────────────────────

TEST_CASE("nft: nft_decide_state -- unknown whenever either dump is untrusted, else per "
         "nft_has_content",
         "[firewall]") {
    NftChainInfo active_chain;
    active_chain.is_base_chain = true;
    active_chain.policy = nft_raw::kNftPolicyDrop;
    std::vector<NftChainInfo> chains{active_chain};
    std::vector<NftRuleInfo> rules;

    CHECK(nft_decide_state(false, true, chains, rules) == NftVerdict::unknown);
    CHECK(nft_decide_state(true, false, chains, rules) == NftVerdict::unknown);
    CHECK(nft_decide_state(false, false, chains, rules) == NftVerdict::unknown);
    CHECK(nft_decide_state(true, true, chains, rules) == NftVerdict::active);
    CHECK(nft_decide_state(true, true, std::vector<NftChainInfo>{}, std::vector<NftRuleInfo>{}) ==
          NftVerdict::inactive);
}

TEST_CASE("nft: nft_fallthrough_clamp -- full truth table", "[firewall]") {
    CHECK(nft_fallthrough_clamp(true, FwState::disabled) == FwState::unknown);
    CHECK(nft_fallthrough_clamp(true, FwState::enabled) == FwState::enabled);
    CHECK(nft_fallthrough_clamp(true, FwState::unknown) == FwState::unknown);
    CHECK(nft_fallthrough_clamp(false, FwState::disabled) == FwState::disabled);
    CHECK(nft_fallthrough_clamp(false, FwState::enabled) == FwState::enabled);
    CHECK(nft_fallthrough_clamp(false, FwState::unknown) == FwState::unknown);
}

// gate_state_on_completeness() is the composition try_ufw_state()/
// try_iptables_state() actually call -- previously an inline ternary at
// each call site with only its two ingredients (subprocess_complete(),
// nft_fallthrough_clamp()) independently tested, never the gate itself
// (governance gate3 quality-engineer finding, r2: this is the security-
// guardian-HIGH completeness-gating fix from r1, and it had no direct
// test).
TEST_CASE("nft: gate_state_on_completeness -- incomplete always wins, regardless of "
         "the parsed state or tables_seen",
         "[firewall]") {
    CHECK(gate_state_on_completeness(false, false, FwState::enabled) == FwState::unknown);
    CHECK(gate_state_on_completeness(false, false, FwState::disabled) == FwState::unknown);
    CHECK(gate_state_on_completeness(false, true, FwState::enabled) == FwState::unknown);
    CHECK(gate_state_on_completeness(false, true, FwState::disabled) == FwState::unknown);
}

TEST_CASE("nft: gate_state_on_completeness -- complete passes through nft_fallthrough_clamp "
         "unchanged",
         "[firewall]") {
    // complete + tables_seen=false: parsed state stands, matching
    // nft_fallthrough_clamp(false, x) == x.
    CHECK(gate_state_on_completeness(true, false, FwState::enabled) == FwState::enabled);
    CHECK(gate_state_on_completeness(true, false, FwState::disabled) == FwState::disabled);
    // complete + tables_seen=true + parsed disabled: clamps to unknown, the
    // exact case this whole mechanism exists to protect (nftables already
    // reported tables present -- a ufw/iptables "disabled" read here would
    // contradict that).
    CHECK(gate_state_on_completeness(true, true, FwState::disabled) == FwState::unknown);
    // complete + tables_seen=true + parsed enabled: enabled is never
    // downgraded.
    CHECK(gate_state_on_completeness(true, true, FwState::enabled) == FwState::enabled);
}

// ── nftables: dump-outcome diagnostics (#3462-6) ────────────────────────────

TEST_CASE("nft: nft_dump_reason maps every status to its exact token", "[firewall]") {
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::ok, 0}) == "ok");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::timeout, 0}) == "timeout");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::kernel_error, -EPERM}) == "eperm");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::kernel_error, -EINTR}) ==
          "errno:" + std::to_string(EINTR));
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::foreign_flood, 0}) == "foreign_flood");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::truncated, 0}) == "truncated");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::oversized, 0}) == "oversized");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::io_error, 0}) == "io_error");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::torn, 0}) == "torn");
}

TEST_CASE("nft: nft_dump_reason distinguishes an undecoded kernel_error from a genuine errno of "
         "zero",
         "[firewall]") {
    // kernel_errno==0 on a kernel_error status means the NLMSG_ERROR payload
    // itself couldn't be decoded (too short, or the error==0 ACK-anomaly
    // parse_nlmsgerr treats as nullopt) -- it must never format as
    // "errno:0", which would read as a specifically decoded errno that
    // never happened (code-review finding K1).
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::kernel_error, 0}) == "errno:undecoded");
    // A genuinely nonzero errno still formats normally, unaffected.
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::kernel_error, -EINVAL}) ==
          "errno:" + std::to_string(EINVAL));
}

TEST_CASE("nft: nft_diag_row and nft_fallthrough_row produce the documented row shapes",
         "[firewall]") {
    NftDumpResult timed_out{NftDumpStatus::timeout, 0};
    CHECK(nft_diag_row("chain", timed_out) == "error|nftables:chain:timeout");
    CHECK(nft_fallthrough_row("table", timed_out) == "fallthrough|nftables:table:timeout");

    NftDumpResult eperm{NftDumpStatus::kernel_error, -EPERM};
    CHECK(nft_diag_row("rule", eperm) == "error|nftables:rule:eperm");
}

// ── sanitize_field (hoisted, #3465) ─────────────────────────────────────────

TEST_CASE("nft: sanitize_field strips pipe/newline/CR", "[firewall]") {
    CHECK(sanitize_field("a|b\nc\rd") == "a_b_c_d");
    CHECK(sanitize_field("clean") == "clean");
}

// ── subprocess_complete (hoisted from the Linux-only shell) ─────────────────

TEST_CASE("nft: subprocess_complete requires every one of tool_ran/exit_code==0/"
         "!timed_out/!output_truncated",
         "[firewall]") {
    yuzu::agent::SubprocessResult clean;
    clean.tool_ran = true;
    clean.exit_code = 0;
    clean.timed_out = false;
    clean.output_truncated = false;
    CHECK(subprocess_complete(clean));

    auto broken = [&](auto mutate) {
        yuzu::agent::SubprocessResult r = clean;
        mutate(r);
        return subprocess_complete(r);
    };
    CHECK_FALSE(broken([](auto& r) { r.tool_ran = false; }));
    CHECK_FALSE(broken([](auto& r) { r.exit_code = 1; }));
    CHECK_FALSE(broken([](auto& r) { r.timed_out = true; }));
    CHECK_FALSE(broken([](auto& r) { r.output_truncated = true; }));
}

// ── Failure tokens and the macOS rows (#6611, #4891, #4375) ─────────────────

namespace {

yuzu::agent::SubprocessResult done(std::string out) {
    yuzu::agent::SubprocessResult r;
    r.tool_ran = true;
    r.exit_code = 0;
    r.output = std::move(out);
    return r;
}

yuzu::agent::SubprocessResult not_run() {
    return {}; // tool_ran == false: the default result
}

yuzu::agent::SubprocessResult timed_out(std::string partial = "") {
    auto r = done(std::move(partial));
    r.exit_code = -1;
    r.timed_out = true;
    return r;
}

yuzu::agent::SubprocessResult truncated(std::string partial) {
    auto r = done(std::move(partial));
    r.output_truncated = true;
    return r;
}

yuzu::agent::SubprocessResult exited(int code, std::string out = "") {
    auto r = done(std::move(out));
    r.exit_code = code;
    return r;
}

bool has_row(const std::vector<std::string>& rows, std::string_view row) {
    return std::find(rows.begin(), rows.end(), row) != rows.end();
}

std::size_t index_of(const std::vector<std::string>& rows, std::string_view row) {
    const auto it = std::find(rows.begin(), rows.end(), row);
    return static_cast<std::size_t>(it - rows.begin());
}

bool any_row_starts_with(const std::vector<std::string>& rows, std::string_view prefix) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
}

constexpr std::string_view kAlfOn = "Firewall is enabled. (State = 1)";
constexpr std::string_view kPfInfoOn = "Status: Enabled for 0 days 00:00:15           Debug: Urgent";

} // namespace

TEST_CASE("subprocess_failure_token names the cause, timeout before truncated before exit",
          "[firewall]") {
    CHECK(subprocess_failure_token(done("ok")).empty());
    CHECK(subprocess_failure_token(not_run()) == "not_run");
    CHECK(subprocess_failure_token(timed_out("x")) == "timeout");
    CHECK(subprocess_failure_token(truncated("x")) == "truncated");
    CHECK(subprocess_failure_token(exited(1)) == "exit:1");
    CHECK(subprocess_failure_token(exited(127)) == "exit:127");
    CHECK(subprocess_failure_token(exited(-1)) == "exit:-1");
    // precedence: a timed-out, clipped, non-zero run is a timeout; a clipped non-zero run is clipped
    auto all = exited(2);
    all.timed_out = true;
    all.output_truncated = true;
    CHECK(subprocess_failure_token(all) == "timeout");
    auto clipped = exited(2);
    clipped.output_truncated = true;
    CHECK(subprocess_failure_token(clipped) == "truncated");
    // and a never-started tool wins over everything the empty result also says
    auto never = not_run();
    never.timed_out = true;
    CHECK(subprocess_failure_token(never) == "not_run");
}

TEST_CASE("subprocess_failure_token is empty exactly when subprocess_complete holds", "[firewall]") {
    for (const bool ran : {false, true})
        for (const int code : {-1, 0, 1})
            for (const bool to : {false, true})
                for (const bool clip : {false, true}) {
                    yuzu::agent::SubprocessResult r;
                    r.tool_ran = ran;
                    r.exit_code = code;
                    r.timed_out = to;
                    r.output_truncated = clip;
                    INFO("ran=" << ran << " code=" << code << " timed_out=" << to << " clipped=" << clip);
                    CHECK(subprocess_failure_token(r).empty() == subprocess_complete(r));
                }
}

TEST_CASE("macos_state_rows: a complete read gives today's rows and no error row (golden)",
          "[firewall]") {
    const auto rows = macos_state_rows(
        done(std::string{kAlfOn}), done(std::string{kPfInfoOn}),
        done("com.apple\n  com.apple/200.AirDrop\n"),
        done("scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"));
    const std::vector<std::string> expected{"backend|appfirewall", "state|enabled",
                                            "pf|enabled",          "anchor|com.apple",
                                            "anchor|com.apple/200.AirDrop", "ruleset|2"};
    CHECK(rows == expected);
    CHECK_FALSE(any_row_starts_with(rows, "error|"));

    // block-all adds the mode row straight after the state row
    const auto block = macos_state_rows(done("Firewall is enabled. (State = 2)"),
                                        done("Status: Disabled for 0 days"), done(""), done(""));
    const std::vector<std::string> expected_block{"backend|appfirewall", "state|enabled",
                                                  "mode|block_all",      "pf|disabled",
                                                  "ruleset|0"};
    CHECK(block == expected_block);
}

TEST_CASE("#6611 macos_state_rows: an incomplete globalstate read is state|unknown plus its error row",
          "[firewall]") {
    struct Case {
        yuzu::agent::SubprocessResult res;
        std::string token;
    };
    // the partial text would parse to `enabled` (and block_all): none of it may show
    for (const auto& c : {Case{not_run(), "not_run"}, Case{timed_out(std::string{kAlfOn}), "timeout"},
                          Case{truncated("Firewall is enabled. (State = 2)"), "truncated"},
                          Case{exited(1, std::string{kAlfOn}), "exit:1"}}) {
        INFO("token " << c.token);
        const auto rows = macos_state_rows(c.res, done(std::string{kPfInfoOn}), done(""), done(""));
        REQUIRE(rows.size() >= 3);
        CHECK(rows[0] == "backend|appfirewall");
        CHECK(rows[1] == "state|unknown");
        CHECK(rows[2] == "error|appfirewall:globalstate:" + c.token); // right after the row it explains
        CHECK_FALSE(has_row(rows, "mode|block_all"));
        CHECK_FALSE(has_row(rows, "state|enabled"));
        CHECK(has_row(rows, "pf|enabled")); // the other reads are unaffected
    }
}

TEST_CASE("#6611/#4891 macos_state_rows: an incomplete pfctl read is pf|unknown plus its error row",
          "[firewall]") {
    struct Case {
        yuzu::agent::SubprocessResult res;
        std::string token;
    };
    for (const auto& c : {Case{not_run(), "not_run"}, Case{timed_out(std::string{kPfInfoOn}), "timeout"},
                          Case{truncated(std::string{kPfInfoOn}), "truncated"},
                          // a clean unprivileged-shaped failure: pfctl cannot open /dev/pf
                          Case{exited(1), "exit:1"}}) {
        INFO("token " << c.token);
        const auto rows = macos_state_rows(done(std::string{kAlfOn}), c.res, done(""), done(""));
        const auto at = index_of(rows, "pf|unknown");
        REQUIRE(at < rows.size());
        REQUIRE(at + 1 < rows.size());
        CHECK(rows[at + 1] == "error|pf:info:" + c.token);
        CHECK_FALSE(has_row(rows, "pf|enabled"));
    }
}

TEST_CASE("#6611 macos_state_rows: the anchor and rule reads are gated and explained",
          "[firewall]") {
    // an unprivileged agent: every pfctl read exits 1
    const auto rows = macos_state_rows(done(std::string{kAlfOn}), exited(1), exited(1), exited(1));
    const std::vector<std::string> expected{"backend|appfirewall",     "state|enabled",
                                            "pf|unknown",              "error|pf:info:exit:1",
                                            "error|pf:anchors:exit:1", "ruleset|unknown",
                                            "error|pf:rules:exit:1"};
    CHECK(rows == expected);

    // a clipped rule read never publishes the partial count, and the anchors still read
    const auto clipped = macos_state_rows(done(std::string{kAlfOn}), done(std::string{kPfInfoOn}),
                                          done("com.apple\n"), truncated("pass all\npass all\n"));
    CHECK(has_row(clipped, "anchor|com.apple"));
    CHECK(has_row(clipped, "ruleset|unknown"));
    CHECK(has_row(clipped, "error|pf:rules:truncated"));
    CHECK_FALSE(has_row(clipped, "ruleset|2"));
    CHECK_FALSE(any_row_starts_with(clipped, "error|pf:anchors"));
}

TEST_CASE("macos_state_rows: pf|unknown comes with the pf info error row exactly when the read "
          "did not complete, every combination",
          "[firewall]") {
    for (const bool info_ok : {false, true})
        for (const bool rules_ok : {false, true}) {
            const auto rows =
                macos_state_rows(done(std::string{kAlfOn}),
                                 info_ok ? done(std::string{kPfInfoOn}) : exited(1), done(""),
                                 rules_ok ? done("pass all\n") : exited(1));
            CHECK(has_row(rows, "pf|unknown") == !info_ok);
            CHECK(any_row_starts_with(rows, "error|pf:info:") == !info_ok);
            CHECK(has_row(rows, "ruleset|unknown") == !rules_ok);
            CHECK(any_row_starts_with(rows, "error|pf:rules:") == !rules_ok);
        }
    // a read that completed but said neither Enabled nor Disabled is `pf|unknown` ALONE: there is
    // no error row, because nothing failed to run (the README says so)
    const auto garbled = macos_state_rows(done(std::string{kAlfOn}), done("Status: ???\n"), done(""),
                                          done("pass all\n"));
    CHECK(has_row(garbled, "pf|unknown"));
    CHECK_FALSE(any_row_starts_with(garbled, "error|pf:info:"));
}

TEST_CASE("#4375 macos_rules_rows: pf rule lines are sanitised at the rule site", "[firewall]") {
    // a pipe or a carriage return in an echoed rule line must not make a second field or row
    const auto rows = macos_rules_rows(
        done(""), done("block drop in all label \"a|b\"\npass out proto tcp from any to any\rport 22\n"),
        done(""));
    CHECK(has_row(rows, "rule|block drop in all label \"a_b\""));
    CHECK(has_row(rows, "rule|pass out proto tcp from any to any_port 22"));
    for (const auto& r : rows)
        if (r.rfind("rule|", 0) == 0) {
            CHECK(r.find('\r') == std::string::npos);
            CHECK(std::count(r.begin(), r.end(), '|') == 1); // `rule` and its one field
        }
    CHECK(has_row(rows, "ruleset|2"));
    CHECK_FALSE(any_row_starts_with(rows, "error|"));
}

TEST_CASE("#4375 macos_rules_rows: an incomplete app or anchor read gives no rows and its error row",
          "[firewall]") {
    const auto rows = macos_rules_rows(exited(1), done("pass all\n"), timed_out("com.apple\n"));
    CHECK_FALSE(any_row_starts_with(rows, "app|"));
    CHECK_FALSE(any_row_starts_with(rows, "anchor|"));
    CHECK(has_row(rows, "error|appfirewall:listapps:exit:1"));
    CHECK(has_row(rows, "error|pf:anchors:timeout"));
    // the rule read was clean: its lines and count stand
    CHECK(has_row(rows, "rule|pass all"));
    CHECK(has_row(rows, "ruleset|1"));
    CHECK_FALSE(any_row_starts_with(rows, "error|pf:rules"));

    // a complete listapps read still produces its app rows
    const auto ok = macos_rules_rows(done(std::string{kAlfListappsCapture}), done(""), done(""));
    CHECK(has_row(ok, "app|/usr/libexec/remoted|allow"));
    CHECK(has_row(ok, "ruleset|0"));
}

TEST_CASE("#4375 macos_rules_rows: a clipped rule read publishes no rule line and no count",
          "[firewall]") {
    for (const auto& res : {truncated("pass all\n"), timed_out("pass all\n"), exited(1, "pass all\n"),
                            not_run()}) {
        const auto rows = macos_rules_rows(done(""), res, done(""));
        CHECK_FALSE(any_row_starts_with(rows, "rule|"));
        const auto at = index_of(rows, "ruleset|unknown");
        REQUIRE(at + 1 < rows.size());
        CHECK(rows[at + 1].rfind("error|pf:rules:", 0) == 0); // right after the row it explains
    }
}

TEST_CASE("macos_rules_rows: ruleset|unknown if and only if the pf rules error row", "[firewall]") {
    for (const bool rules_ok : {false, true}) {
        const auto rows = macos_rules_rows(done(""), rules_ok ? done("pass all\n") : exited(1), done(""));
        CHECK(has_row(rows, "ruleset|unknown") == !rules_ok);
        CHECK(any_row_starts_with(rows, "error|pf:rules:") == !rules_ok);
    }
}

// ── Windows rows (#4375): pure, so this host pins what only Windows compiles ─

TEST_CASE("#4375 win_rule_count_row: the count, or the HRESULT of the step that failed", "[firewall]") {
    CHECK(win_rule_count_row(true, 0, true, 0, 532) == "ruleset|532");
    CHECK(win_rule_count_row(true, 0, true, 0, 0) == "ruleset|0");
    // S_FALSE from get_Count is not a count
    CHECK(win_rule_count_row(true, 0, false, 1, 0) == "error|rules_count:0x00000001");
    // get_Rules failed (or returned nothing): the HRESULT of THAT step, not the count's
    CHECK(win_rule_count_row(false, 0x80070005u, true, 0, 5) == "error|rules_count:0x80070005");
    CHECK(win_rule_count_row(false, 1, false, 0x80004005u, 0) == "error|rules_count:0x00000001");
}

namespace {

constexpr std::uint32_t kAccessDenied = 0x80070005u; // E_ACCESSDENIED
constexpr std::uint32_t kSFalse = 1;                 // passes SUCCEEDED(), means "not found"

/// A rule whose five reads all returned S_OK: the DNS rule of #4375's capture.
WinRuleRead dns_rule() {
    return WinRuleRead{.name = "Core Networking - DNS (UDP-Out)",
                       .enabled = true,
                       .dir = 2,
                       .action = 1,
                       .profiles = 2147483647};
}

} // namespace

TEST_CASE("win_rule_row: every read S_OK is the row byte for byte, whatever the field values",
          "[firewall]") {
    CHECK(win_rule_row(dns_rule()) == "rule|Core Networking - DNS (UDP-Out)|enabled|out|allow|2147483647");
    CHECK(win_rule_row(WinRuleRead{.name = "x", .enabled = false, .dir = 1, .action = 0, .profiles = 7}) ==
          "rule|x|disabled|in|block|7");
    // the name is echoed, so it is sanitised; an S_OK empty name is an empty name
    CHECK(win_rule_row(WinRuleRead{.name = "a|b\r\nc", .enabled = true, .dir = 0, .action = 0, .profiles = 0}) ==
          "rule|a_b__c|enabled|unknown|block|0");
    CHECK(win_rule_row(WinRuleRead{.name = "", .enabled = true, .dir = 1, .action = 1, .profiles = 1}) ==
          "rule||enabled|in|allow|1");
    // a value the plugin does not know is unknown even when its read succeeded
    CHECK(win_rule_row(WinRuleRead{.name = "n", .enabled = true, .dir = 3, .action = 2, .profiles = 0}) ==
          "rule|n|enabled|unknown|unknown|0");
    CHECK(win_rule_row(WinRuleRead{.name = "n", .enabled = true, .dir = -1, .action = -1, .profiles = 0}) ==
          "rule|n|enabled|unknown|unknown|0");
}

TEST_CASE("win_rule_row: a property that failed reads unknown in that field only, never a default",
          "[firewall]") {
    // The out-parameters keep what the caller initialised them to (empty name, disabled, 0, 0, 0)
    // when a read fails. None of that may reach the row: `disabled` and `block` and profiles 0 are
    // all plausible, false-safe words.
    auto failed = [](auto set) {
        auto r = dns_rule();
        set(r);
        r.name = {};
        r.enabled = false;
        r.dir = 0;
        r.action = 0;
        r.profiles = 0;
        return win_rule_row(r);
    };
    CHECK(failed([](WinRuleRead& r) { r.name_hr = kAccessDenied; }) ==
          "rule|unknown|disabled|unknown|block|0");
    CHECK(failed([](WinRuleRead& r) { r.enabled_hr = kAccessDenied; }) == "rule||unknown|unknown|block|0");
    CHECK(failed([](WinRuleRead& r) { r.dir_hr = kAccessDenied; }) == "rule||disabled|unknown|block|0");
    CHECK(failed([](WinRuleRead& r) { r.action_hr = kAccessDenied; }) == "rule||disabled|unknown|unknown|0");
    CHECK(failed([](WinRuleRead& r) { r.profiles_hr = kAccessDenied; }) ==
          "rule||disabled|unknown|block|unknown");
    // with the other four intact and carrying real values, only the failed field changes
    auto only = dns_rule();
    only.enabled_hr = kAccessDenied;
    CHECK(win_rule_row(only) == "rule|Core Networking - DNS (UDP-Out)|unknown|out|allow|2147483647");
    only = dns_rule();
    only.profiles_hr = kAccessDenied;
    CHECK(win_rule_row(only) == "rule|Core Networking - DNS (UDP-Out)|enabled|out|allow|unknown");
    only = dns_rule();
    only.name_hr = kAccessDenied;
    CHECK(win_rule_row(only) == "rule|unknown|enabled|out|allow|2147483647");
}

TEST_CASE("win_rule_row: S_FALSE is not success, on every property (an action is never `block`)",
          "[firewall]") {
    auto r = dns_rule();
    r.name_hr = r.enabled_hr = r.dir_hr = r.action_hr = r.profiles_hr = kSFalse;
    r.action = 0; // what a read that left the out-parameter alone holds: NET_FW_ACTION_BLOCK
    CHECK(win_rule_row(r) == "rule|unknown|unknown|unknown|unknown|unknown");
    r = dns_rule();
    r.action_hr = kSFalse;
    r.action = 0;
    CHECK(win_rule_row(r) == "rule|Core Networking - DNS (UDP-Out)|enabled|out|unknown|2147483647");
    r = dns_rule();
    r.dir_hr = kSFalse;
    CHECK(win_rule_row(r) == "rule|Core Networking - DNS (UDP-Out)|enabled|unknown|allow|2147483647");
}

TEST_CASE("win_rule_unobtained and win_rule_first_failure: the row of a rule with no object, and the "
          "first failed read",
          "[firewall]") {
    // every property failed: the all-unknown row, whatever the other members hold
    const auto none = win_rule_unobtained(0x80020005u); // DISP_E_TYPEMISMATCH
    CHECK(win_rule_row(none) == "rule|unknown|unknown|unknown|unknown|unknown");
    CHECK(win_rule_first_failure(none) == 0x80020005u);
    // all five read: no failure
    CHECK(win_rule_first_failure(dns_rule()) == 0);
    // the first failure in field order wins (name, enabled, direction, action, profiles)
    auto r = dns_rule();
    r.profiles_hr = 3;
    r.action_hr = 2;
    CHECK(win_rule_first_failure(r) == 2);
    r.dir_hr = kAccessDenied;
    CHECK(win_rule_first_failure(r) == kAccessDenied);
    r.enabled_hr = 4;
    CHECK(win_rule_first_failure(r) == 4);
    r.name_hr = kSFalse;
    CHECK(win_rule_first_failure(r) == kSFalse);
}

TEST_CASE("#4375 win_rules_trailer_rows: count, truncation, a failed enumeration and rule-property "
          "failures",
          "[firewall]") {
    using Rows = std::vector<std::string>;
    CHECK(win_rules_trailer_rows(37, false, false, 0, 0, 0) == Rows{"ruleset|37"});
    // exactly 100 rules, none cut off
    CHECK(win_rules_trailer_rows(100, false, false, 0, 0, 0) == Rows{"ruleset|100"});
    // a 101st rule exists: the cap row follows the count
    CHECK(win_rules_trailer_rows(100, true, false, 0, 0, 0) == Rows{"ruleset|100", "truncated|true"});
    // a partial tally is never a count
    CHECK(win_rules_trailer_rows(42, false, true, 0x80004005u, 0, 0) ==
          Rows{"error|enum_next:0x80004005", "ruleset|unknown"});
    CHECK(win_rules_trailer_rows(100, true, true, 0x8007000eu, 0, 0) ==
          Rows{"error|enum_next:0x8007000e", "ruleset|unknown"});

    // rules with an unreadable property: the row is first, names how many rules and the first
    // HRESULT, and the count is unchanged (those rows were written and count)
    CHECK(win_rules_trailer_rows(37, false, false, 0, 2, kAccessDenied) ==
          Rows{"error|rule_property:2:0x80070005", "ruleset|37"});
    CHECK(win_rules_trailer_rows(100, true, false, 0, 1, kSFalse) ==
          Rows{"error|rule_property:1:0x00000001", "ruleset|100", "truncated|true"});
    // combined with a failed enumeration: both rows, the property row first
    CHECK(win_rules_trailer_rows(42, false, true, 0x80004005u, 3, kAccessDenied) ==
          Rows{"error|rule_property:3:0x80070005", "error|enum_next:0x80004005", "ruleset|unknown"});
}

// ── nftables generation, re-run and failure list (#4400, #4401, #4402) ──────

namespace {

std::vector<std::byte> nfgenmsg_gen(std::uint8_t family, std::uint16_t res_id) {
    // res_id is a __be16 on the wire: high byte first
    return {static_cast<std::byte>(family), std::byte{0}, static_cast<std::byte>(res_id >> 8),
            static_cast<std::byte>(res_id & 0xff)};
}

constexpr std::uint16_t kNewTable = (nft_raw::kNfnlSubsysNftables << 8) | nft_raw::kNftMsgNewtable;
constexpr std::uint16_t kNewChain = (nft_raw::kNfnlSubsysNftables << 8) | nft_raw::kNftMsgNewchain;
constexpr std::uint16_t kNewRule = (nft_raw::kNfnlSubsysNftables << 8) | nft_raw::kNftMsgNewrule;

/// A dump of `n` table messages whose nfgenmsg all carry `gen`, then NLMSG_DONE.
std::vector<std::byte> table_dump(std::uint16_t gen, int n = 1) {
    std::vector<std::byte> buf;
    for (int i = 0; i < n; ++i) {
        auto body = nfgenmsg_gen(nft_raw::kNfprotoInet, gen);
        push_attr_str(body, nft_raw::kNftaTableName, "t" + std::to_string(i));
        push_nlmsg(buf, kNewTable, body);
    }
    push_done(buf);
    return buf;
}

} // namespace

TEST_CASE("#4400 nft_dump_generation reads the big-endian res_id of the first typed message",
          "[firewall]") {
    // 0x0102 on the wire is 01 02: a host-order read would say 0x0201
    CHECK(nft_dump_generation(table_dump(0x0102), kNewTable) == std::optional<std::uint16_t>{0x0102});
    CHECK(nft_dump_generation(table_dump(0), kNewTable) == std::optional<std::uint16_t>{0});
    CHECK(nft_dump_generation(table_dump(65535, 3), kNewTable) == std::optional<std::uint16_t>{65535});
    CHECK(nft_dump_generation(table_dump(7), kNewTable) != nft_dump_generation(table_dump(8), kNewTable));

    // a message of another type is not this dump's data
    CHECK_FALSE(nft_dump_generation(table_dump(5), kNewChain).has_value());
    // a stray first message of the wrong type is skipped, the typed one is read
    std::vector<std::byte> mixed;
    {
        auto stray = nfgenmsg_gen(nft_raw::kNfprotoInet, 9);
        push_nlmsg(mixed, kNewRule, stray);
        auto data = nfgenmsg_gen(nft_raw::kNfprotoInet, 11);
        push_attr_str(data, nft_raw::kNftaTableName, "t");
        push_nlmsg(mixed, kNewTable, data);
        push_done(mixed);
    }
    CHECK(nft_dump_generation(mixed, kNewTable) == std::optional<std::uint16_t>{11});
}

TEST_CASE("#4400 nft_dump_generation: an empty dump has no generation, which is not zero",
          "[firewall]") {
    // an empty ruleset dumps NLMSG_DONE and nothing else
    std::vector<std::byte> empty_ruleset;
    push_done(empty_ruleset);
    CHECK_FALSE(nft_dump_generation(empty_ruleset, kNewTable).has_value());
    CHECK_FALSE(nft_dump_generation(std::vector<std::byte>{}, kNewTable).has_value());
    // a typed message too short to carry an nfgenmsg is skipped, not read past
    std::vector<std::byte> shortmsg;
    push_nlmsg(shortmsg, kNewTable, std::vector<std::byte>{std::byte{2}, std::byte{0}});
    CHECK_FALSE(nft_dump_generation(shortmsg, kNewTable).has_value());
}

TEST_CASE("#4400 nft_generations_consistent: equal, one absent, two differ, empty", "[firewall]") {
    using G = std::optional<std::uint16_t>;
    CHECK(nft_generations_consistent(G{4}, G{4}, G{4}));
    CHECK(nft_generations_consistent(G{0}, G{0}, G{0}));
    // an absent value takes no part
    CHECK(nft_generations_consistent(G{4}, std::nullopt, G{4}));
    CHECK(nft_generations_consistent(std::nullopt, G{9}, std::nullopt));
    CHECK_FALSE(nft_generations_consistent(G{4}, std::nullopt, G{5}));
    // a mismatch in any position
    CHECK_FALSE(nft_generations_consistent(G{4}, G{4}, G{5}));
    CHECK_FALSE(nft_generations_consistent(G{4}, G{5}, G{4}));
    CHECK_FALSE(nft_generations_consistent(G{5}, G{4}, G{4}));
    // an empty ruleset (nothing present at all) is consistent with itself and with anything
    CHECK(nft_generations_consistent(std::nullopt, std::nullopt, std::nullopt));
    // zero is a value, not an absence
    CHECK_FALSE(nft_generations_consistent(G{0}, G{1}, std::nullopt));
}

TEST_CASE("#4400 nft_rerun_worthwhile: churn-only, one pass done, time left", "[firewall]") {
    using std::chrono::milliseconds;
    CHECK(nft_rerun_worthwhile(true, 1, milliseconds{3000}));
    CHECK(nft_rerun_worthwhile(true, 1, kNftRerunFloor)); // exactly the floor is enough
    CHECK_FALSE(nft_rerun_worthwhile(true, 1, kNftRerunFloor - milliseconds{1}));
    CHECK_FALSE(nft_rerun_worthwhile(true, 1, milliseconds{0}));
    // a second pass is the last
    CHECK_FALSE(nft_rerun_worthwhile(true, kNftMaxAttempts, milliseconds{4000}));
    CHECK_FALSE(nft_rerun_worthwhile(true, 3, milliseconds{4000}));
    // a timeout, an error or any other failure gets no second look
    CHECK_FALSE(nft_rerun_worthwhile(false, 1, milliseconds{4000}));
}

TEST_CASE("#4400 nft_churn_only: torn and a moved generation are churn, nothing else is",
          "[firewall]") {
    CHECK(nft_is_churn(NftDumpStatus::torn));
    CHECK(nft_is_churn(NftDumpStatus::generation_changed));
    for (const auto s : {NftDumpStatus::ok, NftDumpStatus::timeout, NftDumpStatus::kernel_error,
                         NftDumpStatus::foreign_flood, NftDumpStatus::truncated,
                         NftDumpStatus::oversized, NftDumpStatus::io_error})
        CHECK_FALSE(nft_is_churn(s));

    const NftDumpResult torn{NftDumpStatus::torn, 0};
    const NftDumpResult slow{NftDumpStatus::timeout, 0};
    const std::vector<NftFailedDump> churn{{"chain", torn}, {"generation", {NftDumpStatus::generation_changed, 0}}};
    const std::vector<NftFailedDump> mixed{{"chain", torn}, {"rule", slow}};
    CHECK(nft_churn_only(churn));
    CHECK_FALSE(nft_churn_only(mixed));
    CHECK_FALSE(nft_churn_only(std::vector<NftFailedDump>{})); // nothing failed: nothing to re-run
}

TEST_CASE("#4401 nft_failed_dumps returns every failure in order, the generation only alone",
          "[firewall]") {
    const NftDumpResult ok{NftDumpStatus::ok, 0};
    const NftDumpResult timeout{NftDumpStatus::timeout, 0};
    const NftDumpResult big{NftDumpStatus::oversized, 0};

    // chain timeout plus rule oversized: both, chain first
    const auto both = nft_failed_dumps(timeout, big, true);
    REQUIRE(both.size() == 2);
    CHECK(both[0].dump == "chain");
    CHECK(both[0].result.status == NftDumpStatus::timeout);
    CHECK(both[1].dump == "rule");
    CHECK(both[1].result.status == NftDumpStatus::oversized);

    // one failure is one entry
    const auto chain_only = nft_failed_dumps(timeout, ok, true);
    REQUIRE(chain_only.size() == 1);
    CHECK(chain_only[0].dump == "chain");
    const auto rule_only = nft_failed_dumps(ok, big, true);
    REQUIRE(rule_only.size() == 1);
    CHECK(rule_only[0].dump == "rule");

    // a generation mismatch between two clean dumps is its own failure
    const auto moved = nft_failed_dumps(ok, ok, false);
    REQUIRE(moved.size() == 1);
    CHECK(moved[0].dump == "generation");
    CHECK(moved[0].result.status == NftDumpStatus::generation_changed);
    CHECK(nft_fallthrough_row(moved[0].dump, moved[0].result) ==
          "fallthrough|nftables:generation:changed");

    // next to a failed dump the generation adds nothing: a failed dump has none to compare
    CHECK(nft_failed_dumps(timeout, ok, false).size() == 1);

    // a clean, consistent pass has no failure at all
    CHECK(nft_failed_dumps(ok, ok, true).empty());
}

TEST_CASE("#4402 nft_open_diag_rows: each actionable condition once, in first-seen order",
          "[firewall]") {
    using Rows = std::vector<std::string>;
    CHECK(nft_open_diag_rows(std::vector<int>{EMFILE, EMFILE, EMFILE}) == Rows{"error|fd_exhausted"});
    CHECK(nft_open_diag_rows(std::vector<int>{ENFILE, EMFILE}) == Rows{"error|fd_exhausted"});
    CHECK(nft_open_diag_rows(std::vector<int>{EMFILE, EPERM}) ==
          Rows{"error|fd_exhausted", "error|nftables:socket:eperm"});
    CHECK(nft_open_diag_rows(std::vector<int>{EACCES, EMFILE, EPERM}) ==
          Rows{"error|nftables:socket:eperm", "error|fd_exhausted"});
    // a kernel with no NETLINK_NETFILTER, or an unclassified errno, is silent
    CHECK(nft_open_diag_rows(std::vector<int>{EPROTONOSUPPORT, EAFNOSUPPORT, EINVAL}).empty());
    CHECK(nft_open_diag_rows(std::vector<int>{}).empty());
    // the classification the rows rest on
    CHECK(classify_open_errno(EMFILE) == OpenNftErrClass::fd_exhausted);
    CHECK(classify_open_errno(EPERM) == OpenNftErrClass::permission_denied);
    CHECK(classify_open_errno(EPROTONOSUPPORT) == OpenNftErrClass::unsupported);
    CHECK(classify_open_errno(EINVAL) == OpenNftErrClass::other);
}

TEST_CASE("#4402 nft_churn_reason: torn stays torn below the threshold, torn_persistent from 3",
          "[firewall]") {
    CHECK(kNftChurnThreshold == 3u);
    CHECK(nft_churn_reason("torn", 0) == "torn");
    CHECK(nft_churn_reason("torn", 1) == "torn");
    CHECK(nft_churn_reason("torn", 2) == "torn");
    CHECK(nft_churn_reason("torn", 3) == "torn_persistent");
    CHECK(nft_churn_reason("torn", 40) == "torn_persistent");
    // a moved generation is churn too
    CHECK(nft_churn_reason("changed", 2) == "changed");
    CHECK(nft_churn_reason("changed", 3) == "torn_persistent");
    // any other reason is not churn, however long the streak
    CHECK(nft_churn_reason("timeout", 9) == "timeout");
    CHECK(nft_churn_reason("eperm", 9) == "eperm");
    // and the rows carry it
    const NftDumpResult torn{NftDumpStatus::torn, 0};
    CHECK(nft_fallthrough_row("chain", torn, 2) == "fallthrough|nftables:chain:torn");
    CHECK(nft_fallthrough_row("chain", torn, 3) == "fallthrough|nftables:chain:torn_persistent");
    CHECK(nft_diag_row("rule", torn, 3) == "error|nftables:rule:torn_persistent");
    CHECK(nft_diag_row("rule", torn) == "error|nftables:rule:torn");
    CHECK(nft_dump_reason(NftDumpResult{NftDumpStatus::generation_changed, 0}) == "changed");
}

// ── ufw and iptables: output the parser does not know is not "no rules" (#4402) ─

TEST_CASE("#4402 ufw_shape_ok: real shapes pass", "[firewall]") {
    // an active ufw with a table: a Status line, a column title, a dashed line, bracketed rows
    CHECK(ufw_shape_ok("Status: active\n"
                       "\n"
                       "     To                         Action      From\n"
                       "     --                         ------      ----\n"
                       "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
                       "[ 2] 80,443/tcp                 ALLOW IN    192.168.1.0/24\n"
                       "[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"));
    // ufw prints no table at all when it is off, or on with no rules
    CHECK(ufw_shape_ok("Status: inactive\n"));
    CHECK(ufw_shape_ok("Status: inactive"));
    CHECK(ufw_shape_ok("Status: active\n"));
    CHECK(ufw_shape_ok("Status: active\n\n"));
}

TEST_CASE("#4402 ufw_shape_ok: output that drifted does not pass", "[firewall]") {
    CHECK_FALSE(ufw_shape_ok(""));
    CHECK_FALSE(ufw_shape_ok("sh: ufw: command not found"));
    CHECK_FALSE(ufw_shape_ok("ERROR: You need to be root to run this script\n"));
    // a Status line the parser recognises, then a table that lost its shape
    CHECK_FALSE(ufw_shape_ok("Status: active\n"
                             "\n"
                             "     Dest           Policy      Source\n"
                             "[ 1] 22/tcp         ALLOW       Anywhere\n"));
    // a dashed header, then a row that is not bracketed
    CHECK_FALSE(ufw_shape_ok("Status: active\n"
                             "\n"
                             "     To                         Action      From\n"
                             "     --                         ------      ----\n"
                             "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
                             "22/tcp ALLOW Anywhere\n"));
    // a Status line with junk after it and no table
    CHECK_FALSE(ufw_shape_ok("Status: active\nsomething else entirely\n"));
}

TEST_CASE("#4402 iptables_shape_ok: real captures pass, ignorable lines are ignored", "[firewall]") {
    constexpr std::string_view real = "-P INPUT ACCEPT\n"
                                      "-P FORWARD ACCEPT\n"
                                      "-P OUTPUT ACCEPT\n"
                                      "-N fixture-chain\n"
                                      "-A INPUT -j fixture-chain\n"
                                      "-A fixture-chain -j DROP\n";
    CHECK(iptables_shape_ok(parse_iptables_save(real)));
    // three bare policies and nothing else is still a recognised, empty ruleset
    CHECK(iptables_shape_ok(parse_iptables_save("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n")));
    // a warning or comment line and blank lines must not make a healthy host unrecognised
    CHECK(iptables_shape_ok(parse_iptables_save(
        "# Warning: iptables-legacy tables present, use iptables-legacy to see them\n"
        "\n"
        "   \n"
        "-P INPUT ACCEPT\n"
        "  # indented comment\n"
        "-P FORWARD ACCEPT\n"
        "-P OUTPUT ACCEPT\n")));
}

TEST_CASE("#4402 iptables_shape_ok: no policy line, or an unknown line, does not pass", "[firewall]") {
    CHECK_FALSE(iptables_shape_ok(parse_iptables_save("")));
    CHECK_FALSE(iptables_shape_ok(parse_iptables_save("-N a\n-A a -j ACCEPT\n")));
    CHECK_FALSE(iptables_shape_ok(parse_iptables_save("# only a comment\n")));
    // a line that is none of -P, -N, -A next to good ones
    CHECK_FALSE(iptables_shape_ok(parse_iptables_save(
        "-P INPUT ACCEPT\n"
        "iptables v1.8.9 (nf_tables): unknown option\n"
        "-P FORWARD ACCEPT\n")));
    CHECK_FALSE(iptables_shape_ok(parse_iptables_save("Permission denied (you must be root)\n")));
    CHECK(unrecognised_output_row("ufw") == "error|ufw:unrecognised_output");
    CHECK(unrecognised_output_row("iptables") == "error|iptables:unrecognised_output");
}

// ── Linux: the root snapshot broker (framing, nft text, the save listing, the decision) ────

namespace {

/// A broker reply from three section bodies, each already newline-terminated or empty.
std::string snap(std::string_view nft, std::string_view ipt, std::string_view ip6t) {
    return "== nft -a list ruleset\n" + std::string{nft} + "== iptables-legacy-save\n" + std::string{ipt} +
           "== ip6tables-legacy-save\n" + std::string{ip6t} + "== end\n";
}

// `nft -a list ruleset`: one table, one base chain, handles 4 and 5 (a real listing's shape).
constexpr std::string_view kNftOne =
    "table inet filter { # handle 1\n"
    "\tchain input { # handle 1\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 counter packets 41 bytes 3120 accept # handle 4\n"
    "\t\tct state established,related accept # handle 5\n"
    "\t}\n"
    "}\n";

// sets, maps, a flowtable, a multi-line set element list, a multi-line rule and two tables
constexpr std::string_view kNftBig =
    "# Warning: table ip nat is managed by iptables-nft, do not touch!\n"
    "table inet filter { # handle 1\n"
    "\tset blocked { # handle 2\n"
    "\t\ttype ipv4_addr\n"
    "\t\tflags interval\n"
    "\t\telements = { 192.0.2.0/24, 198.51.100.0/24 }\n"
    "\t}\n"
    "\tmap m { # handle 3\n"
    "\t\ttype ipv4_addr : verdict\n"
    "\t}\n"
    "\tflowtable ft { # handle 4\n"
    "\t\thook ingress priority filter\n"
    "\t}\n"
    "\tchain input { # handle 5\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 accept # handle 6\n"
    "\t\tip saddr @blocked drop # handle 7\n"
    "\t\ttcp dport {\n"
    "\t\t\t80, 443\n"
    "\t\t} accept # handle 8\n"
    "\t\tcounter packets 4 bytes 8 # handle 9\n"
    "\t}\n"
    "\tchain forward { # handle 10\n"
    "\t\ttype filter hook forward priority filter; policy drop;\n"
    "\t}\n"
    "}\n"
    "table ip6 filter { # handle 2\n"
    "\tchain input { # handle 1\n"
    "\t\ticmpv6 type echo-request accept comment \"ping\" # handle 2\n"
    "\t}\n"
    "}\n";

// The broker reply of a real RHEL-family host: Rocky 9.9 aarch64, firewalld running, the packaged account
// reading through the broker (captured 2026-11-22). THE NFT SECTION IS THE CAPTURE, byte for byte. Its two
// legacy sections are not: the capture predates the legacy save reads and held the nft shim's `-S` listing,
// and they read `[tables]` here, which is what a host with no legacy save tool and no instantiated legacy
// table prints. Its table is `table inet firewalld { # handle 3 progname (null)` followed by the line
// `\tflags owner,persist`, which nft prints without a semicolon: the shape the first parser rejected. One
// raw literal, under MSVC's 16 KB limit.
constexpr std::string_view kFirewalldRealReply = R"FWREAL(== nft -a list ruleset
table inet firewalld { # handle 3 progname (null)
	flags owner,persist

	chain mangle_PREROUTING { # handle 144
		type filter hook prerouting priority mangle + 10; policy accept;
		jump mangle_PREROUTING_ZONES # handle 148
	}

	chain mangle_PREROUTING_POLICIES_pre { # handle 145
		jump mangle_PRE_policy_allow-host-ipv6 # handle 314
	}

	chain mangle_PREROUTING_ZONES { # handle 146
		iifname "eth0" goto mangle_PRE_public # handle 327
		goto mangle_PRE_public # handle 278
	}

	chain mangle_PREROUTING_POLICIES_post { # handle 147
	}

	chain nat_PREROUTING { # handle 149
		type nat hook prerouting priority dstnat + 10; policy accept;
		jump nat_PREROUTING_ZONES # handle 153
	}

	chain nat_PREROUTING_POLICIES_pre { # handle 150
		jump nat_PRE_policy_allow-host-ipv6 # handle 313
	}

	chain nat_PREROUTING_ZONES { # handle 151
		iifname "eth0" goto nat_PRE_public # handle 326
		goto nat_PRE_public # handle 277
	}

	chain nat_PREROUTING_POLICIES_post { # handle 152
	}

	chain nat_POSTROUTING { # handle 154
		type nat hook postrouting priority srcnat + 10; policy accept;
		jump nat_POSTROUTING_ZONES # handle 158
	}

	chain nat_POSTROUTING_POLICIES_pre { # handle 155
	}

	chain nat_POSTROUTING_ZONES { # handle 156
		oifname "eth0" goto nat_POST_public # handle 324
		goto nat_POST_public # handle 275
	}

	chain nat_POSTROUTING_POLICIES_post { # handle 157
	}

	chain nat_OUTPUT { # handle 159
		type nat hook output priority dstnat + 10; policy accept;
		jump nat_OUTPUT_POLICIES_pre # handle 161
		jump nat_OUTPUT_POLICIES_post # handle 163
	}

	chain nat_OUTPUT_POLICIES_pre { # handle 160
	}

	chain nat_OUTPUT_POLICIES_post { # handle 162
	}

	chain filter_PREROUTING { # handle 164
		type filter hook prerouting priority filter + 10; policy accept;
		icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept # handle 197
		meta nfproto ipv6 fib saddr . mark . iif check missing drop # handle 195
	}

	chain filter_INPUT { # handle 165
		type filter hook input priority filter + 10; policy accept;
		ct state { established, related } accept # handle 169
		ct status dnat accept # handle 170
		iifname "lo" accept # handle 171
		ct state invalid drop # handle 172
		jump filter_INPUT_ZONES # handle 176
		reject with icmpx admin-prohibited # handle 177
	}

	chain filter_FORWARD { # handle 166
		type filter hook forward priority filter + 10; policy accept;
		ct state { established, related } accept # handle 179
		ct status dnat accept # handle 180
		iifname "lo" accept # handle 181
		ct state invalid drop # handle 182
		ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 addr-unreachable # handle 201
		jump filter_FORWARD_ZONES # handle 185
		reject with icmpx admin-prohibited # handle 187
	}

	chain filter_OUTPUT { # handle 167
		type filter hook output priority filter + 10; policy accept;
		ct state { established, related } accept # handle 189
		oifname "lo" accept # handle 190
		ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 addr-unreachable # handle 199
		jump filter_OUTPUT_POLICIES_pre # handle 192
		jump filter_OUTPUT_POLICIES_post # handle 194
	}

	chain filter_INPUT_POLICIES_pre { # handle 173
		jump filter_IN_policy_allow-host-ipv6 # handle 312
	}

	chain filter_INPUT_ZONES { # handle 174
		iifname "eth0" goto filter_IN_public # handle 323
		goto filter_IN_public # handle 274
	}

	chain filter_INPUT_POLICIES_post { # handle 175
	}

	chain filter_FORWARD_POLICIES_pre { # handle 183
	}

	chain filter_FORWARD_ZONES { # handle 184
		iifname "eth0" goto filter_FWD_public # handle 325
		goto filter_FWD_public # handle 276
	}

	chain filter_FORWARD_POLICIES_post { # handle 186
	}

	chain filter_OUTPUT_POLICIES_pre { # handle 191
	}

	chain filter_OUTPUT_POLICIES_post { # handle 193
	}

	chain filter_IN_public { # handle 202
		jump filter_INPUT_POLICIES_pre # handle 208
		jump filter_IN_public_pre # handle 209
		jump filter_IN_public_log # handle 210
		jump filter_IN_public_deny # handle 211
		jump filter_IN_public_allow # handle 212
		jump filter_IN_public_post # handle 213
		jump filter_INPUT_POLICIES_post # handle 214
		meta l4proto { icmp, ipv6-icmp } accept # handle 273
		reject with icmpx admin-prohibited # handle 215
	}

	chain filter_IN_public_pre { # handle 203
	}

	chain filter_IN_public_log { # handle 204
	}

	chain filter_IN_public_deny { # handle 205
	}

	chain filter_IN_public_allow { # handle 206
		tcp dport 22 accept # handle 216
		ip6 daddr fe80::/64 udp dport 546 accept # handle 217
		tcp dport 9090 accept # handle 218
	}

	chain filter_IN_public_post { # handle 207
	}

	chain nat_POST_public { # handle 219
		jump nat_POSTROUTING_POLICIES_pre # handle 225
		jump nat_POST_public_pre # handle 226
		jump nat_POST_public_log # handle 227
		jump nat_POST_public_deny # handle 228
		jump nat_POST_public_allow # handle 229
		jump nat_POST_public_post # handle 230
		jump nat_POSTROUTING_POLICIES_post # handle 231
	}

	chain nat_POST_public_pre { # handle 220
	}

	chain nat_POST_public_log { # handle 221
	}

	chain nat_POST_public_deny { # handle 222
	}

	chain nat_POST_public_allow { # handle 223
	}

	chain nat_POST_public_post { # handle 224
	}

	chain filter_FWD_public { # handle 232
		jump filter_FORWARD_POLICIES_pre # handle 238
		jump filter_FWD_public_pre # handle 239
		jump filter_FWD_public_log # handle 240
		jump filter_FWD_public_deny # handle 241
		jump filter_FWD_public_allow # handle 242
		jump filter_FWD_public_post # handle 243
		jump filter_FORWARD_POLICIES_post # handle 244
		reject with icmpx admin-prohibited # handle 245
	}

	chain filter_FWD_public_pre { # handle 233
	}

	chain filter_FWD_public_log { # handle 234
	}

	chain filter_FWD_public_deny { # handle 235
	}

	chain filter_FWD_public_allow { # handle 236
		oifname "eth0" accept # handle 328
	}

	chain filter_FWD_public_post { # handle 237
	}

	chain nat_PRE_public { # handle 246
		jump nat_PREROUTING_POLICIES_pre # handle 252
		jump nat_PRE_public_pre # handle 253
		jump nat_PRE_public_log # handle 254
		jump nat_PRE_public_deny # handle 255
		jump nat_PRE_public_allow # handle 256
		jump nat_PRE_public_post # handle 257
		jump nat_PREROUTING_POLICIES_post # handle 258
	}

	chain nat_PRE_public_pre { # handle 247
	}

	chain nat_PRE_public_log { # handle 248
	}

	chain nat_PRE_public_deny { # handle 249
	}

	chain nat_PRE_public_allow { # handle 250
	}

	chain nat_PRE_public_post { # handle 251
	}

	chain mangle_PRE_public { # handle 259
		jump mangle_PREROUTING_POLICIES_pre # handle 265
		jump mangle_PRE_public_pre # handle 266
		jump mangle_PRE_public_log # handle 267
		jump mangle_PRE_public_deny # handle 268
		jump mangle_PRE_public_allow # handle 269
		jump mangle_PRE_public_post # handle 270
		jump mangle_PREROUTING_POLICIES_post # handle 271
	}

	chain mangle_PRE_public_pre { # handle 260
	}

	chain mangle_PRE_public_log { # handle 261
	}

	chain mangle_PRE_public_deny { # handle 262
	}

	chain mangle_PRE_public_allow { # handle 263
	}

	chain mangle_PRE_public_post { # handle 264
	}

	chain filter_IN_policy_allow-host-ipv6 { # handle 279
		jump filter_IN_policy_allow-host-ipv6_pre # handle 285
		jump filter_IN_policy_allow-host-ipv6_log # handle 286
		jump filter_IN_policy_allow-host-ipv6_deny # handle 287
		jump filter_IN_policy_allow-host-ipv6_allow # handle 288
		jump filter_IN_policy_allow-host-ipv6_post # handle 289
	}

	chain filter_IN_policy_allow-host-ipv6_pre { # handle 280
	}

	chain filter_IN_policy_allow-host-ipv6_log { # handle 281
	}

	chain filter_IN_policy_allow-host-ipv6_deny { # handle 282
	}

	chain filter_IN_policy_allow-host-ipv6_allow { # handle 283
		icmpv6 type nd-neighbor-advert accept # handle 315
		icmpv6 type nd-neighbor-solicit accept # handle 316
		icmpv6 type nd-router-advert accept # handle 317
		icmpv6 type nd-redirect accept # handle 318
		icmpv6 type mld-listener-done accept # handle 319
		icmpv6 type mld-listener-query accept # handle 320
		icmpv6 type mld-listener-report accept # handle 321
		icmpv6 type mld2-listener-report accept # handle 322
	}

	chain filter_IN_policy_allow-host-ipv6_post { # handle 284
	}

	chain nat_PRE_policy_allow-host-ipv6 { # handle 290
		jump nat_PRE_policy_allow-host-ipv6_pre # handle 296
		jump nat_PRE_policy_allow-host-ipv6_log # handle 297
		jump nat_PRE_policy_allow-host-ipv6_deny # handle 298
		jump nat_PRE_policy_allow-host-ipv6_allow # handle 299
		jump nat_PRE_policy_allow-host-ipv6_post # handle 300
	}

	chain nat_PRE_policy_allow-host-ipv6_pre { # handle 291
	}

	chain nat_PRE_policy_allow-host-ipv6_log { # handle 292
	}

	chain nat_PRE_policy_allow-host-ipv6_deny { # handle 293
	}

	chain nat_PRE_policy_allow-host-ipv6_allow { # handle 294
	}

	chain nat_PRE_policy_allow-host-ipv6_post { # handle 295
	}

	chain mangle_PRE_policy_allow-host-ipv6 { # handle 301
		jump mangle_PRE_policy_allow-host-ipv6_pre # handle 307
		jump mangle_PRE_policy_allow-host-ipv6_log # handle 308
		jump mangle_PRE_policy_allow-host-ipv6_deny # handle 309
		jump mangle_PRE_policy_allow-host-ipv6_allow # handle 310
		jump mangle_PRE_policy_allow-host-ipv6_post # handle 311
	}

	chain mangle_PRE_policy_allow-host-ipv6_pre { # handle 302
	}

	chain mangle_PRE_policy_allow-host-ipv6_log { # handle 303
	}

	chain mangle_PRE_policy_allow-host-ipv6_deny { # handle 304
	}

	chain mangle_PRE_policy_allow-host-ipv6_allow { # handle 305
	}

	chain mangle_PRE_policy_allow-host-ipv6_post { # handle 306
	}
}
== iptables-legacy-save
[tables]
== ip6tables-legacy-save
[tables]
== end
)FWREAL";

// The whole broker reply of a real RHEL-family host with a RICH ruleset: Rocky 9.9 aarch64, firewalld plus
// lab-loaded tables of every family (13 tables, 215 rules; captured 2026-11-23). THE NFT SECTION IS THE
// CAPTURE (see the one edit below); its two legacy sections read `[tables]`, as for the reply above. It holds
// shapes the printer rules alone could not vouch for: sets with timers, interval and concatenated sets, set
// and map elements wrapped over lines, counter, quota, limit, ct and synproxy objects, a flowtable, a dormant
// table, a table comment, named and inline verdict maps, rich-rule chains and anonymous `jump {` and
// `goto {` chains. It is not trimmed, so it can be compared with the capture byte for byte; the one edit is
// that the two `macset` elements, typed in the lab under a real vendor prefix, read 00:00:5e:00:53:01 and
// 00:00:5e:00:53:02 (the documentation range, same length) so the personal-data guard's MAC detector stays
// quiet. Two adjacent raw literals, each under MSVC's 16,380-byte limit, split at a line boundary.
constexpr std::string_view kRichRealReply = R"FWREAL(== nft -a list ruleset
table inet firewalld { # handle 14 progname (null)
	flags owner,persist

	set labnet { # handle 1
		type ipv4_addr
		flags interval
		elements = { 198.51.100.0/24, 203.0.113.0/25 }
	}

	set labset { # handle 2
		type ipv4_addr
		flags interval
		elements = { 192.0.2.1, 192.0.2.2,
			     192.0.2.3, 192.0.2.4,
			     192.0.2.5, 192.0.2.6,
			     192.0.2.7, 192.0.2.8,
			     192.0.2.9, 192.0.2.10,
			     192.0.2.11, 192.0.2.12 }
	}

	chain mangle_PREROUTING { # handle 3
		type filter hook prerouting priority mangle + 10; policy accept;
		jump mangle_PREROUTING_ZONES # handle 7
	}

	chain mangle_PREROUTING_POLICIES_pre { # handle 4
		jump mangle_PRE_policy_allow-host-ipv6 # handle 173
	}

	chain mangle_PREROUTING_ZONES { # handle 5
		ip saddr 192.0.2.200 goto mangle_PRE_trusted # handle 285
		iifname "eth0" goto mangle_PRE_public # handle 186
		goto mangle_PRE_public # handle 137
	}

	chain mangle_PREROUTING_POLICIES_post { # handle 6
	}

	chain nat_PREROUTING { # handle 8
		type nat hook prerouting priority dstnat + 10; policy accept;
		jump nat_PREROUTING_ZONES # handle 12
	}

	chain nat_PREROUTING_POLICIES_pre { # handle 9
		jump nat_PRE_policy_allow-host-ipv6 # handle 172
	}

	chain nat_PREROUTING_ZONES { # handle 10
		ip saddr 192.0.2.200 goto nat_PRE_trusted # handle 284
		iifname "eth0" goto nat_PRE_public # handle 185
		goto nat_PRE_public # handle 136
	}

	chain nat_PREROUTING_POLICIES_post { # handle 11
	}

	chain nat_POSTROUTING { # handle 13
		type nat hook postrouting priority srcnat + 10; policy accept;
		jump nat_POSTROUTING_ZONES # handle 17
	}

	chain nat_POSTROUTING_POLICIES_pre { # handle 14
	}

	chain nat_POSTROUTING_ZONES { # handle 15
		ip daddr 192.0.2.200 goto nat_POST_trusted # handle 282
		oifname "eth0" goto nat_POST_public # handle 183
		goto nat_POST_public # handle 134
	}

	chain nat_POSTROUTING_POLICIES_post { # handle 16
	}

	chain nat_OUTPUT { # handle 18
		type nat hook output priority dstnat + 10; policy accept;
		jump nat_OUTPUT_POLICIES_pre # handle 20
		jump nat_OUTPUT_POLICIES_post # handle 22
	}

	chain nat_OUTPUT_POLICIES_pre { # handle 19
	}

	chain nat_OUTPUT_POLICIES_post { # handle 21
	}

	chain filter_PREROUTING { # handle 23
		type filter hook prerouting priority filter + 10; policy accept;
		icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept # handle 56
		meta nfproto ipv6 fib saddr . mark . iif check missing drop # handle 54
	}

	chain filter_INPUT { # handle 24
		type filter hook input priority filter + 10; policy accept;
		ct state { established, related } accept # handle 28
		ct status dnat accept # handle 29
		iifname "lo" accept # handle 30
		ct state invalid drop # handle 31
		jump filter_INPUT_ZONES # handle 35
		reject with icmpx admin-prohibited # handle 36
	}

	chain filter_FORWARD { # handle 25
		type filter hook forward priority filter + 10; policy accept;
		ct state { established, related } accept # handle 38
		ct status dnat accept # handle 39
		iifname "lo" accept # handle 40
		ct state invalid drop # handle 41
		ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 addr-unreachable # handle 60
		jump filter_FORWARD_ZONES # handle 44
		reject with icmpx admin-prohibited # handle 46
	}

	chain filter_OUTPUT { # handle 26
		type filter hook output priority filter + 10; policy accept;
		ct state { established, related } accept # handle 48
		oifname "lo" accept # handle 49
		ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002:a9fe::/32, 2002:ac10::/28, 2002:c0a8::/32, 2002:e000::/19 } reject with icmpv6 addr-unreachable # handle 58
		jump filter_OUTPUT_POLICIES_pre # handle 51
		jump filter_OUTPUT_POLICIES_post # handle 53
	}

	chain filter_INPUT_POLICIES_pre { # handle 32
		jump filter_IN_policy_allow-host-ipv6 # handle 171
	}

	chain filter_INPUT_ZONES { # handle 33
		ip saddr 192.0.2.200 goto filter_IN_trusted # handle 281
		iifname "eth0" goto filter_IN_public # handle 182
		goto filter_IN_public # handle 133
	}

	chain filter_INPUT_POLICIES_post { # handle 34
	}

	chain filter_FORWARD_POLICIES_pre { # handle 42
	}

	chain filter_FORWARD_ZONES { # handle 43
		ip saddr 192.0.2.200 goto filter_FWD_trusted # handle 283
		iifname "eth0" goto filter_FWD_public # handle 184
		goto filter_FWD_public # handle 135
	}

	chain filter_FORWARD_POLICIES_post { # handle 45
	}

	chain filter_OUTPUT_POLICIES_pre { # handle 50
	}

	chain filter_OUTPUT_POLICIES_post { # handle 52
	}

	chain filter_IN_public { # handle 61
		jump filter_INPUT_POLICIES_pre # handle 67
		jump filter_IN_public_pre # handle 68
		jump filter_IN_public_log # handle 69
		jump filter_IN_public_deny # handle 70
		jump filter_IN_public_allow # handle 71
		jump filter_IN_public_post # handle 72
		jump filter_INPUT_POLICIES_post # handle 73
		meta l4proto { icmp, ipv6-icmp } accept # handle 132
		reject with icmpx admin-prohibited # handle 74
	}

	chain filter_IN_public_pre { # handle 62
	}

	chain filter_IN_public_log { # handle 63
		ip saddr 192.0.2.0/24 limit rate 1/minute burst 5 packets log prefix "labrich " level info # handle 196
		ip saddr @labnet limit rate 3/minute burst 5 packets log prefix "labnet " # handle 201
	}

	chain filter_IN_public_deny { # handle 64
		ip saddr 203.0.113.0/24 tcp dport 2222 reject with icmp port-unreachable # handle 199
		ip saddr @labset drop # handle 200
		ip saddr @labnet drop # handle 202
		icmp type echo-request reject with icmpx admin-prohibited # handle 212
		icmpv6 type echo-request reject with icmpx admin-prohibited # handle 213
	}

	chain filter_IN_public_allow { # handle 65
		tcp dport 22 accept # handle 75
		ip6 daddr fe80::/64 udp dport 546 accept # handle 76
		tcp dport 9090 accept # handle 77
		tcp dport 80 accept # handle 188
		tcp dport 8080 accept # handle 189
		udp dport 5000-5010 accept # handle 190
		ip saddr 192.0.2.0/24 accept # handle 197
		ip saddr 198.51.100.7 tcp dport 443 accept # handle 198
	}

	chain filter_IN_public_post { # handle 66
	}

	chain nat_POST_public { # handle 78
		jump nat_POSTROUTING_POLICIES_pre # handle 84
		jump nat_POST_public_pre # handle 85
		jump nat_POST_public_log # handle 86
		jump nat_POST_public_deny # handle 87
		jump nat_POST_public_allow # handle 88
		jump nat_POST_public_post # handle 89
		jump nat_POSTROUTING_POLICIES_post # handle 90
	}

	chain nat_POST_public_pre { # handle 79
	}

	chain nat_POST_public_log { # handle 80
	}

	chain nat_POST_public_deny { # handle 81
	}

	chain nat_POST_public_allow { # handle 82
		meta nfproto ipv4 oifname != "lo" masquerade # handle 205
	}

	chain nat_POST_public_post { # handle 83
	}

	chain filter_FWD_public { # handle 91
		jump filter_FORWARD_POLICIES_pre # handle 97
		jump filter_FWD_public_pre # handle 98
		jump filter_FWD_public_log # handle 99
		jump filter_FWD_public_deny # handle 100
		jump filter_FWD_public_allow # handle 101
		jump filter_FWD_public_post # handle 102
		jump filter_FORWARD_POLICIES_post # handle 103
		reject with icmpx admin-prohibited # handle 104
	}

	chain filter_FWD_public_pre { # handle 92
	}

	chain filter_FWD_public_log { # handle 93
	}

	chain filter_FWD_public_deny { # handle 94
	}

	chain filter_FWD_public_allow { # handle 95
		oifname "eth0" accept # handle 187
	}

	chain filter_FWD_public_post { # handle 96
	}

	chain nat_PRE_public { # handle 105
		jump nat_PREROUTING_POLICIES_pre # handle 111
		jump nat_PRE_public_pre # handle 112
		jump nat_PRE_public_log # handle 113
		jump nat_PRE_public_deny # handle 114
		jump nat_PRE_public_allow # handle 115
		jump nat_PRE_public_post # handle 116
		jump nat_PREROUTING_POLICIES_post # handle 117
	}

	chain nat_PRE_public_pre { # handle 106
	}

	chain nat_PRE_public_log { # handle 107
	}

	chain nat_PRE_public_deny { # handle 108
	}

	chain nat_PRE_public_allow { # handle 109
		meta nfproto ipv4 tcp dport 8081 redirect to :80 # handle 208
		meta nfproto ipv4 tcp dport 8082 dnat ip to 192.0.2.99:8080 # handle 211
	}

	chain nat_PRE_public_post { # handle 110
	}

	chain mangle_PRE_public { # handle 118
		jump mangle_PREROUTING_POLICIES_pre # handle 124
		jump mangle_PRE_public_pre # handle 125
		jump mangle_PRE_public_log # handle 126
		jump mangle_PRE_public_deny # handle 127
		jump mangle_PRE_public_allow # handle 128
		jump mangle_PRE_public_post # handle 129
		jump mangle_PREROUTING_POLICIES_post # handle 130
	}

	chain mangle_PRE_public_pre { # handle 119
	}

	chain mangle_PRE_public_log { # handle 120
	}

	chain mangle_PRE_public_deny { # handle 121
	}

	chain mangle_PRE_public_allow { # handle 122
	}

	chain mangle_PRE_public_post { # handle 123
	}

	chain filter_IN_policy_allow-host-ipv6 { # handle 138
		jump filter_IN_policy_allow-host-ipv6_pre # handle 144
		jump filter_IN_policy_allow-host-ipv6_log # handle 145
		jump filter_IN_policy_allow-host-ipv6_deny # handle 146
		jump filter_IN_policy_allow-host-ipv6_allow # handle 147
		jump filter_IN_policy_allow-host-ipv6_post # handle 148
	}

	chain filter_IN_policy_allow-host-ipv6_pre { # handle 139
	}

	chain filter_IN_policy_allow-host-ipv6_log { # handle 140
	}

	chain filter_IN_policy_allow-host-ipv6_deny { # handle 141
	}

	chain filter_IN_policy_allow-host-ipv6_allow { # handle 142
		icmpv6 type nd-neighbor-advert accept # handle 174
		icmpv6 type nd-neighbor-solicit accept # handle 175
		icmpv6 type nd-router-advert accept # handle 176
		icmpv6 type nd-redirect accept # handle 177
		icmpv6 type mld-listener-done accept # handle 178
		icmpv6 type mld-listener-query accept # handle 179
		icmpv6 type mld-listener-report accept # handle 180
		icmpv6 type mld2-listener-report accept # handle 181
	}

	chain filter_IN_policy_allow-host-ipv6_post { # handle 143
	}

	chain nat_PRE_policy_allow-host-ipv6 { # handle 149
		jump nat_PRE_policy_allow-host-ipv6_pre # handle 155
		jump nat_PRE_policy_allow-host-ipv6_log # handle 156
		jump nat_PRE_policy_allow-host-ipv6_deny # handle 157
		jump nat_PRE_policy_allow-host-ipv6_allow # handle 158
		jump nat_PRE_policy_allow-host-ipv6_post # handle 159
	}

	chain nat_PRE_policy_allow-host-ipv6_pre { # handle 150
	}

	chain nat_PRE_policy_allow-host-ipv6_log { # handle 151
	}

	chain nat_PRE_policy_allow-host-ipv6_deny { # handle 152
	}

	chain nat_PRE_policy_allow-host-ipv6_allow { # handle 153
	}

	chain nat_PRE_policy_allow-host-ipv6_post { # handle 154
	}

	chain mangle_PRE_policy_allow-host-ipv6 { # handle 160
		jump mangle_PRE_policy_allow-host-ipv6_pre # handle 166
		jump mangle_PRE_policy_allow-host-ipv6_log # handle 167
		jump mangle_PRE_policy_allow-host-ipv6_deny # handle 168
		jump mangle_PRE_policy_allow-host-ipv6_allow # handle 169
		jump mangle_PRE_policy_allow-host-ipv6_post # handle 170
	}

	chain mangle_PRE_policy_allow-host-ipv6_pre { # handle 161
	}

	chain mangle_PRE_policy_allow-host-ipv6_log { # handle 162
	}

	chain mangle_PRE_policy_allow-host-ipv6_deny { # handle 163
	}

	chain mangle_PRE_policy_allow-host-ipv6_allow { # handle 164
	}

	chain mangle_PRE_policy_allow-host-ipv6_post { # handle 165
	}

	chain filter_IN_trusted { # handle 214
		jump filter_INPUT_POLICIES_pre # handle 220
		jump filter_IN_trusted_pre # handle 221
		jump filter_IN_trusted_log # handle 222
		jump filter_IN_trusted_deny # handle 223
		jump filter_IN_trusted_allow # handle 224
		jump filter_IN_trusted_post # handle 225
		jump filter_INPUT_POLICIES_post # handle 226
		accept # handle 227
	}

	chain filter_IN_trusted_pre { # handle 215
	}

	chain filter_IN_trusted_log { # handle 216
	}

	chain filter_IN_trusted_deny { # handle 217
	}

	chain filter_IN_trusted_allow { # handle 218
	}

	chain filter_IN_trusted_post { # handle 219
	}

	chain nat_POST_trusted { # handle 228
		jump nat_POSTROUTING_POLICIES_pre # handle 234
		jump nat_POST_trusted_pre # handle 235
		jump nat_POST_trusted_log # handle 236
		jump nat_POST_trusted_deny # handle 237
		jump nat_POST_trusted_allow # handle 238
		jump nat_POST_trusted_post # handle 239
		jump nat_POSTROUTING_POLICIES_post # handle 240
	}

)FWREAL" R"FWREAL(	chain nat_POST_trusted_pre { # handle 229
	}

	chain nat_POST_trusted_log { # handle 230
	}

	chain nat_POST_trusted_deny { # handle 231
	}

	chain nat_POST_trusted_allow { # handle 232
	}

	chain nat_POST_trusted_post { # handle 233
	}

	chain filter_FWD_trusted { # handle 241
		jump filter_FORWARD_POLICIES_pre # handle 247
		jump filter_FWD_trusted_pre # handle 248
		jump filter_FWD_trusted_log # handle 249
		jump filter_FWD_trusted_deny # handle 250
		jump filter_FWD_trusted_allow # handle 251
		jump filter_FWD_trusted_post # handle 252
		jump filter_FORWARD_POLICIES_post # handle 253
		accept # handle 254
	}

	chain filter_FWD_trusted_pre { # handle 242
	}

	chain filter_FWD_trusted_log { # handle 243
	}

	chain filter_FWD_trusted_deny { # handle 244
	}

	chain filter_FWD_trusted_allow { # handle 245
		ip daddr 192.0.2.200 accept # handle 286
	}

	chain filter_FWD_trusted_post { # handle 246
	}

	chain nat_PRE_trusted { # handle 255
		jump nat_PREROUTING_POLICIES_pre # handle 261
		jump nat_PRE_trusted_pre # handle 262
		jump nat_PRE_trusted_log # handle 263
		jump nat_PRE_trusted_deny # handle 264
		jump nat_PRE_trusted_allow # handle 265
		jump nat_PRE_trusted_post # handle 266
		jump nat_PREROUTING_POLICIES_post # handle 267
	}

	chain nat_PRE_trusted_pre { # handle 256
	}

	chain nat_PRE_trusted_log { # handle 257
	}

	chain nat_PRE_trusted_deny { # handle 258
	}

	chain nat_PRE_trusted_allow { # handle 259
	}

	chain nat_PRE_trusted_post { # handle 260
	}

	chain mangle_PRE_trusted { # handle 268
		jump mangle_PREROUTING_POLICIES_pre # handle 274
		jump mangle_PRE_trusted_pre # handle 275
		jump mangle_PRE_trusted_log # handle 276
		jump mangle_PRE_trusted_deny # handle 277
		jump mangle_PRE_trusted_allow # handle 278
		jump mangle_PRE_trusted_post # handle 279
		jump mangle_PREROUTING_POLICIES_post # handle 280
	}

	chain mangle_PRE_trusted_pre { # handle 269
	}

	chain mangle_PRE_trusted_log { # handle 270
	}

	chain mangle_PRE_trusted_deny { # handle 271
	}

	chain mangle_PRE_trusted_allow { # handle 272
	}

	chain mangle_PRE_trusted_post { # handle 273
	}
}
table ip filter { # handle 17
	chain INPUT { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 9999 counter packets 0 bytes 0 accept # handle 2
		tcp dport 7777 counter packets 0 bytes 0 accept # handle 3
		ip saddr 192.0.2.4  counter packets 0 bytes 0 accept # handle 4
		ip saddr 192.0.2.5 counter packets 0 bytes 0 jump LAB_CHAIN # handle 9
		ip saddr 192.0.2.6 xt match "recent" counter packets 0 bytes 0 # handle 10
		ip saddr 192.0.2.7 xt match "string" counter packets 0 bytes 0 drop # handle 11
		ip saddr 192.0.2.9 limit rate 5/minute burst 5 packets counter packets 0 bytes 0 log prefix "lab " # handle 12
		ip saddr 192.0.2.8 ip protocol tcp tcp dport { 5000, 5001, 5002 } counter packets 0 bytes 0 accept # handle 13
		ip saddr 192.0.2.10 tcp dport 7778 counter packets 0 bytes 0 reject with tcp reset # handle 14
	}

	chain FORWARD { # handle 5
		type filter hook forward priority filter; policy accept;
		ct state related,established counter packets 0 bytes 0 accept # handle 6
	}

	chain LAB_CHAIN { # handle 7
		counter packets 0 bytes 0 return # handle 8
	}
}
table ip labrich { # handle 18
	counter lab_ctr { # handle 15
		packets 0 bytes 0
	}

	quota lab_quota { # handle 16
		over 25 mbytes
	}

	limit lab_lim { # handle 17
		rate 10/second
	}

	ct helper lab_ftp { # handle 18
		type "ftp" protocol tcp
		l3proto ip
	}

	ct timeout lab_ctt { # handle 19
		protocol tcp
		l3proto ip
		policy = { established : 1m40s }
	}

	ct expectation lab_exp { # handle 20
		protocol tcp
		dport 5000
		timeout 1h
		size 12
		l3proto ip
	}

	synproxy lab_syn { # handle 21
		mss 1460
		wscale 8
		timestamp sack-perm
	}

	set bigset { # handle 1
		type ipv4_addr
		elements = { 10.20.0.1, 10.20.0.2,
			     10.20.0.3, 10.20.0.4,
			     10.20.0.5, 10.20.0.6,
			     10.20.0.7, 10.20.0.8,
			     10.20.0.9, 10.20.1.10,
			     10.20.1.11, 10.20.1.12,
			     10.20.1.13, 10.20.1.14,
			     10.20.1.15, 10.20.1.16,
			     10.20.1.17, 10.20.1.18,
			     10.20.1.19, 10.20.2.20,
			     10.20.2.21, 10.20.2.22,
			     10.20.2.23, 10.20.2.24,
			     10.20.2.25, 10.20.2.26,
			     10.20.2.27, 10.20.2.28,
			     10.20.2.29, 10.20.3.30,
			     10.20.3.31, 10.20.3.32,
			     10.20.3.33, 10.20.3.34,
			     10.20.3.35, 10.20.3.36,
			     10.20.3.37, 10.20.3.38,
			     10.20.3.39, 10.20.4.40,
			     10.20.4.41, 10.20.4.42,
			     10.20.4.43, 10.20.4.44,
			     10.20.4.45, 10.20.4.46,
			     10.20.4.47, 10.20.4.48,
			     10.20.4.49, 10.20.5.50,
			     10.20.5.51, 10.20.5.52,
			     10.20.5.53, 10.20.5.54,
			     10.20.5.55, 10.20.5.56,
			     10.20.5.57, 10.20.5.58,
			     10.20.5.59, 10.20.6.60 }
	}

	set cidrset { # handle 2
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 100.64.0.0/10,
			     169.254.0.0/16, 172.16.0.0/12,
			     192.0.2.0/24, 192.168.0.0/16,
			     198.18.0.0/15, 198.51.100.0/24,
			     203.0.113.0/24 }
	}

	set timedset { # handle 3
		type ipv4_addr
		size 1024
		counter
		timeout 1h
		comment "lab timed set"
		elements = { 192.0.2.50 counter packets 0 bytes 0 timeout 30m expires 29m34s900ms,
			     192.0.2.51 counter packets 0 bytes 0 expires 59m34s900ms }
	}

	set concatset { # handle 4
		type ipv4_addr . inet_service
		flags interval
		elements = { 192.0.2.0/24 . 80-90,
			     198.51.100.1 . 443 }
	}

	set dynset { # handle 5
		type ipv4_addr
		size 4096
		flags dynamic,timeout
		timeout 1m
	}

	set macset { # handle 6
		type ether_addr
		elements = { 00:00:5e:00:53:01,
			     00:00:5e:00:53:02 }
	}

	map lab_vmap { # handle 13
		type ipv4_addr : verdict
		elements = { 192.0.2.1 : accept,
			     192.0.2.2 : drop,
			     192.0.2.3 : jump lab_sub }
	}

	map lab_dmap { # handle 14
		type inet_service : ipv4_addr
		elements = { 8080 : 192.0.2.20,
			     8443 : 192.0.2.21 }
	}

	chain lab_sub { # handle 7
		counter packets 2 bytes 144 # handle 45
		return # handle 46
	}

	chain lab_in { # handle 8
		comment "lab input chain"
		type filter hook input priority filter + 5; policy accept;
		ct state established,related accept # handle 22
		ct state invalid counter packets 0 bytes 0 drop # handle 23
		meta l4proto tcp iifname "lo" accept # handle 24
		iifname "eth*" tcp dport { 22, 80, 443 } counter packets 4 bytes 256 accept # handle 26
		ip saddr @bigset counter packets 0 bytes 0 drop # handle 27
		ip saddr @cidrset jump lab_sub # handle 28
		ip saddr . tcp dport @concatset counter packets 0 bytes 0 accept # handle 29
		tcp dport 9998 log prefix "x" counter packets 0 bytes 0 # handle 30
		tcp dport 9997 log prefix "lab: " level info flags all # handle 31
		ip saddr vmap @lab_vmap # handle 32
		tcp dport 9999 counter name "lab_ctr" # handle 35
		tcp dport 9996 quota name "lab_quota" accept # handle 36
		tcp dport 9995 limit name "lab_lim" accept # handle 37
		ip protocol vmap { icmp : accept, tcp : jump lab_sub, udp : goto lab_sub } # handle 39
		tcp dport 8888 accept comment "has # handle 99 and { brace" # handle 40
		meta mark set 0x00000010 ct mark set meta mark # handle 41
		ip saddr 192.0.2.77 add @dynset { ip saddr timeout 30s limit rate over 10/second burst 5 packets } counter packets 0 bytes 0 drop # handle 42
		tcp dport { 1001, 1008, 1015, 1022, 1029, 1036, 1043, 1050, 1057, 1064, 1071, 1078, 1085, 1092, 1099, 1106, 1113, 1120, 1127, 1134, 1141, 1148, 1155, 1162, 1169, 1176, 1183, 1190, 1197, 1204, 1211, 1218, 1225, 1232, 1239, 1246, 1253, 1260, 1267, 1274, 1281, 1288, 1295, 1302, 1309, 1316, 1323, 1330, 1337, 1344, 1351, 1358, 1365, 1372, 1379, 1386, 1393, 1400, 1407, 1414, 1421, 1428, 1435, 1442, 1449, 1456, 1463, 1470, 1477, 1484, 1491, 1498, 1505, 1512, 1519, 1526, 1533, 1540, 1547, 1554, 1561, 1568, 1575, 1582, 1589, 1596, 1603, 1610, 1617, 1624 } counter packets 0 bytes 0 accept # handle 44
		tcp dport 5555 jump {
			counter packets 0 bytes 0 accept
		} # handle 59
		ip saddr 192.0.2.78 tcp dport 5556 goto {
			counter packets 0 bytes 0 drop
		} # handle 62
		tcp dport 5557 jump {
			ct state established accept
			tcp dport 5558 counter packets 0 bytes 0 drop
		} # handle 66
	}

	chain lab_out { # handle 9
		type filter hook output priority filter - 5; policy accept;
		oif "lo" accept # handle 52
		ct state established,related accept # handle 53
		tcp dport 8099 reject with tcp reset # handle 55
		ip daddr 192.0.2.250 reject with icmp host-unreachable # handle 56
	}

	chain lab_nat { # handle 10
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 8080 dnat to 192.0.2.20:80 # handle 47
		tcp dport 8443 redirect to :443 # handle 48
	}

	chain lab_post { # handle 11
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade # handle 49
		ip saddr 192.0.2.0/24 snat to 203.0.113.1 # handle 50
	}

	chain lab_fwd { # handle 12
		type filter hook forward priority filter; policy accept;
		iifname "lo" oifname "lo" accept # handle 51
	}
}
table ip6 labrich6 { # handle 19
	chain in6 { # handle 1
		type filter hook input priority filter; policy accept;
		ip6 saddr fe80::/10 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept # handle 3
		tcp dport 7770 counter packets 0 bytes 0 drop # handle 4
	}
}
table inet labinet { # handle 20
	comment "lab inet table"
	flowtable ft { # handle 4
		hook ingress priority filter
		devices = { "lo" }
	}

	chain c { # handle 1
		type filter hook input priority filter; policy accept;
		meta nfproto ipv4 tcp dport 7771 counter packets 0 bytes 0 # handle 2
	}
}
table ip labdorm { # handle 21
	flags dormant

	chain c { # handle 1
		type filter hook input priority filter; policy accept;
		counter packets 0 bytes 0 accept # handle 2
	}
}
table bridge labbr { # handle 22
	chain c { # handle 1
		type filter hook prerouting priority dstnat; policy accept;
		ether type ip counter packets 0 bytes 0 # handle 2
	}
}
table arp labarp { # handle 23
	chain c { # handle 1
		type filter hook input priority filter; policy accept;
		arp operation request counter packets 0 bytes 0 accept # handle 2
	}
}
table netdev labnd { # handle 24
	chain c { # handle 1
		type filter hook ingress device "lo" priority filter; policy accept;
		ip saddr 192.0.2.250 counter packets 0 bytes 0 drop # handle 2
	}
}
table ip nat { # handle 25
	chain POSTROUTING { # handle 1
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 192.0.2.0/24 counter packets 0 bytes 0 masquerade # handle 2
	}
}
table ip6 filter { # handle 26
	chain INPUT { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 7777 counter packets 0 bytes 0 accept # handle 2
	}
}
table ip mangle { # handle 27
	chain PREROUTING { # handle 1
		type filter hook prerouting priority mangle; policy accept;
		ip saddr 192.0.2.11 counter packets 0 bytes 0 meta mark set 0x7 # handle 2
	}
}
table ip raw { # handle 28
	chain PREROUTING { # handle 1
		type filter hook prerouting priority raw; policy accept;
		ip saddr 192.0.2.12 counter packets 0 bytes 0 notrack # handle 2
	}
}
== iptables-legacy-save
[tables]
== ip6tables-legacy-save
[tables]
== end
)FWREAL";

// `iptables -S` listings: the root direct legs' command form (iptables_summary, unchanged)
constexpr std::string_view kIptClean = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
constexpr std::string_view kIptV6Rules =
    "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n";

// `iptables-legacy-save` listings: what the broker's legacy sections hold. Counters read [0:0] without -c.
constexpr std::string_view kSaveClean =
    "# Generated by iptables-save v1.8.11 on Mon Nov 23 04:00:00 2026\n"
    "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    "# Completed on Mon Nov 23 04:00:00 2026\n";
constexpr std::string_view kSaveV6Rules =
    "# Generated by iptables-save v1.8.11 on Mon Nov 23 04:00:00 2026\n"
    "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
    "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
    "# Completed on Mon Nov 23 04:00:00 2026\n";
// rules only in raw and mangle, the filter table not instantiated: the case `-S` read as no content
constexpr std::string_view kSaveRawMangle =
    "# Generated by iptables-save v1.8.11 on Mon Nov 23 04:00:00 2026\n"
    "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A PREROUTING -s 192.0.2.1/32 -j DROP\nCOMMIT\n"
    "*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
    ":POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o lo -j ACCEPT\nCOMMIT\n"
    "# Completed on Mon Nov 23 04:00:00 2026\n";
constexpr std::string_view kAbsent = "[absent]\n";
constexpr std::string_view kTablesNone = "[tables]\n";          // no legacy save tool, the family holds no table
constexpr std::string_view kTablesFilter = "[tables]\nfilter\n"; // no legacy save tool, a table nothing listed
constexpr std::string_view kFailed = "# partial\n\n[failed]\n";  // partial output, then the marker

using Rows = std::vector<std::string>;

LinuxSnapshotAnswer snapshot_answer(std::string_view nft, std::string_view ipt, std::string_view ip6t,
                                    bool tables_seen, FwReadAction action) {
    const auto parsed = parse_fw_snapshot(snap(nft, ipt, ip6t));
    REQUIRE(parsed.has_value());
    return linux_snapshot_answer(*parsed, tables_seen, action);
}

Rows state_rows(std::string_view nft, std::string_view ipt, std::string_view ip6t, bool tables_seen = false) {
    return snapshot_answer(nft, ipt, ip6t, tables_seen, FwReadAction::state).rows;
}

Rows rules_rows(std::string_view nft, std::string_view ipt, std::string_view ip6t, bool tables_seen = false) {
    return snapshot_answer(nft, ipt, ip6t, tables_seen, FwReadAction::rules).rows;
}

} // namespace

TEST_CASE("parse_fw_snapshot: the three headed sections in order, then the end line", "[firewall]") {
    const auto got = parse_fw_snapshot(snap(kNftOne, kSaveClean, kAbsent));
    REQUIRE(got.has_value());
    CHECK(got->nft.kind == FwSectionKind::text);
    CHECK(got->nft.text == kNftOne);
    CHECK(got->iptables.kind == FwSectionKind::text);
    CHECK(got->iptables.text == kSaveClean);
    CHECK(got->ip6tables.kind == FwSectionKind::absent); // body is exactly [absent]
    CHECK(got->ip6tables.text.empty());
    // an empty body is a text section with no text (an empty nft ruleset prints nothing)
    const auto empty_nft = parse_fw_snapshot(snap("", kSaveClean, kSaveClean));
    REQUIRE(empty_nft.has_value());
    CHECK(empty_nft->nft.kind == FwSectionKind::text);
    CHECK(empty_nft->nft.text.empty());
    // the labels are the legacy save tools' own names
    CHECK(kFwSnapshotIptablesLabel == "iptables-legacy-save");
    CHECK(kFwSnapshotIp6tablesLabel == "ip6tables-legacy-save");
}

TEST_CASE("parse_fw_snapshot: a [failed] line makes the section failed whatever came before it", "[firewall]") {
    const auto got = parse_fw_snapshot(snap(kNftOne, kFailed, kSaveClean));
    REQUIRE(got.has_value());
    CHECK(got->iptables.kind == FwSectionKind::failed);
    CHECK(got->iptables.text.empty()); // the partial text is not kept
    CHECK(got->nft.kind == FwSectionKind::text);
    // [absent] plus other lines is text, not absent; the marker must be a whole line
    const auto not_absent = parse_fw_snapshot(snap(kNftOne, "[absent]\n-P INPUT ACCEPT\n", kSaveClean));
    REQUIRE(not_absent.has_value());
    CHECK(not_absent->iptables.kind == FwSectionKind::text);
    const auto not_failed =
        parse_fw_snapshot(snap(kNftOne, "-A INPUT -m comment --comment [failed] -j ACCEPT\n", kSaveClean));
    REQUIRE(not_failed.has_value());
    CHECK(not_failed->iptables.kind == FwSectionKind::text);
    // the section a hidden /proc/net makes is a blank line and the marker
    const auto hidden = parse_fw_snapshot(snap(kNftOne, "\n[failed]\n", "\n[failed]\n"));
    REQUIRE(hidden.has_value());
    CHECK(hidden->iptables.kind == FwSectionKind::failed);
    CHECK(hidden->ip6tables.kind == FwSectionKind::failed);
}

TEST_CASE("parse_fw_snapshot: [tables] is its own kind, only as the first line of a legacy section", "[firewall]") {
    CHECK(kFwSnapshotTablesMarker == "[tables]");
    // no table, and a table nothing listed: the text is what follows the marker line
    const auto got = parse_fw_snapshot(snap(kNftOne, kTablesNone, kTablesFilter));
    REQUIRE(got.has_value());
    CHECK(got->iptables.kind == FwSectionKind::tables);
    CHECK(got->iptables.text.empty());
    CHECK(got->ip6tables.kind == FwSectionKind::tables);
    CHECK(got->ip6tables.text == "filter\n");
    CHECK(parse_fw_snapshot(snap(kNftOne, "[tables]\nfilter\nnat\n", kTablesNone))->iptables.text == "filter\nnat\n");
    // in the nft section the same line is ordinary text
    const auto in_nft = parse_fw_snapshot(snap(kTablesNone, kSaveClean, kSaveClean));
    REQUIRE(in_nft.has_value());
    CHECK(in_nft->nft.kind == FwSectionKind::text);
    CHECK(in_nft->nft.text == kTablesNone);
    // anywhere but the first line, or not exactly the marker, it is text
    for (const auto& body : {std::string{kSaveClean} + "[tables]\n", std::string{"\n[tables]\n"},
                             std::string{" [tables]\n"}, std::string{"[tables] \n"}, std::string{"[TABLES]\n"},
                             std::string{"[tables]\r\n"}, std::string{"[tables\n"}, std::string{"tables]\n"},
                             std::string{}}) {
        INFO(body);
        const auto r = parse_fw_snapshot(snap(kNftOne, body, kSaveClean));
        REQUIRE(r.has_value());
        CHECK(r->iptables.kind == FwSectionKind::text);
    }
    // a failed section stays failed, whatever else it says, and it is not the absent marker
    const auto both = parse_fw_snapshot(snap(kNftOne, "[tables]\n\n[failed]\n", kTablesNone));
    REQUIRE(both.has_value());
    CHECK(both->iptables.kind == FwSectionKind::failed);
    CHECK(both->ip6tables.kind == FwSectionKind::tables);
    CHECK(parse_fw_snapshot(snap(kNftOne, kAbsent, kTablesNone))->iptables.kind == FwSectionKind::absent);
    // the retired marker is ordinary text now
    CHECK(parse_fw_snapshot(snap(kNftOne, "[unloaded]\n", kTablesNone))->iptables.kind == FwSectionKind::text);
}

TEST_CASE("parse_fw_snapshot: zero bytes is empty, a missing end line is truncated, anything else malformed",
          "[firewall]") {
    const auto token = [](std::string_view reply) {
        const auto r = parse_fw_snapshot(reply);
        REQUIRE_FALSE(r.has_value());
        return std::string{r.error()};
    };
    CHECK(token("") == "empty");
    // the reply as far as it got: no end line, or an end line cut before its newline
    const auto whole = snap(kNftOne, kSaveClean, kSaveClean);
    CHECK(token(whole.substr(0, whole.size() - std::string_view{"== end\n"}.size())) == "truncated");
    CHECK(token(whole.substr(0, whole.size() - 1)) == "truncated"); // `== end` without its newline
    CHECK(token(whole.substr(0, whole.size() - 4)) == "truncated"); // `== e`
    CHECK(token("== nft -a list ruleset\ntable inet filter { # handle 1\n") == "truncated");
    // wrong order, a missing section, a repeated header, an unknown header, text after the end
    const std::string i4 = "== iptables-legacy-save\n";
    const std::string i6 = "== ip6tables-legacy-save\n";
    const std::string nf = "== nft -a list ruleset\n";
    CHECK(token(i4 + nf + i6 + "== end\n") == "malformed");
    CHECK(token(nf + i6 + i4 + "== end\n") == "malformed");
    CHECK(token(nf + i4 + "== end\n") == "malformed");
    CHECK(token(nf + i4 + i4 + i6 + "== end\n") == "malformed");
    CHECK(token(nf + i4 + i6 + "== surprise\n== end\n") == "malformed");
    CHECK(token(snap("", "", "") + nf) == "malformed");
    CHECK(token(snap("", "", "") + "\n") == "malformed");
    // the retired `-S` labels are not the headers of this reply
    CHECK(token("== nft -a list ruleset\n== iptables -S\n== ip6tables -S\n== end\n") == "malformed");
    // garbage, and a reply that does not start with the first header
    CHECK(token("hello\nworld\n") == "malformed");
    CHECK(token("garbage") == "malformed");
    CHECK(token("\n") == "malformed");
    CHECK(token(i4 + i6 + "== end\n") == "malformed");
}

TEST_CASE("parse_nft_ruleset_text: a real listing is tables, chains with hook and policy, and rules by handle",
          "[firewall]") {
    const auto r = parse_nft_ruleset_text(kNftOne);
    REQUIRE(r.has_value());
    REQUIRE(r->chains.size() == 1);
    CHECK(r->chains[0].name == "input");
    CHECK(r->chains[0].table == "filter");
    CHECK(r->chains[0].family == nft_raw::kNfprotoInet);
    CHECK(r->chains[0].is_base_chain);
    CHECK(r->chains[0].hooknum == std::optional<std::uint32_t>{1});
    CHECK(r->chains[0].policy == std::optional<std::uint32_t>{nft_raw::kNftPolicyAccept});
    REQUIRE(r->rules.size() == 2);
    CHECK(r->rules[0].handle == std::optional<std::uint64_t>{4});
    CHECK(r->rules[1].handle == std::optional<std::uint64_t>{5});
    CHECK(r->rules[0].chain == "input");
    CHECK(r->rules[0].table == "filter");
    CHECK(r->rules[0].family == nft_raw::kNfprotoInet);
    // two independent counters agree
    CHECK(r->rules.size() == yuzu::test::fwrestore::count_nft_rules(kNftOne));
}

TEST_CASE("parse_nft_ruleset_text: sets, maps, a flowtable and a multi-line rule are not rules, and the count "
          "agrees with the independent line counter",
          "[firewall]") {
    const auto r = parse_nft_ruleset_text(kNftBig);
    REQUIRE(r.has_value());
    // handles 6, 7, 8 (one rule over three lines), 9 and the ip6 rule 2: five, and no header counted
    REQUIRE(r->rules.size() == 5);
    CHECK(r->rules[2].handle == std::optional<std::uint64_t>{8});
    CHECK(r->rules[4].table == "filter");
    CHECK(r->rules[4].family == nft_raw::kNfprotoIpv6);
    CHECK(r->rules.size() == yuzu::test::fwrestore::count_nft_rules(kNftBig));
    // chains: input, forward (a policy drop base chain), and the ip6 input; the sets are not chains
    REQUIRE(r->chains.size() == 3);
    CHECK(r->chains[1].name == "forward");
    CHECK(r->chains[1].policy == std::optional<std::uint32_t>{nft_raw::kNftPolicyDrop});
    CHECK(r->chains[1].hooknum == std::optional<std::uint32_t>{2});
    CHECK_FALSE(r->chains[2].is_base_chain); // a regular chain carries no hook
    CHECK(r->chains[2].family == nft_raw::kNfprotoIpv6); // the second table's family and name
    CHECK(r->chains[2].table == "filter");
    // attribution: the rules of the first table are in `input`, none in `forward`
    CHECK(r->rules[0].chain == "input");
    for (const auto& rule : r->rules)
        CHECK(rule.chain == "input");
}

TEST_CASE("parse_nft_ruleset_text: empty text is no chains and no rules, and a listing it cannot read is nullopt",
          "[firewall]") {
    const auto none = parse_nft_ruleset_text("");
    REQUIRE(none.has_value());
    CHECK(none->chains.empty());
    CHECK(none->rules.empty());
    const auto only_comments = parse_nft_ruleset_text("# Warning: nothing here\n\n   \n");
    REQUIRE(only_comments.has_value());
    CHECK(only_comments->chains.empty());
    CHECK(only_comments->rules.empty());
    // cut mid-block
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"));
    CHECK_FALSE(parse_nft_ruleset_text(kNftOne.substr(0, kNftOne.size() - 2))); // the closing brace gone
    // an unknown family, top-level junk, a table header that is not one
    CHECK_FALSE(parse_nft_ruleset_text("table nonsense filter { # handle 1\n}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("junk\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter extra { # handle 1\n}\n"));
    // a rule line without a handle (a listing without -a must never undercount)
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter {\n\tchain input {\n\t\ttype filter hook input priority "
                                       "filter; policy accept;\n\t\ttcp dport 22 accept\n\t}\n}\n"));
    // a multi-line rule that closes without a handle
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\ttcp dport {\n\t\t\t80, 443\n\t\t} accept\n\t}\n}\n"));
    // an unknown object header or a chain header of another shape fails closed
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tmystery thing { # handle 2\n\t}\n}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain a b { # handle 2\n\t}\n}\n"));
    // a base chain whose policy the parser does not know is never read as no content: an unknown policy
    // word and a hook line with no policy clause both fail closed
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\ttype filter hook input priority filter; policy reject;\n\t}\n}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\ttype filter hook input priority filter;\n\t}\n}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\ttype filter hook input priority filter; policy\n\t}\n}\n"));
    // more closing braces than opening ones
    CHECK_FALSE(parse_nft_ruleset_text("}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n}\n}\n"));
    // a quote that never closes, and a handle that does not fit 64 bits
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\tiif \"lo accept # handle 4\n\t}\n}\n"));
    CHECK_FALSE(parse_nft_ruleset_text("table inet filter { # handle 1\n\tchain input { # handle 1\n"
                                       "\t\ttcp dport 22 accept # handle 99999999999999999999999\n\t}\n}\n"));
}

TEST_CASE("parse_nft_ruleset_text: a brace or a handle inside a quoted comment changes nothing", "[firewall]") {
    const auto r = parse_nft_ruleset_text(
        "table inet filter { # handle 1\n"
        "\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\ttcp dport 22 accept comment \"open { brace # handle 9\" # handle 4\n"
        "\t\ttcp dport 80 accept comment \"} close\" # handle 5\n"
        "\t}\n"
        "}\n");
    REQUIRE(r.has_value());
    REQUIRE(r->rules.size() == 2);
    CHECK(r->rules[0].handle == std::optional<std::uint64_t>{4});
    CHECK(r->rules[1].handle == std::optional<std::uint64_t>{5});
    // a quoted name is a name, with its spaces
    const auto q = parse_nft_ruleset_text("table inet \"my table\" { # handle 1\n\tchain c { # handle 2\n\t}\n}\n");
    REQUIRE(q.has_value());
    REQUIRE(q->chains.size() == 1);
    CHECK(q->chains[0].table == "my table");
}

TEST_CASE("parse_nft_ruleset_text: arp and netdev chains parse and leave the verdict to policy and rules",
          "[firewall]") {
    const auto r = parse_nft_ruleset_text(
        "table arp filter { # handle 1\n"
        "\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t}\n"
        "}\n"
        "table netdev filter { # handle 2\n"
        "\tchain ingress { # handle 1\n"
        "\t\ttype filter hook ingress device \"lo\" priority filter; policy accept;\n"
        "\t}\n"
        "}\n");
    REQUIRE(r.has_value());
    REQUIRE(r->chains.size() == 2);
    CHECK(r->chains[0].family == nft_raw::kNfprotoArp);
    CHECK(r->chains[1].family == nft_raw::kNfprotoNetdev);
    CHECK(r->chains[1].is_base_chain);
    CHECK_FALSE(r->chains[1].hooknum.has_value()); // ingress is not one of the five inet hooks
    CHECK(nft_decide_state(true, true, r->chains, r->rules) == NftVerdict::inactive);
    // a drop policy on any of them is content, whatever its hook is called
    const auto drop = parse_nft_ruleset_text(
        "table netdev filter { # handle 2\n\tchain ingress { # handle 1\n"
        "\t\ttype filter hook ingress device \"lo\" priority filter; policy drop;\n\t}\n}\n");
    REQUIRE(drop.has_value());
    CHECK(nft_decide_state(true, true, drop->chains, drop->rules) == NftVerdict::active);
}

TEST_CASE("parse_nft_ruleset_text: the table-level lines nft prints (flags, comment) are properties, not "
          "rules",
          "[firewall]") {
    // nft's table_print_options writes `\tflags <names>` and `\tcomment "<text>"` with no semicolon
    const auto with = [](std::string_view property) {
        return "table inet filter { # handle 1\n" + std::string{property} +
               "\n\tchain input { # handle 2\n\t\ttype filter hook input priority filter; policy accept;\n"
               "\t\taccept # handle 3\n\t}\n}\n";
    };
    for (const std::string_view property :
         {"\tflags owner,persist", "\tflags dormant", "\tflags dormant,owner,persist",
          "\tcomment \"managed by the host\"", "\tcomment \"a # handle 9 { b } c\""}) {
        INFO(property);
        const auto r = parse_nft_ruleset_text(with(property));
        REQUIRE(r.has_value());
        REQUIRE(r->chains.size() == 1);
        REQUIRE(r->rules.size() == 1);
        CHECK(r->rules[0].handle == std::optional<std::uint64_t>{3});
    }
    // both lines, in nft's order, ahead of a named set
    const auto both = parse_nft_ruleset_text(
        "table inet filter { # handle 1\n\tflags owner,persist\n\tcomment \"x\"\n\tset s { # handle 2\n"
        "\t\ttype ipv4_addr\n\t}\n}\n");
    REQUIRE(both.has_value());
    CHECK(both->rules.empty());
    // any other table-level line fails closed: it could hide a rule
    for (const std::string_view bad :
         {"\tflags", "\tflags a b", "\tflags dormant {", "\tflags {a}", "\tflags owner # handle 7",
          "\tcomment hello", "\tcomment \"a\" \"b\"", "\tcomment", "\tmystery;",
          "\tcounter packets 1 bytes 2 # handle 9"}) {
        INFO(bad);
        CHECK_FALSE(parse_nft_ruleset_text(with(bad)));
    }
}

TEST_CASE("parse_nft_ruleset_text: objects, sets, maps and rules shaped as nft prints them", "[firewall]") {
    // built from the nftables printer rules (src/rule.c, src/expression.c, src/statement.c), not from a
    // host: a tunnel (nft 1.1.x), counter, quota, limit and ct objects, a named set and a verdict map
    // with their elements wrapped over lines, an inline vmap, a rule with an anonymous `jump {` chain
    constexpr std::string_view kShapes =
        "table inet filter { # handle 1\n"
        "\tflags owner,persist\n"
        "\tcounter c1 { # handle 2\n\t\tpackets 0 bytes 0\n\t}\n"
        "\tquota q1 { # handle 3\n\t\tover 25 mbytes used 0 bytes\n\t}\n"
        "\tlimit l1 { # handle 4\n\t\trate 10/second burst 5 packets\n\t}\n"
        "\tct helper h1 { # handle 5\n\t\ttype \"ftp\" protocol tcp\n\t\tl3proto inet\n\t}\n"
        "\tct timeout t1 { # handle 6\n\t\tprotocol tcp\n\t\tl3proto inet\n\t\tpolicy = { established : 120 }\n\t}\n"
        "\tsynproxy sp { # handle 7\n\t\tmss 1460 wscale 7 timestamp sack-perm\n\t}\n"
        "\ttunnel tun1 { # handle 8\n\t\tid 10\n\t\tip saddr 192.0.2.1\n\t\tip daddr 192.0.2.2\n"
        "\t\terspan {\n\t\t\tversion 1\n\t\t\tindex 0x123\n\t\t}\n\t}\n"
        "\tset blocked { # handle 9\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = {\n"
        "\t\t\t192.0.2.0/24,\n\t\t\t198.51.100.0/24\n\t\t}\n\t}\n"
        "\tmap vm { # handle 10\n\t\ttype ipv4_addr : verdict\n\t\telements = {\n"
        "\t\t\t192.0.2.1 : drop,\n\t\t\t192.0.2.2 : jump other\n\t\t}\n\t}\n"
        "\tchain other { # handle 11\n\t}\n"
        "\tchain input { # handle 12\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\tip saddr vmap { 192.0.2.1 : drop, 192.0.2.2 : accept } # handle 13\n"
        "\t\ttcp dport 22 jump {\n\t\t\tcounter packets 0 bytes 0 accept\n\t\t} # handle 14\n"
        "\t\tct helper set \"h1\" # handle 15\n"
        "\t}\n"
        "}\n";
    const auto r = parse_nft_ruleset_text(kShapes);
    REQUIRE(r.has_value());
    REQUIRE(r->chains.size() == 2);
    REQUIRE(r->rules.size() == 3);
    CHECK(r->rules[0].handle == std::optional<std::uint64_t>{13});
    CHECK(r->rules[1].handle == std::optional<std::uint64_t>{14});
    CHECK(r->rules[2].handle == std::optional<std::uint64_t>{15});
    CHECK(r->rules.size() == yuzu::test::fwrestore::count_nft_rules(kShapes));
    // the printed shapes here that no real host has shown the parser: the `tunnel` object with its nested
    // `erspan {` block, the `secmark` object header (accepted by the allow-list, in no capture and in no case
    // here) and set or map elements that open `elements = {` with nothing after the brace (the real Rocky 9.9
    // ruleset wraps them after the first element). Every other shape above is in the real rich reply below.
}

TEST_CASE("the real reply of a firewalld host reads active, with the independent rule count and the "
          "base chains it shows",
          "[firewall]") {
    const auto snapshot = parse_fw_snapshot(kFirewalldRealReply);
    REQUIRE(snapshot.has_value()); // the framing is good
    REQUIRE(snapshot->nft.kind == FwSectionKind::text);
    const auto listing = parse_nft_ruleset_text(snapshot->nft.text);
    REQUIRE(listing.has_value());
    const auto handles = yuzu::test::fwrestore::count_nft_rules(snapshot->nft.text); // an independent counter
    CHECK(handles == 103);
    CHECK(listing->rules.size() == handles);
    CHECK(listing->chains.size() == 75);

    const auto state = linux_snapshot_answer(*snapshot, false, FwReadAction::state);
    CHECK(state.state == NftVerdict::active);
    CHECK(state.rows == Rows{"backend|nftables", "state|active", "ruleset|103"});

    const auto rules = linux_snapshot_answer(*snapshot, false, FwReadAction::rules);
    CHECK(rules.state == NftVerdict::active);
    REQUIRE(rules.rows.size() == 1 + 8 + 103 + 1);
    CHECK(rules.rows.front() == "backend|nftables");
    // the eight base chains, in the order the listing prints them, covering all five hooks
    const Rows chains{"rule|nftables|inet|firewalld|mangle_PREROUTING|prerouting|accept",
                      "rule|nftables|inet|firewalld|nat_PREROUTING|prerouting|accept",
                      "rule|nftables|inet|firewalld|nat_POSTROUTING|postrouting|accept",
                      "rule|nftables|inet|firewalld|nat_OUTPUT|output|accept",
                      "rule|nftables|inet|firewalld|filter_PREROUTING|prerouting|accept",
                      "rule|nftables|inet|firewalld|filter_INPUT|input|accept",
                      "rule|nftables|inet|firewalld|filter_FORWARD|forward|accept",
                      "rule|nftables|inet|firewalld|filter_OUTPUT|output|accept"};
    CHECK(Rows(rules.rows.begin() + 1, rules.rows.begin() + 9) == chains);
    CHECK(std::count_if(rules.rows.begin(), rules.rows.end(),
                        [](const std::string& row) { return row.find("|handle|") != std::string::npos; }) == 103);
    CHECK(rules.rows.back() == "ruleset|103");
    // a table the netlink leg saw changes nothing about an active answer
    CHECK(linux_snapshot_answer(*snapshot, true, FwReadAction::state).rows == state.rows);
}

TEST_CASE("the real rich ruleset of a firewalld host reads active, with every rule counted",
          "[firewall]") {
    const auto snapshot = parse_fw_snapshot(kRichRealReply);
    REQUIRE(snapshot.has_value()); // the framing is good
    REQUIRE(snapshot->nft.kind == FwSectionKind::text);
    const auto listing = parse_nft_ruleset_text(snapshot->nft.text); // the whole listing, no line unrecognised
    REQUIRE(listing.has_value());
    const auto handles = yuzu::test::fwrestore::count_nft_rules(snapshot->nft.text); // an independent counter
    CHECK(handles == 215);
    CHECK(listing->rules.size() == handles);

    const auto state = linux_snapshot_answer(*snapshot, false, FwReadAction::state);
    CHECK(state.state == NftVerdict::active);
    CHECK(state.rows == Rows{"backend|nftables", "state|active", "ruleset|215"});

    const auto rules = linux_snapshot_answer(*snapshot, false, FwReadAction::rules);
    CHECK(rules.state == NftVerdict::active);
    CHECK(std::count_if(rules.rows.begin(), rules.rows.end(),
                        [](const std::string& row) { return row.find("|handle|") != std::string::npos; }) == 215);
    CHECK(rules.rows.back() == "ruleset|215");
}

TEST_CASE("the text parser and the netlink formatters name families, hooks and policies alike", "[firewall]") {
    // the two directions are kept by hand: pin them against each other
    for (const std::string_view name : {"ip", "ip6", "inet", "arp", "bridge", "netdev"}) {
        INFO(name);
        const auto family = detail::nft_text_family(name);
        REQUIRE(family.has_value());
        CHECK(nft_family_name(*family) == name);
    }
    CHECK_FALSE(detail::nft_text_family("unspec")); // nft never lists it, and the text parser must not accept it
    CHECK_FALSE(detail::nft_text_family("family7"));
    // one table with a base chain per hook and a drop policy, then the same with accept: each row
    // names the hook and the policy the listing text says
    for (const std::string_view policy : {"accept", "drop"}) {
        std::string text = "table ip t { # handle 1\n";
        for (const std::string_view hook : {"prerouting", "input", "forward", "output", "postrouting"})
            text += std::format("\tchain c_{0} {{ # handle 2\n\t\ttype filter hook {0} priority filter; policy {1};\n\t}}\n",
                                hook, policy);
        text += "}\n";
        const auto r = rules_rows(text, kTablesNone, kTablesNone);
        Rows want{"backend|nftables"};
        for (const std::string_view hook : {"prerouting", "input", "forward", "output", "postrouting"})
            want.push_back(std::format("rule|nftables|ip|t|c_{0}|{0}|{1}", hook, policy));
        want.emplace_back("ruleset|0");
        CHECK(r == want); // a drop policy is content (active) and accept is not (inactive): the same rows
    }
}

TEST_CASE("iptables_summary and format_iptables_rule_row: content, shape and the IPv4 and IPv6 row forms",
          "[firewall]") {
    const auto clean = iptables_summary(kIptClean);
    CHECK(clean.shaped);
    CHECK_FALSE(clean.has_content);
    CHECK(clean.append_count == 0);
    CHECK(iptables_summary(kIptV6Rules).has_content); // a DROP policy
    CHECK(iptables_summary(kIptV6Rules).append_count == 1);
    CHECK(iptables_summary("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N chain\n").has_content);
    CHECK(iptables_summary("-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n").has_content);
    // an unknown line is content and is not in a known shape
    const auto odd = iptables_summary("-P INPUT ACCEPT\nsurprise\n");
    CHECK_FALSE(odd.shaped);
    CHECK(odd.has_content);
    CHECK_FALSE(iptables_summary("").shaped);

    const auto rules = parse_iptables_save("-P INPUT DROP\n-N c\n-A INPUT -p tcp -j c\nsurprise|x\n");
    REQUIRE(rules.size() == 4);
    // today's bytes for IPv4
    CHECK(format_iptables_rule_row(rules[0], false) == "rule|policy|INPUT|DROP");
    CHECK(format_iptables_rule_row(rules[1], false) == "rule|new_chain|c|");
    CHECK(format_iptables_rule_row(rules[2], false) == "rule|append|INPUT|-p tcp -j c");
    CHECK(format_iptables_rule_row(rules[3], false) == "rule|unknown||surprise_x");
    // IPv6 carries `ip6` ahead of the kind, which is none of the four kinds
    CHECK(format_iptables_rule_row(rules[0], true) == "rule|ip6|policy|INPUT|DROP");
    CHECK(format_iptables_rule_row(rules[2], true) == "rule|ip6|append|INPUT|-p tcp -j c");
}

namespace {

/// Whether a listing that must be shaped holds content.
bool legacy_save_content(std::string_view text) {
    const auto listing = parse_iptables_legacy_save(text);
    REQUIRE(listing.has_value());
    return listing->has_content;
}

} // namespace

TEST_CASE("parse_iptables_legacy_save: tables, chains and appends as iptables-save prints them", "[firewall]") {
    const auto clean = parse_iptables_legacy_save(kSaveClean);
    REQUIRE(clean.has_value());
    CHECK(clean->shaped);
    CHECK_FALSE(clean->has_content); // three ACCEPT policies and nothing else
    CHECK(clean->append_count == 0);
    REQUIRE(clean->entries.size() == 3);
    CHECK(clean->entries[0].table.empty()); // the filter table carries no table name
    CHECK(clean->entries[0].type == IptablesEntryType::policy);
    CHECK(clean->entries[0].chain == "INPUT");
    CHECK(clean->entries[0].spec == "ACCEPT");

    const auto v6 = parse_iptables_legacy_save(kSaveV6Rules);
    REQUIRE(v6.has_value());
    CHECK(v6->has_content); // a DROP policy and a rule
    CHECK(v6->append_count == 1);
    CHECK(v6->entries.back().type == IptablesEntryType::append);
    CHECK(v6->entries.back().spec == "-p tcp -m tcp --dport 22 -j ACCEPT");

    // the tables the `-S` read never showed: every table's appends are counted
    const auto raw = parse_iptables_legacy_save(kSaveRawMangle);
    REQUIRE(raw.has_value());
    CHECK(raw->has_content);
    CHECK(raw->append_count == 2);
    CHECK(raw->entries.front().table == "raw");
    CHECK(raw->entries.back().table == "mangle");

    // a user-defined chain is content (`-` is no policy); a bare `-A <chain>` is a rule with no spec
    const auto user = parse_iptables_legacy_save("*filter\n:INPUT ACCEPT [0:0]\n:LAB - [0:0]\nCOMMIT\n");
    REQUIRE(user.has_value());
    CHECK(user->has_content);
    CHECK(user->entries.back().type == IptablesEntryType::new_chain);
    CHECK(user->entries.back().chain == "LAB");
    const auto bare = parse_iptables_legacy_save("*nat\n:OUTPUT ACCEPT [3:180]\n-A OUTPUT\nCOMMIT\n");
    REQUIRE(bare.has_value());
    CHECK(bare->append_count == 1);
    CHECK(bare->entries.back().spec.empty());
    // counters are parsed and never read: a non-zero counter beside an ACCEPT policy is no content
    CHECK_FALSE(legacy_save_content("*filter\n:INPUT ACCEPT [10:2000]\nCOMMIT\n"));
    // a policy other than ACCEPT is content, whatever the word
    CHECK(legacy_save_content("*filter\n:INPUT DROP [0:0]\nCOMMIT\n"));
    CHECK(legacy_save_content("*filter\n:INPUT QUEUE [0:0]\nCOMMIT\n"));
    // empty and comment lines are skipped, inside a table as well; empty text is a family with no table
    const auto noise = parse_iptables_legacy_save("# a\n\n*filter\n# b\n\n:INPUT ACCEPT [0:0]\nCOMMIT\n\n# c\n");
    REQUIRE(noise.has_value());
    CHECK(noise->entries.size() == 1);
    const auto none = parse_iptables_legacy_save("");
    REQUIRE(none.has_value());
    CHECK(none->entries.empty());
    CHECK_FALSE(none->has_content);
    const auto comment_only = parse_iptables_legacy_save("# Generated by iptables-save v1.8.11 on x\n");
    REQUIRE(comment_only.has_value());
    CHECK(comment_only->entries.empty());
}

TEST_CASE("parse_iptables_legacy_save: anything that is not a listing in shape is nullopt", "[firewall]") {
    const std::vector<std::string> unshaped{
        "surprise\n",                                          // not a save line
        "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n",                // the `-S` form is not this listing
        ":INPUT ACCEPT [0:0]\n",                               // a chain outside a table
        "-A INPUT -j ACCEPT\n",                                // an append outside a table
        "COMMIT\n",                                            // a close outside a table
        "*filter\n*nat\n:INPUT ACCEPT [0:0]\nCOMMIT\n",        // a table inside a table
        "*filter\n:INPUT ACCEPT [0:0]\n",                      // cut inside a table
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACC",       // cut mid-line
        "*filter\n:INPUT ACCEPT\nCOMMIT\n",                    // no counters
        "*filter\n:INPUT ACCEPT [0:0] extra\nCOMMIT\n",        // a fourth token
        "*filter\n:INPUT  ACCEPT [0:0]\nCOMMIT\n",             // an empty token
        "*filter\n: ACCEPT [0:0]\nCOMMIT\n",                   // no chain name
        "*filter\n:INPUT ACCEPT [0:]\nCOMMIT\n",               // counters without bytes
        "*filter\n:INPUT ACCEPT [:0]\nCOMMIT\n",               // counters without packets
        "*filter\n:INPUT ACCEPT [a:b]\nCOMMIT\n",              // counters that are not digits
        "*filter\n:INPUT ACCEPT 0:0\nCOMMIT\n",                // counters without brackets
        "*filter\n-A\nCOMMIT\n",                               // an append with no chain
        "*filter\n-A  INPUT\nCOMMIT\n",                        // an append with an empty chain
        "*filter\n[1:60] -A INPUT -j ACCEPT\nCOMMIT\n",        // a counted append (-c output)
        "*filter\nsurprise\nCOMMIT\n",                         // an unknown line in a table
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\r\n",            // a carriage return is not a COMMIT
        "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT trailing\n",     //
        " *filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",             // an indented table line
        "*filter\n \n:INPUT ACCEPT [0:0]\nCOMMIT\n",           // a line of only blanks is not an empty line
        "*\n:INPUT ACCEPT [0:0]\nCOMMIT\n",                    // an empty table name
        "*Filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",              // names the kernel does not have
        "*fil-ter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*my_table2\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*ip6\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*policy\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*append\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*firewalld\n:INPUT ACCEPT [0:0]\nCOMMIT\n",           // another backend's word as a table
        "*nftables\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*filter COMMIT\n",
        // a repeated table block would double the count
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        "*raw\nCOMMIT\n*nat\nCOMMIT\n*raw\nCOMMIT\n",
        // a newline inside a rule comment leaves its line open: the rest is never read as further lines
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"x\nCOMMIT\n*firewalld\n"
        "-A public -j service_ssh\n\" -j ACCEPT\nCOMMIT\n",
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"open\nCOMMIT\n",
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"escaped quote\\\" -j ACCEPT\nCOMMIT\n",
        "*filter\n:IN\"PUT ACCEPT [0:0]\nCOMMIT\n", // an open quote on a chain line
        // a double quote in a field the tool prints outside quotes leaves the line open
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -i a\"b -j DROP\nCOMMIT\n",
    };
    for (const auto& text : unshaped) {
        INFO(text);
        CHECK_FALSE(parse_iptables_legacy_save(text).has_value());
    }
    // the five tables the kernel has are fine, each once
    for (const char* name : {"filter", "nat", "mangle", "raw", "security"})
        CHECK(parse_iptables_legacy_save(std::string{"*"} + name + "\n:INPUT ACCEPT [0:0]\nCOMMIT\n").has_value());
    CHECK(parse_iptables_legacy_save("*filter\nCOMMIT\n*nat\nCOMMIT\n*mangle\nCOMMIT\n*raw\nCOMMIT\n*security\nCOMMIT\n")
              .has_value());
}

TEST_CASE("parse_iptables_legacy_save: quotes close as iptables-save writes them", "[firewall]") {
    // the tool escapes the double quote and the backslash inside a comment: both stay one line
    const auto escaped = parse_iptables_legacy_save(
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -m comment --comment \"say \\\"hi\\\" \\\\\" -j ACCEPT\n"
        "-A INPUT -m comment --comment \"a\tb\" -j ACCEPT\n"
        "-A INPUT -m comment --comment \"a#b *c COMMIT\" -j ACCEPT\nCOMMIT\n");
    REQUIRE(escaped.has_value());
    CHECK(escaped->append_count == 3);
    CHECK(escaped->entries.back().spec == "-m comment --comment \"a#b *c COMMIT\" -j ACCEPT");
    // a newline in a field the tool prints outside quotes reads as a line break: it adds a line and
    // a count, and never removes one
    const auto split = parse_iptables_legacy_save(
        "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -i a\n-A INPUT -j DROP\nCOMMIT\n");
    REQUIRE(split.has_value());
    CHECK(split->has_content);
    CHECK(split->append_count == 2);
    // a backslash outside quotes is nothing special, and a single quote is no quote
    CHECK(parse_iptables_legacy_save("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment it's -j ACCEPT\n"
                                     "COMMIT\n")
              .has_value());
}

TEST_CASE("format_iptables_rule_row: the filter table keeps the -S row form, any other table is named",
          "[firewall]") {
    const auto listing = parse_iptables_legacy_save(
        "*filter\n:INPUT DROP [0:0]\n:LAB - [0:0]\n-A INPUT -p tcp -j LAB\nCOMMIT\n"
        "*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -s 192.0.2.1/32 -j DROP\nCOMMIT\n"
        "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n");
    REQUIRE(listing.has_value());
    REQUIRE(listing->entries.size() == 6);
    const auto& e = listing->entries;
    // filter rows are the bytes the `-S` reads write
    CHECK(format_iptables_rule_row(e[0], false) == "rule|policy|INPUT|DROP");
    CHECK(format_iptables_rule_row(e[1], false) == "rule|new_chain|LAB|");
    CHECK(format_iptables_rule_row(e[2], false) == "rule|append|INPUT|-p tcp -j LAB");
    CHECK(format_iptables_rule_row(e[0], true) == "rule|ip6|policy|INPUT|DROP");
    // another table's name stands before the kind, and after `ip6` for IPv6
    CHECK(format_iptables_rule_row(e[3], false) == "rule|raw|policy|PREROUTING|ACCEPT");
    CHECK(format_iptables_rule_row(e[4], false) == "rule|raw|append|PREROUTING|-s 192.0.2.1/32 -j DROP");
    CHECK(format_iptables_rule_row(e[5], true) == "rule|ip6|mangle|policy|FORWARD|ACCEPT");
    // chain and spec are echoed, so they are sanitised
    IptablesRule hostile;
    hostile.type = IptablesEntryType::append;
    hostile.chain = "A|B";
    hostile.spec = "x|y";
    CHECK(format_iptables_rule_row(hostile, false) == "rule|append|A_B|x_y");
}

TEST_CASE("format_iptables_rule_row: no legacy row's second field is another backend's word", "[firewall]") {
    // every table the parser admits, with chain and rule text that tries to look like another backend's row
    const auto listing = parse_iptables_legacy_save(
        "*filter\n:INPUT ACCEPT [0:0]\n:firewalld - [0:0]\n-A INPUT -m comment --comment \"nftables\" -j ACCEPT\nCOMMIT\n"
        "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j DNAT --to-destination 192.0.2.1\nCOMMIT\n"
        "*mangle\n:FORWARD ACCEPT [0:0]\n-A FORWARD -j MARK --set-mark 1\nCOMMIT\n"
        "*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j NOTRACK\nCOMMIT\n"
        "*security\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -j ACCEPT\nCOMMIT\n");
    REQUIRE(listing.has_value());
    const std::vector<std::string> second_field{"nat", "mangle", "raw", "security", "policy", "new_chain", "append",
                                                "unknown"};
    for (const bool ip6 : {false, true}) {
        for (const auto& entry : listing->entries) {
            const auto row = format_iptables_rule_row(entry, ip6);
            INFO(row);
            // after `rule|` (`rule|ip6|` for IPv6) comes one of the eight words, no backend's
            const std::string head = ip6 ? "rule|ip6|" : "rule|";
            CHECK(std::any_of(second_field.begin(), second_field.end(), [&](const std::string& w) {
                return row.starts_with(head + w + "|");
            }));
        }
    }
}

TEST_CASE("linux_snapshot rule 1: the state is active, unknown or inactive by what was read", "[firewall]") {
    const std::string no_content =
        "table inet filter { # handle 1\n\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
    const std::string cut = "table inet filter { # handle 1\n"; // not closed
    // active: any READ section with content, whatever the others say
    CHECK(snapshot_answer(kNftOne, kSaveClean, kSaveClean, false, FwReadAction::state).state == NftVerdict::active);
    CHECK(snapshot_answer(kNftOne, kFailed, kAbsent, false, FwReadAction::state).state == NftVerdict::active);
    CHECK(snapshot_answer(no_content, kSaveV6Rules, kTablesNone, false, FwReadAction::state).state ==
          NftVerdict::active);
    CHECK(snapshot_answer(no_content, kTablesNone, kSaveRawMangle, false, FwReadAction::state).state ==
          NftVerdict::active);
    // a base chain with a drop policy and no rule is content
    const std::string drop =
        "table inet filter { # handle 1\n\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n";
    CHECK(state_rows(drop, kTablesNone, kTablesNone) == Rows{"backend|nftables", "state|active", "ruleset|0"});
    // unknown: nothing has content and a section was not read
    CHECK(snapshot_answer(no_content, kFailed, kSaveClean, false, FwReadAction::state).state == NftVerdict::unknown);
    CHECK(snapshot_answer(cut, kSaveClean, kSaveClean, false, FwReadAction::state).state == NftVerdict::unknown);
    CHECK(snapshot_answer(kFailed, kSaveClean, kSaveClean, false, FwReadAction::state).state == NftVerdict::unknown);
    CHECK(snapshot_answer(no_content, kTablesFilter, kTablesNone, false, FwReadAction::state).state ==
          NftVerdict::unknown);
    CHECK(snapshot_answer(no_content, kTablesNone, "surprise\n", false, FwReadAction::state).state ==
          NftVerdict::unknown);
    // inactive: all three read and none has content; a table the netlink leg saw makes it unknown
    CHECK(snapshot_answer(no_content, kSaveClean, kSaveClean, false, FwReadAction::state).state ==
          NftVerdict::inactive);
    CHECK(snapshot_answer("", kTablesNone, kTablesNone, false, FwReadAction::state).state == NftVerdict::inactive);
    CHECK(snapshot_answer("", "", "", false, FwReadAction::state).state == NftVerdict::inactive); // tools ran, no table
    CHECK(snapshot_answer("", kTablesNone, kTablesNone, true, FwReadAction::state).state == NftVerdict::unknown);
    // an active reading is never downgraded by it
    CHECK(snapshot_answer(kNftOne, kSaveClean, kSaveClean, true, FwReadAction::state).state == NftVerdict::active);
}

TEST_CASE("linux_snapshot rule 2: a count is the sum of nft and legacy rules, and only when all three were read",
          "[firewall]") {
    // nft 2 rules + IPv4 0 + IPv6 1 append
    CHECK(state_rows(kNftOne, kSaveClean, kSaveV6Rules) == Rows{"backend|nftables", "state|active", "ruleset|3"});
    CHECK(state_rows("", kSaveRawMangle, kSaveV6Rules) == Rows{"backend|iptables", "state|active", "ruleset|3"});
    CHECK(state_rows("", kSaveClean, kSaveClean) == Rows{"backend|nftables", "state|inactive", "ruleset|0"});
    // any section unread: no count, even beside content
    CHECK(state_rows(kNftOne, kFailed, kSaveClean) ==
          Rows{"backend|nftables", "state|active", "ruleset|unknown", "error|iptables:snapshot:failed"});
    CHECK(state_rows(kNftOne, kSaveClean, kTablesFilter) ==
          Rows{"backend|nftables", "state|active", "ruleset|unknown", "error|ip6tables:snapshot:absent"});
    CHECK(state_rows(kNftOne, kSaveClean, "surprise\n") ==
          Rows{"backend|nftables", "state|active", "ruleset|unknown", "error|ip6tables:unrecognised_output"});
    // a clamped state carries no count
    CHECK(state_rows("", kTablesNone, kTablesNone, true) ==
          Rows{"backend|nftables", "state|unknown", "ruleset|unknown"});
}

TEST_CASE("linux_snapshot rule 3: the backend is iptables only when a legacy section has content and nft has none",
          "[firewall]") {
    CHECK(state_rows("", kSaveClean, kSaveV6Rules).front() == "backend|iptables");
    CHECK(state_rows("", kSaveRawMangle, kTablesNone).front() == "backend|iptables");
    CHECK(state_rows(kNftOne, kSaveClean, kSaveV6Rules).front() == "backend|nftables"); // nft has content too
    CHECK(state_rows(kFailed, kSaveClean, kSaveV6Rules).front() == "backend|iptables"); // nft unread, no content
    CHECK(state_rows("", kSaveClean, kSaveClean).front() == "backend|nftables");        // nothing anywhere
    CHECK(state_rows("", kFailed, kSaveClean).front() == "backend|nftables");           // legacy without content
}

TEST_CASE("linux_snapshot rule 4: rules lists every read section, and rules|unknown exactly when the state is unknown",
          "[firewall]") {
    // nft base chains, then rule handles, then IPv4 entries, then IPv6 entries, then the count
    CHECK(rules_rows(kNftOne, kSaveClean, kSaveV6Rules) ==
          Rows{"backend|nftables", "rule|nftables|inet|filter|input|input|accept",
               "rule|nftables|inet|filter|input|handle|4", "rule|nftables|inet|filter|input|handle|5",
               "rule|policy|INPUT|ACCEPT", "rule|policy|FORWARD|ACCEPT", "rule|policy|OUTPUT|ACCEPT",
               "rule|ip6|policy|INPUT|DROP", "rule|ip6|policy|FORWARD|ACCEPT", "rule|ip6|policy|OUTPUT|ACCEPT",
               "rule|ip6|append|INPUT|-p tcp -m tcp --dport 22 -j ACCEPT", "ruleset|3"});
    // a legacy table other than filter carries its name
    CHECK(rules_rows("", kSaveRawMangle, kTablesNone) ==
          Rows{"backend|iptables", "rule|raw|policy|PREROUTING|ACCEPT", "rule|raw|policy|OUTPUT|ACCEPT",
               "rule|raw|append|PREROUTING|-s 192.0.2.1/32 -j DROP", "rule|mangle|policy|PREROUTING|ACCEPT",
               "rule|mangle|policy|INPUT|ACCEPT", "rule|mangle|policy|FORWARD|ACCEPT",
               "rule|mangle|policy|OUTPUT|ACCEPT", "rule|mangle|policy|POSTROUTING|ACCEPT",
               "rule|mangle|append|POSTROUTING|-o lo -j ACCEPT", "ruleset|2"});
    CHECK(rules_rows("", kTablesNone, kSaveRawMangle).at(1) == "rule|ip6|raw|policy|PREROUTING|ACCEPT");
    // no table, nothing listed, and no unknown row: the family was read
    CHECK(rules_rows("", kTablesNone, kTablesNone) == Rows{"backend|nftables", "ruleset|0"});
    // unknown: the read sections' rows stay, then `rules|unknown`, then the unknown count and the errors
    CHECK(rules_rows(kFailed, kSaveClean, kSaveClean) ==
          Rows{"backend|nftables", "rule|policy|INPUT|ACCEPT", "rule|policy|FORWARD|ACCEPT",
               "rule|policy|OUTPUT|ACCEPT", "rule|ip6|policy|INPUT|ACCEPT", "rule|ip6|policy|FORWARD|ACCEPT",
               "rule|ip6|policy|OUTPUT|ACCEPT", "rules|unknown", "ruleset|unknown", "error|nftables:snapshot:failed"});
    CHECK(rules_rows(kFailed, kFailed, kFailed) ==
          Rows{"backend|nftables", "rules|unknown", "ruleset|unknown", "error|nftables:snapshot:failed",
               "error|iptables:snapshot:failed", "error|ip6tables:snapshot:failed"});
    // a clamped state lists nothing
    CHECK(rules_rows("", kSaveClean, kTablesNone, true) ==
          Rows{"backend|nftables", "rules|unknown", "ruleset|unknown"});
    // a hostile name echoed into a row is sanitised
    const std::string hostile =
        "table inet \"a|b\" { # handle 1\n\tchain \"c|d\" { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\taccept # handle 7\n\t}\n}\n";
    const auto rows = rules_rows(hostile, kTablesNone, kTablesNone);
    REQUIRE(rows.size() == 4);
    CHECK(rows[1] == "rule|nftables|inet|a_b|c_d|input|accept");
    CHECK(rows[2] == "rule|nftables|inet|a_b|c_d|handle|7");
}

TEST_CASE("linux_snapshot rule 5: one error row per unread section, last and in section order", "[firewall]") {
    const std::string cut = "table inet filter { # handle 1\n";
    CHECK(state_rows(cut, kFailed, kTablesFilter) ==
          Rows{"backend|nftables", "state|unknown", "ruleset|unknown", "error|nftables:unrecognised_output",
               "error|iptables:snapshot:failed", "error|ip6tables:snapshot:absent"});
    CHECK(state_rows(kNftOne, "surprise\n", kAbsent) ==
          Rows{"backend|nftables", "state|active", "ruleset|unknown", "error|iptables:unrecognised_output",
               "error|ip6tables:snapshot:absent"});
    // a read section writes no error row
    CHECK(state_rows(kNftOne, kSaveClean, kTablesNone) == Rows{"backend|nftables", "state|active", "ruleset|2"});
    // `[tables]` followed by a name is unread and names its cause: tables exist that nothing listed
    CHECK(state_rows("", kTablesFilter, kTablesNone) ==
          Rows{"backend|nftables", "state|unknown", "ruleset|unknown", "error|iptables:snapshot:absent"});
}

TEST_CASE("linux_snapshot rule 6: nft not installed and nothing read with content declines, naming the cause",
          "[firewall]") {
    // an absent nft is no evidence of an empty nf_tables ruleset: never inactive, never a count
    for (const auto action : {FwReadAction::state, FwReadAction::rules}) {
        const auto a = snapshot_answer(kAbsent, kTablesNone, kTablesNone, false, action);
        CHECK(a.declined);
        CHECK(a.rows == Rows{"error|nftables:snapshot:absent"});
        CHECK(snapshot_answer(kAbsent, kSaveClean, kSaveClean, true, action).declined);
        CHECK(snapshot_answer(kAbsent, kSaveClean, kSaveClean, false, action).declined);
    }
    // every unread section is named, and no backend row is written
    CHECK(snapshot_answer(kAbsent, kFailed, kTablesFilter, false, FwReadAction::state).rows ==
          Rows{"error|nftables:snapshot:absent", "error|iptables:snapshot:failed", "error|ip6tables:snapshot:absent"});
    // a legacy section that was read and has content answers, with an unknown count and the cause
    CHECK_FALSE(snapshot_answer(kAbsent, kSaveClean, kSaveV6Rules, false, FwReadAction::state).declined);
    CHECK(state_rows(kAbsent, kSaveClean, kSaveV6Rules) ==
          Rows{"backend|iptables", "state|active", "ruleset|unknown", "error|nftables:snapshot:absent"});
    CHECK(rules_rows(kAbsent, kSaveRawMangle, kTablesNone).front() == "backend|iptables");
    CHECK(rules_rows(kAbsent, kSaveRawMangle, kTablesNone).back() == "error|nftables:snapshot:absent");
    // a failed nft is not absent: it does not decline
    CHECK_FALSE(snapshot_answer(kFailed, kTablesNone, kTablesNone, false, FwReadAction::state).declined);
    CHECK_FALSE(snapshot_answer(kNftOne, kTablesNone, kTablesNone, false, FwReadAction::state).declined);
}

TEST_CASE("linux_snapshot_answer: a section kind the framing parser cannot make is unread", "[firewall]") {
    // built directly: nft as `tables`, which the framing parser makes only for a legacy section
    FwSnapshot snap_tables;
    snap_tables.nft = FwSnapshotSection{FwSectionKind::tables, {}};
    snap_tables.iptables = FwSnapshotSection{FwSectionKind::text, std::string{kSaveClean}};
    snap_tables.ip6tables = FwSnapshotSection{FwSectionKind::text, std::string{kSaveClean}};
    for (const auto action : {FwReadAction::state, FwReadAction::rules}) {
        const auto a = linux_snapshot_answer(snap_tables, false, action);
        CHECK(a.state == NftVerdict::unknown);
        CHECK_FALSE(a.declined);
        CHECK(a.rows.back() == "error|nftables:unrecognised_output");
    }
    // a failed section that kept text, an absent one that kept text: only the kind counts
    FwSnapshot kept;
    kept.nft = FwSnapshotSection{FwSectionKind::failed, std::string{kNftOne}};
    kept.iptables = FwSnapshotSection{FwSectionKind::absent, std::string{kSaveV6Rules}};
    kept.ip6tables = FwSnapshotSection{FwSectionKind::tables, "filter\n"};
    const auto a = linux_snapshot_answer(kept, false, FwReadAction::state);
    CHECK(a.state == NftVerdict::unknown);
    CHECK(a.rows == Rows{"backend|nftables", "state|unknown", "ruleset|unknown", "error|nftables:snapshot:failed",
                         "error|iptables:snapshot:absent", "error|ip6tables:snapshot:absent"});
}

namespace {

/// One section body and what it vouches for, written down here so the sweep below does not borrow
/// the decision's own reading of it.
struct SectionCase {
    std::string_view body;
    bool read;
    bool content;
    std::size_t rules; // meaningful when read
    std::string_view error; // the row an unread section writes
};

} // namespace

TEST_CASE("linux_snapshot_answer: the properties hold over every combination of sections", "[firewall]") {
    static const std::string cut = "table inet filter { # handle 1\n";
    static const std::string no_content =
        "table inet filter { # handle 1\n\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
    const std::array<SectionCase, 6> nfts{{
        {kAbsent, false, false, 0, "error|nftables:snapshot:absent"},
        {kFailed, false, false, 0, "error|nftables:snapshot:failed"},
        {cut, false, false, 0, "error|nftables:unrecognised_output"},
        {kNftOne, true, true, 2, ""},
        {"", true, false, 0, ""},
        {no_content, true, false, 0, ""},
    }};
    const auto legacy = [](std::string_view absent_row, std::string_view failed_row, std::string_view bad_row) {
        return std::array<SectionCase, 9>{{
            {kAbsent, false, false, 0, absent_row},
            {kFailed, false, false, 0, failed_row},
            {kTablesFilter, false, false, 0, absent_row},
            {"surprise\n", false, false, 0, bad_row},
            {kTablesNone, true, false, 0, ""},
            {"", true, false, 0, ""},
            {kSaveClean, true, false, 0, ""},
            {kSaveV6Rules, true, true, 1, ""},
            {kSaveRawMangle, true, true, 2, ""},
        }};
    };
    const auto ipt4 = legacy("error|iptables:snapshot:absent", "error|iptables:snapshot:failed",
                             "error|iptables:unrecognised_output");
    const auto ipt6 = legacy("error|ip6tables:snapshot:absent", "error|ip6tables:snapshot:failed",
                             "error|ip6tables:unrecognised_output");
    const auto has = [](const Rows& rows, std::string_view row) {
        return std::find(rows.begin(), rows.end(), row) != rows.end();
    };
    std::size_t combinations = 0;
    for (const auto& n : nfts) {
        for (const auto& i4 : ipt4) {
            for (const auto& i6 : ipt6) {
                for (const bool seen : {false, true}) {
                    ++combinations;
                    INFO(n.body << " | " << i4.body << " | " << i6.body << " | seen=" << seen);
                    const SectionCase* const all[3] = {&n, &i4, &i6};
                    bool content = false;
                    bool all_read = true;
                    std::size_t total = 0;
                    for (const auto* s : all) {
                        content = content || (s->read && s->content);
                        all_read = all_read && s->read;
                        total += s->read ? s->rules : 0;
                    }
                    const auto st = snapshot_answer(n.body, i4.body, i6.body, seen, FwReadAction::state);
                    const auto ru = snapshot_answer(n.body, i4.body, i6.body, seen, FwReadAction::rules);
                    // the two actions agree on the verdict and on declining
                    CHECK(st.state == ru.state);
                    CHECK(st.declined == ru.declined);
                    // 6. nft not installed and nothing read with content: declines, errors only
                    CHECK(st.declined == (n.body == kAbsent && !content));
                    // nft `[absent]` never gives `inactive` and never a number
                    if (n.body == kAbsent) {
                        CHECK(st.state != NftVerdict::inactive);
                        CHECK(std::none_of(st.rows.begin(), st.rows.end(), [](const std::string& r) {
                            return r.starts_with("ruleset|") && r != "ruleset|unknown";
                        }));
                    }
                    // every unread section has its error row, and nothing else has one
                    std::size_t unread = 0;
                    for (const auto* s : all) {
                        if (!s->read) {
                            ++unread;
                            CHECK(has(st.rows, s->error));
                            CHECK(has(ru.rows, s->error));
                        }
                    }
                    CHECK(static_cast<std::size_t>(std::count_if(st.rows.begin(), st.rows.end(), [](const std::string& r) {
                              return r.starts_with("error|");
                          })) == unread);
                    if (st.declined) {
                        CHECK(static_cast<std::size_t>(st.rows.size()) == unread);
                        continue;
                    }
                    // `active` if and only if a read section has content
                    CHECK((st.state == NftVerdict::active) == content);
                    // `inactive` implies all three read, no content, no table seen
                    if (st.state == NftVerdict::inactive) {
                        CHECK(all_read);
                        CHECK_FALSE(content);
                        CHECK_FALSE(seen);
                    }
                    // `unknown` is exactly: nothing active and (something unread, or the netlink leg saw a table)
                    if (!content)
                        CHECK((st.state == NftVerdict::unknown) == (!all_read || seen));
                    // a numeric count implies all three read, and it is the sum
                    const auto count_row = std::find_if(st.rows.begin(), st.rows.end(),
                                                        [](const std::string& r) { return r.starts_with("ruleset|"); });
                    REQUIRE(count_row != st.rows.end());
                    if (*count_row != "ruleset|unknown") {
                        CHECK(all_read);
                        CHECK(*count_row == "ruleset|" + std::to_string(total));
                    } else {
                        CHECK((!all_read || (!content && seen)));
                    }
                    // one `state|` row says the verdict; `rules|unknown` exactly when the verdict is unknown
                    CHECK(std::count(st.rows.begin(), st.rows.end(),
                                     "state|" + std::string{nft_verdict_name(st.state)}) == 1);
                    CHECK(has(ru.rows, "rules|unknown") == (ru.state == NftVerdict::unknown));
                    // the backend row leads, and the error rows follow the count
                    CHECK(st.rows.front().starts_with("backend|"));
                    CHECK(st.rows[st.rows.size() - unread - 1].starts_with("ruleset|"));
                }
            }
        }
    }
    CHECK(combinations == 6 * 9 * 9 * 2);
}

TEST_CASE("firewalld_read: complete only when firewalld answered and every service list was read", "[firewall]") {
    CHECK(firewalld_read(false, true) == FirewalldRead::absent); // getActiveZones failed: not reachable
    CHECK(firewalld_read(false, false) == FirewalldRead::absent);
    CHECK(firewalld_read(true, true) == FirewalldRead::complete);
    // getServices refused (polkit), undecodable, or the budget ran out: the shell reports all three as
    // an incomplete service list
    CHECK(firewalld_read(true, false) == FirewalldRead::partial);
}

TEST_CASE("firewalld_rows: today's rows, complete and partial, for state and rules", "[firewall]") {
    const std::vector<FirewalldZone> zones{{"public", {"ssh", "dhcpv6-client"}}, {"internal", {"mdns"}}};
    CHECK(firewalld_rows(zones, true, FwReadAction::state) ==
          Rows{"backend|firewalld", "state|running", "ruleset|3"});
    CHECK(firewalld_rows(zones, false, FwReadAction::state) ==
          Rows{"backend|firewalld", "state|running", "ruleset|unknown"}); // an undercount is not a count
    CHECK(firewalld_rows({}, true, FwReadAction::state) == Rows{"backend|firewalld", "state|running", "ruleset|0"});
    CHECK(firewalld_rows(zones, true, FwReadAction::rules) ==
          Rows{"backend|firewalld", "rule|firewalld|public|service|ssh", "rule|firewalld|public|service|dhcpv6-client",
               "rule|firewalld|internal|service|mdns", "ruleset|3"});
    CHECK(firewalld_rows(zones, false, FwReadAction::rules).back() == "ruleset|unknown");
    CHECK(firewalld_rows(zones, false, FwReadAction::rules).size() == 5); // the services that were read stay listed
    CHECK(firewalld_rows({}, true, FwReadAction::rules) == Rows{"backend|firewalld", "ruleset|0"});
    // a `|` or a newline in a zone or service name cannot make a field or a row
    const std::vector<FirewalldZone> hostile{{"a|b\nc", {"x|y\rz"}}};
    CHECK(firewalld_rows(hostile, true, FwReadAction::rules) ==
          Rows{"backend|firewalld", "rule|firewalld|a_b_c|service|x_y_z", "ruleset|1"});
}

TEST_CASE("snapshot_connect_token and snapshot_error_row", "[firewall]") {
    CHECK(snapshot_connect_token(ENOENT).empty()); // no broker installed: silent
    CHECK(snapshot_connect_token(EACCES) == "connect:eacces");
    CHECK(snapshot_connect_token(ECONNREFUSED) == "connect:refused");
    CHECK(snapshot_connect_token(EAGAIN) == "connect:busy");
    CHECK(snapshot_connect_token(EMFILE) == "connect:errno:" + std::to_string(EMFILE));
    CHECK(snapshot_connect_token(0) == "connect:errno:0");
    CHECK(snapshot_error_row("timeout") == "error|snapshot:timeout");
    CHECK(snapshot_error_row("empty") == "error|snapshot:empty");
    CHECK(kFwSnapshotSocketPath == "/run/yuzu-fw-snapshot.sock");
    CHECK(kFwSnapshotMaxBytes == 4194304);
}

TEST_CASE("helper_snapshot_outcome: the listing, or a token that names the failure", "[firewall]") {
    using yuzu::agent::SubprocessResult;
    SubprocessResult done;
    done.tool_ran = true;
    done.exit_code = 0;
    done.output = "== nft -a list ruleset\n";
    // complete with exit 0: the listing
    const auto ok = helper_snapshot_outcome(done);
    REQUIRE(ok.has_value());
    CHECK(*ok == done.output);
    // every incomplete run is a failed read and says why: the token is the one every other read uses
    const auto token = [](SubprocessResult r) {
        const auto out = helper_snapshot_outcome(r);
        REQUIRE_FALSE(out.has_value());
        return out.error();
    };
    auto refused = done; // sudo refused, or the helper failed: the helper file is there, so it is a failed read
    refused.exit_code = 1;
    CHECK(token(refused) == "helper:exit:1");
    auto other_exit = done; // any other exit status is named as it is
    other_exit.exit_code = 64;
    CHECK(token(other_exit) == "helper:exit:64");
    auto timed_out = done;
    timed_out.timed_out = true;
    timed_out.exit_code = 1; // a timeout wins over the exit code
    CHECK(token(timed_out) == "helper:timeout");
    auto clipped = done;
    clipped.output_truncated = true;
    CHECK(token(clipped) == "helper:truncated");
    auto signalled = done;
    signalled.exit_code = -1;
    CHECK(token(signalled) == "helper:exit:-1");
    CHECK(token(SubprocessResult{}) == "helper:not_run");
    CHECK(snapshot_error_row("helper:timeout") == "error|snapshot:helper:timeout");
}

namespace {

using Reply = std::expected<std::string, std::string>;

struct RungRun {
    LinuxSnapshotRung rung;
    std::size_t reads = 0;
};

/// The rung over a scripted transport: each read takes the next reply, and asking for more replies than
/// were scripted fails the case.
RungRun run_rung(const std::vector<Reply>& replies, bool tables_seen = false, bool firewalld_held = false,
                 FwReadAction action = FwReadAction::state) {
    RungRun run;
    const auto read = [&]() -> Reply {
        REQUIRE(run.reads < replies.size());
        return replies[run.reads++];
    };
    run.rung = linux_snapshot_rung(read, tables_seen, firewalld_held, action);
    return run;
}

const std::string kEmptyHost = snap("", kTablesNone, kTablesNone); // nothing anywhere: reads inactive
const std::string kActiveHost = snap(kNftOne, kTablesNone, kTablesNone);
const Reply kNoTransport = std::unexpected(std::string{});

} // namespace

TEST_CASE("linux_snapshot_rung: inactive is never answered from one snapshot", "[firewall]") {
    // inactive twice: exactly two reads, and the second answer is the answer
    const auto twice = run_rung({kEmptyHost, kEmptyHost});
    CHECK(twice.reads == 2);
    CHECK(twice.rung.answered);
    CHECK(twice.rung.rows == Rows{"backend|nftables", "state|inactive", "ruleset|0"});
    // the same for the rules action, which lists nothing and counts zero
    const auto rules = run_rung({kEmptyHost, kEmptyHost}, false, false, FwReadAction::rules);
    CHECK(rules.reads == 2);
    CHECK(rules.rung.answered);
    CHECK(rules.rung.rows == Rows{"backend|nftables", "ruleset|0"});

    // inactive and then active: the second snapshot saw a rule set that moved between backends
    const auto moved = run_rung({kEmptyHost, kActiveHost});
    CHECK(moved.reads == 2);
    CHECK(moved.rung.answered);
    CHECK(moved.rung.rows == state_rows(kNftOne, kTablesNone, kTablesNone));
    CHECK(moved.rung.rows == Rows{"backend|nftables", "state|active", "ruleset|2"});
    // the rule it saw is listed by the rules action
    const auto listed = run_rung({kEmptyHost, kActiveHost}, false, false, FwReadAction::rules);
    CHECK(listed.rung.rows == rules_rows(kNftOne, kTablesNone, kTablesNone));

    // inactive and then a section that was not read: unknown with its error row, never inactive
    const auto unread = run_rung({kEmptyHost, snap("", kFailed, kTablesNone)});
    CHECK(unread.reads == 2);
    CHECK(unread.rung.answered);
    CHECK(unread.rung.rows == state_rows("", kFailed, kTablesNone));
    CHECK(unread.rung.rows == Rows{"backend|nftables", "state|unknown", "ruleset|unknown",
                                   "error|iptables:snapshot:failed"});
}

TEST_CASE("linux_snapshot_rung: a first inactive that the second read cannot confirm is unknown",
          "[firewall]") {
    // the rung owns the answer once the first snapshot reads inactive: the ladder never goes on to
    // the ufw and `iptables -S` rungs, which read less and can print inactive for the same host
    // Each case is a second read that gives no answer, and the row that says why.
    std::vector<std::pair<Reply, std::string>> cases;
    // a failed read on either transport: the reader's token, or the helper's own
    for (const char* token : {"timeout", "io_error", "oversized", "peer_not_root", "connect:refused",
                              "connect:busy", "connect:eacces", "helper:timeout", "helper:exit:1",
                              "helper:truncated", "helper:not_run"})
        cases.push_back(
            {Reply{std::unexpected(std::string{token})}, std::string{"error|snapshot:"} + token});
    // the transport that answered the first read is gone: the reader finds none
    cases.push_back({kNoTransport, "error|snapshot:gone"});
    // a reply that fails the framing: empty, no end line, not a listing
    cases.push_back({Reply{std::string{}}, "error|snapshot:empty"});
    cases.push_back({Reply{kEmptyHost.substr(0, kEmptyHost.size() - 7)}, "error|snapshot:truncated"});
    cases.push_back({Reply{std::string{"not a listing\n"}}, "error|snapshot:malformed"});
    // a snapshot that declines: nft vanished between the reads and nothing read shows content
    cases.push_back(
        {Reply{snap(kAbsent, kTablesNone, kTablesNone)}, "error|nftables:snapshot:absent"});
    for (const auto& [second, error] : cases) {
        INFO(error);
        for (const auto action : {FwReadAction::state, FwReadAction::rules}) {
            const auto run = run_rung({kEmptyHost, second}, false, false, action);
            const char* verdict = action == FwReadAction::state ? "state|unknown" : "rules|unknown";
            CHECK(run.reads == 2);
            CHECK(run.rung.answered);
            CHECK(run.rung.rows == Rows{"backend|nftables", verdict, "ruleset|unknown", error});
            const auto& rows = run.rung.rows;
            CHECK(std::none_of(rows.begin(), rows.end(), [](const std::string& r) {
                return r == "state|inactive" || r == "ruleset|0";
            }));
        }
    }
}

TEST_CASE("linux_snapshot_rung: every answer but inactive is one read", "[firewall]") {
    // active
    const auto active = run_rung({kActiveHost});
    CHECK(active.reads == 1);
    CHECK(active.rung.answered);
    CHECK(active.rung.rows == Rows{"backend|nftables", "state|active", "ruleset|2"});
    // unknown: nft is installed but its section was not read
    const auto unknown = run_rung({snap(kFailed, kTablesNone, kTablesNone)});
    CHECK(unknown.reads == 1);
    CHECK(unknown.rung.answered);
    CHECK(unknown.rung.rows == state_rows(kFailed, kTablesNone, kTablesNone));
    // a netlink read that saw a table turns the empty answer to unknown before it can be inactive
    const auto clamped = run_rung({kEmptyHost}, /*tables_seen=*/true);
    CHECK(clamped.reads == 1);
    CHECK(clamped.rung.answered);
    CHECK(clamped.rung.rows == Rows{"backend|nftables", "state|unknown", "ruleset|unknown"});
    // declined: nft is not installed and nothing read shows content, so the ladder goes on
    const auto declined = run_rung({snap(kAbsent, kTablesNone, kFailed)});
    CHECK(declined.reads == 1);
    CHECK_FALSE(declined.rung.answered);
    CHECK(declined.rung.rows == Rows{"error|nftables:snapshot:absent", "error|ip6tables:snapshot:failed"});
    // the first read failing is one read, a row (or nothing, with no transport) and no answer
    const auto timed_out = run_rung({Reply{std::unexpected(std::string{"timeout"})}});
    CHECK(timed_out.reads == 1);
    CHECK_FALSE(timed_out.rung.answered);
    CHECK(timed_out.rung.rows == Rows{"error|snapshot:timeout"});
    const auto none = run_rung({kNoTransport});
    CHECK(none.reads == 1);
    CHECK_FALSE(none.rung.answered);
    CHECK(none.rung.rows.empty());
    const auto malformed = run_rung({Reply{std::string{"x\n"}}});
    CHECK(malformed.reads == 1);
    CHECK(malformed.rung.rows == Rows{"error|snapshot:malformed"});
}

TEST_CASE("linux_snapshot_rung: while firewalld's answer is held only an active answer stands, in one read",
          "[firewall]") {
    // an empty host would read inactive, which is never accepted here, so there is no second read
    const auto empty = run_rung({kEmptyHost}, false, /*firewalld_held=*/true);
    CHECK(empty.reads == 1);
    CHECK_FALSE(empty.rung.answered);
    CHECK(empty.rung.rows.empty()); // nothing was refused: no error row to write
    // an unread section writes its error row and leaves firewalld's answer standing
    const auto unread = run_rung({snap("", kFailed, kTablesNone)}, false, true);
    CHECK(unread.reads == 1);
    CHECK_FALSE(unread.rung.answered);
    CHECK(unread.rung.rows == Rows{"error|iptables:snapshot:failed"});
    // an active answer replaces it
    const auto active = run_rung({kActiveHost}, false, true);
    CHECK(active.reads == 1);
    CHECK(active.rung.answered);
    CHECK(active.rung.rows == Rows{"backend|nftables", "state|active", "ruleset|2"});
}

// ── the root direct iptables legs read filter, raw, mangle and nat (iptables_direct_answer) ──────
namespace {
constexpr std::string_view kDirectRuleRaw = "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-A PREROUTING -j DROP\n";
constexpr std::string_view kDirectCleanRaw = "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n";

IptablesTableRead direct_read(bool ip6, std::string_view table, std::string_view out,
                              bool tool_ran = true, bool exit_ok = true, bool complete = true) {
    return classify_iptables_table_read(ip6, table, tool_ran, exit_ok, complete, out);
}

/// All eight tables clean, except those `over` replaces.
std::vector<IptablesTableRead> direct_reads(std::initializer_list<IptablesTableRead> over = {}) {
    std::vector<IptablesTableRead> v;
    for (const bool ip6 : {false, true})
        for (const auto t : kIptablesDirectTables) {
            auto r = direct_read(ip6, t, t == "filter" ? kIptClean : kDirectCleanRaw);
            for (const auto& o : over)
                if (o.ip6 == ip6 && o.table == t)
                    r = o;
            v.push_back(std::move(r));
        }
    return v;
}
} // namespace

TEST_CASE("iptables direct: every table clean and read is inactive with a count", "[firewall]") {
    const auto a = iptables_direct_answer(direct_reads(), false);
    CHECK(a.state == NftVerdict::inactive);
    CHECK(a.all_read);
    CHECK(a.appends == 0);
    CHECK(a.rule_rows.size() == 2 * (3 + 2 + 2 + 2)); // every policy row of every table, no rule
    CHECK(iptables_direct_answer(direct_reads(), true).state == NftVerdict::unknown);
}

TEST_CASE("iptables direct: a ruleset only in raw, mangle or nat is active, never inactive",
          "[firewall]") {
    for (const bool ip6 : {false, true})
        for (const std::string_view table : {"raw", "mangle", "nat"}) {
            const auto a = iptables_direct_answer(
                direct_reads({direct_read(ip6, table, kDirectRuleRaw)}), false);
            CHECK(a.state == NftVerdict::active);
            CHECK(a.all_read);
            CHECK(a.appends == 1);
            CHECK(std::ranges::count(
                      a.rule_rows,
                      std::format("rule|{}{}|append|PREROUTING|-j DROP",
                                  ip6 ? "ip6|" : "", table)) == 1);
        }
}

TEST_CASE("iptables direct: a user chain or a non-accept policy in any table is active",
          "[firewall]") {
    CHECK(iptables_direct_answer(
              direct_reads({direct_read(false, "nat", "-P PREROUTING ACCEPT\n-N staged\n")}), false)
              .state == NftVerdict::active);
    CHECK(iptables_direct_answer(
              direct_reads({direct_read(true, "filter", "-P INPUT DROP\n-P FORWARD ACCEPT\n"
                                                        "-P OUTPUT ACCEPT\n")}),
              false)
              .state == NftVerdict::active);
}

TEST_CASE("iptables direct: an unreadable table reads unknown, never inactive", "[firewall]") {
    for (const bool ip6 : {false, true})
        for (const auto table : kIptablesDirectTables) {
            const auto refused = iptables_direct_answer(
                direct_reads({direct_read(ip6, table, "", true, /*exit_ok=*/false)}), false);
            CHECK(refused.state == NftVerdict::unknown);
            CHECK_FALSE(refused.all_read);
            const auto cut = iptables_direct_answer(
                direct_reads({direct_read(ip6, table, kDirectCleanRaw, true, true, /*complete=*/false)}),
                false);
            CHECK(cut.state == NftVerdict::unknown);
            const auto no_time = iptables_direct_answer(
                direct_reads({IptablesTableRead{.ip6 = ip6, .table = std::string{table}}}), false);
            CHECK(no_time.state == NftVerdict::unknown);
        }
}

TEST_CASE("iptables direct: content in one table wins over an unread one; the count is withheld",
          "[firewall]") {
    const auto a = iptables_direct_answer(
        direct_reads({direct_read(false, "raw", kDirectRuleRaw),
                      direct_read(false, "nat", "", true, false)}),
        false);
    CHECK(a.state == NftVerdict::active);
    CHECK_FALSE(a.all_read);
    CHECK(std::ranges::count(a.rule_rows, "rule|raw|append|PREROUTING|-j DROP") == 1);
}

TEST_CASE("iptables direct: an unrecognised listing is unread and says so per tool", "[firewall]") {
    const auto a = iptables_direct_answer(
        direct_reads({direct_read(true, "mangle", "garbage\n")}), false);
    CHECK(a.state == NftVerdict::unknown);
    CHECK(a.error_rows == std::vector<std::string>{"error|ip6tables:unrecognised_output"});
}

TEST_CASE("iptables direct: an absent ip6tables is skipped, nothing read is unknown", "[firewall]") {
    std::vector<IptablesTableRead> v;
    for (const auto t : kIptablesDirectTables)
        v.push_back(direct_read(false, t, t == "filter" ? kIptClean : kDirectCleanRaw));
    for (const auto t : kIptablesDirectTables)
        v.push_back(direct_read(true, t, "", /*tool_ran=*/false));
    CHECK(iptables_direct_answer(v, false).state == NftVerdict::inactive);
    CHECK(iptables_direct_answer({}, false).state == NftVerdict::unknown);
}

TEST_CASE("nft: has_content -- an empty user-defined chain is content (ADR-3007 clause 6)",
          "[firewall]") {
    NftChainInfo c; // table inet filter { chain staged { } }
    c.is_base_chain = false;
    CHECK(nft_has_content({c}, {}));
}
