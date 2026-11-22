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

#include <cerrno>
#include <chrono>
#include <cstring>
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

// ── Linux: the root snapshot broker (framing, nft text, iptables family, decision table) ────

namespace {

/// A broker reply from three section bodies, each already newline-terminated or empty.
std::string snap(std::string_view nft, std::string_view ipt, std::string_view ip6t) {
    return "== nft -a list ruleset\n" + std::string{nft} + "== iptables -S\n" + std::string{ipt} +
           "== ip6tables -S\n" + std::string{ip6t} + "== end\n";
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

constexpr std::string_view kIptClean = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
constexpr std::string_view kIptV6Rules =
    "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n";
constexpr std::string_view kAbsent = "[absent]\n";
constexpr std::string_view kFailed = "-P INPUT ACC\n\n[failed]\n"; // partial output, then the marker

using Rows = std::vector<std::string>;

Rows state_rows(std::string_view nft, std::string_view ipt, std::string_view ip6t, bool tables_seen = false) {
    const auto parsed = parse_fw_snapshot(snap(nft, ipt, ip6t));
    REQUIRE(parsed.has_value());
    return linux_snapshot_state_rows(*parsed, tables_seen);
}

Rows rules_rows(std::string_view nft, std::string_view ipt, std::string_view ip6t, bool tables_seen = false) {
    const auto parsed = parse_fw_snapshot(snap(nft, ipt, ip6t));
    REQUIRE(parsed.has_value());
    return linux_snapshot_rules_rows(*parsed, tables_seen);
}

} // namespace

TEST_CASE("parse_fw_snapshot: the three headed sections in order, then the end line", "[firewall]") {
    const auto got = parse_fw_snapshot(snap(kNftOne, kIptClean, kAbsent));
    REQUIRE(got.has_value());
    CHECK(got->nft.kind == FwSectionKind::text);
    CHECK(got->nft.text == kNftOne);
    CHECK(got->iptables.kind == FwSectionKind::text);
    CHECK(got->iptables.text == kIptClean);
    CHECK(got->ip6tables.kind == FwSectionKind::absent); // body is exactly [absent]
    CHECK(got->ip6tables.text.empty());
    // an empty body is a text section with no text (an empty nft ruleset prints nothing)
    const auto empty_nft = parse_fw_snapshot(snap("", kIptClean, kIptClean));
    REQUIRE(empty_nft.has_value());
    CHECK(empty_nft->nft.kind == FwSectionKind::text);
    CHECK(empty_nft->nft.text.empty());
}

TEST_CASE("parse_fw_snapshot: a [failed] line makes the section failed whatever came before it", "[firewall]") {
    const auto got = parse_fw_snapshot(snap(kNftOne, kFailed, kIptClean));
    REQUIRE(got.has_value());
    CHECK(got->iptables.kind == FwSectionKind::failed);
    CHECK(got->iptables.text.empty()); // the partial text is not kept
    CHECK(got->nft.kind == FwSectionKind::text);
    // [absent] plus other lines is text, not absent; the marker must be a whole line
    const auto not_absent = parse_fw_snapshot(snap(kNftOne, "[absent]\n-P INPUT ACCEPT\n", kIptClean));
    REQUIRE(not_absent.has_value());
    CHECK(not_absent->iptables.kind == FwSectionKind::text);
    const auto not_failed = parse_fw_snapshot(snap(kNftOne, "-A INPUT -m comment --comment [failed] -j ACCEPT\n", kIptClean));
    REQUIRE(not_failed.has_value());
    CHECK(not_failed->iptables.kind == FwSectionKind::text);
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
    const auto whole = snap(kNftOne, kIptClean, kIptClean);
    CHECK(token(whole.substr(0, whole.size() - std::string_view{"== end\n"}.size())) == "truncated");
    CHECK(token(whole.substr(0, whole.size() - 1)) == "truncated"); // `== end` without its newline
    CHECK(token(whole.substr(0, whole.size() - 4)) == "truncated"); // `== e`
    CHECK(token("== nft -a list ruleset\ntable inet filter { # handle 1\n") == "truncated");
    // wrong order, a missing section, a repeated header, an unknown header, text after the end
    CHECK(token("== iptables -S\n== nft -a list ruleset\n== ip6tables -S\n== end\n") == "malformed");
    CHECK(token("== nft -a list ruleset\n== ip6tables -S\n== iptables -S\n== end\n") == "malformed");
    CHECK(token("== nft -a list ruleset\n== iptables -S\n== end\n") == "malformed");
    CHECK(token("== nft -a list ruleset\n== iptables -S\n== iptables -S\n== ip6tables -S\n== end\n") == "malformed");
    CHECK(token("== nft -a list ruleset\n== iptables -S\n== ip6tables -S\n== surprise\n== end\n") == "malformed");
    CHECK(token(snap("", "", "") + "== nft -a list ruleset\n") == "malformed");
    CHECK(token(snap("", "", "") + "\n") == "malformed");
    // garbage, and a reply that does not start with the first header
    CHECK(token("hello\nworld\n") == "malformed");
    CHECK(token("garbage") == "malformed");
    CHECK(token("\n") == "malformed");
    CHECK(token("== iptables -S\n== ip6tables -S\n== end\n") == "malformed");
}

TEST_CASE("parse_nft_ruleset_text: a real listing is tables, chains with hook and policy, and rules by handle",
          "[firewall]") {
    const auto r = parse_nft_ruleset_text(kNftOne);
    REQUIRE(r.has_value());
    REQUIRE(r->tables.size() == 1);
    CHECK(r->tables[0].family == nft_raw::kNfprotoInet);
    CHECK(r->tables[0].name == "filter");
    REQUIRE(r->chains.size() == 1);
    CHECK(r->chains[0].name == "input");
    CHECK(r->chains[0].table == "filter");
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
    REQUIRE(r->tables.size() == 2);
    CHECK(r->tables[1].family == nft_raw::kNfprotoIpv6);
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
    // attribution: the rules of the first table are in `input`, none in `forward`
    CHECK(r->rules[0].chain == "input");
    for (const auto& rule : r->rules)
        CHECK(rule.chain == "input");
}

TEST_CASE("parse_nft_ruleset_text: empty text is no tables, and a listing it cannot read is nullopt", "[firewall]") {
    const auto none = parse_nft_ruleset_text("");
    REQUIRE(none.has_value());
    CHECK(none->tables.empty());
    const auto only_comments = parse_nft_ruleset_text("# Warning: nothing here\n\n   \n");
    REQUIRE(only_comments.has_value());
    CHECK(only_comments->tables.empty());
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
    const auto q = parse_nft_ruleset_text("table inet \"my table\" { # handle 1\n}\n");
    REQUIRE(q.has_value());
    REQUIRE(q->tables.size() == 1);
    CHECK(q->tables[0].name == "my table");
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
    REQUIRE(r->tables.size() == 2);
    CHECK(r->tables[0].family == nft_raw::kNfprotoArp);
    CHECK(r->tables[1].family == nft_raw::kNfprotoNetdev);
    REQUIRE(r->chains.size() == 2);
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

TEST_CASE("iptables family: both address families are read together, and a member that could not be read "
          "never reads as nothing",
          "[firewall]") {
    // IPv4 clean and IPv6 with a DROP policy and one rule: active, with the IPv6 count
    CHECK(state_rows("", kIptClean, kIptV6Rules) ==
          Rows{"backend|iptables", "state|active", "ruleset|1"});
    CHECK(rules_rows("", kIptClean, kIptV6Rules) ==
          Rows{"backend|iptables", "rule|policy|INPUT|ACCEPT", "rule|policy|FORWARD|ACCEPT",
               "rule|policy|OUTPUT|ACCEPT", "rule|ip6|policy|INPUT|DROP", "rule|ip6|policy|FORWARD|ACCEPT",
               "rule|ip6|policy|OUTPUT|ACCEPT", "rule|ip6|append|INPUT|-p tcp -m tcp --dport 22 -j ACCEPT",
               "ruleset|1"});
    // one member failed and neither shows content: unknown, with its error row and no count
    CHECK(state_rows(kAbsent, kFailed, kIptClean) ==
          Rows{"backend|iptables", "state|unknown", "ruleset|unknown", "error|iptables:snapshot:failed"});
    CHECK(state_rows(kAbsent, kIptClean, kFailed) ==
          Rows{"backend|iptables", "state|unknown", "ruleset|unknown", "error|ip6tables:snapshot:failed"});
    // one member failed and the other has content: active, the count unknown
    CHECK(state_rows(kAbsent, kFailed, kIptV6Rules) ==
          Rows{"backend|iptables", "state|active", "ruleset|unknown", "error|iptables:snapshot:failed"});
    // a listing that is not in the known shape is untrusted and says so
    CHECK(state_rows(kAbsent, "surprise\n", kIptClean) ==
          Rows{"backend|iptables", "state|unknown", "ruleset|unknown", "error|iptables:unrecognised_output"});
    // `rules` lists the text members and says unknown when none was text
    CHECK(rules_rows(kAbsent, kFailed, kFailed) ==
          Rows{"backend|iptables", "rules|unknown", "ruleset|unknown", "error|iptables:snapshot:failed",
               "error|ip6tables:snapshot:failed"});
    // ip6tables absent and IPv4 clean is inactive, a count of zero
    CHECK(state_rows(kAbsent, kIptClean, kAbsent) == Rows{"backend|iptables", "state|inactive", "ruleset|0"});
    // both absent is no family at all: with nft absent too the rung declines
    CHECK(state_rows(kAbsent, kAbsent, kAbsent).empty());
    CHECK(rules_rows(kAbsent, kAbsent, kAbsent).empty());
}

TEST_CASE("linux_snapshot rows, branch 1: nft text it cannot read is unknown with the error row", "[firewall]") {
    const std::string cut = "table inet filter { # handle 1\n"; // not closed
    const Rows state{"backend|nftables", "state|unknown", "ruleset|unknown", "error|nftables:unrecognised_output"};
    const Rows rules{"backend|nftables", "rules|unknown", "ruleset|unknown", "error|nftables:unrecognised_output"};
    // whatever the iptables sections say: an unread nft ruleset is not an empty one
    CHECK(state_rows(cut, kIptClean, kIptClean) == state);
    CHECK(rules_rows(cut, kIptClean, kIptClean) == rules);
    CHECK(state_rows(cut, kIptV6Rules, kAbsent) == state);
}

TEST_CASE("linux_snapshot rows, branch 2: nft with content answers for itself", "[firewall]") {
    CHECK(state_rows(kNftOne, kIptClean, kIptClean) == Rows{"backend|nftables", "state|active", "ruleset|2"});
    CHECK(rules_rows(kNftOne, kIptClean, kIptClean) ==
          Rows{"backend|nftables", "rule|nftables|inet|filter|input|input|accept",
               "rule|nftables|inet|filter|input|handle|4", "rule|nftables|inet|filter|input|handle|5",
               "ruleset|2"});
    // a base chain with a drop policy and no rule is content
    const std::string drop =
        "table inet filter { # handle 1\n\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n";
    CHECK(state_rows(drop, kAbsent, kAbsent) == Rows{"backend|nftables", "state|active", "ruleset|0"});
    // content stands with tables_seen set: an active reading is never downgraded
    CHECK(state_rows(kNftOne, kIptClean, kIptClean, true) == Rows{"backend|nftables", "state|active", "ruleset|2"});
    // a hostile name echoed into a row is sanitised
    const std::string hostile =
        "table inet \"a|b\" { # handle 1\n\tchain \"c|d\" { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\taccept # handle 7\n\t}\n}\n";
    const auto rows = rules_rows(hostile, kAbsent, kAbsent);
    REQUIRE(rows.size() == 4);
    CHECK(rows[1] == "rule|nftables|inet|a_b|c_d|input|accept");
    CHECK(rows[2] == "rule|nftables|inet|a_b|c_d|handle|7");
}

TEST_CASE("linux_snapshot rows, branch 3: nft with no content defers to an iptables family that has some "
          "or could not be read",
          "[firewall]") {
    const std::string tables_no_content =
        "table inet filter { # handle 1\n\tchain input { # handle 1\n"
        "\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
    // no nft table at all, IPv4 three ACCEPT policies, IPv6-only rules: active (the review's H1 case)
    CHECK(state_rows("", kIptClean, kIptV6Rules) == Rows{"backend|iptables", "state|active", "ruleset|1"});
    // nft tables with no content beside legacy rules: active, through iptables
    CHECK(state_rows(tables_no_content, kIptV6Rules, kIptClean) ==
          Rows{"backend|iptables", "state|active", "ruleset|1"});
    // an iptables member that could not be read: unknown, never inactive
    CHECK(state_rows(tables_no_content, kFailed, kIptClean) ==
          Rows{"backend|iptables", "state|unknown", "ruleset|unknown", "error|iptables:snapshot:failed"});
    // family inactive or absent: nft answers inactive with a count of zero
    CHECK(state_rows(tables_no_content, kIptClean, kIptClean) ==
          Rows{"backend|nftables", "state|inactive", "ruleset|0"});
    CHECK(state_rows("", kIptClean, kAbsent) == Rows{"backend|nftables", "state|inactive", "ruleset|0"});
    CHECK(state_rows("", kAbsent, kAbsent) == Rows{"backend|nftables", "state|inactive", "ruleset|0"});
    // rules: the base chains nft lists, no rule rows, a count of zero
    CHECK(rules_rows(tables_no_content, kIptClean, kIptClean) ==
          Rows{"backend|nftables", "rule|nftables|inet|filter|input|input|accept", "ruleset|0"});
    CHECK(rules_rows("", kAbsent, kAbsent) == Rows{"backend|nftables", "ruleset|0"});
    CHECK(rules_rows("", kIptClean, kIptV6Rules).front() == "backend|iptables");
}

TEST_CASE("linux_snapshot rows, branch 4: nft absent leaves the iptables family, or declines", "[firewall]") {
    CHECK(state_rows(kAbsent, kAbsent, kAbsent).empty());
    CHECK(state_rows(kAbsent, kIptClean, kIptClean) == Rows{"backend|iptables", "state|inactive", "ruleset|0"});
    CHECK(state_rows(kAbsent, kIptV6Rules, kIptClean) == Rows{"backend|iptables", "state|active", "ruleset|1"});
    CHECK(rules_rows(kAbsent, kIptClean, kAbsent) ==
          Rows{"backend|iptables", "rule|policy|INPUT|ACCEPT", "rule|policy|FORWARD|ACCEPT",
               "rule|policy|OUTPUT|ACCEPT", "ruleset|0"});
}

TEST_CASE("linux_snapshot rows, branch 5: nft that failed is reported and never read as empty", "[firewall]") {
    // a family with content still answers, beside the error row
    CHECK(state_rows(kFailed, kIptV6Rules, kIptClean) ==
          Rows{"error|nftables:snapshot:failed", "backend|iptables", "state|active", "ruleset|1"});
    // otherwise unknown: an unread nft ruleset hides anything, so a clean family does not make it inactive
    CHECK(state_rows(kFailed, kIptClean, kIptClean) ==
          Rows{"error|nftables:snapshot:failed", "backend|nftables", "state|unknown", "ruleset|unknown"});
    CHECK(state_rows(kFailed, kAbsent, kAbsent) ==
          Rows{"error|nftables:snapshot:failed", "backend|nftables", "state|unknown", "ruleset|unknown"});
    CHECK(rules_rows(kFailed, kIptClean, kIptClean) ==
          Rows{"error|nftables:snapshot:failed", "backend|nftables", "rules|unknown", "ruleset|unknown"});
}

TEST_CASE("linux_snapshot rows, branch 6: inactive reads unknown when the netlink leg saw a table", "[firewall]") {
    const Rows unknown{"backend|nftables", "state|unknown", "ruleset|unknown"};
    CHECK(state_rows("", kAbsent, kAbsent, true) == unknown);
    CHECK(state_rows("", kIptClean, kIptClean, true) == unknown);
    CHECK(rules_rows("", kAbsent, kAbsent, true) ==
          Rows{"backend|nftables", "rules|unknown", "ruleset|unknown"});
    // the iptables family's inactive answer is clamped the same way, and carries no count
    CHECK(state_rows(kAbsent, kIptClean, kIptClean, true) ==
          Rows{"backend|iptables", "state|unknown", "ruleset|unknown"});
    CHECK(rules_rows(kAbsent, kIptClean, kIptClean, true) ==
          Rows{"backend|iptables", "rules|unknown", "ruleset|unknown"});
    // and the same snapshot without a table seen is inactive
    CHECK(state_rows(kAbsent, kIptClean, kIptClean, false) ==
          Rows{"backend|iptables", "state|inactive", "ruleset|0"});
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
    CHECK(kFwSnapshotMaxBytes == 1048576);
}
