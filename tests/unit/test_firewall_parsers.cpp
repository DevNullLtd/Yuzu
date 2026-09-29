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

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstring>

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
                                     "-N yuzu-quarantine\n"
                                     "-A INPUT -j yuzu-quarantine\n"
                                     "-A yuzu-quarantine -i lo -j ACCEPT\n"
                                     "-A yuzu-quarantine -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                                     "-A yuzu-quarantine -s 10.0.0.5/32 -j ACCEPT\n"
                                     "-A yuzu-quarantine -j DROP\n";
    auto rules = parse_iptables_save(out);
    REQUIRE(rules.size() == 9);

    CHECK(rules[0].type == IptablesEntryType::policy);
    CHECK(rules[0].chain == "INPUT");
    CHECK(rules[0].spec == "ACCEPT");
    CHECK(rules[2].type == IptablesEntryType::policy);
    CHECK(rules[2].chain == "OUTPUT");
    CHECK(rules[2].spec == "ACCEPT");

    CHECK(rules[3].type == IptablesEntryType::new_chain);
    CHECK(rules[3].chain == "yuzu-quarantine");
    CHECK(rules[3].spec.empty());

    CHECK(rules[4].type == IptablesEntryType::append);
    CHECK(rules[4].chain == "INPUT");
    CHECK(rules[4].spec == "-j yuzu-quarantine");

    CHECK(rules[6].type == IptablesEntryType::append);
    CHECK(rules[6].chain == "yuzu-quarantine");
    CHECK(rules[6].spec == "-m state --state RELATED,ESTABLISHED -j ACCEPT");

    CHECK(rules[8].type == IptablesEntryType::append);
    CHECK(rules[8].chain == "yuzu-quarantine");
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
