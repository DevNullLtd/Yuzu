#pragma once

/**
 * firewall_parsers.hpp — pure parse helpers for the firewall plugin.
 *
 * macOS state leg: the Application Firewall global state (socketfilterfw)
 * and the pf packet-filter status (pfctl). Linux legs: `ufw status`/`ufw
 * status numbered` and `iptables -S` — both now emit STRUCTURED rows,
 * replacing the old opaque `rule|<raw line>` passthrough.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_firewall_parsers.cpp — the netprobe_stats.hpp pattern); the
 * run_bounded_subprocess/sd-bus acquisition in firewall_plugin.cpp is the
 * impure shell.
 *
 * Honest-status invariant: empty, truncated, or unrecognised output parses
 * to `unknown` (state) or an empty row set (rules) — never a false-safe
 * enabled/disabled or a fabricated rule.
 */

#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <yuzu/agent/subprocess_runner.hpp>

namespace yuzu::firewall {

enum class FwState { enabled, disabled, unknown };

[[nodiscard]] constexpr std::string_view to_string(FwState s) {
    switch (s) {
    case FwState::enabled:
        return "enabled";
    case FwState::disabled:
        return "disabled";
    case FwState::unknown:
        return "unknown";
    }
    return "unknown"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// Global state of the macOS Application Firewall as reported by
/// `socketfilterfw --getglobalstate`.
struct AlfGlobalState {
    FwState state{FwState::unknown};
    bool block_all{false}; // "(State = 2)" — enabled AND blocking all incoming
};

/// Parse `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.
/// Primary signal is the "(State = N)" clause — 0 = disabled, 1 = enabled,
/// 2 = enabled + block-all — so prose rewording across macOS releases cannot
/// flip the verdict. A multi-digit or non-digit state is unrecognised and
/// falls through, as does a missing clause: the enabled/disabled prose is the
/// fallback, with "disabled" checked first so ambiguous text biases toward
/// the attention-drawing answer rather than false assurance.
[[nodiscard]] constexpr AlfGlobalState parse_alf_global_state(std::string_view out) {
    AlfGlobalState r;
    constexpr std::string_view kClause = "(State = ";
    const auto pos = out.find(kClause);
    if (pos != std::string_view::npos && pos + kClause.size() < out.size()) {
        const auto idx = pos + kClause.size();
        const bool single_digit =
            idx + 1 >= out.size() || out[idx + 1] < '0' || out[idx + 1] > '9';
        if (single_digit) {
            switch (out[idx]) {
            case '0':
                r.state = FwState::disabled;
                return r;
            case '1':
                r.state = FwState::enabled;
                return r;
            case '2':
                r.state = FwState::enabled;
                r.block_all = true;
                return r;
            default:
                break; // unrecognised state number — fall through to prose
            }
        }
    }
    if (out.find("disabled") != std::string_view::npos)
        r.state = FwState::disabled;
    else if (out.find("enabled") != std::string_view::npos)
        r.state = FwState::enabled;
    return r;
}

/// Parse `pfctl -s info`. The first line reads "Status: Enabled for …" or
/// "Status: Disabled for …". Empty output (reading /dev/pf needs root and the
/// caller discards stderr) or anything unrecognised → unknown.
[[nodiscard]] constexpr FwState parse_pf_status(std::string_view out) {
    if (out.find("Status: Enabled") != std::string_view::npos)
        return FwState::enabled;
    if (out.find("Status: Disabled") != std::string_view::npos)
        return FwState::disabled;
    return FwState::unknown;
}

/// Per-incoming-connection decision the macOS Application Firewall has
/// recorded for one app, as printed by `socketfilterfw --listapps`.
/// `unknown` is a REAL emitted state (an unrecognised parenthetical), not a
/// dropped row — see AlfAppRule below.
enum class AlfDecision { allow, block, unknown };

/// One row of `socketfilterfw --listapps`: an application path paired with
/// its incoming-connection decision.
struct AlfAppRule {
    std::string path;
    AlfDecision decision{AlfDecision::unknown};
};

/// Parse `socketfilterfw --listapps`. The header line ("Total number of
/// apps = N") is skipped — it has no " : " separator preceded by a numeric
/// index. Each app is an "<idx> : <path>" line followed by an indented
/// "(Allow incoming connections)" / "(Block incoming connections)" line;
/// the parenthetical is paired with the path that precedes it. An
/// unrecognised parenthetical is a real emitted state and yields
/// AlfDecision::unknown rather than dropping the row — as does an app line
/// with no following parenthetical at all (end of input, or immediately
/// followed by the next app line). Empty input (unprivileged refusal is
/// empty stdout) yields an empty vector.
[[nodiscard]] inline std::vector<AlfAppRule> parse_alf_listapps(std::string_view out) {
    std::vector<AlfAppRule> rows;
    std::string buf(out); // istringstream needs an owned string
    std::istringstream iss(buf);
    std::string line;
    bool have_pending = false;
    AlfAppRule pending;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto sep = line.find(" : ");
        const std::string_view idx(line.data(), sep == std::string::npos ? 0 : sep);
        const bool numeric_idx =
            sep != std::string::npos && !idx.empty() &&
            std::all_of(idx.begin(), idx.end(), [](char c) { return c >= '0' && c <= '9'; });
        if (numeric_idx) {
            if (have_pending)
                rows.push_back(std::move(pending)); // no parenthetical followed — unknown stands
            std::string_view path(line.data() + sep + 3, line.size() - sep - 3);
            while (!path.empty() && path.back() == ' ')
                path.remove_suffix(1);
            pending = AlfAppRule{std::string(path), AlfDecision::unknown};
            have_pending = true;
            continue;
        }
        if (have_pending) {
            std::string_view trimmed(line);
            while (!trimmed.empty() && trimmed.front() == ' ')
                trimmed.remove_prefix(1);
            while (!trimmed.empty() && trimmed.back() == ' ')
                trimmed.remove_suffix(1);
            if (trimmed == "(Allow incoming connections)")
                pending.decision = AlfDecision::allow;
            else if (trimmed == "(Block incoming connections)")
                pending.decision = AlfDecision::block;
            else
                pending.decision = AlfDecision::unknown;
            rows.push_back(std::move(pending));
            have_pending = false;
        }
    }
    if (have_pending)
        rows.push_back(std::move(pending));
    return rows;
}

/// Parse `pfctl -s Anchors` — one anchor name per line, leading whitespace
/// trimmed. Empty output (unprivileged refusal — "pfctl: /dev/pf:
/// Permission denied" goes to stderr, which the caller discards, leaving
/// empty stdout) yields an empty vector; blank lines are skipped rather than
/// emitted as empty anchor names.
[[nodiscard]] inline std::vector<std::string> parse_pf_anchors(std::string_view out) {
    std::vector<std::string> anchors;
    std::string buf(out);
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string_view trimmed(line);
        while (!trimmed.empty() && trimmed.front() == ' ')
            trimmed.remove_prefix(1);
        if (!trimmed.empty())
            anchors.push_back(std::string(trimmed));
    }
    return anchors;
}

/// Count the non-empty lines of `pfctl -s rules` — a pure line counter.
/// Returns 0 for empty input. This must NOT be read as "refused": a
/// genuinely empty ruleset and an unprivileged refusal both produce empty
/// stdout, and only the shell layer (run_bounded_subprocess's
/// tool_ran/exit_code/timed_out/output_truncated) can tell them apart — that
/// distinction is deliberately out of scope for this parser.
[[nodiscard]] inline std::size_t count_pf_rules(std::string_view out) {
    std::size_t count = 0;
    std::string buf(out);
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string_view trimmed(line);
        while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t'))
            trimmed.remove_prefix(1);
        if (!trimmed.empty())
            ++count;
    }
    return count;
}

// ── Linux: ufw ───────────────────────────────────────────────────────────

/// One row of `ufw status numbered` — a bracketed rule ordinal plus its
/// fixed-width To/Action/From columns.
struct UfwRule {
    std::string index; // the bracketed ordinal, e.g. "1" (from "[ 1]")
    std::string to;
    std::string action;
    std::string from;
};

namespace detail {

/// Split on runs of 2+ spaces (ufw's fixed-width column layout), preserving
/// single spaces inside a column value (e.g. the two-word action "ALLOW IN").
[[nodiscard]] inline std::vector<std::string_view> split_multi_space(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t i = 0;
    const std::size_t n = line.size();
    while (i < n) {
        while (i < n && line[i] == ' ')
            ++i;
        const std::size_t start = i;
        while (i < n && !(line[i] == ' ' && i + 1 < n && line[i + 1] == ' '))
            ++i;
        if (i > start)
            fields.push_back(line.substr(start, i - start));
        while (i < n && line[i] == ' ')
            ++i;
    }
    return fields;
}

} // namespace detail

/// Parse `ufw status` (the unnumbered form) — only the first "Status: …"
/// line matters.
///
/// Fixes a real bug in the shell-out this replaces: the old code did
/// `output.find("active") != npos`, which ALSO matches the substring
/// "active" inside "inactive" — misreporting a disabled ufw as active. This
/// checks a full-prefix match against "Status: active"/"Status: inactive"
/// instead, so "inactive" can never satisfy the "active" branch.
[[nodiscard]] inline FwState parse_ufw_status(std::string_view out) {
    constexpr std::string_view kInactive = "Status: inactive";
    constexpr std::string_view kActive = "Status: active";
    if (out.substr(0, kInactive.size()) == kInactive)
        return FwState::disabled;
    if (out.substr(0, kActive.size()) == kActive)
        return FwState::enabled;
    return FwState::unknown;
}

/// Parse `ufw status numbered` into structured rows. Only bracketed `[ N]`
/// rule lines are emitted — the "Status:" line, the blank separator, and the
/// "To / Action / From" header + its underline are skipped by construction
/// (none of them start with `[`).
[[nodiscard]] inline std::vector<UfwRule> parse_ufw_rules(std::string_view out) {
    std::vector<UfwRule> rules;
    std::string buf(out); // istringstream needs an owned string
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.front() != '[')
            continue;
        const auto close = line.find(']');
        if (close == std::string::npos)
            continue;

        UfwRule rule;
        std::string_view idx(line.data() + 1, close - 1);
        while (!idx.empty() && idx.front() == ' ')
            idx.remove_prefix(1);
        while (!idx.empty() && idx.back() == ' ')
            idx.remove_suffix(1);
        rule.index = std::string(idx);

        const auto fields = detail::split_multi_space(std::string_view(line).substr(close + 1));
        if (fields.size() >= 1)
            rule.to = std::string(fields[0]);
        if (fields.size() >= 2)
            rule.action = std::string(fields[1]);
        if (fields.size() >= 3)
            rule.from = std::string(fields[2]);
        rules.push_back(std::move(rule));
    }
    return rules;
}

// ── Linux: iptables ─────────────────────────────────────────────────────

enum class IptablesEntryType { policy, new_chain, append, unknown };

/// One row of `iptables -S` output — the command-form rule-save syntax
/// (`-P`/`-N`/`-A` lines), one row per line.
struct IptablesRule {
    IptablesEntryType type{IptablesEntryType::unknown};
    std::string chain;
    std::string spec; // policy target ("ACCEPT"/"DROP") for `policy`; empty
                       // for `new_chain`; the rule spec after the chain name
                       // for `append`; the raw line for `unknown`.
};

/// Parse `iptables -S` into structured rows, replacing the old opaque
/// `rule|<raw line>` passthrough. An unrecognised line (not `-P`/`-N`/`-A`)
/// parses to `IptablesEntryType::unknown` with the raw line preserved in
/// `spec` rather than being silently dropped.
[[nodiscard]] inline std::vector<IptablesRule> parse_iptables_save(std::string_view out) {
    std::vector<IptablesRule> rules;
    std::string buf(out);
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;

        std::istringstream ls(line);
        std::string tok;
        ls >> tok;

        IptablesRule r;
        if (tok == "-P") {
            r.type = IptablesEntryType::policy;
            ls >> r.chain;
            std::string target;
            ls >> target;
            r.spec = target;
        } else if (tok == "-N") {
            r.type = IptablesEntryType::new_chain;
            ls >> r.chain;
        } else if (tok == "-A") {
            r.type = IptablesEntryType::append;
            ls >> r.chain;
            std::string rest;
            std::getline(ls, rest);
            while (!rest.empty() && rest.front() == ' ')
                rest.erase(rest.begin());
            r.spec = rest;
        } else {
            r.type = IptablesEntryType::unknown;
            r.spec = line;
        }
        rules.push_back(std::move(r));
    }
    return rules;
}

// ── Linux: nftables (rung 1, netlink) ───────────────────────────────────
//
// Pure decode over NETLINK_NETFILTER/NFNL_SUBSYS_NFTABLES dump-reply bytes —
// zero socket/OS dependency, mirroring tar_netqual_nstat.hpp's split between
// a transcribed wire-format namespace (here: nft_raw) and free decode
// functions, and firewall_plugin.cpp's own header docblock claim that every
// parser in this file is OS-free and unit-tested on every host. Unlike
// tar_netqual_nstat.hpp's private/unversioned Darwin nstat ABI, the structs
// below transcribe STABLE, VERSIONED kernel UAPI headers (linux/netlink.h,
// linux/netfilter/nfnetlink.h, linux/netfilter/nf_tables.h) — confidence is
// correspondingly higher, and this leg HAS since been verified against a
// real kernel (see docs/agent-privilege-model.md's "Verified 2026-08-23"
// note: correct enumeration of ~50 real rules across ip/ip6/inet on a live
// host, 129/129 assertions passing). Every decode function still degrades
// honestly regardless (a malformed/unrecognised byte sequence yields an
// empty result or an "unknown"/`policyN`-shaped fallback string, never a
// crash or a fabricated value) exactly like this header's other parsers —
// that contract is retained for the untested no-CAP_NET_ADMIN denial path
// and any future malformed-reply case, not dropped now that the happy path
// is proven.
//
// Byte-order note (load-bearing, easy to get backwards): `nlmsghdr`/
// `nfgenmsg`/`nlattr` HEADER fields are HOST byte order (every supported
// deployment target is little-endian, so plain memcpy reads them correctly);
// nftables' own numeric ATTRIBUTE VALUES (chain policy, hook number, rule
// handle) are NETWORK byte order (big-endian) by nftables userspace
// convention — this is why load_be32/load_be64 exist as separate, explicit
// big-endian readers rather than reusing a native memcpy like the header
// fields do.
//
// Read-only by design (ADR-3002 Decision 8): only NFT_MSG_GET* dump requests
// are ever sent by the impure shell in firewall_plugin.cpp — a mutating leg
// needs a separately-approved brokered-elevation design and is out of scope
// here. Expression-level rule decoding (individual match/verdict opcodes
// inside NFTA_RULE_EXPRESSIONS) is ALSO out of scope, the same documented-gap
// pattern as this file's own firewalld getPorts() omission above: base-chain
// hook/policy plus per-rule handle enumeration is the high-confidence subset
// (mirrors what `nft list chains` shows), full expression bytecode decoding
// is a distinct, much larger follow-up.

namespace nft_raw {

// Every supported deployment target is little-endian (see the byte-order
// note above); the plain memcpy decode of nlmsghdr/nfgenmsg/nlattr header
// fields below relies on that silently. Pin it so a future big-endian
// target fails the build, not a live host.
static_assert(std::endian::native == std::endian::little,
              "nft_raw header decode assumes a little-endian host");

/// linux/netlink.h `struct nlmsghdr` (16 bytes, host byte order).
struct NlMsgHdr {
    std::uint32_t len{};
    std::uint16_t type{};
    std::uint16_t flags{};
    std::uint32_t seq{};
    std::uint32_t pid{};
};
static_assert(sizeof(NlMsgHdr) == 16);
// The decode is "memcpy the netlink bytes into a NlMsgHdr", which is only
// defined for a trivially copyable, standard-layout type (same precedent as
// linux_tcp_info.hpp) — pin both so a future field breaking either property
// fails the build, not a sanitizer at runtime.
static_assert(std::is_trivially_copyable_v<NlMsgHdr>,
              "NlMsgHdr must stay trivially copyable for the memcpy decode");
static_assert(std::is_standard_layout_v<NlMsgHdr>,
              "NlMsgHdr must stay standard-layout for its field layout to be well-defined");

/// linux/netfilter/nfnetlink.h `struct nfgenmsg` (4 bytes) — immediately
/// follows nlmsghdr in every NFNETLINK-family message, nftables included.
/// `family`/`version` are read like `nlmsghdr`/`nlattr` header fields (host
/// byte order); `res_id` is `__be16` (network byte order) in the real UAPI
/// struct, but this code always sends it as 0 and never reads it back on the
/// decode side, so the byte-order distinction is inert here today.
struct NfGenMsg {
    std::uint8_t family{};
    std::uint8_t version{};
    std::uint16_t res_id{}; // __be16 in the kernel struct; unused/always-zero here
};
static_assert(sizeof(NfGenMsg) == 4);
static_assert(std::is_trivially_copyable_v<NfGenMsg>,
              "NfGenMsg must stay trivially copyable for the memcpy decode");
static_assert(std::is_standard_layout_v<NfGenMsg>,
              "NfGenMsg must stay standard-layout for its field layout to be well-defined");

/// linux/netlink.h `struct nlattr` (4 bytes) — precedes each attribute's
/// value; `len` counts the header itself plus the (unpadded) value.
struct NlAttr {
    std::uint16_t len{};
    std::uint16_t type{};
};
static_assert(sizeof(NlAttr) == 4);
static_assert(std::is_trivially_copyable_v<NlAttr>,
              "NlAttr must stay trivially copyable for the memcpy decode");
static_assert(std::is_standard_layout_v<NlAttr>,
              "NlAttr must stay standard-layout for its field layout to be well-defined");

constexpr std::uint16_t kNlaTypeMask = 0x3fff; // NLA_TYPE_MASK
constexpr std::size_t kNlaAlignTo = 4;

constexpr std::uint16_t kNlmsgError = 0x2;
constexpr std::uint16_t kNlmsgDone = 0x3;

// linux/netlink.h NLM_F_DUMP_INTR: "Dump was inconsistent due to sequence
// change" -- set by the kernel on the terminating NLMSG_DONE when a
// concurrent ruleset mutation (another process editing nftables mid-dump)
// tore the reply. Must be checked on DONE, not inferred from anything else:
// a torn dump otherwise looks identical to a clean one.
constexpr std::uint16_t kNlmFDumpIntr = 0x10;

constexpr std::uint8_t kNfnlSubsysNftables = 10;
constexpr std::uint16_t kNftMsgGettable = 1;
constexpr std::uint16_t kNftMsgGetchain = 4;
constexpr std::uint16_t kNftMsgGetrule = 7;

// Reply message subtypes: the kernel answers a GET* dump request with the
// corresponding NEW* body (never an echo of the GET* type itself).
constexpr std::uint16_t kNftMsgNewtable = 0;
constexpr std::uint16_t kNftMsgNewchain = 3;
constexpr std::uint16_t kNftMsgNewrule = 6;

/// A full nlmsghdr `type` field packs the NFNETLINK subsystem into the high
/// byte and the subsystem-local message subtype into the low byte.
[[nodiscard]] constexpr std::uint16_t nft_msg_type(std::uint16_t msg) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(kNfnlSubsysNftables) << 8) |
                                       msg);
}

constexpr std::uint8_t kNfprotoUnspec = 0;
constexpr std::uint8_t kNfprotoInet = 1;
constexpr std::uint8_t kNfprotoIpv4 = 2;
constexpr std::uint8_t kNfprotoArp = 3;
constexpr std::uint8_t kNfprotoNetdev = 5;
constexpr std::uint8_t kNfprotoBridge = 7;
constexpr std::uint8_t kNfprotoIpv6 = 10;

constexpr std::uint16_t kNftaTableName = 1;

constexpr std::uint16_t kNftaChainTable = 1;
constexpr std::uint16_t kNftaChainName = 3;
constexpr std::uint16_t kNftaChainHook = 4;
constexpr std::uint16_t kNftaChainPolicy = 5;

constexpr std::uint16_t kNftaHookHooknum = 1;

constexpr std::uint16_t kNftaRuleTable = 1;
constexpr std::uint16_t kNftaRuleChain = 2;
constexpr std::uint16_t kNftaRuleHandle = 3;

constexpr std::uint32_t kNftPolicyDrop = 0;
constexpr std::uint32_t kNftPolicyAccept = 1;

/// One decoded netlink message: its header plus the raw payload span
/// (nfgenmsg + attributes for a data message; unexamined for
/// NLMSG_DONE/NLMSG_ERROR).
struct RawNlMsg {
    NlMsgHdr hdr;
    std::span<const std::byte> payload;
};

/// Splits a raw dump-reply buffer into its nlmsghdr-framed messages. A
/// message whose declared `len` is shorter than the header or overruns the
/// buffer stops the walk at that point (truncated input decodes to "as much
/// as could be safely read", never an out-of-bounds read) — same contract as
/// tar_netqual_nstat.hpp's nstat_frame_messages().
[[nodiscard]] inline std::vector<RawNlMsg> split_nlmsgs(std::span<const std::byte> buf) {
    std::vector<RawNlMsg> msgs;
    std::size_t off = 0;
    while (off + sizeof(NlMsgHdr) <= buf.size()) {
        NlMsgHdr hdr{};
        std::memcpy(&hdr, buf.data() + off, sizeof(hdr));
        // Subtraction form, not off + hdr.len > buf.size(): the loop guard
        // above already proves off <= buf.size(), so buf.size() - off can
        // never underflow, whereas the addition form is only safe because
        // hdr.len/off happen to stay well under SIZE_MAX today.
        if (hdr.len < sizeof(NlMsgHdr) || hdr.len > buf.size() - off)
            break;
        const std::size_t payload_len = hdr.len - sizeof(NlMsgHdr);
        msgs.push_back({hdr, buf.subspan(off + sizeof(NlMsgHdr), payload_len)});
        const std::size_t aligned = (hdr.len + (kNlaAlignTo - 1)) & ~(kNlaAlignTo - 1);
        if (aligned == 0)
            break; // unreachable given the >= sizeof(NlMsgHdr) check above; defensive
        // Clamp rather than let off run past buf.size() by up to 3 padding
        // bytes: the next loop guard would catch it either way, but this
        // makes "truncated input decodes to as much as could be safely
        // read" the literal post-condition instead of an incidental one.
        off = std::min(buf.size(), off + aligned);
    }
    return msgs;
}

struct RawAttr {
    std::uint16_t type; // NLA_TYPE_MASK already applied
    std::span<const std::byte> value;
};

/// Walks one flat (non-nested) attribute stream. Same truncated-input
/// contract as split_nlmsgs. Nested attributes (e.g. NFTA_CHAIN_HOOK's
/// value) are walked by calling this again on that attribute's `value`.
[[nodiscard]] inline std::vector<RawAttr> walk_attrs(std::span<const std::byte> data) {
    std::vector<RawAttr> out;
    std::size_t off = 0;
    while (off + sizeof(NlAttr) <= data.size()) {
        NlAttr hdr{};
        std::memcpy(&hdr, data.data() + off, sizeof(hdr));
        // Subtraction form — see split_nlmsgs()'s identical guard above.
        if (hdr.len < sizeof(NlAttr) || hdr.len > data.size() - off)
            break;
        const std::uint16_t type = hdr.type & kNlaTypeMask;
        const std::size_t value_len = hdr.len - sizeof(NlAttr);
        out.push_back({type, data.subspan(off + sizeof(NlAttr), value_len)});
        const std::size_t aligned = (hdr.len + (kNlaAlignTo - 1)) & ~(kNlaAlignTo - 1);
        if (aligned == 0)
            break;
        off += aligned;
    }
    return out;
}

/// NUL-terminated string attribute value → std::string (stops at the first
/// NUL or the end of the value span, whichever comes first).
[[nodiscard]] inline std::string nla_string(std::span<const std::byte> v) {
    std::size_t len = 0;
    while (len < v.size() && v[len] != std::byte{0})
        ++len;
    return std::string(reinterpret_cast<const char*>(v.data()), len);
}

/// Big-endian u32 attribute value (nftables numeric-attribute convention —
/// see the byte-order note above). nullopt if the value is too short.
[[nodiscard]] constexpr std::optional<std::uint32_t>
load_be32(std::span<const std::byte> v) noexcept {
    if (v.size() < 4)
        return std::nullopt;
    return (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[0])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[3]));
}

/// Big-endian u64 attribute value (NFTA_RULE_HANDLE is `__be64`).
[[nodiscard]] constexpr std::optional<std::uint64_t>
load_be64(std::span<const std::byte> v) noexcept {
    if (v.size() < 8)
        return std::nullopt;
    std::uint64_t r = 0;
    for (int i = 0; i < 8; ++i)
        r = (r << 8) | static_cast<std::uint64_t>(std::to_integer<unsigned char>(v[i]));
    return r;
}

/// Decodes an NLMSG_ERROR payload's leading `struct nlmsgerr::error` field
/// (host byte order, like every other header field this file decodes — see
/// the byte-order note above). This backend never sets NLM_F_ACK on its own
/// requests (#3462-5), so error==0 (an ACK, not a failure) is itself
/// anomalous rather than meaningful — treated as nullopt, same as a payload
/// too short to hold the field, rather than misread as "no error".
[[nodiscard]] inline std::optional<std::int32_t>
parse_nlmsgerr(std::span<const std::byte> payload) noexcept {
    if (payload.size() < sizeof(std::int32_t))
        return std::nullopt;
    std::int32_t error{};
    std::memcpy(&error, payload.data(), sizeof(error));
    if (error == 0)
        return std::nullopt; // NLM_F_ACK is never requested; a bare ACK is anomalous, not success
    return error;
}

/// Decodes the signed `dump_done_errno` the kernel memcpys into an
/// NLMSG_DONE message's body (confirmed against net/netlink/af_netlink.c
/// netlink_dump_done(): nlmsg_put_answer(sizeof(dump_done_errno)) then
/// memcpy(nlmsg_data(nlh), &dump_done_errno, ...)). A pre-v4.13 kernel emits
/// a bare DONE with no payload at all — indistinguishable here from "field
/// absent", so that decodes to nullopt and the caller treats it as ok, not
/// as a truncation.
[[nodiscard]] inline std::optional<std::int32_t>
parse_nft_done_errno(std::span<const std::byte> done_msg_payload) noexcept {
    if (done_msg_payload.size() < sizeof(std::int32_t))
        return std::nullopt; // bare (pre-v4.13) DONE, or a too-short payload -- treat as ok
    std::int32_t errno_val{};
    std::memcpy(&errno_val, done_msg_payload.data(), sizeof(errno_val));
    return errno_val;
}

} // namespace nft_raw

namespace detail {

/// Keeps only the messages whose header `type` is EXACTLY `expected_type`
/// (UP-11 #3461): a mistyped/stray reply body — e.g. a NEWCHAIN row arriving
/// on what should be a GETTABLE dump — is dropped rather than misparsed as
/// this dump's data. NLMSG_DONE/NLMSG_ERROR are excluded by the same exact
/// match, since neither carries the requested data-message type.
[[nodiscard]] inline std::vector<nft_raw::RawNlMsg>
nft_data_msgs(std::span<const std::byte> buf, std::uint16_t expected_type) {
    std::vector<nft_raw::RawNlMsg> out;
    for (auto& m : nft_raw::split_nlmsgs(buf)) {
        if (m.hdr.type == expected_type)
            out.push_back(std::move(m));
    }
    return out;
}

} // namespace detail

struct NftTableInfo {
    std::uint8_t family{};
    std::string name;
};

struct NftChainInfo {
    std::uint8_t family{};
    std::string table;
    std::string name;
    bool is_base_chain{false};             // NFTA_CHAIN_HOOK present
    std::optional<std::uint32_t> hooknum;  // only meaningful when is_base_chain
    std::optional<std::uint32_t> policy;   // only meaningful when is_base_chain
};

struct NftRuleInfo {
    std::uint8_t family{};
    std::string table;
    std::string chain;
    std::optional<std::uint64_t> handle;
};

/// Parses one NFT_MSG_GETTABLE dump-reply buffer. Only exactly
/// NFT_MSG_NEWTABLE-typed messages are examined (detail::nft_data_msgs) —
/// NLMSG_DONE/NLMSG_ERROR and any stray/mistyped body are excluded by that
/// same exact match, and the caller decides reachability from the dump
/// round-trip's own success/failure, not from this function; a message whose
/// table name could not be decoded is dropped rather than emitted with an
/// empty name.
[[nodiscard]] inline std::vector<NftTableInfo> parse_nft_tables(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftTableInfo> out;
    for (const auto& m : detail::nft_data_msgs(buf, nft_msg_type(kNftMsgNewtable))) {
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftTableInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            if (a.type == kNftaTableName)
                info.name = nla_string(a.value);
        }
        if (!info.name.empty())
            out.push_back(std::move(info));
    }
    return out;
}

/// Parses one NFT_MSG_GETCHAIN dump-reply buffer. A chain is a "base chain"
/// (attached to a netfilter hook, and the only kind with a policy) iff
/// NFTA_CHAIN_HOOK is present — a regular (non-base) chain exists only as a
/// jump target and carries neither hook nor policy.
[[nodiscard]] inline std::vector<NftChainInfo> parse_nft_chains(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftChainInfo> out;
    for (const auto& m : detail::nft_data_msgs(buf, nft_msg_type(kNftMsgNewchain))) {
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftChainInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            switch (a.type) {
            case kNftaChainTable:
                info.table = nla_string(a.value);
                break;
            case kNftaChainName:
                info.name = nla_string(a.value);
                break;
            case kNftaChainHook:
                info.is_base_chain = true;
                for (const auto& h : walk_attrs(a.value)) {
                    if (h.type == kNftaHookHooknum)
                        info.hooknum = load_be32(h.value);
                }
                break;
            case kNftaChainPolicy:
                info.policy = load_be32(a.value);
                break;
            default:
                break;
            }
        }
        if (!info.name.empty())
            out.push_back(std::move(info));
    }
    return out;
}

/// Parses one NFT_MSG_GETRULE dump-reply buffer into per-rule handle rows
/// (see the header comment above: expression-level decoding is out of
/// scope). A rule row is still emitted even if the table/chain attribute
/// could not be decoded — an incomplete row is still meaningful evidence
/// that a rule exists, unlike a table/chain with no name.
[[nodiscard]] inline std::vector<NftRuleInfo> parse_nft_rules(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftRuleInfo> out;
    for (const auto& m : detail::nft_data_msgs(buf, nft_msg_type(kNftMsgNewrule))) {
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftRuleInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            switch (a.type) {
            case kNftaRuleTable:
                info.table = nla_string(a.value);
                break;
            case kNftaRuleChain:
                info.chain = nla_string(a.value);
                break;
            case kNftaRuleHandle:
                info.handle = load_be64(a.value);
                break;
            default:
                break;
            }
        }
        out.push_back(std::move(info));
    }
    return out;
}

/// "Active" heuristic mirroring parse_iptables_save's has_content logic in
/// firewall_plugin.cpp's try_iptables_state: any actual rule, or any base
/// chain whose policy is not the default-open "accept", counts as active
/// content. An empty ruleset (no tables at all, or tables with no base
/// chains/rules) is inactive — never fabricated as active.
[[nodiscard]] inline bool nft_has_content(const std::vector<NftChainInfo>& chains,
                                          const std::vector<NftRuleInfo>& rules) {
    if (!rules.empty())
        return true;
    for (const auto& c : chains) {
        if (c.is_base_chain && c.policy.has_value() && *c.policy != nft_raw::kNftPolicyAccept)
            return true;
    }
    return false;
}

// ── nftables dump outcome (#3462-6, #3463-2) ────────────────────────────
//
// Every possible way a single GET*-dump round-trip (the impure shell's
// bounded netlink socket I/O in firewall_plugin.cpp) can end, decoupled from
// that I/O so the decision of what a given outcome MEANS is pure and
// unit-testable independent of the socket/poll/deadline machinery that
// produces it.

/// How one nftables dump round-trip (GETTABLE/GETCHAIN/GETRULE) ended.
enum class NftDumpStatus {
    ok,             // clean NLMSG_DONE, errno 0 (or a bare pre-v4.13 DONE)
    timeout,        // the acquisition deadline elapsed before NLMSG_DONE
    kernel_error,   // NLMSG_ERROR, or a nonzero NLMSG_DONE dump_done_errno
    foreign_flood,  // too many non-matching-pid/seq datagrams (kNftMaxForeignDatagrams)
    truncated,      // the socket read returned less than a full message
    oversized,      // the dump exceeded kNftDumpMaxBytes before terminating
    io_error,       // the socket call itself failed (recv/poll error)
    torn,           // NLMSG_DONE arrived with NLM_F_DUMP_INTR -- a concurrent
                     // ruleset mutation interrupted the dump mid-read; the
                     // kernel signals this on an otherwise-normal DONE, so
                     // "io_error" (a syscall failure) would be the wrong
                     // diagnosis for an operator troubleshooting it
                     // (code-review finding).
};

/// One dump round-trip's outcome: the status plus, for `kernel_error`, the
/// decoded errno (from parse_nlmsgerr or parse_nft_done_errno) that caused
/// it — 0 when the status carries no specific errno.
struct NftDumpResult {
    NftDumpStatus status{NftDumpStatus::io_error};
    int kernel_errno{0};
};

constexpr std::size_t kNftDumpMaxBytes = 4 * 1024 * 1024;
constexpr int kNftMaxForeignDatagrams = 64;

/// Whether a dump's data may be trusted as a complete, honest enumeration —
/// the gate try_nftables_state()/try_nftables_rules() must pass before
/// treating either dump's rows as meaningful rather than "reachability
/// unknown".
[[nodiscard]] constexpr bool nft_dumps_trusted(bool chains_ok, bool rules_ok) noexcept {
    return chains_ok && rules_ok;
}

/// The nftables-backend state verdict: `unknown` whenever either dump could
/// not be trusted (never inferred from partial/possibly-truncated content),
/// otherwise `active`/`inactive` per nft_has_content() — moved out of the
/// shell (#3463-2) so this decision is unit-tested at the pure layer.
enum class NftVerdict { active, inactive, unknown };

[[nodiscard]] inline NftVerdict nft_decide_state(bool chains_ok, bool rules_ok,
                                                  const std::vector<NftChainInfo>& chains,
                                                  const std::vector<NftRuleInfo>& rules) {
    if (!nft_dumps_trusted(chains_ok, rules_ok))
        return NftVerdict::unknown;
    return nft_has_content(chains, rules) ? NftVerdict::active : NftVerdict::inactive;
}

/// The wire token for a verdict -- `try_nftables_state()` formats its
/// `state|<token>` row through this rather than re-deriving the string
/// inline, so the tested decision function (nft_decide_state, above) is the
/// same code the production dispatch path actually runs (code-review
/// finding, both Functional and Spec axes: nft_decide_state previously had
/// zero production callers despite being unit-tested).
[[nodiscard]] constexpr std::string_view nft_verdict_name(NftVerdict v) noexcept {
    switch (v) {
    case NftVerdict::active:
        return "active";
    case NftVerdict::inactive:
        return "inactive";
    case NftVerdict::unknown:
        return "unknown";
    }
    return "unknown"; // unreachable -- exhaustive switch, -Wswitch flags enum drift
}

/// Reconciles the nftables backend's own verdict against the fact that a
/// later probe stage already found nftables *tables* present (C4): a
/// downstream `disabled` verdict is contradicted by tables existing at all
/// (something is managing this ruleset, even if this dump could not read its
/// content trustworthily) and is clamped to `unknown` rather than reported
/// as a confident "disabled". `enabled` always stands unchanged — a rung-2
/// active reading is never downgraded by this reconciliation.
[[nodiscard]] constexpr FwState nft_fallthrough_clamp(bool tables_seen,
                                                        FwState downstream_state) noexcept {
    if (tables_seen && downstream_state == FwState::disabled)
        return FwState::unknown;
    return downstream_state;
}

/// Composes subprocess_complete() with nft_fallthrough_clamp(): the single
/// completeness-gated state decision every rung-2 backend (ufw, iptables)
/// makes the same way -- an incomplete subprocess read must degrade to
/// unknown regardless of what its (possibly partial) output parsed to
/// (governance gate2 security-guardian HIGH finding, r1). Pulled out so
/// this composition itself is unit-tested, not just its two halves
/// independently (governance gate3 quality-engineer finding, r2) -- the
/// prior shape (`subprocess_complete(res) ? nft_fallthrough_clamp(...) :
/// FwState::unknown`) was inline at each call site and only its two
/// ingredients had direct test coverage, never the gate itself.
[[nodiscard]] constexpr FwState gate_state_on_completeness(bool complete, bool tables_seen,
                                                            FwState parsed_state) noexcept {
    return complete ? nft_fallthrough_clamp(tables_seen, parsed_state) : FwState::unknown;
}

/// Maps a dump outcome to its diagnostic token. `kernel_error` further
/// distinguishes the common permission-denied case (no CAP_NET_ADMIN) from
/// any other kernel errno, since that's the one an operator can act on
/// directly.
[[nodiscard]] inline std::string nft_dump_reason(NftDumpResult res) {
    switch (res.status) {
    case NftDumpStatus::ok:
        return "ok";
    case NftDumpStatus::timeout:
        return "timeout";
    case NftDumpStatus::kernel_error:
        if (res.kernel_errno == -EPERM)
            return "eperm";
        // A kernel_error whose errno could not itself be decoded (too-short
        // NLMSG_ERROR payload, or the error==0 ACK-anomaly parse_nlmsgerr
        // deliberately treats as nullopt) collapses to kernel_errno==0 here
        // -- formatting that as "errno:0" would read as a specifically
        // decoded errno zero, which never happened (code-review finding:
        // an operator would conclude "the kernel reported errno 0" when
        // the truth is "the errno couldn't be read at all").
        if (res.kernel_errno == 0)
            return "errno:undecoded";
        // Widen to int64_t before abs(): std::abs(INT_MIN) on a plain int
        // is signed-overflow UB. Real kernel errnos are bounded to
        // [-MAX_ERRNO,-1] by convention and this path is only reached
        // after sender verification, so INT_MIN is not reachable in
        // practice -- but nothing upstream enforces that range, so widen
        // rather than rely on it (governance gate2 security-guardian
        // finding, r2).
        return "errno:" +
               std::to_string(std::abs(static_cast<std::int64_t>(res.kernel_errno)));
    case NftDumpStatus::foreign_flood:
        return "foreign_flood";
    case NftDumpStatus::truncated:
        return "truncated";
    case NftDumpStatus::oversized:
        return "oversized";
    case NftDumpStatus::io_error:
        return "io_error";
    case NftDumpStatus::torn:
        return "torn";
    }
    return "io_error"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// Formats a failed-dump diagnostic row for one nftables sub-dump (`dump` is
/// "table"/"chain"/"rule") in the same `<kind>|nftables|...` row family the
/// rest of this backend writes.
[[nodiscard]] inline std::string nft_diag_row(std::string_view dump, NftDumpResult res) {
    return std::format("error|nftables:{}:{}", dump, nft_dump_reason(res));
}

/// Formats the row written when the nftables backend gives up on `dump`
/// entirely and probing falls through to the next backend in the ladder
/// (ufw/iptables) — same shape as nft_diag_row(), distinct leading token so
/// the two cases are distinguishable downstream.
[[nodiscard]] inline std::string nft_fallthrough_row(std::string_view dump, NftDumpResult res) {
    return std::format("fallthrough|nftables:{}:{}", dump, nft_dump_reason(res));
}

[[nodiscard]] inline std::string nft_family_name(std::uint8_t family) {
    using namespace nft_raw;
    switch (family) {
    case kNfprotoUnspec:
        return "unspec";
    case kNfprotoInet:
        return "inet";
    case kNfprotoIpv4:
        return "ip";
    case kNfprotoArp:
        return "arp";
    case kNfprotoNetdev:
        return "netdev";
    case kNfprotoBridge:
        return "bridge";
    case kNfprotoIpv6:
        return "ip6";
    default:
        return "family" + std::to_string(static_cast<int>(family));
    }
}

[[nodiscard]] inline std::string nft_hook_name(std::optional<std::uint32_t> hooknum) {
    if (!hooknum)
        return "unknown";
    switch (*hooknum) {
    case 0:
        return "prerouting";
    case 1:
        return "input";
    case 2:
        return "forward";
    case 3:
        return "output";
    case 4:
        return "postrouting";
    default:
        return "hook" + std::to_string(*hooknum);
    }
}

[[nodiscard]] inline std::string nft_policy_name(std::optional<std::uint32_t> policy) {
    if (!policy)
        return "unknown";
    if (*policy == nft_raw::kNftPolicyAccept)
        return "accept";
    if (*policy == nft_raw::kNftPolicyDrop)
        return "drop";
    return "policy" + std::to_string(*policy);
}

/// Strips pipe/newline/CR from a value echoed back into the pipe-delimited
/// protocol so a hostile/unusual value cannot inject synthetic fields or
/// rows. Hoisted from firewall_plugin.cpp's file-local helper of the same
/// name/body so both the shell's own output rows and this header's
/// format_nft_* rows route through one definition instead of two.
[[nodiscard]] inline std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    }
    return out;
}

/// Formats one base chain as the exact `rule|nftables|...` pipe-delimited
/// row try_nftables_rules() (firewall_plugin.cpp) writes for it. Table/chain
/// names are sanitized via sanitize_field() so a hostile/unusual nftables
/// name can't inject a synthetic field or row. Pulled out as its own pure
/// function so the try_nftables_* -> output-row integration path —
/// previously only exercised by manual live-kernel verification — is
/// covered by a unit test against the actual field order/shape, not just
/// the upstream parse_nft_* decoders.
[[nodiscard]] inline std::string format_nft_chain_rule_row(const NftChainInfo& c) {
    return std::format("rule|nftables|{}|{}|{}|{}|{}", nft_family_name(c.family),
                        sanitize_field(c.table), sanitize_field(c.name), nft_hook_name(c.hooknum),
                        nft_policy_name(c.policy));
}

/// Formats one rule handle as the exact `rule|nftables|...|handle|...` row
/// try_nftables_rules() writes for it -- same pull-out rationale as
/// format_nft_chain_rule_row() above.
[[nodiscard]] inline std::string format_nft_rule_handle_row(const NftRuleInfo& r) {
    return std::format("rule|nftables|{}|{}|{}|handle|{}", nft_family_name(r.family),
                        sanitize_field(r.table), sanitize_field(r.chain),
                        r.handle ? std::to_string(*r.handle) : "unknown");
}

/// Whether a subprocess-backed acquisition genuinely completed: only under
/// this gate may a backend report a real ruleset|<n> count -- anything short
/// (didn't run, nonzero exit, killed by the deadline, or output clipped)
/// must report ruleset|unknown instead of a fabricated/undercounted number.
/// Hoisted out of the (previously Linux-only-compiled) shell so this
/// completeness decision -- which every backend on every platform makes the
/// same way -- is itself unit-tested rather than only exercised indirectly
/// through platform-specific dispatch tests (code-review finding).
[[nodiscard]] constexpr bool subprocess_complete(const yuzu::agent::SubprocessResult& res) noexcept {
    return res.tool_ran && res.exit_code == 0 && !res.timed_out && !res.output_truncated;
}

} // namespace yuzu::firewall
