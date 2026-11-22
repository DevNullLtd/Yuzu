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
#include <chrono>
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
/// trimmed. The caller runs the read as `sudo -n -- /sbin/pfctl -s Anchors` and
/// gates on subprocess_complete() first, so a refused grant or a failed pfctl
/// (exit non-zero) never reaches this parser: it sees only a completed read.
/// Empty output yields an empty vector; blank lines are skipped rather than
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
// zero socket/OS dependency, mirroring echo_netqual_nstat.hpp's split between
// a transcribed wire-format namespace (here: nft_raw) and free decode
// functions, and firewall_plugin.cpp's own header docblock claim that every
// parser in this file is OS-free and unit-tested on every host. Unlike
// echo_netqual_nstat.hpp's private/unversioned Darwin nstat ABI, the structs
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
/// struct. A request always sends it as 0. On a dump REPLY the kernel puts the
/// ruleset generation there (the low 16 bits of its commit counter): it moves
/// with every commit, so nft_dump_generation() reads it, always from the wire
/// bytes as big-endian and never through this host-order field.
struct NfGenMsg {
    std::uint8_t family{};
    std::uint8_t version{};
    std::uint16_t res_id{}; // __be16 in the kernel struct; 0 in a request, the generation in a reply
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
/// echo_netqual_nstat.hpp's nstat_frame_messages().
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
    generation_changed, // every dump ended cleanly, but they did not all carry
                        // the same ruleset generation: a commit landed between
                        // two dumps, so the three views describe different
                        // rulesets even though none was individually torn
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

/// Whether a dump's data may be trusted as a complete, honest enumeration.
/// run_nft_probe's own gate is `failed.empty()` (every dump of the pass ended
/// cleanly); this is the pure function's own guard, so nft_decide_state() below
/// never reads partial content as a verdict even if a caller reaches it with an
/// untrusted dump.
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
    case NftDumpStatus::generation_changed:
        return "changed";
    }
    return "io_error"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// How many consecutive probes that still end in churn (torn or a moved generation, after the
/// one re-run) it takes for the reason to stop reading as a passing collision and say so.
constexpr unsigned kNftChurnThreshold = 3;

/// The reason token for a churn failure, given how many consecutive probes (this one
/// included) have ended in churn. A ruleset that is rewritten continuously is not a collision
/// any more: from the third such probe in a row the reason is `torn_persistent`. Any other
/// reason, and a streak below the threshold, passes through unchanged.
[[nodiscard]] inline std::string nft_churn_reason(std::string_view reason, unsigned consecutive) {
    if (consecutive >= kNftChurnThreshold && (reason == "torn" || reason == "changed"))
        return "torn_persistent";
    return std::string{reason};
}

/// A dump that was torn mid-read or whose generation moved between dumps: the ruleset was being
/// rewritten while it was read, which a second look can settle. Every other failure is not that.
[[nodiscard]] constexpr bool nft_is_churn(NftDumpStatus s) noexcept {
    return s == NftDumpStatus::torn || s == NftDumpStatus::generation_changed;
}

/// One failed dump of a probe pass: its label (`chain`, `rule` or `generation`) and how it ended.
struct NftFailedDump {
    std::string_view dump; // static storage only: every producer passes a string literal
    NftDumpResult result;
};

/// Every dump of a pass that was not trusted, in a fixed order: the chain dump, the rule dump,
/// and only when both of those ended cleanly the generation check. A mismatch between two clean
/// dumps is a failure of its own; next to a failed dump it adds nothing, because a failed dump
/// has no trustworthy generation to compare. Empty means the pass can be trusted.
[[nodiscard]] inline std::vector<NftFailedDump> nft_failed_dumps(NftDumpResult chain_res,
                                                                 NftDumpResult rule_res,
                                                                 bool generations_consistent) {
    std::vector<NftFailedDump> out;
    if (chain_res.status != NftDumpStatus::ok)
        out.push_back({"chain", chain_res});
    if (rule_res.status != NftDumpStatus::ok)
        out.push_back({"rule", rule_res});
    if (out.empty() && !generations_consistent)
        out.push_back({"generation", NftDumpResult{NftDumpStatus::generation_changed, 0}});
    return out;
}

/// True when there is at least one failure and every failure is churn.
[[nodiscard]] inline bool nft_churn_only(std::span<const NftFailedDump> failed) noexcept {
    return !failed.empty() &&
           std::all_of(failed.begin(), failed.end(),
                       [](const NftFailedDump& f) { return nft_is_churn(f.result.status); });
}

/// A probe reads the ruleset at most this many times: the pass and, on churn, one re-run.
constexpr int kNftMaxAttempts = 2;
/// A re-run needs at least this long left in the overall acquisition budget.
inline constexpr std::chrono::milliseconds kNftRerunFloor{2000};

/// Whether to read the ruleset again. `only_churn_failures` is nft_churn_only() of the pass just
/// finished; a timeout, an error or an oversized dump gets no second look, because the cause is
/// not a collision and a second read would only spend more of the budget.
[[nodiscard]] constexpr bool nft_rerun_worthwhile(bool only_churn_failures, int attempts_done,
                                                  std::chrono::milliseconds remaining) noexcept {
    return only_churn_failures && attempts_done < kNftMaxAttempts && remaining >= kNftRerunFloor;
}

// ── nftables ruleset generation (#4400) ─────────────────────────────────

/// The ruleset generation the kernel stamped on a dump: the big-endian `res_id` of the nfgenmsg
/// that follows the nlmsghdr of the first data message of exactly `expected_type`. It moves with
/// every committed change and is the same on every message of one dump. nullopt when the dump
/// holds no such message (an empty ruleset dumps no table, chain or rule at all, so there is no
/// value to compare, which is different from a value of zero). The counter is 16 bits wide, so
/// a wrap between two dumps (65536 commits) is not seen.
[[nodiscard]] inline std::optional<std::uint16_t>
nft_dump_generation(std::span<const std::byte> buf, std::uint16_t expected_type) {
    for (const auto& m : detail::nft_data_msgs(buf, expected_type)) {
        if (m.payload.size() < sizeof(nft_raw::NfGenMsg))
            continue;
        return static_cast<std::uint16_t>((std::to_integer<unsigned>(m.payload[2]) << 8) |
                                          std::to_integer<unsigned>(m.payload[3]));
    }
    return std::nullopt;
}

/// True when every generation that is present is the same one. An absent value (a dump with no
/// data message) takes no part: there is nothing to compare, and an empty ruleset must not read
/// as a change.
[[nodiscard]] constexpr bool nft_generations_consistent(std::optional<std::uint16_t> a,
                                                        std::optional<std::uint16_t> b,
                                                        std::optional<std::uint16_t> c) noexcept {
    std::optional<std::uint16_t> seen;
    for (const auto& g : {a, b, c}) {
        if (!g)
            continue;
        if (seen && *seen != *g)
            return false;
        seen = g;
    }
    return true;
}

// ── opening the netlink socket (#4402) ──────────────────────────────────

/// How an open_nft_socket() failure should be handled by the caller.
enum class OpenNftErrClass {
    fd_exhausted,      // EMFILE/ENFILE -- a system-wide condition worth surfacing
    unsupported,       // EPROTONOSUPPORT/EAFNOSUPPORT -- this kernel has no
                       // NETLINK_NETFILTER at all; not worth a diagnostic row. A
                       // denied address family (systemd RestrictAddressFamilies=
                       // answers EAFNOSUPPORT) reads the same way: no row.
    permission_denied, // EPERM/EACCES -- socket()/bind() itself was refused
                       // (seccomp, AppArmor). Distinct
                       // from `other`: this is diagnosable and actionable the
                       // same way the existing dump-level eperm token already is
                       // (governance gate6 sre finding, r2 -- previously fell
                       // into `other` and emitted no row at all, indistinguishable
                       // from "kernel genuinely has no nftables").
    other,
};

[[nodiscard]] inline OpenNftErrClass classify_open_errno(int err) noexcept {
    if (err == EMFILE || err == ENFILE)
        return OpenNftErrClass::fd_exhausted;
    if (err == EPROTONOSUPPORT || err == EAFNOSUPPORT)
        return OpenNftErrClass::unsupported;
    if (err == EPERM || err == EACCES)
        return OpenNftErrClass::permission_denied;
    return OpenNftErrClass::other;
}

/// The diagnostic rows for the socket-open errnos one probe collected, each actionable row once
/// and in the order it was first seen: `fd_exhausted` and `permission_denied` only. `unsupported`
/// (this kernel has no NETLINK_NETFILTER) and `other` stay silent. The three dumps of a pass, and
/// the re-run, hit the same condition together, so one row says it, not one per dump.
[[nodiscard]] inline std::vector<std::string> nft_open_diag_rows(std::span<const int> errnos) {
    std::vector<std::string> rows;
    auto add = [&rows](std::string row) {
        if (std::find(rows.begin(), rows.end(), row) == rows.end())
            rows.push_back(std::move(row));
    };
    for (const int err : errnos) {
        switch (classify_open_errno(err)) {
        case OpenNftErrClass::fd_exhausted:
            add("error|fd_exhausted");
            break;
        case OpenNftErrClass::permission_denied:
            add("error|nftables:socket:eperm");
            break;
        case OpenNftErrClass::unsupported:
        case OpenNftErrClass::other:
            break;
        }
    }
    return rows;
}

/// Formats a failed-dump diagnostic row for one nftables sub-dump (`dump` is
/// "table"/"chain"/"rule") in the same `<kind>|nftables|...` row family the
/// rest of this backend writes.
[[nodiscard]] inline std::string nft_diag_row(std::string_view dump, NftDumpResult res,
                                              unsigned churn_streak = 0) {
    return std::format("error|nftables:{}:{}", dump, nft_churn_reason(nft_dump_reason(res), churn_streak));
}

/// Formats the row written when the nftables backend gives up on `dump`
/// entirely and probing falls through to the next backend in the ladder
/// (ufw/iptables) — same shape as nft_diag_row(), distinct leading token so
/// the two cases are distinguishable downstream.
[[nodiscard]] inline std::string nft_fallthrough_row(std::string_view dump, NftDumpResult res,
                                                     unsigned churn_streak = 0) {
    return std::format("fallthrough|nftables:{}:{}", dump, nft_churn_reason(nft_dump_reason(res), churn_streak));
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

/// Why a read did not complete, as the token a row carries: empty exactly when
/// subprocess_complete() holds. `not_run` (the tool never started), `timeout`, `truncated` (the
/// output was clipped) or `exit:<n>` (it ran and exited non-zero, `-1` when a signal ended it).
/// A timeout wins over a clipped output, which wins over an exit code, because the earlier cause
/// makes the later ones meaningless.
[[nodiscard]] inline std::string subprocess_failure_token(const yuzu::agent::SubprocessResult& res) {
    if (!res.tool_ran)
        return "not_run";
    if (res.timed_out)
        return "timeout";
    if (res.output_truncated)
        return "truncated";
    if (res.exit_code != 0)
        return std::format("exit:{}", res.exit_code);
    return {};
}

// ── macOS rows ──────────────────────────────────────────────────────────
//
// Every macOS read below is gated on subprocess_complete(): an incomplete read yields no rows
// built from its text, and a row that says `unknown` because the read did not complete is
// followed by the error row that explains it, so an unprivileged agent (pfctl exits 1) reads as
// "could not read", never as "no firewall". A read that completed but whose text is not
// recognised (`pf|unknown` from a `pfctl -s info` with neither `Status: Enabled` nor
// `Status: Disabled`, or `state|unknown` from a garbled socketfilterfw answer) is `unknown` alone:
// nothing failed to run, so there is no error row.

[[nodiscard]] inline std::string alf_decision_name(AlfDecision d) {
    switch (d) {
    case AlfDecision::allow:
        return "allow";
    case AlfDecision::block:
        return "block";
    case AlfDecision::unknown:
        return "unknown";
    }
    return "unknown"; // unreachable -- exhaustive switch, -Wswitch flags enum drift
}

/// The `state` rows of macOS, from the four reads: `socketfilterfw --getglobalstate`,
/// `pfctl -s info`, `pfctl -s Anchors` and `pfctl -s rules`. Row order: backend, state (and
/// `mode|block_all`), pf, the anchors, the rule count; an error row sits right after the row it
/// explains, or where the rows it replaces would have been.
[[nodiscard]] inline std::vector<std::string>
macos_state_rows(const yuzu::agent::SubprocessResult& alf, const yuzu::agent::SubprocessResult& pf_info,
                 const yuzu::agent::SubprocessResult& anchors,
                 const yuzu::agent::SubprocessResult& rules) {
    std::vector<std::string> rows;
    rows.emplace_back("backend|appfirewall");
    if (const auto why = subprocess_failure_token(alf); why.empty()) {
        const auto g = parse_alf_global_state(alf.output);
        rows.push_back(std::format("state|{}", to_string(g.state)));
        if (g.block_all)
            rows.emplace_back("mode|block_all");
    } else {
        rows.emplace_back("state|unknown");
        rows.push_back(std::format("error|appfirewall:globalstate:{}", why));
    }
    if (const auto why = subprocess_failure_token(pf_info); why.empty()) {
        rows.push_back(std::format("pf|{}", to_string(parse_pf_status(pf_info.output))));
    } else {
        rows.emplace_back("pf|unknown");
        rows.push_back(std::format("error|pf:info:{}", why));
    }
    if (const auto why = subprocess_failure_token(anchors); why.empty()) {
        for (const auto& anchor : parse_pf_anchors(anchors.output))
            rows.push_back(std::format("anchor|{}", sanitize_field(anchor)));
    } else {
        rows.push_back(std::format("error|pf:anchors:{}", why));
    }
    if (const auto why = subprocess_failure_token(rules); why.empty()) {
        rows.push_back(std::format("ruleset|{}", count_pf_rules(rules.output)));
    } else {
        rows.emplace_back("ruleset|unknown");
        rows.push_back(std::format("error|pf:rules:{}", why));
    }
    return rows;
}

/// The `rules` rows of macOS, from `socketfilterfw --listapps`, `pfctl -s rules` and
/// `pfctl -s Anchors`: the app rows, the raw pf rule lines, the anchors, then the rule count.
/// The rule lines and the count share one gate, so a clipped or timed-out read never publishes
/// a partial rule set as the whole.
[[nodiscard]] inline std::vector<std::string>
macos_rules_rows(const yuzu::agent::SubprocessResult& listapps, const yuzu::agent::SubprocessResult& rules,
                 const yuzu::agent::SubprocessResult& anchors) {
    std::vector<std::string> rows;
    if (const auto why = subprocess_failure_token(listapps); why.empty()) {
        for (const auto& app : parse_alf_listapps(listapps.output))
            rows.push_back(
                std::format("app|{}|{}", sanitize_field(app.path), alf_decision_name(app.decision)));
    } else {
        rows.push_back(std::format("error|appfirewall:listapps:{}", why));
    }
    const auto rules_why = subprocess_failure_token(rules);
    if (rules_why.empty()) {
        std::istringstream iss(rules.output);
        std::string line;
        while (std::getline(iss, line))
            if (!line.empty())
                rows.push_back(std::format("rule|{}", sanitize_field(line)));
    }
    if (const auto why = subprocess_failure_token(anchors); why.empty()) {
        for (const auto& anchor : parse_pf_anchors(anchors.output))
            rows.push_back(std::format("anchor|{}", sanitize_field(anchor)));
    } else {
        rows.push_back(std::format("error|pf:anchors:{}", why));
    }
    if (rules_why.empty()) {
        rows.push_back(std::format("ruleset|{}", count_pf_rules(rules.output)));
    } else {
        rows.emplace_back("ruleset|unknown");
        rows.push_back(std::format("error|pf:rules:{}", rules_why));
    }
    return rows;
}

// ── Windows rows (pure: no windows.h, so a macOS or Linux build pins the output) ────────────

/// The row `state` ends with: the true rule count, or the failure that kept it from being read.
/// `have_rules` = get_Rules succeeded and returned a collection; `count_ok` = get_Count returned
/// S_OK (S_FALSE is a failure, as everywhere in this plugin). Which HRESULT is reported is the one
/// of the step that failed.
[[nodiscard]] inline std::string win_rule_count_row(bool have_rules, std::uint32_t rules_hr,
                                                    bool count_ok, std::uint32_t count_hr,
                                                    long long count) {
    if (!have_rules || !count_ok)
        return std::format("error|rules_count:0x{:08x}", have_rules ? count_hr : rules_hr);
    return std::format("ruleset|{}", count);
}

/// One `rule|` row of the Windows `rules` action. The name is echoed, so it is sanitised here.
[[nodiscard]] inline std::string win_rule_row(std::string_view name, bool enabled, std::string_view dir,
                                              std::string_view action, long profiles) {
    return std::format("rule|{}|{}|{}|{}|{}", sanitize_field(name), enabled ? "enabled" : "disabled",
                       dir, action, profiles);
}

/// The rows that close the Windows `rules` action. A failed enumeration step means `count` is a
/// partial tally, so it is reported as `error|enum_next` and `ruleset|unknown`, never as a count;
/// otherwise the count, and `truncated|true` only when a rule past the cap really exists.
[[nodiscard]] inline std::vector<std::string> win_rules_trailer_rows(int count, bool truncated,
                                                                     bool enum_failed,
                                                                     std::uint32_t hr) {
    if (enum_failed)
        return {std::format("error|enum_next:0x{:08x}", hr), "ruleset|unknown"};
    std::vector<std::string> rows{std::format("ruleset|{}", count)};
    if (truncated)
        rows.emplace_back("truncated|true");
    return rows;
}

// ── Linux: the recognised shape of ufw and iptables output (#4402) ──────────────────────────

/// Whether `ufw status numbered` output is the shape this parser understands, so output that
/// drifted reads as "not recognised", not as a firewall with no rules. A Status line that
/// parse_ufw_status recognises is required. `Status: inactive` alone, and `Status: active` with
/// no rules, carry no table (ufw prints no header then) and are in shape. When a dashed header
/// line is present, every non-empty line after it must be a bracketed rule row; without one,
/// only blank lines and the `To ...` column-title line may follow the Status line.
[[nodiscard]] inline bool ufw_shape_ok(std::string_view out) {
    if (parse_ufw_status(out) == FwState::unknown)
        return false;
    std::istringstream iss{std::string(out)};
    std::string line;
    bool first = true;
    bool after_header = false;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (first) {
            first = false; // the Status line itself
            continue;
        }
        std::string_view trimmed(line);
        while (!trimmed.empty() && trimmed.front() == ' ')
            trimmed.remove_prefix(1);
        if (trimmed.empty())
            continue;
        if (after_header) {
            if (trimmed.front() != '[')
                return false;
        } else if (trimmed.starts_with("--")) {
            after_header = true;
        } else if (trimmed.starts_with("To ") || trimmed.starts_with("To\t")) {
            continue; // the column title line above the dashed line
        } else {
            return false;
        }
    }
    return true;
}

/// Whether `iptables -S` output is the shape this parser understands: at least one `-P` policy
/// line, and no line that is none of `-P`, `-N` or `-A`. Blank lines and lines that start with
/// `#` are ignored: a warning or a comment must not make a healthy host unrecognised.
[[nodiscard]] inline bool iptables_shape_ok(const std::vector<IptablesRule>& rules) {
    bool have_policy = false;
    for (const auto& r : rules) {
        if (r.type == IptablesEntryType::policy) {
            have_policy = true;
        } else if (r.type == IptablesEntryType::unknown) {
            std::string_view spec(r.spec);
            while (!spec.empty() && (spec.front() == ' ' || spec.front() == '\t'))
                spec.remove_prefix(1);
            if (!spec.empty() && spec.front() != '#')
                return false;
        }
    }
    return have_policy;
}

/// The row that says a backend's output was complete but not in the shape this plugin knows.
[[nodiscard]] inline std::string unrecognised_output_row(std::string_view backend) {
    return std::format("error|{}:unrecognised_output", backend);
}

} // namespace yuzu::firewall
