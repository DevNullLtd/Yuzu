#pragma once

/**
 * firewall_quarantine_parsers.hpp -- the pure core of the firewall plugin's
 * device-containment actions (`quarantine`, `release`, `quarantine_status`,
 * `quarantine_allow`).
 *
 * WHAT LIVES HERE. Everything that decides something, on every OS, with no OS
 * header: the exception grammar, the allow set, the ruleset/argv text for each
 * OS leg, the verify-after-apply decision, the phased state record, the TTL
 * rules, the resolver parser, and the drivers (apply_and_verify / update /
 * release / recover_at_init / report_status) that sequence them. The OS seam
 * is small and injected: a command Runner, a TcpProbe, a Stage (writes a
 * ruleset file), a StateStore and a Leg (what one OS mechanism can do). A unit
 * test never spawns a process, opens a socket or touches a file; it feeds
 * fixtures through fakes and drives every decision path, including a crash
 * between any two runner calls.
 *
 * THIS FILE IS THE PRIVILEGE BOUNDARY. The sudoers lines that let the agent
 * run nft / iptables / pfctl narrow the argv SHAPE but cannot confine it (sudo
 * globs match concatenated args; `nft -f` and `pfctl -a ... -f` execute
 * agent-generated file content). What actually confines the privileged call is
 * that every token reaching an argv or a ruleset line is built here from a
 * typed, validated value and then re-checked against a strict charset
 * (is_safe_token / is_safe_ruleset_line: no whitespace in a token, no `;`,
 * quote, `$`, backtick, `|`, `&`, `#`, `\` or newline anywhere). Operator text
 * is never interpolated: an address is parsed to bytes and re-formatted, a port
 * is a bounded integer, a protocol and a direction are enums. Do not add a code
 * path that puts a caller-supplied string into an argv or a ruleset.
 *
 * Header-only and windows.h-free so the same file compiles under MSVC, gcc and
 * clang and is unit-tested on every host (test_firewall_quarantine_parsers.cpp).
 */

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <yuzu/agent/server_address_parsers.hpp>

namespace yuzu::firewall::quarantine {

// ── Names and limits ────────────────────────────────────────────────────────

inline constexpr std::string_view kStateKey = "quarantine.state";
inline constexpr std::string_view kWinPriorPolicyKey = "win.prior_firewall_policy";
inline constexpr std::string_view kWinDisabledRulesKey = "win.disabled_rules";

/// Windows Firewall rule group every rule we create carries; removal is by group.
inline constexpr std::string_view kWinGroup = "Yuzu Firewall Quarantine";
/// Our rule-name prefix. Deliberately NOT the legacy plugin's `YuzuQuarantine_`
/// prefix: its netsh_matching_rule_names deletes every rule that starts with it.
inline constexpr std::string_view kWinRulePrefix = "YuzuFirewall_Quarantine_";
inline constexpr std::string_view kLegacyWinRulePrefix = "YuzuQuarantine_";
inline constexpr std::string_view kLegacyIptablesChain = "yuzu-quarantine";

inline constexpr std::string_view kNftTable = "yuzu_quarantine";
inline constexpr std::string_view kIptablesChainPrefix = "yuzu-fwq-";
/// pf evaluates the sub-anchors of Apple's `anchor "com.apple/*"` wildcard in
/// name order and a `quick` pass in an earlier one (200.AirDrop,
/// 250.ApplicationFirewall, ...) wins, so ours leads with `000.` to sort first.
inline constexpr std::string_view kPfAnchorParent = "com.apple";
inline constexpr std::string_view kPfAnchorLeaf = "000.yuzu_quarantine";
inline constexpr std::string_view kPfAnchor = "com.apple/000.yuzu_quarantine";

inline constexpr std::string_view kTtlTriggerId = "firewall.quarantine.ttl";
inline constexpr int kTtlPollSeconds = 30; // the trigger engine's floor

inline constexpr std::size_t kMaxResolvers = 8;
inline constexpr std::size_t kMaxExceptions = 64;
inline constexpr std::size_t kMaxControlIps = 32;
inline constexpr std::size_t kMaxExceptionsParamBytes = 8192;
inline constexpr std::size_t kMaxDisabledRules = 20000;
inline constexpr std::int64_t kMinTtlSeconds = 60;
inline constexpr std::int64_t kMaxTtlSeconds = 2'592'000; // 30 days
inline constexpr std::chrono::milliseconds kOperationBudget{60'000};
inline constexpr std::chrono::milliseconds kCallBudget{5'000};
inline constexpr std::chrono::milliseconds kProbeTimeout{2'000};

// ── Token safety ────────────────────────────────────────────────────────────

[[nodiscard]] constexpr bool is_safe_token_char(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           c == '.' || c == ':' || c == '/' || c == '_' || c == '-';
}

/// An argv token or a substituted ruleset token: 1..128 chars of
/// [0-9A-Za-z.:/_-]. No whitespace, `;`, quote, `$`, backtick, `|`, `&`, `#`,
/// `\` or newline can pass.
[[nodiscard]] constexpr bool is_safe_token(std::string_view s) noexcept {
    if (s.empty() || s.size() > 128)
        return false;
    for (char c : s)
        if (!is_safe_token_char(c))
            return false;
    return true;
}

/// A whole generated ruleset line: the token charset plus the structural
/// characters our own templates use (space, braces, `;` between nft chain
/// properties, `,` inside a set). Still no quote, `$`, backtick, `|`, `&`, `#`,
/// `\`, tab or newline.
[[nodiscard]] constexpr bool is_safe_ruleset_line(std::string_view line) noexcept {
    if (line.size() > 512)
        return false;
    for (char c : line) {
        if (is_safe_token_char(c) || c == ' ' || c == '{' || c == '}' || c == ';' || c == ',')
            continue;
        return false;
    }
    return true;
}

/// Every line of a multi-line ruleset passes is_safe_ruleset_line.
[[nodiscard]] inline bool is_safe_ruleset_text(std::string_view text) noexcept {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        const auto line = text.substr(pos, nl == std::string_view::npos ? nl : nl - pos);
        if (!is_safe_ruleset_line(line))
            return false;
        if (nl == std::string_view::npos)
            break;
        pos = nl + 1;
    }
    return true;
}

[[nodiscard]] inline bool all_tokens_safe(const std::vector<std::string>& argv) noexcept {
    if (argv.empty())
        return false;
    for (const auto& t : argv)
        if (!is_safe_token(t))
            return false;
    return true;
}

namespace detail {

[[nodiscard]] inline std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    for (;;) {
        const auto next = s.find(sep, pos);
        if (next == std::string_view::npos) {
            out.push_back(s.substr(pos));
            return out;
        }
        out.push_back(s.substr(pos, next - pos));
        pos = next + 1;
    }
}

[[nodiscard]] inline std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

/// Decimal digits only, no sign, no leading space; nullopt on overflow of `max`.
[[nodiscard]] inline std::optional<std::int64_t> parse_uint(std::string_view s,
                                                             std::int64_t max) {
    if (s.empty() || s.size() > 18)
        return std::nullopt;
    // from_chars on an unsigned type takes no sign and no leading space; 18
    // digits cannot overflow 64 bits, so the cast below is exact.
    std::uint64_t v = 0;
    const char* const end = s.data() + s.size();
    const auto [ptr, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || ptr != end || static_cast<std::int64_t>(v) > max)
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}

/// A pf reference token: decimal digits only (a full 64-bit value, which does
/// not fit parse_uint's 18-digit bound), between `min` and `max` characters.
[[nodiscard]] inline bool is_digits(std::string_view s, std::size_t min, std::size_t max) noexcept {
    return s.size() >= min && s.size() <= max &&
           s.find_first_not_of("0123456789") == std::string_view::npos;
}

/// Free-text safe for a state value or an output field: control characters,
/// `|` and `=` flattened, bounded.
[[nodiscard]] inline std::string sanitize_text(std::string_view s, std::size_t max = 120) {
    std::string out;
    out.reserve(std::min(s.size(), max));
    for (char c : s) {
        if (out.size() >= max)
            break;
        const auto u = static_cast<unsigned char>(c);
        out += (u < 0x20 || u == 0x7f || c == '|' || c == '=') ? '_' : c;
    }
    return out;
}

} // namespace detail

// ── IP addresses ────────────────────────────────────────────────────────────

struct IpAddr {
    bool v6 = false;
    std::array<std::uint8_t, 16> b{}; // an IPv4 address uses b[0..3]
    friend bool operator==(const IpAddr&, const IpAddr&) = default;
};

[[nodiscard]] inline std::optional<IpAddr> parse_ipv4(std::string_view s) {
    IpAddr a;
    std::size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        const std::size_t start = pos;
        unsigned v = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
            v = v * 10 + static_cast<unsigned>(s[pos] - '0');
            ++pos;
            if (pos - start > 3)
                return std::nullopt;
        }
        if (pos == start || v > 255)
            return std::nullopt;
        if (pos - start > 1 && s[start] == '0')
            return std::nullopt; // no leading zeros: octal ambiguity across tools
        a.b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v);
        if (i < 3) {
            if (pos >= s.size() || s[pos] != '.')
                return std::nullopt;
            ++pos;
        }
    }
    if (pos != s.size())
        return std::nullopt;
    return a;
}

namespace detail {

[[nodiscard]] inline bool parse_v6_groups(std::string_view part, bool allow_v4_tail,
                                          std::vector<std::uint16_t>& out) {
    if (part.empty())
        return true;
    std::size_t pos = 0;
    for (;;) {
        const auto next = part.find(':', pos);
        const bool last = next == std::string_view::npos;
        const auto g = part.substr(pos, last ? std::string_view::npos : next - pos);
        if (g.empty())
            return false;
        if (last && allow_v4_tail && g.find('.') != std::string_view::npos) {
            const auto v4 = parse_ipv4(g);
            if (!v4)
                return false;
            out.push_back(static_cast<std::uint16_t>((v4->b[0] << 8) | v4->b[1]));
            out.push_back(static_cast<std::uint16_t>((v4->b[2] << 8) | v4->b[3]));
        } else {
            if (g.size() > 4)
                return false;
            unsigned v = 0;
            const char* const gend = g.data() + g.size();
            const auto [gp, gec] = std::from_chars(g.data(), gend, v, 16);
            if (gec != std::errc{} || gp != gend)
                return false;
            out.push_back(static_cast<std::uint16_t>(v));
        }
        if (last)
            return true;
        pos = next + 1;
    }
}

} // namespace detail

[[nodiscard]] inline std::optional<IpAddr> parse_ipv6(std::string_view s) {
    if (s.size() < 2 || s.size() > 45)
        return std::nullopt;
    const auto dc = s.find("::");
    std::vector<std::uint16_t> head, tail;
    if (dc != std::string_view::npos) {
        if (s.find("::", dc + 1) != std::string_view::npos)
            return std::nullopt; // ":::" or a second "::"
        if (!detail::parse_v6_groups(s.substr(0, dc), false, head) ||
            !detail::parse_v6_groups(s.substr(dc + 2), true, tail))
            return std::nullopt;
        if (head.size() + tail.size() > 7)
            return std::nullopt;
    } else {
        if (!detail::parse_v6_groups(s, true, head) || head.size() != 8)
            return std::nullopt;
    }
    std::array<std::uint16_t, 8> g{};
    for (std::size_t i = 0; i < head.size(); ++i)
        g[i] = head[i];
    for (std::size_t i = 0; i < tail.size(); ++i)
        g[8 - tail.size() + i] = tail[i];
    IpAddr a;
    a.v6 = true;
    for (std::size_t i = 0; i < 8; ++i) {
        a.b[2 * i] = static_cast<std::uint8_t>(g[i] >> 8);
        a.b[2 * i + 1] = static_cast<std::uint8_t>(g[i] & 0xff);
    }
    return a;
}

/// A bare literal: IPv4 dotted-decimal or IPv6 (no brackets, no zone, no port).
[[nodiscard]] inline std::optional<IpAddr> parse_ip(std::string_view s) {
    return s.find(':') != std::string_view::npos ? parse_ipv6(s) : parse_ipv4(s);
}

[[nodiscard]] inline std::string format_ip(const IpAddr& a) {
    if (!a.v6)
        return std::format("{}.{}.{}.{}", a.b[0], a.b[1], a.b[2], a.b[3]);
    std::array<std::uint16_t, 8> g{};
    for (std::size_t i = 0; i < 8; ++i)
        g[i] = static_cast<std::uint16_t>((a.b[2 * i] << 8) | a.b[2 * i + 1]);
    // RFC 5952: compress the longest run (>= 2) of zero groups, first on a tie.
    int best_start = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[static_cast<std::size_t>(i)] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && g[static_cast<std::size_t>(j)] == 0)
            ++j;
        if (j - i > best_len) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if (best_len < 2)
        best_start = -1;
    std::string out;
    for (int i = 0; i < 8; ++i) {
        if (i == best_start) {
            out += "::";
            i += best_len - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':')
            out += ':';
        out += std::format("{:x}", g[static_cast<std::size_t>(i)]);
    }
    return out;
}

[[nodiscard]] inline bool is_loopback(const IpAddr& a) noexcept {
    if (!a.v6)
        return a.b[0] == 127;
    for (std::size_t i = 0; i < 15; ++i)
        if (a.b[i] != 0)
            return false;
    return a.b[15] == 1;
}

/// Zero the host bits so `10.0.0.1/8` and `10.0.0.0/8` are one entry.
[[nodiscard]] inline IpAddr mask_to_prefix(IpAddr a, int prefix) noexcept {
    const int bits = a.v6 ? 128 : 32;
    if (prefix < 0 || prefix >= bits)
        return a;
    for (int i = 0; i < bits / 8; ++i) {
        const int lo = i * 8;
        auto& byte = a.b[static_cast<std::size_t>(i)];
        if (prefix <= lo)
            byte = 0;
        else if (prefix < lo + 8)
            byte = static_cast<std::uint8_t>(byte & (0xff << (8 - (prefix - lo))));
    }
    return a;
}

// ── Exception grammar ───────────────────────────────────────────────────────

enum class Proto : std::uint8_t { tcp, udp, both };
enum class Dir : std::uint8_t { in, out };

/// One operator exception, or one control-channel / resolver entry. `port` is
/// the SERVICE port: the remote port for an outbound entry, the local port for
/// an inbound one. 0 means any port.
struct Endpoint {
    IpAddr ip;
    int prefix = -1; // -1: a single host; otherwise the CIDR length
    int port = 0;
    Proto proto = Proto::both;
    Dir dir = Dir::out;
    friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

[[nodiscard]] inline std::string addr_text(const Endpoint& e) {
    auto s = format_ip(e.ip);
    if (e.prefix >= 0)
        s += std::format("/{}", e.prefix);
    return s;
}

/// The round-trip form parse_exception accepts: always explicit direction,
/// protocol only when it is not the default, v6 always bracketed.
[[nodiscard]] inline std::string canonical(const Endpoint& e) {
    std::string s;
    if (e.ip.v6)
        s = "[" + format_ip(e.ip) + "]";
    else
        s = format_ip(e.ip);
    if (e.prefix >= 0)
        s += std::format("/{}", e.prefix);
    if (e.port > 0)
        s += std::format(":{}", e.port);
    if (e.proto == Proto::tcp)
        s += "/tcp";
    else if (e.proto == Proto::udp)
        s += "/udp";
    s += e.dir == Dir::in ? "/in" : "/out";
    return s;
}

/// `addr[/prefix][:port][/tcp|udp][/in|out]`. A v6 address with a port must be
/// bracketed (`[2001:db8::1]:22/tcp/in`); a numeric segment after the address
/// is the prefix and may carry the port (`10.0.0.0/8:443`); an alphabetic
/// segment is a protocol or a direction. Defaults: both protocols, outbound,
/// any port. Host bits under a prefix are zeroed.
[[nodiscard]] inline std::expected<Endpoint, std::string> parse_exception(std::string_view text) {
    using unex = std::unexpected<std::string>;
    if (text.empty())
        return unex("empty");
    if (text.size() > 96)
        return unex("too_long");
    for (char c : text)
        if (!is_safe_token_char(c) && c != '[' && c != ']')
            return unex("unsafe_token");

    const auto seg = detail::split(text, '/');
    Endpoint e;
    bool have_port = false, have_proto = false, have_dir = false, have_prefix = false;
    std::optional<std::string_view> port_text;

    const auto s0 = seg[0];
    std::string_view addr_part;
    bool bracketed = false;
    if (!s0.empty() && s0.front() == '[') {
        const auto close = s0.find(']');
        if (close == std::string_view::npos)
            return unex("bad_addr");
        addr_part = s0.substr(1, close - 1);
        const auto rest = s0.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':')
                return unex("bad_addr");
            port_text = rest.substr(1);
        }
        bracketed = true;
    } else {
        const auto colons = static_cast<std::size_t>(std::count(s0.begin(), s0.end(), ':'));
        if (colons >= 2) {
            addr_part = s0; // unbracketed v6: no port
        } else if (colons == 1) {
            const auto c = s0.find(':');
            addr_part = s0.substr(0, c);
            port_text = s0.substr(c + 1);
        } else {
            addr_part = s0;
        }
    }
    const auto ip = bracketed ? parse_ipv6(addr_part) : parse_ip(addr_part);
    if (!ip)
        return unex("bad_addr");
    e.ip = *ip;

    auto take_port = [&](std::string_view p) -> std::optional<std::string> {
        if (have_port)
            return "duplicate_port";
        const auto v = detail::parse_uint(p, 65535);
        if (!v || *v < 1)
            return "bad_port";
        e.port = static_cast<int>(*v);
        have_port = true;
        return std::nullopt;
    };
    if (port_text)
        if (auto err = take_port(*port_text))
            return unex(*err);

    for (std::size_t i = 1; i < seg.size(); ++i) {
        const auto s = seg[i];
        if (s.empty())
            return unex("bad_field");
        if (s.front() >= '0' && s.front() <= '9') {
            if (i != 1 || have_prefix)
                return unex("bad_prefix");
            std::string_view prefix_text = s;
            if (const auto c = s.find(':'); c != std::string_view::npos) {
                prefix_text = s.substr(0, c);
                if (auto err = take_port(s.substr(c + 1)))
                    return unex(*err);
            }
            const auto p = detail::parse_uint(prefix_text, e.ip.v6 ? 128 : 32);
            if (!p)
                return unex("bad_prefix");
            e.prefix = static_cast<int>(*p);
            have_prefix = true;
        } else if (s == "tcp" || s == "udp") {
            if (have_proto)
                return unex("duplicate_proto");
            e.proto = s == "tcp" ? Proto::tcp : Proto::udp;
            have_proto = true;
        } else if (s == "in" || s == "out") {
            if (have_dir)
                return unex("duplicate_dir");
            e.dir = s == "in" ? Dir::in : Dir::out;
            have_dir = true;
        } else {
            return unex("bad_field");
        }
    }
    if (e.prefix >= 0)
        e.ip = mask_to_prefix(e.ip, e.prefix);
    return e;
}

/// A comma-separated exception list (the `exceptions` action parameter).
[[nodiscard]] inline std::expected<std::vector<Endpoint>, std::string>
parse_exceptions_csv(std::string_view csv) {
    std::vector<Endpoint> out;
    if (csv.empty())
        return out;
    if (csv.size() > kMaxExceptionsParamBytes)
        return std::unexpected("exceptions_too_long");
    for (const auto item : detail::split(csv, ',')) {
        if (item.empty())
            return std::unexpected("empty_entry");
        auto e = parse_exception(item);
        if (!e)
            return std::unexpected(e.error());
        if (std::find(out.begin(), out.end(), *e) == out.end())
            out.push_back(*e);
        if (out.size() > kMaxExceptions)
            return std::unexpected("too_many_exceptions");
    }
    return out;
}

// ── Allow set ───────────────────────────────────────────────────────────────

struct AllowSet {
    std::vector<Endpoint> control; // tcp, out, port = the control-channel port
    std::vector<IpAddr> resolvers; // DNS (53) outbound
    std::vector<Endpoint> exceptions; // operator exceptions, cumulative
    std::vector<std::string> notes; // build diagnostics; never serialized or compared

    friend bool operator==(const AllowSet& a, const AllowSet& b) {
        return a.control == b.control && a.resolvers == b.resolvers &&
               a.exceptions == b.exceptions;
    }
};

/// Add operator exceptions; the cap is cumulative across every add.
[[nodiscard]] inline std::expected<AllowSet, std::string>
add_exceptions(AllowSet set, const std::vector<Endpoint>& add) {
    for (const auto& e : add)
        if (std::find(set.exceptions.begin(), set.exceptions.end(), e) == set.exceptions.end())
            set.exceptions.push_back(e);
    if (set.exceptions.size() > kMaxExceptions)
        return std::unexpected("exception_cap_exceeded");
    return set;
}

/// The port of a `host:port` / `[v6]:port` control target; nullopt when absent
/// or malformed. (A bracket-less v6 literal carries no unambiguous port.)
[[nodiscard]] inline std::optional<int> extract_server_port(std::string_view target) {
    std::string_view port_text;
    if (target.empty())
        return std::nullopt;
    if (target.front() == '[') {
        const auto close = target.find(']');
        if (close == std::string_view::npos || close + 1 >= target.size() ||
            target[close + 1] != ':')
            return std::nullopt;
        port_text = target.substr(close + 2);
    } else {
        const auto last = target.rfind(':');
        if (last == std::string_view::npos)
            return std::nullopt;
        if (target.substr(0, last).find(':') != std::string_view::npos)
            return std::nullopt;
        port_text = target.substr(last + 1);
    }
    const auto v = detail::parse_uint(port_text, 65535);
    if (!v || *v < 1)
        return std::nullopt;
    return static_cast<int>(*v);
}

/// loopback + control endpoints + DHCP + DNS resolvers + ICMPv6 ND are the
/// mandatory part (emitted by flatten()); this builds the variable part.
/// `control_ips_csv` is the agent's startup-resolved `agent.server_address_
/// resolved`; a literal host in `server_address` is added when the resolved list
/// does not already carry it. An empty control set is refused: an allow set that
/// cannot reach the server would strand the host.
[[nodiscard]] inline std::expected<AllowSet, std::string>
build_allow_set(std::string_view control_ips_csv, std::string_view server_address,
                const std::vector<std::string>& resolver_literals,
                const std::vector<Endpoint>& exceptions) {
    AllowSet set;
    const auto port = extract_server_port(server_address);
    if (!port)
        return std::unexpected("control_port_missing");

    int invalid = 0;
    auto add_control = [&](const IpAddr& ip) {
        Endpoint e;
        e.ip = ip;
        e.port = *port;
        e.proto = Proto::tcp;
        e.dir = Dir::out;
        if (std::find(set.control.begin(), set.control.end(), e) == set.control.end())
            set.control.push_back(e);
    };
    for (const auto item : detail::split(control_ips_csv, ',')) {
        const auto t = detail::trim(item);
        if (t.empty())
            continue;
        if (const auto ip = parse_ip(t))
            add_control(*ip);
        else
            ++invalid;
    }
    if (const auto host = yuzu::agent::extract_server_host(server_address); !host.empty())
        if (const auto ip = parse_ip(host))
            add_control(*ip);
    if (invalid > 0)
        set.notes.push_back(std::format("control_ips_invalid={}", invalid));
    if (set.control.empty())
        return std::unexpected("control_set_empty");
    if (set.control.size() > kMaxControlIps)
        return std::unexpected("control_set_too_large");

    int resolver_invalid = 0;
    int resolver_dropped = 0;
    for (const auto& lit : resolver_literals) {
        const auto ip = parse_ip(detail::trim(lit));
        if (!ip) {
            ++resolver_invalid;
            continue;
        }
        if (std::find(set.resolvers.begin(), set.resolvers.end(), *ip) != set.resolvers.end())
            continue;
        if (set.resolvers.size() >= kMaxResolvers) {
            ++resolver_dropped;
            continue;
        }
        set.resolvers.push_back(*ip);
    }
    if (resolver_dropped > 0)
        set.notes.push_back(std::format("resolvers_dropped={}", resolver_dropped));
    if (resolver_invalid > 0)
        set.notes.push_back(std::format("resolvers_invalid={}", resolver_invalid));

    return add_exceptions(std::move(set), exceptions);
}

/// True when `e` names an allowance the quarantine cannot work without:
/// loopback, a control-channel endpoint, a DNS resolver on 53, or DHCP
/// (udp 67/68). ICMPv6 neighbour discovery is also mandatory but cannot be
/// named by the grammar (it has no ICMP form), so it needs no entry here.
[[nodiscard]] inline bool is_mandatory(const AllowSet& set, const Endpoint& e) {
    if (is_loopback(e.ip))
        return true;
    if (e.proto == Proto::udp && (e.port == 67 || e.port == 68))
        return true;
    for (const auto& c : set.control)
        if (e.dir == Dir::out && e.proto != Proto::udp && e.ip == c.ip && e.prefix < 0 &&
            e.port == c.port)
            return true;
    for (const auto& r : set.resolvers)
        if (e.dir == Dir::out && e.ip == r && e.prefix < 0 && e.port == 53)
            return true;
    return false;
}

struct RemoveResult {
    AllowSet set;
    int removed = 0;
};

/// Remove operator exceptions. A mandatory allowance is refused, never removed;
/// an entry that is not present is a no-op (counted by `removed`).
[[nodiscard]] inline std::expected<RemoveResult, std::string>
remove_exceptions(AllowSet set, const std::vector<Endpoint>& remove) {
    RemoveResult r;
    for (const auto& e : remove) {
        if (is_mandatory(set, e))
            return std::unexpected("mandatory_allowance");
        const auto it = std::find(set.exceptions.begin(), set.exceptions.end(), e);
        if (it != set.exceptions.end()) {
            set.exceptions.erase(it);
            ++r.removed;
        }
    }
    r.set = std::move(set);
    return r;
}

// ── The flattened rule list every OS leg renders ────────────────────────────

enum class RuleKind : std::uint8_t { loopback, control, dhcp, dns, nd, exception };

/// One allowance in OS-neutral form. `dir` is the direction of the REQUEST (we
/// initiate for `out`, the peer initiates for `in`); `svc_port` is the service
/// port (remote for out, local for in); `local_port` pins the other end (DHCP's
/// client port). Each leg adds the stateless reply path itself where its
/// firewall is not stateful.
struct FlatRule {
    RuleKind kind{};
    Dir dir = Dir::out;
    Proto l4 = Proto::tcp; // tcp or udp only, never `both`
    bool v6 = false;
    bool any_addr = false;
    IpAddr ip;
    int prefix = -1;
    int svc_port = 0;
    int local_port = 0;
};

[[nodiscard]] inline std::vector<FlatRule> flatten(const AllowSet& set) {
    std::vector<FlatRule> out;
    {
        FlatRule r;
        r.kind = RuleKind::loopback;
        out.push_back(r);
    }
    for (const auto& c : set.control) {
        FlatRule r;
        r.kind = RuleKind::control;
        r.dir = Dir::out;
        r.l4 = Proto::tcp;
        r.v6 = c.ip.v6;
        r.ip = c.ip;
        r.svc_port = c.port;
        out.push_back(r);
    }
    {
        FlatRule r;
        r.kind = RuleKind::dhcp;
        r.dir = Dir::out;
        r.l4 = Proto::udp;
        r.any_addr = true;
        r.svc_port = 67;
        r.local_port = 68;
        out.push_back(r);
    }
    for (const auto& ip : set.resolvers) {
        for (const auto l4 : {Proto::udp, Proto::tcp}) {
            FlatRule r;
            r.kind = RuleKind::dns;
            r.dir = Dir::out;
            r.l4 = l4;
            r.v6 = ip.v6;
            r.ip = ip;
            r.svc_port = 53;
            out.push_back(r);
        }
    }
    {
        FlatRule r;
        r.kind = RuleKind::nd;
        r.v6 = true;
        r.any_addr = true;
        out.push_back(r);
    }
    for (const auto& e : set.exceptions) {
        const std::array<Proto, 2> both{Proto::tcp, Proto::udp};
        for (const auto l4 : both) {
            if (e.proto != Proto::both && e.proto != l4)
                continue;
            FlatRule r;
            r.kind = RuleKind::exception;
            r.dir = e.dir;
            r.l4 = l4;
            r.v6 = e.ip.v6;
            r.ip = e.ip;
            r.prefix = e.prefix;
            r.svc_port = e.port;
            out.push_back(r);
        }
    }
    return out;
}

[[nodiscard]] inline std::string_view l4_name(Proto p) noexcept {
    return p == Proto::udp ? "udp" : "tcp";
}

[[nodiscard]] inline std::string rule_addr_text(const FlatRule& r) {
    auto s = format_ip(r.ip);
    if (r.prefix >= 0)
        s += std::format("/{}", r.prefix);
    return s;
}

// ── Verify-after-apply ──────────────────────────────────────────────────────

/// A TCP connect ends one of three ways. `refused` (an RST) is positive proof
/// the packet reached the host, so for the "is the block working" question it
/// reads like `connected`, never like `timeout`.
enum class ProbeOutcome : std::uint8_t { connected, refused, timeout };

enum class VerifyOutcome : std::uint8_t {
    verified,
    unproven,
    control_unreachable,
    probe_still_reachable,
    probe_unreachable_before_apply,
};

enum class VerifyMode : std::uint8_t { initial, update, reapply };
enum class VerifyAction : std::uint8_t { keep, rollback_to_absence, revert_to_previous, refuse };

[[nodiscard]] constexpr std::string_view to_string(ProbeOutcome o) noexcept {
    switch (o) {
    case ProbeOutcome::connected:
        return "connected";
    case ProbeOutcome::refused:
        return "refused";
    case ProbeOutcome::timeout:
        return "timeout";
    }
    return "timeout";
}

[[nodiscard]] constexpr std::string_view to_string(VerifyOutcome o) noexcept {
    switch (o) {
    case VerifyOutcome::verified:
        return "verified";
    case VerifyOutcome::unproven:
        return "unproven";
    case VerifyOutcome::control_unreachable:
        return "control_unreachable";
    case VerifyOutcome::probe_still_reachable:
        return "probe_still_reachable";
    case VerifyOutcome::probe_unreachable_before_apply:
        return "probe_unreachable_before_apply";
    }
    return "unproven";
}

/// `before` / `after` are the server-supplied probe target's outcome before the
/// mutation and after it; both nullopt when no target was configured.
[[nodiscard]] constexpr VerifyOutcome decide_verify(bool control_ok,
                                                    std::optional<ProbeOutcome> before,
                                                    std::optional<ProbeOutcome> after) noexcept {
    if (!control_ok)
        return VerifyOutcome::control_unreachable;
    if (!before || !after)
        return VerifyOutcome::unproven;
    if (*before == ProbeOutcome::timeout)
        return VerifyOutcome::probe_unreachable_before_apply;
    return *after == ProbeOutcome::timeout ? VerifyOutcome::verified
                                           : VerifyOutcome::probe_still_reachable;
}

/// What to do about a verify result, by operation. Rollback-to-absence exists
/// only for an INITIAL apply; an update reverts to the previous generation,
/// never to absence; a boot-time re-apply NEVER undoes
/// anything on an unreachable server (never auto-release on lost contact).
[[nodiscard]] constexpr VerifyAction verify_action(VerifyOutcome o, VerifyMode mode) noexcept {
    switch (o) {
    case VerifyOutcome::verified:
    case VerifyOutcome::unproven:
        return VerifyAction::keep;
    case VerifyOutcome::probe_unreachable_before_apply:
        return mode == VerifyMode::initial ? VerifyAction::refuse : VerifyAction::keep;
    case VerifyOutcome::control_unreachable:
    case VerifyOutcome::probe_still_reachable:
        if (mode == VerifyMode::initial)
            return VerifyAction::rollback_to_absence;
        return mode == VerifyMode::update ? VerifyAction::revert_to_previous
                                          : VerifyAction::keep;
    }
    return VerifyAction::keep;
}

/// `verify|control=<ok|fail>|probe=<blocked|reachable|refused|unproven>`.
[[nodiscard]] constexpr std::string_view probe_word(std::optional<ProbeOutcome> before,
                                                    std::optional<ProbeOutcome> after) noexcept {
    if (before && after && *before != ProbeOutcome::timeout)
        return *after == ProbeOutcome::timeout     ? "blocked"
               : *after == ProbeOutcome::connected ? "reachable"
                                                   : "refused";
    return "unproven";
}

[[nodiscard]] inline std::string verify_row(bool control_ok, std::optional<ProbeOutcome> before,
                                            std::optional<ProbeOutcome> after) {
    return std::format("verify|control={}|probe={}", control_ok ? "ok" : "fail",
                       probe_word(before, after));
}

// ── Probe target ────────────────────────────────────────────────────────────

struct ProbeTarget {
    IpAddr ip;
    int port = 0;
    [[nodiscard]] std::string text() const {
        return ip.v6 ? std::format("[{}]:{}", format_ip(ip), port)
                     : std::format("{}:{}", format_ip(ip), port);
    }
};

/// `ip:port` or `[v6]:port`, an IP LITERAL only: a hostname would be resolved
/// by the host being contained (the #3429 trust problem). Loopback is refused
/// because a loopback target is never blocked, so it could never verify.
[[nodiscard]] inline std::expected<ProbeTarget, std::string>
parse_probe_target(std::string_view text) {
    if (text.empty() || text.size() > 64)
        return std::unexpected("probe_target_not_literal");
    const auto port = extract_server_port(text);
    if (!port)
        return std::unexpected("probe_target_bad_port");
    const auto host = yuzu::agent::extract_server_host(text);
    const auto ip = parse_ip(host);
    if (!ip)
        return std::unexpected("probe_target_not_literal");
    if (is_loopback(*ip))
        return std::unexpected("probe_target_loopback");
    return ProbeTarget{*ip, *port};
}

// ── TTL ─────────────────────────────────────────────────────────────────────

[[nodiscard]] constexpr bool validate_ttl(std::int64_t seconds) noexcept {
    return seconds >= kMinTtlSeconds && seconds <= kMaxTtlSeconds;
}

/// The `ttl_seconds` parameter: empty means off (0); otherwise digits within
/// [kMinTtlSeconds, kMaxTtlSeconds].
[[nodiscard]] inline std::expected<std::int64_t, std::string> parse_ttl_param(std::string_view s) {
    if (s.empty())
        return std::int64_t{0};
    const auto v = detail::parse_uint(s, kMaxTtlSeconds + 1);
    if (!v || !validate_ttl(*v))
        return std::unexpected("ttl_out_of_bounds");
    return *v;
}

// ── State record ────────────────────────────────────────────────────────────

enum class Phase : std::uint8_t { applying, active, releasing };
enum class BackendKind : std::uint8_t { none, nft, iptables, windows, pf };

[[nodiscard]] constexpr std::string_view to_string(Phase p) noexcept {
    switch (p) {
    case Phase::applying:
        return "applying";
    case Phase::active:
        return "active";
    case Phase::releasing:
        return "releasing";
    }
    return "applying";
}

[[nodiscard]] constexpr std::string_view to_string(BackendKind b) noexcept {
    switch (b) {
    case BackendKind::none:
        return "none";
    case BackendKind::nft:
        return "nft";
    case BackendKind::iptables:
        return "iptables";
    case BackendKind::windows:
        return "windows";
    case BackendKind::pf:
        return "pf";
    }
    return "none";
}

/// OS-specific facts the record carries between calls.
struct OsPayload {
    std::string pf_token;        // macOS: the `pfctl -E` reference token
    std::string boot_time;       // macOS: kern.boottime the token belongs to
    std::uint32_t ipt_gen = 0;   // iptables: the live chain generation
    bool ipt_v6 = false;         // iptables: ip6tables was part of the apply (an IPv6 stack existed)
    std::uint32_t rules_not_disabled = 0; // Windows: enabled rules the policy store refused to disable
    friend bool operator==(const OsPayload&, const OsPayload&) = default;
};

struct QuarantineState {
    int version = 1;
    Phase phase = Phase::applying;
    std::uint32_t generation = 0;      // logical generation, +1 per committed update
    std::uint32_t prev_generation = 0; // the live generation an `applying` update replaces
    std::int64_t applied_at = 0;
    std::int64_t ttl_expires = 0;      // epoch seconds; 0 = no TTL
    std::string probe_target;          // canonical ProbeTarget text, or empty
    BackendKind backend = BackendKind::none;
    AllowSet allow;
    OsPayload os;
    std::string last_verify;           // free text, sanitized
};

inline constexpr std::size_t kMaxStateBytes = 256 * 1024;

[[nodiscard]] inline std::string serialize_state(const QuarantineState& s) {
    std::string out;
    out += std::format("v={}\n", s.version);
    out += std::format("phase={}\n", to_string(s.phase));
    out += std::format("gen={}\n", s.generation);
    out += std::format("prev_gen={}\n", s.prev_generation);
    out += std::format("applied_at={}\n", s.applied_at);
    out += std::format("ttl_expires={}\n", s.ttl_expires);
    out += std::format("backend={}\n", to_string(s.backend));
    if (!s.probe_target.empty())
        out += std::format("probe={}\n", s.probe_target);
    if (!s.os.pf_token.empty())
        out += std::format("pf_token={}\n", s.os.pf_token);
    if (!s.os.boot_time.empty())
        out += std::format("boot_time={}\n", s.os.boot_time);
    if (s.os.ipt_gen != 0)
        out += std::format("ipt_gen={}\n", s.os.ipt_gen);
    if (s.os.ipt_v6)
        out += "ipt_v6=1\n";
    if (s.os.rules_not_disabled != 0)
        out += std::format("not_disabled={}\n", s.os.rules_not_disabled);
    if (!s.last_verify.empty())
        out += std::format("verify={}\n", detail::sanitize_text(s.last_verify));
    for (const auto& c : s.allow.control)
        out += std::format("ctl={}\n", canonical(c));
    for (const auto& r : s.allow.resolvers)
        out += std::format("res={}\n", format_ip(r));
    for (const auto& e : s.allow.exceptions)
        out += std::format("exc={}\n", canonical(e));
    return out;
}

/// Strict: an unknown key, a duplicate scalar, a bad number or a version other
/// than 1 is "malformed" (nullopt) -- reported as `degraded|state_unreadable`,
/// never silently dropped.
[[nodiscard]] inline std::optional<QuarantineState> parse_state(std::string_view text) {
    if (text.empty() || text.size() > kMaxStateBytes)
        return std::nullopt;
    QuarantineState s;
    bool seen_v = false, seen_phase = false, seen_gen = false, seen_backend = false;
    bool seen_prev = false, seen_applied = false, seen_ttl = false;
    bool seen_probe = false, seen_pf = false, seen_boot = false, seen_ipt = false,
         seen_verify = false, seen_nd = false, seen_v6 = false;
    for (const auto line : detail::split(text, '\n')) {
        if (line.empty())
            continue;
        const auto eq = line.find('=');
        if (eq == std::string_view::npos)
            return std::nullopt;
        const auto key = line.substr(0, eq);
        const auto val = line.substr(eq + 1);
        auto once = [&](bool& seen) {
            if (seen)
                return false;
            seen = true;
            return true;
        };
        if (key == "v") {
            if (!once(seen_v) || val != "1")
                return std::nullopt;
        } else if (key == "phase") {
            if (!once(seen_phase))
                return std::nullopt;
            if (val == "applying")
                s.phase = Phase::applying;
            else if (val == "active")
                s.phase = Phase::active;
            else if (val == "releasing")
                s.phase = Phase::releasing;
            else
                return std::nullopt;
        } else if (key == "gen" || key == "prev_gen" || key == "ipt_gen" ||
                   key == "not_disabled") {
            const auto v = detail::parse_uint(val, 0x7fffffff);
            if (!v)
                return std::nullopt;
            if (key == "gen") {
                if (!once(seen_gen))
                    return std::nullopt;
                s.generation = static_cast<std::uint32_t>(*v);
            } else if (key == "prev_gen") {
                if (!once(seen_prev))
                    return std::nullopt;
                s.prev_generation = static_cast<std::uint32_t>(*v);
            } else if (key == "ipt_gen") {
                if (!once(seen_ipt))
                    return std::nullopt;
                s.os.ipt_gen = static_cast<std::uint32_t>(*v);
            } else {
                if (!once(seen_nd))
                    return std::nullopt;
                s.os.rules_not_disabled = static_cast<std::uint32_t>(*v);
            }
        } else if (key == "applied_at" || key == "ttl_expires") {
            const auto v = detail::parse_uint(val, std::int64_t{1} << 50);
            if (!v)
                return std::nullopt;
            if (key == "applied_at") {
                if (!once(seen_applied))
                    return std::nullopt;
                s.applied_at = *v;
            } else {
                if (!once(seen_ttl))
                    return std::nullopt;
                s.ttl_expires = *v;
            }
        } else if (key == "backend") {
            if (!once(seen_backend))
                return std::nullopt;
            if (val == "nft")
                s.backend = BackendKind::nft;
            else if (val == "iptables")
                s.backend = BackendKind::iptables;
            else if (val == "windows")
                s.backend = BackendKind::windows;
            else if (val == "pf")
                s.backend = BackendKind::pf;
            else
                return std::nullopt;
        } else if (key == "probe") {
            if (!once(seen_probe) || !parse_probe_target(val))
                return std::nullopt;
            s.probe_target = std::string{val};
        } else if (key == "pf_token") {
            if (!once(seen_pf) || !detail::is_digits(val, 1, 24))
                return std::nullopt;
            s.os.pf_token = std::string{val};
        } else if (key == "ipt_v6") {
            if (!once(seen_v6) || val != "1")
                return std::nullopt;
            s.os.ipt_v6 = true;
        } else if (key == "boot_time") {
            if (!once(seen_boot) || !is_safe_token(val))
                return std::nullopt;
            s.os.boot_time = std::string{val};
        } else if (key == "verify") {
            if (!once(seen_verify))
                return std::nullopt;
            s.last_verify = std::string{val};
        } else if (key == "ctl") {
            const auto e = parse_exception(val);
            if (!e || e->port == 0 || e->dir != Dir::out)
                return std::nullopt;
            s.allow.control.push_back(*e);
        } else if (key == "res") {
            const auto ip = parse_ip(val);
            if (!ip)
                return std::nullopt;
            s.allow.resolvers.push_back(*ip);
        } else if (key == "exc") {
            const auto e = parse_exception(val);
            if (!e)
                return std::nullopt;
            s.allow.exceptions.push_back(*e);
        } else {
            return std::nullopt;
        }
    }
    if (!seen_v || !seen_phase || !seen_gen || !seen_backend || s.generation == 0 ||
        s.allow.control.empty() || s.allow.control.size() > kMaxControlIps ||
        s.allow.resolvers.size() > kMaxResolvers || s.allow.exceptions.size() > kMaxExceptions)
        return std::nullopt;
    (void)seen_prev;
    (void)seen_applied;
    (void)seen_ttl;
    return s;
}

[[nodiscard]] constexpr bool ttl_expired(const QuarantineState& s, std::int64_t now_epoch) noexcept {
    return s.ttl_expires > 0 && now_epoch >= s.ttl_expires;
}

// ── Windows: rule specs, policy image, disable list ─────────────────────────

/// One INetFwRule to create. `protocol` follows the Windows values (6 tcp,
/// 17 udp, 58 icmpv6). Ports are Windows port strings ("22") or empty for any;
/// an inbound exception sets LocalPorts, an outbound one RemotePorts.
struct WinRuleSpec {
    std::string name;
    Dir dir = Dir::out;
    int protocol = 6;
    std::string remote_addrs; // empty: any
    std::string local_ports;
    std::string remote_ports;
    std::string icmp_types;   // e.g. "133:*,134:*"; empty otherwise
    friend bool operator==(const WinRuleSpec&, const WinRuleSpec&) = default;
};

[[nodiscard]] inline std::string win_rule_name(std::uint32_t generation, std::size_t index) {
    return std::format("{}{}_{}", kWinRulePrefix, generation, index);
}

/// The Windows firewall is stateful, so one rule per allowance covers the reply
/// path. Loopback needs no rule (Windows does not filter it). The names carry
/// the generation so an update adds a new generation's rules before the stale
/// ones are removed, and a repeated apply of the same generation is a no-op.
[[nodiscard]] inline std::vector<WinRuleSpec> win_rule_specs(const AllowSet& set,
                                                             std::uint32_t generation) {
    std::vector<WinRuleSpec> out;
    std::size_t idx = 0;
    auto add = [&](WinRuleSpec s) {
        s.name = win_rule_name(generation, ++idx);
        out.push_back(std::move(s));
    };
    for (const auto& r : flatten(set)) {
        switch (r.kind) {
        case RuleKind::loopback:
            break;
        case RuleKind::nd: {
            for (const auto d : {Dir::out, Dir::in}) {
                WinRuleSpec s;
                s.dir = d;
                s.protocol = 58;
                s.icmp_types = "133:*,134:*,135:*,136:*";
                add(std::move(s));
            }
            break;
        }
        case RuleKind::dhcp: {
            for (const auto d : {Dir::out, Dir::in}) {
                WinRuleSpec s;
                s.dir = d;
                s.protocol = 17;
                s.local_ports = "68";
                s.remote_ports = "67";
                add(std::move(s));
            }
            break;
        }
        case RuleKind::control:
        case RuleKind::dns:
        case RuleKind::exception: {
            WinRuleSpec s;
            s.dir = r.dir;
            s.protocol = r.l4 == Proto::udp ? 17 : 6;
            s.remote_addrs = rule_addr_text(r);
            if (r.svc_port > 0)
                (r.dir == Dir::out ? s.remote_ports : s.local_ports) = std::to_string(r.svc_port);
            add(std::move(s));
            break;
        }
        }
    }
    return out;
}

[[nodiscard]] inline bool is_legacy_marker(std::string_view rule_name) noexcept {
    return rule_name.starts_with(kLegacyWinRulePrefix);
}

/// A rule is ours when it is in our group or carries our name prefix; the one
/// test the disable list, the removal sweep and status all share.
[[nodiscard]] constexpr bool is_our_win_rule(std::string_view name,
                                             std::string_view group) noexcept {
    return group == kWinGroup || name.starts_with(kWinRulePrefix);
}

struct WinRuleInfo {
    std::string name;
    std::string group;
    bool enabled = false;
};

/// Every ENABLED rule outside our group (an Allow RULE beats a profile-default
/// block, so leaving them enabled would leave the host reachable). Ours are
/// never listed, whatever their group string says.
[[nodiscard]] inline std::vector<std::string>
win_rules_to_disable(const std::vector<WinRuleInfo>& rules) {
    std::vector<std::string> out;
    for (const auto& r : rules) {
        if (!r.enabled || is_our_win_rule(r.name, r.group))
            continue;
        out.push_back(r.name);
    }
    return out;
}

enum class WinAction : std::uint8_t { unknown, allow, block };
struct WinProfilePolicy {
    WinAction in = WinAction::unknown;
    WinAction out = WinAction::unknown;
    friend bool operator==(const WinProfilePolicy&, const WinProfilePolicy&) = default;
};
using WinPriorPolicy = std::array<WinProfilePolicy, 3>; // Domain, Private, Public

inline constexpr std::array<std::string_view, 3> kWinProfileNames{"domain", "private", "public"};

[[nodiscard]] constexpr std::string_view to_string(WinAction a) noexcept {
    return a == WinAction::allow ? "allow" : a == WinAction::block ? "block" : "unknown";
}

[[nodiscard]] constexpr bool is_complete_prior_policy(const WinPriorPolicy& p) noexcept {
    for (const auto& x : p)
        if (x.in == WinAction::unknown || x.out == WinAction::unknown)
            return false;
    return true;
}

[[nodiscard]] constexpr bool is_quarantine_shaped(const WinPriorPolicy& p) noexcept {
    for (const auto& x : p)
        if (x.in != WinAction::block || x.out != WinAction::block)
            return false;
    return true;
}

[[nodiscard]] inline std::string serialize_prior_policy(const WinPriorPolicy& p) {
    std::string out = "v=1\n";
    for (std::size_t i = 0; i < 3; ++i) {
        out += std::format("{}.in={}\n", kWinProfileNames[i], to_string(p[i].in));
        out += std::format("{}.out={}\n", kWinProfileNames[i], to_string(p[i].out));
    }
    return out;
}

/// nullopt unless all six values are present and valid: an incomplete image is
/// never replayed (a guess at the missing half could weaken the host).
[[nodiscard]] inline std::optional<WinPriorPolicy> parse_prior_policy(std::string_view text) {
    WinPriorPolicy p{};
    bool seen_v = false;
    std::array<bool, 6> seen{};
    for (const auto line : detail::split(text, '\n')) {
        if (line.empty())
            continue;
        const auto eq = line.find('=');
        if (eq == std::string_view::npos)
            return std::nullopt;
        const auto key = line.substr(0, eq);
        const auto val = line.substr(eq + 1);
        if (key == "v") {
            if (seen_v || val != "1")
                return std::nullopt;
            seen_v = true;
            continue;
        }
        WinAction a;
        if (val == "allow")
            a = WinAction::allow;
        else if (val == "block")
            a = WinAction::block;
        else
            return std::nullopt;
        bool matched = false;
        for (std::size_t i = 0; i < 3 && !matched; ++i) {
            for (int d = 0; d < 2 && !matched; ++d) {
                const auto want = std::format("{}.{}", kWinProfileNames[i], d == 0 ? "in" : "out");
                if (key != want)
                    continue;
                const auto slot = i * 2 + static_cast<std::size_t>(d);
                if (seen[slot])
                    return std::nullopt;
                seen[slot] = true;
                (d == 0 ? p[i].in : p[i].out) = a;
                matched = true;
            }
        }
        if (!matched)
            return std::nullopt;
    }
    if (!seen_v || !is_complete_prior_policy(p))
        return std::nullopt;
    return p;
}

enum class PriorStore : std::uint8_t { store, keep_existing, refuse_unrestorable, refuse_incomplete };

/// Write-once. An existing image always wins (a second quarantine must never
/// replace the pre-quarantine policy with the quarantine one); an incomplete
/// capture is refused; a block/block capture is refused ONLY when our own rule
/// group is already present (storage was lost while we stayed contained: such an
/// image is unrestorable by construction), because block/block is also a
/// legitimate hardened posture on a host we have not touched.
[[nodiscard]] constexpr PriorStore decide_prior_store(bool image_exists, bool our_group_present,
                                                      const WinPriorPolicy& captured) noexcept {
    if (image_exists)
        return PriorStore::keep_existing;
    if (!is_complete_prior_policy(captured))
        return PriorStore::refuse_incomplete;
    if (our_group_present && is_quarantine_shaped(captured))
        return PriorStore::refuse_unrestorable;
    return PriorStore::store;
}

[[nodiscard]] inline std::string serialize_disabled_rules(const std::vector<std::string>& names) {
    std::string out = "v=1\n";
    for (const auto& n : names) {
        for (char c : n) {
            if (c == '\\')
                out += "\\\\";
            else if (c == '\n')
                out += "\\n";
            else if (c == '\r')
                out += "\\r";
            else
                out += c;
        }
        out += '\n';
    }
    return out;
}

[[nodiscard]] inline std::optional<std::vector<std::string>>
parse_disabled_rules(std::string_view text) {
    std::vector<std::string> out;
    bool first = true;
    for (const auto line : detail::split(text, '\n')) {
        if (first) {
            first = false;
            if (line != "v=1")
                return std::nullopt;
            continue;
        }
        if (line.empty())
            continue;
        std::string name;
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (line[i] != '\\') {
                name += line[i];
                continue;
            }
            if (++i >= line.size())
                return std::nullopt;
            if (line[i] == '\\')
                name += '\\';
            else if (line[i] == 'n')
                name += '\n';
            else if (line[i] == 'r')
                name += '\r';
            else
                return std::nullopt;
        }
        out.push_back(std::move(name));
        if (out.size() > kMaxDisabledRules)
            return std::nullopt;
    }
    if (first)
        return std::nullopt;
    return out;
}

struct WinDisabledMerge {
    std::vector<std::string> list; // the list to keep
    bool grew = false;             // it differs from what is stored: write it
    bool over_cap = false;         // more than kMaxDisabledRules: refuse the apply
};

/// The disabled-rule list across generations. `stored` is the persisted list
/// (empty when none exists), `list_exists` whether one is stored at all. The
/// FIRST apply always writes the list, even an empty one (its presence is what
/// the release keys on); later applies only ever ADD names (a rule created or
/// re-enabled during the quarantine is disabled too), never drop one -- the
/// release must re-enable everything any generation disabled.
[[nodiscard]] inline WinDisabledMerge win_merge_disabled_list(std::vector<std::string> stored,
                                                              const std::vector<std::string>& to_disable,
                                                              bool list_exists) {
    WinDisabledMerge m;
    m.list = std::move(stored);
    m.grew = !list_exists;
    for (const auto& name : to_disable)
        if (std::find(m.list.begin(), m.list.end(), name) == m.list.end()) {
            m.list.push_back(name);
            m.grew = true;
        }
    m.over_cap = m.list.size() > kMaxDisabledRules;
    return m;
}

/// The default action a release puts back for profile `profile_index`: the
/// captured one when an image exists, else Windows' own default (inbound block,
/// outbound allow). The shell uses the fallback ONLY when it actually removed
/// rules of ours, so a second release on an untouched host never rewrites a
/// hardened policy. An `unknown` action in an image (parse_prior_policy never
/// yields one) restores as block, the safe side; an index outside the three
/// profiles reads as no image.
[[nodiscard]] constexpr WinProfilePolicy win_release_policy(const std::optional<WinPriorPolicy>& prior,
                                                            std::size_t profile_index) noexcept {
    if (!prior || profile_index >= prior->size())
        return {WinAction::block, WinAction::allow};
    const auto& p = (*prior)[profile_index];
    return {p.in == WinAction::allow ? WinAction::allow : WinAction::block,
            p.out == WinAction::allow ? WinAction::allow : WinAction::block};
}

struct WinUpdatePlan {
    std::vector<WinRuleSpec> add;      // new rules, created FIRST
    std::vector<std::string> remove;   // stale rules in our group, removed LAST
};

/// `existing` = the names currently in our rule group. Convergent from any
/// starting point (a crash mid-update, a repeated apply): rules already present
/// by name are kept, missing ones added, everything else removed.
[[nodiscard]] inline WinUpdatePlan win_update_plan(const std::vector<std::string>& existing,
                                                   const std::vector<WinRuleSpec>& next) {
    WinUpdatePlan plan;
    for (const auto& s : next)
        if (std::find(existing.begin(), existing.end(), s.name) == existing.end())
            plan.add.push_back(s);
    for (const auto& n : existing) {
        const bool wanted = std::any_of(next.begin(), next.end(),
                                        [&](const WinRuleSpec& s) { return s.name == n; });
        if (!wanted)
            plan.remove.push_back(n);
    }
    return plan;
}

// ── Linux: nftables ─────────────────────────────────────────────────────────

inline constexpr std::string_view kNftPath = "/usr/sbin/nft";
inline constexpr std::string_view kIptablesPath = "/usr/sbin/iptables";
inline constexpr std::string_view kIp6tablesPath = "/usr/sbin/ip6tables";

namespace detail {

inline void add_unique(std::vector<std::string>& v, std::string line) {
    if (std::find(v.begin(), v.end(), line) == v.end())
        v.push_back(std::move(line));
}

} // namespace detail

/// The atomic `nft -f` file: create-if-absent, flush, then the full table, in
/// ONE transaction (chains at policy drop and their rules commit together; a
/// failed load leaves the previous generation intact -- no unrestricted
/// window). Stateless: there is deliberately no `ct state established` accept,
/// so a connection that predates the quarantine is cut unless an allowance
/// matches it; each allowance therefore adds its reply path itself.
[[nodiscard]] inline std::string nft_ruleset_text(const AllowSet& set) {
    std::vector<std::string> in_rules, out_rules;
    for (const auto& r : flatten(set)) {
        if (r.kind == RuleKind::loopback) {
            detail::add_unique(in_rules, "iif lo accept");
            detail::add_unique(out_rules, "oif lo accept");
            continue;
        }
        if (r.kind == RuleKind::nd) {
            // 133-136 only: redirect (137) is not needed and is not allowed on any leg.
            const std::string nd = "icmpv6 type { nd-router-solicit, nd-router-advert, "
                                   "nd-neighbor-solicit, nd-neighbor-advert } accept";
            detail::add_unique(in_rules, nd);
            detail::add_unique(out_rules, nd);
            continue;
        }
        const auto l4 = l4_name(r.l4);
        // One stateless line: [family saddr|daddr ADDR] [l4 sport N] [l4 dport N] accept.
        auto line = [&](bool match_src, int sport, int dport) {
            std::vector<std::string> parts;
            if (!r.any_addr) {
                parts.push_back(r.ip.v6 ? "ip6" : "ip");
                parts.push_back(match_src ? "saddr" : "daddr");
                parts.push_back(rule_addr_text(r));
            }
            if (sport == 0 && dport == 0) {
                parts.insert(parts.end(), {"meta", "l4proto", std::string{l4}});
            } else {
                if (sport > 0)
                    parts.insert(parts.end(), {std::string{l4}, "sport", std::to_string(sport)});
                if (dport > 0)
                    parts.insert(parts.end(), {std::string{l4}, "dport", std::to_string(dport)});
            }
            parts.emplace_back("accept");
            std::string s;
            for (const auto& p : parts) {
                if (!s.empty())
                    s += ' ';
                s += p;
            }
            return s;
        };
        if (r.dir == Dir::out) {
            // request leaves: the peer is the destination and the service is remote;
            // the reply returns: the peer is the source and the service is the source port.
            detail::add_unique(out_rules, line(false, r.local_port, r.svc_port));
            detail::add_unique(in_rules, line(true, r.svc_port, r.local_port));
        } else {
            detail::add_unique(in_rules, line(true, r.local_port, r.svc_port));
            detail::add_unique(out_rules, line(false, r.svc_port, r.local_port));
        }
    }
    std::string t;
    const std::string table{kNftTable};
    t += "table inet " + table + " {}\n";
    t += "flush table inet " + table + "\n";
    t += "table inet " + table + " {\n";
    auto chain = [&](std::string_view name, const std::vector<std::string>& rules) {
        t += std::format("  chain {} {{\n", name);
        t += std::format("    type filter hook {} priority -100; policy drop;\n", name);
        for (const auto& r : rules)
            t += "    " + r + "\n";
        t += "  }\n";
    };
    chain("input", in_rules);
    chain("output", out_rules);
    chain("forward", {});
    t += "}\n";
    return t;
}

[[nodiscard]] inline std::vector<std::string> nft_apply_argv(std::string_view path) {
    return {std::string{kNftPath}, "-f", std::string{path}};
}
[[nodiscard]] inline std::vector<std::string> nft_delete_argv() {
    return {std::string{kNftPath}, "delete", "table", "inet", std::string{kNftTable}};
}
[[nodiscard]] inline std::vector<std::string> nft_list_argv() {
    return {std::string{kNftPath}, "list", "table", "inet", std::string{kNftTable}};
}

struct NftChainRow {
    std::string name;
    std::string hook;
    std::string policy;
};
struct NftTableListing {
    bool found = false;
    std::vector<NftChainRow> chains;
};

/// `nft list table inet yuzu_quarantine` -> the chains and their hook/policy.
[[nodiscard]] inline NftTableListing parse_nft_list_table(std::string_view text) {
    NftTableListing out;
    NftChainRow* cur = nullptr;
    for (const auto raw : detail::split(text, '\n')) {
        const auto line = detail::trim(raw);
        if (line.starts_with("table inet ") && line.find(kNftTable) != line.npos) {
            out.found = true;
            continue;
        }
        if (!out.found)
            continue;
        if (line.starts_with("chain ") && line.back() == '{') {
            const auto name = detail::trim(line.substr(6, line.size() - 7));
            out.chains.push_back({std::string{name}, {}, {}});
            cur = &out.chains.back();
            continue;
        }
        if (cur && line.starts_with("type ")) {
            if (const auto h = line.find(" hook "); h != line.npos) {
                auto rest = line.substr(h + 6);
                cur->hook = std::string{rest.substr(0, rest.find(' '))};
            }
            if (const auto p = line.find("policy "); p != line.npos) {
                auto rest = line.substr(p + 7);
                const auto end = rest.find_first_of("; ");
                cur->policy = std::string{rest.substr(0, end)};
            }
        }
    }
    return out;
}

/// Our table is enforcing iff all three base chains exist at policy drop.
[[nodiscard]] inline bool nft_listing_enforcing(const NftTableListing& l) {
    if (!l.found)
        return false;
    for (const std::string_view want : {"input", "output", "forward"}) {
        const auto it = std::find_if(l.chains.begin(), l.chains.end(),
                                     [&](const NftChainRow& c) { return c.name == want; });
        if (it == l.chains.end() || it->hook != want || it->policy != "drop")
            return false;
    }
    return true;
}

/// `nft delete table` of an already-absent table fails with ENOENT text; that
/// is a successful release, not an error.
[[nodiscard]] inline bool nft_output_means_absent(std::string_view out) {
    return out.find("No such file or directory") != out.npos ||
           out.find("does not exist") != out.npos;
}

// ── Linux: iptables generation chains ───────────────────────────────────────

[[nodiscard]] inline std::string ipt_chain(std::uint32_t gen) {
    return std::format("{}{}", kIptablesChainPrefix, gen);
}
[[nodiscard]] inline std::string ipt_fwd_chain(std::uint32_t gen) { return ipt_chain(gen) + "-f"; }

using Argv = std::vector<std::string>;

/// The rules of one generation chain for one address family. INPUT and OUTPUT
/// share the chain (direction is implicit in which address is local), FORWARD
/// jumps to a chain holding only a DROP.
[[nodiscard]] inline std::vector<Argv> iptables_build_plan(const AllowSet& set,
                                                           std::string_view tool,
                                                           std::uint32_t gen, bool v6) {
    std::vector<Argv> plan;
    const std::string chain = ipt_chain(gen);
    const std::string fwd = ipt_fwd_chain(gen);
    auto cmd = [&](std::initializer_list<std::string_view> args) {
        Argv a{std::string{tool}};
        for (const auto x : args)
            a.emplace_back(x);
        return a;
    };
    plan.push_back(cmd({"-N", chain}));
    auto append = [&](std::vector<std::string> rule) {
        Argv a{std::string{tool}, "-A", chain};
        for (auto& x : rule)
            a.push_back(std::move(x));
        if (std::find(plan.begin(), plan.end(), a) == plan.end())
            plan.push_back(std::move(a));
    };
    for (const auto& r : flatten(set)) {
        if (r.kind == RuleKind::loopback) {
            append({"-i", "lo", "-j", "ACCEPT"});
            append({"-o", "lo", "-j", "ACCEPT"});
            continue;
        }
        if (r.kind == RuleKind::nd) {
            if (!v6)
                continue;
            // 133-136: router/neighbour solicit and advert. 137 (redirect) is not needed
            // for neighbour discovery and would let a router steer traffic.
            for (int t = 133; t <= 136; ++t)
                append({"-p", "icmpv6", "--icmpv6-type", std::to_string(t), "-j", "ACCEPT"});
            continue;
        }
        if (!r.any_addr && r.ip.v6 != v6)
            continue;
        if (r.any_addr && r.v6 != v6)
            continue;
        const std::string l4{l4_name(r.l4)};
        auto rule = [&](bool match_src, int sport, int dport) {
            std::vector<std::string> a;
            if (!r.any_addr) {
                a.push_back(match_src ? "-s" : "-d");
                a.push_back(rule_addr_text(r));
            }
            a.push_back("-p");
            a.push_back(l4);
            if (sport > 0) {
                a.push_back("--sport");
                a.push_back(std::to_string(sport));
            }
            if (dport > 0) {
                a.push_back("--dport");
                a.push_back(std::to_string(dport));
            }
            a.push_back("-j");
            a.push_back("ACCEPT");
            return a;
        };
        if (r.dir == Dir::out) {
            append(rule(false, r.local_port, r.svc_port));
            append(rule(true, r.svc_port, r.local_port));
        } else {
            append(rule(true, r.local_port, r.svc_port));
            append(rule(false, r.svc_port, r.local_port));
        }
    }
    plan.push_back(Argv{std::string{tool}, "-A", chain, "-j", "DROP"});
    plan.push_back(cmd({"-N", fwd}));
    plan.push_back(Argv{std::string{tool}, "-A", fwd, "-j", "DROP"});
    return plan;
}

/// What `iptables -S` shows of us (and of the legacy plugin).
struct IptablesListing {
    std::vector<std::string> chains;                          // yuzu-fwq-* user chains
    std::vector<std::pair<std::string, std::string>> jumps;   // {builtin, our chain}
    bool legacy_chain = false;                                // `yuzu-quarantine` exists
    std::uint32_t max_gen = 0;
};

[[nodiscard]] inline std::optional<std::uint32_t> ipt_chain_gen(std::string_view name) {
    if (!name.starts_with(kIptablesChainPrefix))
        return std::nullopt;
    auto rest = name.substr(kIptablesChainPrefix.size());
    if (rest.size() > 2 && rest.substr(rest.size() - 2) == "-f")
        rest.remove_suffix(2);
    const auto v = detail::parse_uint(rest, 0x7fffffff);
    if (!v)
        return std::nullopt;
    return static_cast<std::uint32_t>(*v);
}

[[nodiscard]] inline IptablesListing parse_iptables_listing(std::string_view text) {
    IptablesListing out;
    for (const auto raw : detail::split(text, '\n')) {
        const auto line = detail::trim(raw);
        const auto f = detail::split(line, ' ');
        if (f.size() == 2 && f[0] == "-N") {
            if (f[1] == kLegacyIptablesChain)
                out.legacy_chain = true;
            if (const auto g = ipt_chain_gen(f[1])) {
                out.chains.emplace_back(f[1]);
                out.max_gen = std::max(out.max_gen, *g);
            }
        } else if (f.size() == 4 && f[0] == "-A" && f[2] == "-j") {
            if (ipt_chain_gen(f[3]))
                out.jumps.emplace_back(std::string{f[1]}, std::string{f[3]});
        }
    }
    return out;
}

/// Insert the new generation's jumps. The caller removes the old generation
/// only after these succeed, so both chains exist during the swap and the new
/// one (first in each built-in chain) governs from the first insert.
[[nodiscard]] inline std::vector<Argv> iptables_activate_plan(std::string_view tool,
                                                              std::uint32_t gen) {
    return {Argv{std::string{tool}, "-I", "INPUT", "1", "-j", ipt_chain(gen)},
            Argv{std::string{tool}, "-I", "OUTPUT", "1", "-j", ipt_chain(gen)},
            Argv{std::string{tool}, "-I", "FORWARD", "1", "-j", ipt_fwd_chain(gen)}};
}

/// Remove every yuzu-fwq-* generation EXCEPT `keep_gen` (0: remove all): jumps
/// first, then flush and delete the chains.
[[nodiscard]] inline std::vector<Argv> iptables_remove_plan(std::string_view tool,
                                                            const IptablesListing& listing,
                                                            std::uint32_t keep_gen) {
    std::vector<Argv> plan;
    auto kept = [&](const std::string& chain) {
        const auto g = ipt_chain_gen(chain);
        return keep_gen != 0 && g && *g == keep_gen;
    };
    for (const auto& [from, to] : listing.jumps)
        if (!kept(to))
            plan.push_back(Argv{std::string{tool}, "-D", from, "-j", to});
    for (const auto& c : listing.chains) {
        if (kept(c))
            continue;
        plan.push_back(Argv{std::string{tool}, "-F", c});
        plan.push_back(Argv{std::string{tool}, "-X", c});
    }
    return plan;
}

// ── macOS: pf anchor (pure pieces; the leg itself is PfLeg, below) ───────────

inline constexpr std::string_view kPfctlPath = "/sbin/pfctl";

/// The sub-anchor ruleset (design note section 2.2). Every rule is `quick`.
///  - `no nat all` / `no rdr all` come first: Apple's main ruleset has
///    `nat-anchor`/`rdr-anchor "com.apple/*"`, translation is first-match, and a
///    `nat pass` / `rdr pass` in another anchor would otherwise skip the filter.
///    Translation rules must precede filter rules in a pf file.
///  - Loopback is `no state`, first among the filter rules: there is no lo0 state
///    to die (the commit 672896112 incident class).
///  - The control channel is STATELESS in both directions. A state rebuilt from a
///    mid-stream packet (`flags any`) lacks the TCP window-scaling factor and
///    would stall the live stream after the state flush; with `no state` the
///    flush cannot touch it, and `flags S/SA` is not applied to a `no state` rule.
///  - DHCP leaves only toward the broadcast address: macOS lets an unprivileged
///    process bind below 1024, so `to any port 67` would be an exit to anything.
///    The reply direction stays `from any port 67` (inbound only, no exit).
///  - ICMPv6 neighbour discovery is 133-136; redirect (137) is not needed.
///  - `block drop quick all` is last so nothing later can override containment.
[[nodiscard]] inline std::string pf_anchor_ruleset(const AllowSet& set) {
    std::vector<std::string> lines;
    lines.emplace_back("no nat all");
    lines.emplace_back("no rdr all");
    lines.emplace_back("pass quick on lo0 all no state");
    for (const auto& r : flatten(set)) {
        switch (r.kind) {
        case RuleKind::loopback:
            break;
        case RuleKind::nd:
            lines.emplace_back("pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } "
                               "no state");
            break;
        case RuleKind::dhcp:
            lines.emplace_back("pass out quick inet proto udp from any port 68 to 255.255.255.255 "
                               "port 67 keep state");
            lines.emplace_back("pass in quick inet proto udp from any port 67 to any port 68 "
                               "keep state");
            break;
        case RuleKind::control: {
            const auto fam = r.ip.v6 ? "inet6" : "inet";
            const auto addr = rule_addr_text(r);
            lines.push_back(std::format("pass out quick {} proto tcp from any to {} port {} no state",
                                        fam, addr, r.svc_port));
            lines.push_back(std::format("pass in quick {} proto tcp from {} port {} to any no state",
                                        fam, addr, r.svc_port));
            break;
        }
        default: {
            std::string s = r.dir == Dir::out ? "pass out quick" : "pass in quick";
            s += r.ip.v6 ? " inet6" : " inet";
            s += std::format(" proto {}", l4_name(r.l4));
            const auto addr = rule_addr_text(r);
            if (r.dir == Dir::out) {
                s += std::format(" from any to {}", addr);
                if (r.svc_port > 0)
                    s += std::format(" port {}", r.svc_port);
            } else {
                s += std::format(" from {} to any", addr);
                if (r.svc_port > 0)
                    s += std::format(" port {}", r.svc_port);
            }
            s += " keep state";
            lines.push_back(std::move(s));
            break;
        }
        }
    }
    lines.emplace_back("block drop quick all");
    std::vector<std::string> unique;
    for (auto& l : lines)
        detail::add_unique(unique, std::move(l));
    std::string out;
    for (const auto& l : unique)
        out += l + "\n";
    return out;
}

[[nodiscard]] inline Argv pfctl_load_argv(std::string_view path) {
    return {std::string{kPfctlPath}, "-a", std::string{kPfAnchor}, "-f", std::string{path}};
}
[[nodiscard]] inline Argv pfctl_flush_states_argv() { return {std::string{kPfctlPath}, "-F", "states"}; }
[[nodiscard]] inline Argv pfctl_enable_argv() { return {std::string{kPfctlPath}, "-E"}; }
[[nodiscard]] inline Argv pfctl_release_argv(std::string_view token) {
    return {std::string{kPfctlPath}, "-X", std::string{token}};
}
/// Empty OUR anchor only. `-a <anchor> -F all` is not used: pfctl scopes only
/// rules, nat and tables by anchor; `-F states`, `Sources`, `info` and `osfp` are
/// global whatever `-a` says, so `-F all` would cut every host connection a second
/// time at release and zero the global counters.
[[nodiscard]] inline Argv pfctl_flush_anchor_rules_argv() {
    return {std::string{kPfctlPath}, "-a", std::string{kPfAnchor}, "-F", "rules"};
}
[[nodiscard]] inline Argv pfctl_flush_anchor_nat_argv() {
    return {std::string{kPfctlPath}, "-a", std::string{kPfAnchor}, "-F", "nat"};
}
[[nodiscard]] inline Argv pfctl_info_argv() { return {std::string{kPfctlPath}, "-s", "info"}; }
[[nodiscard]] inline Argv pfctl_rules_argv() { return {std::string{kPfctlPath}, "-s", "rules"}; }
[[nodiscard]] inline Argv pfctl_anchor_rules_argv() {
    return {std::string{kPfctlPath}, "-a", std::string{kPfAnchor}, "-s", "rules"};
}
[[nodiscard]] inline Argv pfctl_siblings_argv() {
    return {std::string{kPfctlPath}, "-a", std::string{kPfAnchorParent}, "-s", "Anchors"};
}
[[nodiscard]] inline Argv pfctl_references_argv() {
    return {std::string{kPfctlPath}, "-s", "References"};
}

/// `pfctl -E` reports the enable-reference token on stderr as `Token : <digits>`.
[[nodiscard]] inline std::optional<std::string> parse_pfctl_token(std::string_view text) {
    for (const auto raw : detail::split(text, '\n')) {
        const auto line = detail::trim(raw);
        if (!line.starts_with("Token"))
            continue;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        const auto v = detail::trim(line.substr(colon + 1));
        if (detail::is_digits(v, 1, 24))
            return std::string{v};
    }
    return std::nullopt;
}

/// Live enable references from `pfctl -s References` ("pid/name of enabler,
/// token, timestamp", pfctl(8)). The column order is unverified on a live host
/// (design note, open question 3), so a line counts once when ANY of its fields
/// is a 15-24 digit decimal -- a token; a pid and an epoch timestamp are shorter.
[[nodiscard]] inline std::vector<std::string> parse_pf_references(std::string_view text) {
    std::vector<std::string> out;
    for (const auto raw : detail::split(text, '\n')) {
        std::string_view rest = detail::trim(raw);
        while (!rest.empty()) {
            const auto sp = rest.find_first_of(" \t");
            const auto field = rest.substr(0, sp);
            if (detail::is_digits(field, 15, 24)) {
                out.emplace_back(field);
                break;
            }
            if (sp == std::string_view::npos)
                break;
            rest = detail::trim(rest.substr(sp));
        }
    }
    return out;
}

/// Is Apple's wildcard anchor reference in the main ruleset (`pfctl -s rules`)?
/// Without it a sub-anchor is never evaluated: the quarantine would be dangling.
/// The WHOLE line must match: a qualified `anchor "com.apple/*" on en0 ...` only
/// covers one interface, so a prefix match would call it live. A reference is
/// necessary, not sufficient (a `pass quick` before it still wins).
[[nodiscard]] inline bool pf_anchor_referenced(std::string_view rules_text) {
    for (const auto raw : detail::split(rules_text, '\n')) {
        const auto line = detail::trim(raw);
        if (line == "anchor \"com.apple/*\" all" ||
            line == "anchor \"com.apple/000.yuzu_quarantine\" all")
            return true;
    }
    return false;
}

/// Does our anchor hold the containment? (`pfctl -a <anchor> -s rules`): the
/// closing `block drop quick all` is there. An empty anchor reads as absent.
[[nodiscard]] inline bool pf_anchor_enforcing(std::string_view anchor_rules_text) {
    for (const auto raw : detail::split(anchor_rules_text, '\n'))
        if (detail::trim(raw).starts_with("block drop quick all"))
            return true;
    return false;
}

/// Siblings of our anchor under `com.apple` that pf evaluates BEFORE it, from
/// `pfctl -a com.apple -s Anchors`. A line counts only if it is one token that is
/// a direct child (`com.apple/<leaf>` or a bare `<leaf>`); anything else (a
/// banner, a deeper path) is ignored, so a misread cannot flag a healthy host.
/// The printed form is unverified on a live host (design note, open question 6).
[[nodiscard]] inline std::vector<std::string> pf_siblings_before(std::string_view anchors_text) {
    std::vector<std::string> out;
    constexpr std::string_view prefix = "com.apple/";
    for (const auto raw : detail::split(anchors_text, '\n')) {
        auto name = detail::trim(raw);
        if (name.empty() || name.find_first_of(" \t") != std::string_view::npos)
            continue;
        if (name.starts_with(prefix))
            name.remove_prefix(prefix.size());
        if (name.find('/') != std::string_view::npos || !is_safe_token(name))
            continue;
        if (name < kPfAnchorLeaf)
            out.emplace_back(name);
    }
    std::sort(out.begin(), out.end());
    return out;
}

[[nodiscard]] inline bool pf_enabled(std::string_view info_text) {
    for (const auto raw : detail::split(info_text, '\n'))
        if (detail::trim(raw).starts_with("Status: Enabled"))
            return true;
    return false;
}

/// What the leg does about pf's enable reference (design note 2.4).
///  - enable: no token stored, or the token is from another boot (the kernel's
///    reference count reset at reboot, the token means nothing): take a fresh `-E`.
///  - reuse:  a token for THIS boot and pf is on: a second `-E` would take a
///    second reference we would then have to track.
///  - repair: a token for THIS boot but pf is OFF: someone ran `pfctl -d`, so the
///    token is dead. Release it best-effort (it may be gone) and take a fresh `-E`.
enum class PfEnablePlan : std::uint8_t { enable, reuse, repair };

[[nodiscard]] inline PfEnablePlan pf_enable_plan(const OsPayload& os, std::string_view current_boot,
                                                 bool pf_is_enabled) noexcept {
    if (os.pf_token.empty() || os.boot_time != current_boot)
        return PfEnablePlan::enable;
    return pf_is_enabled ? PfEnablePlan::reuse : PfEnablePlan::repair;
}

// ── Resolvers ───────────────────────────────────────────────────────────────

/// `nameserver` values of a resolv.conf (comments `#`/`;` ignored, duplicates
/// dropped, order kept). Entries are returned raw; build_allow_set validates.
[[nodiscard]] inline std::vector<std::string> parse_resolv_conf(std::string_view text) {
    std::vector<std::string> out;
    for (const auto raw : detail::split(text, '\n')) {
        auto line = detail::trim(raw);
        if (line.empty() || line.front() == '#' || line.front() == ';')
            continue;
        if (!line.starts_with("nameserver"))
            continue;
        line.remove_prefix(10);
        if (line.empty() || (line.front() != ' ' && line.front() != '\t'))
            continue;
        auto v = detail::trim(line);
        if (const auto c = v.find_first_of("#; \t"); c != std::string_view::npos)
            v = v.substr(0, c);
        if (v.empty())
            continue;
        if (std::find(out.begin(), out.end(), std::string{v}) == out.end())
            out.emplace_back(v);
    }
    return out;
}

/// The resolvers to allow. A loopback entry is a local stub (systemd-resolved's
/// 127.0.0.53) that forwards from THIS host to the real upstreams, so the real
/// upstream list (/run/systemd/resolve/resolv.conf) is followed one hop and
/// appended; the stub itself stays (loopback is allowed anyway). Capped.
[[nodiscard]] inline std::vector<std::string>
resolver_chain(std::string_view primary_text, std::string_view systemd_upstream_text) {
    auto out = parse_resolv_conf(primary_text);
    bool stub = false;
    for (const auto& r : out)
        if (const auto ip = parse_ip(r); ip && is_loopback(*ip))
            stub = true;
    if (stub)
        for (auto& u : parse_resolv_conf(systemd_upstream_text)) {
            const auto ip = parse_ip(u);
            if (ip && is_loopback(*ip))
                continue;
            if (std::find(out.begin(), out.end(), u) == out.end())
                out.push_back(std::move(u));
        }
    if (out.size() > kMaxResolvers)
        out.resize(kMaxResolvers);
    return out;
}

// ── The injected OS seam ────────────────────────────────────────────────────

/// A command's outcome, independent of the agent's runner type so the core
/// stays free of it. `ok()` is the only success.
struct ToolResult {
    bool ran = false;
    int exit_code = -1;
    bool timed_out = false;
    bool truncated = false;
    std::string output;
    [[nodiscard]] bool ok() const noexcept {
        return ran && exit_code == 0 && !timed_out && !truncated;
    }
};

using Runner = std::function<ToolResult(const Argv& argv, std::chrono::milliseconds budget)>;
using TcpProbe =
    std::function<ProbeOutcome(const std::string& ip, int port, std::chrono::milliseconds timeout)>;

/// A staged ruleset file; `keepalive` owns its deletion.
struct StagedFile {
    std::string path;
    std::shared_ptr<void> keepalive;
};
using Stage = std::function<std::optional<StagedFile>(std::string_view stem,
                                                      std::string_view suffix,
                                                      std::string_view contents)>;
/// Status read of our nft table over netlink; nullopt when it was refused.
using NftChainReader = std::function<std::optional<NftTableListing>()>;
using PersistOs = std::function<bool(const OsPayload&)>;
/// macOS: the current boot's identity (`kern.boottime`), or nullopt when unreadable.
using BootTime = std::function<std::optional<std::string>()>;

/// One operation's deadline (kOperationBudget bounds the apply plan). The undo of
/// a failed initial apply gets a fresh one and the verification a fresh
/// kVerifyBudget (see fresh()), so one quarantine is bounded by about 60 s + 10 s
/// when it succeeds and 60 s + 10 s + 60 s when it fails and is undone; a boot-time
/// re-apply by the first two. The clock is injectable so a test advances it from a
/// fake runner instead of sleeping.
class Deadline {
public:
    using Clock = std::chrono::steady_clock;
    using NowFn = std::function<Clock::time_point()>;

    explicit Deadline(std::chrono::milliseconds budget = kOperationBudget, NowFn now = {})
        : now_(now ? std::move(now) : NowFn{[] { return Clock::now(); }}), end_(now_() + budget) {}

    [[nodiscard]] std::chrono::milliseconds remaining() const {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - now_());
        return left.count() > 0 ? left : std::chrono::milliseconds{0};
    }
    [[nodiscard]] bool expired() const { return remaining().count() <= 0; }
    [[nodiscard]] std::chrono::milliseconds cap(std::chrono::milliseconds per_call) const {
        return std::min(per_call, remaining());
    }
    /// A new deadline on the same clock. Cleanup and verification get their own
    /// budget so a slow apply cannot starve the step that makes it safe.
    [[nodiscard]] Deadline fresh(std::chrono::milliseconds budget) const { return Deadline(budget, now_); }

private:
    NowFn now_;
    Clock::time_point end_;
};

inline constexpr std::chrono::milliseconds kVerifyBudget{10'000};

struct StepResult {
    bool ok = false;
    std::string reason;  // token on failure
    std::string detail;  // sanitized first line of tool output, optional
    bool partial = false; // applied, but not completely (e.g. rules_not_disabled)
    std::vector<std::string> notes;

    [[nodiscard]] static StepResult success() {
        StepResult r;
        r.ok = true;
        return r;
    }
    [[nodiscard]] static StepResult fail(std::string reason, std::string detail = {}) {
        StepResult r;
        r.reason = std::move(reason);
        r.detail = std::move(detail);
        return r;
    }
};

enum class OsState : std::uint8_t { enforcing, not_enforcing, unreadable };
struct LegStatus {
    OsState state = OsState::unreadable;
    bool partial = false;
    std::string reason; // policy_not_blocking | pf_disabled | anchor_not_referenced | ...
    /// False when re-applying cannot repair what is wrong (a dangling anchor, a
    /// sibling that sorts first): `quarantine` then answers `already_active`
    /// instead of flushing every pf state again on each retry.
    bool reapply_helps = true;
    std::vector<std::string> notes;
};

/// What one OS mechanism can do. Windows implements it over COM in the plugin;
/// the nft, iptables and pf legs are implemented here over Runner.
class Leg {
public:
    virtual ~Leg() = default;
    [[nodiscard]] virtual BackendKind kind() const = 0;
    /// A reason to refuse before any mutation (a legacy quarantine in force).
    [[nodiscard]] virtual std::optional<std::string> preflight(Deadline& dl) = 0;
    /// Make `next` the effective generation. On failure the previously effective
    /// generation must still be in force (an initial apply may leave partial
    /// state, which the caller removes with remove()). A leg that cannot meet
    /// that after its commit point (the pf anchor load) reports success with
    /// `partial` for an update (`prev_gen != 0`), so the record and the output
    /// describe what is in force.
    [[nodiscard]] virtual StepResult apply(const AllowSet& next, std::uint32_t gen,
                                           std::uint32_t prev_gen, OsPayload& os, Deadline& dl,
                                           const PersistOs& persist) = 0;
    /// Remove everything this leg created and restore what it replaced. Idempotent.
    [[nodiscard]] virtual StepResult remove(OsPayload& os, Deadline& dl) = 0;
    [[nodiscard]] virtual LegStatus read_status(const OsPayload& os, Deadline& dl) = 0;
};

struct StateLoad {
    enum class Kind : std::uint8_t { absent, ok, unreadable } kind = Kind::absent;
    QuarantineState state;
};

class StateStore {
public:
    virtual ~StateStore() = default;
    [[nodiscard]] virtual StateLoad load() = 0;
    [[nodiscard]] virtual bool save(const QuarantineState& s) = 0;
    [[nodiscard]] virtual bool erase() = 0;
};

namespace detail {

[[nodiscard]] inline std::string first_line(std::string_view out) {
    const auto nl = out.find('\n');
    return sanitize_text(detail::trim(out.substr(0, nl)), 80);
}

/// pfctl prints a warning about flushing system rules on every `-f` (success or
/// not); the useful line of a failure is the first one that is not that boilerplate.
[[nodiscard]] inline std::string pf_error_line(std::string_view out) {
    for (const auto raw : split(out, '\n')) {
        const auto line = trim(raw);
        if (line.empty() || line.starts_with("pfctl: Use of -f option") ||
            line.starts_with("present in the main ruleset") ||
            line.starts_with("See /etc/pf.conf"))
            continue;
        return sanitize_text(line, 80);
    }
    return {};
}

/// Every command goes through here: argv charset check, then the deadline.
class Exec {
public:
    Exec(const Runner& run, Deadline& dl) : run_(run), dl_(dl) {}
    [[nodiscard]] std::optional<ToolResult> call(const Argv& argv) {
        if (!all_tokens_safe(argv)) {
            reason_ = "unsafe_argv";
            return std::nullopt;
        }
        if (dl_.expired()) {
            reason_ = "deadline_exceeded";
            return std::nullopt;
        }
        auto r = run_(argv, dl_.cap(kCallBudget));
        if (r.timed_out && dl_.expired()) {
            reason_ = "deadline_exceeded";
            return std::nullopt;
        }
        return r;
    }
    [[nodiscard]] const std::string& reason() const noexcept { return reason_; }

private:
    const Runner& run_;
    Deadline& dl_;
    std::string reason_;
};

} // namespace detail

// ── Linux legs ──────────────────────────────────────────────────────────────

/// Refuse when the retained legacy quarantine plugin's chain is present (its
/// release would otherwise delete or restore under ours). An unreadable
/// listing does not block: containment must not depend on a diagnostic read.
[[nodiscard]] inline std::optional<std::string> linux_legacy_preflight(const Runner& run,
                                                                       Deadline& dl) {
    detail::Exec ex(run, dl);
    const auto r = ex.call({std::string{kIptablesPath}, "-S"});
    if (!r || !r->ok())
        return std::nullopt;
    if (parse_iptables_listing(r->output).legacy_chain)
        return "legacy_quarantine_active";
    return std::nullopt;
}

class NftLeg final : public Leg {
public:
    NftLeg(Runner run, Stage stage, NftChainReader reader = {})
        : run_(std::move(run)), stage_(std::move(stage)), reader_(std::move(reader)) {}

    [[nodiscard]] BackendKind kind() const override { return BackendKind::nft; }

    [[nodiscard]] std::optional<std::string> preflight(Deadline& dl) override {
        return linux_legacy_preflight(run_, dl);
    }

    [[nodiscard]] StepResult apply(const AllowSet& next, std::uint32_t, std::uint32_t, OsPayload&,
                                   Deadline& dl, const PersistOs&) override {
        const auto text = nft_ruleset_text(next);
        if (!is_safe_ruleset_text(text))
            return StepResult::fail("unsafe_ruleset");
        const auto staged = stage_("yuzu-fwq-", ".nft", text);
        if (!staged)
            return StepResult::fail("stage_failed");
        detail::Exec ex(run_, dl);
        const auto r = ex.call(nft_apply_argv(staged->path));
        if (!r)
            return StepResult::fail(ex.reason());
        if (!r->ok())
            return StepResult::fail("nft_load_failed", detail::first_line(r->output));
        return StepResult::success();
    }

    [[nodiscard]] StepResult remove(OsPayload&, Deadline& dl) override {
        detail::Exec ex(run_, dl);
        const auto r = ex.call(nft_delete_argv());
        if (!r)
            return StepResult::fail(ex.reason());
        if (r->ok() || nft_output_means_absent(r->output))
            return StepResult::success();
        return StepResult::fail("nft_delete_failed", detail::first_line(r->output));
    }

    [[nodiscard]] LegStatus read_status(const OsPayload&, Deadline& dl) override {
        LegStatus st;
        if (reader_) {
            if (const auto listing = reader_()) {
                st.state = nft_listing_enforcing(*listing) ? OsState::enforcing
                                                           : OsState::not_enforcing;
                if (st.state == OsState::not_enforcing)
                    st.reason = "policy_not_blocking";
                return st;
            }
        }
        detail::Exec ex(run_, dl);
        const auto r = ex.call(nft_list_argv());
        if (!r)
            return st;
        if (r->ok()) {
            st.state = nft_listing_enforcing(parse_nft_list_table(r->output))
                           ? OsState::enforcing
                           : OsState::not_enforcing;
        } else if (nft_output_means_absent(r->output)) {
            st.state = OsState::not_enforcing;
        } else {
            return st;
        }
        if (st.state == OsState::not_enforcing)
            st.reason = "policy_not_blocking";
        return st;
    }

private:
    Runner run_;
    Stage stage_;
    NftChainReader reader_;
};

class IptablesLeg final : public Leg {
public:
    IptablesLeg(Runner run, bool has_v6) : run_(std::move(run)), has_v6_(has_v6) {}

    [[nodiscard]] BackendKind kind() const override { return BackendKind::iptables; }

    [[nodiscard]] std::optional<std::string> preflight(Deadline& dl) override {
        return linux_legacy_preflight(run_, dl);
    }

    [[nodiscard]] StepResult apply(const AllowSet& next, std::uint32_t gen, std::uint32_t,
                                   OsPayload& os, Deadline& dl, const PersistOs&) override {
        struct Fam {
            std::string_view tool;
            bool v6;
            IptablesListing before;
        };
        std::vector<Fam> fams{{kIptablesPath, false, {}}};
        if (has_v6_)
            fams.push_back({kIp6tablesPath, true, {}});
        detail::Exec ex(run_, dl);
        std::uint32_t max_gen = 0;
        for (auto& f : fams) {
            const auto r = ex.call({std::string{f.tool}, "-S"});
            if (!r)
                return StepResult::fail(ex.reason());
            if (!r->ok())
                return StepResult::fail("iptables_list_failed", detail::first_line(r->output));
            f.before = parse_iptables_listing(r->output);
            max_gen = std::max(max_gen, f.before.max_gen);
        }
        // A chain of this generation can already exist (an interrupted attempt):
        // never reuse a name, always go one past everything seen.
        const std::uint32_t eff = std::max(gen, max_gen + 1);

        auto run_all = [&](const std::vector<Argv>& plan, std::string& why,
                           std::string& detail_out) {
            for (const auto& a : plan) {
                const auto r = ex.call(a);
                if (!r) {
                    why = ex.reason();
                    return false;
                }
                if (!r->ok()) {
                    why = "iptables_command_failed";
                    detail_out = detail::first_line(r->output);
                    return false;
                }
            }
            return true;
        };
        // Best-effort cleanup runs on its own budget: a slow build must not
        // starve the step that removes its half-built chains.
        auto drop_new = [&](bool with_jumps) {
            auto cleanup_dl = dl.fresh(kVerifyBudget);
            detail::Exec cx(run_, cleanup_dl);
            for (const auto& f : fams) {
                std::vector<Argv> plan;
                if (with_jumps) {
                    plan.push_back({std::string{f.tool}, "-D", "INPUT", "-j", ipt_chain(eff)});
                    plan.push_back({std::string{f.tool}, "-D", "OUTPUT", "-j", ipt_chain(eff)});
                    plan.push_back({std::string{f.tool}, "-D", "FORWARD", "-j", ipt_fwd_chain(eff)});
                }
                for (const auto& c : {ipt_chain(eff), ipt_fwd_chain(eff)}) {
                    plan.push_back({std::string{f.tool}, "-F", c});
                    plan.push_back({std::string{f.tool}, "-X", c});
                }
                for (const auto& a : plan)
                    (void)cx.call(a);
            }
        };

        std::string why, det;
        for (const auto& f : fams) {
            if (!run_all(iptables_build_plan(next, f.tool, eff, f.v6), why, det)) {
                drop_new(false);
                return StepResult::fail(why, det);
            }
        }
        for (const auto& f : fams) {
            if (!run_all(iptables_activate_plan(f.tool, eff), why, det)) {
                drop_new(true);
                return StepResult::fail(why, det);
            }
        }
        StepResult ok = StepResult::success();
        // The new generation governs from the first insert; removing the old one
        // is tidying, so a failure here is a note, not a failed update.
        for (const auto& f : fams) {
            for (const auto& a : iptables_remove_plan(f.tool, f.before, eff)) {
                const auto r = ex.call(a);
                if (!r || !r->ok()) {
                    ok.notes.emplace_back("old_generation_left=1");
                    break;
                }
            }
        }
        os.ipt_gen = eff;
        os.ipt_v6 = has_v6_;
        return ok;
    }

    [[nodiscard]] StepResult remove(OsPayload& os, Deadline& dl) override {
        detail::Exec ex(run_, dl);
        std::vector<std::string_view> tools{kIptablesPath};
        if (has_v6_)
            tools.push_back(kIp6tablesPath);
        for (int pass = 0; pass < 2; ++pass) {
            bool clean = true;
            for (const auto tool : tools) {
                const auto r = ex.call({std::string{tool}, "-S"});
                if (!r)
                    return StepResult::fail(ex.reason());
                if (!r->ok()) {
                    // A host with the ip6tables binary but no IPv6 stack cannot list
                    // it; that is fine unless we put something there.
                    if (tool == kIp6tablesPath && !os.ipt_v6)
                        continue;
                    return StepResult::fail("iptables_list_failed", detail::first_line(r->output));
                }
                const auto listing = parse_iptables_listing(r->output);
                if (listing.chains.empty() && listing.jumps.empty())
                    continue;
                clean = false;
                for (const auto& a : iptables_remove_plan(tool, listing, 0)) {
                    const auto c = ex.call(a);
                    if (!c && ex.reason() == "deadline_exceeded")
                        return StepResult::fail(ex.reason());
                }
            }
            if (clean) {
                os.ipt_gen = 0;
                return StepResult::success();
            }
        }
        return StepResult::fail("remove_incomplete");
    }

    [[nodiscard]] LegStatus read_status(const OsPayload& os, Deadline& dl) override {
        LegStatus st;
        detail::Exec ex(run_, dl);
        std::vector<std::string_view> tools{kIptablesPath};
        // v6 is judged only where the apply covered it (an IPv6 stack existed then).
        if (has_v6_ && os.ipt_v6)
            tools.push_back(kIp6tablesPath);
        bool all = true;
        for (const auto tool : tools) {
            const auto r = ex.call({std::string{tool}, "-S"});
            if (!r || !r->ok())
                return st;
            const auto l = parse_iptables_listing(r->output);
            bool in = false, out = false, fwd = false;
            for (const auto& [from, to] : l.jumps) {
                in = in || from == "INPUT";
                out = out || from == "OUTPUT";
                fwd = fwd || from == "FORWARD";
            }
            all = all && in && out && fwd;
        }
        st.state = all ? OsState::enforcing : OsState::not_enforcing;
        if (!all)
            st.reason = "policy_not_blocking";
        return st;
    }

private:
    Runner run_;
    bool has_v6_;
};

// ── macOS leg ───────────────────────────────────────────────────────────────

/// The pf sub-anchor leg (docs/quarantine-macos-pf-anchor-design.md). The main
/// ruleset is never loaded or rewritten: everything lives in the anchor
/// `com.apple/000.yuzu_quarantine`, reached through Apple's own wildcard.
///
/// One apply, in this order (each step under the operation deadline):
///   1. `-s info`: is pf on?
///   2. enable reference (pf_enable_plan): reuse, fresh `-E`, or release a dead token
///      then `-E`. The token is handed to `persist` IMMEDIATELY, before anything
///      else depends on pf being on. The `applying` record already exists (the
///      driver wrote it first), so a crash between `-E` and `persist` leaks one
///      reference until reboot -- the one residual, visible as `pf_references`.
///   3. `-s rules`: the main ruleset must reference the wildcard, else fail
///      `anchor_not_referenced` (before anything is loaded or flushed).
///   4. `-a com.apple -s Anchors`: a sibling that sorts before ours makes the
///      result partial (`anchor_not_first`), never a clean success.
///   5. `-a <anchor> -f <staged file>`: atomic per anchor.
///   6. `-F states`: pf passes a state-matched packet without evaluating any rule,
///      so pre-existing connections would survive the load. Retried once. A
///      failure on an INITIAL apply is a FAILED apply (`state_flush_failed`), never
///      `active`. On an UPDATE (`prev_gen != 0`) the anchor already holds the new
///      generation and the previous one flushed the states at its own apply, so
///      the leg reports success with `partial` and `state_flush_failed=1`: the
///      driver then records and reports the generation actually in force. The
///      control channel is stateless, so the flush cannot touch it.
/// A failure before step 5 gives back a reference taken in this call. After the
/// anchor is loaded the reference is kept: pf stays on, and the driver either
/// removes the anchor (initial apply) or records the new generation.
class PfLeg final : public Leg {
public:
    PfLeg(Runner run, Stage stage, BootTime boot)
        : run_(std::move(run)), stage_(std::move(stage)), boot_(std::move(boot)) {}

    [[nodiscard]] BackendKind kind() const override { return BackendKind::pf; }

    // The retained plugin's pf path loads a whole main ruleset and leaves no
    // marker in `pfctl -s rules` that could be refused on (design note section 3).
    [[nodiscard]] std::optional<std::string> preflight(Deadline&) override { return std::nullopt; }

    [[nodiscard]] StepResult apply(const AllowSet& next, std::uint32_t, std::uint32_t prev_gen,
                                   OsPayload& os, Deadline& dl, const PersistOs& persist) override {
        const auto text = pf_anchor_ruleset(next);
        if (!is_safe_ruleset_text(text))
            return StepResult::fail("unsafe_ruleset");
        const auto boot = boot_ ? boot_() : std::nullopt;
        if (!boot || !is_safe_token(*boot))
            return StepResult::fail("boot_time_unreadable");
        detail::Exec ex(run_, dl);

        const OsPayload before = os;
        bool took = false;
        auto give_back = [&](StepResult r) {
            if (took) {
                auto cdl = dl.fresh(kVerifyBudget);
                detail::Exec cx(run_, cdl);
                (void)cx.call(pfctl_release_argv(os.pf_token));
                os = before;
                (void)persist(os);
            }
            return r;
        };

        const auto info = ex.call(pfctl_info_argv());
        if (!info)
            return StepResult::fail(ex.reason());
        const auto plan = pf_enable_plan(os, *boot, info->ok() && pf_enabled(info->output));
        if (plan == PfEnablePlan::repair) {
            // pf was switched off behind our back: the token is dead. A vanished
            // token is expected, so the release is best-effort.
            if (!ex.call(pfctl_release_argv(os.pf_token)))
                return StepResult::fail(ex.reason());
            os.pf_token.clear();
            os.boot_time.clear();
        }
        if (plan != PfEnablePlan::reuse) {
            const auto en = ex.call(pfctl_enable_argv());
            if (!en)
                return StepResult::fail(ex.reason());
            if (!en->ok())
                return StepResult::fail("pf_enable_failed", detail::pf_error_line(en->output));
            const auto token = parse_pfctl_token(en->output);
            if (!token)
                return StepResult::fail("pf_enable_no_token");
            os.pf_token = *token;
            os.boot_time = *boot;
            took = true;
            if (!persist(os))
                return give_back(StepResult::fail("state_not_persisted"));
        }

        const auto rules = ex.call(pfctl_rules_argv());
        if (!rules)
            return give_back(StepResult::fail(ex.reason()));
        if (!rules->ok())
            return give_back(StepResult::fail("pf_rules_unreadable", detail::pf_error_line(rules->output)));
        if (!pf_anchor_referenced(rules->output))
            return give_back(StepResult::fail("anchor_not_referenced"));

        StepResult ok = StepResult::success();
        const auto sib = ex.call(pfctl_siblings_argv());
        if (!sib)
            return give_back(StepResult::fail(ex.reason()));
        if (!sib->ok()) {
            ok.notes.emplace_back("pf_siblings_unreadable=1");
        } else if (!pf_siblings_before(sib->output).empty()) {
            ok.partial = true;
            ok.notes.emplace_back("anchor_not_first=1");
        }

        const auto staged = stage_("yuzu-fwq-", ".pf", text);
        if (!staged)
            return give_back(StepResult::fail("stage_failed"));
        const auto ld = ex.call(pfctl_load_argv(staged->path));
        if (!ld)
            return give_back(StepResult::fail(ex.reason()));
        if (!ld->ok())
            return give_back(StepResult::fail("pf_load_failed", detail::pf_error_line(ld->output)));

        bool flushed = false;
        for (int attempt = 0; attempt < 2 && !flushed; ++attempt) {
            const auto fl = ex.call(pfctl_flush_states_argv());
            if (!fl)
                break; // the deadline is spent: no retry
            flushed = fl->ok();
        }
        if (!flushed) {
            // The anchor load already committed `next`, and putting `prev` back would
            // need its allow set, which Leg::apply is not given: an update therefore
            // reports the generation that IS in force, partial. Connections the
            // previous generation allowed and this one does not may live on until
            // they end (the previous apply flushed the states that predate it).
            if (prev_gen == 0)
                return StepResult::fail("state_flush_failed");
            ok.partial = true;
            ok.notes.emplace_back("state_flush_failed=1");
        }
        return ok;
    }

    /// Empty OUR anchor (filter rules, then translation rules), then release our
    /// enable token. Never `-F all`, never `-d`, never a main-ruleset load. A token
    /// pf no longer knows (after `pfctl -d`, a reboot) fails to release: that is a
    /// note, not a failed release -- the reference is not ours any more.
    [[nodiscard]] StepResult remove(OsPayload& os, Deadline& dl) override {
        detail::Exec ex(run_, dl);
        for (const auto& argv : {pfctl_flush_anchor_rules_argv(), pfctl_flush_anchor_nat_argv()}) {
            const auto r = ex.call(argv);
            if (!r)
                return StepResult::fail(ex.reason());
            if (!r->ok() && !anchor_gone(ex))
                return StepResult::fail("pf_anchor_flush_failed", detail::pf_error_line(r->output));
        }
        StepResult ok = StepResult::success();
        const bool had_token = !os.pf_token.empty();
        if (had_token) {
            const auto r = ex.call(pfctl_release_argv(os.pf_token));
            if (!r && ex.reason() == "deadline_exceeded")
                return StepResult::fail(ex.reason());
            if (!r || !r->ok())
                ok.notes.emplace_back("pf_token_release_failed=1");
            os.pf_token.clear();
            os.boot_time.clear();
        }
        if (!had_token)
            if (const auto info = ex.call(pfctl_info_argv()); info && info->ok() && pf_enabled(info->output))
                ok.notes.emplace_back("pf_left_enabled_no_token=1");
        if (const auto refs = ex.call(pfctl_references_argv()); refs && refs->ok())
            ok.notes.push_back(std::format("pf_references={}", parse_pf_references(refs->output).size()));
        return ok;
    }

    /// Enforcing needs ALL of: pf on, our anchor holding the closing block, the
    /// wildcard reference in the main ruleset, no sibling anchor sorting before ours.
    [[nodiscard]] LegStatus read_status(const OsPayload& os, Deadline& dl) override {
        LegStatus st;
        detail::Exec ex(run_, dl);
        const auto info = ex.call(pfctl_info_argv());
        if (!info || !info->ok())
            return st;
        const auto rules = ex.call(pfctl_rules_argv());
        if (!rules || !rules->ok())
            return st;
        // pfctl and sudo work (the two reads above), so a failure to read just our
        // anchor means the anchor does not exist -- after a reboot, say.
        const auto anchor = ex.call(pfctl_anchor_rules_argv());
        const bool anchor_read = anchor && anchor->ok();
        if (anchor && !anchor->ok())
            st.notes.emplace_back("pf_anchor_read_failed=1");
        const bool loaded = anchor_read && pf_anchor_enforcing(anchor->output);
        if (const auto refs = ex.call(pfctl_references_argv()); refs && refs->ok())
            st.notes.push_back(std::format("pf_references={}", parse_pf_references(refs->output).size()));
        bool sibling_first = false;
        if (const auto sib = ex.call(pfctl_siblings_argv()); sib && sib->ok())
            sibling_first = !pf_siblings_before(sib->output).empty();
        else
            st.notes.emplace_back("pf_siblings_unreadable=1");

        st.state = OsState::not_enforcing;
        if (!loaded) {
            st.reason = "policy_not_blocking";
        } else if (!pf_enabled(info->output)) {
            st.reason = "pf_disabled";
            if (!os.pf_token.empty())
                st.notes.emplace_back("pf_token_dead=1");
        } else if (!pf_anchor_referenced(rules->output)) {
            st.reason = "anchor_not_referenced";
            st.reapply_helps = false;
        } else if (sibling_first) {
            st.reason = "anchor_not_first";
            st.reapply_helps = false;
        } else {
            st.state = OsState::enforcing;
        }
        return st;
    }

private:
    /// A flush that failed is still a clean release when our anchor cannot be
    /// addressed at all (pf is readable, the anchor read fails) or holds no
    /// containment: there is nothing left to flush.
    [[nodiscard]] bool anchor_gone(detail::Exec& ex) {
        const auto info = ex.call(pfctl_info_argv());
        if (!info || !info->ok())
            return false;
        const auto a = ex.call(pfctl_anchor_rules_argv());
        if (!a)
            return false;
        return !a->ok() || !pf_anchor_enforcing(a->output);
    }

    Runner run_;
    Stage stage_;
    BootTime boot_;
};

// ── Drivers ─────────────────────────────────────────────────────────────────

struct Env {
    Leg& leg;
    StateStore& store;
    TcpProbe probe;
    std::function<std::int64_t()> epoch_now;
};

struct Outcome {
    std::string status;                 // active|active_unproven|partial|degraded|inactive|
                                        // rolled_back|update_failed|busy|refused
    std::string reason;
    std::vector<std::string> notes;     // "k=v"
    std::optional<std::string> verify;  // the verify| row, when verification ran
    std::optional<QuarantineState> state; // the effective record after the operation
    [[nodiscard]] int rc() const noexcept {
        return (status == "refused" || status == "rolled_back" || status == "update_failed" ||
                status == "busy")
                   ? 1
                   : 0;
    }
};

/// A refusal: nothing was touched.
[[nodiscard]] inline Outcome refused(std::string reason) {
    Outcome o;
    o.status = "refused";
    o.reason = std::move(reason);
    return o;
}

namespace detail {

/// Applied but not completely: the leg said so, or the record remembers rules
/// the policy store refused to disable.
[[nodiscard]] inline bool is_partial(const QuarantineState& st, const StepResult& ap) noexcept {
    return ap.partial || st.os.rules_not_disabled > 0;
}

[[nodiscard]] inline bool control_reachable(Env& env, const AllowSet& set, Deadline& dl) {
    int tried = 0;
    for (const auto& c : set.control) {
        if (tried++ >= 4 || dl.expired())
            break;
        if (env.probe(format_ip(c.ip), c.port, dl.cap(kProbeTimeout)) == ProbeOutcome::connected)
            return true;
    }
    return false;
}

struct VerifyResult {
    bool control_ok = false;
    std::optional<ProbeOutcome> before, after;
    VerifyOutcome outcome = VerifyOutcome::unproven;
    std::string row;
};

/// Control check plus (when a target is stored) the post-mutation probe, on a
/// verification budget of its own.
[[nodiscard]] inline VerifyResult run_verify(Env& env, const QuarantineState& st,
                                             std::optional<ProbeOutcome> before, Deadline& dl) {
    auto vdl = dl.fresh(kVerifyBudget);
    VerifyResult v;
    v.control_ok = control_reachable(env, st.allow, vdl);
    v.before = before;
    if (const auto t = parse_probe_target(st.probe_target))
        v.after = env.probe(format_ip(t->ip), t->port, vdl.cap(kProbeTimeout));
    v.outcome = decide_verify(v.control_ok, v.before, v.after);
    v.row = verify_row(v.control_ok, v.before, v.after);
    return v;
}

/// The record's `last_verify` text: tokens only (the serializer flattens `=` / `|`).
[[nodiscard]] inline std::string verify_text(const VerifyResult& v) {
    return std::format("{} control_{} probe_{}", to_string(v.outcome), v.control_ok ? "ok" : "fail",
                       probe_word(v.before, v.after));
}

inline void add_notes(Outcome& o, const std::vector<std::string>& n) {
    o.notes.insert(o.notes.end(), n.begin(), n.end());
}

/// Undo an initial apply. A removal that fails leaves the record `releasing`, so
/// the boot-time recovery finishes it on a fresh budget.
inline Outcome roll_back(Env& env, QuarantineState st, std::string reason, std::string det,
                         Deadline& dl, Outcome o) {
    auto cdl = dl.fresh(kOperationBudget);
    const auto rm = env.leg.remove(st.os, cdl);
    if (rm.ok) {
        if (!env.store.erase())
            o.notes.emplace_back("state_not_erased=1");
        o.state.reset();
    } else {
        st.phase = Phase::releasing;
        if (!env.store.save(st))
            o.notes.emplace_back("state_not_persisted=1");
        o.notes.emplace_back("rollback_incomplete=1");
        o.state = st;
    }
    o.status = "rolled_back";
    o.reason = std::move(reason);
    if (!det.empty())
        o.notes.push_back("detail=" + det);
    return o;
}

[[nodiscard]] inline Outcome converge(Env& env, QuarantineState prev, const AllowSet& next,
                                      Deadline& dl);

} // namespace detail

struct ApplyRequest {
    AllowSet allow;
    std::string probe_target; // "ip:port" | "[v6]:port" | empty
    std::int64_t ttl_seconds = 0;
};

/// `quarantine`. Order matters: validate, preflight, probe the target BEFORE
/// touching anything, write the `applying` record, only then mutate; verify; on
/// failure of an initial apply remove our own rules and the record.
[[nodiscard]] inline Outcome apply_and_verify(Env& env, const ApplyRequest& req, Deadline& dl) {
    std::optional<ProbeTarget> target;
    if (!req.probe_target.empty()) {
        auto t = parse_probe_target(req.probe_target);
        if (!t)
            return refused(t.error());
        target = *t;
    }
    if (req.allow.control.empty())
        return refused("control_set_empty");
    if (req.ttl_seconds != 0 && !validate_ttl(req.ttl_seconds))
        return refused("ttl_out_of_bounds");

    const auto loaded = env.store.load();
    if (loaded.kind == StateLoad::Kind::unreadable)
        return refused("state_unreadable");
    if (loaded.kind == StateLoad::Kind::ok) {
        const auto& cur = loaded.state;
        if (cur.phase == Phase::releasing)
            return refused("release_in_progress");
        if (cur.phase == Phase::active) {
            // An `active` record is only true while the OS still enforces it: another
            // actor may have undone it (pf switched off, a table deleted, profile
            // defaults restored). Re-apply the STORED allow set -- a retry never
            // rewrites a contained host's allow list -- instead of answering
            // `already_active`. A read that fails changes nothing; a defect a
            // re-apply cannot fix (a dangling anchor, an earlier sibling) is
            // reported, not re-applied on every retry.
            const auto ls = env.leg.read_status(cur.os, dl);
            Outcome o;
            if (ls.state == OsState::not_enforcing && ls.reapply_helps) {
                o = detail::converge(env, cur, cur.allow, dl);
                o.notes.emplace_back("repaired=1");
            } else if (ls.state == OsState::not_enforcing) {
                o.status = "degraded";
                o.reason = ls.reason;
                o.state = cur;
            } else {
                o.status = "active";
                o.state = cur;
                o.notes.emplace_back("already_active=1");
            }
            if (!(cur.allow == req.allow))
                o.notes.emplace_back("allow_set_unchanged_use_quarantine_allow=1");
            return o;
        }
        // An earlier apply never finished: converge to the requested set.
        auto o = detail::converge(env, cur, req.allow, dl);
        o.notes.emplace_back("incomplete_apply_converged=1");
        return o;
    }

    if (auto why = env.leg.preflight(dl))
        return refused(*why);

    std::optional<ProbeOutcome> before;
    if (target) {
        before = env.probe(format_ip(target->ip), target->port, dl.cap(kProbeTimeout));
        if (*before == ProbeOutcome::timeout)
            return refused("probe_unreachable_before_apply");
    }

    QuarantineState st;
    st.phase = Phase::applying;
    st.generation = 1;
    st.applied_at = env.epoch_now();
    st.ttl_expires = req.ttl_seconds > 0 ? st.applied_at + req.ttl_seconds : 0;
    st.probe_target = target ? target->text() : std::string{};
    st.backend = env.leg.kind();
    st.allow = req.allow;
    // No OS mutation without a recovery record.
    if (!env.store.save(st))
        return refused("state_not_persisted");

    Outcome o;
    o.state = st;
    const PersistOs persist = [&](const OsPayload& os) {
        auto t = st;
        t.os = os;
        return env.store.save(t);
    };
    const auto ap = env.leg.apply(st.allow, st.generation, 0, st.os, dl, persist);
    if (!ap.ok)
        return detail::roll_back(env, st, "apply_failed:" + ap.reason, ap.detail, dl, std::move(o));
    detail::add_notes(o, ap.notes);

    const auto v = detail::run_verify(env, st, before, dl);
    o.verify = v.row;
    if (verify_action(v.outcome, VerifyMode::initial) == VerifyAction::rollback_to_absence)
        return detail::roll_back(env, st, std::string{to_string(v.outcome)}, {}, dl, std::move(o));

    st.phase = Phase::active;
    st.last_verify = detail::verify_text(v);
    o.status = detail::is_partial(st, ap) ? "partial"
               : (v.outcome == VerifyOutcome::verified ? "active" : "active_unproven");
    if (!env.store.save(st)) {
        // Contained but the record still says `applying`: boot recovery re-applies.
        o.status = "partial";
        o.notes.emplace_back("state_not_persisted=1");
    }
    o.state = st;
    return o;
}

namespace detail {

/// Move from `prev` (active, or an incomplete `applying`) to `next` as a new
/// generation: the previous generation stays effective until the new one has
/// committed and verified; a failure removes only what the update added.
[[nodiscard]] inline Outcome converge(Env& env, QuarantineState prev, const AllowSet& next,
                                      Deadline& dl) {
    Outcome o;
    QuarantineState cand = prev;
    cand.phase = Phase::applying;
    cand.prev_generation = prev.phase == Phase::active ? prev.generation : prev.prev_generation;
    cand.generation = prev.generation + 1;
    cand.allow = next;
    if (!env.store.save(cand))
        return refused("state_not_persisted");

    const PersistOs persist = [&](const OsPayload& os) {
        auto t = cand;
        t.os = os;
        return env.store.save(t);
    };
    const auto ap = env.leg.apply(cand.allow, cand.generation, cand.prev_generation, cand.os, dl,
                                  persist);
    if (!ap.ok) {
        // The previous generation is still in force: put its record back. The leg's
        // OS facts are carried over: a pf enable token taken before the failure is
        // held by the host, and the record is the only way to release it.
        auto back = prev;
        back.os = cand.os;
        if (!env.store.save(back))
            o.notes.emplace_back("state_restore_failed=1");
        if (!ap.detail.empty())
            o.notes.push_back("detail=" + ap.detail);
        o.status = "update_failed";
        o.reason = ap.reason;
        o.state = back;
        return o;
    }
    add_notes(o, ap.notes);

    // The probe target was proven reachable when the quarantine was first
    // applied, so the "before" side of an update is a reachable placeholder.
    std::optional<ProbeOutcome> before;
    if (!cand.probe_target.empty())
        before = ProbeOutcome::connected;
    const auto v = run_verify(env, cand, before, dl);
    o.verify = v.row;
    if (verify_action(v.outcome, VerifyMode::update) == VerifyAction::revert_to_previous) {
        QuarantineState back = cand;
        back.generation = cand.generation + 1;
        back.prev_generation = cand.generation;
        back.allow = prev.allow;
        const auto rv = env.leg.apply(back.allow, back.generation, back.prev_generation, back.os,
                                      dl, [&](const OsPayload& os) {
                                          auto t = back;
                                          t.os = os;
                                          return env.store.save(t);
                                      });
        o.status = "update_failed";
        if (rv.ok) {
            back.phase = Phase::active;
            if (!env.store.save(back))
                o.notes.emplace_back("state_restore_failed=1");
            o.reason = std::string{to_string(v.outcome)};
            o.state = back;
        } else {
            // The failed generation is what is in force; its record stays
            // `applying` so boot recovery retries.
            o.reason = "revert_failed:" + rv.reason;
            o.state = cand;
        }
        return o;
    }

    cand.phase = Phase::active;
    cand.last_verify = verify_text(v);
    o.status = is_partial(cand, ap) ? "partial"
               : (v.outcome == VerifyOutcome::verified ? "active" : "active_unproven");
    if (!env.store.save(cand)) {
        o.status = "partial";
        o.notes.emplace_back("state_not_persisted=1");
    }
    o.state = cand;
    return o;
}

} // namespace detail

/// `quarantine_allow`. The cap is cumulative; a mandatory allowance is never
/// removed; an unchanged set is a no-op (no mutation, no new generation).
[[nodiscard]] inline Outcome update(Env& env, bool add, const std::vector<Endpoint>& exceptions,
                                    Deadline& dl) {
    const auto loaded = env.store.load();
    if (loaded.kind == StateLoad::Kind::unreadable)
        return refused("state_unreadable");
    if (loaded.kind == StateLoad::Kind::absent || loaded.state.phase != Phase::active)
        return refused("not_active");
    const auto& cur = loaded.state;

    AllowSet next;
    int changed = 0;
    if (add) {
        auto r = add_exceptions(cur.allow, exceptions);
        if (!r)
            return refused(r.error());
        changed = static_cast<int>(r->exceptions.size()) -
                  static_cast<int>(cur.allow.exceptions.size());
        next = std::move(*r);
    } else {
        auto r = remove_exceptions(cur.allow, exceptions);
        if (!r)
            return refused(r.error());
        changed = r->removed;
        next = std::move(r->set);
    }
    if (changed == 0) {
        Outcome o;
        o.status = cur.last_verify.find("unproven") != std::string::npos ? "active_unproven"
                                                                         : "active";
        o.state = cur;
        o.notes.emplace_back("exceptions_unchanged=1");
        return o;
    }
    return detail::converge(env, cur, next, dl);
}

struct ReleaseRequest {
    bool if_ttl_expired = false;
};

/// `release`. Lifting containment is the safe direction, so it is never blocked
/// by a state-write failure or a damaged record: the OS is cleaned regardless.
[[nodiscard]] inline Outcome release(Env& env, const ReleaseRequest& req, Deadline& dl) {
    Outcome o;
    const auto loaded = env.store.load();
    if (req.if_ttl_expired) {
        if (loaded.kind != StateLoad::Kind::ok) {
            o.status = loaded.kind == StateLoad::Kind::unreadable ? "degraded" : "inactive";
            if (loaded.kind == StateLoad::Kind::unreadable)
                o.reason = "state_unreadable";
            return o;
        }
        if (!ttl_expired(loaded.state, env.epoch_now())) {
            o.status = loaded.state.phase == Phase::active ? "active" : "partial";
            o.state = loaded.state;
            o.notes.emplace_back("ttl_not_expired=1");
            return o;
        }
    }
    OsPayload os;
    if (loaded.kind == StateLoad::Kind::ok) {
        auto st = loaded.state;
        os = st.os;
        st.phase = Phase::releasing;
        if (!env.store.save(st))
            o.notes.emplace_back("state_not_persisted=1");
        o.state = st;
    } else if (loaded.kind == StateLoad::Kind::unreadable) {
        o.notes.emplace_back("state_unreadable=1");
    } else {
        o.notes.emplace_back("no_state_record=1");
    }
    const auto rm = env.leg.remove(os, dl);
    if (!rm.ok) {
        o.status = "partial";
        o.reason = "release_failed:" + rm.reason;
        if (!rm.detail.empty())
            o.notes.push_back("detail=" + rm.detail);
        return o;
    }
    detail::add_notes(o, rm.notes);
    if (loaded.kind != StateLoad::Kind::absent && !env.store.erase()) {
        o.notes.emplace_back("state_not_erased=1");
        o.status = "partial";
        o.reason = "state_not_erased";
        return o;
    }
    o.status = "inactive";
    o.state.reset();
    return o;
}

/// Agent start (init(): after the KV store opens, before Register). Completes an
/// interrupted release; re-applies an `applying`/`active` record as a generation
/// update when the OS is not enforcing it (a reboot, a legacy release). It never
/// rolls back and never releases: an unreachable server at boot must not lift
/// containment.
[[nodiscard]] inline Outcome recover_at_init(Env& env, Deadline& dl) {
    Outcome o;
    const auto loaded = env.store.load();
    if (loaded.kind == StateLoad::Kind::absent) {
        o.status = "inactive";
        o.notes.emplace_back("nothing_to_recover=1");
        return o;
    }
    if (loaded.kind == StateLoad::Kind::unreadable) {
        o.status = "degraded";
        o.reason = "state_unreadable";
        return o;
    }
    auto st = loaded.state;
    if (st.phase == Phase::releasing)
        return release(env, ReleaseRequest{}, dl);

    const auto ls = env.leg.read_status(st.os, dl);
    const bool enforcing = ls.state == OsState::enforcing;
    StepResult ap = StepResult::success();
    if (!(st.phase == Phase::active && enforcing)) {
        // A record exists, so mutating is permitted; a failed write is a note.
        QuarantineState cand = st;
        cand.phase = Phase::applying;
        cand.prev_generation = st.phase == Phase::active ? st.generation : st.prev_generation;
        cand.generation = st.generation + 1;
        if (!env.store.save(cand))
            o.notes.emplace_back("state_not_persisted=1");
        ap = env.leg.apply(cand.allow, cand.generation, cand.prev_generation, cand.os, dl,
                           [&](const OsPayload& os) {
                               auto t = cand;
                               t.os = os;
                               return env.store.save(t);
                           });
        if (!ap.ok) {
            o.status = "degraded";
            o.reason = "reapply_failed:" + ap.reason;
            o.state = cand;
            return o;
        }
        st = cand;
        o.notes.emplace_back("reapplied=1");
    }
    detail::add_notes(o, ap.notes);

    // Informational only: record what the probe saw; never act on it.
    std::optional<ProbeOutcome> before;
    if (!st.probe_target.empty())
        before = ProbeOutcome::connected;
    const auto v = detail::run_verify(env, st, before, dl);
    o.verify = v.row;
    st.phase = Phase::active;
    st.last_verify = detail::verify_text(v);
    o.status = detail::is_partial(st, ap) ? "partial"
               : (v.outcome == VerifyOutcome::verified ? "active" : "active_unproven");
    if (!env.store.save(st))
        o.notes.emplace_back("state_not_persisted=1");
    o.state = st;
    return o;
}

// ── TTL enforcement ─────────────────────────────────────────────────────────

/// The agent's trigger engine as the core sees it; the plugin implements it over
/// its PluginContext. Two methods, each a plain success flag.
class TriggerRegistry {
public:
    virtual ~TriggerRegistry() = default;
    [[nodiscard]] virtual bool register_trigger(std::string_view id, std::string_view type,
                                                std::string_view config_json) = 0;
    [[nodiscard]] virtual bool unregister_trigger(std::string_view id) = 0;
};

inline constexpr std::string_view kTtlTriggerType = "interval";

/// The trigger's config: every `kTtlPollSeconds` the agent dispatches
/// `firewall.release` with `if_ttl_expired=1`, a no-op until the record's TTL has
/// passed. The shape agents/core's parse_trigger_config accepts.
[[nodiscard]] inline std::string ttl_trigger_config() {
    return std::format(
        R"({{"interval_seconds":{},"plugin":"firewall","action":"release","parameters":{{"if_ttl_expired":"1"}}}})",
        kTtlPollSeconds);
}

/// A TTL is enforced by that interval trigger. Any outcome that leaves a record
/// with a TTL behind keeps the trigger registered (a failed boot-time re-apply
/// included: the TTL still bounds the quarantine, and the expiry release works on
/// a record in any phase); a completed release removes it. A failed registration
/// keeps the quarantine (lifting containment is never the safe response to a
/// bookkeeping failure) and says so: PARTIAL, retried at the next start.
inline void settle_ttl(Outcome& o, TriggerRegistry& triggers) {
    if (o.state && o.state->ttl_expires > 0 && o.status != "inactive") {
        if (!triggers.register_trigger(kTtlTriggerId, kTtlTriggerType, ttl_trigger_config())) {
            o.notes.emplace_back("ttl_trigger_unregistered=1");
            if (o.status == "active" || o.status == "active_unproven")
                o.status = "partial";
        }
    } else if (o.status == "inactive") {
        (void)triggers.unregister_trigger(kTtlTriggerId);
    }
}

/// `quarantine_status`: record x live OS. Never mutates, never takes the gate.
[[nodiscard]] inline Outcome report_status(Env& env, Deadline& dl) {
    Outcome o;
    const auto loaded = env.store.load();
    const auto ls = env.leg.read_status(
        loaded.kind == StateLoad::Kind::ok ? loaded.state.os : OsPayload{}, dl);
    detail::add_notes(o, ls.notes);
    if (loaded.kind == StateLoad::Kind::unreadable) {
        o.status = "degraded";
        o.reason = "state_unreadable";
        return o;
    }
    if (loaded.kind == StateLoad::Kind::absent) {
        if (ls.state == OsState::enforcing) {
            o.status = "degraded";
            o.reason = "state_missing_rules_present";
        } else {
            o.status = ls.state == OsState::unreadable ? "degraded" : "inactive";
            if (ls.state == OsState::unreadable)
                o.reason = "os_unreadable";
        }
        return o;
    }
    const auto& st = loaded.state;
    o.state = st;
    if (st.phase == Phase::applying) {
        o.status = "partial";
        o.reason = "operation_in_progress";
        return o;
    }
    if (st.phase == Phase::releasing) {
        o.status = "partial";
        o.reason = "release_incomplete";
        return o;
    }
    if (ls.state == OsState::unreadable) {
        o.status = "degraded";
        o.reason = "os_unreadable";
    } else if (ls.state == OsState::not_enforcing) {
        o.status = "degraded";
        o.reason = ls.reason.empty() ? "policy_not_blocking" : ls.reason;
    } else if (ls.partial || st.os.rules_not_disabled > 0) {
        o.status = "partial";
        o.reason = st.os.rules_not_disabled > 0 ? "rules_not_disabled" : ls.reason;
        if (st.os.rules_not_disabled > 0)
            o.notes.push_back(std::format("rules_not_disabled={}", st.os.rules_not_disabled));
    } else {
        o.status = st.last_verify.find("unproven") != std::string::npos ? "active_unproven"
                                                                        : "active";
    }
    return o;
}

// ── Output rows and result status ───────────────────────────────────────────

/// `status|<token>[|<reason>]`, an extra `refused|` / `rolled_back|` row for the
/// two outcomes callers key on, the verify row, the allow set and the facts an
/// operator audits (backend, generation, ttl, probe target).
[[nodiscard]] inline std::vector<std::string> render_rows(const Outcome& o) {
    std::vector<std::string> rows;
    rows.push_back(o.reason.empty() ? std::format("status|{}", o.status)
                                    : std::format("status|{}|{}", o.status, o.reason));
    if ((o.status == "refused" || o.status == "rolled_back") && !o.reason.empty())
        rows.push_back(std::format("{}|{}", o.status, o.reason));
    if (o.verify)
        rows.push_back(*o.verify);
    if (o.state) {
        const auto& s = *o.state;
        rows.push_back(std::format("note|backend={}", to_string(s.backend)));
        rows.push_back(std::format("note|generation={}", s.generation));
        if (s.ttl_expires > 0)
            rows.push_back(std::format("note|ttl_expires={}", s.ttl_expires));
        if (!s.probe_target.empty())
            rows.push_back(std::format("note|probe_target={}", s.probe_target));
        rows.emplace_back("allow|loopback|lo");
        for (const auto& c : s.allow.control)
            rows.push_back(std::format("allow|control|{}", canonical(c)));
        rows.emplace_back("allow|dhcp|udp/67-68");
        for (const auto& r : s.allow.resolvers)
            rows.push_back(std::format("allow|resolver|{}", format_ip(r)));
        rows.emplace_back("allow|nd|icmpv6/133-136");
        for (const auto& e : s.allow.exceptions)
            rows.push_back(std::format("allow|exception|{}", canonical(e)));
    }
    for (const auto& n : o.notes)
        rows.push_back("note|" + n);
    return rows;
}

struct ResultKind {
    enum class Kind : std::uint8_t { ok, unavailable, constrained } kind = Kind::ok;
    bool partial = false;
    std::string provenance; // firewall:<token>
};

[[nodiscard]] inline ResultKind result_kind(const Outcome& o) {
    ResultKind r;
    r.provenance = "firewall:" + o.status;
    if (o.status == "active" || o.status == "inactive") {
        r.kind = ResultKind::Kind::ok;
    } else if (o.status == "active_unproven") {
        r.kind = ResultKind::Kind::ok;
        r.partial = true;
    } else if (o.status == "partial" || o.status == "degraded") {
        r.kind = ResultKind::Kind::constrained;
        r.partial = true;
    } else {
        r.kind = ResultKind::Kind::unavailable;
        r.partial = true;
    }
    return r;
}

} // namespace yuzu::firewall::quarantine
