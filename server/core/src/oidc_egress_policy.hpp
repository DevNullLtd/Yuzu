#pragma once

// OIDC egress policy (#5692): which destination ADDRESSES the server may connect to when it
// fetches an OIDC discovery document, a JWKS or posts to a token endpoint.
//
// PURE decision code: no I/O, no resolver, no sockets. The caller (oidc_provider.cpp) resolves a
// host name, hands every resolved address here, and connects only to one this policy allows. The
// classification is on the ADDRESS BYTES, never on the host text, because a name or a numeric
// spelling (`127.1`, `0x7f.1`, a hostname with an A record of 10.0.0.5) says nothing about where a
// connect will land.
//
// Two tiers:
//   - ALWAYS refused (no switch): unspecified (0.0.0.0/8, ::), link-local (169.254.0.0/16,
//     fe80::/10 - the cloud metadata address 169.254.169.254 lives here), the other well-known
//     cloud metadata addresses, multicast, and the reserved/broadcast block 240.0.0.0/4.
//   - Refused UNLESS the process operator sets `--oidc-allow-private-networks`: loopback,
//     RFC 1918, carrier-grade NAT (100.64.0.0/10), IPv6 unique-local (fc00::/7) and every other
//     non-global unicast block (documentation, benchmarking, IETF protocol assignments, anything
//     outside 2000::/3 for IPv6; inside it the non-global parts of 2001::/23, which holds Teredo
//     and IPv6 benchmarking, except the sub-ranges the IANA registry marks globally reachable).
// An IPv6 address that embeds an IPv4 address (IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96, 6to4
// 2002::/16) is classified by the embedded IPv4 address, so `::ffff:169.254.169.254` is
// link-local, not "public IPv6". A public embedded address stays public.
//
// Third rule, on the TRANSPORT rather than the address: plain http (`cleartext`) to a PUBLIC
// address is refused outright, with no switch. That is the realistic internet man-in-the-middle
// case (anyone on the path forges the discovery document, the JWKS or the token response); https
// to a public address is unchanged. Plain http to a loopback/private/carrier-grade-NAT/unique-local
// address stays governed by `--oidc-allow-private-networks` alone, and stays exposed to anyone on
// that network path.
//
// NAT64 with a NETWORK-SPECIFIC prefix (RFC 6052 section 2.2: /32, /40, /48, /56, /64 or /96): an
// address inside a prefix the caller KNOWS is classified by the IPv4 address embedded in it, so
// `Pref64 + 169.254.169.254` is link-local and not "public IPv6". The caller learns prefixes from
// the operator (`--oidc-nat64-prefix`) and from RFC 7050 (`discover_prefix_from_ipv4only_answer`);
// this header stays pure and only decodes. A prefix never relaxes an address that is already in
// the never-allowed tier. A CONFIGURED prefix is trusted to describe a translator: it is an
// operator assertion, so it may permit a destination its own address class (say unique-local
// fc00::/7 for a private-network NAT64) would otherwise gate; only the always-refused tier is
// immutable.
//
// KNOWN LIMIT: the classification is of the address AS THE SERVER SEES IT, plus the prefixes it
// learned. It cannot know a translator whose prefix is neither discoverable nor configured, nor a
// proxy, a VPN or CLAT/464XLAT outside the host, so an address in 2000::/3 that such a path maps
// to a private IPv4 destination classifies as Public. Plain http to it is refused by the cleartext
// rule; https to it is limited to a blind TCP connect, because TLS verification still uses the
// host name.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::oidc::egress {

enum class AddressClass : std::uint8_t {
    Public,
    // Refused unless the operator allows private networks.
    Loopback,
    Private,         // RFC 1918
    CarrierGradeNat, // 100.64.0.0/10
    UniqueLocal,     // fc00::/7
    OtherNonGlobal,  // documentation, benchmarking, IETF protocol assignments, non-2000::/3 ...
    // Never allowed.
    Unspecified,
    LinkLocal,
    CloudMetadata,
    Multicast,
    Reserved, // 240.0.0.0/4 including the limited broadcast address
};

using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;

namespace detail {

constexpr std::uint32_t pack(const Ipv4& a) {
    return (std::uint32_t{a[0]} << 24) | (std::uint32_t{a[1]} << 16) | (std::uint32_t{a[2]} << 8) |
           std::uint32_t{a[3]};
}

// True when `a` is inside `net`/`prefix_bits`.
constexpr bool in_cidr(const Ipv4& a, const Ipv4& net, int prefix_bits) {
    const std::uint32_t mask = prefix_bits == 0 ? 0u : (~std::uint32_t{0} << (32 - prefix_bits));
    return (pack(a) & mask) == (pack(net) & mask);
}

/// The "never allowed" tier: no operator switch opens it.
constexpr bool never_allowed(AddressClass c) {
    switch (c) {
    case AddressClass::Unspecified:
    case AddressClass::LinkLocal:
    case AddressClass::CloudMetadata:
    case AddressClass::Multicast:
    case AddressClass::Reserved:
        return true;
    default:
        return false;
    }
}

} // namespace detail

/// Classify an IPv4 address given in network byte order.
constexpr AddressClass classify_ipv4(const Ipv4& a) {
    // Single addresses first: they sit inside blocks that are otherwise merely private or public.
    if (a == Ipv4{100, 100, 100, 200}) // Alibaba Cloud metadata (inside 100.64.0.0/10)
        return AddressClass::CloudMetadata;
    if (a == Ipv4{168, 63, 129, 16}) // Azure platform endpoint (WireServer; otherwise "public")
        return AddressClass::CloudMetadata;
    if (a[0] == 0) // 0.0.0.0/8 "this network"; Linux connects 0.0.0.0 to the local host
        return AddressClass::Unspecified;
    if (a[0] == 127)
        return AddressClass::Loopback;
    if (a[0] == 10 || detail::in_cidr(a, {172, 16, 0, 0}, 12) ||
        detail::in_cidr(a, {192, 168, 0, 0}, 16))
        return AddressClass::Private;
    if (detail::in_cidr(a, {100, 64, 0, 0}, 10))
        return AddressClass::CarrierGradeNat;
    if (a[0] == 169 && a[1] == 254) // 169.254.0.0/16, includes 169.254.169.254
        return AddressClass::LinkLocal;
    if (a[0] >= 224 && a[0] <= 239)
        return AddressClass::Multicast;
    if (a[0] >= 240) // 240.0.0.0/4 reserved, includes 255.255.255.255
        return AddressClass::Reserved;
    // IETF protocol assignments, documentation (TEST-NET-1/2/3) and benchmarking: not global.
    if (detail::in_cidr(a, {192, 0, 0, 0}, 24) || detail::in_cidr(a, {192, 0, 2, 0}, 24) ||
        detail::in_cidr(a, {198, 18, 0, 0}, 15) || detail::in_cidr(a, {198, 51, 100, 0}, 24) ||
        detail::in_cidr(a, {203, 0, 113, 0}, 24))
        return AddressClass::OtherNonGlobal;
    return AddressClass::Public;
}

/// Classify an IPv6 address given in network byte order.
constexpr AddressClass classify_ipv6(const Ipv6& a) {
    const auto zeros = [&a](std::size_t from, std::size_t to) { // a[from, to) are all zero
        for (std::size_t i = from; i < to; ++i)
            if (a[i] != 0)
                return false;
        return true;
    };
    const auto embedded = [&a](std::size_t at) {
        return Ipv4{a[at], a[at + 1], a[at + 2], a[at + 3]};
    };

    if (zeros(0, 15) && a[15] == 0)
        return AddressClass::Unspecified;
    if (zeros(0, 15) && a[15] == 1)
        return AddressClass::Loopback;
    // ::ffff:0:0/96 IPv4-mapped: the embedded IPv4 address is where the connect lands.
    if (zeros(0, 10) && a[10] == 0xff && a[11] == 0xff)
        return classify_ipv4(embedded(12));
    // 64:ff9b::/96 NAT64 well-known prefix: a translator forwards to the embedded IPv4 address.
    if (a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xff && a[3] == 0x9b && zeros(4, 12))
        return classify_ipv4(embedded(12));
    // The rest of ::/8 (IPv4-compatible, reserved): never global unicast.
    if (a[0] == 0)
        return AddressClass::OtherNonGlobal;
    // fe80::/10 link-local.
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
        return AddressClass::LinkLocal;
    // fec0::/10 site-local (deprecated).
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0xc0)
        return AddressClass::OtherNonGlobal;
    // ff00::/8 multicast.
    if (a[0] == 0xff)
        return AddressClass::Multicast;
    // fc00::/7 unique-local, except the AWS IPv6 metadata address fd00:ec2::254.
    if ((a[0] & 0xfe) == 0xfc) {
        const bool aws_metadata = a[0] == 0xfd && a[1] == 0x00 && a[2] == 0x0e && a[3] == 0xc2 &&
                                  zeros(4, 14) && a[14] == 0x02 && a[15] == 0x54;
        return aws_metadata ? AddressClass::CloudMetadata : AddressClass::UniqueLocal;
    }
    // Anything outside 2000::/3 is not global unicast.
    if ((a[0] & 0xe0) != 0x20)
        return AddressClass::OtherNonGlobal;
    // 2002::/16 6to4: the embedded IPv4 address (bytes 2..5) is the tunnel endpoint.
    if (a[0] == 0x20 && a[1] == 0x02)
        return classify_ipv4(embedded(2));
    // 2001:db8::/32 documentation and 3fff::/20 documentation (RFC 9637).
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8)
        return AddressClass::OtherNonGlobal;
    if (a[0] == 0x3f && a[1] == 0xff && (a[2] & 0xf0) == 0x00)
        return AddressClass::OtherNonGlobal;
    // 2001::/23 IETF protocol assignments (IANA IPv6 Special-Purpose Address Registry, RFC 6890 /
    // RFC 8190): not globally reachable as a block - it holds Teredo 2001::/32, benchmarking
    // 2001:2::/48 and ORCHID 2001:10::/28 - EXCEPT the sub-ranges the registry marks globally
    // reachable, which stay Public: 2001:1::1, 2001:1::2 and 2001:1::3 (single addresses),
    // 2001:3::/32 AMT, 2001:4:112::/48 AS112-v6, 2001:20::/28 ORCHIDv2 and 2001:30::/28 drone
    // remote ID. Every other address in the block (unallocated, Teredo, benchmarking, ORCHID) is
    // refused: a range the registry does not positively mark globally reachable fails closed.
    if (a[0] == 0x20 && a[1] == 0x01 && (a[2] & 0xfe) == 0x00) {
        const bool service_anycast =
            a[2] == 0x00 && a[3] == 0x01 && zeros(4, 15) && a[15] >= 1 && a[15] <= 3;
        const bool amt = a[2] == 0x00 && a[3] == 0x03;
        const bool as112 = a[2] == 0x00 && a[3] == 0x04 && a[4] == 0x01 && a[5] == 0x12;
        const bool orchid_v2_or_det =
            a[2] == 0x00 && ((a[3] & 0xf0) == 0x20 || (a[3] & 0xf0) == 0x30);
        return (service_anycast || amt || as112 || orchid_v2_or_det) ? AddressClass::Public
                                                                     : AddressClass::OtherNonGlobal;
    }
    return AddressClass::Public;
}

/// Strict dotted-quad IPv4: four decimal octets 0..255, no leading zeros (the OS resolver reads
/// "010" as octal), nothing else. Anything this refuses is NOT assumed to be a name: the caller
/// hands it to the resolver and classifies the address the resolver returns.
constexpr std::optional<Ipv4> parse_ipv4(std::string_view s) {
    Ipv4 out{};
    std::size_t octets = 0;
    std::size_t i = 0;
    while (true) {
        if (octets == 4)
            return std::nullopt;
        const std::size_t start = i;
        unsigned value = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9' && i - start < 4) {
            value = value * 10 + static_cast<unsigned>(s[i] - '0');
            ++i;
        }
        const std::size_t len = i - start;
        if (len == 0 || len > 3 || value > 255 || (len > 1 && s[start] == '0'))
            return std::nullopt;
        out[octets++] = static_cast<std::uint8_t>(value);
        if (i == s.size())
            break;
        if (s[i] != '.')
            return std::nullopt;
        ++i;
    }
    return octets == 4 ? std::optional<Ipv4>(out) : std::nullopt;
}

/// IPv6 text without brackets and without a zone id: up to eight 1..4 digit hex groups, at most
/// one "::", and an optional trailing dotted-quad IPv4 in the last 32 bits.
constexpr std::optional<Ipv6> parse_ipv6(std::string_view s) {
    std::array<std::uint16_t, 8> words{};
    std::size_t n = 0;
    int gap = -1; // index in `words` where "::" sits
    std::size_t i = 0;
    if (s.empty())
        return std::nullopt;
    if (s.starts_with("::")) {
        gap = 0;
        i = 2;
    } else if (s[0] == ':') {
        return std::nullopt;
    }
    while (i < s.size()) {
        const std::size_t start = i;
        while (i < s.size() && s[i] != ':')
            ++i;
        const std::string_view token = s.substr(start, i - start);
        if (token.empty())
            return std::nullopt;
        if (token.find('.') != std::string_view::npos) { // IPv4 tail: must be the last token
            if (i != s.size() || n + 2 > 8)
                return std::nullopt;
            const auto v4 = parse_ipv4(token);
            if (!v4)
                return std::nullopt;
            words[n++] = static_cast<std::uint16_t>((unsigned{(*v4)[0]} << 8) | (*v4)[1]);
            words[n++] = static_cast<std::uint16_t>((unsigned{(*v4)[2]} << 8) | (*v4)[3]);
            break;
        }
        if (token.size() > 4 || n == 8)
            return std::nullopt;
        unsigned value = 0;
        for (const char c : token) {
            unsigned digit = 0;
            if (c >= '0' && c <= '9')
                digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = static_cast<unsigned>(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F')
                digit = static_cast<unsigned>(c - 'A') + 10;
            else
                return std::nullopt;
            value = value * 16 + digit;
        }
        words[n++] = static_cast<std::uint16_t>(value);
        if (i == s.size())
            break;
        ++i; // the ':' after the group
        if (i < s.size() && s[i] == ':') {
            if (gap >= 0)
                return std::nullopt;
            gap = static_cast<int>(n);
            ++i;
        } else if (i == s.size()) {
            return std::nullopt; // a single trailing ':'
        }
    }
    if (gap < 0 ? n != 8 : n >= 8)
        return std::nullopt;
    std::array<std::uint16_t, 8> full{};
    const std::size_t head = gap < 0 ? n : static_cast<std::size_t>(gap);
    for (std::size_t k = 0; k < head; ++k)
        full[k] = words[k];
    if (gap >= 0)
        for (std::size_t k = head; k < n; ++k)
            full[8 - (n - k)] = words[k];
    Ipv6 out{};
    for (std::size_t k = 0; k < 8; ++k) {
        out[2 * k] = static_cast<std::uint8_t>(full[k] >> 8);
        out[2 * k + 1] = static_cast<std::uint8_t>(full[k] & 0xff);
    }
    return out;
}

// ── NAT64 network-specific prefixes (RFC 6052 section 2.2, RFC 7050) ─────────────────────────

/// A NAT64 prefix: the first `length` bits of `bytes`. `length` is one of 32, 40, 48, 56, 64, 96;
/// any other value matches nothing and embeds nothing.
struct Nat64Prefix {
    Ipv6 bytes{};
    int length{96};
    constexpr bool operator==(const Nat64Prefix&) const = default;
};

constexpr bool nat64_length_valid(int length) {
    return length == 32 || length == 40 || length == 48 || length == 56 || length == 64 ||
           length == 96;
}

/// True when the first `p.length` bits of `a` equal those of `p.bytes`.
constexpr bool matches(const Ipv6& a, const Nat64Prefix& p) {
    if (!nat64_length_valid(p.length))
        return false;
    for (std::size_t i = 0; i < static_cast<std::size_t>(p.length) / 8; ++i)
        if (a[i] != p.bytes[i])
            return false;
    return true;
}

/// The IPv4 address embedded in `a` under prefix `p`, nullopt when `a` is outside `p`. RFC 6052
/// section 2.2, figure 1, as byte offsets into the address: the IPv4 octets are contiguous only
/// for /32 and /96; for /40, /48 and /56 they straddle the reserved "u" octet (byte 8, bits 64..71,
/// always skipped), and /64 starts right after it. The u octet and the suffix are not inspected:
/// a receiver ignores them.
///   /32: bytes 4 5 6 7     /40: bytes 5 6 7 9     /48: bytes 6 7 9 10
///   /56: bytes 7 9 10 11   /64: bytes 9 10 11 12  /96: bytes 12 13 14 15
constexpr std::optional<Ipv4> embedded_ipv4(const Ipv6& a, const Nat64Prefix& p) {
    if (!matches(a, p))
        return std::nullopt;
    const auto at = [&a](std::size_t i0, std::size_t i1, std::size_t i2, std::size_t i3) {
        return Ipv4{a[i0], a[i1], a[i2], a[i3]};
    };
    switch (p.length) {
    case 32:
        return at(4, 5, 6, 7);
    case 40:
        return at(5, 6, 7, 9);
    case 48:
        return at(6, 7, 9, 10);
    case 56:
        return at(7, 9, 10, 11);
    case 64:
        return at(9, 10, 11, 12);
    case 96:
        return at(12, 13, 14, 15);
    default:
        return std::nullopt;
    }
}

/// Classify an IPv6 address, also decoding the NAT64 prefixes in `extra`: an address inside one is
/// classified by the IPv4 address embedded in it. A prefix never relaxes an address the built-in
/// rules already put in the never-allowed tier, and when several prefixes match the strictest
/// embedded class wins (never-allowed, then any non-public class, then public).
constexpr AddressClass classify_ipv6(const Ipv6& a, std::span<const Nat64Prefix> extra) {
    const AddressClass base = classify_ipv6(a);
    if (detail::never_allowed(base))
        return base;
    const auto rank = [](AddressClass c) {
        return detail::never_allowed(c) ? 2 : (c == AddressClass::Public ? 0 : 1);
    };
    std::optional<AddressClass> best;
    for (const auto& p : extra)
        if (const auto v4 = embedded_ipv4(a, p)) {
            const AddressClass c = classify_ipv4(*v4);
            if (!best || rank(c) > rank(*best))
                best = c;
        }
    return best ? *best : base;
}

/// "2001:db8:122:344::/64": a valid IPv6 address (no brackets, no zone), a decimal length from the
/// legal set without a sign or leading zero, and every bit after the prefix zero. Anything else
/// is nullopt.
constexpr std::optional<Nat64Prefix> parse_nat64_prefix(std::string_view s) {
    const auto slash = s.find('/');
    if (slash == std::string_view::npos)
        return std::nullopt;
    const std::string_view len_text = s.substr(slash + 1);
    if (len_text.empty() || len_text.size() > 3 || (len_text.size() > 1 && len_text[0] == '0'))
        return std::nullopt;
    int length = 0;
    for (const char c : len_text) {
        if (c < '0' || c > '9')
            return std::nullopt;
        length = length * 10 + (c - '0');
    }
    if (!nat64_length_valid(length))
        return std::nullopt;
    const auto addr = parse_ipv6(s.substr(0, slash));
    if (!addr)
        return std::nullopt;
    for (std::size_t i = static_cast<std::size_t>(length) / 8; i < addr->size(); ++i)
        if ((*addr)[i] != 0)
            return std::nullopt;
    return Nat64Prefix{*addr, length};
}

inline constexpr std::size_t kMaxNat64Prefixes = 16;

/// A comma-separated list of `parse_nat64_prefix` entries (blanks around an entry are ignored).
/// The empty string is the empty list; an empty entry, an unparsable entry or more than
/// `kMaxNat64Prefixes` entries is nullopt.
inline std::optional<std::vector<Nat64Prefix>> parse_nat64_prefix_list(std::string_view csv) {
    std::vector<Nat64Prefix> out;
    const auto blank = [](char c) {
        return c == ' ' || c == '\t';
    };
    const auto trim = [&blank](std::string_view t) {
        while (!t.empty() && blank(t.front()))
            t.remove_prefix(1);
        while (!t.empty() && blank(t.back()))
            t.remove_suffix(1);
        return t;
    };
    if (trim(csv).empty())
        return out;
    while (true) {
        const auto comma = csv.find(',');
        const auto entry = trim(csv.substr(0, comma));
        const auto prefix = parse_nat64_prefix(entry);
        if (!prefix || out.size() >= kMaxNat64Prefixes)
            return std::nullopt;
        out.push_back(*prefix);
        if (comma == std::string_view::npos)
            return out;
        csv.remove_prefix(comma + 1);
    }
}

/// RFC 7050 section 3: the prefix a DNS64 resolver advertises in its AAAA answer for
/// `ipv4only.arpa`, which embeds the well-known 192.0.0.170 / 192.0.0.171. Every legal length is
/// tried; the one whose embedded IPv4 address is one of those two (for /32../64 with the u octet
/// zero, as RFC 6052 requires) is the prefix length. nullopt when no length fits or more than one
/// does (an ambiguous answer is not trusted). The result has every bit after the prefix cleared.
constexpr std::optional<Nat64Prefix> discover_prefix_from_ipv4only_answer(const Ipv6& answer) {
    std::optional<Nat64Prefix> found;
    int hits = 0;
    for (const int length : {32, 40, 48, 56, 64, 96}) {
        Nat64Prefix candidate{answer, length};
        const auto v4 = embedded_ipv4(answer, candidate);
        if (!v4 || !(*v4 == Ipv4{192, 0, 0, 170} || *v4 == Ipv4{192, 0, 0, 171}))
            continue;
        if (length < 96 && answer[8] != 0) // the u octet must be zero (RFC 6052 section 2.2)
            continue;
        for (std::size_t i = static_cast<std::size_t>(length) / 8; i < candidate.bytes.size(); ++i)
            candidate.bytes[i] = 0;
        ++hits;
        found = candidate;
    }
    return hits == 1 ? found : std::nullopt;
}

/// The class of `host` when it is a canonical IPv4 dotted quad or an IPv6 literal (brackets
/// already stripped), nullopt when it is anything else (a name, or a numeric spelling the OS
/// resolver may read differently). A literal needs no DNS: this is the direct classification.
/// `extra` are the NAT64 prefixes to decode for an IPv6 literal.
constexpr std::optional<AddressClass> classify_literal(std::string_view host,
                                                       std::span<const Nat64Prefix> extra) {
    if (host.find(':') != std::string_view::npos) {
        if (const auto v6 = parse_ipv6(host))
            return classify_ipv6(*v6, extra);
        return std::nullopt;
    }
    if (const auto v4 = parse_ipv4(host))
        return classify_ipv4(*v4);
    return std::nullopt;
}

constexpr std::optional<AddressClass> classify_literal(std::string_view host) {
    return classify_literal(host, std::span<const Nat64Prefix>{});
}

enum class Verdict : std::uint8_t { Allow, Refuse };

/// Whether a connect to an address of class `c` is allowed. `allow_private` is the process
/// operator's `--oidc-allow-private-networks`; it never opens the "never allowed" tier.
constexpr Verdict decision(AddressClass c, bool allow_private) {
    switch (c) {
    case AddressClass::Public:
        return Verdict::Allow;
    case AddressClass::Loopback:
    case AddressClass::Private:
    case AddressClass::CarrierGradeNat:
    case AddressClass::UniqueLocal:
    case AddressClass::OtherNonGlobal:
        return allow_private ? Verdict::Allow : Verdict::Refuse;
    case AddressClass::Unspecified:
    case AddressClass::LinkLocal:
    case AddressClass::CloudMetadata:
    case AddressClass::Multicast:
    case AddressClass::Reserved:
        return Verdict::Refuse;
    }
    return Verdict::Refuse; // an out-of-range value fails closed
}

/// As above for a request over `cleartext` (plain http) or not: a PUBLIC address is never allowed
/// over plain http, whatever the operator's switch; every other class decides as the two-argument
/// form does.
constexpr Verdict decision(AddressClass c, bool allow_private, bool cleartext) {
    if (cleartext && c == AddressClass::Public)
        return Verdict::Refuse;
    return decision(c, allow_private);
}

/// A fixed label for logs (never the address itself).
constexpr const char* class_name(AddressClass c) {
    switch (c) {
    case AddressClass::Public:
        return "public";
    case AddressClass::Loopback:
        return "loopback";
    case AddressClass::Private:
        return "private";
    case AddressClass::CarrierGradeNat:
        return "carrier-grade-nat";
    case AddressClass::UniqueLocal:
        return "unique-local";
    case AddressClass::OtherNonGlobal:
        return "non-global";
    case AddressClass::Unspecified:
        return "unspecified";
    case AddressClass::LinkLocal:
        return "link-local";
    case AddressClass::CloudMetadata:
        return "cloud-metadata";
    case AddressClass::Multicast:
        return "multicast";
    case AddressClass::Reserved:
        return "reserved";
    }
    return "unknown";
}

} // namespace yuzu::server::oidc::egress
