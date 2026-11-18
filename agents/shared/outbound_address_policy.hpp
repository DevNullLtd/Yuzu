// outbound_address_policy.hpp -- classify the ADDRESS BYTES an agent plugin is about to connect to.
//
// PURE decision code: no resolver, no socket, no OS header, so every host runs the unit test.
// The caller resolves a name ONCE, classifies every resolved address here and then connects to
// an address it classified (never re-resolving the name: a second lookup is the DNS-rebinding
// window). The classification is on the address bytes, never on the host text, because a name
// or a numeric spelling (`127.1`, `0x7f.1`) says nothing about where a connect lands.
//
// An IPv6 address that embeds an IPv4 address (IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96,
// 6to4 2002::/16) is classified by the embedded IPv4 address, so `::ffff:169.254.169.254` is
// link-local, not "public IPv6". The IPv4-compatible block ::/96 (deprecated, other than :: and
// ::1) and the NAT64 local-use block 64:ff9b:1::/48 are never public.
//
// Two tiers for callers:
//   * `is_public` -- a global unicast address. http_client connects only to these.
//   * `never_probeable` -- loopback, unspecified, link-local (the cloud metadata address
//     169.254.169.254 lives here), the other cloud metadata addresses, multicast and reserved. A caller that must still reach a
//     private network (windows_updates' patch-source probe, where a WSUS server is routinely on
//     RFC 1918) refuses only these.
//
// This is the agent-side twin of server/core/src/oidc_egress_policy.hpp (which the agent cannot
// include: server tree). The two are separate files and the agent one is a SUBSET of the server's
// (no NAT64 operator prefixes, no literal parser): the classes and the address blocks they cover
// must agree, and tests/unit/server/test_egress_classifier_parity.cpp pins server vs agent over
// one table so a change to either side that is not mirrored fails there.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace yuzu::shared::outbound {

using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;

enum class AddressClass : std::uint8_t {
    Public,
    Private,        // RFC 1918, carrier-grade NAT 100.64.0.0/10, IPv6 unique-local fc00::/7
    OtherNonGlobal, // documentation, benchmarking, IETF protocol assignments, site-local, ...
    Loopback,
    Unspecified,
    LinkLocal,
    Multicast,
    Reserved, // 240.0.0.0/4 including the limited broadcast address
    /// Single well-known cloud metadata endpoints that sit inside otherwise Private or Public
    /// blocks: the Alibaba metadata address (inside the carrier-grade NAT block), 168.63.129.16 (Azure WireServer,
    /// otherwise "public"), fd00:ec2::254 (AWS IMDS over IPv6, inside fc00::/7). 169.254.169.254
    /// is LinkLocal (the block it lives in).
    CloudMetadata,
};

[[nodiscard]] constexpr AddressClass classify_ipv4(const Ipv4& a) noexcept {
    const unsigned a0 = a[0], a1 = a[1], a2 = a[2];
    // Single addresses first: they sit inside blocks that are otherwise Private or Public.
    if (a0 == 100 && a1 == 100 && a2 == 100 && a[3] == 200)
        return AddressClass::CloudMetadata;
    if (a0 == 168 && a1 == 63 && a2 == 129 && a[3] == 16)
        return AddressClass::CloudMetadata;
    if (a0 == 0)
        return AddressClass::Unspecified; // 0.0.0.0/8
    if (a0 == 127)
        return AddressClass::Loopback;
    if (a0 == 169 && a1 == 254)
        return AddressClass::LinkLocal;
    if (a0 >= 224 && a0 <= 239)
        return AddressClass::Multicast;
    if (a0 >= 240)
        return AddressClass::Reserved;
    if (a0 == 10 || (a0 == 172 && (a1 & 0xF0) == 16) || (a0 == 192 && a1 == 168) ||
        (a0 == 100 && (a1 & 0xC0) == 64))
        return AddressClass::Private;
    if ((a0 == 192 && a1 == 0 && (a2 == 0 || a2 == 2)) || // IETF assignments, TEST-NET-1
        (a0 == 198 && (a1 & 0xFE) == 18) ||               // benchmarking 198.18.0.0/15
        (a0 == 198 && a1 == 51 && a2 == 100) ||           // TEST-NET-2
        (a0 == 203 && a1 == 0 && a2 == 113))              // TEST-NET-3
        return AddressClass::OtherNonGlobal;
    return AddressClass::Public;
}

[[nodiscard]] constexpr AddressClass classify_ipv6(const Ipv6& b) noexcept {
    const auto embedded = [&b](std::size_t off) {
        return classify_ipv4(Ipv4{b[off], b[off + 1], b[off + 2], b[off + 3]});
    };
    bool first12_zero = true;
    for (std::size_t i = 0; i < 12; ++i)
        first12_zero = first12_zero && b[i] == 0;
    if (first12_zero) { // ::/96
        bool last4_zero = b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 0;
        if (last4_zero)
            return AddressClass::Unspecified; // ::
        if (b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 1)
            return AddressClass::Loopback; // ::1
        return AddressClass::OtherNonGlobal; // IPv4-compatible (deprecated)
    }
    bool mapped = true; // ::ffff:0:0/96
    for (std::size_t i = 0; i < 10; ++i)
        mapped = mapped && b[i] == 0;
    if (mapped && b[10] == 0xff && b[11] == 0xff)
        return embedded(12);
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b) { // 64:ff9b::/32
        bool well_known = true; // 64:ff9b::/96
        for (std::size_t i = 4; i < 12; ++i)
            well_known = well_known && b[i] == 0;
        return well_known ? embedded(12) : AddressClass::OtherNonGlobal;
    }
    if (b[0] == 0x20 && b[1] == 0x02) // 6to4 2002::/16
        return embedded(2);
    if (b[0] == 0xff)
        return AddressClass::Multicast;
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
        return AddressClass::LinkLocal; // fe80::/10
    if ((b[0] & 0xfe) == 0xfc) { // fc00::/7
        bool zeros = true;       // fd00:ec2::254 is the AWS IMDS over IPv6
        for (std::size_t i = 4; i < 14; ++i)
            zeros = zeros && b[i] == 0;
        if (b[0] == 0xfd && b[1] == 0x00 && b[2] == 0x0e && b[3] == 0xc2 && zeros && b[14] == 0x02 &&
            b[15] == 0x54)
            return AddressClass::CloudMetadata;
        return AddressClass::Private;
    }
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0)
        return AddressClass::OtherNonGlobal; // fec0::/10 site-local (deprecated)
    if ((b[0] & 0xe0) != 0x20)
        return AddressClass::OtherNonGlobal; // outside 2000::/3
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        return AddressClass::OtherNonGlobal; // 2001:db8::/32 documentation
    if (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0x00)
        return AddressClass::OtherNonGlobal; // 3fff::/20 documentation (RFC 9637)
    // 2001::/23 IETF protocol assignments (Teredo, benchmarking, ORCHID ...): not global as a
    // block, EXCEPT the sub-ranges the IANA registry marks globally reachable (the server twin
    // documents each; unlisted addresses fail closed).
    if (b[0] == 0x20 && b[1] == 0x01 && (b[2] & 0xfe) == 0x00) {
        bool mid_zero = true;
        for (std::size_t i = 4; i < 15; ++i)
            mid_zero = mid_zero && b[i] == 0;
        const bool service_anycast = b[2] == 0x00 && b[3] == 0x01 && mid_zero && b[15] >= 1 && b[15] <= 3;
        const bool amt = b[2] == 0x00 && b[3] == 0x03;
        const bool as112 = b[2] == 0x00 && b[3] == 0x04 && b[4] == 0x01 && b[5] == 0x12;
        const bool orchid_v2_or_det = b[2] == 0x00 && ((b[3] & 0xf0) == 0x20 || (b[3] & 0xf0) == 0x30);
        return (service_anycast || amt || as112 || orchid_v2_or_det) ? AddressClass::Public
                                                                     : AddressClass::OtherNonGlobal;
    }
    return AddressClass::Public;
}

[[nodiscard]] constexpr bool is_public(AddressClass c) noexcept {
    return c == AddressClass::Public;
}

/// Loopback, unspecified, link-local (cloud metadata), multicast and reserved: never a legitimate
/// probe or fetch target for an endpoint agent, on any network.
[[nodiscard]] constexpr bool never_probeable(AddressClass c) noexcept {
    return c == AddressClass::Loopback || c == AddressClass::Unspecified ||
           c == AddressClass::LinkLocal || c == AddressClass::Multicast ||
           c == AddressClass::Reserved || c == AddressClass::CloudMetadata;
}

/// One resolved address as raw bytes (an IPv4 address occupies bytes 0..3). The OS resolver glue
/// fills these from getaddrinfo; the vetting below stays pure.
struct ResolvedAddress {
    bool is_v6{false};
    Ipv6 bytes{};
};

[[nodiscard]] constexpr AddressClass classify(const ResolvedAddress& a) noexcept {
    return a.is_v6 ? classify_ipv6(a.bytes)
                   : classify_ipv4(Ipv4{a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]});
}

enum class VetStatus : std::uint8_t {
    ok,
    resolution_failed, ///< the resolver answered nothing (fail closed)
    refused,           ///< at least one answer is not a public address
};

struct VetResult {
    VetStatus status{VetStatus::resolution_failed};
    std::size_t index{0}; ///< which answer to connect to, only when status == ok
};

/// Judge a resolver answer: EVERY returned address must be public (a name that answers one public
/// and one private address is refused, not "use the public one": the caller does not control which
/// the connect would pick). On success the caller connects to answer `index`, the address it
/// classified, and never resolves the name again.
[[nodiscard]] inline VetResult vet_addresses(const std::vector<ResolvedAddress>& answers) noexcept {
    if (answers.empty())
        return {VetStatus::resolution_failed, 0};
    for (const auto& a : answers)
        if (!is_public(classify(a)))
            return {VetStatus::refused, 0};
    return {VetStatus::ok, 0};
}

/// What one judged lookup produced: the verdict and the answers that were judged (the caller picks
/// its connect target(s) from `answers`, never from a second lookup).
struct VetOutcome {
    VetResult verdict;
    std::vector<ResolvedAddress> answers;
};

/// `resolve()` returns the answers of ONE lookup. It is called exactly once: the vetted answers are
/// the connect targets (the DNS-rebinding fix).
template <class ResolveFn>
[[nodiscard]] VetOutcome vet_host(ResolveFn&& resolve) {
    VetOutcome out;
    out.answers = resolve();
    out.verdict = vet_addresses(out.answers);
    return out;
}

/// The vetted answers in connect order: IPv4 first, then IPv6, each family in resolver order (so a
/// host that answers both families still falls back to the other when one is unreachable, without
/// ever connecting to an address that was not judged).
[[nodiscard]] inline std::vector<ResolvedAddress>
connect_order(const std::vector<ResolvedAddress>& answers) {
    std::vector<ResolvedAddress> out;
    out.reserve(answers.size());
    for (const auto& a : answers)
        if (!a.is_v6)
            out.push_back(a);
    for (const auto& a : answers)
        if (a.is_v6)
            out.push_back(a);
    return out;
}

} // namespace yuzu::shared::outbound
