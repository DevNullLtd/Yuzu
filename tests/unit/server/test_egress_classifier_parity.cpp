/**
 * test_egress_classifier_parity.cpp -- the agent-side address classifier
 * (agents/shared/outbound_address_policy.hpp, used by http_client and windows_updates) is a SUBSET
 * twin of the server's oidc_egress_policy.hpp. The two cannot share a header (the agent cannot
 * include the server tree), so this pins them together: over one table (plus a structured sweep)
 * both must agree on
 *   - "is this address Public" (what http_client may connect to), and
 *   - "is this address in the never-allowed tier" (loopback excluded: the server tier is
 *     unspecified, link-local, cloud metadata, multicast, reserved).
 * A change to either classifier that is not mirrored fails here.
 */
#include "oidc_egress_policy.hpp"

#include <outbound_address_policy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace srv = yuzu::server::oidc::egress;
namespace agt = yuzu::shared::outbound;

namespace {

bool server_public(srv::AddressClass c) { return c == srv::AddressClass::Public; }
bool server_never(srv::AddressClass c) {
    return srv::decision(c, /*allow_private=*/true) == srv::Verdict::Refuse;
}
bool agent_never_excluding_loopback(agt::AddressClass c) {
    // The agent tier `never_probeable` also holds Loopback (windows_updates refuses loopback
    // targets); the server's never-allowed tier does not (loopback is the operator opt-in there).
    return agt::never_probeable(c) && c != agt::AddressClass::Loopback;
}

void agree_v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    const auto s = srv::classify_ipv4({a, b, c, d});
    const auto g = agt::classify_ipv4({a, b, c, d});
    INFO(int(a) << "." << int(b) << "." << int(c) << "." << int(d));
    CHECK(server_public(s) == agt::is_public(g));
    CHECK(server_never(s) == agent_never_excluding_loopback(g));
    CHECK((s == srv::AddressClass::Loopback) == (g == agt::AddressClass::Loopback));
}

void agree_v6(const std::array<std::uint8_t, 16>& x) {
    const auto s = srv::classify_ipv6(x);
    const auto g = agt::classify_ipv6(x);
    std::string hex;
    for (const auto byte : x) {
        static constexpr char kHex[] = "0123456789abcdef";
        hex += kHex[byte >> 4];
        hex += kHex[byte & 15];
    }
    INFO(hex);
    CHECK(server_public(s) == agt::is_public(g));
    CHECK(server_never(s) == agent_never_excluding_loopback(g));
    CHECK((s == srv::AddressClass::Loopback) == (g == agt::AddressClass::Loopback));
}

} // namespace

TEST_CASE("egress parity: IPv4 sweep across every first octet and the special blocks",
          "[egress_parity][security]") {
    const unsigned second[] = {0, 1, 2, 15, 16, 31, 32, 63, 64, 99, 100, 127, 128, 168, 169, 253, 254, 255};
    const unsigned third[] = {0, 1, 2, 99, 100, 113, 129, 254};
    const unsigned fourth[] = {0, 1, 16, 170, 200, 254, 255};
    for (unsigned a = 0; a < 256; ++a)
        for (const auto b : second)
            for (const auto c : third)
                for (const auto d : fourth)
                    agree_v4(a, b, c, d);
}

TEST_CASE("egress parity: the named IPv4 special addresses", "[egress_parity][security]") {
    agree_v4(100, 100, 100, 200); // Alibaba metadata
    agree_v4(168, 63, 129, 16);   // Azure WireServer
    agree_v4(168, 63, 129, 17);
    agree_v4(169, 254, 169, 254); // AWS/GCP/Azure IMDS
    agree_v4(192, 0, 0, 170);
    agree_v4(198, 18, 0, 1);
    agree_v4(198, 19, 255, 255);
    agree_v4(203, 0, 113, 5);
    agree_v4(255, 255, 255, 255);
    // The pinned expectations, so a parity-preserving mistake on BOTH sides still fails.
    CHECK(agt::classify_ipv4({168, 63, 129, 16}) == agt::AddressClass::CloudMetadata);
    CHECK(srv::classify_ipv4({168, 63, 129, 16}) == srv::AddressClass::CloudMetadata);
    CHECK(agt::classify_ipv4({100, 100, 100, 200}) == agt::AddressClass::CloudMetadata);
    CHECK(srv::classify_ipv4({100, 100, 100, 200}) == srv::AddressClass::CloudMetadata);
}

TEST_CASE("egress parity: IPv6 prefixes, embedded-IPv4 forms and the AWS IMDS address",
          "[egress_parity][security]") {
    std::vector<std::array<std::uint8_t, 16>> table;
    const auto add = [&](std::initializer_list<unsigned> bytes) {
        std::array<std::uint8_t, 16> a{};
        std::size_t i = 0;
        for (const auto b : bytes)
            a[i++] = static_cast<std::uint8_t>(b);
        table.push_back(a);
    };
    add({});                                                           // ::
    add({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});            // ::1
    add({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1});    // v4-mapped loopback
    add({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254});
    add({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8});
    add({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8});            // v4-compatible
    add({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8});
    add({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254});
    add({0x00, 0x64, 0xff, 0x9b, 0, 1, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8});
    add({0x20, 0x02, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});      // 6to4 public
    add({0x20, 0x02, 169, 254, 169, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    add({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    add({0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    add({0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    add({0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54}); // AWS IMDS v6
    add({0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x55});
    add({0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    add({0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11});
    add({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}); // doc
    add({0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});       // doc RFC 9637
    add({0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});       // Teredo
    add({0x20, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}); // service anycast (Public)
    add({0x20, 0x01, 0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});    // AMT (Public)
    add({0x20, 0x01, 0, 0x04, 0x01, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}); // AS112 (Public)
    add({0x20, 0x01, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});    // ORCHIDv2 (Public)
    add({0x20, 0x01, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});    // benchmarking (non-global)
    add({0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    for (const auto& a : table)
        agree_v6(a);
    CHECK(agt::classify_ipv6(table[13]) == agt::AddressClass::Private); // fc00::1
    CHECK(agt::classify_ipv6(table[14]) == agt::AddressClass::CloudMetadata);
    CHECK(srv::classify_ipv6(table[14]) == srv::AddressClass::CloudMetadata);
}
