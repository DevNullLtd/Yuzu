/**
 * test_oidc_egress_policy.cpp -- the OIDC egress address policy (#5692).
 *
 * Pure table-driven cases over oidc_egress_policy.hpp: every boundary of every range, the IPv6
 * forms that embed an IPv4 address, the strict literal parser, and the two-tier decision. The
 * provider-level cases (a refused connect never happens, the pin, the flag plumbing) are in
 * test_oidc_egress.cpp.
 */

#include "oidc_egress_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h> // before any windows.h
#include <ws2tcpip.h> // inet_pton (a pure string parser: no WSAStartup needed)
#else
#include <arpa/inet.h>
#endif

using namespace yuzu::server::oidc::egress;

namespace {

struct Row {
    const char* text;
    AddressClass cls;
};

AddressClass classify_text(const char* text) {
    const auto c = classify_literal(text);
    REQUIRE(c.has_value());
    return *c;
}

} // namespace

TEST_CASE("OIDC egress: IPv4 range boundaries", "[oidc][oidc_egress]") {
    const std::vector<Row> rows = {
        // 0.0.0.0/8 unspecified / "this network"
        {"0.0.0.0", AddressClass::Unspecified},
        {"0.255.255.255", AddressClass::Unspecified},
        {"1.0.0.0", AddressClass::Public},
        // 10.0.0.0/8
        {"9.255.255.255", AddressClass::Public},
        {"10.0.0.0", AddressClass::Private},
        {"10.255.255.255", AddressClass::Private},
        {"11.0.0.0", AddressClass::Public},
        // 172.16.0.0/12
        {"172.15.255.255", AddressClass::Public},
        {"172.16.0.0", AddressClass::Private},
        {"172.31.255.255", AddressClass::Private},
        {"172.32.0.0", AddressClass::Public},
        // 192.168.0.0/16
        {"192.167.255.255", AddressClass::Public},
        {"192.168.0.0", AddressClass::Private},
        {"192.168.255.255", AddressClass::Private},
        {"192.169.0.0", AddressClass::Public},
        // 100.64.0.0/10 carrier-grade NAT
        {"100.63.255.255", AddressClass::Public},
        {"100.64.0.0", AddressClass::CarrierGradeNat},
        {"100.127.255.255", AddressClass::CarrierGradeNat},
        {"100.128.0.0", AddressClass::Public},
        // 127.0.0.0/8 loopback
        {"126.255.255.255", AddressClass::Public},
        {"127.0.0.0", AddressClass::Loopback},
        {"127.0.0.1", AddressClass::Loopback},
        {"127.255.255.255", AddressClass::Loopback},
        {"128.0.0.0", AddressClass::Public},
        // 169.254.0.0/16 link-local (cloud metadata lives here)
        {"169.253.255.255", AddressClass::Public},
        {"169.254.0.0", AddressClass::LinkLocal},
        {"169.254.169.254", AddressClass::LinkLocal},
        {"169.254.255.255", AddressClass::LinkLocal},
        {"169.255.0.0", AddressClass::Public},
        // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved (incl. broadcast)
        {"223.255.255.255", AddressClass::Public},
        {"224.0.0.0", AddressClass::Multicast},
        {"224.0.0.1", AddressClass::Multicast},
        {"239.255.255.255", AddressClass::Multicast},
        {"240.0.0.0", AddressClass::Reserved},
        {"255.255.255.254", AddressClass::Reserved},
        {"255.255.255.255", AddressClass::Reserved},
        // single-address cloud metadata endpoints
        {"100.100.100.200", AddressClass::CloudMetadata},
        {"100.100.100.199", AddressClass::CarrierGradeNat},
        {"100.100.100.201", AddressClass::CarrierGradeNat},
        {"168.63.129.16", AddressClass::CloudMetadata},
        {"168.63.129.15", AddressClass::Public},
        {"168.63.129.17", AddressClass::Public},
        // documentation, benchmarking and IETF protocol blocks (refused unless private allowed)
        {"192.0.0.0", AddressClass::OtherNonGlobal},
        {"192.0.0.255", AddressClass::OtherNonGlobal},
        {"192.0.1.0", AddressClass::Public},
        {"192.0.2.0", AddressClass::OtherNonGlobal},
        {"192.0.2.255", AddressClass::OtherNonGlobal},
        {"192.0.3.0", AddressClass::Public},
        {"198.17.255.255", AddressClass::Public},
        {"198.18.0.0", AddressClass::OtherNonGlobal},
        {"198.19.255.255", AddressClass::OtherNonGlobal},
        {"198.20.0.0", AddressClass::Public},
        {"198.51.99.255", AddressClass::Public},
        {"198.51.100.0", AddressClass::OtherNonGlobal},
        {"198.51.100.255", AddressClass::OtherNonGlobal},
        {"198.51.101.0", AddressClass::Public},
        {"203.0.112.255", AddressClass::Public},
        {"203.0.113.0", AddressClass::OtherNonGlobal},
        {"203.0.113.255", AddressClass::OtherNonGlobal},
        {"203.0.114.0", AddressClass::Public},
        // plainly public
        {"8.8.8.8", AddressClass::Public},
        {"1.1.1.1", AddressClass::Public},
        {"93.184.216.34", AddressClass::Public},
    };
    for (const auto& r : rows) {
        CAPTURE(r.text);
        CHECK(classify_text(r.text) == r.cls);
    }
}

TEST_CASE("OIDC egress: IPv6 ranges and the embedded IPv4 forms", "[oidc][oidc_egress]") {
    const std::vector<Row> rows = {
        {"::", AddressClass::Unspecified},
        {"::1", AddressClass::Loopback},
        {"::2", AddressClass::OtherNonGlobal},
        {"::127.0.0.1", AddressClass::OtherNonGlobal}, // IPv4-compatible (deprecated)
        // IPv4-mapped: classified by the embedded IPv4 address
        {"::ffff:127.0.0.1", AddressClass::Loopback},
        {"::ffff:7f00:1", AddressClass::Loopback},
        {"::ffff:10.1.2.3", AddressClass::Private},
        {"::ffff:169.254.169.254", AddressClass::LinkLocal},
        {"::ffff:a9fe:a9fe", AddressClass::LinkLocal},
        {"::ffff:0.0.0.0", AddressClass::Unspecified},
        {"::ffff:8.8.8.8", AddressClass::Public},
        {"::fffe:8.8.8.8", AddressClass::OtherNonGlobal}, // one bit off the mapped prefix
        // NAT64 well-known prefix
        {"64:ff9b::7f00:1", AddressClass::Loopback},
        {"64:ff9b::a9fe:a9fe", AddressClass::LinkLocal},
        {"64:ff9b::808:808", AddressClass::Public},
        {"64:ff9b:1::1", AddressClass::OtherNonGlobal}, // the local-use prefix is not translated
        // 6to4
        {"2002:a9fe:a9fe::1", AddressClass::LinkLocal},
        {"2002:7f00:1::", AddressClass::Loopback},
        {"2002:808:808::1", AddressClass::Public},
        // link-local fe80::/10 (boundaries fe80 .. febf), site-local fec0::/10
        {"fe7f:ffff::", AddressClass::OtherNonGlobal},
        {"fe80::1", AddressClass::LinkLocal},
        {"febf:ffff::1", AddressClass::LinkLocal},
        {"fec0::1", AddressClass::OtherNonGlobal},
        // unique-local fc00::/7 (fc00 .. fdff)
        {"fbff:ffff::", AddressClass::OtherNonGlobal},
        {"fc00::", AddressClass::UniqueLocal},
        {"fd12:3456::1", AddressClass::UniqueLocal},
        {"fdff:ffff::", AddressClass::UniqueLocal},
        {"fe00::", AddressClass::OtherNonGlobal},
        // AWS IPv6 metadata address, exact
        {"fd00:ec2::254", AddressClass::CloudMetadata},
        {"fd00:ec2::253", AddressClass::UniqueLocal},
        {"fd00:ec2::255", AddressClass::UniqueLocal},
        {"fd00:ec3::254", AddressClass::UniqueLocal},
        // multicast
        {"ff00::", AddressClass::Multicast},
        {"ff02::1", AddressClass::Multicast},
        // documentation 2001:db8::/32 and 3fff::/20, other global unicast
        {"2001:db7:ffff::", AddressClass::Public},
        {"2001:db8::", AddressClass::OtherNonGlobal},
        {"2001:db8:ffff:ffff::1", AddressClass::OtherNonGlobal},
        {"2001:db9::", AddressClass::Public},
        {"3fff::", AddressClass::OtherNonGlobal},
        {"3fff:0fff:ffff::", AddressClass::OtherNonGlobal},
        {"3fff:1000::", AddressClass::Public},
        {"3ffe::", AddressClass::Public},
        // outside 2000::/3 is not global unicast
        {"1fff:ffff::", AddressClass::OtherNonGlobal},
        {"4000::", AddressClass::OtherNonGlobal},
        {"8000::1", AddressClass::OtherNonGlobal},
        // public
        {"2606:4700:4700::1111", AddressClass::Public},
        {"2001:4860:4860::8888", AddressClass::Public},
    };
    for (const auto& r : rows) {
        CAPTURE(r.text);
        CHECK(classify_text(r.text) == r.cls);
    }
}

TEST_CASE("OIDC egress: the two-tier decision", "[oidc][oidc_egress]") {
    const AddressClass allowed_with_flag[] = {
        AddressClass::Loopback, AddressClass::Private, AddressClass::CarrierGradeNat,
        AddressClass::UniqueLocal, AddressClass::OtherNonGlobal};
    const AddressClass never[] = {AddressClass::Unspecified, AddressClass::LinkLocal,
                                  AddressClass::CloudMetadata, AddressClass::Multicast,
                                  AddressClass::Reserved};
    CHECK(decision(AddressClass::Public, false) == Verdict::Allow);
    CHECK(decision(AddressClass::Public, true) == Verdict::Allow);
    for (const auto c : allowed_with_flag) {
        CAPTURE(class_name(c));
        CHECK(decision(c, false) == Verdict::Refuse);
        CHECK(decision(c, true) == Verdict::Allow);
    }
    for (const auto c : never) {
        CAPTURE(class_name(c));
        CHECK(decision(c, false) == Verdict::Refuse);
        CHECK(decision(c, true) == Verdict::Refuse); // the flag never opens this tier
    }
    // An out-of-range value fails closed under both settings.
    const auto bogus = static_cast<AddressClass>(200);
    CHECK(decision(bogus, false) == Verdict::Refuse);
    CHECK(decision(bogus, true) == Verdict::Refuse);
}

TEST_CASE("OIDC egress: plain http to a public address is never allowed", "[oidc][oidc_egress]") {
    const AddressClass all[] = {
        AddressClass::Public,          AddressClass::Loopback,    AddressClass::Private,
        AddressClass::CarrierGradeNat, AddressClass::UniqueLocal, AddressClass::OtherNonGlobal,
        AddressClass::Unspecified,     AddressClass::LinkLocal,   AddressClass::CloudMetadata,
        AddressClass::Multicast,       AddressClass::Reserved};
    for (const auto c : all) {
        CAPTURE(class_name(c));
        for (const bool allow_private : {false, true}) {
            CAPTURE(allow_private);
            // https (not cleartext) decides exactly as the two-argument form does.
            CHECK(decision(c, allow_private, false) == decision(c, allow_private));
            if (c == AddressClass::Public) {
                // The one class the cleartext rule changes: refused, with the switch on or off.
                CHECK(decision(c, allow_private, true) == Verdict::Refuse);
            } else {
                // Every other class is governed by the switch alone, cleartext or not.
                CHECK(decision(c, allow_private, true) == decision(c, allow_private));
            }
        }
    }
    // Plain http to a loopback/private address is still allowed with the switch on.
    CHECK(decision(AddressClass::Loopback, true, true) == Verdict::Allow);
    CHECK(decision(AddressClass::Private, true, true) == Verdict::Allow);
    // An out-of-range value fails closed.
    CHECK(decision(static_cast<AddressClass>(200), true, true) == Verdict::Refuse);
}

TEST_CASE("OIDC egress: a network-specific NAT64 prefix is the documented classification limit",
          "[oidc][oidc_egress]") {
    // The policy classifies the address as the server sees it. It decodes IPv4-mapped, the
    // well-known NAT64 prefix 64:ff9b::/96 and 6to4, but cannot know an operator's
    // network-specific NAT64 prefix (RFC 6052 section 2.2): an address in 2000::/3 whose last 32
    // bits spell 169.254.169.254 under such a prefix classifies as Public. This pins that
    // boundary so a change to it is deliberate and the documented residual stays true.
    CHECK(classify_text("2001:4860:4860::a9fe:a9fe") == AddressClass::Public);
    CHECK(classify_text("2606:4700:4700::a9fe:a9fe") == AddressClass::Public);
    // The same embedded address under the well-known prefix IS decoded.
    CHECK(classify_text("64:ff9b::a9fe:a9fe") == AddressClass::LinkLocal);
    // Plain http to such an address is refused by the cleartext rule.
    CHECK(decision(classify_text("2001:4860:4860::a9fe:a9fe"), true, true) == Verdict::Refuse);
}

TEST_CASE("OIDC egress: the literal parser is strict and leaves odd spellings to the resolver",
          "[oidc][oidc_egress]") {
    // Not canonical literals: classify_literal says nullopt, so the caller resolves them and
    // classifies the address the OS returns (a name, or a numeric spelling the OS reads its own
    // way).
    for (const char* odd : {"",
                            "localhost",
                            "example.com",
                            "127.1",
                            "0x7f.0.0.1",
                            "2130706433",
                            "010.0.0.1",
                            "01.2.3.4",
                            "1.2.3",
                            "1.2.3.4.5",
                            "1.2.3.",
                            ".1.2.3",
                            "256.1.1.1",
                            "1.2.3.-4",
                            "1.2.3.4 ",
                            " 1.2.3.4",
                            "1.2.3.4%eth0",
                            "1..2.3",
                            "::1%eth0",
                            ":1",
                            "1:",
                            "1:2:3:4:5:6:7",
                            "1:2:3:4:5:6:7:8:9",
                            "1::2::3",
                            ":::",
                            "::g",
                            "12345::",
                            "::1.2.3",
                            "::1.2.3.4.5",
                            "1:2:3:4:5:6:7::8",
                            "[::1]",
                            "::ffff:010.0.0.1"}) {
        CAPTURE(odd);
        CHECK_FALSE(classify_literal(odd).has_value());
    }
    // And the canonical forms are accepted.
    CHECK(classify_text("0.0.0.0") == AddressClass::Unspecified);
    CHECK(classify_text("1:2:3:4:5:6:7:8") == AddressClass::OtherNonGlobal);
    CHECK(classify_text("1:2:3:4:5:6:7::") == AddressClass::OtherNonGlobal);
    CHECK(classify_text("::1") == AddressClass::Loopback);
    CHECK(classify_text("FE80::A") == AddressClass::LinkLocal);
    CHECK(classify_text("1:2:3:4:5:6:1.2.3.4") == AddressClass::OtherNonGlobal);
}

TEST_CASE("OIDC egress: the literal parser agrees with the OS parser on what it accepts",
          "[oidc][oidc_egress]") {
    // Anything the strict parser accepts, inet_pton must read as the same bytes: a disagreement
    // would let a spelling be classified as one address and connected to as another.
    const char* v4s[] = {"0.0.0.0",         "1.2.3.4",     "127.0.0.1",      "169.254.169.254",
                         "255.255.255.255", "10.20.30.40", "100.100.100.200"};
    for (const char* t : v4s) {
        CAPTURE(t);
        in_addr os{};
        REQUIRE(::inet_pton(AF_INET, t, &os) == 1);
        const auto mine = parse_ipv4(t);
        REQUIRE(mine.has_value());
        CHECK(std::memcmp(mine->data(), &os, 4) == 0);
    }
    const char* v6s[] = {"::",
                         "::1",
                         "1::",
                         "fe80::1",
                         "::ffff:1.2.3.4",
                         "2001:db8::ff00:42:8329",
                         "1:2:3:4:5:6:7:8",
                         "1::8",
                         "fd00:ec2::254",
                         "64:ff9b::1.2.3.4",
                         "ABCD:ef01::1"};
    for (const char* t : v6s) {
        CAPTURE(t);
        in6_addr os{};
        REQUIRE(::inet_pton(AF_INET6, t, &os) == 1);
        const auto mine = parse_ipv6(t);
        REQUIRE(mine.has_value());
        CHECK(std::memcmp(mine->data(), &os, 16) == 0);
    }
    // And what the strict parser refuses is not something inet_pton reads as a DIFFERENT valid
    // address in a way that matters here: the caller resolves it and classifies the result, so
    // the only requirement is that the parser did not accept it.
    in6_addr os6{};
    CHECK(::inet_pton(AF_INET6, "1:2:3:4:5:6:7::8", &os6) == 0); // the parser also refuses it
}

TEST_CASE("OIDC egress: class names are fixed labels that carry no address",
          "[oidc][oidc_egress]") {
    CHECK(std::string(class_name(AddressClass::Loopback)) == "loopback");
    CHECK(std::string(class_name(AddressClass::LinkLocal)) == "link-local");
    CHECK(std::string(class_name(AddressClass::CloudMetadata)) == "cloud-metadata");
    CHECK(std::string(class_name(static_cast<AddressClass>(200))) == "unknown");
}

// ── NAT64 network-specific prefixes (RFC 6052 section 2.2, RFC 7050) ────────────────────────

namespace {

Ipv6 v6(const char* text) {
    const auto a = parse_ipv6(text);
    REQUIRE(a.has_value());
    return *a;
}

Ipv4 v4(const char* text) {
    const auto a = parse_ipv4(text);
    REQUIRE(a.has_value());
    return *a;
}

Nat64Prefix prefix(const std::string& text) {
    const auto p = parse_nat64_prefix(text);
    REQUIRE(p.has_value());
    return *p;
}

// An INDEPENDENT bit-level encoder of RFC 6052 section 2.2 figure 1 (each IPv4 bit placed one at
// a time into the listed bit ranges), so the byte-offset table in the header is not checked
// against itself. `u` and `suffix_fill` let a case put noise in the reserved octet / suffix.
Ipv6 synthesize(const Ipv6& pfx, int length, const Ipv4& addr, std::uint8_t u = 0,
                std::uint8_t suffix_fill = 0) {
    struct Range {
        int start;
        int bits;
    };
    std::vector<Range> v4_ranges;
    switch (length) {
    case 32:
        v4_ranges = {{32, 32}};
        break;
    case 40:
        v4_ranges = {{40, 24}, {72, 8}};
        break;
    case 48:
        v4_ranges = {{48, 16}, {72, 16}};
        break;
    case 56:
        v4_ranges = {{56, 8}, {72, 24}};
        break;
    case 64:
        v4_ranges = {{72, 32}};
        break;
    default:
        v4_ranges = {{96, 32}};
        break;
    }
    std::array<int, 128> bits{};
    std::array<int, 128> taken{}; // 0 free, 1 prefix, 2 v4
    const auto bit_of = [](const auto& bytes, int i) {
        return (bytes[i / 8] >> (7 - i % 8)) & 1;
    };
    for (int i = 0; i < length; ++i) {
        bits[i] = bit_of(pfx, i);
        taken[i] = 1;
    }
    int k = 0;
    for (const auto& r : v4_ranges)
        for (int i = 0; i < r.bits; ++i, ++k) {
            bits[r.start + i] = bit_of(addr, k);
            taken[r.start + i] = 2;
        }
    for (int i = 0; i < 128; ++i)
        if (taken[i] == 0)
            bits[i] = (i >= 64 && i < 72) ? bit_of(std::array<std::uint8_t, 1>{u}, i - 64)
                                          : bit_of(std::array<std::uint8_t, 1>{suffix_fill}, i % 8);
    Ipv6 out{};
    for (int i = 0; i < 128; ++i)
        out[i / 8] = static_cast<std::uint8_t>(out[i / 8] | (bits[i] << (7 - i % 8)));
    return out;
}

Ipv6 mask_to(Ipv6 a, int length) {
    for (std::size_t i = static_cast<std::size_t>(length) / 8; i < a.size(); ++i)
        a[i] = 0;
    return a;
}

struct Rfc6052Row {
    int length;
    const char* prefix;
    const char* v4;
    const char* address;
};

// Derived with a separate Python implementation of the RFC (bit-level), including the six
// examples of RFC 6052 section 2.4 for 192.0.2.33 under 2001:db8:122:344::/n (the first row of
// each length): /32 2001:db8:c000:221::, /40 2001:db8:1c0:2:21::, /48 2001:db8:122:c000:2:2100::,
// /56 2001:db8:122:3c0:0:221::, /64 2001:db8:122:344:c0:2:2100:0, /96 2001:db8:122:344::c000:221
// (there the prefix carries extra bits, so the /96 address differs from the RFC's /96 example only
// in the prefix bits the table's base address contributes).
const Rfc6052Row kRfc6052Rows[] = {
    {32, "2001:db8::", "192.0.2.33", "2001:db8:c000:221::"},
    {32, "2001:db8::", "192.0.0.170", "2001:db8:c000:aa::"},
    {32, "2001:db8::", "192.0.0.171", "2001:db8:c000:ab::"},
    {32, "2001:db8::", "169.254.169.254", "2001:db8:a9fe:a9fe::"},
    {32, "2001:db8::", "10.0.0.5", "2001:db8:a00:5::"},
    {32, "2001:db8::", "8.8.8.8", "2001:db8:808:808::"},
    {40, "2001:db8:100::", "192.0.2.33", "2001:db8:1c0:2:21::"},
    {40, "2001:db8:100::", "192.0.0.170", "2001:db8:1c0:0:aa::"},
    {40, "2001:db8:100::", "192.0.0.171", "2001:db8:1c0:0:ab::"},
    {40, "2001:db8:100::", "169.254.169.254", "2001:db8:1a9:fea9:fe::"},
    {40, "2001:db8:100::", "10.0.0.5", "2001:db8:10a:0:5::"},
    {40, "2001:db8:100::", "8.8.8.8", "2001:db8:108:808:8::"},
    {48, "2001:db8:122::", "192.0.2.33", "2001:db8:122:c000:2:2100::"},
    {48, "2001:db8:122::", "192.0.0.170", "2001:db8:122:c000:0:aa00::"},
    {48, "2001:db8:122::", "192.0.0.171", "2001:db8:122:c000:0:ab00::"},
    {48, "2001:db8:122::", "169.254.169.254", "2001:db8:122:a9fe:a9:fe00::"},
    {48, "2001:db8:122::", "10.0.0.5", "2001:db8:122:a00:0:500::"},
    {48, "2001:db8:122::", "8.8.8.8", "2001:db8:122:808:8:800::"},
    {56, "2001:db8:122:300::", "192.0.2.33", "2001:db8:122:3c0:0:221::"},
    {56, "2001:db8:122:300::", "192.0.0.170", "2001:db8:122:3c0:0:aa::"},
    {56, "2001:db8:122:300::", "192.0.0.171", "2001:db8:122:3c0:0:ab::"},
    {56, "2001:db8:122:300::", "169.254.169.254", "2001:db8:122:3a9:fe:a9fe::"},
    {56, "2001:db8:122:300::", "10.0.0.5", "2001:db8:122:30a:0:5::"},
    {56, "2001:db8:122:300::", "8.8.8.8", "2001:db8:122:308:8:808::"},
    {64, "2001:db8:122:344::", "192.0.2.33", "2001:db8:122:344:c0:2:2100:0"},
    {64, "2001:db8:122:344::", "192.0.0.170", "2001:db8:122:344:c0:0:aa00:0"},
    {64, "2001:db8:122:344::", "192.0.0.171", "2001:db8:122:344:c0:0:ab00:0"},
    {64, "2001:db8:122:344::", "169.254.169.254", "2001:db8:122:344:a9:fea9:fe00:0"},
    {64, "2001:db8:122:344::", "10.0.0.5", "2001:db8:122:344:a:0:500:0"},
    {64, "2001:db8:122:344::", "8.8.8.8", "2001:db8:122:344:8:808:800:0"},
    {96, "2001:db8:122:344:5566:7788::", "192.0.2.33", "2001:db8:122:344:5566:7788:c000:221"},
    {96, "2001:db8:122:344:5566:7788::", "192.0.0.170", "2001:db8:122:344:5566:7788:c000:aa"},
    {96, "2001:db8:122:344:5566:7788::", "192.0.0.171", "2001:db8:122:344:5566:7788:c000:ab"},
    {96, "2001:db8:122:344:5566:7788::", "169.254.169.254", "2001:db8:122:344:5566:7788:a9fe:a9fe"},
    {96, "2001:db8:122:344:5566:7788::", "10.0.0.5", "2001:db8:122:344:5566:7788:a00:5"},
    {96, "2001:db8:122:344:5566:7788::", "8.8.8.8", "2001:db8:122:344:5566:7788:808:808"},
};

constexpr std::array<int, 6> kLengths = {32, 40, 48, 56, 64, 96};

} // namespace

TEST_CASE("OIDC egress NAT64: the RFC 6052 section 2.2 layouts decode to the embedded IPv4",
          "[oidc][oidc_egress][oidc_nat64]") {
    for (const auto& row : kRfc6052Rows) {
        CAPTURE(row.length, row.prefix, row.v4, row.address);
        const Nat64Prefix p{v6(row.prefix), row.length};
        const auto addr = v6(row.address);
        // The independent encoder reproduces the table (checks the table AND the encoder) ...
        CHECK(synthesize(p.bytes, row.length, v4(row.v4)) == addr);
        // ... and the header's decoder inverts it.
        REQUIRE(matches(addr, p));
        const auto embedded = embedded_ipv4(addr, p);
        REQUIRE(embedded.has_value());
        CHECK(*embedded == v4(row.v4));
    }
}

TEST_CASE("OIDC egress NAT64: the six RFC 6052 section 2.4 example addresses",
          "[oidc][oidc_egress][oidc_nat64]") {
    struct Example {
        const char* prefix;
        const char* address;
    };
    // Prefix lengths 32, 40, 48, 56, 64, 96 for 192.0.2.33 (the RFC's own table).
    const Example examples[] = {{"2001:db8::/32", "2001:db8:c000:221::"},
                                {"2001:db8:100::/40", "2001:db8:1c0:2:21::"},
                                {"2001:db8:122::/48", "2001:db8:122:c000:2:2100::"},
                                {"2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"},
                                {"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"},
                                {"2001:db8:122:344::/96", "2001:db8:122:344::c000:221"}};
    for (const auto& e : examples) {
        CAPTURE(e.prefix, e.address);
        const auto p = prefix(e.prefix);
        const auto embedded = embedded_ipv4(v6(e.address), p);
        REQUIRE(embedded.has_value());
        CHECK(*embedded == v4("192.0.2.33"));
        CHECK(synthesize(p.bytes, p.length, v4("192.0.2.33")) == v6(e.address));
    }
}

TEST_CASE("OIDC egress NAT64: round trip over many random addresses, the u octet and suffix are "
          "ignored",
          "[oidc][oidc_egress][oidc_nat64]") {
    std::mt19937_64 rng(0x5692'6052u); // fixed seed: deterministic
    for (const int length : kLengths) {
        for (int i = 0; i < 400; ++i) {
            Ipv6 pfx{};
            for (auto& b : pfx)
                b = static_cast<std::uint8_t>(rng());
            pfx = mask_to(pfx, length);
            Ipv4 addr{};
            for (auto& b : addr)
                b = static_cast<std::uint8_t>(rng());
            const std::uint8_t u = (i % 2 == 0) ? 0 : static_cast<std::uint8_t>(rng());
            const auto suffix = static_cast<std::uint8_t>(rng());
            const auto a = synthesize(pfx, length, addr, u, suffix);
            const Nat64Prefix p{pfx, length};
            CAPTURE(length, i);
            REQUIRE(matches(a, p));
            const auto embedded = embedded_ipv4(a, p);
            REQUIRE(embedded.has_value());
            CHECK(*embedded == addr);
        }
    }
}

TEST_CASE("OIDC egress NAT64: matching is exactly the first `length` bits",
          "[oidc][oidc_egress][oidc_nat64]") {
    for (const int length : kLengths) {
        CAPTURE(length);
        const Nat64Prefix p{mask_to(v6("2001:db8:122:344:5566:7788:99aa:bbcc"), length), length};
        const auto inside = synthesize(p.bytes, length, v4("8.8.8.8"));
        CHECK(matches(inside, p));
        // Flip the last bit of the prefix, then the first bit after it.
        auto outside = inside;
        outside[static_cast<std::size_t>(length) / 8 - 1] ^= 0x01;
        CHECK_FALSE(matches(outside, p));
        CHECK_FALSE(embedded_ipv4(outside, p).has_value());
        // A bit after the prefix is NOT part of the match.
        auto tail = inside;
        tail[15] ^= 0x80;
        CHECK(matches(tail, p));
    }
    // An illegal length matches and embeds nothing, however the address looks.
    for (const int bad : {-1, 0, 8, 16, 24, 33, 65, 97, 112, 128, 4096}) {
        CAPTURE(bad);
        const Nat64Prefix p{v6("2001:db8::"), bad};
        CHECK_FALSE(matches(v6("2001:db8::1"), p));
        CHECK_FALSE(embedded_ipv4(v6("2001:db8::1"), p).has_value());
    }
}

TEST_CASE("OIDC egress NAT64: an address inside a prefix is classified by its embedded IPv4",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    struct Dest {
        const char* v4;
        AddressClass cls;
    };
    const Dest dests[] = {{"169.254.169.254", AddressClass::LinkLocal},
                          {"100.100.100.200", AddressClass::CloudMetadata},
                          {"10.0.0.5", AddressClass::Private},
                          {"127.0.0.1", AddressClass::Loopback},
                          {"0.0.0.0", AddressClass::Unspecified},
                          {"224.0.0.1", AddressClass::Multicast},
                          {"8.8.8.8", AddressClass::Public}};
    // One documentation prefix (which is non-global on its own) and one in global space.
    for (const char* base : {"2001:db8:122:344:5566:7788::", "2a0e:b107:122:344:5566:7788::"}) {
        for (const int length : kLengths) {
            const Nat64Prefix p{mask_to(v6(base), length), length};
            const std::array<Nat64Prefix, 1> extra{p};
            for (const auto& d : dests) {
                CAPTURE(base, length, d.v4);
                const auto a = synthesize(p.bytes, length, v4(d.v4));
                CHECK(classify_ipv6(a, extra) == d.cls);
                // Without the prefix the same address is merely "some IPv6 address".
                const auto bare = classify_ipv6(a);
                CHECK((bare == AddressClass::Public || bare == AddressClass::OtherNonGlobal));
            }
        }
    }
}

TEST_CASE("OIDC egress NAT64: what the prefix list does not touch stays as it was",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    const std::array<Nat64Prefix, 2> extra{prefix("2a0e:b107:122:344::/64"),
                                           prefix("2001:db8:122::/48")};
    // The well-known prefix and the other embedded forms are unchanged.
    CHECK(classify_ipv6(v6("64:ff9b::a9fe:a9fe"), extra) == AddressClass::LinkLocal);
    CHECK(classify_ipv6(v6("64:ff9b::808:808"), extra) == AddressClass::Public);
    CHECK(classify_ipv6(v6("::ffff:10.0.0.5"), extra) == AddressClass::Private);
    CHECK(classify_ipv6(v6("2002:a00:5::1"), extra) == AddressClass::Private);
    // An address outside every prefix is untouched.
    CHECK(classify_ipv6(v6("2606:4700:4700::1111"), extra) == AddressClass::Public);
    CHECK(classify_ipv6(v6("2a0e:b107:122:345::1"), extra) == AddressClass::Public);
    CHECK(classify_ipv6(v6("fd00::1"), extra) == AddressClass::UniqueLocal);
    CHECK(classify_ipv6(v6("::1"), extra) == AddressClass::Loopback);
    // The one-argument form is the empty list.
    CHECK(classify_ipv6(v6("2a0e:b107:122:344:a9:fea9:fe00:0")) == AddressClass::Public);
    CHECK(classify_ipv6(v6("2a0e:b107:122:344:a9:fea9:fe00:0"), extra) == AddressClass::LinkLocal);
    // A prefix never relaxes an address the built-in rules already put in the never-allowed tier:
    // here fe80::/32 would "embed" 8.8.8.8 in bytes 4..7.
    const std::array<Nat64Prefix, 1> hostile{prefix("fe80::/32")};
    CHECK(classify_ipv6(v6("fe80:0:808:808::"), hostile) == AddressClass::LinkLocal);
    const std::array<Nat64Prefix, 1> multicast{prefix("ff00::/32")};
    CHECK(classify_ipv6(v6("ff00:0:808:808::"), multicast) == AddressClass::Multicast);
}

TEST_CASE("OIDC egress NAT64: overlapping prefixes - the strictest embedded class wins",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    // The /32 reads bytes 4..7 of an address, the /96 inside it reads bytes 12..15.
    const auto wide = prefix("2a0e:b107::/32");
    // bytes 4..7 = 8.8.8.8 (public), bytes 12..15 = 169.254.169.254 (link-local)
    const auto a = v6("2a0e:b107:808:808:0:0:a9fe:a9fe");
    const std::array<Nat64Prefix, 2> both{wide, prefix("2a0e:b107:808:808::/96")};
    const std::array<Nat64Prefix, 2> both_reversed{both[1], both[0]};
    CHECK(classify_ipv6(a, both) == AddressClass::LinkLocal);
    CHECK(classify_ipv6(a, both_reversed) == AddressClass::LinkLocal);
    // A private class beats a public one: /32 reads 10.0.0.5, /96 reads 8.8.8.8.
    const auto b = v6("2a0e:b107:a00:5:0:0:808:808");
    const std::array<Nat64Prefix, 2> mixed{wide, prefix("2a0e:b107:a00:5::/96")};
    const std::array<Nat64Prefix, 2> mixed_reversed{mixed[1], mixed[0]};
    CHECK(classify_ipv6(b, mixed) == AddressClass::Private);
    CHECK(classify_ipv6(b, mixed_reversed) == AddressClass::Private);
}

TEST_CASE("OIDC egress NAT64: prefix text parsing is strict", "[oidc][oidc_egress][oidc_nat64]") {
    for (const char* ok : {"2001:db8::/32", "2001:db8:100::/40", "2001:db8:122::/48",
                           "2001:db8:122:300::/56", "2001:db8:122:344::/64",
                           "2001:db8:122:344:5566:7788::/96", "64:ff9b::/96", "FD00:64::/32"}) {
        CAPTURE(ok);
        const auto p = parse_nat64_prefix(ok);
        REQUIRE(p.has_value());
        CHECK(std::to_string(p->length) == std::string(ok).substr(std::string(ok).rfind('/') + 1));
    }
    CHECK(prefix("2001:db8:122:344::/64").bytes == v6("2001:db8:122:344::"));
    for (const char* bad : {"",
                            "/64",
                            "2001:db8::",
                            "2001:db8::/",
                            "2001:db8::/0",
                            "2001:db8::/8",
                            "2001:db8::/24",
                            "2001:db8::/33",
                            "2001:db8::/65",
                            "2001:db8::/95",
                            "2001:db8::/97",
                            "2001:db8::/112",
                            "2001:db8::/128",
                            "2001:db8::/0032",
                            "2001:db8::/032",
                            "2001:db8::/+32",
                            "2001:db8::/-32",
                            "2001:db8::/32 ",
                            " 2001:db8::/32",
                            "2001:db8::/3x",
                            "2001:db8::/32/32",
                            "2001:db8::/3200",
                            "2001:db8::1/32",              // host bits set
                            "2001:db8:122:344::1/64",      // host bits set
                            "2001:db8:122:344:1::/64",     // host bit just past the prefix
                            "2001:db8:122:344:0:0:0:1/96", // host bits set (byte 15)
                            "192.0.2.0/24",
                            "192.0.2.0/32",
                            "[2001:db8::]/32",
                            "fe80::1%eth0/32",
                            "2001:db8:::/32",
                            "2001:db8::g/32",
                            "garbage",
                            "2001:db8::/32,2001:db8:100::/40"}) {
        CAPTURE(bad);
        CHECK_FALSE(parse_nat64_prefix(bad).has_value());
    }
}

TEST_CASE("OIDC egress NAT64: the operator list", "[oidc][oidc_egress][oidc_nat64]") {
    const auto empty = parse_nat64_prefix_list("");
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
    CHECK(parse_nat64_prefix_list("   ")->empty());

    const auto one = parse_nat64_prefix_list("2001:db8:122:344::/64");
    REQUIRE(one.has_value());
    CHECK(one->size() == 1);

    const auto two = parse_nat64_prefix_list(" 2001:db8::/32 ,\t2a0e:b107:122::/48 ");
    REQUIRE(two.has_value());
    REQUIRE(two->size() == 2);
    CHECK((*two)[0].length == 32);
    CHECK((*two)[1].length == 48);

    for (const char* bad : {",", "2001:db8::/32,", ",2001:db8::/32", "2001:db8::/32,,2a0e::/32",
                            "2001:db8::/32,nonsense", "2001:db8::/33", "2001:db8::1/32",
                            "2001:db8::/32 2a0e::/32", "2001:db8::/32;2a0e::/32"}) {
        CAPTURE(bad);
        CHECK_FALSE(parse_nat64_prefix_list(bad).has_value());
    }
    // The count is bounded.
    std::string many;
    for (std::size_t i = 0; i < kMaxNat64Prefixes; ++i)
        many += (i ? ",2a0e:b107::/32" : "2a0e:b107::/32");
    CHECK(parse_nat64_prefix_list(many).has_value());
    CHECK_FALSE(parse_nat64_prefix_list(many + ",2a0e:b107::/32").has_value());
}

TEST_CASE("OIDC egress NAT64: RFC 7050 discovery from the ipv4only.arpa answer",
          "[oidc][oidc_egress][oidc_nat64]") {
    for (const int length : kLengths) {
        for (const char* wk : {"192.0.0.170", "192.0.0.171"}) {
            CAPTURE(length, wk);
            const auto pfx = mask_to(v6("2001:db8:122:344:5566:7788:99aa:bbcc"), length);
            const auto answer = synthesize(pfx, length, v4(wk));
            const auto found = discover_prefix_from_ipv4only_answer(answer);
            REQUIRE(found.has_value());
            CHECK(found->length == length);
            CHECK(found->bytes == pfx);
            // The learned prefix decodes a metadata address under the same layout.
            const std::array<Nat64Prefix, 1> extra{*found};
            CHECK(classify_ipv6(synthesize(pfx, length, v4("169.254.169.254")), extra) ==
                  AddressClass::LinkLocal);
        }
    }
    // Suffix bits in the answer are not part of the learned prefix.
    {
        const auto pfx = mask_to(v6("2a0e:b107:122:344::"), 64);
        const auto answer = synthesize(pfx, 64, v4("192.0.0.170"), 0, 0x55);
        const auto found = discover_prefix_from_ipv4only_answer(answer);
        REQUIRE(found.has_value());
        CHECK(found->length == 64);
        CHECK(found->bytes == pfx);
    }
    // The well-known prefix is discoverable too (and already decoded by the built-in rules).
    {
        const auto found = discover_prefix_from_ipv4only_answer(v6("64:ff9b::c000:aa"));
        REQUIRE(found.has_value());
        CHECK(found->length == 96);
    }
}

TEST_CASE("OIDC egress NAT64: RFC 7050 discovery refuses what is not an unambiguous answer",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    // Not an ipv4only.arpa answer.
    CHECK_FALSE(discover_prefix_from_ipv4only_answer(v6("2001:db8::1")).has_value());
    CHECK_FALSE(discover_prefix_from_ipv4only_answer(v6("::")).has_value());
    CHECK_FALSE(discover_prefix_from_ipv4only_answer(v6("2606:4700:4700::1111")).has_value());
    // Embeds a neighbour of the well-known addresses, at every length.
    for (const int length : kLengths)
        for (const char* neighbour : {"192.0.0.169", "192.0.0.172", "192.0.2.170", "193.0.0.170"}) {
            CAPTURE(length, neighbour);
            CHECK_FALSE(
                discover_prefix_from_ipv4only_answer(
                    synthesize(mask_to(v6("2a0e:b107:122:344::"), length), length, v4(neighbour)))
                    .has_value());
        }
    // A non-zero u octet is not a legal /32../64 layout.
    for (const int length : {32, 40, 48, 56, 64}) {
        CAPTURE(length);
        CHECK_FALSE(discover_prefix_from_ipv4only_answer(
                        synthesize(mask_to(v6("2a0e:b107:122:344::"), length), length,
                                   v4("192.0.0.170"), 0x01))
                        .has_value());
    }
    // Two lengths fit at once (192.0.0.170 at bytes 4..7 AND at bytes 12..15): ambiguous.
    CHECK_FALSE(
        discover_prefix_from_ipv4only_answer(v6("2a0e:b107:c000:aa:0:0:c000:aa")).has_value());
}
