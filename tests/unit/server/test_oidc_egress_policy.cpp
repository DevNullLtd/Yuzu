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

#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
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

#ifndef _WIN32
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
#endif

TEST_CASE("OIDC egress: class names are fixed labels that carry no address",
          "[oidc][oidc_egress]") {
    CHECK(std::string(class_name(AddressClass::Loopback)) == "loopback");
    CHECK(std::string(class_name(AddressClass::LinkLocal)) == "link-local");
    CHECK(std::string(class_name(AddressClass::CloudMetadata)) == "cloud-metadata");
    CHECK(std::string(class_name(static_cast<AddressClass>(200))) == "unknown");
}
