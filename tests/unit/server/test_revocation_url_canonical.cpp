/**
 * test_revocation_url_canonical.cpp -- the ONE canonical form of a registered CRL URL (owner ruling
 * on #6590, 2026-11-18): scheme and host lowercased, default port dropped, leading port zeros
 * stripped, an IPv6 literal in RFC 5952 form, an empty path as `/`, the path and query kept byte
 * for byte. Pure: no store, no network.
 */

#include "revocation_url_canonical.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace rs = yuzu::server::revocation_source;
namespace eg = yuzu::server::oidc::egress;

namespace {
std::string canon(const std::string& url) {
    const auto c = rs::canonical_crl_url(url);
    return c ? c->url : std::string("<none>");
}
std::string v6(const std::string& text) {
    const auto b = eg::parse_ipv6(text);
    return b ? rs::format_ipv6_rfc5952(*b) : std::string("<bad>");
}
} // namespace

TEST_CASE("CRL URL canonical form: scheme, host, port and empty path", "[revocation_source][canonical]") {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"http://crl.example.com/a.crl", "http://crl.example.com/a.crl"},
        {"HTTP://CRL.Example.COM/a.crl", "http://crl.example.com/a.crl"},
        {"http://crl.example.com:80/a.crl", "http://crl.example.com/a.crl"},
        {"https://crl.example.com:443/a.crl", "https://crl.example.com/a.crl"},
        {"http://crl.example.com:0080/a.crl", "http://crl.example.com/a.crl"},
        {"http://crl.example.com:00443/a.crl", "http://crl.example.com:443/a.crl"}, // 443 is not http's
        {"https://crl.example.com:80/a.crl", "https://crl.example.com:80/a.crl"},
        {"http://crl.example.com:08080/a.crl", "http://crl.example.com:8080/a.crl"},
        {"http://crl.example.com", "http://crl.example.com/"},
        {"http://crl.example.com:80", "http://crl.example.com/"},
        {"http://crl.example.com?x=1", "http://crl.example.com/?x=1"},
        {"http://10.0.0.5:8080", "http://10.0.0.5:8080/"},
    };
    for (const auto& [in, want] : cases) {
        INFO(in);
        CHECK(canon(in) == want);
        CHECK(canon(want) == want); // idempotent
    }
    const auto c = rs::canonical_crl_url("HTTP://CRL.Example.COM:80");
    REQUIRE(c.has_value());
    CHECK(c->host == "crl.example.com");
}

TEST_CASE("CRL URL canonical form: the path and query keep their case and percent-encoding",
          "[revocation_source][canonical]") {
    CHECK(canon("http://h.example/CRL/Issuing%2fCA.crl") == "http://h.example/CRL/Issuing%2fCA.crl");
    CHECK(canon("http://h.example/a%7Eb?Q=%2F&x=Y") == "http://h.example/a%7Eb?Q=%2F&x=Y");
    CHECK(canon("http://h.example/a/../b/./c") == "http://h.example/a/../b/./c"); // no dot removal
    CHECK(canon("http://h.example//a") == "http://h.example//a");
    CHECK(canon("http://h.example/a") != canon("http://h.example/A"));
}

TEST_CASE("CRL URL canonical form: an IPv6 literal in RFC 5952 form", "[revocation_source][canonical]") {
    CHECK(canon("http://[2001:DB8:0:0:0:0:0:1]/a") == "http://[2001:db8::1]/a");
    CHECK(canon("http://[2001:0db8::0001]:80/a") == "http://[2001:db8::1]/a");
    CHECK(canon("https://[2001:db8::1]:8443") == "https://[2001:db8::1]:8443/");
    const auto c = rs::canonical_crl_url("http://[2001:DB8::1]/a");
    REQUIRE(c.has_value());
    CHECK(c->host == "2001:db8::1");
    // RFC 5952 section 4: no leading zeros, the longest zero run, the first on a tie, never a
    // single field, lowercase; section 5: IPv4-mapped in mixed notation.
    CHECK(v6("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1");
    CHECK(v6("2001:db8:0:1:0:0:0:1") == "2001:db8:0:1::1");      // the longer run
    CHECK(v6("2001:db8:0:0:1:0:0:1") == "2001:db8::1:0:0:1");    // the first of two equal runs
    CHECK(v6("2001:db8:0:1:1:1:1:1") == "2001:db8:0:1:1:1:1:1"); // a single zero field stays
    CHECK(v6("0:0:0:0:0:0:0:0") == "::");
    CHECK(v6("0:0:0:0:0:0:0:1") == "::1");
    CHECK(v6("1:0:0:0:0:0:0:0") == "1::");
    CHECK(v6("2001:DB8:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF") == "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff");
    CHECK(v6("::FFFF:C000:0201") == "::ffff:192.0.2.1");
    CHECK(v6("::ffff:192.0.2.1") == "::ffff:192.0.2.1");
    CHECK(v6("64:ff9b::c000:201") == "64:ff9b::c000:201");
}

TEST_CASE("CRL URL canonical form: what it cannot put in the form", "[revocation_source][canonical]") {
    for (const char* bad : {"", "crl.example.com/a", "ftp://h/a", "ldap://h/a", "http:///a", "http://:80/a",
                            "http://u@h/a", "http://h:/a", "http://h:0/a", "http://h:65536/a",
                            "http://h:123456/a", "http://h:8a/a", "http://[2001:db8::1/a",
                            "http://[2001:db8::1]x/a", "http://[fe80::1%25eth0]/a", "http://[zz::1]/a",
                            "http://2001:db8::1/a", "http://[]/a"}) {
        INFO(bad);
        CHECK_FALSE(rs::canonical_crl_url(bad).has_value());
    }
}
