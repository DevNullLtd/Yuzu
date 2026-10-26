/**
 * test_licensing_x509.cpp -- vectors for licensing_x509.hpp (SAM.10), the pure
 * in-process PEM -> notAfter reader that replaced the `openssl x509 -enddate`
 * subprocess on the license_scan Linux entitlement_certs surface.
 *
 * Every case runs over an in-memory PEM string: no filesystem, no subprocess,
 * so it is portable and deterministic on every OS leg (the test exe links
 * OpenSSL on all of them, like test_certificates_x509.cpp).
 *
 * Provenance of the embedded certificates: generated 2026-10-26 with the host
 * OpenSSL 3.6.4 at /opt/homebrew/opt/openssl@3/bin/openssl (NOT the system
 * LibreSSL), one self-signed P-256 certificate each, the private key
 * discarded (`-keyout /dev/null`):
 *
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
 *       -keyout /dev/null -subj "/CN=<name>" -not_before <nb> -not_after <na>
 *
 *   name      notBefore         notAfter          encoding         wire (epoch at 00:00:00 UTC)
 *   sam10-a   20250101000000Z   20270304120000Z   UTCTime          1804118400  (date -u of 2027-03-04)
 *   sam10-b   20250101000000Z   20281231235959Z   UTCTime          1861833600
 *   sam10-c   20250101000000Z   20260101000000Z   UTCTime          1767225600
 *   sam10-d   20250101000000Z   21000101000000Z   GeneralizedTime  4102444800
 *   sam10-e   19600101000000Z   19691231000000Z   UTCTime          (before the epoch: refused)
 *
 * Expected values were computed independently of the code under test with
 * Python `calendar.timegm((Y, M, D, 0, 0, 0))`, and the notAfter of each
 * certificate confirmed with `openssl x509 -noout -enddate` /
 * `openssl asn1parse`.
 *
 * The ENTITLEMENT DATA / RSA SIGNATURE blocks are SYNTHETIC (a base64 of a
 * plain sentence, no key material): they reproduce the shape of a Red Hat
 * entitlement file, where those blocks follow the certificate.
 */

#include <catch2/catch_test_macros.hpp>

#include <licensing_x509.hpp>

#include <string>
#include <vector>

using yuzu::license_scan::parse_pem_not_after;
using yuzu::license_scan::PemNotAfter;

namespace {

constexpr const char* kCertA = R"(-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUErPFZG+tXlGd7jAGQUOJxOYYL+MwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYTAeFw0yNTAxMDEwMDAwMDBaFw0yNzAzMDQxMjAw
MDBaMBIxEDAOBgNVBAMMB3NhbTEwLWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAS7cbHHKFc0DycuXJcynDgJkXpW1bHT7Ab/SXVLKxsArDn65ZW6HndpT/5sEXuW
rYj5G7fKEF9fB1GqqQl42v6Yo1MwUTAdBgNVHQ4EFgQUe9jUh5URCGln+inE8CnT
dkuYA2AwHwYDVR0jBBgwFoAUe9jUh5URCGln+inE8CnTdkuYA2AwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA5cZ0ujBp7EQ3Gf/GDdL7adHS8J3B
2KSyJ30d+efrGmwCIQDLuuO8ASAcRspYmRewnUuWJqHYgDWVzSF10b3I8w3/Cw==
-----END CERTIFICATE-----
)";

constexpr const char* kCertB = R"(-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUG2hF+CO5yCUdiklVS1nEt54UaUIwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYjAeFw0yNTAxMDEwMDAwMDBaFw0yODEyMzEyMzU5
NTlaMBIxEDAOBgNVBAMMB3NhbTEwLWIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARou+gyal15dHQtIQ2Rh/qk9upcgB5vpxSbYsqq5xmDxKazQqNzEtnAQly31wbl
CW8rk+JjdIscH4TZgIXBZjhYo1MwUTAdBgNVHQ4EFgQU7u110fvuqDuGG+mDlj9R
K+4wkgAwHwYDVR0jBBgwFoAU7u110fvuqDuGG+mDlj9RK+4wkgAwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA2FwkyfUv+Mi3+HbtkxNFn5cFsqxq
1IjYrPzVzRJcoUICIQDr635iRaHq+Q0pJ+JV6M1Vx1nbADaHCB1Jj88gf+wTqA==
-----END CERTIFICATE-----
)";

constexpr const char* kCertC = R"(-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIULDo9j7hKsENBKP88Cw7e9FwExQ0wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYzAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAw
MDBaMBIxEDAOBgNVBAMMB3NhbTEwLWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASPZOcZlvYOzSXEiQNyClG62jbH/L1ukSsg0ke6lU3q1W37WLsnw2NdnKMkAfk7
qwQ4BbcJEUbVs+NDhLDi++kpo1MwUTAdBgNVHQ4EFgQUHzNX+dLOY+n/XcoHtypa
Zekhs5UwHwYDVR0jBBgwFoAUHzNX+dLOY+n/XcoHtypaZekhs5UwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA9+dJgYbyXj5OOjUKj4EawU50qYB8
3TbPJM+nY/5f6HsCICI0qLsd3Vwp26okKdnjqCSaXlYVJKuHyEcz9PXIw7mQ
-----END CERTIFICATE-----
)";

constexpr const char* kCertD2100 = R"(-----BEGIN CERTIFICATE-----
MIIBfDCCASGgAwIBAgIUaedAmIAiPL6rM288ZJvLbCN9RuowCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtZDAgFw0yNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAw
MDAwMFowEjEQMA4GA1UEAwwHc2FtMTAtZDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNQf0U9qemoxRWiVOFRrwtZrXuYAaJbq/WCeQR+Y1vPwVnW0EyjZaD48NtW3
lErRQIcvgiGISgGAcu1v4npLpnqjUzBRMB0GA1UdDgQWBBQgj1pDhPUoOyNGLz6k
qGASUM9jkjAfBgNVHSMEGDAWgBQgj1pDhPUoOyNGLz6kqGASUM9jkjAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCTI997wmQgKpChyE308AJrL9KL
/GC1s+4mp3uPMqrJzgIhAMIT8Et4lMjYHR3Oebhucb2OGBpt2c+3TJek1Kz7lUyL
-----END CERTIFICATE-----
)";

// notAfter 1969-12-31: an epoch <= 0 has no wire encoding, so it is refused.
constexpr const char* kCertPreEpoch = R"(-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUFQ47aRRKHLNR2nDeSqXY8i3sNEMwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtZTAeFw02MDAxMDEwMDAwMDBaFw02OTEyMzEwMDAw
MDBaMBIxEDAOBgNVBAMMB3NhbTEwLWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQzsz/Ene6DKiExxaY7wJZU2xcWlu2VHWyC3MGWu3PSWvkg/dyn9w+2gxXMpB7S
YRNUT9guq+cwTeNBEybg8GQfo1MwUTAdBgNVHQ4EFgQUl9TcdlhF2RMWXsHeIsz2
HyjoIiMwHwYDVR0jBBgwFoAUl9TcdlhF2RMWXsHeIsz2HyjoIiMwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAnFs8LV2bVxKu7Ar3WMZ3L75gJ+5Y
N2JE2DQA3aHuQfcCIQCoQmbRfj87bVV5TwJqbzlKs+2xaM2o044JJyfUrbL+fg==
-----END CERTIFICATE-----
)";

// SYNTHETIC non-certificate blocks, the shape Red Hat appends to a certificate.
constexpr const char* kEntitlementData = R"(-----BEGIN ENTITLEMENT DATA-----
c3ludGhldGljIGVudGl0bGVtZW50IGRhdGEsIG5vdCBhIHJlYWwgcGF5bG9hZA==
-----END ENTITLEMENT DATA-----
)";
constexpr const char* kRsaSignature = R"(-----BEGIN RSA SIGNATURE-----
c3ludGhldGljIHNpZ25hdHVyZSBieXRlcywgbm90IHJlYWw=
-----END RSA SIGNATURE-----
)";

constexpr const char* kWireA = "1804118400";
constexpr const char* kWireB = "1861833600";
constexpr const char* kWireC = "1767225600";
constexpr const char* kWireD2100 = "4102444800";

std::string repeat(const std::string& s, int n) {
    std::string out;
    for (int i = 0; i < n; ++i)
        out += s;
    return out;
}

} // namespace

TEST_CASE("licensing_x509: a single certificate yields its UTC-midnight epoch", "[licensing][x509]") {
    const PemNotAfter r = parse_pem_not_after(kCertA, 16);
    REQUIRE(r.expires_wire.size() == 1);
    // notAfter 2027-03-04T12:00:00Z truncates to midnight.
    CHECK(r.expires_wire[0] == kWireA);
    CHECK_FALSE(r.parse_failure);
    CHECK_FALSE(r.cert_cap_hit);
}

TEST_CASE("licensing_x509: a bundle yields one value per certificate in file order",
          "[licensing][x509]") {
    const std::string bundle = std::string(kCertA) + kCertB + kCertC;
    const PemNotAfter r = parse_pem_not_after(bundle, 16);
    CHECK(r.expires_wire == std::vector<std::string>{kWireA, kWireB, kWireC});
    CHECK_FALSE(r.parse_failure);
    CHECK_FALSE(r.cert_cap_hit);
}

TEST_CASE("licensing_x509: GeneralizedTime (year 2100) parses", "[licensing][x509]") {
    const PemNotAfter r = parse_pem_not_after(kCertD2100, 16);
    CHECK(r.expires_wire == std::vector<std::string>{kWireD2100});
    CHECK_FALSE(r.parse_failure);
}

TEST_CASE("licensing_x509: the per-file certificate cap is exact", "[licensing][x509]") {
    // Exactly the cap: all read, nothing left unexamined.
    const PemNotAfter exact = parse_pem_not_after(repeat(kCertA, 16), 16);
    CHECK(exact.expires_wire.size() == 16);
    CHECK_FALSE(exact.cert_cap_hit);
    CHECK_FALSE(exact.parse_failure);

    // One more: the first 16 are kept, the 17th is reported as unexamined.
    const PemNotAfter over = parse_pem_not_after(repeat(kCertA, 17), 16);
    CHECK(over.expires_wire.size() == 16);
    CHECK(over.cert_cap_hit);
    CHECK_FALSE(over.parse_failure);
}

TEST_CASE("licensing_x509: Red Hat's trailing non-certificate blocks are skipped, not errors",
          "[licensing][x509]") {
    const std::string file = std::string(kCertA) + kEntitlementData + kRsaSignature;
    const PemNotAfter r = parse_pem_not_after(file, 16);
    CHECK(r.expires_wire == std::vector<std::string>{kWireA});
    CHECK_FALSE(r.parse_failure);
    CHECK_FALSE(r.cert_cap_hit);

    // Interleaved: a non-certificate block BEFORE the certificate is skipped too.
    const PemNotAfter lead = parse_pem_not_after(std::string(kEntitlementData) + kCertB, 16);
    CHECK(lead.expires_wire == std::vector<std::string>{kWireB});
    CHECK_FALSE(lead.parse_failure);
}

TEST_CASE("licensing_x509: input with no certificate is a failure, never an empty success",
          "[licensing][x509]") {
    for (const std::string& input :
         {std::string{}, std::string("this is not a PEM file\n"),
          std::string(kEntitlementData) + kRsaSignature}) {
        INFO("input: " << input);
        const PemNotAfter r = parse_pem_not_after(input, 16);
        CHECK(r.expires_wire.empty());
        CHECK(r.parse_failure);
        CHECK_FALSE(r.cert_cap_hit);
    }
}

TEST_CASE("licensing_x509: a CERTIFICATE block that is not a certificate is a failure",
          "[licensing][x509]") {
    const PemNotAfter bad = parse_pem_not_after(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 16);
    CHECK(bad.expires_wire.empty());
    CHECK(bad.parse_failure);

    // Bad base64 inside the block.
    const PemNotAfter b64 = parse_pem_not_after(
        "-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n", 16);
    CHECK(b64.expires_wire.empty());
    CHECK(b64.parse_failure);
}

TEST_CASE("licensing_x509: a valid certificate then a truncated block keeps the first and fails",
          "[licensing][x509]") {
    // PEM_R_NO_START_LINE is the ONLY clean end of input: a second block that
    // starts but never ends is a real parse error, not "no more certificates".
    const std::string second(kCertB);
    const std::string truncated = second.substr(0, second.find("-----END"));
    const PemNotAfter r = parse_pem_not_after(std::string(kCertA) + truncated, 16);
    CHECK(r.expires_wire == std::vector<std::string>{kWireA});
    CHECK(r.parse_failure);
    CHECK_FALSE(r.cert_cap_hit);

    // A valid certificate then a corrupt (decodes to nothing) block: same.
    const PemNotAfter corrupt = parse_pem_not_after(
        std::string(kCertA) + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 16);
    CHECK(corrupt.expires_wire == std::vector<std::string>{kWireA});
    CHECK(corrupt.parse_failure);
}

TEST_CASE("licensing_x509: a notAfter before the Unix epoch is a failure with no row",
          "[licensing][x509]") {
    const PemNotAfter r = parse_pem_not_after(kCertPreEpoch, 16);
    CHECK(r.expires_wire.empty());
    CHECK(r.parse_failure);

    // It does not poison its neighbours: the valid certificate still yields.
    const PemNotAfter mixed = parse_pem_not_after(std::string(kCertPreEpoch) + kCertA, 16);
    CHECK(mixed.expires_wire == std::vector<std::string>{kWireA});
    CHECK(mixed.parse_failure);
}
