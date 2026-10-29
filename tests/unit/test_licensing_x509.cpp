/**
 * test_licensing_x509.cpp -- vectors for licensing_x509.hpp, the pure
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
 *   vec-a     20250101000000Z   20270304120000Z   UTCTime          1804118400  (date -u of 2027-03-04)
 *   vec-b     20250101000000Z   20281231235959Z   UTCTime          1861833600
 *   vec-c     20250101000000Z   20260101000000Z   UTCTime          1767225600
 *   vec-d     20250101000000Z   21000101000000Z   GeneralizedTime  4102444800
 *   vec-e     19600101000000Z   19691231000000Z   UTCTime          (before the epoch: refused)
 *
 * Expected values were computed independently of the code under test with
 * Python `calendar.timegm((Y, M, D, 0, 0, 0))`, and the notAfter of each
 * certificate confirmed with `openssl x509 -noout -enddate` /
 * `openssl asn1parse`.
 *
 * The ENCRYPTED-header vector is SYNTHETIC too: a CERTIFICATE block carrying
 * `Proc-Type: 4,ENCRYPTED` / `DEK-Info:` headers over 32 zero bytes of base64.
 * The reader must reject it before any decryption is attempted, so no real
 * ciphertext is needed.
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
MIIBdTCCARugAwIBAgIUejCOkM8eyApdOeDppHzps96mzcQwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFdmVjLWEwHhcNMjUwMTAxMDAwMDAwWhcNMjcwMzA0MTIwMDAw
WjAQMQ4wDAYDVQQDDAV2ZWMtYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLOd
yQNNWnAknpSw3pCVtj8fmMoBNRqWXzkZpOmxVheyOVuUKT2GtVjV0FPGItXiaH/J
LEtNrq8KOW+8zWw1XNajUzBRMB0GA1UdDgQWBBS/RlvsrG9pxajxItoVeUDX7o9k
PDAfBgNVHSMEGDAWgBS/RlvsrG9pxajxItoVeUDX7o9kPDAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQCfYxpVoN54hV452cG/sGXZoV+HoBwcd7vn
gDVLoL30dQIgaTGJkGC/1H39PtQAUc2uoj8P8oxAfRyfNByqNDpbJas=
-----END CERTIFICATE-----
)";

constexpr const char* kCertB = R"(-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIULQ9OboABxbWpSPdL6lSxD9PlCAMwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFdmVjLWIwHhcNMjUwMTAxMDAwMDAwWhcNMjgxMjMxMjM1OTU5
WjAQMQ4wDAYDVQQDDAV2ZWMtYjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAfz
gnJeSi7mFXo0TuSlkHAmgIuZozJPAYi6/uPUUitq9sajFWP6iHtRnlZReoaaqBS3
RjvdCzfN3LCnrQ2g5UejUzBRMB0GA1UdDgQWBBSVpaOJdtOCpDr8TMKasSvGcJUU
OzAfBgNVHSMEGDAWgBSVpaOJdtOCpDr8TMKasSvGcJUUOzAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQCdnMYUx4nTloLGFhr4hl9W0UCRR8381OMY
Jp/hhoKbQAIgSKoYyX08hbnlJ9UmsAbhFO8t2x3j+cgwfFE/FwlwZfg=
-----END CERTIFICATE-----
)";

constexpr const char* kCertC = R"(-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIUKsJdM+9HqYmP6bhDLh2BLSPFxYkwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFdmVjLWMwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAw
WjAQMQ4wDAYDVQQDDAV2ZWMtYzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDil
8GoAX1fXot0p9HNwI26ZVTbd0BPm9oBWyG7PFyBmmOER5gOX6VZ9zY8s3GLdNplj
ZED5opEJLaTDJtQYLiejUzBRMB0GA1UdDgQWBBQOBGSz4xOYWOVD6OeHf9lcLoew
ZTAfBgNVHSMEGDAWgBQOBGSz4xOYWOVD6OeHf9lcLoewZTAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQC4NayBhsD+W9ze7erd1x4e/Wrla+8le+ds
rPVXE4L+cgIgRfJz3fCPA6ZE+vXHvj6hB91XILT4mGWT0Cu9C3WhhRs=
-----END CERTIFICATE-----
)";

constexpr const char* kCertD2100 = R"(-----BEGIN CERTIFICATE-----
MIIBdjCCAR2gAwIBAgIUaNceqrGQOFdHh6VFONJG94qnwCUwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFdmVjLWQwIBcNMjUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAw
MDBaMBAxDjAMBgNVBAMMBXZlYy1kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
T0DO8aGQgOc9IF9jBZ+LzoLg9jax60l21NoXofjZQ8iyeP4yzgYKjuI4pzyfY0S2
l8hkcetLe0Y2GNreGKMtT6NTMFEwHQYDVR0OBBYEFC5gyUWAEil/2O3FE6BR3FDk
Y/wUMB8GA1UdIwQYMBaAFC5gyUWAEil/2O3FE6BR3FDkY/wUMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgJn83dTUs2Vh0F+iRFCEUNYU0Tib5PDjH
M2cU1aDJtMoCIH7REMkMnM+qvAgmDlxnJxmcIWhdN8tr6WL3e85jTri6
-----END CERTIFICATE-----
)";

// notAfter 1969-12-31: an epoch <= 0 has no wire encoding, so it is refused.
constexpr const char* kCertPreEpoch = R"(-----BEGIN CERTIFICATE-----
MIIBdDCCARugAwIBAgIUJVmd56d4zxr5RtunFc+8gVsHBIQwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFdmVjLWUwHhcNNjAwMTAxMDAwMDAwWhcNNjkxMjMxMDAwMDAw
WjAQMQ4wDAYDVQQDDAV2ZWMtZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABASp
VKv4IkQekNmdKvuQdL66MjTWVRFyyB4WuNKdzusVPk4Bgm0hwQa3DK69W4VydX6m
nNB2eQd+EZ8WTj4+JaejUzBRMB0GA1UdDgQWBBTqkD2ESX/zAxT5e9LNLr3HvPMm
NDAfBgNVHSMEGDAWgBTqkD2ESX/zAxT5e9LNLr3HvPMmNDAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0cAMEQCIFgchyqAQYPgDBysRvVp04KdnNWJdzBB50r6
5RGaETuOAiAQBbzbZypSJQcNros+X3eKLtD1YO69HlQzWYpB6VlJgg==
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

TEST_CASE("licensing_x509: an ENCRYPTED block is a parse failure and never a passphrase prompt",
          "[licensing][x509]") {
    // Without a password callback OpenSSL's default one reads a passphrase from
    // the process's stdin (a daemon holding an open pipe blocks on it). The
    // no-op callback must make this fail fast instead. Nothing here touches
    // stdin or a terminal; the case also holds when stdin is an open pipe.
    const std::string encrypted =
        "-----BEGIN CERTIFICATE-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
        "\n" +
        std::string(43, 'A') + "=\n"
        "-----END CERTIFICATE-----\n";

    const PemNotAfter alone = parse_pem_not_after(encrypted, 16);
    CHECK(alone.expires_wire.empty());
    CHECK(alone.parse_failure);
    CHECK_FALSE(alone.cert_cap_hit);

    // A readable certificate before it is kept; the encrypted one fails the file.
    const PemNotAfter after = parse_pem_not_after(std::string(kCertA) + encrypted, 16);
    CHECK(after.expires_wire == std::vector<std::string>{kWireA});
    CHECK(after.parse_failure);
}
