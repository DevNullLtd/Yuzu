/**
 * test_certificates_crypto_profile.cpp -- vectors for
 * certificates_crypto_profile.hpp, the pure OID -> key/signature algorithm
 * naming every certificates plugin leg shares (libcrypto on Linux/macOS,
 * CryptoAPI on Windows). No OpenSSL, no CryptoAPI, no I/O: runs on every OS.
 *
 * The OID/name pairs asserted below were checked against python-cryptography
 * 50.0.1 on 2026-10-16 -- SignatureAlgorithmOID, PublicKeyAlgorithmOID and
 * ec._OID_TO_CURVE (name and key_size) -- except ML-KEM-512
 * (2.16.840.1.101.3.4.4.1), which that release does not define; its OID is
 * NIST CSOR's, the sibling of ML-KEM-768/1024 (.4.4.2/.4.4.3) which it does.
 * The two DER OID encodings are the curve parameters of the P-256 and P-384
 * fixtures in test_certificates_x509.cpp, read straight from their SPKI.
 */

#include <catch2/catch_test_macros.hpp>

#include <certificates_crypto_profile.hpp>

#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using yuzu::certificates_crypto::der_oid_to_dotted;
using yuzu::certificates_crypto::describe;
using yuzu::certificates_crypto::is_dotted_oid;

namespace {

std::span<const unsigned char> bytes(const std::vector<unsigned char>& v) {
    return std::span<const unsigned char>(v.data(), v.size());
}

constexpr std::string_view kRsa = "1.2.840.113549.1.1.1";
constexpr std::string_view kEc = "1.2.840.10045.2.1";
constexpr std::string_view kSha256Rsa = "1.2.840.113549.1.1.11";

} // namespace

// ── is_dotted_oid ───────────────────────────────────────────────────────────

TEST_CASE("is_dotted_oid accepts well-formed dotted OIDs", "[certificates_crypto]") {
    CHECK(is_dotted_oid("1.2"));
    CHECK(is_dotted_oid("1.2.840.113549.1.1.1"));
    CHECK(is_dotted_oid("2.16.840.1.101.3.4.3.17"));
}

TEST_CASE("is_dotted_oid rejects anything that could inject or mislead", "[certificates_crypto]") {
    CHECK_FALSE(is_dotted_oid(""));
    CHECK_FALSE(is_dotted_oid("1"));          // a single arc is not an OID
    CHECK_FALSE(is_dotted_oid(".1.2"));       // leading dot
    CHECK_FALSE(is_dotted_oid("1.2."));       // trailing dot
    CHECK_FALSE(is_dotted_oid("1..2"));       // empty arc
    CHECK_FALSE(is_dotted_oid("rsaEncryption"));
    CHECK_FALSE(is_dotted_oid("1.2|3.4"));    // row-delimiter injection
    CHECK_FALSE(is_dotted_oid("1.2\n3.4"));   // row injection
    CHECK_FALSE(is_dotted_oid("1.2 "));
    CHECK_FALSE(is_dotted_oid(std::string(70, '1') + ".2")); // over kMaxDottedOidLength
}

// ── der_oid_to_dotted ───────────────────────────────────────────────────────

TEST_CASE("der_oid_to_dotted decodes real curve parameters", "[certificates_crypto]") {
    // P-256 (prime256v1) namedCurve, from kEcdsaCertPem's SPKI.
    std::vector<unsigned char> p256{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    CHECK(der_oid_to_dotted(bytes(p256)) == "1.2.840.10045.3.1.7");
    // P-384 (secp384r1) namedCurve, from kEcdsaP384CertPem's SPKI.
    std::vector<unsigned char> p384{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    CHECK(der_oid_to_dotted(bytes(p384)) == "1.3.132.0.34");
}

TEST_CASE("der_oid_to_dotted splits the first subidentifier per X.690", "[certificates_crypto]") {
    // 0x55 = 85 -> arcs 2.5 (85 >= 80); 2.5.4.3 is id-at-commonName.
    std::vector<unsigned char> cn{0x06, 0x03, 0x55, 0x04, 0x03};
    CHECK(der_oid_to_dotted(bytes(cn)) == "2.5.4.3");
    // 0x00 -> 0.0
    std::vector<unsigned char> zero{0x06, 0x01, 0x00};
    CHECK(der_oid_to_dotted(bytes(zero)) == "0.0");
}

TEST_CASE("der_oid_to_dotted rejects malformed or non-OID DER", "[certificates_crypto]") {
    std::vector<unsigned char> empty;
    CHECK_FALSE(der_oid_to_dotted(bytes(empty)));
    std::vector<unsigned char> null_params{0x05, 0x00}; // RSA's NULL parameters
    CHECK_FALSE(der_oid_to_dotted(bytes(null_params)));
    std::vector<unsigned char> wrong_tag{0x04, 0x03, 0x55, 0x04, 0x03};
    CHECK_FALSE(der_oid_to_dotted(bytes(wrong_tag)));
    std::vector<unsigned char> short_len{0x06, 0x04, 0x55, 0x04, 0x03};
    CHECK_FALSE(der_oid_to_dotted(bytes(short_len)));
    std::vector<unsigned char> trailing{0x06, 0x03, 0x55, 0x04, 0x03, 0x00};
    CHECK_FALSE(der_oid_to_dotted(bytes(trailing)));
    std::vector<unsigned char> zero_len{0x06, 0x00, 0x00};
    CHECK_FALSE(der_oid_to_dotted(bytes(zero_len)));
    std::vector<unsigned char> dangling{0x06, 0x02, 0x2A, 0x86}; // last byte continues
    CHECK_FALSE(der_oid_to_dotted(bytes(dangling)));
    std::vector<unsigned char> non_minimal{0x06, 0x03, 0x2A, 0x80, 0x01};
    CHECK_FALSE(der_oid_to_dotted(bytes(non_minimal)));
    std::vector<unsigned char> long_form_small{0x06, 0x81, 0x03, 0x55, 0x04, 0x03};
    CHECK_FALSE(der_oid_to_dotted(bytes(long_form_small))); // DER requires short form here
    // One arc of eleven 0xFF continuation bytes overflows 64 bits.
    std::vector<unsigned char> overflow{0x06, 0x0D, 0x2A};
    for (int i = 0; i < 11; ++i)
        overflow.push_back(0xFF);
    overflow.push_back(0x7F);
    CHECK_FALSE(der_oid_to_dotted(bytes(overflow)));
}

// ── describe ────────────────────────────────────────────────────────────────

TEST_CASE("describe: RSA and DSA take their length from the library", "[certificates_crypto]") {
    auto rsa = describe(kRsa, "", 2048, kSha256Rsa);
    CHECK(rsa.key_algorithm == "RSA");
    CHECK(rsa.key_bits == "2048");
    CHECK(rsa.signature_algorithm == "sha256WithRSAEncryption");

    auto pss = describe("1.2.840.113549.1.1.10", "", 3072, "1.2.840.113549.1.1.10");
    CHECK(pss.key_algorithm == "RSASSA-PSS");
    CHECK(pss.key_bits == "3072");
    CHECK(pss.signature_algorithm == "RSASSA-PSS");

    auto dsa = describe("1.2.840.10040.4.1", "", 2048, "2.16.840.1.101.3.4.3.2");
    CHECK(dsa.key_algorithm == "DSA");
    CHECK(dsa.key_bits == "2048");
    CHECK(dsa.signature_algorithm == "dsa-with-SHA256");
}

TEST_CASE("describe: a key the library could not size reports (unknown), not 0",
          "[certificates_crypto]") {
    auto p = describe(kRsa, "", 0, kSha256Rsa);
    CHECK(p.key_algorithm == "RSA");
    CHECK(p.key_bits == "(unknown)");
    CHECK(describe(kRsa, "", -1, kSha256Rsa).key_bits == "(unknown)");
}

TEST_CASE("describe: EC length comes from the curve table, never the library",
          "[certificates_crypto]") {
    // A library that disagreed (e.g. a field-size quirk) must not change the answer.
    auto p = describe(kEc, "1.3.132.0.35", 999, "1.2.840.10045.4.3.4");
    CHECK(p.key_algorithm == "EC P-521");
    CHECK(p.key_bits == "521");
    CHECK(p.signature_algorithm == "ecdsa-with-SHA512");

    CHECK(describe(kEc, "1.3.132.0.10", 0, "").key_algorithm == "EC secp256k1");
    CHECK(describe(kEc, "1.3.36.3.3.2.8.1.1.11", 0, "").key_algorithm == "EC brainpoolP384r1");
}

TEST_CASE("describe: EC with an unnamed or unknown curve", "[certificates_crypto]") {
    auto explicit_params = describe(kEc, "", 256, "1.2.840.10045.4.3.2");
    CHECK(explicit_params.key_algorithm == "EC");
    CHECK(explicit_params.key_bits == "(unknown)");

    auto unknown_curve = describe(kEc, "1.2.3.4.5", 256, "1.2.840.10045.4.3.2");
    CHECK(unknown_curve.key_algorithm == "EC 1.2.3.4.5");
    CHECK(unknown_curve.key_bits == "(unknown)");
}

TEST_CASE("describe: fixed-size algorithms report an implied length", "[certificates_crypto]") {
    for (auto [oid, name] : std::vector<std::pair<std::string_view, std::string_view>>{
             {"1.3.101.110", "X25519"},
             {"1.3.101.111", "X448"},
             {"1.3.101.112", "Ed25519"},
             {"1.3.101.113", "Ed448"},
             {"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
             {"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
             {"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
             {"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
             {"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
             {"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
         }) {
        INFO(oid);
        auto p = describe(oid, "", 253, "");
        CHECK(p.key_algorithm == name);
        CHECK(p.key_bits == "(implied)");
    }
}

TEST_CASE("describe: signature algorithm table", "[certificates_crypto]") {
    for (auto [oid, name] : std::vector<std::pair<std::string_view, std::string_view>>{
             {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
             {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
             {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
             {"1.3.14.3.2.29", "sha1WithRSASignature"},
             {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
             {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
             {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
             {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
             {"2.16.840.1.101.3.4.3.14", "rsa-with-SHA3-256"},
             {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
             {"1.2.840.10045.4.3.1", "ecdsa-with-SHA224"},
             {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
             {"2.16.840.1.101.3.4.3.10", "ecdsa-with-SHA3-256"},
             {"1.2.840.10040.4.3", "dsa-with-SHA1"},
             {"2.16.840.1.101.3.4.3.1", "dsa-with-SHA224"},
             {"1.3.101.113", "Ed448"},
             {"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
         }) {
        INFO(oid);
        CHECK(describe("", "", 0, oid).signature_algorithm == name);
    }
}

TEST_CASE("describe: an unnamed OID is reported in dotted form, not as (unknown)",
          "[certificates_crypto]") {
    // GOST R 34.10-2012 256-bit -- deliberately not in the table.
    auto p = describe("1.2.643.7.1.1.1.1", "", 256, "1.2.643.7.1.1.3.2");
    CHECK(p.key_algorithm == "1.2.643.7.1.1.1.1");
    CHECK(p.key_bits == "(unknown)");
    CHECK(p.signature_algorithm == "1.2.643.7.1.1.3.2");
}

TEST_CASE("describe: absent or untrusted OIDs keep the (unknown) sentinel",
          "[certificates_crypto]") {
    auto none = describe("", "", 2048, "");
    CHECK(none.key_algorithm == "(unknown)");
    CHECK(none.key_bits == "(unknown)");
    CHECK(none.signature_algorithm == "(unknown)");

    auto hostile = describe("1.2|evil", "1.2\n3", 2048, "x|y");
    CHECK(hostile.key_algorithm == "(unknown)");
    CHECK(hostile.key_bits == "(unknown)");
    CHECK(hostile.signature_algorithm == "(unknown)");

    // A hostile curve OID on a real EC key must not reach the row either.
    CHECK(describe(kEc, "1.2|3", 0, "").key_algorithm == "EC");
}

TEST_CASE("describe: tables hold no duplicate OIDs", "[certificates_crypto]") {
    namespace d = yuzu::certificates_crypto::detail;
    std::set<std::string_view> sig;
    for (const auto& e : d::kSignatureAlgorithms)
        CHECK(sig.insert(e.oid).second);
    std::set<std::string_view> curves;
    for (const auto& c : d::kCurves)
        CHECK(curves.insert(c.oid).second);
    std::set<std::string_view> keys{d::kOidRsa, d::kOidRsaPss, d::kOidDsa, d::kOidEc};
    for (const auto& e : d::kFixedSizeKeyAlgorithms)
        CHECK(keys.insert(e.oid).second);
}
