#pragma once

/// @file cms_test_fixtures.hpp
///
/// In-memory CA + code-signing leaf + detached CMS signature material, built at
/// test time so there are no on-disk fixtures to expire or drift.
///
/// SHARED because two subsystems now verify detached CMS signatures against an
/// operator trust bundle — the plugin loader and the OTA updater (#416/#3807) —
/// and they must be tested against the SAME notion of a valid signature. A
/// second, subtly different fixture builder would let one verifier's tests pass
/// on material the other would reject, which is exactly the drift the shared
/// verifier exists to prevent.
///
/// All OpenSSL handles are unique_ptr-owned; an OpenSSL failure inside
/// build_signing_fixtures() trips a REQUIRE so a test fails loudly rather than
/// running against partial state.

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "test_helpers.hpp"

namespace yuzu::test::cms {

namespace fs = std::filesystem;

struct SslFreer {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
    void operator()(X509_NAME* p) const noexcept { X509_NAME_free(p); }
    void operator()(CMS_ContentInfo* p) const noexcept { CMS_ContentInfo_free(p); }
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
template <typename T> using ssl_ptr = std::unique_ptr<T, SslFreer>;

inline ssl_ptr<EVP_PKEY> generate_ec_key() {
    ssl_ptr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    REQUIRE(ctx);
    REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
    return ssl_ptr<EVP_PKEY>{raw};
}

inline ssl_ptr<X509> mint_cert(EVP_PKEY* subject_key, EVP_PKEY* issuer_key, X509* issuer_cert,
                        const std::string& cn, bool is_ca) {
    ssl_ptr<X509> cert{X509_new()};
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(std::random_device{}()));
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24);

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    if (issuer_cert) {
        REQUIRE(X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert)) == 1);
    } else {
        REQUIRE(X509_set_issuer_name(cert.get(), name) == 1); // self-signed CA
    }
    REQUIRE(X509_set_pubkey(cert.get(), subject_key) == 1);

    // Basic constraints + keyUsage + EKU. Required for OpenSSL's
    // X509_PURPOSE_CODE_SIGN chain check (governance hardening round 1):
    //   * CA cert: basicConstraints=CA:TRUE, keyUsage=keyCertSign,cRLSign
    //   * Leaf: basicConstraints=CA:FALSE, keyUsage=digitalSignature,
    //           extendedKeyUsage=codeSigning
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, issuer_cert ? issuer_cert : cert.get(), cert.get(), nullptr, nullptr, 0);
    const char* bc = is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
    if (auto* ext =
            X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints, const_cast<char*>(bc))) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    const char* ku = is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature";
    if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_key_usage, const_cast<char*>(ku))) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (!is_ca) {
        if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_ext_key_usage,
                                            const_cast<char*>("codeSigning"))) {
            X509_add_ext(cert.get(), ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    REQUIRE(X509_sign(cert.get(), issuer_key, EVP_sha256()) > 0);
    return cert;
}

inline void write_pem_cert(const fs::path& path, X509* cert) {
    ssl_ptr<BIO> bio{BIO_new_file(path.string().c_str(), "wb")};
    REQUIRE(bio);
    REQUIRE(PEM_write_bio_X509(bio.get(), cert) == 1);
}

inline void write_cms_signature(const fs::path& sig_path, const fs::path& payload_path, X509* leaf_cert,
                         EVP_PKEY* leaf_key) {
    ssl_ptr<BIO> in{BIO_new_file(payload_path.string().c_str(), "rb")};
    REQUIRE(in);
    ssl_ptr<CMS_ContentInfo> cms{
        CMS_sign(leaf_cert, leaf_key, nullptr, in.get(), CMS_BINARY | CMS_DETACHED | CMS_PARTIAL)};
    REQUIRE(cms);
    REQUIRE(CMS_final(cms.get(), in.get(), nullptr, CMS_BINARY | CMS_DETACHED) == 1);
    ssl_ptr<BIO> out{BIO_new_file(sig_path.string().c_str(), "wb")};
    REQUIRE(out);
    REQUIRE(PEM_write_bio_CMS(out.get(), cms.get()) == 1);
}

struct SigningFixtures {
    fs::path dir;
    fs::path trust_bundle;       // matching CA
    fs::path other_trust_bundle; // different CA (for untrusted tests)
    fs::path artifact_file;   ///< the signed payload (a plugin .so, or an update binary)
    fs::path sig_file;

    ~SigningFixtures() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

// Same as mint_cert but takes an explicit EKU string (or null for none).
// Used by the EKU-enforcement negative test which mints a leaf with
// EKU=serverAuth instead of codeSigning to prove X509_PURPOSE_CODE_SIGN
// rejects it (governance hardening round 1, sec-LOW-2 negative coverage).
inline ssl_ptr<X509> mint_cert_eku(EVP_PKEY* subject_key, EVP_PKEY* issuer_key, X509* issuer_cert,
                            const std::string& cn, const char* leaf_eku) {
    ssl_ptr<X509> cert{X509_new()};
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(std::random_device{}()));
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    REQUIRE(X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert)) == 1);
    REQUIRE(X509_set_pubkey(cert.get(), subject_key) == 1);
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, issuer_cert, cert.get(), nullptr, nullptr, 0);
    if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints,
                                        const_cast<char*>("critical,CA:FALSE"))) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_key_usage,
                                        const_cast<char*>("critical,digitalSignature"))) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (leaf_eku) {
        if (auto* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_ext_key_usage,
                                            const_cast<char*>(leaf_eku))) {
            X509_add_ext(cert.get(), ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    REQUIRE(X509_sign(cert.get(), issuer_key, EVP_sha256()) > 0);
    return cert;
}

inline SigningFixtures build_signing_fixtures() {
    SigningFixtures f;
    // Use the shared monotonic-counter helper from test_helpers.hpp
    // (#482 / Windows MSVC Defender-flake fix). Bare random_device +
    // mt19937_64 has no monotonic counter and can collide under
    // Defender-induced I/O serialisation.
    f.dir = yuzu::test::unique_temp_path("yuzu_test_cms_sign_");
    fs::create_directories(f.dir);

    // Trusted CA + leaf
    auto ca_key = generate_ec_key();
    auto ca_cert = mint_cert(ca_key.get(), ca_key.get(), nullptr, "Yuzu Test CA", true);
    auto leaf_key = generate_ec_key();
    auto leaf_cert =
        mint_cert(leaf_key.get(), ca_key.get(), ca_cert.get(), "Yuzu Test Plugin Signer", false);

    // A *different* CA used as the "wrong trust bundle" anchor
    auto other_key = generate_ec_key();
    auto other_cert = mint_cert(other_key.get(), other_key.get(), nullptr, "Other CA", true);

    f.trust_bundle = f.dir / "trust-bundle.pem";
    f.other_trust_bundle = f.dir / "other-trust.pem";
    write_pem_cert(f.trust_bundle, ca_cert.get());
    write_pem_cert(f.other_trust_bundle, other_cert.get());

    // Plugin payload — opaque bytes; verifier doesn't dlopen, just hashes
    f.artifact_file = f.dir / "artifact.bin";
    {
        std::ofstream pf(f.artifact_file, std::ios::binary);
        pf << "Yuzu plugin test payload\n0123456789abcdef\n";
    }

    f.sig_file = f.dir / "artifact.bin.sig";
    write_cms_signature(f.sig_file, f.artifact_file, leaf_cert.get(), leaf_key.get());

    return f;
}

} // namespace yuzu::test::cms
