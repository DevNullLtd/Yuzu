#pragma once

// Certificate fixtures for the gateway-peer authorization tests: a throwaway CA
// and leaves with controllable EKU, validity and key reuse, built with the same
// x509_ca primitives the server uses for its default leaves.
//
// The gateway-shaped leaf mirrors default_certs.cpp's "default-gateway": EKU
// serverAuth + clientAuth, SAN localhost/127.0.0.1. The clientAuth-only leaf is the
// shape the server issues to agents, and is used here as a certificate that lacks
// serverAuth.

#include <catch2/catch_test_macros.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "x509_ca.hpp"

namespace yuzu::test::gwpeer {

namespace pki = yuzu::server::pki;

struct TestCa {
    std::string key_pem;
    std::string cert_pem;
};

struct TestLeaf {
    std::string key_pem;
    std::string cert_pem;
};

/// `path_len` defaults to 1 (not the single-tier 0 the install CA uses) so a test can hang an
/// intermediate (`make_intermediate`) under any CA this makes.
inline TestCa make_ca(const std::string& cn, int path_len = 1) {
    TestCa c;
    auto key = pki::generate_private_key(pki::KeyAlgo::EcP384);
    REQUIRE(key.has_value());
    c.key_pem = *key;
    pki::CaParams p;
    p.subject.common_name = cn;
    p.subject.organization = "YuzuTest";
    // Long enough to issue the not-yet-valid fixture (a leaf may not outlive its CA).
    p.validity = pki::validity_days_from_now(10);
    p.path_len = path_len;
    auto cert = pki::self_sign_ca(c.key_pem, p);
    REQUIRE(cert.has_value());
    c.cert_pem = *cert;
    return c;
}

inline pki::LeafParams leaf_params(const std::string& cn, bool server_auth, bool client_auth,
                                   pki::Validity validity) {
    pki::LeafParams lp;
    lp.subject.common_name = cn;
    lp.subject.organization = "YuzuTest";
    lp.validity = validity;
    lp.usage.server_auth = server_auth;
    lp.usage.client_auth = client_auth;
    if (server_auth) {
        lp.san.dns.push_back("localhost");
        lp.san.ips.push_back("127.0.0.1");
    }
    return lp;
}

/// A fresh key and a leaf over it.
inline TestLeaf make_leaf(const TestCa& ca, const std::string& cn, bool server_auth,
                          bool client_auth,
                          pki::Validity validity = pki::validity_days_from_now(1)) {
    auto kc = pki::issue_leaf(ca.cert_pem, ca.key_pem, pki::KeyAlgo::EcP256,
                              leaf_params(cn, server_auth, client_auth, validity));
    REQUIRE(kc.has_value());
    return TestLeaf{kc->private_key_pem, kc->cert_pem};
}

/// The gateway shape (serverAuth + clientAuth, as default-gateway).
inline TestLeaf make_gateway_leaf(const TestCa& ca, const std::string& cn = "Test Gateway") {
    return make_leaf(ca, cn, /*server_auth=*/true, /*client_auth=*/true);
}

/// The agent shape (clientAuth only).
inline TestLeaf make_agent_leaf(const TestCa& ca, const std::string& cn = "agent-1") {
    return make_leaf(ca, cn, /*server_auth=*/false, /*client_auth=*/true);
}

/// A NEW certificate (new serial, new validity) over the SAME key as `old`: the
/// shape of a routine certificate renewal.
inline TestLeaf reissue_same_key(const TestCa& ca, const TestLeaf& old, const std::string& cn,
                                 bool server_auth, bool client_auth) {
    pki::CsrParams cp;
    cp.subject.common_name = cn;
    cp.subject.organization = "YuzuTest";
    auto csr = pki::make_csr(old.key_pem, cp);
    REQUIRE(csr.has_value());
    auto issued = pki::sign_csr(*csr, ca.cert_pem, ca.key_pem,
                                leaf_params(cn, server_auth, client_auth,
                                            pki::validity_days_from_now(1)));
    REQUIRE(issued.has_value());
    return TestLeaf{old.key_pem, issued->cert_pem};
}

namespace detail {
struct BioDel {
    void operator()(BIO* b) const noexcept { BIO_free(b); }
};
struct X509Del {
    void operator()(X509* x) const noexcept { X509_free(x); }
};
struct PkeyDel {
    void operator()(EVP_PKEY* k) const noexcept { EVP_PKEY_free(k); }
};
struct ExtDel {
    void operator()(X509_EXTENSION* e) const noexcept { X509_EXTENSION_free(e); }
};
using BioU = std::unique_ptr<BIO, BioDel>;
using X509U = std::unique_ptr<X509, X509Del>;
using PkeyU = std::unique_ptr<EVP_PKEY, PkeyDel>;
using ExtU = std::unique_ptr<X509_EXTENSION, ExtDel>;

inline X509U load_x509(const std::string& pem) {
    BioU bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    REQUIRE(bio);
    X509U x{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
    REQUIRE(x);
    return x;
}

inline PkeyU load_private_key(const std::string& pem) {
    BioU bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    REQUIRE(bio);
    PkeyU k{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
    REQUIRE(k);
    return k;
}

inline void add_ext(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    ExtU ext{X509V3_EXT_conf_nid(nullptr, &ctx, nid, value)};
    REQUIRE(ext);
    REQUIRE(X509_add_ext(cert, ext.get(), -1) == 1);
}

/// A certificate over `subject_key`'s public half, signed by `issuer_key` (self-signed when
/// `issuer_cert` is null). Built with raw OpenSSL because the x509_ca engine never signs a CA
/// certificate or an RSA one. Valid from five minutes ago for `days` days.
inline std::string raw_cert(EVP_PKEY* subject_key, const std::string& cn, X509* issuer_cert,
                            EVP_PKEY* issuer_key, bool ca, bool server_auth, bool client_auth,
                            int days) {
    X509U x{X509_new()};
    REQUIRE(x);
    REQUIRE(X509_set_version(x.get(), 2) == 1);
    REQUIRE(ASN1_INTEGER_set_uint64(X509_get_serialNumber(x.get()),
                                    0x5eed0000ULL + static_cast<std::uint64_t>(cn.size()) * 7919 +
                                        static_cast<std::uint64_t>(days)) == 1);
    X509_NAME* name = X509_get_subject_name(x.get());
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                       reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                                       0) == 1);
    REQUIRE(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
                                       reinterpret_cast<const unsigned char*>("YuzuTest"), -1, -1,
                                       0) == 1);
    REQUIRE(X509_set_issuer_name(x.get(), issuer_cert ? X509_get_subject_name(issuer_cert)
                                                      : X509_get_subject_name(x.get())) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(x.get()), -300) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(x.get()), 86400L * days) != nullptr);
    REQUIRE(X509_set_pubkey(x.get(), subject_key) == 1);
    X509* issuer_for_ctx = issuer_cert ? issuer_cert : x.get();
    add_ext(x.get(), issuer_for_ctx, NID_subject_key_identifier, "hash");
    add_ext(x.get(), issuer_for_ctx, NID_authority_key_identifier, "keyid:always");
    if (ca) {
        add_ext(x.get(), issuer_for_ctx, NID_basic_constraints, "critical,CA:TRUE");
        add_ext(x.get(), issuer_for_ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else if (server_auth || client_auth) {
        add_ext(x.get(), issuer_for_ctx, NID_basic_constraints, "CA:FALSE");
        std::string eku;
        if (server_auth)
            eku += "serverAuth";
        if (client_auth)
            eku += std::string(eku.empty() ? "" : ",") + "clientAuth";
        add_ext(x.get(), issuer_for_ctx, NID_ext_key_usage, eku.c_str());
    }
    REQUIRE(X509_sign(x.get(), issuer_key ? issuer_key : subject_key, EVP_sha256()) > 0);
    BioU out{BIO_new(BIO_s_mem())};
    REQUIRE(out);
    REQUIRE(PEM_write_bio_X509(out.get(), x.get()) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(out.get(), &data);
    REQUIRE(len > 0);
    return std::string(data, static_cast<std::size_t>(len));
}
} // namespace detail

/// An intermediate CA (CA:TRUE, a fresh P-384 key) signed by `root`, usable as an issuing
/// certificate under that root. Valid for 5 days, inside the 10-day root.
inline TestCa make_intermediate(const TestCa& root, const std::string& cn) {
    TestCa c;
    auto key = pki::generate_private_key(pki::KeyAlgo::EcP384);
    REQUIRE(key.has_value());
    c.key_pem = *key;
    const auto root_cert = detail::load_x509(root.cert_pem);
    const auto root_key = detail::load_private_key(root.key_pem);
    const auto inter_key = detail::load_private_key(c.key_pem);
    c.cert_pem = detail::raw_cert(inter_key.get(), cn, root_cert.get(), root_key.get(),
                                  /*ca=*/true, false, false, 5);
    return c;
}

inline pki::Validity expired_validity() {
    const auto now = std::chrono::system_clock::now();
    return pki::Validity{now - std::chrono::hours(48), now - std::chrono::hours(24)};
}

inline pki::Validity not_yet_valid_validity() {
    const auto now = std::chrono::system_clock::now();
    return pki::Validity{now + std::chrono::hours(24), now + std::chrono::hours(48)};
}

// A self-signed P-256 certificate whose validity ends at the ASN.1 "no expiry" sentinel,
// 9999-12-31T23:59:59Z, and starts 2026-01-01T00:00:00Z. EKU serverAuth + clientAuth.
// Generated once with the openssl CLI (the pki::issue_leaf helper cannot express year 9999 on
// Linux, where system_clock ticks are nanoseconds):
//
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null
//       -subj "/CN=notafter9999/O=YuzuTest" -not_before 20260101000000Z
//       -not_after 99991231235959Z -addext "extendedKeyUsage=serverAuth,clientAuth"
//   (one command; wrapped here for width)
//   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
//   -> d32903dc072355af13c2ba2e847257b892cf9eee083bb8006a3e7eaeb89660c7
inline constexpr const char* kYear9999Pem = R"(-----BEGIN CERTIFICATE-----
MIIByjCCAXCgAwIBAgIUcviDEEb0+MRzcPIqolpHJiEa5MIwCgYIKoZIzj0EAwIw
KjEVMBMGA1UEAwwMbm90YWZ0ZXI5OTk5MREwDwYDVQQKDAhZdXp1VGVzdDAgFw0y
NjAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowKjEVMBMGA1UEAwwMbm90YWZ0
ZXI5OTk5MREwDwYDVQQKDAhZdXp1VGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABCvie29PCYJRrZVB/e+7QQUDNQ3HzRraT1wNeb0cXJezNMylm+rxjIaA7fnX
7lTFi4MSiCJ2HE1+r9iFiC+8mQGjcjBwMB0GA1UdDgQWBBTfGdQITFgOYZrq8fjG
z3S/8ADrlTAfBgNVHSMEGDAWgBTfGdQITFgOYZrq8fjGz3S/8ADrlTAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjO
PQQDAgNIADBFAiEA2y9o4NqpTojP6BKk76s72X3ajU7t6xOMucXnsGFzR+4CIBwh
nAmF1/UtrPuQQ4XSsWJZJPvE9mP7I547u1B027iT
-----END CERTIFICATE-----
)";

} // namespace yuzu::test::gwpeer
