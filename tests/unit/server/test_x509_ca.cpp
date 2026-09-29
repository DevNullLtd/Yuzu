/**
 * test_x509_ca.cpp — Unit tests for the pure-OpenSSL PKI engine (PR1).
 *
 * Covers: EC keygen (P-256/P-384), self-signed CA shape + validity, CSR build,
 * CSR signing with proof-of-possession, the SECURITY invariant that sign_csr
 * ignores attacker-controlled CSR subject/SAN, one-shot leaf issuance, chain
 * verification (positive + negative), random serials, fingerprint format, and
 * CRL generation.
 *
 * The server test binary always compiles with CPPHTTPLIB_OPENSSL_SUPPORT
 * (tests/meson.build https_cpp_args), so the real implementation is under test.
 */

#include "x509_ca.hpp"

#include <catch2/catch_test_macros.hpp>

// pem.h MUST precede cms.h (DECLARE_PEM_rw(CMS, CMS_ContentInfo) is a pem.h
// macro cms.h expands against — see detached_signature.cpp's identical note);
// not sorted alphabetically for that reason.
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h> // EVP_RSA_gen — gov B1 weak-key-floor coverage
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::server::pki;

namespace {

// Flip one base64 char in the SIGNATURE TAIL of a CSR PEM. The signature is the
// final DER element, so corrupting a tail content byte keeps the ASN.1 structure
// parseable (no length byte is touched) but breaks the self-signature — so it
// exercises sign_csr's proof-of-possession verify (X509_REQ_verify), a distinct
// code path from the PEM-parse rejection the garbage-blob test covers.
std::string tamper_csr_sig(std::string pem) {
    const auto body_begin = pem.find('\n', pem.find("BEGIN"));
    const auto body_end = pem.rfind("-----END");
    REQUIRE(body_begin != std::string::npos);
    REQUIRE(body_end != std::string::npos);
    auto is_b64 = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '+' || c == '/';
    };
    std::vector<std::size_t> body_b64;
    for (std::size_t i = body_begin; i < body_end; ++i)
        if (is_b64(pem[i]))
            body_b64.push_back(i);
    REQUIRE(body_b64.size() > 16);
    // ~6 base64 chars (~4-5 bytes) before the end → inside the signature value.
    const std::size_t pos = body_b64[body_b64.size() - 6];
    pem[pos] = (pem[pos] == 'A') ? 'B' : 'A';
    return pem;
}

struct TestCa {
    std::string key;
    std::string cert;
};

// A fresh P-384 self-signed CA for tests that need an issuer.
TestCa make_test_ca(const std::string& cn = "Yuzu Test CA") {
    auto key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(key);
    CaParams p;
    p.subject = {cn, "Yuzu"};
    p.validity = validity_years_from_now(10);
    p.path_len = 0;
    auto cert = self_sign_ca(*key, p);
    REQUIRE(cert);
    return {*key, *cert};
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

// gov B1: unencrypted RSA private key PEM at the given modulus size — used ONLY
// to build a CSR whose SUBJECT key the floor must classify. Mirrors
// test_saml_provider.cpp's generate_small_rsa_key_pem/EVP_RSA_gen idiom.
std::string generate_rsa_key_pem(int bits) {
    EVP_PKEY* pkey = EVP_RSA_gen(static_cast<unsigned int>(bits));
    REQUIRE(pkey != nullptr);
    struct PkeyGuard {
        EVP_PKEY* k;
        ~PkeyGuard() {
            if (k)
                EVP_PKEY_free(k);
        }
    } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard {
        BIO* b;
        ~BioGuard() {
            if (b)
                BIO_free(b);
        }
    } bg{bio};
    REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

// gov MED-2: an Ed25519 private key PEM — used ONLY to build a CSR whose
// SUBJECT key the floor must now REJECT (openssl cms -sign fails on an
// Ed25519 codeSigning cert with "no default digest", so the floor must refuse
// to issue one even though detached_signature.cpp's own CMS_verify would
// accept it).
std::string generate_ed25519_key_pem() {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    REQUIRE(pkey != nullptr);
    struct PkeyGuard {
        EVP_PKEY* k;
        ~PkeyGuard() {
            if (k)
                EVP_PKEY_free(k);
        }
    } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard {
        BIO* b;
        ~BioGuard() {
            if (b)
                BIO_free(b);
        }
    } bg{bio};
    REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

// ── Raw-OpenSSL helpers for the code-signing test cases ────────────────────────
//
// CertDetails (parse_certificate's public shape) does not expose EKU/keyUsage,
// and CsrParams (make_csr's public shape) has no EKU field at all — both are
// dug out / injected with raw OpenSSL here, local to this TU. The RAII pattern
// mirrors x509_ca.cpp's own YUZU_SSL_PTR macro and the agent-side
// detached_signature.cpp / cms_test_fixtures.hpp verifier tests, which is the
// SAME check the CMS round-trip case below reproduces.
struct SslFreer {
    void operator()(BIO* p) const noexcept { BIO_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
    void operator()(X509_REQ* p) const noexcept { X509_REQ_free(p); }
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    void operator()(X509_STORE* p) const noexcept { X509_STORE_free(p); }
    void operator()(CMS_ContentInfo* p) const noexcept { CMS_ContentInfo_free(p); }
};
template <typename T> using ssl_ptr = std::unique_ptr<T, SslFreer>;

ssl_ptr<X509> load_x509(const std::string& pem) {
    ssl_ptr<BIO> bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    REQUIRE(bio);
    return ssl_ptr<X509>{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

ssl_ptr<EVP_PKEY> load_pkey(const std::string& pem) {
    ssl_ptr<BIO> bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    REQUIRE(bio);
    return ssl_ptr<EVP_PKEY>{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
}

// Extended-key-usage OIDs as their config-string short names ("serverAuth",
// "clientAuth", "codeSigning") — the exact literals eku_value() (x509_ca.cpp)
// builds, so this reads the wire content straight back rather than re-deriving
// it a different way.
std::vector<std::string> cert_eku(const std::string& cert_pem) {
    auto cert = load_x509(cert_pem);
    REQUIRE(cert);
    std::vector<std::string> out;
    auto* eku = static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(cert.get(), NID_ext_key_usage, nullptr, nullptr));
    if (!eku)
        return out;
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
        const char* sn = OBJ_nid2sn(OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)));
        out.emplace_back(sn ? sn : "");
    }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    return out;
}

// True iff keyUsage is present, critical, and sets digitalSignature ONLY (bit
// 0) — the fixed keyUsage build_and_sign_leaf sets on every leaf regardless of
// LeafUsage (x509_ca.cpp: "critical,digitalSignature", every leaf, always).
bool cert_key_usage_is_digital_signature_only(const std::string& cert_pem) {
    auto cert = load_x509(cert_pem);
    REQUIRE(cert);
    int crit = -1;
    auto* ku = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(cert.get(), NID_key_usage, &crit, nullptr));
    if (!ku)
        return false;
    bool ok = crit == 1 && ASN1_BIT_STRING_get_bit(ku, 0) == 1; // digitalSignature
    for (int bit = 1; bit <= 8 && ok; ++bit)                    // nonRepudiation..decipherOnly
        ok = ASN1_BIT_STRING_get_bit(ku, bit) == 0;
    ASN1_BIT_STRING_free(ku);
    return ok;
}

// Build a self-signed CSR whose extensionRequest attribute carries an
// ATTACKER-CHOSEN EKU + DNS SAN — the exact shape sign_csr's documented
// security contract (x509_ca.hpp: "the CSR's own subject/SAN are deliberately
// IGNORED") must defeat. CsrParams (make_csr's public shape) has no EKU field,
// so this is built with raw OpenSSL rather than through make_csr.
std::string build_csr_with_eku_and_san(EVP_PKEY* key, const std::string& cn,
                                       const char* eku_value, const char* dns_san) {
    ssl_ptr<X509_REQ> req{X509_REQ_new()};
    REQUIRE(req);
    REQUIRE(X509_REQ_set_version(req.get(), 0) == 1);
    X509_NAME* name = X509_REQ_get_subject_name(req.get());
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                                       0) == 1);
    REQUIRE(X509_REQ_set_pubkey(req.get(), key) == 1);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req.get(), nullptr, 0);
    auto* exts = sk_X509_EXTENSION_new_null();
    REQUIRE(exts);
    const std::string san_val = std::string("DNS:") + dns_san;
    auto* san_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_val.c_str());
    REQUIRE(san_ext);
    sk_X509_EXTENSION_push(exts, san_ext);
    auto* eku_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_ext_key_usage, eku_value);
    REQUIRE(eku_ext);
    sk_X509_EXTENSION_push(exts, eku_ext);
    // Same X509_REQ_add_extensions idiom as make_csr (x509_ca.cpp): serialises
    // `exts` into a request attribute WITHOUT taking ownership — pop_free frees
    // both the stack and the two pushed extensions.
    REQUIRE(X509_REQ_add_extensions(req.get(), exts) == 1);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    REQUIRE(X509_REQ_sign(req.get(), key, EVP_sha256()) > 0);

    ssl_ptr<BIO> bio{BIO_new(BIO_s_mem())};
    REQUIRE(bio);
    REQUIRE(PEM_write_bio_X509_REQ(bio.get(), req.get()) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    REQUIRE(len > 0);
    return std::string(data, static_cast<std::size_t>(len));
}

// gov MED-2: a bare CSR (subject CN only, no extensions) signed with a NULL
// digest — required for Ed25519/Ed448, which are "pure" signature schemes and
// reject `X509_REQ_sign`'s normal digest-then-sign path (the exact "no
// default digest" failure `openssl cms -sign` hits, which is why the floor
// must reject these keys). `make_csr` (x509_ca.cpp) always passes a concrete
// digest, so it cannot build this CSR — only used to get an Ed25519 CSR PEM
// past parsing; `subject_key_meets_code_signing_floor` never verifies the
// CSR's own signature, only its subject public key.
std::string make_csr_null_digest(EVP_PKEY* key, const std::string& cn) {
    ssl_ptr<X509_REQ> req{X509_REQ_new()};
    REQUIRE(req);
    REQUIRE(X509_REQ_set_version(req.get(), 0) == 1);
    X509_NAME* name = X509_REQ_get_subject_name(req.get());
    REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                                       0) == 1);
    REQUIRE(X509_REQ_set_pubkey(req.get(), key) == 1);
    REQUIRE(X509_REQ_sign(req.get(), key, nullptr) > 0);

    ssl_ptr<BIO> bio{BIO_new(BIO_s_mem())};
    REQUIRE(bio);
    REQUIRE(PEM_write_bio_X509_REQ(bio.get(), req.get()) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    REQUIRE(len > 0);
    return std::string(data, static_cast<std::size_t>(len));
}

} // namespace

TEST_CASE("x509_ca: generate EC keys", "[pki][keygen]") {
    auto p256 = generate_private_key(KeyAlgo::EcP256);
    auto p384 = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(p256);
    REQUIRE(p384);
    REQUIRE(p256->find("PRIVATE KEY") != std::string::npos);
    REQUIRE(p384->find("PRIVATE KEY") != std::string::npos);
    // Two generations differ.
    auto p256b = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(p256b);
    REQUIRE(*p256 != *p256b);
}

TEST_CASE("x509_ca: self-signed CA shape and validity", "[pki][ca]") {
    auto ca = make_test_ca("Yuzu Install CA");
    auto d = parse_certificate(ca.cert);
    REQUIRE(d);
    REQUIRE(d->is_ca);
    REQUIRE(d->subject.common_name == "Yuzu Install CA");
    REQUIRE(d->issuer.common_name == "Yuzu Install CA"); // self-signed

    const auto span = std::chrono::duration_cast<std::chrono::seconds>(d->not_after - d->not_before)
                          .count();
    const long ten_years = 10L * 31557600L;
    REQUIRE(std::abs(span - ten_years) < 86400); // within a day
}

TEST_CASE("x509_ca: notBefore is backdated by the clock-skew allowance (H-2)",
          "[pki][validity]") {
    using namespace std::chrono;
    // The CA (minted via validity_years_from_now) backdates notBefore by
    // kClockSkewBackdate (300s) so a slightly-behind peer can still validate a
    // just-issued chain. now() is captured AFTER minting, so now - notBefore >= 300s.
    auto ca = make_test_ca("Yuzu Skew CA");
    auto d = parse_certificate(ca.cert);
    REQUIRE(d);
    const auto now = system_clock::now();
    REQUIRE(d->not_before <= now - seconds(280)); // backdated (280 leaves test-exec slack)
    REQUIRE(d->not_before >= now - seconds(900)); // but not absurdly far back

    // A leaf minted via validity_days_from_now is backdated too (covers both helpers).
    LeafParams lp;
    lp.subject = {"skew-leaf", "Yuzu"};
    lp.validity = validity_days_from_now(365);
    lp.usage.client_auth = true;
    auto leaf = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(leaf);
    auto ld = parse_certificate(leaf->cert_pem);
    REQUIRE(ld);
    REQUIRE(ld->not_before <= now - seconds(280));
}

TEST_CASE("x509_ca: sign CSR produces a verifiable leaf", "[pki][leaf]") {
    auto ca = make_test_ca();
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);

    CsrParams csr_p;
    csr_p.subject = {"agent-123", "Yuzu"};
    auto csr = make_csr(*leaf_key, csr_p);
    REQUIRE(csr);

    LeafParams lp;
    lp.subject = {"agent-123", "Yuzu"};
    lp.san.uris = {"yuzu://install-abc/agent/agent-123"};
    lp.validity = validity_days_from_now(365);
    lp.usage.client_auth = true;
    auto issued = sign_csr(*csr, ca.cert, ca.key, lp);
    REQUIRE(issued);
    REQUIRE_FALSE(issued->serial_hex.empty());
    REQUIRE(verify_chain(issued->cert_pem, ca.cert));

    auto d = parse_certificate(issued->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "agent-123");
    REQUIRE(d->issuer.common_name == "Yuzu Test CA");
    REQUIRE(contains(d->san.uris, "yuzu://install-abc/agent/agent-123"));
    REQUIRE_FALSE(d->is_ca);
}

// The core security property: sign_csr must take subject + SAN ONLY from the
// server-supplied params, never from the (attacker-controlled) CSR.
TEST_CASE("x509_ca: sign_csr ignores CSR-supplied subject and SAN", "[pki][leaf][security]") {
    auto ca = make_test_ca();
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);

    CsrParams evil;
    evil.subject = {"admin", "Megacorp"};
    evil.san.dns = {"evil.example.com"};
    evil.san.uris = {"yuzu://install-abc/agent/some-other-agent"};
    auto csr = make_csr(*leaf_key, evil);
    REQUIRE(csr);

    LeafParams good;
    good.subject = {"agent-7", "Yuzu"};
    good.san.uris = {"yuzu://install-abc/agent/agent-7"};
    good.validity = validity_days_from_now(365);
    good.usage.client_auth = true;
    auto issued = sign_csr(*csr, ca.cert, ca.key, good);
    REQUIRE(issued);

    auto d = parse_certificate(issued->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "agent-7");
    REQUIRE(contains(d->san.uris, "yuzu://install-abc/agent/agent-7"));
    // None of the attacker's requested identity survives.
    REQUIRE_FALSE(contains(d->san.dns, "evil.example.com"));
    REQUIRE_FALSE(contains(d->san.uris, "yuzu://install-abc/agent/some-other-agent"));
    REQUIRE(d->subject.common_name != "admin");
}

// Typed GENERAL_NAMES construction must treat a SAN value containing config
// metacharacters as a single literal entry — never split it into extra SANs.
TEST_CASE("x509_ca: SAN values cannot inject extra entries", "[pki][leaf][security]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"svc", "Yuzu"};
    // Under a config-string SAN builder this would have smuggled a second name.
    lp.san.dns = {"good.example,DNS:evil.example"};
    lp.validity = validity_days_from_now(365);
    lp.usage.server_auth = true;
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc);
    auto d = parse_certificate(kc->cert_pem);
    REQUIRE(d);
    REQUIRE(d->san.dns.size() == 1);
    REQUIRE(d->san.dns[0] == "good.example,DNS:evil.example");
    REQUIRE_FALSE(contains(d->san.dns, "evil.example"));
}

// ── Code-signing leaves (LeafUsage::code_signing) ───────────────────────────────
// No production caller mints these yet — this is the engine primitive's own
// coverage, proving it is safe to build on (PKI / internal CA routed concern).

TEST_CASE("x509_ca: code-signing leaf carries codeSigning EKU only", "[pki][leaf][cms]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"yuzu-plugin-signer", "Yuzu"};
    lp.validity = validity_days_from_now(365);
    lp.usage = LeafUsage{.code_signing = true};
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc);

    auto eku = cert_eku(kc->cert_pem);
    REQUIRE(eku.size() == 1);
    REQUIRE(contains(eku, "codeSigning"));
    REQUIRE_FALSE(contains(eku, "clientAuth"));
    REQUIRE_FALSE(contains(eku, "serverAuth"));

    // keyUsage is the FIXED digitalSignature-only, critical, regardless of
    // LeafUsage — every leaf gets it (x509_ca.cpp's build_and_sign_leaf).
    REQUIRE(cert_key_usage_is_digital_signature_only(kc->cert_pem));

    // basicConstraints=critical,CA:FALSE — reuse the engine's own predicate.
    REQUIRE_FALSE(cert_is_ca(kc->cert_pem));
}

// The security-critical property, restated for a code-signing leaf: sign_csr
// must take EKU (like subject/SAN) ONLY from server-supplied LeafParams, never
// from the (attacker-controlled) CSR's own extensionRequest attribute. A CSR
// requesting clientAuth + a foreign SAN must not smuggle either into the issued
// cert — proven against the shared cert_eku()/parse_certificate() readback.
TEST_CASE("x509_ca: sign_csr ignores CSR-requested EKU and SAN (code-signing leaf)",
          "[pki][leaf][security][cms]") {
    auto ca = make_test_ca();
    auto leaf_key_pem = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key_pem);
    auto leaf_key = load_pkey(*leaf_key_pem);
    REQUIRE(leaf_key);

    const std::string evil_csr = build_csr_with_eku_and_san(
        leaf_key.get(), "requested-cn", "clientAuth", "evil-requested.example.com");
    REQUIRE(evil_csr.find("CERTIFICATE REQUEST") != std::string::npos);

    LeafParams lp;
    lp.subject = {"signer-1", "Yuzu"};
    lp.san.uris = {"yuzu://install-abc/signer/signer-1"};
    lp.validity = validity_days_from_now(365);
    lp.usage = LeafUsage{.code_signing = true};
    auto issued = sign_csr(evil_csr, ca.cert, ca.key, lp);
    REQUIRE(issued);

    // EKU is EXACTLY what LeafParams asked for — codeSigning only. The CSR's
    // requested clientAuth does not survive.
    auto eku = cert_eku(issued->cert_pem);
    REQUIRE(eku.size() == 1);
    REQUIRE(contains(eku, "codeSigning"));
    REQUIRE_FALSE(contains(eku, "clientAuth"));

    // SAN is EXACTLY what LeafParams asked for — the CSR's requested DNS SAN
    // does not survive either (same invariant the existing
    // "sign_csr ignores CSR-supplied subject and SAN" case covers for
    // client-auth leaves, restated here for a code-signing leaf + an EKU
    // request, which CsrParams cannot even express).
    auto d = parse_certificate(issued->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "signer-1");
    REQUIRE(contains(d->san.uris, "yuzu://install-abc/signer/signer-1"));
    REQUIRE(d->san.dns.empty());
    REQUIRE_FALSE(contains(d->san.dns, "evil-requested.example.com"));
}

// End-to-end: a code-signing leaf this engine issues must actually satisfy the
// agent's real plugin-signature verifier's check — X509_STORE_set_purpose(
// X509_PURPOSE_CODE_SIGN) + CMS_verify(..., CMS_BINARY|CMS_DETACHED), the exact
// pair detached_signature.cpp's load_trust_store()/verify_with_content_bio()
// run (see that file's header comments for why the purpose is set: it is what
// makes CMS_verify enforce EKU=codeSigning rather than accepting any leaf that
// merely chains to a trusted root). This TU links x509_ca.cpp AND OpenSSL CMS
// (yuzu_server_tests / test_x509_ca.cpp), so the round-trip is exercised
// directly rather than through the agent's wrapper, which this test target does
// not link.
TEST_CASE("x509_ca: code-signing leaf verifies a CMS detached signature "
          "(the agent plugin verifier's exact check)",
          "[pki][leaf][cms]") {
    auto ca = make_test_ca();
    auto root_cert = load_x509(ca.cert);
    REQUIRE(root_cert);

    LeafParams signer_lp;
    signer_lp.subject = {"yuzu-plugin-signer", "Yuzu"};
    signer_lp.validity = validity_days_from_now(365);
    signer_lp.usage = LeafUsage{.code_signing = true};
    auto signer = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, signer_lp);
    REQUIRE(signer);
    auto signer_cert = load_x509(signer->cert_pem);
    auto signer_key = load_pkey(signer->private_key_pem);
    REQUIRE(signer_cert);
    REQUIRE(signer_key);

    const std::string blob = "yuzu-plugin-artifact-bytes";
    auto sign_and_verify = [&](X509* leaf_cert, EVP_PKEY* leaf_key) {
        ssl_ptr<BIO> content{BIO_new_mem_buf(blob.data(), static_cast<int>(blob.size()))};
        REQUIRE(content);
        ssl_ptr<CMS_ContentInfo> cms{
            CMS_sign(leaf_cert, leaf_key, nullptr, content.get(), CMS_BINARY | CMS_DETACHED)};
        REQUIRE(cms);

        ssl_ptr<X509_STORE> store{X509_STORE_new()};
        REQUIRE(store);
        REQUIRE(X509_STORE_add_cert(store.get(), root_cert.get()) == 1);
        REQUIRE(X509_STORE_set_purpose(store.get(), X509_PURPOSE_CODE_SIGN) == 1);

        ssl_ptr<BIO> verify_content{BIO_new_mem_buf(blob.data(), static_cast<int>(blob.size()))};
        REQUIRE(verify_content);
        return CMS_verify(cms.get(), nullptr, store.get(), verify_content.get(), nullptr,
                          CMS_BINARY | CMS_DETACHED);
    };

    REQUIRE(sign_and_verify(signer_cert.get(), signer_key.get()) == 1);

    // Negative: a client-auth-only leaf (no codeSigning EKU) signed the SAME
    // way must FAIL the SAME purpose check — proves the check actually
    // discriminates by EKU rather than accepting any leaf chaining to the CA.
    LeafParams not_signer_lp;
    not_signer_lp.subject = {"agent-not-a-signer", "Yuzu"};
    not_signer_lp.validity = validity_days_from_now(365);
    not_signer_lp.usage = LeafUsage{.client_auth = true};
    auto not_signer = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, not_signer_lp);
    REQUIRE(not_signer);
    auto not_signer_cert = load_x509(not_signer->cert_pem);
    auto not_signer_key = load_pkey(not_signer->private_key_pem);
    REQUIRE(not_signer_cert);
    REQUIRE(not_signer_key);

    REQUIRE(sign_and_verify(not_signer_cert.get(), not_signer_key.get()) != 1);
}

// gov B1 (UP-1, HIGH, fleet-RCE class): the subject-key strength floor
// `issue_code_signing_leaf` (server.cpp) checks BEFORE ever calling sign_csr on
// an operator-submitted CSR. Exercises the shared pki:: predicate directly —
// the crypto is the engine's job. The server.cpp call site that runs this floor
// BEFORE sign_csr is verified by inspection only: the REST/MCP tests inject a
// stub issuance fn, so no test yet exercises the real issue_code_signing_leaf
// ordering (tracked with the reissue-block/usage-pin end-to-end coverage
// follow-up, F4/F5). This case covers the shared pki:: predicate directly.
TEST_CASE("x509_ca: subject_key_meets_code_signing_floor rejects a sub-2048-bit RSA key and "
          "Ed25519, accepts RSA-2048 and P-256 EC",
          "[pki][leaf][security]") {
    CsrParams cp;
    cp.subject = {"weak-signer", "Yuzu"};

    // 1024-bit RSA — factorable, must be REJECTED.
    auto weak_key_pem = generate_rsa_key_pem(1024);
    auto weak_csr = make_csr(weak_key_pem, cp);
    REQUIRE(weak_csr);
    REQUIRE_FALSE(subject_key_meets_code_signing_floor(*weak_csr));

    // RSA-2048 — meets the floor, must be ACCEPTED.
    auto ok_rsa_key_pem = generate_rsa_key_pem(2048);
    auto ok_rsa_csr = make_csr(ok_rsa_key_pem, cp);
    REQUIRE(ok_rsa_csr);
    REQUIRE(subject_key_meets_code_signing_floor(*ok_rsa_csr));

    // P-256 EC — an approved curve, must be ACCEPTED.
    auto ec_key_pem = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(ec_key_pem);
    auto ec_csr = make_csr(*ec_key_pem, cp);
    REQUIRE(ec_csr);
    REQUIRE(subject_key_meets_code_signing_floor(*ec_csr));

    // gov MED-2: Ed25519 — `openssl cms -sign` (the documented signing tool)
    // fails on an Ed25519 codeSigning cert, so the floor must now REJECT it
    // even though it is cryptographically strong. make_csr (x509_ca.cpp)
    // always signs with a concrete digest, which Ed25519 rejects — build the
    // CSR with the NULL-digest raw helper instead (the floor never verifies
    // the CSR's own signature, only its subject public key).
    auto ed25519_key_pem = generate_ed25519_key_pem();
    auto ed25519_key = load_pkey(ed25519_key_pem);
    REQUIRE(ed25519_key);
    auto ed25519_csr = make_csr_null_digest(ed25519_key.get(), cp.subject.common_name);
    REQUIRE_FALSE(subject_key_meets_code_signing_floor(ed25519_csr));

    // A garbage / unparseable CSR fails CLOSED — never a default-accept.
    REQUIRE_FALSE(subject_key_meets_code_signing_floor("not a csr"));
}

TEST_CASE("x509_ca: leaf may not outlive the issuing CA", "[pki][leaf][security]") {
    // CA valid ~30 days; a leaf requesting 365 days must be rejected.
    auto ca_key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(ca_key);
    CaParams cp;
    cp.subject = {"Short CA", "Yuzu"};
    cp.validity = validity_days_from_now(30);
    auto ca_cert = self_sign_ca(*ca_key, cp);
    REQUIRE(ca_cert);
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(365); // outlives the 30-day CA
    lp.usage.server_auth = true;
    REQUIRE_FALSE(issue_leaf(*ca_cert, *ca_key, KeyAlgo::EcP256, lp));
}

TEST_CASE("x509_ca: sign_csr rejects a non-CSR blob", "[pki][leaf][negative]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"x", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.client_auth = true;
    REQUIRE_FALSE(sign_csr("-----BEGIN CERTIFICATE REQUEST-----\nnotbase64\n", ca.cert, ca.key, lp));
    REQUIRE_FALSE(sign_csr("garbage", ca.cert, ca.key, lp));
}

TEST_CASE("x509_ca: issue_leaf returns key + chained cert", "[pki][leaf]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"https", "Yuzu"};
    lp.san.dns = {"localhost"};
    lp.san.ips = {"127.0.0.1"};
    lp.validity = validity_days_from_now(365);
    lp.usage.server_auth = true;
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc);
    REQUIRE(kc->private_key_pem.find("PRIVATE KEY") != std::string::npos);
    REQUIRE(verify_chain(kc->cert_pem, ca.cert));

    auto d = parse_certificate(kc->cert_pem);
    REQUIRE(d);
    REQUIRE(d->subject.common_name == "https");
    REQUIRE(contains(d->san.dns, "localhost"));
    REQUIRE(contains(d->san.ips, "127.0.0.1"));
}

TEST_CASE("x509_ca: serials are unique per issuance", "[pki][serial]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"n", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.server_auth = true;
    auto a = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    auto b = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(a->serial_hex != b->serial_hex);
}

TEST_CASE("x509_ca: verify_chain rejects a foreign issuer", "[pki][verify][negative]") {
    auto ca1 = make_test_ca("CA One");
    auto ca2 = make_test_ca("CA Two");
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.server_auth = true;
    auto leaf = issue_leaf(ca1.cert, ca1.key, KeyAlgo::EcP256, lp);
    REQUIRE(leaf);
    REQUIRE(verify_chain(leaf->cert_pem, ca1.cert));
    REQUIRE_FALSE(verify_chain(leaf->cert_pem, ca2.cert));
}

TEST_CASE("x509_ca: fingerprint format is stable colon-hex", "[pki][fingerprint]") {
    auto ca = make_test_ca();
    auto fp = fingerprint_sha256(ca.cert);
    REQUIRE(fp);
    REQUIRE(fp->size() == 95); // 32 bytes -> 64 hex + 31 colons
    REQUIRE((*fp)[2] == ':');
    auto fp2 = fingerprint_sha256(ca.cert);
    REQUIRE(fp2);
    REQUIRE(*fp == *fp2); // deterministic

    auto other = make_test_ca("Different");
    auto fp_other = fingerprint_sha256(other.cert);
    REQUIRE(fp_other);
    REQUIRE(*fp != *fp_other);
}

TEST_CASE("x509_ca: issuer_key_id is stable across a re-key, distinct per key (#1296)",
          "[pki][fingerprint][issuer_key_id]") {
    // The stable key-based CA identity must depend ONLY on the public key, so a
    // subordinate-CA re-key (same key, NEW issuer cert) keeps it constant while the
    // whole-cert fingerprint changes — exactly the property that lets an "issued by
    // this CA" query survive the swap.
    auto key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(key);

    CaParams p1;
    p1.subject = {"Yuzu Internal CA", "Yuzu"};
    p1.validity = validity_years_from_now(10);
    p1.path_len = 0;
    auto cert1 = self_sign_ca(*key, p1);
    REQUIRE(cert1);

    // Re-sign a DIFFERENT cert over the SAME key (models the builtin→subordinate
    // identity swap: new issuer cert, unchanged issuing key).
    CaParams p2;
    p2.subject = {"Yuzu Internal CA (subordinate)", "Yuzu"};
    p2.validity = validity_years_from_now(5);
    p2.path_len = 0;
    auto cert2 = self_sign_ca(*key, p2);
    REQUIRE(cert2);

    auto kid1 = issuer_key_id(*cert1);
    auto kid2 = issuer_key_id(*cert2);
    REQUIRE(kid1);
    REQUIRE(kid2);
    REQUIRE(kid1->size() == 95); // 32-byte SHA-256 → 64 hex + 31 colons
    REQUIRE((*kid1)[2] == ':');
    // Stable across the re-key…
    REQUIRE(*kid1 == *kid2);
    // …while the whole-cert fingerprint is NOT (the discriminator #1296 fixes).
    auto fp1 = fingerprint_sha256(*cert1);
    auto fp2 = fingerprint_sha256(*cert2);
    REQUIRE(fp1);
    REQUIRE(fp2);
    REQUIRE(*fp1 != *fp2);

    // A genuinely different key yields a different identity.
    auto other = make_test_ca("Different Key");
    auto kid_other = issuer_key_id(other.cert);
    REQUIRE(kid_other);
    REQUIRE(*kid_other != *kid1);
}

TEST_CASE("x509_ca: build CRL over revoked serials", "[pki][crl]") {
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage.client_auth = true;
    auto leaf = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(leaf);

    std::vector<CrlRevocation> revoked = {
        {leaf->serial_hex, std::chrono::system_clock::now()},
    };
    auto der = build_crl(ca.cert, ca.key, revoked, validity_days_from_now(7), 1);
    REQUIRE(der);
    REQUIRE_FALSE(der->empty());

    // An empty CRL (nothing revoked yet) is still valid + signable.
    auto empty = build_crl(ca.cert, ca.key, {}, validity_days_from_now(7), 2);
    REQUIRE(empty);
    REQUIRE_FALSE(empty->empty());
}

TEST_CASE("x509_ca: build_crl fails closed on a bad serial", "[pki][crl][security]") {
    auto ca = make_test_ca();
    // A non-hex serial must abort CRL generation, never be silently dropped
    // (a dropped revocation = a cert that still validates).
    std::vector<CrlRevocation> bad = {{"not-hex-!!", std::chrono::system_clock::now()}};
    REQUIRE_FALSE(build_crl(ca.cert, ca.key, bad, validity_days_from_now(7), 3));
    std::vector<CrlRevocation> empty_serial = {{"", std::chrono::system_clock::now()}};
    REQUIRE_FALSE(build_crl(ca.cert, ca.key, empty_serial, validity_days_from_now(7), 4));
}

TEST_CASE("x509_ca: verify_chain rejects an expired leaf", "[pki][verify][negative][security]") {
    // verify_chain must enforce the validity window (it backs the mTLS-accept
    // gate). Issue a leaf entirely in the past and confirm it does NOT verify,
    // even though it chains to and was signed by the CA.
    auto ca = make_test_ca();
    LeafParams lp;
    lp.subject = {"agent-expired", "Yuzu"};
    lp.usage.client_auth = true;
    const auto now = std::chrono::system_clock::now();
    lp.validity = Validity{now - std::chrono::hours(24 * 800), now - std::chrono::hours(24 * 400)};
    auto kc = issue_leaf(ca.cert, ca.key, KeyAlgo::EcP256, lp);
    REQUIRE(kc); // a past-dated leaf still issues (notAfter < CA notAfter)...
    REQUIRE_FALSE(verify_chain(kc->cert_pem, ca.cert)); // ...but must not verify (expired)
}

TEST_CASE("x509_ca: sign_csr rejects a tampered CSR signature",
          "[pki][leaf][negative][security]") {
    // Proof-of-possession: a CSR whose self-signature does not match its key must
    // be refused. This hits X509_REQ_verify — distinct from the garbage-blob test
    // (which fails at PEM parse). The pristine CSR signs fine; flipping one byte
    // of its signature tail (still parseable) must flip the result to rejected.
    auto ca = make_test_ca();
    auto key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(key);
    CsrParams cp;
    cp.subject = {"agent-pop", "Yuzu"};
    auto csr = make_csr(*key, cp);
    REQUIRE(csr);

    LeafParams lp;
    lp.subject = {"agent-pop", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    REQUIRE(sign_csr(*csr, ca.cert, ca.key, lp)); // pristine: POP holds

    const std::string tampered = tamper_csr_sig(*csr);
    REQUIRE(tampered != *csr);
    REQUIRE_FALSE(sign_csr(tampered, ca.cert, ca.key, lp)); // tampered: POP fails
}

TEST_CASE("x509_ca: fingerprint/parse reject non-cert input", "[pki][negative]") {
    REQUIRE_FALSE(fingerprint_sha256("not a certificate"));
    REQUIRE_FALSE(parse_certificate("garbage"));
    REQUIRE_FALSE(fingerprint_sha256("")); // empty rejected by the size guard
}

TEST_CASE("x509_ca: is_valid_ip_literal matches the SAN-builder parser", "[pki][security]") {
    // Accepts canonical IPv4 / IPv6.
    REQUIRE(is_valid_ip_literal("127.0.0.1"));
    REQUIRE(is_valid_ip_literal("10.20.30.40"));
    REQUIRE(is_valid_ip_literal("::1"));
    REQUIRE(is_valid_ip_literal("fe80::1"));
    REQUIRE(is_valid_ip_literal("2001:db8::dead:beef"));
    // Rejects the loose-heuristic false positives that would hard-fail issue_leaf
    // (the whole reason this gate exists for --cert-san classification).
    REQUIRE_FALSE(is_valid_ip_literal("1.2.3.4.5"));   // 5 octets
    REQUIRE_FALSE(is_valid_ip_literal("127.1"));       // short form rejected by a2i
    REQUIRE_FALSE(is_valid_ip_literal("999.1.1.1"));   // octet out of range
    REQUIRE_FALSE(is_valid_ip_literal("not-an-ip"));
    REQUIRE_FALSE(is_valid_ip_literal("12:00:00"));    // colon ≠ valid IPv6
    REQUIRE_FALSE(is_valid_ip_literal("gateway"));
    REQUIRE_FALSE(is_valid_ip_literal(""));
}

// ── Subordinate-CA support (PR6) ─────────────────────────────────────────────

TEST_CASE("x509_ca: cert_matches_key pairs a cert with its private key",
          "[pki][subordinate][security]") {
    auto ca = make_test_ca();
    // The self-signed CA cert is over ca.key → matches.
    REQUIRE(cert_matches_key(ca.cert, ca.key));
    // A DIFFERENT key does NOT match the cert — this is the check that stops an
    // imported intermediate carrying someone else's key from being accepted.
    auto other = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(other);
    REQUIRE_FALSE(cert_matches_key(ca.cert, *other));
    // Garbage in → false (fail closed), never a throw/crash.
    REQUIRE_FALSE(cert_matches_key("not a cert", ca.key));
    REQUIRE_FALSE(cert_matches_key(ca.cert, "not a key"));
}

TEST_CASE("x509_ca: cert_is_ca distinguishes CA certs from leaves",
          "[pki][subordinate][security]") {
    auto ca = make_test_ca();
    REQUIRE(cert_is_ca(ca.cert));

    // A signed end-entity leaf is NOT a CA.
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);
    CsrParams cp;
    cp.subject = {"leaf.example", "Yuzu"};
    auto csr = make_csr(*leaf_key, cp);
    REQUIRE(csr);
    LeafParams lp;
    lp.subject = {"leaf.example", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage = LeafUsage{.server_auth = true};
    auto leaf = sign_csr(*csr, ca.cert, ca.key, lp);
    REQUIRE(leaf);
    REQUIRE_FALSE(cert_is_ca(leaf->cert_pem));
    REQUIRE_FALSE(cert_is_ca("garbage")); // fail closed
}

// The subordinate-CA IMPORT must accept an intermediate only when ALL THREE
// primitives hold: it carries OUR key (cert_matches_key), it is a CA
// (cert_is_ca), and it chains to the declared parent (verify_chain). This models
// the import decision against the artifacts the engine can build in-process and
// asserts each independent rejection reason. (The full positive path — a real
// enterprise-signed intermediate over our key that a leaf then chains through —
// needs an externally-minted CA-signed-CA artifact and is exercised in 6b's
// import-handler test with an openssl fixture; the engine itself never signs CA
// intermediates, that is the enterprise's offline step.)
TEST_CASE("x509_ca: subordinate-CA import primitives reject each bad input independently",
          "[pki][subordinate][security]") {
    auto install = make_test_ca("Yuzu Install CA"); // our issuing key + self-signed cert
    auto enterprise = make_test_ca("Acme Corp Root CA");

    // Export a CSR over our EXISTING key (the artifact the enterprise signs).
    CsrParams ca_csr_params;
    ca_csr_params.subject = {"Yuzu Install CA", "Yuzu"};
    auto ca_csr = make_csr(install.key, ca_csr_params);
    REQUIRE(ca_csr);
    REQUIRE(ca_csr->find("CERTIFICATE REQUEST") != std::string::npos);

    // Reject reason 1: an uploaded "intermediate" that does NOT carry our key
    // (here: the enterprise's own self-signed cert). cert_matches_key is false →
    // import refuses, because we could not sign with a cert whose key we lack.
    REQUIRE_FALSE(cert_matches_key(enterprise.cert, install.key));

    // Reject reason 2: a non-CA cert (an end-entity leaf over our key) — even if
    // it carried our key, it cannot issue. cert_is_ca is false.
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);
    CsrParams lcsr_p;
    lcsr_p.subject = {"not-a-ca", "Yuzu"};
    auto lcsr = make_csr(*leaf_key, lcsr_p);
    REQUIRE(lcsr);
    LeafParams lp;
    lp.subject = {"not-a-ca", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage = LeafUsage{.client_auth = true};
    auto leaf = sign_csr(*lcsr, enterprise.cert, enterprise.key, lp);
    REQUIRE(leaf);
    REQUIRE_FALSE(cert_is_ca(leaf->cert_pem));

    // Reject reason 3: a cert that does not chain to the declared parent. Our
    // self-signed install cert does not verify against the enterprise root.
    REQUIRE_FALSE(verify_chain(install.cert, enterprise.cert));

    // Positive composition on what we CAN build in-process: our self-signed
    // install cert carries our key AND is a CA AND chains to itself — the three
    // checks an import runs, each satisfied.
    REQUIRE(cert_matches_key(install.cert, install.key));
    REQUIRE(cert_is_ca(install.cert));
    REQUIRE(verify_chain(install.cert, install.cert));
}

TEST_CASE("x509_ca: verify_chain_to_bundle finds the anchor among several certs",
          "[pki][subordinate]") {
    auto ca_a = make_test_ca("CA A");
    auto ca_b = make_test_ca("CA B");

    // A leaf signed by CA A.
    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);
    CsrParams cp;
    cp.subject = {"leaf", "Yuzu"};
    auto csr = make_csr(*leaf_key, cp);
    REQUIRE(csr);
    LeafParams lp;
    lp.subject = {"leaf", "Yuzu"};
    lp.validity = validity_days_from_now(30);
    lp.usage = LeafUsage{.client_auth = true};
    auto leaf = sign_csr(*csr, ca_a.cert, ca_a.key, lp);
    REQUIRE(leaf);

    // Single-cert bundle = the real signer → verifies (parity with verify_chain).
    REQUIRE(verify_chain_to_bundle(leaf->cert_pem, ca_a.cert));
    // Multi-cert bundle where the real signer is one of several → still verifies
    // (the anchor is found among the bundle, the point of the bundle variant).
    REQUIRE(verify_chain_to_bundle(leaf->cert_pem, ca_b.cert + ca_a.cert));
    REQUIRE(verify_chain_to_bundle(leaf->cert_pem, ca_a.cert + ca_b.cert));
    // Bundle WITHOUT the real signer → fails.
    REQUIRE_FALSE(verify_chain_to_bundle(leaf->cert_pem, ca_b.cert));
    // Empty / garbage bundle → fails (fail closed), never throws.
    REQUIRE_FALSE(verify_chain_to_bundle(leaf->cert_pem, ""));
    REQUIRE_FALSE(verify_chain_to_bundle(leaf->cert_pem, "not a cert"));
}
