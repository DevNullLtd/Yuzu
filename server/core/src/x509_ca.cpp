#include "x509_ca.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <ctime>

// The engine is only meaningful when libcrypto is linked. CPPHTTPLIB_OPENSSL_SUPPORT
// is the project-wide signal (set by server/core/meson.build's https_cpp_args when
// the openssl dependency is found) — the same guard cert_reloader.cpp uses. Without
// it every entry point returns std::nullopt: a build with no OpenSSL cannot serve
// TLS at all, so a non-functional CA there is consistent, not a regression.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace yuzu::server::pki {

// ── Validity helpers (pure chrono — available with or without OpenSSL) ─────────

Validity validity_years_from_now(int years) {
    const auto now = std::chrono::system_clock::now();
    // 365.25 days/year keeps a 10-year cert from drifting a couple of days short
    // of the wall-clock decade; the ±1d test tolerance in test_x509_ca absorbs
    // the leap-day rounding.
    const auto span = std::chrono::seconds(static_cast<int64_t>(years) * 31557600LL);
    // not_before backdated by kClockSkewBackdate (H-2) so a slightly-behind peer
    // can still validate a just-issued cert.
    return Validity{now - kClockSkewBackdate, now + span};
}

Validity validity_days_from_now(int days) {
    const auto now = std::chrono::system_clock::now();
    return Validity{now - kClockSkewBackdate, now + std::chrono::hours(24 * days)};
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

namespace {

// ── RAII for OpenSSL objects ──────────────────────────────────────────────────

#define YUZU_SSL_PTR(T, freefn)                                                                    \
    struct T##_Deleter {                                                                            \
        void operator()(T* p) const noexcept {                                                      \
            freefn(p);                                                                              \
        }                                                                                          \
    };                                                                                             \
    using T##_ptr = std::unique_ptr<T, T##_Deleter>

YUZU_SSL_PTR(BIO, BIO_free);
YUZU_SSL_PTR(EVP_PKEY, EVP_PKEY_free);
YUZU_SSL_PTR(X509, X509_free);
YUZU_SSL_PTR(X509_REQ, X509_REQ_free);
YUZU_SSL_PTR(X509_CRL, X509_CRL_free);
YUZU_SSL_PTR(X509_NAME, X509_NAME_free);
YUZU_SSL_PTR(X509_EXTENSION, X509_EXTENSION_free);
YUZU_SSL_PTR(X509_STORE, X509_STORE_free);
YUZU_SSL_PTR(X509_STORE_CTX, X509_STORE_CTX_free);
YUZU_SSL_PTR(ASN1_INTEGER, ASN1_INTEGER_free);
YUZU_SSL_PTR(ASN1_TIME, ASN1_TIME_free);
YUZU_SSL_PTR(BIGNUM, BN_free);

#undef YUZU_SSL_PTR

void log_ssl_errors(std::string_view ctx) {
    unsigned long e = 0;
    bool any = false;
    while ((e = ERR_get_error()) != 0) {
        std::array<char, 256> buf{};
        ERR_error_string_n(e, buf.data(), buf.size());
        spdlog::error("x509_ca: {}: {}", ctx, buf.data());
        any = true;
    }
    if (!any)
        spdlog::error("x509_ca: {} (no OpenSSL error detail)", ctx);
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (!data || len <= 0)
        return {};
    return std::string(data, static_cast<std::size_t>(len));
}

// Serialize any PEM-writable object via a callback into a std::string.
template <typename Fn>
std::optional<std::string> to_pem(Fn&& write_fn, std::string_view ctx) {
    BIO_ptr bio{BIO_new(BIO_s_mem())};
    if (!bio) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    if (write_fn(bio.get()) != 1) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    return bio_to_string(bio.get());
}

// Cap PEM/CSR inputs: BIO_new_mem_buf takes an int length, so a >2 GiB blob
// would overflow the size cast, and an attacker-supplied input (the agent CSR
// in PR3) must never be unbounded. 1 MiB is far above any real key/cert/CSR.
constexpr std::size_t kMaxPemSize = 1024 * 1024;

BIO_ptr make_mem_bio(std::string_view pem) {
    if (pem.empty() || pem.size() > kMaxPemSize) {
        spdlog::error("x509_ca: PEM input rejected (size {} bytes)", pem.size());
        return nullptr;
    }
    return BIO_ptr{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
}

EVP_PKEY_ptr load_private_key(std::string_view pem) {
    BIO_ptr bio = make_mem_bio(pem);
    if (!bio)
        return nullptr;
    return EVP_PKEY_ptr{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
}

X509_ptr load_cert(std::string_view pem) {
    BIO_ptr bio = make_mem_bio(pem);
    if (!bio)
        return nullptr;
    return X509_ptr{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

X509_REQ_ptr load_csr(std::string_view pem) {
    BIO_ptr bio = make_mem_bio(pem);
    if (!bio)
        return nullptr;
    return X509_REQ_ptr{PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr)};
}

// Signature digest follows the *issuer* key strength: P-384 → SHA-384, else
// SHA-256. (ECDSA pairs the hash to the curve size; using SHA-256 under a P-384
// key would needlessly weaken the binding.)
const EVP_MD* digest_for_key(const EVP_PKEY* key) {
    const int bits = EVP_PKEY_get_bits(key);
    if (bits >= 521)
        return EVP_sha512();
    if (bits >= 384)
        return EVP_sha384();
    return EVP_sha256();
}

const char* curve_name(KeyAlgo algo) {
    switch (algo) {
    case KeyAlgo::EcP256: return "P-256";
    case KeyAlgo::EcP384: return "P-384";
    }
    return "P-256";
}

// time_point → freshly-allocated ASN1_TIME (UTCTime/GeneralizedTime as needed).
ASN1_TIME_ptr to_asn1_time(std::chrono::system_clock::time_point tp) {
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    return ASN1_TIME_ptr{ASN1_TIME_set(nullptr, t)};
}

std::optional<std::chrono::system_clock::time_point> from_asn1_time(const ASN1_TIME* at) {
    if (!at)
        return std::nullopt;
    std::tm tm{};
    if (ASN1_TIME_to_tm(at, &tm) != 1)
        return std::nullopt;
#ifdef _WIN32
    const std::time_t t = _mkgmtime(&tm);
#else
    const std::time_t t = timegm(&tm);
#endif
    if (t == static_cast<std::time_t>(-1))
        return std::nullopt;
    return std::chrono::system_clock::from_time_t(t);
}

// Build an X509_NAME from a DistinguishedName. Organization defaults to "Yuzu".
X509_NAME_ptr make_name(const DistinguishedName& dn) {
    X509_NAME_ptr name{X509_NAME_new()};
    if (!name)
        return nullptr;
    const std::string org = dn.organization.empty() ? "Yuzu" : dn.organization;
    // Explicit lengths (not -1/strlen): an embedded NUL in a future caller's CN
    // must not silently truncate the DN entry.
    if (X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(org.data()),
                                   static_cast<int>(org.size()), -1, 0) != 1)
        return nullptr;
    if (!dn.common_name.empty() &&
        X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(dn.common_name.data()),
                                   static_cast<int>(dn.common_name.size()), -1, 0) != 1)
        return nullptr;
    return name;
}

// Build a GENERAL_NAMES stack from SubjectAltNames using typed ASN.1 entries.
// This replaces an earlier config-string ("DNS:a,IP:b,...") approach, which let
// a SAN value containing a comma/colon inject EXTRA, unauthorised SAN entries
// once attacker-influenced values (the per-agent URI built from agent_id, PR3)
// reached it. Typed construction has no parsing surface. Caller owns the result
// (GENERAL_NAMES_free). Returns nullptr on empty input or any failure.
GENERAL_NAMES* build_san_gens(const SubjectAltNames& san) {
    if (san.empty())
        return nullptr;
    GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
    if (!gens)
        return nullptr;
    auto push_ia5 = [&](int type, const std::string& v) -> bool {
        if (v.empty())
            return true;
        GENERAL_NAME* gn = GENERAL_NAME_new();
        ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
        if (!gn || !ia5) {
            if (gn)
                GENERAL_NAME_free(gn);
            if (ia5)
                ASN1_IA5STRING_free(ia5);
            return false;
        }
        if (ASN1_STRING_set(ia5, v.data(), static_cast<int>(v.size())) != 1) {
            GENERAL_NAME_free(gn);
            ASN1_IA5STRING_free(ia5);
            return false;
        }
        GENERAL_NAME_set0_value(gn, type, ia5); // gn takes ownership of ia5
        if (sk_GENERAL_NAME_push(gens, gn) <= 0) {
            GENERAL_NAME_free(gn);
            return false;
        }
        return true;
    };
    auto push_ip = [&](const std::string& v) -> bool {
        if (v.empty())
            return true;
        ASN1_OCTET_STRING* ip = a2i_IPADDRESS(v.c_str()); // parses v4/v6; nullptr on bad input
        if (!ip)
            return false;
        GENERAL_NAME* gn = GENERAL_NAME_new();
        if (!gn) {
            ASN1_OCTET_STRING_free(ip);
            return false;
        }
        GENERAL_NAME_set0_value(gn, GEN_IPADD, ip); // gn takes ownership of ip
        if (sk_GENERAL_NAME_push(gens, gn) <= 0) {
            GENERAL_NAME_free(gn);
            return false;
        }
        return true;
    };
    for (const auto& d : san.dns)
        if (!push_ia5(GEN_DNS, d)) {
            GENERAL_NAMES_free(gens);
            return nullptr;
        }
    for (const auto& u : san.uris)
        if (!push_ia5(GEN_URI, u)) {
            GENERAL_NAMES_free(gens);
            return nullptr;
        }
    for (const auto& ip : san.ips)
        if (!push_ip(ip)) {
            GENERAL_NAMES_free(gens);
            return nullptr;
        }
    return gens;
}

// Add an extension by NID built from a config-style string, against ctx.
bool add_ext(X509* cert, X509V3_CTX* ctx, int nid, const std::string& value) {
    X509_EXTENSION_ptr ext{X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str())};
    if (!ext)
        return false;
    return X509_add_ext(cert, ext.get(), -1) == 1;
}

std::string eku_value(const LeafUsage& u) {
    std::string out;
    auto add = [&](const char* s) {
        if (!out.empty())
            out += ',';
        out += s;
    };
    if (u.server_auth)
        add("serverAuth");
    if (u.client_auth)
        add("clientAuth");
    if (u.code_signing)
        add("codeSigning");
    return out;
}

// Generate a random, positive 128-bit serial as uppercase hex (BN_bn2hex form).
std::optional<std::string> random_serial_hex() {
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        return std::nullopt;
    BIGNUM_ptr bn{BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr)};
    if (!bn || BN_is_zero(bn.get()))
        return std::nullopt;
    char* hex = BN_bn2hex(bn.get()); // BN is non-negative → positive serial
    if (!hex)
        return std::nullopt;
    std::string out{hex};
    OPENSSL_free(hex);
    return out;
}

// Set cert serial from hex (caller-provided) or a fresh random one. Returns the
// hex actually used.
std::optional<std::string> set_serial(X509* cert, const std::string& serial_hex) {
    std::string hex = serial_hex;
    if (hex.empty()) {
        auto r = random_serial_hex();
        if (!r)
            return std::nullopt;
        hex = *r;
    } else if (hex.find_first_not_of("0123456789ABCDEFabcdef") != std::string::npos) {
        // Reject a caller-supplied serial that is not strictly positive hex.
        // BN_hex2bn() parses a leading '-' as a negative value, which would
        // produce a non-conforming (RFC 5280) negative serial.
        spdlog::error("x509_ca: rejecting non-hex/negative serial '{}'", hex);
        return std::nullopt;
    }
    BIGNUM* bn_raw = nullptr;
    if (BN_hex2bn(&bn_raw, hex.c_str()) == 0) {
        if (bn_raw)
            BN_free(bn_raw);
        return std::nullopt;
    }
    BIGNUM_ptr bn{bn_raw};
    ASN1_INTEGER_ptr serial{BN_to_ASN1_INTEGER(bn.get(), nullptr)};
    if (!serial || X509_set_serialNumber(cert, serial.get()) != 1)
        return std::nullopt;
    // Normalise to BN_bn2hex's canonical uppercase form so the stored serial
    // round-trips byte-for-byte against parse_certificate / the CRL.
    char* norm = BN_bn2hex(bn.get());
    if (!norm)
        return std::nullopt;
    std::string out{norm};
    OPENSSL_free(norm);
    return out;
}

// Core leaf builder shared by sign_csr (pubkey from CSR) and issue_leaf (pubkey
// from a freshly generated key). `subject_pub` is borrowed.
std::optional<IssuedCert> build_and_sign_leaf(EVP_PKEY* subject_pub, X509* ca_cert,
                                              EVP_PKEY* ca_key, const LeafParams& params) {
    X509_ptr cert{X509_new()};
    if (!cert) {
        log_ssl_errors("leaf X509_new");
        return std::nullopt;
    }
    if (X509_set_version(cert.get(), 2) != 1) { // X509 v3
        log_ssl_errors("leaf set_version");
        return std::nullopt;
    }

    if (params.validity.not_after <= params.validity.not_before) {
        spdlog::error("x509_ca: refusing leaf with a non-positive validity window");
        return std::nullopt;
    }
    // RFC 5280 §4.1.2.5: a leaf MUST NOT outlive its issuer. Reject up front so a
    // caller can never mint a cert that fails chain validation once the CA
    // expires. (PR2 sizes server leaves to the CA's notAfter; agent leaves are
    // far shorter.)
    if (auto ca_na = from_asn1_time(X509_get0_notAfter(ca_cert))) {
        if (params.validity.not_after > *ca_na) {
            spdlog::error("x509_ca: refusing leaf whose notAfter exceeds the issuing CA's");
            return std::nullopt;
        }
    }

    auto serial = set_serial(cert.get(), params.serial_hex);
    if (!serial) {
        log_ssl_errors("leaf set_serial");
        return std::nullopt;
    }

    X509_NAME_ptr subject = make_name(params.subject);
    if (!subject || X509_set_subject_name(cert.get(), subject.get()) != 1) {
        log_ssl_errors("leaf subject");
        return std::nullopt;
    }
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert)) != 1) {
        log_ssl_errors("leaf issuer");
        return std::nullopt;
    }
    if (X509_set_pubkey(cert.get(), subject_pub) != 1) {
        log_ssl_errors("leaf set_pubkey");
        return std::nullopt;
    }

    ASN1_TIME_ptr nb = to_asn1_time(params.validity.not_before);
    ASN1_TIME_ptr na = to_asn1_time(params.validity.not_after);
    if (!nb || !na || X509_set1_notBefore(cert.get(), nb.get()) != 1 ||
        X509_set1_notAfter(cert.get(), na.get()) != 1) {
        log_ssl_errors("leaf validity");
        return std::nullopt;
    }

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert.get(), nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&ctx);
    if (!add_ext(cert.get(), &ctx, NID_basic_constraints, "critical,CA:FALSE") ||
        !add_ext(cert.get(), &ctx, NID_key_usage, "critical,digitalSignature") ||
        !add_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash") ||
        !add_ext(cert.get(), &ctx, NID_authority_key_identifier, "keyid:always")) {
        log_ssl_errors("leaf base extensions");
        return std::nullopt;
    }
    const std::string eku = eku_value(params.usage);
    if (!eku.empty() && !add_ext(cert.get(), &ctx, NID_ext_key_usage, eku)) {
        log_ssl_errors("leaf eku");
        return std::nullopt;
    }
    if (!params.san.empty()) {
        GENERAL_NAMES* gens = build_san_gens(params.san);
        if (!gens) {
            log_ssl_errors("leaf san build");
            return std::nullopt;
        }
        const int rc = X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, gens, 0, 0);
        GENERAL_NAMES_free(gens);
        if (rc != 1) {
            log_ssl_errors("leaf san attach");
            return std::nullopt;
        }
    }

    // X509_sign returns the signature length; 0 means failure (not the usual != 1).
    if (X509_sign(cert.get(), ca_key, digest_for_key(ca_key)) == 0) {
        log_ssl_errors("leaf sign");
        return std::nullopt;
    }

    auto pem = to_pem([&](BIO* b) { return PEM_write_bio_X509(b, cert.get()); }, "leaf to_pem");
    if (!pem)
        return std::nullopt;
    return IssuedCert{*pem, *serial};
}

} // namespace

// ── Key generation ────────────────────────────────────────────────────────────

std::optional<std::string> generate_private_key(KeyAlgo algo) {
    EVP_PKEY_ptr key{EVP_EC_gen(curve_name(algo))};
    if (!key) {
        log_ssl_errors("generate_private_key EVP_EC_gen");
        return std::nullopt;
    }
    return to_pem(
        [&](BIO* b) {
            return PEM_write_bio_PrivateKey(b, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        },
        "generate_private_key to_pem");
}

// ── CA root ───────────────────────────────────────────────────────────────────

std::optional<std::string> self_sign_ca(std::string_view ca_key_pem, const CaParams& params) {
    EVP_PKEY_ptr key = load_private_key(ca_key_pem);
    if (!key) {
        log_ssl_errors("self_sign_ca load key");
        return std::nullopt;
    }

    X509_ptr cert{X509_new()};
    if (!cert || X509_set_version(cert.get(), 2) != 1) {
        log_ssl_errors("self_sign_ca new");
        return std::nullopt;
    }
    if (!set_serial(cert.get(), "")) {
        log_ssl_errors("self_sign_ca serial");
        return std::nullopt;
    }
    if (params.validity.not_after <= params.validity.not_before) {
        spdlog::error("x509_ca: refusing CA with a non-positive validity window");
        return std::nullopt;
    }

    X509_NAME_ptr name = make_name(params.subject);
    if (!name || X509_set_subject_name(cert.get(), name.get()) != 1 ||
        X509_set_issuer_name(cert.get(), name.get()) != 1) { // self-signed: subject == issuer
        log_ssl_errors("self_sign_ca name");
        return std::nullopt;
    }
    if (X509_set_pubkey(cert.get(), key.get()) != 1) {
        log_ssl_errors("self_sign_ca pubkey");
        return std::nullopt;
    }

    ASN1_TIME_ptr nb = to_asn1_time(params.validity.not_before);
    ASN1_TIME_ptr na = to_asn1_time(params.validity.not_after);
    if (!nb || !na || X509_set1_notBefore(cert.get(), nb.get()) != 1 ||
        X509_set1_notAfter(cert.get(), na.get()) != 1) {
        log_ssl_errors("self_sign_ca validity");
        return std::nullopt;
    }

    // Extensions. Add SKI first; AKI keyid then resolves against this cert
    // (issuer == subject for a self-signed root).
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&ctx); // no config db; required after set_ctx (leaves ctx->db uninit otherwise)
    const std::string bc = "critical,CA:TRUE,pathlen:" + std::to_string(params.path_len);
    if (!add_ext(cert.get(), &ctx, NID_basic_constraints, bc) ||
        !add_ext(cert.get(), &ctx, NID_key_usage, "critical,keyCertSign,cRLSign") ||
        !add_ext(cert.get(), &ctx, NID_subject_key_identifier, "hash") ||
        !add_ext(cert.get(), &ctx, NID_authority_key_identifier, "keyid:always,issuer")) {
        log_ssl_errors("self_sign_ca extensions");
        return std::nullopt;
    }

    if (X509_sign(cert.get(), key.get(), digest_for_key(key.get())) == 0) {
        log_ssl_errors("self_sign_ca sign");
        return std::nullopt;
    }
    return to_pem([&](BIO* b) { return PEM_write_bio_X509(b, cert.get()); }, "self_sign_ca to_pem");
}

// ── CSR ───────────────────────────────────────────────────────────────────────

std::optional<std::string> make_csr(std::string_view key_pem, const CsrParams& params) {
    EVP_PKEY_ptr key = load_private_key(key_pem);
    if (!key) {
        log_ssl_errors("make_csr load key");
        return std::nullopt;
    }
    X509_REQ_ptr req{X509_REQ_new()};
    if (!req || X509_REQ_set_version(req.get(), 0) != 1) {
        log_ssl_errors("make_csr new");
        return std::nullopt;
    }
    X509_NAME_ptr name = make_name(params.subject);
    if (!name || X509_REQ_set_subject_name(req.get(), name.get()) != 1) {
        log_ssl_errors("make_csr subject");
        return std::nullopt;
    }
    if (X509_REQ_set_pubkey(req.get(), key.get()) != 1) {
        log_ssl_errors("make_csr pubkey");
        return std::nullopt;
    }

    if (!params.san.empty()) {
        GENERAL_NAMES* gens = build_san_gens(params.san);
        if (!gens) {
            log_ssl_errors("make_csr san build");
            return std::nullopt;
        }
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
        GENERAL_NAMES_free(gens);
        if (!ext) {
            log_ssl_errors("make_csr san ext");
            return std::nullopt;
        }
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
        if (!exts || sk_X509_EXTENSION_push(exts, ext) <= 0) {
            X509_EXTENSION_free(ext);
            if (exts)
                sk_X509_EXTENSION_free(exts);
            log_ssl_errors("make_csr exts stack");
            return std::nullopt;
        }
        // X509_REQ_add_extensions SERIALISES `exts` into a request attribute and
        // does NOT take ownership (the parameter is a const stack), so the caller
        // MUST free it. pop_free releases both the stack and the pushed extension.
        // (This is the canonical OpenSSL idiom — not a double-free.)
        const int rc = X509_REQ_add_extensions(req.get(), exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        if (rc != 1) {
            log_ssl_errors("make_csr add_extensions");
            return std::nullopt;
        }
    }

    if (X509_REQ_sign(req.get(), key.get(), digest_for_key(key.get())) == 0) {
        log_ssl_errors("make_csr sign");
        return std::nullopt;
    }
    return to_pem([&](BIO* b) { return PEM_write_bio_X509_REQ(b, req.get()); }, "make_csr to_pem");
}

// ── Leaf issuance ─────────────────────────────────────────────────────────────

std::optional<IssuedCert> sign_csr(std::string_view csr_pem, std::string_view ca_cert_pem,
                                   std::string_view ca_key_pem, const LeafParams& params) {
    X509_REQ_ptr req = load_csr(csr_pem);
    if (!req) {
        log_ssl_errors("sign_csr load csr");
        return std::nullopt;
    }
    // Proof of possession: the CSR must be self-signed by the key it carries.
    EVP_PKEY* req_pub = X509_REQ_get0_pubkey(req.get()); // borrowed
    if (!req_pub || X509_REQ_verify(req.get(), req_pub) != 1) {
        log_ssl_errors("sign_csr POP verify");
        return std::nullopt;
    }
    X509_ptr ca = load_cert(ca_cert_pem);
    EVP_PKEY_ptr ca_key = load_private_key(ca_key_pem);
    if (!ca || !ca_key) {
        log_ssl_errors("sign_csr load ca");
        return std::nullopt;
    }
    // NOTE: only req_pub crosses over from the CSR. Subject/SAN/EKU come from
    // `params` (server-chosen) — the CSR's own subject/SAN are never trusted.
    return build_and_sign_leaf(req_pub, ca.get(), ca_key.get(), params);
}

std::optional<KeyAndCert> issue_leaf(std::string_view ca_cert_pem, std::string_view ca_key_pem,
                                     KeyAlgo leaf_algo, const LeafParams& params) {
    auto leaf_key_pem = generate_private_key(leaf_algo);
    if (!leaf_key_pem)
        return std::nullopt;
    EVP_PKEY_ptr leaf_key = load_private_key(*leaf_key_pem);
    X509_ptr ca = load_cert(ca_cert_pem);
    EVP_PKEY_ptr ca_key = load_private_key(ca_key_pem);
    if (!leaf_key || !ca || !ca_key) {
        log_ssl_errors("issue_leaf load");
        return std::nullopt;
    }
    auto issued = build_and_sign_leaf(leaf_key.get(), ca.get(), ca_key.get(), params);
    if (!issued)
        return std::nullopt;
    return KeyAndCert{*leaf_key_pem, issued->cert_pem, issued->serial_hex};
}

// ── CRL ───────────────────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> build_crl(std::string_view ca_cert_pem,
                                              std::string_view ca_key_pem,
                                              const std::vector<CrlRevocation>& revoked,
                                              const Validity& crl_validity, uint64_t crl_number) {
    X509_ptr ca = load_cert(ca_cert_pem);
    EVP_PKEY_ptr ca_key = load_private_key(ca_key_pem);
    if (!ca || !ca_key) {
        log_ssl_errors("build_crl load ca");
        return std::nullopt;
    }
    X509_CRL_ptr crl{X509_CRL_new()};
    if (!crl || X509_CRL_set_version(crl.get(), 1) != 1) { // v2
        log_ssl_errors("build_crl new");
        return std::nullopt;
    }
    if (X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca.get())) != 1) {
        log_ssl_errors("build_crl issuer");
        return std::nullopt;
    }
    ASN1_TIME_ptr last = to_asn1_time(crl_validity.not_before);
    ASN1_TIME_ptr next = to_asn1_time(crl_validity.not_after);
    if (!last || !next || X509_CRL_set1_lastUpdate(crl.get(), last.get()) != 1 ||
        X509_CRL_set1_nextUpdate(crl.get(), next.get()) != 1) {
        log_ssl_errors("build_crl times");
        return std::nullopt;
    }

    for (const auto& r : revoked) {
        BIGNUM* bn_raw = nullptr;
        // Fail closed: a bad serial must abort CRL generation, never be silently
        // dropped (a dropped revocation = a cert that still validates).
        if (r.serial_hex.empty() ||
            r.serial_hex.find_first_not_of("0123456789ABCDEFabcdef") != std::string::npos ||
            BN_hex2bn(&bn_raw, r.serial_hex.c_str()) == 0) {
            if (bn_raw)
                BN_free(bn_raw);
            spdlog::error("x509_ca: build_crl bad serial '{}' — failing closed", r.serial_hex);
            return std::nullopt;
        }
        BIGNUM_ptr bn{bn_raw};
        ASN1_INTEGER_ptr serial{BN_to_ASN1_INTEGER(bn.get(), nullptr)};
        ASN1_TIME_ptr rev_time = to_asn1_time(r.revoked_at);
        X509_REVOKED* rev = X509_REVOKED_new(); // ownership transfers on add0
        if (!serial || !rev_time || !rev) {
            if (rev)
                X509_REVOKED_free(rev);
            log_ssl_errors("build_crl revoked alloc");
            return std::nullopt;
        }
        if (X509_REVOKED_set_serialNumber(rev, serial.get()) != 1 ||
            X509_REVOKED_set_revocationDate(rev, rev_time.get()) != 1 ||
            X509_CRL_add0_revoked(crl.get(), rev) != 1) {
            X509_REVOKED_free(rev);
            log_ssl_errors("build_crl add revoked");
            return std::nullopt;
        }
    }

    // crlNumber extension (monotonic sequence).
    {
        // BN_set_word takes a BN_ULONG, which is only 32-bit on Windows (LLP64),
        // so a crl_number above 2^32 would silently truncate. Build the BIGNUM
        // from the full 8-byte big-endian representation instead — platform-
        // independent and exact for the whole uint64_t range.
        std::array<unsigned char, 8> be{};
        for (int i = 0; i < 8; ++i)
            be[static_cast<std::size_t>(7 - i)] =
                static_cast<unsigned char>((crl_number >> (8 * i)) & 0xFFu);
        BIGNUM_ptr bn{BN_bin2bn(be.data(), static_cast<int>(be.size()), nullptr)};
        if (!bn) {
            log_ssl_errors("build_crl crlNumber bn");
            return std::nullopt;
        }
        ASN1_INTEGER_ptr num{BN_to_ASN1_INTEGER(bn.get(), nullptr)};
        if (!num || X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, num.get(), 0, 0) != 1) {
            log_ssl_errors("build_crl crlNumber ext");
            return std::nullopt;
        }
    }

    // Authority Key Identifier (RFC 5280 §5.2.1 SHOULD): lets validators match
    // the CRL to the issuing CA by key id, not just issuer name.
    {
        X509V3_CTX crlctx;
        X509V3_set_ctx(&crlctx, ca.get(), nullptr, nullptr, crl.get(), 0);
        X509V3_set_ctx_nodb(&crlctx);
        X509_EXTENSION_ptr akid{
            X509V3_EXT_conf_nid(nullptr, &crlctx, NID_authority_key_identifier, "keyid:always")};
        if (!akid || X509_CRL_add_ext(crl.get(), akid.get(), -1) != 1) {
            log_ssl_errors("build_crl akid");
            return std::nullopt;
        }
    }

    if (X509_CRL_sort(crl.get()) != 1) {
        log_ssl_errors("build_crl sort");
        return std::nullopt;
    }
    if (X509_CRL_sign(crl.get(), ca_key.get(), digest_for_key(ca_key.get())) == 0) {
        log_ssl_errors("build_crl sign");
        return std::nullopt;
    }

    unsigned char* der = nullptr;
    const int len = i2d_X509_CRL(crl.get(), &der);
    if (len <= 0 || !der) {
        log_ssl_errors("build_crl i2d");
        return std::nullopt;
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

// ── Inspection / verification ─────────────────────────────────────────────────

std::optional<std::string> fingerprint_sha256(std::string_view cert_pem) {
    X509_ptr cert = load_cert(cert_pem);
    if (!cert) {
        log_ssl_errors("fingerprint load");
        return std::nullopt;
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int n = 0;
    if (X509_digest(cert.get(), EVP_sha256(), md.data(), &n) != 1) {
        log_ssl_errors("fingerprint digest");
        return std::nullopt;
    }
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 3);
    for (unsigned int i = 0; i < n; ++i) {
        if (i)
            out += ':';
        out += kHex[md[i] >> 4];
        out += kHex[md[i] & 0x0F];
    }
    return out;
}

std::optional<std::string> issuer_key_id(std::string_view cert_pem) {
    X509_ptr cert = load_cert(cert_pem);
    if (!cert) {
        log_ssl_errors("issuer_key_id load");
        return std::nullopt;
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int n = 0;
    // Digest of the subjectPublicKey BIT STRING — NOT the whole cert — so the value
    // is stable across a subordinate re-key (same key, different issuer cert).
    if (X509_pubkey_digest(cert.get(), EVP_sha256(), md.data(), &n) != 1) {
        log_ssl_errors("issuer_key_id digest");
        return std::nullopt;
    }
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 3);
    for (unsigned int i = 0; i < n; ++i) {
        if (i)
            out += ':';
        out += kHex[md[i] >> 4];
        out += kHex[md[i] & 0x0F];
    }
    return out;
}

bool is_valid_ip_literal(const std::string& s) {
    if (s.empty())
        return false;
    // Exactly the parser the SAN builder uses (push_ip / a2i_IPADDRESS), so an
    // accepted value can never be rejected downstream by issue_leaf.
    ASN1_OCTET_STRING* ip = a2i_IPADDRESS(s.c_str());
    if (!ip) {
        // a2i_IPADDRESS can push onto the OpenSSL error stack on an internal
        // alloc failure; this is a speculative classification check, so clear it
        // rather than let a stale error pollute a later issue_leaf log.
        ERR_clear_error();
        return false;
    }
    ASN1_OCTET_STRING_free(ip);
    return true;
}

bool subject_key_meets_code_signing_floor(std::string_view csr_pem) {
    X509_REQ_ptr req = load_csr(csr_pem);
    if (!req) {
        // Not this function's job to log a full error trace for an already-
        // rejected/oversize CSR — just fail closed.
        ERR_clear_error();
        return false;
    }
    EVP_PKEY* pub = X509_REQ_get0_pubkey(req.get()); // borrowed
    if (!pub)
        return false;
    const int base_id = EVP_PKEY_base_id(pub);
    if (base_id == EVP_PKEY_RSA) {
        const int bits = EVP_PKEY_get_bits(pub);
        return bits >= 2048 && bits <= 16384;
    }
    if (base_id == EVP_PKEY_EC) {
        char group[80] = {};
        std::size_t group_len = 0;
        if (EVP_PKEY_get_group_name(pub, group, sizeof(group), &group_len) != 1) {
            ERR_clear_error();
            return false; // can't identify the curve — fail closed
        }
        const std::string_view name(group, group_len);
        // OpenSSL short-names for the three NIST curves TLS 1.3 treats as
        // first-class (matches this file's own P-256/P-384 leaf/CA choice).
        return name == "prime256v1" || name == "secp384r1" || name == "secp521r1";
    }
    // gov MED-2: Ed25519/Ed448 are REJECTED, not accepted. detached_signature.cpp's
    // own CMS_verify tolerates them, but `openssl cms -sign` — the documented
    // code-signing tool (docs/user-manual/agent-plugins.md,
    // docs/user-manual/server-admin.md) — fails on an Ed25519/Ed448 codeSigning
    // cert ("no default digest"), so issuing one would hand the operator a leaf
    // the shipped tooling cannot use. The accepted set is RSA 2048-16384 and EC
    // P-256/P-384/P-521 ONLY; any other key type (RSA-PSS, DH, X25519, Ed25519,
    // Ed448, …) is rejected.
    return false;
}

namespace {

DistinguishedName name_to_dn(X509_NAME* nm) {
    DistinguishedName dn;
    auto field = [&](int nid) -> std::string {
        const int idx = X509_NAME_get_index_by_NID(nm, nid, -1);
        if (idx < 0)
            return {};
        X509_NAME_ENTRY* e = X509_NAME_get_entry(nm, idx);
        ASN1_STRING* s = e ? X509_NAME_ENTRY_get_data(e) : nullptr;
        if (!s)
            return {};
        unsigned char* utf8 = nullptr;
        const int len = ASN1_STRING_to_UTF8(&utf8, s);
        if (len < 0 || !utf8)
            return {};
        std::string out(reinterpret_cast<char*>(utf8), static_cast<std::size_t>(len));
        OPENSSL_free(utf8);
        return out;
    };
    dn.common_name = field(NID_commonName);
    dn.organization = field(NID_organizationName);
    return dn;
}

void extract_san(X509* cert, SubjectAltNames& out) {
    auto* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!names)
        return;
    const int count = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < count; ++i) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        if (!gn)
            continue;
        if (gn->type == GEN_DNS) {
            // Use the explicit ASN.1 length, never strlen — a crafted dNSName
            // with an embedded NUL would otherwise over-read into adjacent heap.
            const unsigned char* d = ASN1_STRING_get0_data(gn->d.dNSName);
            const int len = ASN1_STRING_length(gn->d.dNSName);
            if (d && len > 0)
                out.dns.emplace_back(reinterpret_cast<const char*>(d),
                                     static_cast<std::size_t>(len));
        } else if (gn->type == GEN_URI) {
            const unsigned char* d = ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier);
            const int len = ASN1_STRING_length(gn->d.uniformResourceIdentifier);
            if (d && len > 0)
                out.uris.emplace_back(reinterpret_cast<const char*>(d),
                                      static_cast<std::size_t>(len));
        } else if (gn->type == GEN_IPADD) {
            const ASN1_OCTET_STRING* ip = gn->d.iPAddress;
            std::array<char, 64> buf{};
            if (ip && ip->length == 4) {
                std::snprintf(buf.data(), buf.size(), "%d.%d.%d.%d", ip->data[0], ip->data[1],
                              ip->data[2], ip->data[3]);
                out.ips.emplace_back(buf.data());
            } else if (ip && ip->length == 16) {
                auto grp = [&](int a, int b) {
                    return static_cast<unsigned>((ip->data[a] << 8) | ip->data[b]);
                };
                std::snprintf(buf.data(), buf.size(), "%x:%x:%x:%x:%x:%x:%x:%x", grp(0, 1),
                              grp(2, 3), grp(4, 5), grp(6, 7), grp(8, 9), grp(10, 11), grp(12, 13),
                              grp(14, 15));
                out.ips.emplace_back(buf.data());
            }
        }
    }
    GENERAL_NAMES_free(names);
}

} // namespace

std::optional<CertDetails> parse_certificate(std::string_view cert_pem) {
    X509_ptr cert = load_cert(cert_pem);
    if (!cert) {
        log_ssl_errors("parse_certificate load");
        return std::nullopt;
    }
    CertDetails d;
    d.subject = name_to_dn(X509_get_subject_name(cert.get()));
    d.issuer = name_to_dn(X509_get_issuer_name(cert.get()));

    if (const ASN1_INTEGER* s = X509_get0_serialNumber(cert.get())) {
        BIGNUM_ptr bn{ASN1_INTEGER_to_BN(s, nullptr)};
        if (bn) {
            char* hex = BN_bn2hex(bn.get());
            if (hex) {
                d.serial_hex = hex;
                OPENSSL_free(hex);
            }
        }
    }
    if (auto nb = from_asn1_time(X509_get0_notBefore(cert.get())))
        d.not_before = *nb;
    if (auto na = from_asn1_time(X509_get0_notAfter(cert.get())))
        d.not_after = *na;
    d.is_ca = X509_check_ca(cert.get()) > 0;
    extract_san(cert.get(), d.san);
    return d;
}

bool verify_chain(std::string_view leaf_pem, std::string_view ca_pem) {
    X509_ptr leaf = load_cert(leaf_pem);
    X509_ptr ca = load_cert(ca_pem);
    if (!leaf || !ca) {
        log_ssl_errors("verify_chain load");
        return false;
    }
    X509_STORE_ptr store{X509_STORE_new()};
    if (!store || X509_STORE_add_cert(store.get(), ca.get()) != 1) {
        log_ssl_errors("verify_chain store");
        return false;
    }
    X509_STORE_CTX_ptr ctx{X509_STORE_CTX_new()};
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), nullptr) != 1) {
        log_ssl_errors("verify_chain ctx");
        return false;
    }
    const int rc = X509_verify_cert(ctx.get());
    if (rc != 1) {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        spdlog::warn("x509_ca: verify_chain failed: {}", X509_verify_cert_error_string(err));
    }
    return rc == 1;
}

bool cert_matches_key(std::string_view cert_pem, std::string_view key_pem) {
    X509_ptr cert = load_cert(cert_pem);
    EVP_PKEY_ptr key = load_private_key(key_pem);
    if (!cert || !key) {
        log_ssl_errors("cert_matches_key load");
        return false;
    }
    // X509_get_pubkey returns a NEW reference — own it so it is freed.
    EVP_PKEY_ptr cert_pub{X509_get_pubkey(cert.get())};
    if (!cert_pub) {
        log_ssl_errors("cert_matches_key pubkey");
        return false;
    }
    // EVP_PKEY_eq compares the PUBLIC components only; a private key carries its
    // public half, so this is true iff the cert was issued over `key`'s pair.
    // (1 = match; 0 = mismatch; <0 = not-comparable/error → treat as no match.)
    const int rc = EVP_PKEY_eq(cert_pub.get(), key.get());
    if (rc != 1)
        spdlog::warn("x509_ca: cert_matches_key mismatch (rc={})", rc);
    return rc == 1;
}

bool cert_is_ca(std::string_view cert_pem) {
    X509_ptr cert = load_cert(cert_pem);
    if (!cert) {
        log_ssl_errors("cert_is_ca load");
        return false;
    }
    // X509_check_ca returns >0 when the cert is a CA (1 = with basicConstraints
    // CA:TRUE; other positive values are legacy/v1 heuristics). Require the
    // explicit basicConstraints CA:TRUE form (==1) — an enterprise subordinate CA
    // must carry it; we will not accept a v1/heuristic "CA" as an issuing cert.
    return X509_check_ca(cert.get()) == 1;
}

bool verify_chain_to_bundle(std::string_view cert_pem, std::string_view bundle_pem) {
    X509_ptr target = load_cert(cert_pem);
    if (!target) {
        log_ssl_errors("verify_chain_to_bundle load target");
        return false;
    }
    BIO_ptr bio = make_mem_bio(bundle_pem);
    if (!bio)
        return false;
    X509_STORE_ptr store{X509_STORE_new()};
    if (!store) {
        log_ssl_errors("verify_chain_to_bundle store");
        return false;
    }
    // Add EVERY cert in the bundle as a trust anchor so a parent chain of any
    // depth (enterprise root [+ intermediates]) that roots `target` validates.
    // The operator is Security:Write-authorised and chose this hierarchy; this
    // check confirms the uploaded material is self-consistent and actually signs
    // our intermediate, not that any particular cert is independently trusted.
    int added = 0;
    for (;;) {
        X509_ptr c{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
        if (!c)
            break; // no more certs (or a parse boundary) — stop
        if (X509_STORE_add_cert(store.get(), c.get()) == 1)
            ++added;
    }
    // Clear the benign "no start line" EOF error PEM_read_bio_X509 leaves when it
    // runs off the end of the bundle, so it doesn't masquerade as a real failure.
    ERR_clear_error();
    if (added == 0) {
        spdlog::warn("x509_ca: verify_chain_to_bundle — no certs parsed from bundle");
        return false;
    }
    X509_STORE_CTX_ptr ctx{X509_STORE_CTX_new()};
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), target.get(), nullptr) != 1) {
        log_ssl_errors("verify_chain_to_bundle ctx");
        return false;
    }
    const int rc = X509_verify_cert(ctx.get());
    if (rc != 1) {
        const int err = X509_STORE_CTX_get_error(ctx.get());
        spdlog::warn("x509_ca: verify_chain_to_bundle failed: {}",
                     X509_verify_cert_error_string(err));
    }
    return rc == 1;
}

#else // !CPPHTTPLIB_OPENSSL_SUPPORT — stubs

static std::optional<std::string> unavailable() {
    spdlog::error("x509_ca: OpenSSL not available; CA operations are disabled");
    return std::nullopt;
}

std::optional<std::string> generate_private_key(KeyAlgo) { return unavailable(); }
std::optional<std::string> self_sign_ca(std::string_view, const CaParams&) { return unavailable(); }
std::optional<std::string> make_csr(std::string_view, const CsrParams&) { return unavailable(); }
std::optional<IssuedCert> sign_csr(std::string_view, std::string_view, std::string_view,
                                   const LeafParams&) {
    (void)unavailable();
    return std::nullopt;
}
std::optional<KeyAndCert> issue_leaf(std::string_view, std::string_view, KeyAlgo,
                                     const LeafParams&) {
    (void)unavailable();
    return std::nullopt;
}
std::optional<std::vector<uint8_t>> build_crl(std::string_view, std::string_view,
                                              const std::vector<CrlRevocation>&, const Validity&,
                                              uint64_t) {
    (void)unavailable();
    return std::nullopt;
}
std::optional<std::string> fingerprint_sha256(std::string_view) { return unavailable(); }
std::optional<std::string> issuer_key_id(std::string_view) { return unavailable(); }
std::optional<CertDetails> parse_certificate(std::string_view) {
    (void)unavailable();
    return std::nullopt;
}
bool verify_chain(std::string_view, std::string_view) {
    (void)unavailable();
    return false;
}
bool cert_matches_key(std::string_view, std::string_view) {
    (void)unavailable();
    return false;
}
bool cert_is_ca(std::string_view) {
    (void)unavailable();
    return false;
}
bool verify_chain_to_bundle(std::string_view, std::string_view) {
    (void)unavailable();
    return false;
}
bool subject_key_meets_code_signing_floor(std::string_view) {
    (void)unavailable();
    return false; // fail closed — no OpenSSL means no issuance path either.
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

} // namespace yuzu::server::pki
