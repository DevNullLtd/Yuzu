#include "gateway_peer_cert.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace yuzu::server::gateway_peer {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

namespace {

struct BioDeleter {
    void operator()(BIO* b) const noexcept { BIO_free(b); }
};
struct X509Deleter {
    void operator()(X509* x) const noexcept { X509_free(x); }
};
struct Asn1TimeDeleter {
    void operator()(ASN1_TIME* t) const noexcept { ASN1_TIME_free(t); }
};
struct EkuDeleter {
    void operator()(EXTENDED_KEY_USAGE* e) const noexcept { EXTENDED_KEY_USAGE_free(e); }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;
using EkuPtr = std::unique_ptr<EXTENDED_KEY_USAGE, EkuDeleter>;

/// Empties this thread's OpenSSL error queue on EVERY exit of the scope that owns it, so
/// an early return can never leave an entry for an unrelated caller on the same thread.
struct ErrQueueClearer {
    ErrQueueClearer() = default;
    ErrQueueClearer(const ErrQueueClearer&) = delete;
    ErrQueueClearer& operator=(const ErrQueueClearer&) = delete;
    ~ErrQueueClearer() { ERR_clear_error(); }
};

X509Ptr load_first_cert(std::string_view pem) {
    if (pem.empty() || pem.size() > kMaxCertPemBytes)
        return nullptr;
    BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio)
        return nullptr;
    return X509Ptr{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

/// Seconds since the epoch of an ASN1_TIME, computed as a difference against an
/// epoch ASN1_TIME so no timegm/time_t arithmetic is involved. Kept as whole
/// seconds (`CertInstant`): see the note on that type.
std::optional<CertInstant> to_time_point(const ASN1_TIME* t) {
    if (!t)
        return std::nullopt;
    Asn1TimePtr epoch{ASN1_TIME_set(nullptr, 0)};
    if (!epoch)
        return std::nullopt;
    int days = 0;
    int secs = 0;
    if (ASN1_TIME_diff(&days, &secs, epoch.get(), t) != 1)
        return std::nullopt;
    const std::int64_t total = static_cast<std::int64_t>(days) * 86400 + secs;
    return CertInstant{std::chrono::seconds{total}};
}

bool server_auth_listed(X509* cert) {
    // X509_get_ext_d2i yields nullptr for an absent extension AND for a
    // malformed one; both are "not listed", which is the fail-closed answer.
    EkuPtr eku{static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr))};
    if (!eku)
        return false;
    const int n = sk_ASN1_OBJECT_num(eku.get());
    for (int i = 0; i < n; ++i) {
        const ASN1_OBJECT* o = sk_ASN1_OBJECT_value(eku.get(), i);
        if (o && OBJ_obj2nid(o) == NID_server_auth)
            return true;
    }
    return false;
}

constexpr char kHexDigits[] = "0123456789abcdef";

} // namespace

std::optional<std::string> spki_sha256_hex(const x509_st* cert) {
    const ErrQueueClearer clear_errors;
    if (!cert)
        return std::nullopt;
    X509_PUBKEY* pk = X509_get_X509_PUBKEY(cert);
    if (!pk)
        return std::nullopt;
    const int der_len = i2d_X509_PUBKEY(pk, nullptr);
    if (der_len <= 0)
        return std::nullopt;
    std::vector<unsigned char> der(static_cast<std::size_t>(der_len));
    unsigned char* cursor = der.data();
    if (i2d_X509_PUBKEY(pk, &cursor) != der_len)
        return std::nullopt;

    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int md_len = 0;
    if (EVP_Digest(der.data(), der.size(), md.data(), &md_len, EVP_sha256(), nullptr) != 1)
        return std::nullopt;
    if (md_len != 32)
        return std::nullopt;

    std::string out;
    out.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        out += kHexDigits[md[i] >> 4];
        out += kHexDigits[md[i] & 0x0F];
    }
    return out;
}

std::optional<std::string> spki_sha256_hex(std::string_view cert_pem) {
    const ErrQueueClearer clear_errors;
    X509Ptr cert = load_first_cert(cert_pem);
    if (!cert)
        return std::nullopt;
    return spki_sha256_hex(cert.get());
}

std::optional<CertFacts> parse_cert_facts(std::string_view cert_pem) {
    const ErrQueueClearer clear_errors;
    X509Ptr cert = load_first_cert(cert_pem);
    if (!cert)
        return std::nullopt;
    CertFacts f;
    auto pin = spki_sha256_hex(cert.get());
    if (!pin || pin->empty())
        return std::nullopt;
    f.spki_sha256_hex = std::move(*pin);

    auto nb = to_time_point(X509_get0_notBefore(cert.get()));
    auto na = to_time_point(X509_get0_notAfter(cert.get()));
    if (!nb || !na)
        return std::nullopt;
    f.not_before = *nb;
    f.not_after = *na;
    f.has_server_auth_eku = server_auth_listed(cert.get());
    return f;
}

#else // !CPPHTTPLIB_OPENSSL_SUPPORT

std::optional<std::string> spki_sha256_hex(const x509_st*) { return std::nullopt; }
std::optional<std::string> spki_sha256_hex(std::string_view) { return std::nullopt; }
std::optional<CertFacts> parse_cert_facts(std::string_view) { return std::nullopt; }

#endif

} // namespace yuzu::server::gateway_peer
