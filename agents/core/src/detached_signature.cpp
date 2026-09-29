#include <yuzu/agent/detached_signature.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstdio> // SEEK_SET / SEEK_CUR
#include <limits>
#include <memory>

#ifdef _WIN32
#include <io.h> // _lseeki64
#else
#include <unistd.h> // lseek
#endif

#include <openssl/bio.h>
// pem.h MUST precede cms.h and is NOT sorted alphabetically for that reason.
// `PEM_read_bio_CMS` is declared by `DECLARE_PEM_rw(CMS, CMS_ContentInfo)` inside
// cms.h, and that macro is defined in pem.h — include cms.h first and the macro
// expands to nothing, so the function silently does not exist and the only
// symptom is an "undeclared identifier" a long way from the cause.
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace yuzu::agent {
namespace {

struct OpenSslDeleter {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
    void operator()(CMS_ContentInfo* p) const noexcept { CMS_ContentInfo_free(p); }
    void operator()(X509_STORE* p) const noexcept { X509_STORE_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
};

template <typename T> using openssl_ptr = std::unique_ptr<T, OpenSslDeleter>;

/// Seek wrapper. 64-bit on both platforms deliberately: an update binary can
/// exceed 2 GiB, and a 32-bit offset would silently wrap rather than fail.
/// Returns -1 on error, matching the underlying calls.
std::int64_t seek_fd(int fd, std::int64_t offset, int whence) {
#ifdef _WIN32
    return ::_lseeki64(fd, offset, whence);
#else
    return static_cast<std::int64_t>(::lseek(fd, static_cast<off_t>(offset), whence));
#endif
}

// Drain the OpenSSL error queue into (text, classification). The classification
// flag is true if any drained error came from the X.509 chain validation path
// (CMS or X509 lib reporting cert-verify failure) — so the caller can pick
// between "untrusted chain" and "invalid signature" without re-parsing free-form
// text.
struct DrainedErrors {
    std::string text;
    bool chain_failure{false};
};

DrainedErrors drain_openssl_errors() {
    DrainedErrors out;
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        const int lib = ERR_GET_LIB(e);
        const int reason = ERR_GET_REASON(e);
        // ERR_LIB_CMS / CMS_R_CERTIFICATE_VERIFY_ERROR == 100
        // ERR_LIB_X509 covers all chain-validation surfaces.
        if (lib == ERR_LIB_X509 ||
            (lib == ERR_LIB_CMS && reason == CMS_R_CERTIFICATE_VERIFY_ERROR)) {
            out.chain_failure = true;
        }
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.text.empty())
            out.text += "; ";
        out.text += buf;
    }
    return out;
}

openssl_ptr<X509_STORE> load_trust_store(const std::filesystem::path& bundle_path) {
    openssl_ptr<X509_STORE> store{X509_STORE_new()};
    if (!store)
        return nullptr;

    // X509_STORE_load_locations interprets a *file* parameter as one or more
    // concatenated PEM certs — exactly the format we promise the operator. The
    // third arg (path) lets OpenSSL also accept a hashed dir; we only support a
    // single bundle file today, so pass nullptr.
    if (X509_STORE_load_locations(store.get(), bundle_path.string().c_str(), nullptr) != 1) {
        spdlog::error("Failed to load signature trust bundle '{}': {}", bundle_path.string(),
                      drain_openssl_errors().text);
        return nullptr;
    }
    // Signing certs MUST carry EKU=codeSigning (RFC 5280 §4.2.1.12). Setting the
    // X509_STORE purpose forces OpenSSL to enforce the EKU during chain
    // validation. A leaf without codeSigning EKU — e.g. an mTLS server cert,
    // S/MIME cert, or TLS client cert minted by the *same* CA the operator
    // trusts — is rejected. Without this, a single CA whose downstream issues a
    // non-code-signing cert (very common in internal PKIs that issue mTLS +
    // S/MIME from one root) becomes a signing authority too. Fixed in plugin
    // governance hardening round 1 (sec-LOW-2 / UP-8); preserved in the lift.
    if (X509_STORE_set_purpose(store.get(), X509_PURPOSE_CODE_SIGN) != 1) {
        spdlog::error("Failed to set X509 purpose to codeSigning: {}", drain_openssl_errors().text);
        return nullptr;
    }
    return store;
}

/// The whole verification, parameterised only by how the CONTENT is presented.
/// Both public entry points funnel through here so the CMS policy exists once.
std::optional<CmsVerifyError> verify_with_content_bio(BIO* content_bio,
                                                      std::string_view signature_pem,
                                                      const std::filesystem::path& trust_bundle_path) {
    // Clear on ENTRY as well as on success. The queue is thread-local and shared
    // with every other OpenSSL user in this process, so an error left behind by
    // an earlier caller (a TLS handshake on this worker, say) would be drained by
    // OUR drain_openssl_errors() and could set `chain_failure` — reporting an
    // invalid-signature refusal as reason="untrusted" in both the log and the
    // counter, and sending the operator to debug a certificate chain that is
    // fine. It cannot cause a false PASS: the verdict comes from CMS_verify's
    // return value, never from the queue. This only keeps the REASON honest.
    ERR_clear_error();

    auto store = load_trust_store(trust_bundle_path);
    if (!store) {
        // Bundle unreadable → we cannot prove anything, so refuse to trust.
        // Operator misconfiguration must surface, not silently pass artifacts
        // through.
        return CmsVerifyError{CmsFailure::kUntrusted, "trust bundle unreadable"};
    }

    if (signature_pem.empty())
        return CmsVerifyError{CmsFailure::kInvalid, "empty signature"};

    // BIO_new_mem_buf takes an int length; a signature larger than INT_MAX is
    // not a signature, and letting it wrap would hand OpenSSL a negative length.
    if (signature_pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return CmsVerifyError{CmsFailure::kInvalid, "signature implausibly large"};

    openssl_ptr<BIO> sig_bio{
        BIO_new_mem_buf(signature_pem.data(), static_cast<int>(signature_pem.size()))};
    if (!sig_bio) {
        const auto err = drain_openssl_errors();
        return CmsVerifyError{CmsFailure::kInvalid, "cannot read signature: " + err.text};
    }

    openssl_ptr<CMS_ContentInfo> cms{PEM_read_bio_CMS(sig_bio.get(), nullptr, nullptr, nullptr)};
    if (!cms) {
        const auto err = drain_openssl_errors();
        return CmsVerifyError{CmsFailure::kInvalid, "malformed PEM CMS: " + err.text};
    }

    // A single CMS_verify does both checks atomically:
    //   * chain-validates each signer cert against the trust store (purpose was
    //     set to CODE_SIGN in load_trust_store so any leaf without
    //     EKU=codeSigning is rejected — even if the leaf chains to a CA the
    //     operator trusts).
    //   * verifies the signature digest over the detached payload.
    //   * CMS_BINARY suppresses CRLF canonicalisation we do not want on a
    //     binary payload.
    //   * MUST NOT pass CMS_NO_SIGNER_CERT_VERIFY or CMS_NO_CONTENT_VERIFY —
    //     those flags individually disable the chain check or the digest check
    //     and would silently weaken the verifier. Pinning the policy here as a
    //     load-bearing invariant for future edits (plugin governance hardening
    //     round 1, sec-INFO-8; preserved in the lift).
    if (CMS_verify(cms.get(), nullptr, store.get(), content_bio, nullptr,
                   CMS_BINARY | CMS_DETACHED) != 1) {
        const auto err = drain_openssl_errors();
        return CmsVerifyError{err.chain_failure ? CmsFailure::kUntrusted : CmsFailure::kInvalid,
                              err.text};
    }

    // Drain any benign residual error-queue entries from the success path so a
    // worker thread that handles a TLS call after this one does not see stale
    // OpenSSL errors. PEM_read_bio_X509 + friends push end-of-stream sentinels
    // onto the thread-local queue even on success (cpp-S5 / sec-LOW-6).
    ERR_clear_error();
    return std::nullopt; // verified
}

} // namespace

std::optional<CmsVerifyError> verify_detached_cms(const std::filesystem::path& artifact_path,
                                                  std::string_view signature_pem,
                                                  const std::filesystem::path& trust_bundle_path) {
    openssl_ptr<BIO> content_bio{BIO_new_file(artifact_path.string().c_str(), "rb")};
    if (!content_bio) {
        const auto err = drain_openssl_errors();
        return CmsVerifyError{CmsFailure::kInvalid, "cannot open artifact: " + err.text};
    }
    return verify_with_content_bio(content_bio.get(), signature_pem, trust_bundle_path);
}

std::optional<CmsVerifyError> verify_detached_cms_fd(int artifact_fd,
                                                     std::string_view signature_pem,
                                                     const std::filesystem::path& trust_bundle_path) {
    if (artifact_fd < 0)
        return CmsVerifyError{CmsFailure::kInvalid, "invalid artifact descriptor"};

    // Save and restore the offset. The caller has already read this descriptor
    // to the end to hash it, and may rely on its position afterwards; a verifier
    // that silently rewinds someone else's descriptor is a trap for the next
    // reader.
    const std::int64_t saved = seek_fd(artifact_fd, 0, SEEK_CUR);
    if (saved < 0)
        return CmsVerifyError{CmsFailure::kInvalid, "artifact descriptor is not seekable"};
    if (seek_fd(artifact_fd, 0, SEEK_SET) < 0)
        return CmsVerifyError{CmsFailure::kInvalid, "cannot rewind artifact descriptor"};

    // RAII rather than a trailing call: verify_with_content_bio allocates, so an
    // exception would otherwise leave the caller's descriptor silently rewound —
    // the exact trap this restore exists to prevent, reintroduced on the failure
    // path.
    struct OffsetRestore {
        int fd;
        std::int64_t offset;
        ~OffsetRestore() { seek_fd(fd, offset, SEEK_SET); }
    } restore{artifact_fd, saved};

    // BIO_NOCLOSE: the descriptor belongs to the caller, and closing it here
    // would close the staged file out from under the apply step.
    openssl_ptr<BIO> content_bio{BIO_new_fd(artifact_fd, BIO_NOCLOSE)};
    if (!content_bio) {
        const auto err = drain_openssl_errors();
        return CmsVerifyError{CmsFailure::kInvalid, "cannot wrap artifact descriptor: " + err.text};
    }

    return verify_with_content_bio(content_bio.get(), signature_pem, trust_bundle_path);
}

} // namespace yuzu::agent
