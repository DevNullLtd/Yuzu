#include <yuzu/agent/detached_signature.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio> // SEEK_SET / SEEK_CUR
#include <format>
#include <limits>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

#ifdef _WIN32
// Lean, and BEFORE the OpenSSL headers: the full <windows.h> pulls in
// <wincrypt.h>, whose X509_NAME / PKCS7_SIGNER_INFO macros collide with
// OpenSSL's own type names.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h> // _lseeki64

#include "guard_win_handle.hpp" // ScopedWinHandle: RAII CloseHandle for the bundle read
#else
#include <fcntl.h>    // open, O_NONBLOCK
#include <sys/stat.h> // fstat, S_ISREG
#include <unistd.h>   // lseek, read

#include <yuzu/agent/scoped_fd.hpp> // RAII close for the bundle read
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
    void operator()(STACK_OF(X509_INFO) * p) const noexcept {
        sk_X509_INFO_pop_free(p, X509_INFO_free);
    }
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

/// Why load_trust_store() returned no store.
struct TrustStoreError {
    /// True when the BUNDLE FILE is the problem (missing, unreadable, not a
    /// regular file, over `kMaxTrustBundleBytes`, not valid PEM, or holding no
    /// PEM certificate or CRL) — reported as CmsFailure::kBundleUnreadable
    /// (#5249). False for an internal OpenSSL failure unrelated to the file
    /// (allocation, adding a parsed entry, setting the purpose), which stays
    /// CmsFailure::kUntrusted.
    bool bundle_fault{false};
    std::string detail;
};

/// A one-line, operator-facing reason the bundle FILE failed to load.
///
/// The wording comes from the site that observed the failure (the open, the
/// held-handle type/size check, the read, the PEM parse) — never from a second,
/// path-based probe of the file after the fact.
std::string describe_bundle_fault(const std::filesystem::path& bundle_path, std::string_view what,
                                  std::string_view openssl_text = {}) {
    std::string out = "trust bundle '" + bundle_path.string() + "' ";
    out += what;
    if (!openssl_text.empty()) {
        out += " (";
        out += openssl_text;
        out += ")";
    }
    return out;
}

/// Read the whole bundle file into memory, BOUNDED (#5249 Gate 7).
///
/// The bundle used to be handed to `X509_STORE_load_locations`, which opens the
/// path with a plain blocking `fopen`: a FIFO with no writer blocks that open
/// forever, a character device such as `/dev/zero` is read without end, and a
/// multi-gigabyte file is read in full. Here the open cannot block on a FIFO
/// (`O_NONBLOCK`; on Windows `CreateFileW` returns rather than waits), only a
/// REGULAR file is accepted — checked on the HELD descriptor/handle, never by a
/// second path lookup — and at most `kMaxTrustBundleBytes + 1` bytes are ever
/// read, so a file that lies about its size or grows under the read is still
/// refused rather than truncated. Every failure here is a bundle fault.
///
/// Residual, accepted: a bundle on an unreachable network share (UNC / NFS
/// hard mount) can still stall the open itself; no portable non-blocking open
/// exists for that.
#ifndef _WIN32
std::optional<std::string> read_bundle_bytes(const std::filesystem::path& path,
                                             TrustStoreError& err) {
    const auto fault = [&](std::string_view what) -> std::optional<std::string> {
        err = {true, describe_bundle_fault(path, what)};
        return std::nullopt;
    };
    const auto errno_text = [](int e) {
        return std::generic_category().message(e);
    };
    const std::string over_cap = std::format("exceeds {} bytes", kMaxTrustBundleBytes);

    const int raw = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    const int open_errno = errno;
    const ScopedFd fd{raw};
    if (!fd) {
        if (open_errno == ENOENT || open_errno == ENOTDIR)
            return fault("not found");
        if (open_errno == EACCES || open_errno == EPERM)
            return fault("not readable (permission denied)");
        return fault("cannot open: " + errno_text(open_errno));
    }

    struct stat st{};
    if (::fstat(fd.get(), &st) != 0)
        return fault("cannot stat: " + errno_text(errno));
    if (!S_ISREG(st.st_mode))
        return fault("not a regular file");
    if (st.st_size < 0 || static_cast<std::uintmax_t>(st.st_size) > kMaxTrustBundleBytes)
        return fault(over_cap);

    std::string bytes;
    bytes.reserve(static_cast<std::size_t>(st.st_size));
    char buf[16 * 1024];
    // Bound the bytes ACTUALLY read, not the size fstat reported: read at most
    // one byte past the cap, so "grew past the cap" is observable and refused.
    while (bytes.size() <= kMaxTrustBundleBytes) {
        const std::size_t want = std::min(sizeof(buf), kMaxTrustBundleBytes + 1 - bytes.size());
        const ssize_t n = ::read(fd.get(), buf, want);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return fault("read failed: " + errno_text(errno));
        }
        if (n == 0)
            break;
        bytes.append(buf, static_cast<std::size_t>(n));
    }
    if (bytes.size() > kMaxTrustBundleBytes)
        return fault(over_cap);
    return bytes;
}
#else
std::optional<std::string> read_bundle_bytes(const std::filesystem::path& path,
                                             TrustStoreError& err) {
    const auto fault = [&](std::string_view what) -> std::optional<std::string> {
        err = {true, describe_bundle_fault(path, what)};
        return std::nullopt;
    };
    const std::string over_cap = std::format("exceeds {} bytes", kMaxTrustBundleBytes);

    // The WIDE path, never path.string(): that conversion throws on MSVC for a
    // path outside the active code page. BACKUP_SEMANTICS lets a directory open
    // so it is reported as "not a regular file" rather than as a generic error.
    const HANDLE raw =
        ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const DWORD open_error = ::GetLastError();
    const detail::ScopedWinHandle<&detail::close_handle_> h{raw};
    if (!h) {
        if (open_error == ERROR_FILE_NOT_FOUND || open_error == ERROR_PATH_NOT_FOUND)
            return fault("not found");
        if (open_error == ERROR_ACCESS_DENIED)
            return fault("not readable (access denied)");
        if (open_error == ERROR_SHARING_VIOLATION)
            return fault("not readable (locked by another process)");
        return fault(std::format("CreateFileW error {}", open_error));
    }

    if (::GetFileType(h.get()) != FILE_TYPE_DISK)
        return fault("not a regular file");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!::GetFileInformationByHandle(h.get(), &info))
        return fault(std::format("GetFileInformationByHandle error {}", ::GetLastError()));
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return fault("not a regular file");
    const std::uint64_t size =
        (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (size > kMaxTrustBundleBytes)
        return fault(over_cap);

    std::string bytes;
    bytes.reserve(static_cast<std::size_t>(size));
    char buf[16 * 1024];
    while (bytes.size() <= kMaxTrustBundleBytes) {
        const auto want =
            static_cast<DWORD>(std::min(sizeof(buf), kMaxTrustBundleBytes + 1 - bytes.size()));
        DWORD got = 0;
        if (!::ReadFile(h.get(), buf, want, &got, nullptr))
            return fault(std::format("read failed: ReadFile error {}", ::GetLastError()));
        if (got == 0)
            break;
        bytes.append(buf, got);
    }
    if (bytes.size() > kMaxTrustBundleBytes)
        return fault(over_cap);
    return bytes;
}
#endif

openssl_ptr<X509_STORE> load_trust_store(const std::filesystem::path& bundle_path,
                                         TrustStoreError& err) {
    openssl_ptr<X509_STORE> store{X509_STORE_new()};
    if (!store) {
        err = {false, "cannot allocate X509 store: " + drain_openssl_errors().text};
        return nullptr;
    }

    // Read the file ourselves, bounded, then parse from memory (#5249 Gate 7);
    // see read_bundle_bytes for why not X509_STORE_load_locations.
    const auto bytes = read_bundle_bytes(bundle_path, err);
    if (!bytes)
        return nullptr;

    // kMaxTrustBundleBytes is far below INT_MAX, so the int length cannot wrap.
    static_assert(kMaxTrustBundleBytes <=
                  static_cast<std::size_t>(std::numeric_limits<int>::max()));
    openssl_ptr<BIO> bio{BIO_new_mem_buf(bytes->data(), static_cast<int>(bytes->size()))};
    if (!bio) {
        err = {false, "cannot allocate trust bundle BIO: " + drain_openssl_errors().text};
        return nullptr;
    }

    // One or more concatenated PEM certificates (and optionally CRLs) — exactly
    // the format we promise the operator, and the same parser
    // X509_STORE_load_locations' file lookup used (X509_load_cert_crl_file):
    // text outside PEM blocks is skipped, every certificate and CRL is added.
    openssl_ptr<STACK_OF(X509_INFO)> infos{
        PEM_X509_INFO_read_bio(bio.get(), nullptr, nullptr, nullptr)};
    if (!infos) {
        err = {true, describe_bundle_fault(bundle_path, "not a valid PEM bundle",
                                           drain_openssl_errors().text)};
        return nullptr;
    }
    int count = 0;
    for (int i = 0; i < sk_X509_INFO_num(infos.get()); ++i) {
        X509_INFO* info = sk_X509_INFO_value(infos.get(), i);
        if (info->x509) {
            if (X509_STORE_add_cert(store.get(), info->x509) != 1) {
                err = {false, "cannot add trust bundle certificate to X509 store: " +
                                  drain_openssl_errors().text};
                return nullptr;
            }
            ++count;
        }
        if (info->crl) {
            if (X509_STORE_add_crl(store.get(), info->crl) != 1) {
                err = {false,
                       "cannot add trust bundle CRL to X509 store: " + drain_openssl_errors().text};
                return nullptr;
            }
            ++count;
        }
    }
    if (count == 0) {
        err = {true, describe_bundle_fault(bundle_path, "holds no PEM certificate or CRL")};
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
    // It stays the LAST step of the load.
    if (X509_STORE_set_purpose(store.get(), X509_PURPOSE_CODE_SIGN) != 1) {
        err = {false, "cannot set X509 purpose to codeSigning: " + drain_openssl_errors().text};
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

    TrustStoreError store_err;
    auto store = load_trust_store(trust_bundle_path, store_err);
    if (!store) {
        // Bundle unreadable → we cannot prove anything, so refuse to trust.
        // Operator misconfiguration must surface, not silently pass artifacts
        // through. FAIL CLOSED is the invariant; the kind only says WHERE to look
        // (#5249): the bundle file itself (kBundleUnreadable), or an internal
        // OpenSSL failure unrelated to it (kUntrusted, as before). Both refuse.
        spdlog::error("Failed to load signature trust bundle: {}", store_err.detail);
        return CmsVerifyError{store_err.bundle_fault ? CmsFailure::kBundleUnreadable
                                                     : CmsFailure::kUntrusted,
                              store_err.detail};
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

std::optional<CmsVerifyError> probe_trust_bundle(const std::filesystem::path& trust_bundle_path) {
    // Same queue discipline as the verifier: clear on entry so a stale entry
    // from another OpenSSL user cannot leak into this detail, and on exit so we
    // leave nothing behind for the next one.
    ERR_clear_error();
    TrustStoreError err;
    auto store = load_trust_store(trust_bundle_path, err);
    ERR_clear_error();
    if (store)
        return std::nullopt;
    // The same kind the verifier reports for this load (verify_with_content_bio).
    return CmsVerifyError{err.bundle_fault ? CmsFailure::kBundleUnreadable : CmsFailure::kUntrusted,
                          std::move(err.detail)};
}

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
