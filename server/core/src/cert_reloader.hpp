#pragma once

// Belt-and-suspenders for whichever TU includes this file: see the identical
// comment and #4722 rationale in grpc_tls_credentials.hpp -- a header can only
// guard its own includes, not an unguarded windows.h some earlier header in the
// same TU already pulled in. Idempotent no-op when the includer already guarded.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace httplib {
class Server;
} // namespace httplib

// Opaque forward declaration so this header stays OpenSSL-include-free;
// only cert_reloader.cpp (and any TU that also includes <openssl/ssl.h>,
// such as test_cert_reloader.cpp) needs the full SSL_CTX definition to use
// SslCtxPtr's pointee.
struct ssl_ctx_st;

namespace yuzu::server {

class AuditStore;

/// Polls HTTPS cert/key PEM files for changes and hot-reloads the SSL context
/// without requiring a server restart. Uses std::filesystem::last_write_time for
/// cross-platform file change detection.
///
/// Thread safety: the reload path builds a complete new SSL_CTX, validates it,
/// then atomically swaps it into the httplib SSLServer. Counters are atomic.
class CertReloader {
public:
    static constexpr size_t kMaxPemFileSize = 1024 * 1024; // 1 MB sanity cap

    struct Params {
        std::filesystem::path cert_path;
        std::filesystem::path key_path;
        std::chrono::seconds interval{60};
        httplib::Server* web_server{nullptr}; // must be SSLServer at runtime
        AuditStore* audit_store{nullptr};
    };

    /// Owning pointer to an SSL_CTX built purely for validation (never
    /// installed as a live listener context). The deleter is SSL_CTX_free,
    /// bound in cert_reloader.cpp where the real type is visible.
    using SslCtxPtr = std::unique_ptr<ssl_ctx_st, void (*)(ssl_ctx_st*)>;

    explicit CertReloader(Params params);
    ~CertReloader();

    CertReloader(const CertReloader&) = delete;
    CertReloader& operator=(const CertReloader&) = delete;

    void start();
    void stop();

    /// Attempt a reload now. Returns true if certs were successfully refreshed.
    /// Exposed for testing.
    [[nodiscard]] bool try_reload();

    /// Validate that a PEM cert+key pair is parseable and the key matches the cert.
    /// Exposed for testing.
    [[nodiscard]] static bool validate_pem_pair(const std::string& cert_pem,
                                                 const std::string& key_pem);

    /// Build a throwaway SSL_CTX from `cert_pem`/`key_pem`, apply the #4722
    /// TLS 1.2 cipher pin to it, and verify the cert+chain+key load and the
    /// key matches the cert -- the same validation try_reload() runs before
    /// ever touching the live listener context. Returns the built context on
    /// success (the caller may discard it -- validation is the point, not
    /// reuse) or one of the fixed error strings ("SSL_CTX_new failed",
    /// "cipher policy could not be applied", "SSL context test validation
    /// rejected") on failure -- these are the exact `log_audit` detail
    /// strings try_reload() has always used, now produced in one place.
    /// Exposed for testing: this is the only way a test can observe that the
    /// #4722 cipher pin is actually applied to the *validation* context,
    /// since the pin has no effect on try_reload()'s pass/fail outcome.
    [[nodiscard]] static std::expected<SslCtxPtr, std::string>
    build_validation_context(const std::string& cert_pem, const std::string& key_pem);

    uint64_t reload_count() const { return reload_count_.load(std::memory_order_relaxed); }
    uint64_t failure_count() const { return failure_count_.load(std::memory_order_relaxed); }

private:
    void run_loop();
    [[nodiscard]] bool files_changed();
    void log_audit(const std::string& detail, const std::string& result);

    Params params_;
    std::filesystem::file_time_type last_cert_mtime_{};
    std::filesystem::file_time_type last_key_mtime_{};
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    // stop_cv_ + stop_mu_ make stop() wake the worker immediately rather than
    // forcing it to wait out a 5-second sleep increment. The 5-second poll
    // version pushed the server-tests suite over its 120s budget on contended
    // runners (#flake from PR 734); CV-based wait keeps shutdown < 1ms.
    std::mutex stop_mu_;
    std::condition_variable stop_cv_;
    std::atomic<uint64_t> reload_count_{0};
    std::atomic<uint64_t> failure_count_{0};
};

} // namespace yuzu::server
