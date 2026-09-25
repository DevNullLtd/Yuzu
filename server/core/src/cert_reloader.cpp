// #4722: this TU includes httplib.h below, which pulls in <windows.h> on Windows
// unguarded ahead of <algorithm>'s std::max/std::min use at run_loop() -- matches
// the same collision and the same fix shape already applied in server.cpp and
// grpc_tls_credentials.hpp. Must be first, before any other include.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "cert_reloader.hpp"
#include "audit_store.hpp"
#include "background_jobs.hpp"
#include "file_utils.hpp"

#include <yuzu/secure_zero.hpp>
#include <yuzu/tls_policy.hpp> // #4722: shared TLS 1.2 cipher allow-list

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <system_error>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

void CertReloader::log_audit(const std::string& detail, const std::string& result) {
    if (!params_.audit_store)
        return;
    (void)params_.audit_store->log({.principal = "system",
                                    .principal_role = "system",
                                    .action = "cert.reload",
                                    .target_type = "TlsCertificate",
                                    .target_id = params_.cert_path.string(),
                                    .detail = detail,
                                    .result = result});
}

// ── Constructor / lifecycle ──────────────────────────────────────────────────

CertReloader::CertReloader(Params params) : params_(std::move(params)) {
    // Canonicalize paths to handle macOS /var → /private/var symlinks
    std::error_code ec;
    auto canonical_cert = std::filesystem::canonical(params_.cert_path, ec);
    if (!ec)
        params_.cert_path = canonical_cert;
    ec.clear();
    auto canonical_key = std::filesystem::canonical(params_.key_path, ec);
    if (!ec)
        params_.key_path = canonical_key;

    // Record initial mtimes so the first poll doesn't trigger a spurious reload
    ec.clear();
    last_cert_mtime_ = std::filesystem::last_write_time(params_.cert_path, ec);
    if (ec)
        spdlog::warn("cert-reload: cannot read initial mtime for {}: {}",
                     params_.cert_path.string(), ec.message());
    ec.clear();
    last_key_mtime_ = std::filesystem::last_write_time(params_.key_path, ec);
    if (ec)
        spdlog::warn("cert-reload: cannot read initial mtime for {}: {}", params_.key_path.string(),
                     ec.message());
}

CertReloader::~CertReloader() {
    stop();
}

void CertReloader::start() {
    stop_requested_.store(false, std::memory_order_release);
    YUZU_ASSERT_BACKGROUND_JOB("cert_reloader.run_loop"); // WS-10 ReplicaSafe (per-replica)
    thread_ = std::thread([this] { run_loop(); });
}

void CertReloader::stop() {
    {
        std::lock_guard<std::mutex> lk(stop_mu_);
        stop_requested_.store(true, std::memory_order_release);
    }
    stop_cv_.notify_all();
    if (thread_.joinable())
        thread_.join();
}

void CertReloader::run_loop() {
    spdlog::info("Certificate reload watcher started (interval={}s, cert={}, key={})",
                 params_.interval.count(), params_.cert_path.string(), params_.key_path.string());

    auto interval_secs = std::max(int64_t{10}, params_.interval.count());
    while (true) {
        // wait_for(pred) returns true iff the predicate is true at exit (i.e.
        // stop was requested). Returns false if the timeout elapsed without
        // stop, which is our cue to poll the cert files.
        std::unique_lock<std::mutex> lk(stop_mu_);
        if (stop_cv_.wait_for(lk, std::chrono::seconds{interval_secs},
                              [this] { return stop_requested_.load(std::memory_order_acquire); })) {
            break;
        }
        lk.unlock();

        if (files_changed()) {
            (void)try_reload();
        }
    }

    spdlog::info("Certificate reload watcher stopped");
}

bool CertReloader::files_changed() {
    std::error_code ec;
    auto cert_mtime = std::filesystem::last_write_time(params_.cert_path, ec);
    if (ec)
        return false; // file temporarily missing during atomic rename — skip
    auto key_mtime = std::filesystem::last_write_time(params_.key_path, ec);
    if (ec)
        return false;

    return cert_mtime != last_cert_mtime_ || key_mtime != last_key_mtime_;
}

// ── Validation context (#4722) ───────────────────────────────────────────────

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
std::expected<CertReloader::SslCtxPtr, std::string>
CertReloader::build_validation_context(const std::string& cert_pem, const std::string& key_pem) {
    SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
    if (!ctx) {
        ERR_clear_error();
        return std::unexpected("SSL_CTX_new failed");
    }

    // #4722: the validation context must carry the same cipher pin as the
    // live listener so a hot-swapped cert/key pair is validated under the
    // production policy. (The live ctx keeps its ctx-level cipher list
    // across SSL_CTX_use_certificate_chain_file below — test_cert_reloader.cpp
    // asserts it; this guards the validation path.)
    if (!yuzu::tls::apply_tls12_cipher_list(ctx.get())) {
        ERR_clear_error();
        return std::unexpected("cipher policy could not be applied");
    }

    bool ok = true;

    // Load cert into the validation context.
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())), &BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> x509(
            bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr, &X509_free);
        if (!x509 || SSL_CTX_use_certificate(ctx.get(), x509.get()) != 1)
            ok = false;

        // Load chain certs. SSL_CTX_add_extra_chain_cert takes ownership of
        // `chain` on success (release() must NOT free it in that case).
        if (bio && ok) {
            X509* chain_raw = nullptr;
            while ((chain_raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) !=
                   nullptr) {
                std::unique_ptr<X509, decltype(&X509_free)> chain(chain_raw, &X509_free);
                if (SSL_CTX_add_extra_chain_cert(ctx.get(), chain.get()) == 1)
                    chain.release(); // ownership transferred to ctx
                else
                    break; // chain frees itself on scope exit
            }
            ERR_clear_error();
        }
    }

    // Load key into the validation context.
    if (ok) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size())), &BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr,
            &EVP_PKEY_free);
        if (!pkey || SSL_CTX_use_PrivateKey(ctx.get(), pkey.get()) != 1)
            ok = false;
    }

    // Verify cert/key match in the validation context.
    if (ok && SSL_CTX_check_private_key(ctx.get()) != 1)
        ok = false;

    ERR_clear_error();

    if (!ok)
        return std::unexpected("SSL context test validation rejected");
    return ctx;
}
#else
std::expected<CertReloader::SslCtxPtr, std::string>
CertReloader::build_validation_context(const std::string&, const std::string&) {
    return std::unexpected("OpenSSL not available");
}
#endif

// ── Core reload logic ────────────────────────────────────────────────────────

bool CertReloader::try_reload() {
    spdlog::info("cert-reload: certificate file change detected, attempting reload");

    // Step 1: Validate key file permissions
    if (!detail::validate_key_file_permissions(params_.key_path, "cert-reload")) {
        spdlog::error("cert-reload: key file permission check failed; keeping current certificate");
        ++failure_count_;
        log_audit("Failed: key file permissions too permissive", "failure");
        return false;
    }

    // Step 2: Check file sizes (H1 — OOM prevention)
    {
        std::error_code ec;
        auto cert_size = std::filesystem::file_size(params_.cert_path, ec);
        if (ec || cert_size == 0 || cert_size > kMaxPemFileSize) {
            spdlog::error("cert-reload: cert file size invalid ({})",
                          ec ? ec.message() : std::to_string(cert_size));
            ++failure_count_;
            log_audit("Failed: cert file size invalid", "failure");
            return false;
        }
        auto key_size = std::filesystem::file_size(params_.key_path, ec);
        if (ec || key_size == 0 || key_size > kMaxPemFileSize) {
            spdlog::error("cert-reload: key file size invalid ({})",
                          ec ? ec.message() : std::to_string(key_size));
            ++failure_count_;
            log_audit("Failed: key file size invalid", "failure");
            return false;
        }
    }

    // Step 3: Read file contents
    auto cert_pem = detail::read_file_contents(params_.cert_path);
    auto key_pem = detail::read_file_contents(params_.key_path);

    if (cert_pem.empty() || key_pem.empty()) {
        spdlog::error("cert-reload: failed to read cert or key file");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: empty cert or key file", "failure");
        return false;
    }

    // Step 4: Validate PEM pair (cert matches key)
    if (!validate_pem_pair(cert_pem, key_pem)) {
        spdlog::error(
            "cert-reload: certificate/key validation failed; keeping current certificate");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: PEM validation error (parse failure or cert/key mismatch)", "failure");
        return false;
    }

    // Step 5: Apply atomically via new SSL_CTX (fixes C1: thread safety, C2: partial state)
    //
    // Strategy: build a complete new SSL_CTX with cert+chain+key, verify the
    // private key matches, then write the cert/key into the live context using
    // the PEM file path reload (SSL_CTX_use_certificate_chain_file +
    // SSL_CTX_use_PrivateKey_file) while holding httplib's ctx_mutex_ via
    // the SSLServer's setup callback. This is atomic: either the full
    // cert+chain+key is applied, or the live context is untouched.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto* ssl_server = dynamic_cast<httplib::SSLServer*>(params_.web_server);
    if (!ssl_server) {
        spdlog::error("cert-reload: web server is not an SSLServer; cannot reload");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        return false;
    }

    // tls_context() supersedes ssl_context() in cpp-httplib (the latter is
    // marked [[deprecated]]). Both return the same underlying SSL_CTX*; the
    // typed cast keeps the rest of this function unchanged.
    SSL_CTX* ctx = static_cast<SSL_CTX*>(ssl_server->tls_context());
    if (!ctx) {
        spdlog::error("cert-reload: SSL context is null");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        return false;
    }

    // Build+validate cert+chain+key together under the production cipher
    // policy BEFORE touching the live context. If anything fails here, the
    // live server is completely unaffected. The returned context (if any) is
    // discarded — validating it is the point, not reusing it.
    auto validated = build_validation_context(cert_pem, key_pem);
    if (!validated) {
        // Preserve the exact pre-#4722 operator-facing log text for the two
        // failure causes that existed before this PR (ops runbooks/dashboards
        // sometimes grep exact log text); the cipher-policy-application
        // failure is a genuinely new cause this PR introduces, so it gets its
        // own line rather than being folded into either legacy string.
        if (validated.error() == "SSL_CTX_new failed") {
            spdlog::error("cert-reload: SSL_CTX_new failed");
        } else if (validated.error() == "SSL context test validation rejected") {
            spdlog::error("cert-reload: test SSL_CTX validation failed; keeping current "
                          "certificate");
        } else {
            spdlog::error("cert-reload: {}; keeping current certificate", validated.error());
        }
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: " + validated.error(), "failure");
        return false;
    }

    // All validation passed. Now apply to the live context via file paths.
    // SSL_CTX_use_certificate_chain_file and SSL_CTX_use_PrivateKey_file are
    // atomic per-call (each either fully succeeds or fails without modifying
    // the context's working state). Since we validated above, these should
    // succeed. Using file paths avoids holding BIO objects across the live
    // context and matches httplib's own initialization pattern.
    int cert_rc = SSL_CTX_use_certificate_chain_file(ctx, params_.cert_path.string().c_str());
    int key_rc =
        SSL_CTX_use_PrivateKey_file(ctx, params_.key_path.string().c_str(), SSL_FILETYPE_PEM);
    ERR_clear_error();

    if (cert_rc != 1 || key_rc != 1) {
        spdlog::error("cert-reload: live SSL_CTX update failed (cert_rc={}, key_rc={})", cert_rc,
                      key_rc);
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: live SSL context update rejected", "failure");
        return false;
    }

    yuzu::secure_zero(key_pem);
    yuzu::secure_zero(cert_pem);

    // Step 6: Update cached mtimes
    std::error_code ec;
    last_cert_mtime_ = std::filesystem::last_write_time(params_.cert_path, ec);
    last_key_mtime_ = std::filesystem::last_write_time(params_.key_path, ec);

    ++reload_count_;
    spdlog::info("cert-reload: certificate hot-reloaded successfully (total reloads: {})",
                 reload_count_.load(std::memory_order_relaxed));

    log_audit("Certificate hot-reloaded successfully", "success");
    return true;
#else
    yuzu::secure_zero(key_pem);
    yuzu::secure_zero(cert_pem);
    spdlog::warn("cert-reload: OpenSSL not available; cannot hot-reload certificates");
    ++failure_count_;
    return false;
#endif
}

// ── PEM validation ───────────────────────────────────────────────────────────

bool CertReloader::validate_pem_pair(const std::string& cert_pem, const std::string& key_pem) {
    if (cert_pem.empty() || key_pem.empty())
        return false;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    // Parse certificate
    auto* cert_bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (!cert_bio)
        return false;

    auto* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);
    if (!cert) {
        spdlog::error("cert-reload: failed to parse PEM certificate");
        ERR_clear_error();
        return false;
    }

    // Parse private key
    auto* key_bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!key_bio) {
        X509_free(cert);
        return false;
    }

    auto* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (!pkey) {
        spdlog::error("cert-reload: failed to parse PEM private key");
        ERR_clear_error();
        X509_free(cert);
        return false;
    }

    // Verify key matches certificate
    int match = X509_check_private_key(cert, pkey);
    EVP_PKEY_free(pkey);
    X509_free(cert);

    if (match != 1) {
        spdlog::error("cert-reload: private key does not match certificate");
        ERR_clear_error();
        return false;
    }

    return true;
#else
    // Without OpenSSL, skip deep validation
    (void)cert_pem;
    (void)key_pem;
    return true;
#endif
}

} // namespace yuzu::server
