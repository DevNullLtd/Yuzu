#pragma once

/**
 * tls_probe.hpp -- shared raw-OpenSSL TLS test probes (#4722).
 *
 * There is no raw-OpenSSL client/server precedent under tests/ before this
 * file (grep for SSL_connect/BIO_new_ssl_connect/SSL_accept/BIO_new_accept
 * across tests/ returns nothing) — the real-handshake suites for #4722 are
 * the first to need one, and Part B (agents/core) reuses this file
 * unchanged.
 *
 * WHY EVERY SYSCALL IS SOCKET-DEADLINED, NOT FUTURE-BOUNDED: a
 * std::future's destructor blocks on whatever the async task is doing, so a
 * probe stalled inside a BIO call would hang the whole test binary rather
 * than fail a single case. Every blocking call here is bounded at the
 * SOCKET (SO_RCVTIMEO/SO_SNDTIMEO — the idiom in test_mcp_body_cap.cpp:
 * 277-284; Windows wants a DWORD of MILLISECONDS there, not a `timeval`)
 * plus a steady_clock deadline around every BIO_should_retry loop, so a
 * silent peer yields `timed_out = true` rather than a hang. No std::async,
 * no detached threads for client probes.
 *
 * WHAT `alert_received` MEANS: the TLS alert DESCRIPTION the PEER sent,
 * captured via SSL_set_info_callback on SSL_CB_ALERT|SSL_CB_READ. A genuine
 * peer refusal is either a received alert OR the peer closing the TCP
 * connection outright after our ClientHello/Certificate was already on the
 * wire (SSL_R_UNEXPECTED_EOF_WHILE_READING — gRPC's TLS stack does not
 * always emit an alert record before closing on a certificate-verification
 * failure or an incompatible legacy protocol version); test callers combine
 * both (see `refused_by_peer` in test_grpc_tls_policy.cpp). A purely local
 * failure (e.g. this probe's own ctx never even offered a compatible
 * protocol) would satisfy "handshake_ok == false" too, but proves nothing
 * about server behaviour, so callers guard against it first: on the
 * inbound (client-probes-server) direction that guard is `connect_ok`,
 * which rules out "the probe never reached the peer at all"; on the
 * outbound (RawTlsServer observes a gRPC client) direction `connect_ok` is
 * never set, and the equivalent guard is `wait_for_transient_failure`
 * actually reaching TRANSIENT_FAILURE before `refused_by_peer` is read.
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::test::tls {

#ifdef _WIN32
/// Mirrors httplib.h's own WSAStartup guard: one process-wide init, ref-counted
/// via a function-local static so every probe/server can rely on Winsock being
/// up without each one managing WSAStartup/WSACleanup itself.
struct WinsockGuard {
    WinsockGuard() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    }
    ~WinsockGuard() { WSACleanup(); }
};
inline void ensure_winsock() {
    static WinsockGuard guard;
    (void)guard;
}
#else
inline void ensure_winsock() {}
#endif

/// Bound every blocking socket op on `fd` at `seconds`. Returns false (and
/// callers REQUIRE it) on setsockopt failure.
[[nodiscard]] inline bool set_socket_deadline(int fd, int seconds) {
    ensure_winsock();
#ifdef _WIN32
    DWORD timeout_ms = static_cast<DWORD>(seconds) * 1000; // Windows wants milliseconds, not timeval.
    bool ok = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                           sizeof(timeout_ms)) == 0;
    ok = ok && ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                            sizeof(timeout_ms)) == 0;
    return ok;
#else
    timeval tv{};
    tv.tv_sec = seconds;
    bool ok = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
    ok = ok && ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
    return ok;
#endif
}

namespace detail {

/// Retry a blocking BIO operation until it succeeds, fails for a reason other
/// than "retry", or `deadline` passes. Sets `timed_out` on deadline expiry.
template <typename Fn>
int bounded_bio_retry(BIO* bio, Fn&& op, std::chrono::steady_clock::time_point deadline,
                      bool& timed_out) {
    int r = 0;
    do {
        r = op();
        if (r > 0)
            return r;
        if (!BIO_should_retry(bio))
            return r;
    } while (std::chrono::steady_clock::now() < deadline);
    if (std::chrono::steady_clock::now() >= deadline)
        timed_out = true;
    return r;
}

/// SSL_set_info_callback target: records the alert DESCRIPTION byte the peer
/// sent (an inbound read of an alert record), never an alert we generated.
inline void record_peer_alert(const SSL* ssl, int where, int ret) {
    (void)ssl;
    if ((where & SSL_CB_ALERT) && (where & SSL_CB_READ)) {
        int* slot = static_cast<int*>(SSL_get_app_data(ssl));
        if (slot)
            *slot = ret & 0xff;
    }
}

} // namespace detail

// ── TLS client probe ─────────────────────────────────────────────────────────

struct ProbeOptions {
    int min_version = TLS1_2_VERSION;
    int max_version = TLS1_3_VERSION;
    std::string cipher_list; ///< empty = library default
    int security_level = -1; ///< -1 = don't touch
    std::string client_cert_pem, client_key_pem;
    std::string alpn = "h2";
    std::chrono::seconds deadline{5};
};

struct ProbeResult {
    bool ctx_setup_ok = false;
    bool connect_ok = false;
    bool handshake_ok = false;
    bool timed_out = false;
    std::string version, cipher;
    int err_reason = 0;
    std::string err_text;
    int alert_received = -1; ///< TLS alert description the PEER sent, or -1
};

[[nodiscard]] inline ProbeResult raw_tls_probe(int port, const ProbeOptions& opt) {
    ensure_winsock();
    ProbeResult result;

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()),
                                                           &SSL_CTX_free);
    if (!ctx) {
        ERR_clear_error();
        return result;
    }

    // This probe tests the SERVER's acceptance behaviour, not chain trust.
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(ctx.get(), opt.min_version);
    SSL_CTX_set_max_proto_version(ctx.get(), opt.max_version);
    if (opt.security_level >= 0)
        SSL_CTX_set_security_level(ctx.get(), opt.security_level);

    if (!opt.cipher_list.empty()) {
        if (SSL_CTX_set_cipher_list(ctx.get(), opt.cipher_list.c_str()) != 1) {
            ERR_clear_error();
            return result;
        }
    }

    if (!opt.client_cert_pem.empty() && !opt.client_key_pem.empty()) {
        std::unique_ptr<BIO, decltype(&BIO_free)> cbio(
            BIO_new_mem_buf(opt.client_cert_pem.data(),
                            static_cast<int>(opt.client_cert_pem.size())),
            &BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(
            cbio ? PEM_read_bio_X509(cbio.get(), nullptr, nullptr, nullptr) : nullptr, &X509_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> kbio(
            BIO_new_mem_buf(opt.client_key_pem.data(),
                            static_cast<int>(opt.client_key_pem.size())),
            &BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            kbio ? PEM_read_bio_PrivateKey(kbio.get(), nullptr, nullptr, nullptr) : nullptr,
            &EVP_PKEY_free);
        bool ok = cert && pkey && SSL_CTX_use_certificate(ctx.get(), cert.get()) == 1 &&
                 SSL_CTX_use_PrivateKey(ctx.get(), pkey.get()) == 1;
        if (!ok) {
            ERR_clear_error();
            return result;
        }
    }

    if (!opt.alpn.empty()) {
        std::string wire;
        wire.push_back(static_cast<char>(opt.alpn.size()));
        wire += opt.alpn;
        SSL_CTX_set_alpn_protos(ctx.get(), reinterpret_cast<const unsigned char*>(wire.data()),
                                static_cast<unsigned int>(wire.size()));
    }

    result.ctx_setup_ok = true;

    // Deliberately TWO separate BIOs, not BIO_new_ssl_connect's combined
    // chain: BIO_do_connect on a connect+SSL chain performs the FULL
    // handshake, not just the TCP connect (BIO_do_connect and
    // BIO_do_handshake are the same BIO_C_DO_STATE_MACHINE ctrl call), which
    // would make `connect_ok` collapse into `handshake_ok` and make a
    // negative case's REQUIRE(connect_ok) fail even though the probe
    // genuinely reached the server. TCP connect and TLS handshake are
    // therefore driven as two explicit steps here.
    std::unique_ptr<BIO, decltype(&BIO_free_all)> conn_bio(
        BIO_new(BIO_s_connect()), &BIO_free_all);
    if (!conn_bio) {
        ERR_clear_error();
        return result;
    }
    std::string hostport = "127.0.0.1:" + std::to_string(port);
    BIO_set_conn_hostname(conn_bio.get(), hostport.c_str());

    auto deadline = std::chrono::steady_clock::now() + opt.deadline;
    bool timed_out = false;
    int rc = detail::bounded_bio_retry(
        conn_bio.get(), [&] { return BIO_do_connect(conn_bio.get()); }, deadline, timed_out);
    if (rc <= 0) {
        result.timed_out = timed_out;
        result.err_reason = ERR_GET_REASON(ERR_peek_last_error());
        char buf[256];
        ERR_error_string_n(ERR_peek_last_error(), buf, sizeof(buf));
        result.err_text = buf;
        ERR_clear_error();
        return result;
    }
    result.connect_ok = true;

    int fd = -1;
    BIO_get_fd(conn_bio.get(), &fd);
    if (fd >= 0 && !set_socket_deadline(fd, static_cast<int>(opt.deadline.count()))) {
        return result;
    }

    BIO* ssl_filter = BIO_new(BIO_f_ssl());
    if (!ssl_filter) {
        ERR_clear_error();
        return result;
    }
    SSL* ssl = SSL_new(ctx.get());
    SSL_set_connect_state(ssl);
    int alert_slot = -1;
    SSL_set_app_data(ssl, &alert_slot);
    SSL_set_info_callback(ssl, detail::record_peer_alert);
    BIO_set_ssl(ssl_filter, ssl, BIO_CLOSE);
    BIO_push(ssl_filter, conn_bio.release()); // ssl_filter now owns conn_bio
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(ssl_filter, &BIO_free_all);

    rc = detail::bounded_bio_retry(
        bio.get(), [&] { return BIO_do_handshake(bio.get()); }, deadline, timed_out);
    result.alert_received = alert_slot;
    if (rc <= 0) {
        result.timed_out = timed_out;
        result.err_reason = ERR_GET_REASON(ERR_peek_last_error());
        char buf[256];
        ERR_error_string_n(ERR_peek_last_error(), buf, sizeof(buf));
        result.err_text = buf;
        ERR_clear_error();
        return result;
    }

    result.handshake_ok = true;
    result.version = SSL_get_version(ssl);
    const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
    result.cipher = c ? SSL_CIPHER_get_name(c) : "";
    return result;
}

// ── Plaintext probe (positive/negative control) ─────────────────────────────

struct PlaintextResult {
    bool connect_ok = false;
    bool wrote_all = false;
    bool timed_out = false;
    bool closed = false;
    bool saw_tls_alert = false;
    bool saw_h2_settings = false;
    std::string response;
};

[[nodiscard]] inline PlaintextResult raw_plaintext_probe(int port) {
    ensure_winsock();
    PlaintextResult result;

    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new(BIO_s_connect()), &BIO_free_all);
    if (!bio)
        return result;
    std::string hostport = "127.0.0.1:" + std::to_string(port);
    BIO_set_conn_hostname(bio.get(), hostport.c_str());

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool timed_out = false;
    int rc = detail::bounded_bio_retry(
        bio.get(), [&] { return BIO_do_connect(bio.get()); }, deadline, timed_out);
    if (rc <= 0) {
        result.timed_out = timed_out;
        ERR_clear_error();
        return result;
    }
    result.connect_ok = true;

    int fd = -1;
    BIO_get_fd(bio.get(), &fd);
    if (fd >= 0)
        (void)set_socket_deadline(fd, 5);

    static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static const unsigned char kEmptySettings[9] = {0, 0, 0, 0x04, 0, 0, 0, 0, 0};

    int n1 = BIO_write(bio.get(), kPreface, static_cast<int>(sizeof(kPreface) - 1));
    int n2 = BIO_write(bio.get(), kEmptySettings, static_cast<int>(sizeof(kEmptySettings)));
    result.wrote_all =
        n1 == static_cast<int>(sizeof(kPreface) - 1) && n2 == static_cast<int>(sizeof(kEmptySettings));

    char buf[256];
    while (result.response.size() < sizeof(buf)) {
        int n = BIO_read(bio.get(), buf, static_cast<int>(sizeof(buf)));
        if (n > 0) {
            result.response.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (BIO_should_retry(bio.get()) && std::chrono::steady_clock::now() < deadline)
            continue;
        if (n == 0)
            result.closed = true;
        else if (std::chrono::steady_clock::now() >= deadline)
            result.timed_out = true;
        break;
    }
    ERR_clear_error();

    if (!result.response.empty() && static_cast<unsigned char>(result.response[0]) == 0x15)
        result.saw_tls_alert = true;
    if (result.response.size() >= 4 && static_cast<unsigned char>(result.response[3]) == 0x04)
        result.saw_h2_settings = true;

    return result;
}

// ── One-shot raw TLS accept server ──────────────────────────────────────────

/// Accepts exactly one TLS connection with a caller-chosen cert/cipher/max
/// version, and records what it observed. Used as the outbound-direction
/// twin of raw_tls_probe: it plays the role of a hostile or misconfigured
/// server that the production gRPC CLIENT builder connects out to.
class RawTlsServer {
public:
    RawTlsServer(const std::string& server_cert_pem, const std::string& server_key_pem,
                const std::string& trust_ca_pem = "", bool require_client_cert = false,
                int max_version = TLS1_3_VERSION, const std::string& cipher_list = "")
        : ctx_(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free) {
        ensure_winsock();
        if (!ctx_)
            return;
        SSL_CTX_set_max_proto_version(ctx_.get(), max_version);
        if (!cipher_list.empty()) {
            bool ok = SSL_CTX_set_cipher_list(ctx_.get(), cipher_list.c_str()) == 1;
            (void)ok;
            ctx_cipher_ok_ = ok;
        } else {
            ctx_cipher_ok_ = true;
        }

        {
            std::unique_ptr<BIO, decltype(&BIO_free)> cbio(
                BIO_new_mem_buf(server_cert_pem.data(), static_cast<int>(server_cert_pem.size())),
                &BIO_free);
            std::unique_ptr<X509, decltype(&X509_free)> cert(
                cbio ? PEM_read_bio_X509(cbio.get(), nullptr, nullptr, nullptr) : nullptr,
                &X509_free);
            std::unique_ptr<BIO, decltype(&BIO_free)> kbio(
                BIO_new_mem_buf(server_key_pem.data(), static_cast<int>(server_key_pem.size())),
                &BIO_free);
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
                kbio ? PEM_read_bio_PrivateKey(kbio.get(), nullptr, nullptr, nullptr) : nullptr,
                &EVP_PKEY_free);
            if (cert)
                SSL_CTX_use_certificate(ctx_.get(), cert.get());
            if (pkey)
                SSL_CTX_use_PrivateKey(ctx_.get(), pkey.get());
        }

        if (!trust_ca_pem.empty()) {
            auto* store = SSL_CTX_get_cert_store(ctx_.get());
            std::unique_ptr<BIO, decltype(&BIO_free)> tbio(
                BIO_new_mem_buf(trust_ca_pem.data(), static_cast<int>(trust_ca_pem.size())),
                &BIO_free);
            if (tbio) {
                std::unique_ptr<X509, decltype(&X509_free)> ca(
                    PEM_read_bio_X509(tbio.get(), nullptr, nullptr, nullptr), &X509_free);
                if (ca)
                    X509_STORE_add_cert(store, ca.get());
            }
            SSL_CTX_set_verify(ctx_.get(),
                               require_client_cert
                                   ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                                   : SSL_VERIFY_PEER,
                               nullptr);
        }

        SSL_CTX_set_alpn_select_cb(
            ctx_.get(),
            [](SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
               unsigned int inlen, void*) -> int {
                static const unsigned char kH2[] = "h2";
                if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, kH2, 2, in,
                                          inlen) != OPENSSL_NPN_NEGOTIATED)
                    return SSL_TLSEXT_ERR_NOACK;
                return SSL_TLSEXT_ERR_OK;
            },
            nullptr);

        accept_bio_.reset(BIO_new_accept("127.0.0.1:0"));
        if (accept_bio_) {
            BIO_set_bind_mode(accept_bio_.get(), BIO_BIND_REUSEADDR);
            if (BIO_do_accept(accept_bio_.get()) > 0) {
                int fd = -1;
                BIO_get_fd(accept_bio_.get(), &fd);
                if (fd >= 0) {
                    sockaddr_in addr{};
                    socklen_t len = sizeof(addr);
                    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
                        port_ = ntohs(addr.sin_port);
                }
            }
        }
    }

    ~RawTlsServer() { stop(); }

    RawTlsServer(const RawTlsServer&) = delete;
    RawTlsServer& operator=(const RawTlsServer&) = delete;

    [[nodiscard]] int port() const { return port_; }
    [[nodiscard]] bool cipher_ctx_ok() const { return ctx_cipher_ok_; }

    void start() {
        started_ = true;
        thread_ = std::thread([this] { accept_once(); });
    }

    /// Block until accept_once() has recorded `observed` (or `timeout`
    /// elapses). Event-driven replacement for a fixed sleep before stop():
    /// stop()'s poison-connect races a slow-but-genuine accept, so a fixed
    /// sleep can turn a positive case into a false failure. CHECK this
    /// (never REQUIRE) so stop() still runs and joins the thread either way.
    [[nodiscard]] bool wait_for_handshake(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(done_mu_);
        return done_cv_.wait_for(lk, timeout, [this] { return done_; });
    }

    void stop() {
        if (!started_)
            return;
        started_ = false;
        if (!accepted_.exchange(true)) {
            // Nobody connected yet — poison-connect to unblock BIO_do_accept.
            std::unique_ptr<BIO, decltype(&BIO_free_all)> poison(
                BIO_new_connect(("127.0.0.1:" + std::to_string(port_)).c_str()), &BIO_free_all);
            if (poison)
                BIO_do_connect(poison.get());
        }
        if (thread_.joinable())
            thread_.join();
    }

    ProbeResult observed;

private:
    // Runs accept_once_impl(), then unconditionally marks `done_` on every
    // exit path (including an early return inside the impl) so
    // wait_for_handshake() never blocks past the actual accept finishing.
    void accept_once() {
        accept_once_impl();
        {
            std::lock_guard<std::mutex> lk(done_mu_);
            done_ = true;
        }
        done_cv_.notify_all();
    }

    void accept_once_impl() {
        if (!accept_bio_)
            return;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        bool timed_out = false;
        int rc = detail::bounded_bio_retry(
            accept_bio_.get(), [&] { return BIO_do_accept(accept_bio_.get()); }, deadline,
            timed_out);
        accepted_.store(true);
        if (rc <= 0) {
            observed.timed_out = timed_out;
            ERR_clear_error();
            return;
        }
        std::unique_ptr<BIO, decltype(&BIO_free_all)> client(BIO_pop(accept_bio_.get()),
                                                              &BIO_free_all);
        if (!client)
            return;
        int fd = -1;
        BIO_get_fd(client.get(), &fd);
        if (fd >= 0)
            (void)set_socket_deadline(fd, 5);

        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx_.get()), &SSL_free);
        if (!ssl)
            return;
        SSL_set_bio(ssl.get(), client.get(), client.get());
        client.release(); // the SSL now owns this BIO (freed by SSL_free)
        int alert_slot = -1;
        SSL_set_app_data(ssl.get(), &alert_slot);
        SSL_set_info_callback(ssl.get(), detail::record_peer_alert);

        auto hs_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        int r = 0;
        do {
            r = SSL_accept(ssl.get());
            if (r > 0)
                break;
            int err = SSL_get_error(ssl.get(), r);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                break;
        } while (std::chrono::steady_clock::now() < hs_deadline);

        observed.alert_received = alert_slot;
        if (r > 0) {
            observed.handshake_ok = true;
            observed.version = SSL_get_version(ssl.get());
            const SSL_CIPHER* c = SSL_get_current_cipher(ssl.get());
            observed.cipher = c ? SSL_CIPHER_get_name(c) : "";
        } else {
            observed.err_reason = ERR_GET_REASON(ERR_peek_last_error());
            char buf[256];
            ERR_error_string_n(ERR_peek_last_error(), buf, sizeof(buf));
            observed.err_text = buf;
        }
        ERR_clear_error();
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
    std::unique_ptr<BIO, decltype(&BIO_free_all)> accept_bio_{nullptr, &BIO_free_all};
    bool ctx_cipher_ok_ = false;
    int port_ = 0;
    bool started_ = false;
    std::mutex done_mu_;
    std::condition_variable done_cv_;
    bool done_ = false;
    std::atomic<bool> accepted_{false};
    std::thread thread_;
};

} // namespace yuzu::test::tls
