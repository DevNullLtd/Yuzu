#include "healthcheck_probe.hpp"

#include <yuzu/server/auth.hpp>

#include <csignal>
#include <exception>
#include <fstream>
#include <future>
#include <iterator>
#include <ostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

namespace yuzu::server::healthcheck {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
std::unique_ptr<httplib::SSLClient> make_tls_client(const HealthcheckTarget& t) {
    // An empty CA path makes httplib's load_certs() fall through to the OS trust store
    // (httplib.h:15545-15547), the fallback this probe must never take: refuse instead.
    if (t.trust_anchor.empty())
        return nullptr;
    auto c = std::make_unique<httplib::SSLClient>(t.host, t.port);
    // SSL_CTX_new can fail (a broken OPENSSL_CONF); httplib then leaves the context null and
    // the dereferences below would crash with no diagnostic. run_healthcheck's worker turns
    // this into exit 1 plus one `exception:` line.
    if (!c->is_valid())
        throw std::runtime_error("TLS context unavailable");
    // The anchor goes in through the CA-file setter or the PEM one, NEVER httplib's
    // store-injection setter: with neither a CA file path nor a CA PEM set, httplib 0.37.1
    // load_certs() (httplib.h:15529-15549) merges the OS trust store into the context on first
    // connect. Both of ours skip that merge and load ONLY the anchor, which is the whole trust
    // decision (the server's own install CA, or the operator's --https-cert). The [live]
    // containment test counts the store after a connect.
    bool anchored = false;
    if (t.partial_chain) {
        // Operator mode (D4): the anchor is the server certificate itself, the FIRST
        // certificate in the --https-cert file. The set_ca_cert_path branch below hands httplib
        // the whole file, and a full-chain file would then also trust its issuing intermediate
        // (PARTIAL_CHAIN accepts a chain ending there), letting any sibling leaf pass with
        // hostname checking off. An unreadable or certificate-less file falls through to
        // set_ca_cert_path so the failure is httplib's own `SSL certificate loading failed`,
        // which names the anchor.
        std::ifstream f(t.trust_anchor, std::ios::binary);
        const auto pem = first_pem_certificate(
            std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()));
        if (!pem.empty()) {
            c->load_ca_cert_store(pem.data(), pem.size());
            anchored = true;
        }
    }
    if (!anchored)
        c->set_ca_cert_path(t.trust_anchor.string());
    auto* ctx = static_cast<SSL_CTX*>(c->tls_context());
    if (t.partial_chain) {
        // The anchor may be non-self-signed, so its issuer is absent from the store.
        X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx), X509_V_FLAG_PARTIAL_CHAIN);
    }
    c->enable_server_certificate_verification(true);
    c->enable_server_hostname_verification(false);
    c->set_follow_location(false);
    // Quiet shutdown: skip the TLS close_notify exchange. The request's scope exit always
    // closes the session gracefully, and httplib's tls::shutdown calls SSL_shutdown twice,
    // the second waiting for the peer's close_notify on a socket whose SO_RCVTIMEO is the
    // read timeout. A peer that stalls (never answers, so never reads ours) would cost
    // one more read timeout on top of the request deadline (measured +2.0 s). The probe
    // reads one status line and exits, so there is nothing a clean close would protect.
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    return c;
}
#endif

HealthcheckOutcome probe_once(const HealthcheckTarget& t, int max_total_ms) {
    // Heap client + explicit reset before return: httplib 0.37.1's SSLClient
    // destructor can crash after a failed handshake (same workaround as
    // oidc_provider.cpp).
    std::unique_ptr<httplib::ClientImpl> client;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (t.tls) {
        client = make_tls_client(t);
        if (!client)
            return HealthcheckOutcome{.status = 0, .error = "no trust anchor"};
    } else
#endif
    {
        client = std::make_unique<httplib::ClientImpl>(t.host, t.port);
        client->set_follow_location(false);
    }
    // Per-phase knobs: connect, write and read timeouts plus the request-phase ceiling
    // max_total_ms (httplib.h:9906-9950). Name resolution is bounded by the connect timeout in
    // this build (the vcpkg httplib defines CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO); the
    // handshake loop (httplib.h:16517-16553) is bounded per select, never in total, hence
    // run_healthcheck runs this under probe_bounded's absolute kProbeDeadline.
    client->set_connection_timeout(kConnectSec, 0);
    client->set_write_timeout(kWriteSec, 0);
    client->set_read_timeout(kReadSec, 0);
    client->set_max_timeout(max_total_ms);

    HealthcheckOutcome out;
    const auto r = client->Get(t.path);
    if (r) {
        out.status = r->status;
    } else {
        out.error = httplib::to_string(r.error());
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (r.error() == httplib::Error::SSLServerVerification)
            out.error += ": " + httplib::tls::verify_error_string(
                                    static_cast<long>(r.ssl_backend_error()));
#endif
    }
    client.reset();
    return out;
}

std::optional<HealthcheckOutcome> probe_bounded(std::chrono::milliseconds deadline,
                                                std::function<HealthcheckOutcome()> probe,
                                                ProbeSpawn spawn) {
    // The packaged_task owns the probe and co-owns the shared state with `done`, so an
    // abandoned worker (deadline first) can finish long after this frame is gone. Unlike a
    // std::async future, a packaged_task future does not block in its destructor.
    std::packaged_task<HealthcheckOutcome()> task(std::move(probe));
    auto done = task.get_future();
    // Raw std::thread join/detach rather than an RAII wrapper: a governance-recorded exemption
    // (#5906). Detach is inherent, since the worker is blocked in an uncancellable OpenSSL or
    // name-resolution call and a joining destructor would block on it. Between construction and
    // the terminal join-or-detach the only statement is wait_for on a valid future, which cannot
    // throw, so no path leaves a joinable thread to terminate the process.
    std::thread worker;
    try {
        worker = spawn(std::move(task));
    } catch (const std::system_error& e) {
        // A pids/thread limit hit at startup: report it as the probe's answer (exit 1 plus
        // one line) instead of letting the exception reach main.
        return HealthcheckOutcome{.status = 0,
                                  .error = std::string{"cannot start probe thread: "} + e.what()};
    }
    if (done.wait_for(deadline) != std::future_status::ready) {
        worker.detach();
        return std::nullopt;
    }
    worker.join();
    return done.get();
}

int run_healthcheck(const Config& cfg, std::string_view path, std::ostream& diag,
                    std::function<HealthcheckOutcome(const HealthcheckTarget&)> probe,
                    std::chrono::milliseconds deadline, void (*hard_exit)(int)) {
#ifndef _WIN32
    // httplib ignores SIGPIPE only inside Server::Server() (httplib.h:10404-10406), which this
    // one-shot mode never constructs, and sends with flags 0: a client writing into a reset peer
    // would otherwise die with 141 and no diagnostic. Set before the first socket write.
    std::signal(SIGPIPE, SIG_IGN);
#endif
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    constexpr bool kTlsSupported = true;
#else
    constexpr bool kTlsSupported = false;
#endif
    const auto target =
        resolve_healthcheck_target(cfg, path, auth::default_cert_dir(), kTlsSupported);
    // The worker owns its copy of `probe` and `target`, so abandoning it (deadline first) is safe.
    const auto outcome = probe_bounded(
        deadline, [probe = std::move(probe), target]() -> HealthcheckOutcome {
            try {
                return probe(target);
            } catch (const std::exception& e) {
                // httplib can throw: 0.37.1 reserves res.body on a peer-claimed Content-Length
                // before its payload ceiling applies (std::bad_alloc). The exit contract is
                // exit 1 plus one line, never an abort.
                return HealthcheckOutcome{.status = 0,
                                          .error = std::string{"exception: "} + e.what()};
            } catch (...) {
                return HealthcheckOutcome{.status = 0, .error = "unknown exception"};
            }
        });
    const HealthcheckOutcome timed_out{
        .status = 0, .error = "timed out after " + std::to_string(deadline.count()) + " ms"};
    const HealthcheckOutcome& result = outcome ? *outcome : timed_out;
    const int code = healthcheck_exit_code(result);
    if (code != 0) {
        diag << healthcheck_diagnostic(target, result) << '\n';
        diag.flush(); // required before hard_exit: _Exit runs no stream destructors
    }
    // The abandoned worker is blocked in httplib/OpenSSL, so production skips static destructors
    // (std::_Exit). A test hook that returns falls through to `return code`, which never
    // dereferences *outcome on this branch.
    if (!outcome)
        hard_exit(code);
    return code;
}

} // namespace yuzu::server::healthcheck
