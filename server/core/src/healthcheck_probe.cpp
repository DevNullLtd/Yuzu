#include "healthcheck_probe.hpp"

#include <yuzu/server/auth.hpp>

#include <cstdlib>
#include <ostream>
#include <string>

namespace yuzu::server::healthcheck {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
std::unique_ptr<httplib::SSLClient> make_tls_client(const HealthcheckTarget& t) {
    auto c = std::make_unique<httplib::SSLClient>(t.host, t.port);
    // The anchor goes in via the CA-file setter, NOT the store-injection one: with
    // no CA file path set, httplib 0.37.1 load_certs() (httplib.h:15529-15549)
    // merges the OS trust store into the context on first connect. The file branch
    // loads ONLY the anchor, which is the whole trust decision (the server's own
    // install CA, or the operator's --https-cert). The [live] containment test
    // counts the store after a connect.
    c->set_ca_cert_path(t.trust_anchor.string());
    if (t.partial_chain) {
        // Operator mode: the anchor is the (possibly non-self-signed) server
        // certificate itself, so its issuer is absent from the store.
        X509_STORE_set_flags(SSL_CTX_get_cert_store(static_cast<SSL_CTX*>(c->tls_context())),
                             X509_V_FLAG_PARTIAL_CHAIN);
    }
    c->enable_server_certificate_verification(true);
    c->enable_server_hostname_verification(false);
    c->set_follow_location(false);
    return c;
}
#endif

HealthcheckOutcome probe_once(const HealthcheckTarget& t, const HealthcheckDeadlines& d) {
    // Heap client + explicit reset before return: httplib 0.37.1's SSLClient
    // destructor can crash after a failed handshake (same workaround as
    // oidc_provider.cpp).
    std::unique_ptr<httplib::ClientImpl> client;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (t.tls)
        client = make_tls_client(t);
    else
#endif
    {
        client = std::make_unique<httplib::ClientImpl>(t.host, t.port);
        client->set_follow_location(false);
    }
    // Deadline composition: connect_sec bounds the TCP connect, read/write bound
    // each TLS handshake step, and the whole-request max timeout (httplib.h:9906-9950)
    // bounds the request phase as a whole. No single knob covers all three in
    // 0.37.1; the sum is sized to stay under compose's 5 s on loopback.
    client->set_connection_timeout(d.connect_sec, 0);
    client->set_write_timeout(d.write_sec, 0);
    client->set_read_timeout(d.read_sec, 0);
    client->set_max_timeout(d.max_total_ms);

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

int run_healthcheck(const Config& cfg, std::string_view path, std::ostream& diag) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    constexpr bool kTlsSupported = true;
#else
    constexpr bool kTlsSupported = false;
#endif
    const auto target =
        resolve_healthcheck_target(cfg, path, auth::default_cert_dir(), kTlsSupported);
    const auto outcome = probe_once(target, HealthcheckDeadlines{});
    const int code = healthcheck_exit_code(outcome);
    if (code != 0)
        diag << healthcheck_diagnostic(target, outcome) << '\n';
    return code == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace yuzu::server::healthcheck
