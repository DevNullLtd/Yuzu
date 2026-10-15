/// @file test_healthcheck_probe.cpp
/// `yuzu-server --healthcheck` (#5906). Two layers:
///   - pure cases over healthcheck_rules.hpp (target resolution, exit verdict,
///     the one diagnostic line) — no I/O, run everywhere;
///   - [live] loopback cases proving the transport posture end to end against a
///     real httplib server on an ephemeral port: what the probe trusts, what it
///     refuses, that it cannot hang, and that it never follows a redirect.
///     Compiled out under TSan (#438: httplib's acceptor crashes it with no
///     report), and the TLS ones additionally require OpenSSL support.
/// The [live] layer lives in the unit suite because it needs only loopback
/// sockets and temp PEMs (no process spawn, no Postgres), every bound it checks
/// is an upper bound (the deadline cases assert < 2 s, never a lower bound), and
/// the integration surface has no TLS client harness.

#include "healthcheck_probe.hpp"
#include "healthcheck_rules.hpp"

#include "../test_helpers.hpp"
#include "gateway_peer_test_pki.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_HEALTHCHECK_LIVE_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_HEALTHCHECK_LIVE_TSAN 1
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/x509_vfy.h>
#endif

using namespace yuzu::server;
using namespace yuzu::server::healthcheck;
namespace fs = std::filesystem;

// ── Pure cases ──────────────────────────────────────────────────────────────

TEST_CASE("healthcheck: default Config resolves to the HTTPS listener and the install CA",
          "[server][healthcheck]") {
    const Config cfg{};
    const auto t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true);
    CHECK(t.tls);
    CHECK(t.host == "127.0.0.1");
    CHECK(t.port == 8443);
    CHECK(t.path == "/readyz");
    CHECK(t.trust_anchor == fs::path{"/certs"} / "default-ca.pem");
    CHECK_FALSE(t.partial_chain);
}

TEST_CASE("healthcheck: --ca-dir moves the anchor; --https-cert makes that file the partial-chain "
          "anchor",
          "[server][healthcheck]") {
    Config cfg{};
    cfg.ca_dir = "/custom-ca";
    auto t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true);
    CHECK(t.trust_anchor == fs::path{"/custom-ca"} / "default-ca.pem");
    CHECK_FALSE(t.partial_chain);

    cfg.https_cert_path = "/op/server.pem";
    t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true);
    CHECK(t.trust_anchor == fs::path{"/op/server.pem"});
    CHECK(t.partial_chain);

    cfg.ca_dir.clear();
    t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true);
    CHECK(t.trust_anchor == fs::path{"/op/server.pem"});
    CHECK(t.partial_chain);
}

TEST_CASE("healthcheck: --no-https probes the plain port with no anchor and honours /livez",
          "[server][healthcheck]") {
    Config cfg{};
    cfg.https_enabled = false;
    const auto t = resolve_healthcheck_target(cfg, "/livez", fs::path{"/certs"}, true);
    CHECK_FALSE(t.tls);
    CHECK(t.port == cfg.web_port);
    CHECK(t.path == "/livez");
    CHECK(t.trust_anchor.empty());
    CHECK_FALSE(t.partial_chain);
}

TEST_CASE("healthcheck: a build without TLS support probes plain HTTP even with https enabled",
          "[server][healthcheck]") {
    // Mirrors the server's own fallback when CPPHTTPLIB_OPENSSL_SUPPORT is absent.
    const Config cfg{}; // https_enabled defaults true
    const auto t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, false);
    CHECK_FALSE(t.tls);
    CHECK(t.port == cfg.web_port);
    CHECK(t.trust_anchor.empty());
}

TEST_CASE("healthcheck: wildcard binds map to loopback and IPv6 hosts are bracketed",
          "[server][healthcheck]") {
    CHECK(probe_host_for("") == "127.0.0.1");
    CHECK(probe_host_for("0.0.0.0") == "127.0.0.1");
    CHECK(probe_host_for("::") == "::1");
    CHECK(probe_host_for("10.0.0.5") == "10.0.0.5");
    CHECK(probe_host_for("localhost") == "localhost");

    HealthcheckTarget t;
    t.tls = true;
    t.host = "::1";
    t.port = 8443;
    t.path = "/readyz";
    CHECK(healthcheck_url(t) == "https://[::1]:8443/readyz");
    t.tls = false;
    t.host = "127.0.0.1";
    t.port = 8080;
    CHECK(healthcheck_url(t) == "http://127.0.0.1:8080/readyz");
}

TEST_CASE("healthcheck: only HTTP 200 is healthy", "[server][healthcheck]") {
    CHECK(healthcheck_exit_code({200, {}}) == 0);
    CHECK(healthcheck_exit_code({301, {}}) == 1);
    CHECK(healthcheck_exit_code({503, {}}) == 1);
    CHECK(healthcheck_exit_code({0, "Connection"}) == 1);
    CHECK(healthcheck_exit_code({0, "SSL server verification failed: certificate has expired"}) ==
          1);
}

TEST_CASE("healthcheck: the diagnostic is one line, names target and anchor, never the key path",
          "[server][healthcheck]") {
    Config cfg{};
    cfg.https_cert_path = "/op/server.pem";
    cfg.https_key_path = "/secret/key.pem";
    const auto t = resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true);

    CHECK(healthcheck_diagnostic(t, {200, {}}).empty());

    const auto line503 = healthcheck_diagnostic(t, {503, {}});
    CHECK(line503.find("503") != std::string::npos);
    CHECK(line503.find("https://127.0.0.1:8443/readyz") != std::string::npos);
    CHECK(line503.find("/op/server.pem") != std::string::npos);

    const auto line_err = healthcheck_diagnostic(t, {0, "Connection"});
    CHECK(line_err.find("Connection") != std::string::npos);
    CHECK(line_err.find("/op/server.pem") != std::string::npos);
    for (const auto& line : {line503, line_err}) {
        CHECK(line.find("key.pem") == std::string::npos);
        CHECK(line.find('\n') == std::string::npos);
    }

    Config plain{};
    plain.https_enabled = false;
    const auto tp = resolve_healthcheck_target(plain, "/readyz", fs::path{"/certs"}, true);
    CHECK(healthcheck_diagnostic(tp, {0, "Connection"}).find("trust anchor: none") !=
          std::string::npos);
}

TEST_CASE("healthcheck: control bytes in the target never split the diagnostic line",
          "[server][healthcheck]") {
    HealthcheckTarget t;
    t.tls = true;
    t.host = "bad\nhost";
    t.port = 8443;
    t.path = "/readyz";
    t.trust_anchor = fs::path{"/certs/an\rchor\x7f.pem"};

    const auto line = healthcheck_diagnostic(t, {0, "Conn\nection"});
    CHECK(line.find('\n') == std::string::npos);
    CHECK(line.find('\r') == std::string::npos);
    CHECK(line.find('\x7f') == std::string::npos);
    // The printable parts survive, so the line still names the target and the anchor.
    CHECK(line.find("healthcheck: GET https://bad?host:8443/readyz") != std::string::npos);
    CHECK(line.find("Conn?ection") != std::string::npos);
    CHECK(line.find("(trust anchor: /certs/an?chor?.pem)") != std::string::npos);
}

namespace {
/// Shared with the worker probe_bounded may abandon, so the worker owns what it touches.
struct Gate {
    std::mutex mu;
    std::condition_variable cv;
    bool released{false};
    void release() {
        {
            std::lock_guard<std::mutex> lk(mu);
            released = true;
        }
        cv.notify_all();
    }
};
} // namespace

TEST_CASE("healthcheck: probe_bounded abandons a probe that outlives the deadline",
          "[server][healthcheck]") {
    auto gate = std::make_shared<Gate>();
    // ONE wait that ends by itself after 2 s: a probe_bounded that waited for the probe would
    // return a value here and fail CHECK_FALSE below, instead of hanging the suite.
    auto probe = [gate] {
        std::unique_lock<std::mutex> lk(gate->mu);
        gate->cv.wait_for(lk, std::chrono::seconds(2), [&] { return gate->released; });
        return HealthcheckOutcome{.status = 200, .error = {}};
    };

    const auto t0 = std::chrono::steady_clock::now();
    const auto out = probe_bounded(std::chrono::milliseconds(50), probe);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    gate->release(); // let the abandoned worker finish

    CHECK_FALSE(out.has_value());
    CHECK(elapsed < std::chrono::seconds(2)); // upper bound only, never a lower bound
}

TEST_CASE("healthcheck: probe_bounded returns the outcome of a probe that finishes in time",
          "[server][healthcheck]") {
    const auto out = probe_bounded(std::chrono::seconds(2), [] {
        return HealthcheckOutcome{.status = 200, .error = {}};
    });
    REQUIRE(out.has_value());
    CHECK(out->status == 200);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST_CASE("healthcheck: a TLS target with no trust anchor is refused, never probed against the "
          "system store",
          "[server][healthcheck]") {
    // An empty CA path would make httplib's load_certs() fall back to the OS trust store.
    HealthcheckTarget t;
    t.tls = true;
    t.host = "127.0.0.1";
    t.port = 1; // never dialled: the factory refuses before a socket exists
    t.path = "/readyz";
    CHECK(make_tls_client(t) == nullptr);
    const auto out = probe_once(t);
    CHECK(out.status == 0);
    CHECK(out.error.find("no trust anchor") != std::string::npos);
}
#endif

// ── [live] loopback cases ───────────────────────────────────────────────────

#ifndef YUZU_HEALTHCHECK_LIVE_TSAN

namespace {

/// A loopback httplib server on an ephemeral 127.0.0.1 port (no fixed port, so
/// two concurrent jobs on a shared runner cannot collide).
struct LoopbackServer {
    std::unique_ptr<httplib::Server> svr;
    int port{0};
    std::thread th;

    explicit LoopbackServer(std::unique_ptr<httplib::Server> s) : svr(std::move(s)) {}

    void start() {
        port = svr->bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        th = std::thread([this] { svr->listen_after_bind(); });
        svr->wait_until_ready();
        REQUIRE(svr->is_running());
    }
    ~LoopbackServer() {
        // Order is load-bearing: stop() is a no-op until the accept loop is running, so a
        // join() after an early stop() would hang. See test_mcp_body_cap.cpp for the full
        // account of why the wait sits inside the joinable() test.
        if (th.joinable()) {
            svr->wait_until_ready();
            svr->stop();
            th.join();
        }
    }
};

HealthcheckTarget plain_target(int port, const std::string& path = "/readyz") {
    HealthcheckTarget t;
    t.tls = false;
    t.host = "127.0.0.1";
    t.port = port;
    t.path = path;
    return t;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

namespace gwt = yuzu::test::gwpeer;

void write_file(const fs::path& p, const std::string& content) {
    std::ofstream f(p, std::ios::binary);
    REQUIRE(f.good());
    f << content;
}

HealthcheckTarget tls_target(int port, const fs::path& anchor, bool partial_chain) {
    HealthcheckTarget t;
    t.tls = true;
    t.host = "127.0.0.1";
    t.port = port;
    t.path = "/readyz";
    t.trust_anchor = anchor;
    t.partial_chain = partial_chain;
    return t;
}

/// An SSLServer answering 200 on /readyz and /livez, serving `leaf`. `readyz`, when given,
/// replaces the /readyz handler.
std::unique_ptr<LoopbackServer> tls_server(const fs::path& dir, const gwt::TestLeaf& leaf,
                                           httplib::Server::Handler readyz = nullptr) {
    write_file(dir / "server.pem", leaf.cert_pem);
    write_file(dir / "server.key", leaf.key_pem);
    auto ssl = std::make_unique<httplib::SSLServer>((dir / "server.pem").string().c_str(),
                                                    (dir / "server.key").string().c_str());
    REQUIRE(ssl->is_valid());
    auto ok = [](const httplib::Request&, httplib::Response& res) {
        res.set_content("ok", "text/plain");
    };
    ssl->Get("/readyz", readyz ? std::move(readyz) : httplib::Server::Handler{ok});
    ssl->Get("/livez", ok);
    auto srv = std::make_unique<LoopbackServer>(std::move(ssl));
    srv->start();
    return srv;
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

} // namespace

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

TEST_CASE("healthcheck: default-CA mode verifies a leaf issued by the install CA",
          "[server][healthcheck][live]") {
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    write_file(tmp.path / "default-ca.pem", ca.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    const auto t = tls_target(srv->port, tmp.path / "default-ca.pem", false);
    const auto out = probe_once(t);
    CHECK(out.status == 200);
    CHECK(healthcheck_exit_code(out) == 0);
    CHECK(healthcheck_diagnostic(t, out).empty());
}

TEST_CASE("healthcheck: the probe trusts ONLY its anchor, never the system store",
          "[server][healthcheck][live]") {
    // httplib 0.37.1 load_certs() merges the OS trust store into the context when
    // no CA file path is set. After a connect the client's own store must hold
    // exactly the anchor's one certificate; a system-store merge adds every OS
    // root, so this fails on any httplib branch-order change (and on every host
    // that carries OS roots, which is every CI image and dev box).
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    write_file(tmp.path / "default-ca.pem", ca.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    auto c = make_tls_client(tls_target(srv->port, tmp.path / "default-ca.pem", false));
    c->set_connection_timeout(1, 0);
    c->set_read_timeout(2, 0);
    const auto r = c->Get("/livez"); // triggers load_certs()
    REQUIRE(r);
    CHECK(r->status == 200);
    auto* store = SSL_CTX_get_cert_store(static_cast<SSL_CTX*>(c->tls_context()));
    REQUIRE(store != nullptr);
    CHECK(sk_X509_OBJECT_num(X509_STORE_get0_objects(store)) == 1);
    c.reset(); // explicit destroy (httplib 0.37.1 SSLClient destructor workaround)
}

TEST_CASE("healthcheck: operator mode anchors on the server certificate itself (partial chain), "
          "hostname unchecked",
          "[server][healthcheck][live]") {
    // A CA-issued, SAN-less leaf, with its issuer ABSENT from the anchor file: it
    // verifies only because the leaf is the partial-chain anchor, and it carries
    // no name matching 127.0.0.1, so it also proves hostname checking is off.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    auto lp = gwt::leaf_params("operator-leaf", true, false,
                               yuzu::server::pki::validity_days_from_now(1));
    lp.san = {};
    auto issued = yuzu::server::pki::issue_leaf(ca.cert_pem, ca.key_pem,
                                                yuzu::server::pki::KeyAlgo::EcP256, lp);
    REQUIRE(issued.has_value());
    const gwt::TestLeaf leaf{issued->private_key_pem, issued->cert_pem};
    write_file(tmp.path / "anchor.pem", leaf.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    const auto ok = probe_once(tls_target(srv->port, tmp.path / "anchor.pem", true));
    CHECK(ok.status == 200);
    CHECK(healthcheck_exit_code(ok) == 0);

    // Control: the same anchor WITHOUT partial-chain must fail, proving the flag is
    // what admits the leaf in the case above.
    const auto control = probe_once(tls_target(srv->port, tmp.path / "anchor.pem", false));
    CHECK(control.status == 0);
    CHECK(healthcheck_exit_code(control) == 1);
    CHECK(control.error.find("verification") != std::string::npos);
    CHECK(control.error.find("issuer") != std::string::npos);
}

TEST_CASE("healthcheck: a leaf from another CA is refused with the OpenSSL reason",
          "[server][healthcheck][live]") {
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca_a = gwt::make_ca("hc-ca-a");
    const auto ca_b = gwt::make_ca("hc-ca-b");
    const auto leaf = gwt::make_leaf(ca_a, "hc-server", true, false);
    write_file(tmp.path / "other-ca.pem", ca_b.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    const auto t = tls_target(srv->port, tmp.path / "other-ca.pem", false);
    const auto out = probe_once(t);
    CHECK(out.status == 0);
    CHECK(healthcheck_exit_code(out) == 1);
    CHECK(out.error.find("verification") != std::string::npos);
    CHECK(out.error.find("issuer") != std::string::npos);
    const auto line = healthcheck_diagnostic(t, out);
    CHECK(line.find("other-ca.pem") != std::string::npos);
}

TEST_CASE("healthcheck: an expired leaf is refused and the reason says so",
          "[server][healthcheck][live]") {
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false, gwt::expired_validity());
    write_file(tmp.path / "default-ca.pem", ca.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    const auto out = probe_once(tls_target(srv->port, tmp.path / "default-ca.pem", false));
    CHECK(out.status == 0);
    CHECK(healthcheck_exit_code(out) == 1);
    CHECK(out.error.find("expired") != std::string::npos);
}

TEST_CASE("healthcheck: a stalled TLS responder is cut off",
          "[server][healthcheck][live]") {
    // The request phase is cut at max_total_ms, but httplib then closes the TLS session
    // gracefully: tls::shutdown calls SSL_shutdown twice, and the second call waits for the
    // peer's close_notify on a socket whose SO_RCVTIMEO is the read timeout (2 s here). A
    // responder stuck in its handler never sends one, so without quiet shutdown on the
    // client context this case measures 0.2 s + 2.0 s = 2.2 s and FAILS the 2 s bound;
    // with it, ~0.2 s.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    write_file(tmp.path / "default-ca.pem", ca.cert_pem);

    std::mutex mu;
    std::condition_variable cv;
    bool release = false;
    auto srv = tls_server(tmp.path, leaf, [&](const httplib::Request&, httplib::Response& res) {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return release; });
        res.set_content("late", "text/plain");
    });
    // Declared AFTER the server so it is destroyed first: the blocked handler must be
    // released before the server's destructor joins its worker.
    yuzu::test::ScopeExit releaser{[&] {
        {
            std::lock_guard<std::mutex> lk(mu);
            release = true;
        }
        cv.notify_all();
    }};

    const auto t0 = std::chrono::steady_clock::now();
    const auto out = probe_once(tls_target(srv->port, tmp.path / "default-ca.pem", false),
                                /*max_total_ms=*/200);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    INFO("elapsed ms: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    CHECK(out.status == 0);
    CHECK_FALSE(out.error.empty());
    CHECK(healthcheck_exit_code(out) == 1);
    CHECK(elapsed < std::chrono::seconds(2)); // sanity bound only, never a lower bound
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

TEST_CASE("healthcheck: a stalled responder is cut off by the whole-request ceiling",
          "[server][healthcheck][live]") {
    std::mutex mu;
    std::condition_variable cv;
    bool release = false;
    LoopbackServer srv{std::make_unique<httplib::Server>()};
    srv.svr->Get("/readyz", [&](const httplib::Request&, httplib::Response& res) {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return release; });
        res.set_content("late", "text/plain");
    });
    srv.start();
    // Declared AFTER the server so it is destroyed first: the blocked handler must
    // be released before the server's destructor joins its worker.
    yuzu::test::ScopeExit releaser{[&] {
        {
            std::lock_guard<std::mutex> lk(mu);
            release = true;
        }
        cv.notify_all();
    }};

    const auto t0 = std::chrono::steady_clock::now();
    const auto out = probe_once(plain_target(srv.port), /*max_total_ms=*/200);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(out.status == 0);
    CHECK_FALSE(out.error.empty());
    CHECK(healthcheck_exit_code(out) == 1);
    CHECK(elapsed < std::chrono::seconds(2)); // sanity bound only, never a lower bound
}

TEST_CASE("healthcheck: a redirect is reported as the answer and never followed",
          "[server][healthcheck][live]") {
    std::atomic<int> target_hits{0};
    LoopbackServer srv{std::make_unique<httplib::Server>()};
    srv.svr->Get("/readyz", [](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/elsewhere", 301);
    });
    srv.svr->Get("/elsewhere", [&](const httplib::Request&, httplib::Response& res) {
        ++target_hits;
        res.set_content("ok", "text/plain");
    });
    srv.start();

    const auto out = probe_once(plain_target(srv.port));
    CHECK(out.status == 301);
    CHECK(healthcheck_exit_code(out) == 1);
    CHECK(target_hits.load() == 0);
}

TEST_CASE("healthcheck: --no-https shape probes a plain listener and exits 0 on 200",
          "[server][healthcheck][live]") {
    LoopbackServer srv{std::make_unique<httplib::Server>()};
    srv.svr->Get("/readyz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ready"})", "application/json");
    });
    srv.start();

    const auto out = probe_once(plain_target(srv.port));
    CHECK(out.status == 200);
    CHECK(healthcheck_exit_code(out) == 0);
}

#endif // !YUZU_HEALTHCHECK_LIVE_TSAN
