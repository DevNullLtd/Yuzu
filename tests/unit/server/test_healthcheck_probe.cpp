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
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#ifndef _WIN32
#include <csignal>
#include <signal.h>
#endif

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
using Catch::Matchers::ContainsSubstring;
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

TEST_CASE("healthcheck: the target host comes from --web-address through probe_host_for",
          "[server][healthcheck]") {
    // The shipped images run `--web-address 0.0.0.0`: a probe that dialled the raw bind address
    // (or a hard-coded loopback) would pass every other case here.
    const auto host_for = [](const char* web_address) {
        Config cfg{};
        cfg.web_address = web_address;
        return resolve_healthcheck_target(cfg, "/readyz", fs::path{"/certs"}, true).host;
    };
    CHECK(host_for("0.0.0.0") == "127.0.0.1");
    CHECK(host_for("::") == "::1");
    CHECK(host_for("10.0.0.5") == "10.0.0.5");
}

TEST_CASE("healthcheck: the published per-phase bounds", "[server][healthcheck]") {
    // Published in the server-admin "Time" row and the changelog fragment.
    CHECK(kConnectSec == 1);
    CHECK(kWriteSec == 1);
    CHECK(kReadSec == 2);
    CHECK(kRequestMs == 3000);
    CHECK(kProbeDeadline == std::chrono::milliseconds(4000));
}

TEST_CASE("healthcheck: first_pem_certificate returns only the first certificate block",
          "[server][healthcheck]") {
    const std::string a = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const std::string b = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
    CHECK(first_pem_certificate("").empty());
    CHECK(first_pem_certificate("not a pem\n").empty());
    CHECK(first_pem_certificate(a) == a);
    CHECK(first_pem_certificate(a + b) == a);
    // Whatever surrounds the block is dropped; the closing newline is normalised.
    CHECK(first_pem_certificate("junk\n" + a.substr(0, a.size() - 1) + "\ntrailing") == a);
    // A private key ahead of the certificate is skipped, never returned.
    CHECK(first_pem_certificate("-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----\n" +
                                a + b) == a);
    // An unterminated block is not a certificate.
    CHECK(first_pem_certificate("-----BEGIN CERTIFICATE-----\nAAAA\n").empty());
}

TEST_CASE("healthcheck: first_pem_certificate refuses a certificate under another label",
          "[server][healthcheck]") {
    // OpenSSL's PEM reader loads `X509 CERTIFICATE` and `TRUSTED CERTIFICATE` blocks as
    // certificates, so a file whose first certificate carries one is a real server certificate
    // that this function must not step over: the next plain block is typically the issuing CA,
    // and anchoring on it would trust every sibling leaf under it.
    const std::string a = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const std::string x509 =
        "-----BEGIN X509 CERTIFICATE-----\nXXXX\n-----END X509 CERTIFICATE-----\n";
    const std::string trusted =
        "-----BEGIN TRUSTED CERTIFICATE-----\nTTTT\n-----END TRUSTED CERTIFICATE-----\n";
    CHECK(first_pem_certificate(x509).empty());
    CHECK(first_pem_certificate(trusted).empty());
    CHECK(first_pem_certificate(x509 + a).empty());
    CHECK(first_pem_certificate(trusted + a + a).empty());
    // Marker text in a comment ahead of an alias-labelled leaf must not widen the result: the
    // returned text would carry the leaf AND the CA behind it, and httplib loads every
    // certificate in the text it is handed.
    const std::string prose = "# paste after -----BEGIN CERTIFICATE----- below\n";
    CHECK(first_pem_certificate(prose + x509 + a).empty());
    CHECK(first_pem_certificate(prose + trusted + a).empty());
    // A certificate request is not a certificate: skipped like a key, never a refusal.
    CHECK(first_pem_certificate("-----BEGIN CERTIFICATE REQUEST-----\nRRRR\n"
                                "-----END CERTIFICATE REQUEST-----\n" +
                                a) == a);
}

TEST_CASE("healthcheck: first_pem_certificate reads a block the way OpenSSL does",
          "[server][healthcheck]") {
    // OpenSSL's reader (the server's own chain loader, on the same --https-cert file) accepts
    // a BEGIN line only at the start of a line, after an optional UTF-8 BOM on the first. A
    // marker in mid-line text is not the first certificate: returning it would anchor the
    // probe on the CA body that follows, while the server presents the LEAF behind it.
    const std::string a = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const std::string b = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
    // The mid-line marker shape: `# CA: <ca block>` ahead of the real leaf.
    CHECK(first_pem_certificate("# CA: " + a + b).empty());
    CHECK(first_pem_certificate("x" + a).empty());
    CHECK(first_pem_certificate("  " + a).empty()); // an indented BEGIN is not a line start
    // A BOM is skipped only as the very first three bytes.
    const std::string bom = "\xEF\xBB\xBF";
    CHECK(first_pem_certificate(bom + a) == a);
    CHECK(first_pem_certificate(bom + a + b) == a);
    CHECK(first_pem_certificate("x" + bom + a).empty());
    CHECK(first_pem_certificate(bom + bom + a).empty());
    // A marker after a newline is a line start (CRLF files included).
    CHECK(first_pem_certificate("prose\r\n" + a) == a);
    // A block carrying a PEM header is refused: OpenSSL would prompt for a pass phrase on
    // stderr, a second line against the one-line contract (a base64 body never holds ':').
    CHECK(first_pem_certificate("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n"
                                "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n"
                                "AAAA\n-----END CERTIFICATE-----\n" +
                                b)
              .empty());
}

TEST_CASE("healthcheck: only HTTP 200 is healthy", "[server][healthcheck]") {
    CHECK(healthcheck_exit_code({200, {}}) == 0);
    CHECK(healthcheck_exit_code({301, {}}) == 1);
    CHECK(healthcheck_exit_code({503, {}}) == 1);
    CHECK(healthcheck_exit_code({0, "Connection"}) == 1);
    CHECK(healthcheck_exit_code({0, "SSL server verification failed: certificate has expired"}) ==
          1);
}

TEST_CASE("healthcheck: the diagnostic is one line naming target and anchor - never the key path",
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
    CHECK(line.find("healthcheck: GET https://bad_host:8443/readyz") != std::string::npos);
    CHECK(line.find("Conn_ection") != std::string::npos);
    CHECK(line.find("(trust anchor: /certs/an_chor_.pem)") != std::string::npos);
}

TEST_CASE("healthcheck: each diagnostic field is capped on its own - never the whole line",
          "[server][healthcheck]") {
    // healthcheck_diagnostic wraps log_key_token around the URL, the reason and the anchor
    // SEPARATELY: each over-long field keeps a 231-byte head, '~' and a 24-byte tail (256 bytes),
    // and the literal scaffolding between them survives. A single wrap around the whole line
    // would yield one 256-byte line and fail every check below.
    HealthcheckTarget t;
    t.tls = true;
    t.host = std::string(300, 'a');
    t.port = 8443;
    t.path = "/readyz";
    t.trust_anchor = fs::path{"/" + std::string(300, 'c') + ".pem"};
    const std::string reason(300, 'b');

    const auto url = healthcheck_url(t);
    const auto anchor = t.trust_anchor.string();
    const auto line = healthcheck_diagnostic(t, {0, reason});

    CHECK(line == "healthcheck: GET " + yuzu::log_key_token(url) + " -> " +
                      yuzu::log_key_token(reason) + " (trust anchor: " +
                      yuzu::log_key_token(anchor) + ")");

    // Independently of the helper: 17 + 4 + 16 + 1 bytes of scaffolding around three 256-byte
    // tokens.
    constexpr std::size_t kScaffolding = 17 + 4 + 16 + 1;
    constexpr std::size_t kToken = 256;
    constexpr std::size_t kMarker = 231; // head bytes before the '~'
    REQUIRE(line.size() == 3 * kToken + kScaffolding);

    const std::string url_token = line.substr(17, kToken);
    const std::string reason_token = line.substr(17 + kToken + 4, kToken);
    const std::string anchor_token = line.substr(17 + kToken + 4 + kToken + 16, kToken);
    CHECK(line.substr(17 + kToken, 4) == " -> ");
    CHECK(line.substr(17 + kToken + 4 + kToken, 16) == " (trust anchor: ");
    CHECK(line.back() == ')');

    for (const auto* tok : {&url_token, &reason_token, &anchor_token}) {
        CHECK((*tok)[kMarker] == '~');
        CHECK(tok->find('~') == kMarker);
    }
    CHECK(url_token.starts_with("https://aaaa"));
    CHECK(url_token.substr(kMarker + 1) == url.substr(url.size() - 24));
    CHECK(reason_token.substr(kMarker + 1) == std::string(24, 'b'));
    CHECK(anchor_token.substr(kMarker + 1) == std::string(20, 'c') + ".pem");
}

TEST_CASE("healthcheck: the diagnostic keeps spaces and backslashes in a Windows anchor path",
          "[server][healthcheck]") {
    HealthcheckTarget t;
    t.tls = true;
    t.host = "127.0.0.1";
    t.port = 8443;
    t.path = "/readyz";
    // On POSIX fs::path keeps the backslashes verbatim in .string().
    t.trust_anchor = fs::path{R"(C:\Program Files\Yuzu\certs\default-ca.pem)"};
    CHECK(healthcheck_diagnostic(t, {503, {}}) ==
          "healthcheck: GET https://127.0.0.1:8443/readyz -> 503 (trust anchor: "
          "C:\\Program Files\\Yuzu\\certs\\default-ca.pem)");
}

TEST_CASE("healthcheck: probe_bounded abandons a probe that outlives the deadline",
          "[server][healthcheck]") {
    // The probe captures a shared_future copy, so the abandoned worker owns what it waits on.
    // ONE wait that ends by itself after 2 s: a probe_bounded that waited for the probe would
    // return a value here and fail CHECK_FALSE below, instead of hanging the suite.
    std::promise<void> release;
    auto probe = [released = release.get_future().share()] {
        released.wait_for(std::chrono::seconds(2));
        return HealthcheckOutcome{.status = 200, .error = {}};
    };

    const auto t0 = std::chrono::steady_clock::now();
    const auto out = probe_bounded(std::chrono::milliseconds(50), probe);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    release.set_value(); // let the abandoned worker finish

    CHECK_FALSE(out.has_value());
    CHECK(elapsed < std::chrono::seconds(2)); // upper bound only, never a lower bound
}

namespace {

// File-static so a plain function pointer (run_healthcheck's hard_exit hook, shaped like
// std::_Exit) can record into it.
std::atomic<int> g_recorded_exit{-1};
void record_exit(int code) {
    g_recorded_exit = code;
}

} // namespace

TEST_CASE("healthcheck: run_healthcheck cuts a hanging probe at the deadline - prints the timeout "
          "line and exits 1",
          "[server][healthcheck]") {
    g_recorded_exit = -1;
    Config cfg{};
    cfg.https_enabled = false; // plain target: no anchor, and nothing is dialled (probe injected)
    // The hanging probe ends by itself after 2 s. With the probe_bounded wrapper removed,
    // run_healthcheck would get that 200 back (code 0, no line, no exit) and FAIL the checks
    // below instead of hanging the suite.
    std::promise<void> release;
    auto hanging = [released = release.get_future().share()](const HealthcheckTarget&) {
        released.wait_for(std::chrono::seconds(2));
        return HealthcheckOutcome{.status = 200, .error = {}};
    };
    std::ostringstream diag;

    const int code = run_healthcheck(cfg, "/readyz", diag, hanging, std::chrono::milliseconds(50),
                                     &record_exit);
    release.set_value(); // let the abandoned worker finish

    CHECK(code == 1);
    CHECK(g_recorded_exit.load() == 1);
    CHECK(diag.str() == "healthcheck: GET http://127.0.0.1:" + std::to_string(cfg.web_port) +
                            "/readyz -> timed out after 50 ms (trust anchor: none)\n");
}

TEST_CASE("healthcheck: run_healthcheck with a probe that answers in time prints nothing and does "
          "not hard-exit",
          "[server][healthcheck]") {
    g_recorded_exit = -1;
    Config cfg{};
    cfg.https_enabled = false;
    std::ostringstream diag;

    const int code = run_healthcheck(
        cfg, "/readyz", diag,
        [](const HealthcheckTarget&) { return HealthcheckOutcome{.status = 200, .error = {}}; },
        std::chrono::seconds(2), &record_exit);

    CHECK(code == 0);
    CHECK(diag.str().empty());
    CHECK(g_recorded_exit.load() == -1);
}

TEST_CASE("healthcheck: run_healthcheck turns an exception from the probe into exit 1 and one "
          "line",
          "[server][healthcheck]") {
    // httplib 0.37.1 reserves the response body on a peer-claimed Content-Length before its
    // payload ceiling applies, so a hostile or buggy peer can make the real probe throw
    // std::bad_alloc. Mutation: without the try/catch around run_healthcheck's probe_bounded
    // call, the exception is stored by probe_bounded's packaged_task and rethrown by done.get()
    // into Catch2, which reports these sections failed (unexpected exception) rather than the
    // process aborting.
    Config cfg{};
    cfg.https_enabled = false;
    const auto run = [&cfg](std::function<HealthcheckOutcome(const HealthcheckTarget&)> probe,
                            const std::string& reason) {
        g_recorded_exit = -1;
        std::ostringstream diag;
        const int code = run_healthcheck(cfg, "/readyz", diag, std::move(probe),
                                         std::chrono::seconds(2), &record_exit);
        const std::string line = diag.str();
        CHECK(code == 1);
        CHECK(g_recorded_exit.load() == -1); // the outcome has a value, so no hard_exit
        CHECK(std::count(line.begin(), line.end(), '\n') == 1);
        CHECK(line == "healthcheck: GET http://127.0.0.1:" + std::to_string(cfg.web_port) +
                          "/readyz -> " + reason + " (trust anchor: none)\n");
    };

    SECTION("std::bad_alloc, as httplib throws it on a huge Content-Length") {
        // what() is implementation-defined ("std::bad_alloc" vs MSVC's "bad allocation").
        run([](const HealthcheckTarget&) -> HealthcheckOutcome { throw std::bad_alloc{}; },
            std::string{"exception: "} + std::bad_alloc{}.what());
    }
    SECTION("another std::exception") {
        run([](const HealthcheckTarget&) -> HealthcheckOutcome {
            throw std::runtime_error{"boom"};
        }, "exception: boom");
    }
    SECTION("a non-std exception type") {
        struct NotStd {};
        run([](const HealthcheckTarget&) -> HealthcheckOutcome { throw NotStd{}; },
            "unknown exception");
    }
    SECTION("std::system_error, as std::thread's constructor throws it") {
        // Runtime evidence for the real spawn path (pthread_create forced to EAGAIN with an
        // LD_PRELOAD shim against `--healthcheck --no-https`): exit 1, empty stdout, exactly one
        // `exception: Resource temporarily unavailable` line. A unit test cannot fail the real
        // spawn, so this pins the arm that line comes from: a system_error is a std::exception
        // and must not fall through to the `unknown exception` arm. Mutation: delete the
        // `catch (const std::exception&)` arm in run_healthcheck and this section reads
        // `unknown exception`.
        const std::system_error err{
            std::make_error_code(std::errc::resource_unavailable_try_again)};
        // what() is implementation-defined, so the expectation is built from the object.
        run([err](const HealthcheckTarget&) -> HealthcheckOutcome { throw err; },
            std::string{"exception: "} + err.what());
    }
}

#ifndef _WIN32
TEST_CASE("healthcheck: run_healthcheck ignores SIGPIPE before the probe runs",
          "[server][healthcheck]") {
    // httplib ignores SIGPIPE only inside Server::Server(), which the --healthcheck process never
    // constructs; a reset peer would otherwise kill it with 141 and no diagnostic.
    struct sigaction prev{};
    REQUIRE(sigaction(SIGPIPE, nullptr, &prev) == 0);
    yuzu::test::ScopeExit restore{[&] { sigaction(SIGPIPE, &prev, nullptr); }};
    // The live cases' httplib Server constructors have already flipped SIGPIPE to SIG_IGN
    // process-wide: start from the default so run_healthcheck is the only thing that can ignore it.
    std::signal(SIGPIPE, SIG_DFL);

    g_recorded_exit = -1;
    Config cfg{};
    cfg.https_enabled = false;
    // Owned by the probe (like the sibling cases' abandoned-worker state), so a worker that
    // outlives this frame writes into live memory.
    auto seen_ignored = std::make_shared<std::atomic<bool>>(false);
    std::ostringstream diag;
    // Captured inside the probe, so this also proves the ordering: before the first socket I/O.
    const int code = run_healthcheck(
        cfg, "/readyz", diag,
        [seen_ignored](const HealthcheckTarget&) {
            struct sigaction sa{};
            sigaction(SIGPIPE, nullptr, &sa);
            *seen_ignored = (sa.sa_handler == SIG_IGN);
            return HealthcheckOutcome{.status = 200, .error = {}};
        },
        kProbeDeadline, &record_exit);

    CHECK(code == 0);
    CHECK(seen_ignored->load());
}
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST_CASE("healthcheck: a TLS target with no trust anchor is refused - never probed against the "
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

/// The whole `--healthcheck` path (target resolution, exception translation, diagnostic) in
/// operator mode: 127.0.0.1:`port`, `anchor` as `--https-cert`. Returns the one stderr line of a
/// failing probe.
std::string operator_mode_diagnostic(int port, const fs::path& anchor) {
    Config cfg{};
    cfg.https_port = port;
    cfg.https_cert_path = anchor;
    g_recorded_exit = -1;
    std::ostringstream diag;
    const int code = run_healthcheck(
        cfg, "/readyz", diag, [](const HealthcheckTarget& t) { return probe_once(t); },
        kProbeDeadline, &record_exit);
    const std::string line = diag.str();
    CHECK(code == 1);
    CHECK(g_recorded_exit.load() == -1); // the probe answered, so no hard_exit
    CHECK(std::count(line.begin(), line.end(), '\n') == 1);
    CHECK(line.find("(trust anchor: " + anchor.string() + ")") != std::string::npos);
    return line;
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

TEST_CASE("healthcheck: the probe trusts ONLY its anchor - never the system store",
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
    auto* ctx = static_cast<SSL_CTX*>(c->tls_context());
    auto* store = SSL_CTX_get_cert_store(ctx);
    REQUIRE(store != nullptr);
    CHECK(sk_X509_OBJECT_num(X509_STORE_get0_objects(store)) == 1);
    // The stalled-responder case below measures this by timing only; pin the knob itself.
    CHECK(SSL_CTX_get_quiet_shutdown(ctx) == 1);
    c.reset(); // explicit destroy (httplib 0.37.1 SSLClient destructor workaround)
}

TEST_CASE("healthcheck: operator mode anchors on the server certificate itself (partial chain) - "
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

TEST_CASE("healthcheck: operator mode with a full-chain file trusts only its first certificate",
          "[server][healthcheck][live]") {
    // The anchor file is the server certificate followed by its issuing CA, as an operator's
    // fullchain.pem is. Handing httplib the whole file would trust the CA too, and with the
    // partial-chain flag and hostname checking off, any sibling leaf under that CA would pass.
    // Mutation: load the file with set_ca_cert_path in operator mode and the sibling case below
    // answers 200.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path / "l");
    fs::create_directories(tmp.path / "sibling");
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    const auto sibling = gwt::make_leaf(ca, "hc-sibling", true, false);
    write_file(tmp.path / "fullchain.pem", leaf.cert_pem + ca.cert_pem);

    auto srv = tls_server(tmp.path / "l", leaf);
    const auto ok = probe_once(tls_target(srv->port, tmp.path / "fullchain.pem", true));
    CHECK(ok.status == 200);

    auto srv_sibling = tls_server(tmp.path / "sibling", sibling);
    const auto refused =
        probe_once(tls_target(srv_sibling->port, tmp.path / "fullchain.pem", true));
    CHECK(refused.status == 0);
    CHECK(healthcheck_exit_code(refused) == 1);
    CHECK(refused.error.find("verification") != std::string::npos);
    CHECK(refused.error.find("issuer") != std::string::npos);
}

TEST_CASE("healthcheck: operator mode loads exactly one certificate from a two-certificate file",
          "[server][healthcheck][live]") {
    // The trust-store count after a connect: 2 would mean the whole file was loaded.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    write_file(tmp.path / "fullchain.pem", leaf.cert_pem + ca.cert_pem);
    auto srv = tls_server(tmp.path, leaf);

    auto c = make_tls_client(tls_target(srv->port, tmp.path / "fullchain.pem", true));
    c->set_connection_timeout(1, 0);
    c->set_read_timeout(2, 0);
    const auto r = c->Get("/livez");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto* store = SSL_CTX_get_cert_store(static_cast<SSL_CTX*>(c->tls_context()));
    REQUIRE(store != nullptr);
    CHECK(sk_X509_OBJECT_num(X509_STORE_get0_objects(store)) == 1);
    c.reset(); // explicit destroy (httplib 0.37.1 SSLClient destructor workaround)
}

TEST_CASE("healthcheck: an anchor that cannot be loaded fails as a loading error naming the anchor",
          "[server][healthcheck][live]") {
    // Default-CA mode hands the file to httplib (set_ca_cert_path), whose own `SSL certificate
    // loading failed` is the reason. Operator mode never loads a whole file, so it throws the
    // same words itself and run_healthcheck turns that into the one diagnostic line. Either way
    // the reason is a loading error, never a misleading verification failure.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    write_file(tmp.path / "garbage.pem", "this is not a certificate\n");
    // Right markers but half a body: httplib's load_ca_cert_store drops the PEM reader's result,
    // so only the store count turns this into a loading error (not a verification failure).
    {
        const auto& pem = leaf.cert_pem;
        const auto body = pem.find('\n') + 1;
        const auto half = body + (pem.rfind("-----END") - body) / 2;
        write_file(tmp.path / "truncated.pem",
                   pem.substr(0, pem.find('\n', half) + 1) + "-----END CERTIFICATE-----\n");
    }
    auto srv = tls_server(tmp.path, leaf);

    for (const char* name : {"missing.pem", "garbage.pem", "truncated.pem"}) {
        INFO("anchor: " << name);

        const auto t = tls_target(srv->port, tmp.path / name, false);
        const auto out = probe_once(t);
        CHECK(out.status == 0);
        CHECK(out.error.find("loading") != std::string::npos);
        CHECK(healthcheck_diagnostic(t, out).find(name) != std::string::npos);

        const auto op = tls_target(srv->port, tmp.path / name, true);
        CHECK_THROWS_WITH(probe_once(op), ContainsSubstring("SSL certificate loading failed"));
        CHECK(operator_mode_diagnostic(srv->port, op.trust_anchor).find(name) !=
              std::string::npos);
    }

    // Operator mode: a first block that will not decode is a loading error too.
    {
        const auto op = tls_target(srv->port, tmp.path / "truncated.pem", true);
        CHECK_THROWS_WITH(probe_once(op), ContainsSubstring("does not decode"));
        const auto line = operator_mode_diagnostic(srv->port, op.trust_anchor);
        CHECK(line.find("SSL certificate loading failed") != std::string::npos);
        CHECK(line.find("verification") == std::string::npos);
    }

    // The anchor read is bounded at 64 KiB: a valid leaf first, then padding. At exactly the
    // bound it loads and the probe answers 200; one byte over, the file is refused as a loading
    // error (a FIFO or /dev/zero would otherwise hold the probe or its memory).
    {
        constexpr std::size_t kBound = 64 * 1024;
        const auto padded = [&](std::size_t size) {
            std::string content = leaf.cert_pem;
            content.resize(size, '#');
            return content;
        };
        write_file(tmp.path / "at-bound.pem", padded(kBound));
        write_file(tmp.path / "over-bound.pem", padded(kBound + 1));

        const auto at = tls_target(srv->port, tmp.path / "at-bound.pem", true);
        CHECK(probe_once(at).status == 200);

        const auto over = tls_target(srv->port, tmp.path / "over-bound.pem", true);
        CHECK_THROWS_WITH(probe_once(over), ContainsSubstring("larger than 64 KiB"));
        const auto line = operator_mode_diagnostic(srv->port, over.trust_anchor);
        CHECK(line.find("exception: SSL certificate loading failed") != std::string::npos);
    }
}

TEST_CASE("healthcheck: operator mode refuses a first certificate it cannot read as plain - never "
          "the CA behind it",
          "[server][healthcheck][live]") {
    // `openssl x509 -trustout` writes TRUSTED CERTIFICATE, and some tools write X509 CERTIFICATE;
    // the server's own chain loader reads both. Here the leaf carries the alias label and the
    // plain CA follows it. Skipping the leaf would anchor the probe on the CA, and with
    // PARTIAL_CHAIN set and hostname checking off a SIBLING leaf under that CA would pass.
    // The same hole, third spelling: marker text MID-LINE ahead of the CA body. OpenSSL's reader
    // skips that line and reads the real leaf, but a scanner matching the marker anywhere
    // returned the CA body.
    // Mutation: make first_pem_certificate step over the alias block, match a marker that is
    // not at a line start (or fall back to set_ca_cert_path in operator mode) and the sibling
    // answers 200.
    yuzu::test::TempDir tmp{"yuzu_test_healthcheck-"};
    fs::create_directories(tmp.path);
    const auto ca = gwt::make_ca("hc-ca");
    const auto sibling = gwt::make_leaf(ca, "hc-sibling", true, false);
    const auto leaf = gwt::make_leaf(ca, "hc-server", true, false);
    auto srv_sibling = tls_server(tmp.path, sibling);

    const auto relabel = [](std::string pem, const std::string& label) {
        for (const char* edge : {"BEGIN", "END"}) {
            const std::string from = std::string{"-----"} + edge + " CERTIFICATE-----";
            const std::string to = std::string{"-----"} + edge + " " + label + "-----";
            for (auto pos = pem.find(from); pos != std::string::npos; pos = pem.find(from, pos))
                pem.replace(pos, from.size(), to);
        }
        return pem;
    };
    const auto expect_refused = [&](const char* name, const std::string& content) {
        INFO("anchor: " << name);
        const auto anchor = tmp.path / name;
        write_file(anchor, content);

        const auto t = tls_target(srv_sibling->port, anchor, true);
        CHECK_THROWS_WITH(probe_once(t), ContainsSubstring("SSL certificate loading failed"));
        const auto line = operator_mode_diagnostic(srv_sibling->port, anchor);
        CHECK(line.find("exception: SSL certificate loading failed") != std::string::npos);
        CHECK(line.find(name) != std::string::npos);
    };
    for (const char* label : {"X509 CERTIFICATE", "TRUSTED CERTIFICATE"}) {
        INFO("label: " << label);
        expect_refused("alias-anchor.pem", relabel(leaf.cert_pem, label) + ca.cert_pem);
    }
    expect_refused("midline-anchor.pem", "# CA: " + ca.cert_pem + leaf.cert_pem);
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
