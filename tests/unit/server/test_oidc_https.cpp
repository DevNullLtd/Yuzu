/**
 * test_oidc_https.cpp -- OIDC discovery and JWKS fetches over TLS (#5692).
 *
 * Every other OIDC case reaches its IdP over plain http on loopback. These cases serve the
 * discovery document and the JWKS from an httplib::SSLServer whose leaf certificate is signed by
 * a throwaway CA the client does not trust (the shape of a self-signed IdP), and pin two things:
 *
 *  - certificate verification is honored: `skip_tls_verify=false` refuses the IdP and adopts
 *    nothing, `skip_tls_verify=true` goes through (the flag is observed, not just plumbed);
 *  - the https fetch works from an httplib WORKER thread and from a bare std::thread. The
 *    Windows token POST uses WinHTTP because httplib's OpenSSL client was once found failing from
 *    handler threads there; discovery and the JWKS fetch use that client on every platform, so
 *    this is the case that says whether sign-in works against an https IdP on Windows. Run it
 *    alone with `yuzu_server_tests '[https_handler_thread]'`. It is deliberately NOT skipped or
 *    weakened on any platform.
 *
 * The certificate material is the gateway-peer fixtures (`gateway_peer_test_pki.hpp`).
 */

#include "oidc_provider.hpp"
#include "test_oidc_mock_idp.hpp" // jwks_json, and the ThreadSanitizer guard macro

#include "gateway_peer_test_pki.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

// A real httplib acceptor thread crashes the ThreadSanitizer build (#438); see the MockIdp banner.
#ifndef YUZU_OIDC_MOCK_IDP_TSAN

using namespace yuzu::server::oidc;

namespace {

/// An https IdP on loopback serving a discovery document and a one-key JWKS, every endpoint an
/// https URL on its own origin. The leaf is NOT trusted by the system store.
struct TlsIdp {
    yuzu::test::TempDir tmp{"yuzu_test_oidc_https_"};
    std::unique_ptr<httplib::SSLServer> svr;
    std::thread thread;
    int port{0};
    std::atomic<int> discovery_calls{0};
    std::atomic<int> jwks_calls{0};

    TlsIdp() {
        std::filesystem::create_directories(tmp.path);
        const auto ca = yuzu::test::gwpeer::make_ca("OidcTlsTestCa");
        const auto leaf = yuzu::test::gwpeer::make_gateway_leaf(ca); // SAN 127.0.0.1, serverAuth
        const auto cert_path = tmp.path / "idp.crt";
        const auto key_path = tmp.path / "idp.key";
        write(cert_path, leaf.cert_pem);
        write(key_path, leaf.key_pem);
        svr = std::make_unique<httplib::SSLServer>(cert_path.string().c_str(),
                                                   key_path.string().c_str());
        REQUIRE(svr->is_valid());
        svr->Get(R"(.*/\.well-known/openid-configuration)",
                 [this](const httplib::Request&, httplib::Response& res) {
                     discovery_calls.fetch_add(1);
                     res.set_content(R"({"issuer":")" + base() + R"(","authorization_endpoint":")" +
                                         base() + R"(/authorize","token_endpoint":")" + base() +
                                         R"(/token","jwks_uri":")" + base() + R"(/jwks"})",
                                     "application/json");
                 });
        svr->Get("/jwks", [this](const httplib::Request&, httplib::Response& res) {
            jwks_calls.fetch_add(1);
            res.set_content(yuzu::server::test::jwks_json("tls-kid"), "application/json");
        });
        // The shared RSA key is generated on this thread: the first call may otherwise run on a
        // handler thread (and REQUIRE is not safe there).
        (void)yuzu::server::test::shared_rsa_key();
        port = svr->bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        thread = std::thread([this] { svr->listen_after_bind(); });
        svr->wait_until_ready();
    }
    ~TlsIdp() {
        svr->stop();
        if (thread.joinable())
            thread.join();
    }
    TlsIdp(const TlsIdp&) = delete;
    TlsIdp& operator=(const TlsIdp&) = delete;

    std::string base() const { return "https://127.0.0.1:" + std::to_string(port); }

private:
    static void write(const std::filesystem::path& p, const std::string& text) {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f << text;
        REQUIRE(f.good());
    }
};

/// What one thread saw when it fetched the discovery document and then the JWKS it names.
/// Filled on a thread where REQUIRE is not safe, asserted by the test thread.
struct FetchOutcome {
    bool discovery_ok{false};
    std::string discovery_error;
    bool jwks_ok{false};
    std::string jwks_error;
    std::size_t jwks_keys{0};
    bool ran{false};
};

FetchOutcome fetch_discovery_then_jwks(const std::string& issuer) {
    FetchOutcome out;
    auto doc = OidcProvider::fetch_discovery_document(issuer, /*skip_tls_verify=*/true, 5000);
    out.discovery_ok = doc.has_value();
    if (!doc) {
        out.discovery_error = doc.error();
        out.ran = true;
        return out;
    }
    auto body = OidcProvider::http_get_bounded(doc->jwks_uri, /*skip_tls_verify=*/true, 5000);
    if (!body) {
        out.jwks_error = body.error();
        out.ran = true;
        return out;
    }
    auto keys = OidcProvider::parse_jwks(*body);
    out.jwks_ok = keys.has_value();
    out.jwks_keys = keys ? keys->size() : 0;
    if (!keys)
        out.jwks_error = keys.error();
    out.ran = true;
    return out;
}

void check_fetched(const FetchOutcome& out) {
    REQUIRE(out.ran);
    INFO("discovery error: " << out.discovery_error);
    CHECK(out.discovery_ok);
    INFO("jwks error: " << out.jwks_error);
    CHECK(out.jwks_ok);
    CHECK(out.jwks_keys == 1);
}

} // namespace

TEST_CASE("OIDC https: certificate verification is honored, and skip_tls_verify opts out of it",
          "[oidc][oidc_discovery][oidc_https][security]") {
    TlsIdp idp;

    SECTION(
        "verification on: an IdP whose certificate is not trusted is refused, nothing adopted") {
        auto doc =
            OidcProvider::fetch_discovery_document(idp.base(), /*skip_tls_verify=*/false, 5000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().starts_with("request failed: "));
        CHECK(doc.error().find("SSL") != std::string::npos); // a TLS error, not a refused connect
        CHECK(idp.discovery_calls.load() == 0);              // the handshake never completed

        // The same through the provider: sign-in is refused and no endpoint is adopted.
        OidcConfig cfg;
        cfg.issuer = idp.base();
        cfg.client_id = "yuzu-test-client";
        cfg.redirect_uri = "https://yuzu.example.test/auth/callback";
        cfg.skip_tls_verify = false;
        OidcProvider provider(cfg);
        try {
            (void)provider.start_auth_flow();
            FAIL("start_auth_flow must not succeed against an untrusted certificate");
        } catch (const std::runtime_error& e) {
            CHECK(std::string(e.what()) == OidcProvider::kDiscoveryUnavailable);
        }
        CHECK(provider.pending_flow_count_for_test() == 0);
        CHECK(idp.discovery_calls.load() == 0);
        auto jwks = OidcProvider::http_get_bounded(idp.base() + "/jwks", false, 5000);
        CHECK_FALSE(jwks.has_value());
        CHECK(idp.jwks_calls.load() == 0);
    }
    SECTION("verification off: the same IdP is accepted and its document adopted") {
        auto doc =
            OidcProvider::fetch_discovery_document(idp.base(), /*skip_tls_verify=*/true, 5000);
        REQUIRE(doc.has_value());
        CHECK(doc->jwks_uri == idp.base() + "/jwks");
        CHECK(idp.discovery_calls.load() == 1);

        OidcConfig cfg;
        cfg.issuer = idp.base();
        cfg.client_id = "yuzu-test-client";
        cfg.redirect_uri = "https://yuzu.example.test/auth/callback";
        cfg.skip_tls_verify = true;
        OidcProvider provider(cfg);
        const auto flow = provider.start_auth_flow();
        CHECK(flow.url.starts_with(idp.base() + "/authorize?"));
    }
}

// The decisive Windows question (#5692 CH-5a): does the https fetch work from an httplib worker
// thread, the context every sign-in request runs in? Both legs must pass on every platform.
TEST_CASE("OIDC https: discovery and JWKS fetches work from an httplib handler thread and from a "
          "bare thread",
          "[oidc][oidc_discovery][https_handler_thread]") {
    TlsIdp idp;

    SECTION("from a bare std::thread") {
        FetchOutcome out;
        std::thread t([&] { out = fetch_discovery_then_jwks(idp.base()); });
        t.join();
        check_fetched(out);
        CHECK(idp.discovery_calls.load() == 1);
        CHECK(idp.jwks_calls.load() == 1);
    }

    SECTION("from inside a handler of an httplib::Server (an httplib worker thread)") {
        FetchOutcome out;
        std::mutex mu;
        httplib::Server outer;
        outer.Get("/run", [&](const httplib::Request&, httplib::Response& res) {
            auto result = fetch_discovery_then_jwks(idp.base());
            {
                std::lock_guard lk(mu);
                out = std::move(result);
            }
            res.set_content("done", "text/plain");
        });
        const int outer_port = outer.bind_to_any_port("127.0.0.1");
        REQUIRE(outer_port > 0);
        std::thread serve([&] { outer.listen_after_bind(); });
        outer.wait_until_ready();

        httplib::Client cli("127.0.0.1", outer_port);
        cli.set_read_timeout(30, 0); // the handler does two TLS fetches; bound a hang, not a pass
        auto r = cli.Get("/run");
        outer.stop();
        serve.join();
        REQUIRE(r);
        CHECK(r->status == 200);

        std::lock_guard lk(mu);
        check_fetched(out);
        CHECK(idp.discovery_calls.load() == 1);
        CHECK(idp.jwks_calls.load() == 1);
    }
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN
