/**
 * test_oidc_egress.cpp -- the OIDC egress policy applied to real fetches (#5692).
 *
 * The address classification itself is in test_oidc_egress_policy.cpp. These cases pin what the
 * provider DOES with it: a refused target is never connected to (the loopback mock IdP counts
 * every request it sees, and must see none), the connect goes to the address the policy vetted
 * and not to a second lookup, the refusal text names no address, link-local stays refused with
 * the operator switch on, and an endpoint on another host is vetted when it is used.
 *
 * Names are given answers through OidcProvider::set_resolver_for_test, so no case depends on DNS,
 * on how a platform resolves "localhost", or on an IdP listening on a non-loopback address.
 */

#include "oidc_provider.hpp"
#include "test_oidc_mock_idp.hpp"

#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

// A real httplib acceptor thread crashes the ThreadSanitizer build (#438); see the MockIdp banner.
#ifndef YUZU_OIDC_MOCK_IDP_TSAN

using namespace yuzu::server::oidc;
using yuzu::server::test::MockIdp;

namespace {

constexpr const char* kRefused = "address not permitted";
constexpr const char* kCleartextPublic = "plain http is not permitted to a public address";

/// Gives names an answer for the life of the guard, then restores the OS resolver.
struct ResolverGuard {
    explicit ResolverGuard(OidcProvider::ResolverForTest r) {
        OidcProvider::set_resolver_for_test(std::move(r));
    }
    ~ResolverGuard() { OidcProvider::set_resolver_for_test({}); }
    ResolverGuard(const ResolverGuard&) = delete;
    ResolverGuard& operator=(const ResolverGuard&) = delete;
};

OidcConfig provider_cfg(const std::string& issuer, bool allow_private) {
    OidcConfig cfg;
    cfg.issuer = issuer;
    cfg.client_id = "yuzu-test-client";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    cfg.allow_private_networks = allow_private;
    return cfg;
}

bool names_no_address(const std::string& text) {
    return text.find("127.0.0.1") == std::string::npos &&
           text.find("169.254") == std::string::npos && text.find("10.0.0") == std::string::npos;
}

} // namespace

TEST_CASE("OIDC egress: a loopback IdP is refused by default and sees no request",
          "[oidc][oidc_egress]") {
    MockIdp idp;

    SECTION("discovery") {
        auto doc = OidcProvider::fetch_discovery_document(idp.base(), false, false, 2000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(doc.error()));
        CHECK(idp.discovery_calls.load() == 0);
    }
    SECTION("a plain GET (the JWKS and Test Connection path)") {
        auto body = OidcProvider::http_get_bounded(idp.base() + "/jwks", false, false, 2000);
        REQUIRE_FALSE(body.has_value());
        CHECK(body.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(body.error()));
        CHECK(idp.jwks_calls.load() == 0);
    }
    SECTION("a sign-in start fails closed, stores no flow, and the cause is in the log") {
        OidcProvider provider(provider_cfg(idp.base(), false));
        yuzu::test::LogCapture cap;
        CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
        cap.stop();
        CHECK(idp.discovery_calls.load() == 0);
        CHECK(provider.pending_flow_count_for_test() == 0);
        CHECK(cap.text().find(kRefused) != std::string::npos);
    }
}

TEST_CASE("OIDC egress: with the operator switch on, the same loopback IdP works",
          "[oidc][oidc_egress]") {
    MockIdp idp;
    auto doc = OidcProvider::fetch_discovery_document(idp.base(), false, true, 2000);
    REQUIRE(doc.has_value());
    CHECK(idp.discovery_calls.load() == 1);

    OidcProvider provider(provider_cfg(idp.base(), true));
    const auto flow = provider.start_auth_flow();
    CHECK(flow.url.starts_with(idp.base() + "/authorize?"));
}

TEST_CASE("OIDC egress: link-local and cloud-metadata targets are refused even with the switch on",
          "[oidc][oidc_egress][security]") {
    // IP literals: classified directly, no DNS, so a refusal here proves nothing was connected to
    // (these addresses do not answer in a test environment; a connect would show as a timeout or
    // a connection error, not as the policy text).
    for (const char* issuer :
         {"http://169.254.169.254", "http://169.254.169.254:8080/realms/x", "http://169.254.0.1",
          "http://[fe80::1]", "http://[::ffff:a9fe:a9fe]", "http://[fd00:ec2::254]",
          "http://100.100.100.200", "http://168.63.129.16", "http://0.0.0.0:1", "http://[::]:1",
          "http://224.0.0.1", "http://255.255.255.255"}) {
        CAPTURE(issuer);
        for (const bool allow : {false, true}) {
            auto doc = OidcProvider::fetch_discovery_document(issuer, false, allow, 1000);
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kRefused) != std::string::npos);
            auto body =
                OidcProvider::http_get_bounded(std::string(issuer) + "/jwks", false, allow, 1000);
            REQUIRE_FALSE(body.has_value());
            CHECK(body.error().find(kRefused) != std::string::npos);
        }
    }
}

TEST_CASE("OIDC egress: a real host name goes through the OS resolver, no test seam",
          "[oidc][oidc_egress][security]") {
    // Every other name test installs the resolver seam, so on a platform whose OS resolver
    // needs its own handling (Windows: GetAddrInfoExW with its own list type and deleter) the
    // real path would otherwise never run. "localhost" resolves everywhere without DNS.
    MockIdp idp;
    const std::string issuer = "http://localhost:" + std::to_string(idp.port);
    idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });

    // Loopback is a refused class by default: the name resolves, the answer is classified, and
    // the fetch is refused before any request reaches the mock IdP.
    auto refused = OidcProvider::fetch_discovery_document(issuer, false, false, 5000);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find(kRefused) != std::string::npos);
    CHECK(idp.discovery_calls.load() == 0);

    // With the switch it connects to a pinned loopback address (::1 first on some systems; the
    // mock listens on 127.0.0.1 only, so the second address is the one that works). Windows takes
    // about 2 s to refuse a closed loopback port, hence the generous budget.
    auto allowed = OidcProvider::fetch_discovery_document(issuer, false, true, 10000);
    REQUIRE(allowed.has_value());
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("OIDC egress: a name is resolved, every answer classified, and the connect is pinned",
          "[oidc][oidc_egress][security]") {
    MockIdp idp;
    const std::string issuer = "http://idp.test:" + std::to_string(idp.port);
    idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });

    SECTION("a name that resolves to loopback is refused by default and allowed with the switch") {
        ResolverGuard resolver(
            [](const std::string&) -> std::vector<std::string> { return {"127.0.0.1"}; });
        auto refused = OidcProvider::fetch_discovery_document(issuer, false, false, 2000);
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(refused.error()));
        CHECK(idp.discovery_calls.load() == 0);

        // The OS knows no "idp.test": the request can only succeed because it was PINNED to the
        // address the policy vetted, not because the HTTP client looked the name up again.
        auto allowed = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE(allowed.has_value());
        CHECK(idp.discovery_calls.load() == 1);
    }
    SECTION("a refused answer in a mixed list is skipped, not connected to") {
        ResolverGuard resolver([](const std::string&) -> std::vector<std::string> {
            return {"169.254.169.254", "127.0.0.1"};
        });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE(doc.has_value());
        CHECK(idp.discovery_calls.load() == 1);
    }
    SECTION("an unreachable first address falls through to the next permitted one") {
        ResolverGuard resolver([](const std::string&) -> std::vector<std::string> {
            return {"::1", "127.0.0.1"}; // the mock IdP listens on 127.0.0.1 only
        });
        // Windows takes about 2 s to refuse a connect to a closed loopback port, so the first
        // address alone can use a 2 s budget; give the section room for the second address.
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 10000);
        REQUIRE(doc.has_value());
        CHECK(idp.discovery_calls.load() == 1);
    }
    SECTION("a name that resolves only to link-local is refused with the switch on") {
        ResolverGuard resolver([](const std::string&) -> std::vector<std::string> {
            return {"169.254.169.254", "fe80::1"};
        });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(doc.error()));
        CHECK(idp.discovery_calls.load() == 0);
    }
    SECTION("a name that resolves to a private network address is refused by default") {
        ResolverGuard resolver(
            [](const std::string&) -> std::vector<std::string> { return {"10.0.0.5"}; });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, false, 2000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(doc.error()));
    }
    SECTION("a name that does not resolve is its own fixed failure") {
        ResolverGuard resolver([](const std::string&) -> std::vector<std::string> { return {}; });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find("did not resolve") != std::string::npos);
        CHECK(idp.discovery_calls.load() == 0);
    }
}

TEST_CASE("OIDC egress: plain http to a public address is refused, whatever the operator switch",
          "[oidc][oidc_egress][security]") {
    // No case connects to a public address: every refusal happens before a socket exists, and the
    // https side of the rule is pinned as a pure decision in test_oidc_egress_policy.cpp.
    MockIdp idp;
    const std::string issuer = "http://idp.test:" + std::to_string(idp.port);
    idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });

    SECTION("a name that resolves to a public address is refused with the switch on and off") {
        ResolverGuard resolver(
            [](const std::string&) -> std::vector<std::string> { return {"93.184.216.34"}; });
        for (const bool allow : {false, true}) {
            CAPTURE(allow);
            yuzu::test::LogCapture cap(spdlog::level::warn);
            auto doc = OidcProvider::fetch_discovery_document(issuer, false, allow, 2000);
            cap.stop();
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kCleartextPublic) != std::string::npos);
            CHECK(doc.error().find(kRefused) == std::string::npos);
            CHECK(doc.error().find("93.184.216.34") == std::string::npos);
            CHECK(cap.text().find("plain http") != std::string::npos);
            CHECK(cap.text().find("93.184.216.34") == std::string::npos);
            auto body = OidcProvider::http_get_bounded(issuer + "/jwks", false, allow, 2000);
            REQUIRE_FALSE(body.has_value());
            CHECK(body.error().find(kCleartextPublic) != std::string::npos);
        }
        CHECK(idp.discovery_calls.load() == 0);
        CHECK(idp.jwks_calls.load() == 0);
    }
    SECTION("a public address in a mixed plain-http answer is skipped, not connected to") {
        ResolverGuard resolver([](const std::string&) -> std::vector<std::string> {
            return {"93.184.216.34", "127.0.0.1"};
        });
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE(doc.has_value()); // only the loopback answer was pinned, and the mock saw it
        CHECK(idp.discovery_calls.load() == 1);
    }
    SECTION("a private address over plain http still needs the switch, and works with it") {
        ResolverGuard resolver(
            [](const std::string&) -> std::vector<std::string> { return {"127.0.0.1"}; });
        auto refused = OidcProvider::fetch_discovery_document(issuer, false, false, 2000);
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().find(kRefused) != std::string::npos);
        CHECK(refused.error().find(kCleartextPublic) == std::string::npos);
        CHECK(OidcProvider::fetch_discovery_document(issuer, false, true, 2000).has_value());
    }
    SECTION("an IP literal is refused the same way, with the switch on and off") {
        for (const char* url : {"http://8.8.8.8", "http://8.8.8.8:8080/realms/x",
                                "http://[2606:4700:4700::1111]", "http://[::ffff:808:808]"}) {
            CAPTURE(url);
            for (const bool allow : {false, true}) {
                CAPTURE(allow);
                auto doc = OidcProvider::fetch_discovery_document(url, false, allow, 1000);
                REQUIRE_FALSE(doc.has_value());
                CHECK(doc.error().find(kCleartextPublic) != std::string::npos);
                auto body =
                    OidcProvider::http_get_bounded(std::string(url) + "/jwks", false, allow, 1000);
                REQUIRE_FALSE(body.has_value());
                CHECK(body.error().find(kCleartextPublic) != std::string::npos);
            }
        }
    }
    SECTION("the token POST to a plain-http public endpoint is refused, the secret never sent") {
        idp.with([](MockIdp& m) {
            m.discovery_body = R"({"issuer":")" + m.base() + R"(","authorization_endpoint":")" +
                               m.base() +
                               R"(/authorize","token_endpoint":"http://8.8.8.8/token",)" +
                               R"("jwks_uri":")" + m.base() + R"(/jwks"})";
        });
        const auto cfg = provider_cfg(idp.base(), true);
        OidcProvider provider(cfg);
        const auto flow = provider.start_auth_flow();
        REQUIRE_FALSE(idp.follow_authorize(flow.url).empty());
        auto r = provider.handle_callback("the-code",
                                          yuzu::server::test::url_query_param(flow.url, "state"),
                                          flow.binding_secret);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(kCleartextPublic) != std::string::npos);
        CHECK(idp.token_calls.load() == 0);
    }
}

TEST_CASE("OIDC egress: an endpoint on another host is vetted when it is used, not when the "
          "issuer was",
          "[oidc][oidc_egress][security]") {
    // The issuer is the loopback mock IdP (allowed here), but the document points the signing
    // keys and the token endpoint at the cloud metadata address.
    MockIdp idp;
    idp.with([](MockIdp& m) {
        m.discovery_body = R"({"issuer":")" + m.base() + R"(","authorization_endpoint":")" +
                           m.base() +
                           R"(/authorize","token_endpoint":"http://169.254.169.254/token",)" +
                           R"("jwks_uri":"http://169.254.169.254/jwks"})";
    });
    const auto cfg = provider_cfg(idp.base(), true);
    OidcProvider provider(cfg);
    const auto flow = provider.start_auth_flow(); // the authorization endpoint is on the issuer
    REQUIRE_FALSE(idp.follow_authorize(flow.url).empty());
    CHECK(idp.discovery_calls.load() == 1);

    SECTION("the JWKS fetch is refused") {
        yuzu::test::LogCapture cap;
        const auto jwt = yuzu::server::test::rs256_sign(
            "mock-kid-1", yuzu::server::test::id_token_payload(cfg, "n"));
        auto r = provider.verify_jwt_signature(jwt);
        cap.stop();
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == OidcProvider::kJwksUnavailable);
        CHECK(cap.text().find(kRefused) != std::string::npos);
        CHECK(idp.jwks_calls.load() == 0);
    }
    SECTION("the token POST is refused, so the client secret is never sent") {
        auto r = provider.handle_callback("the-code",
                                          yuzu::server::test::url_query_param(flow.url, "state"),
                                          flow.binding_secret);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(kRefused) != std::string::npos);
        CHECK(names_no_address(r.error()));
        CHECK(idp.token_calls.load() == 0);
    }
}

TEST_CASE("OIDC egress: the provider warns once at construction about an issuer it will refuse "
          "and about a plain-http non-loopback issuer",
          "[oidc][oidc_egress][log_fold]") {
    const auto warnings = [](const OidcConfig& cfg) {
        yuzu::test::LogCapture cap(spdlog::level::warn);
        { OidcProvider provider(cfg); }
        cap.stop();
        return cap.text();
    };

    SECTION("an IP-literal issuer in a switch-gated class names the switch") {
        const auto logs = warnings(provider_cfg("http://10.1.2.3:8080", false));
        CHECK(logs.find("refused class (private)") != std::string::npos);
        CHECK(logs.find("--oidc-allow-private-networks") != std::string::npos);
    }
    SECTION("with the switch on there is no egress warning") {
        const auto logs = warnings(provider_cfg("http://10.1.2.3:8080", true));
        CHECK(logs.find("refused class") == std::string::npos);
    }
    SECTION("a link-local issuer says the class is never allowed") {
        const auto logs = warnings(provider_cfg("https://169.254.169.254", true));
        CHECK(logs.find("refused class (link-local)") != std::string::npos);
        CHECK(logs.find("never allowed") != std::string::npos);
    }
    SECTION("http on a non-loopback host warns that the trust root and the secret are in the "
            "clear") {
        const auto logs = warnings(provider_cfg("http://idp.example.test/realms/x", false));
        CHECK(logs.find("uses http:// on a non-loopback host") != std::string::npos);
        CHECK(logs.find("unencrypted") != std::string::npos);
    }
    SECTION("https, and http on loopback, do not") {
        for (const char* issuer : {"https://idp.example.test", "http://127.0.0.1:1",
                                   "http://localhost:1", "http://[::1]:1"}) {
            CAPTURE(issuer);
            const auto logs = warnings(provider_cfg(issuer, true));
            CHECK(logs.find("non-loopback") == std::string::npos);
        }
    }
    SECTION("the warning folds the issuer it quotes") {
        const auto logs = warnings(provider_cfg("http://idp.example.test/\xE2\x80\xA8x", false));
        CHECK(logs.find("\xE2\x80\xA8") == std::string::npos);
    }
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN
