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

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
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

TEST_CASE("OIDC egress: with the operator switch on - the same loopback IdP works",
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

TEST_CASE("OIDC egress: a real host name goes through the OS resolver - no test seam",
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

TEST_CASE("OIDC egress: a host name the real OS resolver cannot resolve is its own fixed failure",
          "[oidc][oidc_egress]") {
    // RFC 6761: ".invalid" never resolves. This runs the real resolver (the seam is not set), so
    // the failure return of resolve_host_addresses is covered on every platform, with or without
    // a network. A lookup that times out inside the 1 s budget reads the same.
    MockIdp idp;
    auto doc = OidcProvider::fetch_discovery_document("http://yuzu-no-such-host.invalid:1", false,
                                                      true, 1000);
    REQUIRE_FALSE(doc.has_value());
    CHECK(doc.error().find("the host name did not resolve") != std::string::npos);
    CHECK(idp.discovery_calls.load() == 0);
    CHECK(idp.jwks_calls.load() == 0);
}

TEST_CASE("OIDC egress: a name is resolved - every answer classified - and the connect is pinned",
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
    SECTION("control: a mixed list still reaches its permitted address") {
        // A no-regression control, not a proof that the refused address is dropped: an unpinned
        // refused address would fail its connect and fall through to the permitted one, so this
        // stays green either way. The proof is the single-class sections (a link-local-only answer
        // below is refused with nothing connected). No refusal is logged here: the provider logs
        // one only when no permitted address is left, so there is no log line to assert.
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

TEST_CASE("OIDC egress: plain http to a public address is refused - whatever the operator switch",
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
    SECTION("control: a public address in a mixed plain-http answer leaves the permitted one") {
        // A no-regression control (see the mixed-list control above): the discriminators are the
        // public-only sections, which are refused with the cleartext reason before any socket.
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

TEST_CASE("OIDC egress: an endpoint on another host is vetted when it is used - not when the "
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
    SECTION("a plain-http issuer at a public IP literal is a refused class, switch or not") {
        for (const bool allow : {false, true}) {
            CAPTURE(allow);
            const auto logs = warnings(provider_cfg("http://8.8.8.8:8080", allow));
            CHECK(logs.find("refused class (public)") != std::string::npos);
            CHECK(logs.find("plain http to a public address is never allowed") !=
                  std::string::npos);
            CHECK(logs.find("unless the server runs with") == std::string::npos);
        }
        // Control: the same address over https is not a refused class.
        CHECK(warnings(provider_cfg("https://8.8.8.8", false)).find("refused class") ==
              std::string::npos);
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

// ── NAT64 network-specific prefixes (RFC 6052 / RFC 7050) ────────────────────────────────────
//
// The addresses below were derived with a separate bit-level implementation of RFC 6052 (see
// test_oidc_egress_policy.cpp). "doc" prefixes sit in 2001:db8::/32, which the policy treats as
// non-global on its own, so a case that wants the address ALLOWED with the operator switch on can
// still tell "decoded" from "not decoded" by the answer; "pub" prefixes sit in global space and are
// used over https with the default switch, where every case is refused before a socket exists.
// Nothing here connects to a routable address.

namespace {

struct Nat64Net {
    const char* label;
    const char* prefix;       // text for parse_nat64_prefix
    const char* probe_answer; // the AAAA answer for ipv4only.arpa (192.0.0.170 embedded)
    const char* link_local;   // 169.254.169.254 embedded
    const char* priv;         // 10.0.0.5 embedded
    const char* pub;          // 8.8.8.8 embedded
};

const Nat64Net kDoc64{"doc/64",
                      "2001:db8:122:344::/64",
                      "2001:db8:122:344:c0:0:aa00:0",
                      "2001:db8:122:344:a9:fea9:fe00:0",
                      "2001:db8:122:344:a:0:500:0",
                      "2001:db8:122:344:8:808:800:0"};
const Nat64Net kDoc96{"doc/96",
                      "2001:db8:122:344:5566:7788::/96",
                      "2001:db8:122:344:5566:7788:c000:aa",
                      "2001:db8:122:344:5566:7788:a9fe:a9fe",
                      "2001:db8:122:344:5566:7788:a00:5",
                      "2001:db8:122:344:5566:7788:808:808"};
const Nat64Net kPub64{"pub/64",
                      "2a0e:b107:122:344::/64",
                      "2a0e:b107:122:344:c0:0:aa00:0",
                      "2a0e:b107:122:344:a9:fea9:fe00:0",
                      "2a0e:b107:122:344:a:0:500:0",
                      "2a0e:b107:122:344:8:808:800:0"};
const Nat64Net kPub96{"pub/96",
                      "2a0e:b107:122:344:5566:7788::/96",
                      "2a0e:b107:122:344:5566:7788:c000:aa",
                      "2a0e:b107:122:344:5566:7788:a9fe:a9fe",
                      "2a0e:b107:122:344:5566:7788:a00:5",
                      "2a0e:b107:122:344:5566:7788:808:808"};

/// Names resolve to `target`; `ipv4only.arpa` resolves to `probe_answer`. `probes` counts the
/// ipv4only.arpa lookups (the RFC 7050 discovery), so a case can prove it did or did not happen.
OidcProvider::ResolverForTest nat64_resolver(std::atomic<int>& probes,
                                             std::vector<std::string> target,
                                             std::vector<std::string> probe_answer) {
    return [&probes, target = std::move(target),
            probe_answer = std::move(probe_answer)](const std::string& host) {
        if (host == "ipv4only.arpa") {
            probes.fetch_add(1);
            return probe_answer;
        }
        return target;
    };
}

/// The discovery cache is process-wide: every case starts and ends with it empty.
struct Nat64CacheReset {
    Nat64CacheReset() { OidcProvider::clear_nat64_discovery_cache_for_test(); }
    ~Nat64CacheReset() { OidcProvider::clear_nat64_discovery_cache_for_test(); }
    Nat64CacheReset(const Nat64CacheReset&) = delete;
    Nat64CacheReset& operator=(const Nat64CacheReset&) = delete;
};

std::string warnings_of(const std::function<void()>& body) {
    yuzu::test::LogCapture cap(spdlog::level::warn);
    body();
    cap.stop();
    return cap.text();
}

} // namespace

TEST_CASE("OIDC egress NAT64: a prefix learned from ipv4only.arpa - Pref64 plus a metadata "
          "address is refused with the switch on",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    for (const Nat64Net* net : {&kDoc64, &kDoc96}) {
        CAPTURE(net->label);
        Nat64CacheReset cache;
        MockIdp idp;
        const std::string issuer = "http://idp.test:" + std::to_string(idp.port);
        idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });
        std::atomic<int> probes{0};
        ResolverGuard resolver(nat64_resolver(probes, {net->link_local}, {net->probe_answer}));

        const auto logs = warnings_of([&] {
            auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kRefused) != std::string::npos);
            CHECK(names_no_address(doc.error()));
            CHECK(doc.error().find("a9fe") == std::string::npos);
        });
        // Classified by the embedded address, not as "documentation": link-local, never allowed.
        CHECK(logs.find("link-local address (never allowed)") != std::string::npos);
        CHECK(idp.discovery_calls.load() == 0);
        CHECK(probes.load() == 1);

        // The JWKS path is the same function.
        auto body = OidcProvider::http_get_bounded(issuer + "/jwks", false, true, 2000);
        REQUIRE_FALSE(body.has_value());
        CHECK(body.error().find(kRefused) != std::string::npos);
        CHECK(idp.jwks_calls.load() == 0);
        CHECK(probes.load() == 1); // from the cache
    }
}

TEST_CASE("OIDC egress NAT64: a learned prefix over https - every embedded class, no connect",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    namespace egress = yuzu::server::oidc::egress;
    for (const Nat64Net* net : {&kPub64, &kPub96}) {
        CAPTURE(net->label);
        Nat64CacheReset cache;
        std::atomic<int> probes{0};
        const std::string issuer = "https://idp.test";

        SECTION("link-local is refused with the switch on and off") {
            ResolverGuard resolver(nat64_resolver(probes, {net->link_local}, {net->probe_answer}));
            for (const bool allow : {false, true}) {
                CAPTURE(allow);
                const auto logs = warnings_of([&] {
                    auto doc = OidcProvider::fetch_discovery_document(issuer, false, allow, 2000);
                    REQUIRE_FALSE(doc.has_value());
                    CHECK(doc.error().find(kRefused) != std::string::npos);
                    CHECK(names_no_address(doc.error()));
                });
                CHECK(logs.find("link-local address (never allowed)") != std::string::npos);
            }
            CHECK(probes.load() == 1);
        }
        SECTION("a private destination is refused by default and named as private") {
            ResolverGuard resolver(nat64_resolver(probes, {net->priv}, {net->probe_answer}));
            const auto logs = warnings_of([&] {
                auto doc = OidcProvider::fetch_discovery_document(issuer, false, false, 2000);
                REQUIRE_FALSE(doc.has_value());
                CHECK(doc.error().find(kRefused) != std::string::npos);
            });
            CHECK(
                logs.find("private address (permitted only with --oidc-allow-private-networks)") !=
                std::string::npos);
        }
        SECTION("a public destination is public: allowed over https, refused over plain http") {
            // The decision, not a connect: nothing may reach a public address from a test.
            const auto prefix = egress::parse_nat64_prefix(net->prefix);
            REQUIRE(prefix.has_value());
            const std::array<egress::Nat64Prefix, 1> extra{*prefix};
            const auto addr = egress::parse_ipv6(net->pub);
            REQUIRE(addr.has_value());
            const auto cls = egress::classify_ipv6(*addr, extra);
            CHECK(cls == egress::AddressClass::Public);
            CHECK(egress::decision(cls, false, /*cleartext=*/false) == egress::Verdict::Allow);
            CHECK(egress::decision(cls, false, /*cleartext=*/true) == egress::Verdict::Refuse);

            ResolverGuard resolver(nat64_resolver(probes, {net->pub}, {net->probe_answer}));
            auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, true, 2000);
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kCleartextPublic) != std::string::npos);
        }
    }
}

TEST_CASE("OIDC egress NAT64: no ipv4only.arpa answer - the translator stays invisible "
          "(documented residual)",
          "[oidc][oidc_egress][oidc_nat64]") {
    Nat64CacheReset cache;
    std::atomic<int> probes{0};
    SECTION("no answer at all, or only A records") {
        for (const std::vector<std::string>& answer :
             {std::vector<std::string>{}, std::vector<std::string>{"192.0.0.170", "192.0.0.171"}}) {
            Nat64CacheReset again;
            ResolverGuard resolver(nat64_resolver(probes, {kDoc64.link_local}, answer));
            // 500 ms: the address is documentation space (RFC 3849), the connect cannot succeed.
            auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500);
            REQUIRE_FALSE(doc.has_value());
            // Not refused by the policy (it is "documentation", allowed by the switch): the
            // request was attempted and failed to connect.
            CHECK(doc.error().find(kRefused) == std::string::npos);
            CHECK(doc.error().find("did not resolve") == std::string::npos);
        }
        CHECK(probes.load() == 2);
    }
    SECTION("the control: the same name WITH the answer is refused") {
        ResolverGuard resolver(nat64_resolver(probes, {kDoc64.link_local}, {kDoc64.probe_answer}));
        auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) != std::string::npos);
    }
    SECTION("an answer that is not a plausible prefix is ignored") {
        ResolverGuard resolver(
            nat64_resolver(probes, {kDoc64.link_local}, {"2001:db8::1", "2a0e:b107::808:808"}));
        auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) == std::string::npos);
    }
}

TEST_CASE("OIDC egress NAT64: discovery is cached - a miss for a minute, a hit for ten",
          "[oidc][oidc_egress][oidc_nat64]") {
    Nat64CacheReset cache;
    std::atomic<int> probes{0};
    const auto fetch = [] {
        return OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500);
    };

    SECTION("an empty answer is remembered") {
        ResolverGuard resolver(nat64_resolver(probes, {kDoc64.link_local}, {}));
        (void)fetch();
        (void)fetch();
        (void)fetch();
        CHECK(probes.load() == 1);
        OidcProvider::clear_nat64_discovery_cache_for_test();
        (void)fetch();
        CHECK(probes.load() == 2);
    }
    SECTION("a learned prefix is remembered") {
        ResolverGuard resolver(nat64_resolver(probes, {kDoc64.link_local}, {kDoc64.probe_answer}));
        for (int i = 0; i < 3; ++i) {
            auto doc = fetch();
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kRefused) != std::string::npos);
        }
        CHECK(probes.load() == 1);
        OidcProvider::clear_nat64_discovery_cache_for_test();
        (void)fetch();
        CHECK(probes.load() == 2);
    }
}

TEST_CASE("OIDC egress NAT64: an operator-configured prefix works without any discovery",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    namespace egress = yuzu::server::oidc::egress;
    Nat64CacheReset cache;
    std::atomic<int> probes{0};
    const auto prefixes = egress::parse_nat64_prefix_list(std::string(kDoc64.prefix) + "," +
                                                          std::string(kDoc96.prefix));
    REQUIRE(prefixes.has_value());

    SECTION("the static fetches") {
        ResolverGuard resolver(nat64_resolver(probes, {kDoc96.link_local}, {}));
        const auto logs = warnings_of([&] {
            auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, true, 2000,
                                                              *prefixes);
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kRefused) != std::string::npos);
            auto body = OidcProvider::http_get_bounded("http://idp.test/jwks", false, true, 2000,
                                                       *prefixes);
            REQUIRE_FALSE(body.has_value());
            CHECK(body.error().find(kRefused) != std::string::npos);
        });
        CHECK(logs.find("link-local address (never allowed)") != std::string::npos);
        CHECK(probes.load() == 0); // refused by the configured prefix: nothing to look up
    }
    SECTION("a provider built with the prefixes") {
        MockIdp idp;
        const std::string issuer = "http://idp.test:" + std::to_string(idp.port);
        idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });
        ResolverGuard resolver(nat64_resolver(probes, {kDoc64.link_local}, {}));
        auto cfg = provider_cfg(issuer, true);
        cfg.nat64_prefixes = *prefixes;
        OidcProvider provider(std::move(cfg));
        yuzu::test::LogCapture cap;
        CHECK_THROWS_AS(provider.start_auth_flow(), std::runtime_error);
        cap.stop();
        CHECK(cap.text().find("link-local address (never allowed)") != std::string::npos);
        CHECK(idp.discovery_calls.load() == 0);
        CHECK(provider.pending_flow_count_for_test() == 0);

        // The same provider without them does not recognize the address.
        OidcProvider bare(provider_cfg(issuer, true));
        yuzu::test::LogCapture cap2;
        CHECK_THROWS_AS(bare.start_auth_flow(), std::runtime_error);
        cap2.stop();
        CHECK(cap2.text().find(kRefused) == std::string::npos);
    }
    SECTION("a destination the prefix makes private still needs the operator switch") {
        ResolverGuard resolver(nat64_resolver(probes, {kDoc64.priv}, {}));
        // The doc prefix is non-global on its own, so the switch alone would allow it; decoded, the
        // class is "private" and the answer for the default switch stays refused. (The switch-on
        // answer is a connect attempt to documentation space, which is not asserted here.)
        const auto logs = warnings_of([&] {
            auto doc = OidcProvider::fetch_discovery_document("http://idp.test", false, false, 2000,
                                                              *prefixes);
            REQUIRE_FALSE(doc.has_value());
            CHECK(doc.error().find(kRefused) != std::string::npos);
        });
        CHECK(logs.find("private address (permitted only with") != std::string::npos);
    }
}

TEST_CASE("OIDC egress NAT64: an IPv6 literal host is decoded too",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    Nat64CacheReset cache;
    std::atomic<int> probes{0};
    ResolverGuard resolver(nat64_resolver(probes, {}, {kDoc64.probe_answer}));
    const std::string issuer = std::string("http://[") + kDoc64.link_local + "]:1";
    auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
    REQUIRE_FALSE(doc.has_value());
    CHECK(doc.error().find(kRefused) != std::string::npos);
    CHECK(probes.load() == 1);
}

TEST_CASE("OIDC egress NAT64: the lookup is only made for an IPv6 address that would be permitted",
          "[oidc][oidc_egress][oidc_nat64]") {
    Nat64CacheReset cache;
    std::atomic<int> probes{0};
    MockIdp idp;
    const std::string issuer = "http://idp.test:" + std::to_string(idp.port);
    idp.with([&](MockIdp& m) { m.discovery_issuer = issuer; });

    SECTION("an IPv4-only fetch never looks up ipv4only.arpa") {
        ResolverGuard resolver(nat64_resolver(probes, {"127.0.0.1"}, {kDoc64.probe_answer}));
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE(doc.has_value());
        CHECK(idp.discovery_calls.load() == 1);
        // An IPv4 literal host and a refused IPv4 answer do not either.
        auto literal = OidcProvider::http_get_bounded(idp.base() + "/jwks", false, true, 2000);
        REQUIRE(literal.has_value());
        auto refused = OidcProvider::fetch_discovery_document(issuer, false, false, 2000);
        REQUIRE_FALSE(refused.has_value());
        CHECK(probes.load() == 0);
    }
    SECTION("an IPv6 address the built-in rules already refuse is not looked up either") {
        ResolverGuard resolver(
            nat64_resolver(probes, {"fe80::1", "fd00:ec2::254"}, {kDoc64.probe_answer}));
        auto doc = OidcProvider::fetch_discovery_document(issuer, false, true, 2000);
        REQUIRE_FALSE(doc.has_value());
        CHECK(doc.error().find(kRefused) != std::string::npos);
        CHECK(probes.load() == 0);
    }
    SECTION("an IPv6 address that would be pinned is looked up once") {
        ResolverGuard resolver(nat64_resolver(probes, {"::1"}, {}));
        (void)OidcProvider::fetch_discovery_document(issuer, false, true, 500);
        (void)OidcProvider::fetch_discovery_document(issuer, false, true, 500);
        CHECK(probes.load() == 1);
    }
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN
