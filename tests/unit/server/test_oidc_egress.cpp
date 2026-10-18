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
#include <condition_variable>
#include <format>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
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

// ── Learned NAT64 prefixes: they only grow, and a set that does not fit is a refusal ─────────

namespace {

/// The ipv4only.arpa AAAA answer that teaches `2001:db8:<n>::/96` (documentation space: the base
/// class is non-global, so `allow_private` lets the lookup happen and nothing leaves the host).
std::string learn_answer(int n) {
    return std::format("2001:db8:{:x}::c000:aa", n);
}
/// 169.254.169.254 inside the prefix learned from `learn_answer(n)`.
std::string metadata_under(int n) {
    return std::format("2001:db8:{:x}::a9fe:a9fe", n);
}

/// A resolver whose ipv4only.arpa answer changes between lookups; other names resolve through
/// `targets` (host -> address), or to a documentation-space address no prefix covers.
struct ScriptedDns {
    std::mutex mu;
    std::vector<std::string> answer;
    std::vector<std::pair<std::string, std::string>> targets;
    int probes{0};

    void set_answer(std::vector<std::string> a) {
        std::lock_guard lock(mu);
        answer = std::move(a);
    }
    int probe_count() {
        std::lock_guard lock(mu);
        return probes;
    }
    OidcProvider::ResolverForTest resolver() {
        return [this](const std::string& host) -> std::vector<std::string> {
            std::lock_guard lock(mu);
            if (host == "ipv4only.arpa") {
                ++probes;
                return answer;
            }
            for (const auto& [name, address] : targets)
                if (name == host)
                    return {address};
            return {"2001:db8:ffff::1"};
        };
    }
};

/// True when a fetch of `host` (http, switch on) is refused by the egress policy.
bool refused_by_policy(const std::string& host) {
    auto doc = OidcProvider::fetch_discovery_document("http://" + host, false, true, 500);
    return !doc.has_value() && doc.error().find(kRefused) != std::string::npos;
}

std::string error_of(const std::string& host) {
    auto doc = OidcProvider::fetch_discovery_document("http://" + host, false, true, 500);
    return doc.has_value() ? std::string{} : doc.error();
}

} // namespace

TEST_CASE("OIDC egress NAT64: more than eight learned prefixes are ALL honored",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    Nat64CacheReset cache;
    ScriptedDns dns;
    std::vector<std::string> answers;
    for (int n = 1; n <= 9; ++n)
        answers.push_back(learn_answer(n));
    dns.set_answer(answers);
    for (int n : {1, 8, 9}) // the first, the old cap's last, and the one past it
        dns.targets.emplace_back(std::format("t{}.test", n), metadata_under(n));
    ResolverGuard resolver(dns.resolver());

    // The ninth prefix is the one the old cap of eight dropped: its metadata address was then
    // plain documentation space, allowed with the switch on.
    for (int n : {1, 8, 9}) {
        CAPTURE(n);
        CHECK(refused_by_policy(std::format("t{}.test", n)));
    }
    CHECK(dns.probe_count() == 1);
}

TEST_CASE("OIDC egress NAT64: 64 learned prefixes fit, 65 refuse the fetch - never a partial set",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    Nat64CacheReset cache;
    ScriptedDns dns;
    dns.targets.emplace_back("t64.test", metadata_under(64));
    dns.targets.emplace_back("t65.test", metadata_under(65));
    ResolverGuard resolver(dns.resolver());
    const auto answers_up_to = [](int count) {
        std::vector<std::string> a;
        for (int n = 1; n <= count; ++n)
            a.push_back(learn_answer(n));
        return a;
    };

    SECTION("64 is the bound and fits") {
        dns.set_answer(answers_up_to(64));
        CHECK(refused_by_policy("t64.test"));
        CHECK(error_of("t64.test").find(OidcProvider::kEgressNat64Overflow) == std::string::npos);
    }
    SECTION("65 distinct prefixes: the fetch fails closed with its own fixed reason") {
        dns.set_answer(answers_up_to(65));
        const auto logs = warnings_of([&] {
            const auto err = error_of("t65.test");
            CHECK(err.find(OidcProvider::kEgressNat64Overflow) != std::string::npos);
            CHECK(names_no_address(err));
            CHECK(err.find("2001:db8") == std::string::npos);
        });
        CHECK(logs.find("would exceed 64 learned prefixes") != std::string::npos);
        // Even a target no prefix covers is refused (the decision needs a complete set), and the
        // overflow is remembered while the cache is fresh (no second lookup).
        CHECK(error_of("unrelated.test").find(OidcProvider::kEgressNat64Overflow) !=
              std::string::npos);
        CHECK(dns.probe_count() == 1);

        // It heals: once an answer fits again the fetch is classified normally.
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer(answers_up_to(3));
        CHECK(error_of("unrelated.test").find(OidcProvider::kEgressNat64Overflow) ==
              std::string::npos);
        CHECK(dns.probe_count() == 2);
    }
    SECTION("the union counts: 64 known plus one new prefix overflows, and the 64 are kept") {
        dns.set_answer(answers_up_to(64));
        REQUIRE(refused_by_policy("t64.test"));
        OidcProvider::expire_nat64_discovery_cache_for_test();
        auto more = answers_up_to(64);
        more.push_back(learn_answer(65));
        dns.set_answer(more);
        CHECK(error_of("t65.test").find(OidcProvider::kEgressNat64Overflow) != std::string::npos);
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer(answers_up_to(64)); // back to a fitting answer: the earlier set is intact
        CHECK(refused_by_policy("t64.test"));
        CHECK(dns.probe_count() == 3);
    }
}

TEST_CASE("OIDC egress NAT64: a learned prefix is never forgotten by a later answer",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    Nat64CacheReset cache;
    ScriptedDns dns;
    dns.targets.emplace_back("p1.test", metadata_under(1));
    dns.targets.emplace_back("p2.test", metadata_under(2));
    ResolverGuard resolver(dns.resolver());

    dns.set_answer({learn_answer(1)});
    REQUIRE(refused_by_policy("p1.test"));
    CHECK_FALSE(refused_by_policy("p2.test")); // not learned yet (a connect to doc space fails)
    CHECK(dns.probe_count() == 1);

    SECTION("an empty answer") {
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer({});
        CHECK(refused_by_policy("p1.test"));
        CHECK(dns.probe_count() == 2); // it really did look again
    }
    SECTION("an answer with only A records") {
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer({"192.0.0.170", "192.0.0.171"});
        CHECK(refused_by_policy("p1.test"));
        CHECK(dns.probe_count() == 2);
    }
    SECTION("a different prefix adds to the set and removes nothing") {
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer({learn_answer(2)});
        CHECK(refused_by_policy("p2.test"));
        CHECK(refused_by_policy("p1.test"));
        CHECK(dns.probe_count() == 2);
        // ... and an empty answer after that still keeps both.
        OidcProvider::expire_nat64_discovery_cache_for_test();
        dns.set_answer({});
        CHECK(refused_by_policy("p1.test"));
        CHECK(refused_by_policy("p2.test"));
        CHECK(dns.probe_count() == 3);
    }
}

TEST_CASE("OIDC egress NAT64: two concurrent refreshes cannot lose an entry",
          "[oidc][oidc_egress][oidc_nat64][security]") {
    Nat64CacheReset cache;
    std::mutex mu;
    std::condition_variable cv;
    int arrived = 0;
    // Both ipv4only.arpa lookups are held until BOTH are in flight, so each refresh computes its
    // answer without knowing the other's; then each writes. A last-writer-wins cache keeps one.
    ResolverGuard resolver([&](const std::string& host) -> std::vector<std::string> {
        if (host == "p1.test")
            return {metadata_under(1)};
        if (host == "p2.test")
            return {metadata_under(2)};
        if (host != "ipv4only.arpa")
            return {"2001:db8:ffff::1"};
        std::unique_lock lock(mu);
        const int me = arrived++;
        cv.notify_all();
        cv.wait_for(lock, std::chrono::seconds(10), [&] { return arrived >= 2; });
        if (me == 0)
            return {learn_answer(1)};
        if (me == 1)
            return {learn_answer(2)};
        return {};
    });

    std::thread a(
        [] { (void)OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500); });
    std::thread b(
        [] { (void)OidcProvider::fetch_discovery_document("http://idp.test", false, true, 500); });
    a.join();
    b.join();
    {
        std::lock_guard lock(mu);
        REQUIRE(arrived == 2); // both really refreshed concurrently
    }
    CHECK(refused_by_policy("p1.test"));
    CHECK(refused_by_policy("p2.test"));
}

TEST_CASE("OIDC egress: the strict vet mode refuses a mixed answer the pinning mode pins",
          "[oidc][oidc_egress][security]") {
    Nat64CacheReset cache;
    const std::string refused_text = OidcProvider::kEgressRefused;
    const auto vet = [](std::vector<std::string> answer, bool allow_private, bool strict,
                        const std::string& host = "mixed.test") {
        ResolverGuard resolver([answer = std::move(answer)](const std::string&) { return answer; });
        return OidcProvider::vet_egress_target_for_test(host, allow_private, false, 1000, {},
                                                        strict);
    };

    SECTION("link-local plus a public address") {
        const auto pinned = vet({"169.254.169.254", "8.8.8.8"}, false, false);
        REQUIRE(pinned.has_value());
        CHECK(*pinned == std::vector<std::string>{"8.8.8.8"}); // the refused one is dropped
        const auto strict = vet({"169.254.169.254", "8.8.8.8"}, false, true);
        REQUIRE_FALSE(strict.has_value());
        CHECK(strict.error() == refused_text);
        // Order does not matter.
        CHECK_FALSE(vet({"8.8.8.8", "169.254.169.254"}, false, true).has_value());
    }
    SECTION("private plus public is a refusal only without the operator switch") {
        CHECK_FALSE(vet({"10.0.0.5", "8.8.8.8"}, false, true).has_value());
        const auto allowed = vet({"10.0.0.5", "8.8.8.8"}, true, true);
        REQUIRE(allowed.has_value());
        CHECK(allowed->size() == 2);
    }
    SECTION("an IPv6 refused member refuses too") {
        CHECK_FALSE(vet({"fe80::1", "1.1.1.1"}, false, true).has_value());
        CHECK(vet({"fe80::1", "1.1.1.1"}, false, false).has_value());
    }
    SECTION("an all-permitted answer, a literal and an empty answer behave as before") {
        const auto all = vet({"8.8.8.8", "1.1.1.1"}, false, true);
        REQUIRE(all.has_value());
        CHECK(all->size() == 2);
        const auto literal = vet({"169.254.169.254"}, false, true, "8.8.8.8");
        REQUIRE(literal.has_value()); // the host is the literal; the resolver is never asked
        CHECK(literal->empty());
        CHECK_FALSE(vet({}, false, true).has_value());
    }
}

TEST_CASE("OIDC egress: the token POST's pre-check - pinned where the connect is pinned, strict "
          "where it cannot be",
          "[oidc][oidc_egress][security]") {
    // The discovery document names the token endpoint by a HOST NAME ("idp.test", which only the
    // resolver seam knows); the issuer, authorization endpoint and JWKS are the mock's own IP
    // literal, so only the token host consults the seam. On Linux/macOS the token POST is an
    // httplib client pinned to the vetted address; on Windows it is WinHTTP, which does its own
    // second lookup and may use ANY member of the answer, so exchange_code vets it in the STRICT
    // mode (vet_egress_target(..., require_all_permitted=true)): one refused address in the answer
    // refuses the target.
    //
    // Mutation (Linux): pass `/*require_all_permitted=*/true` in exchange_code's httplib branch -
    // the mixed-answer section's success turns into a refusal. On Windows (not performed here)
    // dropping `/*require_all_permitted=*/true` from the WinHTTP branch turns the same section's
    // refusal into a request that reaches the mock.
    MockIdp idp;
    idp.with([](MockIdp& m) {
        m.discovery_body = R"({"issuer":")" + m.base() + R"(","authorization_endpoint":")" +
                           m.base() + R"(/authorize","token_endpoint":"http://idp.test:)" +
                           std::to_string(m.port) + R"(/token","jwks_uri":")" + m.base() +
                           R"(/jwks"})";
    });
    const auto login = [&] {
        // The switch is on: the mock IdP (issuer, JWKS) is on loopback, which is refused otherwise.
        OidcProvider provider(provider_cfg(idp.base(), true));
        const auto flow = provider.start_auth_flow();
        REQUIRE_FALSE(idp.follow_authorize(flow.url).empty());
        return provider.handle_callback("the-code",
                                        yuzu::server::test::url_query_param(flow.url, "state"),
                                        flow.binding_secret);
    };

    SECTION("a mixed answer (link-local plus the loopback IdP): pinned on POSIX, refused strictly "
            "on Windows") {
        ResolverGuard resolver([](const std::string& host) -> std::vector<std::string> {
            if (host == "idp.test")
                return {"169.254.169.254", "127.0.0.1"};
            return {};
        });
        const auto claims = login();
#ifdef _WIN32
        // The strict pre-check: the refused member refuses the whole target, before WinHTTP.
        REQUIRE_FALSE(claims.has_value());
        CHECK(claims.error() ==
              std::string("token endpoint request failed: ") + OidcProvider::kEgressRefused);
        CHECK(idp.token_calls.load() == 0);
#else
        // The httplib path drops the refused address and pins the permitted one.
        REQUIRE(claims.has_value());
        CHECK(claims->sub == "alice-sub");
        CHECK(idp.token_calls.load() == 1);
#endif
    }
    SECTION("a name that resolves only to a PUBLIC address over plain http is refused everywhere, "
            "before any request") {
        ResolverGuard resolver([](const std::string& host) -> std::vector<std::string> {
            if (host == "idp.test")
                return {"93.184.216.34"};
            return {};
        });
        const auto claims = login();
        REQUIRE_FALSE(claims.has_value());
        CHECK(claims.error().find(kCleartextPublic) != std::string::npos);
        CHECK(claims.error().find("93.184.216.34") == std::string::npos);
        CHECK(idp.token_calls.load() == 0); // refused before any request, on every platform
    }
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN
