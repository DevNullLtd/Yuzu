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

#include "bounded_resolver.hpp"
#include "oidc_provider.hpp"
#include "test_oidc_mock_idp.hpp"

#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server::oidc;

// Shared by the MockIdp cases and the resolver cases at the end of the file, which compile in the
// ThreadSanitizer build too.
namespace {

struct Nat64Net {
    const char* label;
    const char* prefix;       // text for parse_nat64_prefix
    const char* probe_answer; // the AAAA answer for ipv4only.arpa (192.0.0.170 embedded)
    const char* link_local;   // 169.254.169.254 embedded
    const char* priv;         // 10.0.0.5 embedded
    const char* pub;          // 8.8.8.8 embedded
};

const Nat64Net kPub64{"pub/64",
                      "2a0e:b107:122:344::/64",
                      "2a0e:b107:122:344:c0:0:aa00:0",
                      "2a0e:b107:122:344:a9:fea9:fe00:0",
                      "2a0e:b107:122:344:a:0:500:0",
                      "2a0e:b107:122:344:8:808:800:0"};

/// The discovery cache is process-wide: every case starts and ends with it empty.
struct Nat64CacheReset {
    Nat64CacheReset() { OidcProvider::clear_nat64_discovery_cache_for_test(); }
    ~Nat64CacheReset() { OidcProvider::clear_nat64_discovery_cache_for_test(); }
    Nat64CacheReset(const Nat64CacheReset&) = delete;
    Nat64CacheReset& operator=(const Nat64CacheReset&) = delete;
};

} // namespace

// A real httplib acceptor thread crashes the ThreadSanitizer build (#438); see the MockIdp banner.
#ifndef YUZU_OIDC_MOCK_IDP_TSAN

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

// The resolver cases below use no MockIdp and no acceptor thread, so they sit outside the guard
// above and also run in the ThreadSanitizer build, where the lookup workers are what is worth
// checking.
#ifndef _WIN32
// ── Name lookups on the bounded resolver (POSIX) ─────────────────────────────────────────────
//
// `resolve_host_addresses_status` runs the lookup through net::bounded_resolve with a pool of the
// OIDC path's own. These cases replace the lookup function and the pool BELOW set_resolver_for_test
// (OidcProvider::set_bounded_lookup_for_test), so the adapter itself is exercised with no DNS.
// Every lookup function handed to the seam owns its state through a shared_ptr: a lookup can
// outlive the case that started it.

namespace {

namespace net = yuzu::server::net;

/// Replaces the bounded lookup and pool for the life of the guard, then restores the defaults.
/// A null pool means the production OIDC pool.
struct BoundedLookupGuard {
    BoundedLookupGuard(net::LookupFn lookup, std::shared_ptr<net::ResolverPool> pool) {
        OidcProvider::set_bounded_lookup_for_test(std::move(lookup), std::move(pool));
    }
    ~BoundedLookupGuard() { OidcProvider::set_bounded_lookup_for_test({}, {}); }
    BoundedLookupGuard(const BoundedLookupGuard&) = delete;
    BoundedLookupGuard& operator=(const BoundedLookupGuard&) = delete;
};

/// A lookup blocks on this until released.
struct LookupGate {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    std::atomic<int> entered{0};
    void wait() {
        std::unique_lock lk(mu);
        cv.wait(lk, [&] { return open; });
    }
    void release() {
        {
            std::lock_guard lk(mu);
            open = true;
        }
        cv.notify_all();
    }
};

/// Opens the gate on scope exit, so a failing REQUIRE never leaves a lookup latched.
struct GateOpener {
    explicit GateOpener(std::shared_ptr<LookupGate> g) : gate(std::move(g)) {}
    ~GateOpener() { gate->release(); }
    GateOpener(const GateOpener&) = delete;
    GateOpener& operator=(const GateOpener&) = delete;
    std::shared_ptr<LookupGate> gate;
};

bool wait_for(const std::function<bool()>& pred) {
    const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!pred()) {
        if (std::chrono::steady_clock::now() > give_up)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return true;
}

net::ResolveResult resolve_result(net::ResolveStatus status, std::vector<std::string> addresses) {
    return {status, std::move(addresses)};
}

constexpr const char* kUnresolved = "the host name did not resolve";
// A refused lookup (full pool, no worker): nothing was learned about the name.
constexpr const char* kBusyReason = "the host name lookup was not started";

std::expected<std::vector<std::string>, std::string> vet_name(const std::string& host,
                                                              int timeout_ms = 1000) {
    return OidcProvider::vet_egress_target_for_test(host, false, false, timeout_ms, {}, false);
}

/// How the ipv4only.arpa probe lookup answers.
enum ProbeMode : int { kProbeAnswer, kProbeTemporary, kProbeBusy, kProbeBlock, kProbeGarbage };

/// State a scripted lookup shares with its workers. A host ending in "a.test" blocks on `gate`;
/// ipv4only.arpa follows `probe_mode`; any other host counts in `others` and answers with
/// `other_status` / `other_answer`.
struct LookupState {
    std::shared_ptr<LookupGate> gate = std::make_shared<LookupGate>();
    std::atomic<int> probes{0};
    std::atomic<int> probe_mode{kProbeAnswer};
    std::atomic<int> others{0};
    net::ResolveStatus other_status{net::ResolveStatus::kOk}; // set before the lookup is installed
    std::string other_answer{"93.184.216.34"};
};

net::LookupFn make_lookup(std::shared_ptr<LookupState> st) {
    return [st](const std::string& host) {
        if (host == "ipv4only.arpa") {
            st->probes.fetch_add(1);
            switch (st->probe_mode.load()) {
            case kProbeTemporary:
                return resolve_result(net::ResolveStatus::kTemporary, {});
            case kProbeBusy:
                return resolve_result(net::ResolveStatus::kBusy, {});
            case kProbeBlock:
                st->gate->wait();
                return resolve_result(net::ResolveStatus::kOk, {kPub64.probe_answer});
            case kProbeGarbage:
                return resolve_result(net::ResolveStatus::kOk, {"garbage", "::zz"});
            default:
                return resolve_result(net::ResolveStatus::kOk, {kPub64.probe_answer});
            }
        }
        if (host.ends_with("a.test")) {
            st->gate->entered.fetch_add(1);
            st->gate->wait();
            return resolve_result(net::ResolveStatus::kOk, {"93.184.216.34"});
        }
        st->others.fetch_add(1);
        if (st->other_status != net::ResolveStatus::kOk)
            return resolve_result(st->other_status, {});
        return resolve_result(net::ResolveStatus::kOk, {st->other_answer});
    };
}

/// Runs vet_name on a thread. The destructor opens the gate and joins, so a failing REQUIRE in
/// the case neither terminates the process nor leaves the lookup latched. Declare it AFTER the
/// state and guard it uses.
struct VetThread {
    VetThread(std::shared_ptr<LookupGate> g, std::string host, int timeout_ms)
        : gate(std::move(g)), thread([this, host = std::move(host), timeout_ms] {
              result = vet_name(host, timeout_ms);
          }) {}
    ~VetThread() { finish(); }
    VetThread(const VetThread&) = delete;
    VetThread& operator=(const VetThread&) = delete;
    /// Opens the gate and joins; `result` is valid afterwards.
    void finish() {
        gate->release();
        if (thread.joinable())
            thread.join();
    }
    std::shared_ptr<LookupGate> gate;
    std::expected<std::vector<std::string>, std::string> result;
    std::thread thread; // last: starts after the other members exist
};

OidcConfig resolver_cfg(const std::string& issuer) {
    OidcConfig cfg;
    cfg.issuer = issuer;
    cfg.client_id = "yuzu-test-client";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    return cfg;
}

/// What start_auth_flow throws; empty when it did not throw.
std::string auth_flow_error(OidcProvider& provider) {
    try {
        (void)provider.start_auth_flow();
    } catch (const std::runtime_error& e) {
        return e.what();
    }
    return {};
}

/// A public-space IPv6 literal that embeds the link-local metadata address under kPub64. It is
/// classified with no name lookup, so only the NAT64 probe touches the pool.
const std::string kLiteralTarget = kPub64.link_local;

/// Learns kPub64 from an answered probe: the literal is then refused, and one probe was made.
void learn_prefix(LookupState& st) {
    const auto learned = vet_name(kLiteralTarget);
    REQUIRE_FALSE(learned.has_value());
    REQUIRE(learned.error() == OidcProvider::kEgressRefused);
    REQUIRE(st.probes.load() == 1);
}

} // namespace

TEST_CASE("OIDC resolver: a lookup answer round-trips to the bytes the vetting classifies, and "
          "text that is not an address is skipped",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(4);
    SECTION("v4 and v6 text become the pinned addresses; a refused class is dropped") {
        BoundedLookupGuard guard(
            [](const std::string& host) {
                if (host == "ipv4only.arpa")
                    return resolve_result(net::ResolveStatus::kNotFound, {});
                return resolve_result(net::ResolveStatus::kOk,
                                      {"not-an-address", "10.0.0.5", "93.184.216.34", "zz:zz",
                                       "2606:4700:4700::1111", "fe80::1", "999.1.1.1"});
            },
            pool);
        const auto pins = vet_name("multi.test");
        REQUIRE(pins.has_value());
        CHECK(*pins == std::vector<std::string>{"93.184.216.34", "2606:4700:4700::1111"});
    }
    SECTION("an answer with nothing parseable is unresolved") {
        BoundedLookupGuard guard(
            [](const std::string&) {
                return resolve_result(net::ResolveStatus::kOk, {"garbage", "::zz"});
            },
            pool);
        const auto pins = vet_name("junk.test");
        REQUIRE_FALSE(pins.has_value());
        CHECK(pins.error() == kUnresolved);
    }
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: every status but an answer is a fixed reason, and only a refused "
          "lookup is told apart",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(4);
    for (const auto status : {net::ResolveStatus::kNotFound, net::ResolveStatus::kTemporary,
                              net::ResolveStatus::kTimeout, net::ResolveStatus::kBusy}) {
        CAPTURE(static_cast<int>(status));
        BoundedLookupGuard guard(
            [status](const std::string&) { return resolve_result(status, {}); }, pool);
        const auto pins = vet_name("gone.test");
        REQUIRE_FALSE(pins.has_value());
        CHECK(pins.error() == (status == net::ResolveStatus::kBusy ? kBusyReason : kUnresolved));
    }
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: a lookup that never returns fails the fetch at the bound, its slot is "
          "held until it returns, and the next lookup then works",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto gate = std::make_shared<LookupGate>();
    GateOpener opener(gate); // after a failed REQUIRE the lookup is still released
    BoundedLookupGuard guard(
        [gate](const std::string& host) {
            if (host == "slow.test") {
                gate->entered.fetch_add(1);
                gate->wait();
            }
            return resolve_result(net::ResolveStatus::kOk, {"93.184.216.34"});
        },
        pool);

    yuzu::test::LogCapture cap(spdlog::level::warn);
    const auto started = std::chrono::steady_clock::now();
    const auto pins = vet_name("slow.test", 1000);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    cap.stop();

    REQUIRE_FALSE(pins.has_value());
    CHECK(pins.error() == kUnresolved);
    // The caller waited the 1 s bound (not zero, as for a full pool) and stopped there.
    CHECK(elapsed >= std::chrono::milliseconds(900));
    CHECK(elapsed < std::chrono::milliseconds(5000));
    REQUIRE(wait_for([&] { return gate->entered.load() == 1; }));
    CHECK(pool->in_flight.load() == 1); // the late lookup still holds its slot
    CHECK(cap.text().find("did not answer") != std::string::npos);

    gate->release(); // the resolver finally returns: the result is discarded, the slot freed
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));

    const auto next = vet_name("fast.test", 1000);
    REQUIRE(next.has_value());
    CHECK(*next == std::vector<std::string>{"93.184.216.34"});
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: a full pool fails closed at once as not started, without waiting",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto st = std::make_shared<LookupState>();
    BoundedLookupGuard guard(make_lookup(st), pool);
    VetThread holder(st->gate, "slow.a.test", 10000);
    REQUIRE(wait_for([&] { return st->gate->entered.load() == 1; }));

    yuzu::test::LogCapture cap(spdlog::level::warn);
    const auto started = std::chrono::steady_clock::now();
    const auto pins = vet_name("other.test", 10000);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    cap.stop();

    REQUIRE_FALSE(pins.has_value());
    CHECK(pins.error() == kBusyReason);
    CHECK(elapsed < std::chrono::milliseconds(2000)); // refused, not queued and not waited for
    CHECK(st->others.load() == 0);                    // nothing was started
    CHECK(cap.text().find("was not started: the lookup pool (1 slots) is full") !=
          std::string::npos);

    holder.finish();
    REQUIRE(holder.result.has_value());
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));

    // Recovery: with the slot free, the same lookup now succeeds.
    const auto again = vet_name("other.test", 1000);
    REQUIRE(again.has_value());
    CHECK(st->others.load() == 1);
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: two issuers share one pool - a name under one fills it for the other",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(2);
    auto st = std::make_shared<LookupState>();
    BoundedLookupGuard guard(make_lookup(st), pool);
    VetThread first(st->gate, "one.a.test", 10000);
    VetThread second(st->gate, "two.a.test", 10000);
    REQUIRE(wait_for([&] { return st->gate->entered.load() == 2; }));
    CHECK(pool->in_flight.load() == 2);

    yuzu::test::LogCapture cap(spdlog::level::warn);
    const auto refused = vet_name("b.test");
    cap.stop();
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error() == kBusyReason);
    CHECK(st->others.load() == 0);
    CHECK(cap.text().find("the lookup pool (2 slots) is full") != std::string::npos);

    first.finish(); // one shared gate: this opens it for both
    second.finish();
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));
    const auto served = vet_name("b.test");
    REQUIRE(served.has_value());
    CHECK(*served == std::vector<std::string>{"93.184.216.34"});
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: the default OIDC pool serves lookups and is separate from the process "
          "pool",
          "[oidc][oidc_egress][oidc_resolver]") {
    Nat64CacheReset cache;
    REQUIRE(wait_for([] { return oidc_resolver_in_flight() == 0; }));
    const int process_before = net::process_resolver_in_flight();
    auto st = std::make_shared<LookupState>();
    BoundedLookupGuard guard(make_lookup(st), nullptr); // null pool: the production default
    auto older = std::make_unique<OidcProvider>(resolver_cfg("https://idp.test"));
    VetThread holder(st->gate, "slow.a.test", 10000);
    REQUIRE(wait_for([&] { return st->gate->entered.load() == 1; }));

    CHECK(oidc_resolver_in_flight() == 1);
    CHECK(net::process_resolver_in_flight() <= process_before); // the process pool is untouched

    // The pool is process state, not provider state: a rebuilt provider sees the same slot held.
    older.reset();
    OidcProvider rebuilt(resolver_cfg("https://idp.test"));
    CHECK(oidc_resolver_in_flight() == 1);

    holder.finish();
    REQUIRE(holder.result.has_value());
    CHECK(wait_for([] { return oidc_resolver_in_flight() == 0; }));
    OidcProvider::set_bounded_lookup_for_test({}, nullptr); // the hook can be cleared
    CHECK(oidc_resolver_in_flight() == 0);
}

TEST_CASE("OIDC resolver: a failed or busy NAT64 probe changes nothing in the learned prefixes",
          "[oidc][oidc_egress][oidc_resolver][oidc_nat64]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(4);
    auto st = std::make_shared<LookupState>();
    // A global-space translated address: public unless the prefix is known.
    st->other_answer = kPub64.link_local;
    BoundedLookupGuard guard(make_lookup(st), pool);

    // Learn the prefix: the embedded link-local address is refused.
    auto learned = vet_name("nat.test");
    REQUIRE_FALSE(learned.has_value());
    CHECK(learned.error() == OidcProvider::kEgressRefused);
    CHECK(st->probes.load() == 1);

    for (const int mode : {kProbeTemporary, kProbeBusy}) {
        CAPTURE(mode);
        st->probe_mode.store(mode);
        OidcProvider::expire_nat64_discovery_cache_for_test(); // the next fetch probes again
        const int before = st->probes.load();
        const auto after = vet_name("nat.test");
        CHECK(st->probes.load() == before + 1);
        REQUIRE_FALSE(after.has_value()); // the learned prefix is still applied
        CHECK(after.error() == OidcProvider::kEgressRefused);
    }
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: a probe refused by a full pool is not remembered - the next fetch "
          "probes again and the learned prefixes still apply",
          "[oidc][oidc_egress][oidc_resolver][oidc_nat64]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto st = std::make_shared<LookupState>();
    BoundedLookupGuard guard(make_lookup(st), pool);
    learn_prefix(*st);
    OidcProvider::expire_nat64_discovery_cache_for_test(); // the next fetch is due to probe
    // The worker frees its slot just after waking the caller, so a cap-1 pool can still read 1.
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));

    {
        VetThread holder(st->gate, "slow.a.test", 10000);
        REQUIRE(wait_for([&] { return st->gate->entered.load() == 1; }));
        yuzu::test::LogCapture cap(spdlog::level::warn);
        const auto busy = vet_name(kLiteralTarget);
        cap.stop();
        CHECK(st->probes.load() == 1); // the probe lookup was never started
        REQUIRE_FALSE(busy.has_value());
        CHECK(busy.error() == OidcProvider::kEgressRefused); // learned prefix still applied
        CHECK(cap.text().find("the NAT64 prefix lookup (ipv4only.arpa) was not started") !=
              std::string::npos);
    } // the holder's gate opens here
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));

    // No expiry call: a busy refusal armed no negative window, so the very next fetch probes.
    const auto next = vet_name(kLiteralTarget);
    CHECK(st->probes.load() == 2);
    REQUIRE_FALSE(next.has_value());
    CHECK(next.error() == OidcProvider::kEgressRefused);
    // The answered probe is cached again.
    CHECK_FALSE(vet_name(kLiteralTarget).has_value());
    CHECK(st->probes.load() == 2);
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: a probe that times out is not repeated inside the window, and the "
          "learned prefixes still apply",
          "[oidc][oidc_egress][oidc_resolver][oidc_nat64]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(4);
    auto st = std::make_shared<LookupState>();
    GateOpener opener(st->gate); // after a failed REQUIRE the blocked probe is still released
    BoundedLookupGuard guard(make_lookup(st), pool);
    learn_prefix(*st);
    OidcProvider::expire_nat64_discovery_cache_for_test();

    st->probe_mode.store(kProbeBlock);
    const auto timed_out = vet_name(kLiteralTarget, 1000); // the one inherent 1 s wait
    CHECK(st->probes.load() == 2);
    REQUIRE_FALSE(timed_out.has_value());
    CHECK(timed_out.error() == OidcProvider::kEgressRefused);

    // Known residual, owner-ruled: a probe that was started and failed arms the 1 minute window,
    // so the next fetch does not probe again (unlike a refusal for a full pool).
    const auto again = vet_name(kLiteralTarget, 1000);
    CHECK(st->probes.load() == 2);
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error() == OidcProvider::kEgressRefused);

    st->gate->release();
    st->probe_mode.store(kProbeAnswer);
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));
    OidcProvider::expire_nat64_discovery_cache_for_test();
    CHECK_FALSE(vet_name(kLiteralTarget).has_value());
    CHECK(st->probes.load() == 3); // the window is over: the probe runs again
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: a probe answered only with unparsable text learns nothing and the "
          "fetch proceeds",
          "[oidc][oidc_egress][oidc_resolver][oidc_nat64]") {
    Nat64CacheReset cache;
    auto pool = std::make_shared<net::ResolverPool>(4);
    auto st = std::make_shared<LookupState>();
    st->probe_mode.store(kProbeGarbage);
    BoundedLookupGuard guard(make_lookup(st), pool);
    const auto pins = vet_name(kLiteralTarget);
    CHECK(st->probes.load() == 1);
    // No prefix was learned, so the literal is a plain public address: permitted, nothing to pin.
    REQUIRE(pins.has_value());
    CHECK(pins->empty());
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: discovery that failed on a real lookup failure is retried only after "
          "its window, and Test Connection does not wait for the window",
          "[oidc][oidc_egress][oidc_resolver][oidc_discovery]") {
    Nat64CacheReset cache;
    constexpr int kWindowMs = 1500;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto st = std::make_shared<LookupState>();
    st->other_status = net::ResolveStatus::kNotFound; // a lookup that does run finds nothing
    BoundedLookupGuard guard(make_lookup(st), pool);
    const std::string issuer = "https://idp.test";
    OidcProvider provider(resolver_cfg(issuer));
    provider.set_discovery_negative_cache_for_test(kWindowMs);

    const auto first_attempt = std::chrono::steady_clock::now();
    CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
    CHECK(st->others.load() == 1); // the lookup ran and found nothing: the window is armed

    if (std::chrono::steady_clock::now() <
        first_attempt + std::chrono::milliseconds(kWindowMs / 2)) {
        // Inside the window the failed attempt is not retried.
        CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
        CHECK(st->others.load() == 1);
        // Test Connection calls the static fetch, which has no window: it does look the name up.
        const auto doc = OidcProvider::fetch_discovery_document(issuer, false, false, 1000);
        CHECK_FALSE(doc.has_value());
        CHECK(st->others.load() == 2);
    } else {
        WARN("the host stalled past half the window: the in-window checks were skipped");
    }

    // After the window a login attempt performs a lookup again.
    const int seen = st->others.load();
    const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (st->others.load() == seen && std::chrono::steady_clock::now() < give_up) {
        CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(st->others.load() == seen + 1);
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: discovery refused for a full pool is not remembered - the next attempt "
          "looks the name up without waiting for the window",
          "[oidc][oidc_egress][oidc_resolver][oidc_discovery]") {
    Nat64CacheReset cache;
    constexpr int kWindowMs = 5000; // never waited out
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto st = std::make_shared<LookupState>();
    st->other_status = net::ResolveStatus::kNotFound;
    BoundedLookupGuard guard(make_lookup(st), pool);
    OidcProvider provider(resolver_cfg("https://idp.test"));
    provider.set_discovery_negative_cache_for_test(kWindowMs);

    {
        VetThread holder(st->gate, "slow.a.test", 10000);
        REQUIRE(wait_for([&] { return st->gate->entered.load() == 1; }));
        CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
        CHECK(st->others.load() == 0); // refused by the full pool: no lookup was performed
    }
    REQUIRE(wait_for([&] { return pool->in_flight.load() == 0; }));

    // The pool is free: the very next attempt performs a lookup (the refusal armed no window).
    CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
    CHECK(st->others.load() == 1);
    CHECK(wait_for([&] { return pool->in_flight.load() == 0; }));
}

TEST_CASE("OIDC resolver: an IdP-supplied issuer text that quotes the busy reason still arms the "
          "discovery window",
          "[oidc][oidc_egress][oidc_resolver][oidc_discovery]") {
    // The failure is an issuer mismatch whose text carries IdP-controlled bytes. Only the exact
    // refusal composed by http_get_bounded may skip the window, so this one must arm it.
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_issuer = "the host name lookup was not started"; });
    auto cfg = resolver_cfg(idp.base());
    cfg.allow_private_networks = true; // the mock IdP listens on loopback
    OidcProvider provider(cfg);
    provider.set_discovery_negative_cache_for_test(5000); // never waited out

    CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
    CHECK(idp.discovery_calls.load() == 1);
    // Inside the window the failed attempt is not retried: no further fetch reaches the IdP.
    CHECK(auth_flow_error(provider) == OidcProvider::kDiscoveryUnavailable);
    CHECK(idp.discovery_calls.load() == 1);
}
#endif // !_WIN32
