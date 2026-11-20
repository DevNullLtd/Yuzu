/**
 * test_agent_witnessed_leaf.cpp - WP01: the predicate that decides whether a client certificate the
 * GATEWAY witnessed in an agent's TLS handshake proves a given agent id
 * (server/core/src/agent_witnessed_leaf.hpp). The gateway accepts ANY presented certificate, so this
 * predicate is the only verifier; each case below is one way a forged or stale witness must fail.
 * Real certificates, no fakes: the CA is minted with the production pki:: helpers.
 */

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <functional>
#include <string>

#include "agent_witnessed_leaf.hpp"
#include "x509_ca.hpp"

using namespace yuzu::server;
namespace pki = yuzu::server::pki;

namespace {

struct Ca {
    std::string key, cert;
};

Ca make_ca(const std::string& cn) {
    auto key = pki::generate_private_key(pki::KeyAlgo::EcP384);
    REQUIRE(key);
    pki::CaParams p;
    p.subject = {cn, "Yuzu"};
    p.validity = pki::validity_years_from_now(10);
    p.path_len = 0;
    auto cert = pki::self_sign_ca(*key, p);
    REQUIRE(cert);
    return {*key, *cert};
}

std::string encode_segment(std::string_view s) { return std::string(s); } // ids here are all unreserved

// An agent leaf the way sign_agent_csr mints one: CN=<id>, client auth, install-scoped URI SAN.
std::string agent_leaf(const Ca& ca, const std::string& id, pki::Validity validity,
                       bool with_agent_uri = true, bool client_auth = true) {
    pki::LeafParams lp;
    lp.subject = {id, "Yuzu"};
    lp.validity = validity;
    lp.usage = pki::LeafUsage{.client_auth = client_auth, .code_signing = !client_auth};
    if (with_agent_uri)
        lp.san.uris.push_back("yuzu://abc123/agent/" + id);
    auto leaf = pki::issue_leaf(ca.cert, ca.key, pki::KeyAlgo::EcP256, lp);
    REQUIRE(leaf);
    return leaf->cert_pem;
}

bool proves(const std::string& pem, const std::string& id, const Ca& ca,
            std::function<bool(const std::string&)> revoked = [](const std::string&) { return false; },
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
    return witnessed_leaf_proves_agent_identity(pem, id, ca.cert, now, revoked, encode_segment);
}

} // namespace

TEST_CASE("witnessed leaf: a current, unrevoked leaf issued by our CA for this id proves it",
          "[pki][wp01][witnessed_leaf]") {
    const auto ca = make_ca("Yuzu Witness CA");
    const auto pem = agent_leaf(ca, "agent-1", pki::validity_days_from_now(30));
    CHECK(proves(pem, "agent-1", ca));
}

TEST_CASE("witnessed leaf: every way a forged or stale witness must fail",
          "[pki][wp01][witnessed_leaf]") {
    const auto ca = make_ca("Yuzu Witness CA");
    const auto good = agent_leaf(ca, "agent-1", pki::validity_days_from_now(30));

    SECTION("another agent's leaf does not prove this id") {
        CHECK_FALSE(proves(good, "agent-2", ca));
    }
    SECTION("a leaf issued by a different CA (a foreign cert with the victim's CN) is refused") {
        const auto other = make_ca("Corporate CA");
        const auto spoof = agent_leaf(other, "agent-1", pki::validity_days_from_now(30));
        CHECK_FALSE(proves(spoof, "agent-1", ca));
    }
    SECTION("an expired leaf is refused, even though it chains") {
        const auto now = std::chrono::system_clock::now();
        const auto expired = agent_leaf(
            ca, "agent-1", pki::Validity{now - std::chrono::hours(48), now - std::chrono::hours(24)});
        CHECK_FALSE(proves(expired, "agent-1", ca));
    }
    SECTION("a not-yet-valid leaf is refused") {
        const auto now = std::chrono::system_clock::now();
        const auto future = agent_leaf(
            ca, "agent-1", pki::Validity{now + std::chrono::hours(24), now + std::chrono::hours(48)});
        CHECK_FALSE(proves(future, "agent-1", ca));
    }
    SECTION("a leaf with the right CN but no agent URI SAN (e.g. a code-signing leaf) is refused") {
        const auto no_uri = agent_leaf(ca, "agent-1", pki::validity_days_from_now(30),
                                       /*with_agent_uri=*/false, /*client_auth=*/false);
        CHECK_FALSE(proves(no_uri, "agent-1", ca));
    }
    SECTION("a revoked leaf is refused; the revocation check is consulted with the witnessed PEM") {
        std::string seen;
        CHECK_FALSE(proves(good, "agent-1", ca, [&](const std::string& pem) {
            seen = pem;
            return true;
        }));
        CHECK(seen == good);
    }
    SECTION("garbage, empty and oversize input are refused") {
        CHECK_FALSE(proves("", "agent-1", ca));
        CHECK_FALSE(proves("not a certificate", "agent-1", ca));
        CHECK_FALSE(proves(std::string(kMaxWitnessedLeafPemBytes + 1, 'A'), "agent-1", ca));
        CHECK_FALSE(proves(good, "", ca));
    }
    SECTION("an unset issuing CA or missing callbacks fail closed") {
        const auto now = std::chrono::system_clock::now();
        CHECK_FALSE(witnessed_leaf_proves_agent_identity(good, "agent-1", "", now,
                                                         [](const std::string&) { return false; },
                                                         encode_segment));
        CHECK_FALSE(witnessed_leaf_proves_agent_identity(good, "agent-1", ca.cert, now, nullptr,
                                                         encode_segment));
        CHECK_FALSE(witnessed_leaf_proves_agent_identity(good, "agent-1", ca.cert, now,
                                                         [](const std::string&) { return false; },
                                                         nullptr));
    }
}
