/**
 * test_ota_audit_key.cpp — the OTA identity-deny audit bucket key.
 *
 * WHY THIS FILE EXISTS. Two blocking defects have been found in this one string,
 * and a gate-8 mutation proved the second one was invisible: reverting the key
 * to the caller's `claimed_agent_id` left the ENTIRE server suite green — 42,326
 * assertions, zero failures. A bound whose central decision no test observes is
 * not a bound, it is a comment.
 */

#include "ota_audit_key.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::detail::kMaxAuditKeyIdentity;
using yuzu::server::detail::ota_identity_audit_key;

TEST_CASE("OTA audit key: the claimed agent_id cannot influence the bucket",
          "[ota][identity][auditkey]") {
    // DEFECT 1, pinned. The key is built from the RPC, the reason and the PEER.
    // The caller's claimed agent_id is not an input at all — there is no argument
    // it could be passed as. That is deliberate: `RateLimiter::allow` admits any
    // NEW key unconditionally, so any caller-varied component in this string
    // hands the caller an unlimited supply of fresh, always-admitting buckets.
    const auto a = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert",
                                          "agent-1.fleet.example");
    const auto b = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert",
                                          "agent-1.fleet.example");
    CHECK(a == b);
    CHECK(a.find("agent-1.fleet.example") != std::string::npos);
}

TEST_CASE("OTA audit key: a foreign-CA peer cannot squat a recognised peer's bucket",
          "[ota][identity][auditkey]") {
    // DEFECT 2, pinned, and it is the subtle one. `ota_admission_key` reports
    // mode="cert" for ANY certificate the listener accepted, without consulting
    // the recognizer. So on a multi-CA trust bundle an attacker holding a cert
    // from some other CA in that bundle can set CN=<victim agent id> and arrive
    // with a byte-identical peer key to the victim's.
    //
    // What separates them is the REASON: an unrecognised issuer can only ever
    // provoke `foreign_ca`, while the victim's own denials are `agent_id_mismatch`
    // or `agent_id_missing`. Different buckets, so the attacker cannot spend the
    // victim's allowance and silence the victim's audit rows.
    const std::string victim_identity = "agent-1.fleet.example";
    const auto victim = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert",
                                               victim_identity);
    const auto impostor =
        ota_identity_audit_key("download_update", "foreign_ca", "cert", victim_identity);
    CHECK(victim != impostor);

    // The other two auditable reasons are likewise disjoint from each other.
    const auto missing =
        ota_identity_audit_key("download_update", "agent_id_missing", "cert", victim_identity);
    CHECK(missing != victim);
    CHECK(missing != impostor);
}

TEST_CASE("OTA audit key: distinct peers and RPCs get distinct buckets",
          "[ota][identity][auditkey]") {
    const auto p1 = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert", "a");
    const auto p2 = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert", "b");
    CHECK(p1 != p2);

    // Per-RPC separation is intentional: a peer exercising both OTA RPCs gets a
    // bucket on each. The docs state the aggregate that follows from it.
    const auto r1 = ota_identity_audit_key("check_for_update", "agent_id_mismatch", "cert", "a");
    CHECK(r1 != p1);

    const auto m1 = ota_identity_audit_key("download_update", "agent_id_mismatch", "peer_ip", "a");
    CHECK(m1 != p1);
}

TEST_CASE("OTA audit key: no peer identity can forge another peer's key",
          "[ota][identity][auditkey]") {
    // Only the LAST field is variable-length and peer-influenced, so a separator
    // embedded in a certificate identity cannot shift the field boundaries that
    // precede it. These two must not collide however the identity is spelled.
    const auto honest = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert", "a");
    const auto forged = ota_identity_audit_key("download_update", "foreign_ca", "cert",
                                               "cert|a"); // tries to re-open the prefix
    CHECK(honest != forged);

    const auto forged2 = ota_identity_audit_key(
        "check_for_update", "foreign_ca", "cert", "|download_update|agent_id_mismatch|cert|a");
    CHECK(honest != forged2);
}

TEST_CASE("OTA audit key: the peer identity is clamped", "[ota][identity][auditkey]") {
    // The limiter's map has no eviction that runs in production, so an unclamped
    // key makes each permanent entry's cost caller-chosen. A trusted CA can still
    // mint an arbitrarily long CN.
    const std::string huge(4096, 'x');
    const auto k = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert", huge);
    CHECK(k.size() <= kMaxAuditKeyIdentity + 64);

    // Clamping must not collapse two long-but-different identities onto one
    // bucket within the retained prefix.
    const auto k1 = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert",
                                           std::string(200, 'x') + "-one");
    const auto k2 = ota_identity_audit_key("download_update", "agent_id_mismatch", "cert",
                                           std::string(200, 'x') + "-two");
    CHECK(k1 != k2);
}
