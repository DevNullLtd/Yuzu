/**
 * test_agent_reregistration_gate.cpp - WP01: the pure decision both agent ingest paths share
 * (server/core/src/agent_reregistration_gate.hpp). The handler-level behaviour is pinned in
 * test_agent_service_impl.cpp; this file pins the truth table and the mode/option contract.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/server/server.hpp>

#include "agent_reregistration_apply.hpp"
#include "agent_reregistration_gate.hpp"

using namespace yuzu::server;

namespace {
constexpr AgentLeafState kLive{.has_live = true, .has_revoked_unexpired = false};
constexpr AgentLeafState kNone{.has_live = false, .has_revoked_unexpired = false};
constexpr AgentLeafState kRevoked{.has_live = false, .has_revoked_unexpired = true};
constexpr AgentLeafState kLiveAndRevoked{.has_live = true, .has_revoked_unexpired = true};

ReregistrationOutcome decide(const AgentLeafState& s, bool cert, bool token, bool can_prove = true) {
    return decide_reregistration(
        std::expected<AgentLeafState, std::string>{s},
        ReregistrationEvidence{.cert_proves_identity = cert,
                               .token_presented = token,
                               .transport_can_prove = can_prove});
}
} // namespace

TEST_CASE("reregistration gate: an id with no live leaf is not the gate's business",
          "[reregistration_gate][wp01]") {
    for (bool cert : {false, true})
        for (bool token : {false, true})
            for (bool can_prove : {false, true})
                CHECK(decide(kNone, cert, token, can_prove) == ReregistrationOutcome::NoLeafOnRecord);
}

TEST_CASE("reregistration gate: a live leaf needs the current leaf or a token",
          "[reregistration_gate][wp01]") {
    CHECK(decide(kLive, true, false) == ReregistrationOutcome::ProvenByLeaf);
    CHECK(decide(kLive, true, true) == ReregistrationOutcome::ProvenByLeaf); // the leaf wins
    CHECK(decide(kLive, false, true) == ReregistrationOutcome::ViaToken);
    CHECK(decide(kLive, false, false) == ReregistrationOutcome::RefuseNoProof);
    // A listener that cannot witness is reported as such BEFORE the token is looked at, so a stale
    // token cannot disguise it as the healthy `via_token` outcome.
    CHECK(decide(kLive, false, false, /*can_prove=*/false) == ReregistrationOutcome::RefuseUnattested);
    CHECK(decide(kLive, false, true, /*can_prove=*/false) == ReregistrationOutcome::RefuseUnattested);
    // A live leaf beside an operator-revoked one (UP-5 / CH-7a): sign_agent_csr's HIGH-2 guard
    // would refuse the issuance, so a token must NOT be consumed for it: refuse BEFORE the token
    // block, token or not. Only the current leaf proves it.
    CHECK(decide(kLiveAndRevoked, false, false) == ReregistrationOutcome::RefuseRevokedIdentity);
    CHECK(decide(kLiveAndRevoked, false, true) == ReregistrationOutcome::RefuseRevokedIdentity);
    CHECK(decide(kLiveAndRevoked, true, false) == ReregistrationOutcome::ProvenByLeaf);
}

TEST_CASE("reregistration gate: a revoked identity with nothing live is refused, token or not",
          "[reregistration_gate][wp01]") {
    for (bool token : {false, true})
        for (bool can_prove : {false, true})
            CHECK(decide(kRevoked, false, token, can_prove) ==
                  ReregistrationOutcome::RefuseRevokedIdentity);
    // Evidence from the transport cannot override it either (an unrevoked-looking cert for a
    // revoked identity is a contradiction the cert checks already refuse upstream).
    CHECK(decide(kRevoked, true, true) == ReregistrationOutcome::RefuseRevokedIdentity);
}

TEST_CASE("reregistration gate: a lookup failure is its own outcome, never 'no leaf'",
          "[reregistration_gate][wp01]") {
    const auto o = decide_reregistration(std::unexpected(std::string("ca store down")),
                                         ReregistrationEvidence{.cert_proves_identity = true,
                                                                .token_presented = true});
    CHECK(o == ReregistrationOutcome::LookupFailed);
    CHECK_FALSE(is_refusal(o)); // the caller answers it UNAVAILABLE (retryable), not UNAUTHENTICATED
}

TEST_CASE("reregistration gate: exactly the three refusal outcomes refuse",
          "[reregistration_gate][wp01]") {
    CHECK(is_refusal(ReregistrationOutcome::RefuseNoProof));
    CHECK(is_refusal(ReregistrationOutcome::RefuseUnattested));
    CHECK(is_refusal(ReregistrationOutcome::RefuseRevokedIdentity));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::NoLeafOnRecord));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::ProvenByLeaf));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::ViaToken));
    CHECK_FALSE(is_refusal(ReregistrationOutcome::LookupFailed));
}

TEST_CASE("reregistration proof mode: exact spellings only, a typo never weakens the mode",
          "[reregistration_gate][wp01]") {
    CHECK(parse_reregistration_proof_mode("off") == ReregistrationProofMode::Off);
    CHECK(parse_reregistration_proof_mode("audit") == ReregistrationProofMode::Audit);
    CHECK(parse_reregistration_proof_mode("enforce") == ReregistrationProofMode::Enforce);
    for (const char* bad : {"", "Enforce", "ENFORCE", "enforced", "on", "true", " audit", "audit "})
        CHECK_FALSE(parse_reregistration_proof_mode(bad).has_value());
    // The compiled-in default is audit for the first release (owner decision D3).
    Config cfg;
    CHECK(cfg.agent_reregistration_proof == "audit");
    CHECK(parse_reregistration_proof_mode(cfg.agent_reregistration_proof) ==
          ReregistrationProofMode::Audit);
}

TEST_CASE("reregistration refusal message does not name the reason", "[reregistration_gate][wp01]") {
    const std::string m(kReregistrationRefusalPublicMessage);
    for (const char* leak : {"revoked", "leaf", "certificate", "exists", "enrolled"})
        CHECK(m.find(leak) == std::string::npos);
}

TEST_CASE("reregistration audit budget: a legitimate first admit always leaves a row, a flood on one "
          "id is cut to the per-id budget with ONE aggregate row per closed window, refusals are bounded",
          "[reregistration_gate][wp01]") {
    const std::expected<AgentLeafState, std::string> live{AgentLeafState{.has_live = true}};
    AgentIdentityHooks hooks;
    hooks.leaf_state = [&](const std::string&) { return live; };
    int refusal_rows = 0, unproven_rows = 0, aggregate_rows = 0;
    std::string aggregate_extra;
    const ReregistrationAuditSink sink = [&](std::string_view action, std::string_view,
                                             std::string_view outcome, std::string_view,
                                             std::string_view extra) {
        if (outcome == "aggregate") {
            ++aggregate_rows;
            aggregate_extra = std::string(extra);
        } else if (action == kAuditActionReregistrationUnproven) {
            ++unproven_rows;
        } else {
            ++refusal_rows;
        }
    };
    yuzu::MetricsRegistry metrics;
    const ReregistrationEvidence ev{};
    auto audit_attempt = [&](const std::string& id) {
        (void)apply_reregistration_gate(ReregistrationProofMode::Audit, &hooks, "direct", id, id, ev,
                                        &metrics, sink);
    };
    // Start from a fresh window regardless of what earlier cases in this process did.
    detail::reregistration_audit_clock_skew_ms() += 1'000'000;
    audit_attempt("window-reset");
    unproven_rows = aggregate_rows = 0;

    // 200 DISTINCT ids, one admitted attempt each (more ids than the old 64-key table): EVERY one
    // leaves its row.
    for (int i = 0; i < 200; ++i)
        audit_attempt("audit-id-" + std::to_string(i));
    CHECK(unproven_rows == 200);

    // An attacker looping on ONE known id: cut to the per-id budget (3), the rest dropped+counted.
    unproven_rows = 0;
    for (int i = 0; i < 100; ++i)
        audit_attempt("victim-loop");
    CHECK(unproven_rows == 3);
    CHECK(metrics.counter("yuzu_register_reregistration_audit_dropped_total",
                          {{"action", std::string(kAuditActionReregistrationUnproven)}})
              .value() == 97.0);
    // The decision counter is NOT sampled.
    CHECK(metrics.counter("yuzu_register_reregistration_total",
                          {{"path", "direct"}, {"outcome", "no_proof"}, {"mode", "audit"}})
              .value() == 301.0); // 1 window-reset + 200 distinct + 100 loop

    // The window reopens: the next admit gets its row again AND the closed window's suppressed
    // total is written once, as one aggregate row.
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    aggregate_rows = 0;
    audit_attempt("victim-loop");
    CHECK(unproven_rows == 4); // 3 + the reopened window's first row
    CHECK(aggregate_rows == 1);
    CHECK(aggregate_extra == "suppressed=97");

    // enforce: a flood on ONE id is bounded to the refusal budget, still refused each time.
    for (int i = 0; i < 100; ++i) {
        const auto v = apply_reregistration_gate(ReregistrationProofMode::Enforce, &hooks, "direct",
                                                 "flood-id", "flood-id", ev, &metrics, sink);
        CHECK(v.route == ReregistrationVerdict::Route::Refuse);
    }
    CHECK(refusal_rows > 0);
    CHECK(refusal_rows <= static_cast<int>(kDefaultAuditMaxRows));
}
