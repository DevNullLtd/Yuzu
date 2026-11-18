/**
 * test_agent_reregistration_gate.cpp - WP01: the pure decision both agent ingest paths share
 * (server/core/src/agent_reregistration_gate.hpp). The handler-level behaviour is pinned in
 * test_agent_service_impl.cpp; this file pins the truth table and the mode/option contract.
 */

#include <catch2/catch_test_macros.hpp>

#include <set>

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
    // The compiled-in default is audit (owner decision D3).
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

TEST_CASE("unproven audit budget: exact numbers - per-source sub-cap, reserved bucket for first-ever "
          "ids, global backstop, distinct counts, time flush",
          "[reregistration_gate][wp01][audit_budget]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 1'000'000;
    const auto admit = [&](const std::string& id, const std::string& src) {
        return b.admit(id, src, t).admitted;
    };

    // W0: 300 ids, each from its OWN source: all admitted (reserved 250 + 50 general), and every id
    // becomes "recent" (no longer first-ever).
    for (int i = 0; i < 300; ++i)
        CHECK(admit("pre-" + std::to_string(i), "src-" + std::to_string(i)));
    t += B::kWindowMs + 1;

    // W1, per-SOURCE sub-cap: one attacker source naming 200 already-known (non-first-ever) ids is
    // cut to exactly kRowsPerSource rows.
    int admitted = 0;
    for (int i = 0; i < 200; ++i)
        admitted += admit("pre-" + std::to_string(i), "attacker") ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kRowsPerSource));
    // The reserved bucket: a first-ever victim id from ANOTHER source is admitted regardless.
    CHECK(admit("victim-first-ever", "victim-src"));

    // The attacker spends the GENERAL budget from 25 more sources (50 each... capped at the global
    // backstop); the reserved bucket still admits first-ever ids until its own cap.
    t += B::kWindowMs + 1;
    int general = 0;
    for (int srcn = 0; srcn < 30; ++srcn)
        for (int i = 0; i < 50; ++i)
            general += admit("pre-" + std::to_string((srcn * 50 + i) % 300), "bot-" + std::to_string(srcn)) ? 1 : 0;
    CHECK(general <= static_cast<int>(B::kGeneralRows));
    CHECK(admit("victim-2", "victim-src")); // first-ever: reserved bucket, not starved
    // Per-id repeats: exactly kRepeatRowsPerId rows.
    int repeats = 0;
    for (int i = 0; i < 10; ++i)
        repeats += admit("victim-2", "victim-src") ? 1 : 0;
    CHECK(repeats == static_cast<int>(B::kRepeatRowsPerId) - 1); // the first admit above was row 1

    // Time-based flush: the closed window's summary is available WITHOUT a later admit.
    CHECK(b.poll_closed(t + 1, /*force=*/false).empty()); // still open
    t += B::kWindowMs + 1;
    const std::string summary = b.poll_closed(t, /*force=*/false);
    CHECK(summary.find("dropped_rows=") != std::string::npos);
    CHECK(summary.find("distinct_dropped_ids=") != std::string::npos);
    CHECK(summary.find("sources=") != std::string::npos);
    CHECK(summary.find("bot-") != std::string::npos); // per-source counts, not a caller identity
    CHECK(b.poll_closed(t, false).empty());           // delivered once
}

TEST_CASE("unproven audit budget: a legitimate restart storm, the shutdown flush and the global backstop",
          "[reregistration_gate][wp01][audit_budget]") {
    using B = detail::UnprovenAuditBudget;
    B b;
    std::int64_t t = 5'000'000;
    // 2000 distinct first-ever ids from 2000 sources in one window: kReservedRows + kGeneralRows
    // are written, the rest dropped and COUNTED as distinct ids.
    int admitted = 0;
    for (int i = 0; i < 2000; ++i)
        admitted += b.admit("storm-" + std::to_string(i), "s" + std::to_string(i), t).admitted ? 1 : 0;
    CHECK(admitted == static_cast<int>(B::kReservedRows + B::kGeneralRows));
    // Shutdown flush closes the OPEN window and reports it (otherwise lost on exit).
    const std::string summary = b.poll_closed(t + 1, /*force=*/true);
    CHECK(summary.find("dropped_rows=750") != std::string::npos);
    CHECK(summary.find("distinct_dropped_ids=750") != std::string::npos);
    CHECK(b.poll_closed(t + 2, true).empty());
}

TEST_CASE("reregistration audit sink path: the aggregate row is a system row with no caller identity",
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
    auto audit_attempt = [&](const std::string& id, const std::string& src) {
        (void)apply_reregistration_gate(ReregistrationProofMode::Audit, &hooks, "direct", id, id, ev,
                                        &metrics, sink, src);
    };
    detail::reregistration_audit_clock_skew_ms() += 1'000'000;
    audit_attempt("window-reset", "x");
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    audit_attempt("window-reset2", "x");
    unproven_rows = aggregate_rows = 0;
    // 100 repeats of one id from one source: 3 rows, 97 dropped and counted.
    for (int i = 0; i < 100; ++i)
        audit_attempt("victim-loop", "9.9.9.9");
    CHECK(unproven_rows == static_cast<int>(detail::UnprovenAuditBudget::kRepeatRowsPerId));
    CHECK(metrics.counter("yuzu_register_reregistration_audit_dropped_total",
                          {{"action", std::string(kAuditActionReregistrationUnproven)}})
              .value() == 97.0);
    // The summary is flushed by TIME (the server's tick), not by a later admit.
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    const auto summary = detail::reregistration_unproven_budget().poll_closed(
        detail::reregistration_audit_now_ms(), false);
    CHECK(summary.find("dropped_rows=97") != std::string::npos);
    CHECK(summary.find("9.9.9.9:97") != std::string::npos);
    CHECK(summary.find("victim-loop") != std::string::npos);
    // The decision counter is NOT sampled: every attempt above was counted.
    CHECK(metrics.counter("yuzu_register_reregistration_total",
                          {{"path", "direct"}, {"outcome", "no_proof"}, {"mode", "audit"}})
              .value() >= 102.0);
    CHECK(aggregate_rows == 0); // no later admit was needed to flush

    // enforce: a flood on ONE id is bounded to the refusal budget, still refused each time.
    for (int i = 0; i < 100; ++i) {
        const auto v = apply_reregistration_gate(ReregistrationProofMode::Enforce, &hooks, "direct",
                                                 "flood-id", "flood-id", ev, &metrics, sink);
        CHECK(v.route == ReregistrationVerdict::Route::Refuse);
    }
    CHECK(refusal_rows > 0);
    CHECK(refusal_rows <= static_cast<int>(kDefaultAuditMaxRows));
}
