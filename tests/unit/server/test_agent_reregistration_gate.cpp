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

TEST_CASE("reregistration audit budget: a first admit always leaves its row (even with the key table "
          "full), repeats are cut, ONE system-attributed aggregate row per closed window, new-id rows "
          "are globally capped and counted",
          "[reregistration_gate][wp01]") {
    const std::expected<AgentLeafState, std::string> live{AgentLeafState{.has_live = true}};
    AgentIdentityHooks hooks;
    hooks.leaf_state = [&](const std::string&) { return live; };
    int refusal_rows = 0, unproven_rows = 0, aggregate_rows = 0;
    std::string aggregate_extra;
    std::set<std::string> admitted_ids;
    std::string current_id;
    const ReregistrationAuditSink sink = [&](std::string_view action, std::string_view,
                                             std::string_view outcome, std::string_view,
                                             std::string_view extra) {
        if (outcome == "aggregate") {
            ++aggregate_rows;
            aggregate_extra = std::string(extra);
        } else if (action == kAuditActionReregistrationUnproven) {
            ++unproven_rows;
            admitted_ids.insert(current_id);
        } else {
            ++refusal_rows;
        }
    };
    yuzu::MetricsRegistry metrics;
    const ReregistrationEvidence ev{};
    auto audit_attempt = [&](const std::string& id) {
        current_id = id;
        (void)apply_reregistration_gate(ReregistrationProofMode::Audit, &hooks, "direct", id, id, ev,
                                        &metrics, sink);
    };
    auto new_window = [&] {
        detail::reregistration_audit_clock_skew_ms() += 11'000;
        audit_attempt("window-opener");
    };
    // Start from a fresh window regardless of what earlier cases in this process did.
    new_window();
    new_window();
    unproven_rows = aggregate_rows = 0;
    admitted_ids.clear();

    // (iii) A flood of 700 NEW ids in one window: exactly the global cap of 500 rows is written,
    // the other 200 are dropped, counted and summarised.
    for (int i = 0; i < 700; ++i)
        audit_attempt("flood-id-" + std::to_string(i));
    // (The window's opener already took one of the 500 rows, so 499 of the flood fit.)
    CHECK(unproven_rows ==
          static_cast<int>(detail::UnprovenAuditBudget::kNewIdRowsPerWindow) - 1);
    CHECK(metrics.counter("yuzu_register_reregistration_audit_dropped_total",
                          {{"action", std::string(kAuditActionReregistrationUnproven)}})
              .value() == 201.0);

    // The window reopens: the closed window's summary is written ONCE, and the opener (a NEW id)
    // gets its own first row again.
    aggregate_rows = 0;
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    audit_attempt("victim-first");
    CHECK(aggregate_rows == 1);
    CHECK(aggregate_extra.find("dropped_new_ids=201") != std::string::npos);
    CHECK(aggregate_extra.find("sample_ids=") != std::string::npos);
    CHECK(admitted_ids.count("victim-first") == 1);

    // (i) The tracked-id table is cleared every window and the global new-id cap (500) is far below
    // its size (4096), so an attacker cannot fill the table: the only way to starve a victim's FIRST
    // row is to spend the global cap in the SAME window (documented residual: that row is dropped,
    // counted and summarised). In the next window the victim's first admit is written again.
    new_window();
    for (int i = 0; i < 500; ++i)
        audit_attempt("fill-" + std::to_string(i));
    admitted_ids.clear();
    audit_attempt("victim-same-window");
    CHECK(admitted_ids.count("victim-same-window") == 0); // cap spent: dropped (and counted)
    detail::reregistration_audit_clock_skew_ms() += 11'000;
    audit_attempt("victim-2");
    CHECK(admitted_ids.count("victim-2") == 1);

    // (ii) Repeats of one id: cut to the per-id budget (3), summarised in the aggregate.
    new_window();
    unproven_rows = 0;
    for (int i = 0; i < 100; ++i)
        audit_attempt("victim-loop");
    CHECK(unproven_rows == static_cast<int>(detail::UnprovenAuditBudget::kRepeatRowsPerId));
    aggregate_rows = 0;
    new_window();
    CHECK(aggregate_rows == 1);
    CHECK(aggregate_extra.find("suppressed_repeats=97") != std::string::npos);
    CHECK(aggregate_extra.find("victim-loop") != std::string::npos); // bounded sample of the ids
    // The decision counter is NOT sampled: every attempt above was counted.
    CHECK(metrics.counter("yuzu_register_reregistration_total",
                          {{"path", "direct"}, {"outcome", "no_proof"}, {"mode", "audit"}})
              .value() > 1000.0);

    // enforce: a flood on ONE id is bounded to the refusal budget, still refused each time.
    for (int i = 0; i < 100; ++i) {
        const auto v = apply_reregistration_gate(ReregistrationProofMode::Enforce, &hooks, "direct",
                                                 "flood-id", "flood-id", ev, &metrics, sink);
        CHECK(v.route == ReregistrationVerdict::Route::Refuse);
    }
    CHECK(refusal_rows > 0);
    CHECK(refusal_rows <= static_cast<int>(kDefaultAuditMaxRows));
}
