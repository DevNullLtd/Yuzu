#pragma once

/// @file agent_reregistration_apply.hpp
///
/// WP01: the shared APPLICATION of `decide_reregistration` (agent_reregistration_gate.hpp) that both
/// `AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` call from their
/// `approved` fast path. One copy: the lookup, the metric, the mode handling and the refusal status
/// live here, so a handler contributes only its transport's evidence. EXTEND it, never fork it.

#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "agent_reregistration_gate.hpp"
#include "bounded_audit_budget.hpp"

namespace yuzu::server {

struct ReregistrationVerdict {
    enum class Route {
        Admit,        ///< Carry on to the enrolled path as before.
        TokenReenrol, ///< Run the token block as a re-enrolment (single-use token required).
        Refuse,       ///< Return `refusal` now, before any session state is touched.
    };
    Route route{Route::Admit};
    ReregistrationOutcome outcome{ReregistrationOutcome::NoLeafOnRecord};
    std::optional<grpc::Status> refusal;
};

/// How a handler writes the audit row for a re-registration decision (it owns the AuditStore, the
/// peer address and the principal shape). `action` is one of the two below, `result` the AuditEvent
/// result, `outcome` the `to_string(ReregistrationOutcome)` token. A refused row must never change
/// the outcome of the call: the sink's failure is the sink's to count.
using ReregistrationAuditSink = std::function<void(std::string_view action, std::string_view result,
                                                   std::string_view outcome, std::string_view mode)>;
/// `enforce` refused the re-registration (result `denied`; `failure` for a lookup failure).
inline constexpr std::string_view kAuditActionReregistrationRefused = "agent.reregistration_refused";
/// `audit` mode ADMITTED a re-registration enforce would have refused (result `success`): the row
/// that makes a takeover in the default mode reconstructable.
inline constexpr std::string_view kAuditActionReregistrationUnproven = "agent.reregistration_unproven";

namespace detail {
/// Rows an unauthenticated caller can provoke are bounded per (outcome, agent id) and per window
/// (`bounded_audit_budget.hpp`); the unsampled counter `yuzu_register_reregistration_total` still
/// counts every decision. Log lines get a separate, tighter budget (a restart storm of a whole
/// fleet re-registering must not flood the log).
inline DenialAuditBudget& reregistration_audit_budget() {
    static DenialAuditBudget b;
    return b;
}
inline DenialAuditBudget& reregistration_log_budget() {
    static DenialAuditBudget b{/*max_rows=*/5, /*window_ms=*/10'000};
    return b;
}
} // namespace detail

/// `path` is the metric label ("direct" | "gateway_proxy"). `hooks` may be null (no CA of our own:
/// the gate is inert). `metrics` may be null (the gateway service's registry is optional).
[[nodiscard]] inline ReregistrationVerdict
apply_reregistration_gate(ReregistrationProofMode mode, const AgentIdentityHooks* hooks,
                          std::string_view path, const std::string& agent_id,
                          const std::string& safe_agent_id, const ReregistrationEvidence& ev,
                          yuzu::MetricsRegistry* metrics,
                          const ReregistrationAuditSink& audit = {}) {
    if (mode == ReregistrationProofMode::Off || hooks == nullptr || !hooks->leaf_state)
        return {};

    std::expected<AgentLeafState, std::string> leaf;
    try {
        leaf = hooks->leaf_state(agent_id);
    } catch (...) {
        leaf = std::unexpected(std::string("leaf_state threw"));
    }
    const auto outcome = decide_reregistration(leaf, ev);
    if (metrics) {
        metrics
            ->counter("yuzu_register_reregistration_total",
                      {{"path", std::string(path)},
                       {"outcome", std::string(to_string(outcome))},
                       {"mode", std::string(to_string(mode))}})
            .increment();
    }

    const bool problem = is_refusal(outcome) || outcome == ReregistrationOutcome::LookupFailed;
    const std::string outcome_token(to_string(outcome));
    const auto log_admitted = [&] {
        return problem && detail::reregistration_log_budget()
                              .try_admit(std::string(path) + "|" + outcome_token)
                              .admitted;
    };
    // Only REFUSAL rows (result denied/failure) are budgeted: they are what an unauthenticated
    // caller can flood. The ADMITTED row of audit mode (`agent.reregistration_unproven`, result
    // success) is the evidence that makes a takeover reconstructable (CC7.2), so it is never
    // dropped by the budget: a caller spreading attempts across many ids could otherwise fill the
    // per-key table and push the victim's row into a shared overflow bucket. Its volume is that of
    // the registrations themselves, like the enrollment success rows beside it.
    const auto write_audit = [&](std::string_view action, std::string_view result) {
        if (!audit)
            return;
        if (result != "success" &&
            !detail::reregistration_audit_budget()
                 .try_admit(outcome_token + "|" + agent_id, outcome_token + "|*")
                 .admitted)
            return;
        try {
            audit(action, result, outcome_token, to_string(mode));
        } catch (...) {
        }
    };
    if (mode == ReregistrationProofMode::Audit) {
        // Decide and count exactly as enforce would, admit exactly as before. The id is
        // caller-supplied and arrives already neutralised (log_id_token).
        if (problem) {
            if (log_admitted())
                spdlog::warn("Re-registration of agent {} on the {} path would be REFUSED under "
                             "--agent-reregistration-proof=enforce: {} (admitted: audit mode)",
                             safe_agent_id, path, to_string(outcome));
            write_audit(kAuditActionReregistrationUnproven, "success");
        }
        return {ReregistrationVerdict::Route::Admit, outcome, std::nullopt};
    }

    // Enforce.
    if (outcome == ReregistrationOutcome::LookupFailed) {
        if (log_admitted())
            spdlog::error("Re-registration of agent {} on the {} path: identity lookup failed ({}) "
                          "- refusing, retryable",
                          safe_agent_id, path, leaf ? "" : ::yuzu::log_key_token(leaf.error()));
        write_audit(kAuditActionReregistrationRefused, "failure");
        // UNAVAILABLE, like every other store outage on this path: the agent retries on its
        // normal backoff (accepted=false would be a PERMANENT rejection).
        return {ReregistrationVerdict::Route::Refuse, outcome,
                grpc::Status(grpc::StatusCode::UNAVAILABLE, "registration temporarily unavailable")};
    }
    if (is_refusal(outcome)) {
        if (log_admitted())
            spdlog::warn("Re-registration of agent {} on the {} path refused: {}", safe_agent_id,
                         path, to_string(outcome));
        write_audit(kAuditActionReregistrationRefused, "denied");
        return {ReregistrationVerdict::Route::Refuse, outcome,
                grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                             std::string(kReregistrationRefusalPublicMessage))};
    }
    if (outcome == ReregistrationOutcome::ViaToken)
        return {ReregistrationVerdict::Route::TokenReenrol, outcome, std::nullopt};
    return {ReregistrationVerdict::Route::Admit, outcome, std::nullopt};
}

} // namespace yuzu::server
