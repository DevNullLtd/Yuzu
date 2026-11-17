#pragma once

/// @file agent_reregistration_apply.hpp
///
/// WP01: the shared APPLICATION of `decide_reregistration` (agent_reregistration_gate.hpp) that both
/// `AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` call from their
/// `approved` fast path. One copy: the lookup, the metric, the mode handling and the refusal status
/// live here, so a handler contributes only its transport's evidence. EXTEND it, never fork it.

#include <optional>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "agent_reregistration_gate.hpp"

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

/// `path` is the metric label ("direct" | "gateway_proxy"). `hooks` may be null (no CA of our own:
/// the gate is inert). `metrics` may be null (the gateway service's registry is optional).
[[nodiscard]] inline ReregistrationVerdict
apply_reregistration_gate(ReregistrationProofMode mode, const AgentIdentityHooks* hooks,
                          std::string_view path, const std::string& agent_id,
                          const std::string& safe_agent_id, const ReregistrationEvidence& ev,
                          yuzu::MetricsRegistry* metrics) {
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
    if (mode == ReregistrationProofMode::Audit) {
        // Decide and count exactly as enforce would, admit exactly as before. The id is
        // caller-supplied and arrives already neutralised (log_id_token).
        if (problem) {
            spdlog::warn("Re-registration of agent {} on the {} path would be REFUSED under "
                         "--agent-reregistration-proof=enforce: {} (admitted: audit mode)",
                         safe_agent_id, path, to_string(outcome));
        }
        return {ReregistrationVerdict::Route::Admit, outcome, std::nullopt};
    }

    // Enforce.
    if (outcome == ReregistrationOutcome::LookupFailed) {
        spdlog::error("Re-registration of agent {} on the {} path: identity lookup failed ({}) - "
                      "refusing, retryable",
                      safe_agent_id, path, leaf ? "" : ::yuzu::log_key_token(leaf.error()));
        // UNAVAILABLE, like every other store outage on this path: the agent retries on its
        // normal backoff (accepted=false would be a PERMANENT rejection).
        return {ReregistrationVerdict::Route::Refuse, outcome,
                grpc::Status(grpc::StatusCode::UNAVAILABLE, "registration temporarily unavailable")};
    }
    if (is_refusal(outcome)) {
        spdlog::warn("Re-registration of agent {} on the {} path refused: {}", safe_agent_id, path,
                     to_string(outcome));
        return {ReregistrationVerdict::Route::Refuse, outcome,
                grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                             std::string(kReregistrationRefusalPublicMessage))};
    }
    if (outcome == ReregistrationOutcome::ViaToken)
        return {ReregistrationVerdict::Route::TokenReenrol, outcome, std::nullopt};
    return {ReregistrationVerdict::Route::Admit, outcome, std::nullopt};
}

} // namespace yuzu::server
