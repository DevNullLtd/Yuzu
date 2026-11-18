#pragma once

/// @file agent_reregistration_apply.hpp
///
/// WP01: the shared APPLICATION of `decide_reregistration` (agent_reregistration_gate.hpp) that both
/// `AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` call from their
/// `approved` fast path. One copy: the lookup, the metric, the mode handling and the refusal status
/// live here, so a handler contributes only its transport's evidence. EXTEND it, never fork it.

#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "agent_reregistration_gate.hpp"
#include "audit_store.hpp"
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
/// `extra` is appended to the row's detail (empty, or the aggregate row's `suppressed=N`).
using ReregistrationAuditSink =
    std::function<void(std::string_view action, std::string_view result, std::string_view outcome,
                       std::string_view mode, std::string_view extra)>;
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
/// TEST HOOK: milliseconds added to the audit budgets' clock, so a unit test can close a window
/// without sleeping. Zero in production (nothing outside tests writes it).
inline std::atomic<std::int64_t>& reregistration_audit_clock_skew_ms() {
    static std::atomic<std::int64_t> skew{0};
    return skew;
}
inline std::int64_t reregistration_audit_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
               .count() +
           reregistration_audit_clock_skew_ms().load(std::memory_order_relaxed);
}
inline DenialAuditBudget& reregistration_audit_budget() {
    static DenialAuditBudget b{kDefaultAuditMaxRows, kDefaultAuditWindowMs,
                               &reregistration_audit_now_ms};
    return b;
}
/// The ADMITTED row of audit mode (`agent.reregistration_unproven`, result success) is the evidence
/// that makes a takeover reconstructable, so a legitimate first admit for an id in a window always
/// leaves a row: it is budgeted PER ID (3 rows per id per 10 s, up to 4096 ids tracked) and an
/// attacker looping on one known id is cut to that, with ONE aggregate row `suppressed=N` per
/// closed window plus `yuzu_register_reregistration_audit_dropped_total`. Unbudgeted, a loop
/// wrote one 330-byte row per attempt (about 28 GB/day at 1000 attempts/s).
inline DenialAuditBudget& reregistration_unproven_budget() {
    static DenialAuditBudget b{/*max_rows=*/3, /*window_ms=*/10'000, &reregistration_audit_now_ms,
                               /*max_keys=*/4096};
    return b;
}
inline DenialAuditBudget& reregistration_log_budget() {
    static DenialAuditBudget b{/*max_rows=*/5, /*window_ms=*/10'000};
    return b;
}
} // namespace detail

/// ONE audit-sink factory for both ingest paths (the two services used to hand-copy it, and the
/// gateway copy discarded a failed write). `store` may be null/closed (no row). `source_ip` is the
/// agent's address (direct: the transport peer; gateway: the observed origin). `extend_detail` lets
/// the gateway path append its origin fields. A failed write is counted
/// (`yuzu_register_reregistration_audit_write_failures_total`) and reported to `on_write_failure`
/// (the direct path surfaces it on the wire like the enrollment rows).
[[nodiscard]] inline ReregistrationAuditSink make_reregistration_audit_sink(
    AuditStore* store, std::string_view path, std::string agent_id, std::string source_ip,
    std::function<void(std::string&)> extend_detail, std::function<void()> on_write_failure,
    yuzu::MetricsRegistry* metrics) {
    return [=, path = std::string(path), agent_id = std::move(agent_id),
            source_ip = std::move(source_ip)](std::string_view action, std::string_view result,
                                               std::string_view outcome, std::string_view mode,
                                               std::string_view extra) {
        if (!store || !store->is_open())
            return;
        AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = "agent:" + agent_id;
        ev.principal_role = "agent";
        ev.action = std::string(action);
        ev.target_type = "Agent";
        ev.target_id = agent_id;
        std::string d = "path=" + path + " outcome=" + std::string(outcome) +
                        " mode=" + std::string(mode);
        if (!extra.empty())
            d.append(" ").append(extra);
        if (extend_detail)
            extend_detail(d);
        ev.detail = std::move(d);
        ev.source_ip = source_ip;
        ev.result = std::string(result);
        if (!store->log(ev)) {
            if (metrics)
                metrics->counter("yuzu_register_reregistration_audit_write_failures_total").increment();
            if (on_write_failure)
                on_write_failure();
        }
    };
}

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
    // Refusal rows (denied/failure) are bounded per (outcome, agent id); the admitted audit-mode
    // row is bounded per agent id with an aggregate row per closed window (see
    // reregistration_unproven_budget). Neither bound changes the call's outcome, and the unsampled
    // counter yuzu_register_reregistration_total counts every decision.
    const auto emit = [&](std::string_view action, std::string_view result,
                          std::string_view outcome_text, std::string_view extra) {
        try {
            audit(action, result, outcome_text, to_string(mode), extra);
        } catch (...) {
        }
    };
    const auto write_audit = [&](std::string_view action, std::string_view result) {
        if (!audit)
            return;
        if (result == "success") {
            const auto r = detail::reregistration_unproven_budget().try_admit(agent_id, "*");
            if (r.closed_window_suppressed > 0)
                emit(action, result, "aggregate",
                     "suppressed=" + std::to_string(r.closed_window_suppressed));
            if (!r.admitted) {
                if (metrics)
                    metrics
                        ->counter("yuzu_register_reregistration_audit_dropped_total",
                                  {{"action", std::string(action)}})
                        .increment();
                return;
            }
        } else if (!detail::reregistration_audit_budget()
                        .try_admit(outcome_token + "|" + agent_id, outcome_token + "|*")
                        .admitted) {
            if (metrics)
                metrics
                    ->counter("yuzu_register_reregistration_audit_dropped_total",
                              {{"action", std::string(action)}})
                    .increment();
            return;
        }
        emit(action, result, outcome_token, {});
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
