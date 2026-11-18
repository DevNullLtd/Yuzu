#pragma once

/// @file agent_reregistration_apply.hpp
///
/// WP01: the shared APPLICATION of `decide_reregistration` (agent_reregistration_gate.hpp) that both
/// `AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` call from their
/// `approved` fast path. One copy: the lookup, the metric, the mode handling and the refusal status
/// live here, so a handler contributes only its transport's evidence. EXTEND it, never fork it.

#include <atomic>
#include <cctype>
#include <map>
#include <mutex>
#include <vector>
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
/// Budget for the ADMITTED row of audit mode (`agent.reregistration_unproven`, result success): the
/// evidence that makes a takeover reconstructable (CC7.2), and a row an unauthenticated caller can
/// provoke. The design, and what it cannot do:
///  - a FIRST admit for an id in a window ALWAYS leaves its row, whatever else the window holds
///    (the table of seen ids filling up does not suppress a new id: it only stops tracking its
///    repeats), up to a GLOBAL cap of `kNewIdRowsPerWindow` such rows per window;
///  - REPEATS of an id already seen in the window are cut to `kRepeatRowsPerId` rows;
///  - everything cut (repeats, and new ids past the global cap) is counted per window and
///    summarised by ONE aggregate row when the next window opens, written under a SYSTEM
///    principal (never the opening caller's identity) with the totals and a bounded sample of the
///    suppressed ids, and by `yuzu_register_reregistration_audit_dropped_total`.
/// RESIDUAL: the global cap bounds bytes (500 new-id rows / 10 s is about 1.4 GB/day at ~330 B, versus
/// ~28 GB/day uncapped at 1000/s), so an attacker who can name more than 500 live-leaf ids inside one
/// window can push a victim's FIRST row past the cap: that row is dropped, counted and summarised,
/// not written. `yuzu_register_reregistration_total{outcome=...}` is NOT budgeted and is the
/// authoritative count of every decision; the unproven-rows alert fires on it.
class UnprovenAuditBudget {
public:
    static constexpr std::size_t kNewIdRowsPerWindow = 500;
    static constexpr std::size_t kRepeatRowsPerId = 3;
    static constexpr std::size_t kMaxTrackedIds = 4096;
    static constexpr std::size_t kSampleIds = 5;
    static constexpr std::int64_t kWindowMs = 10'000;

    struct Decision {
        bool admitted{false};
        /// Non-empty only on the call that opens a new window: the CLOSED window's summary.
        std::string closed_summary;
    };

    [[nodiscard]] Decision admit(const std::string& agent_id, std::int64_t now_ms) {
        std::lock_guard lk(mu_);
        Decision d;
        if (!open_ || now_ms >= start_ms_ + kWindowMs) {
            if (open_ && (suppressed_repeats_ > 0 || dropped_new_ > 0))
                d.closed_summary = summary_locked();
            open_ = true;
            start_ms_ = now_ms;
            seen_.clear();
            window_new_rows_ = 0;
            suppressed_repeats_ = dropped_new_ = 0;
            sample_.clear();
        }
        if (const auto it = seen_.find(agent_id); it != seen_.end()) {
            if (++it->second <= kRepeatRowsPerId) {
                d.admitted = true;
            } else {
                ++suppressed_repeats_;
                note_sample_locked(agent_id);
            }
            return d;
        }
        if (window_new_rows_ >= kNewIdRowsPerWindow) {
            ++dropped_new_;
            note_sample_locked(agent_id);
            return d;
        }
        ++window_new_rows_;
        if (seen_.size() < kMaxTrackedIds)
            seen_.emplace(agent_id, 1);
        d.admitted = true;
        return d;
    }

private:
    static std::string neutralise(const std::string& id) {
        std::string out;
        for (const char c : id.substr(0, 24))
            out.push_back((std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' ||
                           c == ':' || c == '-')
                              ? c
                              : '?');
        return out;
    }
    void note_sample_locked(const std::string& id) {
        if (sample_.size() < kSampleIds)
            sample_.push_back(neutralise(id));
    }
    std::string summary_locked() const {
        std::string s = "suppressed_repeats=" + std::to_string(suppressed_repeats_) +
                        " dropped_new_ids=" + std::to_string(dropped_new_) + " sample_ids=";
        for (std::size_t i = 0; i < sample_.size(); ++i)
            s += (i ? "," : "") + sample_[i];
        return s;
    }
    std::mutex mu_;
    bool open_{false};
    std::int64_t start_ms_{0};
    std::map<std::string, std::size_t> seen_;
    std::size_t window_new_rows_{0};
    std::uint64_t suppressed_repeats_{0};
    std::uint64_t dropped_new_{0};
    std::vector<std::string> sample_;
};
inline UnprovenAuditBudget& reregistration_unproven_budget() {
    static UnprovenAuditBudget b;
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
        const bool aggregate = outcome == "aggregate";
        // An aggregate row summarises OTHER ids and sources: it carries no caller identity
        // (system principal, target `*`, no source address, no path).
        ev.principal = aggregate ? std::string("system:reregistration-audit") : "agent:" + agent_id;
        ev.principal_role = aggregate ? "system" : "agent";
        ev.action = std::string(action);
        ev.target_type = "Agent";
        ev.target_id = aggregate ? std::string("*") : agent_id;
        std::string d = (aggregate ? std::string("outcome=aggregate") : "path=" + path + " outcome=" + std::string(outcome)) +
                        " mode=" + std::string(mode);
        if (!extra.empty())
            d.append(" ").append(extra);
        if (extend_detail && !aggregate)
            extend_detail(d);
        ev.detail = std::move(d);
        ev.source_ip = aggregate ? std::string{} : source_ip;
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
            const auto r = detail::reregistration_unproven_budget().admit(
                agent_id, detail::reregistration_audit_now_ms());
            // The closed window's summary: ONE row under a system principal (the sink keys on
            // outcome "aggregate"), never stamped with this (opening) caller's identity.
            if (!r.closed_summary.empty())
                emit(action, result, "aggregate", r.closed_summary);
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
