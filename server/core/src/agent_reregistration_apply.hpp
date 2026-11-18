#pragma once

/// @file agent_reregistration_apply.hpp
///
/// WP01: the shared APPLICATION of `decide_reregistration` (agent_reregistration_gate.hpp) that both
/// `AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` call from their
/// `approved` fast path. One copy: the lookup, the metric, the mode handling and the refusal status
/// live here, so a handler contributes only its transport's evidence. EXTEND it, never fork it.

#include <atomic>
#include <cctype>
#include <algorithm>
#include <deque>
#include <map>
#include <set>
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
/// provoke. HONEST CLAIM: rows can be DROPPED under load or attack, so the absence of a row is NOT
/// proof that a re-registration did not happen; the authoritative count is the unbudgeted
/// `yuzu_register_reregistration_total{outcome=...}`, and every dropped row is counted
/// (`yuzu_register_reregistration_audit_dropped_total`) and summarised.
///
/// Per 10 s window, per server PROCESS (N replicas = N times these numbers):
///  - repeats of an id seen in the window: `kRepeatRowsPerId` rows, then cut;
///  - a RESERVED bucket (`kReservedRows`) for ids not seen in the last `kRecentIds` admissions
///    (first-ever / long-quiet ids): written regardless of source, so a flood from one source or
///    an exhausted general budget cannot starve a victim whose id is new to the window history;
///  - every other new-id row needs BOTH a per-source slot (`kRowsPerSource`: one peer IP or gateway
///    observed origin cannot spend the window) and a global slot (`kGeneralRows`, the byte backstop).
/// Dropped rows are summarised by ONE aggregate row per closed window, written under a SYSTEM
/// principal with per-source counts, the number of DISTINCT dropped ids and a bounded id list. The
/// summary is flushed by time (`poll_closed`, called from the server's health tick) and at shutdown,
/// not only lazily by a later admit.
/// RESIDUAL: an attacker able to name more than `kReservedRows` brand-new live-leaf ids from many
/// sources inside one window can still drop a victim's row; the count is not lost.
class UnprovenAuditBudget {
public:
    static constexpr std::size_t kRepeatRowsPerId = 3;
    static constexpr std::size_t kReservedRows = 250;
    static constexpr std::size_t kRowsPerSource = 50;
    static constexpr std::size_t kGeneralRows = 1000;
    static constexpr std::size_t kRecentIds = 8192;
    static constexpr std::size_t kMaxTrackedIds = 4096;
    static constexpr std::size_t kSummaryIds = 200;
    static constexpr std::size_t kSummarySources = 10;
    static constexpr std::int64_t kWindowMs = 10'000;

    struct Decision {
        bool admitted{false};
        /// Non-empty only on the call that opens a new window: the CLOSED window's summary.
        std::string closed_summary;
    };

    [[nodiscard]] Decision admit(const std::string& agent_id, const std::string& source,
                                 std::int64_t now_ms) {
        std::lock_guard lk(mu_);
        Decision d;
        d.closed_summary = roll_locked(now_ms, /*force=*/false);
        if (const auto it = seen_.find(agent_id); it != seen_.end()) {
            if (++it->second <= kRepeatRowsPerId) {
                d.admitted = true;
            } else {
                drop_locked(agent_id, source);
            }
            return d;
        }
        const bool first_ever = recent_.find(agent_id) == recent_.end();
        bool ok = false;
        if (first_ever && reserved_rows_ < kReservedRows) {
            ++reserved_rows_;
            ok = true;
        } else if (source_rows_[source] < kRowsPerSource && general_rows_ < kGeneralRows) {
            ++source_rows_[source];
            ++general_rows_;
            ok = true;
        }
        if (!ok) {
            drop_locked(agent_id, source);
            return d;
        }
        if (seen_.size() < kMaxTrackedIds)
            seen_.emplace(agent_id, 1);
        remember_locked(agent_id);
        d.admitted = true;
        return d;
    }

    /// Time-based flush: the closed window's summary (empty if the window is still open or nothing
    /// was dropped). `force` closes the open window too (shutdown).
    [[nodiscard]] std::string poll_closed(std::int64_t now_ms, bool force) {
        std::lock_guard lk(mu_);
        return roll_locked(now_ms, force);
    }

private:
    std::string roll_locked(std::int64_t now_ms, bool force) {
        std::string out;
        if (open_ && (force || now_ms >= start_ms_ + kWindowMs)) {
            if (dropped_rows_ > 0)
                out = summary_locked();
            open_ = false;
            reset_window_locked();
        }
        if (!open_ && !force) {
            open_ = true;
            start_ms_ = now_ms;
        }
        return out;
    }
    void reset_window_locked() {
        seen_.clear();
        source_rows_.clear();
        general_rows_ = reserved_rows_ = 0;
        dropped_rows_ = 0;
        dropped_by_source_.clear();
        dropped_ids_.clear();
        dropped_ids_overflow_ = 0;
    }
    void drop_locked(const std::string& id, const std::string& source) {
        ++dropped_rows_;
        ++dropped_by_source_[source.substr(0, 45)];
        if (dropped_ids_.size() < kMaxTrackedIds)
            dropped_ids_.insert(id);
        else if (dropped_ids_.find(id) == dropped_ids_.end())
            ++dropped_ids_overflow_;
    }
    void remember_locked(const std::string& id) {
        if (recent_.insert(id).second) {
            recent_order_.push_back(id);
            if (recent_order_.size() > kRecentIds) {
                recent_.erase(recent_order_.front());
                recent_order_.pop_front();
            }
        }
    }
    static std::string neutralise(const std::string& id) {
        std::string out;
        for (const char c : id.substr(0, 24))
            out.push_back((std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' ||
                           c == ':' || c == '-')
                              ? c
                              : '?');
        return out;
    }
    std::string summary_locked() const {
        std::string s = "dropped_rows=" + std::to_string(dropped_rows_) +
                        " distinct_dropped_ids=" +
                        std::to_string(dropped_ids_.size() + dropped_ids_overflow_) +
                        " sources=";
        std::vector<std::pair<std::size_t, std::string>> by;
        for (const auto& [src, n] : dropped_by_source_)
            by.emplace_back(n, src);
        std::sort(by.rbegin(), by.rend());
        for (std::size_t i = 0; i < by.size() && i < kSummarySources; ++i)
            s += (i ? "," : "") + neutralise(by[i].second) + ":" + std::to_string(by[i].first);
        s += " ids=";
        std::size_t n = 0;
        for (const auto& id : dropped_ids_) {
            if (n++ >= kSummaryIds)
                break;
            s += (n > 1 ? "," : "") + neutralise(id);
        }
        return s;
    }
    std::mutex mu_;
    bool open_{false};
    std::int64_t start_ms_{0};
    std::map<std::string, std::size_t> seen_;
    std::map<std::string, std::size_t> source_rows_;
    std::size_t general_rows_{0};
    std::size_t reserved_rows_{0};
    std::uint64_t dropped_rows_{0};
    std::map<std::string, std::size_t> dropped_by_source_;
    std::set<std::string> dropped_ids_;
    std::uint64_t dropped_ids_overflow_{0};
    std::set<std::string> recent_;
    std::deque<std::string> recent_order_;
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
        if (!store || !store->is_open()) {
            // A budget slot was spent for a row that cannot be written: count it and say so (rate
            // limited), never silently.
            if (metrics)
                metrics
                    ->counter("yuzu_register_reregistration_audit_write_failures_total",
                              {{"reason", "store_unavailable"}})
                    .increment();
            if (detail::reregistration_log_budget().try_admit("audit-store-unavailable").admitted)
                spdlog::warn("Re-registration audit row NOT written: the audit store is not open "
                             "(action {})",
                             action);
            return;
        }
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
                metrics
                    ->counter("yuzu_register_reregistration_audit_write_failures_total",
                              {{"reason", "write_failed"}})
                    .increment();
            if (on_write_failure)
                on_write_failure();
        }
    };
}

/// Time-based / shutdown flush of the closed window's dropped-row summary (see
/// UnprovenAuditBudget): called from the server's periodic tick and at stop(), so the summary is
/// not lost when no later admit opens the next window. `store` may be null (counted, not written).
inline void flush_reregistration_audit_summary(AuditStore* store, yuzu::MetricsRegistry* metrics,
                                               bool force) {
    const auto summary =
        detail::reregistration_unproven_budget().poll_closed(detail::reregistration_audit_now_ms(), force);
    if (summary.empty())
        return;
    const auto sink = make_reregistration_audit_sink(store, "server", "*", "", nullptr, nullptr, metrics);
    sink(kAuditActionReregistrationUnproven, "success", "aggregate", "audit", summary);
}

/// `path` is the metric label ("direct" | "gateway_proxy"). `hooks` may be null (no CA of our own:
/// the gate is inert). `metrics` may be null (the gateway service's registry is optional).
[[nodiscard]] inline ReregistrationVerdict
apply_reregistration_gate(ReregistrationProofMode mode, const AgentIdentityHooks* hooks,
                          std::string_view path, const std::string& agent_id,
                          const std::string& safe_agent_id, const ReregistrationEvidence& ev,
                          yuzu::MetricsRegistry* metrics,
                          const ReregistrationAuditSink& audit = {},
                          std::string_view source = {}) {
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
                agent_id, std::string(source), detail::reregistration_audit_now_ms());
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
