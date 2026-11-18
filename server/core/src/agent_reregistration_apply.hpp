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
/// `extra` is appended to the row's detail (empty, or one aggregate chunk's text).
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
///    (first-ever / long-quiet ids): written regardless of source;
///  - every other new-id row needs BOTH a per-source slot (`kRowsPerSource`) and a global slot
///    (`kGeneralRows`, the byte backstop). At most `kMaxSources` distinct sources are tracked; the
///    rest share ONE `other` bucket (no per-source cap, the global slot still applies).
/// A row that loses the budget is NOT lost as evidence of WHICH ids: its id is remembered, in DROP
/// order, up to `kMaxDroppedIds` distinct ids per window, and the closed window is written as
/// CHUNKED aggregate rows (at most `kSummaryIds` ids per row, every chunk repeating the per-source
/// counts and `ids_truncated=N`). One source naming 300 distinct live-leaf ids in 10 s, a restart
/// storm behind one origin-less gateway, or 2000 rotating sources therefore still leave every
/// dropped id on record. Chunks are built OUTSIDE `mu_`, queued in a bounded pending deque
/// (`kMaxPendingRows`), and written ONLY by the server's health tick and by stop()
/// (`flush_reregistration_audit_summary`), never on a Register thread.
/// RESIDUAL (MEDIUM, conditional on this bounded wording and on the alert
/// `YuzuRegisterReregistrationAuditIdsTruncated`): more than `kMaxDroppedIds` DISTINCT dropped ids
/// in one window leave the excess unnamed (counted: `ids_truncated=N` on every chunk and
/// `yuzu_register_reregistration_audit_ids_truncated_total`); a pending queue overflow, a failed
/// write after `kMaxWriteAttempts`, or a shutdown that runs out of time drops the chunk (counted:
/// `yuzu_register_reregistration_audit_summary_dropped_total{reason}`). The authoritative decision
/// count is always the unbudgeted counter.
class UnprovenAuditBudget {
public:
    static constexpr std::size_t kRepeatRowsPerId = 3;
    static constexpr std::size_t kReservedRows = 250;
    static constexpr std::size_t kRowsPerSource = 50;
    static constexpr std::size_t kGeneralRows = 1000;
    static constexpr std::size_t kRecentIds = 8192;
    static constexpr std::size_t kMaxTrackedIds = 4096;
    static constexpr std::size_t kSummaryIds = 200;
    static constexpr std::size_t kMaxSources = 1024;
    static constexpr std::size_t kMaxDroppedIds = 20000;
    static constexpr std::size_t kSummarySources = 10;
    static constexpr std::size_t kMaxPendingRows = 128;
    static constexpr int kMaxWriteAttempts = 3;
    static constexpr std::int64_t kWindowMs = 10'000;

    struct Decision {
        bool admitted{false};
        /// Non-empty only on the call that opens a new window: the CLOSED window's chunk rows (one
        /// element per audit row; the sink does not split on newlines). Already queued for the
        /// flush: a caller never writes them.
        std::vector<std::string> closed_summary;
    };

    struct PendingRow {
        std::string text;
        int attempts{0};
    };

    [[nodiscard]] Decision admit(const std::string& agent_id, const std::string& source,
                                 std::int64_t now_ms) {
        Decision d;
        std::optional<ClosedWindow> closed;
        {
            std::lock_guard lk(mu_);
            closed = roll_locked(now_ms, /*force=*/false);
            admit_locked(d, agent_id, source);
        }
        if (closed)
            d.closed_summary = enqueue_closed(*closed);
        return d;
    }

    /// Time-based flush: closes the window when due (or `force`) and returns the NEW chunk rows
    /// (already queued for `take_pending`). Empty if the window is still open or nothing was dropped.
    [[nodiscard]] std::vector<std::string> poll_closed(std::int64_t now_ms, bool force) {
        std::optional<ClosedWindow> closed;
        {
            std::lock_guard lk(mu_);
            closed = roll_locked(now_ms, force);
        }
        if (!closed)
            return {};
        return enqueue_closed(*closed);
    }

    /// The oldest queued chunk, if any. The caller writes it and, on failure, hands it back with
    /// `requeue_front` (bounded by `kMaxWriteAttempts`).
    [[nodiscard]] std::optional<PendingRow> take_pending() {
        std::lock_guard lk(pending_mu_);
        if (pending_.empty())
            return std::nullopt;
        auto r = std::move(pending_.front());
        pending_.pop_front();
        return r;
    }
    /// Returns false (chunk dropped) once the row has failed `kMaxWriteAttempts` times.
    [[nodiscard]] bool requeue_front(PendingRow r) {
        if (++r.attempts >= kMaxWriteAttempts)
            return false;
        std::lock_guard lk(pending_mu_);
        pending_.push_front(std::move(r));
        return true;
    }
    /// Hands a chunk back unchanged (the deadline ran out before it was tried: not a failed attempt).
    void requeue_front_unconditional(PendingRow r) {
        std::lock_guard lk(pending_mu_);
        pending_.push_front(std::move(r));
    }
    [[nodiscard]] std::size_t pending_size() const {
        std::lock_guard lk(pending_mu_);
        return pending_.size();
    }
    /// Discards everything still queued (shutdown out of time); returns how many.
    [[nodiscard]] std::size_t discard_pending() {
        std::lock_guard lk(pending_mu_);
        const auto n = pending_.size();
        pending_.clear();
        return n;
    }
    /// Counts accumulated since the last call, for the flush to publish as counters (the budget
    /// holds no MetricsRegistry).
    [[nodiscard]] std::uint64_t take_ids_truncated() { return ids_truncated_.exchange(0); }
    [[nodiscard]] std::uint64_t take_queue_full_dropped() { return queue_full_dropped_.exchange(0); }

private:
    /// The state of a closed window, moved out of the lock so the chunks are built outside it.
    struct ClosedWindow {
        std::uint64_t dropped_rows{0};
        std::map<std::string, std::size_t> by_source;
        std::vector<std::string> ids; ///< distinct dropped ids in DROP order
        std::uint64_t ids_overflow{0};
    };

    void admit_locked(Decision& d, const std::string& agent_id, const std::string& raw_source) {
        const std::string& src = clamp_source(raw_source);
        if (const auto it = seen_.find(agent_id); it != seen_.end()) {
            if (++it->second <= kRepeatRowsPerId)
                d.admitted = true;
            else
                drop_locked(agent_id, src);
            return;
        }
        const bool first_ever = recent_.find(agent_id) == recent_.end();
        bool ok = false;
        if (first_ever && reserved_rows_ < kReservedRows) {
            ++reserved_rows_;
            ok = true;
        } else if ((src == kOther || source_rows_[src] < kRowsPerSource) &&
                   general_rows_ < kGeneralRows) {
            ++source_rows_[src];
            ++general_rows_;
            ok = true;
        }
        if (!ok) {
            drop_locked(agent_id, src);
            return;
        }
        if (seen_.size() < kMaxTrackedIds)
            seen_.emplace(agent_id, 1);
        remember_locked(agent_id);
        d.admitted = true;
    }

    std::optional<ClosedWindow> roll_locked(std::int64_t now_ms, bool force) {
        std::optional<ClosedWindow> out;
        if (open_ && (force || now_ms >= start_ms_ + kWindowMs)) {
            if (dropped_rows_ > 0) {
                ClosedWindow w;
                w.dropped_rows = dropped_rows_;
                w.by_source = std::move(dropped_by_source_);
                w.ids = std::move(dropped_order_);
                w.ids_overflow = dropped_ids_overflow_;
                out = std::move(w);
            }
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
        dropped_order_.clear();
        dropped_ids_overflow_ = 0;
    }
    void drop_locked(const std::string& id, const std::string& source) {
        ++dropped_rows_;
        ++dropped_by_source_[source.substr(0, 45)];
        if (dropped_ids_.find(id) == dropped_ids_.end()) {
            if (dropped_ids_.size() < kMaxDroppedIds) {
                dropped_ids_.insert(id);
                dropped_order_.push_back(id);
            } else {
                ++dropped_ids_overflow_;
            }
        }
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
    static inline const std::string kOther{"other"};
    /// A source already tracked keeps its own entry; a NEW one past `kMaxSources` shares `other`.
    const std::string& clamp_source(const std::string& s) const {
        if (source_rows_.count(s) || dropped_by_source_.count(s.substr(0, 45)) ||
            source_rows_.size() + dropped_by_source_.size() < kMaxSources)
            return s;
        return kOther;
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
    /// One row per element, each at most `kSummaryIds` ids; every row repeats the head.
    static std::vector<std::string> build_rows(const ClosedWindow& w) {
        std::string head = "dropped_rows=" + std::to_string(w.dropped_rows) +
                           " distinct_dropped_ids=" + std::to_string(w.ids.size() + w.ids_overflow) +
                           " sources=";
        std::vector<std::pair<std::size_t, std::string>> by;
        for (const auto& [src, n] : w.by_source)
            by.emplace_back(n, src);
        std::sort(by.rbegin(), by.rend());
        for (std::size_t i = 0; i < by.size() && i < kSummarySources; ++i)
            head += (i ? "," : "") + neutralise(by[i].second) + ":" + std::to_string(by[i].first);
        const std::size_t parts = std::max<std::size_t>(1, (w.ids.size() + kSummaryIds - 1) / kSummaryIds);
        std::vector<std::string> rows;
        rows.reserve(parts);
        for (std::size_t p = 0; p < parts; ++p) {
            std::string r = head + " ids_truncated=" + std::to_string(w.ids_overflow) +
                            " part=" + std::to_string(p + 1) + "/" + std::to_string(parts) +
                            " ids=";
            for (std::size_t k = p * kSummaryIds; k < w.ids.size() && k < (p + 1) * kSummaryIds; ++k)
                r += (k % kSummaryIds ? "," : "") + neutralise(w.ids[k]);
            rows.push_back(std::move(r));
        }
        return rows;
    }
    /// Builds the chunks (no lock held) and queues them; a full queue drops the new chunk, counted.
    std::vector<std::string> enqueue_closed(const ClosedWindow& w) {
        auto rows = build_rows(w);
        ids_truncated_.fetch_add(w.ids_overflow);
        std::lock_guard lk(pending_mu_);
        for (const auto& r : rows) {
            if (pending_.size() >= kMaxPendingRows)
                queue_full_dropped_.fetch_add(1);
            else
                pending_.push_back(PendingRow{r, 0});
        }
        return rows;
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
    std::vector<std::string> dropped_order_;
    std::uint64_t dropped_ids_overflow_{0};
    std::set<std::string> recent_;
    std::deque<std::string> recent_order_;

    mutable std::mutex pending_mu_;
    std::deque<PendingRow> pending_;
    std::atomic<std::uint64_t> ids_truncated_{0};
    std::atomic<std::uint64_t> queue_full_dropped_{0};
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

/// Time-based / shutdown flush of the closed windows' dropped-row summary chunks (see
/// UnprovenAuditBudget). The ONLY writer of those rows: the server's health tick (deadline 1 s) and
/// stop() (`force`, deadline 2 s). A chunk that fails to write is retried on the next tick up to
/// `kMaxWriteAttempts`; chunks that cannot be written are counted
/// (`yuzu_register_reregistration_audit_summary_dropped_total{reason}`), never silently lost.
/// `store` may be null/closed (counted as a failed attempt). `deadline_ms` bounds the time spent
/// writing; the remainder stays queued (or, at `force`, is dropped with reason `shutdown`).
inline void flush_reregistration_audit_summary(AuditStore* store, yuzu::MetricsRegistry* metrics,
                                               bool force, std::int64_t deadline_ms = -1) {
    auto& budget = detail::reregistration_unproven_budget();
    const auto count_dropped = [&](std::string_view reason, std::uint64_t n) {
        if (metrics && n)
            metrics
                ->counter("yuzu_register_reregistration_audit_summary_dropped_total",
                          {{"reason", std::string(reason)}})
                .increment(static_cast<double>(n));
    };
    (void)budget.poll_closed(detail::reregistration_audit_now_ms(), force);
    if (const auto n = budget.take_ids_truncated(); n && metrics)
        metrics->counter("yuzu_register_reregistration_audit_ids_truncated_total")
            .increment(static_cast<double>(n));
    count_dropped("queue_full", budget.take_queue_full_dropped());
    if (deadline_ms < 0)
        deadline_ms = force ? 2000 : 1000;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms);
    bool failed = false;
    const auto sink = make_reregistration_audit_sink(store, "server", "*", "", nullptr,
                                                     [&] { failed = true; }, metrics);
    while (auto row = budget.take_pending()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            budget.requeue_front_unconditional(std::move(*row));
            break;
        }
        failed = !(store && store->is_open());
        if (!failed) {
            try {
                sink(kAuditActionReregistrationUnproven, "success", "aggregate", "audit", row->text);
            } catch (...) {
                failed = true;
            }
        }
        if (failed) {
            if (!budget.requeue_front(std::move(*row)))
                count_dropped("write_failed", 1);
            break; // a failing store: retry on the next tick, not in a tight loop
        }
    }
    if (force)
        count_dropped("shutdown", budget.discard_pending());
}

/// A single-use token was CONSUMED to re-enrol an id that holds a live leaf, but no new leaf was
/// issued (the agent sent no CSR, no signer is wired, the signer answered nothing, or it threw). The
/// token is spent and the old leaf is not superseded: the operator-visible signal is this counter
/// (`reason` is one of the four spellings below, all seeded at boot) and the alert
/// `YuzuAgentReenrolTokenNoLeaf`. ONE copy for both ingest paths.
inline constexpr std::string_view kReenrolNoLeafNoCsr = "no_csr";
inline constexpr std::string_view kReenrolNoLeafNoSigner = "no_signer";
inline constexpr std::string_view kReenrolNoLeafSignerFailed = "signer_failed";
inline constexpr std::string_view kReenrolNoLeafSignerThrew = "signer_threw";
inline void count_reenrol_token_no_leaf(yuzu::MetricsRegistry* metrics, std::string_view reason) {
    if (metrics)
        metrics->counter("yuzu_register_reenrol_token_no_leaf_total", {{"reason", std::string(reason)}})
            .increment();
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
            // A window this call closes is queued inside the budget and written ONLY by the health
            // tick / stop() (flush_reregistration_audit_summary): never on a Register thread.
            const auto r = detail::reregistration_unproven_budget().admit(
                agent_id, std::string(source), detail::reregistration_audit_now_ms());
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
