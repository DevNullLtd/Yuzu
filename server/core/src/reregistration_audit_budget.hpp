#pragma once

/// @file reregistration_audit_budget.hpp
///
/// WP01: the bounded budget for the audit-mode "unproven re-registration" row and the chunked
/// summary of the rows it drops. Standard library only (no store, wire or metrics types), so it is
/// unit-testable in isolation, including under allocation-failure injection
/// (tests/unit/server/test_reregistration_audit_budget_alloc.cpp). The audit-sink wiring and the
/// flush live in agent_reregistration_apply.hpp.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::detail {

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
/// A row that loses the budget is not written, but its id is remembered, in DROP order, up to
/// `kMaxDroppedIds` distinct ids per window, and the closed window is written as CHUNKED aggregate
/// rows (at most `kSummaryIds` ids per row, every chunk repeating the per-source counts and
/// `ids_beyond_cap_max=N`). Chunks are built OUTSIDE `mu_`, queued in a bounded pending deque
/// (`kMaxPendingRows`), and written ONLY by the server's flush (`flush_reregistration_audit_summary`,
/// every 5 s from its own thread, and at stop()), never on a Register thread. A dropped id is
/// NAMED in a row only when that flush succeeds.
/// WHAT IS NOT GUARANTEED (MEDIUM residual, conditional on this wording and on the alerts
/// `YuzuAgentReregistrationAuditIdsTruncated` / `...AuditSummaryDropped`): the open window and the
/// queue are memory only, so a process kill loses the ids of up to one open window plus the unflushed
/// chunks (measured 47-65% of recent ids in a kill test); ids are cut to 24 characters in a row; more
/// than `kMaxDroppedIds` distinct drops in one window (the figure `distinct_dropped_ids_max` and the
/// count beyond the cap are UPPER BOUNDS: an over-cap id is not remembered, so each repeat of it is
/// counted again), a chunk dropped because the queue was full,
/// the write failed three times, or it was still queued at shutdown, and a window whose summary
/// could not be built (allocation failure) leave their ids UNNAMED; every one of those is counted BY
/// ID in `yuzu_register_reregistration_audit_ids_truncated_total` (chunks, by cause, in
/// `yuzu_register_reregistration_audit_summary_dropped_total{reason}`). The authoritative decision
/// count is always the unbudgeted `yuzu_register_reregistration_total`.
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
        std::size_t ids{0}; ///< ids this chunk names (counted as unnamed if the chunk is dropped)
    };

    [[nodiscard]] Decision admit(const std::string& agent_id, const std::string& source,
                                 std::int64_t now_ms) {
        Decision d;
        std::optional<ClosedWindow> closed;
        // Never throws: an allocation failure (or anything else) inside the lock costs only THIS
        // row (not admitted, so the caller counts it dropped) and must not lose the window that was
        // just moved out, which is queued (or, failing that, counted) below.
        try {
            std::lock_guard lk(mu_);
            closed = roll_locked(now_ms, /*force=*/false);
            admit_locked(d, agent_id, source);
        } catch (...) {
            d.admitted = false;
            note_unrecorded(); // this row's id may be in no summary: counted (an upper bound of 1)
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
    /// Returns false (chunk dropped, its ids counted) once the row has failed `kMaxWriteAttempts`
    /// times, or if handing it back cannot allocate (counted as `alloc_failed`). Never throws.
    [[nodiscard]] bool requeue_front(PendingRow r) noexcept {
        const std::size_t ids = r.ids;
        if (++r.attempts >= kMaxWriteAttempts) {
            ids_truncated_.fetch_add(ids); // the chunk is dropped: its ids are now unnamed
            return false;
        }
        try {
            std::lock_guard lk(pending_mu_);
            pending_.push_front(std::move(r));
            return true;
        } catch (...) {
            alloc_failed_.fetch_add(1);
            ids_truncated_.fetch_add(ids);
            return false;
        }
    }
    /// Hands a chunk back unchanged (the deadline ran out before it was tried: not a failed attempt).
    /// Never throws; if it cannot be re-queued the chunk is dropped and its ids are counted.
    void requeue_front_unconditional(PendingRow r) noexcept {
        const std::size_t ids = r.ids;
        try {
            std::lock_guard lk(pending_mu_);
            pending_.push_front(std::move(r));
        } catch (...) {
            alloc_failed_.fetch_add(1);
            ids_truncated_.fetch_add(ids);
        }
    }
    /// A row (or id) whose evidence may be in NO summary because an allocation failed before it
    /// could be recorded (the budget itself, or the code around it): counted as one unnamed id.
    void note_unrecorded() noexcept { ids_truncated_.fetch_add(1); }
    /// Give counts back after a failed publish (a metric registry that threw) so they are not lost.
    void restore_counts(std::uint64_t ids_truncated, std::uint64_t queue_full,
                        std::uint64_t alloc_failed) noexcept {
        ids_truncated_.fetch_add(ids_truncated);
        queue_full_dropped_.fetch_add(queue_full);
        alloc_failed_.fetch_add(alloc_failed);
    }
    [[nodiscard]] std::size_t pending_size() const {
        std::lock_guard lk(pending_mu_);
        return pending_.size();
    }
    /// Discards everything still queued (shutdown out of time); returns how many.
    [[nodiscard]] std::size_t discard_pending() {
        std::lock_guard lk(pending_mu_);
        const auto n = pending_.size();
        std::uint64_t ids = 0;
        for (const auto& r : pending_)
            ids += r.ids;
        ids_truncated_.fetch_add(ids);
        pending_.clear();
        return n;
    }
    /// Counts accumulated since the last call, for the flush to publish as counters (the budget
    /// holds no MetricsRegistry). `take_ids_truncated` counts IDS that no summary row names: the
    /// excess over `kMaxDroppedIds`, plus every id of a chunk that was dropped (queue full, three
    /// failed writes, left queued at shutdown) or never built (allocation failure).
    [[nodiscard]] std::uint64_t take_ids_truncated() { return ids_truncated_.exchange(0); }
    [[nodiscard]] std::uint64_t take_queue_full_dropped() { return queue_full_dropped_.exchange(0); }
    /// Windows whose summary could not be BUILT (allocation failure): counted, their ids are in
    /// `take_ids_truncated`.
    [[nodiscard]] std::uint64_t take_alloc_failed() { return alloc_failed_.exchange(0); }

private:
    /// The state of a closed window, moved out of the lock so the chunks are built outside it.
    struct ClosedWindow {
        std::uint64_t dropped_rows{0};
        std::map<std::string, std::size_t> by_source;
        std::vector<std::string> ids; ///< distinct dropped ids in DROP order
        std::uint64_t id_events_beyond_cap{0}; ///< UPPER BOUND of distinct ids over the cap
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
                w.id_events_beyond_cap = dropped_id_events_beyond_cap_;
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
        dropped_id_events_beyond_cap_ = 0;
    }
    /// Every allocation happens BEFORE a counter moves, and a partial insert is undone, so a throw
    /// (std::bad_alloc) leaves the window consistent: admit() then counts the one id.
    void drop_locked(const std::string& id, const std::string& source) {
        auto& by_source = dropped_by_source_[source.substr(0, 45)]; // may throw: nothing changed yet
        if (dropped_ids_.find(id) == dropped_ids_.end()) {
            if (dropped_ids_.size() < kMaxDroppedIds) {
                dropped_order_.push_back(id); // may throw
                try {
                    dropped_ids_.insert(id);
                } catch (...) {
                    dropped_order_.pop_back();
                    throw;
                }
            } else {
                // An UPPER BOUND, not a distinct count: an over-cap id is not remembered, so every
                // later repeat of it is counted again.
                ++dropped_id_events_beyond_cap_;
            }
        }
        ++by_source;
        ++dropped_rows_;
    }
    void remember_locked(const std::string& id) {
        if (recent_.find(id) != recent_.end())
            return;
        recent_order_.push_back(id); // may throw: nothing changed yet
        try {
            recent_.insert(id);
        } catch (...) {
            recent_order_.pop_back();
            throw;
        }
        if (recent_order_.size() > kRecentIds) {
            recent_.erase(recent_order_.front());
            recent_order_.pop_front();
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
                           " distinct_dropped_ids_max=" + std::to_string(w.ids.size() + w.id_events_beyond_cap) +
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
            std::string r = head + " ids_beyond_cap_max=" + std::to_string(w.id_events_beyond_cap) +
                            " part=" + std::to_string(p + 1) + "/" + std::to_string(parts) +
                            " ids=";
            for (std::size_t k = p * kSummaryIds; k < w.ids.size() && k < (p + 1) * kSummaryIds; ++k)
                r += (k % kSummaryIds ? "," : "") + neutralise(w.ids[k]);
            rows.push_back(std::move(r));
        }
        return rows;
    }
    /// Builds the chunks (no lock held) and queues them; a full queue drops the new chunk, counted.
    std::vector<std::string> enqueue_closed(const ClosedWindow& w) noexcept {
        std::size_t accounted = 0;      // ids already queued in a chunk or counted unnamed
        bool overflow_counted = false;  // w.id_events_beyond_cap already added to ids_truncated_
        try {
            auto rows = build_rows(w);
            ids_truncated_.fetch_add(w.id_events_beyond_cap);
            overflow_counted = true;
            std::lock_guard lk(pending_mu_);
            std::size_t k = 0;
            for (const auto& r : rows) {
                const std::size_t ids =
                    w.ids.size() > k * kSummaryIds ? std::min(kSummaryIds, w.ids.size() - k * kSummaryIds) : 0;
                ++k;
                if (pending_.size() >= kMaxPendingRows) {
                    queue_full_dropped_.fetch_add(1);
                    ids_truncated_.fetch_add(ids);
                } else {
                    pending_.push_back(PendingRow{r, 0, ids});
                }
                accounted += ids;
            }
            return rows;
        } catch (...) {
            // The window was already moved out: count what is not already queued or counted
            // (one window, those ids unnamed) instead of losing it silently. Atomics do not allocate.
            alloc_failed_.fetch_add(1);
            ids_truncated_.fetch_add((w.ids.size() - std::min(accounted, w.ids.size())) +
                                     (overflow_counted ? 0 : w.id_events_beyond_cap));
            return {};
        }
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
    std::uint64_t dropped_id_events_beyond_cap_{0};
    std::set<std::string> recent_;
    std::deque<std::string> recent_order_;

    mutable std::mutex pending_mu_;
    std::deque<PendingRow> pending_;
    std::atomic<std::uint64_t> ids_truncated_{0};
    std::atomic<std::uint64_t> queue_full_dropped_{0};
    std::atomic<std::uint64_t> alloc_failed_{0};
};

/// How often the server's dedicated flush thread flushes the queued chunks, and the time one round
/// may spend writing (checked BETWEEN rows: one AuditStore::log can overrun it by its 4 s write
/// timeout). Measured: at 2000 distinct dropped ids/s a 15 s cadence (1.5 audit windows) against the
/// 128-row queue named only 78-82% of the ids; 5 s keeps one window's 100 chunks inside the queue.
/// The thread is separate from the health thread so a slow audit store cannot delay the revocation
/// sweep (server.cpp, reregistration_flush_thread_).
inline constexpr std::int64_t kReregistrationFlushIntervalMs = 5000;
inline constexpr std::int64_t kReregistrationFlushDeadlineMs = 2000;

/// What one flush round did (counters for the caller to publish).
struct ReregistrationFlushResult {
    bool any_failed{false};
    std::size_t written{0};
    std::uint64_t queue_full{0};   ///< chunks dropped because the queue was full
    std::uint64_t alloc_failed{0}; ///< windows whose summary could not be built
    std::uint64_t write_failed{0}; ///< chunks dropped after kMaxWriteAttempts failed writes
    std::uint64_t shutdown{0};     ///< chunks still queued at a forced (shutdown) flush
    std::uint64_t ids_truncated{0};///< ids no row names (see UnprovenAuditBudget)
};

/// One flush round over `budget`: close the window if due (or `force`), then write queued chunks in
/// order with `write(row) -> bool` until the queue is empty, a write fails (kept for the next round,
/// at most kMaxWriteAttempts) or `deadline_ms` has elapsed on `now_ms()` (the remainder stays
/// queued). `force` then discards whatever is left, counted. The store-facing wrapper is
/// flush_reregistration_audit_summary (agent_reregistration_apply.hpp); this part is
/// store-free so a slow or failing writer can be simulated deterministically.
template <class Write, class NowMs>
ReregistrationFlushResult flush_reregistration_budget(UnprovenAuditBudget& budget,
                                                      std::int64_t window_now_ms, bool force,
                                                      std::int64_t deadline_ms, Write&& write,
                                                      NowMs&& now_ms) {
    ReregistrationFlushResult r;
    (void)budget.poll_closed(window_now_ms, force);
    r.queue_full = budget.take_queue_full_dropped();
    r.alloc_failed = budget.take_alloc_failed();
    const std::int64_t deadline = now_ms() + deadline_ms;
    while (auto row = budget.take_pending()) {
        if (now_ms() >= deadline) {
            budget.requeue_front_unconditional(std::move(*row));
            break;
        }
        bool ok = false;
        try {
            ok = write(row->text);
        } catch (...) {
            ok = false;
        }
        if (ok) {
            ++r.written;
            continue;
        }
        r.any_failed = true;
        if (!budget.requeue_front(std::move(*row)))
            ++r.write_failed;
        break; // a failing store: retry on the next round, not in a tight loop
    }
    if (force)
        r.shutdown = budget.discard_pending();
    r.ids_truncated = budget.take_ids_truncated();
    return r;
}

} // namespace yuzu::server::detail
