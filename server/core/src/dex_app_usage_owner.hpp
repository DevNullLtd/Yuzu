#pragma once

/// @file dex_app_usage_owner.hpp
/// Cross-store query owner (ADR-0012 §3) for the fleet application usage read:
/// the per-executable usage rows (`app_usage_store.agent_last_used`), the usage
/// freshness rows (`app_usage_store.usage_state`) and the crash and hang
/// observations (`guaranteed_state_store.guardian_observations`) are read in ONE
/// statement on ONE lease. A per-store class must never reach into another
/// store's schema, and the join cannot be split without losing its point: usage
/// collection can be off per device, so crashes and hangs counted on every
/// online device over usage from only the reporting devices would overstate the
/// exposure rate. The numerator (events on devices that freshly report usage for
/// the application) and the denominator (their run time) must come from one
/// population, one window and one snapshot.
///
/// Freshness: a device counts only while the server received its usage state at
/// or after `DexUsageQuery::fresh_since_epoch` (`usage_state.last_seen`, server
/// receipt time, never the agent's collected_at). A stale device contributes no
/// usage, no events and no reporting count; it is counted in `stale_devices`.
/// Events are cut at BOTH ends (`since_iso` inclusive, `until_iso` exclusive), so
/// a future-dated observation never enters a numerator.
///
/// No authorization and no disclosure floor are applied here. The device list,
/// cells, keys and time cuts are taken as given from the caller, and agent ids
/// must be unique (a repeated id repeats its rows in every sum and in the
/// coverage counts). Admitting the caller and the device list is the surface's
/// duty before it builds the query.
///
/// The owner returns aggregates per (application, cell) and per application,
/// never an agent id. Typed failure: `read` returns a `DexReadFault` when the
/// request is over the in-flight budget, no connection is available within the
/// bounded acquire (`pool_acquire_timeout`), an index in the query is out of range or
/// the statement or its transaction fails (`query_error`), or the statement runs
/// past its time bound (`statement_timeout`). That is the authoritative degrade,
/// never an empty result. An engaged EMPTY result means no devices were asked about
/// (no query is run) or the statement found nothing.
///
/// Budget: at most `kDexUsageConcurrentReads` reads in flight, never more than the
/// Apps stability read's own budget (a usage request also takes one Apps read slot).
/// A read over the budget is refused at once, never queued behind the pool.
///
/// Every fault counts `yuzu_server_guardian_read_degrade_total{reason, source="dex_usage"}`
/// when a metrics registry is wired, and writes one sampled warn line that names no
/// subject, agent or tag.
///
/// Sustained timeouts: `kDexUsageTimeoutsBeforeTooLarge` or more consecutive statement
/// timeouts whose unbroken run is at least `kDexUsageTimeoutRunBeforeTooLarge` old (any
/// success resets both) mean the on-request read no longer fits its time bound.
/// `unavailable_detail` then reports `fleet_too_large` instead of the retryable
/// `statement_timeout`. A burst of concurrent reads that time out in one stall cannot
/// meet the 2-minute span, so it stays retryable.
///
/// Read-only, no state written to the database, idempotent per request.

#include "dex_types.hpp"       // DexReadFault, dex_read_fault_token
#include "dex_usage_model.hpp" // DexUsageQuery, DexUsageRead (pure; names no store)
#include "refusal_log_throttle.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <string_view>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// In-flight reads allowed at once. The .cpp pins it at or below the Apps budget.
inline constexpr int kDexUsageConcurrentReads = 4;
/// Consecutive statement timeouts, spanning `kDexUsageTimeoutRunBeforeTooLarge`, after
/// which the failure is reported as `fleet_too_large` (not retryable).
inline constexpr int kDexUsageTimeoutsBeforeTooLarge = 3;
inline constexpr std::chrono::minutes kDexUsageTimeoutRunBeforeTooLarge{2};
/// The per-statement time bound; a parameter of the owner only so a test can make a real
/// timeout without waiting for it.
inline constexpr std::chrono::milliseconds kDexUsageStatementTimeout{10000};

/// PURE: the fault for a failed statement's SQLSTATE. 57014 (query_canceled, the statement
/// timeout) is `statement_timeout`; any other state, or none, is `query_error`.
[[nodiscard]] inline DexReadFault dex_usage_fault_from_sqlstate(const char* sqlstate) noexcept {
    return sqlstate != nullptr && std::string_view(sqlstate) == "57014" ? DexReadFault::kStatementTimeout
                                                                       : DexReadFault::kQueryError;
}

/// PURE: the detail token a surface reports for `f`: `fleet_too_large` iff `f` is a statement
/// timeout, the run holds at least `kDexUsageTimeoutsBeforeTooLarge` consecutive timeouts and
/// its first is at least `kDexUsageTimeoutRunBeforeTooLarge` old; otherwise the fault's own
/// token. A concurrent burst in one stall cannot meet the span, so it stays retryable.
[[nodiscard]] inline const char* dex_usage_unavailable_detail(DexReadFault f, int consecutive_timeouts,
                                                              std::chrono::steady_clock::duration run_age) noexcept {
    if (f == DexReadFault::kStatementTimeout && consecutive_timeouts >= kDexUsageTimeoutsBeforeTooLarge &&
        run_age >= kDexUsageTimeoutRunBeforeTooLarge)
        return "fleet_too_large";
    return dex_read_fault_token(f);
}

class DexAppUsageOwner {
public:
    /// `pool` and `metrics` (optional) are borrowed and must outlive this owner. `concurrent_reads`
    /// and `statement_timeout` exist so a test can reach the budget refusal and a real statement
    /// timeout; production passes neither.
    explicit DexAppUsageOwner(pg::PgPool& pool, yuzu::MetricsRegistry* metrics = nullptr,
                              int concurrent_reads = kDexUsageConcurrentReads,
                              std::chrono::milliseconds statement_timeout = kDexUsageStatementTimeout);

    DexAppUsageOwner(const DexAppUsageOwner&) = delete;
    DexAppUsageOwner& operator=(const DexAppUsageOwner&) = delete;

    /// The fault = authoritative degrade (see above).
    [[nodiscard]] std::expected<DexUsageRead, DexReadFault> read(const DexUsageQuery& q) const;

    /// Statement timeouts since the last success (the sustained-timeout run).
    [[nodiscard]] int consecutive_timeouts() const noexcept { return consecutive_timeouts_.load(); }

    /// The detail token for a fault `read` just returned (see `dex_usage_unavailable_detail`).
    /// `now` is the instant the run's age is measured at; production passes none.
    [[nodiscard]] const char* unavailable_detail(
        DexReadFault f,
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const noexcept;

private:
    /// Counts, logs (sampled) and returns `f`.
    [[nodiscard]] std::unexpected<DexReadFault> fault(DexReadFault f) const;

    pg::PgPool& pool_;
    yuzu::MetricsRegistry* metrics_;
    const int budget_;
    const std::chrono::milliseconds statement_timeout_;
    mutable std::atomic<int> in_flight_{0};
    // The sustained-timeout run: its length and its first timeout's steady_clock tick count
    // (0 = no run). The two are separate atomics, so a reader can see a new count with the old
    // start; that only delays `fleet_too_large` by one read.
    mutable std::atomic<int> consecutive_timeouts_{0};
    mutable std::atomic<std::int64_t> timeout_run_start_{0};
    mutable RefusalLogThrottle log_throttle_;
};

} // namespace yuzu::server
