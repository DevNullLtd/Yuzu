#pragma once

/// @file dex_app_version_failures_owner.hpp
/// Cross-store query owner (ADR-0012 §3) for the per-version crash and hang
/// join of one application: the crash and hang observations
/// (`guaranteed_state_store.guardian_observations`) and the exposure rows
/// (`app_perf_daily_store.app_perf_daily`) are read in ONE statement on ONE
/// lease. A per-store class must never reach into another store's schema, and
/// the join cannot be split without losing its point: the rate's numerator
/// (events on exposed devices) and its denominator (exposed devices) must come
/// from one population, one window and one snapshot, or a version sampled on
/// few of its devices reads as a regression it is not.
///
/// Typed failure: `read` returns `std::nullopt` when no connection is available
/// within the bounded acquire, the statement times out or errors. That is the
/// authoritative degrade the callers surface as a 503 / internal error, never an
/// empty report. An engaged EMPTY vector means a precondition miss (an empty
/// application or version list) or genuinely no failure and no exposure rows.
///
/// Window contract: the caller passes ONE cut. Exposure covers B1 days in
/// `[since_day, end_day]` (UTC midnights, epoch seconds); events cover
/// `[since_iso, end of end_day)` (ISO-8601 UTC; the owner derives the exclusive
/// upper bound from `end_day`, so both sides share one cut). Forward-slack rows
/// of either store (clock skew, a future-dated observation) never count.
///
/// Read-only, no state written, idempotent per request.

#include "dex_app_perf_pure.hpp" // AppPerfVersionFailureRow, kAppPerfFailureWindowDays

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class DexAppVersionFailuresOwner {
public:
    /// `pool` is borrowed and must outlive this owner. `retention_days` is the
    /// observation store's retention (`guardian_event_retention_days`; 0 or less
    /// = unbounded): rows are stamped to expire after it, so a longer window
    /// would silently undercount.
    DexAppVersionFailuresOwner(pg::PgPool& pool, int retention_days);

    DexAppVersionFailuresOwner(const DexAppVersionFailuresOwner&) = delete;
    DexAppVersionFailuresOwner& operator=(const DexAppVersionFailuresOwner&) = delete;

    /// The window the report uses: `kAppPerfFailureWindowDays`, clamped to one
    /// day less than the observation retention when that is positive. The window
    /// is W whole UTC days plus the current day so far, and an event is reaped
    /// `retention` days after it was recorded, so with W = retention - 1 no
    /// counted day has lost any of its events.
    [[nodiscard]] int failure_window_days() const;

    /// One row per version in `versions` that has failure or exposure rows,
    /// ordered by version. nullopt = authoritative degrade (see above).
    [[nodiscard]] std::optional<std::vector<AppPerfVersionFailureRow>>
    read(std::string_view app, const std::vector<std::string>& versions, std::int64_t since_day,
         std::int64_t end_day, std::string_view since_iso) const;

private:
    pg::PgPool& pool_;
    int retention_days_;
};

} // namespace yuzu::server
