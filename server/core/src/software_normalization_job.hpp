#pragma once

/// @file software_normalization_job.hpp
/// Background driver for the SAM.4 title normalisation: one thread that calls
/// `SoftwareTitleDimension::run_tick()` on a COMPLETION-SPACED cadence (a tick slower
/// than the wait backs off - no overlap). A line-for-line sibling of
/// `SoftwareCatalogRollup`: first tick immediately, 5 s stop polls, catch-all so an
/// exception never reaches `std::terminate`. The thread borrows the dimension owner
/// (and through it the pool + stores), so `stop()` MUST run before they are torn down
/// (server.cpp `stop()`), and `request_stop()` is called when the server starts draining.
///
/// Two cadences (`rearm_interval`): QUIET - the configured interval (hourly) - and
/// BACKLOG - `kBacklogRearm` (60 s) while the last tick hit its pass cap on a full page
/// (up to 200,000 titles per tick), so a pack bump or a first boot drains in minutes, not
/// 200,000 titles per hour. A failed, timed-out or cancelled tick KEEPS the quiet interval:
/// retrying at once would re-select the same batch and repeat the failure.
///
/// Metrics: `yuzu_software_normalization_pass_total{outcome=success|error}` (a
/// cancelled tick is neither) and `..._last_success_timestamp` are seeded at construction
/// (a bounded-label counter is pre-seeded to 0, so the first failure is an increase the
/// alert can see); `..._duration_seconds` is the last tick's wall clock.

#include "software_title_dimension.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Re-arm delay while a backlog remains (the last tick ended on a full page at its cap).
inline constexpr std::chrono::seconds kBacklogRearm{60};

/// The wait before the next tick: the short backlog floor only for a capped tick (never
/// longer than the configured interval), otherwise `interval`.
[[nodiscard]] constexpr std::chrono::seconds rearm_interval(const TickResult& r,
                                                            std::chrono::seconds interval) noexcept {
    return r.capped ? std::min(kBacklogRearm, interval) : interval;
}

class SoftwareNormalizationJob {
public:
    /// `dimension` is borrowed (must outlive this). `interval` is the
    /// completion-to-start spacing; non-positive falls back to one hour.
    SoftwareNormalizationJob(SoftwareTitleDimension& dimension, std::chrono::seconds interval,
                             yuzu::MetricsRegistry* metrics = nullptr);
    ~SoftwareNormalizationJob();

    SoftwareNormalizationJob(const SoftwareNormalizationJob&) = delete;
    SoftwareNormalizationJob& operator=(const SoftwareNormalizationJob&) = delete;

    /// Spawn the background thread (idempotent).
    void start();
    /// Signal stop and join (idempotent; also called by the destructor).
    void stop();
    /// Signal stop WITHOUT joining: no new tick starts; one in flight is cancelled at its
    /// next poll and rolls back. Called when the server starts draining.
    void request_stop() noexcept;

    /// One tick plus its metrics, synchronously: the thread's body, public so a test can
    /// observe the metric mapping without a thread. Never throws past `run_tick`'s guarantee.
    [[nodiscard]] TickResult tick_once();

private:
    void run();

    SoftwareTitleDimension& dimension_;
    std::chrono::seconds interval_;
    yuzu::MetricsRegistry* metrics_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
