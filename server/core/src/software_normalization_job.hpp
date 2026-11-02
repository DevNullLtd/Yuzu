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
/// SHORT - `kBacklogRearm` (60 s) after a tick that either hit its pass cap on a full page
/// (up to 200,000 titles per tick) or found the candidate source (`title_triples`) still
/// empty while installed software exists (the catalogue rollup has not completed yet). A
/// backlog therefore moves at up to 200,000 titles per minute-spaced tick rather than per
/// hour, and a fresh boot picks up its first titles as soon as the rollup has run (the
/// rollup's own duration still applies). A failed, timed-out or cancelled tick KEEPS the
/// quiet interval: retrying at once would re-select the same batch and repeat the failure.
///
/// Metrics: `yuzu_software_normalization_pass_total{outcome=success|error}` (a
/// cancelled tick is neither) and `..._last_success_timestamp` are seeded at construction
/// (a bounded-label counter is pre-seeded to 0, so the first failure is an increase the
/// alert can see); `..._duration_seconds` is the last tick's wall clock.

#include "software_title_dimension.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Re-arm delay while work is known to be waiting: the last tick ended on a full page at
/// its cap, or the candidate source had not been filled yet.
inline constexpr std::chrono::seconds kBacklogRearm{60};

/// The wait before the next tick: the short floor only for a capped or source-pending tick
/// (never longer than the configured interval), otherwise `interval`.
[[nodiscard]] constexpr std::chrono::seconds rearm_interval(const TickResult& r,
                                                            std::chrono::seconds interval) noexcept {
    return (r.capped || r.source_pending) ? std::min(kBacklogRearm, interval) : interval;
}

class SoftwareNormalizationJob {
public:
    /// Called after every tick (including a cancelled one), on the thread that ran it, once
    /// its metrics are written. A seam for tests to wait on a completed tick without polling;
    /// production passes none. A throw is caught by the run loop like any tick exception.
    using TickObserver = std::function<void(const TickResult&)>;

    /// `dimension` is borrowed (must outlive this). `interval` is the
    /// completion-to-start spacing; non-positive falls back to one hour.
    SoftwareNormalizationJob(SoftwareTitleDimension& dimension, std::chrono::seconds interval,
                             yuzu::MetricsRegistry* metrics = nullptr, TickObserver on_tick = {});
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
    /// observe the metric mapping without a thread. Throws only if `run_tick` or the metrics
    /// registry does; `run()` catches that.
    [[nodiscard]] TickResult tick_once();

private:
    void run();

    SoftwareTitleDimension& dimension_;
    std::chrono::seconds interval_;
    yuzu::MetricsRegistry* metrics_;
    TickObserver on_tick_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
