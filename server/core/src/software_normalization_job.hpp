#pragma once

/// @file software_normalization_job.hpp
/// Hourly background driver for the SAM.4 title normalisation: one thread that
/// calls `SoftwareTitleDimension::run_tick()` on a COMPLETION-SPACED cadence (a tick
/// slower than the interval backs off - no overlap). A line-for-line sibling of
/// `SoftwareCatalogRollup`: first tick immediately, 5 s stop polls, catch-all so an
/// exception never reaches `std::terminate`. The thread borrows the dimension owner
/// (and through it the pool + stores), so `stop()` MUST run before they are torn down
/// (server.cpp `stop()`), and `request_stop()` is called when the server starts draining.
///
/// Metrics: `yuzu_software_normalization_pass_total{outcome=success|error}` (a
/// cancelled tick is neither), `..._duration_seconds`, and
/// `..._last_success_timestamp` (seeded 0 so the staleness alert can evaluate).

#include <atomic>
#include <chrono>
#include <thread>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class SoftwareTitleDimension;

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

private:
    void run();

    SoftwareTitleDimension& dimension_;
    std::chrono::seconds interval_;
    yuzu::MetricsRegistry* metrics_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
