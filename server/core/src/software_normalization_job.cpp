/// @file software_normalization_job.cpp
/// Implementation of the hourly title-normalisation thread. See the header.

#include "software_normalization_job.hpp"

#include "background_jobs.hpp"
#include "software_title_dimension.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <exception>

namespace yuzu::server {

SoftwareNormalizationJob::SoftwareNormalizationJob(SoftwareTitleDimension& dimension,
                                                   std::chrono::seconds interval,
                                                   yuzu::MetricsRegistry* metrics)
    : dimension_(dimension),
      interval_(interval <= std::chrono::seconds{0} ? std::chrono::seconds{3600} : interval),
      metrics_(metrics) {
    // Seeded BEFORE the first tick: a lazily created error counter would first appear at 1,
    // an increase the Failing rule cannot see, and the Stale rule needs the timestamp series
    // to exist (it guards `> 0`; a never-successful job is the Failing rule's case).
    if (metrics_) {
        metrics_->counter("yuzu_software_normalization_pass_total", {{"outcome", "success"}});
        metrics_->counter("yuzu_software_normalization_pass_total", {{"outcome", "error"}});
        metrics_->gauge("yuzu_software_normalization_last_success_timestamp").set(0);
    }
}

SoftwareNormalizationJob::~SoftwareNormalizationJob() {
    stop();
}

void SoftwareNormalizationJob::start() {
    if (thread_.joinable())
        return;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void SoftwareNormalizationJob::request_stop() noexcept {
    stop_.store(true, std::memory_order_release);
}

void SoftwareNormalizationJob::stop() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable())
        thread_.join();
}

TickResult SoftwareNormalizationJob::tick_once() {
    const auto t0 = std::chrono::steady_clock::now();
    YUZU_ASSERT_BACKGROUND_JOB("software_normalization_job.run_tick"); // ReplicaSafe
    const TickResult r = dimension_.run_tick([this] { return stop_.load(std::memory_order_acquire); });
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (metrics_) {
        if (!r.cancelled)
            metrics_
                ->counter("yuzu_software_normalization_pass_total",
                          {{"outcome", r.errored ? "error" : "success"}})
                .increment();
        metrics_->gauge("yuzu_software_normalization_duration_seconds").set(secs);
        if (!r.errored && !r.cancelled) {
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            metrics_->gauge("yuzu_software_normalization_last_success_timestamp")
                .set(static_cast<double>(now));
        }
    }
    if (r.cancelled)
        spdlog::info("Software normalisation: tick cancelled by shutdown");
    else if (r.errored)
        spdlog::warn("Software normalisation: tick had a failed pass or reconcile "
                     "({} passes, {} titles)",
                     r.passes, r.processed);
    return r;
}

void SoftwareNormalizationJob::run() {
    spdlog::info("Software normalisation thread started (interval={}s)", interval_.count());
    bool first = true;
    auto wait = interval_;
    while (!stop_.load(std::memory_order_acquire)) {
        if (!first) {
            const long steps = (wait.count() + 4) / 5;
            for (long i = 0; i < steps && !stop_.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds{5});
            if (stop_.load(std::memory_order_acquire))
                break;
        }
        first = false;
        wait = interval_; // an exception below keeps the quiet cadence
        try {
            wait = rearm_interval(tick_once(), interval_);
        } catch (const std::exception& e) {
            spdlog::error("Software normalisation: tick threw ({}) - thread continuing", e.what());
        } catch (...) {
            spdlog::error("Software normalisation: tick threw unknown exception - continuing");
        }
    }
}

} // namespace yuzu::server
