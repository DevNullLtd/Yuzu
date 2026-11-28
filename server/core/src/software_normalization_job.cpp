/// @file software_normalization_job.cpp
/// Implementation of the hourly title-normalisation thread. See the header.

#include "software_normalization_job.hpp"

#include "background_jobs.hpp"
#include "software_title_dimension.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <exception>
#include <utility>

namespace yuzu::server {

SoftwareNormalizationJob::SoftwareNormalizationJob(SoftwareTitleDimension& dimension,
                                                   std::chrono::seconds interval,
                                                   yuzu::MetricsRegistry* metrics,
                                                   TickObserver on_tick,
                                                   std::chrono::milliseconds stop_poll)
    : dimension_(dimension),
      interval_(interval <= std::chrono::seconds{0} ? std::chrono::seconds{3600} : interval),
      metrics_(metrics), on_tick_(std::move(on_tick)),
      stop_poll_(stop_poll <= std::chrono::milliseconds{0} ? kNormalizationStopPoll : stop_poll) {
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
    else {
        // A source-pending tick re-arms every kBacklogRearm for as long as the rollup has not
        // produced a title list, so only the entry into and the exit from that state log at
        // INFO; the ticks in between log at DEBUG.
        const bool was_pending =
            source_pending_.exchange(r.source_pending, std::memory_order_relaxed);
        if (was_pending && !r.source_pending)
            spdlog::info("Software normalisation: the candidate source (title_triples) is filled");
        spdlog::log(r.source_pending && was_pending ? spdlog::level::debug : spdlog::level::info,
                    "Software normalisation: tick complete ({} passes, {} titles, {}, "
                    "next in {} s)",
                    r.passes, r.processed,
                    r.capped            ? "backlog remains"
                    : r.source_pending ? "waiting for the catalogue rollup"
                                        : "caught up",
                    rearm_interval(r, interval_).count());
    }
    if (on_tick_)
        on_tick_(r);
    return r;
}

void SoftwareNormalizationJob::run() {
    spdlog::info("Software normalisation thread started (interval={}s)", interval_.count());
    bool first = true;
    auto wait = interval_;
    while (!stop_.load(std::memory_order_acquire)) {
        if (!first) {
            // stop_poll_ steps (5 s in production), rounded up as the former (wait + 4) / 5 was.
            const auto steps =
                (std::chrono::milliseconds{wait} + stop_poll_ - std::chrono::milliseconds{1}) /
                stop_poll_;
            for (std::int64_t i = 0; i < steps && !stop_.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(stop_poll_);
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
