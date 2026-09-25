/// @file software_catalog_rollup.cpp
/// Implementation of the catalogue rollup background thread. See the header.

#include "software_catalog_rollup.hpp"

#include "background_jobs.hpp"

#include "software_inventory_store.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <exception>

namespace yuzu::server {

SoftwareCatalogRollup::SoftwareCatalogRollup(SoftwareInventoryStore& store,
                                             std::chrono::seconds interval,
                                             yuzu::MetricsRegistry* metrics)
    : store_(store),
      interval_(interval <= std::chrono::seconds{0} ? std::chrono::seconds{3600} : interval),
      metrics_(metrics) {}

SoftwareCatalogRollup::~SoftwareCatalogRollup() {
    stop();
}

void SoftwareCatalogRollup::start() {
    if (thread_.joinable())
        return; // already started
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void SoftwareCatalogRollup::request_stop() noexcept {
    stop_.store(true, std::memory_order_release);
}

void SoftwareCatalogRollup::stop() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable())
        thread_.join();
}

void SoftwareCatalogRollup::run() {
    spdlog::info("Software catalogue rollup thread started (interval={}s)", interval_.count());
    // Seed the liveness gauge to 0 BEFORE the first refresh (gov UP-2): otherwise the
    // series is created only on the first SUCCESS, so a server whose first recompute keeps
    // failing has NO gauge at all and the staleness alert can't evaluate. Seeded at 0 the
    // series always exists; the staleness alert guards `> 0` to skip the building window
    // (the ongoing-failure case is covered by ..._rollup_total{outcome="error"}).
    if (metrics_)
        metrics_->gauge("yuzu_inventory_catalog_rollup_last_success_timestamp").set(0);
    bool first = true;
    while (!stop_.load(std::memory_order_acquire)) {
        if (!first) {
            // Sleep the interval in 5s steps so shutdown stays responsive. Spacing is
            // measured from the END of the previous recompute (completion-spaced), so a
            // recompute slower than the interval can never overlap the next.
            const long steps = (interval_.count() + 4) / 5;
            for (long i = 0; i < steps && !stop_.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds{5});
            if (stop_.load(std::memory_order_acquire))
                break;
        }
        first = false;
        // refresh_catalog_rollup touches PG; an exception escaping a std::thread entry
        // calls std::terminate — catch, log, keep ticking.
        try {
            const auto t0 = std::chrono::steady_clock::now();
            YUZU_ASSERT_BACKGROUND_JOB(
                "software_catalog_rollup.refresh_catalog_rollup"); // WS-10 ReplicaSafe
            const bool ok = store_.refresh_catalog_rollup();
            const double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            if (metrics_) {
                metrics_
                    ->counter("yuzu_inventory_catalog_rollup_total",
                              {{"outcome", ok ? "success" : "error"}})
                    .increment();
                metrics_->gauge("yuzu_inventory_catalog_rollup_duration_seconds").set(secs);
                if (ok) {
                    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count();
                    metrics_->gauge("yuzu_inventory_catalog_rollup_last_success_timestamp")
                        .set(static_cast<double>(now));
                }
            }
            if (!ok)
                spdlog::warn(
                    "Software catalogue rollup: refresh failed — keeping last-good rollup");
        } catch (const std::exception& e) {
            spdlog::error("Software catalogue rollup: tick threw ({}) — thread continuing",
                          e.what());
        } catch (...) {
            spdlog::error("Software catalogue rollup: tick threw unknown exception — continuing");
        }
    }
}

} // namespace yuzu::server
