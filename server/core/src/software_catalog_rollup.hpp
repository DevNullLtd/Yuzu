#pragma once

/// @file software_catalog_rollup.hpp
/// Background driver for the `/inventory` Software-tab catalogue rollup and the software
/// components rollup. Owns a single thread that periodically calls
/// `SoftwareInventoryStore::refresh_catalog_rollup()` and then, in the same tick and
/// independently of its outcome, `refresh_component_rollup()` (SAM-17) — the expensive
/// full-table passes (cancellable: the catalogue one polls `stop_` between batches), run OFF
/// the request path so page reads hit only the small precomputed rollup tables. The
/// underlying `installed_software` and `software_components` change only on the daily sync,
/// so a periodic recompute is strictly fresh-enough. Each refresh has its own metric family
/// (`yuzu_inventory_catalog_rollup_*`, `yuzu_inventory_component_rollup_*`).
///
/// Lifecycle mirrors the app-perf roll-up thread: `start()` spawns the thread and runs
/// ONE refresh of each immediately (so both rollups populate at boot), then refreshes on a
/// COMPLETION-SPACED cadence (sleep `interval` AFTER each recompute finishes, so a
/// recompute slower than the interval simply backs off — no overlap, no pile-up). The
/// thread borrows the store + pool, so `stop()` (signal + join) MUST run before the
/// store / pool are torn down (wired in server.cpp `stop()` beside the other join points).
/// A recompute failure is keep-last-good in the store; the thread logs + counts it and
/// keeps ticking (an exception escaping a std::thread entry would call std::terminate).

#include <atomic>
#include <chrono>
#include <thread>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class SoftwareInventoryStore;

/// The step the idle wait between recomputes sleeps in, re-checking the stop flag after each
/// step: the longest a `stop()` waits on a parked thread. Production uses this value; the
/// constructor takes another only so a test need not wait out a 5 s step per `stop()`.
inline constexpr std::chrono::milliseconds kCatalogRollupStopPoll{5000};

class SoftwareCatalogRollup {
public:
    /// `store` is borrowed (must outlive this). `interval` is the completion-to-start
    /// spacing between recomputes. `metrics` is borrowed/optional (null = no emission).
    /// `stop_poll` is the idle-wait step (`kCatalogRollupStopPoll`; non-positive falls back to
    /// it). A test seam only: production passes none.
    SoftwareCatalogRollup(SoftwareInventoryStore& store, std::chrono::seconds interval,
                          yuzu::MetricsRegistry* metrics = nullptr,
                          std::chrono::milliseconds stop_poll = kCatalogRollupStopPoll);
    ~SoftwareCatalogRollup();

    SoftwareCatalogRollup(const SoftwareCatalogRollup&) = delete;
    SoftwareCatalogRollup& operator=(const SoftwareCatalogRollup&) = delete;

    /// Spawn the background thread (idempotent — a second call is a no-op).
    void start();
    /// Signal stop and join the thread (idempotent; also called by the destructor).
    void stop();
    /// Signal stop WITHOUT joining: no new recompute starts; one already in flight
    /// is cancelled at its next poll (last-good kept). Called when the server starts
    /// draining (HA WS-8) so a recompute cannot begin inside the drain grace and then
    /// run after it; stop() joins later.
    void request_stop() noexcept;

private:
    void run();

    SoftwareInventoryStore& store_;
    std::chrono::seconds interval_;
    yuzu::MetricsRegistry* metrics_;
    std::chrono::milliseconds stop_poll_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
