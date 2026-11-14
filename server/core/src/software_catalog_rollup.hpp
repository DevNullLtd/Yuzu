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
///
/// SAM-33: after the two refreshes, and whatever their outcome, the same tick reads the fleet
/// facet health and headline summary, publishes the `yuzu_software_facet_*` gauges, and swaps an
/// immutable snapshot into the holder that GET /api/v1/inventory/software/summary and
/// .../plugin-health serve to a globally admitted caller (software_read_routes.hpp). A failed read
/// keeps the last good snapshot and is counted (`yuzu_software_fleet_snapshot_total`).
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
class SoftwareFleetSnapshotHolder;

class SoftwareCatalogRollup {
public:
    /// `store` is borrowed (must outlive this). `interval` is the completion-to-start
    /// spacing between recomputes. `metrics` is borrowed/optional (null = no emission).
    SoftwareCatalogRollup(SoftwareInventoryStore& store, std::chrono::seconds interval,
                          yuzu::MetricsRegistry* metrics = nullptr);
    ~SoftwareCatalogRollup();

    SoftwareCatalogRollup(const SoftwareCatalogRollup&) = delete;
    SoftwareCatalogRollup& operator=(const SoftwareCatalogRollup&) = delete;

    /// Where the fleet snapshot is published (borrowed; must outlive the thread). Set before
    /// start(); null (the default) publishes only the gauges.
    void set_snapshot_holder(SoftwareFleetSnapshotHolder* holder) noexcept { snapshot_ = holder; }

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
    void refresh_fleet_snapshot();

    SoftwareInventoryStore& store_;
    std::chrono::seconds interval_;
    yuzu::MetricsRegistry* metrics_;
    SoftwareFleetSnapshotHolder* snapshot_{nullptr};
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
