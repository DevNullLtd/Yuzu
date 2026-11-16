#pragma once

// echo_hive_mount_gate.hpp -- the Windows-only gate every Echo source that mounts a user hive
// file through a detached bounded worker shares (the mapped-drive history walk and the
// registry source's offline reads). One counter per plugin DLL, because the thing it protects
// is per DLL: a worker the caller abandoned on a timeout keeps running THIS module's code,
// holding the process-wide offline-hive mutex, so any later mount from either source would
// only queue behind it. See echo_mapdrive_collector.cpp (enum_registry_outbound_history) for the
// full residual and echo_mapdrive_backfill.hpp (decide_walk_gate) for the gate decision.

#ifdef _WIN32

#include <atomic>
#include <chrono>

namespace yuzu::echo {

// Mount workers currently running (spawned by bounded_call_ex, not yet returned from their
// closure). A plugin static, safe because the module is pinned before any worker exists. A
// worker the caller abandoned on a timeout stays counted until it really returns, which is how a
// LATER walk learns that mounting would only queue behind it (decide_walk_gate).
inline std::atomic<int> g_mount_workers_in_flight{0};

struct MountWorkerGuard {
    MountWorkerGuard() noexcept { g_mount_workers_in_flight.fetch_add(1); }
    ~MountWorkerGuard() { g_mount_workers_in_flight.fetch_sub(1); }
    MountWorkerGuard(const MountWorkerGuard&) = delete;
    MountWorkerGuard& operator=(const MountWorkerGuard&) = delete;
};

/// How long the caller waits for one bounded mount-and-read. Generous for a legitimately slow
/// network-share read; see dism's 17s for a comparable Windows API bound.
inline constexpr std::chrono::milliseconds kHiveMountBoundMs{30000};

/// Pins this plugin's module so FreeLibrary can never unmap it (for the life of the process),
/// once, and answers whether it holds. Defined in echo_mapdrive_collector.cpp.
bool pin_plugin_module() noexcept;

} // namespace yuzu::echo

#endif // _WIN32
