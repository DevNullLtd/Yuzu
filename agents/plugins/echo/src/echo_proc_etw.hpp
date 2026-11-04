#pragma once

/**
 * echo_proc_etw.hpp — gap-free process start/stop capture via ETW.
 *
 * Thread 1(a) of the ETW process-events workstream. Subscribes to the
 * Microsoft-Windows-Kernel-Process provider on a real-time ETW session and
 * decodes process start (event id 1) / stop (event id 2) into a bounded ring
 * buffer that the Echo plugin drains and persists in batches. This is the
 * event-driven complement to the snapshot-diff poll (CreateToolhelp32Snapshot /
 * NtQuerySystemInformation): the poll misses anything that starts and exits
 * within an interval; ETW does not.
 *
 * Boot gap (known limitation, thread 1(b)): a real-time session only sees events
 * once it is open, so processes that start AND exit before the agent's session
 * starts are missed. The fix is an AutoLogger that buffers boot events to an
 * .etl the agent drains at startup — a separate slice.
 *
 * windows.h-free by design: all ETW / TDH / windows.h usage lives in the .cpp
 * (mirrors guard.hpp's discipline — keeps windows.h's ERROR/min/max macros out
 * of headers). Off-Windows the collector is a no-op: start() returns false, the
 * ring stays empty, drain() yields nothing — callers degrade cleanly.
 *
 * The `ProcEvent` value type and the `ProcEventRing` push→pull bridge are shared
 * with the macOS Endpoint Security collector and live in echo_proc_stream.hpp.
 */

#include "echo_proc_stream.hpp" // ProcEvent, ProcEventRing

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::echo {

/// Owns a real-time ETW session on Microsoft-Windows-Kernel-Process and decodes
/// start/stop events into a ProcEventRing on a dedicated ProcessTrace thread.
/// Single-owner (non-copyable). Windows-only; every method is a no-op on other
/// platforms and start() returns false.
class ProcEtwCollector : public ProcStreamCollector {
public:
    /// `ring_capacity` bounds buffered-but-not-yet-drained events. Sized for the
    /// drain cadence × peak spawn rate with headroom; overflow drops with a
    /// counter rather than growing.
    explicit ProcEtwCollector(std::size_t ring_capacity = 100000);
    ~ProcEtwCollector() override;

    ProcEtwCollector(const ProcEtwCollector&) = delete;
    ProcEtwCollector& operator=(const ProcEtwCollector&) = delete;

    /// Open the session, enable the provider, and start ProcessTrace on its own
    /// thread. Returns false off-Windows, on any session-open failure, or if
    /// already running. A false return leaves nothing started (no thread, no
    /// session) so callers can fall back to the poll cleanly.
    bool start() override;

    /// Close the session and join the consumer thread. Safe if not started.
    void stop() override;

    bool running() const noexcept override;

    /// Move buffered events out for the batched echo.db write (the drain tick).
    /// Returns empty when not running / off-Windows.
    std::vector<ProcEvent> drain() override;

    /// Count of events dropped due to ring overflow since construction.
    std::uint64_t dropped() const noexcept override;

    /// Always "etw".
    const char* method_name() const noexcept override { return "etw"; }

private:
    struct Impl;                 ///< Windows ETW/TDH state; defined only in the .cpp
    std::unique_ptr<Impl> impl_; ///< null off-Windows / when not running
    ProcEventRing ring_;
};

/// Replay a file-mode ETW trace — the boot AutoLogger's `.etl` — and return the
/// process start/stop events with `ts < before_ts_unix`: the boot window before
/// the live session took over (which owns ts >= before, so this partition avoids
/// both gaps and duplicates). Names are recovered start→stop within the file;
/// there is NO user (the boot processes are dead by replay time).
///
/// Reads the file directly even while the AutoLogger is still writing it — that
/// works fine, PROVIDED the AutoLogger is configured with a FlushTimer so its
/// buffers actually reach the file (without one the file stays empty and this
/// replay sees nothing — verified on Win11). **No session stop, no elevation:**
/// the narrow agent account only needs read access to its own data dir. Caller
/// must dedup per-boot (the file persists, so an agent restart would otherwise
/// re-backfill the same boot events). Windows-only; empty off-Windows or on a
/// missing/empty file.
std::vector<ProcEvent> backfill_proc_events_from_etl(const std::string& etl_path,
                                                     std::int64_t before_ts_unix);

/// This machine's boot instant as unix seconds, floored to the minute so
/// it is STABLE across agent restarts within the same boot yet distinct between
/// boots. Used as the per-boot backfill dedup key: keying on the boot instant
/// (rather than the earliest event in the circular .etl, which shifts as the
/// buffer wraps) makes the dedup immune to .etl wrap and to late restarts — a
/// restarted agent computes the same key and skips re-inserting the boot window.
/// Returns 0 off-Windows (where the backfill is a no-op anyway).
///
/// Known limitations (each causes at most ONE extra bounded, user-empty
/// backfill — far better than the old min-ts key): derived from GetTickCount64
/// (uptime), which excludes sleep, so a sleep/resume of more than a minute
/// between two agent restarts in the same boot can shift the key; and two
/// restarts whose computed boot instants straddle a minute boundary (sub-2s
/// measurement jitter near a :00 second) can floor to different minutes. A
/// precise sleep-immune boot id is a tracked follow-up.
std::int64_t boot_time_unix();

} // namespace yuzu::echo
