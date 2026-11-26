#pragma once

/**
 * proc_snapshot_read.hpp -- bounded, abandonable libproc read of ONE process for the macOS leg of
 * the process_introspect plugin (SRE-1, UP-3).
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * proc_pidinfo takes a reference on the target through proc_find, which waits uninterruptibly
 * while the target is inside the kernel exec switch; the call has no deadline and cannot be
 * cancelled. Bounding the WAIT needs a detached thread (`yuzu::shared::bounded_call_ex`), and a
 * detached thread whose code lives in a plugin shared object is killed by dlclose() of that
 * plugin. Same argument, and same answer, as bundle_id_read.hpp / passwd_lookup.hpp /
 * dism_bounded_call.hpp: the bounded body lives here, in agent-core, which is never unloaded.
 * The plugin calls the exported functions ONLY and never instantiates the template: an
 * instantiation inside a plugin image puts the detached worker's text back in a dlclose()-able
 * object.
 *
 * ONE READ, ONE THREAD, ONE IN FLIGHT
 * -----------------------------------
 * A process-wide slot admits one read at a time. While a read is in flight the next call answers
 * at once instead of stacking another thread: Busy when the read is healthy (a concurrent
 * dispatch, retry shortly), Abandoned when an earlier call hit its deadline and its worker is
 * still blocked in the kernel. The slot and the driver are the shared ones
 * (bounded_single_flight.hpp, which states the release and recovery rules).
 *
 * WHAT IS READ
 * ------------
 * Public libproc only, numbers only, never the process name: one
 * proc_pidinfo(PROC_PIDTBSDINFO) for the wall-clock start stamp and the nice value, then one
 * proc_pid_rusage(RUSAGE_INFO_V0) for ri_proc_start_abstime, the monotonic (mach absolute time)
 * start stamp that a wall-clock step cannot move (UP-3). No task port. The plugin's lexical
 * gate (tests/test_process_introspect_no_task_port_lexical.py) scans this unit's source too.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <utility>

#include <yuzu/agent/bounded_single_flight.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

/// The numbers one read yields. Numbers only: a text member must not be added.
struct ProcSnapshot {
    int err = 0; ///< errno of the failing call; 0 when both succeeded
    std::uint64_t start_sec = 0;
    std::uint64_t start_usec = 0;
    std::int32_t nice = 0;
    std::uint64_t start_abstime = 0; ///< mach absolute time at process start (monotonic)
};

enum class ProcSnapshotStatus {
    Completed, ///< the read returned within the deadline (snap.err may still be nonzero)
    TimedOut,  ///< deadline hit (or the reader threw, or the budget was already spent): no answer
    Busy,      ///< another read is in flight and healthy; none was started by this call
    Abandoned, ///< an earlier call hit its deadline and its worker is still blocked; none started
    Rejected,  ///< the outstanding-call ceiling refused, or setup failed: the worker never ran
};

struct ProcSnapshotResult {
    ProcSnapshotStatus status = ProcSnapshotStatus::Rejected;
    ProcSnapshot snap; ///< meaningful only when status == Completed
};

/// libproc answers in microseconds; this only bounds a kernel wait that never ends.
inline constexpr std::chrono::milliseconds kProcSnapshotDeadline{5000};

using ProcSnapshotSlot = SingleFlightSlot;

namespace detail {

/// Header-only so tests can instantiate it in their own image. `reader` is a callable
/// `ProcSnapshot(int pid)`; `slot` must outlive any abandoned worker (never destroyed).
template <typename Reader>
ProcSnapshotResult bounded_proc_snapshot(ProcSnapshotSlot& slot, int pid,
                                         std::chrono::milliseconds deadline, Reader reader) {
    const auto flight = bounded_single_flight(
        slot, deadline, SlotWait::none,
        [pid, reader = std::move(reader)]() mutable -> ProcSnapshot { return reader(pid); });
    ProcSnapshotResult out;
    switch (flight.status) {
    case BoundedStatus::Completed:
        out.status = ProcSnapshotStatus::Completed;
        out.snap = *flight.value;
        break;
    case BoundedStatus::TimedOut:
        out.status = ProcSnapshotStatus::TimedOut;
        break;
    case BoundedStatus::Busy:
        out.status = ProcSnapshotStatus::Busy;
        break;
    case BoundedStatus::Abandoned:
        out.status = ProcSnapshotStatus::Abandoned;
        break;
    case BoundedStatus::Rejected:
        out.status = ProcSnapshotStatus::Rejected;
        break;
    }
    return out;
}

} // namespace detail

/// Read one process in ONE bounded call. Non-macOS builds answer Completed with err = ENOSYS.
/// Out-of-line (agent-core only).
YUZU_EXPORT ProcSnapshotResult read_proc_snapshot_bounded(int pid,
                                                          std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. No default
/// arguments (see keychain_read.hpp).
YUZU_EXPORT ProcSnapshotResult read_proc_snapshot_bounded_for_test(
    int pid, std::chrono::milliseconds deadline,
    const std::function<ProcSnapshot(int)>& reader);

} // namespace yuzu::agent
