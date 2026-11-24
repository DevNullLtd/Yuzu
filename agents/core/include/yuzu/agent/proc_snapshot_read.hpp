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
 * A process-wide in-flight flag admits one read at a time. While an abandoned (TimedOut) read is
 * still blocked in the kernel, the next call returns Busy at once instead of stacking another
 * blocked thread. The worker releases the flag itself when it returns, so recovery is
 * automatic. A Rejected admission means the worker never ran, so the caller releases the flag.
 * The outstanding-call ceiling that produces Rejected is PER IMAGE, so the driver is a
 * header-only template taking the flag by reference: production binds agent-core's flag, tests
 * bind their own.
 *
 * WHAT IS READ
 * ------------
 * Public libproc only, numbers only, never the process name: one
 * proc_pidinfo(PROC_PIDTBSDINFO) for the wall-clock start stamp and the nice value. No task
 * port. The plugin's lexical gate (tests/test_process_introspect_no_task_port_lexical.py) scans
 * this unit's source too.
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <type_traits>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)
#include <yuzu/plugin.h>    // YUZU_EXPORT

namespace yuzu::agent {

/// The numbers one read yields. Numbers only: a text member must not be added.
struct ProcSnapshot {
    int err = 0; ///< errno of the failing call; 0 when both succeeded
    std::uint64_t start_sec = 0;
    std::uint64_t start_usec = 0;
    std::int32_t nice = 0;
};

enum class ProcSnapshotStatus {
    Completed, ///< the read returned within the deadline (snap.err may still be nonzero)
    TimedOut,  ///< deadline hit; the worker is abandoned and holds the in-flight flag
    Busy,      ///< a previous (abandoned) read is still blocked; nothing was read
    Rejected,  ///< the outstanding-call ceiling refused, or setup failed; nothing was read
};

struct ProcSnapshotResult {
    ProcSnapshotStatus status = ProcSnapshotStatus::Rejected;
    ProcSnapshot snap; ///< meaningful only when status == Completed
};

/// libproc answers in microseconds; this only bounds a kernel wait that never ends.
inline constexpr std::chrono::milliseconds kProcSnapshotDeadline{5000};

namespace detail {

/// Header-only so tests can instantiate it in their own image. `reader` is a callable
/// `ProcSnapshot(int pid)`; `in_flight` must outlive any abandoned worker (a static).
template <typename Reader>
ProcSnapshotResult bounded_proc_snapshot(std::atomic_flag& in_flight, int pid,
                                         std::chrono::milliseconds deadline, Reader reader) {
    static_assert(std::is_nothrow_move_constructible_v<Reader>,
                  "a throwing Reader move would escape with the in-flight flag set");
    ProcSnapshotResult out;
    // Admission first: a call during an abandoned read is Busy even with a spent budget.
    if (in_flight.test_and_set(std::memory_order_acquire)) {
        out.status = ProcSnapshotStatus::Busy;
        return out;
    }
    if (deadline <= std::chrono::milliseconds::zero()) {
        in_flight.clear(std::memory_order_release); // nothing handed off
        out.status = ProcSnapshotStatus::TimedOut;
        return out;
    }
    auto worker = [&in_flight, pid, reader = std::move(reader)]() mutable -> ProcSnapshot {
        // Releaser FIRST: runs when the worker returns or throws, long after a TimedOut caller.
        struct Releaser {
            std::atomic_flag& f;
            ~Releaser() { f.clear(std::memory_order_release); }
        } releaser{in_flight};
        return reader(pid);
    };
    auto r = yuzu::shared::bounded_call_ex(deadline, std::move(worker));
    switch (r.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = ProcSnapshotStatus::Completed;
        out.snap = *r.value;
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.status = ProcSnapshotStatus::TimedOut; // also a throwing reader: no value either way
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        // The worker never ran, so no releaser exists: clear the flag here.
        in_flight.clear(std::memory_order_release);
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

/// Test seam: same driver and process-wide in-flight flag, injected reader. No default
/// arguments (see keychain_read.hpp).
YUZU_EXPORT ProcSnapshotResult read_proc_snapshot_bounded_for_test(
    int pid, std::chrono::milliseconds deadline,
    const std::function<ProcSnapshot(int)>& reader);

} // namespace yuzu::agent
