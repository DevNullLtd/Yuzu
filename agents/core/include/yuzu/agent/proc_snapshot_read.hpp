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
 * still blocked in the kernel. The worker releases the slot itself when it returns, so recovery
 * is automatic. A Rejected admission means the worker never ran, so the caller releases the slot.
 * The outstanding-call ceiling that produces Rejected is PER IMAGE, so the driver is a
 * header-only template taking the slot by reference: production binds agent-core's slot, tests
 * bind their own.
 *
 * WHAT IS READ
 * ------------
 * Public libproc only, numbers only, never the process name: one
 * proc_pidinfo(PROC_PIDTBSDINFO) for the wall-clock start stamp and the nice value, then one
 * proc_pid_rusage(RUSAGE_INFO_V0) for ri_proc_start_abstime, the monotonic (mach absolute time)
 * start stamp that a wall-clock step cannot move (UP-3). No task port. The plugin's lexical
 * gate (tests/test_process_introspect_no_task_port_lexical.py) scans this unit's source too.
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

/// The single-flight slot: free, busy (a healthy read in flight) or abandoned (a read past its
/// deadline whose worker is still blocked). Pure and thread-free, like DismSlot.
///
/// Each acquisition carries a generation, so a late mark_abandoned from a caller whose worker has
/// already released (and whose slot a NEW dispatch has since acquired) cannot land on that new,
/// healthy read. The word packs the state in the low 2 bits and a 62-bit generation above it: at
/// one acquisition per nanosecond the generation would take about 146 years to wrap, so wrap is
/// not a practical concern and is not handled.
class ProcSnapshotSlot {
public:
    enum class Acquire { acquired, busy, abandoned };
    struct Ticket {
        Acquire result = Acquire::busy;
        std::uint64_t generation = 0; ///< meaningful only when result == acquired
    };

    [[nodiscard]] Ticket try_acquire() noexcept {
        std::uint64_t w = word_.load(std::memory_order_acquire);
        for (;;) {
            if (state_of(w) != kFree)
                return {state_of(w) == kAbandoned ? Acquire::abandoned : Acquire::busy, 0};
            const std::uint64_t gen = (w >> kStateBits) + 1;
            if (word_.compare_exchange_weak(w, (gen << kStateBits) | kBusy,
                                            std::memory_order_acquire,
                                            std::memory_order_acquire))
                return {Acquire::acquired, gen};
        }
    }
    /// Called by the caller whose deadline fired, with the generation of ITS acquisition. A CAS on
    /// (generation, busy): a worker that finished at the deadline has already released, and a
    /// stale generation (the slot was released and re-acquired since) does nothing.
    void mark_abandoned(std::uint64_t generation) noexcept {
        std::uint64_t expected = (generation << kStateBits) | kBusy;
        word_.compare_exchange_strong(expected, (generation << kStateBits) | kAbandoned,
                                      std::memory_order_acq_rel, std::memory_order_relaxed);
    }
    /// Called by the worker when its read returns or throws (or by the caller when the worker
    /// never ran). Only the current owner calls it, so keeping the generation is race-free.
    void release() noexcept {
        std::uint64_t w = word_.load(std::memory_order_relaxed);
        while (!word_.compare_exchange_weak(w, (w & ~kStateMask) | kFree,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
        }
    }

private:
    static constexpr std::uint64_t kFree = 0;
    static constexpr std::uint64_t kBusy = 1;
    static constexpr std::uint64_t kAbandoned = 2;
    static constexpr int kStateBits = 2;
    static constexpr std::uint64_t kStateMask = 3;
    static constexpr std::uint64_t state_of(std::uint64_t w) noexcept { return w & kStateMask; }
    std::atomic<std::uint64_t> word_{0};
};

namespace detail {

/// Header-only so tests can instantiate it in their own image. `reader` is a callable
/// `ProcSnapshot(int pid)`; `slot` must outlive any abandoned worker (a static).
template <typename Reader>
ProcSnapshotResult bounded_proc_snapshot(ProcSnapshotSlot& slot, int pid,
                                         std::chrono::milliseconds deadline, Reader reader) {
    static_assert(std::is_nothrow_move_constructible_v<Reader>,
                  "a throwing Reader move would escape with the slot held");
    ProcSnapshotResult out;
    // Admission first: a call during an in-flight read is Busy/Abandoned even with a spent budget.
    const auto ticket = slot.try_acquire();
    switch (ticket.result) {
    case ProcSnapshotSlot::Acquire::acquired:
        break;
    case ProcSnapshotSlot::Acquire::busy:
        out.status = ProcSnapshotStatus::Busy;
        return out;
    case ProcSnapshotSlot::Acquire::abandoned:
        out.status = ProcSnapshotStatus::Abandoned;
        return out;
    }
    if (deadline <= std::chrono::milliseconds::zero()) {
        slot.release(); // nothing handed off
        out.status = ProcSnapshotStatus::TimedOut;
        return out;
    }
    auto worker = [&slot, pid, reader = std::move(reader)]() mutable -> ProcSnapshot {
        // Releaser FIRST: runs when the worker returns or throws, long after a TimedOut caller.
        struct Releaser {
            ProcSnapshotSlot& s;
            ~Releaser() { s.release(); }
        } releaser{slot};
        return reader(pid);
    };
    auto r = yuzu::shared::bounded_call_ex(deadline, std::move(worker));
    switch (r.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = ProcSnapshotStatus::Completed;
        out.snap = *r.value;
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        // Also a throwing reader, which returns at once with no value. If the worker is still
        // running, mark it abandoned so the next dispatch is told so, not just "busy".
        slot.mark_abandoned(ticket.generation);
        out.status = ProcSnapshotStatus::TimedOut;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        // The worker never ran, so no releaser exists: release the slot here.
        slot.release();
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
