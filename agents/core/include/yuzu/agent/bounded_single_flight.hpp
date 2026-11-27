#pragma once

/**
 * bounded_single_flight.hpp -- the single-flight slot and the bounded-call driver for agent-core
 * reads whose OS call has no deadline and cannot be cancelled.
 *
 * AGENT-CORE TUs AND TESTS ONLY. Bounding the WAIT needs a detached thread
 * (`yuzu::shared::bounded_call_ex`), and a detached thread whose code lives in a plugin shared
 * object is killed by dlclose() / FreeLibrary() of that plugin (see dism_bounded_call.hpp). A
 * plugin calls the exported agent-core functions and never instantiates the driver. It may still
 * SEE these declarations: proc_snapshot_read.hpp includes this header and the process_introspect
 * plugin includes that one for its status type. Instantiating the driver there does not compile:
 * yuzu_agent_core_dep defines YUZU_AGENT_CORE_CONSUMER, which only a test image may override.
 *
 * ONE CALL, ONE THREAD, ONE IN FLIGHT. A slot admits one call at a time, so a hung API pins at
 * most one detached worker per slot. While a call is in flight the next one is told so: Busy when
 * it is healthy, Abandoned when it is past its deadline and still blocked. With
 * SlotWait::within_deadline the caller first waits for a healthy call to finish. The worker
 * releases the slot itself when it returns, so recovery is automatic. A Rejected admission means
 * the worker never ran, so the caller releases the slot.
 *
 * A slot must outlive any abandoned worker: production slots are never destroyed. The
 * outstanding-call ceiling that produces Rejected is PER IMAGE, so the driver is a header-only
 * template taking the slot by reference: production binds agent-core's slots, tests bind their own.
 */

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

#include <yuzu/agent/bounded_status.hpp>
#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)

namespace yuzu::agent {

/// The single-flight slot: free, busy (a healthy call in flight) or abandoned (a call past its
/// deadline whose worker is still blocked). Starts no thread of its own.
///
/// Each acquisition carries a generation, so a late mark_abandoned from a caller whose worker has
/// already released (and whose slot a NEW call has since acquired) cannot land on that new,
/// healthy call.
class SingleFlightSlot {
public:
    enum class Acquire { acquired, busy, abandoned };
    struct Ticket {
        Acquire result = Acquire::busy;
        std::uint64_t generation = 0; ///< meaningful only when result == acquired
    };

    [[nodiscard]] Ticket try_acquire() noexcept {
        const std::lock_guard lock{mtx_};
        return take_locked();
    }
    /// Waits while the slot is busy. Answers abandoned at once when the slot is, or becomes,
    /// abandoned, and busy if the slot is still held at `until`.
    [[nodiscard]] Ticket acquire_until(std::chrono::steady_clock::time_point until) noexcept {
        std::unique_lock lock{mtx_};
        ++waiters_;
        cv_.wait_until(lock, until, [this] { return state_ != State::busy; });
        --waiters_;
        return take_locked();
    }
    /// Callers inside acquire_until's wait. The mutex is only free to this reader once a counted
    /// caller is parked, so a test orders a release or abandonment after a waiter with it.
    [[nodiscard]] int waiters() noexcept {
        const std::lock_guard lock{mtx_};
        return waiters_;
    }
    /// Called by the caller whose deadline fired, with the generation of ITS acquisition. A worker
    /// that finished at the deadline has already released, and a stale generation (the slot was
    /// released and re-acquired since) does nothing.
    void mark_abandoned(std::uint64_t generation) noexcept {
        const std::lock_guard lock{mtx_};
        if (state_ != State::busy || generation_ != generation)
            return;
        state_ = State::abandoned;
        cv_.notify_all();
    }
    /// Called by the worker when its call returns or throws (or by the caller when the worker
    /// never ran). Only the current owner calls it.
    void release() noexcept {
        const std::lock_guard lock{mtx_};
        state_ = State::free;
        cv_.notify_all();
    }

private:
    enum class State { free, busy, abandoned };

    Ticket take_locked() noexcept {
        if (state_ != State::free)
            return {state_ == State::abandoned ? Acquire::abandoned : Acquire::busy, 0};
        state_ = State::busy;
        return {Acquire::acquired, ++generation_};
    }

    std::mutex mtx_;
    std::condition_variable cv_;
    State state_ = State::free;
    std::uint64_t generation_ = 0;
    int waiters_ = 0;
};

/// What a call does when the slot is held by a healthy call.
enum class SlotWait {
    none,            ///< answer Busy at once
    within_deadline, ///< wait for it to finish, inside this call's own deadline
};

template <typename R> struct BoundedFlight {
    BoundedStatus status = BoundedStatus::Rejected;
    std::optional<R> value; ///< set only when status == Completed
};

namespace detail {

/// Runs `fn` on a detached worker, one at a time per `slot`, and gives the caller its thread back
/// within `deadline`, which covers the wait for the slot and the call together. `fn` must own
/// everything it touches (it can outlive this frame), and `slot` must outlive it.
template <typename Fn>
auto bounded_single_flight(SingleFlightSlot& slot, std::chrono::milliseconds deadline,
                           SlotWait wait, Fn fn) -> BoundedFlight<std::invoke_result_t<Fn&>> {
#if defined(YUZU_AGENT_CORE_CONSUMER) && !defined(YUZU_BOUNDED_DRIVER_TEST_IMAGE)
    // A plugin image can be unloaded under the detached worker running its code.
    static_assert(sizeof(Fn) == 0, "the bounded driver is agent-core only: call an exported "
                                   "agent-core function");
#endif
    static_assert(std::is_nothrow_move_constructible_v<Fn>,
                  "a throwing Fn move would escape with the slot held");
    BoundedFlight<std::invoke_result_t<Fn&>> out;
    const auto until = std::chrono::steady_clock::now() + deadline;
    // Admission first: a call during an in-flight one is Busy/Abandoned even with a spent budget.
    const auto ticket = wait == SlotWait::none ? slot.try_acquire() : slot.acquire_until(until);
    switch (ticket.result) {
    case SingleFlightSlot::Acquire::acquired:
        break;
    case SingleFlightSlot::Acquire::busy:
        out.status = BoundedStatus::Busy;
        return out;
    case SingleFlightSlot::Acquire::abandoned:
        out.status = BoundedStatus::Abandoned;
        return out;
    }
    // Rounded up, so an unspent budget never truncates to zero.
    const auto remaining =
        std::chrono::ceil<std::chrono::milliseconds>(until - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero()) {
        slot.release(); // nothing handed off
        out.status = BoundedStatus::TimedOut;
        return out;
    }
    auto worker = [&slot, fn = std::move(fn)]() mutable {
        // Releaser FIRST: runs when the worker returns or throws, long after a TimedOut caller.
        struct Releaser {
            SingleFlightSlot& s;
            ~Releaser() { s.release(); }
        } releaser{slot};
        return fn();
    };
    auto r = yuzu::shared::bounded_call_ex(remaining, std::move(worker));
    switch (r.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = BoundedStatus::Completed;
        out.value = std::move(r.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        // Also a throwing fn, which returns at once with no value. If the worker is still
        // running, mark it abandoned so the next call is told so, not just "busy".
        slot.mark_abandoned(ticket.generation);
        out.status = BoundedStatus::TimedOut;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        // The worker never ran, so no releaser exists: release the slot here.
        slot.release();
        out.status = BoundedStatus::Rejected;
        break;
    }
    return out;
}

} // namespace detail

} // namespace yuzu::agent
