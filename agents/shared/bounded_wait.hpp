/**
 * bounded_wait.hpp — generic bounded-wait wrapper for an uncancellable
 * blocking call (Wave 2 PR2.1c, governance Gate 4 unhappy-path finding).
 *
 * Hoisted from agents/plugins/discovery/src/bounded_wait.hpp to agents/shared
 * (#3429 round 4) once a second consumer needed the identical primitive:
 * agents/core/src/server_address_resolver.cpp bounds its own getaddrinfo()
 * call the same way discovery bounds getnameinfo() — a plain
 * std::async(std::launch::async, ...)-obtained future's destructor blocks
 * the calling thread until the task finishes even after wait_for() times
 * out ([futures.async]), so it cannot serve as a caller-side deadline on its
 * own. bounded_call()'s detached-thread-plus-condition-variable shape does
 * not have that problem: nothing on the caller's stack ever waits on the
 * detached thread past `timeout`.
 *
 * Some blocking calls (getnameinfo's reverse-DNS lookup, in particular) have
 * no caller-supplied cancellation or timeout primitive. Calling one directly
 * from a task running on the agent's bounded ThreadPool risks pinning a
 * worker indefinitely if the underlying operation black-holes rather than
 * fails outright — and plugin execute() has no per-task cancellation to fall
 * back on, so a handful of stuck calls can exhaust the whole pool and stall
 * every other command dispatched to the agent.
 *
 * bounded_call() bounds the WAIT instead of the call: `fn` runs on a detached
 * thread, and the caller gives up after `timeout` if it hasn't finished,
 * leaving the detached thread to complete (or not) on its own — harmless
 * once abandoned, since nothing observes its result after the deadline.
 *
 * Two hardenings added by governance Gate 5 (chaos-injector), both closing
 * a real gap in the first cut of this primitive:
 *
 *  - Outstanding-thread ceiling. A caller retrying against a SUSTAINED
 *    black hole (not a one-off) still bounds each individual WAIT, but
 *    nothing bounded how many detached threads could pile up concurrently —
 *    verified by execution to reach dozens of concurrently-outstanding
 *    threads under a simulated black hole. Since this codebase has other,
 *    pre-existing unguarded std::thread spawns elsewhere in the agent
 *    (tracked separately — see the fix commit), letting this primitive grow
 *    the process's OS thread count without limit is itself a resource-
 *    exhaustion vector. Once kMaxOutstandingBoundedCalls threads are already
 *    outstanding, a new call degrades to an immediate nullopt (the same
 *    outcome as a timeout) rather than spawning another thread — this never
 *    blocks the caller, which is the whole point of the primitive.
 *  - Exception safety. `fn()` running on a raw detached thread is NOT
 *    covered by ThreadPool's own exception firewall (that only wraps
 *    pool-dispatched tasks). An exception escaping `fn()` uncaught would
 *    std::terminate() the whole process. Caught and treated as a
 *    non-arrival — the waiting side (if still waiting) simply times out.
 *
 * A third hardening, added by colleague review of the above two: the ceiling
 * counter itself is claimed and released through `detail::OutstandingCallGuard`
 * (RAII: increment on construction, decrement on destruction), not a bare
 * `++`/`--`. `std::make_shared<State>` and `std::thread`'s constructor can
 * both throw (`std::bad_alloc`, `std::system_error` from `pthread_create`
 * under resource pressure) before the detached thread body — the only other
 * place that used to decrement — ever runs; a bare counter leaked a slot on
 * that path permanently. The guard is moved into the detached thread's
 * lambda so it is held for the call's full lifetime and releases correctly
 * whether the thread runs to completion, `fn()` throws inside it, or the
 * thread never starts at all (matches the pattern in `thread_pool.hpp` and
 * `shutdown_watcher.hpp`, both of which guard the identical construction-
 * failure class).
 */
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

namespace yuzu::shared {

namespace detail {

// Well above realistic legitimate concurrency (the agent's ThreadPool caps
// at 32 workers) but far below what would meaningfully threaten the
// process's OS thread budget.
constexpr int kMaxOutstandingBoundedCalls = 64;
inline std::atomic<int> g_outstanding_bounded_calls{0};

// Move-only RAII guard for a claimed slot on the outstanding-call ceiling.
// try_acquire() increments the counter and returns a held guard, or leaves
// the counter untouched and returns nullopt if already at the ceiling.
// Whichever way the held guard's lifetime ends -- normal destruction,
// stack unwinding from an exception thrown while it's still a local (e.g.
// std::make_shared<State> or std::thread's constructor throwing before the
// guard is handed off), or destruction as part of a moved-into lambda once
// the detached thread's body finishes -- release() runs exactly once and
// decrements the counter. A moved-FROM guard's own destructor is then a
// no-op, so ownership transfer (move into the detached thread's lambda)
// never double-decrements.
class OutstandingCallGuard {
public:
    OutstandingCallGuard(const OutstandingCallGuard&) = delete;
    OutstandingCallGuard& operator=(const OutstandingCallGuard&) = delete;

    OutstandingCallGuard(OutstandingCallGuard&& other) noexcept : held_{other.held_} {
        other.held_ = false;
    }
    OutstandingCallGuard& operator=(OutstandingCallGuard&& other) noexcept {
        if (this != &other) {
            release();
            held_ = other.held_;
            other.held_ = false;
        }
        return *this;
    }

    ~OutstandingCallGuard() { release(); }

    static std::optional<OutstandingCallGuard> try_acquire() {
        if (++g_outstanding_bounded_calls > kMaxOutstandingBoundedCalls) {
            --g_outstanding_bounded_calls;
            return std::nullopt; // at the ceiling — degrade like a timeout, never block
        }
        return OutstandingCallGuard{};
    }

private:
    OutstandingCallGuard() = default;

    void release() noexcept {
        if (held_) {
            --g_outstanding_bounded_calls;
            held_ = false;
        }
    }

    bool held_ = true;
};

} // namespace detail

/// Why a caller sometimes needs more than `std::nullopt`.
///
/// bounded_call() collapses two very different outcomes into one empty
/// optional: the call TIMED OUT (a detached thread is still running fn(), and
/// may still be touching whatever fn() captured), or it was REJECTED at the
/// outstanding-call ceiling (fn() was never invoked and no thread was ever
/// created, so nothing has touched anything). A caller holding an OS handle
/// that fn() uses must treat those oppositely: after a timeout, closing the
/// handle races a live call and it has to be leaked; after a rejection,
/// closing it is unconditionally safe. Rejection is also the case that
/// arrives in BURSTS, precisely when the agent is already loaded, so leaking
/// on it is both unnecessary and unbounded.
enum class BoundedCallStatus {
    Completed, ///< fn() ran and returned within the timeout.
    TimedOut,  ///< fn() is still running on a detached thread. Assume it is
               ///< still using anything it captured.
    Rejected,  ///< the ceiling refused the call. fn() was NEVER invoked and no
               ///< thread exists; anything it would have captured is untouched.
};

template <typename Fn>
struct BoundedCallResult {
    std::optional<std::invoke_result_t<Fn>> value;
    BoundedCallStatus status{BoundedCallStatus::Rejected};
};

/// bounded_call() with the outcome distinguished. bounded_call() below is a
/// thin wrapper over this, so the two can never diverge in behaviour.
template <typename Fn>
auto bounded_call_ex(std::chrono::milliseconds timeout, Fn fn) -> BoundedCallResult<Fn> {
    using Result = std::invoke_result_t<Fn>;

    auto guard = detail::OutstandingCallGuard::try_acquire();
    if (!guard)
        return {std::nullopt, BoundedCallStatus::Rejected}; // at the ceiling — never block

    struct State {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        Result value{};
    };
    // Setting the call UP can itself throw: make_shared under memory pressure,
    // and std::thread's constructor with std::system_error when pthread_create
    // fails at the process thread limit. Neither is inside the worker's own
    // try/catch below, so before this guard they propagated out of the caller --
    // and this primitive is reached from plugin entry points whose SDK
    // trampoline is `extern "C"` with no catch of its own, so the exception
    // would cross a C ABI and terminate the agent. Resource exhaustion must
    // degrade to the SAME typed rejection the outstanding-call ceiling already
    // produces, not take the process down. (The counter itself was already
    // safe: OutstandingCallGuard's RAII releases the slot on these paths --
    // that was a separate, earlier fix, and it is not this one.)
    std::shared_ptr<State> state;
    try {
        state = std::make_shared<State>();
    } catch (...) {
        return {std::nullopt, BoundedCallStatus::Rejected};
    }

    try {
        std::thread([fn = std::move(fn), state, guard = std::move(*guard)]() mutable {
        try {
            Result v = fn();
            std::lock_guard<std::mutex> lock(state->mtx);
            state->value = std::move(v);
            state->done = true;
        } catch (...) {
            // fn() throwing must not std::terminate() a detached thread.
            // Leave `done` false — a still-waiting caller simply times out.
        }
            state->cv.notify_all();
            // `guard` (captured by move) is destroyed with this lambda at the
            // end of this scope, releasing the outstanding-call slot -- whether
            // fn() returned normally or threw above.
        }).detach();
    } catch (...) {
        // Thread creation failed. `guard` was moved INTO the lambda, so on this
        // path the thread object never took ownership and the moved-from guard
        // in this scope releases the slot as it unwinds -- no leak, and fn()
        // was never invoked, which is exactly the Rejected contract.
        return {std::nullopt, BoundedCallStatus::Rejected};
    }

    std::unique_lock<std::mutex> lock(state->mtx);
    if (state->cv.wait_for(lock, timeout, [&] { return state->done; }))
        return {std::move(state->value), BoundedCallStatus::Completed};
    return {std::nullopt, BoundedCallStatus::TimedOut}; // the detached thread finishes on its own time
}

template <typename Fn>
auto bounded_call(std::chrono::milliseconds timeout, Fn fn)
    -> std::optional<std::invoke_result_t<Fn>> {
    return bounded_call_ex(timeout, std::move(fn)).value;
}

} // namespace yuzu::shared
