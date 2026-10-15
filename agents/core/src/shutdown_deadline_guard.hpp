#pragma once

/// @file shutdown_deadline_guard.hpp
/// #2233 item 3 ("S+"): a pre-armed, whole-call shutdown deadline. hard_exit.hpp's
/// OrphanExitGuard is a POST-HOC drain poll — constructed before Agent::run(), checked
/// only after it returns — and does not cover a hang DURING teardown itself. The only
/// existing escalation, main.cpp's second-SIGINT hard_exit(1), is human/external-signal-
/// only, never a timer (see common/include/yuzu/shutdown_watcher.hpp's own former "no
/// internal bound" comment, which this file supersedes). ShutdownDeadlineGuard is that
/// missing internal bound: construct it as the first statement of a call that must not
/// hang (AgentImpl::stop(), run()'s teardown ScopeExit); on scope exit it cancels; if the
/// wrapped call is still running when the grace period elapses, it calls hard_exit()
/// directly, without acquiring any lock the wrapped call might be holding.
///
/// WHY hard_exit() STAYS SAFE even with a legitimately in-flight, uncancellable worker
/// (e.g. a plugin-ABI call nothing can interrupt): hard_exit() skips ALL normal teardown —
/// no join, no destructor runs, no unwinding — rather than trying to wait for or cancel
/// anything. A worker "still running" at the moment of hard_exit() is a non-issue by
/// construction. (A prior attempt at an internal deadline failed review three times
/// specifically because it was designed against an idle agent and didn't reason through
/// this; that reasoning is why this design is safe where that one wasn't.)

#include "guardian_io_executor.hpp" // io_detail::spawn_detached
#include "hard_exit.hpp"            // hard_exit()

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>

namespace yuzu::agent {

/// Distinct from hard_exit's other production codes (1 = second-signal escalation,
/// main.cpp; 3 = F3 orphan-exit, main.cpp/service_win.cpp) so exit-code monitoring can
/// tell the three termination reasons apart. Also reused (#4666 PR-2, not via
/// ShutdownDeadlineGuard itself) by service_win.cpp's run_service(): a timeout on its
/// post-dispatcher-return wait for service_main's completion handshake
/// (service_completion.hpp) is the same "something past its own internal watchdogs is
/// wedged" condition this code already denotes, so it shares the code rather than
/// minting a new one.
inline constexpr int kShutdownDeadlineExitCode = 4;

/// Templated on Action rather than std::function, for the exact reason
/// wait_for_workers_to_drain() (hard_exit.hpp) is templated: a std::function CONVERSION
/// can itself allocate and throw, which would skip hard_exit() entirely on the one path
/// where skipping it matters most. Neither this class nor its worker ever lets an
/// exception escape uncaught — every failure mode routes to hard_exit(), fail-closed,
/// because the callers this exists for (AgentImpl::stop()) are themselves noexcept, and
/// a construction failure reaching std::terminate() instead of hard_exit() would run CRT
/// abort handling on Windows — not equivalent to TerminateProcess, and exactly the
/// distinction hard_exit.hpp's own header comment warns about.
///
/// Non-copyable, non-movable: a copy would share one deadline, and destroying either
/// copy would cancel it prematurely. Matches OrphanExitGuard's own precedent
/// (hard_exit.hpp) of deleting copy for a guard whose whole contract is "exactly one
/// owner decides when this cancels."
template <class Action = decltype([] { hard_exit(kShutdownDeadlineExitCode); })>
class ShutdownDeadlineGuard {
public:
    explicit ShutdownDeadlineGuard(std::chrono::milliseconds grace,
                                   Action action = Action{}) noexcept {
        try {
            state_ = std::make_shared<State>();
            state_->deadline = std::chrono::steady_clock::now() + grace;
            const bool launched = io_detail::spawn_detached([state = state_, action] {
                try {
                    std::unique_lock<std::mutex> lk(state->mu);
                    state->cv.wait_until(lk, state->deadline, [&] { return state->cancelled; });
                    if (state->cancelled)
                        return; // cancel() committed first — normal path, nothing to do
                    // Once fired commits under the lock, cancel() (if it races in after
                    // this point) is a documented no-op — see cancel()'s own comment.
                    state->fired = true;
                    lk.unlock(); // action runs OUTSIDE mu_ — it does not return in
                                 // production (hard_exit()), so nothing downstream of this
                                 // worker will ever observe mu_ held past this point anyway,
                                 // but a test-injected action must not need to re-enter mu_.
                    action();
                } catch (...) {
                    // Worker-side backstop: spawn_detached's trampoline has no exception
                    // safety of its own (an uncaught throw here would std::terminate the
                    // detached thread) — fail-closed to the same primitive the whole class
                    // exists to reach.
                    hard_exit(kShutdownDeadlineExitCode);
                }
            });
            if (!launched)
                hard_exit(kShutdownDeadlineExitCode); // OS refused the thread — fail closed,
                                                       // never silently un-armed
        } catch (...) {
            // Construction-side backstop: make_shared<State>, the deadline arithmetic, or
            // capturing `action` into the detached closure can all throw. Uncaught, that
            // would escape this constructor and — since every real caller of this class is
            // itself noexcept — reach std::terminate() instead of hard_exit(). Fail closed
            // instead.
            hard_exit(kShutdownDeadlineExitCode);
        }
    }

    ShutdownDeadlineGuard(const ShutdownDeadlineGuard&) = delete;
    ShutdownDeadlineGuard& operator=(const ShutdownDeadlineGuard&) = delete;
    ShutdownDeadlineGuard(ShutdownDeadlineGuard&&) = delete;
    ShutdownDeadlineGuard& operator=(ShutdownDeadlineGuard&&) = delete;

    ~ShutdownDeadlineGuard() { cancel(); }

    /// Idempotent; safe to call from the constructing thread only (matches this class's
    /// single-owner, stack-local usage — it is not intended as a cross-thread handle).
    void cancel() noexcept {
        if (!state_)
            return;
        {
            std::lock_guard<std::mutex> lk(state_->mu);
            state_->cancelled = true;
        }
        state_->cv.notify_all();
        // If `fired` already committed (the worker observed the deadline and is at or
        // past `state->fired = true;` above), this cancel() is deliberately a no-op: once
        // firing has started there is nothing left to cancel — the worker has already
        // unlocked and may already be inside action(). Documented, not a bug. This includes
        // the microseconds-before-the-deadline boundary case: a call that genuinely returned
        // just before `cancel()` runs can still lose that race and get hard_exit(4)'d anyway
        // (external review, PR #3737) — indistinguishable from an ordinary firing, so it
        // costs an unnecessary exit/restart cycle but nothing worse.
    }

    /// Test seam only.
    bool fired_for_test() const {
        if (!state_)
            return false;
        std::lock_guard<std::mutex> lk(state_->mu);
        return state_->fired;
    }

private:
    struct State {
        std::mutex mu;
        std::condition_variable cv;
        std::chrono::steady_clock::time_point deadline;
        bool cancelled{false};
        bool fired{false};
    };
    std::shared_ptr<State> state_;
};

} // namespace yuzu::agent
