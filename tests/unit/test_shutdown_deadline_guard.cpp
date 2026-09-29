// test_shutdown_deadline_guard.cpp - #2233 item 3 ("S+"): ShutdownDeadlineGuard's own
// primitive, isolated from AgentImpl/GuardianEngine entirely. Every case here injects a
// recorder action and never invokes the real default (hard_exit()) except the one
// POSIX-only death test at the bottom, which proves the REAL production default action
// and exit code in a subprocess - the same fork()/waitpid() shape already established by
// test_guardian_engine_spark_reconcile.cpp's "a worker-thread mtx_ acquisition aborts the
// process" test, reused here rather than building new subprocess infrastructure.

#include "shutdown_deadline_guard.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <type_traits>

#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;
using yuzu::agent::kShutdownDeadlineExitCode;
using yuzu::agent::ShutdownDeadlineGuard;

// ---------------------------------------------------------------------------
// Compile-time: non-copyable, non-movable (governance Sol opine BLOCKING 3 - a copy
// would share one deadline, and destroying either copy would cancel it prematurely).
// ---------------------------------------------------------------------------
static_assert(!std::is_copy_constructible_v<ShutdownDeadlineGuard<>>);
static_assert(!std::is_copy_assignable_v<ShutdownDeadlineGuard<>>);
static_assert(!std::is_move_constructible_v<ShutdownDeadlineGuard<>>);
static_assert(!std::is_move_assignable_v<ShutdownDeadlineGuard<>>);

TEST_CASE("cancel() before the deadline prevents the action from firing",
          "[shutdown_deadline_guard]") {
    auto fired = std::make_shared<std::atomic<bool>>(false);
    ShutdownDeadlineGuard guard{200ms, [fired] { fired->store(true, std::memory_order_release); }};
    guard.cancel();

    // Give the worker time to have observed the deadline if cancel() hadn't worked - the
    // grace (200ms) is generous relative to this sleep, so a real bug here would show up
    // reliably, not just occasionally.
    std::this_thread::sleep_for(300ms);
    CHECK_FALSE(fired->load(std::memory_order_acquire));
    CHECK_FALSE(guard.fired_for_test());
}

TEST_CASE("the destructor cancels an un-fired guard, same as explicit cancel()",
          "[shutdown_deadline_guard]") {
    auto fired = std::make_shared<std::atomic<bool>>(false);
    {
        ShutdownDeadlineGuard guard{200ms, [fired] { fired->store(true, std::memory_order_release); }};
        // left armed - the destructor below must cancel it.
    }
    std::this_thread::sleep_for(300ms);
    CHECK_FALSE(fired->load(std::memory_order_acquire));
}

TEST_CASE("an un-cancelled guard fires the action exactly once after the grace period",
          "[shutdown_deadline_guard]") {
    auto fire_count = std::make_shared<std::atomic<int>>(0);
    ShutdownDeadlineGuard guard{30ms, [fire_count] { fire_count->fetch_add(1, std::memory_order_release); }};

    REQUIRE(yuzu::test::spin_until([&] { return fire_count->load(std::memory_order_acquire) > 0; },
                                   2s));
    CHECK(guard.fired_for_test());
    CHECK(fire_count->load(std::memory_order_acquire) == 1);

    // Documented no-op: once firing has committed, cancel() cannot revoke it. Prove it
    // doesn't somehow suppress a SECOND firing (there is no second firing to suppress -
    // the worker exits after calling action() once) and doesn't itself misbehave.
    guard.cancel();
    std::this_thread::sleep_for(50ms);
    CHECK(fire_count->load(std::memory_order_acquire) == 1);
}

TEST_CASE("two independent guards fire and cancel independently",
          "[shutdown_deadline_guard]") {
    auto fired_a = std::make_shared<std::atomic<bool>>(false);
    auto fired_b = std::make_shared<std::atomic<bool>>(false);

    ShutdownDeadlineGuard guard_a{30ms, [fired_a] { fired_a->store(true, std::memory_order_release); }};
    ShutdownDeadlineGuard guard_b{5s, [fired_b] { fired_b->store(true, std::memory_order_release); }};

    // guard_a fires (short grace); guard_b is cancelled well before its own long grace
    // would elapse - proves one firing has no effect on the other's cancellation.
    REQUIRE(yuzu::test::spin_until(
        [&] { return fired_a->load(std::memory_order_acquire); }, 2s));
    guard_b.cancel();
    std::this_thread::sleep_for(50ms);

    CHECK(fired_a->load(std::memory_order_acquire));
    CHECK_FALSE(fired_b->load(std::memory_order_acquire));
}

TEST_CASE("cancel racing the deadline is race-free under repeat",
          "[shutdown_deadline_guard]") {
    // Sol opine's specific warning: a detached worker must be allowed to retire before
    // test-local recorder state is destroyed, or a repeat-only timing race test can pass
    // vacuously (the worker touches already-destroyed memory, which may or may not crash
    // depending on luck/ASan). Every piece of state the worker can touch is therefore
    // shared_ptr-owned here, and each iteration waits on an explicit "the worker is done"
    // signal (set by BOTH the cancelled path and the fired path) before moving on, so no
    // iteration ever leaves a detached worker with a dangling reference into a destroyed
    // stack frame.
    for (int i = 0; i < 50; ++i) {
        auto retired = std::make_shared<std::atomic<bool>>(false);
        auto fired = std::make_shared<std::atomic<bool>>(false);
        {
            // Tight grace, deliberately racing cancel() below - either outcome (cancelled
            // before firing, or fired before cancel() lands) is a PASS; the only failure
            // mode under test is a crash/hang/UB from the race itself (run this under TSan
            // in CI for the actual data-race guarantee; this loop proves liveness).
            ShutdownDeadlineGuard guard{1ms, [fired, retired] {
                                            fired->store(true, std::memory_order_release);
                                            retired->store(true, std::memory_order_release);
                                        }};
            guard.cancel();
        }
        // If the action never runs (cancel won the race), nothing ever sets `retired` -
        // that is a legitimate outcome, not a hang, so don't require it: wait a bounded,
        // short window for EITHER outcome to settle before the shared_ptrs go out of
        // scope naturally (they stay alive as long as the detached worker holds its own
        // copy, so this is a liveness convenience, not a correctness requirement).
        (void)yuzu::test::spin_until([&] { return retired->load(std::memory_order_acquire); },
                                      20ms);
    }
    SUCCEED("50 cancel-vs-fire races completed without crash/hang");
}

#ifndef _WIN32
// Death test: proves the REAL production default action (hard_exit(kShutdownDeadlineExitCode))
// in a real subprocess - not a mock, not the injected-recorder shape every other case here
// uses. Reuses the fork()/waitpid() pattern already established in
// test_guardian_engine_spark_reconcile.cpp's "a worker-thread mtx_ acquisition aborts the
// process" death test.
TEST_CASE("an un-cancelled guard's real default action hard_exit()s with the documented code",
          "[shutdown_deadline_guard][death]") {
    // Governance pass-4 sg-105: the fourth fork()-without-exec site in yuzu_agent_tests.
    // Under whole-suite TSan another test's detached worker can still be alive here, and
    // TSan kills the child the moment it starts a thread (die_after_fork; reproduced 1/3
    // on rung 9c PR-1). Same gate as the three Guardian death tests.
    REQUIRE(yuzu::test::wait_until_quiescent()); // no stray worker at fork
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);

    if (pid == 0) {
        // ---- child ----
        ::signal(SIGABRT, SIG_DFL); // see the sibling death test for why: Catch2's fatal-
                                    // signal handler would otherwise intercept and print a
                                    // spurious failure from the child into the parent's output.
        ShutdownDeadlineGuard<> guard{10ms}; // REAL default action: hard_exit(kShutdownDeadlineExitCode)
        std::this_thread::sleep_for(std::chrono::seconds(5)); // if the guard fails to fire, this
                                                                // gives it a bounded window before
                                                                // falling through to a distinct code
        ::_exit(95); // distinct from kShutdownDeadlineExitCode - "guard never fired"
    }

    // ---- parent ---- poll rather than a blocking wait, matching the sibling death test's
    // own reasoning: if the guard has regressed to never firing, a blocking wait would hang
    // the whole suite instead of failing cleanly.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            reaped = true;
            break;
        }
        REQUIRE(r == 0); // -1 would be a wait error, not a still-running child
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child did not exit within the bounded window - guard did not fire");
    }

    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == kShutdownDeadlineExitCode);
}
#endif
