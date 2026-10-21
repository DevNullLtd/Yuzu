// test_service_completion.cpp - the platform-neutral completion-handshake pair behind the
// Windows service shutdown race fix (#4666 PR-2): SemaphoreReleaseGuard's "declare first so
// it releases last" contract and wait_for_service_main_completion()'s bounded wait.

#include "service_completion.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <semaphore>
#include <thread>

using namespace std::chrono_literals;

// Timing policy (#5173). No UPPER bound here is a wall-clock margin under ~1 s:
//  - Upper bounds are SCALE-SEPARATED: a 30 s grace asserted against `elapsed < grace / 2`
//    (15 s). A loaded runner (observed: a 310 ms stall against a 250 ms bound on macOS)
//    cannot cross that, while a wait that ignores the semaphore and sleeps out the whole
//    grace (30 s) still fails it.
//  - Lower bounds carry a one-tick tolerance. MSVC's std::binary_semaphore::try_acquire_for
//    builds its deadline from GetTickCount64() (tick = ~15.6 ms), so it can return up to one
//    tick EARLY against steady_clock (observed: 98.4-99.7 ms for a 100 ms wait). kTickTolerance
//    is a little over one tick (the lower bounds below are one-sided, so extra room is free).
//  - "Returned only after the release" is proven deterministically with a flag set before
//    the release, not by elapsed time.
// Only the never-released test actually waits a grace out, so its grace is kept short
// (kShortGrace); its hang/ignore-the-grace failure mode is caught by a 30 s backstop.
// Confirmed on real MSVC (debug, Windows 11): the original `elapsed >= 100ms` failed 14 of
// 200 runs at 98.4-99.7 ms. Not run on macOS.
// Contract note: with the 15 s upper bound this file detects a wait that blocks or ignores the
// grace, and a wait that returns early; it does NOT detect one that overshoots by a small
// factor.
namespace {
constexpr auto kLongGrace = 30s;      // never waited out by a correct implementation
constexpr auto kShortGrace = 250ms;   // waited out once, by the never-released test
constexpr auto kTickTolerance = 50ms; // one GetTickCount64 tick (~15.6 ms) plus truncation, with room
} // namespace

TEST_CASE("wait returns true near-instantly when already released",
          "[service_completion]") {
    std::binary_semaphore done{0};
    done.release();

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kLongGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(completed);
    CHECK(elapsed < kLongGrace / 2); // must not wait the grace out
}

TEST_CASE("wait returns true once released mid-wait, bounded by the release not the grace",
          "[service_completion]") {
    std::binary_semaphore done{0};
    std::atomic<bool> released{false};
    // NOT std::jthread - Apple Clang's libc++ does not provide it (established
    // precedent: test_ca_store.cpp, test_secret_codec.cpp, test_store_worker_pool.cpp).
    // JoinGuard covers the unwind path; the explicit join() below is the normal path.
    std::thread releaser([&done, &released] {
        std::this_thread::sleep_for(20ms);
        released.store(true); // strictly before the release the waiter must observe
        done.release();
    });
    struct JoinGuard {
        std::thread& t;
        ~JoinGuard() {
            if (t.joinable())
                t.join();
        }
    } join_guard{releaser};

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kLongGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const bool saw_release = released.load();
    releaser.join(); // explicit join before asserting; join_guard is the safety net

    CHECK(completed);
    CHECK(saw_release);              // true was returned only after the mid-wait release
    CHECK(elapsed < kLongGrace / 2); // bounded by the release, not the grace
}

TEST_CASE("wait returns false after the grace and neither returns early nor hangs when never released",
          "[service_completion]") {
    std::binary_semaphore done{0};

    // Backstop: if the code under test ignores the grace and blocks, release after 30 s so
    // the test FAILS (completed == true) rather than hanging. Cancelled as soon as the wait
    // returns, so a correct run never reaches it.
    std::mutex m;
    std::condition_variable cv;
    bool cancel = false;
    std::thread backstop([&] {
        std::unique_lock lk(m);
        if (!cv.wait_for(lk, kLongGrace, [&] { return cancel; }))
            done.release();
    });
    struct JoinGuard {
        std::thread& t;
        std::mutex& m;
        std::condition_variable& cv;
        bool& cancel;
        ~JoinGuard() {
            {
                std::lock_guard lk(m);
                cancel = true;
            }
            cv.notify_all();
            if (t.joinable())
                t.join();
        }
    } join_guard{backstop, m, cv, cancel};

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kShortGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(completed);
    CHECK(elapsed >= kShortGrace - kTickTolerance); // did not return early (one-tick tolerance)
    CHECK(elapsed < kLongGrace / 2);                // honoured the grace, did not block on the backstop
}

TEST_CASE("SemaphoreReleaseGuard releases exactly once on normal destruction",
          "[service_completion]") {
    std::binary_semaphore sem{0};
    {
        yuzu::agent::SemaphoreReleaseGuard guard(sem);
    }
    CHECK(sem.try_acquire_for(0ms));
}
