// test_service_completion.cpp - the platform-neutral completion-handshake pair behind the
// Windows service shutdown race fix (#4666 PR-2): SemaphoreReleaseGuard's "declare first so
// it releases last" contract and wait_for_service_main_completion()'s bounded wait.
//
// Scale-separated timing: the original 250ms ceilings were crossed by an ordinary CI runner
// stall (258.6ms observed on a macOS debug leg). Tests 1-2 now use a 30s grace and assert
// completion well inside it (elapsed < grace/2), so a stall of a few seconds can never cross
// the assertion - only a wait that actually sleeps out the grace fails it, at a cost of 30s
// per test (60s worst case). On Linux and macOS that fits the agent suite's budget; the
// Windows legs already run near their 240s budget (tests/meson.build:832), so there that
// regression shows up as a suite timeout rather than two named CHECK failures - still red.
// Test 3 must wait its grace out by design, so it keeps a short 100ms grace, a floor, and a
// loose 5s ceiling.
//
// MUTATION-TESTED (service_completion.hpp temporarily edited, then restored - never committed):
// `sleep_for(grace); return done.try_acquire();` turned tests 1-2 red (elapsed ~30.01s, over the
// 15s bound); `return done.try_acquire();` alone (no wait) turned test 3's floor red (elapsed
// 0ns, under the 80ms floor). Both restored; all four cases green:
//   build-macos/tests/yuzu_agent_tests "[service_completion]"

#include "service_completion.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <semaphore>
#include <thread>

using namespace std::chrono_literals;

TEST_CASE("wait returns true without waiting out the grace when already released",
          "[service_completion]") {
    constexpr auto kGrace = 30s;
    std::binary_semaphore done{0};
    done.release();

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(completed);
    CHECK(elapsed < kGrace / 2); // scale separation: a runner stall of seconds cannot cross
                                 // 15s, while a wait that sleeps out the grace takes 30s
}

TEST_CASE("wait returns true once released mid-wait, bounded by the release not the grace",
          "[service_completion]") {
    constexpr auto kGrace = 30s;
    std::binary_semaphore done{0};
    // NOT std::jthread - Apple Clang's libc++ does not provide it (established
    // precedent: test_ca_store.cpp, test_secret_codec.cpp, test_store_worker_pool.cpp).
    // JoinGuard covers the unwind path; the explicit join() below is the normal path.
    std::thread releaser([&done] {
        std::this_thread::sleep_for(20ms);
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
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    releaser.join(); // explicit join before asserting; join_guard is the safety net

    CHECK(completed);
    CHECK(elapsed < kGrace / 2); // bounded by the ~20ms release, not the 30s grace
}

TEST_CASE("wait returns false once the grace elapses and its wait is bounded when never released",
          "[service_completion]") {
    constexpr auto kGrace = 100ms;
    // MSVC's try_acquire_for was observed returning at 98.891ms against a 100ms grace on the
    // Windows debug CI leg (tick granularity) - the floor carries a documented one-tick
    // tolerance rather than an unconditional `>= kGrace`.
    constexpr auto kFloorTolerance = 20ms;
    std::binary_semaphore done{0};

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, kGrace);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(completed);
    CHECK(elapsed >= kGrace - kFloorTolerance);
    CHECK(elapsed < 5s); // still catches an unbounded wait or a unit mix-up
}

TEST_CASE("SemaphoreReleaseGuard releases exactly once on normal destruction",
          "[service_completion]") {
    std::binary_semaphore sem{0};
    {
        yuzu::agent::SemaphoreReleaseGuard guard(sem);
    }
    CHECK(sem.try_acquire_for(0ms));
}
