// test_service_completion.cpp - the platform-neutral completion-handshake pair behind the
// Windows service shutdown race fix (#4666 PR-2): SemaphoreReleaseGuard's "declare first so
// it releases last" contract and wait_for_service_main_completion()'s bounded wait.

#include "service_completion.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <semaphore>
#include <thread>

using namespace std::chrono_literals;

TEST_CASE("wait returns true near-instantly when already released",
          "[service_completion]") {
    std::binary_semaphore done{0};
    done.release();

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, 500ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(completed);
    CHECK(elapsed < 250ms); // well under the grace - must not wait it out
}

TEST_CASE("wait returns true once released mid-wait, bounded by the release not the grace",
          "[service_completion]") {
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
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, 500ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    releaser.join(); // explicit join before asserting; join_guard is the safety net

    CHECK(completed);
    CHECK(elapsed < 250ms); // bounded by the ~20ms sleep, not the 500ms grace
}

TEST_CASE("wait returns false and does not overshoot the grace when never released",
          "[service_completion]") {
    std::binary_semaphore done{0};

    const auto start = std::chrono::steady_clock::now();
    const bool completed = yuzu::agent::wait_for_service_main_completion(done, 100ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(completed);
    CHECK(elapsed >= 100ms);
    CHECK(elapsed < 300ms); // generous margin - shared CI hardware
}

TEST_CASE("SemaphoreReleaseGuard releases exactly once on normal destruction",
          "[service_completion]") {
    std::binary_semaphore sem{0};
    {
        yuzu::agent::SemaphoreReleaseGuard guard(sem);
    }
    CHECK(sem.try_acquire_for(0ms));
}
