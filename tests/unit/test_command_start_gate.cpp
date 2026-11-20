// command_may_start / command_may_stagger: a protective action queued ahead of a teardown still runs
// and never sleeps a stagger; an ordinary one is rejected (ADR-2005).

#include "command_start_gate.hpp"
#include "thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <condition_variable>
#include <mutex>

using yuzu::agent::command_may_stagger;
using yuzu::agent::command_may_start;
using yuzu::agent::ThreadPool;

TEST_CASE("command_may_start: only a protective action starts while the pool is closing",
          "[command_start_gate][protective]") {
    CHECK(command_may_start("echo", "run", false));
    CHECK_FALSE(command_may_start("echo", "run", true));
    CHECK_FALSE(command_may_start("firewall", "state", true)); // an ordinary firewall action
    CHECK(command_may_start("firewall", "quarantine", true));
    CHECK(command_may_start("firewall", "release", true));
    CHECK(command_may_start("firewall", "quarantine_status", true));
    CHECK(command_may_start("firewall", "quarantine_allow", true));
    CHECK(command_may_start("__guard__", "push_rules", true));
    CHECK(command_may_start("Firewall", "QUARANTINE", true)); // the shared predicate folds case
}

TEST_CASE("command_may_stagger: a protective action never sleeps a stagger or delay",
          "[command_start_gate][protective]") {
    CHECK(command_may_stagger("echo", "run"));
    CHECK_FALSE(command_may_stagger("firewall", "quarantine"));
    CHECK_FALSE(command_may_stagger("__guard__", "push_rules"));
}

TEST_CASE("a protective task queued behind a blocker still runs at teardown; an ordinary one is rejected",
          "[command_start_gate][protective]") {
    std::mutex m;
    std::condition_variable cv;
    bool release = false;
    std::atomic<bool> blocker_started{false};
    std::atomic<bool> closing{false};
    std::atomic<int> protective_ran{0};
    std::atomic<int> ordinary_ran{0};
    std::atomic<int> ordinary_rejected{0};
    {
        // Declared AFTER the state its tasks capture, so ~ThreadPool joins first.
        ThreadPool pool(1);
        REQUIRE(pool.submit([&] {
            blocker_started = true;
            std::unique_lock lk(m);
            cv.wait(lk, [&] { return release; });
        }));
        while (!blocker_started.load())
            std::this_thread::yield();
        auto task = [&](const char* plugin, const char* action, std::atomic<int>& ran,
                        std::atomic<int>* rejected) {
            return [&, plugin, action, rejected] {
                if (!command_may_start(plugin, action, closing.load())) {
                    if (rejected)
                        ++*rejected;
                    return;
                }
                ++ran;
            };
        };
        REQUIRE(pool.submit(task("firewall", "quarantine", protective_ran, nullptr)));
        REQUIRE(pool.submit(task("echo", "run", ordinary_ran, &ordinary_rejected)));
        REQUIRE(pool.submit(task("__guard__", "push_rules", protective_ran, nullptr)));
        closing = true; // the teardown sets the flag before the pool is reset
        {
            std::lock_guard lk(m);
            release = true;
        }
        cv.notify_all();
    } // ~ThreadPool drains the queue and joins
    CHECK(protective_ran.load() == 2);
    CHECK(ordinary_ran.load() == 0);
    CHECK(ordinary_rejected.load() == 1);
}
