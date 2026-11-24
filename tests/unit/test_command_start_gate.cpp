// command_may_start / command_may_stagger: a protective action queued ahead of a teardown still runs
// and never sleeps a stagger; an ordinary one is rejected (ADR-2005).

#include "command_start_gate.hpp"
#include "thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <condition_variable>
#include <mutex>
#include <thread>

using yuzu::agent::closing_run_warn_due;
using yuzu::agent::command_may_expire;
using yuzu::agent::command_may_stagger;
using yuzu::agent::note_protective_run_closing;
using yuzu::agent::protective_runs_while_closing;
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
    // ThreadPool clamps its size to at least 4 workers, so occupy all of them: only then do the
    // three tasks below queue behind running work instead of starting at once.
    constexpr int kBlockers = 4;
    std::atomic<int> blockers_started{0};
    std::atomic<bool> closing{false};
    std::atomic<int> protective_ran{0};
    std::atomic<int> ordinary_ran{0};
    std::atomic<int> ordinary_rejected{0};
    {
        // Declared AFTER the state its tasks capture, so ~ThreadPool joins first.
        ThreadPool pool(1);
        for (int i = 0; i < kBlockers; ++i) {
            REQUIRE(pool.submit([&] {
                ++blockers_started;
                std::unique_lock lk(m);
                cv.wait(lk, [&] { return release; });
            }));
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (blockers_started.load() < kBlockers) {
            if (std::chrono::steady_clock::now() >= deadline) {
                {
                    std::lock_guard lk(m);
                    release = true;
                }
                cv.notify_all();
                FAIL("the blocker tasks did not all start within 30 s");
            }
            std::this_thread::yield();
        }
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

TEST_CASE("command_may_expire: a protective action is never rejected as expired",
          "[command_start_gate][protective]") {
    CHECK(command_may_expire("echo", "run"));
    CHECK(command_may_expire("firewall", "state")); // an ordinary firewall action
    CHECK_FALSE(command_may_expire("firewall", "quarantine"));
    CHECK_FALSE(command_may_expire("firewall", "release"));
    CHECK_FALSE(command_may_expire("firewall", "quarantine_status"));
    CHECK_FALSE(command_may_expire("firewall", "quarantine_allow"));
    CHECK_FALSE(command_may_expire("__guard__", "push_rules"));
    CHECK_FALSE(command_may_expire("FIREWALL", "Quarantine"));
}

TEST_CASE("a protective run at a pool close is counted and its WARN is throttled",
          "[command_start_gate][protective]") {
    CHECK_FALSE(protective_runs_while_closing("firewall", "quarantine", false));
    CHECK_FALSE(protective_runs_while_closing("echo", "run", true));
    CHECK(protective_runs_while_closing("firewall", "quarantine", true));

    yuzu::MetricsRegistry metrics;
    std::atomic<std::uint64_t> seq{0};
    int warns = 0;
    for (int i = 0; i < 250; ++i)
        if (note_protective_run_closing(metrics, seq))
            ++warns;
    CHECK(warns == 7); // runs 1-5, 100 and 200
    CHECK(metrics.counter("yuzu_agent_protective_commands_run_closing_total").value() == 250.0);
    CHECK_FALSE(closing_run_warn_due(0));
}
