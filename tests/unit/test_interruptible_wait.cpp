// sleep_interruptible: a long stagger or delay never outlives a reconnect or stop (#8247's join waits
// for every running task; an uninterruptible sleep of up to 600 s made it wait the whole delay).

#include "interruptible_wait.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::sleep_interruptible;

TEST_CASE("sleep_interruptible: slices of at most one second, full duration when never stopped",
          "[interruptible_wait][stop]") {
    std::vector<std::chrono::milliseconds> slices;
    const bool done = sleep_interruptible(2500ms, [] { return false; },
                                          [&](std::chrono::milliseconds d) { slices.push_back(d); });
    CHECK(done);
    REQUIRE(slices.size() == 3);
    CHECK(slices[0] == 1000ms);
    CHECK(slices[1] == 1000ms);
    CHECK(slices[2] == 500ms);
    for (const auto s : slices)
        CHECK(s <= 1000ms);
    // A zero duration does not sleep.
    slices.clear();
    CHECK(sleep_interruptible(0ms, [] { return false; }, [&](std::chrono::milliseconds d) { slices.push_back(d); }));
    CHECK(slices.empty());
}

TEST_CASE("sleep_interruptible: a stop observed between slices ends it after at most one slice",
          "[interruptible_wait][stop]") {
    int slices = 0;
    bool stop = false;
    const bool done = sleep_interruptible(600s, [&] { return stop; },
                                          [&](std::chrono::milliseconds) {
                                              if (++slices == 2)
                                                  stop = true;
                                          });
    CHECK_FALSE(done);
    CHECK(slices == 2); // 600 s of work was not slept: the stop ended it within one slice
    // Already stopped: not even one slice.
    slices = 0;
    CHECK_FALSE(sleep_interruptible(600s, [] { return true; }, [&](std::chrono::milliseconds) { ++slices; }));
    CHECK(slices == 0);
}

TEST_CASE("sleep_interruptible: a 600 s stagger on a real thread is unblocked promptly by a stop",
          "[interruptible_wait][stop]") {
    // The state is shared with the thread, never borrowed from this stack frame, so a thread that
    // outlives a failed run (detached below) touches only memory it co-owns.
    struct Shared {
        std::atomic<bool> stop{false};
        std::atomic<bool> started{false};
        std::atomic<bool> finished{false};
        std::atomic<bool> result{true};
    };
    const auto st = std::make_shared<Shared>();
    std::thread worker([st] {
        st->started = true;
        st->result = sleep_interruptible(600s, [st] { return st->stop.load(); });
        st->finished = true;
    });
    while (!st->started.load())
        std::this_thread::yield();
    CHECK_FALSE(st->finished.load()); // a 600 s sleep cannot have ended
    const auto t0 = std::chrono::steady_clock::now();
    st->stop = true;
    // The stop is seen within one slice (1 s) plus scheduling slack.
    while (!st->finished.load() && std::chrono::steady_clock::now() - t0 < 5s)
        std::this_thread::yield();
    const bool ok = st->finished.load();
    if (ok)
        worker.join();
    else
        worker.detach(); // a hang is the failure being reported; the thread owns its state
    CHECK(ok);
    CHECK_FALSE(st->result.load());
}
