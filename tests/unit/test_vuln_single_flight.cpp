/**
 * test_vuln_single_flight.cpp — vuln_scan's single-flight/result-cache helper cannot wedge.
 */

#include "single_flight.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using yuzu::vuln::SingleFlight;

namespace {
// Copying throws while `armed` is set (models bad_alloc on an 8 MiB copy).
std::atomic<bool> g_throw_on_copy{false};
struct Payload {
    std::string text;
    Payload() = default;
    explicit Payload(std::string t) : text(std::move(t)) {}
    Payload(const Payload& o) : text(o.text) {
        if (g_throw_on_copy.load())
            throw std::bad_alloc();
    }
    Payload& operator=(const Payload& o) {
        if (g_throw_on_copy.load())
            throw std::bad_alloc();
        text = o.text;
        return *this;
    }
    Payload(Payload&&) noexcept = default;
    Payload& operator=(Payload&&) noexcept = default;
};
// Disarms the throwing copy on scope exit, so a failed assertion cannot leak the armed state.
struct DisarmOnExit {
    ~DisarmOnExit() { g_throw_on_copy = false; }
};
} // namespace

TEST_CASE("single flight: the result is cached for the ttl", "[vuln][flight]") {
    SingleFlight<std::string> f;
    int runs = 0;
    auto run = [&] { ++runs; return std::string("v"); };
    CHECK(f.get(run, 10s, 5s, std::string("failed")) == "v");
    CHECK(f.get(run, 10s, 5s, std::string("failed")) == "v");
    CHECK(runs == 1);
}

TEST_CASE("single flight: an expired entry runs again", "[vuln][flight]") {
    SingleFlight<int> f;
    int runs = 0;
    auto run = [&] { return ++runs; };
    CHECK(f.get(run, 1ms, 5s, -1) == 1);
    std::this_thread::sleep_for(20ms);
    CHECK(f.get(run, 1ms, 5s, -1) == 2);
}

TEST_CASE("single flight: a throwing run returns the failed result and does not wedge",
          "[vuln][flight]") {
    SingleFlight<std::string> f;
    auto boom = []() -> std::string { throw std::runtime_error("x"); };
    CHECK(f.get(boom, 10s, 5s, std::string("failed")) == "failed");
    // a later caller is not blocked behind a stuck "running" flag
    auto fut = std::async(std::launch::async,
                          [&] { return f.get([] { return std::string("ok"); }, 10s, 5s, std::string("failed")); });
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    CHECK(fut.get() != "");
}

TEST_CASE("single flight: a throwing result copy (bad_alloc) is survived and does not wedge",
          "[vuln][flight]") {
    SingleFlight<Payload> f;
    const DisarmOnExit disarm;
    // run() builds its payload, THEN the copy starts throwing: the best-effort cache write (a copy
    // assignment inside the flight) throws, and get() must still return the run's result.
    auto r1 = std::async(std::launch::async, [&] {
        try {
            return f
                .get(
                    [] {
                        Payload p("a");
                        g_throw_on_copy = true;
                        return p;
                    },
                    10s, 5s, Payload("failed"))
                .text;
        } catch (...) {
            return std::string("threw");
        }
    });
    REQUIRE(r1.wait_for(5s) == std::future_status::ready);
    CHECK(r1.get() == "a"); // not "threw": the cache-write exception was contained
    g_throw_on_copy = false;
    // the flag was cleared by the scope guard and nothing was cached: the next caller runs
    const auto t0 = std::chrono::steady_clock::now();
    auto r2 = std::async(std::launch::async,
                         [&] { return f.get([] { return Payload("b"); }, 10s, 5s, Payload("failed")).text; });
    REQUIRE(r2.wait_for(3s) == std::future_status::ready);
    CHECK(r2.get() == "b");
    CHECK(std::chrono::steady_clock::now() - t0 < 3s);
}

TEST_CASE("single flight: a waiter behind an overdue leader gets the failed result, not a hang",
          "[vuln][flight]") {
    SingleFlight<std::string> f;
    std::promise<void> release;
    std::promise<void> started;
    auto gate = release.get_future().share();
    auto leader = std::async(std::launch::async, [&] {
        return f.get([&] { started.set_value(); gate.wait(); return std::string("late"); }, 10s, 5s,
                     std::string("failed"));
    });
    started.get_future().wait(); // the leader is inside run()
    const auto t0 = std::chrono::steady_clock::now();
    auto waiter = std::async(std::launch::async, [&] {
        return f.get([] { return std::string("second"); }, 10s, 300ms, std::string("failed"));
    });
    const bool done = waiter.wait_for(3s) == std::future_status::ready;
    release.set_value(); // always let the leader finish so a failure here cannot hang the suite
    REQUIRE(done);
    CHECK(waiter.get() == "failed");
    CHECK(std::chrono::steady_clock::now() - t0 < 3s);
    CHECK(leader.get() == "late");
}

TEST_CASE("single flight: concurrent callers share one run", "[vuln][flight]") {
    SingleFlight<int> f;
    std::atomic<int> runs{0};
    std::vector<std::future<int>> fs;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 8; ++i)
        fs.push_back(std::async(std::launch::async, [&] {
            return f.get([&] { ++runs; std::this_thread::sleep_for(100ms); return 7; }, 10s, 5s, -1);
        }));
    for (auto& x : fs)
        CHECK(x.get() == 7);
    CHECK(runs.load() == 1);
    // waiters were released by the leader's notify, not by the 5 s wait cap
    CHECK(std::chrono::steady_clock::now() - t0 < 2s);
}
