/**
 * test_guardian_generation_cache.cpp: GuardianGenerationCache (#5513, Fable opinion
 * sections A and F item 1). Injected fetch and clock; concurrency tests synchronise
 * on events, never on sleeps.
 */

#include "guardian_generation_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::server::GuardianGenerationCache;

namespace {

struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};
    GuardianGenerationCache::Clock::time_point now() const {
        return GuardianGenerationCache::Clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    GuardianGenerationCache::ClockFn fn() {
        return [this] { return now(); };
    }
};

// One-shot event.
class Event {
public:
    void set() {
        {
            std::lock_guard lk(m_);
            set_ = true;
        }
        cv_.notify_all();
    }
    void wait() {
        std::unique_lock lk(m_);
        cv_.wait(lk, [&] { return set_; });
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool set_{false};
};

// A fetch that returns `value` (settable) and counts calls.
struct ScriptedFetch {
    std::atomic<std::uint64_t> calls{0};
    std::atomic<std::uint64_t> value{5};
    std::atomic<bool> fail{false};
    GuardianGenerationCache::FetchFn fn() {
        return [this]() -> GuardianGenerationCache::Result {
            calls.fetch_add(1);
            if (fail.load())
                return std::unexpected(std::string("store degraded"));
            return value.load();
        };
    }
};

}  // namespace

TEST_CASE("GuardianGenerationCache: hit within TTL fetches once", "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 6;  // a changed store is not seen inside the TTL
    clk.advance(1999ms);
    CHECK(c.get().value() == 5);
    CHECK(c.get().value() == 5);
    CHECK(f.calls.load() == 1);
    CHECK(c.fetches() == 1);
}

TEST_CASE("GuardianGenerationCache: refetch after TTL expiry", "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 6;
    clk.advance(2000ms);
    CHECK(c.get().value() == 6);
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: custom TTLs are honoured", "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {.ttl = 500ms, .negative_ttl = 100ms}, clk.fn());
    REQUIRE(c.get().value() == 5);
    clk.advance(499ms);
    (void)c.get();
    CHECK(f.calls.load() == 1);
    clk.advance(1ms);
    (void)c.get();
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: a failed fetch is negative-cached for the shorter TTL",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    f.fail = true;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    auto r = c.get();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "store degraded");  // error text propagates unchanged
    clk.advance(999ms);
    CHECK_FALSE(c.get().has_value());
    CHECK(f.calls.load() == 1);  // the degraded store was not hit again

    clk.advance(1ms);  // negative TTL (1 s) elapsed, well inside the positive TTL
    f.fail = false;
    CHECK(c.get().value() == 5);
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: a throwing or missing fetch becomes an error",
          "[guardian][generation_cache]") {
    ManualClock clk;
    {
        GuardianGenerationCache c(
            []() -> GuardianGenerationCache::Result { throw std::runtime_error("boom"); }, {},
            clk.fn());
        auto r = c.get();
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("boom") != std::string::npos);
    }
    {
        GuardianGenerationCache c(GuardianGenerationCache::FetchFn{}, {}, clk.fn());
        CHECK_FALSE(c.get().has_value());
    }
    {
        GuardianGenerationCache c(
            []() -> GuardianGenerationCache::Result { throw 42; }, {}, clk.fn());
        CHECK_FALSE(c.get().has_value());
        // The in-flight state was cleared: a later attempt after expiry runs normally.
        clk.advance(2s);
        CHECK_FALSE(c.get().has_value());
        CHECK(c.fetches() == 2);
    }
}

TEST_CASE("GuardianGenerationCache: a lower fetched value replaces and is counted",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    f.value = 10;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 10);
    f.value = 3;  // store reset
    clk.advance(2s);
    CHECK(c.get().value() == 3);  // not hidden behind the earlier, higher value
    CHECK(c.regressions() == 1);
    f.value = 4;
    clk.advance(2s);
    CHECK(c.get().value() == 4);
    CHECK(c.regressions() == 1);
}

TEST_CASE("GuardianGenerationCache: invalidate forces a refetch", "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 6;
    c.invalidate();
    CHECK(c.get().value() == 6);
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: a backwards clock keeps the entry fresh",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    clk.advance(-1h);
    (void)c.get();
    CHECK(f.calls.load() == 1);
}

TEST_CASE("GuardianGenerationCache: single flight, concurrent callers share one fetch",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            calls.fetch_add(1);
            entered.set();
            release.wait();
            return 42;
        },
        {}, clk.fn());

    std::vector<std::uint64_t> got(8, 0);
    std::vector<std::thread> ts;
    ts.emplace_back([&] { got[0] = c.get().value(); });
    entered.wait();  // the flight is registered before the fetch body runs
    for (std::size_t i = 1; i < got.size(); ++i)
        ts.emplace_back([&, i] { got[i] = c.get().value(); });
    release.set();
    for (auto& t : ts)
        t.join();
    CHECK(calls.load() == 1);
    for (auto v : got)
        CHECK(v == 42);
}

TEST_CASE("GuardianGenerationCache: a stale success is served while a refresh is in flight",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            const int n = calls.fetch_add(1);
            if (n == 0)
                return 5;
            entered.set();
            release.wait();
            return 7;
        },
        {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    clk.advance(3s);  // expired

    std::uint64_t refreshed = 0;
    std::thread leader([&] { refreshed = c.get().value(); });
    entered.wait();
    CHECK(c.get().value() == 5);  // returns immediately with the previous value
    CHECK(calls.load() == 2);
    release.set();
    leader.join();
    CHECK(refreshed == 7);
    CHECK(c.get().value() == 7);
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: a stale success is NOT served after an error",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            switch (calls.fetch_add(1)) {
            case 0:
                return 5;
            case 1:
                return std::unexpected(std::string("down"));
            default:
                entered.set();
                release.wait();
                return 9;
            }
        },
        {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    clk.advance(3s);
    REQUIRE_FALSE(c.get().has_value());  // outage begins
    clk.advance(2s);                     // negative entry expired

    std::uint64_t leader_got = 0, waiter_got = 0;
    std::thread leader([&] { leader_got = c.get().value(); });
    entered.wait();
    std::thread waiter([&] { waiter_got = c.get().value(); });
    release.set();
    leader.join();
    waiter.join();
    CHECK(leader_got == 9);
    CHECK(waiter_got == 9);  // never the pre-outage 5
}

TEST_CASE("GuardianGenerationCache: an invalidate during a flight is not undone by it",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            if (calls.fetch_add(1) == 0) {
                entered.set();
                release.wait();
                return 7;  // the older read
            }
            return 8;
        },
        {}, clk.fn());
    std::uint64_t older = 0;
    std::thread leader([&] { older = c.get().value(); });
    entered.wait();
    c.invalidate();
    release.set();
    leader.join();
    CHECK(older == 7);            // its own caller still gets its result
    CHECK(c.get().value() == 8);  // but it did not repopulate the cache
    CHECK(calls.load() == 2);
}
