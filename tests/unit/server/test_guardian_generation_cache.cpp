/**
 * test_guardian_generation_cache.cpp: GuardianGenerationCache (#5513). Injected fetch and
 * clock; concurrency tests synchronise on events. The one real timeout (max_wait) is set to a
 * few milliseconds.
 */

#include "guardian_generation_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <new>
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

// A manual clock that counts its reads, so a test can wait until a thread has read it (which
// proves that thread has reached a known point) without sleeping.
struct CountingClock {
    ManualClock base;
    std::mutex m;
    std::condition_variable cv;
    int calls{0};
    GuardianGenerationCache::Clock::time_point now() {
        GuardianGenerationCache::Clock::time_point t;
        {
            std::lock_guard lk(m);
            t = base.now();
            ++calls;
        }
        cv.notify_all();
        return t;
    }
    void wait_for_calls(int n) {
        std::unique_lock lk(m);
        cv.wait(lk, [&] { return calls >= n; });
    }
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

TEST_CASE("GuardianGenerationCache: get_fresh bypasses the TTL and installs the result",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 9;  // a bump the cached value has not seen
    // Inside the TTL get() still serves the stale value: that is the hazard get_fresh closes.
    CHECK(c.get().value() == 5);

    CHECK(c.get_fresh().value() == 9);
    CHECK(f.calls.load() == 2);
    // The fresh read became the cached outcome, so get() now agrees with it.
    CHECK(c.get().value() == 9);
    CHECK(f.calls.load() == 2);
    CHECK(c.fetches() == 2);
}

TEST_CASE("GuardianGenerationCache: a stale cached generation never labels a push",
          "[guardian][generation_cache]") {
    // The reconcile lambda decides from get() and labels from get_fresh(). Model that: after a
    // bump the cached value is lower than the store's, and the two reads must disagree.
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 6;
    const std::uint64_t decide_from = c.get().value();
    const std::uint64_t label_with = c.get_fresh().value();
    CHECK(decide_from == 5);
    CHECK(label_with == 6);
    CHECK(label_with > decide_from);
}

TEST_CASE("GuardianGenerationCache: get_fresh reports a failed read and does not hide it",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.fail = true;
    auto r = c.get_fresh();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "store degraded");
    // The error went to the caller only: a transient failure on an admitted push must not
    // make every get() report degraded, so the prior good entry is still served, unfetched.
    auto still = c.get();
    REQUIRE(still.has_value());
    CHECK(*still == 5);
    CHECK(f.calls.load() == 2);  // the initial get and the failed get_fresh; get() hit the cache
}

TEST_CASE("GuardianGenerationCache: a failed get_fresh installs nothing when the cache is empty",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    f.fail = true;
    REQUIRE_FALSE(c.get_fresh().has_value());
    f.fail = false;
    // No negative entry was left behind, so the very next get() reads the store and succeeds.
    auto r = c.get();
    REQUIRE(r.has_value());
    CHECK(*r == 5);
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: an older read finishing last does not overwrite a newer one",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event older_entered, release_older;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            if (calls.fetch_add(1) == 0) {  // the older read: blocks, then reports the LOWER value
                older_entered.set();
                release_older.wait();
                return 7;
            }
            return 8;
        },
        {}, clk.fn());

    std::uint64_t older = 0;
    std::thread t([&] { older = c.get_fresh().value(); });
    older_entered.wait();
    clk.advance(1s);  // the second read starts strictly later
    REQUIRE(c.get_fresh().value() == 8);
    release_older.set();
    t.join();

    CHECK(older == 7);            // its own caller still gets what it read
    CHECK(c.get().value() == 8);  // but the cache holds the newer read
    CHECK(calls.load() == 2);
    CHECK(c.regressions() == 0);  // the older, lower read is not a store reset
}

TEST_CASE("GuardianGenerationCache: a newer read that returns a lower value is a store reset",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    f.value = 9;
    REQUIRE(c.get_fresh().value() == 9);
    clk.advance(1s);
    f.value = 4;  // the store was reset
    REQUIRE(c.get_fresh().value() == 4);
    CHECK(c.regressions() == 1);
    CHECK(c.get().value() == 4);  // installed, not hidden
}

TEST_CASE("GuardianGenerationCache: an invalidate during get_fresh is not undone by it",
          "[guardian][generation_cache]") {
    ManualClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            if (calls.fetch_add(1) == 0) {
                entered.set();
                release.wait();
                return 7;
            }
            return 8;
        },
        {}, clk.fn());
    std::uint64_t older = 0;
    std::thread t([&] { older = c.get_fresh().value(); });
    entered.wait();
    c.invalidate();
    release.set();
    t.join();
    CHECK(older == 7);
    CHECK(c.get().value() == 8);
}

TEST_CASE("GuardianGenerationCache: invalidate makes the next get() refetch",
          "[guardian][generation_cache]") {
    ManualClock clk;
    ScriptedFetch f;
    GuardianGenerationCache c(f.fn(), {}, clk.fn());
    REQUIRE(c.get().value() == 5);
    f.value = 6;
    c.invalidate();
    CHECK(c.get().value() == 6);
    CHECK(f.calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: a waiter gives up after max_wait while the fetch runs on",
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
        {.max_wait = 10ms}, clk.fn());

    std::uint64_t leader_got = 0;
    std::thread leader([&] { leader_got = c.get().value(); });
    entered.wait();
    // No cached value, so this caller waits on the flight and must time out.
    auto waiter = c.get();
    REQUIRE_FALSE(waiter.has_value());
    CHECK(waiter.error().find("timed out") != std::string::npos);
    CHECK(calls.load() == 1);

    release.set();  // the loader thread is unaffected by the waiter's timeout
    leader.join();
    CHECK(leader_got == 42);
    CHECK(c.get().value() == 42);
}

TEST_CASE("GuardianGenerationCache: a fetch that throws bad_alloc leaves the cache usable",
          "[guardian][generation_cache]") {
    ManualClock clk;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            if (calls.fetch_add(1) == 0)
                throw std::bad_alloc();
            return 11;
        },
        {}, clk.fn());
    auto first = c.get();
    REQUIRE_FALSE(first.has_value());
    clk.advance(1s);  // negative entry expired
    // The flight was cleared: a second caller fetches (it does not wait on a dead flight).
    auto second = c.get();
    REQUIRE(second.has_value());
    CHECK(*second == 11);
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianGenerationCache: get() racing a throwing flight never hangs",
          "[guardian][generation_cache]") {
    // A waiter registered on a flight whose fetch throws must wake with an error, not block
    // for max_wait or forever.
    CountingClock clk;
    Event entered, release;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            if (calls.fetch_add(1) == 0) {
                entered.set();
                release.wait();
                throw std::runtime_error("boom");
            }
            return 3;
        },
        {.max_wait = 60'000ms}, clk.fn());  // a hang would show as a 60 s test, not a timeout pass
    std::thread leader([&] { (void)c.get(); });
    entered.wait();
    GuardianGenerationCache::Result waiter = std::unexpected(std::string("unset"));
    std::thread w([&] { waiter = c.get(); });
    // get() reads the clock (read 2; the leader's was read 1) in the same critical section in
    // which it finds the flight registered, and the leader cannot clear the flight without that
    // lock. So once the read is seen the waiter is on the flight: no race with the release.
    clk.wait_for_calls(2);
    release.set();
    leader.join();
    w.join();
    REQUIRE_FALSE(waiter.has_value());
    CHECK(waiter.error().find("boom") != std::string::npos);
}

TEST_CASE("GuardianGenerationCache: a slow failing read is negative-cached from its completion",
          "[guardian][generation_cache]") {
    // The error ages from when the read FINISHED. Stamped with the read's start, a failure
    // that took longer than negative_ttl (a 2 s lease timeout against a 1 s TTL) would be
    // stored already expired and every following get() would re-run the slow read.
    ManualClock clk;
    std::atomic<int> calls{0};
    GuardianGenerationCache c(
        [&]() -> GuardianGenerationCache::Result {
            calls.fetch_add(1);
            clk.advance(3s);  // the read itself outlasts negative_ttl (1 s)
            return std::unexpected(std::string("lease timeout"));
        },
        {}, clk.fn());
    auto first = c.get();
    REQUIRE_FALSE(first.has_value());
    CHECK(calls.load() == 1);

    clk.advance(999ms);  // inside negative_ttl of the COMPLETION
    auto second = c.get();
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == "lease timeout");
    CHECK(calls.load() == 1);  // served from the negative cache, the fetch did not run again

    clk.advance(1ms);  // negative_ttl elapsed since completion
    (void)c.get();
    CHECK(calls.load() == 2);
}
