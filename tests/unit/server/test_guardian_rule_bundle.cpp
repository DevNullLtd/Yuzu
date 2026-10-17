/**
 * test_guardian_rule_bundle.cpp: GuardianRuleBundleCache, make_bundle and
 * load_reconcile_bundle (#5513). Injected loaders and a manual clock; concurrency tests
 * synchronise on events. The one real timeout (max_wait) is set to a few milliseconds.
 */

#include "guardian_push_builder.hpp"  // load_reconcile_bundle
#include "guardian_reconcile_gate.hpp"
#include "guardian_rule_bundle.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::guardian;
using namespace std::chrono_literals;

namespace {

class Event {
public:
    void set() {
        {
            std::lock_guard lk(m_);
            set_ = true;
        }
        cv_.notify_all();
    }
    // Bounded: a test that never reaches set() (a failed REQUIRE upstream, a regression
    // that stops a flight from registering) must fail, not hang the runner. The bound
    // is a hang guard only; it elapses on a regression and never on the happy path.
    bool wait(std::chrono::milliseconds bound = 30'000ms) {
        std::unique_lock lk(m_);
        return cv_.wait_for(lk, bound, [&] { return set_; });
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool set_{false};
};

GuaranteedStateRuleRow rule(std::string id, std::string scope, bool enabled = true) {
    GuaranteedStateRuleRow r;
    r.rule_id = id;
    r.name = std::move(id);
    r.scope_expr = std::move(scope);
    r.enabled = enabled;
    return r;
}

// A loader that builds a one-rule bundle tagged by `marker` and counts calls.
GuardianRuleBundleCache::LoaderFn counting_loader(std::atomic<int>& calls, std::string marker,
                                                  std::uint64_t bogus_generation = 999) {
    return [&calls, marker = std::move(marker), bogus_generation] {
        calls.fetch_add(1);
        Bundle b = make_bundle({rule(marker, "tag:env == \"prod\"")}, {marker});
        b.generation = bogus_generation;  // the cache must overwrite this
        return std::expected<Bundle, BundleLoadError>(std::move(b));
    };
}

struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};
    GuardianRuleBundleCache::Clock::time_point now() const {
        return GuardianRuleBundleCache::Clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    GuardianRuleBundleCache::ClockFn fn() {
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
    GuardianRuleBundleCache::Clock::time_point now() {
        GuardianRuleBundleCache::Clock::time_point t;
        {
            std::lock_guard lk(m);
            t = base.now();  // read BEFORE the count is published, so a waiter that sees the
            ++calls;         // count knows this reading is already fixed
        }
        cv.notify_all();
        return t;
    }
    // Bounded for the same reason as Event::wait: returns false on timeout.
    bool wait_for_calls(int n, std::chrono::milliseconds bound = 30'000ms) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, bound, [&] { return calls >= n; });
    }
    GuardianRuleBundleCache::ClockFn fn() {
        return [this] { return now(); };
    }
};

GuardianRuleBundleCache::LoaderFn failing_loader(std::atomic<int>& calls,
                                                 std::string detail = "store down") {
    return [&calls, detail = std::move(detail)] {
        calls.fetch_add(1);
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, detail}));
    };
}

}  // namespace

TEST_CASE("make_bundle: parses each distinct scope of enabled rules once",
          "[guardian][rule_bundle]") {
    std::vector<GuaranteedStateRuleRow> rows;
    rows.push_back(rule("a", "tag:env == \"prod\""));
    rows.push_back(rule("b", "tag:env == \"prod\""));          // duplicate scope
    rows.push_back(rule("c", ""));                              // fleet-wide, nothing to parse
    rows.push_back(rule("d", "tag:tier == \"gold\"", false));   // disabled: not parsed
    rows.push_back(rule("e", "== == =="));                      // does not parse
    rows.push_back(rule("f", "ostype == \"windows\""));
    auto b = make_bundle(rows, {"a", "b", "c", "d", "e", "f"});

    CHECK(b.rules.size() == 6);  // rows pass through untouched, order preserved
    CHECK(b.rules[0].rule_id == "a");
    CHECK(b.deployed_rule_ids.size() == 6);
    CHECK(b.scopes.size() == 3);  // prod, the unparseable one, ostype
    CHECK(b.find_scope("tag:tier == \"gold\"") == nullptr);  // disabled rule: absent
    CHECK(b.find_scope("") == nullptr);
    CHECK(b.find_scope("never seen") == nullptr);
    CHECK(b.find_scope("== == ==") == nullptr);  // parse failure means "not a member"
    REQUIRE(b.scopes.contains("== == =="));
    CHECK_FALSE(b.scopes.at("== == ==").parse_error.empty());

    const auto* expr = b.find_scope("tag:env == \"prod\"");
    REQUIRE(expr != nullptr);
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
    CHECK_FALSE(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("dev"); }));
    // The same parsed tree evaluates differently per agent: it holds no membership.
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
}

TEST_CASE("GuardianRuleBundleCache: same generation hits the cache",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    const auto loader = counting_loader(calls, "r1");
    auto a = cache.get(7, loader);
    auto b = cache.get(7, loader);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);
    CHECK(a->get() == b->get());  // the very same bundle object
    CHECK((*a)->generation == 7);  // stamped by the cache, not the loader's 999
    CHECK(cache.held_generation() == 7);
}

TEST_CASE("GuardianRuleBundleCache: a different generation reloads and replaces",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    auto g1 = cache.get(1, counting_loader(calls, "one"));
    auto g2 = cache.get(2, counting_loader(calls, "two"));
    REQUIRE(g1.has_value());
    REQUIRE(g2.has_value());
    CHECK(calls.load() == 2);
    CHECK((*g1)->generation == 1);
    CHECK((*g2)->generation == 2);
    CHECK((*g2)->rules[0].rule_id == "two");
    CHECK(cache.held_generation() == 2);
}

TEST_CASE("GuardianRuleBundleCache: never serves a bundle for a different generation",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(5, counting_loader(calls, "five")).has_value());
    // Going to a higher generation and back down must reload each time: only ONE
    // bundle is held and it is returned only for its own generation.
    auto up = cache.get(6, counting_loader(calls, "six"));
    REQUIRE(up.has_value());
    CHECK((*up)->generation == 6);
    CHECK((*up)->rules[0].rule_id == "six");
    auto back = cache.get(5, counting_loader(calls, "five-again"));  // a store reset
    REQUIRE(back.has_value());
    CHECK((*back)->generation == 5);
    CHECK((*back)->rules[0].rule_id == "five-again");  // a fresh load, not the old five
    CHECK(calls.load() == 3);
}

TEST_CASE("GuardianRuleBundleCache: a failed load is never held and is retried after the negative ttl",
          "[guardian][rule_bundle]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 1s}, clk.fn());
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn failing = [&calls] {
        calls.fetch_add(1);
        return std::expected<Bundle, BundleLoadError>(std::unexpected(
            BundleLoadError{BundleLoadError::Source::deployed, "baseline store down"}));
    };
    auto r = cache.get(3, failing);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().source == BundleLoadError::Source::deployed);  // source preserved
    CHECK(r.error().detail == "baseline store down");
    CHECK_FALSE(cache.held_generation().has_value());  // never installed as the held bundle
    clk.advance(1s);  // the negative entry has expired
    auto again = cache.get(3, failing);
    CHECK_FALSE(again.has_value());
    CHECK(calls.load() == 2);  // retried after the ttl

    clk.advance(1s);
    std::atomic<int> ok_calls{0};
    auto ok = cache.get(3, counting_loader(ok_calls, "ok"));
    REQUIRE(ok.has_value());
    CHECK(cache.held_generation() == 3);
}

TEST_CASE("GuardianRuleBundleCache: a failed load is remembered for negative_ttl without re-running the loader",
          "[guardian][rule_bundle][negative]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 1s}, clk.fn());
    std::atomic<int> calls{0};
    const auto failing = failing_loader(calls, "rules down");

    auto first = cache.get(5, failing);
    REQUIRE_FALSE(first.has_value());
    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);

    clk.advance(900ms);
    std::chrono::nanoseconds waited{-1};
    auto within = cache.get(5, failing, &waited);
    REQUIRE_FALSE(within.has_value());
    CHECK(within.error().source == BundleLoadError::Source::rules);  // the SAME error
    CHECK(within.error().detail == "rules down");
    CHECK(calls.load() == 1);      // the loader did not run
    CHECK(cache.loads() == 1);
    CHECK(waited == 0ns);          // a remembered failure is not a wait

    clk.advance(100ms);  // exactly negative_ttl since the failure: expired
    CHECK_FALSE(cache.get(5, failing).has_value());
    CHECK(calls.load() == 2);  // retried
}

TEST_CASE("GuardianRuleBundleCache: the negative cache is per generation and cleared by success or invalidate",
          "[guardian][rule_bundle][negative]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 10s}, clk.fn());
    std::atomic<int> fail_calls{0}, ok_calls{0};
    const auto failing = failing_loader(fail_calls);

    REQUIRE_FALSE(cache.get(1, failing).has_value());
    REQUIRE(fail_calls.load() == 1);

    SECTION("another generation is unaffected") {
        auto other = cache.get(2, counting_loader(ok_calls, "two"));
        REQUIRE(other.has_value());
        CHECK(ok_calls.load() == 1);
        CHECK((*other)->generation == 2);
    }
    SECTION("invalidate clears the remembered failure") {
        cache.invalidate();
        auto r = cache.get(1, counting_loader(ok_calls, "one"));
        REQUIRE(r.has_value());
        CHECK(ok_calls.load() == 1);
    }
    SECTION("a success clears the remembered failure") {
        REQUIRE(cache.get(2, counting_loader(ok_calls, "two")).has_value());
        REQUIRE_FALSE(cache.get(1, failing).has_value());
        CHECK(fail_calls.load() == 2);  // generation 1 was not answered from the old entry
    }
    SECTION("a failure for another generation replaces the single slot") {
        REQUIRE_FALSE(cache.get(2, failing).has_value());
        CHECK(fail_calls.load() == 2);
        REQUIRE_FALSE(cache.get(1, failing).has_value());
        CHECK(fail_calls.load() == 3);  // generation 1's entry was displaced, so it re-runs
    }
}

TEST_CASE("GuardianRuleBundleCache: a load that fails after an invalidate does not repopulate the negative cache",
          "[guardian][rule_bundle][negative]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 10s}, clk.fn());
    Event entered, release;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow_failing = [&] {
        calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, "late failure"}));
    };
    std::jthread t([&] { (void)cache.get(8, slow_failing); });
    REQUIRE(entered.wait());
    cache.invalidate();  // the bump landed while the old load was still running
    release.set();
    t.join();
    REQUIRE(calls.load() == 1);

    std::atomic<int> ok_calls{0};
    auto r = cache.get(8, counting_loader(ok_calls, "after"));
    REQUIRE(r.has_value());  // not answered from the pre-invalidate failure
    CHECK(ok_calls.load() == 1);
}

TEST_CASE("GuardianRuleBundleCache: a load that SUCCEEDS after an invalidate installs nothing",
          "[guardian][rule_bundle][epoch]") {
    // A rule edit commits after this load read its rows, its generation bump fails, and the
    // store hook calls invalidate(): the late result predates the edit, so it must reach its
    // own caller but must not become the held bundle for the (unchanged) generation.
    ManualClock clk;
    GuardianRuleBundleCache cache({}, clk.fn());
    Event entered, release;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(
            make_bundle({rule("pre-edit", "")}, {"pre-edit"}));
    };
    GuardianRuleBundleCache::Result late;
    std::jthread t([&] { late = cache.get(5, slow); });
    REQUIRE(entered.wait());
    cache.invalidate();  // the hook fired while the old load was still running
    release.set();
    t.join();
    REQUIRE(late.has_value());  // its own caller still gets it
    CHECK((*late)->rules.size() == 1);
    CHECK_FALSE(cache.held_generation().has_value());  // but it was not installed

    std::atomic<int> fresh_calls{0};
    auto r = cache.get(5, counting_loader(fresh_calls, "post-edit"));
    REQUIRE(r.has_value());
    CHECK(fresh_calls.load() == 1);  // reloaded, not served from the stale in-flight result
    CHECK((*r)->rules[0].rule_id == "post-edit");
}

TEST_CASE("GuardianRuleBundleCache: a get after an invalidate does not join the detached load",
          "[guardian][rule_bundle][epoch]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({}, clk.fn());
    Event entered, release;
    std::atomic<int> old_calls{0};
    const GuardianRuleBundleCache::LoaderFn old_loader = [&] {
        old_calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(
            make_bundle({rule("old", "")}, {"old"}));
    };
    std::jthread t([&] { (void)cache.get(7, old_loader); });
    REQUIRE(entered.wait());
    cache.invalidate();

    // A new request for the same generation must start its OWN load (not wait on the old
    // one, whose rows predate the edit) and get the new rows while the old load still runs.
    std::atomic<int> new_calls{0};
    auto r = cache.get(7, counting_loader(new_calls, "new"));
    REQUIRE(r.has_value());
    CHECK((*r)->rules[0].rule_id == "new");
    CHECK(new_calls.load() == 1);
    CHECK(cache.held_generation() == std::optional<std::uint64_t>{7});

    // The old load finishing afterwards neither replaces the new bundle nor erases anything
    // that belongs to a newer flight.
    release.set();
    t.join();
    auto again = cache.get(7, counting_loader(new_calls, "must-not-load"));
    REQUIRE(again.has_value());
    CHECK((*again)->rules[0].rule_id == "new");
    CHECK(new_calls.load() == 1);
}

TEST_CASE("GuardianRuleBundleCache: a zero negative_ttl disables the negative cache",
          "[guardian][rule_bundle][negative]") {
    // The manual clock never advances, so only the `negative_ttl > 0` guard can make the second
    // call re-run the loader (a real clock would let a removed guard pass on elapsed time).
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 0ms}, clk.fn());
    std::atomic<int> calls{0};
    const auto failing = failing_loader(calls);
    CHECK_FALSE(cache.get(1, failing).has_value());
    CHECK_FALSE(cache.get(1, failing).has_value());
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianRuleBundleCache: a slow failing load is remembered from when it finished",
          "[guardian][rule_bundle][negative]") {
    // Stamped with the load's start, a failure slower than negative_ttl would be stored
    // already expired and every following call would re-run the slow loader.
    ManualClock clk;
    GuardianRuleBundleCache cache({.negative_ttl = 1s}, clk.fn());
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow_failing = [&] {
        calls.fetch_add(1);
        clk.advance(3s);  // slower than the negative ttl
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, "slow failure"}));
    };
    REQUIRE_FALSE(cache.get(1, slow_failing).has_value());
    clk.advance(999ms);  // inside negative_ttl of the COMPLETION
    auto again = cache.get(1, slow_failing);
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().detail == "slow failure");
    CHECK(calls.load() == 1);  // the second call did not re-run the loader
    clk.advance(1ms);
    CHECK_FALSE(cache.get(1, slow_failing).has_value());
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianRuleBundleCache: a failed load keeps the previously held bundle",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "one")).has_value());
    auto bad = cache.get(2, [] {
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, "rules down"}));
    });
    CHECK_FALSE(bad.has_value());
    CHECK(cache.held_generation() == 1);  // still valid for generation 1
    auto one = cache.get(1, counting_loader(calls, "unused"));
    REQUIRE(one.has_value());
    CHECK(calls.load() == 1);  // generation 1 still served from the cache
}

TEST_CASE("GuardianRuleBundleCache: a throwing or missing loader becomes an error",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache({.negative_ttl = 0ms});  // retries below must reach the loader
    auto r = cache.get(1, []() -> std::expected<Bundle, BundleLoadError> {
        throw std::runtime_error("kaboom");
    });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().source == BundleLoadError::Source::other);
    CHECK(r.error().detail.find("kaboom") != std::string::npos);
    auto r2 = cache.get(1, []() -> std::expected<Bundle, BundleLoadError> { throw 7; });
    CHECK_FALSE(r2.has_value());
    auto r3 = cache.get(1, GuardianRuleBundleCache::LoaderFn{});
    CHECK_FALSE(r3.has_value());
    // The in-flight state was cleared each time: a good load now succeeds.
    std::atomic<int> calls{0};
    CHECK(cache.get(1, counting_loader(calls, "ok")).has_value());
}

TEST_CASE("GuardianRuleBundleCache: concurrent callers for one generation share one load",
          "[guardian][rule_bundle]") {
    // CountingClock proves every follower has joined the flight before the loader is released:
    // the owner reads the clock once, each follower twice (the lock, then t0 before it blocks).
    CountingClock clk;
    GuardianRuleBundleCache cache({.max_wait = 60'000ms}, clk.fn());
    Event entered, release;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };

    constexpr std::size_t kCallers = 8;
    // Results are stored and asserted on the main thread: an unwrapped error inside a jthread
    // body would terminate the binary instead of failing the test.
    std::vector<GuardianRuleBundleCache::Result> got(kCallers, std::shared_ptr<const Bundle>{});
    std::vector<std::jthread> ts;
    ts.emplace_back([&] { got[0] = cache.get(4, slow); });
    REQUIRE(entered.wait());  // the flight is registered before the loader body runs
    for (std::size_t i = 1; i < kCallers; ++i)
        ts.emplace_back([&, i] { got[i] = cache.get(4, slow); });
    const bool followers_joined = clk.wait_for_calls(1 + 2 * static_cast<int>(kCallers - 1));
    release.set();
    for (auto& t : ts)
        t.join();
    REQUIRE(followers_joined);
    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);
    for (const auto& r : got) {
        REQUIRE(r.has_value());
        REQUIRE(*r != nullptr);
        CHECK(r->get() == got[0]->get());
        CHECK((*r)->generation == 4);
    }
}

TEST_CASE("GuardianRuleBundleCache: invalidate() and a replacing install release the held bundle",
          "[guardian][rule_bundle]") {
    // The cache moves the old held bundle out and lets it die after mu_ is released. The lock
    // state at destruction is not observable from here (Bundle has no destructor hook); this
    // checks the part that is: the cache keeps no extra reference, so the bundle really is
    // released once the caller drops its own, whether it was dropped or replaced.
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};

    std::weak_ptr<const Bundle> first;
    {
        auto r = cache.get(1, counting_loader(calls, "one"));
        REQUIRE(r.has_value());
        first = *r;
    }
    CHECK_FALSE(first.expired());  // still held by the cache
    cache.invalidate();
    CHECK(first.expired());
    CHECK_FALSE(cache.held_generation().has_value());

    std::weak_ptr<const Bundle> second;
    {
        auto r = cache.get(2, counting_loader(calls, "two"));
        REQUIRE(r.has_value());
        second = *r;
    }
    CHECK_FALSE(second.expired());
    {
        auto r = cache.get(3, counting_loader(calls, "three"));  // replaces generation 2
        REQUIRE(r.has_value());
        CHECK((*r)->generation == 3);
    }
    CHECK(second.expired());
    CHECK(cache.held_generation() == 3);
}

TEST_CASE("GuardianRuleBundleCache: a request for another generation does not wait on a running load",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("slow", "")}, {"slow"}));
    };
    GuardianRuleBundleCache::Result slow_got = std::shared_ptr<const Bundle>{};
    std::jthread t([&] { slow_got = cache.get(1, slow); });
    REQUIRE(entered.wait());

    std::atomic<int> calls{0};
    auto quick = cache.get(2, counting_loader(calls, "quick"));  // returns while gen 1 is blocked
    REQUIRE(quick.has_value());
    CHECK((*quick)->generation == 2);

    release.set();
    t.join();
    REQUIRE(slow_got.has_value());
    const std::shared_ptr<const Bundle> slow_result = *slow_got;
    REQUIRE(slow_result != nullptr);
    CHECK(slow_result->generation == 1);  // each caller got the bundle for ITS generation
    CHECK(slow_result->rules[0].rule_id == "slow");
    // Whichever finished last is held; a request for the other generation reloads.
    const auto held = cache.held_generation();
    REQUIRE(held.has_value());
    const std::uint64_t other = (*held == 1) ? 2 : 1;
    std::atomic<int> c2{0};
    auto r = cache.get(other, counting_loader(c2, "reload"));
    REQUIRE(r.has_value());
    CHECK((*r)->generation == other);
    CHECK(c2.load() == 1);
}

TEST_CASE("GuardianRuleBundleCache: a held shared_ptr survives a reload",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    auto in_flight_push = cache.get(1, counting_loader(calls, "old"));
    REQUIRE(in_flight_push.has_value());
    const std::shared_ptr<const Bundle> mine = *in_flight_push;
    const auto* expr = mine->find_scope("tag:env == \"prod\"");
    REQUIRE(expr != nullptr);

    REQUIRE(cache.get(2, counting_loader(calls, "new")).has_value());  // reload replaces
    CHECK(cache.held_generation() == 2);
    // The old bundle, and the parsed expression pointer taken from it, are still valid.
    CHECK(mine->generation == 1);
    CHECK(mine->rules[0].rule_id == "old");
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
    CHECK(mine.use_count() >= 1);
}

TEST_CASE("GuardianRuleBundleCache: invalidate drops the held bundle", "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "a")).has_value());
    cache.invalidate();
    CHECK_FALSE(cache.held_generation().has_value());
    REQUIRE(cache.get(1, counting_loader(calls, "b")).has_value());
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianRuleBundleCache: a held bundle older than max_age is reloaded",
          "[guardian][rule_bundle]") {
    // A rule mutation commits and THEN bumps best-effort; a failed bump leaves the generation
    // unchanged while the rules are newer. max_age is the backstop.
    ManualClock clk;
    GuardianRuleBundleCache cache({.max_age = 60s}, clk.fn());
    std::atomic<int> calls{0};
    const auto loader = counting_loader(calls, "r");

    REQUIRE(cache.get(3, loader).has_value());
    clk.advance(59s + 999ms);
    REQUIRE(cache.get(3, loader).has_value());
    CHECK(calls.load() == 1);  // younger than max_age: a hit

    clk.advance(1ms);          // now exactly max_age old
    REQUIRE(cache.get(3, loader).has_value());
    CHECK(calls.load() == 2);  // reloaded
    CHECK(cache.loads() == 2);

    // The reload restarts the age.
    clk.advance(59s);
    REQUIRE(cache.get(3, loader).has_value());
    CHECK(calls.load() == 2);
}

TEST_CASE("GuardianRuleBundleCache: max_age is measured from when the load started, not when it finished",
          "[guardian][rule_bundle]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.max_age = 10s}, clk.fn());
    std::atomic<int> calls{0};
    const auto loader_taking = [&](std::chrono::nanoseconds took) {
        return GuardianRuleBundleCache::LoaderFn{[&calls, &clk, took] {
            calls.fetch_add(1);
            clk.advance(took);  // wall time passes INSIDE the load
            return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
        }};
    };

    SECTION("a load that takes less than max_age is served until max_age after it STARTED") {
        REQUIRE(cache.get(1, loader_taking(6s)).has_value());
        REQUIRE(cache.get(1, loader_taking(6s)).has_value());  // age 6 s: a hit
        CHECK(calls.load() == 1);
        clk.advance(5s);  // 11 s after the start (5 s after it finished)
        REQUIRE(cache.get(1, loader_taking(0s)).has_value());
        CHECK(calls.load() == 2);  // already expired, though only 5 s old by the finish time
    }
    SECTION("a load slower than max_age is stale on arrival and is reloaded") {
        REQUIRE(cache.get(1, loader_taking(11s)).has_value());
        REQUIRE(cache.get(1, loader_taking(11s)).has_value());
        CHECK(calls.load() == 2);
    }
}

TEST_CASE("GuardianRuleBundleCache: an expired bundle is not served when its reload fails",
          "[guardian][rule_bundle]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({.max_age = 10s}, clk.fn());
    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "ok")).has_value());
    clk.advance(11s);
    auto r = cache.get(1, [] {
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, "down"}));
    });
    REQUIRE_FALSE(r.has_value());  // fail closed: never the expired bundle
    CHECK(r.error().source == BundleLoadError::Source::rules);
}

TEST_CASE("GuardianRuleBundleCache: a waiter gives up after max_wait while the load runs on",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache({.max_wait = 10ms});
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };
    GuardianRuleBundleCache::Result loaded_got = std::shared_ptr<const Bundle>{};
    std::jthread t([&] { loaded_got = cache.get(4, slow); });
    REQUIRE(entered.wait());

    auto waiter = cache.get(4, slow);
    REQUIRE_FALSE(waiter.has_value());
    CHECK(waiter.error().source == BundleLoadError::Source::other);
    CHECK(waiter.error().detail.find("timed out") != std::string::npos);
    CHECK(cache.loads() == 1);

    release.set();
    t.join();
    REQUIRE(loaded_got.has_value());
    const std::shared_ptr<const Bundle> loaded = *loaded_got;
    REQUIRE(loaded != nullptr);
    CHECK(loaded->generation == 4);
    CHECK(cache.get(4, slow).has_value());  // the load installed
}

TEST_CASE("GuardianRuleBundleCache: epoch() advances on every invalidate and on nothing else",
          "[guardian][rule_bundle][epoch]") {
    ManualClock clk;
    GuardianRuleBundleCache cache({}, clk.fn());
    const auto e0 = cache.epoch();

    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "a")).has_value());  // a load and its install
    REQUIRE(cache.get(1, counting_loader(calls, "a")).has_value());  // a hit
    REQUIRE_FALSE(cache.get(2, failing_loader(calls)).has_value());  // a failure
    REQUIRE_FALSE(cache.get(2, failing_loader(calls)).has_value());  // a remembered failure
    CHECK(cache.epoch() == e0);

    cache.invalidate();
    CHECK(cache.epoch() == e0 + 1);
    cache.invalidate();  // an invalidate that finds nothing to drop still counts
    CHECK(cache.epoch() == e0 + 2);
    REQUIRE(cache.get(1, counting_loader(calls, "b")).has_value());
    CHECK(cache.epoch() == e0 + 2);
}

TEST_CASE("GuardianRuleBundleCache: epoch() is safe against concurrent invalidates and never goes back",
          "[guardian][rule_bundle][epoch]") {
    GuardianRuleBundleCache cache;
    constexpr int kThreads = 4;
    constexpr int kEach = 500;
    const auto e0 = cache.epoch();
    std::atomic<bool> monotonic{true};
    std::atomic<bool> stop{false};
    std::jthread reader([&] {
        auto last = cache.epoch();
        while (!stop.load()) {
            const auto e = cache.epoch();
            if (e < last)
                monotonic.store(false);
            last = e;
        }
    });
    {
        std::vector<std::jthread> writers;
        for (int i = 0; i < kThreads; ++i)
            writers.emplace_back([&] {
                for (int n = 0; n < kEach; ++n)
                    cache.invalidate();
            });
    }  // joined here
    stop.store(true);
    reader.join();
    CHECK(monotonic.load());
    CHECK(cache.epoch() == e0 + static_cast<std::uint64_t>(kThreads) * kEach);  // none lost
}

TEST_CASE("GuardianRuleBundleCache: an owner and a waiter of a detached load both see the epoch move",
          "[guardian][rule_bundle][epoch]") {
    // What the reconcile flow relies on: a result handed to the owner AND to a waiter that had
    // joined the flight is still delivered after invalidate(), so the epoch read BEFORE the get
    // is the only signal either of them has.
    CountingClock clk;
    GuardianRuleBundleCache cache({.max_wait = 60'000ms}, clk.fn());
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("pre-edit", "")}, {"pre-edit"}));
    };
    const auto before = cache.epoch();
    GuardianRuleBundleCache::Result owner_r, waiter_r;
    std::jthread owner([&] { owner_r = cache.get(5, slow); });
    REQUIRE(entered.wait());
    std::jthread waiter([&] { waiter_r = cache.get(5, slow); });
    REQUIRE(clk.wait_for_calls(3));  // the waiter has joined the flight and is about to block
    cache.invalidate();
    release.set();
    owner.join();
    waiter.join();

    REQUIRE(owner_r.has_value());
    REQUIRE(waiter_r.has_value());  // both still receive the pre-edit result...
    CHECK(owner_r->get() == waiter_r->get());
    CHECK(cache.epoch() != before);  // ...so the epoch is what tells them it was overtaken
    CHECK_FALSE(cache.held_generation().has_value());
}

TEST_CASE("GuardianRuleBundleCache: waiters of a FAILED load all receive its error from the one load",
          "[guardian][rule_bundle]") {
    CountingClock clk;
    GuardianRuleBundleCache cache({.max_wait = 60'000ms}, clk.fn());
    Event entered, release;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow_failing = [&] {
        calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::deployed, "shared failure"}));
    };
    constexpr int kWaiters = 3;
    std::vector<GuardianRuleBundleCache::Result> got(kWaiters + 1, std::shared_ptr<const Bundle>{});
    std::vector<std::jthread> ts;
    ts.emplace_back([&] { got[0] = cache.get(6, slow_failing); });
    REQUIRE(entered.wait());
    for (int i = 1; i <= kWaiters; ++i)
        ts.emplace_back([&, i] { got[static_cast<std::size_t>(i)] = cache.get(6, slow_failing); });
    // The owner read the clock once; each waiter reads it twice before it blocks.
    REQUIRE(clk.wait_for_calls(1 + 2 * kWaiters));
    release.set();
    for (auto& t : ts)
        t.join();

    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);
    for (const auto& r : got) {
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().source == BundleLoadError::Source::deployed);
        CHECK(r.error().detail == "shared failure");
    }
    CHECK_FALSE(cache.held_generation().has_value());
}

TEST_CASE("GuardianRuleBundleCache: a waiter that times out still reports the time it was blocked",
          "[guardian][rule_bundle][waited]") {
    // A timed-out wait misreported as zero would be charged to the waiter's budget debit by
    // Scoped::exclude(0). The clock's FOURTH read is the one after the wait ends (owner: 1,
    // waiter: the lock and t0, then this), and it advances 3 s before returning.
    ManualClock mc;
    std::atomic<int> reads{0};
    GuardianRuleBundleCache cache({.max_wait = 10ms}, [&] {
        if (reads.fetch_add(1) + 1 == 4)
            mc.advance(3s);
        return mc.now();
    });
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };
    std::jthread owner([&] { (void)cache.get(4, slow); });
    REQUIRE(entered.wait());

    std::chrono::nanoseconds waited{-1};
    auto r = cache.get(4, slow, &waited);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().detail.find("timed out") != std::string::npos);
    CHECK(waited == 3s);
    release.set();
    owner.join();
}

TEST_CASE("GuardianRuleBundleCache: a loader that throws bad_alloc leaves the cache usable",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache({.negative_ttl = 0ms});  // the retry below must reach the loader
    auto r = cache.get(1, []() -> std::expected<Bundle, BundleLoadError> { throw std::bad_alloc(); });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().source == BundleLoadError::Source::other);
    std::atomic<int> calls{0};
    auto ok = cache.get(1, counting_loader(calls, "ok"));  // not waiting on a dead flight
    REQUIRE(ok.has_value());
    CHECK(calls.load() == 1);
}

TEST_CASE("GuardianRuleBundleCache: waited reports the time a blocked waiter spent, and zero for the owner and hits",
          "[guardian][rule_bundle][waited]") {
    CountingClock clk;
    // A generous max_wait so a descheduled owner cannot turn the waiter's wait into a timeout.
    GuardianRuleBundleCache cache({.max_wait = 60'000ms}, clk.fn());
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        clk.base.advance(2s);  // the owner's load takes 2 s of (manual) wall time
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };

    std::chrono::nanoseconds owner_waited{-1};
    std::jthread owner([&] { (void)cache.get(4, slow, &owner_waited); });
    REQUIRE(entered.wait());  // the flight is registered; the owner has read the clock once

    std::chrono::nanoseconds waiter_waited{-1};
    std::jthread waiter([&] { (void)cache.get(4, slow, &waiter_waited); });
    // Under the lock (read 2) and just before blocking (read 3): the waiter is about to block.
    REQUIRE(clk.wait_for_calls(3));
    clk.base.advance(3s);  // 3 s pass while the waiter is blocked
    release.set();
    owner.join();
    waiter.join();

    CHECK(owner_waited == 0ns);  // the owner's load time is its own cost, not a wait
    // Blocked from before the 3 s advance until after the owner's own 2 s of loading.
    CHECK(waiter_waited == 5s);

    std::chrono::nanoseconds hit_waited{-1};
    REQUIRE(cache.get(4, slow, &hit_waited).has_value());
    CHECK(hit_waited == 0ns);
}

TEST_CASE("GuardianRuleBundleCache: the owner's load time stays in the push's debit, only a wait is excluded",
          "[guardian][rule_bundle][waited]") {
    // The server wiring in miniature: a Scoped from the gate, the cache's `waited` excluded.
    ManualClock clk;
    GuardianReconcileBudget budget({.budget_ms_per_s = 100.0, .burst_ms = 1000.0, .max_per_s = 1000},
                                   clk.fn());
    GuardianReconcileGate gate(budget, clk.fn());
    GuardianRuleBundleCache cache({}, clk.fn());
    REQUIRE(budget.balance_ms() == Catch::Approx(1000.0));

    const GuardianRuleBundleCache::LoaderFn slow_load = [&] {
        clk.advance(200ms);  // list_rules + deployed ids took 200 ms
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };
    {
        auto admitted = gate.begin_admitted();
        std::chrono::nanoseconds waited{0};
        REQUIRE(cache.get(1, slow_load, &waited).has_value());
        admitted.exclude(waited);
        CHECK(waited == 0ns);
    }
    // The balance started at the burst cap, so the refill adds nothing; the owner's 200 ms
    // load was charged in full.
    CHECK(budget.balance_ms() == Catch::Approx(800.0));
}

namespace {

std::vector<GuaranteedStateRuleRow> three_rules() {
    return {rule("r1", ""), rule("r2", "tag:env == \"prod\""), rule("r3", "")};
}

}  // namespace

TEST_CASE("load_reconcile_bundle: a non-empty deployed set keeps its rules and ids",
          "[guardian][rule_bundle]") {
    // Regression for the unsequenced std::move: with the deployed set moved before the filter
    // read it, the filter saw an empty set and bundle.rules came out empty, converging every
    // agent to zero guards.
    auto b = load_reconcile_bundle(
        []() -> std::expected<std::vector<GuaranteedStateRuleRow>, std::string> {
            return three_rules();
        },
        []() -> std::expected<std::unordered_set<std::string>, std::string> {
            return std::unordered_set<std::string>{"r1", "r2"};
        });
    REQUIRE(b.has_value());
    REQUIRE(b->rules.size() == 2);
    CHECK(b->rules[0].rule_id == "r1");  // order preserved
    CHECK(b->rules[1].rule_id == "r2");
    CHECK(b->deployed_rule_ids == std::unordered_set<std::string>{"r1", "r2"});
    CHECK(b->find_scope("tag:env == \"prod\"") != nullptr);
}

TEST_CASE("load_reconcile_bundle: nothing deployed is an empty rule set, a failed read is an error",
          "[guardian][rule_bundle]") {
    SECTION("empty deployed set is correct by model") {
        auto b = load_reconcile_bundle(
            []() -> std::expected<std::vector<GuaranteedStateRuleRow>, std::string> {
                return three_rules();
            },
            []() -> std::expected<std::unordered_set<std::string>, std::string> {
                return std::unordered_set<std::string>{};
            });
        REQUIRE(b.has_value());
        CHECK(b->rules.empty());
    }
    SECTION("a failed rule read is Source::rules and the deployed read is not attempted") {
        std::atomic<int> deployed_calls{0};
        auto b = load_reconcile_bundle(
            []() -> std::expected<std::vector<GuaranteedStateRuleRow>, std::string> {
                return std::unexpected(std::string("rules down"));
            },
            [&]() -> std::expected<std::unordered_set<std::string>, std::string> {
                deployed_calls.fetch_add(1);
                return std::unordered_set<std::string>{"r1"};
            });
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error().source == BundleLoadError::Source::rules);
        CHECK(b.error().detail == "rules down");
        CHECK(deployed_calls.load() == 0);
    }
    SECTION("a failed deployed read is Source::deployed") {
        auto b = load_reconcile_bundle(
            []() -> std::expected<std::vector<GuaranteedStateRuleRow>, std::string> {
                return three_rules();
            },
            []() -> std::expected<std::unordered_set<std::string>, std::string> {
                return std::unexpected(std::string("baselines down"));
            });
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error().source == BundleLoadError::Source::deployed);
        CHECK(b.error().detail == "baselines down");
    }
    SECTION("unconfigured sources are an error, not a crash") {
        auto b = load_reconcile_bundle({}, {});
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error().source == BundleLoadError::Source::other);
    }
}
