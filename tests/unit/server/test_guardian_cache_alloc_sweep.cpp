/**
 * test_guardian_cache_alloc_sweep.cpp: #5513 - the single-flight Guardian caches
 * (GuardianGenerationCache, GuardianRuleBundleCache) survive an allocation failure at ANY
 * point inside get() / get_fresh() without wedging.
 *
 * WHAT THIS PINS THAT THE FUNCTIONAL TESTS DO NOT. test_guardian_generation_cache.cpp and
 * test_guardian_rule_bundle.cpp already have "a fetch/loader that throws bad_alloc leaves the
 * cache usable" cases, but those throw from INSIDE the fetch/loader, which the old
 * try/catch around the call already handled. The hazard FlightGuard, the noexcept install()
 * and the noexcept run_fetch()/run_loader() close is an allocation failure in the cache's
 * OWN bookkeeping: between registering the flight and clearing it (building an error
 * string, copying a Result into the entry, the promise's shared state, the map node). An
 * escape there used to leave a registered flight nobody would ever complete, so the next
 * get() waited on a dead promise (broken_promise thrown to the caller, or a hang for
 * max_wait). This sweep fails EVERY allocation made on the calling thread inside the call,
 * one index at a time (1..K), and after each injected failure checks the NEXT call.
 *
 * It is a sweep rather than a handful of hand-placed faults so a refactor that adds,
 * removes or reorders an allocation cannot move the failure to a point nobody tested. The
 * fetch returns an error string of 80+ bytes (beyond every supported small-string buffer)
 * so building and copying the error itself allocates.
 *
 * ACCEPTED, and deliberately NOT asserted: the injected failure may make the FIRST call
 * throw std::bad_alloc to its caller (the heartbeat path catches around it). The contract
 * is on the call AFTER the failure is disarmed: it must not throw, must not time out on a
 * dead flight, and the cache must converge to a normal result.
 *
 * WHY THIS IS A SEPARATE EXECUTABLE. It replaces the global operator new/delete, which is
 * process-wide and cannot be scoped to one test, so it must not live in yuzu_server_tests,
 * and it must be ABSENT (not merely disabled) from sanitizer builds, which own the
 * allocator themselves. Same technique and caveats as test_mcp_bridge_alloc_budget.cpp /
 * test_spark_alloc_budget.cpp, whose headers carry the full portability statement: this is
 * measured on the ELF/libstdc++ build (Linux, no sanitizer), not a portable contract.
 *
 * The injection is armed ONLY around the single call under test, on the calling thread
 * (thread_local), so allocation inside Catch2 itself is never failed. No Catch2 assertion
 * runs while armed.
 *
 * The caches, the budget and the gate are header-only and self-contained, so this binary links
 * nothing from libyuzu_server_core (only Catch2). It builds only because make_bundle (inline,
 * calls scope::parse from scope_engine.cpp) is never called here: do not call make_bundle in
 * this binary, it needs scope_engine.cpp.
 */

#include "../../../server/core/src/guardian_generation_cache.hpp"
#include "../../../server/core/src/guardian_reconcile_budget.hpp"
#include "../../../server/core/src/guardian_reconcile_gate.hpp"
#include "../../../server/core/src/guardian_rule_bundle.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <utility>

// -- the failure injector -----------------------------------------------------------------
namespace {
thread_local bool g_armed = false;
thread_local long g_countdown = 0;  // the allocation index that fails; 1 = the very next
thread_local bool g_fired = false;  // an injected failure happened since the last arm()

class FailNth {
public:
    explicit FailNth(long n) {
        g_countdown = n;
        g_fired = false;
        g_armed = true;
    }
    ~FailNth() { g_armed = false; }
    FailNth(const FailNth&) = delete;
    FailNth& operator=(const FailNth&) = delete;
    void disarm() { g_armed = false; }
};

void* alloc_or_throw(std::size_t n) {
    if (g_armed && --g_countdown == 0) {
        g_armed = false;  // one failure per arm; the unwind path must be free to allocate
        g_fired = true;
        throw std::bad_alloc{};
    }
    for (;;) {
        if (void* p = std::malloc(n == 0 ? 1 : n))
            return p;
        std::new_handler h = std::get_new_handler();
        if (h == nullptr)
            throw std::bad_alloc{};
        h();
    }
}
}  // namespace

void* operator new(std::size_t n) { return alloc_or_throw(n); }
void* operator new[](std::size_t n) { return alloc_or_throw(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

// -- fixtures -----------------------------------------------------------------------------
namespace {

using namespace std::chrono_literals;
using yuzu::server::GuardianGenerationCache;
using yuzu::server::guardian::Bundle;
using yuzu::server::guardian::BundleLoadError;
using yuzu::server::guardian::GuardianRuleBundleCache;

// A runaway sweep (a get() that allocates without bound) fails instead of looping forever.
constexpr long kSweepCeiling = 2000;
// One sweep configuration: whether the first fetch/load fails, and the fewest allocation
// points the sweep must have exercised. A sweep that ends sooner ran against code that
// allocates less than expected, i.e. the injector is not reaching it and the test would be
// vacuous. The floors sit at or below the counts measured on libstdc++ (allocation points swept,
// failing-first / succeeding-first: generation cache get() and invalidate-after-get 6 / 3,
// get_fresh() 1 / 0, rule bundle get() and invalidate-after-get 7 / 12, gate decide() 2) so
// a compiler/library difference in make_shared/std::function placement does not trip them.
using SweepSpec = std::pair<bool, long>;

constexpr std::uint64_t kGoodValue = 7;
constexpr std::uint64_t kGeneration = 3;

struct ManualClock {
    std::atomic<std::int64_t> ns{1'000'000'000};
    void advance(std::chrono::nanoseconds d) { ns.fetch_add(d.count()); }
    std::chrono::steady_clock::time_point now() const {
        return std::chrono::steady_clock::time_point{std::chrono::nanoseconds{ns.load()}};
    }
};

// Longer than every small-string buffer, so building/copying it allocates.
std::string long_text() { return std::string(80, 'e'); }

// Fails the first call with an 80-byte error (when `err_first`), succeeds afterwards.
struct GenFetch {
    explicit GenFetch(bool err_first_) : err_first(err_first_) {}
    const bool err_first;
    std::atomic<int> calls{0};
    GuardianGenerationCache::Result operator()() {
        if (calls.fetch_add(1) == 0 && err_first)
            return std::unexpected(long_text());
        return kGoodValue;
    }
};

// A bundle whose strings are all beyond the small-string buffer.
Bundle sample_bundle() {
    Bundle b;
    yuzu::server::GuaranteedStateRuleRow row;
    row.rule_id = std::string(80, 'r');
    row.name = std::string(80, 'n');
    row.scope_expr = std::string(80, 's');
    row.enabled = false;  // never parsed: this binary does not link the scope parser
    b.rules.push_back(std::move(row));
    b.deployed_rule_ids.insert(std::string(80, 'd'));
    return b;
}

struct BundleLoader {
    explicit BundleLoader(bool err_first_) : err_first(err_first_) {}
    const bool err_first;
    std::atomic<int> calls{0};
    std::expected<Bundle, BundleLoadError> operator()() {
        if (calls.fetch_add(1) == 0 && err_first)
            return std::unexpected(BundleLoadError{BundleLoadError::Source::rules, long_text()});
        return sample_bundle();
    }
};

bool timed_out(const std::string& s) { return s.find("timed out") != std::string::npos; }

// Runs `body(n)` for n = 1, 2, ... until a run completes with no injected failure, and
// returns that n (so n - 1 allocation points were exercised). `body` arms the injector
// itself, around only the call under test, and reports whether it fired.
template <typename Body>
long sweep(Body&& body) {
    for (long n = 1; n <= kSweepCeiling; ++n) {
        if (!body(n))
            return n;
    }
    return -1;
}

}  // namespace

// -- GuardianGenerationCache --------------------------------------------------------------

TEST_CASE("alloc sweep: GuardianGenerationCache::get() never wedges after a failed allocation",
          "[guardian][generation_cache][alloc_sweep]") {
    for (const SweepSpec& spec : std::initializer_list<SweepSpec>
         {{true, 3}, {false, 2}}) {
        const bool err_first = spec.first;
        const long min_points = spec.second;
        INFO("first fetch/load is an error: " << err_first);
        int broken = 0;
        const long k = sweep([&](long n) {
            ManualClock clk;
            GenFetch fetch{err_first};
            GuardianGenerationCache c([&fetch] { return fetch(); }, {.max_wait = 200ms},
                                      [&clk] { return clk.now(); });
            {
                FailNth arm(n);
                try {
                    (void)c.get();
                } catch (...) {
                    // accepted: the caller on the heartbeat path catches around this
                }
            }
            const bool fired = g_fired;

            // Post-condition: the NEXT call neither throws nor waits on a dead flight, and the
            // cache converges to the success the fetch returns from its second call on.
            bool ok = false;
            bool bad_call = false;
            for (int attempt = 0; attempt < 3 && !ok && !bad_call; ++attempt) {
                clk.advance(5s);  // expire any cached outcome, positive or negative
                try {
                    auto r = c.get();
                    if (r.has_value())
                        ok = (*r == kGoodValue);
                    else
                        bad_call = timed_out(r.error());
                } catch (...) {
                    bad_call = true;  // e.g. std::future_error(broken_promise)
                }
            }
            if (bad_call || !ok)
                ++broken;
            return fired;
        });
        REQUIRE(k > 0);  // the sweep terminated
        CHECK(k - 1 >= min_points);  // allocation points exercised
        CHECK(broken == 0);
    }
}

TEST_CASE("alloc sweep: GuardianGenerationCache::get_fresh() never wedges after a failed allocation",
          "[guardian][generation_cache][alloc_sweep]") {
    // {true, 1}: the fetch errors, so building and copying the 80-byte error string is the one
    // allocation point inside the call. {false, 0}: the SUCCESS path. Measured on libstdc++, a
    // successful get_fresh() allocates NOTHING (a uint64 result copied into an in-place
    // optional<Entry>, no promise or map node, unlike get()), so this sweep ends at its first
    // iteration and today proves only that the call neither throws nor wedges. It is kept, with
    // a floor of 0, so that the day install()/run_fetch() gains an allocation on the success
    // path (a string key, a heap-held Entry) every point of it is swept instead of nobody
    // noticing the success arm is no longer allocation-free.
    for (const SweepSpec& spec : std::initializer_list<SweepSpec>
         {{true, 1}, {false, 0}}) {
        const bool err_first = spec.first;
        const long min_points = spec.second;
        INFO("first fetch/load is an error: " << err_first);
        int broken = 0;
        const long k = sweep([&](long n) {
            ManualClock clk;
            GenFetch fetch{err_first};
            GuardianGenerationCache c([&fetch] { return fetch(); }, {.max_wait = 200ms},
                                      [&clk] { return clk.now(); });
            {
                FailNth arm(n);
                try {
                    (void)c.get_fresh();
                } catch (...) {
                }
            }
            const bool fired = g_fired;

            bool ok = false;
            bool bad_call = false;
            for (int attempt = 0; attempt < 3 && !ok && !bad_call; ++attempt) {
                try {
                    auto r = c.get_fresh();
                    if (r.has_value())
                        ok = (*r == kGoodValue);
                    else
                        bad_call = timed_out(r.error());
                } catch (...) {
                    bad_call = true;
                }
            }
            // A plain get() afterwards must also be usable (a get_fresh failure must not leave
            // a registered flight for it to wait on).
            clk.advance(5s);
            try {
                auto r = c.get();
                if (!r.has_value() && timed_out(r.error()))
                    bad_call = true;
            } catch (...) {
                bad_call = true;
            }
            if (bad_call || !ok)
                ++broken;
            return fired;
        });
        REQUIRE(k > 0);
        CHECK(k - 1 >= min_points);  // allocation points exercised
        CHECK(broken == 0);
    }
}

TEST_CASE("alloc sweep: GuardianGenerationCache::invalidate() after a failed get() leaves it usable",
          "[guardian][generation_cache][alloc_sweep]") {
    for (const SweepSpec& spec : std::initializer_list<SweepSpec>
         {{true, 3}, {false, 2}}) {
        const bool err_first = spec.first;
        const long min_points = spec.second;
        INFO("first fetch/load is an error: " << err_first);
        int broken = 0;
        const long k = sweep([&](long n) {
            ManualClock clk;
            GenFetch fetch{err_first};
            GuardianGenerationCache c([&fetch] { return fetch(); }, {.max_wait = 200ms},
                                      [&clk] { return clk.now(); });
            {
                FailNth arm(n);
                try {
                    (void)c.get();
                } catch (...) {
                }
            }
            const bool fired = g_fired;

            // No clock advance: invalidate() alone must force the next read to the fetch.
            bool ok = false;
            bool bad_call = false;
            for (int attempt = 0; attempt < 3 && !ok && !bad_call; ++attempt) {
                c.invalidate();
                try {
                    auto r = c.get();
                    if (r.has_value())
                        ok = (*r == kGoodValue);
                    else
                        bad_call = timed_out(r.error());
                } catch (...) {
                    bad_call = true;
                }
            }
            if (bad_call || !ok)
                ++broken;
            return fired;
        });
        REQUIRE(k > 0);
        CHECK(k - 1 >= min_points);  // allocation points exercised
        CHECK(broken == 0);
    }
}

// -- GuardianRuleBundleCache --------------------------------------------------------------

TEST_CASE("alloc sweep: GuardianRuleBundleCache::get() never wedges after a failed allocation",
          "[guardian][rule_bundle][alloc_sweep]") {
    for (const SweepSpec& spec : std::initializer_list<SweepSpec>
         {{true, 4}, {false, 6}}) {
        const bool err_first = spec.first;
        const long min_points = spec.second;
        INFO("first fetch/load is an error: " << err_first);
        int broken = 0;
        const long k = sweep([&](long n) {
            ManualClock clk;
            BundleLoader loader{err_first};
            GuardianRuleBundleCache c({.max_wait = 200ms}, [&clk] { return clk.now(); });
            const GuardianRuleBundleCache::LoaderFn fn = [&loader] { return loader(); };
            {
                FailNth arm(n);
                try {
                    (void)c.get(kGeneration, fn);
                } catch (...) {
                }
            }
            const bool fired = g_fired;

            bool ok = false;
            bool bad_call = false;
            for (int attempt = 0; attempt < 3 && !ok && !bad_call; ++attempt) {
                clk.advance(5s);  // past negative_ttl (1 s); max_age is 60 s so a held bundle stays
                std::chrono::nanoseconds waited{-1};
                try {
                    auto r = c.get(kGeneration, fn, &waited);
                    if (waited != 0ns)
                        bad_call = true;  // this thread is the only caller: it must never wait
                    if (r.has_value())
                        ok = (*r != nullptr && (*r)->generation == kGeneration &&
                              c.held_generation() == kGeneration);
                    else
                        bad_call = bad_call || timed_out(r.error().detail);
                } catch (...) {
                    bad_call = true;
                }
            }
            if (bad_call || !ok)
                ++broken;
            return fired;
        });
        REQUIRE(k > 0);
        CHECK(k - 1 >= min_points);  // allocation points exercised
        CHECK(broken == 0);
    }
}

TEST_CASE("alloc sweep: GuardianRuleBundleCache::invalidate() after a failed get() leaves it usable",
          "[guardian][rule_bundle][alloc_sweep]") {
    for (const SweepSpec& spec : std::initializer_list<SweepSpec>
         {{true, 4}, {false, 6}}) {
        const bool err_first = spec.first;
        const long min_points = spec.second;
        INFO("first fetch/load is an error: " << err_first);
        int broken = 0;
        const long k = sweep([&](long n) {
            ManualClock clk;
            BundleLoader loader{err_first};
            GuardianRuleBundleCache c({.max_wait = 200ms}, [&clk] { return clk.now(); });
            const GuardianRuleBundleCache::LoaderFn fn = [&loader] { return loader(); };
            {
                FailNth arm(n);
                try {
                    (void)c.get(kGeneration, fn);
                } catch (...) {
                }
            }
            const bool fired = g_fired;

            bool ok = false;
            bool bad_call = false;
            for (int attempt = 0; attempt < 3 && !ok && !bad_call; ++attempt) {
                c.invalidate();  // clears a remembered failure too: no clock advance needed
                try {
                    auto r = c.get(kGeneration, fn);
                    if (r.has_value())
                        ok = (*r != nullptr && (*r)->generation == kGeneration);
                    else
                        bad_call = timed_out(r.error().detail);
                } catch (...) {
                    bad_call = true;
                }
            }
            if (bad_call || !ok)
                ++broken;
            return fired;
        });
        REQUIRE(k > 0);
        CHECK(k - 1 >= min_points);  // allocation points exercised
        CHECK(broken == 0);
    }
}

// -- GuardianReconcileGate ----------------------------------------------------------------

TEST_CASE("alloc sweep: GuardianReconcileGate::decide() after a failed claim insert leaves no claim and the agent is admitted next time",
          "[guardian][reconcile_gate][alloc_sweep]") {
    // The documented ALLOCATION FAILURE arm (guardian_reconcile_gate.hpp): decide() may throw
    // bad_alloc while inserting the claim, after try_admit() succeeded. Nothing may leak: no
    // claim is written, the budget has counted exactly that one admission (the documented
    // cost), and the agent is admitted on its next call. (decide() never touches the in-flight
    // count, which only begin_admitted() raises, so it is not asserted here.)
    // The agent id is beyond the small-string buffer, so copying it into the map allocates.
    const std::string agent(40, 'a');
    int broken = 0;
    long threw_points = 0;
    const long k = sweep([&](long n) {
        ManualClock clk;
        const auto clock_fn = [&clk] { return clk.now(); };
        yuzu::server::GuardianReconcileBudget budget(
            {.budget_ms_per_s = 1'000'000.0, .burst_ms = 3'600'000.0, .max_per_s = 1'000'000},
            clock_fn);
        yuzu::server::GuardianReconcileGate gate(budget, clock_fn, std::chrono::seconds(25),
                                                 {.max_reserve = 0});
        bool threw = false;
        {
            FailNth arm(n);
            try {
                (void)gate.decide(agent, 0, 7);
            } catch (const std::bad_alloc&) {
                threw = true;
            } catch (...) {
                ++broken;
            }
        }
        const bool fired = g_fired;
        if (threw != fired)
            ++broken;  // an injected failure must surface as bad_alloc, nothing else may throw
        if (threw) {
            ++threw_points;
            if (gate.claims_size() != 0 || budget.admitted_total() != 1)
                ++broken;
        }
        // The retry: never rate limited by a claim that was not written, and it admits.
        yuzu::server::GuardianReconcileGate::ShedCause cause{};
        const auto again = threw ? gate.decide(agent, 0, 7, &cause) : yuzu::server::GuardianReconcileGate::Decision::Admit;
        if (again != yuzu::server::GuardianReconcileGate::Decision::Admit || gate.claims_size() != 1 ||
            budget.admitted_total() != (threw ? 2u : 1u))
            ++broken;
        return fired;
    });
    REQUIRE(k > 0);
    CHECK(threw_points >= 1);  // at least one failure point (key copy or map node) was reached
    CHECK(broken == 0);
}
