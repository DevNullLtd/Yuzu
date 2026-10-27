// Unit tests for the bounded resolver, the resolver error classifier, the shared NAT64 discovery
// cache and the resolver-status -> discovery-outcome mapping (resolver_errors.hpp,
// bounded_resolver.hpp, nat64_discovery.hpp, nat64_probe.hpp).
//
// NOTE: no Catch2 assertion runs inside an injected lookup (it executes on a worker thread, and
// Catch2 assertions are not thread-safe); lookups only record into atomics read afterwards.

// bounded_resolver.hpp defines NOMINMAX / WIN32_LEAN_AND_MEAN itself before winsock2.h; include it
// before anything that pulls <windows.h>.
#include "bounded_resolver.hpp"
#include "nat64_discovery.hpp"
#include "nat64_probe.hpp"
#include "resolver_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
namespace net = yuzu::server::net;
using namespace std::chrono_literals;

struct Latch {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    void release() {
        {
            std::lock_guard lk(mu);
            open = true;
        }
        cv.notify_all();
    }
    void wait() {
        std::unique_lock lk(mu);
        cv.wait(lk, [&] { return open; });
    }
};

// 2001:db8:122:344::/96 and 3fff:0:0:1::/96 wrapped around 192.0.0.170 (what a DNS64 returns).
const std::string kPref1 = "2001:db8:122:344::c000:aa";

// The full per-lookup budget a consumer gives discovery; a smaller budget is "clamped".
constexpr std::chrono::milliseconds kFullBudget{5000};

net::LookupFn answering(std::vector<std::string> addrs) {
    return [addrs = std::move(addrs)](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kOk, addrs};
    };
}
net::LookupFn failing(net::ResolveStatus st = net::ResolveStatus::kTemporary) {
    return [st](const std::string&) -> net::ResolveResult { return {st, {}}; };
}

// Each test owns its cache (a private net::Nat64DiscoveryCache) and a swappable lookup.
struct DiscoveryRig {
    net::Nat64DiscoveryCache cache;
    net::LookupFn lookup;
    void expire() {
        std::lock_guard lk(cache.mu);
        cache.expires = {};
    }
};

// The wiring every consumer uses: ipv4only.arpa through the bounded resolver, the result mapped
// by the ONE shared mapping, into the shared cache (the OIDC probe does exactly this).
net::Nat64Discovery discover(std::chrono::milliseconds budget, net::LookupFn lookup,
                             net::Nat64DiscoveryCache& cache,
                             std::shared_ptr<net::ResolverPool> pool) {
    const bool clamped = budget < kFullBudget;
    return net::discover_nat64_prefixes_cached(
        [&](std::vector<yuzu::server::oidc::egress::Ipv6>& out) {
            const auto r = net::bounded_resolve(net::kNat64ProbeName, budget, lookup, pool);
            return net::nat64_outcome_from_resolve(r, clamped, out);
        },
        cache, budget);
}
} // namespace

TEST_CASE("bounded resolver: the default cap is exactly 16 and a blocked lookup times out on time",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    static_assert(net::kMaxInFlightLookups == 16);
    CHECK(net::ResolverPool{}.cap == 16); // the DEFAULT pool; a 16->17 change must fail here

    auto latch = std::make_shared<Latch>();
    const net::LookupFn blocked = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"192.0.2.1"}};
    };
    auto pool = std::make_shared<net::ResolverPool>(); // default cap

    // Timing: the call returns at the bound (not before, not much after). Run it on a helper
    // thread with a bounded wait, so an implementation that ignores the timeout fails this test
    // instead of hanging it.
    auto fut = std::async(std::launch::async, [&] {
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = net::bounded_resolve("blocked.example", 400ms, blocked, pool);
        return std::make_pair(r.status, std::chrono::steady_clock::now() - t0);
    });
    if (fut.wait_for(10s) != std::future_status::ready) {
        latch->release(); // unblock so the test can end
        FAIL("bounded_resolve ignored its timeout");
    }
    const auto [status, elapsed] = fut.get();
    CHECK(status == net::ResolveStatus::kTimeout);
    CHECK(elapsed >= 350ms); // not returned early
    CHECK(elapsed < 700ms);  // not a doubled wait
    CHECK(pool->in_flight.load() == 1);

    // 15 more blocked lookups fill the default cap of 16; the 17th is refused kBusy.
    for (int i = 0; i < 15; ++i)
        CHECK(net::bounded_resolve("blocked.example", 1ms, blocked, pool).status ==
              net::ResolveStatus::kTimeout);
    CHECK(pool->in_flight.load() == 16);
    CHECK(net::bounded_resolve("blocked.example", 1ms, blocked, pool).status ==
          net::ResolveStatus::kBusy);

    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
}

TEST_CASE("bounded resolver: exact statuses through the same path", "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    auto pool = std::make_shared<net::ResolverPool>();
    const net::LookupFn nf = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kNotFound, {}};
    };
    const net::LookupFn temp = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kTemporary, {}};
    };
    const net::LookupFn boom = [](const std::string&) -> net::ResolveResult {
        throw std::runtime_error("resolver blew up");
    };
    const net::LookupFn ok = [](const std::string& h) -> net::ResolveResult {
        return {net::ResolveStatus::kOk, {h == "a" ? "192.0.2.7" : "192.0.2.8"}};
    };
    CHECK(net::bounded_resolve("x", 5s, nf, pool).status == net::ResolveStatus::kNotFound);
    CHECK(net::bounded_resolve("x", 5s, temp, pool).status == net::ResolveStatus::kTemporary);
    CHECK(net::bounded_resolve("x", 5s, boom, pool).status == net::ResolveStatus::kTemporary);
    const auto r = net::bounded_resolve("a", 5s, ok, pool);
    REQUIRE(r.status == net::ResolveStatus::kOk);
    CHECK(r.addresses == std::vector<std::string>{"192.0.2.7"});
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
    const auto lit = net::bounded_resolve("127.0.0.1", 5s);
    REQUIRE(lit.status == net::ResolveStatus::kOk);
    CHECK(lit.addresses.front() == "127.0.0.1");
}

TEST_CASE("resolver error codes: only NXDOMAIN / NODATA are an ANSWER, everything else a failure",
          "[bounded_resolver][nat64_discovery]") {
    using yuzu::server::net::resolver_code_is_no_data;
#ifndef _WIN32
    CHECK(resolver_code_is_no_data(EAI_NONAME));
    CHECK_FALSE(resolver_code_is_no_data(EAI_AGAIN));
    CHECK_FALSE(resolver_code_is_no_data(EAI_FAIL));
    CHECK_FALSE(resolver_code_is_no_data(EAI_MEMORY));
    CHECK_FALSE(resolver_code_is_no_data(EAI_SYSTEM));
#else
    CHECK(resolver_code_is_no_data(11001)); // WSAHOST_NOT_FOUND
    CHECK(resolver_code_is_no_data(11004)); // WSANO_DATA
    CHECK_FALSE(resolver_code_is_no_data(11002)); // WSATRY_AGAIN
#endif
    CHECK_FALSE(resolver_code_is_no_data(0));
}

TEST_CASE("NAT64 cache constants are pinned", "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    static_assert(net::kMaxDiscoveredNat64Prefixes == 64);
    static_assert(net::kNat64PositiveTtl == std::chrono::minutes{10});
    static_assert(net::kNat64NegativeTtl == std::chrono::minutes{1});
    // Exactly 64 prefixes fit; 65 do not.
    const auto build = [](int n) {
        net::Nat64DiscoveryCache cache;
        return std::make_pair(net::discover_nat64_prefixes_cached(
                                  [n](std::vector<yuzu::server::oidc::egress::Ipv6>& out) {
                                      for (int i = 0; i < n; ++i) {
                                          yuzu::server::oidc::egress::Ipv6 a{};
                                          a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8;
                                          a[4] = static_cast<std::uint8_t>(i + 1);
                                          a[12] = 0xc0; a[15] = 0xaa; // 192.0.0.170 at /96
                                          out.push_back(a);
                                      }
                                      return net::Nat64LookupOutcome::kAnswered;
                                  },
                                  cache),
                              0);
    };
    const auto at_bound = build(64).first;
    CHECK_FALSE(at_bound.overflowed);
    CHECK(at_bound.prefixes.size() == 64);
    const auto over = build(65).first;
    CHECK(over.overflowed);
    CHECK(over.overflow_started); // logged once, on the transition
}

TEST_CASE("NAT64 cache: a clamped or busy lookup does not poison what another consumer reads",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto latch = std::make_shared<Latch>();
    rig.lookup = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"2001:db8:122:344::c000:aa"}};
    };
    // A budget below a full lookup that times out is INCONCLUSIVE: failed for this call only.
    auto pool = std::make_shared<net::ResolverPool>(1);
    const auto d = discover(10ms, rig.lookup, rig.cache, pool);
    CHECK(d.looked_up);
    CHECK_FALSE(d.answered_now);
    CHECK(d.stale);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.filled);       // no negative entry...
        CHECK_FALSE(rig.cache.last_failed);  // ...no failure flag...
        CHECK(rig.cache.expires == std::chrono::steady_clock::time_point{}); // ...no TTL
    }
    CHECK(rig.cache.stats.inconclusive.load() == 1);
    CHECK(rig.cache.stats.failed.load() == 0);
    // The next consumer, with a fair budget, does its own lookup and learns the prefix.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i) // the abandoned worker finishes
        std::this_thread::sleep_for(10ms);
    rig.lookup = answering({kPref1});
    const auto fair = discover(5s, rig.lookup, rig.cache, pool);
    CHECK(fair.answered_now);
    CHECK(fair.prefixes.size() == 1);
}

TEST_CASE("NAT64 probe: every resolver status maps to exactly one shared outcome",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using O = net::Nat64LookupOutcome;
    using S = net::ResolveStatus;
    std::vector<yuzu::server::oidc::egress::Ipv6> out;
    const auto map = [&](S st, std::vector<std::string> addrs, bool clamped) {
        out.clear();
        return net::nat64_outcome_from_resolve({st, std::move(addrs)}, clamped, out);
    };
    CHECK(map(S::kOk, {"2001:db8:122:344::c000:aa"}, false) == O::kAnswered);
    CHECK(out.size() == 1);
    CHECK(map(S::kOk, {"192.0.0.170"}, false) == O::kAnsweredNone); // A-only: no DNS64 here
    CHECK(map(S::kNotFound, {}, false) == O::kAnsweredNone);        // NXDOMAIN / NODATA: an ANSWER
    CHECK(map(S::kTemporary, {}, false) == O::kFailed);             // EAI_AGAIN / FAIL / SYSTEM
    CHECK(map(S::kTimeout, {}, false) == O::kFailed);               // a full-budget timeout
    CHECK(map(S::kTimeout, {}, true) == O::kInconclusive);          // a clamped budget: not the resolver's fault
    CHECK(map(S::kBusy, {}, false) == O::kInconclusive);            // no capacity: nothing was asked
    CHECK(map(S::kBusy, {}, true) == O::kInconclusive);
}

TEST_CASE("NAT64 discovery is single-flight: N concurrent callers with a blocked resolver use ONE lookup",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1); // the production discovery pool shape
    auto latch = std::make_shared<Latch>();
    std::atomic<int> lookups{0};
    rig.lookup = [latch, &lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        latch->wait();
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    constexpr int kCallers = 12;
    std::vector<std::future<net::Nat64Discovery>> calls;
    for (int i = 0; i < kCallers; ++i)
        calls.push_back(std::async(std::launch::async, [&] {
            // A full per-lookup budget (not clamped); the leader's lookup is blocked, so every
            // caller ends inconclusive at ITS OWN budget rather than starting a lookup of its own.
            return discover(300ms, rig.lookup, rig.cache, pool);
        }));
    std::vector<net::Nat64Discovery> results;
    for (auto& f : calls) {
        REQUIRE(f.wait_for(20s) == std::future_status::ready); // none hangs past its budget
        results.push_back(f.get());
    }
    CHECK(lookups.load() == 1); // exactly one lookup, one worker, one slot, ever started
    CHECK(pool->in_flight.load() == 1); // ...and it is still outstanding (the resolver is hung)
    for (const auto& r : results) {
        CHECK_FALSE(r.answered_now); // nobody got an answer while the resolver was blocked
        CHECK(r.stale);
    }
    // Release: the flight finishes, ONE answer fills the cache, and a late caller reads it.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto after = discover(2s, rig.lookup, rig.cache, pool);
    CHECK(after.prefixes.size() == 1);
    // The abandoned flight's late answer is discarded (nobody was waiting); the late caller made
    // its own, single, lookup.
    CHECK(lookups.load() == 2);
}

TEST_CASE("NAT64 discovery: waiters share the leader's answer (no expiry stampede)",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    std::atomic<int> lookups{0};
    rig.lookup = [&lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        std::this_thread::sleep_for(150ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    std::vector<std::future<net::Nat64Discovery>> calls;
    for (int i = 0; i < 8; ++i)
        calls.push_back(std::async(std::launch::async, [&] {
            return discover(5s, rig.lookup, rig.cache, pool);
        }));
    for (auto& f : calls) {
        const auto d = f.get();
        CHECK(d.ever_answered);
        CHECK(d.prefixes.size() == 1);
    }
    CHECK(lookups.load() == 1);
}

TEST_CASE("NAT64 discovery: an allocation failure in the leader releases the single flight",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    rig.lookup = answering({kPref1});
    // The leader's parse/merge step throws bad_alloc (injected right after the lookup returns).
    rig.cache.test_fault_after_lookup = [] { throw std::bad_alloc(); };
    const auto d = discover(2s, rig.lookup, rig.cache, pool);
    CHECK(d.stale);            // inconclusive for this call
    CHECK_FALSE(d.answered_now);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.inflight); // NOT wedged: the flag was cleared by the guard
        CHECK_FALSE(rig.cache.filled);   // and nothing half-written is served as fresh
    }
    // The next caller is not blocked behind a dead flight: it looks, answers and learns.
    rig.cache.test_fault_after_lookup = nullptr;
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto next = discover(2s, rig.lookup, rig.cache, pool);
    CHECK(next.answered_now);
    CHECK(next.prefixes.size() == 1);
}

TEST_CASE("NAT64 discovery: a waiter whose leader ended inconclusive does not start its own lookup",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    std::atomic<int> lookups{0};
    // The leader's lookup is slow, then reports busy-equivalent (inconclusive via a clamped
    // timeout): 40 ms budget against a 300 ms lookup.
    rig.lookup = [&lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        std::this_thread::sleep_for(300ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    auto leader = std::async(std::launch::async,
                             [&] { return discover(40ms, rig.lookup, rig.cache, pool); });
    std::this_thread::sleep_for(20ms); // the leader holds the flight
    const auto waiter = discover(5s, rig.lookup, rig.cache, pool);
    const auto l = leader.get();
    CHECK(l.stale);
    // The leader ended inconclusive (its clamped budget expired) and wrote nothing, so the waiter
    // must NOT run a second full-budget lookup of its own: it is inconclusive too.
    CHECK(lookups.load() == 1);
    CHECK(waiter.stale);
    CHECK_FALSE(waiter.answered_now);
}

TEST_CASE("NAT64 discovery: finishing the flight WAKES a waiter well before its own budget",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    rig.lookup = [](const std::string&) -> net::ResolveResult {
        std::this_thread::sleep_for(100ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    auto leader = std::async(std::launch::async,
                             [&] { return discover(5s, rig.lookup, rig.cache, pool); });
    std::this_thread::sleep_for(20ms); // the leader holds the flight
    const auto t0 = std::chrono::steady_clock::now();
    const auto waiter = discover(5s, rig.lookup, rig.cache, pool);
    const auto waited = std::chrono::steady_clock::now() - t0;
    (void)leader.get();
    // The waiter shares the leader's answer as soon as the flight ends. Without the guard's
    // notify it would sit out its full 5 s budget.
    CHECK(waited < 1s);
    CHECK(waiter.prefixes.size() == 1);
}

TEST_CASE("NAT64 discovery: a CLAMPED leader's timeout leaves the cache untouched; an unclamped caller then looks",
          "[bounded_resolver][nat64_discovery]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto latch = std::make_shared<Latch>();
    std::atomic<int> lookups{0};
    rig.lookup = [latch, &lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        latch->wait();
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    // A budget below a full per-lookup budget (5 s) that times out: inconclusive, NOT a failure.
    const auto clamped = discover(30ms, rig.lookup, rig.cache, pool);
    CHECK(clamped.stale);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.filled);
        CHECK_FALSE(rig.cache.last_failed);
        CHECK(rig.cache.expires == std::chrono::steady_clock::time_point{});
    }
    CHECK(rig.cache.stats.failed.load() == 0);
    CHECK(rig.cache.stats.inconclusive.load() == 1);
    // Let the abandoned worker finish (its late answer is discarded), then an UNCLAMPED caller
    // (a full 5 s budget) performs a lookup of its own and its timeout WOULD be a recorded failure.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto fair = discover(5s, rig.lookup, rig.cache, pool);
    CHECK(lookups.load() == 2);
    CHECK(fair.answered_now);
    CHECK(fair.prefixes.size() == 1);
}

TEST_CASE("NAT64 cache: NXDOMAIN (an answer) and a later real failure are told apart",
          "[bounded_resolver][nat64_discovery]") {
    DiscoveryRig rig;
    // NXDOMAIN for ipv4only.arpa is an ANSWER (no DNS64 on this network), not a failure.
    rig.lookup = failing(net::ResolveStatus::kNotFound);
    auto pool = std::make_shared<net::ResolverPool>(1);
    const auto first = discover(kFullBudget, rig.lookup, rig.cache, pool);
    CHECK(first.ever_answered);
    CHECK_FALSE(first.stale);
    CHECK(rig.cache.stats.answered_none.load() == 1);
    CHECK(rig.cache.stats.failed.load() == 0);
    // Still fresh: served from the cache, no second lookup.
    const auto cached = discover(kFullBudget, failing(), rig.cache, pool);
    CHECK_FALSE(cached.looked_up);
    CHECK_FALSE(cached.stale);
    // After expiry a real failure IS stale, keeps what was learned, and says when to retry.
    rig.expire();
    const auto failed = discover(kFullBudget, failing(), rig.cache, pool);
    CHECK(failed.looked_up);
    CHECK(failed.stale);
    CHECK(rig.cache.stats.failed.load() == 1);
    const auto again = discover(kFullBudget, failing(), rig.cache, pool);
    CHECK_FALSE(again.looked_up); // the failure is cached for the negative TTL
    CHECK(again.retry_after >= 55s);
    CHECK(again.retry_after <= 60s);
}

TEST_CASE("NAT64 cache: an overflow is reported once and counts each refusal",
          "[bounded_resolver][nat64_discovery]") {
    DiscoveryRig rig;
    std::vector<std::string> many;
    for (int i = 0; i < 65; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "2001:db8:%x:1::c000:aa", i + 1);
        many.emplace_back(buf);
    }
    rig.lookup = answering(many);
    auto pool = std::make_shared<net::ResolverPool>(1);
    const auto d = discover(kFullBudget, rig.lookup, rig.cache, pool);
    CHECK(d.overflowed);
    CHECK(d.overflow_started);
    const auto again = discover(kFullBudget, rig.lookup, rig.cache, pool);
    CHECK(again.overflowed);
    CHECK_FALSE(again.overflow_started);
    CHECK(rig.cache.stats.overflow_refusals.load() >= 1);
    CHECK(rig.cache.overflow_logged);
}
