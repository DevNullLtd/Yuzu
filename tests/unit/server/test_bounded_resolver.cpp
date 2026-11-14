// Unit tests for the bounded resolver and the resolver error classifier (bounded_resolver.hpp,
// resolver_errors.hpp).
//
// NOTE: no Catch2 assertion runs inside an injected lookup (it executes on a worker thread, and
// Catch2 assertions are not thread-safe); lookups only record into atomics read afterwards.

// bounded_resolver.hpp defines NOMINMAX / WIN32_LEAN_AND_MEAN itself before winsock2.h; include it
// before anything that pulls <windows.h>.
#include "bounded_resolver.hpp"
#include "resolver_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

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
} // namespace

TEST_CASE("bounded resolver: the default cap is exactly 16 and a blocked lookup times out on time",
          "[bounded_resolver]") {
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
    CHECK(elapsed < 2s);     // returned near the bound, not after a doubled wait (load-tolerant ceiling)
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

TEST_CASE("bounded resolver: the in-flight reading never exceeds the cap under a refused burst",
          "[bounded_resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    constexpr int kCap = 2;
    auto latch = std::make_shared<Latch>();
    const net::LookupFn blocked = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"192.0.2.1"}};
    };
    auto pool = std::make_shared<net::ResolverPool>(kCap);

    // Fill the pool, then hammer it from several threads so almost every call is refused while a
    // sampler reads the counter. A refused call must never raise the counter, so the highest
    // reading ever seen is the cap. (Nothing asserts on a worker thread: results go to atomics.)
    for (int i = 0; i < kCap; ++i)
        CHECK(net::bounded_resolve("blocked.example", 1ms, blocked, pool).status ==
              net::ResolveStatus::kTimeout);

    std::atomic<bool> stop{false};
    std::atomic<int> max_seen{0};
    std::atomic<int> admitted_beyond_cap{0};
    std::vector<std::thread> hammer;
    for (int t = 0; t < 8; ++t)
        hammer.emplace_back([&] {
            while (!stop.load()) {
                if (net::bounded_resolve("blocked.example", 1ms, blocked, pool).status !=
                    net::ResolveStatus::kBusy)
                    admitted_beyond_cap.fetch_add(1);
            }
        });
    std::thread sampler([&] {
        while (!stop.load()) {
            const int v = pool->in_flight.load();
            int prev = max_seen.load();
            while (v > prev && !max_seen.compare_exchange_weak(prev, v)) {
            }
        }
    });
    std::this_thread::sleep_for(200ms);
    stop.store(true);
    for (auto& th : hammer)
        th.join();
    sampler.join();

    CHECK(admitted_beyond_cap.load() == 0);
    CHECK(max_seen.load() == kCap);

    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
}

TEST_CASE("bounded resolver: exact statuses through the same path", "[bounded_resolver]") {
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

TEST_CASE("bounded resolver: every call is counted exactly once, by the status it returns",
          "[bounded_resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    static_assert(net::kResolveStatusCount == 5);
    // The label of each status is non-empty and distinct: it is the closed `outcome` label set.
    for (std::size_t i = 0; i < net::kResolveStatusCount; ++i) {
        const std::string a = net::resolve_status_label(static_cast<net::ResolveStatus>(i));
        CHECK_FALSE(a.empty());
        CHECK(a != "unknown");
        for (std::size_t j = i + 1; j < net::kResolveStatusCount; ++j)
            CHECK(a != net::resolve_status_label(static_cast<net::ResolveStatus>(j)));
    }
    CHECK(std::string(net::resolve_status_label(net::ResolveStatus::kOk)) == "ok");
    CHECK(std::string(net::resolve_status_label(net::ResolveStatus::kNotFound)) == "not_found");
    CHECK(std::string(net::resolve_status_label(net::ResolveStatus::kTemporary)) == "temporary");
    CHECK(std::string(net::resolve_status_label(net::ResolveStatus::kTimeout)) == "timeout");
    CHECK(std::string(net::resolve_status_label(net::ResolveStatus::kBusy)) == "busy");

    auto pool = std::make_shared<net::ResolverPool>(1);
    const auto at = [&](net::ResolveStatus st) {
        return pool->outcome_counts()[static_cast<std::size_t>(st)];
    };
    CHECK(pool->outcome_counts() == std::array<std::uint64_t, 5>{0, 0, 0, 0, 0});

    const net::LookupFn ok = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kOk, {"192.0.2.1"}};
    };
    const net::LookupFn nf = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kNotFound, {}};
    };
    const net::LookupFn temp = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kTemporary, {}};
    };
    const auto drain = [&] {
        for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
            std::this_thread::sleep_for(10ms);
        return pool->in_flight.load() == 0;
    };

    CHECK(net::bounded_resolve("x", 5s, ok, pool).status == net::ResolveStatus::kOk);
    REQUIRE(drain());
    CHECK(net::bounded_resolve("x", 5s, nf, pool).status == net::ResolveStatus::kNotFound);
    REQUIRE(drain());
    CHECK(net::bounded_resolve("x", 5s, temp, pool).status == net::ResolveStatus::kTemporary);
    REQUIRE(drain());

    // A held lookup: it times out for its caller (counted once), a second call is refused (busy).
    auto latch = std::make_shared<Latch>();
    const net::LookupFn blocked = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"192.0.2.1"}};
    };
    CHECK(net::bounded_resolve("x", 1ms, blocked, pool).status == net::ResolveStatus::kTimeout);
    CHECK(net::bounded_resolve("x", 1ms, blocked, pool).status == net::ResolveStatus::kBusy);
    CHECK(net::bounded_resolve("x", 1ms, blocked, pool).status == net::ResolveStatus::kBusy);

    CHECK(at(net::ResolveStatus::kOk) == 1);
    CHECK(at(net::ResolveStatus::kNotFound) == 1);
    CHECK(at(net::ResolveStatus::kTemporary) == 1);
    CHECK(at(net::ResolveStatus::kTimeout) == 1);
    CHECK(at(net::ResolveStatus::kBusy) == 2);

    // The held lookup finishing later adds nothing: its call was already counted as a timeout.
    latch->release();
    REQUIRE(drain());
    CHECK(pool->outcome_counts() == std::array<std::uint64_t, 5>{1, 1, 1, 1, 2});
}

TEST_CASE("bounded resolver: a lookup that throws is counted as temporary", "[bounded_resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    auto pool = std::make_shared<net::ResolverPool>(1);
    const net::LookupFn boom = [](const std::string&) -> net::ResolveResult {
        throw std::runtime_error("resolver blew up");
    };
    CHECK(net::bounded_resolve("x", 5s, boom, pool).status == net::ResolveStatus::kTemporary);
    CHECK(pool->outcome_counts() == std::array<std::uint64_t, 5>{0, 0, 1, 0, 0});
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
}

TEST_CASE("resolver error codes: only NXDOMAIN / NODATA are an ANSWER, everything else a failure",
          "[bounded_resolver]") {
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
