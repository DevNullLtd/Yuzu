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

#include <chrono>
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
