/**
 * test_server_address_resolver.cpp — bounding behavior of
 * yuzu::agent::detail::resolve_bounded (server_address_resolver.hpp,
 * #3429 round 4 fix). The resolve step is injected so this test proves the
 * DEADLINE WRAPPER returns promptly even while the underlying resolve call
 * is still running -- the exact defect the round-4 external review found (a
 * plain std::async future's destructor blocking the caller past its own
 * wait_for() timeout, [futures.async]). No real DNS I/O here, matching this
 * repo's "no network in unit tests" discipline -- see
 * test_server_address_parsers.cpp for the pure
 * extract_server_host/looks_like_ip_literal coverage.
 */
#include <yuzu/agent/server_address_resolver.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::detail::resolve_bounded;

TEST_CASE("resolve_bounded returns literals from a fast injected resolver, comma-joined",
          "[agent][server_address_resolver]") {
    const auto result =
        resolve_bounded("server.example.com:50051", 500ms, [](const std::string&) {
            return std::vector<std::string>{"10.0.0.1", "10.0.0.2"};
        });
    CHECK(result == "10.0.0.1,10.0.0.2");
}

TEST_CASE("resolve_bounded returns an IP literal target unchanged without invoking resolve",
          "[agent][server_address_resolver]") {
    bool called = false;
    const auto result = resolve_bounded("10.0.0.5:50051", 500ms, [&](const std::string&) {
        called = true;
        return std::vector<std::string>{};
    });
    CHECK(result == "10.0.0.5");
    CHECK_FALSE(called);
}

TEST_CASE("resolve_bounded returns empty for an unparseable target without invoking resolve",
          "[agent][server_address_resolver]") {
    bool called = false;
    const auto result = resolve_bounded("[::1:50051", 500ms, [&](const std::string&) {
        called = true;
        return std::vector<std::string>{};
    });
    CHECK(result.empty());
    CHECK_FALSE(called);
}

TEST_CASE("resolve_bounded: the caller returns at the deadline while the injected resolver is "
          "still running -- the exact round-4 regression (a std::async future's destructor "
          "blocking the caller past its own timed-out wait_for())",
          "[agent][server_address_resolver]") {
    std::atomic<bool> resolver_finished{false};
    const auto start = std::chrono::steady_clock::now();

    const auto result =
        resolve_bounded("slow.example.com:50051", 100ms, [&](const std::string&) {
            std::this_thread::sleep_for(1s);
            resolver_finished = true;
            return std::vector<std::string>{"10.0.0.9"};
        });

    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.empty());
    // The whole point of the fix: THIS call returns promptly, not after the
    // injected resolver finishes. Generous CI-safe ceiling, still far under
    // the 1s the resolver itself sleeps for.
    CHECK(elapsed < 500ms);
    // Proves the caller genuinely didn't wait for the resolver: at the
    // moment resolve_bounded returned, the resolver's own sleep hadn't
    // finished yet -- the round-3 bug would have made this flip true before
    // resolve_bounded's return statement ever executed.
    CHECK_FALSE(resolver_finished.load());

    // Drain: let the detached resolve finish before the test binary moves
    // on, matching test_bounded_wait.cpp's own drain discipline for the
    // shared outstanding-call ceiling in agents/shared/bounded_wait.hpp.
    for (int i = 0; i < 20 && !resolver_finished.load(); ++i)
        std::this_thread::sleep_for(100ms);
}
