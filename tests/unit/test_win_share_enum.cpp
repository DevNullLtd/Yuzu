/**
 * test_win_share_enum.cpp -- yuzu::agent::win::read_share_page (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slot, so each
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the one real
 * case, an OS service): the deadline on a detached worker is the property under test (one 200 ms
 * wait). The real case is one bounded page of the local share list; on Windows it is the only
 * check that the shipped reader answers at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_share_enum.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::read_share_page;
using yuzu::agent::win::read_share_page_for_test;
using yuzu::agent::win::SharePage;

TEST_CASE("read_share_page_for_test passes the request and the injected page through",
          "[bounded_os_call][agent]") {
    const auto r = read_share_page_for_test(2, 7, 5000ms, [](int level, std::uint32_t resume) {
        SharePage out;
        out.nerr = 234;
        out.total = static_cast<std::uint32_t>(level);
        out.resume = resume + 1;
        out.shares.push_back({"share-a", "C:\\a", 3});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 234);
    CHECK(r.total == 2);
    CHECK(r.resume == 8);
    REQUIRE(r.shares.size() == 1);
    CHECK(r.shares.front().name == "share-a");
    CHECK(r.shares.front().path == "C:\\a");
    CHECK(r.shares.front().type == 3);
}

TEST_CASE("a never-returning share reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    // A failing REQUIRE must not leave a worker wedged: it holds the process-wide slot.
    yuzu::test::ScopeExit opener{release};
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    const std::function<SharePage(int, std::uint32_t)> stalled =
        [opened = gate.get_future().share(), entered, calls](int, std::uint32_t) {
            if (++*calls == 1)
                entered->set_value();
            opened.wait();
            return SharePage{};
        };

    const auto first = read_share_page_for_test(2, 0, 200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK(first.shares.empty());
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_share_page_for_test(2, 0, 5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([] {
        return read_share_page_for_test(2, 0, 5000ms, [](int, std::uint32_t) {
                   return SharePage{};
               }).status == BoundedStatus::Completed;
    }));
}

TEST_CASE("read_share_page completes with this OS's answer", "[bounded_os_call][agent]") {
    // Level 1 needs no elevation. The NET_API_STATUS is the host's business on Windows.
    const auto r = read_share_page(1, 0, yuzu::agent::win::kShareEnumDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    const auto bad = read_share_page(502, 0, yuzu::agent::win::kShareEnumDeadline);
    REQUIRE(bad.status == BoundedStatus::Completed);
    CHECK(bad.nerr == 124); // ERROR_INVALID_LEVEL
    CHECK(bad.shares.empty());
#else
    CHECK(r.nerr == 120);
    CHECK(r.shares.empty());
#endif
}
