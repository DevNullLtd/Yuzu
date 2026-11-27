/**
 * test_win_wts_sessions.cpp -- yuzu::agent::win::read_wts_sessions (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slot, so each
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the one real
 * case, an OS service): the deadline on a detached worker is the property under test (one 200 ms
 * wait). The real case is one bounded read of the local session list; on Windows it is the only
 * check that the shipped reader answers at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_wts_sessions.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::read_wts_sessions;
using yuzu::agent::win::read_wts_sessions_for_test;
using yuzu::agent::win::WtsSessionsRead;

TEST_CASE("read_wts_sessions_for_test returns the injected sessions", "[bounded_os_call][agent]") {
    const auto r = read_wts_sessions_for_test(5000ms, [] {
        WtsSessionsRead out;
        out.enumerated = true;
        out.truncated = true;
        out.sessions.push_back({3, 4, "station-a", "user-a", "domain-a", "client-a"});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.enumerated);
    CHECK(r.truncated);
    CHECK(r.win_error == 0);
    REQUIRE(r.sessions.size() == 1);
    const auto& s = r.sessions.front();
    CHECK(s.session_id == 3);
    CHECK(s.state == 4);
    CHECK(s.station_name == "station-a");
    CHECK(s.user == "user-a");
    CHECK(s.domain == "domain-a");
    CHECK(s.client_name == "client-a");
}

TEST_CASE("a never-returning WTS reader times out, then Abandoned, then recovers",
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
    const std::function<WtsSessionsRead()> stalled = [opened = gate.get_future().share(), entered,
                                                      calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return WtsSessionsRead{};
    };

    const auto first = read_wts_sessions_for_test(200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK_FALSE(first.enumerated);
    CHECK(first.sessions.empty());
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_wts_sessions_for_test(5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([] {
        return read_wts_sessions_for_test(5000ms, [] { return WtsSessionsRead{}; }).status ==
               BoundedStatus::Completed;
    }));
}

TEST_CASE("read_wts_sessions completes with this OS's answer", "[bounded_os_call][agent]") {
    const auto r = read_wts_sessions(yuzu::agent::win::kWtsSessionsDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    CHECK(r.enumerated);
#else
    CHECK_FALSE(r.enumerated);
    CHECK(r.win_error == 120);
    CHECK(r.sessions.empty());
#endif
}
