/**
 * test_win_session_enum.cpp -- yuzu::agent::win::read_smb_sessions (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slot, so each
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the one real
 * case, an OS service): the deadline on a detached worker is the property under test (one 200 ms
 * wait). The real case is one bounded drain of the local SMB session list; on Windows it is the
 * only check that the shipped reader answers at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_session_enum.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::read_smb_sessions;
using yuzu::agent::win::read_smb_sessions_for_test;
using yuzu::agent::win::SmbSessionsRead;

TEST_CASE("read_smb_sessions_for_test passes the request and the injected sessions through",
          "[bounded_os_call][agent]") {
    const auto r = read_smb_sessions_for_test(502, 9, 5000ms, [](int level, std::size_t max) {
        SmbSessionsRead out;
        out.nerr = static_cast<std::uint32_t>(level);
        out.truncated = max == 9;
        out.no_progress = true;
        out.sessions.push_back({"client-a", "user-a"});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 502);
    CHECK(r.truncated);
    CHECK(r.no_progress);
    REQUIRE(r.sessions.size() == 1);
    CHECK(r.sessions.front().client == "client-a");
    CHECK(r.sessions.front().user == "user-a");
}

TEST_CASE("a never-returning SMB session reader times out, then Abandoned, then recovers",
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
    const std::function<SmbSessionsRead(int, std::size_t)> stalled =
        [opened = gate.get_future().share(), entered, calls](int, std::size_t) {
            if (++*calls == 1)
                entered->set_value();
            opened.wait();
            return SmbSessionsRead{};
        };

    const auto first = read_smb_sessions_for_test(10, 1, 200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    CHECK(first.sessions.empty());
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_smb_sessions_for_test(10, 1, 5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([] {
        return read_smb_sessions_for_test(10, 1, 5000ms, [](int, std::size_t) {
                   return SmbSessionsRead{};
               }).status == BoundedStatus::Completed;
    }));
}

TEST_CASE("read_smb_sessions completes with this OS's answer", "[bounded_os_call][agent]") {
    // The NET_API_STATUS is the host's business on Windows (level 10 can still be refused).
    const auto r = read_smb_sessions(10, 16, yuzu::agent::win::kSmbSessionsDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    const auto bad = read_smb_sessions(1, 16, yuzu::agent::win::kSmbSessionsDeadline);
    REQUIRE(bad.status == BoundedStatus::Completed);
    CHECK(bad.nerr == 124); // ERROR_INVALID_LEVEL
    CHECK(bad.sessions.empty());
#else
    CHECK(r.nerr == 120);
    CHECK(r.sessions.empty());
#endif
}
