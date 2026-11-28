/**
 * test_win_account_enum.cpp -- yuzu::agent::win::read_local_users / read_local_group_members
 * (agent-core).
 *
 * The injected-reader cases run on every OS and share the production process-wide slots, so each
 * one that blocks a reader opens its gate with a ScopeExit and waits for the slot to recover.
 * Ordering comes from promises; anything an abandonable reader touches is captured BY VALUE.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the real
 * cases, an OS service): the deadline on a detached worker is the property under test (one 200 ms
 * wait per function). The real cases are one bounded read of each local list; on Windows they are
 * the only check that the shipped readers answer at all.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_account_enum.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::GroupMembersRead;
using yuzu::agent::win::LocalUsersRead;
using yuzu::agent::win::read_local_group_members;
using yuzu::agent::win::read_local_group_members_for_test;
using yuzu::agent::win::read_local_users;
using yuzu::agent::win::read_local_users_for_test;

namespace {

/// A never-returning reader times out, the next call is Abandoned without starting a second
/// reader, and the slot recovers once the reader returns.
template <typename Read>
void check_stall_then_recovery(Read (*bounded)(std::chrono::milliseconds,
                                               const std::function<Read()>&)) {
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
    const std::function<Read()> stalled = [opened = gate.get_future().share(), entered, calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return Read{};
    };

    const auto first = bounded(200ms, stalled);
    CHECK(first.status == BoundedStatus::TimedOut);
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = bounded(5000ms, stalled);
    CHECK(second.status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until([bounded] {
        return bounded(5000ms, [] { return Read{}; }).status == BoundedStatus::Completed;
    }));
}

} // namespace

TEST_CASE("read_local_users_for_test returns the injected accounts", "[bounded_os_call][agent]") {
    const auto r = read_local_users_for_test(5000ms, [] {
        LocalUsersRead out;
        out.nerr = 5;
        out.truncated = true;
        out.no_progress = true;
        out.users.push_back({"user-a", "comment-a", 2, 1700000000});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 5);
    CHECK(r.truncated);
    CHECK(r.no_progress);
    REQUIRE(r.users.size() == 1);
    const auto& u = r.users.front();
    CHECK(u.name == "user-a");
    CHECK(u.comment == "comment-a");
    CHECK(u.flags == 2);
    CHECK(u.last_logon == 1700000000);
}

TEST_CASE("read_local_group_members_for_test returns the injected members",
          "[bounded_os_call][agent]") {
    const auto r = read_local_group_members_for_test(5000ms, [] {
        GroupMembersRead out;
        out.nerr = 5;
        out.truncated = true;
        out.no_progress = true;
        out.members.push_back({"domain-a\\user-a", 1});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 5);
    CHECK(r.truncated);
    CHECK(r.no_progress);
    REQUIRE(r.members.size() == 1);
    CHECK(r.members.front().domain_and_name == "domain-a\\user-a");
    CHECK(r.members.front().sid_usage == 1);
}

TEST_CASE("a never-returning local-users reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    check_stall_then_recovery<LocalUsersRead>(&read_local_users_for_test);
}

TEST_CASE("a never-returning group-members reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    check_stall_then_recovery<GroupMembersRead>(&read_local_group_members_for_test);
}

TEST_CASE("read_local_users completes with this OS's answer", "[bounded_os_call][agent]") {
    const auto r = read_local_users(yuzu::agent::win::kLocalUsersDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    CHECK(r.nerr == 0);
    CHECK_FALSE(r.users.empty());
#else
    CHECK(r.nerr == 120);
    CHECK(r.users.empty());
#endif
    CHECK_FALSE(r.truncated);
    CHECK_FALSE(r.no_progress);
}

TEST_CASE("read_local_group_members completes with this OS's answer", "[bounded_os_call][agent]") {
    const auto r =
        read_local_group_members("Administrators", yuzu::agent::win::kGroupMembersDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
#ifdef _WIN32
    CHECK(r.nerr == 0);
    CHECK_FALSE(r.members.empty()); // Administrators always has a member
#else
    CHECK(r.nerr == 120);
    CHECK(r.members.empty());
#endif
    CHECK_FALSE(r.truncated);
    CHECK_FALSE(r.no_progress);
}
