/**
 * test_users_win_rows.cpp -- the pure Windows row builders of the users plugin and its
 * declare_partial status write (agents/plugins/users/src/users_win_rows.hpp). Canned reads in,
 * exact pipe rows and result status out; runs on every OS.
 */

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "users_win_rows.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using namespace yuzu::users_win;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::GroupMembersRead;
using yuzu::agent::win::LocalUsersRead;
using yuzu::agent::win::WtsSessionsRead;

namespace {

using Rows = std::vector<std::string>;

constexpr BoundedStatus kNotCompleted[] = {BoundedStatus::TimedOut, BoundedStatus::Busy,
                                           BoundedStatus::Abandoned, BoundedStatus::Rejected};

// {session_id, state, station_name, user, domain, client_name}
WtsSessionsRead canned_sessions() {
    WtsSessionsRead read;
    read.status = BoundedStatus::Completed;
    read.enumerated = true;
    read.sessions = {
        {0, kWtsDisconnected, "Services", "", "", ""}, // no user: no row
        {1, kWtsActive, "Console", "alice", "HOST-A", ""},
        {2, kWtsActive, "RDP-Tcp#3", "bob", "", "laptop-b"},
        {3, kWtsDisconnected, "rdp-tcp#4", "carol", "CORP", ""},
        {4, kWtsConnected, "", "dave", "CORP", ""},
        {5, kWtsIdle, "", "erin", "CORP", ""},
        {6, kWtsListen, "", "frank", "CORP", ""},
        {65536, 9, "", "grace", "CORP", ""},
    };
    return read;
}

LocalUsersRead canned_users() {
    LocalUsersRead read;
    read.status = BoundedStatus::Completed;
    read.users = {{"alice", "Alice A", 0x200, 1700000000},
                  {"Guest", "", 0x200 | kUfAccountDisable, 0}};
    return read;
}

GroupMembersRead canned_members() {
    GroupMembersRead read;
    read.status = BoundedStatus::Completed;
    read.members = {{"HOST-A\\alice", kSidTypeUser},
                    {"CORP\\Domain Admins", kSidTypeGroup},
                    {"NT AUTHORITY\\INTERACTIVE", kSidTypeWellKnownGroup},
                    {"BUILTIN\\Users", kSidTypeAlias},
                    {"orphan", 8}}; // SidTypeUnknown, no backslash
    return read;
}

std::string stamp(std::uint32_t seconds) {
    return "T" + std::to_string(seconds);
}

// The fake plugin behind the declare_partial case: the Windows session legs' declaration, run on
// the test's thread.
WtsSessionsRead g_declared_read;

int declare_execute(YuzuCommandContext* raw, const char*, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw};
    declare_partial(ctx, wts_degraded_provenance(g_declared_read));
    return 0;
}

} // namespace

TEST_CASE("logged_on rows: active and disconnected sessions with a user",
          "[users][win_rows][bounded_os_call]") {
    CHECK(logged_on_rows(canned_sessions()) ==
          Rows{"user|alice|HOST-A|console|1", "user|bob|local|RDP|2", "user|carol|CORP|RDP|3"});
}

TEST_CASE("session rows: every session with a user, with its state",
          "[users][win_rows][bounded_os_call]") {
    CHECK(session_rows(canned_sessions()) ==
          Rows{"session|1|alice|Active|-|0", "session|2|bob|Active|laptop-b|0",
               "session|3|carol|Disconnected|-|0", "session|4|dave|Connected|-|0",
               "session|5|erin|Idle|-|0", "session|6|frank|Listen|-|0",
               "session|65536|grace|Other|-|0"});
}

TEST_CASE("a failed session listing is declared; an empty one is not",
          "[users][win_rows][bounded_os_call]") {
    WtsSessionsRead empty;
    empty.status = BoundedStatus::Completed;
    empty.enumerated = true;
    CHECK(logged_on_rows(empty).empty());
    CHECK(session_rows(empty).empty());
    CHECK(wts_degraded_provenance(empty).empty());

    WtsSessionsRead failed;
    failed.status = BoundedStatus::Completed;
    failed.win_error = 259;
    CHECK(logged_on_rows(failed).empty());
    CHECK(session_rows(failed).empty());
    CHECK(wts_degraded_provenance(failed) == "windows:users:wts_sessions:enum_failed:259");

    auto cut = canned_sessions();
    CHECK(wts_degraded_provenance(cut).empty());
    cut.truncated = true;
    CHECK(wts_degraded_provenance(cut) == "windows:users:wts_sessions:row_cap");
    CHECK_FALSE(logged_on_rows(cut).empty());
}

TEST_CASE("declare_partial reports a failed or cut read as CONSTRAINED and PARTIAL",
          "[users][win_rows][bounded_os_call]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &declare_execute;
    yuzu::agent::LocalDispatcher dispatcher;

    g_declared_read = {};
    g_declared_read.status = BoundedStatus::Completed;
    g_declared_read.win_error = 259; // not enumerated: the listing failed
    auto r = dispatcher.run(&descriptor, "probe");
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "windows:users:wts_sessions:enum_failed:259");

    g_declared_read = canned_sessions();
    g_declared_read.truncated = true;
    r = dispatcher.run(&descriptor, "probe");
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "windows:users:wts_sessions:row_cap");

    g_declared_read = canned_sessions(); // the whole list: nothing to declare
    r = dispatcher.run(&descriptor, "probe");
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(r.result_provenance.empty());
}

TEST_CASE("local_user rows: flags, comment and last logon", "[users][win_rows][bounded_os_call]") {
    const Rows expected{"local_user|alice|true|T1700000000|Alice A",
                        "local_user|Guest|false|Never|-"};
    auto read = canned_users();
    CHECK(local_user_rows(read, stamp) == expected);

    // Accounts collected before a failing page are still reported.
    read.nerr = 5;
    CHECK(local_user_rows(read, stamp) == expected);
}

TEST_CASE("admin rows: member type and domain split", "[users][win_rows][bounded_os_call]") {
    CHECK(admin_rows(canned_members()) ==
          Rows{"admin|alice|user|HOST-A", "admin|Domain Admins|group|CORP",
               "admin|INTERACTIVE|well_known_group|NT AUTHORITY", "admin|Users|alias|BUILTIN",
               "admin|orphan|unknown|local"});
}

TEST_CASE("group_member rows: member without its domain, only from a successful read",
          "[users][win_rows][bounded_os_call]") {
    auto read = canned_members();
    CHECK(group_member_rows(read, "Administrators") ==
          Rows{"group_member|alice|Administrators|user",
               "group_member|Domain Admins|Administrators|group",
               "group_member|INTERACTIVE|Administrators|well_known_group",
               "group_member|Users|Administrators|alias",
               "group_member|orphan|Administrators|unknown"});
    read.nerr = 2220; // NERR_GroupNotFound
    CHECK(group_member_rows(read, "Administrators").empty());
}

TEST_CASE("every SidType has a member type", "[users][win_rows][bounded_os_call]") {
    // SID_NAME_USE 1..11: User, Group, Domain, Alias, WellKnownGroup, DeletedAccount, Invalid,
    // Unknown, Computer, Label, LogonSession.
    const char* const types[] = {"user",    "group",   "unknown", "alias",   "well_known_group",
                                 "unknown", "unknown", "unknown", "unknown", "unknown",
                                 "unknown"};
    std::uint32_t usage = 0;
    for (const std::string type : types) {
        GroupMembersRead read;
        read.status = BoundedStatus::Completed;
        read.members = {{"D\\m", ++usage}};
        CHECK(admin_rows(read) == Rows{"admin|m|" + type + "|D"});
        CHECK(group_member_rows(read, "G") == Rows{"group_member|m|G|" + type});
    }
}

TEST_CASE("a capped or stalled read keeps its rows and says why",
          "[users][win_rows][bounded_os_call]") {
    auto read = canned_members();
    read.members.resize(3);
    CHECK(incomplete_token(read.truncated, read.no_progress).empty());
    read.truncated = true;
    CHECK(admin_rows(read).size() == 3);
    CHECK(group_member_rows(read, "Administrators").size() == 3);
    CHECK(incomplete_token(read.truncated, read.no_progress) == "row_cap");
    read.no_progress = true; // wins over row_cap
    CHECK(incomplete_token(read.truncated, read.no_progress) == "no_progress");
    CHECK(incomplete_token(false, true) == "no_progress");

    CHECK(incomplete_provenance("windows:users:net_user_enum", true, false) ==
          "windows:users:net_user_enum:row_cap");
    CHECK(incomplete_provenance("windows:users:local_group_members", false, true) ==
          "windows:users:local_group_members:no_progress");
    CHECK(incomplete_provenance("windows:users:net_user_enum", false, false).empty());

    auto sessions = canned_sessions();
    sessions.truncated = true;
    CHECK(logged_on_rows(sessions) == logged_on_rows(canned_sessions()));
    CHECK(session_rows(sessions) == session_rows(canned_sessions()));
}

TEST_CASE("a failure after earlier pages never reads as the member list",
          "[users][win_rows][bounded_os_call]") {
    auto read = canned_members();
    read.members.resize(1);
    read.nerr = 5;
    CHECK(admin_rows(read).empty());
    CHECK(group_member_rows(read, "Administrators").empty());
}

TEST_CASE("a read that did not complete yields no rows", "[users][win_rows][bounded_os_call]") {
    for (const auto status : kNotCompleted) {
        auto sessions = canned_sessions();
        sessions.status = status;
        sessions.enumerated = false;
        CHECK(logged_on_rows(sessions).empty());
        CHECK(session_rows(sessions).empty());
        CHECK(wts_degraded_provenance(sessions).empty()); // forward_bounded_failure reports it

        auto users = canned_users();
        users.status = status;
        CHECK(local_user_rows(users, stamp).empty());

        auto members = canned_members();
        members.status = status;
        CHECK(admin_rows(members).empty());
        CHECK(group_member_rows(members, "Administrators").empty());
    }
}
