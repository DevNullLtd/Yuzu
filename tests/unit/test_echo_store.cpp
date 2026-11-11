/**
 * test_echo_store.cpp -- Unit tests for EchoDatabase (SQLite-backed Echo storage)
 *
 * Covers: open/create, warehouse tables, typed inserts, SQL queries,
 * stats, config get/set, state get/set.
 */

#include "echo_aggregator.hpp" // run_budget: the failed-measurement case
#include "echo_db.hpp"
#include "echo_netqual.hpp"
#include "echo_netqual_boot.hpp"
#include "echo_sql_executor.hpp"
#include "test_helpers.hpp"
#include "test_log_capture.hpp"

#include <yuzu/agent/echo_db_legacy_rename.hpp> // tar.db -> echo.db adoption

#include <sqlite3.h> // raw handle for the reopen-after-DROP upgrade simulation

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h> // geteuid — root-skip in the POSIX-only permission-based tests
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h> // GetNamedSecurityInfoW, SetNamedSecurityInfoW, SetEntriesInAclW
#include <sddl.h>   // ConvertSidToStringSidW, ConvertStringSidToSidW

#include <win_str.hpp>
#endif

namespace fs = std::filesystem;
using namespace yuzu::echo;

// Helper: create an EchoDatabase in a unique temp file, clean up on destruction.
// Uniqueness comes from yuzu::test::unique_temp_path -- never salt with
// std::hash<thread::id> / steady_clock, which collide under Defender-induced
// I/O serialisation on the Windows runner (CLAUDE.md test conventions, #473).
struct TestEchoDb {
    EchoDatabase db;
    fs::path path;

    ~TestEchoDb() {
        { EchoDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
        fs::remove(fs::path{path.string() + "-journal"}, ec); // pre-created empty on Windows
    }
};

static TestEchoDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_");
    auto result = EchoDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestEchoDb{std::move(*result), tmp};
}

// =============================================================================
// Database lifecycle
// =============================================================================

TEST_CASE("EchoDatabase: open creates database file", "[echo][store][lifecycle]") {
    auto t = make_test_db();
    CHECK(fs::exists(t.path));
}

TEST_CASE("EchoDatabase: warehouse tables created on open", "[echo][store][lifecycle]") {
    auto t = make_test_db();
    // Verify by inserting a process event -- would fail if table doesn't exist
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 42;
    ev.name = "test.exe";

    CHECK(t.db.fold_process_events({ev}));
}

TEST_CASE("EchoDatabase: purge_source drops ALL tiers for one source, leaves others",
          "[echo][store][purge]") {
    auto t = make_test_db();

    // Seed EVERY process tier (hourly/daily/monthly) -- not just one -- so a regression that
    // purges only granularities[0] fails, and so the returned rows_deleted proves the cross-tier
    // sum (governance B2). One fold writes all three tiers at once: three events in two hours of
    // one day and month give 3 hourly rows (two in hour 0, one in hour 7200... keyed by name),
    // 3 daily and 3 monthly.
    ProcessEvent p1;
    p1.ts = 1000;
    p1.snapshot_id = 1;
    p1.action = "started";
    p1.pid = 1;
    p1.name = "a.exe";
    ProcessEvent p2 = p1;
    p2.pid = 2;
    p2.name = "b.exe";
    ProcessEvent p3 = p1;
    p3.ts = 7200;
    p3.pid = 3;
    p3.name = "c.exe";
    REQUIRE(t.db.fold_process_events({p1, p2, p3}));

    // A different source, folded into its own tiers, must be entirely untouched.
    NetworkEvent n1;
    n1.ts = 1000;
    n1.snapshot_id = 1;
    n1.action = "connected";
    n1.proto = "tcp";
    n1.local_addr = "127.0.0.1";
    n1.local_port = 5;
    n1.remote_addr = "1.1.1.1";
    n1.remote_port = 53;
    REQUIRE(t.db.fold_network_events({n1}));

    auto count = [&](const std::string& table) {
        auto r = t.db.execute_query("SELECT COUNT(*) FROM " + table);
        REQUIRE(r.has_value());
        REQUIRE(!r->rows.empty());
        return std::stoi(r->rows[0][0]);
    };
    REQUIRE(count("process_hourly") == 3);
    REQUIRE(count("process_daily") == 3);
    REQUIRE(count("process_monthly") == 3);
    REQUIRE(count("tcp_hourly") == 1);
    REQUIRE(count("tcp_daily") == 1);
    REQUIRE(count("tcp_monthly") == 1);

    auto res = t.db.purge_source("process");
    REQUIRE(res.has_value());
    CHECK(res->rows_deleted == 9); // 3 + 3 + 3 across all three tiers -- the cross-tier sum
    CHECK(!res->dictionary_pending); // the sweep finished inside its deadline
    CHECK(count("process_hourly") == 0);
    CHECK(count("process_daily") == 0);
    CHECK(count("process_monthly") == 0);
    CHECK(count("tcp_hourly") == 1);  // a different source is untouched...
    CHECK(count("tcp_daily") == 1);   // ...across all of its tiers
    CHECK(count("tcp_monthly") == 1);
}

TEST_CASE("EchoDatabase: purge_source also removes the strings only the purged source used",
          "[echo][store][purge][dictionary]") {
    // The dictionary interns every text key. A purge that leaves the purged source's strings in
    // it would keep a user name or a DNS name the operator asked to erase, one SELECT away from
    // the rows. The sweep removes exactly the strings no remaining row references.
    auto t = make_test_db();
    DnsEvent dns;
    dns.ts = 1000;
    dns.action = "appeared";
    dns.name = "secret-host.example";
    dns.record_type = "A";
    dns.data = "10.9.8.7";
    REQUIRE(t.db.fold_dns_events({dns}));
    ArpEvent arp;
    arp.ts = 1000;
    arp.action = "appeared";
    arp.iface = "en0";
    arp.ip_address = "10.0.0.1";
    arp.mac_address = "aa:bb";
    REQUIRE(t.db.fold_arp_events({arp}));
    const auto has = [&](const std::string& text) {
        auto r = t.db.execute_query("SELECT COUNT(*) FROM echo_dict WHERE text = '" + text + "'");
        REQUIRE(r.has_value());
        return r->rows[0][0] == "1";
    };
    REQUIRE(has("secret-host.example"));
    REQUIRE(has("10.0.0.1"));

    REQUIRE(t.db.purge_source("dns").has_value());
    CHECK_FALSE(has("secret-host.example")); // gone with its source
    CHECK_FALSE(has("10.9.8.7"));
    CHECK(has("10.0.0.1")); // a string another source still references stays
}

TEST_CASE("EchoDatabase: purge_source(usage) also erases usage_daily_user",
          "[echo][store][purge][usage]") {
    // usage_daily_user (Wave 7 PR7.2b) has no tier of its own in the schema
    // registry -- the generic per-tier purge loop above never reaches it, so
    // this is a REGRESSION test for the dedicated branch in purge_source, not
    // a duplicate of the generic case just above.
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
        "last_seen, distinct_users, superseded_runs, expired_runs) VALUES "
        "(86400, 'a.exe', 1, 10, 1000, 1010, 1, 0, 0)"));
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_daily_user (day_ts, exe_key, user) VALUES (86400, 'a.exe', 'alice')"));
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) VALUES "
        "(1000, 0, 'open', 1, 'a.exe', 'alice', 1000)"));

    auto count = [&](const std::string& table) {
        auto r = t.db.execute_query("SELECT COUNT(*) FROM " + table);
        REQUIRE(r.has_value());
        return std::stoi(r->rows[0][0]);
    };
    REQUIRE(count("usage_daily") == 1);
    REQUIRE(count("usage_daily_user") == 1);
    REQUIRE(count("usage_live") == 1);

    auto res = t.db.purge_source("usage");
    REQUIRE(res.has_value());
    CHECK(res->rows_deleted == 3); // usage_daily + usage_live (registered tiers) + usage_daily_user
    CHECK(count("usage_daily") == 0);
    CHECK(count("usage_daily_user") == 0); // the regression this test pins
    CHECK(count("usage_live") == 0);
}

namespace {

RegistryEvent registry_row(std::string key, std::string action = "changed") {
    RegistryEvent ev;
    ev.ts = 1'761'000'000;
    ev.snapshot_id = 3;
    ev.hive = "HKLM";
    ev.key_path = "SOFTWARE\\Vendor\\Svc";
    ev.value_name = "Start";
    ev.action = std::move(action);
    ev.data_type = "REG_DWORD";
    ev.data = "2";
    ev.data_size = 4;
    ev.prev_data_type = "REG_DWORD";
    ev.prev_data = "3";
    ev.prev_data_size = 4;
    ev.actor_pid = 812;
    ev.actor_image = "actor.exe";
    ev.source = "notify";
    ev.observed_at = 1'761'000'000'000;
    ev.detail = "attr:corr";
    ev.record_key = std::move(key);
    return ev;
}

std::string first_cell(EchoDatabase& db, const std::string& sql) {
    auto r = db.execute_query(sql);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->rows.empty());
    return r->rows[0][0];
}

} // namespace

TEST_CASE("EchoDatabase: insert_registry_events_and_cursor rolls the change up and "
          "replays as a no-op",
          "[echo][store][registry]") {
    auto t = make_test_db();
    auto removed = registry_row("k2", "removed");
    removed.data_type.clear(); // absent value: '' type and data
    removed.data.clear();
    removed.data_size = 0;
    removed.actor_pid = 0; // unattributed
    removed.actor_image.clear();
    removed.detail.clear();
    REQUIRE(t.db.insert_registry_events_and_cursor({registry_row("k1"), removed}, R"({"v":1})",
                                                    {{"registry:HKLM\\R", R"({"v":1,"keys":{}})"}}));
    // A roll-up row per (hive, key, value, action) and hour: what changed and how often, the
    // last rendered value and type, and who last wrote it. Raw rows are not kept.
    auto r = t.db.execute_query("SELECT hive, key_path, value_name, action, change_count, last_data, "
                                "last_data_type, last_actor_image, last_ts FROM registry_hourly "
                                "ORDER BY action");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 2);
    const auto& row = r->rows[0];
    CHECK(row[0] == "HKLM");
    CHECK(row[1] == "SOFTWARE\\Vendor\\Svc");
    CHECK(row[2] == "Start");
    CHECK(row[3] == "changed");
    CHECK(row[4] == "1");
    CHECK(row[5] == "2");
    CHECK(row[6] == "REG_DWORD");
    CHECK(row[7] == "actor.exe");
    CHECK(row[8] == "1761000000");
    CHECK(r->rows[1][3] == "removed");
    CHECK(r->rows[1][6].empty()); // the removed row has no value type: an absent value
    CHECK(r->rows[1][7].empty());

    // A replayed key is a silent no-op (the ring knows it) and still commits the cursor and baseline.
    REQUIRE(t.db.insert_registry_events_and_cursor({registry_row("k1")}, R"({"v":1,"n":2})",
                                                    {{"registry:HKLM\\R", R"({"v":1,"keys":{"K":{}}})"}}));
    CHECK(first_cell(t.db, "SELECT SUM(change_count) FROM registry_hourly") == "2");
    CHECK(*t.db.get_cursor("registry").value() == R"({"v":1,"n":2})");
    CHECK(*t.db.try_get_state("registry:HKLM\\R").value() == R"({"v":1,"keys":{"K":{}}})");
    // ... even when the replay attributes differently: after a restart the in-memory event
    // buffer is gone, so a replayed change can come back degraded or unattributed. Identity
    // is what changed, never who -- the stored row keeps its first attribution.
    auto reattributed = registry_row("k1");
    reattributed.actor_pid = 0;
    reattributed.actor_image.clear();
    reattributed.detail = "attr:degraded";
    CHECK(t.db.insert_registry_events_and_cursor({reattributed}, R"({"v":1})", {}));
    CHECK(first_cell(t.db, "SELECT SUM(change_count) FROM registry_hourly") == "2");
    CHECK(first_cell(t.db, "SELECT last_actor_image FROM registry_hourly WHERE action = 'changed'") ==
          "actor.exe");
}

TEST_CASE("EchoDatabase: insert_registry_events_and_cursor refuses collisions and bad keys atomically",
          "[echo][store][registry]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_registry_events_and_cursor({registry_row("k1")}, R"({"v":1})",
                                                    {{"registry:HKLM\\R", "old"}}));
    // Same key, different change: a collision. The cursor and the baseline roll back with it.
    auto other = registry_row("k1");
    other.data = "9";
    const auto collided = t.db.insert_registry_events_and_cursor({other}, R"({"v":2})",
                                                                 {{"registry:HKLM\\R", "new"}});
    REQUIRE_FALSE(collided.has_value());
    CHECK(collided.error() == EchoDatabase::CursorInsertError::KeyCollision);
    CHECK(*t.db.get_cursor("registry").value() == R"({"v":1})");
    CHECK(*t.db.try_get_state("registry:HKLM\\R").value() == "old");
    // Empty and NUL keys are refused before anything is written.
    for (const std::string& bad : {std::string{}, std::string("a\0b", 3)}) {
        const auto r = t.db.insert_registry_events_and_cursor({registry_row(bad)}, R"({"v":3})", {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == EchoDatabase::CursorInsertError::KeyCollision);
    }
    CHECK(*t.db.get_cursor("registry").value() == R"({"v":1})");
}

TEST_CASE("EchoDatabase: try_get_state is tri-state", "[echo][store][registry]") {
    auto t = make_test_db();
    auto missing = t.db.try_get_state("registry:none");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value()); // succeeded, no row
    REQUIRE(t.db.set_state("registry:one", "{}"));
    CHECK(*t.db.try_get_state("registry:one").value() == "{}");
    // A broken store is an ERROR, not "absent": get_state's empty-on-failure would read as
    // "no baseline" and silently re-baseline.
    sqlite3* h = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &h) == SQLITE_OK);
    REQUIRE(sqlite3_exec(h, "ALTER TABLE echo_state RENAME TO echo_state_away", nullptr, nullptr, nullptr) ==
            SQLITE_OK);
    CHECK_FALSE(t.db.try_get_state("registry:one").has_value());
    sqlite3_close(h);
}

TEST_CASE("EchoDatabase: purge_source(registry) erases the rows, the cursor (held values included) and every baseline",
          "[echo][store][purge][registry]") {
    auto t = make_test_db();
    // The cursor row is a content store too: it holds the rendered values of a change
    // whose writer is not settled yet. Purging the source must erase it with everything else.
    const std::string cursor_with_held =
       R"({"v":1,"tick":4,"held":[{"r":"HKLM\\A","k":"HKLM\\A\\K","v":"Secret","a":"changed",)"
       R"("t":1,"s":14,"d":"held-rendered-value","dtr":false,"hp":true,"pt":1,"ps":14,)"
       R"("pd":"held-previous-value","ptr":false,"o":5,"lo":1,"hi":4,"src":"notify"}]})";
    REQUIRE(t.db.insert_registry_events_and_cursor(
       {registry_row("k1")}, cursor_with_held,
       {{"registry:HKLM\\A", "baseline-a"}, {"registry:HKU\\S-1\\B", "baseline-b"}}));
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM echo_cursor WHERE source = 'registry' AND "
                           "cursor_json LIKE '%held-rendered-value%'") == "1");
    REQUIRE(t.db.set_state("service", "kept")); // unrelated baseline
    REQUIRE(t.db.insert_power_events_and_cursor({PowerEvent{1, 1, "wake", "", "p1"}}, R"({"v":1})"));

    const auto res = t.db.purge_source("registry");
    REQUIRE(res.has_value());
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM registry_hourly") == "0");
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM registry_daily") == "0");
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM echo_fold_seen WHERE source = 'registry'") == "0");
    CHECK_FALSE(t.db.get_cursor("registry").value().has_value());
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM echo_cursor WHERE cursor_json LIKE '%held-%'") == "0");
    CHECK_FALSE(t.db.try_get_state("registry:HKLM\\A").value().has_value());
    CHECK_FALSE(t.db.try_get_state("registry:HKU\\S-1\\B").value().has_value());
    CHECK(*t.db.try_get_state("service").value() == "kept");
    CHECK(t.db.get_cursor("power").value().has_value());

    // Purging another source leaves the registry bookkeeping alone.
    REQUIRE(t.db.insert_registry_events_and_cursor({registry_row("k9")}, R"({"v":1})",
                                                    {{"registry:HKLM\\A", "b"}}));
    REQUIRE(t.db.purge_source("power").has_value());
    CHECK(t.db.get_cursor("registry").value().has_value());
    CHECK(t.db.try_get_state("registry:HKLM\\A").value().has_value());
    CHECK(t.db.get_cursor("power").value().has_value()); // purge(power) leaves its own cursor too
}

TEST_CASE("EchoDatabase: purge_source rejects an unknown source", "[echo][store][purge]") {
    auto t = make_test_db();
    auto res = t.db.purge_source("not_a_source");
    CHECK_FALSE(res.has_value());
}

// =============================================================================
// Typed inserts and SQL queries
// =============================================================================

TEST_CASE("EchoDatabase: fold and query process events", "[echo][store][crud]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 5; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = (i % 2 == 0) ? "started" : "stopped";
        ev.pid = static_cast<uint32_t>(i + 1);
        ev.name = "proc" + std::to_string(i);
        events.push_back(std::move(ev));
    }

    REQUIRE(t.db.fold_process_events(events));

    // One hourly row per (name, user, parent), counting what happened. The five events fall in
    // the hour that starts at 0.
    auto results = t.db.execute_query(
        "SELECT hour_ts, name, start_count, stop_count FROM process_hourly ORDER BY name");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 5);
    CHECK(results->rows[0][0] == "0");
    CHECK(results->rows[0][1] == "proc0");
    CHECK(results->rows[0][2] == "1"); // proc0 started
    CHECK(results->rows[0][3] == "0");
    CHECK(results->rows[1][2] == "0"); // proc1 stopped
    CHECK(results->rows[1][3] == "1");
}

TEST_CASE("EchoDatabase: process wrapper writes the view's enrichment columns",
          "[echo][store][crud][enrichment]") {
    auto t = make_test_db();
    ProcessEvent child;
    child.ts = 5000;
    child.action = "started";
    child.pid = 20;
    child.ppid = 10;
    child.name = "child.exe";
    child.user = "jsmith";
    child.parent_name = "parent.exe";
    ProcessEvent crash = child;
    crash.action = "stopped";
    crash.exit_code = 139;
    ProcessEvent clean = child;
    clean.action = "stopped";
    clean.name = "clean.exe";
    clean.exit_code = 0;
    REQUIRE(t.db.fold_process_events({child, crash, clean}));

    // parent_name is a key, abnormal_exit_count counts a stop with a non-zero status. FAILS if
    // either enrichment is dropped from process_delta or the wrapper.
    auto r = t.db.execute_query("SELECT name, user, parent_name, start_count, stop_count, "
                                "abnormal_exit_count FROM process_hourly ORDER BY name");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 2); // start and stop of one process share a key
    CHECK(r->rows[0] == QueryRow{"child.exe", "jsmith", "parent.exe", "1", "1", "1"}); // exit 139
    CHECK(r->rows[1] == QueryRow{"clean.exe", "jsmith", "parent.exe", "0", "1", "0"});  // exit 0
}

TEST_CASE("EchoDatabase: insert and query software events", "[echo][store][crud][software]") {
    // Direct round-trip through fold_software_events -- the only exerciser of the
    // wrapper's key mapping, so a transposition (e.g. version <-> publisher) is caught here.
    auto t = make_test_db();

    std::vector<SoftwareEvent> events;
    SoftwareEvent inst;
    inst.ts = 1000;
    inst.snapshot_id = 1;
    inst.action = "installed";
    inst.name = "7-Zip";
    inst.version = "23.01";
    inst.publisher = "Igor Pavlov";
    inst.install_date = "20260101";
    events.push_back(inst);

    SoftwareEvent upg;
    upg.ts = 1001;
    upg.snapshot_id = 1;
    upg.action = "upgraded";
    upg.name = "VSCode";
    upg.version = "1.91";
    upg.prev_version = "1.90";
    upg.publisher = "Microsoft";
    upg.install_date = "20260102";
    events.push_back(upg);

    REQUIRE(t.db.fold_software_events(events));

    // A roll-up row per (name, version, publisher) and hour, counting installs, removals and
    // upgrades. prev_version and install_date are not kept: they describe one event, not the
    // application. The two events are distinct keys, so a transposed bind shows here.
    auto r = t.db.execute_query(
        "SELECT name, version, publisher, install_count, remove_count, upgrade_count "
        "FROM software_hourly ORDER BY name");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 2);
    CHECK(r->rows[0] == QueryRow{"7-Zip", "23.01", "Igor Pavlov", "1", "0", "0"});
    CHECK(r->rows[1] == QueryRow{"VSCode", "1.91", "Microsoft", "0", "0", "1"});

    // Empty-vector contract matches the sibling inserts (returns true, no-op).
    CHECK(t.db.fold_software_events({}));
}

TEST_CASE("execute_user_query: software_hourly and software_daily are sandbox-readable",
          "[echo][store][sandbox][software][security]") {
    // The roll-up views read their `_r` tables and the dictionary; the authorizer must let an
    // operator echo.sql aggregate them THROUGH the view, and only through it. No other test runs
    // an actual statement through the read-only connection on these tables (the allowlist
    // iteration test only checks is_queryable_table).
    auto t = make_test_db();
    SoftwareEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "installed";
    ev.name = "7-Zip";
    ev.version = "23.01";
    REQUIRE(t.db.fold_software_events({ev, ev, ev}));

    auto hourly = t.db.execute_user_query("SELECT name, install_count FROM software_hourly");
    REQUIRE(hourly.has_value());
    REQUIRE(hourly->rows.size() == 1);
    CHECK(hourly->rows[0][0] == "7-Zip");

    auto daily = t.db.execute_user_query("SELECT SUM(install_count) FROM software_daily");
    REQUIRE(daily.has_value());
    REQUIRE(daily->rows.size() == 1);
    CHECK(daily->rows[0][0] == "3");

    // The physical table and the dictionary behind the view are NOT readable by name.
    CHECK_FALSE(t.db.execute_user_query("SELECT * FROM software_daily_r").has_value());
    CHECK_FALSE(t.db.execute_user_query("SELECT * FROM echo_dict").has_value());
}

TEST_CASE("execute_user_query: usage tables are denied to generic echo.sql (#4260)",
          "[echo][store][security][usage]") {
    // usage/usage_daily/usage_daily_user are read ONLY through the
    // Forensics-gated app_usage plugin reads (p2.1/p2.2), which never go
    // through execute_user_query. A generic echo.sql query touching any of
    // them -- direct name, $Usage_* placeholder, alias, or JOIN/subquery --
    // must be rejected by the read-only connection's SQLite authorizer, not
    // silently return rows or an empty success.
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
        "last_seen, distinct_users, superseded_runs, expired_runs) VALUES "
        "(86400, 'a.exe', 1, 10, 1000, 1010, 1, 0, 0)"));
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_daily_user (day_ts, exe_key, user) VALUES (86400, 'a.exe', 'alice')"));
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) VALUES "
        "(1000, 0, 'open', 1, 'a.exe', 'alice', 1000)"));
    REQUIRE(t.db.fold_process_events({[] {
        ProcessEvent p;
        p.ts = 1000;
        p.snapshot_id = 1;
        p.action = "started";
        p.pid = 1;
        p.name = "p.exe";
        return p;
    }()}));

    CHECK_FALSE(t.db.execute_user_query("SELECT * FROM usage_daily").has_value());

    // Translation stays intact ($Usage_Daily -> usage_daily resolves) -- the
    // authorizer denies post-translation, not the translator pre-emptively.
    auto translated = validate_and_translate_sql("SELECT * FROM $Usage_Daily");
    REQUIRE(translated.has_value());
    CHECK(translated->find("usage_daily") != std::string::npos);
    CHECK_FALSE(t.db.execute_user_query(*translated).has_value());

    CHECK_FALSE(t.db.execute_user_query("SELECT u.exe_key FROM usage_live u").has_value());
    CHECK_FALSE(t.db
                    .execute_user_query("SELECT p.name FROM process_hourly p JOIN usage_daily d "
                                         "ON d.exe_key = p.name")
                    .has_value());
    CHECK_FALSE(
        t.db.execute_user_query("SELECT (SELECT COUNT(*) FROM usage_daily_user)").has_value());

    // Positive control: the authorizer isn't wedged shut -- a non-usage
    // table via its dollar name still works. execute_user_query never
    // translates $-names itself (confirmed against its implementation --
    // it passes the raw string straight to sqlite3_prepare_v2), so this
    // query must go through validate_and_translate_sql first, exactly like
    // the $Usage_Daily denial check above; passing the bare $Process_Hourly
    // string here would hit SQLite's own "near $Process_Hourly: syntax
    // error" before the authorizer ever ran.
    auto ctrl_sql = validate_and_translate_sql("SELECT COUNT(*) FROM $Process_Hourly");
    REQUIRE(ctrl_sql.has_value());
    auto ctrl = t.db.execute_user_query(*ctrl_sql);
    REQUIRE(ctrl.has_value());
    REQUIRE(ctrl->rows.size() == 1);
    CHECK(ctrl->rows[0][0] == "1");
}

TEST_CASE("echo.export $Software summary projection references only existing columns",
          "[echo][store][software][export]") {
    // Regression guard (#1620): do_export's `software` UNION branch builds a summary expression
    // over software_hourly. That projection must reference only columns the view still has -- a
    // stale column fails at runtime with "no such column". This mirrors do_export's software
    // projection so a future re-introduction of a dropped column in that SELECT is caught by the
    // unit suite.
    auto t = make_test_db();
    SoftwareEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "installed";
    ev.name = "7-Zip";
    ev.version = "23.01";
    REQUIRE(t.db.fold_software_events({ev}));
    auto r = t.db.execute_query(
        "SELECT 'software', hour_ts AS ts, 0, 'bucket', (name || ' ' || version) AS summary "
        "FROM software_hourly");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][4] == "7-Zip 23.01");
}

TEST_CASE("EchoDatabase: insert and query network events", "[echo][store][crud]") {
    auto t = make_test_db();

    NetworkEvent ev;
    ev.ts = 2000;
    ev.snapshot_id = 1;
    ev.action = "connected";
    ev.proto = "tcp";
    ev.local_addr = "127.0.0.1";
    ev.local_port = 8080;
    ev.remote_addr = "10.0.0.1";
    ev.remote_port = 443;
    ev.pid = 100;
    ev.process_name = "curl";

    REQUIRE(t.db.fold_network_events({ev}));

    // The tcp tier keys on the REMOTE end and the owning process; the local address and port are
    // not kept.
    auto results = t.db.execute_query(
        "SELECT proto, remote_port, remote_addr, process_name, connect_count FROM tcp_hourly");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 1);
    CHECK(results->rows[0] == QueryRow{"tcp", "443", "10.0.0.1", "curl", "1"});
}

// The rolling "recent connections" read (query_recent_tcp_connections) is gone with the raw tcp
// rows it walked: the roll-up keeps per-remote hourly counts, not per-socket observations. The
// listening-socket path that test once covered is pinned in test_echo_diff.cpp.

TEST_CASE("EchoDatabase: listening sockets fold as listen_open under the wildcard remote",
          "[echo][store][listen]") {
    auto t = make_test_db();
    NetworkEvent open_ev;
    open_ev.ts = 4001;
    open_ev.action = "listen_open";
    open_ev.proto = "tcp";
    open_ev.local_addr = "0.0.0.0";
    open_ev.local_port = 3000;
    open_ev.state = "LISTEN";
    open_ev.process_name = "node";
    NetworkEvent close_ev = open_ev;
    close_ev.action = "listen_close";
    REQUIRE(t.db.fold_network_events({open_ev, close_ev}));
    auto r = t.db.execute_query("SELECT remote_addr, remote_port, process_name, listen_open_count, "
                                "listen_close_count, connect_count FROM tcp_hourly");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0] == QueryRow{"*", "3000", "node", "1", "1", "0"}); // never a connection
}

TEST_CASE("EchoDatabase: query with time range filter", "[echo][store][query]") {
    auto t = make_test_db();

    // One process start per hour for ten hours: ten hourly buckets.
    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 3600 * i + 5;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.fold_process_events(events));

    auto results = t.db.execute_query(
        "SELECT hour_ts FROM process_hourly WHERE hour_ts >= 10800 AND hour_ts <= 21600 "
        "ORDER BY hour_ts");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 4);
    CHECK(results->rows[0][0] == "10800");
    CHECK(results->rows[3][0] == "21600");
}

TEST_CASE("EchoDatabase: query with LIMIT", "[echo][store][query]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 20; ++i) {
        ProcessEvent ev;
        ev.ts = 3600 * i + 5;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.fold_process_events(events));

    auto results = t.db.execute_query("SELECT hour_ts FROM process_hourly LIMIT 5");
    REQUIRE(results.has_value());
    CHECK(results->rows.size() == 5);
}

// =============================================================================
// Retention (purge via SQL)
// =============================================================================

TEST_CASE("EchoDatabase: purge old records via execute_sql_range", "[echo][store][purge]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 3600 * i + 5;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.fold_process_events(events));

    // The rows live in the physical table; the view is read-only.
    REQUIRE(t.db.execute_sql("DELETE FROM process_hourly_r WHERE hour_ts < 18000"));

    auto remaining = t.db.execute_query("SELECT hour_ts FROM process_hourly ORDER BY hour_ts");
    REQUIRE(remaining.has_value());
    CHECK(remaining->rows.size() == 5);
    CHECK(remaining->rows[0][0] == "18000");
}

// =============================================================================
// Stats
// =============================================================================

TEST_CASE("EchoDatabase: stats returns correct values", "[echo][store][stats]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 5; ++i) {
        ProcessEvent ev;
        ev.ts = 7200 + i; // all in the hour that starts at 7200
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.fold_process_events(events));

    // stats() is data-driven over the roll-up declarations (review S6), so a row in ANY source's
    // finest tier -- not just the original four -- must be counted. Fold one module load an hour
    // later and confirm record_count picks it up. Guards against a regression that drops a source
    // from the aggregate. A source counts through its hourly tier: five events of one process in
    // one hour are ONE row.
    ModuleRow mod;
    mod.ts = 10800;
    mod.snapshot_id = 1;
    mod.action = "loaded";
    mod.process_name = "app.exe";
    mod.module_name = "a.dll";
    mod.signed_state = "signed";
    REQUIRE(t.db.fold_module_events({mod}));

    auto s = t.db.stats();
    CHECK(s.record_count == 2); // 1 process_hourly row + 1 module_hourly row
    CHECK(s.oldest_timestamp == 7200);  // bucket starts, not event times
    CHECK(s.newest_timestamp == 10800);
    CHECK(s.db_size_bytes > 0);
}

// =============================================================================
// Config get/set
// =============================================================================

TEST_CASE("EchoDatabase: config get returns default", "[echo][store][config]") {
    auto t = make_test_db();

    auto val = t.db.get_config("nonexistent", "fallback");
    CHECK(val == "fallback");
}

TEST_CASE("EchoDatabase: config set and get", "[echo][store][config]") {
    auto t = make_test_db();

    t.db.set_config("test_key", "test_value");
    auto val = t.db.get_config("test_key");
    CHECK(val == "test_value");

    // Update
    t.db.set_config("test_key", "updated_value");
    val = t.db.get_config("test_key");
    CHECK(val == "updated_value");
}

TEST_CASE("EchoDatabase: a fresh database stores no retention_days setting", "[echo][store][config]") {
    auto t = make_test_db();

    CHECK(t.db.get_config("retention_days", "absent") == "absent");
}

// =============================================================================
// State get/set
// =============================================================================

TEST_CASE("EchoDatabase: state get returns empty for unknown collector", "[echo][store][state]") {
    auto t = make_test_db();

    auto val = t.db.get_state("unknown_collector");
    CHECK(val.empty());
}

TEST_CASE("EchoDatabase: state set and get", "[echo][store][state]") {
    auto t = make_test_db();

    std::string json = R"([{"pid":1,"name":"init"},{"pid":42,"name":"firefox"}])";
    t.db.set_state("process", json);

    auto val = t.db.get_state("process");
    CHECK(val == json);

    // Update
    std::string updated = R"([{"pid":1,"name":"init"}])";
    t.db.set_state("process", updated);
    val = t.db.get_state("process");
    CHECK(val == updated);
}

TEST_CASE("EchoDatabase: multiple collectors have independent state", "[echo][store][state]") {
    auto t = make_test_db();

    t.db.set_state("process", "process_state");
    t.db.set_state("network", "network_state");

    CHECK(t.db.get_state("process") == "process_state");
    CHECK(t.db.get_state("network") == "network_state");
}

// =============================================================================
// Untrusted operator SQL sandbox — read-only handle + authorizer (#760), and
// the validate/execute divergence fix (#631). execute_user_query is called
// directly here so the engine-level controls are exercised independently of the
// validate_and_translate_sql text filter.
// =============================================================================

TEST_CASE("execute_user_query: SELECT on an allowlisted table succeeds",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 7;
    ev.name = "p";
    REQUIRE(t.db.fold_process_events({ev}));

    auto r = t.db.execute_user_query("SELECT COUNT(*) FROM process_hourly");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "1");
}

TEST_CASE("execute_user_query: the DEX per-app canned aggregate shape stays authorizer-compatible",
          "[echo][store][sandbox][procperf][pin]") {
    // The server's /dex per-app panel dispatches this exact SQL shape
    // (dex_routes.cpp dex_procperf_sql(), with $ProcPerf_Hourly translated to
    // procperf_hourly). No other test runs aggregates through the REAL
    // authorizer on this table — an authorizer tightening that drops
    // SUM/MAX/CAST/COUNT/GROUP BY/ORDER BY-alias/LIMIT would otherwise break
    // the panel with no CI signal (governance G3 quality-engineer).
    auto t = make_test_db();
    // Three view rows for Teams.exe: TWO at hour 3600 (a version flip within the hour,
    // the post-v4 (hour,name,version) granularity) and one at hour 7200. So
    // COUNT(*) == 3 but COUNT(DISTINCT hour_ts) == 2 — they diverge, pinning the
    // happy-path "Hours seen" regression fix (COUNT(*) over-counts across a version
    // change; the correct answer is distinct hourly windows).
    // Folded as raw samples (the view's generated averages come from the sums): version 1.0.0.0
    // twice and 2.0.0.0 once in hour 3600, 2.0.0.0 twice in hour 7200.
    const auto sample = [&](int64_t ts, const char* version, int instances, double cpu, int64_t ws) {
        ProcPerfRow row;
        row.ts = ts;
        row.snapshot_id = 1;
        row.name = "Teams.exe";
        row.version = version;
        row.instances = instances;
        row.cpu_pct = cpu;
        row.ws_bytes = ws;
        return row;
    };
    REQUIRE(t.db.fold_proc_perf_samples({sample(3600, "1.0.0.0", 6, 8.0, 2040109465),
                                         sample(3630, "1.0.0.0", 4, 9.0, 1000000000),
                                         sample(3660, "2.0.0.0", 4, 5.0, 1500000000),
                                         sample(7200, "2.0.0.0", 5, 4.0, 1000000000),
                                         sample(7230, "2.0.0.0", 5, 4.0, 1000000000)}));
    auto r = t.db.execute_user_query(
        "SELECT name, SUM(samples) AS samples, MAX(instances_max) AS instances_max, "
        "SUM(cpu_avg*samples)/SUM(samples) AS cpu_avg, MAX(cpu_max) AS cpu_max, "
        "CAST(SUM(ws_avg_bytes*samples)/SUM(samples) AS INTEGER) AS ws_avg, "
        "MAX(ws_max_bytes) AS ws_max, COUNT(DISTINCT hour_ts) AS hours "
        "FROM procperf_hourly WHERE hour_ts >= 0 "
        "GROUP BY name ORDER BY cpu_avg DESC LIMIT 25");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "Teams.exe");
    CHECK(r->rows[0][1] == "5");    // SUM(samples) across all three rows
    CHECK(r->rows[0][7] == "2");    // COUNT(DISTINCT hour_ts) — NOT 3 (COUNT(*) would over-count)
    // Column names ride the schema line the server parser locates fields by.
    REQUIRE(r->columns.size() == 8);
    CHECK(r->columns[0] == "name");
    CHECK(r->columns[3] == "cpu_avg");
    CHECK(r->columns[5] == "ws_avg");
}

TEST_CASE("execute_user_query: UNION across two allowlisted tables is permitted",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    // Both echo_config and echo_state are base tables on the allowlist; Option A
    // preserves the existing read scope rather than restricting to one table.
    auto r =
        t.db.execute_user_query("SELECT key FROM echo_config UNION SELECT collector FROM echo_state");
    CHECK(r.has_value());
}

TEST_CASE("execute_user_query: write statements are denied by the read-only sandbox",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    REQUIRE(t.db.set_config("sandbox_probe", "7"));
    // These bypass validate_and_translate_sql entirely — the read-only handle and
    // authorizer are the layer under test.
    CHECK_FALSE(t.db.execute_user_query("INSERT INTO echo_config VALUES('k','v')").has_value());
    CHECK_FALSE(t.db.execute_user_query("UPDATE echo_config SET value='x'").has_value());
    CHECK_FALSE(t.db.execute_user_query("DELETE FROM echo_config").has_value());
    CHECK_FALSE(t.db.execute_user_query("DROP TABLE echo_config").has_value());
    // The store is untouched.
    CHECK(t.db.get_config("sandbox_probe") == "7");
}

TEST_CASE("execute_user_query: ATTACH / PRAGMA / schema table are denied",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("ATTACH DATABASE 'evil.db' AS e").has_value());
    CHECK_FALSE(t.db.execute_user_query("PRAGMA table_info(echo_config)").has_value());
    CHECK_FALSE(t.db.execute_user_query("SELECT name FROM sqlite_master").has_value());
}

TEST_CASE("execute_user_query: a non-allowlisted table is denied even via UNION",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(
        t.db.execute_user_query("SELECT key FROM echo_config UNION SELECT name FROM sqlite_master")
            .has_value());
}

TEST_CASE("execute_user_query: trailing statement is rejected at prepare",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("SELECT 1; SELECT 2").has_value());
}

// ── validate_and_translate_sql — divergence fix (#631) + existing guards ──────

TEST_CASE("validate_and_translate_sql: $name in code is translated", "[echo][sql][validate]") {
    auto r = validate_and_translate_sql("SELECT * FROM $Process_Hourly");
    REQUIRE(r.has_value());
    CHECK(r->find("process_hourly") != std::string::npos);
    CHECK(r->find("$Process_Hourly") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name inside a string literal is NOT translated (#631)",
          "[echo][sql][validate][security]") {
    // The placeholder is data, not a table reference: it must survive verbatim so
    // the executed query equals the one that was validated.
    auto r = validate_and_translate_sql("SELECT '$Process_Hourly' AS label");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Hourly") != std::string::npos);
    CHECK(r->find("process_hourly") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: unknown $name is rejected", "[echo][sql][validate]") {
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Made_Up").has_value());
}

TEST_CASE("validate_and_translate_sql: a retired $<Source>_Live name is an unknown table",
          "[echo][sql][validate]") {
    // The sixteen raw capture tables are gone, and so are their names: no view stands in for them.
    for (const char* name : {"$Process_Live", "$TCP_Live", "$Registry_Live", "$Perf_Live"}) {
        INFO(name);
        const auto r = validate_and_translate_sql(std::string{"SELECT * FROM "} + name);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == std::string{"unknown table: "} + name);
    }
}

TEST_CASE("validate_and_translate_sql: non-SELECT, multi-statement, oversize rejected",
          "[echo][sql][validate][security]") {
    CHECK_FALSE(validate_and_translate_sql("DELETE FROM $Process_Hourly").has_value());
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Process_Hourly; DROP TABLE echo_config")
                    .has_value());
    CHECK_FALSE(validate_and_translate_sql(std::string(5000, 'A')).has_value());
}

// ── #631 divergence — comment + escaped-quote coverage (governance Gate 3) ──

TEST_CASE("validate_and_translate_sql: $name in a line comment is not translated",
          "[echo][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT 1 -- $Process_Hourly");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Hourly") != std::string::npos);
    CHECK(r->find("process_hourly") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name in a block comment is not translated",
          "[echo][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT /* $Process_Hourly */ 1");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Hourly") != std::string::npos);
    CHECK(r->find("process_hourly") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name beside an escaped quote is not translated",
          "[echo][sql][validate][security]") {
    // '' is an escaped single quote inside the literal; the whole token is a
    // string, so $Process_Hourly within it must survive verbatim.
    auto r = validate_and_translate_sql("SELECT '$Process_Hourly''s data' AS x");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Hourly") != std::string::npos);
    CHECK(r->find("process_hourly") == std::string::npos);
}

TEST_CASE("execute_user_query: pragma_table_info table-valued function is denied",
          "[echo][store][sandbox][security]") {
    auto t = make_test_db();
    // The pragma-as-TVF form reaches the authorizer as SQLITE_READ on a
    // non-allowlisted table name, so it is denied like any other.
    CHECK_FALSE(
        t.db.execute_user_query("SELECT * FROM pragma_table_info('echo_config')").has_value());
}

// =============================================================================
// A2: per-app perf rows + the every-open table-ensure regression
// =============================================================================

TEST_CASE("EchoDatabase: fold_proc_perf_samples batch round-trips", "[echo][store][procperf]") {
    auto t = make_test_db();
    std::vector<ProcPerfRow> rows;
    for (int i = 0; i < 3; ++i) {
        ProcPerfRow r;
        r.ts = 2000 + i;
        r.snapshot_id = 7;
        r.name = "app" + std::to_string(i) + ".exe";
        r.version = "1.2." + std::to_string(i) + ".0";
        r.instances = i + 1;
        r.cpu_pct = 10.0 * (i + 1);
        r.ws_bytes = (100 << 20) * (i + 1);
        r.is_kthread = (i == 1); // one kernel-thread row among ordinary ones
        rows.push_back(std::move(r));
    }
    REQUIRE(t.db.fold_proc_perf_samples(rows));
    REQUIRE(t.db.fold_proc_perf_samples({})); // empty batch is a no-op success

    auto q = t.db.execute_query(
        "SELECT name, version, instances_max, cpu_max, ws_max_bytes, is_kthread FROM procperf_hourly "
        "ORDER BY name");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 3);
    CHECK(q->rows[0][0] == "app0.exe");
    CHECK(q->rows[0][1] == "1.2.0.0"); // version round-trips
    CHECK(q->rows[2][2] == "3");
    CHECK(q->rows[0][5] == "0");
    CHECK(q->rows[1][5] == "1"); // app1.exe's is_kthread round-trips
    CHECK(q->rows[2][5] == "0");
}

TEST_CASE("EchoDatabase: fold_netqual_samples batch round-trips", "[echo][store][netqual]") {
    auto t = make_test_db();
    std::vector<NetQualRow> rows;
    for (int i = 0; i < 3; ++i) {
        NetQualRow r;
        r.ts = 3000 + i;
        r.snapshot_id = 9;
        r.proto = "tcp";
        r.remote_bucket = (i == 0) ? "private" : "public"; // real remote_bucket() classes
        r.process_name = "app" + std::to_string(i);
        r.rtt_us = 1000 * (i + 1);
        r.rtt_var_us = 100 * (i + 1);
        r.lost = i; // row 0 = no current loss, rows 1/2 = current loss
        r.retrans = 5 * i;
        r.segs_out = 1000 * (i + 1);
        r.ca_state = (i == 2) ? 4 : 0; // app2 in TCP_CA_Loss
        rows.push_back(std::move(r));
    }
    REQUIRE(t.db.fold_netqual_samples(rows));
    REQUIRE(t.db.fold_netqual_samples({})); // empty batch is a no-op success

    // The tier keeps (proto, destination class, process) per hour: sums, maxima, and the number of
    // samples that saw current loss. Lifetime counters (retrans, segs_out) and ca_state are not
    // kept.
    auto q = t.db.execute_query(
        "SELECT proto, remote_bucket, process_name, rtt_us_sum, lost_sum, lost_max, "
        "degraded_samples FROM netqual_hourly ORDER BY process_name");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 3);
    CHECK(q->rows[0][1] == "private");  // app0 destination class
    CHECK(q->rows[0][4] == "0");        // app0 current loss
    CHECK(q->rows[0][6] == "0");        // app0 not degraded
    CHECK(q->rows[2][1] == "public");   // app2 destination class
    CHECK(q->rows[2][4] == "2");        // app2 current loss
    CHECK(q->rows[2][5] == "2");
    CHECK(q->rows[2][6] == "1");        // app2 degraded

    // The degraded-as-query shape (a later server slice): fraction of a window's samples with
    // CURRENT loss. Pin it here so the column semantics stay query-able from the hourly tier.
    auto frac = t.db.execute_query("SELECT SUM(degraded_samples), SUM(samples) FROM netqual_hourly");
    REQUIRE(frac.has_value());
    REQUIRE(frac->rows.size() == 1);
    CHECK(frac->rows[0][0] == "2"); // 2 of 3 samples currently losing
    CHECK(frac->rows[0][1] == "3");
}

TEST_CASE("netqual: remote_bucket classifies destinations into privacy-safe classes",
          "[echo][netqual][privacy]") {
    using yuzu::echo::remote_bucket;
    // Loopback.
    CHECK(remote_bucket("127.0.0.1") == "loopback");
    CHECK(remote_bucket("127.5.6.7") == "loopback");
    CHECK(remote_bucket("::1") == "loopback");
    // RFC1918 + link-local => private.
    CHECK(remote_bucket("10.0.0.5") == "private");
    CHECK(remote_bucket("192.168.1.20") == "private");
    CHECK(remote_bucket("169.254.10.10") == "private");
    CHECK(remote_bucket("172.16.0.1") == "private");
    CHECK(remote_bucket("172.31.255.254") == "private");
    CHECK(remote_bucket("fe80::1") == "private"); // link-local v6
    CHECK(remote_bucket("fd00::abcd") == "private"); // unique-local v6
    // 172.32 is OUT of the private /12 — public.
    CHECK(remote_bucket("172.32.0.1") == "public");
    CHECK(remote_bucket("172.15.0.1") == "public");
    CHECK(remote_bucket("8.8.8.8") == "public");
    CHECK(remote_bucket("2001:4860:4860::8888") == "public");
    // CGNAT 100.64.0.0/10 (RFC6598 shared space) => private; just-outside => public.
    CHECK(remote_bucket("100.64.0.1") == "private");
    CHECK(remote_bucket("100.127.255.254") == "private");
    CHECK(remote_bucket("100.63.255.1") == "public");
    CHECK(remote_bucket("100.128.0.1") == "public");
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) classified by the embedded v4.
    CHECK(remote_bucket("::ffff:10.0.0.5") == "private");
    CHECK(remote_bucket("::ffff:127.0.0.1") == "loopback");
    CHECK(remote_bucket("::ffff:8.8.8.8") == "public");
    // Unknown / wildcard.
    CHECK(remote_bucket("") == "unknown");
    CHECK(remote_bucket("*") == "unknown");
}

TEST_CASE("netqual: select_netqual_rows drops the raw address and keeps degraded-first under cap",
          "[echo][netqual][privacy]") {
    using yuzu::echo::NetQualRow;
    using yuzu::echo::select_netqual_rows;
    using yuzu::echo::TcpQualitySample;

    std::vector<TcpQualitySample> samples;
    // Idle, very active, public destination — would dominate a by-activity cap.
    samples.push_back({"tcp", "8.8.8.8", "chrome", 5000, 100, 0, 0, 100000});
    // Losing connection, low activity, private destination — must be KEPT.
    samples.push_back({"tcp", "10.0.0.9", "vpnclient", 20000, 500, 7, 30, 200});
    // Idle, low activity — the one that should be dropped under cap=2.
    samples.push_back({"tcp", "192.168.1.5", "ssh", 8000, 200, 0, 0, 50});

    auto rows = select_netqual_rows(samples, /*ts=*/111, /*snapshot_id=*/222, /*cap=*/2);
    REQUIRE(rows.size() == 2);

    // Degraded-first: the losing connection ranks ahead of the idle high-activity one.
    CHECK(rows[0].process_name == "vpnclient");
    CHECK(rows[0].lost == 7);
    CHECK(rows[0].remote_bucket == "private");
    CHECK(rows[1].process_name == "chrome");
    CHECK(rows[1].lost == 0);
    CHECK(rows[1].remote_bucket == "public");

    // Privacy: NO row carries a raw address — only the coarse bucket. NetQualRow
    // has no remote_addr field at all, so this is structural; assert the bucket
    // is one of the known classes and never an IP literal.
    for (const auto& r : rows) {
        CHECK((r.remote_bucket == "loopback" || r.remote_bucket == "private" ||
               r.remote_bucket == "public" || r.remote_bucket == "unknown"));
        CHECK(r.remote_bucket.find('.') == std::string::npos);
        CHECK(r.ts == 111);
        CHECK(r.snapshot_id == 222);
    }
}

TEST_CASE("netqual: select_netqual_rows with cap=0 keeps everything", "[echo][netqual]") {
    using yuzu::echo::select_netqual_rows;
    using yuzu::echo::TcpQualitySample;
    std::vector<TcpQualitySample> samples(5);
    for (auto& s : samples) {
        s.proto = "tcp";
        s.remote_addr = "8.8.8.8";
    }
    auto rows = select_netqual_rows(samples, 1, 1, /*cap=*/0);
    CHECK(rows.size() == 5);
}

TEST_CASE("netqual: collect_netqual_boot off-Windows no-op contract", "[echo][netqual]") {
    // The platform collector itself is NOT driven from a unit test — it reads
    // live OS counters and belongs to the harness/UAT, matching how the ETW /
    // ARP / DNS collectors are treated (docs/echo-implementer.md,
    // test_echo_proc_etw.cpp). Here we pin only the cross-platform contract: off
    // Windows the collector is a clean nullopt no-op. The row's warehouse
    // persistence is covered cross-platform by the insert_netqual_boot_row
    // round-trip test above (hand-built row); the Windows since-boot read is a
    // UAT concern.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
#ifndef _WIN32
    CHECK_FALSE(yuzu::echo::collect_netqual_boot(now).has_value());
#else
    (void)now; // Windows since-boot read is exercised by UAT, not here
#endif
}

TEST_CASE("EchoDatabase: insert_netqual_boot_row round-trips every column",
          "[echo][store][netqual]") {
    // Cross-platform (qe-S2): construct the row directly rather than via the
    // Windows-only collector, so all 13 bindings are exercised on every host.
    auto t = make_test_db();
    NetQualBootRow r;
    r.ts = 1710000000;
    r.snapshot_id = 55;
    r.boot_ts = 1709990000;
    r.window_s = 10000;
    r.retrans_segs = 42;
    r.segs_out = 987654;
    r.estab_resets = 3;
    r.if_in_errors = 5;
    r.if_in_discards = 7;
    r.if_out_errors = 11;
    r.if_out_discards = 13;
    r.if_in_octets = 111222333;
    r.if_out_octets = 444555666;
    REQUIRE(t.db.insert_netqual_boot_row(r));

    auto res = t.db.execute_query(
        "SELECT ts, snapshot_id, boot_ts, window_s, retrans_segs, segs_out, estab_resets, "
        "if_in_errors, if_in_discards, if_out_errors, if_out_discards, if_in_octets, "
        "if_out_octets FROM netqual_boot");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    const auto& row = res->rows[0];
    CHECK(row[0] == "1710000000");
    CHECK(row[1] == "55");
    CHECK(row[2] == "1709990000");
    CHECK(row[3] == "10000");
    CHECK(row[4] == "42");
    CHECK(row[5] == "987654");
    CHECK(row[6] == "3");
    CHECK(row[7] == "5");
    CHECK(row[8] == "7");
    CHECK(row[9] == "11");
    CHECK(row[10] == "13");
    CHECK(row[11] == "111222333");
    CHECK(row[12] == "444555666");
}

TEST_CASE("EchoDatabase: insert_netqual_boot_row returns false (no crash) when the table is gone",
          "[echo][store][netqual]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netqual_boot").has_value());
    NetQualBootRow r;
    r.ts = 1;
    CHECK_FALSE(t.db.insert_netqual_boot_row(r));
    REQUIRE(t.db.execute_query("SELECT 1").has_value()); // connection not wedged
}

TEST_CASE("EchoDatabase: fold_netconn_events round-trips every column + empty no-op",
          "[echo][store][netconn]") {
    // qe-S1: the netconn insert had zero coverage. Exercise every binding and
    // the empty-batch success, cross-platform (the row struct is platform-free).
    auto t = make_test_db();
    CHECK(t.db.fold_netconn_events({})); // empty batch is a no-op success

    std::vector<NetConnRow> rows;
    NetConnRow a;
    a.ts = 1710000100;
    a.snapshot_id = 9;
    a.action = "wifi_disconnected";
    a.channel = "wlan";
    a.category = "";
    a.capability = "";
    a.iface_kind = "wifi";
    a.reason_code = 229377;
    rows.push_back(a);
    NetConnRow b;
    b.ts = 1710000200;
    b.snapshot_id = 9;
    b.action = "capability_changed";
    b.channel = "ncsi";
    b.category = "";
    b.capability = "internet";
    b.iface_kind = "";
    b.reason_code = 4;
    rows.push_back(b);
    REQUIRE(t.db.fold_netconn_events(rows));

    auto res = t.db.execute_query(
        "SELECT action, channel, category, capability, iface_kind, reason_code, event_count, last_ts "
        "FROM netconn_hourly ORDER BY last_ts");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 2);
    CHECK(res->rows[0][0] == "wifi_disconnected");
    CHECK(res->rows[0][1] == "wlan");
    CHECK(res->rows[0][4] == "wifi");
    CHECK(res->rows[0][5] == "229377");
    CHECK(res->rows[0][6] == "1");
    CHECK(res->rows[0][7] == "1710000100");
    CHECK(res->rows[1][0] == "capability_changed");
    CHECK(res->rows[1][3] == "internet");
    CHECK(res->rows[1][5] == "4");
}

TEST_CASE("EchoDatabase: fold_netconn_events returns false (no crash) when the table is gone",
          "[echo][store][netconn]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netconn_hourly_r").has_value());
    NetConnRow r;
    r.ts = 1;
    r.action = "connected";
    r.channel = "networkprofile";
    CHECK_FALSE(t.db.fold_netconn_events({r}));
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("netqual: nq_v6_key includes scope IDs so same-text/different-scope rows are distinct",
          "[echo][netqual]") {
    using yuzu::echo::nq_v4_key;
    using yuzu::echo::nq_v6_key;

    // Two link-local connections with IDENTICAL textual address + port but
    // different zone (scope) IDs must NOT collide in g_nq_tracked — otherwise
    // one connection's RTT/retransmit deltas are attributed to the other.
    const auto a = nq_v6_key("fe80::1", 11, 5000, "fe80::2", 11, 443);
    const auto b = nq_v6_key("fe80::1", 22, 5000, "fe80::2", 22, 443); // same text, diff scope
    CHECK(a != b);

    // Identical everything (incl. scope) yields the SAME key (stable tracking).
    CHECK(nq_v6_key("fe80::1", 11, 5000, "fe80::2", 11, 443) == a);

    // The scope is embedded, not merely appended out of band.
    CHECK(a == "tcp6|fe80::1%11:5000|fe80::2%11:443");

    // v4 has no scope dimension; the key is proto|laddr:lport|raddr:rport.
    CHECK(nq_v4_key("10.0.0.1", 5000, "8.8.8.8", 443) == "tcp|10.0.0.1:5000|8.8.8.8:443");
    // v4 and v6 keys never collide (distinct proto prefixes).
    CHECK(nq_v4_key("10.0.0.1", 1, "10.0.0.2", 2) != nq_v6_key("10.0.0.1", 0, 1, "10.0.0.2", 0, 2));
}

TEST_CASE("netqual: nq_win_ca_state severity precedence", "[echo][netqual]") {
    using yuzu::echo::NqPathDeltas;
    using yuzu::echo::nq_win_ca_state;

    CHECK(nq_win_ca_state({}) == 0); // no signals => Open

    // Each signal alone maps to its state.
    CHECK(nq_win_ca_state({.dup_acks_in = 3}) == 1);                      // Disorder
    CHECK(nq_win_ca_state({.ecn_signals = 1}) == 2);                      // CWR
    CHECK(nq_win_ca_state({.pkts_retrans = 2}) == 3);                     // Recovery
    CHECK(nq_win_ca_state({.fast_retran = 1}) == 3);                      // Recovery
    CHECK(nq_win_ca_state({.timeouts = 1}) == 4);                         // Loss (RTO fired)
    CHECK(nq_win_ca_state({.cur_timeout_count = 1}) == 4);                // Loss (RTO in progress)

    // Precedence: the most severe signal wins when several fire in one tick.
    CHECK(nq_win_ca_state({.timeouts = 1, .fast_retran = 5, .pkts_retrans = 9,
                           .dup_acks_in = 20, .ecn_signals = 2}) == 4);
    CHECK(nq_win_ca_state({.fast_retran = 1, .dup_acks_in = 20, .ecn_signals = 2}) == 3);
    CHECK(nq_win_ca_state({.dup_acks_in = 20, .ecn_signals = 2}) == 2);
}

TEST_CASE("netqual: nq_win_build_sample scales ms->us, deltas lost, clamps wrap",
          "[echo][netqual]") {
    using yuzu::echo::NqWinCounters;
    using yuzu::echo::nq_win_build_sample;

    NqWinCounters prev;
    prev.pkts_retrans = 10;
    prev.timeouts = 1;
    prev.segs_out = 1000;

    NqWinCounters cur;
    cur.smoothed_rtt_ms = 42;
    cur.rtt_var_ms = 7;
    cur.pkts_retrans = 14; // +4 this tick
    cur.timeouts = 1;      // unchanged
    cur.segs_out = 5000;

    auto s = nq_win_build_sample(cur, prev, "tcp", "203.0.113.9", "edge");
    CHECK(s.proto == "tcp");
    CHECK(s.remote_addr == "203.0.113.9"); // raw here — select_netqual_rows buckets it away
    CHECK(s.process_name == "edge");
    CHECK(s.rtt_us == 42000); // ESTATS ms -> schema µs
    CHECK(s.rtt_var_us == 7000);
    CHECK(s.lost == 4);       // delta, not cumulative
    CHECK(s.retrans == 14);   // cumulative since stats-enable — context
    CHECK(s.segs_out == 5000);
    CHECK(s.ca_state == 3);   // retrans activity, no new/live RTO => Recovery

    // Counter reset/wrap (another ESTATS consumer toggled collection): negative
    // deltas clamp to 0 — "unknown this tick", never a bogus loss spike.
    NqWinCounters reset; // all-zero cur vs non-zero prev
    auto z = nq_win_build_sample(reset, cur, "tcp6", "2001:db8::1", "svc");
    CHECK(z.lost == 0);
    CHECK(z.ca_state == 0);

    // A live RTO episode (cur_timeout_count gauge) forces Loss even with no
    // completed-timeout delta.
    NqWinCounters rto = cur;
    rto.cur_timeout_count = 2;
    CHECK(nq_win_build_sample(rto, cur, "tcp", "198.51.100.2", "db").ca_state == 4);
}

TEST_CASE("EchoDatabase: fold_netqual_samples returns false (no crash) when the table is gone",
          "[echo][store][netqual]") {
    // Mirrors the procperf prepare-fail ROLLBACK path: drop the netqual tier out from under an
    // open EchoDatabase, then fold — prepare fails, the function must ROLLBACK and return false
    // without wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netqual_hourly_r").has_value());
    NetQualRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.proto = "tcp";
    r.process_name = "x";
    CHECK_FALSE(t.db.fold_netqual_samples({r}));
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("EchoDatabase: fold_proc_perf_samples returns false (no crash) when the table is gone",
          "[echo][store][procperf]") {
    // The prepare-fail ROLLBACK path (gov QE S1): drop the procperf tier out from under an open
    // EchoDatabase via the trusted exec path, then fold -- sqlite3_prepare_v2 fails, the function
    // must ROLLBACK and return false without throwing or wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE procperf_hourly_r").has_value());
    ProcPerfRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.name = "x.exe";
    r.instances = 1;
    CHECK_FALSE(t.db.fold_proc_perf_samples({r}));
    // The connection is still usable afterwards (no wedged transaction).
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("EchoDatabase: missing warehouse tables are re-created on reopen (upgrade path)",
          "[echo][store][lifecycle]") {
    // The A1 regression this pins: create_warehouse_tables used to run only at
    // schema_version<2, so a table added by a NEWER release never materialised on an upgraded
    // fleet's existing echo.db -- inserts then failed every 30 s. The fix runs the idempotent
    // IF-NOT-EXISTS DDL on EVERY open. (After v10 that DDL covers the tables the roll-up does not
    // own: netqual_boot and the usage tables.) Simulate the upgrade by dropping one from a closed
    // DB, then reopening.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_upg_");
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
    } // closed

    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE netqual_boot", nullptr, nullptr, nullptr) ==
                SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = EchoDatabase::open(tmp); // must re-create the dropped table
        REQUIRE(db.has_value());
        NetQualBootRow r;
        r.ts = 1;
        r.boot_ts = 1;
        REQUIRE(db->insert_netqual_boot_row(r));
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: a fresh open creates no tar_events table (#760 UP-8)",
          "[echo][store][lifecycle][echo-events]") {
    // is_queryable_table() excludes tar_events specifically so that its "no such
    // table" error cannot become an existence oracle distinct from the generic
    // authorizer denial. That reasoning only holds while the table is genuinely
    // absent, so pin it: kCreateSchema must never create it again. It used to,
    // and the v3 migration dropped it a few statements later — which left it
    // PRESENT on any database already at schema_version>=3, since that branch is
    // then skipped.
    const char* count_sql = "SELECT COUNT(*) FROM sqlite_master WHERE name = 'tar_events' OR name "
                            "LIKE 'idx_tar_events%'";
    auto t = make_test_db();
    auto q = t.db.execute_query(count_sql);
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 1);
    CHECK(q->rows[0][0] == "0");

    // The case that actually bit: a REOPEN. kCreateSchema runs on every open,
    // but the v3 DROP is gated on schema_version()==2 — so once a database has
    // reached v3+, re-running the create resurrected the table with nothing left
    // to remove it. Every agent restart did this.
    { EchoDatabase discard = std::move(t.db); }
    auto reopened = EchoDatabase::open(t.path);
    REQUIRE(reopened.has_value());
    CHECK(reopened->schema_version() == 10);
    auto q2 = reopened->execute_query(count_sql);
    REQUIRE(q2.has_value());
    CHECK(q2->rows[0][0] == "0");
    t.db = std::move(*reopened); // hand back so TestEchoDb's destructor cleans up
}

TEST_CASE("EchoDatabase: a pre-v3 database still has tar_events dropped on open",
          "[echo][store][lifecycle][echo-events]") {
    // The other half of the same invariant: field databases created before v3
    // DO carry the table, and the migration must still retire it. Seed the exact
    // pre-v3 shape by hand (same technique as the v4 ALTER test below).
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v2_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE echo_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO echo_config (key, value) VALUES ('schema_version', '2');
            CREATE TABLE tar_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL, event_action TEXT NOT NULL,
                detail_json TEXT NOT NULL DEFAULT '{}', snapshot_id INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX idx_tar_events_ts ON tar_events(timestamp);
            INSERT INTO tar_events (timestamp, event_type, event_action)
                VALUES (1000, 'process', 'started');
        )";
        REQUIRE(sqlite3_exec(raw, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10); // the 2→3→4→5→6→7→8→9→10 walk ran
        auto q =
            db->execute_query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'tar_events' OR "
                              "name LIKE 'idx_tar_events%'");
        REQUIRE(q.has_value());
        CHECK(q->rows[0][0] == "0");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: schema v5 drops tar_events from an ALREADY-MIGRATED database",
          "[echo][store][lifecycle][echo-events]") {
    // The installed-base case, and the reason removing the DDL is not enough on
    // its own. Every agent in the field reached v3/v4 while kCreateSchema was
    // still recreating tar_events on each open, so those databases carry it
    // NOW. The v3 drop is gated on schema_version()==2 and will never fire for
    // them again — only the v5 bump reaches them. Without it a fresh install and
    // an upgraded endpoint would hold permanently divergent schemas.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v5_");
    {
        // A v4 database that already carries the resurrected table, exactly as a
        // pre-fix binary would have left it.
        auto seeded = EchoDatabase::open(tmp);
        REQUIRE(seeded.has_value());
        REQUIRE(seeded
                    ->execute_query("CREATE TABLE tar_events (id INTEGER PRIMARY KEY "
                                    "AUTOINCREMENT, timestamp INTEGER NOT NULL)")
                    .has_value());
        REQUIRE(seeded->execute_query("CREATE INDEX idx_tar_events_ts ON tar_events(timestamp)")
                    .has_value());
        REQUIRE(seeded->set_config("schema_version", "4"));
    }

    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        auto q = db->execute_query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'tar_events' "
                                   "OR name LIKE 'idx_tar_events%'");
        REQUIRE(q.has_value());
        CHECK(q->rows[0][0] == "0");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: create_warehouse_tables joins a transaction the caller already holds",
          "[echo][store][lifecycle][ddl-batch]") {
    // exec_ddl_batch wraps the DDL in its own transaction for cost and
    // atomicity, but create_warehouse_tables() is public and a caller may
    // already hold one. It must then run the batch unwrapped and JOIN that
    // transaction rather than failing or nesting, and must leave the
    // connection's autocommit state undisturbed either way.
    auto t = make_test_db();
    auto boot_tables = [&] {
        auto r = t.db.execute_query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='netqual_boot'");
        REQUIRE(r.has_value());
        return r->rows[0][0];
    };

    // Drop a table so the nested call has real work to do, then roll the
    // CALLER's transaction back. Had create_warehouse_tables opened and
    // committed a transaction of its own, the re-created table would SURVIVE
    // that rollback; joining the caller's transaction means it must not. This is
    // what makes the test discriminating rather than merely green.
    REQUIRE(t.db.execute_query("DROP TABLE netqual_boot").has_value());
    REQUIRE(boot_tables() == "0");

    REQUIRE(t.db.execute_sql("BEGIN IMMEDIATE"));
    CHECK(t.db.create_warehouse_tables());
    CHECK(boot_tables() == "1"); // recreated inside the caller's txn
    REQUIRE(t.db.execute_sql("ROLLBACK"));
    CHECK(boot_tables() == "0"); // ...and discarded with it

    // The ordinary un-nested path commits on its own and leaves a usable handle.
    CHECK(t.db.create_warehouse_tables());
    CHECK(boot_tables() == "1");
    auto q = t.db.execute_query("SELECT COUNT(*) FROM netqual_boot");
    REQUIRE(q.has_value());
}

TEST_CASE("EchoDatabase: a v3 database with pre-version procperf tables upgrades to the roll-up tiers",
          "[echo][store][lifecycle][procperf]") {
    // The deployment-critical path the fresh-DB tests never exercise: an UPGRADING agent already
    // has procperf_live/_hourly WITHOUT `version` at schema_version=3. The ladder's v4 and v7
    // ALTERs add the columns, then the v10 migration moves the rows (raw and summarised) into the
    // roll-up tiers. Seed that exact pre-v4 shape by hand with a raw row and a summary row.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v4_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE echo_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO echo_config (key, value) VALUES ('schema_version', '3');
            CREATE TABLE procperf_live (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER, snapshot_id INTEGER, name TEXT,
                instances INTEGER, cpu_pct REAL, ws_bytes INTEGER);
            CREATE TABLE procperf_hourly (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_ts INTEGER, name TEXT, samples INTEGER, instances_max INTEGER,
                cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER, ws_max_bytes INTEGER);
            INSERT INTO procperf_live (ts, snapshot_id, name, instances, cpu_pct, ws_bytes)
                VALUES (7300, 1, 'chrome.exe', 2, 5.0, 100);
            INSERT INTO procperf_hourly (hour_ts, name, samples, instances_max, cpu_avg, cpu_max,
                                         ws_avg_bytes, ws_max_bytes)
                VALUES (3600, 'old.exe', 2, 1, 1.5, 2.0, 50, 60);
            INSERT INTO echo_config (key, value) VALUES ('rollup_procperf_hourly_at', '7200');
        )";
        REQUIRE(sqlite3_exec(raw, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10); // the v3→...→v9→v10 walk ran

        // The summary row survived the move, a retired average back as a sum (1.5 * 2 samples),
        // and the raw row became an hourly bucket (no version column before v4: empty version).
        auto old_row = db->execute_query(
            "SELECT version, samples, instances_max, cpu_avg, ws_avg_bytes FROM procperf_hourly "
            "WHERE name = 'old.exe'");
        REQUIRE(old_row.has_value());
        REQUIRE(old_row->rows.size() == 1);
        CHECK(old_row->rows[0] == QueryRow{"", "2", "1", "1.5", "50"});
        auto raw_row = db->execute_query(
            "SELECT hour_ts, instances_max, ws_max_bytes FROM procperf_hourly WHERE name = 'chrome.exe'");
        REQUIRE(raw_row.has_value());
        REQUIRE(raw_row->rows.size() == 1);
        CHECK(raw_row->rows[0] == QueryRow{"7200", "2", "100"});

        // And a fold carrying a version round-trips through the migrated tier.
        ProcPerfRow r;
        r.ts = 11;
        r.snapshot_id = 1;
        r.name = "chrome.exe";
        r.version = "124.0.6367.91";
        r.instances = 2;
        REQUIRE(db->fold_proc_perf_samples({r}));
        auto q = db->execute_query(
            "SELECT version FROM procperf_hourly WHERE name = 'chrome.exe' AND hour_ts = 0");
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        CHECK(q->rows[0][0] == "124.0.6367.91");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: a v6 database with is_kthread-less procperf tables upgrades "
          "(the v7 step)",
          "[echo][store][lifecycle][procperf]") {
    // Isolates the v7 step specifically: seed the exact POST-v6 shape (both tiers already carry
    // `version`; schema_version=6) so only the v7 ALTER runs before the v10 migration moves the
    // rows. A kernel-thread marker written after the upgrade keeps its own row.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v7_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE echo_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO echo_config (key, value) VALUES ('schema_version', '6');
            CREATE TABLE procperf_live (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER, snapshot_id INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '',
                instances INTEGER, cpu_pct REAL, ws_bytes INTEGER);
            CREATE TABLE procperf_hourly (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_ts INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '', samples INTEGER,
                instances_max INTEGER, cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER,
                ws_max_bytes INTEGER);
            INSERT INTO procperf_live (ts, snapshot_id, name, version, instances, cpu_pct, ws_bytes)
                VALUES (7300, 1, 'app.exe', '2.0', 1, 3.0, 10);
        )";
        REQUIRE(sqlite3_exec(raw, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10); // the v6→v7→...→v10 walk ran

        // The pre-v7 raw row is migrated as an ordinary (non-kernel-thread) app.
        auto old_row = db->execute_query(
            "SELECT version, is_kthread FROM procperf_hourly WHERE name = 'app.exe'");
        REQUIRE(old_row.has_value());
        REQUIRE(old_row->rows.size() == 1);
        CHECK(old_row->rows[0] == QueryRow{"2.0", "0"});

        // A fold carrying is_kthread=true round-trips (stored as SQLite's INTEGER 0/1).
        ProcPerfRow r;
        r.ts = 21;
        r.snapshot_id = 1;
        r.name = "kworker/0:1";
        r.instances = 1;
        r.is_kthread = true;
        REQUIRE(db->fold_proc_perf_samples({r}));
        auto q = db->execute_query("SELECT is_kthread FROM procperf_hourly WHERE name = 'kworker/0:1'");
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        CHECK(q->rows[0][0] == "1");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: insert and query arp events (ADR-0015)", "[echo][store][crud][arp]") {
    auto t = make_test_db();
    ArpEvent ev;
    ev.ts = 3000;
    ev.snapshot_id = 1;
    ev.action = "appeared";
    ev.iface = "Ethernet"; // bound to the SQL column 'interface'
    ev.ip_address = "192.168.1.1";
    ev.mac_address = "aa:bb:cc:dd:ee:ff";
    ev.entry_type = "dynamic";
    REQUIRE(t.db.fold_arp_events({ev}));
    CHECK(t.db.fold_arp_events({})); // empty input is a no-op success

    auto r = t.db.execute_query(
        "SELECT interface, ip_address, mac_address, appear_count, remove_count FROM arp_hourly");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "Ethernet");
    CHECK(r->rows[0][1] == "192.168.1.1");
    CHECK(r->rows[0][2] == "aa:bb:cc:dd:ee:ff");
    CHECK(r->rows[0][3] == "1"); // appeared
    CHECK(r->rows[0][4] == "0");
}

TEST_CASE("EchoDatabase: insert and query dns events (ADR-0015)", "[echo][store][crud][dns]") {
    auto t = make_test_db();
    DnsEvent ev;
    ev.ts = 3100;
    ev.snapshot_id = 1;
    ev.action = "appeared";
    ev.name = "example.com";
    ev.record_type = "A";
    ev.data = "93.184.216.34";
    ev.ttl_remaining_s = 60;
    ev.source = "cache";
    REQUIRE(t.db.fold_dns_events({ev}));
    CHECK(t.db.fold_dns_events({})); // empty input is a no-op success

    auto r = t.db.execute_query(
        "SELECT name, record_type, data, appear_count, remove_count FROM dns_hourly");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "example.com");
    CHECK(r->rows[0][1] == "A");
    CHECK(r->rows[0][2] == "93.184.216.34");
    CHECK(r->rows[0][3] == "1");
    CHECK(r->rows[0][4] == "0");
}

// ── #559: corrupt-DB quarantine on open ────────────────────────────────────

TEST_CASE("EchoDatabase: a corrupt echo.db is quarantined and re-initialised fresh (#559)",
          "[echo][store][lifecycle][corruption]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_corrupt_");

    // 1. Create a real DB and persist a deliberately-paused source. This is the
    //    forensic-preservation state a corrupt read must NOT silently undo.
    {
        auto opened = EchoDatabase::open(tmp);
        REQUIRE(opened.has_value());
        EchoDatabase db = std::move(*opened);
        REQUIRE(db.create_warehouse_tables());
        db.set_config("process_enabled", "false");
        CHECK(db.get_config("process_enabled", "true") == "false");
    } // connection closed; WAL checkpointed into the main file on close

    // 2. Corrupt it: leave EMPTY WAL/SHM sidecars beside it (the Windows open() pre-creates
    //    them that way) and clobber the whole file with non-SQLite bytes so PRAGMA
    //    integrity_check fails deterministically.
    for (const char* suffix : {"-wal", "-shm"})
        REQUIRE(std::ofstream(fs::path{tmp.string() + suffix}, std::ios::binary | std::ios::trunc)
                    .is_open());
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database -- corrupt echo.db for #559";
    }
#ifndef _WIN32
    // Seed the corrupt file group/other-readable (the first open left it 0600 and the truncating
    // rewrite kept that), so the quarantined copy's mode below proves the quarantine re-secured it.
    {
        std::error_code pec;
        fs::permissions(tmp, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                        fs::perm_options::replace, pec);
        REQUIRE_FALSE(pec);
    }
#endif

    // 3. Re-open: must succeed with a FRESH database (not refuse, not trust the
    //    garbage), and quarantine the corrupt file aside for forensic review.
    auto reopened = EchoDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    EchoDatabase db2 = std::move(*reopened);
    REQUIRE(db2.create_warehouse_tables());

    // Fresh DB → the paused config is gone; the default "true" comes from a
    // CLEAN database, not a silent read-failure default over corrupt bytes.
    CHECK(db2.get_config("process_enabled", "true") == "true");

    // Exactly one timestamped quarantine file exists next to the original path: the sidecars
    // were seeded empty (as the Windows open() pre-creates them) and an empty sidecar holds no
    // evidence, so it is dropped, not kept as a forensic artifact of its own.
    int quarantine_files = 0;
    const std::string prefix = tmp.filename().string() + ".corrupt-";
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            ++quarantine_files;
#ifndef _WIN32
            // The quarantined evidence ends owner-only (0600): it was seeded 0644 above.
            CHECK((fs::status(entry.path()).permissions() & fs::perms::mask) ==
                  (fs::perms::owner_read | fs::perms::owner_write));
#endif
            std::error_code ec;
            fs::remove(entry.path(), ec); // tidy up the quarantine artifact
        }
    }
    CHECK(quarantine_files == 1);

    // #1567: this open knows it quarantined, and the fact is persisted (epoch +
    // basename only) so it survives a restart and can be published fleet-wide.
    REQUIRE(db2.quarantined_this_open().has_value());
    const auto q_epoch = db2.get_config("db_health_last_quarantine_epoch", "");
    CHECK_FALSE(q_epoch.empty());
    CHECK(q_epoch.find_first_not_of("0123456789") == std::string::npos);
    CHECK(q_epoch == std::to_string(*db2.quarantined_this_open()));
    const auto q_file = db2.get_config("db_health_last_quarantine_file", "");
    CHECK(q_file.rfind(tmp.filename().string() + ".corrupt-", 0) == 0);
    // One clock read names the file and is persisted: the epoch in the name is the stored one.
    CHECK(q_file == tmp.filename().string() + ".corrupt-" + q_epoch);
    CHECK(q_file.find_first_of("/\\") == std::string::npos);

    // A clean re-open of the same path reports no quarantine, but both config
    // rows persist (echo_config is the durable source of truth).
    { EchoDatabase discard = std::move(db2); }
    auto clean = EchoDatabase::open(tmp);
    REQUIRE(clean.has_value());
    CHECK_FALSE(clean->quarantined_this_open().has_value());
    CHECK(clean->get_config("db_health_last_quarantine_epoch", "") == q_epoch);
    CHECK(clean->get_config("db_health_last_quarantine_file", "") == q_file);
    { EchoDatabase discard = std::move(*clean); }
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(tmp.filename().string() + ".corrupt-", 0) == 0) {
            std::error_code ec;
            fs::remove(entry.path(), ec);
        }
    }
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
        std::error_code ec;
        fs::remove(fs::path{tmp.string() + suffix}, ec);
    }
}

TEST_CASE("EchoDatabase: a second corruption never overwrites the first quarantine (#559 collision-safe)",
          "[echo][store][lifecycle][corruption]") {
    // Quarantine names are 1-second granular; two corruptions in the same wall
    // second (or after a backward clock step) must NOT rename over each other —
    // that would shred preserved forensic evidence. Drive two corrupt-open
    // cycles back-to-back (same second) and assert TWO distinct `.corrupt-*`
    // files survive.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_collide_");
    const std::string prefix = tmp.filename().string() + ".corrupt-";

    auto corrupt_then_open = [&]() {
        for (const char* suffix : {"-wal", "-shm"}) {
            std::error_code ec;
            fs::remove(fs::path{tmp.string() + suffix}, ec);
        }
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            REQUIRE(f.is_open());
            f << "corrupt echo.db -- collision test #559";
        }
        auto reopened = EchoDatabase::open(tmp);
        REQUIRE(reopened.has_value()); // quarantined + fresh DB each time
    };

    corrupt_then_open();
    corrupt_then_open(); // same wall-second as the first → must not clobber it

    int quarantine_count = 0;
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            ++quarantine_count;
            std::error_code ec;
            fs::remove(entry.path(), ec);
        }
    }
    CHECK(quarantine_count >= 2); // both quarantines preserved, neither overwritten
    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

TEST_CASE("EchoDatabase: a valid DB opens cleanly with no quarantine and preserves data (#559)",
          "[echo][store][lifecycle][corruption]") {
    // The happy path: check_integrity answers ok, so a previously-written DB is
    // re-opened in place with its data intact and NO `.corrupt-*` sidecar minted
    // (guards against an integrity check that wrongly fails every open).
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_valid_");
    {
        auto opened = EchoDatabase::open(tmp);
        REQUIRE(opened.has_value());
        EchoDatabase db = std::move(*opened);
        db.set_config("process_enabled", "false");
    }
    auto reopened = EchoDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    EchoDatabase db = std::move(*reopened);
    // Data survived — NOT reset to the default.
    CHECK(db.get_config("process_enabled", "true") == "false");
    // No quarantine sidecar was created for a healthy DB.
    const std::string prefix = tmp.filename().string() + ".corrupt-";
    for (const auto& entry : fs::directory_iterator(tmp.parent_path()))
        CHECK(entry.path().filename().string().rfind(prefix, 0) != 0);
    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec);
}

namespace {

std::vector<unsigned char> read_bytes(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
                                      std::istreambuf_iterator<char>());
}

void put_be32(std::vector<unsigned char>& out, std::uint32_t x) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>(x >> shift));
}

// Writes the rollback journal that, replayed onto `victim`, restores `evil`'s version of every
// page that differs (sqlite.org/fileformat.html, "The Rollback Journal"). It is HOT: a valid
// header with a non-zero first byte, and no lock held on the database it sits beside.
void write_hot_journal(const fs::path& victim, const fs::path& evil, const fs::path& journal) {
    const auto v = read_bytes(victim);
    const auto e = read_bytes(evil);
    REQUIRE(v.size() > 100);
    std::size_t page = (std::size_t{v[16]} << 8) | v[17]; // big-endian page size at offset 16
    if (page == 1)
        page = 65536;
    REQUIRE(e.size() >= page);
    REQUIRE(e.size() % page == 0);
    constexpr std::uint32_t kNonce = 0x12345678;
    constexpr std::size_t kSector = 512;
    const std::size_t evil_pages = e.size() / page;

    std::vector<unsigned char> records;
    std::uint32_t changed = 0;
    for (std::size_t pg = 1; pg <= evil_pages; ++pg) {
        const unsigned char* ep = e.data() + (pg - 1) * page;
        if (pg * page <= v.size() && std::equal(ep, ep + page, v.data() + (pg - 1) * page))
            continue; // identical on both sides: nothing to restore
        ++changed;
        put_be32(records, static_cast<std::uint32_t>(pg));
        records.insert(records.end(), ep, ep + page);
        std::uint32_t checksum = kNonce; // the journal's sparse checksum: every 200th byte from the end
        for (auto j = static_cast<std::ptrdiff_t>(page) - 200; j > 0; j -= 200)
            checksum += ep[j];
        put_be32(records, checksum);
    }
    REQUIRE(changed > 0);

    std::vector<unsigned char> header = {0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7};
    put_be32(header, changed);
    put_be32(header, kNonce);
    put_be32(header, static_cast<std::uint32_t>(evil_pages));
    put_be32(header, static_cast<std::uint32_t>(kSector));
    put_be32(header, static_cast<std::uint32_t>(page));
    header.resize(kSector, 0);
    std::ofstream out(journal, std::ios::binary | std::ios::trunc);
    REQUIRE(out.is_open());
    out.write(reinterpret_cast<const char*>(header.data()),
              static_cast<std::streamsize>(header.size()));
    out.write(reinterpret_cast<const char*>(records.data()),
              static_cast<std::streamsize>(records.size()));
}

// Leaves a CLOSED echo.db at `db` (journal_probe = "7") with a hot rollback journal beside it
// that would rewrite journal_probe to "EVIL". `db`'s directory must exist.
void plant_evil_journal(const fs::path& db) {
    {
        auto created = EchoDatabase::open(db);
        REQUIRE(created.has_value());
        REQUIRE(created->set_config("journal_probe", "7"));
    } // closed: the WAL is empty, so the main file holds everything
    const fs::path evil = db.parent_path() / "evil.db";
    fs::copy_file(db, evil, fs::copy_options::overwrite_existing);
    {
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(evil.string().c_str(), &owner.db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(owner.db,
                             "UPDATE echo_config SET value = 'EVIL' WHERE key = 'journal_probe';"
                             "PRAGMA wal_checkpoint(TRUNCATE);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    write_hot_journal(db, evil, fs::path{db.string() + "-journal"});
}

} // namespace

// The premise of the Windows planted-journal case below, runnable everywhere: a hot journal is
// replayed by open() when nothing says it is foreign. That is crash recovery working, and it is
// why the Windows pass looks at the journal's OWNER before SQLite does.
TEST_CASE("EchoDatabase: a hot rollback journal beside echo.db is replayed by open()",
          "[echo][store][lifecycle][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_journal_"};
    fs::create_directories(dir.path);
    const fs::path db = dir.path / "echo.db";
    plant_evil_journal(db);
    REQUIRE(fs::file_size(fs::path{db.string() + "-journal"}) > 0);

    auto reopened = EchoDatabase::open(db);
    REQUIRE(reopened.has_value());
    CHECK(reopened->get_config("journal_probe", "") == "EVIL");
}

// The journal is one of the four files SQLite reads for a database, so quarantine moves it with
// the rest: it is evidence that belongs beside the quarantine (an empty one is dropped, like
// -wal and -shm), and the fresh database must not serve it. SQLite consumes a HOT journal at the
// integrity probe, before quarantine runs, so the journal planted here has a zero first byte
// (what journal_mode=PERSIST leaves behind): not hot, so the probe leaves it, byte-ful, for
// quarantine to deal with.
TEST_CASE("EchoDatabase: a corrupt echo.db's rollback journal is quarantined with it (#559)",
          "[echo][store][lifecycle][corruption]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_qjournal_"};
    fs::create_directories(dir.path);
    const fs::path db = dir.path / "echo.db";
    plant_evil_journal(db);
    const fs::path journal{db.string() + "-journal"};
    const auto journal_size = fs::file_size(journal);
    REQUIRE(journal_size > 0);
    {
        std::fstream f(journal, std::ios::binary | std::ios::in | std::ios::out);
        REQUIRE(f.is_open());
        f.put('\0');
    }
    {
        std::ofstream f(db, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database -- corrupt echo.db beside a journal";
    }

    auto reopened = EchoDatabase::open(db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->get_config("journal_probe", "") != "EVIL");

    // The journal sits beside the quarantine, byte for byte, and not beside the fresh database.
    const std::string prefix = db.filename().string() + ".corrupt-";
    int moved = 0;
    for (const auto& entry : fs::directory_iterator(dir.path)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0 && name.ends_with("-journal")) {
            ++moved;
            CHECK(fs::file_size(entry.path()) == journal_size);
        }
    }
    CHECK(moved == 1);
    // Nothing byte-ful stays beside the fresh database (the Windows open() pre-creates an EMPTY
    // protected journal there, so absence is not the portable statement).
    CHECK((!fs::exists(journal) || fs::file_size(journal) == 0));
}

#ifndef _WIN32
TEST_CASE("EchoDatabase: a corrupt-and-unmovable echo.db fails closed (#559 primary)",
          "[echo][store][lifecycle][corruption]") {
    // The PRIMARY #559 safety property: when a corrupt echo.db CANNOT be moved
    // aside (read-only mount, locked file, permissions), open() must REFUSE
    // (std::unexpected) rather than re-open-and-trust the still-corrupt file —
    // doing so would serve the "true" get_config default for every
    // <source>_enabled key and silently re-enable an operator-paused source.
    // POSIX-only: modelled with a read-only parent dir so the quarantine rename
    // fails. (Windows reparse/rename behaviour is a separate, static-reviewed
    // path with no CI here.)
    if (::geteuid() == 0) {
        SKIP("root bypasses directory permissions; cannot make the rename fail");
    }

    auto dir = yuzu::test::unique_temp_path("yuzu_test_echo_unmovable_");
    REQUIRE(fs::create_directory(dir));
    // RAII: re-add write perms and remove the dir even if an assertion throws,
    // so a read-only temp dir never leaks onto a CI box that reuses workspaces.
    struct DirGuard {
        fs::path dir;
        ~DirGuard() {
            std::error_code ec;
            fs::permissions(dir, fs::perms::owner_all, fs::perm_options::add, ec);
            fs::remove_all(dir, ec);
        }
    } dir_guard{dir};
    const auto db_path = dir / "echo.db";

    // 1. Create a valid DB with a deliberately-paused source, then corrupt it.
    {
        auto opened = EchoDatabase::open(db_path);
        REQUIRE(opened.has_value());
        EchoDatabase db = std::move(*opened);
        REQUIRE(db.create_warehouse_tables());
        db.set_config("process_enabled", "false");
    }
    for (const char* suffix : {"-wal", "-shm"}) {
        std::error_code ec;
        fs::remove(fs::path{db_path.string() + suffix}, ec);
    }
    {
        std::ofstream f(db_path, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "not a valid sqlite database -- corrupt + unmovable (#559)";
    }

    // 2. Strip write permission from the parent dir so the .corrupt-<epoch>
    //    rename inside it fails → quarantine returns nullopt → fail closed.
    std::error_code perm_ec;
    fs::permissions(dir,
                    fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write,
                    fs::perm_options::remove, perm_ec);
    REQUIRE_FALSE(perm_ec);

    // 3. open() must REFUSE — not silently re-init a fresh DB over the corruption.
    auto reopened = EchoDatabase::open(db_path);
    CHECK_FALSE(reopened.has_value());
    if (!reopened.has_value())
        CHECK(reopened.error().find("corrupt and unmovable") != std::string::npos);
    // dir_guard restores perms + removes the dir.
}

TEST_CASE("EchoDatabase: open() sets echo.db and its WAL sidecars owner-only (0600)",
          "[echo][store][lifecycle][hardening]") {
    // The db is seeded group/other-readable (0644) with an explicit chmod, which no umask
    // can alter, so the assertions fail unless open() itself re-modes an EXISTING file
    // (and, because SQLite derives a sidecar's mode from the db file, its -wal/-shm too).
    constexpr auto kOwnerOnly = fs::perms::owner_read | fs::perms::owner_write;
    const auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_mode_");
    struct Cleanup {
        fs::path db;
        ~Cleanup() {
            std::error_code ec;
            fs::remove(db, ec);
            fs::remove(fs::path{db.string() + "-wal"}, ec);
            fs::remove(fs::path{db.string() + "-shm"}, ec);
            fs::remove(fs::path{db.string() + "-journal"}, ec);
        }
    } cleanup{tmp};
    {
        auto created = EchoDatabase::open(tmp);
        REQUIRE(created.has_value());
    } // closed
    std::error_code ec;
    fs::permissions(tmp,
                    kOwnerOnly | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, ec);
    REQUIRE_FALSE(ec);
    REQUIRE((fs::status(tmp).permissions() & fs::perms::mask) != kOwnerOnly); // seed took

    auto reopened = EchoDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    for (const char* suffix : {"", "-wal", "-shm"}) {
        const fs::path p{tmp.string() + suffix};
        INFO("file=" << p.filename().string());
        if (suffix[0] != '\0' && !fs::exists(p))
            continue; // a sidecar is checked only where SQLite has created it
        REQUIRE(fs::exists(p));
        CHECK((fs::status(p).permissions() & fs::perms::mask) == kOwnerOnly);
    }
}
#else // _WIN32
// ── Windows: protected owner-only DACL on echo.db and its sidecars ─────────────────────
// The directory carries an INHERITABLE BUILTIN\Users read ACE (as C:\ProgramData does), so a
// sidecar SQLite creates itself WOULD inherit it: every case fails unless open() pre-creates or
// re-secures the file before SQLite does.
namespace {

using LocalPtr = std::unique_ptr<void, decltype(&::LocalFree)>;

constexpr const char* kUsers = "S-1-5-32-545";
constexpr const char* kSystem = "S-1-5-18";
constexpr const char* kAdministrators = "S-1-5-32-544";

std::string sid_string(PSID sid) {
    LPWSTR raw = nullptr;
    REQUIRE(::ConvertSidToStringSidW(sid, &raw));
    const LocalPtr guard{raw, ::LocalFree};
    return yuzu::win::from_wide(raw);
}

std::string token_user_sid() {
    HANDLE token = nullptr;
    REQUIRE(::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD len = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    const BOOL got = ::GetTokenInformation(token, TokenUser, buf.data(), len, &len);
    ::CloseHandle(token);
    REQUIRE(got);
    // Aligned cast: vector<BYTE>::data() is a heap block aligned to the default new alignment.
    return sid_string(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid);
}

// What a file's DACL says: whether it is protected, and the SIDs of its ALLOW aces.
struct DaclFacts {
    bool dacl_protected{false};
    std::vector<std::string> allowed;
    [[nodiscard]] bool allows(const std::string& sid) const {
        return std::find(allowed.begin(), allowed.end(), sid) != allowed.end();
    }
};

DaclFacts dacl_facts(const fs::path& p) {
    DaclFacts out;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    REQUIRE(::GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                    nullptr, &dacl, nullptr, &sd) == ERROR_SUCCESS);
    const LocalPtr sd_guard{sd, ::LocalFree};
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    REQUIRE(::GetSecurityDescriptorControl(sd, &control, &revision));
    out.dacl_protected = (control & SE_DACL_PROTECTED) != 0;
    for (WORD i = 0; dacl != nullptr && i < dacl->AceCount; ++i) { // a NULL DACL lists nothing
        void* ace = nullptr;
        if (::GetAce(dacl, i, &ace) &&
            static_cast<const ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            auto* allow = static_cast<ACCESS_ALLOWED_ACE*>(ace);
            out.allowed.push_back(sid_string(reinterpret_cast<PSID>(&allow->SidStart)));
        }
    }
    return out;
}

std::string owner_sid(const fs::path& p) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    REQUIRE(::GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                    &owner, nullptr, nullptr, nullptr, &sd) == ERROR_SUCCESS);
    const LocalPtr sd_guard{sd, ::LocalFree};
    return sid_string(owner);
}

void assert_owner_only(const fs::path& p) {
    INFO("file=" << p.filename().string());
    REQUIRE(fs::exists(p));
    const DaclFacts f = dacl_facts(p);
    CHECK(f.dacl_protected);
    for (const char* wide_group : {kUsers, "S-1-1-0" /*Everyone*/, "S-1-5-11" /*Authenticated*/})
        CHECK_FALSE(f.allows(wide_group));
    CHECK(f.allows(kSystem));
    CHECK(f.allows(kAdministrators));
    CHECK(f.allows(token_user_sid()));
}

// Adds an allow-read ACE for BUILTIN\Users and leaves the DACL UNPROTECTED -- which also strips
// a protected file back to the pre-upgrade shape. `inheritable` is for a directory.
void seed_users_ace(const fs::path& p, bool inheritable) {
    PSID users = nullptr;
    REQUIRE(::ConvertStringSidToSidW(L"S-1-5-32-545", &users));
    const LocalPtr users_guard{users, ::LocalFree};
    PACL old_dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    REQUIRE(::GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                    nullptr, &old_dacl, nullptr, &sd) == ERROR_SUCCESS);
    const LocalPtr sd_guard{sd, ::LocalFree};
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = FILE_GENERIC_READ;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = inheritable ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) : NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(users);
    PACL new_dacl = nullptr;
    REQUIRE(::SetEntriesInAclW(1, &ea, old_dacl, &new_dacl) == ERROR_SUCCESS);
    const LocalPtr acl_guard{new_dacl, ::LocalFree};
    std::wstring name = p.wstring(); // SetNamedSecurityInfoW takes a mutable LPWSTR
    REQUIRE(::SetNamedSecurityInfoW(
                name.data(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                nullptr, new_dacl, nullptr) == ERROR_SUCCESS);
    REQUIRE(dacl_facts(p).allows(kUsers)); // the seed took
}

// Lets this process hand a file to another owner; false when the privilege is not held.
bool enable_restore_privilege() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool ok =
        ::LookupPrivilegeValueW(nullptr, L"SeRestorePrivilege", &tp.Privileges[0].Luid) &&
        ::AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr) &&
        ::GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    ::CloseHandle(token);
    return ok;
}

void set_owner(const fs::path& p, const std::string& sid_text) {
    PSID sid = nullptr;
    REQUIRE(::ConvertStringSidToSidW(yuzu::win::to_wide(sid_text).c_str(), &sid));
    const LocalPtr sid_guard{sid, ::LocalFree};
    std::wstring name = p.wstring();
    REQUIRE(::SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, sid,
                                    nullptr, nullptr, nullptr) == ERROR_SUCCESS);
    REQUIRE(owner_sid(p) == sid_text); // the owner change took
}

// Gives ONLY the token user and SYSTEM read/write on `p` (protected, no WRITE_DAC, no DELETE):
// what a planting user would set so the service can use the file but not re-secure it. Call it
// while the test still owns `p`.
void set_read_write_only_dacl(const fs::path& p) {
    PSID system_sid = nullptr;
    REQUIRE(::ConvertStringSidToSidW(L"S-1-5-18", &system_sid));
    const LocalPtr system_guard{system_sid, ::LocalFree};
    PSID user_sid = nullptr;
    REQUIRE(::ConvertStringSidToSidW(yuzu::win::to_wide(token_user_sid()).c_str(), &user_sid));
    const LocalPtr user_guard{user_sid, ::LocalFree};
    PSID sids[] = {system_sid, user_sid};
    EXPLICIT_ACCESS_W ea[2]{};
    for (int i = 0; i < 2; ++i) {
        ea[i].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
        ea[i].grfAccessMode = GRANT_ACCESS;
        ea[i].grfInheritance = NO_INHERITANCE;
        ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea[i].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[i]);
    }
    PACL acl = nullptr;
    REQUIRE(::SetEntriesInAclW(2, ea, nullptr, &acl) == ERROR_SUCCESS);
    const LocalPtr acl_guard{acl, ::LocalFree};
    std::wstring name = p.wstring();
    REQUIRE(::SetNamedSecurityInfoW(
                name.data(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                nullptr, acl, nullptr) == ERROR_SUCCESS);
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// A directory carrying the inheritable Users ACE, and the echo.db path inside it.
struct AclDir {
    yuzu::test::TempDir dir{"yuzu_test_echo_acl_"};
    fs::path db;
    AclDir() {
        fs::create_directories(dir.path);
        seed_users_ace(dir.path, true);
        db = dir.path / "echo.db";
    }
    [[nodiscard]] fs::path file(const char* suffix) const { return fs::path{db.string() + suffix}; }
};

constexpr const char* kFiles[] = {"", "-wal", "-shm", "-journal"};

// True when `dir` is on NTFS or ReFS. Hard links need one of them, so a hard-link case run from a
// temp dir on FAT/exFAT or a network share would fail at its set-up, not in the code it tests.
bool volume_has_hard_links(const fs::path& dir) {
    wchar_t root[MAX_PATH] = {};
    if (!::GetVolumePathNameW(dir.c_str(), root, MAX_PATH))
        return false;
    wchar_t fs_name[MAX_PATH] = {};
    DWORD flags = 0;
    if (!::GetVolumeInformationW(root, nullptr, 0, nullptr, nullptr, &flags, fs_name, MAX_PATH))
        return false;
    const std::wstring name = fs_name;
    return name == L"NTFS" || name == L"ReFS";
}

} // namespace

TEST_CASE("EchoDatabase (Windows): a fresh db and its sidecars are created owner-only",
          "[echo][store][lifecycle][hardening]") {
    AclDir d;
    auto opened = EchoDatabase::open(d.db);
    REQUIRE(opened.has_value());
    REQUIRE(opened->set_config("acl_probe", "1")); // the WAL is live
    for (const char* sfx : kFiles)
        assert_owner_only(d.file(sfx)); // exists (REQUIRE) so the sidecar half is not vacuous
}

TEST_CASE("EchoDatabase (Windows): an upgraded world-readable db is re-secured on open",
          "[echo][store][lifecycle][hardening]") {
    AclDir d;
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    seed_users_ace(d.db, false); // the pre-upgrade shape: unprotected, Users can read
    REQUIRE_FALSE(dacl_facts(d.db).dacl_protected);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->set_config("acl_probe", "1"));
    for (const char* sfx : kFiles)
        assert_owner_only(d.file(sfx));
}

TEST_CASE("EchoDatabase (Windows): a foreign-owned sidecar is replaced, not adopted",
          "[echo][store][lifecycle][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    const fs::path wal = d.file("-wal");
    { std::ofstream plant(wal, std::ios::binary | std::ios::trunc); }
    set_owner(wal, kUsers);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->set_config("acl_probe", "1"));
    const std::string owner = owner_sid(wal);
    CHECK((owner == token_user_sid() || owner == kSystem || owner == kAdministrators));
    assert_owner_only(wal);
}

// SQLite replays a hot rollback journal beside the database before it reads the WAL. The journal
// planted here is the one the portable premise test above shows being replayed; only its owner
// differs, so what keeps "EVIL" out is the owner test.
TEST_CASE("EchoDatabase (Windows): a foreign-owned hot journal is replaced, not replayed",
          "[echo][store][lifecycle][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    plant_evil_journal(d.db);
    const fs::path journal = d.file("-journal");
    REQUIRE(fs::file_size(journal) > 0); // the attack is armed
    set_owner(journal, kUsers);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    CHECK(reopened->get_config("journal_probe", "") == "7"); // not "EVIL"
    CHECK(fs::file_size(journal) == 0); // swapped for the protected empty one, which is inert
    const std::string owner = owner_sid(journal);
    CHECK((owner == token_user_sid() || owner == kSystem || owner == kAdministrators));
    assert_owner_only(journal);
}

TEST_CASE("EchoDatabase (Windows): a foreign-owned echo.db refuses the open",
          "[echo][store][lifecycle][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    set_owner(d.db, kUsers);

    auto refused = EchoDatabase::open(d.db);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("owner") != std::string::npos);
    CHECK(refused.error().find("move it aside or remove it") != std::string::npos);
    CHECK(refused.error().find("grant the agent account full access") != std::string::npos);

    set_owner(d.db, token_user_sid()); // reversible: back to ours, the next open works
    CHECK(EchoDatabase::open(d.db).has_value());
}

// A hard link shares its target's owner and security descriptor, so the owner test passes it:
// only the link count tells it from a file of ours.
TEST_CASE("EchoDatabase (Windows): a hard-linked sidecar is replaced and its target left alone",
          "[echo][store][lifecycle][hardening]") {
    AclDir d;
    if (!volume_has_hard_links(d.dir.path))
        SKIP("the temp directory's volume is not NTFS or ReFS: no hard links");
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    const fs::path decoy = d.dir.path / "decoy.bin"; // ours, inherits the directory's Users ACE
    { std::ofstream(decoy, std::ios::binary) << "not a wal"; }
    REQUIRE(dacl_facts(decoy).allows(kUsers));
    REQUIRE_FALSE(dacl_facts(decoy).dacl_protected);

    const fs::path wal = d.file("-wal");
    std::error_code ec;
    fs::remove(wal, ec); // SQLite normally removes it on close; a plant needs the name free
    fs::create_hard_link(decoy, wal, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(fs::hard_link_count(wal) == 2);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->set_config("acl_probe", "1"));
    CHECK(fs::hard_link_count(wal) == 1); // our name was replaced, not rewritten in place
    assert_owner_only(wal);
    // The target kept its bytes and its descriptor: nothing re-secured or initialised it.
    CHECK(fs::hard_link_count(decoy) == 1);
    CHECK(read_file(decoy) == "not a wal");
    CHECK_FALSE(dacl_facts(decoy).dacl_protected);
    CHECK(dacl_facts(decoy).allows(kUsers));
}

TEST_CASE("EchoDatabase (Windows): a hard-linked echo.db refuses the open",
          "[echo][store][lifecycle][hardening]") {
    AclDir d;
    if (!volume_has_hard_links(d.dir.path))
        SKIP("the temp directory's volume is not NTFS or ReFS: no hard links");
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    const fs::path alias = d.dir.path / "alias.db";
    std::error_code ec;
    fs::create_hard_link(d.db, alias, ec);
    REQUIRE_FALSE(ec);

    auto refused = EchoDatabase::open(d.db);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("hard link") != std::string::npos);
    CHECK(refused.error().find("fsutil") != std::string::npos);

    REQUIRE(fs::remove(alias)); // reversible: one name again, the next open works
    CHECK(EchoDatabase::open(d.db).has_value());
}

// The planting user owns the file, so it can deny the service WRITE_DAC: the re-secure open then
// fails ACCESS_DENIED, and without a fallback look the owner test would never run on it. The
// owner is a SID outside this token (a group such as BUILTIN\Users in the token would hand the
// service implicit WRITE_DAC and hide the case).
TEST_CASE("EchoDatabase (Windows): a foreign sidecar that denies WRITE_DAC is still replaced",
          "[echo][store][lifecycle][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    const fs::path wal = d.file("-wal");
    { std::ofstream plant(wal, std::ios::binary | std::ios::trunc); }
    set_read_write_only_dacl(wal);
    set_owner(wal, "S-1-5-21-1111111111-2222222222-3333333333-1001");

    // The premise: the open secure_echo_db_files makes first is refused for this file.
    HANDLE probe = ::CreateFileW(wal.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const DWORD probe_err = ::GetLastError();
    if (probe != INVALID_HANDLE_VALUE)
        ::CloseHandle(probe);
    REQUIRE(probe == INVALID_HANDLE_VALUE);
    REQUIRE(probe_err == ERROR_ACCESS_DENIED);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->set_config("acl_probe", "1"));
    const std::string owner = owner_sid(wal);
    CHECK((owner == token_user_sid() || owner == kSystem || owner == kAdministrators));
    assert_owner_only(wal);
}

// #6362. A planted sidecar that is read-only is refused by DeleteFileW (access denied), which would
// leave the foreign file in place and stop the open: it is deleted through a handle with POSIX
// semantics that ignore the read-only attribute.
TEST_CASE("EchoDatabase (Windows): a foreign read-only sidecar is still replaced",
          "[echo][store][lifecycle][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    { REQUIRE(EchoDatabase::open(d.db).has_value()); } // created, then closed
    const fs::path wal = d.file("-wal");
    { std::ofstream plant(wal, std::ios::binary | std::ios::trunc); }
    REQUIRE(::SetFileAttributesW(wal.c_str(), FILE_ATTRIBUTE_READONLY)); // before the owner change
    set_owner(wal, kUsers);

    auto reopened = EchoDatabase::open(d.db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->set_config("acl_probe", "1"));
    const std::string owner = owner_sid(wal);
    CHECK((owner == token_user_sid() || owner == kSystem || owner == kAdministrators));
    CHECK((::GetFileAttributesW(wal.c_str()) & FILE_ATTRIBUTE_READONLY) == 0); // the new file
    assert_owner_only(wal);
}

// #1527. A junction at the database path is a reparse point std::filesystem may not call a symlink.
TEST_CASE("EchoDatabase (Windows): a junction at echo.db is refused",
          "[echo][store][lifecycle][hardening]") {
    AclDir d;
    const fs::path target = d.dir.path / "junction_target";
    REQUIRE(fs::create_directories(target));
    // mklink /J needs no privilege; a directory junction at a name SQLite would open as a file.
    const std::string cmd = "cmd /c mklink /J \"" + d.db.string() + "\" \"" + target.string() +
                            "\" >nul 2>&1";
    if (std::system(cmd.c_str()) != 0 || !fs::exists(d.db))
        SKIP("cannot create a junction here");
    auto refused = EchoDatabase::open(d.db);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("symbolic link or reparse point") != std::string::npos);
}
#endif // _WIN32

// =============================================================================
// checked_transaction (Wave 7 PR7.2b commit 1: strict Echo transaction executor)
// =============================================================================
//
// Fault-injection idiom matches Echo #2361's execute_atomic_batch tests
// (test_echo_aggregator.cpp): a `RAISE(ABORT, ...)` trigger leaves the
// transaction intact (a statement-preserving fault); `RAISE(ROLLBACK, ...)`
// aborts it. Both are real SQLite behaviour, not a mock.

namespace {

int64_t row_count(EchoDatabase& db, const std::string& table) {
    auto r = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(r.has_value());
    REQUIRE(!r->rows.empty());
    return std::stoll(r->rows[0][0]);
}

} // namespace

TEST_CASE("checked_transaction: happy path commits every statement together",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (2,1,'started',2,'b.exe','u',2)"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(result.has_value());
    CHECK(row_count(t.db, "usage_live") == 2);
}

TEST_CASE("checked_transaction: a fault on the FIRST statement commits nothing",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON usage_live "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        // Never reached in a correct implementation -- but written anyway to
        // prove the SECOND statement is not what stops the commit; poisoning
        // is what does, whether or not the callback keeps going.
        h.exec("INSERT INTO echo_config (key,value) VALUES ('canary','1')");
        return {};
    });
    CHECK_FALSE(result.has_value());
    CHECK(row_count(t.db, "usage_live") == 0);
    CHECK(t.db.get_config("canary", "") == ""); // the "second statement" never committed either
}

TEST_CASE("checked_transaction: a fault on a MIDDLE statement commits nothing, "
          "not even the earlier statements in the same transaction",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_cfg BEFORE INSERT ON echo_config "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO echo_config (key,value) VALUES ('mid','1')"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (2,1,'started',2,'b.exe','u',2)"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(result.has_value());
    // This is the property execute_atomic_batch does NOT have: the first
    // statement here would be durable under that primitive (it precedes the
    // failure and the batch's data segment is tolerant). checked_transaction
    // has no such segment -- the whole thing is one all-or-nothing unit.
    CHECK(row_count(t.db, "usage_live") == 0);
}

TEST_CASE("checked_transaction: a fault on the LAST statement commits nothing",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_cfg BEFORE INSERT ON echo_config "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO echo_config (key,value) VALUES ('last','1')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(result.has_value());
    CHECK(row_count(t.db, "usage_live") == 0);
}

TEST_CASE("checked_transaction: a statement-preserving fault (RAISE ABORT) leaves the "
          "connection usable, and a retry without the fault applies exactly once",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON usage_live "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto first = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(first.has_value());
    CHECK(t.db.is_open()); // statement-preserving -- the store is NOT taken offline
    REQUIRE(row_count(t.db, "usage_live") == 0);

    REQUIRE(t.db.execute_sql("DROP TRIGGER block_ins"));

    auto retry = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(retry.has_value());
    CHECK(row_count(t.db, "usage_live") == 1); // applied exactly once, not twice
}

TEST_CASE("checked_transaction: a transaction-aborting fault (RAISE ROLLBACK) stops the "
          "operation from issuing further statements",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON usage_live "
                             "BEGIN SELECT RAISE(ROLLBACK, 'aborted'); END;"));

    int exec_attempts = 0;
    auto result = t.db.checked_transaction(
        [&exec_attempts](TransactionHandle& h) -> std::expected<void, std::string> {
            ++exec_attempts;
            h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                   "VALUES (1,1,'started',1,'a.exe','u',1)"); // aborts the transaction
            ++exec_attempts;
            // poisoned() now true -- this exec() must no-op, never touch SQLite,
            // never insert the canary row.
            CHECK(h.poisoned());
            const bool second_ran =
                h.exec("INSERT INTO echo_config (key,value) VALUES ('canary','1')");
            CHECK_FALSE(second_ran);
            return {}; // deliberately ignored by the callback -- proves poisoning
                       // wins over a callback that forgets to check
        });
    CHECK_FALSE(result.has_value());
    CHECK(exec_attempts == 2); // both exec() CALLS were attempted by the callback...
    CHECK(t.db.get_config("canary", "") == ""); // ...but the second never touched the DB
    CHECK(row_count(t.db, "usage_live") == 0);
}

TEST_CASE("checked_transaction: an already-offline store refuses immediately, no crash",
          "[echo][store][checked_transaction]") {
    // Rollback-fails-with-transaction-still-open (the path that actually
    // TAKES a store offline) needs a disk-level fault this harness cannot
    // induce -- same limitation Echo #2361's "a closed store skips the pass"
    // test documents for execute_atomic_batch's identical wedge path
    // (test_echo_aggregator.cpp). This test covers the downstream behaviour:
    // checked_transaction against an ALREADY-offline connection (db_ ==
    // nullptr, simulated via move exactly as that test does) must refuse via
    // the `if (!db_)` pre-check, never attempt BEGIN, never crash.
    auto t = make_test_db();
    EchoDatabase live = std::move(t.db); // t.db is now the closed store

    auto result =
        t.db.checked_transaction([](TransactionHandle&) -> std::expected<void, std::string> {
            FAIL("operation must not run against an offline store");
            return {};
        });
    CHECK_FALSE(result.has_value());
    CHECK(result.error() == "database not open");
}

TEST_CASE("checked_transaction: an exception thrown from the operation still rolls back",
          "[echo][store][checked_transaction]") {
    auto t = make_test_db();
    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        throw std::runtime_error("simulated fault mid-operation");
    });
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("simulated fault mid-operation") != std::string::npos);
    CHECK(row_count(t.db, "usage_live") == 0); // the pre-throw INSERT did not survive
    CHECK(t.db.is_open()); // an exception is not a wedge -- the connection stays usable

    // And the connection genuinely still works afterward.
    auto retry = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO usage_live (ts,snapshot_id,action,pid,exe_key,user,start_ts) "
                    "VALUES (1,1,'started',1,'a.exe','u',1)"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(retry.has_value());
    CHECK(row_count(t.db, "usage_live") == 1);
}

TEST_CASE("checked_transaction: every statement individually succeeding does not imply "
          "success -- a COMMIT-time failure (deferred FK) still rolls back",
          "[echo][store][checked_transaction]") {
    // The one failure class none of the per-statement triggers above can
    // reach: every exec() in the operation returns true, so nothing pokes
    // poisoned() -- the failure only exists at COMMIT. A deferred foreign key
    // is real SQLite behaviour that manifests exactly there, so this proves
    // checked_transaction's own COMMIT check is load-bearing and not
    // redundant with poisoned().
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("PRAGMA foreign_keys=ON"));
    REQUIRE(t.db.execute_sql("CREATE TABLE fk_parent (id INTEGER PRIMARY KEY)"));
    REQUIRE(t.db.execute_sql(
        "CREATE TABLE fk_child (id INTEGER PRIMARY KEY, parent_id INTEGER "
        "REFERENCES fk_parent(id) DEFERRABLE INITIALLY DEFERRED)"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        // Every exec() below returns true -- the FK violation is deferred to
        // COMMIT, not caught here.
        if (!h.exec("INSERT INTO fk_child (id, parent_id) VALUES (1, 999)")) // no such parent
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("COMMIT failed") != std::string::npos);
    CHECK(row_count(t.db, "fk_child") == 0);
}

// ── #1654: events + baseline commit atomically ─────────────────────────────────
//
// The failure is injected with RAISE(ABORT) triggers (deterministic, in-process,
// no timing) on echo_state, both the INSERT and the UPDATE form so the test does
// not depend on which UPSERT branch SQLite takes. It hits the same
// `rc != SQLITE_DONE -> ROLLBACK` path a real SQLITE_BUSY would.

static void install_state_fault(EchoDatabase& db, const std::string& collector) {
    REQUIRE(db.execute_sql("CREATE TRIGGER yuzu_test_fail_state_i BEFORE INSERT ON echo_state "
                           "WHEN NEW.collector='" + collector +
                           "' BEGIN SELECT RAISE(ABORT,'injected'); END"));
    REQUIRE(db.execute_sql("CREATE TRIGGER yuzu_test_fail_state_u BEFORE UPDATE ON echo_state "
                           "WHEN NEW.collector='" + collector +
                           "' BEGIN SELECT RAISE(ABORT,'injected'); END"));
}

static void drop_state_fault(EchoDatabase& db) {
    REQUIRE(db.execute_sql("DROP TRIGGER yuzu_test_fail_state_i"));
    REQUIRE(db.execute_sql("DROP TRIGGER yuzu_test_fail_state_u"));
}

static int64_t count_rows(EchoDatabase& db, const std::string& table) {
    auto r = db.execute_query("SELECT COUNT(*) FROM " + table, 1);
    REQUIRE(r.has_value());
    return std::stoll(r->rows[0][0]);
}

TEST_CASE("EchoDatabase: process events + baseline are one transaction (#1654)",
          "[echo][store][corruption][atomic]") {
    auto t = make_test_db();
    REQUIRE(t.db.set_state("process", "baseline-1"));

    ProcessEvent a;
    a.ts = 1000;
    a.snapshot_id = 1;
    a.action = "started";
    a.pid = 1;
    a.name = "a.exe";
    ProcessEvent b = a;
    b.pid = 2;
    b.name = "b.exe";

    install_state_fault(t.db, "process");
    CHECK_FALSE(t.db.fold_process_events({a, b}, StateWrite{"process", "baseline-2"}));
    // Nothing durable: no events, baseline unchanged -> the next tick re-diffs the
    // identical delta instead of double-emitting.
    CHECK(count_rows(t.db, "process_hourly") == 0);
    CHECK(t.db.get_state("process") == "baseline-1");

    drop_state_fault(t.db);
    CHECK(t.db.fold_process_events({a, b}, StateWrite{"process", "baseline-2"}));
    CHECK(count_rows(t.db, "process_hourly") == 2);
    CHECK(t.db.get_state("process") == "baseline-2");
}

TEST_CASE("EchoDatabase: software + network events + baseline are one transaction (#1654)",
          "[echo][store][corruption][atomic]") {
    auto t = make_test_db();

    SoftwareEvent sw;
    sw.ts = 1000;
    sw.snapshot_id = 1;
    sw.action = "installed";
    sw.name = "app";
    install_state_fault(t.db, "software");
    CHECK_FALSE(t.db.fold_software_events({sw}, StateWrite{"software", "s2"}));
    CHECK(count_rows(t.db, "software_hourly") == 0);
    CHECK(t.db.get_state("software").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_software_events({sw}, StateWrite{"software", "s2"}));
    CHECK(count_rows(t.db, "software_hourly") == 1);
    CHECK(t.db.get_state("software") == "s2");

    NetworkEvent ne;
    ne.ts = 1000;
    ne.snapshot_id = 1;
    ne.action = "connected";
    ne.proto = "tcp";
    install_state_fault(t.db, "network");
    CHECK_FALSE(t.db.fold_network_events({ne}, StateWrite{"network", "n2"}));
    CHECK(count_rows(t.db, "tcp_hourly") == 0);
    CHECK(t.db.get_state("network").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_network_events({ne}, StateWrite{"network", "n2"}));
    CHECK(count_rows(t.db, "tcp_hourly") == 1);
    CHECK(t.db.get_state("network") == "n2");
}

TEST_CASE("EchoDatabase: service/user/arp/dns/mapdrive events + baseline are one transaction (#1654)",
          "[echo][store][corruption][atomic]") {
    auto t = make_test_db();

    ServiceEvent se; se.ts = 1000; se.snapshot_id = 1; se.action = "started"; se.name = "svc";
    install_state_fault(t.db, "service");
    CHECK_FALSE(t.db.fold_service_events({se}, StateWrite{"service", "b2"}));
    CHECK(count_rows(t.db, "service_hourly") == 0);
    CHECK(t.db.get_state("service").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_service_events({se}, StateWrite{"service", "b2"}));
    CHECK(count_rows(t.db, "service_hourly") == 1);
    CHECK(t.db.get_state("service") == "b2");

    UserEvent ue; ue.ts = 1000; ue.snapshot_id = 1; ue.action = "login"; ue.user = "alice";
    install_state_fault(t.db, "user");
    CHECK_FALSE(t.db.fold_user_events({ue}, StateWrite{"user", "b2"}));
    CHECK(count_rows(t.db, "user_hourly") == 0);
    CHECK(t.db.get_state("user").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_user_events({ue}, StateWrite{"user", "b2"}));
    CHECK(count_rows(t.db, "user_hourly") == 1);
    CHECK(t.db.get_state("user") == "b2");

    ArpEvent ae; ae.ts = 3000; ae.snapshot_id = 1; ae.action = "appeared"; ae.iface = "Ethernet";
    ae.ip_address = "192.168.1.1"; ae.mac_address = "aa:bb:cc:dd:ee:ff"; ae.entry_type = "dynamic";
    install_state_fault(t.db, "arp");
    CHECK_FALSE(t.db.fold_arp_events({ae}, StateWrite{"arp", "b2"}));
    CHECK(count_rows(t.db, "arp_hourly") == 0);
    CHECK(t.db.get_state("arp").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_arp_events({ae}, StateWrite{"arp", "b2"}));
    CHECK(count_rows(t.db, "arp_hourly") == 1);
    CHECK(t.db.get_state("arp") == "b2");

    DnsEvent de; de.ts = 3100; de.snapshot_id = 1; de.action = "appeared"; de.name = "example.com";
    de.record_type = "A"; de.data = "93.184.216.34"; de.ttl_remaining_s = 60; de.source = "cache";
    install_state_fault(t.db, "dns");
    CHECK_FALSE(t.db.fold_dns_events({de}, StateWrite{"dns", "b2"}));
    CHECK(count_rows(t.db, "dns_hourly") == 0);
    CHECK(t.db.get_state("dns").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_dns_events({de}, StateWrite{"dns", "b2"}));
    CHECK(count_rows(t.db, "dns_hourly") == 1);
    CHECK(t.db.get_state("dns") == "b2");

    MapDriveEvent me{1000, 5, "historical", "outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB", "historical"};
    install_state_fault(t.db, "mapdrive");
    CHECK_FALSE(t.db.fold_mapdrive_events({me}, StateWrite{"mapdrive", "b2"}));
    CHECK(count_rows(t.db, "mapdrive_hourly") == 0);
    CHECK(t.db.get_state("mapdrive").empty());
    drop_state_fault(t.db);
    CHECK(t.db.fold_mapdrive_events({me}, StateWrite{"mapdrive", "b2"}));
    CHECK(count_rows(t.db, "mapdrive_hourly") == 1);
    CHECK(t.db.get_state("mapdrive") == "b2");
}

TEST_CASE("EchoDatabase: StateWrite with empty events writes only the baseline (#1654)",
          "[echo][store][corruption][atomic]") {
    auto t = make_test_db();
    CHECK(t.db.fold_process_events({}, StateWrite{"process", "only-state"}));
    CHECK(t.db.get_state("process") == "only-state");
    CHECK(count_rows(t.db, "process_hourly") == 0);

    // nullopt state keeps the historical contract for an open handle byte-for-byte
    // (a closed handle now returns false for the state-carrying overloads).
    CHECK(t.db.fold_process_events({}));
    CHECK(t.db.fold_process_events({}, std::nullopt));
    CHECK(t.db.get_state("process") == "only-state");
}

TEST_CASE("EchoDatabase: set_state reports a failed baseline write (#1654)",
          "[echo][store][corruption][atomic]") {
    auto t = make_test_db();
    install_state_fault(t.db, "process");
    CHECK_FALSE(t.db.set_state("process", "x"));
    drop_state_fault(t.db);
    CHECK(t.db.set_state("process", "x"));
    CHECK(t.db.get_state("process") == "x");
}

// ── v7 -> v8: every capture source ships enabled ─────────────────────────────
namespace {

// Seed a closed echo.db at schema v7 with the given echo_config rows (raw sqlite
// so no migration or registry default is involved). `extra_sql` runs after the
// rows are in (used to install a fault-injecting trigger).
void seed_v7_config(const fs::path& path,
                    const std::vector<std::pair<std::string, std::string>>& rows,
                    const char* extra_sql = nullptr) {
    {
        auto db = EchoDatabase::open(path);
        REQUIRE(db.has_value());
    } // closed: lands at the current version
    // Owner declared before the open: sqlite3_open populates the handle even on
    // failure, so a failing REQUIRE still unwinds through a live owner.
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open(path.string().c_str(), &owner.db) == SQLITE_OK);
    auto put = [&](const std::string& k, const std::string& v) {
        const auto sql = "INSERT INTO echo_config (key, value) VALUES ('" + k + "', '" + v +
                         "') ON CONFLICT(key) DO UPDATE SET value = excluded.value";
        REQUIRE(sqlite3_exec(owner.db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    };
    put("schema_version", "7");
    for (const auto& [k, v] : rows)
        put(k, v);
    if (extra_sql)
        REQUIRE(sqlite3_exec(owner.db, extra_sql, nullptr, nullptr, nullptr) == SQLITE_OK);
}

void remove_db_files(const fs::path& tmp) {
    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
    fs::remove(fs::path{tmp.string() + "-journal"}, ec); // pre-created empty by the Windows open()
}

} // namespace

TEST_CASE("EchoDatabase: a fresh open lands at schema_version 10", "[echo][store][migration][v10]") {
    auto t = make_test_db();
    CHECK(t.db.schema_version() == 10);
}

TEST_CASE("EchoDatabase v7->v8: stored opt-outs of every formerly-off source flip once",
          "[echo][store][migration][v8]") {
    // Table-driven over all eight so a dropped or misspelt name in the migration's
    // literal list fails here. The eight already-on sources are seeded "false" as
    // negative controls: a deliberate pause on them must survive untouched.
    static constexpr std::array<std::string_view, 8> kFormerlyOff = {
        "procperf", "netqual", "module", "software", "arp", "dns", "netconn", "mapdrive"};
    static constexpr std::array<std::string_view, 8> kAlreadyOn = {
        "process", "tcp", "service", "user", "perf", "power", "removable", "usage"};
    std::vector<std::pair<std::string, std::string>> rows;
    int64_t paused = 1'700'000'000;
    for (const auto* group : {&kFormerlyOff, &kAlreadyOn}) {
        for (const auto src : *group) {
            rows.emplace_back(std::format("{}_enabled", src), "false");
            rows.emplace_back(std::format("{}_paused_at", src), std::to_string(paused++));
        }
    }
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    seed_v7_config(tmp, rows);
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        int64_t expect = 1'700'000'000;
        for (const auto src : kFormerlyOff) {
            INFO("formerly-off source=" << src);
            CHECK(db->get_config(std::format("{}_enabled", src), "") == "true");
            CHECK(db->get_config(std::format("{}_paused_at", src), "") == "0");
            ++expect;
        }
        for (const auto src : kAlreadyOn) {
            INFO("already-on source=" << src);
            CHECK(db->get_config(std::format("{}_enabled", src), "") == "false");
            CHECK(db->get_config(std::format("{}_paused_at", src), "") == std::to_string(expect));
            ++expect;
        }
    }
    remove_db_files(tmp);
}

TEST_CASE("EchoDatabase v7->v8: errored / already-on / absent rows are left alone",
          "[echo][store][migration][v8]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    seed_v7_config(tmp, {{"netqual_enabled", "errored"},
                         {"process_enabled", "false"},
                         {"process_paused_at", "5"},
                         {"software_enabled", "true"}});
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        CHECK(db->get_config("netqual_enabled", "") == "errored");
        // An already-on source's deliberate pause survives.
        CHECK(db->get_config("process_enabled", "") == "false");
        CHECK(db->get_config("process_paused_at", "") == "5");
        CHECK(db->get_config("software_enabled", "") == "true");
        // No row stays no row (the registry default supplies "true").
        CHECK(db->get_config("arp_enabled", "") == "");
    }
    remove_db_files(tmp);
}

TEST_CASE("EchoDatabase v7->v8: an opt-out written after the migration sticks",
          "[echo][store][migration][v8]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    seed_v7_config(tmp, {{"procperf_enabled", "false"}});
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        REQUIRE(db->get_config("procperf_enabled", "") == "true");
        REQUIRE(db->set_config("procperf_enabled", "false"));
    }
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        CHECK(db->get_config("procperf_enabled", "") == "false");
    }
    remove_db_files(tmp);
}

TEST_CASE("EchoDatabase v7->v8: a failed flip rolls the whole migration back and the "
          "open refuses and the retry completes",
          "[echo][store][migration][v8][atomic]") {
    // The trigger fails the flip UPDATE after the paused_at upsert already ran inside the same
    // savepoint: the rollback must undo that, and the roll-up step must NOT run past the failed
    // one -- it would take the version to 10 and the flip would never be retried. The open refuses
    // (a retryable error); a reopen with the fault removed completes both steps.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    seed_v7_config(tmp,
                   {{"procperf_enabled", "false"},
                    {"procperf_paused_at", "7"},
                    {"netqual_enabled", "false"},
                    {"netqual_paused_at", "9"}},
                   "CREATE TRIGGER yuzu_test_v8_abort BEFORE UPDATE ON echo_config "
                   "WHEN NEW.key = 'netqual_enabled' "
                   "BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE_FALSE(db.has_value());
        CHECK(db.error().find("earlier migration step did not finish") != std::string::npos);
    }
    {
        // Nothing the failed step did survived: read the file the way the next open will.
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &owner.db) == SQLITE_OK);
        const auto stored = [&](const char* key) {
            sqlite3_stmt* st = nullptr;
            const std::string sql = std::string{"SELECT value FROM echo_config WHERE key = '"} + key + "'";
            REQUIRE(sqlite3_prepare_v2(owner.db, sql.c_str(), -1, &st, nullptr) == SQLITE_OK);
            std::string v;
            if (sqlite3_step(st) == SQLITE_ROW)
                v = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            sqlite3_finalize(st);
            return v;
        };
        CHECK(stored("schema_version") == "7");
        CHECK(stored("procperf_enabled") == "false");
        CHECK(stored("procperf_paused_at") == "7");
        CHECK(stored("netqual_enabled") == "false");
        REQUIRE(sqlite3_exec(owner.db, "DROP TRIGGER yuzu_test_v8_abort", nullptr, nullptr,
                             nullptr) == SQLITE_OK);
    }
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        CHECK(db->get_config("procperf_enabled", "") == "true");
        CHECK(db->get_config("procperf_paused_at", "") == "0");
        CHECK(db->get_config("netqual_enabled", "") == "true");
        CHECK(db->get_config("netqual_paused_at", "") == "0");
    }
    remove_db_files(tmp);
}

TEST_CASE("EchoDatabase v7: a failed v8 step blocks the roll-up step and leaves the raw capture "
          "rows intact until a reopen succeeds",
          "[echo][store][migration][v8][v10][atomic]") {
    // A v7 file that still holds raw capture rows, with a trigger that fails the v8 flip. The
    // roll-up step must refuse to run past the failed step: it would take the version to 10 and
    // v8 would never be retried. After the fault is removed one reopen walks v7 to v10.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    {
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &owner.db) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE echo_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO echo_config (key, value) VALUES ('schema_version', '7');
            INSERT INTO echo_config (key, value) VALUES ('netqual_enabled', 'false');
            CREATE TABLE procperf_live (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER, snapshot_id INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '',
                instances INTEGER, cpu_pct REAL, ws_bytes INTEGER);
            CREATE TABLE procperf_hourly (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour_ts INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '', samples INTEGER,
                instances_max INTEGER, cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER,
                ws_max_bytes INTEGER, is_kthread INTEGER NOT NULL DEFAULT 0);
            ALTER TABLE procperf_live ADD COLUMN is_kthread INTEGER NOT NULL DEFAULT 0;
            INSERT INTO procperf_live (ts, snapshot_id, name, version, instances, cpu_pct, ws_bytes)
                VALUES (7300, 1, 'app.exe', '2.0', 1, 3.0, 10);
            CREATE TRIGGER yuzu_test_v8_abort BEFORE UPDATE ON echo_config
                WHEN NEW.key = 'netqual_enabled'
                BEGIN SELECT RAISE(ABORT, 'injected'); END;
        )";
        REQUIRE(sqlite3_exec(owner.db, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE_FALSE(db.has_value());
        CHECK(db.error().find("earlier migration step") != std::string::npos);
    }
    {
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &owner.db) == SQLITE_OK);
        const auto scalar = [&](const char* sql) {
            sqlite3_stmt* st = nullptr;
            REQUIRE(sqlite3_prepare_v2(owner.db, sql, -1, &st, nullptr) == SQLITE_OK);
            std::string v;
            if (sqlite3_step(st) == SQLITE_ROW)
                v = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            sqlite3_finalize(st);
            return v;
        };
        CHECK(scalar("SELECT value FROM echo_config WHERE key = 'schema_version'") == "7");
        CHECK(scalar("SELECT COUNT(*) FROM procperf_live") == "1");
        CHECK(scalar("SELECT COUNT(*) FROM procperf_hourly") == "0");
        // No transaction or lock survived the refused open: autocommit, and a writer can begin.
        CHECK(sqlite3_get_autocommit(owner.db) == 1);
        CHECK(sqlite3_exec(owner.db, "BEGIN IMMEDIATE; ROLLBACK;", nullptr, nullptr, nullptr) ==
              SQLITE_OK);
        REQUIRE(sqlite3_exec(owner.db, "DROP TRIGGER yuzu_test_v8_abort", nullptr, nullptr,
                             nullptr) == SQLITE_OK);
    }
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
        CHECK(db->get_config("netqual_enabled", "") == "true");
        auto row = db->execute_query("SELECT version FROM procperf_hourly WHERE name = 'app.exe'");
        REQUIRE(row.has_value());
        CHECK(row->rows.size() == 1);
    }
    remove_db_files(tmp);
}

namespace {

// Denies the Nth read of echo_config.value on the FIRST connection a later EchoDatabase::open()
// creates. Inside open() that connection's first read of the column is the schema_version read
// (1) that decides whether the version needs writing.
// A SQLITE_DENY at prepare time makes get_config fall to its default, which is a failed read.
std::atomic<int> g_value_reads{0};
std::atomic<int> g_deny_value_read{-1};
std::atomic<bool> g_denied{false};
std::atomic<bool> g_instrument_next{false};

int deny_nth_value_read(void*, int action, const char* table, const char* column, const char*,
                        const char*) {
    if (action == SQLITE_READ && table != nullptr && column != nullptr &&
        std::strcmp(table, "echo_config") == 0 && std::strcmp(column, "value") == 0 &&
        ++g_value_reads == g_deny_value_read.load()) {
        g_denied = true;
        return SQLITE_DENY;
    }
    return SQLITE_OK;
}

// Denies `PRAGMA integrity_check` (prepare fails with SQLITE_AUTH) on the FIRST connection a later
// EchoDatabase::open() creates: the portable stand-in for an I/O, permission or space failure at
// the integrity stage, which open() must treat as "unreadable" (refuse, move nothing; #7286).
std::atomic<bool> g_deny_integrity_check{false};

int deny_integrity_check(void*, int action, const char* a1, const char*, const char*,
                         const char*) {
    if (action == SQLITE_PRAGMA && a1 != nullptr && std::strcmp(a1, "integrity_check") == 0)
        return SQLITE_DENY;
    return SQLITE_OK;
}

int instrument_first_connection(sqlite3* db, char**, const sqlite3_api_routines*) {
    if (g_deny_integrity_check.exchange(false))
        sqlite3_set_authorizer(db, deny_integrity_check, nullptr);
    else if (g_instrument_next.exchange(false))
        sqlite3_set_authorizer(db, deny_nth_value_read, nullptr);
    return SQLITE_OK;
}

// Unregisters the process-wide hook on every exit path, so no later test's connection sees it.
struct AutoExtensionGuard {
    AutoExtensionGuard() {
        sqlite3_auto_extension(reinterpret_cast<void (*)()>(instrument_first_connection));
    }
    ~AutoExtensionGuard() {
        sqlite3_cancel_auto_extension(reinterpret_cast<void (*)()>(instrument_first_connection));
        g_instrument_next = false;
        g_deny_value_read = -1;
        g_deny_integrity_check = false;
    }
    AutoExtensionGuard(const AutoExtensionGuard&) = delete;
    AutoExtensionGuard& operator=(const AutoExtensionGuard&) = delete;
};

} // namespace

TEST_CASE("EchoDatabase: one failed schema_version read at open does not replay the migrations",
          "[echo][store][migration][v8]") {
    // A post-upgrade operator state that must survive: module disabled and paused. A schema_version
    // read that FAILS used to read as 0, rewrite the version to 2 and walk the whole ladder again,
    // v8 included, which flips every formerly-off source's "false" back to "true".
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_echo_v8_");
    {
        auto db = EchoDatabase::open(tmp);
        REQUIRE(db.has_value());
        REQUIRE(db->schema_version() == 10);
        REQUIRE(db->set_config("module_enabled", "false"));
        REQUIRE(db->set_config("module_paused_at", "1761000000"));
    }
    {
        const AutoExtensionGuard hook;
        g_value_reads = 0;
        g_denied = false;
        g_deny_value_read = 1;
        g_instrument_next = true;
        auto db = EchoDatabase::open(tmp);
        g_deny_value_read = -1;
        REQUIRE(db.has_value());
        REQUIRE(g_denied.load()); // the fault reached the schema_version read
        CHECK(db->schema_version() == 10);
        CHECK(db->get_config("module_enabled", "") == "false");
        CHECK(db->get_config("module_paused_at", "") == "1761000000");
    }
    remove_db_files(tmp);
}

// ── Echo rename: adopting a pre-rename tar.db (upgrade window) ───────────────
//
// The legacy names below (tar.db, tar_state, tar_config, tar_cursor) are the on-disk spelling of
// databases written before the rename, so they stay verbatim here.
namespace {

using SqliteOwner = yuzu::test::SqliteHandleOwner<sqlite3>;

void exec_sql(sqlite3* db, const char* sql) {
    REQUIRE(sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
}

std::string slurp_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void spit_file(const fs::path& p, std::string_view bytes) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    REQUIRE(f.is_open());
    f << bytes;
}

std::vector<std::string> table_names(const fs::path& db_file) {
    SqliteOwner o;
    REQUIRE(sqlite3_open_v2(db_file.string().c_str(), &o.db, SQLITE_OPEN_READONLY, nullptr) ==
            SQLITE_OK);
    std::vector<std::string> out;
    sqlite3_stmt* raw = nullptr;
    REQUIRE(sqlite3_prepare_v2(o.db, "SELECT name FROM sqlite_master WHERE type = 'table'", -1,
                               &raw, nullptr) == SQLITE_OK);
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{raw, &sqlite3_finalize};
    while (sqlite3_step(stmt.get()) == SQLITE_ROW)
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0)));
    return out;
}

bool has_table(const std::vector<std::string>& names, std::string_view n) {
    return std::ranges::find(names, n) != names.end();
}

// One echo_config value read through raw SQLite (so any WAL beside the file is recovered exactly as a
// plain open would), "<no row>" when the row or table is absent. Opens read-write: the caller owns a
// scratch copy, and recovery needs a writable -shm.
std::string raw_config_value(const fs::path& db_file, const char* key) {
    SqliteOwner o;
    REQUIRE(sqlite3_open_v2(db_file.string().c_str(), &o.db, SQLITE_OPEN_READWRITE, nullptr) ==
            SQLITE_OK);
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(o.db, "SELECT value FROM echo_config WHERE key = ?1", -1, &raw,
                           nullptr) != SQLITE_OK)
        return std::string{sqlite3_errmsg(o.db)}.find("no such table") != std::string::npos
                   ? "<no row>"
                   : "<error>";
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{raw, &sqlite3_finalize};
    sqlite3_bind_text(stmt.get(), 1, key, -1, SQLITE_STATIC);
    const int step_rc = sqlite3_step(stmt.get());
    if (step_rc == SQLITE_DONE)
        return "<no row>";
    if (step_rc != SQLITE_ROW)
        return "<error>";
    return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
}

// A closed, healthy, pre-rename database at <dir>/tar.db: tar_* tables, schema_version 8, rollback
// journal (so no WAL is left behind). Built from the real schema, then renamed by raw SQL.
void make_legacy_tar_db(const fs::path& dir) {
    const auto scratch = dir / "echo.db";
    {
        auto db = EchoDatabase::open(scratch);
        REQUIRE(db.has_value());
    }
    {
        SqliteOwner o;
        REQUIRE(sqlite3_open(scratch.string().c_str(), &o.db) == SQLITE_OK);
        exec_sql(o.db, "PRAGMA journal_mode=DELETE");
        exec_sql(o.db, "ALTER TABLE echo_state RENAME TO tar_state");
        exec_sql(o.db, "ALTER TABLE echo_config RENAME TO tar_config");
        exec_sql(o.db, "ALTER TABLE echo_cursor RENAME TO tar_cursor");
        exec_sql(o.db, "UPDATE tar_config SET value = '8' WHERE key = 'schema_version'");
    }
    for (const char* suffix : {"-wal", "-shm", "-journal"}) {
        std::error_code ec;
        fs::remove(fs::path{scratch.string() + suffix}, ec);
    }
    fs::rename(scratch, dir / "tar.db");
}

// A crash-shaped legacy file set in `dst`: tar.db plus a tar.db-wal holding one committed but
// never-checkpointed row (wal_marker=x). The copy is taken while the writer is still open, so the
// row exists ONLY in the WAL.
void make_legacy_tar_db_with_wal(const fs::path& dst) {
    yuzu::test::TempDir src("yuzu_test_echo_walsrc_");
    REQUIRE(fs::create_directories(src.path));
    make_legacy_tar_db(src.path);
    SqliteOwner o;
    REQUIRE(sqlite3_open((src.path / "tar.db").string().c_str(), &o.db) == SQLITE_OK);
    exec_sql(o.db, "PRAGMA journal_mode=WAL");
    exec_sql(o.db, "PRAGMA wal_autocheckpoint=0");
    exec_sql(o.db, "INSERT INTO tar_config(key, value) VALUES ('wal_marker', 'x')");
    REQUIRE(fs::exists(src.path / "tar.db-wal"));
    fs::copy_file(src.path / "tar.db", dst / "tar.db");
    fs::copy_file(src.path / "tar.db-wal", dst / "tar.db-wal");
    // Positive control: the marker row exists ONLY in the WAL. If a checkpoint ever lands before
    // the copy, the main file would carry it and every "WAL-only row survives" claim built on
    // this helper would pass vacuously.
    REQUIRE(slurp_file(dst / "tar.db").find("wal_marker") == std::string::npos);
    REQUIRE(slurp_file(dst / "tar.db-wal").find("wal_marker") != std::string::npos);
}

struct ScratchDir {
    yuzu::test::TempDir dir{"yuzu_test_echo_adopt_"};
    ScratchDir() { REQUIRE(fs::create_directories(dir.path)); }
    [[nodiscard]] const fs::path& path() const { return dir.path; }
};

// Write the adoption-intent marker exactly as an interrupted adoption would have left it: the
// current size and mtime of tar.db.
void write_adoption_marker(const fs::path& dir) {
    const auto fp = yuzu::agent::detail::legacy_echo_fingerprint(dir / "tar.db");
    REQUIRE(fp.has_value());
    spit_file(dir / "echo.db.adopting", *fp);
}

} // namespace

TEST_CASE("adopt_legacy_echo_db: a crash-shaped tar.db + un-checkpointed WAL opens as echo.db",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    const auto echo_db = d.path() / "echo.db";

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "tar.db-wal"));
    CHECK(fs::exists(echo_db));
    CHECK(fs::exists(d.path() / "echo.db-wal"));

    {
        auto db = EchoDatabase::open(echo_db);
        REQUIRE(db.has_value());
        CHECK(db->get_config("wal_marker", "") == "x"); // the WAL-only row survived the move
        CHECK(db->schema_version() == 10);
    }
    const auto names = table_names(echo_db);
    CHECK(has_table(names, "echo_state"));
    CHECK(has_table(names, "echo_config"));
    CHECK(has_table(names, "echo_cursor"));
    CHECK_FALSE(has_table(names, "tar_state"));
    CHECK_FALSE(has_table(names, "tar_config"));
    CHECK_FALSE(has_table(names, "tar_cursor"));
}

TEST_CASE("adopt_legacy_echo_db: an interrupted adoption resumes", "[echo][store][adopt]") {
    SECTION("sidecar already moved, main file not") {
        ScratchDir d;
        make_legacy_tar_db_with_wal(d.path());
        write_adoption_marker(d.path()); // what the interrupted run wrote before its first move
        fs::rename(d.path() / "tar.db-wal", d.path() / "echo.db-wal");
        REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
        CHECK_FALSE(fs::exists(d.path() / "tar.db"));
        CHECK_FALSE(fs::exists(d.path() / "echo.db.adopting")); // spent once the main file moved
        auto db = EchoDatabase::open(d.path() / "echo.db");
        REQUIRE(db.has_value());
        CHECK(db->get_config("wal_marker", "") == "x");
    }
    SECTION("everything already at the echo names: a no-op") {
        ScratchDir d;
        make_legacy_tar_db_with_wal(d.path());
        REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
        const auto before = slurp_file(d.path() / "echo.db");
        const auto wal_before = slurp_file(d.path() / "echo.db-wal");
        REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
        CHECK(slurp_file(d.path() / "echo.db") == before);
        CHECK(slurp_file(d.path() / "echo.db-wal") == wal_before);
    }
}

TEST_CASE("adopt_legacy_echo_db: the adoption marker is written before the first sidecar move "
          "and survives an interruption",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    // -wal moves (so the marker must already exist), then -shm collides and adoption stops.
    spit_file(d.path() / "tar.db-shm", "legacy shm");
    spit_file(d.path() / "echo.db-shm", "foreign shm");
    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(fs::exists(d.path() / "echo.db-wal"));       // the first move happened
    CHECK(fs::exists(d.path() / "echo.db.adopting"));  // and the marker preceded it
    CHECK(slurp_file(d.path() / "echo.db.adopting") ==
          *yuzu::agent::detail::legacy_echo_fingerprint(d.path() / "tar.db"));

    // The documented remedy resumes under the surviving marker and spends it.
    fs::remove(d.path() / "echo.db-shm");
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db.adopting"));
}

TEST_CASE("adopt_legacy_echo_db: an echo.db sidecar beside tar.db without the marker refuses",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db(d.path());
    spit_file(d.path() / "echo.db-wal", "a log of unknown origin");

    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("tar.db") != std::string::npos);
    CHECK(adopted.error().find("echo.db-wal") != std::string::npos);
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db.adopting"));
    CHECK(slurp_file(d.path() / "echo.db-wal") == "a log of unknown origin");
}

TEST_CASE("adopt_legacy_echo_db: an older agent running between interruption and resume is "
          "refused and never replayed over",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    // Back-date tar.db so the older agent's write below is distinguishable by mtime on any
    // filesystem timestamp granularity.
    fs::last_write_time(d.path() / "tar.db",
                        fs::last_write_time(d.path() / "tar.db") - std::chrono::hours(1));
    // Steps 1-2: the marker and the WAL move happen, the power fails before the main rename.
    write_adoption_marker(d.path());
    fs::rename(d.path() / "tar.db-wal", d.path() / "echo.db-wal");
    const auto stale_wal = slurp_file(d.path() / "echo.db-wal");
    // Step 3: an older agent opens tar.db, writes, and closes cleanly (checkpoint, WAL deleted).
    {
        SqliteOwner o;
        REQUIRE(sqlite3_open((d.path() / "tar.db").string().c_str(), &o.db) == SQLITE_OK);
        exec_sql(o.db, "PRAGMA journal_mode=WAL");
        exec_sql(o.db, "INSERT INTO tar_config(key, value) VALUES ('newer', 'yes')");
    }
    REQUIRE_FALSE(fs::exists(d.path() / "tar.db-wal"));
    const auto newer_main = slurp_file(d.path() / "tar.db");

    // Step 4: the re-upgrade must not pair the newer tar.db with the older log.
    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("echo.db-wal") != std::string::npos);
    CHECK_FALSE(fs::exists(d.path() / "echo.db"));
    CHECK(slurp_file(d.path() / "tar.db") == newer_main);
    CHECK(slurp_file(d.path() / "echo.db-wal") == stale_wal);

    auto refused = EchoDatabase::open(d.path() / "echo.db");
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("not adopted - refusing") != std::string::npos);
}

TEST_CASE("adopt_legacy_echo_db: an oversized marker reads as a mismatch and refuses",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db(d.path());
    spit_file(d.path() / "echo.db-wal", "a log of unknown origin");
    spit_file(d.path() / "echo.db.adopting", std::string(300, 'x'));

    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("records a different") != std::string::npos);
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db"));
}

TEST_CASE("adopt_legacy_echo_db: a stale marker with no echo.db sidecar is rewritten before the "
          "first move",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    // A marker from an earlier, fully undone attempt (no echo.db sidecar is left) records a
    // tar.db that no longer exists in that shape: it must not be trusted as this adoption's own.
    spit_file(d.path() / "echo.db.adopting", "1 2\n");
    // -wal moves, then -shm collides: the interrupted state shows which marker preceded the move.
    spit_file(d.path() / "tar.db-shm", "legacy shm");
    spit_file(d.path() / "echo.db-shm", "foreign shm");

    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(fs::exists(d.path() / "echo.db-wal"));
    CHECK(slurp_file(d.path() / "echo.db.adopting") ==
          *yuzu::agent::detail::legacy_echo_fingerprint(d.path() / "tar.db"));

    fs::remove(d.path() / "echo.db-shm");
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db.adopting"));
}

TEST_CASE("adopt_legacy_echo_db: a marker that cannot be written refuses before anything moves",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    const auto wal = slurp_file(d.path() / "tar.db-wal");
    // A directory at the marker path: the atomic writer cannot rename its temp file over it.
    REQUIRE(fs::create_directory(d.path() / "echo.db.adopting"));

    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("cannot record the adoption marker") != std::string::npos);
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK(slurp_file(d.path() / "tar.db-wal") == wal);
    CHECK_FALSE(fs::exists(d.path() / "echo.db"));
    CHECK_FALSE(fs::exists(d.path() / "echo.db-wal"));
    CHECK(fs::is_directory(d.path() / "echo.db.adopting"));
}

TEST_CASE("adopt_legacy_echo_db: a spent marker left behind without a tar.db is deleted at boot",
          "[echo][store][adopt]") {
    ScratchDir d;
    {
        auto db = EchoDatabase::open(d.path() / "echo.db");
        REQUIRE(db.has_value());
    }
    spit_file(d.path() / "echo.db.adopting", "12345 67890\n");
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
    CHECK_FALSE(fs::exists(d.path() / "echo.db.adopting"));
    CHECK(fs::exists(d.path() / "echo.db"));
}

TEST_CASE("adopt_legacy_echo_db: a leftover legacy sidecar without a tar.db is warned about and left",
          "[echo][store][adopt]") {
    SECTION("a lone tar.db-shm beside an adopted echo.db") {
        ScratchDir d;
        {
            auto db = EchoDatabase::open(d.path() / "echo.db");
            REQUIRE(db.has_value());
        }
        std::error_code ec;
        fs::remove(d.path() / "echo.db-shm", ec);
        spit_file(d.path() / "tar.db-shm", "stale");
        yuzu::test::LogCapture logs;
        REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
        logs.stop();
        CHECK(logs.text().find("tar.db-shm") != std::string::npos);
        CHECK(logs.text().find("left in place") != std::string::npos);
        CHECK(fs::exists(d.path() / "tar.db-shm"));
        CHECK_FALSE(fs::exists(d.path() / "echo.db-shm"));
        auto db = EchoDatabase::open(d.path() / "echo.db");
        CHECK(db.has_value());
    }
    SECTION("an orphan tar.db-wal is never replayed over a live echo.db") {
        ScratchDir d;
        const auto echo_db = d.path() / "echo.db";
        {
            auto db = EchoDatabase::open(echo_db);
            REQUIRE(db.has_value());
            REQUIRE(db->set_config("known_row", "current echo history"));
        }
        // A cleanly closed WAL database leaves no -wal: the state a stray one would pair up with.
        REQUIRE_FALSE(fs::exists(d.path() / "echo.db-wal"));
        {
            ScratchDir legacy_src;
            make_legacy_tar_db_with_wal(legacy_src.path());
            fs::copy_file(legacy_src.path() / "tar.db-wal", d.path() / "tar.db-wal");
        }
        const std::string foreign_wal = slurp_file(d.path() / "tar.db-wal");

        // Positive control: under the echo.db name this very WAL is valid and SQLite replays it
        // over the file, so the assertions below are not vacuous.
        {
            ScratchDir probe;
            fs::copy_file(echo_db, probe.path() / "echo.db");
            fs::copy_file(d.path() / "tar.db-wal", probe.path() / "echo.db-wal");
            const std::string replayed = raw_config_value(probe.path() / "echo.db", "known_row");
            CHECK(replayed != "<error>");  // an SQL failure must not pass for "replayed over"
            CHECK(replayed != "current echo history");
        }

        yuzu::test::LogCapture logs;
        REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
        logs.stop();
        CHECK(logs.text().find("tar.db-wal") != std::string::npos);
        CHECK(logs.text().find("left in place") != std::string::npos);
        CHECK(slurp_file(d.path() / "tar.db-wal") == foreign_wal); // unmoved, unmodified
        CHECK_FALSE(fs::exists(d.path() / "echo.db-wal"));

        auto db = EchoDatabase::open(echo_db);
        REQUIRE(db.has_value());
        CHECK(db->get_config("known_row", "") == "current echo history");
    }
}

TEST_CASE("adopt_legacy_echo_db: both main files present is two databases and nothing moves",
          "[echo][store][adopt]") {
    ScratchDir d;
    {
        auto db = EchoDatabase::open(d.path() / "echo.db");
        REQUIRE(db.has_value());
        REQUIRE(db->set_config("which", "echo"));
    }
    make_legacy_tar_db_with_wal(d.path());
    spit_file(d.path() / "echo.db-wal", ""); // an empty live WAL beside the live echo.db

    const std::array<const char*, 4> files = {"tar.db", "tar.db-wal", "echo.db", "echo.db-wal"};
    std::vector<std::string> before;
    for (const char* f : files)
        before.push_back(slurp_file(d.path() / f));

    // The warning is the operator's only signal; its phrase is quoted in docs/user-manual/upgrading.md.
    // The adopter is header-only, so it logs through this binary's own spdlog (LogCapture reaches it).
    yuzu::test::LogCapture logs;
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
    logs.stop();
    CHECK(logs.text().find("two independent databases") != std::string::npos);
    for (std::size_t i = 0; i < files.size(); ++i) {
        INFO(files[i]);
        REQUIRE(fs::exists(d.path() / files[i]));
        CHECK(slurp_file(d.path() / files[i]) == before[i]);
    }
    auto db = EchoDatabase::open(d.path() / "echo.db");
    REQUIRE(db.has_value());
    CHECK(db->get_config("which", "") == "echo");
}

TEST_CASE("adopt_legacy_echo_db: a WAL at both names fails closed and moves nothing",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path()); // tar.db + tar.db-wal holding the row wal_marker=x
    spit_file(d.path() / "echo.db-wal", "a foreign WAL with distinct bytes");

    const std::array<const char*, 3> files = {"tar.db", "tar.db-wal", "echo.db-wal"};
    std::vector<std::string> before;
    for (const char* f : files)
        before.push_back(slurp_file(d.path() / f));

    auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db");
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("tar.db-wal") != std::string::npos);
    CHECK(adopted.error().find("echo.db-wal") != std::string::npos);
    CHECK_FALSE(fs::exists(d.path() / "echo.db"));
    for (std::size_t i = 0; i < files.size(); ++i) {
        INFO(files[i]);
        REQUIRE(fs::exists(d.path() / files[i]));
        CHECK(slurp_file(d.path() / files[i]) == before[i]); // the committed WAL-only row is intact
    }

    // The state is the same fail-closed one an interrupted adoption leaves: open() refuses. The
    // phrase is quoted verbatim in docs/user-manual/upgrading.md; this pin keeps the two in step.
    auto refused = EchoDatabase::open(d.path() / "echo.db");
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("tar.db") != std::string::npos);
    CHECK(refused.error().find("not adopted - refusing") != std::string::npos);

    // The documented remedy (upgrading.md): move the echo.db sidecar out, restart, and the
    // adoption continues with the committed WAL-only row intact.
    fs::remove(d.path() / "echo.db-wal");
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db").has_value());
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK(fs::exists(d.path() / "echo.db-wal"));
    auto resumed = EchoDatabase::open(d.path() / "echo.db");
    REQUIRE(resumed.has_value());
    CHECK(resumed->get_config("wal_marker", "") == "x");
}

TEST_CASE("EchoDatabase::open refuses to create a fresh echo.db beside an unadopted tar.db",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db(d.path());
    const auto echo_db = d.path() / "echo.db";

    auto refused = EchoDatabase::open(echo_db);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("tar.db") != std::string::npos);
    CHECK(refused.error().find("not adopted - refusing") != std::string::npos); // quoted in the guide
    CHECK_FALSE(fs::exists(echo_db));

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->schema_version() == 10);
}

TEST_CASE("adopt_legacy_echo_db: a fresh directory is a no-op and opens at schema 9",
          "[echo][store][adopt]") {
    ScratchDir d;
    const auto echo_db = d.path() / "echo.db";
    REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
    CHECK_FALSE(fs::exists(echo_db));
    {
        auto db = EchoDatabase::open(echo_db);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 10);
    }
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    auto again = EchoDatabase::open(echo_db);
    REQUIRE(again.has_value());
    CHECK(again->schema_version() == 10);
}

TEST_CASE("EchoDatabase: a v8 file already holding echo_* tables only gets the version marker",
          "[echo][store][migration][v9]") {
    ScratchDir d;
    const auto echo_db = d.path() / "echo.db";
    {
        auto db = EchoDatabase::open(echo_db);
        REQUIRE(db.has_value());
        REQUIRE(db->set_config("kept", "yes"));
    }
    {
        SqliteOwner o;
        REQUIRE(sqlite3_open(echo_db.string().c_str(), &o.db) == SQLITE_OK);
        exec_sql(o.db, "UPDATE echo_config SET value = '8' WHERE key = 'schema_version'");
    }
    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->schema_version() == 10);
    CHECK(db->get_config("kept", "") == "yes");
}

TEST_CASE("adopt_legacy_echo_db: a rename that cannot complete fails closed and open() refuses too",
          "[echo][store][adopt]") {
    // Only the "make tar.db -> echo.db fail" set-up differs per OS; every assertion is shared.
#ifndef _WIN32
    if (::geteuid() == 0)
        SKIP("root bypasses directory permissions; cannot make the rename fail");
#endif
    ScratchDir d;
    make_legacy_tar_db(d.path());
#ifndef _WIN32
    // POSIX: rename needs write permission on the directory.
    struct DirGuard {
        fs::path dir;
        ~DirGuard() {
            std::error_code ec;
            fs::permissions(dir, fs::perms::owner_all, fs::perm_options::add, ec);
        }
    } guard{d.path()};
    std::error_code perm_ec;
    fs::permissions(d.path(),
                    fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write,
                    fs::perm_options::remove, perm_ec);
    REQUIRE_FALSE(perm_ec);
#else
    // Windows: a directory's read-only attribute does not stop rename/create inside it, so hold
    // tar.db open WITHOUT FILE_SHARE_DELETE instead -- the move then fails with
    // ERROR_SHARING_VIOLATION (elevation does not bypass it). Declared after ScratchDir so the
    // handle closes before the directory is removed.
    HANDLE raw = ::CreateFileW((d.path() / "tar.db").c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(raw != INVALID_HANDLE_VALUE);
    const std::unique_ptr<void, decltype(&::CloseHandle)> held{raw, ::CloseHandle};
#endif

    const auto echo_db = d.path() / "echo.db";
    auto adopted = yuzu::agent::adopt_legacy_echo_db(echo_db);
    REQUIRE_FALSE(adopted.has_value());
    CHECK(adopted.error().find("tar.db") != std::string::npos);
    CHECK_FALSE(fs::exists(echo_db));

    auto opened = EchoDatabase::open(echo_db);
    REQUIRE_FALSE(opened.has_value());
    CHECK(opened.error().find("tar.db") != std::string::npos);
    CHECK_FALSE(fs::exists(echo_db));
}

// ── Echo open hardening: busy, links, shared quarantine, planted-file self-heal ──────────
//
// Helpers (SqliteOwner, exec_sql, slurp_file, spit_file, make_legacy_tar_db*, ScratchDir) come from
// the adoption block above.
namespace {

// Names in `dir` that start with `prefix`.
std::vector<std::string> names_with_prefix(const fs::path& dir, const std::string& prefix) {
    std::vector<std::string> out;
    for (const auto& e : fs::directory_iterator(dir)) {
        const std::string n = e.path().filename().string();
        if (n.rfind(prefix, 0) == 0)
            out.push_back(n);
    }
    return out;
}

// A closed, healthy echo.db with one recognisable config row.
fs::path make_healthy_echo_db(const fs::path& dir) {
    REQUIRE(fs::create_directories(dir));
    const auto db = dir / "echo.db";
    auto opened = EchoDatabase::open(db);
    REQUIRE(opened.has_value());
    REQUIRE(opened->set_config("process_enabled", "false")); // a paused source: must survive
    return db;
}

// True only when `ec` says this account may not create a symbolic link (POSIX: EPERM/EACCES;
// Windows: ERROR_PRIVILEGE_NOT_HELD, which MSVC's std::filesystem reports as the raw Win32 code in
// the system category, so the value is compared and no errc mapping is relied on). Any other
// failure, `file_exists` above all, is a defect in the test's set-up and must fail the case, not
// skip it.
bool symlink_unavailable(const std::error_code& ec) {
#ifdef _WIN32
    return ec.value() == ERROR_PRIVILEGE_NOT_HELD;
#else
    return ec == std::errc::operation_not_permitted || ec == std::errc::permission_denied;
#endif
}

// Call with the error code a create_symlink / create_directory_symlink filled: nothing when it
// succeeded, SKIP when only a missing privilege stopped it, FAIL for anything else. `file_exists`
// is what a seam moved before the quarantine would hit (the name still exists), and it must fail
// the case.
void skip_unless_symlink_capable(const std::error_code& ec) {
    if (!ec)
        return;
    if (symlink_unavailable(ec))
        SKIP("cannot create a symlink here: " << ec.message());
    FAIL("symlink creation failed for another reason: " << ec.message());
}

} // namespace

// #7286. echo.db is WAL-mode, so a plain BEGIN IMMEDIATE writer would NOT block a reader and this
// case would pass green without proving anything. A connection in locking_mode=EXCLUSIVE does:
// it bypasses the wal-index and holds the file, so every other connection's first read returns
// SQLITE_BUSY once its busy handler expires. The case records the rc that integrity_check sees on
// a connection configured like open()'s (busy timeout 0 here, so the probe itself does not wait),
// asserts it is BUSY, and then asserts open() refuses WITHOUT moving the file. open() waits out
// its full 5 s busy timeout once: acceptable for a boot-time call, and the only wait in the case.
TEST_CASE("EchoDatabase: a busy echo.db is refused and never quarantined (#7286)",
          "[echo][store][lifecycle][corruption]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_busy_"};
    const auto db = make_healthy_echo_db(dir.path);

    auto holder = std::make_unique<SqliteOwner>();
    REQUIRE(sqlite3_open_v2(db.string().c_str(), &holder->db, SQLITE_OPEN_READWRITE, nullptr) ==
            SQLITE_OK);
    exec_sql(holder->db, "PRAGMA locking_mode=EXCLUSIVE");
    exec_sql(holder->db, "BEGIN IMMEDIATE");
    exec_sql(holder->db, "INSERT OR REPLACE INTO echo_config(key, value) VALUES ('busy_probe', '1')");

    {   // What the integrity stage observes: BUSY (or LOCKED), not a snapshot read.
        SqliteOwner probe;
        REQUIRE(sqlite3_open_v2(db.string().c_str(), &probe.db, SQLITE_OPEN_READWRITE, nullptr) ==
                SQLITE_OK);
        sqlite3_busy_timeout(probe.db, 0);
        sqlite3_stmt* raw = nullptr;
        int rc = sqlite3_prepare_v2(probe.db, "PRAGMA integrity_check", -1, &raw, nullptr);
        if (rc == SQLITE_OK)
            rc = sqlite3_step(raw);
        sqlite3_finalize(raw);
        INFO("observed rc at the integrity stage = " << rc << " (" << sqlite3_errstr(rc) << ")");
        CHECK(((rc & 0xff) == SQLITE_BUSY || (rc & 0xff) == SQLITE_LOCKED));
    }

    const auto started = std::chrono::steady_clock::now();
    auto refused = EchoDatabase::open(db);
    // The refusal came AFTER the busy timeout ran out, not from an immediate BUSY: open() set the
    // timeout on the connection before the integrity check (kBusyTimeoutMs = 5000 in echo_db.cpp).
    // A lower bound on a wait that already happens; load can only lengthen it, never shorten it.
    CHECK(std::chrono::steady_clock::now() - started >= std::chrono::seconds{4});
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("echo.db is busy") != std::string::npos);
    CHECK(refused.error().find("not quarantined") != std::string::npos);
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty()); // nothing moved aside
    CHECK(fs::exists(db));

    exec_sql(holder->db, "COMMIT");
    holder.reset();

    // The holder is gone: the very same file opens, healthy, with its paused source intact.
    auto reopened = EchoDatabase::open(db);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->get_config("process_enabled", "true") == "false");
    CHECK(reopened->get_config("busy_probe", "") == "1");
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty());
}

// #7286. IOERR-class failures cannot be provoked portably at the integrity stage, so the rc
// classifier open() uses is a pure function, pinned here: codes that say nothing about the file's
// health are "unreadable" and make open() refuse without moving anything (rationale:
// check_integrity, echo_db.cpp).
TEST_CASE("classify_integrity_rc: only CORRUPT and NOTADB quarantine while BUSY refuses and the rest is unreadable (#7286)",
          "[echo][store][corruption]") {
    // Busy: the holder's problem, not the file's -- including the extended codes.
    CHECK(classify_integrity_rc(SQLITE_BUSY) == IntegrityCheck::busy);
    CHECK(classify_integrity_rc(SQLITE_LOCKED) == IntegrityCheck::busy);
    CHECK(classify_integrity_rc(SQLITE_BUSY_SNAPSHOT) == IntegrityCheck::busy);
    CHECK(classify_integrity_rc(SQLITE_BUSY_RECOVERY) == IntegrityCheck::busy);
    // Corrupt: the two codes the sibling store also quarantines on, extended codes included.
    CHECK(classify_integrity_rc(SQLITE_CORRUPT) == IntegrityCheck::corrupt);
    CHECK(classify_integrity_rc(SQLITE_CORRUPT_VTAB) == IntegrityCheck::corrupt);
    CHECK(classify_integrity_rc(SQLITE_NOTADB) == IntegrityCheck::corrupt);
    // Unreadable: environmental or transient faults must never move a healthy file away.
    for (const int rc : {SQLITE_IOERR, SQLITE_IOERR_READ, SQLITE_CANTOPEN, SQLITE_PERM,
                         SQLITE_READONLY, SQLITE_NOMEM, SQLITE_FULL, SQLITE_PROTOCOL, SQLITE_ERROR,
                         SQLITE_DONE}) {
        INFO("rc = " << rc << " (" << sqlite3_errstr(rc) << ")");
        CHECK(classify_integrity_rc(rc) == IntegrityCheck::unreadable);
    }
}

// #7286. open() acting on the `unreadable` verdict: the integrity check fails for a reason that is
// neither corruption nor contention (here SQLITE_AUTH from an authorizer on open()'s first
// connection; in the field an I/O, permission or space error), so open() refuses, moves nothing,
// and the very same file opens on the next start. Mapping `unreadable` onto the corrupt path
// would quarantine this healthy file and boot a fresh database with every paused source re-enabled.
TEST_CASE("EchoDatabase: an unreadable integrity check refuses and quarantines nothing (#7286)",
          "[echo][store][lifecycle][corruption]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_unreadable_"};
    const auto db = make_healthy_echo_db(dir.path);

    {
        const AutoExtensionGuard hook;
        g_deny_integrity_check = true;
        auto refused = EchoDatabase::open(db);
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().find("could not be checked") != std::string::npos);
        CHECK(refused.error().find("not quarantined") != std::string::npos);
    }
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty()); // nothing moved aside
    CHECK(fs::exists(db));

    // The next start: the same file, healthy, with its paused source intact.
    auto reopened = EchoDatabase::open(db);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->get_config("process_enabled", "true") == "false");
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty());
}

TEST_CASE("EchoDatabase: a genuinely corrupt echo.db is still quarantined and its handle is closed (#7286 and #6698)",
          "[echo][store][lifecycle][corruption]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_stillcorrupt_"};
    const auto db = make_healthy_echo_db(dir.path);
    for (const char* sfx : {"-wal", "-shm"}) {
        std::error_code ec;
        fs::remove(fs::path{db.string() + sfx}, ec);
    }
    spit_file(db, "this is not a SQLite database -- busy change must not hide it");

    {
        auto reopened = EchoDatabase::open(db);
        REQUIRE(reopened.has_value());
        REQUIRE(reopened->quarantined_this_open().has_value());
        CHECK(reopened->get_config("process_enabled", "true") == "true"); // fresh database
    }
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").size() == 1);

    // The failed-integrity handle was closed exactly once: nothing still holds the file, so a raw
    // connection takes the exclusive lock at once (a leaked handle would answer SQLITE_BUSY).
    SqliteOwner o;
    REQUIRE(sqlite3_open_v2(db.string().c_str(), &o.db, SQLITE_OPEN_READWRITE, nullptr) ==
            SQLITE_OK);
    sqlite3_busy_timeout(o.db, 0);
    CHECK(sqlite3_exec(o.db, "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_exec(o.db, "ROLLBACK", nullptr, nullptr, nullptr);
}

// #1527. A link at the database path (or a sidecar) is refused before anything is opened, moved or
// secured; the link's target is never touched. A dangling link is refused as well. Windows needs a
// privilege to create a symlink, so the case skips where it cannot; the junction/reparse arm is
// exercised on the Windows leg only.
TEST_CASE("EchoDatabase: a symlink at echo.db or a sidecar is refused (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
        for (const bool dangling : {false, true}) {
            INFO("suffix='" << suffix << "' dangling=" << dangling);
            yuzu::test::TempDir dir{"yuzu_test_echo_link_"};
            REQUIRE(fs::create_directories(dir.path));
            const auto db = dir.path / "echo.db";
            const fs::path target = dir.path / "elsewhere.bin";
            if (!dangling)
                spit_file(target, "target bytes");
            const fs::path link{db.string() + suffix};
            std::error_code ec;
            fs::create_symlink(target, link, ec);
            skip_unless_symlink_capable(ec);

            auto refused = EchoDatabase::open(db);
            REQUIRE_FALSE(refused.has_value());
            CHECK(refused.error().find("symbolic link or reparse point") != std::string::npos);
            CHECK(fs::is_symlink(link));                      // not replaced, not followed
            CHECK(fs::exists(target) == !dangling);           // nothing created through it
            if (!dangling)
                CHECK(slurp_file(target) == "target bytes");   // never opened or quarantined
            CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty());
        }
    }
}

// #1527. A quarantine frees the echo.db names for a moment. A link planted there before the reopen
// is refused exactly like one found at the first check, and its target is never opened through:
// the seam stands in for a swap the first check cannot see.
TEST_CASE("EchoDatabase: a link planted after a quarantine is refused before the reopen (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    for (const char* suffix : {"", "-wal"}) {
        INFO("suffix='" << suffix << "'");
        yuzu::test::TempDir dir{"yuzu_test_echo_relink_"};
        REQUIRE(fs::create_directories(dir.path));
        const auto db = dir.path / "echo.db";
        spit_file(db, "this is not a SQLite database");
        const fs::path target = dir.path / "elsewhere.bin";
        spit_file(target, "target bytes");
        const fs::path link{db.string() + suffix};
        std::error_code planted;
        bool fired = false;
        OpenSeams seams;
        seams.after_quarantine = [&] {
            fired = true;
            fs::create_symlink(target, link, planted);
        };

        auto refused = EchoDatabase::open(db, seams);
        REQUIRE(fired); // a seam that never ran would leave every check below vacuous
        skip_unless_symlink_capable(planted);
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().find("symbolic link or reparse point") != std::string::npos);
        CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").size() == 1); // the quarantine stood
        CHECK(fs::is_symlink(link));                                        // not replaced
        CHECK(slurp_file(target) == "target bytes");                        // never opened through
    }
}

// #1527. The window the two cases below cover is the one between the corrupt verdict and the
// hard-link claim, which no name check reaches: `quarantine_ops.link` runs exactly there, so the
// seam swaps a symlink in before the real create_hard_link. On macOS link(2) follows the link and
// would claim its TARGET (then chmod it 0600); on Linux the link itself would travel and the
// following chmod would reach the target. Either way the victim must keep its mode, its single
// name and its bytes, and nothing of the victim's may appear under a quarantine name.
TEST_CASE("EchoDatabase: a link swapped in at echo.db between the verdict and the claim is caught and its target untouched (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_preclaim_"};
    REQUIRE(fs::create_directories(dir.path));
    const auto db = dir.path / "echo.db";
    spit_file(db, "this is not a SQLite database");
    const fs::path victim = dir.path / "victim.bin";
    spit_file(victim, "victim bytes");
    std::error_code pec;
    fs::permissions(victim, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, pec);
    REQUIRE_FALSE(pec);
    const auto victim_mode = fs::status(victim).permissions();
    std::error_code planted;
    bool fired = false;
    OpenSeams seams;
    seams.quarantine_ops.link = [&](const fs::path& from, const fs::path& to, std::error_code& ec) {
        fired = true;
        fs::remove(from);
        fs::create_symlink(victim, from, planted);
        if (planted) {
            ec = planted;
            return;
        }
        fs::create_hard_link(from, to, ec); // the real claim, now over the planted link
    };

    auto refused = EchoDatabase::open(db, seams);
    REQUIRE(fired);
    skip_unless_symlink_capable(planted);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("corrupt and unmovable") != std::string::npos); // fail closed
    CHECK(fs::status(victim).permissions() == victim_mode);                   // never chmodded
    CHECK(fs::hard_link_count(victim) == 1);                                   // never linked
    CHECK(slurp_file(victim) == "victim bytes");
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty()); // the claim was released
    CHECK(fs::is_symlink(db));                                      // left for the operator
}

// Identity is lstat device+inode, which Windows does not have here; there the regular-file swap
// is a recorded residual (header of sqlite_quarantine.hpp), so the next two cases are POSIX only.
#ifndef _WIN32
// A REGULAR file swapped for another regular file passes every no-follow regular-file test, so
// only the identity compare (device + inode read right after the open) can catch it. The seam
// runs between the pre-claim checks and the post-link re-check, where a second recovery or a
// planter can replace the name. The claim landed on the judged file, so that file keeps its
// claimed name (its only name now), the planted file keeps the name, and Echo fails closed.
TEST_CASE("EchoDatabase: a regular file swapped in at echo.db between the verdict and the claim is refused and fails closed (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_preclaim_reg_"};
    REQUIRE(fs::create_directories(dir.path));
    const auto db = dir.path / "echo.db";
    spit_file(db, "this is not a SQLite database");
    bool fired = false;
    OpenSeams seams;
    seams.quarantine_ops.link = [&](const fs::path& from, const fs::path& to, std::error_code& ec) {
        fired = true;
        fs::create_hard_link(from, to, ec); // the real claim lands on the judged file
        fs::remove(from);
        spit_file(from, "planted regular file"); // then the name is replaced by a plain file
    };

    auto refused = EchoDatabase::open(db, seams);
    REQUIRE(fired);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("corrupt and unmovable") != std::string::npos); // fail closed
    CHECK(slurp_file(db) == "planted regular file"); // the file at the name is left alone
    CHECK(fs::hard_link_count(db) == 1);
    // The judged (corrupt) file is the evidence and the claim is its only name: it is kept.
    const auto kept = names_with_prefix(dir.path, "echo.db.corrupt-");
    REQUIRE(kept.size() == 1);
    CHECK(slurp_file(dir.path / kept[0]) == "this is not a SQLite database");
}

// The identity is read right after the open, not after the integrity check: a name swapped while
// the check runs (it can wait the busy timeout and scan every page) is not the file SQLite judged,
// so the quarantine must refuse it. Before the read was hoisted, the planted file was quarantined
// and a fresh database opened over its name.
TEST_CASE("EchoDatabase: a regular file swapped in at echo.db while the integrity check runs is refused and fails closed (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_midcheck_"};
    REQUIRE(fs::create_directories(dir.path));
    const auto db = dir.path / "echo.db";
    spit_file(db, "this is not a SQLite database");
    bool fired = false;
    OpenSeams seams;
    seams.before_integrity_check = [&] {
        fired = true;
        fs::remove(db);
        spit_file(db, "planted while the check ran");
    };

    auto refused = EchoDatabase::open(db, seams);
    REQUIRE(fired);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("corrupt and unmovable") != std::string::npos); // fail closed
    CHECK(slurp_file(db) == "planted while the check ran");                   // left in place
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty());            // nothing moved
}
#endif // !_WIN32

TEST_CASE("EchoDatabase: a link swapped in at echo.db-wal before the claim travels as a link and its target is never chmodded (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_preclaim_wal_"};
    REQUIRE(fs::create_directories(dir.path));
    const auto db = dir.path / "echo.db";
    spit_file(db, "this is not a SQLite database");
    const fs::path victim = dir.path / "victim.bin";
    spit_file(victim, "victim bytes"); // non-empty: an empty sidecar is simply removed
    std::error_code pec;
    fs::permissions(victim, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, pec);
    REQUIRE_FALSE(pec);
    const auto victim_mode = fs::status(victim).permissions();
    const fs::path wal{db.string() + "-wal"};
    std::error_code planted;
    bool fired = false;
    OpenSeams seams;
    seams.quarantine_ops.link = [&](const fs::path& from, const fs::path& to, std::error_code& ec) {
        // Plant the link on the FIRST claim only. Where the sidecar is claimed by a hard link
        // too (Windows), the seam runs again for the planted `-wal` itself, and a second
        // create_symlink over the name it already holds reports file_exists, which
        // skip_unless_symlink_capable rightly treats as a set-up defect.
        if (!fired) {
            fired = true;
            // Windows can leave a real -wal behind from the failed open; the planted link must
            // take that name, so clear it first (an absent file is fine).
            std::error_code rm;
            fs::remove(wal, rm);
            fs::create_symlink(victim, wal, planted);
        }
        fs::create_hard_link(from, to, ec);
    };

    auto opened = EchoDatabase::open(db, seams);
    REQUIRE(fired);
    skip_unless_symlink_capable(planted);
    CHECK(fs::status(victim).permissions() == victim_mode); // the sidecar chmod did not follow
    CHECK(fs::hard_link_count(victim) == 1);
    CHECK(slurp_file(victim) == "victim bytes");
    const auto quarantined = names_with_prefix(dir.path, "echo.db.corrupt-");
    REQUIRE(opened.has_value()); // the main claim stood and the fresh file reopened clean
    // The link itself travelled under the quarantine name (one entry is the main file, one the
    // moved -wal), still a link, never resolved.
    REQUIRE(quarantined.size() == 2);
    const fs::path moved_wal = dir.path / (quarantined[0].ends_with("-wal") ? quarantined[0]
                                                                            : quarantined[1]);
    CHECK(fs::is_symlink(moved_wal));
    CHECK_FALSE(fs::is_symlink(wal)); // the fresh database's own -wal, not the planted link
}

// The recheck after a quarantine names the sqlite rc that ended it, so an operator can tell a file
// that is corrupt again (26, SQLITE_NOTADB) from a busy or unreadable one. A non-database written
// into the freed name by the seam makes the reopened file fail the check with a known rc.
TEST_CASE("EchoDatabase: a file that still fails integrity_check after a quarantine is refused with its rc (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_recheck_"};
    REQUIRE(fs::create_directories(dir.path));
    const auto db = dir.path / "echo.db";
    spit_file(db, "this is not a SQLite database");
    bool fired = false;
    OpenSeams seams;
    seams.after_quarantine = [&] {
        fired = true;
        spit_file(db, "still not a database");
    };

    auto refused = EchoDatabase::open(db, seams);
    REQUIRE(fired);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("still fails integrity_check (sqlite rc 26)") != std::string::npos);
    CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").size() == 1);
}

#ifndef _WIN32
// #1527. What binds the name check to the open on POSIX: the vendored SQLite, given the flags
// open() uses, refuses a symbolic link at the database name itself rather than following it (the
// directory part is resolved by open() first, so a link in an ancestor such as macOS's /var is no
// refusal). A build of SQLite without lstat/readlink support would pass the link through.
TEST_CASE("sqlite: SQLITE_OPEN_NOFOLLOW refuses a symlink at the database name (#1527)",
          "[echo][store][lifecycle][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_nofollow_"};
    REQUIRE(fs::create_directories(dir.path));
    const fs::path resolved = fs::canonical(dir.path);
    const fs::path target = resolved / "elsewhere.db";
    const fs::path link = resolved / "echo.db";
    std::error_code ec;
    fs::create_symlink(target, link, ec);
    skip_unless_symlink_capable(ec);

    SqliteOwner o;
    const int rc = sqlite3_open_v2(link.string().c_str(), &o.db,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                       SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW,
                                   nullptr);
    CHECK(rc == SQLITE_CANTOPEN);
    CHECK_FALSE(fs::exists(target)); // nothing was created through the link
}

// #1527. What the case above does not reach: that open() itself passes SQLITE_OPEN_NOFOLLOW on its
// own sqlite3_open_v2 calls. The name check fires first, so a link planted before it is refused by
// the check, not by the flag. `before_sqlite_open` runs after the last check and right before the
// open, which is the window the flag closes; each case swaps echo.db for a link there. Drop the
// flag from the main open and the first one creates the link's target through it; drop it from
// the read-only query connection and the second one opens a non-database through the link.
TEST_CASE("EchoDatabase: a link swapped in at echo.db right before SQLite opens it is refused (#1527)",
          "[echo][store][lifecycle][corruption][hardening]") {
    for (const bool read_only_open : {false, true}) {
        INFO("read_only_open=" << read_only_open);
        yuzu::test::TempDir dir{"yuzu_test_echo_swap_"};
        const auto db = make_healthy_echo_db(dir.path);
        const fs::path target = dir.path / "elsewhere.db";
        // A dangling target is enough for the main open (SQLite would CREATE it through a followed
        // link). The read-only open needs a real file: a dangling one fails READONLY with or
        // without the flag and would not tell the two apart.
        if (read_only_open)
            spit_file(target, "target bytes");
        // Call 1 is the main open; with no quarantine, call 2 is the read-only query connection.
        const int swap_at = read_only_open ? 2 : 1;
        int calls = 0;
        bool fired = false;
        std::error_code planted;
        OpenSeams seams;
        seams.before_sqlite_open = [&] {
            if (++calls != swap_at)
                return;
            fired = true;
            std::error_code removed;
            fs::remove(db, removed);
            fs::create_symlink(target, db, planted);
        };

        auto opened = EchoDatabase::open(db, seams);
        REQUIRE(fired);
        skip_unless_symlink_capable(planted);
        CHECK(fs::is_symlink(db)); // not replaced
        if (!read_only_open) {
            REQUIRE_FALSE(opened.has_value());
            CHECK(opened.error().find("failed to open echo.db: unable to open database file") !=
                  std::string::npos);
            CHECK_FALSE(fs::exists(target)); // nothing was created through the link
            CHECK(names_with_prefix(dir.path, "echo.db.corrupt-").empty());
        } else {
            // The main connection is already open, so the agent runs; only the sandboxed query
            // connection is refused (fail closed), and the link's target is never read.
            REQUIRE(opened.has_value());
            auto query = opened->execute_user_query("SELECT 1", 1);
            REQUIRE_FALSE(query.has_value());
            CHECK(query.error() == "query engine unavailable");
            CHECK(slurp_file(target) == "target bytes");
        }
    }
}

// #1527. A data directory that itself sits behind a link is legitimate (macOS's /var is one, and so
// is a symlinked /var/lib): open() resolves the directory once, so only a link at the database name
// trips the no-follow flag. macOS pins this incidentally through its temp directory; on Linux /tmp
// is not a link, so this case is what keeps the canonicalisation from being reverted unnoticed.
TEST_CASE("EchoDatabase: a data directory behind a symlink opens and reopens (#1527)",
          "[echo][store][lifecycle][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_linkeddir_"};
    const fs::path real = dir.path / "real";
    const fs::path linked = dir.path / "linked";
    REQUIRE(fs::create_directories(real));
    std::error_code ec;
    fs::create_directory_symlink(real, linked, ec);
    skip_unless_symlink_capable(ec);

    {
        auto first = EchoDatabase::open(linked / "echo.db");
        REQUIRE(first.has_value());
        REQUIRE(first->set_config("via_link", "1"));
    }
    CHECK(fs::exists(real / "echo.db"));
    auto second = EchoDatabase::open(linked / "echo.db");
    REQUIRE(second.has_value());
    CHECK(second->get_config("via_link", "") == "1");
}

// #6366. A non-empty -wal beside a corrupt echo.db is evidence. A second connection keeps the WAL
// open (and un-checkpointed) across the corrupt reopen, as a concurrent reader would; the quarantine
// must carry the WAL byte for byte and leave nothing byte-ful beside the fresh database.
TEST_CASE("EchoDatabase: a non-empty -wal held open by another connection travels with the quarantine (#6366)",
          "[echo][store][lifecycle][corruption]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_realwal_"};
    const auto db = make_healthy_echo_db(dir.path);
    const fs::path wal{db.string() + "-wal"};

    SqliteOwner keeper;
    REQUIRE(sqlite3_open_v2(db.string().c_str(), &keeper.db, SQLITE_OPEN_READWRITE, nullptr) ==
            SQLITE_OK);
    exec_sql(keeper.db, "PRAGMA journal_mode=WAL");
    exec_sql(keeper.db, "PRAGMA wal_autocheckpoint=0");
    exec_sql(keeper.db, "INSERT OR REPLACE INTO echo_config(key, value) VALUES ('wal_row', 'x')");
    REQUIRE(fs::exists(wal));
    REQUIRE(fs::file_size(wal) > 0);
    const std::string wal_bytes = slurp_file(wal);
    spit_file(db, "this is not a SQLite database -- corrupt main file beside a live WAL");
#ifndef _WIN32
    // Seed the live -wal group/other-readable so the quarantined copy's mode proves the sidecar
    // was re-secured, not inherited.
    std::error_code pec;
    fs::permissions(wal, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, pec);
    REQUIRE_FALSE(pec);
#endif

    auto reopened = EchoDatabase::open(db);
    REQUIRE(reopened.has_value());
    REQUIRE(reopened->quarantined_this_open().has_value());
    const std::string qfile = reopened->get_config("db_health_last_quarantine_file", "");
    REQUIRE_FALSE(qfile.empty());
    REQUIRE(fs::exists(dir.path / (qfile + "-wal")));
    CHECK(slurp_file(dir.path / (qfile + "-wal")) == wal_bytes); // byte for byte
#ifndef _WIN32
    for (const std::string name : {qfile, qfile + "-wal"}) {
        INFO("quarantined=" << name);
        CHECK((fs::status(dir.path / name).permissions() & fs::perms::mask) ==
              (fs::perms::owner_read | fs::perms::owner_write)); // owner-only (0600)
    }
#endif
    CHECK((!fs::exists(wal) || slurp_file(wal) != wal_bytes));   // not replayed by the fresh file
}

TEST_CASE("EchoDatabase: a rollback journal beside echo.db is owner-only after open (#6366)",
          "[echo][store][lifecycle][hardening]") {
    yuzu::test::TempDir dir{"yuzu_test_echo_jmode_"};
    const auto db = make_healthy_echo_db(dir.path);
    const fs::path journal{db.string() + "-journal"};
    spit_file(journal, ""); // empty: not hot, so SQLite leaves it and open() only re-modes it
    std::error_code ec;
    fs::permissions(journal, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                                 fs::perms::others_read,
                    fs::perm_options::replace, ec);
    REQUIRE_FALSE(ec);

    auto opened = EchoDatabase::open(db);
    REQUIRE(opened.has_value());
    REQUIRE(fs::exists(journal));
    CHECK((fs::status(journal).permissions() & fs::perms::mask) ==
          (fs::perms::owner_read | fs::perms::owner_write));
}
#endif // !_WIN32

// #6695. The both-present arm's decisions, driven with a fake owner probe so they run on every
// host (the real Windows probe is EchoDbOwnerProbe; it is exercised on the Windows leg).
namespace {

using yuzu::agent::EchoFileOwner;

// Probe by file name: anything not listed is ours.
yuzu::agent::EchoOwnerProbe probe_by_name(std::map<std::string, EchoFileOwner> table) {
    return [table = std::move(table)](const fs::path& f) {
        const auto it = table.find(f.filename().string());
        return it == table.end() ? EchoFileOwner::ours : it->second;
    };
}

} // namespace

TEST_CASE("adopt_legacy_echo_db: a foreign-owned echo.db beside tar.db is moved aside alone and tar.db adopted (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "planted by another account");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(
                echo_db, probe_by_name({{"echo.db", EchoFileOwner::foreign}}))
                .has_value());
    const auto planted = names_with_prefix(d.path(), "echo.db.planted-");
    REQUIRE(planted.size() == 1);
    CHECK(slurp_file(d.path() / planted[0]) == "planted by another account"); // kept as evidence
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->get_config("wal_marker", "") == "x"); // the legitimate WAL-only row came along
}

TEST_CASE("adopt_legacy_echo_db: an owner-verified echo.db wins and nothing is moved (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db(d.path());
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "ours");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db, probe_by_name({})).has_value());
    CHECK(slurp_file(echo_db) == "ours");
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty());
}

TEST_CASE("adopt_legacy_echo_db: an owner that cannot be resolved moves nothing (#6695)",
          "[echo][store][adopt]") {
    for (const auto& unresolved : {std::string{"echo.db"}, std::string{"echo.db-wal"}}) {
        INFO("unresolvable: " << unresolved);
        ScratchDir d;
        make_legacy_tar_db(d.path());
        const auto echo_db = d.path() / "echo.db";
        spit_file(echo_db, "maybe planted");
        spit_file(d.path() / "echo.db-wal", "maybe a wal");
        // echo.db-wal unresolvable, echo.db foreign -> still nothing moves; echo.db unresolvable -> same.
        auto table = std::map<std::string, EchoFileOwner>{{unresolved, EchoFileOwner::unknown}};
        if (unresolved != "echo.db")
            table["echo.db"] = EchoFileOwner::foreign;

        REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db, probe_by_name(table)).has_value());
        CHECK(slurp_file(echo_db) == "maybe planted");
        CHECK(slurp_file(d.path() / "echo.db-wal") == "maybe a wal");
        CHECK(fs::exists(d.path() / "tar.db"));
        CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty());
    }
}

// The documented resume state is "tar.db present, its WAL already moved to echo.db-wal". A planted
// echo.db appearing on top of it must not take the legitimate WAL away: only the foreign file moves.
TEST_CASE("adopt_legacy_echo_db: an interrupted adoption plus a planted echo.db keeps the resumable WAL (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    fs::rename(d.path() / "tar.db-wal", d.path() / "echo.db-wal"); // the interrupted step
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "planted by another account");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(
                echo_db, probe_by_name({{"echo.db", EchoFileOwner::foreign}}))
                .has_value());
    const auto planted = names_with_prefix(d.path(), "echo.db.planted-");
    REQUIRE(planted.size() == 1); // echo.db alone: no planted-*-wal, the group was not carried off
    CHECK(planted[0].find("-wal") == std::string::npos);
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK(fs::exists(d.path() / "echo.db-wal"));

    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->get_config("wal_marker", "") == "x"); // the committed WAL-only row is still there
}

// The second planted shape (#6695): no echo.db at all, only a foreign echo.db-wal beside the real
// tar.db-wal. Before the self-heal this was refused as a sidecar collision for good.
TEST_CASE("adopt_legacy_echo_db: a foreign-owned echo.db-wal beside tar.db-wal is moved aside alone and tar.db adopted (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path()); // tar.db + tar.db-wal holding wal_marker=x
    const auto echo_db = d.path() / "echo.db";
    spit_file(d.path() / "echo.db-wal", "planted sidecar");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(
                echo_db, probe_by_name({{"echo.db-wal", EchoFileOwner::foreign}}))
                .has_value());
    const auto planted = names_with_prefix(d.path(), "echo.db-wal.planted-");
    REQUIRE(planted.size() == 1);
    CHECK(slurp_file(d.path() / planted[0]) == "planted sidecar"); // kept as evidence
    CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty()); // nothing else moved
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    CHECK_FALSE(fs::exists(d.path() / "tar.db-wal"));
    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->get_config("wal_marker", "") == "x"); // the legitimate WAL came along, not the plant
}

TEST_CASE("adopt_legacy_echo_db: an echo.db-wal that is ours or unresolvable beside tar.db-wal still fails closed (#6695)",
          "[echo][store][adopt]") {
    for (const auto owner : {EchoFileOwner::ours, EchoFileOwner::unknown}) {
        INFO("echo.db-wal owner = " << static_cast<int>(owner));
        ScratchDir d;
        make_legacy_tar_db_with_wal(d.path());
        spit_file(d.path() / "echo.db-wal", "a WAL with distinct bytes");

        auto adopted = yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db",
                                                         probe_by_name({{"echo.db-wal", owner}}));
        REQUIRE_FALSE(adopted.has_value());
        CHECK(adopted.error().find("both exist") != std::string::npos);
        CHECK(fs::exists(d.path() / "tar.db"));
        CHECK(fs::exists(d.path() / "tar.db-wal"));
        CHECK(slurp_file(d.path() / "echo.db-wal") == "a WAL with distinct bytes");
        CHECK(names_with_prefix(d.path(), "echo.db-wal.planted-").empty());
    }
}

// A lone echo.db-wal with no tar.db-wal twin is the documented resume state: never probed, never
// moved, whatever the probe would say about it.
TEST_CASE("adopt_legacy_echo_db: a lone echo.db-wal is the resume state and is never probed (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    fs::rename(d.path() / "tar.db-wal", d.path() / "echo.db-wal"); // the interrupted step
    bool probed = false;
    auto probe = [&](const fs::path&) {
        probed = true;
        return EchoFileOwner::foreign;
    };

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(d.path() / "echo.db", probe).has_value());
    CHECK_FALSE(probed);
    CHECK(names_with_prefix(d.path(), "echo.db-wal.planted-").empty());
    auto db = EchoDatabase::open(d.path() / "echo.db");
    REQUIRE(db.has_value());
    CHECK(db->get_config("wal_marker", "") == "x");
}

TEST_CASE("adopt_legacy_echo_db: two foreign files are both moved aside one at a time (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "planted main");
    spit_file(d.path() / "echo.db-wal", "planted sidecar");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db, probe_by_name({
                                                           {"echo.db", EchoFileOwner::foreign},
                                                           {"echo.db-wal", EchoFileOwner::foreign},
                                                       }))
                .has_value());
    const auto main_planted = names_with_prefix(d.path(), "echo.db.planted-");
    const auto wal_planted = names_with_prefix(d.path(), "echo.db-wal.planted-");
    REQUIRE(main_planted.size() == 1);
    REQUIRE(wal_planted.size() == 1);
    CHECK(slurp_file(d.path() / main_planted[0]) == "planted main");
    CHECK(slurp_file(d.path() / wal_planted[0]) == "planted sidecar");
    CHECK_FALSE(fs::exists(d.path() / "tar.db"));
    auto db = EchoDatabase::open(echo_db);
    REQUIRE(db.has_value());
    CHECK(db->get_config("wal_marker", "") == "x");
}

#ifndef _WIN32
// The heal's order and its fail-closed arm: files move one at a time, sidecars first and the main
// file last, and the first move that fails stops everything with that file named, so an
// interruption leaves "echo.db still planted" (re-detected next start), never a stranded sidecar.
// A read-only directory makes the hard-link claim fail at the first attempt, so the file the error
// names IS the first one tried: the sidecar. POSIX only (Windows ignores a directory's write bit).
TEST_CASE("adopt_legacy_echo_db: a failed move stops the heal: sidecar first and nothing moved (#6695)",
          "[echo][store][adopt]") {
    if (::geteuid() == 0)
        SKIP("root bypasses directory permissions; cannot make the claim fail");
    ScratchDir d;
    make_legacy_tar_db_with_wal(d.path());
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "planted main");
    spit_file(d.path() / "echo.db-wal", "planted sidecar");
    // Declared after `d`, so it runs first and the scratch dir can be removed.
    struct WritableAgain {
        fs::path dir;
        ~WritableAgain() {
            std::error_code ec;
            fs::permissions(dir, fs::perms::owner_write, fs::perm_options::add, ec);
        }
    } writable_again{d.path()};
    std::error_code perm_ec;
    fs::permissions(d.path(),
                    fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write,
                    fs::perm_options::remove, perm_ec);
    REQUIRE_FALSE(perm_ec);

    const auto result = yuzu::agent::adopt_legacy_echo_db(
        echo_db, probe_by_name({
                     {"echo.db", EchoFileOwner::foreign},
                     {"echo.db-wal", EchoFileOwner::foreign},
                 }));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("echo.db-wal") != std::string::npos); // the sidecar went first
    CHECK(result.error().find("resolve it by hand") != std::string::npos);
    CHECK(slurp_file(echo_db) == "planted main");
    CHECK(slurp_file(d.path() / "echo.db-wal") == "planted sidecar");
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty());
    CHECK(names_with_prefix(d.path(), "echo.db-wal.planted-").empty());
}
#endif // !_WIN32

// An owner-verified echo.db wins even when a sidecar beside it is foreign: adoption moves nothing
// (open() replaces a foreign sidecar on Windows; that is its job, not adoption's).
TEST_CASE("adopt_legacy_echo_db: an owner-verified echo.db with a foreign sidecar moves nothing (#6695)",
          "[echo][store][adopt]") {
    ScratchDir d;
    make_legacy_tar_db(d.path());
    const auto echo_db = d.path() / "echo.db";
    spit_file(echo_db, "ours");
    spit_file(d.path() / "echo.db-wal", "planted sidecar");

    REQUIRE(yuzu::agent::adopt_legacy_echo_db(
                echo_db, probe_by_name({{"echo.db-wal", EchoFileOwner::foreign}}))
                .has_value());
    CHECK(slurp_file(echo_db) == "ours");
    CHECK(slurp_file(d.path() / "echo.db-wal") == "planted sidecar");
    CHECK(fs::exists(d.path() / "tar.db"));
    CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty());
    CHECK(names_with_prefix(d.path(), "echo.db-wal.planted-").empty());
}

#ifdef _WIN32
// A sidecar that cannot be renamed is COPIED into the quarantine set, and a copy takes the
// directory's inherited ACL (here an inheritable BUILTIN\Users read ACE, as C:\ProgramData has),
// which would leave a corrupt database's WAL readable by every local user while the live files are
// protected. open() protects the copy again. Each sidecar is held open without FILE_SHARE_DELETE,
// as a scanner or a backup agent holds one, so the rename and the removal of the original both
// fail and the copy fallback runs: the seam shows it, because the originals are still there once
// the quarantine is done. The holders share READ and WRITE, so SQLite's own opens are unaffected,
// and the seam releases them so the stale originals can go with the fresh database. The journal's
// first byte is zero (not hot, so SQLite leaves it for the quarantine to deal with).
TEST_CASE("EchoDatabase (Windows): a quarantined sidecar that had to be copied is protected again",
          "[echo][store][lifecycle][corruption][hardening]") {
    AclDir d;
    spit_file(d.db, "this is not a SQLite database");
    const std::string wal_bytes = "a wal with content";
    const std::string journal_bytes = std::string(1, '\0') + "journal bytes";
    spit_file(d.file("-wal"), wal_bytes);
    spit_file(d.file("-journal"), journal_bytes);

    std::vector<std::unique_ptr<void, decltype(&::CloseHandle)>> holders;
    for (const char* sfx : {"-wal", "-journal"}) {
        HANDLE raw = ::CreateFileW(d.file(sfx).c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        REQUIRE(raw != INVALID_HANDLE_VALUE);
        holders.emplace_back(raw, ::CloseHandle);
    }

    bool fired = false;
    OpenSeams seams;
    seams.after_quarantine = [&] {
        fired = true;
        CHECK(fs::exists(d.file("-wal")));     // not renamed, not removed: copied
        CHECK(fs::exists(d.file("-journal")));
        holders.clear();
    };
    auto opened = EchoDatabase::open(d.db, seams);
    REQUIRE(fired);
    CHECK(opened.has_value());

    const auto names = names_with_prefix(d.dir.path, "echo.db.corrupt-");
    struct Sidecar {
        std::string suffix;
        std::string bytes;
    };
    for (const Sidecar& sc : {Sidecar{"-wal", wal_bytes}, Sidecar{"-journal", journal_bytes}}) {
        INFO("sidecar " << sc.suffix);
        const auto it = std::ranges::find_if(
            names, [&](const std::string& n) { return n.ends_with(sc.suffix); });
        REQUIRE(it != names.end());
        const fs::path copied = d.dir.path / *it;
        CHECK(slurp_file(copied) == sc.bytes);
        assert_owner_only(copied); // protected, and no Users ACE inherited from the directory
    }
}

// The re-secure pass above runs for every OCCUPIED derived name, and the quarantine name
// is predictable (the current epoch second, n = 0), so a local user can squat `<claimed>-wal`
// ahead of a corruption with a hard link to a file of theirs, or to any file the service holds
// WRITE_DAC on. A hard link shares its target's security descriptor: without the owner and link
// tests the pass would rewrite the TARGET's DACL. The squat covers now and the thirty seconds after
// it so the claim lands on one of them without a seam into the clock (a slower landing skips); the live sidecar that could
// not take the squatted name is removed by the quarantine (the first recorded limit in
// sqlite_quarantine.hpp, the squatted-sidecar name), which is not
// what this case is about: here there is none.
TEST_CASE("EchoDatabase (Windows): a hard link squatted at a quarantine sidecar name is left alone",
          "[echo][store][lifecycle][corruption][hardening]") {
    AclDir d;
    if (!volume_has_hard_links(d.dir.path))
        SKIP("the temp directory's volume is not NTFS or ReFS: no hard links");
    spit_file(d.db, "this is not a SQLite database");
    const fs::path decoy = d.dir.path / "decoy.bin"; // inherits the directory's Users ACE
    spit_file(decoy, "not a wal");
    REQUIRE(dacl_facts(decoy).allows(kUsers));
    REQUIRE_FALSE(dacl_facts(decoy).dacl_protected);

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    constexpr int kSquats = 31; // now .. now + 30 s; a slower landing skips below, never fails
    for (int i = 0; i < kSquats; ++i) {
        std::error_code ec;
        fs::create_hard_link(decoy, d.dir.path / std::format("echo.db.corrupt-{}-wal", now + i), ec);
        REQUIRE_FALSE(ec);
    }
    REQUIRE(fs::hard_link_count(decoy) == kSquats + 1);

    auto opened = EchoDatabase::open(d.db);
    REQUIRE(opened.has_value());
    REQUIRE(opened->quarantined_this_open().has_value());
    // The claim landed inside the squatted window, so the pass met a squatted `-wal` name.
    const fs::path squatted =
        d.dir.path / std::format("echo.db.corrupt-{}-wal", *opened->quarantined_this_open());
    if (*opened->quarantined_this_open() >= now + kSquats)
        SKIP("the claim landed outside the squatted window (stalled runner)");
    REQUIRE(fs::exists(squatted));
    REQUIRE(fs::exists(d.dir.path / std::format("echo.db.corrupt-{}", *opened->quarantined_this_open())));

    // Nothing was re-secured through the squat: the target keeps its descriptor and every link.
    CHECK(fs::hard_link_count(decoy) == kSquats + 1);
    CHECK(read_file(decoy) == "not a wal");
    CHECK_FALSE(dacl_facts(decoy).dacl_protected);
    CHECK(dacl_facts(decoy).allows(kUsers));
}

// The other half of the same pass: a plain file (one link) squatted at a quarantine sidecar name
// by another account. The pass tests the owner first, so the file is left as it is and logged
// rather than re-secured. SeRestorePrivilege hands the plant to Users, so the case SKIPs without it.
TEST_CASE("EchoDatabase (Windows): a foreign-owned file squatted at a quarantine sidecar name is left alone",
          "[echo][store][lifecycle][corruption][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    AclDir d;
    spit_file(d.db, "this is not a SQLite database");

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    constexpr int kSquats = 31; // now .. now + 30 s; a slower landing skips below, never fails
    for (int i = 0; i < kSquats; ++i) {
        const fs::path squat = d.dir.path / std::format("echo.db.corrupt-{}-wal", now + i);
        spit_file(squat, "not a wal");
        set_owner(squat, kUsers);
    }

    auto opened = EchoDatabase::open(d.db);
    REQUIRE(opened.has_value());
    REQUIRE(opened->quarantined_this_open().has_value());
    const fs::path squatted =
        d.dir.path / std::format("echo.db.corrupt-{}-wal", *opened->quarantined_this_open());
    if (*opened->quarantined_this_open() >= now + kSquats)
        SKIP("the claim landed outside the squatted window (stalled runner)");
    REQUIRE(fs::exists(squatted));
    REQUIRE(fs::exists(d.dir.path / std::format("echo.db.corrupt-{}", *opened->quarantined_this_open())));

    // Left as the planter made it: still theirs, still the inherited (unprotected) ACL.
    CHECK(owner_sid(squatted) == kUsers);
    CHECK_FALSE(dacl_facts(squatted).dacl_protected);
    CHECK(dacl_facts(squatted).allows(kUsers));
}

// The real probe (default_echo_owner_probe, the owner test open() applies), not a fake: a file
// owned by Users is foreign and moves; a file we created is ours and stays. SeRestorePrivilege is
// needed to hand the plant to another owner, so the case SKIPs without it (as the open() cases do).
TEST_CASE("adopt_legacy_echo_db (Windows): the real owner probe moves a Users-owned echo.db and keeps ours (#6695)",
          "[echo][store][adopt][hardening]") {
    if (!enable_restore_privilege())
        SKIP("SeRestorePrivilege unavailable");
    {
        ScratchDir d;
        make_legacy_tar_db(d.path());
        const auto echo_db = d.path() / "echo.db";
        spit_file(echo_db, "planted by another account");
        set_owner(echo_db, kUsers);

        REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
        const auto planted = names_with_prefix(d.path(), "echo.db.planted-");
        REQUIRE(planted.size() == 1);
        CHECK(slurp_file(d.path() / planted[0]) == "planted by another account");
        CHECK_FALSE(fs::exists(d.path() / "tar.db"));
        CHECK(EchoDatabase::open(echo_db).has_value());
    }
    {
        ScratchDir d;
        make_legacy_tar_db(d.path());
        const auto echo_db = d.path() / "echo.db";
        spit_file(echo_db, "ours"); // created by this process: owner-verified

        REQUIRE(yuzu::agent::adopt_legacy_echo_db(echo_db).has_value());
        CHECK(slurp_file(echo_db) == "ours");
        CHECK(fs::exists(d.path() / "tar.db"));
        CHECK(names_with_prefix(d.path(), "echo.db.planted-").empty());
    }
}
#endif // _WIN32

// =============================================================================
// Storage budget primitives (auto_vacuum, db_size_bytes, delete_counted, hygiene)
// =============================================================================

namespace {

int64_t pragma_int(EchoDatabase& db, const std::string& pragma) {
    auto q = db.execute_query("PRAGMA " + pragma, /*max_rows=*/1);
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 1);
    return std::stoll(q->rows[0][0]);
}

void insert_tcp_rows(EchoDatabase& db, int n, int64_t ts0) {
    std::vector<NetworkEvent> evs;
    for (int i = 0; i < n; ++i) {
        NetworkEvent ev;
        ev.ts = ts0 + i;
        ev.snapshot_id = 1;
        ev.action = "connected";
        ev.proto = "tcp";
        ev.local_addr = "10.0.0.1";
        ev.local_port = 1000 + i;
        ev.remote_addr = "10.0.0." + std::to_string(i % 200);
        ev.remote_port = 1000 + i; // the remote port is part of the roll-up key: one row per i
        ev.state = "ESTABLISHED";
        ev.pid = 1;
        ev.process_name = "curl";
        evs.push_back(std::move(ev));
    }
    REQUIRE(db.fold_network_events(evs));
}

int64_t count_table_rows(EchoDatabase& db, const std::string& table) {
    auto q = db.execute_query("SELECT COUNT(*) FROM " + table, 1);
    REQUIRE(q.has_value());
    return std::stoll(q->rows.at(0).at(0));
}

} // namespace

TEST_CASE("EchoDatabase: a fresh echo.db is incremental auto_vacuum with a capped WAL",
          "[echo][store][budget]") {
    auto t = make_test_db();
    CHECK(pragma_int(t.db, "auto_vacuum") == 2);
    CHECK(t.db.storage_bytes().auto_vacuum == 2);
    CHECK(pragma_int(t.db, "journal_size_limit") == 16777216);
}

TEST_CASE("EchoDatabase: db_size_bytes is used pages plus the WAL, not the file size",
          "[echo][store][budget]") {
    auto t = make_test_db();
    insert_tcp_rows(t.db, 3000, 1000);
    // A contiguous range empties whole pages (every-other-row deletes may free none), and the
    // case is only meaningful with a non-empty freelist: used pages differ from the file then.
    REQUIRE(t.db.execute_sql("DELETE FROM tcp_hourly_r WHERE id <= 2000"));

    const int64_t page_count = pragma_int(t.db, "page_count");
    const int64_t freelist = pragma_int(t.db, "freelist_count");
    REQUIRE(freelist > 0);
    const int64_t page_size = pragma_int(t.db, "page_size");
    std::error_code ec;
    const auto wal = fs::file_size(fs::path{t.path.string() + "-wal"}, ec);
    const int64_t wal_bytes = ec ? 0 : static_cast<int64_t>(wal);

    const auto sb = t.db.storage_bytes();
    CHECK(sb.page_count == page_count);
    CHECK(sb.freelist_count == freelist);
    CHECK(sb.page_size == page_size);
    CHECK(sb.wal_bytes == wal_bytes);
    CHECK(t.db.stats().db_size_bytes == (page_count - freelist) * page_size + wal_bytes);
    CHECK(sb.data_bytes() == (page_count - freelist) * page_size);
    CHECK(sb.file_bytes() == page_count * page_size);
}

namespace {

// Denies the pragma reads behind storage_bytes() while `deny` is set (an authorizer is how a
// failing measurement is injected without a production hook).
struct PragmaDenier {
    bool deny{false};
};

int deny_pragma_reads(void* user, int action, const char* arg1, const char*, const char*,
                      const char*) {
    if (!static_cast<const PragmaDenier*>(user)->deny)
        return SQLITE_OK;
    if (action == SQLITE_PRAGMA)
        return SQLITE_DENY;
    if (action == SQLITE_READ && arg1 != nullptr && std::string_view{arg1}.starts_with("pragma_"))
        return SQLITE_DENY;
    return SQLITE_OK;
}

} // namespace

TEST_CASE("EchoDatabase: a failed size measurement is reported as failed, never as an empty database",
          "[echo][store][budget][chaos]") {
    PragmaDenier denier; // outlives the database that holds a pointer to it
    auto t = make_test_db();
    insert_tcp_rows(t.db, 200, 1000);
    REQUIRE(t.db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        sqlite3_set_authorizer(h.raw(), deny_pragma_reads, &denier);
        return {};
    }));

    // Positive control: with the injector off the measurement is real.
    const auto healthy = t.db.storage_bytes();
    REQUIRE(healthy.ok);
    CHECK(healthy.page_count > 0);
    CHECK(healthy.page_size > 0);

    denier.deny = true;
    const auto failed = t.db.storage_bytes();
    CHECK_FALSE(failed.ok);
    CHECK(failed.data_bytes() == 0); // all zero: the reason callers must look at `ok`
    // The eviction pass treats it as a failure, not as "within budget" (and so does not evict).
    const auto res = yuzu::echo::run_budget(t.db, 1'700'000'000, /*target_bytes=*/0, [] { return true; });
    CHECK(res.failed);
    CHECK_FALSE(res.exhausted);
    CHECK(res.evicted_hourly == 0);
    denier.deny = false;
    CHECK(t.db.storage_bytes().ok);
    CHECK(count_table_rows(t.db, "tcp_hourly_r") == 200);

    // A closed store is the same shape.
    EchoDatabase moved = std::move(t.db);
    CHECK_FALSE(t.db.storage_bytes().ok);
    t.db = std::move(moved); // hand it back so the fixture's destructor sees a live handle
}

TEST_CASE("EchoDatabase: set_state with identical JSON is a no-op, a change rewrites",
          "[echo][store][state][budget]") {
    auto t = make_test_db();
    const auto updated_at = [&] {
        auto q = t.db.execute_query("SELECT updated_at FROM echo_state WHERE collector='process'", 1);
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        return std::stoll(q->rows[0][0]);
    };
    REQUIRE(t.db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(t.db.execute_sql("UPDATE echo_state SET updated_at = 1 WHERE collector='process'"));

    REQUIRE(t.db.set_state("process", R"([{"pid":1}])")); // identical: no page dirtied
    CHECK(updated_at() == 1);
    CHECK(t.db.get_state("process") == R"([{"pid":1}])");

    REQUIRE(t.db.set_state("process", R"([{"pid":2}])")); // different: rewritten
    CHECK(updated_at() > 1);
    CHECK(t.db.get_state("process") == R"([{"pid":2}])");
}

TEST_CASE("EchoDatabase: a StateWrite inside fold_network_events skips an identical baseline",
          "[echo][store][state][budget]") {
    auto t = make_test_db();
    const auto updated_at = [&] {
        auto q = t.db.execute_query("SELECT updated_at FROM echo_state WHERE collector='network'", 1);
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        return std::stoll(q->rows[0][0]);
    };
    NetworkEvent ev;
    ev.ts = 5;
    ev.snapshot_id = 1;
    ev.action = "connected";
    ev.proto = "tcp";
    ev.local_port = 1;
    ev.remote_port = 2;
    REQUIRE(t.db.fold_network_events({ev}, StateWrite{"network", "[1]"}));
    REQUIRE(t.db.execute_sql("UPDATE echo_state SET updated_at = 1 WHERE collector='network'"));

    ev.local_port = 3;
    REQUIRE(t.db.fold_network_events({ev}, StateWrite{"network", "[1]"}));
    CHECK(updated_at() == 1); // the counts landed, the identical baseline did not rewrite
    auto landed = t.db.execute_query("SELECT SUM(connect_count) FROM tcp_hourly", 1);
    REQUIRE(landed.has_value());
    CHECK(landed->rows.at(0).at(0) == "2");
    REQUIRE(t.db.fold_network_events({ev}, StateWrite{"network", "[2]"}));
    CHECK(updated_at() > 1);
}

TEST_CASE("EchoDatabase: delete_counted counts RETURNING rows and bumps the counter atomically",
          "[echo][store][budget]") {
    auto t = make_test_db();
    insert_tcp_rows(t.db, 10, 1000);
    const std::string sql =
        "DELETE FROM tcp_hourly_r WHERE id IN (SELECT id FROM tcp_hourly_r ORDER BY id LIMIT 4) RETURNING id";

    auto first = t.db.delete_counted(sql, "budget_test_counter");
    REQUIRE(first.has_value());
    CHECK(*first == 4);
    CHECK(count_table_rows(t.db, "tcp_hourly_r") == 6);
    CHECK(t.db.get_config("budget_test_counter", "") == "4");

    auto second = t.db.delete_counted(sql, "budget_test_counter");
    REQUIRE(second.has_value());
    CHECK(*second == 4);
    CHECK(t.db.get_config("budget_test_counter", "") == "8"); // accumulates

    auto none = t.db.delete_counted("DELETE FROM tcp_hourly_r WHERE id < 0 RETURNING id",
                                    "budget_test_counter");
    REQUIRE(none.has_value());
    CHECK(*none == 0);
    CHECK(t.db.get_config("budget_test_counter", "") == "8");
}

TEST_CASE("EchoDatabase: a failing delete_counted leaves the rows and the counter unchanged",
          "[echo][store][budget]") {
    auto t = make_test_db();
    insert_tcp_rows(t.db, 10, 1000);
    const std::string sql =
        "DELETE FROM tcp_hourly_r WHERE id IN (SELECT id FROM tcp_hourly_r ORDER BY id LIMIT 4) RETURNING id";

    SECTION("a statement that fails part-way") {
        // A trigger aborts the whole statement on one of the rows.
        REQUIRE(t.db.execute_sql(
            "CREATE TRIGGER yuzu_test_block BEFORE DELETE ON tcp_hourly_r WHEN OLD.remote_port = 1002 "
            "BEGIN SELECT RAISE(ABORT, 'blocked'); END"));
        auto r = t.db.delete_counted(sql, "budget_test_counter");
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
        CHECK(count_table_rows(t.db, "tcp_hourly_r") == 10);
        CHECK(t.db.get_config("budget_test_counter", "absent") == "absent");
    }
    SECTION("the counter bump failing rolls the deletes back") {
        REQUIRE(t.db.execute_sql(
            "CREATE TRIGGER yuzu_test_block_cfg BEFORE INSERT ON echo_config "
            "WHEN NEW.key = 'budget_test_counter' BEGIN SELECT RAISE(ABORT, 'blocked'); END"));
        auto r = t.db.delete_counted(sql, "budget_test_counter");
        REQUIRE_FALSE(r.has_value());
        CHECK(count_table_rows(t.db, "tcp_hourly_r") == 10); // the deletes did not survive the failed bump
    }
    SECTION("an unknown table") {
        auto r = t.db.delete_counted("DELETE FROM no_such_table RETURNING id", "budget_test_counter");
        REQUIRE_FALSE(r.has_value());
    }
    // The connection is not left inside a transaction by any failure.
    CHECK(t.db.execute_sql("DROP TRIGGER IF EXISTS yuzu_test_block"));
    insert_tcp_rows(t.db, 1, 5000);
}

TEST_CASE("EchoDatabase: rollback_open_transaction clears a transaction an unwind left open",
          "[echo][store][budget]") {
    auto t = make_test_db();
    // Autocommit: a no-op, the database stays usable.
    t.db.rollback_open_transaction();
    insert_tcp_rows(t.db, 1, 1000);

    // A raw BEGIN left open (what an exception between BEGIN and COMMIT does).
    REQUIRE(t.db.execute_sql("BEGIN"));
    NetworkEvent ev;
    ev.ts = 2000;
    ev.snapshot_id = 1;
    ev.action = "connected";
    ev.proto = "tcp";
    CHECK_FALSE(t.db.fold_network_events({ev})); // cannot BEGIN inside the open transaction
    t.db.rollback_open_transaction();
    CHECK(t.db.fold_network_events({ev}));
    CHECK(count_table_rows(t.db, "tcp_hourly_r") == 2);
}

namespace {

// Denies the ROLLBACK statement while `deny` is set: a ROLLBACK that fails with the transaction
// still open, the one state a failed rollback_open_transaction must not leave behind.
struct RollbackDenier {
    bool deny{false};
};

int deny_rollback(void* user, int action, const char* arg1, const char*, const char*, const char*) {
    if (static_cast<const RollbackDenier*>(user)->deny && action == SQLITE_TRANSACTION &&
        arg1 != nullptr && std::string_view{arg1} == "ROLLBACK")
        return SQLITE_DENY;
    return SQLITE_OK;
}

} // namespace

TEST_CASE("EchoDatabase: a rollback that fails with the transaction still open closes the store (B3)",
          "[echo][store][budget][chaos]") {
    // #6889 review B3: rollback_open_transaction only LOGGED a failed ROLLBACK and left the shared
    // connection inside the transaction, so every later write was reported durable and lost at
    // close. It must do what checked_transaction does: ask sqlite3_get_autocommit, and when the
    // transaction is genuinely still open, close the connection so every method fails closed.
    RollbackDenier denier; // outlives the database that holds a pointer to it
    auto t = make_test_db();
    REQUIRE(t.db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        sqlite3_set_authorizer(h.raw(), deny_rollback, &denier);
        return {};
    }));
    REQUIRE(t.db.execute_sql("BEGIN")); // what an exception between BEGIN and COMMIT leaves behind
    denier.deny = true;
    t.db.rollback_open_transaction();
    CHECK_FALSE(t.db.is_open()); // closed: FAILS WITHOUT the autocommit check + close
    CHECK_FALSE(t.db.set_config("yuzu_test_key", "v")); // every write now fails closed

    // The healthy path is unchanged (covered by the sibling test): a rollback that works leaves it open.
}

TEST_CASE("EchoDatabase: set_config and set_state refuse to join a transaction left open",
          "[echo][store][budget]") {
    // The window between an unwind releasing mu_ and fail_internal's rollback: a standalone
    // write that joined the abandoned transaction would report success and then be discarded.
    auto t = make_test_db();
    REQUIRE(t.db.set_config("yuzu_test_key", "before"));
    REQUIRE(t.db.execute_sql("BEGIN"));
    CHECK_FALSE(t.db.set_config("yuzu_test_key", "joined"));
    CHECK_FALSE(t.db.set_state("yuzu_test_collector", "{\"joined\":1}"));
    t.db.rollback_open_transaction();
    CHECK(t.db.get_config("yuzu_test_key", "") == "before"); // nothing was written, nothing lost
    CHECK(t.db.set_config("yuzu_test_key", "after"));
    CHECK(t.db.set_state("yuzu_test_collector", "{\"after\":1}"));
    CHECK(t.db.get_config("yuzu_test_key", "") == "after");
    CHECK(t.db.get_state("yuzu_test_collector") == "{\"after\":1}");
}

TEST_CASE("EchoDatabase: an interrupted conversion VACUUM leaves the file intact and a retry works",
          "[echo][store][budget][chaos]") {
    yuzu::test::TempDbFile tmp{"yuzu_test_echo_av_interrupt_"};
    {
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(tmp.path.string().c_str(), &owner.db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(owner.db,
                             "PRAGMA auto_vacuum=0; CREATE TABLE yuzu_test_pad(x BLOB);"
                             "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1500) "
                             "INSERT INTO yuzu_test_pad SELECT zeroblob(4000) FROM n;"
                             "DELETE FROM yuzu_test_pad WHERE rowid % 4 != 0;",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    auto opened = EchoDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    EchoDatabase db = std::move(*opened);

    // A progress handler installed through the transaction handle's raw connection (it outlives
    // the transaction). It counts every callback and, once armed, interrupts the statement that
    // makes callback number `interrupt_after + 1`.
    struct Interrupter {
        bool armed{false};
        int calls{0};
        int interrupt_after{0};
    } interrupter;
    REQUIRE(db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        sqlite3_progress_handler(
            h.raw(), 1,
            [](void* p) -> int {
                auto* i = static_cast<Interrupter*>(p);
                ++i->calls;
                return (i->armed && i->calls > i->interrupt_after) ? 1 : 0;
            },
            &interrupter);
        return {};
    }));

    const auto before = db.storage_bytes();
    REQUIRE(before.ok);
    REQUIRE(before.auto_vacuum == 0);
    REQUIRE(before.freelist_count > 0);

    // vacuum_to_incremental() runs `PRAGMA auto_vacuum=INCREMENTAL` and then VACUUM. Measure how
    // many callbacks the PRAGMA alone makes, so the interrupt lands inside the VACUUM and not in
    // the PRAGMA that precedes it (an interrupted PRAGMA would prove nothing about the VACUUM).
    interrupter.calls = 0;
    REQUIRE(db.execute_sql("PRAGMA auto_vacuum=INCREMENTAL"));
    const int pragma_calls = interrupter.calls;

    interrupter.calls = 0;
    interrupter.interrupt_after = pragma_calls;
    interrupter.armed = true;
    CHECK_FALSE(db.vacuum_to_incremental());
    interrupter.armed = false;
    CHECK(interrupter.calls > pragma_calls); // the injector fired inside the VACUUM

    // Nothing half-converted: still the original file, still sound.
    const auto after = db.storage_bytes();
    CHECK(after.auto_vacuum == 0);
    CHECK(after.page_count == before.page_count);
    CHECK(after.freelist_count == before.freelist_count);
    auto integrity = db.execute_query("PRAGMA integrity_check", 5);
    REQUIRE(integrity.has_value());
    REQUIRE(integrity->rows.size() == 1);
    CHECK(integrity->rows[0][0] == "ok");
    CHECK(db.get_config("schema_version", "") == "10");

    // And the interruption is not sticky: the next attempt converts.
    REQUIRE(db.vacuum_to_incremental());
    CHECK(db.storage_bytes().auto_vacuum == 2);
}

TEST_CASE("EchoDatabase: a pre-auto_vacuum database converts with one VACUUM",
          "[echo][store][budget]") {
    yuzu::test::TempDbFile tmp{"yuzu_test_echo_av_"};
    {
        // A database as an older build left it: tables already exist, auto_vacuum none, and
        // plenty of free pages (the schema the open creates would otherwise use up a small
        // freelist).
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open(tmp.path.string().c_str(), &owner.db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(owner.db,
                             "PRAGMA auto_vacuum=0; CREATE TABLE yuzu_test_pad(x BLOB);"
                             "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1500) "
                             "INSERT INTO yuzu_test_pad SELECT zeroblob(4000) FROM n;"
                             "DELETE FROM yuzu_test_pad WHERE rowid % 4 != 0;",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    auto opened = EchoDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    {
        EchoDatabase db = std::move(*opened);
        const auto before = db.storage_bytes();
        CHECK(before.auto_vacuum == 0); // the open pragma cannot convert a populated file
        CHECK(before.freelist_count > 0);

        REQUIRE(db.vacuum_to_incremental());
        const auto after = db.storage_bytes();
        CHECK(after.auto_vacuum == 2);
        CHECK(after.freelist_count == 0);
        CHECK(after.page_count < before.page_count);
        CHECK(db.get_config("schema_version", "") == "10"); // data survived the rebuild

        // Hygiene calls on a healthy database.
        db.incremental_vacuum(256);
        CHECK(db.checkpoint(CheckpointMode::kPassive) != CheckpointResult::kError);
        CHECK(db.checkpoint(CheckpointMode::kTruncate) == CheckpointResult::kOk);
        CHECK(db.storage_bytes().wal_bytes == 0); // TRUNCATE reclaimed the WAL file
    }
}

TEST_CASE("EchoDatabase: purge_source reports a dictionary sweep that did not finish and counts it",
          "[echo][store][purge][dictionary]") {
    // The rows go either way; the strings of the purged rows are forensic data too, so a sweep
    // that outran its deadline is reported (dictionary_pending) and counted, never a silent
    // "purged". A deadline already past is gc_dictionary's own seam for that path.
    auto t = make_test_db();
    ProcessEvent e;
    e.ts = 1000;
    e.snapshot_id = 1;
    e.action = "started";
    e.pid = 1;
    e.name = "purged.exe";
    e.user = "u";
    REQUIRE(t.db.fold_process_events({e}));

    const auto starved = t.db.purge_source("process", std::chrono::seconds(0));
    REQUIRE(starved.has_value());
    CHECK(starved->rows_deleted == 3); // hourly, daily, monthly
    CHECK(starved->dictionary_pending);
    CHECK(t.db.get_config("dict_gc_starved_total", "0") == "1");
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM echo_dict WHERE text = 'purged.exe'") == "1"); // still there

    const auto swept = t.db.purge_source("process");
    REQUIRE(swept.has_value());
    CHECK(swept->rows_deleted == 0);
    CHECK(!swept->dictionary_pending);
    CHECK(t.db.get_config("dict_gc_starved_total", "0") == "1");
    CHECK(first_cell(t.db, "SELECT COUNT(*) FROM echo_dict WHERE text = 'purged.exe'") == "0");
}
