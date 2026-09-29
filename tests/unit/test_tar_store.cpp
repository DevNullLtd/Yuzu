/**
 * test_tar_store.cpp -- Unit tests for TarDatabase (SQLite-backed TAR storage)
 *
 * Covers: open/create, warehouse tables, typed inserts, SQL queries,
 * stats, config get/set, state get/set.
 */

#include "tar_db.hpp"
#include "tar_netqual.hpp"
#include "tar_netqual_boot.hpp"
#include "tar_sql_executor.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h> // raw handle for the reopen-after-DROP upgrade simulation

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h> // geteuid — the unmovable-quarantine test is POSIX-only
#endif

namespace fs = std::filesystem;
using namespace yuzu::tar;

// Helper: create a TarDatabase in a unique temp file, clean up on destruction.
// Uniqueness comes from yuzu::test::unique_temp_path -- never salt with
// std::hash<thread::id> / steady_clock, which collide under Defender-induced
// I/O serialisation on the Windows runner (CLAUDE.md test conventions, #473).
struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

static TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestTarDb{std::move(*result), tmp};
}

// =============================================================================
// Database lifecycle
// =============================================================================

TEST_CASE("TarDatabase: open creates database file", "[tar][store][lifecycle]") {
    auto t = make_test_db();
    CHECK(fs::exists(t.path));
}

TEST_CASE("TarDatabase: warehouse tables created on open", "[tar][store][lifecycle]") {
    auto t = make_test_db();
    // Verify by inserting a process event -- would fail if table doesn't exist
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 42;
    ev.name = "test.exe";

    CHECK(t.db.insert_process_events({ev}));
}

TEST_CASE("TarDatabase: purge_source drops ALL tiers for one source, leaves others",
          "[tar][store][purge]") {
    auto t = make_test_db();

    // Seed EVERY process tier (live/hourly/daily/monthly) — not just live — so a
    // regression that purges only granularities[0] fails, and so the returned
    // rows_deleted proves the cross-tier sum (governance B2). live via the typed
    // insert; the rollup tiers via direct INSERT (schema per tar_schema_registry).
    ProcessEvent p1;
    p1.ts = 1000;
    p1.snapshot_id = 1;
    p1.action = "started";
    p1.pid = 1;
    p1.name = "a.exe";
    ProcessEvent p2 = p1;
    p2.pid = 2;
    p2.name = "b.exe";
    REQUIRE(t.db.insert_process_events({p1, p2})); // process_live: 2
    REQUIRE(t.db.execute_sql("INSERT INTO process_hourly "
                             "(hour_ts,name,user,start_count,stop_count) VALUES "
                             "(3600,'a.exe','SYSTEM',1,1),(7200,'b.exe','SYSTEM',1,1),"
                             "(10800,'c.exe','SYSTEM',1,1)")); // process_hourly: 3
    REQUIRE(t.db.execute_sql("INSERT INTO process_daily "
                             "(day_ts,name,user,start_count,stop_count) VALUES "
                             "(86400,'a.exe','SYSTEM',1,1)")); // process_daily: 1
    REQUIRE(t.db.execute_sql("INSERT INTO process_monthly "
                             "(month_ts,name,user,start_count,stop_count) VALUES "
                             "(2592000,'a.exe','SYSTEM',1,1)")); // process_monthly: 1

    // A different source, seeded across TWO tiers, must be entirely untouched.
    NetworkEvent n1;
    n1.ts = 1000;
    n1.snapshot_id = 1;
    n1.action = "connected";
    n1.proto = "tcp";
    n1.local_addr = "127.0.0.1";
    n1.local_port = 5;
    n1.remote_addr = "1.1.1.1";
    n1.remote_port = 53;
    REQUIRE(t.db.insert_network_events({n1})); // tcp_live: 1
    REQUIRE(t.db.execute_sql("INSERT INTO tcp_hourly "
                             "(hour_ts,remote_addr,remote_port,proto,process_name,"
                             "connect_count,disconnect_count) VALUES "
                             "(3600,'1.1.1.1',53,'tcp','sshd',1,1)")); // tcp_hourly: 1

    auto count = [&](const std::string& table) {
        auto r = t.db.execute_query("SELECT COUNT(*) FROM " + table);
        REQUIRE(r.has_value());
        REQUIRE(!r->rows.empty());
        return std::stoi(r->rows[0][0]);
    };
    REQUIRE(count("process_live") == 2);
    REQUIRE(count("process_hourly") == 3);
    REQUIRE(count("process_daily") == 1);
    REQUIRE(count("process_monthly") == 1);
    REQUIRE(count("tcp_live") == 1);
    REQUIRE(count("tcp_hourly") == 1);

    auto res = t.db.purge_source("process");
    REQUIRE(res.has_value());
    CHECK(*res == 7); // 2 + 3 + 1 + 1 across all four tiers — the cross-tier sum
    CHECK(count("process_live") == 0);
    CHECK(count("process_hourly") == 0);
    CHECK(count("process_daily") == 0);
    CHECK(count("process_monthly") == 0);
    CHECK(count("tcp_live") == 1);   // a different source is untouched...
    CHECK(count("tcp_hourly") == 1); // ...across all of its tiers
}

TEST_CASE("TarDatabase: purge_source(usage) also erases usage_daily_user",
          "[tar][store][purge][usage]") {
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
    CHECK(*res == 3); // usage_daily + usage_live (registered tiers) + usage_daily_user
    CHECK(count("usage_daily") == 0);
    CHECK(count("usage_daily_user") == 0); // the regression this test pins
    CHECK(count("usage_live") == 0);
}

TEST_CASE("TarDatabase: purge_source rejects an unknown source", "[tar][store][purge]") {
    auto t = make_test_db();
    auto res = t.db.purge_source("not_a_source");
    CHECK_FALSE(res.has_value());
}

// =============================================================================
// Typed inserts and SQL queries
// =============================================================================

TEST_CASE("TarDatabase: insert and query process events", "[tar][store][crud]") {
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

    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query("SELECT ts, action, pid, name FROM process_live ORDER BY ts");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 5);
    CHECK(results->rows[0][0] == "1000");
    CHECK(results->rows[4][0] == "1004");
    CHECK(results->rows[0][1] == "started");
}

TEST_CASE("TarDatabase: insert and query software events", "[tar][store][crud][software]") {
    // Direct round-trip through insert_software_events — the only exerciser of the
    // 8-parameter prepared statement, so a column-binding transposition (e.g.
    // publisher <-> install_date) is caught here rather than slipping past the
    // aggregator test (which seeds software_live with raw SQL).
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

    REQUIRE(t.db.insert_software_events(events));

    auto r = t.db.execute_query(
        "SELECT action, name, version, prev_version, publisher, install_date "
        "FROM software_live ORDER BY ts");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 2);
    // Row 0: install — every column in declared order (machine scope only, no
    // scope/user columns).
    CHECK(r->rows[0][0] == "installed");
    CHECK(r->rows[0][1] == "7-Zip");
    CHECK(r->rows[0][2] == "23.01");
    CHECK(r->rows[0][3] == ""); // prev_version empty for install
    CHECK(r->rows[0][4] == "Igor Pavlov");
    CHECK(r->rows[0][5] == "20260101");
    // Row 1: upgrade — prev_version + publisher + install_date populated, not transposed.
    CHECK(r->rows[1][0] == "upgraded");
    CHECK(r->rows[1][3] == "1.90");
    CHECK(r->rows[1][4] == "Microsoft");
    CHECK(r->rows[1][5] == "20260102");

    // Empty-vector contract matches the sibling inserts (returns true, no-op).
    CHECK(t.db.insert_software_events({}));
}

TEST_CASE("execute_user_query: software_live and software_daily are sandbox-readable",
          "[tar][store][sandbox][software][security]") {
    // The monthly rollup reads FROM software_daily, so both tiers must be
    // authorizer-allowlisted for an operator tar.sql to aggregate them. No other
    // test runs an actual statement through the read-only connection on these
    // tables (the allowlist iteration test only checks is_queryable_table).
    auto t = make_test_db();
    SoftwareEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "installed";
    ev.name = "7-Zip";
    ev.version = "23.01";
    REQUIRE(t.db.insert_software_events({ev}));
    REQUIRE(t.db.execute_sql(
        "INSERT INTO software_daily (day_ts, name, install_count, remove_count, "
        "upgrade_count) VALUES (86400, '7-Zip', 3, 1, 2)"));

    auto live = t.db.execute_user_query("SELECT action, name FROM software_live");
    REQUIRE(live.has_value());
    REQUIRE(live->rows.size() == 1);
    CHECK(live->rows[0][0] == "installed");

    auto daily = t.db.execute_user_query("SELECT SUM(install_count) FROM software_daily");
    REQUIRE(daily.has_value());
    REQUIRE(daily->rows.size() == 1);
    CHECK(daily->rows[0][0] == "3");
}

TEST_CASE("execute_user_query: usage tables are denied to generic tar.sql (#4260)",
          "[tar][store][security][usage]") {
    // usage/usage_daily/usage_daily_user are read ONLY through the
    // Forensics-gated app_usage plugin reads (p2.1/p2.2), which never go
    // through execute_user_query. A generic tar.sql query touching any of
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
    REQUIRE(t.db.insert_process_events({[] {
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
                    .execute_user_query("SELECT p.name FROM process_live p JOIN usage_daily d "
                                         "ON d.exe_key = p.name")
                    .has_value());
    CHECK_FALSE(
        t.db.execute_user_query("SELECT (SELECT COUNT(*) FROM usage_daily_user)").has_value());

    // Positive control: the authorizer isn't wedged shut -- a non-usage
    // table via its dollar name still works. execute_user_query never
    // translates $-names itself (confirmed against its implementation --
    // it passes the raw string straight to sqlite3_prepare_v2), so this
    // query must go through validate_and_translate_sql first, exactly like
    // the $Usage_Daily denial check above; passing the bare $Process_Live
    // string here previously hit SQLite's own "near $Process_Live: syntax
    // error" before the authorizer ever ran.
    auto ctrl_sql = validate_and_translate_sql("SELECT COUNT(*) FROM $Process_Live");
    REQUIRE(ctrl_sql.has_value());
    auto ctrl = t.db.execute_user_query(*ctrl_sql);
    REQUIRE(ctrl.has_value());
    REQUIRE(ctrl->rows.size() == 1);
    CHECK(ctrl->rows[0][0] == "1");
}

TEST_CASE("tar.export $Software summary projection references only existing columns",
          "[tar][store][software][export]") {
    // Regression guard (#1620): do_export's `software` UNION branch builds a summary
    // expression over software_live. After dropping the per-user `scope`/`user`
    // columns, that projection must reference only columns that still exist — a stale
    // column (the removed `scope`) failed at runtime with "no such column: scope".
    // This mirrors do_export's software projection so a future re-introduction of a
    // dropped column in that SELECT is caught by the unit suite.
    auto t = make_test_db();
    SoftwareEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "installed";
    ev.name = "7-Zip";
    ev.version = "23.01";
    REQUIRE(t.db.insert_software_events({ev}));
    auto r = t.db.execute_query(
        "SELECT 'software', ts, snapshot_id, action, "
        "(name || ' ' || COALESCE(version,'')) AS summary FROM software_live");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][4] == "7-Zip 23.01");
}

TEST_CASE("TarDatabase: insert and query network events", "[tar][store][crud]") {
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

    REQUIRE(t.db.insert_network_events({ev}));

    auto results = t.db.execute_query("SELECT proto, local_port, remote_addr FROM tcp_live");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 1);
    CHECK(results->rows[0][0] == "tcp");
    CHECK(results->rows[0][1] == "8080");
    CHECK(results->rows[0][2] == "10.0.0.1");
}

// ── query_recent_tcp_connections — last-N-seconds window for the viz ─────────
//
// Tracer bullet: TAR keeps every observed TCP connection in tcp_live with
// its observation timestamp. The viz wants to render any connection that
// existed within the last hour as a tube, not just the currently-ESTABLISHED
// ones from /proc/net/tcp. So `tar.fleet_snapshot` needs a way to ask the
// warehouse for the rolling window of connections seen recently.
//
// Behaviour: returns one row per unique (proto, local_addr, local_port,
// remote_addr, remote_port, pid) 5-tuple, with `ts` set to the most recent
// observation timestamp. Rows older than `since_ts` are dropped. State
// values other than ESTABLISHED are filtered out (LISTEN, TIME_WAIT, etc.
// — those aren't "this box talks to that box" edges).
TEST_CASE("TarDatabase: query_recent_tcp_connections returns rows newer than the window",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    NetworkEvent in_window;
    in_window.ts = 5000;
    in_window.action = "connected";
    in_window.proto = "tcp";
    in_window.local_addr = "10.0.0.10";
    in_window.local_port = 50001;
    in_window.remote_addr = "10.0.0.20";
    in_window.remote_port = 5432;
    in_window.state = "ESTABLISHED";
    in_window.pid = 100;
    in_window.process_name = "node";

    NetworkEvent out_of_window;
    out_of_window.ts = 1000; // 4000 seconds before in_window
    out_of_window.action = "connected";
    out_of_window.proto = "tcp";
    out_of_window.local_addr = "10.0.0.10";
    out_of_window.local_port = 49999;
    out_of_window.remote_addr = "10.0.0.30";
    out_of_window.remote_port = 6379;
    out_of_window.state = "ESTABLISHED";
    out_of_window.pid = 100;
    out_of_window.process_name = "node";

    REQUIRE(t.db.insert_network_events({in_window, out_of_window}));

    // Window: [5000 - 3600, 5000] = [1400, 5000]. The t=1000 row is outside.
    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/1400);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).proto == "tcp");
    CHECK(recent->at(0).local_addr == "10.0.0.10");
    CHECK(recent->at(0).local_port == 50001);
    CHECK(recent->at(0).remote_addr == "10.0.0.20");
    CHECK(recent->at(0).remote_port == 5432);
    CHECK(recent->at(0).pid == 100u);
    CHECK(recent->at(0).ts == 5000);
}

TEST_CASE("TarDatabase: query_recent_tcp_connections dedups by 5-tuple, keeps latest ts",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    // Same 5-tuple+pid observed three times. The result MUST be a single
    // row with ts set to the most recent observation (3000).
    NetworkEvent base;
    base.action = "connected";
    base.proto = "tcp";
    base.local_addr = "10.0.0.10";
    base.local_port = 60001;
    base.remote_addr = "10.0.0.20";
    base.remote_port = 5432;
    base.state = "ESTABLISHED";
    base.pid = 200;
    base.process_name = "node";

    base.ts = 1500;
    NetworkEvent first = base;
    base.ts = 2500;
    NetworkEvent middle = base;
    base.ts = 3000;
    NetworkEvent latest = base;

    REQUIRE(t.db.insert_network_events({first, middle, latest}));

    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/1000);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).ts == 3000);
    CHECK(recent->at(0).local_port == 60001);
}

TEST_CASE("TarDatabase: query_recent_tcp_connections filters out LISTEN and TIME_WAIT",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    NetworkEvent established;
    established.ts = 4000;
    established.action = "connected";
    established.proto = "tcp";
    established.local_addr = "10.0.0.10";
    established.local_port = 50100;
    established.remote_addr = "10.0.0.20";
    established.remote_port = 5432;
    established.state = "ESTABLISHED";
    established.pid = 300;
    established.process_name = "node";

    NetworkEvent listen;
    listen.ts = 4001;
    listen.action = "connected";
    listen.proto = "tcp";
    listen.local_addr = "0.0.0.0";
    listen.local_port = 3000;
    listen.remote_addr = "0.0.0.0";
    listen.remote_port = 0;
    listen.state = "LISTEN";
    listen.pid = 300;
    listen.process_name = "node";

    NetworkEvent time_wait;
    time_wait.ts = 4002;
    time_wait.action = "connected";
    time_wait.proto = "tcp";
    time_wait.local_addr = "10.0.0.10";
    time_wait.local_port = 50101;
    time_wait.remote_addr = "10.0.0.20";
    time_wait.remote_port = 5432;
    time_wait.state = "TIME_WAIT";
    time_wait.pid = 300;
    time_wait.process_name = "node";

    REQUIRE(t.db.insert_network_events({established, listen, time_wait}));

    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/0);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).state == "ESTABLISHED");
    CHECK(recent->at(0).local_port == 50100);
}

TEST_CASE("TarDatabase: query with time range filter", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query(
        "SELECT ts FROM process_live WHERE ts >= 1003 AND ts <= 1006 ORDER BY ts");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 4);
    CHECK(results->rows[0][0] == "1003");
    CHECK(results->rows[3][0] == "1006");
}

TEST_CASE("TarDatabase: query with LIMIT", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 20; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query("SELECT ts FROM process_live LIMIT 5");
    REQUIRE(results.has_value());
    CHECK(results->rows.size() == 5);
}

// =============================================================================
// Retention (purge via SQL)
// =============================================================================

TEST_CASE("TarDatabase: purge old records via execute_sql_range", "[tar][store][purge]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    // Delete records with ts < 1005
    REQUIRE(t.db.execute_sql("DELETE FROM process_live WHERE ts < 1005"));

    auto remaining = t.db.execute_query("SELECT ts FROM process_live ORDER BY ts");
    REQUIRE(remaining.has_value());
    CHECK(remaining->rows.size() == 5);
    CHECK(remaining->rows[0][0] == "1005");
}

// =============================================================================
// Stats
// =============================================================================

TEST_CASE("TarDatabase: stats returns correct values", "[tar][store][stats]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 5; ++i) {
        ProcessEvent ev;
        ev.ts = 2000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    // stats() is data-driven over capture_sources() (review S6), so a row in any
    // live table — not just the original four — must be counted. Insert one
    // module_live row (ts within [2000,2004] so oldest/newest are unchanged) and
    // confirm record_count picks it up. Guards against a future regression that
    // drops a source from the aggregate.
    REQUIRE(t.db.execute_sql(
        "INSERT INTO module_live "
        "(ts,snapshot_id,action,pid,process_name,module_name,module_dir,"
        "signed_state,signer,is_kernel) "
        "VALUES (2002, 1, 'loaded', 100, 'app.exe', 'a.dll', '', 'signed', '', 0)"));

    auto s = t.db.stats();
    CHECK(s.record_count == 6); // 5 process_live + 1 module_live
    CHECK(s.oldest_timestamp == 2000);
    CHECK(s.newest_timestamp == 2004);
    CHECK(s.db_size_bytes > 0);
    CHECK(s.retention_days == 7); // default
}

// =============================================================================
// Config get/set
// =============================================================================

TEST_CASE("TarDatabase: config get returns default", "[tar][store][config]") {
    auto t = make_test_db();

    auto val = t.db.get_config("nonexistent", "fallback");
    CHECK(val == "fallback");
}

TEST_CASE("TarDatabase: config set and get", "[tar][store][config]") {
    auto t = make_test_db();

    t.db.set_config("test_key", "test_value");
    auto val = t.db.get_config("test_key");
    CHECK(val == "test_value");

    // Update
    t.db.set_config("test_key", "updated_value");
    val = t.db.get_config("test_key");
    CHECK(val == "updated_value");
}

TEST_CASE("TarDatabase: default retention_days is 7", "[tar][store][config]") {
    auto t = make_test_db();

    auto val = t.db.get_config("retention_days");
    CHECK(val == "7");
}

// =============================================================================
// State get/set
// =============================================================================

TEST_CASE("TarDatabase: state get returns empty for unknown collector", "[tar][store][state]") {
    auto t = make_test_db();

    auto val = t.db.get_state("unknown_collector");
    CHECK(val.empty());
}

TEST_CASE("TarDatabase: state set and get", "[tar][store][state]") {
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

TEST_CASE("TarDatabase: multiple collectors have independent state", "[tar][store][state]") {
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
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 7;
    ev.name = "p";
    REQUIRE(t.db.insert_process_events({ev}));

    auto r = t.db.execute_user_query("SELECT COUNT(*) FROM process_live");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "1");
}

TEST_CASE("execute_user_query: the DEX per-app canned aggregate shape stays authorizer-compatible",
          "[tar][store][sandbox][procperf][pin]") {
    // The server's /dex per-app panel dispatches this exact SQL shape
    // (dex_routes.cpp dex_procperf_sql(), with $ProcPerf_Hourly translated to
    // procperf_hourly). No other test runs aggregates through the REAL
    // authorizer on this table — an authorizer tightening that drops
    // SUM/MAX/CAST/COUNT/GROUP BY/ORDER BY-alias/LIMIT would otherwise break
    // the panel with no CI signal (governance G3 quality-engineer).
    auto t = make_test_db();
    // Three rows for Teams.exe: TWO at hour 3600 (a version flip within the hour,
    // the post-v4 (hour,name,version) granularity) and one at hour 7200. So
    // COUNT(*) == 3 but COUNT(DISTINCT hour_ts) == 2 — they diverge, pinning the
    // happy-path "Hours seen" regression fix (COUNT(*) over-counts across a version
    // change; the correct answer is distinct hourly windows).
    REQUIRE(t.db.execute_sql(
        "INSERT INTO procperf_hourly (hour_ts, name, version, samples, instances_max, "
        "cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes) VALUES "
        "(3600, 'Teams.exe', '1.0.0.0', 120, 6, 8.4, 41.2, 2040109465, 3328599654), "
        "(3600, 'Teams.exe', '2.0.0.0', 60,  4, 5.0, 22.0, 1500000000, 2500000000), "
        "(7200, 'Teams.exe', '2.0.0.0', 120, 5, 4.0, 20.0, 1000000000, 2000000000)"));
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
    CHECK(r->rows[0][1] == "300");  // SUM(samples) across all three rows
    CHECK(r->rows[0][7] == "2");    // COUNT(DISTINCT hour_ts) — NOT 3 (COUNT(*) would over-count)
    // Column names ride the schema line the server parser locates fields by.
    REQUIRE(r->columns.size() == 8);
    CHECK(r->columns[0] == "name");
    CHECK(r->columns[3] == "cpu_avg");
    CHECK(r->columns[5] == "ws_avg");
}

TEST_CASE("execute_user_query: UNION across two allowlisted tables is permitted",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // Both tar_config and tar_state are base tables on the allowlist; Option A
    // preserves the existing read scope rather than restricting to one table.
    auto r =
        t.db.execute_user_query("SELECT key FROM tar_config UNION SELECT collector FROM tar_state");
    CHECK(r.has_value());
}

TEST_CASE("execute_user_query: write statements are denied by the read-only sandbox",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // These bypass validate_and_translate_sql entirely — the read-only handle and
    // authorizer are the layer under test.
    CHECK_FALSE(t.db.execute_user_query("INSERT INTO tar_config VALUES('k','v')").has_value());
    CHECK_FALSE(t.db.execute_user_query("UPDATE tar_config SET value='x'").has_value());
    CHECK_FALSE(t.db.execute_user_query("DELETE FROM tar_config").has_value());
    CHECK_FALSE(t.db.execute_user_query("DROP TABLE tar_config").has_value());
    // The store is untouched.
    CHECK(t.db.get_config("retention_days") == "7");
}

TEST_CASE("execute_user_query: ATTACH / PRAGMA / schema table are denied",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("ATTACH DATABASE 'evil.db' AS e").has_value());
    CHECK_FALSE(t.db.execute_user_query("PRAGMA table_info(tar_config)").has_value());
    CHECK_FALSE(t.db.execute_user_query("SELECT name FROM sqlite_master").has_value());
}

TEST_CASE("execute_user_query: a non-allowlisted table is denied even via UNION",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(
        t.db.execute_user_query("SELECT key FROM tar_config UNION SELECT name FROM sqlite_master")
            .has_value());
}

TEST_CASE("execute_user_query: trailing statement is rejected at prepare",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("SELECT 1; SELECT 2").has_value());
}

// ── validate_and_translate_sql — divergence fix (#631) + existing guards ──────

TEST_CASE("validate_and_translate_sql: $name in code is translated", "[tar][sql][validate]") {
    auto r = validate_and_translate_sql("SELECT * FROM $Process_Live");
    REQUIRE(r.has_value());
    CHECK(r->find("process_live") != std::string::npos);
    CHECK(r->find("$Process_Live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name inside a string literal is NOT translated (#631)",
          "[tar][sql][validate][security]") {
    // The placeholder is data, not a table reference: it must survive verbatim so
    // the executed query equals the one that was validated.
    auto r = validate_and_translate_sql("SELECT '$Process_Live' AS label");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: unknown $name is rejected", "[tar][sql][validate]") {
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Made_Up").has_value());
}

TEST_CASE("validate_and_translate_sql: non-SELECT, multi-statement, oversize rejected",
          "[tar][sql][validate][security]") {
    CHECK_FALSE(validate_and_translate_sql("DELETE FROM $Process_Live").has_value());
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Process_Live; DROP TABLE tar_config")
                    .has_value());
    CHECK_FALSE(validate_and_translate_sql(std::string(5000, 'A')).has_value());
}

// ── #631 divergence — comment + escaped-quote coverage (governance Gate 3) ──

TEST_CASE("validate_and_translate_sql: $name in a line comment is not translated",
          "[tar][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT 1 -- $Process_Live");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name in a block comment is not translated",
          "[tar][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT /* $Process_Live */ 1");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name beside an escaped quote is not translated",
          "[tar][sql][validate][security]") {
    // '' is an escaped single quote inside the literal; the whole token is a
    // string, so $Process_Live within it must survive verbatim.
    auto r = validate_and_translate_sql("SELECT '$Process_Live''s data' AS x");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("execute_user_query: pragma_table_info table-valued function is denied",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // The pragma-as-TVF form reaches the authorizer as SQLITE_READ on a
    // non-allowlisted table name, so it is denied like any other.
    CHECK_FALSE(
        t.db.execute_user_query("SELECT * FROM pragma_table_info('tar_config')").has_value());
}

// =============================================================================
// A2: per-app perf rows + the every-open table-ensure regression
// =============================================================================

TEST_CASE("TarDatabase: insert_proc_perf_samples batch round-trips", "[tar][store][procperf]") {
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
    REQUIRE(t.db.insert_proc_perf_samples(rows));
    REQUIRE(t.db.insert_proc_perf_samples({})); // empty batch is a no-op success

    auto q = t.db.execute_query(
        "SELECT name, version, instances, cpu_pct, ws_bytes, is_kthread FROM procperf_live "
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

TEST_CASE("TarDatabase: insert_netqual_samples batch round-trips", "[tar][store][netqual]") {
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
    REQUIRE(t.db.insert_netqual_samples(rows));
    REQUIRE(t.db.insert_netqual_samples({})); // empty batch is a no-op success

    auto q = t.db.execute_query(
        "SELECT proto, remote_bucket, process_name, rtt_us, lost, segs_out, ca_state "
        "FROM netqual_live ORDER BY process_name");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 3);
    CHECK(q->rows[0][1] == "private");  // app0 destination class
    CHECK(q->rows[0][4] == "0");        // app0 current loss
    CHECK(q->rows[0][6] == "0");        // app0 ca_state = Open
    CHECK(q->rows[2][1] == "public");   // app2 destination class
    CHECK(q->rows[2][4] == "2");        // app2 current loss
    CHECK(q->rows[2][6] == "4");        // app2 ca_state = Loss

    // The degraded-as-query shape (a later server slice): fraction of a
    // snapshot's connections with CURRENT loss. Pin it here so the column
    // semantics stay query-able from the live tier.
    auto frac = t.db.execute_query(
        "SELECT SUM(CASE WHEN lost > 0 THEN 1 ELSE 0 END), COUNT(*) "
        "FROM netqual_live WHERE snapshot_id = 9");
    REQUIRE(frac.has_value());
    REQUIRE(frac->rows.size() == 1);
    CHECK(frac->rows[0][0] == "2"); // 2 of 3 connections currently losing
    CHECK(frac->rows[0][1] == "3");
}

TEST_CASE("netqual: remote_bucket classifies destinations into privacy-safe classes",
          "[tar][netqual][privacy]") {
    using yuzu::tar::remote_bucket;
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
          "[tar][netqual][privacy]") {
    using yuzu::tar::NetQualRow;
    using yuzu::tar::select_netqual_rows;
    using yuzu::tar::TcpQualitySample;

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

TEST_CASE("netqual: select_netqual_rows with cap=0 keeps everything", "[tar][netqual]") {
    using yuzu::tar::select_netqual_rows;
    using yuzu::tar::TcpQualitySample;
    std::vector<TcpQualitySample> samples(5);
    for (auto& s : samples) {
        s.proto = "tcp";
        s.remote_addr = "8.8.8.8";
    }
    auto rows = select_netqual_rows(samples, 1, 1, /*cap=*/0);
    CHECK(rows.size() == 5);
}

TEST_CASE("netqual: collect_netqual_boot off-Windows no-op contract", "[tar][netqual]") {
    // The platform collector itself is NOT driven from a unit test — it reads
    // live OS counters and belongs to the harness/UAT, matching how the ETW /
    // ARP / DNS collectors are treated (docs/tar-implementer.md,
    // test_tar_proc_etw.cpp). Here we pin only the cross-platform contract: off
    // Windows the collector is a clean nullopt no-op. The row's warehouse
    // persistence is covered cross-platform by the insert_netqual_boot_row
    // round-trip test above (hand-built row); the Windows since-boot read is a
    // UAT concern.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
#ifndef _WIN32
    CHECK_FALSE(yuzu::tar::collect_netqual_boot(now).has_value());
#else
    (void)now; // Windows since-boot read is exercised by UAT, not here
#endif
}

TEST_CASE("TarDatabase: insert_netqual_boot_row round-trips every column",
          "[tar][store][netqual]") {
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

TEST_CASE("TarDatabase: insert_netqual_boot_row returns false (no crash) when the table is gone",
          "[tar][store][netqual]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netqual_boot").has_value());
    NetQualBootRow r;
    r.ts = 1;
    CHECK_FALSE(t.db.insert_netqual_boot_row(r));
    REQUIRE(t.db.execute_query("SELECT 1").has_value()); // connection not wedged
}

TEST_CASE("TarDatabase: insert_netconn_events round-trips every column + empty no-op",
          "[tar][store][netconn]") {
    // qe-S1: the netconn insert had zero coverage. Exercise every binding and
    // the empty-batch success, cross-platform (the row struct is platform-free).
    auto t = make_test_db();
    CHECK(t.db.insert_netconn_events({})); // empty batch is a no-op success

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
    REQUIRE(t.db.insert_netconn_events(rows));

    auto res = t.db.execute_query(
        "SELECT ts, snapshot_id, action, channel, category, capability, iface_kind, "
        "reason_code FROM netconn_live ORDER BY ts");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 2);
    CHECK(res->rows[0][2] == "wifi_disconnected");
    CHECK(res->rows[0][3] == "wlan");
    CHECK(res->rows[0][6] == "wifi");
    CHECK(res->rows[0][7] == "229377");
    CHECK(res->rows[1][2] == "capability_changed");
    CHECK(res->rows[1][5] == "internet");
    CHECK(res->rows[1][7] == "4");
}

TEST_CASE("TarDatabase: insert_netconn_events returns false (no crash) when the table is gone",
          "[tar][store][netconn]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netconn_live").has_value());
    NetConnRow r;
    r.ts = 1;
    r.action = "connected";
    r.channel = "networkprofile";
    CHECK_FALSE(t.db.insert_netconn_events({r}));
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("netqual: nq_v6_key includes scope IDs so same-text/different-scope rows are distinct",
          "[tar][netqual]") {
    using yuzu::tar::nq_v4_key;
    using yuzu::tar::nq_v6_key;

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

TEST_CASE("netqual: nq_win_ca_state severity precedence", "[tar][netqual]") {
    using yuzu::tar::NqPathDeltas;
    using yuzu::tar::nq_win_ca_state;

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
          "[tar][netqual]") {
    using yuzu::tar::NqWinCounters;
    using yuzu::tar::nq_win_build_sample;

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

TEST_CASE("TarDatabase: insert_netqual_samples returns false (no crash) when the table is gone",
          "[tar][store][netqual]") {
    // Mirrors the procperf prepare-fail ROLLBACK path: drop netqual_live out
    // from under an open TarDatabase, then insert — prepare fails, the function
    // must ROLLBACK and return false without wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netqual_live").has_value());
    NetQualRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.proto = "tcp";
    r.process_name = "x";
    CHECK_FALSE(t.db.insert_netqual_samples({r}));
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("TarDatabase: insert_proc_perf_samples returns false (no crash) when the table is gone",
          "[tar][store][procperf]") {
    // The prepare-fail ROLLBACK path (gov QE S1): drop procperf_live out from
    // under an open TarDatabase via the trusted exec path, then insert —
    // sqlite3_prepare_v2 fails, the function must ROLLBACK and return false
    // without throwing or wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE procperf_live").has_value());
    ProcPerfRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.name = "x.exe";
    r.instances = 1;
    CHECK_FALSE(t.db.insert_proc_perf_samples({r}));
    // The connection is still usable afterwards (no wedged transaction).
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("TarDatabase: missing warehouse tables are re-created on reopen (upgrade path)",
          "[tar][store][lifecycle]") {
    // The A1 regression this pins: create_warehouse_tables used to run only at
    // schema_version<2, so a table added by a NEWER release (perf tier,
    // procperf tier) never materialised on an upgraded fleet's existing
    // tar.db — inserts then failed every 30 s. The fix runs the idempotent
    // IF-NOT-EXISTS DDL on EVERY open. Simulate the upgrade by dropping a
    // "new" table from a closed v3 DB, then reopening.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_upg_");
    {
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
    } // closed

    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE procperf_live", nullptr, nullptr, nullptr) ==
                SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = TarDatabase::open(tmp); // must re-create the dropped table
        REQUIRE(db.has_value());
        ProcPerfRow r;
        r.ts = 1;
        r.snapshot_id = 1;
        r.name = "x.exe";
        r.instances = 1;
        REQUIRE(db->insert_proc_perf_samples({r}));
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("TarDatabase: a fresh open creates no tar_events table (#760 UP-8)",
          "[tar][store][lifecycle][tar-events]") {
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
    { TarDatabase discard = std::move(t.db); }
    auto reopened = TarDatabase::open(t.path);
    REQUIRE(reopened.has_value());
    CHECK(reopened->schema_version() == 7);
    auto q2 = reopened->execute_query(count_sql);
    REQUIRE(q2.has_value());
    CHECK(q2->rows[0][0] == "0");
    t.db = std::move(*reopened); // hand back so TestTarDb's destructor cleans up
}

TEST_CASE("TarDatabase: a pre-v3 database still has tar_events dropped on open",
          "[tar][store][lifecycle][tar-events]") {
    // The other half of the same invariant: field databases created before v3
    // DO carry the table, and the migration must still retire it. Seed the exact
    // pre-v3 shape by hand (same technique as the v4 ALTER test below).
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_v2_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO tar_config (key, value) VALUES ('schema_version', '2');
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
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 7); // the 2→3→4→5→6→7 walk ran
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
}

TEST_CASE("TarDatabase: schema v5 drops tar_events from an ALREADY-MIGRATED database",
          "[tar][store][lifecycle][tar-events]") {
    // The installed-base case, and the reason removing the DDL is not enough on
    // its own. Every agent in the field reached v3/v4 while kCreateSchema was
    // still recreating tar_events on each open, so those databases carry it
    // NOW. The v3 drop is gated on schema_version()==2 and will never fire for
    // them again — only the v5 bump reaches them. Without it a fresh install and
    // an upgraded endpoint would hold permanently divergent schemas.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_v5_");
    {
        // A v4 database that already carries the resurrected table, exactly as a
        // pre-fix binary would have left it.
        auto seeded = TarDatabase::open(tmp);
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
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 7);
        auto q = db->execute_query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'tar_events' "
                                   "OR name LIKE 'idx_tar_events%'");
        REQUIRE(q.has_value());
        CHECK(q->rows[0][0] == "0");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("TarDatabase: create_warehouse_tables joins a transaction the caller already holds",
          "[tar][store][lifecycle][ddl-batch]") {
    // exec_ddl_batch wraps the DDL in its own transaction for cost and
    // atomicity, but create_warehouse_tables() is public and a caller may
    // already hold one. It must then run the batch unwrapped and JOIN that
    // transaction rather than failing or nesting, and must leave the
    // connection's autocommit state undisturbed either way.
    auto t = make_test_db();
    auto process_live_tables = [&] {
        auto r = t.db.execute_query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='process_live'");
        REQUIRE(r.has_value());
        return r->rows[0][0];
    };

    // Drop a table so the nested call has real work to do, then roll the
    // CALLER's transaction back. Had create_warehouse_tables opened and
    // committed a transaction of its own, the re-created table would SURVIVE
    // that rollback; joining the caller's transaction means it must not. This is
    // what makes the test discriminating rather than merely green.
    REQUIRE(t.db.execute_query("DROP TABLE process_live").has_value());
    REQUIRE(process_live_tables() == "0");

    REQUIRE(t.db.execute_sql("BEGIN IMMEDIATE"));
    CHECK(t.db.create_warehouse_tables());
    CHECK(process_live_tables() == "1"); // recreated inside the caller's txn
    REQUIRE(t.db.execute_sql("ROLLBACK"));
    CHECK(process_live_tables() == "0"); // ...and discarded with it

    // The ordinary un-nested path commits on its own and leaves a usable handle.
    CHECK(t.db.create_warehouse_tables());
    CHECK(process_live_tables() == "1");
    auto q = t.db.execute_query("SELECT COUNT(*) FROM process_live");
    REQUIRE(q.has_value());
}

TEST_CASE("TarDatabase: schema v4 ALTERs version onto a pre-existing procperf tier (upgrade path)",
          "[tar][store][lifecycle][procperf]") {
    // The deployment-critical path the fresh-DB tests never exercise: an
    // UPGRADING agent already has procperf_live/_hourly WITHOUT `version` at
    // schema_version=3, so create_warehouse_tables' IF-NOT-EXISTS leaves them
    // alone and the v4 block's ALTER TABLE ADD COLUMN must run. Seed that exact
    // pre-v4 shape by hand, then open and prove the ALTER fired.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_v4_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO tar_config (key, value) VALUES ('schema_version', '3');
            CREATE TABLE procperf_live (
                ts INTEGER, snapshot_id INTEGER, name TEXT,
                instances INTEGER, cpu_pct REAL, ws_bytes INTEGER);
            CREATE TABLE procperf_hourly (
                hour_ts INTEGER, name TEXT, samples INTEGER, instances_max INTEGER,
                cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER, ws_max_bytes INTEGER);
        )";
        REQUIRE(sqlite3_exec(raw, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 7); // the v3→v4→v5→v6→v7 walk ran

        // Both tiers now carry `version` (added by the ALTER, not the DDL).
        for (const char* tbl : {"procperf_live", "procperf_hourly"}) {
            auto info = db->execute_query(std::string{"PRAGMA table_info("} + tbl + ")");
            REQUIRE(info.has_value());
            bool has_version = false;
            for (const auto& row : info->rows)
                if (row.size() > 1 && row[1] == "version")
                    has_version = true;
            CHECK(has_version);
        }

        // And a real insert carrying a version round-trips through the migrated table.
        ProcPerfRow r;
        r.ts = 11;
        r.snapshot_id = 1;
        r.name = "chrome.exe";
        r.version = "124.0.6367.91";
        r.instances = 2;
        REQUIRE(db->insert_proc_perf_samples({r}));
        auto q = db->execute_query("SELECT version FROM procperf_live WHERE name = 'chrome.exe'");
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        CHECK(q->rows[0][0] == "124.0.6367.91");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("TarDatabase: schema v7 ALTERs is_kthread onto a pre-existing procperf tier "
          "(upgrade path)",
          "[tar][store][lifecycle][procperf]") {
    // Isolates the v7 step specifically: seed the exact POST-v6 shape (both
    // tiers already carry `version`, from the v4 ALTER; schema_version=6) so
    // create_warehouse_tables' IF-NOT-EXISTS leaves them alone and only the
    // v7 block's ALTER TABLE ADD COLUMN is exercised.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_v7_");
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        const char* seed = R"(
            CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
            INSERT INTO tar_config (key, value) VALUES ('schema_version', '6');
            CREATE TABLE procperf_live (
                ts INTEGER, snapshot_id INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '',
                instances INTEGER, cpu_pct REAL, ws_bytes INTEGER);
            CREATE TABLE procperf_hourly (
                hour_ts INTEGER, name TEXT, version TEXT NOT NULL DEFAULT '', samples INTEGER,
                instances_max INTEGER, cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER,
                ws_max_bytes INTEGER);
        )";
        REQUIRE(sqlite3_exec(raw, seed, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
        CHECK(db->schema_version() == 7); // the v6→v7 walk ran

        // Both tiers now carry `is_kthread` (added by the ALTER, not the DDL).
        for (const char* tbl : {"procperf_live", "procperf_hourly"}) {
            auto info = db->execute_query(std::string{"PRAGMA table_info("} + tbl + ")");
            REQUIRE(info.has_value());
            bool has_is_kthread = false;
            for (const auto& row : info->rows)
                if (row.size() > 1 && row[1] == "is_kthread")
                    has_is_kthread = true;
            CHECK(has_is_kthread);
        }

        // A real insert carrying is_kthread=true round-trips through the migrated
        // table (stored as SQLite's INTEGER 0/1).
        ProcPerfRow r;
        r.ts = 21;
        r.snapshot_id = 1;
        r.name = "kworker/0:1";
        r.instances = 1;
        r.is_kthread = true;
        REQUIRE(db->insert_proc_perf_samples({r}));
        auto q =
            db->execute_query("SELECT is_kthread FROM procperf_live WHERE name = 'kworker/0:1'");
        REQUIRE(q.has_value());
        REQUIRE(q->rows.size() == 1);
        CHECK(q->rows[0][0] == "1");
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("TarDatabase: insert and query arp events (ADR-0015)", "[tar][store][crud][arp]") {
    auto t = make_test_db();
    ArpEvent ev;
    ev.ts = 3000;
    ev.snapshot_id = 1;
    ev.action = "appeared";
    ev.iface = "Ethernet"; // bound to the SQL column 'interface'
    ev.ip_address = "192.168.1.1";
    ev.mac_address = "aa:bb:cc:dd:ee:ff";
    ev.entry_type = "dynamic";
    REQUIRE(t.db.insert_arp_events({ev}));
    CHECK(t.db.insert_arp_events({})); // empty input is a no-op success

    auto r = t.db.execute_query(
        "SELECT interface, ip_address, mac_address, entry_type, action FROM arp_live");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "Ethernet");
    CHECK(r->rows[0][1] == "192.168.1.1");
    CHECK(r->rows[0][2] == "aa:bb:cc:dd:ee:ff");
    CHECK(r->rows[0][4] == "appeared");
}

TEST_CASE("TarDatabase: insert and query dns events (ADR-0015)", "[tar][store][crud][dns]") {
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
    REQUIRE(t.db.insert_dns_events({ev}));
    CHECK(t.db.insert_dns_events({})); // empty input is a no-op success

    auto r = t.db.execute_query(
        "SELECT name, record_type, data, ttl_remaining_s, source FROM dns_live");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "example.com");
    CHECK(r->rows[0][2] == "93.184.216.34");
    CHECK(r->rows[0][3] == "60");
    CHECK(r->rows[0][4] == "cache");
}

// ── #559: corrupt-DB quarantine on open ────────────────────────────────────

TEST_CASE("TarDatabase: a corrupt tar.db is quarantined and re-initialised fresh (#559)",
          "[tar][store][lifecycle][corruption]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_corrupt_");

    // 1. Create a real DB and persist a deliberately-paused source. This is the
    //    forensic-preservation state a corrupt read must NOT silently undo.
    {
        auto opened = TarDatabase::open(tmp);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        REQUIRE(db.create_warehouse_tables());
        db.set_config("process_enabled", "false");
        CHECK(db.get_config("process_enabled", "true") == "false");
    } // connection closed; WAL checkpointed into the main file on close

    // 2. Corrupt it: drop any WAL/SHM sidecars and clobber the whole file with
    //    non-SQLite bytes so PRAGMA integrity_check fails deterministically.
    for (const char* suffix : {"-wal", "-shm"}) {
        std::error_code ec;
        fs::remove(fs::path{tmp.string() + suffix}, ec);
    }
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database -- corrupt tar.db for #559";
    }

    // 3. Re-open: must succeed with a FRESH database (not refuse, not trust the
    //    garbage), and quarantine the corrupt file aside for forensic review.
    auto reopened = TarDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    TarDatabase db2 = std::move(*reopened);
    REQUIRE(db2.create_warehouse_tables());

    // Fresh DB → the paused config is gone; the default "true" comes from a
    // CLEAN database, not a silent read-failure default over corrupt bytes.
    CHECK(db2.get_config("process_enabled", "true") == "true");

    // A timestamped quarantine sidecar exists next to the original path.
    bool found_quarantine = false;
    const std::string prefix = tmp.filename().string() + ".corrupt-";
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            found_quarantine = true;
            std::error_code ec;
            fs::remove(entry.path(), ec); // tidy up the quarantine artifact
        }
    }
    CHECK(found_quarantine);

    // #1567: this open knows it quarantined, and the fact is persisted (epoch +
    // basename only) so it survives a restart and can be published fleet-wide.
    REQUIRE(db2.quarantined_this_open().has_value());
    const auto q_epoch = db2.get_config("db_health_last_quarantine_epoch", "");
    CHECK_FALSE(q_epoch.empty());
    CHECK(q_epoch.find_first_not_of("0123456789") == std::string::npos);
    CHECK(q_epoch == std::to_string(*db2.quarantined_this_open()));
    const auto q_file = db2.get_config("db_health_last_quarantine_file", "");
    CHECK(q_file.rfind(tmp.filename().string() + ".corrupt-", 0) == 0);
    CHECK(q_file.find_first_of("/\\") == std::string::npos);

    // A clean re-open of the same path reports no quarantine, but both config
    // rows persist (tar_config is the durable source of truth).
    { TarDatabase discard = std::move(db2); }
    auto clean = TarDatabase::open(tmp);
    REQUIRE(clean.has_value());
    CHECK_FALSE(clean->quarantined_this_open().has_value());
    CHECK(clean->get_config("db_health_last_quarantine_epoch", "") == q_epoch);
    CHECK(clean->get_config("db_health_last_quarantine_file", "") == q_file);
    { TarDatabase discard = std::move(*clean); }
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(tmp.filename().string() + ".corrupt-", 0) == 0) {
            std::error_code ec;
            fs::remove(entry.path(), ec);
        }
    }
    {
        std::error_code ec;
        fs::remove(tmp, ec);
    }
}

TEST_CASE("TarDatabase: a second corruption never overwrites the first quarantine (#559 collision-safe)",
          "[tar][store][lifecycle][corruption]") {
    // Quarantine names are 1-second granular; two corruptions in the same wall
    // second (or after a backward clock step) must NOT rename over each other —
    // that would shred preserved forensic evidence. Drive two corrupt-open
    // cycles back-to-back (same second) and assert TWO distinct `.corrupt-*`
    // files survive.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_collide_");
    const std::string prefix = tmp.filename().string() + ".corrupt-";

    auto corrupt_then_open = [&]() {
        for (const char* suffix : {"-wal", "-shm"}) {
            std::error_code ec;
            fs::remove(fs::path{tmp.string() + suffix}, ec);
        }
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            REQUIRE(f.is_open());
            f << "corrupt tar.db -- collision test #559";
        }
        auto reopened = TarDatabase::open(tmp);
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
}

TEST_CASE("TarDatabase: a valid DB opens cleanly with no quarantine and preserves data (#559)",
          "[tar][store][lifecycle][corruption]") {
    // The happy path: integrity_ok returns true, so a previously-written DB is
    // re-opened in place with its data intact and NO `.corrupt-*` sidecar minted
    // (guards against an integrity_ok that wrongly fails every open).
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_valid_");
    {
        auto opened = TarDatabase::open(tmp);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        db.set_config("process_enabled", "false");
    }
    auto reopened = TarDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    TarDatabase db = std::move(*reopened);
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
}

#ifndef _WIN32
TEST_CASE("TarDatabase: a corrupt-and-unmovable tar.db fails closed (#559 primary)",
          "[tar][store][lifecycle][corruption]") {
    // The PRIMARY #559 safety property: when a corrupt tar.db CANNOT be moved
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

    auto dir = yuzu::test::unique_temp_path("yuzu_test_tar_unmovable_");
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
    const auto db_path = dir / "tar.db";

    // 1. Create a valid DB with a deliberately-paused source, then corrupt it.
    {
        auto opened = TarDatabase::open(db_path);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
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
    auto reopened = TarDatabase::open(db_path);
    CHECK_FALSE(reopened.has_value());
    if (!reopened.has_value())
        CHECK(reopened.error().find("corrupt and unmovable") != std::string::npos);
    // dir_guard restores perms + removes the dir.
}
#endif // _WIN32

// =============================================================================
// checked_transaction (Wave 7 PR7.2b commit 1: strict TAR transaction executor)
// =============================================================================
//
// Fault-injection idiom matches TAR #2361's execute_atomic_batch tests
// (test_tar_aggregator.cpp): a `RAISE(ABORT, ...)` trigger leaves the
// transaction intact (a statement-preserving fault); `RAISE(ROLLBACK, ...)`
// aborts it. Both are real SQLite behaviour, not a mock.

namespace {

int64_t row_count(TarDatabase& db, const std::string& table) {
    auto r = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(r.has_value());
    REQUIRE(!r->rows.empty());
    return std::stoll(r->rows[0][0]);
}

} // namespace

TEST_CASE("checked_transaction: happy path commits every statement together",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (2,1,'started',2,0,'b.exe','','u')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(result.has_value());
    CHECK(row_count(t.db, "process_live") == 2);
}

TEST_CASE("checked_transaction: a fault on the FIRST statement commits nothing",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON process_live "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        // Never reached in a correct implementation -- but written anyway to
        // prove the SECOND statement is not what stops the commit; poisoning
        // is what does, whether or not the callback keeps going.
        h.exec("INSERT INTO tar_config (key,value) VALUES ('canary','1')");
        return {};
    });
    CHECK_FALSE(result.has_value());
    CHECK(row_count(t.db, "process_live") == 0);
    CHECK(t.db.get_config("canary", "") == ""); // the "second statement" never committed either
}

TEST_CASE("checked_transaction: a fault on a MIDDLE statement commits nothing, "
          "not even the earlier statements in the same transaction",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_cfg BEFORE INSERT ON tar_config "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO tar_config (key,value) VALUES ('mid','1')"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (2,1,'started',2,0,'b.exe','','u')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(result.has_value());
    // This is the property execute_atomic_batch does NOT have: the first
    // statement here would be durable under that primitive (it precedes the
    // failure and the batch's data segment is tolerant). checked_transaction
    // has no such segment -- the whole thing is one all-or-nothing unit.
    CHECK(row_count(t.db, "process_live") == 0);
}

TEST_CASE("checked_transaction: a fault on the LAST statement commits nothing",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_cfg BEFORE INSERT ON tar_config "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO tar_config (key,value) VALUES ('last','1')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(result.has_value());
    CHECK(row_count(t.db, "process_live") == 0);
}

TEST_CASE("checked_transaction: a statement-preserving fault (RAISE ABORT) leaves the "
          "connection usable, and a retry without the fault applies exactly once",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON process_live "
                             "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    auto first = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK_FALSE(first.has_value());
    CHECK(t.db.is_open()); // statement-preserving -- the store is NOT taken offline
    REQUIRE(row_count(t.db, "process_live") == 0);

    REQUIRE(t.db.execute_sql("DROP TRIGGER block_ins"));

    auto retry = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(retry.has_value());
    CHECK(row_count(t.db, "process_live") == 1); // applied exactly once, not twice
}

TEST_CASE("checked_transaction: a transaction-aborting fault (RAISE ROLLBACK) stops the "
          "operation from issuing further statements",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("CREATE TRIGGER block_ins BEFORE INSERT ON process_live "
                             "BEGIN SELECT RAISE(ROLLBACK, 'aborted'); END;"));

    int exec_attempts = 0;
    auto result = t.db.checked_transaction(
        [&exec_attempts](TransactionHandle& h) -> std::expected<void, std::string> {
            ++exec_attempts;
            h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                   "VALUES (1,1,'started',1,0,'a.exe','','u')"); // aborts the transaction
            ++exec_attempts;
            // poisoned() now true -- this exec() must no-op, never touch SQLite,
            // never insert the canary row.
            CHECK(h.poisoned());
            const bool second_ran =
                h.exec("INSERT INTO tar_config (key,value) VALUES ('canary','1')");
            CHECK_FALSE(second_ran);
            return {}; // deliberately ignored by the callback -- proves poisoning
                       // wins over a callback that forgets to check
        });
    CHECK_FALSE(result.has_value());
    CHECK(exec_attempts == 2); // both exec() CALLS were attempted by the callback...
    CHECK(t.db.get_config("canary", "") == ""); // ...but the second never touched the DB
    CHECK(row_count(t.db, "process_live") == 0);
}

TEST_CASE("checked_transaction: an already-offline store refuses immediately, no crash",
          "[tar][store][checked_transaction]") {
    // Rollback-fails-with-transaction-still-open (the path that actually
    // TAKES a store offline) needs a disk-level fault this harness cannot
    // induce -- same limitation TAR #2361's "a closed store skips the pass"
    // test documents for execute_atomic_batch's identical wedge path
    // (test_tar_aggregator.cpp). This test covers the downstream behaviour:
    // checked_transaction against an ALREADY-offline connection (db_ ==
    // nullptr, simulated via move exactly as that test does) must refuse via
    // the `if (!db_)` pre-check, never attempt BEGIN, never crash.
    auto t = make_test_db();
    TarDatabase live = std::move(t.db); // t.db is now the closed store

    auto result =
        t.db.checked_transaction([](TransactionHandle&) -> std::expected<void, std::string> {
            FAIL("operation must not run against an offline store");
            return {};
        });
    CHECK_FALSE(result.has_value());
    CHECK(result.error() == "database not open");
}

TEST_CASE("checked_transaction: an exception thrown from the operation still rolls back",
          "[tar][store][checked_transaction]") {
    auto t = make_test_db();
    auto result = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        throw std::runtime_error("simulated fault mid-operation");
    });
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("simulated fault mid-operation") != std::string::npos);
    CHECK(row_count(t.db, "process_live") == 0); // the pre-throw INSERT did not survive
    CHECK(t.db.is_open()); // an exception is not a wedge -- the connection stays usable

    // And the connection genuinely still works afterward.
    auto retry = t.db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!h.exec("INSERT INTO process_live (ts,snapshot_id,action,pid,ppid,name,cmdline,user) "
                    "VALUES (1,1,'started',1,0,'a.exe','','u')"))
            return std::unexpected(h.error());
        return {};
    });
    CHECK(retry.has_value());
    CHECK(row_count(t.db, "process_live") == 1);
}

TEST_CASE("checked_transaction: every statement individually succeeding does not imply "
          "success -- a COMMIT-time failure (deferred FK) still rolls back",
          "[tar][store][checked_transaction]") {
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
// no timing) on tar_state, both the INSERT and the UPDATE form so the test does
// not depend on which UPSERT branch SQLite takes. It hits the same
// `rc != SQLITE_DONE -> ROLLBACK` path a real SQLITE_BUSY would.

static void install_state_fault(TarDatabase& db, const std::string& collector) {
    REQUIRE(db.execute_sql("CREATE TRIGGER yuzu_test_fail_state_i BEFORE INSERT ON tar_state "
                           "WHEN NEW.collector='" + collector +
                           "' BEGIN SELECT RAISE(ABORT,'injected'); END"));
    REQUIRE(db.execute_sql("CREATE TRIGGER yuzu_test_fail_state_u BEFORE UPDATE ON tar_state "
                           "WHEN NEW.collector='" + collector +
                           "' BEGIN SELECT RAISE(ABORT,'injected'); END"));
}

static void drop_state_fault(TarDatabase& db) {
    REQUIRE(db.execute_sql("DROP TRIGGER yuzu_test_fail_state_i"));
    REQUIRE(db.execute_sql("DROP TRIGGER yuzu_test_fail_state_u"));
}

static int64_t count_rows(TarDatabase& db, const std::string& table) {
    auto r = db.execute_query("SELECT COUNT(*) FROM " + table, 1);
    REQUIRE(r.has_value());
    return std::stoll(r->rows[0][0]);
}

TEST_CASE("TarDatabase: process events + baseline are one transaction (#1654)",
          "[tar][store][corruption][atomic]") {
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
    CHECK_FALSE(t.db.insert_process_events({a, b}, StateWrite{"process", "baseline-2"}));
    // Nothing durable: no events, baseline unchanged -> the next tick re-diffs the
    // identical delta instead of double-emitting.
    CHECK(count_rows(t.db, "process_live") == 0);
    CHECK(t.db.get_state("process") == "baseline-1");

    drop_state_fault(t.db);
    CHECK(t.db.insert_process_events({a, b}, StateWrite{"process", "baseline-2"}));
    CHECK(count_rows(t.db, "process_live") == 2);
    CHECK(t.db.get_state("process") == "baseline-2");
}

TEST_CASE("TarDatabase: software + network events + baseline are one transaction (#1654)",
          "[tar][store][corruption][atomic]") {
    auto t = make_test_db();

    SoftwareEvent sw;
    sw.ts = 1000;
    sw.snapshot_id = 1;
    sw.action = "installed";
    sw.name = "app";
    install_state_fault(t.db, "software");
    CHECK_FALSE(t.db.insert_software_events({sw}, StateWrite{"software", "s2"}));
    CHECK(count_rows(t.db, "software_live") == 0);
    CHECK(t.db.get_state("software").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_software_events({sw}, StateWrite{"software", "s2"}));
    CHECK(count_rows(t.db, "software_live") == 1);
    CHECK(t.db.get_state("software") == "s2");

    NetworkEvent ne;
    ne.ts = 1000;
    ne.snapshot_id = 1;
    ne.action = "connected";
    ne.proto = "tcp";
    install_state_fault(t.db, "network");
    CHECK_FALSE(t.db.insert_network_events({ne}, StateWrite{"network", "n2"}));
    CHECK(count_rows(t.db, "tcp_live") == 0);
    CHECK(t.db.get_state("network").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_network_events({ne}, StateWrite{"network", "n2"}));
    CHECK(count_rows(t.db, "tcp_live") == 1);
    CHECK(t.db.get_state("network") == "n2");
}

TEST_CASE("TarDatabase: service/user/arp/dns/mapdrive events + baseline are one transaction (#1654)",
          "[tar][store][corruption][atomic]") {
    auto t = make_test_db();

    ServiceEvent se; se.ts = 1000; se.snapshot_id = 1; se.action = "started"; se.name = "svc";
    install_state_fault(t.db, "service");
    CHECK_FALSE(t.db.insert_service_events({se}, StateWrite{"service", "b2"}));
    CHECK(count_rows(t.db, "service_live") == 0);
    CHECK(t.db.get_state("service").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_service_events({se}, StateWrite{"service", "b2"}));
    CHECK(count_rows(t.db, "service_live") == 1);
    CHECK(t.db.get_state("service") == "b2");

    UserEvent ue; ue.ts = 1000; ue.snapshot_id = 1; ue.action = "login"; ue.user = "alice";
    install_state_fault(t.db, "user");
    CHECK_FALSE(t.db.insert_user_events({ue}, StateWrite{"user", "b2"}));
    CHECK(count_rows(t.db, "user_live") == 0);
    CHECK(t.db.get_state("user").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_user_events({ue}, StateWrite{"user", "b2"}));
    CHECK(count_rows(t.db, "user_live") == 1);
    CHECK(t.db.get_state("user") == "b2");

    ArpEvent ae; ae.ts = 3000; ae.snapshot_id = 1; ae.action = "appeared"; ae.iface = "Ethernet";
    ae.ip_address = "192.168.1.1"; ae.mac_address = "aa:bb:cc:dd:ee:ff"; ae.entry_type = "dynamic";
    install_state_fault(t.db, "arp");
    CHECK_FALSE(t.db.insert_arp_events({ae}, StateWrite{"arp", "b2"}));
    CHECK(count_rows(t.db, "arp_live") == 0);
    CHECK(t.db.get_state("arp").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_arp_events({ae}, StateWrite{"arp", "b2"}));
    CHECK(count_rows(t.db, "arp_live") == 1);
    CHECK(t.db.get_state("arp") == "b2");

    DnsEvent de; de.ts = 3100; de.snapshot_id = 1; de.action = "appeared"; de.name = "example.com";
    de.record_type = "A"; de.data = "93.184.216.34"; de.ttl_remaining_s = 60; de.source = "cache";
    install_state_fault(t.db, "dns");
    CHECK_FALSE(t.db.insert_dns_events({de}, StateWrite{"dns", "b2"}));
    CHECK(count_rows(t.db, "dns_live") == 0);
    CHECK(t.db.get_state("dns").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_dns_events({de}, StateWrite{"dns", "b2"}));
    CHECK(count_rows(t.db, "dns_live") == 1);
    CHECK(t.db.get_state("dns") == "b2");

    MapDriveEvent me{1000, 5, "historical", "outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB", "historical"};
    install_state_fault(t.db, "mapdrive");
    CHECK_FALSE(t.db.insert_mapdrive_events({me}, StateWrite{"mapdrive", "b2"}));
    CHECK(count_rows(t.db, "mapdrive_live") == 0);
    CHECK(t.db.get_state("mapdrive").empty());
    drop_state_fault(t.db);
    CHECK(t.db.insert_mapdrive_events({me}, StateWrite{"mapdrive", "b2"}));
    CHECK(count_rows(t.db, "mapdrive_live") == 1);
    CHECK(t.db.get_state("mapdrive") == "b2");
}

TEST_CASE("TarDatabase: StateWrite with empty events writes only the baseline (#1654)",
          "[tar][store][corruption][atomic]") {
    auto t = make_test_db();
    CHECK(t.db.insert_process_events({}, StateWrite{"process", "only-state"}));
    CHECK(t.db.get_state("process") == "only-state");
    CHECK(count_rows(t.db, "process_live") == 0);

    // nullopt state keeps the historical contract for an open handle byte-for-byte
    // (a closed handle now returns false for the state-carrying overloads).
    CHECK(t.db.insert_process_events({}));
    CHECK(t.db.insert_process_events({}, std::nullopt));
    CHECK(t.db.get_state("process") == "only-state");
}

TEST_CASE("TarDatabase: set_state reports a failed baseline write (#1654)",
          "[tar][store][corruption][atomic]") {
    auto t = make_test_db();
    install_state_fault(t.db, "process");
    CHECK_FALSE(t.db.set_state("process", "x"));
    drop_state_fault(t.db);
    CHECK(t.db.set_state("process", "x"));
    CHECK(t.db.get_state("process") == "x");
}
