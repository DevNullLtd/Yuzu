// test_tar_warehouse.cpp -- Issue #60 coverage gaps:
//
//  * every source/table combination is in the DDL,
//  * live-to-aggregate rollup SQL exists for every documented pair,
//  * retention independence across granularities (row-count vs time-based),
//  * restart double-capture caveat for TCP (documented behavior — no diff
//    is possible against an empty `previous` snapshot, so all current
//    connections appear as `connected`),
//  * midnight rollover and carry-over for User_Daily,
//  * schema validation: `columns_for_table` agrees with the GranularityDef
//    column list plus the implicit `id` PK.
//
// These are deliberately store-agnostic tests over the schema-registry API
// so they keep firing as new sources land.

#include "tar_collectors.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::tar;

// ── DDL coverage ───────────────────────────────────────────────────────────

TEST_CASE("TAR warehouse DDL: every source/granularity has CREATE TABLE",
          "[tar][warehouse][issue60]") {
    auto ddl = generate_warehouse_ddl();
    REQUIRE_FALSE(ddl.empty());

    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            std::string create = "CREATE TABLE IF NOT EXISTS " + table;
            INFO("expected DDL: " << create);
            CHECK(ddl.find(create) != std::string::npos);
        }
    }
}

TEST_CASE("TAR warehouse DDL: every source/granularity has a timestamp index",
          "[tar][warehouse][issue60]") {
    auto ddl = generate_warehouse_ddl();
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            std::string idx_prefix = "CREATE INDEX IF NOT EXISTS idx_" + table + "_";
            INFO("expected index prefix: " << idx_prefix);
            CHECK(ddl.find(idx_prefix) != std::string::npos);
        }
    }
}

// ── Schema validation ──────────────────────────────────────────────────────

TEST_CASE("TAR warehouse: columns_for_table includes id + every defined column",
          "[tar][warehouse][issue60]") {
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto cols = columns_for_table(table);
            REQUIRE_FALSE(cols.empty());

            // Implicit id PK is always first.
            CHECK(cols.front() == "id");

            // Every declared column must appear (id + N declared = cols.size).
            CHECK(cols.size() == g.columns.size() + 1);
            for (const auto& declared : g.columns) {
                INFO("table=" << table << " expected col=" << declared.name);
                CHECK(std::find(cols.begin(), cols.end(),
                                std::string{declared.name}) != cols.end());
            }
        }
    }
}

TEST_CASE("TAR warehouse: columns_for_table returns empty for unknown table",
          "[tar][warehouse][issue60]") {
    CHECK(columns_for_table("does_not_exist").empty());
}

// ── Dollar-name round trip ─────────────────────────────────────────────────

TEST_CASE("TAR warehouse: every dollar name translates back to a real table",
          "[tar][warehouse][issue60]") {
    auto names = all_dollar_names();
    REQUIRE_FALSE(names.empty());
    std::set<std::string> seen;
    for (const auto& dn : names) {
        auto translated = translate_dollar_name(dn);
        INFO("dollar name: " << dn);
        REQUIRE(translated.has_value());
        CHECK(!translated->empty());
        CHECK(seen.insert(*translated).second);  // every dollar name is unique
    }
}

TEST_CASE("TAR warehouse: unknown dollar name returns nullopt",
          "[tar][warehouse][issue60]") {
    CHECK_FALSE(translate_dollar_name("$Made_Up").has_value());
    CHECK_FALSE(translate_dollar_name("not a dollar name").has_value());
}

TEST_CASE("TAR warehouse: is_queryable_table allows registry + base tables, denies others",
          "[tar][warehouse][security]") {
    // Every real warehouse table the registry knows about is queryable — this is
    // the allowlist the read-only SQL sandbox's authorizer enforces (#760) —
    // EXCEPT the three app-usage tables, a deliberate post-loop removal
    // (#4260): they're read only through the Forensics-gated app_usage plugin,
    // never generic tar.sql. Asserted as denials below instead of skipped
    // silently, so a future registry change can't silently re-admit them here.
    static const std::unordered_set<std::string> kDeniedDespiteRegistered{
        "usage_live", "usage_daily", "usage_daily_user"};
    for (const auto& dn : all_dollar_names()) {
        auto real = translate_dollar_name(dn);
        REQUIRE(real.has_value());
        INFO("table: " << *real);
        if (kDeniedDespiteRegistered.contains(*real)) {
            CHECK_FALSE(is_queryable_table(*real));
        } else {
            CHECK(is_queryable_table(*real));
        }
    }
    CHECK(is_queryable_table("tar_state"));
    CHECK(is_queryable_table("tar_config"));
    // Not on the allowlist — schema table, server tables, the v3-dropped
    // tar_events (excluded to avoid an existence oracle, #760 UP-8), fabricated.
    CHECK_FALSE(is_queryable_table("tar_events"));
    CHECK_FALSE(is_queryable_table("sqlite_master"));
    CHECK_FALSE(is_queryable_table("users"));
    CHECK_FALSE(is_queryable_table("made_up_table"));
    // #4260: the app-usage tables remain registered (so schema/DDL machinery
    // still sees them) but must never become queryable via this authorizer.
    for (const auto& t : kDeniedDespiteRegistered) CHECK_FALSE(is_queryable_table(t));
}

// ── Rollup SQL coverage ────────────────────────────────────────────────────

TEST_CASE("TAR warehouse rollups: process live -> hourly -> daily -> monthly",
          "[tar][warehouse][rollup][issue60]") {
    CHECK_FALSE(rollup_sql("process", "hourly").empty());
    CHECK_FALSE(rollup_sql("process", "daily").empty());
    CHECK_FALSE(rollup_sql("process", "monthly").empty());

    // Each rollup must cite the lower tier as its FROM and the upper tier
    // as its INSERT INTO target — otherwise we'd be aggregating from the
    // wrong place or writing to the wrong granularity.
    CHECK(rollup_sql("process", "hourly").find("FROM process_live") != std::string::npos);
    CHECK(rollup_sql("process", "daily").find("FROM process_hourly") != std::string::npos);
    CHECK(rollup_sql("process", "monthly").find("FROM process_daily") != std::string::npos);

    CHECK(rollup_sql("process", "hourly").find("INSERT INTO process_hourly") != std::string::npos);
    CHECK(rollup_sql("process", "daily").find("INSERT INTO process_daily") != std::string::npos);
    CHECK(rollup_sql("process", "monthly").find("INSERT INTO process_monthly") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: tcp live -> hourly -> daily -> monthly",
          "[tar][warehouse][rollup][issue60]") {
    CHECK(rollup_sql("tcp", "hourly").find("FROM tcp_live") != std::string::npos);
    CHECK(rollup_sql("tcp", "daily").find("FROM tcp_hourly") != std::string::npos);
    CHECK(rollup_sql("tcp", "monthly").find("FROM tcp_daily") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: service hourly only",
          "[tar][warehouse][rollup][issue60]") {
    CHECK_FALSE(rollup_sql("service", "hourly").empty());
    // Service does not roll up beyond hourly; daily/monthly should be empty.
    CHECK(rollup_sql("service", "daily").empty());
    CHECK(rollup_sql("service", "monthly").empty());
}

TEST_CASE("TAR warehouse rollups: user live -> daily (midnight rollover)",
          "[tar][warehouse][rollup][issue60]") {
    auto sql = rollup_sql("user", "daily");
    REQUIRE_FALSE(sql.empty());
    CHECK(sql.find("FROM user_live") != std::string::npos);
    CHECK(sql.find("INSERT INTO user_daily") != std::string::npos);

    // Midnight rollover correctness: the day boundary is `(ts / 86400) *
    // 86400`, which buckets all events on the same UTC day together.
    // Carry-over (login on day N still active on day N+1) yields a login
    // event on day N and no logout — the user appears in user_daily once,
    // with login_count=1 and logout_count=0. This is intentional: TAR
    // records *events*, not session durations.
    CHECK(sql.find("(ts / 86400) * 86400") != std::string::npos);
    CHECK(sql.find("login_count") != std::string::npos);
    CHECK(sql.find("logout_count") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: unknown source returns empty",
          "[tar][warehouse][rollup][issue60]") {
    CHECK(rollup_sql("nope", "hourly").empty());
    CHECK(rollup_sql("process", "yearly").empty());  // unsupported tier
}

// ── Retention independence across granularities ────────────────────────────

TEST_CASE("TAR warehouse retention: row-count tier uses OFFSET delete pattern",
          "[tar][warehouse][retention][issue60]") {
    // Verify every kRowCount tier's SQL uses the OFFSET-boundary pattern
    // (H6) rather than NOT IN, which is O(n*k) and broke under load.
    // Retention TYPE is the granularity's declared choice, not a property of
    // the tier suffix — perf_live is time-based (a fixed-cadence sampler
    // keeps a time window, so the window must not shrink if an operator
    // raises the sample rate), while the event-diff live tiers are row-count.
    int seen = 0;
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            if (g.retention_type != RetentionType::kRowCount)
                continue;
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
            INFO("table=" << table);
            REQUIRE_FALSE(sql.empty());
            CHECK(sql.find("OFFSET") != std::string::npos);
            CHECK(sql.find("DELETE FROM " + table) != std::string::npos);
            ++seen;
        }
    }
    REQUIRE(seen > 0); // guard against a vacuous pass if no kRowCount tier exists
}

TEST_CASE("TAR warehouse retention: time-based tier uses ts cutoff",
          "[tar][warehouse][retention][issue60]") {
    // Every kTimeBased tier must produce a DELETE with a `< <cutoff>`
    // predicate against the granularity's timestamp column (this includes
    // perf_live — see the row-count test above for why that tier is
    // time-based).
    int seen = 0;
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            if (g.retention_type != RetentionType::kTimeBased) continue;
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
            INFO("table=" << table);
            REQUIRE_FALSE(sql.empty());
            CHECK(sql.find("DELETE FROM " + table) != std::string::npos);
            CHECK(sql.find("<") != std::string::npos);
            ++seen;
        }
    }
    REQUIRE(seen > 0); // guard against a vacuous pass if no kTimeBased tier exists
}

TEST_CASE("TAR warehouse retention: each granularity retains independently",
          "[tar][warehouse][retention][issue60]") {
    // Independence invariant: deleting from a daily table must not touch
    // the hourly table for the same source, and vice versa. The SQL is
    // single-table, so this is true by construction — but the test pins
    // the contract so a future "join cleanup" refactor cannot accidentally
    // couple them.
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
            REQUIRE_FALSE(sql.empty());
            // For every OTHER granularity in the same source, the SQL must
            // not name that table.
            for (const auto& other : src.granularities) {
                if (other.suffix == g.suffix) continue;
                std::string other_table = std::string{src.name} + "_" + std::string{other.suffix};
                INFO("retention sql for " << table << " must not mention " << other_table);
                CHECK(sql.find(other_table) == std::string::npos);
            }
        }
    }
}

// ── TCP restart / double-capture caveat ─────────────────────────────────────

TEST_CASE("TAR diff: TCP post-restart with empty previous yields all-connected",
          "[tar][diff][network][restart][issue60]") {
    // Documented caveat: after the agent restarts, the saved `network`
    // state in tar_state is empty (or stale). The first collect_fast
    // cycle compares an empty `previous` to a populated `current`, so
    // every currently-open connection emits a `connected` event. This
    // looks like a flood of "new" connections but is the correct
    // behavior — TAR has no way to know which were already open.
    //
    // This test pins the behavior so a future refactor that tries to
    // suppress the post-restart "flood" doesn't silently break the
    // forensic timeline.
    std::vector<NetConnection> previous;  // post-restart: empty
    std::vector<NetConnection> current = {
        {.proto = "tcp", .local_addr = "192.168.1.10", .remote_addr = "10.0.0.5",
         .remote_host = "", .local_port = 22, .remote_port = 50001,
         .state = "ESTABLISHED", .pid = 1234, .process_name = "sshd"},
        {.proto = "tcp", .local_addr = "192.168.1.10", .remote_addr = "10.0.0.6",
         .remote_host = "", .local_port = 443, .remote_port = 51022,
         .state = "ESTABLISHED", .pid = 5678, .process_name = "nginx"},
    };

    auto events = compute_network_diff(previous, current,
                                        /*timestamp=*/1'700'000'000,
                                        /*snapshot_id=*/1);

    REQUIRE(events.size() == 2);
    for (const auto& e : events) {
        CHECK(e.event_action == "connected");
    }
}

TEST_CASE("TAR warehouse rollups: arp/dns are live + hourly only (ADR-0015)",
          "[tar][warehouse][rollup][arp][dns]") {
    // ARP/DNS have a live + hourly tier only — assert the hourly rollup exists and
    // the daily/monthly tiers do NOT (so a future incorrect granularity is caught).
    CHECK_FALSE(rollup_sql("arp", "hourly").empty());
    CHECK(rollup_sql("arp", "daily").empty());
    CHECK(rollup_sql("arp", "monthly").empty());
    CHECK(rollup_sql("arp", "hourly").find("FROM arp_live") != std::string::npos);
    CHECK(rollup_sql("arp", "hourly").find("INSERT INTO arp_hourly") != std::string::npos);

    CHECK_FALSE(rollup_sql("dns", "hourly").empty());
    CHECK(rollup_sql("dns", "daily").empty());
    CHECK(rollup_sql("dns", "monthly").empty());
    CHECK(rollup_sql("dns", "hourly").find("FROM dns_live") != std::string::npos);
    CHECK(rollup_sql("dns", "hourly").find("INSERT INTO dns_hourly") != std::string::npos);

    // DDL + $-name translation + the read-only authorizer reach the new tables.
    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("arp_live") != std::string::npos);
    CHECK(ddl.find("dns_hourly") != std::string::npos);
    CHECK(translate_dollar_name("$ARP_Live").value_or("") == "arp_live");
    CHECK(translate_dollar_name("$DNS_Hourly").value_or("") == "dns_hourly");
    CHECK(is_queryable_table("arp_live"));
    CHECK(is_queryable_table("dns_live"));
}

TEST_CASE("TAR warehouse rollups: mapdrive is live + hourly only (§3.8)",
          "[tar][warehouse][rollup][mapdrive]") {
    CHECK_FALSE(rollup_sql("mapdrive", "hourly").empty());
    CHECK(rollup_sql("mapdrive", "daily").empty());
    CHECK(rollup_sql("mapdrive", "monthly").empty());
    CHECK(rollup_sql("mapdrive", "hourly").find("FROM mapdrive_live") != std::string::npos);
    CHECK(rollup_sql("mapdrive", "hourly").find("INSERT INTO mapdrive_hourly") !=
          std::string::npos);
    // direction participates in the rollup grouping.
    CHECK(rollup_sql("mapdrive", "hourly").find("direction") != std::string::npos);
    // `historical` rows are excluded so a recent-artifact backfill row cannot emit a
    // zero-count hourly row (adversarial-review LOW).
    CHECK(rollup_sql("mapdrive", "hourly").find("action IN ('appeared', 'removed')") !=
          std::string::npos);

    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("mapdrive_live") != std::string::npos);
    CHECK(ddl.find("mapdrive_hourly") != std::string::npos);
    CHECK(translate_dollar_name("$MapDrive_Live").value_or("") == "mapdrive_live");
    CHECK(translate_dollar_name("$MapDrive_Hourly").value_or("") == "mapdrive_hourly");
    CHECK(is_queryable_table("mapdrive_live"));
    CHECK(is_queryable_table("mapdrive_hourly"));

    // The live table carries the direction-polymorphic columns + origin.
    auto cols = columns_for_table("mapdrive_live");
    for (const auto* c : {"direction", "local_mount", "remote_path", "remote_host", "username",
                          "provider", "origin"}) {
        INFO("mapdrive_live column=" << c);
        CHECK(std::find(cols.begin(), cols.end(), c) != cols.end());
    }
}
