// test_echo_warehouse.cpp -- Issue #60 coverage gaps, restated for the roll-up model:
//
//  * every source/tier is in the DDL (the roll-up tiers as `_r` tables and views, the plain
//    tables in the registry's own DDL, and never an index on a view),
//  * the tier-to-tier roll-up SQL the v10 migration uses is defined for exactly the pairs
//    that exist,
//  * retention types and default windows of every tier,
//  * restart double-capture caveat for TCP (documented behavior -- no diff
//    is possible against an empty `previous` snapshot, so all current
//    connections appear as `connected`),
//  * midnight rollover for the daily tier,
//  * schema validation: `columns_for_table` agrees with the GranularityDef
//    column list plus the implicit `id` PK.
//
// These are deliberately store-agnostic tests over the schema-registry API
// so they keep firing as new sources land.

#include "echo_collectors.hpp"
#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "echo_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::echo;

// ── DDL coverage ───────────────────────────────────────────────────────────

TEST_CASE("Echo warehouse DDL: every source/granularity has a table, and a roll-up tier a view",
          "[echo][warehouse][issue60]") {
    const auto plain = generate_warehouse_ddl();
    const auto fold = generate_fold_ddl();
    REQUIRE_FALSE(plain.empty());
    REQUIRE_FALSE(fold.empty());

    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string name = std::string{src.name} + "_" + std::string{g.suffix};
            INFO("tier: " << name);
            if (is_fold_view(name)) {
                // The name is a VIEW over `<name>_r`; the registry's own DDL must not create a
                // table (or an index) under it, or it collides with the view.
                CHECK(fold.find("CREATE TABLE IF NOT EXISTS " + name + "_r") != std::string::npos);
                CHECK(fold.find("CREATE VIEW IF NOT EXISTS " + name + " AS") != std::string::npos);
                CHECK(plain.find(name) == std::string::npos);
            } else {
                CHECK(plain.find("CREATE TABLE IF NOT EXISTS " + name) != std::string::npos);
            }
        }
    }
}

TEST_CASE("Echo warehouse DDL: every source/granularity has a bucket-leading index",
          "[echo][warehouse][issue60]") {
    const auto plain = generate_warehouse_ddl();
    const auto fold = generate_fold_ddl();
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string name = std::string{src.name} + "_" + std::string{g.suffix};
            INFO("tier: " << name);
            if (is_fold_view(name)) {
                // the unique index is both the UPSERT target and the retention index: bucket first
                CHECK(fold.find("CREATE UNIQUE INDEX IF NOT EXISTS " + name + "_r_uq ON " + name +
                                "_r(" + std::string{ts_column_for_suffix(g.suffix)}) !=
                      std::string::npos);
            } else {
                CHECK(plain.find("CREATE INDEX IF NOT EXISTS idx_" + name + "_") != std::string::npos);
            }
        }
    }
}

// ── Schema validation ──────────────────────────────────────────────────────

TEST_CASE("Echo warehouse: columns_for_table includes id + every defined column",
          "[echo][warehouse][issue60]") {
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

TEST_CASE("Echo warehouse: columns_for_table returns empty for unknown table",
          "[echo][warehouse][issue60]") {
    CHECK(columns_for_table("does_not_exist").empty());
}

// ── Dollar-name round trip ─────────────────────────────────────────────────

TEST_CASE("Echo warehouse: every dollar name translates back to a real table",
          "[echo][warehouse][issue60]") {
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

TEST_CASE("Echo warehouse: unknown dollar name returns nullopt",
          "[echo][warehouse][issue60]") {
    CHECK_FALSE(translate_dollar_name("$Made_Up").has_value());
    CHECK_FALSE(translate_dollar_name("not a dollar name").has_value());
}

TEST_CASE("Echo warehouse: is_queryable_table allows registry + base tables, denies others",
          "[echo][warehouse][security]") {
    // Every real warehouse table the registry knows about is queryable — this is
    // the allowlist the read-only SQL sandbox's authorizer enforces (#760) —
    // EXCEPT the three app-usage tables, a deliberate post-loop removal
    // (#4260): they're read only through the Forensics-gated app_usage plugin,
    // never generic echo.sql. Asserted as denials below instead of skipped
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
    CHECK(is_queryable_table("echo_state"));
    CHECK(is_queryable_table("echo_config"));
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

// ── Tier-to-tier roll-up SQL (the v10 migration) ───────────────────────────

TEST_CASE("Echo warehouse roll-up: process hourly -> daily -> monthly",
          "[echo][warehouse][rollup][issue60]") {
    const auto daily = fold_tier_from_tier_sql("process", "hourly", "daily");
    const auto monthly = fold_tier_from_tier_sql("process", "daily", "monthly");
    REQUIRE_FALSE(daily.empty());
    REQUIRE_FALSE(monthly.empty());

    // Each step cites the lower tier's table as its FROM and the upper tier's as its INSERT
    // target -- otherwise we'd be aggregating from the wrong place or writing to the wrong tier.
    CHECK(daily.find("FROM process_hourly_r") != std::string::npos);
    CHECK(monthly.find("FROM process_daily_r") != std::string::npos);
    CHECK(daily.find("INSERT INTO process_daily_r") != std::string::npos);
    CHECK(monthly.find("INSERT INTO process_monthly_r") != std::string::npos);
    // bucketed to the coarser grain, merged by the fold's own rules
    CHECK(daily.find("86400") != std::string::npos);
    CHECK(monthly.find("start of month") != std::string::npos);
    CHECK(daily.find("start_count=start_count+excluded.start_count") != std::string::npos);
    // only rows at or above the mark the caller binds
    CHECK(daily.find("r.hour_ts >= ?1") != std::string::npos);
}

TEST_CASE("Echo warehouse roll-up: tcp hourly -> daily -> monthly",
          "[echo][warehouse][rollup][issue60]") {
    CHECK(fold_tier_from_tier_sql("tcp", "hourly", "daily").find("FROM tcp_hourly_r") !=
          std::string::npos);
    CHECK(fold_tier_from_tier_sql("tcp", "daily", "monthly").find("FROM tcp_daily_r") !=
          std::string::npos);
}

TEST_CASE("Echo warehouse roll-up: service hourly and daily only",
          "[echo][warehouse][rollup][issue60]") {
    CHECK_FALSE(fold_tier_from_tier_sql("service", "hourly", "daily").empty());
    // service has no monthly tier
    CHECK(fold_tier_from_tier_sql("service", "daily", "monthly").empty());
    // a last-by-guard measure carries its guard in the merge
    CHECK(fold_tier_from_tier_sql("service", "hourly", "daily").find("excluded.last_ts>=last_ts") !=
          std::string::npos);
}

TEST_CASE("Echo warehouse roll-up: the daily bucket is the UTC day (midnight rollover)",
          "[echo][warehouse][rollup][issue60]") {
    // Midnight rollover correctness: all events on one UTC day share a daily bucket, whatever
    // the hour. Carry-over (a login on day N still active on day N+1) is a login on day N and no
    // logout until it happens: Echo records *events*, not session durations.
    const int64_t day0 = 1793577600; // 2026-11-02T00:00:00Z
    CHECK(bucket_start(day0, "daily").value() == day0);
    CHECK(bucket_start(day0 + 86399, "daily").value() == day0);
    CHECK(bucket_start(day0 + 86400, "daily").value() == day0 + 86400);
    CHECK(bucket_start(day0 + 3600 * 23 + 59 * 60, "hourly").value() == day0 + 3600 * 23);
    const auto sql = fold_tier_from_tier_sql("user", "hourly", "daily");
    REQUIRE_FALSE(sql.empty());
    CHECK(sql.find("login_count=login_count+excluded.login_count") != std::string::npos);
    CHECK(sql.find("logout_count=logout_count+excluded.logout_count") != std::string::npos);
}

TEST_CASE("Echo warehouse roll-up: unknown source or unsupported step is empty",
          "[echo][warehouse][rollup][issue60]") {
    CHECK(fold_tier_from_tier_sql("nope", "hourly", "daily").empty());
    CHECK(fold_tier_from_tier_sql("process", "hourly", "monthly").empty()); // not a supported step
    CHECK(fold_tier_from_tier_sql("process", "daily", "hourly").empty());
    CHECK(fold_tier_from_tier_sql("usage", "hourly", "daily").empty());     // own tables, no tiers
}

// ── Retention independence across granularities ────────────────────────────

TEST_CASE("Echo warehouse retention: only netqual_boot and usage_live are row-count tables",
          "[echo][warehouse][retention][issue60]") {
    // Retention TYPE is the granularity's declared choice. Every roll-up tier is time-based (the
    // bucket start against a window); the two plain tables that remain keep a row cap.
    std::set<std::string> row_count;
    int time_based = 0;
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            const std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            if (g.retention_type == RetentionType::kRowCount)
                row_count.insert(table);
            else
                ++time_based;
            if (is_fold_view(table)) {
                INFO("tier=" << table);
                CHECK(g.retention_type == RetentionType::kTimeBased);
            }
        }
    }
    CHECK(row_count == std::set<std::string>{"netqual_boot", "usage_live"});
    REQUIRE(time_based > 0); // guard against a vacuous pass
}

TEST_CASE("Echo warehouse retention: each tier keeps its own default window",
          "[echo][warehouse][retention][issue60]") {
    // 90 days hourly, 180 days daily, a year monthly; usage_daily keeps its 31 days.
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            const std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            if (!is_fold_view(table))
                continue;
            INFO("tier=" << table);
            CHECK(g.retention_default == (g.suffix == "hourly"  ? 7776000
                                          : g.suffix == "daily" ? 15552000
                                                                : 31536000));
        }
    }
}

// ── TCP restart / double-capture caveat ─────────────────────────────────────

TEST_CASE("Echo diff: TCP post-restart with empty previous yields all-connected",
          "[echo][diff][network][restart][issue60]") {
    // Documented caveat: after the agent restarts, the saved `network`
    // state in echo_state is empty (or stale). The first collect_fast
    // cycle compares an empty `previous` to a populated `current`, so
    // every currently-open connection emits a `connected` event. This
    // looks like a flood of "new" connections but is the correct
    // behavior — Echo has no way to know which were already open.
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

TEST_CASE("Echo warehouse roll-up: arp/dns are hourly only (ADR-0015)",
          "[echo][warehouse][rollup][arp][dns]") {
    // ARP/DNS keep an hourly tier only -- assert there is no daily/monthly view and no step to
    // one (so a future incorrect granularity is caught).
    for (const auto* source : {"arp", "dns"}) {
        const auto* def = fold_source(source);
        REQUIRE(def != nullptr);
        CHECK(def->tiers == std::vector<std::string_view>{"hourly"});
        CHECK(fold_tier_from_tier_sql(source, "hourly", "daily").empty());
        CHECK_FALSE(is_fold_view(std::string{source} + "_daily"));
        CHECK_FALSE(is_fold_view(std::string{source} + "_monthly"));
    }

    // DDL + $-name translation + the read-only authorizer reach the tables, and the retired raw
    // names answer with an empty shim view rather than failing.
    CHECK(generate_fold_ddl().find("CREATE VIEW IF NOT EXISTS arp_hourly") != std::string::npos);
    CHECK(translate_dollar_name("$ARP_Live").value_or("") == "arp_live");
    CHECK(translate_dollar_name("$ARP_Hourly").value_or("") == "arp_hourly");
    CHECK(translate_dollar_name("$DNS_Hourly").value_or("") == "dns_hourly");
    CHECK(is_queryable_table("arp_live"));
    CHECK(is_queryable_table("arp_hourly"));
    CHECK(is_queryable_table("dns_live"));
    CHECK(is_queryable_table("dns_hourly"));
    CHECK(legacy_live_shim_ddl().find("CREATE VIEW IF NOT EXISTS arp_live") != std::string::npos);
}

TEST_CASE("Echo warehouse roll-up: mapdrive is hourly + daily (§3.8)",
          "[echo][warehouse][rollup][mapdrive]") {
    const auto* def = fold_source("mapdrive");
    REQUIRE(def != nullptr);
    CHECK(def->tiers == std::vector<std::string_view>{"hourly", "daily"});
    CHECK_FALSE(fold_tier_from_tier_sql("mapdrive", "hourly", "daily").empty());
    CHECK(fold_tier_from_tier_sql("mapdrive", "daily", "monthly").empty());

    // `historical` events count in historical_count and in neither appear nor remove: a
    // recent-artifact backfill row cannot emit a phantom appearance (adversarial-review LOW).
    MapDriveEvent historical;
    historical.ts = 1'700'000'000;
    historical.action = "historical";
    historical.direction = "outbound";
    TierAccumulator acc(*def);
    mapdrive_delta({historical}, acc);
    const auto rows = acc.rows("hourly");
    REQUIRE(rows.size() == 1);
    CHECK(std::get<int64_t>(*acc.measure(rows[0], "historical_count")) == 1);
    CHECK(std::get<int64_t>(*acc.measure(rows[0], "appear_count")) == 0);
    CHECK(std::get<int64_t>(*acc.measure(rows[0], "remove_count")) == 0);
    // direction participates in the identity.
    CHECK(std::get<std::string>(*acc.key(rows[0], "direction")) == "outbound");

    CHECK(translate_dollar_name("$MapDrive_Live").value_or("") == "mapdrive_live");
    CHECK(translate_dollar_name("$MapDrive_Hourly").value_or("") == "mapdrive_hourly");
    CHECK(is_queryable_table("mapdrive_live"));
    CHECK(is_queryable_table("mapdrive_hourly"));

    // The tier carries the direction-polymorphic identity columns; the username, provider and
    // origin of the retired raw rows are not kept (the shim keeps their names for old queries).
    auto cols = columns_for_table("mapdrive_hourly");
    for (const auto* c : {"direction", "local_mount", "remote_path", "remote_host"}) {
        INFO("mapdrive_hourly column=" << c);
        CHECK(std::find(cols.begin(), cols.end(), c) != cols.end());
    }
    for (const auto* c : {"username", "provider", "origin"})
        CHECK(std::find(cols.begin(), cols.end(), c) == cols.end());
    auto legacy = columns_for_table("mapdrive_live");
    for (const auto* c : {"direction", "local_mount", "remote_path", "remote_host", "username",
                          "provider", "origin"}) {
        INFO("mapdrive_live (shim) column=" << c);
        CHECK(std::find(legacy.begin(), legacy.end(), c) != legacy.end());
    }
}
