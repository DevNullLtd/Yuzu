// AppPerfRollup (DEX app-perf-over-time B2): the B1->B2 cross-store roll-up query
// owner + AppPerfFleetStore read/prune. The headline is the HISTOGRAM-BOUNDARY
// test — seed per-device B1 values that land ON and STRADDLE bucket boundaries,
// run the real roll-up, and assert the EXACT cpu_hist[]/ws_hist[] count arrays.
// A naive "a B2 row appeared" test would pass while the half-open FILTER
// predicates are off-by-one; the wrong histogram would only surface as wrong
// percentiles in slice 2, every test green.

#include <catch2/catch_test_macros.hpp>

#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "app_perf_rollup.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::AppPerfFleetStore;
using yuzu::server::AppPerfRollup;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): mirrors the
// tests' store set (the rollup query owner carries no migration of its own).
yuzu::test::PgTestTemplate apperf_rollup_tpl{"apperf_rollup", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    if (!b1.is_open())
        throw std::runtime_error("apperf_rollup template: B1 store failed to migrate");
    if (!b2.is_open())
        throw std::runtime_error("apperf_rollup template: B2 store failed to migrate");
}};
std::int64_t today_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}
// Seed one device's B1 row through the real B1 write path.
void seed(AppPerfDailyStore& b1, const std::string& agent, const std::string& app,
          const std::string& ver, std::int64_t day, double cpu_avg, std::int64_t ws_avg) {
    std::vector<AppPerfDailyRow> rows = {{.app_name = app, .version = ver, .day = day,
                                         .samples = 10, .instances_max = 1, .cpu_avg = cpu_avg,
                                         .cpu_max = cpu_avg, .ws_avg_bytes = ws_avg,
                                         .ws_max_bytes = ws_avg}};
    REQUIRE(b1.apply_daily(agent, rows));
}
} // namespace

TEST_CASE("build_hist_array_sql emits half-open [lo,hi) FILTER buckets", "[app_perf][rollup]") {
    const auto s = AppPerfRollup::build_hist_array_sql("x", {"1", "2"});
    CHECK(s == "ARRAY[COUNT(*) FILTER (WHERE x < 1), "
               "COUNT(*) FILTER (WHERE x >= 1 AND x < 2), "
               "COUNT(*) FILTER (WHERE x >= 2)]::bigint[]");
}

TEST_CASE("AppPerfRollup B1->B2 roll-up", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_rollup_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfFleetStore b2{pool};
    AppPerfRollup rollup{pool};
    REQUIRE(b1.is_open());
    REQUIRE(b2.is_open());
    const std::int64_t day = today_utc() - 86400; // within B1's 31d retention

    SECTION("histogram counts are exact on/straddling bucket boundaries") {
        // cpu_buckets = {0.5,1,2,3,5,8,12,20,30,50,75} -> 12 buckets [0..11].
        // values: 0.0->b0(<0.5), 0.5->b1([0.5,1) lower-inclusive), 1.0->b2([1,2)),
        //         75.0->b11(>=75), 100.0->b11.
        // ws_buckets = {32M,64M,128M,256M,512M,1G,2G,4G,8G} -> 10 buckets [0..9].
        // values: 0->b0(<32M), 33554432(=32M)->b1, 50000000->b1([32M,64M)),
        //         100000000->b2([64M,128M)), 9000000000->b9(>=8G).
        seed(b1, "a1", "chrome.exe", "119.0.0.0", day, 0.0, 0);
        seed(b1, "a2", "chrome.exe", "119.0.0.0", day, 0.5, 33554432);
        seed(b1, "a3", "chrome.exe", "119.0.0.0", day, 1.0, 50000000);
        seed(b1, "a4", "chrome.exe", "119.0.0.0", day, 75.0, 100000000);
        seed(b1, "a5", "chrome.exe", "119.0.0.0", day, 100.0, 9000000000);

        REQUIRE(rollup.roll_day(day));
        auto rows = b2.get_app_fleet_perf("chrome.exe", "");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        const auto& r = (*rows)[0];
        CHECK(r.device_count == 5);
        CHECK(r.hist_version == AppPerfRollup::kHistVersion);
        CHECK(std::abs(r.cpu_sum - 176.5) < 1e-6); // 0+0.5+1+75+100
        CHECK(std::abs(r.cpu_max - 100.0) < 1e-6);
        CHECK(r.ws_sum == std::int64_t{9183554432}); // 0+33554432+50000000+100000000+9000000000
        CHECK(r.ws_max == std::int64_t{9000000000});
        CHECK(r.cpu_hist == std::vector<std::int64_t>{1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2});
        CHECK(r.ws_hist == std::vector<std::int64_t>{1, 2, 1, 0, 0, 0, 0, 0, 0, 1});
        std::int64_t cpu_total = 0;
        for (auto c : r.cpu_hist)
            cpu_total += c;
        CHECK(cpu_total == r.device_count); // histogram sums to device_count
    }

    SECTION("full-version grain: distinct versions stay separate rows") {
        seed(b1, "a1", "app.exe", "1.0.0.0", day, 10.0, 1000);
        seed(b1, "a2", "app.exe", "2.0.0.0", day, 20.0, 2000);
        REQUIRE(rollup.roll_day(day));
        auto rows = b2.get_app_fleet_perf("app.exe", "");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 2);
        CHECK((*rows)[0].version == "1.0.0.0"); // ORDER BY version
        CHECK((*rows)[1].version == "2.0.0.0");
    }

    SECTION("re-roll is idempotent (ON CONFLICT overwrites, not doubles)") {
        seed(b1, "a1", "x.exe", "1.0.0.0", day, 5.0, 1000);
        REQUIRE(rollup.roll_day(day));
        REQUIRE(rollup.roll_day(day)); // second roll, same data
        auto rows = b2.get_app_fleet_perf("x.exe", "1.0.0.0");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].device_count == 1); // not 2
    }

    SECTION("read: unknown app = empty value (not nullopt); empty app_name = empty") {
        auto none = b2.get_app_fleet_perf("nope.exe", "");
        REQUIRE(none.has_value());
        CHECK(none->empty());
        auto empty = b2.get_app_fleet_perf("", "");
        REQUIRE(empty.has_value());
        CHECK(empty->empty());
    }

    SECTION("rollup saturates a >INT64_MAX ws sum instead of aborting the day (UP-1)") {
        // Two devices with near-INT64_MAX working set on the same (app,version,day):
        // their SUM(ws) exceeds INT64_MAX. Inserted RAW (bypassing the per-row clamp)
        // to exercise the rollup's LEAST(SUM, INT64_MAX) backstop — the day must still
        // roll (COMMAND_OK, not a 22003 abort) and ws_sum saturates to INT64_MAX
        // rather than poisoning the WHOLE fleet-day.
        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            const char* ins = "INSERT INTO app_perf_daily_store.app_perf_daily "
                              "(agent_id, app_name, version, day, samples, instances_max, "
                              " cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes, updated_at) "
                              "VALUES ($1,'big.exe','1.0',$2,1,1,1.0,1.0,$3,$3,0)";
            for (const char* ag : {"d1", "d2"}) {
                auto r = yuzu::server::pg::exec_params(
                    lease.get(), ins,
                    std::vector<std::string>{ag, std::to_string(day),
                                             std::string("5000000000000000000")}); // 5e18
                REQUIRE(r.status() == PGRES_COMMAND_OK);
            }
        }
        REQUIRE(rollup.roll_day(day)); // must NOT abort on the bigint-overflow cast
        // Query all-versions ("") — the raw-inserted version "1.0" is stored verbatim,
        // and the all-versions read applies no canon filter.
        auto rows = b2.get_app_fleet_perf("big.exe", "");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].device_count == 2);
        CHECK((*rows)[0].ws_sum == std::int64_t{9223372036854775807}); // saturated, not aborted
    }

    SECTION("prune deletes day-buckets older than the retention window (clock-guarded)") {
        // Both within B1's 31-day retention so roll_day rolls them into B2; the
        // prune window sits between them.
        const std::int64_t old_day = today_utc() - 25 * 86400; // 25 days ago
        const std::int64_t recent_day = today_utc() - 1 * 86400; // 1 day ago
        seed(b1, "a1", "p.exe", "1.0.0.0", old_day, 5.0, 1000);
        seed(b1, "a1", "p.exe", "1.0.0.0", recent_day, 5.0, 1000);
        REQUIRE(rollup.roll_day(old_day));
        REQUIRE(rollup.roll_day(recent_day));
        // WS-10: run_retention_prune reads Postgres now() and takes the retention
        // WINDOW in SECONDS (the `day` column is day-floored unix-seconds). A
        // 12-day window deletes the 25-day bucket and keeps the 1-day one. The
        // clock guard's part-6 Decline means the FIRST pass on a store with data
        // but no persisted anchor declines (records the anchor, deletes nothing).
        const std::int64_t window = 12LL * 86400;
        CHECK(b2.run_retention_prune(window) == 0); // bootstrap decline
        CHECK(b2.run_retention_prune(window) >= 1);
        REQUIRE(b2.get_app_fleet_perf("p.exe", "")->size() == 1); // only recent survives
    }

    SECTION("prune DAY-FLOORS the cutoff — the boundary bucket is not deleted ~24h early (WS-10 S1)") {
        // The spec's cutoff_align=86400 floors ONLY the cutoff (now_expr stays RAW —
        // flooring the reading itself would false-fire a 24h Step at every midnight,
        // WS-10 C1). So cutoff = floor((raw_now - window)/day)*day is day-aligned and a
        // bucket EXACTLY at floor(now)-window survives (== cutoff, not < cutoff).
        // Without cutoff alignment the cutoff would be raw_now - window, up to ~24h
        // later, and delete that boundary bucket. At any non-midnight-UTC second — the
        // normal case — the two cutoffs differ.
        const std::int64_t window = 10LL * 86400;
        const std::int64_t old_day = today_utc() - 11 * 86400;      // < cutoff → deleted
        const std::int64_t boundary_day = today_utc() - 10 * 86400; // == floored cutoff → survives
        const std::int64_t recent_day = today_utc();                // survivor (avoids would_wipe)
        seed(b1, "a1", "bnd.exe", "1.0.0.0", old_day, 5.0, 1000);
        seed(b1, "a1", "bnd.exe", "1.0.0.0", boundary_day, 5.0, 1000);
        seed(b1, "a1", "bnd.exe", "1.0.0.0", recent_day, 5.0, 1000);
        REQUIRE(rollup.roll_day(old_day));
        REQUIRE(rollup.roll_day(boundary_day));
        REQUIRE(rollup.roll_day(recent_day));
        CHECK(b2.run_retention_prune(window) == 0); // bootstrap decline
        CHECK(b2.run_retention_prune(window) >= 1);
        // Boundary + recent survive; only the strictly-older bucket is gone. A
        // non-day-floored cutoff would delete the boundary bucket too (size == 1).
        REQUIRE(b2.get_app_fleet_perf("bnd.exe", "")->size() == 2);
    }
}
