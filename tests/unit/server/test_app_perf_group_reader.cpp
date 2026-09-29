// AppPerfGroupReader (DEX app-perf-over-time slice 2): the on-the-fly B1
// aggregate over a management group's member agent_ids. The headline is that the
// real ANY($1::text[]) member filter + the histogram aggregate SQL execute
// against live Postgres and return the CORRECT per-(version,day) aggregate over
// ONLY the supplied members — the path pure tests can't reach (they'd ship the
// SQL dark, the slice-3a advisor lesson).

#include <catch2/catch_test_macros.hpp>

#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "app_perf_group_reader.hpp"
#include "app_perf_rollup.hpp" // kHistVersion
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::AppPerfGroupReader;
using yuzu::server::AppPerfRollup;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): mirrors the
// tests' store set (the reader carries no migration of its own).
yuzu::test::PgTestTemplate apperf_group_tpl{"apperf_group", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore b1{pool};
    AppPerfGroupReader reader{pool};
    if (!b1.is_open())
        throw std::runtime_error("apperf_group template: store failed to migrate");
}};
std::int64_t today_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}
void seed(AppPerfDailyStore& b1, const std::string& agent, const std::string& app,
          const std::string& ver, std::int64_t day, double cpu_avg, std::int64_t ws_avg) {
    std::vector<AppPerfDailyRow> rows = {{.app_name = app, .version = ver, .day = day,
                                         .samples = 10, .instances_max = 1, .cpu_avg = cpu_avg,
                                         .cpu_max = cpu_avg, .ws_avg_bytes = ws_avg,
                                         .ws_max_bytes = ws_avg}};
    REQUIRE(b1.apply_daily(agent, rows));
}
} // namespace

TEST_CASE("AppPerfGroupReader aggregates ONLY the group's members", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_group_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfGroupReader reader{pool};
    REQUIRE(b1.is_open());
    const std::int64_t day = today_utc() - 86400; // within B1 retention

    // a1..a3 are group members; a4 is NOT (must be excluded by the ANY filter).
    seed(b1, "a1", "chrome.exe", "124.0.0.0", day, 2.0, 50000000);
    seed(b1, "a2", "chrome.exe", "124.0.0.0", day, 2.0, 50000000);
    seed(b1, "a3", "chrome.exe", "124.0.0.0", day, 2.0, 50000000);
    seed(b1, "a4", "chrome.exe", "124.0.0.0", day, 99.0, 9000000000); // non-member
    // a member running a DIFFERENT app — excluded by the app filter, not summed in.
    seed(b1, "a1", "edge.exe", "1.0.0.0", day, 40.0, 8000000000);

    SECTION("member + app filter: device_count counts members only") {
        auto rows = reader.get_group_trend({"a1", "a2", "a3"}, "chrome.exe", "");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        const auto& r = (*rows)[0];
        CHECK(r.app_name == "chrome.exe");
        CHECK(r.version == "124.0.0.0");
        CHECK(r.day == day);
        CHECK(r.device_count == 3); // a4 excluded by ANY(); proves the member filter
        CHECK(std::abs(r.cpu_sum - 6.0) < 1e-6); // 2+2+2, NOT a4's 99
        CHECK(std::abs(r.cpu_max - 2.0) < 1e-6);
        CHECK(r.ws_sum == std::int64_t{150000000});
        CHECK(r.hist_version == AppPerfRollup::kHistVersion);
        // cpu 2.0 -> bucket 3 (half-open [2,3); boundaries {0.5,1,2,...} so >=2 AND
        // <3); ws 50M -> bucket 1 ([32M,64M)).
        CHECK(r.cpu_hist == std::vector<std::int64_t>{0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0});
        CHECK(r.ws_hist == std::vector<std::int64_t>{0, 3, 0, 0, 0, 0, 0, 0, 0, 0});
        std::int64_t total = 0;
        for (auto c : r.cpu_hist)
            total += c;
        CHECK(total == r.device_count);
    }

    SECTION("version filter narrows to the canon-matched version") {
        auto rows = reader.get_group_trend({"a1", "a2", "a3"}, "chrome.exe", "124.0.0.0");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].device_count == 3);
    }

    SECTION("empty member list is a precondition miss, not a degrade") {
        auto rows = reader.get_group_trend({}, "chrome.exe", "");
        REQUIRE(rows.has_value()); // empty value, NOT nullopt
        CHECK(rows->empty());
    }
}
