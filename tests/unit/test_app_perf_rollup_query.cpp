// Integration: the agent's app_perf rollup query (sync_source_app_perf, DEX
// app-perf-over-time B1) must survive the REAL TAR `sql` path end-to-end —
// `$ProcPerf_Hourly` translation, the SELECT validator, AND the read-only
// authorizer — and return correctly-aggregated rows. The pure agent unit tests
// only string-match `build_app_perf_query`; this is the one cross-module path
// (agent query → tar validator/authorizer/SQLite) that would otherwise fail
// SILENTLY in production (B1 stays empty) with every unit test green. It lives in
// the tar suite because only that exe compiles both agent-core (the query
// builder) and the tar SQL executor + warehouse DB.

#include <catch2/catch_test_macros.hpp>

#include "sync_source_app_perf.hpp" // build_app_perf_query (agent-core)
#include "tar_db.hpp"               // TarDatabase
#include "tar_sql_executor.hpp"     // validate_and_translate_sql
#include "test_helpers.hpp"

#include <cmath>
#include <cstdint>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using yuzu::agent::build_app_perf_query;
using yuzu::tar::TarDatabase;

namespace {
struct TestDb {
    TarDatabase db;
    fs::path path;
    ~TestDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};
TestDb make_db() {
    auto tmp = yuzu::test::unique_temp_path("tar_appperf_");
    auto r = TarDatabase::open(tmp);
    REQUIRE(r.has_value());
    return TestDb{std::move(*r), tmp};
}
} // namespace

TEST_CASE("app_perf rollup query survives the real TAR sql path", "[tar][app_perf]") {
    auto t = make_db();
    // 2025-01-01 00:00:00 UTC — exactly divisible by 86400, so (hour_ts/86400)*86400
    // == day_start for both seed rows.
    const std::int64_t day_start = 1735689600;
    const std::int64_t window_start = day_start;
    const std::int64_t today_start = day_start + 86400; // half-open [day_start, +1d)

    // Seed two procperf_hourly rows: same (name, version), two hours of the same
    // UTC day (trusted DML seed — what the rollup would have written).
    REQUIRE(t.db.execute_sql(
        "INSERT INTO procperf_hourly "
        "(hour_ts, name, version, samples, instances_max, cpu_avg, cpu_max, ws_avg_bytes, "
        " ws_max_bytes) VALUES "
        "(" +
        std::to_string(day_start) +
        ", 'chrome.exe', '119.0.0.0', 10, 2, 90.0, 95.0, 100, 200),"
        "(" +
        std::to_string(day_start + 3600) + ", 'chrome.exe', '119.0.0.0', 30, 5, 10.0, 20.0, 300, 400)"));

    const std::string sql = build_app_perf_query(window_start, today_start);

    SECTION("translates $ProcPerf_Hourly and passes the SELECT validator") {
        auto validated = yuzu::tar::validate_and_translate_sql(sql);
        REQUIRE(validated.has_value()); // SELECT-start, no dangerous kw, single stmt, <=4KB
        CHECK(validated->find("procperf_hourly") != std::string::npos); // $-name translated
        CHECK(validated->find('$') == std::string::npos);               // nothing left untranslated
    }

    SECTION("passes the authorizer and returns the sample-weighted aggregate row") {
        auto validated = yuzu::tar::validate_and_translate_sql(sql);
        REQUIRE(validated.has_value());
        auto res = t.db.execute_user_query(*validated);
        REQUIRE(res.has_value()); // authorizer accepts (day-bucket arithmetic, aggregates, version col)
        REQUIRE(res->rows.size() == 1); // one (name, version, day) group
        const auto& row = res->rows[0];
        REQUIRE(row.size() == 9); // SELECT column order = build_app_perf_query's contract
        CHECK(row[0] == "chrome.exe");
        CHECK(row[1] == "119.0.0.0");
        CHECK(row[2] == std::to_string(day_start));            // (hour_ts/86400)*86400
        CHECK(row[3] == "40");                                 // SUM(samples)
        CHECK(row[4] == "5");                                  // MAX(instances_max)
        CHECK(std::abs(std::stod(row[5]) - 30.0) < 1e-6);      // (90*10+10*30)/40 sample-weighted
        CHECK(std::abs(std::stod(row[6]) - 95.0) < 1e-6);      // MAX(cpu_max)
        CHECK(row[7] == "250");                                // (100*10+300*30)/40 integer
        CHECK(row[8] == "400");                                // MAX(ws_max_bytes)
    }
}

TEST_CASE("app_perf rollup query excludes is_kthread rows, keeps normal processes",
          "[tar][app_perf][procperf]") {
    // Kernel threads (Linux PF_KTHREAD) and the Windows System process (pid 4)
    // are recorded unfiltered into procperf_hourly (the live TAR tier keeps
    // them — tar_proc_perf.hpp's "Kernel-thread marker" note); this rollup
    // query is the ONE place that excludes them from the daily app-perf
    // history sent to the server.
    auto t = make_db();
    const std::int64_t day_start = 1735689600;
    const std::int64_t window_start = day_start;
    const std::int64_t today_start = day_start + 86400;

    REQUIRE(t.db.execute_sql(
        "INSERT INTO procperf_hourly "
        "(hour_ts, name, version, is_kthread, samples, instances_max, cpu_avg, cpu_max, "
        " ws_avg_bytes, ws_max_bytes) VALUES "
        "(" +
        std::to_string(day_start) +
        ", 'kworker/0:1', '', 1, 10, 1, 5.0, 8.0, 0, 0)," // kernel thread — excluded
        "(" +
        std::to_string(day_start) +
        ", 'normal.exe', '1.0.0.0', 0, 10, 2, 12.5, 20.0, 1024, 2048)")); // normal — included

    const std::string sql = build_app_perf_query(window_start, today_start);
    auto validated = yuzu::tar::validate_and_translate_sql(sql);
    REQUIRE(validated.has_value());
    CHECK(validated->find("is_kthread") != std::string::npos);
    auto res = t.db.execute_user_query(*validated);
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1); // the kernel-thread row never reaches the output
    CHECK(res->rows[0][0] == "normal.exe");
}
