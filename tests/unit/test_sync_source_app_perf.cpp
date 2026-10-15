// app_perf daily-sync source (DEX app-perf-over-time B1) — pure agent-side
// helpers: the rollup query shape, the TAR `sql`-action output parse, version
// canon + sample-weighted merge, and the wire-blob render.

#include <catch2/catch_test_macros.hpp>

#include "sync_source_app_perf.hpp"

#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

using yuzu::agent::AppPerfRow;
using yuzu::agent::build_app_perf_query;
using yuzu::agent::canon_merge_app_perf;
using yuzu::agent::parse_app_perf_sql_output;
using yuzu::agent::render_app_perf_blob;

TEST_CASE("build_app_perf_query targets $ProcPerf_Hourly over the window", "[app_perf][agent]") {
    const std::string q = build_app_perf_query(86400, 259200); // [day1, day3)
    CHECK(q.rfind("SELECT", 0) == 0); // tar sql validator: must start with SELECT
    CHECK(q.find("$ProcPerf_Hourly") != std::string::npos);
    CHECK(q.find("hour_ts >= 86400") != std::string::npos);
    CHECK(q.find("hour_ts < 259200") != std::string::npos);
    CHECK(q.find("GROUP BY name, version") != std::string::npos);
    CHECK(q.size() < 4096); // tar sql 4KB limit
}

TEST_CASE("build_app_perf_query excludes kernel-thread / Windows System rows",
          "[app_perf][agent]") {
    // Kernel threads (Linux PF_KTHREAD) and the Windows System process (pid 4)
    // are recorded unfiltered into procperf_live/_hourly (the live TAR tier
    // keeps them by design); this daily rollup is the one place that excludes
    // them from the app-perf-over-time history sent to the server.
    const std::string q = build_app_perf_query(86400, 259200);
    CHECK(q.find("AND NOT is_kthread") != std::string::npos);
    // Must sit inside the WHERE clause, not the SELECT list or GROUP BY — the
    // wire/parse contract (9 positional columns) never changes shape.
    CHECK(q.find("is_kthread") > q.find("WHERE"));
    CHECK(q.find("is_kthread") < q.find("GROUP BY"));
}

TEST_CASE("parse_app_perf_sql_output skips markers and parses data rows", "[app_perf][agent]") {
    const std::string out =
        "__schema__|name|version|day|samples|instances_max|cpu_avg|cpu_max|ws_avg_bytes|ws_max_bytes\n"
        "chrome.exe|119.0.1.2|86400|120|3|12.5|80|1048576|2097152\n"
        "__total__|1\n";
    auto rows = parse_app_perf_sql_output(out);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "chrome.exe");
    CHECK(rows[0].version == "119.0.1.2");
    CHECK(rows[0].day == 86400);
    CHECK(rows[0].samples == 120);
    CHECK(rows[0].instances_max == 3);
    CHECK(std::abs(rows[0].cpu_avg - 12.5) < 1e-9);
    CHECK(rows[0].ws_avg_bytes == 1048576);
    CHECK(rows[0].ws_max_bytes == 2097152);
}

TEST_CASE("parse_app_perf_sql_output drops error/empty-name/bad-day rows", "[app_perf][agent]") {
    const std::string out =
        "error|something failed\n"
        "|1.0|86400|1|1|1|1|1|1\n"        // empty name -> dropped
        "ok.exe|1.0|0|1|1|1|1|1|1\n"      // day<=0 -> dropped
        "ok.exe|1.0|86400|1|1|1|1|1|1\n"; // good
    auto rows = parse_app_perf_sql_output(out);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "ok.exe");
}

TEST_CASE("canon_merge_app_perf canons version + merges collisions sample-weighted",
          "[app_perf][agent]") {
    std::vector<AppPerfRow> rows = {
        {.name = "app", .version = "1.2.3", .day = 86400, .samples = 10, .instances_max = 2,
         .cpu_avg = 90.0, .cpu_max = 95.0, .ws_avg_bytes = 100, .ws_max_bytes = 200},
        {.name = "app", .version = "1.2.3.0", .day = 86400, .samples = 30, .instances_max = 5,
         .cpu_avg = 10.0, .cpu_max = 20.0, .ws_avg_bytes = 300, .ws_max_bytes = 400},
    };
    auto m = canon_merge_app_perf(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].version == "1.2.3.0"); // both canon to the 4-quad -> one key
    CHECK(m[0].samples == 40);
    CHECK(std::abs(m[0].cpu_avg - 30.0) < 1e-9); // (90*10 + 10*30)/40
    CHECK(std::abs(m[0].cpu_max - 95.0) < 1e-9); // max-of-max
    CHECK(m[0].instances_max == 5);
    CHECK(m[0].ws_avg_bytes == 250); // (100*10 + 300*30)/40
    CHECK(m[0].ws_max_bytes == 400);
}

TEST_CASE("canon_merge_app_perf clamps negatives, all-zero version -> unknown bucket",
          "[app_perf][agent]") {
    std::vector<AppPerfRow> rows = {
        {.name = "x", .version = "0.0.0.0", .day = 86400, .samples = -5, .instances_max = -1,
         .cpu_avg = -3.0, .cpu_max = -1.0, .ws_avg_bytes = -9, .ws_max_bytes = -2},
    };
    auto m = canon_merge_app_perf(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].version.empty()); // all-zero -> unknown bucket
    CHECK(m[0].samples == 0);
    CHECK(std::abs(m[0].cpu_avg) < 1e-12);
    CHECK(m[0].ws_avg_bytes == 0);
}

TEST_CASE("render_app_perf_blob emits 9 0x1F-separated fields per 0x1E record",
          "[app_perf][agent]") {
    std::vector<AppPerfRow> rows = {
        {.name = "a.exe", .version = "1.0.0.0", .day = 86400, .samples = 5, .instances_max = 1,
         .cpu_avg = 2.5, .cpu_max = 3.0, .ws_avg_bytes = 10, .ws_max_bytes = 20},
    };
    const std::string blob = render_app_perf_blob(std::move(rows));
    REQUIRE(!blob.empty());
    CHECK(blob.back() == '\x1e');                                       // record terminator
    CHECK(std::count(blob.begin(), blob.end(), '\x1f') == 8);           // 9 fields -> 8 seps
    CHECK(blob.find("a.exe") != std::string::npos);
    CHECK(blob.find("1.0.0.0") != std::string::npos);
}

// CROSS-PIN. B1 is hash-less, so a field-order drift between the agent's
// render_app_perf_blob and the server's parse_app_perf_blob would corrupt data
// with nothing to catch it. This literal blob is the wire contract; the SERVER
// side asserts the byte-identical blob parses back to these values
// (test_app_perf_ingestion.cpp, "app_perf wire cross-pin"). Keep the two literals
// identical. Field order: name|version|day|samples|instances_max|cpu_avg|cpu_max|
// ws_avg_bytes|ws_max_bytes.
TEST_CASE("app_perf wire cross-pin — render matches the pinned blob",
          "[app_perf][agent][crosspin]") {
    const std::string expected = std::string("chrome.exe") + '\x1f' + "119.0.0.0" + '\x1f' +
                                 "1700000000" + '\x1f' + "120" + '\x1f' + "3" + '\x1f' + "12.5" +
                                 '\x1f' + "95.5" + '\x1f' + "1048576" + '\x1f' + "2097152" + '\x1e';
    std::vector<AppPerfRow> rows = {{.name = "chrome.exe", .version = "119.0.0.0",
                                     .day = 1700000000, .samples = 120, .instances_max = 3,
                                     .cpu_avg = 12.5, .cpu_max = 95.5, .ws_avg_bytes = 1048576,
                                     .ws_max_bytes = 2097152}};
    CHECK(render_app_perf_blob(std::move(rows)) == expected);
}
