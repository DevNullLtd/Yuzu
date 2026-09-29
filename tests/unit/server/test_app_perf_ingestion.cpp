// app_perf ingest seam (DEX app-perf-over-time B1): wire-blob parse (field caps,
// numeric bounds, drop rules) and ingest_app_perf_report end-to-end through the
// store (full → stored, hash-only → need_full, source-absent → no-op).

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "app_perf_daily_store.hpp"
#include "app_perf_ingestion.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>

using yuzu::server::AppPerfDailyStore;
using yuzu::server::ingest_app_perf_report;
using yuzu::server::parse_app_perf_blob;
using yuzu::server::pg::PgPool;
namespace agentpb = yuzu::agent::v1;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): shared key
// with test_app_perf_daily_store.cpp (identical setup — first build wins).
yuzu::test::PgTestTemplate apperf_daily_tpl{"apperf_daily", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("apperf_daily template: store failed to migrate");
}};
std::int64_t yesterday_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400 - 86400;
}
// One 9-field 0x1F-record terminated by 0x1E.
std::string rec(const std::string& name, const std::string& ver, std::int64_t day) {
    return name + '\x1f' + ver + '\x1f' + std::to_string(day) + '\x1f' + "10" + '\x1f' + "2" +
           '\x1f' + "12.5" + '\x1f' + "30" + '\x1f' + "100" + '\x1f' + "200" + '\x1e';
}
} // namespace

TEST_CASE("parse_app_perf_blob parses, caps names, drops bad rows", "[app_perf][parse]") {
    const std::int64_t day = yesterday_utc();

    SECTION("good row round-trips") {
        auto rows = parse_app_perf_blob(rec("chrome.exe", "119.0.0.0", day));
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].app_name == "chrome.exe");
        CHECK(rows[0].version == "119.0.0.0");
        CHECK(rows[0].day == day);
        CHECK(rows[0].samples == 10);
        CHECK(rows[0].instances_max == 2);
        CHECK(rows[0].ws_max_bytes == 200);
    }
    SECTION("empty-name dropped; over-long name capped at 256 bytes") {
        const std::string longname(300, 'a');
        auto rows = parse_app_perf_blob(rec("", "1.0", day) + rec(longname, "1.0", day));
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].app_name.size() == 256);
    }
    SECTION("non-positive day dropped") {
        CHECK(parse_app_perf_blob(rec("a", "1.0", 0)).empty());
    }
    SECTION("malformed numeric -> 0, row still parsed") {
        const std::string blob =
            std::string("a") + '\x1f' + "1.0" + '\x1f' + std::to_string(day) + '\x1f' + "junk" +
            '\x1f' + "x" + '\x1f' + "y" + '\x1f' + "z" + '\x1f' + "q" + '\x1f' + "w" + '\x1e';
        auto rows = parse_app_perf_blob(blob);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].samples == 0);
        CHECK(std::abs(rows[0].cpu_avg) < 1e-12);
    }
}

TEST_CASE("ingest_app_perf_report end-to-end", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_daily_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t day = yesterday_utc();

    SECTION("full blob stores, no need_full") {
        agentpb::InventoryReport report;
        (*report.mutable_content_hashes())["app_perf"] = "h";
        (*report.mutable_plugin_data())["app_perf"] = rec("app.exe", "1.0.0.0", day);
        agentpb::InventoryAck ack;
        ingest_app_perf_report(store, "agent-x", report, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
        auto got = store.get_agent_app_perf("agent-x");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].app_name == "app.exe");
    }

    SECTION("hash-only report (no blob) -> need_full (hash-less store)") {
        agentpb::InventoryReport report;
        (*report.mutable_content_hashes())["app_perf"] = "h";
        agentpb::InventoryAck ack;
        ingest_app_perf_report(store, "agent-y", report, ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "app_perf");
    }

    SECTION("source absent -> no-op, no need_full") {
        agentpb::InventoryReport report;
        (*report.mutable_content_hashes())["installed_software"] = "h";
        agentpb::InventoryAck ack;
        ingest_app_perf_report(store, "agent-z", report, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
    }
}

// CROSS-PIN (server half). Byte-identical to the agent render cross-pin
// (test_sync_source_app_perf.cpp, "app_perf wire cross-pin — render matches the
// pinned blob"). If parse_app_perf_blob's field order drifts from the agent's
// render, this breaks. Field order: name|version|day|samples|instances_max|
// cpu_avg|cpu_max|ws_avg_bytes|ws_max_bytes.
TEST_CASE("app_perf wire cross-pin — parse recovers the pinned blob", "[app_perf][parse]") {
    const std::string blob = std::string("chrome.exe") + '\x1f' + "119.0.0.0" + '\x1f' +
                             "1700000000" + '\x1f' + "120" + '\x1f' + "3" + '\x1f' + "12.5" +
                             '\x1f' + "95.5" + '\x1f' + "1048576" + '\x1f' + "2097152" + '\x1e';
    auto rows = parse_app_perf_blob(blob);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].app_name == "chrome.exe");
    CHECK(rows[0].version == "119.0.0.0");
    CHECK(rows[0].day == 1700000000);
    CHECK(rows[0].samples == 120);
    CHECK(rows[0].instances_max == 3);
    CHECK(std::abs(rows[0].cpu_avg - 12.5) < 1e-9);
    CHECK(std::abs(rows[0].cpu_max - 95.5) < 1e-9);
    CHECK(rows[0].ws_avg_bytes == 1048576);
    CHECK(rows[0].ws_max_bytes == 2097152);
}
