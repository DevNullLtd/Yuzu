// AppPerfDailyStore (DEX app-perf-over-time B1) — the born-on-Postgres per-device
// daily projection: pure canon-merge, apply/read round-trip, ON-CONFLICT overwrite,
// canon-collision safety, 31-day retention prune, and delete_agent.

#include <catch2/catch_test_macros.hpp>

#include "app_perf_daily_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::canon_merge_daily;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): shared key
// with test_app_perf_ingestion.cpp (identical setup — first build wins).
yuzu::test::PgTestTemplate apperf_daily_tpl{"apperf_daily", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("apperf_daily template: store failed to migrate");
}};
std::int64_t today_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}
} // namespace

TEST_CASE("canon_merge_daily merges canon-collisions sample-weighted", "[app_perf][merge]") {
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "app", .version = "1.2.3", .day = 86400, .samples = 10, .instances_max = 2,
         .cpu_avg = 90.0, .cpu_max = 95.0, .ws_avg_bytes = 100, .ws_max_bytes = 200},
        {.app_name = "app", .version = "1.2.3.0", .day = 86400, .samples = 30, .instances_max = 5,
         .cpu_avg = 10.0, .cpu_max = 20.0, .ws_avg_bytes = 300, .ws_max_bytes = 400},
    };
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].version == "1.2.3.0");
    CHECK(m[0].samples == 40);
    CHECK(std::abs(m[0].cpu_avg - 30.0) < 1e-9);
    CHECK(std::abs(m[0].cpu_max - 95.0) < 1e-9);
    CHECK(m[0].instances_max == 5);
    CHECK(m[0].ws_avg_bytes == 250);
    CHECK(m[0].ws_max_bytes == 400);
}

TEST_CASE("canon_merge_daily clamps cpu>100% and ws>1PiB (UP-1 per-row defense)",
          "[app_perf][merge]") {
    constexpr std::int64_t kPiB = std::int64_t{1} << 50; // the ws ceiling
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "x", .version = "1.0", .day = 86400, .samples = 1, .instances_max = 1,
         .cpu_avg = 1.0e9, .cpu_max = 1.0e9,
         .ws_avg_bytes = 9223372036854775807LL, .ws_max_bytes = 9223372036854775807LL}};
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].cpu_avg == 100.0); // share-of-capacity percent ceiling
    CHECK(m[0].cpu_max == 100.0);
    CHECK(m[0].ws_avg_bytes == kPiB); // 1 PiB — keeps the rollup SUM(ws) from overflowing
    CHECK(m[0].ws_max_bytes == kPiB);
}

TEST_CASE("canon_merge_daily upper-clamps samples (sec-M1)", "[app_perf][merge]") {
    // `samples` is the weight in the reductions' sample-weighted means; an uncapped
    // near-INT64_MAX value would overflow the int64 sample_sum accumulator (UB) and
    // make the downstream llround UB. canon upper-caps it at 1e9 (>> any legit daily
    // count: ≤2880 30 s ticks/day × instances).
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "x", .version = "1.0", .day = 86400, .samples = 9223372036854775807LL,
         .instances_max = 1, .cpu_avg = 50.0, .cpu_max = 50.0, .ws_avg_bytes = 100,
         .ws_max_bytes = 100}};
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].samples == 1'000'000'000LL); // capped — bounds the reductions' int64 weight sum
}

TEST_CASE("canon_merge_daily re-clamps the MERGED sample sum (sec-M1 LOW)", "[app_perf][merge]") {
    // The per-row cap bounds each raw row, but a batch of duplicate-key rows sums in
    // the merge; the merged value must be re-clamped so `samples` ≤ kMaxSamples holds
    // by construction (the read-side int64 weight sum then stays ≪ INT64_MAX
    // regardless of how many duplicates arrived in one apply).
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "x", .version = "1.0", .day = 86400, .samples = 1'000'000'000LL,
         .instances_max = 1, .cpu_avg = 50.0, .cpu_max = 50.0, .ws_avg_bytes = 100,
         .ws_max_bytes = 100},
        {.app_name = "x", .version = "1.0", .day = 86400, .samples = 1'000'000'000LL,
         .instances_max = 1, .cpu_avg = 50.0, .cpu_max = 50.0, .ws_avg_bytes = 100,
         .ws_max_bytes = 100},
    };
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].samples == 1'000'000'000LL); // 2e9 merged → re-clamped to 1e9
    CHECK(m[0].cpu_avg == 50.0);            // weighted mean used the true total first
}

TEST_CASE("AppPerfDailyStore apply + read", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_daily_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t day = today_utc() - 86400; // a completed day, within retention

    SECTION("stores rows read back app-ordered; unknown/empty agent = empty value not nullopt") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "chrome.exe", .version = "119.0.0.0", .day = day, .samples = 100,
             .instances_max = 8, .cpu_avg = 15.0, .cpu_max = 60.0, .ws_avg_bytes = 1000,
             .ws_max_bytes = 2000},
            {.app_name = "code.exe", .version = "1.85.0.0", .day = day, .samples = 50,
             .instances_max = 2, .cpu_avg = 5.0, .cpu_max = 20.0, .ws_avg_bytes = 500,
             .ws_max_bytes = 900},
        };
        CHECK(store.apply_daily("agent-a", rows));
        auto got = store.get_agent_app_perf("agent-a");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        CHECK((*got)[0].app_name == "chrome.exe"); // ORDER BY app_name
        CHECK((*got)[1].app_name == "code.exe");
        CHECK((*got)[0].samples == 100);
        CHECK(std::abs((*got)[0].cpu_avg - 15.0) < 1e-9);

        auto none = store.get_agent_app_perf("agent-unknown");
        REQUIRE(none.has_value()); // not a degrade — a genuine empty
        CHECK(none->empty());
        auto empty_id = store.get_agent_app_perf("");
        REQUIRE(empty_id.has_value());
        CHECK(empty_id->empty());
    }

    SECTION("re-apply same key overwrites (ON CONFLICT DO UPDATE)") {
        std::vector<AppPerfDailyRow> v1 = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 50.0, .cpu_max = 50.0, .ws_avg_bytes = 1, .ws_max_bytes = 1}};
        CHECK(store.apply_daily("agent-b", v1));
        std::vector<AppPerfDailyRow> v2 = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 99, .instances_max = 9,
             .cpu_avg = 9.0, .cpu_max = 9.0, .ws_avg_bytes = 9, .ws_max_bytes = 9}};
        CHECK(store.apply_daily("agent-b", v2));
        auto got = store.get_agent_app_perf("agent-b");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].samples == 99); // latest wins
    }

    SECTION("canon-colliding rows store one merged row (no ON CONFLICT double-affect)") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "x", .version = "2.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 80.0, .cpu_max = 80.0, .ws_avg_bytes = 10, .ws_max_bytes = 10},
            {.app_name = "x", .version = "2.0.0.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 20.0, .cpu_max = 20.0, .ws_avg_bytes = 30, .ws_max_bytes = 30},
        };
        CHECK(store.apply_daily("agent-c", rows));
        auto got = store.get_agent_app_perf("agent-c");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].version == "2.0.0.0");
        CHECK((*got)[0].samples == 20);
        CHECK(std::abs((*got)[0].cpu_avg - 50.0) < 1e-9); // (80*10 + 20*10)/20
    }

    SECTION("retention prunes rows older than 31 days on apply") {
        const std::int64_t old_day = today_utc() - 40 * 86400;
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "old", .version = "1.0.0.0", .day = old_day, .samples = 1,
             .instances_max = 1, .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1},
            {.app_name = "new", .version = "1.0.0.0", .day = day, .samples = 1, .instances_max = 1,
             .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1},
        };
        CHECK(store.apply_daily("agent-d", rows));
        auto got = store.get_agent_app_perf("agent-d");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].app_name == "new"); // the 40-day-old row was pruned
    }

    SECTION("drops far-future-dated rows (retention-bypass guard, UP-2)") {
        // `day` is agent-supplied; an unbounded far-future day would survive the
        // `WHERE day < cutoff` prune forever (retention bypass → unbounded storage)
        // and could amplify one version's sparkline. apply_daily drops rows beyond
        // today + 2 days of slack BEFORE the upsert.
        const std::int64_t future = today_utc() + 30 * 86400; // well past the 2-day slack
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "future", .version = "1.0.0.0", .day = future, .samples = 1,
             .instances_max = 1, .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1,
             .ws_max_bytes = 1},
            {.app_name = "now", .version = "1.0.0.0", .day = day, .samples = 1, .instances_max = 1,
             .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1},
        };
        CHECK(store.apply_daily("agent-f", rows));
        auto got = store.get_agent_app_perf("agent-f");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].app_name == "now"); // the far-future row never reached the table
    }

    SECTION("delete_agent removes all rows") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 1, .instances_max = 1,
             .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1}};
        CHECK(store.apply_daily("agent-e", rows));
        CHECK(store.delete_agent("agent-e")); // committed → true
        auto got = store.get_agent_app_perf("agent-e");
        REQUIRE(got.has_value());
        CHECK(got->empty());
    }
}

TEST_CASE("AppPerfDailyStore::list_devices_for_version", "[pg][app_perf][version_devices]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_daily_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t day = today_utc() - 86400;

    // Three devices all reporting the SAME (app,version) with distinct cpu_avg
    // so ordering is unambiguous; a fourth device reports a DIFFERENT version of
    // the same app (must never be returned) and a fifth reports the SAME
    // version of a DIFFERENT app (must never be returned either).
    auto row = [&](double cpu) {
        return std::vector<AppPerfDailyRow>{
            {.app_name = "chrome.exe", .version = "119.0.0.0", .day = day, .samples = 10,
             .instances_max = 1, .cpu_avg = cpu, .cpu_max = cpu, .ws_avg_bytes = 100,
             .ws_max_bytes = 100}};
    };
    CHECK(store.apply_daily("agent-lo", row(5.0)));
    CHECK(store.apply_daily("agent-mid", row(50.0)));
    CHECK(store.apply_daily("agent-hi", row(90.0)));
    CHECK(store.apply_daily(
        "agent-other-version",
        {{.app_name = "chrome.exe", .version = "118.0.0.0", .day = day, .samples = 10,
          .instances_max = 1, .cpu_avg = 99.0, .cpu_max = 99.0, .ws_avg_bytes = 1,
          .ws_max_bytes = 1}}));
    CHECK(store.apply_daily(
        "agent-other-app",
        {{.app_name = "code.exe", .version = "119.0.0.0", .day = day, .samples = 10,
          .instances_max = 1, .cpu_avg = 99.0, .cpu_max = 99.0, .ws_avg_bytes = 1,
          .ws_max_bytes = 1}}));

    SECTION("nullopt visible_agent_ids = unfiltered, ordered by descending cpu_avg") {
        bool truncated = false;
        auto got = store.list_devices_for_version("chrome.exe", "119.0.0.0", std::nullopt,
                                                   truncated);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 3); // never the other-version/other-app rows
        CHECK((*got)[0].agent_id == "agent-hi");
        CHECK((*got)[1].agent_id == "agent-mid");
        CHECK((*got)[2].agent_id == "agent-lo");
        CHECK((*got)[0].last_day == day);
        CHECK(std::abs((*got)[0].cpu_avg - 90.0) < 1e-9);
        CHECK((*got)[0].ws_avg_bytes == 100);
        CHECK_FALSE(truncated);
    }

    SECTION("engaged, non-empty visible_agent_ids restricts to exactly that set (ADR-0017)") {
        // Pushed into the WHERE clause, never a post-fetch filter: only
        // "agent-lo" is admitted even though it is the LOWEST-cpu (not the
        // rank-1 row) — proves the filter is not merely "take the top of an
        // unfiltered read".
        std::optional<std::vector<std::string>> visible{std::vector<std::string>{"agent-lo"}};
        bool truncated = false;
        auto got = store.list_devices_for_version("chrome.exe", "119.0.0.0", visible, truncated);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].agent_id == "agent-lo");
    }

    SECTION("present-but-EMPTY visible_agent_ids yields ZERO rows (deny-all, not unfiltered)") {
        // ADR-0033 §1 / ADR-0017: present-empty must NEVER read as "no filter".
        std::optional<std::vector<std::string>> deny_all{std::vector<std::string>{}};
        bool truncated = false;
        auto got = store.list_devices_for_version("chrome.exe", "119.0.0.0", deny_all, truncated);
        REQUIRE(got.has_value()); // NOT a degrade — a genuine, correctly-filtered empty
        CHECK(got->empty());
    }

    SECTION("a version with no matching rows returns empty, not a degrade (retention-mismatch case)") {
        bool truncated = false;
        auto got = store.list_devices_for_version("chrome.exe", "999.0.0.0", std::nullopt,
                                                   truncated);
        REQUIRE(got.has_value());
        CHECK(got->empty());
    }

    SECTION("empty app_name is a precondition miss, not a degrade; empty version is a valid key") {
        bool truncated = false;
        auto got = store.list_devices_for_version("", "119.0.0.0", std::nullopt, truncated);
        REQUIRE(got.has_value());
        CHECK(got->empty());

        // "" is the valid unknown-version bucket, matched exactly like any other
        // version string — not a precondition miss and not "all versions".
        CHECK(store.apply_daily(
            "agent-unknown-version",
            {{.app_name = "linuxapp", .version = "", .day = day, .samples = 5, .instances_max = 1,
              .cpu_avg = 42.0, .cpu_max = 42.0, .ws_avg_bytes = 1, .ws_max_bytes = 1}}));
        auto unknown = store.list_devices_for_version("linuxapp", "", std::nullopt, truncated);
        REQUIRE(unknown.has_value());
        REQUIRE(unknown->size() == 1);
        CHECK((*unknown)[0].agent_id == "agent-unknown-version");
    }

    SECTION("reports the device's MOST RECENT day for this version, not an older one") {
        const std::int64_t older_day = day - 86400;
        CHECK(store.apply_daily(
            "agent-two-days",
            {{.app_name = "twoday.exe", .version = "1.0.0.0", .day = older_day, .samples = 1,
              .instances_max = 1, .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1,
              .ws_max_bytes = 1},
             {.app_name = "twoday.exe", .version = "1.0.0.0", .day = day, .samples = 1,
              .instances_max = 1, .cpu_avg = 77.0, .cpu_max = 77.0, .ws_avg_bytes = 1,
              .ws_max_bytes = 1}}));
        bool truncated = false;
        auto got =
            store.list_devices_for_version("twoday.exe", "1.0.0.0", std::nullopt, truncated);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].last_day == day); // the newer of the two days, not older_day
        CHECK(std::abs((*got)[0].cpu_avg - 77.0) < 1e-9);
    }
}
