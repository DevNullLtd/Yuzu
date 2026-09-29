// AppPerfCohortReader (/auto VERIFY): the raw B1 read that preserves agent_id so
// the compare engine can pair each machine. The headline is that the real
// `agent_id = ANY($1::text[]) AND app_name = $2 AND version = ANY($3::text[])`
// filter executes against live Postgres and returns ONLY the supplied members ×
// app × the two compared versions — the path pure tests can't reach (they inject
// pre-cooked CohortRead via the harness lambda and ship the SQL dark, the
// recurring B-tier slice lesson). Also exercises the read end-to-end through
// build_comparison, so the engine runs on rows the real query produced.

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include "app_perf_cohort_reader.hpp"
#include "app_perf_compare.hpp" // build_comparison, AppPerfCohortRow
#include "app_perf_daily_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/version_string.hpp> // canon_version

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Approx;
using yuzu::server::AppPerfCohortReader;
using yuzu::server::AppPerfCohortRow;
using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::build_comparison;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): mirrors the
// tests' store set (the reader carries no migration of its own).
yuzu::test::PgTestTemplate apperf_cohort_tpl{"apperf_cohort", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    if (!b1.is_open())
        throw std::runtime_error("apperf_cohort template: store failed to migrate");
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
bool has(const std::vector<AppPerfCohortRow>& v, const std::string& agent, const std::string& ver) {
    return std::any_of(v.begin(), v.end(), [&](const AppPerfCohortRow& r) {
        return r.agent_id == agent && r.version == ver;
    });
}
} // namespace

TEST_CASE("AppPerfCohortReader returns ONLY members × app × the two versions", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_cohort_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(b1.is_open());
    const std::int64_t d1 = today_utc() - 2 * 86400; // baseline-version day
    const std::int64_t d2 = today_utc() - 86400;     // candidate-version day

    // a1, a2 are cohort members; a3 is NOT (must be excluded by ANY($1)).
    seed(b1, "a1", "AcmeVPN.exe", "4.2.0.0", d1, 2.0, 100000000);
    seed(b1, "a1", "AcmeVPN.exe", "4.3.0.0", d2, 5.0, 150000000);
    seed(b1, "a2", "AcmeVPN.exe", "4.2.0.0", d1, 3.0, 100000000);
    seed(b1, "a2", "AcmeVPN.exe", "4.3.0.0", d2, 4.0, 110000000);
    seed(b1, "a3", "AcmeVPN.exe", "4.2.0.0", d1, 9.0, 900000000); // non-member
    seed(b1, "a3", "AcmeVPN.exe", "4.3.0.0", d2, 9.0, 900000000); // non-member
    // a1 also ran a THIRD version + a DIFFERENT app — both excluded by the filters.
    seed(b1, "a1", "AcmeVPN.exe", "4.1.0.0", d1, 1.0, 90000000); // version not compared
    seed(b1, "a1", "Other.exe", "4.2.0.0", d1, 1.0, 90000000);   // different app

    SECTION("member + app + two-version filter, agent_id preserved") {
        bool tr = false;
        auto rows = reader.get_cohort_rows({"a1", "a2"}, "AcmeVPN.exe", "4.2.0.0", "4.3.0.0", /*window=*/7, tr);
        REQUIRE(rows.has_value());
        CHECK_FALSE(tr); // 4 rows is far below the cap
        // a1×{4.2,4.3} + a2×{4.2,4.3} = 4 rows; a3 excluded (member filter); 4.1.0.0
        // and Other.exe excluded (version/app filters).
        CHECK(rows->size() == 4);
        CHECK(has(*rows, "a1", "4.2.0.0"));
        CHECK(has(*rows, "a1", "4.3.0.0"));
        CHECK(has(*rows, "a2", "4.2.0.0"));
        CHECK(has(*rows, "a2", "4.3.0.0"));
        CHECK_FALSE(has(*rows, "a3", "4.2.0.0")); // ANY($1) excludes the non-member
        CHECK_FALSE(has(*rows, "a1", "4.1.0.0")); // ANY($3) excludes the third version
    }

    SECTION("the read drives build_comparison end-to-end (real SQL → engine)") {
        bool tr = false;
        auto rows = reader.get_cohort_rows({"a1", "a2"}, "AcmeVPN.exe", "4.2.0.0", "4.3.0.0", /*window=*/7, tr);
        REQUIRE(rows.has_value());
        auto c = build_comparison(*rows, yuzu::util::canon_version("4.2.0.0"),
                                  yuzu::util::canon_version("4.3.0.0"), 7);
        CHECK(c.paired == 2); // a1, a2 ran both
        CHECK(c.baseline_only == 0);
        CHECK(c.candidate_only == 0);
        CHECK(c.cpu_before_mean == Approx(2.5)); // (2+3)/2
        CHECK(c.cpu_after_mean == Approx(4.5));  // (5+4)/2
        CHECK(c.moved_up == 2);
    }

    SECTION("empty member list is a precondition miss, not a degrade") {
        bool tr = false;
        auto rows = reader.get_cohort_rows({}, "AcmeVPN.exe", "4.2.0.0", "4.3.0.0", /*window=*/7, tr);
        REQUIRE(rows.has_value()); // empty value, NOT nullopt
        CHECK(rows->empty());
    }

    SECTION("empty app is a precondition miss, not a degrade") {
        bool tr = false;
        auto rows = reader.get_cohort_rows({"a1"}, "", "4.2.0.0", "4.3.0.0", /*window=*/7, tr);
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("AppPerfCohortReader windows in SQL — most-recent N days per (agent,version)",
          "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_cohort_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(b1.is_open());

    // 5 consecutive days of one version on one machine (all within 31d retention).
    const std::int64_t start = today_utc() - 6 * 86400;
    for (int i = 0; i < 5; ++i)
        seed(b1, "wm", "WinApp.exe", "4.2.0.0", start + i * 86400, 2.0, 1000);

    bool tr = false;
    // window=2 → only the 2 most-recent days come back (the SQL ROW_NUMBER filter,
    // not an in-memory trim). Candidate "9.9.9.9" is absent — proves the version
    // filter too. (gov M1: a smaller window genuinely shrinks the read.)
    auto rows = reader.get_cohort_rows({"wm"}, "WinApp.exe", "4.2.0.0", "9.9.9.9", /*window=*/2, tr);
    REQUIRE(rows.has_value());
    CHECK(rows->size() == 2);
    for (const auto& r : *rows)
        CHECK(r.day >= start + 3 * 86400); // the two newest days only

    // Counter-case: a window covering all days returns all 5 (catches a hard-coded
    // cap in the SQL window; gov NICE).
    bool tr2 = false;
    auto all = reader.get_cohort_rows({"wm"}, "WinApp.exe", "4.2.0.0", "9.9.9.9", /*window=*/7, tr2);
    REQUIRE(all.has_value());
    CHECK(all->size() == 5);
}

TEST_CASE("AppPerfCohortReader: the SQL window is PER-(agent,version) — staggered upgrade still pairs",
          "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, apperf_cohort_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(b1.is_open());

    // m1 ran baseline 4.2.0.0 on an EARLY block of days, then candidate 4.3.0.0 on a
    // LATER block — a real staggered transition. The window must apply PER version
    // (PARTITION BY agent_id, version), not globally, or the most-recent N days would
    // be all-candidate and the machine would read as candidate_only.
    const std::int64_t start = today_utc() - 14 * 86400;
    for (int i = 0; i < 4; ++i)
        seed(b1, "m1", "Acme.exe", "4.2.0.0", start + i * 86400, 2.0, 1000); // days 0..3
    for (int i = 0; i < 4; ++i)
        seed(b1, "m1", "Acme.exe", "4.3.0.0", start + (10 + i) * 86400, 5.0, 1500); // days 10..13

    bool tr = false;
    auto rows = reader.get_cohort_rows({"m1"}, "Acme.exe", "4.2.0.0", "4.3.0.0", /*window=*/2, tr);
    REQUIRE(rows.has_value());
    // 2 most-recent baseline days (2,3) + 2 most-recent candidate days (12,13) = 4.
    CHECK(rows->size() == 4);
    auto c = build_comparison(*rows, yuzu::util::canon_version("4.2.0.0"),
                              yuzu::util::canon_version("4.3.0.0"), 2);
    CHECK(c.paired == 1);        // BOTH versions present per the per-version window
    CHECK(c.baseline_only == 0); // a global PARTITION BY agent_id would break this
    CHECK(c.candidate_only == 0);
}
