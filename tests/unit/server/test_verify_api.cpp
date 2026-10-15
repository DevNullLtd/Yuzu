/**
 * test_verify_api.cpp — the SECOND per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4 #4250, copying the merged
 * `network_api`/test_network_api.cpp template). `LocalVerifyApi`
 * (verify_api.cpp) is the store-reaching assembly previously split between
 * server.cpp's `app_perf_providers.cohort` lambda and each of the three
 * callers' own `build_comparison` call — moved verbatim behind the
 * `VerifyApi` seam so it is independently testable. Every behaviour the move
 * promises to preserve gets its own case: the two-bounded-reads composition
 * (members, then B1 rows), the AUTHORITATIVE-degrade nullopt on a missing
 * reader / a failed row read, the empty/unknown-group precondition-miss
 * (member_count 0, NOT a degrade), and truncation pass-through. Only reached
 * through the public `VerifyApi` interface (`compare`) — the class itself
 * (`LocalVerifyApi`) is deliberately private to verify_api.cpp, so this file
 * uses only `make_local_verify_api`, matching how a real presentation/MCP
 * caller will use it.
 */

#include "verify_api_local.hpp"

#include "app_perf_cohort_reader.hpp"
#include "app_perf_daily_store.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::AppPerfCohortReader;
using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::make_local_verify_api;
using yuzu::server::ManagementGroup;
using yuzu::server::ManagementGroupStore;
using yuzu::server::VerifyCompareQuery;
using yuzu::server::kMaxWindowDays;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own stores against a clone of this schema. Mirrors
// the sibling readers' own templates (mgmt_tpl / apperf_cohort_tpl) but
// combines both schemas in one database, since LocalVerifyApi composes both
// stores in a single `compare()` call.
yuzu::test::PgTestTemplate verify_api_tpl{"verifyapi", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore groups{pool};
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    if (!groups.is_open() || !b1.is_open())
        throw std::runtime_error("verifyapi template: a store failed to migrate");
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

std::string make_static_group(ManagementGroupStore& groups,
                              const std::vector<std::string>& agent_ids) {
    ManagementGroup g;
    g.name = "verify-api-test-group";
    g.membership_type = "static";
    auto id = groups.create_group(g);
    REQUIRE(id.has_value());
    for (const auto& a : agent_ids)
        REQUIRE(groups.add_member(*id, a).has_value());
    return *id;
}

} // namespace

TEST_CASE("VerifyApi: null cohort reader is the AUTHORITATIVE degrade", "[pg][verify_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    REQUIRE(groups.is_open());
    auto group_id = make_static_group(groups, {"a1"});

    auto api = make_local_verify_api(groups, /*cohort_reader=*/nullptr);

    VerifyCompareQuery q;
    q.group_id = group_id;
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";
    q.window_days = 7;
    const auto result = api->compare(q);
    CHECK_FALSE(result.has_value()); // nullopt, not an empty/insufficient comparison
}

// #1762: a degraded ManagementGroupStore member-resolution read must fail
// compare() closed to nullopt — never render as member_count == 0, which is
// indistinguishable from a genuinely empty/unknown group. No live database
// needed: an invalid pool makes ManagementGroupStore::is_open() false, so
// get_members_checked() degrades before compare() ever reaches the cohort
// reader.
TEST_CASE("VerifyApi: degraded member-resolution read fails closed, not member_count 0 (#1762)",
          "[verify_api]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore groups{pool};
    REQUIRE(!groups.is_open());
    AppPerfCohortReader reader{pool};

    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = "g1";
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";
    q.window_days = 7;
    const auto result = api->compare(q);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("VerifyApi: unknown/empty group is a precondition miss, NOT a degrade",
          "[pg][verify_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(groups.is_open());

    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = "no-such-group";
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";
    q.window_days = 7;
    const auto result = api->compare(q);
    REQUIRE(result.has_value()); // present, not degraded
    CHECK(result->member_count == 0);
    CHECK_FALSE(result->truncated);
    CHECK(result->comparison.paired == 0);
    CHECK(result->comparison.insufficient); // paired == 0 -> nothing to compare
}

TEST_CASE("VerifyApi: window_days is clamped to [1, kMaxWindowDays], no bypass",
          "[pg][verify_api]") {
    // The internal std::clamp in compare() protects a FUTURE caller (e.g. a
    // presentation-side client post-WS-B2) that forgets to clamp its own
    // parsed window param. The empty-group path still runs build_comparison,
    // which echoes the clamped window into comparison.window_days, so this
    // asserts the clamp WITHOUT needing seeded cohort rows.
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(groups.is_open());

    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = "no-such-group"; // precondition-miss path (present, not degrade)
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";

    SECTION("over-cap window clamps down to kMaxWindowDays") {
        q.window_days = 999;
        const auto result = api->compare(q);
        REQUIRE(result.has_value());
        CHECK(result->comparison.window_days == kMaxWindowDays);
    }
    SECTION("zero window clamps up to 1") {
        q.window_days = 0;
        const auto result = api->compare(q);
        REQUIRE(result.has_value());
        CHECK(result->comparison.window_days == 1);
    }
    SECTION("negative window clamps up to 1") {
        q.window_days = -5;
        const auto result = api->compare(q);
        REQUIRE(result.has_value());
        CHECK(result->comparison.window_days == 1);
    }
    SECTION("lower in-range boundary (1) passes through unchanged") {
        q.window_days = 1;
        const auto result = api->compare(q);
        REQUIRE(result.has_value());
        CHECK(result->comparison.window_days == 1);
    }
    SECTION("upper in-range boundary (kMaxWindowDays) passes through unchanged") {
        q.window_days = kMaxWindowDays;
        const auto result = api->compare(q);
        REQUIRE(result.has_value());
        CHECK(result->comparison.window_days == kMaxWindowDays);
    }
}

TEST_CASE("VerifyApi: compare pairs ONLY resolved group members, agent_id preserved",
          "[pg][verify_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(groups.is_open());
    REQUIRE(b1.is_open());

    const std::int64_t d1 = today_utc() - 2 * 86400; // baseline-version day
    const std::int64_t d2 = today_utc() - 86400;     // candidate-version day

    // a1, a2 are group members; a3 is NOT — the resolved cohort must exclude it
    // even though it has matching rows (the reader's own ANY($1) filter, but
    // this test also proves the API resolves membership itself, not a
    // caller-supplied agent list).
    seed(b1, "a1", "AcmeVPN.exe", "4.2.0.0", d1, 2.0, 100000000);
    seed(b1, "a1", "AcmeVPN.exe", "4.3.0.0", d2, 5.0, 150000000);
    seed(b1, "a2", "AcmeVPN.exe", "4.2.0.0", d1, 3.0, 100000000);
    seed(b1, "a2", "AcmeVPN.exe", "4.3.0.0", d2, 4.0, 110000000);
    seed(b1, "a3", "AcmeVPN.exe", "4.2.0.0", d1, 9.0, 900000000); // non-member
    seed(b1, "a3", "AcmeVPN.exe", "4.3.0.0", d2, 9.0, 900000000); // non-member

    auto group_id = make_static_group(groups, {"a1", "a2"});
    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = group_id;
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";
    q.window_days = 7;
    const auto result = api->compare(q);
    REQUIRE(result.has_value());
    CHECK(result->member_count == 2);
    CHECK_FALSE(result->truncated);
    CHECK(result->comparison.paired == 2); // a1 + a2, a3 excluded
    CHECK_FALSE(result->comparison.insufficient);
    // The audited drill's own data — the deliberate PII carried in the full
    // comparison (see verify_api.hpp's PII policy split doc).
    REQUIRE(result->comparison.pairs.size() == 2);
    bool has_a1 = false, has_a2 = false;
    for (const auto& p : result->comparison.pairs) {
        if (p.agent_id == "a1")
            has_a1 = true;
        if (p.agent_id == "a2")
            has_a2 = true;
    }
    CHECK(has_a1);
    CHECK(has_a2);
}

TEST_CASE("VerifyApi: version-key canonicalization matches the stored key",
          "[pg][verify_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(groups.is_open());
    REQUIRE(b1.is_open());

    const std::int64_t d1 = today_utc() - 2 * 86400;
    const std::int64_t d2 = today_utc() - 86400;

    // Rows are stored under the CANON quad form; the query below supplies a
    // shorter, equivalent spelling — canon_version must reconcile both sides
    // (get_cohort_rows internally, build_comparison again here) or the pair
    // is silently dropped.
    seed(b1, "a1", "AcmeVPN.exe", "4.2.0.0", d1, 2.0, 100000000);
    seed(b1, "a1", "AcmeVPN.exe", "4.3.0.0", d2, 5.0, 150000000);

    auto group_id = make_static_group(groups, {"a1"});
    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = group_id;
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2"; // short form -> canon_version("4.2") == "4.2.0.0"
    q.candidate_version = "4.3";
    q.window_days = 7;
    const auto result = api->compare(q);
    REQUIRE(result.has_value());
    CHECK(result->comparison.paired == 1);
    CHECK(result->comparison.baseline_version == "4.2.0.0");
    CHECK(result->comparison.candidate_version == "4.3.0.0");
}

TEST_CASE("VerifyApi: a truncated read is surfaced, not hidden", "[pg][verify_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, verify_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore groups{pool};
    AppPerfDailyStore b1{pool};
    AppPerfCohortReader reader{pool};
    REQUIRE(groups.is_open());
    REQUIRE(b1.is_open());

    const std::int64_t d1 = today_utc() - 2 * 86400;
    const std::int64_t d2 = today_utc() - 86400;
    seed(b1, "a1", "AcmeVPN.exe", "4.2.0.0", d1, 2.0, 100000000);
    seed(b1, "a1", "AcmeVPN.exe", "4.3.0.0", d2, 5.0, 150000000);

    auto group_id = make_static_group(groups, {"a1"});
    auto api = make_local_verify_api(groups, &reader);

    VerifyCompareQuery q;
    q.group_id = group_id;
    q.app = "AcmeVPN.exe";
    q.baseline_version = "4.2.0.0";
    q.candidate_version = "4.3.0.0";
    q.window_days = 7;
    const auto result = api->compare(q);
    REQUIRE(result.has_value());
    // Not exercising the real row cap here (that is the reader's own test,
    // test_app_perf_cohort_reader.cpp); this asserts the field passes
    // through untouched on the ordinary (non-truncated) path, so a future
    // change that drops the plumbing between `get_cohort_rows`'s out-param
    // and `VerifyCompareResult::truncated` fails loudly rather than by
    // omission.
    CHECK_FALSE(result->truncated);
}
