/**
 * test_app_usage_parsers.cpp — pure app_usage sqlite seam
 * (app_usage_parsers.hpp).
 *
 * Every SQL/format function under test takes an already-open `sqlite3*` —
 * no OS dependency, so these run identically on every host. The primary
 * fixture is loaded from the committed exports under
 * tests/unit/fixtures/wave7/app_usage/ (YUZU_TEST_FIXTURE_DIR,
 * REQUIRE(exists) — never skipped on a missing fixture; see that
 * directory's .provenance.txt sidecars). RECONSTRUCTION rows cover edge
 * cases the fixture doesn't happen to exercise (disabled source, missing
 * table, by=unmodelled, exe normalisation, top/days clamps, P5 delimiter
 * safety).
 */

#include "app_usage_parsers.hpp"
#include "app_usage_test_seed.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

using namespace yuzu::app_usage;
namespace fs = std::filesystem;
namespace seed = yuzu::test::app_usage;

namespace {

fs::path fixture_dir() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "app_usage";
}

/// The REAL CAPTURE fixture: loads the four committed pipe-delimited
/// exports (see that directory's .provenance.txt sidecars) into a fresh
/// :memory: db built with app_usage_test_seed.hpp's schema.
class RealFixture {
public:
    RealFixture() {
        REQUIRE(sqlite3_open(":memory:", &db_) == SQLITE_OK);
        seed::create_schema(db_);
        const auto dir = fixture_dir();
        REQUIRE(fs::exists(dir));
        seed::seed_from_fixture_dir(db_, dir.string());
    }
    ~RealFixture() {
        if (db_)
            sqlite3_close(db_);
    }
    RealFixture(const RealFixture&) = delete;
    RealFixture& operator=(const RealFixture&) = delete;

    sqlite3* db() const { return db_; }

private:
    sqlite3* db_{nullptr};
};

} // namespace

// ─────────────────────────────────────────────────── parse_window_params ──

TEST_CASE("parse_window_params: defaults with empty inputs", "[app_usage][params]") {
    const auto w = parse_window_params("", "", "");
    CHECK(w.days == 30);
    CHECK(w.top == 25);
    CHECK(w.by == WindowParams::By::run_time);
}

TEST_CASE("parse_window_params: days clamped to [1, 365]", "[app_usage][params]") {
    CHECK(parse_window_params("0", "10", "").days == 1);
    CHECK(parse_window_params("-5", "10", "").days == 1);
    CHECK(parse_window_params("400", "10", "").days == 365);
    CHECK(parse_window_params("90", "10", "").days == 90);
    CHECK(parse_window_params("not_a_number", "10", "").days == 30); // unparsable -> default
}

TEST_CASE("parse_window_params: top clamped to [1, 500]", "[app_usage][params]") {
    CHECK(parse_window_params("10", "0", "").top == 1);
    CHECK(parse_window_params("10", "9999", "").top == 500);
    CHECK(parse_window_params("10", "100", "").top == 100);
}

TEST_CASE("parse_window_params: by run_count/run_time recognised; anything else -> unmodelled",
          "[app_usage][params]") {
    CHECK(parse_window_params("10", "10", "run_time").by == WindowParams::By::run_time);
    CHECK(parse_window_params("10", "10", "run_count").by == WindowParams::By::run_count);
    CHECK(parse_window_params("10", "10", "bogus").by == WindowParams::By::unmodelled);
    CHECK(parse_window_params("10", "10", "RUN_TIME").by == WindowParams::By::unmodelled);
}

// ────────────────────────────────────────────────── normalise_exe_key() ───

TEST_CASE("normalise_exe_key: 10-input parity with tar_usage.hpp's rule "
          "(lowercase, basename, trim, empty -> (unknown))",
          "[app_usage][exe_key]") {
    CHECK(normalise_exe_key("Chrome.EXE") == "chrome.exe");
    CHECK(normalise_exe_key("C:\\Program Files\\Google\\Chrome.exe") == "chrome.exe");
    CHECK(normalise_exe_key("/usr/bin/bash") == "bash");
    CHECK(normalise_exe_key("  notepad.exe  ") == "notepad.exe");
    CHECK(normalise_exe_key("") == "(unknown)");
    CHECK(normalise_exe_key("   ") == "(unknown)");
    CHECK(normalise_exe_key("firefox") == "firefox");
    CHECK(normalise_exe_key("/opt/app/Weird.Name.BIN") == "weird.name.bin");
    CHECK(normalise_exe_key("C:/mixed/slashes\\App.exe") == "app.exe");
    CHECK(normalise_exe_key("systemd-journald") == "systemd-journald"); // 15-char comm, untouched
}

// ───────────────────────────────────────────── source_state_from_config() ─

TEST_CASE("source_state_from_config: RECONSTRUCTION — the #560 tri-state, seven inputs",
          "[app_usage][source_state]") {
    CHECK(source_state_from_config(std::nullopt) == SourceState::Enabled); // key absent
    CHECK(source_state_from_config(std::string_view{"true"}) == SourceState::Enabled);
    CHECK(source_state_from_config(std::string_view{"false"}) == SourceState::Disabled);
    CHECK(source_state_from_config(std::string_view{"1"}) == SourceState::Errored);
    CHECK(source_state_from_config(std::string_view{""}) == SourceState::Errored);
    CHECK(source_state_from_config(std::string_view{"maybe"}) == SourceState::Errored);
    CHECK(source_state_from_config(std::string_view{"TRUE"}) == SourceState::Errored); // case-sensitive
}

TEST_CASE("source_state_from_config: RECONSTRUCTION — seeded :memory: db with "
         "usage_enabled=maybe reports Errored via the same tar_config read read_meta uses",
          "[app_usage][source_state][sql]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::insert_tar_config(db, "usage_enabled", "maybe");

    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "SELECT value FROM tar_config WHERE key = ?", -1, &stmt,
                               nullptr) == SQLITE_OK);
    sqlite3_bind_text(stmt, 1, "usage_enabled", -1, SQLITE_STATIC);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    const auto* raw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    const std::string stored{raw ? raw : ""};
    sqlite3_finalize(stmt);

    CHECK(stored == "maybe");
    CHECK(source_state_from_config(std::string_view{stored}) == SourceState::Errored);
    sqlite3_close(db);
}

// ─────────────────────────────────────────────────────────── SQL pinning ──

TEST_CASE("summary SQL text is pinned", "[app_usage][sql]") {
    CHECK(kSummarySqlByRunTime ==
         "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
         "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
         "GROUP BY exe_key ORDER BY SUM(total_seconds) DESC LIMIT ?");
    CHECK(kSummarySqlByRunCount ==
         "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
         "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
         "GROUP BY exe_key ORDER BY SUM(run_count) DESC LIMIT ?");
}

// ──────────────────────────────────────────── read_meta (REAL CAPTURE) ────

// Expectations below are the actual values this REAL CAPTURE fixture holds
// at capture time — see tar_config_macos.txt.provenance.txt for the
// derivation. Five of the eleven candidate keys are ABSENT on this real,
// fresh-host capture (unmatched_stops/clock_anomalies/gap_count/
// gap_lost_events/gap_last_ts are only ever written when non-zero,
// tar_usage.cpp:648-671) — asserting their honest absent-key defaults here
// is itself the point: a prior RECONSTRUCTION fixture invented non-zero
// values for all of these, which no real host actually produces.
TEST_CASE("read_meta: REAL CAPTURE fixture — tar_config counters match the captured "
         "snapshot, including the honest absent-key defaults",
          "[app_usage][meta][fixture]") {
    RealFixture fx;
    const auto meta = read_meta(fx.db(), /*since_day_ts=*/0);
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "1788954914");
    CHECK(meta->days_present == 6); // six distinct day_ts rows in the fixture
    CHECK(meta->open_runs == 741);  // usage_live_macos.txt's captured count
    CHECK(meta->unmatched_stops == 0);  // key absent on this real host
    CHECK(meta->clock_anomalies == 0);  // key absent
    CHECK(meta->gap_count == 0);        // key absent
    CHECK(meta->gap_lost_events == 0);  // key absent
    CHECK(meta->gap_last_ts == "-");    // key absent
    CHECK(meta->lag_events == 0);
    CHECK(meta->feeder_enabled);
    CHECK(meta->last_fold_ts == "1789411607");
}

TEST_CASE("read_meta: RECONSTRUCTION — every tar_config counter reads back non-default "
         "when actually seeded (contrast with the REAL CAPTURE case's honest absent-key "
         "defaults)",
          "[app_usage][meta]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::insert_tar_config(db, "usage_coverage_since", "1000");
    seed::insert_tar_config(db, "usage_unmatched_stops", "2");
    seed::insert_tar_config(db, "usage_clock_anomalies", "1");
    seed::insert_tar_config(db, "usage_gap_count", "1");
    seed::insert_tar_config(db, "usage_gap_lost_events", "9");
    seed::insert_tar_config(db, "usage_gap_last_ts", "5000");
    seed::insert_tar_config(db, "usage_lag_events", "3");
    seed::insert_tar_config(db, "usage_feeder_enabled", "false");
    seed::insert_tar_config(db, "usage_last_fold_ts", "6000");

    const auto meta = read_meta(db);
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "1000");
    CHECK(meta->unmatched_stops == 2);
    CHECK(meta->clock_anomalies == 1);
    CHECK(meta->gap_count == 1);
    CHECK(meta->gap_lost_events == 9);
    CHECK(meta->gap_last_ts == "5000");
    CHECK(meta->lag_events == 3);
    CHECK_FALSE(meta->feeder_enabled);
    CHECK(meta->last_fold_ts == "6000");
    sqlite3_close(db);
}

TEST_CASE("read_meta: RECONSTRUCTION — missing tar_config keys fall back to honest defaults",
          "[app_usage][meta]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);

    const auto meta = read_meta(db);
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "-");
    CHECK(meta->open_runs == 0);
    CHECK(meta->unmatched_stops == 0);
    // Round-3 review SHOULD-FIX: an absent usage_feeder_enabled key must
    // read as disabled here, matching last_used's own gate -- unlike
    // usage_enabled, this key does NOT default missing-to-enabled.
    CHECK_FALSE(meta->feeder_enabled);
    sqlite3_close(db);
}

// Round-3 review SHOULD-FIX: summary's meta row and last_used's gate
// previously disagreed about a missing usage_feeder_enabled key -- meta
// read it as enabled (get_config's old "true" default combined with
// `!= "false"`) while last_used's check_source_state(missing_means_enabled
// =false) already reported Disabled. Isolates just the feeder key (with
// other config present and populated) so this can't pass by accident
// alongside the "every key missing" case above.
TEST_CASE("read_meta: usage_feeder_enabled key specifically omitted reads as disabled, "
         "not the general missing-key default",
          "[app_usage][meta][regression]") {
    // RAII-owned per the round-3 review policy-floor blocker (this file's
    // own idiom, see the distinct-users regression test above) -- take
    // ownership before the REQUIRE.
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db{nullptr, &sqlite3_close};
    {
        sqlite3* raw = nullptr;
        const int rc = sqlite3_open(":memory:", &raw);
        db.reset(raw);
        REQUIRE(rc == SQLITE_OK);
    }
    seed::create_schema(db.get());
    seed::insert_tar_config(db.get(), "usage_enabled", "true");
    seed::insert_tar_config(db.get(), "usage_coverage_since", "1000");
    // Deliberately no usage_feeder_enabled row at all.

    const auto meta = read_meta(db.get());
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "1000"); // other keys still read normally
    CHECK_FALSE(meta->feeder_enabled); // NOT true -- the bug this test guards against
}

// ───────────────────────────────────── run_summary (REAL CAPTURE) + user leak ─

TEST_CASE("run_summary: REAL CAPTURE fixture — 266 distinct executables, ordered by "
         "total_seconds, and NO real user name leaks into any formatted line",
          "[app_usage][summary][fixture]") {
    RealFixture fx;
    WindowParams w;
    w.days = 365; // wide enough to cover the whole fixture (since_day_ts=0 below anyway)
    w.top = 500;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, /*since_day_ts=*/0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 266); // distinct exe_key count, see usage_daily_macos.txt.provenance.txt

    // Highest SUM(total_seconds) over the whole fixture: mtlcompilerservi
    // (see usage_daily_macos.txt.provenance.txt's derivation queries).
    CHECK(result->rows.front().exe_key == "mtlcompilerservi");
    CHECK(result->rows.front().total_seconds == 6052482);

    std::string meta_line = format_meta_line(w, *read_meta(fx.db(), 0));
    std::string rows_text;
    for (const auto& r : result->rows)
        rows_text += format_usage_row(r) + "\n";

    // The fixture's usage_daily_user rows carry real local account names
    // (alex, root, _locationd, _spotlight, ...; see
    // usage_daily_user_macos.txt.provenance.txt) — none of that may ever
    // reach a formatted summary/meta line. "alex" is this host's own real
    // account, the strongest instance of the leak this test guards against.
    for (const char* forbidden : {"alex", "_locationd", "_spotlight"}) {
        INFO("forbidden token: " << forbidden);
        CHECK(meta_line.find(forbidden) == std::string::npos);
        CHECK(rows_text.find(forbidden) == std::string::npos);
    }
}

TEST_CASE("run_summary: REAL CAPTURE fixture — distinct_users aggregates "
         "COUNT(DISTINCT user), a count only",
          "[app_usage][summary][fixture]") {
    RealFixture fx;
    WindowParams w;
    w.days = 365;
    w.top = 500;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, 0);
    REQUIRE(result.has_value());
    const auto it = std::find_if(result->rows.begin(), result->rows.end(),
                                 [](const auto& r) { return r.exe_key == "contactsd"; });
    REQUIRE(it != result->rows.end());
    CHECK(it->distinct_users == 20); // count only, see usage_daily_macos.txt.provenance.txt
}

TEST_CASE("run_summary: RECONSTRUCTION — ordered by run_count when by=run_count",
          "[app_usage][summary]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::insert_usage_daily(db, 100000, "chrome.exe", 10, 100, 100000, 100100, 0, 0);
    seed::insert_usage_daily(db, 100000, "notepad.exe", 2, 5000, 100000, 100100, 0, 0);

    WindowParams w;
    w.days = 30;
    w.top = 25;
    w.by = WindowParams::By::run_count;

    const auto result = run_summary(db, w, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 2);
    CHECK(result->rows[0].exe_key == "chrome.exe"); // run_count 10 > 2, despite lower total_seconds
    sqlite3_close(db);
}

TEST_CASE("run_summary: REAL CAPTURE fixture — since_day_ts window excludes the older day",
          "[app_usage][summary][fixture]") {
    RealFixture fx;
    // Anchors to the last 3 fixture days (kFixtureLastDay and the two days
    // before it) — excludes the earliest captured day entirely. See
    // usage_daily_macos.txt.provenance.txt for the derivation queries.
    const int64_t since_day_ts = seed::kFixtureLastDay - 2 * 86400;

    WindowParams w;
    w.days = 3;
    w.top = 500;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, since_day_ts);
    REQUIRE(result.has_value());

    // aboutextension appears ONLY on the earliest captured day and nowhere
    // in the 3-day window — excluded entirely, not merely reduced.
    const auto excluded = std::find_if(result->rows.begin(), result->rows.end(),
                                       [](const auto& r) { return r.exe_key == "aboutextension"; });
    CHECK(excluded == result->rows.end());

    // biomesyncd appears on every day (including the excluded earliest one)
    // — its windowed aggregate must reflect only the 3 in-window rows.
    const auto it = std::find_if(result->rows.begin(), result->rows.end(),
                                 [](const auto& r) { return r.exe_key == "biomesyncd"; });
    REQUIRE(it != result->rows.end());
    CHECK(it->first_seen == 1789172295);
    CHECK(it->last_seen == 1789411063);
    CHECK(it->run_count == 178);
    CHECK(it->total_seconds == 37556);
}

TEST_CASE("run_summary: REAL CAPTURE fixture — top limit is respected", "[app_usage][summary]") {
    RealFixture fx;
    // Same 3-day window as the test above: top-1 by total_seconds within it
    // is contactsd (870563s) — a different executable than the whole-table
    // top-1 (mtlcompilerservi), which is itself proof the window is applied
    // before the ranking, not after.
    const int64_t since_day_ts = seed::kFixtureLastDay - 2 * 86400;
    WindowParams w;
    w.days = 3;
    w.top = 1;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, since_day_ts);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 1);
    CHECK(result->rows[0].exe_key == "contactsd");
    CHECK(result->rows[0].total_seconds == 870563);
}

// Round-3 review MEDIUM (CDX-R2-03/K5): run_summary's distinct-user merge
// previously used an unordered, independently-LIMIT-capped query with no
// relationship to which exe_keys the (top-ranked, <=w.top) result.rows had
// already selected -- a genuinely top-ranked executable could silently read
// distinct_users=0 once usage_daily_user held more than kMaxLastUsedRows
// distinct exe_keys, because the old query's arbitrary first-N rows could
// easily miss it. Reproduced here by inserting far more than
// kMaxLastUsedRows "noise_*" exe_keys into usage_daily_user: the old query's
// GROUP BY with no ORDER BY sorts through SQLite's temp b-tree, which lands
// every "noise_*" key lexicographically before "target.exe" regardless of
// insertion order (confirmed by round-3 review inserting the target both
// first and last with identical results) -- so its unordered LIMIT scan
// exhausts on noise and never reaches the target. The target is the ONLY
// exe_key with a usage_daily row, so it is unambiguously result.rows[0].
TEST_CASE("run_summary: a genuinely top-ranked executable's distinct_users survives "
         "when usage_daily_user holds more than kMaxLastUsedRows OTHER exe_keys "
         "that sort lexicographically first",
          "[app_usage][summary][regression]") {
    // Round-3 review Blocker (policy floor): RAII-owned -- take ownership
    // before the REQUIRE so a failed open still unwinds through a live
    // owner rather than leaking the handle (same idiom as the corruption
    // fixture in test_app_usage_local_dispatcher.cpp).
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db{nullptr, &sqlite3_close};
    {
        sqlite3* raw = nullptr;
        const int rc = sqlite3_open(":memory:", &raw);
        db.reset(raw);
        REQUIRE(rc == SQLITE_OK);
    }
    seed::create_schema(db.get());
    seed::exec_or_fail(db.get(), "BEGIN");
    const auto noise_count = static_cast<int64_t>(kMaxLastUsedRows) + 500;
    for (int64_t i = 0; i < noise_count; ++i) {
        seed::insert_usage_daily_user(db.get(), 100000, "noise_" + std::to_string(i), "someuser");
    }
    seed::insert_usage_daily(db.get(), 100000, "target.exe", 5, 12000, 100000, 100500, 0, 0);
    seed::insert_usage_daily_user(db.get(), 100000, "target.exe", "alice");
    seed::insert_usage_daily_user(db.get(), 100000, "target.exe", "bob");
    seed::exec_or_fail(db.get(), "COMMIT");

    WindowParams w;
    w.days = 30;
    w.top = 25;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(db.get(), w, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 1);
    CHECK(result->rows[0].exe_key == "target.exe");
    CHECK(result->rows[0].distinct_users == 2); // NOT 0 -- the bug this test guards against
}

// ─────────────────────────────────────────────────────────── run_last_used ─

TEST_CASE("run_last_used: REAL CAPTURE fixture — no exe filter returns every exe_key",
          "[app_usage][last_used][fixture]") {
    RealFixture fx;
    const auto rows = run_last_used(fx.db(), std::nullopt, /*since_30d_ts=*/0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 266); // distinct exe_key count, see usage_daily_macos.txt.provenance.txt
}

TEST_CASE("run_last_used: REAL CAPTURE fixture — exe filter normalises the same way "
         "stored exe_key was written (mixed case, no path)",
          "[app_usage][last_used][fixture]") {
    RealFixture fx;
    const auto rows = run_last_used(fx.db(), std::string_view{"ZSH"}, 0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().exe_key == "zsh");
    CHECK(rows->front().first_seen == 1788954975);
    CHECK(rows->front().last_seen == 1789411426);
}

TEST_CASE("run_last_used: RECONSTRUCTION — unknown exe filter returns zero rows, not an error",
          "[app_usage][last_used]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::insert_usage_daily(db, 100000, "chrome.exe", 1, 1, 100000, 100000, 0, 0);
    const auto rows = run_last_used(db, std::string_view{"never_seen.exe"}, 0);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
    sqlite3_close(db);
}

// Round-3 review MEDIUM: kLastUsedSqlAll's LIMIT clause must actually bound
// what SQLite materializes and returns, not merely rely on the shell
// resizing the vector afterward -- app_usage_plugin.cpp's do_last_used_on
// truncates to kMaxLastUsedRows regardless of how many rows run_last_used
// hands it, so a dispatcher-level test asserting the FINAL output size
// cannot distinguish "the SQL LIMIT worked" from "the SQL returned every
// one of 5000+ rows and the shell truncated after the fact" -- this test
// asserts the query layer itself, decoupled from that shell behaviour: it
// must return AT MOST kMaxLastUsedRows+1 rows (the +1 the shell relies on to
// detect truncation without a second COUNT(*)) even when far more exist.
TEST_CASE("run_last_used: unfiltered form never returns more than "
         "kMaxLastUsedRows+1 rows, even when the table holds far more",
          "[app_usage][last_used]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::exec_or_fail(db, "BEGIN");
    const auto over_cap = static_cast<int64_t>(kMaxLastUsedRows) + 50;
    for (int64_t i = 0; i < over_cap; ++i) {
        seed::insert_usage_daily(db, 100000, "exe_" + std::to_string(i), 1, 1, 100000, 100000, 0,
                                 0);
    }
    seed::exec_or_fail(db, "COMMIT");

    const auto rows = run_last_used(db, std::nullopt, 0);
    REQUIRE(rows.has_value());
    CHECK(rows->size() == static_cast<std::size_t>(kMaxLastUsedRows) + 1);
    sqlite3_close(db);
}

// Governance Gate 4 unhappy-path UP-4: the exact-boundary case (precisely
// kMaxLastUsedRows rows, not over it) was untested -- both existing tests
// used +50/+5 over-cap. At exactly the cap, LIMIT kMaxLastUsedRows+1 can
// only return kMaxLastUsedRows rows (there is nothing to fill the +1 with),
// so the shell's `size() > kMaxLastUsedRows` truncation check must correctly
// see this as NOT truncated.
TEST_CASE("run_last_used: unfiltered form returns exactly kMaxLastUsedRows "
         "when the table holds precisely that many rows -- the untruncated "
         "boundary",
          "[app_usage][last_used]") {
    // cpp-safety governance re-sweep: same raw-handle-across-throwing-
    // assertions shape as the round-3 blocker, in a block that actually
    // predates round 2 (commit 7c6b5f3a1). Fixed while already touching
    // this file's RAII idiom this round -- not asserting this reclassifies
    // every other pre-existing raw sqlite3_open in this file (the 6+
    // blocks round 2 deliberately left alone stay left alone; this one
    // just happened to also get independently found and is cheap to fix
    // alongside the others). Take ownership before the REQUIRE.
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db{nullptr, &sqlite3_close};
    {
        sqlite3* raw = nullptr;
        const int rc = sqlite3_open(":memory:", &raw);
        db.reset(raw);
        REQUIRE(rc == SQLITE_OK);
    }
    seed::create_schema(db.get());
    seed::exec_or_fail(db.get(), "BEGIN");
    for (int64_t i = 0; i < static_cast<int64_t>(kMaxLastUsedRows); ++i) {
        seed::insert_usage_daily(db.get(), 100000, "exe_" + std::to_string(i), 1, 1, 100000,
                                 100000, 0, 0);
    }
    seed::exec_or_fail(db.get(), "COMMIT");

    const auto rows = run_last_used(db.get(), std::nullopt, 0);
    REQUIRE(rows.has_value());
    CHECK(rows->size() == static_cast<std::size_t>(kMaxLastUsedRows));
}

// ───────────────────────────────────────────────────────── schema check ───

TEST_CASE("usage_daily_table_exists: true with the table, false without", "[app_usage][schema]") {
    RealFixture fx;
    const auto with_table = usage_daily_table_exists(fx.db());
    REQUIRE(with_table.has_value());
    CHECK(*with_table);

    sqlite3* empty_db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &empty_db) == SQLITE_OK);
    const auto without_table = usage_daily_table_exists(empty_db);
    REQUIRE(without_table.has_value()); // legitimately absent, not a read failure
    CHECK_FALSE(*without_table);
    sqlite3_close(empty_db);
}

// Governance Gate 7 round 2 (unhappy-path UP-1): a GENUINE read failure
// (here, a corrupt/not-a-database file) must be distinguished from the
// legitimate "no such table" case above -- the old bool-returning version
// conflated both into `false`, which app_usage_plugin.cpp's caller read as
// "older TAR schema". Same bug class as check_usage_source_state's
// tar_config tri-state (b88c3b690), now closed for the schema check too.
TEST_CASE("usage_daily_table_exists: a genuine read failure (corrupt db) is distinguished "
         "from a legitimately-absent table, never silently mapped to false",
          "[app_usage][schema]") {
    yuzu::test::TempDbFile fixture_db{"yuzu_test_app_usage_corrupt-"};
    {
        std::ofstream f(fixture_db.path, std::ios::binary | std::ios::trunc);
        f << "not a valid sqlite database file -- forces a genuine prepare/step failure "
             "rather than a legitimate absent-table result";
    }
    sqlite3* db = nullptr;
    // sqlite3_open() succeeds lazily -- the file header is only parsed on
    // first real access, which is exactly what usage_daily_table_exists does.
    REQUIRE(sqlite3_open(fixture_db.path.string().c_str(), &db) == SQLITE_OK);
    const auto result = usage_daily_table_exists(db);
    CHECK_FALSE(result.has_value()); // a genuine failure, never a silent `false`
    sqlite3_close(db);
}

// ──────────────────────────────────────────── RO+WAL open, on-disk temp db ─

TEST_CASE("plugin's exact open flags (RO|NOMUTEX) succeed against a WAL-mode on-disk db",
          "[app_usage][sqlite][wal]") {
    yuzu::test::TempDbFile fixture_db{"yuzu_test_app_usage-"};

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open(fixture_db.path.string().c_str(), &writer) == SQLITE_OK);
    seed::exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    seed::create_schema(writer);
    seed::insert_usage_daily(writer, 100, "x.exe", 1, 1, 100, 100, 0, 0);

    sqlite3* reader = nullptr;
    const int rc = sqlite3_open_v2(fixture_db.path.string().c_str(), &reader,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    REQUIRE(rc == SQLITE_OK);
    REQUIRE(reader != nullptr);
    sqlite3_busy_timeout(reader, 2000);
    REQUIRE(sqlite3_exec(reader, "PRAGMA query_only=1", nullptr, nullptr, nullptr) == SQLITE_OK);

    const auto reader_table_exists = usage_daily_table_exists(reader);
    REQUIRE(reader_table_exists.has_value());
    CHECK(*reader_table_exists);
    const auto rows = run_last_used(reader, std::nullopt, 0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().exe_key == "x.exe");

    sqlite3_close(reader);
    sqlite3_close(writer);
}

// ─────────────────────────────────────────────────────────── formatting ───

TEST_CASE("format_meta_line / format_usage_row / format_last_used_row shapes",
          "[app_usage][format]") {
    WindowParams w;
    w.days = 7;
    MetaInfo m;
    m.coverage_since = "1000";
    m.days_present = 3;
    m.open_runs = 2;
    m.feeder_enabled = false;
    const auto meta_line = format_meta_line(w, m);
    CHECK(meta_line.rfind("meta|window_days|7|", 0) == 0);
    CHECK(meta_line.find("|feeder_enabled|0|") != std::string::npos);

    UsageRow row;
    row.exe_key = "app.exe";
    row.run_count = 3;
    const auto usage_line = format_usage_row(row);
    CHECK(usage_line.rfind("usage|app.exe|3|", 0) == 0);

    LastUsedRow lu;
    lu.exe_key = "app.exe";
    lu.last_seen = 42;
    const auto lu_line = format_last_used_row(lu);
    CHECK(lu_line == "last_used|app.exe|42|0|0|0");
}

// ─────────────────────────────────────── P5 delimiter safety, round-trip ──

namespace {

/// A `\|`-aware splitter recovering the ORIGINAL (pre-escape) exe_key from
/// a formatted row — mirrors the rule the p3.2 daily-sync source's parser
/// uses on the same wire grammar (this package's spec, DELIMITER SAFETY).
std::string unescape_pipe_field(std::string_view field) {
    std::string out;
    out.reserve(field.size());
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 1 < field.size() && field[i + 1] == '|') {
            out += '|';
            ++i;
        } else {
            out += field[i];
        }
    }
    return out;
}

} // namespace

TEST_CASE("P5: format_usage_row escapes a pipe-bearing exe_key; a \\|-aware splitter "
         "recovers it",
          "[app_usage][format][p5]") {
    UsageRow row;
    row.exe_key = "a|b.exe";
    const auto line = format_usage_row(row);
    // The raw '|' must have become "\|", not a bare field separator.
    REQUIRE(line.find("a\\|b.exe") != std::string::npos);
    CHECK(line.find("a|b.exe|") == std::string::npos); // no UNESCAPED pipe mid-field

    // Extract the escaped exe_key field (between the leading "usage|" tag
    // and the next unescaped '|') and unescape it back to the original.
    const std::string escaped = line.substr(std::string("usage|").size(), std::string("a\\|b.exe").size());
    CHECK(unescape_pipe_field(escaped) == "a|b.exe");
}

TEST_CASE("P5: format_usage_row folds CR/LF in exe_key to a space (no row-separator "
         "injection)",
          "[app_usage][format][p5]") {
    UsageRow row;
    row.exe_key = "c\nd.exe";
    const auto line = format_usage_row(row);
    CHECK(line.find('\n') == std::string::npos);
    CHECK(line.find("c d.exe") != std::string::npos);
}

TEST_CASE("P5: format_usage_row folds a literal backslash in exe_key to '/' (lossy by "
         "design, per safe_output_field's doc comment)",
          "[app_usage][format][p5]") {
    UsageRow row;
    row.exe_key = "e\\f.exe";
    const auto line = format_usage_row(row);
    CHECK(line.find("e/f.exe") != std::string::npos);
    CHECK(line.find('\\') == std::string::npos); // the literal backslash never survives raw
}

TEST_CASE("P5: format_last_used_row applies the identical exe_key escaping as "
         "format_usage_row",
          "[app_usage][format][p5]") {
    LastUsedRow r;
    r.exe_key = "a|b.exe";
    const auto line = format_last_used_row(r);
    CHECK(line.rfind("last_used|a\\|b.exe|", 0) == 0);
}

TEST_CASE("P5: RECONSTRUCTION round-trip through the sqlite seam — a pipe-bearing "
         "exe_key stored, queried, and formatted comes back escaped and recoverable",
          "[app_usage][format][p5][sql]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    seed::create_schema(db);
    seed::insert_usage_daily(db, 100000, "a|b.exe", 1, 10, 100000, 100000, 0, 0);
    seed::insert_usage_daily(db, 100000, "c\nd.exe", 1, 10, 100000, 100000, 0, 0);
    seed::insert_usage_daily(db, 100000, "e\\f.exe", 1, 10, 100000, 100000, 0, 0);

    WindowParams w;
    const auto result = run_summary(db, w, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 3);

    bool saw_pipe = false, saw_newline = false, saw_backslash = false;
    for (const auto& row : result->rows) {
        const auto line = format_usage_row(row);
        CHECK(line.find('\n') == std::string::npos);
        if (row.exe_key == "a|b.exe") {
            CHECK(line.find("a\\|b.exe") != std::string::npos);
            saw_pipe = true;
        } else if (row.exe_key == "c\nd.exe") {
            CHECK(line.find("c d.exe") != std::string::npos);
            saw_newline = true;
        } else if (row.exe_key == "e\\f.exe") {
            CHECK(line.find("e/f.exe") != std::string::npos);
            saw_backslash = true;
        }
    }
    CHECK(saw_pipe);
    CHECK(saw_newline);
    CHECK(saw_backslash);
    sqlite3_close(db);
}

// ───────────────────────────────────────────────────────────── negative ───

namespace {

std::string read_whole_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.is_open());
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("negative: no app_usage plugin source mentions TAR's raw process-event table "
         "or a cmdline column",
          "[app_usage][negative][security]") {
    // YUZU_TEST_FIXTURE_DIR is "<source_root>/tests/unit/fixtures" (tests/meson.build) —
    // three levels up from there is the repo source root, from which the
    // plugin sources are addressed by their normal repo-relative path.
    const fs::path repo_root = fs::path{YUZU_TEST_FIXTURE_DIR} / ".." / ".." / "..";
    for (const char* rel :
        {"agents/plugins/app_usage/src/app_usage_parsers.hpp",
         "agents/plugins/app_usage/src/app_usage_plugin.cpp"}) {
        const fs::path p = repo_root / rel;
        REQUIRE(fs::exists(p));
        const auto text = read_whole_file(p);
        INFO("file: " << rel);
        CHECK(text.find("process_live") == std::string::npos);
        CHECK(text.find("cmdline") == std::string::npos);
    }
}

TEST_CASE("negative: REAL CAPTURE fixture summary/last_used output carries no pid or "
         "user-name field",
          "[app_usage][negative][fixture]") {
    RealFixture fx;
    WindowParams w;
    const auto summary = run_summary(fx.db(), w, 0);
    REQUIRE(summary.has_value());
    std::string summary_text = format_meta_line(w, *read_meta(fx.db(), 0)) + "\n";
    for (const auto& r : summary->rows)
        summary_text += format_usage_row(r) + "\n";

    const auto last_used = run_last_used(fx.db(), std::nullopt, 0);
    REQUIRE(last_used.has_value());
    std::string last_used_text;
    for (const auto& r : *last_used)
        last_used_text += format_last_used_row(r) + "\n";

    // "alex" is this host's own real account name in the committed
    // usage_daily_user_macos.txt fixture (see its .provenance.txt) — the
    // strongest instance of the leak this test guards against.
    for (const char* forbidden : {"alex", "_locationd", "_spotlight"}) {
        CHECK(summary_text.find(forbidden) == std::string::npos);
        CHECK(last_used_text.find(forbidden) == std::string::npos);
    }
}
