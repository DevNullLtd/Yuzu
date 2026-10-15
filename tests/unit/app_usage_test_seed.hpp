#pragma once

/**
 * app_usage_test_seed.hpp — DDL + seed helpers shared by
 * test_app_usage_parsers.cpp and test_app_usage_local_dispatcher.cpp.
 *
 * Test-only: creates the four tables app_usage_parsers.hpp reads
 * (usage_daily, usage_daily_user, usage_live, tar_config) with the exact
 * columns that header's SQL selects, and inserts rows through bound
 * parameters (never string-built SQL) so a fixture row containing a quote,
 * pipe, backslash, or newline seeds cleanly regardless of the plugin's own
 * P5 escaping on the READ side.
 *
 * Two seeding paths:
 *   - seed_from_fixture_dir(): loads the committed pipe-delimited fixture
 *     exports under tests/unit/fixtures/wave7/app_usage/ (REAL CAPTURE —
 *     see that directory's .provenance.txt sidecars). usage_live_macos.txt
 *     is a single-line COUNT (the plugin's only read of usage_live is
 *     `SELECT COUNT(*) FROM usage_live`, kOpenRunsSql) — this loader parses
 *     that one integer and inserts N placeholder rows, since no app_usage
 *     query reads a usage_live row's own columns.
 *   - the individual insert_*() functions: for RECONSTRUCTION rows (edge
 *     cases the real capture doesn't happen to cover — disabled source,
 *     missing table, delimiter-bearing exe_keys, etc).
 */

#include <sqlite3.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

namespace yuzu::test::app_usage {

// MAX(day_ts) in the committed usage_daily_macos.txt REAL CAPTURE (see that
// file's .provenance.txt sidecar) — every fixture-derived window in
// test_app_usage_parsers.cpp anchors to this constant, never to
// std::chrono::system_clock, so expectations never rot with wall-clock time.
inline constexpr int64_t kFixtureLastDay = 1789344000;

// Row counts recorded in the fixture's own .provenance.txt sidecars — used
// to REQUIRE a silently edited/truncated fixture fails loudly rather than
// quietly changing what the tests exercise.
inline constexpr std::size_t kFixtureUsageDailyRowCount = 438;
inline constexpr std::size_t kFixtureUsageDailyUserRowCount = 583;

inline void exec_or_fail(sqlite3* db, const char* sql) {
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        const std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        FAIL("sqlite3_exec failed: " << msg << " -- sql: " << sql);
    }
}

/// Creates the four tables app_usage_parsers.hpp's SQL reads from, with the
/// exact columns its queries select (usage_daily has no distinct_users
/// column here — the real tar.db table does, but no app_usage query ever
/// selects it; distinct_users is derived entirely from usage_daily_user).
inline void create_schema(sqlite3* db) {
    exec_or_fail(db, "CREATE TABLE usage_daily (day_ts INTEGER, exe_key TEXT, "
                     "run_count INTEGER, total_seconds INTEGER, first_seen INTEGER, "
                     "last_seen INTEGER, superseded_runs INTEGER, expired_runs INTEGER)");
    exec_or_fail(db, "CREATE TABLE usage_daily_user (day_ts INTEGER, exe_key TEXT, user TEXT)");
    exec_or_fail(db, "CREATE TABLE usage_live (pid INTEGER, exe_key TEXT, user TEXT, "
                     "start_ts INTEGER)");
    exec_or_fail(db, "CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT)");
}

namespace detail {

inline void bind_text(sqlite3_stmt* stmt, int idx, std::string_view v) {
    sqlite3_bind_text(stmt, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

} // namespace detail

inline void insert_usage_daily(sqlite3* db, int64_t day_ts, std::string_view exe_key,
                               int64_t run_count, int64_t total_seconds, int64_t first_seen,
                               int64_t last_seen, int64_t superseded_runs, int64_t expired_runs) {
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db,
                               "INSERT INTO usage_daily VALUES (?,?,?,?,?,?,?,?)", -1, &stmt,
                               nullptr) == SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, day_ts);
    detail::bind_text(stmt, 2, exe_key);
    sqlite3_bind_int64(stmt, 3, run_count);
    sqlite3_bind_int64(stmt, 4, total_seconds);
    sqlite3_bind_int64(stmt, 5, first_seen);
    sqlite3_bind_int64(stmt, 6, last_seen);
    sqlite3_bind_int64(stmt, 7, superseded_runs);
    sqlite3_bind_int64(stmt, 8, expired_runs);
    REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
}

inline void insert_usage_daily_user(sqlite3* db, int64_t day_ts, std::string_view exe_key,
                                    std::string_view user) {
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "INSERT INTO usage_daily_user VALUES (?,?,?)", -1, &stmt,
                               nullptr) == SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, day_ts);
    detail::bind_text(stmt, 2, exe_key);
    detail::bind_text(stmt, 3, user);
    REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
}

inline void insert_usage_live(sqlite3* db, int64_t pid, std::string_view exe_key,
                              std::string_view user, int64_t start_ts) {
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "INSERT INTO usage_live VALUES (?,?,?,?)", -1, &stmt,
                               nullptr) == SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, pid);
    detail::bind_text(stmt, 2, exe_key);
    detail::bind_text(stmt, 3, user);
    sqlite3_bind_int64(stmt, 4, start_ts);
    REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
}

inline void insert_tar_config(sqlite3* db, std::string_view key, std::string_view value) {
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "INSERT INTO tar_config VALUES (?,?)", -1, &stmt, nullptr) ==
           SQLITE_OK);
    detail::bind_text(stmt, 1, key);
    detail::bind_text(stmt, 2, value);
    REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
}

/// Splits one pipe-delimited fixture line (sqlite3 CLI's `.mode list
/// .separator |` export format) into fields. No quoting/escaping in this
/// grammar — the fixture exporter never emits a raw `|` inside a field
/// (verified when the fixture was produced); this is a plain split, not
/// app_usage_parsers.hpp's own P5 wire-format reader.
inline std::vector<std::string> split_fixture_line(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : line) {
        if (c == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

inline std::vector<std::vector<std::string>> read_fixture_rows(const std::string& path) {
    std::ifstream f(path);
    REQUIRE(f.is_open());
    std::vector<std::vector<std::string>> rows;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        rows.push_back(split_fixture_line(line));
    }
    return rows;
}

/// Loads the four committed fixture exports from `fixture_dir` (already
/// resolved to .../fixtures/wave7/app_usage) into `db`, whose schema must
/// already exist (create_schema()). Field order matches each table's
/// insert_*() helper above, which itself matches create_schema()'s column
/// order.
inline void seed_from_fixture_dir(sqlite3* db, const std::string& fixture_dir) {
    {
        const auto rows = read_fixture_rows(fixture_dir + "/usage_daily_macos.txt");
        // A silently edited/truncated fixture fails loudly here, before any
        // test's hardcoded expectations (derived from the SAME snapshot —
        // see the fixture's .provenance.txt) get a chance to pass by
        // accident against different data.
        REQUIRE(rows.size() == kFixtureUsageDailyRowCount);
        for (const auto& row : rows) {
            REQUIRE(row.size() == 8);
            insert_usage_daily(db, std::stoll(row[0]), row[1], std::stoll(row[2]),
                               std::stoll(row[3]), std::stoll(row[4]), std::stoll(row[5]),
                               std::stoll(row[6]), std::stoll(row[7]));
        }
    }
    {
        const auto rows = read_fixture_rows(fixture_dir + "/usage_daily_user_macos.txt");
        REQUIRE(rows.size() == kFixtureUsageDailyUserRowCount);
        for (const auto& row : rows) {
            REQUIRE(row.size() == 3);
            insert_usage_daily_user(db, std::stoll(row[0]), row[1], row[2]);
        }
    }
    // usage_live_macos.txt is a single-integer COUNT (see this file's header
    // and the fixture's .provenance.txt) — the row bodies below are
    // placeholders; only the count is real captured data.
    {
        const auto rows = read_fixture_rows(fixture_dir + "/usage_live_macos.txt");
        REQUIRE(rows.size() == 1);
        REQUIRE(rows[0].size() == 1);
        const int64_t open_run_count = std::stoll(rows[0][0]);
        REQUIRE(open_run_count >= 1);
        for (int64_t i = 1; i <= open_run_count; ++i)
            insert_usage_live(db, i, "(placeholder)", "", 0);
    }
    for (const auto& row : read_fixture_rows(fixture_dir + "/tar_config_macos.txt")) {
        REQUIRE(row.size() == 2);
        insert_tar_config(db, row[0], row[1]);
    }
}

} // namespace yuzu::test::app_usage
