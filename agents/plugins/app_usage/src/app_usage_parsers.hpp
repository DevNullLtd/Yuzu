#pragma once

/**
 * app_usage_parsers.hpp — pure sqlite seam for the app_usage plugin
 * (summary / last_used over TAR's usage_daily / usage_daily_user /
 * usage_live tables inside tar.db).
 *
 * ALL SQL and formatting live here, taking an already-open `sqlite3*` — the
 * shell (app_usage_plugin.cpp) owns opening/closing the connection and
 * reading params/config; this header owns query construction, row mapping,
 * and pipe-delimited formatting, so the fixture-db tests
 * (test_app_usage_parsers.cpp) exercise the real query text against a
 * `:memory:` sqlite db with no OS dependency at all (firewall_parsers.hpp /
 * power_health_parsers.hpp precedent).
 *
 * Reads allowed, and ONLY these: usage_daily, usage_daily_user
 * (COUNT(DISTINCT user) only — user names never leave SQLite),
 * `SELECT COUNT(*) FROM usage_live` (open-run count only — no pid/exe
 * column is ever selected from usage_live), and the named tar_config keys
 * below. Never TAR's raw process-event table or any command-line column —
 * a grep of the plugin sources for those two forbidden identifiers is a
 * test in its own right (test_app_usage_parsers.cpp).
 *
 * Time cutoffs (`since_day_ts`) are computed by the shell and injected in —
 * this header never reads the system clock, matching tar_usage.hpp's own
 * `now`-injection shape (apply_event/expire_open_runs) so every query is
 * driven off values the fixture tests fully control.
 *
 * RETENTION (adjudication P3, binding): `first_seen`/`last_seen` are
 * MIN/MAX over the `usage_daily` rows that are actually present in the
 * table — i.e. within TAR's retained usage window (31 days default; TAR
 * prunes usage_daily on its own retention cadence). Never described as
 * spanning every run this executable has ever had: once TAR's retention
 * prunes a day's rows, this plugin has no way to see past them, so
 * claiming an unbounded history would overstate what the fold can still
 * answer.
 *
 * DELIMITER SAFETY (adjudication P5): every formatted row that carries an
 * `exe_key` passes it through `yuzu::util::safe_output_field` before
 * emission — an exe_key is attacker/OS-controlled text (an executable's own
 * basename) and must never be able to inject a `|` field separator or a
 * newline row separator into this plugin's pipe-delimited grammar. The
 * inbound `exe` request parameter (run_last_used) is normalised through the
 * same `normalise_exe_key` the stored rows were written under, and bound as
 * a parameter — never string-built into SQL.
 */

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <format>
#include <map>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <vector>

#include <constraint_accumulator.hpp>
#include <yuzu/string_utils.hpp>

namespace yuzu::app_usage {

// ─────────────────────────────────────────────────────── window params ────

struct WindowParams {
    int days{30};
    int top{25};
    enum class By { run_time, run_count, unmodelled } by{By::run_time};
};

constexpr int kMinDays = 1, kMaxDays = 365, kDefaultDays = 30;
constexpr int kMinTop = 1, kMaxTop = 500, kDefaultTop = 25;

namespace detail {
[[nodiscard]] inline int clamp_int(std::string_view s, int def, int lo, int hi) {
    int v = def;
    if (!s.empty()) {
        auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (ec != std::errc{} || ptr != s.data() + s.size())
            v = def;
    }
    return std::clamp(v, lo, hi);
}
} // namespace detail

/// `by_str` empty defaults to `run_time`; any non-empty value that is
/// neither "run_time" nor "run_count" parses to `By::unmodelled` — the
/// shell reports `error|bad_param|by` for that case and never runs a query.
[[nodiscard]] inline WindowParams parse_window_params(std::string_view days_str,
                                                       std::string_view top_str,
                                                       std::string_view by_str) {
    WindowParams w;
    w.days = detail::clamp_int(days_str, kDefaultDays, kMinDays, kMaxDays);
    w.top = detail::clamp_int(top_str, kDefaultTop, kMinTop, kMaxTop);
    if (by_str.empty() || by_str == "run_time")
        w.by = WindowParams::By::run_time;
    else if (by_str == "run_count")
        w.by = WindowParams::By::run_count;
    else
        w.by = WindowParams::By::unmodelled;
    return w;
}

// ──────────────────────────────────────────────────────── source state ────

/// TAR's #560 tri-state for a source's `<name>_enabled` tar_config key
/// (tar_aggregator.cpp:375-381, `canonical_source_enabled`): a stored value
/// of anything other than "true"/"false" means the source is ERRORED —
/// TAR itself has stopped collecting for it, not merely disabled — so a
/// consumer that only checks `!= "false"` would keep reporting stale rows
/// as if the source were still live. `Errored` must never be treated as
/// `Enabled`.
enum class SourceState { Enabled, Disabled, Errored };

/// `stored` is the raw `tar_config` value for `usage_enabled`
/// (`std::nullopt` when the key is absent). A missing key falls to
/// `source_default_enabled("usage")` = true (tar_schema_registry.cpp:1111),
/// so `nullopt` maps to `Enabled`, matching TAR's own default. `"true"` ->
/// `Enabled`, `"false"` -> `Disabled`; any other stored text (corruption, a
/// future tri-state value this plugin doesn't know about, hand-editing) ->
/// `Errored`, mirroring `canonical_source_enabled`'s #560 rule above.
[[nodiscard]] inline SourceState
source_state_from_config(std::optional<std::string_view> stored) {
    if (!stored)
        return SourceState::Enabled;
    if (*stored == "true")
        return SourceState::Enabled;
    if (*stored == "false")
        return SourceState::Disabled;
    return SourceState::Errored;
}

// ─────────────────────────────────────────────── exe_key normalisation ────

/// Mirrors tar_usage.hpp's `normalise_exe_key()` byte-for-byte — tar_usage
/// .hpp (agents/plugins/tar/src/tar_usage.hpp, P21/wave 2) is the SOURCE OF
/// TRUTH for this rule. Duplicated rather than shared: this plugin cannot
/// depend on the tar plugin's internal header (P21/P22 have no dependency
/// ordering between them), so the rule is copied here and pinned by
/// test_app_usage_parsers.cpp's 10-input parity test — any future drift in
/// tar_usage.hpp's rule must be mirrored here by hand, and that parity test
/// is what catches a missed mirror.
///
/// Rule: lowercase, basename after the last '/' or '\\', trimmed of
/// surrounding whitespace, empty → "(unknown)". Windows keeps the `.exe`
/// suffix (never stripped); Linux `comm` is already 15-char truncated by
/// the kernel before it ever reaches this function — this function does
/// not itself truncate.
[[nodiscard]] inline std::string normalise_exe_key(std::string_view raw) {
    std::string s{raw};
    if (const auto pos = s.find_last_of("/\\"); pos != std::string::npos)
        s = s.substr(pos + 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s.empty())
        return "(unknown)";
    return s;
}

// ───────────────────────────────────────────────────────────── errors ─────

struct QueryError {
    std::string detail;
};

// ─────────────────────────────────────────────────────────────── rows ─────

struct UsageRow {
    std::string exe_key;
    int64_t run_count{0};
    int64_t total_seconds{0};
    int64_t first_seen{0};
    int64_t last_seen{0};
    int64_t distinct_users{0};
    int64_t superseded_runs{0};
    int64_t expired_runs{0};
};

struct SummaryResult {
    std::vector<UsageRow> rows;
};

struct LastUsedRow {
    std::string exe_key;
    int64_t last_seen{0};
    int64_t first_seen{0};
    int64_t run_count_30d{0};
    int64_t total_seconds_30d{0};
};

struct MetaInfo {
    std::string coverage_since{"-"};
    int64_t days_present{0};
    int64_t open_runs{0};
    int64_t unmatched_stops{0};
    int64_t clock_anomalies{0};
    int64_t gap_count{0};
    int64_t gap_lost_events{0};
    std::string gap_last_ts{"-"};
    int64_t lag_events{0};
    bool feeder_enabled{true};
    std::string last_fold_ts{"-"};
};

// ─────────────────────────────────────────────────── SQL builders (pinned)──

// Pinned by text (test_app_usage_parsers.cpp): the `<by>` ORDER BY target is
// the same aggregate expression selected, so a plain `ORDER BY <column>`
// alias ambiguity across sqlite versions is never relied on.
inline constexpr std::string_view kSummarySqlByRunTime =
    "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
    "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
    "GROUP BY exe_key ORDER BY SUM(total_seconds) DESC LIMIT ?";
inline constexpr std::string_view kSummarySqlByRunCount =
    "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
    "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
    "GROUP BY exe_key ORDER BY SUM(run_count) DESC LIMIT ?";
// A local unprivileged user can create unboundedly many distinct exe_keys
// (each uniquely-named binary earns its own GROUP BY row in usage_daily),
// and this query has no window filter on the GROUP BY dimension itself —
// round-3 review finding (MEDIUM): an unprivileged-to-privileged resource
// exhaustion path, since the agent reading this runs as LocalSystem/root.
// Capped at kMaxLastUsedRows; run_last_used requests one extra row so the
// shell can detect truncation without a second COUNT(*) query.
inline constexpr int64_t kMaxLastUsedRows = 5000;

// run_summary's distinct-user lookup is a runtime-built IN-list query, not
// a pinned constant here -- see the comment at its call site in
// run_summary for why (round-3 review CDX-R2-03/K5: a fixed-text
// LIMIT-only cap here previously produced wrong distinct_users values for
// legitimately top-ranked executables once the table held more than
// kMaxLastUsedRows distinct exe_keys, since it had no relationship to
// WHICH exe_keys result.rows had already selected).
inline constexpr std::string_view kOpenRunsSql = "SELECT COUNT(*) FROM usage_live";
inline constexpr std::string_view kUsageDailyExistsSql =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='usage_daily'";

inline constexpr std::string_view kLastUsedSqlAll =
    "SELECT exe_key, MAX(last_seen), MIN(first_seen), "
    "SUM(CASE WHEN day_ts >= ? THEN run_count ELSE 0 END), "
    "SUM(CASE WHEN day_ts >= ? THEN total_seconds ELSE 0 END) "
    "FROM usage_daily GROUP BY exe_key ORDER BY exe_key LIMIT ?";
inline constexpr std::string_view kLastUsedSqlOne =
    "SELECT exe_key, MAX(last_seen), MIN(first_seen), "
    "SUM(CASE WHEN day_ts >= ? THEN run_count ELSE 0 END), "
    "SUM(CASE WHEN day_ts >= ? THEN total_seconds ELSE 0 END) "
    "FROM usage_daily WHERE exe_key = ? GROUP BY exe_key";

// tar_config keys this plugin is allowed to read — nothing else.
inline constexpr std::string_view kConfigUsageEnabled = "usage_enabled";
// process_enabled (tar_config) gates TAR's own process fold, not this
// plugin: its only effect on app_usage is indirect, surfacing as a stale
// usage_last_fold_ts once the fold stops advancing. Nothing here reads it
// directly, so no constant for that key is declared in this header.
inline constexpr std::string_view kConfigFeederEnabled = "usage_feeder_enabled";
inline constexpr std::string_view kConfigCoverageSince = "usage_coverage_since";
inline constexpr std::string_view kConfigUnmatchedStops = "usage_unmatched_stops";
inline constexpr std::string_view kConfigClockAnomalies = "usage_clock_anomalies";
inline constexpr std::string_view kConfigGapCount = "usage_gap_count";
inline constexpr std::string_view kConfigGapLostEvents = "usage_gap_lost_events";
inline constexpr std::string_view kConfigGapLastTs = "usage_gap_last_ts";
inline constexpr std::string_view kConfigLagEvents = "usage_lag_events";
inline constexpr std::string_view kConfigLastFoldTs = "usage_last_fold_ts";

// ───────────────────────────────────────────────────────── sqlite helpers ─

namespace detail {

class Stmt {
public:
    Stmt(sqlite3* db, std::string_view sql) noexcept {
        sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &stmt_, nullptr);
    }
    ~Stmt() {
        if (stmt_)
            sqlite3_finalize(stmt_);
    }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }
    [[nodiscard]] explicit operator bool() const noexcept { return stmt_ != nullptr; }

private:
    sqlite3_stmt* stmt_{nullptr};
};

[[nodiscard]] inline std::string col_text(sqlite3_stmt* stmt, int i) {
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
    return text ? std::string{text} : std::string{};
}

} // namespace detail

// ────────────────────────────────────────────────────────── read_meta() ───

/// `since_day_ts` (default 0 — the whole table) drives `days_present`, the
/// only meta field that is itself window-scoped; every other field is a
/// tar_config scalar or the current `usage_live` open-run count and is not
/// affected by the caller's window.
///
/// The two SQL-driven counters here (`open_runs` from usage_live,
/// `days_present` from usage_daily) are independent acquisition steps over
/// the SAME already-open connection — a genuinely open db with the expected
/// schema essentially never fails to prepare either constant query, but
/// когда it does (a mid-read schema change, a corrupt page under the WAL
/// reader), one counter failing must not silently blank out the other: both
/// are attempted, and `yuzu::shared::ConstraintAccumulator` composes
/// whichever tokens actually failed into one CC-07 reason rather than
/// reporting only the first. (The tar_config scalar reads below have no
/// failure mode of their own — `get_config`'s lambda falls back to `def` on
/// any prepare/step failure — so they are not accumulator inputs; a code
/// path that can only ever produce exactly one token doesn't need the
/// accumulator at all — e.g. `run_summary`/`run_last_used` below each
/// return on their first SQL failure, a single QueryError.)
[[nodiscard]] inline std::expected<MetaInfo, QueryError> read_meta(sqlite3* db,
                                                                    int64_t since_day_ts = 0) {
    if (!db)
        return std::unexpected(QueryError{"read_meta: null db"});

    MetaInfo meta;
    yuzu::shared::ConstraintAccumulator acc;

    {
        detail::Stmt stmt{db, kOpenRunsSql};
        if (!stmt) {
            acc.add_failure("open_runs_query_failed");
        } else if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            meta.open_runs = sqlite3_column_int64(stmt.get(), 0);
        } else {
            acc.add_failure("open_runs_query_failed");
        }
    }
    {
        detail::Stmt stmt{db, "SELECT COUNT(DISTINCT day_ts) FROM usage_daily WHERE day_ts >= ?"};
        if (!stmt) {
            acc.add_failure("days_present_query_failed");
        } else {
            sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                meta.days_present = sqlite3_column_int64(stmt.get(), 0);
            else
                acc.add_failure("days_present_query_failed");
        }
    }
    if (acc.any_failure())
        return std::unexpected(QueryError{acc.reason()});

    const auto get_config = [&](std::string_view key, std::string_view def) -> std::string {
        detail::Stmt stmt{db, "SELECT value FROM tar_config WHERE key = ?"};
        if (!stmt)
            return std::string{def};
        sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()),
                          SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW)
            return detail::col_text(stmt.get(), 0);
        return std::string{def};
    };
    const auto get_config_i64 = [&](std::string_view key, int64_t def) -> int64_t {
        const auto v = get_config(key, "");
        if (v.empty())
            return def;
        int64_t out = def;
        std::from_chars(v.data(), v.data() + v.size(), out);
        return out;
    };

    meta.coverage_since = get_config(kConfigCoverageSince, "-");
    meta.unmatched_stops = get_config_i64(kConfigUnmatchedStops, 0);
    meta.clock_anomalies = get_config_i64(kConfigClockAnomalies, 0);
    meta.gap_count = get_config_i64(kConfigGapCount, 0);
    meta.gap_lost_events = get_config_i64(kConfigGapLostEvents, 0);
    meta.gap_last_ts = get_config(kConfigGapLastTs, "-");
    meta.lag_events = get_config_i64(kConfigLagEvents, 0);
    // Round-3 review SHOULD-FIX: an absent key must read as disabled here,
    // matching last_used's own gate (check_source_state's
    // missing_means_enabled=false for this same key, app_usage_plugin.cpp)
    // -- unlike usage_enabled, whose missing-means-enabled default this
    // deliberately does NOT share. An exact-match comparison against the
    // literal "true" is required: defaulting to an empty string and still
    // comparing with `!= "false"` leaves a missing key reading as enabled
    // ("" != "false" is true), which is the same bug restated.
    meta.feeder_enabled = get_config(kConfigFeederEnabled, "") == "true";
    meta.last_fold_ts = get_config(kConfigLastFoldTs, "-");

    return meta;
}

// ─────────────────────────────────────────────────────────── run_summary ──

[[nodiscard]] inline std::expected<SummaryResult, QueryError>
run_summary(sqlite3* db, const WindowParams& w, int64_t since_day_ts) {
    if (!db)
        return std::unexpected(QueryError{"run_summary: null db"});

    const std::string_view sql =
        w.by == WindowParams::By::run_count ? kSummarySqlByRunCount : kSummarySqlByRunTime;

    SummaryResult result;
    {
        detail::Stmt stmt{db, sql};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
        sqlite3_bind_int(stmt.get(), 2, w.top);
        int rc;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            UsageRow row;
            row.exe_key = detail::col_text(stmt.get(), 0);
            row.run_count = sqlite3_column_int64(stmt.get(), 1);
            row.total_seconds = sqlite3_column_int64(stmt.get(), 2);
            row.first_seen = sqlite3_column_int64(stmt.get(), 3);
            row.last_seen = sqlite3_column_int64(stmt.get(), 4);
            row.superseded_runs = sqlite3_column_int64(stmt.get(), 5);
            row.expired_runs = sqlite3_column_int64(stmt.get(), 6);
            result.rows.push_back(std::move(row));
        }
        if (rc != SQLITE_DONE)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
    }

    // Merge in distinct-user counts (usage_daily_user — COUNT(DISTINCT user)
    // only; the user names themselves never leave this function).
    //
    // Round-3 review MEDIUM (CDX-R2-03/K5): restricted to exactly the
    // exe_keys already selected into result.rows (<= w.top, <= kMaxTop=500)
    // via a parameterized IN-list, rather than an independently-capped,
    // unordered scan of the whole usage_daily_user table. The prior
    // LIMIT-only cap (kDistinctUsersSql, no ORDER BY) had no relationship
    // to WHICH exe_keys it returned -- once the table held more than
    // kMaxLastUsedRows distinct exe_keys, a genuinely top-ranked executable
    // could fall outside the arbitrary first-N SQLite happened to return,
    // silently reporting distinct_users=0 (a real, wrong RESULT, not merely
    // an omission -- worse than the unbounded-cost problem the cap was
    // meant to fix). This departs from this header's usual "SQL text pinned
    // as a constexpr string_view" convention because the IN-list's arity
    // depends on result.rows.size() at runtime; there is nothing to pin.
    std::map<std::string, int64_t> distinct_users;
    if (!result.rows.empty()) {
        std::string sql = "SELECT exe_key, COUNT(DISTINCT user) FROM usage_daily_user "
                          "WHERE day_ts >= ? AND exe_key IN (";
        for (std::size_t i = 0; i < result.rows.size(); ++i) {
            if (i != 0)
                sql += ',';
            sql += '?';
        }
        sql += ") GROUP BY exe_key";
        detail::Stmt stmt{db, sql};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
        for (std::size_t i = 0; i < result.rows.size(); ++i) {
            const auto& key = result.rows[i].exe_key;
            sqlite3_bind_text(stmt.get(), static_cast<int>(i) + 2, key.c_str(),
                              static_cast<int>(key.size()), SQLITE_TRANSIENT);
        }
        int rc;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            distinct_users[detail::col_text(stmt.get(), 0)] = sqlite3_column_int64(stmt.get(), 1);
        }
        if (rc != SQLITE_DONE)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
    }
    for (auto& row : result.rows) {
        if (const auto it = distinct_users.find(row.exe_key); it != distinct_users.end())
            row.distinct_users = it->second;
    }

    return result;
}

// ───────────────────────────────────────────────────────── run_last_used ──

[[nodiscard]] inline std::expected<std::vector<LastUsedRow>, QueryError>
run_last_used(sqlite3* db, std::optional<std::string_view> exe, int64_t since_30d_ts) {
    if (!db)
        return std::unexpected(QueryError{"run_last_used: null db"});

    // The `exe` request parameter is normalised through the identical rule
    // stored rows were written under, and bound as a parameter below —
    // never string-built into SQL (P5).
    const std::optional<std::string> normalised_exe =
        exe ? std::optional<std::string>(normalise_exe_key(*exe)) : std::nullopt;

    std::vector<LastUsedRow> out;
    detail::Stmt stmt{db, normalised_exe ? kLastUsedSqlOne : kLastUsedSqlAll};
    if (!stmt)
        return std::unexpected(QueryError{sqlite3_errmsg(db)});
    sqlite3_bind_int64(stmt.get(), 1, since_30d_ts);
    sqlite3_bind_int64(stmt.get(), 2, since_30d_ts);
    if (normalised_exe) {
        sqlite3_bind_text(stmt.get(), 3, normalised_exe->c_str(),
                          static_cast<int>(normalised_exe->size()), SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_int64(stmt.get(), 3, kMaxLastUsedRows + 1);
    }

    int rc;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        LastUsedRow row;
        row.exe_key = detail::col_text(stmt.get(), 0);
        row.last_seen = sqlite3_column_int64(stmt.get(), 1);
        row.first_seen = sqlite3_column_int64(stmt.get(), 2);
        row.run_count_30d = sqlite3_column_int64(stmt.get(), 3);
        row.total_seconds_30d = sqlite3_column_int64(stmt.get(), 4);
        out.push_back(std::move(row));
    }
    if (rc != SQLITE_DONE)
        return std::unexpected(QueryError{sqlite3_errmsg(db)});

    return out;
}

// ───────────────────────────────────────────────────────── schema check ───

// Governance Gate 7 round 2 (unhappy-path UP-1): distinguishes a GENUINE read
// failure (busy/locked/corrupt -- prepare fails, or step returns anything
// other than SQLITE_ROW/SQLITE_DONE) from the legitimate "no such table"
// case (step returns SQLITE_DONE, zero rows). The old bool-returning version
// conflated both into `false`, which the caller read as "older TAR schema" --
// exactly the same bug class check_usage_source_state's tri-state already
// guards against for tar_config reads. `std::unexpected` on a genuine
// failure; `false` inside the expected on legitimate absence.
[[nodiscard]] inline std::expected<bool, QueryError> usage_daily_table_exists(sqlite3* db) {
    if (!db)
        return std::unexpected(QueryError{"usage_daily_table_exists: null db"});
    detail::Stmt stmt{db, kUsageDailyExistsSql};
    if (!stmt)
        return std::unexpected(QueryError{sqlite3_errmsg(db)});
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    return std::unexpected(QueryError{sqlite3_errmsg(db)});
}

// Round-3 review finding (HIGH): a fresh per-dispatch sqlite3_open_v2 alone
// never proves tar.db's integrity -- TarDatabase::open (tar_db.cpp) runs a
// full PRAGMA integrity_check and quarantines/fails closed on a corrupt file
// at ITS OWN open time, but that guarantee is scoped to TAR's own long-lived
// connection; this plugin's own connection has none of it. PRAGMA
// quick_check(1) trades the full cross-index consistency pass for speed
// (this runs on every dispatch, not once at process start) and stops at the
// first error rather than enumerating every one. Uses `detail::Stmt` (not a
// hand-rolled prepare/finalize) so this joins the SQL boundary this header's
// own file comment states -- app_usage_plugin.cpp's open_readonly only OPENS
// the connection, it does not run SQL of its own.
[[nodiscard]] inline bool quick_check_ok(sqlite3* db) {
    if (!db)
        return false;
    detail::Stmt stmt{db, "PRAGMA quick_check(1)"};
    if (!stmt)
        return false;
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return false;
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    return text != nullptr && std::string_view{text} == "ok";
}

// ─────────────────────────────────────────────────────────── formatting ───

/// See format_usage_row's P5 / no-fixed-buffer note — identical treatment.
/// `coverage_since`/`gap_last_ts`/`last_fold_ts` are tar_config values TAR
/// itself writes, not operator/attacker input this plugin controls, but
/// they are still opaque text reaching this plugin's pipe-delimited wire
/// format from outside it, so they get the same `safe_output_field` pass
/// and the same unbounded `std::string` build as an exe_key.
[[nodiscard]] inline std::string format_meta_line(const WindowParams& w, const MetaInfo& m) {
    return std::format(
        "meta|window_days|{}|coverage_since|{}|days_present|{}|open_runs|{}|"
        "unmatched_stops|{}|clock_anomalies|{}|gap_count|{}|gap_lost_events|{}|"
        "gap_last_ts|{}|lag_events|{}|feeder_enabled|{}|last_fold_ts|{}",
        w.days, yuzu::util::safe_output_field(m.coverage_since), m.days_present, m.open_runs,
        m.unmatched_stops, m.clock_anomalies, m.gap_count, m.gap_lost_events,
        yuzu::util::safe_output_field(m.gap_last_ts), m.lag_events, m.feeder_enabled ? 1 : 0,
        yuzu::util::safe_output_field(m.last_fold_ts));
}

/// exe_key is untrusted, attacker/OS-controlled text — passed through
/// `safe_output_field` (P5) before it ever reaches the pipe-delimited wire
/// format, so a `|`, CR, or LF embedded in a real executable's basename can
/// never inject a field or row boundary. Built directly into a std::string
/// (no fixed-size stack buffer) — neither normalise_exe_key nor TAR's own
/// writer caps executable-name length, and pipe-escaping can roughly double a
/// pipe-heavy name, so a fixed ceiling here would silently truncate a real
/// row (the daily-sync consumer then drops a truncated row outright).
[[nodiscard]] inline std::string format_usage_row(const UsageRow& r) {
    const std::string safe_exe_key = yuzu::util::safe_output_field(r.exe_key);
    return std::format("usage|{}|{}|{}|{}|{}|{}|{}|{}", safe_exe_key, r.run_count,
                       r.total_seconds, r.first_seen, r.last_seen, r.distinct_users,
                       r.superseded_runs, r.expired_runs);
}

/// See format_usage_row's P5 / no-fixed-buffer note — identical treatment.
[[nodiscard]] inline std::string format_last_used_row(const LastUsedRow& r) {
    const std::string safe_exe_key = yuzu::util::safe_output_field(r.exe_key);
    return std::format("last_used|{}|{}|{}|{}|{}", safe_exe_key, r.last_seen, r.first_seen,
                       r.run_count_30d, r.total_seconds_30d);
}

} // namespace yuzu::app_usage
