#include "dex_app_version_failures_owner.hpp"

#include "dex_window.hpp" // dex_iso_at (pure)

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>

namespace yuzu::server {

namespace {

// A request-path read: a short bounded acquire and a short statement bound, so a
// saturated pool or a slow plan degrades to a typed failure instead of holding a
// web worker.
constexpr std::chrono::milliseconds kAcquireTimeout{3000};
constexpr const char* kStatementTimeout = "10s";

// `exp`: the exposed (version, device) pairs; `obs`: crash and hang events for
// the application, each flagged by whether its device is exposed for that
// version; `ex` / `fo`: the per-version exposure and failure aggregates. The
// FULL OUTER JOIN keeps a version that has only one side; exposure_devices is
// NULL (unknown, never zero) when a version has no exposure rows. The version
// list is bounded by the caller's ANY() list, so LIMIT is a depth guard only.
// Events are cut at BOTH ends: `observed_at >= $5` and `observed_at < $7` (the
// end of the current UTC day, the same cut as the exposure side), so a
// future-dated observation never enters a numerator the denominator cannot see.
constexpr const char* kReadSql =
    "WITH exp AS ("
    " SELECT version, agent_id FROM app_perf_daily_store.app_perf_daily"
    " WHERE app_name = $1 AND version = ANY($2::text[])"
    "   AND day >= $3::bigint AND day <= $4::bigint"
    " GROUP BY version, agent_id), "
    "obs AS ("
    " SELECT o.version, o.obs_type, o.agent_id, (e.agent_id IS NOT NULL) AS exposed"
    " FROM guaranteed_state_store.guardian_observations o"
    " LEFT JOIN exp e ON e.version = o.version AND e.agent_id = o.agent_id"
    " WHERE o.obs_type IN ('process.crashed', 'process.hung')"
    "   AND o.observed_at >= $5 AND o.observed_at < $7 AND o.subject = $1 AND o.version = ANY($2::text[])), "
    "ex AS (SELECT version, COUNT(*) AS exposure_devices FROM exp GROUP BY version), "
    "fo AS ("
    " SELECT version,"
    "  COUNT(*) FILTER (WHERE obs_type = 'process.crashed') AS crashes,"
    "  COUNT(*) FILTER (WHERE obs_type = 'process.hung') AS hangs,"
    "  COUNT(DISTINCT agent_id) AS affected_devices,"
    "  COUNT(*) FILTER (WHERE obs_type = 'process.crashed' AND exposed) AS exposed_crashes,"
    "  COUNT(*) FILTER (WHERE obs_type = 'process.hung' AND exposed) AS exposed_hangs"
    " FROM obs GROUP BY version) "
    "SELECT COALESCE(ex.version, fo.version), ex.exposure_devices,"
    " COALESCE(fo.crashes, 0), COALESCE(fo.hangs, 0), COALESCE(fo.affected_devices, 0),"
    " COALESCE(fo.exposed_crashes, 0), COALESCE(fo.exposed_hangs, 0)"
    " FROM ex FULL OUTER JOIN fo ON ex.version = fo.version"
    " ORDER BY 1 LIMIT $6::bigint";

std::int64_t col_i64(PGresult* res, int row, int col) {
    const char* s = PQgetvalue(res, row, col);
    return s == nullptr || s[0] == '\0' ? 0 : static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

} // namespace

DexAppVersionFailuresOwner::DexAppVersionFailuresOwner(pg::PgPool& pool, int retention_days)
    : pool_(pool), retention_days_(retention_days) {}

int DexAppVersionFailuresOwner::failure_window_days() const {
    return retention_days_ > 0 ? (std::min)(kAppPerfFailureWindowDays, retention_days_ - 1)
                               : kAppPerfFailureWindowDays;
}

std::optional<std::vector<AppPerfVersionFailureRow>>
DexAppVersionFailuresOwner::read(std::string_view app, const std::vector<std::string>& versions,
                                 std::int64_t since_day, std::int64_t end_day,
                                 std::string_view since_iso) const {
    if (app.empty() || versions.empty())
        return std::vector<AppPerfVersionFailureRow>{};

    std::vector<std::string_view> vs(versions.begin(), versions.end());
    std::vector<std::optional<std::string>> params{
        std::string(app),
        pg::to_text_array(vs),
        std::to_string(since_day),
        std::to_string(end_day),
        std::string(since_iso),
        std::to_string(versions.size() + 1),
        // Exclusive upper cut: the end of `end_day`'s UTC day, one derivation with
        // the exposure side's `day <= end_day`.
        dex_iso_at(end_day + 86400)};

    std::optional<std::vector<AppPerfVersionFailureRow>> out;
    bool statement_failed = false;
    // Never names the application: it is caller-supplied text.
    const auto fail = [&statement_failed](const pg::PgResult& res) {
        statement_failed = true;
        const char* state = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        spdlog::warn("DexAppVersionFailuresOwner: statement failed, SQLSTATE {}",
                     state != nullptr ? state : "unknown");
        return false;
    };
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(
            c,
            std::string("SET LOCAL statement_timeout = '").append(kStatementTimeout).append("'").c_str(),
            std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return fail(t);
        pg::PgResult r = pg::exec_params(c, kReadSql, params);
        if (r.status() != PGRES_TUPLES_OK)
            return fail(r);
        std::vector<AppPerfVersionFailureRow> rows;
        const int n = PQntuples(r.get());
        rows.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            AppPerfVersionFailureRow row;
            row.version = PQgetisnull(r.get(), i, 0) ? std::string{} : PQgetvalue(r.get(), i, 0);
            if (!PQgetisnull(r.get(), i, 1))
                row.exposure_devices = col_i64(r.get(), i, 1);
            row.crashes = col_i64(r.get(), i, 2);
            row.hangs = col_i64(r.get(), i, 3);
            row.affected_devices = col_i64(r.get(), i, 4);
            row.exposed_crashes = col_i64(r.get(), i, 5);
            row.exposed_hangs = col_i64(r.get(), i, 6);
            rows.push_back(std::move(row));
        }
        out = std::move(rows);
        return true;
    });
    if (!ok || !out) {
        if (!statement_failed)
            spdlog::warn(
                "DexAppVersionFailuresOwner: pool acquire timed out or transaction not committed");
        return std::nullopt;
    }
    return out;
}

} // namespace yuzu::server
