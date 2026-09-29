#include "app_perf_fleet_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_retention_guard.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp> // canon_version — read path must match ingest

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "app_perf_fleet_store";
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
constexpr std::chrono::milliseconds kPruneAcquireTimeout{2000};
// Hard ceiling on rows a single app read materialises (an app over the full 180d
// retention × its versions is small; this is unbounded-growth defence).
constexpr int kQueryRowCap = 100000;
// Picker cap — a bounded slice of the fleet's distinct app set (unbounded in
// principle). Clipping is reported via the out-param, never silent.
constexpr int kAppListCap = 5000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the
    // migration txn, so `app_perf_fleet` lands in `app_perf_fleet_store`. The (day)
    // index serves the prune; the PK serves per-app reads + the roll-up's ON CONFLICT.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE app_perf_fleet ("
         "  app_name     TEXT   NOT NULL,"
         "  version      TEXT   NOT NULL DEFAULT '',"
         "  day          BIGINT NOT NULL,"
         "  device_count BIGINT NOT NULL DEFAULT 0,"
         "  cpu_sum      DOUBLE PRECISION NOT NULL DEFAULT 0,"
         "  cpu_max      DOUBLE PRECISION NOT NULL DEFAULT 0,"
         "  ws_sum       BIGINT NOT NULL DEFAULT 0,"
         "  ws_max       BIGINT NOT NULL DEFAULT 0,"
         "  cpu_hist     BIGINT[] NOT NULL,"
         "  ws_hist      BIGINT[] NOT NULL,"
         "  hist_version SMALLINT NOT NULL DEFAULT 1,"
         "  updated_at   BIGINT NOT NULL,"
         "  PRIMARY KEY (app_name, version, day));"
         "CREATE INDEX app_perf_fleet_day_idx ON app_perf_fleet (day);"},
        // WS-10 (#2508): durable anchor + dedup state for the clock-guarded,
        // single-writer retention prune (shared shape, see run_retention_prune).
        {2, "CREATE TABLE IF NOT EXISTS retention_meta ("
            "  key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
    };
    return kMigrations;
}

// WS-10 retention-guard constants — PER-STORE. The `day` column is a day-floored
// UNIX-SECONDS bucket, so every value here is in SECONDS. app_perf fleet history
// is non-regenerable aggregated analytics at a ~1h prune cadence, 180-day
// retention; part-6 missing-anchor = Decline (audit_store's answer).
constexpr std::int64_t kPruneBigStepFloorSecs = 86'400;      // 24h absolute (> any legit inter-pass gap at 1h cadence)
constexpr std::int64_t kPruneImplausibilitySecs = 86'400;    // day buckets are never future; >1d ahead is skew
constexpr std::int64_t kPruneMinPlausibleSecs = 946'684'800; // year 2000 in seconds
// kPruneCapPerPass is a PUBLIC static member (app_perf_fleet_store.hpp) so the
// roll-up thread can detect a cap-hit and re-arm; referenced below via the member.

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    const double v = std::strtod(s, nullptr);
    return std::isfinite(v) ? v : 0.0; // a stored Inf never propagates to model/JSON/UI (UP-2)
}

// Parse a PostgreSQL bigint[] text rendering ("{1,2,3}" / "{}") into a vector.
// Numeric elements only (this store's arrays are never NULL/quoted).
std::vector<std::int64_t> parse_bigint_array(const char* s) {
    std::vector<std::int64_t> out;
    if (s == nullptr)
        return out;
    const char* p = s;
    while (*p != '\0' && *p != '{')
        ++p;
    if (*p == '{')
        ++p;
    while (*p != '\0' && *p != '}') {
        char* end = nullptr;
        const long long v = std::strtoll(p, &end, 10);
        if (end == p)
            break; // no digits — malformed, stop
        out.push_back(static_cast<std::int64_t>(v));
        p = end;
        while (*p == ',' || *p == ' ')
            ++p;
    }
    return out;
}

// ── Read-degrade observability (mirrors the B1 store) ─────────────────────────
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_app_perf_fleet_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

} // namespace

AppPerfFleetStore::AppPerfFleetStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AppPerfFleetStore: no database connection at construction ({}) — "
                      "fleet app-perf persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AppPerfFleetStore: schema migration failed — fleet app-perf persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

std::optional<std::vector<AppPerfFleetRow>>
AppPerfFleetStore::get_app_fleet_perf(std::string_view app_name, std::string_view version) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: get_app_fleet_perf degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AppPerfFleetRow> out;
    if (app_name.empty())
        return out; // precondition miss, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: get_app_fleet_perf degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }

    // Canonicalize the version FILTER exactly as ingest canonicalized the stored
    // key (yuzu::util::canon_version, the same fn AppPerfDailyStore applies). A raw
    // "1.2.3.4" must match a canon-collapsed stored row, or the filter silently
    // misses every row — a bug invisible to any test that queries the already-canon
    // form. "" stays "" (the all-versions sentinel).
    const std::string cversion = yuzu::util::canon_version(version);

    std::string sql =
        "SELECT app_name, version, day, device_count, cpu_sum, cpu_max, ws_sum, ws_max, "
        "       cpu_hist, ws_hist, hist_version "
        "FROM app_perf_fleet_store.app_perf_fleet WHERE app_name = $1";
    std::vector<std::string> params;
    params.emplace_back(app_name);
    if (!cversion.empty()) {
        sql += " AND version = $2";
        params.emplace_back(cversion);
    }
    sql += " ORDER BY version, day LIMIT $" + std::to_string(params.size() + 1) + "::bigint";
    params.push_back(std::to_string(kQueryRowCap));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: get_app_fleet_perf degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfFleetRow r;
        r.app_name = PQgetvalue(res.get(), i, 0);
        r.version = PQgetvalue(res.get(), i, 1);
        r.day = to_i64(PQgetvalue(res.get(), i, 2));
        r.device_count = to_i64(PQgetvalue(res.get(), i, 3));
        r.cpu_sum = to_double(PQgetvalue(res.get(), i, 4));
        r.cpu_max = to_double(PQgetvalue(res.get(), i, 5));
        r.ws_sum = to_i64(PQgetvalue(res.get(), i, 6));
        r.ws_max = to_i64(PQgetvalue(res.get(), i, 7));
        r.cpu_hist = parse_bigint_array(PQgetvalue(res.get(), i, 8));
        r.ws_hist = parse_bigint_array(PQgetvalue(res.get(), i, 9));
        r.hist_version = static_cast<int>(to_i64(PQgetvalue(res.get(), i, 10)));
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<AppPerfAppSummary>> AppPerfFleetStore::list_apps(bool& truncated) {
    truncated = false;
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: list_apps degraded — store not open (occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: list_apps degraded — no connection ({}) (occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    // One extra row over the cap distinguishes "exactly cap" from "more than cap"
    // so truncation is reported, never silent (the fleet's distinct-app count is
    // unbounded in principle; the picker only needs a bounded slice).
    const std::string sql =
        "SELECT app_name, COUNT(DISTINCT version), MAX(day) "
        "FROM app_perf_fleet_store.app_perf_fleet "
        "GROUP BY app_name ORDER BY app_name LIMIT $1::bigint";
    std::vector<std::string> params{std::to_string(kAppListCap + 1)};
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppPerfFleetStore: list_apps degraded — query failed: {} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<AppPerfAppSummary> out;
    int n = PQntuples(res.get());
    if (n > kAppListCap) {
        truncated = true;
        n = kAppListCap; // drop the probe row
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfAppSummary s;
        s.app_name = PQgetvalue(res.get(), i, 0);
        s.versions = to_i64(PQgetvalue(res.get(), i, 1));
        s.last_day = to_i64(PQgetvalue(res.get(), i, 2));
        out.push_back(std::move(s));
    }
    return out;
}

int AppPerfFleetStore::run_retention_prune(std::int64_t retention_window_secs) {
    if (!open_)
        return -1;
    // WS-10 (#2508): clock-guarded, single-writer, capped retention. All units are
    // SECONDS (the `day` column is a day-floored unix-seconds bucket). Part-6
    // missing-anchor = Decline: fleet perf history is non-regenerable aggregated
    // analytics, so a from-boot skewed clock must not silently wipe it.
    // now_expr is RAW epoch seconds (NOT day-floored): the anchor + big_step need
    // the true reading, or an hourly tick across UTC midnight false-fires a 24h
    // Step and pauses retention (WS-10 C1). The DAY alignment lives in
    // `cutoff_align = 86400` below, which floors ONLY the cutoff to the `day`
    // bucket — matching the pre-WS-10 caller (`(now/86400)*86400 - window`) and the
    // sibling app_perf_daily_store, so the 180-day boundary bucket is not deleted
    // ~24h early.
    const pg::ClockGuardedPruneSpec spec{
        .store_label = kStoreName,
        .target_table = "app_perf_fleet_store.app_perf_fleet",
        .ts_column = "day",
        .now_expr = "(EXTRACT(EPOCH FROM now()))::bigint",
        .meta_table = "app_perf_fleet_store.retention_meta",
        .anchor_key = "app_perf_prune_last_pass_now",
        .settled_key = "app_perf_prune_bootstrap_settled",
        .facts_key = "app_perf_prune_last_anomaly_facts",
        .advisory_lock_key = "hashtext('app_perf_fleet_store:app_perf_prune')",
        .retention_window = retention_window_secs,
        .big_step_floor = kPruneBigStepFloorSecs,
        .implausibility_bound = kPruneImplausibilitySecs,
        .min_plausible_reading = kPruneMinPlausibleSecs,
        .cap_per_pass = kPruneCapPerPass,
        .missing_anchor = pg::MissingAnchorPolicy::Decline,
        .cutoff_align = 86'400, // day-align the cutoff to the `day` bucket (raw now stays for big_step)
    };
    const auto r = pg::run_clock_guarded_prune(pool_, spec, kPruneAcquireTimeout);
    return r.error ? -1 : r.deleted;
}

} // namespace yuzu::server
