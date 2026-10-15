#include "app_perf_daily_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "app_perf_daily_store";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC thread
// (direct ReportInventory / gateway ProxyInventory) so it must give up fast on a
// saturated pool — best-effort, the agent re-sends next cycle (the 2-day window
// self-heals). The read is a (future) user-facing request and can wait longer.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// Hard ceiling on rows a per-agent read will materialise, independent of fleet /
// table growth: 31 days × top-N(~20) × a few versions is ~1k; this is generous
// headroom so the store can never allocate an unbounded result set.
constexpr int kQueryRowCap = 100000;
// Hard ceiling on DEVICES a single "which devices ran (app,version)" drill will
// materialise. Backs an interactive UI table (not a bulk export), so a much
// tighter cap than kQueryRowCap above is appropriate; ordering by descending
// cpu_avg before the cap keeps the highest resource consumers even when a
// wildly popular version is truncated.
constexpr int kVersionDevicesRowCap = 2000;
// Defensive cap on rows accepted from one apply (a legit agent sends ~tens — the
// 2-day window × top-N). Bounds memory + the upsert batch against a misbehaving
// agent; the ingest seam's blob cap is the primary bound, this is depth.
constexpr std::size_t kMaxRowsPerApply = 5000;
// Sane ceiling for the per-day instance count (defense-in-depth; procperf
// instance counts are tiny). Keeps a forged value from poisoning aggregates.
constexpr std::int64_t kMaxInstances = 1'000'000;
// Upper ceiling for the per-day sample count. `samples` is the ONE agent-supplied
// numeric the canon previously only lower-clamped — yet it is the weight in the
// reductions' sample-weighted means (dex_app_perf_model), so a forged near-INT64_MAX
// value (or a sum of several) overflows the int64 `sample_sum` accumulator (signed
// overflow = UB) and makes the downstream `llround(ws_sum/sample_sum)` UB too
// (sec-M1). 1e9 is >> any legitimate daily count (≤2880 30 s ticks/day × instances)
// and kMaxSamples × kQueryRowCap (1e5) = 1e14 ≪ INT64_MAX, so the read-side sum is
// safe even at the row cap.
constexpr std::int64_t kMaxSamples = 1'000'000'000;
// Future-dating slack: rows whose agent-supplied `day` is more than this many days
// ahead of the server's current UTC day are dropped on apply. `day` is agent
// time and was never upper-bounded; the retention prune is `WHERE day < cutoff`, so
// a far-future `day` would survive forever (retention bypass → unbounded per-agent
// storage) and could spread one (app,version) across ~kQueryRowCap distinct days
// (a multi-MB sparkline). The agent only ever sends the last 2 *completed* UTC days,
// so 2 days of slack absorbs any benign clock skew / TZ boundary without rejecting a
// legitimate payload (UP-2; the #1685 agent-clock lesson, applied to `day`).
constexpr int kFutureSlackDays = 2;
// Upper ceilings for the per-device daily perf values (defense-in-depth against a
// forged/hostile agent). cpu is share-of-total-capacity percent (documented 0..100).
// ws caps at 1 PiB — far above any real working set; combined with the rollup's
// saturating SUM it stops a forged value from aborting the fleet-day aggregate
// (overflow of SUM(ws)::bigint, UP-1) or skewing MAX/mean.
constexpr double kMaxCpuPct = 100.0;
constexpr std::int64_t kMaxWsBytes = std::int64_t{1} << 50; // 1 PiB

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the
    // migration transaction, so `app_perf_daily` lands in `app_perf_daily_store`.
    // Runtime statements below schema-qualify explicitly. Plain table + PK; the
    // fleet/rollup secondary index is deferred to B2 (a cheap transactional
    // migration on a small table) — the PK serves apply (ON CONFLICT), the
    // per-agent read (agent_id prefix), and the per-agent prune.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE app_perf_daily ("
         "  agent_id      TEXT   NOT NULL,"
         "  app_name      TEXT   NOT NULL,"
         "  version       TEXT   NOT NULL DEFAULT '',"
         "  day           BIGINT NOT NULL,"
         "  samples       BIGINT NOT NULL DEFAULT 0,"
         "  instances_max BIGINT NOT NULL DEFAULT 0,"
         "  cpu_avg       DOUBLE PRECISION NOT NULL DEFAULT 0,"
         "  cpu_max       DOUBLE PRECISION NOT NULL DEFAULT 0,"
         "  ws_avg_bytes  BIGINT NOT NULL DEFAULT 0,"
         "  ws_max_bytes  BIGINT NOT NULL DEFAULT 0,"
         "  updated_at    BIGINT NOT NULL,"
         "  PRIMARY KEY (agent_id, app_name, version, day));"},
        {2,
         // Rollup-scan index (DEX app-perf-over-time B2): the daily fleet rollup
         // (AppPerfRollup) reads `WHERE day = $1 GROUP BY app_name, version`. Leading
         // `day` serves the equality + per-(app,version) grouping. Plain CREATE INDEX
         // is safe here — this table is born-on-Pg alongside B2, so it is empty at
         // first migration (no ACCESS EXCLUSIVE stall, no CONCURRENTLY needed).
         "CREATE INDEX app_perf_daily_day_idx ON app_perf_daily (day, app_name, version);"},
        // v3 (the version-drill index) is deliberately NOT here. list_devices_for_version
        // below runs correctly without it — a full scan, not a wrong answer — until the
        // non-transactional migration kind exists (ADR-0008 Update, 2026-06-22): this
        // table is live-written (daily-sync has been shipping since v1/v2), so a plain
        // CREATE INDEX would take an ACCESS EXCLUSIVE lock for the build's duration, and
        // ADR-0008 requires the non-transactional kind for DDL on an already-large,
        // live table rather than "weakening the transactional default to sneak one in".
        // Tracked as https://github.com/Tr3kkR/Yuzu/issues/4432 — land the index via
        // that migration kind (or a reviewed ADR-0008 exception), never a plain
        // CREATE INDEX here.
    };
    return kMigrations;
}

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
    return std::isfinite(v) ? v : 0.0;
}

double clamp_finite_nonneg(double v) {
    return (std::isfinite(v) && v > 0.0) ? v : 0.0;
}

// Locale-independent double formatting for a float8 text parameter. std::format
// uses '.' regardless of the process locale (std::to_string("%f") does NOT — a
// comma-decimal locale would emit "12,3" and PG would reject it). The value is
// pre-clamped finite + non-negative, so no NaN/Inf token can reach PG.
std::string fmt_double(double v) {
    return std::format("{}", v);
}

// ── Read-degrade observability (mirrors SoftwareInventoryStore #1675) ─────────
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
        metrics->counter("yuzu_app_perf_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

} // namespace

std::vector<AppPerfDailyRow> canon_merge_daily(std::vector<AppPerfDailyRow> rows) {
    // 1. Canonicalize version + clamp every numeric. canon_version is the SAME
    //    function the stability side uses, so B1 rows join `(app, version)` later.
    for (auto& r : rows) {
        r.version = yuzu::util::canon_version(r.version);
        r.cpu_avg = (std::min)(clamp_finite_nonneg(r.cpu_avg), kMaxCpuPct);
        r.cpu_max = (std::min)(clamp_finite_nonneg(r.cpu_max), kMaxCpuPct);
        if (r.samples < 0)
            r.samples = 0;
        else if (r.samples > kMaxSamples)
            r.samples = kMaxSamples; // weight in the reductions' sample-weighted means — cap to bound the int64 sum (sec-M1)
        if (r.instances_max < 0)
            r.instances_max = 0;
        else if (r.instances_max > kMaxInstances)
            r.instances_max = kMaxInstances;
        // Working set: upper-clamp too (was lower-only). A forged near-INT64_MAX ws
        // on a popular app would otherwise overflow the rollup's SUM(ws)::bigint and
        // abort the entire fleet-day roll-up (UP-1).
        if (r.ws_avg_bytes < 0)
            r.ws_avg_bytes = 0;
        else if (r.ws_avg_bytes > kMaxWsBytes)
            r.ws_avg_bytes = kMaxWsBytes;
        if (r.ws_max_bytes < 0)
            r.ws_max_bytes = 0;
        else if (r.ws_max_bytes > kMaxWsBytes)
            r.ws_max_bytes = kMaxWsBytes;
    }
    // 2. Sort by the merge key so collisions (two raw versions that canon to the
    //    same string) become adjacent.
    std::sort(rows.begin(), rows.end(), [](const AppPerfDailyRow& a, const AppPerfDailyRow& b) {
        if (a.app_name != b.app_name)
            return a.app_name < b.app_name;
        if (a.version != b.version)
            return a.version < b.version;
        return a.day < b.day;
    });
    // 3. Combine adjacent equal keys, sample-weighting the averages so the merged
    //    daily mean is the true mean over all samples (max-of-max for peaks).
    std::vector<AppPerfDailyRow> out;
    out.reserve(rows.size());
    for (auto& r : rows) {
        if (!out.empty() && out.back().app_name == r.app_name &&
            out.back().version == r.version && out.back().day == r.day) {
            AppPerfDailyRow& m = out.back();
            const std::int64_t total = m.samples + r.samples;
            if (total > 0) {
                m.cpu_avg = (m.cpu_avg * static_cast<double>(m.samples) +
                             r.cpu_avg * static_cast<double>(r.samples)) /
                            static_cast<double>(total);
                const long double wavg = (static_cast<long double>(m.ws_avg_bytes) *
                                              static_cast<long double>(m.samples) +
                                          static_cast<long double>(r.ws_avg_bytes) *
                                              static_cast<long double>(r.samples)) /
                                         static_cast<long double>(total);
                m.ws_avg_bytes = static_cast<std::int64_t>(wavg);
            }
            // Re-clamp the MERGED count: the per-row cap bounds each raw row, but a
            // batch of duplicate-key rows sums here, so the stored value must be
            // re-capped to keep `samples` ≤ kMaxSamples by construction (so the
            // read-side int64 weight sum stays ≤ kMaxSamples × kQueryRowCap = 1e14 ≪
            // INT64_MAX regardless of the wire message size — sec-M1 LOW). The
            // weighted means above already used the true `total`; 1e9 samples/day is
            // physically impossible, so the clamp only engages on hostile input where
            // the mean is already meaningless.
            m.samples = (std::min)(total, kMaxSamples);
            m.cpu_max = std::max(m.cpu_max, r.cpu_max);
            m.ws_max_bytes = std::max(m.ws_max_bytes, r.ws_max_bytes);
            m.instances_max = std::max(m.instances_max, r.instances_max);
        } else {
            out.push_back(std::move(r));
        }
    }
    return out;
}

AppPerfDailyStore::AppPerfDailyStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AppPerfDailyStore: no database connection at construction ({}) — "
                      "app-perf daily persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AppPerfDailyStore: schema migration failed — app-perf daily "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

bool AppPerfDailyStore::apply_daily(std::string_view agent_id, std::vector<AppPerfDailyRow> rows) {
    if (!open_ || agent_id.empty())
        return false;

    const std::int64_t ts = now_secs();
    const std::int64_t today_start = (ts / 86400) * 86400;
    const std::int64_t cutoff = today_start - static_cast<std::int64_t>(kRetentionDays) * 86400;
    const std::int64_t day_upper = today_start + static_cast<std::int64_t>(kFutureSlackDays) * 86400;
    const std::string agent_id_s{agent_id};

    // Re-canon + merge server-side (authoritative writer, defense-in-depth) so the
    // batch is key-unique — otherwise ON CONFLICT would "affect a row a second time".
    std::vector<AppPerfDailyRow> merged = canon_merge_daily(std::move(rows));
    // Drop rows whose agent-supplied `day` is outside the retention window — in
    // particular far-FUTURE days, which the `WHERE day < cutoff` prune below would
    // never reclaim (retention bypass / sparkline amplification, UP-2). Filtered
    // BEFORE the per-apply cap so a flood of forged future rows can't crowd out the
    // agent's legitimate recent days. A day < cutoff is already stale (the prune
    // would delete it this same txn) — dropping it here is equivalent and cheaper.
    std::erase_if(merged, [&](const AppPerfDailyRow& r) {
        return r.day < cutoff || r.day > day_upper;
    });
    if (merged.size() > kMaxRowsPerApply)
        merged.resize(kMaxRowsPerApply);

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        if (!merged.empty()) {
            // Parallel arrays for the batched unnest upsert (house pattern, #1664):
            // agent_id + updated_at are scalars, so the param count is a constant 11
            // regardless of row count. name/version view the rows directly; the
            // numerics are formatted into owning string vectors then viewed.
            std::vector<std::string_view> names, versions;
            std::vector<std::string> days, samples, instances, cpuavg, cpumax, wsavg, wsmax;
            const std::size_t n = merged.size();
            names.reserve(n);
            versions.reserve(n);
            days.reserve(n);
            samples.reserve(n);
            instances.reserve(n);
            cpuavg.reserve(n);
            cpumax.reserve(n);
            wsavg.reserve(n);
            wsmax.reserve(n);
            for (const auto& r : merged) {
                names.emplace_back(r.app_name);
                versions.emplace_back(r.version);
                days.push_back(std::to_string(r.day));
                samples.push_back(std::to_string(r.samples));
                instances.push_back(std::to_string(r.instances_max));
                cpuavg.push_back(fmt_double(r.cpu_avg));
                cpumax.push_back(fmt_double(r.cpu_max));
                wsavg.push_back(std::to_string(r.ws_avg_bytes));
                wsmax.push_back(std::to_string(r.ws_max_bytes));
            }
            const auto sv = [](const std::vector<std::string>& v) {
                return std::vector<std::string_view>(v.begin(), v.end());
            };
            std::vector<std::string> params;
            params.reserve(11);
            params.push_back(agent_id_s);
            params.push_back(pg::to_text_array(names));
            params.push_back(pg::to_text_array(versions));
            params.push_back(pg::to_text_array(sv(days)));
            params.push_back(pg::to_text_array(sv(samples)));
            params.push_back(pg::to_text_array(sv(instances)));
            params.push_back(pg::to_text_array(sv(cpuavg)));
            params.push_back(pg::to_text_array(sv(cpumax)));
            params.push_back(pg::to_text_array(sv(wsavg)));
            params.push_back(pg::to_text_array(sv(wsmax)));
            params.push_back(std::to_string(ts)); // $11 updated_at (server receipt time)

            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO app_perf_daily_store.app_perf_daily "
                "(agent_id, app_name, version, day, samples, instances_max, cpu_avg, cpu_max, "
                " ws_avg_bytes, ws_max_bytes, updated_at) "
                "SELECT $1, n, v, d::bigint, s::bigint, im::bigint, ca::float8, cm::float8, "
                "       wa::bigint, wm::bigint, $11::bigint "
                "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], "
                "            $7::text[], $8::text[], $9::text[], $10::text[]) "
                "  AS t(n, v, d, s, im, ca, cm, wa, wm) "
                "ON CONFLICT (agent_id, app_name, version, day) DO UPDATE SET "
                "  samples = EXCLUDED.samples, instances_max = EXCLUDED.instances_max, "
                "  cpu_avg = EXCLUDED.cpu_avg, cpu_max = EXCLUDED.cpu_max, "
                "  ws_avg_bytes = EXCLUDED.ws_avg_bytes, ws_max_bytes = EXCLUDED.ws_max_bytes, "
                "  updated_at = EXCLUDED.updated_at",
                params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        // Per-agent retention prune in the same transaction (bounded: one agent's
        // rows). A dark agent's residual is ≤31 days and reclaimed by delete_agent.
        pg::PgResult del = pg::exec_params(
            c,
            "DELETE FROM app_perf_daily_store.app_perf_daily WHERE agent_id = $1 AND day < $2::bigint",
            std::vector<std::string>{agent_id_s, std::to_string(cutoff)});
        return del.status() == PGRES_COMMAND_OK;
    });
    if (!ok)
        spdlog::warn("AppPerfDailyStore: apply_daily transaction failed for agent={}", agent_id);
    return ok;
}

std::optional<std::vector<AppPerfDailyRow>>
AppPerfDailyStore::get_agent_app_perf(std::string_view agent_id) {
    // AUTHORITATIVE read: a degrade returns nullopt, never a silent empty.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: get_agent_app_perf degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AppPerfDailyRow> out;
    if (agent_id.empty())
        return out; // precondition miss, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: get_agent_app_perf degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT app_name, version, day, samples, instances_max, cpu_avg, cpu_max, "
        "       ws_avg_bytes, ws_max_bytes "
        "FROM app_perf_daily_store.app_perf_daily "
        "WHERE agent_id = $1 ORDER BY app_name, version, day LIMIT $2::bigint",
        std::vector<std::string>{std::string(agent_id), std::to_string(kQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: get_agent_app_perf degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfDailyRow r;
        r.app_name = PQgetvalue(res.get(), i, 0);
        r.version = PQgetvalue(res.get(), i, 1);
        r.day = to_i64(PQgetvalue(res.get(), i, 2));
        r.samples = to_i64(PQgetvalue(res.get(), i, 3));
        r.instances_max = to_i64(PQgetvalue(res.get(), i, 4));
        r.cpu_avg = to_double(PQgetvalue(res.get(), i, 5));
        r.cpu_max = to_double(PQgetvalue(res.get(), i, 6));
        r.ws_avg_bytes = to_i64(PQgetvalue(res.get(), i, 7));
        r.ws_max_bytes = to_i64(PQgetvalue(res.get(), i, 8));
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<AppPerfVersionDeviceRow>>
AppPerfDailyStore::list_devices_for_version(
    std::string_view app_name, std::string_view version,
    const std::optional<std::vector<std::string>>& visible_agent_ids, bool& truncated) {
    truncated = false;
    // AUTHORITATIVE read: a degrade returns nullopt, never a silent empty.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: list_devices_for_version degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AppPerfVersionDeviceRow> out;
    if (app_name.empty())
        return out; // precondition miss, not a degrade (version="" is the valid unknown bucket)
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: list_devices_for_version degraded — no connection "
                         "({}) (occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }

    std::vector<std::string> params;
    params.emplace_back(app_name);
    params.emplace_back(version);
    // ADR-0017: the caller's visible-agent set is pushed into the WHERE clause
    // (never applied post-fetch) so it composes correctly with the LIMIT below —
    // a present-but-empty set binds an empty text[] literal, and
    // `agent_id = ANY('{}'::text[])` is false for every row, yielding zero rows
    // (deny-all) with no special-casing needed.
    std::string sql =
        "SELECT agent_id, day, samples, cpu_avg, ws_avg_bytes FROM ("
        "  SELECT DISTINCT ON (agent_id) agent_id, day, samples, cpu_avg, ws_avg_bytes "
        "  FROM app_perf_daily_store.app_perf_daily "
        "  WHERE app_name = $1 AND version = $2";
    if (visible_agent_ids) {
        std::vector<std::string_view> views(visible_agent_ids->begin(), visible_agent_ids->end());
        params.push_back(pg::to_text_array(views));
        sql += " AND agent_id = ANY($3::text[])";
    }
    sql += "  ORDER BY agent_id, day DESC"
           ") t ORDER BY cpu_avg DESC, agent_id LIMIT " +
           // One row PAST the cap (#4030 pattern) so a fleet of exactly
           // kVersionDevicesRowCap devices is never misreported as truncated —
           // the sentinel row is trimmed back off below, never returned.
           std::to_string(kVersionDevicesRowCap + 1);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppPerfDailyStore: list_devices_for_version degraded — query failed: "
                         "{} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    truncated = rows > kVersionDevicesRowCap;
    const int n = truncated ? kVersionDevicesRowCap : rows;
    if (truncated) {
        // The cap sits on the OUTER (cpu_avg DESC) ordering, so the dropped rows
        // are the LOWEST-cpu devices past the ceiling — a truncated read still
        // surfaces the highest resource consumers, never an arbitrary subset.
        if (metrics_)
            metrics_->counter("yuzu_app_perf_version_devices_cap_hit_total", {}).increment();
        spdlog::warn("AppPerfDailyStore: list_devices_for_version hit the {}-row cap for "
                     "app='{}' version='{}' — the device list is truncated to the highest-CPU "
                     "devices",
                     kVersionDevicesRowCap, app_name, version);
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfVersionDeviceRow r;
        r.agent_id = PQgetvalue(res.get(), i, 0);
        r.last_day = to_i64(PQgetvalue(res.get(), i, 1));
        r.samples = to_i64(PQgetvalue(res.get(), i, 2));
        r.cpu_avg = to_double(PQgetvalue(res.get(), i, 3));
        r.ws_avg_bytes = to_i64(PQgetvalue(res.get(), i, 4));
        out.push_back(std::move(r));
    }
    return out;
}

bool AppPerfDailyStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::debug("AppPerfDailyStore: delete_agent skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM app_perf_daily_store.app_perf_daily WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("AppPerfDailyStore: delete_agent failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

} // namespace yuzu::server
