#include "dex_app_usage_owner.hpp"

#include "guaranteed_state_store.hpp" // kDexAppsConcurrentReads (the budget pin below)
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

// A request-path read: a short bounded acquire and a short statement bound, so a
// saturated pool or a slow plan degrades to a typed failure instead of holding a
// web worker.
constexpr std::chrono::milliseconds kAcquireTimeout{3000};

// The metric source for this owner's faults; the reasons are dex_read_fault_token().
constexpr const char* kDegradeSource = "dex_usage";

// A usage request also takes one Apps stability read slot (the Apps store's budget), so this
// owner's own budget can never be wider than that one.
static_assert(kDexUsageConcurrentReads <= GuaranteedStateStore::kDexAppsConcurrentReads,
              "the usage read budget must not exceed the Apps read budget");

// Result discriminator (column 0) and column use:
//   0 = a usage cell:  c1 subject, c2 cell, c3 devices, c4 exact, c5 trunc, c6 launches, c7 seconds
//   1 = event counts:  c1 subject, c2 crashes, c3 hangs
//   2 = coverage:      c1 fresh devices, c2 stale devices
//
// pop: the asked-about devices with their cell and platform. Agent ids must be
// unique: a repeated id repeats its rows in every sum and in the coverage counts
// (no DISTINCT here, so this population stays the same list the Apps read took
// at face value). st: those with a usage_state row, `fresh` against the server
// receipt time. m: the match keys.
// mu: usage rows of FRESH devices that match a key (an exact key matches any
// device; a trunc key only a Linux one), with the agent-reported values clamped.
// agent_last_used is keyed (agent_id, exe_key) and a subject's exact key never
// equals its trunc key (over 15 bytes against 15), so one stored row joins at
// most one key of a subject: a device matching through both keys has two
// different stored rows, each summed once (the device is counted once by
// COUNT(DISTINCT agent_id)).
// ev: crash and hang observations of the raw subject, cut at BOTH ends (the same
// as dex_app_version_failures_owner.cpp), kept only when the same device freshly
// reports usage for the same subject (an EXISTS over mu), so the events, the
// usage totals and the reporting count are one population by construction.
// Crashes and hangs are RAW counts, as in the Apps rate per 1,000 devices; the
// per-device cap applies to the Apps stability score only. Events clustered on one
// crash-looping device make the interval falsely narrow (the consumer duty at
// dex_stats.hpp).
// ponytail: no exe_key index on agent_last_used, so the usage side is a filtered
// scan bounded by the statement timeout; add an index (a migration) only when a
// measured fleet nears that bound. Past the bound every request times out; after
// kDexUsageTimeoutsBeforeTooLarge in a row over kDexUsageTimeoutRunBeforeTooLarge
// the owner reports fleet_too_large (not retryable) until the index or a
// precomputed rollup exists; the fleet size at which that happens has not been
// measured. The result is bounded by the caller's subject and cell counts (one row
// per application and cell, one per application, one coverage row).
const std::string& read_sql() {
    static const std::string sql =
        "WITH pop AS ("
        " SELECT p.agent_id, p.cell, p.is_linux"
        " FROM unnest($1::text[], $2::int[], $3::bool[]) AS p(agent_id, cell, is_linux)), "
        "st AS ("
        " SELECT pop.agent_id, pop.cell, pop.is_linux,"
        "  (us.last_seen >= to_timestamp($10::bigint)) AS fresh"
        " FROM pop JOIN app_usage_store.usage_state us ON us.agent_id = pop.agent_id), "
        "m AS ("
        " SELECT k.subject, k.match_key, k.is_trunc"
        " FROM unnest($4::int[], $5::text[], $6::bool[]) AS k(subject, match_key, is_trunc)), "
        "mu AS ("
        " SELECT m.subject, st.agent_id, st.cell, m.is_trunc,"
        "  GREATEST(0::bigint, LEAST(a.run_count_30d, " +
        std::to_string(kDexUsageRowLaunchesCap) +
        "::bigint)) AS launches,"
        "  GREATEST(0::bigint, LEAST(a.total_seconds_30d, " +
        std::to_string(kDexUsageRowSecondsCap) +
        "::bigint)) AS seconds"
        " FROM st"
        " JOIN app_usage_store.agent_last_used a ON a.agent_id = st.agent_id"
        " JOIN m ON m.match_key = a.exe_key AND (NOT m.is_trunc OR st.is_linux)"
        " WHERE st.fresh), "
        "ev AS ("
        " SELECT (s.idx - 1)::int AS subject, o.obs_type, o.agent_id"
        " FROM unnest($7::text[]) WITH ORDINALITY AS s(subject, idx)"
        " JOIN guaranteed_state_store.guardian_observations o ON o.subject = s.subject"
        " WHERE o.obs_type IN ('process.crashed', 'process.hung')"
        "   AND o.observed_at >= $8 AND o.observed_at < $9"
        "   AND EXISTS (SELECT 1 FROM mu WHERE mu.subject = (s.idx - 1)::int"
        "               AND mu.agent_id = o.agent_id)) "
        "SELECT 0::bigint, subject::bigint, cell::bigint, COUNT(DISTINCT agent_id),"
        " COUNT(DISTINCT agent_id) FILTER (WHERE NOT is_trunc),"
        " COUNT(DISTINCT agent_id) FILTER (WHERE is_trunc),"
        " SUM(launches)::bigint, SUM(seconds)::bigint"
        " FROM mu GROUP BY subject, cell "
        "UNION ALL "
        "SELECT 1::bigint, subject::bigint,"
        " COUNT(*) FILTER (WHERE obs_type = 'process.crashed'),"
        " COUNT(*) FILTER (WHERE obs_type = 'process.hung'),"
        " 0::bigint, 0::bigint, 0::bigint, 0::bigint"
        " FROM ev GROUP BY subject "
        "UNION ALL "
        "SELECT 2::bigint, COUNT(*) FILTER (WHERE fresh), COUNT(*) FILTER (WHERE NOT fresh),"
        " 0::bigint, 0::bigint, 0::bigint, 0::bigint, 0::bigint"
        " FROM st";
    return sql;
}

std::int64_t col_i64(PGresult* res, int row, int col) {
    const char* s = PQgetvalue(res, row, col);
    return s == nullptr || s[0] == '\0' ? 0 : static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// An array literal "{tok,tok,...}" ("{}" when empty) for tokens that need no quoting:
// integers and t/f. Text never goes through here; it stays on pg::to_text_array,
// which escapes (trust boundary).
template <typename Range, typename Token>
std::string array_literal(const Range& items, Token token) {
    std::string out = "{";
    const char* sep = "";
    for (const auto& item : items) {
        out += sep;
        out += token(item);
        sep = ",";
    }
    out.push_back('}');
    return out;
}

std::vector<std::string_view> views(const std::vector<std::string>& v) {
    return std::vector<std::string_view>(v.begin(), v.end());
}

} // namespace

DexAppUsageOwner::DexAppUsageOwner(pg::PgPool& pool, yuzu::MetricsRegistry* metrics, int concurrent_reads,
                                   std::chrono::milliseconds statement_timeout)
    : pool_(pool), metrics_(metrics), budget_(concurrent_reads), statement_timeout_(statement_timeout) {}

const char* DexAppUsageOwner::unavailable_detail(DexReadFault f,
                                                 std::chrono::steady_clock::time_point now) const {
    int count = 0;
    std::int64_t start = 0;
    {
        std::lock_guard lock(run_mu_);
        count = consecutive_timeouts_;
        start = timeout_run_start_;
    }
    const auto age = start == 0 ? std::chrono::steady_clock::duration::zero()
                                : now.time_since_epoch() - std::chrono::steady_clock::duration(start);
    return dex_usage_unavailable_detail(f, count, age);
}

std::unexpected<DexReadFault> DexAppUsageOwner::fault(DexReadFault f) const {
    const char* reason = dex_read_fault_token(f);
    if (metrics_)
        metrics_->counter("yuzu_server_guardian_read_degrade_total",
                          {{"reason", reason}, {"source", kDegradeSource}})
            .increment();
    // The counter is the continuous signal; the log is a sampled breadcrumb. The text names no
    // subject, agent or tag.
    if (log_throttle_.should_warn(reason))
        spdlog::warn("DexAppUsageOwner: read degraded: {}", reason);
    else
        spdlog::debug("DexAppUsageOwner: read degraded: {}", reason);
    return std::unexpected(f);
}

std::expected<DexUsageRead, DexReadFault> DexAppUsageOwner::read(const DexUsageQuery& q) const {
    if (q.devices.empty())
        return DexUsageRead{};

    // The caller's indices are checked here, so a bad one never reaches the statement.
    for (const auto& d : q.devices)
        if (d.cell < 0 || d.cell >= q.cell_count)
            return fault(DexReadFault::kQueryError);
    for (const auto& k : q.keys)
        if (k.subject < 0 || static_cast<std::size_t>(k.subject) >= q.subjects.size())
            return fault(DexReadFault::kQueryError);

    // A refused caller holds its increment until it returns, so a burst can refuse a few reads
    // more than necessary for an instant; the refusal is retryable and the budget is never exceeded.
    struct Slot {
        std::atomic<int>& n;
        ~Slot() { n.fetch_sub(1); }
    };
    const Slot slot{in_flight_};
    if (in_flight_.fetch_add(1) >= budget_)
        return fault(DexReadFault::kConcurrencyBudget);

    // Views into `q`, which outlives this call.
    std::vector<std::string_view> ids, key_text;
    ids.reserve(q.devices.size());
    key_text.reserve(q.keys.size());
    for (const auto& d : q.devices)
        ids.emplace_back(d.agent_id);
    for (const auto& k : q.keys)
        key_text.emplace_back(k.key);

    std::vector<std::optional<std::string>> params{
        pg::to_text_array(ids),
        array_literal(q.devices, [](const DexUsageDevice& d) { return std::to_string(d.cell); }),
        array_literal(q.devices, [](const DexUsageDevice& d) { return d.is_linux ? "t" : "f"; }),
        array_literal(q.keys, [](const DexUsageKey& k) { return std::to_string(k.subject); }),
        pg::to_text_array(key_text),
        array_literal(q.keys, [](const DexUsageKey& k) { return k.trunc ? "t" : "f"; }),
        pg::to_text_array(views(q.subjects)),
        q.since_iso,
        q.until_iso,
        std::to_string(q.fresh_since_epoch)};
    const std::string set_timeout =
        "SET LOCAL statement_timeout = '" + std::to_string(statement_timeout_.count()) + "ms'";

    std::optional<DexUsageRead> out;
    std::optional<DexReadFault> statement_fault;
    // Never names a subject or an agent: both are caller-supplied text.
    const auto fail = [&statement_fault](const pg::PgResult& res) {
        const char* state = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        statement_fault = dex_usage_fault_from_sqlstate(state);
        spdlog::debug("DexAppUsageOwner: statement failed, SQLSTATE {}", state != nullptr ? state : "unknown");
        return false;
    };
    // Acquire first, then run the transaction on that lease with nothing in between (the
    // with_txn_on contract), so an acquire timeout and a failed transaction are told apart.
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease)
        return fault(DexReadFault::kPoolTimeout);
    const bool ok = pool_.with_txn_on(std::move(lease), [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, set_timeout.c_str(), std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return fail(t);
        pg::PgResult r = pg::exec_params(c, read_sql().c_str(), params);
        if (r.status() != PGRES_TUPLES_OK)
            return fail(r);
        DexUsageRead rd;
        const int n = PQntuples(r.get());
        for (int i = 0; i < n; ++i) {
            switch (col_i64(r.get(), i, 0)) {
            case 0:
                rd.cells.push_back({static_cast<int>(col_i64(r.get(), i, 1)),
                                    static_cast<int>(col_i64(r.get(), i, 2)),
                                    col_i64(r.get(), i, 3), col_i64(r.get(), i, 4),
                                    col_i64(r.get(), i, 5), col_i64(r.get(), i, 6),
                                    col_i64(r.get(), i, 7)});
                break;
            case 1:
                rd.events.push_back({static_cast<int>(col_i64(r.get(), i, 1)),
                                     col_i64(r.get(), i, 2), col_i64(r.get(), i, 3)});
                break;
            case 2:
                rd.reporting_devices = col_i64(r.get(), i, 1);
                rd.stale_devices = col_i64(r.get(), i, 2);
                break;
            default:
                break;
            }
        }
        out = std::move(rd);
        return true;
    });
    if (!ok || !out) {
        // A false return with no statement failure is a failed BEGIN or COMMIT: a query error,
        // never a pool timeout (the lease was acquired).
        const DexReadFault f = statement_fault.value_or(DexReadFault::kQueryError);
        if (f == DexReadFault::kStatementTimeout) {
            // The first timeout of an unbroken run stamps its start; the run is cleared by a success.
            const std::int64_t now = std::max<std::int64_t>(
                1, std::chrono::steady_clock::now().time_since_epoch().count());
            std::lock_guard lock(run_mu_);
            ++consecutive_timeouts_;
            if (timeout_run_start_ == 0)
                timeout_run_start_ = now;
        }
        return fault(f);
    }
    {
        std::lock_guard lock(run_mu_);
        consecutive_timeouts_ = 0;
        timeout_run_start_ = 0;
    }
    return std::move(*out);
}

} // namespace yuzu::server
