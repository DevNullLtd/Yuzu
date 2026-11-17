#include "dex_app_usage_owner.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

// A request-path read: a short bounded acquire and a short statement bound, so a
// saturated pool or a slow plan degrades to a typed failure instead of holding a
// web worker.
constexpr std::chrono::milliseconds kAcquireTimeout{3000};
constexpr const char* kStatementTimeout = "10s";

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
// scan bounded by the 10 s statement timeout; add an index (a migration) only when
// a measured fleet nears that bound. Past the bound every request times out, so the
// model reads usage_unavailable on every request until the index exists; the fleet
// size at which that happens has not been measured. The result is bounded by the
// caller's subject and cell counts (one row per application and cell, one per
// application, one coverage row).
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

DexAppUsageOwner::DexAppUsageOwner(pg::PgPool& pool) : pool_(pool) {}

std::optional<DexUsageRead> DexAppUsageOwner::read(const DexUsageQuery& q) const {
    if (q.devices.empty())
        return DexUsageRead{};

    // The caller's indices are checked here, so a bad one never reaches the statement.
    // The warning names no subject and no agent.
    for (const auto& d : q.devices)
        if (d.cell < 0 || d.cell >= q.cell_count) {
            spdlog::warn("DexAppUsageOwner: a device cell index is out of range");
            return std::nullopt;
        }
    for (const auto& k : q.keys)
        if (k.subject < 0 || static_cast<std::size_t>(k.subject) >= q.subjects.size()) {
            spdlog::warn("DexAppUsageOwner: a key subject index is out of range");
            return std::nullopt;
        }

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

    std::optional<DexUsageRead> out;
    bool statement_failed = false;
    // Never names a subject or an agent: both are caller-supplied text.
    const auto fail = [&statement_failed](const pg::PgResult& res) {
        statement_failed = true;
        const char* state = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        spdlog::warn("DexAppUsageOwner: statement failed, SQLSTATE {}",
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
        if (!statement_failed)
            spdlog::warn("DexAppUsageOwner: pool acquire timed out or transaction not committed");
        return std::nullopt;
    }
    return out;
}

} // namespace yuzu::server
