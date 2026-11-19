/// @file certificate_inventory_read.cpp
/// The READ half of CertificateInventoryStore (slice-2 PR 2a-2b): the per-certificate page, the
/// raw-value summary and the fleet store-status rollup. See certificate_inventory_store.hpp for
/// the contract; the schema and the write path are in certificate_inventory_store.cpp.
///
/// Every filter value is BOUND, never spliced. The visible-device set is pushed into every
/// statement as `agent_id = ANY($n::text[])` (present-empty answers with no SQL at all). Every
/// read is one REPEATABLE READ transaction, so a page and its children (SANs, EKUs, locations,
/// store statuses) are ONE snapshot.
///
/// WALL DEADLINE. `statement_timeout` bounds ONE statement, and a read runs several. So the whole
/// transaction carries a steady_clock budget (`kReadTxnBudget`): before EVERY statement `run()`
/// re-sets `statement_timeout` to the budget that remains, and a statement started with none left
/// fails the read (a 503 upstream; a SUMMARY's, a non-retryable scale limit). One transaction
/// therefore holds its pool lease and the vacuum horizon for at most the budget plus one round trip,
/// however many statements it needs. A page makes TWO transactions (the page, then the coverage
/// denominator), so a page request holds its admission slot for at most two budgets; a summary is one. (No reliance on `transaction_timeout`, which needs PG17+.)

#include "certificate_inventory_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

constexpr std::chrono::milliseconds kReadAcquireTimeout{3000};
/// The whole-transaction wall budget of a certificate read (design "Truncation": 30 s for the
/// heavier snapshot export; a page or a rollup is bounded tighter).
constexpr std::chrono::milliseconds kReadTxnBudget{15000};

/// The deadline of the transaction running on THIS thread (set by `bounded`, read by `run`).
thread_local std::chrono::steady_clock::time_point t_txn_deadline{};
/// The failing statement's SQLSTATE and whether it was a timeout (set by `run`, drained by `bounded`).
thread_local std::string t_sqlstate;
thread_local bool t_timed_out = false;

/// A timestamptz column as RFC 3339 UTC to the second (year 9999 and pre-1970 included).
std::string fmt(std::string_view col) {
    return "to_char(" + std::string(col) +
           " AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";
}

struct SqlParams {
    std::vector<std::string> values;
    /// Bind `v` and return its placeholder (`$n`) with an explicit cast.
    std::string add(std::string v, const char* cast) {
        values.push_back(std::move(v));
        return "$" + std::to_string(values.size()) + cast;
    }
};

/// The LIKE-literal form of a substring: `\`, `%` and `_` escaped (matched with ESCAPE '\').
std::string like_literal(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (const char c : s) {
        if (c == '\\' || c == '%' || c == '_')
            out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

std::optional<std::string> cell(const pg::PgResult& r, int row, int col) {
    if (PQgetisnull(r.get(), row, col))
        return std::nullopt;
    return std::string(PQgetvalue(r.get(), row, col),
                       static_cast<std::size_t>(PQgetlength(r.get(), row, col)));
}

std::string cell_s(const pg::PgResult& r, int row, int col) {
    return cell(r, row, col).value_or(std::string{});
}

std::optional<int> cell_int(const pg::PgResult& r, int row, int col) {
    const auto v = cell(r, row, col);
    if (!v)
        return std::nullopt;
    int n = 0;
    const auto fc = std::from_chars(v->data(), v->data() + v->size(), n);
    if (fc.ec != std::errc{})
        return std::nullopt; // an unparsable integer is UNKNOWN, never a fabricated 0
    return n;
}

std::int64_t cell_i64(const pg::PgResult& r, int row, int col) {
    const auto v = cell(r, row, col);
    std::int64_t n = 0;
    if (v)
        std::from_chars(v->data(), v->data() + v->size(), n);
    return n;
}

std::optional<bool> cell_bool(const pg::PgResult& r, int row, int col) {
    const auto v = cell(r, row, col);
    if (!v)
        return std::nullopt;
    return *v == "t" || *v == "true";
}

/// The WHERE clause shared by the page and every summary statement: the scope push-down, then
/// each present filter. Always a syntactically complete clause (starts " WHERE TRUE").
/// The distinct DNs a substring filter matched in the dictionary, resolved FIRST (one cheap statement
/// over thousands of rows) and then bound as an array, so the planner sees the real element count and
/// picks the btree on issuer_dn / subject_dn (a correlated sub-select makes it walk the primary key
/// and probe the dictionary per row - measured 14 s for a rare name).
struct DnMatches {
    std::optional<std::vector<std::string>> issuer, subject;
};
constexpr std::size_t kMaxDnMatches = 20000;
/// At or below this many matching rows a substring page is materialised and sorted (see list_certificates).
constexpr std::size_t kSelectiveMatches = 5000;
thread_local bool t_too_broad = false;

std::string filter_where(const CertReadFilter& f, const CertScopeIds& scope, SqlParams& sp,
                         const DnMatches& dn) {
    std::string w = " WHERE TRUE";
    if (scope) {
        std::vector<std::string_view> ids(scope->begin(), scope->end());
        w += " AND f.agent_id = ANY(" + sp.add(pg::to_text_array(ids), "::text[]") + ")";
    }
    const auto eq = [&](const std::optional<std::string>& v, const char* col) {
        if (v)
            w += std::string(" AND ") + col + " = " + sp.add(*v, "::text");
    };
    if (f.store)
        w += " AND EXISTS (SELECT 1 FROM certificate_inventory_store.cert_location l WHERE "
             "l.agent_id = f.agent_id AND l.sha256 = f.sha256 AND l.store_id = " +
             sp.add(*f.store, "::text") + ")";
    if (f.scope)
        w += " AND EXISTS (SELECT 1 FROM certificate_inventory_store.cert_location l JOIN "
             "certificate_inventory_store.store_state ss ON ss.agent_id = l.agent_id AND ss.store_id = "
             "l.store_id AND ss.user_ref = l.user_ref WHERE l.agent_id = f.agent_id AND "
             "l.sha256 = f.sha256 AND ss.scope = " +
             sp.add(*f.scope, "::text") + ")";
    eq(f.key_alg_oid, "f.key_alg_oid");
    eq(f.sig_alg_oid, "f.sig_alg_oid");
    eq(f.ec_curve_oid, "f.ec_curve_oid");
    if (f.not_after_before)
        w += " AND f.not_after < " + sp.add(*f.not_after_before, "::timestamptz");
    if (f.not_after_after)
        w += " AND f.not_after > " + sp.add(*f.not_after_after, "::timestamptz");
    if (f.not_before_after)
        w += " AND f.not_before > " + sp.add(*f.not_before_after, "::timestamptz");
    if (f.rsa_modulus_bits_lt)
        w += " AND f.rsa_modulus_bits < " + sp.add(std::to_string(*f.rsa_modulus_bits_lt), "::int");
    if (f.ec_order_bits_lt)
        w += " AND f.ec_order_bits < " + sp.add(std::to_string(*f.ec_order_bits_lt), "::int");
    if (f.is_ca)
        w += " AND f.is_ca = " + sp.add(*f.is_ca ? "true" : "false", "::boolean");
    if (f.self_signed)
        w += " AND f.self_signed = " + sp.add(*f.self_signed ? "true" : "false", "::boolean");
    eq(f.agent_id, "f.agent_id");
    eq(f.issuer_dn, "f.issuer_dn");
    // The substring filters were resolved through the DISTINCT-DN dictionary (see DnMatches); they
    // reach cert_fact through the plain btrees on the DN. An empty match set matches nothing.
    const auto dns = [&](const std::optional<std::vector<std::string>>& m, const char* col) {
        if (!m)
            return;
        std::vector<std::string_view> v(m->begin(), m->end());
        w += std::string(" AND ") + col + " = ANY(" + sp.add(pg::to_text_array(v), "::text[]") + ")";
    };
    dns(dn.issuer, "f.issuer_dn");
    dns(dn.subject, "f.subject_dn");
    eq(f.sha256, "f.sha256");
    eq(f.spki_sha256, "f.spki_sha256");
    eq(f.aki_key_id, "f.aki_key_id");
    return w;
}

CertReadError fail(CertReadError::Kind k, std::string m) { return CertReadError{k, std::move(m)}; }

/// A read that ran out of time (SQLSTATE 57014, or the armed wall deadline elapsed - never English
/// text, which follows lc_messages). A SUMMARY's cost grows with the visible fleet, so its timeout
/// is a scale limit (non-retryable); a page's is an ordinary retryable degrade.
CertReadError as_summary_failure(CertReadError e) {
    if (e.kind == CertReadError::Kind::kQueryError && e.timed_out) {
        e.kind = CertReadError::Kind::kScaleLimit;
        e.message = "the summary exceeded its read budget for this many devices; narrow it with "
                    "agent_id, store or another filter (the fleet-wide counts are a later release)";
    }
    return e;
}

CertReadError substring_refusal(SubstringState st) {
    if (st == SubstringState::kReconciling) {
        // A wait that is EXPECTED (a restart, a leader change): retryable, with an honest estimate.
        auto e = fail(CertReadError::Kind::kQueryError,
                      "the substring filters (issuer_dn_contains, subject_dn_contains) are not yet "
                      "reconciled after a server start; this clears by itself - seconds on a "
                      "steady store, a couple of minutes at fleet scale when the indexes must be "
                      "built - retry");
        e.reconciling = true;
        return e;
    }
    if (st == SubstringState::kFailedTransient) {
        // The last background pass failed on a cause that clears by itself and is retried by the
        // leader. Retryable with the pass interval; the database error text is never echoed.
        auto e = fail(CertReadError::Kind::kQueryError,
                      "the substring filters (issuer_dn_contains, subject_dn_contains) are "
                      "temporarily unavailable: the last background reconcile failed on a transient "
                      "cause and is retried automatically; retry later");
        e.reconciling = true;
        e.transient_failure = true;
        e.retry_hint_ms = CertificateInventoryStore::kPassIntervalMs;
        return e;
    }
    return fail(CertReadError::Kind::kSubstringIndexMissing,
                "the substring filters (issuer_dn_contains, subject_dn_contains) are unavailable: "
                "the distinct-DN dictionary behind them is not built; see server-admin.md "
                "\"The substring-filter dictionary\", or filter with issuer_dn / agent_id instead");
}

/// A subject substring is only ever searched among CA certificates (design "Finding one CA's
/// certificates"): defence in depth behind the model's parameter check.
bool filter_invalid(const CertReadFilter& f) {
    return f.subject_dn_contains && !(f.is_ca && *f.is_ca);
}

/// Run `fn` in one REPEATABLE READ transaction with a wall `budget` (see the file banner). `fn`
/// returns false on a SQL fault. Distinguishes "never got a connection" (kPoolAcquireTimeout), a
/// transaction that could not begin or commit, and a query fault or deadline (kQueryError).
template <class Fn>
std::optional<CertReadError> bounded(pg::PgPool& pool, const char* what, Fn&& fn,
                                     std::chrono::milliseconds acquire = kReadAcquireTimeout,
                                     std::chrono::milliseconds budget = kReadTxnBudget) {
    auto lease = pool.try_acquire_for(acquire);
    if (!lease) {
        spdlog::warn("CertificateInventoryStore: {} degraded - {}", what, pool.last_error());
        return fail(CertReadError::Kind::kPoolAcquireTimeout, pool.last_error());
    }
    bool entered = false;
    std::string err;
    t_too_broad = false;
    t_sqlstate.clear(); // a throw out of an earlier read must not leak its state into this one
    t_timed_out = false;
    // The clock starts once the lease is held (an acquire wait has its own bound).
    const auto deadline = std::chrono::steady_clock::now() + budget;
    const bool ok = pool.with_txn_on(std::move(lease), [&](PGconn* c) -> bool {
        entered = true;
        t_txn_deadline = deadline;
        pg::PgResult t = pg::exec_params(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        return fn(c, err);
    });
    t_txn_deadline = {};
    const std::string sqlstate = std::exchange(t_sqlstate, {});
    const bool timed_out = std::exchange(t_timed_out, false);
    if (ok)
        return std::nullopt;
    spdlog::warn("CertificateInventoryStore: {} degraded - {} (sqlstate={})", what,
                 entered ? err : "transaction did not begin", sqlstate);
    auto e = fail(CertReadError::Kind::kQueryError, entered ? err : "transaction did not begin");
    if (std::exchange(t_too_broad, false)) {
        e.kind = CertReadError::Kind::kInvalid; // caller input: lengthen the substring
        e.message = "the substring matches more than " + std::to_string(kMaxDnMatches) +
                    " distinct names; make it longer";
    }
    e.sqlstate = sqlstate;
    e.timed_out = timed_out;
    return e;
}

/// One statement inside `bounded`: re-sets `statement_timeout` to the wall budget that remains,
/// and fails (without sending the statement) when none is left.
pg::PgResult run(PGconn* c, const std::string& sql, const std::vector<std::string>& params,
                 std::string& err) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        t_txn_deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) {
        err = "read deadline exceeded";
        t_timed_out = true;
        return pg::PgResult{};
    }
    pg::PgResult t = pg::exec_params(
        c, ("SET LOCAL statement_timeout = " + std::to_string(left.count())).c_str(),
        std::vector<std::string>{});
    if (t.status() != PGRES_COMMAND_OK) {
        err = PQerrorMessage(c);
        return pg::PgResult{};
    }
    pg::PgResult r = pg::exec_params(c, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        if (const char* st = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE)) {
            t_sqlstate = st;
            t_timed_out = t_sqlstate == "57014"; // query_canceled: the statement_timeout we armed
        }
    }
    return r;
}

/// Resolve the substring filters against the dictionary (inside the read's transaction, so it is part of
/// the same snapshot and wall budget). false on a SQL fault or when a substring matches more than
/// kMaxDnMatches distinct names (a caller-input refusal: make the substring longer).
bool resolve_dns(PGconn* c, const CertReadFilter& f, DnMatches& out, std::string& err) {
    const auto one = [&](const std::optional<std::string>& sub, const char* role,
                         std::optional<std::vector<std::string>>& dst) {
        if (!sub)
            return true;
        pg::PgResult r = run(c,
                             std::string("SELECT dn FROM certificate_inventory_store.dn_dict WHERE ") + role +
                                 " AND dn ILIKE '%' || $1::text || '%' ESCAPE '\\' ORDER BY dn LIMIT " +
                                 std::to_string(kMaxDnMatches + 1),
                             {like_literal(*sub)}, err);
        if (r.status() != PGRES_TUPLES_OK)
            return false;
        const int n = PQntuples(r.get());
        if (static_cast<std::size_t>(n) > kMaxDnMatches) {
            t_too_broad = true;
            err = "the substring matches too many distinct names";
            return false;
        }
        std::vector<std::string> v;
        v.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i)
            v.push_back(cell_s(r, i, 0));
        dst = std::move(v);
        return true;
    };
    return one(f.issuer_dn_contains, "is_issuer", out.issuer) &&
           one(f.subject_dn_contains, "is_ca_subject", out.subject);
}

// The cert_fact columns of one page row, in this order (read by index below).
const std::string& page_columns() {
    static const std::string cols =
        "f.agent_id, f.sha256, f.sha1, f.tbs_sha256, f.serial, f.subject_dn, f.issuer_dn, " +
        fmt("f.not_before") + ", " + fmt("f.not_after") +
        ", f.key_alg_oid, f.rsa_modulus_bits, f.ec_curve_oid, f.ec_order_bits, f.sig_alg_oid, "
        "f.pss_hash_oid, f.spki_sha256, f.ski, f.aki_key_id, f.is_ca, f.path_len, f.self_signed, "
        "f.key_usage, f.key_association, f.key_provider, f.key_exportable, f.constrained_fields";
    return cols;
}

// The same columns, raw, for the selective path's materialised CTE: an explicit list so the
// per-agent `sample_key` (and any future internal column) can never ride out through `SELECT *`.
const std::string& page_source_columns() {
    static const std::string cols =
        "agent_id, sha256, sha1, tbs_sha256, serial, subject_dn, issuer_dn, not_before, not_after, "
        "key_alg_oid, rsa_modulus_bits, ec_curve_oid, ec_order_bits, sig_alg_oid, pss_hash_oid, "
        "spki_sha256, ski, aki_key_id, is_ca, path_len, self_signed, key_usage, key_association, "
        "key_provider, key_exportable, constrained_fields";
    return cols;
}

CertReadRow row_from(const pg::PgResult& r, int i) {
    CertReadRow o;
    o.agent_id = cell_s(r, i, 0);
    o.sha256 = cell_s(r, i, 1);
    o.sha1 = cell(r, i, 2);
    o.tbs_sha256 = cell(r, i, 3);
    o.serial = cell(r, i, 4);
    o.subject_dn = cell(r, i, 5);
    o.issuer_dn = cell(r, i, 6);
    o.not_before = cell(r, i, 7);
    o.not_after = cell(r, i, 8);
    o.key_alg_oid = cell(r, i, 9);
    o.rsa_modulus_bits = cell_int(r, i, 10);
    o.ec_curve_oid = cell(r, i, 11);
    o.ec_order_bits = cell_int(r, i, 12);
    o.sig_alg_oid = cell(r, i, 13);
    o.pss_hash_oid = cell(r, i, 14);
    o.spki_sha256 = cell(r, i, 15);
    o.ski = cell(r, i, 16);
    o.aki_key_id = cell(r, i, 17);
    o.is_ca = cell_bool(r, i, 18);
    o.path_len = cell_int(r, i, 19);
    o.self_signed = cell_bool(r, i, 20);
    o.key_usage = cell(r, i, 21);
    o.key_association = cell(r, i, 22);
    o.key_provider = cell(r, i, 23);
    o.key_exportable = cell(r, i, 24);
    o.constrained_fields = cell_s(r, i, 25);
    return o;
}

using RowKey = std::pair<std::string, std::string>; // (agent_id, sha256)

} // namespace

std::expected<CertPage, CertReadError>
CertificateInventoryStore::list_certificates(const CertReadFilter& filter, const CertScopeIds& scope,
                                             const std::optional<CertReadAfter>& after, int limit) {
    if (!open_)
        return std::unexpected(fail(CertReadError::Kind::kNotOpen, "store not open"));
    if (filter_invalid(filter) || limit < 1 || limit > kCertPageMax)
        return std::unexpected(fail(CertReadError::Kind::kInvalid, "invalid certificate read"));
    if ((filter.issuer_dn_contains || filter.subject_dn_contains) && !substring_index_available())
        return std::unexpected(substring_refusal(substring_state()));
    CertPage page;
    page.coverage.confined = scope.has_value();
    if (scope && scope->empty()) // present-empty = deny-all: no SQL, never "no filter"
        return page;

    const auto err = bounded(pool_, "list_certificates", [&](PGconn* c, std::string& e) -> bool {
        DnMatches dn;
        if (!resolve_dns(c, filter, dn, e))
            return false;
        // A substring filter that resolved to a handful of names matches few rows, but the planner
        // (n_distinct is underestimated on a skewed DN column) can still choose to WALK the primary
        // key to satisfy ORDER BY .. LIMIT and filter 4M+ rows - measured past the 15 s budget for 10
        // rare names. So: probe the match count (bounded, btree), and when it is small materialise the
        // matches first and sort THEM. A broad match keeps the primary-key walk, which is right for it.
        bool selective = false;
        if (dn.issuer || dn.subject) {
            SqlParams pp;
            const std::string probe =
                "SELECT count(*) FROM (SELECT 1 FROM certificate_inventory_store.cert_fact f" +
                filter_where(filter, scope, pp, dn) + " LIMIT " + std::to_string(kSelectiveMatches + 1) +
                ") x";
            pg::PgResult pr = run(c, probe, pp.values, e);
            if (pr.status() != PGRES_TUPLES_OK || PQntuples(pr.get()) != 1)
                return false;
            selective = cell_i64(pr, 0, 0) <= static_cast<std::int64_t>(kSelectiveMatches);
        }
        SqlParams sp;
        const std::string base_where = filter_where(filter, scope, sp, dn);
        std::string page_where;
        if (after)
            page_where = std::string(selective ? " WHERE " : " AND ") + "(f.agent_id, f.sha256) > (" +
                         sp.add(after->agent_id, "::text") + ", " + sp.add(after->sha256, "::text") + ")";
        const std::string sql =
            selective ? "WITH f AS MATERIALIZED (SELECT " + page_source_columns() +
                            " FROM certificate_inventory_store.cert_fact f" + base_where + ") SELECT " +
                            page_columns() + " FROM f" + page_where +
                            " ORDER BY f.agent_id, f.sha256 LIMIT " + sp.add(std::to_string(limit + 1), "::int")
                      : "SELECT " + page_columns() + " FROM certificate_inventory_store.cert_fact f" +
                            base_where + page_where + " ORDER BY f.agent_id, f.sha256 LIMIT " +
                            sp.add(std::to_string(limit + 1), "::int");
        pg::PgResult rows = run(c, sql, sp.values, e);
        if (rows.status() != PGRES_TUPLES_OK)
            return false;
        const int n = PQntuples(rows.get());
        page.has_more = n > limit;
        const int take = std::min(n, limit);
        std::map<RowKey, std::size_t> index;
        std::set<std::string> agents;
        std::vector<std::string_view> k_agent, k_sha;
        for (int i = 0; i < take; ++i) {
            page.rows.push_back(row_from(rows, i));
            const auto& r = page.rows.back();
            index.emplace(RowKey{r.agent_id, r.sha256}, page.rows.size() - 1);
            agents.insert(r.agent_id);
        }
        if (page.rows.empty())
            return true;
        for (const auto& r : page.rows) {
            k_agent.emplace_back(r.agent_id);
            k_sha.emplace_back(r.sha256);
        }
        const std::vector<std::string> kp = {pg::to_text_array(k_agent), pg::to_text_array(k_sha)};

        // SANs and EKUs, in stored order.
        pg::PgResult sans = run(
            c,
            "SELECT s.agent_id, s.sha256, s.san_type, s.value FROM certificate_inventory_store.cert_san s JOIN "
            "unnest($1::text[], $2::text[]) AS k(agent_id, sha256) ON s.agent_id = k.agent_id AND "
            "s.sha256 = k.sha256 ORDER BY s.agent_id, s.sha256, s.ord",
            kp, e);
        if (sans.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(sans.get()); ++i) {
            const auto it = index.find({cell_s(sans, i, 0), cell_s(sans, i, 1)});
            if (it == index.end())
                continue; // a child of a row outside the page snapshot: never a bare exception
            auto& r = page.rows[it->second];
            if (r.sans.size() >= kCertReadMaxSans) {
                r.sans_truncated = true;
                continue;
            }
            r.sans.push_back({cell_s(sans, i, 2), cell_s(sans, i, 3)});
        }
        pg::PgResult ekus = run(
            c,
            "SELECT s.agent_id, s.sha256, s.oid FROM certificate_inventory_store.cert_eku s JOIN "
            "unnest($1::text[], $2::text[]) AS k(agent_id, sha256) ON s.agent_id = k.agent_id AND "
            "s.sha256 = k.sha256 ORDER BY s.agent_id, s.sha256, s.ord",
            kp, e);
        if (ekus.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(ekus.get()); ++i)
            if (const auto it = index.find({cell_s(ekus, i, 0), cell_s(ekus, i, 1)}); it != index.end())
                page.rows[it->second].ekus.push_back(cell_s(ekus, i, 2));

        // Locations with the status of the store each sits in.
        pg::PgResult locs = run(
            c,
            "SELECT l.agent_id, l.sha256, l.store_id, l.path, COALESCE(ss.status, 'not_observed'), " +
                fmt("ss.observed_at") + ", " + fmt("l.last_seen") +
                " FROM certificate_inventory_store.cert_location l JOIN unnest($1::text[], $2::text[]) AS "
                "k(agent_id, sha256) ON l.agent_id = k.agent_id AND l.sha256 = k.sha256 LEFT JOIN "
                "certificate_inventory_store.store_state ss ON ss.agent_id = l.agent_id AND ss.store_id = "
                "l.store_id AND ss.user_ref = l.user_ref ORDER BY l.agent_id, l.sha256, "
                "l.store_id, l.path",
            kp, e);
        if (locs.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(locs.get()); ++i) {
            const auto it = index.find({cell_s(locs, i, 0), cell_s(locs, i, 1)});
            if (it == index.end())
                continue;
            auto& r = page.rows[it->second];
            const std::string seen = cell_s(locs, i, 6);
            if (seen > r.last_seen) // fixed-width RFC 3339 UTC sorts lexically
                r.last_seen = seen;
            if (r.locations.size() >= kCertReadMaxLocations) {
                r.locations_truncated = true;
                continue;
            }
            r.locations.push_back(
                {cell_s(locs, i, 2), cell_s(locs, i, 3), cell_s(locs, i, 4), cell(locs, i, 5), seen});
        }

        // Every store of every device on the page, so a kept row never shows without its status.
        std::vector<std::string_view> agent_list(agents.begin(), agents.end());
        const std::vector<std::string> ap = {pg::to_text_array(agent_list)};
        pg::PgResult stores = run(
            c,
            "SELECT agent_id, store_id, status, reason, " + fmt("observed_at") + ", " +
                fmt("status_at") +
                " FROM certificate_inventory_store.store_state WHERE agent_id = ANY($1::text[]) ORDER BY "
                "agent_id, store_id",
            ap, e);
        if (stores.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(stores.get()); ++i)
            page.stores.push_back({cell_s(stores, i, 0), cell_s(stores, i, 1), cell_s(stores, i, 2),
                                   cell_s(stores, i, 3), cell(stores, i, 4), cell_s(stores, i, 5)});
        pg::PgResult versions = run(
            c, "SELECT DISTINCT blob_version FROM certificate_inventory_store.agent_state WHERE agent_id = "
               "ANY($1::text[]) ORDER BY 1",
            ap, e);
        if (versions.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(versions.get()); ++i)
            page.blob_versions.push_back(cell_s(versions, i, 0));
        page.coverage.devices_included = static_cast<std::int64_t>(agents.size());
        return true;
    }, kReadAcquireTimeout, read_budget_);
    if (err)
        return std::unexpected(*err);

    // Coverage denominator: the in-scope devices with a certificate_inventory report. A separate
    // short statement in its own bounded transaction (the page above is already complete).
    const auto cov = bounded(pool_, "list_certificates.coverage", [&](PGconn* c, std::string& e) -> bool {
        SqlParams sp;
        std::string sql = "SELECT count(*) FROM certificate_inventory_store.agent_state f WHERE TRUE";
        if (scope) {
            std::vector<std::string_view> ids(scope->begin(), scope->end());
            sql += " AND f.agent_id = ANY(" + sp.add(pg::to_text_array(ids), "::text[]") + ")";
        }
        pg::PgResult r = run(c, sql, sp.values, e);
        if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
            return false;
        page.coverage.devices_reporting = cell_i64(r, 0, 0);
        return true;
    }, kReadAcquireTimeout, read_budget_);
    if (cov)
        return std::unexpected(*cov);
    return page;
}

std::expected<CertSummary, CertReadError>
CertificateInventoryStore::summarize_certificates(const CertSummaryQuery& query,
                                                  const CertScopeIds& scope) {
    if (!open_)
        return std::unexpected(fail(CertReadError::Kind::kNotOpen, "store not open"));
    if (filter_invalid(query.filter) || query.not_after_edges.size() > kCertEdgesMax)
        return std::unexpected(fail(CertReadError::Kind::kInvalid, "invalid certificate read"));
    if ((query.filter.issuer_dn_contains || query.filter.subject_dn_contains) &&
        !substring_index_available())
        return std::unexpected(substring_refusal(substring_state()));
    CertSummary out;
    out.coverage.confined = scope.has_value();
    const auto fill_empty_histogram = [&] {
        const auto& e = query.not_after_edges;
        if (e.empty())
            return;
        for (std::size_t i = 0; i <= e.size(); ++i) {
            CertHistogramBucket b;
            if (i > 0)
                b.from = e[i - 1];
            if (i < e.size())
                b.to = e[i];
            out.not_after_histogram.push_back(std::move(b));
        }
        CertHistogramBucket unknown;
        unknown.unknown = true;
        out.not_after_histogram.push_back(std::move(unknown));
    };
    if (scope && scope->empty()) { // deny-all: no SQL
        fill_empty_histogram();
        return out;
    }

    const auto err = bounded(pool_, "summarize_certificates", [&](PGconn* c, std::string& e) -> bool {
        DnMatches dn;
        if (!resolve_dns(c, query.filter, dn, e))
            return false;
        const auto counts = [](const pg::PgResult& r, int row, int col) {
            return CertCounts{cell_i64(r, row, col), cell_i64(r, row, col + 1)};
        };
        // A group is over the certificates where its field is KNOWN (`not_null`): a NULL is not a
        // value to group on (an RSA certificate has no curve), and the totals cover the rest.
        const auto group = [&](const std::string& cols, const std::string& group_by,
                               std::size_t cap, const std::string& from_extra,
                               const std::string& not_null) -> pg::PgResult {
            SqlParams sp;
            std::string where =
                filter_where(query.filter, scope, sp, dn) + " AND " +
                (not_null.find(' ') == std::string::npos ? not_null + " IS NOT NULL" : not_null);
            // The joined location side carries the scope too: the planner does not derive
            // `l.agent_id = ANY(..)` from `f.agent_id = ANY(..)` through the join, and without it the
            // store group hash-joins ALL of cert_location (measured: a confined 1k-device rollup
            // timed out; with the predicate it finishes in ~1.4 s). `$1` is the scope array, the
            // first parameter filter_where binds.
            if (scope && !from_extra.empty())
                where += " AND l.agent_id = ANY($1::text[])";
            const std::string sql =
                "SELECT " + cols + ", count(DISTINCT f.agent_id), count(DISTINCT f.sha256) FROM "
                "certificate_inventory_store.cert_fact f" + from_extra + where + " GROUP BY " + group_by +
                " ORDER BY count(DISTINCT f.agent_id) DESC, " + group_by + " LIMIT " +
                std::to_string(cap + 1);
            return run(c, sql, sp.values, e);
        };

        {
            SqlParams sp;
            pg::PgResult r = run(c,
                                 "SELECT count(DISTINCT f.agent_id), count(DISTINCT f.sha256) FROM "
                                 "certificate_inventory_store.cert_fact f" + filter_where(query.filter, scope, sp, dn),
                                 sp.values, e);
            if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
                return false;
            out.totals = counts(r, 0, 0);
        }
        const auto cap_flag = [&](int n, std::size_t cap) {
            if (static_cast<std::size_t>(n) > cap) {
                out.result_truncated = true;
                if (std::ranges::find(out.truncated_parts, "row_ceiling") == out.truncated_parts.end())
                    out.truncated_parts.emplace_back("row_ceiling");
            }
            return std::min(static_cast<std::size_t>(n), cap);
        };
        {
            pg::PgResult r = group("f.key_alg_oid, f.rsa_modulus_bits, f.ec_order_bits",
                                   "f.key_alg_oid, f.rsa_modulus_bits, f.ec_order_bits",
                                   kCertSummaryGroupMax, "", "f.key_alg_oid");
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            const auto n = cap_flag(PQntuples(r.get()), kCertSummaryGroupMax);
            for (std::size_t i = 0; i < n; ++i)
                out.key_algorithms.push_back({cell_s(r, static_cast<int>(i), 0),
                                              cell_int(r, static_cast<int>(i), 1),
                                              cell_int(r, static_cast<int>(i), 2),
                                              counts(r, static_cast<int>(i), 3)});
        }
        {
            pg::PgResult r = group("f.sig_alg_oid, f.pss_hash_oid", "f.sig_alg_oid, f.pss_hash_oid",
                                   kCertSummaryGroupMax, "", "f.sig_alg_oid");
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            const auto n = cap_flag(PQntuples(r.get()), kCertSummaryGroupMax);
            for (std::size_t i = 0; i < n; ++i)
                out.signature_algorithms.push_back({cell_s(r, static_cast<int>(i), 0),
                                                    cell(r, static_cast<int>(i), 1),
                                                    counts(r, static_cast<int>(i), 2)});
        }
        {
            pg::PgResult r = group("f.ec_curve_oid", "f.ec_curve_oid", kCertSummaryGroupMax, "",
                                   "f.ec_curve_oid");
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            const auto n = cap_flag(PQntuples(r.get()), kCertSummaryGroupMax);
            for (std::size_t i = 0; i < n; ++i)
                out.ec_curves.push_back(
                    {cell_s(r, static_cast<int>(i), 0), counts(r, static_cast<int>(i), 1)});
        }
        {
            pg::PgResult r = group("f.issuer_dn", "f.issuer_dn", kCertSummaryIssuerMax, "",
                                   // A self-signed END-ENTITY certificate repeats its subject (which can
                                   // be a person's name) as its issuer: it is never an issuer GROUP.
                                   // Self-issued (issuer == subject) counts too, so a certificate
                                   // whose self_signed the collector left unknown (NULL) is excluded.
                                   "f.issuer_dn IS NOT NULL AND NOT ((f.self_signed IS TRUE OR "
                                   "(f.issuer_dn = f.subject_dn) IS TRUE) AND f.is_ca IS NOT TRUE)");
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            const auto n = cap_flag(PQntuples(r.get()), kCertSummaryIssuerMax);
            for (std::size_t i = 0; i < n; ++i)
                out.issuers.push_back(
                    {cell_s(r, static_cast<int>(i), 0), counts(r, static_cast<int>(i), 1)});
        }
        {
            pg::PgResult r = group("l.store_id", "l.store_id", kCertSummaryGroupMax,
                                   " JOIN certificate_inventory_store.cert_location l ON l.agent_id = "
                                   "f.agent_id AND l.sha256 = f.sha256",
                                   "l.store_id");
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            const auto n = cap_flag(PQntuples(r.get()), kCertSummaryGroupMax);
            for (std::size_t i = 0; i < n; ++i)
                out.stores.push_back(
                    {cell_s(r, static_cast<int>(i), 0), counts(r, static_cast<int>(i), 1)});
        }
        {
            // Stores per status over the in-scope devices (not narrowed by the certificate filters:
            // a store is a coverage fact about the device, not about one certificate).
            SqlParams sp;
            std::string sql = "SELECT status, count(*), count(DISTINCT agent_id) FROM "
                              "certificate_inventory_store.store_state f WHERE TRUE";
            if (scope) {
                std::vector<std::string_view> ids(scope->begin(), scope->end());
                sql += " AND f.agent_id = ANY(" + sp.add(pg::to_text_array(ids), "::text[]") + ")";
            }
            sql += " GROUP BY status ORDER BY status";
            pg::PgResult r = run(c, sql, sp.values, e);
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            for (int i = 0; i < PQntuples(r.get()); ++i)
                out.store_statuses.push_back(
                    {cell_s(r, i, 0), cell_i64(r, i, 1), cell_i64(r, i, 2)});
        }
        if (!query.not_after_edges.empty()) {
            SqlParams sp;
            const std::string where = filter_where(query.filter, scope, sp, dn);
            std::string edges = "{";
            for (std::size_t i = 0; i < query.not_after_edges.size(); ++i) {
                if (i)
                    edges += ',';
                edges += '"' + query.not_after_edges[i] + '"'; // validated RFC 3339, no escapes
            }
            edges += '}';
            const std::string sql =
                "SELECT b, count(DISTINCT agent_id), count(DISTINCT sha256) FROM (SELECT "
                "f.agent_id, f.sha256, CASE WHEN f.not_after IS NULL THEN -1 ELSE "
                "width_bucket(f.not_after, " + sp.add(edges, "::timestamptz[]") +
                ") END AS b FROM certificate_inventory_store.cert_fact f" + where + ") t GROUP BY b";
            pg::PgResult r = run(c, sql, sp.values, e);
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            std::map<int, CertCounts> by_bucket;
            for (int i = 0; i < PQntuples(r.get()); ++i)
                by_bucket[static_cast<int>(cell_i64(r, i, 0))] = counts(r, i, 1);
            fill_empty_histogram();
            const auto& ed = query.not_after_edges;
            for (std::size_t i = 0; i <= ed.size(); ++i)
                if (const auto it = by_bucket.find(static_cast<int>(i)); it != by_bucket.end())
                    out.not_after_histogram[i].counts = it->second;
            if (const auto it = by_bucket.find(-1); it != by_bucket.end())
                out.not_after_histogram.back().counts = it->second;
        }
        {
            SqlParams sp;
            std::string sql = "SELECT count(*) FROM certificate_inventory_store.agent_state f WHERE TRUE";
            if (scope) {
                std::vector<std::string_view> ids(scope->begin(), scope->end());
                sql += " AND f.agent_id = ANY(" + sp.add(pg::to_text_array(ids), "::text[]") + ")";
            }
            pg::PgResult r = run(c, sql, sp.values, e);
            if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
                return false;
            out.coverage.devices_reporting = cell_i64(r, 0, 0);
            out.coverage.devices_included = out.totals.device_count;
        }
        {
            SqlParams sp;
            std::string sql = "SELECT DISTINCT blob_version FROM certificate_inventory_store.agent_state f "
                              "WHERE TRUE";
            if (scope) {
                std::vector<std::string_view> ids(scope->begin(), scope->end());
                sql += " AND f.agent_id = ANY(" + sp.add(pg::to_text_array(ids), "::text[]") + ")";
            }
            sql += " ORDER BY 1";
            pg::PgResult r = run(c, sql, sp.values, e);
            if (r.status() != PGRES_TUPLES_OK)
                return false;
            for (int i = 0; i < PQntuples(r.get()); ++i)
                out.blob_versions.push_back(cell_s(r, i, 0));
        }
        return true;
    }, kReadAcquireTimeout, read_budget_);
    if (err)
        return std::unexpected(as_summary_failure(*err));
    return out;
}

std::expected<CertFleetStatusCounts, CertReadError>
CertificateInventoryStore::fleet_status_counts(const std::vector<std::string>& agent_ids,
                                               const std::vector<std::string>& os_buckets,
                                               std::chrono::milliseconds acquire_timeout,
                                               std::chrono::milliseconds budget) {
    if (!open_)
        return std::unexpected(fail(CertReadError::Kind::kNotOpen, "store not open"));
    if (agent_ids.size() != os_buckets.size())
        return std::unexpected(fail(CertReadError::Kind::kInvalid, "agent_ids and os_buckets differ in length"));
    CertFleetStatusCounts out;
    const std::vector<std::string> params = {pg::to_text_array(agent_ids), pg::to_text_array(os_buckets)};
    const auto err = bounded(pool_, "fleet_status_counts", [&](PGconn* c, std::string& e) -> bool {
        // Folded entirely in SQL: at most (5 OS buckets x 5 statuses) rows come back, whatever the
        // fleet size. A device missing from the snapshot joins no row and is `unknown`.
        pg::PgResult r = run(c,
                             "SELECT COALESCE(m.os, 'unknown'), s.status, count(*) "
                             "FROM certificate_inventory_store.store_state s "
                             "LEFT JOIN unnest($1::text[], $2::text[]) AS m(agent_id, os) "
                             "ON m.agent_id = s.agent_id "
                             "WHERE s.status IN ('ok', 'absent', 'unreadable', 'constrained', 'not_observed') "
                             "GROUP BY 1, 2",
                             params, e);
        if (r.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out[{cell_s(r, i, 0), cell_s(r, i, 1)}] += cell_i64(r, i, 2);
        return true;
    }, acquire_timeout, budget);
    if (err)
        return std::unexpected(*err);
    return out;
}

} // namespace yuzu::server
