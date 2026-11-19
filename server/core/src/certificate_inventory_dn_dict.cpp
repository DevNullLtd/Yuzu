/// @file certificate_inventory_dn_dict.cpp
/// The BACKGROUND maintenance of the certificate inventory's distinct-DN dictionary
/// (`CertificateInventoryStore::run_dn_dictionary_maintenance`). See certificate_inventory_store.cpp
/// (why the dictionary exists, the marker) and pg/pg_background_build.hpp (the step contract).

#include "certificate_inventory_store.hpp"

#include <optional>

#include "pg/pg_array.hpp"
#include "pg/pg_background_build.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kSchema = "certificate_inventory_store";
constexpr std::size_t kBatch = 1000;
constexpr std::chrono::milliseconds kLeaseWait{10000};

// A name column to reconcile: the cert_fact column, the partial-index predicate and the dictionary
// role flag it sets.
struct Role {
    const char* column;   ///< cert_fact column (compile-time constant)
    const char* extra;    ///< extra predicate on alias f ("" or " AND f.is_ca")
    const char* extra2;   ///< the same on alias f2
    const char* flag;     ///< dn_dict flag column
};
constexpr Role kIssuer{"issuer_dn", "", "", "is_issuer"};
constexpr Role kSubject{"subject_dn", " AND f.is_ca", " AND f2.is_ca", "is_ca_subject"};

pg::BuildResult exec_ok(PGconn* c, const std::string& sql, const std::vector<std::string>& params) {
    pg::PgResult r = pg::exec_params(c, sql.c_str(), params);
    if (r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK)
        return {true, false, "", "", false};
    return pg::result_from_failure(c, r);
}

// Loose index scan: the next <= kBatch DISTINCT names after `cursor`, one btree probe each, however
// many duplicates the 27M-row table holds. (Not DISTINCT/GROUP BY, which would walk every entry.)
pg::BatchedReconcile reconcile_step(PGconn* c, const Role& role) {
    pg::BatchedReconcile step;
    step.fetch = [c, role](std::string& cursor, std::vector<std::string>& batch) -> pg::BuildResult {
        const std::string col = role.column;
        const std::string sql =
            "WITH RECURSIVE t(dn) AS ((SELECT f." + col + " FROM " + kSchema + ".cert_fact f WHERE f." +
            col + " > $1" + role.extra + " ORDER BY f." + col + " LIMIT 1) UNION ALL SELECT (SELECT f2." +
            col + " FROM " + kSchema + ".cert_fact f2 WHERE f2." + col + " > t.dn" +
            role.extra2 + std::string(" ORDER BY f2.") + col +
            " LIMIT 1) FROM t WHERE t.dn IS NOT NULL) SELECT dn FROM t WHERE dn IS NOT NULL LIMIT " +
            std::to_string(kBatch);
        pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{cursor});
        if (r.status() != PGRES_TUPLES_OK)
            return pg::result_from_failure(c, r);
        for (int i = 0; i < PQntuples(r.get()); ++i)
            batch.emplace_back(PQgetvalue(r.get(), i, 0), static_cast<std::size_t>(PQgetlength(r.get(), i, 0)));
        if (!batch.empty())
            cursor = batch.back();
        return {true, false, "", "", false};
    };
    step.apply = [c, role](const std::vector<std::string>& batch) -> pg::BuildResult {
        std::vector<std::string_view> v(batch.begin(), batch.end());
        const std::string arr = pg::to_text_array(v);
        const std::string flag = role.flag;
        // DO NOTHING for a new name; a flag is raised only by a separate sorted UPDATE of the rows
        // whose flag is still false (the ingest path's rule: no ON CONFLICT .. DO UPDATE .. WHERE).
        auto r1 = exec_ok(c,
                          std::string("INSERT INTO ") + kSchema + ".dn_dict (dn, " + flag +
                              ") SELECT x, true FROM unnest($1::text[]) AS x ORDER BY x ON CONFLICT (dn) "
                              "DO NOTHING",
                          {arr});
        if (!r1.ok)
            return r1;
        return exec_ok(c,
                       std::string("UPDATE ") + kSchema + ".dn_dict d SET " + flag +
                           " = true FROM (SELECT dn FROM " + kSchema + ".dn_dict WHERE dn = ANY($1::text[]) AND NOT " +
                           flag + " ORDER BY dn FOR NO KEY UPDATE) s WHERE d.dn = s.dn",
                       {arr});
    };
    return step;
}

// Prune: keyset over the dictionary itself; each batch is its own short TRANSACTION (the row locks
// of prune_dn_names must be held across its two statements).
pg::BatchedReconcile prune_step(PGconn* c) {
    pg::BatchedReconcile step;
    step.fetch = [c](std::string& cursor, std::vector<std::string>& batch) -> pg::BuildResult {
        pg::PgResult r = pg::exec_params(
            c,
            (std::string("SELECT dn FROM ") + kSchema + ".dn_dict WHERE dn > $1 ORDER BY dn LIMIT " +
             std::to_string(kBatch))
                .c_str(),
            std::vector<std::string>{cursor});
        if (r.status() != PGRES_TUPLES_OK)
            return pg::result_from_failure(c, r);
        for (int i = 0; i < PQntuples(r.get()); ++i)
            batch.emplace_back(PQgetvalue(r.get(), i, 0), static_cast<std::size_t>(PQgetlength(r.get(), i, 0)));
        if (!batch.empty())
            cursor = batch.back();
        return {true, false, "", "", false};
    };
    step.apply = [c](const std::vector<std::string>& batch) -> pg::BuildResult {
        std::vector<std::string_view> v(batch.begin(), batch.end());
        auto b = exec_ok(c, "BEGIN", {});
        if (!b.ok)
            return b;
        pg::PgTxn txn{c};
        if (!prune_dn_names(c, v)) {
            pg::PgResult probe{PQexec(c, "SELECT 1")}; // surface the aborted-txn error text
            return {false, false, "", "dictionary prune batch failed", false};
        }
        if (!txn.commit())
            return {false, false, "", "dictionary prune commit failed", false};
        return {true, false, "", "", false};
    };
    return step;
}

struct LiteralDeleter {
    void operator()(char* p) const noexcept { PQfreemem(p); }
};

// COMMENT ON TABLE dn_dict IS <literal>. The literal is escaped by libpq (the failure text is data).
pg::BuildResult set_marker(PGconn* c, const std::string& text) {
    std::unique_ptr<char, LiteralDeleter> lit{PQescapeLiteral(c, text.c_str(), text.size())};
    if (!lit)
        return {false, false, "", "could not escape the marker text", false};
    return exec_ok(c, std::string("COMMENT ON TABLE ") + kSchema + ".dn_dict IS " + lit.get(), {});
}

std::int64_t db_now_ms(PGconn* c) {
    pg::PgResult t = pg::exec_params(
        c, "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint", std::vector<std::string>{});
    return t.status() == PGRES_TUPLES_OK && PQntuples(t.get()) == 1 ? std::stoll(PQgetvalue(t.get(), 0, 0)) : -1;
}

pg::BuildResult set_state(PGconn* c, const char* key, std::int64_t value) {
    return exec_ok(c,
                   std::string("INSERT INTO ") + kSchema +
                       ".dn_dict_state (k, v) VALUES ($1, $2::bigint) ON CONFLICT (k) DO UPDATE SET v = "
                       "EXCLUDED.v",
                   {key, std::to_string(value)});
}

constexpr const char* kIssuerIndex = "cert_fact_issuer_dn_idx";
constexpr const char* kSubjectIndex = "cert_fact_subject_ca_dn_idx";

} // namespace

bool prune_dn_names(PGconn* conn, const std::vector<std::string_view>& names) {
    if (names.empty())
        return true;
    const std::string arr = pg::to_text_array(names);
    // Statement 1: lock the candidates (sorted; rows an ingest holds FOR KEY SHARE are skipped).
    pg::PgResult lk = pg::exec_params(conn,
                                      "SELECT dn FROM certificate_inventory_store.dn_dict WHERE dn = "
                                      "ANY($1::text[]) ORDER BY dn FOR UPDATE SKIP LOCKED",
                                      std::vector<std::string>{arr});
    if (lk.status() != PGRES_TUPLES_OK)
        return false;
    std::vector<std::string> locked;
    for (int i = 0; i < PQntuples(lk.get()); ++i)
        locked.emplace_back(PQgetvalue(lk.get(), i, 0), static_cast<std::size_t>(PQgetlength(lk.get(), i, 0)));
    if (locked.empty())
        return true;
    std::vector<std::string_view> lv(locked.begin(), locked.end());
    // Statement 2 runs in a NEW snapshot taken AFTER the locks are held: an ingest that committed
    // facts naming one of these before we locked it is visible here, and one that has not yet
    // committed holds a conflicting key-share lock, so the row would have been skipped above.
    pg::PgResult del = pg::exec_params(
        conn,
        "DELETE FROM certificate_inventory_store.dn_dict d WHERE d.dn = ANY($1::text[]) AND NOT EXISTS "
        "(SELECT 1 FROM certificate_inventory_store.cert_fact f WHERE f.issuer_dn = d.dn) AND NOT "
        "EXISTS (SELECT 1 FROM certificate_inventory_store.cert_fact f WHERE f.is_ca AND f.subject_dn = "
        "d.dn)",
        std::vector<std::string>{pg::to_text_array(lv)});
    return del.status() == PGRES_COMMAND_OK;
}

std::optional<CertificateInventoryStore::DictSchedule>
CertificateInventoryStore::read_dn_dictionary_schedule() {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(std::chrono::milliseconds{250});
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint, "
        "coalesce(max(v) FILTER (WHERE k = 'last_pass_start_ms'), 0), "
        "coalesce(max(v) FILTER (WHERE k = 'last_prune_ms'), 0), "
        "coalesce(max(v) FILTER (WHERE k = 'reconcile_requested_ms'), 0) FROM "
        "certificate_inventory_store.dn_dict_state",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    DictSchedule d;
    d.db_now_ms = std::stoll(PQgetvalue(r.get(), 0, 0));
    d.last_pass_start_ms = std::stoll(PQgetvalue(r.get(), 0, 1));
    d.last_prune_ms = std::stoll(PQgetvalue(r.get(), 0, 2));
    d.reconcile_requested_ms = std::stoll(PQgetvalue(r.get(), 0, 3));
    last_prune_unix_s_.store(d.last_prune_ms / 1000, std::memory_order_release);
    return d;
}

void CertificateInventoryStore::request_dn_reconcile() {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(std::chrono::milliseconds{250});
    if (!lease)
        return;
    // Rate-limited in SQL: at most one request per 20 s however many non-leaders ask.
    (void)exec_ok(lease.get(),
                  "INSERT INTO certificate_inventory_store.dn_dict_state (k, v) VALUES "
                  "('reconcile_requested_ms', floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) "
                  "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v WHERE "
                  "certificate_inventory_store.dn_dict_state.v < EXCLUDED.v - 20000",
                  {});
}

bool CertificateInventoryStore::prune_dn_dictionary(const std::function<bool()>& should_stop) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kLeaseWait);
    if (!lease)
        return false;
    auto step = prune_step(lease.get());
    return pg::run_batched_reconcile(step, should_stop).ok;
}

bool CertificateInventoryStore::run_dn_dictionary_maintenance(const std::function<bool()>& should_stop) {
    if (!open_)
        return false;
    const auto note = [&](const char* step, const char* result) {
        if (dn_observer_)
            dn_observer_(step, result);
    };
    auto lease = pool_.try_acquire_for(kLeaseWait);
    if (!lease) {
        spdlog::warn("CertificateInventoryStore: DN dictionary maintenance skipped: no pooled connection "
                     "within {} ms (pool saturated); retrying next cycle", kLeaseWait.count());
        note("lease", "timeout");
        return false;
    }
    PGconn* c = lease.get();

    // The marker records when THIS run started: everything referenced before then is reconciled.
    const std::int64_t run_started_ms = db_now_ms(c);
    if (run_started_ms < 0)
        return false;
    (void)set_state(c, "last_pass_start_ms", run_started_ms);

    bool all_ok = true;
    const auto fail = [&](const char* step, const std::string& what, const pg::BuildResult& r) {
        if (r.stopped) {
            note(step, "stopped");
            return; // shutdown / lost leadership, not a fault
        }
        all_ok = false;
        note(step, r.cancelled ? "cancelled" : "failed");
        spdlog::warn("CertificateInventoryStore: DN dictionary maintenance failed at {} ({}{})", what,
                     r.error, r.cancelled ? "; the statement was cancelled - retried next cycle" : "");
        // Record the failure on a connection that can still speak: if `c` was lost (a terminate, a
        // failover) take a FRESH lease, else the comment would keep a stale `ready:` while reads
        // refuse. A usable dictionary from THIS process (`ready:` with ms >= started_ms_) is not
        // flipped off by a failed periodic run - the failure is appended (`;last_failure:`) so the
        // comment stays truthful for a replica that started later and cannot count it as ready. An
        // EARLIER process's `ready:` is not usable and is replaced by `failed:`.
        std::optional<pg::PgPool::Lease> fresh;
        PGconn* wc = c;
        if (PQstatus(c) != CONNECTION_OK) {
            fresh.emplace(pool_.try_acquire_for(std::chrono::milliseconds{2000}));
            if (!*fresh) { // an engaged optional can hold an EMPTY lease (timeout)
                spdlog::warn("CertificateInventoryStore: could not record the DN dictionary failure: no "
                             "pooled connection (the comment may still read ready)");
                return;
            }
            wc = fresh->get();
        }
        pg::PgResult st = pg::exec_params(
            wc, "SELECT coalesce(obj_description('certificate_inventory_store.dn_dict'::regclass, 'pg_class'), '')",
            std::vector<std::string>{});
        std::string marker;
        if (st.status() == PGRES_TUPLES_OK && PQntuples(st.get()) == 1)
            marker = PQgetvalue(st.get(), 0, 0);
        std::int64_t ready_ms = -1;
        if (marker.rfind("ready:", 0) == 0)
            ready_ms = std::strtoll(marker.c_str() + 6, nullptr, 10);
        // A connection lost client-side carries no SQLSTATE: record the connection-failure class
        // (08006) so the marker classifies as transient.
        const bool lost = r.sqlstate.empty() && PQstatus(c) != CONNECTION_OK;
        const std::string what_err = std::string(what) + ": " + (lost ? "08006 " : "") + r.error;
        if (ready_ms >= started_ms_.load(std::memory_order_acquire)) {
            (void)set_marker(wc, "ready:" + std::to_string(ready_ms) + ";last_failure:" + what_err);
        } else {
            (void)set_marker(wc, "failed: " + what_err);
        }
        refresh_substring_index_state(wc);
    };
    const auto stopped = [&] { return (should_stop && should_stop()) || build_cancel_.stop_requested(); };

    // (1) indexes, CONCURRENTLY, on this connection in autocommit; one spec each.
    bool indexes_ok = true;
    for (const auto& spec : {pg::IndexSpec{kSchema, kIssuerIndex, "cert_fact", "btree", "issuer_dn", ""},
                             pg::IndexSpec{kSchema, kSubjectIndex, "cert_fact", "btree", "subject_dn", "is_ca"}}) {
        if (stopped())
            return false;
        auto r = pg::ensure_index_concurrently(c, spec, &build_cancel_);
        if (!r.ok) {
            fail("index", spec.name, r);
            indexes_ok = false;
            if (r.stopped)
                return false;
            break;
        }
    }
    if (indexes_ok)
        note("index", "ok");

    // (2) reconcile, both roles (needs the indexes: the loose scan).
    bool reconciled = false;
    if (indexes_ok) {
        reconciled = true;
        for (const Role* role : {&kIssuer, &kSubject}) {
            auto step = reconcile_step(c, *role);
            if (auto r = pg::run_batched_reconcile(step, stopped); !r.ok) {
                fail("reconcile", role->column, r);
                reconciled = false;
                if (r.stopped)
                    return false;
                break;
            }
        }
        if (reconciled)
            note("reconcile", "ok");
    }

    // (3) OPTIONAL trigram index on the small dictionary: a convenience for a dictionary of millions
    // of names, never required. Every failure here is ignored.
    if (indexes_ok) {
        auto ext = exec_ok(c, "CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public", {});
        if (ext.ok)
            (void)pg::ensure_index_concurrently(
                c, pg::IndexSpec{kSchema, "dn_dict_dn_trgm_idx", "dn_dict", "gin", "dn public.gin_trgm_ops", ""},
                &build_cancel_);
    }

    // (4) PRUNE names no certificate references: scheduled from the DB clock (last prune recorded in
    // dn_dict_state, hourly), decoupled from whether the build/reconcile above succeeded - but it
    // needs the two indexes (its anti-join probes them), so an unbuilt index skips it, loudly.
    {
        const std::int64_t now = db_now_ms(c);
        auto sch = read_dn_dictionary_schedule();
        const bool due = !sch || sch->last_prune_ms == 0 || now - sch->last_prune_ms >= kPruneIntervalMs;
        if (due && !stopped()) {
            if (pg::index_is_valid(c, kSchema, kIssuerIndex) && pg::index_is_valid(c, kSchema, kSubjectIndex)) {
                auto step = prune_step(c);
                if (auto r = pg::run_batched_reconcile(step, stopped); r.ok) {
                    (void)set_state(c, "last_prune_ms", db_now_ms(c));
                    note("prune", "ok");
                    (void)read_dn_dictionary_schedule(); // refresh the exported timestamp
                } else {
                    fail("prune", "prune", r);
                    if (r.stopped)
                        return false;
                }
            } else {
                note("prune", "skipped");
                spdlog::warn("CertificateInventoryStore: the DN dictionary prune is due but skipped: the "
                             "dictionary indexes are not built yet");
            }
        }
    }

    // (5) ready - only when the indexes and the reconcile both succeeded.
    if (indexes_ok && reconciled) {
        auto r = set_marker(c, "ready:" + std::to_string(run_started_ms));
        if (!r.ok) {
            fail("marker", "marker", r);
            return false;
        }
        note("marker", "ok");
        refresh_substring_index_state(c);
    }
    return all_ok && indexes_ok && reconciled;
}

} // namespace yuzu::server
