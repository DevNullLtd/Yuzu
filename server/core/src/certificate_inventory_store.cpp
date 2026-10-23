#include "certificate_inventory_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <yuzu/metrics.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <array>
#include <charconv>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "certificate_inventory_store";

// The ingest path runs on the gRPC thread (direct ReportInventory / gateway ProxyInventory), so
// it gives up fast on a saturated pool: best-effort, the agent resends next cycle.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};

// Rows per jsonb_to_recordset statement. Bounds the statement size; the parameter count stays at
// two or three however many rows go in.
constexpr std::size_t kChunkRows = 500;

// The cert_fact payload columns (everything but agent_id, server_parsed), name and SQL type. The
// JSON object keys of a batch equal the column names, so the INSERT, the recordset column list
// and the ON CONFLICT list are all generated from this one table.
struct FactCol {
    const char* name;
    const char* type;
};
constexpr FactCol kFactCols[] = {
    {"sha256", "text"},
    {"sha1", "text"},
    {"tbs_sha256", "text"},
    {"version", "int"},
    {"serial", "text"},
    {"serial_negative", "boolean"},
    {"subject_dn", "text"},
    {"issuer_dn", "text"},
    {"subject_name_sha256", "text"},
    {"issuer_name_sha256", "text"},
    {"not_before", "timestamptz"},
    {"not_after", "timestamptz"},
    {"key_alg_oid", "text"},
    {"rsa_modulus_bits", "int"},
    {"ec_curve_oid", "text"},
    {"ec_order_bits", "int"},
    {"sig_alg_oid", "text"},
    {"pss_hash_oid", "text"},
    {"pss_mgf1_hash_oid", "text"},
    {"spki_sha256", "text"},
    {"ski", "text"},
    {"aki_key_id", "text"},
    {"is_ca", "boolean"},
    {"path_len", "int"},
    {"key_usage", "text"},
    {"self_signed", "boolean"},
    {"key_association", "text"},
    {"key_provider", "text"},
    {"key_exportable", "text"},
    {"der_omitted", "text"},
    {"der", "text"},
    {"constrained_fields", "text"},
    {"child_digest", "text"},
};

const std::string& fact_upsert_sql() {
    static const std::string sql = [] {
        std::string cols = "agent_id";
        std::string sel = "$1";
        std::string rec;
        std::string upd, cur, exc;
        for (const auto& c : kFactCols) {
            cols += std::string(", ") + c.name;
            sel += std::string(", t.") + c.name;
            if (!rec.empty())
                rec += ", ";
            rec += std::string(c.name) + " " + c.type;
            if (std::string_view(c.name) != "sha256") {
                upd += std::string(upd.empty() ? "" : ", ") + c.name + " = EXCLUDED." + c.name;
                cur += std::string(cur.empty() ? "" : ", ") + "cert_fact." + c.name;
                exc += std::string(exc.empty() ? "" : ", ") + "EXCLUDED." + c.name;
            }
        }
        return "INSERT INTO certificate_inventory_store.cert_fact (" + cols + ", server_parsed) SELECT " + sel +
               ", false FROM jsonb_to_recordset($2::jsonb) AS t(" + rec +
               ") ON CONFLICT (agent_id, sha256) DO UPDATE SET " + upd +
               ", server_parsed = false WHERE (" + cur + ", cert_fact.server_parsed) IS DISTINCT FROM (" +
               exc + ", false) RETURNING sha256";
    }();
    return sql;
}

const std::vector<pg::PgMigration>& build_migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration
    // transaction. Runtime statements schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Per-agent hash-skip state. content_hash is the SHA-256 of the RAW received blob
         // bytes, recomputed by the ingest seam. first_seen/last_seen/last_full_at are SERVER
         // receipt time (#1685); last_seen moves on any report, last_full_at only on a full one.
         "CREATE TABLE agent_state ("
         "  agent_id      TEXT PRIMARY KEY,"
         "  content_hash  TEXT NOT NULL,"
         "  blob_version  TEXT NOT NULL,"
         "  first_seen    TIMESTAMPTZ NOT NULL,"
         "  last_seen     TIMESTAMPTZ NOT NULL,"
         "  last_full_at  TIMESTAMPTZ NOT NULL);"
         // One row per store per device (user_ref is '' for the machine scope; slice 2 reads no
         // per-user store). observed_at is the receipt of the last report in which the store
         // read ok or absent (NULL until there has been one); status_at is the receipt of the
         // last report that carried the store.
         "CREATE TABLE store_state ("
         "  agent_id     TEXT NOT NULL REFERENCES agent_state (agent_id) ON DELETE CASCADE,"
         "  store_id     TEXT NOT NULL,"
         "  user_ref     TEXT NOT NULL DEFAULT '',"
         "  scope        TEXT NOT NULL,"
         "  status       TEXT NOT NULL,"
         "  reason       TEXT NOT NULL DEFAULT '',"
         "  observed_at  TIMESTAMPTZ,"
         "  status_at    TIMESTAMPTZ NOT NULL,"
         "  cert_count   INTEGER NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (agent_id, store_id, user_ref));"
         "CREATE INDEX store_state_status_observed_idx ON store_state (status, observed_at);"
         // One row per (device, certificate): the X.509 facts. An unset column is UNKNOWN (NULL),
         // distinct from a real empty value. der is the base64 whole-DER, kept only when shipped.
         "CREATE TABLE cert_fact ("
         "  agent_id             TEXT NOT NULL REFERENCES agent_state (agent_id) ON DELETE CASCADE,"
         "  sha256               TEXT NOT NULL,"
         "  sha1                 TEXT,"
         "  tbs_sha256           TEXT,"
         "  version              INTEGER,"
         "  serial               TEXT,"
         "  serial_negative      BOOLEAN,"
         "  subject_dn           TEXT,"
         "  issuer_dn            TEXT,"
         "  subject_name_sha256  TEXT,"
         "  issuer_name_sha256   TEXT,"
         "  not_before           TIMESTAMPTZ,"
         "  not_after            TIMESTAMPTZ,"
         "  key_alg_oid          TEXT,"
         "  rsa_modulus_bits     INTEGER,"
         "  ec_curve_oid         TEXT,"
         "  ec_order_bits        INTEGER,"
         "  sig_alg_oid          TEXT,"
         "  pss_hash_oid         TEXT,"
         "  pss_mgf1_hash_oid    TEXT,"
         "  spki_sha256          TEXT,"
         "  ski                  TEXT,"
         "  aki_key_id           TEXT,"
         "  is_ca                BOOLEAN,"
         "  path_len             INTEGER,"
         "  key_usage            TEXT,"
         "  self_signed          BOOLEAN,"
         "  key_association      TEXT,"
         "  key_provider         TEXT,"
         "  key_exportable       TEXT,"
         "  der_omitted          TEXT,"
         "  der                  TEXT,"
         "  server_parsed        BOOLEAN NOT NULL DEFAULT false,"
         "  constrained_fields   TEXT NOT NULL DEFAULT '',"
         // Digest of the SAN/EKU/CDP child set: part of the unchanged-fact guard, so a child-only
         // change (the facts equal, the children differ) is never skipped and never goes stale.
         "  child_digest         TEXT NOT NULL DEFAULT '',"
         "  PRIMARY KEY (agent_id, sha256));"
         "CREATE INDEX cert_fact_not_after_idx ON cert_fact (not_after);"
         "CREATE INDEX cert_fact_not_before_idx ON cert_fact (not_before);"
         "CREATE INDEX cert_fact_issuer_serial_idx ON cert_fact (issuer_name_sha256, serial);"
         "CREATE INDEX cert_fact_sig_alg_idx ON cert_fact (sig_alg_oid, pss_hash_oid);"
         "CREATE INDEX cert_fact_key_alg_idx ON cert_fact (key_alg_oid, rsa_modulus_bits);"
         "CREATE INDEX cert_fact_ec_order_idx ON cert_fact (ec_order_bits);"
         "CREATE INDEX cert_fact_sha256_idx ON cert_fact (sha256);"
         "CREATE INDEX cert_fact_spki_idx ON cert_fact (spki_sha256);"
         "CREATE INDEX cert_fact_aki_idx ON cert_fact (aki_key_id);"
         // Where a certificate was seen. full_report_at is the last_full_at of the full report
         // that last carried the location, which is how a hash-skip refreshes exactly that set
         // and lets a kept, unreported location keep ageing.
         "CREATE TABLE cert_location ("
         "  agent_id        TEXT NOT NULL,"
         "  store_id        TEXT NOT NULL,"
         "  user_ref        TEXT NOT NULL DEFAULT '',"
         "  path            TEXT NOT NULL DEFAULT '',"
         // The key is on md5(path), not the path: a btree index row over ~2.7 KB is an error, and
         // a path is attacker-influenced text. The path itself is still stored in full.
         "  path_md5        TEXT GENERATED ALWAYS AS (md5(path)) STORED,"
         "  sha256          TEXT NOT NULL,"
         "  first_seen      TIMESTAMPTZ NOT NULL,"
         "  last_seen       TIMESTAMPTZ NOT NULL,"
         "  full_report_at  TIMESTAMPTZ NOT NULL,"
         "  PRIMARY KEY (agent_id, store_id, user_ref, path_md5, sha256),"
         "  FOREIGN KEY (agent_id, sha256) REFERENCES cert_fact (agent_id, sha256)"
         "    ON DELETE CASCADE);"
         "CREATE INDEX cert_location_fact_idx ON cert_location (agent_id, sha256);"
         "CREATE TABLE cert_san ("
         "  agent_id  TEXT NOT NULL,"
         "  sha256    TEXT NOT NULL,"
         "  ord       INTEGER NOT NULL,"
         "  san_type  TEXT NOT NULL,"
         "  value     TEXT NOT NULL,"
         "  PRIMARY KEY (agent_id, sha256, ord),"
         "  FOREIGN KEY (agent_id, sha256) REFERENCES cert_fact (agent_id, sha256)"
         "    ON DELETE CASCADE);"
         "CREATE TABLE cert_eku ("
         "  agent_id  TEXT NOT NULL,"
         "  sha256    TEXT NOT NULL,"
         "  ord       INTEGER NOT NULL,"
         "  oid       TEXT NOT NULL,"
         "  PRIMARY KEY (agent_id, sha256, ord),"
         "  FOREIGN KEY (agent_id, sha256) REFERENCES cert_fact (agent_id, sha256)"
         "    ON DELETE CASCADE);"
         "CREATE TABLE cert_cdp ("
         "  agent_id  TEXT NOT NULL,"
         "  sha256    TEXT NOT NULL,"
         "  ord       INTEGER NOT NULL,"
         "  uri       TEXT NOT NULL,"
         "  PRIMARY KEY (agent_id, sha256, ord),"
         "  FOREIGN KEY (agent_id, sha256) REFERENCES cert_fact (agent_id, sha256)"
         "    ON DELETE CASCADE);"},
    };
    return kMigrations;
}

// Per-agent serialisation. The prefix is the shared constant in the header (stable, independent of
// the schema name). Ingest TRIES the lock: a report that cannot get it must not park a pooled
// connection (many concurrent reports for one agent would otherwise starve the shared pool), so it
// is answered "busy" and retried by the agent. delete_agent, an operator action, waits.
constexpr const char* kLockSql =
    "SELECT pg_advisory_xact_lock(hashtextextended($2::text || $1::text, 0))";
constexpr const char* kTryLockSql =
    "SELECT pg_try_advisory_xact_lock(hashtextextended($2::text || $1::text, 0))";

// One transaction timestamp from the plain DATABASE clock. No ordering against a previous report
// is assumed: the ok-store sweep compares for DIFFERENCE from this value (every location this
// report carries is stamped exactly T), so a DB clock step or restore cannot freeze sweeps.
constexpr const char* kTimeSql = "SELECT clock_timestamp()::text";

// Upper bound on one ingest transaction, checked between statements and chunks: a transaction that
// keeps a pooled connection past it rolls back and gives the connection up. The budget scales with
// the report (a large legitimate report must be able to finish) and is capped; an overrun is a
// DISTINCT outcome (kBudgetExceeded), never an indistinguishable store error.
constexpr std::chrono::seconds kIngestTxnBudgetBase{8};
constexpr std::chrono::milliseconds kIngestTxnBudgetPerRow{5};
constexpr std::chrono::seconds kIngestTxnBudgetMax{60};
constexpr int kMaxConcurrentFull = 4;

std::chrono::steady_clock::duration txn_budget(std::size_t rows) {
    const auto b = kIngestTxnBudgetBase + kIngestTxnBudgetPerRow * static_cast<long>(rows);
    return std::min<std::chrono::steady_clock::duration>(b, kIngestTxnBudgetMax);
}

bool take_lock(PGconn* c, const std::string& id, bool blocking, bool& got) {
    pg::PgResult r = pg::exec_params(c, blocking ? kLockSql : kTryLockSql,
                                     std::vector<std::string>{id, std::string(kCertInventoryAgentLockPrefix)});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return false;
    got = blocking || std::string_view(PQgetvalue(r.get(), 0, 0)) == "t";
    return true;
}

bool cmd_ok(const pg::PgResult& r) { return r.status() == PGRES_COMMAND_OK; }
bool tup_ok(const pg::PgResult& r) { return r.status() == PGRES_TUPLES_OK; }

using Json = nlohmann::json;

Json opt_json(const std::optional<std::string>& v) { return v ? Json(*v) : Json(nullptr); }
Json opt_json(const std::optional<int>& v) { return v ? Json(*v) : Json(nullptr); }
Json opt_json(const std::optional<bool>& v) { return v ? Json(*v) : Json(nullptr); }

std::string digest_hex(const char* algo, std::string_view bytes) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    const EVP_MD* type = EVP_sha256(); (void)algo;
    if (EVP_Digest(bytes.data(), bytes.size(), md, &len, type, nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

// Canonical, length-prefixed digest of the child rows (order matters: `ord` is stored).
std::string child_digest_input(const CertFactRow& f) {
    std::string c;
    const auto put = [&](char tag, std::string_view a, std::string_view b = {}) {
        c += tag;
        c += std::to_string(a.size()) + ":" + std::string(a) + std::to_string(b.size()) + ":" +
             std::string(b);
    };
    for (const auto& s : f.sans)
        put('s', s.type, s.value);
    for (const auto& e : f.ekus)
        put('e', e);
    for (const auto& d : f.cdps)
        put('c', d);
    return c;
}

Json fact_json(const CertFactRow& f, const std::string& child_digest) {
    Json j;
    j["sha256"] = f.sha256;
    j["sha1"] = opt_json(f.sha1);
    j["tbs_sha256"] = opt_json(f.tbs_sha256);
    j["version"] = opt_json(f.version);
    j["serial"] = opt_json(f.serial);
    j["serial_negative"] = opt_json(f.serial_negative);
    j["subject_dn"] = opt_json(f.subject_dn);
    j["issuer_dn"] = opt_json(f.issuer_dn);
    j["subject_name_sha256"] = opt_json(f.subject_name_sha256);
    j["issuer_name_sha256"] = opt_json(f.issuer_name_sha256);
    j["not_before"] = opt_json(f.not_before);
    j["not_after"] = opt_json(f.not_after);
    j["key_alg_oid"] = opt_json(f.key_alg_oid);
    j["rsa_modulus_bits"] = opt_json(f.rsa_modulus_bits);
    j["ec_curve_oid"] = opt_json(f.ec_curve_oid);
    j["ec_order_bits"] = opt_json(f.ec_order_bits);
    j["sig_alg_oid"] = opt_json(f.sig_alg_oid);
    j["pss_hash_oid"] = opt_json(f.pss_hash_oid);
    j["pss_mgf1_hash_oid"] = opt_json(f.pss_mgf1_hash_oid);
    j["spki_sha256"] = opt_json(f.spki_sha256);
    j["ski"] = opt_json(f.ski);
    j["aki_key_id"] = opt_json(f.aki_key_id);
    j["is_ca"] = opt_json(f.is_ca);
    j["path_len"] = opt_json(f.path_len);
    j["key_usage"] = opt_json(f.key_usage);
    j["self_signed"] = opt_json(f.self_signed);
    j["key_association"] = opt_json(f.key_association);
    j["key_provider"] = opt_json(f.key_provider);
    j["key_exportable"] = opt_json(f.key_exportable);
    j["der_omitted"] = opt_json(f.der_omitted);
    j["der"] = opt_json(f.der_base64);
    j["constrained_fields"] = f.constrained_fields;
    j["child_digest"] = child_digest;
    return j;
}

std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v);
    return v;
}

// Run one jsonb batch statement per chunk of `rows`. `make_params` turns a chunk into the bound
// parameters; the statement text is fixed.
template <typename Row, typename MakeParams>
bool for_each_chunk(PGconn* c, const char* sql, const std::vector<Row>& rows,
                    const std::function<bool()>& over, MakeParams&& make_params) {
    for (std::size_t i = 0; i < rows.size(); i += kChunkRows) {
        if (over())
            return false; // over the transaction budget: `over` records it, the caller names it
        const auto end = std::min(rows.size(), i + kChunkRows);
        pg::PgResult r = pg::exec_params(c, sql, make_params(i, end));
        if (!cmd_ok(r))
            return false;
    }
    return true;
}

} // namespace

const std::vector<pg::PgMigration>& certificate_inventory_migrations() {
    return build_migrations();
}

CertificateInventoryStore::CertificateInventoryStore(pg::PgPool& pool) : pool_(pool) {
    ingest_budget_ = [](std::size_t rows) { return txn_budget(rows); };
    child_hash_ = [](std::string_view in) { return digest_hex("sha256", in); };
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CertificateInventoryStore: no database connection at construction ({}) — "
                      "certificate inventory persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, build_migrations())) {
        spdlog::error("CertificateInventoryStore: schema migration failed — certificate "
                      "inventory persistence disabled");
        return;
    }
    open_ = true;
}

CertIngestResult CertificateInventoryStore::ingest_full(std::string_view agent_id,
                                                        const CertReportData& report,
                                                        std::string_view content_hash) {
    CertIngestResult result;
    if (!open_ || agent_id.empty())
        return result;
    const std::string id{agent_id};

    // Defensive de-duplication: the seam already de-duplicates, but a duplicate key inside one
    // INSERT ... ON CONFLICT statement is an error that would fail the report on every attempt.
    std::unordered_map<std::string, std::string> store_status; // store_id -> status
    std::vector<const CertStoreReport*> stores;
    for (const auto& s : report.stores)
        if (store_status.emplace(s.store_id, s.status).second)
            stores.push_back(&s);

    // Exact duplicates are dropped here. Two DIFFERENT paths that collide on md5(path) (the table's
    // key) are folded in SQL (DISTINCT ON the same md5() expression the generated column uses), so
    // the application never computes the key itself - md5 is unavailable under FIPS.
    std::set<std::tuple<std::string, std::string, std::string>> seen_loc;
    std::vector<const CertLocationRow*> locs; // locations that land in ok/constrained stores
    std::set<std::string> live_shas;
    for (const auto& l : report.locations) {
        const auto it = store_status.find(l.store_id);
        if (it == store_status.end())
            continue;
        if (it->second != cert_status::kOk && it->second != cert_status::kConstrained)
            continue;
        if (!seen_loc.emplace(l.store_id, l.path, l.sha256).second)
            continue;
        locs.push_back(&l);
        live_shas.insert(l.sha256);
    }
    std::vector<const CertFactRow*> facts;
    std::set<std::string> seen_fact;
    for (const auto& f : report.facts)
        if (live_shas.contains(f.sha256) && seen_fact.insert(f.sha256).second)
            facts.push_back(&f);

    // At most kMaxConcurrentFull long ingests at once, so a few 60 s budgets cannot hold many
    // pooled connections: beyond that the report is deferred (counted deferred/agent_busy).
    struct FullSlot {
        std::atomic<int>& n;
        bool ok;
        explicit FullSlot(std::atomic<int>& a) : n(a), ok(a.fetch_add(1) < kMaxConcurrentFull) {
            if (!ok)
                n.fetch_sub(1);
        }
        ~FullSlot() {
            if (ok)
                n.fetch_sub(1);
        }
    } slot(active_full_);
    if (!slot.ok) {
        CertIngestResult r;
        r.outcome = CertIngestOutcome::kBusy;
        return r;
    }
    // Child digests, SHA-256 (always available). A failed digest is an ERROR, never an empty
    // string stored as if it were a value.
    std::vector<std::string> digests;
    digests.reserve(facts.size());
    for (const auto* f : facts) {
        std::string d = child_hash_(child_digest_input(*f));
        if (d.empty()) {
            spdlog::warn("CertificateInventoryStore: child digest failed for agent={} - not stored",
                         agent_id);
            return CertIngestResult{}; // kError
        }
        digests.push_back(std::move(d));
    }
    bool budget_hit = false;
    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        std::size_t rows = facts.size() + locs.size();
        for (const auto* f : facts)
            rows += f->sans.size() + f->ekus.size() + f->cdps.size();
        const auto deadline = std::chrono::steady_clock::now() + ingest_budget_(rows);
        const std::function<bool()> over = [&] {
            if (std::chrono::steady_clock::now() > deadline) {
                budget_hit = true;
                return true;
            }
            return false;
        };
        const auto chunked = [&](const char* sql, const auto& rs, auto&& mk) {
            return for_each_chunk(c, sql, rs, over, mk);
        };
        bool got = false;
        if (!take_lock(c, id, /*blocking=*/false, got))
            return false;
        if (!got) {
            result.outcome = CertIngestOutcome::kBusy; // another report for this agent is running
            return true;
        }
        if (test_hook_after_lock_)
            test_hook_after_lock_();

        pg::PgResult tr = pg::exec_params(c, kTimeSql, std::vector<std::string>{});
        if (!tup_ok(tr) || PQntuples(tr.get()) != 1)
            return false;
        const std::string T = PQgetvalue(tr.get(), 0, 0);

        pg::PgResult as = pg::exec_params(
            c,
            "INSERT INTO certificate_inventory_store.agent_state "
            "(agent_id, content_hash, blob_version, first_seen, last_seen, last_full_at) "
            "VALUES ($1, $2, $3, $4::timestamptz, $4::timestamptz, $4::timestamptz) "
            "ON CONFLICT (agent_id) DO UPDATE SET content_hash = EXCLUDED.content_hash, "
            "  first_seen = LEAST(certificate_inventory_store.agent_state.first_seen, EXCLUDED.first_seen), "
            "  blob_version = EXCLUDED.blob_version, last_seen = EXCLUDED.last_seen, "
            "  last_full_at = EXCLUDED.last_full_at",
            std::vector<std::string>{id, std::string(content_hash), report.blob_version, T});
        if (!cmd_ok(as))
            return false;

        // Facts and their children first (cert_location references cert_fact).
        // An unchanged fact is not rewritten (IS DISTINCT FROM guard): RETURNING names only the
        // facts that were inserted or changed, and only those get their children rewritten.
        std::set<std::string> changed;
        for (std::size_t i = 0; i < facts.size(); i += kChunkRows) {
            if (over())
                return false;
            const auto e = std::min(facts.size(), i + kChunkRows);
            Json arr = Json::array();
            for (std::size_t k = i; k < e; ++k)
                arr.push_back(fact_json(*facts[k], digests[k]));
            pg::PgResult fr =
                pg::exec_params(c, fact_upsert_sql().c_str(), std::vector<std::string>{id, arr.dump()});
            if (!tup_ok(fr))
                return false;
            for (int r = 0; r < PQntuples(fr.get()); ++r)
                changed.insert(PQgetvalue(fr.get(), r, 0));
        }
        if (test_hook_after_facts_)
            test_hook_after_facts_();
        std::vector<const CertFactRow*> child_facts;
        for (const auto* f : facts)
            if (changed.contains(f->sha256))
                child_facts.push_back(f);
        {
            std::vector<std::string_view> shas;
            shas.reserve(child_facts.size());
            for (const auto* f : child_facts)
                shas.emplace_back(f->sha256);
            for (std::size_t i = 0; i < shas.size(); i += kChunkRows) {
                const auto e = std::min(shas.size(), i + kChunkRows);
                const std::string arr = pg::to_text_array(
                    std::vector<std::string_view>(shas.begin() + static_cast<std::ptrdiff_t>(i),
                                                  shas.begin() + static_cast<std::ptrdiff_t>(e)));
                for (const char* t : {"cert_san", "cert_eku", "cert_cdp"}) {
                    const std::string sql = std::string("DELETE FROM certificate_inventory_store.") + t +
                                            " WHERE agent_id = $1 AND sha256 = ANY($2::text[])";
                    if (!cmd_ok(pg::exec_params(c, sql.c_str(), std::vector<std::string>{id, arr})))
                        return false;
                }
            }
        }
        struct SanRow {
            const std::string* sha;
            int ord;
            const CertSan* san;
        };
        std::vector<SanRow> san_rows;
        std::vector<std::pair<const std::string*, std::pair<int, const std::string*>>> eku_rows,
            cdp_rows;
        for (const auto* f : child_facts) {
            for (std::size_t i = 0; i < f->sans.size(); ++i)
                san_rows.push_back({&f->sha256, static_cast<int>(i), &f->sans[i]});
            for (std::size_t i = 0; i < f->ekus.size(); ++i)
                eku_rows.push_back({&f->sha256, {static_cast<int>(i), &f->ekus[i]}});
            for (std::size_t i = 0; i < f->cdps.size(); ++i)
                cdp_rows.push_back({&f->sha256, {static_cast<int>(i), &f->cdps[i]}});
        }
        if (!chunked("INSERT INTO certificate_inventory_store.cert_san (agent_id, sha256, ord, san_type, value) "
                "SELECT $1, t.sha256, t.ord, t.san_type, t.value FROM "
                "jsonb_to_recordset($2::jsonb) AS t(sha256 text, ord int, san_type text, "
                "value text)",
                san_rows, [&](std::size_t b, std::size_t e) {
                    Json arr = Json::array();
                    for (std::size_t i = b; i < e; ++i)
                        arr.push_back({{"sha256", *san_rows[i].sha},
                                       {"ord", san_rows[i].ord},
                                       {"san_type", san_rows[i].san->type},
                                       {"value", san_rows[i].san->value}});
                    return std::vector<std::string>{id, arr.dump()};
                }))
            return false;
        if (!chunked("INSERT INTO certificate_inventory_store.cert_eku (agent_id, sha256, ord, oid) "
                            "SELECT $1, t.sha256, t.ord, t.oid FROM jsonb_to_recordset($2::jsonb) "
                            "AS t(sha256 text, ord int, oid text)",
                            eku_rows, [&](std::size_t b, std::size_t e) {
                                Json arr = Json::array();
                                for (std::size_t i = b; i < e; ++i)
                                    arr.push_back({{"sha256", *eku_rows[i].first},
                                                   {"ord", eku_rows[i].second.first},
                                                   {"oid", *eku_rows[i].second.second}});
                                return std::vector<std::string>{id, arr.dump()};
                            }))
            return false;
        if (!chunked("INSERT INTO certificate_inventory_store.cert_cdp (agent_id, sha256, ord, uri) "
                            "SELECT $1, t.sha256, t.ord, t.uri FROM jsonb_to_recordset($2::jsonb) "
                            "AS t(sha256 text, ord int, uri text)",
                            cdp_rows, [&](std::size_t b, std::size_t e) {
                                Json arr = Json::array();
                                for (std::size_t i = b; i < e; ++i)
                                    arr.push_back({{"sha256", *cdp_rows[i].first},
                                                   {"ord", cdp_rows[i].second.first},
                                                   {"uri", *cdp_rows[i].second.second}});
                                return std::vector<std::string>{id, arr.dump()};
                            }))
            return false;

        // Locations, then each store's removal rule. `ok` replaces (sweep everything this
        // report did not carry), `absent` removes all, `constrained` keeps the rest.
        if (!chunked("INSERT INTO certificate_inventory_store.cert_location (agent_id, store_id, user_ref, path, "
                "sha256, first_seen, last_seen, full_report_at) "
                "SELECT DISTINCT ON (t.store_id, md5(t.path), t.sha256) $1, t.store_id, '', t.path, t.sha256, "
                "$3::timestamptz, $3::timestamptz, $3::timestamptz FROM jsonb_to_recordset($2::jsonb) "
                "AS t(store_id text, path text, sha256 text) ORDER BY t.store_id, md5(t.path), t.sha256 "
                "ON CONFLICT (agent_id, store_id, user_ref, path_md5, sha256) DO UPDATE SET "
                "  first_seen = LEAST(certificate_inventory_store.cert_location.first_seen, EXCLUDED.first_seen), "
                "  last_seen = EXCLUDED.last_seen, full_report_at = EXCLUDED.full_report_at",
                locs, [&](std::size_t b, std::size_t e) {
                    Json arr = Json::array();
                    for (std::size_t i = b; i < e; ++i)
                        arr.push_back({{"store_id", locs[i]->store_id},
                                       {"path", locs[i]->path},
                                       {"sha256", locs[i]->sha256}});
                    return std::vector<std::string>{id, arr.dump(), T};
                }))
            return false;

        for (const auto* s : stores) {
            if (over())
                return false;
            if (s->status == cert_status::kOk) {
                if (!cmd_ok(pg::exec_params(
                        c,
                        "DELETE FROM certificate_inventory_store.cert_location WHERE agent_id = $1 AND "
                        "store_id = $2 AND user_ref = '' AND full_report_at IS DISTINCT FROM $3::timestamptz",
                        std::vector<std::string>{id, s->store_id, T})))
                    return false;
            } else if (s->status == cert_status::kAbsent) {
                if (!cmd_ok(pg::exec_params(
                        c,
                        "DELETE FROM certificate_inventory_store.cert_location WHERE agent_id = $1 AND "
                        "store_id = $2 AND user_ref = ''",
                        std::vector<std::string>{id, s->store_id})))
                    return false;
            }
            const bool observed =
                s->status == cert_status::kOk || s->status == cert_status::kAbsent;
            if (!cmd_ok(pg::exec_params(
                    c,
                    "INSERT INTO certificate_inventory_store.store_state (agent_id, store_id, user_ref, scope, "
                    "status, reason, observed_at, status_at, cert_count) "
                    "VALUES ($1, $2, '', $3, $4, $5, CASE WHEN $6::boolean THEN $7::timestamptz "
                    "END, $7::timestamptz, 0) "
                    "ON CONFLICT (agent_id, store_id, user_ref) DO UPDATE SET "
                    "  scope = EXCLUDED.scope, status = EXCLUDED.status, "
                    "  reason = EXCLUDED.reason, "
                    "  observed_at = COALESCE(EXCLUDED.observed_at, "
                    "    certificate_inventory_store.store_state.observed_at), "
                    "  status_at = EXCLUDED.status_at",
                    std::vector<std::string>{id, s->store_id, s->scope, s->status, s->reason,
                                             observed ? "true" : "false", T})))
                return false;
        }

        // A stored store the report no longer names: not_observed from the first omission. Its
        // rows, observed_at and status_at are untouched.
        {
            std::vector<std::string_view> names;
            for (const auto* s : stores)
                names.emplace_back(s->store_id);
            if (!cmd_ok(pg::exec_params(
                    c,
                    "UPDATE certificate_inventory_store.store_state SET status = 'not_observed', "
                    "reason = 'missing_from_report' WHERE agent_id = $1 AND "
                    "store_id <> ALL($2::text[]) AND status <> 'not_observed'",
                    std::vector<std::string>{id, pg::to_text_array(names)})))
                return false;
        }

        if (over())
            return false;
        // Orphaned facts (no location references them) go in this same transaction, then the
        // per-store distinct-certificate counts are recomputed.
        if (!cmd_ok(pg::exec_params(
                c,
                "DELETE FROM certificate_inventory_store.cert_fact f WHERE f.agent_id = $1 AND NOT EXISTS "
                "(SELECT 1 FROM certificate_inventory_store.cert_location l WHERE l.agent_id = f.agent_id AND "
                "l.sha256 = f.sha256)",
                std::vector<std::string>{id})))
            return false;
        if (!cmd_ok(pg::exec_params(
                c,
                "UPDATE certificate_inventory_store.store_state s SET cert_count = (SELECT count(DISTINCT "
                "l.sha256) FROM certificate_inventory_store.cert_location l WHERE l.agent_id = s.agent_id AND "
                "l.store_id = s.store_id AND l.user_ref = s.user_ref)::int "
                "WHERE s.agent_id = $1 AND s.status IN ('ok', 'absent', 'constrained')",
                std::vector<std::string>{id})))
            return false;
        result.outcome = CertIngestOutcome::kStored;
        return true;
    });
    if (!committed && budget_hit) {
        spdlog::warn("CertificateInventoryStore: ingest_full for agent={} exceeded its transaction "
                     "budget ({} facts, {} locations) - rolled back, nothing stored",
                     agent_id, facts.size(), locs.size());
        CertIngestResult r;
        r.outcome = CertIngestOutcome::kBudgetExceeded;
        return r;
    }
    if (!committed) {
        spdlog::warn("CertificateInventoryStore: ingest_full transaction failed for agent={} ({})",
                     agent_id, pool_.last_error());
        return CertIngestResult{};
    }
    return result;
}

CertIngestResult CertificateInventoryStore::ingest_touch(std::string_view agent_id,
                                                         std::string_view claimed_hash) {
    CertIngestResult result;
    if (!open_ || agent_id.empty())
        return result;
    const std::string id{agent_id};

    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        bool got = false;
        if (!take_lock(c, id, /*blocking=*/false, got))
            return false;
        if (!got) {
            result.outcome = CertIngestOutcome::kBusy;
            return true;
        }
        if (test_hook_after_lock_)
            test_hook_after_lock_();
        pg::PgResult st = pg::exec_params(
            c, "SELECT content_hash FROM certificate_inventory_store.agent_state WHERE agent_id = $1",
            std::vector<std::string>{id});
        if (!tup_ok(st))
            return false;
        if (PQntuples(st.get()) == 0) {
            result.outcome = CertIngestOutcome::kNeedFull;
            result.need_full_cause = CertNeedFullCause::kCold;
            return true;
        }
        if (std::string_view(PQgetvalue(st.get(), 0, 0)) != claimed_hash) {
            result.outcome = CertIngestOutcome::kNeedFull;
            result.need_full_cause = CertNeedFullCause::kHashMismatch;
            return true;
        }
        pg::PgResult tr = pg::exec_params(c, kTimeSql, std::vector<std::string>{});
        if (!tup_ok(tr) || PQntuples(tr.get()) != 1)
            return false;
        const std::string T = PQgetvalue(tr.get(), 0, 0);
        // The locations the last full report carried are exactly those whose full_report_at
        // equals agent_state.last_full_at; kept, unreported locations are not refreshed.
        if (!cmd_ok(pg::exec_params(
                c,
                "UPDATE certificate_inventory_store.cert_location l SET last_seen = $2::timestamptz FROM "
                "certificate_inventory_store.agent_state a WHERE a.agent_id = $1 AND l.agent_id = a.agent_id "
                "AND l.full_report_at = a.last_full_at",
                std::vector<std::string>{id, T})))
            return false;
        if (!cmd_ok(pg::exec_params(
                c,
                "UPDATE certificate_inventory_store.store_state SET status_at = $2::timestamptz, "
                "observed_at = CASE WHEN status IN ('ok', 'absent') THEN $2::timestamptz "
                "ELSE observed_at END WHERE agent_id = $1 AND status <> 'not_observed'",
                std::vector<std::string>{id, T})))
            return false;
        if (!cmd_ok(pg::exec_params(
                c,
                "UPDATE certificate_inventory_store.agent_state SET last_seen = $2::timestamptz "
                "WHERE agent_id = $1",
                std::vector<std::string>{id, T})))
            return false;
        result.outcome = CertIngestOutcome::kTouched;
        return true;
    });
    if (!committed) {
        spdlog::warn("CertificateInventoryStore: ingest_touch transaction failed for agent={} ({})",
                     agent_id, pool_.last_error());
        return CertIngestResult{};
    }
    return result;
}

bool CertificateInventoryStore::delete_agent(std::string_view agent_id) {
    if (agent_id.empty()) {
        spdlog::warn("CertificateInventoryStore: delete_agent called with an empty agent_id — "
                     "refusing without touching PG");
        return false;
    }
    if (!open_)
        return false;
    const std::string id{agent_id};
    // Erase in ONE transaction under the same per-agent lock ingest takes: an in-flight ingest
    // either commits first (and is erased here) or runs after the erase and re-creates its rows
    // from its own report; either way the result is one whole state, never partial rows.
    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Bounded wait (an operator action, but never an unbounded one): a report holding the
        // lock for longer than this makes the cascade report this store Failed (PARTIAL), and the
        // decommission is simply re-issued.
        if (!cmd_ok(pg::exec_params(c, "SET LOCAL lock_timeout = '5s'", std::vector<std::string>{})))
            return false;
        bool got = false;
        if (!take_lock(c, id, /*blocking=*/true, got))
            return false;
        for (const char* t : {"cert_san", "cert_eku", "cert_cdp", "cert_location", "cert_fact",
                              "store_state", "agent_state"}) {
            const std::string sql =
                std::string("DELETE FROM certificate_inventory_store.") + t + " WHERE agent_id = $1";
            if (!cmd_ok(pg::exec_params(c, sql.c_str(), std::vector<std::string>{id})))
                return false;
        }
        if (test_hook_after_erase_)
            test_hook_after_erase_();
        return true;
    });
    if (!committed && metrics_)
        metrics_->counter("yuzu_server_cert_inventory_delete_failed_total").increment();
    if (!committed)
        spdlog::debug("CertificateInventoryStore: delete_agent did not commit for agent={} ({})",
                      agent_id, pool_.last_error());
    return committed;
}

std::optional<CertificateInventoryStore::RowCounts>
CertificateInventoryStore::row_counts(std::string_view agent_id) {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease)
        return std::nullopt;
    RowCounts out;
    const std::array<std::pair<const char*, std::int64_t RowCounts::*>, 7> tables = {{
        {"agent_state", &RowCounts::agent_state},
        {"store_state", &RowCounts::store_state},
        {"cert_location", &RowCounts::cert_location},
        {"cert_fact", &RowCounts::cert_fact},
        {"cert_san", &RowCounts::cert_san},
        {"cert_eku", &RowCounts::cert_eku},
        {"cert_cdp", &RowCounts::cert_cdp},
    }};
    for (const auto& [name, member] : tables) {
        const std::string sql =
            std::string("SELECT count(*) FROM certificate_inventory_store.") + name + " WHERE agent_id = $1";
        pg::PgResult r =
            pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::string(agent_id)});
        if (!tup_ok(r) || PQntuples(r.get()) != 1)
            return std::nullopt;
        out.*member = result_i64(r, 0, 0);
    }
    return out;
}

} // namespace yuzu::server
