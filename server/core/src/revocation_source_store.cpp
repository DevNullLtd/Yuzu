#include "revocation_source_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <map>
#include <set>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "revocation_source_store";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly.
    //
    // The WHOLE schema of the design's "The store" table is created here, in v1, so the
    // fetcher PR (2b-1b) adds no migration for its tables. Times a CA signs (`this_update`,
    // `next_update`, `revocation_date`) are the CA's own; `fetched_at`, `last_*_at`,
    // `created_at` and `updated_at` are Postgres now(). CRL numbers are up to 20 octets
    // (RFC 5280 5.2.3), so NUMERIC; `serial` is UPPERCASE hex in the minimal BYTE form (even length, whole bytes, no leading 00 byte unless the value is zero); a CHECK pins that form so two spellings of one serial can never be two rows.
    //
    // `rollback_high_water` is keyed by the CA (subject Name hash) and scope, NOT by `source`,
    // and has no foreign key: it deliberately outlives a removed source. `crl_number` and
    // `this_update` are NULL on a row that only records a reset. `reset_at` is set by every
    // reset and never cleared.
    //
    // `verified_key_sha256` is the SPKI hash of the registered key the CRL verified under.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, "CREATE TABLE source ("
            "  id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
            "  name                   TEXT NOT NULL,"
            "  ca_subject_name_sha256 TEXT NOT NULL UNIQUE,"
            "  config_version         BIGINT NOT NULL DEFAULT 1 CHECK (config_version >= 1),"
            "  created_by             TEXT NOT NULL,"
            "  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now());"
            "CREATE TABLE source_ca_key ("
            "  source_id   BIGINT NOT NULL REFERENCES source(id) ON DELETE CASCADE,"
            "  cert_sha256 TEXT NOT NULL,"
            "  cert_der    BYTEA NOT NULL,"
            "  ski         TEXT,"
            "  spki_sha256 TEXT NOT NULL,"
            "  PRIMARY KEY (source_id, cert_sha256));"
            "CREATE TABLE source_url ("
            "  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
            "  source_id BIGINT NOT NULL REFERENCES source(id) ON DELETE CASCADE,"
            "  url       TEXT NOT NULL,"
            "  host      TEXT NOT NULL,"
            "  confirmed_address_classes TEXT NOT NULL,"
            "  UNIQUE (source_id, url));"
            "CREATE TABLE fetch_status ("
            "  url_id               BIGINT PRIMARY KEY REFERENCES source_url(id) ON DELETE CASCADE,"
            "  last_attempt_at      TIMESTAMPTZ,"
            "  last_success_at      TIMESTAMPTZ,"
            "  last_failure_cause   TEXT,"
            "  consecutive_failures BIGINT NOT NULL DEFAULT 0,"
            "  next_attempt_at      TIMESTAMPTZ,"
            "  etag                 TEXT,"
            "  last_modified        TEXT);"
            "CREATE TABLE crl ("
            "  id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
            "  source_id            BIGINT NOT NULL REFERENCES source(id) ON DELETE CASCADE,"
            "  scope_key            TEXT NOT NULL,"
            "  url_id               BIGINT NOT NULL REFERENCES source_url(id) ON DELETE CASCADE,"
            "  crl_number           NUMERIC,"
            "  this_update          TIMESTAMPTZ NOT NULL,"
            "  next_update          TIMESTAMPTZ,"
            "  is_delta             BOOLEAN NOT NULL DEFAULT FALSE,"
            "  base_crl_number      NUMERIC,"
            "  idp_reasons          TEXT,"
            "  expired_certs_on_crl TIMESTAMPTZ,"
            "  verified_key_sha256  TEXT NOT NULL,"
            "  der_sha256           TEXT NOT NULL,"
            "  entry_count          BIGINT NOT NULL,"
            "  fetched_at           TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  UNIQUE (source_id, scope_key, is_delta));"
            "CREATE INDEX crl_next_update_idx ON crl (next_update);"
            "CREATE TABLE crl_entry ("
            "  crl_id          BIGINT NOT NULL REFERENCES crl(id) ON DELETE CASCADE,"
            "  serial          TEXT NOT NULL CHECK (serial ~ '^([0-9A-F]{2})+$' AND "
            "                  (serial = '00' OR serial !~ '^00')),"
            "  revocation_date TIMESTAMPTZ NOT NULL,"
            "  reason          SMALLINT,"
            "  invalidity_date TIMESTAMPTZ,"
            "  PRIMARY KEY (crl_id, serial));"
            "CREATE TABLE rollback_high_water ("
            "  ca_subject_name_sha256 TEXT NOT NULL,"
            "  scope_key              TEXT NOT NULL,"
            "  crl_number             NUMERIC,"
            "  this_update            TIMESTAMPTZ,"
            "  reset_at               TIMESTAMPTZ,"
            "  pinned_crl_sha256      TEXT,"
            "  PRIMARY KEY (ca_subject_name_sha256, scope_key));"},
    };
    return kMigrations;
}

using Kind = RevocationSourceStoreError::Kind;

// Strict UTF-8, no NUL: anything else cannot bind as TEXT (SQLSTATE 22021) and would read as a
// store fault rather than the caller's bad argument.
bool bindable(std::string_view v) {
    return v.find('\0') == std::string_view::npos && sanitize_utf8_strict(v) == v;
}

// Degrade-log sampling (the DegradeSampler pattern of the other stores): the first warn of an
// episode and every kLogSample-th after it. The 503 to the operator is unaffected.
constexpr std::uint64_t kLogSample = 100;
constexpr std::int64_t kEpisodeGapSecs = 60;
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};
DegradeLog sample(DegradeSampler& s) {
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count() +
                             1; // never 0, so 0 stays "no previous degrade"
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    return {prev == 0 || (now - prev) > kEpisodeGapSecs || (n % kLogSample) == 0, n};
}
DegradeSampler g_timeout_sampler;
DegradeSampler g_statement_sampler;

void warn_no_connection(std::string_view op, std::chrono::milliseconds timeout) {
    if (const auto d = sample(g_timeout_sampler); d.should_log)
        spdlog::warn("RevocationSourceStore: {} skipped, no connection within {} ms "
                     "(occurrence {})",
                     op, timeout.count(), d.occurrence);
}

// The SQLSTATE only: a libpq message can quote the failing row, which here holds a URL.
std::string_view sqlstate(const pg::PgResult& res) {
    const char* code = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return code ? std::string_view(code) : std::string_view("none");
}

std::unexpected<RevocationSourceStoreError> fail(Kind kind, std::string message) {
    return std::unexpected(RevocationSourceStoreError{kind, std::move(message), 0});
}

// A statement that did not answer as expected. A lost connection after a WRITE was sent is
// kOutcomeUnknown (Postgres may have committed it before the link dropped); any failure on a
// live connection is a definite rollback (kQueryError). A read is never ambiguous.
std::unexpected<RevocationSourceStoreError> statement_error(std::string_view op, PGconn* conn,
                                                            const pg::PgResult& res, bool write) {
    const bool lost = PQstatus(conn) == CONNECTION_BAD;
    if (const auto d = sample(g_statement_sampler); d.should_log)
        spdlog::warn("RevocationSourceStore: {} failed{} (SQLSTATE {}, occurrence {})", op,
                     lost ? " (connection lost)" : "", sqlstate(res), d.occurrence);
    if (lost && write)
        return fail(Kind::kOutcomeUnknown, std::string(op) + ": connection lost, outcome unknown");
    return fail(Kind::kQueryError, std::string(op) + ": query failed");
}

bool begin(PGconn* conn, const char* sql) {
    pg::PgResult r{PQexec(conn, sql)};
    return r.status() == PGRES_COMMAND_OK;
}

std::string hex_encode(std::string_view bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char c : bytes) {
        out.push_back(kDigits[c >> 4]);
        out.push_back(kDigits[c & 0x0f]);
    }
    return out;
}

// The bytea text input form: `\x` then hex.
std::string bytea_param(std::string_view bytes) { return "\\x" + hex_encode(bytes); }

std::string join_csv(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) {
        if (!out.empty())
            out += ',';
        out += s;
    }
    return out;
}

std::vector<std::string> split_csv(std::string_view s) {
    std::vector<std::string> out;
    while (!s.empty()) {
        const auto comma = s.find(',');
        out.emplace_back(s.substr(0, comma));
        if (comma == std::string_view::npos)
            break;
        s.remove_prefix(comma + 1);
    }
    return out;
}

// A Postgres text[] literal of values that need no quoting (lowercase hex digests only).
std::string hex_array_literal(const std::vector<std::string>& hex) {
    std::string out = "{";
    for (std::size_t i = 0; i < hex.size(); ++i) {
        if (i)
            out += ',';
        out += hex[i];
    }
    out += '}';
    return out;
}

bool is_lower_hex(std::string_view s, std::size_t len) {
    return s.size() == len &&
           std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

std::int64_t to_i64(const pg::PgResult& res, int row, int col) {
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(res.get(), row, col), nullptr, 10));
}

std::optional<std::int64_t> opt_i64(const pg::PgResult& res, int row, int col) {
    if (PQgetisnull(res.get(), row, col))
        return std::nullopt;
    return to_i64(res, row, col);
}

std::optional<std::string> opt_str(const pg::PgResult& res, int row, int col) {
    if (PQgetisnull(res.get(), row, col))
        return std::nullopt;
    return std::string(PQgetvalue(res.get(), row, col));
}

constexpr const char* kEpoch = "floor(EXTRACT(EPOCH FROM ";

// What the writers share: the input checks that keep the stored shape consistent. The service
// validates richly and first; this only defends the store's own invariants.
std::optional<RevocationSourceStoreError> source_error(const NewRevocationSource& src) {
    const auto bad = [](std::string m) {
        return RevocationSourceStoreError{Kind::kInvalidInput, std::move(m), 0};
    };
    if (src.name.empty() || src.name.size() > RevocationSourceStore::kMaxNameBytes ||
        !bindable(src.name))
        return bad("invalid name");
    if (!is_lower_hex(src.ca_subject_name_sha256, 64))
        return bad("invalid CA subject hash");
    if (src.keys.empty() || src.keys.size() > RevocationSourceStore::kMaxCaKeys)
        return bad("key count out of range");
    std::set<std::string> seen_keys;
    for (const auto& k : src.keys) {
        if (!is_lower_hex(k.cert_sha256, 64) || !is_lower_hex(k.spki_sha256, 64) ||
            (k.ski && (k.ski->empty() || !is_lower_hex(*k.ski, k.ski->size()))) ||
            k.cert_der.empty() || k.cert_der.size() > RevocationSourceStore::kMaxCertDerBytes)
            return bad("invalid CA key");
        if (!seen_keys.insert(k.cert_sha256).second)
            return bad("duplicate CA key");
    }
    if (src.urls.empty() || src.urls.size() > RevocationSourceStore::kMaxUrls)
        return bad("URL count out of range");
    std::set<std::string> seen_urls;
    for (const auto& u : src.urls) {
        if (u.url.empty() || u.url.size() > RevocationSourceStore::kMaxUrlBytes || u.host.empty() ||
            !bindable(u.url) || !bindable(u.host))
            return bad("invalid URL");
        for (const auto& c : u.confirmed_address_classes)
            if (c.empty() || c.find(',') != std::string::npos || !bindable(c))
                return bad("invalid address class");
        if (!seen_urls.insert(u.url).second)
            return bad("duplicate URL");
    }
    return std::nullopt;
}

std::vector<std::string> sorted_classes(std::vector<std::string> c) {
    std::ranges::sort(c);
    c.erase(std::unique(c.begin(), c.end()), c.end());
    return c;
}

// Load one source (or all, id = nullopt) on a connection already in a transaction. Three
// statements; the caller's transaction makes them one snapshot.
std::expected<std::vector<RevocationSourceRecord>, RevocationSourceStoreError>
load_sources(PGconn* conn, std::optional<std::int64_t> id) {
    std::vector<std::string> params;
    std::string where;
    if (id) {
        params.push_back(std::to_string(*id));
        where = " WHERE s.id = $1";
    }
    pg::PgResult res = pg::exec_params(
        conn,
        (std::string("SELECT s.id, s.name, s.ca_subject_name_sha256, s.config_version, "
                     "s.created_by, ") +
         kEpoch + "s.created_at))::bigint, " + kEpoch +
         "s.updated_at))::bigint, (SELECT count(*) FROM revocation_source_store.crl c WHERE "
         "c.source_id = s.id), " + kEpoch + "h.reset_at))::bigint, h.pinned_crl_sha256 "
         "FROM revocation_source_store.source s LEFT JOIN "
         "revocation_source_store.rollback_high_water h ON "
         "h.ca_subject_name_sha256 = s.ca_subject_name_sha256 AND h.scope_key = '*'" +
         where + " ORDER BY s.id")
            .c_str(),
        params);
    if (res.status() != PGRES_TUPLES_OK)
        return statement_error("read sources", conn, res, false);
    std::vector<RevocationSourceRecord> out;
    std::map<std::int64_t, std::size_t> at;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        RevocationSourceRecord r;
        r.id = to_i64(res, i, 0);
        r.name = PQgetvalue(res.get(), i, 1);
        r.ca_subject_name_sha256 = PQgetvalue(res.get(), i, 2);
        r.config_version = to_i64(res, i, 3);
        r.created_by = PQgetvalue(res.get(), i, 4);
        r.created_at = to_i64(res, i, 5);
        r.updated_at = to_i64(res, i, 6);
        r.reset_at = opt_i64(res, i, 8);
        r.pinned_crl_sha256 = opt_str(res, i, 9);
        r.held_crl_count = to_i64(res, i, 7);
        at[r.id] = out.size();
        out.push_back(std::move(r));
    }

    pg::PgResult keys = pg::exec_params(
        conn,
        (std::string("SELECT source_id, cert_sha256, ski, spki_sha256 FROM "
                     "revocation_source_store.source_ca_key") +
         (id ? " WHERE source_id = $1" : "") + " ORDER BY source_id, cert_sha256")
            .c_str(),
        params);
    if (keys.status() != PGRES_TUPLES_OK)
        return statement_error("read keys", conn, keys, false);
    for (int i = 0; i < PQntuples(keys.get()); ++i) {
        const auto it = at.find(to_i64(keys, i, 0));
        if (it == at.end())
            continue;
        RevocationSourceKey k;
        k.cert_sha256 = PQgetvalue(keys.get(), i, 1);
        k.ski = opt_str(keys, i, 2);
        k.spki_sha256 = PQgetvalue(keys.get(), i, 3);
        out[it->second].keys.push_back(std::move(k));
    }

    pg::PgResult urls = pg::exec_params(
        conn,
        (std::string("SELECT u.source_id, u.id, u.url, u.host, u.confirmed_address_classes, "
                     "(f.url_id IS NOT NULL), ") +
         kEpoch + "f.last_attempt_at))::bigint, " + kEpoch + "f.last_success_at))::bigint, " +
         "f.last_failure_cause, f.consecutive_failures, " + kEpoch +
         "f.next_attempt_at))::bigint FROM revocation_source_store.source_url u LEFT JOIN "
         "revocation_source_store.fetch_status f ON f.url_id = u.id" +
         (id ? " WHERE u.source_id = $1" : "") + " ORDER BY u.source_id, u.id")
            .c_str(),
        params);
    if (urls.status() != PGRES_TUPLES_OK)
        return statement_error("read urls", conn, urls, false);
    for (int i = 0; i < PQntuples(urls.get()); ++i) {
        const auto it = at.find(to_i64(urls, i, 0));
        if (it == at.end())
            continue;
        RevocationSourceUrl u;
        u.id = to_i64(urls, i, 1);
        u.url = PQgetvalue(urls.get(), i, 2);
        u.host = PQgetvalue(urls.get(), i, 3);
        u.confirmed_address_classes = split_csv(PQgetvalue(urls.get(), i, 4));
        u.fetch.present = std::string_view(PQgetvalue(urls.get(), i, 5)) == "t";
        u.fetch.last_attempt_at = opt_i64(urls, i, 6);
        u.fetch.last_success_at = opt_i64(urls, i, 7);
        u.fetch.last_failure_cause = opt_str(urls, i, 8);
        u.fetch.consecutive_failures = PQgetisnull(urls.get(), i, 9) ? 0 : to_i64(urls, i, 9);
        u.fetch.next_attempt_at = opt_i64(urls, i, 10);
        out[it->second].urls.push_back(std::move(u));
    }
    return out;
}

std::expected<void, RevocationSourceStoreError>
insert_key(PGconn* conn, std::int64_t id, const RevocationSourceKey& k) {
    std::vector<std::optional<std::string>> p{std::to_string(id), k.cert_sha256,
                                              bytea_param(k.cert_der), std::nullopt,
                                              k.spki_sha256};
    if (k.ski)
        p[3] = *k.ski;
    pg::PgResult r = pg::exec_params(
        conn,
        "INSERT INTO revocation_source_store.source_ca_key (source_id, cert_sha256, cert_der, ski, "
        "spki_sha256) VALUES ($1::bigint, $2, $3::bytea, $4, $5)",
        p);
    if (r.status() != PGRES_COMMAND_OK)
        return statement_error("insert key", conn, r, true);
    return {};
}

std::expected<void, RevocationSourceStoreError>
insert_url(PGconn* conn, std::int64_t id, const NewRevocationSource::Url& u) {
    pg::PgResult r = pg::exec_params(
        conn,
        "INSERT INTO revocation_source_store.source_url (source_id, url, host, "
        "confirmed_address_classes) VALUES ($1::bigint, $2, $3, $4)",
        std::vector<std::string>{std::to_string(id), u.url, u.host,
                                 join_csv(sorted_classes(u.confirmed_address_classes))});
    if (r.status() != PGRES_COMMAND_OK)
        return statement_error("insert url", conn, r, true);
    return {};
}

} // namespace

RevocationSourceStore::RevocationSourceStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RevocationSourceStore: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RevocationSourceStore: schema migration failed");
        return;
    }
    open_ = true;
}

std::expected<std::vector<RevocationSourceRecord>, RevocationSourceStoreError>
RevocationSourceStore::list() {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("list", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    if (!begin(lease.get(), "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        return fail(Kind::kQueryError, "list: begin failed");
    pg::PgTxn txn(lease.get());
    auto rows = load_sources(lease.get(), std::nullopt);
    (void)txn.commit();
    return rows;
}

std::expected<RevocationSourceRecord, RevocationSourceStoreError>
RevocationSourceStore::get(std::int64_t id) {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("get", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    if (!begin(lease.get(), "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        return fail(Kind::kQueryError, "get: begin failed");
    pg::PgTxn txn(lease.get());
    auto rows = load_sources(lease.get(), id);
    (void)txn.commit();
    if (!rows)
        return std::unexpected(rows.error());
    if (rows->empty())
        return fail(Kind::kNotFound, "no such revocation source");
    return std::move(rows->front());
}

std::expected<std::int64_t, RevocationSourceStoreError>
RevocationSourceStore::crl_past_next_update_count() {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("crl_past_next_update_count", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT count(DISTINCT source_id) FROM revocation_source_store.crl WHERE next_update IS NOT "
        "NULL AND next_update < now()",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return statement_error("crl_past_next_update_count", lease.get(), res, false);
    return to_i64(res, 0, 0);
}

std::expected<std::int64_t, RevocationSourceStoreError>
RevocationSourceStore::create(const NewRevocationSource& src, const std::string& created_by) {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    if (write_fault_)
        if (const auto k = write_fault_("create"))
            return fail(*k, "injected write fault");
    if (auto bad = source_error(src))
        return std::unexpected(std::move(*bad));
    if (created_by.empty() || created_by.size() > kMaxUsernameBytes || !bindable(created_by))
        return fail(Kind::kInvalidInput, "invalid creator");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("create", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    PGconn* conn = lease.get();
    if (!begin(conn, "BEGIN"))
        return fail(Kind::kQueryError, "create: begin failed");
    pg::PgTxn txn(conn);

    // Serialise registrations across replicas so the ceiling and the one-source-per-CA rule are
    // checked against a quiescent table.
    pg::PgResult lock = pg::exec_params(
        conn, "SELECT pg_advisory_xact_lock(hashtext('revocation_source.registration'))",
        std::vector<std::string>{});
    if (lock.status() != PGRES_TUPLES_OK)
        return statement_error("create lock", conn, lock, true);
    pg::PgResult count = pg::exec_params(
        conn, "SELECT count(*) FROM revocation_source_store.source", std::vector<std::string>{});
    if (count.status() != PGRES_TUPLES_OK || PQntuples(count.get()) != 1)
        return statement_error("create count", conn, count, true);
    if (to_i64(count, 0, 0) >= static_cast<std::int64_t>(kMaxSources))
        return fail(Kind::kLimitReached, "the source ceiling is reached");

    pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO revocation_source_store.source (name, ca_subject_name_sha256, created_by) VALUES "
        "($1, $2, $3) ON CONFLICT (ca_subject_name_sha256) DO NOTHING RETURNING id",
        std::vector<std::string>{src.name, src.ca_subject_name_sha256, created_by});
    if (ins.status() != PGRES_TUPLES_OK)
        return statement_error("create insert", conn, ins, true);
    if (PQntuples(ins.get()) != 1) {
        pg::PgResult ex = pg::exec_params(
            conn,
            "SELECT id FROM revocation_source_store.source WHERE ca_subject_name_sha256 = $1",
            std::vector<std::string>{src.ca_subject_name_sha256});
        if (ex.status() != PGRES_TUPLES_OK || PQntuples(ex.get()) != 1)
            return statement_error("create conflict read", conn, ex, true);
        return std::unexpected(RevocationSourceStoreError{Kind::kConflict,
                                                          "a source for this CA is registered",
                                                          to_i64(ex, 0, 0)});
    }
    const std::int64_t id = to_i64(ins, 0, 0);
    for (const auto& k : src.keys)
        if (auto r = insert_key(conn, id, k); !r)
            return std::unexpected(r.error());
    for (const auto& u : src.urls)
        if (auto r = insert_url(conn, id, u); !r)
            return std::unexpected(r.error());
    if (!txn.commit()) {
        const bool lost = PQstatus(conn) == CONNECTION_BAD;
        return fail(lost ? Kind::kOutcomeUnknown : Kind::kQueryError, "create: commit failed");
    }
    return id;
}

std::expected<RevocationSourceUpdate, RevocationSourceStoreError>
RevocationSourceStore::replace(std::int64_t id, const NewRevocationSource& src) {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    if (write_fault_)
        if (const auto k = write_fault_("replace"))
            return fail(*k, "injected write fault");
    if (auto bad = source_error(src))
        return std::unexpected(std::move(*bad));
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("replace", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    PGconn* conn = lease.get();
    if (!begin(conn, "BEGIN"))
        return fail(Kind::kQueryError, "replace: begin failed");
    pg::PgTxn txn(conn);

    pg::PgResult lock = pg::exec_params(
        conn, "SELECT ca_subject_name_sha256 FROM revocation_source_store.source WHERE id = $1::bigint "
              "FOR UPDATE",
        std::vector<std::string>{std::to_string(id)});
    if (lock.status() != PGRES_TUPLES_OK)
        return statement_error("replace lock", conn, lock, true);
    if (PQntuples(lock.get()) != 1)
        return fail(Kind::kNotFound, "no such revocation source");
    if (src.ca_subject_name_sha256 != PQgetvalue(lock.get(), 0, 0))
        return fail(Kind::kSubjectChanged, "the CA subject differs from the registered source");

    auto loaded = load_sources(conn, id);
    if (!loaded)
        return std::unexpected(loaded.error());
    if (loaded->size() != 1)
        return fail(Kind::kNotFound, "no such revocation source");
    RevocationSourceRecord cur = std::move(loaded->front());

    // Equal configuration: nothing to write, no version bump.
    std::set<std::string> cur_keys, new_keys;
    for (const auto& k : cur.keys)
        cur_keys.insert(k.cert_sha256);
    for (const auto& k : src.keys)
        new_keys.insert(k.cert_sha256);
    std::map<std::string, std::string> cur_urls, new_urls; // url -> csv classes
    for (const auto& u : cur.urls)
        cur_urls[u.url] = join_csv(sorted_classes(u.confirmed_address_classes));
    for (const auto& u : src.urls)
        new_urls[u.url] = join_csv(sorted_classes(u.confirmed_address_classes));
    RevocationSourceUpdate out;
    const bool equal = cur.name == src.name && cur_keys == new_keys && cur_urls == new_urls;
    // The caller's precondition, checked under the row lock AFTER the equality test: a body that
    // already IS the stored configuration is a retry of the caller's own committed change (the
    // version moved because of it), which is a no-op success, never a conflict. Only a body that
    // would CHANGE the configuration must prove it was read from the current version, so a stale
    // body (an approved MCP call, a form loaded before another administrator's change) cannot
    // silently revert a newer configuration.
    if (!equal && src.expected_config_version &&
        *src.expected_config_version != cur.config_version) {
        return std::unexpected(RevocationSourceStoreError{
            Kind::kVersionConflict, "config_version has moved on", cur.config_version});
    }
    if (equal) {
        (void)txn.commit();
        out.source = std::move(cur);
        out.changed = false;
        return out;
    }

    pg::PgResult upd = pg::exec_params(
        conn,
        "UPDATE revocation_source_store.source SET name = $2, config_version = config_version + 1, "
        "updated_at = now() WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id), src.name});
    if (upd.status() != PGRES_COMMAND_OK)
        return statement_error("replace update", conn, upd, true);

    // Keys: drop the absent, add the new.
    for (const auto& k : cur.keys) {
        if (new_keys.contains(k.cert_sha256))
            continue;
        pg::PgResult d = pg::exec_params(
            conn,
            "DELETE FROM revocation_source_store.source_ca_key WHERE source_id = $1::bigint AND "
            "cert_sha256 = $2 RETURNING 1",
            std::vector<std::string>{std::to_string(id), k.cert_sha256});
        if (d.status() != PGRES_TUPLES_OK)
            return statement_error("replace drop key", conn, d, true);
        out.dropped_keys += PQntuples(d.get());
    }
    for (const auto& k : src.keys)
        if (!cur_keys.contains(k.cert_sha256))
            if (auto r = insert_key(conn, id, k); !r)
                return std::unexpected(r.error());

    // URLs: dropping one deletes its fetch status and held CRLs (cascade). A retained URL whose
    // confirmed classes changed is updated in place, keeping its id and fetch status.
    for (const auto& u : cur.urls) {
        if (new_urls.contains(u.url))
            continue;
        pg::PgResult d = pg::exec_params(
            conn, "DELETE FROM revocation_source_store.source_url WHERE id = $1::bigint RETURNING 1",
            std::vector<std::string>{std::to_string(u.id)});
        if (d.status() != PGRES_TUPLES_OK)
            return statement_error("replace drop url", conn, d, true);
        out.dropped_urls += PQntuples(d.get());
    }
    for (const auto& u : src.urls) {
        const auto it = cur_urls.find(u.url);
        if (it == cur_urls.end()) {
            if (auto r = insert_url(conn, id, u); !r)
                return std::unexpected(r.error());
        } else if (it->second != new_urls[u.url]) {
            pg::PgResult c = pg::exec_params(
                conn,
                "UPDATE revocation_source_store.source_url SET confirmed_address_classes = $3, host = "
                "$4 WHERE source_id = $1::bigint AND url = $2",
                std::vector<std::string>{std::to_string(id), u.url, new_urls[u.url], u.host});
            if (c.status() != PGRES_COMMAND_OK)
                return statement_error("replace update url", conn, c, true);
        }
    }

    // A dropped key deletes every held CRL that verified only under it. Keyed by SPKI hash: a
    // renewal certificate over the same key keeps the CRLs that key verified.
    std::vector<std::string> spkis;
    for (const auto& k : src.keys)
        spkis.push_back(k.spki_sha256);
    pg::PgResult crl = pg::exec_params(
        conn,
        "DELETE FROM revocation_source_store.crl WHERE source_id = $1::bigint AND "
        "verified_key_sha256 <> ALL($2::text[]) RETURNING 1",
        std::vector<std::string>{std::to_string(id), hex_array_literal(spkis)});
    if (crl.status() != PGRES_TUPLES_OK)
        return statement_error("replace drop crls", conn, crl, true);
    out.crls_deleted = PQntuples(crl.get());

    auto reread = load_sources(conn, id);
    if (!reread)
        return std::unexpected(reread.error());
    if (reread->size() != 1)
        return fail(Kind::kQueryError, "replace: source vanished");
    if (!txn.commit()) {
        const bool lost = PQstatus(conn) == CONNECTION_BAD;
        return fail(lost ? Kind::kOutcomeUnknown : Kind::kQueryError, "replace: commit failed");
    }
    out.source = std::move(reread->front());
    out.changed = true;
    return out;
}

std::expected<void, RevocationSourceStoreError> RevocationSourceStore::remove(std::int64_t id) {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    if (write_fault_)
        if (const auto k = write_fault_("remove"))
            return fail(*k, "injected write fault");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("remove", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    // One statement; the foreign keys cascade the URLs, keys, fetch status, CRLs and entries.
    // rollback_high_water has no foreign key and so survives.
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM revocation_source_store.source WHERE id = $1::bigint RETURNING 1",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK)
        return statement_error("remove", lease.get(), res, true);
    if (PQntuples(res.get()) != 1)
        return fail(Kind::kNotFound, "no such revocation source");
    return {};
}

std::expected<HighWaterReset, RevocationSourceStoreError>
RevocationSourceStore::reset_high_water(std::int64_t id, const std::string& reset_at_rfc3339,
                                        const std::string& pin_crl_sha256) {
    if (!open_)
        return fail(Kind::kNotOpen, "revocation source store is not open");
    if (write_fault_)
        if (const auto k = write_fault_("reset_high_water"))
            return fail(*k, "injected write fault");
    if (!reset_at_rfc3339.empty() && !bindable(reset_at_rfc3339))
        return fail(Kind::kInvalidInput, "invalid reset_at");
    if (!pin_crl_sha256.empty() && !is_lower_hex(pin_crl_sha256, 64))
        return fail(Kind::kInvalidInput, "invalid pin");
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("reset_high_water", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    PGconn* conn = lease.get();
    if (!begin(conn, "BEGIN"))
        return fail(Kind::kQueryError, "reset_high_water: begin failed");
    pg::PgTxn txn(conn);

    pg::PgResult lock = pg::exec_params(
        conn, "SELECT ca_subject_name_sha256 FROM revocation_source_store.source WHERE id = $1::bigint "
              "FOR UPDATE",
        std::vector<std::string>{std::to_string(id)});
    if (lock.status() != PGRES_TUPLES_OK)
        return statement_error("reset lock", conn, lock, true);
    if (PQntuples(lock.get()) != 1)
        return fail(Kind::kNotFound, "no such revocation source");
    const std::string ca = PQgetvalue(lock.get(), 0, 0);

    // The floor: the supplied time (never later than Postgres now()) or now().
    std::vector<std::optional<std::string>> tp;
    if (!reset_at_rfc3339.empty())
        tp.emplace_back(reset_at_rfc3339);
    else
        tp.emplace_back(std::nullopt);
    pg::PgResult when = pg::exec_params(
        conn,
        (std::string("SELECT ts, ts > now(), ") + kEpoch +
         "ts))::bigint FROM (SELECT COALESCE($1::timestamptz, now()) AS ts) q")
            .c_str(),
        tp);
    if (when.status() != PGRES_TUPLES_OK || PQntuples(when.get()) != 1) {
        // An unparseable time is the caller's bad argument (22007/22008), not a store fault.
        const std::string_view code = sqlstate(when);
        if (code == "22007" || code == "22008" || code == "22P02")
            return fail(Kind::kInvalidInput, "invalid reset_at");
        return statement_error("reset time", conn, when, true);
    }
    if (std::string_view(PQgetvalue(when.get(), 0, 1)) == "t")
        return fail(Kind::kBadResetTime, "reset_at is later than the server clock");
    const std::string ts = PQgetvalue(when.get(), 0, 0);
    HighWaterReset out;
    out.reset_at = to_i64(when, 0, 2);
    out.pinned = !pin_crl_sha256.empty();

    // The CA-level row (created if none) takes the floor and the optional pin; every scope row
    // loses its number and thisUpdate (a rebuilt CA restarts both) and takes the same floor. The
    // floor is permanent: a later reset only moves it.
    std::vector<std::optional<std::string>> hp{ca, ts, std::nullopt};
    if (!pin_crl_sha256.empty())
        hp[2] = pin_crl_sha256;
    pg::PgResult hw = pg::exec_params(
        conn,
        "INSERT INTO revocation_source_store.rollback_high_water (ca_subject_name_sha256, scope_key, "
        "reset_at, pinned_crl_sha256) VALUES ($1, '*', $2::timestamptz, $3) ON CONFLICT "
        "(ca_subject_name_sha256, scope_key) DO UPDATE SET reset_at = EXCLUDED.reset_at, "
        "pinned_crl_sha256 = EXCLUDED.pinned_crl_sha256, crl_number = NULL, this_update = NULL",
        hp);
    if (hw.status() != PGRES_COMMAND_OK)
        return statement_error("reset upsert", conn, hw, true);
    pg::PgResult hw2 = pg::exec_params(
        conn,
        "UPDATE revocation_source_store.rollback_high_water SET reset_at = $2::timestamptz, "
        "crl_number = NULL, this_update = NULL WHERE ca_subject_name_sha256 = $1 AND scope_key <> '*'",
        std::vector<std::string>{ca, ts});
    if (hw2.status() != PGRES_COMMAND_OK)
        return statement_error("reset scopes", conn, hw2, true);
    // A reset is a configuration change: in-flight fetches (2b-1b) compare config_version.
    pg::PgResult bump = pg::exec_params(
        conn,
        "UPDATE revocation_source_store.source SET config_version = config_version + 1, "
        "updated_at = now() WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (bump.status() != PGRES_COMMAND_OK)
        return statement_error("reset version", conn, bump, true);
    pg::PgResult crl = pg::exec_params(
        conn, "DELETE FROM revocation_source_store.crl WHERE source_id = $1::bigint RETURNING 1",
        std::vector<std::string>{std::to_string(id)});
    if (crl.status() != PGRES_TUPLES_OK)
        return statement_error("reset crls", conn, crl, true);
    out.crls_deleted = PQntuples(crl.get());
    if (!txn.commit()) {
        const bool lost = PQstatus(conn) == CONNECTION_BAD;
        return fail(lost ? Kind::kOutcomeUnknown : Kind::kQueryError,
                    "reset_high_water: commit failed");
    }
    return out;
}

} // namespace yuzu::server
