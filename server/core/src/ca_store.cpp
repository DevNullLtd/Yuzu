#include "ca_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdlib>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "ca_store";

// Read side. is_revoked()/list_revoked() feed the mTLS-accept gate and CRL construction
// respectively — not "low traffic" in the way issuance/revoke are; matches
// ApiTokenStore::validate_token's hot-path timeout (another security-gate read).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2500};
static_assert(CaStore::kCrlLeaseTimeout == kWriteTimeout,
              "publish_next_crl's default local wait assumes the store's write-lease bound");

// gov UP-5 precedent (every migrated store on this ladder): bounded materialization regardless
// of table growth — an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

constexpr const char* kPgUniqueViolation = "23505";

// ── Small helpers ────────────────────────────────────────────────────────────

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres, mirroring discovery_store.cpp's
// sanitize_pg_text / license_store.cpp's identically-named helper — a bad byte at-rest in a
// legacy ca.db must not brick the mandatory backfill, and revocation_reason in particular is
// operator/REST-supplied (PR4) untrusted text.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// der (CrlVersionRecord::der) can contain 0x00 bytes, which pg::exec_params' text-format binding
// cannot transmit (pg/pg_array.hpp documents this for the array case; it holds for a bare bytea
// param too). Codebase convention (auth_db.cpp's mfa_totp_secret, guaranteed_state_store.cpp's
// signature): hex-encode app-side, `decode($n,'hex')` on write, `encode(col,'hex')` on read —
// avoids libpq's `\x`-prefixed bytea text-output format entirely.
std::string bytes_to_hex(const std::vector<uint8_t>& b) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t byte : b) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break; // malformed — server-authored hex only, defensive stop
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// active=0 (initial); revoked=1 (terminal); unrecognised=2 (maximal — used both as the
// legacy-status validation gate and as the direction check's "always ahead" sentinel, matching
// LicenseStore/DeploymentStore's lifecycle_rank shape).
int cert_status_rank(std::string_view status) {
    if (status == "active")
        return 0;
    if (status == "revoked")
        return 1;
    return 2;
}

// ── Enum bridges ──────────────────────────────────────────────────────────────

CertStatus status_from_string(const std::string& s) {
    return s == "revoked" ? CertStatus::Revoked : CertStatus::Active;
}

} // namespace

std::string ca_mode_to_string(CaMode m) {
    return m == CaMode::Subordinate ? "subordinate" : "builtin";
}
CaMode ca_mode_from_string(const std::string& s) {
    return s == "subordinate" ? CaMode::Subordinate : CaMode::Builtin;
}
std::string cert_status_to_string(CertStatus s) {
    return s == CertStatus::Revoked ? "revoked" : "active";
}

std::optional<std::string> normalize_serial_hex(std::string_view serial) {
    // RFC 5280 serials are <= 20 octets (40 hex chars); cap generously so a
    // pathological multi-megabyte "serial" can't drive an unbounded allocation.
    if (serial.size() > 256)
        return std::nullopt;
    std::string out;
    out.reserve(serial.size());
    for (char c : serial) {
        // Strip the common decorations OpenSSL/operators add (colons, whitespace).
        if (c == ':' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v')
            continue;
        if (c >= '0' && c <= '9')
            out += c;
        else if (c >= 'A' && c <= 'F')
            out += c;
        else if (c >= 'a' && c <= 'f')
            out += static_cast<char>(c - 'a' + 'A'); // canonical uppercase
        else
            return std::nullopt; // any non-hex byte → fail closed
    }
    if (out.empty())
        return std::nullopt;
    // Strip leading zeros so the canonical form matches BN_bn2hex's value
    // semantics (a BIGNUM carries no leading zeros). This makes the form
    // mathematically unique, so an operator-supplied zero-padded serial still
    // matches the stored one. Keep a single digit for the (invalid-but-canonical)
    // zero value rather than collapsing to empty.
    const auto first = out.find_first_not_of('0');
    if (first == std::string::npos)
        out = "0";
    else if (first > 0)
        out.erase(0, first);
    return out;
}

namespace {

// ── Row readers (runtime, public-column-set) ────────────────────────────────

constexpr const char* kIssuedCols =
    "serial_hex, subject, san, purpose, not_after, status, revocation_reason, revoked_at, "
    "issued_at, issued_by, enrollment_request_id, cert_pem, issuer_fingerprint, issuer_key_id";

IssuedCertRecord read_issued_row(PGresult* res, int row) {
    IssuedCertRecord r;
    int c = 0;
    r.serial_hex = text_col(res, row, c++);
    r.subject = text_col(res, row, c++);
    r.san = text_col(res, row, c++);
    r.purpose = text_col(res, row, c++);
    r.not_after = to_i64(PQgetvalue(res, row, c++));
    r.status = status_from_string(text_col(res, row, c++));
    r.revocation_reason = text_col(res, row, c++);
    r.revoked_at = to_i64(PQgetvalue(res, row, c++));
    r.issued_at = to_i64(PQgetvalue(res, row, c++));
    r.issued_by = text_col(res, row, c++);
    r.enrollment_request_id = text_col(res, row, c++);
    r.cert_pem = text_col(res, row, c++);
    r.issuer_fingerprint = text_col(res, row, c++);
    r.issuer_key_id = text_col(res, row, c++);
    return r;
}

// The full revoked set, read on the SUPPLIED connection so `publish_next_crl` can read it inside
// its own transaction (after taking the CRL table lock) rather than on a separate lease.
std::expected<std::vector<IssuedCertRecord>, std::string> query_revoked_on(PGconn* conn) {
    std::string sql = std::string("SELECT ") + kIssuedCols +
                      " FROM ca_store.ca_issued WHERE status = 'revoked' ORDER BY revoked_at";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "list_revoked failed: " + PQerrorMessage(conn));
    const int rows = PQntuples(res.get());
    std::vector<IssuedCertRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_issued_row(res.get(), i));
    return out;
}

// The single INSERT into ca_crl_versions, shared by publish_next_crl and record_crl_for_test so
// the column list and the version/DER guards cannot drift apart.
bool insert_crl_on(PGconn* conn, const CrlVersionRecord& rec) {
    if (rec.der.empty()) {
        spdlog::error("CaStore: refusing to record empty CRL");
        return false;
    }
    if (rec.version < 1) {
        // crlNumber is a positive monotonic sequence (RFC 5280 §5.2.3); version 0 would collide
        // with COALESCE(MAX,0) sentinels and is never legitimate.
        spdlog::error("CaStore: refusing to record CRL with version {} (< 1)", rec.version);
        return false;
    }
    // Plain INSERT (never "ON CONFLICT ... DO UPDATE"): a duplicate version is refused, never a
    // silent clobber of an existing generation.
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO ca_store.ca_crl_versions (version, der, this_update, next_update, "
        "published_at, issuer_fingerprint, issuer_key_id, revoked_count) "
        "VALUES ($1::bigint, decode($2,'hex'), $3::bigint, $4::bigint, $5::bigint, $6, $7, "
        "NULLIF($8, '')::bigint)",
        std::vector<std::string>{
            std::to_string(rec.version), bytes_to_hex(rec.der), std::to_string(rec.this_update),
            std::to_string(rec.next_update), std::to_string(rec.published_at),
            rec.issuer_fingerprint, rec.issuer_key_id,
            rec.revoked_count ? std::to_string(*rec.revoked_count) : std::string{}});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("CaStore: insert of CRL v{} failed: {}", rec.version, PQerrorMessage(conn));
        return false;
    }
    return true;
}

constexpr const char* kRootCols =
    "cert_pem, key_ref, algo, not_before, not_after, fingerprint_sha256, mode, created_at, "
    "chain_pem";

CaRoot read_root_row(PGresult* res, int row) {
    CaRoot r;
    int c = 0;
    r.cert_pem = text_col(res, row, c++);
    r.key_ref = text_col(res, row, c++);
    r.algo = text_col(res, row, c++);
    r.not_before = to_i64(PQgetvalue(res, row, c++));
    r.not_after = to_i64(PQgetvalue(res, row, c++));
    r.fingerprint_sha256 = text_col(res, row, c++);
    r.mode = ca_mode_from_string(text_col(res, row, c++));
    r.created_at = to_i64(PQgetvalue(res, row, c++));
    r.chain_pem = text_col(res, row, c++);
    return r;
}

// ── Migration DDL ────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly. A single consolidated v1 — the SQLite
    // store's v2-v5 ALTERs existed only to upgrade already-deployed local files; no Postgres
    // database predates this store's Postgres schema, so every column ships in v1 here.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE ca_root ("
         "  id                 INTEGER PRIMARY KEY CHECK (id = 1),"
         "  cert_pem           TEXT    NOT NULL,"
         "  key_ref            TEXT    NOT NULL,"
         "  algo               TEXT    NOT NULL,"
         "  not_before         BIGINT  NOT NULL,"
         "  not_after          BIGINT  NOT NULL,"
         "  fingerprint_sha256 TEXT    NOT NULL,"
         "  mode               TEXT    NOT NULL DEFAULT 'builtin',"
         "  created_at         BIGINT  NOT NULL,"
         // Subordinate-CA parent chain (PR6) — empty in Builtin mode.
         "  chain_pem          TEXT    NOT NULL DEFAULT '');"
         "CREATE TABLE ca_issued ("
         "  serial_hex            TEXT   PRIMARY KEY,"
         "  subject               TEXT   NOT NULL,"
         "  san                   TEXT   NOT NULL DEFAULT '',"
         "  purpose               TEXT   NOT NULL DEFAULT '',"
         "  not_after             BIGINT NOT NULL,"
         "  status                TEXT   NOT NULL DEFAULT 'active',"
         "  revocation_reason     TEXT   NOT NULL DEFAULT '',"
         "  revoked_at            BIGINT NOT NULL DEFAULT 0,"
         "  issued_at             BIGINT NOT NULL,"
         // Provenance (CC6.1 "who issued/revoked"; enterprise forensic "produce the exact cert").
         "  issued_by             TEXT   NOT NULL DEFAULT '',"
         "  enrollment_request_id TEXT   NOT NULL DEFAULT '',"
         "  cert_pem              TEXT   NOT NULL DEFAULT '',"
         // Provenance link to the signing root — see IssuedCertRecord's doc comments for the
         // fingerprint-vs-key_id distinction (#1296).
         "  issuer_fingerprint    TEXT   NOT NULL DEFAULT '',"
         "  issuer_key_id         TEXT   NOT NULL DEFAULT '');"
         "CREATE INDEX idx_ca_issued_status ON ca_issued(status) WHERE status = 'revoked';"
         "CREATE INDEX idx_ca_issued_issued_at ON ca_issued(issued_at);"
         "CREATE INDEX idx_ca_issued_issuer_key_id ON ca_issued(issuer_key_id);"
         "CREATE TABLE ca_crl_versions ("
         "  version            BIGINT PRIMARY KEY,"
         "  der                BYTEA  NOT NULL,"
         "  this_update        BIGINT NOT NULL,"
         "  next_update        BIGINT NOT NULL,"
         "  published_at       BIGINT NOT NULL,"
         "  issuer_fingerprint TEXT   NOT NULL DEFAULT '',"
         "  issuer_key_id      TEXT   NOT NULL DEFAULT '');"
         // ADR-0009 backfill idempotency marker — see ADR-0053's Update: migrate_from_sqlite()
         // is retired, so this table has no remaining writer.
         "CREATE TABLE sqlite_backfill_source ("
         "  fingerprint  TEXT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL);"},
        // migrate_from_sqlite() retired (#3623, ADR-0053 Update) — sqlite_backfill_source was
        // its sole idempotency marker. Appended at the next free slot, never renumbering v1
        // (PgMigrationRunner applies only version > current — renumbering an already-shipped
        // version re-applies it against a database that already ran it).
        {2, "DROP TABLE IF EXISTS sqlite_backfill_source;"},
        // HA WS-6 6.1: how many revoked certs each CRL was built from, so the freshness pass
        // can tell — without comparing timestamps written by different replicas' clocks —
        // whether a revocation is missing from the latest CRL. NULL on rows published before v3
        // reads as "not covered" (normally superseded at once by the startup publish).
        // The ALTER needs ACCESS EXCLUSIVE on a table publishers lock; bound the wait so boot
        // fails loudly (and retries on restart) rather than hanging behind a stalled holder.
        // 30 s rather than the pool's usual 10 s: long enough to outlast a legitimate publish
        // that holds the lock (5 s lock wait + statements under a 30 s statement_timeout).
        {3, "SET LOCAL lock_timeout = '30s'; "
            "ALTER TABLE ca_crl_versions ADD COLUMN revoked_count BIGINT;"},
        // The revoked set is append-only, enforced by the database rather than by the one
        // WHERE clause in delete_issued_by(): an older binary sharing this schema during a
        // rolling upgrade or rollback still runs the unconditional pre-6.1 DELETE, which would
        // un-revoke the cert (is_revoked() accepts it again, later CRLs drop it). Row triggers
        // do not fire on TRUNCATE, so the documented clean re-root still works. It rejects ANY
        // update of a revoked row, so a future migration that backfills a ca_issued column must
        // account for it (skip revoked rows, or ALTER TABLE ... DISABLE TRIGGER inside that
        // migration's own transaction), and an expiry-based prune of revoked rows would need a
        // deliberate change here. The lock_timeout bounds CREATE TRIGGER's wait on ca_issued.
        {4, "SET LOCAL lock_timeout = '30s'; "
            "CREATE FUNCTION ca_issued_keep_revoked() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN "
            "  RAISE EXCEPTION 'ca_issued: a revoked certificate row (serial %) cannot be % "
            "(revocations are append-only)', OLD.serial_hex, lower(TG_OP) "
            "    USING ERRCODE = 'integrity_constraint_violation'; "
            "END $$; "
            "CREATE TRIGGER ca_issued_keep_revoked BEFORE DELETE OR UPDATE ON ca_issued "
            "FOR EACH ROW WHEN (OLD.status = 'revoked') "
            "EXECUTE FUNCTION ca_issued_keep_revoked();"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

CaStore::CaStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CaStore: no database connection at construction ({}) — CA persistence "
                      "disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CaStore: schema migration failed — CA persistence disabled");
        return;
    }
    open_ = true;
}

CaStore::~CaStore() = default;

// ── Root ──────────────────────────────────────────────────────────────────────

std::expected<std::optional<CaRoot>, std::string> CaStore::get_root() {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    std::string sql = std::string("SELECT ") + kRootCols + " FROM ca_store.ca_root WHERE id = 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "get_root failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<CaRoot>{std::nullopt};
    return std::optional<CaRoot>{read_root_row(res.get(), 0)};
}

bool CaStore::has_root() {
    auto r = get_root();
    return r.has_value() && r->has_value();
}

std::expected<void, std::string> CaStore::set_root(const CaRoot& root) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    if (root.cert_pem.empty() || root.key_ref.empty())
        return std::unexpected("refusing to set root with empty cert/key_ref");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO ca_store.ca_root (id, cert_pem, key_ref, algo, not_before, not_after, "
        "fingerprint_sha256, mode, created_at, chain_pem) "
        "VALUES (1,$1,$2,$3,$4::bigint,$5::bigint,$6,$7,$8::bigint,$9) "
        "ON CONFLICT (id) DO UPDATE SET cert_pem=EXCLUDED.cert_pem, key_ref=EXCLUDED.key_ref, "
        "algo=EXCLUDED.algo, not_before=EXCLUDED.not_before, not_after=EXCLUDED.not_after, "
        "fingerprint_sha256=EXCLUDED.fingerprint_sha256, mode=EXCLUDED.mode, "
        "created_at=EXCLUDED.created_at, chain_pem=EXCLUDED.chain_pem "
        "RETURNING id",
        std::vector<std::string>{sanitize_pg_text(root.cert_pem), root.key_ref, root.algo,
                                 std::to_string(root.not_before), std::to_string(root.not_after),
                                 root.fingerprint_sha256, ca_mode_to_string(root.mode),
                                 std::to_string(root.created_at ? root.created_at : now_epoch()),
                                 sanitize_pg_text(root.chain_pem)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "set_root failed: " + PQerrorMessage(lease.get()));
    return {};
}

std::expected<CaRoot, std::string> CaStore::try_insert_root(const CaRoot& root) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    if (root.cert_pem.empty() || root.key_ref.empty())
        return std::unexpected("refusing to insert root with empty cert/key_ref");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    const std::string sanitized_cert = sanitize_pg_text(root.cert_pem);
    const std::string sanitized_chain = sanitize_pg_text(root.chain_pem);
    std::string sql = std::string("INSERT INTO ca_store.ca_root (id, cert_pem, key_ref, algo, "
                                  "not_before, not_after, fingerprint_sha256, mode, created_at, "
                                  "chain_pem) VALUES (1,$1,$2,$3,$4::bigint,$5::bigint,$6,$7,"
                                  "$8::bigint,$9) ON CONFLICT (id) DO NOTHING RETURNING ") +
                      kRootCols;
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{sanitized_cert, root.key_ref, root.algo,
                                 std::to_string(root.not_before), std::to_string(root.not_after),
                                 root.fingerprint_sha256, ca_mode_to_string(root.mode),
                                 std::to_string(root.created_at ? root.created_at : now_epoch()),
                                 sanitized_chain});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "try_insert_root failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) > 0) {
        spdlog::info("CaStore: try_insert_root won the first-boot race (fingerprint {})",
                     root.fingerprint_sha256);
        return read_root_row(res.get(), 0);
    }
    // Lost — read back the winner.
    std::string sel = std::string("SELECT ") + kRootCols + " FROM ca_store.ca_root WHERE id = 1";
    pg::PgResult existing = pg::exec_params(lease.get(), sel.c_str(), std::vector<std::string>{});
    if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "try_insert_root lost the race but the winning row could not be "
                               "read back: " +
                               PQerrorMessage(lease.get()));
    const CaRoot winner = read_root_row(existing.get(), 0);
    spdlog::warn("CaStore: try_insert_root LOST the first-boot race — ca_store already holds a "
                "DIFFERENT root (fingerprint {}) than the one just generated (fingerprint {}). "
                "The caller's freshly-generated key material is unusable and must be discarded.",
                winner.fingerprint_sha256, root.fingerprint_sha256);
    return winner;
}

// ── Issued inventory ────────────────────────────────────────────────────────────

std::expected<void, std::string> CaStore::record_issued(const IssuedCertRecord& rec) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    // Canonicalise the serial at the write boundary so a later revoke()/is_revoked() lookup
    // matches regardless of case/colon decoration. Fail closed on a non-hex serial — never store
    // a cert we couldn't later revoke.
    const auto serial = normalize_serial_hex(rec.serial_hex);
    if (!serial)
        return std::unexpected("refusing to record issued cert with empty/non-hex serial (len " +
                               std::to_string(rec.serial_hex.size()) + ")");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO ca_store.ca_issued (serial_hex, subject, san, purpose, not_after, status, "
        "revocation_reason, revoked_at, issued_at, issued_by, enrollment_request_id, cert_pem, "
        "issuer_fingerprint, issuer_key_id) "
        "VALUES ($1,$2,$3,$4,$5::bigint,$6,$7,$8::bigint,$9::bigint,$10,$11,$12,$13,$14)",
        std::vector<std::string>{
            *serial, sanitize_pg_text(rec.subject), sanitize_pg_text(rec.san),
            sanitize_pg_text(rec.purpose), std::to_string(rec.not_after),
            cert_status_to_string(rec.status), sanitize_pg_text(rec.revocation_reason),
            std::to_string(rec.revoked_at), std::to_string(rec.issued_at ? rec.issued_at : now_epoch()),
            sanitize_pg_text(rec.issued_by), sanitize_pg_text(rec.enrollment_request_id),
            sanitize_pg_text(rec.cert_pem), rec.issuer_fingerprint, rec.issuer_key_id});
    if (res.status() != PGRES_COMMAND_OK) {
        // #1276 (record_issued's flake lead): x509_ca mints a random 128-bit serial per
        // issuance, so a genuine collision is astronomically unlikely in production — a real
        // SQLSTATE 23505 here is far more likely a test fixture reusing a fixed serial than a
        // live collision. Classified distinctly regardless: the caller (server.cpp) can retry
        // issuance with a freshly-minted serial rather than treating this as an outage.
        const char* sqlstate = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        if (sqlstate && std::string_view(sqlstate) == kPgUniqueViolation)
            return std::unexpected(std::string(kCaDuplicateSerialPrefix) + *serial);
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "record_issued failed: " + PQerrorMessage(lease.get()));
    }
    return {};
}

std::expected<std::optional<IssuedCertRecord>, std::string>
CaStore::get_issued(const std::string& serial_hex) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial)
        return std::optional<IssuedCertRecord>{std::nullopt}; // non-hex → no such cert
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    std::string sql =
        std::string("SELECT ") + kIssuedCols + " FROM ca_store.ca_issued WHERE serial_hex = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{*serial});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "get_issued failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<IssuedCertRecord>{std::nullopt};
    return std::optional<IssuedCertRecord>{read_issued_row(res.get(), 0)};
}

std::expected<std::vector<IssuedCertRecord>, std::string> CaStore::list_issued(int limit,
                                                                                int offset) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    if (limit < 0 || limit > kListRowCap)
        limit = kListRowCap;
    if (offset < 0)
        offset = 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    // serial_hex (unique) is a deterministic secondary sort key — see the pre-migration store's
    // pagination-stability note.
    std::string sql = std::string("SELECT ") + kIssuedCols +
                      " FROM ca_store.ca_issued ORDER BY issued_at DESC, serial_hex DESC "
                      "LIMIT $1 OFFSET $2";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "list_issued failed: " + PQerrorMessage(lease.get()));
    const int rows = PQntuples(res.get());
    std::vector<IssuedCertRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_issued_row(res.get(), i));
    return out;
}

std::expected<std::vector<IssuedCertRecord>, std::string>
CaStore::list_issued_by_key_id(const std::string& issuer_key_id, int limit, int offset) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    // An EMPTY key id is the historical-row sentinel (pre-v5 / unpopulated), NOT a CA identity —
    // returning those would conflate "issued by this CA" with "we don't know". Fail closed.
    if (issuer_key_id.empty())
        return std::vector<IssuedCertRecord>{};
    if (limit < 0 || limit > kListRowCap)
        limit = kListRowCap;
    if (offset < 0)
        offset = 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    std::string sql = std::string("SELECT ") + kIssuedCols +
                      " FROM ca_store.ca_issued WHERE issuer_key_id = $1 "
                      "ORDER BY issued_at DESC, serial_hex DESC LIMIT $2 OFFSET $3";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{issuer_key_id, std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "list_issued_by_key_id failed: " + PQerrorMessage(lease.get()));
    const int rows = PQntuples(res.get());
    std::vector<IssuedCertRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_issued_row(res.get(), i));
    return out;
}

std::expected<bool, std::string> CaStore::revoke(const std::string& serial_hex,
                                                  const std::string& reason) {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial)
        return false; // non-hex → no such cert to revoke (genuine business answer, not an error)
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    // RETURNING carries the change — never sqlite3_changes()-style counting (#1033 idiom).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE ca_store.ca_issued SET status = 'revoked', revocation_reason = $1, "
        "revoked_at = $2::bigint WHERE serial_hex = $3 AND status != 'revoked' "
        "RETURNING serial_hex",
        std::vector<std::string>{sanitize_pg_text(reason), std::to_string(now_epoch()), *serial});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "revoke failed: " + PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

bool CaStore::is_revoked(const std::string& serial_hex) {
    if (!open_) {
        spdlog::error("CaStore::is_revoked: database not open — failing closed (revoked)");
        return true;
    }
    // Canonicalise so the lookup matches the stored form. This is a SECURITY gate ("reject if
    // revoked"); a serial that won't normalise to hex cannot be one of our issued certs, so fail
    // closed — treat it as revoked (reject) rather than silently returning "not revoked". In
    // practice every real caller passes a BN_bn2hex-form serial from a chain-verified leaf, so
    // this branch is unreachable on the happy path.
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial) {
        // Don't echo the raw serial (untrusted → CRLF/log-forging risk).
        spdlog::warn("CaStore::is_revoked: non-hex serial (len {}) — failing closed (revoked)",
                     serial_hex.size());
        return true;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        // Distinct log line (ADR-0053): during a sustained outage every mTLS accept fails closed
        // fleet-wide via this path — an operator needs to be able to tell that apart from a real
        // mass-revocation sweep from logs/metrics alone, since the bool return itself cannot.
        spdlog::error("CaStore::is_revoked: database unavailable ({}) — failing closed (revoked) "
                      "for serial (canonicalised, len {}); this is a DEGRADED-DB rejection, NOT "
                      "a real revocation — if heartbeats/Subscribe/Register are failing "
                      "fleet-wide, check Postgres reachability before assuming mass compromise",
                      pool_.last_error(), serial->size());
        return true;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT 1 FROM ca_store.ca_issued WHERE serial_hex = $1 AND status = 'revoked'",
        std::vector<std::string>{*serial});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("CaStore::is_revoked: query failed ({}) — failing closed (revoked); this "
                      "is a DEGRADED-DB rejection, NOT a real revocation",
                      PQerrorMessage(lease.get()));
        return true;
    }
    return PQntuples(res.get()) > 0;
}

std::expected<std::vector<IssuedCertRecord>, std::string> CaStore::list_revoked() {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    return query_revoked_on(lease.get());
}

std::expected<std::vector<std::string>, std::string> CaStore::list_revoked_serials() {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    // No cert_pem (unbounded blob), no ORDER BY — this is the sweep-tick-cheap
    // variant of list_revoked(); hits the same idx_ca_issued_status partial
    // index, but returns nothing list_revoked()'s heavier row shape does.
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT serial_hex FROM ca_store.ca_issued WHERE status = 'revoked'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "list_revoked_serials failed: " + PQerrorMessage(lease.get()));
    const int serial_rows = PQntuples(res.get());
    std::vector<std::string> serials;
    serials.reserve(static_cast<std::size_t>(serial_rows));
    // text_col(), not raw PQgetvalue — serial_hex is PRIMARY KEY (NOT NULL) today
    // so this is idiom consistency (matches read_issued_row's use of the same
    // helper for the identical column) rather than a live defect, cpp-safety NICE.
    for (int i = 0; i < serial_rows; ++i)
        serials.push_back(text_col(res.get(), i, 0));
    return serials;
}

bool CaStore::delete_issued_by(const std::string& issued_by) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;
    // Never delete a revoked row: it is the record that keeps the cert rejected by is_revoked()
    // and listed in every later CRL, and it keeps the revoked set append-only, which
    // has_unpublished_revocations() relies on.
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "DELETE FROM ca_store.ca_issued WHERE issued_by = $1 "
                                       "AND status <> 'revoked'",
                                       std::vector<std::string>{sanitize_pg_text(issued_by)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("CaStore::delete_issued_by: failed: {}", PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

// ── CRL versions ────────────────────────────────────────────────────────────────

std::expected<std::uint64_t, std::string> CaStore::next_crl_number() {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COALESCE(MAX(version), 0) + 1 FROM ca_store.ca_crl_versions",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "next_crl_number failed: " + PQerrorMessage(lease.get()));
    return static_cast<std::uint64_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

bool CaStore::record_crl_for_test(const CrlVersionRecord& rec) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("CaStore::record_crl_for_test: database unavailable");
        return false;
    }
    CrlVersionRecord stamped = rec;
    if (!stamped.published_at)
        stamped.published_at = now_epoch();
    return insert_crl_on(lease.get(), stamped);
}

std::expected<bool, std::string> CaStore::has_unpublished_revocations() {
    if (!open_)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kCaDbErrorPrefix) + "database unavailable — try again");
    // One statement, one snapshot. The revoked set is append-only (revoke() never un-revokes and
    // delete_issued_by() keeps revoked rows), so a count that differs from the one the latest
    // CRL was built from means that CRL does not cover the current set. No CRL at all, or a
    // pre-v3 row (NULL count), also reads as "not covered". Deleting a revoked row by hand breaks
    // that assumption (and un-revokes the cert) — see pki-architecture.md.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT (SELECT revoked_count FROM ca_store.ca_crl_versions ORDER BY version DESC "
        "LIMIT 1) IS DISTINCT FROM (SELECT COUNT(*) FROM ca_store.ca_issued "
        "WHERE status = 'revoked')",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kCaDbErrorPrefix) +
                               "has_unpublished_revocations failed: " +
                               PQerrorMessage(lease.get()));
    return std::string_view(PQgetvalue(res.get(), 0, 0)) == "t";
}

std::optional<CrlVersionRecord> CaStore::latest_crl() {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT version, encode(der,'hex'), this_update, next_update, published_at, "
        "issuer_fingerprint, issuer_key_id, revoked_count FROM ca_store.ca_crl_versions "
        "ORDER BY version DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    CrlVersionRecord r;
    int c = 0;
    r.version = to_i64(PQgetvalue(res.get(), 0, c++));
    r.der = hex_to_bytes(text_col(res.get(), 0, c++));
    r.this_update = to_i64(PQgetvalue(res.get(), 0, c++));
    r.next_update = to_i64(PQgetvalue(res.get(), 0, c++));
    r.published_at = to_i64(PQgetvalue(res.get(), 0, c++));
    r.issuer_fingerprint = text_col(res.get(), 0, c++);
    r.issuer_key_id = text_col(res.get(), 0, c++);
    if (!PQgetisnull(res.get(), 0, c))
        r.revoked_count = to_i64(PQgetvalue(res.get(), 0, c));
    return r;
}

std::expected<CrlVersionRecord, CaStore::PublishError>
CaStore::publish_next_crl(const CrlBuilder& build, const std::string& issuer_fingerprint,
                          const std::string& issuer_key_id,
                          std::chrono::milliseconds local_wait) {
    if (!build || !open_) {
        spdlog::error("CaStore::publish_next_crl: {} — CRL not published",
                      !open_ ? "store not open" : "no CRL builder supplied");
        return std::unexpected(PublishError::Failed);
    }
    // Bounded, not "until the holder finishes": a holder can legitimately run longer (up to
    // kCrlStatementTimeout per statement), and giving up here is healed by the freshness pass.
    std::unique_lock local(publish_mu_, std::defer_lock);
    if (!local.try_lock_for(local_wait)) {
        spdlog::warn("CaStore::publish_next_crl: another CRL publish in this process is still "
                     "running after {} ms — not publishing",
                     local_wait.count());
        return std::unexpected(PublishError::Busy);
    }
    std::optional<CrlVersionRecord> published;
    bool txn_body_ran = false;
    bool root_changed = false;
    const bool committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        txn_body_ran = true;
        // Transaction-scoped bounds: they hold even when the pool could not set its own at
        // connect time (a DSN carrying `options=`, or PGOPTIONS). lock_timeout bounds OUR wait;
        // idle_in_transaction_session_timeout bounds how long WE can hold the lock if this
        // process is frozen mid-transaction (SIGSTOP, a paused container), so a stalled holder
        // cannot block every other replica's publish indefinitely.
        pg::PgResult bounds = pg::exec_params(
            conn,
            "SELECT set_config('lock_timeout', $1, true), "
            "set_config('statement_timeout', $2, true), "
            "set_config('idle_in_transaction_session_timeout', $2, true)",
            std::vector<std::string>{std::to_string(kCrlLockTimeout.count()) + "ms",
                                     std::to_string(kCrlStatementTimeout.count()) + "ms"});
        if (bounds.status() != PGRES_TUPLES_OK) {
            spdlog::error("CaStore::publish_next_crl: setting txn timeouts failed: {} — aborting",
                          PQerrorMessage(conn));
            return false;
        }
        // SHARE ROW EXCLUSIVE conflicts with itself and with the ROW EXCLUSIVE any INSERT takes,
        // so every publisher on every replica — and any writer that doesn't opt in, which an
        // advisory lock would not stop — queues here until the holder commits or rolls back. It
        // does NOT conflict with the ACCESS SHARE a plain SELECT takes, so `latest_crl()` /
        // `GET /api/v1/ca/crl` keep serving throughout.
        pg::PgResult lock = pg::exec_params(
            conn, "LOCK TABLE ca_store.ca_crl_versions IN SHARE ROW EXCLUSIVE MODE",
            std::vector<std::string>{});
        if (lock.status() != PGRES_COMMAND_OK) {
            spdlog::error("CaStore::publish_next_crl: CRL table lock failed: {} — aborting",
                          PQerrorMessage(conn));
            return false;
        }
        // The caller read the root and loaded its key before the lock. A subordinate import that
        // committed in between would otherwise let this publish record a CRL signed under the
        // superseded issuer AFTER the import's own CRL, so the latest CRL would carry the wrong
        // issuer until the next publish. FOR SHARE also holds the root row until this
        // transaction ends, so an import cannot swap it between this check and our COMMIT (its
        // UPDATE waits, then publishes its own CRL after ours).
        if (!issuer_fingerprint.empty()) {
            pg::PgResult root = pg::exec_params(
                conn, "SELECT fingerprint_sha256 FROM ca_store.ca_root WHERE id = 1 FOR SHARE",
                std::vector<std::string>{});
            if (root.status() != PGRES_TUPLES_OK) {
                spdlog::error("CaStore::publish_next_crl: root re-read failed: {} — aborting",
                              PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(root.get()) != 1 || text_col(root.get(), 0, 0) != issuer_fingerprint) {
                spdlog::warn("CaStore::publish_next_crl: CA root changed since the caller loaded "
                             "it — aborting so the caller re-reads the root");
                root_changed = true;
                return false;
            }
        }
        pg::PgResult num = pg::exec_params(
            conn, "SELECT COALESCE(MAX(version), 0) + 1 FROM ca_store.ca_crl_versions",
            std::vector<std::string>{});
        if (num.status() != PGRES_TUPLES_OK) {
            spdlog::error("CaStore::publish_next_crl: number read failed: {} — aborting",
                          PQerrorMessage(conn));
            return false;
        }
        const auto number = static_cast<std::uint64_t>(to_i64(PQgetvalue(num.get(), 0, 0)));
        // Read AFTER the lock: every revocation committed before the previous CRL's commit is
        // visible to this statement, so CRL N+1 is always a superset of CRL N. A revocation
        // committing after this read is covered by that revoke's own publish (queued behind this
        // one) or, if that publish fails, by the freshness pass's unpublished-revocation check.
        auto revoked = query_revoked_on(conn);
        if (!revoked) {
            spdlog::error("CaStore::publish_next_crl: {} — aborting (never build a CRL over a "
                          "possibly-incomplete revoked set)",
                          revoked.error());
            return false;
        }
        auto built = build(number, *revoked);
        if (!built || built->der.empty()) {
            spdlog::error("CaStore::publish_next_crl: build produced no DER (version {})", number);
            return false; // rolled back → the number is not consumed
        }
        CrlVersionRecord rec;
        rec.version = static_cast<int64_t>(number);
        rec.der = std::move(built->der);
        rec.this_update = built->this_update;
        rec.next_update = built->next_update;
        rec.published_at = now_epoch();
        rec.issuer_fingerprint = issuer_fingerprint;
        rec.issuer_key_id = issuer_key_id;
        rec.revoked_count = static_cast<int64_t>(revoked->size());
        if (!insert_crl_on(conn, rec))
            return false;
        published = std::move(rec);
        return true;
    });
    if (!txn_body_ran)
        spdlog::error("CaStore::publish_next_crl: no database connection within {} ms ({}) — "
                      "CRL not published",
                      kWriteTimeout.count(), pool_.last_error());
    if (root_changed)
        return std::unexpected(PublishError::RootChanged);
    // A lost COMMIT acknowledgement reports failure even if Postgres committed. That is the safe
    // direction: the caller reports "not republished", and the next publish takes the next number.
    if (!committed || !published)
        return std::unexpected(PublishError::Failed);
    return std::move(*published);
}

} // namespace yuzu::server
