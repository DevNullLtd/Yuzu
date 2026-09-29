#include "upload_grant_store.hpp"

#include "evp_raii.hpp"
#include "upload_grant_parsers.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/server/auth.hpp> // AuthManager::random_bytes/bytes_to_hex — per frozen protocol

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <memory>
#include <stdexcept>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "upload_grant_store";

// Bounded acquires (ADR-0012 §2). Grant/session redemption authenticates a
// request, same tier as ApiTokenStore's read/write split; mutations get a
// little more room than reads.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to upload_grant_store for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE grants ("
         "  grant_id          TEXT PRIMARY KEY,"
         "  agent_id          TEXT NOT NULL,"
         "  source_path       TEXT NOT NULL DEFAULT '',"
         "  declared_max_size BIGINT NOT NULL,"
         "  expected_sha256   TEXT NOT NULL DEFAULT '',"
         "  retention_class   TEXT NOT NULL DEFAULT 'standard',"
         "  destination_key   TEXT NOT NULL,"
         "  grant_secret_hash TEXT NOT NULL UNIQUE,"
         "  state             TEXT NOT NULL DEFAULT 'minted' "
         "    CHECK (state IN ('minted','redeemed','revoked')),"
         "  minted_by         TEXT NOT NULL DEFAULT '',"
         "  created_at        BIGINT NOT NULL DEFAULT 0,"
         "  expires_at        BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX grants_agent_idx ON grants (agent_id);"
         ""
         "CREATE TABLE sessions ("
         "  upload_id           TEXT PRIMARY KEY,"
         "  grant_id             TEXT NOT NULL,"
         "  agent_id             TEXT NOT NULL,"
         "  destination_key      TEXT NOT NULL,"
         "  declared_max_size    BIGINT NOT NULL,"
         "  expected_sha256      TEXT NOT NULL DEFAULT '',"
         "  retention_class      TEXT NOT NULL DEFAULT 'standard',"
         "  session_secret_hash  TEXT NOT NULL UNIQUE,"
         "  state                TEXT NOT NULL DEFAULT 'open' "
         "    CHECK (state IN ('open','committed','cancelled','expired')),"
         "  recorded_offset      BIGINT NOT NULL DEFAULT 0,"
         "  created_at           BIGINT NOT NULL DEFAULT 0,"
         "  expires_at           BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX sessions_grant_idx ON sessions (grant_id);"
         ""
         "CREATE TABLE completed_uploads ("
         "  upload_id        TEXT PRIMARY KEY,"
         "  grant_id         TEXT NOT NULL,"
         "  agent_id         TEXT NOT NULL,"
         "  destination_key  TEXT NOT NULL,"
         "  actual_size      BIGINT NOT NULL,"
         "  verified_hash    TEXT NOT NULL,"
         "  retention_class  TEXT NOT NULL DEFAULT 'standard',"
         "  received_at      BIGINT NOT NULL DEFAULT 0);"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? std::string{} : std::string(PQgetvalue(res, row, c));
}

UploadGrantRow read_grant_row(PGresult* res, int row) {
    UploadGrantRow g;
    int c = 0;
    g.grant_id = col(res, row, c++);
    g.agent_id = col(res, row, c++);
    g.source_path = col(res, row, c++);
    g.declared_max_size = to_i64(col(res, row, c++).c_str());
    g.expected_sha256 = col(res, row, c++);
    g.retention_class = col(res, row, c++);
    g.destination_key = col(res, row, c++);
    g.state = col(res, row, c++);
    g.minted_by = col(res, row, c++);
    g.created_at = to_i64(col(res, row, c++).c_str());
    g.expires_at = to_i64(col(res, row, c++).c_str());
    return g;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────

UploadGrantStore::UploadGrantStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("UploadGrantStore: no database connection at construction ({}) — upload "
                      "grant store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("UploadGrantStore: schema migration failed — upload grant store disabled");
        return;
    }
    open_ = true;
    spdlog::info("UploadGrantStore: opened (schema {})", kStoreName);
}

namespace {

// SHA-256 hex over a short in-memory secret (grant/session secrets — a few
// dozen bytes). Streaming file digests at commit time are a SEPARATE
// concern handled entirely in file_retrieval_routes.cpp (this store never
// touches the blob itself). Cross-platform OpenSSL EVP, matching
// plugin_signing_helpers.cpp's pattern — no Windows/BCrypt branch needed
// (OpenSSL is already a hard dep via gRPC TLS, per secure_random.hpp).
//
// Returns "" on ANY digest failure (context alloc, init, update or final) —
// callers MUST treat an empty result as a hard failure, never as a
// comparable value: `digest_ok` below is the one place that distinction is
// enforced, so a persistently-broken digest provider can never make every
// presented secret hash to the same stored "" and authenticate.
std::string sha256_hex_impl(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return {};
    bool ok = EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1 &&
             EVP_DigestUpdate(ctx.get(), input.data(), input.size()) == 1;
    unsigned int out_len = 0;
    ok = ok && EVP_DigestFinal_ex(ctx.get(), digest, &out_len) == 1 &&
         out_len == SHA256_DIGEST_LENGTH;
    if (!ok)
        return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

/// A genuine SHA-256 hex digest is always exactly 64 lowercase hex chars;
/// `sha256_hex_impl` returning anything else (in practice only "") means the
/// digest provider failed. Gates EVERY persist and EVERY comparison that
/// touches a `sha256_hex_impl` result — see that function's doc comment.
bool digest_ok(const std::string& hex) { return hex.size() == SHA256_DIGEST_LENGTH * 2; }

} // namespace

// ── Mint ─────────────────────────────────────────────────────────────────

std::expected<UploadGrantMinted, MintFailure>
UploadGrantStore::mint(const UploadGrantMintParams& params, std::int64_t now) {
    if (!open_)
        return std::unexpected(MintFailure{MintError::kUnavailable, "database not open"});
    if (params.agent_id.empty())
        return std::unexpected(MintFailure{MintError::kInvalidInput, "agent_id is required"});
    if (params.declared_max_size <= 0)
        return std::unexpected(
            MintFailure{MintError::kInvalidInput, "declared_max_size must be positive"});

    const std::string retention =
        params.retention_class.empty() ? "standard" : params.retention_class;
    if (!upload_grant::is_valid_retention_class(retention))
        return std::unexpected(MintFailure{MintError::kInvalidInput, "invalid retention_class"});

    std::string grant_id, grant_secret;
    try {
        grant_id = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        grant_secret = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
    } catch (const std::exception& e) {
        return std::unexpected(
            MintFailure{MintError::kUnavailable, std::string("CSPRNG unavailable: ") + e.what()});
    }
    const auto secret_hash = sha256_hex_impl(grant_secret);
    if (!digest_ok(secret_hash))
        return std::unexpected(MintFailure{MintError::kUnavailable, "digest provider unavailable"});
    const auto destination_key = upload_grant::derive_destination_key(retention, grant_id);
    const auto ttl = upload_grant::resolve_grant_ttl_secs(params.requested_ttl_secs);
    const auto expires_at = now + ttl;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(
            MintFailure{MintError::kUnavailable, "database unavailable — try again"});

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO upload_grant_store.grants "
        "(grant_id, agent_id, source_path, declared_max_size, expected_sha256, retention_class, "
        " destination_key, grant_secret_hash, state, minted_by, created_at, expires_at) "
        "VALUES ($1,$2,$3,$4::bigint,$5,$6,$7,$8,'minted',$9,$10::bigint,$11::bigint) "
        "RETURNING grant_id",
        std::vector<std::string>{grant_id, params.agent_id, params.source_path,
                                 std::to_string(params.declared_max_size), params.expected_sha256,
                                 retention, destination_key, secret_hash, params.minted_by,
                                 std::to_string(now), std::to_string(expires_at)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(MintFailure{
            MintError::kUnavailable, std::string("failed to mint grant: ") + PQerrorMessage(lease.get())});

    return UploadGrantMinted{grant_id, grant_secret, expires_at, destination_key};
}

// ── Operator list / revoke ──────────────────────────────────────────────

std::expected<std::vector<UploadGrantRow>, std::string>
UploadGrantStore::list_for_agent(const std::string& agent_id) const {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql =
        "SELECT grant_id, agent_id, source_path, declared_max_size, expected_sha256, "
        "retention_class, destination_key, state, minted_by, created_at, expires_at "
        "FROM upload_grant_store.grants";
    std::vector<std::string> params;
    if (!agent_id.empty()) {
        sql += " WHERE agent_id = $1";
        params.push_back(agent_id);
    }
    sql += " ORDER BY created_at DESC";

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("list_for_agent read failed: ") +
                               PQerrorMessage(lease.get()));

    std::vector<UploadGrantRow> out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_grant_row(res.get(), i));
    return out;
}

std::expected<bool, std::string> UploadGrantStore::revoke(const std::string& grant_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (grant_id.empty())
        return false;

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE upload_grant_store.grants SET state='revoked' "
        "WHERE grant_id=$1 AND state='minted' RETURNING grant_id",
        std::vector<std::string>{grant_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke failed: ") + PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

// ── Session open (the atomic single-redemption operation) ──────────────

OpenSessionResult UploadGrantStore::open_session(const std::string& grant_id,
                                                 const std::string& presented_secret,
                                                 std::int64_t now) {
    OpenSessionResult result;
    if (!open_ || grant_id.empty() || presented_secret.empty()) {
        result.outcome = OpenSessionOutcome::kGrantUnknown;
        return result;
    }

    // Step 1: plain lookup by id — NOT gated by secret. The frozen
    // protocol's atomic redemption UPDATE conditions only on
    // grant_id/state/expiry (below); the secret check is this separate step.
    // Scoped to its OWN lease, released before Step 4 below acquires a
    // transaction lease of its own — holding this one open across that call
    // would tie up a SECOND connection for the duration (pg_pool.hpp's own
    // nesting warning: fine on a multi-connection pool, but needlessly
    // doubles this request's connection footprint and can starve a
    // small/saturated pool).
    std::string stored_hash, state, agent_id, destination_key, expected_sha256, retention_class;
    std::int64_t expires_at = 0, declared_max_size = 0;
    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease) {
            result.outcome = OpenSessionOutcome::kUnavailable;
            return result;
        }

        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT grant_secret_hash, state, expires_at, agent_id, destination_key, "
            "declared_max_size, expected_sha256, retention_class "
            "FROM upload_grant_store.grants WHERE grant_id=$1",
            std::vector<std::string>{grant_id});
        if (sel.status() != PGRES_TUPLES_OK) {
            result.outcome = OpenSessionOutcome::kUnavailable;
            return result;
        }
        if (PQntuples(sel.get()) == 0) {
            result.outcome = OpenSessionOutcome::kGrantUnknown;
            return result;
        }

        stored_hash = PQgetvalue(sel.get(), 0, 0);
        state = PQgetvalue(sel.get(), 0, 1);
        expires_at = to_i64(PQgetvalue(sel.get(), 0, 2));
        agent_id = PQgetvalue(sel.get(), 0, 3);
        destination_key = PQgetvalue(sel.get(), 0, 4);
        declared_max_size = to_i64(PQgetvalue(sel.get(), 0, 5));
        expected_sha256 = PQgetvalue(sel.get(), 0, 6);
        retention_class = PQgetvalue(sel.get(), 0, 7);
    } // lease released — Step 4 below acquires its own transaction lease

    // Step 2: constant-time secret verify — collapse "unknown grant" and
    // "wrong secret" onto the SAME wire outcome (device_token_rejection.hpp
    // precedent: never let an attacker discriminate "exists" from "doesn't"
    // by response shape). A digest FAILURE on the presented secret is never
    // treated as comparable — `digest_ok` guards against a broken provider
    // making every secret hash to the same "" and matching a (should-be-
    // impossible, but defense-in-depth) empty stored digest.
    const auto presented_hash = sha256_hex_impl(presented_secret);
    if (!digest_ok(presented_hash) ||
        !upload_grant::constant_time_equals(presented_hash, stored_hash)) {
        result.outcome = OpenSessionOutcome::kGrantUnknown;
        return result;
    }
    // A revoked grant reads the same as unknown — never confirm it once
    // existed.
    if (state == "revoked") {
        result.outcome = OpenSessionOutcome::kGrantUnknown;
        return result;
    }

    // Step 3: generate the session credential BEFORE the redemption UPDATE
    // so both the CAS-redemption and the session INSERT can run inside ONE
    // transaction below — an insert failure then rolls the redemption back
    // too, instead of permanently burning the grant with no session to show
    // for it.
    std::string upload_id, session_secret;
    try {
        upload_id = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        session_secret = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
    } catch (const std::exception&) {
        result.outcome = OpenSessionOutcome::kUnavailable;
        return result;
    }
    const auto session_hash = sha256_hex_impl(session_secret);
    if (!digest_ok(session_hash)) {
        result.outcome = OpenSessionOutcome::kUnavailable;
        return result;
    }

    // Step 4: THE atomic single-redemption UPDATE, plus the session INSERT,
    // in ONE transaction. A concurrent second caller's identical UPDATE
    // deterministically sees 0 rows once this one commits (Postgres
    // row-level locking + EvalPlanQual re-check under READ COMMITTED) — this
    // is what makes single-redemption safe under concurrency, not the
    // read-then-write steps above (those only decide the WIRE REASON on a
    // miss). `expires_at >= now` (not strict `>`) — mirrors
    // `upload_grant::is_expired`'s exact-boundary rule (`now == expires_at`
    // is still valid; only `now > expires_at` is expired).
    bool redeemed_miss = false;
    std::string miss_state; ///< the grant's CURRENT state when the CAS missed
    const bool txn_ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE upload_grant_store.grants SET state='redeemed' "
            "WHERE grant_id=$1 AND state='minted' AND expires_at >= $2::bigint "
            "RETURNING grant_id",
            std::vector<std::string>{grant_id, std::to_string(now)});
        if (upd.status() != PGRES_TUPLES_OK)
            return false; // genuine store error -> unexpected via txn_ok==false

        if (PQntuples(upd.get()) == 0) {
            // Not a store error — the redemption itself simply missed
            // (already redeemed/revoked, or expired). Nothing to roll back;
            // commit the (no-op) transaction and report the miss below.
            redeemed_miss = true;
            // Re-read the CURRENT state inside this same transaction rather
            // than inferring the reason from the step-1 snapshot. The
            // snapshot can be stale in exactly the way that matters: a grant
            // that read 'minted' at step 1 and was REVOKED before this CAS
            // misses here, and the snapshot-based fallback below would then
            // report `grant_already_redeemed` — a 409 that confirms the
            // grant existed and was valid, defeating the deliberate collapse
            // of revoked onto `grant_unknown` (401) twenty lines above,
            // whose whole point is never to confirm a revoked grant once
            // existed. A failed re-read leaves `miss_state` empty, which the
            // fallback treats as "unknown" and answers with the same
            // non-committal 401 — the safe direction.
            pg::PgResult cur = pg::exec_params(
                conn, "SELECT state FROM upload_grant_store.grants WHERE grant_id=$1",
                std::vector<std::string>{grant_id});
            if (cur.status() == PGRES_TUPLES_OK && PQntuples(cur.get()) == 1)
                miss_state = PQgetvalue(cur.get(), 0, 0);
            return true;
        }

        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO upload_grant_store.sessions "
            "(upload_id, grant_id, agent_id, destination_key, declared_max_size, expected_sha256, "
            " retention_class, session_secret_hash, state, recorded_offset, created_at, expires_at) "
            "VALUES ($1,$2,$3,$4,$5::bigint,$6,$7,$8,'open',0,$9::bigint,$10::bigint) "
            "RETURNING upload_id",
            std::vector<std::string>{upload_id, grant_id, agent_id, destination_key,
                                     std::to_string(declared_max_size), expected_sha256,
                                     retention_class, session_hash, std::to_string(now),
                                     std::to_string(expires_at)});
        if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0)
            return false; // rolls back the redemption too

        return true;
    });

    if (!txn_ok) {
        result.outcome = OpenSessionOutcome::kUnavailable;
        return result;
    }
    if (redeemed_miss) {
        // Disambiguate against the grant's CURRENT state, re-read inside the
        // CAS transaction above — NOT the step-1 snapshot, which can be
        // stale in the one direction that leaks (see the re-read's comment).
        //
        //   revoked / gone / unreadable -> kGrantUnknown (401). A revoked
        //     grant reads exactly like one that never existed, matching the
        //     non-race path twenty lines above; an unreadable one is
        //     answered the same way because that is the non-committal
        //     direction.
        //   still 'minted' -> the CAS can only have missed on the expiry
        //     predicate, so this is a genuine expiry.
        //   anything else ('redeemed') -> a concurrent caller won the atomic
        //     race, which is the same fact a straightforward replay reports.
        if (miss_state == "revoked" || miss_state.empty())
            result.outcome = OpenSessionOutcome::kGrantUnknown;
        else if (miss_state == "minted")
            result.outcome = OpenSessionOutcome::kExpired;
        else
            result.outcome = OpenSessionOutcome::kAlreadyRedeemed;
        return result;
    }

    result.outcome = OpenSessionOutcome::kOpened;
    result.session = UploadGrantSession{upload_id, session_secret,
                                        upload_grant::kDefaultChunkMaxBytes, 0, expires_at};
    return result;
}

// ── Session authentication ──────────────────────────────────────────────

SessionAuthResult UploadGrantStore::authenticate_session(const std::string& upload_id,
                                                         const std::string& presented_secret,
                                                         std::int64_t now) {
    SessionAuthResult result;
    if (!open_ || upload_id.empty() || presented_secret.empty()) {
        result.outcome = SessionAuthOutcome::kSessionUnknown;
        return result;
    }

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        result.outcome = SessionAuthOutcome::kUnavailable;
        return result;
    }

    pg::PgResult sel = pg::exec_params(
        lease.get(),
        "SELECT session_secret_hash, grant_id, agent_id, destination_key, declared_max_size, "
        "expected_sha256, retention_class, state, recorded_offset, created_at, expires_at "
        "FROM upload_grant_store.sessions WHERE upload_id=$1",
        std::vector<std::string>{upload_id});
    if (sel.status() != PGRES_TUPLES_OK) {
        result.outcome = SessionAuthOutcome::kUnavailable;
        return result;
    }
    if (PQntuples(sel.get()) == 0) {
        result.outcome = SessionAuthOutcome::kSessionUnknown;
        return result;
    }

    const std::string stored_hash = PQgetvalue(sel.get(), 0, 0);
    const auto presented_hash = sha256_hex_impl(presented_secret);
    if (!digest_ok(presented_hash) ||
        !upload_grant::constant_time_equals(presented_hash, stored_hash)) {
        result.outcome = SessionAuthOutcome::kSessionUnknown;
        return result;
    }

    UploadSessionInfo info;
    info.upload_id = upload_id;
    info.grant_id = PQgetvalue(sel.get(), 0, 1);
    info.agent_id = PQgetvalue(sel.get(), 0, 2);
    info.destination_key = PQgetvalue(sel.get(), 0, 3);
    info.declared_max_size = to_i64(PQgetvalue(sel.get(), 0, 4));
    info.expected_sha256 = PQgetvalue(sel.get(), 0, 5);
    info.retention_class = PQgetvalue(sel.get(), 0, 6);
    info.state = PQgetvalue(sel.get(), 0, 7);
    info.recorded_offset = to_i64(PQgetvalue(sel.get(), 0, 8));
    info.created_at = to_i64(PQgetvalue(sel.get(), 0, 9));
    info.expires_at = to_i64(PQgetvalue(sel.get(), 0, 10));

    // Populate `info` on EVERY outcome (including terminal/expired) — the
    // GET status/resume route needs to report a terminal session's final
    // state, not just an open one's.
    result.info = info;

    // `expired` is checked FIRST and takes priority over an already-'expired'
    // row's own state string: the frozen protocol says "any request after
    // [expiry] -> 410 expired", not just the FIRST one. Without this, a row
    // already flipped to 'expired' (by a prior request's own expire_now call,
    // or the background sweep) would fall through to the generic
    // `state != "open"` check below and report `session_terminal` — a request
    // arriving in second place would see 409, not the mandated 410. A still-
    // 'open' row whose clock has simply passed its expiry gets the same
    // outcome, symmetrically.
    if (info.state == "expired" ||
        (info.state == "open" && upload_grant::is_expired(info.expires_at, now))) {
        result.outcome = SessionAuthOutcome::kExpired;
        return result;
    }
    if (info.state != "open") {
        result.outcome = SessionAuthOutcome::kSessionTerminal;
        return result;
    }
    result.outcome = SessionAuthOutcome::kOk;
    return result;
}

// ── Chunk offset advance ─────────────────────────────────────────────────

std::expected<bool, std::string> UploadGrantStore::advance_offset(const std::string& upload_id,
                                                                   std::int64_t expected_prev_offset,
                                                                   std::int64_t new_offset) {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE upload_grant_store.sessions SET recorded_offset=$1::bigint "
        "WHERE upload_id=$2 AND recorded_offset=$3::bigint AND state='open' "
        "RETURNING upload_id",
        std::vector<std::string>{std::to_string(new_offset), upload_id,
                                 std::to_string(expected_prev_offset)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("advance_offset failed: ") + PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

// ── Terminal transitions ─────────────────────────────────────────────────

std::expected<bool, std::string> UploadGrantStore::commit_session(const std::string& upload_id,
                                                                   std::int64_t actual_size,
                                                                   const std::string& verified_hash,
                                                                   std::int64_t now) {
    if (!open_)
        return std::unexpected("database not open");

    std::string error_msg;
    bool committed = false;

    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Lock the row first so a concurrent cancel/commit for the same
        // upload_id serializes against this one, rather than racing the
        // UPDATE below independently.
        pg::PgResult sel = pg::exec_params(
            conn,
            "SELECT grant_id, agent_id, destination_key, retention_class "
            "FROM upload_grant_store.sessions WHERE upload_id=$1 AND state='open' FOR UPDATE",
            std::vector<std::string>{upload_id});
        if (sel.status() != PGRES_TUPLES_OK) {
            error_msg = "commit read failed";
            return false;
        }
        if (PQntuples(sel.get()) == 0) {
            // Not open (already terminal, or never existed) — a CAS miss,
            // not a store error. The caller re-authenticates to learn why.
            committed = false;
            return true;
        }
        const std::string grant_id = PQgetvalue(sel.get(), 0, 0);
        const std::string agent_id = PQgetvalue(sel.get(), 0, 1);
        const std::string destination_key = PQgetvalue(sel.get(), 0, 2);
        const std::string retention_class = PQgetvalue(sel.get(), 0, 3);

        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE upload_grant_store.sessions SET state='committed' "
            "WHERE upload_id=$1 AND state='open' RETURNING upload_id",
            std::vector<std::string>{upload_id});
        if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) == 0) {
            error_msg = "commit update failed";
            return false;
        }

        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO upload_grant_store.completed_uploads "
            "(upload_id, grant_id, agent_id, destination_key, actual_size, verified_hash, "
            " retention_class, received_at) "
            "VALUES ($1,$2,$3,$4,$5::bigint,$6,$7,$8::bigint) RETURNING upload_id",
            std::vector<std::string>{upload_id, grant_id, agent_id, destination_key,
                                     std::to_string(actual_size), verified_hash, retention_class,
                                     std::to_string(now)});
        if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0) {
            error_msg = "completed_uploads insert failed";
            return false;
        }
        committed = true;
        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "commit failed" : error_msg);
    return committed;
}

std::expected<bool, std::string> UploadGrantStore::cancel_session(const std::string& upload_id) {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE upload_grant_store.sessions SET state='cancelled' "
        "WHERE upload_id=$1 AND state='open' RETURNING upload_id",
        std::vector<std::string>{upload_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("cancel failed: ") + PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

std::expected<bool, std::string> UploadGrantStore::expire_now(const std::string& upload_id) {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE upload_grant_store.sessions SET state='expired' "
        "WHERE upload_id=$1 AND state='open' RETURNING upload_id",
        std::vector<std::string>{upload_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("expire_now failed: ") + PQerrorMessage(lease.get()));
    return PQntuples(res.get()) > 0;
}

// ── Maintenance ───────────────────────────────────────────────────────────

std::size_t UploadGrantStore::expire_stale_sessions(std::int64_t now) {
    if (!open_)
        return 0;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;

    // `expires_at < now` (strict), matching `upload_grant::is_expired`'s
    // exact-boundary rule exactly — `now == expires_at` is still valid, so
    // the sweep must never expire a session sitting exactly at that instant.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE upload_grant_store.sessions SET state='expired' "
        "WHERE state='open' AND expires_at < $1::bigint RETURNING upload_id",
        std::vector<std::string>{std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("UploadGrantStore: expire_stale_sessions sweep failed (best-effort)");
        return 0;
    }
    return static_cast<std::size_t>(PQntuples(res.get()));
}

} // namespace yuzu::server
