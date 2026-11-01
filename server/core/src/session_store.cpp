/**
 * session_store.cpp -- see session_store.hpp
 *
 * Idioms mirror access_review_store.cpp (authoritative std::expected + with_txn_for)
 * and rbac_store.cpp (durable write-generation bumped in the same txn as every
 * authz-affecting mutation). Runtime SQL is schema-qualified; migration DDL is
 * unqualified (the runner sets search_path).
 */

#include "session_store.hpp"
#include "session_store_sql_helpers.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm> // std::max (reap anchor) — not transitively guaranteed on libc++
#include <cerrno>    // errno — checked parse of the clock-guard-critical readings (#3785)
#include <chrono>
#include <cstdlib>
#include <optional>
#include <string_view>

namespace yuzu::server {

using pg::exec_params;
using pg::PgResult;

namespace {

constexpr const char* kStoreName = "session_store"; // schema = snake_case(SessionStore)
// The ONE statement of the stored-principal invariant (#2343): a human session (any source
// except engine_token) or an engine session (engine_token). The v2 migration interpolates it
// into both the DELETE (negated) and the CHECK, so the two cannot drift apart.
constexpr const char* kPrincipalPairingOk =
    "((principal_kind = 'human' AND auth_source <> 'engine_token')"
    " OR (principal_kind = 'engine' AND auth_source = 'engine_token'))";
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kReadTimeout{2000};

// Retention: substrate-tuned; copy the SHAPE from a sibling, never the numbers.
constexpr int kReapCap = 5000;                 // hard per-pass cap (always applies)
constexpr std::int64_t kMaxPlausibleSkewMs = 366LL * 24 * 3600 * 1000; // ~1y ahead of anchor = anomaly

std::int64_t to_i64(const char* s) {
    if (!s || !*s)
        return 0;
    return std::strtoll(s, nullptr, 10);
}

// Checked parse for the two clock-guard-critical readings in reap_expired (the
// DB now() column and the persisted session_meta anchor) — deliberately NOT the
// ambient `to_i64` above, which is a lenient strtoll-with-no-validation helper
// appropriate for the trusted DB-returned row columns elsewhere in this file,
// but NOT for a value the clock-guarded-retention routed concern (CLAUDE.md
// part 3) requires be SANITISED: "ahead-of-now / negative / unparseable =
// anomaly, never a quiet reset — on an endpoint the user controls, a quiet
// reset IS the bypass". A hand-edited session_meta row, a bad migration, or
// storage corruption writing `123junk`, a negative value, or an overflowed
// value must be REJECTED as an anomaly, not silently truncated/wrapped by an
// unchecked strtoll (#3785 — the identical sibling defect execution_tracker.cpp
// closed in PR #3780; api_token_store.cpp's `parse_meta_i64` /
// response_store.cpp's inline equivalent are the reference shape this mirrors,
// and a second hand-rolled copy is the drift those two already accepted as
// cheaper than a shared-utility header for a three-line function).
std::optional<std::int64_t> parse_reap_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}

std::uint64_t to_u64(const char* s) {
    if (!s || !*s)
        return 0;
    return std::strtoull(s, nullptr, 10);
}

// The durable write-generation bump lives in session_store_sql_helpers.hpp (one
// copy, shared with the ADR-0012 §3 CredentialChangeOwner, #5342).
using session_sql::bump_generation_in_txn;

SessionRow row_from(PGresult* res, int i) {
    SessionRow row;
    row.token_hash = PQgetvalue(res, i, 0);
    row.username = PQgetvalue(res, i, 1);
    row.display_name = PQgetvalue(res, i, 2);
    row.role = PQgetvalue(res, i, 3);
    row.auth_source = PQgetvalue(res, i, 4);
    row.oidc_sub = PQgetvalue(res, i, 5);
    row.token_scope_service = PQgetvalue(res, i, 6);
    row.mcp_tier = PQgetvalue(res, i, 7);
    row.principal_kind = PQgetvalue(res, i, 8);
    row.created_at_ms = to_i64(PQgetvalue(res, i, 9));
    row.expires_at_ms = to_i64(PQgetvalue(res, i, 10));
    row.last_activity_ms = to_i64(PQgetvalue(res, i, 11));
    row.mfa_verified_ms = to_i64(PQgetvalue(res, i, 12));
    row.elevated_until_ms = to_i64(PQgetvalue(res, i, 13));
    row.elevation_issued_ms = to_i64(PQgetvalue(res, i, 14));
    row.mfa_factor_gen = to_i64(PQgetvalue(res, i, 15));
    row.mfa_bind_seq = to_i64(PQgetvalue(res, i, 16));
    return row;
}

constexpr const char* kSelectCols =
    "token_hash, username, display_name, role, auth_source, oidc_sub, token_scope_service, "
    "mcp_tier, principal_kind, created_at_ms, expires_at_ms, last_activity_ms, mfa_verified_ms, "
    "elevated_until_ms, elevation_issued_ms, mfa_factor_gen, mfa_bind_seq";
// The 17 columns kSelectCols lists (indices 0..16 in row_from); so find()'s
// appended db_now expression lands at index kSessionRowColumns. Keep these two in
// lockstep: a column added to kSelectCols/row_from MUST bump this, or the db_now
// read shifts silently. find() also guards PQnfields at runtime as a backstop.
constexpr int kSessionRowColumns = 17;

// The DB clock at statement time, in wall-clock epoch-millis. `now()` is
// transaction-start time and is STABLE within a txn, so every use inside one
// txn (SET value, WHERE guard, RETURNING) reads the same instant — that
// stability is what makes "author and return the same now()" exact.
constexpr const char* kDbNowMsSql = "(extract(epoch from now())*1000)::bigint";

// RETURNING clause naming the six authored time columns + db_now + the factor
// generation the guard trigger left on the row, in the order authored_from() reads
// them. Shared by create/set_elevation/mark_mfa/clear_mfa_proof so the caller always
// seeds its cache with the exact DB-authored values. The INSERT form is unqualified
// (the target row); the UPDATE ... FROM n form is below. Keep the two in lockstep.
constexpr const char* kAuthoredReturning =
    "created_at_ms, expires_at_ms, last_activity_ms, mfa_verified_ms, "
    "elevated_until_ms, elevation_issued_ms, (extract(epoch from now())*1000)::bigint, "
    "mfa_factor_gen";
// The `UPDATE session_store.sessions s ... FROM (SELECT ... AS ms) n` form.
constexpr const char* kAuthoredReturningUpd =
    "s.created_at_ms, s.expires_at_ms, s.last_activity_ms, s.mfa_verified_ms, "
    "s.elevated_until_ms, s.elevation_issued_ms, n.ms, s.mfa_factor_gen";

AuthoredTimes authored_from(PGresult* res, int i) {
    AuthoredTimes t;
    t.created_at_ms = to_i64(PQgetvalue(res, i, 0));
    t.expires_at_ms = to_i64(PQgetvalue(res, i, 1));
    t.last_activity_ms = to_i64(PQgetvalue(res, i, 2));
    t.mfa_verified_ms = to_i64(PQgetvalue(res, i, 3));
    t.elevated_until_ms = to_i64(PQgetvalue(res, i, 4));
    t.elevation_issued_ms = to_i64(PQgetvalue(res, i, 5));
    t.db_now_ms = to_i64(PQgetvalue(res, i, 6));
    t.mfa_factor_gen = to_i64(PQgetvalue(res, i, 7));
    return t;
}

// Body of the rebind-guard trigger function. ONE constant shared by the migration
// (below) and the effective-firing validation (`pg_proc.prosrc` compared by plain text
// equality, no md5: md5() is refused on a FIPS-mode server, and AuthDB's check does the
// same), so the two cannot drift. A write of a proof or identity column that
// does not advance the bind sequence leaves the proof UNBOUND (factor generation 0),
// whatever the new values.
// FROZEN: shipped in migration v3 and pinned byte-for-byte by the boot check; changing it
// needs a NEW migration (CREATE OR REPLACE) and an accepted (old,new) pair in the check, or
// every migrated replica refuses to boot.
constexpr std::string_view kRebindGuardBody =
    "\nBEGIN\n"
    "  IF NOT (NEW.mfa_bind_seq > OLD.mfa_bind_seq) THEN\n"
    "    NEW.mfa_factor_gen := 0;\n"
    "  END IF;\n"
    "  RETURN NEW;\n"
    "END ";

std::string migration_v3_sql() {
    // The 3 s lock_timeout is the same short cap v2 uses: while the ALTER TABLE / CREATE
    // TRIGGER queues behind a long transaction, every new sessions query on a running peer
    // queues behind it, so a short cap keeps that stall short. A failed attempt rolls the
    // whole migration back and the next boot retries it.
    return "SET LOCAL lock_timeout = '3s'; "
           "ALTER TABLE sessions ADD COLUMN mfa_factor_gen BIGINT NOT NULL DEFAULT 0, "
           "ADD COLUMN mfa_bind_seq BIGINT NOT NULL DEFAULT 0; "
           "CREATE FUNCTION sessions_mfa_rebind_guard() RETURNS trigger LANGUAGE plpgsql AS $$" +
           std::string(kRebindGuardBody) +
           "$$; "
           "CREATE TRIGGER sessions_mfa_rebind_guard "
           "BEFORE UPDATE OF mfa_verified_ms, mfa_factor_gen, username, auth_source, "
           "principal_kind "
           "ON sessions FOR EACH ROW EXECUTE FUNCTION sessions_mfa_rebind_guard(); "
           // ENABLE ALWAYS (tgenabled = 'A') fires under every session_replication_role;
           // the default 'O' is skipped under 'replica', which would let a replication-
           // role session write a bound proof past the guard.
           "ALTER TABLE sessions ENABLE ALWAYS TRIGGER sessions_mfa_rebind_guard;";
}

enum class GuardCheck { kOk, kFailed, kInconclusive };

// Is the rebind guard in force for every writer? Reads the catalog: the trigger exists,
// is ENABLE ALWAYS ('A'), is a ROW BEFORE UPDATE trigger and nothing else (tgtype & 127 = 19: no
// INSERT, DELETE, TRUNCATE or INSTEAD bit, as AuthDB's check) with no WHEN clause, lists all five
// guarded columns, and calls the pinned function body. A missing
// sessions table (a rename fault, a drop) is INCONCLUSIVE rather than a failure: it is
// not evidence about the trigger and every session query fails on it anyway. When `cause` is
// given, an inconclusive result describes why (SQLSTATE and server message, or the row count).
GuardCheck check_rebind_guard(PGconn* conn, std::string* cause = nullptr) {
    PgResult r = exec_params(
        conn,
        "SELECT COALESCE(t.tgenabled = 'A' "
        "  AND (t.tgtype & 127) = 19 AND t.tgqual IS NULL "
        "  AND (SELECT count(*) FROM pg_attribute a WHERE a.attrelid = c.oid "
        "AND NOT a.attisdropped "
        "         AND a.attname IN ('mfa_verified_ms','mfa_factor_gen','username','auth_source',"
        "'principal_kind')) = 5 "
        "  AND t.tgattr::int2[] @> ARRAY(SELECT a.attnum FROM pg_attribute a "
        "         WHERE a.attrelid = c.oid AND NOT a.attisdropped "
        "           AND a.attname IN ('mfa_verified_ms','mfa_factor_gen','username','auth_source',"
        "'principal_kind')) "
        "  AND p.proname = 'sessions_mfa_rebind_guard' AND p.pronamespace = c.relnamespace "
        "  AND p.prolang = (SELECT oid FROM pg_language WHERE lanname = 'plpgsql') "
        "  AND p.prosrc = $1::text, false) "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "LEFT JOIN pg_trigger t ON t.tgrelid = c.oid AND t.tgname = 'sessions_mfa_rebind_guard' "
        "  AND NOT t.tgisinternal "
        "LEFT JOIN pg_proc p ON p.oid = t.tgfoid "
        "WHERE n.nspname = 'session_store' AND c.relname = 'sessions' AND c.relkind = 'r'",
        std::vector<std::string>{std::string(kRebindGuardBody)});
    if (r.status() != PGRES_TUPLES_OK) {
        if (cause) {
            const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
            std::string msg = PQerrorMessage(conn);
            while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
                msg.pop_back();
            *cause = std::string("catalog query failed, SQLSTATE ") + (state ? state : "none") +
                     ": " + msg;
        }
        return GuardCheck::kInconclusive;
    }
    if (PQntuples(r.get()) != 1) {
        if (cause)
            *cause = "catalog query returned " + std::to_string(PQntuples(r.get())) +
                     " rows for session_store.sessions, expected 1";
        return GuardCheck::kInconclusive;
    }
    return std::string_view(PQgetvalue(r.get(), 0, 0)) == "t" ? GuardCheck::kOk
                                                              : GuardCheck::kFailed;
}

std::int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, "CREATE TABLE sessions ("
            "  token_hash          TEXT PRIMARY KEY,"
            "  username            TEXT NOT NULL,"
            "  display_name        TEXT NOT NULL DEFAULT '',"
            "  role                TEXT NOT NULL,"
            "  auth_source         TEXT NOT NULL DEFAULT 'local',"
            "  oidc_sub            TEXT NOT NULL DEFAULT '',"
            "  token_scope_service TEXT NOT NULL DEFAULT '',"
            "  mcp_tier            TEXT NOT NULL DEFAULT '',"
            "  principal_kind      TEXT NOT NULL DEFAULT 'human',"
            "  created_at_ms       BIGINT NOT NULL,"
            "  expires_at_ms       BIGINT NOT NULL,"
            "  last_activity_ms    BIGINT NOT NULL,"
            "  mfa_verified_ms     BIGINT NOT NULL DEFAULT 0,"
            "  elevated_until_ms   BIGINT NOT NULL DEFAULT 0,"
            "  elevation_issued_ms BIGINT NOT NULL DEFAULT 0);"
            "CREATE INDEX sessions_username_idx ON sessions (username);"
            "CREATE INDEX sessions_expires_idx ON sessions (expires_at_ms);"
            "CREATE TABLE session_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
        // v2 (#2343): the stored principal class is exactly one of two pairings: a human
        // session (any source but engine_token) or an engine session (engine_token). Token
        // sessions (api/mcp/engine tokens) are never persisted, and every persist_new_session
        // caller hard-codes a local, oidc or saml auth_source with the default 'human' kind,
        // so no binary writes a row this constraint rejects; only a hand-edited row can. Such
        // a row is untrusted by definition and a session is ephemeral, so the DELETE costs
        // that principal one sign-in; the count is raised as a server-log WARNING (a forced
        // sign-out leaves a trace). Without the constraint, code that reads the stored kind
        // alone and code that reads Session::is_engine() could classify one session
        // differently.
        // Shape: ONE migration (the runner commits each migration as one transaction),
        // DELETE first so a retry clears any row an older binary wrote between attempts
        // before the ALTER validates (same shape as AuditStore v2). The DROP ... IF EXISTS
        // makes the ADD idempotent against a constraint of the same name applied by hand
        // (otherwise 42710 would refuse boot on every restart). The LOCK TABLE comes first so
        // the migration holds the strongest lock before it deletes anything: without it the
        // DELETE (row locks) followed by the ALTER (lock upgrade) deadlocks with a live
        // session writer waiting on a row the DELETE removed (reproduced on postgres:18), and
        // a row committed between the DELETE and the ALTER would fail the ADD's validation
        // and refuse boot. The lock wait is capped at 3 s by this migration's own SET LOCAL
        // lock_timeout (the CaStore v4 precedent), whatever the pool or a DSN `options`
        // setting says: while the request queues behind a long transaction (pg_dump), every
        // new sessions query on a running peer queues behind it, so a short cap keeps that
        // stall short, and the whole migration rolls back and retries on the next boot.
        // The write_generation bump runs only when rows were deleted, inside the DO block's
        // IF, so a clean upgrade does not make every replica drop its validate cache for
        // nothing. Its position is safe because the ACCESS EXCLUSIVE lock is already held: a
        // session writer takes sessions locks before it bumps session_meta (see
        // session_store_sql_helpers.hpp "take it LAST"), so none can be holding the
        // session_meta row while this waits on sessions. A peer replica's validate cache then
        // drops the deleted rows on its next generation poll instead of serving them until
        // some unrelated login bumps it. v2 has not shipped, so it is edited in place.
        {2, std::string("SET LOCAL lock_timeout = '3s';"
                        "LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE;"
                        "DO $$ DECLARE n bigint; BEGIN"
                        " DELETE FROM sessions WHERE NOT ") +
                kPrincipalPairingOk +
                std::string(";"
                            " GET DIAGNOSTICS n = ROW_COUNT;"
                            " IF n > 0 THEN"
                            " RAISE WARNING 'session_store v2 (#2343): deleted % inconsistent"
                            " session row(s); each affected principal must sign in again', n;"
                            " INSERT INTO session_store.session_meta (key, value)"
                            " VALUES ('write_generation', '1')"
                            " ON CONFLICT (key) DO UPDATE SET value ="
                            " (session_store.session_meta.value::bigint + 1)::text;"
                            " END IF;"
                            " END $$;"
                            "ALTER TABLE sessions DROP CONSTRAINT IF EXISTS"
                            " sessions_principal_kind_consistent;"
                            "ALTER TABLE sessions ADD CONSTRAINT"
                            " sessions_principal_kind_consistent CHECK (") +
                kPrincipalPairingOk + std::string(");")},
        // v3 (#6079): factor-generation binding of local MFA proofs. Additive columns
        // (a legacy binary's explicit-column INSERT/SELECT is unaffected) plus the
        // rebind guard trigger. A pre-existing row keeps generation 0 = UNBOUND, so the
        // previous release's proofs are re-proven once.
        {3, migration_v3_sql()},
    };
    return kMigrations;
}

} // namespace

SessionStore::SessionStore(pg::PgPool& pool) : SessionStore(pool, MfaBindingCheck::kEnforce) {}

SessionStore::SessionStore(pg::PgPool& pool, MfaBindingCheck binding_check) : pool_(pool) {
    auto lease = pool_.acquire(); // unbounded — construction ONLY
    if (!lease) {
        spdlog::error("SessionStore: no database connection at construction ({})",
                      pool_.last_error());
        return; // open_ stays false → fail closed
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SessionStore: schema migration failed");
        return;
    }
    // The binding is only as good as the trigger that unbinds legacy writes: refuse to
    // open (fail closed, like a failed migration) if it is not provably in force.
    const GuardCheck boot_check = check_rebind_guard(lease.get());
    if (binding_check == MfaBindingCheck::kBypassForRecovery) {
        // Host-CLI recovery one-shot (--mfa-reset): the store opens whatever the guard state so
        // the operator can still end the account's sessions. `rebind_guard_ok_` stays false (its
        // default) for the life of this instance, so any binding decision through it fails
        // closed; the one-shot makes none.
        spdlog::warn("SessionStore: recovery bypass of the rebind-guard check (guard state: {}); "
                     "this one-shot process does not enforce session proof binding",
                     boot_check == GuardCheck::kOk       ? "in force"
                     : boot_check == GuardCheck::kFailed ? "missing, not ENABLE ALWAYS, or altered"
                                                         : "unreadable");
        open_ = true;
        return;
    }
    if (boot_check != GuardCheck::kOk) {
        spdlog::error("SessionStore: sessions_mfa_rebind_guard is missing, not ENABLE ALWAYS, "
                      "or altered; refusing to open (local MFA binding cannot be trusted)");
        return;
    }
    next_validation_steady_ms_.store(steady_now_ms() + validation_memo_ms_.load());
    rebind_guard_ok_.store(true, std::memory_order_release);
    open_ = true;
}

std::expected<AuthoredTimes, SessionStore::Error>
SessionStore::create(const SessionWriteParams& params) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    if (params.token_hash.empty() || params.username.empty())
        return std::unexpected(Error{"token_hash and username are required"});

    const LocalMfaProof& lp = params.local_mfa;
    // Writer-error and ambiguity guards: a proof is {gen, instant} with the instant
    // positive, a binding without an instant is a caller bug (never a silent unbound
    // stamp), and at most one MFA option may be set.
    if (lp.verified_ms < 0 || lp.factor_gen < 0 || (lp.factor_gen > 0 && lp.verified_ms == 0))
        return std::unexpected(Error{"invalid local MFA proof (binding without an instant)"});
    if (lp.verified_ms > 0 && params.mfa_verified_ms_abs != 0)
        return std::unexpected(Error{"more than one MFA proof option set"});

    AuthoredTimes authored;
    std::string err;
    // created_at / expires_at / last_activity are authored from the ONE DB clock
    // (`now()`, txn-stable); mfa_verified is the carried local instant ($12) when it is
    // not in the future of this statement's now() (a future-dated instant stores NO proof
    // and NO binding, never a clamped age-zero one), else the passed absolute (an IdP
    // proof time, or 0). `n.ms` is
    // that now() reused across the INSERT and the RETURNING so the caller's cache gets
    // exact values. The bind sequence starts at 1 and advances on a conflicting rewrite,
    // so the rebind guard never unbinds THIS writer; a legacy INSERT omits the column.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            ("INSERT INTO session_store.sessions ("
             "token_hash, username, display_name, role, auth_source, oidc_sub, "
             "token_scope_service, "
             "mcp_tier, principal_kind, created_at_ms, expires_at_ms, last_activity_ms, "
             "mfa_verified_ms, elevated_until_ms, elevation_issued_ms, mfa_factor_gen, "
             "mfa_bind_seq) "
             "SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9, n.ms, n.ms + $10::bigint, n.ms, "
             "CASE WHEN $12::bigint > 0 THEN (CASE WHEN $12::bigint <= n.ms THEN $12::bigint "
             "ELSE 0 END) ELSE $11::bigint END, 0, 0, "
             "CASE WHEN $12::bigint > 0 AND $12::bigint <= n.ms THEN $13::bigint ELSE 0 END, 1 "
             "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
             "ON CONFLICT (token_hash) DO UPDATE SET "
             "username=EXCLUDED.username, display_name=EXCLUDED.display_name, role=EXCLUDED.role, "
             "auth_source=EXCLUDED.auth_source, oidc_sub=EXCLUDED.oidc_sub, "
             "token_scope_service=EXCLUDED.token_scope_service, mcp_tier=EXCLUDED.mcp_tier, "
             "principal_kind=EXCLUDED.principal_kind, created_at_ms=EXCLUDED.created_at_ms, "
             "expires_at_ms=EXCLUDED.expires_at_ms, last_activity_ms=EXCLUDED.last_activity_ms, "
             "mfa_verified_ms=EXCLUDED.mfa_verified_ms, "
             "elevated_until_ms=EXCLUDED.elevated_until_ms, "
             "elevation_issued_ms=EXCLUDED.elevation_issued_ms, "
             "mfa_factor_gen=EXCLUDED.mfa_factor_gen, "
             "mfa_bind_seq=session_store.sessions.mfa_bind_seq + 1 "
             "RETURNING " +
             std::string(kAuthoredReturning))
                .c_str(),
            std::vector<std::string>{
                params.token_hash, params.username, params.display_name, params.role,
                params.auth_source, params.oidc_sub, params.token_scope_service, params.mcp_tier,
                params.principal_kind, std::to_string(params.session_lifetime_ms),
                std::to_string(params.mfa_verified_ms_abs), std::to_string(lp.verified_ms),
                std::to_string(lp.factor_gen)});
        if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0) {
            err = std::string("session insert failed: ") + PQerrorMessage(c);
            return false;
        }
        authored = authored_from(r.get(), 0);
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "create failed" : err});
    return authored;
}

std::expected<bool, SessionStore::Error> SessionStore::invalidate(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool removed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r =
            exec_params(c,
                        "DELETE FROM session_store.sessions WHERE token_hash=$1 RETURNING token_hash",
                        std::vector<std::string>{token_hash});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("session delete failed: ") + PQerrorMessage(c);
            return false;
        }
        removed = PQntuples(r.get()) > 0;
        return bump_generation_in_txn(c);
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "invalidate failed" : err});
    return removed;
}

std::expected<int, SessionStore::Error>
SessionStore::invalidate_user(const std::string& username) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    int count = 0;
    std::string err;
    // The ONE "revoke every session of a user" statement pair
    // (session_store_sql_helpers.hpp, #5342); CredentialChangeOwner runs the
    // same two statements split around its audit INSERT (bump last, T1′).
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        const auto deleted = session_sql::invalidate_user_in_txn(c, username, err);
        if (!deleted)
            return false;
        count = *deleted;
        return true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "invalidate_user failed" : err});
    return count;
}

std::expected<std::optional<AuthoredTimes>, SessionStore::Error>
SessionStore::set_elevation(const std::string& token_hash, std::int64_t elevation_duration_ms) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    std::optional<AuthoredTimes> authored;
    std::string err;
    // elevation_issued = now(); elevated_until = LEAST(now()+duration, expires_at)
    // — the "never past absolute expiry" clamp is atomic in SQL against the row's
    // own expiry. The WHERE dead-window guard (computed until > now()) matches NO
    // row when the session is already at/past expiry OR duration<=0, so a
    // near-expired grant writes nothing and does not bump the generation for a
    // failed op (design-review S4). 0 rows ⇒ nullopt (absent OR dead-window).
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            (std::string("UPDATE session_store.sessions s SET "
                         "elevation_issued_ms = n.ms, "
                         "elevated_until_ms = LEAST(n.ms + $2::bigint, s.expires_at_ms) "
                         "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
                         "WHERE s.token_hash = $1 AND LEAST(n.ms + $2::bigint, s.expires_at_ms) "
                         "> n.ms RETURNING ") +
             kAuthoredReturningUpd)
                .c_str(),
            std::vector<std::string>{token_hash, std::to_string(elevation_duration_ms)});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("set_elevation failed: ") + PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) > 0)
            authored = authored_from(r.get(), 0);
        // Bump the generation only when a row actually changed — a no-op
        // (absent/dead-window) is not an authz change worth clearing caches for.
        return authored.has_value() ? bump_generation_in_txn(c) : true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "set_elevation failed" : err});
    return authored;
}

std::expected<bool, SessionStore::Error>
SessionStore::clear_elevation(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    bool existed = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(c,
                                 "UPDATE session_store.sessions SET elevated_until_ms=0, "
                                 "elevation_issued_ms=0 WHERE token_hash=$1 RETURNING token_hash",
                                 std::vector<std::string>{token_hash});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("clear_elevation failed: ") + PQerrorMessage(c);
            return false;
        }
        existed = PQntuples(r.get()) > 0;
        // Skip the bump on a no-op (nonexistent token) — a spurious bump needlessly
        // clears every replica's validate-cache (authdb LOW, parity w/ set_elevation).
        return existed ? bump_generation_in_txn(c) : true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "clear_elevation failed" : err});
    return existed;
}

std::expected<int, SessionStore::Error>
SessionStore::clear_user_elevations(const std::string& username) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    int count = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            "UPDATE session_store.sessions SET elevated_until_ms=0, elevation_issued_ms=0 "
            "WHERE username=$1 AND elevated_until_ms<>0 RETURNING token_hash",
            std::vector<std::string>{username});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("clear_user_elevations failed: ") + PQerrorMessage(c);
            return false;
        }
        count = PQntuples(r.get());
        return count > 0 ? bump_generation_in_txn(c) : true; // no bump on a 0-row no-op
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "clear_user_elevations failed" : err});
    return count;
}

std::expected<std::optional<AuthoredTimes>, SessionStore::Error>
SessionStore::mark_mfa(const std::string& token_hash, const LocalMfaProof& proof) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    // A proof needs an instant; a binding without one is a writer error, and an absent
    // proof is clear_mfa_proof's job (never a silent clear through the stamp path).
    if (proof.verified_ms <= 0 || proof.factor_gen < 0)
        return std::unexpected(Error{"invalid local MFA proof (use clear_mfa_proof to remove)"});
    std::optional<AuthoredTimes> authored;
    std::string err;
    // $2 is the carried verification instant, $3 its factor generation. An instant later
    // than this statement's now() (the DB clock stepped back between the verification
    // and this write) stores NO proof and NO binding: the caller sees mfa_verified_ms == 0
    // in the result and treats it as a refusal. The bind sequence advances in the same
    // statement so the rebind guard keeps the generation.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            (std::string(
                 "UPDATE session_store.sessions s SET "
                 "mfa_verified_ms = CASE WHEN $2::bigint <= n.ms THEN $2::bigint ELSE 0 END, "
                 "mfa_factor_gen = CASE WHEN $2::bigint <= n.ms THEN $3::bigint ELSE 0 END, "
                 "mfa_bind_seq = s.mfa_bind_seq + 1 "
                 "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
                 "WHERE s.token_hash = $1 RETURNING ") +
             kAuthoredReturningUpd)
                .c_str(),
            std::vector<std::string>{token_hash, std::to_string(proof.verified_ms),
                                     std::to_string(proof.factor_gen)});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("mark_mfa failed: ") + PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) > 0)
            authored = authored_from(r.get(), 0);
        return authored.has_value() ? bump_generation_in_txn(c) : true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "mark_mfa failed" : err});
    return authored;
}

std::expected<std::optional<AuthoredTimes>, SessionStore::Error>
SessionStore::clear_mfa_proof(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    std::optional<AuthoredTimes> authored;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        PgResult r = exec_params(
            c,
            (std::string("UPDATE session_store.sessions s SET mfa_verified_ms = 0, "
                         "mfa_factor_gen = 0, mfa_bind_seq = s.mfa_bind_seq + 1 "
                         "FROM (SELECT (extract(epoch from now())*1000)::bigint AS ms) n "
                         "WHERE s.token_hash = $1 RETURNING ") +
             kAuthoredReturningUpd)
                .c_str(),
            std::vector<std::string>{token_hash});
        if (r.status() != PGRES_TUPLES_OK) {
            err = std::string("clear_mfa_proof failed: ") + PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) > 0)
            authored = authored_from(r.get(), 0);
        return authored.has_value() ? bump_generation_in_txn(c) : true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "clear_mfa_proof failed" : err});
    return authored;
}

std::expected<bool, SessionStore::Error>
SessionStore::touch_activity(const std::string& token_hash) {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    // NO generation bump — a sliding idle update is not an authz change, and
    // bumping here would invalidate every replica's cache on every request.
    // Authored from the DB clock (`now()`), GREATEST-clamped so an out-of-order /
    // cross-replica write cannot REGRESS last_activity_ms and prematurely idle-out
    // a session whose latest authenticated activity is newer (adversarial C3).
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    PgResult r = exec_params(
        lease.get(),
        (std::string("UPDATE session_store.sessions "
                     "SET last_activity_ms=GREATEST(last_activity_ms, ") +
         kDbNowMsSql + ") WHERE token_hash=$1 RETURNING token_hash")
            .c_str(),
        std::vector<std::string>{token_hash});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("touch_activity failed: ") +
                                     PQerrorMessage(lease.get())});
    return PQntuples(r.get()) > 0;
}

std::expected<std::optional<FoundSession>, SessionStore::Error>
SessionStore::find(const std::string& token_hash) const {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    revalidate_rebind_guard_if_due(lease.get());
    // db_now_ms is the LAST column, read in the SAME atomic SELECT as the row, so
    // adjudication is against the DB clock at read time — never the replica's
    // local clock, and never a separate query that could skew (design-review N1).
    PgResult r =
        exec_params(lease.get(),
                    (std::string("SELECT ") + kSelectCols + ", " + kDbNowMsSql +
                     " FROM session_store.sessions WHERE token_hash=$1")
                        .c_str(),
                    std::vector<std::string>{token_hash});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("find failed: ") + PQerrorMessage(lease.get())});
    if (PQntuples(r.get()) == 0)
        return std::optional<FoundSession>{}; // definitively absent
    if (PQnfields(r.get()) <= kSessionRowColumns) // db_now column missing — never trust a 0
        return std::unexpected(Error{"find: db_now column absent (kSelectCols/db_now drift)"});
    FoundSession fs;
    fs.row = row_from(r.get(), 0);
    fs.db_now_ms = to_i64(PQgetvalue(r.get(), 0, kSessionRowColumns)); // db_now after the row cols
    fs.guard_unverified = last_validation_inconclusive_.load(std::memory_order_acquire);
    return std::optional<FoundSession>{std::move(fs)};
}

void SessionStore::revalidate_rebind_guard_if_due(PGconn* conn) const {
    if (!rebind_guard_ok_.load(std::memory_order_acquire))
        return; // sticky: a failure observed once stays until restart
    const std::int64_t now = steady_now_ms();
    std::int64_t due = next_validation_steady_ms_.load(std::memory_order_relaxed);
    if (now < due)
        return;
    // Exactly one thread per expiry runs the catalog query; the rest proceed.
    if (!next_validation_steady_ms_.compare_exchange_strong(
            due, now + validation_memo_ms_.load(std::memory_order_relaxed)))
        return;
    std::string cause;
    GuardCheck verdict;
    if (force_inconclusive_for_test_.load(std::memory_order_relaxed)) {
        verdict = GuardCheck::kInconclusive;
        cause = "forced by the test seam";
    } else {
        verdict = check_rebind_guard(conn, &cause);
    }
    switch (verdict) {
    case GuardCheck::kOk:
        last_validation_inconclusive_.store(false, std::memory_order_release);
        return;
    case GuardCheck::kFailed:
        rebind_guard_ok_.store(false, std::memory_order_release);
        spdlog::error("SessionStore: sessions_mfa_rebind_guard is missing, not ENABLE ALWAYS, or "
                      "altered; local MFA binding decisions now fail closed until restart");
        return;
    case GuardCheck::kInconclusive:
        // Not evidence about the trigger (query error, table unreachable): retry on the
        // next find rather than waiting out the memo and do not latch. The row is still served,
        // but flagged `guard_unverified` so a binding decision refuses this read. The cause is
        // logged once per episode (on the transition), not on every retry. The memo reset is a
        // release store so a thread that wins the CAS at 0 also sees the flag stored above.
        if (!last_validation_inconclusive_.exchange(true, std::memory_order_acq_rel))
            spdlog::warn("SessionStore: the rebind-guard check could not run ({}); local MFA "
                         "binding reads are refused as unavailable until a check succeeds, "
                         "session validation is unaffected",
                         cause);
        next_validation_steady_ms_.store(0, std::memory_order_release);
        return;
    }
}

std::expected<std::uint64_t, SessionStore::Error> SessionStore::read_generation() const {
    if (!open_)
        return std::unexpected(Error{"session store not open"});
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(Error{"database unavailable"});
    PgResult r = exec_params(
        lease.get(),
        "SELECT value FROM session_store.session_meta WHERE key='write_generation'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error{std::string("read_generation failed: ") +
                                     PQerrorMessage(lease.get())});
    if (PQntuples(r.get()) == 0)
        return std::uint64_t{0}; // no mutation has happened yet
    return to_u64(PQgetvalue(r.get(), 0, 0));
}

std::expected<SessionStore::ReapOutcome, SessionStore::Error>
SessionStore::reap_expired() {
    if (!open_)
        return std::unexpected(Error{"session store not open"});

    // Clock-guarded, single-writer across replicas. The advisory lock is taken as
    // its OWN statement before the check-and-delete (a CTE-embedded lock does not
    // work — fixed-snapshot hazard). now_ms is the DB clock (Postgres now(), read
    // once in-SQL under the lock below — the SAME clock that authors expires_at,
    // #3715), NOT a caller-supplied wall clock; it is sanitised against a durable
    // anchor in session_meta so a forward-skewed reading (an already-wrong clock on
    // the pass that matters) is DECLINED, not acted on. Every accepted pass is
    // unconditionally capped.
    //
    // Part-6 (missing-anchor) DECISION, recorded per the clock-guarded-retention
    // rule: on the FIRST pass (no `reap_anchor_ms` yet) this store PROCEEDS to
    // delete rather than declining — ResultSetStore's answer, not audit_store's.
    // Rationale: a session is REGENERABLE via re-login, so the worst case of a
    // from-boot forward-skewed clock on that first pass is a mass early logout
    // (annoying, self-healing), never the loss of non-reproducible compliance
    // evidence that makes audit_store/Guardian decline. Part-1 (would-wipe) is
    // deliberately NOT probed for the same reason api_token_store omits it:
    // sessions reach 100% expiry as routine drain, so a would-wipe verdict cannot
    // separate a true from a false positive here. The magnitude guard
    // (kMaxPlausibleSkewMs) still declines a later implausibly-forward reading.
    int deleted = 0;
    bool clock_anomaly = false;
    std::int64_t now_ms = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        if (exec_params(c, "SELECT pg_advisory_xact_lock(hashtext('session_store:reap'))",
                        std::vector<std::string>{})
                .status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock failed";
            return false;
        }
        // now_ms is the DB clock (`now()`, txn-stable), NOT a caller-supplied wall
        // clock — so the cutoff, the anchor comparison, and the anchor update all
        // live in the ONE clock domain that authored expires_at (design-review
        // S2). Read once under the lock and reuse for every guard below.
        {
            PgResult nr = exec_params(c, (std::string("SELECT ") + kDbNowMsSql).c_str(),
                                      std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "reap now() read failed";
                return false;
            }
            // SANITISE the reading (clock-guarded-retention part 3, #3785):
            // unparseable or negative is an ANOMALY, never a quiet fallback to
            // 0/silently-truncated garbage — the prior unchecked `to_i64` here
            // parsed a malformed/overflowed value with no error and no
            // rejection, in direct violation of this exact standing rule.
            const std::string now_raw = PQgetvalue(nr.get(), 0, 0);
            auto parsed_now = parse_reap_i64(now_raw);
            if (!parsed_now || *parsed_now < 0) {
                spdlog::warn("SessionStore::reap declined: unparseable or negative now() "
                             "reading '{}'",
                             now_raw);
                clock_anomaly = true;
                return true; // decline (commit the no-op lock release), anchor unchanged
            }
            now_ms = *parsed_now;
        }
        // Persisted anchor = the max now_ms any prior pass accepted. A reading
        // implausibly far ahead of it is an anomaly: decline this pass, do not
        // advance the anchor (part 2/3 — compare against a PERSISTED reading,
        // sanitise it).
        PgResult ar = exec_params(
            c, "SELECT value FROM session_store.session_meta WHERE key='reap_anchor_ms'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        std::int64_t anchor = 0;
        if (has_anchor) {
            // Same sanitisation as now_ms, for the SAME reason (#3785) — session_meta
            // is a plain key/value table a bad migration, a manual repair, or storage
            // corruption can write anything into. An unparseable or negative persisted
            // anchor is an anomaly: decline this pass rather than let the lenient
            // strtoll silently ACCEPT a corrupt value as a legitimate anchor — which
            // masks the corruption (a value that happens to parse within the plausible
            // window is taken as real, the pass deletes, and the anchor is advanced to
            // the corrupt reading) and, for an overflowed value, feeds the signed-
            // overflow comparison below. "Never a quiet reset" (clock-guard part 3).
            const std::string anchor_raw = PQgetvalue(ar.get(), 0, 0);
            auto parsed_anchor = parse_reap_i64(anchor_raw);
            if (!parsed_anchor || *parsed_anchor < 0) {
                spdlog::warn("SessionStore::reap declined: unparseable or negative persisted "
                             "anchor '{}'",
                             anchor_raw);
                clock_anomaly = true;
                return true; // decline, anchor unchanged
            }
            anchor = *parsed_anchor;
        }
        // Overflow-safe forward-skew comparison (#3785, mirroring execution_tracker.cpp's
        // PR #3780 round-2 fix): `parse_reap_i64` rejects unparseable/negative values but
        // NOT an implausibly-large one that parses cleanly (e.g. INT64_MAX from a bad
        // migration/manual repair/corruption) — `anchor + kMaxPlausibleSkewMs` on such a
        // value is signed-integer-overflow UB. Subtracting instead of adding cannot
        // overflow: both operands are already sanitised to be non-negative int64_t, so
        // their difference always fits (int64_t's negative range strictly exceeds its
        // positive range). The `now_ms >= anchor` guard preserves the existing branch
        // order — when now_ms < anchor, this is false and control falls through to the
        // backward-anomaly check below, unchanged.
        if (has_anchor && now_ms >= anchor && now_ms - anchor > kMaxPlausibleSkewMs) {
            spdlog::warn("SessionStore::reap declined: now_ms {} implausibly ahead of anchor {}",
                         now_ms, anchor);
            clock_anomaly = true;
            return true; // decline (commit the no-op lock release), anchor unchanged
        }
        // BACKWARD-anomaly guard (adversarial C8/K5): now_ms below the highest
        // accepted reading means the wall clock moved backward — either a genuine
        // backward step, or an earlier forward-skewed pass poisoned the anchor.
        // Decline (never delete under a rewound clock; never regress the anchor).
        // This is the SAFE direction: a poisoned anchor disables reap (rows
        // accrue, alertable via this warning) rather than mass-deleting live
        // sessions when a later, smaller forward skew reads as "behind" it.
        if (has_anchor && now_ms < anchor) {
            spdlog::warn("SessionStore::reap declined: now_ms {} is behind anchor {} (backward "
                         "clock movement or a poisoned anchor) — not deleting under a rewound clock",
                         now_ms, anchor);
            clock_anomaly = true;
            return true;
        }
        // Accepted pass: capped delete of absolutely-expired sessions.
        PgResult dr = exec_params(
            c,
            "DELETE FROM session_store.sessions WHERE token_hash IN "
            "(SELECT token_hash FROM session_store.sessions WHERE expires_at_ms < $1::bigint "
            "LIMIT $2::bigint) RETURNING token_hash",
            std::vector<std::string>{std::to_string(now_ms), std::to_string(kReapCap)});
        if (dr.status() != PGRES_TUPLES_OK) {
            err = std::string("reap delete failed: ") + PQerrorMessage(c);
            return false;
        }
        deleted = PQntuples(dr.get());
        // (std::max) parenthesised to dodge the <windows.h> `max` function-like macro (MSVC).
        const std::int64_t new_anchor = has_anchor ? (std::max)(anchor, now_ms) : now_ms;
        PgResult ur = exec_params(
            c,
            "INSERT INTO session_store.session_meta (key, value) VALUES ('reap_anchor_ms', $1) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "reap anchor update failed";
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(Error{err.empty() ? "reap failed" : err});
    return ReapOutcome{deleted, clock_anomaly};
}

} // namespace yuzu::server
