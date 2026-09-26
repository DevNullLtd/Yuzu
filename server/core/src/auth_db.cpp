/**
 * auth_db.cpp — Postgres-backed authentication persistence for Yuzu Server
 * (ADR-0006 server substrate migration; schema `auth`).
 *
 * Fixes carried forward from the SQLite-era Red Team review (semantics
 * preserved across the port):
 * - C1: Role parameter stripped from user creation (admin-only via separate endpoint)
 * - C2: Enrollment token consumption is atomic + persisted immediately
 * - C3: OIDC admin role ONLY via group membership (removed local username matching)
 * - H1: Username validation (alphanumeric + ._- only, no ':' config injection)
 *
 * ★ Security fix carried by THIS port: MFA readers that touch
 * `mfa_totp_secret` now fail CLOSED (`AuthDBError::SecretUnavailable`) on any
 * decrypt failure, rather than silently reading as "not enrolled" / "code
 * didn't match" — see auth_db.hpp's `AuthDBError::SecretUnavailable` doc.
 */

#include <yuzu/server/auth_db.hpp>

#include "background_jobs.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "acquire_retry.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "totp.hpp"

#include <spdlog/spdlog.h>

#include <libpq-fe.h>

// MSVC's STL does not transitively include these via <regex>/<chrono>/<thread>.
// Keep them explicit (cf. governance round 7ea7be6 + xp-B1 / cpp-SH-2).
#include <algorithm> // std::min
#include <atomic>
#include <cctype> // std::isalnum / std::toupper
#include <chrono>
#include <cstdlib> // std::strtoll
#include <span>
#include <thread>

namespace yuzu::server {

// The reserved engine-principal namespace (auth-engine-principals design
// §3.3 / decision log #3). Single literal so every write-surface guard in
// this file agrees on the exact prefix rather than re-deriving it.
// `rbac_store.cpp` has its own internal-linkage `kEnginePrefix` for the same
// string — no shared header exists across those two translation units, so
// this is auth_db.cpp's own copy.
constexpr std::string_view kEngineReservedPrefix = "engine:";

// ── Username Validation (H1 Fix) ─────────────────────────────────────────────

bool is_valid_username(const std::string& username) {
    if (username.empty() || username.size() > 64) {
        spdlog::warn("Username validation failed: invalid length ({})", username.size());
        return false;
    }
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-') {
            spdlog::warn("Username validation failed: invalid character '{}' in '{}'", c, username);
            return false;
        }
    }
    return true;
}

bool is_reserved_identity_prefix(const std::string& username) {
    static constexpr std::string_view kReservedPrefixes[] = {"oidc:", "saml:", "ad:",
                                                              kEngineReservedPrefix};
    for (auto prefix : kReservedPrefixes) {
        if (username.size() < prefix.size())
            continue;
        bool matches = true;
        for (std::size_t i = 0; i < prefix.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(username[i])) !=
                std::tolower(static_cast<unsigned char>(prefix[i]))) {
                matches = false;
                break;
            }
        }
        if (matches)
            return true;
    }
    return false;
}

bool is_valid_principal(const std::string& s) {
    if (is_valid_username(s)) {
        return true;
    }
    if (!is_reserved_identity_prefix(s)) {
        return false;
    }
    if (s.empty() || s.size() > 255) {
        return false;
    }
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7F || c == ';' || c == '=' || c == '\\' || c == '\'' ||
            c == '"' || c == '`' || c == ' ') {
            return false;
        }
    }
    return true;
}

namespace {

// ── PG result helpers ────────────────────────────────────────────────────────

// Null-safe column read: a NULL cell degrades to "" rather than dereferencing
// a nullptr into std::string. Mirrors api_token_store.cpp's `col`.
const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}

int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }

/// True if `s` contains an embedded NUL byte. PostgreSQL `text` columns
/// cannot round-trip one — `pg::exec_params` hands libpq a NUL-terminated
/// C string regardless of the caller's `std::string` length, so anything
/// after the first NUL is silently dropped on write, not stored. Same
/// truncation class as the SCIM parse-boundary guard
/// (`scim_json.cpp::has_embedded_nul`, #2018 UP-3) — `external_sub` in
/// particular is identity-matching material (SSO re-login resolves by
/// `external_iss`+`external_sub`), so a silently-truncated value here would
/// let a crafted "victim-sub\0decoy" collide with a shorter legitimate
/// subject.
bool has_embedded_nul(std::string_view s) {
    return s.find('\0') != std::string_view::npos;
}

// Same first advisory-lock key as PgMigrationRunner/SecretCodec (cluster-wide
// "yuzu" namespace, 2037545589); constant second key scoped to first-boot
// admin seeding. `INSERT ... SELECT ... WHERE NOT EXISTS` alone is NOT
// race-free under READ COMMITTED: two server processes racing first boot can
// each run their SELECT against a still-empty `auth.users`, see zero rows,
// and both proceed to INSERT before either commits — two admins (unhappy F2,
// governance hardening round). Wrapping the whole statement in a
// transaction-scoped advisory lock serializes the two processes so the loser
// re-evaluates WHERE NOT EXISTS against the winner's now-committed row and
// correctly no-ops.
constexpr const char* kSeedAdminLockSql =
    // Literal second key (not hashtext, which is NOT guaranteed stable across
    // Postgres major versions — two mixed-version first-boot processes could
    // otherwise compute different locks and both seed). `1` in the shared
    // `2037545589` yuzu namespace (the migration runner's global lock uses `0`).
    "SELECT pg_advisory_xact_lock(2037545589, 1)";

// ── Schema ────────────────────────────────────────────────────────────────

constexpr const char* kStoreName = "auth";

// Bounded acquires (ADR-0012 §2). Reads get the shorter budget; multi-
// statement / mutation paths get a little more room. Neither is unbounded —
// unbounded `acquire()` is construction-only (used once, in the ctor).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// Bounded acquire-retry (issue #2396). The shared PG pool arms a short
// connect-backoff breaker after a connectivity hiccup (pg_pool.cpp): for a
// 200ms..5s window EVERY acquire returns an empty lease *immediately*, so a
// single transient blip denies logins fleet-wide even after the database has
// recovered. A first acquire can also come back empty under genuine pool
// saturation. Both are TRANSIENT. `acquire_with_retry` rides one out by
// retrying the acquire a few times within a tight total budget, so a
// momentary blip does not turn into a total console lockout.
//
// This NEVER weakens the fail-closed guarantee: on budget exhaustion the
// caller still returns a store-unavailable error (`StoreBusy`) ->
// `is_store_unavailable()` -> 503, no session minted. Only the ACQUIRE is
// retried; a query that RAN and errored (non-`PGRES_TUPLES_OK`) is not an empty
// lease, will not self-heal in milliseconds, and is never retried.
//
// SCOPE (deliberately narrow — governance Gate 4, worker-pool starvation).
// Applied ONLY to the login-DECISION reads `mfa_status` and `load_mfa_row`,
// which run AFTER the /login handler releases its per-username stripe mutex
// (and, on the elevate / enrollment paths, outside that mutex entirely). It is
// deliberately NOT applied to the stripe-held lockout-section acquires
// (`lockout_status`, `record_failed_login`, `clear_failed_logins`), which keep
// their plain single `try_acquire_for`: sleeping under the stripe would extend
// the per-username hold from ~PBKDF2-time to ~PBKDF2+budget during an outage,
// so a same-username login pile-up would pin one httplib worker per attempt and
// starve unrelated routes (/metrics, SSE). `mfa_status` is also the exact call
// #2396 names as denying ALL logins — it 503s a legitimate, correct-password
// login on a blip — whereas the lockout-section reads either fail OPEN
// (`lockout_status` / `clear_failed_logins`) or only gate a wrong-password
// attempt (`record_failed_login`), so they lose nothing by not retrying. NO
// `acquire_with_retry` call therefore ever sleeps under the login stripe.
// Worst-case added latency past the first attempt:
// kAcquireRetries * (kAcquireRetryBackoff + kAcquireRetryTimeout) =
// 2 * (150 + 150) = 600ms.
constexpr int kAcquireRetries = 2; // extra attempts AFTER the first
constexpr std::chrono::milliseconds kAcquireRetryBackoff{150};
// >= the backoff so the retry acquire actually has time to catch a
// just-freed connection once the breaker clears, rather than fast-failing a
// too-narrow window into a false StoreBusy under mere contention (Gate 4 UP-3).
constexpr std::chrono::milliseconds kAcquireRetryTimeout{150};

// Acquire a pooled connection, retrying a bounded number of times on a
// transient empty lease (see the block above). Returns an empty lease iff the
// budget is exhausted — the caller maps that to `AuthDBError::StoreBusy`. The
// retry loop itself lives in the header-only, pool-free
// `detail::acquire_with_bounded_retry` so its ride-out-to-success behaviour is
// deterministically unit-testable without a live pool (adv-review CDX-P1-02).
[[nodiscard]] pg::PgPool::Lease acquire_with_retry(pg::PgPool& pool,
                                                   std::chrono::milliseconds first_timeout) {
    return detail::acquire_with_bounded_retry(
        kAcquireRetries,
        [&](bool first) {
            return pool.try_acquire_for(first ? first_timeout : kAcquireRetryTimeout);
        },
        [] { std::this_thread::sleep_for(kAcquireRetryBackoff); });
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly
    // (`auth.users`, ...). Deliberately NO `sessions` / `auth_kv` tables —
    // sessions stay in-memory only (AuthManager's `sessions_` map); `auth_kv`
    // was unused scaffolding in the SQLite era and is not carried forward.
    //
    // EXTERNAL cross-schema reader of `users.is_active` (routed-concerns
    // access-control table, "A2 global human role assignment" row):
    // `RbacStore::unassign_role`'s last-Administrator guard (rbac_store.cpp)
    // runs `rbac_store.principal_roles JOIN auth.users ... WHERE
    // u.is_active` in its OWN transaction, on the assumption this column
    // keeps its name and its "not soft-deleted / deactivated" meaning — the
    // precondition every LOCAL PASSWORD login path filters on (lockout via
    // locked_until/failed_login_count, an MFA-enrolled-but-pending account,
    // and --auth-mode=sso-only all additionally gate the local path). An
    // OIDC/SAML session is minted directly from IdP group membership
    // (AuthManager::create_oidc_session/create_saml_session, auth.cpp) and
    // never reads this column at all — see docs/user-manual/rbac.md's
    // local-account-only-check note (#4966) for the resulting guard-coverage
    // gap. A rename fails the guard closed (SQL error); a change to what
    // `is_active` *means* silently changes what the guard counts.
    //
    // The guard also TAKES A ROW LOCK on one `auth.users` row: after its
    // DELETE it runs `SELECT is_active FROM auth.users WHERE username = $1
    // FOR UPDATE` for the deleted principal, so a concurrent reactivation
    // (`reactivate_user`) cannot commit between that read and the guard's
    // own COMMIT. Its lock order is `rbac_store.principal_roles` rows, then
    // that one `auth.users` row, then `rbac_store.rbac_meta`. A change here
    // (e.g. a last-Administrator guard on `remove_user`, #4966) that holds an
    // `auth.users` row lock and then touches `principal_roles` or `rbac_meta`
    // would invert it and can deadlock; use one shared transaction-scoped
    // advisory lock instead of per-path row locks.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE users ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  username TEXT NOT NULL UNIQUE,"
         "  password_hash TEXT NOT NULL DEFAULT '',"
         "  salt_hex TEXT NOT NULL DEFAULT '',"
         "  role TEXT NOT NULL DEFAULT 'user',"
         "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  last_login_at TIMESTAMPTZ,"
         "  is_active BOOLEAN NOT NULL DEFAULT TRUE," // see RbacStore::unassign_role back-reference above
         "  mfa_totp_secret BYTEA,"
         "  mfa_enrolled_at TIMESTAMPTZ,"
         "  mfa_disabled_at TIMESTAMPTZ,"
         "  mfa_last_counter BIGINT NOT NULL DEFAULT 0,"
         "  failed_login_count INTEGER NOT NULL DEFAULT 0,"
         "  last_failed_login_at TIMESTAMPTZ,"
         "  locked_until TIMESTAMPTZ,"
         "  break_glass_armed_until TIMESTAMPTZ,"
         "  elevation_eligible BOOLEAN NOT NULL DEFAULT FALSE,"
         "  identity_source TEXT NOT NULL DEFAULT 'local',"
         "  external_iss TEXT,"
         "  external_sub TEXT,"
         "  display_name TEXT,"
         "  last_seen_at TIMESTAMPTZ,"
         "  provisioning_source TEXT NOT NULL DEFAULT 'local'"
         ");"
         "CREATE INDEX users_active_idx ON users (is_active) WHERE is_active;"

         "CREATE TABLE enrollment_tokens ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  token_hash TEXT NOT NULL UNIQUE,"
         "  created_by TEXT NOT NULL,"
         "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  expires_at TIMESTAMPTZ NOT NULL,"
         "  is_used BOOLEAN NOT NULL DEFAULT FALSE,"
         "  used_at TIMESTAMPTZ,"
         "  used_by_agent_id TEXT"
         ");"
         "CREATE INDEX enrollment_tokens_expires_idx ON enrollment_tokens (expires_at);"

         "CREATE TABLE pending_agents ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  agent_id TEXT NOT NULL UNIQUE,"
         "  hostname TEXT NOT NULL,"
         "  os TEXT,"
         "  arch TEXT,"
         "  agent_version TEXT,"
         "  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
         "  approved_at TIMESTAMPTZ,"
         "  approved_by TEXT,"
         "  status TEXT NOT NULL DEFAULT 'pending'"
         ");"
         "CREATE INDEX pending_agents_status_idx ON pending_agents (status);"

         "CREATE TABLE mfa_recovery_codes ("
         "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  username TEXT NOT NULL,"
         "  code_hash TEXT NOT NULL,"
         "  code_salt TEXT NOT NULL,"
         "  consumed_at TIMESTAMPTZ,"
         "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
         ");"
         "CREATE INDEX mfa_recovery_username_idx ON mfa_recovery_codes (username);"
         "CREATE INDEX mfa_recovery_unconsumed_idx ON mfa_recovery_codes (username) "
         "  WHERE consumed_at IS NULL;"},
    };
    return kMigrations;
}

constexpr int kRecoveryCodeCount = 10;
constexpr int kRecoveryCodePbkdfIters = 100'000;

// Txn-free core of recovery-code regeneration: DELETE the user's existing
// codes and INSERT `kRecoveryCodeCount` fresh ones, on a connection the
// CALLER already holds inside an open transaction (mirrors the SQLite-era
// `regenerate_recovery_codes_locked`, ported from `TxnGuard` to
// `pool.with_txn_for`'s callback connection).
//
// CONTRACT: the caller MUST already hold the `auth.users` row lock for
// `username` (a `SELECT … FOR UPDATE` or a guarded row `UPDATE`) for the life
// of this call. DELETE-all + INSERT is NOT self-serializing — two concurrent
// callers without that lock each persist 10 rows (20 total under READ
// COMMITTED, since neither DELETE sees the other's uncommitted INSERTs) and
// each receive a code set that does not match storage (#3779).
// `mfa_verify_enrollment` holds it via its guarded `UPDATE`;
// `mfa_regenerate_recovery_codes` via a `SELECT … FOR UPDATE`.
[[nodiscard]] std::expected<std::vector<std::string>, AuthDBError>
regenerate_recovery_codes_locked(PGconn* conn, const std::string& username) {
    pg::PgResult del = pg::exec_params(conn, "DELETE FROM auth.mfa_recovery_codes WHERE username = $1",
                                       std::vector<std::string>{username});
    if (del.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);

    std::vector<std::string> raw_codes;
    raw_codes.reserve(kRecoveryCodeCount);
    for (int i = 0; i < kRecoveryCodeCount; ++i) {
        auto code = mfa::random_recovery_code();
        std::string norm;
        norm.reserve(code.size());
        for (char c : code) {
            if (c == '-' || c == ' ')
                continue;
            norm += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        auto hash = auth::AuthManager::pbkdf2_sha256(norm, salt, kRecoveryCodePbkdfIters);

        pg::PgResult ins = pg::exec_params(
            conn, "INSERT INTO auth.mfa_recovery_codes (username, code_hash, code_salt) VALUES ($1,$2,$3)",
            std::vector<std::string>{username, hash, salt_hex});
        if (ins.status() != PGRES_COMMAND_OK)
            return std::unexpected(AuthDBError::WriteFailed);
        raw_codes.push_back(std::move(code));
    }
    return raw_codes;
}

// Row shape shared by every MFA reader that needs the encrypted secret +
// its AAD-binding row id. `secret_blob` is the raw envelope bytes (still
// encrypted) — empty when the column is NULL (no provisional/enrolled
// secret at all). `encode(col,'hex')`/`decode($n,'hex')` is used for every
// BYTEA read/write in this file rather than relying on the session's
// `bytea_output` GUC (hex is the modern default, but this makes the wire
// format explicit and GUC-independent — see the .hpp header note).
struct LoadedMfaRow {
    int64_t id{0};
    std::vector<uint8_t> secret_blob;
    bool enrolled{false};
    int64_t last_counter{0};
};

// ★ SECURITY (2026-07-25 review, HIGH #2): this helper returns a TYPED
// result, never a bare `optional`, because every one of its failure modes has
// a different correct response and an `optional` cannot carry them:
//
//   * `QueryFailed`   — the pool lease timed out OR the SELECT came back
//                       non-`PGRES_TUPLES_OK` (connection reset,
//                       `statement_timeout`, failover). BOTH are store
//                       outages. The second used to collapse into the same
//                       empty answer as "this user has no secret", which let
//                       `mfa_init_enrollment` mint a fresh secret over a live
//                       provisional one during a blip — precisely the outcome
//                       its own comment below says must never happen. The
//                       earlier `acquire_failed` out-param only ever covered
//                       the lease half, so it closed half the hole.
//   * `UserNotFound`  — no active row for this username. A real business
//                       outcome, not an outage.
//   * success         — the row was read. `secret_blob` MAY be empty; that is
//                       data, not an error, and the CALLER decides what it
//                       means (for an enrolled row it is `SecretUnavailable`;
//                       for a provisional one it is "mint a fresh secret").
//                       Folding it into a failure here is what erased the
//                       enrolled-vs-absent distinction from every caller.
[[nodiscard]] std::expected<LoadedMfaRow, AuthDBError> load_mfa_row(pg::PgPool& pool,
                                                                    const std::string& username) {
    auto lease = acquire_with_retry(pool, kReadTimeout); // #2396 transient-blip ride-out
    if (!lease)
        return std::unexpected(AuthDBError::StoreBusy);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, encode(mfa_totp_secret, 'hex'), (mfa_enrolled_at IS NOT NULL), mfa_last_counter "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);

    LoadedMfaRow out;
    out.id = to_i64(col(res.get(), 0, 0));
    if (!PQgetisnull(res.get(), 0, 1))
        out.secret_blob = auth::AuthManager::hex_to_bytes(col_str(res.get(), 0, 1));
    out.enrolled = to_bool(col(res.get(), 0, 2));
    out.last_counter = to_i64(col(res.get(), 0, 3));
    return out;
}

// Decrypt one loaded row's secret through the shared codec. Returns
// SecretUnavailable (never silently "not enrolled"/"no match") on any
// decrypt failure — the single chokepoint every MFA reader below funnels
// through.
[[nodiscard]] std::expected<SecureBuffer, AuthDBError>
decrypt_mfa_secret(pg::SecretCodec& codec, const LoadedMfaRow& row) {
    auto pk = pg::SecretCodec::encode_bigint_pk(row.id);
    auto dec = codec.decrypt(pg::SecretCodec::SecretId{"auth", "users", "mfa_totp_secret", pk},
                             row.secret_blob);
    if (!dec.has_value())
        return std::unexpected(AuthDBError::SecretUnavailable);
    return std::move(*dec);
}

} // namespace

// ── AuthDB Implementation ────────────────────────────────────────────────────

struct AuthDB::Impl {
    pg::PgPool& pool;
    pg::SecretCodec& secret_codec;
    bool open{false};
    int cleanup_interval_secs{60};

    // Background stale-provisional-MFA reaper. Sessions are no longer
    // persisted here at all, so this thread has exactly one job (unlike the
    // SQLite era, which also reaped expired session rows).
#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread;
#else
    std::thread cleanup_thread;
    std::atomic<bool> stop_cleanup{false};
#endif

    Impl(pg::PgPool& p, pg::SecretCodec& sc) : pool(p), secret_codec(sc) {}

    ~Impl() {
        // Stop the cleanup thread BEFORE either reference could conceivably
        // become invalid — the thread only touches `pool`/`secret_codec`
        // (both owned by the caller, outliving this AuthDB by contract), but
        // stopping first keeps teardown ordering simple and matches the
        // SQLite-era shutdown discipline.
#ifdef __cpp_lib_jthread
        if (cleanup_thread.joinable()) {
            cleanup_thread.request_stop();
            cleanup_thread.join();
        }
#else
        stop_cleanup.store(true);
        if (cleanup_thread.joinable()) {
            cleanup_thread.join();
        }
#endif
    }
};

AuthDB::AuthDB(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : AuthDB(pool, secret_codec, /*cleanup_interval_secs=*/60) {}

AuthDB::AuthDB(pg::PgPool& pool, pg::SecretCodec& secret_codec, int cleanup_interval_secs)
    : impl_(std::make_unique<Impl>(pool, secret_codec)) {
    impl_->cleanup_interval_secs = cleanup_interval_secs;

    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = impl_->pool.acquire();
    if (!lease) {
        spdlog::error("AuthDB: no database connection at construction ({}) — auth store disabled",
                      impl_->pool.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AuthDB: schema migration failed — auth store disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010: register the sole secret-bearing column. This ctor never
    // calls `secret_codec.init()` — the codec is only CONSTRUCTED by the
    // caller at this point; `init()` (substrate-level boot init) runs AFTER
    // this ctor returns, once `mfa_totp_secret` has been registered and
    // `auth.users` has been migrated, so the column it validates already
    // exists (authdb MEDIUM, governance hardening round — this comment
    // previously had the order backwards: register-then-init, not
    // init-then-register).
    if (!impl_->secret_codec.register_secret_column({"auth", "users", "mfa_totp_secret", "id"})) {
        spdlog::error(
            "AuthDB: failed to register mfa_totp_secret as a secret column — auth store disabled");
        return;
    }

    impl_->open = true;
    spdlog::info("AuthDB: opened (schema {})", kStoreName);

    if (impl_->cleanup_interval_secs <= 0) {
        spdlog::info("AuthDB: cleanup thread disabled (interval={})", impl_->cleanup_interval_secs);
        return;
    }

    YUZU_ASSERT_BACKGROUND_JOB("auth_db.cleanup_provisional_mfa"); // WS-10 ReplicaSafe (idempotent)
#ifdef __cpp_lib_jthread
    impl_->cleanup_thread = std::jthread([this, interval = impl_->cleanup_interval_secs](
                                             std::stop_token stop) {
        while (!stop.stop_requested()) {
            for (int i = 0; i < interval && !stop.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (stop.stop_requested())
                break;
            auto mfa_result = cleanup_provisional_mfa();
            if (!mfa_result) {
                spdlog::warn("AuthDB: periodic provisional-MFA cleanup failed: error={}",
                             static_cast<int>(mfa_result.error()));
            } else if (*mfa_result > 0) {
                spdlog::info("AuthDB: reaped {} stale provisional MFA enrollments", *mfa_result);
            }
        }
    });
#else
    impl_->cleanup_thread = std::thread([this, interval = impl_->cleanup_interval_secs]() {
        while (!impl_->stop_cleanup.load()) {
            for (int i = 0; i < interval && !impl_->stop_cleanup.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (impl_->stop_cleanup.load())
                break;
            auto mfa_result = cleanup_provisional_mfa();
            if (!mfa_result) {
                spdlog::warn("AuthDB: periodic provisional-MFA cleanup failed: error={}",
                             static_cast<int>(mfa_result.error()));
            } else if (*mfa_result > 0) {
                spdlog::info("AuthDB: reaped {} stale provisional MFA enrollments", *mfa_result);
            }
        }
    });
#endif
}

AuthDB::~AuthDB() = default;

void AuthDB::request_stop() noexcept {
    // Signal-only: request the reaper to exit but do NOT join here (the join
    // stays in ~Impl). Idempotent — safe to call before destruction and safe
    // to call more than once. The reaper checks this each 1s of its sleep, so
    // an early call lets it wind down concurrently with the rest of shutdown.
    if (!impl_)
        return;
#ifdef __cpp_lib_jthread
    impl_->cleanup_thread.request_stop();
#else
    impl_->stop_cleanup.store(true);
#endif
}

bool AuthDB::is_ready() const noexcept { return impl_ && impl_->open; }
bool AuthDB::is_open() const noexcept { return is_ready(); }

// ── User Operations ──────────────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::upsert_user(const std::string& username,
                                                     const std::string& password_hash,
                                                     const std::string& salt_hex, auth::Role role) {
    if (!is_valid_username(username)) {
        spdlog::warn("upsert_user rejected invalid username: '{}'", username);
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    std::string role_str = (role == auth::Role::admin) ? "admin" : "user";

    // INSERT ... ON CONFLICT DO NOTHING (never DO UPDATE) — prevents the
    // TOCTOU race where two concurrent requests could both pass
    // user_exists(), then one overwrites the other's credentials. Callers
    // use update_role() for role changes.
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO auth.users (username, password_hash, salt_hex, role, updated_at) "
        "VALUES ($1,$2,$3,$4,now()) ON CONFLICT (username) DO NOTHING RETURNING id",
        std::vector<std::string>{username, password_hash, salt_hex, role_str});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0) {
        spdlog::warn("upsert_user: user already exists, not overwriting: '{}'", username);
        return std::unexpected(AuthDBError::UserAlreadyExists);
    }
    spdlog::info("User upserted: {} (role={})", username, role_str);
    return {};
}

std::expected<bool, AuthDBError> AuthDB::seed_admin_if_empty(const std::string& username,
                                                              const std::string& password_hash,
                                                              const std::string& salt_hex) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Advisory-lock-guarded transaction (governance hardening round, unhappy
    // F2): the `INSERT ... SELECT ... WHERE NOT EXISTS` statement alone is
    // NOT race-free under READ COMMITTED — see kSeedAdminLockSql's doc
    // comment. Taking `pg_advisory_xact_lock` first serializes two processes
    // racing first boot so only one ever inserts.
    bool seeded = false;
    const bool ok = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res{PQexec(conn, kSeedAdminLockSql)};
        if (lock_res.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult res = pg::exec_params(
            conn,
            "INSERT INTO auth.users (username, password_hash, salt_hex, role) "
            "SELECT $1, $2, $3, 'admin' WHERE NOT EXISTS (SELECT 1 FROM auth.users) RETURNING id",
            std::vector<std::string>{username, password_hash, salt_hex});
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        seeded = PQntuples(res.get()) > 0;
        return true;
    });
    if (!ok)
        return std::unexpected(AuthDBError::WriteFailed);
    if (seeded)
        spdlog::info("AuthDB: seeded first admin user '{}'", username);
    return seeded;
}

std::expected<void, AuthDBError> AuthDB::upsert_sso_identity(const std::string& principal,
                                                              const std::string& iss,
                                                              const std::string& sub,
                                                              const std::string& display_name,
                                                              const std::string& source) {
    if (principal.starts_with(kEngineReservedPrefix)) {
        spdlog::warn("upsert_sso_identity rejected reserved 'engine:' principal: '{}'", principal);
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (!is_valid_principal(principal)) {
        spdlog::warn("upsert_sso_identity rejected invalid principal: '{}'", principal);
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // ★ SECURITY (security-guardian LOW): reject an embedded NUL in any of
    // the identity-matching/display fields before they ever reach
    // exec_params — see has_embedded_nul's doc comment. `iss`/`sub` are the
    // re-login match key; `display_name` is operator-facing but stored
    // alongside them, so it is rejected too rather than silently truncated.
    if (has_embedded_nul(iss) || has_embedded_nul(sub) || has_embedded_nul(display_name) ||
        has_embedded_nul(principal)) {
        spdlog::warn("upsert_sso_identity rejected embedded NUL in principal/iss/sub/display_name");
        return std::unexpected(AuthDBError::WriteFailed);
    }

    // password_hash/salt_hex are '' — never resolvable on the local login
    // path. role='user' on first insert only; the ON CONFLICT arm
    // deliberately omits role/elevation_eligible/is_active so a standing
    // grant, JIT eligibility, and a deprovisioning-sweep soft-delete all
    // survive re-login (#1852 CRITICAL invariant / governance round).
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO auth.users(username, password_hash, salt_hex, role, identity_source, "
        "                       external_iss, external_sub, display_name, last_seen_at) "
        "VALUES ($1, '', '', 'user', $2, $3, $4, $5, now()) "
        "ON CONFLICT (username) DO UPDATE SET "
        "  display_name = excluded.display_name, last_seen_at = now() "
        "RETURNING id",
        std::vector<std::string>{principal, source, iss, sub, display_name});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("upsert_sso_identity failed for '{}'", principal);
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

std::expected<auth::UserEntry, AuthDBError> AuthDB::get_user(const std::string& username) {
    // Gate 4 governance BLOCKING finding (unhappy-path): unlike ~20 sibling
    // AuthDB methods, this READ path never validated `username` at all before
    // handing it to PQexecParams. PQexecParams is called with paramLengths=
    // nullptr (pg_exec.hpp), so libpq reads every text-format parameter as a
    // NUL-terminated C string — an embedded NUL in `username` (trivially
    // produced by URL-decoding a request body's "username=admin%00<garbage>")
    // makes the SQL query match the TRUNCATED prefix ("admin") while the
    // FULL raw C++ string (NUL and garbage suffix included) is what callers
    // use as an in-memory map/session key. #4020 made this function newly
    // reachable, unauthenticated, from POST /login's raw form field (via
    // find_user_or_hydrate -> verify_password/authenticate), where the
    // returned row was then try_emplace'd into AuthManager::users_ keyed by
    // the FULL mangled string — every distinct garbage suffix an attacker
    // sends for the SAME real username creates a new, permanent, unevictable
    // cache entry (unauthenticated, unbounded memory growth) and, if the
    // attacker also holds the real password, mints a session whose
    // `Session::username` (the same mangled string) never matches the
    // canonical name compared during remove_user()/update_role()'s session
    // sweep — surviving a demotion or removal. Both closed at the source:
    // reject here, before any query or any caller ever sees a successful
    // result to cache.
    //
    // `is_valid_principal`, NOT `is_valid_username`: `auth.users.username`
    // legitimately holds SSO principal strings too (upsert_sso_identity
    // stores an "oidc:"/"saml:"/"ad:"-prefixed principal directly as this
    // column, validated there via this SAME wider function) — and this
    // function IS called with such a principal today, via
    // get_user_role(api_token.principal_id) at auth_routes.cpp's legacy
    // API-token session synthesis for an SSO-authenticated human's token.
    // is_valid_username() would reject the ':' every SSO-prefixed principal
    // contains, silently demoting every such token to Role::user
    // (auth_routes.cpp's own .value_or(Role::user)) — a regression nearly as
    // bad as the vulnerability this fixes. is_valid_principal() still closes
    // the NUL-byte attack: its non-prefixed branch delegates to
    // is_valid_username's own alnum/./_/- allowlist (NUL is none of those),
    // and its reserved-prefix branch explicitly rejects every byte < 0x20
    // (NUL included) plus a control/shell-metacharacter set.
    if (!is_valid_principal(username)) {
        spdlog::warn("get_user rejected invalid username/principal: '{}'", username);
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT username, role, password_hash, salt_hex, identity_source "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);

    auth::UserEntry entry;
    entry.username = col_str(res.get(), 0, 0);
    entry.role = auth::string_to_role(col_str(res.get(), 0, 1));
    entry.hash_hex = col_str(res.get(), 0, 2);
    entry.salt_hex = col_str(res.get(), 0, 3);
    entry.identity_source = col_str(res.get(), 0, 4);
    return entry;
}

std::expected<std::vector<auth::UserEntry>, AuthDBError> AuthDB::list_users() {
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT username, role, identity_source FROM auth.users "
                        "WHERE is_active = TRUE ORDER BY username",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);

    std::vector<auth::UserEntry> users;
    const int rows = PQntuples(res.get());
    users.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        auth::UserEntry entry;
        entry.username = col_str(res.get(), i, 0);
        entry.role = auth::string_to_role(col_str(res.get(), i, 1));
        entry.identity_source = col_str(res.get(), i, 2);
        users.push_back(std::move(entry));
    }
    return users;
}

std::expected<std::vector<UserWithStatus>, AuthDBError> AuthDB::list_users_including_inactive() {
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT username, role, identity_source, is_active FROM auth.users "
                        "ORDER BY username",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);

    std::vector<UserWithStatus> users;
    const int rows = PQntuples(res.get());
    users.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        UserWithStatus entry;
        entry.username = col_str(res.get(), i, 0);
        entry.role = auth::string_to_role(col_str(res.get(), i, 1));
        entry.identity_source = col_str(res.get(), i, 2);
        entry.is_active = to_bool(col(res.get(), i, 3));
        users.push_back(std::move(entry));
    }
    return users;
}

std::optional<std::vector<std::string>> AuthDB::find_reserved_prefix_users(const std::string& prefix) {
    // `prefix` is code-controlled (e.g. "engine:"), never user input — fail
    // closed (nullopt = cannot verify) rather than trust the caller if it ever
    // carries a LIKE metacharacter.
    if (prefix.empty() || prefix.find_first_of("%_\\") != std::string::npos)
        return std::nullopt;

    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    std::string pattern = prefix + "%";
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT username FROM auth.users WHERE username LIKE $1",
                                       std::vector<std::string>{pattern});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt; // scan error → fail closed, never "no collision"

    std::vector<std::string> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(col_str(res.get(), i, 0));
    return result;
}

void AuthDB::touch_last_login(const std::string& username) {
    if (!is_valid_username(username))
        return;
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return;
    pg::PgResult res = pg::exec_params(
        lease.get(), "UPDATE auth.users SET last_login_at = now() WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("touch_last_login failed for '{}'", username);
}

std::expected<bool, AuthDBError> AuthDB::remove_user(const std::string& username) {
    // SOC 2 CC6.8 — credential revocation on termination. Soft-delete +
    // wipe MFA enrollment material atomically (a returning/reactivated user
    // must never silently inherit a stale secret). No session-invalidation
    // side effect here — AuthDB carries no session surface at all (see the
    // .hpp header note); AuthManager wipes its own in-memory map.
    bool removed = false;
    const bool ok = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // AND is_active = TRUE: re-removing an already-inactive row must be a
        // no-op (matches zero rows -> removed=false), never a spurious
        // "re-removal" success — the test/caller contract is idempotent-false,
        // not idempotent-true, on an already-soft-deleted user.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE auth.users SET is_active = FALSE, mfa_totp_secret = NULL, mfa_enrolled_at = NULL, "
            "mfa_disabled_at = now(), mfa_last_counter = 0, updated_at = now() "
            "WHERE username = $1 AND is_active = TRUE RETURNING id",
            std::vector<std::string>{username});
        if (upd.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(upd.get()) == 0) {
            removed = false;
            return true; // commit a no-op — user not found is not a write failure
        }
        removed = true;
        pg::PgResult del = pg::exec_params(conn, "DELETE FROM auth.mfa_recovery_codes WHERE username = $1",
                                           std::vector<std::string>{username});
        return del.status() == PGRES_COMMAND_OK;
    });
    if (!ok)
        return std::unexpected(AuthDBError::WriteFailed);

    if (removed) {
        spdlog::info("User removed (MFA state cleared): {}", username);
    } else {
        spdlog::warn("User not found for removal: {}", username);
    }
    return removed;
}

std::expected<bool, AuthDBError> AuthDB::user_exists(const std::string& username) {
    // Contract (see .hpp): "active only" — a soft-deleted row must read as
    // absent, matching get_user()'s is_active filter (Postgres-port fix:
    // the initial port dropped this filter, so a removed user still read
    // as existing).
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    return to_i64(col(res.get(), 0, 0)) > 0;
}

// ── Role Update (C1 FIX — Separate from upsert_user to avoid password overwrite) ──

std::expected<void, AuthDBError> AuthDB::update_role(const std::string& username,
                                                     auth::Role new_role) {
    if (!is_valid_username(username)) {
        spdlog::warn("update_role rejected invalid username: '{}'", username);
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    std::string role_str = (new_role == auth::Role::admin) ? "admin" : "user";

    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET role = $1, updated_at = now() WHERE username = $2 AND is_active = TRUE "
        "RETURNING id",
        std::vector<std::string>{role_str, username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0) {
        spdlog::warn("update_role: user not found or inactive: '{}'", username);
        return std::unexpected(AuthDBError::UserNotFound);
    }
    spdlog::info("User role updated: {} -> {}", username, role_str);
    return {};
}

std::expected<void, AuthDBError>
AuthDB::recheck_role_locked(const std::string& username,
                            const std::function<void(auth::Role)>& under_row_lock) {
    // is_valid_principal, NOT is_valid_username: this is called on the exact
    // same path as get_user() (via AuthManager::recheck_role_after_credential_
    // check, reachable with an SSO-prefixed principal) - see get_user()'s own
    // header comment for the full rationale.
    if (!is_valid_principal(username))
        return std::unexpected(AuthDBError::InvalidUsername);

    // #4107: SELECT ... FOR UPDATE serializes this read against any
    // concurrent update_role()/reactivate_user() write - same technique as
    // mfa_verify_login_code's replay guard above. kWriteTimeout (not
    // kReadTimeout) because FOR UPDATE takes a write-class lock, matching
    // that precedent. with_txn_for does a SINGLE bounded try_acquire_for (no
    // #2396 retry loop), matching the acquire-shape discipline this file's
    // stripe-held call sites already use.
    //
    // Safety argument (security-guardian Gate 8 re-review correction: an
    // earlier draft of this comment leaned on the /login stripe mutex -
    // auth_routes.cpp's login_lock_for - as if it universally guarded this
    // call; it doesn't, since the stripe is only taken when
    // `auth_lockout_threshold > 0`, an operator-configurable setting that
    // can be 0). The actual safety argument doesn't need the stripe: this
    // critical section (one SELECT, one fast/uncontended mu_ map write, one
    // COMMIT) is microseconds, not anywhere near kWriteTimeout's ceiling, so
    // N concurrent same-username rechecks drain in roughly N x low-single-
    // digit-ms regardless of whether the stripe happens to be serializing
    // them too - the row lock's own bounded hold time is what keeps this
    // safe on the shared connection pool, with or without the stripe.
    //
    // authdb Gate 8 finding: kWriteTimeout only bounds the connection
    // ACQUIRE (with_txn_for's try_acquire_for). Once inside the txn, the
    // FOR UPDATE's own row-lock WAIT is bounded by PgPool::connect_one's
    // per-connection `lock_timeout` (10000ms default, pg_pool.hpp) unless
    // overridden - a contended lock could otherwise block ~5x longer than
    // this call's own acquire bound. The set_config() call below closes
    // that: it scopes to this transaction only (no leak back to the pooled
    // connection) and matches the wait bound to kWriteTimeout itself, so a
    // genuinely stuck writer fails this call closed (QueryFailed, via the
    // SQLSTATE 55P03 lock_timeout error surfacing as a non-PGRES_COMMAND_OK/
    // TUPLES_OK status) well inside the caller's own expectations.
    std::optional<AuthDBError> err;
    const bool committed = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Bound parameter, not string interpolation (authdb review contract,
        // .claude/agents/authdb.md: "zero string interpolation", SQL string
        // interpolation grades HIGH/block-merge - fjarvis PR #4076 re-review
        // caught the prior version building this via std::to_string +
        // concatenation, even though the value was a trusted compile-time
        // constant). set_config('lock_timeout', $1, true) is the
        // parameterized equivalent of `SET LOCAL lock_timeout = $1` - the
        // third argument (is_local=true) scopes it to this transaction only,
        // identically to SET LOCAL.
        pg::PgResult set_lt = pg::exec_params(
            conn, "SELECT set_config('lock_timeout', $1, true)",
            std::vector<std::string>{std::to_string(kWriteTimeout.count()) + "ms"});
        if (set_lt.status() != PGRES_TUPLES_OK) {
            err = AuthDBError::QueryFailed;
            return false;
        }
        pg::PgResult sel = pg::exec_params(
            conn, "SELECT role FROM auth.users WHERE username = $1 AND is_active = TRUE FOR UPDATE",
            std::vector<std::string>{username});
        if (sel.status() != PGRES_TUPLES_OK) {
            err = AuthDBError::QueryFailed;
            return false;
        }
        if (PQntuples(sel.get()) == 0) {
            // No active row - either never existed, or a concurrent
            // remove_user() already committed its soft-delete UPDATE (which
            // took this SAME row lock for its own transaction, so this
            // SELECT either saw it directly or waited for it) before this
            // SELECT ran.
            err = AuthDBError::UserNotFound;
            return false;
        }
        // under_row_lock runs here, still holding the row lock - see the
        // header doc: fast, local, in-process work only, no further DB I/O.
        under_row_lock(auth::string_to_role(col_str(sel.get(), 0, 0)));
        return true; // commit - releases the row lock; no DB mutation to persist
    });
    if (err)
        return std::unexpected(*err);
    if (!committed)
        return std::unexpected(AuthDBError::QueryFailed);
    return {};
}

std::expected<void, AuthDBError> AuthDB::set_elevation_eligible(const std::string& username,
                                                               bool eligible) {
    if (!is_valid_principal(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET elevation_eligible = $1::boolean, updated_at = now() "
        "WHERE username = $2 AND is_active = TRUE RETURNING elevation_eligible",
        std::vector<std::string>{eligible ? "true" : "false", username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    return {};
}

std::expected<bool, AuthDBError> AuthDB::is_elevation_eligible(const std::string& username) {
    if (!is_valid_principal(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT elevation_eligible FROM auth.users WHERE username = $1 AND is_active = TRUE",
                        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    if (PQntuples(res.get()) == 0)
        return false; // no active row → fail-closed (not eligible)
    return to_bool(col(res.get(), 0, 0));
}

std::expected<void, AuthDBError> AuthDB::set_provisioning_source(const std::string& username,
                                                                  const std::string& source) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET provisioning_source = $1, updated_at = now() "
        "WHERE username = $2 AND is_active = TRUE RETURNING provisioning_source",
        std::vector<std::string>{source, username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    return {};
}

std::expected<std::string, AuthDBError>
AuthDB::get_provisioning_source(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Deliberately NO `is_active = TRUE` filter — see the .hpp doc comment:
    // the SCIM provenance guard must read a soft-deleted row too.
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT provisioning_source FROM auth.users WHERE username = $1",
                                       std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    return col_str(res.get(), 0, 0);
}

std::expected<void, AuthDBError> AuthDB::set_identity_source(const std::string& username,
                                                              const std::string& source) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET identity_source = $1, updated_at = now() "
        "WHERE username = $2 AND is_active = TRUE RETURNING identity_source",
        std::vector<std::string>{source, username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    return {};
}

std::expected<void, AuthDBError> AuthDB::reactivate_user(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // No `is_active = TRUE` filter — this is the ONLY writer that revives a
    // soft-deleted row. See the .hpp doc comment for the full semantics
    // contract (clears lockout state; leaves MFA/provisioning_source/role
    // untouched).
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET is_active = TRUE, updated_at = now(), failed_login_count = 0, "
        "last_failed_login_at = NULL, locked_until = NULL WHERE username = $1 RETURNING id",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    spdlog::info("User reactivated: {}", username);
    return {};
}

std::expected<int, AuthDBError>
AuthDB::cleanup_provisional_mfa(std::chrono::seconds older_than) {
    auto secs = older_than.count();
    if (secs < 60)
        secs = 60; // never clear a row still inside the enrollment UX window
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET mfa_totp_secret = NULL, mfa_last_counter = 0, updated_at = now() "
        "WHERE mfa_enrolled_at IS NULL AND mfa_totp_secret IS NOT NULL "
        "AND updated_at < now() - make_interval(secs => $1::int) RETURNING id",
        std::vector<std::string>{std::to_string(secs)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    return PQntuples(res.get());
}

// ── Account-lockout Operations ────────────────────────────────────────────────

std::expected<AuthDB::LockoutStatus, AuthDBError>
AuthDB::lockout_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Plain single acquire: #2396's bounded RETRY is deliberately NOT applied
    // here (nor in record_failed_login / clear_failed_logins) — this read runs
    // under the /login per-username stripe mutex, and retrying (sleeping) under
    // it would amplify an outage into worker-pool starvation (see
    // acquire_with_retry). An empty lease still reports StoreBusy (empty lease
    // == StoreBusy, retry or not), so a pool-acquire timeout stays correctly
    // labelled; lockout_status fails OPEN at the caller regardless.
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::StoreBusy);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT failed_login_count, COALESCE((locked_until AT TIME ZONE 'UTC')::text, ''), "
        "(locked_until IS NOT NULL AND locked_until > now()) "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    LockoutStatus out;
    if (PQntuples(res.get()) > 0) {
        out.failed_count = static_cast<int>(to_i64(col(res.get(), 0, 0)));
        out.locked_until = col_str(res.get(), 0, 1);
        out.locked = to_bool(col(res.get(), 0, 2));
    }
    // No active row → zero-initialised (not-locked) status; anti-enumeration.
    return out;
}

std::expected<AuthDB::LockoutRecord, AuthDBError>
AuthDB::record_failed_login(const std::string& username, int threshold, int window_secs) {
    LockoutRecord out;
    if (threshold <= 0) {
        return out; // feature disabled — pure no-op
    }
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // No clamp on window_secs: a negative window (already-expired lock) is a
    // legitimate, deliberate caller shape — the account-lockout test suite
    // synthesizes an already-expired lock this way (same SQLite-era
    // contract), and `make_interval(secs => ...)` handles negative values
    // correctly (a past `locked_until`). Production callers always pass a
    // positive operator-configured window; there is nothing to defend here.

    // Plain single acquire: stripe-held write, no #2396 retry (see
    // acquire_with_retry SCOPE). A blip here only 503s a wrong-password
    // attempt, and retrying under the login stripe is the starvation vector.
    // An empty lease reports StoreBusy so this fail-closed 503's degrade metric
    // labels a pool-acquire timeout as pool_acquire_timeout, not query_error.
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::StoreBusy);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users "
        "SET failed_login_count = CASE "
        "        WHEN locked_until IS NOT NULL AND locked_until <= now() THEN 1 "
        "        ELSE failed_login_count + 1 "
        "    END, "
        "    last_failed_login_at = now(), "
        "    locked_until = CASE "
        "        WHEN locked_until IS NOT NULL AND locked_until <= now() "
        "            THEN CASE WHEN 1 >= $1::int THEN now() + make_interval(secs => $2::int) ELSE NULL END "
        "        ELSE CASE WHEN failed_login_count + 1 >= $1::int "
        "                  THEN now() + make_interval(secs => $2::int) "
        "                  ELSE locked_until END "
        "    END "
        "WHERE username = $3 AND is_active = TRUE "
        "RETURNING failed_login_count, COALESCE((locked_until AT TIME ZONE 'UTC')::text, ''), "
        "          (locked_until IS NOT NULL AND locked_until > now())",
        std::vector<std::string>{std::to_string(threshold), std::to_string(window_secs), username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return out; // no such active user → clean not-locked state
    out.failed_count = static_cast<int>(to_i64(col(res.get(), 0, 0)));
    out.locked_until = col_str(res.get(), 0, 1);
    out.locked = to_bool(col(res.get(), 0, 2));
    out.just_locked = out.locked && (out.failed_count == threshold);
    return out;
}

std::expected<void, AuthDBError> AuthDB::clear_failed_logins(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Plain single acquire: stripe-held write, no #2396 retry (see
    // acquire_with_retry SCOPE). clear_failed_logins fails OPEN at the caller,
    // so a blip here is logged and the login proceeds — nothing to ride out.
    // An empty lease still reports StoreBusy (empty lease == StoreBusy).
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::StoreBusy);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL "
        "WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    return {};
}

// ── Break-glass arming (hardened mode) ───────────────────────────────────────

std::expected<AuthDB::BreakGlassStatus, AuthDBError>
AuthDB::break_glass_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COALESCE((break_glass_armed_until AT TIME ZONE 'UTC')::text, ''), "
        "(break_glass_armed_until IS NOT NULL AND break_glass_armed_until > now()) "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    BreakGlassStatus out;
    if (PQntuples(res.get()) > 0) {
        out.armed_until = col_str(res.get(), 0, 0);
        out.armed = to_bool(col(res.get(), 0, 1));
    }
    return out;
}

std::expected<AuthDB::BreakGlassStatus, AuthDBError>
AuthDB::arm_break_glass(const std::string& username, int window_secs) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (window_secs < 1) {
        window_secs = 1;
    }
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET break_glass_armed_until = now() + make_interval(secs => $1::int) "
        "WHERE username = $2 AND is_active = TRUE "
        "RETURNING COALESCE((break_glass_armed_until AT TIME ZONE 'UTC')::text, ''), "
        "          (break_glass_armed_until IS NOT NULL AND break_glass_armed_until > now())",
        std::vector<std::string>{std::to_string(window_secs), username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    BreakGlassStatus out;
    out.armed_until = col_str(res.get(), 0, 0);
    out.armed = to_bool(col(res.get(), 0, 1));
    return out;
}

std::expected<void, AuthDBError> AuthDB::disarm_break_glass(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "UPDATE auth.users SET break_glass_armed_until = NULL WHERE username = $1",
                                       std::vector<std::string>{username});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    return {};
}

std::optional<std::string> break_glass_account_problem(AuthDB& db, const std::string& username) {
    if (!is_valid_username(username)) {
        return "not a valid username";
    }
    auto exists = db.user_exists(username);
    if (!exists) {
        return "auth store error while checking the account";
    }
    if (!*exists) {
        return "account does not exist";
    }
    auto mfa = db.mfa_status(username);
    if (!mfa) {
        return "auth store error while checking MFA enrollment";
    }
    if (!mfa->enrolled) {
        return "account has no MFA enrolled, or the account is deactivated (a break-glass account "
               "must be active and carry a second factor)";
    }
    return std::nullopt;
}

// ── MFA / TOTP Operations ────────────────────────────────────────────────────

std::expected<AuthDB::MfaStatus, AuthDBError> AuthDB::mfa_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    auto lease = acquire_with_retry(impl_->pool, kReadTimeout); // #2396 transient-blip ride-out
    if (!lease)
        return std::unexpected(AuthDBError::StoreBusy);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, encode(mfa_totp_secret, 'hex'), (mfa_enrolled_at IS NOT NULL), "
        "COALESCE((mfa_enrolled_at AT TIME ZONE 'UTC')::text, ''), "
        "COALESCE((mfa_disabled_at AT TIME ZONE 'UTC')::text, '') "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);

    const int64_t user_id = to_i64(col(res.get(), 0, 0));
    const bool has_secret = !PQgetisnull(res.get(), 0, 1);
    const bool enrolled_flag = to_bool(col(res.get(), 0, 2));

    MfaStatus status;
    status.disabled_at = col_str(res.get(), 0, 4);

    if (!enrolled_flag) {
        // Genuinely not enrolled — a provisional secret, if any, does not
        // count (matches the SQLite-era contract).
        status.enrolled = false;
    } else {
        // ★ Enrolled: the secret MUST decrypt, or this is SecretUnavailable —
        // never silently "not enrolled". See AuthDBError::SecretUnavailable.
        if (!has_secret)
            return std::unexpected(AuthDBError::SecretUnavailable);
        LoadedMfaRow row;
        row.id = user_id;
        row.secret_blob = auth::AuthManager::hex_to_bytes(col_str(res.get(), 0, 1));
        auto dec = decrypt_mfa_secret(impl_->secret_codec, row);
        if (!dec.has_value())
            return std::unexpected(dec.error());
        status.enrolled = true;
        status.enrolled_at = col_str(res.get(), 0, 3);
    }

    // Recovery-code count is best-effort display metadata (matches the
    // SQLite-era contract — a failure here does not fail the whole read).
    auto lease2 = impl_->pool.try_acquire_for(kReadTimeout);
    if (lease2) {
        pg::PgResult cres = pg::exec_params(
            lease2.get(), "SELECT COUNT(*) FROM auth.mfa_recovery_codes WHERE username = $1 AND consumed_at IS NULL",
            std::vector<std::string>{username});
        if (cres.status() == PGRES_TUPLES_OK && PQntuples(cres.get()) > 0)
            status.recovery_codes_remaining = static_cast<int>(to_i64(col(cres.get(), 0, 0)));
    }
    return status;
}

std::expected<AuthDB::MfaEnrollmentInit, AuthDBError>
AuthDB::mfa_init_enrollment(const std::string& username, std::string_view issuer) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    auto status = mfa_status(username);
    if (!status)
        return std::unexpected(status.error());
    if (status->enrolled) {
        spdlog::warn("mfa_init_enrollment: already enrolled: {}", username);
        return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
    }

    // Reuse, don't rotate (#1227). A provisional secret (not yet enrolled —
    // just checked above — but a secret blob present) is re-revealed rather
    // than replaced, so re-initialising mid-enrollment (two tabs, a retried
    // bootstrap) doesn't invalidate a QR the operator already scanned.
    //
    // ★ SECURITY (security-guardian LOW, governance hardening round; widened
    // by the 2026-07-25 review's HIGH #2): a store outage on this reuse-load
    // is NOT "no provisional secret" — falling through to mint-fresh below
    // during a transient failure would silently invalidate an in-progress
    // enrollment the caller merely couldn't currently read. `load_mfa_row`
    // reports BOTH outage shapes as store-unavailable — a lease-acquire timeout
    // (now `StoreBusy` after the #2396 bounded retry is exhausted) and a
    // non-TUPLES_OK result (`QueryFailed`) — so gate on `is_store_unavailable`,
    // which covers both (plus `WriteFailed`/`SecretUnavailable`); matching only
    // `== QueryFailed` here would let a #2396 acquire-timeout fall through to
    // mint-fresh over a possibly-enrolled row. `UserNotFound` (impossible here —
    // mfa_status above already proved an active row) still passes through.
    auto existing = load_mfa_row(impl_->pool, username);
    if (!existing && is_store_unavailable(existing.error())) {
        spdlog::error("mfa_init_enrollment: reuse-load failed for '{}' (store outage) — refusing "
                      "to mint a fresh secret over a possibly-existing provisional one",
                      username);
        // Preserve the actual store-unavailable error (StoreBusy for an acquire
        // timeout, QueryFailed for a failed statement) rather than flattening to
        // WriteFailed — otherwise the enroll-init 503's degrade metric would
        // mislabel a pool-acquire timeout as reason=query_error (#2396 adv-review
        // CDX-P2-03/K1). Still fail-closed: is_store_unavailable() is true for both.
        return std::unexpected(existing.error());
    }
    if (existing && !existing->secret_blob.empty()) {
        // TOCTOU re-check: load_mfa_row's SELECT is a separate statement from
        // mfa_status's — a concurrent mfa_verify_enrollment could have
        // stamped enrolled between the two. Re-check the freshly-loaded row.
        if (existing->enrolled) {
            spdlog::warn("mfa_init_enrollment: enrolled between status-check and reuse-load "
                         "(concurrent verify) — refusing to re-reveal: {}",
                         username);
            return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
        }
        // ★ Decrypt failure here means fail closed — NEVER mint a fresh
        // secret over a provisional one that merely failed to decrypt (that
        // would silently invalidate an in-progress enrollment).
        auto dec = decrypt_mfa_secret(impl_->secret_codec, *existing);
        if (!dec.has_value())
            return std::unexpected(dec.error());
        auto secret_view = std::string_view(reinterpret_cast<const char*>(dec->data()), dec->size());
        auto secret_b32 = mfa::base32_encode(secret_view);
        auto uri = mfa::otpauth_uri(issuer, username, secret_b32);
        return MfaEnrollmentInit{std::move(secret_b32), std::move(uri)};
    }
    // Falling through means the row exists and genuinely carries no secret
    // (UserNotFound is impossible here — mfa_status above already proved an
    // active row — and QueryFailed already returned). Mint a fresh one.

    // Fresh secret. Need the row id for the SecretId AAD before encrypting.
    auto lease0 = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease0)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult idres = pg::exec_params(lease0.get(),
                                         "SELECT id FROM auth.users WHERE username = $1 AND is_active = TRUE",
                                         std::vector<std::string>{username});
    if (idres.status() != PGRES_TUPLES_OK || PQntuples(idres.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    const int64_t user_id = to_i64(col(idres.get(), 0, 0));
    lease0.reset();

    auto secret_bytes = mfa::random_secret();
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(secret_bytes.data()), secret_bytes.size());
    auto secret_b32 = mfa::base32_encode(secret_view);
    auto uri = mfa::otpauth_uri(issuer, username, secret_b32);

    auto pk = pg::SecretCodec::encode_bigint_pk(user_id);
    auto enc = impl_->secret_codec.encrypt(pg::SecretCodec::SecretId{"auth", "users", "mfa_totp_secret", pk},
                                           std::span<const std::uint8_t>{secret_bytes});
    if (!enc.has_value()) {
        // Encrypt failure aborts here — never write plaintext, never write
        // anything at all.
        spdlog::error("mfa_init_enrollment: secret encrypt failed for '{}'", username);
        return std::unexpected(AuthDBError::WriteFailed);
    }

    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.users SET mfa_totp_secret = decode($1,'hex'), mfa_last_counter = 0, "
        "mfa_disabled_at = NULL, updated_at = now() WHERE username = $2 AND is_active = TRUE RETURNING id",
        std::vector<std::string>{auth::AuthManager::bytes_to_hex(*enc), username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::UserNotFound);
    return MfaEnrollmentInit{std::move(secret_b32), std::move(uri)};
}

std::expected<std::vector<std::string>, AuthDBError>
AuthDB::mfa_verify_enrollment(const std::string& username, std::string_view code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    auto status = mfa_status(username);
    if (!status)
        return std::unexpected(status.error());
    if (status->enrolled) {
        return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
    }

    // Store outage (lease timeout OR failed statement) → fail closed (503),
    // never "no provisional secret". UserNotFound passes through unchanged.
    auto row = load_mfa_row(impl_->pool, username);
    if (!row)
        return std::unexpected(row.error());
    if (row->secret_blob.empty()) {
        // No provisional secret — caller must call mfa_init_enrollment first.
        return std::unexpected(AuthDBError::UserNotFound);
    }
    auto dec = decrypt_mfa_secret(impl_->secret_codec, *row);
    if (!dec.has_value())
        return std::unexpected(dec.error());

    auto secret_view = std::string_view(reinterpret_cast<const char*>(dec->data()), dec->size());
    auto current = mfa::current_counter(std::chrono::system_clock::now());
    auto matched = mfa::verify_window(secret_view, code, current, -1);
    if (!matched) {
        return std::unexpected(AuthDBError::InvalidCredentials);
    }

    // Stamp enrolled_at + generate recovery codes ATOMICALLY — a code-gen
    // failure must roll the stamp back too (the user stays provisional and
    // can simply retry, rather than landing in a permanent
    // MfaAlreadyEnrolled-with-zero-recovery-codes lockout).
    std::vector<std::string> raw_codes;
    AuthDBError txn_error = AuthDBError::WriteFailed;
    const bool ok = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // ★ TOCTOU guard (#3762): the WHERE predicate makes the provisional→enrolled
        // commit atomic with its own preconditions, exactly as `mfa_consume_recovery_code`
        // guards on `consumed_at IS NULL` (docs/auth-mfa-design.md "Recovery codes",
        // "race-safe without an explicit transaction"). The pre-txn `mfa_status()` /
        // `load_mfa_row` reads above are separate pooled statements, so two concurrency
        // hazards exist that this one guarded UPDATE closes under READ COMMITTED (the
        // loser blocks on the row lock and re-evaluates its WHERE against the committed
        // row):
        //   (a) `mfa_enrolled_at IS NULL` — two concurrent verifies of one code would
        //       otherwise BOTH stamp enrolled_at and BOTH run
        //       regenerate_recovery_codes_locked (DELETE-all + INSERT), the loser deleting
        //       the winner's just-issued codes and orphaning the set the winner was handed.
        //   (b) `mfa_totp_secret = decode($3,'hex')` binds the commit to the EXACT encrypted
        //       secret blob that was loaded, decrypted, and TOTP-verified pre-txn (`row.
        //       secret_blob`). The secret verified against must still be the stored secret,
        //       upholding the "mfa_disable is atomic against in-flight verifies" hard
        //       invariant (docs/auth-mfa-design.md §Hard invariants item 3: a concurrent
        //       verify sees the old state and matches, OR the new state and FAILS). It is
        //       IDENTITY, not mere presence: a concurrent `mfa_disable` NULLs the secret
        //       (NULL ≠ loaded blob → 0 rows), AND a concurrent `mfa_disable`+`mfa_init`
        //       that rotates to a DIFFERENT provisional secret B likewise fails (B ≠ the
        //       loaded A → 0 rows) — a bare `IS NOT NULL` would have MATCHED B and enrolled
        //       the account against a secret whose code was never verified (#3781 review).
        //       Any 0-row outcome here → classify below keeps WriteFailed/503 (fail-closed,
        //       no half-enrolled state).
        // LOAD-BEARING: dropping (a) reopens the double-regen; weakening (b) from the exact
        // blob to `IS NOT NULL` reopens the enrol-over-a-rotated-secret race. Neither wedges
        // a legitimate enroll: an uninterrupted verify's loaded secret is still the stored
        // one, and a post-disable re-enroll re-inits a fresh secret and verifies a code of
        // THAT secret, so its own loaded blob matches.
        pg::PgResult r = pg::exec_params(
            conn,
            "UPDATE auth.users SET mfa_enrolled_at = now(), mfa_last_counter = $1, updated_at = now() "
            "WHERE username = $2 AND is_active = TRUE AND mfa_enrolled_at IS NULL "
            "AND mfa_totp_secret = decode($3, 'hex') RETURNING id",
            std::vector<std::string>{std::to_string(*matched), username,
                                     auth::AuthManager::bytes_to_hex(row->secret_blob)});
        if (r.status() != PGRES_TUPLES_OK)
            return false; // write outage → fail closed (WriteFailed → 503)
        if (PQntuples(r.get()) == 0) {
            // 0 rows = the user was deactivated/deleted mid-request, OR a concurrent
            // verify already enrolled them (the guard above). Classify so the
            // concurrent-enroll loser is graded MfaAlreadyEnrolled — NOT WriteFailed,
            // which `is_store_unavailable()` routes to a false 503 + a
            // secret-unavailable degrade metric + a kCritical "store unavailable" audit
            // for a benign race. A genuinely deactivated user keeps the fail-closed
            // WriteFailed/503 (unchanged).
            pg::PgResult cls = pg::exec_params(
                conn,
                "SELECT is_active, (mfa_enrolled_at IS NOT NULL) FROM auth.users WHERE username = $1",
                std::vector<std::string>{username});
            if (cls.status() == PGRES_TUPLES_OK && PQntuples(cls.get()) == 1 &&
                to_bool(col(cls.get(), 0, 0)) && to_bool(col(cls.get(), 0, 1))) {
                txn_error = AuthDBError::MfaAlreadyEnrolled;
            }
            return false;
        }

        auto codes = regenerate_recovery_codes_locked(conn, username);
        if (!codes) {
            txn_error = codes.error();
            return false;
        }
        raw_codes = std::move(*codes);
        return true;
    });
    if (!ok)
        return std::unexpected(txn_error);
    return raw_codes;
}

std::expected<bool, AuthDBError>
AuthDB::mfa_verify_login_code(const std::string& username, std::string_view code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // ★ HIGH (Hermes p2 — MFA replay): the SELECT-verify-UPDATE must be ONE
    // row-locked transaction. SQLite's single FULLMUTEX connection implicitly
    // serialized these steps; the Postgres pool does NOT, so two concurrent
    // verifies of the same still-valid code on different connections could both
    // pass and both bump the counter → a TOTP code consumed twice (replay).
    // `SELECT ... FOR UPDATE` serializes them: the second waiter reads the
    // just-advanced counter and the monotonic window check rejects the replay.
    std::optional<bool> result;                 // set = definitive true/false; unset = store/decrypt error
    AuthDBError err = AuthDBError::QueryFailed;  // used only when result stays unset
    const bool committed = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult sel = pg::exec_params(
            conn,
            "SELECT id, encode(mfa_totp_secret, 'hex'), (mfa_enrolled_at IS NOT NULL), mfa_last_counter "
            "FROM auth.users WHERE username = $1 AND is_active = TRUE FOR UPDATE",
            std::vector<std::string>{username});
        if (sel.status() != PGRES_TUPLES_OK) {
            err = AuthDBError::QueryFailed; // read outage → fail closed (503), never "wrong code"
            return false;
        }
        if (PQntuples(sel.get()) == 0) {
            result = false; // no such active user
            return false;
        }
        LoadedMfaRow row;
        row.id = to_i64(col(sel.get(), 0, 0));
        if (!PQgetisnull(sel.get(), 0, 1))
            row.secret_blob = auth::AuthManager::hex_to_bytes(col_str(sel.get(), 0, 1));
        row.enrolled = to_bool(col(sel.get(), 0, 2));
        row.last_counter = to_i64(col(sel.get(), 0, 3));
        if (!row.enrolled) {
            result = false; // genuinely not enrolled — nothing to verify against
            return false;
        }
        // ★ SECURITY: enrolled-but-NULL-secret is NOT "wrong code". These two
        // states were fused into a single `false` until the 2026-07-25 review
        // — an enrolled row whose `mfa_totp_secret` went NULL (partial write,
        // operator UPDATE, restore from a backup taken mid-enrollment) would
        // report every login code as invalid rather than telling anyone the
        // second factor had become unreadable. `mfa_status` has always graded
        // the identical row state as SecretUnavailable (see above); this path
        // now matches it, which is what AuthDBError::SecretUnavailable's
        // contract and docs/auth-architecture.md already claimed.
        if (row.secret_blob.empty()) {
            err = AuthDBError::SecretUnavailable;
            return false;
        }
        // ★ Decrypt failure NEVER silently reads as "code didn't match" — SecretUnavailable.
        auto dec = decrypt_mfa_secret(impl_->secret_codec, row);
        if (!dec.has_value()) {
            err = dec.error();
            return false;
        }
        auto secret_view = std::string_view(reinterpret_cast<const char*>(dec->data()), dec->size());
        auto current = mfa::current_counter(std::chrono::system_clock::now());
        auto matched = mfa::verify_window(secret_view, code, current, row.last_counter);
        if (!matched) {
            result = false; // wrong or already-consumed (replayed) code
            return false;
        }
        // Belt-and-suspenders monotonic guard (#2399): fold the counter check
        // into the UPDATE's WHERE. The `FOR UPDATE` row lock above already
        // serializes concurrent verifies, so `mfa_last_counter` cannot advance
        // between the SELECT and this write on a correctly-isolated store — but
        // conditioning the write on `mfa_last_counter < $1 RETURNING id` makes
        // the advance self-consistent even if that isolation were ever weakened
        // (a replica read, a future lock-free refactor): a stale/racing write
        // whose stored counter has already reached `*matched` touches zero rows
        // and is graded a replayed code (clean `false`), NEVER a burned success
        // and NEVER an error. `verify_window` only ever returns a counter
        // strictly greater than the SELECTed `row.last_counter`, so on the
        // normal FOR-UPDATE-serialized path this guard always matches the one row.
        //
        // LOAD-BEARING: `RETURNING id` is what makes this a `PGRES_TUPLES_OK`
        // result, so the zero-rows check below can distinguish a guard rejection
        // from a genuine write. Dropping `RETURNING` (e.g. a "simplify" refactor)
        // WITHOUT also reverting the `!= PGRES_TUPLES_OK` check would grade every
        // successful advance as `WriteFailed` and 503 every legitimate MFA login
        // (fail-closed, not a bypass — but a total login outage). Change both or
        // neither.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE auth.users SET mfa_last_counter = $1, last_login_at = now() "
            "WHERE id = $2 AND mfa_last_counter < $1 RETURNING id",
            std::vector<std::string>{std::to_string(*matched), std::to_string(row.id)});
        if (upd.status() != PGRES_TUPLES_OK) {
            err = AuthDBError::WriteFailed; // write outage → fail closed (503), never "wrong code"
            return false;
        }
        if (PQntuples(upd.get()) == 0) {
            // The monotonic guard rejected the advance — the stored counter had
            // already reached `*matched` (a replay that slipped past the window
            // read). Treat exactly as an already-consumed code; nothing to commit.
            // This branch is unreachable while the `FOR UPDATE` lock holds (the
            // window read already rejects the replay first), so if it EVER fires
            // it signals a weakened-isolation regression (a replica SELECT, a
            // lock-free refactor) — warn rather than swallow it silently, since
            // it is otherwise indistinguishable from an ordinary wrong code.
            spdlog::warn("AuthDB: MFA monotonic guard rejected a counter advance "
                         "(user_id={}, matched_counter={}) — the FOR UPDATE lock should make "
                         "this unreachable; investigate isolation/replica routing",
                         row.id, *matched);
            result = false;
            return false;
        }
        result = true;
        return true; // commit the counter advance
    });
    if (result.has_value())
        return *result;
    (void)committed; // false on this path (error rollback or lease-acquire failure) → surface the error
    return std::unexpected(err);
}

std::expected<bool, AuthDBError>
AuthDB::mfa_consume_recovery_code(const std::string& username, std::string_view raw_code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (raw_code.empty()) {
        return false;
    }

    struct Candidate {
        int64_t id;
        std::string code_hash;
        std::string code_salt;
    };
    std::vector<Candidate> candidates;
    {
        auto lease = impl_->pool.try_acquire_for(kReadTimeout);
        if (!lease)
            return std::unexpected(AuthDBError::WriteFailed);
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, code_hash, code_salt FROM auth.mfa_recovery_codes "
            "WHERE username = $1 AND consumed_at IS NULL",
            std::vector<std::string>{username});
        if (res.status() != PGRES_TUPLES_OK)
            return std::unexpected(AuthDBError::WriteFailed);
        const int rows = PQntuples(res.get());
        candidates.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i)
            candidates.push_back(
                {to_i64(col(res.get(), i, 0)), col_str(res.get(), i, 1), col_str(res.get(), i, 2)});
    }

    // Normalise: recovery codes are displayed with a '-' separator for
    // readability; accept with or without it. Case-insensitive base32.
    std::string normalised;
    normalised.reserve(raw_code.size());
    for (char c : raw_code) {
        if (c == '-' || c == ' ')
            continue;
        normalised += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }

    // Walk every candidate unconditionally — no early break on match. An
    // early break leaks the position-in-list via wall-clock (N×PBKDF2 for a
    // wrong code vs K×PBKDF2 for a match at slot K). N is bounded by
    // kRecoveryCodeCount = 10, so the constant scan cost is trivial.
    int64_t matched_id = -1;
    for (const auto& cand : candidates) {
        auto salt_bytes = auth::AuthManager::hex_to_bytes(cand.code_salt);
        auto presented_hash =
            auth::AuthManager::pbkdf2_sha256(normalised, salt_bytes, kRecoveryCodePbkdfIters);
        if (auth::AuthManager::constant_time_compare(presented_hash, cand.code_hash) && matched_id < 0)
            matched_id = cand.id;
    }
    if (matched_id < 0) {
        return false;
    }

    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.mfa_recovery_codes SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL "
        "RETURNING id",
        std::vector<std::string>{std::to_string(matched_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) == 0)
        return false; // a concurrent consume won the race
    return true;
}

std::expected<std::vector<std::string>, AuthDBError>
AuthDB::mfa_regenerate_recovery_codes(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    std::vector<std::string> raw_codes;
    AuthDBError txn_error = AuthDBError::WriteFailed;
    const bool ok = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Serialize on the auth.users row BEFORE the DELETE-all + INSERT-10 in
        // regenerate_recovery_codes_locked (#3779). That helper is not
        // self-serializing: without a row lock two concurrent regenerates each
        // DELETE the committed rows and INSERT 10 → 20 persist, and each caller
        // is handed a set that no longer matches storage. This FOR UPDATE joins
        // regenerate to the same per-user serialization group every other MFA
        // writer already takes (mfa_verify_enrollment / mfa_verify_login_code /
        // mfa_disable / remove_user all lock this row), so the loser blocks then
        // re-runs against the winner's committed state → returned == persisted for
        // each caller in turn (clean sequential last-writer-wins).
        //
        // `is_active = TRUE` is load-bearing, not cosmetic: it cross-serializes
        // against remove_user (UPDATE+DELETE on this row). Without it a regen
        // racing a deactivation could DELETE, block behind remove_user, then
        // INSERT 10 fresh codes onto a now-deactivated account — live recovery
        // codes on a dead login, the stale-code hazard docs/auth-mfa-design.md
        // warns of. Post-lock the loser re-reads is_active = FALSE → 0 rows →
        // UserNotFound.
        //
        // Lock_timeout: this deliberately does NOT scope lock_timeout to
        // kWriteTimeout the way the #4107 sibling (mfa_verify_login_code /
        // recheck_role_locked, ~line 969) does. That sibling narrows it to 2000ms
        // because its critical section is microsecond-scale; here the row is held
        // across 10x PBKDF2 (100k iters, ~0.3-0.6s), so a 2s bound would surface a
        // legitimate loser's wait as a false QueryFailed. The pool's inherited
        // per-connection lock_timeout (10000ms, pg_pool.hpp) still bounds a
        // wedged-connection hang; a loser that genuinely waits >10s (≈20 piled
        // same-user regenerates) gets SQLSTATE 55P03 → QueryFailed → 503, which is
        // acceptable graceful degradation for a self-service action. The real fix —
        // shrinking the hold to microseconds by minting+hashing BEFORE the lock —
        // is a shared-helper refactor (it touches the enrollment path too) tracked
        // as a follow-up, not folded here.
        pg::PgResult lock = pg::exec_params(
            conn, "SELECT id FROM auth.users WHERE username = $1 AND is_active = TRUE FOR UPDATE",
            std::vector<std::string>{username});
        if (lock.status() != PGRES_TUPLES_OK) {
            txn_error = AuthDBError::QueryFailed; // read outage → fail closed (503)
            return false;
        }
        if (PQntuples(lock.get()) == 0) {
            txn_error = AuthDBError::UserNotFound; // no active user → never issue codes
            return false;
        }
        auto codes = regenerate_recovery_codes_locked(conn, username);
        if (!codes) {
            txn_error = codes.error();
            return false;
        }
        raw_codes = std::move(*codes);
        return true;
    });
    if (!ok)
        return std::unexpected(txn_error);
    return raw_codes;
}

std::expected<void, AuthDBError> AuthDB::mfa_disable(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // UPDATE + DELETE atomically — a kill mid-way must never leave secret=NULL
    // with recovery codes still present (design doc §3 "no half-disabled state").
    const bool ok = impl_->pool.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE auth.users SET mfa_totp_secret = NULL, mfa_enrolled_at = NULL, "
            "mfa_disabled_at = now(), mfa_last_counter = 0, updated_at = now() "
            "WHERE username = $1 AND is_active = TRUE",
            std::vector<std::string>{username});
        if (upd.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult del = pg::exec_params(conn, "DELETE FROM auth.mfa_recovery_codes WHERE username = $1",
                                           std::vector<std::string>{username});
        return del.status() == PGRES_COMMAND_OK;
    });
    if (!ok)
        return std::unexpected(AuthDBError::WriteFailed);
    return {};
}

// ── Enrollment Token Operations (C2 FIX: Atomic Consumption) ─────────────────

std::expected<std::string, AuthDBError>
AuthDB::create_enrollment_token(const std::string& created_by, std::chrono::seconds validity) {
    auto token_bytes = auth::AuthManager::random_bytes(32);
    std::string plain_token = auth::AuthManager::bytes_to_hex(token_bytes);
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);

    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO auth.enrollment_tokens (token_hash, created_by, expires_at) "
        "VALUES ($1, $2, now() + make_interval(secs => $3::int)) RETURNING id",
        std::vector<std::string>{token_hash, created_by, std::to_string(validity.count())});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(AuthDBError::WriteFailed);
    spdlog::info("Enrollment token created by {}", created_by);
    return plain_token;
}

std::expected<bool, AuthDBError> AuthDB::validate_enrollment_token(const std::string& plain_token) {
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM auth.enrollment_tokens WHERE token_hash = $1 AND is_used = FALSE "
        "AND expires_at > now()",
        std::vector<std::string>{token_hash});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);
    return to_i64(col(res.get(), 0, 0)) > 0;
}

std::expected<bool, AuthDBError> AuthDB::consume_enrollment_token(const std::string& plain_token,
                                                                  const std::string& agent_id) {
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);

    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    // RETURNING carries the "did my UPDATE affect a row" signal directly —
    // token doesn't exist / already consumed / expired all collapse to the
    // same zero-row "rejected" outcome (deliberately not discriminated here,
    // matching the SQLite-era anti-oracle posture).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.enrollment_tokens SET is_used = TRUE, used_at = now(), used_by_agent_id = $1 "
        "WHERE token_hash = $2 AND is_used = FALSE AND expires_at > now() RETURNING id",
        std::vector<std::string>{agent_id, token_hash});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    if (PQntuples(res.get()) > 0) {
        spdlog::info("Enrollment token consumed: agent={}", agent_id);
        return true;
    }
    spdlog::warn("Enrollment token consumption failed (no matching row): token={}..., agent={}",
                plain_token.substr(0, std::min<std::size_t>(8, plain_token.size())), agent_id);
    return false;
}

// ── Pending Agent Operations ────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::add_pending_agent(const auth::PendingAgent& agent) {
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO auth.pending_agents (agent_id, hostname, os, arch, agent_version, status) "
        "VALUES ($1,$2,$3,$4,$5,'pending') ON CONFLICT (agent_id) DO NOTHING",
        std::vector<std::string>{agent.agent_id, agent.hostname, agent.os, agent.arch,
                                 agent.agent_version});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    spdlog::info("Pending agent added: {} ({})", agent.agent_id, agent.hostname);
    return {};
}

std::expected<std::vector<auth::PendingAgent>, AuthDBError> AuthDB::list_pending_agents() {
    auto lease = impl_->pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::QueryFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, arch, agent_version FROM auth.pending_agents "
        "WHERE status = 'pending' ORDER BY requested_at DESC",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(AuthDBError::QueryFailed);

    std::vector<auth::PendingAgent> agents;
    const int rows = PQntuples(res.get());
    agents.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        auth::PendingAgent agent;
        agent.agent_id = col_str(res.get(), i, 0);
        agent.hostname = col_str(res.get(), i, 1);
        agent.os = col_str(res.get(), i, 2);
        agent.arch = col_str(res.get(), i, 3);
        agent.agent_version = col_str(res.get(), i, 4);
        agents.push_back(std::move(agent));
    }
    return agents;
}

std::expected<void, AuthDBError> AuthDB::approve_agent(const std::string& agent_id,
                                                       const std::string& approved_by) {
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE auth.pending_agents SET status = 'approved', approved_at = now(), approved_by = $1 "
        "WHERE agent_id = $2",
        std::vector<std::string>{approved_by, agent_id});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    spdlog::info("Agent approved: {} by {}", agent_id, approved_by);
    return {};
}

std::expected<void, AuthDBError> AuthDB::reject_agent(const std::string& agent_id) {
    auto lease = impl_->pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(AuthDBError::WriteFailed);
    pg::PgResult res = pg::exec_params(lease.get(), "UPDATE auth.pending_agents SET status = 'rejected' WHERE agent_id = $1",
                                       std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(AuthDBError::WriteFailed);
    spdlog::info("Agent rejected: {}", agent_id);
    return {};
}

} // namespace yuzu::server
