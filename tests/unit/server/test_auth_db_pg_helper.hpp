#pragma once

// test_auth_db_pg_helper.hpp — shared PG-backed AuthDB (+ its
// FileKeyProvider/SecretCodec dependency chain, ADR-0006/ADR-0010)
// construction helper for every auth-route/store fixture that used to open
// a SQLite `AuthDB(data_dir)` (test_auth.cpp, test_auth_sso_identity.cpp,
// test_auth_jit_elevation.cpp, test_mfa_store.cpp, test_auth_lockout.cpp,
// test_auth_break_glass.cpp, test_mfa_step_up.cpp, test_auth_routes_mfa.cpp,
// test_settings_routes_mfa.cpp, test_scim_routes.cpp, ...).
//
// Mirrors test_api_token_pg_helper.hpp's shared-fixture shape and
// test_auth_db_pg.cpp's own `Harness` (kept file-local there; promoted here
// so every consumer gets one migration/KEK-mint per PgTestTemplate clone
// instead of re-deriving the FileKeyProvider/SecretCodec/AuthDB wiring
// per file).
//
// Construction order mirrors server.cpp's ServerImpl AuthDB block EXACTLY
// (load-bearing — see auth_db.hpp's ctor doc comment): FileKeyProvider ->
// SecretCodec (constructed, NOT init'd yet) -> AuthDB (this migrates
// `auth.users` AND registers `mfa_totp_secret` as a secret column) ->
// SecretCodec::init() (runs AFTER AuthDB so the column it validates already
// exists).
//
// The PgTestTemplate clone trick needs one extra step versus a plain store:
// the KEK material lives on the LOCAL FILESYSTEM (FileKeyProvider), not in
// Postgres, so the template build's `secrets.kek_meta` fingerprint rows
// (which point at the THROWAWAY template-build keys dir) are deleted before
// the template is captured — every clone's `codec.init()` then performs its
// own first-boot KEK generation into ITS OWN fresh TempDir, so a clone never
// tries to resolve a KEK file that only ever existed in the template-build
// process.
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the
// same skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "key_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"

#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace yuzu::test {

/// KekProvider decorator that delegates every op to an inner
/// `FileKeyProvider` (real KEK generation/resolution/unwrap — needed so
/// `codec.init()` still mints a genuine KEK) but can be flipped, via
/// `set_fail_wrap(true)`, to fail `wrap_dek` — the call
/// `SecretCodec::encrypt` makes after it has already generated the DEK,
/// minted the payload nonce, and encrypted the plaintext into a local
/// buffer (governance hardening round, quality SHOULD: "mfa_init_enrollment
/// aborts with no plaintext/partial write when encrypt fails"). Forcing
/// THIS specific failure point — rather than e.g. corrupting the KEK file —
/// isolates the "encrypt failed after plaintext touched, before any DB
/// write" window precisely, without disturbing `init()` (which never calls
/// `wrap_dek`) or `unwrap_dek`-based decrypt paths.
class FaultyKekProvider : public yuzu::server::KekProvider {
public:
    explicit FaultyKekProvider(yuzu::server::FileKeyProvider& inner) : inner_(inner) {}

    void set_fail_wrap(bool fail) noexcept { fail_wrap_.store(fail, std::memory_order_relaxed); }

    std::optional<std::string> generate_kek(std::string_view id) override {
        return inner_.generate_kek(id);
    }
    std::optional<std::string> resolve_kek(std::string_view id) override {
        return inner_.resolve_kek(id);
    }
    std::expected<yuzu::server::WrappedDek, yuzu::server::KekError>
    wrap_dek(std::string_view ref, std::span<const std::uint8_t, 32> dek,
            std::span<const std::uint8_t> aad) override {
        if (fail_wrap_.load(std::memory_order_relaxed))
            return std::unexpected(yuzu::server::KekError::crypto_failure);
        return inner_.wrap_dek(ref, dek, aad);
    }
    std::expected<yuzu::server::SecureBuffer, yuzu::server::KekError>
    unwrap_dek(std::string_view ref, const yuzu::server::WrappedDek& w,
              std::span<const std::uint8_t> aad) override {
        return inner_.unwrap_dek(ref, w, aad);
    }
    std::optional<std::array<std::uint8_t, 32>> kek_check_value(std::string_view ref,
                                                                 std::string_view alg) override {
        return inner_.kek_check_value(ref, alg);
    }
    bool delete_kek(std::string_view ref) override { return inner_.delete_kek(ref); }

private:
    yuzu::server::FileKeyProvider& inner_;
    std::atomic<bool> fail_wrap_{false};
};

namespace detail {
inline void setup_auth_db_pg_template(const std::string& dsn) {
    yuzu::test::TempDir keys;
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("authdb template: connect failed");

    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuthDB db{pool, codec}; // migrates auth.users + registers the secret column
    if (!db.is_open())
        throw std::runtime_error("authdb template: store failed to migrate");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("authdb template: secret codec init failed");

    // Reset the fingerprint table — see file header. Every clone mints its
    // own KEK against its own (fresh, per-fixture) keys dir.
    yuzu::server::pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("authdb template: kek_meta reset failed");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header. Distinct key from test_auth_db_pg.cpp's
/// own "authdb" template (different setup-callback internal ordering —
/// AuthDB-then-`codec.init()` here, matching server.cpp's production wiring
/// exactly; that file's template calls `codec.init()` before AuthDB) — a
/// deliberately separate registry entry, no shared-state risk (mirrors
/// test_engine_principal_integration.cpp's "engineprincipal_integ" vs
/// test_engine_principal_store.cpp's "engineprincipal" precedent).
inline PgTestTemplate auth_db_pg_template{"authdbwire", &detail::setup_auth_db_pg_template};

/// RAII bundle: ephemeral database + a fresh per-fixture keys dir +
/// FileKeyProvider + SecretCodec + PgPool + AuthDB, in destruction-safe
/// member order (AuthDB's background reaper stops before the codec/provider
/// it touches go away; both the store and the pool close before the
/// ephemeral database is dropped) — the exact ordering server.cpp uses.
/// Behaves like a `std::unique_ptr<AuthDB>` at call sites (`get()`/
/// `operator->`/`operator*`).
class AuthDbPg {
public:
    /// `cleanup_interval_secs` defaults to 0 (reaper thread disabled) — this
    /// fixture is typically instantiated once per TEST_CASE_METHOD/TEST_CASE
    /// across a whole suite file (dozens to hundreds of times in one process);
    /// the production 60 s cadence would spawn+join that many background
    /// jthreads (see AuthDB's SQLite-era PR #1199 macOS-arm64 rationale, still
    /// applicable to any tight construct/destruct loop). Pass a positive value
    /// only for a test that specifically exercises the reaper.
    ///
    /// `inject_encrypt_faults` (default false) wraps the real
    /// `FileKeyProvider` in a `FaultyKekProvider` and hands THAT to
    /// `SecretCodec` instead — `fault_provider()` is non-null only when this
    /// is true, and `set_fail_wrap(true)` on it then forces every subsequent
    /// `encrypt()` call to fail deterministically (governance hardening
    /// round, quality SHOULD: mfa_init_enrollment's abort-on-encrypt-failure
    /// path was untested).
    explicit AuthDbPg(int cleanup_interval_secs = 0, bool inject_encrypt_faults = false)
        : cleanup_interval_secs_(cleanup_interval_secs) {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(auth_db_pg_template);
        INFO("[AuthDbPg] fixture status (blank == database came up OK): " << db_->error());
        REQUIRE(db_->available());

        provider_ = std::make_unique<yuzu::server::FileKeyProvider>(keys_.path);
        if (inject_encrypt_faults) {
            faulty_provider_ = std::make_unique<FaultyKekProvider>(*provider_);
            codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*faulty_provider_);
        } else {
            codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*provider_);
        }
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());

        authdb_ = std::make_unique<yuzu::server::AuthDB>(*pool_, *codec_, cleanup_interval_secs_);
        REQUIRE(authdb_->is_open());

        // Per-clone first-boot KEK generation (see file header) — needs a
        // connection of its own; AuthDB's ctor above already released its
        // construction-only lease.
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto init_res = codec_->init(conn.get());
        INFO("[AuthDbPg] SecretCodec::init status (blank == ok): "
             << (init_res.has_value() ? "" : std::string(yuzu::server::pg::SecretCodec::to_string(
                                                  init_res.error().kind))));
        REQUIRE(init_res.has_value());
    }

    AuthDbPg(const AuthDbPg&) = delete;
    AuthDbPg& operator=(const AuthDbPg&) = delete;
    AuthDbPg(AuthDbPg&&) = delete;
    AuthDbPg& operator=(AuthDbPg&&) = delete;

    /// Connection string of the ephemeral database backing this store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::AuthDB* get() const noexcept { return authdb_.get(); }
    yuzu::server::AuthDB* operator->() const noexcept { return authdb_.get(); }
    yuzu::server::AuthDB& operator*() const noexcept { return *authdb_; }
    explicit operator bool() const noexcept { return authdb_ != nullptr; }

    /// Direct access to the codec/pool for tests that need to reach in
    /// (e.g. corrupting a secret blob on a second connection, or building a
    /// sibling ScimStore on the same pool).
    [[nodiscard]] yuzu::server::pg::SecretCodec& codec() noexcept { return *codec_; }
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

    /// Non-null only when constructed with `inject_encrypt_faults = true`.
    [[nodiscard]] FaultyKekProvider* fault_provider() noexcept { return faulty_provider_.get(); }

    /// Tear down early (store, then pool/codec/provider, then database) —
    /// mirrors `std::unique_ptr::reset()` for fixtures that sequence
    /// teardown explicitly.
    void reset() noexcept {
        authdb_.reset();
        pool_.reset();
        codec_.reset();
        faulty_provider_.reset();
        provider_.reset();
        db_.reset();
    }

private:
    int cleanup_interval_secs_{0};
    yuzu::test::TempDir keys_;
    std::unique_ptr<yuzu::server::FileKeyProvider> provider_;
    // Declared AFTER provider_, BEFORE codec_ — codec_ (which may hold a
    // reference to *this*) must destruct before it, and it must destruct
    // before the real provider_ it wraps.
    std::unique_ptr<FaultyKekProvider> faulty_provider_;
    std::unique_ptr<yuzu::server::pg::SecretCodec> codec_;
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::AuthDB> authdb_;
};

namespace detail {
/// One migrated "authdbwire" clone + one persistent pool for the whole
/// PROCESS, shared by every AuthDbPgShared fixture and TRUNCATE-reset between
/// tests, instead of a fresh CREATE DATABASE + 4-conn pool + KEK mint per
/// fixture — the dominant [pg]-shard cost on Windows EXEC_BACKEND (#2354).
/// Built lazily; at testRunEnded the pool is drained and the clone dropped
/// (keep_until_run_end), leaving the function-local static destructor inert.
struct AuthDbSharedBundle {
    PostgresTestDb db{auth_db_pg_template};
    std::optional<yuzu::server::pg::PgPool> pool;
    AuthDbSharedBundle() {
        INFO("[AuthDbSharedBundle] bundle status (blank == database came up OK): " << db.error());
        REQUIRE(db.available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
inline AuthDbSharedBundle& auth_db_shared_bundle() {
    static AuthDbSharedBundle b;
    return b;
}
} // namespace detail

/// Shared-DB sibling of AuthDbPg (same call-site interface): the
/// provider/codec/AuthDB chain is fresh per fixture — construction order
/// still mirrors server.cpp exactly, and every fixture still mints its own
/// KEK into its own fresh keys TempDir — but they run over the process-wide
/// shared clone/pool, restored to its fresh-clone state at construction:
///
///   1. TRUNCATE the four `auth` tables (blob holders FIRST — see 2),
///   2. DELETE FROM secrets.kek_meta — with the blobs already gone, the S6
///      orphan scan stays clean and this fixture's codec.init() performs
///      first-boot KEK generation, exactly like a fresh clone's would (the
///      same reset the template build performs; see the file header).
///
/// Use for CRUD-only tests. NOT for: tests that need TWO distinct AuthDB
/// databases in one Catch2 leaf (e.g. the seeded-vs-clean collision-scan
/// pair in test_engine_principal_integration.cpp — the second construction
/// would TRUNCATE the first's data), or anything that alters the schema via
/// dsn() — keep those on AuthDbPg.
class AuthDbPgShared {
public:
    /// Same parameters/semantics as AuthDbPg (see its ctor doc).
    explicit AuthDbPgShared(int cleanup_interval_secs = 0, bool inject_encrypt_faults = false) {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        auto& bundle = detail::auth_db_shared_bundle();
        {
            auto lease = bundle.pool->acquire();
            REQUIRE(lease);
            // pg::exec_params is single-statement (PQexecParams) — two calls.
            auto trunc = yuzu::server::pg::exec_params(
                lease.get(),
                "TRUNCATE auth.users, auth.enrollment_tokens, auth.pending_agents, "
                "auth.mfa_recovery_codes RESTART IDENTITY CASCADE",
                std::vector<std::string>{});
            INFO("[AuthDbPgShared] reset TRUNCATE: " << PQresultErrorMessage(trunc.get()));
            REQUIRE(trunc.status() == PGRES_COMMAND_OK);
            // COUPLING: this DELETE is sound ONLY while every registered
            // secret column lives in a table TRUNCATEd above (today:
            // auth.users.mfa_totp_secret). A future secret column in a table
            // outside that list would leave blobs whose kek_version this
            // DELETE orphans — SecretCodec's S6 scan then fails every later
            // fixture. Extend the TRUNCATE list in the same commit that
            // registers any new secret column reachable from these fixtures.
            auto kek = yuzu::server::pg::exec_params(lease.get(), "DELETE FROM secrets.kek_meta",
                                                     std::vector<std::string>{});
            INFO("[AuthDbPgShared] reset kek_meta: " << PQresultErrorMessage(kek.get()));
            REQUIRE(kek.status() == PGRES_COMMAND_OK);
        }

        provider_ = std::make_unique<yuzu::server::FileKeyProvider>(keys_.path);
        if (inject_encrypt_faults) {
            faulty_provider_ = std::make_unique<FaultyKekProvider>(*provider_);
            codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*faulty_provider_);
        } else {
            codec_ = std::make_unique<yuzu::server::pg::SecretCodec>(*provider_);
        }
        // Migration check is a no-op on the already-migrated clone (a cheap
        // SELECT, no new backend); the secret-column registration re-runs
        // idempotently, exactly as it does on every AuthDbPg clone today.
        authdb_ =
            std::make_unique<yuzu::server::AuthDB>(*bundle.pool, *codec_, cleanup_interval_secs);
        REQUIRE(authdb_->is_open());

        yuzu::server::pg::PgConn conn{PQconnectdb(bundle.db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto init_res = codec_->init(conn.get());
        INFO("[AuthDbPgShared] SecretCodec::init status (blank == ok): "
             << (init_res.has_value() ? "" : std::string(yuzu::server::pg::SecretCodec::to_string(
                                                  init_res.error().kind))));
        REQUIRE(init_res.has_value());
    }

    AuthDbPgShared(const AuthDbPgShared&) = delete;
    AuthDbPgShared& operator=(const AuthDbPgShared&) = delete;
    AuthDbPgShared(AuthDbPgShared&&) = delete;
    AuthDbPgShared& operator=(AuthDbPgShared&&) = delete;

    /// Connection string of the SHARED database backing this store — for
    /// tests that act on its data from a second connection. DML only: DDL
    /// through this DSN poisons every later shared-fixture test.
    [[nodiscard]] std::string dsn() const { return detail::auth_db_shared_bundle().db.dsn(); }

    [[nodiscard]] yuzu::server::AuthDB* get() const noexcept { return authdb_.get(); }
    yuzu::server::AuthDB* operator->() const noexcept { return authdb_.get(); }
    yuzu::server::AuthDB& operator*() const noexcept { return *authdb_; }
    explicit operator bool() const noexcept { return authdb_ != nullptr; }

    [[nodiscard]] yuzu::server::pg::SecretCodec& codec() noexcept { return *codec_; }
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept {
        return *detail::auth_db_shared_bundle().pool;
    }

    /// Non-null only when constructed with `inject_encrypt_faults = true`.
    [[nodiscard]] FaultyKekProvider* fault_provider() noexcept { return faulty_provider_.get(); }

    /// Tear down the per-fixture chain early (store, then codec/provider).
    /// The shared pool/database deliberately outlive every fixture
    /// (SharedPgDbRegistry owns their teardown).
    void reset() noexcept {
        authdb_.reset();
        codec_.reset();
        faulty_provider_.reset();
        provider_.reset();
    }

private:
    yuzu::test::TempDir keys_;
    std::unique_ptr<yuzu::server::FileKeyProvider> provider_;
    // Same ordering constraint as AuthDbPg: destruct codec_ before
    // faulty_provider_ before provider_.
    std::unique_ptr<FaultyKekProvider> faulty_provider_;
    std::unique_ptr<yuzu::server::pg::SecretCodec> codec_;
    std::unique_ptr<yuzu::server::AuthDB> authdb_;
};

} // namespace yuzu::test
