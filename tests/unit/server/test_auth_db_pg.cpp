// AuthDB (Postgres) tests — born-on-PG `auth` schema (ADR-0006 server
// substrate migration). Covers user CRUD + role, account lockout, break-glass
// arming, JIT elevation eligibility, provisioning_source / identity_source
// (SSO), enrollment tokens, recovery codes, the MFA enroll -> verify round
// trip THROUGH the real `pg::SecretCodec`, fresh-start admin seeding, and —
// the ★ security-critical deliverable — the three MFA fail-closed cases: a
// decrypt failure on an ENROLLED secret must surface `SecretUnavailable`,
// NEVER read as "not enrolled" (mfa_status) or "code didn't match"
// (mfa_verify_login_code); a decrypt failure on a PROVISIONAL secret must
// refuse to mint a fresh one (mfa_init_enrollment) and must refuse to accept
// any code against it (mfa_verify_enrollment).
//
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
// but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour tests
// use the pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md
// step 7) — the template runs a throwaway SecretCodec::init() + AuthDB
// construction once, then resets `secrets.kek_meta` to empty so every clone
// starts fresh and mints its OWN KEK against its OWN keys dir (mirrors
// test_secret_codec.cpp's `secrets_tpl`).

#include "acquire_retry.hpp"
#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "totp.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::AuthDB;
using yuzu::server::AuthDBError;
using yuzu::server::FileKeyProvider;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate auth_db_tpl{"authdb", [](const std::string& dsn) {
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("authdb template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("authdb template: secret codec init failed");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("authdb template: kek_meta reset failed");

    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuthDB db{pool, codec};
    if (!db.is_open())
        throw std::runtime_error("authdb template: store failed to migrate");
}};

// Corrupts a user's stored `mfa_totp_secret` envelope in place with garbage
// bytes that cannot possibly decrypt (wrong length + no valid GCM tag) —
// simulates tamper / a wrong-KEK-version blob without needing a second KEK.
void corrupt_secret(PGconn* conn, const std::string& username) {
    const char* values[] = {username.c_str()};
    PgResult res{PQexecParams(
        conn,
        "UPDATE auth.users SET mfa_totp_secret = decode('deadbeefcafebabe0011223344','hex') "
        "WHERE username = $1",
        1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.ok());
}

// NULL the secret while LEAVING `mfa_enrolled_at` set — the row state the
// 2026-07-25 review reproduced against live PG (HIGH #1). Distinct from
// corrupt_secret above: there the blob is present but undecryptable; here the
// column is absent entirely, which took a different (and, until the fix, a
// silently-wrong) branch in mfa_verify_login_code.
void null_secret_keep_enrolled(PGconn* conn, const std::string& username) {
    const char* values[] = {username.c_str()};
    PgResult res{PQexecParams(conn,
                              "UPDATE auth.users SET mfa_totp_secret = NULL WHERE username = $1",
                              1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.ok());
}

std::string read_secret_hex(PGconn* conn, const std::string& username) {
    const char* values[] = {username.c_str()};
    PgResult res{PQexecParams(conn, "SELECT encode(mfa_totp_secret,'hex') FROM auth.users WHERE username = $1",
                              1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    if (PQgetisnull(res.get(), 0, 0))
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

struct Harness {
    yuzu::test::TempDir keys;
    FileKeyProvider provider;
    SecretCodec codec;
    PgConn conn;
    PgPool pool;
    AuthDB db;

    explicit Harness(const std::string& dsn)
        : provider(keys.path), codec(provider), conn(connect(dsn)),
          pool(PgPool::Options{.conninfo = dsn, .size = 4}), db(pool, codec) {
        REQUIRE(codec.init(conn.get()).has_value());
        REQUIRE(pool.valid());
        REQUIRE(db.is_open());
    }
};

} // namespace

// #2396: StoreBusy (the bounded acquire-retry exhausted → transient pool
// outage) MUST classify as store-unavailable, so every existing
// is_store_unavailable()-gated 503 site keeps failing CLOSED on a pool blip.
// This is the load-bearing mapping — a regression here would let a transient
// acquire outage fall through to a wrong-code 401 (burning a lockout attempt)
// or, on the MFA read, a password-only minted session. No PG needed — a pure
// header contract, so it runs on every leg.
TEST_CASE("is_store_unavailable classifies StoreBusy as unavailable (#2396)",
          "[auth_db][degrade]") {
    using yuzu::server::AuthDBError;
    using yuzu::server::is_store_unavailable;
    CHECK(is_store_unavailable(AuthDBError::StoreBusy));
    // Regression guard on the rest of the store-unavailable set...
    CHECK(is_store_unavailable(AuthDBError::QueryFailed));
    CHECK(is_store_unavailable(AuthDBError::WriteFailed));
    CHECK(is_store_unavailable(AuthDBError::SecretUnavailable));
    // ...and that genuine business outcomes stay OUT of it (never a 503).
    CHECK_FALSE(is_store_unavailable(AuthDBError::UserNotFound));
    CHECK_FALSE(is_store_unavailable(AuthDBError::InvalidCredentials));
    CHECK_FALSE(is_store_unavailable(AuthDBError::InvalidUsername));
}

// #2396 (adv-review CDX-P1-02 / K7): a saturated-pool test can prove fail-closed
// EXHAUSTION but not that a transient empty acquire actually rides out to a
// SUCCESS within the same call — the feature's primary recovery behaviour. The
// retry loop is factored into detail::acquire_with_bounded_retry precisely so
// that property is deterministically testable (no live pool, no timing). A
// move-only truthy-on-success stand-in for pg::PgPool::Lease drives it.
namespace {
struct FakeLease {
    bool ok{false};
    FakeLease() = default;
    explicit FakeLease(bool o) : ok(o) {}
    FakeLease(FakeLease&&) = default;
    FakeLease& operator=(FakeLease&&) = default;
    FakeLease(const FakeLease&) = delete;
    FakeLease& operator=(const FakeLease&) = delete;
    explicit operator bool() const { return ok; }
};
} // namespace

TEST_CASE("acquire_with_bounded_retry rides a transient empty acquire out to success (#2396)",
          "[auth_db][degrade]") {
    using yuzu::server::detail::acquire_with_bounded_retry;

    // (a) THE property CDX-P1-02 wanted pinned: first two acquires come back
    // empty, the third succeeds -> the loop returns success within one call,
    // having retried exactly twice with a backoff before each retry.
    int calls = 0, sleeps = 0;
    auto v = acquire_with_bounded_retry(
        2, [&](bool) { ++calls; return FakeLease(calls >= 3); }, [&] { ++sleeps; });
    CHECK(bool(v));
    CHECK(calls == 3); // 1 first attempt + 2 retries
    CHECK(sleeps == 2);

    // (b) sustained outage: every acquire empty -> exhausted, returns empty,
    // BOUNDED at 1 + retries attempts (never a hang, never unbounded).
    calls = 0, sleeps = 0;
    auto v2 = acquire_with_bounded_retry(
        2, [&](bool) { ++calls; return FakeLease(false); }, [&] { ++sleeps; });
    CHECK_FALSE(bool(v2));
    CHECK(calls == 3);
    CHECK(sleeps == 2);

    // (c) healthy: first acquire succeeds -> no retry, no backoff (zero added
    // latency on the normal path).
    calls = 0, sleeps = 0;
    auto v3 = acquire_with_bounded_retry(
        2, [&](bool) { ++calls; return FakeLease(true); }, [&] { ++sleeps; });
    CHECK(bool(v3));
    CHECK(calls == 1);
    CHECK(sleeps == 0);

    // (d) retries == 0 (the stripe-held acquires' policy): a single un-retried
    // attempt, empty stays empty, no backoff.
    calls = 0, sleeps = 0;
    auto v4 = acquire_with_bounded_retry(
        0, [&](bool) { ++calls; return FakeLease(false); }, [&] { ++sleeps; });
    CHECK_FALSE(bool(v4));
    CHECK(calls == 1);
    CHECK(sleeps == 0);
}

#ifdef YUZU_TEST_ENABLE_PG

// ── construction ───────────────────────────────────────────────────────────

TEST_CASE("AuthDB constructs, migrates, and opens", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    CHECK(h.db.is_ready());
    CHECK(h.db.is_open());
}

TEST_CASE("AuthDB reports !is_open on a migration failure", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA auth")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE auth.users (bogus int)")};
        REQUIRE(t.ok());
    }
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(codec.init(conn.get()).has_value());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AuthDB authdb{pool, codec};
    CHECK_FALSE(authdb.is_open()); // fail-closed (ADR-0012 §1)
}

// ── user CRUD + role ──────────────────────────────────────────────────────

TEST_CASE("AuthDB user CRUD + role", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    SECTION("upsert + get + list + exists") {
        REQUIRE(h.db.upsert_user("alice", "hash1", "salt1", yuzu::server::auth::Role::user).has_value());
        CHECK(h.db.user_exists("alice").value());
        CHECK_FALSE(h.db.user_exists("nobody").value());

        auto entry = h.db.get_user("alice");
        REQUIRE(entry.has_value());
        CHECK(entry->username == "alice");
        CHECK(entry->role == yuzu::server::auth::Role::user);
        CHECK(entry->hash_hex == "hash1");
        CHECK(entry->salt_hex == "salt1");
        CHECK(entry->identity_source == "local");

        auto users = h.db.list_users();
        REQUIRE(users.has_value());
        REQUIRE(users->size() == 1);
        CHECK((*users)[0].username == "alice");
    }

    SECTION("duplicate upsert is rejected, never overwrites") {
        REQUIRE(h.db.upsert_user("bob", "hashA", "saltA", yuzu::server::auth::Role::user).has_value());
        auto dup = h.db.upsert_user("bob", "hashB", "saltB", yuzu::server::auth::Role::admin);
        REQUIRE_FALSE(dup.has_value());
        CHECK(dup.error() == AuthDBError::UserAlreadyExists);
        auto entry = h.db.get_user("bob");
        REQUIRE(entry.has_value());
        CHECK(entry->hash_hex == "hashA"); // unchanged
    }

    SECTION("update_role never touches credentials") {
        REQUIRE(h.db.upsert_user("carol", "hashC", "saltC", yuzu::server::auth::Role::user).has_value());
        REQUIRE(h.db.update_role("carol", yuzu::server::auth::Role::admin).has_value());
        auto entry = h.db.get_user("carol");
        REQUIRE(entry.has_value());
        CHECK(entry->role == yuzu::server::auth::Role::admin);
        CHECK(entry->hash_hex == "hashC");
        auto missing = h.db.update_role("nope", yuzu::server::auth::Role::admin);
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error() == AuthDBError::UserNotFound);
    }

    SECTION("remove_user soft-deletes; reactivate_user clears lockout state") {
        REQUIRE(h.db.upsert_user("dave", "hashD", "saltD", yuzu::server::auth::Role::user).has_value());
        auto removed = h.db.remove_user("dave");
        REQUIRE(removed.has_value());
        CHECK(*removed == true);
        CHECK_FALSE(h.db.user_exists("dave").value()); // is_active filter
        auto again = h.db.remove_user("dave");
        REQUIRE(again.has_value());
        CHECK(*again == false); // already inactive — not a re-removal

        REQUIRE(h.db.reactivate_user("dave").has_value());
        CHECK(h.db.user_exists("dave").value());

        auto missing = h.db.reactivate_user("ghost");
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error() == AuthDBError::UserNotFound);
    }

    SECTION("list_users_including_inactive surfaces the is_active flag") {
        REQUIRE(h.db.upsert_user("erin", "h", "s", yuzu::server::auth::Role::user).has_value());
        REQUIRE(h.db.remove_user("erin").has_value());
        auto all = h.db.list_users_including_inactive();
        REQUIRE(all.has_value());
        REQUIRE(all->size() == 1);
        CHECK((*all)[0].username == "erin");
        CHECK_FALSE((*all)[0].is_active);
    }
}

// ── fresh-start admin seeding ─────────────────────────────────────────────

TEST_CASE("AuthDB::seed_admin_if_empty seeds once and no-ops thereafter", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto seeded = h.db.seed_admin_if_empty("admin", "roothash", "rootsalt");
    REQUIRE(seeded.has_value());
    CHECK(*seeded == true);
    auto entry = h.db.get_user("admin");
    REQUIRE(entry.has_value());
    CHECK(entry->role == yuzu::server::auth::Role::admin);

    // A second attempt (even with different creds) is a clean no-op — table
    // is no longer empty.
    auto again = h.db.seed_admin_if_empty("someoneelse", "x", "y");
    REQUIRE(again.has_value());
    CHECK(*again == false);
    CHECK_FALSE(h.db.user_exists("someoneelse").value());

    auto bad = h.db.seed_admin_if_empty("not a valid username!", "x", "y");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);
}

// ── account lockout ────────────────────────────────────────────────────────

TEST_CASE("AuthDB account lockout apply / clear / expiry", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("locky", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto status0 = h.db.lockout_status("locky");
    REQUIRE(status0.has_value());
    CHECK_FALSE(status0->locked);
    CHECK(status0->failed_count == 0);

    // Threshold 3: first two failures increment but don't lock.
    for (int i = 1; i <= 2; ++i) {
        auto rec = h.db.record_failed_login("locky", /*threshold=*/3, /*window_secs=*/3600);
        REQUIRE(rec.has_value());
        CHECK(rec->failed_count == i);
        CHECK_FALSE(rec->locked);
    }
    // Third failure crosses the threshold.
    auto rec3 = h.db.record_failed_login("locky", 3, 3600);
    REQUIRE(rec3.has_value());
    CHECK(rec3->failed_count == 3);
    CHECK(rec3->locked);
    CHECK(rec3->just_locked);
    CHECK_FALSE(rec3->locked_until.empty());

    auto status1 = h.db.lockout_status("locky");
    REQUIRE(status1.has_value());
    CHECK(status1->locked);

    REQUIRE(h.db.clear_failed_logins("locky").has_value());
    auto status2 = h.db.lockout_status("locky");
    REQUIRE(status2.has_value());
    CHECK_FALSE(status2->locked);
    CHECK(status2->failed_count == 0);

    // A lock that has already expired (negative window) resets the cycle
    // rather than staying stuck — same "expiry" contract as the SQLite era.
    auto expired_rec = h.db.record_failed_login("locky", 1, /*window_secs=*/-100);
    REQUIRE(expired_rec.has_value());
    // `now()` is transaction-stable in Postgres (one evaluation per
    // statement), so `locked_until = now() + (-100s)` and the RETURNING
    // check `locked_until > now()` use the SAME instant — a negative window
    // is therefore, correctly, NEVER "currently locked": the 1-strike
    // threshold crossing wrote a locked_until, but it is already in the
    // past the moment it lands.
    CHECK_FALSE(expired_rec->locked);
    CHECK_FALSE(expired_rec->locked_until.empty()); // locked_until WAS written (past-dated)
    auto rearm = h.db.record_failed_login("locky", 1, 3600);
    REQUIRE(rearm.has_value());
    CHECK(rearm->failed_count == 1); // cycle restarted, not accumulated

    // Anti-enumeration: a non-existent user reads as "not locked", not an error.
    auto nouser = h.db.lockout_status("ghost");
    REQUIRE(nouser.has_value());
    CHECK_FALSE(nouser->locked);
}

// ── break-glass arming ────────────────────────────────────────────────────

TEST_CASE("AuthDB break-glass arm / status / disarm", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("glass", "h", "s", yuzu::server::auth::Role::admin).has_value());

    auto status0 = h.db.break_glass_status("glass");
    REQUIRE(status0.has_value());
    CHECK_FALSE(status0->armed);

    auto armed = h.db.arm_break_glass("glass", 3600);
    REQUIRE(armed.has_value());
    CHECK(armed->armed);
    CHECK_FALSE(armed->armed_until.empty());

    auto status1 = h.db.break_glass_status("glass");
    REQUIRE(status1.has_value());
    CHECK(status1->armed);

    REQUIRE(h.db.disarm_break_glass("glass").has_value());
    auto status2 = h.db.break_glass_status("glass");
    REQUIRE(status2.has_value());
    CHECK_FALSE(status2->armed);

    auto missing = h.db.arm_break_glass("ghost", 3600);
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── JIT elevation eligibility ─────────────────────────────────────────────

TEST_CASE("AuthDB elevation eligibility", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("jit", "h", "s", yuzu::server::auth::Role::user).has_value());

    CHECK_FALSE(h.db.is_elevation_eligible("jit").value());
    REQUIRE(h.db.set_elevation_eligible("jit", true).has_value());
    CHECK(h.db.is_elevation_eligible("jit").value());
    REQUIRE(h.db.set_elevation_eligible("jit", false).has_value());
    CHECK_FALSE(h.db.is_elevation_eligible("jit").value());

    // Fail-closed for an absent user, not an error.
    CHECK_FALSE(h.db.is_elevation_eligible("ghost").value());
}

// ── provisioning_source / identity_source / SSO ───────────────────────────

TEST_CASE("AuthDB provisioning_source and identity_source", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("prov", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto src0 = h.db.get_provisioning_source("prov");
    REQUIRE(src0.has_value());
    CHECK(*src0 == "local");

    REQUIRE(h.db.set_provisioning_source("prov", std::string{yuzu::server::kProvisioningSourceScim})
                .has_value());
    auto src1 = h.db.get_provisioning_source("prov");
    REQUIRE(src1.has_value());
    CHECK(*src1 == "scim");

    REQUIRE(h.db.set_identity_source("prov", "oidc").has_value());
    auto entry = h.db.get_user("prov");
    REQUIRE(entry.has_value());
    CHECK(entry->identity_source == "oidc");

    auto missing = h.db.set_provisioning_source("ghost", "scim");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

TEST_CASE("AuthDB upsert_sso_identity provisions and refreshes without clobbering role",
          "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    const std::string principal = "oidc:https://idp.example#sub-123";
    REQUIRE(h.db.upsert_sso_identity(principal, "https://idp.example", "sub-123", "Alice", "oidc")
                .has_value());
    auto entry = h.db.get_user(principal);
    REQUIRE(entry.has_value());
    CHECK(entry->role == yuzu::server::auth::Role::user);
    CHECK(entry->identity_source == "oidc");

    // Promote to admin, then log in again — role must survive re-login.
    // update_role() deliberately stays on the STRICT is_valid_username gate
    // (#1852 item 5) — it cannot target an SSO principal (':'/'#' rejected),
    // so there is no standing-role-grant path through the public API here.
    // Simulate an out-of-band role grant via a raw UPDATE (a real deployment
    // would need its own future admin tool for this) purely to prove
    // upsert_sso_identity's ON CONFLICT arm never clobbers an existing role.
    {
        auto conn = connect(db.dsn());
        const char* values[] = {principal.c_str()};
        PgResult upd{PQexecParams(conn.get(), "UPDATE auth.users SET role = 'admin' WHERE username = $1",
                                  1, nullptr, values, nullptr, nullptr, 0)};
        REQUIRE(upd.ok());
    }
    REQUIRE(h.db.upsert_sso_identity(principal, "https://idp.example", "sub-123", "Alice R.", "oidc")
                .has_value());
    auto entry2 = h.db.get_user(principal);
    REQUIRE(entry2.has_value());
    CHECK(entry2->role == yuzu::server::auth::Role::admin);

    // The reserved `engine:` namespace is never constructible via this path.
    auto rejected = h.db.upsert_sso_identity("engine:vuln-sync", "iss", "sub", "x", "oidc");
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error() == AuthDBError::InvalidUsername);
}

// ── get_user() input validation (Gate 4 governance BLOCKING finding) ───────
//
// Unlike ~20 sibling AuthDB methods, get_user() never validated its input
// before this fix — harmless while every caller was admin-invoked, but #4020
// made it reachable, unauthenticated, from POST /login's raw username field.
// PQexecParams (paramLengths=nullptr) reads a text parameter as a
// NUL-terminated C string, so "admin\0<garbage>" matches the real "admin" row
// at the DB layer while the FULL raw string (including everything after the
// NUL) is what AuthManager::find_user_or_hydrate uses as its in-memory
// users_ cache key - every distinct garbage suffix an unauthenticated caller
// sends creates a new, permanent, never-evicted cache entry, and if the
// caller also knows the real password, mints a session whose username field
// never matches the canonical name compared during remove_user()/
// update_role()'s session-invalidation sweep.

TEST_CASE("get_user rejects a username containing an embedded NUL byte",
          "[pg][auth_db][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("admin", "hash", "salt", yuzu::server::auth::Role::admin)
                .has_value());

    // The exact attack shape: a real, active username's bytes followed by a
    // NUL and arbitrary garbage - what url_decode("admin%00garbage-1")
    // produces. Must be rejected outright, never match the real "admin" row.
    const std::string mangled = std::string("admin", 5) + '\0' + "garbage-1";
    REQUIRE(mangled.size() == 15); // std::string preserves the embedded NUL + suffix
    auto result = h.db.get_user(mangled);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == AuthDBError::InvalidUsername);

    // The real username is completely unaffected.
    auto real = h.db.get_user("admin");
    REQUIRE(real.has_value());
    CHECK(real->role == yuzu::server::auth::Role::admin);
}

TEST_CASE("get_user still resolves a legitimate SSO principal after the NUL-byte fix",
          "[pg][auth_db][security]") {
    // Regression guard for the fix above: get_user() must stay usable with a
    // colon-containing SSO principal (auth_routes.cpp's legacy API-token
    // session synthesis calls get_user_role(api_token.principal_id), and a
    // human SSO user's token principal_id IS such a string) - a naive fix
    // gating on the STRICT is_valid_username (which rejects ':') would have
    // silently demoted every SSO-authenticated API-token request to
    // Role::user instead of closing a security hole.
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    const std::string principal = "oidc:https://idp.example#nul-fix-check";
    REQUIRE(h.db.upsert_sso_identity(principal, "https://idp.example", "nul-fix-check", "Bob",
                                     "oidc")
                .has_value());
    auto entry = h.db.get_user(principal);
    REQUIRE(entry.has_value());
    CHECK(entry->identity_source == "oidc");
}

TEST_CASE("AuthDB find_reserved_prefix_users scans active and soft-deleted rows", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_sso_identity("oidc:https://idp#a", "https://idp", "a", "A", "oidc").has_value());
    REQUIRE(h.db.upsert_sso_identity("oidc:https://idp#b", "https://idp", "b", "B", "oidc").has_value());
    REQUIRE(h.db.remove_user("oidc:https://idp#b").has_value()); // soft-delete

    auto found = h.db.find_reserved_prefix_users("oidc:");
    REQUIRE(found.has_value());
    CHECK(found->size() == 2); // includes the soft-deleted row

    // LIKE-metacharacter guard fails closed (nullopt), never "no collision".
    auto guarded = h.db.find_reserved_prefix_users("oid%c:");
    CHECK_FALSE(guarded.has_value());
}

// ── enrollment tokens ──────────────────────────────────────────────────────

TEST_CASE("AuthDB enrollment token lifecycle", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto token = h.db.create_enrollment_token("admin", std::chrono::seconds(3600));
    REQUIRE(token.has_value());
    CHECK_FALSE(token->empty());

    CHECK(h.db.validate_enrollment_token(*token).value());
    auto consumed = h.db.consume_enrollment_token(*token, "agent-1");
    REQUIRE(consumed.has_value());
    CHECK(*consumed == true);

    // Reuse is rejected — already consumed.
    CHECK_FALSE(h.db.validate_enrollment_token(*token).value());
    auto second = h.db.consume_enrollment_token(*token, "agent-2");
    REQUIRE(second.has_value());
    CHECK(*second == false);

    CHECK_FALSE(h.db.validate_enrollment_token("not-a-real-token").value());
}

// ── pending agents ─────────────────────────────────────────────────────────

TEST_CASE("AuthDB pending agent approve/reject", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    yuzu::server::auth::PendingAgent agent;
    agent.agent_id = "agent-xyz";
    agent.hostname = "host1";
    agent.os = "linux";
    agent.arch = "x86_64";
    agent.agent_version = "1.0.0";
    REQUIRE(h.db.add_pending_agent(agent).has_value());

    auto pending = h.db.list_pending_agents();
    REQUIRE(pending.has_value());
    REQUIRE(pending->size() == 1);
    CHECK((*pending)[0].agent_id == "agent-xyz");

    REQUIRE(h.db.approve_agent("agent-xyz", "admin").has_value());
    auto after_approve = h.db.list_pending_agents();
    REQUIRE(after_approve.has_value());
    CHECK(after_approve->empty()); // no longer 'pending'

    yuzu::server::auth::PendingAgent agent2;
    agent2.agent_id = "agent-abc";
    agent2.hostname = "host2";
    REQUIRE(h.db.add_pending_agent(agent2).has_value());
    REQUIRE(h.db.reject_agent("agent-abc").has_value());
    auto after_reject = h.db.list_pending_agents();
    REQUIRE(after_reject.has_value());
    CHECK(after_reject->empty());
}

// ── recovery codes ─────────────────────────────────────────────────────────

TEST_CASE("AuthDB recovery codes regenerate + single-use consume", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("rec", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto codes = h.db.mfa_regenerate_recovery_codes("rec");
    REQUIRE(codes.has_value());
    REQUIRE(codes->size() == 10);

    const auto& one = (*codes)[0];
    CHECK(h.db.mfa_consume_recovery_code("rec", one).value());
    // Single-use: consuming again fails.
    CHECK_FALSE(h.db.mfa_consume_recovery_code("rec", one).value());
    // A never-issued code fails cleanly (not an error).
    CHECK_FALSE(h.db.mfa_consume_recovery_code("rec", "ZZZZZ-ZZZZZ").value());
}

// ── #3779: concurrent recovery-code regenerate must serialize ───────────────
//
// mfa_regenerate_recovery_codes runs DELETE-all + INSERT-10. Without the
// SELECT … FOR UPDATE guard on auth.users, two concurrent regenerates each
// DELETE the committed rows (neither sees the other's uncommitted INSERTs under
// READ COMMITTED) and each INSERT 10 → 20 rows persist, and each caller is
// handed a 10-code set that no longer matches storage. The row lock serializes
// them: BOTH still succeed (regenerate has no "already"-loser — it is
// idempotently repeatable), but exactly one set of 10 persists (clean
// sequential last-writer-wins) and it is the set that consumes. Assert on COUNTS
// (recovery_codes_remaining == 10, not 20) so the test is deterministic; each
// thread writes only its own codes slot via a distinct pointer.
TEST_CASE("AuthDB MFA: concurrent recovery-code regenerate persists exactly one set of 10",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()}; // pool size 4 — enough for two concurrent regenerates
    REQUIRE(h.db.upsert_user("regenrace", "h", "s", yuzu::server::auth::Role::user).has_value());

    std::atomic<int> ok{0};
    std::atomic<int> err{0};
    std::atomic<bool> go{false};
    std::vector<std::string> v1, v2;
    auto submit = [&](std::vector<std::string>* slot) {
        while (!go.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        auto r = h.db.mfa_regenerate_recovery_codes("regenrace");
        if (r.has_value()) {
            *slot = *r;
            ok.fetch_add(1, std::memory_order_relaxed);
        } else {
            err.fetch_add(1, std::memory_order_relaxed);
        }
    };
    std::thread t1(submit, &v1);
    std::thread t2(submit, &v2);
    go.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    // Both regenerates succeed; serialization only orders them.
    CHECK(ok.load() == 2);
    CHECK(err.load() == 0);
    REQUIRE(v1.size() == 10);
    REQUIRE(v2.size() == 10);

    // Core assertion: exactly one set of 10 persists — NOT 20 (the pre-fix
    // torn-interleave count).
    auto status = h.db.mfa_status("regenrace");
    REQUIRE(status.has_value());
    CHECK(status->recovery_codes_remaining == 10);

    // Returned == persisted: exactly one of the two returned sets is the live one
    // (its first code consumes), the other is cleanly dead (its first code does
    // not) — deterministic regardless of which thread committed last. Pre-fix,
    // ALL 20 rows are present so both would consume (this CHECK would fail).
    const bool v1_live = h.db.mfa_consume_recovery_code("regenrace", v1[0]).value();
    const bool v2_live = h.db.mfa_consume_recovery_code("regenrace", v2[0]).value();
    CHECK(v1_live != v2_live);

    // The consume above spent one code from the live set → 9 remain.
    auto after = h.db.mfa_status("regenrace");
    REQUIRE(after.has_value());
    CHECK(after->recovery_codes_remaining == 9);
}

// #3779: the new `SELECT … FOR UPDATE` 0-row branch — regenerate for a
// nonexistent user returns UserNotFound (never a false store-outage grade).
TEST_CASE("AuthDB MFA: regenerate for a nonexistent user returns UserNotFound",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    auto r = h.db.mfa_regenerate_recovery_codes("nobody");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == AuthDBError::UserNotFound);
}

// #3779: the sequential form of the regenerate-vs-remove_user race — the
// `is_active = TRUE` predicate refuses a regenerate once the account is
// deactivated, so no fresh recovery codes land on a dead login. (remove_user
// soft-deletes: is_active=FALSE + DELETE codes; the subsequent regenerate's
// FOR UPDATE matches 0 active rows and returns UserNotFound before any INSERT.)
TEST_CASE("AuthDB MFA: regenerate refuses a deactivated account (no live codes)",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("gone", "h", "s", yuzu::server::auth::Role::user).has_value());
    REQUIRE(h.db.mfa_regenerate_recovery_codes("gone").has_value()); // seed a live set
    REQUIRE(h.db.remove_user("gone").has_value());                   // deactivate

    auto r = h.db.mfa_regenerate_recovery_codes("gone");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == AuthDBError::UserNotFound);
    // mfa_status on a deactivated account also returns UserNotFound — there is no
    // active row to carry recovery codes, so none were (or could be) reissued.
    CHECK_FALSE(h.db.mfa_status("gone").has_value());
}

// ── MFA enroll -> verify round trip THROUGH SecretCodec ──────────────────

TEST_CASE("AuthDB MFA enroll -> verify round trip is envelope-encrypted end to end",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("mfauser", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto pre = h.db.mfa_status("mfauser");
    REQUIRE(pre.has_value());
    CHECK_FALSE(pre->enrolled);

    auto init = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE(init.has_value());
    CHECK_FALSE(init->secret_base32.empty());
    CHECK(init->otpauth_uri.find("otpauth://") == 0);

    // The secret is genuinely encrypted at rest — the raw column bytes must
    // NOT equal the plaintext secret we were handed.
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto stored_hex = read_secret_hex(h.conn.get(), "mfauser");
    CHECK_FALSE(stored_hex.empty());

    // Re-init while still provisional REUSES the same secret (idempotent).
    auto init2 = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE(init2.has_value());
    CHECK(init2->secret_base32 == init->secret_base32);

    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto now = std::chrono::system_clock::now();
    auto counter = yuzu::server::mfa::current_counter(now);
    auto code = yuzu::server::mfa::generate(secret_view, counter);

    auto verify = h.db.mfa_verify_enrollment("mfauser", code);
    REQUIRE(verify.has_value());
    CHECK(verify->size() == 10);

    // Enrolling twice is rejected.
    auto redo = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE_FALSE(redo.has_value());
    CHECK(redo.error() == AuthDBError::MfaAlreadyEnrolled);

    auto status = h.db.mfa_status("mfauser");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
    CHECK(status->recovery_codes_remaining == 10);

    // A fresh code at the NEXT step (replay protection rejects re-using the
    // enrollment counter) verifies for login.
    auto code2 = yuzu::server::mfa::generate(secret_view, counter + 1);
    auto login = h.db.mfa_verify_login_code("mfauser", code2);
    REQUIRE(login.has_value());
    CHECK(*login == true);

    // A wrong code is a clean `false`, not an error.
    auto wrong = h.db.mfa_verify_login_code("mfauser", "000000");
    REQUIRE(wrong.has_value());
    CHECK(*wrong == false);

    REQUIRE(h.db.mfa_disable("mfauser").has_value());
    auto after_disable = h.db.mfa_status("mfauser");
    REQUIRE(after_disable.has_value());
    CHECK_FALSE(after_disable->enrolled);
}

// ── #3762: enrollment double-verify is atomic — one winner, no orphaned codes ──
//
// `mfa_verify_enrollment`'s pre-txn `mfa_status().enrolled` check and its enrollment
// UPDATE are not atomic; the guard predicate `AND mfa_enrolled_at IS NULL` closes the
// window where two concurrent verifies of one enrollment code both stamp `enrolled_at`
// and both run `regenerate_recovery_codes_locked` (DELETE-all + INSERT) — the loser
// deleting the winner's just-issued set. Exactly one caller must get 10 codes; the loser
// must be graded `MfaAlreadyEnrolled` (NOT a false `WriteFailed`/503 from the classify
// branch); and the PERSISTED set must be the winner's (a winner code must still consume).
// Assert on COUNTS, not which thread wins, so the test is deterministic; each thread
// writes only its own codes slot (via a distinct pointer), so there is no shared mutation.
TEST_CASE("AuthDB MFA: concurrent enrollment verify enrolls exactly once, no orphaned "
          "recovery codes",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()}; // pool size 4 — enough for two concurrent verifies
    REQUIRE(h.db.upsert_user("enrollrace", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("enrollrace", "Yuzu");
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    auto code = yuzu::server::mfa::generate(secret_view, counter);

    std::atomic<int> ok{0};
    std::atomic<int> already{0};   // MfaAlreadyEnrolled — the intended loser outcome
    std::atomic<int> other_err{0}; // any other error (e.g. a false WriteFailed/503)
    std::atomic<bool> go{false};
    std::vector<std::string> v1, v2;
    auto submit = [&](std::vector<std::string>* slot) {
        while (!go.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        auto r = h.db.mfa_verify_enrollment("enrollrace", code);
        if (r.has_value()) {
            *slot = *r;
            ok.fetch_add(1, std::memory_order_relaxed);
        } else if (r.error() == AuthDBError::MfaAlreadyEnrolled) {
            already.fetch_add(1, std::memory_order_relaxed);
        } else {
            other_err.fetch_add(1, std::memory_order_relaxed);
        }
    };
    std::thread t1(submit, &v1);
    std::thread t2(submit, &v2);
    go.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    // Exactly one enrollment; the loser is graded MfaAlreadyEnrolled — never a false
    // WriteFailed/503, and never a second success.
    CHECK(ok.load() == 1);
    CHECK(already.load() == 1);
    CHECK(other_err.load() == 0);

    const std::vector<std::string>& winner = v1.empty() ? v2 : v1;
    REQUIRE(winner.size() == 10);

    // Anti-orphan: the persisted set is the winner's — 10 remain, and a winner code
    // consumes (it would fail if the loser had regenerated over it).
    auto status = h.db.mfa_status("enrollrace");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
    CHECK(status->recovery_codes_remaining == 10);
    CHECK(h.db.mfa_consume_recovery_code("enrollrace", winner[0]).value());
}

// ── #3762: white-box coverage of the enrollment guard's WHERE predicate ─────
//
// The concurrency test above proves exactly-once end-to-end, but the loser can be
// caught by the pre-txn `mfa_status().enrolled` check before ever reaching the guarded
// UPDATE, so it does not deterministically exercise the guard's own 0-row branch. This
// pins every predicate clause directly against a seeded row. The guard binds the commit to
// the EXACT secret blob the verify authenticated against (`mfa_totp_secret = decode($3,
// 'hex')`), so a row is claimed ONLY when it is active, still provisional (`mfa_enrolled_at
// IS NULL`), and its stored secret is byte-identical to the loaded one. It rejects,
// deterministically: deactivated, already-enrolled, disabled (secret NULLed), and ROTATED
// (a concurrent disable+init put a DIFFERENT secret B in the column — a bare `IS NOT NULL`
// would wrongly match B and enrol over an unverified secret; #3781 review). It mirrors the
// exact predicate from `mfa_verify_enrollment`; a drift between the two is the thing to
// notice. Each `run_guard()` match stamps `mfa_enrolled_at`, so state is reset per case.
TEST_CASE("AuthDB MFA: enrollment guard claims only the row whose stored secret still "
          "matches the verified one; rejects rotated / disabled / enrolled / deactivated",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("enrollguard", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto set_col = [&](const char* sql) {
        const char* v[] = {"enrollguard"};
        PgResult r{PQexecParams(h.conn.get(), sql, 1, nullptr, v, nullptr, nullptr, 0)};
        REQUIRE(r.ok());
    };
    // A provisional pending-enrollment candidate: active, enrolled_at NULL, secret present.
    auto make_provisional = [&] {
        set_col("UPDATE auth.users SET is_active = TRUE, mfa_enrolled_at = NULL, "
                "mfa_totp_secret = decode('0011223344','hex') WHERE username = $1");
    };
    // The exact guard from mfa_verify_enrollment, bound to the verified secret's hex ($3).
    auto run_guard = [&](const char* bound_secret_hex) -> int {
        const char* v[] = {"7", "enrollguard", bound_secret_hex};
        PgResult r{PQexecParams(
            h.conn.get(),
            "UPDATE auth.users SET mfa_enrolled_at = now(), mfa_last_counter = $1, updated_at = now() "
            "WHERE username = $2 AND is_active = TRUE AND mfa_enrolled_at IS NULL "
            "AND mfa_totp_secret = decode($3, 'hex') RETURNING id",
            3, nullptr, v, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get());
    };

    const char* kSecretA = "0011223344";        // what make_provisional() seeds (verified)
    const char* kSecretB = "aabbccddee";         // a different, rotated secret

    make_provisional();
    CHECK(run_guard(kSecretA) == 1); // still holding A -> claimed (stamps enrolled_at)
    CHECK(run_guard(kSecretA) == 0); // now enrolled -> rejected

    // Rotated: a concurrent disable+init replaced the secret with B while still provisional.
    // The verify authenticated against A, so the guard bound to A must reject B -- a bare
    // `IS NOT NULL` would wrongly match B and enrol over an unverified secret (#3781).
    make_provisional();
    set_col("UPDATE auth.users SET mfa_totp_secret = decode('aabbccddee','hex') WHERE username = $1");
    CHECK(run_guard(kSecretA) == 0); // B != A -> rejected
    CHECK(run_guard(kSecretB) == 1); // a verify of B would, of course, claim it

    // Disabled: mfa_disable NULLs the secret. NULL != A -> rejected.
    make_provisional();
    set_col("UPDATE auth.users SET mfa_enrolled_at = NULL, mfa_totp_secret = NULL WHERE username = $1");
    CHECK(run_guard(kSecretA) == 0);

    // Deactivated: is_active = FALSE rejects.
    make_provisional();
    set_col("UPDATE auth.users SET is_active = FALSE WHERE username = $1");
    CHECK(run_guard(kSecretA) == 0);
}

// ── #3762: the enrollment guard must NOT wedge a legitimate re-enroll ───────
//
// The `mfa_enrolled_at IS NULL` guard is safe against blocking a post-disable
// re-enroll ONLY because the un-enroll paths NULL `mfa_enrolled_at`. This pins the
// `mfa_disable` path specifically (the primary un-enroll path): enroll → disable →
// re-enroll must yield a fresh 10-code set. A future `mfa_disable` variant that forgot
// to clear the column would wedge re-enrollment into a permanent MfaAlreadyEnrolled, and
// this test is what catches it. (Soft-delete also NULLs the column, but is not exercised
// here — a re-enroll through that path additionally requires reactivation.)
TEST_CASE("AuthDB MFA: disable then re-enroll succeeds — the guard does not wedge re-enroll",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("reenroll", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto enroll_once = [&]() {
        auto init = h.db.mfa_init_enrollment("reenroll", "Yuzu");
        REQUIRE(init.has_value());
        auto raw = yuzu::server::mfa::base32_decode(init->secret_base32);
        REQUIRE(raw.has_value());
        auto sv = std::string_view(reinterpret_cast<const char*>(raw->data()), raw->size());
        auto code = yuzu::server::mfa::generate(
            sv, yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));
        auto verify = h.db.mfa_verify_enrollment("reenroll", code);
        REQUIRE(verify.has_value());
        CHECK(verify->size() == 10);
    };

    enroll_once();
    REQUIRE(h.db.mfa_disable("reenroll").has_value());
    auto disabled = h.db.mfa_status("reenroll");
    REQUIRE(disabled.has_value());
    CHECK_FALSE(disabled->enrolled); // mfa_disable NULLed mfa_enrolled_at

    // Re-enroll from scratch: a fresh secret + code must be accepted, proving the guard
    // did not permanently latch on the prior enrollment.
    enroll_once();
    auto reenrolled = h.db.mfa_status("reenroll");
    REQUIRE(reenrolled.has_value());
    CHECK(reenrolled->enrolled);
    CHECK(reenrolled->recovery_codes_remaining == 10);
}

// ── #2399: a single valid TOTP code is consumed AT MOST ONCE, even under two
//    concurrent submissions ─────────────────────────────────────────────────
//
// `mfa_verify_login_code` is a `SELECT ... FOR UPDATE` transaction whose
// counter advance is additionally guarded by `WHERE mfa_last_counter < $matched
// RETURNING`. Two mechanisms, one invariant: the same code cannot pass twice.
// This exercises it end-to-end against live PG with the pool handing each
// thread its own connection — the row lock serializes them, and the monotonic
// WHERE is the belt to that lock's suspenders. Assert on the COUNT (exactly one
// success), not on which thread wins, so the test is deterministic.
TEST_CASE("AuthDB MFA: concurrent submission of one valid code succeeds exactly once",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()}; // pool size 4 — enough for two concurrent verifies
    REQUIRE(h.db.upsert_user("racer", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("racer", "Yuzu");
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    // Complete enrollment at `counter`; the login code is the NEXT step so the
    // enrollment counter's own replay protection does not reject it.
    REQUIRE(h.db.mfa_verify_enrollment("racer", yuzu::server::mfa::generate(secret_view, counter))
                .has_value());
    auto login_code = yuzu::server::mfa::generate(secret_view, counter + 1);

    std::atomic<int> ok{0};
    std::atomic<int> rejected{0};
    std::atomic<int> errored{0};
    std::atomic<bool> go{false};
    auto submit = [&] {
        while (!go.load(std::memory_order_acquire)) {
            std::this_thread::yield(); // start barrier — yield (not busy-spin) so two
                                       // spinners don't burn a core on the shared 4-runner CI box
        }
        auto r = h.db.mfa_verify_login_code("racer", login_code);
        if (!r.has_value())
            errored.fetch_add(1, std::memory_order_relaxed);
        else if (*r)
            ok.fetch_add(1, std::memory_order_relaxed);
        else
            rejected.fetch_add(1, std::memory_order_relaxed);
    };
    std::thread t1(submit);
    std::thread t2(submit);
    go.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    // Exactly one submission burns the code; the other is a clean `false`
    // (already-consumed), never a second success and never a store error.
    CHECK(ok.load() == 1);
    CHECK(rejected.load() == 1);
    CHECK(errored.load() == 0);

    // And the code stays burned for any later attempt.
    auto replay = h.db.mfa_verify_login_code("racer", login_code);
    REQUIRE(replay.has_value());
    CHECK(*replay == false);
}

// ── #2399: white-box coverage of the monotonic guard's WHERE predicate ──────
//
// The concurrency test above proves single-consumption end-to-end, but under
// the production `FOR UPDATE` lock the guard's own zero-rows branch is
// unreachable (verify_window rejects a replay before the UPDATE runs). This
// test exercises the guard clause DIRECTLY against a seeded row so BOTH
// outcomes — a forward advance (1 row) and a non-forward reject (0 rows) — are
// deterministically pinned. It mirrors the exact `mfa_last_counter < $matched`
// predicate from `mfa_verify_login_code`; a drift between the two is the thing
// to notice.
TEST_CASE("AuthDB MFA: monotonic counter guard accepts a forward advance, rejects "
          "a non-forward one",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("guardrow", "h", "s", yuzu::server::auth::Role::user).has_value());

    // Seed the stored counter at 100.
    {
        const char* v[] = {"guardrow"};
        PgResult seed{PQexecParams(h.conn.get(),
                                   "UPDATE auth.users SET mfa_last_counter = 100 WHERE username = $1",
                                   1, nullptr, v, nullptr, nullptr, 0)};
        REQUIRE(seed.ok());
    }

    // The exact monotonic predicate from mfa_verify_login_code, keyed by username
    // for the test's convenience (production keys by id — the `mfa_last_counter <
    // $1 RETURNING` clause is identical). Returns the row count the guard yields.
    auto run_guard = [&](const char* matched) -> int {
        const char* v[] = {matched, "guardrow"};
        PgResult r{PQexecParams(
            h.conn.get(),
            "UPDATE auth.users SET mfa_last_counter = $1, last_login_at = now() "
            "WHERE username = $2 AND mfa_last_counter < $1 RETURNING id",
            2, nullptr, v, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get());
    };

    CHECK(run_guard("101") == 1); // forward advance (101 > 100): matches the one row
    CHECK(run_guard("101") == 0); // equal (101 == stored-now-101): non-forward → rejected
    CHECK(run_guard("50") == 0);  // backward (50 < 101): rejected
    CHECK(run_guard("102") == 1); // a further forward advance (102 > 101) is accepted
}

// ── ★ fail-closed: corrupted/undecryptable secret NEVER reads as "not
//    enrolled" or "code didn't match" ─────────────────────────────────────

TEST_CASE("AuthDB MFA fail-closed: corrupted ENROLLED secret -> SecretUnavailable, never "
          "'not enrolled'",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt1", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt1", "Yuzu");
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    auto code = yuzu::server::mfa::generate(secret_view, counter);
    REQUIRE(h.db.mfa_verify_enrollment("corrupt1", code).has_value());

    corrupt_secret(h.conn.get(), "corrupt1");

    // mfa_status must surface SecretUnavailable — NEVER enrolled=false.
    auto status = h.db.mfa_status("corrupt1");
    REQUIRE_FALSE(status.has_value());
    CHECK(status.error() == AuthDBError::SecretUnavailable);

    // mfa_verify_login_code must surface SecretUnavailable — NEVER a silent
    // `false` indistinguishable from "wrong code".
    auto login = h.db.mfa_verify_login_code("corrupt1", "123456");
    REQUIRE_FALSE(login.has_value());
    CHECK(login.error() == AuthDBError::SecretUnavailable);
}

// ── 2026-07-25 review regressions (HIGH #1 / HIGH #2) ────────────────────────
//
// Both of these row states were previously graded as ordinary business
// outcomes ("wrong code" / "no secret"), which is what let a broken second
// factor look like a user typo and a store outage look like a fresh
// enrollment. They are asserted separately from the corrupted-blob cases
// above because they take different branches.

TEST_CASE("AuthDB MFA fail-closed: ENROLLED but NULL secret is SecretUnavailable, never a "
          "silent 'wrong code'",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("nullsec1", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("nullsec1", "Yuzu");
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    REQUIRE(h.db.mfa_verify_enrollment("nullsec1", yuzu::server::mfa::generate(secret_view, counter))
                .has_value());

    null_secret_keep_enrolled(h.conn.get(), "nullsec1");

    // mfa_status graded this correctly all along...
    auto status = h.db.mfa_status("nullsec1");
    REQUIRE_FALSE(status.has_value());
    CHECK(status.error() == AuthDBError::SecretUnavailable);

    // ...but mfa_verify_login_code folded it into `false`, i.e. "wrong code",
    // so every login attempt failed with no signal that the second factor had
    // become unreadable. It must now agree with mfa_status.
    auto login = h.db.mfa_verify_login_code("nullsec1", "123456");
    REQUIRE_FALSE(login.has_value());
    CHECK(login.error() == AuthDBError::SecretUnavailable);
    CHECK(yuzu::server::is_store_unavailable(login.error()));
}

// Inject a statement-level failure that hits ONLY `load_mfa_row`. Its SELECT
// is the sole MFA read that touches `mfa_last_counter`, so dropping that
// column leaves `mfa_status` (which runs first in both call sites below)
// working while load_mfa_row's statement comes back non-PGRES_TUPLES_OK —
// exactly the outage shape HIGH #2 says used to be indistinguishable from
// "this user has no secret". Each test gets its own cloned DB, so the DDL is
// contained.
void break_load_mfa_row_only(PGconn* conn) {
    PgResult res{PQexec(conn, "ALTER TABLE auth.users DROP COLUMN mfa_last_counter")};
    REQUIRE(res.ok());
}

TEST_CASE("AuthDB MFA fail-closed: a FAILED secret read is not 'no secret' — init refuses to "
          "mint over a live provisional secret",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("qfail1", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("qfail1", "Yuzu");
    REQUIRE(init.has_value());
    auto before_hex = read_secret_hex(h.conn.get(), "qfail1");
    REQUIRE_FALSE(before_hex.empty());

    break_load_mfa_row_only(h.conn.get());

    // Before the fix the failed statement returned the same empty answer as
    // "no provisional secret", and this call minted a FRESH secret over the
    // live one — silently invalidating a QR the operator had already scanned.
    auto reinit = h.db.mfa_init_enrollment("qfail1", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    // The reuse guard preserves the actual store-unavailable error (here
    // QueryFailed — a failed statement, not an acquire timeout) rather than
    // flattening to WriteFailed, so the enroll-init degrade metric labels the
    // reason correctly (#2396 adv-review CDX-P2-03). Still fail-closed.
    CHECK(reinit.error() == AuthDBError::QueryFailed);
    CHECK(yuzu::server::is_store_unavailable(reinit.error()));

    // The decisive assertion: the stored bytes are untouched.
    CHECK(read_secret_hex(h.conn.get(), "qfail1") == before_hex);
}

TEST_CASE("AuthDB MFA fail-closed: a FAILED secret read surfaces as a store outage, not "
          "UserNotFound",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("qfail2", "h", "s", yuzu::server::auth::Role::user).has_value());
    REQUIRE(h.db.mfa_init_enrollment("qfail2", "Yuzu").has_value());

    break_load_mfa_row_only(h.conn.get());

    // A 404-shaped UserNotFound would tell the caller "enroll first" and burn
    // the in-progress enrollment; the caller needs a 503-shaped retry.
    auto verify = h.db.mfa_verify_enrollment("qfail2", "123456");
    REQUIRE_FALSE(verify.has_value());
    CHECK(verify.error() == AuthDBError::QueryFailed);
    CHECK(yuzu::server::is_store_unavailable(verify.error()));
}

// #2396: under a transient pool outage (every connection held), every login
// acquire fails CLOSED as StoreBusy (empty lease == StoreBusy, retry or not) —
// never a business-outcome error, never a hang, and it recovers once
// connections free (no permanent wedge). The retried decision read `mfa_status`
// returns StoreBusy AFTER exhausting its bounded retry; the stripe-held reads/
// writes (`lockout_status`/`record_failed_login`/`clear_failed_logins`) return
// it on a single un-retried acquire (they are deliberately not retried —
// worker-pool starvation, Gate 4 — see acquire_with_retry SCOPE). All are
// is_store_unavailable, so all 503 fail-closed, and all label a pool-acquire
// timeout as StoreBusy (-> reason=pool_acquire_timeout) rather than conflating
// it with a query error.
TEST_CASE("AuthDB login acquires fail closed as StoreBusy under pool saturation (#2396)",
          "[pg][auth_db][degrade]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("busy1", "h", "s", yuzu::server::auth::Role::user).has_value());

    // Happy path first: with the pool free the reads succeed.
    CHECK(h.db.mfa_status("busy1").has_value());
    CHECK(h.db.lockout_status("busy1").has_value());

    // Saturate the size-4 pool by holding every connection. A 2s acquire budget
    // absorbs any transient hold by AuthDB's own cleanup thread; once all four
    // are held, nothing else can hold one, so the reads below deterministically
    // find no free connection.
    std::vector<PgPool::Lease> held;
    for (int i = 0; i < 4; ++i) {
        auto lease = h.pool.try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        held.push_back(std::move(lease));
    }

    // The retried decision read fails CLOSED as StoreBusy, bounded (the test
    // returns — the retry does not hang).
    auto st = h.db.mfa_status("busy1");
    REQUIRE_FALSE(st.has_value());
    CHECK(st.error() == AuthDBError::StoreBusy);
    CHECK(yuzu::server::is_store_unavailable(st.error()));

    // The stripe-held, un-retried read/writes also report an empty lease as
    // StoreBusy (empty lease == StoreBusy) — so a pool-acquire timeout is
    // labelled pool_acquire_timeout, never conflated with a query error.
    auto lk = h.db.lockout_status("busy1");
    REQUIRE_FALSE(lk.has_value());
    CHECK(lk.error() == AuthDBError::StoreBusy);
    CHECK(yuzu::server::is_store_unavailable(lk.error()));

    auto rec = h.db.record_failed_login("busy1", 5, 900);
    REQUIRE_FALSE(rec.has_value());
    CHECK(rec.error() == AuthDBError::StoreBusy);
    CHECK(yuzu::server::is_store_unavailable(rec.error()));
    auto clr = h.db.clear_failed_logins("busy1");
    REQUIRE_FALSE(clr.has_value());
    CHECK(clr.error() == AuthDBError::StoreBusy);

    // Releasing the connections restores normal reads — a blip is transient,
    // not a permanent lockout.
    held.clear();
    CHECK(h.db.mfa_status("busy1").has_value());
}

// #2396 fail-closed regression (security-guardian Gate 2 HIGH): the enum change
// routed a load_mfa_row acquire-timeout to StoreBusy, which the mfa_init reuse
// guard's old `== QueryFailed` test missed — letting a transient blip fall
// through to mint-fresh over a provisional/enrolled secret. The guard now gates
// on is_store_unavailable (covers StoreBusy). This proves the SECURITY PROPERTY
// end-to-end: under a store outage, mfa_init_enrollment fails CLOSED and never
// overwrites the stored secret. (Full pool saturation is caught at the mfa_status
// pre-read, itself a StoreBusy site post-#2396; the reuse guard's StoreBusy
// coverage additionally rests on is_store_unavailable — the mapping test above —
// and on the break_load_mfa_row_only QueryFailed guard test below.)
TEST_CASE("AuthDB mfa_init_enrollment fails closed on a store outage, never overwrites the "
          "secret (#2396)",
          "[pg][auth_db][degrade][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("busymfa", "h", "s", yuzu::server::auth::Role::user).has_value());

    // Mint a provisional secret with the pool free.
    REQUIRE(h.db.mfa_init_enrollment("busymfa", "Yuzu").has_value());
    const std::string before = read_secret_hex(h.conn.get(), "busymfa");
    REQUIRE_FALSE(before.empty());

    // Saturate the pool, then re-init: it must fail CLOSED as a store-unavailable
    // outcome (never a fresh mint), leaving the provisional secret byte-identical.
    std::vector<PgPool::Lease> held;
    for (int i = 0; i < 4; ++i) {
        auto lease = h.pool.try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        held.push_back(std::move(lease));
    }
    auto reinit = h.db.mfa_init_enrollment("busymfa", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    CHECK(yuzu::server::is_store_unavailable(reinit.error()));

    held.clear();
    CHECK(read_secret_hex(h.conn.get(), "busymfa") == before);
}

TEST_CASE("AuthDB MFA: a genuinely NOT-enrolled user still verifies as a plain false",
          "[pg][auth_db][secrets]") {
    // Guard against over-correcting HIGH #1: only the ENROLLED-with-no-secret
    // state is SecretUnavailable. A user who never enrolled must stay an
    // ordinary `false`, or every non-MFA login would start 503-ing.
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("noenroll", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto login = h.db.mfa_verify_login_code("noenroll", "123456");
    REQUIRE(login.has_value());
    CHECK(*login == false);
}

TEST_CASE("AuthDB MFA fail-closed: mfa_init_enrollment never mints a fresh secret over a "
          "corrupted provisional one",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt2", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt2", "Yuzu");
    REQUIRE(init.has_value());

    corrupt_secret(h.conn.get(), "corrupt2");
    auto corrupted_hex = read_secret_hex(h.conn.get(), "corrupt2");

    auto reinit = h.db.mfa_init_enrollment("corrupt2", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    CHECK(reinit.error() == AuthDBError::SecretUnavailable);

    // The stored bytes must be UNCHANGED — no fresh secret was minted over
    // the corrupted one.
    auto after_hex = read_secret_hex(h.conn.get(), "corrupt2");
    CHECK(after_hex == corrupted_hex);
}

TEST_CASE("AuthDB MFA fail-closed: mfa_verify_enrollment refuses a corrupted provisional secret",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt3", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt3", "Yuzu");
    REQUIRE(init.has_value());
    corrupt_secret(h.conn.get(), "corrupt3");

    auto verify = h.db.mfa_verify_enrollment("corrupt3", "123456");
    REQUIRE_FALSE(verify.has_value());
    CHECK(verify.error() == AuthDBError::SecretUnavailable);

    // The row must still read as NOT enrolled (the stamp never ran) —
    // mfa_status's documented contract only attempts to decrypt for an
    // ENROLLED row (mfa_enrolled_at set); a corrupted PROVISIONAL secret on
    // a not-yet-enrolled row is irrelevant to it (see auth_db.hpp's
    // mfa_status doc comment: "a provisional secret, if any, does not
    // count"). It must NOT surface SecretUnavailable here.
    auto status = h.db.mfa_status("corrupt3");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
}

#endif // YUZU_TEST_ENABLE_PG
