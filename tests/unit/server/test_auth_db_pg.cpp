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
#include "test_auth_db_pg_helper.hpp" // wait_for_pg_lock_waiter

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <expected>
#include <optional>
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

// AuthDB has NO credential-write method (#5342 Gate 8): an existing row's
// password_hash is written only by CredentialChangeOwner, in one transaction
// with the account's sessions, provisional MFA, lockout and audit row(s) —
// covered in test_auth_password.cpp / test_rest_password_routes.cpp.

TEST_CASE("AuthDB::recheck_role_locked hands the current password_hash to the callback (#5274)",
          "[pg][auth_db][password]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("rr", "h0", "s0", yuzu::server::auth::Role::admin).has_value());
    std::string seen_hash;
    yuzu::server::auth::Role seen_role = yuzu::server::auth::Role::user;
    REQUIRE(h.db.recheck_role_locked("rr", [&](yuzu::server::auth::Role r, const std::string& hh) {
                    seen_role = r;
                    seen_hash = hh;
                }).has_value());
    CHECK(seen_role == yuzu::server::auth::Role::admin);
    CHECK(seen_hash == "h0");
    // A committed credential change (a plain UPDATE stands in for the owner's).
    PgResult upd{PQexec(h.conn.get(),
                        "UPDATE auth.users SET password_hash = 'h1', salt_hex = 's1' "
                        "WHERE username = 'rr'")};
    REQUIRE(upd.ok());
    REQUIRE(h.db.recheck_role_locked("rr", [&](yuzu::server::auth::Role, const std::string& hh) {
                    seen_hash = hh;
                }).has_value());
    CHECK(seen_hash == "h1");
}

// #5342 Gate 8 (F2): an enrolment bound to the credential the caller proved.
TEST_CASE("AuthDB::mfa_verify_enrollment binds to the proven credential (CredentialChanged)",
          "[pg][auth_db][password][mfa]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("bind", "h0", "s0", yuzu::server::auth::Role::user).has_value());
    auto init = h.db.mfa_init_enrollment("bind", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto raw = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw.has_value());
    const auto code = yuzu::server::mfa::generate(
        std::string_view(reinterpret_cast<const char*>(raw->data()), raw->size()),
        yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));

    // The stored hash is no longer the one the caller proved → refused, not
    // enrolled, and graded as a business outcome (never a store fault).
    auto stale = h.db.mfa_verify_enrollment("bind", code, std::string("not-h0"));
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == AuthDBError::CredentialChanged);
    CHECK_FALSE(yuzu::server::is_store_unavailable(AuthDBError::CredentialChanged));
    CHECK_FALSE(h.db.mfa_status("bind")->enrolled);

    // The proven credential still stored → enrols.
    auto ok = h.db.mfa_verify_enrollment("bind", code, std::string("h0"));
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 10);
    CHECK(h.db.mfa_status("bind")->enrolled);
}

namespace {

std::string totp_for(const std::string& secret_b32) {
    auto raw = yuzu::server::mfa::base32_decode(secret_b32);
    REQUIRE(raw.has_value());
    return yuzu::server::mfa::generate(
        std::string_view(reinterpret_cast<const char*>(raw->data()), raw->size()),
        yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));
}

} // namespace

// #5342 Gate 8 (F4): the mint is anchored to the credential the caller proved.
TEST_CASE("AuthDB::mfa_init_enrollment binds to the proven credential (CredentialChanged)",
          "[pg][auth_db][password][mfa]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("ibind", "h0", "s0", yuzu::server::auth::Role::user).has_value());

    // A proven hash that is no longer the stored one → refused BEFORE any mint.
    auto stale = h.db.mfa_init_enrollment("ibind", "Yuzu", std::string("not-h0"));
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == AuthDBError::CredentialChanged);
    CHECK(read_secret_hex(h.conn.get(), "ibind").empty()); // mfa_totp_secret IS NULL

    // The proven credential still stored → mints.
    auto ok = h.db.mfa_init_enrollment("ibind", "Yuzu", std::string("h0"));
    REQUIRE(ok.has_value());
    CHECK_FALSE(read_secret_hex(h.conn.get(), "ibind").empty());

    // ...and a stale anchor also refuses the REUSE reveal of that secret.
    auto stale_reveal = h.db.mfa_init_enrollment("ibind", "Yuzu", std::string("not-h0"));
    REQUIRE_FALSE(stale_reveal.has_value());
    CHECK(stale_reveal.error() == AuthDBError::CredentialChanged);
}

// #5342 Gate 8 (F4): the guarded mint's `mfa_totp_secret IS NULL AND
// mfa_enrolled_at IS NULL` pair. A mint that read "no secret" and then queued on
// the row lock behind a writer that stored one must never overwrite it.
TEST_CASE("AuthDB::mfa_init_enrollment never overwrites a secret written while its mint waited",
          "[pg][auth_db][password][mfa]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("irace", "h0", "s0", yuzu::server::auth::Role::user).has_value());
    // A genuine encrypted blob for this row (SecretId AAD = this row's id),
    // then back to "no secret" so the racing init reads NULL.
    auto first = h.db.mfa_init_enrollment("irace", "Yuzu", std::nullopt);
    REQUIRE(first.has_value());
    const std::string blob = read_secret_hex(h.conn.get(), "irace");
    REQUIRE_FALSE(blob.empty());
    {
        PgResult n{PQexec(h.conn.get(),
                          "UPDATE auth.users SET mfa_totp_secret = NULL WHERE username = 'irace'")};
        REQUIRE(n.ok());
    }

    std::string writer_sql;
    SECTION("a concurrent init's provisional secret is re-revealed, not rotated") {
        writer_sql = "UPDATE auth.users SET mfa_totp_secret = decode('" + blob +
                     "','hex') WHERE username = 'irace'";
    }
    SECTION("a just-enrolled secret is MfaAlreadyEnrolled, not overwritten") {
        writer_sql = "UPDATE auth.users SET mfa_totp_secret = decode('" + blob +
                     "','hex'), mfa_enrolled_at = now() WHERE username = 'irace'";
    }
    const bool enrolled_case = writer_sql.find("mfa_enrolled_at") != std::string::npos;

    PgConn locker = connect(db.dsn());
    { PgResult b{PQexec(locker.get(), "BEGIN")}; REQUIRE(b.ok()); }
    { PgResult u{PQexec(locker.get(), writer_sql.c_str())}; REQUIRE(u.ok()); }
    std::optional<std::expected<AuthDB::MfaEnrollmentInit, AuthDBError>> racing;
    {
        std::jthread initer(
            [&] { racing = h.db.mfa_init_enrollment("irace", "Yuzu", std::nullopt); });
        const bool waited = yuzu::test::wait_for_pg_lock_waiter(
            db.dsn(), "%UPDATE auth.users SET mfa_totp_secret%");
        PgResult c{PQexec(locker.get(), "COMMIT")};
        CHECK(c.ok());
        CHECK(waited);
    } // jthread joins here
    REQUIRE(racing.has_value());
    CHECK(read_secret_hex(h.conn.get(), "irace") == blob); // never overwritten
    if (enrolled_case) {
        REQUIRE_FALSE(racing->has_value());
        CHECK(racing->error() == AuthDBError::MfaAlreadyEnrolled);
    } else {
        REQUIRE(racing->has_value());
        CHECK((*racing)->secret_base32 == first->secret_base32); // the stored secret, revealed
    }
}

TEST_CASE("AuthDB::mfa_verify_enrollment with no expected hash anchors to the hash read in the "
          "same call (Settings)",
          "[pg][auth_db][password][mfa]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    SECTION("a change BEFORE the call is honoured") {
        REQUIRE(h.db.upsert_user("sett", "h0", "s0", yuzu::server::auth::Role::user).has_value());
        auto init = h.db.mfa_init_enrollment("sett", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        // A committed credential change between init and verify (a plain UPDATE
        // stands in for the owner's) — the verify reads h1 and anchors to it.
        PgResult upd{PQexec(h.conn.get(),
                            "UPDATE auth.users SET password_hash = 'h1' WHERE username = 'sett'")};
        REQUIRE(upd.ok());
        auto ok = h.db.mfa_verify_enrollment("sett", totp_for(init->secret_base32), std::nullopt);
        REQUIRE(ok.has_value());
        CHECK(h.db.mfa_status("sett")->enrolled);
    }

    SECTION("a change DURING the call is CredentialChanged") {
        REQUIRE(h.db.upsert_user("sett2", "h0", "s0", yuzu::server::auth::Role::user).has_value());
        auto init = h.db.mfa_init_enrollment("sett2", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        const auto code = totp_for(init->secret_base32);

        // A second connection holds the row lock with an UNCOMMITTED credential
        // change; the verify reads the committed h0, then its guarded UPDATE
        // waits on the lock and re-evaluates against the committed h1.
        PgConn locker = connect(db.dsn());
        { PgResult b{PQexec(locker.get(), "BEGIN")}; REQUIRE(b.ok()); }
        {
            PgResult u{PQexec(locker.get(),
                              "UPDATE auth.users SET password_hash = 'h1' WHERE username = 'sett2'")};
            REQUIRE(u.ok());
        }
        std::optional<std::expected<std::vector<std::string>, AuthDBError>> during;
        {
            std::jthread verifier(
                [&] { during = h.db.mfa_verify_enrollment("sett2", code, std::nullopt); });
            const bool waited = yuzu::test::wait_for_pg_lock_waiter(
                db.dsn(), "%UPDATE auth.users SET mfa_enrolled_at%");
            PgResult c{PQexec(locker.get(), "COMMIT")};
            CHECK(c.ok());
            CHECK(waited);
        } // jthread joins here
        REQUIRE(during.has_value());
        REQUIRE_FALSE(during->has_value());
        CHECK(during->error() == AuthDBError::CredentialChanged);
        CHECK_FALSE(h.db.mfa_status("sett2")->enrolled);
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

// ── enrollment tokens + pending agents (WS-6 slice 6.2) ─────────────────────

namespace {

using yuzu::server::StoreError;
using CEK = yuzu::server::AuthDB::ConsumeEnrollResult::Kind;
using yuzu::server::auth::EnrollmentTokenError;
using yuzu::server::auth::PendingAgent;
using yuzu::server::auth::PendingStatus;
using yuzu::server::auth::RemovePendingOutcome;

PendingAgent mk_agent(const std::string& id, const std::string& host = "host") {
    PendingAgent a;
    a.agent_id = id;
    a.hostname = host;
    a.os = "linux";
    a.arch = "x86_64";
    a.agent_version = "1.0.0";
    a.status = PendingStatus::pending;
    return a;
}

/// Runs one param-less/param'd statement on the harness' side connection and
/// returns the first cell ("" for NULL / no rows).
std::string scalar(PGconn* conn, const char* sql, const std::vector<std::string>& params = {}) {
    std::vector<const char*> v;
    for (const auto& p : params)
        v.push_back(p.c_str());
    PgResult res{PQexecParams(conn, sql, static_cast<int>(v.size()), nullptr,
                              v.empty() ? nullptr : v.data(), nullptr, nullptr, 0)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    if (PQntuples(res.get()) == 0 || PQgetisnull(res.get(), 0, 0))
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

std::string make_token(AuthDB& db, int max_uses, std::chrono::seconds ttl = std::chrono::seconds(3600),
                       const std::string& label = "t") {
    auto t = db.create_token(label, max_uses, ttl, "admin");
    REQUIRE(t.has_value());
    return t->raw_token;
}

} // namespace

TEST_CASE("AuthDB enrollment token lifecycle: create, consume, exhaust, list", "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto created = h.db.create_token("NYC rollout", 1, std::chrono::seconds(3600), "admin");
    REQUIRE(created.has_value());
    CHECK(created->raw_token.size() == 64);
    CHECK(created->token_id.size() == 8);

    // Only the hash is stored — never the raw token.
    CHECK(scalar(h.conn.get(), "SELECT count(*) FROM auth.enrollment_tokens WHERE token_hash = $1",
                 {created->raw_token}) == "0");

    auto first = h.db.consume_and_enroll(created->raw_token, "agent-1", "host1", "linux", "x86_64", "1.0");
    REQUIRE(first.has_value());
    REQUIRE(first->kind == CEK::enrolled);
    CHECK(first->claim.token_id == created->token_id);
    CHECK(first->claim.max_uses == 1);
    CHECK(first->claim.use_count_after == 1);
    CHECK(first->claim.single_use);

    auto st = h.db.pending_status("agent-1");
    REQUIRE(st.has_value());
    REQUIRE(st->has_value());
    CHECK(**st == PendingStatus::approved);
    CHECK(scalar(h.conn.get(), "SELECT status_changed_by FROM auth.pending_agents WHERE agent_id='agent-1'") ==
          "token:" + created->token_id);

    // Exhausted: classified already_consumed and names the winner.
    auto second = h.db.consume_and_enroll(created->raw_token, "agent-2", "host2", "linux", "x86_64", "1.0");
    REQUIRE(second.has_value());
    CHECK(second->kind == CEK::token_rejected);
    CHECK(second->token_error == EnrollmentTokenError::already_consumed);
    CHECK(second->already_consumed_by == "agent-1");
    // The loser was NOT enrolled.
    auto st2 = h.db.pending_status("agent-2");
    REQUIRE(st2.has_value());
    CHECK_FALSE(st2->has_value());

    auto tokens = h.db.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK((*tokens)[0].label == "NYC rollout");
    CHECK((*tokens)[0].use_count == 1);
    CHECK((*tokens)[0].last_consumed_by_agent_id == "agent-1");
    CHECK_FALSE((*tokens)[0].revoked);
    CHECK((*tokens)[0].expires_at > std::chrono::system_clock::now());
}

TEST_CASE("AuthDB enrollment token: unlimited uses and never-expires", "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    auto created = h.db.create_token("forever", 0, std::chrono::seconds(0), "admin");
    REQUIRE(created.has_value());
    for (int i = 0; i < 5; ++i) {
        auto r = h.db.consume_and_enroll(created->raw_token, "a" + std::to_string(i), "h", "", "", "");
        REQUIRE(r.has_value());
        CHECK(r->kind == CEK::enrolled);
        CHECK_FALSE(r->claim.single_use);
    }
    auto tokens = h.db.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK((*tokens)[0].use_count == 5);
    CHECK((*tokens)[0].expires_at == (std::chrono::system_clock::time_point::max)());
    CHECK(scalar(h.conn.get(), "SELECT expires_at IS NULL FROM auth.enrollment_tokens") == "t");
}

TEST_CASE("AuthDB consume_and_enroll classifies each miss reason", "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    // not_found
    auto nf = h.db.consume_and_enroll(std::string(64, 'a'), "agent-x", "h", "", "", "");
    REQUIRE(nf.has_value());
    CHECK(nf->kind == CEK::token_rejected);
    CHECK(nf->token_error == EnrollmentTokenError::not_found);

    // revoked
    auto rev = h.db.create_token("r", 1, std::chrono::seconds(3600), "admin");
    REQUIRE(rev.has_value());
    CHECK(h.db.revoke_token(rev->token_id).value());
    CHECK(h.db.revoke_token(rev->token_id).value()); // idempotent
    CHECK_FALSE(h.db.revoke_token("deadbeef").value());
    auto r1 = h.db.consume_and_enroll(rev->raw_token, "agent-r", "h", "", "", "");
    REQUIRE(r1.has_value());
    CHECK(r1->token_error == EnrollmentTokenError::revoked);

    // expired — evaluated by the DB clock in SQL: push expires_at into the PG past.
    auto exp = h.db.create_token("e", 1, std::chrono::seconds(3600), "admin");
    REQUIRE(exp.has_value());
    scalar(h.conn.get(),
           "WITH u AS (UPDATE auth.enrollment_tokens SET expires_at = now() - interval '1 second' "
           "WHERE token_id = $1 RETURNING 1) SELECT count(*) FROM u",
           {exp->token_id});
    auto e1 = h.db.consume_and_enroll(exp->raw_token, "agent-e", "h", "", "", "");
    REQUIRE(e1.has_value());
    CHECK(e1->kind == CEK::token_rejected);
    CHECK(e1->token_error == EnrollmentTokenError::expired);

    // No miss enrolled anyone.
    auto all = h.db.list_pending();
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

TEST_CASE("AuthDB consume_and_enroll: admin-denied agent rolls the token use back",
          "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto tok = h.db.create_token("t", 1, std::chrono::seconds(3600), "admin");
    REQUIRE(tok.has_value());
    REQUIRE(h.db.add_pending(mk_agent("evil")).value());
    REQUIRE(h.db.deny_pending("evil", "alice").value());

    // An attempted removal of the denied row is REFUSED (Fix 1) — the denial
    // holds, so the token below still cannot re-enroll the agent.
    CHECK(h.db.remove_pending("evil").value() == RemovePendingOutcome::wrong_status);
    CHECK(**h.db.pending_status("evil") == PendingStatus::denied);

    auto r = h.db.consume_and_enroll(tok->raw_token, "evil", "h", "", "", "");
    REQUIRE(r.has_value());
    CHECK(r->kind == CEK::admin_denied);

    // ROLLBACK, not a refund: use_count and last_consumer are exactly as created.
    auto tokens = h.db.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK((*tokens)[0].use_count == 0);
    CHECK((*tokens)[0].last_consumed_by_agent_id.empty());
    CHECK(scalar(h.conn.get(), "SELECT last_used_at IS NULL FROM auth.enrollment_tokens") == "t");
    // The denied row stays denied.
    CHECK(**h.db.pending_status("evil") == PendingStatus::denied);

    // The single use is still available to a legitimate agent.
    auto ok = h.db.consume_and_enroll(tok->raw_token, "good", "h", "", "", "");
    REQUIRE(ok.has_value());
    CHECK(ok->kind == CEK::enrolled);
}

namespace {
/// Fires `threads` concurrent consume_and_enroll calls (each its own agent_id and
/// its own pooled connection) at ONE token and returns {enrolled, rejected, other}.
struct RaceTally {
    int enrolled{0};
    int rejected{0};
    int other{0};
};
RaceTally race(AuthDB& db, const std::string& raw, int threads) {
    std::atomic<bool> go{false};
    std::vector<int> outcome(static_cast<std::size_t>(threads), -1);
    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back([&, i] {
            while (!go.load()) {
                std::this_thread::yield();
            }
            auto r = db.consume_and_enroll(raw, "race-" + std::to_string(i), "h", "", "", "");
            outcome[static_cast<std::size_t>(i)] =
                !r.has_value() ? 2 : (r->kind == CEK::enrolled ? 0 : 1);
        });
    }
    go.store(true);
    for (auto& t : pool)
        t.join();
    RaceTally t;
    for (int o : outcome)
        (o == 0 ? t.enrolled : o == 1 ? t.rejected : t.other)++;
    return t;
}
} // namespace

TEST_CASE("AuthDB consume_and_enroll: exactly one winner for max_uses=1 across connections",
          "[pg][auth_db][enrollment][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    PgPool pool{PgPool::Options{.conninfo = db.dsn(), .size = 16}};
    AuthDB adb(pool, codec);
    REQUIRE(adb.is_open());

    const std::string raw = make_token(adb, 1);
    const auto t = race(adb, raw, 16);
    CHECK(t.other == 0);
    CHECK(t.enrolled == 1);
    CHECK(t.rejected == 15);
    CHECK(adb.list_tokens().value()[0].use_count == 1);
    CHECK(adb.list_pending(PendingStatus::approved).value().size() == 1);
}

TEST_CASE("AuthDB consume_and_enroll: exactly N winners for max_uses=N across connections",
          "[pg][auth_db][enrollment][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn = connect(db.dsn());
    REQUIRE(codec.init(conn.get()).has_value());
    PgPool pool{PgPool::Options{.conninfo = db.dsn(), .size = 16}};
    AuthDB adb(pool, codec);
    REQUIRE(adb.is_open());

    const std::string raw = make_token(adb, 5);
    const auto t = race(adb, raw, 16);
    CHECK(t.other == 0);
    CHECK(t.enrolled == 5);
    CHECK(t.rejected == 11);
    CHECK(adb.list_tokens().value()[0].use_count == 5);
    CHECK(adb.list_pending(PendingStatus::approved).value().size() == 5);
}

TEST_CASE("AuthDB create_token regenerates on a token_id collision, never overwriting",
          "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    const std::vector<std::uint8_t> fixed(32, 0x11);
    const std::vector<std::uint8_t> other(32, 0x22);
    auto a = h.db.create_token_with_entropy("first", 3, std::chrono::seconds(60), "admin",
                                            [&] { return fixed; });
    REQUIRE(a.has_value());

    // Second call is handed the SAME entropy first (=> identical hash/token_id,
    // a 23505), then fresh entropy: it must regenerate, not fail and not clobber.
    int calls = 0;
    auto b = h.db.create_token_with_entropy("second", 7, std::chrono::seconds(60), "admin", [&] {
        return (calls++ == 0) ? fixed : other;
    });
    REQUIRE(b.has_value());
    CHECK(calls == 2);
    CHECK(b->raw_token != a->raw_token);
    CHECK(b->token_id != a->token_id);

    auto tokens = h.db.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 2);
    for (const auto& t : *tokens) {
        if (t.token_id == a->token_id) {
            CHECK(t.label == "first");
            CHECK(t.max_uses == 3);
        } else {
            CHECK(t.label == "second");
            CHECK(t.max_uses == 7);
        }
    }

    // Persistent collision (entropy never changes) fails closed after bounded attempts.
    auto c = h.db.create_token_with_entropy("third", 1, std::chrono::seconds(60), "admin",
                                            [&] { return fixed; });
    REQUIRE_FALSE(c.has_value());
    CHECK(c.error() == StoreError::QueryFailed);
    CHECK(h.db.list_tokens().value().size() == 2);
}

TEST_CASE("AuthDB enrollment store rejects out-of-bounds input", "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    const auto secs = std::chrono::seconds(60);
    const std::string nul{"a\0b", 3};
    const std::string big(yuzu::server::AuthDB::kMaxEnrollmentTextLength + 1, 'x');

    auto bad = [](const auto& r) { return !r.has_value() && r.error() == StoreError::InvalidInput; };
    CHECK(bad(h.db.create_token(nul, 1, secs, "admin")));
    CHECK(bad(h.db.create_token(big, 1, secs, "admin")));
    CHECK(bad(h.db.create_token("l", -1, secs, "admin")));
    CHECK(bad(h.db.create_token("l", 1, std::chrono::seconds(-1), "admin")));
    CHECK(bad(h.db.create_token("l", 1, std::chrono::seconds(yuzu::server::AuthDB::kMaxEnrollmentTtlSeconds + 1), "admin")));
    CHECK(bad(h.db.create_token("l", 1, secs, "")));

    const std::string tok(64, 'a');
    CHECK(bad(h.db.consume_and_enroll("", "a", "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(std::string(300, 'a'), "a", "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(std::string{"ab\0cd", 5}, "a", "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, "", "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, std::string(yuzu::server::auth::kMaxAgentIdLength + 1, 'a'), "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, nul, "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, "a", nul, "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, "a", "h", big, "", "")));
    CHECK(bad(h.db.add_pending(mk_agent("a", nul))));
    CHECK(bad(h.db.add_pending(mk_agent(""))));
    CHECK(bad(h.db.pending_status(nul)));
    CHECK(bad(h.db.approve_pending("a", "")));
    CHECK(bad(h.db.deny_pending("a", nul)));
    CHECK(bad(h.db.approve_all_pending("")));
    CHECK(bad(h.db.remove_pending("")));
    CHECK(bad(h.db.revoke_token("")));

    // agent_id charset (Fix 3, #compliance-officer Finding 2 / UP-3): a comma
    // would corrupt the comma-joined bulk_audit_detail list; \n/\r could forge
    // additional lines in a plain-string audit detail. Rejected everywhere
    // agent_id reaches the store, not just at one call site.
    CHECK(bad(h.db.add_pending(mk_agent("agent,evil"))));
    CHECK(bad(h.db.add_pending(mk_agent("agent\nevil"))));
    CHECK(bad(h.db.add_pending(mk_agent("agent\revil"))));
    CHECK(bad(h.db.pending_status("agent,evil")));
    CHECK(bad(h.db.approve_pending("agent,evil", "alice")));
    CHECK(bad(h.db.deny_pending("agent\nevil", "alice")));
    CHECK(bad(h.db.remove_pending("agent,evil")));
    CHECK(bad(h.db.consume_and_enroll(tok, "agent,evil", "h", "", "", "")));
    CHECK(bad(h.db.consume_and_enroll(tok, "agent\nevil", "h", "", "", "")));

    // Legitimate agent_id shapes (UUID, hostname-derived with dots/hyphens)
    // still pass — the guard is not over-restrictive.
    REQUIRE(h.db.add_pending(mk_agent("550e8400-e29b-41d4-a716-446655440000")).value());
    REQUIRE(h.db.add_pending(mk_agent("host-01.example.com")).value());

    // None of the rejected calls reached the tables (beyond the two valid
    // adds just made above).
    CHECK(h.db.list_tokens().value().empty());
    CHECK(h.db.list_pending().value().size() == 2);
}

TEST_CASE("AuthDB pending agents: add, five-state lookup, approve/deny/remove, ensure_enrolled",
          "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    // absent
    auto none = h.db.pending_status("agent-xyz");
    REQUIRE(none.has_value());
    CHECK_FALSE(none->has_value());

    // add_pending: newly-added bool
    CHECK(h.db.add_pending(mk_agent("agent-xyz", "host1")).value() == true);
    CHECK(h.db.add_pending(mk_agent("agent-xyz", "OTHER")).value() == false); // unchanged
    CHECK(scalar(h.conn.get(), "SELECT hostname FROM auth.pending_agents WHERE agent_id='agent-xyz'") == "host1");
    CHECK(**h.db.pending_status("agent-xyz") == PendingStatus::pending);

    // approve records the principal
    CHECK(h.db.approve_pending("agent-xyz", "alice").value());
    CHECK(**h.db.pending_status("agent-xyz") == PendingStatus::approved);
    CHECK(scalar(h.conn.get(), "SELECT status_changed_by FROM auth.pending_agents WHERE agent_id='agent-xyz'") == "alice");
    CHECK_FALSE(h.db.approve_pending("ghost", "alice").value());

    // deny
    REQUIRE(h.db.add_pending(mk_agent("agent-abc", "host2")).value());
    CHECK(h.db.deny_pending("agent-abc", "bob").value());
    CHECK(**h.db.pending_status("agent-abc") == PendingStatus::denied);
    CHECK_FALSE(h.db.deny_pending("ghost", "bob").value());

    // list + filter (newest first, status carried)
    auto all = h.db.list_pending();
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);
    auto only_denied = h.db.list_pending(PendingStatus::denied);
    REQUIRE(only_denied.has_value());
    REQUIRE(only_denied->size() == 1);
    CHECK((*only_denied)[0].agent_id == "agent-abc");
    CHECK((*only_denied)[0].hostname == "host2");
    CHECK((*only_denied)[0].status == PendingStatus::denied);
    CHECK(h.db.list_pending(PendingStatus::pending).value().empty());

    // ensure_enrolled: never overrides a denial; upserts otherwise; keeps the existing row's metadata.
    CHECK_FALSE(h.db.ensure_enrolled(mk_agent("agent-abc"), "system").value());
    CHECK(**h.db.pending_status("agent-abc") == PendingStatus::denied);
    CHECK(h.db.ensure_enrolled(mk_agent("brand-new", "hN"), "system").value());
    CHECK(**h.db.pending_status("brand-new") == PendingStatus::approved);
    REQUIRE(h.db.add_pending(mk_agent("was-pending", "hP")).value());
    CHECK(h.db.ensure_enrolled(mk_agent("was-pending", "IGNORED"), "system").value());
    CHECK(**h.db.pending_status("was-pending") == PendingStatus::approved);
    CHECK(scalar(h.conn.get(), "SELECT hostname FROM auth.pending_agents WHERE agent_id='was-pending'") == "hP");

    // remove: hard delete, but ONLY a still-`pending` row.
    REQUIRE(h.db.add_pending(mk_agent("to-remove", "hR")).value());
    CHECK(h.db.remove_pending("to-remove").value() == RemovePendingOutcome::removed);
    CHECK(h.db.remove_pending("to-remove").value() == RemovePendingOutcome::not_found);
    CHECK_FALSE(h.db.pending_status("to-remove").value().has_value());

    // remove REFUSES a denied row — the denial holds, no silent reversal
    // (governance Finding 1: removing it would delete the very guard
    // kEnrollUpsertSql's `WHERE status <> 'denied'` depends on).
    CHECK(h.db.remove_pending("agent-abc").value() == RemovePendingOutcome::wrong_status);
    CHECK(**h.db.pending_status("agent-abc") == PendingStatus::denied);

    // remove REFUSES an approved row too — no silent deregistration.
    CHECK(h.db.remove_pending("agent-xyz").value() == RemovePendingOutcome::wrong_status);
    CHECK(**h.db.pending_status("agent-xyz") == PendingStatus::approved);
}

TEST_CASE("AuthDB bulk approve/deny transitions only currently-pending rows",
          "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    for (const char* id : {"p1", "p2", "p3", "d1", "a1"})
        REQUIRE(h.db.add_pending(mk_agent(id)).value());
    REQUIRE(h.db.deny_pending("d1", "admin").value());
    REQUIRE(h.db.approve_pending("a1", "admin").value());

    auto approved = h.db.approve_all_pending("carol");
    REQUIRE(approved.has_value());
    std::sort(approved->begin(), approved->end());
    CHECK(*approved == std::vector<std::string>{"p1", "p2", "p3"});
    CHECK(**h.db.pending_status("d1") == PendingStatus::denied); // untouched
    CHECK(scalar(h.conn.get(), "SELECT status_changed_by FROM auth.pending_agents WHERE agent_id='p2'") == "carol");
    CHECK(h.db.approve_all_pending("carol").value().empty()); // nothing left

    REQUIRE(h.db.add_pending(mk_agent("q1")).value());
    REQUIRE(h.db.add_pending(mk_agent("q2")).value());
    auto denied = h.db.deny_all_pending("dave");
    REQUIRE(denied.has_value());
    CHECK(denied->size() == 2);
    CHECK(**h.db.pending_status("q1") == PendingStatus::denied);
    CHECK(**h.db.pending_status("p1") == PendingStatus::approved); // earlier approvals untouched
}

TEST_CASE("AuthDB enrollment store degrade surfaces a typed error, never absent/empty",
          "[pg][auth_db][enrollment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.add_pending(mk_agent("agent-1")).value());

    // Break the store underneath the live AuthDB (a query that RUNS and errors).
    PgResult drop{PQexec(h.conn.get(), "DROP TABLE auth.pending_agents")};
    REQUIRE(drop.ok());

    auto st = h.db.pending_status("agent-1");
    REQUIRE_FALSE(st.has_value()); // ERROR — not nullopt/"absent"
    CHECK(st.error() == StoreError::QueryFailed);
    CHECK(yuzu::server::is_store_unavailable(st.error()));
    CHECK_FALSE(h.db.list_pending().has_value());
    CHECK_FALSE(h.db.add_pending(mk_agent("agent-2")).has_value());
    CHECK_FALSE(h.db.approve_all_pending("admin").has_value());

    // A consume whose step 2 fails must not leave the use counted (txn rolled back).
    auto tok = h.db.create_token("t", 1, std::chrono::seconds(60), "admin");
    REQUIRE(tok.has_value());
    auto c = h.db.consume_and_enroll(tok->raw_token, "agent-3", "h", "", "", "");
    REQUIRE_FALSE(c.has_value());
    CHECK(c.error() == StoreError::QueryFailed);
    CHECK(h.db.list_tokens().value()[0].use_count == 0);
}

// ── v1 -> v2 migration (WS-6 6.2) ───────────────────────────────────────────

// Hand-seeds the v1 `auth` schema (users + the dead v1 enrollment_tokens /
// pending_agents shapes + mfa_recovery_codes) exactly as migrations()[0] created
// it, stamps schema_meta at 1 with a populated v1 row in each dead table, then
// hands the database to a real AuthDB construction. Proves the v2 step drops the
// v1 shapes and creates the clean ones + import_meta, keeps unrelated v1 data,
// and that the resulting store works end-to-end.
TEST_CASE("AuthDB migrates v1 -> v2: clean enrollment/pending shape + import_meta",
          "[pg][auth_db][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn = connect(db.dsn());
        PgResult meta{PQexec(conn.get(), "CREATE TABLE public.schema_meta ("
                                         "  store TEXT PRIMARY KEY, version INTEGER NOT NULL,"
                                         "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA auth")};
        REQUIRE(schema.ok());
        PgResult v1{PQexec(
            conn.get(),
            "CREATE TABLE auth.users ("
            "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
            "  password_hash TEXT NOT NULL DEFAULT '', salt_hex TEXT NOT NULL DEFAULT '',"
            "  role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_login_at TIMESTAMPTZ,"
            "  is_active BOOLEAN NOT NULL DEFAULT TRUE, mfa_totp_secret BYTEA,"
            "  mfa_enrolled_at TIMESTAMPTZ, mfa_disabled_at TIMESTAMPTZ,"
            "  mfa_last_counter BIGINT NOT NULL DEFAULT 0, failed_login_count INTEGER NOT NULL DEFAULT 0,"
            "  last_failed_login_at TIMESTAMPTZ, locked_until TIMESTAMPTZ,"
            "  break_glass_armed_until TIMESTAMPTZ, elevation_eligible BOOLEAN NOT NULL DEFAULT FALSE,"
            "  identity_source TEXT NOT NULL DEFAULT 'local', external_iss TEXT, external_sub TEXT,"
            "  display_name TEXT, last_seen_at TIMESTAMPTZ,"
            "  provisioning_source TEXT NOT NULL DEFAULT 'local');"
            "CREATE INDEX users_active_idx ON auth.users (is_active) WHERE is_active;"
            "CREATE TABLE auth.enrollment_tokens ("
            "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,"
            "  created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  expires_at TIMESTAMPTZ NOT NULL, is_used BOOLEAN NOT NULL DEFAULT FALSE,"
            "  used_at TIMESTAMPTZ, used_by_agent_id TEXT);"
            "CREATE INDEX enrollment_tokens_expires_idx ON auth.enrollment_tokens (expires_at);"
            "CREATE TABLE auth.pending_agents ("
            "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, agent_id TEXT NOT NULL UNIQUE,"
            "  hostname TEXT NOT NULL, os TEXT, arch TEXT, agent_version TEXT,"
            "  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(), approved_at TIMESTAMPTZ,"
            "  approved_by TEXT, status TEXT NOT NULL DEFAULT 'pending');"
            "CREATE INDEX pending_agents_status_idx ON auth.pending_agents (status);"
            "CREATE TABLE auth.mfa_recovery_codes ("
            "  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, username TEXT NOT NULL,"
            "  code_hash TEXT NOT NULL, code_salt TEXT NOT NULL, consumed_at TIMESTAMPTZ,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now());"
            "CREATE INDEX mfa_recovery_username_idx ON auth.mfa_recovery_codes (username);"
            "CREATE INDEX mfa_recovery_unconsumed_idx ON auth.mfa_recovery_codes (username) "
            "  WHERE consumed_at IS NULL;"
            "INSERT INTO public.schema_meta (store, version, upgraded_at) "
            "  VALUES ('auth', 1, extract(epoch FROM now())::bigint);"
            "INSERT INTO auth.users (username, password_hash, salt_hex, role) "
            "  VALUES ('legacy-admin', 'h', 's', 'admin');"
            "INSERT INTO auth.enrollment_tokens (token_hash, created_by, expires_at) "
            "  VALUES ('v1-dead-row', 'x', now() + interval '1 day');"
            "INSERT INTO auth.pending_agents (agent_id, hostname) VALUES ('v1-dead-agent', 'h');")};
        REQUIRE(v1.ok());
    }

    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    {
        PgConn conn = connect(db.dsn());
        REQUIRE(codec.init(conn.get()).has_value());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AuthDB adb{pool, codec};
    REQUIRE(adb.is_open()); // the v2 step applied

    PgConn conn = connect(db.dsn());
    CHECK(scalar(conn.get(), "SELECT version FROM public.schema_meta WHERE store='auth'") == "2");

    // v1 dead shapes gone, clean shape present (no `is_used`, has `max_uses`/`token_id`).
    CHECK(scalar(conn.get(), "SELECT count(*) FROM auth.enrollment_tokens") == "0");
    CHECK(scalar(conn.get(), "SELECT count(*) FROM auth.pending_agents") == "0");
    CHECK(scalar(conn.get(),
                 "SELECT count(*) FROM information_schema.columns WHERE table_schema='auth' "
                 "AND table_name='enrollment_tokens' AND column_name IN "
                 "('token_id','label','max_uses','use_count','revoked','last_used_at',"
                 " 'last_consumed_by_agent_id')") == "7");
    CHECK(scalar(conn.get(),
                 "SELECT count(*) FROM information_schema.columns WHERE table_schema='auth' "
                 "AND table_name='enrollment_tokens' AND column_name IN ('is_used','used_at')") == "0");
    CHECK(scalar(conn.get(),
                 "SELECT count(*) FROM information_schema.columns WHERE table_schema='auth' "
                 "AND table_name='pending_agents' AND column_name IN "
                 "('status_changed_at','status_changed_by')") == "2");
    CHECK(scalar(conn.get(),
                 "SELECT count(*) FROM information_schema.columns WHERE table_schema='auth' "
                 "AND table_name='import_meta' AND column_name IN "
                 "('key','fingerprint','imported_at','imported_by')") == "4");
    // Unrelated v1 data survives.
    CHECK(scalar(conn.get(), "SELECT role FROM auth.users WHERE username='legacy-admin'") == "admin");

    // DB-level guards on the clean shape.
    PgResult neg{PQexec(conn.get(), "INSERT INTO auth.enrollment_tokens (token_id, token_hash, max_uses) "
                                    "VALUES ('x','y',-1)")};
    CHECK_FALSE(neg.ok());
    PgResult bad_status{PQexec(conn.get(), "INSERT INTO auth.pending_agents (agent_id, status) "
                                           "VALUES ('z','rejected')")};
    CHECK_FALSE(bad_status.ok());

    // And the migrated store works end to end.
    auto tok = adb.create_token("post-upgrade", 1, std::chrono::seconds(60), "admin");
    REQUIRE(tok.has_value());
    auto r = adb.consume_and_enroll(tok->raw_token, "agent-up", "h", "", "", "");
    REQUIRE(r.has_value());
    CHECK(r->kind == CEK::enrolled);
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

    auto init = h.db.mfa_init_enrollment("mfauser", "Yuzu", std::nullopt);
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
    auto init2 = h.db.mfa_init_enrollment("mfauser", "Yuzu", std::nullopt);
    REQUIRE(init2.has_value());
    CHECK(init2->secret_base32 == init->secret_base32);

    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto now = std::chrono::system_clock::now();
    auto counter = yuzu::server::mfa::current_counter(now);
    auto code = yuzu::server::mfa::generate(secret_view, counter);

    auto verify = h.db.mfa_verify_enrollment("mfauser", code, std::nullopt);
    REQUIRE(verify.has_value());
    CHECK(verify->size() == 10);

    // Enrolling twice is rejected.
    auto redo = h.db.mfa_init_enrollment("mfauser", "Yuzu", std::nullopt);
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

    auto init = h.db.mfa_init_enrollment("enrollrace", "Yuzu", std::nullopt);
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
        auto r = h.db.mfa_verify_enrollment("enrollrace", code, std::nullopt);
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
        auto init = h.db.mfa_init_enrollment("reenroll", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto raw = yuzu::server::mfa::base32_decode(init->secret_base32);
        REQUIRE(raw.has_value());
        auto sv = std::string_view(reinterpret_cast<const char*>(raw->data()), raw->size());
        auto code = yuzu::server::mfa::generate(
            sv, yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));
        auto verify = h.db.mfa_verify_enrollment("reenroll", code, std::nullopt);
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

    auto init = h.db.mfa_init_enrollment("racer", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    // Complete enrollment at `counter`; the login code is the NEXT step so the
    // enrollment counter's own replay protection does not reject it.
    REQUIRE(h.db.mfa_verify_enrollment("racer", yuzu::server::mfa::generate(secret_view, counter), std::nullopt)
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

    auto init = h.db.mfa_init_enrollment("corrupt1", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    auto code = yuzu::server::mfa::generate(secret_view, counter);
    REQUIRE(h.db.mfa_verify_enrollment("corrupt1", code, std::nullopt).has_value());

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

    auto init = h.db.mfa_init_enrollment("nullsec1", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    REQUIRE(h.db.mfa_verify_enrollment("nullsec1", yuzu::server::mfa::generate(secret_view, counter), std::nullopt)
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

    auto init = h.db.mfa_init_enrollment("qfail1", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto before_hex = read_secret_hex(h.conn.get(), "qfail1");
    REQUIRE_FALSE(before_hex.empty());

    break_load_mfa_row_only(h.conn.get());

    // Before the fix the failed statement returned the same empty answer as
    // "no provisional secret", and this call minted a FRESH secret over the
    // live one — silently invalidating a QR the operator had already scanned.
    auto reinit = h.db.mfa_init_enrollment("qfail1", "Yuzu", std::nullopt);
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
    REQUIRE(h.db.mfa_init_enrollment("qfail2", "Yuzu", std::nullopt).has_value());

    break_load_mfa_row_only(h.conn.get());

    // A 404-shaped UserNotFound would tell the caller "enroll first" and burn
    // the in-progress enrollment; the caller needs a 503-shaped retry.
    auto verify = h.db.mfa_verify_enrollment("qfail2", "123456", std::nullopt);
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
    REQUIRE(h.db.mfa_init_enrollment("busymfa", "Yuzu", std::nullopt).has_value());
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
    auto reinit = h.db.mfa_init_enrollment("busymfa", "Yuzu", std::nullopt);
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

    auto init = h.db.mfa_init_enrollment("corrupt2", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());

    corrupt_secret(h.conn.get(), "corrupt2");
    auto corrupted_hex = read_secret_hex(h.conn.get(), "corrupt2");

    auto reinit = h.db.mfa_init_enrollment("corrupt2", "Yuzu", std::nullopt);
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

    auto init = h.db.mfa_init_enrollment("corrupt3", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    corrupt_secret(h.conn.get(), "corrupt3");

    auto verify = h.db.mfa_verify_enrollment("corrupt3", "123456", std::nullopt);
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
