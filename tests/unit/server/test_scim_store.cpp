/**
 * test_scim_store.cpp — AuthDB-side tests for the SCIM v2 provisioning
 * surface: the v7 `provisioning_source` column, `set_identity_source`, and
 * `reactivate_user`. None of these exercise `ScimStore` (they construct
 * `AuthDB` directly) — kept in this file for historical reasons (the PR
 * that added SCIM provisioning added them here alongside the ScimStore
 * tests).
 *
 * ScimStore itself is a born-on-Postgres store (ADR-0006, schema
 * `scim_store`) — its unit tests live in `test_scim_store_pg.cpp`, which
 * uses `PgTestTemplate`/`YUZU_REQUIRE_PG_DB[_TPL]`. The former "opens a
 * second connection to the same auth.db AuthDB owns" coexistence test no
 * longer applies — ScimStore no longer shares AuthDB's storage (it has its
 * own Postgres schema).
 *
 * AuthDB is ALSO now Postgres-backed (ADR-0006) — these tests use the
 * shared `yuzu::test::AuthDbPg` fixture (test_auth_db_pg_helper.hpp)
 * instead of a SQLite temp-dir constructor. PG-gated: SKIPs when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken.
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

// ── AuthDB v7 provisioning_source ───────────────────────────────────────

TEST_CASE("AuthDB: provisioning_source defaults to local and round-trips via SCIM setter",
         "[pg][scim][auth_db][provisioning_source]") {
    yuzu::test::AuthDbPg fixture;

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(fixture->upsert_user("frank", hash, salt_hex, Role::admin).has_value());

    // Pre-v7 rows (and any row nobody has touched) default to 'local' with
    // zero migration backfill.
    auto initial = fixture->get_provisioning_source("frank");
    REQUIRE(initial.has_value());
    CHECK(*initial == "local");

    auto set_result = fixture->set_provisioning_source("frank", "scim");
    REQUIRE(set_result.has_value());

    auto after = fixture->get_provisioning_source("frank");
    REQUIRE(after.has_value());
    CHECK(*after == "scim");
}

TEST_CASE("AuthDB: provisioning_source accessors reject unknown/invalid usernames",
         "[pg][scim][auth_db][provisioning_source]") {
    yuzu::test::AuthDbPg fixture;

    // Malformed username (contains ':') -> InvalidUsername.
    auto bad = fixture->set_provisioning_source("bad:name", "scim");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    // Well-formed but absent user -> UserNotFound.
    auto missing = fixture->get_provisioning_source("ghost");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── AuthDB::set_identity_source (S-IDENTITY-SRC) ────────────────────────

TEST_CASE("AuthDB: set_identity_source round-trips and defaults to local",
         "[pg][scim][auth_db][identity_source]") {
    yuzu::test::AuthDbPg fixture;

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(fixture->upsert_user("ida", hash, salt_hex, Role::user).has_value());

    // v6 default, before any SCIM provisioning touches it.
    auto before = fixture->get_user("ida");
    REQUIRE(before.has_value());
    CHECK(before->identity_source == "local");

    REQUIRE(fixture->set_identity_source("ida", "scim").has_value());

    auto after = fixture->get_user("ida");
    REQUIRE(after.has_value());
    CHECK(after->identity_source == "scim");
    // Distinct dimension — provisioning_source is untouched by this call.
    CHECK(fixture->get_provisioning_source("ida").value() == "local");
}

TEST_CASE("AuthDB: set_identity_source rejects unknown/invalid usernames",
         "[pg][scim][auth_db][identity_source]") {
    yuzu::test::AuthDbPg fixture;

    auto bad = fixture->set_identity_source("bad:name", "scim");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    auto missing = fixture->set_identity_source("ghost", "scim");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── AuthDB::reactivate_user (SCIM PATCH/PUT active=true un-suspend) ────────

TEST_CASE("AuthDB: reactivate_user revives a soft-deleted row and clears lockout state",
         "[pg][scim][auth_db][reactivate]") {
    yuzu::test::AuthDbPg fixture;

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(fixture->upsert_user("ivan", hash, salt_hex, Role::user).has_value());
    REQUIRE(fixture->set_provisioning_source("ivan", "scim").has_value());

    // Seed a real lockout (threshold=1 crosses immediately) BEFORE
    // deactivating, so clearing it after reactivation is a meaningful
    // assertion rather than an all-zero coincidence.
    auto lockout = fixture->record_failed_login("ivan", /*threshold=*/1, /*window_secs=*/3600);
    REQUIRE(lockout.has_value());
    REQUIRE(lockout->locked);

    REQUIRE(fixture->remove_user("ivan").has_value());
    // Soft-deleted: get_user (is_active filter) can no longer see it.
    REQUIRE_FALSE(fixture->get_user("ivan").has_value());

    auto reactivated = fixture->reactivate_user("ivan");
    REQUIRE(reactivated.has_value());

    // The row resolves again...
    auto user = fixture->get_user("ivan");
    REQUIRE(user.has_value());
    CHECK(user->username == "ivan");
    CHECK(user->role == Role::user);
    // ...provisioning_source and role are untouched...
    auto source = fixture->get_provisioning_source("ivan");
    REQUIRE(source.has_value());
    CHECK(*source == "scim");
    // ...and the stale lockout is cleared, not inherited.
    auto status = fixture->lockout_status("ivan");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->locked);
    CHECK(status->failed_count == 0);
}

TEST_CASE("AuthDB: reactivate_user is a harmless no-op on an already-active user",
         "[pg][scim][auth_db][reactivate]") {
    yuzu::test::AuthDbPg fixture;

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(fixture->upsert_user("judy", hash, salt_hex, Role::user).has_value());

    REQUIRE(fixture->reactivate_user("judy").has_value());
    auto user = fixture->get_user("judy");
    REQUIRE(user.has_value());
    CHECK(user->username == "judy");
}

TEST_CASE("AuthDB: reactivate_user rejects unknown/invalid usernames",
         "[pg][scim][auth_db][reactivate]") {
    yuzu::test::AuthDbPg fixture;

    auto bad = fixture->reactivate_user("bad:name");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    auto missing = fixture->reactivate_user("ghost");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}
