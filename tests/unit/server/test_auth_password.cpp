/**
 * test_auth_password.cpp — AuthManager local-account password change / admin
 * reset (#5342) and the DB-first credential read that makes it hold across
 * restarts and replicas (#5274).
 *
 * #5274 in one sentence: `users_` is seeded at boot from yuzu-server.cfg and
 * was consulted FIRST for credentials, so after a password change in AuthDB
 * (a) every restart re-seeded the old cfg hash, which then shadowed the new
 * password, and (b) a second replica kept accepting the old password until it
 * restarted. The acceptance tests below construct exactly those two shapes:
 * a fresh AuthManager that loaded the OLD cfg entry, and a second warm
 * AuthManager over the same AuthDB.
 *
 * PG-gated through AuthDbPg (skips when YUZU_TEST_POSTGRES_DSN is unset,
 * fails when it is set but broken).
 */

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "password_policy.hpp"
#include "test_auth_db_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::PasswordWriteOutcome;
using yuzu::server::auth::Role;

namespace {

constexpr const char* kOld = "old-password-123";
constexpr const char* kNew = "new-password-456";

/// Seed a LOCAL row directly in AuthDB with a hash the real verifier accepts
/// (kPbkdf2Iterations — a cheaper count would never verify).
void seed_local(yuzu::server::AuthDB& db, const std::string& user, const std::string& pw,
                Role role) {
    auto salt = AuthManager::random_bytes(16);
    REQUIRE(db.upsert_user(user, AuthManager::pbkdf2_sha256(pw, salt, AuthManager::kPbkdf2Iterations),
                           AuthManager::bytes_to_hex(salt), role)
                .has_value());
}

/// A cfg-file path with no file behind it yet (`yuzu_test_` prefix — the
/// Defender-exclusion wildcard, test conventions doc).
fs::path fresh_cfg_path() {
    auto cfg = yuzu::test::unique_temp_path("yuzu_test_pwcfg_");
    cfg += ".cfg";
    fs::create_directories(cfg.parent_path());
    fs::remove(cfg);
    return cfg;
}

} // namespace

// ── change_password / reset_password contract ──────────────────────────────

TEST_CASE("change_password: verifies the stored hash, writes, old password stops working",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("alice", kOld, Role::user));
    const auto before = db->get_user("alice");
    REQUIRE(before.has_value());

    const auto r = mgr.change_password("alice", kOld, kNew);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    CHECK(r.role == Role::user);
    CHECK(r.previous_hash_hex == before->hash_hex);
    CHECK(r.previous_salt_hex == before->salt_hex);
    CHECK(r.new_hash_hex == db->get_user("alice")->hash_hex);
    CHECK(r.new_hash_hex != r.previous_hash_hex);

    CHECK_FALSE(mgr.verify_password("alice", kOld).has_value());
    CHECK(mgr.verify_password("alice", kNew) == Role::user);
}

TEST_CASE("change_password: a wrong current password writes nothing", "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("bob", kOld, Role::user));
    const auto before = db->get_user("bob")->hash_hex;

    CHECK(mgr.change_password("bob", "not-the-password", kNew).outcome ==
          PasswordWriteOutcome::kWrongCurrent);
    // An over-max "current" can never match and is refused without hashing.
    CHECK(mgr.change_password("bob", std::string(yuzu::server::auth::kMaxPasswordBytes + 1, 'x'),
                              kNew)
              .outcome == PasswordWriteOutcome::kWrongCurrent);
    CHECK(db->get_user("bob")->hash_hex == before);
    CHECK(mgr.verify_password("bob", kOld) == Role::user);
}

TEST_CASE("change_password / reset_password: length policy", "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("carol", kOld, Role::user));
    using yuzu::server::auth::kMaxPasswordBytes;
    using yuzu::server::auth::kMinPasswordBytes;

    CHECK(mgr.change_password("carol", kOld, std::string(kMinPasswordBytes - 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooShort);
    CHECK(mgr.change_password("carol", kOld, std::string(kMaxPasswordBytes + 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooLong);
    CHECK(mgr.reset_password("carol", std::string(kMinPasswordBytes - 1, 'a'), true).outcome ==
          PasswordWriteOutcome::kTooShort);
    CHECK(mgr.reset_password("carol", std::string(kMaxPasswordBytes + 1, 'a'), true).outcome ==
          PasswordWriteOutcome::kTooLong);
    // Exactly at both bounds is accepted.
    CHECK(mgr.reset_password("carol", std::string(kMinPasswordBytes, 'a'), true).outcome ==
          PasswordWriteOutcome::kOk);
    CHECK(mgr.reset_password("carol", std::string(kMaxPasswordBytes, 'b'), true).outcome ==
          PasswordWriteOutcome::kOk);
    CHECK(mgr.verify_password("carol", std::string(kMaxPasswordBytes, 'b')) == Role::user);
}

TEST_CASE("change_password / reset_password: not-local and absent accounts",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());

    SECTION("SCIM-provisioned") {
        seed_local(*db, "scimmy", kOld, Role::user);
        REQUIRE(db->set_provisioning_source("scimmy", "scim").has_value());
        CHECK(mgr.reset_password("scimmy", kNew, true).outcome == PasswordWriteOutcome::kNotLocal);
        CHECK(mgr.change_password("scimmy", kOld, kNew).outcome ==
              PasswordWriteOutcome::kNotLocal);
    }
    SECTION("SSO principal") {
        const std::string principal = "oidc:https://idp.example#s1";
        REQUIRE(db->upsert_sso_identity(principal, "https://idp.example", "s1", "S", "oidc")
                    .has_value());
        CHECK(mgr.reset_password(principal, kNew, true).outcome ==
              PasswordWriteOutcome::kNotLocal);
    }
    SECTION("identity_source not local") {
        seed_local(*db, "idp_user", kOld, Role::user);
        REQUIRE(db->set_identity_source("idp_user", "scim").has_value());
        CHECK(mgr.reset_password("idp_user", kNew, true).outcome ==
              PasswordWriteOutcome::kNotLocal);
    }
    SECTION("absent and inactive") {
        CHECK(mgr.reset_password("ghost", kNew, true).outcome == PasswordWriteOutcome::kNotFound);
        seed_local(*db, "removed", kOld, Role::user);
        REQUIRE(db->remove_user("removed").has_value());
        CHECK(mgr.reset_password("removed", kNew, true).outcome ==
              PasswordWriteOutcome::kNotFound);
    }
}

TEST_CASE("reset_password: an admin target needs permit_admin_target", "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "root2", kOld, Role::admin);
    const auto before = db->get_user("root2")->hash_hex;

    CHECK(mgr.reset_password("root2", kNew, /*permit_admin_target=*/false).outcome ==
          PasswordWriteOutcome::kAdminTarget);
    CHECK(db->get_user("root2")->hash_hex == before);
    CHECK(mgr.reset_password("root2", kNew, /*permit_admin_target=*/true).outcome ==
          PasswordWriteOutcome::kOk);
    CHECK(mgr.verify_password("root2", kNew) == Role::admin);
}

TEST_CASE("change_password / reset_password fail closed without AuthDB", "[auth][password]") {
    AuthManager mgr; // cfg-file-only: no durable credential to change
    CHECK(mgr.change_password("x", kOld, kNew).outcome == PasswordWriteOutcome::kStoreUnavailable);
    CHECK(mgr.reset_password("x", kNew, true).outcome == PasswordWriteOutcome::kStoreUnavailable);
}

TEST_CASE("rollback_password_write restores the previous credential, only if still ours",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "dora", kOld, Role::user);

    const auto r = mgr.reset_password("dora", kNew, true);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    REQUIRE(mgr.rollback_password_write("dora", r));
    CHECK(mgr.verify_password("dora", kOld) == Role::user);
    CHECK_FALSE(mgr.verify_password("dora", kNew).has_value());
    // A second compensation finds the stored hash is no longer the one it
    // wrote — refused, never clobbering.
    CHECK_FALSE(mgr.rollback_password_write("dora", r));

    // A write that LOST the race is never "rolled back" over the winner.
    const auto mine = mgr.reset_password("dora", kNew, true);
    REQUIRE(mine.outcome == PasswordWriteOutcome::kOk);
    REQUIRE(mgr.reset_password("dora", "third-password-789", true).outcome ==
            PasswordWriteOutcome::kOk);
    CHECK_FALSE(mgr.rollback_password_write("dora", mine));
    CHECK(mgr.verify_password("dora", "third-password-789") == Role::user);
}

// ── #5274 acceptance ───────────────────────────────────────────────────────

TEST_CASE("#5274: a restart that re-seeds the OLD cfg hash does not shadow the changed password",
          "[pg][auth][password][5274]") {
    yuzu::test::AuthDbPg db;
    const auto cfg = fresh_cfg_path();

    // The installer/first-run shape: the account lives in yuzu-server.cfg AND
    // in AuthDB with the same (old) password.
    {
        AuthManager cfg_only;
        REQUIRE_FALSE(cfg_only.load_config(cfg)); // sets the path; no file yet
        REQUIRE(cfg_only.upsert_user("alice", kOld, Role::admin)); // writes the cfg file
    }
    REQUIRE(fs::exists(cfg));
    seed_local(*db, "alice", kOld, Role::admin);

    // Boot 1: load the cfg (seeds users_ with the OLD hash), wire AuthDB,
    // change the password.
    {
        AuthManager boot1;
        REQUIRE(boot1.load_config(cfg));
        boot1.set_auth_db(db.get());
        REQUIRE(boot1.change_password("alice", kOld, kNew).outcome == PasswordWriteOutcome::kOk);
    }

    // Boot 2 (the restart): the cfg file still carries the OLD hash and is
    // re-seeded into users_ — it must not win.
    AuthManager boot2;
    REQUIRE(boot2.load_config(cfg));
    boot2.set_auth_db(db.get());
    CHECK_FALSE(boot2.verify_password("alice", kOld).has_value());
    CHECK_FALSE(boot2.authenticate("alice", kOld).has_value());
    CHECK(boot2.verify_password("alice", kNew) == Role::admin);
    CHECK(boot2.authenticate("alice", kNew).has_value());
    fs::remove(cfg);
}

TEST_CASE("#5274: a second replica's warm cache does not keep accepting the old password",
          "[pg][auth][password][5274]") {
    yuzu::test::AuthDbPg db;
    seed_local(*db, "erin", kOld, Role::user);

    AuthManager replica_a;
    replica_a.set_auth_db(db.get());
    AuthManager replica_b;
    replica_b.set_auth_db(db.get());
    // Warm BOTH caches with the old credential.
    REQUIRE(replica_a.authenticate("erin", kOld).has_value());
    REQUIRE(replica_b.authenticate("erin", kOld).has_value());

    REQUIRE(replica_a.change_password("erin", kOld, kNew).outcome == PasswordWriteOutcome::kOk);

    CHECK_FALSE(replica_b.authenticate("erin", kOld).has_value());
    CHECK_FALSE(replica_b.verify_password("erin", kOld).has_value());
    CHECK(replica_b.verify_password("erin", kNew) == Role::user);
}

TEST_CASE("#5274: a password change committing mid-verification denies the in-flight login",
          "[pg][auth][password][5274]") {
    yuzu::test::AuthDbPg db;
    yuzu::MetricsRegistry metrics;
    seed_local(*db, "fay", kOld, Role::user);

    AuthManager mgr;
    mgr.set_auth_db(db.get());
    mgr.set_metrics_registry(&metrics);
    // Fires after the DB-first read + PBKDF2 matched the OLD hash and before
    // the row-locked recheck: the moment a concurrent change commits. (Not
    // inside the row lock — a synchronous set_password there would
    // self-deadlock; see set_role_recheck_race_hook_for_test's doc.)
    auto salt = AuthManager::random_bytes(16);
    const auto new_hash = AuthManager::pbkdf2_sha256(kNew, salt, AuthManager::kPbkdf2Iterations);
    const auto new_salt = AuthManager::bytes_to_hex(salt);
    bool fired = false;
    mgr.set_role_recheck_race_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        REQUIRE(db->set_password("fay", new_hash, new_salt).has_value());
    });

    CHECK_FALSE(mgr.verify_password("fay", kOld).has_value()); // verified against a dead hash
    CHECK(fired);
    CHECK(metrics.counter("yuzu_auth_credential_changed_during_verify_total").value() == 1.0);
    mgr.set_role_recheck_race_hook_for_test(nullptr);
    CHECK(mgr.verify_password("fay", kNew) == Role::user); // the retry succeeds
}

TEST_CASE("verify_password / authenticate refuse an over-max password without a lookup",
          "[auth][password]") {
    // cfg-only manager: the short-circuit runs before any store is consulted.
    AuthManager mgr;
    const auto cfg = fresh_cfg_path();
    REQUIRE_FALSE(mgr.load_config(cfg));
    const std::string max_pw(yuzu::server::auth::kMaxPasswordBytes, 'm');
    REQUIRE(mgr.upsert_user("gus", max_pw, Role::user));
    CHECK(mgr.verify_password("gus", max_pw) == Role::user); // exactly-max still verifies
    const std::string over(yuzu::server::auth::kMaxPasswordBytes + 1, 'm');
    CHECK_FALSE(mgr.verify_password("gus", over).has_value());
    CHECK_FALSE(mgr.authenticate("gus", over).has_value());
    // upsert_user enforces the same maximum when SETTING a password.
    CHECK_FALSE(mgr.upsert_user("hal", over, Role::user));
    fs::remove(cfg);
}
