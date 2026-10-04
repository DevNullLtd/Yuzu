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
 * #5342 Gate 7 additions: the typed `verify_password` result (a store error or
 * a concurrent credential change is TRANSIENT, never a failed guess), the
 * credential anchor every login carries to its session mint (a reset landing
 * between verify and mint denies the mint), the self-change CAS on the
 * verified hash (no second PBKDF2), the plain admin reset (no target-role
 * classification), the lockout-preserving `set_password`, and the #5274 boot
 * signal for stale cfg credentials.
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
#include <fstream>
#include <optional>
#include <string>

namespace fs = std::filesystem;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::PasswordWriteOutcome;
using yuzu::server::auth::Role;
using yuzu::server::auth::VerifyFailure;

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

/// The verified role, or nullopt on any refusal — keeps the many
/// "does this password work?" assertions below one line each.
std::optional<Role> vrole(AuthManager& mgr, const std::string& user, const std::string& pw) {
    auto v = mgr.verify_password(user, pw);
    if (!v)
        return std::nullopt;
    return v->role;
}

/// The stored hash a successful verify anchored on (the value the self-change
/// CAS and the session mint carry). REQUIREs the password to verify.
std::string anchor_of(AuthManager& mgr, const std::string& user, const std::string& pw) {
    auto v = mgr.verify_password(user, pw);
    REQUIRE(v.has_value());
    REQUIRE_FALSE(v->hash_hex.empty());
    return v->hash_hex;
}

/// Break ONLY AuthDB::get_user's own SELECT (it reads identity_source; the
/// lockout/role-recheck/password statements do not), the test_auth_db_pg.cpp
/// fault-injection idiom. Each TEST_CASE gets its own cloned database.
void break_get_user(const yuzu::test::AuthDbPg& db) {
    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult alter{
        PQexec(conn.get(), "ALTER TABLE auth.users DROP COLUMN identity_source")};
    REQUIRE(alter.ok());
}

} // namespace

// ── verify_password: typed result (#5342 Gate 7, sec-3) ────────────────────

TEST_CASE("verify_password returns the verified role AND the stored hash it anchored on",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "vic", kOld, Role::admin);

    auto ok = mgr.verify_password("vic", kOld);
    REQUIRE(ok.has_value());
    CHECK(ok->role == Role::admin);
    CHECK(ok->hash_hex == db->get_user("vic")->hash_hex);

    auto bad = mgr.verify_password("vic", "not-the-password");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == VerifyFailure::kBadCredential);
    CHECK_FALSE(yuzu::server::auth::is_transient(bad.error()));

    auto ghost = mgr.verify_password("nobody-here", kOld);
    REQUIRE_FALSE(ghost.has_value());
    CHECK(ghost.error() == VerifyFailure::kUnknownUser);

    // An over-max password is a credential verdict (it can never match).
    auto over = mgr.verify_password(
        "vic", std::string(yuzu::server::auth::kMaxPasswordBytes + 1, 'x'));
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error() == VerifyFailure::kBadCredential);
}

TEST_CASE("verify_password: an AuthDB read failure is kStoreUnavailable, never a bad credential",
          "[pg][auth][password]") {
    // Before Gate 7 this collapsed to nullopt, which /login answered as a
    // wrong password — counted toward lockout and audited auth.login_failed.
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "sam", kOld, Role::user);
    break_get_user(db);

    auto r = mgr.verify_password("sam", kOld);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == VerifyFailure::kStoreUnavailable);
    CHECK(yuzu::server::auth::is_transient(r.error()));
}

// ── change_password / reset_password contract ──────────────────────────────

TEST_CASE("change_password: CAS on the verified hash writes, old password stops working",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("alice", kOld, Role::user));
    const auto before = db->get_user("alice");
    REQUIRE(before.has_value());

    const auto r = mgr.change_password("alice", anchor_of(mgr, "alice", kOld), kNew);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    CHECK(r.role == Role::user);
    CHECK(r.previous_hash_hex == before->hash_hex);
    CHECK(r.previous_salt_hex == before->salt_hex);
    CHECK(r.new_hash_hex == db->get_user("alice")->hash_hex);
    CHECK(r.new_hash_hex != r.previous_hash_hex);

    CHECK_FALSE(vrole(mgr, "alice", kOld).has_value());
    CHECK(vrole(mgr, "alice", kNew) == Role::user);
}

TEST_CASE("change_password: a stale or empty anchor writes nothing (kConflict)",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("bob", kOld, Role::user));
    const auto anchor = anchor_of(mgr, "bob", kOld);
    const auto before = db->get_user("bob")->hash_hex;

    // An anchor that is not the stored hash (the credential moved since the
    // caller proved it) — refused without a write. No second PBKDF2 happens:
    // change_password never sees a password, only the anchor.
    CHECK(mgr.change_password("bob", std::string(before.size(), 'f'), kNew).outcome ==
          PasswordWriteOutcome::kConflict);
    CHECK(mgr.change_password("bob", "", kNew).outcome == PasswordWriteOutcome::kConflict);
    CHECK(db->get_user("bob")->hash_hex == before);
    CHECK(vrole(mgr, "bob", kOld) == Role::user);

    // A reset committing between the verify and the change wins: the anchor
    // the caller holds is dead, so the change is refused.
    REQUIRE(mgr.reset_password("bob", "reset-by-admin-1").outcome == PasswordWriteOutcome::kOk);
    CHECK(mgr.change_password("bob", anchor, kNew).outcome == PasswordWriteOutcome::kConflict);
    CHECK(vrole(mgr, "bob", "reset-by-admin-1") == Role::user);
}

TEST_CASE("change_password: the CAS closes the read->write window", "[pg][auth][password]") {
    // The race hook fires after change_password's own read (which still sees
    // the anchored hash) and before the UPDATE: a concurrent writer there must
    // make the CAS miss rather than be silently overwritten.
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "cass", kOld, Role::user);
    const auto anchor = anchor_of(mgr, "cass", kOld);
    auto salt = AuthManager::random_bytes(16);
    const auto racer = AuthManager::pbkdf2_sha256("racer-password-1", salt,
                                                  AuthManager::kPbkdf2Iterations);
    mgr.set_password_write_race_hook_for_test([&] {
        REQUIRE(db->set_password("cass", racer, AuthManager::bytes_to_hex(salt)).has_value());
    });
    const auto r = mgr.change_password("cass", anchor, kNew);
    mgr.set_password_write_race_hook_for_test(nullptr);
    CHECK(r.outcome == PasswordWriteOutcome::kConflict);
    CHECK(db->get_user("cass")->hash_hex == racer);
}

TEST_CASE("change_password / reset_password: length policy", "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    REQUIRE(mgr.upsert_user("carol", kOld, Role::user));
    using yuzu::server::auth::kMaxPasswordBytes;
    using yuzu::server::auth::kMinPasswordBytes;
    const auto anchor = anchor_of(mgr, "carol", kOld);

    CHECK(mgr.change_password("carol", anchor, std::string(kMinPasswordBytes - 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooShort);
    CHECK(mgr.change_password("carol", anchor, std::string(kMaxPasswordBytes + 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooLong);
    CHECK(mgr.reset_password("carol", std::string(kMinPasswordBytes - 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooShort);
    CHECK(mgr.reset_password("carol", std::string(kMaxPasswordBytes + 1, 'a')).outcome ==
          PasswordWriteOutcome::kTooLong);
    // Exactly at both bounds is accepted.
    CHECK(mgr.reset_password("carol", std::string(kMinPasswordBytes, 'a')).outcome ==
          PasswordWriteOutcome::kOk);
    CHECK(mgr.reset_password("carol", std::string(kMaxPasswordBytes, 'b')).outcome ==
          PasswordWriteOutcome::kOk);
    CHECK(vrole(mgr, "carol", std::string(kMaxPasswordBytes, 'b')) == Role::user);
}

TEST_CASE("change_password / reset_password: not-local and absent accounts",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());

    SECTION("SCIM-provisioned") {
        seed_local(*db, "scimmy", kOld, Role::user);
        const auto anchor = db->get_user("scimmy")->hash_hex;
        REQUIRE(db->set_provisioning_source("scimmy", "scim").has_value());
        CHECK(mgr.reset_password("scimmy", kNew).outcome == PasswordWriteOutcome::kNotLocal);
        CHECK(mgr.change_password("scimmy", anchor, kNew).outcome ==
              PasswordWriteOutcome::kNotLocal);
    }
    SECTION("SSO principal") {
        const std::string principal = "oidc:https://idp.example#s1";
        REQUIRE(db->upsert_sso_identity(principal, "https://idp.example", "s1", "S", "oidc")
                    .has_value());
        CHECK(mgr.reset_password(principal, kNew).outcome == PasswordWriteOutcome::kNotLocal);
    }
    SECTION("identity_source not local") {
        seed_local(*db, "idp_user", kOld, Role::user);
        REQUIRE(db->set_identity_source("idp_user", "scim").has_value());
        CHECK(mgr.reset_password("idp_user", kNew).outcome == PasswordWriteOutcome::kNotLocal);
    }
    SECTION("absent and inactive") {
        CHECK(mgr.reset_password("ghost", kNew).outcome == PasswordWriteOutcome::kNotFound);
        seed_local(*db, "removed", kOld, Role::user);
        REQUIRE(db->remove_user("removed").has_value());
        CHECK(mgr.reset_password("removed", kNew).outcome == PasswordWriteOutcome::kNotFound);
    }
}

TEST_CASE("change_password / reset_password: a SCIM adoption racing the write is kNotLocal",
          "[pg][auth][password]") {
    // The race hook fires after the pre-write read (which still sees a local
    // row) and before the UPDATE. Flipping provisioning_source there makes the
    // guarded write match nothing; the re-read must classify that as "not
    // local any more" on BOTH paths — on the CAS path it must not be
    // misreported as a concurrent password change (kConflict).
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());

    SECTION("self change (CAS)") {
        seed_local(*db, "adoptee", kOld, Role::user);
        const auto anchor = anchor_of(mgr, "adoptee", kOld);
        const auto before = db->get_user("adoptee")->hash_hex;
        mgr.set_password_write_race_hook_for_test(
            [&] { REQUIRE(db->set_provisioning_source("adoptee", "scim").has_value()); });
        const auto r = mgr.change_password("adoptee", anchor, kNew);
        mgr.set_password_write_race_hook_for_test(nullptr);
        CHECK(r.outcome == PasswordWriteOutcome::kNotLocal);
        CHECK(db->get_user("adoptee")->hash_hex == before);
    }
    SECTION("admin reset (plain)") {
        seed_local(*db, "adoptee2", kOld, Role::user);
        const auto before = db->get_user("adoptee2")->hash_hex;
        mgr.set_password_write_race_hook_for_test(
            [&] { REQUIRE(db->set_provisioning_source("adoptee2", "scim").has_value()); });
        const auto r = mgr.reset_password("adoptee2", kNew);
        mgr.set_password_write_race_hook_for_test(nullptr);
        CHECK(r.outcome == PasswordWriteOutcome::kNotLocal);
        CHECK(db->get_user("adoptee2")->hash_hex == before);
    }
}

TEST_CASE("reset_password: a plain write, no target-role classification (#5342 Gate 7)",
          "[pg][auth][password]") {
    // Who may reset whom is decided ONCE, at the route, by is_rbac_administrator.
    // The store/manager layer writes any active LOCAL row — including an admin
    // one — and the write's admin-ness never changes the outcome.
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "root2", kOld, Role::admin);

    const auto r = mgr.reset_password("root2", kNew);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    CHECK(r.role == Role::admin);
    CHECK(vrole(mgr, "root2", kNew) == Role::admin);
    CHECK_FALSE(vrole(mgr, "root2", kOld).has_value());

    SECTION("a promotion racing the write does not change the outcome") {
        seed_local(*db, "climber", kOld, Role::user);
        mgr.set_password_write_race_hook_for_test(
            [&] { REQUIRE(db->update_role("climber", Role::admin).has_value()); });
        const auto raced = mgr.reset_password("climber", kNew);
        mgr.set_password_write_race_hook_for_test(nullptr);
        CHECK(raced.outcome == PasswordWriteOutcome::kOk);
        CHECK(vrole(mgr, "climber", kNew) == Role::admin);
    }
}

TEST_CASE("reset_password / rollback never touch the lockout columns (#5342 Gate 7, C7)",
          "[pg][auth][password][lockout]") {
    // set_password writes hash/salt/updated_at ONLY: a lock armed before an
    // admin reset is cleared by the route's audited admin-unlock step, not by
    // the write — so an audit-failure rollback cannot have silently erased it.
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "lockie", kOld, Role::user);
    for (int i = 0; i < 3; ++i)
        REQUIRE(db->record_failed_login("lockie", 3, 3600).has_value());
    const auto armed = db->lockout_status("lockie");
    REQUIRE(armed.has_value());
    REQUIRE(armed->locked);

    const auto r = mgr.reset_password("lockie", kNew);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    auto after_write = db->lockout_status("lockie");
    REQUIRE(after_write.has_value());
    CHECK(after_write->locked);
    CHECK(after_write->failed_count == armed->failed_count);

    REQUIRE(mgr.rollback_password_write("lockie", r));
    auto after_rollback = db->lockout_status("lockie");
    REQUIRE(after_rollback.has_value());
    CHECK(after_rollback->locked);
    CHECK(after_rollback->failed_count == armed->failed_count);
}

TEST_CASE("change_password / reset_password fail closed without AuthDB", "[auth][password]") {
    AuthManager mgr; // cfg-file-only: no durable credential to change
    CHECK(mgr.change_password("x", "deadbeef", kNew).outcome ==
          PasswordWriteOutcome::kStoreUnavailable);
    CHECK(mgr.reset_password("x", kNew).outcome == PasswordWriteOutcome::kStoreUnavailable);
}

TEST_CASE("rollback_password_write restores the previous credential, only if still ours",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "dora", kOld, Role::user);

    const auto r = mgr.reset_password("dora", kNew);
    REQUIRE(r.outcome == PasswordWriteOutcome::kOk);
    REQUIRE(mgr.rollback_password_write("dora", r));
    CHECK(vrole(mgr, "dora", kOld) == Role::user);
    CHECK_FALSE(vrole(mgr, "dora", kNew).has_value());
    // A second compensation finds the stored hash is no longer the one it
    // wrote — refused, never clobbering.
    CHECK_FALSE(mgr.rollback_password_write("dora", r));

    // A write that LOST the race is never "rolled back" over the winner.
    const auto mine = mgr.reset_password("dora", kNew);
    REQUIRE(mine.outcome == PasswordWriteOutcome::kOk);
    REQUIRE(mgr.reset_password("dora", "third-password-789").outcome == PasswordWriteOutcome::kOk);
    CHECK_FALSE(mgr.rollback_password_write("dora", mine));
    CHECK(vrole(mgr, "dora", "third-password-789") == Role::user);
}

// ── The credential anchor at session mint (#5342 Gate 7, B4) ───────────────

TEST_CASE("create_local_session denies a mint whose verified hash is no longer stored",
          "[pg][auth][password]") {
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "mira", kOld, Role::user);
    const auto anchor = anchor_of(mgr, "mira", kOld);

    // The anchor is current: the mint lands.
    auto ok = mgr.create_local_session("mira", Role::user, false, anchor);
    REQUIRE_FALSE(ok.empty());
    CHECK(mgr.validate_session(ok).has_value());

    // An empty anchor never disables the check — it denies (fail closed).
    CHECK(mgr.create_local_session("mira", Role::user, false, "").empty());

    // A reset after the verify: the OLD anchor can no longer mint, and the
    // denied mint leaves no live session behind (revoke-and-deny).
    REQUIRE(mgr.reset_password("mira", kNew).outcome == PasswordWriteOutcome::kOk);
    CHECK(mgr.create_local_session("mira", Role::user, false, anchor).empty());
    CHECK_FALSE(mgr.validate_session(ok).has_value()); // swept by the deny's revoke
}

TEST_CASE("authenticate: a reset committing between the recheck and the mint revokes the session",
          "[pg][auth][password]") {
    // post_mint_race_hook_for_test fires inside authenticate() after the
    // row-locked recheck released and before the session is persisted — the
    // check-then-mint window. A reset landing there must not leave a session
    // proven with the OLD password alive.
    yuzu::test::AuthDbPg db;
    AuthManager mgr;
    mgr.set_auth_db(db.get());
    seed_local(*db, "rhea", kOld, Role::user);
    bool fired = false;
    mgr.set_post_mint_race_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        AuthManager other; // a second replica's admin reset
        other.set_auth_db(db.get());
        REQUIRE(other.reset_password("rhea", kNew).outcome == PasswordWriteOutcome::kOk);
    });
    auto token = mgr.authenticate("rhea", kOld);
    mgr.set_post_mint_race_hook_for_test(nullptr);
    CHECK(fired);
    CHECK_FALSE(token.has_value());
    CHECK(vrole(mgr, "rhea", kNew) == Role::user);
}

// ── #5274 acceptance ───────────────────────────────────────────────────────

TEST_CASE("#5274: a restart that re-seeds the OLD cfg hash does not shadow the changed password",
          "[pg][auth][password][5274]") {
    yuzu::test::TempDir dir{"yuzu_test_pwcfg_"};
    fs::create_directories(dir.path);
    const auto cfg = dir.path / "yuzu-server.cfg";
    yuzu::test::AuthDbPg db;

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
        REQUIRE(boot1.change_password("alice", anchor_of(boot1, "alice", kOld), kNew).outcome ==
                PasswordWriteOutcome::kOk);
    }

    // Boot 2 (the restart): the cfg file still carries the OLD hash and is
    // re-seeded into users_ — it must not win.
    AuthManager boot2;
    REQUIRE(boot2.load_config(cfg));
    boot2.set_auth_db(db.get());
    CHECK_FALSE(vrole(boot2, "alice", kOld).has_value());
    CHECK_FALSE(boot2.authenticate("alice", kOld).has_value());
    CHECK(vrole(boot2, "alice", kNew) == Role::admin);
    CHECK(boot2.authenticate("alice", kNew).has_value());
}

TEST_CASE("#5274: the boot check names and counts cfg users whose stored credential diverged",
          "[pg][auth][password][5274]") {
    yuzu::test::TempDir dir{"yuzu_test_pwcfg_"};
    fs::create_directories(dir.path);
    const auto cfg = dir.path / "yuzu-server.cfg";
    yuzu::test::AuthDbPg db;
    {
        AuthManager cfg_only;
        REQUIRE_FALSE(cfg_only.load_config(cfg));
        REQUIRE(cfg_only.upsert_user("alice", kOld, Role::admin));
        REQUIRE(cfg_only.upsert_user("bert", kOld, Role::user));
        REQUIRE(cfg_only.upsert_user("cfgonly", kOld, Role::user)); // no AuthDB row at all
    }
    // alice's stored credential matches the cfg; bert's diverged (changed
    // in-product) — only bert is stale. cfgonly has no row: not counted.
    {
        // Copy alice's cfg credential into AuthDB byte-for-byte (cfg line
        // format: username:role:salt:hash — AuthManager::save_config).
        std::ifstream in(cfg);
        std::string line;
        bool copied = false;
        while (std::getline(in, line)) {
            if (!line.starts_with("alice:"))
                continue;
            const auto p1 = line.find(':');
            const auto p2 = line.find(':', p1 + 1);
            const auto p3 = line.find(':', p2 + 1);
            REQUIRE(p3 != std::string::npos);
            REQUIRE(db->upsert_user("alice", line.substr(p3 + 1), line.substr(p2 + 1, p3 - p2 - 1),
                                    Role::admin)
                        .has_value());
            copied = true;
        }
        REQUIRE(copied);
    }
    seed_local(*db, "bert", "bert-changed-pw-1", Role::user);

    yuzu::MetricsRegistry metrics;
    AuthManager boot;
    REQUIRE(boot.load_config(cfg));
    boot.set_metrics_registry(&metrics);
    boot.set_auth_db(db.get());
    CHECK(boot.report_stale_cfg_credentials() == 1);
    CHECK(metrics.gauge("yuzu_auth_cfg_credentials_stale").value() == 1.0);

    AuthManager cfg_mode; // no AuthDB: nothing to compare against
    REQUIRE(cfg_mode.load_config(cfg));
    CHECK(cfg_mode.report_stale_cfg_credentials() == 0);
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

    REQUIRE(replica_a.change_password("erin", anchor_of(replica_a, "erin", kOld), kNew).outcome ==
            PasswordWriteOutcome::kOk);

    CHECK_FALSE(replica_b.authenticate("erin", kOld).has_value());
    CHECK_FALSE(vrole(replica_b, "erin", kOld).has_value());
    CHECK(vrole(replica_b, "erin", kNew) == Role::user);
}

TEST_CASE("#5274: a password change committing mid-verification is kCredentialChanged (transient)",
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

    auto raced = mgr.verify_password("fay", kOld); // verified against a dead hash
    REQUIRE_FALSE(raced.has_value());
    CHECK(raced.error() == VerifyFailure::kCredentialChanged);
    CHECK(yuzu::server::auth::is_transient(raced.error()));
    CHECK(fired);
    CHECK(metrics.counter("yuzu_auth_credential_changed_during_verify_total").value() == 1.0);
    mgr.set_role_recheck_race_hook_for_test(nullptr);
    CHECK(vrole(mgr, "fay", kNew) == Role::user); // the retry succeeds
}

TEST_CASE("verify_password / authenticate refuse an over-max password without a lookup",
          "[auth][password]") {
    yuzu::test::TempDir dir{"yuzu_test_pwcfg_"};
    fs::create_directories(dir.path);
    const auto cfg = dir.path / "yuzu-server.cfg";
    // cfg-only manager: the short-circuit runs before any store is consulted.
    AuthManager mgr;
    REQUIRE_FALSE(mgr.load_config(cfg));
    const std::string max_pw(yuzu::server::auth::kMaxPasswordBytes, 'm');
    REQUIRE(mgr.upsert_user("gus", max_pw, Role::user));
    CHECK(vrole(mgr, "gus", max_pw) == Role::user); // exactly-max still verifies
    const std::string over(yuzu::server::auth::kMaxPasswordBytes + 1, 'm');
    CHECK_FALSE(vrole(mgr, "gus", over).has_value());
    CHECK_FALSE(mgr.authenticate("gus", over).has_value());
    // upsert_user enforces the same maximum when SETTING a password.
    CHECK_FALSE(mgr.upsert_user("hal", over, Role::user));
}
