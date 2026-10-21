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
 * between verify and mint denies the mint), and the #5274 boot signal for
 * stale cfg credentials.
 *
 * #5342 Gate 8 (the class fix): every credential write goes through
 * `AuthManager::commit_password_change` → `CredentialChangeOwner` — ONE
 * transaction under the `auth.users` row lock for the credential, the
 * account's sessions, its provisional MFA secret, its lockout (admin) and the
 * audit row(s). The cases below drive that owner against a real AuthDB +
 * SessionStore + AuditStore on one pool (the production shape), inject REAL
 * statement faults inside the throwaway database, and pin the locking
 * post-mint re-read (M1).
 *
 * PG-gated through AuthDbPg (skips when YUZU_TEST_POSTGRES_DSN is unset,
 * fails when it is set but broken).
 */

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "audit_store.hpp"
#include "credential_change_owner.hpp"
#include "password_policy.hpp"
#include "session_store.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "../../../server/core/src/totp.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using yuzu::server::auth::AuthManager;
using Kind = yuzu::server::CredentialChangeRequest::Kind;
using Result = yuzu::server::CredentialChangeResult;
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

/// A credential-change request as the routes build it: PBKDF2 of `pw` at the
/// production iteration count (anything cheaper would never verify).
yuzu::server::CredentialChangeRequest mkreq(Kind kind, const std::string& user,
                                            const std::string& pw,
                                            std::optional<std::string> anchor = std::nullopt) {
    yuzu::server::CredentialChangeRequest r;
    r.kind = kind;
    r.username = user;
    const auto salt = AuthManager::random_bytes(16);
    r.new_salt_hex = AuthManager::bytes_to_hex(salt);
    r.new_hash_hex = AuthManager::pbkdf2_sha256(pw, salt, AuthManager::kPbkdf2Iterations);
    r.expected_current_hash_hex = std::move(anchor);
    r.audit_template.principal = kind == Kind::kSelf ? user : "root";
    r.audit_template.principal_role = "admin";
    r.audit_template.target_type = "User";
    r.audit_template.target_id = user;
    return r;
}

/// The production store shape on ONE pool: AuthDB + SessionStore + AuditStore
/// + the credential-change owner (server.cpp wires all four on `*pg_pool_`).
struct CredInfra {
    yuzu::test::AuthDbPg db;
    yuzu::server::SessionStore sessions{db.pool()};
    yuzu::server::AuditStore audit{db.pool()};
    yuzu::server::CredentialChangeOwner owner{db.pool(), &audit};

    CredInfra() {
        REQUIRE(sessions.is_open());
        REQUIRE(audit.is_open());
    }

    void wire(AuthManager& mgr) {
        mgr.set_auth_db(db.get());
        mgr.set_session_store(&sessions);
        mgr.set_credential_change_owner(&owner);
    }

    void exec_on(PGconn* c, const std::string& sql) {
        yuzu::server::pg::PgResult r{PQexec(c, sql.c_str())};
        INFO(sql << " -> " << PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
    }
    void exec(const std::string& sql) {
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        exec_on(c.get(), sql);
    }
    std::string scalar(const std::string& sql) {
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(c.get(), sql.c_str())};
        INFO(sql << " -> " << PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
        return PQntuples(r.get()) == 0 ? std::string{} : std::string(PQgetvalue(r.get(), 0, 0));
    }
    int sessions_of(const std::string& user) {
        return std::stoi(scalar("SELECT count(*) FROM session_store.sessions WHERE username = '" +
                                user + "'"));
    }
    /// REAL statement fault for ONE audit action (BEFORE INSERT trigger on
    /// NEW.action) — every other audit row still commits.
    void fault_audit_for_action(const std::string& action) {
        exec("CREATE FUNCTION public.yuzu_test_audit_action_fault() RETURNS trigger LANGUAGE "
             "plpgsql AS $$ BEGIN IF NEW.action = '" + action +
             "' THEN RAISE EXCEPTION 'injected audit fault'; END IF; RETURN NEW; END $$");
        exec("CREATE TRIGGER yuzu_test_audit_action_fault BEFORE INSERT ON "
             "audit_store.audit_events FOR EACH ROW EXECUTE FUNCTION "
             "public.yuzu_test_audit_action_fault()");
    }
    int audit_total() { return std::stoi(scalar("SELECT count(*) FROM audit_store.audit_events")); }
    int audit_rows(const std::string& action, const std::string& target) {
        return std::stoi(scalar("SELECT count(*) FROM audit_store.audit_events WHERE action = '" +
                                action + "' AND target_id = '" + target + "'"));
    }
    std::string audit_detail(const std::string& action, const std::string& target) {
        return scalar("SELECT detail FROM audit_store.audit_events WHERE action = '" + action +
                      "' AND target_id = '" + target + "' ORDER BY id DESC LIMIT 1");
    }
};

/// A TOTP code for the current step from an enrolment's base32 secret.
std::string code_for_now(const std::string& secret_b32) {
    auto bytes = yuzu::server::mfa::base32_decode(secret_b32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return yuzu::server::mfa::generate(
        raw, yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));
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

// ── The one-transaction credential change (#5342 Gate 8, T1) ───────────────

TEST_CASE("commit_password_change (self): anchor compared under the row lock; old password dies",
          "[pg][auth][password]") {
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    REQUIRE(mgr.upsert_user("alice", kOld, Role::user));
    auto s1 = mgr.create_local_session("alice", Role::user, false, anchor_of(mgr, "alice", kOld));
    REQUIRE_FALSE(s1.empty());

    const auto r = mgr.commit_password_change(
        mkreq(Kind::kSelf, "alice", kNew, anchor_of(mgr, "alice", kOld)));
    REQUIRE(r.result == Result::kOk);
    CHECK(r.target_role == "user");
    CHECK(r.sessions_revoked == 1);
    CHECK_FALSE(r.lockout_cleared); // a self change never touches the lockout
    CHECK_FALSE(vrole(mgr, "alice", kOld).has_value());
    CHECK(vrole(mgr, "alice", kNew) == Role::user);
    CHECK_FALSE(mgr.validate_session(s1).has_value());
    CHECK(f.sessions_of("alice") == 0);
    CHECK(f.audit_rows("user.password_change", "alice") == 1);
    CHECK(f.audit_detail("user.password_change", "alice") ==
          "self_service sessions_revoked=1 provisional_mfa_cleared=false");
}

TEST_CASE("commit_password_change: every refusal under the lock writes NOTHING",
          "[pg][auth][password]") {
    // T1(i): hash, sessions and audit rows are byte-for-byte unchanged.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);

    auto check_untouched = [&](const std::string& user, const std::string& hash_before,
                               const std::string& session) {
        CHECK(f.db->get_user(user)->hash_hex == hash_before);
        CHECK(mgr.validate_session(session).has_value());
        CHECK(f.sessions_of(user) == 1);
        CHECK(f.audit_total() == 0);
    };

    SECTION("self: a stale anchor is kConflict") {
        seed_local(*f.db, "bob", kOld, Role::user);
        const auto before = f.db->get_user("bob")->hash_hex;
        auto s = mgr.create_local_session_for_test("bob", Role::user, false);
        REQUIRE_FALSE(s.empty());
        CHECK(mgr.commit_password_change(
                      mkreq(Kind::kSelf, "bob", kNew, std::string(before.size(), 'f')))
                  .result == Result::kConflict);
        CHECK(mgr.commit_password_change(mkreq(Kind::kSelf, "bob", kNew, std::string{})).result ==
              Result::kConflict);
        CHECK(mgr.commit_password_change(mkreq(Kind::kSelf, "bob", kNew, std::nullopt)).result ==
              Result::kConflict);
        check_untouched("bob", before, s);
        CHECK(vrole(mgr, "bob", kOld) == Role::user);
    }
    SECTION("SCIM-provisioned is kNotLocal (both kinds)") {
        seed_local(*f.db, "scimmy", kOld, Role::user);
        const auto before = f.db->get_user("scimmy")->hash_hex;
        auto s = mgr.create_local_session_for_test("scimmy", Role::user, false);
        REQUIRE(f.db->set_provisioning_source("scimmy", "scim").has_value());
        CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "scimmy", kNew)).result ==
              Result::kNotLocal);
        CHECK(mgr.commit_password_change(mkreq(Kind::kSelf, "scimmy", kNew, before)).result ==
              Result::kNotLocal);
        check_untouched("scimmy", before, s);
    }
    SECTION("identity_source not local is kNotLocal") {
        seed_local(*f.db, "idp_user", kOld, Role::user);
        const auto before = f.db->get_user("idp_user")->hash_hex;
        auto s = mgr.create_local_session_for_test("idp_user", Role::user, false);
        REQUIRE(f.db->set_identity_source("idp_user", "scim").has_value());
        CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "idp_user", kNew)).result ==
              Result::kNotLocal);
        check_untouched("idp_user", before, s);
    }
    SECTION("SSO principal-shaped name is kNotLocal, absent/inactive is kNotFound") {
        const std::string principal = "oidc:https://idp.example#s1";
        REQUIRE(f.db->upsert_sso_identity(principal, "https://idp.example", "s1", "S", "oidc")
                    .has_value());
        CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, principal, kNew)).result ==
              Result::kNotLocal);
        CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "ghost", kNew)).result ==
              Result::kNotFound);
        seed_local(*f.db, "removed", kOld, Role::user);
        REQUIRE(f.db->remove_user("removed").has_value());
        CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "removed", kNew)).result ==
              Result::kNotFound);
        CHECK(f.audit_total() == 0);
    }
}

TEST_CASE("commit_password_change (admin): a plain write, no target-role classification",
          "[pg][auth][password]") {
    // Who may reset whom is decided ONCE, at the route, by is_rbac_administrator.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "root2", kOld, Role::admin);
    const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "root2", kNew));
    REQUIRE(r.result == Result::kOk);
    CHECK(r.target_role == "admin");
    CHECK(vrole(mgr, "root2", kNew) == Role::admin);
    CHECK_FALSE(vrole(mgr, "root2", kOld).has_value());
    CHECK(f.audit_detail("user.password_reset", "root2") ==
          "admin_reset target_role=admin sessions_revoked=0 provisional_mfa_cleared=false");
}

TEST_CASE("commit_password_change (admin): the lockout clears IN the transaction, audited iff it "
          "existed",
          "[pg][auth][password][lockout]") {
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);

    SECTION("a locked account: cleared + one auth.lockout.cleared row") {
        seed_local(*f.db, "lockie", kOld, Role::user);
        for (int i = 0; i < 3; ++i)
            REQUIRE(f.db->record_failed_login("lockie", 3, 3600).has_value());
        REQUIRE(f.db->lockout_status("lockie")->locked);
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "lockie", kNew));
        REQUIRE(r.result == Result::kOk);
        CHECK(r.lockout_cleared);
        const auto after = f.db->lockout_status("lockie");
        REQUIRE(after.has_value());
        CHECK_FALSE(after->locked);
        CHECK(after->failed_count == 0);
        CHECK(f.audit_rows("auth.lockout.cleared", "lockie") == 1);
        CHECK(f.audit_detail("auth.lockout.cleared", "lockie") == "password_reset");
    }
    SECTION("a never-locked account: lockout_cleared=false and NO auth.lockout.cleared row") {
        seed_local(*f.db, "calm", kOld, Role::user);
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "calm", kNew));
        REQUIRE(r.result == Result::kOk);
        CHECK_FALSE(r.lockout_cleared);
        CHECK(f.audit_rows("auth.lockout.cleared", "calm") == 0);
        CHECK(f.audit_rows("user.password_reset", "calm") == 1);
    }
    SECTION("a self change leaves an armed lock armed") {
        seed_local(*f.db, "selfie", kOld, Role::user);
        const auto anchor = anchor_of(mgr, "selfie", kOld);
        for (int i = 0; i < 2; ++i)
            REQUIRE(f.db->record_failed_login("selfie", 5, 3600).has_value());
        const auto r = mgr.commit_password_change(mkreq(Kind::kSelf, "selfie", kNew, anchor));
        REQUIRE(r.result == Result::kOk);
        CHECK_FALSE(r.lockout_cleared);
        CHECK(f.db->lockout_status("selfie")->failed_count == 2);
        CHECK(f.audit_rows("auth.lockout.cleared", "selfie") == 0);
    }
}

TEST_CASE("commit_password_change: a provisional TOTP secret is wiped; an enrolled one is kept",
          "[pg][auth][password][mfa]") {
    // F1 (chaos R4 inverted) + F3.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);

    SECTION("admin reset wipes a provisional secret; the next enrolment gets a NEW one") {
        seed_local(*f.db, "vic", kOld, Role::user);
        auto s1 = f.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
        REQUIRE(s1.has_value());
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "vic", kNew));
        REQUIRE(r.result == Result::kOk);
        CHECK(r.provisional_mfa_cleared);
        CHECK(f.audit_detail("user.password_reset", "vic").ends_with("provisional_mfa_cleared=true"));
        auto st = f.db->mfa_status("vic");
        REQUIRE(st.has_value());
        CHECK_FALSE(st->enrolled);
        auto s2 = f.db->mfa_init_enrollment("vic", "Yuzu", std::nullopt);
        REQUIRE(s2.has_value());
        CHECK(s1->secret_base32 != s2->secret_base32);
    }
    SECTION("self change wipes a provisional secret too") {
        seed_local(*f.db, "pia", kOld, Role::user);
        auto s1 = f.db->mfa_init_enrollment("pia", "Yuzu", std::nullopt);
        REQUIRE(s1.has_value());
        const auto r = mgr.commit_password_change(
            mkreq(Kind::kSelf, "pia", kNew, anchor_of(mgr, "pia", kOld)));
        REQUIRE(r.result == Result::kOk);
        CHECK(r.provisional_mfa_cleared);
        auto s2 = f.db->mfa_init_enrollment("pia", "Yuzu", std::nullopt);
        REQUIRE(s2.has_value());
        CHECK(s1->secret_base32 != s2->secret_base32);
    }
    SECTION("an ENROLLED secret and its recovery codes survive a reset (F3)") {
        seed_local(*f.db, "eno", kOld, Role::user);
        auto init = f.db->mfa_init_enrollment("eno", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto codes = f.db->mfa_verify_enrollment("eno", code_for_now(init->secret_base32),
                                                 std::nullopt);
        REQUIRE(codes.has_value());
        const auto before = f.db->mfa_status("eno");
        REQUIRE(before.has_value());
        REQUIRE(before->enrolled);
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "eno", kNew));
        REQUIRE(r.result == Result::kOk);
        CHECK_FALSE(r.provisional_mfa_cleared);
        const auto after = f.db->mfa_status("eno");
        REQUIRE(after.has_value());
        CHECK(after->enrolled);
        CHECK(after->recovery_codes_remaining == before->recovery_codes_remaining);
        // The enrolled secret still verifies a fresh code.
        auto again = f.db->mfa_init_enrollment("eno", "Yuzu", std::nullopt);
        REQUIRE_FALSE(again.has_value());
        CHECK(again.error() == yuzu::server::AuthDBError::MfaAlreadyEnrolled);
    }
}

TEST_CASE("commit_password_change: a REAL audit statement fault rolls the whole change back",
          "[pg][auth][password][audit]") {
    // T1(ii) at the owner seam: the audit table is renamed in the throwaway
    // database, so the in-transaction INSERT genuinely fails.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "ivy", kOld, Role::user);
    const auto before = f.db->get_user("ivy")->hash_hex;
    auto s = mgr.create_local_session("ivy", Role::user, false, anchor_of(mgr, "ivy", kOld));
    REQUIRE_FALSE(s.empty());
    f.exec("ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone");

    const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "ivy", kNew));
    CHECK(r.result == Result::kAuditUnavailable);
    CHECK(f.db->get_user("ivy")->hash_hex == before);
    CHECK(mgr.validate_session(s).has_value());
    CHECK(f.sessions_of("ivy") == 1);
    CHECK(vrole(mgr, "ivy", kOld) == Role::user);
    CHECK_FALSE(vrole(mgr, "ivy", kNew).has_value());
    CHECK(f.audit.emit_failed_count() >= 1);
}

TEST_CASE("commit_password_change (admin): a fault on ONLY the auth.lockout.cleared row rolls "
          "the whole change back",
          "[pg][auth][password][audit][lockout]") {
    // The second in-transaction row is atomic with the credential change: the
    // user.password_reset INSERT succeeds, the lockout row alone faults, and
    // nothing commits. Distinguishes "both rows in the transaction" from "the
    // lockout row written post-commit", which a whole-table fault cannot.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "lockd", kOld, Role::user);
    const auto before = f.db->get_user("lockd")->hash_hex;
    auto s = mgr.create_local_session("lockd", Role::user, false, anchor_of(mgr, "lockd", kOld));
    REQUIRE_FALSE(s.empty());
    for (int i = 0; i < 3; ++i)
        REQUIRE(f.db->record_failed_login("lockd", 3, 3600).has_value());
    const auto armed = f.db->lockout_status("lockd");
    REQUIRE(armed->locked);
    f.fault_audit_for_action("auth.lockout.cleared");

    const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "lockd", kNew));
    CHECK(r.result == Result::kAuditUnavailable);
    CHECK_FALSE(r.lockout_cleared);
    CHECK(f.db->get_user("lockd")->hash_hex == before);
    CHECK(mgr.validate_session(s).has_value());
    CHECK(f.sessions_of("lockd") == 1);
    const auto st = f.db->lockout_status("lockd");
    REQUIRE(st.has_value());
    CHECK(st->locked);
    CHECK(st->failed_count == armed->failed_count);
    CHECK(f.audit_rows("user.password_reset", "lockd") == 0);
    CHECK(f.audit_rows("auth.lockout.cleared", "lockd") == 0);
}

TEST_CASE("commit_password_change: audit-row presence <=> new-hash presence, on abort and commit "
          "failure",
          "[pg][auth][password][audit]") {
    // T1(iv). The owner's evidence and its credential land together or not at
    // all — whichever way the transaction ends.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "ada", kOld, Role::user);
    const auto before = f.db->get_user("ada")->hash_hex;

    SECTION("forced abort inside the transaction (pre-commit hook throws)") {
        f.owner.set_pre_commit_hook_for_test([] { throw std::runtime_error("forced abort"); });
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "ada", kNew));
        f.owner.set_pre_commit_hook_for_test(nullptr);
        CHECK(r.result == Result::kStoreUnavailable);
        CHECK(f.db->get_user("ada")->hash_hex == before);
        CHECK(f.audit_rows("user.password_reset", "ada") == 0);
    }
    SECTION("COMMIT itself fails (a deferred constraint trigger raises at commit)") {
        f.exec("CREATE FUNCTION public.yuzu_test_fail_commit() RETURNS trigger LANGUAGE plpgsql AS "
               "$$ BEGIN RAISE EXCEPTION 'forced commit failure'; END $$");
        f.exec("CREATE CONSTRAINT TRIGGER yuzu_test_fail_commit AFTER INSERT ON "
               "audit_store.audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE "
               "FUNCTION public.yuzu_test_fail_commit()");
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "ada", kNew));
        CHECK(r.result == Result::kStoreUnavailable);
        CHECK(f.db->get_user("ada")->hash_hex == before);
        CHECK(f.audit_rows("user.password_reset", "ada") == 0);
        CHECK(vrole(mgr, "ada", kOld) == Role::user);
    }
    SECTION("commit succeeds: both present") {
        const auto r = mgr.commit_password_change(mkreq(Kind::kAdminReset, "ada", kNew));
        REQUIRE(r.result == Result::kOk);
        CHECK(f.db->get_user("ada")->hash_hex != before);
        CHECK(f.audit_rows("user.password_reset", "ada") == 1);
    }
}

TEST_CASE("commit_password_change fails closed without an owner or an audit store",
          "[auth][password]") {
    AuthManager mgr; // cfg-file-only: no durable credential to change
    CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "x", kNew)).result ==
          Result::kStoreUnavailable);
    yuzu::test::AuthDbPg db;
    yuzu::server::CredentialChangeOwner no_audit{db.pool(), nullptr};
    mgr.set_auth_db(db.get());
    mgr.set_credential_change_owner(&no_audit);
    seed_local(*db, "y", kOld, Role::user);
    const auto before = db->get_user("y")->hash_hex;
    CHECK(mgr.commit_password_change(mkreq(Kind::kAdminReset, "y", kNew)).result ==
          Result::kAuditUnavailable);
    CHECK(db->get_user("y")->hash_hex == before);
}

// ── The credential anchor at session mint (#5342 Gate 7 B4 + Gate 8 M1) ────

TEST_CASE("create_local_session denies a mint whose verified hash is no longer stored",
          "[pg][auth][password]") {
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "mira", kOld, Role::user);
    const auto anchor = anchor_of(mgr, "mira", kOld);

    // The anchor is current: the mint lands.
    auto ok = mgr.create_local_session("mira", Role::user, false, anchor);
    REQUIRE_FALSE(ok.empty());
    CHECK(mgr.validate_session(ok).has_value());

    // An empty anchor never disables the check — it denies (fail closed).
    CHECK(mgr.create_local_session("mira", Role::user, false, "").empty());

    // A reset after the verify: the OLD anchor can no longer mint, and the
    // denied mint leaves no live session behind.
    REQUIRE(mgr.commit_password_change(mkreq(Kind::kAdminReset, "mira", kNew)).result ==
            Result::kOk);
    CHECK(mgr.create_local_session("mira", Role::user, false, anchor).empty());
    CHECK_FALSE(mgr.validate_session(ok).has_value());
    CHECK(f.sessions_of("mira") == 0);
}

TEST_CASE("authenticate: a reset committing between the recheck and the mint revokes the session",
          "[pg][auth][password]") {
    // post_mint_race_hook_for_test fires inside authenticate() after the
    // row-locked recheck released and before the session is persisted — the
    // check-then-mint window. A reset landing there must not leave a session
    // proven with the OLD password alive.
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "rhea", kOld, Role::user);
    bool fired = false;
    mgr.set_post_mint_race_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        AuthManager other; // a second replica's admin reset
        f.wire(other);
        REQUIRE(other.commit_password_change(mkreq(Kind::kAdminReset, "rhea", kNew)).result ==
                Result::kOk);
    });
    auto token = mgr.authenticate("rhea", kOld);
    mgr.set_post_mint_race_hook_for_test(nullptr);
    CHECK(fired);
    CHECK_FALSE(token.has_value());
    CHECK(f.sessions_of("rhea") == 0);
    CHECK(vrole(mgr, "rhea", kNew) == Role::user);
}

TEST_CASE("post-mint recheck WAITS on an uncommitted credential write and then denies (M1)",
          "[pg][auth][password]") {
    // #5342 Gate 8 M1, deterministic: transaction A has executed its credential
    // UPDATE (holding the auth.users row lock) but not committed. A mint for
    // the OLD credential, started after A's UPDATE returned, must not be
    // admitted by reading the old hash past A's uncommitted write: its post-
    // mint re-read is row-locked, so it waits for A's COMMIT and then sees the
    // new hash. (A plain read here was the Gate 8 R1 defect: the mint survived
    // because A's session DELETE had already run before it existed.)
    CredInfra f;
    AuthManager mgr;
    f.wire(mgr);
    seed_local(*f.db, "mona", kOld, Role::user);
    const auto anchor = anchor_of(mgr, "mona", kOld);

    yuzu::server::pg::PgConn a{PQconnectdb(f.db.dsn().c_str())};
    REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
    f.exec_on(a.get(), "BEGIN");
    f.exec_on(a.get(), "UPDATE auth.users SET password_hash = 'deadbeef', salt_hex = 'abcd' "
                       "WHERE username = 'mona'");
    f.exec_on(a.get(), "DELETE FROM session_store.sessions WHERE username = 'mona'");

    std::string token = "unset";
    // jthread: joined on every exit path (a failed REQUIRE below never leaves a
    // joinable std::thread to std::terminate; at worst B waits out lock_timeout).
    std::jthread b([&] { token = mgr.create_local_session("mona", Role::user, false, anchor); });
    // Give B ample time to persist its session and reach the row-locked
    // re-read (where it blocks). At HEAD's plain read it would already have
    // returned a live token by now.
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    f.exec_on(a.get(), "COMMIT");
    b.join();
    CHECK(token.empty());
    CHECK(f.sessions_of("mona") == 0);
}

// ── #5274 acceptance ───────────────────────────────────────────────────────

TEST_CASE("#5274: a restart that re-seeds the OLD cfg hash does not shadow the changed password",
          "[pg][auth][password][5274]") {
    yuzu::test::TempDir dir{"yuzu_test_pwcfg_"};
    fs::create_directories(dir.path);
    const auto cfg = dir.path / "yuzu-server.cfg";
    CredInfra f;
    auto& db = f.db;

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
        f.wire(boot1);
        REQUIRE(boot1.commit_password_change(
                         mkreq(Kind::kSelf, "alice", kNew, anchor_of(boot1, "alice", kOld)))
                    .result == Result::kOk);
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
    std::size_t stale = 0;
    std::string logs;
    {
        yuzu::test::LogCapture capture{spdlog::level::warn};
        stale = boot.report_stale_cfg_credentials();
        capture.stop();
        logs = capture.text();
    }
    CHECK(stale == 1);
    CHECK(metrics.gauge("yuzu_auth_cfg_credentials_stale").value() == 1.0);
    // #5343: the no-row cfg entry is named (and only it) by the new WARN, and
    // is still NOT counted as stale. alice (matching row) and bert (diverged
    // row) must not get the no-row warning.
    CHECK(logs.find("#5343 boot check: cfg entry 'cfgonly' has no auth.users row") !=
          std::string::npos);
    CHECK(logs.find("cfg entry 'alice' has no auth.users row") == std::string::npos);
    CHECK(logs.find("cfg entry 'bert' has no auth.users row") == std::string::npos);

    AuthManager cfg_mode; // no AuthDB: nothing to compare against
    REQUIRE(cfg_mode.load_config(cfg));
    CHECK(cfg_mode.report_stale_cfg_credentials() == 0);
}

TEST_CASE("#5274: a second replica's warm cache does not keep accepting the old password",
          "[pg][auth][password][5274]") {
    CredInfra f;
    seed_local(*f.db, "erin", kOld, Role::user);

    AuthManager replica_a;
    f.wire(replica_a);
    AuthManager replica_b;
    f.wire(replica_b);
    // Warm BOTH caches with the old credential.
    REQUIRE(replica_a.authenticate("erin", kOld).has_value());
    REQUIRE(replica_b.authenticate("erin", kOld).has_value());

    REQUIRE(replica_a
                .commit_password_change(
                    mkreq(Kind::kSelf, "erin", kNew, anchor_of(replica_a, "erin", kOld)))
                .result == Result::kOk);

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
    // inside the row lock — a synchronous write there would self-deadlock;
    // see set_role_recheck_race_hook_for_test's doc.) The concurrent writer is
    // a plain UPDATE on its own connection, standing in for the credential
    // change's committed write.
    auto salt = AuthManager::random_bytes(16);
    const auto new_hash = AuthManager::pbkdf2_sha256(kNew, salt, AuthManager::kPbkdf2Iterations);
    const auto new_salt = AuthManager::bytes_to_hex(salt);
    bool fired = false;
    mgr.set_role_recheck_race_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult u{PQexec(
            c.get(), ("UPDATE auth.users SET password_hash = '" + new_hash + "', salt_hex = '" +
                      new_salt + "' WHERE username = 'fay'")
                         .c_str())};
        REQUIRE(u.ok());
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

// ── #5343: first-run setup creates the administrator ONLY ────────────────────
//
// first_run_setup used to prompt for a SECOND, non-admin "user" account and
// write it to yuzu-server.cfg. On the Postgres substrate only the admin cfg
// entry is provisioned into auth.users at first boot, so that second account
// could never sign in. The prompt is removed; this drives the real
// first_run_setup through swapped std::cin/std::cout buffers.

namespace {
/// Swap std::cin/std::cout buffers for the scope; restore on exit.
struct StdioSwap {
    explicit StdioSwap(const std::string& input) : in_(input) {
        old_in_ = std::cin.rdbuf(in_.rdbuf());
        old_out_ = std::cout.rdbuf(out_.rdbuf());
    }
    ~StdioSwap() {
        std::cin.rdbuf(old_in_);
        std::cout.rdbuf(old_out_);
    }
    StdioSwap(const StdioSwap&) = delete;
    StdioSwap& operator=(const StdioSwap&) = delete;
    [[nodiscard]] std::string output() const { return out_.str(); }

private:
    std::istringstream in_;
    std::ostringstream out_;
    std::streambuf* old_in_ = nullptr;
    std::streambuf* old_out_ = nullptr;
};
} // namespace

TEST_CASE("#5343: first_run_setup creates exactly one administrator and no second account",
          "[auth][password][5343]") {
    yuzu::test::TempDir dir{"yuzu_test_firstrun_"};
    fs::create_directories(dir.path);
    const auto cfg = dir.path / "yuzu-server.cfg";

    // Prompt order: admin name, admin password, confirm. The trailing lines
    // would answer the REMOVED second-account prompts (default name, password,
    // confirm); they must be left unread, so a regression that re-adds the
    // prompt writes a second cfg entry and fails the assertions below instead
    // of failing early on EOF.
    std::string out;
    bool ok = false;
    {
        StdioSwap io{"admin\nfirst-run-pw-12345\nfirst-run-pw-12345\n"
                     "\nsecond-run-pw-12345\nsecond-run-pw-12345\n"};
        ok = AuthManager::first_run_setup(cfg);
        out = io.output();
    }
    CHECK(ok);
    CHECK(out.find("User account") == std::string::npos);
    CHECK(out.find("User password") == std::string::npos);

    AuthManager mgr;
    REQUIRE(mgr.load_config(cfg));
    const auto users = mgr.list_users();
    REQUIRE(users.size() == 1);
    CHECK(users.front().role == Role::admin);
    CHECK(mgr.get_user_role("admin") == Role::admin);
    CHECK_FALSE(mgr.get_user_role("user").has_value());
}
