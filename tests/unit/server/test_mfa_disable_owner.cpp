/**
 * test_mfa_disable_owner.cpp -- MfaDisableOwner (#6079 PR 2c): the one-transaction
 * clear of a local account's second factor, its durable session set, its recovery
 * codes and the OUTCOME audit row.
 *
 * The cases drive the owner directly against a real AuthDB + SessionStore +
 * AuditStore on ONE pool (the production shape), inject REAL statement faults
 * inside the throwaway database (a renamed table, as test_auth_password.cpp does for
 * the credential owner), and assert the all-or-nothing contract: every fault leaves
 * the factor enrolled, the recovery codes and sessions intact and no audit row.
 *
 * PG-gated through AuthDbPg (skips when YUZU_TEST_POSTGRES_DSN is unset, fails when
 * it is set but broken).
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "audit_store.hpp"
#include "mfa_disable_owner.hpp"
#include "session_store.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_principal_lock_gate.hpp" // SqlFault, SessionWipeFault
#include "totp.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::LocalMfaProof;
using yuzu::server::MfaDisableOutcome;
using yuzu::server::MfaDisableOwner;
using yuzu::server::MfaDisableRequest;
using yuzu::server::MfaDisableResult;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

/// A TOTP code for the current step from an enrolment's base32 secret.
std::string code_for_now(const std::string& secret_b32) {
    auto bytes = yuzu::server::mfa::base32_decode(secret_b32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return yuzu::server::mfa::generate(
        raw, yuzu::server::mfa::current_counter(std::chrono::system_clock::now()));
}

/// An OUTCOME-row template as a caller builds it: action, result and identity set, detail
/// whatever the caller passes (empty for the Settings shape).
MfaDisableRequest mkreq(const std::string& user, std::optional<std::int64_t> expected_gen,
                        std::string detail = {}) {
    MfaDisableRequest r;
    r.username = user;
    r.expected_factor_gen = expected_gen;
    r.audit_template.principal = user;
    r.audit_template.principal_role = "user";
    r.audit_template.action = "mfa.disabled";
    r.audit_template.result = "ok";
    r.audit_template.target_type = "User";
    r.audit_template.target_id = user;
    r.audit_template.detail = std::move(detail);
    return r;
}

/// The production store shape on ONE pool: AuthDB + SessionStore + AuditStore + the owner
/// (server.cpp wires all of them on `*pg_pool_`), plus an AuthManager used only to mint
/// durable sessions.
struct MfaInfra {
    yuzu::test::AuthDbPg db;
    yuzu::server::SessionStore sessions{db.pool()};
    yuzu::server::AuditStore audit{db.pool()};
    MfaDisableOwner owner{db.pool(), &audit};
    AuthManager mgr;

    MfaInfra() {
        REQUIRE(sessions.is_open());
        REQUIRE(audit.is_open());
        mgr.set_auth_db(db.get());
        mgr.set_session_store(&sessions);
    }
    ~MfaInfra() {
        mgr.set_session_store(nullptr);
        mgr.set_auth_db(nullptr);
    }
    MfaInfra(const MfaInfra&) = delete;
    MfaInfra& operator=(const MfaInfra&) = delete;

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
    int codes_of(const std::string& user) {
        return std::stoi(
            scalar("SELECT count(*) FROM auth.mfa_recovery_codes WHERE username = '" + user + "'"));
    }
    std::int64_t write_generation() {
        return std::stoll(
            scalar("SELECT value FROM session_store.session_meta WHERE key = 'write_generation'"));
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

    void seed(const std::string& user, Role role = Role::user) {
        REQUIRE(db->upsert_user(user, "hash", "salt", role).has_value());
    }
    /// Seed `user` and complete an enrolment: a verified factor plus its recovery codes.
    void seed_enrolled(const std::string& user) {
        seed(user);
        auto init = db->mfa_init_enrollment(user, "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto done = db->mfa_verify_enrollment(user, code_for_now(init->secret_base32), std::nullopt);
        REQUIRE(done.has_value());
        const auto st = db->mfa_status(user);
        REQUIRE(st.has_value());
        REQUIRE(st->enrolled);
        REQUIRE(codes_of(user) > 0);
    }
    /// One durable session of `user`; returns its token.
    std::string session_for(const std::string& user) {
        auto token = mgr.create_local_session_for_test(user, Role::user, false);
        REQUIRE_FALSE(token.empty());
        return token;
    }
    std::int64_t factor_gen(const std::string& user) {
        const auto st = db->mfa_status(user);
        REQUIRE(st.has_value());
        return st->factor_gen;
    }
    bool enrolled(const std::string& user) {
        const auto st = db->mfa_status(user);
        REQUIRE(st.has_value());
        return st->enrolled;
    }
};

} // namespace

TEST_CASE("MfaDisableOwner: success clears the factor, the codes and the sessions and audits once",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("alice");
    f.seed("bob");
    const auto t1 = f.session_for("alice");
    const auto t2 = f.session_for("alice");
    const auto bob_token = f.session_for("bob");
    const auto gen_before = f.factor_gen("alice");
    REQUIRE(gen_before > 0);
    const auto write_gen_before = f.write_generation();

    SECTION("an empty template detail becomes exactly sessions_ended=<n>") {
        const auto r = f.owner.commit(mkreq("alice", gen_before));
        REQUIRE(r.result == MfaDisableResult::kOk);
        CHECK(r.was_enrolled);
        CHECK(r.sessions_ended == 2);
        CHECK_FALSE(f.enrolled("alice"));
        CHECK(f.codes_of("alice") == 0);
        CHECK(f.sessions_of("alice") == 0);
        CHECK_FALSE(f.mgr.validate_session(t1).has_value());
        CHECK_FALSE(f.mgr.validate_session(t2).has_value());
        // The trigger redrew the generation: a proof made under the cleared factor no longer binds.
        const auto gen_after = f.factor_gen("alice");
        CHECK(gen_after > 0);
        CHECK(gen_after != gen_before);
        // The durable write-generation moved, so every replica drops its cache.
        CHECK(f.write_generation() > write_gen_before);
        CHECK(f.audit_total() == 1);
        CHECK(f.audit_rows("mfa.disabled", "alice") == 1);
        CHECK(f.audit_detail("mfa.disabled", "alice") == "sessions_ended=2");
        // Another account is untouched.
        CHECK(f.sessions_of("bob") == 1);
        CHECK(f.mgr.validate_session(bob_token).has_value());
    }
    SECTION("a non-empty template detail is kept and the count appended after a space") {
        const auto r = f.owner.commit(mkreq("alice", gen_before, "MFA cleared via test"));
        REQUIRE(r.result == MfaDisableResult::kOk);
        CHECK(f.audit_detail("mfa.disabled", "alice") == "MFA cleared via test sessions_ended=2");
    }
}

TEST_CASE("MfaDisableOwner: no expected generation (the CLI shape) clears the same way",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("carol");
    (void)f.session_for("carol");

    const auto r = f.owner.commit(mkreq("carol", std::nullopt));
    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK(r.was_enrolled);
    CHECK(r.sessions_ended == 1);
    CHECK_FALSE(f.enrolled("carol"));
    CHECK(f.codes_of("carol") == 0);
    CHECK(f.sessions_of("carol") == 0);
    CHECK(f.audit_rows("mfa.disabled", "carol") == 1);
}

TEST_CASE("MfaDisableOwner: an un-enrolled account still succeeds and reports was_enrolled=false",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed("dave");
    (void)f.session_for("dave");
    const auto gen = f.factor_gen("dave");

    const auto r = f.owner.commit(mkreq("dave", gen));
    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK_FALSE(r.was_enrolled);
    CHECK(r.sessions_ended == 1);
    CHECK(f.sessions_of("dave") == 0);
    CHECK(f.audit_detail("mfa.disabled", "dave") == "sessions_ended=1");
}

TEST_CASE("MfaDisableOwner: no active account is kNotFound and writes nothing",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed("erin");
    (void)f.session_for("erin");
    REQUIRE(f.db->remove_user("erin").has_value()); // soft delete: the row is now inactive
    const auto write_gen_before = f.write_generation();

    SECTION("unknown account, no expected generation") {
        CHECK(f.owner.commit(mkreq("ghost", std::nullopt)).result == MfaDisableResult::kNotFound);
    }
    SECTION("unknown account, expected generation engaged") {
        CHECK(f.owner.commit(mkreq("ghost", 7)).result == MfaDisableResult::kNotFound);
    }
    SECTION("inactive account") {
        CHECK(f.owner.commit(mkreq("erin", std::nullopt)).result == MfaDisableResult::kNotFound);
        CHECK(f.owner.commit(mkreq("erin", 0)).result == MfaDisableResult::kNotFound);
    }
    SECTION("a malformed name") {
        CHECK(f.owner.commit(mkreq("not a valid name!", std::nullopt)).result ==
              MfaDisableResult::kNotFound);
    }
    CHECK(f.audit_total() == 0);
    CHECK(f.sessions_of("erin") == 1); // the session of the inactive account is not this owner's
    CHECK(f.write_generation() == write_gen_before);
}

TEST_CASE("MfaDisableOwner: a stale expected generation is kFactorChanged and writes nothing",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("frank");
    const auto token = f.session_for("frank");
    const auto gen = f.factor_gen("frank");
    const auto codes_before = f.codes_of("frank");
    const auto write_gen_before = f.write_generation();

    const auto r = f.owner.commit(mkreq("frank", gen + 1));
    CHECK(r.result == MfaDisableResult::kFactorChanged);
    CHECK(f.enrolled("frank"));
    CHECK(f.factor_gen("frank") == gen);
    CHECK(f.codes_of("frank") == codes_before);
    CHECK(f.sessions_of("frank") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.audit_total() == 0);
    CHECK(f.write_generation() == write_gen_before);
}

TEST_CASE("MfaDisableOwner: a faulted session DELETE rolls the whole clear back",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("gina");
    (void)f.session_for("gina");
    const auto gen = f.factor_gen("gina");
    const auto codes_before = f.codes_of("gina");

    yuzu::test::SessionWipeFault fault{f.db.pool()};
    fault.arm();
    const auto r = f.owner.commit(mkreq("gina", gen));
    fault.repair();

    CHECK(r.result == MfaDisableResult::kStoreUnavailable);
    // The clear was in the same transaction as the failed DELETE: the factor is still enrolled.
    CHECK(f.enrolled("gina"));
    CHECK(f.factor_gen("gina") == gen);
    CHECK(f.codes_of("gina") == codes_before);
    CHECK(f.sessions_of("gina") == 1);
    CHECK(f.audit_total() == 0);
}

TEST_CASE("MfaDisableOwner: a REAL audit statement fault rolls the whole clear back",
          "[pg][auth][mfa][mfa_disable_owner][audit]") {
    MfaInfra f;
    f.seed_enrolled("hugo");
    const auto token = f.session_for("hugo");
    const auto gen = f.factor_gen("hugo");
    const auto codes_before = f.codes_of("hugo");

    yuzu::test::SqlFault fault{f.db.pool(),
                               "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events"};
    fault.arm();
    const auto r = f.owner.commit(mkreq("hugo", gen));
    fault.repair();

    CHECK(r.result == MfaDisableResult::kAuditUnavailable);
    CHECK(f.enrolled("hugo"));
    CHECK(f.factor_gen("hugo") == gen);
    CHECK(f.codes_of("hugo") == codes_before);
    CHECK(f.sessions_of("hugo") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.audit.emit_failed_count() >= 1);
    CHECK(f.audit_total() == 0);
}

TEST_CASE("MfaDisableOwner: a forced abort before COMMIT leaves everything untouched",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("iris");
    (void)f.session_for("iris");
    const auto gen = f.factor_gen("iris");
    const auto codes_before = f.codes_of("iris");
    const auto wg = f.write_generation();

    f.owner.set_pre_commit_hook_for_test([] { throw std::runtime_error("forced abort"); });
    const auto r = f.owner.commit(mkreq("iris", gen));
    f.owner.set_pre_commit_hook_for_test(nullptr);

    CHECK(r.result == MfaDisableResult::kStoreUnavailable);
    CHECK(f.enrolled("iris"));
    CHECK(f.factor_gen("iris") == gen);
    CHECK(f.codes_of("iris") == codes_before);
    CHECK(f.sessions_of("iris") == 1);
    CHECK(f.audit_total() == 0);
    // The generation bump ran before the hook, inside the same transaction: it rolled back too.
    CHECK(f.write_generation() == wg);
}

// The session write-generation bump is the LAST statement before COMMIT (step d of the banner), so
// a fault on its table is the "fails after everything else succeeded" case: the factor clear, the
// recovery-code delete, the session delete and the audit INSERT have all run in the transaction
// and must all disappear with it.
TEST_CASE("MfaDisableOwner: a faulted session_meta bump rolls the whole clear back",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("olga");
    const auto token = f.session_for("olga");
    const auto gen = f.factor_gen("olga");
    const auto codes_before = f.codes_of("olga");
    const auto wg = f.write_generation();

    yuzu::test::SqlFault fault{f.db.pool(),
                               "ALTER TABLE session_store.session_meta RENAME TO session_meta_gone",
                               "ALTER TABLE session_store.session_meta_gone RENAME TO session_meta"};
    fault.arm();
    const auto r = f.owner.commit(mkreq("olga", gen));
    fault.repair();

    CHECK(r.result == MfaDisableResult::kStoreUnavailable);
    CHECK(f.enrolled("olga"));
    CHECK(f.factor_gen("olga") == gen);
    CHECK(f.codes_of("olga") == codes_before);
    CHECK(f.sessions_of("olga") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.audit_total() == 0);
    CHECK(f.write_generation() == wg);
}

// The mirror: an account with no verified factor and `end_sessions_if_not_enrolled = false` takes
// no `session_meta` lock and runs no generation bump, so the same fault is invisible to it. This
// pins that the skipped path really skips the statement (a regression that bumped anyway would
// fail here with kStoreUnavailable).
TEST_CASE("MfaDisableOwner: the same session_meta fault does not touch the un-enrolled "
          "skip-sessions path",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed("pete");
    const auto token = f.session_for("pete");
    const auto gen = f.factor_gen("pete");
    const auto wg = f.write_generation();

    yuzu::test::SqlFault fault{f.db.pool(),
                               "ALTER TABLE session_store.session_meta RENAME TO session_meta_gone",
                               "ALTER TABLE session_store.session_meta_gone RENAME TO session_meta"};
    fault.arm();
    auto req = mkreq("pete", gen, "ignored when the account was not enrolled");
    req.end_sessions_if_not_enrolled = false;
    req.detail_if_not_enrolled = "no verified factor to clear";
    const auto r = f.owner.commit(req);
    fault.repair();

    CHECK(r.result == MfaDisableResult::kOk);
    CHECK_FALSE(r.was_enrolled);
    CHECK(r.sessions_ended == 0);
    CHECK(f.sessions_of("pete") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.audit_rows("mfa.disabled", "pete") == 1);
    CHECK(f.write_generation() == wg);
}

TEST_CASE("MfaDisableOwner: no audit store wired is kAuditUnavailable and writes nothing",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("jane");
    (void)f.session_for("jane");
    const auto gen = f.factor_gen("jane");
    const auto codes_before = f.codes_of("jane");

    MfaDisableOwner no_audit{f.db.pool(), nullptr};
    const auto r = no_audit.commit(mkreq("jane", gen));

    CHECK(r.result == MfaDisableResult::kAuditUnavailable);
    CHECK(f.enrolled("jane"));
    CHECK(f.factor_gen("jane") == gen);
    CHECK(f.codes_of("jane") == codes_before);
    CHECK(f.sessions_of("jane") == 1);
    CHECK(f.audit_total() == 0);
}

TEST_CASE("mfa_disable_complete_detail: placeholder substitution and the append fallback",
          "[auth][mfa][mfa_disable_owner]") {
    using yuzu::server::mfa_disable_complete_detail;
    SECTION("a single placeholder is replaced by the count") {
        CHECK(mfa_disable_complete_detail("MFA cleared (sessions_ended={sessions_ended})", 3) ==
              "MFA cleared (sessions_ended=3)");
    }
    SECTION("every occurrence is replaced") {
        CHECK(mfa_disable_complete_detail("{sessions_ended} and {sessions_ended}/{sessions_ended}",
                                          12) == "12 and 12/12");
    }
    SECTION("a placeholder suppresses the append") {
        CHECK(mfa_disable_complete_detail("n={sessions_ended}", 0) == "n=0");
    }
    SECTION("no placeholder: empty becomes exactly sessions_ended=<n>") {
        CHECK(mfa_disable_complete_detail("", 2) == "sessions_ended=2");
    }
    SECTION("no placeholder: non-empty gets the count appended after a space") {
        CHECK(mfa_disable_complete_detail("MFA cleared via test", 2) ==
              "MFA cleared via test sessions_ended=2");
    }
    SECTION("a near-miss token is not a placeholder") {
        CHECK(mfa_disable_complete_detail("{sessions_ended", 1) == "{sessions_ended sessions_ended=1");
        CHECK(mfa_disable_complete_detail("{Sessions_Ended}", 1) ==
              "{Sessions_Ended} sessions_ended=1");
    }
    SECTION("a count inside a partial token leaves the partial token literal") {
        // The substituted text is digits only, so it can never complete a token and "never
        // re-scanned" is not observable here (a re-scanning implementation would give the same
        // answer). What this pins: the surrounding partial tokens stay literal and exactly one
        // substitution happens.
        CHECK(mfa_disable_complete_detail("{sessions_{sessions_ended}ended}", 5) ==
              "{sessions_5ended}");
    }
}

TEST_CASE("MfaDisableOwner: the placeholder shapes the committed outcome row",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("kate");
    (void)f.session_for("kate");
    (void)f.session_for("kate");

    const auto r = f.owner.commit(
        mkreq("kate", std::nullopt,
              "MFA enrollment cleared via --mfa-reset CLI (os_identity=root, "
              "sessions_ended={sessions_ended})"));
    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK(f.audit_detail("mfa.disabled", "kate") ==
          "MFA enrollment cleared via --mfa-reset CLI (os_identity=root, sessions_ended=2)");
}

TEST_CASE("MfaDisableOwner: un-enrolled with end_sessions_if_not_enrolled=false leaves sessions "
          "alone",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed("liam");
    const auto token = f.session_for("liam");
    const auto gen = f.factor_gen("liam");
    const auto write_gen_before = f.write_generation();

    auto req = mkreq("liam", gen, "ignored when the account was not enrolled");
    req.end_sessions_if_not_enrolled = false;
    req.detail_if_not_enrolled = "no verified factor to clear";
    const auto r = f.owner.commit(req);

    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK_FALSE(r.was_enrolled);
    CHECK(r.sessions_ended == 0);
    CHECK(f.sessions_of("liam") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.write_generation() == write_gen_before); // no fleet-wide generation bump
    CHECK(f.audit_total() == 1);
    CHECK(f.audit_rows("mfa.disabled", "liam") == 1);
    CHECK(f.audit_detail("mfa.disabled", "liam") == "no verified factor to clear");
}

TEST_CASE("MfaDisableOwner: un-enrolled with end_sessions_if_not_enrolled=true ends sessions and "
          "bumps the generation",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed("mona");
    (void)f.session_for("mona");
    const auto write_gen_before = f.write_generation();

    auto req = mkreq("mona", std::nullopt, "cleared (sessions_ended={sessions_ended})");
    req.end_sessions_if_not_enrolled = true;
    req.detail_if_not_enrolled = "must not be used";
    const auto r = f.owner.commit(req);

    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK_FALSE(r.was_enrolled);
    CHECK(r.sessions_ended == 1);
    CHECK(f.sessions_of("mona") == 0);
    CHECK(f.write_generation() > write_gen_before);
    CHECK(f.audit_detail("mfa.disabled", "mona") == "cleared (sessions_ended=1)");
}

TEST_CASE("MfaDisableOwner: an ENROLLED account ends its sessions even when the flag is false",
          "[pg][auth][mfa][mfa_disable_owner]") {
    MfaInfra f;
    f.seed_enrolled("nina");
    (void)f.session_for("nina");
    const auto gen = f.factor_gen("nina");

    auto req = mkreq("nina", gen);
    req.end_sessions_if_not_enrolled = false;
    req.detail_if_not_enrolled = "must not be used";
    const auto r = f.owner.commit(req);

    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK(r.was_enrolled);
    CHECK(r.sessions_ended == 1);
    CHECK(f.sessions_of("nina") == 0);
    CHECK(f.audit_detail("mfa.disabled", "nina") == "sessions_ended=1");
}

// Concurrency (#6079 PR 2c)
//
// Every case below parks a second actor on a REAL Postgres lock while the owner holds its whole
// lock set, through the pre-commit hook (every lock in the banner's order is held there) and
// `yuzu::test::wait_for_lock_waiter`, which observes a backend blocked on a row or advisory lock.
// The hook never waits on the held rows themselves, only on the observation that the other
// actor is parked, so it cannot self-deadlock; the wait is bounded (`kLockWaitDeadline`) and a
// failing observation is reported by a CHECK after the commit, never by a throw inside the hook.
// Worker threads are joined by `yuzu::test::Workers` on every exit path. No sleeps.

namespace {

/// Clears the owner's test hook on scope exit so a failing REQUIRE cannot leave a lambda that
/// captures test locals installed on a fixture that outlives it.
struct OwnerHookReset {
    MfaDisableOwner& owner;
    ~OwnerHookReset() { owner.set_pre_commit_hook_for_test(nullptr); }
};

std::int64_t db_now_ms(MfaInfra& f) {
    return std::stoll(f.scalar("SELECT (extract(epoch from now())*1000)::bigint"));
}

} // namespace

TEST_CASE("MfaDisableOwner: a proof stamp racing the clear never leaves a usable proof",
          "[pg][auth][mfa][mfa_disable_owner][concurrency]") {
    MfaInfra f;
    f.seed_enrolled("pia");
    const auto t_clear = f.session_for("pia");
    const auto t_stamp = f.session_for("pia");
    const auto gen = f.factor_gen("pia");
    // An instant safely in the past on the database clock, so only the race can refuse the stamp.
    const std::int64_t verified_ms = db_now_ms(f) - 1000;

    yuzu::test::Workers workers{[] {}};
    OwnerHookReset reset{f.owner};
    std::atomic<bool> stamper_parked{false};
    std::atomic<bool> stamped{true};
    // Inside the hook the owner holds the account row, the (deleted) session rows and the
    // session_meta row, uncommitted. A stamp of the OTHER session of the account started now
    // queues on that session's row (the clear deleted it) until the owner commits.
    f.owner.set_pre_commit_hook_for_test([&] {
        workers.add([&] {
            stamped = f.mgr.mark_session_mfa_verified(t_stamp, LocalMfaProof{gen, verified_ms});
        });
        stamper_parked = yuzu::test::wait_for_lock_waiter(f.db.pool());
    });

    const auto r = f.owner.commit(mkreq("pia", gen));
    workers.join_all();

    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK(stamper_parked.load()); // the race was real: the stamp was blocked when the clear committed
    CHECK(r.sessions_ended == 2);
    // The stamp lost: the session it targeted was deleted by the committed clear.
    CHECK_FALSE(stamped.load());
    CHECK(f.sessions_of("pia") == 0);
    CHECK_FALSE(f.mgr.validate_session(t_stamp).has_value());
    CHECK_FALSE(f.mgr.validate_session(t_clear).has_value());
    CHECK_FALSE(f.enrolled("pia"));
    CHECK(f.audit_rows("mfa.disabled", "pia") == 1);
}

TEST_CASE("MfaDisableOwner: two commits at the same admitted generation clear exactly once",
          "[pg][auth][mfa][mfa_disable_owner][concurrency]") {
    MfaInfra f;
    f.seed_enrolled("quin");
    (void)f.session_for("quin");
    (void)f.session_for("quin");
    (void)f.session_for("quin");
    const auto gen = f.factor_gen("quin");

    yuzu::test::Workers workers{[] {}};
    OwnerHookReset reset{f.owner};
    std::atomic<bool> loser_parked{false};
    // Only the winner reaches the hook (the loser is refused before it). Holding the winner there
    // until the loser is parked on the account row makes the overlap certain, whichever thread wins.
    f.owner.set_pre_commit_hook_for_test(
        [&] { loser_parked = yuzu::test::wait_for_lock_waiter(f.db.pool()); });

    MfaDisableOutcome outcomes[2];
    workers.add([&] { outcomes[0] = f.owner.commit(mkreq("quin", gen)); });
    workers.add([&] { outcomes[1] = f.owner.commit(mkreq("quin", gen)); });
    workers.join_all();

    CHECK(loser_parked.load());
    int ok = 0, changed = 0, ended = 0;
    for (const auto& o : outcomes) {
        if (o.result == MfaDisableResult::kOk) {
            ++ok;
            ended += o.sessions_ended;
        } else if (o.result == MfaDisableResult::kFactorChanged) {
            ++changed;
            CHECK(o.sessions_ended == 0);
        }
    }
    CHECK(ok == 1);
    CHECK(changed == 1);
    CHECK(ended == 3); // the sessions were counted once, by the winner
    CHECK_FALSE(f.enrolled("quin"));
    CHECK(f.sessions_of("quin") == 0);
    CHECK(f.audit_total() == 1);
    CHECK(f.audit_rows("mfa.disabled", "quin") == 1);
    CHECK(f.audit_detail("mfa.disabled", "quin") == "sessions_ended=3");
}

TEST_CASE("MfaDisableOwner: a stalled account row lock answers kStoreUnavailable within the write "
          "timeout and changes nothing",
          "[pg][auth][mfa][mfa_disable_owner][concurrency]") {
    MfaInfra f;
    f.seed_enrolled("rosa");
    const auto token = f.session_for("rosa");
    const auto gen = f.factor_gen("rosa");
    const auto codes_before = f.codes_of("rosa");
    const auto wg = f.write_generation();

    MfaDisableOutcome r;
    std::chrono::milliseconds elapsed{0};
    {
        // A second connection holds the account's row lock for the whole commit attempt.
        yuzu::test::HeldLocks held{f.db.pool()};
        held.run("SELECT 1 FROM auth.users WHERE username = 'rosa' FOR UPDATE");
        const auto t0 = std::chrono::steady_clock::now();
        r = f.owner.commit(mkreq("rosa", gen));
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        held.rollback();
    }

    CHECK(r.result == MfaDisableResult::kStoreUnavailable);
    // It waited out its own bound (the lock_timeout) and then gave up, rather than failing at once
    // for another reason or hanging: at least half the bound, at most the bound plus a generous
    // margin for a slow runner.
    CHECK(elapsed >= MfaDisableOwner::kWriteTimeout / 2);
    CHECK(elapsed < MfaDisableOwner::kWriteTimeout + std::chrono::milliseconds(5000));
    CHECK(f.enrolled("rosa"));
    CHECK(f.factor_gen("rosa") == gen);
    CHECK(f.codes_of("rosa") == codes_before);
    CHECK(f.sessions_of("rosa") == 1);
    CHECK(f.mgr.validate_session(token).has_value());
    CHECK(f.audit_total() == 0);
    CHECK(f.write_generation() == wg);
}

TEST_CASE("MfaDisableOwner: a sign-in minting a session while the clear commits neither "
          "deadlocks nor half-applies",
          "[pg][auth][mfa][mfa_disable_owner][concurrency]") {
    MfaInfra f;
    f.seed_enrolled("tess");
    const auto old_token = f.session_for("tess");
    const auto gen = f.factor_gen("tess");

    yuzu::test::Workers workers{[] {}};
    OwnerHookReset reset{f.owner};
    std::atomic<bool> minter_parked{false};
    std::string minted;
    // The mint queues on the session_meta row the owner holds (every session create bumps the
    // write generation), so it can only finish after the commit.
    f.owner.set_pre_commit_hook_for_test([&] {
        workers.add([&] { minted = f.mgr.create_local_session_for_test("tess", Role::user, false); });
        minter_parked = yuzu::test::wait_for_lock_waiter(f.db.pool());
    });

    const auto r = f.owner.commit(mkreq("tess", gen));
    workers.join_all();

    REQUIRE(r.result == MfaDisableResult::kOk);
    CHECK(minter_parked.load());
    // The clear counted only the session that existed when it ran.
    CHECK(r.sessions_ended == 1);
    CHECK_FALSE(f.enrolled("tess"));
    CHECK_FALSE(f.mgr.validate_session(old_token).has_value());
    // The sign-in completed after the commit (no deadlock, no lock_timeout failure), and its
    // session is the only one the account has: whole before, whole after.
    REQUIRE_FALSE(minted.empty());
    CHECK(f.mgr.validate_session(minted).has_value());
    CHECK(f.sessions_of("tess") == 1);
    CHECK(f.audit_rows("mfa.disabled", "tess") == 1);
}
