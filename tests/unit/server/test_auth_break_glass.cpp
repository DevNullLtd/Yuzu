/**
 * test_auth_break_glass.cpp — AuthDB break-glass arming method tests.
 *
 * Drives AuthDB::break_glass_status / arm_break_glass against a per-test temp
 * auth.db with a fresh schema (migration v4). SOC 2 CC6.6 — `/auth-and-authz`
 * skill gap matrix P0 #3 (hardened mode + break-glass). Verifies:
 *   - a fresh user is dormant (not armed)
 *   - arm_break_glass arms the account and returns a future armed_until
 *   - re-arming extends/refreshes the window (idempotent)
 *   - an expired window auto-disarms (no background job) — the same
 *     CURRENT_TIMESTAMP comparison the login gate relies on
 *   - arming a non-existent account returns UserNotFound (no silent no-op)
 *   - a malformed username is rejected with InvalidUsername on both methods
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <thread>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

struct BreakGlassFixture {
    // AuthDbPg defaults to cleanup_interval_secs=0 — no background reaper
    // jthread (matches the lockout fixture).
    yuzu::test::AuthDbPg db;

    BreakGlassFixture() {
        auto salt = AuthManager::random_bytes(16);
        auto salt_hex = AuthManager::bytes_to_hex(salt);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("alice", hash, salt_hex, Role::admin).has_value());
    }

    // Complete a real MFA enrollment for `name` so break_glass_account_problem
    // sees an enrolled second factor.
    void enroll_mfa(const std::string& name) {
        auto init = db->mfa_init_enrollment(name, "Yuzu");
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment(name, code).has_value());
    }
};

} // namespace

TEST_CASE_METHOD(BreakGlassFixture, "fresh user is dormant (not armed)", "[pg][auth][breakglass]") {
    auto st = db->break_glass_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->armed);
    CHECK(st->armed_until.empty());
}

TEST_CASE_METHOD(BreakGlassFixture, "arm_break_glass arms the account", "[pg][auth][breakglass]") {
    auto armed = db->arm_break_glass("alice", 3600);
    REQUIRE(armed.has_value());
    CHECK(armed->armed);
    CHECK_FALSE(armed->armed_until.empty());

    // A separate status read agrees (the SQL armed-ness is computed against the
    // DB clock, so this is the exact predicate the login gate evaluates).
    auto st = db->break_glass_status("alice");
    REQUIRE(st.has_value());
    CHECK(st->armed);
    CHECK(st->armed_until == armed->armed_until);
}

TEST_CASE_METHOD(BreakGlassFixture, "disarm_break_glass rolls back an arm", "[pg][auth][breakglass]") {
    // The compensating un-arm used when the mandatory audit row fails to persist
    // (review #1735 HIGH-2) — so the exemption is never left standing without a
    // record.
    REQUIRE(db->arm_break_glass("alice", 3600).has_value());
    REQUIRE(db->break_glass_status("alice")->armed);

    REQUIRE(db->disarm_break_glass("alice").has_value());
    auto st = db->break_glass_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->armed);
    CHECK(st->armed_until.empty());

    // Idempotent: disarming an already-dormant account (and a non-existent one)
    // is success — the desired post-state ("not armed") already holds.
    CHECK(db->disarm_break_glass("alice").has_value());
    CHECK(db->disarm_break_glass("nobody").has_value());
    // Malformed input is still rejected.
    CHECK_FALSE(db->disarm_break_glass("alice:admin").has_value());
}

TEST_CASE_METHOD(BreakGlassFixture, "re-arming refreshes the window", "[pg][auth][breakglass]") {
    auto first = db->arm_break_glass("alice", 3600);
    REQUIRE(first.has_value());
    REQUIRE(first->armed);
    // Re-arm with a longer window — the new armed_until must be >= the first
    // (datetime is monotonic here; a refresh never shortens an active arm by
    // accident because the operator chose the larger window).
    auto second = db->arm_break_glass("alice", 7200);
    REQUIRE(second.has_value());
    CHECK(second->armed);
    CHECK(second->armed_until >= first->armed_until);
}

TEST_CASE_METHOD(BreakGlassFixture, "expired window auto-disarms", "[pg][auth][breakglass][slow]") {
    // Arm with a 1-second window. SQLite datetime('now','+1 seconds') has
    // calendar-second granularity, so the real wait is up to ~2 s; the
    // `yuzu-local-windows` runner adds Defender I/O serialisation on top (flake
    // #473). Sleep 3.5 s for margin. Tagged [slow] so quick runs exclude it.
    auto armed = db->arm_break_glass("alice", 1);
    REQUIRE(armed.has_value());
    REQUIRE(armed->armed);

    std::this_thread::sleep_for(std::chrono::milliseconds(3500));

    // The arm auto-expires with no background job — the login gate would now
    // reject the break-glass account exactly like any other local login.
    auto st = db->break_glass_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->armed);
}

TEST_CASE_METHOD(BreakGlassFixture, "arming a non-existent account is UserNotFound",
                 "[pg][auth][breakglass]") {
    // No silent no-op: the host operator running --break-glass-arm against a
    // typo'd username must get a hard error, not a false "armed" report.
    auto r = db->arm_break_glass("nobody", 3600);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == AuthDBError::UserNotFound);
}

TEST_CASE_METHOD(BreakGlassFixture, "malformed username is rejected", "[pg][auth][breakglass]") {
    // A ':' is config-injection-reserved and rejected by is_valid_username, so
    // both methods surface InvalidUsername rather than touching a divergent row.
    const std::string bad = "alice:admin";
    CHECK_FALSE(db->break_glass_status(bad).has_value());
    CHECK_FALSE(db->arm_break_glass(bad, 3600).has_value());
}

// ── break_glass_account_problem (boot guard + --break-glass-arm validator) ────

TEST_CASE_METHOD(BreakGlassFixture, "break_glass_account_problem: enrolled user is usable",
                 "[pg][auth][breakglass]") {
    enroll_mfa("alice");
    CHECK_FALSE(break_glass_account_problem(*db, "alice").has_value()); // nullopt = usable
}

TEST_CASE_METHOD(BreakGlassFixture, "break_glass_account_problem: no-MFA user is rejected",
                 "[pg][auth][breakglass]") {
    // alice exists but has no MFA — a break-glass account MUST carry a second
    // factor, so this is fail-closed (SOC 2 CC6.6).
    auto problem = break_glass_account_problem(*db, "alice");
    REQUIRE(problem.has_value());
    CHECK(problem->find("MFA") != std::string::npos);
}

TEST_CASE_METHOD(BreakGlassFixture, "break_glass_account_problem: missing user is rejected",
                 "[pg][auth][breakglass]") {
    auto problem = break_glass_account_problem(*db, "ghost");
    REQUIRE(problem.has_value());
    CHECK(problem->find("does not exist") != std::string::npos);
}

TEST_CASE_METHOD(BreakGlassFixture, "break_glass_account_problem: malformed username is rejected",
                 "[pg][auth][breakglass]") {
    auto problem = break_glass_account_problem(*db, "alice:admin");
    REQUIRE(problem.has_value());
    CHECK(problem->find("valid username") != std::string::npos);
}
