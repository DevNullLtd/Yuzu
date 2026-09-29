/**
 * test_auth_lockout.cpp — AuthDB account-lockout method tests.
 *
 * Drives AuthDB::lockout_status / record_failed_login / clear_failed_logins
 * against a per-test temp auth.db with a fresh schema (migration v3). SOC 2
 * CC6.3 — `/auth-and-authz` skill gap matrix P0 #2. Verifies:
 *   - failures below the threshold do not lock; the counter climbs
 *   - the threshold-th failure locks, sets just_locked exactly once
 *   - a subsequent failure while locked does NOT re-fire just_locked
 *   - clear_failed_logins (success / admin unlock) resets the state
 *   - threshold <= 0 disables recording entirely
 *   - a non-existent username never creates a row (anti-enumeration)
 *   - a malformed username is rejected with InvalidUsername
 *   - an expired window auto-unlocks AND starts a fresh attempt budget
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

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

struct LockoutFixture {
    // AuthDbPg defaults to cleanup_interval_secs=0 — no background reaper
    // jthread (the rapid create/destruct of one fixture per
    // TEST_CASE_METHOD otherwise spawns+joins it once per case).
    yuzu::test::AuthDbPg db;

    LockoutFixture() {
        auto salt = AuthManager::random_bytes(16);
        auto salt_hex = AuthManager::bytes_to_hex(salt);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("alice", hash, salt_hex, Role::admin).has_value());
    }
};

} // namespace

TEST_CASE_METHOD(LockoutFixture, "fresh user is not locked", "[pg][auth][lockout]") {
    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);
    CHECK(st->failed_count == 0);
}

TEST_CASE_METHOD(LockoutFixture, "failures below threshold do not lock", "[pg][auth][lockout]") {
    const int threshold = 5;
    for (int i = 1; i < threshold; ++i) {
        auto rec = db->record_failed_login("alice", threshold, 900);
        REQUIRE(rec.has_value());
        CHECK(rec->failed_count == i);
        CHECK_FALSE(rec->locked);
        CHECK_FALSE(rec->just_locked);
    }
    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);
    CHECK(st->failed_count == threshold - 1);
}

TEST_CASE_METHOD(LockoutFixture, "threshold-th failure locks exactly once", "[pg][auth][lockout]") {
    const int threshold = 3;
    db->record_failed_login("alice", threshold, 900);
    db->record_failed_login("alice", threshold, 900);
    auto crossing = db->record_failed_login("alice", threshold, 900);
    REQUIRE(crossing.has_value());
    CHECK(crossing->failed_count == threshold);
    CHECK(crossing->locked);
    CHECK(crossing->just_locked);          // the one audit-worthy edge
    CHECK_FALSE(crossing->locked_until.empty());

    // A further failure (e.g. via the pre-check fail-open path) keeps the
    // account locked but must NOT re-fire the just_locked edge — otherwise
    // every blocked attempt would spam the audit log.
    auto again = db->record_failed_login("alice", threshold, 900);
    REQUIRE(again.has_value());
    CHECK(again->locked);
    CHECK_FALSE(again->just_locked);

    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK(st->locked);
}

TEST_CASE_METHOD(LockoutFixture, "clear resets lockout state", "[pg][auth][lockout]") {
    const int threshold = 2;
    db->record_failed_login("alice", threshold, 900);
    auto locked = db->record_failed_login("alice", threshold, 900);
    REQUIRE(locked.has_value());
    REQUIRE(locked->locked);

    REQUIRE(db->clear_failed_logins("alice").has_value());

    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);
    CHECK(st->failed_count == 0);
}

TEST_CASE_METHOD(LockoutFixture, "threshold <= 0 disables recording", "[pg][auth][lockout]") {
    auto rec = db->record_failed_login("alice", /*threshold=*/0, 900);
    REQUIRE(rec.has_value());
    CHECK(rec->failed_count == 0);
    CHECK_FALSE(rec->locked);
    // The column must be untouched — a disabled feature records nothing.
    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK(st->failed_count == 0);
}

TEST_CASE_METHOD(LockoutFixture, "non-existent user never creates a row", "[pg][auth][lockout]") {
    // Anti-enumeration + no storage growth: spraying random usernames must
    // not lock (or create) an account that does not exist.
    auto rec = db->record_failed_login("ghost", 5, 900);
    REQUIRE(rec.has_value());
    CHECK(rec->failed_count == 0);
    CHECK_FALSE(rec->locked);

    auto st = db->lockout_status("ghost");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);
    CHECK(st->failed_count == 0);
}

TEST_CASE_METHOD(LockoutFixture, "malformed username is rejected", "[pg][auth][lockout]") {
    // A ':' is config-injection-reserved and rejected by is_valid_username,
    // so all three methods surface InvalidUsername rather than silently
    // touching a divergent row.
    const std::string bad = "alice:admin";
    CHECK_FALSE(db->lockout_status(bad).has_value());
    CHECK_FALSE(db->record_failed_login(bad, 5, 900).has_value());
    CHECK_FALSE(db->clear_failed_logins(bad).has_value());
}

TEST_CASE_METHOD(LockoutFixture, "expired window unlocks and grants a fresh budget",
                 "[pg][auth][lockout][slow]") {
    const int threshold = 2;
    // Lock with a 1-second window.
    db->record_failed_login("alice", threshold, 1);
    auto locked = db->record_failed_login("alice", threshold, 1);
    REQUIRE(locked.has_value());
    REQUIRE(locked->locked);

    // Wait out the window. SQLite datetime('now','+1 seconds') has calendar-
    // second granularity, so the real required wait is up to ~2 s depending on
    // where in the second the lock landed; the `yuzu-local-windows` runner adds
    // Defender-induced I/O serialisation on top (flake #473). Sleep 3.5 s (3.5×
    // the window) for a comfortable margin. Tagged `[slow]` so quick runs can
    // exclude it with `~[slow]`.
    std::this_thread::sleep_for(std::chrono::milliseconds(3500));

    // The lock auto-expires — no background job needed.
    auto st = db->lockout_status("alice");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->locked);

    // The next failure starts a FRESH cycle: the counter resets to 1 and the
    // account is not immediately re-locked (the waited-out user got their
    // attempt budget back).
    auto fresh = db->record_failed_login("alice", threshold, 1);
    REQUIRE(fresh.has_value());
    CHECK(fresh->failed_count == 1);
    CHECK_FALSE(fresh->locked);
    CHECK_FALSE(fresh->just_locked);
}
