/**
 * test_mfa_store.cpp — AuthDB MFA / TOTP method tests.
 *
 * Drives AuthDB::mfa_init_enrollment / mfa_verify_enrollment /
 * mfa_verify_login_code / mfa_consume_recovery_code /
 * mfa_regenerate_recovery_codes / mfa_disable / mfa_status against a
 * per-test temp auth.db with a fresh schema. Verifies:
 *   - status reads on never-enrolled, provisional, and enrolled rows
 *   - init/verify round-trip
 *   - replay protection on login codes
 *   - recovery codes are single-use and case-insensitive
 *   - regenerate wipes prior codes
 *   - disable clears the secret + recovery codes
 *   - re-enroll after disable succeeds
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../../../server/core/src/totp.hpp"
#include "pg/pg_exec.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <filesystem>
#include <memory>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

struct MfaFixture {
    // AuthDbPg defaults to cleanup_interval_secs=0 (reaper disabled) — see
    // its ctor doc comment; this fixture is instantiated once per
    // TEST_CASE_METHOD across the whole file.
    yuzu::test::AuthDbPg db;

    MfaFixture() {
        // Seed a user — mfa_* methods key by username and require an
        // is_active row to exist.
        auto salt = AuthManager::random_bytes(16);
        auto salt_hex = AuthManager::bytes_to_hex(salt);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("alice", hash, salt_hex, Role::admin).has_value());
    }

    /// Decode the base32 secret from the enrollment-init result and emit a
    /// TOTP code for the current step. Used to drive verify() with a code
    /// the production verifier will accept.
    std::string code_for_now(const std::string& secret_b32) {
        auto bytes = mfa::base32_decode(secret_b32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto counter = mfa::current_counter(std::chrono::system_clock::now());
        return mfa::generate(raw, counter);
    }
};

} // namespace

TEST_CASE_METHOD(MfaFixture, "mfa_status on never-enrolled user", "[pg][mfa][store]") {
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
    REQUIRE(s->enrolled_at.empty());
    REQUIRE(s->disabled_at.empty());
    REQUIRE(s->recovery_codes_remaining == 0);
}

TEST_CASE_METHOD(MfaFixture, "mfa_init_enrollment provides URI and secret", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    REQUIRE_FALSE(init->secret_base32.empty());
    REQUIRE(init->otpauth_uri.starts_with("otpauth://totp/Yuzu:alice"));
    REQUIRE(init->otpauth_uri.find("secret=" + init->secret_base32) != std::string::npos);

    // Still "not enrolled" — provisional rows do not stamp mfa_enrolled_at.
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_enrollment with valid code enrolls and issues codes",
                 "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);

    auto recovery = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery.has_value());
    REQUIRE(recovery->size() == 10);

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE(s->enrolled);
    REQUIRE(s->recovery_codes_remaining == 10);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_enrollment rejects wrong code", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());

    auto r = db->mfa_verify_enrollment("alice", "000000");
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error() == AuthDBError::InvalidCredentials);

    auto s = db->mfa_status("alice");
    REQUIRE_FALSE(s->enrolled); // still provisional
}

TEST_CASE_METHOD(MfaFixture, "double init reuses the provisional secret (no rotation, #1227)",
                 "[pg][mfa][store]") {
    auto first = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(first.has_value());
    auto second = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(second.has_value());
    // #1227: re-initialising a PROVISIONAL row returns the SAME secret + URI.
    // A second browser tab / retried /login bootstrap / re-opened Settings
    // panel must not invalidate the QR the operator already scanned.
    // (Rotation only happens once the provisional secret is reaped by
    // cleanup_provisional_mfa or the user is mfa_disabled.) The
    // confirmed-enrollment one-time-reveal property is unaffected — see the
    // "init refuses if already enrolled" case below.
    CHECK(first->secret_base32 == second->secret_base32);
    CHECK(first->otpauth_uri == second->otpauth_uri);
    // And a code from the first QR still verifies after the second init.
    auto code = code_for_now(first->secret_base32);
    CHECK(db->mfa_verify_enrollment("alice", code).has_value());
}

TEST_CASE_METHOD(MfaFixture, "init refuses if already enrolled", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    auto reinit = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    REQUIRE(reinit.error() == AuthDBError::MfaAlreadyEnrolled);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code replay-protected", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    // Same code in the same step is rejected on login (replay).
    auto replay = db->mfa_verify_login_code("alice", code);
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(*replay);
}

TEST_CASE_METHOD(MfaFixture,
                 "mfa_verify_login_code stamps last_counter so a successful login cannot be replayed",
                 "[pg][mfa][store]") {
    // security Gate 2 LOW follow-up: the route-test `totp_at(offset=1)`
    // workaround sidesteps the post-enrollment floor. To prove that the
    // *post-login* floor is also enforced, drive a login that succeeds
    // at counter+1 and assert the same code at counter+1 fails the
    // immediate next call. A regression that drops the
    // `mfa_last_counter` UPDATE inside mfa_verify_login_code would let
    // an intercepted TOTP be re-used within the same 30 s step.
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto enroll_code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", enroll_code).has_value());

    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto future_counter = mfa::current_counter(std::chrono::system_clock::now()) + 1;
    auto future_code = mfa::generate(raw, future_counter);

    auto first = db->mfa_verify_login_code("alice", future_code);
    REQUIRE(first.has_value());
    REQUIRE(*first);

    auto replay = db->mfa_verify_login_code("alice", future_code);
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(*replay);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code rejects garbage", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    auto r = db->mfa_verify_login_code("alice", "");
    REQUIRE(r.has_value());
    REQUIRE_FALSE(*r);

    auto r2 = db->mfa_verify_login_code("alice", "abcdef");
    REQUIRE(r2.has_value());
    REQUIRE_FALSE(*r2);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes are single-use", "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery_res.has_value());

    const auto& codes = *recovery_res;
    REQUIRE_FALSE(codes.empty());

    auto first = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(first.has_value());
    REQUIRE(*first);

    auto replay = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(*replay);

    auto s = db->mfa_status("alice");
    REQUIRE(s->recovery_codes_remaining == 9);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes normalise separator and case",
                 "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery_res.has_value());
    auto orig = recovery_res->front(); // shape "XXXXX-XXXXX"

    // Strip the dash; should still match the same stored row.
    std::string no_dash;
    for (char c : orig)
        if (c != '-')
            no_dash += c;

    auto stripped = db->mfa_consume_recovery_code("alice", no_dash);
    REQUIRE(stripped.has_value());
    REQUIRE(*stripped);

    // Lowercased should also have matched if we hadn't already consumed.
    auto next = recovery_res->at(1);
    std::string lower;
    for (char c : next)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto matched = db->mfa_consume_recovery_code("alice", lower);
    REQUIRE(matched.has_value());
    REQUIRE(*matched);
}

TEST_CASE_METHOD(MfaFixture, "regenerate replaces all codes", "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    auto first_set = db->mfa_verify_enrollment("alice", code);
    REQUIRE(first_set.has_value());

    auto second_set = db->mfa_regenerate_recovery_codes("alice");
    REQUIRE(second_set.has_value());
    REQUIRE(second_set->size() == 10);

    // Old codes no longer valid.
    auto stale = db->mfa_consume_recovery_code("alice", first_set->front());
    REQUIRE(stale.has_value());
    REQUIRE_FALSE(*stale);

    // New ones are.
    auto fresh = db->mfa_consume_recovery_code("alice", second_set->front());
    REQUIRE(fresh.has_value());
    REQUIRE(*fresh);
}

TEST_CASE_METHOD(MfaFixture, "disable clears secret and recovery codes", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    REQUIRE(db->mfa_disable("alice").has_value());

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
    REQUIRE_FALSE(s->disabled_at.empty());
    REQUIRE(s->recovery_codes_remaining == 0);

    // Re-init works after disable AND mints a FRESH secret — rotation
    // resumes once the provisional/enrolled secret is cleared (#1227: reuse
    // applies ONLY to a live provisional row; mfa_disable nulls the secret,
    // so load_mfa_row returns empty and init falls through to mint-fresh).
    auto reinit = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(reinit.has_value());
    CHECK(reinit->secret_base32 != init->secret_base32);
    // The fresh secret completes a new enroll → verify cycle end-to-end.
    auto new_code = code_for_now(reinit->secret_base32);
    CHECK(db->mfa_verify_enrollment("alice", new_code).has_value());
}

TEST_CASE_METHOD(MfaFixture, "verify_login_code on disabled user always fails", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());
    REQUIRE(db->mfa_disable("alice").has_value());

    auto r = db->mfa_verify_login_code("alice", code);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(*r);
}

// Quality SHOULD (governance hardening round): mfa_init_enrollment's fresh-
// secret path already had a comment claiming "encrypt failure aborts here —
// never write plaintext, never write anything at all" (auth_db.cpp), but no
// test exercised it. Uses AuthDbPg's FaultyKekProvider option
// (test_auth_db_pg_helper.hpp) to force SecretCodec::encrypt's wrap_dek call
// to fail deterministically — AFTER the DEK is minted and the plaintext is
// GCM-encrypted into a local buffer, BEFORE any database write — and
// confirms the row is left exactly as it started: no secret column write at
// all, not even a truncated/partial one.
TEST_CASE("mfa_init_enrollment aborts with no plaintext/partial write when encrypt fails",
         "[pg][mfa][store][fault]") {
    yuzu::test::AuthDbPg db{/*cleanup_interval_secs=*/0, /*inject_encrypt_faults=*/true};
    auto* fault = db.fault_provider();
    REQUIRE(fault != nullptr);

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db->upsert_user("alice", hash, salt_hex, Role::admin).has_value());

    fault->set_fail_wrap(true);
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE_FALSE(init.has_value());
    CHECK(init.error() == yuzu::server::AuthDBError::WriteFailed);

    // No partial write: mfa_totp_secret is still genuinely NULL, not a
    // truncated/garbage blob — check the column directly rather than
    // trusting mfa_status alone (a successful provisional-secret write would
    // ALSO report enrolled=false, so that check alone can't distinguish
    // "aborted, nothing written" from "wrote a provisional secret").
    {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto res = yuzu::server::pg::exec_params(
            lease.get(), "SELECT mfa_totp_secret IS NULL, mfa_enrolled_at IS NULL FROM auth.users WHERE username = $1",
            std::vector<std::string>{"alice"});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        CHECK(std::string(PQgetvalue(res.get(), 0, 0)) == "t"); // secret column still NULL
        CHECK(std::string(PQgetvalue(res.get(), 0, 1)) == "t"); // never stamped enrolled
    }

    auto status = db->mfa_status("alice");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);

    // Recovering: with the fault cleared, a normal enrollment now succeeds
    // cleanly — the aborted attempt left nothing behind to interfere.
    fault->set_fail_wrap(false);
    auto retry = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(retry.has_value());
    CHECK_FALSE(retry->secret_base32.empty());
}
