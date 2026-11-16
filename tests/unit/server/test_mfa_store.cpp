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

#include "../../../server/core/src/secure_random.hpp"
#include "../../../server/core/src/totp.hpp"
#include "pg/pg_exec.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_forced_csprng_failure.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

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
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
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
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);

    auto recovery = db->mfa_verify_enrollment("alice", code, std::nullopt);
    REQUIRE(recovery.has_value());
    REQUIRE(recovery->recovery_codes.size() == 10);

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE(s->enrolled);
    REQUIRE(s->recovery_codes_remaining == 10);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_enrollment rejects wrong code", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());

    auto r = db->mfa_verify_enrollment("alice", "000000", std::nullopt);
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error() == AuthDBError::InvalidCredentials);

    auto s = db->mfa_status("alice");
    REQUIRE_FALSE(s->enrolled); // still provisional
}

TEST_CASE_METHOD(MfaFixture, "double init reuses the provisional secret (no rotation, #1227)",
                 "[pg][mfa][store]") {
    auto first = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(first.has_value());
    auto second = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
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
    CHECK(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());
}

TEST_CASE_METHOD(MfaFixture, "init refuses if already enrolled", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

    auto reinit = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE_FALSE(reinit.has_value());
    REQUIRE(reinit.error() == AuthDBError::MfaAlreadyEnrolled);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code replay-protected", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

    // Same code in the same step is rejected on login (replay).
    auto replay = db->mfa_verify_login_code("alice", code);
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(replay->ok);
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
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto enroll_code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", enroll_code, std::nullopt).has_value());

    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto future_counter = mfa::current_counter(std::chrono::system_clock::now()) + 1;
    auto future_code = mfa::generate(raw, future_counter);

    auto first = db->mfa_verify_login_code("alice", future_code);
    REQUIRE(first.has_value());
    REQUIRE(first->ok);

    auto replay = db->mfa_verify_login_code("alice", future_code);
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(replay->ok);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code rejects garbage", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

    auto r = db->mfa_verify_login_code("alice", "");
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->ok);

    auto r2 = db->mfa_verify_login_code("alice", "abcdef");
    REQUIRE(r2.has_value());
    REQUIRE_FALSE(r2->ok);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes are single-use", "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code, std::nullopt);
    REQUIRE(recovery_res.has_value());

    const auto& codes = recovery_res->recovery_codes;
    REQUIRE_FALSE(codes.empty());

    auto first = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(first.has_value());
    REQUIRE(first->ok);

    auto replay = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(replay->ok);

    auto s = db->mfa_status("alice");
    REQUIRE(s->recovery_codes_remaining == 9);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes normalise separator and case",
                 "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code, std::nullopt);
    REQUIRE(recovery_res.has_value());
    auto orig = recovery_res->recovery_codes.front(); // shape "XXXXX-XXXXX"

    // Strip the dash; should still match the same stored row.
    std::string no_dash;
    for (char c : orig)
        if (c != '-')
            no_dash += c;

    auto stripped = db->mfa_consume_recovery_code("alice", no_dash);
    REQUIRE(stripped.has_value());
    REQUIRE(stripped->ok);

    // Lowercased should also have matched if we hadn't already consumed.
    auto next = recovery_res->recovery_codes.at(1);
    std::string lower;
    for (char c : next)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto matched = db->mfa_consume_recovery_code("alice", lower);
    REQUIRE(matched.has_value());
    REQUIRE(matched->ok);
}

TEST_CASE_METHOD(MfaFixture, "regenerate replaces all codes", "[pg][mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    auto code = code_for_now(init->secret_base32);
    auto first_set = db->mfa_verify_enrollment("alice", code, std::nullopt);
    REQUIRE(first_set.has_value());

    auto second_set = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
    REQUIRE(second_set.has_value());
    REQUIRE(second_set->size() == 10);

    // Old codes no longer valid.
    auto stale = db->mfa_consume_recovery_code("alice", first_set->recovery_codes.front());
    REQUIRE(stale.has_value());
    REQUIRE_FALSE(stale->ok);

    // New ones are.
    auto fresh = db->mfa_consume_recovery_code("alice", second_set->front());
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->ok);
}

TEST_CASE_METHOD(MfaFixture, "disable clears secret and recovery codes", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

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
    auto reinit = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(reinit.has_value());
    CHECK(reinit->secret_base32 != init->secret_base32);
    // The fresh secret completes a new enroll → verify cycle end-to-end.
    auto new_code = code_for_now(reinit->secret_base32);
    CHECK(db->mfa_verify_enrollment("alice", new_code, std::nullopt).has_value());
}

TEST_CASE_METHOD(MfaFixture, "verify_login_code on disabled user always fails", "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());
    REQUIRE(db->mfa_disable("alice").has_value());

    auto r = db->mfa_verify_login_code("alice", code);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(r->ok);
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
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
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
    auto retry = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(retry.has_value());
    CHECK_FALSE(retry->secret_base32.empty());
}

// ── #4763: a CSPRNG failure fails enrollment / regeneration CLOSED ───────────
// `force_next_failure_for_this_thread` is one-shot and thread-local; it is
// consumed by the first `fill_random` on this thread, which in these paths is
// the mfa::random_secret / mfa::random_recovery_code call under test.
//
// KNOWN LIMIT: this typed-draw hook always fails the FIRST draw, so the regeneration case
// below fails on recovery code #0 (the DELETE has run, no INSERT has). A failure at code #1..#9
// (DELETE plus k INSERTs already issued) takes the same `unexpected(EntropyUnavailable)` ->
// `with_txn_for` rollback path; that mid-batch rollback IS covered, for the per-code SALT draw, by the
// `FailNthSaltDraw` tests further down (nth 5 and 10, and the concurrent case).

using yuzu::test::ForcedCsprngFailure; // shared with the route tests (#6995)

TEST_CASE_METHOD(MfaFixture, "mfa_init_enrollment fails closed on a CSPRNG failure (#4763)",
                 "[pg][mfa][store]") {
    auto init = [&] {
        ForcedCsprngFailure forced;
        auto r = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
        // Checked BEFORE the guard drains it: proves the mint draw was reached and
        // consumed the hook, i.e. the EntropyUnavailable below is the CSPRNG path and not
        // an unrelated earlier failure.
        REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
        return r;
    }();
    REQUIRE_FALSE(init.has_value());
    REQUIRE(init.error() == AuthDBError::EntropyUnavailable);

    // Nothing was written: not enrolled, and a retry mints a real, non-zero secret.
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);

    auto retry = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(retry.has_value());
    auto bytes = mfa::base32_decode(retry->secret_base32);
    REQUIRE(bytes.has_value());
    REQUIRE(bytes->size() == static_cast<std::size_t>(mfa::kTotpSecretBytes));
    REQUIRE(std::any_of(bytes->begin(), bytes->end(), [](uint8_t b) { return b != 0; }));
}

TEST_CASE_METHOD(MfaFixture,
                 "mfa_regenerate_recovery_codes fails closed on a CSPRNG failure (#4763)",
                 "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto original = db->mfa_verify_enrollment("alice", code_for_now(init->secret_base32),
                                              std::nullopt);
    REQUIRE(original.has_value());
    REQUIRE(original->recovery_codes.size() == 10);

    auto regen = [&] {
        ForcedCsprngFailure forced;
        auto r = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
        REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
        return r;
    }();
    REQUIRE_FALSE(regen.has_value());
    REQUIRE(regen.error() == AuthDBError::EntropyUnavailable);

    // The txn rolled back: the user keeps all ten ORIGINAL codes (not wiped,
    // not a partial new set), and one of them still redeems.
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE(s->recovery_codes_remaining == 10);
    auto consumed = db->mfa_consume_recovery_code("alice", original->recovery_codes[0]);
    REQUIRE(consumed.has_value());
    REQUIRE(consumed->ok);
}

TEST_CASE_METHOD(MfaFixture,
                 "factor-bound regenerate: a CSPRNG failure leaves the codes and the generation "
                 "untouched, and a stale generation still wins over the mint (#6079, #4763)",
                 "[pg][mfa][store][mfa_binding]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto original = db->mfa_verify_enrollment("alice", code_for_now(init->secret_base32),
                                              std::nullopt);
    REQUIRE(original.has_value());
    const std::int64_t gen = original->factor_gen;
    REQUIRE(gen > 0);

    // The route passes the generation its step-up check admitted. A CSPRNG fault with that
    // real generation must roll back: same ten codes, same generation.
    auto failed = [&] {
        ForcedCsprngFailure forced;
        auto r = db->mfa_regenerate_recovery_codes("alice", gen);
        REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
        return r;
    }();
    REQUIRE_FALSE(failed.has_value());
    REQUIRE(failed.error() == AuthDBError::EntropyUnavailable); // #6995: not a store fault
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE(s->recovery_codes_remaining == 10);
    REQUIRE(s->factor_gen == gen);

    // A stale generation is refused BEFORE any mint: the armed failure is not consumed, and
    // the error is FactorChanged, not EntropyUnavailable.
    {
        ForcedCsprngFailure forced;
        auto stale = db->mfa_regenerate_recovery_codes("alice", gen - 1);
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error() == AuthDBError::FactorChanged);
        REQUIRE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
    }

    // Healthy CSPRNG, matching generation: the regenerate succeeds and does not move the
    // generation (only a change of mfa_enrolled_at does).
    auto ok = db->mfa_regenerate_recovery_codes("alice", gen);
    REQUIRE(ok.has_value());
    REQUIRE(ok->size() == 10);
    auto after = db->mfa_status("alice");
    REQUIRE(after.has_value());
    REQUIRE(after->factor_gen == gen);
}

TEST_CASE_METHOD(MfaFixture,
                 "mfa_verify_enrollment rolls the enrol back on a recovery-code CSPRNG failure (#4763)",
                 "[pg][mfa][store]") {
    // The enrolling UPDATE and the recovery-code mint share ONE transaction. A CSPRNG
    // failure in the mint must roll the whole thing back: the user stays provisional
    // (never "enrolled with zero recovery codes"), so the same code can enrol again.
    // (This does not exercise the TOTP replay counter: mfa_verify_enrollment verifies
    // with no minimum counter, so the proof here is the mfa_enrolled_at rollback.)
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    const auto code = code_for_now(init->secret_base32);

    auto failed = [&] {
        ForcedCsprngFailure forced;
        auto r = db->mfa_verify_enrollment("alice", code, std::nullopt);
        REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());
        return r;
    }();
    REQUIRE_FALSE(failed.has_value());
    REQUIRE(failed.error() == AuthDBError::EntropyUnavailable);

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
    REQUIRE(s->recovery_codes_remaining == 0);

    // Same code, healthy CSPRNG: the enrolment now succeeds with ten codes.
    auto ok = db->mfa_verify_enrollment("alice", code, std::nullopt);
    REQUIRE(ok.has_value());
    REQUIRE(ok->recovery_codes.size() == 10);
    auto after = db->mfa_status("alice");
    REQUIRE(after.has_value());
    REQUIRE(after->enrolled);
    REQUIRE(after->recovery_codes_remaining == 10);
}

// ── #6995 (gov UP-1/CH-1): the recovery-code SALT draw is part of the same fault class ──────────
// The salt comes from AuthManager::random_bytes, which calls RAND_bytes directly and THROWS on
// failure. Before #6995 that exception unwound out of the txn callback into httplib (a bare 500,
// no audit row, no counter). `FailNthSaltDraw` fails exactly the Nth 16-byte RAND_bytes call; a
// recovery code is 10 bytes and a TOTP secret 20, so only a salt can match.
#ifndef _WIN32
TEST_CASE_METHOD(MfaFixture,
                 "mfa_regenerate_recovery_codes maps a salt-draw failure to EntropyUnavailable "
                 "and rolls back (#6995)",
                 "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto original = db->mfa_verify_enrollment("alice", code_for_now(init->secret_base32),
                                              std::nullopt);
    REQUIRE(original.has_value());
    REQUIRE(original->recovery_codes.size() == 10);

    // First, middle and last code of the batch: the DELETE and k-1 INSERTs have run each time.
    for (const int nth : {1, 5, 10}) {
        INFO("salt draw #" << nth);
        auto regen = [&] {
            yuzu::test::FailNthSaltDraw fail{nth};
            auto r = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
            REQUIRE(fail.fired()); // proves the intended draw was reached, not another failure
            return r;
        }();
        REQUIRE_FALSE(regen.has_value());
        REQUIRE(regen.error() == AuthDBError::EntropyUnavailable);

        // Rolled back: all ten ORIGINAL codes remain (no wipe, no partial set).
        auto s = db->mfa_status("alice");
        REQUIRE(s.has_value());
        REQUIRE(s->recovery_codes_remaining == 10);
    }
    auto consumed = db->mfa_consume_recovery_code("alice", original->recovery_codes[0]);
    REQUIRE(consumed.has_value());
    REQUIRE(consumed->ok);

    // Healthy RNG afterwards: regeneration works again.
    auto fresh = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->size() == 10);
}

TEST_CASE_METHOD(MfaFixture,
                 "mfa_verify_enrollment rolls the enrol back on a salt-draw failure and the same "
                 "code can retry (#6995)",
                 "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    const auto code = code_for_now(init->secret_base32);

    auto failed = [&] {
        yuzu::test::FailNthSaltDraw fail{1};
        auto r = db->mfa_verify_enrollment("alice", code, std::nullopt);
        REQUIRE(fail.fired());
        return r;
    }();
    REQUIRE_FALSE(failed.has_value());
    REQUIRE(failed.error() == AuthDBError::EntropyUnavailable);

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled); // the enrolling UPDATE and the TOTP counter rolled back together
    REQUIRE(s->recovery_codes_remaining == 0);

    auto ok = db->mfa_verify_enrollment("alice", code, std::nullopt); // same code, healthy RNG
    REQUIRE(ok.has_value());
    REQUIRE(ok->recovery_codes.size() == 10);
}
// CH-2 (gov Gate 5): a fault in one regeneration racing a clean one. The two serialise on the
// auth.users row lock; whichever order they run in, the faulting caller must roll back to nothing and
// the clean caller's set must be the one that remains -- never a mix of old and new codes. The salt
// counter is thread-local, so only the faulting thread's draw is failed.
TEST_CASE_METHOD(MfaFixture,
                 "concurrent regenerate: one caller's salt-draw failure never leaves a mixed set "
                 "(#6995)",
                 "[pg][mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto original = db->mfa_verify_enrollment("alice", code_for_now(init->secret_base32),
                                              std::nullopt);
    REQUIRE(original.has_value());

    std::atomic<bool> go{false};
    std::expected<std::vector<std::string>, AuthDBError> faulting =
        std::unexpected(AuthDBError::WriteFailed);
    std::expected<std::vector<std::string>, AuthDBError> clean =
        std::unexpected(AuthDBError::WriteFailed);
    bool fired = false;

    std::thread a{[&] {
        yuzu::test::FailNthSaltDraw fail{5};
        while (!go.load())
            std::this_thread::yield();
        faulting = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
        fired = fail.fired();
    }};
    std::thread b{[&] {
        while (!go.load())
            std::this_thread::yield();
        clean = db->mfa_regenerate_recovery_codes("alice", std::nullopt);
    }};
    go.store(true);
    a.join();
    b.join();

    REQUIRE(fired);
    REQUIRE_FALSE(faulting.has_value());
    CHECK(faulting.error() == AuthDBError::EntropyUnavailable);
    REQUIRE(clean.has_value());
    REQUIRE(clean->size() == 10);

    // Exactly the clean caller's ten codes remain: none of the originals, and no partial set.
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    CHECK(s->recovery_codes_remaining == 10);
    auto old_code = db->mfa_consume_recovery_code("alice", original->recovery_codes[0]);
    REQUIRE(old_code.has_value());
    CHECK_FALSE(old_code->ok);
    auto new_code = db->mfa_consume_recovery_code("alice", (*clean)[0]);
    REQUIRE(new_code.has_value());
    CHECK(new_code->ok);
}

#endif // !_WIN32
