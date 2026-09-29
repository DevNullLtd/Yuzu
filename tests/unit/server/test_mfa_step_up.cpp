/**
 * test_mfa_step_up.cpp — unit tests for the `require_mfa_step_up`
 * helper added by PR2 of the TOTP MFA ladder (SOC 2 CC6.6).
 *
 * Drives every branch of the gate decision tree:
 *
 *   - escape hatch (window_secs <= 0)
 *   - bearer-credential bypass (auth_source == api_token / mcp_token)
 *   - non-enrolled user bypass (mfa_status->enrolled == false)
 *   - no-proof session (mfa_verified_at == 0) → 401
 *   - fresh proof within window → pass
 *   - stale proof beyond window → 401
 *   - 401 envelope shape (code, message, correlation_id, remediation,
 *     meta.api_version, meta.mfa_step_up_required, meta.challenge_url)
 *   - audit capture (action, result, target_type, target_id, detail)
 *   - empty audit_fn does not crash
 *
 * The helper does not touch httplib::Server; we construct synthetic
 * Request + Response objects directly and assert post-call state.
 */

#include "../../../server/core/src/mfa_step_up.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "test_auth_db_pg_helper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

struct AuditCapture {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct StepUpFixture {
    yuzu::test::AuthDbPg db;
    std::vector<AuditCapture> audits;
    StepUpAuditFn audit_fn;

    StepUpFixture() {
        // Seed alice (MFA-enrolled) + bob (not enrolled).
        auto salt_a = AuthManager::random_bytes(16);
        auto hash_a = AuthManager::pbkdf2_sha256("pw", salt_a, 1000);
        REQUIRE(db->upsert_user("alice", hash_a, AuthManager::bytes_to_hex(salt_a),
                                Role::admin)
                    .has_value());
        auto salt_b = AuthManager::random_bytes(16);
        auto hash_b = AuthManager::pbkdf2_sha256("pw", salt_b, 1000);
        REQUIRE(db->upsert_user("bob", hash_b, AuthManager::bytes_to_hex(salt_b),
                                Role::user)
                    .has_value());

        // Enroll alice in MFA so mfa_status->enrolled == true.
        auto init = db->mfa_init_enrollment("alice", "Yuzu");
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

        audit_fn = [this](const httplib::Request&, const std::string& action,
                          const std::string& result, const std::string& target_type,
                          const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            return true;
        };
    }

    auth::Session make_session(const std::string& user, const std::string& source,
                               std::chrono::system_clock::time_point verified_at = {}) {
        auth::Session s;
        s.username = user;
        s.role = (user == "alice") ? Role::admin : Role::user;
        s.auth_source = source;
        // Since HA WS-1/1a DB-clock authority (ADR-2002 §4), require_mfa_step_up
        // ages against the local monotonic `steady_mfa_verified` derived by
        // AuthManager::derive_session_deadlines, not the raw wall `mfa_verified_at`
        // — so populate through it (here the local wall clock is the authority).
        // The total verified→check elapsed age is identical to the old wall path,
        // and derive maps an epoch (no proof) / future-dated (backward step) proof
        // to the {} sentinel exactly as the old `mfa_verified_at > now` guard did.
        const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
        const std::int64_t verified_ms =
            verified_at.time_since_epoch().count() == 0
                ? 0
                : std::chrono::duration_cast<std::chrono::milliseconds>(
                      verified_at.time_since_epoch())
                      .count();
        auth::AuthManager::derive_session_deadlines(s, now, now + 3600'000, now, verified_ms,
                                                    /*elevated_until*/ 0, /*issued*/ 0, now);
        return s;
    }
};

} // namespace

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: window_secs <= 0 returns true (escape hatch)",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local");

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/0, audit_fn,
                              "POST /api/v1/whatever"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/-1, audit_fn,
                              "POST /api/v1/whatever"));
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: SAML session is denied with honest 403 (not api-token "
                 "message, not mfa_status lookup) — gate stays CLOSED",
                 "[pg][mfa][stepup][saml]") {
    // F3 regression guard: SAML sessions have no local users row.  Before
    // this fix the gate fell through to mfa_status() which returned an
    // error (UserNotFound → fail-closed), producing a confusing
    // "auth_db unavailable" 401.  The fix returns an honest 403 BEFORE
    // consulting the DB.  carol has no local row (proving the lookup is skipped).
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    REQUIRE_FALSE(db->mfa_status("carol").has_value()); // no local row for SAML user

    auto session = make_session("carol", "saml");

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "DELETE /api/v1/users/carol"));
    // Must deny (gate stays CLOSED), not bypass.
    CHECK(res.status == 403);

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["code"] == 403);
    // Message must mention SAML, not the API-token message.
    const auto msg = body["error"]["message"].get<std::string>();
    CHECK(msg.find("SAML") != std::string::npos);
    CHECK(msg.find("API") == std::string::npos);
    CHECK(msg.find("token") == std::string::npos);
    // mfa_step_up_required false: there is no step-up path available for SAML.
    CHECK(body["meta"]["mfa_step_up_required"] == false);

    // Audit must be emitted and mention the SAML reason.
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].result == "error");
    CHECK(audits[0].detail.find("saml") != std::string::npos);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: api_token / mcp_token principals bypass the gate",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;

    auto api = make_session("alice", "api_token");
    CHECK(require_mfa_step_up(req, res, api, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(audits.empty());

    auto mcp = make_session("alice", "mcp_token");
    CHECK(require_mfa_step_up(req, res, mcp, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: non-enrolled user (bob) bypasses the gate",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("bob", "local");

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: MFA-enrolled session with no proof yields 401",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // mfa_verified_at is default-constructed (epoch 0) → "no proof yet".
    auto session = make_session("alice", "local");

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["code"] == 401);
    CHECK(body["error"]["message"] == "MFA step-up required");
    CHECK(body["error"].contains("correlation_id"));
    CHECK(body["error"]["remediation"].get<std::string>().find("/login/mfa/stepup") !=
          std::string::npos);
    CHECK(body["meta"]["api_version"] == "v1");
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    CHECK(body["meta"]["challenge_url"] == "/login/mfa/stepup");

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].result == "error");
    CHECK(audits[0].target_type == "Endpoint");
    CHECK(audits[0].target_id == "POST /api/v1/tokens");
    CHECK(audits[0].detail.find("user=alice") != std::string::npos);
    CHECK(audits[0].detail.find("age_secs=-1") != std::string::npos); // sentinel
    CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: fresh proof within window passes the gate",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local", std::chrono::system_clock::now());

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture, "require_mfa_step_up: stale proof beyond window yields 401",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // 600 s old; window is 300 s → stale.
    auto session = make_session("alice", "local",
                                std::chrono::system_clock::now() - std::chrono::seconds(600));

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    // age_secs should be ~600 (allow a small wobble for scheduler jitter).
    auto age_pos = audits[0].detail.find("age_secs=");
    REQUIRE(age_pos != std::string::npos);
    int age = std::stoi(audits[0].detail.substr(age_pos + 9));
    CHECK(age >= 600);
    CHECK(age < 610);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: a proof older than the 24h hard ceiling fails CLOSED even "
                 "under an oversized configured window",
                 "[pg][mfa][stepup]") {
    // Adversarial-round #2 C3 / PR #3702 blocker #1: the effective freshness
    // window is min(window_secs, kMaxMfaStepUpWindowSecs=24h). A misconfigured or
    // over-large window_secs cannot extend the step-up window past the hard
    // ceiling (parity with JIT's kMaxElevationWindow).
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // Proof aged 25h; configured window a (misconfigured) 30h. Without the
    // ceiling, age(25h) <= window(30h) would PASS; the 24h ceiling rejects it.
    auto session = make_session("alice", "local",
                                std::chrono::system_clock::now() - std::chrono::hours(25));
    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/30 * 3600, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);

    // A proof just INSIDE the ceiling (23h) with the same oversized window passes
    // — proving the ceiling is what rejects above, not the configured window.
    httplib::Response res2;
    res2.status = 200;
    auto fresh = make_session("alice", "local",
                              std::chrono::system_clock::now() - std::chrono::hours(23));
    CHECK(require_mfa_step_up(req, res2, fresh, *db, /*window_secs=*/30 * 3600, audit_fn,
                             "POST /api/v1/tokens"));
    CHECK(res2.status == 200);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: a future-dated proof (backward clock step) fails CLOSED",
                 "[pg][mfa][stepup]") {
    // HA WS-1/1a wall-clock reversal: mfa_verified_at is now system_clock. A
    // proof timestamped AFTER now — a backward step on the issuing/holding
    // replica — must be treated as NO proof (never a spurious-fresh window a
    // rewind would otherwise hold open), so the gate requires step-up (401).
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local",
                                std::chrono::system_clock::now() + std::chrono::seconds(600));

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: mfa_status store error fails CLOSED (UP-4)",
                 "[pg][mfa][stepup]") {
    // Tear down auth_db so mfa_status() returns an error → helper must
    // emit a 401 with the mfa_status_unavailable detail, not silently
    // bypass the gate. Governance Gate 4 unhappy-path UP-4 / qe Gate 3
    // BLOCKING.
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // alice was enrolled in the fixture; we now drop her row to simulate
    // a deleted-mid-request user. mfa_status() returns an error.
    REQUIRE(db->remove_user("alice").has_value());
    auto session = make_session("alice", "local", std::chrono::system_clock::now());

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    CHECK(body["error"]["remediation"].get<std::string>().find("auth_db unavailable") !=
          std::string::npos);

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].result == "error");
    CHECK(audits[0].detail.find("mfa_status_unavailable") != std::string::npos);
    CHECK(audits[0].detail.find("fail-closed") != std::string::npos);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: empty audit_fn does not crash on the deny path",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local");

    StepUpAuditFn empty_audit; // default-constructed std::function is empty
    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, empty_audit,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    // Body still constructed correctly.
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: OIDC session with fresh amr-seeded proof passes",
                 "[pg][mfa][stepup][oidc]") {
    // PR3: OIDC sessions are no longer blanket-exempt. /auth/callback seeds
    // mfa_verified_at from the IdP `amr` claim. A session whose IdP login
    // attested MFA recently clears the gate WITHOUT a local users-row
    // lookup (carol has no row, proving the lookup is skipped).
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    REQUIRE_FALSE(db->mfa_status("carol").has_value()); // no local row
    auto session = make_session("carol", "oidc", std::chrono::system_clock::now());

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: OIDC session WITHOUT MFA proof PASSES (UP-5 regression)",
                 "[pg][mfa][stepup][oidc]") {
    // GOVERNANCE UP-5 regression. An SSO login from an IdP that did not
    // attest MFA (no amr → mfa_verified_at default) has no second factor to
    // step up against — it must PASS, exactly like an un-enrolled local
    // user. Failing it would 401 → /auth/oidc/start → silent re-SSO → same
    // amr-less token → 401 … an infinite lockout loop re-opening the PR
    // #1199 HIGH for every non-MFA IdP. The gate must NOT consult the local
    // users row (carol has none) and must NOT fail closed.
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    REQUIRE_FALSE(db->mfa_status("carol").has_value()); // no local row
    auto session = make_session("carol", "oidc");       // default-constructed proof

    // Pass "optional" explicitly so the UP-5 invariant is not silently tied
    // to the parameter default (governance qe SHOULD).
    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                             "DELETE /api/v1/sessions", "optional"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: OIDC no-proof is GATED under enforcement (A4/B1)",
                 "[pg][mfa][stepup][oidc][enforce]") {
    // Hermes adversarial + cyber A4/B1 + governance UP-6: under enforcement
    // that protects the principal's role, an SSO login the IdP did not MFA
    // must step up (re-SSO), symmetric with a local user being forced to
    // enroll. (The default/optional case — no-proof passes — is the
    // separate UP-5 regression test above.)
    httplib::Request req;
    REQUIRE_FALSE(db->mfa_status("carol").has_value()); // oidc, no local row

    // required → every role gated. carol is a user-role oidc session.
    {
        httplib::Response res;
        res.status = 200;
        auto s = make_session("carol", "oidc"); // no proof
        CHECK_FALSE(require_mfa_step_up(req, res, s, *db, 300, audit_fn, "X", "required"));
        CHECK(res.status == 401);
        auto body = nlohmann::json::parse(res.body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        CHECK(body["meta"]["challenge_url"] == "/auth/oidc/start");
    }

    // admin-only → a non-admin oidc session still PASSES (not protected)…
    {
        httplib::Response res;
        res.status = 200;
        auto s = make_session("carol", "oidc"); // user role
        CHECK(require_mfa_step_up(req, res, s, *db, 300, audit_fn, "X", "admin-only"));
        CHECK(res.status == 200);
    }
    // …but an admin oidc session under admin-only is gated.
    {
        httplib::Response res;
        res.status = 200;
        auto s = make_session("alice", "oidc"); // admin role (make_session maps alice→admin)
        CHECK_FALSE(require_mfa_step_up(req, res, s, *db, 300, audit_fn, "X", "admin-only"));
        CHECK(res.status == 401);
    }

    // A FRESH amr-seeded proof passes even under `required` — enforcement
    // gates the no-proof case, not a session the IdP actually MFA'd
    // (guards against a future refactor broadening the gate to all OIDC).
    {
        httplib::Response res;
        res.status = 200;
        auto s = make_session("carol", "oidc", std::chrono::system_clock::now());
        CHECK(require_mfa_step_up(req, res, s, *db, 300, audit_fn, "X", "required"));
        CHECK(res.status == 200);
    }
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: window boundary — age == window passes, age > window fails",
                 "[pg][mfa][stepup]") {
    // The comparison is inclusive (`age <= window_secs`). A local enrolled
    // session proven exactly `window_secs` ago passes; one second past
    // fails. Guards the boundary against an off-by-one regression.
    httplib::Request req;
    const auto now = std::chrono::system_clock::now();

    httplib::Response res_at;
    res_at.status = 200;
    auto at = make_session("alice", "local", now - std::chrono::seconds(300));
    CHECK(require_mfa_step_up(req, res_at, at, *db, /*window_secs=*/300, audit_fn, "X"));
    CHECK(res_at.status == 200);

    httplib::Response res_past;
    res_past.status = 200;
    auto past = make_session("alice", "local", now - std::chrono::seconds(301));
    CHECK_FALSE(require_mfa_step_up(req, res_past, past, *db, /*window_secs=*/300, audit_fn, "X"));
    CHECK(res_past.status == 401);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: OIDC session with stale amr proof is gated",
                 "[pg][mfa][stepup][oidc]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // amr attested MFA, but 600s ago; window is 300s → stale.
    auto session = make_session("carol", "oidc",
                                std::chrono::system_clock::now() - std::chrono::seconds(600));

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["challenge_url"] == "/auth/oidc/start");
}

TEST_CASE("mfa_enforcement_protects: single source of truth for the enforcement predicate",
          "[mfa][stepup][enforce]") {
    using yuzu::server::mfa_enforcement_protects;
    using yuzu::server::auth::Role;
    // optional → never protects.
    CHECK_FALSE(mfa_enforcement_protects("optional", Role::admin));
    CHECK_FALSE(mfa_enforcement_protects("optional", Role::user));
    // admin-only → admins only.
    CHECK(mfa_enforcement_protects("admin-only", Role::admin));
    CHECK_FALSE(mfa_enforcement_protects("admin-only", Role::user));
    // required → every role.
    CHECK(mfa_enforcement_protects("required", Role::admin));
    CHECK(mfa_enforcement_protects("required", Role::user));
    // Unknown value → fail-safe (not enforced; CLI validation rejects it
    // upstream so this never locks anyone out on a typo).
    CHECK_FALSE(mfa_enforcement_protects("bogus", Role::admin));
    CHECK_FALSE(mfa_enforcement_protects("", Role::admin));
}

TEST_CASE("amr_asserts_mfa: MFA-bearing methods are recognised, password-only is not",
          "[mfa][stepup][oidc][amr]") {
    using yuzu::server::amr_asserts_mfa;
    // Empty / single-factor → false.
    CHECK_FALSE(amr_asserts_mfa({}));
    CHECK_FALSE(amr_asserts_mfa({"pwd"}));
    CHECK_FALSE(amr_asserts_mfa({"pwd", "rba"})); // risk-based, no factor
    CHECK_FALSE(amr_asserts_mfa({"unknown", "method"}));

    // Single-factor presence/knowledge methods are NOT MFA (governance
    // UP-7): a device-unlock PIN or "user presence" must not satisfy the
    // gate.
    CHECK_FALSE(amr_asserts_mfa({"pin"}));
    CHECK_FALSE(amr_asserts_mfa({"user"}));
    CHECK_FALSE(amr_asserts_mfa({"pwd", "pin"}));

    // Case-sensitive per RFC 8176 (Entra emits lowercase "mfa"). A
    // mixed-case value is conservatively rejected — fail-safe (the session
    // is gated/re-SSO'd, never wrongly admitted). Documents the behavior so
    // a future normalization change is detectable.
    CHECK_FALSE(amr_asserts_mfa({"MFA"}));
    CHECK_FALSE(amr_asserts_mfa({"Otp"}));

    // Entra aggregate + RFC 8176 factor references → true.
    CHECK(amr_asserts_mfa({"mfa"}));
    CHECK(amr_asserts_mfa({"pwd", "otp"}));     // password + one-time-code
    CHECK(amr_asserts_mfa({"pwd", "hwk"}));     // hardware key
    CHECK(amr_asserts_mfa({"fpt"}));            // fingerprint
    CHECK(amr_asserts_mfa({"face"}));
    CHECK(amr_asserts_mfa({"sms"}));            // weak but a possession factor
    CHECK(amr_asserts_mfa({"x", "y", "mfa"}));  // any position
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: per-call correlation_id is unique across calls",
                 "[pg][mfa][stepup]") {
    httplib::Request req;
    auto session = make_session("alice", "local");

    httplib::Response res1;
    res1.status = 200;
    require_mfa_step_up(req, res1, session, *db, 300, audit_fn, "POST /api/v1/tokens");
    httplib::Response res2;
    res2.status = 200;
    require_mfa_step_up(req, res2, session, *db, 300, audit_fn, "POST /api/v1/tokens");

    auto b1 = nlohmann::json::parse(res1.body);
    auto b2 = nlohmann::json::parse(res2.body);
    CHECK(b1["error"]["correlation_id"].get<std::string>() !=
          b2["error"]["correlation_id"].get<std::string>());
}
