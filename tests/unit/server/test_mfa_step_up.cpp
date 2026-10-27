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
#include "../../../server/core/src/session_store.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "test_auth_db_pg_helper.hpp"
#include "../test_log_capture.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
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
        auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

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
    // The reason token stands alone: no "(fail-closed)" parenthetical (audit grammar, docs).
    CHECK(audits[0].detail.find("reason=mfa_status_unavailable") != std::string::npos);
    CHECK(audits[0].detail.find("fail-closed") == std::string::npos);
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

// ═══════════════════════════════════════════════════════════════════════════
// Approver MFA gate (#6079): probe_mfa_factor, approver_step_up_window,
// require_enrolled_fresh_mfa.
//
// alice = enrolled admin, bob = not enrolled, carol = enrolled non-admin. alice's and
// carol's enrolment is backdated an hour so a proof of any age under test is NOT
// "older than the enrolment"; the enrolment-instant cases move it explicitly.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

using Kind = ApproverMfaOutcome::Kind;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;

struct ApproverFixture : StepUpFixture {
    ApproverFixture() {
        auto salt = AuthManager::random_bytes(16);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("carol", hash, AuthManager::bytes_to_hex(salt), Role::user)
                    .has_value());
        enroll("carol");
        backdate_enrolment("alice", seconds(3600));
        backdate_enrolment("carol", seconds(3600));
    }

    void add_user(const std::string& name) {
        auto salt = AuthManager::random_bytes(16);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user(name, hash, AuthManager::bytes_to_hex(salt), Role::user)
                    .has_value());
    }

    void enroll(const std::string& user) {
        auto init = db->mfa_init_enrollment(user, "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment(user, code, std::nullopt).has_value());
    }

    /// Run one statement against auth.users for `user` through the fixture's pool.
    void sql(const char* statement, const std::string& user, const std::string& arg2 = {}) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        std::vector<std::string> params{user};
        if (!arg2.empty())
            params.push_back(arg2);
        auto r = yuzu::server::pg::exec_params(lease.get(), statement, params);
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    void backdate_enrolment(const std::string& user, seconds by) {
        sql("UPDATE auth.users SET mfa_enrolled_at = now() - ($2 || ' seconds')::interval "
            "WHERE username = $1",
            user, std::to_string(by.count()));
    }
    void null_secret_keep_enrolled(const std::string& user) {
        sql("UPDATE auth.users SET mfa_totp_secret = NULL WHERE username = $1", user);
    }
    void corrupt_secret(const std::string& user) {
        sql("UPDATE auth.users SET mfa_totp_secret = decode('deadbeefcafebabe0011223344','hex') "
            "WHERE username = $1",
            user);
    }

    /// Epoch ms of the user's enrolment read straight from the column (not via AuthDB).
    std::int64_t enrolled_ms_from_column(const std::string& user) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "SELECT (extract(epoch from mfa_enrolled_at)*1000)::bigint FROM auth.users "
            "WHERE username = $1",
            std::vector<std::string>{user});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 1);
        return std::stoll(PQgetvalue(r.get(), 0, 0));
    }

    struct Run {
        ApproverMfaOutcome outcome;
        httplib::Response res;
    };
    /// The authoritative read of a session's stored proof that production hands the gate.
    /// With no `durable` argument the tests build the `kRow` the store would return for the
    /// session as constructed: the durable proof is the session's own proof instant, and the
    /// database clock reads "now" (plus 5 ms: a proof instant authored by Postgres is rounded
    /// to the millisecond and can sit a hair ahead of this process's clock, which the gate
    /// correctly reads as future-dated; a real read carries the database's own clock and has
    /// no such skew). The DurableFixture cases below pass a real read instead.
    static auth::DurableMfaProof durable_row_for(const auth::Session& s) {
        const auto ms = [](system_clock::time_point t) {
            return t.time_since_epoch().count() == 0
                       ? std::int64_t{0}
                       : std::chrono::duration_cast<milliseconds>(t.time_since_epoch()).count();
        };
        return {auth::DurableMfaProof::Source::kRow, ms(s.mfa_verified_at),
                ms(system_clock::now()) + 5};
    }
    Run run(const auth::Session& s, int configured_window = 300,
            yuzu::MetricsRegistry* metrics = nullptr,
            const std::optional<auth::DurableMfaProof>& durable = std::nullopt) {
        Run r;
        r.res.status = 299; // sentinel: "untouched"
        httplib::Request req;
        r.outcome = require_enrolled_fresh_mfa(req, r.res, s, *db, configured_window, audit_fn,
                                               "POST /api/approvals/{id}/approve",
                                               durable ? *durable : durable_row_for(s), metrics);
        return r;
    }
    static void check_untouched(const Run& r) {
        CHECK(r.res.status == 299);
        CHECK(r.res.body.empty());
    }
};

auth::Session with_wall_proof(ApproverFixture& fx, const std::string& user, const char* source,
                              milliseconds age) {
    return fx.make_session(user, source, system_clock::now() - age);
}

} // namespace

// ── approver_step_up_window ──────────────────────────────────────────────────

TEST_CASE("approver_step_up_window: configured value is capped at 300 s and a disabled gate "
          "still yields 300 s",
          "[mfa][stepup][approver][window]") {
    CHECK(approver_step_up_window(0) == 300);     // W1 gate disabled elsewhere, not here
    CHECK(approver_step_up_window(-5) == 300);    // W2
    CHECK(approver_step_up_window(60) == 60);     // W3 can tighten
    CHECK(approver_step_up_window(299) == 299);   // W4
    CHECK(approver_step_up_window(300) == 300);   // W5
    CHECK(approver_step_up_window(301) == 300);   // W6 cannot widen
    CHECK(approver_step_up_window(86400) == 300); // W7
    CHECK(kApproverStepUpCeilingSecs == 300);
}

// ── probe_mfa_factor ─────────────────────────────────────────────────────────

TEST_CASE_METHOD(ApproverFixture, "probe_mfa_factor: local accounts are classified by their own "
                                  "enrolment row",
                 "[pg][mfa][stepup][approver][probe]") {
    auto alice = probe_mfa_factor(make_session("alice", "local", system_clock::now()), *db);
    CHECK(alice.state == MfaFactorState::kEnrolledLocal); // P1
    CHECK(alice.enrolled_at_ms == enrolled_ms_from_column("alice"));
    CHECK(alice.enrolled_at_ms > 0);

    auto carol = probe_mfa_factor(make_session("carol", "local", system_clock::now()), *db);
    CHECK(carol.state == MfaFactorState::kEnrolledLocal);

    auto bob = probe_mfa_factor(make_session("bob", "local"), *db);
    CHECK(bob.state == MfaFactorState::kNotEnrolled); // P2
    CHECK(bob.enrolled_at_ms == 0);

    add_user("dave"); // P3 provisional secret only
    REQUIRE(db->mfa_init_enrollment("dave", "Yuzu", std::nullopt).has_value());
    CHECK(probe_mfa_factor(make_session("dave", "local"), *db).state ==
          MfaFactorState::kNotEnrolled);

    // P4: no such account is NOT "not enrolled" (different remedy), and still refuses.
    CHECK(probe_mfa_factor(make_session("nobody", "local"), *db).state ==
          MfaFactorState::kAccountUnavailable);
    // A name that is not a valid username (mfa_status -> InvalidUsername) is the same state.
    CHECK(probe_mfa_factor(make_session("bad name!", "local"), *db).state ==
          MfaFactorState::kAccountUnavailable);

    add_user("erin"); // P5 enrolled, then deactivated
    enroll("erin");
    REQUIRE(probe_mfa_factor(make_session("erin", "local"), *db).state ==
            MfaFactorState::kEnrolledLocal);
    REQUIRE(db->remove_user("erin").has_value());
    CHECK(probe_mfa_factor(make_session("erin", "local"), *db).state ==
          MfaFactorState::kAccountUnavailable);
}

TEST_CASE_METHOD(ApproverFixture, "probe_mfa_factor: an enrolled row with no usable enrolment "
                                  "instant fails closed as kStoreUnavailable (sec-4)",
                 "[pg][mfa][stepup][approver][probe]") {
    // `enrolled` is `mfa_enrolled_at IS NOT NULL`, so an epoch-or-earlier instant reads back
    // as enrolled with enrolled_at_ms <= 0. Left as kEnrolledLocal it would make the
    // pre-enrolment proof comparison vacuous.
    for (const char* instant : {"to_timestamp(0)", "to_timestamp(-5)"}) {
        INFO(instant);
        sql((std::string("UPDATE auth.users SET mfa_enrolled_at = ") + instant +
             " WHERE username = $1")
                .c_str(),
            "alice");
        const auto probe = probe_mfa_factor(make_session("alice", "local", system_clock::now()), *db);
        CHECK(probe.state == MfaFactorState::kStoreUnavailable);
        CHECK(probe.enrolled_at_ms == 0);

        yuzu::MetricsRegistry metrics;
        auto r = run(make_session("alice", "local", system_clock::now()), 300, &metrics);
        CHECK(r.outcome.kind == Kind::kStoreUnavailable);
        check_untouched(r);
        CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}})
                  .value() == 1.0);
    }
}

TEST_CASE_METHOD(ApproverFixture, "probe_mfa_factor: an SSO or bearer session never borrows a "
                                  "local namesake's factor",
                 "[pg][mfa][stepup][approver][probe]") {
    // Both an SSO-shaped name and an ENROLLED local namesake (alice) must give the same answer.
    for (const char* user : {"oidc:x#y", "alice"}) {
        INFO(user);
        CHECK(probe_mfa_factor(make_session(user, "oidc", system_clock::now()), *db).state ==
              MfaFactorState::kIdpAttested); // P6
        CHECK(probe_mfa_factor(make_session(user, "oidc"), *db).state ==
              MfaFactorState::kNoIdpProof); // P7
        CHECK(probe_mfa_factor(make_session(user, "saml", system_clock::now()), *db).state ==
              MfaFactorState::kSamlUnsupported); // P8
        for (const char* src : {"api_token", "mcp_token", "engine_token", "", "something_new"}) {
            INFO(src);
            CHECK(probe_mfa_factor(make_session(user, src, system_clock::now()), *db).state ==
                  MfaFactorState::kNotInteractive); // P9
        }
    }
    // An un-enrolled namesake does not take an SSO session's attestation away either.
    CHECK(probe_mfa_factor(make_session("bob", "oidc", system_clock::now()), *db).state ==
          MfaFactorState::kIdpAttested);
}

TEST_CASE_METHOD(ApproverFixture, "probe_mfa_factor: an unreadable secret is kStoreUnavailable, "
                                  "never kNotEnrolled",
                 "[pg][mfa][stepup][approver][probe]") {
    null_secret_keep_enrolled("alice"); // P10
    CHECK(probe_mfa_factor(make_session("alice", "local"), *db).state ==
          MfaFactorState::kStoreUnavailable);
    corrupt_secret("carol"); // P11
    CHECK(probe_mfa_factor(make_session("carol", "local"), *db).state ==
          MfaFactorState::kStoreUnavailable);
}

// ── require_enrolled_fresh_mfa ───────────────────────────────────────────────

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: an enrolled local account with a "
                                  "fresh proof passes and the response is untouched",
                 "[pg][mfa][stepup][approver]") {
    for (const char* user : {"alice", "carol"}) { // admin and non-admin alike
        INFO(user);
        auto r = run(with_wall_proof(*this, user, "local", milliseconds(10'000)));
        CHECK(r.outcome.kind == Kind::kPass); // R1
        CHECK(r.outcome.factor == MfaFactorState::kEnrolledLocal);
        check_untouched(r);
    }
    CHECK(audits.empty());
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: the 300 s ceiling is hard to the "
                                  "sub-second",
                 "[pg][mfa][stepup][approver]") {
    auto in = run(with_wall_proof(*this, "alice", "local", milliseconds(299'500)));
    CHECK(in.outcome.kind == Kind::kPass); // R2
    check_untouched(in);
    CHECK(audits.empty());

    auto out = run(with_wall_proof(*this, "alice", "local", milliseconds(300'500)));
    CHECK(out.outcome.kind == Kind::kChallengeWritten); // R3
    CHECK(out.outcome.factor == MfaFactorState::kEnrolledLocal);
    CHECK(out.res.status == 401);
    auto body = nlohmann::json::parse(out.res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    CHECK(body["meta"]["challenge_url"] == "/login/mfa/stepup");
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].detail.find("user=alice") != std::string::npos);
    CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
    CHECK(audits[0].detail.find("reason=") == std::string::npos);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: no proof at all is challenged",
                 "[pg][mfa][stepup][approver]") {
    auto r = run(make_session("alice", "local")); // R4
    CHECK(r.outcome.kind == Kind::kChallengeWritten);
    CHECK(r.res.status == 401);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].detail.find("age_secs=-1") != std::string::npos);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: the configured window can only "
                                  "tighten the ceiling, and 0 does not disable it",
                 "[pg][mfa][stepup][approver]") {
    CHECK(run(with_wall_proof(*this, "alice", "local", seconds(200)), 0).outcome.kind ==
          Kind::kPass); // R5
    {
        auto r = run(with_wall_proof(*this, "alice", "local", seconds(400)), 0); // R6
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
    }
    audits.clear();
    {
        auto r = run(with_wall_proof(*this, "alice", "local", seconds(400)), 86400); // R7
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
    }
    audits.clear();
    {
        auto r = run(with_wall_proof(*this, "alice", "local", seconds(100)), 60); // R8
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("window_secs=60") != std::string::npos);
    }
    CHECK(run(with_wall_proof(*this, "alice", "local", seconds(50)), 60).outcome.kind ==
          Kind::kPass);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: an un-enrolled local account is "
                                  "refused, writing nothing and counting nothing",
                 "[pg][mfa][stepup][approver]") {
    yuzu::MetricsRegistry metrics;
    auto r = run(make_session("bob", "local", system_clock::now()), 300, &metrics); // R9
    CHECK(r.outcome.kind == Kind::kRefuse);
    CHECK(r.outcome.factor == MfaFactorState::kNotEnrolled);
    check_untouched(r);
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          0.0);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: a deactivated or missing account "
                                  "is refused as account_unavailable, writing nothing and "
                                  "counting nothing (sec-2)",
                 "[pg][mfa][stepup][approver]") {
    add_user("erin");
    enroll("erin");
    REQUIRE(db->remove_user("erin").has_value());
    yuzu::MetricsRegistry metrics;
    for (const char* user : {"erin", "nobody"}) {
        INFO(user);
        auto r = run(make_session(user, "local", system_clock::now()), 300, &metrics);
        CHECK(r.outcome.kind == Kind::kRefuse);
        CHECK(r.outcome.factor == MfaFactorState::kAccountUnavailable);
        check_untouched(r);
    }
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          0.0);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: an unreadable secret is "
                                  "kStoreUnavailable, counted once, and writes nothing",
                 "[pg][mfa][stepup][approver]") {
    null_secret_keep_enrolled("alice");
    yuzu::MetricsRegistry metrics;
    auto r = run(make_session("alice", "local", system_clock::now()), 300, &metrics); // R10
    CHECK(r.outcome.kind == Kind::kStoreUnavailable);
    CHECK(r.outcome.factor == MfaFactorState::kStoreUnavailable);
    check_untouched(r);
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          1.0);
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
              .value() == 0.0);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: SSO sessions stand on the IdP "
                                  "proof alone, never a namesake row",
                 "[pg][mfa][stepup][approver]") {
    // R11: fresh proof passes even though the namesake `bob` is un-enrolled.
    {
        auto r = run(with_wall_proof(*this, "bob", "oidc", seconds(10)));
        CHECK(r.outcome.kind == Kind::kPass);
        CHECK(r.outcome.factor == MfaFactorState::kIdpAttested);
        check_untouched(r);
    }
    // R12: stale proof is challenged, back through SSO.
    {
        auto r = run(with_wall_proof(*this, "oidc:x#y", "oidc", seconds(400)));
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
        auto body = nlohmann::json::parse(r.res.body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        CHECK(body["meta"]["challenge_url"] == "/auth/oidc/start");
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
    }
    audits.clear();
    // R13: no proof is refused outright, even for an enrolled namesake (alice).
    for (const char* user : {"oidc:x#y", "alice"}) {
        auto r = run(make_session(user, "oidc"));
        CHECK(r.outcome.kind == Kind::kRefuse);
        CHECK(r.outcome.factor == MfaFactorState::kNoIdpProof);
        check_untouched(r);
    }
    CHECK(audits.empty());
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: SAML and bearer sessions are "
                                  "refused whatever proof they carry",
                 "[pg][mfa][stepup][approver]") {
    auto saml = run(make_session("alice", "saml", system_clock::now())); // R14
    CHECK(saml.outcome.kind == Kind::kRefuse);
    CHECK(saml.outcome.factor == MfaFactorState::kSamlUnsupported);
    check_untouched(saml);
    for (const char* src : {"api_token", "mcp_token", "engine_token"}) { // R15
        INFO(src);
        auto r = run(make_session("alice", src, system_clock::now()));
        CHECK(r.outcome.kind == Kind::kRefuse);
        CHECK(r.outcome.factor == MfaFactorState::kNotInteractive);
        check_untouched(r);
    }
    CHECK(audits.empty());
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: a proof that predates the current "
                                  "enrolment is challenged; one made under it passes",
                 "[pg][mfa][stepup][approver][approver_enrolment_instant]") {
    // R17: alice proves, then her factor is cleared and re-enrolled.
    auto old_proof = with_wall_proof(*this, "alice", "local", seconds(10));
    REQUIRE(run(old_proof).outcome.kind == Kind::kPass);

    REQUIRE(db->mfa_disable("alice").has_value());
    std::this_thread::sleep_for(milliseconds(10)); // ms resolution: re-enrol strictly later
    enroll("alice");
    std::this_thread::sleep_for(milliseconds(10)); // and the new proof strictly after that

    {
        auto r = run(old_proof);
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("reason=proof_predates_enrolment") != std::string::npos);
    }
    audits.clear();
    {
        auto r = run(make_session("alice", "local", system_clock::now()));
        CHECK(r.outcome.kind == Kind::kPass);
        check_untouched(r);
        CHECK(audits.empty());
    }
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: a hostile SSO subject cannot forge "
                                  "audit detail fields through the step-up challenge (sec-3)",
                 "[pg][mfa][stepup][approver]") {
    // An OIDC session's username is IdP-controlled. Its proof is 10 minutes old, so the gate
    // writes the challenge and the `mfa.step_up.required` detail embeds `user=<username>`.
    const std::string hostile = "oidc:ev\nil=1,window_secs=9 x#y";
    auto r = run(make_session(hostile, "oidc", system_clock::now() - seconds(600)));
    CHECK(r.outcome.kind == Kind::kChallengeWritten);
    REQUIRE(audits.size() == 1);
    const auto& detail = audits[0].detail;
    CHECK(detail.find('\n') == std::string::npos);
    CHECK(detail.rfind("user=oidc:ev_il_1_window_secs_9_x#y age_secs=", 0) == 0);
    // Exactly one window_secs field: the subject's own "window_secs=9" was neutralised.
    CHECK(detail.find("window_secs=") == detail.rfind("window_secs="));
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: the enrolment boundary is "
                                  "inclusive to the millisecond",
                 "[pg][mfa][stepup][approver][approver_enrolment_instant]") {
    // bob enrols NOW (no backdating), so the boundary is a few ms ago and the proofs are fresh.
    enroll("bob");
    const auto at_ms = probe_mfa_factor(make_session("bob", "local"), *db).enrolled_at_ms;
    REQUIRE(at_ms > 0);
    auto at = [&](std::int64_t ms) {
        return make_session("bob", "local", system_clock::time_point{milliseconds(ms)});
    };
    CHECK(run(at(at_ms)).outcome.kind == Kind::kPass);                 // equal passes
    CHECK(run(at(at_ms + 1)).outcome.kind == Kind::kPass);
    CHECK(run(at(at_ms - 1)).outcome.kind == Kind::kChallengeWritten); // one ms earlier does not
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: a future-dated or wall-stale proof "
                                  "is not fresh",
                 "[pg][mfa][stepup][approver]") {
    // R18: a proof stamped in the future derives to "no proof".
    {
        auto future = with_wall_proof(*this, "alice", "local", milliseconds(-600'000));
        auto r = run(future);
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
    }
    {
        // The cached anchor is empty (nothing to age), and the durable row holds the same
        // future instant, i.e. one dated after the database clock. That is clock skew, not a
        // login that attested no second factor, so it is a 503 and not the 403
        // "sign in again" refusal whose remedy cannot work (UP-4). A genuinely proof-less SSO
        // session is still the 403 (R13 below, and the dedicated UP-4 case).
        auto future_sso = with_wall_proof(*this, "oidc:x#y", "oidc", milliseconds(-600'000));
        auto r = run(future_sso);
        CHECK(r.outcome.kind == Kind::kStoreUnavailable);
        CHECK(r.outcome.factor == MfaFactorState::kStoreUnavailable);
        check_untouched(r);
    }
    audits.clear();
    // R19: the monotonic anchor reads fresh (a host suspend freezes it) but the proof instant
    // is an hour old. The approver gate does not consult the wall figure (`wall_stale`); what
    // challenges here is the durable ceiling: `durable_row_for` builds the stored row from the
    // same hour-old instant, so the database-clock age is an hour, past the 300 s window.
    {
        // The enrolment is two hours old, so the one-hour-old proof is strictly NEWER than it:
        // the pre-enrolment rule cannot be what challenges (it would otherwise pass this test
        // for the wrong reason).
        backdate_enrolment("alice", seconds(7200));
        auto s = with_wall_proof(*this, "alice", "local", seconds(10));
        s.mfa_verified_at = system_clock::now() - std::chrono::hours(1);
        auto r = run(s);
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail.find("reason=") == std::string::npos);
    }
}

TEST_CASE("ApproverMfaOutcome: a value-initialised outcome refuses (R20)",
          "[mfa][stepup][approver]") {
    static_assert(ApproverMfaOutcome{}.kind == ApproverMfaOutcome::Kind::kRefuse);
    static_assert(MfaFactorProbe{}.state == MfaFactorState::kNotEnrolled);
    static_assert(static_cast<int>(ApproverMfaOutcome::Kind::kRefuse) == 0);
    static_assert(static_cast<int>(MfaFactorState::kNotEnrolled) == 0);
    ApproverMfaOutcome unset{};
    CHECK(unset.kind != ApproverMfaOutcome::Kind::kPass);
}

// ── UP-8 (#6079): the approver ceiling is hard across a suspended host / paused VM ───────────
//
// The cached session's monotonic anchor freezes while the host is suspended, and the generic
// wall backstop tolerates auth::kWallSanitySkew (5 min), so a proof 10 s old on the steady
// clock but 450 s old in elapsed time used to pass a 300 s window. The approver gate judges the
// DURABLE proof against the database clock instead.

namespace {

struct DurableFixture : ApproverFixture {
    yuzu::server::SessionStore store{db.pool()};
    AuthManager mgr;
    std::string token;
    auth::Session cached; // the replica's cache entry: minted just now, steady age ~0

    DurableFixture() {
        REQUIRE(store.is_open());
        mgr.set_session_store(&store);
        token = mgr.create_local_session_for_test("alice", Role::admin, /*mfa_verified=*/true);
        REQUIRE_FALSE(token.empty());
        auto s = mgr.validate_session(token);
        REQUIRE(s.has_value());
        cached = *s;
    }
    ~DurableFixture() { mgr.set_session_store(nullptr); }

    /// Rewrite the durable proof as `age_ms` old on the DATABASE clock (negative = future).
    /// Raw SQL, so the write generation does not move and `cached` stays "fresh", exactly the
    /// state a replica is in after its steady clock paused.
    void set_durable_proof_age(long long age_ms) {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE session_store.sessions SET mfa_verified_ms = "
            "(extract(epoch from now())*1000)::bigint - $1::bigint",
            std::vector<std::string>{std::to_string(age_ms)});
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    Run run_durable(int configured_window = 300, yuzu::MetricsRegistry* metrics = nullptr) {
        return run(cached, configured_window, metrics,
                   mgr.read_durable_mfa_proof(token, cached.username));
    }
};

} // namespace

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: a proof young on the steady clock but "
                                 "450 s old on the database clock is challenged (UP-8)",
                 "[pg][mfa][stepup][approver][durable]") {
    // Sanity: the cached monotonic view is fresh, so the OLD logic would have passed.
    REQUIRE(detail::mfa_proof_age(cached, std::chrono::seconds(300)).fresh);
    set_durable_proof_age(450'000);
    auto r = run_durable();
    CHECK(r.outcome.kind == Kind::kChallengeWritten);
    CHECK(r.res.status == 401);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
    // The audit row reports the age that decided it, not the frozen monotonic one.
    CHECK(audits[0].detail.find("age_secs=450") != std::string::npos);
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: the durable ceiling is 300 s with no "
                                 "skew allowance",
                 "[pg][mfa][stepup][approver][durable]") {
    set_durable_proof_age(299'000);
    auto in = run_durable();
    CHECK(in.outcome.kind == Kind::kPass);
    check_untouched(in);
    CHECK(audits.empty());

    set_durable_proof_age(301'000);
    auto out = run_durable();
    CHECK(out.outcome.kind == Kind::kChallengeWritten);
    CHECK(out.res.status == 401);

    // A configured window tightens it the same way.
    set_durable_proof_age(100'000);
    CHECK(run_durable(60).outcome.kind == Kind::kChallengeWritten);
    CHECK(run_durable(120).outcome.kind == Kind::kPass);
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: a future-dated, missing or foreign "
                                 "durable proof is challenged, never passed",
                 "[pg][mfa][stepup][approver][durable]") {
    set_durable_proof_age(-600'000); // stamped 10 minutes in the DATABASE's future
    CHECK(run_durable().outcome.kind == Kind::kChallengeWritten);

    set_durable_proof_age(1'000); // sanity: a young proof passes again
    CHECK(run_durable().outcome.kind == Kind::kPass);

    // The row carries no proof at all.
    {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(), "UPDATE session_store.sessions SET mfa_verified_ms = 0",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    CHECK(run_durable().outcome.kind == Kind::kChallengeWritten);

    // Another principal's session, or a token that is not a session, has no proof to age.
    set_durable_proof_age(1'000);
    auto foreign = mgr.read_durable_mfa_proof(token, "carol");
    CHECK(foreign.source == auth::DurableMfaProof::Source::kAbsent);
    CHECK(run(cached, 300, nullptr, foreign).outcome.kind == Kind::kChallengeWritten);
    CHECK(mgr.read_durable_mfa_proof("", "alice").source ==
          auth::DurableMfaProof::Source::kAbsent);
    CHECK(mgr.read_durable_mfa_proof(std::string(200, 'x'), "alice").source ==
          auth::DurableMfaProof::Source::kAbsent);
}

// UP-4 (#6079): an SSO proof is `min(IdP iat, replica now)` stored as authored. A replica (or IdP)
// whose clock runs ahead of the database stores an instant the database reads as future-dated;
// derive_session_deadlines then leaves the cached anchor empty, which used to surface as the 403
// "your login did not attest a second factor, sign in again" - a remedy that cannot work, because
// the next login repeats it. The cause is clock skew, so the answer is the fail-closed 503.
TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: an SSO proof dated after the "
                                 "database clock is a 503, not a sign-in-again 403 (UP-4)",
                 "[pg][mfa][stepup][approver][approver_mfa][durable]") {
    const auto now_ms = std::chrono::duration_cast<milliseconds>(
                            system_clock::now().time_since_epoch())
                            .count();
    auto mint_oidc = [&](const std::string& tok, std::int64_t proof_ms) {
        yuzu::server::SessionWriteParams p;
        p.token_hash = AuthManager::sha256_hex(tok);
        p.username = "oidc:x#y";
        p.role = "user";
        p.auth_source = "oidc";
        p.session_lifetime_ms = 3600'000;
        p.mfa_verified_ms_abs = proof_ms;
        REQUIRE(store.create(p).has_value());
        auto s = mgr.validate_session(tok);
        REQUIRE(s.has_value());
        REQUIRE(s->auth_source == "oidc");
        return *s;
    };

    // Proof 2 minutes ahead of the database clock.
    const std::string skewed_token = "yuzu-test-oidc-skewed-proof-token-0001";
    const auto skewed = mint_oidc(skewed_token, now_ms + 120'000);
    REQUIRE(skewed.steady_mfa_verified.time_since_epoch().count() == 0); // derive dropped it
    const auto skewed_durable = mgr.read_durable_mfa_proof(skewed_token, skewed.username);
    REQUIRE(skewed_durable.source == auth::DurableMfaProof::Source::kRow);
    REQUIRE(skewed_durable.mfa_verified_ms > skewed_durable.db_now_ms);

    yuzu::MetricsRegistry metrics;
    yuzu::test::LogCapture logs;
    auto r = run(skewed, 300, &metrics, skewed_durable);
    logs.stop();
    CHECK(r.outcome.kind == Kind::kStoreUnavailable);
    CHECK(r.outcome.factor == MfaFactorState::kStoreUnavailable);
    CHECK_FALSE(r.outcome.kind == Kind::kRefuse);
    check_untouched(r); // no 403/401 body, no challenge
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          1.0);
    CHECK(logs.text().find("dated after the database clock") != std::string::npos);
    CHECK(logs.text().find("clock skew") != std::string::npos);

    // A genuinely missing proof (the IdP attested no second factor) is still the 403 refusal,
    // and is not counted as an outage.
    const std::string bare_token = "yuzu-test-oidc-no-amr-token-0001";
    const auto bare = mint_oidc(bare_token, 0);
    const auto bare_durable = mgr.read_durable_mfa_proof(bare_token, bare.username);
    REQUIRE(bare_durable.source == auth::DurableMfaProof::Source::kRow);
    REQUIRE(bare_durable.mfa_verified_ms == 0);
    yuzu::MetricsRegistry bare_metrics;
    auto b = run(bare, 300, &bare_metrics, bare_durable);
    CHECK(b.outcome.kind == Kind::kRefuse);
    CHECK(b.outcome.factor == MfaFactorState::kNoIdpProof);
    check_untouched(b);
    CHECK(bare_metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}})
              .value() == 0.0);
    // ...as is one whose durable session is absent (nothing dated after the clock).
    auto absent = run(bare, 300, nullptr, auth::DurableMfaProof{auth::DurableMfaProof::Source::kAbsent, 0, 0});
    CHECK(absent.outcome.kind == Kind::kRefuse);
    CHECK(absent.outcome.factor == MfaFactorState::kNoIdpProof);
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: a fresh durable proof does not "
                                 "rescue a cached proof that is stale or missing",
                 "[pg][mfa][stepup][approver][durable]") {
    // The cached monotonic check is a second, stricter condition (it also covers a backward
    // database step the durable arithmetic cannot see). Durable 10 s old, cached anchor varied.
    set_durable_proof_age(10'000);
    REQUIRE(run_durable().outcome.kind == Kind::kPass); // sanity: durable fresh + cached fresh

    auto stale = cached;
    stale.steady_mfa_verified = std::chrono::steady_clock::now() - seconds(200);
    CHECK(run(stale, 300, nullptr, mgr.read_durable_mfa_proof(token, stale.username))
              .outcome.kind == Kind::kPass); // 200 s on the anchor is inside the window

    stale.steady_mfa_verified = std::chrono::steady_clock::now() - seconds(400);
    {
        auto r = run(stale, 300, nullptr, mgr.read_durable_mfa_proof(token, stale.username));
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
    }
    audits.clear();

    auto missing = cached;
    missing.steady_mfa_verified = {}; // the "no usable proof" sentinel
    {
        auto r = run(missing, 300, nullptr, mgr.read_durable_mfa_proof(token, missing.username));
        CHECK(r.outcome.kind == Kind::kChallengeWritten);
        CHECK(r.res.status == 401);
    }
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: the durable ceiling admits an age "
                                 "equal to the window and refuses one millisecond more",
                 "[pg][mfa][stepup][approver][durable]") {
    // The database clock is read in the same SELECT as the proof, so the exact age cannot be
    // produced by backdating (the read lands a few ms after the UPDATE). Take the real read
    // and pin its clock instead: age = window, then window + 1 ms.
    set_durable_proof_age(1'000);
    const auto real = mgr.read_durable_mfa_proof(token, cached.username);
    REQUIRE(real.source == auth::DurableMfaProof::Source::kRow);
    REQUIRE(real.mfa_verified_ms > 0);
    for (const int window : {300, 60}) {
        INFO("window=" << window);
        const long long window_ms = static_cast<long long>(window) * 1000;
        auto at = real;
        at.db_now_ms = real.mfa_verified_ms + window_ms;
        auto in = run(cached, window, nullptr, at);
        CHECK(in.outcome.kind == Kind::kPass);
        check_untouched(in);
        CHECK(audits.empty());

        auto over = real;
        over.db_now_ms = real.mfa_verified_ms + window_ms + 1;
        auto out = run(cached, window, nullptr, over);
        CHECK(out.outcome.kind == Kind::kChallengeWritten);
        CHECK(out.res.status == 401);
        audits.clear();
    }
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: a degraded durable read is a 503, "
                                 "not a challenge, and is counted",
                 "[pg][mfa][stepup][approver][durable]") {
    yuzu::MetricsRegistry metrics;
    {
        auto lease = db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                               std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto durable = mgr.read_durable_mfa_proof(token, cached.username);
    CHECK(durable.source == auth::DurableMfaProof::Source::kUnavailable);
    auto r = run(cached, 300, &metrics, durable);
    CHECK(r.outcome.kind == Kind::kStoreUnavailable);
    check_untouched(r);
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          1.0);
    // A value-initialised read is the same fail-closed answer.
    CHECK(run(cached, 300, nullptr, auth::DurableMfaProof{}).outcome.kind ==
          Kind::kStoreUnavailable);
}

TEST_CASE_METHOD(DurableFixture, "require_enrolled_fresh_mfa: the durable proof, not the cached "
                                 "one, is compared with the enrolment instant",
                 "[pg][mfa][stepup][approver][durable][approver_enrolment_instant]") {
    // Alice enrolled 10 s ago. The cached session was minted just now (after the enrolment),
    // so the cached comparison would pass; the durable proof is 100 s old, i.e. made before
    // the enrolment, and inside the 300 s window, so only the enrolment rule can refuse it.
    backdate_enrolment("alice", seconds(10));
    set_durable_proof_age(100'000);
    auto r = run_durable();
    CHECK(r.outcome.kind == Kind::kChallengeWritten);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].detail.find("reason=proof_predates_enrolment") != std::string::npos);
}

TEST_CASE_METHOD(ApproverFixture, "require_enrolled_fresh_mfa: with no SessionStore attached the "
                                  "gate fails closed as store-unavailable (503), never a pass",
                 "[pg][mfa][stepup][approver][durable]") {
    // No store means no database clock to age a proof on, and no replica clock stands in for
    // it: the read is "unavailable", so the gate answers 503 (counted like any outage) rather
    // than challenge or pass, even for a proof that is fresh on every clock the session has.
    AuthManager no_store; // never given a SessionStore
    const auto session = with_wall_proof(*this, "alice", "local", seconds(10));
    const auto durable = no_store.read_durable_mfa_proof("any-token", session.username);
    CHECK(durable.source == auth::DurableMfaProof::Source::kUnavailable);

    yuzu::MetricsRegistry metrics;
    auto r = run(session, 300, &metrics, durable);
    CHECK(r.outcome.kind == Kind::kStoreUnavailable);
    check_untouched(r);
    CHECK(audits.empty());
    CHECK(metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
          1.0);
}

// (f) The generic gate is deliberately unchanged: same inputs, same pass.
TEST_CASE_METHOD(StepUpFixture, "require_mfa_step_up: the same steady-10s / wall-450s proof still "
                                "passes the generic 300 s window (legacy behaviour pinned)",
                 "[pg][mfa][stepup][durable]") {
    auto s = make_session("alice", "local", std::chrono::system_clock::now() - std::chrono::seconds(10));
    s.mfa_verified_at = std::chrono::system_clock::now() - std::chrono::seconds(450);
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    CHECK(require_mfa_step_up(req, res, s, *db, 300, audit_fn, "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(audits.empty());
}
