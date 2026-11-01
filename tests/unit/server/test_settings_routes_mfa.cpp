/**
 * test_settings_routes_mfa.cpp — Route-level coverage for the 5 Settings
 * MFA HTMX routes added by PR1 (and CSRF-gated by the same PR's Hermes
 * round): GET /fragments/settings/mfa, POST /api/settings/mfa/init,
 * POST /api/settings/mfa/verify, POST /api/settings/mfa/recovery-codes,
 * POST /api/settings/mfa/disable.
 *
 * Closes the second half of the quality-engineer Gate 3 SHOULD-FIX that
 * PR1 deferred. Companion to `test_auth_routes_mfa.cpp` — together they
 * are the regression net for the bug class that let Hermes Agent's
 * CRITICAL finding (`/login/mfa` unreachable behind the pre-routing auth
 * gate) ship the first time around.
 *
 * Pattern: register SettingsRoutes against an in-process TestRouteSink,
 * dispatch synthesized requests, assert on response shape, the audit
 * chain (captured via a mock audit_fn), the `Cache-Control: no-store`
 * reveal contract, and the `origin_safe` CSRF gate (host equality after
 * default-port normalisation, userinfo rejection, sanitised audit
 * detail, no-Origin pass-through for non-browser clients).
 *
 * Why in-process and not a real `httplib::Server`: prior fixture pattern
 * spun up a listening server behind a `std::thread` acceptor, which
 * crashes under TSan with no TSan report (#438).
 */

#include "test_principal_lock_gate.hpp"
#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "credential_change_owner.hpp"
#include "session_store.hpp"
#include "mfa_factor_state.hpp" // judge_local_mfa_binding: is the stored proof bound (#6079)
#include "step_up_gate.hpp"
#include "step_up_wiring.hpp" // detail::run_in_handler_step_up: the gate as server.cpp wires it
#include "test_approver_route_fixture.hpp" // the real approval routes behind the real approver gate
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "../test_log_capture.hpp"
#include "source_scan.hpp"
#include "test_principal_lock_gate.hpp" // SessionWipeFault
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <regex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) { fs::create_directories(path); }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// Single audit call captured by the mock audit_fn. Mirrors the shape in
/// test_settings_routes_users.cpp so a future helper-promotion is
/// mechanical.
struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

/// Mock session state read by the auth_fn / admin_fn closures. Tests
/// switch `session_user` / `session_role` between calls to act as
/// different principals against the same harness.
struct MfaSettingsHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::AuthDbPg auth_db;
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    yuzu::MetricsRegistry metrics; // before `routes`, which keeps a pointer to it
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    std::string session_user;
    auth::Role session_role{auth::Role::admin};
    /// What `auth_fn` reports as the settings session's `auth_source` (the real default is "local").
    std::string session_auth_source{"local"};
    /// When true, `auth_fn` resolves the request's own session cookie through the AuthManager (the
    /// production shape: the session carries the cached proof anchor the generic gate ages)
    /// instead of synthesising a session from `session_user`. Off by default.
    bool use_cookie_sessions{false};
    std::vector<AuditCall> audit_calls;

    explicit MfaSettingsHarness(StepUpFn step_up_fn = {})
        : tmp(yuzu::test::unique_temp_path("yuzu_test_settings_mfa_")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));
        // Mirror admin / bob into AuthDB so the MFA accessor surface
        // works (mfa_status / mfa_init_enrollment do is_active reads).
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(
            auth_db
                ->upsert_user("admin",
                              auth::AuthManager::pbkdf2_sha256("adminpassword1", salt, 100'000),
                              salt_hex, auth::Role::admin)
                .has_value());
        auth_mgr.set_auth_db(auth_db.get());
        session_user = "admin";

        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            if (use_cookie_sessions)
                return auth_mgr.validate_session(AuthRoutes::extract_session_cookie(req));
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.auth_source = session_auth_source;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn, oidc_mu,
                               oidc_provider, /*metrics_registry=*/&metrics, std::move(step_up_fn));
        // The recovery-codes and disable routes use the factor-credential gate, not step_up_fn.
        // Default: admit at the account's CURRENT generation (what the real gate would admit for
        // a caller holding a fresh bound proof); tests that exercise the gate replace it.
        routes.set_factor_credential_gate_fn(
            [this](const httplib::Request&, httplib::Response&, const auth::Session& s,
                   const std::string&) -> std::optional<StepUpAdmission> {
                const auto st = auth_db->mfa_status(s.username);
                return StepUpAdmission{true, st ? st->factor_gen : 0};
            });
    }

    /// True if any captured audit row matches action + result + (optional) target_id.
    bool has_audit(std::string_view action, std::string_view result = {},
                   std::string_view target_id = {}) const {
        for (const auto& a : audit_calls) {
            if (a.action != action)
                continue;
            if (!result.empty() && a.result != result)
                continue;
            if (!target_id.empty() && a.target_id != target_id)
                continue;
            return true;
        }
        return false;
    }

    /// Return the most recent matching audit detail string, or empty.
    std::string audit_detail(std::string_view action) const {
        for (auto it = audit_calls.rbegin(); it != audit_calls.rend(); ++it) {
            if (it->action == action)
                return it->detail;
        }
        return {};
    }
};

/// Detaches the SessionStore from the AuthManager on every exit path, so a failed REQUIRE
/// never leaves the manager holding a pointer to a destroyed store.
struct SessionStoreDetach {
    auth::AuthManager& m;
    ~SessionStoreDetach() { m.set_session_store(nullptr); }
};

/// Enrol `user` with a verified TOTP factor (a usable second factor).
void enrol_verified(MfaSettingsHarness& h, const std::string& user = "admin") {
    auto init = h.auth_db->mfa_init_enrollment(user, "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment(user, code, std::nullopt).has_value());
}

/// The `result` column of every captured `mfa.disabled` row, in write order.
std::vector<std::string> disable_results(const MfaSettingsHarness& h) {
    std::vector<std::string> out;
    for (const auto& a : h.audit_calls)
        if (a.action == "mfa.disabled")
            out.push_back(a.result);
    return out;
}

/// Convenience: POST with same-origin Origin header so the CSRF gate
/// passes (host equality after default-port normalisation).
std::unique_ptr<httplib::Response>
post_same_origin(yuzu::server::test::TestRouteSink& sink, const std::string& path,
                 const std::string& body = {}) {
    return sink.dispatch("POST", path, body, "application/x-www-form-urlencoded",
                         {{"Host", "yuzu.example"}, {"Origin", "http://yuzu.example"}});
}

} // namespace

/// `auth.users.mfa_enrolled_at` as epoch milliseconds, read from the column (0 = not enrolled).
static std::int64_t enrolled_ms(yuzu::test::AuthDbPg& auth_db, const std::string& user) {
    auto lease = auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT COALESCE((extract(epoch from mfa_enrolled_at)*1000)::bigint, 0) "
        "FROM auth.users WHERE username = $1",
        std::vector<std::string>{user});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
}

TEST_CASE("GET /fragments/settings/mfa renders 'Not enrolled' panel for fresh admin",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = h.sink.Get("/fragments/settings/mfa");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Not enrolled") != std::string::npos);
    CHECK(res->body.find("Set up two-factor") != std::string::npos);
    // GETs are not CSRF-sensitive — no csrf.denied should fire.
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("POST /api/settings/mfa/init reveals secret with Cache-Control: no-store",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Reveal contract — secret + URI in the body, plus the cache-busting
    // headers added by PR1's set_no_store helper.
    CHECK(res->body.find("otpauth://totp/Yuzu") != std::string::npos);
    CHECK(res->body.find("Base32 secret") != std::string::npos);
    // The provisional reveal now renders the inline SVG QR (#1232 wiring).
    CHECK(res->body.find("<svg") != std::string::npos);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Pragma") == "no-cache");
    CHECK(res->get_header_value("Referrer-Policy") == "no-referrer");
    CHECK(h.has_audit("mfa.enroll.initiated", "ok", "admin"));
}

TEST_CASE("POST /api/settings/mfa/init twice returns MfaAlreadyEnrolled with operator message",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Stand up an enrolled state through the AuthDB directly so the
    // second init hits the "already enrolled" branch.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("MFA is already enabled") != std::string::npos);
    CHECK(h.has_audit("mfa.enroll.initiated", "error", "admin"));
}

TEST_CASE("POST /api/settings/mfa/recovery-codes regenerates 10 codes + cache headers",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Get into enrolled state via the same path the panel uses
    // server-side.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/recovery-codes");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    // Each recovery code is XXXX-XXXX-XXXX-XXXX (19 chars). Look for a
    // representative bullet pattern.
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.has_audit("mfa.recovery_codes.generated", "ok", "admin"));
}

namespace {

/// Starts an enrolment for `user` and returns a currently-valid TOTP code for it.
std::string begin_admin_enrolment(MfaSettingsHarness& h, const std::string& user = "admin") {
    auto init = h.auth_db->mfa_init_enrollment(user, "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
}

std::unique_ptr<httplib::Response> post_verify_with_cookie(MfaSettingsHarness& h,
                                                           const std::string& code,
                                                           const std::string& cookie_token) {
    std::unordered_map<std::string, std::string> headers{
        {"Host", "yuzu.example"}, {"Origin", "http://yuzu.example"}};
    if (!cookie_token.empty())
        headers["Cookie"] = "yuzu_session=" + cookie_token;
    return h.sink.dispatch("POST", "/api/settings/mfa/verify", "code=" + code,
                           "application/x-www-form-urlencoded", headers);
}

bool has_step_up_proof(const MfaSettingsHarness& h, const std::string& token) {
    const auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    return s->steady_mfa_verified.time_since_epoch().count() != 0;
}

} // namespace

TEST_CASE("an in-handler step-up refusal on an htmx request sends exactly one HX-Trigger toast",
          "[pg][mfa][routes][settings][stepup]") {
    // The factor-credential gate refuses through the shared renderer (as require_mfa_step_up does);
    // the handler then calls toast_step_up_refusal, which must not append a second HX-Trigger
    // (httplib's Response::set_header emplaces into a multimap).
    MfaSettingsHarness h;
    h.routes.set_factor_credential_gate_fn(
        [](const httplib::Request& req, httplib::Response& res, const auth::Session& session,
           const std::string&) -> std::optional<StepUpAdmission> {
            StepUpVerdict v;
            v.decision = StepUpDecision::kChallenge;
            v.user = session.username;
            render_step_up_refusal(req, res, v, StepUpSurface::kRest);
            return std::nullopt;
        });
    for (const char* path : {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable"}) {
        CAPTURE(path);
        auto res = h.sink.dispatch("POST", path, {}, "application/x-www-form-urlencoded",
                                   {{"Host", "yuzu.example"},
                                    {"Origin", "http://yuzu.example"},
                                    {"HX-Request", "true"}});
        REQUIRE(res);
        CHECK(res->status == 401);
        REQUIRE(res->get_header_value_count("HX-Trigger") == 1);
        const auto t = nlohmann::json::parse(res->get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["level"] == "error");
        CHECK(t["showToast"]["message"] == "MFA step-up required");
    }
}

TEST_CASE("a step-up refusal that wrote no toast still gets the Settings handler's toast",
          "[pg][mfa][routes][settings][stepup]") {
    // A gate that refuses without rendering through the shared renderer (a 401 envelope, no
    // HX-Trigger): the handler's own toast fills the gap, with the envelope's message.
    MfaSettingsHarness h;
    h.routes.set_factor_credential_gate_fn(
        [](const httplib::Request&, httplib::Response& res, const auth::Session&,
           const std::string&) -> std::optional<StepUpAdmission> {
            res.status = 401;
            res.set_content(R"({"error":{"message":"custom refusal"}})", "application/json");
            return std::nullopt;
        });
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/recovery-codes", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"}, {"Origin", "http://yuzu.example"}});
    REQUIRE(res);
    REQUIRE(res->get_header_value_count("HX-Trigger") == 1);
    const auto t = nlohmann::json::parse(res->get_header_value("HX-Trigger"));
    CHECK(t["showToast"]["message"] == "custom refusal");
}

TEST_CASE("POST /api/settings/mfa/verify on an already-enrolled account audits mfa.enroll.race, "
          "not mfa.enroll.failed (#3777)",
          "[pg][mfa][routes][settings]") {
    // A concurrent verify can win the enrollment race between this operator's
    // init and their verify — mfa_verify_enrollment then returns
    // MfaAlreadyEnrolled (the top-of-function enrolled-state check short-circuits
    // before the code is even examined, so the submitted code's validity is
    // immaterial). That benign race must be audited distinctly (CC7.2), never as
    // mfa.enroll.failed (a bad-code attempt) or a store outage, and must tell the
    // operator the true state. Simulate the winner by enrolling admin out-of-band.
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    // Concurrent winner: enroll out-of-band, then drive the settings verify route
    // with the same still-valid code the racing operator would have submitted.
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
    // A valid local cookie session for the same user: the loser of the race is still not stamped.
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());

    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("already enrolled") != std::string::npos);
    CHECK_FALSE(has_step_up_proof(h, token));
    // Audited as the benign race, NOT as a rejected code or a verified enrollment,
    // and no store-outage path.
    CHECK(h.has_audit("mfa.enroll.race", "ok", "admin"));
    CHECK_FALSE(h.has_audit("mfa.enroll.failed"));
    CHECK_FALSE(h.has_audit("mfa.enroll.verified"));
}

TEST_CASE("POST /api/settings/mfa/verify tells the operator to start again and audits "
          "mfa.enroll.cancelled when a concurrent disable lands mid-verify (#3808)",
          "[pg][mfa][routes][settings]") {
    // The REAL race (see run_enroll_verify_race): a committed MFA disable lands between the
    // verify's secret load and its guarded UPDATE. Before #3808 this graded WriteFailed, which
    // the route reported as "authentication store is temporarily unavailable" and counted as a
    // secret-unavailable degrade; the store was fine and the enrolment had simply been cancelled.
    MfaSettingsHarness h;
    const auto code = begin_admin_enrolment(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());

    std::unique_ptr<httplib::Response> res;
    REQUIRE(yuzu::test::run_enroll_verify_race(
        h.auth_db.dsn(), "admin",
        {"UPDATE auth.users SET mfa_totp_secret = NULL, mfa_enrolled_at = NULL WHERE "
         "username = $1"},
        [&] { res = post_verify_with_cookie(h, code, token); }));

    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("cancelled or replaced") != std::string::npos);
    // Honest about what happened: not the store-outage wording, not "code rejected".
    CHECK(res->body.find("temporarily unavailable") == std::string::npos);
    CHECK(res->body.find("Code rejected") == std::string::npos);
    // RECOVERABLE: the operator is told to start again, so the page must OFFER that. A
    // non-empty `enrollment_pending_for_verify` forced the provisional confirm form instead
    // (a code box whose secret is gone, a "wait for the next code" hint, no Set-up button;
    // under enforcement not even Cancel). The not-enrolled state has the Set-up button.
    CHECK(res->body.find("Set up two-factor") != std::string::npos);
    CHECK(res->body.find("wait for the next code") == std::string::npos);
    CHECK(res->body.find("Confirm code") == std::string::npos);
    // The audit detail states only the observed fact and NEVER a cause: a named "disable"
    // sends an auditor looking for an mfa.disabled row that may not exist (the stale-
    // provisional sweep, `--mfa-reset` and a KEK rewrap reach this path with no disable).
    CHECK(h.audit_detail("mfa.enroll.cancelled") ==
          "reason=provisional_secret_changed; nothing enrolled");
    CHECK(h.audit_detail("mfa.enroll.cancelled").find("disable") == std::string::npos);
    CHECK_FALSE(has_step_up_proof(h, token)); // nothing enrolled, so no proof is earned
    CHECK(h.has_audit("mfa.enroll.cancelled", "ok", "admin"));
    CHECK_FALSE(h.has_audit("mfa.enroll.failed"));
    CHECK_FALSE(h.has_audit("mfa.enroll.race"));
    CHECK_FALSE(h.has_audit("mfa.enroll.verified"));
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
}


TEST_CASE("POST /api/settings/mfa/verify success stamps a step-up proof on the current session",
          "[pg][mfa][routes][settings][stepup]") {
    // An admin who enrols in a session and immediately regenerates recovery codes or disables
    // MFA must not be refused for want of a proof: the confirming code IS a fresh proof.
    MfaSettingsHarness h;
    // The generic gate judges the STORED proof, so the sessions live in a real session store.
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin,
                                                                /*mfa_verified=*/false);
    REQUIRE_FALSE(token.empty());
    // A second, unrelated session of the same user: the control that the stamp is per-session.
    const auto other = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(other.empty());
    REQUIRE_FALSE(has_step_up_proof(h, token));

    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);

    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=stamped");
    CHECK(has_step_up_proof(h, token));
    CHECK_FALSE(has_step_up_proof(h, other));

    // The decision a kRequired route applies: the stamped session passes, the control does not.
    const auto stamped = h.auth_mgr.validate_session(token);
    const auto unstamped = h.auth_mgr.validate_session(other);
    REQUIRE(stamped.has_value());
    REQUIRE(unstamped.has_value());
    // The generic gate also judges the stored proof, so read each session's own from the store.
    const DurableProofReadFn read_stamped = [&] {
        return h.auth_mgr.read_durable_mfa_proof(token, "admin");
    };
    const DurableProofReadFn read_unstamped = [&] {
        return h.auth_mgr.read_durable_mfa_proof(other, "admin");
    };
    CHECK(
        decide_step_up(*stamped, *h.auth_db, read_stamped, 300, "optional", StepUpClass::kRequired)
            .passed());
    CHECK(decide_step_up(*unstamped, *h.auth_db, read_unstamped, 300, "optional",
                         StepUpClass::kRequired)
              .decision == StepUpDecision::kChallenge);
}

TEST_CASE("POST /api/settings/mfa/verify failure never stamps a step-up proof",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    (void)begin_admin_enrolment(h);

    // A 5-digit value is never a valid TOTP code, so this cannot pass by coincidence.
    auto res = post_verify_with_cookie(h, "12345", token);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Code rejected") != std::string::npos);
    CHECK(h.has_audit("mfa.enroll.failed", "error", "admin"));
    CHECK_FALSE(h.has_audit("mfa.enroll.verified"));
    CHECK_FALSE(has_step_up_proof(h, token));
    CHECK_FALSE(h.auth_db->mfa_status("admin")->enrolled);
}

TEST_CASE("POST /api/settings/mfa/verify stamps only a cookie that resolves to the same local user",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    auto salt = auth::AuthManager::random_bytes(16);
    REQUIRE(h.auth_db
                ->upsert_user("bob",
                              auth::AuthManager::pbkdf2_sha256("bobpassword12", salt, 100'000),
                              auth::AuthManager::bytes_to_hex(salt), auth::Role::user)
                .has_value());
    const auto bob_token = h.auth_mgr.create_local_session_for_test("bob", auth::Role::user, false);
    REQUIRE_FALSE(bob_token.empty());

    SECTION("a cookie of a different user is not stamped (the enrolment itself still commits)") {
        const auto code = begin_admin_enrolment(h);
        auto res = post_verify_with_cookie(h, code, bob_token);
        REQUIRE(res);
        CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
        CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped");
        CHECK_FALSE(has_step_up_proof(h, bob_token));
    }
    SECTION("no cookie (a bearer-authenticated caller) is not stamped") {
        const auto code = begin_admin_enrolment(h);
        auto res = post_verify_with_cookie(h, code, {});
        REQUIRE(res);
        CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
        CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped");
    }
}

TEST_CASE("POST /api/settings/mfa/verify never stamps from a non-local settings session",
          "[pg][mfa][routes][settings][stepup]") {
    // The first guard in the stamp block (`session->auth_source == "local"`). The settings
    // principal here is an OIDC session; the cookie is a LOCAL session of the same user name, so
    // only that guard stands between the enrolment and a stamped proof.
    MfaSettingsHarness h;
    h.session_auth_source = "oidc";
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE_FALSE(has_step_up_proof(h, token));

    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->status == 200);
    // The enrolment itself still commits and reveals the one-time codes.
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.has_audit("mfa.recovery_codes.generated", "ok", "admin"));
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped");
    CHECK(h.auth_db->mfa_status("admin")->enrolled);
    CHECK_FALSE(has_step_up_proof(h, token));
}

TEST_CASE("POST /api/settings/mfa/verify never stamps an OIDC cookie session that shares the user name",
          "[pg][mfa][routes][settings][stepup]") {
    // The second guard (`cookie_session->auth_source == "local"`). The settings session is local
    // and the cookie resolves to the SAME user name, but the cookie's session is an OIDC one. No
    // login flow mints an OIDC session under a plain local name (it is "oidc:<iss>#<sub>", which
    // AuthDB refuses as a user name), so the row is authored straight into the durable store: this
    // pins the guard itself, not the reachability of the shape.
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};

    const std::string raw_token = "yuzu-test-oidc-cookie-token-0001";
    SessionWriteParams params;
    params.token_hash = auth::AuthManager::sha256_hex(raw_token);
    params.username = "admin";
    params.role = "admin";
    params.auth_source = "oidc";
    params.session_lifetime_ms = 3600'000;
    REQUIRE(sessions.create(params).has_value());
    const auto cookie_session = h.auth_mgr.validate_session(raw_token);
    REQUIRE(cookie_session.has_value());
    REQUIRE(cookie_session->auth_source == "oidc");
    REQUIRE(cookie_session->username == "admin");
    REQUIRE_FALSE(has_step_up_proof(h, raw_token));

    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, raw_token);
    REQUIRE(res);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped");
    CHECK_FALSE(has_step_up_proof(h, raw_token));
}

TEST_CASE("POST /api/settings/mfa/verify: a failed durable stamp reports not_stamped and keeps "
          "the enrolment",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};
    yuzu::test::SessionWipeFault fault{h.auth_db.pool()}; // RAII: repaired on every exit path

    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    const auto code = begin_admin_enrolment(h);
    // A first validate confirms this replica's generation view, which is what lets the cache be
    // trusted once the store is damaged.
    REQUIRE(h.auth_mgr.validate_session(token).has_value());

    // The durable sessions table is moved aside: the cookie still validates from this replica's
    // cache (so the stamp block reaches `mark_session_mfa_verified`), whose durable write fails.
    fault.arm();
    REQUIRE(h.auth_mgr.validate_session(token).has_value());

    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped");
    CHECK(h.has_audit("mfa.recovery_codes.generated", "ok", "admin"));
    CHECK(h.auth_db->mfa_status("admin")->enrolled);
    CHECK_FALSE(has_step_up_proof(h, token));
}

namespace {

/// The enrol-confirm stamp catch logs one sampled line (the first hit of a process-wide counter,
/// then 1 in `kStampThrewLogEvery`). Any `kStampThrewLogEvery` consecutive throwing confirms therefore log exactly once whatever the
/// counter held on entry, so the cases below drive 100 on one harness (the account is un-enrolled
/// between rounds) and assert on the whole run instead of depending on test order.
constexpr int kStampSampleWindow = static_cast<int>(kStampThrewLogEvery);

struct StampThrowRun {
    std::string logs;
    int confirms{0};
    int ok_responses{0};
    int stamped{0};
    int hook_calls{0}; // times the fault hook actually ran (must equal the window)
};

StampThrowRun run_throwing_confirms(MfaSettingsHarness& h, std::function<void()> hook) {
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    StampThrowRun run;
    // Count every hook invocation so a confirm that skipped the seam fails loudly.
    std::atomic<int> hook_calls{0};
    h.routes.set_stamp_fault_hook_for_test([&hook_calls, hook = std::move(hook)] {
        hook_calls.fetch_add(1, std::memory_order_relaxed);
        hook();
    });
    // The hook borrows `hook_calls` from this frame: clear it on every exit, including a REQUIRE
    // that throws mid-loop (declared after `hook_calls`, so it runs before that dies).
    yuzu::test::ScopeExit clear_hook{[&h] { h.routes.set_stamp_fault_hook_for_test(nullptr); }};
    yuzu::test::LogCapture capture(spdlog::level::warn);
    for (int i = 0; i < kStampSampleWindow; ++i) {
        const auto code = begin_admin_enrolment(h);
        auto res = post_verify_with_cookie(h, code, token);
        REQUIRE(res);
        ++run.confirms;
        if (res->status == 200 &&
            res->body.find("Store these recovery codes now") != std::string::npos)
            ++run.ok_responses;
        // The enrolment committed even though the stamp threw.
        REQUIRE(h.auth_db->mfa_status("admin")->enrolled);
        if (has_step_up_proof(h, token))
            ++run.stamped;
        REQUIRE(h.auth_db->mfa_disable("admin").has_value());
    }
    capture.stop(); // quiesce before reading the captured text
    run.logs = capture.text();
    run.hook_calls = hook_calls.load();
    return run;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}

std::size_t count_audit(const MfaSettingsHarness& h, std::string_view action,
                        std::string_view detail = {}) {
    std::size_t n = 0;
    for (const auto& a : h.audit_calls)
        if (a.action == action && (detail.empty() || a.detail == detail))
            ++n;
    return n;
}

} // namespace

TEST_CASE("POST /api/settings/mfa/verify: a std::exception from the stamp keeps the codes reveal "
          "and the audit rows, records not_stamped, and logs one sanitised sampled line",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    // A control byte in what() must reach the log sanitised ('?'), never raw.
    const auto run = run_throwing_confirms(h, [] { throw std::runtime_error("boo\x01m\nFORGED"); });

    CHECK(run.hook_calls == kStampSampleWindow);
    CHECK(run.ok_responses == run.confirms);
    CHECK(run.stamped == 0);
    CHECK(count_audit(h, "mfa.enroll.verified", "step_up_proof=not_stamped") ==
          static_cast<std::size_t>(run.confirms));
    CHECK(count_audit(h, "mfa.enroll.verified", "step_up_proof=stamped") == 0);
    CHECK(count_audit(h, "mfa.recovery_codes.generated") == static_cast<std::size_t>(run.confirms));

    const std::string line = "enrol-confirm: step-up proof stamp threw; recording not_stamped";
    CHECK(count_of(run.logs, line) == 1);
    CHECK(count_of(run.logs, "(boo?m?FORGED)") == 1);
    CHECK(run.logs.find('\x01') == std::string::npos);
    // One well-formed line: the only control byte is its own terminator.
    CHECK(yuzu::test::stray_control_bytes(run.logs) == 0);
}

TEST_CASE("POST /api/settings/mfa/verify: a non-std throw from the stamp has the same outcome and "
          "logs one line without a cause",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    const auto run = run_throwing_confirms(h, [] { throw 42; });

    CHECK(run.hook_calls == kStampSampleWindow);
    CHECK(run.ok_responses == run.confirms);
    CHECK(run.stamped == 0);
    CHECK(count_audit(h, "mfa.enroll.verified", "step_up_proof=not_stamped") ==
          static_cast<std::size_t>(run.confirms));
    CHECK(count_audit(h, "mfa.recovery_codes.generated") == static_cast<std::size_t>(run.confirms));

    const std::string line = "enrol-confirm: step-up proof stamp threw; recording not_stamped";
    CHECK(count_of(run.logs, line) == 1);
    // The no-cause form ends right after "not_stamped": no parenthesised what().
    CHECK(count_of(run.logs, line + " (") == 0);
    CHECK(yuzu::test::stray_control_bytes(run.logs) == 0);
}

TEST_CASE("POST /api/settings/mfa/verify: an empty-effect stamp fault hook leaves the stamp as today",
          "[pg][mfa][routes][settings][stepup]") {
    // Control: the seam is inert when it does not throw.
    MfaSettingsHarness h;
    h.routes.set_stamp_fault_hook_for_test([] {});
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    REQUIRE_FALSE(has_step_up_proof(h, token));

    yuzu::test::LogCapture capture(spdlog::level::warn);
    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    capture.stop();
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=stamped");
    CHECK(has_step_up_proof(h, token));
    CHECK(capture.text().find("stamp threw") == std::string::npos);
}

TEST_CASE("Settings MFA init/verify queued behind a password reset refuses with credential_changed "
          "(#5342 F4)",
          "[pg][mfa][routes][settings][password]") {
    // #5342 Gate 8 iteration 3 (F4). A REAL CredentialChangeOwner resets the
    // admin's password; its pre-commit hook (every lock held, the provisional
    // secret already wiped but uncommitted) fires the Settings route, waits
    // until the route's guarded write is queued on the account's row lock,
    // then lets the reset commit. The write re-evaluates against the committed
    // row and lands as CredentialChanged: the operator sees "sign in again",
    // the audit row is mfa.enroll.failed/credential_changed, nothing is
    // revealed, written or enrolled.
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()}; // migrates session_store (the owner DELETEs from it)
    AuditStore audit_store{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    REQUIRE(audit_store.is_open());
    CredentialChangeOwner owner{h.auth_db.pool(), &audit_store};

    CredentialChangeRequest req;
    req.kind = CredentialChangeRequest::Kind::kAdminReset;
    req.username = "admin";
    auto salt = auth::AuthManager::random_bytes(16);
    req.new_hash_hex = auth::AuthManager::pbkdf2_sha256("a-brand-new-password-1", salt, 100'000);
    req.new_salt_hex = auth::AuthManager::bytes_to_hex(salt);
    req.audit_template.principal = "root";
    req.audit_template.target_type = "User";
    req.audit_template.target_id = "admin";

    std::string path;
    std::string body;
    std::string waiter_like;
    SECTION("init") {
        path = "/api/settings/mfa/init";
        waiter_like = "%UPDATE auth.users SET mfa_totp_secret%";
    }
    SECTION("verify") {
        auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        path = "/api/settings/mfa/verify";
        body = "code=" + mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        waiter_like = "%UPDATE auth.users SET mfa_enrolled_at%";
    }

    // A valid local cookie session for the same user: a refused enrolment never stamps it.
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    const std::unordered_map<std::string, std::string> racer_headers{
        {"Host", "yuzu.example"},
        {"Origin", "http://yuzu.example"},
        {"Cookie", "yuzu_session=" + token}};

    std::unique_ptr<httplib::Response> racing;
    std::atomic<bool> fired{false};
    bool waiter_seen = false;
    std::jthread racer; // joined on every exit path
    owner.set_pre_commit_hook_for_test([&] {
        if (fired.exchange(true))
            return;
        racer = std::jthread([&] {
            racing = h.sink.dispatch("POST", path, body, "application/x-www-form-urlencoded",
                                     racer_headers);
        });
        waiter_seen = yuzu::test::wait_for_pg_lock_waiter(h.auth_db.dsn(), waiter_like);
    });
    const auto out = owner.commit(req);
    if (racer.joinable())
        racer.join();
    owner.set_pre_commit_hook_for_test(nullptr); // after the join
    REQUIRE(fired);
    REQUIRE(out.result == CredentialChangeResult::kOk);
    CHECK(waiter_seen);

    REQUIRE(racing);
    INFO("body=" << racing->body);
    CHECK(racing->status == 200);
    CHECK(racing->body.find("Your password changed during enrolment") != std::string::npos);
    CHECK(racing->body.find("otpauth://") == std::string::npos); // no reveal
    CHECK(racing->body.find("Store these recovery codes now") == std::string::npos); // no recovery codes
    CHECK(h.has_audit("mfa.enroll.failed", "error", "admin"));
    CHECK(h.audit_detail("mfa.enroll.failed") == "credential_changed");
    CHECK_FALSE(h.has_audit("mfa.enroll.verified"));
    CHECK_FALSE(has_step_up_proof(h, token));
    CHECK_FALSE(h.auth_db->mfa_status("admin")->enrolled);
    yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(
        conn.get(), "SELECT (mfa_totp_secret IS NULL)::text FROM auth.users WHERE username='admin'")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "true");
}

TEST_CASE("POST /api/settings/mfa/disable clears state + emits mfa.disabled",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The account's sessions end with the factor (#6079), so the response is the logout
    // exit: the cookie is dropped and htmx is sent to the landing page.
    CHECK(res->get_header_value("HX-Redirect") == "/home");
    CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") != std::string::npos);
    CHECK(h.has_audit("mfa.disabled", "ok", "admin"));
    // Two rows: the intent row is written BEFORE the clear, the outcome row after (#6079 au-F1).
    CHECK(disable_results(h) == std::vector<std::string>{"attempted", "ok"});

    // DB-side: secret cleared + recovery codes deleted (atomic via TxnGuard).
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
    CHECK(status->recovery_codes_remaining == 0);
}

namespace {

struct StoreScope {
    SessionStore sessions;
    auth::AuthManager& mgr;
    explicit StoreScope(MfaSettingsHarness& h) : sessions{h.auth_db.pool()}, mgr(h.auth_mgr) {
        REQUIRE(sessions.is_open());
        mgr.set_session_store(&sessions);
    }
    ~StoreScope() { mgr.set_session_store(nullptr); }
};

} // namespace

TEST_CASE("POST /api/settings/mfa/disable ends EVERY session of the account, the caller's included "
          "(#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    auto& sessions = scope.sessions;

    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    {
        auto salt = auth::AuthManager::random_bytes(16);
        REQUIRE(h.auth_db
                    ->upsert_user("bob",
                                  auth::AuthManager::pbkdf2_sha256("bobpassword12", salt, 100'000),
                                  auth::AuthManager::bytes_to_hex(salt), auth::Role::user)
                    .has_value());
    }
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    const auto other = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    const auto bobs = h.auth_mgr.create_local_session_for_test("bob", auth::Role::user, false);
    REQUIRE_FALSE(mine.empty());
    REQUIRE_FALSE(other.empty());
    REQUIRE_FALSE(bobs.empty());

    // Warm the validate cache so the assertions below prove the local erase, not a cold miss.
    REQUIRE(h.auth_mgr.validate_session(mine).has_value());
    REQUIRE(h.auth_mgr.validate_session(other).has_value());
    REQUIRE(h.auth_mgr.validate_session(bobs).has_value());

    // The row is written after the actor's own session is deleted, so it must go through the
    // session-bound writer: record what that writer is handed.
    std::string bound_user, bound_role, bound_action, bound_result;
    std::vector<std::string> bound_results;
    h.routes.set_audit_as_session_fn([&](const httplib::Request&, const auth::Session& s,
                                         const std::string& role, const std::string& action,
                                         const std::string& result, const std::string&,
                                         const std::string&, const std::string&) {
        bound_user = s.username;
        bound_role = role;
        bound_action = action;
        bound_result = result;
        bound_results.push_back(result);
        return true;
    });

    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(bound_user == "admin");
    CHECK(bound_role == "admin");
    CHECK(bound_action == "mfa.disabled");
    CHECK(bound_result == "ok");
    // Intent row first, outcome row last, both through the session-bound writer.
    CHECK(bound_results == std::vector<std::string>{"attempted", "ok"});
    CHECK(res->get_header_value("HX-Redirect") == "/home");
    CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") != std::string::npos);
    // Written through the session-bound writer, not the request-resolving one.
    CHECK_FALSE(h.has_audit("mfa.disabled"));

    // Durable view: both sessions of the account are gone, an unrelated user's row survives.
    CHECK_FALSE(sessions.find(auth::AuthManager::sha256_hex(mine)).value().has_value());
    CHECK_FALSE(sessions.find(auth::AuthManager::sha256_hex(other)).value().has_value());
    CHECK(sessions.find(auth::AuthManager::sha256_hex(bobs)).value().has_value());
    // Cache view (warmed above): neither account session validates; bob's still does.
    CHECK_FALSE(h.auth_mgr.validate_session(mine).has_value());
    CHECK_FALSE(h.auth_mgr.validate_session(other).has_value());
    CHECK(h.auth_mgr.validate_session(bobs).has_value());
}

TEST_CASE("POST /api/settings/mfa/disable reports a failed session delete and audits it as partial "
          "(#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    StoreScope scope(h);

    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    // The factor clear commits first, so a session store that cannot delete leaves the factor
    // cleared and the sessions alive: the response must say so and must not redirect.
    yuzu::test::SqlFault fault(h.auth_db.pool(),
                               "ALTER TABLE session_store.sessions RENAME TO sessions_gone",
                               "ALTER TABLE session_store.sessions_gone RENAME TO sessions");
    fault.arm();
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    fault.repair();
    REQUIRE(res);
    CHECK(res->get_header_value("HX-Redirect").empty());
    CHECK(res->body.find("sessions could not be ended") != std::string::npos);
    CHECK(res->body.find("Try again") == std::string::npos);
    CHECK(h.has_audit("mfa.disabled", "partial", "admin"));
    CHECK(disable_results(h) == std::vector<std::string>{"attempted", "partial"});
    CHECK(h.audit_detail("mfa.disabled").find("sessions_ended=failed") != std::string::npos);
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
}

TEST_CASE("POST /api/settings/mfa/disable cancelling an unfinished enrolment keeps the sessions "
          "(#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    auto& sessions = scope.sessions;
    // A provisional secret that was never verified: no usable factor exists.
    REQUIRE(h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt).has_value());
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("HX-Redirect").empty());
    CHECK(h.has_audit("mfa.disabled", "ok", "admin"));
    CHECK(h.audit_detail("mfa.disabled") == "no verified factor to clear");
    CHECK(sessions.find(auth::AuthManager::sha256_hex(mine)).value().has_value());
    CHECK(h.auth_mgr.validate_session(mine).has_value());
}

TEST_CASE("POST /api/settings/mfa/disable still ends the sessions when the clear fails "
          "(#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    auto& sessions = scope.sessions;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    // The clear may commit with its acknowledgement lost: an enrolled account's sessions end
    // even though the call reports failure. Break the users table so mfa_disable errors.
    yuzu::test::SqlFault fault(h.auth_db.pool(), "ALTER TABLE auth.users RENAME TO users_gone",
                               "ALTER TABLE auth.users_gone RENAME TO users");
    fault.arm();
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    fault.repair();
    REQUIRE(res);
    CHECK(h.has_audit("mfa.disabled", "error", "admin"));
    CHECK(h.audit_detail("mfa.disabled") == "disable failed (sessions_ended=1)");
    CHECK(disable_results(h) == std::vector<std::string>{"attempted", "error"});
    CHECK(res->get_header_value("HX-Redirect") == "/home");
    CHECK_FALSE(sessions.find(auth::AuthManager::sha256_hex(mine)).value().has_value());
}

TEST_CASE("AuthDB::mfa_disable_report reports the pre-image of the clear itself (#6079)",
          "[pg][mfa][auth_db]") {
    MfaSettingsHarness h;
    // Provisional secret only: nothing verified, so the report is false.
    REQUIRE(h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt).has_value());
    auto provisional = h.auth_db->mfa_disable_report("admin", std::nullopt);
    REQUIRE(provisional.has_value());
    CHECK_FALSE(*provisional);

    // Verified factor: true, and the factor is gone afterwards.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
    auto verified = h.auth_db->mfa_disable_report("admin", std::nullopt);
    REQUIRE(verified.has_value());
    CHECK(*verified);
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);

    // Already cleared: false (idempotent). An unknown account matches no row and reports true,
    // so a caller deciding whether to end sessions fails safe.
    auto again = h.auth_db->mfa_disable_report("admin", std::nullopt);
    REQUIRE(again.has_value());
    CHECK_FALSE(*again);
    auto unknown = h.auth_db->mfa_disable_report("nobody", std::nullopt);
    REQUIRE(unknown.has_value());
    CHECK(*unknown);
}

TEST_CASE("POST /api/settings/mfa/disable says the state is unknown when neither the clear nor "
          "the delete is confirmed (#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    yuzu::test::SqlFault users_fault(h.auth_db.pool(),
                                     "ALTER TABLE auth.users RENAME TO users_gone",
                                     "ALTER TABLE auth.users_gone RENAME TO users");
    yuzu::test::SqlFault sessions_fault(
        h.auth_db.pool(), "ALTER TABLE session_store.sessions RENAME TO sessions_gone",
        "ALTER TABLE session_store.sessions_gone RENAME TO sessions");
    users_fault.arm();
    sessions_fault.arm();
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    sessions_fault.repair();
    users_fault.repair();
    REQUIRE(res);
    CHECK(res->get_header_value("HX-Redirect").empty());
    CHECK(res->body.find("state is unknown") != std::string::npos);
    CHECK(h.has_audit("mfa.disabled", "error", "admin"));
    CHECK(h.audit_detail("mfa.disabled") == "disable failed (sessions_ended=failed)");
}

// au-F1 (#6079): the intent row is the fail-closed gate. A clear that cannot be recorded does not
// happen: the factor stays enrolled, every session survives, and the response is a 503 carrying
// Sec-Audit-Failed.
TEST_CASE("POST /api/settings/mfa/disable refuses to clear when the intent audit row cannot be "
          "written (#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    yuzu::server::SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    SessionStoreDetach detach{h.auth_mgr};
    enrol_verified(h);
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    std::vector<std::string> results;
    h.routes.set_audit_as_session_fn(
        [&](const httplib::Request&, const auth::Session&, const std::string&, const std::string&,
            const std::string& result, const std::string&, const std::string&, const std::string&) {
            results.push_back(result);
            return false; // the audit store rejects every row
        });
    yuzu::test::LogCapture logs;
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    logs.stop();
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->get_header_value("HX-Redirect").empty());
    CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") == std::string::npos);
    CHECK(res->body.find("MFA was not changed") != std::string::npos);
    CHECK(res->get_header_value("Retry-After") == "5");
    // /settings drops a 5xx body, so the refusal also rides an HX-Trigger toast.
    const auto toast = nlohmann::json::parse(res->get_header_value("HX-Trigger"));
    CHECK(toast["showToast"]["message"] == "Audit store unavailable; MFA was not changed.");
    CHECK(toast["showToast"]["level"] == "error");
    // Only the intent row was attempted: nothing after it ran.
    CHECK(results == std::vector<std::string>{"attempted"});
    CHECK(logs.text().find("MFA was NOT changed") != std::string::npos);
    // The factor is untouched and the session is intact, durably and in the cache.
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
    CHECK(sessions.find(auth::AuthManager::sha256_hex(mine)).value().has_value());
    CHECK(h.auth_mgr.validate_session(mine).has_value());
}

// The clear has no undo, so a lost OUTCOME row neither stops it nor changes the response; it is
// logged at error level so the missing evidence is not silent.
TEST_CASE("POST /api/settings/mfa/disable logs a lost outcome audit row and still completes "
          "(#6079)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    yuzu::server::SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    SessionStoreDetach detach{h.auth_mgr};
    enrol_verified(h);
    const auto mine = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(mine.empty());

    std::vector<std::string> results;
    h.routes.set_audit_as_session_fn(
        [&](const httplib::Request&, const auth::Session&, const std::string&, const std::string&,
            const std::string& result, const std::string&, const std::string&, const std::string&) {
            results.push_back(result);
            return result == "attempted"; // the intent row lands, the outcome row does not
        });
    yuzu::test::LogCapture logs;
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                               "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"},
                                {"Origin", "http://yuzu.example"},
                                {"Cookie", "yuzu_session=" + mine}});
    logs.stop();
    REQUIRE(res);
    // Same response as when the outcome row lands: the logout exit.
    CHECK(res->status == 200);
    CHECK(res->get_header_value("HX-Redirect") == "/home");
    CHECK(res->get_header_value("Set-Cookie").find("Max-Age=0") != std::string::npos);
    CHECK(results == std::vector<std::string>{"attempted", "ok"});
    CHECK(logs.text().find("MFA cleared for 'admin' but the outcome audit row failed to persist") !=
          std::string::npos);
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
    CHECK_FALSE(sessions.find(auth::AuthManager::sha256_hex(mine)).value().has_value());
}

// The disable handler falls back to the request-resolving AuditFn when the session-bound writer
// is unwired, which would silently write an empty principal (the actor's session is gone by the
// time the row is written). A handler test cannot see server.cpp, so pin the production binding.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
TEST_CASE("settings: server.cpp binds the session-bound audit writer to AuthRoutes (#6079)",
          "[mfa][settings]") {
    // Comments are stripped first: a commented-out binding must not satisfy the pin (#6079).
    const std::string& src = yuzu::test::source_scan::comment_free_source("server.cpp");
    CHECK(src.find(
              "settings_routes_->set_audit_as_session_fn(auth_routes_->audit_as_session_fn())") !=
          std::string::npos);
}

TEST_CASE("POST /api/settings/mfa/disable is blocked for self under enforcement (PR3 invariant)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Enroll admin first.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    // Turn on enforcement (cfg is held by reference by SettingsRoutes).
    h.cfg.mfa_enforcement = "required";

    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->status == 200); // fragment-with-error convention, not a hard status
    CHECK(res->body.find("required by policy") != std::string::npos);
    // Audit captures the policy block.
    CHECK(h.has_audit("mfa.disabled", "error", "admin"));
    CHECK(h.audit_detail("mfa.disabled").find("blocked: mfa_enforcement=required") !=
          std::string::npos);
    // Crucially, MFA is STILL enrolled — the disable did not take effect.
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

TEST_CASE("POST /api/settings/mfa/disable under admin-only blocks admins but the gate is "
          "role-scoped",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt);
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());

    h.cfg.mfa_enforcement = "admin-only";
    // Admin (session_role defaults to admin) is protected.
    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->body.find("required by policy") != std::string::npos);
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

TEST_CASE("Non-admin same-origin POST: 403 from admin_fn after origin_safe passes",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    h.session_role = auth::Role::user; // bob
    h.session_user = "bob";
    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 403);
    // settings_routes.cpp:4145 calls origin_safe FIRST, then admin_fn_.
    // For a same-origin POST origin_safe returns true (host==origin host)
    // and admin_fn_ then rejects the non-admin session with 403. The
    // assertion is that no csrf.denied audit row is emitted — origin_safe
    // passed, so only the admin denial fires.
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("Cross-origin POST is rejected 403 with csrf.denied audit on every MFA route",
          "[pg][mfa][routes][settings]") {
    // qe Gate 3 S-2 follow-up: previously only /disable carried a
    // cross-origin reject case. Each of the 4 mutating MFA routes now
    // has its own assertion so a regression that drops origin_safe from
    // any single one trips a test.
    for (const auto& path : {std::string{"/api/settings/mfa/init"},
                             std::string{"/api/settings/mfa/verify"},
                             std::string{"/api/settings/mfa/recovery-codes"},
                             std::string{"/api/settings/mfa/disable"}}) {
        MfaSettingsHarness h;
        auto res = h.sink.dispatch("POST", path, {}, "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"}, {"Origin", "http://evil.com"}});
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("cross-origin POST refused") != std::string::npos);
        CHECK(h.has_audit("csrf.denied", "error", path));
    }
}

TEST_CASE("Default-port normalisation: Origin :443 matches Host without port",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example:443"}});
    REQUIRE(res);
    // Same host after stripping :443 — passes origin_safe, hits admin_fn
    // (admin session) → ok.
    CHECK(res->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("Userinfo (`@`) in Origin is rejected per RFC 6454",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Origin", "http://evil@yuzu.example"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.has_audit("csrf.denied"));
}

TEST_CASE("Non-browser caller with neither Origin nor Referer passes through",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                           {{"Host", "yuzu.example"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("csrf.denied audit detail captures Origin / Referer / Host for SIEM",
          "[pg][mfa][routes][settings]") {
    // Audit-detail sanitisation (control + high-bit byte stripping +
    // 128 B per-field cap) is implemented as an inline lambda inside
    // SettingsRoutes::register_routes and verified by code review +
    // governance gates 2/4. A route-level test that drives bytes
    // >= 0x80 through `req.set_header` and `req.get_header_value`
    // depends on httplib's header-value handling, which is opaque
    // across versions. We assert the *correctness-relevant* property
    // here — that the detail captures the host mismatch so a SIEM
    // operator can correlate the 403 — and leave the sanitisation
    // property to be locked down by a dedicated unit test on the
    // helper once it's promoted out of the lambda scope.
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                        {{"Host", "yuzu.example"}, {"Origin", "http://evil.com"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    auto detail = h.audit_detail("csrf.denied");
    REQUIRE_FALSE(detail.empty());
    // Tightened (security Gate 2 INFO): assert the field-tagged format
    // so a regression that drops `Origin=` / `Host=` keys or flips field
    // order trips this assertion. Loose substring `find("evil.com")`
    // would have passed for any garbled detail string that still
    // contained the literal.
    CHECK(detail.find("Origin=http://evil.com") != std::string::npos);
    CHECK(detail.find("Host=yuzu.example") != std::string::npos);
}

TEST_CASE("Referer fallback also evaluated when Origin is absent",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto good =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Referer", "http://yuzu.example/settings"}});
    REQUIRE(good);
    CHECK(good->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));

    MfaSettingsHarness h2;
    auto bad = h2.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                            {{"Host", "yuzu.example"}, {"Referer", "http://evil.com/x"}});
    REQUIRE(bad);
    CHECK(bad->status == 403);
    CHECK(h2.has_audit("csrf.denied"));
}

// ---------------------------------------------------------------------------
// #6079: the Settings enrol-confirm stamps a proof BOUND to the enrolment, and the approver gate
// judges survivors of a factor replacement by that binding.
// ---------------------------------------------------------------------------

namespace {

/// The stored-proof read the production approver closure takes (cookie token, principal-checked).
yuzu::test::ApproverRouteFixture::DurableFn durable_from_cookie(MfaSettingsHarness& h) {
    return [&h](const httplib::Request& req, const auth::Session& s) {
        return h.auth_mgr.read_durable_mfa_proof(AuthRoutes::extract_session_cookie(req),
                                                 s.username);
    };
}

/// Enrols `admin` straight through AuthDB (no route, no session touched).
void enrol_admin_directly(MfaSettingsHarness& h) {
    const auto code = begin_admin_enrolment(h);
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code, std::nullopt).has_value());
}

/// Clears `admin`'s factor and enrols a new one, WITHOUT ending any session (the survivors of a
/// factor replacement: R1 of the design, and what a partial hygiene delete leaves behind).
void replace_factor_keeping_sessions(MfaSettingsHarness& h) {
    REQUIRE(h.auth_db->mfa_disable_report("admin", std::nullopt).has_value());
    enrol_admin_directly(h);
}

std::string audit_details(const yuzu::test::ApproverRouteFixture& fx) {
    std::string all;
    for (const auto& a : fx.audits)
        all += a.action + "|" + a.result + "|" + a.detail + "\n";
    return all;
}

} // namespace

TEST_CASE("POST /api/settings/mfa/verify stamps the enrolment's generation and its pre-UPDATE "
          "instant (#6079 T5)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};

    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    // Waits between the enrolment and the stamp, so the stamp's own now() is strictly later than
    // the enrolment: only a CARRIED instant can still precede mfa_enrolled_at.
    h.routes.set_stamp_fault_hook_for_test(
        [] { std::this_thread::sleep_for(std::chrono::milliseconds(5)); });
    yuzu::test::ScopeExit clear_hook{[&h] { h.routes.set_stamp_fault_hook_for_test(nullptr); }};

    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=stamped");

    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    REQUIRE(st->enrolled);
    auto found = sessions.find(auth::AuthManager::sha256_hex(token));
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    const auto& row = (*found)->row;
    CHECK(row.mfa_factor_gen == st->factor_gen);
    CHECK(row.mfa_factor_gen > 0);
    CHECK(row.mfa_verified_ms > 0);
    // captured before the enrolling UPDATE
    CHECK(row.mfa_verified_ms <= enrolled_ms(h.auth_db, "admin"));
    const auto durable = h.auth_mgr.read_durable_mfa_proof(token, "admin");
    CHECK(judge_local_mfa_binding(durable, st->factor_gen, st->binding_enforced).kind ==
          LocalMfaBinding::kBound);
}

TEST_CASE(
    "POST /api/settings/mfa/verify: a factor replaced before the stamp lands clears the stamp "
    "but keeps the enrolment and the codes (#6079 T5)",
    "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};

    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    // The hook must NOT delete the session (the stamp would match zero rows and the recheck
    // would never run); it replaces the factor, moving the generation by two.
    h.routes.set_stamp_fault_hook_for_test([&h] { replace_factor_keeping_sessions(h); });
    yuzu::test::ScopeExit clear_hook{[&h] { h.routes.set_stamp_fault_hook_for_test(nullptr); }};

    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.audit_detail("mfa.enroll.verified") == "step_up_proof=not_stamped;factor_changed");

    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    const auto durable = h.auth_mgr.read_durable_mfa_proof(token, "admin");
    CHECK(durable.mfa_verified_ms == 0);
    CHECK(durable.mfa_factor_gen == 0);
    CHECK(judge_local_mfa_binding(durable, st->factor_gen, st->binding_enforced).kind !=
          LocalMfaBinding::kBound);
}

TEST_CASE("enrol via Settings then approve at once passes the real approver gate (#6079 T18)",
          "[pg][mfa][routes][settings][stepup][binding][approval_routes]") {
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};
    yuzu::test::ApproverRouteFixture fx(h.auth_mgr, *h.auth_db.get(), durable_from_cookie(h));

    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    REQUIRE_FALSE(token.empty());
    const auto code = begin_admin_enrolment(h);
    auto res = post_verify_with_cookie(h, code, token);
    REQUIRE(res);
    REQUIRE(h.audit_detail("mfa.enroll.verified") == "step_up_proof=stamped");

    const auto approve_ticket = fx.submit();
    auto approved = fx.decide("approve", approve_ticket, token);
    REQUIRE(approved);
    CHECK(approved->status == 200);
    CHECK(fx.status_of(approve_ticket) == "approved");
    const auto reject_ticket = fx.submit();
    auto rejected = fx.decide("reject", reject_ticket, token);
    REQUIRE(rejected);
    CHECK(rejected->status == 200);
    CHECK(fx.status_of(reject_ticket) == "rejected");
}

TEST_CASE("a session that survived a factor replacement cannot decide an approval until it "
          "re-proves under the new factor (#6079 T4: R1, R2, R8)",
          "[pg][mfa][routes][settings][binding][approval_routes]") {
    MfaSettingsHarness h;
    SessionStore sessions{h.auth_db.pool()};
    REQUIRE(sessions.is_open());
    h.auth_mgr.set_session_store(&sessions);
    struct Detach {
        auth::AuthManager& m;
        ~Detach() { m.set_session_store(nullptr); }
    } detach{h.auth_mgr};
    yuzu::test::ApproverRouteFixture fx(h.auth_mgr, *h.auth_db.get(), durable_from_cookie(h));

    enrol_admin_directly(h);
    // Minted AFTER the enrolment with an MFA proof: bound to F1 (the live identity).
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    {
        // Control: the F1 session decides while F1 is current.
        const auto ticket = fx.submit();
        auto ok = fx.decide("approve", ticket, token);
        REQUIRE(ok);
        REQUIRE(ok->status == 200);
    }

    SECTION("R1: the factor is cleared and re-enrolled, no session deleted") {
        replace_factor_keeping_sessions(h);
    }
    SECTION("R2 + R8: the hygiene delete fails after the clear, then a second disable finds "
            "nothing to clear") {
        yuzu::test::SqlFault fault(h.auth_db.pool(),
                                   "ALTER TABLE session_store.sessions RENAME TO sessions_gone",
                                   "ALTER TABLE session_store.sessions_gone RENAME TO sessions");
        fault.arm();
        auto partial = h.sink.dispatch("POST", "/api/settings/mfa/disable", {},
                                       "application/x-www-form-urlencoded",
                                       {{"Host", "yuzu.example"},
                                        {"Origin", "http://yuzu.example"},
                                        {"Cookie", "yuzu_session=" + token}});
        fault.repair();
        REQUIRE(partial);
        REQUIRE(h.has_audit("mfa.disabled", "partial", "admin"));
        REQUIRE_FALSE(h.auth_db->mfa_status("admin")->enrolled);
        // R8: the second disable has no verified factor left to clear and keeps the sessions.
        auto second = post_same_origin(h.sink, "/api/settings/mfa/disable");
        REQUIRE(second);
        REQUIRE(h.auth_db->mfa_status("admin").has_value());
        enrol_admin_directly(h);
    }

    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    REQUIRE(st->enrolled);

    // The survivor is signed in and holds a proof, but for the factor that no longer exists.
    const auto approve_ticket = fx.submit();
    auto approve = fx.decide("approve", approve_ticket, token);
    REQUIRE(approve);
    CHECK(approve->status == 401);
    CHECK(fx.status_of(approve_ticket) == "pending");
    const auto reject_ticket = fx.submit();
    auto reject = fx.decide("reject", reject_ticket, token);
    REQUIRE(reject);
    CHECK(reject->status == 401);
    CHECK(fx.status_of(reject_ticket) == "pending");
    CHECK(audit_details(fx).find("proof_factor_mismatch") != std::string::npos);

    // Re-proving under F2 (the step-up route's stamp, carrying F2's generation and an instant
    // the database has already reached) restores both decisions.
    REQUIRE(
        h.auth_mgr.mark_session_mfa_verified(token, LocalMfaProof{st->factor_gen, st->db_now_ms}));
    auto approve2 = fx.decide("approve", approve_ticket, token);
    REQUIRE(approve2);
    CHECK(approve2->status == 200);
    CHECK(fx.status_of(approve_ticket) == "approved");
    auto reject2 = fx.decide("reject", reject_ticket, token);
    REQUIRE(reject2);
    CHECK(reject2->status == 200);
    CHECK(fx.status_of(reject_ticket) == "rejected");
}

// ---------------------------------------------------------------------------
// #6079 C5c: the recovery-codes and disable routes call the factor-credential gate and compare the
// generation it admitted under the users row lock. These cases wire the gate the way server.cpp
// does (run_in_handler_step_up over the real stores, with the out-parameter) and rotate the factor
// in the window between the gate and the AuthDB call.
// ---------------------------------------------------------------------------

namespace {

/// The factor-credential gate as server.cpp wires it, over the harness's own stores. The session
/// is the cookie's (so the cached proof anchor is real) unless `cookie_sessions` is false.
void wire_real_gate(MfaSettingsHarness& h, int window_secs = 300, bool cookie_sessions = true) {
    h.use_cookie_sessions = cookie_sessions;
    h.routes.set_factor_credential_gate_fn(
        [&h, window_secs](const httplib::Request& req, httplib::Response& res,
                          const auth::Session& s,
                          const std::string& label) -> std::optional<StepUpAdmission> {
            const StepUpAuditFn audit = [&h](const httplib::Request&, const std::string& a,
                                             const std::string& r, const std::string& tt,
                                             const std::string& ti, const std::string& d) {
                h.audit_calls.push_back({a, r, tt, ti, d});
                return true;
            };
            const DurableProofFn durable = [&h](const httplib::Request& rq,
                                                const auth::Session& ss) {
                return h.auth_mgr.read_durable_mfa_proof(AuthRoutes::extract_session_cookie(rq),
                                                         ss.username);
            };
            StepUpAdmission admitted{};
            if (!detail::run_in_handler_step_up(req, res, s, label, h.auth_db.get(), window_secs,
                                                audit, "optional", &h.metrics, &durable, &admitted))
                return std::nullopt;
            return admitted;
        });
}

std::unique_ptr<httplib::Response> post_with_cookie(MfaSettingsHarness& h, const std::string& path,
                                                    const std::string& token) {
    std::unordered_map<std::string, std::string> headers{{"Host", "yuzu.example"},
                                                         {"Origin", "http://yuzu.example"}};
    if (!token.empty())
        headers["Cookie"] = "yuzu_session=" + token;
    return h.sink.dispatch("POST", path, {}, "application/x-www-form-urlencoded", headers);
}

/// The ids of `user`'s stored recovery codes in order: unchanged iff nothing was regenerated.
std::string code_ids(MfaSettingsHarness& h, const std::string& user = "admin") {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT COALESCE(string_agg(id::text, ',' ORDER BY id), '') FROM "
        "auth.mfa_recovery_codes WHERE username = $1",
        std::vector<std::string>{user});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    return PQgetvalue(r.get(), 0, 0);
}

std::size_t count_ids(const std::string& ids) {
    return ids.empty() ? 0 : static_cast<std::size_t>(std::count(ids.begin(), ids.end(), ',')) + 1;
}

std::int64_t current_gen(MfaSettingsHarness& h) {
    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    return st->factor_gen;
}

std::int64_t factor_changed_count(MfaSettingsHarness& h, const char* route) {
    return h.metrics.counter("yuzu_auth_mfa_factor_changed_total", {{"route", route}}).value();
}

} // namespace

TEST_CASE("the factor-credential routes refuse an admission that is not local and mutate "
          "nothing (#6079)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    // The real gate never hands one back; a gate defect that did must still not reach the
    // mutation, because the generation it carries is only meaningful for a local account.
    MfaSettingsHarness h;
    StoreScope scope(h);
    enrol_admin_directly(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    const auto gen = current_gen(h);
    h.routes.set_factor_credential_gate_fn(
        [gen](const httplib::Request&, httplib::Response&, const auth::Session&,
              const std::string&) -> std::optional<StepUpAdmission> {
            return StepUpAdmission{false, gen};
        });
    const auto ids_before = code_ids(h);
    for (const char* path : {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable"}) {
        CAPTURE(path);
        auto res = post_with_cookie(h, path, token);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("Store these recovery codes now") == std::string::npos);
        CHECK(res->get_header_value("HX-Redirect").empty());
        CHECK(res->get_header_value("Set-Cookie").empty());
    }
    CHECK(code_ids(h) == ids_before);
    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    CHECK(st->enrolled);
    CHECK(st->factor_gen == gen);
    CHECK(h.auth_mgr.validate_session(token).has_value());
    CHECK_FALSE(h.has_audit("mfa.recovery_codes.generated", "ok"));
    CHECK_FALSE(h.has_audit("mfa.disabled", "ok"));
}

TEST_CASE("recovery-codes route: a factor rotated after the gate admitted the request answers 409 "
          "and regenerates nothing (#6079 T12a)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    // The counter series exists, at zero, before any refusal (increase() sees the first event).
    CHECK(h.metrics.serialize().find(
              "yuzu_auth_mfa_factor_changed_total{route=\"recovery_codes\"} 0") !=
          std::string::npos);
    enrol_admin_directly(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    wire_real_gate(h);
    const auto admitted_gen = current_gen(h);

    std::string f2_ids;
    std::string seen_route;
    h.routes.set_factor_credential_barrier_for_test([&](std::string_view route) {
        seen_route = std::string(route);
        replace_factor_keeping_sessions(h); // F2, no session ended
        f2_ids = code_ids(h);
    });
    auto res = post_with_cookie(h, "/api/settings/mfa/recovery-codes", token);
    REQUIRE(res);
    CHECK(seen_route == "recovery_codes");
    CHECK(res->status == 409);
    CHECK(res->body.find("Your MFA factor changed while this request was in flight. Reload the "
                         "page; if you are asked to sign in again, do so.") != std::string::npos);
    CHECK(res->body.find("Store these recovery codes now") == std::string::npos);
    CHECK(res->get_header_value("HX-Redirect").empty());
    CHECK(res->get_header_value("Set-Cookie").empty());
    // F2's ten code rows are the original rows: nothing was deleted or inserted.
    REQUIRE(count_ids(f2_ids) == 10);
    CHECK(code_ids(h) == f2_ids);
    CHECK(h.has_audit("mfa.recovery_codes.generated", "denied", "admin"));
    CHECK(h.audit_detail("mfa.recovery_codes.generated") ==
          "reason=factor_changed expected_gen=" + std::to_string(admitted_gen));
    CHECK_FALSE(h.has_audit("mfa.recovery_codes.generated", "ok"));
    CHECK(factor_changed_count(h, "recovery_codes") == 1);
    CHECK(factor_changed_count(h, "disable") == 0);
    // The session is neither ended nor signed out.
    CHECK(h.auth_mgr.validate_session(token).has_value());
}

TEST_CASE("disable route: a factor rotated after the gate admitted the request answers 409, "
          "clears nothing and ends no session (#6079 T12b)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    enrol_admin_directly(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    const auto other = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    REQUIRE_FALSE(other.empty());
    wire_real_gate(h);
    const auto admitted_gen = current_gen(h);

    std::string f2_ids;
    h.routes.set_factor_credential_barrier_for_test([&](std::string_view route) {
        CHECK(route == "disable");
        replace_factor_keeping_sessions(h);
        f2_ids = code_ids(h);
    });
    auto res = post_with_cookie(h, "/api/settings/mfa/disable", token);
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->body.find("MFA factor changed while this request was in flight") !=
          std::string::npos);
    CHECK(res->get_header_value("HX-Redirect").empty()); // no sign-out
    CHECK(res->get_header_value("Set-Cookie").empty());
    // F2 is intact: still enrolled with its ten codes, and no session of the account ended.
    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    CHECK(st->enrolled);
    CHECK(st->factor_gen == admitted_gen + 2);
    CHECK(code_ids(h) == f2_ids);
    CHECK(count_ids(f2_ids) == 10);
    CHECK(h.auth_mgr.validate_session(token).has_value());
    CHECK(h.auth_mgr.validate_session(other).has_value());
    CHECK(scope.sessions.find(auth::AuthManager::sha256_hex(token)).value().has_value());
    CHECK(scope.sessions.find(auth::AuthManager::sha256_hex(other)).value().has_value());
    CHECK(h.has_audit("mfa.disabled", "denied", "admin"));
    CHECK(h.audit_detail("mfa.disabled") ==
          "reason=factor_changed expected_gen=" + std::to_string(admitted_gen));
    CHECK_FALSE(h.has_audit("mfa.disabled", "ok"));
    CHECK(factor_changed_count(h, "disable") == 1);
}

TEST_CASE("disable route: cancelling an enrolment that completed after the gate admitted the "
          "request answers 409 and keeps the new factor (#6079 T12c)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    // A provisional secret only: un-enrolled, so the gate admits without a proof.
    REQUIRE(h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt).has_value());
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    wire_real_gate(h);
    const auto admitted_gen = current_gen(h);
    REQUIRE_FALSE(h.auth_db->mfa_status("admin")->enrolled);

    h.routes.set_factor_credential_barrier_for_test(
        [&](std::string_view) { enrol_admin_directly(h); }); // a concurrent enrolment completes
    auto res = post_with_cookie(h, "/api/settings/mfa/disable", token);
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->get_header_value("HX-Redirect").empty());
    const auto st = h.auth_db->mfa_status("admin");
    REQUIRE(st.has_value());
    CHECK(st->enrolled); // the cancel did not strip a factor that did not exist when admitted
    CHECK(st->factor_gen == admitted_gen + 1);
    CHECK(count_ids(code_ids(h)) == 10);
    CHECK(h.auth_mgr.validate_session(token).has_value());
    CHECK(h.audit_detail("mfa.disabled") ==
          "reason=factor_changed expected_gen=" + std::to_string(admitted_gen));
}

TEST_CASE("the factor-credential routes with no rotation in the window behave as before "
          "(#6079 T12 control)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    enrol_admin_directly(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    wire_real_gate(h);
    int fired = 0;
    h.routes.set_factor_credential_barrier_for_test([&](std::string_view) { ++fired; });

    auto codes = post_with_cookie(h, "/api/settings/mfa/recovery-codes", token);
    REQUIRE(codes);
    CHECK(codes->status == 200);
    CHECK(codes->body.find("Store these recovery codes now") != std::string::npos);
    CHECK(h.has_audit("mfa.recovery_codes.generated", "ok", "admin"));

    auto disable = post_with_cookie(h, "/api/settings/mfa/disable", token);
    REQUIRE(disable);
    CHECK(disable->status == 200);
    CHECK(disable->get_header_value("HX-Redirect") == "/home"); // every session ended
    CHECK_FALSE(h.auth_mgr.validate_session(token).has_value());
    CHECK(fired == 2);
    CHECK(factor_changed_count(h, "recovery_codes") == 0);
    CHECK(factor_changed_count(h, "disable") == 0);
}

TEST_CASE("the factor-credential routes answer 503 and mutate nothing when no gate is wired "
          "(#6079)",
          "[pg][mfa][routes][settings][stepup]") {
    MfaSettingsHarness h;
    enrol_admin_directly(h);
    h.routes.set_factor_credential_gate_fn({});
    bool fired = false;
    h.routes.set_factor_credential_barrier_for_test([&](std::string_view) { fired = true; });
    const auto ids = code_ids(h);
    for (const char* path : {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable"}) {
        CAPTURE(path);
        auto res = post_same_origin(h.sink, path);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("Store these recovery codes now") == std::string::npos);
    }
    CHECK_FALSE(fired);
    CHECK(code_ids(h) == ids);
    CHECK(h.auth_db->mfa_status("admin")->enrolled);
}

TEST_CASE("recovery-codes route: a survivor of a factor replacement is refused before any code is "
          "regenerated, and only a re-proved session reaches an approval (#6079 T9, T4)",
          "[pg][mfa][routes][settings][stepup][binding][approval_routes]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    yuzu::test::ApproverRouteFixture fx(h.auth_mgr, *h.auth_db.get(), durable_from_cookie(h));
    enrol_admin_directly(h);
    const auto survivor =
        h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    REQUIRE_FALSE(survivor.empty());
    wire_real_gate(h);
    replace_factor_keeping_sessions(h); // F2; the survivor's session is NOT deleted
    const auto ids_before = code_ids(h);
    REQUIRE(count_ids(ids_before) == 10);

    // Step 1 of the chain: refused by the route's own gate, under the default window...
    auto refused = post_with_cookie(h, "/api/settings/mfa/recovery-codes", survivor);
    REQUIRE(refused);
    CHECK(refused->status == 401);
    CHECK(refused->body.find("Store these recovery codes now") == std::string::npos);
    bool mismatch = false;
    for (const auto& a : h.audit_calls)
        mismatch |= a.detail.find("reason=proof_factor_mismatch") != std::string::npos;
    CHECK(mismatch);
    CHECK(code_ids(h) == ids_before); // no code regenerated, none revealed
    // ...and the survivor decides nothing.
    for (const char* verb : {"approve", "reject"}) {
        const auto ticket = fx.submit();
        auto res = fx.decide(verb, ticket, survivor);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(fx.status_of(ticket) == "pending");
    }

    // The control chain from a session bound to F2: regenerate through the route, consume one of
    // the revealed codes through the step-up verification, and decide an approval.
    const auto legit = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    auto regen = post_with_cookie(h, "/api/settings/mfa/recovery-codes", legit);
    REQUIRE(regen);
    REQUIRE(regen->status == 200);
    CHECK(code_ids(h) != ids_before);
    static const std::regex code_re("[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}");
    std::smatch m;
    REQUIRE(std::regex_search(regen->body, m, code_re));
    auto verified = h.auth_db->mfa_consume_recovery_code("admin", m.str());
    REQUIRE(verified.has_value());
    REQUIRE(verified->ok);
    REQUIRE(h.auth_mgr.mark_session_mfa_verified(
        legit,
        LocalMfaProof{.factor_gen = verified->factor_gen, .verified_ms = verified->verified_ms}));
    const auto ticket = fx.submit();
    auto approved = fx.decide("approve", ticket, legit);
    REQUIRE(approved);
    CHECK(approved->status == 200);
    CHECK(fx.status_of(ticket) == "approved");
}

TEST_CASE("the factor-credential routes ignore the window-0 hatch: a survivor and a password-only "
          "session are refused, an un-enrolled account still cancels (#6079 T11, T15)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    enrol_admin_directly(h);
    const auto survivor =
        h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    const auto password_only =
        h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    wire_real_gate(h, /*window_secs=*/0);
    replace_factor_keeping_sessions(h);
    const auto ids = code_ids(h);

    for (const auto& token : {survivor, password_only}) {
        for (const char* path : {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable"}) {
            CAPTURE(path);
            auto res = post_with_cookie(h, path, token);
            REQUIRE(res);
            CHECK(res->status == 401);
            CHECK(res->get_header_value("HX-Redirect").empty());
        }
    }
    CHECK(code_ids(h) == ids);                       // nothing regenerated
    CHECK(h.auth_db->mfa_status("admin")->enrolled); // nothing cleared
    CHECK(h.auth_mgr.validate_session(survivor).has_value());

    // A bound fresh session of F2 succeeds on both rows (a window of 0 does not lock it out).
    const auto legit = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    auto codes = post_with_cookie(h, "/api/settings/mfa/recovery-codes", legit);
    REQUIRE(codes);
    CHECK(codes->status == 200);
    auto disable = post_with_cookie(h, "/api/settings/mfa/disable", legit);
    REQUIRE(disable);
    CHECK(disable->status == 200);
    CHECK_FALSE(h.auth_db->mfa_status("admin")->enrolled);

    // An un-enrolled account still cancels a provisional enrolment at window 0.
    REQUIRE(h.auth_db->mfa_init_enrollment("admin", "Yuzu", std::nullopt).has_value());
    const auto cancelling =
        h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, false);
    auto cancel = post_with_cookie(h, "/api/settings/mfa/disable", cancelling);
    REQUIRE(cancel);
    CHECK(cancel->status == 200);
    CHECK(h.audit_detail("mfa.disabled") == "no verified factor to clear");
}

TEST_CASE("recovery-codes route: a cached-fresh proof that is durably old is refused (#6079 T13)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    StoreScope scope(h);
    enrol_admin_directly(h);
    const auto token = h.auth_mgr.create_local_session_for_test("admin", auth::Role::admin, true);
    wire_real_gate(h);
    // Warm the cache, then move the stored instant 400 s back WITH the bind sequence so the guard
    // keeps the binding: the cached anchor still reads fresh.
    REQUIRE(h.auth_mgr.validate_session(token).has_value());
    {
        auto lease = h.auth_db.pool().acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE session_store.sessions SET mfa_verified_ms = "
            "(extract(epoch from now())*1000)::bigint - 400000, mfa_bind_seq = mfa_bind_seq + 1 "
            "WHERE token_hash = $1",
            std::vector<std::string>{auth::AuthManager::sha256_hex(token)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    const auto ids = code_ids(h);
    auto res = post_with_cookie(h, "/api/settings/mfa/recovery-codes", token);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(code_ids(h) == ids);
    std::string detail_text;
    for (const auto& a : h.audit_calls)
        if (a.detail.find("age_secs=") != std::string::npos)
            detail_text = a.detail;
    const auto pos = detail_text.find("age_secs=");
    REQUIRE(pos != std::string::npos);
    CHECK(std::stoi(detail_text.substr(pos + 9)) >= 400);
}

TEST_CASE("the factor-credential routes refuse every non-local session 403 and mutate nothing "
          "(#6079 T14)",
          "[pg][mfa][routes][settings][stepup][binding]") {
    MfaSettingsHarness h;
    enrol_admin_directly(h);
    wire_real_gate(h, /*window_secs=*/300, /*cookie_sessions=*/false);
    const auto ids = code_ids(h);
    for (const char* source : {"api_token", "oidc"}) {
        h.session_auth_source = source;
        for (const char* path : {"/api/settings/mfa/recovery-codes", "/api/settings/mfa/disable"}) {
            CAPTURE(source, path);
            h.audit_calls.clear();
            auto res = post_same_origin(h.sink, path);
            REQUIRE(res);
            CHECK(res->status == 403);
            bool reason = false;
            for (const auto& a : h.audit_calls)
                reason |= a.detail.find("reason=factor_credential_requires_local_session") !=
                          std::string::npos;
            CHECK(reason);
        }
    }
    CHECK(code_ids(h) == ids);
    CHECK(h.auth_db->mfa_status("admin")->enrolled);
}

TEST_CASE(
    "settings: server.cpp wires the factor-credential gate to run_in_handler_step_up with the "
    "admission out-parameter (#6079)",
    "[mfa][settings]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto wired = src.find("settings_routes_->set_factor_credential_gate_fn(");
    REQUIRE(wired != std::string::npos);
    const auto call = src.find("detail::run_in_handler_step_up(", wired);
    REQUIRE(call != std::string::npos);
    CHECK(call - wired < 2500);
    // The out-parameter is a real admission, not the nullptr the 35 kRequired rows pass.
    const auto args = src.substr(call, 800);
    CHECK(args.find("&admitted") != std::string::npos);
}
