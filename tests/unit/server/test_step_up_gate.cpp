/**
 * test_step_up_gate.cpp — the MFA step-up decide/render split and the request chokepoint
 * (server/core/src/step_up_gate.{hpp,cpp}).
 *
 * Two layers:
 *
 *   [stepup][gate]        PURE. The MFA store is injected through `MfaStatusFn`, so every branch
 *                         of `decide_step_up`, the renderer and `apply_step_up_chokepoint` runs
 *                         without Postgres.
 *   [pg][mfa][stepup]     The equivalence matrix: for every (identity source x enforcement mode x
 *                         proof state) cell, `decide_step_up` and the historical
 *                         `require_mfa_step_up` entry point agree with each other AND with a
 *                         hand-written table of the status each cell has always produced, against
 *                         a real AuthDB. test_mfa_step_up.cpp (unchanged) pins the wire shape.
 */

#include "../../../server/core/src/step_up_gate.hpp"
#include "../../../server/core/src/step_up_policy.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "test_auth_db_pg_helper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <expected>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;
using namespace std::chrono_literals;

namespace {

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

constexpr std::string_view kTokensPattern = "/api/v1/tokens";
constexpr std::string_view kTokensLabel = "POST /api/v1/tokens";

std::chrono::system_clock::time_point ago(std::chrono::seconds s) {
    return std::chrono::system_clock::now() - s;
}

// Populates the session through derive_session_deadlines, exactly as the sibling
// test_mfa_step_up.cpp does: the gate ages the proof against the monotonic anchor.
auth::Session make_session(const std::string& user, const std::string& source, Role role,
                           std::chrono::system_clock::time_point verified_at = {}) {
    auth::Session s;
    s.username = user;
    s.role = role;
    s.auth_source = source;
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t verified_ms =
        verified_at.time_since_epoch().count() == 0
            ? 0
            : std::chrono::duration_cast<std::chrono::milliseconds>(verified_at.time_since_epoch())
                  .count();
    AuthManager::derive_session_deadlines(s, now, now + 3600'000, now, verified_ms,
                                          /*elevated_until*/ 0, /*issued*/ 0, now);
    return s;
}

MfaStatusFn status_enrolled() {
    return [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        AuthDB::MfaStatus st;
        st.enrolled = true;
        return st;
    };
}
MfaStatusFn status_not_enrolled() {
    return [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return AuthDB::MfaStatus{};
    };
}
MfaStatusFn status_error(AuthDBError e) {
    return [e](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return std::unexpected(e);
    };
}

// A wired chokepoint over an injected MFA store and a fixed session.
struct Rig {
    std::optional<auth::Session> session;
    MfaStatusFn mfa_status = status_enrolled();
    bool wire_store = true;
    bool wire_resolver = true;
    bool resolver_throws = false;
    int window_secs = 300;
    std::string enforcement = "optional";
    std::vector<AuditRow> audits;
    yuzu::MetricsRegistry metrics;

    StepUpSessionFn resolver = [this](const httplib::Request&) -> std::optional<auth::Session> {
        if (resolver_throws)
            throw std::runtime_error("resolver failure");
        return session;
    };
    StepUpAuditFn audit = [this](const httplib::Request&, const std::string& a,
                                 const std::string& r, const std::string& tt, const std::string& ti,
                                 const std::string& d) -> bool {
        audits.push_back({a, r, tt, ti, d});
        return true;
    };

    StepUpChokepointDeps deps() {
        return StepUpChokepointDeps{.resolve_session = wire_resolver ? &resolver : nullptr,
                                    .auth_db = nullptr,
                                    .mfa_status = wire_store ? &mfa_status : nullptr,
                                    .audit_fn = &audit,
                                    .metrics = &metrics,
                                    .window_secs = window_secs,
                                    .mfa_enforcement = enforcement};
    }

    double gate_count(std::string_view outcome, std::string_view source, std::string_view surface) {
        return metrics
            .counter("yuzu_auth_mfa_step_up_gate_total", {{"outcome", std::string(outcome)},
                                                          {"source", std::string(source)},
                                                          {"surface", std::string(surface)}})
            .value();
    }
};

httplib::Request make_request(std::string method, std::string_view pattern, std::string path) {
    httplib::Request req;
    req.method = std::move(method);
    req.matched_route = std::string(pattern);
    req.path = std::move(path);
    return req;
}

nlohmann::json body_of(const httplib::Response& res) {
    return nlohmann::json::parse(res.body);
}

} // namespace

// ── decide_step_up: the pure decision ────────────────────────────────────────

TEST_CASE("decide_step_up: window <= 0, bearer principals and un-enrolled users pass",
          "[stepup][gate]") {
    const auto stale = make_session("alice", "local", Role::admin, ago(1h));
    CHECK(decide_step_up(stale, status_enrolled(), 0, "optional").passed());
    CHECK(decide_step_up(stale, status_enrolled(), -1, "optional").passed());
    CHECK(decide_step_up(make_session("t", "api_token", Role::admin), status_enrolled(), 300,
                         "optional")
              .passed());
    CHECK(decide_step_up(make_session("t", "mcp_token", Role::admin), status_enrolled(), 300,
                         "optional")
              .passed());
    CHECK(decide_step_up(make_session("bob", "local", Role::user), status_not_enrolled(), 300,
                         "optional")
              .passed());
}

TEST_CASE("decide_step_up: window <= 0 does not consult the store at all", "[stepup][gate]") {
    bool called = false;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        called = true;
        return AuthDB::MfaStatus{};
    };
    CHECK(
        decide_step_up(make_session("alice", "local", Role::admin), probe, 0, "optional").passed());
    CHECK_FALSE(called);
}

TEST_CASE("decide_step_up: local enrolled session is judged on proof age", "[stepup][gate]") {
    SECTION("fresh proof passes") {
        CHECK(decide_step_up(make_session("alice", "local", Role::admin, ago(10s)),
                             status_enrolled(), 300, "optional")
                  .passed());
    }
    SECTION("stale proof is a challenge carrying the age and window") {
        const auto v = decide_step_up(make_session("alice", "local", Role::admin, ago(1h)),
                                      status_enrolled(), 300, "optional");
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK_FALSE(v.is_oidc);
        CHECK(v.age_secs >= 3500);
        CHECK(v.window_secs == 300);
        CHECK(v.user == "alice");
    }
    SECTION("no proof at all is a challenge with age -1") {
        const auto v = decide_step_up(make_session("alice", "local", Role::admin),
                                      status_enrolled(), 300, "optional");
        CHECK(v.decision == StepUpDecision::kChallenge);
        CHECK(v.age_secs == -1);
    }
}

TEST_CASE("decide_step_up: a proof older than the 24h ceiling never counts", "[stepup][gate]") {
    // window_secs is far above the ceiling; a 25 h old proof must still be refused.
    const auto v = decide_step_up(make_session("alice", "local", Role::admin, ago(25h)),
                                  status_enrolled(), 7 * 24 * 3600, "optional");
    CHECK(v.decision == StepUpDecision::kChallenge);
}

TEST_CASE("decide_step_up: store failures fail closed and are told apart", "[stepup][gate]") {
    const auto s = make_session("alice", "local", Role::admin, ago(10s));
    for (const auto e : {AuthDBError::SecretUnavailable, AuthDBError::QueryFailed,
                         AuthDBError::WriteFailed, AuthDBError::StoreBusy}) {
        CHECK(decide_step_up(s, status_error(e), 300, "optional").decision ==
              StepUpDecision::kStoreUnavailable);
    }
    CHECK(decide_step_up(s, status_error(AuthDBError::UserNotFound), 300, "optional").decision ==
          StepUpDecision::kStatusFailed);
    // An engine session has no users row: it fails closed rather than counting as proven.
    CHECK(decide_step_up(make_session("engine:x", "engine_token", Role::user, ago(10s)),
                         status_error(AuthDBError::UserNotFound), 300, "optional")
              .decision == StepUpDecision::kStatusFailed);
}

TEST_CASE("decide_step_up: SAML is an honest denial in every mode", "[stepup][gate]") {
    for (const char* mode : {"optional", "admin-only", "required"}) {
        const auto v = decide_step_up(make_session("saml-user", "saml", Role::admin, ago(1s)),
                                      status_enrolled(), 300, mode);
        CHECK(v.decision == StepUpDecision::kSamlDenied);
    }
}

TEST_CASE("decide_step_up: OIDC never takes the local lookup", "[stepup][gate]") {
    bool called = false;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        called = true;
        return AuthDB::MfaStatus{.enrolled = true};
    };
    CHECK(decide_step_up(make_session("oidc:iss#sub", "oidc", Role::admin, ago(10s)), probe, 300,
                         "optional")
              .passed());
    CHECK_FALSE(called);
}

TEST_CASE("decide_step_up: OIDC amr-less session depends on enforcement and role",
          "[stepup][gate]") {
    const auto admin = make_session("oidc:iss#a", "oidc", Role::admin);
    const auto user = make_session("oidc:iss#u", "oidc", Role::user);
    CHECK(decide_step_up(admin, status_enrolled(), 300, "optional").passed());
    CHECK(decide_step_up(user, status_enrolled(), 300, "optional").passed());
    CHECK(decide_step_up(admin, status_enrolled(), 300, "admin-only").decision ==
          StepUpDecision::kChallenge);
    CHECK(decide_step_up(user, status_enrolled(), 300, "admin-only").passed());
    CHECK(decide_step_up(admin, status_enrolled(), 300, "required").decision ==
          StepUpDecision::kChallenge);
    CHECK(decide_step_up(user, status_enrolled(), 300, "required").decision ==
          StepUpDecision::kChallenge);
    const auto challenge = decide_step_up(admin, status_enrolled(), 300, "required");
    CHECK(challenge.is_oidc);
}

TEST_CASE("decide_step_up: OIDC session with a seeded proof takes the freshness check in any mode",
          "[stepup][gate]") {
    for (const char* mode : {"optional", "admin-only", "required"}) {
        CHECK(decide_step_up(make_session("oidc:iss#a", "oidc", Role::admin, ago(10s)),
                             status_enrolled(), 300, mode)
                  .passed());
        CHECK(decide_step_up(make_session("oidc:iss#a", "oidc", Role::admin, ago(1h)),
                             status_enrolled(), 300, mode)
                  .decision == StepUpDecision::kChallenge);
    }
}

// ── render_step_up_refusal ───────────────────────────────────────────────────

TEST_CASE("render_step_up_refusal: stale local session is the 401 challenge envelope",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 401);
    const auto j = body_of(res);
    CHECK(j["error"]["code"] == 401);
    CHECK(j["error"]["message"] == "MFA step-up required");
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(j["meta"]["mfa_step_up_required"] == true);
    CHECK(j["meta"]["challenge_url"] == "/login/mfa/stepup");
}

TEST_CASE("render_step_up_refusal: OIDC challenge points at SSO", "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    v.is_oidc = true;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(body_of(res)["meta"]["challenge_url"] == "/auth/oidc/start");
}

TEST_CASE("render_step_up_refusal: SAML is 403 with no challenge", "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kSamlDenied;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 403);
    const auto j = body_of(res);
    CHECK(j["meta"]["mfa_step_up_required"] == false);
    CHECK_FALSE(j["meta"].contains("challenge_url"));
}

TEST_CASE("render_step_up_refusal: 503 for store outage, unwired store and unsupported class",
          "[stepup][gate]") {
    for (const auto d : {StepUpDecision::kStoreUnavailable, StepUpDecision::kUnwired,
                         StepUpDecision::kUnsupportedClass, StepUpDecision::kEvaluationFailed}) {
        StepUpVerdict v;
        v.decision = d;
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.status == 503);
        const auto j = body_of(res);
        CHECK(j["error"]["message"] == "authentication store is temporarily unavailable");
        CHECK_FALSE(j["meta"].contains("challenge_url"));
    }
}

TEST_CASE("render_step_up_refusal: status-read failure is a 401 that still names the challenge",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kStatusFailed;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
    CHECK(res.status == 401);
    CHECK(body_of(res)["meta"]["challenge_url"] == "/login/mfa/stepup");
}

TEST_CASE("render_step_up_refusal: the htmx toast is dashboard-only and needs HX-Request",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;

    SECTION("dashboard + HX-Request carries the toast with the envelope's own message") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "MFA step-up required");
        CHECK(t["showToast"]["level"] == "error");
        CHECK(res.status == 401);
    }
    SECTION(
        "the toast never carries the remediation (it can point at a sign-in that cannot help)") {
        StepUpVerdict saml;
        saml.decision = StepUpDecision::kSamlDenied;
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, saml, StepUpSurface::kDashboard);
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"].get<std::string>().find("/auth/saml/start") ==
              std::string::npos);
    }
    SECTION("dashboard without HX-Request has no toast") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("REST never toasts, even with HX-Request") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
}

TEST_CASE("render_step_up_refusal: MCP surface is a JSON-RPC permission error, not an HTTP 401",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    httplib::Request req;
    httplib::Response res;
    render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
    CHECK(res.status == 200);
    const auto j = body_of(res);
    CHECK(j["jsonrpc"] == "2.0");
    CHECK(j["id"].is_null());
    CHECK(j["error"]["code"] == -32003);
    CHECK(j["error"]["data"]["mfa_step_up_required"] == true);
    CHECK(j["error"]["data"]["challenge_url"] == "/login/mfa/stepup");
    // The bare error object (for a caller that wraps it with the real request id) is the same.
    const auto bare = nlohmann::json::parse(step_up_refusal_json_rpc_error(v));
    CHECK(bare["code"] == -32003);
}

TEST_CASE("step-up labels: source and surface sets are closed", "[stepup][gate]") {
    for (const char* s : {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token"})
        CHECK(step_up_source_label(s) == s);
    CHECK(step_up_source_label("attacker-chosen") == "other");
    CHECK(step_up_source_label("") == "other");
    CHECK(step_up_surface_for_path("/api/v1/tokens") == StepUpSurface::kRest);
    CHECK(step_up_surface_for_path("/api/settings/api-tokens") == StepUpSurface::kDashboard);
    CHECK(step_up_surface_for_path("/fragments/guardian/guard/x/update") ==
          StepUpSurface::kDashboard);
    CHECK(step_up_surface_for_path("/mcp/v1/") == StepUpSurface::kMcp);
}

TEST_CASE("seed_step_up_gate_metrics: every closed label combination exists at zero",
          "[stepup][gate]") {
    yuzu::MetricsRegistry metrics;
    seed_step_up_gate_metrics(metrics);
    const auto text = metrics.serialize();
    CHECK(text.find("# TYPE yuzu_auth_mfa_step_up_gate_total counter") != std::string::npos);
    CHECK(text.find("outcome=\"handler_skipped\"") != std::string::npos);
    CHECK(text.find("source=\"engine_token\"") != std::string::npos);
    CHECK(text.find("surface=\"mcp\"") != std::string::npos);
}

// ── apply_step_up_chokepoint ─────────────────────────────────────────────────

TEST_CASE("chokepoint: a route with no table row is not applicable and reads nothing",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    bool resolved = false;
    rig.resolver = [&](const httplib::Request&) {
        resolved = true;
        return rig.session;
    };
    auto req = make_request("POST", "/api/v1/not-in-the-table", "/api/v1/not-in-the-table");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    CHECK_FALSE(resolved);
    CHECK(res.status == -1);
    CHECK(rig.audits.empty());
}

TEST_CASE("chokepoint: no matched route, or a non-mutating verb, is not applicable",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response res;
    auto no_route = make_request("POST", "", "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(no_route, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    auto get = make_request("GET", kTokensPattern, "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(get, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
}

TEST_CASE("chokepoint: the verb is part of the key", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response res;
    // PUT /api/v1/tokens is not a registered row (only POST is).
    auto req = make_request("PUT", kTokensPattern, "/api/v1/tokens");
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
}

TEST_CASE("chokepoint: kOwnGate rows are skipped even for a stale session", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    for (const char* pattern : {R"(/api/v1/elevate)", R"(/api/v1/users/elevation-eligibility)",
                                R"(/api/v1/users/([^/]+)/elevation-eligibility)"}) {
        auto req = make_request("POST", pattern, "/api/v1/elevate");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kNotApplicable);
        CHECK(res.status == -1);
    }
    CHECK(rig.audits.empty());
}

TEST_CASE("chokepoint: stale proof on a kRequired row is refused before the handler",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 401);
    CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);

    SECTION("the audit row keeps today's action label and is tagged pre_authz") {
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_type == "Endpoint");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(rig.audits[0].detail.find("user=alice") != std::string::npos);
        CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    }
    SECTION("the gate metric counts a refusal by source and surface") {
        CHECK(rig.gate_count("refused", "local", "rest") == 1);
        CHECK(rig.gate_count("pass", "local", "rest") == 0);
    }
    SECTION("a refusal arms no pass stash") {
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
}

TEST_CASE("chokepoint: a dashboard route on an htmx request gets the toast", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    auto req = make_request("POST", R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/update)",
                            "/fragments/guardian/guard/g1/update");
    req.set_header("HX-Request", "true");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 401);
    CHECK(res.has_header("HX-Trigger"));
    CHECK(rig.gate_count("refused", "local", "dashboard") == 1);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].target_id == "POST /fragments/guardian/guard/{id}/update");
}

TEST_CASE("chokepoint: a REST route never carries the toast", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    req.set_header("HX-Request", "true");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK_FALSE(res.has_header("HX-Trigger"));
}

TEST_CASE("chokepoint: SAML session is a 403 on a kRequired row", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("saml-user", "saml", Role::admin, ago(1s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 403);
    CHECK(rig.gate_count("refused", "saml", "rest") == 1);
}

TEST_CASE("chokepoint: a bearer principal passes", "[stepup][gate]") {
    for (const char* source : {"api_token", "mcp_token"}) {
        Rig rig;
        rig.session = make_session("t", source, Role::admin);
        auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        CHECK(res.status == -1);
        CHECK(rig.audits.empty());
        CHECK(rig.gate_count("pass", source, "rest") == 1);
        detail::clear_step_up_pass();
    }
}

TEST_CASE("chokepoint: an engine session fails closed", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("engine:x", "engine_token", Role::user);
    rig.mfa_status = status_error(AuthDBError::UserNotFound);
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 401);
}

TEST_CASE("chokepoint: a store outage is a 503, counted unavailable", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    rig.mfa_status = status_error(AuthDBError::SecretUnavailable);
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
    CHECK(rig.metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
              .value() == 1);
}

TEST_CASE("chokepoint: an unwired auth store fails CLOSED with a 503, never a pass",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s)); // fresh: would pass
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
    CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
    // Distinct from the 401 challenge and the 403 SAML refusal.
    CHECK(res.status != 401);
    CHECK(res.status != 403);
}

TEST_CASE("chokepoint: an unwired store is a 503 for a bearer principal too", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("t", "api_token", Role::admin);
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
}

TEST_CASE("chokepoint: window <= 0 passes a kRequired row (operator hatch)", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(1h));
    rig.window_secs = 0;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kPassed);
    detail::clear_step_up_pass();
}

TEST_CASE("chokepoint: no session, an unwired resolver and a throwing resolver all refuse",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("no session is a 401 unauthorized") {
        Rig rig;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
        CHECK(body_of(res)["error"]["message"] == "unauthorized");
        CHECK(rig.gate_count("refused", "none", "rest") == 1);
    }
    SECTION("an unwired resolver fails closed") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.wire_resolver = false;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 401);
    }
    SECTION("a resolver that throws is a 503, never a pass") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.resolver_throws = true;
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        // No session resolved, so there is no source to report.
        CHECK(rig.gate_count("unavailable", "other", "rest") == 1);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        // No session had resolved, so the row has no user; the reason token is still recorded.
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].detail == "user= reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("an MFA status read that throws is a 503 with an audit row, never a pass") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s)); // fresh: would pass
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        const auto j = body_of(res);
        CHECK(j["error"]["message"] == "authentication store is temporarily unavailable");
        CHECK_FALSE(j["meta"].contains("challenge_url"));
        CHECK(j["meta"]["mfa_step_up_required"] == true);
        CHECK_FALSE(res.has_header("HX-Trigger"));
        // The session resolved before the throw, so its own source labels the metric.
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
        CHECK(rig.gate_count("pass", "local", "rest") == 0);
        // The pass stash is not armed: a handler-side consume finds nothing.
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(rig.audits[0].detail == "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("the dashboard surface gets the toast and the real source label") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto dash = make_request("POST", kTokensPattern, "/api/settings/api-tokens");
        dash.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(dash, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "authentication store is temporarily unavailable");
        CHECK(t["showToast"]["level"] == "error");
        CHECK(rig.gate_count("unavailable", "local", "dashboard") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].detail == "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("the dashboard surface without HX-Request has no toast") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto dash = make_request("POST", kTokensPattern, "/api/settings/api-tokens");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(dash, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("the MCP surface gets the JSON-RPC shape, not the REST envelope") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        auto mcp_req = make_request("POST", kTokensPattern, "/mcp/v1/");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(mcp_req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        const auto j = body_of(res);
        CHECK(j["jsonrpc"] == "2.0");
        CHECK(j["error"]["data"]["mfa_step_up_required"] == true);
        CHECK(j["error"]["data"]["http_status"] == 503);
        CHECK(rig.gate_count("unavailable", "local", "mcp") == 1);
    }
    SECTION("a bearer-class session keeps its own source label on the metric") {
        // An OIDC session never takes the local enrolment lookup, so the lookup throwing is
        // reachable for the sources that do: `engine_token` is one.
        Rig rig;
        rig.session = make_session("engine-1", "engine_token", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "engine_token", "rest") == 1);
        CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
    }
    SECTION("an audit writer that throws inside the fallback cannot escape or soften the 503") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.mfa_status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            throw std::runtime_error("status read failure");
        };
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit failure");
        };
        httplib::Response res;
        CHECK_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
}

TEST_CASE("chokepoint: OIDC proof states and enforcement modes", "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("amr-less OIDC admin passes under optional, is refused under admin-only") {
        Rig rig;
        rig.session = make_session("oidc:iss#a", "oidc", Role::admin);
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kPassed);
        detail::clear_step_up_pass();

        rig.enforcement = "admin-only";
        httplib::Response res2;
        CHECK(detail::apply_step_up_chokepoint(req, res2, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(res2.status == 401);
        CHECK(body_of(res2)["meta"]["challenge_url"] == "/auth/oidc/start");
    }
    SECTION("fresh amr proof passes in every mode") {
        for (const char* mode : {"optional", "admin-only", "required"}) {
            Rig rig;
            rig.session = make_session("oidc:iss#a", "oidc", Role::admin, ago(5s));
            rig.enforcement = mode;
            httplib::Response res;
            CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                  StepUpChokepointResult::kPassed);
            detail::clear_step_up_pass();
        }
    }
}

// ── the pass stash ───────────────────────────────────────────────────────────

TEST_CASE("pass stash: consumed once, for this request and this label only", "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    SECTION("a different action label does not consume it") {
        CHECK_FALSE(detail::consume_step_up_pass(req, "DELETE /api/v1/tokens/{id}"));
        CHECK(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("a different request object does not consume it") {
        auto other = make_request("POST", kTokensPattern, "/api/v1/tokens");
        CHECK_FALSE(detail::consume_step_up_pass(other, std::string(kTokensLabel)));
        CHECK(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("it is single-use: the second call re-evaluates") {
        CHECK(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("a cleared stash (pre-routing / post-routing) is gone") {
        detail::clear_step_up_pass();
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    detail::clear_step_up_pass();
}

TEST_CASE("pass stash: an unconsumed pass on a 2xx response is counted handler_skipped",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
            StepUpChokepointResult::kPassed);

    SECTION("2xx and never consumed: counted, then cleared") {
        httplib::Response out;
        out.status = 200;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 1);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("a consumed pass is not counted") {
        REQUIRE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        httplib::Response out;
        out.status = 200;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a non-2xx response is not counted, but the stash is still cleared") {
        httplib::Response out;
        out.status = 403;
        detail::finish_step_up_pass(req, out, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
}

// ── in-handler fail-closed helper ────────────────────────────────────────────

TEST_CASE("refuse_step_up_store_unwired: 503 + audit + metric", "[stepup][gate]") {
    Rig rig;
    const auto session = make_session("alice", "local", Role::admin, ago(10s));
    httplib::Request req;
    httplib::Response res;
    refuse_step_up_store_unwired(req, res, session, rig.audit, "POST /api/v1/elevate",
                                 &rig.metrics);
    CHECK(res.status == 503);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].target_id == "POST /api/v1/elevate");
    CHECK(rig.audits[0].detail == "user=alice reason=auth_store_unwired");
    CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
}

// ── equivalence matrix against a real AuthDB ─────────────────────────────────

namespace {

struct EquivFixture {
    yuzu::test::AuthDbPg db;
    std::vector<AuditRow> audits;
    StepUpAuditFn audit_fn;

    EquivFixture() {
        auto salt_a = AuthManager::random_bytes(16);
        auto hash_a = AuthManager::pbkdf2_sha256("pw", salt_a, 1000);
        REQUIRE(db->upsert_user("alice", hash_a, AuthManager::bytes_to_hex(salt_a), Role::admin)
                    .has_value());
        auto salt_b = AuthManager::random_bytes(16);
        auto hash_b = AuthManager::pbkdf2_sha256("pw", salt_b, 1000);
        REQUIRE(db->upsert_user("bob", hash_b, AuthManager::bytes_to_hex(salt_b), Role::user)
                    .has_value());
        auto init = db->mfa_init_enrollment("alice", "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment("alice", code, std::nullopt).has_value());

        audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                          const std::string& tt, const std::string& ti,
                          const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return true;
        };
    }
};

struct Cell {
    const char* name;
    std::string user;
    std::string source;
    Role role;
    std::chrono::system_clock::time_point verified_at;
    std::string mode;
    int window;
    int expected_status; // 200 = pass
};

} // namespace

TEST_CASE_METHOD(EquivFixture,
                 "step-up equivalence matrix: decide_step_up, require_mfa_step_up and the "
                 "historical status agree for every cell",
                 "[pg][mfa][stepup]") {
    const auto fresh = ago(10s);
    const auto stale = ago(1h);
    const auto none = std::chrono::system_clock::time_point{};

    std::vector<Cell> cells;
    for (const char* mode : {"optional", "admin-only", "required"}) {
        const std::string m = mode;
        // local, MFA-enrolled alice
        cells.push_back(
            {"local enrolled fresh", "alice", "local", Role::admin, fresh, m, 300, 200});
        cells.push_back(
            {"local enrolled stale", "alice", "local", Role::admin, stale, m, 300, 401});
        cells.push_back(
            {"local enrolled no proof", "alice", "local", Role::admin, none, m, 300, 401});
        // local, un-enrolled bob passes in every mode (enrolment is forced at login, not here)
        cells.push_back(
            {"local un-enrolled stale", "bob", "local", Role::user, stale, m, 300, 200});
        cells.push_back(
            {"local un-enrolled no proof", "bob", "local", Role::user, none, m, 300, 200});
        // a user with no row fails closed
        cells.push_back({"local unknown user", "ghost", "local", Role::user, fresh, m, 300, 401});
        // OIDC: proof states
        cells.push_back(
            {"oidc fresh amr proof", "oidc:i#a", "oidc", Role::admin, fresh, m, 300, 200});
        cells.push_back(
            {"oidc stale amr proof", "oidc:i#a", "oidc", Role::admin, stale, m, 300, 401});
        // OIDC with no amr proof: depends on the mode and the role
        const bool admin_protected = (m != "optional");
        const bool user_protected = (m == "required");
        cells.push_back({"oidc admin no amr", "oidc:i#a", "oidc", Role::admin, none, m, 300,
                         admin_protected ? 401 : 200});
        cells.push_back({"oidc user no amr", "oidc:i#u", "oidc", Role::user, none, m, 300,
                         user_protected ? 401 : 200});
        // SAML is a 403 in every mode
        cells.push_back({"saml", "saml-user", "saml", Role::admin, fresh, m, 300, 403});
        // bearer principals pass; an engine session fails closed
        cells.push_back({"api_token", "tok", "api_token", Role::admin, none, m, 300, 200});
        cells.push_back({"mcp_token", "tok", "mcp_token", Role::admin, none, m, 300, 200});
        cells.push_back(
            {"engine_token", "engine:x", "engine_token", Role::user, none, m, 300, 401});
        // the window hatch passes every identity, including the ones that would refuse
        for (const int w : {0, -1}) {
            cells.push_back({"hatch local stale", "alice", "local", Role::admin, stale, m, w, 200});
            cells.push_back({"hatch saml", "saml-user", "saml", Role::admin, fresh, m, w, 200});
            cells.push_back(
                {"hatch engine", "engine:x", "engine_token", Role::user, none, m, w, 200});
        }
    }

    for (const auto& c : cells) {
        DYNAMIC_SECTION(c.name << " / user=" << c.user << " mode=" << c.mode
                               << " window=" << c.window) {
            const auto session = make_session(c.user, c.source, c.role, c.verified_at);

            const auto verdict = decide_step_up(session, *db, c.window, c.mode);

            httplib::Request req;
            httplib::Response res;
            res.status = 200;
            audits.clear();
            const bool passed = require_mfa_step_up(req, res, session, *db, c.window, audit_fn,
                                                    "POST /api/v1/whatever", c.mode);

            CHECK(passed == verdict.passed());
            CHECK(passed == (c.expected_status == 200));
            if (!passed) {
                CHECK(res.status == c.expected_status);
                // The renderer, called directly, writes the same status the entry point wrote.
                httplib::Response direct;
                render_step_up_refusal(req, direct, verdict, StepUpSurface::kRest);
                CHECK(direct.status == res.status);
                auto a = body_of(direct);
                auto b = body_of(res);
                a["error"].erase("correlation_id");
                b["error"].erase("correlation_id");
                CHECK(a == b);
                // One audit row per refusal, none on a pass.
                CHECK(audits.size() == 1);
            } else {
                CHECK(res.status == 200);
                CHECK(res.body.empty());
                CHECK(audits.empty());
            }
        }
    }
}

TEST_CASE_METHOD(EquivFixture,
                 "step-up chokepoint over a real AuthDB: stale refused, fresh passes, un-enrolled "
                 "passes",
                 "[pg][mfa][stepup]") {
    yuzu::MetricsRegistry metrics;
    std::optional<auth::Session> session;
    const StepUpSessionFn resolver = [&](const httplib::Request&) {
        return session;
    };
    auto make_deps = [&] {
        return StepUpChokepointDeps{.resolve_session = &resolver,
                                    .auth_db = db.get(),
                                    .mfa_status = nullptr,
                                    .audit_fn = &audit_fn,
                                    .metrics = &metrics,
                                    .window_secs = 300,
                                    .mfa_enforcement = "optional"};
    };
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    session = make_session("alice", "local", Role::admin, ago(1h));
    httplib::Response stale_res;
    CHECK(detail::apply_step_up_chokepoint(req, stale_res, make_deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(stale_res.status == 401);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].detail.ends_with(" stage=pre_authz"));

    audits.clear();
    session = make_session("alice", "local", Role::admin, ago(5s));
    httplib::Response fresh_res;
    CHECK(detail::apply_step_up_chokepoint(req, fresh_res, make_deps()) ==
          StepUpChokepointResult::kPassed);
    CHECK(fresh_res.status == -1);
    CHECK(audits.empty());
    detail::clear_step_up_pass();

    session = make_session("bob", "local", Role::user, ago(1h));
    httplib::Response bob_res;
    CHECK(detail::apply_step_up_chokepoint(req, bob_res, make_deps()) ==
          StepUpChokepointResult::kPassed);
    detail::clear_step_up_pass();
}
