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
 *                         hand-written table of the status each cell produces, against a real
 *                         AuthDB (the engine_token cell is the one deliberate change from the
 *                         pre-chokepoint gate: it was a 401, it is now a 403 engine denial).
 *                         test_mfa_step_up.cpp (unchanged) pins the wire shape.
 */

#include "../../../server/core/src/step_up_gate.hpp"
#include "../../../server/core/src/step_up_policy.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../test_log_capture.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <expected>
#include <functional>
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
    // Empty means the seam is not wired, as in production.
    std::function<void(StepUpFaultPoint)> fault_hook;

    // The pass stash is a thread_local shared by every test on this thread. A Rig clears it on the
    // way in and on the way out, so a test that fails (or throws) between arming and consuming
    // cannot leak a stash into the next test, and a test never starts on another's leftovers.
    // A test that needs a stash to SURVIVE a Rig (arming one "as a previous request would have
    // left it") must keep that Rig alive for the duration, not scope it in a block.
    Rig() { detail::clear_step_up_pass(); }
    ~Rig() { detail::clear_step_up_pass(); }
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

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
                                    .mfa_enforcement = enforcement,
                                    .fault_hook = fault_hook ? &fault_hook : nullptr};
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
    // Not a store outage: a missing row and a name the store rejects before any read both fail
    // closed as a 401.
    for (const auto e : {AuthDBError::UserNotFound, AuthDBError::InvalidUsername}) {
        CHECK_FALSE(is_store_unavailable(e));
        CHECK(decide_step_up(s, status_error(e), 300, "optional").decision ==
              StepUpDecision::kStatusFailed);
    }
}

TEST_CASE("decide_step_up: an engine principal is denied before any store read",
          "[stepup][gate]") {
    // Engines are operator-less non-interactive bearers: denied on every gated route whatever
    // grant they hold, in every mode and at every window (the operator hatch included), and
    // without touching the store.
    int store_reads = 0;
    const MfaStatusFn probe =
        [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        ++store_reads;
        return std::unexpected(AuthDBError::InvalidUsername);
    };
    for (const char* mode : {"optional", "admin-only", "required"}) {
        // The auth_source discriminator and the persisted principal_kind discriminator each
        // suffice on their own (the S1 two-predicate check).
        auto by_source = make_session("engine:x", "engine_token", Role::user);
        auto by_kind = make_session("engine:y", "other", Role::user);
        by_kind.principal_kind = "engine";
        for (const auto& session : {by_source, by_kind}) {
            for (const int window : {300, 0, -1}) {
                const auto v = decide_step_up(session, probe, window, mode);
                CHECK(v.decision == StepUpDecision::kEngineDenied);
                CHECK_FALSE(v.passed());
                CHECK_FALSE(v.is_oidc);
                CHECK(v.user == session.username);
            }
        }
    }
    CHECK(store_reads == 0);
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

TEST_CASE("render_step_up_refusal: an engine denial is 403 with no challenge on every surface",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kEngineDenied;
    v.user = "engine:x";

    SECTION("REST: A4 envelope, 403, correlation id in header and body, no challenge") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.status == 403);
        const auto j = body_of(res);
        CHECK(j["error"]["code"] == 403);
        CHECK(j["error"]["message"] == "engine principals cannot perform this operation");
        CHECK(j["meta"]["api_version"] == "v1");
        CHECK(j["meta"]["mfa_step_up_required"] == false);
        CHECK_FALSE(j["meta"].contains("challenge_url"));
        CHECK_FALSE(res.has_header("HX-Trigger"));
        REQUIRE(res.has_header("X-Correlation-Id"));
        CHECK(j["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
    }
    SECTION("dashboard + HX-Request: the same 403 and the standard toast with the message") {
        httplib::Request req;
        req.set_header("HX-Request", "true");
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK(res.status == 403);
        REQUIRE(res.has_header("HX-Trigger"));
        const auto t = nlohmann::json::parse(res.get_header_value("HX-Trigger"));
        CHECK(t["showToast"]["message"] == "engine principals cannot perform this operation");
        CHECK(t["showToast"]["level"] == "error");
    }
    SECTION("dashboard without HX-Request: 403, no toast") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kDashboard);
        CHECK(res.status == 403);
        CHECK_FALSE(res.has_header("HX-Trigger"));
    }
    SECTION("MCP: a JSON-RPC permission error whose data carries http_status 403") {
        httplib::Request req;
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
        CHECK(res.status == 200);
        const auto j = body_of(res);
        CHECK(j["error"]["code"] == -32003);
        CHECK(j["error"]["data"]["http_status"] == 403);
        CHECK(j["error"]["data"]["mfa_step_up_required"] == false);
        CHECK_FALSE(j["error"]["data"].contains("challenge_url"));
    }
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

// The two MFA settings routes that mint or remove the factor the gate itself checks: a hijacked
// admin cookie must not be able to mint a recovery code (which satisfies a step-up challenge) or
// strip MFA (after which an un-enrolled caller passes every gate) without a fresh proof.
TEST_CASE("chokepoint: the MFA recovery-codes and disable routes are gated",
          "[stepup][gate]") {
    struct MfaRoute {
        const char* pattern;
        const char* label;
    };
    for (const auto& route : {MfaRoute{"/api/settings/mfa/recovery-codes",
                                       "POST /api/settings/mfa/recovery-codes"},
                              MfaRoute{"/api/settings/mfa/disable",
                                       "POST /api/settings/mfa/disable"}}) {
        CAPTURE(route.pattern);
        const auto* row = step_up_policy_for("POST", route.pattern);
        REQUIRE(row != nullptr);
        CHECK(row->cls == StepUpClass::kRequired);
        CHECK(row->action_label == route.label);
        CHECK(step_up_surface_for_path(route.pattern) == StepUpSurface::kDashboard);

        SECTION("a stale proof is refused with the toast on an htmx request") {
            Rig rig;
            rig.session = make_session("alice", "local", Role::admin, ago(1h));
            auto req = make_request("POST", route.pattern, route.pattern);
            req.set_header("HX-Request", "true");
            httplib::Response res;
            CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                  StepUpChokepointResult::kRefused);
            CHECK(res.status == 401);
            CHECK(res.has_header("HX-Trigger"));
            CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
            CHECK(rig.gate_count("refused", "local", "dashboard") == 1);
            REQUIRE(rig.audits.size() == 1);
            CHECK(rig.audits[0].target_id == route.label);
            CHECK(rig.audits[0].detail.ends_with(" stage=pre_authz"));
        }
        SECTION("a fresh proof passes and arms the stash for the in-handler call") {
            Rig rig;
            rig.session = make_session("alice", "local", Role::admin, ago(5s));
            auto req = make_request("POST", route.pattern, route.pattern);
            httplib::Response res;
            CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                  StepUpChokepointResult::kPassed);
            CHECK(res.status == -1);
            CHECK(rig.gate_count("pass", "local", "dashboard") == 1);
            CHECK(detail::consume_step_up_pass(req, route.label));
        }
        SECTION("an un-enrolled caller passes whatever the proof age") {
            Rig rig;
            rig.session = make_session("bob", "local", Role::admin, ago(1h));
            rig.mfa_status = status_not_enrolled();
            auto req = make_request("POST", route.pattern, route.pattern);
            httplib::Response res;
            CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                  StepUpChokepointResult::kPassed);
            CHECK(rig.audits.empty());
            detail::clear_step_up_pass();
        }
    }
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

TEST_CASE("chokepoint: an engine session is refused 403 before the handler and any store read",
          "[stepup][gate]") {
    struct Surface {
        const char* path;
        const char* surface;
    };
    for (const auto& sf :
         {Surface{"/api/v1/tokens", "rest"}, Surface{"/api/settings/api-tokens", "dashboard"},
          Surface{"/mcp/v1/", "mcp"}}) {
        CAPTURE(sf.surface);
        Rig rig;
        rig.session = make_session("engine:x", "engine_token", Role::admin);
        int store_reads = 0;
        rig.mfa_status = [&](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
            ++store_reads;
            return std::unexpected(AuthDBError::InvalidUsername);
        };
        auto req = make_request("POST", kTokensPattern, sf.path);
        req.set_header("HX-Request", "true");
        httplib::Response res;
        CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
              StepUpChokepointResult::kRefused);
        CHECK(store_reads == 0);
        if (std::string_view(sf.surface) == "mcp") {
            CHECK(res.status == 200);
            CHECK(body_of(res)["error"]["data"]["http_status"] == 403);
        } else {
            CHECK(res.status == 403);
            CHECK(body_of(res)["error"]["message"] ==
                  "engine principals cannot perform this operation");
        }
        // The handler is never reached: no pass stash is armed for it.
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].action == "mfa.step_up.required");
        CHECK(rig.audits[0].result == "error");
        CHECK(rig.audits[0].target_id == kTokensLabel);
        CHECK(rig.audits[0].detail ==
              "user=engine:x reason=engine_principal_denied stage=pre_authz");
        CHECK(rig.gate_count("refused", "engine_token", sf.surface) == 1);
        CHECK(rig.gate_count("pass", "engine_token", sf.surface) == 0);
        CHECK(rig.gate_count("unavailable", "engine_token", sf.surface) == 0);
    }
}

TEST_CASE("chokepoint: an engine is refused by principal_kind alone, and past the operator hatch",
          "[stepup][gate]") {
    Rig rig;
    rig.session = make_session("engine:y", "other", Role::admin);
    rig.session->principal_kind = "engine";
    rig.window_secs = 0; // gate disabled: an engine still never reaches the handler
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 403);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail ==
          "user=engine:y reason=engine_principal_denied stage=pre_authz");
    CHECK(rig.gate_count("refused", "other", "rest") == 1);
}

TEST_CASE("chokepoint: an engine on an unwired store gets the 503, not the 403", "[stepup][gate]") {
    // The null-store check precedes the decision, so the unwired fail-closed answer is the same
    // for every caller class.
    Rig rig;
    rig.session = make_session("engine:x", "engine_token", Role::admin);
    rig.wire_store = false;
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(rig.gate_count("unavailable", "engine_token", "rest") == 1);
    CHECK(rig.gate_count("refused", "engine_token", "rest") == 0);
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
}

TEST_CASE("chokepoint: a kOwnGate row is not the chokepoint's, so an engine is left to its handler",
          "[stepup][gate]") {
    // The elevation rows are kOwnGate: the chokepoint evaluates nothing. Their in-handler gate
    // (`require_mfa_step_up`) shares decide_step_up, so it answers an engine 403 there.
    Rig rig;
    rig.session = make_session("engine:x", "engine_token", Role::admin);
    auto req = make_request("POST", R"(/api/v1/elevate)", "/api/v1/elevate");
    httplib::Response res;
    CHECK(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
          StepUpChokepointResult::kNotApplicable);
    CHECK(res.status == -1);
    CHECK(rig.audits.empty());
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
        // Bearer-class sessions (engine included) never reach the store lookup, so the throw is
        // injected at the fault point that follows session resolution.
        Rig rig;
        rig.session = make_session("engine-1", "engine_token", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw std::runtime_error("evaluation failure");
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

TEST_CASE("chokepoint: an evaluation that throws after the session resolves keeps the real "
          "source label",
          "[stepup][gate]") {
    // `decide_step_up` itself reads no store for these sources, so the fault hook is the only way
    // to make their evaluation throw. Every session below has a fresh proof, or is exempt, and
    // so would not be refused for any reason other than the throw (SAML is refused 403).
    const auto source = GENERATE(as<std::string>{}, "oidc", "saml", "api_token", "mcp_token");
    CAPTURE(source);
    Rig rig;
    rig.session = make_session("carol", source, Role::admin, ago(10s));
    std::vector<StepUpFaultPoint> seen;
    rig.fault_hook = [&seen](StepUpFaultPoint p) {
        seen.push_back(p);
        if (p == StepUpFaultPoint::kBeforeDecide)
            throw std::runtime_error("evaluation failure");
    };
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    // Arm a pass stash first, as a previous request on this worker thread would have left it, so
    // the check below proves the fallback clears it rather than that it was never set. `passing`
    // stays alive to the end of the case: a Rig clears the stash when it is destroyed.
    Rig passing;
    passing.session = make_session("carol", "api_token", Role::admin);
    {
        httplib::Response ok;
        REQUIRE(detail::apply_step_up_chokepoint(req, ok, passing.deps()) ==
                StepUpChokepointResult::kPassed);
    }

    httplib::Response res;
    StepUpChokepointResult result{};
    REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
    CHECK(result == StepUpChokepointResult::kRefused);
    CHECK(res.status == 503);
    CHECK(body_of(res)["meta"]["mfa_step_up_required"] == true);
    // The throw is observed once before the decision and the fallback then renders once.
    CHECK(seen == std::vector<StepUpFaultPoint>{StepUpFaultPoint::kBeforeDecide,
                                                StepUpFaultPoint::kFallbackRender});
    // The session resolved, so its own bounded source label counts the refusal; "other" is for a
    // resolver that itself threw.
    CHECK(rig.gate_count("unavailable", source, "rest") == 1);
    CHECK(rig.gate_count("unavailable", "other", "rest") == 0);
    CHECK(rig.gate_count("pass", source, "rest") == 0);
    CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    REQUIRE(rig.audits.size() == 1);
    CHECK(rig.audits[0].action == "mfa.step_up.required");
    CHECK(rig.audits[0].result == "error");
    CHECK(rig.audits[0].target_id == kTokensLabel);
    CHECK(rig.audits[0].detail == "user=carol reason=chokepoint_exception stage=pre_authz");
}

TEST_CASE("chokepoint: a refusal renderer that throws still ends in a 503", "[stepup][gate]") {
    // The hook throws at both points, so the evaluation fails and then the fallback's render
    // fails too. The last-resort branch sets the status and writes no body, and here the hook
    // throws before the renderer writes anything, so only the status is asserted: the code
    // guarantees a 503, not a body.
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    rig.fault_hook = [](StepUpFaultPoint) { throw std::runtime_error("injected failure"); };

    // A stash left armed by an earlier request on this thread must not survive the fallback.
    Rig passing;
    passing.session = make_session("alice", "api_token", Role::admin);
    {
        httplib::Response ok;
        REQUIRE(detail::apply_step_up_chokepoint(req, ok, passing.deps()) ==
                StepUpChokepointResult::kPassed);
    }

    SECTION("REST") {
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].detail == "user=alice reason=chokepoint_exception stage=pre_authz");
    }
    SECTION("MCP: the status is 503 although the MCP renderer would have answered 200") {
        auto mcp_req = make_request("POST", kTokensPattern, "/mcp/v1/");
        httplib::Response res;
        REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(mcp_req, res, rig.deps()));
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "mcp") == 1);
        REQUIRE(rig.audits.size() == 1);
    }
    SECTION("the audit writer throwing as well changes nothing") {
        rig.audit = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
            throw std::runtime_error("audit failure");
        };
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
}

namespace {
std::size_t count_occurrences(const std::string& haystack, std::string_view needle) {
    std::size_t n = 0;
    for (auto pos = haystack.find(needle); pos != std::string::npos;
         pos = haystack.find(needle, pos + needle.size()))
        ++n;
    return n;
}
} // namespace

TEST_CASE("chokepoint: an exception's what() is logged and the answer is still a fail-closed 503",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");

    SECTION("a std::exception: its what() reaches the log") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw std::runtime_error("yuzu_test_distinctive_what_text");
        };
        yuzu::test::LogCapture capture;
        // The log line is sampled (the first of every 100 is written), and the sampling counter
        // is process-wide, so drive a full period: at least one line is guaranteed.
        for (int i = 0; i < 100; ++i) {
            httplib::Response res;
            REQUIRE_NOTHROW(detail::apply_step_up_chokepoint(req, res, rig.deps()));
            CHECK(res.status == 503);
        }
        capture.stop();
        const auto logs = capture.text();
        CHECK(logs.find("yuzu_test_distinctive_what_text") != std::string::npos);
        CHECK(logs.find(std::string(kTokensLabel)) != std::string::npos);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 100);
    }
    SECTION("a non-std exception takes the same fail-closed answer") {
        Rig rig;
        rig.session = make_session("alice", "local", Role::admin, ago(10s));
        rig.fault_hook = [](StepUpFaultPoint p) {
            if (p == StepUpFaultPoint::kBeforeDecide)
                throw 42; // NOLINT(hicpp-exception-baseclass): the point of the test
        };
        httplib::Response res;
        StepUpChokepointResult result{};
        REQUIRE_NOTHROW(result = detail::apply_step_up_chokepoint(req, res, rig.deps()));
        CHECK(result == StepUpChokepointResult::kRefused);
        CHECK(res.status == 503);
        CHECK(rig.gate_count("unavailable", "local", "rest") == 1);
        REQUIRE(rig.audits.size() == 1);
        CHECK(rig.audits[0].detail == "user=alice reason=chokepoint_exception stage=pre_authz");
    }
}

TEST_CASE("chokepoint: a refusal storm is logged once per hundred but counted every time",
          "[stepup][gate]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    // UserNotFound is the 401 "status read failed" refusal, which logs at error level.
    rig.mfa_status = status_error(AuthDBError::UserNotFound);

    constexpr int kRefusals = 250;
    yuzu::test::LogCapture capture;
    for (int i = 0; i < kRefusals; ++i) {
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, rig.deps()) ==
                StepUpChokepointResult::kRefused);
    }
    capture.stop();
    const auto lines = count_occurrences(capture.text(), "failing closed");
    // The sampling counter is process-wide: a window of 250 hits holds 2 or 3 multiples of 100.
    CHECK(lines >= 2);
    CHECK(lines <= 3);
    CHECK(rig.gate_count("refused", "local", "rest") == kRefusals);
    CHECK(rig.audits.size() == static_cast<std::size_t>(kRefusals));
}

TEST_CASE("render_step_up_refusal: X-Correlation-Id equals the body's correlation_id",
          "[stepup][gate]") {
    StepUpVerdict v;
    v.decision = StepUpDecision::kChallenge;
    v.user = "alice";
    httplib::Request req;

    SECTION("REST and dashboard envelopes") {
        for (const auto surface : {StepUpSurface::kRest, StepUpSurface::kDashboard}) {
            httplib::Response res;
            render_step_up_refusal(req, res, v, surface);
            const auto cid = res.get_header_value("X-Correlation-Id");
            CHECK_FALSE(cid.empty());
            CHECK(body_of(res)["error"]["correlation_id"] == cid);
        }
    }
    SECTION("the MCP error carries it in data") {
        httplib::Response res;
        render_step_up_refusal(req, res, v, StepUpSurface::kMcp);
        const auto cid = res.get_header_value("X-Correlation-Id");
        CHECK_FALSE(cid.empty());
        CHECK(body_of(res)["error"]["data"]["correlation_id"] == cid);
    }
    SECTION("a correlation id an upstream gate already set is reused, not replaced") {
        httplib::Response res;
        res.set_header("X-Correlation-Id", "req-upstream-1");
        render_step_up_refusal(req, res, v, StepUpSurface::kRest);
        CHECK(res.get_header_value("X-Correlation-Id") == "req-upstream-1");
        CHECK(body_of(res)["error"]["correlation_id"] == "req-upstream-1");
    }
    SECTION("the chokepoint's own refusals, including its no-session 401 and its fallback") {
        auto choke_req = make_request("POST", kTokensPattern, "/api/v1/tokens");
        {
            Rig rig; // no session
            httplib::Response res;
            REQUIRE(detail::apply_step_up_chokepoint(choke_req, res, rig.deps()) ==
                    StepUpChokepointResult::kRefused);
            CHECK(res.status == 401);
            CHECK(body_of(res)["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
            CHECK_FALSE(res.get_header_value("X-Correlation-Id").empty());
        }
        {
            Rig rig;
            rig.session = make_session("alice", "local", Role::admin, ago(10s));
            rig.fault_hook = [](StepUpFaultPoint p) {
                if (p == StepUpFaultPoint::kBeforeDecide)
                    throw std::runtime_error("evaluation failure");
            };
            httplib::Response res;
            REQUIRE(detail::apply_step_up_chokepoint(choke_req, res, rig.deps()) ==
                    StepUpChokepointResult::kRefused);
            CHECK(res.status == 503);
            CHECK(body_of(res)["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
        }
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

// The stash is a thread_local, and successive requests on one httplib worker thread can share a
// `httplib::Request` address, so the address is not a key. These cases run the sequences the
// three clear sites in server.cpp (pre-routing top, post-routing, and the consume/catch sites in
// step_up_gate.cpp) exist for, through the same `detail::` entry points those sites call.
// server.cpp's own calls are pinned by test_step_up_wiring.cpp.
TEST_CASE("pass stash lifecycle: a pass armed by request A is not consumable by request B at the "
          "same address",
          "[stepup][gate][lifecycle]") {
    Rig rig;
    rig.session = make_session("alice", "local", Role::admin, ago(10s));
    // ONE object stands for both requests: B reuses A's address, as the next request on a worker
    // thread can. Only its fields change between them.
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    httplib::Response res_a;
    REQUIRE(detail::apply_step_up_chokepoint(req, res_a, rig.deps()) ==
            StepUpChokepointResult::kPassed);
    const httplib::Request* const address_of_a = &req;

    // B: same address, same registered row (so the same action label).
    auto become_request_b = [&] {
        req.path = "/api/v1/tokens";
        req.matched_route = std::string(kTokensPattern);
        REQUIRE(&req == address_of_a);
    };

    SECTION("control: with NO clear between them the address and label alone admit B") {
        // This is why the clears exist: nothing in the stash distinguishes A from B.
        become_request_b();
        CHECK(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("the post-routing handler of A clears it (and reports it once if A skipped its gate)") {
        httplib::Response a_done;
        a_done.status = 200;
        detail::finish_step_up_pass(req, a_done, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 1);
        become_request_b();
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("post-routing clears on a non-2xx response too, without reporting it") {
        httplib::Response a_failed;
        a_failed.status = 500;
        detail::finish_step_up_pass(req, a_failed, &rig.metrics);
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
        become_request_b();
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("the pre-routing top of B clears a pass A left (A's post-routing never ran)") {
        // What the first statements of server.cpp's pre-routing handler do for a request that
        // follows one which bypassed post-routing.
        detail::clear_step_up_pass();
        become_request_b();
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
    SECTION("a refused request B does not inherit A's pass, and its post-routing clears it") {
        rig.session = make_session("alice", "local", Role::admin, ago(1h));
        httplib::Response res_b;
        become_request_b();
        REQUIRE(detail::apply_step_up_chokepoint(req, res_b, rig.deps()) ==
                StepUpChokepointResult::kRefused);
        // A refused B is Handled, so no handler runs; post-routing must still leave nothing armed.
        detail::finish_step_up_pass(req, res_b, &rig.metrics);
        CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
        CHECK(rig.gate_count("handler_skipped", "local", "rest") == 0);
    }
    SECTION("a different action label at the same address never consumes it, and keeps it") {
        CHECK_FALSE(detail::consume_step_up_pass(req, "DELETE /api/v1/tokens/{id}"));
        // The refused attempt did not burn A's pass: only a matching consume or a clear does.
        CHECK(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
    }
}

TEST_CASE("pass stash lifecycle: a Rig leaves no stash behind for the next test",
          "[stepup][gate][lifecycle]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    {
        Rig first;
        first.session = make_session("alice", "local", Role::admin, ago(10s));
        httplib::Response res;
        REQUIRE(detail::apply_step_up_chokepoint(req, res, first.deps()) ==
                StepUpChokepointResult::kPassed);
        // Deliberately neither consumed nor cleared: a failing REQUIRE would leave exactly this.
    }
    CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
}

TEST_CASE("pass stash lifecycle: a Rig starts with an empty stash", "[stepup][gate][lifecycle]") {
    auto req = make_request("POST", kTokensPattern, "/api/v1/tokens");
    // Arm the thread_local directly, as a stash leaked by a test that has no Rig would be.
    auto& stash = detail::tls_step_up_pass();
    stash.req = &req;
    stash.row = step_up_policy_for("POST", kTokensPattern);
    REQUIRE(stash.row != nullptr);
    Rig next;
    CHECK_FALSE(detail::consume_step_up_pass(req, std::string(kTokensLabel)));
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
        // API and MCP token principals pass; an engine principal is a 403 whatever its role
        cells.push_back({"api_token", "tok", "api_token", Role::admin, none, m, 300, 200});
        cells.push_back({"mcp_token", "tok", "mcp_token", Role::admin, none, m, 300, 200});
        cells.push_back(
            {"engine_token", "engine:x", "engine_token", Role::user, none, m, 300, 403});
        cells.push_back(
            {"engine_token admin", "engine:x", "engine_token", Role::admin, fresh, m, 300, 403});
        // the window hatch passes every identity that would refuse, except an engine, which the
        // hatch does not admit
        for (const int w : {0, -1}) {
            cells.push_back({"hatch local stale", "alice", "local", Role::admin, stale, m, w, 200});
            cells.push_back({"hatch saml", "saml-user", "saml", Role::admin, fresh, m, w, 200});
            cells.push_back(
                {"hatch engine", "engine:x", "engine_token", Role::user, none, m, w, 403});
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

            // Both entry points against the hand-written expectation, never against each other.
            CHECK(verdict.passed() == (c.expected_status == 200));
            CHECK(passed == (c.expected_status == 200));
            if (!passed) {
                CHECK(res.status == c.expected_status);
                // The renderer, called directly, writes the status the table expects.
                httplib::Response direct;
                render_step_up_refusal(req, direct, verdict, StepUpSurface::kRest);
                CHECK(direct.status == c.expected_status);
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
