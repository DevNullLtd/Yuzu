/**
 * test_step_up_null_store.cpp — the two production sites that answer 503 when a step-up gate finds
 * no auth store, for every caller class.
 *
 * The unwired-store branch is "fail closed": a gate that cannot evaluate must refuse, not wave the
 * request through. Reverting either branch to a silent pass fails nothing in test_step_up_gate.cpp,
 * which tests `refuse_step_up_store_unwired` itself but not the two callers that decide to use it:
 *
 *   server.cpp  `step_up_fn`           -> `detail::run_in_handler_step_up` (step_up_wiring.hpp)
 *   auth_routes.cpp `elevation_step_up` -> reached by POST /api/v1/users/{name}/elevation-eligibility
 *
 * Each case asserts the 503, the A4 envelope, the `reason=auth_store_unwired` audit token and the
 * `unavailable` gate counter. Production cannot reach a null store after boot (the server refuses
 * to start without one), so the stores are nulled in the test, as the per-request re-read in
 * server.cpp would see them.
 */

#include "../../../server/core/src/step_up_wiring.hpp"
#include "auth_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include "../test_helpers.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

auth::Session session_of(const std::string& user, const std::string& source, Role role) {
    auth::Session s;
    s.username = user;
    s.role = role;
    s.auth_source = source;
    return s;
}

double gate_count(yuzu::MetricsRegistry& m, std::string_view outcome, std::string_view source,
                  std::string_view surface = "rest") {
    return m
        .counter("yuzu_auth_mfa_step_up_gate_total", {{"outcome", std::string(outcome)},
                                                      {"source", std::string(source)},
                                                      {"surface", std::string(surface)}})
        .value();
}

} // namespace

// ── server.cpp's step_up_fn ───────────────────────────────────────────────────────────────────

TEST_CASE("in-handler step-up with no auth store is a 503 for every caller class",
          "[stepup][null_store]") {
    // The class does not matter: the unwired check precedes any decision, so a bearer principal
    // (which `decide_step_up` would pass) and an engine principal (which it would refuse 403) are
    // both answered 503 rather than reaching their own verdict.
    const auto source = GENERATE(as<std::string>{}, "local", "oidc", "saml", "api_token",
                                 "mcp_token", "engine_token");
    CAPTURE(source);
    yuzu::MetricsRegistry metrics;
    struct Row {
        std::string action, result, target_id, detail;
    };
    std::vector<Row> audits;
    const StepUpAuditFn audit = [&](const httplib::Request&, const std::string& a,
                                    const std::string& r, const std::string&,
                                    const std::string& ti, const std::string& d) {
        audits.push_back({a, r, ti, d});
        return true;
    };

    httplib::Request req;
    req.method = "POST";
    req.path = "/api/v1/tokens";
    httplib::Response res;
    const auto session = session_of(source == "engine_token" ? "engine:x" : "alice", source,
                                    Role::admin);

    const bool allowed = detail::run_in_handler_step_up(req, res, session, "POST /api/v1/tokens",
                                                        /*auth_db=*/nullptr, 300, audit, "optional",
                                                        &metrics);

    CHECK_FALSE(allowed);
    CHECK(res.status == 503);
    const auto body = nlohmann::json::parse(res.body, nullptr, /*allow_exceptions=*/false);
    REQUIRE(body.is_object());
    REQUIRE(body.contains("error"));
    CHECK(body["error"].value("code", 0) == 503);
    CHECK_FALSE(res.get_header_value("X-Correlation-Id").empty());
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].target_id == "POST /api/v1/tokens");
    CHECK(audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
    CHECK(gate_count(metrics, "unavailable", source) == 1);
    CHECK(gate_count(metrics, "pass", source) == 0);
}

TEST_CASE("in-handler step-up with no auth store still consumes a pass the chokepoint armed",
          "[stepup][null_store]") {
    // Order is part of the contract: the consume comes first (it replaces a store read, so it has
    // no use for the store). A pass can only exist if the chokepoint evaluated against a store, so
    // this is not a way past an unwired store; it pins that the 503 is the SECOND step.
    httplib::Request req;
    req.method = "POST";
    req.matched_route = "/api/v1/tokens";
    req.path = "/api/v1/tokens";
    const MfaStatusFn status = [](const std::string&) -> std::expected<AuthDB::MfaStatus, AuthDBError> {
        return AuthDB::MfaStatus{};
    };
    const StepUpSessionFn resolver = [](const httplib::Request&) {
        return std::optional<auth::Session>(session_of("t", "api_token", Role::admin));
    };
    const StepUpChokepointDeps deps{.resolve_session = &resolver, .mfa_status = &status,
                                    .window_secs = 300};
    httplib::Response chokepoint_res;
    REQUIRE(detail::apply_step_up_chokepoint(req, chokepoint_res, deps) ==
            StepUpChokepointResult::kPassed);

    httplib::Response res;
    yuzu::MetricsRegistry metrics;
    const StepUpAuditFn no_audit;
    CHECK(detail::run_in_handler_step_up(req, res, session_of("t", "api_token", Role::admin),
                                         "POST /api/v1/tokens", nullptr, 300, no_audit,
                                         "optional", &metrics));
    CHECK(res.status == -1);
    detail::clear_step_up_pass();
}

// ── auth_routes.cpp's elevation_step_up ───────────────────────────────────────────────────────

namespace {

yuzu::test::PgTestTemplate step_up_null_store_audit_tpl{
    "stepupnullaudit", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::AuditStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("stepupnullaudit template: store failed to migrate");
    }};

// An AuthManager that was never given an AuthDB (the null store), real local users for role
// resolution, a real AuditStore and ApiTokenStore for the audit row and the bearer classes.
struct NullStoreAuthHarness {
    yuzu::test::TempDir tmp;
    Config cfg{};
    AuthManager auth_mgr{};
    yuzu::MetricsRegistry metrics;
    yuzu::test::ApiTokenStorePg api_tokens;
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> auth_routes;
    yuzu::server::test::TestRouteSink sink;

    NullStoreAuthHarness() {
        std::filesystem::create_directories(tmp.path);
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false;
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", Role::admin));
        auth_mgr.set_metrics_registry(&metrics);
        REQUIRE(auth_mgr.auth_db_ptr() == nullptr); // the premise of every case in this file

        audit_db.emplace(step_up_null_store_audit_tpl);
        INFO("audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit_store->is_open());

        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   api_tokens.get(), audit_store.get(), nullptr,
                                                   nullptr, /*analytics_store=*/nullptr, oidc_mu,
                                                   oidc_provider);
        auth_routes->register_routes(sink);
    }

    // POST /api/v1/users/bob/elevation-eligibility with the given extra headers.
    auto post_eligibility(const std::unordered_map<std::string, std::string>& headers) {
        return sink.dispatch("POST", "/api/v1/users/bob/elevation-eligibility",
                             R"({"eligible":true})", "application/json", headers);
    }

    std::vector<AuditEvent> step_up_audits() {
        AuditQuery q;
        q.action = "mfa.step_up.required";
        auto rows = audit_store->query(q);
        return rows.has_value() ? *rows : std::vector<AuditEvent>{};
    }
};

} // namespace

TEST_CASE("elevation-eligibility with no auth store is a 503 for a cookie admin and an api_token "
          "admin",
          "[pg][stepup][null_store]") {
    NullStoreAuthHarness h;

    std::string expected_source;
    std::unordered_map<std::string, std::string> headers;
    SECTION("local cookie session") {
        const auto token = h.auth_mgr.create_local_session_for_test("admin", Role::admin,
                                                                    /*mfa_verified=*/true);
        REQUIRE_FALSE(token.empty());
        headers = {{"Cookie", "yuzu_session=" + token}};
        expected_source = "local";
    }
    SECTION("api_token bearer") {
        auto raw = h.api_tokens->create_token("null-store-key", "admin");
        REQUIRE(raw.has_value());
        headers = {{"Authorization", "Bearer " + *raw}};
        expected_source = "api_token";
    }
    CAPTURE(expected_source);

    auto res = h.post_eligibility(headers);
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto body = nlohmann::json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE(body.is_object());
    REQUIRE(body.contains("error"));
    CHECK(body["error"].value("code", 0) == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());

    const auto audits = h.step_up_audits();
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].target_id == "POST /api/v1/users/{name}/elevation-eligibility");
    CHECK(audits[0].detail.find("reason=auth_store_unwired") != std::string::npos);
    CHECK(gate_count(h.metrics, "unavailable", expected_source) == 1);
    CHECK(gate_count(h.metrics, "pass", expected_source) == 0);
}

TEST_CASE("elevation-eligibility: a non-interactive MCP-tier token is refused before the "
          "step-up, so the null store is not what answers it",
          "[pg][stepup][null_store]") {
    NullStoreAuthHarness h;
    // An MCP-tier token must expire; one hour is well inside the tier's ceiling.
    const auto expires_at = std::chrono::duration_cast<std::chrono::seconds>(
                                (std::chrono::system_clock::now() + std::chrono::hours(1))
                                    .time_since_epoch())
                                .count();
    auto raw = h.api_tokens->create_token("null-store-mcp", "admin", expires_at,
                                          /*scope_service=*/"", /*mcp_tier=*/"operator");
    REQUIRE(raw.has_value());

    auto res = h.post_eligibility({{"Authorization", "Bearer " + *raw}});
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.step_up_audits().empty());
    CHECK(gate_count(h.metrics, "unavailable", "mcp_token") == 0);
}
