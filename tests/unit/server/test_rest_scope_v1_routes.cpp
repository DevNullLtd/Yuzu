/**
 * test_rest_scope_v1_routes.cpp — HTTP-level coverage for the #2146 Batch B2
 * versioned scope routes: `POST /api/v1/scope/validate` and `POST
 * /api/v1/scope/preview`. Uses the TestRouteSink dispatch pattern (#438, no
 * httplib acceptor thread).
 *
 * Both routes share their underlying logic with the corresponding MCP tools
 * (validate_scope / preview_scope_targets) via yuzu::scope::validate() and
 * scope_preview.hpp's preview_scope_targets() respectively — these tests
 * cover the REST-side wiring specifically: auth-only for validate (no RBAC
 * gate), the admit-then-filter fleet_read_fn confinement for preview (the
 * #2146 B2 review fix — a bare perm_fn would disclose the whole fleet to a
 * management-group-confined caller), and the fail-closed-when-unwired
 * postures.
 */

#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_set>

using namespace yuzu::server;

namespace {

struct ScopeV1Harness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    bool authenticated{true};
    // Mutable after construction — a test overwrites .admitted/.scope and the
    // registered route sees the live value (captured by `this`, not by copy).
    // The genuinely-unwired case is `wire_fleet_read=false` at construction
    // instead (see the constructor's own doc comment) — a live-mutable value
    // here cannot model an actually-empty std::function.
    authz::FleetReadGate fleet_gate{.admitted = true};

    // The raw agent snapshot GET /api/v1/devices and this preview route both
    // read — same shape as MCP's agents_fn() stub.
    nlohmann::json agents = nlohmann::json::array({
        {{"agent_id", "agent-001"}, {"hostname", "h1"}, {"os", "linux"}, {"arch", "x64"},
         {"agent_version", "1.0"}},
        {{"agent_id", "agent-002"}, {"hostname", "h2"}, {"os", "windows"}, {"arch", "x64"},
         {"agent_version", "1.0"}},
    });

    /// `wire_fleet_read=false` passes a genuinely EMPTY std::function to
    /// register_routes, exercising the ROUTE's OWN "if (!fleet_read_fn)"
    /// unwired-misconfiguration branch — a live-mutable `fleet_gate` (see
    /// below) cannot model that case, since the route only checks
    /// truthiness of the std::function itself, never calls it to find out.
    explicit ScopeV1Harness(bool wire_fleet_read = true) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!authenticated) {
                res.status = 401;
                res.set_content(R"({"error":"unauthenticated"})", "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool {
            return true; // validate has no perm_fn gate; unused by preview post-fix
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };
        // Checked LIVE (at call time, via captured `this`) rather than baked
        // in at construction time — a test mutates `fleet_gate`'s VALUE
        // (admitted/scope) AFTER the harness is built, and the registered
        // route must see that live value, not a snapshot from construction.
        // The truly "unwired" case is modelled by `wire_fleet_read=false`
        // leaving the std::function passed to register_routes genuinely
        // empty instead (see this constructor's own doc comment).
        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&, const std::string&) -> authz::FleetReadGate {
                if (!fleet_gate.admitted) {
                    res.status = 403;
                    res.set_content(R"({"error":"forbidden"})", "application/json");
                }
                return fleet_gate;
            };
        }
        RestApiV1::AgentsJsonFn agents_fn = [this]() -> nlohmann::json { return agents; };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
            /*metrics_registry=*/nullptr, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
            /*dex_perf_fn=*/{}, /*network_api=*/nullptr, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{}, /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr, /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{}, /*list_read_fn=*/{},
            fleet_read_fn, agents_fn);
    }
};

} // namespace

// ── POST /api/v1/scope/validate ─────────────────────────────────────────────

TEST_CASE("scope v1: POST /api/v1/scope/validate requires auth", "[rest][scope][v1]") {
    ScopeV1Harness h;
    h.authenticated = false;
    auto r = h.sink.Post("/api/v1/scope/validate", R"({"expression":"tag:env == \"prod\""})");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("scope v1: POST /api/v1/scope/validate requires a non-empty expression",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    auto r = h.sink.Post("/api/v1/scope/validate", R"({})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("scope v1: POST /api/v1/scope/validate reports valid:true for a well-formed "
          "expression",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    auto r = h.sink.Post("/api/v1/scope/validate", R"({"expression":"tag:env == \"prod\""})");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    auto body = nlohmann::json::parse(r->body);
    CHECK(body["data"]["valid"] == true);
    CHECK(body["data"]["expression"] == "tag:env == \"prod\"");
}

TEST_CASE("scope v1: POST /api/v1/scope/validate reports valid:false with an error for a "
          "malformed expression",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    auto r = h.sink.Post("/api/v1/scope/validate", R"({"expression":"tag:env =="})");
    REQUIRE(r);
    REQUIRE(r->status == 200); // the REQUEST is well-formed; the response reports invalidity
    auto body = nlohmann::json::parse(r->body);
    CHECK(body["data"]["valid"] == false);
    REQUIRE(body["data"].contains("error"));
}

// ── POST /api/v1/scope/preview ──────────────────────────────────────────────

TEST_CASE("scope v1: POST /api/v1/scope/preview fails closed when fleet_read_fn is unwired",
          "[rest][scope][v1]") {
    ScopeV1Harness h{/*wire_fleet_read=*/false};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({"expression":"arch == \"x64\""})");
    REQUIRE(r);
    CHECK(r->status == 503);
}

TEST_CASE("scope v1: POST /api/v1/scope/preview denies when fleet_read_fn does not admit",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    h.fleet_gate = authz::FleetReadGate{.admitted = false};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({"expression":"arch == \"x64\""})");
    REQUIRE(r);
    CHECK(r->status == 403);
}

TEST_CASE("scope v1: POST /api/v1/scope/preview requires a non-empty expression",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    auto r = h.sink.Post("/api/v1/scope/preview", R"({})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("scope v1: POST /api/v1/scope/preview matches both agents when unconfined "
          "(gate.scope == nullopt)",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    // `FleetReadGate{.admitted=true}` alone (the harness field's default)
    // fails closed to an ENGAGED-EMPTY scope (deny_all), not nullopt/TOP —
    // by design, so a caller that forgets to set .scope filters everything
    // out rather than leaking the fleet. Set it explicitly for this
    // deliberately-unconfined case.
    h.fleet_gate = authz::FleetReadGate{.admitted = true, .scope = std::nullopt};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({"expression":"arch == \"x64\""})");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    auto body = nlohmann::json::parse(r->body);
    CHECK(body["data"]["matched_count"] == 2);
}

// ── #2146 B2 review fix regression: a management-group-confined caller must
// see ONLY their own visible agents on this fan-out read, never the whole
// fleet — mirrors the MCP preview_scope_targets regression test exactly
// (routed-concerns.md's authorize_list_read row).
TEST_CASE("scope v1: POST /api/v1/scope/preview confines matched_agents to the caller's "
          "fleet_read_fn scope, never the whole fleet",
          "[rest][scope][v1]") {
    ScopeV1Harness h;
    h.fleet_gate = authz::FleetReadGate{
        .admitted = true, .scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-001"}}};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({"expression":"arch == \"x64\""})");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    auto body = nlohmann::json::parse(r->body);
    CHECK(body["data"]["matched_count"] == 1);
    REQUIRE(body["data"]["matched_agents"].size() == 1);
    CHECK(body["data"]["matched_agents"][0] == "agent-001");
}
