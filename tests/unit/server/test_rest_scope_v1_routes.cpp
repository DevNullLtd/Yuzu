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
 *
 * #4981 PR-2: `POST /api/v1/scope/preview` now routes through the SAME
 * `resolve_scope_targets` ladder a real dispatch uses (via
 * `set_scope_evaluate_fn`, a closure over a REAL `AgentRegistry`), so this
 * harness wires a real registry too — a bare attribute-JSON stub can no
 * longer stand in for it.
 */

#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_set_store.hpp"

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <unordered_set>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

// Shares the "resultset" template key with test_scope_walking_authz.cpp /
// test_rest_result_sets_async.cpp (identical setup).
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

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

    // Kept for source-stability of the register_routes call (still consumed
    // by other agents_fn-driven routes in this harness's registration list,
    // e.g. GET /api/v1/devices if a future test exercises it) — #4981 PR-2:
    // no longer read by POST /api/v1/scope/preview itself.
    nlohmann::json agents = nlohmann::json::array({
        {{"agent_id", "agent-001"}, {"hostname", "h1"}, {"os", "linux"}, {"arch", "x64"},
         {"agent_version", "1.0"}},
        {{"agent_id", "agent-002"}, {"hostname", "h2"}, {"os", "windows"}, {"arch", "x64"},
         {"agent_version", "1.0"}},
    });

    // #4981 PR-2 — a REAL AgentRegistry, populated to match `agents` above
    // exactly (agent-001 linux/x64, agent-002 windows/x64) so every
    // pre-#4981 ostype/arch-only test keeps its original expectation.
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    // Records every result_set.access audit call (#4981 PR-2's 404 case) so
    // a test can assert the forensic row without a real AuditStore.
    struct AuditCall {
        std::string action, result, target_type, target_id, detail;
    };
    std::vector<AuditCall> audit_calls;

    /// `wire_fleet_read=false` passes a genuinely EMPTY std::function to
    /// register_routes, exercising the ROUTE's OWN "if (!fleet_read_fn)"
    /// unwired-misconfiguration branch — a live-mutable `fleet_gate` (see
    /// below) cannot model that case, since the route only checks
    /// truthiness of the std::function itself, never calls it to find out.
    ///
    /// #4981 PR-2: `wire_scope_evaluate=false` is the identical pattern for
    /// `set_scope_evaluate_fn` — the setter is simply never called, leaving
    /// the route's own unwired branch live. `result_set_store` (nullable) is
    /// bound into BOTH `register_routes`'s own `result_set_store` param
    /// (feeds the ladder's alias-resolution/owner-check-gate steps) AND the
    /// `scope_evaluate_fn` closure (feeds `AgentRegistry::evaluate_scope`'s
    /// own preload) — a [pg] test constructs a real store BEFORE building
    /// this harness and passes the SAME pointer here, so the two can never
    /// disagree about which store is live (the concrete failure mode: a
    /// mismatch doesn't fail loudly, it just skips the gate's forensic row
    /// or returns `unresolvable` where a test expects `owner_check_failed`).
    explicit ScopeV1Harness(bool wire_fleet_read = true, bool wire_scope_evaluate = true,
                            ResultSetStore* result_set_store = nullptr) {
        agent_pb::AgentInfo a1;
        a1.set_agent_id("agent-001");
        a1.set_hostname("h1");
        a1.mutable_platform()->set_os("linux");
        a1.mutable_platform()->set_arch("x64");
        a1.set_agent_version("1.0");
        (void)registry.register_agent(a1);
        agent_pb::AgentInfo a2;
        a2.set_agent_id("agent-002");
        a2.set_hostname("h2");
        a2.mutable_platform()->set_os("windows");
        a2.mutable_platform()->set_arch("x64");
        a2.set_agent_version("1.0");
        (void)registry.register_agent(a2);

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
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
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

        if (wire_scope_evaluate) {
            api.set_scope_evaluate_fn(
                [this, result_set_store](const yuzu::scope::Expression& expr,
                                         const std::string& principal) {
                    return registry.evaluate_scope(expr, /*tag_store=*/nullptr,
                                                   /*props_store=*/nullptr, result_set_store,
                                                   principal);
                });
        }

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
            /*execution_event_bus=*/nullptr, /*result_set_store=*/result_set_store,
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

// #4981 PR-2: the expression-shape check runs BEFORE the scope_evaluate_fn
// unwired check (mirrors GET /api/v1/events' own 400-before-503 ordering) —
// an empty expression still 400s even with no evaluator wired at all.
TEST_CASE("scope v1: POST /api/v1/scope/preview still 400s on an empty expression when "
          "scope_evaluate_fn is ALSO unwired (input-shape checked first)",
          "[rest][scope][v1]") {
    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/false};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

// #4981 PR-2: the new evaluator seam's own fail-closed-when-unwired posture.
TEST_CASE("scope v1: POST /api/v1/scope/preview fails closed when scope_evaluate_fn is unwired",
          "[rest][scope][v1]") {
    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/false};
    auto r = h.sink.Post("/api/v1/scope/preview", R"({"expression":"arch == \"x64\""})");
    REQUIRE(r);
    CHECK(r->status == 503);
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
// (routed-concerns.md's authorize_list_read row). #4981 PR-2: now the exact
// -send-set assertion against a REAL ladder-produced match, not a bespoke
// resolver.
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

// #4981 regression: NOT from_result_set:<id> with a null ResultSetStore*
// aborts (503), never silently matches the whole fleet.
TEST_CASE("scope v1: POST /api/v1/scope/preview with a null ResultSetStore* aborts a "
          "from_result_set: atom, never a silent fleet-wide match",
          "[rest][scope][v1]") {
    ScopeV1Harness h; // default result_set_store = nullptr
    auto r =
        h.sink.Post("/api/v1/scope/preview", R"({"expression":"NOT from_result_set:rs_anything"})");
    REQUIRE(r);
    CHECK(r->status == 503);
}

// ── [pg] — a real ResultSetStore, exercising the owner-check gate end-to-end ─

TEST_CASE("scope v1: POST /api/v1/scope/preview resolves from_result_set: against a real, "
          "owned result set",
          "[pg][rest][scope][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "tester"; // matches ScopeV1Harness's fixed auth_fn username
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-001"});
    REQUIRE(set.has_value());

    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/true, &store};
    // FleetReadGate{.admitted=true} alone defaults .scope to deny_all() —
    // see the harness's own unconfined-match test above for the same note.
    h.fleet_gate = authz::FleetReadGate{.admitted = true, .scope = std::nullopt};
    auto r = h.sink.Post("/api/v1/scope/preview",
                         nlohmann::json({{"expression", "from_result_set:" + set->id}}).dump());
    REQUIRE(r);
    REQUIRE(r->status == 200);
    auto body = nlohmann::json::parse(r->body);
    CHECK(body["data"]["matched_count"] == 1);
    CHECK(body["data"]["matched_agents"][0] == "agent-001");
}

TEST_CASE("scope v1: POST /api/v1/scope/preview 404s on a foreign result set, existence-"
          "oracle-safe, and audits the forensic row",
          "[pg][rest][scope][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "someone-else"; // NOT "tester" — the harness's fixed username
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-001"});
    REQUIRE(set.has_value());

    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/true, &store};
    auto r = h.sink.Post("/api/v1/scope/preview",
                         nlohmann::json({{"expression", "from_result_set:" + set->id}}).dump());
    REQUIRE(r);
    CHECK(r->status == 404);

    bool found = false;
    for (const auto& c : h.audit_calls)
        if (c.action == "result_set.access" && c.result == "denied" && c.target_id == set->id)
            found = true;
    CHECK(found);
}

TEST_CASE("scope v1: POST /api/v1/scope/preview 404s on an absent result set",
          "[pg][rest][scope][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/true, &store};
    auto r = h.sink.Post("/api/v1/scope/preview",
                         R"({"expression":"from_result_set:rs_does_not_exist"})");
    REQUIRE(r);
    CHECK(r->status == 404);
}

TEST_CASE("scope v1: POST /api/v1/scope/preview 503s on a degraded result-set store, never a "
          "silent 0-match",
          "[pg][rest][scope][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "tester";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-001"});
    REQUIRE(set.has_value());

    // Simulate a Postgres-side degrade — same technique
    // test_scope_walking_authz.cpp uses.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE result_set_store.result_set_members CASCADE")};
        REQUIRE(r.ok());
    }

    ScopeV1Harness h{/*wire_fleet_read=*/true, /*wire_scope_evaluate=*/true, &store};
    auto r = h.sink.Post("/api/v1/scope/preview",
                         nlohmann::json({{"expression", "from_result_set:" + set->id}}).dump());
    REQUIRE(r);
    CHECK(r->status == 503);
}
