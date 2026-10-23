/**
 * test_rest_executions_v1_twins.cpp — HTTP-level coverage for #4030's
 * executions REST v1 surface: the new confined list route
 * (GET /api/v1/executions), the widened detail route's per-agent expansion
 * (GET /api/v1/executions/{id}?include=agents), and the new execution-scoped
 * responses route (GET /api/v1/executions/{id}/responses).
 *
 * Pattern matches test_rest_visualization.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised requests
 * directly into the captured handlers. No real socket → no #438 TSan trap.
 */

#include "auth_routes.hpp"
#include "execution_tracker.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "response_export_metrics.hpp"
#include "rest_api_v1.hpp"
#include "response_store.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <set>
#include <shared_mutex>
#include <unordered_map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {
// Fault-injection helper for the #2146 A2-R1 degrade test below: runs a raw
// statement over a fresh side connection (never the harness's own pool, so
// the tracker's `open_`/pool state stays otherwise healthy -- only the ONE
// targeted query fails). Mirrors test_audit_store.cpp's identical
// `exec_sql` idiom.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}
} // namespace

namespace {

// Shares the "responsestore" template key with test_response_store.cpp /
// test_rest_visualization.cpp (identical setup) — ResponseStore is the base
// PgTestTemplate; ExecutionTracker/InstructionStore self-migrate their own
// schemas idempotently when constructed against the same database (matches
// test_workflow_routes.cpp's ExecHarness pattern).
yuzu::test::PgTestTemplate execv1_responsestore_tpl{
    "responsestore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("execv1 responsestore template: store failed to migrate");
    }};

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct ExecV1Harness {
    yuzu::MetricsRegistry metrics; // #4644 counter, seeded like production; outlives the sink
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ExecutionTracker> execution_tracker;
    std::unique_ptr<InstructionStore> instruction_store;
    std::unique_ptr<ResponseStore> response_store;

    bool perm_grant{true};
    authz::VisibleSet fleet_read_scope{std::nullopt};
    std::string session_username{"tester"};
    std::vector<AuditRecord> audit_log;
    // #4990: the caller's Forensics visibility (admin by default; the tier cases flip it).
    yuzu::server::test::ForensicsCaller forensics;
    // #4990: an audit verb whose row does NOT persist (every other row does).
    std::string audit_fail_action;

    RestApiV1 api;

    // wire_fleet_read=false leaves fleet_read_fn unwired (exercises the 503 guard).
    // real_fleet_read, when set, replaces the mocked gate with a production-shaped one.
    // wire_tracker=false registers the routes with a null ExecutionTracker* (the 503 guard).
    // real_forensics_fn, when set, replaces the stubbed ForensicsCaller with a production-shaped
    // resolver (#4990 role cases drive the REAL resolver over a real RbacStore).
    explicit ExecV1Harness(pg::PgPool& pool, bool wire_fleet_read = true,
                           RestApiV1::FleetReadFn real_fleet_read = {}, bool wire_tracker = true,
                           ForensicsVisibilityFn real_forensics_fn = {}) {
        yuzu::server::seed_response_metrics(metrics);
        api.set_forensics_plugin_set(&yuzu::server::test::forensics_plugin_set());
        api.set_forensics_visibility_fn(real_forensics_fn ? std::move(real_forensics_fn)
                                                           : forensics.fn());
        execution_tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(execution_tracker->is_open());
        instruction_store = std::make_unique<InstructionStore>(pool);
        REQUIRE(instruction_store->is_open());
        instruction_store->set_require_signed_definitions(false);
        response_store = std::make_unique<ResponseStore>(pool, /*retention_days=*/0);
        REQUIRE(response_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string&,
                                    const std::string&) -> authz::FleetReadGate {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return {false, authz::deny_all()};
            }
            return {true, fleet_read_scope};
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return a != audit_fail_action;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, response_store.get(),
                            instruction_store.get(),
                            wire_tracker ? execution_tracker.get() : nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{},
                            /*fleet_read_fn=*/!wire_fleet_read ? RestApiV1::FleetReadFn{}
                            : real_fleet_read ? std::move(real_fleet_read)
                                              : RestApiV1::FleetReadFn(std::move(fleet_read_fn)));
    }

    ~ExecV1Harness() {
        response_store.reset();
        instruction_store.reset();
        execution_tracker.reset();
    }

    /// Creates an execution row with two agent-status rows (one success, one
    /// failure) and returns the execution id.
    std::string make_exec_with_agents(const std::string& definition_id = "def-1") {
        Execution e;
        e.definition_id = definition_id;
        e.dispatched_by = "tester";
        e.status = "completed";
        e.dispatched_at = 1735689600;
        auto id = execution_tracker->create_execution(e);
        REQUIRE(id.has_value());
        AgentExecStatus a1;
        a1.agent_id = "agent-A";
        a1.status = "success";
        a1.dispatched_at = 1735689600;
        a1.completed_at = 1735689610;
        execution_tracker->update_agent_status(*id, a1);
        AgentExecStatus a2;
        a2.agent_id = "agent-B";
        a2.status = "failure";
        a2.dispatched_at = 1735689600;
        a2.completed_at = 1735689620;
        a2.error_detail = "boom";
        execution_tracker->update_agent_status(*id, a2);
        return *id;
    }
};

} // namespace

TEST_CASE("GET /api/v1/executions: lists via the shared builder", "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-list-1");

    auto res = h.sink.Get("/api/v1/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    bool found = false;
    for (const auto& row : body["data"]) {
        if (row["id"] == exec_id) {
            found = true;
            CHECK(row["agents_success"] == 1);
            CHECK(row["agents_failure"] == 1);
            CHECK(row.contains("definition_name"));
            CHECK(row.contains("error_preview"));
        }
    }
    CHECK(found);
    CHECK(body["pagination"]["total"] >= 1);
}

TEST_CASE("GET /api/v1/executions: fleet_read_fn denial → 403",
          "[pg][rest][executions][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/executions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// Confined list (#3526): the handler pushes the caller's scope into the list query, reads the
// per-agent status rows through the SAME visible set, and recomputes the counters from the
// in-scope rows only. Exact ids and exact projected counts, so (a) a mutation that hands the
// status read some other list (the owner, an empty set) zeroes the counters and (b) one that
// drops the scope or the owner disjunct changes the id set. Fake gate (the harness has no real
// chokepoint); the real-gate drive of the same decision is in
// test_workflow_executions_list_authz.cpp.
TEST_CASE("GET /api/v1/executions: a confined caller gets owner-or-visible rows with projected "
          "counts",
          "[pg][rest][executions][v1][confinement][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A", "agent-C"}};
    h.session_username = "bob";

    auto make = [&](const std::string& by, int64_t at) {
        Execution e;
        e.definition_id = "def-rest-confined";
        e.dispatched_by = by;
        e.status = "completed";
        e.dispatched_at = at;
        e.agents_targeted = 9; // the unconfined counter: must never reach a confined caller
        auto id = h.execution_tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    };
    auto st = [&](const std::string& exec, const std::string& agent, const std::string& status,
                  const std::string& err, int64_t done) {
        AgentExecStatus a;
        a.agent_id = agent;
        a.status = status;
        a.completed_at = done;
        a.error_detail = err;
        h.execution_tracker->update_agent_status(exec, a);
    };
    const auto x_mixed = make("carol", 1735689601); // A ok + B failed: visible via A
    st(x_mixed, "agent-A", "success", "", 1735689610);
    st(x_mixed, "agent-B", "failure", "SECRET-B-ERR", 1735689690);
    const auto x_hidden = make("carol", 1735689602); // B only: invisible
    st(x_hidden, "agent-B", "failure", "SECRET-B-ONLY", 1735689691);
    const auto x_own = make("bob", 1735689603); // owner row, B only: visible, counters 0
    st(x_own, "agent-B", "failure", "SECRET-B-OWN", 1735689692);
    const auto x_two = make("carol", 1735689604); // A failed + C ok + B ok
    st(x_two, "agent-A", "failure", "ERR-A", 1735689700);
    st(x_two, "agent-C", "success", "", 1735689701);
    st(x_two, "agent-B", "success", "", 1735689702);

    auto res = h.sink.Get("/api/v1/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("SECRET-B") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    std::unordered_map<std::string, nlohmann::json> rows;
    for (const auto& row : body["data"])
        rows[row["id"].get<std::string>()] = row;
    CHECK(rows.size() == 3);
    CHECK(rows.count(x_hidden) == 0);
    REQUIRE(rows.count(x_mixed) == 1);
    CHECK(rows[x_mixed]["agents_targeted"] == 1);
    CHECK(rows[x_mixed]["agents_responded"] == 1);
    CHECK(rows[x_mixed]["agents_success"] == 1);
    CHECK(rows[x_mixed]["agents_failure"] == 0);
    CHECK(rows[x_mixed]["error_preview"] == "");
    REQUIRE(rows.count(x_own) == 1);
    CHECK(rows[x_own]["agents_targeted"] == 0);
    CHECK(rows[x_own]["agents_responded"] == 0);
    CHECK(rows[x_own]["error_preview"] == "");
    REQUIRE(rows.count(x_two) == 1);
    CHECK(rows[x_two]["agents_targeted"] == 2);
    CHECK(rows[x_two]["agents_responded"] == 2);
    CHECK(rows[x_two]["agents_success"] == 1);
    CHECK(rows[x_two]["agents_failure"] == 1);
    CHECK(rows[x_two]["error_preview"] == "ERR-A");

    // The same caller with an empty visible set sees ONLY the row they dispatched.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{}};
    auto none = h.sink.Get("/api/v1/executions");
    REQUIRE(none);
    CHECK(none->status == 200);
    auto nb = nlohmann::json::parse(none->body);
    REQUIRE(nb["data"].size() == 1);
    CHECK(nb["data"][0]["id"] == x_own);
    CHECK(nb["data"][0]["agents_targeted"] == 0);
}

TEST_CASE("GET /api/v1/executions/:id: bare request has no agents/kpi and is unaudited",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-bare-1");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK_FALSE(body["data"].contains("agents"));
    CHECK_FALSE(body["data"].contains("kpi"));
    for (const auto& c : h.audit_log)
        CHECK(c.target_id != exec_id);
}

// Governance fix (#2146 A2-R1 re-review, adjudicated): this route used the
// plain get_execution(), which collapses "execution genuinely absent" and
// "read degraded" (a transient pool/query failure) to the same nullopt -- a
// degrade fell through to the SAME not-found + denial-audit branch a genuine
// absence takes, producing a FALSE 404 for a legitimate owner and a
// permanently wrong CC7.2 denial audit row for a confined caller whose only
// "fault" was hitting a transient outage. get_execution_checked's outer
// std::expected now distinguishes the two; the degrade branch returns
// BEFORE any denial audit is recorded.
TEST_CASE("GET /api/v1/executions/:id: a transient tracker degrade is 503, not a "
          "false 404, and records no denial audit (#2146 A2-R1)",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-degrade-1");
    // Engage a confined scope so the OLD code's denial-audit branch would
    // have fired on the false 404 this fix closes -- an unconfined caller
    // never reaches that branch at all, which would make assertion (b)
    // below pass trivially even against the unfixed code.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    // Break ONLY the get_execution_checked query -- a raw statement over a
    // side connection, never the harness's own pool, so the tracker stays
    // "open" and this is a genuine single-call fault (a full outage would
    // already hit the pre-existing tracker-unavailable/pool-exhaustion
    // branch above and mask this specific defect).
    exec_sql(db.dsn(), "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_2146");
    auto res = h.sink.Get("/api/v1/executions/" + exec_id);
    exec_sql(db.dsn(), "ALTER TABLE execution_tracker.executions_hidden_2146 RENAME TO executions");

    REQUIRE(res);
    // (a) 503, never the old false 404.
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["retry_after_ms"] == 5000);

    // (b) no denial audit row for this execution -- pre-fix, this recorded
    // execution.detail.fetch/denied here.
    for (const auto& c : h.audit_log)
        CHECK(c.target_id != exec_id);
}

TEST_CASE("GET /api/v1/executions/:id?include=agents: adds per-agent array + kpi, audited",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-inc-1");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "?include=agents");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].contains("agents"));
    REQUIRE(body["data"]["agents"].is_array());
    CHECK(body["data"]["agents"].size() == 2);
    REQUIRE(body["data"].contains("kpi"));
    CHECK(body["data"]["kpi"]["total"] == 2);
    CHECK(body["data"]["kpi"]["succeeded"] == 1);
    CHECK(body["data"]["kpi"]["failed"] == 1);

    bool audited = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "execution.detail.fetch" && c.target_id == exec_id)
            audited = true;
    }
    CHECK(audited);
}

TEST_CASE("GET /api/v1/executions/:id?include=agents: confines the per-agent array to the "
          "caller's fleet-read scope",
          "[pg][rest][executions][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-conf-1");
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "?include=agents");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["agents"].is_array());
    CHECK(body["data"]["agents"].size() == 1);
    CHECK(body["data"]["agents"][0]["agent_id"] == "agent-A");
    CHECK(body["data"]["agents_targeted"] == 1);
}

TEST_CASE("GET /api/v1/executions/:id/responses: mirrors query_responses' execution_id filter",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-1");

    StoredResponse r;
    r.instruction_id = "def-resp-1";
    r.agent_id = "agent-A";
    r.timestamp = 1735689610;
    r.status = 0;
    r.output = "hello";
    r.execution_id = exec_id;
    h.response_store->store(r);

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-A");
    CHECK(body["data"][0]["execution_id"] == exec_id);
    CHECK(body["data"][0]["output"] == "hello");

    bool audited = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "execution.detail.fetch" && c.target_id == exec_id)
            audited = true;
    }
    CHECK(audited);
}

// #4990: the Forensics tier. Real PG-backed store, exact rendered rows, a non-Forensics control row.
TEST_CASE("GET /api/v1/executions/:id/responses: Forensics rows follow the caller's Forensics "
          "visibility",
          "[pg][rest][executions][v1][responses][security][forensics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-tier");

    auto put = [&](const std::string& agent, const std::string& plugin, const std::string& out,
                   int64_t ts) {
        StoredResponse r;
        r.instruction_id = "def-resp-tier";
        r.agent_id = agent;
        r.timestamp = ts;
        r.status = 0;
        r.output = out;
        r.plugin = plugin;
        r.execution_id = exec_id;
        h.response_store->store(r);
    };
    using yuzu::server::test::kForensicsPlugin;
    using yuzu::server::test::kOrdinaryPlugin;
    put("agent-A", kForensicsPlugin, "forensics-A", 1735689610);
    put("agent-B", kForensicsPlugin, "forensics-B", 1735689611);
    put("agent-A", kOrdinaryPlugin, "ordinary-A", 1735689612);
    put("agent-B", kOrdinaryPlugin, "ordinary-B", 1735689613);

    auto outputs = [&](const std::string& q = "") {
        auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses" + q);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        std::set<std::string> out;
        for (const auto& r : body["data"])
            out.insert(r["output"].get<std::string>());
        return out;
    };
    using Outputs = std::set<std::string>;

    h.forensics.viewer();
    CHECK(outputs() == Outputs{"ordinary-A", "ordinary-B"});
    h.forensics.admin();
    CHECK(outputs() == Outputs{"forensics-A", "forensics-B", "ordinary-A", "ordinary-B"});
    h.forensics.scoped({"agent-B"});
    CHECK(outputs() == Outputs{"forensics-B", "ordinary-A", "ordinary-B"});

    // A confined caller (gate scope engaged): the in-scope agent set is derived from the
    // permitted rows, so an agent that answered only with a Forensics row is not even enumerated.
    h.forensics.viewer();
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};
    CHECK(outputs() == Outputs{"ordinary-A"});
}

// #4990: the delegable ForensicsAnalyst role through the REAL resolver. The route's own gates are the
// harness mocks (open); what is real here is the Forensics visibility, resolved by the production
// `resolve_forensics_visible` over a real AuthRoutes + RbacStore + ManagementGroupStore from the
// caller's session cookie.
TEST_CASE("GET /api/v1/executions/:id/responses through the REAL resolver: a ForensicsAnalyst holder "
          "reads Forensics rows, a Viewer does not, and neither can dispatch",
          "[pg][rest][executions][v1][responses][security][forensics][forensics_analyst]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};

    Config cfg{};
    auth::AuthManager auth_mgr{};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr, &mgmt,
                  /*tag_store=*/nullptr, /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    ForensicsVisibilityDeps deps{
        .auth_routes = &ar, .rbac_store = &rbac, .mgmt_store = &mgmt, .metrics = nullptr};
    ExecV1Harness h(pool, true, {}, true, [&deps](const httplib::Request& req) {
        return resolve_forensics_visible(deps, req);
    });
    auto exec_id = h.make_exec_with_agents("def-resp-analyst");

    using yuzu::server::test::kForensicsPlugin;
    using yuzu::server::test::kOrdinaryPlugin;
    auto put = [&](const std::string& agent, const std::string& plugin, const std::string& out,
                   int64_t ts) {
        StoredResponse r;
        r.instruction_id = "def-resp-analyst";
        r.agent_id = agent;
        r.timestamp = ts;
        r.status = 0;
        r.output = out;
        r.plugin = plugin;
        r.execution_id = exec_id;
        h.response_store->store(r);
    };
    put("agent-A", kForensicsPlugin, "forensics-A", 1735689610);
    put("agent-B", kForensicsPlugin, "forensics-B", 1735689611);
    put("agent-A", kOrdinaryPlugin, "ordinary-A", 1735689612);
    put("agent-B", kOrdinaryPlugin, "ordinary-B", 1735689613);

    auto cookie_for = [&](const std::string& user) {
        REQUIRE(auth_mgr.upsert_user(user, "correct-horse-battery-staple", auth::Role::user));
        auto token = auth_mgr.create_local_session_for_test(user, auth::Role::user, true);
        return std::unordered_map<std::string, std::string>{{"Cookie", "yuzu_session=" + token}};
    };
    using Outputs = std::set<std::string>;
    auto outputs = [&](const std::unordered_map<std::string, std::string>& headers) {
        auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses", headers);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        Outputs out;
        for (const auto& r : body["data"])
            out.insert(r["output"].get<std::string>());
        return out;
    };

    REQUIRE(rbac.assign_role({"user", "ana", "ForensicsAnalyst"}).has_value());
    REQUIRE(rbac.assign_role({"user", "vic", "Viewer"}).has_value());
    REQUIRE(rbac.assign_role({"user", "oli", "Operator"}).has_value());
    const auto ana = cookie_for("ana");
    const auto vic = cookie_for("vic");
    const auto oli = cookie_for("oli");

    // The analyst reads the Forensics-tier rows AND the ordinary ones; a Viewer and an Operator
    // (both hold Response:Read) still see only the ordinary rows.
    CHECK(outputs(ana) == Outputs{"forensics-A", "forensics-B", "ordinary-A", "ordinary-B"});
    CHECK(outputs(vic) == Outputs{"ordinary-A", "ordinary-B"});
    CHECK(outputs(oli) == Outputs{"ordinary-A", "ordinary-B"});

    // Operator + ForensicsAnalyst: the Forensics rows appear for the combined holder.
    REQUIRE(rbac.assign_role({"user", "oli", "ForensicsAnalyst"}).has_value());
    CHECK(outputs(oli) == Outputs{"forensics-A", "forensics-B", "ordinary-A", "ordinary-B"});

    // Reading is all the role does: the analyst cannot dispatch, the combined holder keeps only the
    // Operator's own Execute, and the Forensics tier gains no write.
    auto probe = [&](const std::unordered_map<std::string, std::string>& headers,
                     const char* securable, const char* op) {
        httplib::Request req;
        for (const auto& [k, v] : headers)
            req.headers.emplace(k, v);
        return ar.has_permission(req, securable, op);
    };
    CHECK_FALSE(probe(ana, "Execution", "Execute"));
    CHECK(probe(ana, "Forensics", "Read"));
    CHECK_FALSE(probe(ana, "Forensics", "Write"));
    CHECK_FALSE(probe(ana, "Infrastructure", "Execute"));
    CHECK_FALSE(probe(vic, "Forensics", "Read"));
    CHECK(probe(oli, "Execution", "Execute")); // the Operator role's, unchanged

    // Revoking the role takes the rows away again, with no restart.
    REQUIRE(rbac.unassign_role("user", "ana", "ForensicsAnalyst").has_value());
    CHECK(outputs(ana) == Outputs{"ordinary-A", "ordinary-B"});

    // RBAC off: the grant is inert and the floor stands, so a non-admin sees no Forensics row.
    rbac.set_rbac_enabled(false);
    CHECK(outputs(oli) == Outputs{"ordinary-A", "ordinary-B"});
}

// #4990: an Unknown Forensics decision is a retryable 503 on the machine surface, never a partial 200.
TEST_CASE("GET /api/v1/executions/:id/responses: an Unknown Forensics decision is a retryable 503",
          "[pg][rest][executions][v1][responses][security][forensics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-unk");
    StoredResponse r;
    r.instruction_id = "def-resp-unk";
    r.agent_id = "agent-A";
    r.timestamp = 1735689610;
    r.status = 0;
    r.output = "ordinary-A";
    r.plugin = yuzu::server::test::kOrdinaryPlugin;
    r.execution_id = exec_id;
    h.response_store->store(r);

    h.forensics.unknown();
    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    const auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"] == 503);
    CHECK(body["error"]["retry_after_ms"] == 5000);
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK(res->body.find("ordinary-A") == std::string::npos);

    // Control: a Denied decision serves the ordinary row.
    h.forensics.viewer();
    auto ok = h.sink.Get("/api/v1/executions/" + exec_id + "/responses");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->body.find("ordinary-A") != std::string::npos);
}

// #4990: the `response.forensics.read` audit row on the execution-scoped read.
TEST_CASE("GET /api/v1/executions/:id/responses: response.forensics.read is written only when "
          "Forensics rows are served",
          "[pg][rest][executions][v1][responses][audit][security][forensics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-faud");

    auto put = [&](const std::string& agent, const std::string& plugin, const std::string& out,
                   int64_t ts) {
        StoredResponse r;
        r.instruction_id = "def-resp-faud";
        r.agent_id = agent;
        r.timestamp = ts;
        r.status = 0;
        r.output = out;
        r.plugin = plugin;
        r.execution_id = exec_id;
        h.response_store->store(r);
    };
    using yuzu::server::test::kForensicsPlugin;
    using yuzu::server::test::kOrdinaryPlugin;
    put("agent-A", kForensicsPlugin, "forensics-A", 1735689610);
    put("agent-B", kForensicsPlugin, "forensics-B", 1735689611);
    put("agent-A", kOrdinaryPlugin, "ordinary-A", 1735689612);

    auto verb_rows = [&] {
        std::vector<AuditRecord> out;
        for (const auto& a : h.audit_log)
            if (a.action == "response.forensics.read")
                out.push_back(a);
        return out;
    };
    const std::string path = "/api/v1/executions/" + exec_id + "/responses";

    h.forensics.viewer();
    {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(verb_rows().empty());
    }
    h.forensics.admin();
    h.audit_log.clear();
    {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto rows = verb_rows();
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "success");
        CHECK(rows[0].target_type == "Execution");
        CHECK(rows[0].target_id == exec_id);
        CHECK(rows[0].detail == "forensics_rows=2 plugins=browser_inventory surface=rest");
    }
    h.forensics.scoped({"agent-B"});
    h.audit_log.clear();
    {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        const auto rows = verb_rows();
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].detail == "forensics_rows=1 plugins=browser_inventory surface=rest");
    }
    h.forensics.admin();
    h.audit_log.clear();
    h.audit_fail_action = "response.forensics.read";
    {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(res->body.find("forensics-") == std::string::npos);
        CHECK(res->body.find("ordinary-") == std::string::npos);
    }
}

// #4030 Gate 8 fix (happy-path, Gate 4, HIGH/I3): `offset` over this
// route's non-unique, actively-growing `timestamp DESC` order silently
// skips/duplicates rows while an execution is non-terminal -- the same
// hazard its declared MCP twin query_responses deliberately avoids by
// never accepting the parameter. Reject rather than silently ignore.
TEST_CASE("GET /api/v1/executions/:id/responses: offset is rejected with 400, "
          "not silently ignored (#4030 Gate 8 fix)",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-offset");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses?offset=1");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/executions/:id/responses: a malformed numeric query parameter is a 400 "
          "not a different valid-looking filter; -1 'any' and zero-padding still pass (#4644)",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-strict");

    const std::string bad = GENERATE(as<std::string>{}, "status=0x1", "status=-5", "since=1e9",
                                     "since=-5", "until=-5", "until=0", "until=000", "since=5&until=0",
                                     "until=100abc", "limit=1e3", "limit=");
    INFO(bad);
    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses?" + bad);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(nlohmann::json::parse(res->body)["error"]["message"] == "invalid numeric query parameter");

    const std::string good = GENERATE(as<std::string>{}, "status=-1", "status=007", "limit=10",
                                      "since=0", "until=1", "since=0&until=4102444800");
    INFO(good);
    auto ok = h.sink.Get("/api/v1/executions/" + exec_id + "/responses?" + good);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("GET /api/v1/executions/:id/responses: a rejected numeric parameter counts on the "
          "rest_v1 surface and a valid request does not (#4644)",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-metric");
    auto rejected = [&](const char* surface) {
        return h.metrics
            .counter(yuzu::server::kResponseParamRejectedMetric, {{"surface", surface}})
            .value();
    };
    REQUIRE(rejected("rest_v1") == 0.0);

    CHECK(h.sink.Get("/api/v1/executions/" + exec_id + "/responses?limit=100abc")->status == 400);
    CHECK(rejected("rest_v1") == 1.0);
    CHECK(h.sink.Get("/api/v1/executions/" + exec_id + "/responses?status=0x1")->status == 400);
    CHECK(rejected("rest_v1") == 2.0);
    // A valid request, and the offset 400 (a different refusal), do not count.
    CHECK(h.sink.Get("/api/v1/executions/" + exec_id + "/responses?limit=10")->status == 200);
    CHECK(h.sink.Get("/api/v1/executions/" + exec_id + "/responses?offset=1")->status == 400);
    CHECK(rejected("rest_v1") == 2.0);
    // The other surfaces stay untouched.
    CHECK(rejected("rest") == 0.0);
    CHECK(rejected("mcp") == 0.0);
}

TEST_CASE("GET /api/v1/executions/:id/responses: fleet_read_fn gates on Response:Read, "
          "independent of Execution:Read",
          "[pg][rest][executions][v1][responses][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/executions/anything/responses");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// #2146 A2-R1: GET /api/v1/executions/{id}/children -- REST v1 twin of the
// legacy GET /api/executions/{id}/children (execution_routes.cpp), same
// gate/confinement rules, same execution_child_row_json shared builder
// (docs/api-twin-recipe.md Rule 1).

TEST_CASE("GET /api/v1/executions/:id/children: lists children via the shared builder",
          "[pg][rest][executions][v1][children]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto parent_id = h.make_exec_with_agents("def-children-parent");

    Execution child;
    child.definition_id = "def-children-parent";
    child.dispatched_by = "tester";
    child.status = "completed";
    child.dispatched_at = 1735689700;
    child.parent_id = parent_id;
    auto child_id = h.execution_tracker->create_execution(child);
    REQUIRE(child_id.has_value());

    auto res = h.sink.Get("/api/v1/executions/" + parent_id + "/children");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].contains("children"));
    REQUIRE(body["data"]["children"].is_array());
    bool found = false;
    for (const auto& c : body["data"]["children"]) {
        if (c["id"] == *child_id) {
            found = true;
            CHECK(c["status"] == "completed");
            CHECK(c["dispatched_at"] == 1735689700);
        }
    }
    CHECK(found);
}

TEST_CASE("GET /api/v1/executions/:id/children: unknown parent id is 404",
          "[pg][rest][executions][v1][children]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);

    auto res = h.sink.Get("/api/v1/executions/does-not-exist/children");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("GET /api/v1/executions/:id/children: each child is confined independently of the "
          "parent's own visibility (#3789)",
          "[pg][rest][executions][v1][children][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    // Parent has agent-A(success)/agent-B(failure) -- visible to a caller
    // confined to agent-A.
    auto parent_id = h.make_exec_with_agents("def-children-conf");

    Execution visible_child;
    visible_child.definition_id = "def-children-conf";
    visible_child.dispatched_by = "someone-else";
    visible_child.status = "completed";
    visible_child.dispatched_at = 1735689710;
    visible_child.parent_id = parent_id;
    auto visible_child_id = h.execution_tracker->create_execution(visible_child);
    REQUIRE(visible_child_id.has_value());
    AgentExecStatus visible_status;
    visible_status.agent_id = "agent-A";
    visible_status.status = "success";
    h.execution_tracker->update_agent_status(*visible_child_id, visible_status);

    Execution invisible_child;
    invisible_child.definition_id = "def-children-conf";
    invisible_child.dispatched_by = "someone-else";
    invisible_child.status = "completed";
    invisible_child.dispatched_at = 1735689720;
    invisible_child.parent_id = parent_id;
    auto invisible_child_id = h.execution_tracker->create_execution(invisible_child);
    REQUIRE(invisible_child_id.has_value());
    AgentExecStatus invisible_status;
    invisible_status.agent_id = "agent-C";
    invisible_status.status = "success";
    h.execution_tracker->update_agent_status(*invisible_child_id, invisible_status);

    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/executions/" + parent_id + "/children");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["children"].is_array());
    bool found_visible = false, found_invisible = false;
    for (const auto& c : body["data"]["children"]) {
        if (c["id"] == *visible_child_id)
            found_visible = true;
        if (c["id"] == *invisible_child_id)
            found_invisible = true;
    }
    CHECK(found_visible);
    CHECK_FALSE(found_invisible);
}

// #2146 A2-R1 Gate 8 fix: the exact bug the SQL scope-fold closes -- the
// 100-row cap used to apply to the RAW `parent_id`-matched row set BEFORE
// the caller-side confinement filter, so an invisible sibling dispatched
// more recently could displace this caller's own visible child entirely out
// of the capped `dispatched_at DESC` window, with `result_truncated_by_cap`
// absent (a false "this is your complete visible list"). This is a
// ROUTE-level test, not just a tracker-level one: it proves the REST v1
// handler actually threads its real confinement scope into
// get_children_checked, not merely that the tracker's SQL fold works in
// isolation (a caller that forgot to pass its scope would stay green here
// too if this test only asserted at the tracker layer).
TEST_CASE("GET /api/v1/executions/:id/children: an invisible sibling cannot displace a "
          "visible child out of the capped window (#2146 A2-R1 Gate 8 fix)",
          "[pg][rest][executions][v1][children][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto parent_id = h.make_exec_with_agents("def-children-displace");

    Execution visible_child;
    visible_child.definition_id = "def-children-displace";
    visible_child.dispatched_by = "someone-else";
    visible_child.status = "completed";
    visible_child.dispatched_at = 1000;
    visible_child.parent_id = parent_id;
    auto visible_child_id = h.execution_tracker->create_execution(visible_child);
    REQUIRE(visible_child_id.has_value());
    AgentExecStatus visible_status;
    visible_status.agent_id = "agent-A";
    visible_status.status = "success";
    h.execution_tracker->update_agent_status(*visible_child_id, visible_status);

    // 105 invisible siblings, all dispatched strictly AFTER the visible
    // child -- every one of these sorts ahead of it in the dispatched_at
    // DESC window the pre-fix cap-before-scope defect used to apply the cap
    // to.
    for (int i = 0; i < 105; ++i) {
        Execution invisible_child;
        invisible_child.definition_id = "def-children-displace";
        invisible_child.dispatched_by = "someone-else";
        invisible_child.status = "completed";
        invisible_child.dispatched_at = 2000 + i;
        invisible_child.parent_id = parent_id;
        auto invisible_id = h.execution_tracker->create_execution(invisible_child);
        REQUIRE(invisible_id.has_value());
        AgentExecStatus invisible_status;
        invisible_status.agent_id = "agent-invisible-" + std::to_string(i);
        invisible_status.status = "success";
        h.execution_tracker->update_agent_status(*invisible_id, invisible_status);
    }

    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/executions/" + parent_id + "/children");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["children"].is_array());
    bool found_visible = false;
    for (const auto& c : body["data"]["children"]) {
        if (c["id"] == *visible_child_id)
            found_visible = true;
    }
    CHECK(found_visible);
    // The caller's OWN visible row set is one row -- nowhere near the cap --
    // so this must never be reported as truncated.
    CHECK_FALSE(body["data"].contains("result_truncated_by_cap"));
}

TEST_CASE("GET /api/v1/executions/:id/children: fleet_read_fn denial -> 403",
          "[pg][rest][executions][v1][children][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/executions/anything/children");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── #4644: the execution-statistics routes and the v1 executions list read
// `since`/`limit` strictly. A malformed value used to be swallowed into the default
// (`?since=junk` meant "from the beginning"), answering a different query than asked.

TEST_CASE("GET /api/v1/execution-statistics/{agents|definitions}: a malformed since or limit is "
          "a 400 not the default; a clean value still works (#4644)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.make_exec_with_agents("def-stats-strict");

    const std::string route = GENERATE(as<std::string>{}, "/api/v1/execution-statistics/agents",
                                       "/api/v1/execution-statistics/definitions");
    const std::string bad = GENERATE(as<std::string>{}, "since=junk", "since=1e9", "since=100abc",
                                     "since=", "since=99999999999999999999", "limit=100abc",
                                     "limit=1e3", "limit=", "limit=4294967296");
    INFO(route << "?" << bad);
    auto res = h.sink.Get(route + "?" + bad);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(nlohmann::json::parse(res->body)["error"]["message"] == "invalid numeric query parameter");

    const std::string good = GENERATE(as<std::string>{}, "since=0", "since=007", "limit=10",
                                      "since=1700000000&limit=5");
    INFO(route << "?" << good);
    auto ok = h.sink.Get(route + "?" + good);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

// The three statistics routes (and /statistics) used to dereference the tracker unchecked, unlike
// their siblings: an unwired tracker is a 503, never a null dereference.
TEST_CASE("GET /api/v1/execution-statistics{,/agents,/definitions} and /statistics: an unwired "
          "tracker is a 503 (#4644)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool, /*wire_fleet_read=*/true, /*real_fleet_read=*/{}, /*wire_tracker=*/false);
    for (const char* route : {"/api/v1/execution-statistics", "/api/v1/execution-statistics/agents",
                              "/api/v1/execution-statistics/definitions", "/api/v1/statistics"}) {
        INFO(route);
        auto res = h.sink.Get(route);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(nlohmann::json::parse(res->body)["error"]["message"] ==
              "execution tracker unavailable");
    }
}

TEST_CASE("GET /api/v1/execution-statistics/{agents|definitions}: a limit below 1 is a 400 like "
          "the MCP twin, not the default 50 (#4644)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.make_exec_with_agents("def-stats-limit-floor");

    const std::string route = GENERATE(as<std::string>{}, "/api/v1/execution-statistics/agents",
                                       "/api/v1/execution-statistics/definitions");
    for (const char* bad : {"limit=0", "limit=-1", "limit=-2147483648"}) {
        INFO(route << "?" << bad);
        auto res = h.sink.Get(route + "?" + bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(nlohmann::json::parse(res->body)["error"]["message"] == "limit must be at least 1");
    }
    auto one = h.sink.Get(route + "?limit=1");
    REQUIRE(one);
    CHECK(one->status == 200);
}

TEST_CASE("GET /api/v1/executions: a trailing-garbage limit is a 400 not the numeric prefix "
          "(#4644)",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.make_exec_with_agents("def-list-strict");

    for (const char* bad : {"limit=100abc", "limit=1e3", "limit=0x10", "limit=", "limit=4294967296"}) {
        INFO(bad);
        auto res = h.sink.Get(std::string("/api/v1/executions?") + bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(nlohmann::json::parse(res->body)["error"]["message"] ==
              "invalid numeric query parameter");
    }
    auto ok = h.sink.Get("/api/v1/executions?limit=10");
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

// ── #3526 (ADR-0017): GET /api/v1/execution-statistics/agents is confined ─────

namespace {
// Agent ids of the rows an /agents response served, in served order.
std::vector<std::string> served_agent_ids(const httplib::Response& res) {
    std::vector<std::string> ids;
    for (const auto& row : nlohmann::json::parse(res.body)["data"])
        ids.push_back(row["agent_id"].get<std::string>());
    return ids;
}

// One execution with a terminal row for each named agent (so each counts once in /agents).
void stats_exec_for(ExecV1Harness& h, std::initializer_list<const char*> agents) {
    Execution e;
    e.definition_id = "def-stats-scope";
    e.dispatched_by = "tester";
    e.status = "completed";
    e.dispatched_at = 1735689600;
    auto id = h.execution_tracker->create_execution(e);
    REQUIRE(id.has_value());
    for (const char* agent : agents) {
        AgentExecStatus a;
        a.agent_id = agent;
        a.status = "success";
        a.dispatched_at = 1735689600;
        a.completed_at = 1735689610;
        h.execution_tracker->update_agent_status(*id, a);
    }
}
} // namespace

TEST_CASE("GET /api/v1/execution-statistics/agents: an unconfined caller sees every agent a "
          "confined one sees exactly its visible set deny-all sees none (#3526)",
          "[pg][rest][executions][v1][statistics][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    stats_exec_for(h, {"agent-in", "agent-out", "agent-other"});

    auto sorted = [](std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    };

    // Unconfined (a global grant): the whole fleet's rows.
    auto all = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(all);
    CHECK(all->status == 200);
    CHECK(sorted(served_agent_ids(*all)) ==
          std::vector<std::string>{"agent-in", "agent-other", "agent-out"});

    // Confined to {agent-in}: exactly that agent, never the others.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
    auto confined = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(confined);
    CHECK(confined->status == 200);
    CHECK(served_agent_ids(*confined) == std::vector<std::string>{"agent-in"});
    CHECK(nlohmann::json::parse(confined->body)["pagination"]["total"] == 1);

    // Confined to two of three.
    h.fleet_read_scope =
        authz::VisibleSet{std::unordered_set<std::string>{"agent-in", "agent-other"}};
    auto two = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(two);
    CHECK(sorted(served_agent_ids(*two)) == std::vector<std::string>{"agent-in", "agent-other"});

    // Present-EMPTY is deny-all, never "no filter": a 200 with no rows, not the fleet.
    h.fleet_read_scope = authz::deny_all();
    auto none = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(none);
    CHECK(none->status == 200);
    CHECK(served_agent_ids(*none).empty());

    // Naming an out-of-scope agent explicitly yields the same empty answer.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
    auto named = h.sink.Get("/api/v1/execution-statistics/agents?agent_id=agent-out");
    REQUIRE(named);
    CHECK(named->status == 200);
    CHECK(served_agent_ids(*named).empty());
}

TEST_CASE("GET /api/v1/execution-statistics/agents: the visible set is applied BEFORE the limit "
          "(a confined caller is not handed a short or empty page)",
          "[pg][rest][executions][v1][statistics][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    // agent-busy has 3 completed rows, agent-quiet 1: unconfined `limit=1` ranks agent-busy first.
    stats_exec_for(h, {"agent-busy", "agent-quiet"});
    stats_exec_for(h, {"agent-busy"});
    stats_exec_for(h, {"agent-busy"});

    auto top = h.sink.Get("/api/v1/execution-statistics/agents?limit=1");
    REQUIRE(top);
    CHECK(served_agent_ids(*top) == std::vector<std::string>{"agent-busy"});

    // Confined to the lower-ranked agent: a post-fetch filter after LIMIT 1 would return nothing.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-quiet"}};
    auto confined = h.sink.Get("/api/v1/execution-statistics/agents?limit=1");
    REQUIRE(confined);
    CHECK(served_agent_ids(*confined) == std::vector<std::string>{"agent-quiet"});
}

// The route above is tested with a MOCKED fleet_read_fn. This drives the same route through
// the REAL AuthRoutes::require_fleet_read (production adapter shape, server.cpp), so the
// REST-admits-a-service-scoped-token-as-a-confined-view behaviour (#3526) is pinned at the
// route, not only at the gate (test_authz_gates.cpp pins the gate alone).
TEST_CASE("GET /api/v1/execution-statistics/agents through the REAL require_fleet_read: a "
          "service-scoped token sees exactly its service's agents a gate denial serves no agent "
          "a degraded tag store is a 503 (#3526)",
          "[pg][rest][executions][v1][statistics][security][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};

    Config cfg{};
    auth::AuthManager auth_mgr{};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    TagStore tags{pool};
    REQUIRE(tags.is_open());
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
    AuthRoutes ar(cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr, &mgmt, &tags,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    // Execution:Read is a GLOBAL grant for "minter"; a_p, a_c1 and a_s carry service=printers,
    // a_c2 does not. The service-scoped token must see exactly the first three, never a_c2.
    REQUIRE(rbac.create_role({"ExecReader", "", false, 0}).has_value());
    REQUIRE(rbac.set_permission({"ExecReader", "Execution", "Read", "allow"}).has_value());
    REQUIRE(rbac.assign_role({"user", "minter", "ExecReader"}).has_value());
    for (const char* a : {"a_p", "a_c1", "a_s"})
        REQUIRE(tags.set_tag(a, "service", "printers").has_value());

    auto adapter_for = [](AuthRoutes& routes) {
        return RestApiV1::FleetReadFn(
            [&routes](const httplib::Request& req, httplib::Response& res, const std::string& type,
                      const std::string& op) -> authz::FleetReadGate {
                auto result = routes.require_fleet_read(req, res, type, op);
                if (!result)
                    return {}; // admitted=false, res already written
                return {true, result->visible_for_query()};
            });
    };
    ExecV1Harness h(pool, /*wire_fleet_read=*/true, adapter_for(ar));
    stats_exec_for(h, {"a_p", "a_c1", "a_c2", "a_s"});

    auto mint = [&](const std::string& scope_service) {
        auto raw = api_tokens->create_token("exec-stats", "minter",
                                            std::chrono::duration_cast<std::chrono::seconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                    .count() +
                                                3600,
                                            scope_service);
        REQUIRE(raw.has_value());
        return std::unordered_map<std::string, std::string>{{"Authorization", "Bearer " + *raw}};
    };
    auto sorted_ids = [](const httplib::Response& r) {
        auto v = served_agent_ids(r);
        std::sort(v.begin(), v.end());
        return v;
    };

    // Non-service token with the global grant: AdmitAll, the whole fleet.
    auto all = h.sink.Get("/api/v1/execution-statistics/agents", mint(""));
    REQUIRE(all);
    CHECK(all->status == 200);
    CHECK(sorted_ids(*all) == std::vector<std::string>{"a_c1", "a_c2", "a_p", "a_s"});

    // Service-scoped token, same global grant: confined to the service's agents EXACTLY. The
    // service axis, not the minter's global grant, decides (never the unfiltered fleet).
    auto svc = h.sink.Get("/api/v1/execution-statistics/agents", mint("printers"));
    REQUIRE(svc);
    CHECK(svc->status == 200);
    CHECK(sorted_ids(*svc) == std::vector<std::string>{"a_c1", "a_p", "a_s"});

    // Naming an out-of-service agent explicitly still yields nothing for the service token.
    auto named = h.sink.Get("/api/v1/execution-statistics/agents?agent_id=a_c2", mint("printers"));
    REQUIRE(named);
    CHECK(named->status == 200);
    CHECK(served_agent_ids(*named).empty());

    // No bearer token at all: the gate answers 401 and serves no agent.
    auto anon = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(anon);
    CHECK(anon->status == 401);
    CHECK(anon->body.find("a_p") == std::string::npos);

    // RBAC grant revoked: the service token is denied, no agent served.
    REQUIRE(rbac.unassign_role("user", "minter", "ExecReader").has_value());
    auto revoked = h.sink.Get("/api/v1/execution-statistics/agents", mint("printers"));
    REQUIRE(revoked);
    CHECK(revoked->status == 403);
    CHECK(revoked->body.find("a_p") == std::string::npos);
    REQUIRE(rbac.assign_role({"user", "minter", "ExecReader"}).has_value());

    // A degraded tag store (here: none wired) on a service token is a 503, never an empty or
    // unfiltered 200.
    AuthRoutes ar_no_tags(cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr, &mgmt,
                          /*tag_store=*/nullptr, /*analytics_store=*/nullptr, oidc_mu,
                          oidc_provider);
    ExecV1Harness h2(pool, /*wire_fleet_read=*/true, adapter_for(ar_no_tags));
    auto degraded = h2.sink.Get("/api/v1/execution-statistics/agents", mint("printers"));
    REQUIRE(degraded);
    CHECK(degraded->status == 503);
    CHECK(degraded->body.find("a_p") == std::string::npos);
}

TEST_CASE("GET /api/v1/execution-statistics/agents: an unwired fleet_read_fn fails closed with a 503 "
          "not an exception (#3526)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool, /*wire_fleet_read=*/false);
    auto r = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(r->body.find("agent") == std::string::npos);
}

TEST_CASE("GET /api/v1/execution-statistics/definitions: a negative since is a 400 like /agents "
          "zero and omitted stay unbounded (#4644)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto neg = h.sink.Get("/api/v1/execution-statistics/definitions?since=-1");
    REQUIRE(neg);
    CHECK(neg->status == 400);
    CHECK(nlohmann::json::parse(neg->body)["error"]["message"] == "since must not be negative");
    for (const char* ok : {"?since=0", "", "?since=1700000000"}) {
        INFO(ok);
        auto r = h.sink.Get(std::string("/api/v1/execution-statistics/definitions") + ok);
        REQUIRE(r);
        CHECK(r->status == 200);
    }
}

TEST_CASE("GET /api/v1/execution-statistics/agents: a gate denial is a 403 and a negative since "
          "is a 400 (#3526 #4644)",
          "[pg][rest][executions][v1][statistics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    stats_exec_for(h, {"agent-in"});

    auto neg = h.sink.Get("/api/v1/execution-statistics/agents?since=-1");
    REQUIRE(neg);
    CHECK(neg->status == 400);
    auto zero = h.sink.Get("/api/v1/execution-statistics/agents?since=0");
    REQUIRE(zero);
    CHECK(zero->status == 200);

    h.perm_grant = false;
    auto denied = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(denied->body.find("agent-in") == std::string::npos);
}

// #4644: the statistics tracker reads used to answer a store degrade (pool timeout,
// failed statement) with an EMPTY or ZEROED value, so REST served 200 `[]` / an all-zero
// summary: "no executions" presented as a measurement. A degraded read is now a 503 with
// retry_after_ms; an HONEST empty scope (deny-all, no rows) is still a 200 `[]`.
TEST_CASE("execution-statistics routes: a degraded tracker read is a 503 and an honest empty is a 200",
          "[pg][rest][executions][v1][statistics][degrade]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    stats_exec_for(h, {"agent-in"});

    // Honest empty: a deny-all scope is a valid, successful, EMPTY answer.
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{}};
    auto honest = h.sink.Get("/api/v1/execution-statistics/agents");
    REQUIRE(honest);
    CHECK(honest->status == 200);
    CHECK(nlohmann::json::parse(honest->body)["data"].empty());
    h.fleet_read_scope = std::nullopt;

    // Degrade: hide the table every statistics query reads, over a side connection.
    exec_sql(db.dsn(), "ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_4644");
    std::vector<std::pair<std::string, int>> seen;
    for (const char* route : {"/api/v1/execution-statistics", "/api/v1/execution-statistics/agents",
                              "/api/v1/execution-statistics/definitions", "/api/v1/statistics"}) {
        auto res = h.sink.Get(route);
        REQUIRE(res);
        seen.emplace_back(route, res->status);
        if (res->status == 503) {
            auto body = nlohmann::json::parse(res->body);
            REQUIRE(body.contains("error"));
            CHECK(body["error"]["retry_after_ms"] == 2000);
        }
    }
    exec_sql(db.dsn(), "ALTER TABLE execution_tracker.executions_hidden_4644 RENAME TO executions");
    for (const auto& [route, status] : seen) {
        INFO(route);
        CHECK(status == 503);
    }
}
