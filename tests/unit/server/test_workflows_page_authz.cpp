/**
 * test_workflows_page_authz.cpp -- the Workflows page fragments drive the REAL
 * AuthRoutes::require_fleet_read / require_permission over a real Postgres RbacStore,
 * ManagementGroupStore, ApiTokenStore, TagStore and a real WorkflowEngine behind the real
 * LocalWorkflowApi seam.
 *
 * What a fake gate cannot prove is asserted here with exact id sets and exact bytes: which
 * runs each caller is served, that a hidden run and an unknown id answer identically, that a
 * confined caller's run detail carries no reach count and no out-of-scope agent id, and that
 * the definitions fragment keeps its own (perm_fn) gate. Route contracts against fake gates:
 * test_workflows_page_routes.cpp.
 */

#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "workflow_api_local.hpp"
#include "workflow_engine.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

yuzu::test::PgTestTemplate wf_page_tpl{"wf_page_authz", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    WorkflowEngine engine{pool};
    TagStore tags{pool};
    AuditStore audit{pool};
    if (!rbac.is_open() || !engine.is_open() || !tags.is_open() || !audit.is_open())
        throw std::runtime_error("wf_page_authz template: a store failed to migrate");
}};

std::string wf_yaml(const std::string& name) {
    return "kind: Workflow\nmetadata:\n  displayName: " + name +
           "\nspec:\n  steps:\n    - instruction: inst-1\n";
}

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

struct Rig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    WorkflowEngine engine;
    TagStore tags;
    pg::PgPool audit_pool;
    AuditStore audit_store;
    std::unique_ptr<AuthRoutes> auth;
    std::shared_ptr<WorkflowApi> api;
    std::string dsn, wf;

    explicit Rig(const std::string& dsn_in)
        : rig{dsn_in}, engine{rig.pool}, tags{rig.pool},
          audit_pool{{.conninfo = dsn_in, .size = 2}}, audit_store{audit_pool}, dsn{dsn_in} {
        REQUIRE(engine.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(audit_store.is_open());
        // gary: GLOBAL Workflow:Read. bob: Workflow:Read only through his management group.
        // erin: GLOBAL Workflow:Read and nothing else (no InstructionDefinition:Read).
        // dave: no Workflow grant at all.
        REQUIRE(rig.rbac.create_role({"WorkflowReaderPage", "", false, 0}).has_value());
        REQUIRE(rig.rbac.set_permission({"WorkflowReaderPage", "Workflow", "Read", "allow"}).has_value());
        REQUIRE(rig.rbac.assign_role({"user", "gary", "WorkflowReaderPage"}).has_value());
        REQUIRE(rig.rbac.assign_role({"user", "erin", "WorkflowReaderPage"}).has_value());
        REQUIRE(rig.mgmt.assign_role({rig.bob_group, "user", "bob", "WorkflowReaderPage"}).has_value());
        for (const char* u : {"gary", "dave", "erin"})
            REQUIRE(rig.auth_mgr.upsert_user(u, "correct-horse-battery-staple", auth::Role::user));
        REQUIRE(tags.set_tag("bob-agent", "service", "printers").has_value());
        REQUIRE(tags.set_tag("alice-agent", "service", "scanners").has_value());
        auth = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac, rig.api_tokens.get(),
                                            &audit_store, &rig.mgmt, &tags, nullptr, rig.oidc_mu,
                                            rig.oidc_provider);
        api = make_local_workflow_api(engine);
        wf = *engine.create_workflow(wf_yaml("page-wf"));
        run("r-bob", 100, R"(["bob-agent"])");
        run("r-mixed", 200, R"(["bob-agent","alice-agent-secret"])");
        run("r-alice", 300, R"(["alice-agent-secret"])");
    }

    void exec_sql(const std::string& sql, std::vector<std::string> p) {
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r = pg::exec_params(conn.get(), sql.c_str(), p);
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    void run(const std::string& id, int64_t at, const std::string& agents) {
        exec_sql("INSERT INTO workflow_engine.workflow_executions (id, workflow_id, status, "
                 "agent_ids_json, started_at, completed_at, current_step) "
                 "VALUES ($1, $2, 'completed', $3, $4::bigint, $4::bigint + 30, 0)",
                 {id, wf, agents, std::to_string(at)});
        exec_sql("INSERT INTO workflow_engine.workflow_step_results (execution_id, step_index, "
                 "instruction_id, status, result_json, started_at, completed_at) "
                 "VALUES ($1, 0, 'inst-1', 'success', "
                 "'{\"status\":\"dispatched\",\"agents_reached\":7}', $2::bigint, $2::bigint + 5)",
                 {id, std::to_string(at)});
    }

    std::string mint(const std::string& user, const std::string& service = {}) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = rig.api_tokens->create_token("wf-page-authz", user, expires, service);
        REQUIRE(t.has_value());
        return *t;
    }

    std::unique_ptr<httplib::Response> get(const std::string& token, const std::string& target) {
        yuzu::server::test::TestRouteSink sink;
        WorkflowRoutes routes;
        WorkflowRoutes::Deps d;
        d.fleet_read_fn = [this](const httplib::Request& req, httplib::Response& res,
                                 const std::string& t,
                                 const std::string& o) -> authz::FleetReadGate {
            auto result = auth->require_fleet_read(req, res, t, o);
            if (!result)
                return {};
            return {true, result->visible_for_query()};
        };
        d.perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                           const std::string& t, const std::string& o) {
            return auth->require_permission(req, res, t, o);
        };
        d.audit_fn = [this](const httplib::Request& req, const std::string& action,
                            const std::string& result, const std::string& target_type,
                            const std::string& target_id, const std::string& detail) {
            AuditEvent e;
            e.principal = "test";
            e.action = action;
            e.result = result;
            e.target_type = target_type;
            e.target_id = target_id;
            e.detail = detail;
            (void)req;
            (void)audit_store.log(e);
        };
        d.workflow_api = api;
        routes.register_routes(sink, std::move(d));
        std::unordered_map<std::string, std::string> hdrs;
        if (!token.empty())
            hdrs = {{"Authorization", "Bearer " + token}};
        auto res = sink.dispatch("GET", target, {}, "text/html", hdrs);
        REQUIRE(res);
        return res;
    }

    // The run ids (data-run-id) a runs fragment served, in order.
    static std::vector<std::string> run_ids(const std::string& html) {
        std::vector<std::string> out;
        static const std::regex re(R"re(data-run-id="([^"]*)")re");
        for (std::sregex_iterator it(html.begin(), html.end(), re), end; it != end; ++it)
            out.push_back((*it)[1].str());
        return out;
    }

    std::vector<std::string> audit(const std::string& action) {
        std::vector<std::string> out;
        AuditQuery q;
        q.action = action;
        q.limit = 1000;
        auto rows = audit_store.query(q);
        REQUIRE(rows.has_value());
        for (const auto& row : *rows)
            if (row.action == action)
                out.push_back(row.result + "|" + row.target_id);
        return out;
    }
};

using Ids = std::vector<std::string>;

} // namespace

TEST_CASE("workflows page real gate: a global reader sees every run and its reach count",
          "[pg][workflow][workflows][page][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    auto list = r.get(r.mint("gary"), "/fragments/workflow-runs?workflow_id=" + r.wf);
    CHECK(list->status == 200);
    CHECK(Rig::run_ids(list->body) == Ids{"r-alice", "r-mixed", "r-bob"});
    CHECK(has(list->body, "data-confined=\"0\""));
    auto det = r.get(r.mint("gary"), "/fragments/workflow-runs/r-mixed");
    CHECK(det->status == 200);
    CHECK(has(det->body, "Reached 7 devices"));
    const auto rows = r.audit("workflow_execution.detail.fetch");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "success|r-mixed");
}

TEST_CASE("workflows page real gate: a group-scoped reader sees its runs and nothing of the others",
          "[pg][workflow][workflows][page][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    const auto bob = r.mint("bob");
    auto list = r.get(bob, "/fragments/workflow-runs?latest_per_workflow=true&limit=500");
    CHECK(list->status == 200);
    CHECK(Rig::run_ids(list->body) == Ids{"r-mixed"}); // the newest run bob may SEE
    CHECK(has(list->body, "data-confined=\"1\""));

    auto mixed = r.get(bob, "/fragments/workflow-runs/r-mixed");
    CHECK(mixed->status == 200);
    CHECK_FALSE(has(mixed->body, "alice-agent-secret"));
    CHECK_FALSE(has(mixed->body, "Reached"));
    CHECK_FALSE(has(mixed->body, "7 devices"));
    CHECK(has(mixed->body, "Dispatched (run-wide)"));
    CHECK(has(mixed->body, "Devices in your scope"));

    // Hidden and unknown: identical status and bytes; only the hidden one is audited, as denied.
    auto hidden = r.get(bob, "/fragments/workflow-runs/r-alice");
    auto unknown = r.get(bob, "/fragments/workflow-runs/r-nope");
    CHECK(hidden->status == 404);
    CHECK(unknown->status == 404);
    CHECK(hidden->body == unknown->body);
    const auto rows = r.audit("workflow_execution.detail.fetch");
    CHECK(std::find(rows.begin(), rows.end(), "denied|r-alice") != rows.end());
    CHECK(std::find(rows.begin(), rows.end(), "denied|r-nope") == rows.end());
}

TEST_CASE("workflows page real gate: a service-scoped token is narrowed on runs and refused definitions",
          "[pg][workflow][workflows][page][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    const auto svc = r.mint("gary", "printers"); // {bob-agent}
    auto list = r.get(svc, "/fragments/workflow-runs?workflow_id=" + r.wf);
    CHECK(list->status == 200);
    CHECK(Rig::run_ids(list->body) == Ids{"r-mixed", "r-bob"});
    // The definitions fragment keeps its own perm_fn gate: a service-scoped token is refused.
    auto defs = r.get(svc, "/fragments/workflows");
    CHECK(defs->status == 200);
    CHECK(has(defs->body, "data-denied=\"true\""));
}

TEST_CASE("workflows page real gate: no Workflow:Read is a denied note on every fragment",
          "[pg][workflow][workflows][page][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    const auto dave = r.mint("dave");
    for (const char* target :
         {"/fragments/workflows", "/fragments/workflow-runs", "/fragments/workflow-runs/r-bob"}) {
        auto res = r.get(dave, target);
        INFO(target);
        CHECK(res->status == 200);
        CHECK(has(res->body, "data-denied=\"true\""));
        CHECK_FALSE(has(res->body, "r-bob"));
    }
    CHECK(r.audit("workflow_execution.detail.fetch").empty());
}

TEST_CASE("workflows page real gate: definitions need the global grant, runs follow the fleet scope",
          "[pg][workflow][workflows][page][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    // erin holds Workflow:Read only: definitions render with ids and labels, no instruction name.
    auto erin = r.get(r.mint("erin"), "/fragments/workflows");
    CHECK(erin->status == 200);
    CHECK(has(erin->body, "data-workflow-id=\"" + r.wf + "\""));
    CHECK(has(erin->body, "inst-1"));
    // bob holds it only through a management group: the definitions gate refuses him.
    auto bob = r.get(r.mint("bob"), "/fragments/workflows");
    CHECK(bob->status == 200);
    CHECK(has(bob->body, "data-denied=\"true\""));
}

TEST_CASE("workflows page real gate: with RBAC off an authenticated caller is unconfined",
          "[pg][workflow][workflows][page][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_page_tpl);
    Rig r{db.dsn()};
    const auto bob = r.mint("bob");
    const auto svc = r.mint("gary", "printers");
    r.rig.rbac.set_rbac_enabled(false);
    auto list = r.get(bob, "/fragments/workflow-runs?workflow_id=" + r.wf);
    CHECK(Rig::run_ids(list->body) == Ids{"r-alice", "r-mixed", "r-bob"});
    // A service-scoped token requires RBAC to be enabled: refused.
    auto refused = r.get(svc, "/fragments/workflow-runs");
    CHECK(refused->status == 200);
    CHECK(has(refused->body, "data-denied=\"true\""));
}
