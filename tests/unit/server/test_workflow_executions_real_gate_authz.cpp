/**
 * test_workflow_executions_real_gate_authz.cpp -- GET /api/v1/workflow-executions drives the REAL
 * AuthRoutes::require_fleet_read over a real Postgres RbacStore, ManagementGroupStore,
 * ApiTokenStore, TagStore and a real WorkflowEngine behind the real LocalWorkflowApi seam.
 *
 * The route's sole gate is require_fleet_read (ADR-0017); the scope it composes is applied in the
 * store's SQL before ORDER BY/LIMIT. Each case asserts the EXACT ordered id set served (and the
 * exact cursor walk), not just that a VisibleSet was handed over: a confinement test that only
 * observes the scope stays green while the predicate is deleted (docs/authz-model.md). Route-level
 * envelope, 400s and degrade against a fake gate: test_workflow_execution_list_routes.cpp.
 *
 * (Despite its name, test_workflow_executions_list_authz.cpp covers the /fragments/executions
 * instruction-execution list, a different data model.)
 */

#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "workflow_api_local.hpp"
#include "workflow_engine.hpp"
#include "workflow_execution_list_model.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

// RbacStore + WorkflowEngine + TagStore + AuditStore pre-migrated into one clone (the rig opens
// its ManagementGroup and ApiToken stores on their own template databases), so no case pays
// migration DDL.
yuzu::test::PgTestTemplate wf_real_gate_tpl{"wf_real_gate_list", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    WorkflowEngine engine{pool};
    TagStore tags{pool};
    AuditStore audit{pool};
    if (!rbac.is_open() || !engine.is_open() || !tags.is_open() || !audit.is_open())
        throw std::runtime_error("wf_real_gate_list template: a store failed to migrate");
}};

std::string wf_yaml(const std::string& name) {
    return "kind: Workflow\nmetadata:\n  displayName: " + name +
           "\nspec:\n  steps:\n    - instruction: inst-1\n";
}

struct Rig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    WorkflowEngine engine;
    TagStore tags;
    pg::PgPool audit_pool;
    AuditStore audit_store;
    std::unique_ptr<AuthRoutes> auth; // real stores + a TagStore: service-scoped tokens resolve
    std::shared_ptr<WorkflowApi> api;
    std::string dsn, wf1, wf2;

    explicit Rig(const std::string& dsn_in)
        : rig{dsn_in}, engine{rig.pool}, tags{rig.pool},
          audit_pool{{.conninfo = dsn_in, .size = 2}}, audit_store{audit_pool}, dsn{dsn_in} {
        REQUIRE(engine.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(audit_store.is_open());
        // gary: GLOBAL Workflow:Read. bob: Workflow:Read only through his management group.
        // dave: no Workflow grant at all.
        REQUIRE(rig.rbac.create_role({"WorkflowReaderList", "", false, 0}).has_value());
        REQUIRE(rig.rbac.set_permission({"WorkflowReaderList", "Workflow", "Read", "allow"}).has_value());
        REQUIRE(rig.rbac.assign_role({"user", "gary", "WorkflowReaderList"}).has_value());
        REQUIRE(rig.mgmt.assign_role({rig.bob_group, "user", "bob", "WorkflowReaderList"}).has_value());
        for (const char* u : {"gary", "dave"})
            REQUIRE(rig.auth_mgr.upsert_user(u, "correct-horse-battery-staple", auth::Role::user));
        REQUIRE(tags.set_tag("bob-agent", "service", "printers").has_value());
        REQUIRE(tags.set_tag("alice-agent", "service", "scanners").has_value());
        auth = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac, rig.api_tokens.get(),
                                            &audit_store, &rig.mgmt, &tags, nullptr, rig.oidc_mu,
                                            rig.oidc_provider);
        api = make_local_workflow_api(engine);
        wf1 = *engine.create_workflow(wf_yaml("list-one"));
        wf2 = *engine.create_workflow(wf_yaml("list-two"));
        seed();
    }

    void run(const std::string& id, const std::string& wf, int64_t at, const std::string& agents) {
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r = pg::exec_params(
            conn.get(),
            "INSERT INTO workflow_engine.workflow_executions (id, workflow_id, status, "
            "agent_ids_json, started_at, completed_at, current_step) "
            "VALUES ($1, $2, 'completed', $3, $4::bigint, $4::bigint, 0)",
            std::vector<std::string>{id, wf, agents, std::to_string(at)});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    // Newest first: wf2-alice(600) bad(500) none(400) alice(300) mixed(200) bob(100) wf2-bob(50).
    void seed() {
        run("r-bob", wf1, 100, R"(["bob-agent"])");
        run("r-mixed", wf1, 200, R"(["bob-agent","alice-agent"])");
        run("r-alice", wf1, 300, R"(["alice-agent"])");
        run("r-none", wf1, 400, "[]");
        run("r-bad", wf1, 500, "not json");
        run("r-wf2-alice", wf2, 600, R"(["alice-agent"])");
        run("r-wf2-bob", wf2, 50, R"(["bob-agent"])");
    }

    std::string mint(const std::string& user, const std::string& service = {}) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = rig.api_tokens->create_token("wf-list-authz", user, expires, service);
        REQUIRE(t.has_value());
        return *t;
    }

    struct Resp {
        int status{0};
        json body;
        std::vector<std::string> ids; // in served order
        json next_cursor;
    };
    Resp get(const std::string& token, const std::string& query = {}) {
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
        d.workflow_api = api;
        routes.register_routes(sink, std::move(d));
        std::unordered_map<std::string, std::string> hdrs;
        if (!token.empty())
            hdrs = {{"Authorization", "Bearer " + token}};
        auto res = sink.dispatch("GET", "/api/v1/workflow-executions" + query, {}, "application/json", hdrs);
        REQUIRE(res);
        Resp r;
        r.status = res->status;
        r.body = json::parse(res->body, nullptr, false);
        if (r.status == 200) {
            for (const auto& row : r.body["data"])
                r.ids.push_back(row["id"].get<std::string>());
            r.next_cursor = r.body["pagination"]["next_cursor"];
        }
        return r;
    }

    // Every page of a limit-1 walk, as the served ids in order.
    std::vector<std::string> walk(const std::string& token, const std::string& extra = {}) {
        std::vector<std::string> all;
        std::string cursor;
        for (int guard = 0; guard < 20; ++guard) {
            auto page = get(token, "?limit=1" + extra + (cursor.empty() ? "" : "&cursor=" + cursor));
            REQUIRE(page.status == 200);
            CHECK(page.ids.size() <= 1);
            all.insert(all.end(), page.ids.begin(), page.ids.end());
            if (page.next_cursor.is_null())
                break;
            // A cursor is derived from a row this caller was served, never from a hidden one.
            const auto pos = keyset::decode_cursor(kWorkflowExecutionCursorPrefix,
                                                   page.next_cursor.get<std::string>());
            REQUIRE(pos.has_value());
            CHECK(pos->id == page.ids.back());
            cursor = page.next_cursor.get<std::string>();
        }
        return all;
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
                out.push_back(row.result + "|" + row.detail);
        return out;
    }
};

using Ids = std::vector<std::string>;
const Ids kEverything{"r-wf2-alice", "r-bad", "r-none", "r-alice", "r-mixed", "r-bob", "r-wf2-bob"};
const Ids kBobVisible{"r-mixed", "r-bob", "r-wf2-bob"};

} // namespace

TEST_CASE("GET /api/v1/workflow-executions real gate: a global principal is unfiltered by design",
          "[pg][routes][workflow][executions][list][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    auto got = r.get(r.mint("gary"));
    CHECK(got.status == 200);
    // Includes the run whose agent_ids_json is malformed and the one with no agents: an
    // unconfined caller has no agent predicate to fail.
    CHECK(got.ids == kEverything);
    CHECK(r.walk(r.mint("gary")) == kEverything);
}

TEST_CASE("GET /api/v1/workflow-executions real gate: a group-scoped operator gets exactly its "
          "visible runs across a page walk",
          "[pg][routes][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    const auto token = r.mint("bob");
    auto got = r.get(token);
    CHECK(got.status == 200);
    CHECK(got.ids == kBobVisible);
    // The four NEWER runs bob cannot see (alice-only, empty, malformed, other workflow) neither
    // appear nor consume page slots: with limit=1 every page is a visible run, never empty.
    CHECK(r.walk(token) == kBobVisible);
    // total is the rows in the page, never a count that would reveal the hidden runs.
    CHECK(got.body["pagination"]["total"] == 3);
    // A malformed or empty-agents run is invisible to a confined caller (fail closed).
    for (const char* hidden : {"r-bad", "r-none", "r-alice", "r-wf2-alice"})
        CHECK(std::find(got.ids.begin(), got.ids.end(), hidden) == got.ids.end());
}

TEST_CASE("GET /api/v1/workflow-executions real gate: a forged cursor naming a hidden run reveals "
          "nothing",
          "[pg][routes][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    const auto token = r.mint("bob");
    // Positions of hidden runs, and one beyond everything: the scope is ANDed with the position,
    // so the answer is exactly bob's visible runs older than it.
    const std::vector<std::pair<std::string, int64_t>> bob_runs{
        {"r-mixed", 200}, {"r-bob", 100}, {"r-wf2-bob", 50}};
    for (const auto& pos : {keyset::Position{300, "r-alice"}, keyset::Position{500, "r-bad"},
                            keyset::Position{9999, "r-never-existed"}, keyset::Position{0, "x"}}) {
        const auto cursor = keyset::encode_cursor(kWorkflowExecutionCursorPrefix, pos);
        auto got = r.get(token, "?cursor=" + cursor);
        CHECK(got.status == 200);
        Ids expected;
        for (const auto& [id, at] : bob_runs)
            if (at < pos.key)
                expected.push_back(id);
        INFO("position " << pos.key << " " << pos.id);
        CHECK(got.ids == expected);
    }
}

TEST_CASE("GET /api/v1/workflow-executions real gate: latest_per_workflow is the newest VISIBLE run",
          "[pg][routes][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    // Ordered by workflow id (generated, so derive the order from the minted ids).
    const bool wf1_first = r.wf1 < r.wf2;
    const auto in_wf_order = [&](const std::string& a_wf1, const std::string& a_wf2) {
        return wf1_first ? Ids{a_wf1, a_wf2} : Ids{a_wf2, a_wf1};
    };
    CHECK(r.get(r.mint("gary"), "?latest_per_workflow=true").ids == in_wf_order("r-bad", "r-wf2-alice"));
    // bob: wf1's newest run is hidden, but its newest VISIBLE one is served (not a blanked newest),
    // and wf2's likewise.
    CHECK(r.get(r.mint("bob"), "?latest_per_workflow=true").ids == in_wf_order("r-mixed", "r-wf2-bob"));
    // A service token scoped to scanners (alice-agent): each workflow's newest run with alice-agent.
    CHECK(r.get(r.mint("gary", "scanners"), "?latest_per_workflow=true").ids ==
          in_wf_order("r-alice", "r-wf2-alice"));
}

TEST_CASE("GET /api/v1/workflow-executions real gate: a service-scoped token gets a narrowed view",
          "[pg][routes][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    // A GLOBAL principal's token narrowed to service "printers" (= {bob-agent}).
    auto g = r.get(r.mint("gary", "printers"));
    CHECK(g.status == 200);
    CHECK(g.ids == kBobVisible);
    CHECK(r.walk(r.mint("gary", "printers")) == kBobVisible);
    // "scanners" (= {alice-agent}).
    CHECK(r.get(r.mint("gary", "scanners")).ids == Ids{"r-wf2-alice", "r-alice", "r-mixed"});
    // bob's group scope {bob-agent} intersected with service "scanners" (= {alice-agent}) is empty:
    // nothing visible, and an empty page carries no cursor.
    auto b = r.get(r.mint("bob", "scanners"));
    CHECK(b.status == 200);
    CHECK(b.ids.empty());
    CHECK(b.next_cursor.is_null());
}

TEST_CASE("GET /api/v1/workflow-executions real gate: a principal with no Workflow:Read is refused "
          "and the gate audits it",
          "[pg][routes][workflow][executions][list][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    auto dave = r.get(r.mint("dave"));
    CHECK(dave.status == 403);
    CHECK(dave.ids.empty());
    const auto rows = r.audit("auth.fleet_read_required");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].rfind("denied|", 0) == 0);
    // Unauthenticated: the gate's 401, no row.
    CHECK(r.get("").status == 401);
    // A successful list writes no audit row of its own (metadata only).
    REQUIRE(r.get(r.mint("gary")).status == 200);
    CHECK(r.audit("workflow_execution.list").empty());
    CHECK(r.audit("workflow_execution.detail.fetch").empty());
    CHECK(r.audit("auth.fleet_read_required").size() == 1);
}

TEST_CASE("GET /api/v1/workflow-executions real gate: revoking Workflow:Read from ITServiceOwner "
          "refuses service tokens only",
          "[pg][routes][workflow][executions][list][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    const auto svc = r.mint("gary", "printers");
    CHECK(r.get(svc).status == 200); // control: seeded defaults admit
    REQUIRE(r.rig.rbac.remove_permission("ITServiceOwner", "Workflow", "Read").has_value());
    CHECK(r.get(svc).status == 403);
    CHECK(r.get(svc).ids.empty());
    // Non-service principals are unaffected: global gary unfiltered, group-scoped bob confined.
    CHECK(r.get(r.mint("gary")).ids == kEverything);
    CHECK(r.get(r.mint("bob")).ids == kBobVisible);
}

TEST_CASE("GET /api/v1/workflow-executions real gate: a degraded ceiling read is a 503 and serves "
          "no rows",
          "[pg][routes][workflow][executions][list][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    const auto svc = r.mint("gary", "printers");
    CHECK(r.get(svc).status == 200); // control
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult d{PQexec(conn.get(), "DROP TABLE rbac_store.role_permissions CASCADE")};
        REQUIRE(d.ok());
    }
    auto got = r.get(svc);
    CHECK(got.status == 503);
    CHECK(got.ids.empty());
    CHECK(got.body["error"]["retry_after_ms"].is_number());
}

TEST_CASE("GET /api/v1/workflow-executions real gate: with RBAC off every authenticated caller is "
          "unconfined and a service token is refused",
          "[pg][routes][workflow][executions][list][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, wf_real_gate_tpl);
    Rig r{db.dsn()};
    const auto bob = r.mint("bob");
    const auto dave = r.mint("dave");
    const auto svc = r.mint("gary", "printers");
    // Control (RBAC on): bob confined, dave refused.
    CHECK(r.get(bob).ids == kBobVisible);
    CHECK(r.get(dave).status == 403);

    r.rig.rbac.set_rbac_enabled(false);
    for (const auto& token : {bob, dave, r.mint("gary")}) {
        auto got = r.get(token);
        CHECK(got.status == 200);
        CHECK(got.ids == kEverything);
    }
    CHECK(r.get(svc).status == 403); // a service token requires RBAC to be enabled
}
