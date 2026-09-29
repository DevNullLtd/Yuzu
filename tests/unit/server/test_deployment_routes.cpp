/**
 * test_deployment_routes.cpp — SEC-2/SEC-3 confinement-gap class coverage for
 * DeploymentRoutes. DeploymentRoutes previously had no route-handler test
 * coverage at all (only DeploymentRunStore/deployment_engine had unit tests).
 *
 * GET /fragments/auto/deploy, GET /fragments/auto/deploy/result, and POST
 * /fragments/auto/deploy/delete all scope by session->username alone —
 * ApiToken::principal_id ("the username... who created it") means a
 * service-scoped token shares its creating principal's username, so a token
 * scoped to e.g. one IT service could otherwise read/advance/delete a
 * fleet-wide deployment its own principal created interactively. Denied the
 * same way as the sibling PreflightRoutes fix in this branch.
 *
 * POST /fragments/auto/deploy/run (the mutating create+first-dispatch route)
 * had no deny at all until external review (PR #3156) caught it - this file
 * previously left it deliberately uncovered pending a review of the
 * guarded-transition contract; that review found the missing deny, not a
 * conflict with it, so it is now fixed and covered below alongside its
 * siblings.
 */

#include "deployment_routes.hpp"
#include "deployment_run_store.hpp"
#include "preflight_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate deprun_routes_tpl{"deprun", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DeploymentRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("deprun template: store failed to migrate");
}};

yuzu::test::PgTestTemplate preflight_routes_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, const std::string& owner, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = owner;
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000;
    r.status = "running";
    return r;
}

DeploymentRow make_dep(const std::string& id, const std::string& run_id, const std::string& owner,
                       std::int64_t created) {
    DeploymentRow d;
    d.deployment_id = id;
    d.source_run_id = run_id;
    d.created_by = owner;
    d.name = "test " + id;
    d.artifact_url = "https://repo.lan/pkg.msi";
    d.artifact_filename = "pkg.msi";
    d.artifact_sha256 = std::string(64, 'a');
    d.exec_args = "/qn";
    d.status = "running";
    d.created_at_ms = created;
    return d;
}

preflight::PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

} // namespace

// SEC-2/SEC-3 confinement-gap class (found via Gate 6 hardening re-check,
// the same "owner-scoped by username" sub-pattern as PreflightRoutes): a
// service-scoped token sharing its creating principal's username could
// otherwise read the deploy config form, poll/advance an in-flight
// deployment, or delete a deployment — all outside its own service.
TEST_CASE("deployment routes: config/result/delete deny a service-scoped "
          "token sharing the creator's username, nothing leaked or mutated",
          "[pg][deployment][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(depdb, deprun_routes_tpl);
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool dep_pool{{.conninfo = depdb.dsn(), .size = 4}};
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    DeploymentRunStore deploy_store(dep_pool);
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(deploy_store.is_open());
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-confinement-1";
    auto run = make_run(run_id, "alice", t);
    run.go = 1;
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    const std::string dep_id = "dep-confinement-1";
    auto dep = make_dep(dep_id, run_id, "alice", t);
    REQUIRE(deploy_store.create_deployment(dep, {tgt("agent-1")}));

    // The SAME principal ("alice") now authenticates with a service-scoped
    // token — mirrors ApiToken::principal_id sharing the creator's username.
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    // Deliberately WIRED to authorize "agent-1" (the deployment's only device,
    // still in step="pending") — if the deny were bypassed, advance() would
    // claim + dispatch it (deployment_engine.cpp's CAS-claim-and-stage step).
    // An unwired/empty devices_fn would make dispatched==0 vacuously true
    // regardless of the fix (the device is SKIPPED, not dispatched, when
    // unauthorized) — gov QE review already caught this exact trap once in
    // this branch (PreflightRoutes' deny test).
    auto devices = [](const std::string&) {
        DeviceRow d;
        d.agent_id = "agent-1";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&,
                                  const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    auto poll = [](const std::string&) { return std::unordered_map<std::string, deployment::AgentResponse>{}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, devices, dispatch, poll, audit,
                           &preflight_store, &deploy_store);

    auto cfg = sink.Get("/fragments/auto/deploy?run=" + run_id);
    REQUIRE(cfg);
    CHECK(cfg->status == 403);
    CHECK(cfg->body.find(run.name) == std::string::npos);

    auto result = sink.Get("/fragments/auto/deploy/result?dep=" + dep_id);
    REQUIRE(result);
    CHECK(result->status == 403);
    CHECK(result->body.find(dep.artifact_filename) == std::string::npos);
    CHECK(dispatched == 0); // the mutating advance() tick never ran

    auto del = sink.Post("/fragments/auto/deploy/delete?dep=" + dep_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status == 403);
    // The deployment survives — the deny fires before delete_deployment.
    REQUIRE(deploy_store.get_deployment(dep_id, "alice").has_value());
    // Gate 8 (#2298 PR 3 hardening round, supersedes the prior GC-7 fix
    // this test pinned): `.permission` is now omitted entirely, not
    // renamed to the "correct" grant — `kServiceScopeGlobalSafe` is
    // compile-time-empty, so no grant, correctly-named or not, actually
    // admits a service-scoped caller here (routed-concern MUST clause 5).
    auto del_body = nlohmann::json::parse(del->body, nullptr, false);
    REQUIRE_FALSE(del_body.is_discarded());
    CHECK_FALSE(del_body["error"].contains("permission"));

    // Important finding from external review (PR #3156): the create route
    // itself - the first fleet-wide dispatch, not just the config/poll/
    // delete siblings above - had no deny at all until this fix.
    auto create = sink.Post("/fragments/auto/deploy/run?run=" + run_id, "",
                            "application/x-www-form-urlencoded");
    REQUIRE(create);
    CHECK(create->status == 403);
    CHECK(dispatched == 0); // still zero - create never reached advance() either
    auto create_body = nlohmann::json::parse(create->body, nullptr, false);
    REQUIRE_FALSE(create_body.is_discarded());
    CHECK_FALSE(create_body["error"].contains("permission"));
    // No second deployment was created for this run - the run's only
    // running deployment is still the pre-existing fixture, unchanged.
    auto still_running = deploy_store.find_running_for_run(run_id, "alice");
    REQUIRE(still_running.has_value());
    CHECK(*still_running == dep_id);

    REQUIRE(audit_log.size() == 4);
    CHECK(audit_log[0] == "deployment.config.view|denied");
    CHECK(audit_log[1] == "deployment.advance|denied");
    CHECK(audit_log[2] == "deployment.delete|denied");
    CHECK(audit_log[3] == "deployment.create|denied");
}

TEST_CASE("deployment routes: ordinary session reaches config/result/delete, "
          "audited success",
          "[pg][deployment][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(depdb, deprun_routes_tpl);
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool dep_pool{{.conninfo = depdb.dsn(), .size = 4}};
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    DeploymentRunStore deploy_store(dep_pool);
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(deploy_store.is_open());
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-ordinary-1";
    auto run = make_run(run_id, "alice", t);
    run.go = 1;
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    const std::string dep_id = "dep-ordinary-1";
    auto dep = make_dep(dep_id, run_id, "alice", t);
    REQUIRE(deploy_store.create_deployment(dep, {tgt("agent-1")}));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto devices = [](const std::string&) { return std::vector<DeviceRow>{}; };
    auto dispatch = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&,
                       const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
        return {.sent = 1, .command_id = "cmd-1"};
    };
    auto poll = [](const std::string&) { return std::unordered_map<std::string, deployment::AgentResponse>{}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, dispatch, poll, audit, &preflight_store,
                           &deploy_store);

    auto cfg = sink.Get("/fragments/auto/deploy?run=" + run_id);
    REQUIRE(cfg);
    CHECK(cfg->status != 403);
    CHECK(cfg->body.find(run.name) != std::string::npos);

    auto result = sink.Get("/fragments/auto/deploy/result?dep=" + dep_id);
    REQUIRE(result);
    CHECK(result->status != 403);

    auto del = sink.Post("/fragments/auto/deploy/delete?dep=" + dep_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status != 403);
    CHECK_FALSE(deploy_store.get_deployment(dep_id, "alice").has_value());

    for (const auto& a : audit_log)
        CHECK(a.find("|denied") == std::string::npos);
}

// #4036 (api-parity Batch A) — GET /api/v1/deployments/preview REST twin.

TEST_CASE("deployment routes: GET /api/v1/deployments/preview is owner-scoped "
          "and shares deploy_preview_json with the MCP twin's builder",
          "[pg][deployment][routes][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-preview-1";
    auto run = make_run(run_id, "alice", t);
    run.go = 4;
    run.warn = 2;
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));
    REQUIRE(preflight_store.persist_grid(run_id, {}, /*total=*/6, /*go=*/4, /*warn=*/2,
                                         /*nogo=*/0, /*inc=*/0));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*dispatch_fn=*/{},
                           /*poll_fn=*/{}, /*audit_fn=*/{}, &preflight_store,
                           /*deploy_store=*/nullptr);

    auto res = sink.Get("/api/v1/deployments/preview?run=" + run_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["api_version"] == "v1");
    CHECK(body["data"]["run_id"] == run_id);
    CHECK(body["data"]["name"] == run.name);
    CHECK(body["data"]["go"] == 4);
    CHECK(body["data"]["warn"] == 2);

    // Missing run param -> 400.
    auto missing = sink.Get("/api/v1/deployments/preview");
    REQUIRE(missing);
    CHECK(missing->status == 400);

    // A genuinely nonexistent run -> 404.
    auto other = sink.Get("/api/v1/deployments/preview?run=does-not-exist");
    REQUIRE(other);
    CHECK(other->status == 404);

    // A run that EXISTS but belongs to someone else -> the SAME 404, not
    // distinguishable from not-found (no existence oracle) — the fragment's
    // own posture. This is the case the "does-not-exist" id above cannot
    // prove: a real row, owned by bob, requested by alice's session.
    auto bob_run_id = std::string("run-preview-bob-1");
    auto bob_run = make_run(bob_run_id, "bob", t);
    REQUIRE(preflight_store.create_run(bob_run, {{"agent-2", "host-2", "linux"}}));
    auto not_yours = sink.Get("/api/v1/deployments/preview?run=" + bob_run_id);
    REQUIRE(not_yours);
    CHECK(not_yours->status == 404);
    CHECK(not_yours->body.find(bob_run_id) == std::string::npos);
}

TEST_CASE("deployment routes: GET /api/v1/deployments/preview denies a "
          "service-scoped token sharing the run creator's username, audited "
          "under deployment.config.view (not deployment.create)",
          "[pg][deployment][routes][rest][security]") {
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-preview-svc-1";
    auto run = make_run(run_id, "alice", t);
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, /*devices_fn=*/{}, /*dispatch_fn=*/{},
                           /*poll_fn=*/{}, audit, &preflight_store, /*deploy_store=*/nullptr);

    auto res = sink.Get("/api/v1/deployments/preview?run=" + run_id);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find(run_id) == std::string::npos);
    REQUIRE(audit_log.size() == 1);
    CHECK(audit_log[0] == "deployment.config.view|denied");
}

TEST_CASE("deployment routes: GET /api/v1/deployments/preview 503s (not 404) "
          "when the pre-flight store's connection pool is exhausted, "
          "#4036 hardening round",
          "[pg][deployment][routes][rest]") {
    // A store-level fault must not read as "not found" — get_run's plain
    // accessor collapsed a pool-acquire timeout into the same nullopt as a
    // genuine miss/not-yours; get_run_checked distinguishes them, and this
    // route must surface the distinction as 503, matching rest-api.md's
    // published "Pre-flight run store unavailable → 503" contract for this
    // route (previously only true for the unwired-pointer case).
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    // A pool of exactly one, whose sole connection this test holds for the
    // duration — same recipe as test_api_token_store.cpp's "an EXHAUSTED
    // connection pool is kUnavailable, not kInvalid".
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 1}};
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-preview-starved-1";
    auto run = make_run(run_id, "alice", t);
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*dispatch_fn=*/{},
                           /*poll_fn=*/{}, /*audit_fn=*/{}, &preflight_store,
                           /*deploy_store=*/nullptr);

    // Hold the pool's only connection with a longer timeout than the store's
    // own kReadTimeout (2s), so the route's internal acquire is the one that
    // times out first.
    auto hog = pre_pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // we now hold the only connection

    auto res = sink.Get("/api/v1/deployments/preview?run=" + run_id);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find(run_id) == std::string::npos);
    // #2146 Batch A retry-hint audit: this genuine store-fault (not the
    // unwired-pointer case in the sibling TEST_CASE below) must carry a
    // retry hint matching the MCP twin's own kMcpStoreFaultShortRetryMs
    // (2000ms) — see mcp_server.cpp's get_deployment_preview handler and
    // mcp_retry.hpp.
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["error"].contains("retry_after_ms"));
    CHECK(body["error"]["retry_after_ms"].get<int>() == 2000);
}

TEST_CASE("deployment routes: GET /api/v1/deployments/preview 503s when the "
          "pre-flight store is unwired",
          "[deployment][routes][rest]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, /*devices_fn=*/{}, /*dispatch_fn=*/{},
                           /*poll_fn=*/{}, /*audit_fn=*/{}, /*preflight_store=*/nullptr,
                           /*deploy_store=*/nullptr);

    auto res = sink.Get("/api/v1/deployments/preview?run=whatever");
    REQUIRE(res);
    CHECK(res->status == 503);
}
