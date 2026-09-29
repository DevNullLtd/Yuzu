/**
 * test_workflow_api.cpp — the EIGHTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4). `LocalWorkflowApi`
 * (workflow_api.cpp) is a thin wrap of `WorkflowEngine::list_workflows`/
 * `get_workflow`/`get_execution` — each method's own behaviour is already
 * covered by `test_workflow_engine.cpp`, so this file proves only the
 * WIRING: that the seam forwards each call unmodified and returns the
 * engine's result unmodified, through the public `WorkflowApi` interface —
 * the class itself (`LocalWorkflowApi`) is deliberately private to
 * workflow_api.cpp, so this file uses only `make_local_workflow_api`,
 * matching how a real presentation/MCP caller will use it.
 */

#include "workflow_api_local.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_workflow_engine_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

using yuzu::server::make_local_workflow_api;
using yuzu::server::Workflow;
using yuzu::server::WorkflowEngine;
using yuzu::server::WorkflowQuery;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::test::WorkflowEnginePg;

TEST_CASE("WorkflowApi::list_workflows: forwards an empty query and returns an honest-empty result",
          "[pg][workflow_api]") {
    WorkflowEnginePg fx;
    auto api = make_local_workflow_api(*fx.get());

    auto result = api->list_workflows(WorkflowQuery{});
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("WorkflowApi::list_workflows: name_filter reaches the store unmodified",
          "[pg][workflow_api]") {
    WorkflowEnginePg fx;
    auto api = make_local_workflow_api(*fx.get());

    const std::string yaml_a = "kind: Workflow\n"
                              "metadata:\n"
                              "  displayName: match-me\n"
                              "spec:\n"
                              "  steps:\n"
                              "    - instruction: inst-1\n";
    const std::string yaml_b = "kind: Workflow\n"
                              "metadata:\n"
                              "  displayName: other\n"
                              "spec:\n"
                              "  steps:\n"
                              "    - instruction: inst-1\n";
    REQUIRE(fx->create_workflow(yaml_a).has_value());
    REQUIRE(fx->create_workflow(yaml_b).has_value());

    WorkflowQuery q;
    q.name_filter = "match-me";
    auto result = api->list_workflows(q);
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 1);
    CHECK(result->at(0).name == "match-me");
}

TEST_CASE("WorkflowApi::get_workflow: forwards a found id and an honest not-found the same as the "
          "engine",
          "[pg][workflow_api]") {
    WorkflowEnginePg fx;
    auto api = make_local_workflow_api(*fx.get());

    auto created = fx->create_workflow("kind: Workflow\n"
                                      "metadata:\n"
                                      "  displayName: wf-one\n"
                                      "spec:\n"
                                      "  steps:\n"
                                      "    - instruction: inst-1\n");
    REQUIRE(created.has_value());

    auto found = api->get_workflow(*created);
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->name == "wf-one");

    auto missing = api->get_workflow("does-not-exist");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());
}

TEST_CASE("WorkflowApi::get_workflow_execution: forwards get_execution unmodified, including an "
          "honest not-found",
          "[pg][workflow_api]") {
    WorkflowEnginePg fx;
    auto api = make_local_workflow_api(*fx.get());

    auto missing = api->get_workflow_execution("does-not-exist");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->has_value());
}

// Mirrors test_workflow_engine.cpp's degrade case: a reachable database whose
// schema migration FAILS leaves the engine `!is_open()`. `LocalWorkflowApi`'s
// three methods are thin wraps of the checked engine calls — this proves the
// seam forwards that AUTHORITATIVE degrade unmodified (not swallowed into a
// false empty/not-found result), which is what the REST v1/MCP degraded-path
// tests all depend on.
TEST_CASE("WorkflowApi: an unopened engine answers the AUTHORITATIVE degrade on every method",
          "[pg][workflow_api]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA workflow_engine")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE workflow_engine.bogus (x int)")};
        REQUIRE(t.ok());
    }

    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    WorkflowEngine engine{pool};
    REQUIRE_FALSE(engine.is_open());
    auto api = make_local_workflow_api(engine);

    auto list_result = api->list_workflows(WorkflowQuery{});
    REQUIRE_FALSE(list_result.has_value());
    CHECK(list_result.error().find("workflow engine not available") != std::string::npos);

    auto get_result = api->get_workflow("any-id");
    REQUIRE_FALSE(get_result.has_value());
    CHECK(get_result.error().find("workflow engine not available") != std::string::npos);

    auto exec_result = api->get_workflow_execution("any-id");
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().find("workflow engine not available") != std::string::npos);
}
