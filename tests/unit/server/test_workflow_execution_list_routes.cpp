/**
 * test_workflow_execution_list_routes.cpp -- GET /api/v1/workflow-executions through
 * TestRouteSink with a fake fleet-read gate and an FnWorkflowApi double. No database: what is
 * proved here is the route's own contract (gate first, strict 400s, envelope, degrade, what it
 * hands the seam). That the seam's store really applies the scope, and that the REAL gate yields
 * the right id set, are test_workflow_engine.cpp and
 * test_workflow_executions_real_gate_authz.cpp.
 */

#include "store_errors.hpp"
#include "test_route_sink.hpp"
#include "test_workflow_api_double.hpp"
#include "workflow_execution_list_model.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

struct Fx {
    // Seam capture: what the route actually handed the store-facing API.
    int api_calls{0};
    WorkflowExecutionListQuery seen_query;
    authz::VisibleSet seen_scope;
    std::expected<WorkflowExecutionPage, std::string> api_result{WorkflowExecutionPage{}};

    // Fake gate (the real one is exercised in the [pg] authz test).
    int gate_calls{0};
    std::string gate_type, gate_op;
    bool gate_admits{true};
    authz::VisibleSet gate_scope; // nullopt = unfiltered
    int audit_calls{0};
    bool wire_gate{true};
    bool wire_api{true};

    WorkflowRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared AFTER the route owner (see the sink header)

    explicit Fx(bool with_gate = true, bool with_api = true) : wire_gate(with_gate), wire_api(with_api) {
        WorkflowRoutes::Deps d;
        if (wire_gate)
            d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const std::string& type,
                                     const std::string& op) -> authz::FleetReadGate {
                ++gate_calls;
                gate_type = type;
                gate_op = op;
                if (!gate_admits) {
                    res.status = 403;
                    return {false, authz::deny_all()};
                }
                return {true, gate_scope};
            };
        d.audit_fn = [this](const httplib::Request&, const std::string&, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
            ++audit_calls;
        };
        if (wire_api)
            d.workflow_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
                yuzu::server::test::FnWorkflowApi::ListFn{},
                yuzu::server::test::FnWorkflowApi::GetFn{},
                yuzu::server::test::FnWorkflowApi::GetExecutionFn{},
                [this](const WorkflowExecutionListQuery& q, const authz::VisibleSet& scope) {
                    ++api_calls;
                    seen_query = q;
                    seen_scope = scope;
                    return api_result;
                });
        routes.register_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& target) {
        auto res = sink.Get(target);
        REQUIRE(res);
        return res;
    }
};

WorkflowExecutionSummary run(const std::string& id, int64_t at, const std::string& status = "completed") {
    WorkflowExecutionSummary s;
    s.id = id;
    s.workflow_id = "wf-1";
    s.workflow_name = "Patch Tuesday";
    s.status = status;
    s.current_step = 2;
    s.started_at = at;
    s.completed_at = at + 5;
    return s;
}

} // namespace

TEST_CASE("GET /api/v1/workflow-executions: envelope rows and defaults",
          "[workflow][executions][list][rest]") {
    Fx fx;
    fx.api_result = WorkflowExecutionPage{{run("r2", 200), run("r1", 100)}, std::nullopt, false};
    auto res = fx.get("/api/v1/workflow-executions");
    CHECK(res->status == 200);
    CHECK(fx.gate_type == "Workflow");
    CHECK(fx.gate_op == "Read");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    const auto body = json::parse(res->body);
    CHECK(body["meta"]["api_version"] == "v1");
    REQUIRE(body["data"].size() == 2);
    CHECK(body["data"][0]["id"] == "r2");
    CHECK(body["data"][0]["workflow_name"] == "Patch Tuesday");
    CHECK(body["data"][0]["workflow_deleted"] == false);
    CHECK_FALSE(body["data"][0].contains("agent_ids"));
    // `total` is the rows in THIS page, never a fleet-wide count.
    CHECK(body["pagination"]["total"] == 2);
    CHECK(body["pagination"]["start"] == 0);
    CHECK(body["pagination"]["page_size"] == 50);
    CHECK(body["pagination"]["next_cursor"].is_null());
    CHECK_FALSE(body["pagination"].contains("result_truncated_by_cap"));
    // Unfiltered caller: the seam receives an UNFILTERED scope (nullopt), not an empty set.
    CHECK_FALSE(fx.seen_scope.has_value());
    CHECK(fx.seen_query.limit == 50);
    CHECK_FALSE(fx.seen_query.latest_per_workflow);
    // A successful list writes no audit row (run metadata; denials are audited by the gate).
    CHECK(fx.audit_calls == 0);
}

TEST_CASE("GET /api/v1/workflow-executions: parameters reach the seam validated",
          "[workflow][executions][list][rest]") {
    Fx fx;
    auto res = fx.get("/api/v1/workflow-executions?workflow_id=wf-1&status=failed&since=10&until=20&limit=3");
    CHECK(res->status == 200);
    CHECK(fx.api_calls == 1);
    CHECK(fx.seen_query.workflow_id == "wf-1");
    CHECK(fx.seen_query.status == "failed");
    CHECK(fx.seen_query.since == 10);
    CHECK(fx.seen_query.until == 20);
    CHECK(fx.seen_query.limit == 3);
    CHECK(json::parse(res->body)["pagination"]["page_size"] == 3);

    fx.get("/api/v1/workflow-executions?limit=100000");
    CHECK(fx.seen_query.limit == 500); // clamped, like the sibling lists
    fx.get("/api/v1/workflow-executions?latest_per_workflow=true");
    CHECK(fx.seen_query.latest_per_workflow);
}

TEST_CASE("GET /api/v1/workflow-executions: bad input is a 400 and never reaches the seam",
          "[workflow][executions][list][rest]") {
    Fx fx;
    for (const char* q : {"?bogus=1", "?workflow-id=x", "?limit=5&limit=6", "?status=nope",
                          "?status=", "?limit=0", "?limit=abc", "?since=20&until=10",
                          "?workflow_id=a%20b", "?cursor=garbage", "?latest_per_workflow=yes",
                          "?latest_per_workflow=true&cursor=w1:1:YWJj"}) {
        INFO(q);
        auto res = fx.get(std::string("/api/v1/workflow-executions") + q);
        CHECK(res->status == 400);
        const auto body = json::parse(res->body);
        CHECK(body["error"]["code"] == 400);
        CHECK_FALSE(body["error"]["message"].get<std::string>().empty());
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    }
    CHECK(fx.api_calls == 0);
}

TEST_CASE("GET /api/v1/workflow-executions: a cursor round trips through next_cursor",
          "[workflow][executions][list][rest]") {
    Fx fx;
    WorkflowExecutionPage page{{run("r2", 200), run("r1", 100)}, keyset::Position{100, "r1"}, false};
    fx.api_result = page;
    const auto first = json::parse(fx.get("/api/v1/workflow-executions?limit=2")->body);
    const auto token = first["pagination"]["next_cursor"].get<std::string>();
    CHECK(token == "w1:100:cjE");

    fx.api_result = WorkflowExecutionPage{{run("r0", 50)}, std::nullopt, false};
    fx.get("/api/v1/workflow-executions?cursor=" + token);
    REQUIRE(fx.seen_query.after.has_value());
    CHECK(fx.seen_query.after->key == 100);
    CHECK(fx.seen_query.after->id == "r1");
}

TEST_CASE("GET /api/v1/workflow-executions: latest_per_workflow reports the cap and no cursor",
          "[workflow][executions][list][rest]") {
    Fx fx;
    fx.api_result = WorkflowExecutionPage{{run("r1", 100)}, std::nullopt, true};
    const auto body = json::parse(fx.get("/api/v1/workflow-executions?latest_per_workflow=true&limit=1")->body);
    CHECK(body["pagination"]["result_truncated_by_cap"] == true);
    CHECK(body["pagination"]["next_cursor"].is_null());
}

TEST_CASE("GET /api/v1/workflow-executions: the gate's scope is handed to the seam exactly",
          "[workflow][executions][list][rest][confinement]") {
    Fx fx;
    fx.gate_scope = authz::VisibleSet{std::unordered_set<std::string>{"a1", "a2"}};
    CHECK(fx.get("/api/v1/workflow-executions")->status == 200);
    REQUIRE(fx.seen_scope.has_value());
    CHECK(*fx.seen_scope == std::unordered_set<std::string>{"a1", "a2"});

    // Engaged-empty (deny-all) stays engaged-empty: never widened to "no filter".
    fx.gate_scope = authz::deny_all();
    CHECK(fx.get("/api/v1/workflow-executions")->status == 200);
    REQUIRE(fx.seen_scope.has_value());
    CHECK(fx.seen_scope->empty());
}

TEST_CASE("GET /api/v1/workflow-executions: the gate is the first and sole authorization",
          "[workflow][executions][list][rest][confinement]") {
    {
        Fx fx;
        fx.gate_admits = false;
        // Even a malformed request is answered by the gate first: no validation oracle for a
        // caller who may not read the list.
        auto res = fx.get("/api/v1/workflow-executions?bogus=1");
        CHECK(res->status == 403);
        CHECK(fx.gate_calls == 1);
        CHECK(fx.api_calls == 0);
    }
    {
        Fx fx(/*with_gate=*/false);
        auto res = fx.get("/api/v1/workflow-executions");
        CHECK(res->status == 503); // an unwired gate fails closed, never open
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        CHECK(fx.api_calls == 0);
    }
    {
        Fx fx(/*with_gate=*/true, /*with_api=*/false);
        auto res = fx.get("/api/v1/workflow-executions");
        CHECK(res->status == 503);
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        CHECK(fx.gate_calls == 1);
    }
}

TEST_CASE("GET /api/v1/workflow-executions: a store failure is a 503 never an empty list",
          "[workflow][executions][list][rest][degrade]") {
    Fx fx;
    fx.api_result = std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted (internal, must not render)");
    auto res = fx.get("/api/v1/workflow-executions");
    CHECK(res->status == 503);
    const auto body = json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"] == 5000);
    CHECK(body["error"]["message"].get<std::string>().find("pool exhausted") == std::string::npos);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    CHECK_FALSE(body.contains("data"));
}

TEST_CASE("GET /api/v1/workflow-executions: the collection route does not shadow the detail route",
          "[workflow][executions][list][rest]") {
    Fx fx;
    // `/{id}` is a different pattern: it must not be answered by the list handler (and vice
    // versa). The detail route needs get_workflow_execution, which this double leaves unwired.
    auto res = fx.get("/api/v1/workflow-executions/some-id");
    CHECK(fx.api_calls == 0);
    CHECK(res->status == 503);
}
