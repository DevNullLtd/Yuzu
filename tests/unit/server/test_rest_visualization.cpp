/**
 * test_rest_visualization.cpp — HTTP-level coverage for the
 * /api/v1/executions/{id}/visualization endpoint added in issue #253.
 *
 * Pattern matches test_rest_guaranteed_state.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised requests
 * directly into the captured handlers. No real socket → no #438 TSan trap.
 *
 * Coverage focuses on the wire-contract surface the dashboard depends on:
 *   - 400 when definition_id query parameter is missing
 *   - 404 when the InstructionDefinition does not exist
 *   - 404 when the definition exists but has no spec.visualization
 *   - 200 with a chart payload when responses are present
 *   - 200 with an empty bucket list when responses are absent
 */

#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};
// InstructionStore is now a migrated Postgres store (ADR-0058).
yuzu::test::PgTestTemplate restviz_instr_tpl{"restvizinstr", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    InstructionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("restviz_instr template: store failed to migrate");
}};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct VizHarness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<InstructionStore> instruction_store;
    std::unique_ptr<ResponseStore> response_store;

    bool perm_grant{true};
    // #1634: the route's sole scope source is now the fleet-read gate's
    // VisibleSet, not response_scope_fn (kept below only for source-stable
    // call sites elsewhere). nullopt = unrestricted, matching FleetReadGate's
    // own TOP convention.
    authz::VisibleSet fleet_read_scope{std::nullopt};
    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    explicit VizHarness(pg::PgPool& pool, RestApiV1::ResponseScopeFn scope_fn = {}) {
        // ADR-0058: InstructionStore is now a migrated Postgres store — shares
        // the same pool/database as ResponseStore below (schema-per-store).
        instruction_store = std::make_unique<InstructionStore>(pool);
        REQUIRE(instruction_store->is_open());
        // #1073: InstructionStore defaults to require_signed_definitions=true.
        // These tests exercise the import path + visualization-spec
        // normalisation, not the signature gate — opt out so unsigned
        // fixtures still pass.
        instruction_store->set_require_signed_definitions(false);
        response_store = std::make_unique<ResponseStore>(pool, /*retention_days=*/0);
        REQUIRE(response_store->is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
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
        // #1634: the visualization route's sole gate is now fleet_read_fn
        // (perm_fn above is retained only for the older negative-case wiring
        // pattern below and is no longer called by the route itself). Mirror
        // RestEventsHarness's default: unrestricted admit, or a 403 denial
        // when a test flips perm_grant.
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
        // PR W1.1 UP-H1: AuditFn typedef → std::function<bool(...)>.
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, response_store.get(),
                            instruction_store.get(),
                            /*execution_tracker=*/nullptr,
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
                            /*metrics_registry=*/nullptr,
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
                            /*response_scope_fn=*/std::move(scope_fn),
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{},
                            /*fleet_read_fn=*/std::move(fleet_read_fn));
    }

    ~VizHarness() {
        response_store.reset();
        instruction_store.reset();
    }

    /// Insert a definition with the given visualization spec and return its id.
    std::string make_def(const std::string& visualization_spec,
                         const std::string& plugin = "procfetch") {
        InstructionDefinition d;
        d.id = "def-" + std::to_string(std::hash<std::string>{}(visualization_spec) % 0xFFFFFF);
        d.name = "viz-test-" + d.id;
        d.type = "question";
        d.plugin = plugin;
        d.action = "list";
        d.visualization_spec = visualization_spec;
        auto created = instruction_store->create_definition(d);
        if (!created.has_value()) {
            INFO("create_definition failed: " << created.error());
            REQUIRE(created.has_value());
        }
        return *created;
    }

    /// Push a response into the store keyed by `instruction_id` (a.k.a.
    /// command_id, a.k.a. the {id} path parameter on the visualization route).
    void push_response(const std::string& instruction_id, const std::string& agent,
                       const std::string& output) {
        StoredResponse r;
        r.instruction_id = instruction_id;
        r.agent_id = agent;
        r.output = output;
        r.status = 0;
        r.timestamp = 1000;
        response_store->store(r);
    }
};

} // namespace

TEST_CASE("REST visualization: missing definition_id → 400", "[pg][rest][visualization][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto res = h.sink.Get("/api/v1/executions/cmd-001/visualization");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("definition_id") != std::string::npos);
    // Closes governance sec-F2: error paths emit failure audit so SIEM
    // can detect enumeration probes against the visualization endpoint.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "execution.visualization.fetch");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail.find("missing_definition_id") != std::string::npos);
}

TEST_CASE("REST visualization: malformed definition_id → 400",
          "[pg][rest][visualization][validation]") {
    // Closes governance sec-F3 / C-15: REST regex bound matches the
    // dashboard fragment; an unbounded value no longer flows into SQL
    // bind / audit / log without validation.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto res =
        h.sink.Get("/api/v1/executions/cmd-001/visualization?definition_id=evil%22%3E%3Cscript%3E");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("[A-Za-z0-9._-]") != std::string::npos);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail.find("malformed_definition_id") != std::string::npos);
}

TEST_CASE("REST visualization: fleet_read_fn denies → 403, no audit emission",
          "[pg][rest][visualization][rbac]") {
    // Closes governance qe-1: 403 path was untested. A future change that
    // accidentally inverts the permission check would silently expose an
    // operator-only endpoint to lower-privileged sessions.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/executions/cmd-001/visualization?definition_id=does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST visualization: null stores → 503", "[rest][visualization][unavailable]") {
    // Closes governance qe-3: 503 path was untested. Mounts the route with
    // null stores so the guard at the top of the handler fires.
    yuzu::server::test::TestRouteSink sink;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "x";
        s.role = auth::Role::admin;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool {
        return true;
    };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };
    RestApiV1 api;
    api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                        /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                        {}, {}, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    auto res = sink.Get("/api/v1/executions/cmd-001/visualization?definition_id=foo");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("service unavailable") != std::string::npos);
}

TEST_CASE("REST visualization: unknown definition_id → 404", "[pg][rest][visualization][not_found]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto res = h.sink.Get("/api/v1/executions/cmd-001/visualization?definition_id=does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("not found") != std::string::npos);
}

TEST_CASE("REST visualization: definition without spec.visualization → 404",
          "[pg][rest][visualization][not_found]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto def_id = h.make_def(""); // no visualization configured
    auto res = h.sink.Get("/api/v1/executions/cmd-001/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("no visualization configured") != std::string::npos);
}

TEST_CASE("REST visualization: pie chart over procfetch responses → 200 with buckets",
          "[pg][rest][visualization][round_trip]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1,
                    "title":"Top procs"})";
    auto def_id = h.make_def(spec, "procfetch");

    h.push_response(
        "cmd-A1", "agent-1",
        "1|chrome|/usr/bin/chrome|d\n2|chrome|/usr/bin/chrome|d\n3|firefox|/usr/bin/ff|c");
    h.push_response("cmd-A1", "agent-2", "1|chrome|/usr/bin/chrome|d\n2|sshd|/usr/sbin/sshd|s");

    auto res = h.sink.Get("/api/v1/executions/cmd-A1/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    auto& d = body["data"];
    CHECK(d["chart_type"] == "pie");
    CHECK(d["title"] == "Top procs");

    // Aggregate labels → counts for an order-independent assertion
    std::map<std::string, double> got;
    REQUIRE(d["labels"].size() >= 3);
    for (size_t i = 0; i < d["labels"].size(); ++i)
        got[d["labels"][i].get<std::string>()] = d["series"][0]["data"][i].get<double>();
    CHECK(got["chrome"] == 3);
    CHECK(got["firefox"] == 1);
    CHECK(got["sshd"] == 1);
    CHECK(d["meta"]["responses_total"] == 2);

    // Closes governance qe-2: audit emission was untested.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "execution.visualization.fetch");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "execution");
    CHECK(h.audit_log[0].target_id == "cmd-A1");
    // Detail format: "<def_id> index=<N>" — issue #587 added the index
    // suffix so multi-chart fetches are distinguishable in the audit log.
    CHECK(h.audit_log[0].detail == def_id + " index=0");
}

TEST_CASE("REST visualization: multi-chart definition (#587)",
          "[pg][rest][visualization][multi_chart]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    // Two charts on a single definition, supplied via the canonical
    // `visualizations` array shape that import normalises into the
    // visualization_spec column.
    nlohmann::json import_body;
    import_body["id"] = "def-multi";
    import_body["name"] = "multi-chart";
    import_body["type"] = "question";
    import_body["plugin"] = "procfetch";
    import_body["visualizations"] = nlohmann::json::array({
        nlohmann::json::object({
            {"type", "pie"},
            {"processor", "single_series"},
            {"title", "By name"},
            {"labelField", 1},
        }),
        nlohmann::json::object({
            {"type", "bar"},
            {"processor", "single_series"},
            {"title", "By path"},
            {"labelField", 2},
        }),
    });
    REQUIRE(h.instruction_store->import_definition_json(import_body.dump()).has_value());

    h.push_response(
        "cmd-multi", "agent-1",
        "1|chrome|/usr/bin/chrome|d\n2|chrome|/usr/bin/chrome|d\n3|firefox|/usr/bin/ff|c");

    // index=0 returns the pie
    auto res0 = h.sink.Get("/api/v1/executions/cmd-multi/visualization?definition_id=def-multi");
    REQUIRE(res0);
    CHECK(res0->status == 200);
    auto body0 = nlohmann::json::parse(res0->body);
    CHECK(body0["data"]["chart_type"] == "pie");
    CHECK(body0["data"]["title"] == "By name");
    CHECK(body0["data"]["chart_index"] == 0);
    CHECK(body0["data"]["chart_count"] == 2);

    // index=1 returns the bar
    auto res1 =
        h.sink.Get("/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=1");
    REQUIRE(res1);
    CHECK(res1->status == 200);
    auto body1 = nlohmann::json::parse(res1->body);
    CHECK(body1["data"]["chart_type"] == "bar");
    CHECK(body1["data"]["title"] == "By path");
    CHECK(body1["data"]["chart_index"] == 1);
    CHECK(body1["data"]["chart_count"] == 2);

    // index=2 → 404 (out of range)
    auto res2 =
        h.sink.Get("/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=2");
    REQUIRE(res2);
    CHECK(res2->status == 404);
    CHECK(res2->body.find("out of range") != std::string::npos);

    // negative index → 400
    auto res_neg =
        h.sink.Get("/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=-1");
    REQUIRE(res_neg);
    CHECK(res_neg->status == 400);

    // garbage index → 400
    auto res_bad =
        h.sink.Get("/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=abc");
    REQUIRE(res_bad);
    CHECK(res_bad->status == 400);
}

TEST_CASE("REST visualization: legacy single-object spec is still index-0 reachable",
          "[pg][rest][visualization][multi_chart][backward_compat]") {
    // Operators authoring a single chart can still use the singular
    // `visualization` block; the engine + store treat it equivalently
    // to a 1-element array (the import path normalises, the engine
    // count() / chart_at() tolerate both shapes for any rows that
    // bypass normalisation — e.g. tests calling create_definition
    // directly).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1})";
    auto def_id = h.make_def(spec, "procfetch");

    h.push_response("cmd-legacy-single", "a1", "1|chrome|/u/b/c|d");

    auto res =
        h.sink.Get("/api/v1/executions/cmd-legacy-single/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["chart_index"] == 0);
    CHECK(body["data"]["chart_count"] == 1);
}

TEST_CASE("REST visualization: snake_case keys still accepted as legacy alias",
          "[pg][rest][visualization][backward_compat]") {
    // The DSL surface migrated to camelCase (governance dsl-B2). The engine
    // accepts the old snake_case names as deprecated aliases so any
    // pre-rename YAML out in the wild keeps working through one transition
    // window.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto spec = R"({"type":"bar","processor":"single_series","label_field":1})";
    auto def_id = h.make_def(spec, "procfetch");
    h.push_response("cmd-legacy", "a1", "1|chrome|/u/b/c|d\n2|chrome|/u/b/c|d");
    auto res = h.sink.Get("/api/v1/executions/cmd-legacy/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("REST visualization: empty response set → 200 with empty payload",
          "[pg][rest][visualization][edge]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    auto spec = R"({"type":"bar","processor":"single_series","label_field":1})";
    auto def_id = h.make_def(spec, "procfetch");

    auto res =
        h.sink.Get("/api/v1/executions/never-dispatched/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    auto& d = body["data"];
    CHECK(d["chart_type"] == "bar");
    CHECK(d["labels"].size() == 0);
    CHECK(d["meta"]["responses_total"] == 0);
}

TEST_CASE("InstructionStore: visualization_spec round-trips through create / get / update",
          "[instruction_store][visualization][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, restviz_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition d;
    d.id = "def-viz-rt";
    d.name = "rt";
    d.type = "question";
    d.plugin = "procfetch";
    d.visualization_spec = R"({"type":"pie","processor":"single_series","label_field":1})";
    auto created = store.create_definition(d);
    REQUIRE(created.has_value());

    auto got = store.get_definition("def-viz-rt");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->visualization_spec.find("\"type\":\"pie\"") != std::string::npos);

    // Update the spec to a different chart type and confirm it persists
    InstructionDefinition updated = **got;
    updated.visualization_spec = R"({"type":"line","processor":"datetime_series"})";
    REQUIRE(store.update_definition(updated).has_value());
    auto got2 = store.get_definition("def-viz-rt");
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->visualization_spec.find("\"type\":\"line\"") != std::string::npos);
}

TEST_CASE("InstructionStore: import_definition_json accepts visualization_spec as object or string",
          "[instruction_store][visualization][import][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, restviz_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    // #1073: opt out of signature enforcement — this test pins
    // visualization_spec normalisation, not the signature gate.
    store.set_require_signed_definitions(false);

    // Object form (CLI converts YAML→JSON in one shot)
    nlohmann::json j;
    j["id"] = "def-imp-obj";
    j["name"] = "imp-obj";
    j["type"] = "question";
    j["plugin"] = "procfetch";
    j["visualization_spec"] = nlohmann::json::object({
        {"type", "pie"},
        {"processor", "single_series"},
        {"label_field", 1},
    });
    REQUIRE(store.import_definition_json(j.dump()).has_value());
    auto got = store.get_definition("def-imp-obj");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->visualization_spec.find("\"type\":\"pie\"") != std::string::npos);

    // Pre-serialized string form
    nlohmann::json j2;
    j2["id"] = "def-imp-str";
    j2["name"] = "imp-str";
    j2["type"] = "question";
    j2["plugin"] = "procfetch";
    j2["visualization_spec"] = R"({"type":"bar","processor":"single_series"})";
    REQUIRE(store.import_definition_json(j2.dump()).has_value());
    auto got2 = store.get_definition("def-imp-str");
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->visualization_spec.find("\"type\":\"bar\"") != std::string::npos);
}

TEST_CASE("REST visualization: management-group scope drops out-of-scope agents' rows (#1634)",
          "[pg][rest][visualization][scope]") {
    // The flat Response:Read gate is not a per-agent ownership check, so without
    // the scope filter an operator charts another operator's execution by id.
    // Same fixture as the pie round-trip, but the fleet-read gate's VisibleSet
    // admits only agent-1 — agent-2's rows (sshd) must never reach the chart
    // transform.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-1"}};
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1,
                    "title":"Top procs"})";
    auto def_id = h.make_def(spec, "procfetch");

    h.push_response(
        "cmd-S1", "agent-1",
        "1|chrome|/usr/bin/chrome|d\n2|chrome|/usr/bin/chrome|d\n3|firefox|/usr/bin/ff|c");
    h.push_response("cmd-S1", "agent-2", "1|chrome|/usr/bin/chrome|d\n2|sshd|/usr/sbin/sshd|s");

    auto res = h.sink.Get("/api/v1/executions/cmd-S1/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    auto& d = body["data"];
    std::map<std::string, double> got;
    for (size_t i = 0; i < d["labels"].size(); ++i)
        got[d["labels"][i].get<std::string>()] = d["series"][0]["data"][i].get<double>();
    // Only agent-1's rows fold into the chart.
    CHECK(got["chrome"] == 2); // agent-1's two chrome rows only (agent-2's third excluded)
    CHECK(got["firefox"] == 1);
    CHECK(got.find("sshd") == got.end()); // agent-2's sshd never charted
    CHECK(d["meta"]["responses_total"] == 1);
    // sshd never appears anywhere in the body.
    CHECK(res->body.find("sshd") == std::string::npos);
    // #1634 (governance Gate 4 fix): the out-of-scope drop is a distinct
    // `denied` audit row (CC7.2 evidence), paired with the `success` row for
    // the served set — same shape as the legacy responses routes / MCP
    // query_responses/aggregate_responses, not folded into the success detail.
    REQUIRE(h.audit_log.size() == 2);
    bool saw_denied = false, saw_success = false;
    for (const auto& a : h.audit_log) {
        if (a.result == "denied") {
            saw_denied = true;
            CHECK(a.detail.find("scope_dropped=1") != std::string::npos);
        }
        if (a.result == "success")
            saw_success = true;
    }
    CHECK(saw_denied);
    CHECK(saw_success);
}

TEST_CASE("REST visualization: every agent out of scope → empty chart, no leak (#1634)",
          "[pg][rest][visualization][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    VizHarness h(pool);
    h.fleet_read_scope = authz::deny_all();
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1,"title":"t"})";
    auto def_id = h.make_def(spec, "procfetch");
    h.push_response("cmd-S2", "agent-1", "1|chrome|/usr/bin/chrome|d");
    h.push_response("cmd-S2", "agent-2", "1|sshd|/usr/sbin/sshd|s");

    auto res = h.sink.Get("/api/v1/executions/cmd-S2/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["meta"]["responses_total"] == 0);
    CHECK(res->body.find("chrome") == std::string::npos);
    CHECK(res->body.find("sshd") == std::string::npos);
}
