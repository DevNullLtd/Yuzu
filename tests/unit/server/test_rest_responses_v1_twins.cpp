/**
 * test_rest_responses_v1_twins.cpp — HTTP-level coverage for #2146 A2-R2's
 * command/instruction-ID-keyed Responses REST v1 surface: GET
 * /api/v1/responses/{id}, GET /api/v1/responses/{id}/aggregate, and GET
 * /api/v1/responses/{id}/export. DISTINCT from
 * test_rest_executions_v1_twins.cpp's GET /api/v1/executions/{id}/responses
 * (execution-ID-keyed, a different, already-shipped capability).
 *
 * Pattern matches test_rest_executions_v1_twins.cpp: register RestApiV1
 * routes against an in-process TestRouteSink and dispatch synthesised
 * requests directly into the captured handlers. No real socket → no #438
 * TSan trap.
 */

#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "response_export_metrics.hpp"
#include "response_query_params.hpp"
#include "response_store.hpp"
#include "test_export_cap_guard.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Shares the "responsestore" template key with test_response_store.cpp /
// test_rest_visualization.cpp / test_rest_executions_v1_twins.cpp (identical
// setup) — ResponseStore is the base PgTestTemplate.
yuzu::test::PgTestTemplate respv1_responsestore_tpl{
    "responsestore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("respv1 responsestore template: store failed to migrate");
    }};

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct RespV1Harness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ResponseStore> response_store;

    bool perm_grant{true};
    authz::VisibleSet fleet_read_scope{std::nullopt};
    bool audit_persist{true}; // flip to simulate an audit-write failure
    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics; // #4644/#4703 counters, seeded like production

    RestApiV1 api;

    explicit RespV1Harness(pg::PgPool& pool) {
        response_store = std::make_unique<ResponseStore>(pool, /*retention_days=*/0);
        REQUIRE(response_store->is_open());
        yuzu::server::seed_response_metrics(metrics);

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
            return audit_persist;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, response_store.get(),
                            /*instruction_store=*/nullptr,
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
                            /*fleet_read_fn=*/std::move(fleet_read_fn));
    }

    ~RespV1Harness() { response_store.reset(); }
};

StoredResponse mk_resp(const std::string& instr_id, const std::string& agent_id, int status,
                       const std::string& output, int64_t ts) {
    StoredResponse r;
    r.instruction_id = instr_id;
    r.agent_id = agent_id;
    r.status = status;
    r.output = output;
    r.timestamp = ts;
    return r;
}

} // namespace

// ── GET /api/v1/responses/{id} ──────────────────────────────────────────

TEST_CASE("GET /api/v1/responses/:id: returns the widened row shape via the shared builder",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    StoredResponse r = mk_resp("instr-get-1", "agent-A", 0, "hello", 1735689600);
    r.error_detail = "";
    r.plugin = "shellexec";
    h.response_store->store(r);

    auto res = h.sink.Get("/api/v1/responses/instr-get-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    const auto& row = body["data"][0];
    CHECK(row["agent_id"] == "agent-A");
    CHECK(row["instruction_id"] == "instr-get-1");
    CHECK(row["output"] == "hello");
    CHECK(row.contains("id"));
    CHECK(row.contains("execution_id"));
    CHECK(row.contains("error_detail"));
    CHECK(row["plugin"] == "shellexec");
    CHECK(row.contains("received_at_ms"));

    bool audited_success = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "response.read" && c.result == "success" && c.target_id == "instr-get-1")
            audited_success = true;
    }
    CHECK(audited_success);
}

TEST_CASE("GET /api/v1/responses/:id: fleet_read_fn denial -> 403",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/responses/anything");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/responses/:id: offset is rejected with 400, not silently ignored",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    auto res = h.sink.Get("/api/v1/responses/instr-offset-1?offset=1");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/responses/:id: limit is clamped on BOTH bounds",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    for (int i = 0; i < 5; ++i)
        h.response_store->store(
            mk_resp("instr-limit-1", "agent-" + std::to_string(i), 0, "o", 100 + i));

    // A caller-supplied limit far past the cap must not attempt an unbounded
    // fetch -- it is silently clamped to the [1,1000] ceiling, still serving
    // the (small) real result set here.
    auto res_huge = h.sink.Get("/api/v1/responses/instr-limit-1?limit=999999999");
    REQUIRE(res_huge);
    CHECK(res_huge->status == 200);
    auto body_huge = nlohmann::json::parse(res_huge->body);
    CHECK(body_huge["data"].size() == 5);

    // A non-positive limit clamps to the floor (1), never binds unbounded and
    // never returns zero rows (0 would read as "no responses" to a caller).
    auto res_zero = h.sink.Get("/api/v1/responses/instr-limit-1?limit=0");
    REQUIRE(res_zero);
    CHECK(res_zero->status == 200);
    auto body_zero = nlohmann::json::parse(res_zero->body);
    CHECK(body_zero["data"].size() == 1);
}

TEST_CASE("GET /api/v1/responses/:id: a cap-hit signals result_truncated_by_cap, an "
          "under-cap result does not (governance finding, #2146 A2-R2)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    for (int i = 0; i < 3; ++i)
        h.response_store->store(
            mk_resp("instr-trunc-1", "agent-" + std::to_string(i), 0, "o", 100 + i));

    // Served count == limit -> the cap may have dropped rows; signal it.
    auto res_capped = h.sink.Get("/api/v1/responses/instr-trunc-1?limit=2");
    REQUIRE(res_capped);
    auto body_capped = nlohmann::json::parse(res_capped->body);
    CHECK(body_capped["data"].size() == 2);
    REQUIRE(body_capped["pagination"].contains("result_truncated_by_cap"));
    CHECK(body_capped["pagination"]["result_truncated_by_cap"].get<bool>() == true);

    // Served count < limit -> genuinely complete; the field must be absent
    // (never present-false, matching the codebase's own present-only-when-
    // true convention for this field elsewhere).
    auto res_complete = h.sink.Get("/api/v1/responses/instr-trunc-1?limit=100");
    REQUIRE(res_complete);
    auto body_complete = nlohmann::json::parse(res_complete->body);
    CHECK(body_complete["data"].size() == 3);
    CHECK_FALSE(body_complete["pagination"].contains("result_truncated_by_cap"));
}

TEST_CASE("GET /api/v1/responses/:id: management-group scope filters another operator's rows",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-scope-1", "agent-A", 0, "a", 100));
    h.response_store->store(mk_resp("instr-scope-1", "agent-B", 0, "b", 101));
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/responses/instr-scope-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-A");

    bool denied_audited = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "response.read" && c.result == "denied" &&
            c.target_id == "instr-scope-1")
            denied_audited = true;
    }
    CHECK(denied_audited);
}

TEST_CASE("GET /api/v1/responses/:id: audit-persist failure fails closed (503)",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-auditfail-1", "agent-A", 0, "a", 100));
    h.audit_persist = false;

    auto res = h.sink.Get("/api/v1/responses/instr-auditfail-1");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── GET /api/v1/responses/{id}/aggregate ────────────────────────────────

TEST_CASE("GET /api/v1/responses/:id/aggregate: groups + op_column honored via the shared builder",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-agg-1", "agent-A", 0, "a", 100));
    h.response_store->store(mk_resp("instr-agg-1", "agent-B", 0, "b", 200));
    h.response_store->store(mk_resp("instr-agg-1", "agent-C", 1, "c", 300));

    auto res = h.sink.Get(
        "/api/v1/responses/instr-agg-1/aggregate?group_by=status&op=max&op_column=timestamp");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["groups"].is_array());
    CHECK(body["data"]["total_rows"] == 3);
    bool found_status0 = false;
    for (const auto& g : body["data"]["groups"]) {
        if (g["group_value"] == "0") {
            found_status0 = true;
            CHECK(g["count"] == 2);
            // MAX(timestamp) over the two status=0 rows (100, 200) is 200.
            CHECK(g["aggregate_value"] == 200.0);
        }
    }
    CHECK(found_status0);
}

TEST_CASE("GET /api/v1/responses/:id/aggregate: invalid op_column is a 400",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    auto res = h.sink.Get("/api/v1/responses/instr-agg-bad/aggregate?op=sum&op_column=output");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/responses/:id/aggregate: invalid group_by is a 400",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    auto res = h.sink.Get("/api/v1/responses/instr-agg-bad2/aggregate?group_by=output");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/responses/:id/aggregate: fleet_read_fn denial -> 403",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/responses/anything/aggregate");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── GET /api/v1/responses/{id}/export ───────────────────────────────────

TEST_CASE("GET /api/v1/responses/:id/export: json format uses the shared row builder",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-exp-1", "agent-A", 0, "hello", 100));

    auto res = h.sink.Get("/api/v1/responses/instr-exp-1/export");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Disposition").find("responses-instr-exp-1.json") !=
          std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["output"] == "hello");
    CHECK(body["data"][0].contains("plugin"));
}

TEST_CASE("GET /api/v1/responses/:id/export: csv format", "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-exp-2", "agent-A", 0, "hello", 100));

    auto res = h.sink.Get("/api/v1/responses/instr-exp-2/export?format=csv");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Disposition").find("responses-instr-exp-2.csv") !=
          std::string::npos);
    CHECK(res->body.find("id,instruction_id,agent_id,execution_id,status,output,error_detail,"
                        "timestamp,plugin,received_at_ms") != std::string::npos);
    CHECK(res->body.find("hello") != std::string::npos);
}

TEST_CASE("GET /api/v1/responses/:id/export: CSV formula injection (CWE-1236) is neutralized, "
          "not passed through raw (#2146 A2-R2 governance finding)",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(
        mk_resp("instr-exp-formula", "agent-A", 0, "=cmd|'/c calc'!A1", 100));

    auto res = h.sink.Get("/api/v1/responses/instr-exp-formula/export?format=csv");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Pre-fix: the raw "=cmd|..." byte sequence reached the CSV cell
    // unneutralized -- opening the export in Excel/Sheets would execute it as
    // a formula. Post-fix: a leading apostrophe forces Excel/Sheets to treat
    // the cell as text.
    CHECK(res->body.find("'=cmd") != std::string::npos);
    CHECK(res->body.find(",=cmd") == std::string::npos);
}

TEST_CASE("GET /api/v1/responses/:id/export: a caller-supplied limit is clamped, "
          "not left unbounded (#2146 A2-R2 -- corrects the legacy route's own gap)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-exp-limit", "agent-A", 0, "a", 100));

    auto res = h.sink.Get("/api/v1/responses/instr-exp-limit/export?limit=999999999");
    REQUIRE(res);
    CHECK(res->status == 200); // clamped, not an unbounded fetch attempt
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"].size() == 1);
}

TEST_CASE("GET /api/v1/responses/:id/export: offset is rejected with 400, not silently "
          "ignored (unhappy-path governance finding, #2146 A2-R2)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    auto res = h.sink.Get("/api/v1/responses/instr-exp-offset-1/export?offset=1");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/responses/:id/export: a cap-hit signals result_truncated_by_cap on "
          "JSON (pagination) and CSV (response header) (#2146 A2-R2 governance finding)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    for (int i = 0; i < 3; ++i)
        h.response_store->store(
            mk_resp("instr-exp-trunc-1", "agent-" + std::to_string(i), 0, "o", 100 + i));

    auto res_json = h.sink.Get("/api/v1/responses/instr-exp-trunc-1/export?limit=2");
    REQUIRE(res_json);
    auto body_json = nlohmann::json::parse(res_json->body);
    CHECK(body_json["data"].size() == 2);
    REQUIRE(body_json["pagination"].contains("result_truncated_by_cap"));
    CHECK(body_json["pagination"]["result_truncated_by_cap"].get<bool>() == true);

    auto res_csv = h.sink.Get("/api/v1/responses/instr-exp-trunc-1/export?limit=2&format=csv");
    REQUIRE(res_csv);
    CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");

    // Under the cap: complete, no marker on either format.
    auto res_complete = h.sink.Get("/api/v1/responses/instr-exp-trunc-1/export?limit=100");
    REQUIRE(res_complete);
    auto body_complete = nlohmann::json::parse(res_complete->body);
    CHECK(body_complete["data"].size() == 3);
    CHECK_FALSE(body_complete["pagination"].contains("result_truncated_by_cap"));
}

TEST_CASE("GET /api/v1/responses/:id/export: fleet_read_fn denial -> 403",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/responses/anything/export");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/responses/:id/export: management-group scope filters another "
          "operator's rows",
          "[pg][rest][responses][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-exp-scope", "agent-A", 0, "a", 100));
    h.response_store->store(mk_resp("instr-exp-scope", "agent-B", 0, "b", 101));
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/responses/instr-exp-scope/export");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-A");
}

// ── #4644: strict numeric query parameters ─────────────────────────────────

TEST_CASE("response routes: a malformed numeric query parameter is a 400 never a different "
          "valid-looking filter (#4644)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-strict", "agent-A", 0, "ok", 100));

    // route suffix x malformed query. stoi/stoll used to read these as 0, 1, 100, 1 and
    // -5 (a "filter" the store ignores because it only applies status >= 0).
    const std::string route = GENERATE(as<std::string>{}, "", "/aggregate", "/export");
    const std::string query = GENERATE(as<std::string>{}, "status=0x1", "status=1e0",
                                       "status=-5", "status=", "status=+1",
                                       "since=1e9", "since=100abc", "until=0x10", "until=",
                                       "status=99999999999");
    INFO("route=" << route << " query=" << query);
    auto res = h.sink.Get("/api/v1/responses/instr-strict" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 400);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"] == "invalid numeric query parameter");
}

TEST_CASE("response routes: limit rejects trailing garbage on the routes that accept it (#4644)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);

    const std::string route = GENERATE(as<std::string>{}, "", "/export");
    const std::string query =
        GENERATE(as<std::string>{}, "limit=100abc", "limit=1e3", "limit=0x10", "limit=");
    INFO("route=" << route << " query=" << query);
    auto res = h.sink.Get("/api/v1/responses/instr-strict-limit" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("response routes: well-formed numerics still pass including zero-padding and the "
          "-1 'any' sentinel (the fix is not over-strict) (#4644)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-strict-ok", "agent-A", 0, "ok", 100));

    const std::string route = GENERATE(as<std::string>{}, "", "/aggregate", "/export");
    const std::string query = GENERATE(as<std::string>{}, "status=007", "status=-1", "status=0",
                                       "since=0&until=0", "since=50&until=200");
    INFO("route=" << route << " query=" << query);
    auto res = h.sink.Get("/api/v1/responses/instr-strict-ok" + route + "?" + query);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("response export: status filter matches the row it names so a malformed value can no "
          "longer silently widen it (#4644)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-strict-st", "agent-A", 0, "success-row", 100));
    h.response_store->store(mk_resp("instr-strict-st", "agent-B", 1, "other-row", 101));

    auto res = h.sink.Get("/api/v1/responses/instr-strict-st/export?status=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["output"] == "other-row");
}

// ── #4703: total export body byte cap ──────────────────────────────────────

namespace {
constexpr const char* kV1CsvTrailerPrefix = "# result_truncated_by_cap";

// The in-band truncation record of a CUT CSV export, or "" when the body has none. It is
// the last CRLF-terminated record.
std::string v1_csv_trailer(const std::string& body) {
    if (body.size() < 2 || body.compare(body.size() - 2, 2, "\r\n") != 0)
        return {};
    const auto start = body.rfind("\r\n", body.size() - 3);
    const std::size_t from = start == std::string::npos ? 0 : start + 2;
    const std::string last = body.substr(from, body.size() - 2 - from);
    return last.rfind(kV1CsvTrailerPrefix, 0) == 0 ? last : std::string{};
}

// Data rows in a CSV export body: every record ends CRLF, the header is one of them and a
// cut export's trailer is another, neither counted. The seeded payloads contain no CR/LF.
std::size_t v1_csv_data_rows(const std::string& body) {
    std::size_t lines = 0;
    for (std::size_t pos = body.find("\r\n"); pos != std::string::npos;
         pos = body.find("\r\n", pos + 2))
        ++lines;
    if (!v1_csv_trailer(body).empty() && lines > 0)
        --lines;
    return lines == 0 ? 0 : lines - 1;
}
} // namespace


TEST_CASE("GET /api/v1/responses/:id/export: the total-byte cap truncates JSON and CSV and "
          "sets the same truncation signal as the row cap (#4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    for (int i = 0; i < 5; ++i)
        h.response_store->store(mk_resp("instr-bytecap", "agent-" + std::to_string(i), 0,
                                        std::string(400, 'x'), 100 + i));

    {
        yuzu::test::ExportByteCapGuard cap(600); // < two rows
        auto res_json = h.sink.Get("/api/v1/responses/instr-bytecap/export");
        REQUIRE(res_json);
        REQUIRE(res_json->status == 200);
        auto body = nlohmann::json::parse(res_json->body);
        CHECK(body["data"].size() >= 1);        // progress: at least one row always lands
        CHECK(body["data"].size() < 5);         // and the cap actually cut the export
        REQUIRE(body["pagination"].contains("result_truncated_by_cap"));
        CHECK(body["pagination"]["result_truncated_by_cap"].get<bool>() == true);
        CHECK(res_json->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-bytecap-truncated.json\"");

        auto res_csv = h.sink.Get("/api/v1/responses/instr-bytecap/export?format=csv");
        REQUIRE(res_csv);
        CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
        CHECK(res_csv->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-bytecap-truncated.csv\"");
        CHECK(res_csv->body.size() < 5 * 400);
        // In-band signal: the cut CSV ends with one 10-field trailer record naming the cause.
        CHECK(v1_csv_trailer(res_csv->body) ==
              "# result_truncated_by_cap cause=byte_cap,,,,,,,,,");
    }

    // Default cap restored: the same export is complete and unmarked.
    auto res_full = h.sink.Get("/api/v1/responses/instr-bytecap/export");
    REQUIRE(res_full);
    auto full = nlohmann::json::parse(res_full->body);
    CHECK(full["data"].size() == 5);
    CHECK_FALSE(full["pagination"].contains("result_truncated_by_cap"));
    CHECK(res_full->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-bytecap.json\"");

    auto res_full_csv = h.sink.Get("/api/v1/responses/instr-bytecap/export?format=csv");
    REQUIRE(res_full_csv);
    CHECK(res_full_csv->get_header_value("X-Result-Truncated-By-Cap").empty());
    CHECK(v1_csv_trailer(res_full_csv->body).empty());
    CHECK(res_full_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-bytecap.csv\"");
}

TEST_CASE("GET /api/v1/responses/:id/export: the SERIALIZATION backstop alone flags a byte-cap "
          "cut when the SQL cut kept every row (#4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    // Quote-heavy payload: 100 raw bytes per row, but CSV doubles each quote and JSON
    // escapes each one, so the serialized row is about twice its raw payload.
    for (int i = 0; i < 2; ++i)
        h.response_store->store(mk_resp("instr-backstop", "agent-" + std::to_string(i), 1,
                                        std::string(100, '"'), 100 + i));

    // Cap 150 sits between one row's raw payload (100) and its serialized size (>150).
    // Precondition, so this test can only pass through the backstop: the SQL cut keeps both
    // rows (the rows BEFORE the second total 100 < 150) and reports no cut of its own.
    {
        ResponseQuery q;
        q.limit = 10000;
        auto sql_only = h.response_store->query_bounded("instr-backstop", q, std::nullopt, 150);
        REQUIRE(sql_only.has_value());
        REQUIRE(sql_only->rows.size() == 2);
        REQUIRE_FALSE(sql_only->byte_cap_hit);
        REQUIRE_FALSE(sql_only->row_cap_hit);
    }

    yuzu::test::ExportByteCapGuard cap(150);

    auto res_json = h.sink.Get("/api/v1/responses/instr-backstop/export");
    REQUIRE(res_json);
    REQUIRE(res_json->status == 200);
    auto body = nlohmann::json::parse(res_json->body);
    CHECK(body["data"].size() == 1); // the backstop stopped before the second row
    REQUIRE(body["pagination"].contains("result_truncated_by_cap"));
    CHECK(body["pagination"]["result_truncated_by_cap"].get<bool>() == true);
    CHECK(res_json->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-backstop-truncated.json\"");

    auto res_csv = h.sink.Get("/api/v1/responses/instr-backstop/export?format=csv");
    REQUIRE(res_csv);
    REQUIRE(res_csv->status == 200);
    CHECK(res_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(v1_csv_trailer(res_csv->body) ==
          "# result_truncated_by_cap cause=byte_cap,,,,,,,,,");
    CHECK(v1_csv_data_rows(res_csv->body) == 1);
    CHECK(res_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-backstop-truncated.csv\"");
}

TEST_CASE("GET /api/v1/responses/:id/export: a ROW-cap cut renames the download and an "
          "exactly-full export does not (#4703 UP-3)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    for (int i = 0; i < 3; ++i)
        h.response_store->store(
            mk_resp("instr-rowcut", "agent-" + std::to_string(i), 0, "o", 100 + i));
    for (const char* fmt : {"json", "csv"}) {
        const std::string f = fmt;
        auto cut = h.sink.Get("/api/v1/responses/instr-rowcut/export?limit=2&format=" + f);
        REQUIRE(cut);
        CHECK(cut->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-rowcut-truncated." + f + "\"");
        if (f == "csv") {
            CHECK(v1_csv_trailer(cut->body) ==
                  "# result_truncated_by_cap cause=row_cap,,,,,,,,,");
            CHECK(v1_csv_data_rows(cut->body) == 2); // the trailer is not a data row
        }
        auto exact = h.sink.Get("/api/v1/responses/instr-rowcut/export?limit=3&format=" + f);
        REQUIRE(exact);
        CHECK(exact->get_header_value("Content-Disposition") ==
              "attachment; filename=\"responses-instr-rowcut." + f + "\"");
        CHECK(exact->get_header_value("X-Result-Truncated-By-Cap").empty());
        if (f == "csv") {
            CHECK(v1_csv_trailer(exact->body).empty());
            CHECK(v1_csv_data_rows(exact->body) == 3);
        }
    }
}

TEST_CASE("GET /api/v1/responses/:id/export: a LAST row that crosses the byte cap is not a "
          "truncation (nothing was dropped) (#4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-bytecap-one", "agent-A", 0, std::string(400, 'y'), 100));

    yuzu::test::ExportByteCapGuard cap(10); // the single row alone exceeds this
    auto res = h.sink.Get("/api/v1/responses/instr-bytecap-one/export");
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"].size() == 1);
    CHECK_FALSE(body["pagination"].contains("result_truncated_by_cap"));
}

TEST_CASE("GET /api/v1/responses/:id/export: no limit serves every row up to the ceiling and "
          "limit 0 serves exactly one (#4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    // 101 rows: more than the query route's default of 100, so a handler that fell back
    // to that default instead of the export ceiling would serve 100 and fail here.
    for (int i = 0; i < 101; ++i)
        h.response_store->store(
            mk_resp("instr-default", "agent-" + std::to_string(i), 0, "o", 100 + i));

    auto all_json = h.sink.Get("/api/v1/responses/instr-default/export");
    REQUIRE(all_json);
    auto all = nlohmann::json::parse(all_json->body);
    CHECK(all["data"].size() == 101);
    CHECK_FALSE(all["pagination"].contains("result_truncated_by_cap"));
    auto all_csv = h.sink.Get("/api/v1/responses/instr-default/export?format=csv");
    REQUIRE(all_csv);
    CHECK(v1_csv_data_rows(all_csv->body) == 101);

    auto zero = h.sink.Get("/api/v1/responses/instr-default/export?limit=0");
    REQUIRE(zero);
    auto zero_body = nlohmann::json::parse(zero->body);
    CHECK(zero_body["data"].size() == 1);
    REQUIRE(zero_body["pagination"].contains("result_truncated_by_cap"));
    CHECK(zero_body["pagination"]["result_truncated_by_cap"].get<bool>() == true);
}

TEST_CASE("GET /api/v1/responses/:id/export: the byte cap always serves one row and never "
          "flags a last row that merely crosses it (#4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    h.response_store->store(mk_resp("instr-lastcross", "agent-0", 0, std::string(400, 'y'), 100));
    for (int i = 0; i < 3; ++i)
        h.response_store->store(
            mk_resp("instr-progress", "agent-" + std::to_string(i), 0, std::string(400, 'z'),
                    100 + i));
    yuzu::test::ExportByteCapGuard cap(1); // every row alone exceeds this

    auto one_json = h.sink.Get("/api/v1/responses/instr-lastcross/export");
    REQUIRE(one_json);
    auto one = nlohmann::json::parse(one_json->body);
    CHECK(one["data"].size() == 1);
    CHECK_FALSE(one["pagination"].contains("result_truncated_by_cap"));
    CHECK(one_json->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-lastcross.json\"");
    auto one_csv = h.sink.Get("/api/v1/responses/instr-lastcross/export?format=csv");
    REQUIRE(one_csv);
    CHECK(v1_csv_data_rows(one_csv->body) == 1);
    CHECK(one_csv->get_header_value("X-Result-Truncated-By-Cap").empty());
    CHECK(v1_csv_trailer(one_csv->body).empty());
    CHECK(one_csv->get_header_value("Content-Disposition") ==
          "attachment; filename=\"responses-instr-lastcross.csv\"");

    auto many_json = h.sink.Get("/api/v1/responses/instr-progress/export");
    REQUIRE(many_json);
    auto many = nlohmann::json::parse(many_json->body);
    CHECK(many["data"].size() == 1);
    REQUIRE(many["pagination"].contains("result_truncated_by_cap"));
    CHECK(many["pagination"]["result_truncated_by_cap"].get<bool>() == true);
    auto many_csv = h.sink.Get("/api/v1/responses/instr-progress/export?format=csv");
    REQUIRE(many_csv);
    CHECK(v1_csv_data_rows(many_csv->body) == 1);
    CHECK(many_csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(v1_csv_trailer(many_csv->body) == "# result_truncated_by_cap cause=byte_cap,,,,,,,,,");
}

TEST_CASE("v1 response routes: since and until of zero mean unbounded, a negative one is a 400 "
          "(#4644)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    for (int i = 0; i < 3; ++i)
        h.response_store->store(
            mk_resp("instr-window", "agent-" + std::to_string(i), 0, "o", 100 + i));
    // Zero is the documented "no bound on that side" sentinel: pinned.
    for (const char* route : {"", "/export"}) {
        for (const char* q : {"since=0", "until=0", "since=0&until=0"}) {
            INFO(route << " " << q);
            auto res = h.sink.Get(std::string("/api/v1/responses/instr-window") + route + "?" + q);
            REQUIRE(res);
            REQUIRE(res->status == 200);
            CHECK(nlohmann::json::parse(res->body)["data"].size() == 3);
        }
    }
    // A negative epoch is no timestamp; it used to widen to "unbounded".
    for (const char* route : {"", "/export", "/aggregate"}) {
        for (const char* q : {"since=-5", "until=-5", "since=-1&until=0", "since=0&until=-9"}) {
            INFO(route << " " << q);
            auto res = h.sink.Get(std::string("/api/v1/responses/instr-window") + route + "?" + q);
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(nlohmann::json::parse(res->body)["error"]["message"] ==
                  "invalid numeric query parameter");
        }
    }
}

TEST_CASE("v1 response routes count rejected numeric params and cut exports by surface "
          "(#4644 #4703)",
          "[pg][rest][responses][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, respv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RespV1Harness h(pool);
    for (int i = 0; i < 3; ++i)
        h.response_store->store(mk_resp("instr-metric", "agent-" + std::to_string(i), 0,
                                        std::string(400, 'x'), 100 + i));
    using yuzu::server::kResponseExportTruncatedMetric;
    using yuzu::server::kResponseParamRejectedMetric;
    auto rejected = [&](const char* surface) {
        return h.metrics.counter(kResponseParamRejectedMetric, {{"surface", surface}}).value();
    };
    auto cut = [&](const char* surface, const char* cause) {
        return h.metrics
            .counter(kResponseExportTruncatedMetric, {{"surface", surface}, {"cause", cause}})
            .value();
    };

    // One rejection per v1 handler: query, aggregate, export.
    CHECK(h.sink.Get("/api/v1/responses/instr-metric?limit=100abc")->status == 400);
    CHECK(h.sink.Get("/api/v1/responses/instr-metric/aggregate?since=1e9")->status == 400);
    CHECK(h.sink.Get("/api/v1/responses/instr-metric/export?status=0x1")->status == 400);
    CHECK(rejected("rest_v1") == 3.0);
    CHECK(rejected("rest") == 0.0);
    CHECK(h.sink.Get("/api/v1/responses/instr-metric?limit=2")->status == 200);
    CHECK(rejected("rest_v1") == 3.0);

    CHECK(h.sink.Get("/api/v1/responses/instr-metric/export?limit=2")->status == 200);
    CHECK(cut("rest_v1", "row_cap") == 1.0);
    CHECK(h.sink.Get("/api/v1/responses/instr-metric/export")->status == 200);
    CHECK(cut("rest_v1", "row_cap") == 1.0);
    {
        yuzu::test::ExportByteCapGuard cap(500);
        CHECK(h.sink.Get("/api/v1/responses/instr-metric/export?format=csv")->status == 200);
    }
    CHECK(cut("rest_v1", "byte_cap") == 1.0);
    CHECK(cut("rest", "byte_cap") == 0.0);
}

TEST_CASE("append_rows_until_byte_cap / parse_query_int: pure helper contracts (#4644 #4703)",
          "[rest][responses][v1]") {
    using yuzu::server::append_rows_until_byte_cap;
    using yuzu::server::parse_query_int;

    CHECK(parse_query_int<int>("42") == 42);
    CHECK(parse_query_int<int>("-1") == -1);
    CHECK(parse_query_int<int>("007") == 7);
    CHECK_FALSE(parse_query_int<int>("").has_value());
    CHECK_FALSE(parse_query_int<int>("+1").has_value());
    CHECK_FALSE(parse_query_int<int>(" 1").has_value());
    CHECK_FALSE(parse_query_int<int>("1 ").has_value());
    CHECK_FALSE(parse_query_int<int>("0x1").has_value());
    CHECK_FALSE(parse_query_int<int>("1e9").has_value());
    CHECK_FALSE(parse_query_int<int>("100abc").has_value());
    CHECK_FALSE(parse_query_int<int>("99999999999").has_value()); // int overflow: no wrap
    CHECK(parse_query_int<std::int64_t>("99999999999") == 99999999999LL);
    CHECK_FALSE(parse_query_int<std::int64_t>("9223372036854775808").has_value());

    const std::vector<int> rows{10, 10, 10, 10};
    std::size_t total = 0;
    CHECK(append_rows_until_byte_cap(rows, 25, [&](int r) { return total += static_cast<std::size_t>(r); }));
    CHECK(total == 30); // stops after the row that reached the cap
    total = 0;
    CHECK_FALSE(append_rows_until_byte_cap(rows, 1000, [&](int r) { return total += static_cast<std::size_t>(r); }));
    CHECK(total == 40);
    total = 0;
    CHECK_FALSE(append_rows_until_byte_cap(rows, 40, [&](int r) { return total += static_cast<std::size_t>(r); }));

    // The `>=` boundary: three rows of 10. A cap of 20 is REACHED by the second row, so the
    // third is left out (cut); a cap of 21 is not reached until the third, which is the last
    // row, so nothing is left out. `>` instead of `>=` would flip the first of these.
    const std::vector<int> three{10, 10, 10};
    total = 0;
    CHECK(append_rows_until_byte_cap(three, 20, [&](int r) { return total += static_cast<std::size_t>(r); }));
    CHECK(total == 20);
    total = 0;
    CHECK_FALSE(append_rows_until_byte_cap(three, 21, [&](int r) { return total += static_cast<std::size_t>(r); }));
    CHECK(total == 30);
}
