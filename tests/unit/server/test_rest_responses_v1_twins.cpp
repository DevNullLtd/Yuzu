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
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>

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

    RestApiV1 api;

    explicit RespV1Harness(pg::PgPool& pool) {
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
