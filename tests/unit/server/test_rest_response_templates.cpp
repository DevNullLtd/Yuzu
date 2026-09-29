/**
 * test_rest_response_templates.cpp — HTTP-level coverage for the
 * /api/v1/definitions/{id}/response-templates surface added in issue #254.
 *
 * Pattern matches test_rest_visualization.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised requests
 * directly into the captured handlers.
 *
 * Coverage:
 *   - GET list synthesises the __default__ when no operator templates exist
 *   - GET list omits the synthesised default once an operator default is set
 *   - GET /{tid} returns the synth default for the kDefaultId sentinel
 *   - POST creates and assigns an id
 *   - POST rejects malformed JSON
 *   - PUT replaces in place
 *   - PUT rejects __default__ as a path id
 *   - DELETE removes the entry
 *   - DELETE rejects __default__
 *   - 403 path: perm_fn denies
 *   - 503 path: null instruction_store
 *   - 404 path: definition does not exist
 */

#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include "../test_helpers.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// InstructionStore is now a migrated Postgres store (ADR-0058).
yuzu::test::PgTestTemplate rt_instr_tpl{"restrtinstr", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    InstructionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rt_instr template: store failed to migrate");
}};

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct RtHarness {
    yuzu::server::test::TestRouteSink sink;
    std::optional<yuzu::test::PostgresTestDb> inst_pg_db;
    std::optional<pg::PgPool> inst_pool;
    std::unique_ptr<InstructionStore> instruction_store;
    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;
    RestApiV1 api;

    RtHarness() {
        construct_store();
        register_with(/*store_present=*/true);
    }

    explicit RtHarness(bool with_store) {
        if (with_store)
            construct_store();
        register_with(with_store);
    }

    // Manual equivalent of YUZU_REQUIRE_PG_DB_TPL (test_helpers.hpp) — the
    // macro declares a local, non-movable PostgresTestDb/PgPool, so it can't
    // populate a data member directly; emplace() constructs them in place
    // instead (mirrors test_discovery_routes.cpp's DiscoverHarness).
    void construct_store() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        inst_pg_db.emplace(rt_instr_tpl);
        INFO("[RtHarness instr fixture] status (blank == came up OK): " << inst_pg_db->error());
        REQUIRE(inst_pg_db->available());
        inst_pool.emplace(pg::PgPool::Options{.conninfo = inst_pg_db->dsn(), .size = 4});
        REQUIRE(inst_pool->valid());
        instruction_store = std::make_unique<InstructionStore>(*inst_pool);
        REQUIRE(instruction_store->is_open());
        // #1073: opt out of signature enforcement for these tests — they
        // exercise the import + response-templates normalisation, not the
        // signature gate.
        instruction_store->set_require_signed_definitions(false);
    }

    ~RtHarness() { instruction_store.reset(); }

    void register_with(bool with_store) {
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
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            with_store ? instruction_store.get() : nullptr,
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
                            /*guaranteed_state_store=*/nullptr);
    }

    /// Insert a definition and return its id.
    std::string make_def(const std::string& plugin = "procfetch",
                         const std::string& result_schema = "") {
        InstructionDefinition d;
        d.id = "def-rt-" + std::to_string(audit_log.size() + 1);
        d.name = "rt-test-" + d.id;
        d.type = "question";
        d.plugin = plugin;
        d.action = "list";
        d.result_schema = result_schema;
        auto created = instruction_store->create_definition(d);
        REQUIRE(created.has_value());
        return *created;
    }
};

} // namespace

TEST_CASE("REST templates: GET list synthesises default when none authored",
          "[rest][response_templates][list]") {
    RtHarness h;
    auto def_id = h.make_def("procfetch");
    auto res = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    auto& arr = body["data"];
    REQUIRE(arr.is_array());
    REQUIRE(arr.size() == 1);
    CHECK(arr[0]["id"] == "__default__");
    CHECK(arr[0]["default"] == true);
    // procfetch columns excluding Agent
    REQUIRE(arr[0]["columns"].is_array());
    CHECK(arr[0]["columns"].size() == 4);
}

TEST_CASE("REST templates: GET list uses result_schema when populated",
          "[rest][response_templates][list]") {
    RtHarness h;
    auto def_id = h.make_def("procfetch", R"([{"name":"hostname","type":"string"},
                         {"name":"uptime","type":"int64"}])");
    auto res = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    auto cols = body["data"][0]["columns"];
    REQUIRE(cols.size() == 2);
    CHECK(cols[0] == "hostname");
    CHECK(cols[1] == "uptime");
}

TEST_CASE("REST templates: GET /__default__ returns the synthesised default",
          "[rest][response_templates][get]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates/__default__");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["id"] == "__default__");
    CHECK(body["data"]["default"] == true);
}

TEST_CASE("REST templates: POST creates and assigns id", "[rest][response_templates][create]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                           R"({"name":"Failures only",
            "columns":["PID","Name"],
            "filters":[{"column":"Name","op":"contains","value":"chrome"}]})");
    REQUIRE(res);
    CHECK(res->status == 201);
    auto body = nlohmann::json::parse(res->body);
    auto id = body["data"]["id"].get<std::string>();
    CHECK(id.size() == 32);

    // Now list — synth default should be gone iff this template is the
    // operator's default; here it's not, so synth default survives.
    auto list = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(list);
    auto list_body = nlohmann::json::parse(list->body);
    REQUIRE(list_body["data"].is_array());
    CHECK(list_body["data"].size() == 2); // synth default + new template
    bool found_synth = false, found_new = false;
    for (auto& t : list_body["data"]) {
        if (t["id"] == "__default__")
            found_synth = true;
        if (t["id"] == id)
            found_new = true;
    }
    CHECK(found_synth);
    CHECK(found_new);
}

TEST_CASE("REST templates: POST with operator default suppresses synth default",
          "[rest][response_templates][create][default]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                           R"({"name":"My default","default":true})");
    REQUIRE(res);
    CHECK(res->status == 201);

    auto list = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(list);
    auto list_body = nlohmann::json::parse(list->body);
    REQUIRE(list_body["data"].is_array());
    CHECK(list_body["data"].size() == 1);
    CHECK(list_body["data"][0]["id"] != "__default__");
    CHECK(list_body["data"][0]["default"] == true);
}

TEST_CASE("REST templates: POST with malformed JSON → 400",
          "[rest][response_templates][create][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates", "not-json");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("invalid JSON") != std::string::npos);
}

TEST_CASE("REST templates: POST missing name → 400",
          "[rest][response_templates][create][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates", R"({})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("name") != std::string::npos);
}

TEST_CASE("REST templates: PUT replaces in place", "[rest][response_templates][update]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto post =
        h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates", R"({"name":"orig"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["data"]["id"].get<std::string>();

    auto put = h.sink.Put("/api/v1/definitions/" + def_id + "/response-templates/" + id,
                          R"({"name":"updated"})");
    REQUIRE(put);
    CHECK(put->status == 200);
    CHECK(nlohmann::json::parse(put->body)["data"]["name"] == "updated");
}

TEST_CASE("REST templates: PUT __default__ → 400",
          "[rest][response_templates][update][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto put = h.sink.Put("/api/v1/definitions/" + def_id + "/response-templates/__default__",
                          R"({"name":"hijack"})");
    REQUIRE(put);
    CHECK(put->status == 400);
    CHECK(put->body.find("reserved") != std::string::npos);
}

TEST_CASE("REST templates: DELETE removes the entry", "[rest][response_templates][delete]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto post = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                            R"({"name":"transient"})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["data"]["id"].get<std::string>();

    auto del = h.sink.Delete("/api/v1/definitions/" + def_id + "/response-templates/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);

    // After deletion the list is back to just the synthesised default.
    auto list = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(list);
    auto list_body = nlohmann::json::parse(list->body);
    CHECK(list_body["data"].size() == 1);
    CHECK(list_body["data"][0]["id"] == "__default__");
}

TEST_CASE("REST templates: DELETE __default__ → 400",
          "[rest][response_templates][delete][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto del = h.sink.Delete("/api/v1/definitions/" + def_id + "/response-templates/__default__");
    REQUIRE(del);
    CHECK(del->status == 400);
    CHECK(del->body.find("cannot be deleted") != std::string::npos);
}

TEST_CASE("REST templates: perm_fn denies → 403", "[rest][response_templates][rbac]") {
    RtHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/definitions/foo/response-templates");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST templates: null instruction_store → 503",
          "[rest][response_templates][unavailable]") {
    RtHarness h(/*with_store=*/false);
    auto res = h.sink.Get("/api/v1/definitions/foo/response-templates");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("service unavailable") != std::string::npos);
}

TEST_CASE("REST templates: unknown definition_id → 404", "[rest][response_templates][not_found]") {
    RtHarness h;
    auto res = h.sink.Get("/api/v1/definitions/does-not-exist/response-templates");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("definition not found") != std::string::npos);
}

// ─── Gate 7 hardening — qe-B1..B4 + sec-M1 + UP-8 + S-4 coverage ─────────

TEST_CASE("REST templates: PUT with non-existent template_id → 404 (qe-B1)",
          "[rest][response_templates][update][not_found]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Put("/api/v1/definitions/" + def_id + "/response-templates/abcd1234",
                          R"({"name":"phantom"})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("template not found") != std::string::npos);
}

TEST_CASE("REST templates: DELETE operator-default re-instates synth (qe-B2)",
          "[rest][response_templates][delete][default]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto post = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                            R"({"name":"My default","default":true})");
    REQUIRE(post);
    auto id = nlohmann::json::parse(post->body)["data"]["id"].get<std::string>();
    // Confirm synth is suppressed while operator default exists.
    {
        auto list = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
        REQUIRE(list);
        auto data = nlohmann::json::parse(list->body)["data"];
        REQUIRE(data.size() == 1);
        CHECK(data[0]["id"] != "__default__");
    }
    // Delete the operator default; synth must re-emerge.
    auto del = h.sink.Delete("/api/v1/definitions/" + def_id + "/response-templates/" + id);
    REQUIRE(del);
    CHECK(del->status == 200);
    auto list2 = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates");
    REQUIRE(list2);
    auto data2 = nlohmann::json::parse(list2->body)["data"];
    REQUIRE(data2.size() == 1);
    CHECK(data2[0]["id"] == "__default__");
    CHECK(data2[0]["default"] == true);
}

TEST_CASE("REST templates: malformed template_id rejected by route regex (qe-B4)",
          "[rest][response_templates][validation]") {
    // The regex kRtTemplateIdRegex is ^[A-Za-z0-9_-]{1,64}$. A request with
    // characters outside the allowed set (e.g. a slash, dot, or space) falls
    // through to the generic 404 because no route matches the pattern. This
    // test pins that contract — a template id with a slash never reaches
    // the handler, so neither the body parse nor the audit emission fire.
    RtHarness h;
    auto def_id = h.make_def();
    // a/b — slash splits the path; httplib treats the trailing 'b' as
    // beyond the second capture group, so no route matches. Our sink
    // returns nullptr in that case.
    auto res = h.sink.Get("/api/v1/definitions/" + def_id + "/response-templates/a%2Fb");
    // Either nullptr (no route matched) or a 4xx — both prove the regex
    // gate held.
    if (res)
        CHECK((res->status == 400 || res->status == 404));
}

TEST_CASE("REST templates: PUT/DELETE with perm denied → 403 (qe-S2)",
          "[rest][response_templates][rbac]") {
    RtHarness h;
    auto def_id = h.make_def();
    h.perm_grant = false;
    auto put =
        h.sink.Put("/api/v1/definitions/" + def_id + "/response-templates/x", R"({"name":"x"})");
    REQUIRE(put);
    CHECK(put->status == 403);
    auto del = h.sink.Delete("/api/v1/definitions/" + def_id + "/response-templates/x");
    REQUIRE(del);
    CHECK(del->status == 403);
    auto post =
        h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates", R"({"name":"x"})");
    REQUIRE(post);
    CHECK(post->status == 403);
}

TEST_CASE("REST templates: 503 on POST/PUT/DELETE with null store (qe-S6)",
          "[rest][response_templates][unavailable]") {
    RtHarness h(/*with_store=*/false);
    auto post = h.sink.Post("/api/v1/definitions/foo/response-templates", R"({"name":"x"})");
    REQUIRE(post);
    CHECK(post->status == 503);
    auto put = h.sink.Put("/api/v1/definitions/foo/response-templates/x", R"({"name":"x"})");
    REQUIRE(put);
    CHECK(put->status == 503);
    auto del = h.sink.Delete("/api/v1/definitions/foo/response-templates/x");
    REQUIRE(del);
    CHECK(del->status == 503);
}

TEST_CASE("REST templates: oversized POST body → 413 + audit (UP-8)",
          "[rest][response_templates][create][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    // 65 KiB of valid JSON — exceeds the 64 KiB cap. The cap is the first
    // gate after perm_fn / regex, so even malformed bodies above the cap
    // hit 413 before parse.
    std::string huge_body = R"({"name":")" + std::string(65 * 1024, 'a') + R"("})";
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates", huge_body);
    REQUIRE(res);
    CHECK(res->status == 413);
    CHECK(res->body.find("64 KiB") != std::string::npos);
    // Failure-audit emitted (sec-M1).
    REQUIRE(h.audit_log.size() >= 1);
    bool found_audit = false;
    for (const auto& r : h.audit_log) {
        // Audit vocabulary per audit-log.md: 4xx branches use "denied"
        // (S-7 alignment); only 5xx persist failures use "failure".
        if (r.action == "response_template.create" && r.result == "denied" &&
            r.detail.find("body_too_large") != std::string::npos) {
            found_audit = true;
            break;
        }
    }
    CHECK(found_audit);
}

TEST_CASE("REST templates: success audits emitted (sec-M1 / qe-S1)",
          "[rest][response_templates][audit]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto post = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                            R"({"name":"audited"})");
    REQUIRE(post);
    REQUIRE(post->status == 201);
    auto id = nlohmann::json::parse(post->body)["data"]["id"].get<std::string>();
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "response_template.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "InstructionDefinition");
    CHECK(h.audit_log[0].target_id == def_id);
    CHECK(h.audit_log[0].detail == id);

    auto put = h.sink.Put("/api/v1/definitions/" + def_id + "/response-templates/" + id,
                          R"({"name":"audited2"})");
    REQUIRE(put);
    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[1].action == "response_template.update");
    CHECK(h.audit_log[1].result == "success");

    auto del = h.sink.Delete("/api/v1/definitions/" + def_id + "/response-templates/" + id);
    REQUIRE(del);
    REQUIRE(h.audit_log.size() == 3);
    CHECK(h.audit_log[2].action == "response_template.delete");
    CHECK(h.audit_log[2].result == "success");
}

TEST_CASE("REST templates: POST validation failure emits audit (sec-M1)",
          "[rest][response_templates][audit][validation]") {
    RtHarness h;
    auto def_id = h.make_def();
    auto res = h.sink.Post("/api/v1/definitions/" + def_id + "/response-templates",
                           R"({})"); // missing name
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "response_template.create");
    CHECK(h.audit_log[0].result == "denied"); // 4xx → "denied" per audit-log.md
    CHECK(h.audit_log[0].detail.find("validation_failed") != std::string::npos);
}

TEST_CASE("REST templates: import_definition_json strips reserved __default__ id (S-4)",
          "[rest][response_templates][import]") {
    RtHarness h;
    // Import a definition whose responseTemplates carries a reserved id.
    // The import path must silently drop the bad element, leaving a clean
    // (empty) templates spec — REST PUT/DELETE cannot remove a stuck
    // reserved-id row, so dropping at import is the only safe path.
    std::string json_payload = R"({
        "id": "import-reserved-test",
        "name": "Import test",
        "type": "question",
        "plugin": "procfetch",
        "action": "list",
        "responseTemplates": [
            {"id": "__default__", "name": "Hijack"},
            {"id": "valid", "name": "Valid one"}
        ]
    })";
    auto created = h.instruction_store->import_definition_json(json_payload);
    REQUIRE(created.has_value());
    auto def = h.instruction_store->get_definition(*created);
    REQUIRE(def.has_value());
    REQUIRE(def->has_value());
    auto parsed_arr = nlohmann::json::parse((*def)->response_templates_spec);
    REQUIRE(parsed_arr.is_array());
    REQUIRE(parsed_arr.size() == 1);
    CHECK(parsed_arr[0]["id"] == "valid");
}

TEST_CASE("REST templates: import_definition_json drops oversized string form (sec-M4)",
          "[rest][response_templates][import][security]") {
    RtHarness h;
    // 300 KiB JSON-as-string exceeds the 256 KiB import cap; dropped to "[]".
    std::string huge = "[";
    for (int i = 0; i < 5000; ++i) {
        huge += R"({"id":"t)" + std::to_string(i) +
                R"(","name":"Name with padding aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},)";
    }
    huge.back() = ']';
    REQUIRE(huge.size() > 256 * 1024);
    nlohmann::json payload = {{"id", "import-oversize-test"},
                              {"name", "Oversize test"},
                              {"type", "question"},
                              {"plugin", "procfetch"},
                              {"action", "list"},
                              {"responseTemplates", huge}}; // string form, oversized
    auto created = h.instruction_store->import_definition_json(payload.dump());
    REQUIRE(created.has_value());
    auto def = h.instruction_store->get_definition(*created);
    REQUIRE(def.has_value());
    REQUIRE(def->has_value());
    CHECK((*def)->response_templates_spec == "[]");
}

// "REST templates: migration v3 probe-and-stamp on pre-existing column (qe-B3)"
// RETIRED (ADR-0058) — it hand-built a raw SQLite file at schema_meta v1 with
// the response_templates_spec column already present, to prove
// InstructionStore's probe-and-stamp guard could recognise a pre-existing
// column and skip re-running the ALTER (SQLite's "duplicate column name"
// hazard). That whole mechanism — the legacy_alters[] compat ALTERs and the
// v1→v2→v3 schema_meta probe-and-stamp dance — no longer exists: the
// Postgres schema is born fresh in a single v1 migration (no ALTER-table
// compat dance to test). Nothing analogous applies on Postgres.
