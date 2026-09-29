/**
 * test_rest_instructions_productpacks.cpp — HTTP-level coverage for #4029's
 * new REST v1 routes: GET /api/v1/instructions[/{id}[/export]] and
 * GET /api/v1/product-packs[/{id}].
 *
 * Pattern matches test_rest_response_templates.cpp: register RestApiV1
 * routes against an in-process TestRouteSink and dispatch synthesised
 * requests directly into the captured handlers.
 *
 * Coverage:
 *   - GET /api/v1/instructions: full row shape, name/plugin/type/set_id/
 *     enabled_only/limit filters, byte-identical to the shared builder.
 *   - GET /api/v1/instructions/{id}: reconciled superset shape, 404 unknown id.
 *   - GET /api/v1/instructions/{id}/export: full export document, 404 unknown
 *     id (the deliberate divergence from the legacy route's 200 "{}" quirk).
 *   - GET /api/v1/product-packs: row shape (no yaml_source), name filter,
 *     byte-identical to the shared builder.
 *   - GET /api/v1/product-packs/{id}: detail shape (with yaml_source), 404
 *     unknown id.
 *   - 403 path: perm_fn denies (both domains).
 *   - 503 path: null store (both domains).
 */

#include "instruction_definition_model.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "product_pack_model.hpp"
#include "product_pack_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <expected>
#include <memory>
#include <optional>
#include <string>

using namespace yuzu::server;

namespace {

yuzu::test::PgTestTemplate ip4029_instr_tpl{
    "ip4029instr", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("ip4029instr template: store failed to migrate");
    }};

yuzu::test::PgTestTemplate ip4029_pp_tpl{
    "ip4029pp", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ProductPackStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("ip4029pp template: store failed to migrate");
    }};

struct IpHarness {
    yuzu::server::test::TestRouteSink sink;
    std::optional<yuzu::test::PostgresTestDb> instr_pg_db;
    std::optional<pg::PgPool> instr_pool;
    std::unique_ptr<InstructionStore> instruction_store;
    std::optional<yuzu::test::PostgresTestDb> pp_pg_db;
    std::optional<pg::PgPool> pp_pool;
    std::unique_ptr<ProductPackStore> product_pack_store;
    bool perm_grant{true};
    RestApiV1 api;

    IpHarness() : IpHarness(/*with_store=*/true) {}

    explicit IpHarness(bool with_store) {
        if (with_store)
            construct_stores();
        register_with(with_store);
    }

    // Manual equivalent of YUZU_REQUIRE_PG_DB_TPL (test_helpers.hpp) — the
    // macro declares a local, non-movable PostgresTestDb/PgPool, so it can't
    // populate a data member directly; emplace() constructs them in place
    // instead (mirrors test_rest_response_templates.cpp's RtHarness).
    void construct_stores() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        instr_pg_db.emplace(ip4029_instr_tpl);
        REQUIRE(instr_pg_db->available());
        instr_pool.emplace(pg::PgPool::Options{.conninfo = instr_pg_db->dsn(), .size = 4});
        REQUIRE(instr_pool->valid());
        instruction_store = std::make_unique<InstructionStore>(*instr_pool);
        REQUIRE(instruction_store->is_open());
        instruction_store->set_require_signed_definitions(false);

        pp_pg_db.emplace(ip4029_pp_tpl);
        REQUIRE(pp_pg_db->available());
        pp_pool.emplace(pg::PgPool::Options{.conninfo = pp_pg_db->dsn(), .size = 4});
        REQUIRE(pp_pool->valid());
        product_pack_store = std::make_unique<ProductPackStore>(*pp_pool);
        REQUIRE(product_pack_store->is_open());
        product_pack_store->set_require_signed_packs(false);
    }

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
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
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
                            with_store ? product_pack_store.get() : nullptr);
    }

    std::string make_def(const std::string& plugin = "system_info_4029ip") {
        InstructionDefinition d;
        d.name = "Get Hostname";
        d.version = "1.0";
        d.plugin = plugin;
        d.action = "query";
        d.type = "question";
        d.description = "test";
        d.enabled = true;
        d.instruction_set_id = "set-ip4029";
        d.approval_mode = "auto";
        d.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n";
        auto r = instruction_store->create_definition(d);
        REQUIRE(r.has_value());
        return *r;
    }

    std::string make_pack() {
        constexpr const char* kBundle = R"(apiVersion: yuzu.io/v1alpha1
kind: ProductPack
name: test-pack-ip4029
version: 1.0.0
description: REST v1 test pack
---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
name: test-instruction-ip4029
)";
        auto install_fn = [](const std::string&,
                             const std::string&) -> std::expected<std::string, std::string> {
            return std::string{"item-id"};
        };
        auto r = product_pack_store->install(kBundle, install_fn);
        REQUIRE(r.has_value());
        return *r;
    }
};

} // namespace

// ── GET /api/v1/instructions ────────────────────────────────────────────

TEST_CASE("GET /api/v1/instructions: full row shape, byte-identical to shared builder",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    h.make_def("system_info_4029ip_list");

    auto res = h.sink.Get("/api/v1/instructions?plugin=system_info_4029ip_list");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    REQUIRE_FALSE(body["data"].empty());
    auto row = body["data"][0];
    CHECK(row.contains("instruction_set_id"));
    CHECK(row.contains("created_at"));
    CHECK(row.contains("updated_at"));

    auto defs = h.instruction_store->query_definitions();
    REQUIRE(defs.has_value());
    REQUIRE_FALSE(defs->empty());
    CHECK(row == yuzu::server::instruction_definition_row_json((*defs)[0]));
}

TEST_CASE("GET /api/v1/instructions: name/set_id/enabled_only/limit filters",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    h.make_def("system_info_4029ip_filt");

    auto res = h.sink.Get("/api/v1/instructions?set_id=set-ip4029&enabled_only=true&limit=5");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE_FALSE(body["data"].empty());
    for (const auto& row : body["data"])
        CHECK(row["instruction_set_id"] == "set-ip4029");
}

TEST_CASE("GET /api/v1/instructions: enabled_only=false does NOT filter (Gate 4/8 #4029 fix)",
          "[rest][v1][instructions][4029][pg]") {
    // Regression test for the presence-vs-value bug: `?enabled_only=false`
    // used to still filter to enabled-only (req.has_param() alone gated the
    // filter, ignoring the actual value) -- silently narrowing the result
    // set with no signal to the caller. A disabled definition must be
    // visible with `enabled_only=false` (and absent with `enabled_only=true`).
    IpHarness h;
    InstructionDefinition d;
    d.name = "Disabled Def";
    d.version = "1.0";
    d.plugin = "system_info_4029ip_disabled";
    d.action = "query";
    d.type = "question";
    d.description = "test";
    d.enabled = false;
    d.approval_mode = "auto";
    d.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n";
    auto created = h.instruction_store->create_definition(d);
    REQUIRE(created.has_value());

    {
        auto res = h.sink.Get(
            "/api/v1/instructions?plugin=system_info_4029ip_disabled&enabled_only=false");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE_FALSE(body["data"].empty());
        CHECK(body["data"][0]["enabled"] == false);
    }
    {
        auto res = h.sink.Get(
            "/api/v1/instructions?plugin=system_info_4029ip_disabled&enabled_only=true");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        CHECK(body["data"].empty());
    }
}

TEST_CASE("GET /api/v1/instructions: bad limit is 400, null store is 503, denied perm is 403",
          "[rest][v1][instructions][4029][pg]") {
    {
        IpHarness h;
        auto res = h.sink.Get("/api/v1/instructions?limit=not-a-number");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    {
        IpHarness h;
        h.perm_grant = false;
        auto res = h.sink.Get("/api/v1/instructions");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        IpHarness h(/*with_store=*/false);
        auto res = h.sink.Get("/api/v1/instructions");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

// ── GET /api/v1/instructions/{id} ───────────────────────────────────────

TEST_CASE("GET /api/v1/instructions/{id}: reconciled superset shape",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    auto id = h.make_def();

    auto res = h.sink.Get("/api/v1/instructions/" + id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    auto got = body["data"];
    CHECK(got.contains("gather_ttl_seconds"));
    CHECK(got.contains("response_ttl_days"));
    CHECK(got.contains("created_by"));
    CHECK(got.contains("approval_mode"));
    CHECK(got.contains("parameter_schema"));
    CHECK(got.contains("result_schema"));
    CHECK(got.contains("yaml_source"));

    auto def_result = h.instruction_store->get_definition(id);
    REQUIRE(def_result.has_value());
    REQUIRE(def_result->has_value());
    CHECK(got == yuzu::server::instruction_definition_detail_json(**def_result));
}

TEST_CASE("GET /api/v1/instructions/{id}: unknown id is 404",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    auto res = h.sink.Get("/api/v1/instructions/does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}

// ── GET /api/v1/instructions/{id}/export ────────────────────────────────

TEST_CASE("GET /api/v1/instructions/{id}/export: full export document",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    auto id = h.make_def();

    auto res = h.sink.Get("/api/v1/instructions/" + id + "/export");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    auto got = body["data"];
    CHECK(got.contains("concurrency_mode"));
    CHECK(got.contains("visualization_spec"));
    CHECK(got.contains("response_templates_spec"));

    auto def_result = h.instruction_store->get_definition(id);
    REQUIRE(def_result.has_value());
    REQUIRE(def_result->has_value());
    CHECK(got == yuzu::server::instruction_definition_export_json(**def_result));
}

TEST_CASE("GET /api/v1/instructions/{id}/export: unknown id is 404 (diverges from the "
          "legacy route's 200 \"{}\" quirk)",
          "[rest][v1][instructions][4029][pg]") {
    IpHarness h;
    auto res = h.sink.Get("/api/v1/instructions/does-not-exist/export");
    REQUIRE(res);
    CHECK(res->status == 404);
}

// ── GET /api/v1/product-packs ───────────────────────────────────────────

TEST_CASE("GET /api/v1/product-packs: row shape (no yaml_source), byte-identical to shared "
          "builder",
          "[rest][v1][product_pack][4029][pg]") {
    IpHarness h;
    auto pack_id = h.make_pack();

    auto res = h.sink.Get("/api/v1/product-packs?name=test-pack-ip4029");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE_FALSE(body["data"].empty());
    auto row = body["data"][0];
    CHECK(row["id"] == pack_id);
    CHECK(row.contains("item_count"));
    CHECK_FALSE(row.contains("yaml_source"));

    auto packs = h.product_pack_store->list({});
    REQUIRE(packs.has_value());
    auto it = std::find_if(packs->begin(), packs->end(),
                           [&](const auto& p) { return p.id == pack_id; });
    REQUIRE(it != packs->end());
    CHECK(row == yuzu::server::product_pack_row_json(*it));
}

TEST_CASE("GET /api/v1/product-packs: bad limit is 400, null store is 503, denied perm is 403",
          "[rest][v1][product_pack][4029][pg]") {
    {
        IpHarness h;
        auto res = h.sink.Get("/api/v1/product-packs?limit=not-a-number");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    {
        IpHarness h;
        h.perm_grant = false;
        auto res = h.sink.Get("/api/v1/product-packs");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        IpHarness h(/*with_store=*/false);
        auto res = h.sink.Get("/api/v1/product-packs");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

// ── GET /api/v1/product-packs/{id} ──────────────────────────────────────

TEST_CASE("GET /api/v1/product-packs/{id}: detail shape (with yaml_source)",
          "[rest][v1][product_pack][4029][pg]") {
    IpHarness h;
    auto pack_id = h.make_pack();

    auto res = h.sink.Get("/api/v1/product-packs/" + pack_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    auto got = body["data"];
    CHECK(got["id"] == pack_id);
    REQUIRE(got.contains("items"));
    REQUIRE_FALSE(got["items"].empty());
    CHECK(got["items"][0].contains("yaml_source"));

    auto pack_result = h.product_pack_store->get(pack_id);
    REQUIRE(pack_result.has_value());
    REQUIRE(pack_result->has_value());
    CHECK(got == yuzu::server::product_pack_detail_json(**pack_result));
}

TEST_CASE("GET /api/v1/product-packs/{id}: unknown id is 404",
          "[rest][v1][product_pack][4029][pg]") {
    IpHarness h;
    auto res = h.sink.Get("/api/v1/product-packs/does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}
