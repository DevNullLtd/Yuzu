/**
 * test_rest_result_sets_tier_policy.cpp — #5047: the MCP tier/approval belt
 * (`AuthRoutes::require_tier_policy`, wired as `tier_policy_fn`) on the 4
 * `/api/v1/result-sets` JSON write routes (create/pin/unpin/delete).
 *
 * Before this fix these 4 routes had NO `perm_fn`/RBAC gate at all —
 * ownership (`owner_principal == session.username`) was the sole check —
 * so an MCP-tiered bearer token could reach the identical mutation its own
 * MCP tool (create_result_set/pin_result_set/unpin_result_set/
 * delete_result_set) is tier/approval-gated for, simply by calling REST
 * instead of `/mcp/v1/` (#520-class bypass). This file drives the REAL
 * `/api/v1/result-sets` REST surface (in-process `TestRouteSink`, #438)
 * with a REAL `ResultSetStore` and a fake `tier_policy_fn` wired through
 * the ACTUAL `mcp::tier_allows`/`mcp::requires_approval` logic
 * (`mcp_policy.hpp`) — same approach as `test_result_set_routes.cpp`'s
 * fragment-side coverage of the same fix, kept in a separate file because
 * the JSON CRUD write routes have no pre-existing dedicated test file
 * (`test_rest_result_sets_async.cpp` covers only the 3 async producers;
 * `test_chrome_ir_chain.cpp` is a narrow end-to-end narrative test).
 *
 * `AuthRoutes::require_tier_policy` itself is unit-tested directly, with a
 * REAL `AuthRoutes`, in `test_auth_routes.cpp` — this file's job is the
 * WIRING: is the belt actually reached on these 4 routes, with the right
 * (securable_type, operation), and does a denial actually stop the
 * mutation before it touches the store.
 */

#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "result_set_store.hpp"
#include "test_route_sink.hpp"

#include "mcp_policy.hpp" // mcp::tier_allows/requires_approval — the real logic this fake mirrors

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Shares the "resultset" template key with test_result_set_store.cpp /
// test_result_set_routes.cpp / test_chrome_ir_chain.cpp — identical setup
// body, so sharing the registry entry across files is safe (see any of
// those files' own PgTestTemplate doc comment).
yuzu::test::PgTestTemplate tier_policy_result_set_tpl{
    "resultset", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ResultSetStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("resultset tier-policy template: store failed to migrate");
    }};

/// Drives the real /api/v1/result-sets REST surface with a configurable
/// caller session and a genuine tier_policy_fn (mirrors
/// AuthRoutes::require_tier_policy exactly, via the same free functions it
/// calls — mcp_policy.hpp — so this harness cannot silently drift from the
/// production belt's actual rules).
struct Harness {
    std::unique_ptr<ResultSetStore> store;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    std::string session_username{"alice"};
    std::string session_mcp_tier;         // empty = untiered (default)
    std::string session_scope_service;    // non-empty = service-scoped token
    std::string session_principal_kind{"human"};

    explicit Harness(pg::PgPool& pool) {
        store = std::make_unique<ResultSetStore>(pool);
        REQUIRE(store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::user;
            s.mcp_tier = session_mcp_tier;
            s.token_scope_service = session_scope_service;
            s.principal_kind = session_principal_kind;
            return s;
        };
        // Not called by any of the 4 write routes under test (ownership is
        // their primary/only RBAC-shaped gate) — a permissive stub matches
        // test_chrome_ir_chain.cpp's identical precedent.
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };
        TierPolicyFn tier_policy_fn =
            [](const httplib::Request& req, httplib::Response& res, const auth::Session& session,
               const std::string& securable_type, const std::string& operation) -> bool {
            if (session.mcp_tier.empty())
                return true;
            if (!mcp::tier_allows(session.mcp_tier, securable_type, operation)) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"MCP token tier does not allow )"
                    R"(this operation"}})",
                    "application/json");
                return false;
            }
            if (req.path != "/mcp/v1/" &&
                mcp::requires_approval(session.mcp_tier, securable_type, operation)) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"operation requires approval for )"
                    R"(this MCP tier on this transport","remediation":"use the MCP )"
                    R"(ticket-then-recall flow (POST /mcp/v1/) or the dashboard"}})",
                    "application/json");
                return false;
            }
            return true;
        };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, store.get(), /*command_dispatch_fn=*/{},
            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
            /*network_api=*/{}, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
            /*software_inventory_store=*/nullptr,
            /*response_scope_fn=*/{},
            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
            /*stream_budget=*/nullptr,
            [](const auth::Session&) -> yuzu::server::authz::VisibleSet { return std::nullopt; },
            /*list_read_fn=*/{}, /*fleet_read_fn=*/{}, /*agents_fn=*/{},
            /*response_visible_set_fn=*/{}, /*dex_visible_fn=*/{},
            /*verify_api=*/{}, /*device_api=*/{}, /*dex_api=*/{}, /*dex_perf_api=*/{},
            /*guardian_api=*/{}, tier_policy_fn);
    }

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    std::string post_raw(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return res->body;
    }
    std::string del_raw(const std::string& path, int& status) {
        auto res = sink.dispatch("DELETE", path, "");
        REQUIRE(res != nullptr);
        status = res->status;
        return res->body;
    }
};

CreateRequest simple_req(const std::string& owner) {
    CreateRequest r;
    r.owner_principal = owner;
    r.source_kind = std::string(source_kind::kManualCurate);
    r.source_payload = "{}";
    return r;
}

} // namespace

TEST_CASE("REST /api/v1/result-sets: a supervised-tier bearer DELETE-ing its "
          "OWN result set is denied (403, approval-gated for supervised "
          "tier's Infrastructure:Delete) with a remediation pointing at the "
          "MCP ticket-then-recall flow — the exact cross-transport gap #5047 "
          "closes",
          "[pg][result_set][tier_policy][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);

    auto created = h.store->create_materialized(simple_req("alice"), {"dev-1"});
    REQUIRE(created.has_value());

    h.session_mcp_tier = "supervised";
    int status = 0;
    auto body = h.del_raw("/api/v1/result-sets/" + created->id, status);
    CHECK(status == 403);
    CHECK(body.find("approval") != std::string::npos);
    CHECK(body.find("ticket-then-recall") != std::string::npos);

    // Confirm the store was never touched — the set still exists.
    auto row = h.store->get(created->id);
    REQUIRE(row.has_value());
    CHECK(row->has_value());
}

TEST_CASE("REST /api/v1/result-sets: an operator-tier bearer create/pin on "
          "its own scope is denied (403) — Infrastructure:Write is not on "
          "tier_allows()'s operator allow-list",
          "[pg][result_set][tier_policy][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);

    h.session_mcp_tier = "operator";
    int status = 0;
    auto create_body = h.post_raw("/api/v1/result-sets", R"({"name":"t"})", status);
    CHECK(status == 403);

    auto created = h.store->create_materialized(simple_req("alice"), {"dev-1"});
    REQUIRE(created.has_value());
    auto pin_body = h.post_raw("/api/v1/result-sets/" + created->id + "/pin", "", status);
    CHECK(status == 403);

    // Never pinned.
    auto row = h.store->get(created->id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->pinned);
}

TEST_CASE("REST /api/v1/result-sets: an empty-tier (plain RBAC / untiered "
          "token) owner still succeeds on create/pin/unpin/delete — no "
          "regression from #5047",
          "[pg][result_set][tier_policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);
    // session_mcp_tier defaults to "" — untiered.

    int status = 0;
    auto created_json = h.post("/api/v1/result-sets", R"({"name":"t"})", status);
    REQUIRE(status == 201);
    const auto id = created_json["data"]["id"].get<std::string>();

    auto pinned = h.post("/api/v1/result-sets/" + id + "/pin", "", status);
    CHECK(status == 200);
    auto unpinned = h.post("/api/v1/result-sets/" + id + "/unpin", "", status);
    CHECK(status == 200);
    auto del_body = h.del_raw("/api/v1/result-sets/" + id, status);
    CHECK(status == 200);
}

TEST_CASE("REST /api/v1/result-sets: a non-owner is still 404'd on pin "
          "(unchanged by #5047 — ownership stays the primary gate)",
          "[pg][result_set][tier_policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);

    auto created = h.store->create_materialized(simple_req("bob"), {"dev-1"});
    REQUIRE(created.has_value());

    h.session_username = "alice"; // not the owner
    int status = 0;
    h.post_raw("/api/v1/result-sets/" + created->id + "/pin", "", status);
    CHECK(status == 404);
}

TEST_CASE("REST /api/v1/result-sets: a service-scoped token is still denied "
          "create (unchanged by #5047 — deny_fleet_wide_service_scoped runs "
          "before the tier belt)",
          "[pg][result_set][tier_policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);

    h.session_scope_service = "printers";
    int status = 0;
    h.post_raw("/api/v1/result-sets", R"({"name":"t"})", status);
    CHECK(status == 403);
}

TEST_CASE("REST /api/v1/result-sets: an engine-principal session (hard-"
          "locked to mcp_tier=readonly, api_token_store.cpp's "
          "validate_engine_mint §8) is now DENIED a write on its own result "
          "set — a REAL behavior change: this route has no perm_fn/engine-"
          "branch gate at all, so before #5047 ownership alone admitted it",
          "[pg][result_set][tier_policy][security][engine]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tier_policy_result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    Harness h(pool);

    h.session_username = "engine:svc-1";
    h.session_principal_kind = "engine";
    h.session_mcp_tier = "readonly";

    auto created = h.store->create_materialized(simple_req("engine:svc-1"), {"dev-1"});
    REQUIRE(created.has_value());

    int status = 0;
    h.post_raw("/api/v1/result-sets/" + created->id + "/pin", "", status);
    CHECK(status == 403);

    auto row = h.store->get(created->id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->pinned);
}
