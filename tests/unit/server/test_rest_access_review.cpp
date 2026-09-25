/**
 * test_rest_access_review.cpp — HTTP-level (and MCP-twin) coverage for the
 * `/api/v1/access-reviews*` family (Periodic Access Reviews, SOC 2 CC6.2):
 * `GET .../export`, `GET /access-reviews` (list campaigns), `POST
 * /access-reviews`, `GET /{id}`, `POST /{id}/attestations`,
 * `POST /{id}/close`; plus the MCP twins `export_access_review`,
 * `list_access_reviews`, `open_access_review`, `get_access_review`,
 * `record_attestation`, `close_access_review`.
 *
 * Pattern: register both `RestApiV1::register_routes(HttpRouteSink&, ...)`
 * (TestRouteSink, mirrors test_rest_engine_principal_roles.cpp) AND
 * `McpServer::build_handler(...)` (mirrors test_mcp_engine_principal_roles.cpp)
 * against the SAME underlying stores from one harness, so the #2291
 * classifier-completeness cases can drive both transports and compare. A real
 * `yuzu::MetricsRegistry` (not nullptr) is wired into BOTH transports so the
 * governance-round metrics wiring can be exercised directly.
 *
 * Covers: the AccessReview:Read/AccessReview:Attest gate split (both
 * transports; a dedicated narrow securable seeded ONLY to Administrator +
 * the Reviewer role — NOT AuditLog, so an AuditLog:Read-only principal like
 * Operator/PlatformEngineer is denied), the
 * engine-classed-session structural deny belt (both transports — REST gets a
 * raw 403, MCP's `deny_if_engine_session()` is a JSON-RPC-shaped kTierDenied
 * error at transport-level 200), 503 fail-loud on a source-store failure
 * (never a silent 200-empty), the decision enum (400, both transports), the
 * `format` enum (400 on REST), flag != revoke (no side effect on the
 * underlying grant), not_found -> 404 REST / kInvalidParams MCP (never 503 /
 * kInternalError), store-down -> 503 REST / kInternalError MCP, the
 * self-audit rows, the `GET /access-reviews` list route, MCP happy paths for
 * every tool, and metric presence/increment for the 4 governance-round
 * metrics (REST-only — the MCP twins are deliberately NOT double-counted,
 * per server.cpp's own wiring comment).
 *
 * PG-gated: EnginePrincipalStore, AccessReviewStore, AND RbacStore are all
 * born-on-Postgres (ADR-0006/0012). Skips when YUZU_TEST_POSTGRES_DSN is
 * unset, fails when set but broken (test_helpers.hpp skip-vs-fail contract).
 */

#include "access_review_store.hpp"
#include "engine_principal_store.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "test_auth_db_pg_helper.hpp"

using namespace yuzu::server;

namespace {

void setup_access_review_rest_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 2}};
    EnginePrincipalStore eps{pool};
    if (!eps.is_open())
        throw std::runtime_error("access_review rest template: engine principal store failed to "
                                 "migrate");
    AccessReviewStore ars{pool};
    if (!ars.is_open())
        throw std::runtime_error("access_review rest template: access review store failed to "
                                 "migrate");
    // RbacStore (ADR-0006) now coexists in the SAME database, in its own
    // `rbac_store` schema — AccessReviewHarness shares acc_rev_shared().pool
    // for all three stores rather than standing up a fourth PG database.
    RbacStore rbac{pool};
    if (!rbac.is_open())
        throw std::runtime_error("access_review rest template: rbac store failed to migrate");
}

yuzu::test::PgTestTemplate access_review_rest_tpl{"accrevresttx",
                                                   &setup_access_review_rest_pg_template};

// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per harness (the
// dominant Windows [pg]-shard cost, #2354 — see test_software_inventory_store
// .cpp's SwinvShared, the reference conversion). Built lazily; at testRunEnded
// the pool is drained and the clone dropped (keep_until_run_end). Every test
// in this file is CRUD-only against these stores (the store-down arms pass
// nullptr rather than breaking the schema), so there are no per-case-database
// carve-outs.
struct AccRevShared {
    yuzu::test::PostgresTestDb db{access_review_rest_tpl};
    std::optional<yuzu::server::pg::PgPool> pool;
    AccRevShared() {
        INFO("[AccRevShared] bundle status (blank == database came up OK): " << db.error());
        REQUIRE(db.available());
        pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = 6});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
AccRevShared& acc_rev_shared() {
    static AccRevShared s;
    return s;
}

// Restore the shared clone to its fresh state: all three stores' tables in
// one TRUNCATE (engine_principals is referenced by attest flows; RESTART
// IDENTITY keeps any serial ids deterministic per test). The RbacStore
// tables that tests actually write (roles/role_permissions/principal_roles/
// groups/group_members) are truncated too — every AccessReviewHarness
// re-constructs its own RbacStore on this same shared pool, and its
// constructor's seed_defaults() re-seeds the system roles on an empty
// table, so this reproduces the same fully-fresh-RBAC-state-per-test
// guarantee the old per-harness SQLite file gave. rbac_store.securable_types
// /operations/rbac_meta are static seed data no test mutates, so they're
// deliberately left alone (mirrors public.schema_meta below). public
// .schema_meta is deliberately untouched — the clone stays migrated, so the
// per-harness store ctors find the schema current and skip migration.
void acc_rev_reset() {
    auto lease = acc_rev_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = yuzu::server::pg::exec_params(
        lease.get(),
        "TRUNCATE engine_principal_store.engine_principals, "
        "access_review_store.access_review_campaign, "
        "access_review_store.access_review_attestation, "
        "rbac_store.principal_roles, rbac_store.group_members, rbac_store.groups, "
        "rbac_store.role_permissions, rbac_store.roles RESTART IDENTITY CASCADE",
        std::vector<std::string>{});
    INFO("[acc_rev_reset] " << PQresultErrorMessage(trunc.get()));
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

struct AuditRecord {
    std::string action, result, target_id, detail;
};

/// One harness driving BOTH the REST TestRouteSink and the MCP JSON-RPC
/// handler off the SAME RbacStore / AuthDB / EnginePrincipalStore /
/// AccessReviewStore — so a dual-transport test can assert the two agree.
///
/// `auth_db_available=false` simulates the export route's source-store-down
/// 503 path (build_access_review's own `!users` guard) without needing a
/// second harness type.
struct AccessReviewHarness {
    yuzu::server::test::TestRouteSink sink;

    yuzu::test::AuthDbPgShared auth_db;

    std::unique_ptr<RbacStore> rbac;
    std::unique_ptr<EnginePrincipalStore> eps;
    std::unique_ptr<AccessReviewStore> access_review_store;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};
    std::string session_principal_kind{"human"};
    std::string session_auth_source{"local"};
    bool auth_enabled{true};

    /// nullptr = always allow. Set to a predicate returning FALSE to deny a
    /// (securable_type, operation) pair — mirrors
    /// RestEngineRolesHarness::perm_override.
    std::function<bool(const std::string&, const std::string&)> perm_override;

    std::vector<AuditRecord> audit_log;

    /// When non-empty, `rest_audit_fn` returns false (simulating a persist
    /// failure) for exactly this action name — every other action still
    /// succeeds. Scoped to one action (rather than a blanket bool) so setup
    /// calls, e.g. opening a campaign before testing an attest/close-path
    /// audit failure, aren't collaterally broken. Mirrors InvHarness's
    /// audit_should_fail in test_inventory_routes.cpp.
    std::string audit_fail_action;

    /// Real (not nullptr) registry — item G (governance hardening round)
    /// exercises the metric names/labels rest_api_v1.cpp actually touches.
    yuzu::MetricsRegistry metrics;

    RestApiV1 api;
    yuzu::server::mcp::McpServer mcp;
    yuzu::server::mcp::McpServer::HandlerFn mcp_handler;
    bool read_only_mode_{false};
    bool mcp_disabled_{false};

    /// `store_available=false` simulates the access-review-store-down 503/
    /// kInternalError path on BOTH transports (list/open/get/attest/close)
    /// without needing a third harness type — mirrors `auth_db_available`
    /// above.
    explicit AccessReviewHarness(bool auth_db_available = true, bool store_available = true) {
        // Redundant with AuthDbPgShared's own SKIP above (both gate on the
        // same env var) — kept as a defence-in-depth guard directly on this
        // fixture's own PG dependencies (RbacStore + EnginePrincipalStore +
        // AccessReviewStore, all on acc_rev_shared().pool).
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        acc_rev_reset();
        // RbacStore coexists in the SAME shared database as EnginePrincipalStore
        // /AccessReviewStore (own `rbac_store` schema) — acc_rev_reset() above
        // TRUNCATEs its user-data tables too, so each harness still gets fully
        // fresh RBAC state (the old per-harness SQLite file's guarantee).
        rbac = std::make_unique<RbacStore>(*acc_rev_shared().pool);
        REQUIRE(rbac->is_open());
        eps = std::make_unique<EnginePrincipalStore>(*acc_rev_shared().pool);
        REQUIRE(eps->is_open());
        access_review_store = std::make_unique<AccessReviewStore>(*acc_rev_shared().pool);
        REQUIRE(access_review_store->is_open());
        AccessReviewStore* ars_ptr = store_available ? access_review_store.get() : nullptr;

        AuthDB* auth_db_ptr = auth_db_available ? auth_db.get() : nullptr;

        auto rest_auth_fn = [this](const httplib::Request&,
                                   httplib::Response&) -> std::optional<auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            return s;
        };
        auto rest_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto rest_audit_fn = [this](const httplib::Request&, const std::string& action,
                                    const std::string& result, const std::string&,
                                    const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_fail_action.empty() || action != audit_fail_action;
        };

        // The access-review routes' `eps` local (rest_api_v1.cpp) is sourced
        // from the `engine_principal_store_` MEMBER (set via
        // set_engine_principal_store), NOT the `engine_principal_store`
        // register_routes PARAMETER (that parameter only backs the PR 4.2
        // grant-assignment routes) — MUST be called before register_routes()
        // per the setter's own doc comment (captures the pointer's value at
        // registration time).
        api.set_engine_principal_store(eps.get());

        api.register_routes(sink, rest_auth_fn, rest_perm_fn, rest_audit_fn,
                            /*rbac_store=*/rbac.get(),
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
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
                            /*engine_principal_store=*/eps.get(),
                            /*access_review_store=*/ars_ptr,
                            /*auth_db=*/auth_db_ptr,
                            /*directory_sync=*/nullptr);

        auto mcp_auth_fn = [this](const httplib::Request&,
                                  httplib::Response&) -> std::optional<auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            return s;
        };
        auto mcp_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                  const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto mcp_audit_fn = [this](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string&,
                                   const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };

        // Same member-vs-parameter split as RestApiV1 above: the access-review
        // tool handlers in mcp_server.cpp read `engine_principal_store_` (the
        // MEMBER), not the `engine_principal_store` build_handler parameter
        // (that one backs the PR 4.2 assign/unassign/list_engine_roles tools).
        mcp.set_engine_principal_store(eps.get());

        mcp_handler = mcp.build_handler(
            std::move(mcp_auth_fn), std::move(mcp_perm_fn), std::move(mcp_audit_fn),
            std::move(agents_fn),
            /*rbac_store=*/rbac.get(),
            /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr,
            /*audit_store=*/nullptr,
            /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr,
            /*policy_store=*/nullptr,
            /*mgmt_store=*/nullptr,
            /*approval_manager=*/nullptr,
            /*schedule_engine=*/nullptr, read_only_mode_, mcp_disabled_,
            /*dispatch_fn=*/nullptr,
            /*ca_store=*/nullptr,
            /*publish_crl_fn=*/nullptr,
            /*guaranteed_state_store=*/nullptr,
            /*dex_perf_fn=*/{},
            /*network_api=*/{},
            /*response_scope_fn=*/{},
            /*software_inventory_store=*/nullptr,
            /*metrics=*/&metrics,
            /*quarantine_store=*/nullptr,
            /*tag_push_fn=*/{},
            /*agent_registry=*/nullptr,
            /*scoped_perm_fn=*/{},
            /*sessions=*/nullptr,
            /*mcp_streaming_disabled=*/nullptr,
            /*mcp_streamed_post_enabled=*/nullptr,
            /*allowed_origins=*/{},
            /*software_licensing_store=*/nullptr,
            /*engine_principal_store=*/eps.get(),
            /*access_review_store=*/ars_ptr,
            /*auth_db=*/auth_db_ptr,
            /*directory_sync=*/nullptr);
    }

    std::unique_ptr<httplib::Response> mcp_call(const std::string& json_body) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/mcp/v1/";
        req.body = json_body;
        req.set_header("Content-Type", "application/json");
        auto res = std::make_unique<httplib::Response>();
        res->status = 200;
        REQUIRE(mcp_handler);
        mcp_handler(req, *res);
        return res;
    }

    std::unique_ptr<httplib::Response> mcp_call_tool(const std::string& name,
                                                      const nlohmann::json& args) {
        nlohmann::json req = {{"jsonrpc", "2.0"},
                              {"id", 1},
                              {"method", "tools/call"},
                              {"params", {{"name", name}, {"arguments", args}}}};
        return mcp_call(req.dump());
    }

    /// Opens a campaign over whatever grants currently exist and returns its
    /// campaign_id. REQUIREs 201.
    std::string open_campaign_rest(const std::string& title = "test campaign") {
        auto res = sink.Post("/api/v1/access-reviews",
                             nlohmann::json{{"title", title}}.dump());
        REQUIRE(res);
        REQUIRE(res->status == 201);
        auto body = nlohmann::json::parse(res->body);
        return body["data"]["campaign_id"].get<std::string>();
    }
};

} // namespace

// ── Gates: AccessReview:Read vs AccessReview:Attest ─────────────────────────
// A dedicated narrow securable — NOT AuditLog:Read/AuditLog:Attest — seeded
// ONLY to Administrator + the Reviewer role (rbac_store.cpp seed_defaults()).
// This is the exact over-disclosure fix: an AuditLog:Read-only principal
// (e.g. Operator, PlatformEngineer) must NOT be able to pull the fleet-wide
// grant graph merely because it also holds AuditLog:Read for unrelated
// reasons (auth-sample export etc.) — see #2225 round 2.

TEST_CASE("access-reviews: read routes require AccessReview:Read, write routes require "
          "AccessReview:Attest — denied without the right permission",
          "[pg][access_review][rest][gate]") {
    AccessReviewHarness h;

    SECTION("export denied without AccessReview:Read") {
        h.perm_override = [](const std::string& t, const std::string& op) {
            return !(t == "AccessReview" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/access-reviews/export");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("GET /{id} denied without AccessReview:Read") {
        h.perm_override = [](const std::string& t, const std::string& op) {
            return !(t == "AccessReview" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/access-reviews/whatever");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("open (POST /access-reviews) denied without AccessReview:Attest") {
        h.perm_override = [](const std::string& t, const std::string& op) {
            return !(t == "AccessReview" && op == "Attest");
        };
        auto res = h.sink.Post("/api/v1/access-reviews", R"({"title":"x"})");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("attestations denied without AccessReview:Attest") {
        h.perm_override = [](const std::string& t, const std::string& op) {
            return !(t == "AccessReview" && op == "Attest");
        };
        auto res = h.sink.Post("/api/v1/access-reviews/whatever/attestations",
                               R"({"principal_type":"user","principal_id":"a",)"
                               R"("role_name":"R","decision":"attested"})");
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("close denied without AccessReview:Attest") {
        h.perm_override = [](const std::string& t, const std::string& op) {
            return !(t == "AccessReview" && op == "Attest");
        };
        auto res = h.sink.Post("/api/v1/access-reviews/whatever/close", "");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

TEST_CASE("access-reviews: a session with only AccessReview:Read can export but not attest",
          "[pg][access_review][rest][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AccessReview" && op == "Read"; // ONLY Read is granted
    };

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    CHECK(export_res->status == 200);

    auto open_res = h.sink.Post("/api/v1/access-reviews", R"({"title":"x"})");
    REQUIRE(open_res);
    CHECK(open_res->status == 403);

    auto attest_res = h.sink.Post("/api/v1/access-reviews/whatever/attestations",
                                  R"({"principal_type":"user","principal_id":"a",)"
                                  R"("role_name":"R","decision":"attested"})");
    REQUIRE(attest_res);
    CHECK(attest_res->status == 403);

    auto close_res = h.sink.Post("/api/v1/access-reviews/whatever/close", "");
    REQUIRE(close_res);
    CHECK(close_res->status == 403);
}

TEST_CASE("access-reviews: an AuditLog:Read-only principal is denied all six ops — the "
          "over-disclosure #2225 round 2 closes (Operator/PlatformEngineer no longer pull "
          "the grant graph via their unrelated AuditLog:Read grant)",
          "[pg][access_review][rest][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AuditLog" && op == "Read"; // AuditLog:Read only — NOT AccessReview
    };

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    CHECK(export_res->status == 403);

    auto list_res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(list_res);
    CHECK(list_res->status == 403);

    auto get_res = h.sink.Get("/api/v1/access-reviews/whatever");
    REQUIRE(get_res);
    CHECK(get_res->status == 403);

    auto open_res = h.sink.Post("/api/v1/access-reviews", R"({"title":"x"})");
    REQUIRE(open_res);
    CHECK(open_res->status == 403);

    auto attest_res = h.sink.Post("/api/v1/access-reviews/whatever/attestations",
                                  R"({"principal_type":"user","principal_id":"a",)"
                                  R"("role_name":"R","decision":"attested"})");
    REQUIRE(attest_res);
    CHECK(attest_res->status == 403);

    auto close_res = h.sink.Post("/api/v1/access-reviews/whatever/close", "");
    REQUIRE(close_res);
    CHECK(close_res->status == 403);
}

TEST_CASE("MCP: an AuditLog:Read-only principal is denied all six access-review tools — the "
          "over-disclosure #2225 round 2 closes, MCP twin",
          "[pg][access_review][mcp][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AuditLog" && op == "Read"; // AuditLog:Read only — NOT AccessReview
    };

    auto export_res = h.mcp_call_tool("export_access_review", nlohmann::json::object());
    REQUIRE(export_res);
    CHECK(export_res->status == 403);

    auto list_res = h.mcp_call_tool("list_access_reviews", nlohmann::json::object());
    REQUIRE(list_res);
    CHECK(list_res->status == 403);

    auto get_res = h.mcp_call_tool("get_access_review", {{"campaign_id", "whatever"}});
    REQUIRE(get_res);
    CHECK(get_res->status == 403);

    auto open_res = h.mcp_call_tool("open_access_review", {{"title", "x"}});
    REQUIRE(open_res);
    CHECK(open_res->status == 403);

    auto attest_res = h.mcp_call_tool("record_attestation", {{"campaign_id", "whatever"},
                                                              {"principal_type", "user"},
                                                              {"principal_id", "a"},
                                                              {"role_name", "R"},
                                                              {"decision", "attested"}});
    REQUIRE(attest_res);
    CHECK(attest_res->status == 403);

    auto close_res = h.mcp_call_tool("close_access_review", {{"campaign_id", "whatever"}});
    REQUIRE(close_res);
    CHECK(close_res->status == 403);
}

TEST_CASE("access-reviews: a Reviewer-equivalent grant (AccessReview:Read + "
          "AccessReview:Attest) can perform all six ops — the seeded Reviewer role's shape",
          "[pg][access_review][rest][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AccessReview" && (op == "Read" || op == "Attest");
    };
    REQUIRE(h.rbac->create_role({.name = "ReviewerAllowRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("revallow", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "revallow", "ReviewerAllowRole"}).has_value());

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    CHECK(export_res->status == 200);

    auto list_before_res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(list_before_res);
    CHECK(list_before_res->status == 200);

    const auto cid = h.open_campaign_rest("reviewer allow test");

    auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(get_res);
    CHECK(get_res->status == 200);

    auto list_res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(list_res);
    CHECK(list_res->status == 200);
    CHECK(list_res->body.find(cid) != std::string::npos);

    auto attest_res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "revallow"},
                      {"role_name", "ReviewerAllowRole"},
                      {"decision", "attested"}}
            .dump());
    REQUIRE(attest_res);
    CHECK(attest_res->status == 200);

    auto close_res = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
    REQUIRE(close_res);
    CHECK(close_res->status == 200);
}

TEST_CASE("MCP: a Reviewer-equivalent grant (AccessReview:Read + AccessReview:Attest) can "
          "perform all six access-review tools",
          "[pg][access_review][mcp][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AccessReview" && (op == "Read" || op == "Attest");
    };
    REQUIRE(h.rbac->create_role({.name = "McpReviewerAllowRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("mcprevallow", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "mcprevallow", "McpReviewerAllowRole"}).has_value());

    auto export_res = h.mcp_call_tool("export_access_review", nlohmann::json::object());
    REQUIRE(export_res);
    CHECK(export_res->status == 200);
    CHECK(export_res->body.find("\"error\"") == std::string::npos);

    auto open_res = h.mcp_call_tool("open_access_review", {{"title", "mcp reviewer allow"}});
    REQUIRE(open_res);
    CHECK(open_res->status == 200);
    auto open_body = nlohmann::json::parse(open_res->body);
    REQUIRE(open_body.contains("result"));
    const std::string cid =
        open_body["result"]["structuredContent"]["campaign_id"].get<std::string>();

    auto get_res = h.mcp_call_tool("get_access_review", {{"campaign_id", cid}});
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    CHECK(get_res->body.find("\"error\"") == std::string::npos);

    auto list_res = h.mcp_call_tool("list_access_reviews", nlohmann::json::object());
    REQUIRE(list_res);
    CHECK(list_res->status == 200);
    CHECK(list_res->body.find(cid) != std::string::npos);

    auto attest_res = h.mcp_call_tool("record_attestation", {{"campaign_id", cid},
                                                              {"principal_type", "user"},
                                                              {"principal_id", "mcprevallow"},
                                                              {"role_name", "McpReviewerAllowRole"},
                                                              {"decision", "attested"}});
    REQUIRE(attest_res);
    CHECK(attest_res->status == 200);
    CHECK(attest_res->body.find("\"error\"") == std::string::npos);

    auto close_res = h.mcp_call_tool("close_access_review", {{"campaign_id", cid}});
    REQUIRE(close_res);
    CHECK(close_res->status == 200);
    CHECK(close_res->body.find("\"error\"") == std::string::npos);
}

// ── Engine-classed session structural deny belt ─────────────────────────────

TEST_CASE("access-reviews: an engine-classed session is denied on every route",
          "[pg][access_review][rest][engine_deny]") {
    AccessReviewHarness h;
    h.session_principal_kind = "engine"; // perm_fn stays permissive (nullptr override)

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    CHECK(export_res->status == 403);

    auto open_res = h.sink.Post("/api/v1/access-reviews", R"({"title":"x"})");
    REQUIRE(open_res);
    CHECK(open_res->status == 403);

    auto get_res = h.sink.Get("/api/v1/access-reviews/whatever");
    REQUIRE(get_res);
    CHECK(get_res->status == 403);

    auto attest_res = h.sink.Post("/api/v1/access-reviews/whatever/attestations",
                                  R"({"principal_type":"user","principal_id":"a",)"
                                  R"("role_name":"R","decision":"attested"})");
    REQUIRE(attest_res);
    CHECK(attest_res->status == 403);

    auto close_res = h.sink.Post("/api/v1/access-reviews/whatever/close", "");
    REQUIRE(close_res);
    CHECK(close_res->status == 403);
}

// ── 503 fail-loud, never a silent 200-empty ─────────────────────────────────

TEST_CASE("export: fails loud with 503 when a source store is unavailable, never a silent "
          "200-empty",
          "[pg][access_review][rest][503]") {
    AccessReviewHarness h{/*auth_db_available=*/false};
    auto res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 envelope shape carries a correlation_id — never a bare empty "data":[].
    CHECK(res->body.find("correlation_id") != std::string::npos);
    CHECK(res->body.find("\"total\":0") == std::string::npos);
}

// ── decision enum ────────────────────────────────────────────────────────────

TEST_CASE("attestations: decision outside {attested,flagged_revoke} -> 400",
          "[pg][access_review][rest][decision]") {
    AccessReviewHarness h;
    auto res = h.sink.Post("/api/v1/access-reviews/whatever/attestations",
                           R"({"principal_type":"user","principal_id":"a","role_name":"R",)"
                           R"("decision":"maybe"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ── wrong-typed JSON body fields degrade to 400, never an uncaught 500 ──────
// `access_review_str_field`'s is_string guard treats a wrong-typed field
// (number/array/null) as absent rather than throwing nlohmann::json's
// type_error, so these hit the ordinary "required field missing" 400 path.

TEST_CASE("open campaign: wrong-typed title degrades to 400, never 500",
          "[pg][access_review][rest][badtype]") {
    AccessReviewHarness h;
    for (const std::string body : {R"({"title":123})", R"({"title":[]})", R"({"title":null})"}) {
        INFO("body=" << body);
        auto res = h.sink.Post("/api/v1/access-reviews", body);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
}

TEST_CASE("attestations: wrong-typed decision/principal_type degrades to 400, never 500",
          "[pg][access_review][rest][badtype]") {
    AccessReviewHarness h;

    SECTION("decision not a string") {
        auto res = h.sink.Post(
            "/api/v1/access-reviews/whatever/attestations",
            nlohmann::json{{"principal_type", "user"},
                          {"principal_id", "a"},
                          {"role_name", "R"},
                          {"decision", 123}}
                .dump());
        REQUIRE(res);
        CHECK(res->status == 400);
    }

    SECTION("principal_type not a string") {
        auto res = h.sink.Post(
            "/api/v1/access-reviews/whatever/attestations",
            nlohmann::json{{"principal_type", 123},
                          {"principal_id", "a"},
                          {"role_name", "R"},
                          {"decision", "attested"}}
                .dump());
        REQUIRE(res);
        CHECK(res->status == 400);
    }
}

// ── Sec-Audit-Failed on the mutation paths — set-and-proceed, mirrors export ─

TEST_CASE("access-reviews: an audit-persist failure on open/attest/close still commits the "
          "mutation and surfaces Sec-Audit-Failed",
          "[pg][access_review][rest][audit][secauditfailed]") {
    SECTION("open") {
        AccessReviewHarness h;
        h.audit_fail_action = "access_review.campaign_opened";
        auto res = h.sink.Post("/api/v1/access-reviews", R"({"title":"audit fail open"})");
        REQUIRE(res);
        CHECK(res->status == 201); // still committed
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        auto body = nlohmann::json::parse(res->body);
        const auto cid = body["data"]["campaign_id"].get<std::string>();

        // The campaign really was opened — a subsequent (audit-succeeding)
        // read finds it.
        h.audit_fail_action.clear();
        auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
        REQUIRE(get_res);
        CHECK(get_res->status == 200);
        CHECK(get_res->get_header_value("Sec-Audit-Failed").empty());
    }

    SECTION("attest") {
        AccessReviewHarness h;
        REQUIRE(h.rbac->create_role({.name = "AuditFailRole", .description = "d"}).has_value());
        REQUIRE(
            h.auth_db->upsert_user("auditfailuser", "hash", "salt", auth::Role::user).has_value());
        REQUIRE(h.rbac->assign_role({"user", "auditfailuser", "AuditFailRole"}).has_value());
        const auto cid = h.open_campaign_rest("audit fail attest");

        h.audit_fail_action = "access_review.attested";
        auto res = h.sink.Post(
            "/api/v1/access-reviews/" + cid + "/attestations",
            nlohmann::json{{"principal_type", "user"},
                          {"principal_id", "auditfailuser"},
                          {"role_name", "AuditFailRole"},
                          {"decision", "attested"}}
                .dump());
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");

        // The attestation really was recorded.
        h.audit_fail_action.clear();
        auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
        REQUIRE(get_res);
        CHECK(get_res->body.find("\"attested\"") != std::string::npos);
    }

    SECTION("close") {
        AccessReviewHarness h;
        const auto cid = h.open_campaign_rest("audit fail close");

        h.audit_fail_action = "access_review.closed";
        auto res = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");

        // The close really committed — a re-close 404s (already closed).
        h.audit_fail_action.clear();
        auto reclose_res = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
        REQUIRE(reclose_res);
        CHECK(reclose_res->status == 404);
    }
}

// ── format enum (REST-only — MCP export has no format concept) #2291 ───────

TEST_CASE("export: format classifier — json|csv 200, anything else 400",
          "[pg][access_review][rest][format][2291]") {
    AccessReviewHarness h;

    auto json_res = h.sink.Get("/api/v1/access-reviews/export?format=json");
    REQUIRE(json_res);
    CHECK(json_res->status == 200);
    CHECK(json_res->get_header_value("Content-Type").find("json") != std::string::npos);

    auto csv_res = h.sink.Get("/api/v1/access-reviews/export?format=csv");
    REQUIRE(csv_res);
    CHECK(csv_res->status == 200);
    CHECK(csv_res->body.starts_with("principal_type,principal_id,"));

    auto default_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(default_res);
    CHECK(default_res->status == 200); // default format=json

    auto bad_res = h.sink.Get("/api/v1/access-reviews/export?format=xml");
    REQUIRE(bad_res);
    CHECK(bad_res->status == 400);
}

// ── decision enum parity across REST and MCP twins #2291 ───────────────────

TEST_CASE("record_attestation decision validity is consistent across REST and the MCP twin",
          "[pg][access_review][rest][mcp][decision][2291]") {
    AccessReviewHarness h;

    SECTION("valid decisions -> not a 400/invalid-params rejection on either transport") {
        for (const std::string decision : {"attested", "flagged_revoke"}) {
            INFO("decision=" << decision);
            auto rest_res = h.sink.Post(
                "/api/v1/access-reviews/bogus-campaign/attestations",
                nlohmann::json{{"principal_type", "user"},
                              {"principal_id", "a"},
                              {"role_name", "R"},
                              {"decision", decision}}
                    .dump());
            REQUIRE(rest_res);
            // Neither transport rejects a VALID decision at the enum-validation
            // step — both proceed to the store, which then 404s on the bogus
            // campaign (not 400 — the enum check itself passed).
            CHECK(rest_res->status == 404);

            auto mcp_res = h.mcp_call_tool("record_attestation",
                                          {{"campaign_id", "bogus-campaign"},
                                           {"principal_type", "user"},
                                           {"principal_id", "a"},
                                           {"role_name", "R"},
                                           {"decision", decision}});
            REQUIRE(mcp_res);
            CHECK(mcp_res->status == 200); // JSON-RPC transport-level 200 either way
            // kInvalidParams for the enum check is -32602; not_found also maps to
            // kInvalidParams (mcp_error_for_access_review_msg), so distinguish by
            // the "not_found:" substring the store's error message carries.
            CHECK(mcp_res->body.find("not_found:") != std::string::npos);
            CHECK(mcp_res->body.find("decision must be") == std::string::npos);
        }
    }

    SECTION("invalid decision -> 400 REST / invalid-params MCP, on BOTH transports") {
        auto rest_res = h.sink.Post(
            "/api/v1/access-reviews/bogus-campaign/attestations",
            nlohmann::json{{"principal_type", "user"},
                          {"principal_id", "a"},
                          {"role_name", "R"},
                          {"decision", "maybe"}}
                .dump());
        REQUIRE(rest_res);
        CHECK(rest_res->status == 400);

        auto mcp_res = h.mcp_call_tool("record_attestation", {{"campaign_id", "bogus-campaign"},
                                                              {"principal_type", "user"},
                                                              {"principal_id", "a"},
                                                              {"role_name", "R"},
                                                              {"decision", "maybe"}});
        REQUIRE(mcp_res);
        CHECK(mcp_res->status == 200); // JSON-RPC transport-level 200; error is in the body
        CHECK(mcp_res->body.find("\"error\"") != std::string::npos);
        CHECK(mcp_res->body.find("decision must be") != std::string::npos);
    }
}

// ── flag != revoke ───────────────────────────────────────────────────────────

TEST_CASE("attestations: decision=flagged_revoke records evidence only — the underlying grant "
          "is never mutated",
          "[pg][access_review][rest][flag]") {
    AccessReviewHarness h;
    REQUIRE(h.rbac->create_role({.name = "SomeRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("alice", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "alice", "SomeRole"}).has_value());
    REQUIRE_FALSE(h.rbac->get_principal_roles("user", "alice").empty());

    const auto cid = h.open_campaign_rest("flag test");

    auto res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "alice"},
                      {"role_name", "SomeRole"},
                      {"decision", "flagged_revoke"},
                      {"justification", "looks stale"}}
            .dump());
    REQUIRE(res);
    CHECK(res->status == 200);

    // The grant is UNCHANGED — no unassign_role side effect. flagged_revoke is
    // evidence-only; acting on it is a separate, explicit operator write.
    auto roles_after = h.rbac->get_principal_roles("user", "alice");
    REQUIRE(roles_after.size() == 1);
    CHECK(roles_after[0].role_name == "SomeRole");

    // The campaign DOES show the flag.
    auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    CHECK(get_res->body.find("\"flagged_revoke\"") != std::string::npos);
}

// ── not_found -> 404, never 503 ─────────────────────────────────────────────

TEST_CASE("attest/get/close on an unknown campaign_id -> 404, not 503",
          "[pg][access_review][rest][not_found]") {
    AccessReviewHarness h;

    auto get_res = h.sink.Get("/api/v1/access-reviews/no-such-campaign");
    REQUIRE(get_res);
    CHECK(get_res->status == 404);

    auto attest_res = h.sink.Post(
        "/api/v1/access-reviews/no-such-campaign/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "a"},
                      {"role_name", "R"},
                      {"decision", "attested"}}
            .dump());
    REQUIRE(attest_res);
    CHECK(attest_res->status == 404);

    auto close_res = h.sink.Post("/api/v1/access-reviews/no-such-campaign/close", "");
    REQUIRE(close_res);
    CHECK(close_res->status == 404);
}

// ── Self-audit ───────────────────────────────────────────────────────────────

TEST_CASE("access-reviews: export/attest/flag emit their own self-audit rows",
          "[pg][access_review][rest][audit]") {
    AccessReviewHarness h;
    REQUIRE(h.rbac->create_role({.name = "AuditRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("bob", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "bob", "AuditRole"}).has_value());

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    REQUIRE(export_res->status == 200);
    bool export_audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "access_review.exported" && a.result == "success")
            export_audited = true;
    CHECK(export_audited);

    const auto cid = h.open_campaign_rest("audit test");
    bool open_audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "access_review.campaign_opened" && a.result == "success")
            open_audited = true;
    CHECK(open_audited);

    auto attest_res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "bob"},
                      {"role_name", "AuditRole"},
                      {"decision", "attested"}}
            .dump());
    REQUIRE(attest_res);
    REQUIRE(attest_res->status == 200);
    bool attested_audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "access_review.attested" && a.result == "success")
            attested_audited = true;
    CHECK(attested_audited);

    auto flag_res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "bob"},
                      {"role_name", "AuditRole"},
                      {"decision", "flagged_revoke"}}
            .dump());
    REQUIRE(flag_res);
    REQUIRE(flag_res->status == 200);
    bool flagged_audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "access_review.flagged" && a.result == "success")
            flagged_audited = true;
    CHECK(flagged_audited);
}

// ── GET /api/v1/access-reviews (list campaigns, H-2) ────────────────────────

TEST_CASE("GET /access-reviews: happy path returns opened campaigns", "[pg][access_review][rest][list]") {
    AccessReviewHarness h;
    const auto cid = h.open_campaign_rest("List me");

    auto res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find(cid) != std::string::npos);
    CHECK(res->body.find("\"List me\"") != std::string::npos);
}

TEST_CASE("GET /access-reviews: 403 without AccessReview:Read", "[pg][access_review][rest][list]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Read");
    };
    auto res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /access-reviews: an engine-classed session is denied",
          "[pg][access_review][rest][list][engine_deny]") {
    AccessReviewHarness h;
    h.session_principal_kind = "engine";
    auto res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /access-reviews: 503 when the access review store is unavailable, never a "
          "silent 200-empty",
          "[pg][access_review][rest][list][503]") {
    AccessReviewHarness h{/*auth_db_available=*/true, /*store_available=*/false};
    auto res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── MCP happy paths ──────────────────────────────────────────────────────────

TEST_CASE("MCP: export_access_review / open_access_review / get_access_review / "
          "list_access_reviews / close_access_review happy paths, end to end",
          "[pg][access_review][mcp][happy]") {
    AccessReviewHarness h;
    REQUIRE(h.rbac->create_role({.name = "McpRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("mcpuser", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "mcpuser", "McpRole"}).has_value());

    // export_access_review — the granted principal appears in the export.
    {
        auto res = h.mcp_call_tool("export_access_review", nlohmann::json::object());
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        auto& sc = body["result"]["structuredContent"];
        REQUIRE(sc.contains("rows"));
        bool found = false;
        for (auto& row : sc["rows"])
            if (row["principal_id"] == "mcpuser")
                found = true;
        CHECK(found);
    }

    // open_access_review — freezes the current population into a campaign.
    std::string campaign_id;
    {
        auto res = h.mcp_call_tool("open_access_review", {{"title", "mcp campaign"}});
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        auto& sc = body["result"]["structuredContent"];
        REQUIRE(sc.contains("campaign_id"));
        campaign_id = sc["campaign_id"].get<std::string>();
        CHECK_FALSE(campaign_id.empty());
        CHECK(sc["grant_count"].get<std::int64_t>() >= 1);
    }

    // get_access_review — full evidentiary state of the campaign just opened.
    {
        auto res = h.mcp_call_tool("get_access_review", {{"campaign_id", campaign_id}});
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        auto& sc = body["result"]["structuredContent"];
        CHECK(sc["campaign"]["campaign_id"] == campaign_id);
        CHECK(sc["campaign"]["status"] == "open");
        CHECK(sc["pending_count"].get<std::int64_t>() >= 1);
    }

    // list_access_reviews — the campaign appears in the roster.
    {
        auto res = h.mcp_call_tool("list_access_reviews", nlohmann::json::object());
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        auto& sc = body["result"]["structuredContent"];
        bool found = false;
        for (auto& c : sc["campaigns"])
            if (c["campaign_id"] == campaign_id)
                found = true;
        CHECK(found);
    }

    // close_access_review — happy close.
    {
        auto res = h.mcp_call_tool("close_access_review", {{"campaign_id", campaign_id}});
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        auto& sc = body["result"]["structuredContent"];
        CHECK(sc["closed"] == true);
    }

    // The closed status is now visible via get_access_review too.
    {
        auto res = h.mcp_call_tool("get_access_review", {{"campaign_id", campaign_id}});
        REQUIRE(res);
        auto body = nlohmann::json::parse(res->body);
        CHECK(body["result"]["structuredContent"]["campaign"]["status"] == "closed");
    }
}

TEST_CASE("MCP: close_access_review — not_found maps to kInvalidParams, store-down maps to "
          "kInternalError",
          "[pg][access_review][mcp][close]") {
    SECTION("not_found -> kInvalidParams (mirrors the REST twin's 404, never 503-shaped)") {
        AccessReviewHarness h;
        auto res = h.mcp_call_tool("close_access_review", {{"campaign_id", "no-such-campaign"}});
        REQUIRE(res);
        CHECK(res->status == 200); // JSON-RPC transport-level 200; error is in the body
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    }

    SECTION("store down -> kInternalError (retryable — mirrors the REST twin's 503)") {
        AccessReviewHarness h{/*auth_db_available=*/true, /*store_available=*/false};
        auto res = h.mcp_call_tool("close_access_review", {{"campaign_id", "whatever"}});
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    }
}

// ── MCP gate-split + engine-deny ─────────────────────────────────────────────

TEST_CASE("MCP: a session with only AccessReview:Read can export/get/list but not "
          "open/attest/close",
          "[pg][access_review][mcp][gate]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return t == "AccessReview" && op == "Read"; // ONLY Read granted
    };

    auto export_res = h.mcp_call_tool("export_access_review", nlohmann::json::object());
    REQUIRE(export_res);
    CHECK(export_res->status == 200);
    CHECK(export_res->body.find("\"error\"") == std::string::npos);

    // get_access_review reaches the store (permission check passed) and 404s
    // on the bogus campaign — proof it wasn't stopped at the permission gate.
    auto get_res = h.mcp_call_tool("get_access_review", {{"campaign_id", "whatever"}});
    REQUIRE(get_res);
    CHECK(get_res->status == 200);
    CHECK(get_res->body.find("not_found:") != std::string::npos);

    auto list_res = h.mcp_call_tool("list_access_reviews", nlohmann::json::object());
    REQUIRE(list_res);
    CHECK(list_res->status == 200);
    CHECK(list_res->body.find("\"error\"") == std::string::npos);

    // Write tools are denied at the permission gate — the mock perm_fn sets a
    // raw 403 (mirrors require_permission), same as the REST gate tests.
    auto open_res = h.mcp_call_tool("open_access_review", {{"title", "x"}});
    REQUIRE(open_res);
    CHECK(open_res->status == 403);

    auto attest_res = h.mcp_call_tool("record_attestation",
                                      {{"campaign_id", "whatever"},
                                       {"principal_type", "user"},
                                       {"principal_id", "a"},
                                       {"role_name", "R"},
                                       {"decision", "attested"}});
    REQUIRE(attest_res);
    CHECK(attest_res->status == 403);

    auto close_res = h.mcp_call_tool("close_access_review", {{"campaign_id", "whatever"}});
    REQUIRE(close_res);
    CHECK(close_res->status == 403);
}

TEST_CASE("MCP: an engine-classed session is denied (kTierDenied) on every access-review tool",
          "[pg][access_review][mcp][engine_deny]") {
    AccessReviewHarness h;
    h.session_principal_kind = "engine"; // perm_fn stays permissive (nullptr override)

    // deny_if_engine_session() is a JSON-RPC-shaped kTierDenied error at
    // transport-level 200 — unlike a permission denial (which the mock
    // perm_fn surfaces as a raw 403), this is the tool handler's OWN belt,
    // exercised AFTER perm_fn has already allowed the call through.
    auto check_denied = [](const std::unique_ptr<httplib::Response>& res) {
        REQUIRE(res);
        CHECK(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == yuzu::server::mcp::kTierDenied);
    };

    check_denied(h.mcp_call_tool("export_access_review", nlohmann::json::object()));
    check_denied(h.mcp_call_tool("open_access_review", {{"title", "x"}}));
    check_denied(h.mcp_call_tool("get_access_review", {{"campaign_id", "whatever"}}));
    check_denied(h.mcp_call_tool("list_access_reviews", nlohmann::json::object()));
    check_denied(h.mcp_call_tool("record_attestation", {{"campaign_id", "whatever"},
                                                        {"principal_type", "user"},
                                                        {"principal_id", "a"},
                                                        {"role_name", "R"},
                                                        {"decision", "attested"}}));
    check_denied(h.mcp_call_tool("close_access_review", {{"campaign_id", "whatever"}}));
}

// ── Metrics presence + increment (governance hardening round) ───────────────

TEST_CASE("access-reviews: the 4 new metrics are wired with the documented names/labels and "
          "increment on their respective operation (REST-only — server.cpp's own wiring "
          "comment says the MCP twins are deliberately not double-counted)",
          "[pg][access_review][rest][metrics]") {
    AccessReviewHarness h;
    // Pre-seed exactly as server.cpp does at startup (the "Periodic Access
    // Reviews (SOC 2 CC6.2) feature metrics" block) — rest_api_v1.cpp's
    // handlers only INCREMENT an already-registered series
    // (MetricsRegistry::counter/histogram are get-or-create), so replicating
    // the pre-seed here reproduces the production wiring and pins the exact
    // name+label contract those handlers depend on.
    h.metrics.describe("yuzu_access_review_export_total", "d", "counter");
    for (const char* format : {"json", "csv"})
        h.metrics.counter("yuzu_access_review_export_total", {{"format", format}});
    h.metrics.describe("yuzu_access_review_export_duration_seconds", "d", "histogram");
    h.metrics.histogram("yuzu_access_review_export_duration_seconds");
    h.metrics.describe("yuzu_access_review_campaigns_opened_total", "d", "counter");
    h.metrics.counter("yuzu_access_review_campaigns_opened_total");
    h.metrics.describe("yuzu_access_review_attestations_total", "d", "counter");
    for (const char* decision : {"attested", "flagged_revoke"})
        h.metrics.counter("yuzu_access_review_attestations_total", {{"decision", decision}});

    // Pre-seeded to 0.
    CHECK(h.metrics.counter("yuzu_access_review_export_total", {{"format", "json"}}).value() ==
         0);
    CHECK(h.metrics.counter("yuzu_access_review_export_total", {{"format", "csv"}}).value() == 0);
    CHECK(h.metrics.counter("yuzu_access_review_campaigns_opened_total").value() == 0);
    CHECK(h.metrics.counter("yuzu_access_review_attestations_total", {{"decision", "attested"}})
             .value() == 0);
    CHECK(h.metrics
             .counter("yuzu_access_review_attestations_total", {{"decision", "flagged_revoke"}})
             .value() == 0);
    CHECK(h.metrics.histogram("yuzu_access_review_export_duration_seconds").snapshot().count == 0);

    // export ?format=json increments export_total{format=json} + observes the
    // duration histogram; the csv label is untouched.
    REQUIRE(h.sink.Get("/api/v1/access-reviews/export?format=json"));
    CHECK(h.metrics.counter("yuzu_access_review_export_total", {{"format", "json"}}).value() ==
         1);
    CHECK(h.metrics.counter("yuzu_access_review_export_total", {{"format", "csv"}}).value() == 0);
    CHECK(h.metrics.histogram("yuzu_access_review_export_duration_seconds").snapshot().count == 1);

    // export ?format=csv increments the csv label independently.
    REQUIRE(h.sink.Get("/api/v1/access-reviews/export?format=csv"));
    CHECK(h.metrics.counter("yuzu_access_review_export_total", {{"format", "csv"}}).value() == 1);
    CHECK(h.metrics.histogram("yuzu_access_review_export_duration_seconds").snapshot().count == 2);

    // A grant to freeze, so the attestation write below lands on a real row.
    REQUIRE(h.rbac->create_role({.name = "MetricsRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("metricsuser", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "metricsuser", "MetricsRole"}).has_value());

    // open_campaign increments campaigns_opened_total.
    const auto cid = h.open_campaign_rest("metrics test");
    CHECK(h.metrics.counter("yuzu_access_review_campaigns_opened_total").value() == 1);

    // attest/flag increments attestations_total{decision}, independently.
    auto attest_res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "metricsuser"},
                      {"role_name", "MetricsRole"},
                      {"decision", "attested"}}
            .dump());
    REQUIRE(attest_res);
    REQUIRE(attest_res->status == 200);
    CHECK(h.metrics.counter("yuzu_access_review_attestations_total", {{"decision", "attested"}})
             .value() == 1);
    CHECK(h.metrics
             .counter("yuzu_access_review_attestations_total", {{"decision", "flagged_revoke"}})
             .value() == 0);

    auto flag_res = h.sink.Post(
        "/api/v1/access-reviews/" + cid + "/attestations",
        nlohmann::json{{"principal_type", "user"},
                      {"principal_id", "metricsuser"},
                      {"role_name", "MetricsRole"},
                      {"decision", "flagged_revoke"}}
            .dump());
    REQUIRE(flag_res);
    REQUIRE(flag_res->status == 200);
    CHECK(h.metrics
             .counter("yuzu_access_review_attestations_total", {{"decision", "flagged_revoke"}})
             .value() == 1);
    // The re-attest (same grant) does not double-count the attested label.
    CHECK(h.metrics.counter("yuzu_access_review_attestations_total", {{"decision", "attested"}})
             .value() == 1);
}
