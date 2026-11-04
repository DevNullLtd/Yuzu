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

#include "access_review_attest_gate.hpp"
#include "access_review_store.hpp"
#include "access_reviews_routes.hpp"
#include "engine_principal_store.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "openapi_spec_access.hpp"
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

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "test_auth_db_pg_helper.hpp"
#include "../test_log_capture.hpp"

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
// nullptr rather than breaking the schema), EXCEPT the cases that DROP a table to
// force a degrade: they take a per-test migrated clone through the harness's
// `own_pool` (the shared reset's TRUNCATE cannot repair a dropped table).
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
// /operations are static seed data no test mutates, so they're deliberately
// left alone (mirrors public.schema_meta below). public.schema_meta is
// deliberately untouched — the clone stays migrated, so the per-harness
// store ctors find the schema current and skip migration.
//
// rbac_store.rbac_meta's `rbac_enabled` row is NOT static — a test that
// calls RbacStore::set_rbac_enabled(true) (governance round 3 SHOULD-3,
// the genuinely-ENABLED rbac_enforcement route test) durably flips it, and
// TRUNCATE above never reaches rbac_meta (it isn't in that list, and
// row_meta is a key/value table shared with write_generation/backfill
// markers, not something to TRUNCATE wholesale). Reset the ONE key tests
// actually toggle back to the fresh-install default explicitly, in its own
// statement (PQexecParams is single-command-only, so this cannot ride the
// TRUNCATE above) — every harness's freshly-constructed RbacStore reads
// this durable row at its own first refresh, so this single UPDATE is
// sufficient; no generation bump is needed (there is no PRE-EXISTING
// in-process RbacStore instance whose cache this must invalidate — each
// harness constructs its own).
void acc_rev_reset() {
    auto lease = acc_rev_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = yuzu::server::pg::exec_params(
        lease.get(),
        "TRUNCATE engine_principal_store.engine_principals, "
        "access_review_store.access_review_campaign, "
        "access_review_store.access_review_attestation, "
        "access_review_store.access_review_attestation_history, "
        "rbac_store.principal_roles, rbac_store.group_members, rbac_store.groups, "
        "rbac_store.role_permissions, rbac_store.roles RESTART IDENTITY CASCADE",
        std::vector<std::string>{});
    INFO("[acc_rev_reset] " << PQresultErrorMessage(trunc.get()));
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);

    auto reset_enabled = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE rbac_store.rbac_meta SET value = 'false' WHERE key = 'rbac_enabled'",
        std::vector<std::string>{});
    INFO("[acc_rev_reset:rbac_enabled] " << PQresultErrorMessage(reset_enabled.get()));
    REQUIRE(reset_enabled.status() == PGRES_COMMAND_OK);
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

    /// What the MCP audit callback does. `fail` returns false (a persist failure), `throws` throws
    /// std::runtime_error (a bad_alloc-class fault), both only for `mcp_audit_mode_action` (empty =
    /// every action, the domain row AND the `mcp.<tool>` wrapper row). The REST callback has its own
    /// knob above; the MCP one defaulted to always-true before the attestation refusal tests.
    enum class McpAuditMode { ok, fail, throws };
    McpAuditMode mcp_audit_mode{McpAuditMode::ok};
    std::string mcp_audit_mode_action;

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
    ///
    /// `own_pool` puts the three stores on a caller-owned pool (a per-test migrated clone) instead
    /// of the file-wide shared one, and skips the shared reset. Needed where a test DROPs a table:
    /// the shared clone's TRUNCATE reset cannot repair a dropped table.
    explicit AccessReviewHarness(bool auth_db_available = true, bool store_available = true,
                                 yuzu::server::pg::PgPool* own_pool = nullptr) {
        // Redundant with AuthDbPgShared's own SKIP above (both gate on the
        // same env var) — kept as a defence-in-depth guard directly on this
        // fixture's own PG dependencies (RbacStore + EnginePrincipalStore +
        // AccessReviewStore, all on acc_rev_shared().pool).
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        yuzu::server::pg::PgPool* pool = own_pool;
        if (!pool) {
            acc_rev_reset();
            pool = &*acc_rev_shared().pool;
        }
        // The cookie session below is a browser session, and a browser write must name this site
        // (the access-review mutations refuse a cross-site or header-less cookie write). Every
        // call carries the same-origin headers a browser sends; the csrf cases override them.
        sink.default_headers = {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};
        // RbacStore coexists in the SAME shared database as EnginePrincipalStore
        // /AccessReviewStore (own `rbac_store` schema) — acc_rev_reset() above
        // TRUNCATEs its user-data tables too, so each harness still gets fully
        // fresh RBAC state (the old per-harness SQLite file's guarantee).
        rbac = std::make_unique<RbacStore>(*pool);
        REQUIRE(rbac->is_open());
        eps = std::make_unique<EnginePrincipalStore>(*pool);
        REQUIRE(eps->is_open());
        access_review_store = std::make_unique<AccessReviewStore>(*pool);
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
            if (mcp_audit_mode != McpAuditMode::ok &&
                (mcp_audit_mode_action.empty() || action == mcp_audit_mode_action)) {
                if (mcp_audit_mode == McpAuditMode::throws)
                    throw std::runtime_error("injected audit fault");
                return false;
            }
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
    // A3: the unconditional rbac_enforcement metadata line precedes the real
    // header — fresh harness, RBAC never toggled on in this harness.
    CHECK(csv_res->body.starts_with("# rbac_enforcement=disabled\r\n"
                                    "principal_type,principal_id,"));

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

// ── the store's forbidden: refusal -> 403 / kPermissionDenied, never 503 ────

// The store refuses a reviewer who is the subject of a user grant (#4752). The harness session is
// "admin", so attesting a grant whose principal_id is "admin" is the self-subject case on both
// transports; the campaign need not exist because the refusal precedes the lookup.
TEST_CASE("attest on a user grant naming the session user -> 403 REST / kPermissionDenied MCP",
          "[pg][access_review][rest][sod]") {
    AccessReviewHarness h;

    auto rest = h.sink.Post("/api/v1/access-reviews/no-such-campaign/attestations",
                            nlohmann::json{{"principal_type", "user"},
                                           {"principal_id", "admin"},
                                           {"role_name", "R"},
                                           {"decision", "attested"}}
                                .dump());
    REQUIRE(rest);
    CHECK(rest->status == 403);

    auto mcp = h.mcp_call_tool("record_attestation", {{"campaign_id", "no-such-campaign"},
                                                      {"principal_type", "user"},
                                                      {"principal_id", "admin"},
                                                      {"role_name", "R"},
                                                      {"decision", "attested"}});
    REQUIRE(mcp);
    auto body = nlohmann::json::parse(mcp->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kPermissionDenied);
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

    // A3 (RBAC delivery plan) — the campaign was frozen with RBAC's default
    // (never toggled in this harness) enforcement state.
    auto body = nlohmann::json::parse(res->body);
    bool found = false;
    for (auto& c : body["data"]) {
        if (c["campaign_id"] == cid) {
            found = true;
            CHECK(c["rbac_enforcement"] == "disabled");
        }
    }
    CHECK(found);
}

TEST_CASE("GET /access-reviews/{id} and GET .../export: rbac_enforcement is present and "
         "reflects RBAC's current state",
         "[pg][access_review][rest]") {
    AccessReviewHarness h;

    auto export_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(export_res);
    REQUIRE(export_res->status == 200);
    auto export_body = nlohmann::json::parse(export_res->body);
    REQUIRE(export_body.contains("rbac_enforcement"));
    CHECK(export_body["rbac_enforcement"] == "disabled");

    const auto cid = h.open_campaign_rest("Enforcement stamp test");
    auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    auto get_body = nlohmann::json::parse(get_res->body);
    CHECK(get_body["data"]["campaign"]["rbac_enforcement"] == "disabled");
}

// Governance round 3 SHOULD-3: every other route-level rbac_enforcement
// assertion in this file exercises only the harness's "disabled" default —
// the classifier itself is exhaustively unit-tested (test_rbac_store.cpp),
// and the wiring has been read-reviewed, but the actual end-to-end
// route -> handler -> field path for a genuinely ENABLED store was
// previously unverified by any test. `h.rbac->set_rbac_enabled(true)` is
// safe here: this harness's permission gate is `perm_override`
// (test-controlled), entirely independent of the real RBAC engine, so
// toggling the store's enabled flag changes ONLY the derived
// rbac_enforcement label, never what the harness permits.
//
// Governance round 4 (consistency-auditor): extended to also cover REST
// campaign-open (no dedicated "enabled" case existed for it either) and to
// assert the `rbac_enforcement=<value>` audit-detail field this round's fix
// added at all FOUR sites (REST export, REST campaign-open, MCP export, MCP
// campaign-open) — previously the field had zero regression coverage
// anywhere, so a format drift or a silent drop would compile and pass CI
// undetected. `assert_new_audit_detail` scopes its search to rows appended
// SINCE the `before` snapshot (REST and MCP share one action-name space —
// both log "access_review.exported"/"access_review.campaign_opened" into
// the SAME `h.audit_log` — so a snapshot-then-diff is what isolates "the
// row THIS call just produced" from an earlier call's row for the same
// action). Read-back under "enabled" (`GET /access-reviews` +
// `GET /access-reviews/{id}`) rides along on the REST-opened campaign.
TEST_CASE("rbac_enforcement reflects a genuinely ENABLED store across REST JSON/CSV export, "
         "REST + MCP campaign-open, and an MCP export tool, with rbac_enforcement=enabled on "
         "every audit row",
         "[pg][access_review][rest][mcp][audit]") {
    AccessReviewHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->is_rbac_enabled());

    auto assert_new_audit_detail = [&](std::size_t before, const std::string& action) {
        bool found = false;
        for (std::size_t i = before; i < h.audit_log.size(); ++i) {
            const auto& a = h.audit_log[i];
            if (a.action == action && a.result == "success") {
                found = true;
                CHECK(a.detail.find("rbac_enforcement=enabled") != std::string::npos);
            }
        }
        CHECK(found);
    };

    // REST JSON export.
    std::size_t before = h.audit_log.size();
    auto json_res = h.sink.Get("/api/v1/access-reviews/export");
    REQUIRE(json_res);
    REQUIRE(json_res->status == 200);
    auto json_body = nlohmann::json::parse(json_res->body);
    CHECK(json_body["rbac_enforcement"] == "enabled");
    assert_new_audit_detail(before, "access_review.exported");

    // REST CSV export (no separate audit row — same route, same action name;
    // already covered by the JSON call's assertion above).
    auto csv_res = h.sink.Get("/api/v1/access-reviews/export?format=csv");
    REQUIRE(csv_res);
    REQUIRE(csv_res->status == 200);
    CHECK(csv_res->body.starts_with("# rbac_enforcement=enabled\r\n"
                                    "principal_type,principal_id,"));

    // REST campaign-open.
    before = h.audit_log.size();
    const auto cid = h.open_campaign_rest("enabled state campaign");
    assert_new_audit_detail(before, "access_review.campaign_opened");

    // Read-back under "enabled": list + single-campaign GET.
    auto list_res = h.sink.Get("/api/v1/access-reviews");
    REQUIRE(list_res);
    REQUIRE(list_res->status == 200);
    auto list_body = nlohmann::json::parse(list_res->body);
    bool found_in_list = false;
    for (auto& c : list_body["data"]) {
        if (c["campaign_id"] == cid) {
            found_in_list = true;
            CHECK(c["rbac_enforcement"] == "enabled");
        }
    }
    CHECK(found_in_list);

    auto get_res = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(get_res);
    REQUIRE(get_res->status == 200);
    auto get_body = nlohmann::json::parse(get_res->body);
    CHECK(get_body["data"]["campaign"]["rbac_enforcement"] == "enabled");

    // MCP export_access_review.
    before = h.audit_log.size();
    auto mcp_export_res = h.mcp_call_tool("export_access_review", nlohmann::json::object());
    REQUIRE(mcp_export_res);
    CHECK(mcp_export_res->status == 200);
    auto mcp_export_body = nlohmann::json::parse(mcp_export_res->body);
    REQUIRE(mcp_export_body.contains("result"));
    CHECK(mcp_export_body["result"]["structuredContent"]["rbac_enforcement"] == "enabled");
    assert_new_audit_detail(before, "access_review.exported");

    // MCP open_access_review.
    before = h.audit_log.size();
    auto mcp_open_res =
        h.mcp_call_tool("open_access_review", {{"title", "mcp enabled state campaign"}});
    REQUIRE(mcp_open_res);
    CHECK(mcp_open_res->status == 200);
    auto mcp_open_body = nlohmann::json::parse(mcp_open_res->body);
    REQUIRE(mcp_open_body.contains("result"));
    assert_new_audit_detail(before, "access_review.campaign_opened");
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
        // A3 (RBAC delivery plan) — fresh harness, RBAC never toggled on.
        REQUIRE(sc.contains("rbac_enforcement"));
        CHECK(sc["rbac_enforcement"] == "disabled");
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
        CHECK(sc["campaign"]["rbac_enforcement"] == "disabled"); // A3 — frozen at open
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
        for (auto& c : sc["campaigns"]) {
            if (c["campaign_id"] == campaign_id) {
                found = true;
                CHECK(c["rbac_enforcement"] == "disabled"); // A3
            }
        }
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

// ── Browser-write gate: the three cookie-callable mutations ─────────────────────────────────
// POST /access-reviews, /{id}/attestations and /{id}/close are called by the Audit and reviews
// page and the Settings panel with a session cookie. A cookie is an ambient credential, so a
// cookie write must name this site in Origin/Referer (403 + a `csrf.denied` row) and a JSON body
// must be application/json (415). A token caller is not riding a cookie and keeps working.

namespace {

const std::unordered_map<std::string, std::string> kSiblingOrigin{
    {"Host", "yuzu.example"}, {"Origin", "https://evil.yuzu.example"}};
const std::unordered_map<std::string, std::string> kNoOrigin{{"Host", "yuzu.example"}};
const std::unordered_map<std::string, std::string> kSameOrigin{
    {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};
const std::unordered_map<std::string, std::string> kSameSiteReferer{
    {"Host", "yuzu.example"}, {"Referer", "https://yuzu.example/access/audit"}};

std::string attest_body(const std::string& user, const std::string& role,
                        const std::string& decision = "attested") {
    return nlohmann::json{{"principal_type", "user"},
                          {"principal_id", user},
                          {"role_name", role},
                          {"decision", decision}}
        .dump();
}

bool has_audit(const AccessReviewHarness& h, const std::string& action, const std::string& result,
               const std::string& target_id, const std::string& detail) {
    for (const auto& r : h.audit_log)
        if (r.action == action && r.result == result && r.target_id == target_id &&
            r.detail == detail)
            return true;
    return false;
}

// One real grant, so a campaign freezes one pending row the attestation can target.
void seed_one_grant(AccessReviewHarness& h) {
    REQUIRE(h.rbac->create_role({.name = "CsrfRole", .description = "d"}).has_value());
    REQUIRE(h.auth_db->upsert_user("csrfuser", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "csrfuser", "CsrfRole"}).has_value());
}

int pending_in(const AccessReviewHarness& h, const std::string& cid) {
    auto v = h.access_review_store->get_campaign(cid);
    REQUIRE(v.has_value());
    int n = 0;
    for (const auto& a : v->attestations)
        if (a.decision == "pending")
            ++n;
    return n;
}

} // namespace

TEST_CASE("access-reviews: a cookie write from another origin or with no Origin is refused 403 "
          "and changes nothing on all three mutations",
          "[pg][access_review][rest][security][csrf]") {
    AccessReviewHarness h;
    seed_one_grant(h);
    const auto cid = h.open_campaign_rest("csrf target");
    const int pending0 = pending_in(h, cid);
    REQUIRE(pending0 >= 1);
    const auto campaigns_before = h.access_review_store->list_campaigns();
    REQUIRE(campaigns_before.has_value());
    // Setup is done; from here every request names its own headers (the sink's same-origin
    // default would otherwise survive in the "no Origin" case).
    h.sink.default_headers.clear();

    for (const auto* headers : {&kSiblingOrigin, &kNoOrigin}) {
        h.audit_log.clear();

        auto open = h.sink.dispatch("POST", "/api/v1/access-reviews", R"({"title":"forged"})",
                                    "application/json", *headers);
        REQUIRE(open);
        CHECK(open->status == 403);
        CHECK(open->body.find("cross-site request refused") != std::string::npos);
        CHECK(has_audit(h, "csrf.denied", "denied", "/api/v1/access-reviews",
                        "cross-site or header-less browser write refused"));

        auto attest = h.sink.dispatch("POST", "/api/v1/access-reviews/" + cid + "/attestations",
                                      attest_body("csrfuser", "CsrfRole"), "application/json",
                                      *headers);
        REQUIRE(attest);
        CHECK(attest->status == 403);
        CHECK(attest->body.find("cross-site request refused") != std::string::npos);
        CHECK(has_audit(h, "csrf.denied", "denied", "/api/v1/access-reviews/{id}/attestations",
                        "cross-site or header-less browser write refused"));

        auto close = h.sink.dispatch("POST", "/api/v1/access-reviews/" + cid + "/close", "",
                                     "application/json", *headers);
        REQUIRE(close);
        CHECK(close->status == 403);
        CHECK(close->body.find("cross-site request refused") != std::string::npos);
        CHECK(has_audit(h, "csrf.denied", "denied", "/api/v1/access-reviews/{id}/close",
                        "cross-site or header-less browser write refused"));

        // No success row of any kind, and the stores are untouched.
        for (const auto& r : h.audit_log)
            CHECK(r.result == "denied");
    }
    const auto campaigns_after = h.access_review_store->list_campaigns();
    REQUIRE(campaigns_after.has_value());
    CHECK(campaigns_after->size() == campaigns_before->size());
    CHECK(pending_in(h, cid) == pending0);
    auto view = h.access_review_store->get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "open");
}

TEST_CASE("access-reviews: a cookie write with a text/plain or form body is refused 415; "
          "a cross-site one stays 403",
          "[pg][access_review][rest][security][csrf]") {
    AccessReviewHarness h;
    seed_one_grant(h);
    const auto cid = h.open_campaign_rest("content type target");
    const int pending0 = pending_in(h, cid);
    REQUIRE(pending0 >= 1);

    for (const char* ct : {"text/plain", "application/x-www-form-urlencoded", ""}) {
        INFO("content type: '" << ct << "'");
        h.audit_log.clear();
        auto open = h.sink.dispatch("POST", "/api/v1/access-reviews", R"({"title":"plain"})", ct,
                                    kSameOrigin);
        REQUIRE(open);
        CHECK(open->status == 415);
        CHECK(has_audit(h, "access_review.campaign_opened", "denied", "", "content_type_not_json"));

        auto attest = h.sink.dispatch("POST", "/api/v1/access-reviews/" + cid + "/attestations",
                                      attest_body("csrfuser", "CsrfRole"), ct, kSameOrigin);
        REQUIRE(attest);
        CHECK(attest->status == 415);
        CHECK(has_audit(h, "access_review.attested", "denied", "", "content_type_not_json"));

        // The cross-site check comes first: a forged text/plain write is a 403, not a 415.
        auto forged = h.sink.dispatch("POST", "/api/v1/access-reviews/" + cid + "/attestations",
                                      attest_body("csrfuser", "CsrfRole"), ct, kSiblingOrigin);
        REQUIRE(forged);
        CHECK(forged->status == 403);
    }
    CHECK(pending_in(h, cid) == pending0);
    const auto campaigns = h.access_review_store->list_campaigns();
    REQUIRE(campaigns.has_value());
    CHECK(campaigns->size() == 1);

    // Parameters and case on the media type are fine.
    auto ok = h.sink.dispatch("POST", "/api/v1/access-reviews", R"({"title":"charset"})",
                              "Application/JSON; charset=utf-8", kSameOrigin);
    REQUIRE(ok);
    CHECK(ok->status == 201);
}

TEST_CASE("access-reviews: same-origin and token calls still open; attest and close",
          "[pg][access_review][rest][security][csrf]") {
    AccessReviewHarness h;
    seed_one_grant(h);

    SECTION("a browser cookie session naming this site by Origin") {
        h.sink.default_headers = kSameOrigin;
        const auto cid = h.open_campaign_rest("same origin");
        const int pending0 = pending_in(h, cid);
        auto attest = h.sink.Post("/api/v1/access-reviews/" + cid + "/attestations",
                                  attest_body("csrfuser", "CsrfRole"));
        REQUIRE(attest);
        CHECK(attest->status == 200);
        CHECK(pending_in(h, cid) == pending0 - 1);
        auto close = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
        REQUIRE(close);
        CHECK(close->status == 200);
        for (const auto& r : h.audit_log)
            CHECK(r.action != "csrf.denied");
    }

    SECTION("a browser cookie session naming this site by Referer only") {
        h.sink.default_headers = kSameSiteReferer;
        const auto cid = h.open_campaign_rest("same site referer");
        auto close = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
        REQUIRE(close);
        CHECK(close->status == 200);
    }

    SECTION("an API-token caller sends no Origin and is not gated") {
        h.session_auth_source = "api_token";
        h.sink.default_headers.clear();
        const auto cid = h.open_campaign_rest("token caller");
        auto attest = h.sink.Post("/api/v1/access-reviews/" + cid + "/attestations",
                                  attest_body("csrfuser", "CsrfRole"));
        REQUIRE(attest);
        CHECK(attest->status == 200);
        auto close = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
        REQUIRE(close);
        CHECK(close->status == 200);
        for (const auto& r : h.audit_log)
            CHECK(r.action != "csrf.denied");
    }

    SECTION("a token caller is still held to a JSON body") {
        h.session_auth_source = "api_token";
        h.sink.default_headers.clear();
        auto open = h.sink.Post("/api/v1/access-reviews", R"({"title":"x"})", "text/plain");
        REQUIRE(open);
        CHECK(open->status == 415);
    }
}

TEST_CASE("access-reviews: the browser-write gate runs after the permission gate",
          "[pg][access_review][rest][security][csrf]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Attest");
    };
    // A caller without AccessReview:Attest is told so (the gate's own 403), not "cross-site".
    auto res = h.sink.dispatch("POST", "/api/v1/access-reviews", R"({"title":"x"})",
                               "application/json", kSiblingOrigin);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("cross-site") == std::string::npos);
    CHECK_FALSE(has_audit(h, "csrf.denied", "denied", "/api/v1/access-reviews",
                          "cross-site or header-less browser write refused"));
}

// ── Central campaign id validation (#6939) ──────────────────────────────────

namespace {

constexpr const char* kCampaignIdMessage =
    "campaign id must be 1-64 characters of A-Z, a-z, 0-9, _ or -";

/// Ids that must be refused before any store call. The first is the dangerous one: a real
/// campaign id followed by a NUL. libpq binds c_str(), so without the check the bound id would
/// truncate back to the real campaign and the mutation would land on it. TestRouteSink does NOT
/// percent-decode (test_route_sink.hpp), so the NUL is a literal byte in the path here; httplib
/// decodes `%00` in a route capture to exactly that byte in production.
std::vector<std::pair<std::string, std::string>> bad_campaign_ids(const std::string& real_cid) {
    return {{"real id then NUL", real_cid + std::string("\0x", 2)},
            {"NUL in the middle", std::string("abc\0def", 7)},
            {"65 characters", std::string(65, 'a')},
            {"disallowed dot", "bad.id"},
            {"disallowed colon", "a:b"}};
}

} // namespace

TEST_CASE("REST get/attest/close refuse a malformed campaign id with 400 and touch nothing",
          "[pg][access_review][rest][campaign_id][6939]") {
    AccessReviewHarness h;
    seed_one_grant(h);
    const auto cid = h.open_campaign_rest("id validation");
    const int pending0 = pending_in(h, cid);
    REQUIRE(pending0 >= 1);

    // Control: the same grant with a well-formed but unknown id reaches the store and is 404,
    // so the 400s below come from the id check and not from a routing or body problem.
    {
        auto control = h.sink.Get("/api/v1/access-reviews/abc");
        REQUIRE(control);
        CHECK(control->status == 404);
    }

    const nlohmann::json attest_body = {{"principal_type", "user"},
                                       {"principal_id", "csrfuser"},
                                       {"role_name", "CsrfRole"},
                                       {"decision", "attested"}};

    for (const auto& [label, bad] : bad_campaign_ids(cid)) {
        INFO("case: " << label << " (size " << bad.size() << ")");
        h.audit_log.clear();

        const auto expect_refused = [&](const std::unique_ptr<httplib::Response>& res) {
            REQUIRE(res);
            CHECK(res->status == 400);
            auto body = nlohmann::json::parse(res->body, nullptr, false);
            REQUIRE_FALSE(body.is_discarded());
            CHECK(body["error"]["message"] == kCampaignIdMessage);
        };

        expect_refused(h.sink.Get("/api/v1/access-reviews/" + bad));
        expect_refused(
            h.sink.Post("/api/v1/access-reviews/" + bad + "/attestations", attest_body.dump()));
        expect_refused(h.sink.Post("/api/v1/access-reviews/" + bad + "/close", ""));

        // No audit row for a refused id, on any of the three routes.
        CHECK(h.audit_log.empty());

        // The real campaign is untouched: still open, every row still pending.
        auto view = h.access_review_store->get_campaign(cid);
        REQUIRE(view.has_value());
        CHECK(view->campaign.status == "open");
        CHECK(pending_in(h, cid) == pending0);
    }

    // A valid id still works end to end on all three routes.
    auto get_ok = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(get_ok);
    CHECK(get_ok->status == 200);
    auto attest_ok =
        h.sink.Post("/api/v1/access-reviews/" + cid + "/attestations", attest_body.dump());
    REQUIRE(attest_ok);
    CHECK(attest_ok->status == 200);
    CHECK(pending_in(h, cid) == pending0 - 1);
    auto close_ok = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
    REQUIRE(close_ok);
    CHECK(close_ok->status == 200);
}

TEST_CASE("REST id check runs after the permission gate, so a denied caller gets the gate's answer",
          "[pg][access_review][rest][campaign_id][6939]") {
    AccessReviewHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Read");
    };
    auto res = h.sink.Get("/api/v1/access-reviews/" + std::string("abc\0def", 7));
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("MCP get/record/close refuse a malformed campaign id with invalid-params and touch "
          "nothing",
          "[pg][access_review][mcp][campaign_id][6939]") {
    AccessReviewHarness h;
    seed_one_grant(h);
    const auto cid = h.open_campaign_rest("mcp id validation");
    const int pending0 = pending_in(h, cid);
    REQUIRE(pending0 >= 1);

    const auto code_and_message = [](const std::unique_ptr<httplib::Response>& res) {
        REQUIRE(res);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body.contains("error"));
        return std::make_pair(body["error"]["code"].get<int>(),
                              body["error"]["message"].get<std::string>());
    };

    for (const auto& [label, bad] : bad_campaign_ids(cid)) {
        INFO("case: " << label << " (size " << bad.size() << ")");
        h.audit_log.clear();

        const auto [c1, m1] = code_and_message(h.mcp_call_tool("get_access_review", {{"campaign_id", bad}}));
        CHECK(c1 == yuzu::server::mcp::kInvalidParams);
        CHECK(m1 == kCampaignIdMessage);

        const auto [c2, m2] = code_and_message(
            h.mcp_call_tool("record_attestation", {{"campaign_id", bad},
                                                   {"principal_type", "user"},
                                                   {"principal_id", "csrfuser"},
                                                   {"role_name", "CsrfRole"},
                                                   {"decision", "attested"}}));
        CHECK(c2 == yuzu::server::mcp::kInvalidParams);
        CHECK(m2 == kCampaignIdMessage);

        const auto [c3, m3] =
            code_and_message(h.mcp_call_tool("close_access_review", {{"campaign_id", bad}}));
        CHECK(c3 == yuzu::server::mcp::kInvalidParams);
        CHECK(m3 == kCampaignIdMessage);

        // No domain audit row from the refused call, and nothing changed.
        for (const auto& r : h.audit_log)
            CHECK(r.action.rfind("access_review.", 0) != 0);
        auto view = h.access_review_store->get_campaign(cid);
        REQUIRE(view.has_value());
        CHECK(view->campaign.status == "open");
        CHECK(pending_in(h, cid) == pending0);
    }

    // A valid id still works end to end.
    auto get_ok = h.mcp_call_tool("get_access_review", {{"campaign_id", cid}});
    REQUIRE(get_ok);
    CHECK(nlohmann::json::parse(get_ok->body).contains("result"));
    auto close_ok = h.mcp_call_tool("close_access_review", {{"campaign_id", cid}});
    REQUIRE(close_ok);
    CHECK(nlohmann::json::parse(close_ok->body).contains("result"));
}

TEST_CASE("the store's bad_request prefix maps to 400 and invalid-params, not 503",
          "[pg][access_review][rest][mcp][campaign_id][6939]") {
    AccessReviewHarness h;
    seed_one_grant(h);
    const auto cid = h.open_campaign_rest("justification cap");
    const int pending0 = pending_in(h, cid);
    REQUIRE(pending0 >= 1);

    // The justification cap lives in the store, so the transports reach it with a well-formed id.
    const std::string huge(4097, 'j');
    auto rest = h.sink.Post("/api/v1/access-reviews/" + cid + "/attestations",
                            nlohmann::json{{"principal_type", "user"},
                                           {"principal_id", "csrfuser"},
                                           {"role_name", "CsrfRole"},
                                           {"decision", "attested"},
                                           {"justification", huge}}
                                .dump());
    REQUIRE(rest);
    CHECK(rest->status == 400);

    auto mcp = h.mcp_call_tool("record_attestation", {{"campaign_id", cid},
                                                      {"principal_type", "user"},
                                                      {"principal_id", "csrfuser"},
                                                      {"role_name", "CsrfRole"},
                                                      {"decision", "attested"},
                                                      {"justification", huge}});
    REQUIRE(mcp);
    auto body = nlohmann::json::parse(mcp->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    CHECK(pending_in(h, cid) == pending0);
}

// ── Attestation separation of duties (#4752) ────────────────────────────────
//
// The reviewer must differ from the subject of the grant, on REST and MCP, through ONE gate
// (access_review_attest_gate.hpp). The harness session defaults to an ADMIN with RBAC off, which is
// the "RBAC off, administrator attesting their own grant" case. RBAC on/off, service scope and the
// MCP tier are NOT driven here: the harness stubs `rest_perm_fn`/`mcp_perm_fn`, so those paths are
// unreachable from these cases (the gate itself is pure of them).

namespace {

namespace sod = yuzu::server::access_review_sod;

constexpr const char* kRefusedMetric = "yuzu_access_review_attestation_refused_total";

double refused_count(AccessReviewHarness& h, const char* surface, const char* reason) {
    return h.metrics.counter(kRefusedMetric, {{"surface", surface}, {"reason", reason}}).value();
}

std::string sod_body(const std::string& type, const std::string& id, const std::string& role,
                     const std::string& decision = "attested") {
    return nlohmann::json{
        {"principal_type", type}, {"principal_id", id}, {"role_name", role}, {"decision", decision}}
        .dump();
}

nlohmann::json sod_args(const std::string& cid, const std::string& type, const std::string& id,
                        const std::string& role, const std::string& decision = "attested") {
    return {{"campaign_id", cid},
            {"principal_type", type},
            {"principal_id", id},
            {"role_name", role},
            {"decision", decision}};
}

std::string attest_url(const std::string& cid) {
    return "/api/v1/access-reviews/" + cid + "/attestations";
}

std::vector<AuditRecord> audit_rows(const AccessReviewHarness& h, const std::string& action) {
    std::vector<AuditRecord> out;
    for (const auto& r : h.audit_log)
        if (r.action == action)
            out.push_back(r);
    return out;
}

AccessReviewAttestationRow grant_row(const AccessReviewHarness& h, const std::string& cid,
                                     const std::string& type, const std::string& id,
                                     const std::string& role) {
    auto v = h.access_review_store->get_campaign(cid, /*include_history=*/true);
    REQUIRE(v.has_value());
    for (const auto& a : v->attestations)
        if (a.principal_type == type && a.principal_id == id && a.role_name == role)
            return a;
    FAIL("grant not frozen in the campaign: " << type << ":" << id << ":" << role);
    return {};
}

void seed_user_grant(AccessReviewHarness& h, const std::string& user,
                     const std::string& role = "Operator") {
    REQUIRE(h.auth_db->upsert_user(user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", user, role}).has_value());
}

// An engine principal owned by `owner` holding `role`. The id is the full "engine:<slug>".
void seed_engine_grant(AccessReviewHarness& h, const std::string& engine_id,
                       const std::string& owner, const std::string& role = "Writer") {
    if (!h.rbac->get_role(role))
        REQUIRE(h.rbac->create_role({.name = role, .description = "d"}).has_value());
    REQUIRE(h.eps->create("Svc", owner, "sod test", "internal", "admin", engine_id).has_value());
    REQUIRE(h.rbac->assign_role({"engine", engine_id, role}).has_value());
}

void seed_group_grant(AccessReviewHarness& h, const std::string& group, const std::string& member,
                      const std::string& role = "Reader") {
    if (!h.rbac->get_role(role))
        REQUIRE(h.rbac->create_role({.name = role, .description = "d"}).has_value());
    REQUIRE(
        h.rbac->create_group({.name = group, .description = "d", .source = "local"}).has_value());
    if (!member.empty())
        REQUIRE(h.rbac->add_group_member(group, member).has_value());
    REQUIRE(h.rbac->assign_role({"group", group, role}).has_value());
}

void drop_table_cascade(const std::string& dsn, const char* table) {
    yuzu::server::pg::PgConn c{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult dr{
        PQexec(c.get(), (std::string("DROP TABLE ") + table + " CASCADE").c_str())};
    REQUIRE(dr.ok());
}

// The refusal's wire answer must be identical in message on both transports and must name no
// permission (the caller holds AccessReview:Attest, so a named permission would be a false hint).
void check_rest_sod_refusal(const std::unique_ptr<httplib::Response>& res) {
    REQUIRE(res);
    CHECK(res->status == 403);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["message"] == std::string(sod::kSodMessage));
    CHECK(body["error"]["remediation"] == std::string(sod::kSodRemediation));
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK(res->body.find("\"permission\"") == std::string::npos);
}

nlohmann::json mcp_error_of(const std::unique_ptr<httplib::Response>& res) {
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    return body["error"];
}

} // namespace

TEST_CASE("attestation SoD gate: pure decisions with no store, and the store-error mapping",
          "[access_review][sod][4752]") {
    using sod::SodOutcome;
    // user: byte-exact comparison, no store needed.
    CHECK(sod::evaluate_attestation_sod("bob", "user", "bob", nullptr, nullptr).outcome ==
          SodOutcome::kSelfSubject);
    CHECK(sod::evaluate_attestation_sod("bob", "user", "Bob", nullptr, nullptr).outcome ==
          SodOutcome::kPass);
    CHECK(sod::evaluate_attestation_sod("bob", "user", "bob ", nullptr, nullptr).outcome ==
          SodOutcome::kPass);
    CHECK(sod::evaluate_attestation_sod("bob", "user", "carol", nullptr, nullptr).outcome ==
          SodOutcome::kPass);
    // An embedded NUL is a different subject (the comparison is over every byte, not a c_str()).
    CHECK(sod::evaluate_attestation_sod("bob", "user", std::string("bob\0x", 5), nullptr, nullptr)
              .outcome == SodOutcome::kPass);
    CHECK(sod::evaluate_attestation_sod(std::string("bob\0x", 5), "user", "bob", nullptr, nullptr)
              .outcome == SodOutcome::kPass);
    // Prefixed identities (an SSO principal's stable name): exact match is refused, a case or
    // whitespace variant is another reviewer.
    CHECK(sod::evaluate_attestation_sod("oidc:iss#sub", "user", "oidc:iss#sub", nullptr, nullptr)
              .outcome == SodOutcome::kSelfSubject);
    CHECK(sod::evaluate_attestation_sod("saml:idp#nameid", "user", "saml:idp#nameid", nullptr,
                                        nullptr)
              .outcome == SodOutcome::kSelfSubject);
    CHECK(sod::evaluate_attestation_sod("OIDC:iss#sub", "user", "oidc:iss#sub", nullptr, nullptr)
              .outcome == SodOutcome::kPass);
    CHECK(sod::evaluate_attestation_sod("oidc:iss#sub ", "user", "oidc:iss#sub", nullptr, nullptr)
              .outcome == SodOutcome::kPass);
    CHECK(sod::evaluate_attestation_sod("saml:idp#NameID", "user", "saml:idp#nameid", nullptr,
                                        nullptr)
              .outcome == SodOutcome::kPass);
    // An unknown type is the store's not_found, never a separation-of-duties answer.
    CHECK(sod::evaluate_attestation_sod("bob", "robot", "bob", nullptr, nullptr).outcome ==
          SodOutcome::kPass);
    // engine / group with no store wired fail CLOSED and name the store.
    const auto e = sod::evaluate_attestation_sod("bob", "engine", "engine:x", nullptr, nullptr);
    CHECK(e.outcome == SodOutcome::kUnavailable);
    CHECK(e.store == "engine");
    const auto g = sod::evaluate_attestation_sod("bob", "group", "eng", nullptr, nullptr);
    CHECK(g.outcome == SodOutcome::kUnavailable);
    CHECK(g.store == "rbac");

    // The store's in-write refusal maps onto the same outcome; nothing else does.
    CHECK(sod::sod_from_store_error("forbidden: reviewer is the subject").value() ==
          SodOutcome::kSelfSubject);
    CHECK_FALSE(sod::sod_from_store_error("not_found: no such campaign").has_value());
    CHECK_FALSE(sod::sod_from_store_error("bad_request: campaign_id invalid").has_value());
    CHECK_FALSE(sod::sod_from_store_error("pool acquire timeout").has_value());
    CHECK_FALSE(sod::sod_from_store_error("").has_value());

    // The three refusals share one self-contained message; only the audit token differs.
    for (const auto& [outcome, token, reason] :
         {std::tuple{SodOutcome::kSelfSubject, "sod_self_subject", "self_subject"},
          std::tuple{SodOutcome::kEngineOwner, "sod_engine_owner", "engine_owner"},
          std::tuple{SodOutcome::kGroupMember, "sod_group_member", "group_member"}}) {
        const auto r = sod::sod_refusal_for(outcome);
        CHECK(r.http_status == 403);
        CHECK(r.jsonrpc_code == yuzu::server::mcp::kPermissionDenied);
        CHECK(r.message == sod::kSodMessage);
        CHECK(r.audit_result == "denied");
        CHECK(r.audit_detail == token);
        CHECK(r.reason == reason);
        CHECK_FALSE(r.retry_after_ms.has_value());
    }
    const auto u = sod::sod_refusal_for(SodOutcome::kUnavailable);
    CHECK(u.http_status == 503);
    CHECK(u.jsonrpc_code == yuzu::server::mcp::kInternalError);
    CHECK(u.audit_result == "failure");
    CHECK(u.audit_detail == "sod_check_unavailable");
    CHECK(u.reason == "check_unavailable");
    REQUIRE(u.retry_after_ms.has_value());
    CHECK(*u.retry_after_ms == 5000);
    CHECK(std::string(sod::kSodMessage) ==
          "the reviewer must differ from the subject of this grant; ask another reviewer to "
          "record this decision");
}

TEST_CASE("attestation SoD: the subject of a user grant is refused on REST and MCP, once, with "
          "the same message, an audit row and the counter",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    CHECK_FALSE(h.rbac->is_rbac_enabled()); // RBAC off: an ADMIN self-attesting is still refused
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod self");
    h.session_user = "bob";
    h.audit_log.clear();
    const std::string tuple = " principal_type=user principal_id=bob role=Operator";

    SECTION("REST") {
        auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        check_rest_sod_refusal(res);

        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "denied");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "sod_self_subject" + tuple);
        CHECK(audit_rows(h, "access_review.flagged").empty());
        // A persisted refusal row sets no failure header.
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());

        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision == "pending");
        CHECK(row.decision_seq == 0);
        CHECK(row.history.empty());
        CHECK(refused_count(h, "rest", "self_subject") == 1.0);
        CHECK(refused_count(h, "mcp", "self_subject") == 0.0);
    }

    SECTION("REST: flag uses the flagged verb") {
        auto res =
            h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator", "flagged_revoke"));
        check_rest_sod_refusal(res);
        const auto rows = audit_rows(h, "access_review.flagged");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "denied");
        CHECK(rows[0].detail == "sod_self_subject" + tuple);
        CHECK(audit_rows(h, "access_review.attested").empty());
    }

    SECTION("MCP") {
        auto res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator"));
        const auto err = mcp_error_of(res);
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["message"] == std::string(sod::kSodMessage));
        CHECK(err["data"]["remediation"] == std::string(sod::kSodRemediation));
        CHECK_FALSE(err["data"].contains("audit_persisted")); // both rows persisted

        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "denied");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "sod_self_subject" + tuple);
        const auto wrapper = audit_rows(h, "mcp.record_attestation");
        REQUIRE(wrapper.size() == 1);
        CHECK(wrapper[0].result == "denied");

        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision == "pending");
        CHECK(row.history.empty());
        CHECK(refused_count(h, "mcp", "self_subject") == 1.0);
        CHECK(refused_count(h, "rest", "self_subject") == 0.0);
    }
}

TEST_CASE("attestation SoD: a different reviewer records, and every decision is appended",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod other");
    h.session_user = "carol";
    h.audit_log.clear();
    const std::string tuple = " principal_type=user principal_id=bob role=Operator";

    SECTION("REST: attest, attest again, then flag") {
        auto r1 = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(r1);
        CHECK(r1->status == 200);
        // The success body names what the decision superseded: a first decision answers seq 1
        // over `pending`.
        const auto b1 = nlohmann::json::parse(r1->body)["data"];
        REQUIRE(b1.contains("decision_seq"));
        REQUIRE(b1.contains("previous_decision"));
        CHECK(b1["recorded"] == true);
        CHECK(b1["decision_seq"] == 1);
        CHECK(b1["previous_decision"] == "pending");
        CHECK(b1.size() == 3);
        CHECK(r1->get_header_value("Sec-Audit-Failed").empty());
        auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "success");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "decision=attested previous=pending seq=1 sod=pass" + tuple);

        auto r2 = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(r2);
        CHECK(r2->status == 200);
        // An identical repeat appends too: seq 2, superseding the attested decision.
        const auto b2 = nlohmann::json::parse(r2->body)["data"];
        CHECK(b2["decision_seq"] == 2);
        CHECK(b2["previous_decision"] == "attested");
        rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].target_id == cid);
        CHECK(rows[1].detail == "decision=attested previous=attested seq=2 sod=pass" + tuple);

        auto r3 =
            h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator", "flagged_revoke"));
        REQUIRE(r3);
        CHECK(r3->status == 200);
        const auto b3 = nlohmann::json::parse(r3->body)["data"];
        CHECK(b3["decision_seq"] == 3);
        CHECK(b3["previous_decision"] == "attested");
        const auto flagged = audit_rows(h, "access_review.flagged");
        REQUIRE(flagged.size() == 1);
        CHECK(flagged[0].detail ==
              "decision=flagged_revoke previous=attested seq=3 sod=pass" + tuple);

        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision == "flagged_revoke");
        CHECK(row.reviewer == "carol");
        CHECK(row.decision_seq == 3);
        REQUIRE(row.history.size() == 3);
        CHECK(row.history[2].previous_decision == "attested");
        // An attest over the flag reports that it replaced a flagged_revoke decision.
        auto r4 = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(r4);
        CHECK(r4->status == 200);
        const auto b4 = nlohmann::json::parse(r4->body)["data"];
        CHECK(b4["decision_seq"] == 4);
        CHECK(b4["previous_decision"] == "flagged_revoke");
        // No refusal was counted.
        CHECK(refused_count(h, "rest", "self_subject") == 0.0);
    }

    SECTION("MCP") {
        auto res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator"));
        REQUIRE(res);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        const auto& sc = body["result"]["structuredContent"];
        CHECK(sc["recorded"] == true);
        REQUIRE(sc.contains("decision_seq"));
        REQUIRE(sc.contains("previous_decision"));
        CHECK(sc["decision_seq"] == 1);
        CHECK(sc["previous_decision"] == "pending");
        CHECK_FALSE(sc.contains("audit_persisted"));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "success");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "decision=attested previous=pending seq=1 sod=pass" + tuple);
        CHECK(grant_row(h, cid, "user", "bob", "Operator").decision_seq == 1);

        // A second call (a different decision) reports seq 2 over the first.
        auto again = h.mcp_call_tool("record_attestation",
                                     sod_args(cid, "user", "bob", "Operator", "flagged_revoke"));
        REQUIRE(again);
        const auto sc2 = nlohmann::json::parse(again->body)["result"]["structuredContent"];
        CHECK(sc2["decision_seq"] == 2);
        CHECK(sc2["previous_decision"] == "attested");
        // And an identical repeat appends at 3 over the flag it repeats.
        auto third = h.mcp_call_tool("record_attestation",
                                     sod_args(cid, "user", "bob", "Operator", "flagged_revoke"));
        REQUIRE(third);
        const auto sc3 = nlohmann::json::parse(third->body)["result"]["structuredContent"];
        CHECK(sc3["decision_seq"] == 3);
        CHECK(sc3["previous_decision"] == "flagged_revoke");
    }
}

TEST_CASE("attestation SoD: a subject cannot un-flag a grant that a reviewer flagged",
          "[pg][access_review][rest][sod][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod unflag");

    h.session_user = "carol";
    auto flag = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator", "flagged_revoke"));
    REQUIRE(flag);
    REQUIRE(flag->status == 200);

    h.session_user = "bob";
    check_rest_sod_refusal(h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator")));

    const auto row = grant_row(h, cid, "user", "bob", "Operator");
    CHECK(row.decision == "flagged_revoke");
    CHECK(row.reviewer == "carol");
    CHECK(row.decision_seq == 1);
    CHECK(row.history.size() == 1);
}

TEST_CASE("attestation SoD: the owner of an engine principal is refused, revoked or not; an "
          "orphan engine id is admitted",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    seed_engine_grant(h, "engine:svc", "bob");
    // An orphan grant: the grant table names an engine that has no principal row.
    REQUIRE(h.rbac->assign_role({"engine", "engine:ghost", "Writer"}).has_value());
    const auto cid = h.open_campaign_rest("sod engine");
    h.audit_log.clear();
    const std::string tuple = " principal_type=engine principal_id=engine:svc role=Writer";

    SECTION("REST: the owner is refused, another reviewer records") {
        h.session_user = "bob";
        check_rest_sod_refusal(
            h.sink.Post(attest_url(cid), sod_body("engine", "engine:svc", "Writer")));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "denied");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "sod_engine_owner" + tuple);
        CHECK(refused_count(h, "rest", "engine_owner") == 1.0);
        CHECK(grant_row(h, cid, "engine", "engine:svc", "Writer").history.empty());

        h.session_user = "carol";
        auto ok = h.sink.Post(attest_url(cid), sod_body("engine", "engine:svc", "Writer"));
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(grant_row(h, cid, "engine", "engine:svc", "Writer").decision_seq == 1);
    }

    SECTION("REST: a REVOKED engine owned by the reviewer is still refused") {
        REQUIRE(h.eps->revoke("engine:svc").has_value());
        h.session_user = "bob";
        check_rest_sod_refusal(
            h.sink.Post(attest_url(cid), sod_body("engine", "engine:svc", "Writer")));
        CHECK(refused_count(h, "rest", "engine_owner") == 1.0);
    }

    SECTION("REST: an orphan engine id (no principal row) is admitted") {
        h.session_user = "bob";
        auto ok = h.sink.Post(attest_url(cid), sod_body("engine", "engine:ghost", "Writer"));
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(refused_count(h, "rest", "engine_owner") == 0.0);
    }

    SECTION("MCP: the owner is refused, another reviewer records") {
        h.session_user = "bob";
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "engine", "engine:svc", "Writer")));
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["message"] == std::string(sod::kSodMessage));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].detail == "sod_engine_owner" + tuple);
        CHECK(refused_count(h, "mcp", "engine_owner") == 1.0);

        h.session_user = "carol";
        auto ok =
            h.mcp_call_tool("record_attestation", sod_args(cid, "engine", "engine:svc", "Writer"));
        REQUIRE(ok);
        CHECK(nlohmann::json::parse(ok->body).contains("result"));
    }
}

TEST_CASE("attestation SoD: a member of a group is refused; a non-member and a group with no "
          "row are admitted",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    seed_group_grant(h, "eng", "bob");
    // A grant naming a group that has no row at all.
    REQUIRE(h.rbac->assign_role({"group", "ghosts", "Reader"}).has_value());
    const auto cid = h.open_campaign_rest("sod group");
    h.audit_log.clear();
    const std::string tuple = " principal_type=group principal_id=eng role=Reader";

    SECTION("REST") {
        h.session_user = "bob";
        check_rest_sod_refusal(h.sink.Post(attest_url(cid), sod_body("group", "eng", "Reader")));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "denied");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "sod_group_member" + tuple);
        CHECK(refused_count(h, "rest", "group_member") == 1.0);
        CHECK(grant_row(h, cid, "group", "eng", "Reader").history.empty());

        h.session_user = "carol";
        auto ok = h.sink.Post(attest_url(cid), sod_body("group", "eng", "Reader"));
        REQUIRE(ok);
        CHECK(ok->status == 200);

        // bob is not in "ghosts" (no such group row): admitted.
        h.session_user = "bob";
        auto orphan = h.sink.Post(attest_url(cid), sod_body("group", "ghosts", "Reader"));
        REQUIRE(orphan);
        CHECK(orphan->status == 200);
        CHECK(refused_count(h, "rest", "group_member") == 1.0);
    }

    SECTION("MCP") {
        h.session_user = "bob";
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "group", "eng", "Reader")));
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["message"] == std::string(sod::kSodMessage));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].detail == "sod_group_member" + tuple);
        CHECK(refused_count(h, "mcp", "group_member") == 1.0);
    }
}

TEST_CASE("attestation SoD: the permission gate answers before the refusal",
          "[pg][access_review][rest][sod][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod perm order");
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Attest");
    };
    h.session_user = "bob";
    h.audit_log.clear();
    auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body == R"({"error":"forbidden"})");
    CHECK(h.audit_log.empty());
    CHECK(refused_count(h, "rest", "self_subject") == 0.0);
}

TEST_CASE("attestation SoD: a closed campaign is 404 for another reviewer, but the subject is "
          "refused (403) on both transports",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod closed");

    auto closed = h.sink.Post("/api/v1/access-reviews/" + cid + "/close", "");
    REQUIRE(closed);
    REQUIRE(closed->status == 200);

    SECTION("another reviewer: 404 REST, invalid-params MCP, no history") {
        h.session_user = "carol";
        auto rest = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(rest);
        CHECK(rest->status == 404);
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        CHECK(err["code"] == yuzu::server::mcp::kInvalidParams);
        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision == "pending");
        CHECK(row.history.empty());
    }

    SECTION("the subject: 403 on both transports (the refusal precedes not_found)") {
        h.session_user = "bob";
        check_rest_sod_refusal(h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator")));
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(grant_row(h, cid, "user", "bob", "Operator").history.empty());
    }
}

TEST_CASE("attestation SoD: an engine or group lookup that cannot be answered fails closed (503 "
          "REST / internal-error MCP), writes nothing, and is counted",
          "[pg][access_review][rest][mcp][sod][degrade][4752]") {
    // A per-test migrated clone, NOT the file-wide shared one: the shared reset TRUNCATEs and
    // cannot repair a table this case DROPs.
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_rest_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    REQUIRE(pool.valid());
    AccessReviewHarness h{true, true, &pool};

    SECTION("engine store unavailable") {
        seed_engine_grant(h, "engine:svc", "bob");
        const auto cid = h.open_campaign_rest("sod degrade engine");
        drop_table_cascade(db.dsn(), "engine_principal_store.engine_principals");
        h.session_user = "carol";
        h.audit_log.clear();
        const std::string tuple = " principal_type=engine principal_id=engine:svc role=Writer";

        auto rest = h.sink.Post(attest_url(cid), sod_body("engine", "engine:svc", "Writer"));
        REQUIRE(rest);
        CHECK(rest->status == 503);
        auto body = nlohmann::json::parse(rest->body);
        CHECK(body["error"]["retry_after_ms"] == 5000);
        CHECK(body["error"]["message"] == std::string(sod::kSodUnavailableMessage));
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == "sod_check_unavailable store=engine" + tuple);
        CHECK(refused_count(h, "rest", "check_unavailable") == 1.0);
        const auto row = grant_row(h, cid, "engine", "engine:svc", "Writer");
        CHECK(row.decision == "pending");
        CHECK(row.history.empty());

        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "engine", "engine:svc", "Writer")));
        CHECK(err["code"] == yuzu::server::mcp::kInternalError);
        CHECK(err["data"]["retry_after_ms"] == 5000);
        CHECK(refused_count(h, "mcp", "check_unavailable") == 1.0);
        CHECK(grant_row(h, cid, "engine", "engine:svc", "Writer").history.empty());
    }

    SECTION("rbac group store unavailable (RBAC off, administrator session)") {
        seed_group_grant(h, "eng", "bob");
        const auto cid = h.open_campaign_rest("sod degrade group");
        drop_table_cascade(db.dsn(), "rbac_store.group_members");
        h.session_user = "carol";
        h.audit_log.clear();
        const std::string tuple = " principal_type=group principal_id=eng role=Reader";

        auto rest = h.sink.Post(attest_url(cid), sod_body("group", "eng", "Reader"));
        REQUIRE(rest);
        CHECK(rest->status == 503);
        CHECK(nlohmann::json::parse(rest->body)["error"]["retry_after_ms"] == 5000);
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].detail == "sod_check_unavailable store=rbac" + tuple);
        CHECK(refused_count(h, "rest", "check_unavailable") == 1.0);
        CHECK(grant_row(h, cid, "group", "eng", "Reader").history.empty());

        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "group", "eng", "Reader")));
        CHECK(err["code"] == yuzu::server::mcp::kInternalError);
        CHECK(err["data"]["retry_after_ms"] == 5000);
        CHECK(refused_count(h, "mcp", "check_unavailable") == 1.0);
    }
}

TEST_CASE("attestation SoD: a refusal stands and a recorded decision stands when its audit row "
          "cannot be persisted, and nothing escapes a throwing audit callback",
          "[pg][access_review][rest][mcp][sod][audit][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("sod audit faults");

    SECTION("REST refusal: 403 stands, Sec-Audit-Failed set") {
        h.session_user = "bob";
        h.audit_fail_action = "access_review.attested";
        auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        check_rest_sod_refusal(res);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(grant_row(h, cid, "user", "bob", "Operator").history.empty());
        CHECK(refused_count(h, "rest", "self_subject") == 1.0); // counted though the row failed
    }

    SECTION("REST success: decision recorded, Sec-Audit-Failed set") {
        h.session_user = "carol";
        h.audit_fail_action = "access_review.attested";
        auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision == "attested");
        CHECK(row.decision_seq == 1);
        CHECK(row.history.size() == 1);
    }

    SECTION("MCP refusal, audit row returns false") {
        h.session_user = "bob";
        h.mcp_audit_mode = AccessReviewHarness::McpAuditMode::fail;
        h.mcp_audit_mode_action = "access_review.attested";
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["message"] == std::string(sod::kSodMessage));
        CHECK(err["data"]["audit_persisted"] == false);
        CHECK(grant_row(h, cid, "user", "bob", "Operator").history.empty());
    }

    SECTION("MCP refusal, only the mcp.<tool> wrapper row fails") {
        h.session_user = "bob";
        h.mcp_audit_mode = AccessReviewHarness::McpAuditMode::fail;
        h.mcp_audit_mode_action = "mcp.record_attestation";
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["data"]["audit_persisted"] == false);
    }

    SECTION("MCP refusal, audit callback throws") {
        h.session_user = "bob";
        h.mcp_audit_mode = AccessReviewHarness::McpAuditMode::throws;
        h.mcp_audit_mode_action = "access_review.attested";
        std::unique_ptr<httplib::Response> res;
        REQUIRE_NOTHROW(
            res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        const auto err = mcp_error_of(res);
        CHECK(err["code"] == yuzu::server::mcp::kPermissionDenied);
        CHECK(err["data"]["audit_persisted"] == false);
    }

    SECTION("MCP success, audit row returns false") {
        h.session_user = "carol";
        h.mcp_audit_mode = AccessReviewHarness::McpAuditMode::fail;
        h.mcp_audit_mode_action = "access_review.attested";
        auto res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator"));
        REQUIRE(res);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        CHECK(body["result"]["structuredContent"]["recorded"] == true);
        CHECK(body["result"]["structuredContent"]["audit_persisted"] == false);
        CHECK(grant_row(h, cid, "user", "bob", "Operator").decision_seq == 1);
    }

    SECTION("MCP success, audit callback throws after the mutation") {
        h.session_user = "carol";
        h.mcp_audit_mode = AccessReviewHarness::McpAuditMode::throws;
        h.mcp_audit_mode_action = "access_review.attested";
        std::unique_ptr<httplib::Response> res;
        REQUIRE_NOTHROW(
            res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        REQUIRE(res);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        CHECK(body["result"]["structuredContent"]["recorded"] == true);
        CHECK(body["result"]["structuredContent"]["audit_persisted"] == false);
        CHECK(grant_row(h, cid, "user", "bob", "Operator").decision_seq == 1);
    }
}

// ── Byte-exact subject comparison, input bounds, store-failure answers (#4752 round 7) ─────────

TEST_CASE("attestation SoD: the engine-owner and group-member rules compare byte-exact",
          "[pg][access_review][sod][4752]") {
    AccessReviewHarness h;
    seed_engine_grant(h, "engine:svc", "bob");
    seed_group_grant(h, "eng", "bob");
    using sod::SodOutcome;
    const auto verdict = [&h](const std::string& reviewer, const char* type,
                              const std::string& id) {
        return sod::evaluate_attestation_sod(reviewer, type, id, h.eps.get(), h.rbac.get()).outcome;
    };

    // Engine: the owner's exact name is refused; a case or whitespace variant is another reviewer.
    CHECK(verdict("bob", "engine", "engine:svc") == SodOutcome::kEngineOwner);
    CHECK(verdict("Bob", "engine", "engine:svc") == SodOutcome::kPass);
    CHECK(verdict("BOB", "engine", "engine:svc") == SodOutcome::kPass);
    CHECK(verdict("bob ", "engine", "engine:svc") == SodOutcome::kPass);
    CHECK(verdict(" bob", "engine", "engine:svc") == SodOutcome::kPass);
    // A variant of the engine id names no principal row, so it is an orphan grant (admitted).
    CHECK(verdict("bob", "engine", "ENGINE:svc") == SodOutcome::kPass);
    CHECK(verdict("bob", "engine", "engine:svc ") == SodOutcome::kPass);

    // Group: the same exactness on the member name and on the group name.
    CHECK(verdict("bob", "group", "eng") == SodOutcome::kGroupMember);
    CHECK(verdict("Bob", "group", "eng") == SodOutcome::kPass);
    CHECK(verdict("bob ", "group", "eng") == SodOutcome::kPass);
    CHECK(verdict("bob", "group", "Eng") == SodOutcome::kPass);
    CHECK(verdict("bob", "group", "eng ") == SodOutcome::kPass);
    // A NUL in the group id is a different name: it compares over every byte.
    CHECK(verdict("bob", "group", std::string("eng\0x", 5)) == SodOutcome::kPass);
    // (A NUL in an ENGINE id reaches EnginePrincipalStore::get, whose bound value c_str() would
    // truncate; the transports refuse it before the gate, see the bounds case below, so it is not
    // pinned here.)
}

TEST_CASE("attestation SoD at the route: a case or whitespace variant of the subject is another "
          "reviewer on all three rules; the exact name is refused",
          "[pg][access_review][rest][sod][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    seed_engine_grant(h, "engine:svc", "bob");
    seed_group_grant(h, "eng", "bob");
    // SSO principals are stored under their stable, prefixed name.
    REQUIRE(h.rbac->assign_role({"user", "oidc:iss#sub", "Operator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "saml:idp#nameid", "Operator"}).has_value());
    const auto cid = h.open_campaign_rest("sod byte exact");

    struct Rule {
        const char* type;
        const char* id;
        const char* role;
        const char* exact;   // refused
        const char* variant; // admitted
        const char* refusal;
    };
    const Rule rules[] = {
        {"user", "bob", "Operator", "bob", "Bob", "self_subject"},
        {"user", "bob", "Operator", "bob", "bob ", "self_subject"},
        {"user", "oidc:iss#sub", "Operator", "oidc:iss#sub", "OIDC:iss#sub", "self_subject"},
        {"user", "saml:idp#nameid", "Operator", "saml:idp#nameid", "saml:idp#nameid ",
         "self_subject"},
        {"engine", "engine:svc", "Writer", "bob", "Bob", "engine_owner"},
        {"engine", "engine:svc", "Writer", "bob", "bob ", "engine_owner"},
        {"group", "eng", "Reader", "bob", "Bob", "group_member"},
        {"group", "eng", "Reader", "bob", "bob ", "group_member"},
    };
    for (const auto& r : rules) {
        INFO(r.type << " " << r.id << " exact='" << r.exact << "' variant='" << r.variant << "'");
        const double before = refused_count(h, "rest", r.refusal);
        h.session_user = r.exact;
        check_rest_sod_refusal(h.sink.Post(attest_url(cid), sod_body(r.type, r.id, r.role)));
        CHECK(refused_count(h, "rest", r.refusal) == before + 1.0);

        h.session_user = r.variant;
        auto ok = h.sink.Post(attest_url(cid), sod_body(r.type, r.id, r.role));
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(refused_count(h, "rest", r.refusal) == before + 1.0); // the variant was not refused
        CHECK(grant_row(h, cid, r.type, r.id, r.role).reviewer == r.variant);
    }

    // MCP reaches the same answers through the same gate.
    h.session_user = "bob";
    CHECK(mcp_error_of(h.mcp_call_tool("record_attestation",
                                       sod_args(cid, "engine", "engine:svc", "Writer")))["code"] ==
          yuzu::server::mcp::kPermissionDenied);
    h.session_user = "Bob";
    auto mcp_ok =
        h.mcp_call_tool("record_attestation", sod_args(cid, "engine", "engine:svc", "Writer"));
    REQUIRE(mcp_ok);
    CHECK(nlohmann::json::parse(mcp_ok->body).contains("result"));
}

TEST_CASE("attestation bounds: an over-long or NUL-bearing principal_type, principal_id or "
          "role_name is 400 / invalid-params before the gate, with no audit row and no counter",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    seed_engine_grant(h, "engine:svc", "bob");
    seed_group_grant(h, "eng", "bob");
    const auto cid = h.open_campaign_rest("sod bounds");
    h.session_user = "carol";
    h.audit_log.clear();

    const std::string max_id(yuzu::server::kPrincipalIdMaxLen, 'a');
    const std::string long_id(yuzu::server::kPrincipalIdMaxLen + 1, 'a');
    const std::string nul_engine("engine:svc\0x", 12);
    const std::string nul_group("eng\0x", 5);
    struct Case {
        const char* label;
        std::string type, id, role;
    };
    const std::vector<Case> cases = {
        {"engine id over 1024", "engine", long_id, "Writer"},
        {"group id over 1024", "group", long_id, "Reader"},
        {"role over 1024", "group", "eng", long_id},
        {"type over 1024", long_id, "eng", "Reader"},
        {"engine id with NUL", "engine", nul_engine, "Writer"},
        {"group id with NUL", "group", nul_group, "Reader"},
        {"role with NUL", "group", "eng", std::string("Reader\0x", 8)},
        {"type with NUL", std::string("group\0x", 7), "eng", "Reader"},
    };
    const auto no_refusal_counted = [&h] {
        for (const char* surface : {"rest", "mcp"})
            for (const char* reason :
                 {"self_subject", "engine_owner", "group_member", "check_unavailable"})
                if (refused_count(h, surface, reason) != 0.0)
                    return false;
        return true;
    };
    for (const auto& c : cases) {
        INFO(c.label);
        auto rest = h.sink.Post(attest_url(cid), sod_body(c.type, c.id, c.role));
        REQUIRE(rest);
        CHECK(rest->status == 400);
        const auto body = nlohmann::json::parse(rest->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        CHECK(body["error"]["message"] == std::string(kGrantFieldInvalidMessage));

        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, c.type, c.id, c.role)));
        CHECK(err["code"] == yuzu::server::mcp::kInvalidParams);
        CHECK(err["message"] == std::string(kGrantFieldInvalidMessage));

        // Nothing was audited (no forged `denied` row for a grant that does not exist), nothing
        // was counted, and nothing was recorded.
        CHECK(h.audit_log.empty());
        CHECK(no_refusal_counted());
    }
    CHECK(grant_row(h, cid, "group", "eng", "Reader").history.empty());
    CHECK(grant_row(h, cid, "engine", "engine:svc", "Writer").history.empty());

    // The boundary is inclusive: exactly 1024 bytes passes the bound and reaches the store, which
    // answers not_found for a grant that was never frozen (404 / invalid-params, not 400's text).
    auto at_cap = h.sink.Post(attest_url(cid), sod_body("group", max_id, "Reader"));
    REQUIRE(at_cap);
    CHECK(at_cap->status == 404);
    auto at_cap_role = h.sink.Post(attest_url(cid), sod_body("group", "eng", max_id));
    REQUIRE(at_cap_role);
    CHECK(at_cap_role->status == 404);
}

TEST_CASE("attestation bounds: a frozen grant with the longest ids the identity stores produce "
          "can be attested on REST and MCP, and its audit rows stay bounded",
          "[pg][access_review][rest][mcp][sod][4752]") {
    AccessReviewHarness h;
    // `oidc:<iss>#<sub>` with iss and sub at their 255-byte caps (oidc_provider.cpp): 516 bytes.
    const std::string oidc_id = "oidc:" + std::string(255, 'i') + "#" + std::string(255, 's');
    REQUIRE(oidc_id.size() == 516);
    // An IdP group is `<source>:<external_id>` with an external id up to 512 bytes: about 530.
    const std::string group_id = "oidc:" + std::string(525, 'g');
    // A role name has no store-side cap; one well past the old 256-byte bound.
    const std::string long_role(600, 'r');
    REQUIRE(oidc_id.size() <= yuzu::server::kPrincipalIdMaxLen);
    REQUIRE(group_id.size() <= yuzu::server::kPrincipalIdMaxLen);
    REQUIRE(h.rbac->assign_role({"user", oidc_id, "Operator"}).has_value());
    seed_group_grant(h, group_id, "bob", long_role);
    const auto cid = h.open_campaign_rest("long ids");
    // The grants really are frozen with these ids (the tuple is exactly what the page shows).
    REQUIRE(grant_row(h, cid, "user", oidc_id, "Operator").decision == "pending");
    REQUIRE(grant_row(h, cid, "group", group_id, long_role).decision == "pending");
    h.session_user = "carol";
    h.audit_log.clear();

    auto rest_user = h.sink.Post(attest_url(cid), sod_body("user", oidc_id, "Operator"));
    REQUIRE(rest_user);
    CHECK(rest_user->status == 200);
    auto rest_group = h.sink.Post(attest_url(cid), sod_body("group", group_id, long_role));
    REQUIRE(rest_group);
    CHECK(rest_group->status == 200);
    auto mcp_group =
        h.mcp_call_tool("record_attestation", sod_args(cid, "group", group_id, long_role));
    REQUIRE(mcp_group);
    CHECK(nlohmann::json::parse(mcp_group->body).contains("result"));

    CHECK(grant_row(h, cid, "user", oidc_id, "Operator").decision == "attested");
    CHECK(grant_row(h, cid, "group", group_id, long_role).decision_seq == 2);

    // The audit rows carry the tuple through audit_token, which neutralises bytes but does not
    // shorten, so a row is bounded by the three field caps plus its fixed labels: a few KiB.
    const auto rows = audit_rows(h, "access_review.attested");
    REQUIRE(rows.size() == 3);
    const std::size_t bound = 2 * yuzu::server::kPrincipalIdMaxLen +
                              yuzu::server::kRoleNameMaxLen + 256;
    for (const auto& r : rows) {
        CHECK(r.detail.size() > 600); // the long ids really are in the row
        CHECK(r.detail.size() <= bound);
    }
}

TEST_CASE("attestation store failure: REST and MCP answer a fixed message with a retry hint, log "
          "the raw error, and never put database text in the response or the audit rows",
          "[pg][access_review][rest][mcp][degrade][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_rest_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    REQUIRE(pool.valid());
    AccessReviewHarness h{true, true, &pool};
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("store failure");
    // The pre-read passes, then the history INSERT fails with a libpq message that names the
    // relation: the shape of a genuine write fault.
    drop_table_cascade(db.dsn(), "access_review_store.access_review_attestation_history");
    h.session_user = "carol";
    h.audit_log.clear();
    const std::string tuple = " principal_type=user principal_id=bob role=Operator";
    const std::string fixed(sod::kStoreFailureMessage);
    const auto leaks_db_text = [](const std::string& text) {
        return text.find("does not exist") != std::string::npos ||
               text.find("relation \\\"") != std::string::npos ||
               text.find("relation \"") != std::string::npos ||
               text.find("access_review_attestation_history") != std::string::npos ||
               text.find("history write failed") != std::string::npos ||
               text.find("ERROR:") != std::string::npos;
    };

    SECTION("REST") {
        yuzu::test::LogCapture logs;
        auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        logs.stop();
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        CHECK(body["error"]["message"] == fixed);
        CHECK(body["error"]["retry_after_ms"] == 5000);
        CHECK_FALSE(leaks_db_text(res->body));

        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail == fixed + tuple);
        CHECK_FALSE(leaks_db_text(rows[0].detail));

        // The raw error went to the server log, on one line, not to the caller.
        const auto log_text = logs.text();
        CHECK(log_text.find("access review attestation store failure") != std::string::npos);
        CHECK(log_text.find("history write failed") != std::string::npos);
    }

    SECTION("MCP") {
        const auto err = mcp_error_of(
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator")));
        CHECK(err["code"] == yuzu::server::mcp::kInternalError);
        CHECK(err["message"] == fixed);
        CHECK(err["data"]["retry_after_ms"] == 5000);
        CHECK(err["data"]["remediation"] == std::string(sod::kStoreFailureRemediation));
        CHECK_FALSE(leaks_db_text(err.dump()));

        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].detail == fixed + tuple);
        const auto wrapper = audit_rows(h, "mcp.record_attestation");
        REQUIRE(wrapper.size() == 1);
        CHECK(wrapper[0].result == "failure");
        CHECK(wrapper[0].detail == fixed);
        for (const auto& r : h.audit_log)
            CHECK_FALSE(leaks_db_text(r.detail));
    }
}

TEST_CASE("access review store errors: every string the store returns maps to one REST status and "
          "one MCP code, through the shared classifier both transports delegate to",
          "[access_review][sod][classifier][4752]") {
    // Every error AccessReviewStore can return (access_review_store.cpp's unexpected( sites; the
    // Python lexical gate checks the DIRECT string literals after `unexpected(` against its own
    // table; a message built in a variable, like the decision-cap refusal, is covered below).
    // Prefixed strings are client or business refusals; every other string is a genuine fault
    // the caller did not cause.
    struct Row {
        const char* err;
        int http;
        int jsonrpc;
    };
    using yuzu::server::mcp::kInternalError;
    using yuzu::server::mcp::kInvalidParams;
    using yuzu::server::mcp::kPermissionDenied;
    const Row rows[] = {
        {"not_found: no frozen grant matches (campaign_id, principal_type, principal_id, "
         "role_name) in an open campaign",
         404, kInvalidParams},
        {"not_found: no campaign with this id", 404, kInvalidParams},
        {"not_found: campaign missing or already closed", 404, kInvalidParams},
        {"bad_request: campaign_id invalid", 400, kInvalidParams},
        {"bad_request: title contains a NUL byte", 400, kInvalidParams},
        {"bad_request: created_by contains a NUL byte", 400, kInvalidParams},
        {"bad_request: principal_type contains a NUL byte", 400, kInvalidParams},
        {"bad_request: principal_id contains a NUL byte", 400, kInvalidParams},
        {"bad_request: role_name contains a NUL byte", 400, kInvalidParams},
        {"bad_request: reviewer contains a NUL byte", 400, kInvalidParams},
        {"bad_request: reviewer cannot be empty", 400, kInvalidParams},
        {"bad_request: justification contains a NUL byte", 400, kInvalidParams},
        {"bad_request: justification exceeds 4096 bytes", 400, kInvalidParams},
        {"bad_request: closed_by contains a NUL byte", 400, kInvalidParams},
        {"forbidden: reviewer is the subject of this grant", 403, kPermissionDenied},
        {"database not open", 503, kInternalError},
        {"database unavailable \xe2\x80\x94 try again", 503, kInternalError},
        {"open_campaign failed", 503, kInternalError},
        {"get_campaign failed", 503, kInternalError},
        {"record_attestation read failed: ERROR: x", 503, kInternalError},
        {"record_attestation history write failed: ERROR: x", 503, kInternalError},
        {"record_attestation write failed: ERROR: x", 503, kInternalError},
        {"record_attestation write failed: the decision did not advance", 503, kInternalError},
        {"record_attestation failed: database unavailable or the decision was not committed, try "
         "again",
         503, kInternalError},
        {"close_campaign write failed: ERROR: x", 503, kInternalError},
        {"list_campaigns read failed: ERROR: x", 503, kInternalError},
        // Validation strings the handlers pre-empt; unprefixed, so today they classify as a fault.
        {"title cannot be empty", 503, kInternalError},
        {"created_by cannot be empty", 503, kInternalError},
        {"closed_by cannot be empty", 503, kInternalError},
        {"decision must be 'attested' or 'flagged_revoke'", 503, kInternalError},
        {"campaign_id/principal_type/principal_id/role_name required", 503, kInternalError},
        {"rbac_enforcement must be 'enabled', 'disabled', or 'degraded'", 503, kInternalError},
        {"", 503, kInternalError},
    };
    for (const auto& r : rows) {
        INFO("store error: " << r.err);
        const auto cls = sod::classify_store_error(r.err);
        CHECK(sod::store_error_http_status(cls) == r.http);
        CHECK(sod::store_error_jsonrpc_code(cls) == r.jsonrpc);
    }
    // The prefix is the whole contract: a prefix that is not at the start is not a refusal, and
    // the check is case-sensitive.
    CHECK(sod::store_error_http_status(sod::classify_store_error("x not_found: y")) == 503);
    CHECK(sod::store_error_http_status(sod::classify_store_error("Not_Found: y")) == 503);
    // The user-rule refusal also maps onto the gate's own outcome (one wire answer, both paths).
    CHECK(
        sod::sod_from_store_error("forbidden: reviewer is the subject of this grant").has_value());
    CHECK_FALSE(sod::sod_from_store_error("bad_request: x").has_value());
    CHECK_FALSE(sod::sod_from_store_error("record_attestation write failed: x").has_value());

    // The decision-cap refusal: the store returns it prefixed (classified 400 / invalid params),
    // the handlers put only the bare message on the wire, and no other string is rewritten.
    const std::string cap_err = "bad_request: " + std::string(yuzu::server::kDecisionCapMessage);
    const auto cap_cls = sod::classify_store_error(cap_err);
    CHECK(sod::store_error_http_status(cap_cls) == 400);
    CHECK(sod::store_error_jsonrpc_code(cap_cls) == kInvalidParams);
    CHECK(yuzu::server::decision_cap_wire_message(cap_err) == yuzu::server::kDecisionCapMessage);
    CHECK_FALSE(yuzu::server::decision_cap_wire_message(
                    std::string(yuzu::server::kDecisionCapMessage)));
    CHECK_FALSE(yuzu::server::decision_cap_wire_message(cap_err + " "));
    CHECK_FALSE(yuzu::server::decision_cap_wire_message("bad_request: reviewer cannot be empty"));
    CHECK_FALSE(yuzu::server::decision_cap_wire_message(""));
}

// ── Decision history on the read surfaces (#4752) ───────────────────────────
//
// GET /{id}, MCP get_access_review and the Access page show the same decisions: the latest, its
// decision_seq and every earlier one. The page case drives the real fragment route over a callback
// that reads the real store with include_history=true, which is what server.cpp wires; the Settings
// fragment keeps reading without history and shows the latest decision only (an intended difference).

namespace {

std::set<std::string> keys_of(const nlohmann::json& o) {
    std::set<std::string> out;
    for (auto it = o.begin(); it != o.end(); ++it)
        out.insert(it.key());
    return out;
}

std::set<std::string> property_names(const nlohmann::json& schema) {
    return keys_of(schema.at("properties"));
}

} // namespace

TEST_CASE("decision history: REST, MCP and the Access page agree, and the OpenAPI schema names exactly "
          "what is emitted",
          "[pg][access_review][rest][mcp][access-reviews][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    seed_user_grant(h, "alice");
    const auto cid = h.open_campaign_rest("history reads");

    // The first decision carries a justification longer than the preview, so once it is
    // superseded every read surface returns it cut and flagged (the #4752 read ceiling).
    const std::string long_note(600, 'x');
    h.session_user = "carol";
    REQUIRE(h.sink
                .Post(attest_url(cid),
                      nlohmann::json{{"principal_type", "user"},
                                     {"principal_id", "bob"},
                                     {"role_name", "Operator"},
                                     {"decision", "attested"},
                                     {"justification", long_note}}
                          .dump())
                ->status == 200);
    h.session_user = "dave";
    REQUIRE(h.sink
                .Post(attest_url(cid),
                      nlohmann::json{{"principal_type", "user"},
                                     {"principal_id", "bob"},
                                     {"role_name", "Operator"},
                                     {"decision", "flagged_revoke"},
                                     {"justification", "left <the> team"}}
                          .dump())
                ->status == 200);

    const auto find_att = [](const nlohmann::json& atts, const std::string& id) {
        for (const auto& a : atts)
            if (a["principal_id"] == id)
                return a;
        FAIL("attestation not found: " << id);
        return nlohmann::json{};
    };

    auto rest = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(rest);
    REQUIRE(rest->status == 200);
    const auto rest_atts = nlohmann::json::parse(rest->body)["data"]["attestations"];
    const auto bob = find_att(rest_atts, "bob");
    CHECK(bob["decision"] == "flagged_revoke");
    CHECK(bob["reviewer"] == "dave");
    CHECK(bob["decision_seq"] == 2);
    REQUIRE(bob["history"].is_array());
    REQUIRE(bob["history"].size() == 2);
    CHECK(bob["history"][0]["seq"] == 1);
    CHECK(bob["history"][0]["decision"] == "attested");
    CHECK(bob["history"][0]["previous_decision"] == "pending");
    CHECK(bob["history"][0]["reviewer"] == "carol");
    CHECK(bob["history"][1]["seq"] == 2);
    CHECK(bob["history"][1]["decision"] == "flagged_revoke");
    CHECK(bob["history"][1]["previous_decision"] == "attested");
    CHECK(bob["history"][1]["reviewer"] == "dave");
    CHECK(bob["history"][1]["justification"] == "left <the> team");
    CHECK(bob["history"][1]["decided_at_ms"].get<std::int64_t>() > 0);
    // The superseded entry is cut to the preview and flagged; the latest entry is whole.
    CHECK(bob["history"][0]["justification"] == std::string(512, 'x'));
    CHECK(bob["history"][0]["justification_truncated"] == true);
    CHECK(bob["history"][1]["justification_truncated"] == false);
    CHECK(bob["justification"] == "left <the> team");

    // A grant nobody has decided: seq 0 and an empty array, never absent.
    const auto alice = find_att(rest_atts, "alice");
    CHECK(alice["decision"] == "pending");
    CHECK(alice["decision_seq"] == 0);
    REQUIRE(alice.contains("history"));
    CHECK(alice["history"].is_array());
    CHECK(alice["history"].empty());

    // MCP returns the identical attestation objects.
    auto mcp = h.mcp_call_tool("get_access_review", {{"campaign_id", cid}});
    REQUIRE(mcp);
    const auto mcp_body = nlohmann::json::parse(mcp->body);
    REQUIRE(mcp_body.contains("result"));
    const auto mcp_atts = mcp_body["result"]["structuredContent"]["attestations"];
    CHECK(mcp_atts.dump() == rest_atts.dump());
    CHECK(find_att(mcp_atts, "bob")["history"].size() == 2);
    CHECK(find_att(mcp_atts, "bob")["history"][0]["justification_truncated"] == true);

    // OpenAPI names exactly the keys the route emits, on both the row and the history entry.
    const auto spec = nlohmann::json::parse(yuzu::server::openapi_spec_json());
    const auto& schemas = spec["components"]["schemas"];
    const auto& att_schema = schemas["AccessReviewAttestation"];
    CHECK(property_names(att_schema) == keys_of(bob));
    CHECK(std::set<std::string>(att_schema["required"].begin(), att_schema["required"].end()) ==
          keys_of(bob));
    const auto& hist_schema = schemas["AccessReviewAttestationHistoryEntry"];
    CHECK(property_names(hist_schema) == keys_of(bob["history"][0]));
    CHECK(std::set<std::string>(hist_schema["required"].begin(), hist_schema["required"].end()) ==
          keys_of(bob["history"][0]));
    CHECK(att_schema["properties"]["history"]["items"]["$ref"] ==
          "#/components/schemas/AccessReviewAttestationHistoryEntry");
    // The OpenAPI prose states the preview length from the constant, so a change to one that
    // leaves the other behind fails.
    const std::string preview_chars =
        std::to_string(yuzu::server::kHistoryJustificationPreviewChars);
    const std::string first_n = "first " + preview_chars + " characters";
    CHECK(spec["paths"]["/access-reviews/{id}"]["get"]["description"].get<std::string>().find(
              first_n) != std::string::npos);
    CHECK(spec["paths"]["/access-reviews/{id}/attestations"]["post"]["description"]
              .get<std::string>()
              .find(first_n) != std::string::npos);
    CHECK(hist_schema["properties"]["justification"]["description"].get<std::string>().find(
              "at most its first " + preview_chars + " characters") != std::string::npos);

    // The MCP output schema names exactly the keys the tool emits for a history entry too (an
    // extra emitted key must fail here, not only a missing one).
    {
        nlohmann::json list = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/list"}};
        auto tools = h.mcp_call(list.dump());
        REQUIRE(tools);
        bool schema_found = false;
        for (const auto& t : nlohmann::json::parse(tools->body)["result"]["tools"]) {
            if (t["name"] != "get_access_review")
                continue;
            schema_found = true;
            const auto& mcp_hist =
                t["outputSchema"]["properties"]["attestations"]["items"]["properties"]["history"]
                 ["items"];
            CHECK(property_names(mcp_hist) == keys_of(find_att(mcp_atts, "bob")["history"][0]));
            CHECK(std::set<std::string>(mcp_hist["required"].begin(),
                                        mcp_hist["required"].end()) ==
                  keys_of(find_att(mcp_atts, "bob")["history"][0]));
        }
        CHECK(schema_found);
    }

    // The Access page: the real fragment route over the real store, history opted in.
    yuzu::server::test::TestRouteSink page;
    yuzu::server::access_reviews::ReviewsDeps d;
    d.auth_fn = [&h](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = h.session_user;
        s.role = h.session_role;
        return s;
    };
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    d.quiet_perm_fn = d.perm_fn;
    d.probe_perm_fn = [](const httplib::Request&, const std::string&, const std::string&) {
        return true;
    };
    d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    d.list_campaigns_fn = []() -> std::expected<std::vector<AccessReviewCampaignRow>, std::string> {
        return std::vector<AccessReviewCampaignRow>{};
    };
    d.get_campaign_fn = [&h](const std::string& id) {
        return h.access_review_store->get_campaign(id, /*include_history=*/true);
    };
    d.grants_fn = []() -> std::expected<yuzu::server::access_reviews::GrantsView, std::string> {
        return yuzu::server::access_reviews::GrantsView{};
    };
    yuzu::server::access_reviews::register_access_reviews_routes(page, std::move(d));
    const auto frag = page.Get("/fragments/access/reviews/campaign?id=" + cid);
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    CHECK(frag->body.find("<span class=\"pill warn\">flagged_revoke</span>") != std::string::npos);
    CHECK(frag->body.find("superseded 1 earlier decision") != std::string::npos);
    CHECK(frag->body.find("#1 attested (previous: pending) by carol") != std::string::npos);
    CHECK(frag->body.find("#2 flagged_revoke (previous: attested) by dave") != std::string::npos);
    // The justification carries markup; it reaches the page escaped only.
    CHECK(frag->body.find("left &lt;the&gt; team") != std::string::npos);
    CHECK(frag->body.find("left <the> team") == std::string::npos);
    // The cut entry shows the preview and the marker; the whole one shows none.
    CHECK(frag->body.find(std::string(512, 'x') + " (truncated)") != std::string::npos);
    CHECK(frag->body.find(std::string(513, 'x')) == std::string::npos);
    std::size_t markers = 0;
    for (auto at = frag->body.find("(truncated)"); at != std::string::npos;
         at = frag->body.find("(truncated)", at + 1))
        ++markers;
    CHECK(markers == 1);
}

// The ceiling in numbers: a grant at the 100-decision limit with a 4096-character justification on
// every decision serialises to one whole latest entry plus 99 previews, not 100 x 4 KiB. The bound
// is derived from the constants; kEntryOverheadBytes covers the fixed keys, the seq, the decision
// words, a short reviewer name and the timestamp of one entry (320 is an ASCII estimate with
// headroom, not a measurement).
TEST_CASE("decision history: a grant at the decision limit serialises under the derived ceiling",
          "[pg][access_review][rest][access-reviews][4752]") {
    constexpr std::size_t kEntryOverheadBytes = 320;
    constexpr std::size_t kBound =
        static_cast<std::size_t>(yuzu::server::kMaxDecisionsPerGrant) *
            (static_cast<std::size_t>(yuzu::server::kHistoryJustificationPreviewChars) +
             kEntryOverheadBytes) +
        yuzu::server::kMaxJustificationBytes;
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("read ceiling");
    for (std::int32_t i = 1; i <= yuzu::server::kMaxDecisionsPerGrant; ++i) {
        REQUIRE(h.access_review_store
                    ->record_attestation(cid, "user", "bob", "Operator",
                                         i % 2 ? "attested" : "flagged_revoke", "carol",
                                         std::string(yuzu::server::kMaxJustificationBytes, 'j'))
                    .has_value());
    }
    auto rest = h.sink.Get("/api/v1/access-reviews/" + cid);
    REQUIRE(rest);
    REQUIRE(rest->status == 200);
    const auto atts = nlohmann::json::parse(rest->body)["data"]["attestations"];
    REQUIRE(atts.size() == 1);
    const auto& history = atts[0]["history"];
    REQUIRE(history.size() == 100);
    for (std::size_t i = 0; i < 99; ++i) {
        CHECK(history[i]["justification"].get<std::string>().size() == 512);
        CHECK(history[i]["justification_truncated"] == true);
    }
    CHECK(history[99]["justification"].get<std::string>().size() == 4096);
    CHECK(history[99]["justification_truncated"] == false);
    const auto bytes = history.dump().size();
    INFO("serialised history bytes: " << bytes << " bound: " << kBound);
    CHECK(bytes < kBound);
    // Not vacuous: the stored text alone is 100 x 4096 bytes, well over the bound.
    CHECK(static_cast<std::size_t>(yuzu::server::kMaxDecisionsPerGrant) *
              yuzu::server::kMaxJustificationBytes >
          kBound);
}

// ── Per-grant decision cap and the success body (#4752) ────────────────────

namespace {

// Fill one grant to exactly `kMaxDecisionsPerGrant` decisions through the store, which the REST and
// MCP handlers sit on (the cap is the store's, so this is the same state a run of real attests
// leaves).
void fill_grant_to_cap(AccessReviewHarness& h, const std::string& cid, const std::string& user,
                       const std::string& reviewer) {
    for (std::int32_t i = 1; i <= yuzu::server::kMaxDecisionsPerGrant; ++i) {
        auto r = h.access_review_store->record_attestation(
            cid, "user", user, "Operator", i % 2 ? "attested" : "flagged_revoke", reviewer, "");
        REQUIRE(r.has_value());
        REQUIRE(r->seq == i);
    }
}

} // namespace

TEST_CASE("attestation cap: the decision after the 100th is 400 on REST and invalid-params on MCP, "
          "audited as a failure, and writes nothing",
          "[pg][access_review][rest][mcp][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    seed_user_grant(h, "erin");
    const auto cid = h.open_campaign_rest("decision cap");
    fill_grant_to_cap(h, cid, "bob", "carol");
    h.session_user = "carol";
    h.audit_log.clear();
    const std::string tuple = " principal_type=user principal_id=bob role=Operator";
    // The wire text is the bare message: the store's `bad_request: ` classification prefix is
    // stripped for this refusal (the audit detail below keeps the store text).
    const std::string expected{yuzu::server::kDecisionCapMessage};
    REQUIRE_FALSE(expected.starts_with("bad_request"));

    const auto unchanged = [&] {
        const auto row = grant_row(h, cid, "user", "bob", "Operator");
        CHECK(row.decision_seq == 100);
        CHECK(row.decision == "flagged_revoke"); // the 100th decision is even
        CHECK(row.reviewer == "carol");
        CHECK(row.history.size() == 100);
        CHECK(row.history.back().seq == 100);
    };

    SECTION("REST") {
        auto res = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body.contains("error")); // a success body here means the cap was not enforced
        CHECK(body["error"]["message"] == expected);
        CHECK(body["error"]["retry_after_ms"].is_null()); // a refusal, not a retryable fault
        // The existing bad_request path: one failure row under the attested verb, the campaign as
        // target and the grant tuple in the detail; no success row, no flagged row.
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail.starts_with("bad_request:"));
        CHECK(rows[0].detail.ends_with(tuple));
        CHECK(audit_rows(h, "access_review.flagged").empty());
        unchanged();

        // The refusal repeats and still writes nothing.
        auto again = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator", "attested"));
        REQUIRE(again);
        CHECK(again->status == 400);
        unchanged();

        // Another grant in the same campaign is unaffected.
        auto other = h.sink.Post(attest_url(cid), sod_body("user", "erin", "Operator"));
        REQUIRE(other);
        CHECK(other->status == 200);
        CHECK(nlohmann::json::parse(other->body)["data"]["decision_seq"] == 1);
    }

    SECTION("MCP") {
        auto res = h.mcp_call_tool("record_attestation", sod_args(cid, "user", "bob", "Operator"));
        const auto err = mcp_error_of(res);
        CHECK(err["code"] == yuzu::server::mcp::kInvalidParams);
        CHECK(err["message"] == expected);
        const auto rows = audit_rows(h, "access_review.attested");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].target_id == cid);
        CHECK(rows[0].detail.starts_with("bad_request:"));
        CHECK(rows[0].detail.ends_with(tuple));
        const auto wrapper = audit_rows(h, "mcp.record_attestation");
        REQUIRE(wrapper.size() == 1);
        CHECK(wrapper[0].result == "failure");
        unchanged();

        auto other =
            h.mcp_call_tool("record_attestation", sod_args(cid, "user", "erin", "Operator"));
        REQUIRE(other);
        const auto sc = nlohmann::json::parse(other->body)["result"]["structuredContent"];
        REQUIRE(sc.contains("decision_seq"));
        CHECK(sc["decision_seq"] == 1);
        CHECK(sc["previous_decision"] == "pending");
    }
}

// Negative control for the wire-prefix strip: only the cap refusal loses its `bad_request: `
// classification prefix. Another store refusal of the caller's (a justification over its bound,
// decided in the store after the gate) keeps the text it has always had, on both transports.
TEST_CASE("attestation wire text: only the cap refusal loses the bad_request prefix, another store "
          "refusal keeps it on REST and MCP",
          "[pg][access_review][rest][mcp][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("wire prefix");
    h.session_user = "carol";
    const std::string too_long(yuzu::server::kMaxJustificationBytes + 1, 'j');
    const std::string expected = "bad_request: justification exceeds " +
                                 std::to_string(yuzu::server::kMaxJustificationBytes) + " bytes";

    SECTION("REST") {
        auto req = nlohmann::json::parse(sod_body("user", "bob", "Operator"));
        req["justification"] = too_long;
        auto res = h.sink.Post(attest_url(cid), req.dump());
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["message"].get<std::string>().starts_with("bad_request: "));
        CHECK(body["error"]["message"] == expected);
    }

    SECTION("MCP") {
        auto args = sod_args(cid, "user", "bob", "Operator");
        args["justification"] = too_long;
        auto res = h.mcp_call_tool("record_attestation", args);
        const auto err = mcp_error_of(res);
        CHECK(err["code"] == yuzu::server::mcp::kInvalidParams);
        CHECK(err["message"].get<std::string>().starts_with("bad_request: "));
        CHECK(err["message"] == expected);
    }
    // Nothing was recorded.
    CHECK(grant_row(h, cid, "user", "bob", "Operator").decision_seq == 0);
}

TEST_CASE("attestation success body: OpenAPI and the MCP output schema name exactly the fields the "
          "handlers return",
          "[pg][access_review][rest][mcp][4752]") {
    AccessReviewHarness h;
    seed_user_grant(h, "bob");
    const auto cid = h.open_campaign_rest("success schema");
    h.session_user = "carol";

    auto rest = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
    REQUIRE(rest);
    REQUIRE(rest->status == 200);
    const auto data = nlohmann::json::parse(rest->body)["data"];

    const auto spec = nlohmann::json::parse(yuzu::server::openapi_spec_json());
    const auto& ok = spec["paths"]["/access-reviews/{id}/attestations"]["post"]["responses"]["200"];
    const auto& props =
        ok["content"]["application/json"]["schema"]["properties"]["data"]["properties"];
    CHECK(props.size() == data.size());
    for (auto it = data.begin(); it != data.end(); ++it)
        CHECK(props.contains(it.key()));
    CHECK(ok["content"]["application/json"]["schema"]["properties"]["data"]["required"].size() ==
          data.size());

    nlohmann::json list = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/list"}};
    auto tools = h.mcp_call(list.dump());
    REQUIRE(tools);
    const auto tool_list = nlohmann::json::parse(tools->body)["result"]["tools"];
    bool found = false;
    for (const auto& t : tool_list) {
        if (t["name"] != "record_attestation")
            continue;
        found = true;
        const auto& out = t["outputSchema"];
        CHECK(out["properties"]["decision_seq"]["type"] == "integer");
        CHECK(out["properties"]["previous_decision"]["type"] == "string");
        CHECK(out["properties"].size() == 3);
        CHECK(out["required"].size() == 3);
    }
    CHECK(found);
}

// The limits are spelled out in the MCP schema, the MCP description and the OpenAPI text. Each is
// rendered here from the constants, so a change to a constant that leaves one of them behind fails.
TEST_CASE("attestation limits: the MCP input schema and description and the OpenAPI text carry "
          "the constants' numbers",
          "[pg][access_review][rest][mcp][4752]") {
    AccessReviewHarness h;
    const std::string principal_max = std::to_string(yuzu::server::kPrincipalIdMaxLen);
    const std::string role_max = std::to_string(yuzu::server::kRoleNameMaxLen);
    const std::string just_max = std::to_string(yuzu::server::kMaxJustificationBytes);
    const std::string cap = std::to_string(yuzu::server::kMaxDecisionsPerGrant);

    nlohmann::json list = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/list"}};
    auto tools = h.mcp_call(list.dump());
    REQUIRE(tools);
    bool found = false;
    for (const auto& t : nlohmann::json::parse(tools->body)["result"]["tools"]) {
        if (t["name"] != "record_attestation")
            continue;
        found = true;
        const auto& in = t["inputSchema"]["properties"];
        CHECK(in["principal_id"]["maxLength"] == yuzu::server::kPrincipalIdMaxLen);
        CHECK(in["role_name"]["maxLength"] == yuzu::server::kRoleNameMaxLen);
        CHECK(in["justification"]["maxLength"] == yuzu::server::kMaxJustificationBytes);
        const auto desc = t["description"].get<std::string>();
        CHECK(desc.find("principal_id and role_name are at most " + principal_max +
                        " bytes each and justification at most " + just_max + " bytes") !=
              std::string::npos);
        CHECK(desc.find("at most " + cap + " recorded decisions") != std::string::npos);
    }
    CHECK(found);

    const auto spec = nlohmann::json::parse(yuzu::server::openapi_spec_json());
    const auto& post = spec["paths"]["/access-reviews/{id}/attestations"]["post"];
    const auto& body =
        post["requestBody"]["content"]["application/json"]["schema"]["properties"];
    CHECK(body["principal_id"]["maxLength"] == yuzu::server::kPrincipalIdMaxLen);
    CHECK(body["role_name"]["maxLength"] == yuzu::server::kRoleNameMaxLen);
    CHECK(body["justification"]["maxLength"] == yuzu::server::kMaxJustificationBytes);
    const auto bad = post["responses"]["400"]["description"].get<std::string>();
    CHECK(bad.find("over " + principal_max + " bytes") != std::string::npos);
    CHECK(bad.find("maximum of " + cap + " recorded decisions") != std::string::npos);
    CHECK(post["description"].get<std::string>().find("at most " + cap + " decisions") !=
          std::string::npos);
    // The 503 text quotes the fixed store-failure message and its retry hint.
    const auto unavailable = post["responses"]["503"]["description"].get<std::string>();
    CHECK(unavailable.find(std::string(sod::kStoreFailureMessage)) != std::string::npos);
    CHECK(unavailable.find("retry_after_ms " + std::to_string(sod::kStoreFailureRetryMs)) !=
          std::string::npos);
    // The shared refusal texts spell the same numbers.
    CHECK(std::string(yuzu::server::kGrantFieldInvalidMessage).find("1-" + principal_max) !=
          std::string::npos);
    CHECK(std::string(yuzu::server::kDecisionCapMessage).find("(" + cap + ")") !=
          std::string::npos);
    CHECK(principal_max == role_max); // the text names one number for both fields
}

TEST_CASE("bounded history read: a grant carrying 105 history rows returns its latest 100, and the "
          "Access page says how many earlier decisions are not shown",
          "[pg][access_review][rest][access-reviews][4752]") {
    // A per-test migrated clone: the guard triggers are disabled below, which must not reach the
    // file-wide shared database.
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_rest_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    REQUIRE(pool.valid());
    AccessReviewHarness h{true, true, &pool};
    seed_user_grant(h, "bob");
    seed_user_grant(h, "erin");
    const auto cid = h.open_campaign_rest("bounded read");
    h.session_user = "carol";
    REQUIRE(h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"))->status == 200);
    REQUIRE(h.sink.Post(attest_url(cid), sod_body("user", "erin", "Operator"))->status == 200);

    {
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        const std::string att = "access_review_store.access_review_attestation";
        const std::string hist = "access_review_store.access_review_attestation_history";
        for (const std::string sql :
             {"ALTER TABLE " + att + " DISABLE TRIGGER access_review_attestation_guard",
              "ALTER TABLE " + hist + " DISABLE TRIGGER access_review_history_consistent",
              "INSERT INTO " + hist +
                  " (campaign_id, principal_type, principal_id, role_name, seq, decision, "
                  "previous_decision, reviewer, justification, decided_at_ms) "
                  "SELECT '" + cid + "','user','bob','Operator', g, 'attested', 'attested', "
                  "'carol', '', g FROM generate_series(2,105) g",
              "UPDATE " + att + " SET decision_seq=105 WHERE campaign_id='" + cid +
                  "' AND principal_id='bob'"}) {
            yuzu::server::pg::PgResult r{PQexec(c.get(), sql.c_str())};
            INFO(sql);
            REQUIRE(r.ok());
        }
    }

    auto view = h.access_review_store->get_campaign(cid, /*include_history=*/true);
    REQUIRE(view.has_value());
    const yuzu::server::AccessReviewAttestationRow* bob = nullptr;
    const yuzu::server::AccessReviewAttestationRow* erin = nullptr;
    for (const auto& a : view->attestations)
        (a.principal_id == "bob" ? bob : erin) = &a;
    REQUIRE(bob != nullptr);
    REQUIRE(erin != nullptr);
    CHECK(bob->decision_seq == 105);
    REQUIRE(bob->history.size() == 100);
    CHECK(bob->history.front().seq == 6);
    CHECK(bob->history.back().seq == 105);
    for (std::size_t i = 1; i < bob->history.size(); ++i)
        CHECK(bob->history[i].seq == bob->history[i - 1].seq + 1);
    // The other grant keeps its whole (one-entry) history.
    CHECK(erin->decision_seq == 1);
    CHECK(erin->history.size() == 1);

    // Without history the shape is unchanged: no entries, the total still reported.
    auto bare = h.access_review_store->get_campaign(cid);
    REQUIRE(bare.has_value());
    for (const auto& a : bare->attestations)
        CHECK(a.history.empty());

    // The write cap still holds past the cap: nothing more is recorded for the over-cap grant.
    auto over = h.sink.Post(attest_url(cid), sod_body("user", "bob", "Operator"));
    REQUIRE(over);
    CHECK(over->status == 400);

    // The Access page names the gap.
    yuzu::server::test::TestRouteSink page;
    yuzu::server::access_reviews::ReviewsDeps d;
    d.auth_fn = [&h](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = h.session_user;
        s.role = h.session_role;
        return s;
    };
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    d.quiet_perm_fn = d.perm_fn;
    d.probe_perm_fn = [](const httplib::Request&, const std::string&, const std::string&) {
        return true;
    };
    d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    d.list_campaigns_fn = []() -> std::expected<std::vector<AccessReviewCampaignRow>, std::string> {
        return std::vector<AccessReviewCampaignRow>{};
    };
    d.get_campaign_fn = [&h](const std::string& id) {
        return h.access_review_store->get_campaign(id, /*include_history=*/true);
    };
    d.grants_fn = []() -> std::expected<yuzu::server::access_reviews::GrantsView, std::string> {
        return yuzu::server::access_reviews::GrantsView{};
    };
    yuzu::server::access_reviews::register_access_reviews_routes(page, std::move(d));
    const auto frag = page.Get("/fragments/access/reviews/campaign?id=" + cid);
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    CHECK(frag->body.find("5 earlier decisions are not shown") != std::string::npos);
    CHECK(frag->body.find("#6 attested") != std::string::npos);
    CHECK(frag->body.find("#5 attested") == std::string::npos);
    // The grant with a complete history shows no such line (the phrase appears once).
    const auto first = frag->body.find("earlier decisions are not shown");
    CHECK(frag->body.find("earlier decisions are not shown", first + 1) == std::string::npos);
}
