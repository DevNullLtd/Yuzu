/**
 * test_mcp_engine_principal_roles.cpp — MCP JSON-RPC twins of
 * `/api/v1/engine-principals/{id}/roles` (PR 4.2, design doc
 * docs/auth-engine-principals-design.md §4.1), covering `assign_engine_role`
 * / `unassign_engine_role` / `list_engine_roles`.
 *
 * Pattern: build the McpServer POST /mcp/v1/ handler via
 * `McpServer::build_handler()` and dispatch synthesized httplib::Request
 * objects directly — no httplib::Server, no acceptor thread (mirrors
 * test_mcp_server.cpp's McpTestServer fixture; #438).
 *
 * PG-gated: EnginePrincipalStore is a born-on-Postgres store (ADR-0006).
 * Skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken.
 */

#include "engine_principal_store.hpp"
#include "mcp_server.hpp"
#include "rbac_store.hpp"

#include "pg/pg_pool.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>

#include <memory>
#include <optional>
#include <string>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using namespace yuzu::server::mcp;

namespace {

void setup_engine_principal_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("engine_principal (mcp roles) template: store failed to migrate");
}

yuzu::test::PgTestTemplate engine_principal_mcp_template{
    "engineprincipal_mcp", &setup_engine_principal_store_pg_template};

class EnginePrincipalStorePg {
public:
    EnginePrincipalStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(engine_principal_mcp_template);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<EnginePrincipalStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    EnginePrincipalStorePg(const EnginePrincipalStorePg&) = delete;
    EnginePrincipalStorePg& operator=(const EnginePrincipalStorePg&) = delete;

    [[nodiscard]] EnginePrincipalStore* get() const noexcept { return store_.get(); }
    EnginePrincipalStore* operator->() const noexcept { return store_.get(); }

    /// Direct access to the pool backing this store — this class builds a
    /// fresh, per-instance clone database (unlike the shared/process-wide
    /// EnginePrincipalStorePg variants in test_engine_principal_integration.cpp
    /// / test_engine_principal_lifecycle.cpp), so it's safe for a sibling
    /// store (RbacStore, below) to coexist on the SAME pool/database without
    /// any cross-TEST_CASE contamination risk.
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<EnginePrincipalStore> store_;
};

struct McpEngineRolesHarness {
    // engine_store declared FIRST: rbac_store's default member initializer
    // constructs it on engine_store's pool (both stores' schemas coexist in
    // that one fresh-per-instance database), and reverse-declaration-order
    // destruction then closes rbac_store before engine_store's pool goes away.
    EnginePrincipalStorePg engine_store;
    RbacStore rbac_store{engine_store.pool()};

    bool read_only_mode{false};
    bool mcp_disabled{false};
    // #3937: when false, audit_fn returns false (dropped row) so the role
    // mutation twins must fail closed (JSON-RPC 503 error, not success).
    bool audit_succeeds{true};

    // Not-an-MCP-token session (mcp_tier == "") so tier_allows()/
    // requires_approval() are both no-ops — exercises the route/RBAC logic
    // without standing up an ApprovalManager (mirrors many McpTestServer
    // tests in test_mcp_server.cpp that use the empty-tier session).
    std::string mock_username{"admin"};
    auth::Role mock_role{auth::Role::admin};

    std::vector<std::string> audit_log; // "action|result"

    McpServer mcp;
    McpServer::HandlerFn handler;

    McpEngineRolesHarness() {
        REQUIRE(rbac_store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = mock_username;
            s.role = mock_role;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string&) -> bool {
            audit_log.push_back(action + "|" + result);
            return audit_succeeds;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };

        handler = mcp.build_handler(
            std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), std::move(agents_fn),
            /*rbac_store=*/&rbac_store,
            /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr,
            /*audit_store=*/nullptr,
            /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr,
            /*policy_store=*/nullptr,
            /*mgmt_store=*/nullptr,
            /*approval_manager=*/nullptr,
            /*schedule_engine=*/nullptr, read_only_mode, mcp_disabled,
            /*dispatch_fn=*/nullptr,
            /*ca_store=*/nullptr,
            /*publish_crl_fn=*/nullptr,
            /*guaranteed_state_store=*/nullptr,
            /*dex_perf_fn=*/{},
            /*network_api=*/{},
            /*response_scope_fn=*/{},
            /*software_inventory_store=*/nullptr,
            /*metrics=*/nullptr,
            /*quarantine_store=*/nullptr,
            /*tag_push_fn=*/{},
            /*agent_registry=*/nullptr,
            /*scoped_perm_fn=*/{},
            /*sessions=*/nullptr,
            /*mcp_streaming_disabled=*/nullptr,
            /*mcp_streamed_post_enabled=*/nullptr,
            /*allowed_origins=*/{},
            /*software_licensing_store=*/nullptr,
            /*engine_principal_store=*/engine_store.get());
    }

    std::unique_ptr<httplib::Response> call(const std::string& json_body) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/mcp/v1/";
        req.body = json_body;
        req.set_header("Content-Type", "application/json");
        auto res = std::make_unique<httplib::Response>();
        res->status = 200;
        REQUIRE(handler);
        handler(req, *res);
        return res;
    }

    std::unique_ptr<httplib::Response> call_tool(const std::string& name,
                                                 const nlohmann::json& args) {
        nlohmann::json req = {{"jsonrpc", "2.0"},
                              {"id", 1},
                              {"method", "tools/call"},
                              {"params", {{"name", name}, {"arguments", args}}}};
        return call(req.dump());
    }
};

} // namespace

TEST_CASE("MCP assign_engine_role: grants a fleet-wide role, resolvable via check_permission",
          "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store
               ->create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                        "engine:vuln")
               .has_value());

    CHECK_FALSE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));

    auto res = h.call_tool("assign_engine_role",
                           {{"principal_id", "vuln"}, {"role", "EngineReader"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") == std::string::npos);
    CHECK(res->body.find("EngineReader") != std::string::npos);

    // The end-to-end proof: the MCP authoring surface reaches the same
    // RbacStore::assign_role the REST route does — the resolver's engine
    // UNION arm is now reachable.
    CHECK(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));

    bool found = false;
    for (const auto& a : h.audit_log)
        if (a == "engine_principal.role.assigned|success")
            found = true;
    CHECK(found);
}

TEST_CASE("MCP unassign_engine_role: revokes a previously-assigned role",
          "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    REQUIRE(h.rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());
    REQUIRE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));

    auto res = h.call_tool("unassign_engine_role",
                           {{"principal_id", "vuln"}, {"role", "EngineReader"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"unassigned\":true") != std::string::npos);

    CHECK_FALSE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));
}

// #3937: the role mutation twins fail closed (JSON-RPC error, not success) when
// their audit row cannot persist — parity with REST #2466 + the plugin-config
// MCP precedent. The grant still committed (the mutation happened before the
// audit); the error tells the caller to reconcile via a read.
TEST_CASE("MCP #3937: assign_engine_role fails CLOSED on a dropped audit (grant still committed)",
          "[pg][mcp][engine_principal][rbac][audit_failclose]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    // Explicit before/after bracket (qe parity with the unassign test): the grant
    // is NOT yet in effect, so the post-call check proves the mutation committed.
    REQUIRE_FALSE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));

    h.audit_succeeds = false;
    auto res = h.call_tool("assign_engine_role",
                           {{"principal_id", "vuln"}, {"role", "EngineReader"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("could not be persisted") != std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant DID commit though the audit dropped.
    CHECK(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));
}

TEST_CASE("MCP #3937: unassign_engine_role fails CLOSED on a dropped audit (grant still removed)",
          "[pg][mcp][engine_principal][rbac][audit_failclose]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    REQUIRE(h.rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());
    REQUIRE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));

    h.audit_succeeds = false;
    auto res = h.call_tool("unassign_engine_role",
                           {{"principal_id", "vuln"}, {"role", "EngineReader"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant was removed though the audit dropped.
    CHECK_FALSE(h.rbac_store.check_permission("engine:vuln", "Inventory", "Read"));
}

// #3937: create/revoke/transfer share the byte-identical fail-closed block with
// the 5 tested twins (mint/rotate/confirm/assign/unassign) but need additional
// harness wiring the role fixture lacks to reach their store mutation on the
// audit-drop path (create/transfer: the supervised-tier + owner FK path;
// revoke: an engine-credential store) — tracked as a follow-up. The block itself
// is verified byte-for-byte by the Gate-2 security review.
TEST_CASE("MCP list_engine_roles: reflects current grants", "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    REQUIRE(h.rbac_store.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());

    auto res = h.call_tool("list_engine_roles", {{"principal_id", "vuln"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("EngineReader") != std::string::npos);
    CHECK(res->body.find("\"count\":1") != std::string::npos);
}

TEST_CASE("MCP assign_engine_role: admin role rejected 4xx-shaped JSON-RPC error, never a "
          "silent success",
          "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    auto res = h.call_tool("assign_engine_role", {{"principal_id", "vuln"}, {"role", "admin"}});
    REQUIRE(res);
    CHECK(res->status == 200); // JSON-RPC transport-level 200; the error is in the body
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac_store.get_principal_roles("engine", "engine:vuln").empty());
}

TEST_CASE("MCP assign_engine_role: nonexistent engine principal rejected",
          "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());

    auto res = h.call_tool("assign_engine_role",
                           {{"principal_id", "no-such-principal"}, {"role", "EngineReader"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac_store.get_principal_roles("engine", "engine:no-such-principal").empty());
}

TEST_CASE("MCP engine-role tools reject a slug outside [a-z0-9._-] (A1 — no charset gap vs REST)",
          "[pg][mcp][engine_principal][rbac]") {
    McpEngineRolesHarness h;
    REQUIRE(h.rbac_store.create_role({.name = "EngineReader", .description = "d"}).has_value());

    // The MCP slug arrives via param_str (any string) — unlike the REST URL
    // regex — so it must be charset-validated before becoming engine:<slug>
    // or landing in an audit-detail string. Uppercase, ':' (double-prefix),
    // path-traversal, and markup chars must all be rejected with an error,
    // and no grant must land.
    for (const std::string bad : {"Vuln", "a:b", "../etc", "x<script>", "has space"}) {
        auto res = h.call_tool("assign_engine_role", {{"principal_id", bad}, {"role", "EngineReader"}});
        REQUIRE(res);
        CHECK(res->body.find("\"error\"") != std::string::npos);
        CHECK(res->body.find("invalid principal_id") != std::string::npos);
        CHECK(h.rbac_store.get_principal_roles("engine", "engine:" + bad).empty());
    }
}

TEST_CASE("MCP: assign_engine_role / unassign_engine_role / list_engine_roles are advertised "
          "in tools/list",
          "[pg][mcp][engine_principal][integration]") {
    McpEngineRolesHarness h;
    auto res = h.call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    CHECK(res->body.find("\"assign_engine_role\"") != std::string::npos);
    CHECK(res->body.find("\"unassign_engine_role\"") != std::string::npos);
    CHECK(res->body.find("\"list_engine_roles\"") != std::string::npos);
}
