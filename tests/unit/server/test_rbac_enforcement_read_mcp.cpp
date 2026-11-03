/**
 * test_rbac_enforcement_read_mcp.cpp - the MCP tool `get_rbac_enforcement` (#6033), the machine twin
 * of GET /fragments/access/enforcement (the REST twin is GET /api/v1/rbac/enforcement).
 *
 * The tool is a thin wrapper over `read_rbac_enforcement` (rbac_enforcement_read.hpp) on the kMcp
 * surface. What is pinned here is the MCP-specific contract around it:
 *   - the served metadata (typed output schema, empty strict input schema, read-only annotations);
 *   - the generic tier gate and the default-denied service-scope class (both audited by C8);
 *   - the handler refusing any supplied argument itself (additionalProperties:false is not enforced
 *     for a tool that is not approval-gated);
 *   - the null/closed store: a retryable error, NO audit row, no raw store text in the body;
 *   - the dual audit: the domain row `rbac.enforcement.read` AND the generic `mcp.get_rbac_enforcement`
 *     row are each attempted, and `audit_persisted:false` reports either one dropping with the data
 *     still returned;
 *   - the `administrator` verdict on the kMcp surface (no tier rule), independent of `unconfirmed`.
 *
 * The tool is driven through its OWN handler (`McpRig`) built on the stores of an `RbacRoleHarness`,
 * not the harness's handler, because three cases need what the harness cannot give: a null or closed
 * RBAC store, a degraded enforcement view, and an audit sink that drops one action's row.
 *
 * PG-gated (RbacStore, AuthDB). Skips when YUZU_TEST_POSTGRES_DSN is unset; a skip is NOT a pass.
 */

#include "mcp_retry.hpp"
#include "rbac_admin_predicate.hpp"
#include "rbac_enforcement_read.hpp"
#include "saml_principal.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_json_schema_subset.hpp"
#include "test_rbac_admin_surface_harness.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kTool = "get_rbac_enforcement";

/// An MCP handler of its own over the harness's stores, with a caller-chosen RBAC store and an audit
/// sink that can drop the rows of named actions. The session is the harness's (`session_*` fields,
/// stamped with `session_mcp_tier`), read live on every call so a test can change it after
/// construction. Every audit attempt is recorded in `audit_log` BEFORE the drop decision, so a test
/// sees that a row was attempted even when it was dropped.
struct McpRig {
    RbacRoleHarness& h;
    bool read_only{false};
    bool disabled{false};
    std::vector<AuditRecord> audit_log;
    std::set<std::string> drop_actions; ///< rows for these actions are attempted but not persisted
    yuzu::server::mcp::McpServer server;
    yuzu::server::mcp::McpServer::HandlerFn handler;

    McpRig(RbacRoleHarness& harness, RbacStore* store) : h(harness) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
            return h.session_with_tier(h.session_mcp_tier);
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail, target_type});
            return drop_actions.count(action) == 0;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };
        handler = server.build_handler(
            std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), std::move(agents_fn),
            /*rbac_store=*/store,
            /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr,
            /*audit_store=*/nullptr,
            /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr,
            /*policy_store=*/nullptr,
            /*mgmt_store=*/nullptr,
            /*approval_manager=*/h.appr.get(),
            /*schedule_engine=*/nullptr, read_only, disabled,
            /*dispatch_fn=*/nullptr,
            /*ca_store=*/nullptr,
            /*publish_crl_fn=*/nullptr,
            /*guaranteed_state_store=*/nullptr,
            /*dex_perf_fn=*/{},
            /*network_api=*/{},
            /*response_scope_fn=*/{},
            /*software_inventory_store=*/nullptr,
            /*metrics=*/&h.metrics,
            /*quarantine_store=*/nullptr,
            /*tag_push_fn=*/{},
            /*agent_registry=*/nullptr,
            /*scoped_perm_fn=*/{},
            /*sessions=*/nullptr,
            /*mcp_streaming_disabled=*/nullptr,
            /*mcp_streamed_post_enabled=*/nullptr,
            /*allowed_origins=*/{},
            /*software_licensing_store=*/nullptr,
            /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr,
            /*auth_db=*/h.auth_db.get(),
            /*directory_sync=*/nullptr);
    }

    /// POSTs a raw JSON-RPC body and parses the answer.
    nlohmann::json raw(const std::string& json_body) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/mcp/v1/";
        req.body = json_body;
        req.set_header("Content-Type", "application/json");
        httplib::Response res;
        res.status = 200;
        REQUIRE(handler);
        handler(req, res);
        auto body = nlohmann::json::parse(res.body, nullptr, /*allow_exceptions=*/false);
        REQUIRE_FALSE(body.is_discarded());
        return body;
    }

    nlohmann::json call_tool(const std::string& name, const nlohmann::json& args) {
        const nlohmann::json req = {{"jsonrpc", "2.0"},
                                    {"id", 1},
                                    {"method", "tools/call"},
                                    {"params", {{"name", name}, {"arguments", args}}}};
        return raw(req.dump());
    }

    /// `get_rbac_enforcement` with no arguments.
    nlohmann::json call() { return call_tool(kTool, nlohmann::json::object()); }

    /// The served tools/list entry for the tool.
    nlohmann::json served_tool() {
        const auto list = raw(R"({"jsonrpc":"2.0","method":"tools/list","id":2})");
        nlohmann::json found;
        for (const auto& t : list["result"]["tools"])
            if (t["name"] == kTool)
                found = t;
        REQUIRE(found.is_object()); // a missing tool must fail here, never pass a check vacuously
        return found;
    }

    std::size_t rows(const std::string& action, const std::string& result) const {
        std::size_t n = 0;
        for (const auto& r : audit_log)
            if (r.action == action && r.result == result)
                ++n;
        return n;
    }
    std::size_t rows_for(const std::string& action) const {
        std::size_t n = 0;
        for (const auto& r : audit_log)
            if (r.action == action)
                ++n;
        return n;
    }
    /// Neither the domain row nor the generic row was attempted, whatever the result.
    bool no_tool_rows() const {
        return rows_for("rbac.enforcement.read") == 0 && rows_for("mcp.get_rbac_enforcement") == 0;
    }
};

/// The structured success body, after proving the call succeeded and conforms to the SERVED schema.
nlohmann::json success_body(McpRig& rig, const nlohmann::json& body) {
    REQUIRE(body.contains("result"));
    REQUIRE_FALSE(body.contains("error"));
    const auto& sc = body["result"]["structuredContent"];
    REQUIRE(sc.is_object());
    CHECK(yuzu::test::schema_violation(rig.served_tool()["outputSchema"], sc) == "");
    // content[0].text carries the same object.
    CHECK(nlohmann::json::parse(body["result"]["content"][0]["text"].get<std::string>()) == sc);
    return sc;
}

/// No fixed server-authored store string, driver text or SQL name reaches a body.
void check_no_store_text(const nlohmann::json& body) {
    const std::string text = body.dump();
    INFO("body=" << text);
    CHECK(text.find("rbac store not open") == std::string::npos);
    CHECK(text.find("auth.users") == std::string::npos);
    CHECK(text.find("relation \"") == std::string::npos);
    CHECK(text.find("does not exist") == std::string::npos);
    CHECK(text.find("PGRES") == std::string::npos);
    CHECK(text.find("ERROR") == std::string::npos);
}

/// The break-glass rename the hint tests use: the regime check's auth.users JOIN cannot run, while
/// the predicate (principal_roles) still answers.
void make_regime_store_unreadable(RbacRoleHarness& h) {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(lease.get(), "ALTER TABLE auth.users RENAME TO users_enfread_gone",
                             std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

/// A SAML session of the production shape; the predicate admits it (bare principal_roles
/// membership) and only the regime check separates it from an administrator.
void make_saml_caller(RbacRoleHarness& h) {
    h.session_user = saml::saml_principal_id("https://idp.example", "alice");
    h.session_auth_source = "saml";
    REQUIRE_FALSE(is_valid_username(h.session_user));
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(is_rbac_administrator(h.session_with_tier(h.session_mcp_tier), h.auth_db.get(),
                                  h.rbac.get(), RbacAdminSurface::kMcp) == RbacAdminGate::kAdmin);
}

} // namespace

// ── Served metadata ────────────────────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: served metadata is typed, strict and read-only",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    McpRig rig{h, h.rbac.get()};
    const auto tool = rig.served_tool();

    CHECK(tool["inputSchema"] == nlohmann::json::parse(
                                     R"({"type":"object","properties":{},"additionalProperties":false})"));

    const auto& out = tool["outputSchema"];
    REQUIRE(out.is_object());
    std::set<std::string> required;
    for (const auto& k : out["required"])
        required.insert(k.get<std::string>());
    // By NAME, not count: a swapped key must not pass.
    CHECK(required == std::set<std::string>{"enabled", "unconfirmed", "administrator",
                                            "audit_persisted"});
    CHECK(out["additionalProperties"] == false);
    for (const auto& k : required)
        CHECK(out["properties"].contains(k));
    CHECK(out["properties"]["enabled"]["type"] == "boolean");
    CHECK(out["properties"]["unconfirmed"]["type"] == "boolean");
    CHECK(out["properties"]["audit_persisted"]["type"] == "boolean");
    CHECK(out["properties"]["administrator"]["type"] == "string");
    CHECK(out["properties"]["administrator"]["enum"] ==
          nlohmann::json::array({"may", "may_not", "unconfirmed"}));

    CHECK(tool["annotations"]["readOnlyHint"] == true);
    CHECK(tool["annotations"]["destructiveHint"] == false);
    CHECK(tool["annotations"]["idempotentHint"] == true);

    // The decision-grade description names the advisory semantics, the exclusions and the audit.
    const std::string desc = tool["description"].get<std::string>();
    CHECK(desc.find("ADVISORY") != std::string::npos);
    CHECK(desc.find("approval ladder") != std::string::npos);
    CHECK(desc.find("MFA step-up") != std::string::npos);
    CHECK(desc.find("rbac.enforcement.read") != std::string::npos);
    CHECK(desc.find("audit_persisted") != std::string::npos);
    CHECK(desc.find("retry_after_ms") != std::string::npos);
    // The stale pointer to the tracking issue is gone from the sibling get_me text.
    nlohmann::json me;
    for (const auto& t : rig.raw(R"({"jsonrpc":"2.0","method":"tools/list","id":3})")["result"]["tools"])
        if (t["name"] == "get_me")
            me = t;
    REQUIRE(me.is_object());
    CHECK(me["description"].get<std::string>().find("#6033") == std::string::npos);
    CHECK(me["description"].get<std::string>().find("get_rbac_enforcement") != std::string::npos);
}

// ── Bodies ─────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: RBAC off, durable base admin: may, both audit rows written",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    McpRig rig{h, h.rbac.get()};

    const auto sc = success_body(rig, rig.call());
    CHECK(sc["enabled"] == false);
    CHECK(sc["unconfirmed"] == false);
    CHECK(sc["administrator"] == "may");
    CHECK(sc["audit_persisted"] == true);

    // Both rows, each once, on success.
    CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
    CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 1);
    const AuditRecord* domain = nullptr;
    for (const auto& r : rig.audit_log)
        if (r.action == "rbac.enforcement.read")
            domain = &r;
    REQUIRE(domain != nullptr);
    CHECK(domain->target_type == "Setting");
    CHECK(domain->target_id == "rbac_enabled");
    // Server-derived detail, from the builder result alone.
    CHECK(domain->detail == "enabled=false; unconfirmed=false; administrator=may");
    check_no_store_text(rig.call());
}

TEST_CASE("MCP get_rbac_enforcement: RBAC off, caller without durable admin authority: may_not",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    McpRig rig{h, h.rbac.get()};

    const auto sc = success_body(rig, rig.call());
    CHECK(sc["enabled"] == false);
    CHECK(sc["unconfirmed"] == false);
    CHECK(sc["administrator"] == "may_not");
    CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
}

TEST_CASE("MCP get_rbac_enforcement: RBAC on, administrator and non-administrator",
          "[pg][rbac_enforcement_read][mcp]") {
    SECTION("durable Administrator grant with an active account row") {
        RbacRoleHarness h;
        h.make_caller_admin(/*rbac_on=*/true);
        McpRig rig{h, h.rbac.get()};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["enabled"] == true);
        CHECK(sc["unconfirmed"] == false);
        CHECK(sc["administrator"] == "may");
        CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
        const AuditRecord* domain = nullptr;
        for (const auto& r : rig.audit_log)
            if (r.action == "rbac.enforcement.read")
                domain = &r;
        REQUIRE(domain != nullptr);
        CHECK(domain->detail == "enabled=true; unconfirmed=false; administrator=may");
    }
    SECTION("a base admin with NO Administrator grant is may_not (the local role is inert)") {
        RbacRoleHarness h;
        h.rbac->set_rbac_enabled(true);
        REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::admin).has_value());
        McpRig rig{h, h.rbac.get()};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["enabled"] == true);
        CHECK(sc["administrator"] == "may_not");
    }
}

// ── The kMcp surface: no tier rule ─────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: the principal REST reads as may_not for an MCP-tier token "
          "reads may here (kMcp applies no tier rule)",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_mcp_tier = "supervised";
    McpRig rig{h, h.rbac.get()};

    // The same credential on the REST surface is structurally denied (#520).
    const auto rest = read_rbac_enforcement(h.session_with_tier("supervised"), h.auth_db.get(),
                                            h.rbac.get(), RbacAdminSurface::kRest);
    REQUIRE(rest.has_value());
    CHECK(rest->administrator == RbacAdminHint::kMayNot);
    CHECK(yuzu::server::to_string(rest->administrator) == "may_not");

    const auto sc = success_body(rig, rig.call());
    CHECK(sc["administrator"] == "may");
}

TEST_CASE("MCP get_rbac_enforcement: the readonly tier is admitted and a durable admin reads may "
          "although the tool tier check still refuses the mutation",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_mcp_tier = "readonly";
    McpRig rig{h, h.rbac.get()};

    const auto sc = success_body(rig, rig.call());
    CHECK(sc["administrator"] == "may");
    CHECK(sc["audit_persisted"] == true);

    // `may` is advisory: the same credential cannot change enforcement at this tier.
    const auto mutation = rig.call_tool("set_rbac_enforcement", {{"enabled", true}});
    CHECK(mutation.contains("error"));
    CHECK_FALSE(mutation.contains("result"));
    CHECK_FALSE(h.rbac->is_rbac_enabled());
}

TEST_CASE("MCP get_rbac_enforcement: an unknown tier lacks Infrastructure:Read and is refused by "
          "the tier gate, audited as denied",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_mcp_tier = "not-a-real-tier"; // tier_allows denies an unknown tier
    McpRig rig{h, h.rbac.get()};

    const auto body = rig.call();
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kTierDenied);
    CHECK_FALSE(body.contains("result"));
    // The generic gate audits the refusal; the handler never ran, so no success row of either kind.
    CHECK(rig.rows("mcp.get_rbac_enforcement", "denied") == 1);
    CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 0);
    CHECK(rig.rows_for("rbac.enforcement.read") == 0);
}

TEST_CASE("MCP get_rbac_enforcement: a service-scoped token is refused (default denied class) and "
          "audited, with no domain row",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "payments";
    McpRig rig{h, h.rbac.get()};

    const auto body = rig.call();
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kPermissionDenied);
    CHECK_FALSE(body.contains("result"));
    CHECK(rig.rows("mcp.get_rbac_enforcement", "denied") == 1);
    CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 0);
    CHECK(rig.rows_for("rbac.enforcement.read") == 0);
}

TEST_CASE("MCP get_rbac_enforcement: an engine principal reads may_not, a SAML principal with no "
          "account row reads may_not",
          "[pg][rbac_enforcement_read][mcp]") {
    SECTION("engine principal, even with a durable admin account of the same name") {
        RbacRoleHarness h;
        h.make_caller_admin(/*rbac_on=*/false);
        h.session_principal_kind = "engine";
        McpRig rig{h, h.rbac.get()};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["administrator"] == "may_not");
        CHECK(sc["unconfirmed"] == false);
    }
    SECTION("SAML principal: the predicate admits, the regime check refuses") {
        RbacRoleHarness h;
        make_saml_caller(h);
        McpRig rig{h, h.rbac.get()};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["enabled"] == true);
        CHECK(sc["administrator"] == "may_not");
    }
}

// ── unconfirmed and administrator are independent ──────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: unconfirmed:false with administrator:unconfirmed (regime store "
          "unreadable) is legitimate and the body carries no store text",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    McpRig rig{h, h.rbac.get()};

    const auto body = rig.call();
    const auto sc = success_body(rig, body);
    CHECK(sc["enabled"] == true);
    CHECK(sc["unconfirmed"] == false);
    CHECK(sc["administrator"] == "unconfirmed");
    check_no_store_text(body);
    // The unconfirmed verdict is still a successful, audited read.
    CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
    const AuditRecord* domain = nullptr;
    for (const auto& r : rig.audit_log)
        if (r.action == "rbac.enforcement.read")
            domain = &r;
    REQUIRE(domain != nullptr);
    CHECK(domain->detail == "enabled=true; unconfirmed=false; administrator=unconfirmed");
}

TEST_CASE("MCP get_rbac_enforcement: a degraded enforcement view gives unconfirmed:true while "
          "administrator still follows the hint",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);

    // A second replica of the RBAC store on its own one-connection pool, observing the durable
    // enable at construction. Holding its only connection and ageing its refresh readings past the
    // stale-serve bound makes every refresh fail and the cached view degraded: the same technique
    // test_rbac_store.cpp uses for the real degrade path.
    yuzu::server::pg::PgPool pool_b{{.conninfo = h.auth_db.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    REQUIRE(replica_b.is_rbac_enabled());
    auto held = pool_b.acquire();
    REQUIRE(held);
    replica_b.age_refresh_state_for_test(std::chrono::milliseconds(5200));
    REQUIRE(replica_b.rbac_enabled_view_degraded());

    McpRig rig{h, &replica_b};

    SECTION("an engine principal is definitively may_not in every store state") {
        h.session_principal_kind = "engine";
        const auto body = rig.call();
        const auto sc = success_body(rig, body);
        CHECK(sc["enabled"] == true); // a cached on, gone stale: enforcement is in effect either way
        CHECK(sc["unconfirmed"] == true);
        CHECK(sc["administrator"] == "may_not");
        check_no_store_text(body);
    }
    SECTION("a human caller whose grant read cannot run reads unconfirmed, never may_not") {
        const auto body = rig.call();
        const auto sc = success_body(rig, body);
        CHECK(sc["unconfirmed"] == true);
        CHECK(sc["administrator"] == "unconfirmed");
        check_no_store_text(body);
    }
}

// ── Arguments ──────────────────────────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: any supplied argument is refused with invalid params and "
          "writes no audit row",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    McpRig rig{h, h.rbac.get()};

    SECTION("an unknown property") {
        const auto body = rig.call_tool(kTool, {{"principal_id", "someone-else"}});
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
        CHECK_FALSE(body.contains("result"));
    }
    SECTION("a non-object arguments value") {
        const auto body = rig.call_tool(kTool, nlohmann::json::array({1}));
        REQUIRE(body.contains("error"));
        CHECK_FALSE(body.contains("result"));
    }
    CHECK(rig.no_tool_rows());
}

// ── Store unavailable ──────────────────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: an unwired RBAC store is a retryable error with no audit row "
          "and no raw store text",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    McpRig rig{h, /*store=*/nullptr};

    const auto body = rig.call();
    REQUIRE(body.contains("error"));
    CHECK_FALSE(body.contains("result"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(body["error"]["data"]["retry_after_ms"] == yuzu::server::mcp::kMcpStoreFaultRetryMs);
    CHECK(rig.no_tool_rows());
    check_no_store_text(body);
}

TEST_CASE("MCP get_rbac_enforcement: a closed RBAC store is a retryable error with no audit row "
          "and no raw store text",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    // An unroutable substrate: the constructor's failure path leaves the store closed.
    yuzu::server::pg::PgPool bad_pool{
        {.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    RbacStore closed{bad_pool};
    REQUIRE_FALSE(closed.is_open());
    McpRig rig{h, &closed};

    const auto body = rig.call();
    REQUIRE(body.contains("error"));
    CHECK_FALSE(body.contains("result"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(body["error"]["data"]["retry_after_ms"] == yuzu::server::mcp::kMcpStoreFaultRetryMs);
    CHECK(rig.no_tool_rows());
    check_no_store_text(body);
}

// ── Audit ──────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("MCP get_rbac_enforcement: either audit row dropping reports audit_persisted:false and "
          "the data is still returned; both rows are always attempted",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    McpRig rig{h, h.rbac.get()};

    SECTION("the domain row is dropped") {
        rig.drop_actions = {"rbac.enforcement.read"};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["audit_persisted"] == false);
        CHECK(sc["enabled"] == true);
        CHECK(sc["administrator"] == "may");
        // The generic row was still attempted: the two writes are independent.
        CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
        CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 1);
    }
    SECTION("the generic row is dropped") {
        rig.drop_actions = {"mcp.get_rbac_enforcement"};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["audit_persisted"] == false);
        CHECK(sc["administrator"] == "may");
        CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
        CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 1);
    }
    SECTION("both rows are dropped") {
        rig.drop_actions = {"rbac.enforcement.read", "mcp.get_rbac_enforcement"};
        const auto sc = success_body(rig, rig.call());
        CHECK(sc["audit_persisted"] == false);
        CHECK(sc["administrator"] == "may");
        CHECK(rig.rows("rbac.enforcement.read", "success") == 1);
        CHECK(rig.rows("mcp.get_rbac_enforcement", "success") == 1);
    }
}

TEST_CASE("MCP get_rbac_enforcement: audit rows carry nothing the session supplied",
          "[pg][rbac_enforcement_read][mcp]") {
    RbacRoleHarness h;
    // A hostile principal name (CWE-117): newline plus a forged field. It must reach no audit field.
    h.session_user = "evil\nresult=success; forged=1";
    McpRig rig{h, h.rbac.get()};

    const auto sc = success_body(rig, rig.call());
    // Whatever the verdict for a name no account can hold, it is one of the three spellings.
    CHECK((sc["administrator"] == "may" || sc["administrator"] == "may_not" ||
           sc["administrator"] == "unconfirmed"));
    REQUIRE(rig.rows("rbac.enforcement.read", "success") == 1);
    for (const auto& r : rig.audit_log) {
        INFO("action=" << r.action << " detail=" << r.detail << " target_id=" << r.target_id);
        CHECK(r.detail.find("evil") == std::string::npos);
        CHECK(r.detail.find("forged") == std::string::npos);
        CHECK(r.target_id.find("evil") == std::string::npos);
    }
}
