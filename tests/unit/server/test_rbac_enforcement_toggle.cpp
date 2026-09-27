/**
 * test_rbac_enforcement_toggle.cpp — HTTP-level (and MCP-twin) coverage for
 * the A1 RBAC enforcement enable/disable toggle:
 * `PUT /api/v1/rbac/enforcement` + MCP twin `set_rbac_enforcement`.
 *
 * Shares `RbacRoleHarness` (test_rbac_admin_surface_harness.hpp, extracted
 * from test_rbac_role_assignment.cpp in this same PR) with A2's own test
 * file, driving both the REST TestRouteSink and the MCP JSON-RPC handler off
 * the SAME RbacStore/AuthDB/ApprovalManager.
 *
 * Store-level coverage of the caller-survives guard itself (the deterministic
 * FOR UPDATE OF pr lock-ordering scaffolds, the generation-gated publication
 * fix, the idempotent no-op path) lives in test_rbac_store.cpp's
 * "set_rbac_enforcement" cases; these tests prove the SAME guard surfaces
 * correctly through both transports (409/503 shape, audit rows, metrics,
 * the step-up gate, and the strict-boolean body validation).
 *
 * PG-gated: RbacStore, AuthDB, AND ApprovalManager are all born-on-Postgres.
 * Skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken.
 */

#include "mcp_jsonrpc.hpp" // mcp::kInvalidParams
#include "rbac_store.hpp"

#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacStoreOnAuthPool, RbacRoleHarness

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>

using namespace yuzu::server;

// ── REST: happy path ─────────────────────────────────────────────────────────

TEST_CASE("REST PUT /rbac/enforcement: enable applies for a durable admin holding their own "
          "grant (RBAC off -> on)",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    auto res = h.set_enforcement_rest(true);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["enabled"] == true);
    CHECK(body["data"]["previous_enabled"] == false);
    CHECK(body["data"]["changed"] == true);
    CHECK(body["data"]["post_transition_administrators"] == 1);
    CHECK(h.rbac->is_rbac_enabled());

    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action != "rbac.enforcement_changed" || a.result != "success")
            continue;
        found = true;
        CHECK(a.target_id == "rbac_enabled");
        CHECK(a.detail.find("enabled=true") != std::string::npos);
        CHECK(a.detail.find("previous=false") != std::string::npos);
        CHECK(a.detail.find("changed=true") != std::string::npos);
        CHECK(a.detail.find("post_transition_administrators=1") != std::string::npos);
    }
    CHECK(found);
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "rest"}, {"result", "applied"}})
             .value() == 1);
}

TEST_CASE("REST PUT /rbac/enforcement: enable refused 409 when the caller holds no grant",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false); // local admin role only, no principal_roles grant

    auto res = h.set_enforcement_rest(true);
    REQUIRE(res);
    CHECK(res->status == 409);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["error"].contains("remediation"));
    CHECK(body["error"]["remediation"].get<std::string>().find(
              "POST /api/v1/rbac/roles/Administrator/assignments") != std::string::npos);
    CHECK(body["error"]["retry_after_ms"].is_null());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(h.rbac->is_rbac_enabled());

    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.enforcement_changed" && a.result == "denied" &&
            a.detail.find("guard:") != std::string::npos)
            found = true;
    CHECK(found);
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "rest"}, {"result", "refused"}})
             .value() == 1);
}

// Gate 7 Fix 1 sibling: the test above proves the pre-existing DESTINATION
// check (409); this proves the NEW SOURCE-regime check (403) reachable
// through the FULL transport stack, not just the store directly. A caller
// whose ONLY authority is a fleet-wide Administrator grant belonging to a
// DEACTIVATED account is a genuine divergence between the outer
// is_rbac_administrator gate (its RBAC-on branch checks only
// `principal_roles`, no `auth.users.is_active` join at all) and the store's
// new source check (`list_authenticatable_admin_grants`, which DOES join on
// `is_active`) — the outer gate admits this caller, the store's source
// check does not. This is the harness-reachable analogue of
// test_rbac_store.cpp's C1(b) case, exercised end-to-end through REST.
// (A caller with literally no grant at all is denied by the OUTER gate
// first, 403 with no `remediation` field — that is a different, pre-existing
// code path, not this one.)
TEST_CASE("REST PUT /rbac/enforcement: disable refused 403 (source check) when the caller's "
          "fleet-wide grant belongs to a DEACTIVATED account — the outer admin gate admits, the "
          "store's source check does not",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::admin).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.set_enforcement_rest(false);
    REQUIRE(res);
    CHECK(res->status == 403);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["error"].contains("remediation"));
    CHECK(body["error"]["remediation"].get<std::string>().find(
              "POST /api/v1/rbac/roles/Administrator/assignments") != std::string::npos);
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK(h.rbac->is_rbac_enabled()); // unchanged — still on

    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.enforcement_changed" && a.result == "denied" &&
            a.detail.find("guard:") != std::string::npos)
            found = true;
    CHECK(found);
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "rest"}, {"result", "refused"}})
             .value() == 1);
}

TEST_CASE("REST PUT /rbac/enforcement: disable applies for a local role=admin caller; refused "
          "409 for a principal_roles-only Administrator whose local role is 'user'",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    // RBAC on; caller holds a fleet-wide Administrator grant but their LOCAL
    // account role is 'user' — the demoted-everyone scenario.
    h.rbac->set_rbac_enabled(true);
    REQUIRE(
        h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    auto refused = h.set_enforcement_rest(false);
    REQUIRE(refused);
    CHECK(refused->status == 409);
    CHECK(h.rbac->is_rbac_enabled());

    // Promote the caller to local admin — disable now applies.
    REQUIRE(h.auth_db->update_role(h.session_user, auth::Role::admin).has_value());
    auto applied = h.set_enforcement_rest(false);
    REQUIRE(applied);
    CHECK(applied->status == 200);
    auto body = nlohmann::json::parse(applied->body);
    CHECK(body["data"]["changed"] == true);
    CHECK(body["data"]["post_transition_administrators"] == 1);
    CHECK_FALSE(h.rbac->is_rbac_enabled());
}

TEST_CASE("REST PUT /rbac/enforcement: idempotent no-op returns changed=false, audited "
          "success, counter {rest,unchanged}",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.set_enforcement_rest(true)->status == 200);
    REQUIRE(h.rbac->is_rbac_enabled());

    auto res = h.set_enforcement_rest(true);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["changed"] == false);

    bool found_success = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.enforcement_changed" && a.result == "success" &&
            a.detail.find("changed=false") != std::string::npos)
            found_success = true;
    CHECK(found_success);
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "rest"}, {"result", "unchanged"}})
             .value() == 1);
}

// ── REST: durable-admin gate + structural denials ────────────────────────────

TEST_CASE("REST PUT /rbac/enforcement: a non-admin caller is denied 403 (RBAC off, role=user "
          "row; RBAC on, no grant)",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    SECTION("RBAC off") {
        REQUIRE(
            h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
        h.session_user = "plainuser";
        auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    SECTION("RBAC on") {
        h.rbac->set_rbac_enabled(true);
        REQUIRE(h.rbac->assign_role({"user", "vieweronly", "Viewer"}).has_value());
        h.session_user = "vieweronly";
        auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

TEST_CASE("REST PUT /rbac/enforcement: a service-scoped token is denied (no permission field "
          "in the A4 body); an engine session is denied",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    SECTION("service-scoped token") {
        h.session_token_scope_service = "some-service";
        auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        CHECK(res->status == 403);
        auto body = nlohmann::json::parse(res->body);
        CHECK_FALSE(body["error"].contains("permission"));
        CHECK_FALSE(h.rbac->is_rbac_enabled());
    }
    SECTION("engine session") {
        h.session_principal_kind = "engine";
        auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(h.rbac->is_rbac_enabled());
    }
    // Doomgoose external review, PR #4985 round-2, CRITICAL/BLOCKING (#520):
    // `is_rbac_administrator(..., RbacAdminSurface::kRest)` structurally
    // denies any non-empty mcp_tier (MCP needs the opposite answer — see
    // rbac_admin_predicate.hpp's decision 3), and REST's own
    // `deny_mcp_token_session` helper pre-empts the predicate on the same
    // field for accurate audit wording — a bearer token minted with a tier
    // must never reach this route via REST, even for a durable admin, since
    // REST has no tier/approval concept to legitimize it the way MCP's own
    // dispatch guard does. A1's toggle route reuses this same
    // Fable-adjudicated mechanism, never a fork.
    SECTION("mcp-tiered token (REST)") {
        h.rest_session_mcp_tier = "readonly";
        auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(h.rbac->is_rbac_enabled());
    }
}

// ── REST: body validation ────────────────────────────────────────────────────

TEST_CASE("REST PUT /rbac/enforcement: malformed JSON, missing enabled, or a coerced boolean "
          "are all rejected 400, no store write, no success audit row",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    for (const std::string& body :
         {std::string("not json"), std::string("{}"), std::string(R"({"enabled":"true"})"),
          std::string(R"({"enabled":1})")}) {
        auto res = h.put_rest("/api/v1/rbac/enforcement", body);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK_FALSE(h.rbac->is_rbac_enabled());
    for (const auto& a : h.audit_log)
        CHECK_FALSE((a.action == "rbac.enforcement_changed" && a.result == "success"));
}

// ── REST: MFA step-up gate ────────────────────────────────────────────────────

TEST_CASE("REST PUT /rbac/enforcement: a step-up denial blocks the write before the body is "
          "even parsed",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.step_up = [](const httplib::Request&, httplib::Response&, const auth::Session&,
                  const std::string&) { return false; };

    auto res = h.set_enforcement_rest(true);
    REQUIRE(res);
    CHECK(h.step_up_actions.size() == 1);
    CHECK_FALSE(h.rbac->is_rbac_enabled());
    for (const auto& a : h.audit_log)
        CHECK(a.action != "rbac.enforcement_changed");
}

// ── REST: audit fail-closed ──────────────────────────────────────────────────

TEST_CASE("REST PUT /rbac/enforcement: fails CLOSED (503) when its audit write drops, though "
          "the flag DID change",
          "[pg][rest][rbac][a1][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.audit_allow = false;

    auto res = h.set_enforcement_rest(true);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.rbac->is_rbac_enabled()); // the transition committed regardless
}

// ── REST: store/predicate unavailable ────────────────────────────────────────
//
// Neither branch is reachable through RbacRoleHarness's own registration
// (its RbacStore/AuthDB are always open/non-null), so these two cases
// register a second, minimal RestApiV1 directly — same register_routes call
// shape as the harness, with only rbac_store/auth_db swapped.

TEST_CASE("REST PUT /rbac/enforcement: store unavailable 503; predicate kUnavailable (null "
          "auth_db, RBAC off) also 503",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h; // supplies a real, open, RBAC-off RbacStore to reuse below

    auto auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
        yuzu::server::auth::Session s;
        s.username = "someone";
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };

    auto register_minimal = [&](yuzu::server::test::TestRouteSink& sink,
                                yuzu::server::RbacStore* rbac_store_ptr,
                                yuzu::server::AuthDB* auth_db_ptr) {
        static yuzu::server::RestApiV1 api;
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/rbac_store_ptr,
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
                            /*auth_db=*/auth_db_ptr);
    };

    SECTION("rbac_store is null") {
        yuzu::server::test::TestRouteSink sink;
        register_minimal(sink, /*rbac_store_ptr=*/nullptr, /*auth_db_ptr=*/h.auth_db.get());
        auto res = sink.Put("/api/v1/rbac/enforcement", R"({"enabled":true})");
        REQUIRE(res);
        CHECK(res->status == 503);
    }

    SECTION("auth_db is null, RBAC off -- predicate cannot confirm, kUnavailable") {
        REQUIRE_FALSE(h.rbac->is_rbac_enabled()); // fresh RbacRoleHarness defaults RBAC off
        yuzu::server::test::TestRouteSink sink;
        register_minimal(sink, /*rbac_store_ptr=*/h.rbac.get(), /*auth_db_ptr=*/nullptr);
        auto res = sink.Put("/api/v1/rbac/enforcement", R"({"enabled":true})");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

// ── MCP twin ──────────────────────────────────────────────────────────────────

TEST_CASE("MCP set_rbac_enforcement: happy-path enable; structuredContent has the four "
          "required output fields",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    auto res = h.mcp_call_tool_approved("set_rbac_enforcement", {{"enabled", true}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") == std::string::npos);
    auto body = nlohmann::json::parse(res->body);
    auto sc = body["result"]["structuredContent"];
    CHECK(sc.contains("enabled"));
    CHECK(sc.contains("previous_enabled"));
    CHECK(sc.contains("changed"));
    CHECK(sc.contains("post_transition_administrators"));
    CHECK(h.rbac->is_rbac_enabled());
}

TEST_CASE("MCP set_rbac_enforcement: refusal is JSON-RPC kInvalidParams carrying the guard "
          "message; counter {mcp,refused}; audit denied",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false); // local admin role only, no grant

    auto res = h.mcp_call_tool_approved("set_rbac_enforcement", {{"enabled", true}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInvalidParams);
    CHECK(body["error"]["message"].get<std::string>().find("Administrator") !=
          std::string::npos);
    CHECK_FALSE(h.rbac->is_rbac_enabled());
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "mcp"}, {"result", "refused"}})
             .value() == 1);
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.enforcement_changed" && a.result == "denied" &&
            a.detail.find("guard:") != std::string::npos)
            found = true;
    CHECK(found);
}

// Gate 7 Fix 1 sibling: the test above proves the pre-existing DESTINATION
// check (kInvalidParams); this proves the NEW SOURCE-regime check
// (kPermissionDenied, A4-shaped with a remediation hint per Fix 5) reachable
// through the FULL MCP stack. Same divergence as the REST sibling: a fleet-
// wide grant belonging to a DEACTIVATED account is admitted by the outer
// is_rbac_administrator gate (no `is_active` join) but refused by the
// store's new source check (`list_authenticatable_admin_grants`, which DOES
// join on `is_active`).
TEST_CASE("MCP set_rbac_enforcement: disable refused kPermissionDenied (source check) when the "
          "caller's fleet-wide grant belongs to a DEACTIVATED account",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::admin).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.mcp_call_tool_approved("set_rbac_enforcement", {{"enabled", false}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kPermissionDenied);
    CHECK(body["error"]["message"].get<std::string>().find("Administrator") !=
          std::string::npos);
    REQUIRE(body["error"].contains("data"));
    CHECK(body["error"]["data"].contains("correlation_id"));
    REQUIRE(body["error"]["data"].contains("remediation"));
    CHECK(body["error"]["data"]["remediation"].get<std::string>().find(
              "POST /api/v1/rbac/roles/Administrator/assignments") != std::string::npos);
    CHECK(h.rbac->is_rbac_enabled()); // unchanged — still on
    CHECK(h.metrics
             .counter("yuzu_server_rbac_enforcement_toggle_total",
                      {{"transport", "mcp"}, {"result", "refused"}})
             .value() == 1);
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.enforcement_changed" && a.result == "denied" &&
            a.detail.find("guard:") != std::string::npos)
            found = true;
    CHECK(found);
}

TEST_CASE("MCP set_rbac_enforcement: a non-admin caller is denied; an empty mcp_tier caller "
          "is denied outright with the MCP-tier-bearer-token message",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    SECTION("non-admin") {
        REQUIRE(
            h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
        h.session_user = "plainuser";
        auto res = h.mcp_call_tool_approved("set_rbac_enforcement", {{"enabled", true}});
        REQUIRE(res);
        CHECK(res->body.find("\"error\"") != std::string::npos);
        CHECK_FALSE(h.rbac->is_rbac_enabled());
    }
    SECTION("empty mcp_tier") {
        h.make_caller_admin(/*rbac_on=*/false);
        REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
        h.session_mcp_tier = "";
        auto res = h.mcp_call_tool("set_rbac_enforcement", {{"enabled", true}});
        REQUIRE(res);
        CHECK(res->body.find("\"error\"") != std::string::npos);
        CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
        CHECK_FALSE(h.rbac->is_rbac_enabled());
        bool found = false;
        for (const auto& a : h.audit_log)
            if (a.action == "rbac.enforcement_changed" && a.result == "denied" &&
                a.detail.find("empty mcp_tier") != std::string::npos)
                found = true;
        CHECK(found);
    }
}

TEST_CASE("MCP set_rbac_enforcement: {\"enabled\":\"true\"} is rejected by the #2405 "
          "input-schema chokepoint before the handler, no ticket minted, no audit row",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    auto res = h.mcp_call_tool("set_rbac_enforcement", {{"enabled", "true"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("do not match the tool input schema") != std::string::npos);
    CHECK(h.appr->pending_count() == 0); // no ticket minted
    CHECK_FALSE(h.rbac->is_rbac_enabled());
    for (const auto& a : h.audit_log)
        CHECK(a.action != "rbac.enforcement_changed");
}

TEST_CASE("MCP set_rbac_enforcement: fails CLOSED on a dropped audit (audit_persisted=false, "
          "503 shape, flag DID change)",
          "[pg][mcp][rbac][a1][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    const std::string approval_id =
        h.mcp_mint_and_approve("set_rbac_enforcement", {{"enabled", true}});
    h.audit_allow = false;
    nlohmann::json recall_args = {{"enabled", true}, {"approval_id", approval_id}};
    auto res = h.mcp_call_tool("set_rbac_enforcement", recall_args);
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 503);
    CHECK(body["error"]["data"]["audit_persisted"] == false);
    CHECK(h.rbac->is_rbac_enabled()); // the transition committed regardless
}

TEST_CASE("MCP set_rbac_enforcement: advertised in tools/list with destructiveHint=true, "
          "idempotentHint=true, readOnlyHint=false, openWorldHint=false",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    bool found = false;
    for (const auto& t : body["result"]["tools"]) {
        if (t["name"] != "set_rbac_enforcement")
            continue;
        found = true;
        CHECK(t["annotations"]["destructiveHint"] == true);
        CHECK(t["annotations"]["idempotentHint"] == true);
        CHECK(t["annotations"]["readOnlyHint"] == false);
        CHECK(t["annotations"]["openWorldHint"] == false);
    }
    CHECK(found);
}
