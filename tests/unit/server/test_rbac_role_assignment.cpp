/**
 * test_rbac_role_assignment.cpp — HTTP-level (and MCP-twin) coverage for the
 * A2 global human role assignment surface (`.claude/plans/rbac-industry-
 * leading-DELIVERY-PLAN.md` §2): `POST/DELETE
 * /api/v1/rbac/roles/{name}/assignments[/{principal_id}]` + MCP twins
 * `assign_rbac_role`/`unassign_rbac_role`.
 *
 * Pattern: register both `RestApiV1::register_routes(HttpRouteSink&, ...)`
 * (TestRouteSink, mirrors test_rest_engine_principal_roles.cpp) AND
 * `McpServer::build_handler(...)` (mirrors test_mcp_engine_principal_roles.cpp)
 * against the SAME underlying RbacStore/AuthDB from one harness. UNLIKE
 * McpEngineRolesHarness's "not an MCP token" convention (empty `mcp_tier`,
 * which makes `tier_allows()`/`requires_approval()` both no-op): both MCP
 * tools here carry the empty-`mcp_tier` deny-outright guard (#4309,
 * adversarial-review PR1/A2 round-2), so the harness's DEFAULT MCP-transport
 * session tier (`session_mcp_tier`) is `"supervised"` (matching what the tool
 * descriptions claim) and a real PG-backed `ApprovalManager` IS wired in.
 * Every MCP call that is meant to reach the tool handler goes through the
 * full ticket-then-recall dance (`RbacRoleHarness::mcp_call_tool_approved`/
 * `mcp_mint_and_approve` — mint, approve as "reviewer-bob", recall with
 * `approval_id`), mirroring `test_mcp_server.cpp`'s `SchemaGateHarness`
 * pattern; the two dedicated empty-tier tests explicitly reset
 * `session_mcp_tier` to `""` to exercise the new guard directly, bypassing
 * C8's ticket flow entirely (an empty tier is still a no-op for
 * `tier_allows()`/`requires_approval()` — that has not changed, only the NEW
 * per-handler guard has been added on top).
 *
 * REST sessions carry their OWN, SEPARATE `rest_session_mcp_tier` member
 * (default `""`) — #520/Doomgoose external review, PR #4985 round-2,
 * CRITICAL/BLOCKING: before this fix, REST and MCP sessions shared ONE
 * `session_mcp_tier` field (default `"supervised"`), so every REST
 * happy-path test in this file was unknowingly exercising an MCP-tiered
 * session against the REST route — exactly the credential-confusion gap
 * `is_rbac_administrator(..., RbacAdminSurface::kRest)` now structurally
 * denies. `is_rbac_administrator(..., RbacAdminSurface::kRest)` DOES read
 * `session.mcp_tier` now (unlike before this fix) — REST's own
 * `deny_mcp_token_session` helper pre-empts the predicate on the same field
 * for the identical reason, so a REST test wanting the MCP-token-on-REST
 * denial path sets `rest_session_mcp_tier` directly (see the two new
 * "REST: MCP-tier-token denial" tests below).
 *
 * Covers: the is_rbac_administrator gate on both transports (RBAC-off
 * durable-AuthDB-reread AND RBAC-on principal_roles-reread), the
 * ITServiceOwner/non-"user"/unknown-role rejections (M1 uniform message;
 * on MCP, an out-of-enum `role` is now actually caught by the tool's own
 * input schema before the handler's M1 logic runs at all — see that test's
 * own comment), the self-target and last-Administrator guards, service-scope
 * structural denial, the REST-surface MCP-tier-token structural denial, the
 * empty-`mcp_tier` deny-outright guard (MCP surface only), and
 * audit-fail-closed on both mutations.
 *
 * PG-gated: RbacStore, AuthDB, AND ApprovalManager are all born-on-Postgres
 * (ADR-0006/ADR-0065). Skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when set but broken.
 */

#include "mcp_server_testonly.hpp" // input_schemas_for_test — SHOULD #3's schema<->header sync test
#include "mfa_step_up.hpp"          // StepUpFn, the step-up seam the REST routes call
#include "pg/pg_raii.hpp"           // PgConn/PgResult — the list-route query-failure test
#include "rbac_admin_predicate.hpp" // kRbacAdminGateUnavailableAuditReason
#include "rbac_assignable_roles.hpp"
#include "web_utils.hpp" // audit_token — C5's expected-neutralization oracle

#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacStoreOnAuthPool, RbacRoleHarness (A1 Step 6.1 extraction)

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;

// ── REST: happy path ────────────────────────────────────────────────────────

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: RBAC-off durable admin "
          "grants Operator to a user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"assigned\":true") != std::string::npos);
    // Doomgoose external review, PR #4985 (IMPORTANT #3): "jane" has no
    // auth.users row at all — the "false" leg of the target_provisioned
    // three-state field.
    CHECK(res->body.find(R"("target_provisioned":"false")") != std::string::npos);

    auto roles = h.rbac->get_principal_roles("user", "jane");
    REQUIRE(roles.size() == 1);
    CHECK(roles[0].role_name == "Operator");

    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.assigned" && a.result == "success")
            found = true;
    CHECK(found);
}

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: RBAC-on durable admin "
          "grants Viewer to a user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    auto res = h.assign_rest("Viewer",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

// MINOR (Doomgoose external review, PR #4985): the enum-sync test
// (kRbacAssignableRoles matches the MCP schema's role enum) covers the
// ALLOW-LIST itself, but only 3 of the 6 names were ever exercised via a
// REAL assign call anywhere in this file (Administrator/Operator/Viewer) —
// PlatformEngineer/ApiTokenManager/Reviewer never went through the actual
// route. Small, direct coverage for the remaining 3.
TEST_CASE("REST POST .../rbac/roles/{name}/assignments: the remaining 3 "
          "allow-listed roles (PlatformEngineer/ApiTokenManager/Reviewer) "
          "assign successfully too",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    for (const std::string role : {"PlatformEngineer", "ApiTokenManager", "Reviewer"}) {
        const std::string principal = "user-" + role;
        auto res = h.assign_rest(
            role, R"({"principal_type":"user","principal_id":")" + principal + R"("})");
        REQUIRE(res);
        CHECK(res->status == 201);
        auto roles = h.rbac->get_principal_roles("user", principal);
        REQUIRE(roles.size() == 1);
        CHECK(roles[0].role_name == role);
    }
}

// Doomgoose external review, PR #4985 (IMPORTANT #3): the target_provisioned
// three-state field ("true"/"false"/"unknown") had zero test coverage
// despite docs/test-coverage.md claiming otherwise. Three cases below cover
// all three states through the real REST assign route.

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: target_provisioned is "
          "\"true\" for an existing ACTIVE auth.users row",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true); // RBAC-on: the admin gate never touches auth.users
    REQUIRE(h.auth_db->upsert_user("jane", "hash", "salt", auth::Role::user).has_value());

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find(R"("target_provisioned":"true")") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("REST POST .../rbac/roles/{name}/assignments: target_provisioned is "
          "\"unknown\" when the AuthDB read genuinely degrades (never "
          "conflated with \"false\")",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true); // RBAC-on: the admin gate never touches auth.users

    // Break ONLY get_user()'s own SELECT column list (mirrors
    // test_auth_db_pg.cpp's break_load_mfa_row_only fault-injection idiom —
    // DROP a column that ONE specific statement selects, leaving every
    // other query against the same table, including the RBAC-on admin gate
    // and assign_role's own write, completely unaffected). Each TEST_CASE
    // gets its own cloned database, so the DDL is contained.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult alter{
            PQexec(conn.get(), "ALTER TABLE auth.users DROP COLUMN identity_source")};
        REQUIRE(alter.ok());
    }

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    // The degraded read must never block the assignment itself (A2
    // explicitly permits pre-provisioning even when the read to CONFIRM
    // provisioning state fails) — only the reported state is affected.
    CHECK(res->status == 201);
    CHECK(res->body.find(R"("target_provisioned":"unknown")") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("REST DELETE .../rbac/roles/{name}/assignments/{id}: removes a "
          "non-Administrator grant",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);

    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: rejections ────────────────────────────────────────────────────────

TEST_CASE("REST assign: ITServiceOwner is rejected 400, never assigned",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("ITServiceOwner",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: a malformed JSON body is rejected 400 (governance "
          "SHOULD #13)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator", "not json");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST assign: a JSON body missing principal_id is rejected 400 "
          "(governance SHOULD #13)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator", R"({"principal_type":"user"})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST assign: an empty JSON body ({}) is rejected 400, missing "
          "principal_id (governance SHOULD #13)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator", "{}");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ── REST: wrong-typed body fields (Doomgoose external review, PR #4985
// IMPORTANT finding #4) — body.value(key, default) THREW nlohmann's
// type_error.302/.306 on a present-but-wrong-typed field or a non-object
// top-level body, producing an uncaught exception instead of the documented
// 400 and skipping this route's denial audit entirely. Fixed via the
// established, non-throwing access_review_str_field extractor
// (#4623/#2146 A2-R1) plus an explicit body.is_object() guard. ─────────────

TEST_CASE("REST assign: a non-object top-level body (array/scalar) is "
          "rejected 400, never an uncaught exception (PR #4985 finding #4)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    for (const std::string bad_body : {"[1,2,3]", "42", "\"just a string\"", "true"}) {
        auto res = h.assign_rest("Operator", bad_body);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: a wrong-typed principal_type (number/bool/object/"
          "array) is rejected 400 with an audited denial, never an uncaught "
          "exception (PR #4985 finding #4)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    for (nlohmann::json bad_type : {nlohmann::json(123), nlohmann::json(true),
                                    nlohmann::json::object(), nlohmann::json::array()}) {
        h.audit_log.clear();
        nlohmann::json body = {{"principal_type", bad_type}, {"principal_id", "jane"}};
        auto res = h.assign_rest("Operator", body.dump());
        REQUIRE(res);
        CHECK(res->status == 400);
        // access_review_str_field degrades the wrong-typed value to "" (the
        // default), which then fails the EXISTING, already-audited
        // `principal_type != "user"` check — never a client crash, never a
        // silently-skipped audit.
        bool found = false;
        for (const auto& a : h.audit_log) {
            if (a.action == "rbac.role.assigned" && a.result == "denied")
                found = true;
        }
        CHECK(found);
    }
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: a wrong-typed principal_id (number/bool/object/"
          "array) is rejected 400, never an uncaught exception (PR #4985 "
          "finding #4)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    // access_review_str_field degrades the wrong-typed value to "" (the
    // default), which then fails the EXISTING `principal_id.empty()` check
    // — the SAME 400 a genuinely-missing principal_id gets (see "a JSON
    // body missing principal_id is rejected 400" above), which is
    // deliberately left UNAUDITED, matching the pre-existing unaudited
    // "invalid JSON" 400 branch a few lines above it (both are
    // pre-validation rejections). This is NOT a CWE-117 necessity —
    // `audit_token()`/`log_token()` are order-independent and safe to call
    // on any string at any point, including empty, so this branch COULD be
    // audited if a future change wants it to be (Gate 8 re-review, PR
    // #4985 pass 13: an earlier version of this comment incorrectly
    // claimed the ordering was forced by CWE-117 safety). This test's
    // point is "no uncaught exception, no 500" — not that this specific
    // branch is, or must stay, unaudited.
    for (nlohmann::json bad_id : {nlohmann::json(123), nlohmann::json(false),
                                  nlohmann::json::object(), nlohmann::json::array()}) {
        nlohmann::json body = {{"principal_type", "user"}, {"principal_id", bad_id}};
        auto res = h.assign_rest("Operator", body.dump());
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: unknown role rejected 400 with the SAME message as "
          "ITServiceOwner (M1 uniform reject)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto its = h.assign_rest("ITServiceOwner",
                             R"({"principal_type":"user","principal_id":"jane"})");
    auto unk = h.assign_rest("NoSuchRole",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(its);
    REQUIRE(unk);
    CHECK(its->status == 400);
    CHECK(unk->status == 400);
    // Both land on the SAME uniform client-facing phrase (M1 — no role-
    // catalog oracle): the specific reason (ITServiceOwner-vs-unknown) is
    // never distinguishable from the response body, only from the audit log.
    const bool its_uniform = its->body.find("cannot be assigned") != std::string::npos;
    const bool unk_uniform = unk->body.find("cannot be assigned") != std::string::npos;
    CHECK(its_uniform);
    CHECK(unk_uniform);
}

TEST_CASE("REST assign: non-\"user\" principal_type rejected 400",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"group","principal_id":"engineers"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rbac->get_principal_roles("group", "engineers").empty());
}

// ── REST: C5 — audit-log-injection neutralization (governance BLOCKING #2,
// CWE-117, full-pipeline review on 765bc7ec1). A CRLF/ANSI-escape payload in
// a JSON-body field must never reach the audit trail raw — every site is
// wrapped in audit_token()/log_token() (web_utils.hpp). Both cases here are
// DENIED rows: principal_id fails is_valid_username's charset check before
// ever reaching the store, and principal_type is free-text (only equality-
// checked, never charset-validated) so the injection surfaces in the
// principal_type-rejection detail instead. ─────────────────────────────────

TEST_CASE("REST assign C5: a CRLF/ANSI-escape principal_id is rejected and "
          "its audit target_id is neutralized, never embedded raw",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    const std::string evil_id = "carol\r\nrbac.role.assigned result=success\x1B[31mFAKE\x1B[0m";
    nlohmann::json body = {{"principal_type", "user"}, {"principal_id", evil_id}};
    auto res = h.assign_rest("Operator", body.dump());
    REQUIRE(res);
    CHECK(res->status == 400);

    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action != "rbac.role.assigned" || a.result != "denied")
            continue;
        found = true;
        CHECK(a.target_id == yuzu::server::audit_token(evil_id));
        CHECK(a.target_id.find('\r') == std::string::npos);
        CHECK(a.target_id.find('\n') == std::string::npos);
        CHECK(a.target_id.find('\x1B') == std::string::npos);
    }
    CHECK(found);
}

TEST_CASE("REST assign C5: a CRLF/ANSI-escape principal_type is rejected and "
          "the audit detail's embedded copy is neutralized, never raw",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    const std::string evil_type = "user\r\nrbac.role.assigned result=success\x1B[31mFAKE\x1B[0m";
    nlohmann::json body = {{"principal_type", evil_type}, {"principal_id", "jane"}};
    auto res = h.assign_rest("Operator", body.dump());
    REQUIRE(res);
    CHECK(res->status == 400);

    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action != "rbac.role.assigned" || a.result != "denied")
            continue;
        if (a.detail.find("not supported") == std::string::npos)
            continue; // the principal_type-rejection row specifically
        found = true;
        CHECK(a.detail.find(yuzu::server::audit_token(evil_type)) != std::string::npos);
        CHECK(a.detail.find('\r') == std::string::npos);
        CHECK(a.detail.find('\n') == std::string::npos);
        CHECK(a.detail.find('\x1B') == std::string::npos);
    }
    CHECK(found);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: durable-admin gate (not perm_fn) ──────────────────────────────────

TEST_CASE("REST assign: a non-admin caller is denied 403 (RBAC off, no durable "
          "admin row)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST assign: a non-admin caller is denied 403 (RBAC on, no "
          "principal_roles Administrator row)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "vieweronly", "Viewer"}).has_value());
    h.session_user = "vieweronly";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST assign: a service-scoped token is denied even for a durable "
          "admin user",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "some-service";

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: MCP-tier-token denial (#520/Doomgoose external review, PR #4985 ──
// ── round-2, CRITICAL/BLOCKING) ──────────────────────────────────────────────

TEST_CASE("REST assign: an MCP-tier bearer token of any tier is denied 403, "
          "even a durable admin — nothing assigned, audit names the reason",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    for (const std::string& tier : {"readonly", "supervised"}) {
        h.rest_session_mcp_tier = tier;
        INFO("mcp_tier = " << tier);
        auto res = h.assign_rest(
            "Operator", R"({"principal_type":"user","principal_id":"jane-)" + tier + R"("})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.rbac->get_principal_roles("user", "jane-" + tier).empty());

        // `mcp_tier='<tier>'` (not just "MCP token") so iteration 2 cannot be
        // silently satisfied by iteration 1's accumulated audit row — each
        // iteration proves its OWN denial fired for its OWN tier.
        bool found = false;
        for (const auto& a : h.audit_log)
            if (a.action == "rbac.role.assigned" && a.result == "denied" &&
                a.detail.find("mcp_tier='" + tier + "'") != std::string::npos)
                found = true;
        CHECK(found);
    }
}

TEST_CASE("REST unassign: an MCP-tier bearer token of any tier is denied 403, "
          "even a durable admin — the pre-seeded grant is NOT removed, audit "
          "names the reason",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    // Pre-seed via the store directly (never through the REST route under
    // test) so "the grant was not removed" is provable rather than assumed.
    REQUIRE(h.rbac->assign_role({"user", "jane", "Operator"}).has_value());

    for (const std::string& tier : {"readonly", "supervised"}) {
        h.rest_session_mcp_tier = tier;
        INFO("mcp_tier = " << tier);
        auto res = h.unassign_rest("Operator", "jane");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);

        // See the assign test's identical comment above.
        bool found = false;
        for (const auto& a : h.audit_log)
            if (a.action == "rbac.role.unassigned" && a.result == "denied" &&
                a.detail.find("mcp_tier='" + tier + "'") != std::string::npos)
                found = true;
        CHECK(found);
    }
}

// Gate 8 HIGH (security-guardian): assign_role/unassign_role share
// set_rbac_enforcement's exact cross-replica cache-staleness root cause —
// is_rbac_administrator's branch selection is driven by a replica-local
// cached rbac_enabled_ view that can lag a real commit, and (unlike the
// toggle's transient window) a grant minted through a stale-regime read
// persists indefinitely. Fixed via RbacStore::check_caller_authorized_
// under_current_regime, called at the REST/MCP handler level right after
// is_rbac_administrator and before assign_role/unassign_role.
//
// A "local admin, no RBAC grant, while RBAC is durably on" caller (the
// scenario one might reach for first) is actually denied by the PRE-
// EXISTING outer is_rbac_administrator gate already — its RBAC-on branch
// requires a principal_roles Administrator row before ever reaching this
// NEW check, so that shape doesn't exercise it. The only way for a caller
// to pass the outer gate on the ON regime is to already hold that row —
// the divergence this NEW check closes is the SAME one Fix 1's REST tests
// use: a real principal_roles Administrator grant belonging to a
// DEACTIVATED account. is_rbac_administrator's ON branch checks bare
// principal_roles membership (no auth.users join) and admits; this NEW
// check reads list_authenticatable_admin_grants fresh (which DOES join on
// auth.users.is_active) and refuses.
TEST_CASE("REST assign: refused 403 (fresh regime check) when the caller's fleet-wide grant "
          "belongs to a DEACTIVATED account — the outer admin gate admits, the fresh check "
          "does not",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.assign_rest("Viewer", R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("REST unassign: refused 403 (fresh regime check) when the caller's fleet-wide grant "
          "belongs to a DEACTIVATED account",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "jane", "Viewer"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.unassign_rest("Viewer", "jane");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1); // unchanged
}

// ── REST: self-target + last-Administrator guards ───────────────────────────

TEST_CASE("REST unassign: a caller may not remove their own Administrator "
          "assignment",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "admin", "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "otheradmin", "Administrator"}).has_value());

    auto res = h.unassign_rest("Administrator", "admin"); // session_user == "admin"
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac->get_principal_roles("user", "admin").size() == 1);
}

TEST_CASE("REST unassign: removing the fleet's last remaining Administrator "
          "grant is refused 409",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    // "soleadmin" MUST have a genuine, active auth.users row — a bare
    // principal_roles grant with no matching active account is a GHOST
    // admin, never counted as a survivor in the first place (Doomgoose
    // external review, PR #4985 IMPORTANT #1), so removing ONLY a ghost
    // grant would no longer be refused. This test is about a REAL last
    // administrator.
    REQUIRE(h.auth_db->upsert_user("soleadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "soleadmin", "Administrator"}).has_value());

    auto res = h.unassign_rest("Administrator", "soleadmin");
    REQUIRE(res);
    CHECK(res->status == 409);
    // The refusal keeps its business-rule message; only store faults return the
    // constant client message.
    CHECK(res->body.find("zero administrators") != std::string::npos);
    CHECK(res->body.find("role unassignment store fault") == std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "soleadmin").size() == 1);
    // Governance follow-up (item 3): the metric fires exactly once, under
    // the "rest" transport label.
    CHECK(h.metrics.counter("yuzu_server_rbac_last_admin_guard_refused_total",
                            {{"transport", "rest"}})
             .value() == 1);
    CHECK(h.metrics.counter("yuzu_server_rbac_last_admin_guard_refused_total",
                            {{"transport", "mcp"}})
             .value() == 0);
}

// ── REST: C1 — last-admin guard counts AUTHENTICATABLE admins, not bare
// principal_roles rows (governance BLOCKING #1, full-pipeline review on
// 765bc7ec1). Store-level coverage of the guard itself lives in
// test_rbac_store.cpp's "RbacStore C1(a/b/c)" cases; these three prove the
// SAME refusal surfaces correctly through the REST transport (409, not a
// raw 503/500 from an unqualified guard).  ───────────────────────────────

TEST_CASE("REST unassign C1(a): removing the fleet's real Administrator is "
          "refused when the only OTHER Administrator row names a NONEXISTENT "
          "username",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    // "ghostadmin" holds an Administrator grant but NO auth.users row at
    // all — exactly the pre-fix false "surviving admin".
    REQUIRE(h.rbac->assign_role({"user", "ghostadmin", "Administrator"}).has_value());

    auto res = h.unassign_rest("Administrator", "realadmin");
    REQUIRE(res);
    CHECK(res->status == 409);
    // Negative control: the row a naive unjoined count would have counted
    // as "one other admin remaining" is still there, unaffected by the
    // refusal — proving the refusal came from the JOIN excluding it, not
    // from it having been removed by some other path.
    CHECK(h.rbac->get_principal_roles("user", "ghostadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

TEST_CASE("REST unassign C1(b): removing the fleet's real Administrator is "
          "refused when the only OTHER Administrator row names a "
          "DEACTIVATED account",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->upsert_user("deactivatedadmin", "hash", "salt", auth::Role::user)
               .has_value());
    REQUIRE(h.rbac->assign_role({"user", "deactivatedadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user("deactivatedadmin").has_value());

    auto res = h.unassign_rest("Administrator", "realadmin");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(h.rbac->get_principal_roles("user", "deactivatedadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

TEST_CASE("REST unassign C1(c): removing the fleet's real Administrator is "
          "refused when the only OTHER Administrator row names a DELETED "
          "account",
          "[pg][rest][rbac][a2]") {
    // This codebase has no hard-delete/cascade path for a user account
    // (AuthDB::remove_user is a soft delete — `is_active = FALSE`), so
    // "deleted" and C1(b)'s "deactivated" are mechanically the identical
    // case here; kept as its own test because the finding named it as a
    // separate sub-case and a future hard-delete path must not silently
    // stop being covered by SOME test named after it.
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->upsert_user("deletedadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "deletedadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user("deletedadmin").has_value());

    auto res = h.unassign_rest("Administrator", "realadmin");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(h.rbac->get_principal_roles("user", "deletedadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

// ── REST/MCP: the admin gate's own kUnavailable outcome (Doomgoose external
// review, PR #4985 IMPORTANT finding #2) — a genuinely degraded-but-open
// RBAC store reaching is_rbac_administrator's RBAC-on branch (as opposed to
// a null/closed store, already covered elsewhere) must log AND audit the
// denial. Closes a2-p7-doomgoose-11's own gap ("is_rbac_administrator's
// kUnavailable outcome was exercised only via null-pointer inputs"). ───────

TEST_CASE("REST assign: the admin gate's own kUnavailable outcome (RBAC-on and "
          "genuinely degraded store) is 503 with an audited denial (PR "
          "#4985 finding #2)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    // RBAC-on: the gate re-reads principal_roles for durable Administrator
    // authority, unlike the RBAC-off branch (a durable AuthDB re-read),
    // which the DROP below would not affect.
    h.make_caller_admin(/*rbac_on=*/true);

    // DROP TABLE on a second connection — rbac_enforcement_label() reads
    // ONLY rbac_meta (untouched), so enforcement still reads as ON; but
    // get_principal_roles_checked's own query against principal_roles now
    // fails, which the gate maps to kUnavailable rather than kDenied.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacAdminGateUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

TEST_CASE("MCP assign_rbac_role: the admin gate's own kUnavailable outcome "
          "(RBAC-on and genuinely degraded store) is kInternalError with an "
          "audited denial (PR #4985 finding #2)",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    // Full ticket-then-recall, matching every other admin-gate test in this
    // file: the mint/approve dance itself has no notion of admin status —
    // only the RECALL reaches is_rbac_administrator (see "MCP
    // assign_rbac_role: a non-admin caller is denied" above for the same
    // reasoning).
    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacAdminGateUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

// ── REST/MCP: the Gate 8 HIGH regime check's OWN kUnavailable outcome
// (governance re-verification, post A1/A2 rebase) — the SECOND, independent
// degradable check on these routes (RbacAdminAuthorityOwner::regime_authority,
// via RbacStore::check_caller_authorized_under_current_regime) never had this
// same audit+log treatment carried over when it was added during the rebase —
// the exact invisible-to-operators shape the two tests above already close
// for the FIRST check (is_rbac_administrator). Distinguished from those tests
// by degrading ONLY `auth.users` (never `rbac_store.principal_roles`):
// is_rbac_administrator's own RBAC-on branch reads bare `principal_roles`
// (no join) and still succeeds, admitting the caller — regime_authority's
// `list_authenticatable_admin_grants` JOINs `auth.users`, so ONLY its read
// fails, isolating the SECOND check's own degradation from the first. ───────

TEST_CASE("REST assign: the Gate 8 HIGH regime check's own kUnavailable "
          "outcome (RBAC-on, is_rbac_administrator passes but the fresh "
          "regime read degrades) is 503 with an audited denial",
          "[pg][rest][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    // DROP auth.users only — is_rbac_administrator's RBAC-on branch never
    // touches it (bare principal_roles read) and still admits the caller;
    // regime_authority's list_authenticatable_admin_grants JOINs auth.users,
    // so its read — and only its read — now fails.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{PQexec(conn.get(), "DROP TABLE auth.users CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacRegimeAuthorityUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

TEST_CASE("MCP assign_rbac_role: the Gate 8 HIGH regime check's own "
          "kUnavailable outcome (RBAC-on, is_rbac_administrator passes but "
          "the fresh regime read degrades) is kInternalError with an "
          "audited denial",
          "[pg][mcp][rbac][a1]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{PQexec(conn.get(), "DROP TABLE auth.users CASCADE")};
        REQUIRE(d.ok());
    }

    // Full ticket-then-recall, matching the sibling kUnavailable test above:
    // the mint/approve dance itself has no notion of admin status — only the
    // RECALL reaches is_rbac_administrator/regime_authority.
    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacRegimeAuthorityUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

// ── REST: the MFA step-up gate (Doomgoose external review, PR #4985 round 3):
// the OpenAPI 401 text says "MFA step-up required (stale/absent proof)". The harness
// used to pass no step-up gate at all, so that claim had no test. These prove the
// ROUTE contract only: when the gate returns false (it has already written its own
// response) the route stops before mutating, and it consulted the gate with the right
// label. The stub's 401 body carries no `meta`, so nothing here can regress
// meta.challenge_url; the real gate's 401/challenge_url, stale-proof, OIDC and SAML
// behaviour is tested in test_mfa_step_up.cpp.
TEST_CASE("REST assign: a failing MFA step-up gate stops the route with its "
          "own 401 before any mutation",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.step_up = [](const httplib::Request&, httplib::Response& res, const auth::Session&,
                   const std::string&) {
        res.status = 401;
        res.set_content(R"({"error":{"code":401,"message":"step-up required"}})",
                        "application/json");
        return false;
    };

    auto res = h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
    REQUIRE(h.step_up_actions.size() == 1);
    CHECK(h.step_up_actions[0] == "POST /api/v1/rbac/roles/{name}/assignments");
    for (const auto& a : h.audit_log)
        CHECK_FALSE((a.action == "rbac.role.assigned" && a.result == "success"));
}

TEST_CASE("REST unassign: a failing MFA step-up gate stops the route with its "
          "own 401 before any mutation",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
                ->status == 201);
    REQUIRE(h.rbac->get_principal_roles("user", "jane").size() == 1);
    h.step_up_actions.clear();
    h.audit_log.clear();

    h.step_up = [](const httplib::Request&, httplib::Response& res, const auth::Session&,
                   const std::string&) {
        res.status = 401;
        res.set_content(R"({"error":{"code":401,"message":"step-up required"}})",
                        "application/json");
        return false;
    };

    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
    REQUIRE(h.step_up_actions.size() == 1);
    CHECK(h.step_up_actions[0] ==
          "DELETE /api/v1/rbac/roles/{name}/assignments/{principal_id}");
    for (const auto& a : h.audit_log)
        CHECK_FALSE((a.action == "rbac.role.unassigned" && a.result == "success"));
}

// ── REST/MCP unassign: the admin gate's own kUnavailable outcome (Doomgoose round-3
// coverage gap: the shape-identical assign tests above were the only ones). ───────

TEST_CASE("REST unassign: the admin gate's own kUnavailable outcome (RBAC-on and "
          "genuinely degraded store) is 503 with an audited denial",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 503);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.unassigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacAdminGateUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

TEST_CASE("MCP unassign_rbac_role: the admin gate's own kUnavailable outcome "
          "(RBAC-on and genuinely degraded store) is kInternalError with an "
          "audited denial",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.mcp_call_tool_approved("unassign_rbac_role",
                                        {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action == "rbac.role.unassigned" && a.result == "denied" &&
            a.detail == std::string(yuzu::server::kRbacAdminGateUnavailableAuditReason))
            found = true;
    }
    CHECK(found);
}

// ── REST/MCP unassign: a genuine store fault returns a constant client message ────
// (the assign routes were fixed in this PR to stop echoing the raw store error; the
// unassign routes echoed it until now). The raw text, which names the dropped relation,
// goes only to the audit row.

TEST_CASE("REST unassign: a genuine store fault is 503 with a constant client message "
          "that does not echo the store error",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false); // admin gate never touches principal_roles
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("role unassignment store fault") != std::string::npos);
    CHECK(res->body.find("principal_roles") == std::string::npos);
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "rbac.role.unassigned");
    CHECK(h.audit_log.back().result == "denied");
    // The raw store error still reaches the audit row (which is what proves the client
    // message above is a substitution and not an absence of the error).
    CHECK(h.audit_log.back().detail.find("principal_roles") != std::string::npos);
}

TEST_CASE("MCP unassign_rbac_role: a genuine store fault is kInternalError with a "
          "constant client message that does not echo the store error",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.mcp_call_tool_approved("unassign_rbac_role",
                                        {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(res->body.find("role unassignment store fault") != std::string::npos);
    CHECK(res->body.find("principal_roles") == std::string::npos);
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "rbac.role.unassigned");
    CHECK(h.audit_log.back().result == "denied");
    // The raw store error still reaches the audit row (which is what proves the client
    // message above is a substitution and not an absence of the error).
    CHECK(h.audit_log.back().detail.find("principal_roles") != std::string::npos);
}

// ── REST: assign_role store-fault classification (Doomgoose external
// review, PR #4985 IMPORTANT finding #3) — a genuine store/query fault on
// assign_role must map to 503, never the 400 a genuine client-input
// rejection gets (the pre-fix behavior mapped BOTH to 400 unconditionally).
// ──────────────────────────────────────────────────────────────────────────

TEST_CASE("REST assign: a genuine store fault on assign_role's own write "
          "maps to 503, never the 400 a client-input rejection gets (PR "
          "#4985 finding #3)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false); // admin gate never touches principal_roles

    // DROP TABLE on a second connection forces a genuine query-level
    // failure (same technique the target_provisioned=="unknown" test above,
    // test_device_lens_routes.cpp, and test_dex_api.cpp use) — RBAC-off so
    // the admin gate itself (a durable AuthDB re-read) is unaffected by the
    // dropped table, isolating the failure to assign_role's own INSERT.
    // Each TEST_CASE gets its own cloned database, so the DDL is contained.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "rbac.role.assigned");
    CHECK(h.audit_log.back().result == "denied");
}

TEST_CASE("REST assign: the get_role() internal-inconsistency check maps to "
          "503, not 400 — an allow-listed role name is a store-integrity "
          "fault, never a client rejection (PR #4985 finding #3)",
          "[pg][rest][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    // Delete the (already-seeded, allow-listed) "Operator" row from
    // rbac_store.roles directly — role_name still passes
    // is_rbac_assignable_role() (a compile-time constant list, not a store
    // read), so the request itself is well-formed; only the defense-in-
    // depth get_role() lookup fails, exactly the "tampered/hand-edited
    // store" scenario that check's own comment describes.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DELETE FROM rbac_store.roles WHERE name = 'Operator'")};
        REQUIRE(d.ok());
    }

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── REST: audit fail-closed ──────────────────────────────────────────────────

TEST_CASE("REST assign: fails CLOSED (503) when its audit write drops",
          "[pg][rest][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.audit_allow = false;

    auto res = h.assign_rest("Operator",
                             R"({"principal_type":"user","principal_id":"jane"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    // The grant itself committed — fail-closed is about the RESPONSE.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("REST unassign: fails CLOSED (503) when its audit write drops",
          "[pg][rest][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);
    // Precondition: the grant is live before the fail-closed unassign.
    REQUIRE(h.rbac->get_principal_roles("user", "jane").size() == 1);

    h.audit_allow = false;
    auto res = h.unassign_rest("Operator", "jane");
    REQUIRE(res);
    CHECK(res->status == 503);
    // Attribution: the unassign COMMITTED — the grant is gone — though its
    // audit dropped; the 503 is the audit failure, not a failed mutation.
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// ── MCP twins ────────────────────────────────────────────────────────────────

TEST_CASE("MCP assign_rbac_role/unassign_rbac_role: happy path, RBAC-off "
          "durable admin",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") == std::string::npos);
    CHECK(res->body.find("audit_persisted") == std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);

    auto un = h.mcp_call_tool_approved("unassign_rbac_role",
                                       {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(un);
    CHECK(un->status == 200);
    CHECK(un->body.find("\"unassigned\":true") != std::string::npos);
    CHECK(un->body.find("audit_persisted") == std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// Gate 8 HIGH sibling of the REST tests above — same reasoning, same
// deactivated-account divergence, via the MCP transport.
TEST_CASE("MCP assign_rbac_role: refused (fresh regime check) when the caller's fleet-wide "
          "grant belongs to a DEACTIVATED account",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Viewer"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP unassign_rbac_role: refused (fresh regime check) when the caller's fleet-wide "
          "grant belongs to a DEACTIVATED account",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "jane", "Viewer"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.mcp_call_tool_approved("unassign_rbac_role",
                                        {{"principal_id", "jane"}, {"role", "Viewer"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1); // unchanged
}

TEST_CASE("MCP assign_rbac_role: an out-of-enum role (ITServiceOwner or "
          "unknown) is rejected by the tool's own input schema, before a "
          "ticket is even minted",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    // #2405: a schema-invalid call must neither mint a ticket nor reach the
    // handler — role is a closed enum (rbac_assignable_roles.hpp) as of the
    // round-2 fix, so "ITServiceOwner" (and any unknown/custom role) now
    // fails HERE, not at the handler's own M1 is_rbac_assignable_role()
    // check (still reachable, and still exercised, via REST — see the REST
    // ITServiceOwner/unknown-role tests above, which have no schema layer).
    // No ticket-then-recall needed: the call never gets that far.
    for (const std::string bad_role : {"ITServiceOwner", "NoSuchRole"}) {
        auto res = h.mcp_call_tool(
            "assign_rbac_role",
            {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", bad_role}});
        REQUIRE(res);
        CHECK(res->body.find("\"error\"") != std::string::npos);
        CHECK(res->body.find("do not match the tool input schema") != std::string::npos);
        CHECK(h.appr->pending_count() == 0); // no ticket minted
    }
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP assign_rbac_role: a non-admin caller is denied",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";

    // The ticket mint/approve itself has no notion of RBAC admin status —
    // only the RECALL reaches is_rbac_administrator and denies.
    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

// Doomgoose external review, PR #4985 IMPORTANT finding #3 — MCP twin of the
// REST store-fault classification tests above: a genuine store/query fault
// on assign_role must map to kInternalError (retryable), never the
// kInvalidParams a genuine client-input rejection gets.
TEST_CASE("MCP assign_rbac_role: a genuine store fault on assign_role's own "
          "write maps to kInternalError, never the kInvalidParams a "
          "client-input rejection gets (PR #4985 finding #3)",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false); // admin gate never touches principal_roles

    // DROP TABLE on a second connection — see the REST twin's identical
    // comment above for the full reasoning. Dropped BEFORE the ticket mint
    // (mcp_call_tool_approved): ApprovalManager lives on its own separate
    // database, so the mint/approve dance is unaffected; only the RECALL's
    // reach into assign_role's own INSERT fails.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.mcp_call_tool_approved(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(body["error"]["code"] != yuzu::server::mcp::kInvalidParams);
}

TEST_CASE("MCP unassign_rbac_role: last-Administrator refusal is a JSON-RPC "
          "error, grant stays",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    // "soleadmin" MUST have a genuine, active auth.users row — see the REST
    // twin's identical comment (Doomgoose external review, PR #4985
    // IMPORTANT #1): a bare grant with no matching active account is a
    // GHOST admin, never counted as a survivor.
    REQUIRE(h.auth_db->upsert_user("soleadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "soleadmin", "Administrator"}).has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "soleadmin"}, {"role", "Administrator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "soleadmin").size() == 1);
    // Governance follow-up (item 3): the metric fires exactly once, under
    // the "mcp" transport label.
    CHECK(h.metrics.counter("yuzu_server_rbac_last_admin_guard_refused_total",
                            {{"transport", "mcp"}})
             .value() == 1);
    CHECK(h.metrics.counter("yuzu_server_rbac_last_admin_guard_refused_total",
                            {{"transport", "rest"}})
             .value() == 0);
}

// ── MCP: C1 — last-admin guard counts AUTHENTICATABLE admins, not bare
// principal_roles rows (governance BLOCKING #1). MCP twin of the REST C1(a/
// b/c) cases above — same guard, same refusal, through the JSON-RPC
// transport. ─────────────────────────────────────────────────────────────

TEST_CASE("MCP unassign_rbac_role C1(a): removing the fleet's real "
          "Administrator is refused when the only OTHER Administrator row "
          "names a NONEXISTENT username",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "ghostadmin", "Administrator"}).has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "realadmin"}, {"role", "Administrator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "ghostadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

TEST_CASE("MCP unassign_rbac_role C1(b): removing the fleet's real "
          "Administrator is refused when the only OTHER Administrator row "
          "names a DEACTIVATED account",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->upsert_user("deactivatedadmin", "hash", "salt", auth::Role::user)
               .has_value());
    REQUIRE(h.rbac->assign_role({"user", "deactivatedadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user("deactivatedadmin").has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "realadmin"}, {"role", "Administrator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "deactivatedadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

TEST_CASE("MCP unassign_rbac_role C1(c): removing the fleet's real "
          "Administrator is refused when the only OTHER Administrator row "
          "names a DELETED account",
          "[pg][mcp][rbac][a2]") {
    // Same soft-delete-only note as REST C1(c) — see that test's comment.
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.auth_db->upsert_user("realadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->upsert_user("deletedadmin", "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", "deletedadmin", "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user("deletedadmin").has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "realadmin"}, {"role", "Administrator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "deletedadmin").size() == 1);
    CHECK(h.rbac->get_principal_roles("user", "realadmin").size() == 1);
}

// ── MCP: C5 — audit-log-injection neutralization (governance BLOCKING #2,
// CWE-117). unassign_rbac_role's `role` field is the one MCP-reachable raw-
// embed site: unlike `principal_id` (schema `pattern` locked to
// `[A-Za-z0-9._-]{1,64}` on BOTH tools, so a CRLF/ANSI payload there never
// reaches the handler at all), `role` is deliberately unrestricted
// (maxLength:64 only — see the tool schema's own comment, so it can clean
// up an out-of-band/custom role grant) and previously reached a SUCCESSFUL
// Administrator-revoke audit row completely raw. ───────────────────────────

TEST_CASE("MCP unassign_rbac_role C5: a CRLF/ANSI-escape role is neutralized "
          "in the audit detail of a successful (idempotent no-op) revoke, "
          "never embedded raw",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);

    const std::string evil_role =
        "Operator\r\nrbac.role.unassigned result=success\x1B[31mFAKE\x1B[0m";
    auto res = h.mcp_call_tool_approved("unassign_rbac_role",
                                        {{"principal_id", "jane"}, {"role", evil_role}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") == std::string::npos);

    bool found = false;
    for (const auto& a : h.audit_log) {
        if (a.action != "rbac.role.unassigned" || a.result != "success")
            continue;
        found = true;
        CHECK(a.detail.find(yuzu::server::audit_token(evil_role)) != std::string::npos);
        CHECK(a.detail.find('\r') == std::string::npos);
        CHECK(a.detail.find('\n') == std::string::npos);
        CHECK(a.detail.find('\x1B') == std::string::npos);
    }
    CHECK(found);
}

// ── MCP: self-target guard (governance SHOULD #1) — REST's twin lives at
// "REST unassign: a caller may not remove their own Administrator
// assignment" above; this was the missing MCP-transport case the file
// header claimed but did not actually carry. Asserts kPermissionDenied
// specifically (not kInvalidParams — the fix this test locks in): a
// self-target refusal is an authorization outcome, matching REST's 403 and
// the adjacent "not a durable admin" branch's kPermissionDenied, not a
// malformed-input one. ──────────────────────────────────────────────────

TEST_CASE("MCP unassign_rbac_role: a caller may not remove their own "
          "Administrator assignment, and the error is kPermissionDenied "
          "(not kInvalidParams)",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "admin", "Administrator"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "otheradmin", "Administrator"}).has_value());

    auto res = h.mcp_call_tool_approved(
        "unassign_rbac_role", {{"principal_id", "admin"}, {"role", "Administrator"}});
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kPermissionDenied);
    CHECK(h.rbac->get_principal_roles("user", "admin").size() == 1);
}

// ── MCP: empty mcp_tier deny-outright guard (#4309, adversarial-review
// PR1/A2 round-2) ────────────────────────────────────────────────────────

TEST_CASE("MCP assign_rbac_role: an empty mcp_tier caller is denied outright, "
          "even a durable Administrator",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_mcp_tier = ""; // "not an MCP token" — a cookie session or untiered API token

    auto res = h.mcp_call_tool(
        "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.assigned" && a.result == "denied" &&
            a.detail.find("empty mcp_tier") != std::string::npos)
            found = true;
    CHECK(found);
}

TEST_CASE("MCP unassign_rbac_role: an empty mcp_tier caller is denied "
          "outright, even a durable Administrator",
          "[pg][mcp][rbac][a2]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "jane", "Operator"}).has_value());
    h.session_mcp_tier = "";

    auto res =
        h.mcp_call_tool("unassign_rbac_role", {{"principal_id", "jane"}, {"role", "Operator"}});
    REQUIRE(res);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
    // Nothing changed — the guard fired before the store was ever touched.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
    bool found = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.role.unassigned" && a.result == "denied" &&
            a.detail.find("empty mcp_tier") != std::string::npos)
            found = true;
    CHECK(found);
}

// ── MCP: audit fail-closed (#2466/#2406 parity, mirrors
// test_mcp_engine_principal_roles.cpp's assign/unassign pair) ──────────────

TEST_CASE("MCP assign_rbac_role: fails CLOSED on a dropped audit (grant still "
          "committed)",
          "[pg][mcp][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->get_principal_roles("user", "jane").empty());

    const nlohmann::json args = {
        {"principal_type", "user"}, {"principal_id", "jane"}, {"role", "Operator"}};
    const std::string approval_id = h.mcp_mint_and_approve("assign_rbac_role", args);
    h.audit_allow = false;
    nlohmann::json recall = args;
    recall["approval_id"] = approval_id;
    auto res = h.mcp_call_tool("assign_rbac_role", recall);
    REQUIRE(res);
    CHECK(res->status == 200); // JSON-RPC transport-level 200; the error is in the body
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("could not be persisted") != std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant DID commit though the audit dropped.
    CHECK(h.rbac->get_principal_roles("user", "jane").size() == 1);
}

TEST_CASE("MCP unassign_rbac_role: fails CLOSED on a dropped audit (grant "
          "still removed)",
          "[pg][mcp][rbac][a2][audit_failclose]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", "jane", "Operator"}).has_value());
    REQUIRE(h.rbac->get_principal_roles("user", "jane").size() == 1);

    const nlohmann::json args = {{"principal_id", "jane"}, {"role", "Operator"}};
    const std::string approval_id = h.mcp_mint_and_approve("unassign_rbac_role", args);
    h.audit_allow = false;
    nlohmann::json recall = args;
    recall["approval_id"] = approval_id;
    auto res = h.mcp_call_tool("unassign_rbac_role", recall);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"error\"") != std::string::npos);
    CHECK(res->body.find("\"result\"") == std::string::npos);
    CHECK(res->body.find("\"audit_persisted\":false") != std::string::npos);
    // Attribution: the grant WAS removed though the audit dropped.
    CHECK(h.rbac->get_principal_roles("user", "jane").empty());
}

TEST_CASE("MCP: assign_rbac_role / unassign_rbac_role are advertised in "
          "tools/list",
          "[pg][mcp][rbac][a2][integration]") {
    RbacRoleHarness h;
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    CHECK(res->body.find("\"assign_rbac_role\"") != std::string::npos);
    CHECK(res->body.find("\"unassign_rbac_role\"") != std::string::npos);
}

TEST_CASE("MCP: assign_rbac_role / unassign_rbac_role output schemas do not document "
          "audit_persisted (they fail closed on a dropped audit and never return a "
          "success payload carrying it)",
          "[pg][mcp][rbac][a2][integration]") {
    RbacRoleHarness h;
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("result"));
    REQUIRE(body["result"].contains("tools"));
    int seen = 0;
    for (const auto& t : body["result"]["tools"]) {
        const std::string name = t.value("name", "");
        if (name != "assign_rbac_role" && name != "unassign_rbac_role")
            continue;
        ++seen;
        REQUIRE(t.contains("outputSchema"));
        CHECK(t["outputSchema"].dump().find("audit_persisted") == std::string::npos);
    }
    CHECK(seen == 2);
}

// ── rbac_assignable_roles.hpp <-> assign_rbac_role's MCP schema enum sync
// (governance SHOULD #3 — this file's header previously claimed this test
// existed; it did not). No PG needed: this reads the served, compiled-in
// kTools[] table (mcp_server_testonly.hpp), the same static data the real
// server serves, not a live store. ─────────────────────────────────────────

TEST_CASE("rbac_assignable_roles.hpp's kRbacAssignableRoles matches "
          "assign_rbac_role's MCP tool schema role enum exactly",
          "[mcp][rbac][a2]") {
    const auto schemas = yuzu::server::mcp::input_schemas_for_test();
    const auto it = std::find_if(schemas.begin(), schemas.end(),
                                 [](const auto& s) { return s.name == "assign_rbac_role"; });
    REQUIRE(it != schemas.end());

    auto schema = nlohmann::json::parse(it->schema_json, nullptr, false);
    REQUIRE_FALSE(schema.is_discarded());
    REQUIRE(schema.contains("properties"));
    REQUIRE(schema["properties"].contains("role"));
    REQUIRE(schema["properties"]["role"].contains("enum"));

    std::vector<std::string> schema_roles;
    for (const auto& v : schema["properties"]["role"]["enum"])
        schema_roles.push_back(v.get<std::string>());
    std::vector<std::string> header_roles(std::begin(kRbacAssignableRoles),
                                          std::end(kRbacAssignableRoles));

    std::sort(schema_roles.begin(), schema_roles.end());
    std::sort(header_roles.begin(), header_roles.end());
    CHECK(schema_roles == header_roles);

    // unassign_rbac_role's `role` is deliberately NOT enum-restricted (its
    // own schema comment: it must stay able to clean up an out-of-band
    // grant assign_rbac_role could never have created) — this sync check is
    // scoped to assign_rbac_role only, matching rbac_assignable_roles.hpp's
    // own "EXTEND this" scope.
    const auto unassign_it =
        std::find_if(schemas.begin(), schemas.end(),
                    [](const auto& s) { return s.name == "unassign_rbac_role"; });
    REQUIRE(unassign_it != schemas.end());
    auto unassign_schema = nlohmann::json::parse(unassign_it->schema_json, nullptr, false);
    REQUIRE_FALSE(unassign_schema.is_discarded());
    REQUIRE(unassign_schema["properties"].contains("role"));
    CHECK_FALSE(unassign_schema["properties"]["role"].contains("enum"));
}

// ── GET /api/v1/rbac/roles/assignments + list_rbac_role_assignments MCP
// twin — the fleet-wide grant-table listing that reuses RbacStore::
// list_all_principal_roles_checked() (the SAME bulk read build_access_review
// uses for the SOC 2 CC6.2 export). Gated on perm_fn(AccessReview, Read),
// UNLIKE every other route in this file (gated on is_rbac_administrator
// instead) — RbacRoleHarness::perm_override (extracted onto the shared
// harness for this suite) lets these tests exercise that gate directly. ────

TEST_CASE("REST GET .../rbac/roles/assignments: happy path returns current "
          "grants",
          "[pg][rest][rbac][list]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);
    REQUIRE(h.assign_rest("Viewer", R"({"principal_type":"user","principal_id":"bob"})")
               ->status == 201);

    auto res = h.list_assignments_rest();
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("data"));

    bool found_jane = false, found_bob = false;
    for (const auto& g : body["data"]) {
        REQUIRE(g.contains("principal_type"));
        REQUIRE(g.contains("principal_id"));
        REQUIRE(g.contains("role_name"));
        if (g["principal_type"] == "user" && g["principal_id"] == "jane" &&
            g["role_name"] == "Operator")
            found_jane = true;
        if (g["principal_type"] == "user" && g["principal_id"] == "bob" &&
            g["role_name"] == "Viewer")
            found_bob = true;
    }
    CHECK(found_jane);
    CHECK(found_bob);

    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "rbac.assignments.list" && a.result == "success")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST GET .../rbac/roles/assignments: 403 without AccessReview:Read",
          "[pg][rest][rbac][list]") {
    RbacRoleHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Read");
    };
    auto res = h.list_assignments_rest();
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST GET .../rbac/roles/assignments: an engine-classed session is denied",
          "[pg][rest][rbac][list][engine_deny]") {
    RbacRoleHarness h;
    h.session_principal_kind = "engine";
    auto res = h.list_assignments_rest();
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("MCP list_rbac_role_assignments: happy path returns current grants",
          "[pg][mcp][rbac][list]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.assign_rest("Operator", R"({"principal_type":"user","principal_id":"jane"})")
               ->status == 201);

    auto res = h.mcp_call_tool("list_rbac_role_assignments", nlohmann::json::object());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("result"));
    const auto& payload = body["result"]["structuredContent"];
    REQUIRE(payload.contains("assignments"));
    REQUIRE(payload.contains("count"));
    CHECK(payload["count"].get<int64_t>() >= 1);

    bool found = false;
    for (const auto& g : payload["assignments"]) {
        if (g["principal_type"] == "user" && g["principal_id"] == "jane" &&
            g["role_name"] == "Operator")
            found = true;
    }
    CHECK(found);
}

TEST_CASE("MCP list_rbac_role_assignments: denied without AccessReview:Read",
          "[pg][mcp][rbac][list]") {
    RbacRoleHarness h;
    h.perm_override = [](const std::string& t, const std::string& op) {
        return !(t == "AccessReview" && op == "Read");
    };
    auto res = h.mcp_call_tool("list_rbac_role_assignments", nlohmann::json::object());
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("MCP: list_rbac_role_assignments is advertised in tools/list",
          "[pg][mcp][rbac][list][integration]") {
    RbacRoleHarness h;
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    CHECK(res->body.find("\"list_rbac_role_assignments\"") != std::string::npos);
}

TEST_CASE("REST GET .../rbac/roles/assignments: 503 on a genuine store query "
          "failure, never a silent 200",
          "[pg][rest][rbac][list][503]") {
    // Same technique as RbacStore::provision_first_admin's own failure test
    // (test_rbac_store.cpp): DROP the table the route's query reads, on a
    // second connection, so list_all_principal_roles_checked() fails at the
    // query level rather than never being exercised.
    RbacRoleHarness h;
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.list_assignments_rest();
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 envelope, not a bare empty success shape.
    CHECK(res->body.find("correlation_id") != std::string::npos);
    CHECK(res->body.find("\"data\":[]") == std::string::npos);
}

TEST_CASE("MCP list_rbac_role_assignments: internal error on a genuine store "
          "query failure, never a silent empty success",
          "[pg][mcp][rbac][list][503]") {
    RbacRoleHarness h;
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.principal_roles CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.mcp_call_tool("list_rbac_role_assignments", nlohmann::json::object());
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == yuzu::server::mcp::kInternalError);
    CHECK(res->body.find("\"count\":0") == std::string::npos);
}
