#pragma once

/// test_rbac_admin_surface_harness.hpp — shared REST+MCP harness for the
/// "durable Administrator" gate surface (rbac_admin_predicate.hpp's
/// is_rbac_administrator): A2's global human role assignment
/// (POST/DELETE /api/v1/rbac/roles/{name}/assignments[/{principal_id}] +
/// assign_rbac_role/unassign_rbac_role) and A1's enforcement toggle
/// (PUT /api/v1/rbac/enforcement + set_rbac_enforcement).
///
/// Extracted VERBATIM (A1 Step 6.1) from test_rbac_role_assignment.cpp,
/// which now `#include`s this header — the class name (RbacRoleHarness) and
/// every existing member are UNCHANGED, so that file's references stay
/// valid. Two additions for A1: the `put_rest`/`set_enforcement_rest`
/// convenience wrappers, and a `make_caller_admin(/*rbac_on=*/true)` fix — an
/// active `auth.users` row alongside the RBAC grant, needed so an RBAC-on
/// caller also passes `check_caller_authorized_under_current_regime`'s
/// `list_authenticatable_admin_grants` JOIN (A1's Gate 8 HIGH fix, now also
/// gating A2's own assign/unassign routes) — `is_rbac_administrator`'s own
/// RBAC-on branch never needed this (bare `principal_roles` membership, no
/// `auth.users` join), so origin A2 tests never needed the row either.
/// Everything else, including the REST/MCP `mcp_tier` split
/// (`rest_session_mcp_tier` / `session_mcp_tier`) and the real, testable
/// `step_up`/`step_up_actions` MFA seam, is A2's own already-shipped,
/// Doomgoose-and-Fable-adjudicated design (PR #4985) — A1 reuses it
/// verbatim rather than forking a parallel mechanism.
///
/// PG-gated: RbacStore, AuthDB, AND ApprovalManager are all born-on-Postgres
/// (ADR-0006/ADR-0065). Skips when YUZU_TEST_POSTGRES_DSN is unset, fails
/// when set but broken.

#include "mcp_jsonrpc.hpp" // mcp::kApprovalRequired — the ticket-then-recall dance
#include "mcp_server.hpp"
#include "mfa_step_up.hpp" // StepUpFn — A1's PUT /api/v1/rbac/enforcement calls it
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "test_approval_manager_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>
#include <yuzu/metrics.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

namespace {

struct AuditRecord {
    std::string action, result, target_id, detail;
};

/// RbacStore co-located on AuthDbPg's own pool/database, NOT RbacStorePg's
/// separate ephemeral one (governance BLOCKING #1, full-pipeline review on
/// 765bc7ec1): `unassign_role`'s last-admin guard now runs a same-transaction
/// `rbac_store.principal_roles JOIN auth.users` (rbac_admin_authority_owner.cpp), which is
/// safe ONLY because production always constructs both stores on the SAME
/// PgPool/database (ADR-0006, server.cpp) — an `auth` schema that
/// does not exist in THIS harness's rbac database would make every
/// `role_name=="Administrator"` unassign fail the lock query outright (a raw
/// Postgres "relation does not exist" error, not the intended 409 refusal).
/// Exposes the same `get()`/`operator->`/`operator*` shape as `RbacStorePg`
/// so every existing `rbac->`/`h.rbac->` call site below is unchanged.
class RbacStoreOnAuthPool {
public:
    explicit RbacStoreOnAuthPool(yuzu::server::pg::PgPool& pool) : store_(pool) {
        REQUIRE(store_.is_open());
    }
    [[nodiscard]] yuzu::server::RbacStore* get() noexcept { return &store_; }
    yuzu::server::RbacStore* operator->() noexcept { return &store_; }
    yuzu::server::RbacStore& operator*() noexcept { return store_; }

private:
    yuzu::server::RbacStore store_;
};

/// One harness driving BOTH the REST TestRouteSink and the MCP JSON-RPC
/// handler off the SAME RbacStore/AuthDB/ApprovalManager. RbacStore and
/// AuthDB share ONE database (RbacStoreOnAuthPool, above) — the last-admin
/// guard's auth.users JOIN needs it; ApprovalManager stays on its own
/// independent database (no cross-store transaction requirement with either
/// store), mirroring test_rest_access_review.cpp's AuthDbPgShared-alongside-
/// RbacStore composition for that one piece.
struct RbacRoleHarness {
    yuzu::server::test::TestRouteSink sink;

    // Declaration order is construction order: auth_db's pool must exist
    // before rbac borrows it.
    yuzu::test::AuthDbPg auth_db;
    RbacStoreOnAuthPool rbac{auth_db.pool()};
    yuzu::test::ApprovalManagerPg appr;

    std::string session_user{"admin"};
    std::string session_token_scope_service;
    std::string session_principal_kind{"human"};
    std::string session_auth_source{"local"};
    // Both MCP tools deny an empty mcp_tier outright (#4309, adversarial-
    // review PR1/A2 round-2) and are approval-gated at "supervised" once a
    // real tier is presented — default to the tier the tool descriptions
    // themselves claim, so an MCP call reaches the tool handler via the
    // real ticket-then-recall dance (mcp_call_tool_approved below) rather
    // than being intercepted by C8 before ever reaching it. The two
    // dedicated empty-tier tests reset this to "" explicitly. MCP-transport
    // sessions ONLY — see `rest_session_mcp_tier` below for why REST's own
    // sessions do NOT share this field.
    std::string session_mcp_tier{"supervised"};
    // #520/Doomgoose (PR #4985 round-2, CRITICAL/BLOCKING): REST sessions
    // MUST default to an EMPTY mcp_tier. Before this fix, BOTH transports
    // shared `session_mcp_tier` (default "supervised"), so every REST
    // happy-path test in this file was UNKNOWINGLY exercising an MCP-tiered
    // session against the REST route — exactly the credential-confusion gap
    // `is_rbac_administrator(..., RbacAdminSurface::kRest)` now structurally
    // denies. A REST test wanting to exercise the (mostly theoretical, since
    // a real browser session never carries an mcp_tier) MCP-token-on-REST
    // denial path sets THIS field directly.
    std::string rest_session_mcp_tier{""};
    bool auth_enabled{true};
    bool audit_allow{true};

    /// nullptr = always allow — the default every is_rbac_administrator-gated
    /// route in this file relies on (assign_rbac_role/unassign_rbac_role/
    /// set_rbac_enforcement never call perm_fn at all). Set to a predicate
    /// returning FALSE to deny a (securable_type, operation) pair — needed
    /// for the READ-ONLY GET /api/v1/rbac/roles/assignments route (+ its
    /// list_rbac_role_assignments MCP twin), which DOES gate on
    /// perm_fn(AccessReview, Read). Mirrors
    /// AccessReviewHarness::perm_override (test_rest_access_review.cpp).
    std::function<bool(const std::string&, const std::string&)> perm_override;

    std::vector<AuditRecord> audit_log;
    // MFA step-up seam. Unset = permissive, the default for every test. A test sets it
    // to stand in for a failed or stale step-up: the route contract under test is that
    // a gate returning false has already written its own response and the route stops
    // before mutating. `step_up_actions` records every action label the routes passed —
    // A2's assign/unassign routes never call it (neither has an MFA gate); A1's PUT
    // /api/v1/rbac/enforcement DOES, so this is exercised by that suite's step-up tests.
    yuzu::server::StepUpFn step_up;
    std::vector<std::string> step_up_actions;

    // Live registry (not nullptr) — governance follow-up (full-pipeline
    // round on 765bc7ec1, item 3): the last-admin-guard-refused metric's
    // increment sites were previously guarded-but-unexercised (the branch
    // logic that decides WHETHER to fire was already proven by the existing
    // last-admin-refusal tests; only the metric call itself was untested).
    // Mirrors test_mcp_server.cpp's `ts.metrics_for_test = &reg` idiom.
    yuzu::MetricsRegistry metrics;

    yuzu::server::RestApiV1 api;
    yuzu::server::mcp::McpServer mcp;
    yuzu::server::mcp::McpServer::HandlerFn mcp_handler;
    bool read_only_mode_{false};
    bool mcp_disabled_{false};

    RbacRoleHarness() {
        REQUIRE(rbac->is_open());
        REQUIRE(auth_db->is_open());
        REQUIRE(appr->is_open());

        // `tier` is the mcp_tier to stamp onto the built session — REST and
        // MCP each pass their OWN member (`rest_session_mcp_tier` /
        // `session_mcp_tier`) so the two transports can never accidentally
        // share one convention again (#520/Doomgoose PR #4985 round-2).
        auto session_of = [this](const std::string& tier) {
            yuzu::server::auth::Session s;
            s.username = session_user;
            s.token_scope_service = session_token_scope_service;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            s.mcp_tier = tier;
            return s;
        };

        auto rest_auth_fn = [this, session_of](const httplib::Request&,
                                               httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            // is_rbac_administrator(..., RbacAdminSurface::kRest) structurally
            // denies ANY non-empty mcp_tier — a real browser/cookie REST
            // session never carries one, so this defaults empty.
            return session_of(rest_session_mcp_tier);
        };
        // Permissive by default — assign_rbac_role/unassign_rbac_role/
        // set_rbac_enforcement never call perm_fn at all (gated on
        // is_rbac_administrator instead); GET /api/v1/rbac/roles/assignments
        // DOES call it (perm_fn(AccessReview, Read)), so `perm_override` lets
        // a test simulate a denial for that route without disturbing the
        // is_rbac_administrator-gated routes' own tests.
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_allow;
        };

        api.register_routes(sink, rest_auth_fn, perm_fn, audit_fn,
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
                            /*step_up_fn=*/
                            [this](const httplib::Request& req, httplib::Response& res,
                                   const yuzu::server::auth::Session& session,
                                   const std::string& action) -> bool {
                                step_up_actions.push_back(action);
                                return !step_up || step_up(req, res, session, action);
                            },
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
                            /*auth_db=*/auth_db.get());

        auto mcp_auth_fn = [this, session_of](const httplib::Request&,
                                              httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            return session_of(session_mcp_tier); // mcp_tier from session_mcp_tier — see its own doc comment
        };
        // Same perm_override shape as the REST perm_fn above — mirrors
        // AccessReviewHarness::mcp_perm_fn (test_rest_access_review.cpp).
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
            return audit_allow;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };

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
            /*approval_manager=*/appr.get(),
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
            /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr,
            /*auth_db=*/auth_db.get(),
            /*directory_sync=*/nullptr);
    }

    /// GET /api/v1/rbac/roles/assignments — the fleet-wide grant-table
    /// listing (gated on perm_fn(AccessReview, Read), unlike every other
    /// route this harness drives).
    auto list_assignments_rest() { return sink.Get("/api/v1/rbac/roles/assignments"); }

    auto assign_rest(const std::string& role, const std::string& body) {
        return sink.Post("/api/v1/rbac/roles/" + role + "/assignments", body);
    }
    auto unassign_rest(const std::string& role, const std::string& principal_id) {
        return sink.Delete("/api/v1/rbac/roles/" + role + "/assignments/" + principal_id);
    }
    /// A1: generic PUT wrapper — used by the enforcement-toggle tests
    /// (currently the toggle is the sole PUT route this harness exercises).
    auto put_rest(const std::string& path, const std::string& body) {
        return sink.Put(path, body);
    }
    /// A1: PUT /api/v1/rbac/enforcement {"enabled": <enabled>}.
    auto set_enforcement_rest(bool enabled) {
        return put_rest("/api/v1/rbac/enforcement",
                        std::string("{\"enabled\":") + (enabled ? "true" : "false") + "}");
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

    /// Ticket-then-recall mint+approve for one approval-gated MCP call
    /// (mirrors test_mcp_server.cpp's SchemaGateHarness pattern): the FIRST
    /// `mcp_call_tool(name, args)` call must mint a pending ticket
    /// (kApprovalRequired), approved here as "reviewer-bob". Returns the
    /// approval_id — the caller embeds it into `args` for the recall.
    /// REQUIREs `audit_allow` to be `true` for this call (the ticket's own
    /// mint/approve-path audit is not what an audit_failclose test exercises
    /// — flip `audit_allow` AFTER calling this, before the recall).
    std::string mcp_mint_and_approve(const std::string& name, const nlohmann::json& args) {
        auto first = mcp_call_tool(name, args);
        REQUIRE(first);
        auto body = nlohmann::json::parse(first->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body.contains("error"));
        REQUIRE(body["error"]["code"] == yuzu::server::mcp::kApprovalRequired);
        REQUIRE(body["error"].contains("data"));
        REQUIRE(body["error"]["data"].contains("approval_id"));
        const std::string approval_id = body["error"]["data"]["approval_id"].get<std::string>();
        REQUIRE(appr->approve(approval_id, "reviewer-bob", "").has_value());
        return approval_id;
    }

    /// Full ticket-then-recall for a call meant to reach the tool handler
    /// (mint+approve via mcp_mint_and_approve, then recall with
    /// `approval_id` embedded in the SAME args). Use this instead of a bare
    /// `mcp_call_tool` for every MCP call to assign_rbac_role/
    /// unassign_rbac_role/set_rbac_enforcement in this suite EXCEPT the
    /// dedicated empty-tier tests (which deliberately bypass C8's ticket
    /// flow) and the schema-enum-rejection test (which fails BEFORE a
    /// ticket is ever minted).
    std::unique_ptr<httplib::Response> mcp_call_tool_approved(const std::string& name,
                                                               const nlohmann::json& args) {
        const std::string approval_id = mcp_mint_and_approve(name, args);
        nlohmann::json recall_args = args;
        recall_args["approval_id"] = approval_id;
        return mcp_call_tool(name, recall_args);
    }

    /// Seeds `admin` as a durable RBAC administrator for the default
    /// `session_user` ("admin"), via whichever branch `rbac_on` selects.
    void make_caller_admin(bool rbac_on) {
        if (rbac_on) {
            rbac->set_rbac_enabled(true);
            // Gate 8 HIGH: an active auth.users row alongside the grant — a
            // "local" auth_source session (this harness's default) can only
            // exist for a real local account in production, so a bare
            // principal_roles row with no corresponding account is an
            // internally-inconsistent double for a "local" caller (it IS a
            // legitimate shape for an SSO/OIDC caller, which never has an
            // auth.users row at all — a different, already-tracked #4966
            // gap, not this one). Needed so this caller passes
            // check_caller_authorized_under_current_regime's
            // list_authenticatable_admin_grants JOIN, the fresh source-regime
            // read reused from set_rbac_enforcement's own Fix 1 check. Local
            // role is deliberately 'user', not 'admin' — this caller's
            // authority comes entirely from the RBAC grant while RBAC is on,
            // never from the (irrelevant, while on) local role field.
            REQUIRE(auth_db->upsert_user(session_user, "hash", "salt", yuzu::server::auth::Role::user)
                       .has_value());
            REQUIRE(rbac->assign_role({"user", session_user, "Administrator"}).has_value());
        } else {
            REQUIRE(auth_db->upsert_user(session_user, "hash", "salt", yuzu::server::auth::Role::admin)
                       .has_value());
        }
    }
};

} // namespace
