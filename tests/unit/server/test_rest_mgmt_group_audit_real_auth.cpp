/**
 * test_rest_mgmt_group_audit_real_auth.cpp: #7074: the audit-first management-group routes
 * (`POST /api/v1/management-groups`, `POST .../members`) end to end through the PRODUCTION auth
 * and audit wiring, with no stub in the identity path.
 *
 * `test_rest_mgmt_group_audit_first.cpp` drives the same routes through a stub `auth_fn`, a stub
 * `perm_fn` and stub audit writers; `test_auth_routes.cpp` drives `AuthRoutes::audit_as_session_fn`
 * alone. Neither pins the JOIN: that every row a route writes after it resolved the session goes
 * through the session-bound writer `server.cpp` binds, so a session revoked after the `attempted`
 * row cannot blank the principal of the `session_revoked` failure row. Here the wiring is the one
 * `server.cpp` hands `RestApiV1::register_routes`:
 *
 *   auth_fn  = AuthRoutes::require_auth           (cookie resolved by a REAL AuthManager over a
 *                                                  REAL AuthDB (PG) and a durable SessionStore;
 *                                                  or a bearer token resolved by a REAL
 *                                                  ApiTokenStore)
 *   perm_fn  = AuthRoutes::require_permission     (RBAC off: the legacy admin path)
 *   audit_fn = AuthRoutes::audit_log              (the re-resolving writer)
 *   set_audit_as_session_fn(AuthRoutes::audit_as_session_fn())
 *
 * and every assertion reads the REAL rows back through `AuditStore::query`. The one deliberate
 * addition is a pass-through wrapper on both writers that delegates to the real writer first and
 * then revokes the caller's session once an `attempted` row of the configured action has been
 * stored: the window the route's post-`attempted` re-check exists for. The wrapper sits on BOTH
 * writers so the case fails on what the route's rows say, not on which writer happened to carry
 * the revoke.
 *
 * PG-gated: every case SKIPs when YUZU_TEST_POSTGRES_DSN is unset.
 */

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "rest_api_v1.hpp"
#include "session_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

constexpr const char* kCreate = "management_group.create";
constexpr const char* kAdd = "management_group.add_member";
constexpr const char* kRemove = "management_group.remove_member";
constexpr const char* kPassword = "real-auth-password-123";

struct RealAuthHarness {
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    yuzu::test::AuthDbPg db;
    SessionStore sessions{db.pool()};
    AuditStore audit_store{db.pool()};
    AuthManager auth_mgr;
    std::optional<yuzu::test::ApiTokenStorePg> tokens; // only when `with_api_tokens`
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    /// Armed by a case: once a row of `revoke_on_action` with result `attempted` has been stored
    /// (through either writer), `revoke_token`'s session is invalidated in the real AuthManager.
    std::string revoke_on_action;
    std::string revoke_token;
    int revoke_fired = 0;

    explicit RealAuthHarness(bool with_api_tokens = false) {
        cfg.https_enabled = false;
        REQUIRE(sessions.is_open());
        REQUIRE(audit_store.is_open());
        auth_mgr.set_auth_db(db.get());
        auth_mgr.set_session_store(&sessions);
        auth_mgr.set_metrics_registry(&metrics);
        mgmt_bundle->set_metrics(&metrics);
        if (with_api_tokens)
            tokens.emplace();
        // The production wiring: the REAL audit store reaches AuthRoutes (server.cpp), so every
        // writer below persists rows the cases read back.
        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr, /*rbac_store=*/nullptr,
            tokens ? tokens->get() : static_cast<ApiTokenStore*>(nullptr), &audit_store,
            /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, /*analytics_store=*/nullptr,
            oidc_mu, oidc_provider);

        // server.cpp's three delegating lambdas (require_auth / require_permission / audit_log).
        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response& res) -> std::optional<auth::Session> {
            return auth_routes->require_auth(req, res);
        };
        auto perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            return auth_routes->require_permission(req, res, type, op);
        };
        auto audit_fn = [this](const httplib::Request& req, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            const bool ok =
                auth_routes->audit_log(req, action, result, target_type, target_id, detail);
            revoke_if_armed(action, result);
            return ok;
        };
        // THE production session-bound writer, wrapped only to fire the revoke after delegating.
        api.set_audit_as_session_fn(
            [this, real = auth_routes->audit_as_session_fn()](
                const httplib::Request& req, const auth::Session& session,
                const std::string& principal_role, const std::string& action,
                const std::string& result, const std::string& target_type,
                const std::string& target_id, const std::string& detail) -> bool {
                const bool ok = real(req, session, principal_role, action, result, target_type,
                                     target_id, detail);
                revoke_if_armed(action, result);
                return ok;
            });

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/&*mgmt_bundle,
                            /*token_store=*/tokens ? tokens->get() : nullptr,
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
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/db.get(),
                            /*directory_sync=*/nullptr);
    }

    void revoke_if_armed(const std::string& action, const std::string& result) {
        if (revoke_on_action.empty() || action != revoke_on_action || result != "attempted")
            return;
        ++revoke_fired;
        revoke_on_action.clear(); // once
        (void)auth_mgr.invalidate_session(revoke_token);
    }

    /// A local, RBAC-off administrator who has signed in: returns the real session cookie value.
    std::string login_admin(const std::string& user) {
        auto salt = AuthManager::random_bytes(16);
        REQUIRE(db->upsert_user(
                      user,
                      AuthManager::pbkdf2_sha256(kPassword, salt, AuthManager::kPbkdf2Iterations),
                      AuthManager::bytes_to_hex(salt), Role::admin)
                    .has_value());
        auto token = auth_mgr.authenticate(user, kPassword);
        REQUIRE(token.has_value());
        return *token;
    }

    static std::unordered_map<std::string, std::string> cookie_headers(const std::string& token) {
        return {{"Cookie", "yuzu_session=" + token}};
    }

    std::unique_ptr<httplib::Response>
    post(const std::string& path, const nlohmann::json& body,
         const std::unordered_map<std::string, std::string>& headers) {
        return sink.dispatch("POST", path, body.dump(), "application/json", headers);
    }

    std::unique_ptr<httplib::Response>
    del(const std::string& path, const std::unordered_map<std::string, std::string>& headers) {
        return sink.dispatch("DELETE", path, {}, "application/json", headers);
    }

    /// Alice's cookie AND bob's bearer API token on ONE request, both for local administrators.
    /// The resolver tries the cookie first and falls through to the bearer token, so once alice's
    /// session is revoked mid-request the request resolves to bob.
    std::unordered_map<std::string, std::string> mixed_headers(const std::string& alice_cookie,
                                                              const std::string& bob_bearer) {
        return {{"Cookie", "yuzu_session=" + alice_cookie},
                {"Authorization", "Bearer " + bob_bearer}};
    }

    /// Every stored row of one action, oldest first (the REAL store).
    std::vector<AuditEvent> rows_of(const std::string& action) {
        AuditQuery q;
        q.action = action;
        q.limit = 100;
        auto rows = audit_store.query(q);
        REQUIRE(rows.has_value());
        std::vector<AuditEvent> out(rows->begin(), rows->end());
        std::sort(out.begin(), out.end(),
                  [](const AuditEvent& a, const AuditEvent& b) { return a.id < b.id; });
        return out;
    }

    [[nodiscard]] bool group_exists(const std::string& name) const {
        for (const auto& g : mgmt_bundle->list_groups())
            if (g.name == name)
                return true;
        return false;
    }

    std::string make_group(const std::string& name) {
        ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.created_by = "seed";
        auto id = mgmt_bundle->create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }
};

std::string cookie_digest(const std::string& token) { return AuthManager::sha256_hex(token); }

} // namespace

TEST_CASE("real auth: POST /management-groups stores attempted then success, both naming the "
          "signed-in principal, one role and the cookie digest",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h;
    const auto token = h.login_admin("alice");

    auto res = h.post("/api/v1/management-groups", {{"name", "real-create"}},
                      RealAuthHarness::cookie_headers(token));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(res->status == 201);
    const auto new_id = nlohmann::json::parse(res->body)["data"]["id"].get<std::string>();
    CHECK(h.group_exists("real-create"));

    const auto rows = h.rows_of(kCreate);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "success");
    for (const auto& r : rows) {
        INFO("row result=" << r.result);
        CHECK(r.principal == "alice");
        CHECK(r.principal_role == "admin");
        CHECK(r.session_id == cookie_digest(token));
        CHECK_FALSE(r.session_id.empty());
        CHECK(r.target_type == "ManagementGroup");
        CHECK(r.detail == "real-create");
    }
    CHECK(rows[0].principal_role == rows[1].principal_role);
    CHECK(rows[0].target_id.empty());
    CHECK(rows[1].target_id == new_id);
}

TEST_CASE("real auth: POST .../members stores attempted then success, both naming the signed-in "
          "principal and the cookie digest",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h;
    const auto token = h.login_admin("alice");
    const auto gid = h.make_group("real-add-group");

    auto res = h.post("/api/v1/management-groups/" + gid + "/members",
                      {{"agent_id", "agent-real-1"}}, RealAuthHarness::cookie_headers(token));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(res->status == 201);
    CHECK(h.mgmt_bundle->get_members(gid).size() == 1);

    const auto rows = h.rows_of(kAdd);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "success");
    for (const auto& r : rows) {
        INFO("row result=" << r.result);
        CHECK(r.principal == "alice");
        CHECK(r.principal_role == "admin");
        CHECK(r.session_id == cookie_digest(token));
        CHECK(r.target_type == "ManagementGroup");
        CHECK(r.target_id == gid);
    }
    CHECK(rows[0].detail == "agent-real-1");
    CHECK(rows[1].detail.starts_with("agent-real-1 agent_known="));
}

TEST_CASE("real auth: a session revoked right after the create attempted row still yields a "
          "session_revoked failure row naming the ORIGINAL principal, and no group",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h;
    const auto token = h.login_admin("alice");
    h.revoke_on_action = kCreate;
    h.revoke_token = token;

    auto res = h.post("/api/v1/management-groups", {{"name", "real-revoked"}},
                      RealAuthHarness::cookie_headers(token));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    // The revoke really happened in the real AuthManager, inside the route's audit window.
    REQUIRE(h.revoke_fired == 1);
    CHECK_FALSE(h.auth_mgr.validate_session(token).has_value());
    CHECK(res->status == 401);
    CHECK_FALSE(h.group_exists("real-revoked"));

    const auto rows = h.rows_of(kCreate);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].principal == "alice");
    CHECK(rows[1].result == "failure");
    // The class this case exists for: the failure row is written AFTER the session is gone, and
    // must still name who made the request (a re-resolving writer would record an empty principal).
    CHECK(rows[1].principal == "alice");
    CHECK(rows[1].principal_role == "admin");
    CHECK(rows[1].session_id == cookie_digest(token));
    CHECK(rows[1].detail == "session_revoked real-revoked");
    // Principal-based pairing of the two rows of one request holds.
    CHECK(rows[0].principal == rows[1].principal);
    CHECK(rows[0].principal_role == rows[1].principal_role);
    CHECK(rows[0].session_id == rows[1].session_id);
}

TEST_CASE("real auth: a session revoked right after the add-member attempted row still yields a "
          "session_revoked failure row naming the ORIGINAL principal, and no member",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h;
    const auto token = h.login_admin("alice");
    const auto gid = h.make_group("real-revoked-add");
    h.revoke_on_action = kAdd;
    h.revoke_token = token;

    auto res = h.post("/api/v1/management-groups/" + gid + "/members",
                      {{"agent_id", "agent-real-2"}}, RealAuthHarness::cookie_headers(token));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(h.revoke_fired == 1);
    CHECK_FALSE(h.auth_mgr.validate_session(token).has_value());
    CHECK(res->status == 401);
    CHECK(h.mgmt_bundle->get_members(gid).empty());

    const auto rows = h.rows_of(kAdd);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].principal == "alice");
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].principal == "alice");
    CHECK(rows[1].principal_role == "admin");
    CHECK(rows[1].session_id == cookie_digest(token));
    CHECK(rows[1].target_id == gid);
    CHECK(rows[1].detail == "session_revoked agent-real-2");
    CHECK(rows[0].principal == rows[1].principal);
    CHECK(rows[0].session_id == rows[1].session_id);
}

TEST_CASE("real auth: a bearer API token request names the token's principal with an EMPTY "
          "session_id (the correlator is the cookie digest)",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h(/*with_api_tokens=*/true);
    // The token's principal is a real local administrator: the synthesized session takes the
    // creator's live legacy role, which RBAC-off permission checks consult.
    (void)h.login_admin("alice");
    auto raw = (*h.tokens)->create_token("real-auth-ci", "alice");
    REQUIRE(raw.has_value());

    auto res = h.post("/api/v1/management-groups", {{"name", "real-bearer"}},
                      {{"Authorization", "Bearer " + *raw}});
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(res->status == 201);
    CHECK(h.group_exists("real-bearer"));

    const auto rows = h.rows_of(kCreate);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "success");
    for (const auto& r : rows) {
        INFO("row result=" << r.result);
        CHECK(r.principal == "alice");
        CHECK(r.session_id.empty());
    }
}

// C1 (PR #7920 review): the post-attempted re-check must refuse a DIFFERENT principal, not just
// an absent one. The resolver falls through cookie -> Bearer -> X-Yuzu-Token, so a request that
// carries alice's cookie and bob's API token resolves to bob once alice's session is gone.
// The rows are bound to alice; a mutation authorised as bob would misname the actor.

TEST_CASE("real auth: create with alice's cookie and bob's bearer token, alice revoked after the "
          "attempted row, is refused (the fall-through principal is not alice) and creates nothing",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h(/*with_api_tokens=*/true);
    const auto alice = h.login_admin("alice");
    (void)h.login_admin("bob");
    auto bob_raw = (*h.tokens)->create_token("bob-ci", "bob");
    REQUIRE(bob_raw.has_value());
    h.revoke_on_action = kCreate;
    h.revoke_token = alice;

    auto res = h.post("/api/v1/management-groups", {{"name", "real-mixed-create"}},
                      h.mixed_headers(alice, *bob_raw));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(h.revoke_fired == 1);
    CHECK_FALSE(h.auth_mgr.validate_session(alice).has_value());
    CHECK(res->status == 401);
    CHECK_FALSE(h.group_exists("real-mixed-create"));

    const auto rows = h.rows_of(kCreate);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].principal == "alice");
    CHECK(rows[1].principal_role == "admin");
    CHECK(rows[1].session_id == cookie_digest(alice));
    CHECK(rows[1].detail == "session_revoked real-mixed-create");
    for (const auto& r : rows)
        CHECK(r.result != "success");
}

TEST_CASE("real auth: add member with alice's cookie and bob's bearer token, alice revoked after "
          "the attempted row, is refused and adds nothing",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h(/*with_api_tokens=*/true);
    const auto alice = h.login_admin("alice");
    (void)h.login_admin("bob");
    auto bob_raw = (*h.tokens)->create_token("bob-ci", "bob");
    REQUIRE(bob_raw.has_value());
    const auto gid = h.make_group("real-mixed-add");
    h.revoke_on_action = kAdd;
    h.revoke_token = alice;

    auto res = h.post("/api/v1/management-groups/" + gid + "/members",
                      {{"agent_id", "agent-mixed-1"}}, h.mixed_headers(alice, *bob_raw));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(h.revoke_fired == 1);
    CHECK(res->status == 401);
    CHECK(h.mgmt_bundle->get_members(gid).empty());

    const auto rows = h.rows_of(kAdd);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].principal == "alice");
    CHECK(rows[1].principal_role == "admin");
    CHECK(rows[1].session_id == cookie_digest(alice));
    CHECK(rows[1].target_id == gid);
    CHECK(rows[1].detail == "session_revoked agent-mixed-1");
    for (const auto& r : rows)
        CHECK(r.result != "success");
}

TEST_CASE("real auth: remove member with alice's cookie and bob's bearer token, alice revoked "
          "after the attempted row, is refused and removes nothing",
          "[pg][rest][mgmt_group][mgmt-audit-first][real-auth]") {
    RealAuthHarness h(/*with_api_tokens=*/true);
    const auto alice = h.login_admin("alice");
    (void)h.login_admin("bob");
    auto bob_raw = (*h.tokens)->create_token("bob-ci", "bob");
    REQUIRE(bob_raw.has_value());
    const auto gid = h.make_group("real-mixed-remove");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-mixed-2").has_value());
    h.revoke_on_action = kRemove;
    h.revoke_token = alice;

    auto res = h.del("/api/v1/management-groups/" + gid + "/members/agent-mixed-2",
                     h.mixed_headers(alice, *bob_raw));
    REQUIRE(res);
    INFO(res->status << " " << res->body);
    REQUIRE(h.revoke_fired == 1);
    CHECK(res->status == 401);
    CHECK(h.mgmt_bundle->get_members(gid).size() == 1);

    const auto rows = h.rows_of(kRemove);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].principal == "alice");
    CHECK(rows[1].principal_role == "admin");
    CHECK(rows[1].session_id == cookie_digest(alice));
    CHECK(rows[1].target_id == gid);
    CHECK(rows[1].detail == "session_revoked agent-mixed-2");
    for (const auto& r : rows)
        CHECK(r.result != "success");
}
