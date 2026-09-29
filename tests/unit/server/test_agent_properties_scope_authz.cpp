/**
 * test_agent_properties_scope_authz.cpp — #3700: GET/PUT/DELETE
 * /api/agents/:id/properties[/:key] must gate on per-agent
 * `require_scoped_permission("Infrastructure", "Read"/"Write", agent_id)`,
 * not a bare global `require_permission`.
 *
 * These TEST_CASEs drive the gate directly through
 * `AuthRoutes::require_scoped_permission` rather than through an httplib
 * route harness — net-new coverage for that gate's ordinary-RBAC branch
 * composed with a REAL `ManagementGroupStore` through `AuthRoutes` (the
 * primitive, `RbacStore::check_scoped_permission`, is covered directly in
 * test_rbac_store.cpp, but no prior test drove it through this gate with
 * group-scoped confinement).
 *
 * HISTORY — the wiring-regression tripwire moved. Until #2542 PR-4, the
 * three route handlers were inline `web_server_->Get/Put/Delete` lambdas in
 * `ServerImpl` with no route-injection seam, so the primitive-level cases
 * above could not detect a wiring regression in the handlers themselves (a
 * future edit reverting one back to `require_permission`, or swapping the
 * regex capture index) — a real, disclosed limitation flagged independently
 * by both the adversarial review (Kimi/Codex) and a PR #3742 review
 * (Doomgoose). This file used to close that gap with a source-text tripwire
 * (the `test_body_cap_route_inventory.cpp` pattern, scoped down to these
 * three routes) that read `server.cpp` at test-run time. #2542 PR-4
 * extracted the three handlers onto the `HttpRouteSink` seam
 * (`custom_properties_routes.{hpp,cpp}`), which gives them a REAL
 * in-process dispatch path — `test_custom_properties_routes.cpp`'s gate-
 * pinning TEST_CASEs now prove the wiring behaviourally (dispatch a denied
 * request, assert 403/the right securable+operation+agent_id) instead of by
 * scanning source text, so the text-scan tripwire here was deleted rather
 * than repointed at the new file: a real dispatch is strictly stronger
 * evidence than a regex over source, and the old approach would in any case
 * have needed to scan a different file post-move.
 */

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"  // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <string>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

httplib::Request bearer_request(const std::string& token) {
    httplib::Request req;
    req.headers.emplace("Authorization", "Bearer " + token);
    return req;
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Distinct template name from every other file's "rbacstore*" registrations
// (test_authz_gates.cpp's "rbacstore_authzgates", test_list_read_confinement.cpp's
// "rbacstore") — same registry, no shared-state risk.
yuzu::test::PgTestTemplate rbac_props_scope_tpl{
    "rbacstore_propsscope", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac (props scope) template: store failed to migrate/seed");
    }};

/// Minimal rig for `require_scoped_permission("Infrastructure", ...)`: real
/// RbacStorePg + ManagementGroupStorePg + AuthRoutes wired exactly as
/// ServerImpl wires it. Tree mirrors test_authz_gates.cpp's GatesRig:
///   P ─── C1        S   (P and S are roots; C1 is a child of P)
/// a_c1 is reachable from a P-scoped grant (ancestor-aware); a_s is not.
struct PropsScopeRig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    // Real AuditStore (not nullptr) so a denial-path audit_log call is
    // regression-testable — mirrors GatesRig's rationale in
    // test_authz_gates.cpp (governance Gate 8 re-review, cc93f499c arg-order
    // bug had zero coverage until a real store was wired in). Shares the rbac
    // clone's database via a second pool, its own `audit_store` schema.
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;
    std::string gP, gC1, gS;

    explicit PropsScopeRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(audit_store.is_open());
        rbac.set_rbac_enabled(true); // enforcement in effect, not legacy-open

        REQUIRE(rbac.create_role({"InfraReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"InfraReader", "Infrastructure", "Read", "allow"})
                    .has_value());
        REQUIRE(rbac.create_role({"InfraWriter", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"InfraWriter", "Infrastructure", "Write", "allow"})
                    .has_value());

        gP = make_group("P", "");
        gC1 = make_group("C1", gP);
        gS = make_group("S", "");

        REQUIRE(mgmt.add_member(gP, "a_p").has_value());
        REQUIRE(mgmt.add_member(gC1, "a_c1").has_value());
        REQUIRE(mgmt.add_member(gS, "a_s").has_value());

        REQUIRE(auth_mgr.upsert_user("operator", "correct-horse-battery-staple",
                                     auth::Role::admin));

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &mgmt,
                                          /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    std::string make_group(const std::string& name, const std::string& parent) {
        ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.parent_id = parent;
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }

    void group_assign(const std::string& group, const std::string& user,
                      const std::string& role) {
        REQUIRE(mgmt.assign_role({group, "user", user, role}).has_value());
    }

    std::string mint(const std::string& user = "operator") {
        auto raw = api_tokens->create_token("props-scope-test", user, now_epoch() + 3600);
        REQUIRE(raw.has_value());
        return *raw;
    }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// #3700 acceptance criterion: a confined caller must not read or write
// custom-properties for an out-of-scope agent.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("require_scoped_permission(Infrastructure,Read): group-confined operator "
          "admitted on an in-scope agent",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraReader");
    auto req = bearer_request(r.mint());
    httplib::Response res;

    CHECK(r.ar->require_scoped_permission(req, res, "Infrastructure", "Read", "a_c1"));
}

TEST_CASE("require_scoped_permission(Infrastructure,Read): group-confined operator "
          "denied on an out-of-scope agent",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraReader");
    auto req = bearer_request(r.mint());
    httplib::Response res;

    CHECK_FALSE(r.ar->require_scoped_permission(req, res, "Infrastructure", "Read", "a_s"));
    CHECK(res.status == 403);

    // A real denial audit row IS written (was unverifiable with the
    // nullptr audit_store the first version of this rig used). NOT
    // asserting target_type/target_id field placement here: the ordinary-
    // RBAC denial branch (auth_routes.cpp ~:1124) passes agent_id
    // positionally into the audit_log wrapper's target_type slot and its
    // reason string into target_id, leaving detail empty -- the same
    // slot-swap class cc93f499c fixed for confine_agent_target, but this
    // call site was never fixed. Pre-existing, not touched by #3700's
    // diff (auth_routes.cpp is unmodified here) -- tracked as issue #3219
    // rather than asserted (right or wrong) by this test.
    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].action == "auth.scoped_permission_required");
    CHECK((*rows)[0].result == "denied");
}

TEST_CASE("require_scoped_permission(Infrastructure,Write): group-confined operator "
          "denied on an out-of-scope agent (the WRITE path #3700 flags as higher risk)",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraWriter");
    auto req = bearer_request(r.mint());
    httplib::Response res;

    CHECK_FALSE(r.ar->require_scoped_permission(req, res, "Infrastructure", "Write", "a_s"));
    CHECK(res.status == 403);
}

TEST_CASE("require_scoped_permission(Infrastructure,Write): group-confined operator "
          "admitted on an in-scope agent",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraWriter");
    auto req = bearer_request(r.mint());
    httplib::Response res;

    CHECK(r.ar->require_scoped_permission(req, res, "Infrastructure", "Write", "a_c1"));
}

TEST_CASE("require_scoped_permission(Infrastructure,Write): a GLOBAL grant holder is "
          "admitted on every agent (no behaviour change for unconfined operators)",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "operator", "InfraWriter"}).has_value()); // GLOBAL allow
    auto req = bearer_request(r.mint());
    httplib::Response res;

    CHECK(r.ar->require_scoped_permission(req, res, "Infrastructure", "Write", "a_s"));
    CHECK(r.ar->require_scoped_permission(req, res, "Infrastructure", "Write", "a_p"));
}

TEST_CASE("require_scoped_permission(Infrastructure,Read): RBAC disabled — legacy "
          "fallback is unchanged (Infrastructure is not topology-floored)",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false);
    REQUIRE(r.auth_mgr.upsert_user("plain_user", "correct-horse-battery-staple",
                                   auth::Role::user));
    auto req = bearer_request(r.mint("plain_user"));
    httplib::Response res;

    // Legacy Read is any-authenticated-user — same as require_permission's
    // legacy branch, so RBAC-off deployments see no behaviour change.
    CHECK(r.ar->require_scoped_permission(req, res, "Infrastructure", "Read", "a_s"));
}

TEST_CASE("require_scoped_permission(Infrastructure,Write): RBAC disabled — legacy "
          "fallback requires admin, matching require_permission's legacy branch",
          "[pg][auth_routes][authz_gates][properties_authz]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false);
    REQUIRE(r.auth_mgr.upsert_user("plain_user", "correct-horse-battery-staple",
                                   auth::Role::user));
    auto req = bearer_request(r.mint("plain_user"));
    httplib::Response res;

    CHECK_FALSE(r.ar->require_scoped_permission(req, res, "Infrastructure", "Write", "a_s"));
    CHECK(res.status == 403);
}

// The former source-text wiring-regression tripwire (a scan of server.cpp
// pinning that these three handlers call require_scoped_permission, not
// require_permission) lived here through #2542 PR-4. It is now
// test_custom_properties_routes.cpp's real TestRouteSink dispatch coverage
// — see this file's header comment (HISTORY) for why a behavioural test
// replaced it outright rather than being repointed at the new file.
