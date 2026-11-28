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
#include "dashboard_routes.hpp" // the #2532 acceptance case drives the Echo purge fragment
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp" // PgConn/PgResult for the mid-flight mgmt-store degrade injection
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"  // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

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
    // The typed call is the same gate's one body: the verdict as a class.
    httplib::Response typed;
    CHECK(r.ar->require_scoped_permission_outcome(req, typed, "Infrastructure", "Read", "a_c1") ==
          ScopedGateOutcome::Admitted);
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

    // A real denial audit row IS written (was unverifiable with the nullptr audit_store the
    // first version of this rig used). #3739 also pins the field placement: the reason is in
    // `detail`, the agent is `target_type="Agent"` / `target_id=<id>` (the call site used to
    // pass the id and the reason positionally into target_type/target_id, #3219).
    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].action == "auth.scoped_permission_required");
    CHECK((*rows)[0].result == "denied");
    CHECK((*rows)[0].target_type == "Agent");
    CHECK((*rows)[0].target_id == "a_s");
    // A genuine no-grant: the plain "denied" form, NOT the degraded one.
    CHECK((*rows)[0].detail == "RBAC denied Infrastructure:Read");

    // The typed call answers the same refusal as the class Denied (not a degraded read): the
    // same 403, and the audit row it writes carries no `read degraded` token. The Boolean gate
    // agrees with `== Admitted`.
    httplib::Response typed;
    CHECK(r.ar->require_scoped_permission_outcome(req, typed, "Infrastructure", "Read", "a_s") ==
          ScopedGateOutcome::Denied);
    CHECK(typed.status == 403);
    auto after = r.audit_store.query({});
    REQUIRE(after.has_value());
    REQUIRE(after->size() == 2);
    for (const auto& row : *after)
        CHECK(row.detail == "RBAC denied Infrastructure:Read");

    // A request with no credentials is refused by authentication, as the class Unauthenticated.
    httplib::Request anonymous;
    httplib::Response unauthenticated;
    CHECK(r.ar->require_scoped_permission_outcome(anonymous, unauthenticated, "Infrastructure",
                                                  "Read", "a_c1") ==
          ScopedGateOutcome::Unauthenticated);
    CHECK(unauthenticated.status == 401);
    httplib::Response unauthenticated_bool;
    CHECK_FALSE(r.ar->require_scoped_permission(anonymous, unauthenticated_bool, "Infrastructure",
                                                "Read", "a_c1"));
}

// #3739 acceptance: a denial caused by a management-group store degrade is distinguishable in
// the audit row from a genuine no-grant denial. Same principal, same agent, same grant -- the
// only change between the allow and the deny is the injected fault.
TEST_CASE("require_scoped_permission: a mgmt-group store degrade is audited as degraded, "
          "not as a genuine no-grant denial (#3739)",
          "[pg][auth_routes][authz_gates][properties_authz][degrade]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraReader");
    auto req = bearer_request(r.mint());

    // Healthy baseline: the in-scope agent IS admitted, so the denial below is attributable to
    // the fault and not to an absent grant. (An allow writes no audit row.)
    {
        httplib::Response ok;
        REQUIRE(r.ar->require_scoped_permission(req, ok, "Infrastructure", "Read", "a_c1"));
    }

    // Isolate the fault to the management-group store only; RBAC itself stays healthy.
    {
        yuzu::server::pg::PgConn c{PQconnectdb(r.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult dr{PQexec(
            c.get(), "DROP TABLE management_group_store.management_group_members CASCADE")};
        REQUIRE(dr.ok());
    }

    httplib::Response res;
    CHECK_FALSE(r.ar->require_scoped_permission(req, res, "Infrastructure", "Read", "a_c1"));
    CHECK(res.status == 403); // still the fail-closed 403 (ADR-0041), not a 503

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].action == "auth.scoped_permission_required");
    CHECK((*rows)[0].result == "denied");
    CHECK((*rows)[0].target_type == "Agent");
    CHECK((*rows)[0].target_id == "a_c1");
    CHECK((*rows)[0].detail ==
          "RBAC denied Infrastructure:Read (read degraded: mgmt_group_store)");

    // The class carries the same store label as the row: a typed caller learns a read failed,
    // and which store, from the gate itself. Same 403, and the Boolean gate never admits it.
    httplib::Response typed;
    CHECK(r.ar->require_scoped_permission_outcome(req, typed, "Infrastructure", "Read", "a_c1") ==
          ScopedGateOutcome::MgmtGroupReadDegraded);
    CHECK(typed.status == 403);
    httplib::Response boolean_res;
    CHECK_FALSE(r.ar->require_scoped_permission(req, boolean_res, "Infrastructure", "Read", "a_c1"));
}

// Same chaos scenario through the OTHER mgmt-store source: the assignments read
// (`management_group_roles`) fails FIRST in a real management-group outage, before the member
// and ancestor reads are reached. It must be labelled as the management-group store too.
TEST_CASE("require_scoped_permission: a mgmt-group ASSIGNMENTS-read degrade is labelled "
          "mgmt_group_store, not rbac_store (#3739)",
          "[pg][auth_routes][authz_gates][properties_authz][degrade]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraReader");
    auto req = bearer_request(r.mint());
    {
        httplib::Response ok;
        REQUIRE(r.ar->require_scoped_permission(req, ok, "Infrastructure", "Read", "a_c1"));
    }
    {
        yuzu::server::pg::PgConn c{PQconnectdb(r.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult dr{PQexec(
            c.get(), "DROP TABLE management_group_store.management_group_roles CASCADE")};
        REQUIRE(dr.ok());
    }

    httplib::Response res;
    CHECK_FALSE(r.ar->require_scoped_permission(req, res, "Infrastructure", "Read", "a_c1"));
    CHECK(res.status == 403);

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].action == "auth.scoped_permission_required");
    CHECK((*rows)[0].detail ==
          "RBAC denied Infrastructure:Read (read degraded: mgmt_group_store)");

    httplib::Response typed;
    CHECK(r.ar->require_scoped_permission_outcome(req, typed, "Infrastructure", "Read", "a_c1") ==
          ScopedGateOutcome::MgmtGroupReadDegraded);
    CHECK(typed.status == 403);
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

// ═══════════════════════════════════════════════════════════════════════════
// #2532: the gate reports WHY it refused, as a class, so a caller that must tell a denial from an
// outage never reads a status or a second store. No status, body or audit row changes.
// ═══════════════════════════════════════════════════════════════════════════

// The RBAC store's own read failing is the other degrade class. Same principal, same grant: only
// the injected fault differs from the admitted case above. There is deliberately NO healthy gate
// call for this pair before the fault: a warm permission cache would answer the global read and
// the failure would never be reached.
TEST_CASE("require_scoped_permission: an RBAC-store read degrade is the class RbacReadDegraded and "
          "is audited rbac_store (#2532)",
          "[pg][auth_routes][authz_gates][properties_authz][degrade][2532]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "operator", "InfraReader");
    auto req = bearer_request(r.mint());

    {
        yuzu::server::pg::PgConn c{PQconnectdb(rbac_db_.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult dr{
            PQexec(c.get(), "DROP TABLE rbac_store.role_permissions CASCADE")};
        REQUIRE(dr.ok());
    }

    httplib::Response res;
    CHECK(r.ar->require_scoped_permission_outcome(req, res, "Infrastructure", "Read", "a_c1") ==
          ScopedGateOutcome::RbacReadDegraded);
    CHECK(res.status == 403); // still the fail-closed 403 (ADR-0041), not a 503

    // The Boolean gate never admits a degraded read either.
    httplib::Response boolean_res;
    CHECK_FALSE(r.ar->require_scoped_permission(req, boolean_res, "Infrastructure", "Read", "a_c1"));

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    for (const auto& row : *rows) {
        CHECK(row.action == "auth.scoped_permission_required");
        CHECK(row.target_id == "a_c1");
        CHECK(row.detail == "RBAC denied Infrastructure:Read (read degraded: rbac_store)");
    }
}

// Acceptance criterion: a management-group read failure behind the Echo purge is reported as an
// outage (503, recorded store_unavailable), where it used to collapse into the 404 that an
// out-of-scope device gets (recorded scope_violation). The REAL gate over REAL stores, through
// the real route; only the dispatch is a counter.
TEST_CASE("Echo purge fragment: a real management-group read failure through the real gate answers "
          "503 and is recorded store_unavailable; an out-of-scope device is still the 404 "
          "scope_violation (#2532)",
          "[pg][auth_routes][authz_gates][properties_authz][degrade][2532]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_props_scope_tpl);
    PropsScopeRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.create_role({"InfraPurger", "", false, 0}).has_value());
    REQUIRE(r.rbac.set_permission({"InfraPurger", "Infrastructure", "Delete", "allow"}).has_value());
    r.group_assign(r.gP, "operator", "InfraPurger"); // a_c1 is in P's subtree; a_s is not

    // Declared AFTER the rig, in this order so the destruction order is safe: `sink` is destroyed
    // first, while the `DashboardRoutes` whose `this` its handlers captured is still alive, and the
    // recorders outlive both.
    struct DashboardRow {
        std::string action, result, detail;
    };
    yuzu::MetricsRegistry metrics;
    std::vector<DashboardRow> dashboard_rows;
    int dispatches = 0;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    auto auth_fn = [](const httplib::Request&,
                      httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "operator";
        s.role = auth::Role::admin;
        s.auth_source = "local";
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    // ONE recording sink behind both callbacks, as production wires one `audit_log` behind both.
    auto audit_fn = [&dashboard_rows](const httplib::Request&, const std::string& action,
                                      const std::string& result, const std::string&,
                                      const std::string&, const std::string& detail) {
        dashboard_rows.push_back({action, result, detail});
        return true;
    };
    routes.set_persist_audit_fn(audit_fn);
    // The call server.cpp's `scoped_gate_fn` makes.
    routes.set_scoped_perm_fn([&r](const httplib::Request& req, httplib::Response& res,
                                   const std::string& type, const std::string& op,
                                   const std::string& agent) {
        return r.ar->require_scoped_permission_outcome(req, res, type, op, agent);
    });
    DashboardRoutes::DispatchFn dispatch =
        [&dispatches](const std::string&, const std::string&, const std::vector<std::string>&,
                      const std::string&, const std::unordered_map<std::string, std::string>&,
                      const yuzu::server::DispatchCaller&) -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatches;
        return {.sent = 1, .command_id = "cmd-1"};
    };
    routes.register_routes(
        sink, auth_fn, perm_fn, audit_fn, /*response_store=*/nullptr, &r.mgmt, /*registry=*/nullptr,
        /*tag_store=*/nullptr, /*event_bus=*/nullptr,
        /*agents_json_fn=*/[] { return std::string{"[]"}; }, dispatch,
        /*caller_fn=*/
        [](const httplib::Request&) -> yuzu::server::DispatchCaller {
            return yuzu::server::DispatchCaller{.exec_visible = yuzu::server::authz::VisibleSet{}};
        },
        /*resolve_fn=*/[](const std::string&) { return std::pair<std::string, std::string>{}; },
        &metrics, /*instruction_store=*/nullptr);

    const std::string token = r.mint();
    const auto post = [&](const std::string& body) {
        auto res = sink.dispatch("POST", "/fragments/echo/retention-paused/purge", body,
                                 "application/x-www-form-urlencoded",
                                 {{"Host", "yuzu.example:8080"},
                                  {"Origin", "https://yuzu.example:8080"},
                                  {"Authorization", "Bearer " + token}});
        REQUIRE(res != nullptr);
        return res;
    };
    const auto rows_with = [&dashboard_rows](const std::string& result) {
        std::vector<DashboardRow> out;
        for (const auto& row : dashboard_rows)
            if (row.action == "echo.source.purge" && row.result == result)
                out.push_back(row);
        return out;
    };
    const auto series = [&metrics](const char* result) {
        return metrics
            .counter("yuzu_echo_source_purge_total", {{"result", result}, {"surface", "dashboard"}})
            .value();
    };
    constexpr const char* kNotReachable = "<span class=\"echo-row-error\">Agent not reachable.</span>";

    // (1) Healthy: the operator holds Infrastructure:Delete on group P, a_c1 is under it.
    CHECK(post("device_id=a_c1&source=tcp")->status == 200);
    CHECK(dispatches == 1);
    CHECK(rows_with("attempted").size() == 1);

    // (2) A device outside the grant: the real gate denies; the route collapses it to the 404 and
    // records the real reason as a scope violation.
    {
        auto res = post("device_id=a_s&source=process");
        CHECK(res->status == 404);
        CHECK(res->body == kNotReachable);
        const auto failures = rows_with("failure");
        REQUIRE(failures.size() == 1);
        CHECK(failures[0].detail == "scope_violation source=process");
        CHECK(series("scope_violation") == 1.0);
        CHECK(dispatches == 1);
    }

    // (3) The management-group member table fails under the live store.
    {
        yuzu::server::pg::PgConn c{PQconnectdb(r.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult dr{PQexec(
            c.get(), "DROP TABLE management_group_store.management_group_members CASCADE")};
        REQUIRE(dr.ok());
    }

    // (4) The same in-scope device now answers 503, not the 404, and is recorded as the outage it
    // is. Nothing is dispatched and no scope violation is recorded.
    {
        auto res = post("device_id=a_c1&source=process");
        CHECK(res->status == 503);
        CHECK_FALSE(res->get_header_value("HX-Trigger").empty()); // the error toast
        CHECK(res->body != kNotReachable);

        const auto denied = rows_with("denied");
        REQUIRE(denied.size() == 1);
        CHECK(denied[0].detail == "store_unavailable store=mgmt_group_store source=process");
        CHECK(rows_with("failure").size() == 1);   // still step (2)'s scope violation only
        CHECK(rows_with("attempted").size() == 1); // still step (1)'s
        CHECK(series("store_unavailable") == 1.0);
        CHECK(series("scope_violation") == 1.0);
        CHECK(dispatches == 1);

        // The gate's own row carries the same store label (one row for this device: the healthy
        // admissions write none).
        auto audit_rows = r.audit_store.query({});
        REQUIRE(audit_rows.has_value());
        int for_device = 0;
        for (const auto& row : *audit_rows) {
            if (row.action == "auth.scoped_permission_required" && row.target_id == "a_c1") {
                ++for_device;
                CHECK(row.detail ==
                      "RBAC denied Infrastructure:Delete (read degraded: mgmt_group_store)");
            }
        }
        CHECK(for_device == 1);
    }
}
