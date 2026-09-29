/**
 * test_authz_gates.cpp — Unit tests for the service-scope-confinement Phase 0
 * primitives: `AuthRoutes::require_fleet_read` / `confine_agent_target`
 * (authz_gates.hpp/.cpp).
 *
 * PR 2 of the durable service-scope-confinement fix
 * (.claude/plans/service-scope-confinement-review-2026-08-16.md,
 * .claude/plans/handover-written-to-claude-plans-guardia-piped-owl.md §2c/§2d):
 * these gates are wired here but called by NO route yet — zero behavior
 * change. This file is the net-new coverage implementation-plan §2d calls
 * out: no existing test drove a service-scoped token through the AuthRoutes
 * gates with RBAC enabled AND a real tag store.
 */

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "authz_gates.hpp"
#include "service_scope_policy.hpp"

#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp"  // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

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

// Drop the tags table out from under a live TagStore so its next read fails
// deterministically — same degrade injection as test_rest_tag_routes.cpp /
// test_tag_store.cpp (ADR-0050). On PG this replaces BOTH of the SQLite
// mechanisms this file used pre-migration (authorizer prepare-deny and
// progress-handler mid-scan interrupt): libpq returns one status-checked
// PGresult per query, so prepare-time vs mid-scan failure is not a
// distinction the store can observe — any query failure is the single
// degraded case, TagReadError::kDegraded.
void drop_tags_table(const std::string& dsn) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
    REQUIRE(r.ok());
}

// Distinct template name from every other file's "rbacstore*" registrations
// (test_list_read_confinement.cpp's "rbacstore", test_engine_principal_
// integration.cpp's "rbacstore_integ") — same registry, no shared-state risk.
yuzu::test::PgTestTemplate rbac_gates_tpl{
    "rbacstore_authzgates", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac (authz_gates) template: store failed to migrate/seed");
        TagStore tags{pool};
        if (!tags.is_open())
            throw std::runtime_error("rbac (authz_gates) template: tag store failed to migrate");
    }};

/// Full-stack rig: real RbacStorePg + real ManagementGroupStorePg + real
/// ApiTokenStorePg + a PG TagStore (ADR-0050, sharing the rbac clone's
/// database — its own `tag_store` schema, no conflict), wired into a real
/// AuthRoutes exactly as ServerImpl wires it (auth_routes.hpp:73-78).
///
/// Management-group tree (mirrors test_list_read_confinement.cpp's Rig):
///   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
///      └─ C2
/// Members: a_p∈P, a_c1∈C1, a_c2∈C2, a_s∈S. Tag store: "printers" service ==
/// {a_p, a_c1, a_s} — overlaps P's subtree AND crosses into S, so
/// intersecting mgmt-scope against it is a REAL narrowing, not a no-op.
struct GatesRig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    TagStore tags;
    // Shares the rbac database via a second pool (its own `audit_store`
    // schema, no conflict) — same pattern as test_rest_api_tokens.cpp's
    // CSPRNG-failure audit test. Real AuditStore, not nullptr, so denial
    // paths' audit_log calls are regression-testable (quality-engineer,
    // governance Gate 8 re-review 2026-08-17: the cc93f499c arg-order bug
    // this fixed had zero coverage until this rig wired one in).
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;
    std::string gP, gC1, gC2, gS;

    explicit GatesRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, tags{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(audit_store.is_open());
        rbac.set_rbac_enabled(true); // enforcement in effect, not legacy-open

        REQUIRE(rbac.create_role({"RespReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespReader", "Response", "Read", "allow"}).has_value());
        REQUIRE(rbac.create_role({"RespDenier", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespDenier", "Response", "Read", "deny"}).has_value());

        gP = make_group("P", "");
        gC1 = make_group("C1", gP);
        gC2 = make_group("C2", gP);
        gS = make_group("S", "");

        REQUIRE(mgmt.add_member(gP, "a_p").has_value());
        REQUIRE(mgmt.add_member(gC1, "a_c1").has_value());
        REQUIRE(mgmt.add_member(gC2, "a_c2").has_value());
        REQUIRE(mgmt.add_member(gS, "a_s").has_value());

        REQUIRE(tags.set_tag("a_p", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_c1", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_s", "service", "printers").has_value());
        // a_c2 deliberately untagged: inside mgmt scope, outside service scope.

        REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &mgmt, &tags,
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

    void group_assign(const std::string& group, const std::string& user, const std::string& role) {
        REQUIRE(mgmt.assign_role({group, "user", user, role}).has_value());
    }

    /// Mint a token as "minter" — scope_service empty ⇒ a non-service token.
    std::string mint(const std::string& scope_service = {}) {
        auto raw =
            api_tokens->create_token("gates-test", "minter", now_epoch() + 3600, scope_service);
        REQUIRE(raw.has_value());
        return *raw;
    }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// require_fleet_read — the six composition cells (implementation plan §2d):
// three mgmt decisions {Deny, AdmitAll, AdmitScoped-M} × service {absent, S}.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("require_fleet_read: Deny × absent service ⇒ Forbidden",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    // "minter" holds no Response:Read grant at all ⇒ authorize_list_read DenyAll.
    auto token = r.mint(); // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
}

TEST_CASE("require_fleet_read: null management-group store ⇒ Degraded, never a "
          "permanent-looking Forbidden",
          "[pg][auth_routes][authz_gates][service_scope]") {
    // Same "no grant at all" caller shape as the sibling Deny test above, but
    // with mgmt_group_store_=nullptr — rbac_store_/tag_store_ each get an
    // explicit pre-check (line ~117/196) that turns "store unavailable" into
    // 503 Degraded before a real authorization decision is even attempted;
    // this axis had none, so a null store silently fell through into
    // authorize_list_read -> resolve_perm_groups, which itself already
    // null-checks mgmt_store and returns unexpected("management group store
    // unavailable") -> DenyAll -> a 403 indistinguishable from "you genuinely
    // have no grant" (unhappy-path finding UP-1, governance run 2026-08-20).
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePg api_tokens;
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    PgPool pool{{.conninfo = rbac_db_.dsn(), .size = 4}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));

    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr,
                  /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    auto raw = api_tokens->create_token("gates-test", "minter", now_epoch() + 3600);
    REQUIRE(raw.has_value());
    auto req = bearer_request(*raw);
    httplib::Response res;

    auto result = ar.require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Degraded);
    CHECK(res.status == 503);
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == 5000);
}

TEST_CASE("require_fleet_read: Deny × service S ⇒ Forbidden (mgmt axis is decisive)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
}

TEST_CASE("require_fleet_read: AdmitAll × absent service ⇒ unfiltered "
          "(byte-identical regression: authorize_list_read alone)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value()); // GLOBAL allow
    auto token = r.mint();                                                     // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered());
}

TEST_CASE("require_fleet_read: AdmitAll × service S ⇒ scoped to S "
          "(the never-unfiltered CDX-001 property, list-read side)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value()); // GLOBAL allow
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK_FALSE(result->unfiltered()); // never unfiltered, DESPITE the global grant
    CHECK(result->in_scope("a_p"));
    CHECK(result->in_scope("a_c1"));
    CHECK(result->in_scope("a_s"));
    CHECK_FALSE(result->in_scope("a_c2")); // untagged — outside the service axis
}

TEST_CASE("require_fleet_read: AdmitScoped-M × absent service ⇒ mgmt scope alone "
          "(byte-identical regression: authorize_list_read alone)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "minter", "RespReader"); // group allow ⇒ AdmitScoped(P's subtree)
    auto token = r.mint();                        // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK_FALSE(result->unfiltered());
    CHECK(result->in_scope("a_p"));
    CHECK(result->in_scope("a_c1"));
    CHECK(result->in_scope("a_c2")); // INV-4 descendant-ward expansion
    CHECK_FALSE(result->in_scope("a_s"));

    // Pin against the raw authorize_list_read call: identical visible set.
    auto raw = r.rbac.authorize_list_read("minter", "Response", "Read", &r.mgmt);
    REQUIRE(raw.decision == ListReadDecision::AdmitScoped);
    for (const auto& id : raw.visible_agents)
        CHECK(result->in_scope(id));
}

TEST_CASE("require_fleet_read: AdmitScoped-M × service S ⇒ real intersection, "
          "narrower than either axis alone",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "minter", "RespReader"); // AdmitScoped({a_p,a_c1,a_c2})
    auto token = r.mint("printers");              // service S = {a_p,a_c1,a_s}
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK_FALSE(result->unfiltered());
    CHECK(result->in_scope("a_p"));        // in both
    CHECK(result->in_scope("a_c1"));       // in both
    CHECK_FALSE(result->in_scope("a_c2")); // mgmt-only, dropped by the service axis
    CHECK_FALSE(result->in_scope("a_s"));  // service-only, dropped by the mgmt axis

    const std::vector<std::string> requested{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = result->filter(requested);
    CHECK(filtered.size() == 2);
    CHECK(contains(filtered, "a_p"));
    CHECK(contains(filtered, "a_c1"));
}

TEST_CASE("require_fleet_read: documented pairing — require_permission-then-this-gate is "
          "the wrong sequence and denies a mgmt-scoped-only caller; this gate alone admits them",
          "[pg][auth_routes][authz_gates][service_scope]") {
    // Falsifier for the BLOCKING finding fjarvis's review caught (2026-08-17,
    // PR #3216): the doc comment on require_fleet_read used to instruct
    // callers to pair it with require_permission for the same
    // (securable_type, operation). require_permission's ordinary RBAC branch
    // decides on RbacStore::check_permission ALONE — no mgmt_group_store_ —
    // so a caller whose only grant is management-group-scoped is rejected by
    // require_permission before ever reaching require_fleet_read's own
    // authorize_list_read call, making the AdmitScoped branch unreachable
    // for exactly the confined reader ADR-0017 exists to serve. The doc
    // comment is now corrected to say the opposite (do NOT pair with
    // require_permission — this gate is self-sufficient for that axis).
    // This test pins both halves of that correction as executable facts.
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "minter", "RespReader"); // ONLY a group-scoped grant — no global grant
    auto token = r.mint();                        // non-service
    auto req_a = bearer_request(token);
    httplib::Response res_a;

    // The OLD documented (broken) sequence: require_permission first.
    bool old_sequence_admitted = r.ar->require_permission(req_a, res_a, "Response", "Read");
    CHECK_FALSE(old_sequence_admitted); // denied — the finding, demonstrated
    CHECK(res_a.status == 403);

    // The CORRECTED sequence: require_fleet_read alone, no require_permission
    // in front of or behind it. Same caller, same grant, fresh request/response.
    auto req_b = bearer_request(token);
    httplib::Response res_b;
    auto result = r.ar->require_fleet_read(req_b, res_b, "Response", "Read");
    REQUIRE(result.has_value()); // admitted — the gate is self-sufficient
    CHECK_FALSE(result->unfiltered());
    CHECK(result->in_scope("a_p"));       // exactly this group's witness
    CHECK_FALSE(result->in_scope("a_s")); // NOT the whole fleet — a_s is outside group P
}

// ── Caller-class ladder (#3290 D1 — elevated/mcp_tier; engine coverage lives
// in test_engine_principal_integration.cpp §6c, alongside require_permission/
// require_list_read's own engine-branch tests) ──────────────────────────────

TEST_CASE("require_fleet_read: non-Read operation ⇒ Forbidden (structurally "
          "Read-only, mirrors require_list_read)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value()); // GLOBAL allow
    auto token = r.mint();                                                    // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    // Even a global RBAC grant does not admit a non-Read operation through
    // this gate — the legacy-open AdmitAll branch never applies to a
    // mutation here.
    auto result = r.ar->require_fleet_read(req, res, "Response", "Write");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
}

TEST_CASE("require_fleet_read: JIT-elevated non-service session ⇒ TOP, no "
          "underlying RBAC grant needed (the #3038 regression class)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    // "minter" holds NO Response:Read grant of any kind — elevation alone
    // must still admit, and require_fleet_read must NOT call
    // authorize_list_read for an elevated session (which would deny a
    // grant-less caller).
    auto cookie_token = r.auth_mgr.create_local_session("minter", auth::Role::user,
                                                        /*mfa_verified=*/true);
    REQUIRE(r.auth_mgr.elevate_session(cookie_token, std::chrono::seconds(300)).has_value());
    httplib::Request req;
    req.headers.emplace("Cookie", "yuzu_session=" + cookie_token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered()); // TOP — elevation alone, no meet(mgmt, service)
}

TEST_CASE("require_fleet_read: mcp_tier='readonly' token, Read op ⇒ tier "
          "falls through to the RBAC axis (does not itself deny a tier that "
          "allows Read)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value()); // GLOBAL allow
    auto raw = r.api_tokens->create_token("gates-test-tier", "minter", now_epoch() + 3600,
                                          /*scope_service=*/"", /*mcp_tier=*/"readonly");
    REQUIRE(raw.has_value());
    auto req = bearer_request(*raw);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered());
}

// ── Degradation and store-unavailable failure modes ─────────────────────────

TEST_CASE("require_fleet_read: null tag store on a service token ⇒ Degraded",
          "[pg][auth_routes][authz_gates][service_scope]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePg api_tokens;
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    PgPool pool{{.conninfo = rbac_db_.dsn(), .size = 4}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.create_role({"RespReader", "", false, 0}).has_value());
    REQUIRE(rbac.set_permission({"RespReader", "Response", "Read", "allow"}).has_value());
    REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
    REQUIRE(rbac.assign_role({"user", "minter", "RespReader"}).has_value());

    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr,
                  /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    auto raw = api_tokens->create_token("gates-test", "minter", now_epoch() + 3600, "printers");
    REQUIRE(raw.has_value());
    auto req = bearer_request(*raw);
    httplib::Response res;

    auto result = ar.require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Degraded);
    CHECK(res.status == 503);
}

TEST_CASE("require_fleet_read: degraded tag-store read on a service token ⇒ Degraded, "
          "never a partial admit",
          "[pg][auth_routes][authz_gates][service_scope]") {
    // Pre-ADR-0050 this was TWO tests, exercising SQLite's prepare-deny and
    // mid-scan-interrupt failure paths separately. The PG TagStore has no
    // such split to test — agents_with_tag issues one query and checks one
    // PGresult status, so a partial row set is structurally unobservable and
    // every read failure is the single kDegraded case this test injects.
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value());
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    drop_tags_table(rbac_db_.dsn());

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Degraded);
    CHECK(res.status == 503);
}

TEST_CASE("require_fleet_read: genuinely empty service set ⇒ admitted-empty witness, "
          "not denied (present-empty != degraded)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "RespReader"}).has_value()); // AdmitAll
    auto token = r.mint("no-such-service"); // no agent carries this tag value
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value()); // present, not an error — a real answer, not a degradation
    CHECK_FALSE(result->unfiltered());
    CHECK_FALSE(result->in_scope("a_p"));
    CHECK_FALSE(result->in_scope("a_c1"));
    CHECK_FALSE(result->in_scope("a_s"));
}

TEST_CASE("require_fleet_read: null rbac store ⇒ Degraded (not a crash)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePg api_tokens; // hard PG dependency even though rbac_store is null
    REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, api_tokens.get(),
                  /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    auto raw = api_tokens->create_token("gates-test", "minter");
    REQUIRE(raw.has_value());
    auto req = bearer_request(*raw);
    httplib::Response res;

    auto result = ar.require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Degraded);
    CHECK(res.status == 503);
    // Pins the sibling-convention claim (the three "authorization store
    // unavailable" sites in auth_routes.cpp): same text, same status, plus
    // the retry_after_ms this specific branch adds.
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["message"].get<std::string>() == "authorization store unavailable");
    CHECK(j["error"]["retry_after_ms"].get<std::int64_t>() == 5000);
}

TEST_CASE("require_fleet_read: service-scoped token, RBAC genuinely disabled "
          "⇒ Forbidden (#2298 PR 3 decision 1 — preserve require_permission's "
          "hard-403, do not let the tag axis alone admit a narrowed result)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false); // genuinely, freshly disabled — denied before the mgmt
                                    // axis is even consulted, so no grant is needed here.
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
    CHECK(res.body.find("require RBAC to be enabled") != std::string::npos);
}

TEST_CASE("require_fleet_read: non-service token, RBAC genuinely disabled ⇒ "
          "unfiltered (regression — the new RBAC-off check is service-scoped "
          "only, legacy-open AdmitAll is untouched for an ordinary caller)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false);
    auto token = r.mint(); // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Response", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered());
}

TEST_CASE("require_fleet_read: RBAC genuinely disabled, floored securable (Enrollment:Read), "
          "non-admin session ⇒ Forbidden (#4031 topology-floor fix — closes the gap "
          "require_list_read's own doc comment warns a future floored-securable caller must "
          "close itself; GET /api/v1/enrollment/pending-agents is the first floored securable "
          "ever routed through this gate)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false);
    auto cookie_token =
        r.auth_mgr.create_local_session("minter", auth::Role::user, /*mfa_verified=*/true);
    httplib::Request req;
    req.headers.emplace("Cookie", "yuzu_session=" + cookie_token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Enrollment", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Forbidden);
    CHECK(res.status == 403);
    CHECK(res.body.find("admin role required") != std::string::npos);
}

TEST_CASE("require_fleet_read: RBAC genuinely disabled, floored securable (Enrollment:Read), "
          "admin session ⇒ unfiltered (the floor never blocks admin — parity with "
          "require_permission on the same pair)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    r.rbac.set_rbac_enabled(false);
    auto cookie_token =
        r.auth_mgr.create_local_session("minter", auth::Role::admin, /*mfa_verified=*/true);
    httplib::Request req;
    req.headers.emplace("Cookie", "yuzu_session=" + cookie_token);
    httplib::Response res;

    auto result = r.ar->require_fleet_read(req, res, "Enrollment", "Read");
    REQUIRE(result.has_value());
    CHECK(result->unfiltered());
}

TEST_CASE("require_fleet_read: no bearer token ⇒ Unauthenticated",
          "[pg][auth_routes][authz_gates][service_scope]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePg api_tokens;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, api_tokens.get(),
                  /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    httplib::Request req; // no Authorization header at all
    httplib::Response res;

    auto result = ar.require_fleet_read(req, res, "Response", "Read");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == authz::GateFailure::Unauthenticated);
    CHECK(res.status == 401);
}

// ═══════════════════════════════════════════════════════════════════════════
// confine_agent_target — confinement-axis-only gate (see the declaration's
// doc comment in auth_routes.hpp: it does not redo the ITServiceOwner check).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("confine_agent_target: empty agent_id ⇒ 400, never an admit",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    bool ok = r.ar->confine_agent_target(req, res, "Response", "Read", "");
    CHECK_FALSE(ok);
    CHECK(res.status == 400);
}

TEST_CASE("confine_agent_target: non-service session ⇒ true (axis is TOP)",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint(); // non-service
    auto req = bearer_request(token);
    httplib::Response res;

    // Even an agent with NO service tag at all is admitted — this gate does
    // not decide RBAC authority, only service-scope confinement, and a
    // non-service session has no such axis to confine on.
    CHECK(r.ar->confine_agent_target(req, res, "Response", "Read", "a_unknown"));
}

TEST_CASE("confine_agent_target: matching service tag ⇒ true", "[pg][auth_routes][authz_gates]"
                                                                 "[service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    CHECK(r.ar->confine_agent_target(req, res, "Response", "Read", "a_p"));
}

TEST_CASE("confine_agent_target: non-matching service tag ⇒ 403",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    // a_c2 is untagged — not in the "printers" service.
    bool ok = r.ar->confine_agent_target(req, res, "Response", "Read", "a_c2");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
}

TEST_CASE("confine_agent_target: denial audit row carries agent_id in target_id and the "
          "reason in detail, not swapped",
          "[pg][auth_routes][authz_gates][service_scope]") {
    // Regression test for cc93f499c: the three denial-path audit_log calls in
    // confine_agent_target originally omitted target_type, so agent_id
    // landed in that slot and the message landed in target_id, leaving
    // detail empty. GatesRig now wires a real AuditStore (previously
    // nullptr, so this was unverifiable — quality-engineer, governance
    // Gate 8 re-review 2026-08-17) to pin the correct field placement.
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    bool ok = r.ar->confine_agent_target(req, res, "Response", "Read", "a_c2");
    CHECK_FALSE(ok);

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& row = (*rows)[0];
    CHECK(row.action == "auth.agent_target_required");
    CHECK(row.result == "denied");
    CHECK(row.target_type == "Agent");
    CHECK(row.target_id == "a_c2"); // was landing in target_type pre-cc93f499c
    CHECK(row.detail.find("not in service") != std::string::npos); // was empty pre-cc93f499c
}

TEST_CASE("confine_agent_target: null tag store on a service token ⇒ 503",
          "[pg][auth_routes][authz_gates][service_scope]") {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePg api_tokens;
    REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, api_tokens.get(),
                  /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                  /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    auto raw = api_tokens->create_token("gates-test", "minter", now_epoch() + 3600, "printers");
    REQUIRE(raw.has_value());
    auto req = bearer_request(*raw);
    httplib::Response res;

    bool ok = ar.confine_agent_target(req, res, "Response", "Read", "a_p");
    CHECK_FALSE(ok);
    CHECK(res.status == 503);
}

TEST_CASE("confine_agent_target: degraded tag-store read on a service token ⇒ 503",
          "[pg][auth_routes][authz_gates][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_gates_tpl);
    GatesRig r{rbac_db_.dsn()};
    auto token = r.mint("printers");
    auto req = bearer_request(token);
    httplib::Response res;

    drop_tags_table(rbac_db_.dsn());

    bool ok = r.ar->confine_agent_target(req, res, "Response", "Read", "a_p");
    CHECK_FALSE(ok);
    CHECK(res.status == 503);
}

// ── service_scope_policy.hpp — compile coverage ─────────────────────────────
//
// No TU in this PR includes this header otherwise (it isn't wired to
// anything yet), so without this it has zero compile-time or runtime
// verification this round (architect, governance run 2026-08-17). A
// static_assert plus a runtime lookup tripwire the moment the first entry
// lands without a matching test update.

static_assert(yuzu::server::authz::kServiceScopeGlobalSafe.empty(),
              "kServiceScopeGlobalSafe must stay seeded empty until an entry clears the bar "
              "documented in service_scope_policy.hpp — if this fires, add a case here.");

TEST_CASE("service_scope_policy: service_scope_global_safe denies everything while the "
          "allow-list is empty",
          "[authz_gates][service_scope]") {
    using yuzu::server::authz::service_scope_global_safe;
    CHECK_FALSE(service_scope_global_safe("Response", "Read"));
    CHECK_FALSE(service_scope_global_safe("Execution", "Execute"));
    CHECK_FALSE(service_scope_global_safe("", ""));
}
