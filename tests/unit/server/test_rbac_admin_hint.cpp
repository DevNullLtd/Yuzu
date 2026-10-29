/**
 * test_rbac_admin_hint.cpp - `rbac_admin_hint` (rbac_admin_predicate.hpp), the advisory
 * tri-state the Users and roles page uses to decide whether to draw the Assign button and the
 * enforcement switch (#6034).
 *
 * Two layers:
 *   1. The ROUTE-LEVEL equality matrix, the empirical control that the hint equals the gate for
 *      every persona it models. The assign routes call the same two functions in the same
 *      order; the enforcement route applies the regime rule inside set_enforcement on a real
 *      transition, so its equality rests on this matrix. A change to the gate sequence of
 *      any of the three routes needs a matching row here. Per persona, the hint is computed
 *      from the same stores the routes read, then the
 *      REAL `POST /api/v1/rbac/roles/{name}/assignments` (plus `DELETE .../assignments/{id}`
 *      for two personas, and, for the personas that can reach a real transition,
 *      `PUT /api/v1/rbac/enforcement`) is called and its answer
 *      classified: 2xx / 400 / 409 = authority admitted (kMay), 403 = kMayNot, 503 = kUnconfirmed.
 *      The hint must equal that classification, and must not have written an audit row.
 *   2. The fold itself: structural denies need no store, a null or degraded store is
 *      kUnconfirmed, `RbacAdminSurface` has no default argument.
 *
 * PG-gated (RbacStore, AuthDB). Skips when YUZU_TEST_POSTGRES_DSN is unset; a skip is NOT a pass.
 */

#include "rbac_admin_predicate.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_rbac_admin_surface_harness.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <type_traits>

using namespace yuzu::server;

namespace {

/// What a real route answer says about the caller's authority. Anything outside the three
/// shapes is not an authority answer, so the test fails loudly rather than guessing. Two
/// statuses are NOT modelled and would misclassify: the unassign route's 403
/// `self_admin_unassign_blocked` (a refusal about the request, after the gates passed, which
/// would read as kMayNot; no persona here removes its own Administrator grant) and a 503 from
/// a store read after the gates passed (which would read as kUnconfirmed).
std::optional<RbacAdminHint> classify(int status) {
    if ((status >= 200 && status < 300) || status == 400 || status == 409)
        return RbacAdminHint::kMay; // the gates passed; the refusal (if any) is about the request
    if (status == 403)
        return RbacAdminHint::kMayNot;
    if (status == 503)
        return RbacAdminHint::kUnconfirmed;
    return std::nullopt;
}

const char* name_of(RbacAdminHint h) {
    switch (h) {
    case RbacAdminHint::kMay:
        return "kMay";
    case RbacAdminHint::kMayNot:
        return "kMayNot";
    case RbacAdminHint::kUnconfirmed:
        return "kUnconfirmed";
    }
    return "?";
}

RbacAdminHint hint_of(RbacRoleHarness& h) {
    return rbac_admin_hint(h.rest_session(), h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest);
}

/// The hint equals the real POST assign answer, and the hint wrote no audit row.
void check_assign(RbacRoleHarness& h, RbacAdminHint expected) {
    const auto audits_before = h.audit_log.size();
    const auto hint = hint_of(h);
    CHECK(h.audit_log.size() == audits_before); // the hint path is silent (#5792)
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);

    const auto res = h.assign_rest("Viewer", R"({"principal_type":"user","principal_id":"hint-target"})");
    REQUIRE(res);
    INFO("assign status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
}

/// The hint equals the real DELETE unassign answer. The target holds the grant first, so a
/// request that clears both gates succeeds (2xx) instead of answering 404, which is not an
/// authority answer and fails the classification loudly.
void check_unassign(RbacRoleHarness& h, RbacAdminHint expected) {
    REQUIRE(h.rbac->assign_role({"user", "hint-target", "Viewer"}).has_value());
    const auto audits_before = h.audit_log.size();
    const auto hint = hint_of(h);
    CHECK(h.audit_log.size() == audits_before); // the hint path is silent (#5792)
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);

    const auto res = h.unassign_rest("Viewer", "hint-target");
    REQUIRE(res);
    INFO("unassign status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
}

/// The hint equals the real PUT enforcement answer for a REAL transition (`target` is the
/// opposite of the current state, so the idempotent no-op path never hides the gates).
void check_enforcement(RbacRoleHarness& h, RbacAdminHint expected, bool target) {
    const auto hint = hint_of(h);
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);
    const auto res = h.set_enforcement_rest(target);
    REQUIRE(res);
    INFO("enforcement status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
}

void make_user(RbacRoleHarness& h, const std::string& name, auth::Role role) {
    REQUIRE(h.auth_db->upsert_user(name, "hash", "salt", role).has_value());
}

template <typename S>
concept HintCallableWithoutSurface =
    requires(S s) { rbac_admin_hint(s, static_cast<AuthDB*>(nullptr), static_cast<const RbacStore*>(nullptr)); };

} // namespace

// The surface parameter has NO default, exactly like the predicate it folds.
static_assert(!HintCallableWithoutSurface<const auth::Session&>,
              "rbac_admin_hint must force every caller to name its surface");

// ── Route-level equality, POST assign ───────────────────────────────────────

TEST_CASE("rbac_admin_hint == POST assign: base admin, RBAC off (P1)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    check_assign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint == POST assign: base admin with NO Administrator grant, RBAC on (P2)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_assign(h, RbacAdminHint::kMayNot); // the old base-role hint drew the button here
}

TEST_CASE("rbac_admin_hint == POST assign: base admin WITH the Administrator grant, RBAC on (P3)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_assign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint == POST assign: base user WITH the Administrator grant and an active row, RBAC on (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true); // role=user + grant + active auth.users row
    check_assign(h, RbacAdminHint::kMay);  // the #6034 headline: the old hint drew nothing
}

TEST_CASE("rbac_admin_hint == POST assign: Administrator grant is inert while RBAC is off (P5)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: base user holding a non-administrator role, RBAC on (P6)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Viewer"}).has_value());
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: SSO principal with the grant but NO auth.users row (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    // The predicate admits (bare principal_roles membership); the regime check needs an active
    // auth.users row, so the route refuses. A predicate-only hint would overstate here.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: SSO-labelled principal WITH a break-glass active row (P7b)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "sso-breakglass";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::user); // the documented SQL-provisioned row
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_assign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint == POST assign: durable demotion after sign-in, RBAC off (P14)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::admin);
    {
        // upsert_user refuses to demote an account (#4966); break-glass SQL stands in for the
        // demotion that landed after this session was minted.
        auto lease = h.auth_db.pool().acquire();
        REQUIRE(lease);
        auto r = pg::exec_params(lease.get(), "UPDATE auth.users SET role = 'user' WHERE username = $1",
                                 std::vector<std::string>{h.session_user});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    check_assign(h, RbacAdminHint::kMayNot); // the durable row is re-read, never the session
}

TEST_CASE("rbac_admin_hint == POST assign: a principal with no auth.users row at all, RBAC off",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    check_assign(h, RbacAdminHint::kMayNot);
}

// DELETE unassign calls the same two authority functions in the same order as POST assign
// (rest_api_v1.cpp), but through its own handler, so its sequence is pinned on its own.
TEST_CASE("rbac_admin_hint == DELETE unassign: base user WITH the Administrator grant, RBAC on (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    check_unassign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: SSO principal with the grant but NO auth.users row (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    // Past the predicate, refused by the regime check: the second gate of the DELETE handler.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: MCP-tier token on the REST surface (P9)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.rest_session_mcp_tier = "supervised";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: service-scoped token (P10)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "payments";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: engine session (P11)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_principal_kind = "engine";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: plain API-token session of an administrator (P12)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_auth_source = "api_token"; // no tier, unscoped: the gates never read auth_source
    check_assign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint == POST assign: regime store unreadable, RBAC on (P13)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    // The predicate (principal_roles) still answers kAdmin; the regime check's auth.users JOIN
    // cannot run. A hint that skipped the regime check would say kMay here, the route says 503.
    {
        auto lease = h.auth_db.pool().acquire();
        REQUIRE(lease);
        auto r = pg::exec_params(lease.get(), "ALTER TABLE auth.users RENAME TO users_hint_gone",
                                 std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_assign(h, RbacAdminHint::kUnconfirmed);
}

// ── Route-level equality, PUT enforcement (real transitions only) ────────────

TEST_CASE("rbac_admin_hint == PUT enforcement: durable admin holding the grant, RBAC off -> on (P1)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/true);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base admin with NO grant, RBAC on (P2)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base admin with the grant, RBAC on -> off (P3)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base user with the grant, RBAC on -> off (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    // Authority is admitted; the destination guard may still answer 409 (the caller would not
    // remain a local admin), which classifies as admitted, not as a refusal of authority.
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: SSO principal with the grant and no row, RBAC on (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false); // the store's source check
}

TEST_CASE("rbac_admin_hint == PUT enforcement: engine session (P11)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.session_principal_kind = "engine";
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
}

// ── The fold itself ──────────────────────────────────────────────────────────

TEST_CASE("rbac_admin_hint: structural denies need no store", "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    auth::Session engine;
    engine.username = "e";
    engine.principal_kind = "engine";
    auth::Session scoped;
    scoped.username = "s";
    scoped.token_scope_service = "payments";
    auth::Session tiered;
    tiered.username = "t";
    tiered.mcp_tier = "readonly";
    for (const auto* s : {&engine, &scoped, &tiered}) {
        INFO(s->username);
        CHECK(rbac_admin_hint(*s, nullptr, nullptr, RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);
    }
    // The MCP surface applies no tier rule: with no store it cannot decide, never kMayNot.
    CHECK(rbac_admin_hint(tiered, nullptr, nullptr, RbacAdminSurface::kMcp) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: a null RbacStore is kUnconfirmed", "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    yuzu::test::AuthDbPg auth_db;
    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, auth_db.get(), nullptr, RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: RBAC off with a null AuthDB is kUnconfirmed",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    yuzu::test::RbacStorePg rbac;
    REQUIRE_FALSE(rbac->is_rbac_enabled());
    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, nullptr, rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: a session elevated to admin is still kMayNot without a durable grant (P8)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::user);
    auto s = h.rest_session();
    s.role = auth::Role::admin; // the effective role a JIT elevation produces
    s.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
    s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);

    // RBAC on: still no durable grant, still kMayNot.
    h.rbac->set_rbac_enabled(true);
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);

    // The grant, not the elevation, is what admits (P8b).
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint: the predicate's DEGRADED enforcement view folds to kUnconfirmed, not kMayNot",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    // Same construction as test_rbac_admin_predicate.cpp's degraded-view case: a replica whose
    // pool is starved past the stale-serve bound reads the enabled flag as degraded.
    yuzu::test::RbacStorePg rbac;
    yuzu::test::AuthDbPg auth_db;
    yuzu::server::pg::PgPool pool_b{{.conninfo = rbac.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    replica_b.age_refresh_state_for_test(std::chrono::milliseconds(1100));
    auto held = pool_b.acquire();
    REQUIRE(held);
    CHECK_FALSE(rbac_enforcement_in_effect(&replica_b));
    replica_b.age_refresh_state_for_test(std::chrono::milliseconds(4200));
    REQUIRE(rbac_enforcement_in_effect(&replica_b));
    REQUIRE(rbac_enforcement_label(&replica_b) == RbacEnforcementLabel::kDegraded);
    held.reset();

    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, auth_db.get(), &replica_b, RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}
