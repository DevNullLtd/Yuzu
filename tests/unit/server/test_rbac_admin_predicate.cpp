/**
 * test_rbac_admin_predicate.cpp — Unit tests for
 * `rbac_admin_predicate.hpp`'s `is_rbac_administrator` / `is_self_target`
 * (A2, `.claude/plans/rbac-industry-leading-DELIVERY-PLAN.md` §2).
 *
 * Covers: the RBAC-off durable-AuthDB-reread branch, the RBAC-on
 * principal_roles branch, the four deliberate scope decisions documented at
 * the header (no JIT elevation, no group-held Administrator, structural
 * service-scope/engine-session denial), and every `kUnavailable` fail-closed
 * path (null store, degraded read).
 *
 * PG-gated: RbacStore AND AuthDB are both born-on-Postgres (ADR-0006).
 * Independent databases (mirrors test_rest_access_review.cpp's
 * AuthDbPgShared-alongside-RbacStore composition) — the predicate takes two
 * independent store pointers with no cross-store transaction requirement.
 * Skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken.
 */

#include "rbac_admin_predicate.hpp"

#include "pg/pg_pool.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>

using namespace yuzu::server;

namespace {

/// One fresh RbacStore + one fresh AuthDB, independent databases. Both
/// fixtures SKIP the TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset.
struct PredicateHarness {
    yuzu::test::RbacStorePg rbac;
    yuzu::test::AuthDbPg auth_db;
};

auth::Session make_session(const std::string& username) {
    auth::Session s;
    s.username = username;
    return s;
}

} // namespace

// ── RBAC-off branch: durable AuthDB re-read ─────────────────────────────────

TEST_CASE("is_rbac_administrator: RBAC off, durable role=admin -> kAdmin",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    REQUIRE(h.auth_db->upsert_user("adminuser", "hash", "salt", auth::Role::admin).has_value());

    auto gate = is_rbac_administrator(make_session("adminuser"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kAdmin);
}

TEST_CASE("is_rbac_administrator: RBAC off, durable role=user -> kDenied",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());

    auto gate = is_rbac_administrator(make_session("plainuser"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC off, session role='admin' but NO durable "
          "auth.users row (JIT-elevation-shaped session) -> kDenied, not kAdmin",
          "[pg][rbac_admin_predicate]") {
    // Simulates the plan's decision 1: a session carrying a JIT-elevated
    // effective role must NOT satisfy this predicate — only a durable
    // auth.users row does. A session for a username with no row at all is
    // the simplest way to prove the predicate never trusts the Session
    // object's own .role field.
    PredicateHarness h;
    auth::Session s = make_session("nobody-durable");
    s.role = auth::Role::admin; // the session's own cached role — ignored

    auto gate =
        is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC off, null AuthDB -> kUnavailable",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    auto gate = is_rbac_administrator(make_session("whoever"), nullptr, h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kUnavailable);
}

// ── RBAC-on branch: principal_roles re-read ─────────────────────────────────

TEST_CASE("is_rbac_administrator: RBAC on, principal_roles(user,*,Administrator) "
          "row -> kAdmin",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "rbacadmin", "Administrator"}).has_value());

    auto gate = is_rbac_administrator(make_session("rbacadmin"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kAdmin);
}

TEST_CASE("is_rbac_administrator: RBAC on, no principal_roles row -> kDenied "
          "(even with a durable auth.users role=admin row — RBAC-on ignores AuthDB)",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    // A durable AuthDB admin row exists, but once RBAC is truly on, only the
    // principal_roles grant table is authoritative — the two branches are
    // mutually exclusive, never "OR"'d together.
    REQUIRE(h.auth_db->upsert_user("legacyadmin", "hash", "salt", auth::Role::admin).has_value());

    auto gate = is_rbac_administrator(make_session("legacyadmin"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC on, principal_roles row for a DIFFERENT "
          "role -> kDenied",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "vieweronly", "Viewer"}).has_value());

    auto gate = is_rbac_administrator(make_session("vieweronly"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: RBAC on, ONLY a group-held Administrator grant "
          "-> kDenied (deliberate A2 scope limit)",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"group", "admins-group", "Administrator"}).has_value());

    // "groupmember" holds no DIRECT principal_roles(user,...) row — only
    // group membership would grant it, which this predicate deliberately
    // does not resolve (decision 2 in the header comment).
    auto gate = is_rbac_administrator(make_session("groupmember"), h.auth_db.get(), h.rbac.get(),
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kDenied);
}

// Doomgoose external review, PR #4985 (IMPORTANT #2): `rbac_enforcement_in_
// effect()` deliberately returns `true` (enforcement "in effect") not only
// when RBAC is genuinely enabled, but ALSO when the enabled-flag cache view
// is DEGRADED (a refresh outage left a replica's cached rbac_enabled_ stale
// — see rbac_store.cpp's #2703 comment right above it). Pre-fix,
// `is_rbac_administrator`'s RBAC-on branch could not tell the two apart: a
// degraded view with no matching Administrator row read as a confirmed
// kDenied (403, terminal) instead of kUnavailable (503, retryable) —
// contradicting this file's own header invariant that a transient store
// hiccup must never masquerade as a permanent policy denial.
//
// Reproduces the degrade via the SAME technique as test_rbac_store.cpp's
// "rbac_enforcement_in_effect fails closed when a generation refresh fails
// PAST the bounded stale-serve window" test: a SECOND RbacStore replica on
// its OWN size-1 pool, starved by holding its one connection, pushed past
// kRbacStaleServeBoundMs (5000ms) so `generation_valid_` gets cleared by a
// genuinely FAILED refresh attempt (not merely elapsed time with a healthy
// pool — a healthy pool's very next successful refresh would self-heal the
// view before this predicate ever observed it degraded, exactly as that
// sibling file's neighboring "elapsed time alone" test warns). The starved
// connection is then released so `is_rbac_administrator`'s OWN
// `get_principal_roles_checked` read can succeed normally — the 1s
// refresh-stampede gate (`kRbacGenerationRefreshMs`) keeps the very next
// `is_rbac_enabled()` call (inside `rbac_enforcement_label`) on the fast,
// no-query path, so it does not touch the now-healthy pool and does not
// self-heal either. This reproduces exactly the combination the fix
// targets: a CONFIRMED-empty row lookup on a view that is DEGRADED, not
// genuinely enabled.
TEST_CASE("is_rbac_administrator: RBAC-on branch reached via a DEGRADED "
          "(not genuinely enabled) enforcement view, no Administrator row "
          "-> kUnavailable, never kDenied",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE_FALSE(h.rbac->is_rbac_enabled()); // fresh install default: disabled

    yuzu::server::pg::PgPool pool_b{{.conninfo = h.rbac.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    REQUIRE_FALSE(replica_b.is_rbac_enabled());
    REQUIRE_FALSE(rbac_enforcement_in_effect(&replica_b)); // baseline: genuinely fresh+disabled

    // Clear the 1s refresh-stampede gate so the next call genuinely attempts
    // a durable re-read instead of serving the just-constructed cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Starve replica_b's own pool: every maybe_refresh_generation() call
    // from here on cannot acquire a connection and must fail.
    auto held = pool_b.acquire();
    REQUIRE(held);

    // First failed attempt lands well inside kRbacStaleServeBoundMs (5000ms)
    // of construction — bounded stale-serve keeps this NOT degraded yet.
    CHECK_FALSE(rbac_enforcement_in_effect(&replica_b));

    // Push wall time past the bound, still starved — this failed attempt is
    // the one that finally exceeds the bound and clears generation_valid_.
    std::this_thread::sleep_for(std::chrono::milliseconds(4200));
    REQUIRE(rbac_enforcement_in_effect(&replica_b));
    REQUIRE(rbac_enforcement_label(&replica_b) == RbacEnforcementLabel::kDegraded);

    // Release the starved connection — see the comment above the TEST_CASE
    // for why the very next read still observes the degraded view.
    held.reset();

    // No principal_roles(user, *, Administrator) row exists anywhere on this
    // database. Pre-fix, reaching the RBAC-on branch (because
    // rbac_enforcement_in_effect() returned true above) with no matching row
    // was read as a confirmed kDenied regardless of WHY that branch was
    // reached. Post-fix, the degraded case maps a missing row to
    // kUnavailable instead — "could not confirm", not "confirmed not
    // admin".
    auto gate = is_rbac_administrator(make_session("whoever"), h.auth_db.get(), &replica_b,
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kUnavailable);
}

TEST_CASE("is_rbac_administrator: null RbacStore -> kUnavailable regardless of "
          "RBAC on/off",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    auto gate = is_rbac_administrator(make_session("whoever"), h.auth_db.get(), nullptr,
                                      RbacAdminSurface::kRest);
    CHECK(gate == RbacAdminGate::kUnavailable);
}

// (cpp-safety re-review, PR #4985 fix round, corrected by a security-guardian
// follow-up pass: rbac_enforcement_label() itself was previously exercised
// only indirectly through is_rbac_administrator's other tests. This test
// directly asserts 3 of its 4 input classes (null store, fresh+disabled,
// genuinely enabled) against the classifier by name. The 4th class — a
// degraded/stale-view store — needs the expensive starved-pool setup the
// "is_rbac_administrator: RBAC-on branch reached via a DEGRADED..." TEST_CASE
// above already builds; rather than duplicate that setup, this test relies
// on that TEST_CASE's own direct `rbac_enforcement_label(&replica_b) ==
// RbacEnforcementLabel::kDegraded` assertion for the 4th class. Together the
// two TEST_CASEs give the classifier direct coverage of all 4 branches.)
TEST_CASE("rbac_enforcement_label: direct coverage of the null/disabled/"
          "enabled branches (see the DEGRADED test above for the 4th)",
          "[pg][rbac_admin_predicate]") {
    CHECK(rbac_enforcement_label(nullptr) == RbacEnforcementLabel::kDegraded);

    PredicateHarness h;
    REQUIRE_FALSE(h.rbac->is_rbac_enabled()); // fresh install default: disabled
    CHECK(rbac_enforcement_label(h.rbac.get()) == RbacEnforcementLabel::kDisabled);

    h.rbac->set_rbac_enabled(true);
    CHECK(rbac_enforcement_label(h.rbac.get()) == RbacEnforcementLabel::kEnabled);
    h.rbac->set_rbac_enabled(false);
}

// ── Structural exclusions (checked before any I/O) ──────────────────────────

TEST_CASE("is_rbac_administrator: an engine-classed session is denied even if "
          "the username coincidentally has a durable admin row",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(
        h.auth_db->upsert_user("coincidence", "hash", "salt", auth::Role::admin).has_value());
    REQUIRE(
        h.auth_db->upsert_user("coincidence2", "hash", "salt", auth::Role::admin).has_value());

    auto s = make_session("coincidence");
    s.principal_kind = "engine";
    CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) ==
          RbacAdminGate::kDenied);

    auto s2 = make_session("coincidence2");
    s2.auth_source = "engine_token";
    CHECK(is_rbac_administrator(s2, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) ==
          RbacAdminGate::kDenied);
}

TEST_CASE("is_rbac_administrator: a service-scoped session is denied even for a "
          "durable admin user",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("scopedadmin", "hash", "salt", auth::Role::admin).has_value());

    auto s = make_session("scopedadmin");
    s.token_scope_service = "some-service";
    CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) ==
          RbacAdminGate::kDenied);
}

// ── #520/Doomgoose (PR #4985 round-2, CRITICAL/BLOCKING): the REST-surface ──
// ── MCP-tier structural denial, and the MCP surface's negative control ─────

TEST_CASE("is_rbac_administrator: kRest denies a durable admin presenting ANY "
          "non-empty mcp_tier, RBAC off",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("mcptoken-admin", "hash", "salt", auth::Role::admin)
               .has_value());

    for (const std::string& tier : {"readonly", "operator", "supervised"}) {
        auto s = make_session("mcptoken-admin");
        s.mcp_tier = tier;
        INFO("mcp_tier = " << tier);
        CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) ==
              RbacAdminGate::kDenied);
    }
}

TEST_CASE("is_rbac_administrator: kRest denies a durable admin presenting ANY "
          "non-empty mcp_tier, RBAC on",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "mcptoken-admin2", "Administrator"}).has_value());

    for (const std::string& tier : {"readonly", "operator", "supervised"}) {
        auto s = make_session("mcptoken-admin2");
        s.mcp_tier = tier;
        INFO("mcp_tier = " << tier);
        CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) ==
              RbacAdminGate::kDenied);
    }
}

TEST_CASE("is_rbac_administrator: kMcp negative control — a supervised-tier "
          "durable admin still reaches kAdmin (the fix must not over-deny the "
          "legitimate MCP path)",
          "[pg][rbac_admin_predicate]") {
    PredicateHarness h;
    REQUIRE(h.auth_db->upsert_user("mcp-legit-admin", "hash", "salt", auth::Role::admin)
               .has_value());

    auto s = make_session("mcp-legit-admin");
    s.mcp_tier = "supervised";
    CHECK(is_rbac_administrator(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kMcp) ==
          RbacAdminGate::kAdmin);
}

// ── is_self_target ───────────────────────────────────────────────────────────

TEST_CASE("is_self_target: same username -> true", "[rbac_admin_predicate]") {
    CHECK(is_self_target(make_session("dave"), "dave"));
}

TEST_CASE("is_self_target: different username -> false", "[rbac_admin_predicate]") {
    CHECK_FALSE(is_self_target(make_session("dave"), "someone-else"));
}

TEST_CASE("is_self_target: empty session.username fails closed to true",
          "[rbac_admin_predicate]") {
    auth::Session s;
    CHECK(is_self_target(s, "anyone"));
    CHECK(is_self_target(s, ""));
}
