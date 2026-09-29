/**
 * test_list_read_confinement.cpp — ADR-0017 admit-then-filter list gate.
 *
 * Foundation tests for RbacStore::authorize_list_read + the shared resolver
 * (holds_permission_via_any_group / visible_agents_for_permission) and the
 * refactored check_scoped_permission. Covers the frozen #1715 combining
 * lattice (cross-boundary additive/OR; deny-overrides intra-group only) and
 * the design invariants:
 *   INV-1  fail-closed is total (corrupt/unavailable store → DenyAll, not AdmitAll)
 *   INV-2  empty visible set ⇒ AdmitScoped({}) (200 empty), not DenyAll (403)
 *   INV-4  descendant-ward expansion (a grant on a group covers its subtree)
 *   INV-5  partial failure denies, never includes
 *   INV-7  ONE resolver — visible set == { a : check_scoped_permission(...) }
 */

#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp" // PgConn/PgResult for the mid-flight degrade injection
#include "rbac_store.hpp"
#include "test_mgmt_group_pg_helper.hpp" // PG-backed ManagementGroupStore (ADR-0042)

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

// Pre-migrated + seeded template (RbacStore construction runs the migration AND
// seed_defaults). Every store-behaviour case clones this instead of
// re-migrating/re-seeding per test (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rbac_tpl{"rbacstore", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        RbacStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "rbac template: store failed to migrate/seed");
                                    }};

/// A two-store rig with a small management-group tree, custom allow/deny
/// Response:Read roles, and RBAC enforcement ON so authorize_list_read runs
/// the real admit-then-filter path (a fresh store is loaded-and-disabled →
/// legacy-open, which we test separately).
///
///   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
///      └─ C2
///
/// Members: a_p∈P, a_c1∈C1, a_c2∈C2, a_s∈S.
struct Rig {
    PgPool pool;
    RbacStore rbac;
    // ManagementGroupStore is a PG store (ADR-0042); the bundle SKIPs the
    // TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset — so every case that
    // constructs a Rig carries the [pg] tag.
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    std::string gP, gC1, gC2, gS;

    explicit Rig(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, rbac{pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        rbac.set_rbac_enabled(true); // enforcement in effect

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
};

} // namespace

// ── #1715(b): a global ALLOW overrides any group deny → AdmitAll ──────────────

TEST_CASE("authorize_list_read: global allow ⇒ AdmitAll", "[list_read][rbac][1715][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "bob", "RespReader"}).has_value()); // GLOBAL allow
    r.group_assign(r.gC2, "bob", "RespDenier"); // a group deny must NOT carve out

    auto d = r.rbac.authorize_list_read("bob", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitAll);
}

// ── #1715(a): a global DENY does NOT override a group allow (additive) ────────

TEST_CASE("authorize_list_read: global deny + group allow ⇒ AdmitScoped (additive)",
          "[list_read][rbac][1715][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "carol", "RespDenier"}).has_value()); // GLOBAL deny
    r.group_assign(r.gP, "carol", "RespReader");                              // group allow

    // Global deny makes check_permission false, but the group allow still admits.
    auto d = r.rbac.authorize_list_read("carol", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitScoped);
    CHECK(contains(d.visible_agents, "a_p"));
}

// ── DenyAll: no grant anywhere ────────────────────────────────────────────────

TEST_CASE("authorize_list_read: no grant ⇒ DenyAll", "[list_read][rbac][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    auto d = r.rbac.authorize_list_read("nobody", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::DenyAll);
    CHECK(d.visible_agents.empty());
}

// ── INV-2: holds via a group but sees nothing ⇒ AdmitScoped({}), not DenyAll ──

TEST_CASE("authorize_list_read: allow on an empty group ⇒ AdmitScoped empty (INV-2)",
          "[list_read][rbac][inv2][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    auto empty = r.make_group("Empty", ""); // no members
    r.group_assign(empty, "dave", "RespReader");

    auto d = r.rbac.authorize_list_read("dave", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitScoped); // 200 empty, NOT a 403
    CHECK(d.visible_agents.empty());
    CHECK(r.rbac.holds_permission_via_any_group("dave", "Response", "Read", &r.mgmt));
}

// ── INV-4: descendant-ward expansion + deny-override subtraction ──────────────

TEST_CASE("authorize_list_read: descendant-ward visible set with a deny branch (INV-4)",
          "[list_read][rbac][inv4][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "alice", "RespReader");  // allow on P (covers P,C1,C2)
    r.group_assign(r.gC2, "alice", "RespDenier"); // deny on the C2 branch

    auto d = r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    CHECK(contains(d.visible_agents, "a_p"));   // P member
    CHECK(contains(d.visible_agents, "a_c1"));  // descendant of P, not denied
    CHECK(!contains(d.visible_agents, "a_c2")); // descendant of P but denied
    CHECK(!contains(d.visible_agents, "a_s"));  // outside P's subtree
    CHECK(d.visible_agents.size() == 2);
}

// ── INV-7: the set-equivalence property + one-resolver cross-check ────────────

TEST_CASE("authorize_list_read: visible set == {a : check_scoped_permission} (INV-7)",
          "[list_read][rbac][inv7][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "alice", "RespReader");
    r.group_assign(r.gC2, "alice", "RespDenier");

    // The property, over every agent in the fixture tree.
    const std::vector<std::string> all_agents{"a_p", "a_c1", "a_c2", "a_s"};

    auto visible = r.rbac.visible_agents_for_permission("alice", "Response", "Read", &r.mgmt);
    REQUIRE(visible.has_value());

    for (const auto& a : all_agents) {
        bool per_row = r.rbac.check_scoped_permission("alice", "Response", "Read", a, &r.mgmt);
        bool in_set = contains(*visible, a);
        INFO("agent=" << a);
        CHECK(in_set == per_row); // one resolver: the set and the per-row gate agree
    }

    // Cross-check: authorize_list_read's AdmitScoped set == visible_agents_for_permission.
    auto d = r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    auto lhs = d.visible_agents;
    auto rhs = *visible;
    std::sort(lhs.begin(), lhs.end());
    std::sort(rhs.begin(), rhs.end());
    CHECK(lhs == rhs);
}

// ── Legacy-open: RBAC loaded-and-disabled ⇒ AdmitAll (behaviour-neutral) ──────

TEST_CASE("authorize_list_read: RBAC disabled ⇒ AdmitAll (legacy-open)", "[list_read][rbac][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_}; // is_open() && !is_rbac_enabled() → legacy-open
    REQUIRE(rbac.is_open());
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;

    auto d = rbac.authorize_list_read("anyone", "Response", "Read", &mgmt);
    CHECK(d.decision == ListReadDecision::AdmitAll);
}

// ── INV-1/INV-5: fail-closed is total ────────────────────────────────────────

TEST_CASE("authorize_list_read: null mgmt store under enforcement ⇒ DenyAll (INV-1)",
          "[list_read][rbac][inv1][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true); // enforcement in effect, but no global grant
    auto d = rbac.authorize_list_read("alice", "Response", "Read", /*mgmt=*/nullptr);
    CHECK(d.decision == ListReadDecision::DenyAll); // never AdmitAll
}

TEST_CASE("authorize_list_read: corrupt rbac.db ⇒ DenyAll, never AdmitAll (INV-1)",
          "[list_read][rbac][inv1][pg]") {
    // The PG analogue of the SQLite corrupt-file fail-closed test: a pool
    // whose DSN never connects leaves the store's construction lease empty,
    // so migration never runs and is_open()==false — the same state a
    // corrupt/unreachable rbac substrate produces.
    PgPool bad_pool{
        {.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1", .size = 1}};
    RbacStore bad{bad_pool};
    REQUIRE(!bad.is_open()); // precondition: migrations failed → store not open

    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;

    // rbac_enforcement_in_effect(!is_open()) == true (enforce), so this must NOT
    // take the legacy-open AdmitAll branch — a corrupt store fails CLOSED.
    auto d = bad.authorize_list_read("alice", "Response", "Read", &mgmt);
    CHECK(d.decision == ListReadDecision::DenyAll);
}

// ── check_scoped_permission behaviour preserved by the INV-7 refactor ─────────

TEST_CASE("check_scoped_permission: preserved through the shared-resolver refactor",
          "[list_read][rbac][refactor][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "alice", "RespReader");
    r.group_assign(r.gC2, "alice", "RespDenier");

    // allow on P covers P + descendants (ancestor-ward admit); deny on C2 wins there.
    CHECK(r.rbac.check_scoped_permission("alice", "Response", "Read", "a_p", &r.mgmt));
    CHECK(r.rbac.check_scoped_permission("alice", "Response", "Read", "a_c1", &r.mgmt));
    CHECK(!r.rbac.check_scoped_permission("alice", "Response", "Read", "a_c2", &r.mgmt)); // deny
    CHECK(!r.rbac.check_scoped_permission("alice", "Response", "Read", "a_s", &r.mgmt));  // no grant

    // Global allow still short-circuits (matches #1715(b)).
    REQUIRE(r.rbac.assign_role({"user", "gadmin", "RespReader"}).has_value());
    CHECK(r.rbac.check_scoped_permission("gadmin", "Response", "Read", "a_s", &r.mgmt));
}

// ── INV-7 set-equivalence over a DEEP tree (≥3 levels) with a mid-tree deny ───
// Exercises the ancestor-ward ⟷ descendant-ward duality past one level:
// a grandchild inherits a root allow AND a mid-tree deny; a sibling branch is
// isolated from the deny (architect + consistency-auditor SHOULD).
//
//   R(allow) ── DP ──┬── DC1(deny) ── DGC          members: a_R,a_dp,a_dc1,a_dgc,a_dc2
//                    └── DC2
TEST_CASE("authorize_list_read: INV-7 holds over a 4-level tree with a mid-tree deny",
          "[list_read][rbac][inv7][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()}; // reuses RespReader/RespDenier roles + RBAC-enabled store
    auto R = r.make_group("R", "");
    auto DP = r.make_group("DP", R);
    auto DC1 = r.make_group("DC1", DP);
    auto DGC = r.make_group("DGC", DC1); // depth 3 — within create_group's cap of 5
    auto DC2 = r.make_group("DC2", DP);
    REQUIRE(r.mgmt.add_member(R, "a_R").has_value());
    REQUIRE(r.mgmt.add_member(DP, "a_dp").has_value());
    REQUIRE(r.mgmt.add_member(DC1, "a_dc1").has_value());
    REQUIRE(r.mgmt.add_member(DGC, "a_dgc").has_value());
    REQUIRE(r.mgmt.add_member(DC2, "a_dc2").has_value());

    r.group_assign(R, "deep", "RespReader");   // allow on the root (covers whole tree)
    r.group_assign(DC1, "deep", "RespDenier");  // deny mid-tree (covers DC1 + DGC)

    const std::vector<std::string> all_agents{"a_R", "a_dp", "a_dc1", "a_dgc", "a_dc2"};

    auto visible = r.rbac.visible_agents_for_permission("deep", "Response", "Read", &r.mgmt);
    REQUIRE(visible.has_value());
    // Expected: allow(R-subtree) minus deny(DC1-subtree) = {a_R,a_dp,a_dc2}.
    CHECK(contains(*visible, "a_R"));
    CHECK(contains(*visible, "a_dp"));
    CHECK(contains(*visible, "a_dc2"));  // sibling of the denied branch — survives
    CHECK(!contains(*visible, "a_dc1")); // denied directly
    CHECK(!contains(*visible, "a_dgc")); // grandchild inherits the mid-tree deny
    CHECK(visible->size() == 3);

    // The set-equivalence property AND the INV-7 cross-check, past one level.
    for (const auto& a : all_agents) {
        bool per_row = r.rbac.check_scoped_permission("deep", "Response", "Read", a, &r.mgmt);
        INFO("agent=" << a);
        CHECK(contains(*visible, a) == per_row);
    }
    auto d = r.rbac.authorize_list_read("deep", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    auto lhs = d.visible_agents, rhs = *visible;
    std::sort(lhs.begin(), lhs.end());
    std::sort(rhs.begin(), rhs.end());
    CHECK(lhs == rhs);
}

// ── Grant via an RBAC GROUP (principal_type='group' arm) ──────────────────────
// The security-relevant "grant to a team, not an individual" path: a
// management-group role assigned to an RBAC group, reached by a user through
// RBAC-group membership (get_assignments_for_principal's group OR-arm). Was
// entirely untested (quality-engineer SHOULD).
TEST_CASE("authorize_list_read: grant via an RBAC group (principal_type='group')",
          "[list_read][rbac][group-principal][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    REQUIRE(r.rbac.create_group({"soc-team", "", "local", "", 0}).has_value());
    REQUIRE(r.rbac.add_group_member("soc-team", "teamuser").has_value());
    // Role granted to the RBAC GROUP on P, not to teamuser directly.
    REQUIRE(r.mgmt.assign_role({r.gP, "group", "soc-team", "RespReader"}).has_value());

    auto d = r.rbac.authorize_list_read("teamuser", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped); // reached via the group arm
    CHECK(contains(d.visible_agents, "a_p"));
    CHECK(contains(d.visible_agents, "a_c1")); // P's descendant
    CHECK(contains(d.visible_agents, "a_c2"));
    CHECK(!contains(d.visible_agents, "a_s")); // outside P's subtree
    CHECK(r.rbac.check_scoped_permission("teamuser", "Response", "Read", "a_p", &r.mgmt));

    // Negative: drop the RBAC-group membership → the scoped grant is gone.
    REQUIRE(r.rbac.remove_group_member("soc-team", "teamuser").has_value());
    auto d2 = r.rbac.authorize_list_read("teamuser", "Response", "Read", &r.mgmt);
    CHECK(d2.decision == ListReadDecision::DenyAll);
}

// ── Same group carrying BOTH an allow-role and a deny-role ⇒ deny wins ────────
// The group lands in both allow_groups and deny_groups; expand_visible_set
// subtracts the deny subtree, so its members are excluded despite the allow
// (quality-engineer SHOULD — INV-4 tests only used different groups).
TEST_CASE("authorize_list_read: same group allow+deny roles ⇒ AdmitScoped empty (deny wins)",
          "[list_read][rbac][inv7][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "split", "RespReader");
    r.group_assign(r.gP, "split", "RespDenier");

    auto d = r.rbac.authorize_list_read("split", "Response", "Read", &r.mgmt);
    // Holds an allow (→ not DenyAll), but the co-located deny subtracts P's whole
    // subtree → AdmitScoped with an empty visible set.
    CHECK(d.decision == ListReadDecision::AdmitScoped);
    CHECK(d.visible_agents.empty());
    CHECK(r.rbac.holds_permission_via_any_group("split", "Response", "Read", &r.mgmt));
    // Per-row gate agrees: deny wins for every member of the group.
    CHECK(!r.rbac.check_scoped_permission("split", "Response", "Read", "a_p", &r.mgmt));
    CHECK(!r.rbac.check_scoped_permission("split", "Response", "Read", "a_c1", &r.mgmt));
}

// Gate 3 QE BLOCKING: prove RbacStore's confinement gate DENIES when the
// ManagementGroupStore degrades mid-flight — the seam ADR-0042 exists to close.
// A CONFINED operator (group-scoped grant, no global short-circuit) whose
// visible-set resolution hits a degraded mgmt store must fail closed (DenyAll),
// never fall through to an unfiltered admit or a silent under-deny.
TEST_CASE("authorize_list_read: a degraded mgmt store denies a confined operator (fail-closed)",
          "[list_read][rbac][degrade][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    Rig r{rbac_db_.dsn()};
    r.group_assign(r.gP, "alice", "RespReader"); // group-scoped allow → confined, no #1715(b)
    // Healthy baseline: alice is confined (AdmitScoped), NOT DenyAll — so the
    // DenyAll below is caused by the degrade, not by an absent grant.
    REQUIRE(r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt).decision !=
            ListReadDecision::DenyAll);
    // Break the mgmt store mid-flight: drop a confinement table so the
    // subtree/member reads return a genuine query error.
    {
        yuzu::server::pg::PgConn c{PQconnectdb(r.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult dr{PQexec(
            c.get(), "DROP TABLE management_group_store.management_group_members CASCADE")};
        REQUIRE(dr.ok());
    }
    CHECK(r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt).decision ==
          ListReadDecision::DenyAll);
    // The per-agent scoped check on the same degraded store also fails closed.
    CHECK_FALSE(r.rbac.check_scoped_permission("alice", "Response", "Read", "a_p", &r.mgmt));
}

// Governance re-review, #2703 Gate 7 (G11-SEC-CALLSITE-01 / QA-1): a lexical
// regression backstop for the class of defect just found and fixed —
// confinement-relevant closures reading the raw `is_rbac_enabled()` accessor
// instead of the fail-closed `rbac_enforcement_in_effect()` free function.
// `rbac_enforcement_in_effect()` itself is already covered at the primitive
// level (test_rbac_store.cpp's degraded-generation-view test), and
// `visible_set_fn`/`inventory_agent_in_scope` are now one-line delegations to
// it — so the residual, previously-uncaught risk is WIRING drift at the call
// site, which no store-level test can see and which a doc comment has
// already failed to prevent three times (cpp-expert/architect, Gate 3, same
// round). No ServerImpl test harness exists to exercise this at runtime
// (`response_agent_in_scope`, the established-correct sibling, has no direct
// test either), so this scans the real source text instead: every live
// `is_rbac_enabled()` call site across the files below must be on the
// explicit allowlist or the test fails, naming the offending line, so a
// future addition is a deliberate allowlist edit rather than a silent
// regression.
//
// #2703 Gate 7 item Commit C (consistency-auditor + quality-engineer, Gate 3):
// resolves the scanned path via the compile-time `YUZU_SERVER_SRC_DIR` macro
// (injected by tests/meson.build — the same seam test_body_cap_route_
// inventory.cpp already uses) rather than a runtime current_path()/__FILE__
// walk-up. That walk had two problems: it silently found nothing (a
// REQUIRE_FALSE failure with no useful diagnosis) when the test binary was
// invoked from a CWD more than 6 parents away from the repo root, and it was
// the exact same CWD-sensitivity class that produced a false failure earlier
// in this same session. The macro is absolute and CWD-independent by
// construction.
//
// Also extended (security-guardian, Gate 2, LOW) to rest_api_v1.cpp, which
// has its own `is_rbac_enabled()` call sites — the REST surface was
// previously unscanned entirely.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (see test_body_cap_route_inventory.cpp's identical guard)."
#endif
TEST_CASE("every live is_rbac_enabled() call site is display-only "
          "(allowlisted), never a confinement decision (#2703 Gate 7)",
          "[list_read][rbac][lexical]") {
    const std::filesystem::path src_dir{YUZU_SERVER_SRC_DIR};

    // Per-file allowlists, keyed by exact trimmed live-code line — matched
    // this way (not by proximity to a comment) so a future reformat that
    // keeps the same test-and-branch shape still matches, and any OTHER new
    // call site (different shape, different purpose) does not.
    const std::unordered_map<std::string, std::unordered_set<std::string>> allowlists = {
        {"server.cpp",
         {
             // The nav-bar/`/api/me`-style session JSON — display-only per
             // rbac_store.hpp's own documented exception.
             "if (rbac_store_ && rbac_store_->is_rbac_enabled()) {",
         }},
        {"rest_api_v1.cpp",
         {
             // Exact REST twin of server.cpp's nav-bar site above — same
             // session-info JSON, same display-only exception.
             "if (rbac_store && rbac_store->is_rbac_enabled()) {",
             // NOT display-only, but not the list-read/visible-agents
             // confinement class this test otherwise guards either: a
             // service-scoped-token issuance precondition. The REAL
             // authorization decision immediately following this gate is
             // check_permission(username, "ManagementGroup", "Write") (or
             // the ITServiceOwner group-role check) — that call does not
             // itself consult rbac_enabled at all, so a stale raw view here
             // can only ever bias this endpoint toward wrongly REFUSING a
             // legitimate scoped-token request (availability), never toward
             // over-disclosure or privilege escalation. Still inconsistent
             // with rbac_store.hpp's documented MUST for confinement-
             // adjacent callers — tracked for cleanup, not urgent given the
             // above (see the filed follow-up cited in this PR's issue
             // filings).
             "if (!rbac_store || !rbac_store->is_rbac_enabled()) {",
         }},
        {"auth_routes.cpp",
         {
             // security-guardian (Gate 8, MEDIUM): auth_routes.cpp had 4 of
             // its own is_rbac_enabled() call sites, entirely unscanned
             // before this entry. All 4 are single-target require_permission/
             // require_scoped_permission preconditions ("RBAC must be
             // enabled for this token/grant kind"), not the list-read/
             // visible-agents confinement class this test otherwise guards —
             // same disposition as rest_api_v1.cpp's precondition site above.
             // Each is a deny-first compound gate (`!is_rbac_enabled() ||
             // !check_...(...)`), so a stale raw view here can only ever
             // bias toward wrongly DENYING a request, never toward
             // over-disclosure. Two distinct trimmed shapes cover all 4
             // sites (2 occurrences each).
             "if (!rbac_store_->is_rbac_enabled() ||",
             "if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {",
         }},
    };

    std::vector<std::string> offenders;
    for (const auto& [filename, allowlist] : allowlists) {
        const auto path = src_dir / filename;
        std::ifstream in(path);
        REQUIRE(in.is_open());
        std::ostringstream buf;
        buf << in.rdbuf();

        std::istringstream lines(buf.str());
        std::string line;
        int lineno = 0;
        while (std::getline(lines, line)) {
            ++lineno;
            if (line.find("is_rbac_enabled()") == std::string::npos)
                continue;
            // Skip comment-only lines (// or ///) — this test guards live
            // code, not the prose warning against this exact mistake.
            auto first_nonspace = line.find_first_not_of(" \t");
            if (first_nonspace != std::string::npos &&
                line.compare(first_nonspace, 2, "//") == 0)
                continue;
            std::string trimmed =
                line.substr(first_nonspace == std::string::npos ? 0 : first_nonspace);
            if (allowlist.count(trimmed))
                continue;
            offenders.push_back(filename + ":" + std::to_string(lineno) + ": " + trimmed);
        }
    }

    INFO("A new/changed is_rbac_enabled() call site was found outside its file's allowlist. "
         "If it decides confinement/authorization scope, use "
         "rbac_enforcement_in_effect(rbac_store_.get()) instead (see rbac_store.hpp's doc "
         "comment on is_rbac_enabled()). If it is genuinely display-only (like the nav-bar "
         "JSON), add its exact trimmed line text to that file's allowlist deliberately.");
    for (const auto& o : offenders)
        UNSCOPED_INFO(o);
    CHECK(offenders.empty());
}
