/**
 * test_authz_model.cpp — the registry-independent authz MODEL (ADR-0033 §2)
 * and the shared #1788 per-device-visibility primitive.
 *
 * Two independent halves, per `authz_model.hpp`'s own split:
 *
 *   1. `CapabilityDeclaration` / `kSeedCatalogue` / `is_valid()` — a stub
 *      consumer exercising the PR1.9-facing declaration schema.
 *   2. `VisibleSet` / `in_scope` / `filter_to_scope` — composition tests
 *      against `RbacStore`'s PUBLIC resolver-backed API (never the private
 *      `resolve_perm_groups`), asserting the documented #1715/INV-7 lattice
 *      semantics for `Execution:Execute` specifically, PLUS negative tests
 *      for each of the four `/api/command` dispatch-arm shapes.
 *
 * These tests cover the shared `in_scope`/`filter_to_scope` PRIMITIVE against
 * each arm's characteristic already-resolved target-set shape — the helper
 * semantics, not the dispatch path.
 *
 * The arms THEMSELVES are covered by `test_dispatch_confined_arms.cpp`, which
 * binds the production `dispatch_confined_arms` seam with exact-send-set
 * assertions. Both files are needed and neither substitutes for the other:
 * proving the primitive is correct says nothing about whether every arm calls
 * it, which is exactly the gap that let a false-green closure test pass while
 * the intersection was deleted (CDX-R8-02).
 */

#include "authz_model.hpp"
#include "management_group_store.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_mgmt_group_pg_helper.hpp" // PG-backed ManagementGroupStore (ADR-0042)
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)
#include "test_tag_store_pg_helper.hpp"  // PG-backed TagStore (ADR-0050)

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server::authz;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

} // namespace

// ── 1. CapabilityDeclaration / kSeedCatalogue ────────────────────────────

TEST_CASE("authz_model: every seed catalogue row materializes to a valid declaration",
          "[authz_model][seed]") {
    for (const auto& seed : kSeedCatalogue) {
        auto decl = from_seed(seed);
        INFO("securable=" << decl.securable << " operation=" << to_string(decl.operation));
        CHECK(decl.is_valid());
        CHECK(decl.securable == std::string(seed.securable));
        CHECK(decl.operation == seed.operation);
        CHECK(decl.risk_tier == seed.risk_tier);
        CHECK(decl.mcp_tier_class == default_mcp_tier_class(seed.operation));
    }
}

TEST_CASE("authz_model: seed catalogue includes AccessReview:Attest (SOC 2 CC6.2)",
          "[authz_model][seed]") {
    bool found = false;
    for (const auto& seed : kSeedCatalogue) {
        if (seed.securable == "AccessReview" && seed.operation == Operation::Attest) {
            found = true;
            // Attest is a narrow op, outside every CRUD loop — floors at Medium,
            // not Low (it is not an ordinary read).
            CHECK(static_cast<uint8_t>(seed.risk_tier) >=
                  static_cast<uint8_t>(min_risk_tier_for(Operation::Attest)));
        }
    }
    CHECK(found);
}

TEST_CASE("authz_model: seed catalogue includes Execution:Execute", "[authz_model][seed]") {
    bool found = false;
    for (const auto& seed : kSeedCatalogue)
        if (seed.securable == "Execution" && seed.operation == Operation::Execute)
            found = true;
    CHECK(found);
}

TEST_CASE("authz_model: default_mcp_tier_class matches mcp_policy.hpp's Execution:Execute "
          "special-case",
          "[authz_model][mcp_tier_class]") {
    // mcp_policy.hpp's operator tier auto-approves Execution:Execute without
    // allowing arbitrary writes — the ONE non-Read operation that maps to the
    // execute tier class rather than write.
    CHECK(default_mcp_tier_class(Operation::Execute) == McpTierClass::Execute);
    CHECK(default_mcp_tier_class(Operation::Read) == McpTierClass::Read);
    CHECK(default_mcp_tier_class(Operation::Write) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Delete) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Approve) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Push) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Attest) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Rotate) == McpTierClass::Write);
}

// ── is_valid(): "undeclared means the capability does not exist" ────────

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects a missing required field",
          "[authz_model][validate]") {
    CapabilityDeclaration base = from_seed(kSeedCatalogue[0]);
    REQUIRE(base.is_valid());

    auto no_securable = base;
    no_securable.securable.clear();
    CHECK(!no_securable.is_valid());

    auto no_discovery = base;
    no_discovery.discovery_entry.clear();
    CHECK(!no_discovery.is_valid());

    auto no_data_class = base;
    no_data_class.data_class.clear();
    CHECK(!no_data_class.is_valid());

    auto no_audit_verb = base;
    no_audit_verb.audit_verb.clear();
    CHECK(!no_audit_verb.is_valid());
}

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects a risk_tier below its floor",
          "[authz_model][validate]") {
    CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]); // Response:Read
    decl.operation = Operation::Delete; // floor: High
    decl.risk_tier = RiskTier::Low;     // under-declared
    CHECK(!decl.is_valid());
    decl.risk_tier = RiskTier::High; // at the floor
    CHECK(decl.is_valid());
}

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects both twins absent with no "
          "recorded exception",
          "[authz_model][validate]") {
    CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]);
    decl.has_rest_twin = false;
    decl.has_mcp_twin = false;
    CHECK(!decl.is_valid());

    decl.twin_exception_ref = "ADR-1005-ledger#42";
    CHECK(decl.is_valid()); // a recorded exception makes an absent twin valid
}

TEST_CASE("authz_model: is_valid rejects EITHER single twin missing without an exception (BR-005)",
          "[authz_model][validate]") {
    // The contract is BOTH twins present unless excepted -- not merely "at
    // least one". Each single-missing shape must be invalid on its own, and an
    // exception must rescue each.
    {
        CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]);
        decl.has_rest_twin = true;
        decl.has_mcp_twin = false;
        CHECK(!decl.is_valid()); // MCP twin missing
        decl.twin_exception_ref = "ADR-1005-ledger#7";
        CHECK(decl.is_valid());
    }
    {
        CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]);
        decl.has_rest_twin = false;
        decl.has_mcp_twin = true;
        CHECK(!decl.is_valid()); // REST twin missing
        decl.twin_exception_ref = "ADR-1005-ledger#8";
        CHECK(decl.is_valid());
    }
    {
        CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]);
        decl.has_rest_twin = true;
        decl.has_mcp_twin = true;
        CHECK(decl.is_valid()); // both present, no exception needed
    }
}

TEST_CASE("authz_model: is_valid fails closed on an un-supplied classification/A4/agentic field "
          "(CDX-P2-004)",
          "[authz_model][validate]") {
    // ADR-0033 §2 "never defaults to read": because operation/mcp_tier_class are
    // plain enums whose zero value IS Read, a decoder that fails to populate them
    // must NOT leave a silently-Read capability registered. The presence
    // sentinels make a default-constructed or partially-decoded declaration
    // invalid.
    SECTION("a default-constructed declaration is invalid") {
        CapabilityDeclaration blank; // every sentinel false by default
        CHECK(!blank.is_valid());
    }
    SECTION("each sentinel is independently load-bearing") {
        {
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            REQUIRE(d.is_valid());
            d.classification_explicit = false;
            CHECK(!d.is_valid());
        }
        {
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            d.a4_envelope_declared = false;
            CHECK(!d.is_valid());
        }
        {
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            d.agentic_context_annotated = false;
            CHECK(!d.is_valid());
        }
    }
    SECTION("an out-of-range enum (bad decode cast) is rejected") {
        {
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            d.operation = static_cast<Operation>(0xFF);
            CHECK(!d.is_valid());
        }
        {
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            d.mcp_tier_class = static_cast<McpTierClass>(0xFF);
            CHECK(!d.is_valid());
        }
        {
            // CDX-R2-005: risk_tier needs a ceiling, not just the floor check.
            CapabilityDeclaration d = from_seed(kSeedCatalogue[0]);
            d.risk_tier = static_cast<RiskTier>(0xFF);
            CHECK(!d.is_valid());
        }
    }
}

TEST_CASE("authz_model: min_risk_tier_for never floors below Low, never above High",
          "[authz_model][validate]") {
    CHECK(min_risk_tier_for(Operation::Read) == RiskTier::Low);
    CHECK(min_risk_tier_for(Operation::Write) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Execute) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Attest) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Rotate) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Delete) == RiskTier::High);
    CHECK(min_risk_tier_for(Operation::Approve) == RiskTier::High);
    CHECK(min_risk_tier_for(Operation::Push) == RiskTier::High);
}

// ── 2. Composition with RbacStore's public resolver-backed API ──────────
// Mirrors test_list_read_confinement.cpp's fixture pattern, for
// Execution:Execute specifically (the #1788 fix's securable/operation).

namespace {

/// A two-store rig with a small management-group tree, custom allow/deny
/// Execution:Execute roles, and RBAC enforcement ON.
///
///   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
///      └─ C2
///
/// Members: a_p∈P, a_c1∈C1, a_c2∈C2, a_s∈S.
struct Rig {
    /// ADR-0041/ADR-0042: RbacStore and ManagementGroupStore are both
    /// Postgres-only — the SQLite `":memory:"`/temp-file constructors this
    /// fixture used are gone. Both bundles SKIP the enclosing TEST_CASE when
    /// YUZU_TEST_POSTGRES_DSN is unset, so every case that constructs a Rig
    /// carries the [pg] tag (same contract as test_list_read_confinement.cpp,
    /// whose fixture pattern this mirrors).
    yuzu::test::RbacStorePg rbac_bundle;
    yuzu::server::RbacStore& rbac = *rbac_bundle;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::server::ManagementGroupStore& mgmt = *mgmt_bundle;
    std::string gP, gC1, gC2, gS;

    Rig() {
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"ExecReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecReader", "Execution", "Execute", "allow"}).has_value());
        REQUIRE(rbac.create_role({"ExecDenier", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecDenier", "Execution", "Execute", "deny"}).has_value());

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
        yuzu::server::ManagementGroup g;
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

/// Resolve the facts from REAL stores, then hand them to the PRODUCTION
/// composer `authz::compose_exec_visible`.
///
/// This mirrors only the LOOKUPS `ServerImpl::derive_exec_visible` performs.
/// The DECISION — crucially the CDX-001 precedence, that a service-scoped token
/// is resolved first and is never unfiltered — belongs to the production
/// function, so deleting that branch there FAILS these tests.
///
/// An earlier revision of this file re-implemented the decision instead, split
/// across two helpers, one of which took no `RbacStore` at all. The precedence
/// was therefore composed by neither, and reinstating CDX-001 in production left
/// every case here green — a false-green offered as closure evidence for a
/// blocking finding. Do not reintroduce a local copy of the ordering.
VisibleSet resolve_and_compose(const yuzu::server::RbacStore& rbac, const std::string& user,
                               yuzu::server::ManagementGroupStore* mgmt,
                               yuzu::server::TagStore* tags = nullptr,
                               const std::string& token_scope_service = {}) {
    yuzu::server::authz::ExecVisibleFacts f;
    f.service_scoped = !token_scope_service.empty();
    if (f.service_scoped) {
        if (tags) {
            // ADR-0050 typed read: a degraded store leaves service_tagged
            // nullopt (deny-all), same as the production seam.
            if (auto svc = tags->agents_with_tag("service", token_scope_service))
                f.service_tagged = std::unordered_set<std::string>(svc->begin(), svc->end());
        }
        // tags == nullptr -> service_tagged stays nullopt -> fail closed.
        return yuzu::server::authz::compose_exec_visible(f);
    }
    f.global_grant = rbac.check_permission(user, "Execution", "Execute");
    if (auto v = rbac.visible_agents_for_permission(user, "Execution", "Execute", mgmt))
        f.scoped_visible = std::unordered_set<std::string>(v->begin(), v->end());
    return yuzu::server::authz::compose_exec_visible(f);
}

/// Non-service-token spelling, kept so the group-arm cases below read plainly.
VisibleSet compose_exec_visible(const yuzu::server::RbacStore& rbac, const std::string& user,
                                yuzu::server::ManagementGroupStore* mgmt) {
    return resolve_and_compose(rbac, user, mgmt);
}

} // namespace

// CDX-001, store-free arm. Deliberately UNTAGGED so it runs everywhere,
// including a dev box with no Postgres.
//
// The `[pg]` sibling below proves the same precedence against real stores, but
// porting this fixture to Postgres (ADR-0042) meant the single highest-value
// assertion in the file — that a service-scoped token is never unfiltered even
// when its minter holds a global grant — would SKIP wherever a database is
// absent, which is most local runs. The precedence lives in the pure production
// composer, so it can be asserted with no stores at all: hand
// `compose_exec_visible` the facts directly. Deleting the CDX-001 branch from
// production fails THIS case with no database in sight.
TEST_CASE("authz_model #1788: a service-scoped token is narrowed even when the minter holds a "
          "GLOBAL grant (CDX-001 precedence, store-free)",
          "[authz_model][1788][service]") {
    yuzu::server::authz::ExecVisibleFacts f;
    f.service_scoped = true;
    f.service_tagged = std::unordered_set<std::string>{"a_svcA1", "a_svcA2"};
    f.global_grant = true; // THE VECTOR: the minting principal is a global admin
    f.elevated = true;     // and JIT-elevated, the other full-fleet bypass

    auto visible = yuzu::server::authz::compose_exec_visible(f);
    REQUIRE(visible.has_value()); // never unfiltered, DESPITE both bypasses
    CHECK(visible->contains("a_svcA1"));
    CHECK(!visible->contains("a_svcB1"));

    SECTION("a degraded tag store fails closed to deny-all, never unfiltered") {
        f.service_tagged = std::nullopt; // store unavailable
        auto broken = yuzu::server::authz::compose_exec_visible(f);
        REQUIRE(broken.has_value());
        CHECK(broken->empty());
    }

    SECTION("the SAME facts without the token scope are unfiltered — the token, not the "
            "user, is what narrows") {
        f.service_scoped = false;
        f.service_tagged.reset();
        CHECK_FALSE(yuzu::server::authz::compose_exec_visible(f).has_value());
    }
}

TEST_CASE("authz_model #1788: a service-scoped token narrows to its service, over a global grant "
          "(CDX-001, live arm)",
          "[pg][authz_model][1788][service]") {
    yuzu::test::TagStorePg tag_bundle;
    yuzu::server::TagStore& tags = *tag_bundle;
    REQUIRE(tags.set_tag("a_svcA1", "service", "serviceA").has_value());
    REQUIRE(tags.set_tag("a_svcA2", "service", "serviceA").has_value());
    REQUIRE(tags.set_tag("a_svcB1", "service", "serviceB").has_value());

    // THE CDX-001 VECTOR, and the reason this needs a REAL RbacStore rather
    // than a tag store alone: the minting principal holds a GLOBAL
    // Execution:Execute grant. BR-001 confined service tokens only inside the
    // `!unfiltered` branch, so this exact combination came out unfiltered and
    // reached the whole fleet. The token must win over the grant.
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "svc_admin", "ExecReader"}).has_value()); // GLOBAL allow
    REQUIRE(r.rbac.check_permission("svc_admin", "Execution", "Execute")); // grant is real

    auto visible = resolve_and_compose(r.rbac, "svc_admin", &r.mgmt, &tags, "serviceA");
    REQUIRE(visible.has_value()); // never unfiltered, DESPITE the global grant
    CHECK(visible->contains("a_svcA1"));
    CHECK(visible->contains("a_svcA2"));
    CHECK(!visible->contains("a_svcB1"));

    SECTION("the same principal WITHOUT the token scope is unfiltered — proving the "
            "token, not the user, is what narrows") {
        auto unscoped = resolve_and_compose(r.rbac, "svc_admin", &r.mgmt);
        CHECK_FALSE(unscoped.has_value()); // nullopt == unfiltered
    }

    // Each of the four arms then intersects its resolved targets against it via
    // the same in_scope/filter_to_scope primitive the route uses — so naming a
    // serviceB device in agent_ids (the most direct arm) drops it.
    const std::vector<std::string> requested{"a_svcA1", "a_svcB1"};
    auto sent = filter_to_scope(requested, visible);
    CHECK(contains(sent, "a_svcA1"));
    CHECK(!contains(sent, "a_svcB1"));

    SECTION("a null/unavailable tag store fails closed to the empty set, never unfiltered") {
        auto broken = resolve_and_compose(r.rbac, "svc_admin", &r.mgmt, nullptr, "serviceA");
        REQUIRE(broken.has_value());
        CHECK(broken->empty());
    }
}

TEST_CASE("authz_model composition: global allow ⇒ unfiltered (#1715(b))",
          "[pg][authz_model][compose][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "bob", "ExecReader"}).has_value()); // GLOBAL allow
    r.group_assign(r.gC2, "bob", "ExecDenier"); // a group deny must NOT carve out

    auto visible = compose_exec_visible(r.rbac, "bob", &r.mgmt);
    CHECK(!visible.has_value()); // nullopt == unfiltered
    CHECK(in_scope(visible, "a_s")); // outside every group, still admitted
}

TEST_CASE("authz_model composition: global deny + group allow ⇒ scoped (additive, #1715(a))",
          "[pg][authz_model][compose][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "carol", "ExecDenier"}).has_value()); // GLOBAL deny
    r.group_assign(r.gP, "carol", "ExecReader");                              // group allow

    auto visible = compose_exec_visible(r.rbac, "carol", &r.mgmt);
    REQUIRE(visible.has_value());
    CHECK(visible->contains("a_p"));
    CHECK(visible->contains("a_c1")); // descendant of P
    CHECK(!visible->contains("a_s")); // outside P's subtree
}

TEST_CASE("authz_model composition: no grant anywhere ⇒ empty visible set (fail-closed)",
          "[pg][authz_model][compose]") {
    Rig r;
    auto visible = compose_exec_visible(r.rbac, "nobody", &r.mgmt);
    REQUIRE(visible.has_value());
    CHECK(visible->empty());
}

TEST_CASE("authz_model composition: null mgmt store ⇒ empty visible set, never unfiltered",
          "[authz_model][compose][fail-closed][pg]") {
    yuzu::test::RbacStorePg rbac_bundle;
    yuzu::server::RbacStore& rbac = *rbac_bundle;
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.create_role({"ExecReader2", "", false, 0}).has_value());
    REQUIRE(rbac.set_permission({"ExecReader2", "Execution", "Execute", "allow"}).has_value());
    // "alice" has no GLOBAL grant; her only route to a visible set is the
    // (here, unavailable) scoped resolver — a store error must narrow to
    // nothing, never fall through to unfiltered.
    auto visible = compose_exec_visible(rbac, "alice", nullptr);
    REQUIRE(visible.has_value());
    CHECK(visible->empty());
}

// ── Negative tests: each of the four dispatch-arm shapes ─────────────────
// `in_scope`/`filter_to_scope` is the ONE primitive `server.cpp` calls for
// all four /api/command arms; these exercise it against each arm's
// characteristic already-resolved target-set shape.

TEST_CASE("authz_model #1788: Ids arm — an explicit agent_ids list drops a hidden device",
          "[pg][authz_model][1788][ids]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2 (not a_s)
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    const std::vector<std::string> requested{"a_p", "a_s"}; // a_s is OUTSIDE the group
    auto filtered = filter_to_scope(requested, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(!contains(filtered, "a_s")); // #1788: hidden device never reached
}

TEST_CASE("authz_model #1788: Group arm — resolved members outside scope are dropped",
          "[pg][authz_model][1788][group]") {
    Rig r;
    r.group_assign(r.gC1, "scoped_op", "ExecReader"); // visible: only a_c1
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates a Group-arm dispatch to a DIFFERENT group (C2) than the one
    // the operator is scoped to — every resolved member is out of scope.
    const std::vector<std::string> group_members{"a_c2"};
    auto filtered = filter_to_scope(group_members, visible);
    CHECK(filtered.empty());
}

TEST_CASE("authz_model #1788: Scope arm — evaluate_scope's matched ids are narrowed",
          "[pg][authz_model][1788][scope]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates a scope expression (e.g. a broad tag match) that resolved
    // to devices both inside AND outside the operator's confinement.
    const std::vector<std::string> matched_ids{"a_p", "a_c2", "a_s"};
    auto filtered = filter_to_scope(matched_ids, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(contains(filtered, "a_c2"));
    CHECK(!contains(filtered, "a_s")); // #1788: outside confinement, dropped
}

TEST_CASE("authz_model #1788: Broadcast arm — __all__ narrows to the visible set, never widens",
          "[pg][authz_model][1788][broadcast]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates the full known-agent-id list a broadcast would otherwise
    // reach unfiltered.
    const std::vector<std::string> all_known_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_known_ids, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(contains(filtered, "a_c1"));
    CHECK(contains(filtered, "a_c2"));
    CHECK(!contains(filtered, "a_s")); // #1788: broadcast no longer reaches everyone
    CHECK(filtered.size() == 3);
}

TEST_CASE("authz_model #1788: Broadcast arm — a global grant stays truly unfiltered",
          "[pg][authz_model][1788][broadcast]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "admin_op", "ExecReader"}).has_value()); // GLOBAL
    auto visible = compose_exec_visible(r.rbac, "admin_op", &r.mgmt);
    CHECK(!visible.has_value());

    const std::vector<std::string> all_known_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_known_ids, visible);
    CHECK(filtered == all_known_ids); // unchanged — no regression for a global admin
}

TEST_CASE("authz_model #1788: in_scope agrees with filter_to_scope per id",
          "[pg][authz_model][1788]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader");
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    const std::vector<std::string> all_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_ids, visible);
    for (const auto& id : all_ids) {
        INFO("id=" << id);
        CHECK(in_scope(visible, id) == contains(filtered, id));
    }
}

// ── meet(): the new list-read gate's composition primitive ─────────────────
//
// Store-free, deliberately UNTAGGED so it runs everywhere — meet() is pure
// set algebra with no store dependency at all, and this is the only place
// its lattice properties are pinned. These pin out the exact BR-001 bug
// shape `deny_all()`'s own comment warns about: a naive
// `if (!a || !b) return nullopt;` would make TOP contagious through a meet
// with a deny-all set, instead of deny-all correctly absorbing.

TEST_CASE("authz_model meet: nullopt (TOP) is the identity on either side",
          "[authz_model][meet]") {
    using yuzu::server::authz::meet;
    yuzu::server::authz::VisibleSet s{std::unordered_set<std::string>{"a_1", "a_2"}};

    auto left_top = meet(std::nullopt, s);
    REQUIRE(left_top.has_value());
    CHECK(*left_top == *s);

    auto right_top = meet(s, std::nullopt);
    REQUIRE(right_top.has_value());
    CHECK(*right_top == *s);

    // both TOP -> TOP
    CHECK_FALSE(meet(std::nullopt, std::nullopt).has_value());
}

TEST_CASE("authz_model meet: deny_all() absorbs — never resurrected to TOP",
          "[authz_model][meet]") {
    using yuzu::server::authz::deny_all;
    using yuzu::server::authz::meet;
    yuzu::server::authz::VisibleSet s{std::unordered_set<std::string>{"a_1", "a_2"}};

    auto with_top = meet(deny_all(), std::nullopt);
    REQUIRE(with_top.has_value());
    CHECK(with_top->empty()); // the load-bearing case: TOP must NOT win here

    auto with_set = meet(deny_all(), s);
    REQUIRE(with_set.has_value());
    CHECK(with_set->empty());
}

TEST_CASE("authz_model meet: two present sets intersect", "[authz_model][meet]") {
    using yuzu::server::authz::meet;
    yuzu::server::authz::VisibleSet a{std::unordered_set<std::string>{"a_1", "a_2", "a_3"}};
    yuzu::server::authz::VisibleSet b{std::unordered_set<std::string>{"a_2", "a_3", "a_4"}};

    auto result = meet(a, b);
    REQUIRE(result.has_value());
    CHECK(result->size() == 2);
    CHECK(result->contains("a_2"));
    CHECK(result->contains("a_3"));
    CHECK_FALSE(result->contains("a_1"));
    CHECK_FALSE(result->contains("a_4"));

    SECTION("disjoint sets meet to present-but-empty, never nullopt") {
        yuzu::server::authz::VisibleSet c{std::unordered_set<std::string>{"a_9"}};
        auto disjoint = meet(a, c);
        REQUIRE(disjoint.has_value());
        CHECK(disjoint->empty());
    }
}

TEST_CASE("authz_model meet: commutative and associative", "[authz_model][meet]") {
    using yuzu::server::authz::meet;
    yuzu::server::authz::VisibleSet a{std::unordered_set<std::string>{"a_1", "a_2", "a_3"}};
    yuzu::server::authz::VisibleSet b{std::unordered_set<std::string>{"a_2", "a_3", "a_4"}};
    yuzu::server::authz::VisibleSet c{std::unordered_set<std::string>{"a_3", "a_4", "a_5"}};

    CHECK(meet(a, b) == meet(b, a)); // commutative

    auto left_assoc = meet(meet(a, b), c);
    auto right_assoc = meet(a, meet(b, c));
    REQUIRE(left_assoc.has_value());
    REQUIRE(right_assoc.has_value());
    CHECK(*left_assoc == *right_assoc); // associative
    CHECK(left_assoc->size() == 1);
    CHECK(left_assoc->contains("a_3"));
}
