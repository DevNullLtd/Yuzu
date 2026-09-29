/**
 * test_compliance_api.cpp — the THIRD per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4, copying the merged
 * `network_api`/`verify_api` templates). `LocalComplianceApi`
 * (compliance_api.cpp) is the store-reaching assembly previously duplicated
 * inline between `compliance_routes.cpp`'s REST handlers and
 * `mcp_server.cpp`'s MCP tool dispatch — moved verbatim behind the
 * `ComplianceApi` seam so it is independently testable. Every behaviour the
 * move promises to preserve gets its own case: the thin per-method forwards
 * to `PolicyStore`, the `get_policy` three-read composite assembly
 * (policy + compliance_summary + fail-soft fragment lookup for
 * `remediation_available`, both true and false), the not-found vs degraded
 * distinction, fleet_compliance, compliance_summary, and
 * policy_agent_statuses. Only reached through the public `ComplianceApi`
 * interface — `LocalComplianceApi` itself is deliberately private to
 * compliance_api.cpp, so this file uses only `make_local_compliance_api`,
 * matching how a real presentation/MCP caller will use it.
 */

#include "compliance_api_local.hpp"

#include "policy_store.hpp"

#include "../test_helpers.hpp"

#include <stdexcept>
#include <string>

#include <catch2/catch_test_macros.hpp>

using yuzu::server::ComplianceSummary;
using yuzu::server::FleetCompliance;
using yuzu::server::FragmentQuery;
using yuzu::server::make_local_compliance_api;
using yuzu::server::Policy;
using yuzu::server::PolicyFragment;
using yuzu::server::PolicyQuery;
using yuzu::server::PolicyReadError;
using yuzu::server::PolicyStore;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp) — mirrors
// policy_store_tpl in test_policy_store.cpp.
yuzu::test::PgTestTemplate compliance_api_tpl{"complianceapi", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PolicyStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("compliance_api template: failed to migrate");
}};

// A fragment WITH a fix_instruction -- remediation_available should be true.
const std::string kFragmentWithFix = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check And Fix Service
description: Verify and restart a Windows service
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
  fix:
    instruction: start_service
    parameters:
      service_name: "{{inputs.service}}"
)";

// A fragment with NO fix_instruction -- remediation_available should be false.
const std::string kFragmentNoFix = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check Only Service
description: Verify a Windows service is running, no remediation
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

std::string make_policy_yaml(const std::string& fragment_id,
                             const std::string& name = "Compliance API Test Policy") {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: )" +
          name + R"(
description: A compliance-api test policy
fragment: )" +
          fragment_id + R"(
scope: "tags.env == 'production'"
inputs:
  service: WinRM
triggers:
  - type: interval
    interval_seconds: 300
)";
}

} // namespace

TEST_CASE("ComplianceApi: list_fragments forwards to the store, empty and non-empty",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    // Empty before any fragment is created.
    auto empty = api->list_fragments(FragmentQuery{});
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());

    auto listed = api->list_fragments(FragmentQuery{});
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].id == frag.value());
}

TEST_CASE("ComplianceApi: list_policies forwards to the store, empty and non-empty",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto empty = api->list_policies(PolicyQuery{});
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto listed = api->list_policies(PolicyQuery{});
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].id == pol.value());
}

TEST_CASE("ComplianceApi: get_policy composite -- remediation_available true when the "
          "bound fragment has a fix_instruction",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value(), "With Fix"));
    REQUIRE(pol.has_value());

    auto result = api->get_policy(pol.value());
    REQUIRE(result.has_value());
    REQUIRE(result->has_value());
    CHECK((*result)->policy.id == pol.value());
    CHECK((*result)->policy.name == "With Fix");
    CHECK((*result)->remediation_available);
    CHECK((*result)->summary.policy_id == pol.value());
}

TEST_CASE("ComplianceApi: get_policy composite -- remediation_available false when the "
          "bound fragment has no fix_instruction",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto frag = store.create_fragment(kFragmentNoFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value(), "No Fix"));
    REQUIRE(pol.has_value());

    auto result = api->get_policy(pol.value());
    REQUIRE(result.has_value());
    REQUIRE(result->has_value());
    CHECK_FALSE((*result)->remediation_available);
}

TEST_CASE("ComplianceApi: get_policy on an unknown id is a present-but-empty optional, "
          "not a degrade",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto result = api->get_policy("no-such-policy");
    REQUIRE(result.has_value()); // present (not kDegraded) ...
    CHECK_FALSE(result->has_value()); // ... but nullopt (not found)
}

TEST_CASE("ComplianceApi: fleet_compliance forwards to the store",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-2", "non_compliant").has_value());

    auto fc = api->fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->total_checks == 2);
    CHECK(fc->compliant == 1);
    CHECK(fc->non_compliant == 1);
}

TEST_CASE("ComplianceApi: compliance_summary forwards to the store",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-2", "unknown").has_value());

    auto cs = api->compliance_summary(pol.value());
    REQUIRE(cs.has_value());
    CHECK(cs->policy_id == pol.value());
    CHECK(cs->compliant == 1);
    CHECK(cs->unknown == 1);
    CHECK(cs->total == 2);
}

TEST_CASE("ComplianceApi: policy_agent_statuses returns the unfiltered fleet-wide rows",
          "[pg][compliance_api]") {
    YUZU_REQUIRE_PG_DB_TPL(db, compliance_api_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto frag = store.create_fragment(kFragmentWithFix);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-2", "non_compliant").has_value());

    auto statuses = api->policy_agent_statuses(pol.value());
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 2);
    bool has_a1 = false, has_a2 = false;
    for (const auto& s : *statuses) {
        CHECK(s.policy_id == pol.value());
        if (s.agent_id == "agent-1")
            has_a1 = true;
        if (s.agent_id == "agent-2")
            has_a2 = true;
    }
    CHECK(has_a1);
    CHECK(has_a2);
}

TEST_CASE("ComplianceApi: a genuinely unreachable store degrades (kDegraded), never an "
          "empty result",
          "[pg][compliance_api]") {
    // Mirrors PolicyStore's own !is_open() construction-failure posture
    // (test_policy_store.cpp's "reports !is_open on an unreachable pool"):
    // an unreachable pool makes every PolicyStore read return kDegraded, and
    // LocalComplianceApi forwards that verbatim rather than collapsing it
    // into an empty list/optional.
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    PolicyStore store{pool};
    REQUIRE_FALSE(store.is_open());

    auto api = make_local_compliance_api(store);

    auto fragments = api->list_fragments(FragmentQuery{});
    REQUIRE_FALSE(fragments.has_value());
    CHECK(fragments.error() == PolicyReadError::kDegraded);

    auto policies = api->list_policies(PolicyQuery{});
    REQUIRE_FALSE(policies.has_value());
    CHECK(policies.error() == PolicyReadError::kDegraded);

    auto policy = api->get_policy("any-id");
    REQUIRE_FALSE(policy.has_value());
    CHECK(policy.error() == PolicyReadError::kDegraded);

    auto fc = api->fleet_compliance();
    REQUIRE_FALSE(fc.has_value());
    CHECK(fc.error() == PolicyReadError::kDegraded);

    auto cs = api->compliance_summary("any-id");
    REQUIRE_FALSE(cs.has_value());
    CHECK(cs.error() == PolicyReadError::kDegraded);

    auto statuses = api->policy_agent_statuses("any-id");
    REQUIRE_FALSE(statuses.has_value());
    CHECK(statuses.error() == PolicyReadError::kDegraded);
}
