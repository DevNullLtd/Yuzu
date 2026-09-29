/**
 * test_policy_store.cpp -- Unit tests for PolicyStore (ADR-0056, Postgres)
 *
 * Covers: fail-closed construction, Fragment CRUD, Policy CRUD, compliance
 * tracking, cache invalidation, YAML parsing edge cases, cascading deletes,
 * and claim_due_policies (the ADR-0056 headline multi-replica dispatch
 * design) — single-instance coverage here; the two-instance dispatch-dedup
 * regression test lives in test_policy_evaluator.cpp alongside the
 * evaluator that drives it.
 *
 * No legacy-SQLite backfill coverage: migrate_from_sqlite() was retired
 * (no production fleet ever ran the pre-Postgres build).
 *
 * Born-on-Postgres migrated store (ADR-0012 §1, split posture — see
 * policy_store.hpp). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset,
 * fails when set but broken (test_helpers.hpp skip-vs-fail contract).
 * Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the construction case uses
 * YUZU_REQUIRE_PG_DB, per that macro's plain-migration-test carve-out.
 */

#include "policy_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// ---- YAML helpers ----------------------------------------------------------

static const std::string kCheckOnlyFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check Service Running
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kFullFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-full-001
displayName: Full Fragment
description: Fragment with check, fix, and postCheck
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
  postCheck:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kCheckOnlyNoFix = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-check-only
displayName: Check Only Fragment
description: A fragment with only a check section
spec:
  check:
    instruction: check_disk_space
    compliance: "result.free_gb > 10"
    parameters:
      drive: C
)";

// Returns a Policy YAML that references the given fragment ID
static std::string make_policy_yaml(const std::string& fragment_id,
                                     const std::string& name = "Test Policy") {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: )" +
           name + R"(
description: A test policy
fragment: )" +
           fragment_id + R"(
scope: "tags.env == 'production'"
inputs:
  service: WinRM
triggers:
  - type: interval
    interval_seconds: 300
  - type: file_change
    path: "C:\\config.yaml"
managementGroups:
  - "all-devices"
  - "windows-servers"
)";
}

namespace {

yuzu::test::PgTestTemplate policy_store_tpl{
    "policystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        PolicyStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("policy_store template: failed to migrate");
    }};

} // namespace

// ============================================================================
// Construction fail-closed
// ============================================================================

TEST_CASE("PolicyStore reports !is_open on a migration failure", "[policy_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA policy_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE policy_store.policy_fragments (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("PolicyStore reports !is_open on an unreachable pool", "[policy_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    PolicyStore store{pool};
    CHECK_FALSE(store.is_open());
}

// ============================================================================
// Fragment CRUD
// ============================================================================

TEST_CASE("PolicyStore: open against Postgres", "[policy_store][pg][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
}

TEST_CASE("PolicyStore: create fragment from YAML", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->name == "Check Service Running");
    CHECK((*frag)->description == "Verify a Windows service is running");
    CHECK((*frag)->check_instruction == "get_service_status");
    CHECK((*frag)->check_compliance == "result.status == 'running'");
    CHECK((*frag)->created_at > 0);
    CHECK((*frag)->updated_at > 0);
}

TEST_CASE("PolicyStore: create fragment with explicit ID", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());
    CHECK(result.value() == "frag-full-001");

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->name == "Full Fragment");
}

TEST_CASE("PolicyStore: query fragments", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    (void)store.create_fragment(kCheckOnlyFragment);
    (void)store.create_fragment(kFullFragment);
    (void)store.create_fragment(kCheckOnlyNoFix);

    auto all = store.query_fragments();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 3);

    FragmentQuery q;
    q.name_filter = "Check";
    auto filtered = store.query_fragments(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 2); // "Check Service Running" and "Check Only Fragment"

    FragmentQuery q2;
    q2.limit = 1;
    auto limited = store.query_fragments(q2);
    REQUIRE(limited.has_value());
    REQUIRE(limited->size() == 1);
}

TEST_CASE("PolicyStore: delete fragment", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());

    CHECK(store.delete_fragment(result.value()) == true);
    auto gone = store.get_fragment(result.value());
    REQUIRE(gone.has_value());
    CHECK(*gone == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_fragment(result.value()) == false);
}

TEST_CASE("PolicyStore: create fragment with duplicate ID", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r1 = store.create_fragment(kFullFragment);
    REQUIRE(r1.has_value());
    CHECK(r1.value() == "frag-full-001");

    // Attempt duplicate — fragment has both duplicate id and duplicate
    // displayName. The #396 name guard fires first (and is more informative
    // than the id PK-conflict), so the error carries the "conflict:" prefix
    // routes use to map to HTTP 409.
    auto r2 = store.create_fragment(kFullFragment);
    REQUIRE(!r2.has_value());
    CHECK(is_conflict_error(r2.error()));
}

TEST_CASE("PolicyStore: create fragment with empty YAML", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("");
    REQUIRE(!result.has_value());
    CHECK(result.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create fragment with wrong kind", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("kind: Policy\nname: oops\n");
    REQUIRE(!result.has_value());
    CHECK_THAT(result.error(), ContainsSubstring("kind must be 'PolicyFragment'"));
    // Issue #621: error must include a worked example so operators sending
    // partial YAML (or sending `kind` as a request param) get unstuck without
    // having to find the docs separately. The prefix above stays stable so
    // existing scripts that grep on it keep working.
    CHECK_THAT(result.error(), ContainsSubstring("apiVersion: yuzu.io/v1alpha1"));
    CHECK_THAT(result.error(), ContainsSubstring("docs/user-manual/policy-engine.md"));
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create fragment with missing kind", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!result.has_value());
    CHECK_THAT(result.error(), ContainsSubstring("kind must be 'PolicyFragment'"));
    CHECK_THAT(result.error(), ContainsSubstring("apiVersion: yuzu.io/v1alpha1"));
    // Governance Gate 7 (consistency S2 / QA SHOULD): docs link must be
    // pinned on this branch too — not just the wrong-kind branch — so the
    // operator-facing UX is symmetric across both `kind`-failure modes.
    CHECK_THAT(result.error(), ContainsSubstring("docs/user-manual/policy-engine.md"));
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: fragment with check only (no fix, no postCheck)",
          "[policy_store][pg][fragment][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->check_instruction == "check_disk_space");
    CHECK((*frag)->check_compliance == "result.free_gb > 10");
    CHECK((*frag)->fix_instruction.empty());
    CHECK((*frag)->fix_parameters == "{}");
    CHECK((*frag)->post_check_instruction.empty());
    CHECK((*frag)->post_check_parameters == "{}");
}

TEST_CASE("PolicyStore: fragment with all three sections", "[policy_store][pg][fragment][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->check_instruction == "get_service_status");
    CHECK((*frag)->check_compliance == "result.status == 'running'");
    CHECK((*frag)->fix_instruction == "start_service");
    CHECK((*frag)->post_check_instruction == "get_service_status");
    CHECK((*frag)->post_check_compliance == "result.status == 'running'");
}

TEST_CASE("PolicyStore: cannot delete fragment referenced by a policy",
          "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag_result = store.create_fragment(kFullFragment);
    REQUIRE(frag_result.has_value());

    auto yaml = make_policy_yaml(frag_result.value());
    auto pol_result = store.create_policy(yaml);
    REQUIRE(pol_result.has_value());

    CHECK(store.delete_fragment(frag_result.value()) == false);

    auto still_there = store.get_fragment(frag_result.value());
    REQUIRE(still_there.has_value());
    CHECK(still_there->has_value());
}

// ============================================================================
// Policy CRUD
// ============================================================================

TEST_CASE("PolicyStore: create policy from YAML", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto yaml = make_policy_yaml(frag.value(), "My Service Policy");
    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->name == "My Service Policy");
    CHECK((*pol)->description == "A test policy");
    CHECK((*pol)->fragment_id == frag.value());
    CHECK((*pol)->enabled == true);
    CHECK((*pol)->created_at > 0);

    REQUIRE((*pol)->inputs.size() == 1);
    CHECK((*pol)->inputs[0].key == "service");
    CHECK((*pol)->inputs[0].value == "WinRM");

    REQUIRE((*pol)->triggers.size() == 2);
    bool has_interval = false, has_file_change = false;
    for (const auto& t : (*pol)->triggers) {
        if (t.trigger_type == "interval")
            has_interval = true;
        if (t.trigger_type == "file_change")
            has_file_change = true;
    }
    CHECK(has_interval);
    CHECK(has_file_change);

    REQUIRE((*pol)->management_groups.size() == 2);
    CHECK((*pol)->management_groups[0] == "all-devices");
    CHECK((*pol)->management_groups[1] == "windows-servers");
}

TEST_CASE("PolicyStore: scope.selector mapping lowers to an expression (PR-E)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Selector Policy
fragment: )" + frag.value() +
                       R"(
scope:
  selector:
    platform: Windows
    tags:
      - prod
)";
    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());
    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->scope_expression == "ostype == \"windows\" AND EXISTS tag:prod");
}

TEST_CASE("PolicyStore: scope.fromResultSet is rejected for policies (deferred to PR-E2)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: RS Policy
fragment: )" + frag.value() +
                       R"(
scope:
  fromResultSet: rs_abc
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK_THAT(result.error(), ContainsSubstring("fromResultSet"));
}

TEST_CASE("PolicyStore: scalar scope.fromResultSet is also rejected (#1221 MEDIUM-1)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Scalar RS Policy
fragment: )" + frag.value() +
                       R"(
scope: from_result_set:rs_abc
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK_THAT(result.error(), ContainsSubstring("fromResultSet"));

    std::string yaml2 = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Composed RS Policy
fragment: )" + frag.value() +
                        R"(
scope: ostype == "windows" AND from_result_set:rs_abc
)";
    auto result2 = store.create_policy(yaml2);
    REQUIRE_FALSE(result2.has_value());
    CHECK_THAT(result2.error(), ContainsSubstring("fromResultSet"));
}

TEST_CASE("PolicyStore: inline flow-mapping scope is rejected (UP-6)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Inline Policy
fragment: )" + frag.value() +
                       R"(
scope: {selector: {platform: windows}}
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK_THAT(result.error(), ContainsSubstring("inline flow-mapping"));
}

TEST_CASE("PolicyStore: query policies with filters", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    (void)store.create_policy(make_policy_yaml(frag.value(), "Alpha Policy"));
    (void)store.create_policy(make_policy_yaml(frag.value(), "Beta Policy"));
    (void)store.create_policy(make_policy_yaml(frag.value(), "Gamma Policy"));

    auto all = store.query_policies();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 3);

    PolicyQuery q;
    q.name_filter = "Alpha";
    auto filtered = store.query_policies(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 1);
    CHECK((*filtered)[0].name == "Alpha Policy");

    PolicyQuery q2;
    q2.fragment_filter = frag.value();
    auto by_frag = store.query_policies(q2);
    REQUIRE(by_frag.has_value());
    CHECK(by_frag->size() == 3);

    PolicyQuery q3;
    q3.limit = 2;
    auto limited = store.query_policies(q3);
    REQUIRE(limited.has_value());
    CHECK(limited->size() == 2);
}

TEST_CASE("PolicyStore: enable and disable policy", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    auto pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == true);

    auto disable_r = store.disable_policy(pol_result.value());
    REQUIRE(disable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == false);

    PolicyQuery q;
    q.enabled_only = true;
    auto enabled = store.query_policies(q);
    REQUIRE(enabled.has_value());
    CHECK(enabled->empty());

    auto enable_r = store.enable_policy(pol_result.value());
    REQUIRE(enable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == true);
}

TEST_CASE("PolicyStore: enable/disable nonexistent policy", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.enable_policy("does-not-exist");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "policy not found");

    auto r2 = store.disable_policy("does-not-exist");
    REQUIRE(!r2.has_value());
    CHECK(r2.error() == "policy not found");
}

TEST_CASE("PolicyStore: delete policy cascades", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    (void)store.update_agent_status(pol_result.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol_result.value(), "agent-2", "non_compliant");

    CHECK(store.delete_policy(pol_result.value()) == true);

    auto gone_pol = store.get_policy(pol_result.value());
    REQUIRE(gone_pol.has_value());
    CHECK(*gone_pol == std::nullopt);

    auto gone_s1 = store.get_agent_status(pol_result.value(), "agent-1");
    REQUIRE(gone_s1.has_value());
    CHECK(*gone_s1 == std::nullopt);
    auto gone_s2 = store.get_agent_status(pol_result.value(), "agent-2");
    REQUIRE(gone_s2.has_value());
    CHECK(*gone_s2 == std::nullopt);

    auto cs = store.get_compliance_summary(pol_result.value());
    REQUIRE(cs.has_value());
    CHECK(cs->total == 0);

    CHECK(store.delete_policy(pol_result.value()) == false);
}

TEST_CASE("PolicyStore: delete policy invalidates the fleet compliance cache "
          "(security-guardian finding, 2026-08-24)",
          "[policy_store][pg][policy]") {
    // delete_policy()'s CASCADE removes this policy's policy_status rows too
    // (security-guardian caught this during the bounded re-review of the K7
    // fix: the other three policy_status writers were fixed to invalidate
    // the cache, this one was missed) — the fleet-compliance aggregate must
    // not keep counting a deleted policy's rows for up to 60s.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());

    // Populate the cache with this policy's data present.
    auto fc1 = store.get_fleet_compliance();
    REQUIRE(fc1.has_value());
    CHECK(fc1->total_checks == 1);

    CHECK(store.delete_policy(pol.value()) == true);

    auto fc2 = store.get_fleet_compliance();
    REQUIRE(fc2.has_value());
    CHECK(fc2->total_checks == 0);
}

TEST_CASE("PolicyStore: create policy with empty YAML", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create policy with wrong kind", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("kind: PolicyFragment\nname: wrong\n");
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("kind must be 'Policy'"));
    // Issue #621: same UX expectation as create_fragment — operators must
    // see a worked example in the error body, not just the prefix.
    CHECK_THAT(r.error(), ContainsSubstring("apiVersion: yuzu.io/v1alpha1"));
    CHECK_THAT(r.error(), ContainsSubstring("docs/user-manual/policy-engine.md"));
    CHECK(r.error().find("kind must be 'Policy'") != std::string::npos);
    CHECK(r.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(r.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy with missing kind", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("kind must be 'Policy'"));
    CHECK_THAT(r.error(), ContainsSubstring("apiVersion: yuzu.io/v1alpha1"));
    CHECK_THAT(r.error(), ContainsSubstring("docs/user-manual/policy-engine.md"));
}

TEST_CASE("PolicyStore: create policy with missing fragment", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto yaml = make_policy_yaml("nonexistent-fragment-id");
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("not found"));
}

TEST_CASE("PolicyStore: create policy without fragment field", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: No Fragment
description: missing fragment field
)";
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("fragment"));
}

// ============================================================================
// Degrade behaviour — detail-query failures (adversarial review, round 2)
// ============================================================================

TEST_CASE("PolicyStore: get_policy/query_policies degrade on a detail-table failure, "
          "never a partial policy",
          "[policy_store][pg][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto yaml = make_policy_yaml(frag.value(), "Detail-Degrade Policy");
    auto pol = store.create_policy(yaml);
    REQUIRE(pol.has_value());

    // Sanity: the policy has real details before the table is dropped.
    auto before = store.get_policy(pol.value());
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());
    REQUIRE((*before)->triggers.size() == 2);

    // OWN clone: drops the triggers table out from under the live store —
    // a reproducible stand-in for a transient connection loss / botched
    // migration (same mechanism test_tag_store.cpp uses).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_triggers CASCADE")};
        REQUIRE(r.ok());
    }

    CHECK_FALSE(store.get_policy(pol.value()).has_value());
    CHECK_FALSE(store.query_policies().has_value());
}

// ============================================================================
// Compliance tracking
// ============================================================================

TEST_CASE("PolicyStore: update and get agent status", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto r = store.update_agent_status(pol.value(), "agent-1", "compliant", "{\"status\":\"ok\"}");
    REQUIRE(r.has_value());

    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->policy_id == pol.value());
    CHECK((*status)->agent_id == "agent-1");
    CHECK((*status)->status == "compliant");
    CHECK((*status)->check_result == "{\"status\":\"ok\"}");
    CHECK((*status)->last_check_at > 0);
}

TEST_CASE("PolicyStore: update agent status overwrites", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "unknown");
    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");

    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->status == "compliant");
}

TEST_CASE("PolicyStore: update agent status with invalid status", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.update_agent_status("pol-1", "agent-1", "garbage");
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("invalid status"));
}

TEST_CASE("PolicyStore: update agent status with empty IDs", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r1 = store.update_agent_status("", "agent-1", "compliant");
    REQUIRE(!r1.has_value());

    auto r2 = store.update_agent_status("pol-1", "", "compliant");
    REQUIRE(!r2.has_value());
}

TEST_CASE("PolicyStore: fix retry cap forces error after 3 fixing transitions",
          "[policy_store][pg][compliance]") {
    // ADR-0056: the retry-cap check folds into the UPSERT itself — this is
    // the regression test for that fold (previously a separate pre-check
    // SELECT, now a CASE inside the same statement).
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // Seed the row via a non-'fixing' write first (the fresh-INSERT branch
    // always starts fix_attempt_count at 0 regardless of status, so seeding
    // with 'fixing' directly would consume one attempt "for free" outside
    // the increment CASE — matches the evaluator's own remediate() flow,
    // which always writes a check verdict before any fix is ever attempted).
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());

    for (int i = 0; i < 3; ++i) {
        auto r = store.update_agent_status(pol.value(), "agent-1", "fixing");
        REQUIRE(r.has_value());
        auto s = store.get_agent_status(pol.value(), "agent-1");
        REQUIRE(s.has_value());
        REQUIRE(s->has_value());
        CHECK((*s)->status == "fixing");
    }
    // 4th attempt exceeds the cap (kMaxFixAttempts=3) and is forced to error.
    auto r = store.update_agent_status(pol.value(), "agent-1", "fixing");
    REQUIRE(r.has_value());
    auto s = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s.has_value());
    REQUIRE(s->has_value());
    CHECK((*s)->status == "error");

    // A compliant result resets the counter — fixing is allowed again.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->status == "fixing");
}

TEST_CASE("PolicyStore: get compliance summary", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-4", "unknown");
    (void)store.update_agent_status(pol.value(), "agent-5", "fixing");
    (void)store.update_agent_status(pol.value(), "agent-6", "error");

    auto cs = store.get_compliance_summary(pol.value());
    REQUIRE(cs.has_value());
    CHECK(cs->policy_id == pol.value());
    CHECK(cs->compliant == 2);
    CHECK(cs->non_compliant == 1);
    CHECK(cs->unknown == 1);
    CHECK(cs->fixing == 1);
    CHECK(cs->error == 1);
    CHECK(cs->total == 6);
}

TEST_CASE("PolicyStore: get compliance summary for empty policy",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto cs = store.get_compliance_summary("nonexistent");
    REQUIRE(cs.has_value());
    CHECK(cs->policy_id == "nonexistent");
    CHECK(cs->total == 0);
    CHECK(cs->compliant == 0);
}

TEST_CASE("PolicyStore: get fleet compliance", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-4", "compliant");

    auto fc = store.get_fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->total_checks == 4);
    CHECK(fc->compliant == 3);
    CHECK(fc->non_compliant == 1);
    // 3/4 = 75%
    CHECK(fc->compliance_pct > 74.9);
    CHECK(fc->compliance_pct < 75.1);
}

TEST_CASE("PolicyStore: get fleet compliance with no data", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto fc = store.get_fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->total_checks == 0);
    CHECK(fc->compliance_pct == 0.0);
}

TEST_CASE("PolicyStore: fleet compliance cache is invalidated on the store's "
          "own writes (adversarial review K7, 2026-08-24)",
          "[policy_store][pg][compliance]") {
    // Regression for the eighth-correction fix: get_fleet_compliance()'s 60s
    // TTL cache was never cleared by update_agent_status/invalidate_policy/
    // invalidate_all_policies, so a status change could read back through
    // the aggregate as stale for up to a minute (ADR-0012 §4 rule 2). This
    // pins that a write immediately followed by a read sees the new value,
    // not the cached one — both calls land well inside the 60s TTL, so a
    // pass here is only possible if the write actually invalidated the
    // cache rather than the TTL happening to have expired.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());

    // Populate the cache with the all-compliant picture.
    auto fc1 = store.get_fleet_compliance();
    REQUIRE(fc1.has_value());
    CHECK(fc1->compliant == 1);
    CHECK(fc1->non_compliant == 0);

    // The store's own write should invalidate that cache entry.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());

    auto fc2 = store.get_fleet_compliance();
    REQUIRE(fc2.has_value());
    CHECK(fc2->compliant == 0);
    CHECK(fc2->non_compliant == 1);
}

TEST_CASE("PolicyStore: get policy agent statuses", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "non_compliant");

    auto statuses = store.get_policy_agent_statuses(pol.value());
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 2);
    CHECK((*statuses)[0].agent_id == "agent-1");
    CHECK((*statuses)[0].status == "compliant");
    CHECK((*statuses)[1].agent_id == "agent-2");
    CHECK((*statuses)[1].status == "non_compliant");
}

TEST_CASE("PolicyStore: fixing status updates last_fix_at", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "non_compliant");
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->last_fix_at == 0);

    (void)store.update_agent_status(pol.value(), "agent-1", "fixing");
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->last_fix_at > 0);
}

// ============================================================================
// Cache invalidation
// ============================================================================

TEST_CASE("PolicyStore: invalidate policy resets statuses", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "error");

    auto r = store.invalidate_policy(pol.value());
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    for (const char* agent : {"agent-1", "agent-2", "agent-3"}) {
        auto s = store.get_agent_status(pol.value(), agent);
        REQUIRE(s.has_value());
        REQUIRE(s->has_value());
        CHECK((*s)->status == "unknown");
    }
}

TEST_CASE("PolicyStore: invalidate policy clears a capped fix_attempt_count "
          "(adversarial review K2, 2026-08-24)",
          "[policy_store][pg][invalidation]") {
    // Regression for the eighth-correction fix: invalidate_policy() only
    // reset `status` to 'unknown', leaving fix_attempt_count at the cap —
    // remediate() dispatches the fix before marking 'fixing' (gov UP-7), so
    // the fix genuinely runs, but the very next update_agent_status('fixing')
    // immediately flipped straight to 'error' because the stale counter was
    // still >= kMaxFixAttempts, misrepresenting a real remediation attempt
    // as already-failed.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // Drive fix_attempt_count to the cap, same as the sibling cap test above.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());
    for (int i = 0; i < 3; ++i)
        REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto capped = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(capped.has_value());
    REQUIRE(capped->has_value());
    CHECK((*capped)->status == "fixing"); // 3rd attempt, still under the cap

    // One more 'fixing' write confirms the cap is live before invalidation.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto pre = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(pre.has_value());
    REQUIRE(pre->has_value());
    CHECK((*pre)->status == "error");

    auto inv = store.invalidate_policy(pol.value());
    REQUIRE(inv.has_value());

    // The next remediation's 'fixing' write must NOT immediately flip back
    // to 'error' — that would mean invalidation didn't actually reset the
    // lifecycle, only the visible status field.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto post = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(post.has_value());
    REQUIRE(post->has_value());
    CHECK((*post)->status == "fixing");
}

TEST_CASE("PolicyStore: invalidate nonexistent policy returns 0",
          "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_policy("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

TEST_CASE("PolicyStore: invalidate empty policy ID", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_policy("");
    REQUIRE(!r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("required"));
}

TEST_CASE("PolicyStore: invalidate all policies", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol1 = store.create_policy(make_policy_yaml(frag.value(), "Policy A"));
    auto pol2 = store.create_policy(make_policy_yaml(frag.value(), "Policy B"));
    REQUIRE(pol1.has_value());
    REQUIRE(pol2.has_value());

    (void)store.update_agent_status(pol1.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol1.value(), "agent-2", "non_compliant");
    (void)store.update_agent_status(pol2.value(), "agent-3", "compliant");

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    auto s1 = store.get_agent_status(pol1.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->status == "unknown");

    auto s3 = store.get_agent_status(pol2.value(), "agent-3");
    REQUIRE(s3.has_value());
    REQUIRE(s3->has_value());
    CHECK((*s3)->status == "unknown");
}

TEST_CASE("PolicyStore: invalidate all with no data returns 0",
          "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

// ============================================================================
// Policy YAML parsing edge cases
// ============================================================================

TEST_CASE("PolicyStore: policy with multiple triggers and groups",
          "[policy_store][pg][policy][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Multi Trigger Policy
description: Policy with many triggers and groups
fragment: )" + frag.value() + R"(
scope: "tags.env == 'prod'"
inputs:
  service: Spooler
  timeout: "60"
triggers:
  - type: interval
    interval_seconds: 600
  - type: file_change
    path: "C:\\config.yaml"
  - type: event_log
    event_source: System
    event_id: "7036"
managementGroups:
  - "all-devices"
  - "windows-servers"
  - "us-east-region"
)";

    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());

    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());

    REQUIRE((*pol)->inputs.size() == 2);
    REQUIRE((*pol)->triggers.size() == 3);
    REQUIRE((*pol)->management_groups.size() == 3);
}

TEST_CASE("PolicyStore: get nonexistent fragment returns nullopt",
          "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_fragment("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent policy returns nullopt", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_policy("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent agent status returns nullopt",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_agent_status("pol", "agent");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

// ── Duplicate-name guard (#396) ──────────────────────────────────────────

TEST_CASE("PolicyStore: duplicate fragment name rejected with conflict prefix",
          "[policy_store][pg][fragment][duplicate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto first = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(first.has_value());

    auto second = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE_FALSE(second.has_value());
    CHECK(is_conflict_error(second.error()));

    auto fragments = store.query_fragments({});
    REQUIRE(fragments.has_value());
    int matches = 0;
    for (const auto& f : *fragments)
        if (f.name == "Check Only Fragment")
            ++matches;
    CHECK(matches == 1);
}

// ============================================================================
// claim_due_policies (ADR-0056) — single-instance coverage
// ============================================================================

TEST_CASE("claim_due_policies claims a due policy once, then not again within the interval",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Claim Test Policy
fragment: )" + frag.value() + R"(
scope: "tags.env == 'prod'"
triggers:
  - type: interval
    interval_seconds: 3600
)";
    auto pol = store.create_policy(yaml);
    REQUIRE(pol.has_value());

    int64_t t0 = 1000000;
    auto claimed1 = store.claim_due_policies(t0, 3600, 1800);
    REQUIRE(claimed1.has_value());
    REQUIRE(claimed1->size() == 1);
    CHECK((*claimed1)[0].id == pol.value());

    // A second claim moments later (still within the 3600s interval) claims
    // nothing — the WHERE-on-conflict guard is the atomic check-and-claim.
    auto claimed2 = store.claim_due_policies(t0 + 10, 3600, 1800);
    REQUIRE(claimed2.has_value());
    CHECK(claimed2->empty());

    // After the interval elapses, it is due again.
    auto claimed3 = store.claim_due_policies(t0 + 3601, 3600, 1800);
    REQUIRE(claimed3.has_value());
    REQUIRE(claimed3->size() == 1);
}

TEST_CASE("claim_due_policies does not claim a disabled policy",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.disable_policy(pol.value()).has_value());

    auto claimed = store.claim_due_policies(1000000, 3600, 1800);
    REQUIRE(claimed.has_value());
    CHECK(claimed->empty());
}

TEST_CASE("claim_due_policies sweeps a stale 'fixing' row back to 'unknown'",
          "[policy_store][pg][claim]") {
    // HA WS-3 3.4 review B2 follow-on: the stranded-'fixing' sweep's
    // staleness cutoff is now authored from Postgres NOW() in-SQL (the SAME
    // authority claim_remediation's own staleness guard uses), NOT the
    // `now` param claim_due_policies otherwise uses for its due-policy
    // interval check — passing a future fake `now` no longer ages this row
    // for the sweep. Simulating staleness means backdating the stored
    // `last_fix_at` directly, same technique as claim_remediation's own
    // `backdate_claim` helper above.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());

    int64_t t0 = 1000000; // the due-policy interval check still reads this param.

    // Within the staleness window (last_fix_at is fresh, just stamped from
    // real NOW() by update_agent_status above): untouched.
    auto claimed1 = store.claim_due_policies(t0, 3600, 1800);
    REQUIRE(claimed1.has_value());
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->status == "fixing");

    // Past the staleness window: backdate last_fix_at (real Postgres NOW()
    // minus 1801s), then the sweep's own NOW()-authored cutoff catches it.
    {
        auto lease = pool.try_acquire_for(std::chrono::milliseconds{2000});
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE policy_store.policy_status SET last_fix_at = "
            "EXTRACT(EPOCH FROM NOW())::bigint - 1801 "
            "WHERE policy_id = $1 AND agent_id = $2",
            std::vector<std::string>{pol.value(), std::string("agent-1")});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto claimed2 = store.claim_due_policies(t0 + 1, 3600, 1800);
    REQUIRE(claimed2.has_value());
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->status == "unknown");
}

TEST_CASE("claim_due_policies sweep does NOT erase a FRESH reclaim of a stranded row "
          "(HA WS-3 3.4 adversarial review C3/K1 — Codex+Kimi)",
          "[policy_store][pg][claim]") {
    // Regression for the sweep-erases-a-live-reclaim race. A reclaim
    // (claim_remediation's ON CONFLICT) refreshes remediation_claim_at + _gen
    // but NOT last_fix_at/status; only the reclaimer's LATER mark-fixing write
    // refreshes last_fix_at. So a row a sibling just reclaimed carries a FRESH
    // claim_at but the dead ex-holder's OLD last_fix_at + status 'fixing'. A
    // sweep gated on last_fix_at ALONE would zero that live claim, freeing the
    // row for a third claimant → duplicate dispatch by two un-paused holders,
    // OUTSIDE the effectively-once residual. The fix gates the sweep on
    // remediation_claim_at freshness too.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // A claims agent-1 and marks it 'fixing' (stamps last_fix_at = NOW), then
    // strands it: backdate BOTH last_fix_at AND remediation_claim_at to well
    // past the window, simulating A dying mid-flight.
    auto claimA = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimA.has_value());
    REQUIRE(claimA->ids.size() == 1);
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing", "", claimA->generation)
                .has_value());
    {
        auto lease = pool.try_acquire_for(std::chrono::milliseconds{2000});
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE policy_store.policy_status SET "
            "  last_fix_at = EXTRACT(EPOCH FROM NOW())::bigint - 1801, "
            "  remediation_claim_at = EXTRACT(EPOCH FROM NOW())::bigint - 1801 "
            "WHERE policy_id = $1 AND agent_id = $2",
            std::vector<std::string>{pol.value(), std::string("agent-1")});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // B reclaims the stranded row: claim_at is refreshed to NOW (FRESH), gen
    // bumped — but status stays 'fixing' and last_fix_at stays 1801s old
    // (claim_remediation touches neither). This is the exact race precondition.
    auto claimB = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimB.has_value());
    REQUIRE(claimB->ids.size() == 1);
    CHECK(claimB->generation != claimA->generation);

    // The leader sweep runs. Pre-fix it matched on the old last_fix_at and
    // zeroed B's fresh claim; the fix's claim-age guard must now EXCLUDE it.
    auto swept = store.claim_due_policies(1000000, 3600, 1800);
    REQUIRE(swept.has_value());

    // B's claim survived: status is still 'fixing' (not reset to 'unknown')...
    auto s = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s.has_value());
    REQUIRE(s->has_value());
    CHECK((*s)->status == "fixing");
    // ...and a third claimant C still gets NOTHING, because B's fresh claim_at
    // was not zeroed. (Pre-fix the sweep zeroed it and C would win — the
    // double-dispatch this test exists to prevent.)
    auto claimC = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimC.has_value());
    CHECK(claimC->ids.empty());
}

// ============================================================================
// claim_remediation / release_remediation_claim (HA WS-3 3.4)
// ============================================================================

// Backdate an existing claim so the pg-NOW() staleness guard sees it as
// aged. Staleness is authored AND adjudicated entirely from Postgres NOW()
// (review B2) -- claim_remediation takes no `now` param -- so simulating a
// stale claim in a test means rewriting the stored `remediation_claim_at`
// directly, not passing a different fake clock value.
static void backdate_claim(PgPool& pool, const std::string& pol, const std::string& agent,
                           int64_t seconds_ago) {
    auto lease = pool.try_acquire_for(std::chrono::milliseconds{2000});
    REQUIRE(lease);
    auto r = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policy_status SET remediation_claim_at = EXTRACT(EPOCH FROM NOW())::bigint - $3::bigint "
        "WHERE policy_id = $1 AND agent_id = $2",
        std::vector<std::string>{pol, agent, std::to_string(seconds_ago)});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

TEST_CASE("claim_remediation claims a fresh target with no pre-existing policy_status row "
          "(the UPSERT branch)",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // "agent-1" has never been checked/fixed for this policy -- no
    // policy_status row exists yet. An UPDATE-only claim would silently
    // claim nothing here; this is the regression test for that.
    auto claimed = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed.has_value());
    REQUIRE(claimed->ids.size() == 1);
    CHECK(claimed->ids[0] == "agent-1");

    auto s = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s.has_value());
    REQUIRE(s->has_value());
    // The fresh-INSERT branch seeds an 'unknown' status row purely to carry
    // the claim -- it must not fabricate a compliance verdict.
    CHECK((*s)->status == "unknown");
}

TEST_CASE("claim_remediation dedups a duplicate agent id in the input list",
          "[policy_store][pg][claim]") {
    // Regression test: a caller-supplied duplicate agent id used to make the
    // INSERT...SELECT...ON CONFLICT DO UPDATE raise cardinality_violation
    // (21000) -- "ON CONFLICT DO UPDATE command cannot affect row a second
    // time" -- and fail the whole claim (fixed via SELECT DISTINCT).
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto claimed = store.claim_remediation(pol.value(), {"agentX", "agentX"}, 1800);
    REQUIRE(claimed.has_value());
    REQUIRE(claimed->ids.size() == 1);
    CHECK(claimed->ids[0] == "agentX");
}

TEST_CASE("claim_remediation refuses a second concurrent claim of the same target",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto claimed1 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed1.has_value());
    REQUIRE(claimed1->ids.size() == 1);

    // Fresh claim, no backdating: a second claim attempt (a sibling
    // replica, or the same replica's own retry) gets nothing back.
    auto claimed2 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed2.has_value());
    CHECK(claimed2->ids.empty());
}

TEST_CASE("claim_remediation refuses a target that has already exhausted the fix retry cap",
          "[policy_store][pg][claim]") {
    // kMaxFixAttempts=3 (policy_store.cpp) -- mirrors the "fix retry cap
    // forces error after 3 fixing transitions" test's own hardcoded 3.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());
    for (int i = 0; i < 4; ++i)
        REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto s = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s.has_value());
    REQUIRE(s->has_value());
    REQUIRE((*s)->status == "error"); // cap tripped -- confirms the setup

    // Even fully unclaimed (remediation_claim_at is still its default 0),
    // the retry-cap guard in claim_remediation's own WHERE clause refuses
    // this target -- there is nothing left to remediate it with.
    auto claimed = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed.has_value());
    CHECK(claimed->ids.empty());
}

TEST_CASE("claim_remediation re-claims a stale claim past the staleness window",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto claimed1 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed1.has_value());
    REQUIRE(claimed1->ids.size() == 1);

    // Just short of the staleness window: still refused.
    backdate_claim(pool, pol.value(), "agent-1", 1799);
    auto claimed_early = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed_early.has_value());
    CHECK(claimed_early->ids.empty());

    // Past the staleness window (the claiming replica presumably died): a
    // fresh claim succeeds, same as `claim_due_policies`'s own stranded-
    // 'fixing' staleness sweep.
    backdate_claim(pool, pol.value(), "agent-1", 1801);
    auto claimed2 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed2.has_value());
    REQUIRE(claimed2->ids.size() == 1);
    CHECK(claimed2->ids[0] == "agent-1");
}

TEST_CASE("release_remediation_claim frees a claim so it can be re-claimed immediately",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto claimed1 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed1.has_value());
    REQUIRE(claimed1->ids.size() == 1);
    const int64_t gen1 = claimed1->generation;

    // Still well within the staleness window -- without an explicit
    // release, a re-claim here would be refused (see the "second concurrent
    // claim" test above).
    REQUIRE(store.release_remediation_claim(pol.value(), {"agent-1"}, gen1).has_value());

    auto claimed2 = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed2.has_value());
    REQUIRE(claimed2->ids.size() == 1);
    CHECK(claimed2->ids[0] == "agent-1");

    // Releasing an already-unclaimed / never-claimed target is a benign
    // no-op, not an error -- any generation value is fine here, the point is
    // that it returns Ok, not that it frees anything.
    REQUIRE(store.release_remediation_claim(pol.value(), {"agent-1"}, claimed2->generation)
                .has_value());
    REQUIRE(store.release_remediation_claim("nonexistent-policy", {"agent-99"}, 0).has_value());
}

TEST_CASE("release_remediation_claim with a stale generation is a fenced no-op that cannot "
          "erase a sibling's reclaim (HA WS-3 3.4 review B3 / ABA)",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // A claims agent-1.
    auto claimA = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimA.has_value());
    REQUIRE(claimA->ids.size() == 1);
    const int64_t gen_a = claimA->generation;

    // A's claim ages past the staleness window (A "dies" mid-flight).
    backdate_claim(pool, pol.value(), "agent-1", 1801);

    // B reclaims the same target -- succeeds, with a NEW generation.
    auto claimB = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimB.has_value());
    REQUIRE(claimB->ids.size() == 1);
    const int64_t gen_b = claimB->generation;
    CHECK(gen_b != gen_a);

    // A resumes and releases with its now-STALE generation. This must
    // return Ok (a fenced no-op is benign, never an error) but must NOT
    // free B's live claim.
    REQUIRE(store.release_remediation_claim(pol.value(), {"agent-1"}, gen_a).has_value());

    // Proof the fence held: a third claimant (C) attempting the same
    // target right now still gets nothing back -- B's claim, stamped with
    // gen_b, is still live because A's stale-gen release matched zero rows.
    auto claimC = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimC.has_value());
    CHECK(claimC->ids.empty());

    // Only B, releasing with its OWN current generation, can actually free
    // the row.
    REQUIRE(store.release_remediation_claim(pol.value(), {"agent-1"}, gen_b).has_value());
    auto claimD = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimD.has_value());
    REQUIRE(claimD->ids.size() == 1);
}

TEST_CASE("update_agent_status with expected_gen is a fenced write: the owning generation "
          "writes, a stale generation is a benign no-op that does not stomp the live status "
          "(HA WS-3 3.4 review B3)",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto claimed = store.claim_remediation(pol.value(), {"agent-1"}, 1800);
    REQUIRE(claimed.has_value());
    REQUIRE(claimed->ids.size() == 1);
    const int64_t gen = claimed->generation;

    // The owning generation writes, and reports TRUE (a row was written).
    auto r1 = store.update_agent_status(pol.value(), "agent-1", "fixing", "", gen);
    REQUIRE(r1.has_value());
    CHECK(*r1 == true);
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->status == "fixing");

    // A wrong/stale generation is a benign fenced no-op: Ok(false), and the
    // live 'fixing' status must be left untouched -- a stale holder must
    // never stomp a row a sibling now owns.
    auto r2 = store.update_agent_status(pol.value(), "agent-1", "error", "", gen + 999);
    REQUIRE(r2.has_value());
    CHECK(*r2 == false);
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->status == "fixing"); // unchanged by the fenced no-op

    // An UNFENCED write (no expected_gen) is the ordinary detection path --
    // unconditional, and DOES change status.
    auto r3 = store.update_agent_status(pol.value(), "agent-1", "compliant");
    REQUIRE(r3.has_value());
    CHECK(*r3 == true);
    auto s3 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s3.has_value());
    REQUIRE(s3->has_value());
    CHECK((*s3)->status == "compliant");
}
