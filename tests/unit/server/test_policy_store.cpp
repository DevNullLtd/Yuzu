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
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <string>
#include <utility>
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

// #2123 fail-open regression pin. A blank or comment line inside the scope
// selector used to end the block under CRLF/lone-CR endings (comment lines
// under LF too), so the stored scope_expression lost `EXISTS tag:prod` and the
// policy evaluated every Windows device. The triggers list carries the same
// shape, so its count is pinned too. managementGroups is deliberately NOT
// asserted here: its accepted placement is an open question on #2123.
TEST_CASE("PolicyStore: scope selector survives blank/comment lines and any line ending (#2123)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    const std::string lf = "apiVersion: yuzu.io/v1alpha1\n"
                           "kind: Policy\n"
                           "displayName: Line Ending Policy\n"
                           "fragment: " +
                           frag.value() +
                           "\n"
                           "scope:\n"
                           "  selector:\n"
                           "    platform: Windows\n"
                           "\n"
                           "    tags:\n"
                           "      - prod\n"
                           "triggers:\n"
                           "  - type: interval\n"
                           "    interval_seconds: 300\n"
                           "\n"
                           "  - type: interval\n"
                           "    interval_seconds: 600\n";
    auto with_eol = [](const std::string& s, const std::string& eol) {
        std::string out;
        for (char c : s)
            out += (c == '\n') ? eol : std::string(1, c);
        return out;
    };
    std::string mixed = lf;
    mixed.replace(mixed.find("Windows\n\n"), 9, "Windows\n\r\n");
    std::string commented = lf;
    commented.replace(commented.find("Windows\n\n"), 9, "Windows\n# prod only\n");

    const std::pair<const char*, std::string> cases[] = {
        {"LF", lf},
        {"CRLF", with_eol(lf, "\r\n")},
        {"lone CR inside LF",
         [&] {
             std::string d = lf;
             d.replace(d.find("Windows\n\n"), 9, "Windows\n\r");
             return d;
         }()},
        {"mixed", mixed},
        {"LF comment line", commented},
    };
    for (const auto& [label, yaml] : cases) {
        INFO("case: " << label);
        auto result = store.create_policy(yaml);
        REQUIRE(result.has_value());
        auto pol = store.get_policy(result.value());
        REQUIRE(pol.has_value());
        REQUIRE(pol->has_value());
        CHECK((*pol)->scope_expression == "ostype == \"windows\" AND EXISTS tag:prod");
        CHECK((*pol)->triggers.size() == 2);
    }
}

// #2123 security review. Placement-neutral on purpose: managementGroups'
// accepted location is an open question on #2123, so these assert only what
// must NOT be absorbed, never which nested managementGroups is read.
TEST_CASE("PolicyStore: list extent never widens groups or drops tags (#2123)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    const std::string head = "apiVersion: yuzu.io/v1alpha1\n"
                             "kind: Policy\n"
                             "displayName: Extent Policy\n"
                             "fragment: " +
                             frag.value() + "\n";

    SECTION("an outer list's item is refused, never absorbed as a management group") {
        auto result = store.create_policy(head + "spec:\n"
                                                 "  things:\n"
                                                 "    - name: a\n"
                                                 "      managementGroups:\n"
                                                 "        - g1\n"
                                                 "    - g2\n");
        // The outer item is kept raw by the scanner and refused as a group id:
        // never stored as group `g2` (governance G3-QE-3: assert the outcome,
        // not a loop that passes on an empty list).
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("is not a management group id") != std::string::npos);
    }
    // An inline list that does not close on its key's line becomes one raw item.
    // A management group id outside the scope-token charset is now refused, so a
    // broken groups list is a 400, never a policy silently targeting nobody or
    // overriding its selector (governance G4-UP-1, G4-UP-2, G3-ARCH-F1).
    SECTION("comment text in a multi-line flow groups list is refused, never a group") {
        auto result =
            store.create_policy(head + "managementGroups: [g1,  # canary, prod-all,\n  g2]\n");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("a valid multi-line flow groups list is refused, not silently zero targets") {
        auto result = store.create_policy(head + "managementGroups: [g1,\n  g2]\n");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("an unterminated groups list never overrides a valid selector") {
        auto result = store.create_policy(head + "scope:\n"
                                                 "  selector:\n"
                                                 "    platform: windows\n"
                                                 "    tags: [prod]\n"
                                                 "managementGroups: [g1");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("an unterminated tags list is rejected, never stored without the tag") {
        auto result = store.create_policy(head + "scope:\n"
                                                 "  selector:\n"
                                                 "    platform: windows\n"
                                                 "    tags: [prod\n"
                                                 "other: [x]\n");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("selector.tags entry '[prod'") != std::string::npos);
        CHECK(result.error().find("same line") != std::string::npos);
    }
    SECTION("a misindented tag item is rejected, never stored without the tag") {
        auto result = store.create_policy(head + "scope:\n"
                                                 "  selector:\n"
                                                 "    platform: windows\n"
                                                 "    tags:\n"
                                                 "   - prod\n");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().find("indentation") != std::string::npos);
    }
    SECTION("managementGroups: null is no groups, and a scalar group id is refused") {
        // Governance Gate 8 A1 / UP-A / UP-B: a YAML null is an empty list (the
        // selector applies); any other scalar is refused, never read as a group
        // that replaces the selector.
        auto none = store.create_policy(head + "scope:\n  selector:\n    platform: windows\n"
                                               "managementGroups: null\n");
        REQUIRE(none.has_value());
        auto pol = store.get_policy(none.value());
        REQUIRE(pol.has_value());
        REQUIRE(pol->has_value());
        CHECK((*pol)->management_groups.empty());
        CHECK((*pol)->scope_expression == "ostype == \"windows\"");
        auto scalar = store.create_policy(head + "managementGroups: abc123def456\n");
        REQUIRE_FALSE(scalar.has_value());
        CHECK(scalar.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("a scalar managementGroups inside a description block is refused") {
        // Round 4 quality-engineer: pins UP-B's placement end to end.
        auto r = store.create_policy(head + "description: |\n  managementGroups: abc123def456\n"
                                            "scope:\n  selector:\n    platform: windows\n");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("managementGroups null followed by a list line is refused") {
        // Round 4 R4-1 / UP-F: the null must not hide the line after it.
        auto r = store.create_policy(head + "scope:\n  selector:\n    platform: windows\n"
                                            "managementGroups: null\n  - abc123def456\n");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("is not a management group id") != std::string::npos);
    }
    SECTION("a hyphen inside a comment does not drop the triggers") {
        // Governance G4-TRIG-1: the trigger splitter used the first '-' in the
        // section, comments included, so dash_indent was wrong and no trigger
        // was stored (the interval fell back to the default).
        auto result = store.create_policy(head + "triggers:\n"
                                                 "  # re-check every 5-min\n"
                                                 "  - type: interval\n"
                                                 "    interval_seconds: 300\n");
        REQUIRE(result.has_value());
        auto pol = store.get_policy(result.value());
        REQUIRE(pol.has_value());
        REQUIRE(pol->has_value());
        REQUIRE((*pol)->triggers.size() == 1);
        CHECK((*pol)->triggers[0].config_json.find("300") != std::string::npos);
    }
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

TEST_CASE("PolicyStore: compliance_by_policy_checked groups per policy, agrees with "
          "get_compliance_summary, and is cached until a store write",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto p1 = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(p1.has_value());
    auto p2 = store.create_policy(make_policy_yaml(frag.value(), "second-policy"));
    REQUIRE(p2.has_value());

    REQUIRE(store.update_agent_status(p1.value(), "a1", "compliant").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a2", "non_compliant").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a3", "compliant").has_value());
    REQUIRE(store.update_agent_status(p2.value(), "a1", "error").has_value());

    auto by = store.compliance_by_policy_checked();
    REQUIRE(by.has_value());
    REQUIRE(by->size() == 2);
    for (const auto& row : *by) {
        auto one = store.get_compliance_summary(row.policy_id);
        REQUIRE(one.has_value());
        CHECK(row.compliant == one->compliant);
        CHECK(row.non_compliant == one->non_compliant);
        CHECK(row.error == one->error);
        CHECK(row.total == one->total);
    }
    const auto& first = (*by)[0].policy_id == p1.value() ? (*by)[0] : (*by)[1];
    CHECK(first.compliant == 2);
    CHECK(first.non_compliant == 1);
    CHECK(first.total == 3);

    // Cached: a write that bypasses the store (no invalidation hook) is not seen.
    {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        PgResult r{PQexec(lease.get(),
                          "UPDATE policy_store.policy_status SET status = 'non_compliant' "
                          "WHERE agent_id = 'a1' AND status = 'compliant'")};
        REQUIRE(r.ok());
    }
    auto cached = store.compliance_by_policy_checked();
    REQUIRE(cached.has_value());
    for (const auto& row : *cached)
        if (row.policy_id == p1.value())
            CHECK(row.compliant == 2);

    // The store's own write drops the cache.
    REQUIRE(store.update_agent_status(p2.value(), "a9", "compliant").has_value());
    auto fresh = store.compliance_by_policy_checked();
    REQUIRE(fresh.has_value());
    for (const auto& row : *fresh)
        if (row.policy_id == p1.value())
            CHECK(row.compliant == 1);
}

TEST_CASE("PolicyStore: compliance_by_policy_checked shape, all five statuses, and 60 s expiry",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    // No status rows at all: an empty success, not an error.
    auto none = store.compliance_by_policy_checked();
    REQUIRE(none.has_value());
    CHECK(none->empty());

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto p1 = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(p1.has_value());
    auto p2 = store.create_policy(make_policy_yaml(frag.value(), "second-policy"));
    REQUIRE(p2.has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a1", "compliant").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a2", "non_compliant").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a3", "unknown").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a4", "fixing").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a5", "error").has_value());
    REQUIRE(store.update_agent_status(p2.value(), "a1", "compliant").has_value());

    auto fake_now = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    store.set_cache_clock_for_test([&fake_now] { return fake_now; });

    auto by = store.compliance_by_policy_checked();
    REQUIRE(by.has_value());
    REQUIRE(by->size() == 2);
    CHECK((*by)[0].policy_id < (*by)[1].policy_id); // ordered by policy_id
    for (const auto& row : *by) {
        if (row.policy_id != p1.value())
            continue;
        CHECK(row.compliant == 1);
        CHECK(row.non_compliant == 1);
        CHECK(row.unknown == 1);
        CHECK(row.fixing == 1);
        CHECK(row.error == 1);
        CHECK(row.total == 5);
    }

    // Bypass the store's own write hook, then step the injected clock.
    {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        PgResult r{PQexec(lease.get(),
                          "UPDATE policy_store.policy_status SET status = 'non_compliant' "
                          "WHERE agent_id = 'a1' AND status = 'compliant'")};
        REQUIRE(r.ok());
    }
    auto count_compliant = [&](const std::vector<yuzu::server::ComplianceSummary>& v) {
        std::int64_t n = 0;
        for (const auto& row : v)
            n += row.compliant;
        return n;
    };
    fake_now += std::chrono::seconds(59);
    auto at59 = store.compliance_by_policy_checked();
    REQUIRE(at59.has_value());
    CHECK(count_compliant(*at59) == 2); // still the cached value
    fake_now += std::chrono::seconds(1);
    auto at60 = store.compliance_by_policy_checked();
    REQUIRE(at60.has_value());
    CHECK(count_compliant(*at60) == 0); // expired: recomputed
}

TEST_CASE("PolicyStore: compliance_by_policy_checked is kDegraded on a closed store, "
          "never an empty list",
          "[policy_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    PolicyStore store{pool};
    auto by = store.compliance_by_policy_checked();
    REQUIRE_FALSE(by.has_value());
    CHECK(by.error() == yuzu::server::PolicyReadError::kDegraded);
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

// ============================================================================
// Explicit ids at creation: [A-Za-z0-9._-]{1,128}, not dot-only (new records only)
// ============================================================================

namespace {
std::string with_id_line(const std::string& yaml, const std::string& id) {
    // Insert `id: <id>` after the `kind:` line (extract_yaml_value reads the first `id:`).
    const auto kind_end = yaml.find('\n', yaml.find("kind:"));
    return yaml.substr(0, kind_end + 1) + "id: " + id + "\n" + yaml.substr(kind_end + 1);
}
} // namespace

TEST_CASE("PolicyStore: an explicit policy or fragment id must be a safe path segment",
          "[policy_store][pg][policy][fragment][url_path_segment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    const std::vector<std::string> bad = {"..", ".", "a/b", "../x", "a?b", "a b",
                                          "a%2Fb", "x\"y", std::string(129, 'a')};
    for (const auto& id : bad) {
        INFO("id=" << id);
        auto p = store.create_policy(with_id_line(make_policy_yaml(frag.value()), id));
        CHECK_FALSE(p.has_value());
        auto f = store.create_fragment(with_id_line(kCheckOnlyFragment, id));
        CHECK_FALSE(f.has_value());
    }

    // Generated ids and ordinary explicit ids still work, including dots/underscores/dashes.
    const std::vector<std::string> good = {"pol-1", "my.policy_v2", "a..b", std::string(128, 'a')};
    for (const auto& id : good) {
        INFO("id=" << id);
        auto p = store.create_policy(with_id_line(make_policy_yaml(frag.value()), id));
        REQUIRE(p.has_value());
        CHECK(p.value() == id);
    }
    CHECK(store.create_policy(make_policy_yaml(frag.value())).has_value());
}

// ============================================================================
// `blocked`: policy evaluation refused to dispatch the pair (G01)
// ============================================================================

namespace {

nlohmann::json check_result_of(PolicyStore& store, const std::string& policy_id,
                               const std::string& agent_id) {
    auto st = store.get_agent_status(policy_id, agent_id);
    REQUIRE(st.has_value());
    REQUIRE(st->has_value());
    return nlohmann::json::parse((*st)->check_result);
}

std::string status_of(PolicyStore& store, const std::string& policy_id, const std::string& agent_id) {
    auto st = store.get_agent_status(policy_id, agent_id);
    REQUIRE(st.has_value());
    if (!*st)
        return "<none>";
    return (*st)->status;
}

} // namespace

TEST_CASE("PolicyStore: peek_fragment_instructions names the check, fix and postCheck instructions",
          "[policy_store][blocked]") {
    CHECK(PolicyStore::peek_fragment_instructions(kFullFragment) ==
          std::vector<std::string>{"get_service_status", "start_service", "get_service_status"});
    CHECK(PolicyStore::peek_fragment_instructions(kCheckOnlyNoFix) ==
          std::vector<std::string>{"check_disk_space"});
    CHECK(PolicyStore::peek_fragment_instructions("kind: PolicyFragment\n").empty());
    CHECK(PolicyStore::peek_fragment_instructions("").empty());
}

TEST_CASE("PolicyStore: update_agent_status still rejects blocked, only mark_blocked writes it",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto r = store.update_agent_status(pol.value(), "agent-1", "blocked");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("invalid status") != std::string::npos);
    CHECK(status_of(store, pol.value(), "agent-1") == "<none>");
}

TEST_CASE("PolicyStore: mark_blocked writes on change and reports the changed rows",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    const std::vector<std::string> ids{"agent-1", "agent-2", "agent-3"};

    // First refusal: all three rows are new.
    auto r1 = store.mark_blocked(pol.value(), ids, "check", "content_dist", "execute_staged", "gated");
    REQUIRE(r1.has_value());
    CHECK(r1->changed == 3);
    CHECK(r1->fenced_out == 0);
    for (const auto& id : ids) {
        CHECK(status_of(store, pol.value(), id) == "blocked");
        const auto j = check_result_of(store, pol.value(), id);
        CHECK(j["phase"] == "check");
        CHECK(j["result"] == "blocked");
        CHECK(j["reason"] == "gated");
        CHECK(j["plugin"] == "content_dist");
        CHECK(j["action"] == "execute_staged");
    }

    // The same refusal again changes nothing: zero rows, in steady state.
    auto r2 = store.mark_blocked(pol.value(), ids, "check", "content_dist", "execute_staged", "gated");
    REQUIRE(r2.has_value());
    CHECK(r2->changed == 0);

    // A different pair, reason or phase is a change; each rewrites every row once.
    auto pair = store.mark_blocked(pol.value(), ids, "check", "content_dist", "stage", "gated");
    REQUIRE(pair.has_value());
    CHECK(pair->changed == 3);
    auto why = store.mark_blocked(pol.value(), ids, "check", "content_dist", "stage", "destructive");
    REQUIRE(why.has_value());
    CHECK(why->changed == 3);
    auto phase = store.mark_blocked(pol.value(), ids, "verify", "content_dist", "stage", "destructive");
    REQUIRE(phase.has_value());
    CHECK(phase->changed == 3);
    CHECK(check_result_of(store, pol.value(), "agent-1")["phase"] == "verify");
    auto again = store.mark_blocked(pol.value(), ids, "verify", "content_dist", "stage", "destructive");
    REQUIRE(again.has_value());
    CHECK(again->changed == 0);

    // A newly in-scope agent is the only changed row.
    auto wider = store.mark_blocked(pol.value(), {"agent-1", "agent-4"}, "verify", "content_dist",
                                    "stage", "destructive");
    REQUIRE(wider.has_value());
    CHECK(wider->changed == 1);
}

TEST_CASE("PolicyStore: mark_blocked takes a row over from another status without touching the fix "
          "bookkeeping",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // The first write inserts (attempt count 0); the second counts one attempt.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    const auto attempts_of = [&] {
        auto lease = pool.try_acquire_for(std::chrono::milliseconds{2000});
        REQUIRE(lease);
        auto q = yuzu::server::pg::exec_params(
            lease.get(),
            "SELECT fix_attempt_count FROM policy_store.policy_status WHERE policy_id = $1 AND agent_id = $2",
            std::vector<std::string>{pol.value(), std::string("agent-1")});
        REQUIRE(q.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(q.get()) == 1);
        return std::string(PQgetvalue(q.get(), 0, 0));
    };
    const auto attempts_before = attempts_of();
    REQUIRE(attempts_before == "1");
    const auto before = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());
    REQUIRE((*before)->last_fix_at > 0);

    auto r = store.mark_blocked(pol.value(), {"agent-1"}, "check", "echo", "purge_source", "destructive");
    REQUIRE(r.has_value());
    CHECK(r->changed == 1);
    const auto after = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "blocked");
    CHECK((*after)->last_fix_at == (*before)->last_fix_at);

    // fix_attempt_count is not exposed on the status struct; it was read directly above.
    CHECK(attempts_of() == attempts_before);
}

TEST_CASE("PolicyStore: mark_blocked writes in chunks and counts distinct ids",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // 1201 ids is three chunks (500, 500, 201); a duplicate must not double count.
    std::vector<std::string> ids;
    for (int i = 0; i < 1201; ++i)
        ids.push_back("agent-" + std::to_string(i));
    ids.push_back("agent-0");

    auto r = store.mark_blocked(pol.value(), ids, "check", "echo", "purge_source", "destructive");
    REQUIRE(r.has_value());
    CHECK(r->changed == 1201);
    auto again = store.mark_blocked(pol.value(), ids, "check", "echo", "purge_source", "destructive");
    REQUIRE(again.has_value());
    CHECK(again->changed == 0);

    auto cs = store.get_compliance_summary(pol.value());
    REQUIRE(cs.has_value());
    CHECK(cs->blocked == 1201);
    CHECK(cs->total == 1201);
}

TEST_CASE("PolicyStore: mark_blocked never stores an identifier authoring would refuse",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    const std::vector<std::string> ids{"agent-1", "agent-2"};

    const std::string too_long(129, 'a');
    auto r1 = store.mark_blocked(pol.value(), ids, "check", too_long, "run", "unclassified");
    REQUIRE(r1.has_value());
    CHECK(r1->changed == 2);
    const auto j = check_result_of(store, pol.value(), "agent-1");
    CHECK(j["reason"] == "dispatch_identifier_invalid");
    CHECK(j["plugin"].is_null());
    CHECK(j["action"].is_null());
    CHECK(j["phase"] == "check");
    auto st = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(st.has_value());
    REQUIRE(st->has_value());
    CHECK((*st)->check_result.find(too_long) == std::string::npos);

    // A different invalid pair (off the charset, 128 bytes or fewer) stores the same value, so
    // moving from one to the other is not a change.
    auto r2 = store.mark_blocked(pol.value(), ids, "check", "echo", "pur ge", "unclassified");
    REQUIRE(r2.has_value());
    CHECK(r2->changed == 0);
    auto r3 = store.mark_blocked(pol.value(), ids, "check", "ec/ho", "status", "gated");
    REQUIRE(r3.has_value());
    CHECK(r3->changed == 0);
    CHECK(check_result_of(store, pol.value(), "agent-2") == j);

    // 128 bytes is within the limit: stored as given, with the caller's reason.
    const std::string at_limit(128, 'b');
    auto r4 = store.mark_blocked(pol.value(), ids, "check", at_limit, "run", "unclassified");
    REQUIRE(r4.has_value());
    CHECK(r4->changed == 2);
    const auto k = check_result_of(store, pol.value(), "agent-1");
    CHECK(k["reason"] == "unclassified");
    CHECK(k["plugin"] == at_limit);
}

TEST_CASE("PolicyStore: mark_blocked refuses bad arguments", "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    CHECK_FALSE(store.mark_blocked("", {"a"}, "check", "echo", "status", "gated").has_value());
    CHECK_FALSE(store.mark_blocked(pol.value(), {"a"}, "bogus", "echo", "status", "gated").has_value());
    CHECK_FALSE(store.mark_blocked(pol.value(), {"a"}, "check", "echo", "status", "").has_value());
    // 0 would match every unclaimed row.
    CHECK_FALSE(
        store.mark_blocked(pol.value(), {"a"}, "fix", "echo", "status", "gated", int64_t{0}).has_value());
    // No ids is a no-op, not an error.
    auto none = store.mark_blocked(pol.value(), {}, "check", "echo", "status", "gated");
    REQUIRE(none.has_value());
    CHECK(none->changed == 0);
    CHECK(none->fenced_out == 0);
}

TEST_CASE("PolicyStore: a fenced mark_blocked never overwrites a row a sibling reclaimed",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    const std::vector<std::string> ids{"agent-1", "agent-2"};

    auto claimA = store.claim_remediation(pol.value(), ids, 1800);
    REQUIRE(claimA.has_value());
    REQUIRE(claimA->ids.size() == 2);

    // While the claim is held: the fenced write changes both rows and loses neither.
    auto w1 = store.mark_blocked(pol.value(), ids, "fix", "content_dist", "execute_staged", "gated",
                                 claimA->generation);
    REQUIRE(w1.has_value());
    CHECK(w1->changed == 2);
    CHECK(w1->fenced_out == 0);
    CHECK(check_result_of(store, pol.value(), "agent-1")["phase"] == "fix");

    // The same refusal again: nothing changed, and that is not a lost fence.
    auto w2 = store.mark_blocked(pol.value(), ids, "fix", "content_dist", "execute_staged", "gated",
                                 claimA->generation);
    REQUIRE(w2.has_value());
    CHECK(w2->changed == 0);
    CHECK(w2->fenced_out == 0);

    // The fenced write does not release the claim: a sibling still cannot take it.
    auto sibling = store.claim_remediation(pol.value(), ids, 1800);
    REQUIRE(sibling.has_value());
    CHECK(sibling->ids.empty());

    // Release, then a sibling reclaims with a new generation.
    REQUIRE(store.release_remediation_claim(pol.value(), ids, claimA->generation).has_value());
    auto claimB = store.claim_remediation(pol.value(), ids, 1800);
    REQUIRE(claimB.has_value());
    REQUIRE(claimB->ids.size() == 2);
    REQUIRE(claimB->generation != claimA->generation);

    // The stale holder's write matches nothing: both targets are reported fenced out and the
    // rows keep the first refusal's reason.
    auto stale = store.mark_blocked(pol.value(), ids, "fix", "echo", "purge_source", "destructive",
                                    claimA->generation);
    REQUIRE(stale.has_value());
    CHECK(stale->changed == 0);
    CHECK(stale->fenced_out == 2);
    CHECK(check_result_of(store, pol.value(), "agent-1")["reason"] == "gated");

    // The current holder's write goes through.
    auto fresh = store.mark_blocked(pol.value(), ids, "fix", "echo", "purge_source", "destructive",
                                    claimB->generation);
    REQUIRE(fresh.has_value());
    CHECK(fresh->changed == 2);
    CHECK(fresh->fenced_out == 0);
    CHECK(check_result_of(store, pol.value(), "agent-1")["reason"] == "destructive");

    // A fenced write never creates a row: an agent with no row is fenced out, not inserted.
    auto ghost = store.mark_blocked(pol.value(), {"agent-ghost"}, "fix", "echo", "purge_source",
                                    "destructive", claimB->generation);
    REQUIRE(ghost.has_value());
    CHECK(ghost->changed == 0);
    CHECK(ghost->fenced_out == 1);
    CHECK(status_of(store, pol.value(), "agent-ghost") == "<none>");
}

TEST_CASE("PolicyStore: blocked has its own bucket in every compliance summary",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto p1 = store.create_policy(make_policy_yaml(frag.value(), "Policy One"));
    auto p2 = store.create_policy(make_policy_yaml(frag.value(), "Policy Two"));
    REQUIRE(p1.has_value());
    REQUIRE(p2.has_value());

    REQUIRE(store.update_agent_status(p1.value(), "a1", "compliant").has_value());
    REQUIRE(store.update_agent_status(p1.value(), "a2", "non_compliant").has_value());
    REQUIRE(store.mark_blocked(p1.value(), {"a3", "a4", "a5"}, "check", "echo", "purge_source",
                               "destructive")
                .has_value());
    REQUIRE(store.update_agent_status(p2.value(), "a1", "compliant").has_value());

    auto fake_now = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    store.set_cache_clock_for_test([&fake_now] { return fake_now; });

    auto cs = store.get_compliance_summary(p1.value());
    REQUIRE(cs.has_value());
    CHECK(cs->compliant == 1);
    CHECK(cs->non_compliant == 1);
    CHECK(cs->blocked == 3);
    CHECK(cs->total == 5);

    auto fc = store.get_fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->blocked == 3);
    CHECK(fc->total_checks == 6);

    auto by = store.compliance_by_policy_checked();
    REQUIRE(by.has_value());
    int64_t by_blocked = 0;
    int64_t by_total = 0;
    for (const auto& row : *by) {
        by_blocked += row.blocked;
        by_total += row.total;
        if (row.policy_id == p1.value())
            CHECK(row.blocked == 3);
        else
            CHECK(row.blocked == 0);
    }
    // On fresh rows the fleet figure and the by-policy view agree.
    CHECK(by_blocked == fc->blocked);
    CHECK(by_total == fc->total_checks);
}

TEST_CASE("PolicyStore: mark_blocked invalidates the fleet compliance cache",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());

    // Populate the cache, then change a row without advancing any clock.
    auto fc1 = store.get_fleet_compliance();
    REQUIRE(fc1.has_value());
    CHECK(fc1->blocked == 0);

    REQUIRE(store.mark_blocked(pol.value(), {"agent-2"}, "check", "echo", "purge_source", "destructive")
                .has_value());
    auto fc2 = store.get_fleet_compliance();
    REQUIRE(fc2.has_value());
    CHECK(fc2->blocked == 1);
    CHECK(fc2->total_checks == 2);

    // A repeat that changes nothing reports zero changed rows.
    auto same = store.mark_blocked(pol.value(), {"agent-2"}, "check", "echo", "purge_source", "destructive");
    REQUIRE(same.has_value());
    CHECK(same->changed == 0);
}

// ----------------------------------------------------------------------------
// `blocked` freshness (G01, B6): a refusal that still applies refreshes its rows, and a row
// nothing refreshes decays like any other status.
// ----------------------------------------------------------------------------

namespace {

// Move a row's last_check_at `seconds_ago` into the past, as if the last refresh was that long ago.
void age_check_stamp(PgPool& pool, const std::string& pol, const std::string& agent,
                     int64_t seconds_ago) {
    auto lease = pool.try_acquire_for(std::chrono::milliseconds{2000});
    REQUIRE(lease);
    auto r = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE policy_store.policy_status SET "
        "last_check_at = EXTRACT(EPOCH FROM NOW())::bigint - $3::bigint "
        "WHERE policy_id = $1 AND agent_id = $2",
        std::vector<std::string>{pol, agent, std::to_string(seconds_ago)});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

int64_t check_stamp_age(PolicyStore& store, const std::string& pol, const std::string& agent) {
    auto st = store.get_agent_status(pol, agent);
    REQUIRE(st.has_value());
    REQUIRE(st->has_value());
    return static_cast<int64_t>(std::time(nullptr)) - (*st)->last_check_at;
}

constexpr int64_t kHour = 3600;

} // namespace

TEST_CASE("PolicyStore: a refusal that changes nothing still refreshes last_check_at",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    const std::vector<std::string> ids{"agent-1", "agent-2"};

    REQUIRE(store.mark_blocked(pol.value(), ids, "check", "content_dist", "execute_staged", "gated")
                .has_value());
    age_check_stamp(pool, pol.value(), "agent-1", 23 * kHour);
    age_check_stamp(pool, pol.value(), "agent-2", 23 * kHour);
    REQUIRE(check_stamp_age(store, pol.value(), "agent-1") > 22 * kHour);

    // The same refusal: no row changed (so no audit row downstream), and both stamps are fresh.
    auto same = store.mark_blocked(pol.value(), ids, "check", "content_dist", "execute_staged", "gated");
    REQUIRE(same.has_value());
    CHECK(same->changed == 0);
    CHECK(same->fenced_out == 0);
    CHECK(check_stamp_age(store, pol.value(), "agent-1") < 60);
    CHECK(check_stamp_age(store, pol.value(), "agent-2") < 60);
    // Only the stamp moved: the stored reason is the same.
    CHECK(check_result_of(store, pol.value(), "agent-1")["reason"] == "gated");

    // An agent that is not a target of this call is not refreshed.
    REQUIRE(store.mark_blocked(pol.value(), {"agent-3"}, "check", "content_dist", "execute_staged", "gated")
                .has_value());
    age_check_stamp(pool, pol.value(), "agent-3", 23 * kHour);
    auto only1 = store.mark_blocked(pol.value(), {"agent-1"}, "check", "content_dist",
                                    "execute_staged", "gated");
    REQUIRE(only1.has_value());
    CHECK(only1->changed == 0);
    CHECK(check_stamp_age(store, pol.value(), "agent-3") > 22 * kHour);
}

TEST_CASE("PolicyStore: a fenced refusal that changes nothing refreshes only the rows it holds",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    const std::vector<std::string> ids{"agent-1", "agent-2"};

    auto claimA = store.claim_remediation(pol.value(), ids, 1800);
    REQUIRE(claimA.has_value());
    REQUIRE(claimA->ids.size() == 2);
    REQUIRE(store.mark_blocked(pol.value(), ids, "fix", "content_dist", "execute_staged", "gated",
                               claimA->generation)
                .has_value());
    age_check_stamp(pool, pol.value(), "agent-1", 23 * kHour);
    age_check_stamp(pool, pol.value(), "agent-2", 23 * kHour);

    // The holder repeats the same refusal: nothing changed, nothing fenced out, stamps fresh.
    auto same = store.mark_blocked(pol.value(), ids, "fix", "content_dist", "execute_staged", "gated",
                                   claimA->generation);
    REQUIRE(same.has_value());
    CHECK(same->changed == 0);
    CHECK(same->fenced_out == 0);
    CHECK(check_stamp_age(store, pol.value(), "agent-1") < 60);
    CHECK(check_stamp_age(store, pol.value(), "agent-2") < 60);

    // A holder that lost its claim neither changes nor refreshes the rows.
    age_check_stamp(pool, pol.value(), "agent-1", 23 * kHour);
    REQUIRE(store.release_remediation_claim(pol.value(), ids, claimA->generation).has_value());
    auto claimB = store.claim_remediation(pol.value(), ids, 1800);
    REQUIRE(claimB.has_value());
    REQUIRE(claimB->generation != claimA->generation);
    auto stale = store.mark_blocked(pol.value(), ids, "fix", "content_dist", "execute_staged", "gated",
                                    claimA->generation);
    REQUIRE(stale.has_value());
    CHECK(stale->changed == 0);
    CHECK(stale->fenced_out == 2);
    CHECK(check_stamp_age(store, pol.value(), "agent-1") > 22 * kHour);

    // A fenced write never creates a row, so there is nothing to refresh for an unknown agent.
    auto ghost = store.mark_blocked(pol.value(), {"agent-ghost"}, "fix", "content_dist",
                                    "execute_staged", "gated", claimB->generation);
    REQUIRE(ghost.has_value());
    CHECK(ghost->changed == 0);
    CHECK(status_of(store, pol.value(), "agent-ghost") == "<none>");
}

TEST_CASE("PolicyStore: a live refusal stays in the fleet figure and an unrefreshed one decays",
          "[policy_store][pg][blocked]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto live = store.create_policy(make_policy_yaml(frag.value(), "Live Refusal"));
    auto gone = store.create_policy(make_policy_yaml(frag.value(), "Refusal Nothing Refreshes"));
    REQUIRE(live.has_value());
    REQUIRE(gone.has_value());
    REQUIRE(store.mark_blocked(live.value(), {"agent-1"}, "check", "echo", "purge_source", "destructive")
                .has_value());
    REQUIRE(store.mark_blocked(gone.value(), {"agent-1"}, "check", "echo", "purge_source", "destructive")
                .has_value());

    auto fresh = store.get_fleet_compliance();
    REQUIRE(fresh.has_value());
    CHECK(fresh->blocked == 2);

    // Both rows last refreshed 25 hours ago, past the 24 hour freshness window.
    age_check_stamp(pool, live.value(), "agent-1", 25 * kHour);
    age_check_stamp(pool, gone.value(), "agent-1", 25 * kHour);

    // The live refusal is raised again (the policy dispatched and was refused again): same
    // pair, same reason, so no row changes, but its rows are fresh. The other policy is
    // disabled, out of scope or its agent is gone: nothing marks it again.
    auto again = store.mark_blocked(live.value(), {"agent-1"}, "check", "echo", "purge_source",
                                    "destructive");
    REQUIRE(again.has_value());
    CHECK(again->changed == 0);

    // The fleet figure is cached and ages on the real clock, so a status write on another agent
    // (which resets the cache) stands in for the TTL passing.
    REQUIRE(store.update_agent_status(live.value(), "agent-2", "compliant").has_value());
    auto after = store.get_fleet_compliance();
    REQUIRE(after.has_value());
    CHECK(after->blocked == 1);  // the live refusal never decayed
    CHECK(after->unknown == 1);  // the unrefreshed row decayed like any other status
    CHECK(after->compliant == 1);
    CHECK(after->total_checks == 3);

    // The per-policy summary is not subject to the freshness rule and still shows both.
    auto cs = store.get_compliance_summary(gone.value());
    REQUIRE(cs.has_value());
    CHECK(cs->blocked == 1);
}
