/**
 * test_management_group_store.cpp — Unit tests for the management-group
 * CONFINEMENT hierarchy store. Migrated Postgres store (ADR-0042, schema
 * `management_group_store`). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is
 * unset, fails when it is set but broken.
 *
 * The confinement-feeding reads are degrade-distinguishable (nullopt/unexpected
 * on store-not-open / pool-acquire timeout / query error). The `[management_group]
 * [degrade]` case below exercises that fail-closed path with NO database at all
 * (a construct-invalid pool), so it is deliberately NOT `[pg]`-tagged and runs
 * in every shard.
 *
 * `ManagementGroupStore::migrate_from_sqlite()` itself was retired
 * (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0042 Update, 2026-09-03) -- no
 * production fleet has ever run a pre-Postgres build, so the mandatory backfill never had real
 * legacy data to protect. `server.cpp` now runs `legacy_sqlite_probe::warn_if_legacy_rows` over
 * the three legacy tables instead.
 */

#include "management_group_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own ManagementGroupStore against a clone of this schema.
yuzu::test::PgTestTemplate mgmt_tpl{"mgmtgroupstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("mgmtgroupstore template: store failed to migrate");
}};

// Run a raw SQL statement against the test database on a second connection —
// lets a test inject a parent_id cycle the public API deliberately cannot
// produce. `id` values come from generate_id() (hex-only), so there is no real
// injection vector, but production code never string-concatenates SQL.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

} // namespace

TEST_CASE("ManagementGroupStore migration lands at v2 and drops mgmt_group_meta (#3623)",
          "[pg][management_group][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ManagementGroupStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult ver{PQexec(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                    "'management_group_store'")};
    REQUIRE(ver.ok());
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "2");
    PgResult tbl{PQexec(conn.get(), "SELECT COUNT(*) FROM information_schema.tables WHERE "
                                    "table_schema = 'management_group_store' AND table_name = "
                                    "'mgmt_group_meta'")};
    REQUIRE(tbl.ok());
    CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
}

TEST_CASE("ManagementGroupStore: create and retrieve group", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};
    REQUIRE(store.is_open());

    ManagementGroup g;
    g.name = "Production Servers";
    g.description = "All production servers";
    g.membership_type = "static";
    g.created_by = "admin";

    auto result = store.create_group(g);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*result);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Production Servers");
    CHECK(retrieved->description == "All production servers");
    CHECK(retrieved->membership_type == "static");
    CHECK(retrieved->created_by == "admin");
    CHECK(retrieved->created_at > 0);
}

TEST_CASE("ManagementGroupStore: list groups", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g1;
    g1.name = "Group A";
    g1.membership_type = "static";
    ManagementGroup g2;
    g2.name = "Group B";
    g2.membership_type = "static";

    store.create_group(g1);
    store.create_group(g2);

    auto groups = store.list_groups();
    REQUIRE(groups.size() == 2);
}

TEST_CASE("ManagementGroupStore: duplicate name rejected", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Duplicate";
    g.membership_type = "static";
    auto r1 = store.create_group(g);
    REQUIRE(r1.has_value());

    auto r2 = store.create_group(g);
    REQUIRE(!r2.has_value());
}

TEST_CASE("ManagementGroupStore: update group", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Original";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    ManagementGroup updated;
    updated.id = *id;
    updated.name = "Updated";
    updated.description = "New description";
    updated.membership_type = "dynamic";
    updated.scope_expression = R"(ostype == "Windows")";

    auto result = store.update_group(updated);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Updated");
    CHECK(retrieved->membership_type == "dynamic");
    CHECK(retrieved->scope_expression == R"(ostype == "Windows")");
}

TEST_CASE("ManagementGroupStore: update_group on missing id reports not found",
          "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.id = "aaaaaaaaaaaa";
    g.name = "Nope";
    g.membership_type = "static";
    auto r = store.update_group(g);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("not found") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: delete group", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "ToDelete";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    auto del = store.delete_group(*id);
    REQUIRE(del.has_value());

    auto retrieved = store.get_group(*id);
    CHECK(!retrieved.has_value());

    // Deleting again reports not found (RETURNING/PQcmdTuples, not sqlite3_changes).
    auto del2 = store.delete_group(*id);
    REQUIRE(!del2.has_value());
}

TEST_CASE("ManagementGroupStore: parent-child hierarchy", "[pg][management_group][hierarchy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup parent;
    parent.name = "Parent";
    parent.membership_type = "static";
    auto parent_id = store.create_group(parent);
    REQUIRE(parent_id.has_value());

    ManagementGroup child;
    child.name = "Child";
    child.membership_type = "static";
    child.parent_id = *parent_id;
    auto child_id = store.create_group(child);
    REQUIRE(child_id.has_value());

    auto children = store.get_children(*parent_id);
    REQUIRE(children.size() == 1);
    CHECK(children[0].name == "Child");

    auto ancestors = store.get_ancestor_ids(*child_id);
    REQUIRE(ancestors.has_value());
    REQUIRE(ancestors->size() == 1);
    CHECK((*ancestors)[0] == *parent_id);

    auto descendants = store.get_descendant_ids(*parent_id);
    REQUIRE(descendants.has_value());
    REQUIRE(descendants->size() == 1);
    CHECK((*descendants)[0] == *child_id);
}

TEST_CASE("ManagementGroupStore: hierarchy depth limit", "[pg][management_group][hierarchy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    std::string prev_id;
    for (int i = 0; i < 6; ++i) {
        ManagementGroup g;
        g.name = "Level " + std::to_string(i);
        g.membership_type = "static";
        g.parent_id = prev_id;
        auto result = store.create_group(g);
        if (result.has_value()) {
            prev_id = *result;
        } else {
            CHECK(i >= 5); // Should fail at level 5 or later
            break;
        }
    }
}

TEST_CASE("ManagementGroupStore: static membership", "[pg][management_group][members]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Test";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.add_member(*group_id, "agent-001");
    store.add_member(*group_id, "agent-002");
    store.add_member(*group_id, "agent-001"); // idempotent (ON CONFLICT DO NOTHING)

    auto members = store.get_members(*group_id);
    REQUIRE(members.size() == 2);

    auto groups = store.get_agent_groups("agent-001");
    REQUIRE(groups.has_value());
    REQUIRE(groups->size() == 1);
    CHECK((*groups)[0] == *group_id);

    store.remove_member(*group_id, "agent-001");
    auto members2 = store.get_members(*group_id);
    CHECK(members2.size() == 1);
}

TEST_CASE("ManagementGroupStore: dynamic membership refresh", "[pg][management_group][members]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Dynamic";
    g.membership_type = "dynamic";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.refresh_dynamic_membership(*group_id, {"agent-A", "agent-B", "agent-C"});
    auto members = store.get_members(*group_id);
    CHECK(members.size() == 3);

    // Refresh with new set — atomic replace.
    store.refresh_dynamic_membership(*group_id, {"agent-B", "agent-D"});
    auto members2 = store.get_members(*group_id);
    CHECK(members2.size() == 2);
}

TEST_CASE("ManagementGroupStore: group role assignments", "[pg][management_group][roles]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "RoleGroup";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "Operator";

    auto result = store.assign_role(a);
    REQUIRE(result.has_value());

    auto roles = store.get_group_roles(*group_id);
    REQUIRE(roles.size() == 1);
    CHECK(roles[0].principal_id == "alice");
    CHECK(roles[0].role_name == "Operator");

    store.unassign_role(*group_id, "user", "alice", "Operator");
    auto roles2 = store.get_group_roles(*group_id);
    CHECK(roles2.empty());
}

TEST_CASE("ManagementGroupStore: engine principals cannot hold scoped role assignments",
          "[pg][management_group][roles]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "EngGroup";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "engine";
    a.principal_id = "engine:nvd";
    a.role_name = "Viewer";
    auto r = store.assign_role(a);
    REQUIRE(!r.has_value());
}

TEST_CASE("ManagementGroupStore: get_assignments_for_principal unions user and group arms",
          "[pg][management_group][roles]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "AssignGroup";
    g.membership_type = "static";
    auto gid = store.create_group(g);
    REQUIRE(gid.has_value());

    GroupRoleAssignment ua;
    ua.group_id = *gid;
    ua.principal_type = "user";
    ua.principal_id = "alice";
    ua.role_name = "Operator";
    REQUIRE(store.assign_role(ua).has_value());
    GroupRoleAssignment gaR;
    gaR.group_id = *gid;
    gaR.principal_type = "group";
    gaR.principal_id = "ops-team";
    gaR.role_name = "Viewer";
    REQUIRE(store.assign_role(gaR).has_value());

    auto both = store.get_assignments_for_principal("alice", {"ops-team"});
    REQUIRE(both.has_value());
    CHECK(both->size() == 2);

    // No rbac groups → only the user arm.
    auto user_only = store.get_assignments_for_principal("alice", {});
    REQUIRE(user_only.has_value());
    CHECK(user_only->size() == 1);
}

TEST_CASE("ManagementGroupStore: get_member_agents_in_subtrees walks descendants",
          "[pg][management_group][hierarchy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup parent;
    parent.name = "SubParent";
    parent.membership_type = "static";
    auto pid = store.create_group(parent);
    REQUIRE(pid.has_value());
    ManagementGroup child;
    child.name = "SubChild";
    child.membership_type = "static";
    child.parent_id = *pid;
    auto cid = store.create_group(child);
    REQUIRE(cid.has_value());
    REQUIRE(store.add_member(*pid, "agent-p").has_value());
    REQUIRE(store.add_member(*cid, "agent-c").has_value());

    // Seed at the parent → sees both its own and the descendant's members.
    auto members = store.get_member_agents_in_subtrees({*pid});
    REQUIRE(members.has_value());
    CHECK(std::find(members->begin(), members->end(), "agent-p") != members->end());
    CHECK(std::find(members->begin(), members->end(), "agent-c") != members->end());

    // Empty seed set → empty value, no query.
    auto empty = store.get_member_agents_in_subtrees({});
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
}

TEST_CASE("ManagementGroupStore: get_visible_agents honors RBAC-disabled posture (#1453)",
          "[pg][management_group][roles][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup ga;
    ga.name = "Group A";
    ga.membership_type = "static";
    auto gid_a = store.create_group(ga);
    REQUIRE(gid_a.has_value());
    ManagementGroup gb;
    gb.name = "Group B";
    gb.membership_type = "static";
    auto gid_b = store.create_group(gb);
    REQUIRE(gid_b.has_value());
    store.add_member(*gid_a, "agent-001");
    store.add_member(*gid_a, "agent-002");
    store.add_member(*gid_b, "agent-003");

    SECTION("probe unset → fail-closed role-scoped join (empty without a role)") {
        auto v = store.get_visible_agents("admin");
        REQUIRE(v.has_value());
        CHECK(v->empty());
    }

    SECTION("RBAC enabled → role-scoped join, strict subset (no cross-group leak)") {
        store.set_rbac_enabled_probe([] { return true; });
        auto none = store.get_visible_agents("admin");
        REQUIRE(none.has_value());
        CHECK(none->empty());
        GroupRoleAssignment a;
        a.group_id = *gid_a;
        a.principal_type = "user";
        a.principal_id = "admin";
        a.role_name = "ITServiceOwner";
        REQUIRE(store.assign_role(a).has_value());
        auto visible = store.get_visible_agents("admin");
        REQUIRE(visible.has_value());
        CHECK(visible->size() == 2);
        CHECK(std::find(visible->begin(), visible->end(), "agent-003") == visible->end());
    }

    SECTION("RBAC disabled → full enrolled set regardless of role rows") {
        store.set_rbac_enabled_probe([] { return false; });
        auto visible = store.get_visible_agents("admin");
        REQUIRE(visible.has_value());
        REQUIRE(visible->size() == 3);
        CHECK(std::find(visible->begin(), visible->end(), "agent-003") != visible->end());
        auto nobody = store.get_visible_agents("nobody");
        REQUIRE(nobody.has_value());
        CHECK(nobody->size() == 3);
    }

    SECTION("RBAC disabled → DISTINCT dedups an agent in multiple groups") {
        store.add_member(*gid_b, "agent-001"); // agent-001 now in A and B
        store.set_rbac_enabled_probe([] { return false; });
        auto v = store.get_visible_agents("admin");
        REQUIRE(v.has_value());
        CHECK(v->size() == 3);
    }
}

TEST_CASE("ManagementGroupStore: RBAC disabled → empty fleet yields empty set",
          "[pg][management_group][roles][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};
    store.set_rbac_enabled_probe([] { return false; });
    auto v = store.get_visible_agents("admin");
    REQUIRE(v.has_value());
    CHECK(v->empty());
}

TEST_CASE("ManagementGroupStore: find_group_by_name", "[pg][management_group][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "dynamic";
    g.scope_expression = R"(tag:service == "CRM")";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    auto found = store.find_group_by_name("Service: CRM");
    REQUIRE(found.has_value());
    CHECK(found->id == *id);
    CHECK(found->name == "Service: CRM");
    CHECK(found->membership_type == "dynamic");

    auto not_found = store.find_group_by_name("Service: ERP");
    CHECK(!not_found.has_value());
}

TEST_CASE("ManagementGroupStore: update_group rejects self-parent",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "Self";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    ManagementGroup updated;
    updated.id = *id;
    updated.name = "Self";
    updated.membership_type = "static";
    updated.parent_id = *id; // attempt to become its own parent

    auto result = store.update_group(updated);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("own parent") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: update_group rejects re-parenting cycle",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup a;
    a.name = "A";
    a.membership_type = "static";
    auto a_id = store.create_group(a);
    REQUIRE(a_id.has_value());

    ManagementGroup b;
    b.name = "B";
    b.membership_type = "static";
    b.parent_id = *a_id;
    auto b_id = store.create_group(b);
    REQUIRE(b_id.has_value());

    // Attempt to set A.parent = B, which would form the cycle A->B->A.
    ManagementGroup a_update;
    a_update.id = *a_id;
    a_update.name = "A";
    a_update.membership_type = "static";
    a_update.parent_id = *b_id;

    auto result = store.update_group(a_update);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("cycle") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: update_group rejects depth overflow",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    // Build a 5-deep chain: root -> L1 -> L2 -> L3 -> L4.
    std::string prev;
    std::vector<std::string> chain;
    for (int i = 0; i < 5; ++i) {
        ManagementGroup g;
        g.name = "L" + std::to_string(i);
        g.membership_type = "static";
        g.parent_id = prev;
        auto result = store.create_group(g);
        REQUIRE(result.has_value());
        chain.push_back(*result);
        prev = *result;
    }

    ManagementGroup orphan;
    orphan.name = "Orphan";
    orphan.membership_type = "static";
    auto orphan_id = store.create_group(orphan);
    REQUIRE(orphan_id.has_value());

    ManagementGroup reparent;
    reparent.id = *orphan_id;
    reparent.name = "Orphan";
    reparent.membership_type = "static";
    reparent.parent_id = chain.back();

    auto result = store.update_group(reparent);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("depth") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: recursive CTE terminates on injected 2-node cycle",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup a;
    a.name = "Cycle-A";
    a.membership_type = "static";
    auto r1 = store.create_group(a);
    REQUIRE(r1.has_value());
    ManagementGroup b;
    b.name = "Cycle-B";
    b.membership_type = "static";
    b.parent_id = *r1;
    auto r2 = store.create_group(b);
    REQUIRE(r2.has_value());
    const std::string a_id = *r1, b_id = *r2;

    // Inject A.parent = B → the cycle A->B->A (a value the API rejects).
    exec_sql(db.dsn(), "UPDATE management_group_store.management_groups SET parent_id = '" + b_id +
                           "' WHERE id = '" + a_id + "'");

    // The bounded recursive CTE MUST terminate (not spin) and DISTINCT out any
    // phantom cycle IDs — the ADR-0042 cycle guard.
    auto descendants = store.get_descendant_ids(a_id);
    REQUIRE(descendants.has_value());
    CHECK(std::find(descendants->begin(), descendants->end(), b_id) != descendants->end());
    std::vector<std::string> sorted = *descendants;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());
}

TEST_CASE("ManagementGroupStore: recursive CTE terminates on injected 3-node cycle",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup a;
    a.name = "Three-A";
    a.membership_type = "static";
    auto r1 = store.create_group(a);
    REQUIRE(r1.has_value());
    ManagementGroup b;
    b.name = "Three-B";
    b.membership_type = "static";
    b.parent_id = *r1;
    auto r2 = store.create_group(b);
    REQUIRE(r2.has_value());
    ManagementGroup c;
    c.name = "Three-C";
    c.membership_type = "static";
    c.parent_id = *r2;
    auto r3 = store.create_group(c);
    REQUIRE(r3.has_value());
    const std::string a_id = *r1, b_id = *r2, c_id = *r3;

    // Inject A.parent = C → A->B->C->A.
    exec_sql(db.dsn(), "UPDATE management_group_store.management_groups SET parent_id = '" + c_id +
                           "' WHERE id = '" + a_id + "'");

    auto descendants = store.get_descendant_ids(a_id);
    REQUIRE(descendants.has_value());
    CHECK(std::find(descendants->begin(), descendants->end(), b_id) != descendants->end());
    CHECK(std::find(descendants->begin(), descendants->end(), c_id) != descendants->end());
    CHECK(descendants->size() <= 3); // the depth bound keeps it small
    std::vector<std::string> dsorted = *descendants;
    std::sort(dsorted.begin(), dsorted.end());
    CHECK(std::adjacent_find(dsorted.begin(), dsorted.end()) == dsorted.end());

    // Ancestor walk from C must also terminate and return at most 3 unique IDs.
    auto ancestors = store.get_ancestor_ids(c_id);
    REQUIRE(ancestors.has_value());
    CHECK(ancestors->size() <= 3);
    std::vector<std::string> asorted = *ancestors;
    std::sort(asorted.begin(), asorted.end());
    CHECK(std::adjacent_find(asorted.begin(), asorted.end()) == asorted.end());
}

TEST_CASE("ManagementGroupStore: recursive CTE terminates on self-loop row",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup a;
    a.name = "SelfLoop";
    a.membership_type = "static";
    auto r = store.create_group(a);
    REQUIRE(r.has_value());
    const std::string a_id = *r;

    // parent_id = id — the degenerate 1-row cycle.
    exec_sql(db.dsn(), "UPDATE management_group_store.management_groups SET parent_id = '" + a_id +
                           "' WHERE id = '" + a_id + "'");

    auto descendants = store.get_descendant_ids(a_id);
    REQUIRE(descendants.has_value());
    // A is its own child; the outer DISTINCT ... need not exclude it here, but
    // the walk terminates. Assert it does not blow up past the seed.
    CHECK(descendants->size() <= 1);
    auto ancestors = store.get_ancestor_ids(a_id);
    REQUIRE(ancestors.has_value());
    CHECK(ancestors->empty()); // self filtered by WHERE id <> $1
}

TEST_CASE("ManagementGroupStore: get_member_agents_in_subtrees terminates on injected cycle",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup a;
    a.name = "SubCyc-A";
    a.membership_type = "static";
    auto r1 = store.create_group(a);
    REQUIRE(r1.has_value());
    ManagementGroup b;
    b.name = "SubCyc-B";
    b.membership_type = "static";
    b.parent_id = *r1;
    auto r2 = store.create_group(b);
    REQUIRE(r2.has_value());
    const std::string a_id = *r1, b_id = *r2;
    REQUIRE(store.add_member(a_id, "agent-a").has_value());
    REQUIRE(store.add_member(b_id, "agent-b").has_value());

    exec_sql(db.dsn(), "UPDATE management_group_store.management_groups SET parent_id = '" + b_id +
                           "' WHERE id = '" + a_id + "'");

    auto members = store.get_member_agents_in_subtrees({a_id});
    REQUIRE(members.has_value()); // terminates (no hang), fully-read result
    CHECK(std::find(members->begin(), members->end(), "agent-a") != members->end());
    CHECK(std::find(members->begin(), members->end(), "agent-b") != members->end());
}

TEST_CASE("ManagementGroupStore: update_group accepts reparent-to-root",
          "[pg][management_group][hierarchy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup root;
    root.name = "RootParent";
    root.membership_type = "static";
    auto root_id = store.create_group(root);
    REQUIRE(root_id.has_value());

    ManagementGroup child;
    child.name = "MovableChild";
    child.membership_type = "static";
    child.parent_id = *root_id;
    auto child_id = store.create_group(child);
    REQUIRE(child_id.has_value());

    ManagementGroup moved;
    moved.id = *child_id;
    moved.name = "MovableChild";
    moved.membership_type = "static";
    moved.parent_id = "";
    auto result = store.update_group(moved);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*child_id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->parent_id.empty());
}

TEST_CASE("ManagementGroupStore: create_group rejects caller-supplied self-parent",
          "[pg][management_group][hierarchy][cycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.id = "abcdef012345"; // caller-supplied id
    g.parent_id = g.id;    // self-parent
    g.name = "SelfCreate";
    g.membership_type = "static";

    auto result = store.create_group(g);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("own parent") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: cascade delete removes members and roles",
          "[pg][management_group][cascade]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore store{pool};

    ManagementGroup g;
    g.name = "CascadeTest";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.add_member(*group_id, "agent-001");

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "bob";
    a.role_name = "Viewer";
    store.assign_role(a);

    store.delete_group(*group_id);

    auto members = store.get_members(*group_id);
    CHECK(members.empty());

    auto roles = store.get_group_roles(*group_id);
    CHECK(roles.empty());
}

// Degrade-distinguishable fail-closed path (ADR-0042). Deliberately NOT [pg]:
// it needs NO database — a construct-invalid pool makes is_open() false, and
// every confinement read must then report a degrade (nullopt / unexpected),
// NEVER a silent empty. This is the load-bearing property RbacStore consumes as
// DenyAll, so it must hold in every shard.
TEST_CASE("ManagementGroupStore: confinement reads degrade-distinguishable when store not open",
          "[management_group][degrade]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore store{pool};
    REQUIRE(!store.is_open());

    CHECK(!store.get_agent_groups("agent-x").has_value());
    CHECK(!store.get_ancestor_ids("group-x").has_value());
    CHECK(!store.get_descendant_ids("group-x").has_value());
    CHECK(!store.get_visible_agents("user-x").has_value());
    CHECK(!store.get_assignments_for_principal("user-x", {}).has_value());
    // A non-empty seed set must report the degrade (a silent empty deny-set is
    // the fail-OPEN ADR-0042 exists to prevent).
    CHECK(!store.get_member_agents_in_subtrees({"group-x"}).has_value());
    // Empty seeds is a genuine no-query empty, not a degrade.
    auto empty = store.get_member_agents_in_subtrees({});
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
}

// #1762: a member-read degrade must be distinguishable from a genuinely
// empty group. get_members_checked() reports the degrade (nullopt); the
// LEGACY get_members() stays fail-soft (empty vector) for its render-only
// callers, but MUST NOT be mistaken for "the group has zero members" by any
// caller that needs to fail closed instead (dex_perf_api's group_trend,
// verify_api's compare — both now use get_members_checked).
TEST_CASE("ManagementGroupStore: get_members_checked degrades on a closed store, "
         "get_members stays fail-soft (#1762)",
         "[management_group][degrade]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore store{pool};
    REQUIRE(!store.is_open());

    CHECK(!store.get_members_checked("group-x").has_value());
    // The legacy wrapper renders the SAME degrade as an empty vector — that is
    // the documented fail-soft behaviour, not a regression.
    CHECK(store.get_members("group-x").empty());
}

// #1762 (governance round-2): a group-row read degrade must be distinguishable
// from a genuine not-found. get_group_checked() reports the degrade
// (unexpected); the LEGACY get_group() stays fail-soft (nullopt, collapsing
// the two) for callers that keep the old semantics (parent-id validation in
// create_group/update_group), but MUST NOT be mistaken for "no such group" by
// a caller that needs to fail closed instead (the REST GET route and its MCP
// twin, both now on get_group_checked).
TEST_CASE("ManagementGroupStore: get_group_checked degrades on a closed store, "
         "get_group stays fail-soft (#1762)",
         "[management_group][degrade]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore store{pool};
    REQUIRE(!store.is_open());

    CHECK(!store.get_group_checked("group-x").has_value());
    // The legacy wrapper renders the SAME degrade as nullopt — that is the
    // documented fail-soft behaviour, not a regression.
    CHECK(!store.get_group("group-x").has_value());
}

TEST_CASE("ManagementGroupStore: get_group_checked distinguishes a genuine "
         "not-found from a degrade on an open store (#1762)",
         "[pg][management_group][degrade]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ManagementGroupStore store{pool};
    REQUIRE(store.is_open());

    // A genuine not-found on a healthy store is a value (present, nullopt
    // inside) — never `unexpected`.
    auto missing = store.get_group_checked("deadbeef0000");
    REQUIRE(missing.has_value());
    CHECK(!missing->has_value());

    ManagementGroup g;
    g.name = "get-group-checked-found";
    g.membership_type = "static";
    g.created_by = "tester";
    auto created = store.create_group(g);
    REQUIRE(created.has_value());

    auto found = store.get_group_checked(*created);
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->name == "get-group-checked-found");
}

