/**
 * test_access_review_model.cpp — `access_review_model.hpp`'s
 * `build_access_review` / `to_csv` (Periodic Access Reviews, SOC 2 CC6.2).
 *
 * Governance hardening round (UP-1): `build_access_review` pivoted from a
 * roster walk (user/group/engine rosters, ask RBAC per member) to being
 * GRANT-TABLE-DRIVEN (`RbacStore::list_all_principal_roles_checked()` is the
 * spine). Consequences exercised below:
 *  - A principal with ZERO grants produces NO row — the export answers "who
 *    currently has access", not "who exists". Every roster-membership-only
 *    case below asserts ABSENCE, not a hollow present-with-empty-roles row.
 *  - A grant whose principal matches nothing in any roster (deleted user,
 *    stale IdP row, an OIDC/SSO principal never materialized into a roster)
 *    is surfaced as an "orphan" row (`source="orphan"`,
 *    `lifecycle_state="unknown"`, `display_name=principal_id`) rather than
 *    silently dropped — never omitted.
 *
 * Covers:
 *  - cross-principal enumeration: user + group + engine (active AND revoked)
 *    all present in one call when GRANTED, no type dropped (the file
 *    header's "union" contract) — and a grant-less roster member is
 *    correctly excluded.
 *  - R2: per-type permission computation. A group's `effective_permission_count`
 *    comes from `get_principal_roles_checked("group", ...)` + role-permission
 *    expansion — NEVER a `get_effective_permissions(group_name)`-style
 *    username-keyed lookup (a user happens to share the group's name in one
 *    test, with a DIFFERENT role grant, to prove the two paths don't
 *    conflate). A user's own count is DIRECT-grant-only (excludes
 *    group-inherited roles) and an engine principal's count is exercised
 *    too.
 *  - UP-1: an unrostered grant (orphan user/group/engine) is surfaced, never
 *    dropped, and coexists correctly alongside a normal rostered grant.
 *  - R1 (the load-bearing one): a genuine READ FAILURE partway through
 *    enumeration (not just the top-of-function store-closed guard) makes
 *    `build_access_review` return `std::unexpected` — never a partial
 *    vector. Forced by dropping the engine-principal database out from
 *    under an already-`is_open()==true` store, so the users+groups reads
 *    that precede it in the function genuinely succeed first.
 *  - `to_csv`: header + RFC 4180 escaping (comma/quote/newline), plus CWE-1236
 *    formula-injection neutralization (leading `=`/`+`/`-`/`@`/tab/CR).
 *
 * `RbacStore` is now ALSO a born-on-Postgres store (ADR-0006), alongside
 * `AuthDB` and `EnginePrincipalStore` — every case that constructs
 * `ModelHarness` (or the standalone R1 fixture) carries `[pg]` and skips
 * cleanly without `YUZU_TEST_POSTGRES_DSN` (via `yuzu::test::AuthDbPg`'s own
 * SKIP, which now fires before the RbacStore/EnginePrincipalStore SKIPs ever
 * would) — the `to_csv` cases do not depend on any of the three stores and
 * always run.
 */

#include "access_review_model.hpp"

#include "engine_principal_store.hpp"
#include "rbac_store.hpp"

#include "pg/pg_pool.hpp"

#include <yuzu/server/auth_db.hpp>

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "test_auth_db_pg_helper.hpp"

using yuzu::server::AccessReviewRow;
using yuzu::server::AuthDB;
using yuzu::server::build_access_review;
using yuzu::server::EnginePrincipalStore;
using yuzu::server::Permission;
using yuzu::server::PrincipalRole;
using yuzu::server::RbacGroup;
using yuzu::server::RbacRole;
using yuzu::server::RbacStore;
using yuzu::server::to_csv;
using yuzu::server::auth::Role;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp) — this file
// only needs EnginePrincipalStore's schema migrated once.
void setup_access_review_model_eps_tpl(const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("access_review model template: engine principal store failed "
                                 "to migrate");
}

yuzu::test::PgTestTemplate access_review_model_eps_tpl{"accrevmodel",
                                                        &setup_access_review_model_eps_tpl};

// Pre-migrated template for RbacStore (own `rbac_store` schema) — kept as a
// SEPARATE database/template from the EnginePrincipalStore one above,
// deliberately NOT shared. The R1 fixture below drops the
// EnginePrincipalStore database out from under an already-open store to
// force a mid-enumeration read failure, while the users+groups reads (the
// groups read goes through RbacStore) must keep succeeding — sharing one PG
// database between the two stores would break that read too and defeat the
// whole point of R1. ModelHarness uses the same independent-database shape
// for consistency with the R1 fixture.
void setup_access_review_model_rbac_tpl(const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error(
            "access_review model template: rbac store failed to migrate/seed");
}

yuzu::test::PgTestTemplate access_review_model_rbac_tpl{"accrevrbac",
                                                         &setup_access_review_model_rbac_tpl};

/// Shared fixture: a born-on-PG AuthDB, plus PG-backed RbacStore and
/// EnginePrincipalStore (each on its own independent database — see the
/// setup functions above for why they're kept separate). SKIPs (Catch2 SKIP
/// from inside AuthDbPg's constructor, mirroring EnginePrincipalStorePg in
/// test_rest_engine_principal_roles.cpp) when YUZU_TEST_POSTGRES_DSN is
/// unset.
struct ModelHarness {
    yuzu::test::AuthDbPg auth_db;

    std::optional<yuzu::test::PostgresTestDb> rbac_db;
    std::optional<PgPool> rbac_pool;
    std::unique_ptr<RbacStore> rbac;

    std::optional<yuzu::test::PostgresTestDb> engine_db;
    std::optional<PgPool> engine_pool;
    std::unique_ptr<EnginePrincipalStore> engines;

    ModelHarness() {
        // Redundant with AuthDbPg's own SKIP above (both gate on the same
        // env var) — kept as a defence-in-depth guard directly on this
        // fixture's own PG dependencies (RbacStore + EnginePrincipalStore),
        // matching the original shape.
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        rbac_db.emplace(access_review_model_rbac_tpl);
        REQUIRE(rbac_db->available());
        rbac_pool.emplace(PgPool::Options{.conninfo = rbac_db->dsn(), .size = 4});
        REQUIRE(rbac_pool->valid());
        rbac = std::make_unique<RbacStore>(*rbac_pool);
        REQUIRE(rbac->is_open());

        engine_db.emplace(access_review_model_eps_tpl);
        REQUIRE(engine_db->available());
        engine_pool.emplace(PgPool::Options{.conninfo = engine_db->dsn(), .size = 4});
        REQUIRE(engine_pool->valid());
        engines = std::make_unique<EnginePrincipalStore>(*engine_pool);
        REQUIRE(engines->is_open());
    }

    void add_user(const std::string& username) {
        REQUIRE(auth_db->upsert_user(username, "hash", "salt", Role::user).has_value());
    }

    const AccessReviewRow* find(const std::vector<AccessReviewRow>& rows, const std::string& type,
                                const std::string& id) {
        for (const auto& r : rows)
            if (r.principal_type == type && r.principal_id == id)
                return &r;
        return nullptr;
    }
};

} // namespace

// ── Cross-principal enumeration ─────────────────────────────────────────────

TEST_CASE("build_access_review: union of GRANTED user/group/active-engine/revoked-engine, no "
          "type dropped — and a grant-less roster member produces NO row (UP-1)",
          "[access_review][model][pg]") {
    ModelHarness h;
    REQUIRE(h.rbac->create_role({.name = "UnionRole", .description = "d"}).has_value());

    h.add_user("alice");
    REQUIRE(h.rbac->assign_role({"user", "alice", "UnionRole"}).has_value());

    REQUIRE(h.rbac->create_group({.name = "eng", .description = "d", .source = "local"})
               .has_value());
    REQUIRE(h.rbac->assign_role({"group", "eng", "UnionRole"}).has_value());

    REQUIRE(h.engines->create("Active Svc", "alice", "j", "internal", "admin", "engine:active")
               .has_value());
    REQUIRE(h.rbac->assign_role({"engine", "engine:active", "UnionRole"}).has_value());

    REQUIRE(h.engines->create("Revoked Svc", "alice", "j", "external", "admin", "engine:revoked")
               .has_value());
    REQUIRE(h.rbac->assign_role({"engine", "engine:revoked", "UnionRole"}).has_value());
    auto revoke_res = h.engines->revoke("engine:revoked");
    REQUIRE(revoke_res.has_value());
    CHECK(*revoke_res == true);

    // UP-1: a roster member with ZERO grants must produce NO row — the export
    // answers "who currently has access", not "who exists".
    h.add_user("carol-no-grants");

    auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
    REQUIRE(result.has_value());
    const auto& rows = *result;

    const auto* user_row = h.find(rows, "user", "alice");
    REQUIRE(user_row != nullptr);
    CHECK(user_row->lifecycle_state == "active");

    const auto* group_row = h.find(rows, "group", "eng");
    REQUIRE(group_row != nullptr);

    const auto* active_engine = h.find(rows, "engine", "engine:active");
    REQUIRE(active_engine != nullptr);
    CHECK(active_engine->lifecycle_state == "active");

    // The evidence must SHOW the revoked state, not merely include the row —
    // and the row survives the revoke because `revoke()` only flips
    // `lifecycle_state` in EnginePrincipalStore; it never touches RBAC's
    // `principal_roles` (a separate store), so the grant this export walks is
    // still on record.
    const auto* revoked_engine = h.find(rows, "engine", "engine:revoked");
    REQUIRE(revoked_engine != nullptr);
    CHECK(revoked_engine->lifecycle_state == "revoked");

    // UP-1 narrowing, made explicit: present in the users roster, but never
    // granted a role — no row at all.
    CHECK(h.find(rows, "user", "carol-no-grants") == nullptr);

    // Exactly the union of GRANTED principals — one user + one group + two
    // engines, nothing dropped and nothing invented.
    CHECK(rows.size() == 4);
}

// ── R2: per-type permission computation ─────────────────────────────────────

TEST_CASE("build_access_review: R2 — a group's permission count comes from the group-direct "
          "path, never a username-keyed lookup",
          "[access_review][model][pg]") {
    ModelHarness h;

    REQUIRE(h.rbac->create_role({.name = "GroupRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"GroupRole", "Tag", "Read", "allow"}).has_value());
    REQUIRE(h.rbac->set_permission({"GroupRole", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.rbac->create_group({.name = "g1", .description = "d", .source = "local"})
               .has_value());
    REQUIRE(h.rbac->assign_role({"group", "g1", "GroupRole"}).has_value());

    // A USER literally named "g1", carrying a DIFFERENT role grant. If the
    // model ever called something like get_effective_permissions("g1") for
    // the group row (the exact anti-pattern R2's doc comment forbids), this
    // user's UserRole grant would leak onto the group's row.
    h.add_user("g1");
    REQUIRE(h.rbac->create_role({.name = "UserRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"UserRole", "Security", "Write", "allow"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "g1", "UserRole"}).has_value());

    auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
    REQUIRE(result.has_value());

    const auto* group_row = h.find(*result, "group", "g1");
    const auto* user_row = h.find(*result, "user", "g1");
    REQUIRE(group_row != nullptr);
    REQUIRE(user_row != nullptr);

    REQUIRE(group_row->roles.size() == 1);
    CHECK(group_row->roles[0] == "GroupRole");
    CHECK(group_row->effective_permission_count == 2); // Tag:Read + Inventory:Read

    REQUIRE(user_row->roles.size() == 1);
    CHECK(user_row->roles[0] == "UserRole");
    CHECK(user_row->effective_permission_count == 1); // Security:Write only
}

TEST_CASE("build_access_review: an engine principal's effective_permission_count is computed "
          "correctly",
          "[access_review][model][pg]") {
    ModelHarness h;
    h.add_user("owner1");
    REQUIRE(h.rbac->create_role({.name = "EngineRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"EngineRole", "Execution", "Execute", "allow"}).has_value());
    REQUIRE(h.engines->create("Svc", "owner1", "j", "internal", "admin", "engine:perm")
               .has_value());
    REQUIRE(h.rbac->assign_role({"engine", "engine:perm", "EngineRole"}).has_value());

    auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
    REQUIRE(result.has_value());
    const auto* row = h.find(*result, "engine", "engine:perm");
    REQUIRE(row != nullptr);
    REQUIRE(row->roles.size() == 1);
    CHECK(row->roles[0] == "EngineRole");
    CHECK(row->effective_permission_count == 1);
}

TEST_CASE("build_access_review: a user row carries DIRECT grants only — group membership does "
          "not leak into the user's own count, and a user with ONLY inherited (no direct) "
          "access produces no row at all (UP-1)",
          "[access_review][model][pg]") {
    ModelHarness h;
    REQUIRE(h.rbac->create_group({.name = "grp-inherit", .description = "d", .source = "local"})
               .has_value());
    REQUIRE(h.rbac->create_role({.name = "GroupOnlyRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"GroupOnlyRole", "Tag", "Read", "allow"}).has_value());
    REQUIRE(h.rbac->assign_role({"group", "grp-inherit", "GroupOnlyRole"}).has_value());

    // bob: group member, NO direct grant of his own.
    h.add_user("bob");
    REQUIRE(h.rbac->add_group_member("grp-inherit", "bob").has_value());

    // dana: ALSO a group member, but additionally holds a DIRECT grant of a
    // DIFFERENT role — proves the group's GroupOnlyRole does not leak onto
    // her own row's roles/count even though she does get a row (via her own
    // direct grant).
    h.add_user("dana");
    REQUIRE(h.rbac->add_group_member("grp-inherit", "dana").has_value());
    REQUIRE(h.rbac->create_role({.name = "DirectRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"DirectRole", "Security", "Write", "allow"}).has_value());
    REQUIRE(h.rbac->assign_role({"user", "dana", "DirectRole"}).has_value());

    auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
    REQUIRE(result.has_value());

    // UP-1: bob holds ZERO direct grants — group membership is not a
    // grant-table row — so he produces NO row at all, never a hollow
    // "roles: []" placeholder.
    CHECK(h.find(*result, "user", "bob") == nullptr);

    // R2: dana's row is DIRECT-grant-only — DirectRole (and only its own
    // permission), never the group's GroupOnlyRole/Tag:Read.
    const auto* dana_row = h.find(*result, "user", "dana");
    REQUIRE(dana_row != nullptr);
    REQUIRE(dana_row->roles.size() == 1);
    CHECK(dana_row->roles[0] == "DirectRole");
    CHECK(dana_row->effective_permission_count == 1); // Security:Write only

    // The group's own row DOES show the grant — it's fully visible in this
    // same export, just attributed to the group, not inherited onto either
    // member.
    const auto* group_row = h.find(*result, "group", "grp-inherit");
    REQUIRE(group_row != nullptr);
    CHECK(group_row->effective_permission_count == 1);
}

// ── UP-1: unrostered grants are surfaced as orphans, never dropped ─────────
//
// `RbacStore::assign_role` has no FK against any roster (users/groups/engine
// principals) — this is exactly the real-world shape UP-1 defends: a grant
// can outlive (or simply never correspond to) a roster row (a deleted user,
// a stale IdP-provisioned row, or an OIDC/SSO principal — e.g.
// `oidc:<iss>#<sub>` — that was never materialized into a roster). Each
// SECTION seeds such a grant directly via `assign_role` (bypassing
// `add_user`/`create_group`/`engines->create`) and asserts the row is
// surfaced, not silently omitted.

TEST_CASE("build_access_review: UP-1 — a grant whose principal matches no roster is surfaced "
          "as an orphan row, never silently dropped",
          "[access_review][model][pg]") {
    ModelHarness h;
    REQUIRE(h.rbac->create_role({.name = "OrphanRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"OrphanRole", "Tag", "Read", "allow"}).has_value());

    SECTION("orphan user — an OIDC/SSO principal never materialized into the users roster") {
        const std::string orphan_id = "oidc:https://idp.example.com#deleted-abc";
        REQUIRE(h.rbac->assign_role({"user", orphan_id, "OrphanRole"}).has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        const auto* row = h.find(*result, "user", orphan_id);
        REQUIRE(row != nullptr); // the whole point of UP-1 — never silently dropped
        CHECK(row->source == "orphan");
        CHECK(row->lifecycle_state == "unknown");
        CHECK(row->display_name == orphan_id);
        CHECK(row->owner_or_email.empty());
        CHECK(row->last_activity_kind == "n/a");
        CHECK(row->last_activity_ms == 0);
        CHECK(row->classification.empty());
        REQUIRE(row->roles.size() == 1);
        CHECK(row->roles[0] == "OrphanRole");
        CHECK(row->effective_permission_count == 1); // Tag:Read still computed correctly
    }

    SECTION("disabled user — a soft-deleted roster row with a residual grant is surfaced as "
            "source=user/lifecycle=disabled, NOT an orphan") {
        // A user who was disabled (SCIM deprovision / admin remove — a soft
        // delete that sets is_active=0 but keeps the row) while an RBAC grant
        // still points at them. This is materially different, higher-priority
        // CC6.2 evidence than an orphan: a KNOWN account with RESIDUAL access,
        // not an unrostered principal. It must NOT collapse into orphan/unknown.
        h.add_user("evicted-eve");
        REQUIRE(h.rbac->assign_role({"user", "evicted-eve", "OrphanRole"}).has_value());
        // Soft-delete via remove_user (is_active=0); the RBAC grant lives in a
        // separate store and survives, reproducing the disabled-but-granted case.
        REQUIRE(h.auth_db->remove_user("evicted-eve").has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        const auto* row = h.find(*result, "user", "evicted-eve");
        REQUIRE(row != nullptr);
        // Still a rostered user: source stays the identity source (NOT "orphan"),
        // and only the lifecycle reflects the disablement.
        CHECK(row->source != "orphan");
        CHECK(row->source == "local");             // identity source, as for an active user
        CHECK(row->lifecycle_state == "disabled"); // NOT "unknown"
        CHECK(row->display_name == "evicted-eve");
        REQUIRE(row->roles.size() == 1);
        CHECK(row->roles[0] == "OrphanRole");
        CHECK(row->effective_permission_count == 1); // Tag:Read still computed
    }

    SECTION("orphan group — a grant against a group name no longer in the groups roster") {
        REQUIRE(h.rbac->assign_role({"group", "deleted-group", "OrphanRole"}).has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        const auto* row = h.find(*result, "group", "deleted-group");
        REQUIRE(row != nullptr);
        CHECK(row->source == "orphan");
        CHECK(row->lifecycle_state == "unknown");
        CHECK(row->display_name == "deleted-group");
    }

    SECTION("orphan engine — a grant against an engine principal_id no longer in the engine "
            "roster") {
        REQUIRE(h.rbac->assign_role({"engine", "engine:deleted", "OrphanRole"}).has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        const auto* row = h.find(*result, "engine", "engine:deleted");
        REQUIRE(row != nullptr);
        CHECK(row->source == "orphan");
        CHECK(row->lifecycle_state == "unknown");
        CHECK(row->display_name == "engine:deleted");
    }

    SECTION("a NORMAL rostered grant coexists and enriches correctly alongside an orphan") {
        h.add_user("alice");
        REQUIRE(h.rbac->assign_role({"user", "alice", "OrphanRole"}).has_value());
        const std::string orphan_id = "oidc:https://idp.example.com#deleted-xyz";
        REQUIRE(h.rbac->assign_role({"user", orphan_id, "OrphanRole"}).has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        // The rostered grant enriches normally — NOT flagged as an orphan.
        const auto* alice_row = h.find(*result, "user", "alice");
        REQUIRE(alice_row != nullptr);
        CHECK(alice_row->source != "orphan");
        CHECK(alice_row->lifecycle_state == "active");
        CHECK(alice_row->display_name == "alice");

        // The orphan grant is STILL surfaced right alongside it.
        const auto* orphan_row = h.find(*result, "user", orphan_id);
        REQUIRE(orphan_row != nullptr);
        CHECK(orphan_row->source == "orphan");
        CHECK(orphan_row->lifecycle_state == "unknown");

        CHECK(result->size() == 2);
    }
}

// governance hardening round: disabled-user edges. Mirrors the "disabled
// user" SECTION above, but isolates two invariants that section doesn't
// exercise on its own: a disabled principal is subject to the SAME
// grant-table-driven "no row without a grant" rule as anyone else, and a
// disabled + an active grant coexist in one result without collapsing onto
// a shared (buggy) code path.
TEST_CASE("build_access_review: disabled-user edges — zero grants still yields no row, and a "
          "disabled + active grant coexist with distinct lifecycle_state",
          "[access_review][model][pg]") {
    ModelHarness h;
    REQUIRE(h.rbac->create_role({.name = "DisabledEdgeRole", .description = "d"}).has_value());
    REQUIRE(h.rbac->set_permission({"DisabledEdgeRole", "Tag", "Read", "allow"}).has_value());

    SECTION("a disabled user with ZERO grants produces NO row — the 'who has access' invariant "
            "holds even for a disabled account") {
        h.add_user("disabled-no-grants");
        REQUIRE(h.auth_db->remove_user("disabled-no-grants").has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        CHECK(h.find(*result, "user", "disabled-no-grants") == nullptr);
    }

    SECTION("a disabled user and an active user with grants in the SAME result — lifecycle "
            "differs, proving they don't share a buggy code path") {
        h.add_user("disabled-with-grant");
        REQUIRE(h.rbac->assign_role({"user", "disabled-with-grant", "DisabledEdgeRole"})
                    .has_value());
        REQUIRE(h.auth_db->remove_user("disabled-with-grant").has_value());

        h.add_user("active-with-grant");
        REQUIRE(h.rbac->assign_role({"user", "active-with-grant", "DisabledEdgeRole"}).has_value());

        auto result = build_access_review(h.auth_db.get(), h.rbac.get(), h.engines.get(), nullptr, nullptr);
        REQUIRE(result.has_value());

        const auto* disabled_row = h.find(*result, "user", "disabled-with-grant");
        REQUIRE(disabled_row != nullptr);
        CHECK(disabled_row->lifecycle_state == "disabled");
        CHECK(disabled_row->source != "orphan");

        const auto* active_row = h.find(*result, "user", "active-with-grant");
        REQUIRE(active_row != nullptr);
        CHECK(active_row->lifecycle_state == "active");
        CHECK(active_row->source != "orphan");
    }
}

// ── R1: error propagation — the anti-silent-partial-export guard ───────────

TEST_CASE("build_access_review: R1 — a genuine read failure MID-enumeration returns "
          "unexpected, never a partial vector",
          "[access_review][model][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }

    std::optional<yuzu::test::PostgresTestDb> engine_db;
    engine_db.emplace(access_review_model_eps_tpl);
    REQUIRE(engine_db->available());
    std::optional<PgPool> pool;
    pool.emplace(PgPool::Options{.conninfo = engine_db->dsn(), .size = 2});
    REQUIRE(pool->valid());
    auto engines = std::make_unique<EnginePrincipalStore>(*pool);
    REQUIRE(engines->is_open());

    yuzu::test::AuthDbPg auth_db;
    REQUIRE(auth_db->upsert_user("alice", "hash", "salt", Role::user).has_value());

    // RbacStore needs an INDEPENDENT database from `engine_db` below — R1
    // forces the mid-enumeration failure by dropping `engine_db` out from
    // under the already-`is_open()==true` `engines` store while the
    // users+groups reads (the groups read goes through `rbac`) must keep
    // succeeding first. Sharing engine_db's pool here would break both
    // reads at once and defeat the whole point of this test.
    yuzu::test::PostgresTestDb rbac_db{access_review_model_rbac_tpl};
    REQUIRE(rbac_db.available());
    PgPool rbac_pool{{.conninfo = rbac_db.dsn(), .size = 4}};
    REQUIRE(rbac_pool.valid());
    RbacStore rbac{rbac_pool};
    REQUIRE(rbac.is_open());
    REQUIRE(rbac.create_group({.name = "eng", .description = "d", .source = "local"})
               .has_value());

    // build_access_review reads users, then groups, then engine principals
    // (access_review_model.cpp) — users and groups above are both genuinely
    // readable right now. Force the LAST read (engine principals) to fail by
    // dropping the database out from under the still-`is_open()==true`
    // store: `is_open()` is a bool cached at construction (never re-probed),
    // so the top-of-function `!engines->is_open()` guard still passes — this
    // is a REAL mid-enumeration failure on `list_all_checked`, not the
    // trivial "the call never even started" guard case.
    engine_db.reset(); // DROP DATABASE ... WITH (FORCE)

    auto result = build_access_review(auth_db.get(), &rbac, engines.get(), nullptr, nullptr);
    REQUIRE_FALSE(result.has_value());
    // std::expected holding `unexpected` structurally CANNOT also carry a
    // vector — there is no "partial vector" representation to leak here;
    // this assertion is the whole point of R1.
    CHECK(result.error().find("engine principal") != std::string::npos);
}

// ── access_review_rbac_enforcement (A3, RBAC delivery plan) ────────────────

// Thin-wrapper correctness only — the exhaustive three-way derivation
// (null/unopened store, cached-enabled, fresh-disabled, degraded-view) is
// covered by rbac_enforcement_label's own tests in test_rbac_store.cpp; this
// proves access_review_rbac_enforcement forwards to it faithfully rather than
// re-deriving anything independently.
TEST_CASE("access_review_rbac_enforcement forwards to rbac_enforcement_label/to_string",
          "[access_review][model][pg]") {
    CHECK(yuzu::server::access_review_rbac_enforcement(nullptr) == "degraded");

    ModelHarness h;
    REQUIRE_FALSE(h.rbac->is_rbac_enabled()); // fresh install default
    CHECK(yuzu::server::access_review_rbac_enforcement(h.rbac.get()) == "disabled");

    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->is_rbac_enabled());
    CHECK(yuzu::server::access_review_rbac_enforcement(h.rbac.get()) == "enabled");
}

// ── to_csv ───────────────────────────────────────────────────────────────────

TEST_CASE("to_csv: header + RFC 4180 escaping for comma/quote/newline", "[access_review][model]") {
    AccessReviewRow r;
    r.principal_type = "user";
    r.principal_id = "alice";
    r.display_name = "Alice, \"The\" Admin\nSecond line";
    r.owner_or_email = "alice@example.com";
    r.roles = {"Role, A", "RoleB"};
    r.effective_permission_count = 3;
    r.last_activity_ms = 1000;
    r.last_activity_kind = "last_login";
    r.classification = "";
    r.lifecycle_state = "active";
    r.source = "local";

    auto csv = to_csv({r}, "enabled");

    // The unconditional leading metadata line precedes the header row.
    CHECK(csv.starts_with("# rbac_enforcement=enabled\r\n"
                         "principal_type,principal_id,display_name,owner_or_email,roles,"
                         "effective_permission_count,last_activity_ms,last_activity_kind,"
                         "classification,lifecycle_state,source\r\n"));
    // display_name has a comma, embedded double-quotes, AND a newline — must
    // be wrapped in quotes with interior quotes doubled, embedded newline
    // preserved verbatim inside the quoted field.
    CHECK(csv.find("\"Alice, \"\"The\"\" Admin\nSecond line\"") != std::string::npos);
    // roles is semicolon-joined ("Role, A;RoleB") — THAT joined string still
    // contains a comma (from within "Role, A"), so the whole field is quoted.
    CHECK(csv.find("\"Role, A;RoleB\"") != std::string::npos);
    // Unquoted numeric/plain fields pass through untouched.
    CHECK(csv.find(",3,1000,last_login,") != std::string::npos);
    CHECK(csv.ends_with(",active,local\r\n"));
}

TEST_CASE("to_csv: empty input yields metadata line + header only", "[access_review][model]") {
    auto csv = to_csv({}, "disabled");
    // A3: the metadata line is unconditional — present even with zero rows,
    // so "no grants" is never ambiguous with "the stamp was omitted".
    CHECK(csv == "# rbac_enforcement=disabled\r\n"
                "principal_type,principal_id,display_name,owner_or_email,roles,"
                "effective_permission_count,last_activity_ms,last_activity_kind,"
                "classification,lifecycle_state,source\r\n");
}

// ── to_csv: rbac_enforcement metadata line (A3, RBAC delivery plan) ────────

TEST_CASE("to_csv: rbac_enforcement metadata line carries each of the three enforcement "
         "values, both with and without rows",
         "[access_review][model][csv]") {
    AccessReviewRow r;
    r.principal_type = "user";
    r.principal_id = "alice";
    r.display_name = "Alice";
    r.source = "local";

    for (const std::string& value : {"enabled", "disabled", "degraded"}) {
        INFO("rbac_enforcement=" << value);

        // Non-empty population: exactly one metadata line, immediately
        // followed by the real header — never duplicated, never
        // interleaved with a data row.
        auto csv = to_csv({r}, value);
        CHECK(csv.find("# rbac_enforcement=" + value +
                       "\r\nprincipal_type,principal_id,display_name,owner_or_email,roles,"
                       "effective_permission_count,last_activity_ms,last_activity_kind,"
                       "classification,lifecycle_state,source\r\n") == 0);

        // Empty population: the metadata line is UNCONDITIONAL — a
        // zero-grant population is never ambiguous with "the stamp was
        // omitted".
        auto csv_empty = to_csv({}, value);
        CHECK(csv_empty == "# rbac_enforcement=" + value +
                          "\r\nprincipal_type,principal_id,display_name,owner_or_email,roles,"
                          "effective_permission_count,last_activity_ms,last_activity_kind,"
                          "classification,lifecycle_state,source\r\n");
    }
}

// ── to_csv: CWE-1236 formula-injection neutralization ──────────────────────

TEST_CASE("to_csv: CWE-1236 — a leading formula-trigger byte is neutralized with a leading "
          "apostrophe before RFC-4180 quoting is applied",
          "[access_review][model][csv]") {
    SECTION("a field needing BOTH neutralization AND quoting: leading '=' plus embedded commas "
            "and quotes still renders with the neutralizing apostrophe as the FIRST character "
            "of the quoted value") {
        AccessReviewRow r;
        r.principal_type = "user";
        r.principal_id = R"(=HYPERLINK("http://evil.example","click"))";
        r.display_name = "x";
        r.source = "local";
        auto csv = to_csv({r}, "enabled");
        // Neutralize first ('=HYPERLINK(...) -> '=HYPERLINK(...)), THEN
        // RFC-4180-quote (still contains commas/quotes, so it's wrapped, with
        // interior quotes doubled) — the apostrophe is the first character
        // inside the quotes, proving neutralization ran before quoting.
        const std::string expected =
            "\"'=HYPERLINK(\"\"http://evil.example\"\",\"\"click\"\")\"";
        CHECK(csv.find(expected) != std::string::npos);
    }

    SECTION("a field needing ONLY neutralization (no comma/quote/newline) stays unquoted, just "
            "apostrophe-prefixed") {
        for (const char trigger : {'=', '+', '-', '@'}) {
            INFO("trigger=" << trigger);
            AccessReviewRow r;
            r.principal_type = "user";
            r.principal_id = "id1";
            r.display_name = "x";
            r.roles = {std::string(1, trigger) + "cmd"};
            r.source = "local";
            auto csv = to_csv({r}, "enabled");
            // roles field sits between owner_or_email (empty) and
            // effective_permission_count (0) — bounded on both sides by a
            // comma with nothing else that could false-match.
            const std::string expected = ",'" + std::string(1, trigger) + "cmd,0,";
            CHECK(csv.find(expected) != std::string::npos);
        }
    }

    SECTION("a leading tab is neutralized and stays unquoted (tab is not itself an RFC-4180 "
            "quote trigger)") {
        AccessReviewRow r;
        r.principal_type = "user";
        r.principal_id = "id2";
        r.display_name = "\t=cmd";
        r.source = "local";
        auto csv = to_csv({r}, "enabled");
        CHECK(csv.find("id2,'\t=cmd,,") != std::string::npos);
    }

    SECTION("a leading CR is neutralized AND triggers RFC-4180 quoting (CR is also a quote "
            "trigger) — the smuggle-past-a-naive-'='-check case") {
        AccessReviewRow r;
        r.principal_type = "user";
        r.principal_id = "id3";
        r.display_name = "\r=cmd";
        r.source = "local";
        auto csv = to_csv({r}, "enabled");
        CHECK(csv.find("id3,\"'\r=cmd\",") != std::string::npos);
    }

    SECTION("a field NOT starting with a trigger byte is left byte-for-byte untouched") {
        AccessReviewRow r;
        r.principal_type = "user";
        r.principal_id = "normal-id";
        r.display_name = "Normal Name";
        r.source = "local";
        auto csv = to_csv({r}, "enabled");
        CHECK(csv.find(",normal-id,Normal Name,") != std::string::npos);
    }
}
