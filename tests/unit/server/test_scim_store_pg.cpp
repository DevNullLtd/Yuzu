// ScimStore born-on-Postgres tests (auth.db -> PG migration, ADR-0006):
// resource provision/deprovision/reactivate + etag bump, token create ->
// verify -> revoke, group CRUD + membership, active-flag transitions, the
// displayName-keyed group lookup semantics, and the fresh-start /
// migration-failure construction contracts. Schema `scim_store`.

#include <catch2/catch_test_macros.hpp>

#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::LinkedIdentity;
using yuzu::server::ScimGroup;
using yuzu::server::ScimResource;
using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp). The
// migration-failure / fresh-start-construction tests stay on plain
// YUZU_REQUIRE_PG_DB — they need an empty database, not an already-migrated
// one.
yuzu::test::PgTestTemplate scim_tpl{"scimstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool}; // ctor runs the schema migration
    if (!store.is_open())
        throw std::runtime_error("scim template: store failed to migrate");
}};

} // namespace

TEST_CASE("ScimStore fresh-start construction succeeds on an empty database", "[pg][scim]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    CHECK(store.is_open());
}

// gov fjarvis B1 pattern (mirrors OfflineEndpointStore): a reachable database
// whose schema migration FAILS must leave the store !is_open() — the server
// wires that to startup_failed_ (fail closed, never serve-degraded).
TEST_CASE("ScimStore reports !is_open on a migration failure", "[pg][scim]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Pre-seed: create the scim_store schema + a conflicting table, but no
    // public.schema_meta row for the store — the runner's schema-drift guard
    // refuses (version 0 but tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA scim_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE scim_store.scim_resources (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("ScimStore resource provision / deprovision / reactivate + etag bump", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("create_resource assigns a scim_id, defaults active=true, etag=1") {
        auto r = store.create_resource("alice", "ext-1");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->scim_id.empty());
        CHECK(r->external_id == "ext-1");
        CHECK(r->username == "alice");
        CHECK(r->active);
        CHECK(r->etag_version == 1);
        CHECK_FALSE(r->created_at.empty());
        CHECK_FALSE(r->updated_at.empty());
    }

    SECTION("create_resource with empty external_id round-trips as empty (stored NULL)") {
        auto r = store.create_resource("noext");
        REQUIRE(r.has_value());
        CHECK(r->external_id.empty());
    }

    SECTION("create_resource rejects a duplicate username (UNIQUE)") {
        REQUIRE(store.create_resource("dupe").has_value());
        CHECK_FALSE(store.create_resource("dupe").has_value());
    }

    SECTION("get_by_scim_id / get_by_username / find_by_external_id round-trip") {
        auto r = store.create_resource("bob", "ext-bob");
        REQUIRE(r.has_value());

        auto by_id = store.get_by_scim_id(r->scim_id);
        REQUIRE(by_id.has_value());
        CHECK(by_id->username == "bob");

        auto by_username = store.get_by_username("bob");
        REQUIRE(by_username.has_value());
        CHECK(by_username->scim_id == r->scim_id);

        auto by_ext = store.find_by_external_id("ext-bob");
        REQUIRE(by_ext.has_value());
        CHECK(by_ext->scim_id == r->scim_id);

        CHECK_FALSE(store.find_by_external_id("").has_value());
        CHECK_FALSE(store.get_by_scim_id("does-not-exist").has_value());
    }

    SECTION("set_active toggles + bumps etag_version and updated_at") {
        auto r = store.create_resource("carol");
        REQUIRE(r.has_value());
        REQUIRE(store.set_active(r->scim_id, false)); // deprovision
        auto after_deactivate = store.get_by_scim_id(r->scim_id);
        REQUIRE(after_deactivate.has_value());
        CHECK_FALSE(after_deactivate->active);
        CHECK(after_deactivate->etag_version == 2);

        REQUIRE(store.set_active(r->scim_id, true)); // reactivate
        auto after_reactivate = store.get_by_scim_id(r->scim_id);
        REQUIRE(after_reactivate.has_value());
        CHECK(after_reactivate->active);
        CHECK(after_reactivate->etag_version == 3);

        CHECK_FALSE(store.set_active("no-such-id", true));
    }

    SECTION("update_resource bumps etag_version") {
        auto r = store.create_resource("dave", "old-ext");
        REQUIRE(r.has_value());
        REQUIRE(store.update_resource(r->scim_id, "dave2", "new-ext"));
        auto updated = store.get_by_scim_id(r->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->username == "dave2");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);
    }

    SECTION("delete_by_scim_id: true on first delete, false (idempotent) on the second") {
        auto r = store.create_resource("erin");
        REQUIRE(r.has_value());
        auto first = store.delete_by_scim_id(r->scim_id);
        REQUIRE(first.has_value());
        CHECK(*first == true);

        auto second = store.delete_by_scim_id(r->scim_id);
        REQUIRE(second.has_value());
        CHECK(*second == false);

        CHECK_FALSE(store.get_by_scim_id(r->scim_id).has_value());
    }

    // Gate-8 round-2 MEDIUM (CC6.8), ported from the pre-migration SQLite
    // test (dropped in the PG migration): a genuine query-time failure must
    // surface as `nullopt`, NEVER collapse to `false` ("already gone") — the
    // routes layer relies on that distinction to 500 a failed teardown
    // instead of 204ing it. Force a deterministic PG-side failure by
    // dropping the backing table out from under the already-open store
    // (each YUZU_REQUIRE_PG_DB_TPL test gets its own clone, so this cannot
    // bleed into another case).
    SECTION("delete_by_scim_id surfaces a genuine query-time error as nullopt, never false") {
        auto r = store.create_resource("frank");
        REQUIRE(r.has_value());

        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            auto drop = yuzu::server::pg::exec_params(
                lease.get(), "DROP TABLE scim_store.scim_resources", std::vector<std::string>{});
            REQUIRE(drop.ok());
        }

        auto result = store.delete_by_scim_id(r->scim_id);
        CHECK_FALSE(result.has_value()); // DB error → nullopt, NOT value(false)
    }

    SECTION("list paginates in stable creation order and reports total_out") {
        REQUIRE(store.create_resource("p1").has_value());
        REQUIRE(store.create_resource("p2").has_value());
        REQUIRE(store.create_resource("p3").has_value());

        int total = 0;
        auto page1 = store.list(1, 2, total);
        CHECK(total >= 3);
        REQUIRE(page1.size() == 2);
        CHECK(page1[0].username == "p1");
        CHECK(page1[1].username == "p2");

        int total2 = 0;
        auto page2 = store.list(3, 2, total2);
        REQUIRE(page2.size() >= 1);
        CHECK(page2[0].username == "p3");
    }
}

TEST_CASE("ScimStore bearer token create / verify / revoke", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("no token initially") {
        CHECK_FALSE(store.has_token());
        CHECK_FALSE(store.validate_token("anything"));
    }

    SECTION("set_token then validate with the correct raw value succeeds") {
        REQUIRE(store.set_token("s3cr3t-raw-token", "idp-1"));
        CHECK(store.has_token());
        CHECK(store.validate_token("s3cr3t-raw-token"));
        CHECK_FALSE(store.validate_token("wrong-token"));
        CHECK_FALSE(store.validate_token(""));
    }

    SECTION("re-setting the same label revokes the prior token (upsert by label)") {
        REQUIRE(store.set_token("first-token", "idp-1"));
        REQUIRE(store.set_token("second-token", "idp-1"));
        CHECK_FALSE(store.validate_token("first-token"));
        CHECK(store.validate_token("second-token"));
    }

    SECTION("set_token rejects an empty raw value") {
        CHECK_FALSE(store.set_token("", "idp-1"));
        CHECK_FALSE(store.has_token());
    }

    // Ported from the pre-migration SQLite test (dropped in the PG
    // migration): set_token upserts BY LABEL, so two distinct labels are
    // two independent active rows, not one overwritten row — both must
    // still validate.
    SECTION("distinct labels coexist as separate active tokens") {
        REQUIRE(store.set_token("token-a", "label-a"));
        REQUIRE(store.set_token("token-b", "label-b"));

        CHECK(store.validate_token("token-a"));
        CHECK(store.validate_token("token-b"));
    }
}

TEST_CASE("ScimStore group CRUD, membership, and displayName-keyed lookup", "[pg][scim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("create_group + get_group_by_id / get_group_by_display_name round-trip") {
        auto g = store.create_group("Engineering", "ext-grp-1");
        REQUIRE(g.has_value());
        CHECK_FALSE(g->scim_id.empty());
        CHECK(g->display_name == "Engineering");
        CHECK(g->active);
        CHECK(g->etag_version == 1);

        auto by_id = store.get_group_by_id(g->scim_id);
        REQUIRE(by_id.has_value());
        CHECK(by_id->display_name == "Engineering");

        // displayName-keyed match: exact-match lookup, no DB-level UNIQUE —
        // used by the routes layer for idempotent-create / 409 checks.
        auto by_name = store.get_group_by_display_name("Engineering");
        REQUIRE(by_name.has_value());
        CHECK(by_name->scim_id == g->scim_id);
        CHECK_FALSE(store.get_group_by_display_name("Nonexistent").has_value());
    }

    SECTION("displayName has no uniqueness constraint at the storage layer") {
        auto g1 = store.create_group("Sales");
        auto g2 = store.create_group("Sales");
        REQUIRE(g1.has_value());
        REQUIRE(g2.has_value());
        CHECK(g1->scim_id != g2->scim_id);
    }

    SECTION("update_group bumps etag_version") {
        auto g = store.create_group("Support", "old-ext");
        REQUIRE(g.has_value());
        REQUIRE(store.update_group(g->scim_id, "Support2", "new-ext"));
        auto updated = store.get_group_by_id(g->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->display_name == "Support2");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);
        CHECK_FALSE(store.update_group("no-such-group", "x", ""));
    }

    SECTION("count_groups / list_groups pagination") {
        REQUIRE(store.create_group("G1").has_value());
        REQUIRE(store.create_group("G2").has_value());
        int before = store.count_groups();
        REQUIRE(store.create_group("G3").has_value());
        CHECK(store.count_groups() == before + 1);

        int total = 0;
        auto page = store.list_groups(1, 2, total);
        CHECK(total >= 3);
        CHECK(page.size() == 2);
    }

    SECTION("add_group_member / remove_group_member are idempotent") {
        auto g = store.create_group("Membership1");
        REQUIRE(g.has_value());
        CHECK(store.add_group_member(g->scim_id, "user-a"));
        CHECK(store.add_group_member(g->scim_id, "user-a")); // idempotent no-op
        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "user-a");

        CHECK(store.remove_group_member(g->scim_id, "user-a"));
        CHECK(store.remove_group_member(g->scim_id, "user-a")); // idempotent no-op
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());
    }

    SECTION("set_group_members replaces the entire membership set") {
        auto g = store.create_group("Membership2");
        REQUIRE(g.has_value());
        REQUIRE(store.set_group_members(g->scim_id, {"u1", "u2", "u3"}));
        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        CHECK(members.size() == 3);

        REQUIRE(store.set_group_members(g->scim_id, {"u4"}));
        members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "u4");

        REQUIRE(store.set_group_members(g->scim_id, {})); // empty set is a real value
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());
    }

    SECTION("list_group_display_names_for_user reverse lookup") {
        auto g1 = store.create_group("Alpha");
        auto g2 = store.create_group("Beta");
        REQUIRE(g1.has_value());
        REQUIRE(g2.has_value());
        REQUIRE(store.add_group_member(g1->scim_id, "shared-user"));
        REQUIRE(store.add_group_member(g2->scim_id, "shared-user"));

        auto names = store.list_group_display_names_for_user("shared-user").value();
        REQUIRE(names.size() == 2);
        CHECK(names[0] == "Alpha"); // ordered by display_name ASC
        CHECK(names[1] == "Beta");

        CHECK(store.list_group_display_names_for_user("no-such-user").value().empty());
    }

    SECTION("replace_group_and_members atomically renames + replaces membership") {
        auto g = store.create_group("Original", "orig-ext");
        REQUIRE(g.has_value());
        REQUIRE(store.set_group_members(g->scim_id, {"old-member"}));

        auto result =
            store.replace_group_and_members(g->scim_id, "Renamed", "new-ext", {"new-member"});
        REQUIRE(result.has_value());
        CHECK(*result == true);

        auto updated = store.get_group_by_id(g->scim_id);
        REQUIRE(updated.has_value());
        CHECK(updated->display_name == "Renamed");
        CHECK(updated->external_id == "new-ext");
        CHECK(updated->etag_version == 2);

        auto members = store.list_group_member_user_scim_ids(g->scim_id).value();
        REQUIRE(members.size() == 1);
        CHECK(members[0] == "new-member");
    }

    SECTION("replace_group_and_members on an unknown scim_id reports false, no side effects") {
        auto result = store.replace_group_and_members("no-such-group", "X", "", {"m1"});
        REQUIRE(result.has_value());
        CHECK(*result == false);
    }

    SECTION("delete_group cascades membership and is idempotent (tri-state)") {
        auto g = store.create_group("ToDelete");
        REQUIRE(g.has_value());
        REQUIRE(store.add_group_member(g->scim_id, "member-x"));

        auto first = store.delete_group(g->scim_id);
        REQUIRE(first.has_value());
        CHECK(*first == true);
        CHECK_FALSE(store.get_group_by_id(g->scim_id).has_value());
        // The reverse lookup must not dangle after the cascade.
        CHECK(store.list_group_member_user_scim_ids(g->scim_id).value().empty());

        auto second = store.delete_group(g->scim_id);
        REQUIRE(second.has_value());
        CHECK(*second == false); // idempotent: already gone
    }
}

// ── Transaction-rollback coverage (re-ported from the deleted SQLite
//    test_scim_group_store.cpp; 2026-07-25 review MEDIUM) ──────────────────
//
// The SQLite suite proved all three `with_txn_for` writers roll back FULLY —
// not just the failed statement — by poisoning a member id with a trigger so
// the INSERT loop aborts after the transaction's earlier DELETE/UPDATE have
// already run. Those three cases were dropped in the PG migration and had no
// replacement, leaving every rollback path untested. This is the same
// technique in Postgres (plpgsql RAISE EXCEPTION instead of RAISE(ABORT)).
//
// This matters more on PG than it did on SQLite: `replace_group_and_members`
// is what the SCIM PUT/PATCH routes commit, so a partial apply here is a
// torn group membership and, through the role recompute, a wrong admin set.

namespace {

// Abort any INSERT of the sentinel member id, mid-transaction.
void install_member_insert_poison(PGconn* conn) {
    PgResult fn{PQexec(conn, R"(
        CREATE OR REPLACE FUNCTION scim_store.poison_member_insert() RETURNS trigger AS $$
        BEGIN
            IF NEW.user_scim_id = 'POISON' THEN
                RAISE EXCEPTION 'induced failure';
            END IF;
            RETURN NEW;
        END; $$ LANGUAGE plpgsql;
    )")};
    REQUIRE(fn.ok());
    PgResult trg{PQexec(conn, "CREATE TRIGGER poison_member_insert BEFORE INSERT ON "
                              "scim_store.scim_group_members FOR EACH ROW "
                              "EXECUTE FUNCTION scim_store.poison_member_insert()")};
    REQUIRE(trg.ok());
}

// Abort the group DELETE itself, after the membership rows have been removed
// earlier in the same transaction.
void install_group_delete_poison(PGconn* conn) {
    PgResult fn{PQexec(conn, R"(
        CREATE OR REPLACE FUNCTION scim_store.poison_group_delete() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'induced failure';
        END; $$ LANGUAGE plpgsql;
    )")};
    REQUIRE(fn.ok());
    PgResult trg{PQexec(conn, "CREATE TRIGGER poison_group_delete BEFORE DELETE ON "
                              "scim_store.scim_groups FOR EACH ROW "
                              "EXECUTE FUNCTION scim_store.poison_group_delete()")};
    REQUIRE(trg.ok());
}

std::vector<std::string> sorted_members(ScimStore& store, const std::string& scim_id) {
    auto members = store.list_group_member_user_scim_ids(scim_id);
    REQUIRE(members.has_value());
    auto out = *members;
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace

TEST_CASE("ScimStore: replace_group_and_members rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Sales", "ext-1");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_member_insert_poison(conn.get());

    auto result = store.replace_group_and_members(grp->scim_id, "Sales EMEA", "ext-2",
                                                  {"new-1", "POISON", "new-2"});
    REQUIRE_FALSE(result.has_value());

    // Neither half of the write leaked: the rename did NOT persist...
    auto after = store.get_group_by_id(grp->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name == "Sales");
    CHECK(after->external_id == "ext-1");

    // ...and the membership-clearing DELETE that ran earlier in the SAME
    // transaction rolled back too. A half-applied outcome (just "new-1", or
    // an empty set) is the bug this guards.
    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: set_group_members rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_member_insert_poison(conn.get());

    CHECK_FALSE(store.set_group_members(grp->scim_id, {"new-1", "POISON", "new-2"}));

    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: delete_group rolls back fully on a mid-transaction failure",
          "[pg][scim][group][transaction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("Doomed");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"m1", "m2"}));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    install_group_delete_poison(conn.get());

    // nullopt = "could not determine" (fail closed / retry), never a silent
    // "already gone" — the tri-state delete_by_scim_id contract.
    auto result = store.delete_group(grp->scim_id);
    CHECK_FALSE(result.has_value());

    // The group AND its membership both survive — the cascade DELETE that ran
    // first in the transaction was rolled back with it.
    CHECK(store.get_group_by_id(grp->scim_id).has_value());
    auto members = sorted_members(store, grp->scim_id);
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "m1");
    CHECK(members[1] == "m2");
}

// ── 2026-07-25 review HIGH #3: authoritative membership reads fail CLOSED ──
//
// The reviewer's scenario: a transient read failure was indistinguishable
// from "this group has no members", and because the SCIM PATCH route folds
// its ops onto that read and then persists the whole set, one blip durably
// deleted a group's entire membership. The store-level contract that makes
// the route fix possible is that a failed read is `nullopt`, never an
// engaged-but-empty vector.
TEST_CASE("ScimStore: a FAILED membership read is nullopt, never an empty member set",
          "[pg][scim][group][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto grp = store.create_group("RealMembers");
    REQUIRE(grp.has_value());
    REQUIRE(store.set_group_members(grp->scim_id, {"u1", "u2"}));

    // Sanity: a genuinely empty group is an ENGAGED empty vector, which must
    // stay distinguishable from the failure below.
    auto empty_grp = store.create_group("NoMembers");
    REQUIRE(empty_grp.has_value());
    auto empty_read = store.list_group_member_user_scim_ids(empty_grp->scim_id);
    REQUIRE(empty_read.has_value());
    CHECK(empty_read->empty());

    // Break the reads' statements only (the join table for the forward read,
    // which the reverse read also traverses).
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP TABLE scim_store.scim_group_members")};
    REQUIRE(drop.ok());

    CHECK_FALSE(store.list_group_member_user_scim_ids(grp->scim_id).has_value());
    CHECK_FALSE(store.list_group_display_names_for_user("u1").has_value());
}

// ── ADR-2001 Task 1 — identity linkage foundation ───────────────────────
//
// identity_links / oidc_login_observations tables + the
// scim_resources.external_id ambiguity fix (find_unique_active_by_external_id
// + the partial-unique index + its fail-closed migration). No route/
// orchestration behaviour lands here — pure substrate.

TEST_CASE("ScimStore: find_unique_active_by_external_id — exactly-one / zero / "
         "empty-input contract",
         "[pg][scim][2001][linkage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("returns the row on exactly one match") {
        auto r = store.create_resource("alice", "ext-unique-1");
        REQUIRE(r.has_value());
        auto found = store.find_unique_active_by_external_id("ext-unique-1");
        REQUIRE(found.has_value());
        CHECK(found->scim_id == r->scim_id);
        CHECK(found->username == "alice");
    }

    SECTION("nullopt on zero matches") {
        CHECK_FALSE(store.find_unique_active_by_external_id("no-such-ext-id").has_value());
    }

    SECTION("nullopt on empty external_id") {
        CHECK_FALSE(store.find_unique_active_by_external_id("").has_value());
    }

    SECTION("nullopt when the only match is inactive (deprovisioned)") {
        auto r = store.create_resource("inactive-user", "ext-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.set_active(r->scim_id, false));
        CHECK_FALSE(store.find_unique_active_by_external_id("ext-inactive").has_value());
    }
}

// Mutation-check (ADR-2001 task spec): if `find_unique_active_by_external_id`
// regressed to `... LIMIT 1` instead of asserting exactly-one-row, this test
// would start passing a value instead of nullopt — that is the bug this test
// exists to catch. The partial-unique index (migration v3) makes this
// scenario unreachable through the store's own write path once the store is
// open, so the duplicate rows are seeded directly via SQL after dropping the
// index — modelling "a duplicate slipped in via a bug/manual DB edit", the
// exact belt-and-braces scenario ADR-2001 §2 calls out for this method.
TEST_CASE("ScimStore: find_unique_active_by_external_id returns nullopt on TWO "
         "matching active rows (mis-link guard, mutation-checked)",
         "[pg][scim][2001][linkage][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
    REQUIRE(drop.ok());

    auto r1 = store.create_resource("dup-user-1", "dup-ext");
    auto r2 = store.create_resource("dup-user-2", "dup-ext");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r1->scim_id != r2->scim_id);

    CHECK_FALSE(store.find_unique_active_by_external_id("dup-ext").has_value());
}

TEST_CASE("ScimStore: identity_links upsert + links_for_scim_id", "[pg][scim][2001][linkage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("upsert_link is idempotent and links_for_scim_id returns it") {
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-1", "scim-alice"));
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-1", "scim-alice")); // repeat

        auto links = store.links_for_scim_id("scim-alice");
        REQUIRE(links.has_value());
        REQUIRE(links->size() == 1);
        CHECK((*links)[0].iss == "https://idp.example.com/");
        CHECK((*links)[0].sub == "sub-1");
    }

    SECTION("multiple (iss,sub) identities can link to the same scim_id") {
        REQUIRE(store.upsert_link("https://idp-a.example.com/", "sub-a", "scim-bob"));
        REQUIRE(store.upsert_link("https://idp-b.example.com/", "sub-b", "scim-bob"));

        auto links = store.links_for_scim_id("scim-bob");
        REQUIRE(links.has_value());
        REQUIRE(links->size() == 2);
    }

    SECTION("links_for_scim_id returns an engaged-but-empty vector for an unknown scim_id") {
        auto links = store.links_for_scim_id("no-such-scim-id");
        REQUIRE(links.has_value());
        CHECK(links->empty());
    }

    SECTION("re-linking the same (iss,sub) to a different scim_id moves the link "
           "(UNIQUE (iss,sub) enforced)") {
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-move", "scim-old"));
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-move", "scim-new"));

        CHECK(store.links_for_scim_id("scim-old")->empty());
        auto new_links = store.links_for_scim_id("scim-new");
        REQUIRE(new_links.has_value());
        REQUIRE(new_links->size() == 1);
        CHECK((*new_links)[0].sub == "sub-move");
    }

    SECTION("upsert_link rejects empty iss/sub/scim_id") {
        CHECK_FALSE(store.upsert_link("", "sub", "scim-x"));
        CHECK_FALSE(store.upsert_link("iss", "", "scim-x"));
        CHECK_FALSE(store.upsert_link("iss", "sub", ""));
    }
}

TEST_CASE("ScimStore: oidc_login_observations upsert-on-relogin + observation_matches",
         "[pg][scim][2001][linkage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("observation_matches is false before any observation is recorded") {
        CHECK_FALSE(store.observation_matches("some-claim-value"));
    }

    SECTION("record then observation_matches is true for the exact value, false otherwise") {
        REQUIRE(store.record_login_observation("https://idp.example.com/", "sub-1", "sub",
                                               "candidate-value-1"));
        CHECK(store.observation_matches("candidate-value-1"));
        CHECK_FALSE(store.observation_matches("some-other-value"));
    }

    SECTION("re-login with a different claim_value upserts (replaces) the prior observation") {
        REQUIRE(store.record_login_observation("https://idp.example.com/", "sub-1", "sub",
                                               "first-login-value"));
        CHECK(store.observation_matches("first-login-value"));

        REQUIRE(store.record_login_observation("https://idp.example.com/", "sub-1", "sub",
                                               "second-login-value"));
        CHECK(store.observation_matches("second-login-value"));
        // The stale value from the first login no longer matches — one row
        // per (iss,sub), upserted, not accumulated.
        CHECK_FALSE(store.observation_matches("first-login-value"));
    }

    SECTION("record_login_observation rejects empty iss/sub/claim_name") {
        CHECK_FALSE(store.record_login_observation("", "sub", "sub", "val"));
        CHECK_FALSE(store.record_login_observation("iss", "", "sub", "val"));
        CHECK_FALSE(store.record_login_observation("iss", "sub", "", "val"));
    }
}

// ── ADR-2001 PR4a — SAML identity linkage (migration v4) ────────────────
//
// saml_identity_links — the SAML analogue of v3's identity_links. A
// SEPARATE table from identity_links (never a generalization) — keeps this
// PR off PR3's scim_store schema surface. No scim_resources.external_id
// ambiguity guard is re-tested here (that guard, and its migration, are
// v3's — this table adds no new one; find_unique_active_by_external_id is
// already covered above).

TEST_CASE("ScimStore: saml_identity_links upsert + saml_links_for_scim_id",
         "[pg][scim][2001][linkage][saml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("upsert_saml_link is idempotent and saml_links_for_scim_id returns it") {
        REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata",
                                       "alice@example.com", "scim-alice"));
        REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata",
                                       "alice@example.com", "scim-alice")); // repeat

        auto links = store.saml_links_for_scim_id("scim-alice");
        REQUIRE(links.has_value());
        REQUIRE(links->size() == 1);
        CHECK((*links)[0].entity_id == "https://idp.example.com/saml/metadata");
        CHECK((*links)[0].name_id == "alice@example.com");
    }

    SECTION("multiple (entity_id,name_id) identities can link to the same scim_id") {
        REQUIRE(store.upsert_saml_link("https://idp-a.example.com/", "a@example.com",
                                       "scim-bob"));
        REQUIRE(store.upsert_saml_link("https://idp-b.example.com/", "b@example.com",
                                       "scim-bob"));

        auto links = store.saml_links_for_scim_id("scim-bob");
        REQUIRE(links.has_value());
        REQUIRE(links->size() == 2);
    }

    SECTION("saml_links_for_scim_id returns an engaged-but-empty vector for an unknown "
           "scim_id") {
        auto links = store.saml_links_for_scim_id("no-such-scim-id");
        REQUIRE(links.has_value());
        CHECK(links->empty());
    }

    SECTION("re-linking the same (entity_id,name_id) to a different scim_id moves the link "
           "(UNIQUE (entity_id,name_id) enforced)") {
        REQUIRE(store.upsert_saml_link("https://idp.example.com/", "move@example.com",
                                       "scim-old"));
        REQUIRE(store.upsert_saml_link("https://idp.example.com/", "move@example.com",
                                       "scim-new"));

        CHECK(store.saml_links_for_scim_id("scim-old")->empty());
        auto new_links = store.saml_links_for_scim_id("scim-new");
        REQUIRE(new_links.has_value());
        REQUIRE(new_links->size() == 1);
        CHECK((*new_links)[0].name_id == "move@example.com");
    }

    SECTION("upsert_saml_link rejects empty entity_id/name_id/scim_id") {
        CHECK_FALSE(store.upsert_saml_link("", "name", "scim-x"));
        CHECK_FALSE(store.upsert_saml_link("entity", "", "scim-x"));
        CHECK_FALSE(store.upsert_saml_link("entity", "name", ""));
    }
}

TEST_CASE("ScimStore: saml_identity_links and identity_links (OIDC) are independent tables",
         "[pg][scim][2001][linkage][saml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // Link the SAME scim_id from both sides — an OIDC link and a SAML link
    // coexisting on one SCIM resource must not interfere with each other's
    // read (a shared/generalized table would risk exactly this).
    REQUIRE(store.upsert_link("https://oidc-idp.example.com/", "sub-1", "scim-both"));
    REQUIRE(store.upsert_saml_link("https://saml-idp.example.com/", "name@example.com",
                                   "scim-both"));

    auto oidc_links = store.links_for_scim_id("scim-both");
    auto saml_links = store.saml_links_for_scim_id("scim-both");
    REQUIRE(oidc_links.has_value());
    REQUIRE(saml_links.has_value());
    REQUIRE(oidc_links->size() == 1);
    REQUIRE(saml_links->size() == 1);
    CHECK((*oidc_links)[0].sub == "sub-1");
    CHECK((*saml_links)[0].name_id == "name@example.com");
}

// ── ADR-2001 §4 — deny-at-login backstop accessor ───────────────────────

TEST_CASE("ScimStore: linked_resource_active — deny-at-login backstop tri-state + scim_id",
         "[pg][scim][2001][linkage][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("active linked resource -> engaged, scim_id set, active=true (PROCEED)") {
        auto r = store.create_resource("active-user", "ext-active");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-active", r->scim_id));

        auto result = store.linked_resource_active("https://idp.example.com/", "sub-active");
        REQUIRE(result.has_value()); // OUTER engaged — store answered
        REQUIRE(result->scim_id.has_value());
        CHECK(*result->scim_id == r->scim_id); // the audit-detail id, asserted
        REQUIRE(result->active.has_value());
        CHECK(*result->active == true);
    }

    SECTION("deactivated linked resource (set_active false) -> engaged, scim_id set, "
           "active=false (DENY)") {
        auto r = store.create_resource("inactive-user", "ext-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-inactive", r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto result = store.linked_resource_active("https://idp.example.com/", "sub-inactive");
        REQUIRE(result.has_value());
        REQUIRE(result->scim_id.has_value());
        CHECK(*result->scim_id == r->scim_id);
        REQUIRE(result->active.has_value());
        CHECK(*result->active == false);
    }

    // The LOAD-BEARING case: the scim_resources row was hard-DELETEd (a
    // completed SCIM DELETE) but identity_links is not FK-cascaded, so the
    // link row survives, orphaned. An INNER join would read this as "no
    // rows" (= no link = PROCEED) — the exact bypass ADR-2001 §4 exists to
    // close. `scim_id` still names the (now-gone) resource — that's the
    // audit-detail id a DENY on this path reports.
    SECTION("orphaned link (scim_resources row hard-deleted) -> engaged, scim_id set, "
           "active=nullopt (DENY)") {
        auto r = store.create_resource("deleted-user", "ext-deleted");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-deleted", r->scim_id));
        auto del = store.delete_by_scim_id(r->scim_id);
        REQUIRE(del.has_value());
        CHECK(*del == true);

        auto result = store.linked_resource_active("https://idp.example.com/", "sub-deleted");
        REQUIRE(result.has_value());          // store answered
        REQUIRE(result->scim_id.has_value()); // identity_links row still exists, names the id
        CHECK(*result->scim_id == r->scim_id);
        CHECK_FALSE(result->active.has_value()); // NULL sr.active (join miss) -> deny
    }

    SECTION("no identity_links row at all -> engaged, scim_id=nullopt (PROCEED — unlinked, "
           "not deprovisioned)") {
        auto result = store.linked_resource_active("https://idp.example.com/", "sub-never-linked");
        REQUIRE(result.has_value());           // store answered
        CHECK_FALSE(result->scim_id.has_value()); // zero rows — genuinely no link
        CHECK_FALSE(result->active.has_value());
    }

    SECTION("empty iss/sub -> engaged, scim_id=nullopt (a definitive non-match, not a store "
           "error)") {
        auto result_empty_iss = store.linked_resource_active("", "sub-x");
        REQUIRE(result_empty_iss.has_value());
        CHECK_FALSE(result_empty_iss->scim_id.has_value());

        auto result_empty_sub = store.linked_resource_active("https://idp.example.com/", "");
        REQUIRE(result_empty_sub.has_value());
        CHECK_FALSE(result_empty_sub->scim_id.has_value());
    }
}

// Mutation-check (ADR-2001 §4 task spec): pins the LEFT JOIN's load-bearing
// behaviour directly against the raw SQL. Runs the SAME orphaned-link
// scenario the section above already denies via the store's real (LEFT
// JOIN) accessor, then proves an INNER JOIN over the identical data returns
// ZERO rows — the exact "no rows = read as no link = PROCEED" bypass that
// would ship if `linked_resource_active`'s JOIN type ever regressed.
TEST_CASE("ScimStore: linked_resource_active — LEFT JOIN is load-bearing (mutation-checked)",
         "[pg][scim][2001][linkage][deny-at-login][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("mutcheck-user", "ext-mutcheck");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-mutcheck", r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // Sanity: the store's own (correct, LEFT JOIN) accessor denies, and
    // still names the (now-gone) resource.
    auto result = store.linked_resource_active("https://idp.example.com/", "sub-mutcheck");
    REQUIRE(result.has_value());
    REQUIRE(result->scim_id.has_value());
    CHECK(*result->scim_id == r->scim_id);
    CHECK_FALSE(result->active.has_value());

    // The counterfactual: an INNER JOIN over the SAME orphaned-link data
    // returns zero rows, which `linked_resource_active`'s "0 rows -> engaged,
    // scim_id=nullopt -> PROCEED" branch would then read as "genuinely
    // unlinked" — letting a fully-deprovisioned identity log back in. This
    // is what an `INNER JOIN` regression in the production query would
    // produce.
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto inner = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT il.scim_id, sr.active FROM scim_store.identity_links il "
        "INNER JOIN scim_store.scim_resources sr ON sr.scim_id = il.scim_id "
        "WHERE il.iss = $1 AND il.sub = $2 LIMIT 1",
        std::vector<std::string>{"https://idp.example.com/", "sub-mutcheck"});
    REQUIRE(inner.ok());
    CHECK(PQntuples(inner.get()) == 0);
}

// ── ADR-2001 PR4b — SAML deny-at-login backstop accessor ────────────────
//
// Mirrors the `linked_resource_active` (OIDC) test block above exactly —
// `saml_linked_resource_active` is its SAML analogue over
// `saml_identity_links` instead of `identity_links`, sharing the same
// `LinkedResourceState` tri-state contract.

TEST_CASE("ScimStore: saml_linked_resource_active — deny-at-login backstop tri-state + scim_id",
         "[pg][scim][2001][linkage][saml][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("active linked resource -> engaged, scim_id set, active=true (PROCEED)") {
        auto r = store.create_resource("saml-active-user", "ext-saml-active");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_saml_link("https://saml-idp.example.com/", "name-active",
                                       r->scim_id));

        auto result =
            store.saml_linked_resource_active("https://saml-idp.example.com/", "name-active");
        REQUIRE(result.has_value()); // OUTER engaged — store answered
        REQUIRE(result->scim_id.has_value());
        CHECK(*result->scim_id == r->scim_id); // the audit-detail id, asserted
        REQUIRE(result->active.has_value());
        CHECK(*result->active == true);
    }

    SECTION("deactivated linked resource (set_active false) -> engaged, scim_id set, "
           "active=false (DENY)") {
        auto r = store.create_resource("saml-inactive-user", "ext-saml-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_saml_link("https://saml-idp.example.com/", "name-inactive",
                                       r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto result =
            store.saml_linked_resource_active("https://saml-idp.example.com/", "name-inactive");
        REQUIRE(result.has_value());
        REQUIRE(result->scim_id.has_value());
        CHECK(*result->scim_id == r->scim_id);
        REQUIRE(result->active.has_value());
        CHECK(*result->active == false);
    }

    // The LOAD-BEARING case: the scim_resources row was hard-DELETEd (a
    // completed SCIM DELETE) but saml_identity_links is not FK-cascaded, so
    // the link row survives, orphaned. An INNER join would read this as "no
    // rows" (= no link = PROCEED) — the exact bypass ADR-2001 §4 exists to
    // close. `scim_id` still names the (now-gone) resource — that's the
    // audit-detail id a DENY on this path reports.
    SECTION("orphaned link (scim_resources row hard-deleted) -> engaged, scim_id set, "
           "active=nullopt (DENY)") {
        auto r = store.create_resource("saml-deleted-user", "ext-saml-deleted");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_saml_link("https://saml-idp.example.com/", "name-deleted",
                                       r->scim_id));
        auto del = store.delete_by_scim_id(r->scim_id);
        REQUIRE(del.has_value());
        CHECK(*del == true);

        auto result =
            store.saml_linked_resource_active("https://saml-idp.example.com/", "name-deleted");
        REQUIRE(result.has_value());          // store answered
        REQUIRE(result->scim_id.has_value()); // saml_identity_links row still exists, names the id
        CHECK(*result->scim_id == r->scim_id);
        CHECK_FALSE(result->active.has_value()); // NULL sr.active (join miss) -> deny
    }

    SECTION("no saml_identity_links row at all -> engaged, scim_id=nullopt (PROCEED — unlinked, "
           "not deprovisioned)") {
        auto result = store.saml_linked_resource_active("https://saml-idp.example.com/",
                                                         "name-never-linked");
        REQUIRE(result.has_value());           // store answered
        CHECK_FALSE(result->scim_id.has_value()); // zero rows — genuinely no link
        CHECK_FALSE(result->active.has_value());
    }

    SECTION("empty entity_id/name_id -> engaged, scim_id=nullopt (a definitive non-match, not a "
           "store error)") {
        auto result_empty_entity = store.saml_linked_resource_active("", "name-x");
        REQUIRE(result_empty_entity.has_value());
        CHECK_FALSE(result_empty_entity->scim_id.has_value());

        auto result_empty_name =
            store.saml_linked_resource_active("https://saml-idp.example.com/", "");
        REQUIRE(result_empty_name.has_value());
        CHECK_FALSE(result_empty_name->scim_id.has_value());
    }
}

// Mutation-check (ADR-2001 §4 task spec, PR4b): pins the LEFT JOIN's
// load-bearing behaviour directly against the raw SQL, mirroring the OIDC
// mutation-check test above. Runs the SAME orphaned-link scenario the
// section above already denies via the store's real (LEFT JOIN) accessor,
// then proves an INNER JOIN over the identical data returns ZERO rows — the
// exact "no rows = read as no link = PROCEED" bypass that would ship if
// `saml_linked_resource_active`'s JOIN type ever regressed.
TEST_CASE("ScimStore: saml_linked_resource_active — LEFT JOIN is load-bearing (mutation-checked)",
         "[pg][scim][2001][linkage][saml][deny-at-login][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("saml-mutcheck-user", "ext-saml-mutcheck");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://saml-idp.example.com/", "name-mutcheck", r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // Sanity: the store's own (correct, LEFT JOIN) accessor denies, and
    // still names the (now-gone) resource.
    auto result =
        store.saml_linked_resource_active("https://saml-idp.example.com/", "name-mutcheck");
    REQUIRE(result.has_value());
    REQUIRE(result->scim_id.has_value());
    CHECK(*result->scim_id == r->scim_id);
    CHECK_FALSE(result->active.has_value());

    // The counterfactual: an INNER JOIN over the SAME orphaned-link data
    // returns zero rows, which `saml_linked_resource_active`'s "0 rows ->
    // engaged, scim_id=nullopt -> PROCEED" branch would then read as
    // "genuinely unlinked" — letting a fully-deprovisioned identity log
    // back in. This is what an `INNER JOIN` regression in the production
    // query would produce.
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto inner = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT sl.scim_id, sr.active FROM scim_store.saml_identity_links sl "
        "INNER JOIN scim_store.scim_resources sr ON sr.scim_id = sl.scim_id "
        "WHERE sl.entity_id = $1 AND sl.name_id = $2 LIMIT 1",
        std::vector<std::string>{"https://saml-idp.example.com/", "name-mutcheck"});
    REQUIRE(inner.ok());
    CHECK(PQntuples(inner.get()) == 0);
}

// ── ADR-2001 #3072 — SAML login observations (migration v5, D2-style) ───
//
// saml_login_observations — the SAML analogue of oidc_login_observations
// (tested above). Unlike the OIDC surface, saml_observation_matches is
// TRI-STATE (nullopt/true/false) rather than a plain bool — see the .hpp
// doc comment for why. Mirrors the oidc test structure, plus the
// distinct-row-per-name_id_format assertion the SAML uniqueness key adds.

TEST_CASE("ScimStore: saml_login_observations upsert-on-relogin + distinct rows per "
         "name_id_format",
         "[pg][scim][2001][linkage][saml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    const std::string entity = "https://saml-idp.example.com/metadata";
    const std::string name_id = "alice@example.com";

    SECTION("record_saml_login_observation rejects empty entity_id/name_id, but NOT an empty "
            "name_id_format (Gate 7 fix: a missing NameID Format attribute is a common, "
            "legitimate IdP configuration and must still be recorded — see the .hpp doc "
            "comment)") {
        CHECK_FALSE(store.record_saml_login_observation("", name_id, "persistent"));
        CHECK_FALSE(store.record_saml_login_observation(entity, "", "persistent"));
        // MUTATION-CHECK (task spec): restoring `name_id_format.empty()` to
        // the guard makes this assertion fail (the write is rejected
        // instead of recorded as "").
        CHECK(store.record_saml_login_observation(entity, name_id, ""));
    }

    SECTION("re-login upserts (refreshes seen_at) the SAME (entity_id,name_id,format) row") {
        REQUIRE(store.record_saml_login_observation(entity, name_id, "persistent"));

        // Force seen_at into the past via raw SQL so the second upsert's
        // "refreshed to now" effect is observable rather than possibly
        // landing in the same wall-clock second.
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult backdate{PQexec(
            conn.get(),
            "UPDATE scim_store.saml_login_observations SET seen_at = 12345 "
            "WHERE entity_id = 'https://saml-idp.example.com/metadata' "
            "AND name_id = 'alice@example.com' AND name_id_format = 'persistent'")};
        REQUIRE(backdate.ok());

        REQUIRE(store.record_saml_login_observation(entity, name_id, "persistent"));

        PgResult after{PQexec(
            conn.get(),
            "SELECT seen_at FROM scim_store.saml_login_observations "
            "WHERE entity_id = 'https://saml-idp.example.com/metadata' "
            "AND name_id = 'alice@example.com' AND name_id_format = 'persistent'")};
        REQUIRE(after.ok());
        REQUIRE(PQntuples(after.get()) == 1); // still exactly one row — upsert, not accumulate
        CHECK(std::string(PQgetvalue(after.get(), 0, 0)) != "12345"); // seen_at refreshed to now
    }

    SECTION("a different name_id_format for the same (entity_id,name_id) is a DISTINCT row — "
           "both coexist") {
        REQUIRE(store.record_saml_login_observation(entity, name_id, "persistent"));
        REQUIRE(store.record_saml_login_observation(entity, name_id, "transient"));

        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult rows{PQexec(
            conn.get(),
            "SELECT name_id_format FROM scim_store.saml_login_observations "
            "WHERE entity_id = 'https://saml-idp.example.com/metadata' "
            "AND name_id = 'alice@example.com' ORDER BY name_id_format ASC")};
        REQUIRE(rows.ok());
        REQUIRE(PQntuples(rows.get()) == 2); // TWO distinct rows, neither erased the other
        CHECK(std::string(PQgetvalue(rows.get(), 0, 0)) == "persistent");
        CHECK(std::string(PQgetvalue(rows.get(), 1, 0)) == "transient");

        // Both remain independently discoverable by name_id — the value the
        // D2 detector actually keys its read on.
        auto match = store.saml_observation_matches(name_id);
        REQUIRE(match.has_value());
        CHECK(*match);
    }
}

TEST_CASE("ScimStore: saml_observation_matches — tri-state (engaged-true / engaged-false / "
         "store-error)",
         "[pg][scim][2001][linkage][saml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("engaged false before any observation is recorded") {
        auto result = store.saml_observation_matches("never-seen@example.com");
        REQUIRE(result.has_value()); // store answered
        CHECK_FALSE(*result);
    }

    SECTION("engaged true once a matching observation exists, engaged false for a different "
           "name_id") {
        REQUIRE(store.record_saml_login_observation("https://saml-idp.example.com/",
                                                    "bob@example.com", "persistent"));

        auto hit = store.saml_observation_matches("bob@example.com");
        REQUIRE(hit.has_value());
        CHECK(*hit);

        auto miss = store.saml_observation_matches("carol@example.com");
        REQUIRE(miss.has_value());
        CHECK_FALSE(*miss);
    }

    SECTION("empty name_id is engaged false — a definitive non-match, not a store error") {
        auto result = store.saml_observation_matches("");
        REQUIRE(result.has_value());
        CHECK_FALSE(*result);
    }

    SECTION("a store that cannot answer (closed/unreachable pool) returns nullopt, never "
           "false — the caller must SKIP, not report a false negative") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        CHECK_FALSE(broken_store.saml_observation_matches("anything@example.com").has_value());
    }
}

// ── ADR-2001 #3072 — find_unique_active_by_external_id_checked ──────────
//
// The checked tri/quad-state variant of the mis-link guard already covered
// (collapsed) above (line ~602). Same underlying query — this exercises the
// STATUS discrimination the checked variant adds, plus confirms the
// existing `find_unique_active_by_external_id` wrapper still collapses
// every non-`matched` status to `nullopt` (byte-unchanged caller contract).

TEST_CASE("ScimStore: find_unique_active_by_external_id_checked — matched / no_match / "
         "ambiguous / store_error, and the compatibility wrapper",
         "[pg][scim][2001][linkage]") {
    using yuzu::server::ActiveExternalIdLookupStatus;

    YUZU_REQUIRE_PG_DB_TPL(db, scim_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    SECTION("matched: exactly one active row — resource populated, wrapper returns it") {
        auto r = store.create_resource("checked-alice", "checked-ext-1");
        REQUIRE(r.has_value());

        auto checked = store.find_unique_active_by_external_id_checked("checked-ext-1");
        CHECK(checked.status == ActiveExternalIdLookupStatus::matched);
        REQUIRE(checked.resource.has_value());
        CHECK(checked.resource->scim_id == r->scim_id);

        auto wrapped = store.find_unique_active_by_external_id("checked-ext-1");
        REQUIRE(wrapped.has_value());
        CHECK(wrapped->scim_id == r->scim_id);
    }

    SECTION("no_match: zero rows — resource absent, wrapper returns nullopt") {
        auto checked = store.find_unique_active_by_external_id_checked("checked-no-such-ext-id");
        CHECK(checked.status == ActiveExternalIdLookupStatus::no_match);
        CHECK_FALSE(checked.resource.has_value());
        CHECK_FALSE(store.find_unique_active_by_external_id("checked-no-such-ext-id").has_value());
    }

    SECTION("no_match: empty external_id — matches find_unique_active_by_external_id's "
           "existing empty-input contract, not a store error") {
        auto checked = store.find_unique_active_by_external_id_checked("");
        CHECK(checked.status == ActiveExternalIdLookupStatus::no_match);
        CHECK_FALSE(checked.resource.has_value());
    }

    SECTION("ambiguous: two ACTIVE rows sharing the external_id — resource absent, wrapper "
           "returns nullopt") {
        // Same technique as the existing ambiguous-guard test above: the
        // partial-unique index makes this unreachable through the store's
        // own write path, so seed the duplicate directly via SQL after
        // dropping it — modelling a pre-existing duplicate slipping in.
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult drop{
            PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
        REQUIRE(drop.ok());

        auto r1 = store.create_resource("checked-dup-1", "checked-dup-ext");
        auto r2 = store.create_resource("checked-dup-2", "checked-dup-ext");
        REQUIRE(r1.has_value());
        REQUIRE(r2.has_value());
        REQUIRE(r1->scim_id != r2->scim_id);

        auto checked = store.find_unique_active_by_external_id_checked("checked-dup-ext");
        CHECK(checked.status == ActiveExternalIdLookupStatus::ambiguous);
        CHECK_FALSE(checked.resource.has_value());
        CHECK_FALSE(store.find_unique_active_by_external_id("checked-dup-ext").has_value());
    }

    SECTION("store_error: a store that cannot answer — resource absent, wrapper returns "
           "nullopt (same collapsed outcome as no_match/ambiguous — byte-unchanged wrapper "
           "contract)") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        auto checked = broken_store.find_unique_active_by_external_id_checked("anything");
        CHECK(checked.status == ActiveExternalIdLookupStatus::store_error);
        CHECK_FALSE(checked.resource.has_value());
        CHECK_FALSE(broken_store.find_unique_active_by_external_id("anything").has_value());
    }
}

// ── Dup-detecting fail-closed migration (v3) ────────────────────────────
//
// Mirrors the api_token_store #3013 fail-closed test pattern: pre-seed a
// database already at v2 (scim_resources exists, no identity_links/
// oidc_login_observations/unique-index yet) with two ACTIVE resources
// sharing a non-empty external_id, then construct ScimStore. Its v3
// migration's partial-unique index creation must hit Postgres's own
// unique_violation, which fails the whole v3 migration transaction (the two
// new tables roll back with it) — construction must report !is_open(),
// never silently skip the index and open anyway.
TEST_CASE("ScimStore reports !is_open when v3 migration finds pre-existing duplicate "
         "external_ids (dup-detecting fail-closed migration)",
         "[pg][scim][2001][migration][failclosed]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA scim_store")};
        REQUIRE(schema.ok());

        // v1 scim_resources DDL, copied verbatim from migrations() in
        // scim_store.cpp (v1 entry) — deliberately missing v3's identity
        // tables + unique index, modelling a real pre-upgrade deployment at
        // v2 (v2's scim_groups/scim_group_members are irrelevant here and
        // omitted — the drift guard only checks table_schema has SOME
        // tables, which scim_resources alone satisfies).
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE scim_store.scim_resources ("
                           "  id            BIGSERIAL,"
                           "  scim_id       TEXT PRIMARY KEY,"
                           "  external_id   TEXT,"
                           "  username      TEXT NOT NULL UNIQUE,"
                           "  active        BOOLEAN NOT NULL DEFAULT TRUE,"
                           "  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
                           "  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),"
                           "  etag_version  BIGINT NOT NULL DEFAULT 1)")};
        REQUIRE(v1.ok());
        PgResult idx{
            PQexec(conn.get(),
                  "CREATE INDEX scim_resources_external_id_idx ON "
                  "scim_store.scim_resources (external_id)")};
        REQUIRE(idx.ok());

        // schema_meta claims v2 already applied — v3 is the next pending
        // migration the runner will attempt.
        PgResult ver{PQexec(conn.get(),
                            "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                            "VALUES ('scim_store', 2, extract(epoch FROM now())::bigint)")};
        REQUIRE(ver.ok());

        // Two ACTIVE resources sharing a non-empty external_id — the
        // pre-existing duplicate the v3 migration's unique index must
        // refuse to build over.
        PgResult seed{PQexec(conn.get(),
                             "INSERT INTO scim_store.scim_resources "
                             "(scim_id, external_id, username, active) VALUES "
                             "('scim-dup-1', 'dup-external-id', 'dup-user-1', TRUE), "
                             "('scim-dup-2', 'dup-external-id', 'dup-user-2', TRUE)")};
        REQUIRE(seed.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    CHECK_FALSE(store.is_open());

    // Belt-and-braces: the failed migration must not have left either new
    // table behind (whole-transaction rollback, not a partial apply).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult check{PQexec(conn.get(), "SELECT 1 FROM scim_store.identity_links LIMIT 1")};
        CHECK_FALSE(check.ok()); // table must not exist
    }
}
