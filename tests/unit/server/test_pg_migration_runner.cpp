// PgMigrationRunner tests (#1320 PR 1): versioning, schema namespacing,
// re-run idempotency, partial failure, store-name validation.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_migration_runner.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <cstdlib>
#include <string>
#include <vector>

using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgMigration;
using yuzu::server::pg::PgMigrationRunner;
using yuzu::server::pg::PgResult;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

int scalar(PGconn* conn, const std::string& sql) {
    PgResult res{PQexec(conn, sql.c_str())};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) >= 1);
    REQUIRE(PQnfields(res.get()) >= 1);
    return std::atoi(PQgetvalue(res.get(), 0, 0));
}

bool table_exists(PGconn* conn, const std::string& schema, const std::string& table) {
    const std::string sql = "SELECT count(*) FROM information_schema.tables "
                            "WHERE table_schema = '" +
                            schema + "' AND table_name = '" + table + "'";
    return scalar(conn, sql) == 1;
}

} // namespace

TEST_CASE("PgMigrationRunner versioning", "[pg][migration][pg-smoke]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    const std::vector<PgMigration> v1 = {
        {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
    };
    const std::vector<PgMigration> v3 = {
        {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
        {2, "ALTER TABLE items ADD COLUMN name TEXT"},
        {3, "CREATE INDEX items_name_idx ON items (name)"},
    };

    SECTION("fresh database starts untracked") {
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 0);
    }

    SECTION("applies pending migrations in order and records the version") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
        CHECK(table_exists(conn.get(), "store_a", "items"));
    }

    SECTION("incremental upgrade applies only the new steps") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v1));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 1);
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
    }

    SECTION("re-run is idempotent") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3)); // no-op
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
    }

    SECTION("empty migration list is trivially fine") {
        CHECK(PgMigrationRunner::run(conn.get(), "store_a", {}));
    }
}

TEST_CASE("PgMigrationRunner schema namespacing", "[pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    // Two stores create the SAME unqualified table name; each must land in
    // its own schema (ADR-0008 schema-per-store).
    const std::vector<PgMigration> mk_items = {
        {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
    };
    REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", mk_items));
    REQUIRE(PgMigrationRunner::run(conn.get(), "store_b", mk_items));

    CHECK(table_exists(conn.get(), "store_a", "items"));
    CHECK(table_exists(conn.get(), "store_b", "items"));

    // Versions tracked independently in the shared meta table.
    CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 1);
    CHECK(PgMigrationRunner::current_version(conn.get(), "store_b") == 1);

    // search_path was SET LOCAL — nothing leaked onto the connection.
    {
        PgResult res{PQexec(conn.get(), "SHOW search_path")};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        const std::string path = PQgetvalue(res.get(), 0, 0);
        CHECK(path.find("store_a") == std::string::npos);
        CHECK(path.find("store_b") == std::string::npos);
    }
}

TEST_CASE("PgMigrationRunner failure handling", "[pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    SECTION("failing step stops the run; earlier steps stay applied") {
        const std::vector<PgMigration> broken = {
            {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {2, "THIS IS NOT SQL"},
            {3, "ALTER TABLE items ADD COLUMN never_reached TEXT"},
        };
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_a", broken));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 1);
        CHECK(table_exists(conn.get(), "store_a", "items"));
        // Connection must be usable (no wedged transaction).
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);

        // A fixed ladder picks up from where it stopped.
        const std::vector<PgMigration> fixed = {
            {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {2, "ALTER TABLE items ADD COLUMN name TEXT"},
        };
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", fixed));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 2);
    }

    SECTION("invalid store names are rejected") {
        const std::vector<PgMigration> noop = {{1, "SELECT 1"}};
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "Bad-Name", noop));
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store\"; DROP SCHEMA public", noop));
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "", noop));
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "0starts_with_digit", noop));
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), std::string(64, 'a'), noop)); // > 63 bytes
    }

    SECTION("valid_store_name accepts the conventional names") {
        CHECK(PgMigrationRunner::valid_store_name("response"));
        CHECK(PgMigrationRunner::valid_store_name("endpoint_state"));
        CHECK(PgMigrationRunner::valid_store_name("_private"));
        CHECK(PgMigrationRunner::valid_store_name("vuln_graph2"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("Response"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("with space"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("semi;colon"));
    }

    SECTION("reserved namespaces are rejected") {
        CHECK_FALSE(PgMigrationRunner::valid_store_name("public"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("information_schema"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("pg_catalog"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("pg_toast"));
        CHECK_FALSE(PgMigrationRunner::valid_store_name("pg_anything"));
        const std::vector<PgMigration> noop = {{1, "SELECT 1"}};
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "public", noop));
    }

    SECTION("null connection is an error, even with an empty migration list") {
        CHECK(PgMigrationRunner::current_version(nullptr, "store_a") == -1);
        // PR 3 feeds run() from Lease::get(), which is nullptr on an empty
        // lease — success here would boot a store against nothing.
        CHECK_FALSE(PgMigrationRunner::run(nullptr, "store_a", {}));
    }
}

// #3013 (found in review, #2961/#2964): before this guard, a duplicate or
// out-of-order version in a store's own migrations() vector was silently
// swallowed by the apply loop's `m.version <= current` skip — `run()` still
// returned true, and the store opened against a schema missing whatever the
// swallowed migration was meant to add. Disabling this guard left the
// entire server suite green (4879 cases, 94587 assertions) before these
// cases existed.
TEST_CASE("PgMigrationRunner #3013 duplicate/non-monotonic version guard", "[pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    SECTION("a duplicate version anywhere in the vector refuses the whole run") {
        const std::vector<PgMigration> dup = {
            {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {2, "ALTER TABLE items ADD COLUMN name TEXT"},
            {2, "ALTER TABLE items ADD COLUMN other TEXT"}, // duplicate of the step above
        };
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_a", dup));
        // Nothing applied — not even migration 1, which is individually
        // valid: the guard runs BEFORE ensure_meta_and_schema/the apply
        // loop, so a duplicate anywhere in the vector fails the whole call
        // closed rather than applying a valid prefix.
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 0);
        CHECK_FALSE(table_exists(conn.get(), "store_a", "items"));
    }

    SECTION("a descending pair refuses the whole run") {
        const std::vector<PgMigration> descending = {
            {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {3, "ALTER TABLE items ADD COLUMN name TEXT"},
            {2, "ALTER TABLE items ADD COLUMN out_of_order TEXT"}, // < the prior entry
        };
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_a", descending));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 0);
        CHECK_FALSE(table_exists(conn.get(), "store_a", "items"));
    }

    SECTION("a strictly-increasing positive vector is unaffected (positive control)") {
        const std::vector<PgMigration> ok = {
            {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {2, "ALTER TABLE items ADD COLUMN name TEXT"},
            {3, "CREATE INDEX items_name_idx ON items (name)"},
        };
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", ok));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
        CHECK(table_exists(conn.get(), "store_a", "items"));
    }

    SECTION("a non-positive first version refuses the whole run") {
        // read_version returns 0 for an untracked store, so a vector
        // beginning at version 0 passes the pairwise ordering check (it IS
        // strictly increasing against version 1) but is indistinguishable
        // from "already applied" to the apply loop's `m.version <= current`
        // skip, and version 0 would be skipped forever — #3013's shape at
        // index 0 rather than a duplicate/descending pair.
        const std::vector<PgMigration> zero_start = {
            {0, "CREATE TABLE items (id INT PRIMARY KEY)"},
            {1, "ALTER TABLE items ADD COLUMN name TEXT"},
        };
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_a", zero_start));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 0);
        CHECK_FALSE(table_exists(conn.get(), "store_a", "items"));
    }
}
