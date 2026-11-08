// PgMigrationRunner tests (#1320 PR 1): versioning, schema namespacing,
// re-run idempotency, partial failure, store-name validation.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_migration_runner.hpp"
#include "pg/pg_raii.hpp"
#include "sha256_hex.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <libpq-fe.h>

#include <cstdlib>
#include <latch>
#include <string>
#include <thread>
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

std::string text_scalar(PGconn* conn, const std::string& sql) {
    PgResult res{PQexec(conn, sql.c_str())};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    return PQgetvalue(res.get(), 0, 0);
}

void exec_ok_or_fail(PGconn* conn, const std::string& sql) {
    PgResult res{PQexec(conn, sql.c_str())};
    REQUIRE(res.ok());
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

// #3894: an older binary booting against a database a newer replica already
// migrated. Before this, run() applied nothing and said nothing — the older
// binary failed later (or misbehaved) with no pointer to the cause. The
// decision is WARN-ONLY (never a refusal): the upgrade guide promises an older
// build can run against an additively-upgraded database.
TEST_CASE("PgMigrationRunner is_schema_ahead decision (#3894)", "[pg][migration]") {
    const std::vector<PgMigration> v2 = {{1, "SELECT 1"}, {2, "SELECT 1"}};

    CHECK(PgMigrationRunner::is_schema_ahead(3, v2));       // database ahead
    CHECK_FALSE(PgMigrationRunner::is_schema_ahead(2, v2)); // equal
    CHECK_FALSE(PgMigrationRunner::is_schema_ahead(1, v2)); // behind (normal upgrade)
    CHECK_FALSE(PgMigrationRunner::is_schema_ahead(0, v2)); // untracked store
    CHECK_FALSE(PgMigrationRunner::is_schema_ahead(5, {})); // nothing declared
}

TEST_CASE("PgMigrationRunner version-ahead warning (#3894)", "[pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    const std::vector<PgMigration> v3 = {
        {1, "CREATE TABLE items (id INT PRIMARY KEY)"},
        {2, "ALTER TABLE items ADD COLUMN name TEXT"},
        {3, "CREATE INDEX items_name_idx ON items (name)"},
    };
    const std::vector<PgMigration> v2 = {v3[0], v3[1]}; // the "older binary"

    SECTION("an older vector against a newer database warns, applies nothing, still succeeds") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3)); // the newer replica

        std::string logs;
        bool ok = false;
        {
            yuzu::test::LogCapture capture{spdlog::level::warn};
            ok = PgMigrationRunner::run(conn.get(), "store_a", v2);
            capture.stop();
            logs = capture.text();
        }
        CHECK(ok);
        // Nothing downgraded or re-run.
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
        // The warning is actionable: names the store and both versions.
        CHECK(logs.find("store 'store_a'") != std::string::npos);
        CHECK(logs.find("schema v3") != std::string::npos);
        CHECK(logs.find("up to v2") != std::string::npos);
        CHECK(logs.find("newer build has already migrated") != std::string::npos);
    }

    SECTION("an up-to-date store does not warn (negative control)") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));

        std::string logs;
        {
            // debug level so the runner's own "(up to date)" line is captured:
            // an in-section liveness control proving the absence assertion
            // below is not vacuous (capture really reaches the runner).
            yuzu::test::LogCapture capture{spdlog::level::debug};
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));
            capture.stop();
            logs = capture.text();
        }
        CHECK(logs.find("up to date") != std::string::npos); // liveness control
        CHECK(logs.find("newer build has already migrated") == std::string::npos);
    }

    SECTION("a normal upgrade (database behind the vector) does not warn") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v2));

        std::string logs;
        {
            // info level so the runner's "migrated to v3" line is captured —
            // the in-section liveness control (see the section above).
            yuzu::test::LogCapture capture{spdlog::level::info};
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));
            capture.stop();
            logs = capture.text();
        }
        CHECK(logs.find("migrated to v3") != std::string::npos); // liveness control
        CHECK(logs.find("newer build has already migrated") == std::string::npos);
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_a") == 3);
    }

    SECTION("the warning fires on every call (some stores call run() more than once)") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v3));

        std::string logs;
        {
            yuzu::test::LogCapture capture{spdlog::level::warn};
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v2));
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_a", v2));
            capture.stop();
            logs = capture.text();
        }
        const std::string needle = "newer build has already migrated";
        std::size_t count = 0;
        for (auto pos = logs.find(needle); pos != std::string::npos;
             pos = logs.find(needle, pos + needle.size()))
            ++count;
        CHECK(count == 2); // pins the documented per-call (not per-process) contract
    }
}

// ---------------------------------------------------------------------------
// #7158: recorded migration hashes — drift refuses, first sight is recorded
// ---------------------------------------------------------------------------

TEST_CASE("PgMigrationRunner check_recorded_hashes decision (#7158)", "[pg][migration]") {
    using VH = PgMigrationRunner::VersionHash;
    const std::vector<VH> expected = {{1, "a"}, {2, "b"}, {3, "c"}};

    SECTION("everything recorded and equal") {
        const auto v = PgMigrationRunner::check_recorded_hashes(3, expected, expected);
        CHECK(v.missing.empty());
        CHECK(v.drifted.empty());
    }
    SECTION("an applied version with no row is missing, not drifted") {
        const auto v = PgMigrationRunner::check_recorded_hashes(3, expected, {{1, "a"}});
        CHECK(v.missing == std::vector<int>{2, 3});
        CHECK(v.drifted.empty());
    }
    SECTION("a differing hash is drift, at any applied version") {
        const auto v1 = PgMigrationRunner::check_recorded_hashes(3, expected, {{1, "X"}, {2, "b"}, {3, "c"}});
        CHECK(v1.drifted == std::vector<int>{1});
        const auto v2 = PgMigrationRunner::check_recorded_hashes(3, expected, {{1, "a"}, {2, "X"}, {3, "c"}});
        CHECK(v2.drifted == std::vector<int>{2});
    }
    SECTION("versions above the recorded schema version are not judged (rewound schema_meta)") {
        const auto v = PgMigrationRunner::check_recorded_hashes(1, expected, {{1, "a"}, {2, "OLD"}});
        CHECK(v.missing.empty());
        CHECK(v.drifted.empty());
    }
    SECTION("a recorded row above this binary's vector is ignored (#3894 ahead)") {
        const auto v = PgMigrationRunner::check_recorded_hashes(
            5, expected, {{1, "a"}, {2, "b"}, {3, "c"}, {4, "from a newer build"}});
        CHECK(v.missing.empty());
        CHECK(v.drifted.empty());
    }
    SECTION("nothing applied, nothing to judge") {
        const auto v = PgMigrationRunner::check_recorded_hashes(0, expected, {});
        CHECK(v.missing.empty());
        CHECK(v.drifted.empty());
    }
}

TEST_CASE("PgMigrationRunner hashes the exact migration bytes (#7158)", "[pg][migration]") {
    // Pins the helper and the "exact bytes, no normalisation" decision: this text
    // has newlines and a trailing newline, and a runner that trimmed or folded
    // whitespace would hash something else.
    const auto h = yuzu::server::sha256_hex("CREATE TABLE t (\n  id INT\n);\n");
    REQUIRE(h.has_value());
    CHECK(*h == "4eab02f428e85198d82945a894e72cee24ecdc1d711ec09795a787c79fa65f03");
    const auto trimmed = yuzu::server::sha256_hex("CREATE TABLE t (\n  id INT\n);");
    REQUIRE(trimmed.has_value());
    CHECK(*trimmed != *h);
}

TEST_CASE("PgMigrationRunner records and checks migration hashes (#7158)",
          "[pg][migration][drift]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());

    // Newlines and a trailing newline on purpose: the recorded hash is compared to
    // hash_of(t1) below, so a runner that trimmed or folded whitespace fails here.
    const std::string t1 = "CREATE TABLE items (\n  id INT PRIMARY KEY\n);\n";
    const std::string t2 = "ALTER TABLE items ADD COLUMN IF NOT EXISTS name TEXT";
    const std::string t3 = "ALTER TABLE items ADD COLUMN IF NOT EXISTS note TEXT";
    const std::vector<PgMigration> v3 = {{1, t1}, {2, t2}, {3, t3}};
    const auto hash_of = [](const std::string& sql) { return *yuzu::server::sha256_hex(sql); };
    const auto recorded = [&](int version, const char* col) {
        return text_scalar(conn.get(), std::string("SELECT ") + col +
                                           " FROM public.yuzu_schema_migrations WHERE store = 'store_h' "
                                           "AND version = " + std::to_string(version));
    };
    const auto row_count = [&] {
        return scalar(conn.get(),
                      "SELECT count(*) FROM public.yuzu_schema_migrations WHERE store = 'store_h'");
    };

    SECTION("apply records one verified row per version") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        CHECK(row_count() == 3);
        CHECK(recorded(1, "sha256") == hash_of(t1));
        CHECK(recorded(3, "sha256") == hash_of(t3));
        CHECK(recorded(2, "recorded_by") == "apply");
    }

    SECTION("a changed text for an applied version refuses and changes nothing") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        const std::vector<PgMigration> edited = {
            {1, t1}, {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS name_edited TEXT"}, {3, t3}};
        std::string logs;
        bool ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            ok = PgMigrationRunner::run(conn.get(), "store_h", edited);
            capture.stop();
            logs = capture.text();
        }
        CHECK_FALSE(ok);
        CHECK(logs.find("store 'store_h' recorded migration v2") != std::string::npos);
        CHECK(logs.find(hash_of(t2).substr(0, 12)) != std::string::npos);
        CHECK(logs.find(hash_of(edited[1].sql).substr(0, 12)) != std::string::npos);
        CHECK(logs.find("DROP") == std::string::npos); // names no destructive step
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 3);
        CHECK(recorded(2, "sha256") == hash_of(t2));
        // The unedited text still opens: the refusal is about content, not state.
        CHECK(PgMigrationRunner::run(conn.get(), "store_h", v3));
    }

    SECTION("drift at the first version refuses too") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        const std::vector<PgMigration> edited = {
            {1, t1 + "-- edited"}, {2, t2}, {3, t3}};
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_h", edited));
    }

    SECTION("a rewound schema_meta re-applies and the hash row is overwritten") {
        // This is the documented dev/UAT reset: the text that just ran is the authority.
        const std::vector<PgMigration> two = {{1, t1}, {2, t2}};
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", two));
        exec_ok_or_fail(conn.get(),
                        "UPDATE public.schema_meta SET version = 1 WHERE store = 'store_h'");
        const std::string t2b = "ALTER TABLE items ADD COLUMN IF NOT EXISTS name_b TEXT";
        const std::vector<PgMigration> changed = {{1, t1}, {2, t2b}};
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", changed));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 2);
        CHECK(recorded(2, "sha256") == hash_of(t2b));
        CHECK(recorded(2, "recorded_by") == "apply");
        CHECK(row_count() == 2);
    }

    SECTION("a database that predates the table is recorded as first seen, then checked") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        exec_ok_or_fail(conn.get(), "DELETE FROM public.yuzu_schema_migrations WHERE store = 'store_h'");
        REQUIRE(row_count() == 0);

        std::string logs;
        {
            yuzu::test::LogCapture capture{spdlog::level::info};
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
            capture.stop();
            logs = capture.text();
        }
        CHECK(logs.find("trust on first use") != std::string::npos);
        CHECK(row_count() == 3);
        CHECK(recorded(1, "recorded_by") == "tofu");
        CHECK(recorded(3, "sha256") == hash_of(t3));

        // Second run records nothing new and stays quiet.
        {
            yuzu::test::LogCapture capture{spdlog::level::info};
            REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
            capture.stop();
            CHECK(capture.text().find("trust on first use") == std::string::npos);
        }
        CHECK(row_count() == 3);

        // And a later in-place edit of a first-seen version is now caught.
        const std::vector<PgMigration> edited = {{1, t1}, {2, t2}, {3, t3 + " "}};
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_h", edited));
    }

    SECTION("a database with no table at all (the real upgrade shape) creates it and records") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        exec_ok_or_fail(conn.get(), "DROP TABLE public.yuzu_schema_migrations");
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        CHECK(row_count() == 3);
        CHECK(recorded(2, "recorded_by") == "tofu");
        CHECK(recorded(2, "sha256") == hash_of(t2));
    }

    SECTION("a foreign public.schema_migrations table is left alone and does not break the runner") {
        exec_ok_or_fail(conn.get(),
                        "CREATE TABLE public.schema_migrations (version bigint PRIMARY KEY, "
                        "dirty boolean NOT NULL)");
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        CHECK(row_count() == 3);
        CHECK(scalar(conn.get(), "SELECT count(*) FROM public.schema_migrations") == 0);
    }

    SECTION("a database ahead of this binary is not judged on versions it does not know") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        const std::vector<PgMigration> older = {{1, t1}, {2, t2}};
        CHECK(PgMigrationRunner::run(conn.get(), "store_h", older)); // #3894: WARN only
        CHECK(row_count() == 3);
    }

    SECTION("an unreadable hash record fails closed") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        exec_ok_or_fail(conn.get(),
                        "ALTER TABLE public.yuzu_schema_migrations RENAME COLUMN sha256 TO sha");
        std::string logs;
        bool ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            ok = PgMigrationRunner::run(conn.get(), "store_h", v3);
            capture.stop();
            logs = capture.text();
        }
        CHECK_FALSE(ok);
        CHECK(logs.find("reading recorded migration hashes failed for store_h") !=
              std::string::npos);
        exec_ok_or_fail(conn.get(),
                        "ALTER TABLE public.yuzu_schema_migrations RENAME COLUMN sha TO sha256");
    }

    SECTION("a recorded hash that is not lowercase hex is refused with its own message") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        exec_ok_or_fail(conn.get(),
                        "UPDATE public.yuzu_schema_migrations SET sha256 = repeat('Z', 64) "
                        "WHERE store = 'store_h' AND version = 2");
        std::string logs;
        bool ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            ok = PgMigrationRunner::run(conn.get(), "store_h", v3);
            capture.stop();
            logs = capture.text();
        }
        CHECK_FALSE(ok);
        CHECK(logs.find("not a lowercase SHA-256") != std::string::npos);
        CHECK(logs.find("ZZZZ") == std::string::npos); // the bad value never reaches a log
        CHECK(logs.find("was changed after") == std::string::npos); // not misdescribed as drift
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 3);
    }
}

namespace {

// One thread per vector, each on its OWN connection, released together by a latch (no
// sleeps). Results are collected and asserted on the calling thread only: Catch2's
// assertion macros are not safe to call from the workers.
std::vector<int> run_concurrently(const std::string& dsn, const std::string& store,
                                  const std::vector<std::vector<PgMigration>>& vectors) {
    std::vector<int> results(vectors.size(), -1);
    std::latch start{1};
    std::vector<std::thread> workers;
    for (std::size_t i = 0; i < vectors.size(); ++i) {
        workers.emplace_back([&, i] {
            PgConn conn{PQconnectdb(dsn.c_str())};
            if (PQstatus(conn.get()) != CONNECTION_OK)
                return;
            start.wait();
            results[i] = PgMigrationRunner::run(conn.get(), store, vectors[i]) ? 1 : 0;
        });
    }
    start.count_down();
    for (auto& w : workers)
        w.join();
    return results;
}

} // namespace

TEST_CASE("PgMigrationRunner hash recording under concurrent runners (#7158)",
          "[pg][migration][drift][concurrency]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());
    const std::vector<PgMigration> v3 = {
        {1, "CREATE TABLE IF NOT EXISTS items (id INT PRIMARY KEY)"},
        {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS name TEXT"},
        {3, "ALTER TABLE items ADD COLUMN IF NOT EXISTS note TEXT"}};
    const auto rows = [&](const std::string& store, const char* extra = "") {
        return scalar(conn.get(), "SELECT count(*) FROM public.yuzu_schema_migrations WHERE store = '" +
                                      store + "' " + extra);
    };

    SECTION("same vector on a fresh store: every runner succeeds, one apply row per version") {
        const auto r = run_concurrently(db.dsn(), "store_c", {v3, v3, v3, v3});
        for (int x : r)
            CHECK(x == 1);
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_c") == 3);
        CHECK(rows("store_c") == 3);
        CHECK(rows("store_c", "AND recorded_by = 'apply'") == 3);
    }

    SECTION("competing text for one version: exactly one text wins, the other refuses") {
        // Whichever interleaving, the loser dies either at the verify read or in the apply
        // loop's skip branch, so removing the skip-branch compare turns this red.
        for (int round = 0; round < 5; ++round) {
            const std::string store = "store_x" + std::to_string(round);
            const std::vector<PgMigration> a = {{1, "CREATE TABLE IF NOT EXISTS items_a (id INT)"}};
            const std::vector<PgMigration> b = {{1, "CREATE TABLE IF NOT EXISTS items_b (id INT)"}};
            const auto r = run_concurrently(db.dsn(), store, {a, b});
            CHECK(r[0] + r[1] == 1);
            CHECK(rows(store) == 1);
        }
    }

    SECTION("a pre-table store opened by several runners at once is recorded once each") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_p", v3));
        exec_ok_or_fail(conn.get(), "DELETE FROM public.yuzu_schema_migrations WHERE store = 'store_p'");
        const auto r = run_concurrently(db.dsn(), "store_p", {v3, v3, v3, v3});
        for (int x : r)
            CHECK(x == 1);
        CHECK(rows("store_p") == 3);
        CHECK(rows("store_p", "AND recorded_by = 'tofu'") == 3);
    }
}
