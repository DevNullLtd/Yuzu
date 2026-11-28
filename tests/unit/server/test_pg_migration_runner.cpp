// PgMigrationRunner tests (#1320 PR 1): versioning, schema namespacing,
// re-run idempotency, partial failure, store-name validation.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_migration_runner.hpp"
#include "pg/pg_raii.hpp"
#include "sha256_hex.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <cstdlib>
#include <latch>
#include <string>
#include <thread>
#include <utility>
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
        const auto v1 =
            PgMigrationRunner::check_recorded_hashes(3, expected, {{1, "X"}, {2, "b"}, {3, "c"}});
        CHECK(v1.drifted == std::vector<int>{1});
        const auto v2 =
            PgMigrationRunner::check_recorded_hashes(3, expected, {{1, "a"}, {2, "X"}, {3, "c"}});
        CHECK(v2.drifted == std::vector<int>{2});
    }
    SECTION("versions above the recorded schema version are not judged (rewound schema_meta)") {
        const auto v =
            PgMigrationRunner::check_recorded_hashes(1, expected, {{1, "a"}, {2, "OLD"}});
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

TEST_CASE("PgMigrationRunner records the SHA-256 of the exact migration bytes (#7158)",
          "[pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());
    // Pins the helper AND the runner's "exact bytes, no normalisation" decision: this text
    // has newlines and a trailing newline, and a runner that trimmed or folded whitespace
    // would record something else. The literal is the SHA-256 of these bytes.
    const std::string sql = "CREATE TABLE t (\n  id INT\n);\n";
    const std::string pinned = "4eab02f428e85198d82945a894e72cee24ecdc1d711ec09795a787c79fa65f03";
    const auto h = yuzu::server::sha256_hex(sql);
    REQUIRE(h.has_value());
    CHECK(*h == pinned);
    const auto trimmed = yuzu::server::sha256_hex("CREATE TABLE t (\n  id INT\n);");
    REQUIRE(trimmed.has_value());
    CHECK(*trimmed != *h);

    REQUIRE(PgMigrationRunner::run(conn.get(), "store_bytes", {{1, sql}}));
    CHECK(text_scalar(conn.get(), "SELECT sha256 FROM public.yuzu_schema_migrations "
                                  "WHERE store = 'store_bytes' AND version = 1") == pinned);
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
    const auto hash_of = [](const std::string& sql) {
        return *yuzu::server::sha256_hex(sql);
    };
    const auto recorded = [&](int version, const char* col) {
        return text_scalar(conn.get(),
                           std::string("SELECT ") + col +
                               " FROM public.yuzu_schema_migrations WHERE store = 'store_h' "
                               "AND version = " +
                               std::to_string(version));
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
        const std::vector<PgMigration> edited = {{1, t1 + "-- edited"}, {2, t2}, {3, t3}};
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
        exec_ok_or_fail(conn.get(),
                        "DELETE FROM public.yuzu_schema_migrations WHERE store = 'store_h'");
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

    SECTION(
        "a foreign public.schema_migrations table is left alone and does not break the runner") {
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

    SECTION("a database ahead of this binary still refuses a version it carries with edited "
            "text (the downgrade-onto-edited-text sub-case, pinned)") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        const std::vector<PgMigration> older_edited = {
            {1, t1}, {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS name_edited TEXT"}};
        std::string logs;
        bool ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            ok = PgMigrationRunner::run(conn.get(), "store_h", older_edited);
            capture.stop();
            logs = capture.text();
        }
        CHECK_FALSE(ok);
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 3);
        CHECK(logs.find("recorded migration v2") != std::string::npos);
    }

    SECTION("the hashes are verified BEFORE a pending higher migration is applied") {
        // Pins "no schema movement before the refusal": were the verify to run after the
        // apply loop, v3 would be applied and only then refused, so the schema would move
        // under a build that is about to be rejected. (It does not distinguish the
        // lock-free verify from any other ordering that refuses before applying.)
        const std::vector<PgMigration> two = {{1, t1}, {2, t2}};
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", two));
        const std::vector<PgMigration> edited_plus_new = {
            {1, t1}, {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS name_edited TEXT"}, {3, t3}};
        CHECK_FALSE(PgMigrationRunner::run(conn.get(), "store_h", edited_plus_new));
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 2);
        CHECK(row_count() == 2);
        CHECK(scalar(conn.get(),
                     "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
                     "'store_h' AND table_name = 'items' AND column_name = 'note'") == 0);
    }

    // Runs v3 for store_h with a CHECK constraint that refuses every hash-row write for it,
    // returning {run() result, captured error log}; the constraint is dropped again before
    // returning so the caller's later assertions see a normal table.
    const auto run_with_hash_writes_refused = [&]() -> std::pair<bool, std::string> {
        exec_ok_or_fail(
            conn.get(),
            "ALTER TABLE public.yuzu_schema_migrations ADD CONSTRAINT yuzu_test_nowrite "
            "CHECK (store <> 'store_h')");
        std::string logs;
        bool ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            ok = PgMigrationRunner::run(conn.get(), "store_h", v3);
            capture.stop();
            logs = capture.text();
        }
        exec_ok_or_fail(conn.get(), "ALTER TABLE public.yuzu_schema_migrations DROP CONSTRAINT "
                                    "yuzu_test_nowrite");
        return {ok, logs};
    };

    SECTION("a hash write that fails rolls the whole migration back (apply path)") {
        // Another store creates the table first, so the constraint has something to attach to.
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_seed", {{1, "CREATE TABLE s (id INT)"}}));
        const auto [ok, logs] = run_with_hash_writes_refused();
        CHECK_FALSE(ok);
        CHECK(logs.find("failed to record the hash of v1 for store_h") != std::string::npos);
        // Same transaction as the schema_meta bump: nothing applied, nothing recorded.
        CHECK(PgMigrationRunner::current_version(conn.get(), "store_h") == 0);
        CHECK(row_count() == 0);
        CHECK_FALSE(table_exists(conn.get(), "store_h", "items"));
    }

    SECTION("a first-sight hash write that fails refuses the store and records nothing") {
        REQUIRE(PgMigrationRunner::run(conn.get(), "store_h", v3));
        exec_ok_or_fail(conn.get(),
                        "DELETE FROM public.yuzu_schema_migrations WHERE store = 'store_h'");
        const auto [ok, logs] = run_with_hash_writes_refused();
        CHECK_FALSE(ok);
        CHECK(logs.find("failed to record the hash of v1 for store_h") != std::string::npos);
        CHECK(row_count() == 0);
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
        return scalar(conn.get(),
                      "SELECT count(*) FROM public.yuzu_schema_migrations WHERE store = '" + store +
                          "' " + extra);
    };

    SECTION("same vector on a fresh store: every runner succeeds, one apply row per version") {
        // Pins the re-read in the version-0-with-tables guard: a loser that read 0 just
        // before the winner committed must not be refused as "schema_meta loss".
        // Probabilistic by nature (about 1 run in 6 catches the regression with the re-read
        // removed; nothing here can force the interleaving without a production hook). A red
        // run of this section is the re-read gone, not noise: do not retry it away.
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
        exec_ok_or_fail(conn.get(),
                        "DELETE FROM public.yuzu_schema_migrations WHERE store = 'store_p'");
        const auto r = run_concurrently(db.dsn(), "store_p", {v3, v3, v3, v3});
        for (int x : r)
            CHECK(x == 1);
        CHECK(rows("store_p") == 3);
        CHECK(rows("store_p", "AND recorded_by = 'tofu'") == 3);
    }

    SECTION("multi-version vectors sharing v1 and differing on v2: exactly one text wins") {
        // Probabilistic (the interleaving is not forced); the deterministic twin below pins
        // the skip-branch race. Here the loser can die at the verify read, in the skip
        // branch, or at the apply loop's compare, but never return true against the winner.
        for (int round = 0; round < 5; ++round) {
            const std::string store = "store_m" + std::to_string(round);
            const std::string v1 = "CREATE TABLE IF NOT EXISTS items (id INT)";
            const std::vector<PgMigration> a = {
                {1, v1}, {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS a TEXT"}};
            const std::vector<PgMigration> b = {
                {1, v1}, {2, "ALTER TABLE items ADD COLUMN IF NOT EXISTS b TEXT"}};
            const auto r = run_concurrently(db.dsn(), store, {a, b});
            CHECK(r[0] + r[1] == 1);
            CHECK(rows(store) == 2);
        }
    }
}

namespace {

/// Holds the per-store advisory lock the runner takes, on a second connection, so a
/// runner started in a thread blocks at it. Lets a test commit "the other process's"
/// work in the exact window between the runner's lock-free verify and its locked
/// re-read, which is otherwise a race nothing can force. No production hook: the lock
/// key is the runner's documented one (2037545589, hashtext(store)).
struct HeldStoreLock {
    PGconn* holder;
    std::string store;

    HeldStoreLock(PGconn* h, std::string s) : holder(h), store(std::move(s)) {
        exec_ok_or_fail(holder, "BEGIN");
        exec_ok_or_fail(holder,
                        "SELECT pg_advisory_xact_lock(2037545589, hashtext('" + store + "')) ");
    }

    /// Polls pg_locks until a runner is waiting on this store's lock (bounded: 20 s).
    bool wait_for_waiter(PGconn* observer) const {
        const std::string sql =
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
            "AND classid = 2037545589 AND objid::bigint = (hashtext('" +
            store + "')::bigint & 4294967295)";
        for (int i = 0; i < 2000; ++i) {
            if (scalar(observer, sql) >= 1)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }
};

/// Releases the lock-holder and joins the runner thread on EVERY exit path, including the
/// exception a failed REQUIRE throws: a std::thread destroyed while joinable calls
/// std::terminate, which would abort the whole test binary and hide every other result.
/// ROLLBACK is a harmless no-op warning when the holder already committed. Declare it
/// immediately after the thread, before any call that can throw. (std::jthread is not
/// available in every supported libc++; see test_command_dedup_store.cpp.)
struct ReleaseAndJoin {
    PGconn* holder;
    std::thread& thread;
    ~ReleaseAndJoin() {
        if (thread.joinable()) {
            PgResult rb{PQexec(holder, "ROLLBACK")};
            thread.join();
        }
    }
};

} // namespace

TEST_CASE("PgMigrationRunner concurrent-winner branch compares every adopted version (#7158)",
          "[pg][migration][drift][concurrency]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgConn conn = connect(db.dsn());
    PgConn holder = connect(db.dsn());
    const std::string v1 = "CREATE TABLE items (id INT)";
    const std::string x2 = "ALTER TABLE items ADD COLUMN a TEXT";
    const std::string y2 = "ALTER TABLE items ADD COLUMN b TEXT";
    const auto hash_of = [](const std::string& sql) {
        return *yuzu::server::sha256_hex(sql);
    };

    SECTION("build Y shares v1 with build X, differs on v2, and loses the race: refuses") {
        // Y verifies at version 0 (lock-free) and blocks on the per-store lock; X then
        // commits v1 AND v2 (schema_meta + hashes in one txn, as the runner does). Y wakes,
        // adopts version 2, and must still compare v2 rather than skip it.
        const std::string store = "store_r";
        HeldStoreLock lock{holder.get(), store};
        const std::vector<PgMigration> y = {{1, v1}, {2, y2}};
        std::string logs;
        bool y_ok = true;
        {
            yuzu::test::LogCapture capture{spdlog::level::err};
            std::thread t{[&] {
                PgConn c{PQconnectdb(db.dsn().c_str())};
                y_ok =
                    PQstatus(c.get()) == CONNECTION_OK && PgMigrationRunner::run(c.get(), store, y);
            }};
            ReleaseAndJoin release{holder.get(), t};
            const bool waiting = lock.wait_for_waiter(conn.get());
            if (waiting) {
                exec_ok_or_fail(holder.get(), "SET LOCAL search_path TO \"" + store + "\", public");
                exec_ok_or_fail(holder.get(), v1);
                exec_ok_or_fail(holder.get(), x2);
                exec_ok_or_fail(holder.get(),
                                "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                                "VALUES ('" +
                                    store + "', 2, 0)");
                exec_ok_or_fail(holder.get(),
                                "INSERT INTO public.yuzu_schema_migrations "
                                "(store, version, sha256, recorded_by, recorded_at) VALUES ('" +
                                    store + "', 1, '" + hash_of(v1) + "', 'apply', 0), ('" + store +
                                    "', 2, '" + hash_of(x2) + "', 'apply', 0)");
            }
            exec_ok_or_fail(holder.get(), "COMMIT");
            t.join();
            capture.stop();
            logs = capture.text();
            REQUIRE(waiting);
        }
        CHECK_FALSE(y_ok);
        CHECK(logs.find("store '" + store + "' recorded migration v2") != std::string::npos);
        CHECK(PgMigrationRunner::current_version(conn.get(), store) == 2);
        CHECK(text_scalar(conn.get(), "SELECT sha256 FROM public.yuzu_schema_migrations WHERE "
                                      "store = 'store_r' AND version = 2") == hash_of(x2));
    }

    SECTION("a pre-table store: the first-sight re-read under the lock catches competing text") {
        // The store is already at v2 with build X's text and no hash rows (a database that
        // predates the table). Y (different v2) reads no rows lock-free, blocks on the lock;
        // X's first-sight record commits in the window; Y's re-read must see it differ. Without
        // the re-read, Y's DO NOTHING insert silently "succeeds" against X's rows.
        const std::string store = "store_f";
        const std::vector<PgMigration> x = {{1, v1}, {2, x2}};
        REQUIRE(PgMigrationRunner::run(conn.get(), store, x));
        exec_ok_or_fail(conn.get(),
                        "DELETE FROM public.yuzu_schema_migrations WHERE store = '" + store + "'");
        HeldStoreLock lock{holder.get(), store};
        const std::vector<PgMigration> y = {{1, v1}, {2, y2}};
        bool y_ok = true;
        std::thread t{[&] {
            PgConn c{PQconnectdb(db.dsn().c_str())};
            y_ok = PQstatus(c.get()) == CONNECTION_OK && PgMigrationRunner::run(c.get(), store, y);
        }};
        ReleaseAndJoin release{holder.get(), t};
        const bool waiting = lock.wait_for_waiter(conn.get());
        if (waiting)
            exec_ok_or_fail(holder.get(),
                            "INSERT INTO public.yuzu_schema_migrations "
                            "(store, version, sha256, recorded_by, recorded_at) VALUES ('" +
                                store + "', 1, '" + hash_of(v1) + "', 'tofu', 0), ('" + store +
                                "', 2, '" + hash_of(x2) + "', 'tofu', 0)");
        exec_ok_or_fail(holder.get(), "COMMIT");
        t.join();
        REQUIRE(waiting);
        CHECK_FALSE(y_ok);
        CHECK(text_scalar(conn.get(), "SELECT sha256 FROM public.yuzu_schema_migrations WHERE "
                                      "store = 'store_f' AND version = 2") == hash_of(x2));
    }
}
