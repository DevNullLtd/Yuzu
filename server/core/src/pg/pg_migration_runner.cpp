#include "pg_migration_runner.hpp"

#include "pg_exec.hpp"
#include "pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <libpq-fe.h>

#include <cstdlib>
#include <cstring>

namespace yuzu::server::pg {

namespace {

// First key of the two-int advisory-lock pair every runner transaction
// takes; the second key is hashtext(store_name). Transaction-scoped
// (pg_advisory_xact_lock), so a crashed runner can never leave the lock
// behind. 0x79757A75 is "yuzu" read as big-endian ASCII.
//
// Advisory locks are CLUSTER-wide, not per-database: two runners migrating
// the same store name in *different* databases on one Postgres instance
// (e.g. two test binaries against the shared yuzu-ci-postgres container)
// serialize on each other. That is benign — transaction-scoped locks
// release on commit/abort/disconnect, so the worst case is brief
// serialization, never deadlock or cross-database corruption.
//
// Collision bound (gov fjarvis L3): hashtext() yields a 32-bit signed int, so
// two DISTINCT store names can collide on the second lock key. The only effect
// is brief over-serialization (the two stores' migration txns can't run
// concurrently); the per-store version is still re-read under the lock, so
// correctness is unaffected. Across ~27 stores the birthday probability is
// negligible. A collision can never corrupt or mis-apply a migration.
constexpr const char* kAdvisoryLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext($1::text))";

// Global (constant-key) variant for the meta-table/schema bootstrap txn:
// two processes migrating DIFFERENT stores hold different per-store locks
// yet race the same `CREATE TABLE IF NOT EXISTS public.schema_meta`, which
// can fail one of them spuriously on the catalog unique index (UP-1).
// Startup-only, so the brief global serialization is free.
constexpr const char* kGlobalLockSql = "SELECT pg_advisory_xact_lock(2037545589, 0)";

/// One-row, one-param text query helper — the single-param case of the shared
/// `pg::exec_params` (#1368 promoted the boilerplate into pg_exec.hpp; this is
/// now a thin adapter so there is one PQexecParams call site, not two).
PgResult exec_param(PGconn* conn, const char* sql, const std::string& param) {
    return exec_params(conn, sql, std::vector<std::string>{param});
}

/// Version row lookup. Returns 0 when absent, -1 on error. `missing_table_ok`
/// maps SQLSTATE 42P01 (undefined_table — schema_meta not created yet) to 0.
int read_version(PGconn* conn, const std::string& store, bool missing_table_ok) {
    PgResult res =
        exec_param(conn, "SELECT version FROM public.schema_meta WHERE store = $1", store);
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate = res ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
        if (missing_table_ok && sqlstate && std::strcmp(sqlstate, "42P01") == 0)
            return 0;
        spdlog::error("PgMigrationRunner: version lookup failed for {}: {}", store,
                      PQerrorMessage(conn));
        return -1;
    }
    if (PQntuples(res.get()) < 1)
        return 0;
    // Bounds-checked above (1 row); field 0 exists by construction of the
    // SELECT. PQgetvalue never returns NULL for a valid coordinate.
    return std::atoi(PQgetvalue(res.get(), 0, 0));
}

bool exec_ok(PGconn* conn, const std::string& sql, std::string_view what, std::string_view store) {
    PgResult res{PQexec(conn, sql.c_str())};
    if (!res.ok()) {
        spdlog::error("PgMigrationRunner: {} failed for {}: {}", what, store, PQerrorMessage(conn));
        return false;
    }
    return true;
}

} // namespace

bool PgMigrationRunner::valid_store_name(std::string_view name) {
    if (name.empty() || name.size() > 63)
        return false;
    const auto lower_or_underscore = [](char c) {
        return (c >= 'a' && c <= 'z') || c == '_';
    };
    if (!lower_or_underscore(name.front()))
        return false;
    for (char c : name) {
        if (!lower_or_underscore(c) && !(c >= '0' && c <= '9'))
            return false;
    }
    // Reserved namespaces (Gate 3 arch/qe): "public" would land the store's
    // tables next to public.schema_meta and shadow it via search_path;
    // "information_schema" pollutes a system schema; Postgres itself
    // rejects "pg_*" schemas (42939) but we fail it at validation so the
    // error names the actual rule. Tightening this AFTER a store ships
    // would be a breaking substrate change — hence locked down now, while
    // the substrate has zero consumers.
    if (name == "public" || name == "information_schema" || name.starts_with("pg_"))
        return false;
    return true;
}

bool PgMigrationRunner::ensure_meta_and_schema(PGconn* conn, std::string_view store_name) {
    const std::string store{store_name};
    if (!exec_ok(conn, "BEGIN", "BEGIN (meta)", store))
        return false;
    PgTxn txn{conn};

    // Serialize ALL runners (global key — see kGlobalLockSql) before the
    // IF NOT EXISTS DDL: two simultaneous CREATE TABLE IF NOT EXISTS can
    // collide on the catalog unique index and fail one of them spuriously,
    // and a per-store key would not cover two processes bootstrapping
    // different stores.
    {
        PgResult lock{PQexec(conn, kGlobalLockSql)};
        if (lock.status() != PGRES_TUPLES_OK) {
            spdlog::error("PgMigrationRunner: global advisory lock failed for {}: {}", store,
                          PQerrorMessage(conn));
            return false;
        }
    }
    if (!exec_ok(conn,
                 "CREATE TABLE IF NOT EXISTS public.schema_meta ("
                 "  store       TEXT PRIMARY KEY,"
                 "  version     INTEGER NOT NULL,"
                 "  upgraded_at BIGINT NOT NULL)",
                 "CREATE schema_meta", store))
        return false;
    // store_name is validated as [a-z_][a-z0-9_]* by run(); quoted anyway.
    if (!exec_ok(conn, "CREATE SCHEMA IF NOT EXISTS \"" + store + "\"", "CREATE SCHEMA", store))
        return false;
    return txn.commit();
}

int PgMigrationRunner::current_version(PGconn* conn, std::string_view store_name) {
    if (!conn)
        return -1;
    // Read-only: tolerate the meta table not existing yet (0 = untracked)
    // instead of creating it here — keeps this path free of DDL so it can
    // never race another process's CREATE TABLE IF NOT EXISTS.
    return read_version(conn, std::string{store_name}, /*missing_table_ok=*/true);
}

bool PgMigrationRunner::run(PGconn* conn, std::string_view store_name,
                            const std::vector<PgMigration>& migrations) {
    // Null connection is an error even with nothing to do — PR 3 feeds this
    // from Lease::get(), which is nullptr on an empty lease; reporting
    // success there would boot a store against a database it never reached
    // (Gate 2 sec finding: fail-open).
    if (!conn)
        return false;
    if (migrations.empty())
        return true;
    if (!valid_store_name(store_name)) {
        spdlog::error("PgMigrationRunner: invalid store name '{}' — must match "
                      "[a-z_][a-z0-9_]*, max 63 bytes",
                      store_name);
        return false;
    }
    const std::string store{store_name};

    // #3013 (found in review, #2961/#2964): two independently-authored
    // branches can each allocate the SAME "next" version number for the
    // SAME store — nothing here previously stopped that. Before this check,
    // the loop below's `if (m.version <= current) continue;` treated
    // whichever migration landed SECOND as "already applied" and silently
    // skipped it — `run()` still returned true, `any_applied` could still be
    // true for the OTHER migrations in the vector, so the store opened
    // clean while missing schema every runtime query written against it
    // assumes exists. Checked once, up front, against the CALLER-SUPPLIED
    // vector order — never a re-sorted copy — so an author who lists two
    // migrations out of numeric order gets the same loud refusal a genuine
    // duplicate does, rather than the runner quietly reordering intent.
    // The pairwise check below only orders migrations against EACH OTHER —
    // it never anchors the vector against `read_version`'s own floor. Since
    // `read_version` returns 0 for an untracked store, a vector beginning
    // `{0, 1, 2, ...}` is strictly increasing and passes the pairwise check,
    // but the apply loop's `m.version <= current` treats version 0 as
    // already-applied and skips it forever — the same silent-skip shape
    // #3013 closed for a duplicate/non-monotonic pair, at index 0 instead.
    if (migrations.front().version <= 0) {
        spdlog::error(
            "PgMigrationRunner: store '{}' has a non-positive first migration version ({}) — "
            "refusing to run any migration for this store. Migration versions must start at 1: "
            "version 0 is indistinguishable from an untracked store and would be skipped "
            "forever by the apply loop's <= current check.",
            store, migrations.front().version);
        return false;
    }
    for (std::size_t i = 1; i < migrations.size(); ++i) {
        if (migrations[i].version <= migrations[i - 1].version) {
            spdlog::error(
                "PgMigrationRunner: store '{}' has a non-monotonic or duplicate migration "
                "version in its migrations() vector (version {} at index {} does not exceed "
                "version {} at index {}) — refusing to run any migration for this store. Two "
                "migrations were likely allocated the same version number by independent "
                "branches (#3013) — renumber one of them.",
                store, migrations[i].version, i, migrations[i - 1].version, i - 1);
            return false;
        }
    }

    if (!ensure_meta_and_schema(conn, store))
        return false;

    int current = read_version(conn, store, /*missing_table_ok=*/false);
    if (current < 0)
        return false;

    // Schema-drift guard (#1368 CH-11 / UP-9). Version 0 means "no migration
    // recorded", yet a non-empty store schema means tables exist out-of-band:
    // schema_meta was wiped or poisoned, or someone hand-created tables. Blindly
    // running migration v1 (whose `CREATE TABLE` is not IF-NOT-EXISTS) over
    // existing tables would either error opaquely or silently diverge. Refuse
    // and fail the boot closed with a cause the operator can act on. A genuinely
    // new store reaches here with the empty schema just created above, so this
    // never false-fires on first boot. ensure_meta_and_schema already created
    // the schema, so information_schema.tables is the authoritative check.
    if (current == 0) {
        PgResult drift = exec_param(
            conn, "SELECT 1 FROM information_schema.tables WHERE table_schema = $1 LIMIT 1", store);
        if (drift.status() == PGRES_TUPLES_OK && PQntuples(drift.get()) > 0) {
            spdlog::error("PgMigrationRunner: store '{}' is at version 0 in schema_meta but its "
                          "schema already contains tables — schema_meta loss/poisoning or "
                          "out-of-band DDL. Refusing to migrate (manual reconciliation required).",
                          store);
            return false;
        }
    }

    bool any_applied = false;
    for (const auto& m : migrations) {
        if (m.version <= current)
            continue;

        if (!exec_ok(conn, "BEGIN", "BEGIN", store))
            return false;
        PgTxn txn{conn};

        // Per-store advisory lock, then re-read: the loser of a two-server
        // race blocks here until the winner commits, then sees the winner's
        // version and skips.
        {
            PgResult lock = exec_param(conn, kAdvisoryLockSql, store);
            if (lock.status() != PGRES_TUPLES_OK) {
                spdlog::error("PgMigrationRunner: advisory lock failed for {}: {}", store,
                              PQerrorMessage(conn));
                return false;
            }
        }
        const int locked_version = read_version(conn, store, /*missing_table_ok=*/false);
        if (locked_version < 0)
            return false;
        if (m.version <= locked_version) { // another process applied it
            current = locked_version;
            continue; // txn dtor rolls back the empty transaction
        }

        // Transaction-local search_path so the migration's unqualified DDL
        // lands in the store's schema and nothing leaks onto the pooled
        // connection after COMMIT/ROLLBACK. `store` is interpolated (libpq has
        // no parameter binding for identifiers), which is injection-safe ONLY
        // because run() rejected anything but [a-z_][a-z0-9_]{0,62} via
        // valid_store_name() before reaching here (gov fjarvis L4); double-
        // quoted as defence in depth.
        if (!exec_ok(conn, "SET LOCAL search_path TO \"" + store + "\", public", "SET search_path",
                     store))
            return false;

        if (!exec_ok(conn, m.sql, "migration v" + std::to_string(m.version), store))
            return false;

        {
            const std::string version_str = std::to_string(m.version);
            const char* values[] = {store.c_str(), version_str.c_str()};
            PgResult res{
                PQexecParams(conn,
                             "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                             "VALUES ($1, $2::int, extract(epoch FROM now())::bigint) "
                             "ON CONFLICT (store) DO UPDATE "
                             "SET version = EXCLUDED.version, upgraded_at = EXCLUDED.upgraded_at",
                             2, nullptr, values, nullptr, nullptr, 0)};
            if (res.status() != PGRES_COMMAND_OK) {
                spdlog::error("PgMigrationRunner: failed to set version {} for {}: {}", m.version,
                              store, PQerrorMessage(conn));
                return false;
            }
        }

        if (!txn.commit()) {
            spdlog::error("PgMigrationRunner: COMMIT failed for {} v{}: {}", store, m.version,
                          PQerrorMessage(conn));
            return false;
        }

        spdlog::info("PgMigrationRunner: {} migrated to v{}", store, m.version);
        any_applied = true;
        current = m.version;
    }

    if (!any_applied)
        spdlog::debug("PgMigrationRunner: {} at v{} (up to date)", store, current);

    return true;
}

} // namespace yuzu::server::pg
