#pragma once

/// @file pg_migration_runner.hpp
/// Postgres port of `MigrationRunner` (ADR-0008 "Migrations" +
/// "Namespacing"): numbered `{version, sql}` migrations registered in C++
/// next to each store, applied against a shared
/// `public.schema_meta(store, version, upgraded_at)` table, with one
/// Postgres SCHEMA per store namespace.
///
/// Differences from the SQLite runner that callers must know:
///  - The runner creates `CREATE SCHEMA IF NOT EXISTS <store>` and runs each
///    migration with `SET LOCAL search_path TO <store>, public` — so a
///    migration's unqualified `CREATE TABLE items (...)` lands in the
///    store's own schema. The setting is transaction-local (`SET LOCAL`);
///    nothing leaks onto the pooled connection.
///  - At runtime (outside migrations) stores must schema-qualify their table
///    names (`SELECT ... FROM response.items`) — pooled connections carry no
///    per-store search_path.
///  - Concurrent runners (two server processes against one database) are
///    serialized per store via a transaction-scoped advisory lock, and the
///    applied version is re-read under that lock — the loser of the race
///    sees the winner's version and skips.
///  - Store names are SQL identifiers here, so they are restricted to
///    `[a-z_][a-z0-9_]*`, max 63 bytes, excluding the reserved namespaces
///    `public`, `information_schema`, and the `pg_` prefix. Anything else
///    is rejected.
///
/// Future-evolution note (mirrors the SQLite runner's ALTER-TABLE note):
/// every migration runs inside a transaction, and the search_path
/// mechanism REQUIRES that (`SET LOCAL` reverts at txn end). Statements
/// that cannot run in a transaction block — `CREATE INDEX CONCURRENTLY`,
/// `VACUUM`, `ALTER TYPE ... ADD VALUE` (pre-12 semantics) — cannot be
/// expressed as a `PgMigration`. When a store needs one (likely for the
/// response/audit-scale indexes), add an explicit non-transactional
/// migration kind that schema-qualifies its table names instead of relying
/// on search_path; do not weaken the transactional default.

#include <string>
#include <string_view>
#include <vector>

// Real header, not a forward-declare: `PGconn` is a typedef of libpq's
// PRIVATE struct tag `pg_conn`, and re-declaring a third party's internal
// name pins it — a libpq rename would break the build here last and least
// legibly. The include costs nothing in practice: every consumer of this
// header also pulls pg_raii.hpp/pg_pool.hpp, which include it directly.
#include <libpq-fe.h>

namespace yuzu::server::pg {

/// A single schema migration step. `sql` is owning (`std::string`) for the
/// same reason as the SQLite `Migration`: libpq's `PQexec` requires a
/// null-terminated C string, and a future caller constructing from a
/// non-null-terminated view must not be able to slip one in.
struct PgMigration {
    int version;     ///< Target version after this migration runs.
    std::string sql; ///< SQL statement(s) to execute.
};

/**
 * Runs sequential schema migrations for one store against a PostgreSQL
 * connection (typically a pinned `PgPool` lease at store construction).
 *
 * Usage:
 *   PgMigrationRunner::run(conn, "response", {
 *       {1, "CREATE TABLE responses (...)"},
 *       {2, "ALTER TABLE responses ADD COLUMN ..."},
 *   });
 */
class PgMigrationRunner {
public:
    /// Run all pending migrations for the named store. Each migration runs in
    /// its own transaction (Postgres DDL is transactional), so a failure at
    /// step N leaves 1..N-1 applied and recorded — same contract as the
    /// SQLite runner. Returns true if all migrations succeeded (or none were
    /// needed).
    ///
    /// #3013: `migrations` must be strictly increasing by `version` with no
    /// duplicates, checked up front — a duplicate or out-of-order version
    /// (e.g. two independent branches both allocating the next number) fails
    /// the WHOLE call closed rather than silently skipping whichever one
    /// loses the `<= current` race in the apply loop below.
    [[nodiscard]] static bool run(PGconn* conn, std::string_view store_name,
                                  const std::vector<PgMigration>& migrations);

    /// Current schema version for a store. Returns 0 if the store (or the
    /// schema_meta table itself) is untracked, -1 on query error.
    [[nodiscard]] static int current_version(PGconn* conn, std::string_view store_name);

    /// True when `name` is usable as a store name / Postgres schema
    /// identifier: `[a-z_][a-z0-9_]*`, at most 63 bytes.
    [[nodiscard]] static bool valid_store_name(std::string_view name);

private:
    static bool ensure_meta_and_schema(PGconn* conn, std::string_view store_name);
};

} // namespace yuzu::server::pg
