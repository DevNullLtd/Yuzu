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
    ///
    /// #7158: every applied migration's SHA-256 is recorded in
    /// `public.yuzu_schema_migrations`, and every `run()` compares the recorded hash
    /// of each version at or below the recorded schema version with this
    /// binary's text. A DIFFERENT hash means the database recorded a version
    /// whose DDL is not what this build's runtime queries were written against
    /// (an in-place edit of an already-applied migration): `run()` refuses
    /// (returns false, one error line naming the store, the version and both
    /// hashes) instead of letting the store open and fail at its first query.
    /// Unlike the ahead case below this is ON-procedure (same build lineage)
    /// and the refusal is the FIRST failure, so it fails closed; there is
    /// deliberately no override. A version applied before this table existed
    /// has no recorded hash: it is recorded as it is first seen
    /// (`recorded_by = 'tofu'`, trust on first use). That cannot detect drift
    /// that predates the table, and it assumes one build lineage per database
    /// (the hard-cutover deployment contract): a binary that applied different
    /// text and was later replaced is recorded as whatever the current build
    /// holds. Steady state is one lock-free read; only first sight of an
    /// unhashed version takes the per-store lock. The table has a
    /// Yuzu-specific name because `public` is shared with whatever else lives
    /// in the database: a foreign `schema_migrations` (golang-migrate, Rails,
    /// Flyway) would make `CREATE TABLE IF NOT EXISTS` skip silently and every
    /// store then fail on a missing column. This detects accidental or
    /// procedural drift, NOT tampering: whoever can write the table can also
    /// rewrite `schema_meta`, and a deleted row is simply recorded again.
    /// A recorded hash that is not 64 lowercase hex digits (a hand-edited row)
    /// is refused with its own message and never reaches a compare or a log.
    /// Versions at or below the recorded version that this binary also carries
    /// are judged even when the database is ahead of the vector (below), so a
    /// downgrade onto edited text now refuses where it used to warn.
    ///
    /// #3894: the complementary case — a database already AHEAD of this
    /// binary's vector (an older build started against a database a newer one
    /// migrated). That situation is outside the supported procedure (rolling
    /// upgrades and a return to an earlier build are not supported at this
    /// stage), so this is WARN-ONLY, never a refusal: a refusal would add a
    /// second failure to a situation that is already off-procedure, and the
    /// owner chose to end the silence without changing what boots. `run()`
    /// applies nothing, logs one actionable warning per CALL naming the store
    /// and both versions, and returns true. Some stores call `run()` more than
    /// once per process start (the auth and secrets stores are opened twice;
    /// `LeaderElector` re-runs it on every reconnect), so the warning can
    /// repeat. A store's own constructor can still refuse afterwards (e.g. a
    /// projection smoke-check), so "returns true" is not "the store will
    /// start". Log-only by design (the pg/ layer has no metrics registry). The
    /// warning protects only binaries that contain it; builds shipped before
    /// it stay silent.
    [[nodiscard]] static bool run(PGconn* conn, std::string_view store_name,
                                  const std::vector<PgMigration>& migrations);

    /// #3894: true when the database's recorded version for a store is HIGHER
    /// than the highest version this binary's `migrations` vector declares —
    /// i.e. a newer build already migrated it. False for an empty vector, an
    /// untracked store (0) and an equal or lower version. Pure; exposed so the
    /// decision is testable without a database.
    [[nodiscard]] static bool is_schema_ahead(int db_version,
                                              const std::vector<PgMigration>& migrations);

    /// One (version, SHA-256 hex) pair: what this binary's migration text hashes
    /// to (`expected`) or what `public.yuzu_schema_migrations` recorded (`recorded`).
    struct VersionHash {
        int version;
        std::string sha256;
    };

    /// #7158: the verdict of comparing recorded migration hashes with this
    /// binary's. Both lists hold versions, ascending.
    struct HashVerdict {
        std::vector<int> missing; ///< applied (<= db_version) but no recorded hash
        std::vector<int> drifted; ///< recorded hash differs from this binary's text
    };

    /// #7158: pure comparison, exposed so the decision is testable without a
    /// database. Only versions at or below `db_version` are judged: a recorded
    /// row ABOVE it (a rewound `schema_meta`) is overwritten when that version
    /// re-applies, and a version above this binary's vector (#3894, a newer
    /// build) has no expected hash and is ignored.
    [[nodiscard]] static HashVerdict check_recorded_hashes(int db_version,
                                                           const std::vector<VersionHash>& expected,
                                                           const std::vector<VersionHash>& recorded);

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
