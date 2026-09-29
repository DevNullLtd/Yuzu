#include "migration_runner.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>

namespace yuzu::server {

bool MigrationRunner::ensure_meta_table(sqlite3* db) {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS schema_meta (
            store      TEXT PRIMARY KEY,
            version    INTEGER NOT NULL,
            upgraded_at INTEGER NOT NULL
        );
    )";
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        spdlog::error("MigrationRunner: failed to create schema_meta: {}", err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }
    return true;
}

int MigrationRunner::current_version(sqlite3* db, std::string_view store_name) {
    // Idempotently ensure `schema_meta` exists. `run()` also calls this once
    // at its entry, so there is a redundant call on the hot path — the cost
    // is one `CREATE TABLE IF NOT EXISTS` (sub-millisecond on warm cache).
    // Defense-in-depth: `current_version` is a public static method, and
    // external callers (e.g. a future per-store version status endpoint)
    // would silently see `-1`-as-error instead of `0`-as-never-migrated
    // if we relied on `run()` to have been called first.
    if (!ensure_meta_table(db))
        return -1;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, "SELECT version FROM schema_meta WHERE store = ?", -1, &stmt,
                                nullptr);
    if (rc != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, store_name.data(), static_cast<int>(store_name.size()),
                      SQLITE_STATIC);

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return version;
}

bool MigrationRunner::set_version(sqlite3* db, std::string_view store_name, int version) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(
        db,
        "INSERT OR REPLACE INTO schema_meta (store, version, upgraded_at) VALUES (?, ?, ?)", -1,
        &stmt, nullptr);
    if (rc != SQLITE_OK)
        return false;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    sqlite3_bind_text(stmt, 1, store_name.data(), static_cast<int>(store_name.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, version);
    sqlite3_bind_int64(stmt, 3, now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool MigrationRunner::run(sqlite3* db, std::string_view store_name,
                          const std::vector<Migration>& migrations) {
    if (!db || migrations.empty())
        return true;

    if (!ensure_meta_table(db))
        return false;

    int current = current_version(db, store_name);
    if (current < 0)
        return false;

    // Find first migration that needs to run
    bool any_applied = false;
    for (const auto& m : migrations) {
        if (m.version <= current)
            continue;

        // Run this migration in a transaction
        char* err = nullptr;
        int rc = sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            spdlog::error("MigrationRunner: BEGIN failed for {}: {}", store_name,
                          err ? err : "unknown");
            sqlite3_free(err);
            return false;
        }

        rc = sqlite3_exec(db, m.sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            spdlog::error("MigrationRunner: migration v{} failed for {}: {}", m.version,
                          store_name, err ? err : "unknown");
            sqlite3_free(err);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }

        if (!set_version(db, store_name, m.version)) {
            spdlog::error("MigrationRunner: failed to set version {} for {}", m.version,
                          store_name);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }

        rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            spdlog::error("MigrationRunner: COMMIT failed for {}: {}", store_name,
                          err ? err : "unknown");
            sqlite3_free(err);
            // Explicit ROLLBACK even though a failed COMMIT already aborts
            // the transaction in WAL mode — required so a shared-connection
            // caller (`InstructionDbPool`'s trio deleted it in ADR-0065; any
            // remaining SQLite store sharing a connection across migrations
            // is the same concern) doesn't inherit a half-open transaction
            // state on the next store's BEGIN IMMEDIATE.
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }

        spdlog::info("MigrationRunner: {} migrated to v{}", store_name, m.version);
        any_applied = true;
        current = m.version;
    }

    if (!any_applied) {
        spdlog::debug("MigrationRunner: {} at v{} (up to date)", store_name, current);
    }

    return true;
}

} // namespace yuzu::server
