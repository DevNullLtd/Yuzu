/**
 * tar_db.cpp -- SQLite-backed Timeline Activity Record database
 *
 * Tables:
 *   tar_state(collector PRIMARY KEY, state_json, updated_at)
 *   tar_config(key PRIMARY KEY, value)
 *   plus every typed warehouse tier the schema registry declares.
 *
 * The legacy tar_events log was retired by schema v3 and is no longer created;
 * see kCreateSchema below.
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include "tar_db.hpp"
#include "tar_schema_registry.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string_view>

namespace yuzu::tar {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

// Owning holder for the `char*` sqlite3_exec writes through its last parameter.
// That string is malloc'd by SQLite and must be released with sqlite3_free.
//
// RAII rather than hand-placed frees: `execute_atomic_batch` alone has nine
// acquire points across BEGIN / per-statement / COMMIT / ROLLBACK, several of
// them on branches that also `break` or `return`. Every one is correct today
// (governance Gate 3 traced them), but the shape is one added early return away
// from a leak and one missed reset away from a double free, which is a poor
// thing to leave in the code that runs when the database is already in trouble.
//
// `addr()` hands out the `char**` sqlite3_exec wants, freeing anything already
// held so a single holder can be reused across the calls in a loop.
class SqliteErrMsg {
public:
    SqliteErrMsg() = default;
    ~SqliteErrMsg() { sqlite3_free(msg_); }
    SqliteErrMsg(const SqliteErrMsg&) = delete;
    SqliteErrMsg& operator=(const SqliteErrMsg&) = delete;

    char** addr() noexcept {
        sqlite3_free(msg_);
        msg_ = nullptr;
        return &msg_;
    }
    // Never null, so format sites do not need their own ternary.
    [[nodiscard]] const char* text() const noexcept { return msg_ ? msg_ : "unknown error"; }

private:
    char* msg_{nullptr};
};

// Case-insensitive ASCII equality for a short, NUL-terminated SQL identifier
// (SQLite function/identifier names are case-insensitive).
bool ascii_iequals(const char* a, const char* b) noexcept {
    for (; *a && *b; ++a, ++b)
        if (std::tolower(static_cast<unsigned char>(*a)) !=
            std::tolower(static_cast<unsigned char>(*b)))
            return false;
    return *a == *b;
}

// SQLite authorizer for the read-only operator-SQL sandbox (#760). Permits only
// the overall SELECT, reads of registry-known warehouse tables, and scalar/
// aggregate function calls (the handle is read-only, so no function can mutate;
// load_extension is denied both by name here and via SQLITE_DBCONFIG). Everything
// else — INSERT/UPDATE/DELETE/DDL, ATTACH/DETACH, PRAGMA, transaction control,
// recursive CTEs — is denied at prepare time.
//
// noexcept + catch-all is load-bearing: SQLite invokes this from C frames during
// sqlite3_prepare_v2, so a C++ exception (e.g. std::bad_alloc from
// is_queryable_table's allocation) must never unwind through them — that would be
// UB. Any exception fails closed (SQLITE_DENY).
int tar_query_authorizer(void* /*ctx*/, int action, const char* arg1, const char* arg2,
                         const char* /*db_name*/, const char* /*inner_trigger_or_view*/) noexcept {
    try {
        switch (action) {
        case SQLITE_SELECT:
            return SQLITE_OK;
        case SQLITE_FUNCTION:
            // arg2 is the function name; deny load_extension by name (case-
            // insensitive, as SQLite names are) atop the SQLITE_DBCONFIG disable.
            if (arg2 && ascii_iequals(arg2, "load_extension"))
                return SQLITE_DENY;
            return SQLITE_OK;
        case SQLITE_READ:
            return (arg1 && is_queryable_table(arg1)) ? SQLITE_OK : SQLITE_DENY;
        default:
            return SQLITE_DENY;
        }
    } catch (...) {
        return SQLITE_DENY;
    }
}

/// Schema DDL for all TAR tables.
///
/// `tar_events` is deliberately ABSENT. Schema v3 retired it, and the migration
/// in open() still drops it from any pre-v3 database that carries one. Creating
/// it here only to drop it a few statements later cost every fresh open one
/// table plus three indexes, and — worse — left it PRESENT on any database
/// whose schema_version had already reached 3+, because the v3 branch is then
/// skipped. `is_queryable_table()` excludes tar_events specifically so that its
/// "no such table" error cannot become an existence oracle (#760 UP-8); that
/// reasoning holds only while the table really is absent. Dropping it here
/// covers new databases; the v5 migration in open() covers the installed base,
/// which had already resurrected it. Do NOT reintroduce it here — a new capture
/// source goes through the schema registry.
constexpr const char* kCreateSchema = R"(
    CREATE TABLE IF NOT EXISTS tar_state (
        collector   TEXT PRIMARY KEY,
        state_json  TEXT NOT NULL DEFAULT '{}',
        updated_at  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tar_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );

    -- Cursor-model seam (tar_cursor.hpp): one row per cursor-model source
    -- ("power", "removable" — wave 2), holding its last-persisted opaque
    -- versioned cursor JSON. Beside tar_state rather than folded into it —
    -- tar_state's state_json is a snapshot-diff BASELINE (the previous full
    -- enumeration); a cursor is a LOG POSITION, a different shape with a
    -- different persistence contract (always written atomically with the
    -- events it produced — see insert_power_events_and_cursor /
    -- insert_removable_events_and_cursor).
    CREATE TABLE IF NOT EXISTS tar_cursor (
        source      TEXT PRIMARY KEY,
        cursor_json TEXT NOT NULL,
        updated_at  INTEGER NOT NULL DEFAULT 0
    );
)";

// #559 — self-test a freshly-opened tar.db with PRAGMA integrity_check. A
// corrupt file (filesystem damage, partial restore, mid-write crash) must NOT
// be silently trusted: get_config() returns the caller's default on a read
// failure, so a corrupt DB would read every `<source>_enabled` key as its
// "true" default and silently re-enable sources an operator deliberately paused
// for forensic preservation — defeating the #539 retention guard with no
// telemetry. Returns true only when the check reports the canonical "ok".
bool integrity_ok(sqlite3* db) noexcept {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &raw, nullptr) != SQLITE_OK)
        return false; // can't even read the DB → treat as corrupt
    StmtPtr stmt(raw);
    bool ok = false;
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ok = txt && std::string_view{txt} == "ok";
    }
    return ok;
}

// Move a corrupt tar.db (and its -wal/-shm sidecars) aside to a timestamped
// `.corrupt-<epoch>` path for forensic review, so open() can re-initialise a
// fresh, trustworthy database rather than refusing to load TAR entirely.
// Returns the quarantine path, or std::nullopt if the corrupt main file could
// NOT be moved aside (read-only mount, locked file on Windows, permissions) —
// in which case the caller MUST fail closed rather than re-open-and-trust the
// still-corrupt file (#559 / UP-1). A sidecar that can't be moved is removed
// instead, so the freshly-created DB can never adopt a stale -wal/-shm; the
// caller's post-reopen integrity re-check is the backstop if even that fails.
std::optional<std::filesystem::path>
quarantine_corrupt_db(const std::filesystem::path& path) {
    const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    std::filesystem::path dest = path;
    dest += std::format(".corrupt-{}", epoch);
    // Collision-safe naming: `epoch` is only 1-second granular, and the wall
    // clock can step backward (NTP correction, RTC reset). A second corruption
    // that resolved to an already-existing `.corrupt-<epoch>` would otherwise
    // rename ON TOP of the earlier quarantine and silently destroy preserved
    // forensic evidence. Append a disambiguator so every quarantine is kept.
    {
        std::error_code exists_ec;
        for (int n = 1; n < 10'000 && std::filesystem::exists(dest, exists_ec); ++n) {
            dest = path;
            dest += std::format(".corrupt-{}-{}", epoch, n);
        }
    }
    std::error_code ec;
    std::filesystem::rename(path, dest, ec);
    if (ec)
        return std::nullopt; // could not move the corrupt DB aside — fail closed
    for (const char* suffix : {"-wal", "-shm"}) {
        std::filesystem::path side = path;
        side += suffix;
        std::error_code ec2;
        if (std::filesystem::exists(side, ec2)) {
            std::filesystem::path side_dest = dest;
            side_dest += suffix;
            std::filesystem::rename(side, side_dest, ec2);
            if (ec2) {
                // Couldn't preserve the sidecar — remove it so the fresh DB
                // can't replay a stale WAL belonging to the quarantined file.
                std::error_code ec3;
                std::filesystem::remove(side, ec3);
            }
        }
    }
    return dest;
}

/// Execute a multi-statement DDL batch inside ONE transaction.
///
/// SQLite gives every bare statement its own implicit transaction, and WAL
/// defaults to `synchronous=FULL` — so handing `sqlite3_exec` a ~75-statement
/// schema batch costs ~75 separate commits, each with its own fsync. Measured
/// on the Windows CI runner (91 iterations, best of 3, #2093): 72.4 ms per
/// `TarDatabase::open()` unwrapped against 11.0 ms for the identical DDL in a
/// single transaction. Every agent pays this at boot, on every endpoint.
///
/// It is also the atomicity fix. Unwrapped, a batch that fails partway through
/// leaves a half-built schema on disk and `open()` returns an error, so the
/// next open inherits the debris; wrapped, the database is left exactly as it
/// was found.
///
/// Returns SQLITE_OK, or the first failing rc with `*err_msg` set — ownership
/// of which passes to the caller, as with `sqlite3_exec` itself.
/// True if the legacy `tar_events` table (or one of its indexes) is still on
/// disk. One indexed sqlite_master read; no write.
bool tar_events_present(sqlite3* db) {
    const char* sql = "SELECT 1 FROM sqlite_master WHERE name = 'tar_events' OR name LIKE "
                      "'idx_tar_events%' LIMIT 1";
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK) {
        return false; // can't tell — treat as absent; the next open retries
    }
    StmtPtr stmt(raw);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

int exec_ddl_batch(sqlite3* db, const char* ddl, char** err_msg) {
    // A caller may already hold a transaction — create_warehouse_tables() is
    // public. Detect that EXPLICITLY rather than inferring it from a failed
    // BEGIN: SQLITE_BUSY, a read-only handle and OOM all fail BEGIN too, and
    // treating those as "nested, carry on unwrapped" would silently restore
    // both the per-statement fsync cost and the non-atomicity with no trace.
    if (sqlite3_get_autocommit(db) == 0) {
        return sqlite3_exec(db, ddl, nullptr, nullptr, err_msg);
    }

    // IMMEDIATE, not DEFERRED. A deferred BEGIN takes its write lock at the
    // first writing statement, and in WAL a concurrent committer between the
    // read snapshot and that upgrade yields SQLITE_BUSY_SNAPSHOT — for which
    // SQLite does NOT invoke the busy handler, so the 5000 ms busy_timeout set
    // in open() would not help. IMMEDIATE takes the lock up front, where the
    // busy handler does apply. This matches purge_source() and
    // execute_atomic_batch() elsewhere in this file.
    char* begin_err = nullptr;
    int rc = sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, &begin_err);
    if (rc == SQLITE_BUSY || rc == SQLITE_BUSY_SNAPSHOT) {
        // Another connection holds the write lock and outlasted the busy
        // timeout. Do NOT fall back to unwrapped: each of the ~75 statements
        // would then wait out its own busy timeout under mu_, stalling every
        // collector for minutes. Fail and let the caller retry on the next open.
        if (err_msg) {
            *err_msg = begin_err;
        } else {
            sqlite3_free(begin_err);
        }
        return rc;
    }
    if (rc != SQLITE_OK) {
        spdlog::warn("TarDatabase: could not open a transaction for the schema batch ({}) — "
                     "running it unwrapped; this is slower and not atomic",
                     begin_err ? begin_err : "unknown");
        sqlite3_free(begin_err);
        return sqlite3_exec(db, ddl, nullptr, nullptr, err_msg);
    }
    sqlite3_free(begin_err);

    rc = sqlite3_exec(db, ddl, nullptr, nullptr, err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        return rc;
    }

    rc = sqlite3_exec(db, "COMMIT", nullptr, nullptr, err_msg);
    if (rc != SQLITE_OK) {
        // A failed COMMIT leaves the transaction open. Drop it, or every later
        // write on this connection silently joins a transaction that is never
        // committed and is discarded at close.
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        if (sqlite3_get_autocommit(db) == 0) {
            // ROLLBACK failed too — the connection is wedged. Say so loudly:
            // every subsequent write on it will be lost at close.
            spdlog::error("TarDatabase: schema transaction could neither commit nor roll back — "
                          "this connection is wedged and its writes will be discarded. Restart "
                          "the agent.");
        }
    }
    return rc;
}

} // namespace

// ── Construction / destruction ───────────────────────────────────────────────

TarDatabase::TarDatabase(sqlite3* db) : db_{db} {}

TarDatabase::~TarDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    if (query_db_) {
        sqlite3_close(query_db_);
        query_db_ = nullptr;
    }
}

TarDatabase::TarDatabase(TarDatabase&& other) noexcept
    : db_{other.db_.load()}, query_db_{other.query_db_}, quarantined_at_{other.quarantined_at_} {
    other.quarantined_at_.reset();
    other.db_ = nullptr;
    other.query_db_ = nullptr;
}

TarDatabase& TarDatabase::operator=(TarDatabase&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        if (query_db_)
            sqlite3_close(query_db_);
        db_ = other.db_.load();
        query_db_ = other.query_db_;
        quarantined_at_ = other.quarantined_at_;
        other.quarantined_at_.reset();
        other.db_ = nullptr;
        other.query_db_ = nullptr;
    }
    return *this;
}

std::expected<TarDatabase, std::string> TarDatabase::open(const std::filesystem::path& path) {
    // Ensure parent directory exists
    std::error_code ec;
    auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(
                std::format("failed to create directory {}: {}", parent.string(), ec.message()));
        }
    }

    // #1567 — set when this open quarantined a corrupt file; persisted into the
    // fresh DB's tar_config once it is fully initialised (see end of open()).
    std::optional<int64_t> quarantined_at;
    std::string quarantined_file;

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to open tar.db: {}", err));
    }

    // #559 — corruption self-test BEFORE we trust the DB. A fresh/empty file
    // passes trivially; an existing corrupt one is quarantined aside and a clean
    // DB is re-opened in its place, so the agent never silently serves garbage
    // config (which would re-enable operator-paused sources, compounding #539).
    if (!integrity_ok(raw_db)) {
        sqlite3_close(raw_db);
        raw_db = nullptr;
        auto quarantined = quarantine_corrupt_db(path);
        if (!quarantined) {
            // FAIL CLOSED (UP-1): the corrupt DB could not be moved aside, so we
            // must NOT re-open and trust it — doing so would silently serve the
            // "true" get_config default for every `<source>_enabled` key and
            // re-enable sources an operator paused for forensic preservation,
            // the exact failure #559 guards against. Refuse to open; the
            // operator must clear the underlying fault (read-only mount, locked
            // file, permissions) and restart.
            return std::unexpected(std::format(
                "tar.db failed integrity_check and could not be quarantined "
                "(corrupt and unmovable): {}",
                path.string()));
        }
        quarantined_at = now_epoch_seconds();
        quarantined_file = quarantined->filename().string();
        spdlog::error("TAR: tar.db failed PRAGMA integrity_check (tar.db.corruption_detected) — "
                      "quarantined to {} and re-initialising a fresh database",
                      quarantined->string());
        rc = sqlite3_open_v2(path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
        if (rc != SQLITE_OK) {
            std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
            if (raw_db)
                sqlite3_close(raw_db);
            return std::unexpected(
                std::format("failed to re-open tar.db after quarantine: {}", err));
        }
        // Backstop (UP-2): the freshly-created DB must itself be clean — this
        // also catches the case where a -wal/-shm sidecar belonging to the
        // quarantined file could neither be moved nor removed and was adopted by
        // the new file. If even the fresh DB is corrupt, fail closed.
        if (!integrity_ok(raw_db)) {
            sqlite3_close(raw_db);
            return std::unexpected(std::format(
                "tar.db re-initialised after quarantine still fails integrity_check: {}",
                path.string()));
        }
    }

    // WAL mode for concurrent read performance -- required for correctness
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable WAL mode: {}", err));
    }
    sqlite3_free(err_msg);

    // Busy timeout for concurrent access
    sqlite3_busy_timeout(raw_db, 5000);

    // Secure delete -- zeroes deleted content; required for security
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA secure_delete=ON", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable secure_delete: {}", err));
    }
    sqlite3_free(err_msg);

    // Create schema — one transaction, not one per statement (see
    // exec_ddl_batch: ~75 fsync'd commits otherwise, #2093).
    err_msg = nullptr;
    rc = exec_ddl_batch(raw_db, kCreateSchema, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to create TAR schema: {}", err));
    }

    // Set default retention if not already configured
    {
        const char* check_sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        rc = sqlite3_prepare_v2(raw_db, check_sql, -1, &raw_stmt, nullptr);
        if (rc == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
                // No retention_days configured -- set default
                const char* insert_sql =
                    "INSERT INTO tar_config (key, value) VALUES ('retention_days', '7')";
                sqlite3_exec(raw_db, insert_sql, nullptr, nullptr, nullptr);
            }
        }
    }

    auto db = TarDatabase{raw_db};

    // Ensure every registry-declared warehouse table exists on EVERY open —
    // the DDL is IF-NOT-EXISTS-idempotent, and gating it on schema_version<2
    // left upgraded fleets without tables added by NEWER releases (the A1
    // perf tier never materialised on a pre-existing v3 tar.db, so
    // insert_perf_sample failed every 30 s; found during A2). The version
    // marker keeps its legacy meaning (>=2 = typed warehouse present).
    if (db.create_warehouse_tables()) {
        if (db.schema_version() < 2) {
            db.set_config("schema_version", "2");
            spdlog::info("TarDatabase: migrated to schema version 2 (typed warehouse tables)");
        }
    } else {
        // A failed batch that could neither commit nor roll back leaves this
        // connection inside a transaction. Publishing that handle would mean
        // every collector write silently joins a transaction that is never
        // committed and is discarded at close — data loss reported as success.
        // Fail closed instead; the next open starts from a clean connection.
        if (sqlite3_get_autocommit(raw_db) == 0) {
            // `db` owns raw_db by now — returning destroys it, which closes both
            // connections. Do NOT sqlite3_close(raw_db) here as well.
            return std::unexpected(
                std::string{"tar.db schema transaction could neither commit nor roll back; "
                            "refusing to open on a wedged connection"});
        }
        spdlog::warn("TarDatabase: warehouse table creation failed{}",
                     db.schema_version() < 2 ? ", continuing in legacy mode" : "");
    }

    // Disable load_extension for defense-in-depth (H2)
    sqlite3_db_config(raw_db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);

    // Version 3: retire legacy tar_events table (reclaim disk space)
    if (db.schema_version() == 2) {
        std::lock_guard lock(db.mu_);
        char* emsg = nullptr;
        // Use SAVEPOINT for atomicity
        sqlite3_exec(raw_db, "SAVEPOINT v3_migration", nullptr, nullptr, nullptr);
        int mrc = sqlite3_exec(raw_db, "DROP TABLE IF EXISTS tar_events", nullptr, nullptr, &emsg);
        if (mrc == SQLITE_OK) {
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_ts", nullptr, nullptr,
                         nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_type_ts", nullptr, nullptr,
                         nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_snapshot", nullptr, nullptr,
                         nullptr);
            // Only set version to 3 if DROP succeeded
            db.set_config_locked("schema_version", "3");
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: migrated to schema version 3 (legacy tar_events retired)");
        } else {
            spdlog::warn("TarDatabase: failed to drop tar_events: {}", emsg ? emsg : "unknown");
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "ROLLBACK TO v3_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
        }
    }

    // Version 4: add the per-app `version` column to the procperf tiers (DEX
    // app-perf-over-time, slice 1). A FRESH db already has the column from the
    // registry DDL (create_warehouse_tables ran above), and the version walk
    // 0→2→3→4 reaches here with it present — so each ALTER is guarded on a
    // PRAGMA table_info existence check. The version is bumped only when both
    // tiers carry the column (already-present counts as success).
    if (db.schema_version() == 3) {
        std::lock_guard lock(db.mu_);
        auto has_version_col = [&](const char* tbl) -> bool {
            const auto pragma = std::format("PRAGMA table_info({})", tbl);
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(raw_db, pragma.c_str(), -1, &raw, nullptr) != SQLITE_OK)
                return false;
            StmtPtr q(raw);
            while (sqlite3_step(q.get()) == SQLITE_ROW) {
                const auto* col = reinterpret_cast<const char*>(sqlite3_column_text(q.get(), 1));
                if (col && std::string_view{col} == "version")
                    return true;
            }
            return false;
        };
        char* emsg = nullptr;
        sqlite3_exec(raw_db, "SAVEPOINT v4_migration", nullptr, nullptr, nullptr);
        bool ok = true;
        for (const char* tbl : {"procperf_live", "procperf_hourly"}) {
            if (has_version_col(tbl))
                continue;
            const auto alter =
                std::format("ALTER TABLE {} ADD COLUMN version TEXT NOT NULL DEFAULT ''", tbl);
            if (sqlite3_exec(raw_db, alter.c_str(), nullptr, nullptr, &emsg) != SQLITE_OK) {
                // ERROR, not warn: a stranded v4 is NOT a degraded-version state —
                // insert_proc_perf_samples and the hourly rollup both name the
                // `version` column unconditionally, so on a schema-v3 DB they fail
                // to prepare EVERY tick and ALL procperf collection stops. Give the
                // on-call operator the exact recovery, since the schema stays at v3.
                spdlog::error("TarDatabase: v4 ALTER {} failed: {} — schema remains at v3; ALL "
                              "procperf collection will fail until the column is added. Recovery: "
                              "stop the agent and run `ALTER TABLE {} ADD COLUMN version TEXT NOT "
                              "NULL DEFAULT '';` on the tar.db, then restart.",
                              tbl, emsg ? emsg : "unknown", tbl);
                sqlite3_free(emsg);
                emsg = nullptr;
                ok = false;
                break;
            }
        }
        if (ok) {
            db.set_config_locked("schema_version", "4");
            sqlite3_exec(raw_db, "RELEASE v4_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: migrated to schema version 4 (procperf version column)");
        } else {
            sqlite3_exec(raw_db, "ROLLBACK TO v4_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v4_migration", nullptr, nullptr, nullptr);
        }
    }

    // Version 5: retire tar_events for real, on the INSTALLED BASE.
    //
    // v3 already dropped it — but `kCreateSchema` used to recreate it on every
    // open, and the v3 branch is gated on `schema_version() == 2`, so every
    // database that had already reached v3 resurrected the table on each open
    // with nothing left to remove it. Dropping the DDL (above) stops the
    // resurrection for good, yet every agent already in the field sits at v3/v4
    // WITH the table present. Without this bump a fresh install and an upgraded
    // endpoint would carry permanently divergent schemas, and the #760 UP-8
    // argument — that `is_queryable_table()` may exclude tar_events because it
    // is genuinely absent — would hold for fresh installs only.
    //
    // Gated on PRESENCE, not on a version number. A version gate (`== 4`) is
    // armed exactly once and then never again: roll an endpoint back to a
    // pre-fix binary and its kCreateSchema recreates the table while the stored
    // version stays 5, so rolling forward would find the gate false and strand
    // the table forever — reinstating the very divergence this fixes. Agent
    // rollback is supported, so the gate has to be the fact on disk. It is also
    // the only gate that reaches a database stranded at v3 by a failed v4 ALTER.
    // Cost is one sqlite_master read per open; the DROP still happens at most
    // once per resurrection, so no endpoint takes a write on every boot (and
    // with secure_delete=ON a populated table is never re-zeroed at each start).
    if (tar_events_present(raw_db)) {
        std::lock_guard lock(db.mu_);
        char* emsg = nullptr;
        sqlite3_exec(raw_db, "SAVEPOINT v5_migration", nullptr, nullptr, nullptr);
        int mrc = sqlite3_exec(raw_db, "DROP TABLE IF EXISTS tar_events", nullptr, nullptr, &emsg);
        if (mrc == SQLITE_OK) {
            sqlite3_free(emsg);
            // The indexes go with the table; these cover a database that somehow
            // kept an index without it.
            for (const char* idx :
                 {"idx_tar_events_ts", "idx_tar_events_type_ts", "idx_tar_events_snapshot"}) {
                const auto drop = std::format("DROP INDEX IF EXISTS {}", idx);
                sqlite3_exec(raw_db, drop.c_str(), nullptr, nullptr, nullptr);
            }
            sqlite3_exec(raw_db, "RELEASE v5_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: retired the legacy tar_events table");
        } else {
            // WARN, not ERROR: nothing reads or writes tar_events, so the cost of
            // failing here is a residual empty table. The next open retries.
            spdlog::warn("TarDatabase: could not drop the legacy tar_events table: {} — it will be "
                         "retried on the next open; to clear it by hand, stop the agent and run "
                         "`DROP TABLE tar_events;` against the tar.db",
                         emsg ? emsg : "unknown");
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "ROLLBACK TO v5_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v5_migration", nullptr, nullptr, nullptr);
        }
    }
    // The version marker is independent of the drop above: it records that this
    // binary's schema contract has been applied, for in-band auditability.
    if (db.schema_version() == 4) {
        std::lock_guard lock(db.mu_);
        db.set_config_locked("schema_version", "5");
        spdlog::info("TarDatabase: migrated to schema version 5 (legacy tar_events retired)");
    }

    // Version 6: the `usage` derived fold's supplementary table + the two
    // UNIQUE indexes it and usage_live's fold logic depend on (Wave 7
    // PR7.2b). usage_live and usage_daily themselves come from the schema
    // registry's usual CREATE-TABLE-IF-NOT-EXISTS path (create_warehouse_
    // tables() above) once the "usage" CaptureSourceDef is registered --
    // this migration is the SINGLE source of usage_daily_user and both
    // indexes; there is no generate_warehouse_ddl special case for them. A
    // fresh DB runs v2->v6 sequentially in this one open() call, so it
    // reaches v6 with no usage_daily/usage_live rows to reconcile -- the
    // indexes are created against empty tables and can never fail on a
    // pre-existing duplicate.
    if (db.schema_version() == 5) {
        std::lock_guard lock(db.mu_);
        char* emsg = nullptr;
        sqlite3_exec(raw_db, "SAVEPOINT v6_migration", nullptr, nullptr, nullptr);
        bool ok = true;
        for (const char* stmt :
             {"CREATE TABLE IF NOT EXISTS usage_daily_user (day_ts INTEGER NOT NULL, "
              "exe_key TEXT NOT NULL, user TEXT NOT NULL, PRIMARY KEY(day_ts, exe_key, user))",
              "CREATE UNIQUE INDEX IF NOT EXISTS usage_daily_day_exe_uq ON usage_daily(day_ts, "
              "exe_key)",
              "CREATE UNIQUE INDEX IF NOT EXISTS usage_live_pid_exe_uq ON usage_live(pid, "
              "exe_key)"}) {
            if (sqlite3_exec(raw_db, stmt, nullptr, nullptr, &emsg) != SQLITE_OK) {
                spdlog::error("TarDatabase: v6 migration statement failed: {} ({})",
                              emsg ? emsg : "unknown", stmt);
                sqlite3_free(emsg);
                emsg = nullptr;
                ok = false;
                break;
            }
        }
        if (ok) {
            db.set_config_locked("schema_version", "6");
            sqlite3_exec(raw_db, "RELEASE v6_migration", nullptr, nullptr, nullptr);
            spdlog::info(
                "TarDatabase: migrated to schema version 6 (usage_daily_user + usage indexes)");
        } else {
            // Schema stays at 5 -- usage_live/usage_daily DDL from the registry
            // still exists (create_warehouse_tables ran unconditionally above),
            // but without these indexes the fold's DELETE-then-INSERT open-run
            // lifecycle relies on an application-level invariant instead of a
            // DB-enforced one. Retried on the next open.
            sqlite3_exec(raw_db, "ROLLBACK TO v6_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v6_migration", nullptr, nullptr, nullptr);
        }
    }

    // Version 7: add the `is_kthread` marker column to the procperf tiers —
    // kernel-thread (Linux PF_KTHREAD) / Windows System-process (pid 4)
    // exclusion for the daily app-perf-over-time rollup
    // (sync_source_app_perf.cpp); see tar_proc_perf.hpp's "Kernel-thread
    // marker" note. Same guarded-ALTER pattern as v4's `version` column: a
    // FRESH db already has the column (create_warehouse_tables ran above),
    // so each ALTER is guarded on a PRAGMA table_info existence check.
    if (db.schema_version() == 6) {
        std::lock_guard lock(db.mu_);
        auto has_is_kthread_col = [&](const char* tbl) -> bool {
            const auto pragma = std::format("PRAGMA table_info({})", tbl);
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(raw_db, pragma.c_str(), -1, &raw, nullptr) != SQLITE_OK)
                return false;
            StmtPtr q(raw);
            while (sqlite3_step(q.get()) == SQLITE_ROW) {
                const auto* col = reinterpret_cast<const char*>(sqlite3_column_text(q.get(), 1));
                if (col && std::string_view{col} == "is_kthread")
                    return true;
            }
            return false;
        };
        SqliteErrMsg emsg;
        sqlite3_exec(raw_db, "SAVEPOINT v7_migration", nullptr, nullptr, nullptr);
        bool ok = true;
        for (const char* tbl : {"procperf_live", "procperf_hourly"}) {
            if (has_is_kthread_col(tbl))
                continue;
            const auto alter =
                std::format("ALTER TABLE {} ADD COLUMN is_kthread INTEGER NOT NULL DEFAULT 0", tbl);
            if (sqlite3_exec(raw_db, alter.c_str(), nullptr, nullptr, emsg.addr()) != SQLITE_OK) {
                // ERROR, not warn: insert_proc_perf_samples and the hourly rollup
                // both name `is_kthread` unconditionally, so a stranded v6 DB fails
                // to prepare EVERY tick and ALL procperf collection stops.
                spdlog::error("TarDatabase: v7 ALTER {} failed: {} — schema remains at v6; ALL "
                              "procperf collection will fail until the column is added. Recovery: "
                              "stop the agent and run `ALTER TABLE {} ADD COLUMN is_kthread INTEGER "
                              "NOT NULL DEFAULT 0;` on the tar.db, then restart.",
                              tbl, emsg.text(), tbl);
                ok = false;
                break;
            }
        }
        if (ok) {
            db.set_config_locked("schema_version", "7");
            sqlite3_exec(raw_db, "RELEASE v7_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: migrated to schema version 7 (procperf is_kthread column)");
        } else {
            sqlite3_exec(raw_db, "ROLLBACK TO v7_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v7_migration", nullptr, nullptr, nullptr);
        }
    }

    // Open a dedicated read-only, authorizer-sandboxed connection for untrusted
    // operator SQL (the tar.sql action). On this handle writes are structurally
    // impossible and the authorizer restricts reads to registry-known warehouse
    // tables (#760). Internal trusted reads keep using db_. If this connection
    // can't be opened we continue without it; execute_user_query then fails
    // closed.
    {
        sqlite3* ro = nullptr;
        int rrc = sqlite3_open_v2(path.string().c_str(), &ro,
                                  SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rrc == SQLITE_OK) {
            sqlite3_busy_timeout(ro, 5000);
            sqlite3_db_config(ro, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);
            sqlite3_set_authorizer(ro, &tar_query_authorizer, nullptr);
            // Force the is_queryable_table allowlist's one-time static init now,
            // on a normal C++ stack — never lazily inside the authorizer callback
            // while it runs in SQLite's C prepare frames.
            (void)is_queryable_table("");
            db.query_db_ = ro;
        } else {
            spdlog::warn("TarDatabase: read-only query connection unavailable ({}); "
                         "tar.sql queries will be refused",
                         ro ? sqlite3_errmsg(ro) : "open failed");
            if (ro)
                sqlite3_close(ro);
        }
    }

    if (quarantined_at) {
        // Durable source of truth for the fleet-visible corruption fact; the
        // plugin reconciles it into its heartbeat KV keys (a crash between the
        // rename above and this write is the one window where the fact is lost).
        // Basename only — never a full path in status or heartbeat.
        db.quarantined_at_ = quarantined_at;
        db.set_config("db_health_last_quarantine_epoch", std::to_string(*quarantined_at));
        db.set_config("db_health_last_quarantine_file", quarantined_file);
    }

    spdlog::info("TarDatabase opened: {} (schema v{})", path.string(), db.schema_version());
    return db;
}

// ── Statistics (queries typed warehouse tables) ─────────────────────────────

TarStats TarDatabase::stats() {
    std::lock_guard lock(mu_);
    TarStats s{};
    if (!db_)
        return s;

    // Build the per-source live-table fragments once, data-driven over the
    // capture-source registry — so a newly-registered source (perf, procperf,
    // netqual, module, …) is counted automatically instead of being silently
    // omitted by a hand-maintained four-table list. Source names come from the
    // registry, a compile-time allowlist, so the concatenation carries no
    // injection risk; every live tier has a `ts` column, and an empty table
    // contributes COUNT 0 / NULL MIN/MAX, so including them is harmless.
    std::string count_expr;
    std::string min_union;
    std::string max_union;
    bool first = true;
    for (const auto& src : capture_sources()) {
        std::string live = std::string(src.name) + "_live";
        if (!first) {
            count_expr += " + ";
            min_union += " UNION ALL ";
            max_union += " UNION ALL ";
        }
        count_expr += "(SELECT COUNT(*) FROM " + live + ")";
        min_union += "SELECT MIN(ts) AS m FROM " + live;
        max_union += "SELECT MAX(ts) AS m FROM " + live;
        first = false;
    }

    // Aggregate record count across all live tables
    {
        std::string sql = "SELECT " + count_expr;
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.record_count = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Oldest timestamp across all live tables
    {
        std::string sql = "SELECT MIN(m) FROM (" + min_union + ")";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.oldest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Newest timestamp
    {
        std::string sql = "SELECT MAX(m) FROM (" + max_union + ")";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.newest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // DB size (page_count * page_size)
    {
        const char* sql =
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.db_size_bytes = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Retention days from config
    {
        const char* sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
                if (text) {
                    try {
                        s.retention_days = std::stoi(text);
                    } catch (...) {
                        s.retention_days = 7;
                    }
                }
            }
        }
    }

    return s;
}

// ── State management ─────────────────────────────────────────────────────────

std::string TarDatabase::get_state(const std::string& collector) {
    std::lock_guard lock(mu_);
    if (!db_)
        return {};

    const char* sql = "SELECT state_json FROM tar_state WHERE collector = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_state prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : "";
    }
    return {};
}

bool TarDatabase::set_state(const std::string& collector, const std::string& json) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    return upsert_state_locked(db_, collector, json);
}

bool TarDatabase::upsert_state_locked(sqlite3* db, const std::string& collector,
                                      const std::string& json) {
    const char* sql = R"(
        INSERT INTO tar_state (collector, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(collector) DO UPDATE SET state_json = excluded.state_json,
                                             updated_at = excluded.updated_at
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_state prepare failed: {}", sqlite3_errmsg(db));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_state step failed: {}", sqlite3_errmsg(db));
        return false;
    }
    return true;
}

// ── Cursor-model persistence (tar_cursor.hpp) ─────────────────────────────────

std::expected<std::optional<std::string>, std::string>
TarDatabase::get_cursor(const std::string& source) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("TarDatabase::get_cursor: no open database");

    const char* sql = "SELECT cursor_json FROM tar_cursor WHERE source = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::string err = std::string("TarDatabase::get_cursor prepare failed: ") +
                          sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, source.c_str(), static_cast<int>(source.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return std::optional<std::string>(text ? std::string(text) : std::string{});
    }
    if (rc != SQLITE_DONE) {
        // A step that is neither ROW nor DONE is a read FAILURE. Returning
        // nullopt here would tell the caller "never persisted" -- see the
        // header. Only SQLITE_DONE means the query ran and matched nothing.
        std::string err = std::string("TarDatabase::get_cursor step failed: ") +
                          sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    return std::optional<std::string>{};
}

namespace {

// Shared body for insert_power_events_and_cursor / insert_removable_events_and_cursor:
// BEGIN IMMEDIATE, run `insert_events` (which prepares+steps its own INSERT OR
// IGNORE statement against db), INSERT OR REPLACE the cursor row for `source`,
// COMMIT -- all under the caller's mu_, all as one transaction (tar_cursor.hpp
// rule 6). On ANY failure the whole batch is rolled back so events and cursor
// commit or fail together (tar_db.hpp:458-477 documents why per-call-locked
// execute_sql cannot give this guarantee, and why BEGIN IMMEDIATE rather than
// bare BEGIN — IMMEDIATE takes the write lock up front so a concurrent writer
// on this same connection cannot interleave between the events and the cursor
// write).
template <class InsertEventsFn>
bool insert_events_and_cursor_locked(sqlite3* db, const char* log_prefix,
                                     const std::string& source, const std::string& cursor_json,
                                     InsertEventsFn&& insert_events) {
    char* err_msg = nullptr;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("{} BEGIN IMMEDIATE: {}", log_prefix, err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    if (!std::forward<InsertEventsFn>(insert_events)(db, log_prefix)) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    const char* cursor_sql = R"(
        INSERT INTO tar_cursor (source, cursor_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET cursor_json = excluded.cursor_json,
                                          updated_at = excluded.updated_at
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db, cursor_sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("{} cursor prepare: {}", log_prefix, sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr cursor_stmt(raw_stmt);
    sqlite3_bind_text(cursor_stmt.get(), 1, source.c_str(), static_cast<int>(source.size()),
                      SQLITE_STATIC);
    sqlite3_bind_text(cursor_stmt.get(), 2, cursor_json.c_str(),
                      static_cast<int>(cursor_json.size()), SQLITE_STATIC);
    sqlite3_bind_int64(cursor_stmt.get(), 3, now_epoch_seconds());
    if (sqlite3_step(cursor_stmt.get()) != SQLITE_DONE) {
        spdlog::error("{} cursor step: {}", log_prefix, sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    cursor_stmt.reset();

    err_msg = nullptr;
    if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("{} commit: {}", log_prefix, err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

} // namespace

std::expected<void, TarDatabase::CursorInsertError> TarDatabase::insert_power_events_and_cursor(const std::vector<PowerEvent>& events,
                                                 const std::string& cursor_json) {
    // A blank record_key is silently catastrophic: the UNIQUE index makes
    // INSERT OR IGNORE drop every event after the first, and the call still
    // reports success -- forensic loss indistinguishable from an empty tick.
    // Refuse instead, so a collector that fails to derive a key is a loud bug.
    for (const auto& ev : events) {
        if (ev.record_key.empty()) {
            spdlog::error("TarDatabase::insert_power_events_and_cursor: refusing a batch with an "
                          "empty record_key -- the dedupe index would discard all but "
                          "the first event and report success");
            return std::unexpected(CursorInsertError::KeyCollision);
        }
        // A key containing a NUL is NOT caught by empty() but binds as
        // zero-length TEXT, so "\0a" and "\0b" collapse to one row -- the same
        // silent discard the guard above exists to prevent, wearing a
        // non-empty key. Fixed-width USB string descriptors and EvtRender
        // buffers are both realistic sources of one.
        if (ev.record_key.find('\0') != std::string::npos) {
            spdlog::error("TarDatabase::insert_power_events_and_cursor: refusing a batch whose "
                          "record_key contains a NUL -- it is non-empty but binds as "
                          "zero-length, collapsing distinct keys onto one row");
            return std::unexpected(CursorInsertError::KeyCollision);
        }
    }

    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected(CursorInsertError::Transient);

    // Set by the events lambda when it refuses a batch on a payload mismatch.
    // That refusal is PERMANENT -- the same batch is re-derived and re-refused
    // every tick -- so it must not reach the caller as an ordinary failure.
    bool collided = false;
    const bool ok = insert_events_and_cursor_locked(
        db_, "insert_power_events_and_cursor", "power", cursor_json,
        [&events, &collided](sqlite3* db, const char* log_prefix) {
            if (events.empty())
                return true;
            const char* sql = R"(
                INSERT OR IGNORE INTO power_live (ts, snapshot_id, action, detail, record_key)
                VALUES (?, ?, ?, ?, ?) RETURNING record_key
            )";
            sqlite3_stmt* raw_stmt = nullptr;
            if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
                spdlog::error("{} events prepare: {}", log_prefix, sqlite3_errmsg(db));
                return false;
            }
            StmtPtr stmt(raw_stmt);
            // Collision check, paid ONLY when a row is actually ignored.
            // INSERT OR IGNORE cannot tell a legitimate replay (the same OS
            // record re-offered after a failed commit) from a COLLISION (two
            // different OS records that derived the same key). Both look like
            // success, and on a collision the cursor advances past an event
            // that was silently discarded -- forensic loss reported as a clean
            // tick. A non-empty key does not establish identity; only the
            // stored payload does.
            const char* dup_sql = R"(
                SELECT ts, snapshot_id, action, detail FROM power_live WHERE record_key = ?
            )";
            sqlite3_stmt* raw_dup = nullptr;
            if (sqlite3_prepare_v2(db, dup_sql, -1, &raw_dup, nullptr) != SQLITE_OK) {
                spdlog::error("{} dup-check prepare: {}", log_prefix, sqlite3_errmsg(db));
                return false;
            }
            StmtPtr dup(raw_dup);
            for (const auto& ev : events) {
                sqlite3_reset(stmt.get());
                sqlite3_clear_bindings(stmt.get());
                sqlite3_bind_int64(stmt.get(), 1, ev.ts);
                sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
                sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), static_cast<int>(ev.action.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 4, ev.detail.c_str(), static_cast<int>(ev.detail.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 5, ev.record_key.c_str(), static_cast<int>(ev.record_key.size()), SQLITE_STATIC);
                // RETURNING, not sqlite3_changes(): this connection is opened
                // SQLITE_OPEN_FULLMUTEX and shared, and FULLMUTEX serialises
                // individual calls, NOT the step->changes PAIR. Reading
                // db->nChange afterwards is a data race whose wrong answer would
                // make this check miss a real collision or refuse a valid batch
                // (routed-concerns "SQLite sqlite3_changes()" row, issue #1033).
                // RETURNING folds the answer into the statement: a returned row
                // means this INSERT actually inserted.
                const int step_rc = sqlite3_step(stmt.get());
                if (step_rc == SQLITE_ROW)
                    continue; // inserted -- the ordinary path, no extra work
                if (step_rc != SQLITE_DONE) {
                    spdlog::error("{} events step: {}", log_prefix, sqlite3_errmsg(db));
                    return false;
                }
                // SQLITE_DONE with no row == the INSERT was IGNORED.
                sqlite3_reset(dup.get());
                sqlite3_clear_bindings(dup.get());
                sqlite3_bind_text(dup.get(), 1, ev.record_key.c_str(), static_cast<int>(ev.record_key.size()), SQLITE_STATIC);
                if (sqlite3_step(dup.get()) != SQLITE_ROW) {
                    spdlog::error("{} dup-check: record_key '{}' was ignored but no stored row "
                                  "could be read back", log_prefix, ev.record_key);
                    return false;
                }
                // Length from sqlite3_column_bytes, NOT strlen. Constructing a
                // string_view from the char* alone stops at an embedded NUL, so
                // a stored "head\0tail" would compare equal to "head" -- and
                // unequal to the value actually re-offered on a replay, which
                // refuses the event as a collision on every later tick. The
                // bind side has the same trap and is fixed the same way.
                auto col = [&](int i) {
                    const auto* t =
                       reinterpret_cast<const char*>(sqlite3_column_text(dup.get(), i));
                    if (t == nullptr)
                        return std::string_view{};
                    return std::string_view{t, static_cast<std::size_t>(
                                                  sqlite3_column_bytes(dup.get(), i))};
                };
                // Compare only what actually identifies the OS RECORD.
                // `snapshot_id` is collection metadata -- which tick gathered
                // it -- and it is freshly minted every tick, so including it
                // would turn every legitimate retry into a "collision" and
                // wedge the source permanently. `ts` is identity for a real
                // transition, but for a capture_gap it is merely "when we
                // noticed"; a gap's identity lives entirely in its record_key,
                // which encodes the window bounds. So ts participates for
                // everything EXCEPT a gap.
                const bool is_gap = ev.action == "capture_gap";
                if ((is_gap || sqlite3_column_int64(dup.get(), 0) == ev.ts) &&
                    col(2) == ev.action && col(3) == ev.detail)
                    continue; // an exact replay -- the intended dedupe
                spdlog::error("{} record_key COLLISION on '{}': the stored row is a DIFFERENT "
                              "event, so accepting this batch would advance the cursor past an "
                              "event that was never stored -- failing the transaction instead",
                              log_prefix, ev.record_key);
                collided = true;
                return false;
            }
            return true;
        });
    if (ok)
        return {};
    return std::unexpected(collided ? CursorInsertError::KeyCollision
                                    : CursorInsertError::Transient);
}

std::expected<void, TarDatabase::CursorInsertError> TarDatabase::insert_removable_events_and_cursor(const std::vector<RemovableEvent>& events,
                                                      const std::string& cursor_json) {
    // A blank record_key is silently catastrophic: the UNIQUE index makes
    // INSERT OR IGNORE drop every event after the first, and the call still
    // reports success -- forensic loss indistinguishable from an empty tick.
    // Refuse instead, so a collector that fails to derive a key is a loud bug.
    for (const auto& ev : events) {
        if (ev.record_key.empty()) {
            spdlog::error("TarDatabase::insert_removable_events_and_cursor: refusing a batch with an "
                          "empty record_key -- the dedupe index would discard all but "
                          "the first event and report success");
            return std::unexpected(CursorInsertError::KeyCollision);
        }
        // A key containing a NUL is NOT caught by empty() but binds as
        // zero-length TEXT, so "\0a" and "\0b" collapse to one row -- the same
        // silent discard the guard above exists to prevent, wearing a
        // non-empty key. Fixed-width USB string descriptors and EvtRender
        // buffers are both realistic sources of one.
        if (ev.record_key.find('\0') != std::string::npos) {
            spdlog::error("TarDatabase::insert_removable_events_and_cursor: refusing a batch whose "
                          "record_key contains a NUL -- it is non-empty but binds as "
                          "zero-length, collapsing distinct keys onto one row");
            return std::unexpected(CursorInsertError::KeyCollision);
        }
    }

    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected(CursorInsertError::Transient);

    // See the power twin.
    bool collided = false;
    const bool ok = insert_events_and_cursor_locked(
        db_, "insert_removable_events_and_cursor", "removable", cursor_json,
        [&events, &collided](sqlite3* db, const char* log_prefix) {
            if (events.empty())
                return true;
            const char* sql = R"(
                INSERT OR IGNORE INTO removable_live
                    (ts, snapshot_id, action, device_key, vendor, product, serial, bus,
                     volume, size_bytes, image_path, pid, evidence, record_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING record_key
            )";
            sqlite3_stmt* raw_stmt = nullptr;
            if (sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
                spdlog::error("{} events prepare: {}", log_prefix, sqlite3_errmsg(db));
                return false;
            }
            StmtPtr stmt(raw_stmt);
            const char* dup_sql = R"(
                SELECT ts, snapshot_id, action, device_key, vendor, product, serial, bus,
                       volume, size_bytes, image_path, pid, evidence
                  FROM removable_live WHERE record_key = ?
            )";
            sqlite3_stmt* raw_dup = nullptr;
            if (sqlite3_prepare_v2(db, dup_sql, -1, &raw_dup, nullptr) != SQLITE_OK) {
                spdlog::error("{} dup-check prepare: {}", log_prefix, sqlite3_errmsg(db));
                return false;
            }
            StmtPtr dup(raw_dup);
            for (const auto& ev : events) {
                sqlite3_reset(stmt.get());
                sqlite3_clear_bindings(stmt.get());
                sqlite3_bind_int64(stmt.get(), 1, ev.ts);
                sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
                sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), static_cast<int>(ev.action.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 4, ev.device_key.c_str(), static_cast<int>(ev.device_key.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 5, ev.vendor.c_str(), static_cast<int>(ev.vendor.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 6, ev.product.c_str(), static_cast<int>(ev.product.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 7, ev.serial.c_str(), static_cast<int>(ev.serial.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 8, ev.bus.c_str(), static_cast<int>(ev.bus.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 9, ev.volume.c_str(), static_cast<int>(ev.volume.size()), SQLITE_STATIC);
                sqlite3_bind_int64(stmt.get(), 10, ev.size_bytes);
                sqlite3_bind_text(stmt.get(), 11, ev.image_path.c_str(), static_cast<int>(ev.image_path.size()), SQLITE_STATIC);
                sqlite3_bind_int64(stmt.get(), 12, ev.pid);
                sqlite3_bind_text(stmt.get(), 13, ev.evidence.c_str(), static_cast<int>(ev.evidence.size()), SQLITE_STATIC);
                sqlite3_bind_text(stmt.get(), 14, ev.record_key.c_str(), static_cast<int>(ev.record_key.size()), SQLITE_STATIC);
                // Same as the power twin. RETURNING, not sqlite3_changes(): this connection is opened
                // SQLITE_OPEN_FULLMUTEX and shared, and FULLMUTEX serialises
                // individual calls, NOT the step->changes PAIR. Reading
                // db->nChange afterwards is a data race whose wrong answer would
                // make this check miss a real collision or refuse a valid batch
                // (routed-concerns "SQLite sqlite3_changes()" row, issue #1033).
                // RETURNING folds the answer into the statement: a returned row
                // means this INSERT actually inserted.
                const int step_rc = sqlite3_step(stmt.get());
                if (step_rc == SQLITE_ROW)
                    continue; // inserted -- the ordinary path, no extra work
                if (step_rc != SQLITE_DONE) {
                    spdlog::error("{} events step: {}", log_prefix, sqlite3_errmsg(db));
                    return false;
                }
                // SQLITE_DONE with no row == the INSERT was IGNORED.
                sqlite3_reset(dup.get());
                sqlite3_clear_bindings(dup.get());
                sqlite3_bind_text(dup.get(), 1, ev.record_key.c_str(), static_cast<int>(ev.record_key.size()), SQLITE_STATIC);
                if (sqlite3_step(dup.get()) != SQLITE_ROW) {
                    spdlog::error("{} dup-check: record_key '{}' was ignored but no stored row "
                                  "could be read back", log_prefix, ev.record_key);
                    return false;
                }
                // Length from sqlite3_column_bytes, NOT strlen. Constructing a
                // string_view from the char* alone stops at an embedded NUL, so
                // a stored "head\0tail" would compare equal to "head" -- and
                // unequal to the value actually re-offered on a replay, which
                // refuses the event as a collision on every later tick. The
                // bind side has the same trap and is fixed the same way.
                auto col = [&](int i) {
                    const auto* t =
                       reinterpret_cast<const char*>(sqlite3_column_text(dup.get(), i));
                    if (t == nullptr)
                        return std::string_view{};
                    return std::string_view{t, static_cast<std::size_t>(
                                                  sqlite3_column_bytes(dup.get(), i))};
                };
                // Same rule as the power twin: snapshot_id is per-tick
                // collection metadata and never participates, and ts is
                // identity for a real attach/detach but only "when we noticed"
                // for a capture_gap. present_at_baseline joins that second
                // group too (PR #4023 review round 2, blocker #2):
                // removable_baseline_record_key() already keys ONLY on
                // device_key, deliberately excluding ts, because a CursorLost
                // re-baseline re-emits the identical baseline row with a
                // fresh wall-clock ts -- if ts still participated here that
                // re-emission would collide against the original row on every
                // retry forever, permanently wedging the source on a
                // corrupted-cursor recovery path that exists specifically to
                // UN-wedge it.
                const bool ts_is_not_identity =
                    ev.action == "capture_gap" || ev.action == "present_at_baseline";
                if ((ts_is_not_identity || sqlite3_column_int64(dup.get(), 0) == ev.ts) &&
                    col(2) == ev.action && col(3) == ev.device_key && col(4) == ev.vendor &&
                    col(5) == ev.product && col(6) == ev.serial && col(7) == ev.bus &&
                    col(8) == ev.volume && sqlite3_column_int64(dup.get(), 9) == ev.size_bytes &&
                    col(10) == ev.image_path && sqlite3_column_int64(dup.get(), 11) == ev.pid &&
                    col(12) == ev.evidence)
                    continue; // an exact replay -- the intended dedupe
                spdlog::error("{} record_key COLLISION on '{}': the stored row is a DIFFERENT "
                              "event, so accepting this batch would advance the cursor past an "
                              "event that was never stored -- failing the transaction instead",
                              log_prefix, ev.record_key);
                collided = true;
                return false;
            }
            return true;
        });
    if (ok)
        return {};
    return std::unexpected(collided ? CursorInsertError::KeyCollision
                                    : CursorInsertError::Transient);
}

// ── Config management ────────────────────────────────────────────────────────

std::expected<std::optional<std::string>, std::string>
TarDatabase::try_get_config(const std::string& key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("TarDatabase::try_get_config: no open database");

    const char* sql = "SELECT value FROM tar_config WHERE key = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        std::string err =
           std::string("TarDatabase::try_get_config prepare failed: ") + sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return std::optional<std::string>(
           t ? std::string(t, static_cast<std::size_t>(sqlite3_column_bytes(stmt.get(), 0)))
             : std::string{});
    }
    if (rc != SQLITE_DONE) {
        std::string err =
           std::string("TarDatabase::try_get_config step failed: ") + sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    return std::optional<std::string>{}; // succeeded, no row
}

std::string TarDatabase::get_config(const std::string& key, const std::string& default_val) {
    std::lock_guard lock(mu_);
    if (!db_)
        return default_val;

    const char* sql = "SELECT value FROM tar_config WHERE key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_config prepare failed: {}", sqlite3_errmsg(db_));
        return default_val;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : default_val;
    }
    return default_val;
}

bool TarDatabase::set_config(const std::string& key, const std::string& value) {
    std::lock_guard lock(mu_);
    return set_config_locked(key, value);
}

bool TarDatabase::set_config_locked(const std::string& key, const std::string& value) {
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO tar_config (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_config prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, value.c_str(), static_cast<int>(value.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_config step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

// ── Warehouse schema management ─────────────────────────────────────────────

int TarDatabase::schema_version() {
    auto v = get_config("schema_version", "0");
    try {
        return std::stoi(v);
    } catch (...) {
        return 0;
    }
}

bool TarDatabase::create_warehouse_tables() {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    auto ddl = generate_warehouse_ddl();
    char* err_msg = nullptr;
    // One transaction for the whole registry DDL — the dominant cost of an
    // open, and the larger of the two batches (#2093). See exec_ddl_batch.
    int rc = exec_ddl_batch(db_, ddl.c_str(), &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::create_warehouse_tables failed: {}",
                      err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

std::expected<int, std::string> TarDatabase::purge_source(const std::string& source) {
    // Resolve the source's tier tables from the schema registry — never hardcode.
    // Table names are <name>_<suffix> (same construction as stats()/DDL).
    const CaptureSourceDef* def = nullptr;
    for (const auto& s : capture_sources()) {
        if (s.name == source) {
            def = &s;
            break;
        }
    }
    if (!def)
        return std::unexpected("unknown source: " + source);

    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected(std::string("database not open"));

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string e = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        return std::unexpected("BEGIN failed: " + e);
    }

    int total = 0;
    for (const auto& g : def->granularities) {
        const std::string table = std::string(def->name) + "_" + std::string(g.suffix);
        const std::string sql = "DELETE FROM " + table;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
            std::string e = err_msg ? err_msg : "unknown";
            sqlite3_free(err_msg);
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return std::unexpected("purge failed on " + table + ": " + e);
        }
        // Safe under mu_: it serialises every access to db_, so no concurrent
        // step() can race this changes() read (the #1033 hazard needs a shared,
        // concurrently-used handle). O(1) vs stepping RETURNING rows on a bulk
        // delete.
        total += sqlite3_changes(db_);
    }

    // usage_daily_user (Wave 7 PR7.2b) has no tier of its own in the schema
    // registry -- its shape (PRIMARY KEY(day_ts, exe_key, user), no `id`
    // column; see this file's v6 migration) does not fit the generic
    // per-tier layout the loop above walks, so the granularity walk above
    // never reaches it and an operator-initiated `tar.purge_source usage`
    // would otherwise leave every username behind (docs/tar-dashboard.md
    // §3.4's purge promise). Purge it here, in the SAME transaction as the
    // registered "usage" tiers above, so it erases atomically with
    // everything else -- and it must never resurrect on re-enable: the
    // lifecycle's PendingBaseline gate (tar_usage.cpp) always requires a
    // fresh baseline before the next fold, which never reads usage_daily_
    // user at all.
    if (source == "usage") {
        if (sqlite3_exec(db_, "DELETE FROM usage_daily_user", nullptr, nullptr, &err_msg) !=
            SQLITE_OK) {
            std::string e = err_msg ? err_msg : "unknown";
            sqlite3_free(err_msg);
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return std::unexpected("purge failed on usage_daily_user: " + e);
        }
        total += sqlite3_changes(db_);
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string e = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return std::unexpected("COMMIT failed: " + e);
    }

    // Forensic-erasure completion: secure_delete=ON (open path) zeroes the
    // deleted rows in the MAIN-db pages, but under journal_mode=WAL the pre-delete
    // page images (still bearing the purged data) linger in the -wal file until a
    // checkpoint truncates it. For a "permanent / cannot be undone" purge that is
    // a real residue window — and the operator often purges to reclaim disk, which
    // a passive checkpoint won't do promptly. Force a TRUNCATE checkpoint here so
    // the erasure is complete and the WAL is reclaimed at return. Best-effort: the
    // DELETE already committed, so a checkpoint that can't fully complete (e.g. a
    // lingering reader) is logged, not fatal — the residue clears at the next one.
    if (int wrc = sqlite3_wal_checkpoint_v2(db_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr,
                                            nullptr);
        wrc != SQLITE_OK) {
        spdlog::warn("purge_source({}): WAL checkpoint(TRUNCATE) returned {} — purged data may "
                     "persist in the WAL until the next checkpoint",
                     source, wrc);
    }
    return total;
}

// ── Typed inserts ───────────────────────────────────────────────────────────

bool TarDatabase::insert_process_events(const std::vector<ProcessEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_process_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO process_live (ts, snapshot_id, action, pid, ppid, name, cmdline, user)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 4, static_cast<int>(ev.pid));
        sqlite3_bind_int(stmt.get(), 5, static_cast<int>(ev.ppid));
        sqlite3_bind_text(stmt.get(), 6, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.cmdline.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.user.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_process_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_network_events(const std::vector<NetworkEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_network_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO tcp_live (ts, snapshot_id, action, proto, local_addr, local_port,
                              remote_addr, remote_host, remote_port, state, pid, process_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.proto.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.local_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 6, ev.local_port);
        sqlite3_bind_text(stmt.get(), 7, ev.remote_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.remote_host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 9, ev.remote_port);
        sqlite3_bind_text(stmt.get(), 10, ev.state.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 11, static_cast<int>(ev.pid));
        sqlite3_bind_text(stmt.get(), 12, ev.process_name.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_network_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

std::expected<std::vector<NetworkEvent>, std::string>
TarDatabase::query_recent_tcp_connections(int64_t since_ts) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected{"database not open"};

    // Group by 5-tuple+pid; surface the most recent observation per group.
    // Filter to ESTABLISHED — LISTEN/TIME_WAIT/CLOSE_WAIT/etc. are not
    // "this box talks to that box" edges and would pollute the viz.
    // remote_host (reverse-DNS) is taken from the latest row in the group
    // via a correlated subquery; if two rows in the same group resolved
    // differently, we accept the newest.
    const char* sql = R"(
        SELECT proto, local_addr, local_port, remote_addr, remote_port, pid,
               MAX(process_name) AS process_name,
               MAX(remote_host)  AS remote_host,
               MAX(state)        AS state,
               MAX(ts)           AS ts
        FROM tcp_live
        WHERE ts >= ?
          AND state = 'ESTABLISHED'
        GROUP BY proto, local_addr, local_port, remote_addr, remote_port, pid
        ORDER BY ts DESC
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected{std::string{"prepare: "} + sqlite3_errmsg(db_)};
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, since_ts);

    std::vector<NetworkEvent> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        NetworkEvent ev;
        auto col_text = [&](int i) -> std::string {
            const unsigned char* p = sqlite3_column_text(stmt.get(), i);
            return p ? std::string{reinterpret_cast<const char*>(p)} : std::string{};
        };
        ev.proto = col_text(0);
        ev.local_addr = col_text(1);
        ev.local_port = sqlite3_column_int(stmt.get(), 2);
        ev.remote_addr = col_text(3);
        ev.remote_port = sqlite3_column_int(stmt.get(), 4);
        ev.pid = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 5));
        ev.process_name = col_text(6);
        ev.remote_host = col_text(7);
        ev.state = col_text(8);
        ev.ts = sqlite3_column_int64(stmt.get(), 9);
        out.push_back(std::move(ev));
    }
    return out;
}

bool TarDatabase::insert_service_events(const std::vector<ServiceEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_service_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO service_live (ts, snapshot_id, action, name, display_name, status,
                                  prev_status, startup_type, prev_startup_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.display_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.prev_status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.startup_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 9, ev.prev_startup_type.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_service_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_user_events(const std::vector<UserEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_user_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO user_live (ts, snapshot_id, action, user, domain, logon_type, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.user.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.domain.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.logon_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.session_id.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_user_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_software_events(const std::vector<SoftwareEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_software_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO software_live (ts, snapshot_id, action, name, version, prev_version,
                                   publisher, install_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_software_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.prev_version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.publisher.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.install_date.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_software_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_software_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_arp_events(const std::vector<ArpEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_arp_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO arp_live (ts, snapshot_id, action, interface, ip_address, mac_address, entry_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_arp_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.iface.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.ip_address.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.mac_address.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.entry_type.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_arp_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_arp_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_dns_events(const std::vector<DnsEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_dns_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO dns_live (ts, snapshot_id, action, name, record_type, data, ttl_remaining_s, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_dns_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.record_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.data.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt.get(), 7, ev.ttl_remaining_s);
        sqlite3_bind_text(stmt.get(), 8, ev.source.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_dns_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_dns_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_mapdrive_events(const std::vector<MapDriveEvent>& events,
                                       const std::optional<StateWrite>& state) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    if (events.empty())
        return !state || upsert_state_locked(db_, state->collector, state->json);

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_mapdrive_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO mapdrive_live (ts, snapshot_id, action, direction, local_mount, remote_path, remote_host, username, provider, origin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_mapdrive_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.direction.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.local_mount.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.remote_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.remote_host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 9, ev.provider.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 10, ev.origin.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_mapdrive_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    if (state && !upsert_state_locked(db_, state->collector, state->json)) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_mapdrive_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_perf_sample(const PerfRow& row) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    // Single row per sample interval — no transaction wrapper needed (one
    // statement is already atomic; one fsync per 30 s is the WAL cost).
    const char* sql = R"(
        INSERT INTO perf_live (ts, snapshot_id, cpu_pct, mem_used_pct, commit_pct,
                               disk_read_bps, disk_write_bps, disk_read_lat_us,
                               disk_write_lat_us, net_rx_bps, net_tx_bps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_perf_sample prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, row.ts);
    sqlite3_bind_int64(stmt.get(), 2, row.snapshot_id);
    sqlite3_bind_double(stmt.get(), 3, row.cpu_pct);
    sqlite3_bind_double(stmt.get(), 4, row.mem_used_pct);
    sqlite3_bind_double(stmt.get(), 5, row.commit_pct);
    sqlite3_bind_int64(stmt.get(), 6, row.disk_read_bps);
    sqlite3_bind_int64(stmt.get(), 7, row.disk_write_bps);
    sqlite3_bind_int64(stmt.get(), 8, row.disk_read_lat_us);
    sqlite3_bind_int64(stmt.get(), 9, row.disk_write_lat_us);
    sqlite3_bind_int64(stmt.get(), 10, row.net_rx_bps);
    sqlite3_bind_int64(stmt.get(), 11, row.net_tx_bps);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        spdlog::error("insert_perf_sample step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

bool TarDatabase::insert_proc_perf_samples(const std::vector<ProcPerfRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    // <= 2*kProcTopN rows per tick — one transaction, one fsync per 30 s.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO procperf_live (ts, snapshot_id, name, version, instances, cpu_pct, ws_bytes,
            is_kthread)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, r.version.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt.get(), 5, r.instances);
        sqlite3_bind_double(stmt.get(), 6, r.cpu_pct);
        sqlite3_bind_int64(stmt.get(), 7, r.ws_bytes);
        sqlite3_bind_int(stmt.get(), 8, r.is_kthread ? 1 : 0);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_proc_perf_samples step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::insert_module_events(const std::vector<ModuleRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    // One transaction per drain batch — one fsync regardless of batch size.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_module_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO module_live (ts, snapshot_id, action, pid, process_name,
                                 module_name, module_dir, signed_state, signer, is_kernel)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_module_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.action.c_str(), -1, SQLITE_TRANSIENT);
        // pid is uint32; bind as int64 so a high pid never wraps negative.
        sqlite3_bind_int64(stmt.get(), 4, static_cast<int64_t>(r.pid));
        sqlite3_bind_text(stmt.get(), 5, r.process_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 6, r.module_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 7, r.module_dir.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 8, r.signed_state.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 9, r.signer.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt.get(), 10, r.is_kernel ? 1 : 0);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_module_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_module_events COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::insert_netqual_samples(const std::vector<NetQualRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    // <= top-N connections per tick (collector cap) — one transaction per tick.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO netqual_live
            (ts, snapshot_id, proto, remote_bucket, process_name,
             rtt_us, rtt_var_us, lost, retrans, segs_out, ca_state)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.proto.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, r.remote_bucket.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, r.process_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 6, r.rtt_us);
        sqlite3_bind_int64(stmt.get(), 7, r.rtt_var_us);
        sqlite3_bind_int64(stmt.get(), 8, r.lost);
        sqlite3_bind_int64(stmt.get(), 9, r.retrans);
        sqlite3_bind_int64(stmt.get(), 10, r.segs_out);
        sqlite3_bind_int64(stmt.get(), 11, r.ca_state);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_netqual_samples step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::insert_netconn_events(const std::vector<NetConnRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netconn_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO netconn_live
            (ts, snapshot_id, action, channel, category, capability,
             iface_kind, reason_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_netconn_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.action.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, r.channel.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, r.category.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 6, r.capability.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 7, r.iface_kind.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 8, r.reason_code);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_netconn_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netconn_events COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::insert_netqual_boot_row(const NetQualBootRow& row) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    // One row per boot — a single autocommit INSERT, no transaction needed.
    const char* sql = R"(
        INSERT INTO netqual_boot
            (ts, snapshot_id, boot_ts, window_s, retrans_segs, segs_out,
             estab_resets, if_in_errors, if_in_discards, if_out_errors,
             if_out_discards, if_in_octets, if_out_octets)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_netqual_boot_row prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, row.ts);
    sqlite3_bind_int64(stmt.get(), 2, row.snapshot_id);
    sqlite3_bind_int64(stmt.get(), 3, row.boot_ts);
    sqlite3_bind_int64(stmt.get(), 4, row.window_s);
    sqlite3_bind_int64(stmt.get(), 5, row.retrans_segs);
    sqlite3_bind_int64(stmt.get(), 6, row.segs_out);
    sqlite3_bind_int64(stmt.get(), 7, row.estab_resets);
    sqlite3_bind_int64(stmt.get(), 8, row.if_in_errors);
    sqlite3_bind_int64(stmt.get(), 9, row.if_in_discards);
    sqlite3_bind_int64(stmt.get(), 10, row.if_out_errors);
    sqlite3_bind_int64(stmt.get(), 11, row.if_out_discards);
    sqlite3_bind_int64(stmt.get(), 12, row.if_in_octets);
    sqlite3_bind_int64(stmt.get(), 13, row.if_out_octets);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        spdlog::error("insert_netqual_boot_row step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

// ── Generic SQL execution ───────────────────────────────────────────────────

std::expected<QueryResult, std::string> TarDatabase::execute_query(const std::string& sql,
                                                                   int max_rows) {
    std::lock_guard lock(mu_);
    QueryResult result;
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        auto err = std::string(sqlite3_errmsg(db_));
        spdlog::error("execute_query prepare: {}", err);
        return std::unexpected(std::format("query failed: {}", err));
    }
    StmtPtr stmt(raw_stmt);

    // Extract column names
    int col_count = sqlite3_column_count(stmt.get());
    result.columns.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        auto name = sqlite3_column_name(stmt.get(), i);
        result.columns.emplace_back(name ? name : "");
    }

    // Step through rows with enforced row limit (H1: prevent DoS via cross-joins)
    int row_count = 0;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (++row_count > max_rows) {
            spdlog::warn("execute_query: row limit ({}) exceeded, truncating", max_rows);
            break;
        }
        QueryRow row;
        row.reserve(col_count);
        for (int i = 0; i < col_count; ++i) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), i));
            row.emplace_back(text ? text : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

std::expected<QueryResult, std::string> TarDatabase::execute_user_query(const std::string& sql,
                                                                        int max_rows) {
    std::lock_guard lock(query_mu_);
    QueryResult result;
    if (!query_db_)
        return std::unexpected("query engine unavailable");

    sqlite3_stmt* raw_stmt = nullptr;
    const char* tail = nullptr;
    // Pass the explicit byte length (not -1): with -1 SQLite stops at the first
    // embedded NUL, which would let the executed query differ from the validated
    // one (the #631 class). An explicit length makes an embedded NUL a tokenizer
    // error instead.
    int rc = sqlite3_prepare_v2(query_db_, sql.c_str(), static_cast<int>(sql.size()), &raw_stmt,
                                &tail);
    if (rc != SQLITE_OK) {
        // Authorizer denials surface as SQLITE_AUTH; keep the reason generic so
        // a probe can't use the message to enumerate tables or columns.
        if (rc == SQLITE_AUTH)
            return std::unexpected("query rejected: operation or table not permitted");
        auto err = std::string(sqlite3_errmsg(query_db_));
        spdlog::warn("execute_user_query prepare failed: {}", err);
        return std::unexpected(std::format("query failed: {}", err));
    }
    StmtPtr stmt(raw_stmt);

    // Engine-level single-statement enforcement: prepare_v2 compiles only the
    // first statement and points `tail` at the remainder — reject any trailing
    // SQL (defence in depth alongside the validator's check).
    if (tail) {
        while (*tail && std::isspace(static_cast<unsigned char>(*tail)))
            ++tail;
        if (*tail)
            return std::unexpected("only single-statement queries are allowed");
    }

    int col_count = sqlite3_column_count(stmt.get());
    result.columns.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        auto name = sqlite3_column_name(stmt.get(), i);
        result.columns.emplace_back(name ? name : "");
    }

    int row_count = 0;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (++row_count > max_rows) {
            spdlog::warn("execute_user_query: row limit ({}) exceeded, truncating", max_rows);
            break;
        }
        QueryRow row;
        row.reserve(col_count);
        for (int i = 0; i < col_count; ++i) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), i));
            row.emplace_back(text ? text : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

bool TarDatabase::execute_sql(const std::string& sql) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

TarDatabase::BatchResult
TarDatabase::execute_atomic_batch(const std::vector<std::string>& statements) {
    BatchResult out;
    out.failed.assign(statements.size(), 0);
    if (statements.empty())
        return out;

    std::lock_guard lock(mu_);
    if (!db_) {
        out.failed.assign(statements.size(), 1);
        return out;
    }

    SqliteErrMsg err;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, err.addr()) != SQLITE_OK) {
        spdlog::error("TarDatabase::execute_atomic_batch BEGIN failed: {}", err.text());
        out.failed.assign(statements.size(), 1);
        return out; // no transaction was opened, so nothing to roll back
    }
    out.began = true;

    bool ok = true;
    for (std::size_t i = 0; i < statements.size(); ++i) {
        const int rc = sqlite3_exec(db_, statements[i].c_str(), nullptr, nullptr, err.addr());
        if (rc == SQLITE_OK)
            continue;

        // ASK whether SQLite aborted the transaction; do not assume it did.
        //
        // This used to `break` unconditionally, on the reasoning that continuing
        // risks autocommits past an auto-rollback. That is true only of errors
        // that abort the transaction THEMSELVES (SQLITE_FULL, a RAISE(ROLLBACK)
        // trigger). A plain SQLITE_ERROR -- a missing column after a partial
        // DDL, a corrupt index on ONE table -- leaves the transaction perfectly
        // intact, and breaking there rolled the whole pass back.
        //
        // That turned one permanently-broken table into permanently-broken
        // retention for EVERY table: each pass rolled back, nothing was ever
        // deleted, and tar.db grew without bound on the endpoint behind a single
        // warn line. Before this batch existed each statement ran independently
        // and the COMMIT kept the successes, so this was a regression, and a
        // silent one (governance Gate 3, cpp-expert).
        //
        // `sqlite3_get_autocommit` is the same question the ROLLBACK path below
        // already asks, for the same reason.
        //
        // But autocommit ALONE is not sufficient, and reading it alone was a
        // defect in the first version of this fix (Gate 7 security re-review).
        // Some conditions leave the transaction technically intact while making
        // it wrong to continue: SQLITE_CORRUPT/NOTADB would COMMIT onto a
        // damaged database -- against the fail-closed-and-quarantine posture
        // this store takes everywhere else (#559) -- and SQLITE_BUSY/LOCKED
        // would pay the 5s busy_timeout PER TABLE while holding `mu_`, stalling
        // every collector, where the old unconditional break paid it once.
        // NOMEM/IOERR/FULL are likewise whole-database conditions, not a
        // property of one table.
        //
        // So continue ONLY for the narrow per-table faults this exists for: a
        // plain error or a constraint violation, with the transaction intact.
        const bool per_table_fault = (rc == SQLITE_ERROR || rc == SQLITE_CONSTRAINT);
        const bool txn_aborted = sqlite3_get_autocommit(db_) != 0 || !per_table_fault;
        spdlog::error("TarDatabase::execute_atomic_batch statement failed: {} (rc={}, {})",
                      err.text(), rc,
                      txn_aborted ? "abandoning the pass"
                                  : "transaction intact and the fault is per-table, "
                                    "skipping this table only");
        if (txn_aborted) {
            ok = false;
            break;
        }
        // Transaction still good: fail THIS statement, keep the rest of the pass.
        out.failed[i] = 1;
    }

    if (ok) {
        if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, err.addr()) == SQLITE_OK) {
            // Any per-statement failures recorded above survive in out.failed:
            // the transaction committed, so the statements that DID run are
            // durable and only the skipped ones are reported failed.
            out.committed = true;
            return out;
        }
        spdlog::error("TarDatabase::execute_atomic_batch COMMIT failed: {}", err.text());
    }

    // Rolled back as a whole, so every statement is reported failed.
    const int rb = sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, err.addr());
    if (rb != SQLITE_OK) {
        // A ROLLBACK error USUALLY means SQLite already rolled back on its own,
        // which is the state we wanted. But it can also mean the rollback itself
        // failed with the transaction still open -- and returning then would
        // release mu_ with the connection still inside a transaction, so the
        // NEXT writer's INSERT would silently join it and be lost, which is
        // precisely the defect this whole method exists to prevent. Do not
        // assume; ask.
        if (sqlite3_get_autocommit(db_) == 0) {
            // The connection is genuinely stuck inside a transaction that will
            // never commit. Every subsequent write on it -- a collector INSERT,
            // a set_config, anything -- would join that transaction, be told it
            // succeeded, and be lost at the next restart. Collection is not
            // "still working" in that state; it is silently failing.
            //
            // So close the connection rather than flagging it. An earlier
            // version set a `txn_wedged_` bool that ONLY this method consulted,
            // which left ~118 other statement sites writing into the doomed
            // transaction while the comment claimed writes were protected -- a
            // guard covering one path out of 119 reads as handled and is worse
            // than none. Nulling `db_` reuses the `if (!db_)` check every
            // TarDatabase method already has, so all of them fail closed at once.
            //
            // close_v2 rather than close: it detaches immediately and defers
            // deallocation until any outstanding statements finalize, so this is
            // safe even though callers elsewhere may still hold prepared
            // statements. We hold `mu_`, and every primary-connection method
            // takes `mu_`, so no other thread is mid-statement here.
            spdlog::error("TarDatabase: ROLLBACK failed and the connection is STILL in a "
                          "transaction ({}). Closing the TAR database: further writes would be "
                          "reported as durable and then lost. TAR storage is offline on this "
                          "endpoint until the agent restarts.",
                          err.text());
            sqlite3_close_v2(db_);
            db_ = nullptr;
        } else {
            spdlog::debug("TarDatabase::execute_atomic_batch ROLLBACK: {}", err.text());
        }
    }
    out.failed.assign(statements.size(), 1);
    return out;
}

bool TransactionHandle::exec(const std::string& sql) {
    if (poisoned_)
        return false; // already aborted or failed -- do not autocommit past it

    SqliteErrMsg err;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, err.addr()) == SQLITE_OK)
        return true;

    fail(err.text());
    return false;
}

void TransactionHandle::fail(std::string reason) {
    if (!poisoned_) // first failure wins -- see the class doc for why this is load-bearing
        error_ = std::move(reason);
    poisoned_ = true;
}

std::expected<void, std::string> TarDatabase::checked_transaction(
    const std::function<std::expected<void, std::string>(TransactionHandle&)>& operation) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("database not open");

    SqliteErrMsg err;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, err.addr()) != SQLITE_OK) {
        spdlog::error("TarDatabase::checked_transaction BEGIN failed: {}", err.text());
        return std::unexpected(std::string("BEGIN failed: ") + err.text());
        // No transaction was opened, so nothing to roll back.
    }

    TransactionHandle handle(db_);
    std::expected<void, std::string> op_result;
    try {
        op_result = operation(handle);
    } catch (const std::exception& e) {
        handle.fail(std::string("exception: ") + e.what());
    } catch (...) {
        handle.fail("unknown exception");
    }

    // Poisoned wins regardless of what `operation` returned -- a callback
    // that ignores one intermediate `raw()` failure and returns success
    // anyway must not be able to erase that failure. See TransactionHandle's
    // doc comment.
    const bool ok = op_result.has_value() && !handle.poisoned();
    // Poisoned takes precedence when both fired: it is the more specific
    // diagnostic (a real SQLite error) over the callback's own postcondition
    // text, and is the only one of the two that can fire alongside a
    // has_value() op_result (the "ignored intermediate failure" case).
    std::string failure_reason;
    if (!ok)
        failure_reason = handle.poisoned() ? handle.error() : op_result.error();

    if (ok) {
        if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, err.addr()) == SQLITE_OK)
            return {};
        spdlog::error("TarDatabase::checked_transaction COMMIT failed: {}", err.text());
        failure_reason = std::string("COMMIT failed: ") + err.text();
    }

    // Rolled back (or never should have been committed) -- same wedge
    // handling as execute_atomic_batch: ask sqlite3_get_autocommit rather
    // than assume, because a ROLLBACK failure can mean SQLite already rolled
    // back on its own OR that the connection is genuinely stuck inside a
    // transaction that will never commit. See that method's doc comment for
    // the full reasoning; this is the identical pattern, reused rather than
    // reinvented.
    const int rb = sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, err.addr());
    if (rb != SQLITE_OK && sqlite3_get_autocommit(db_) == 0) {
        spdlog::error("TarDatabase: checked_transaction ROLLBACK failed and the connection is "
                      "STILL in a transaction ({}). Closing the TAR database: further writes "
                      "would be reported as durable and then lost. TAR storage is offline on "
                      "this endpoint until the agent restarts.",
                      err.text());
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
    return std::unexpected(failure_reason);
}

bool TarDatabase::execute_sql_range(const std::string& sql, int64_t from, int64_t to) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql_range prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    // Bind all ? placeholders as repeating (from, to) pairs.
    // CONTRACT: All rollup SQL must use ? in (from, to) pairs with identical semantics.
    int param_count = sqlite3_bind_parameter_count(stmt.get());
    if (param_count % 2 != 0) {
        spdlog::error("execute_sql_range: odd parameter count {} — expected (from,to) pairs",
                      param_count);
        return false;
    }
    for (int i = 1; i <= param_count; i += 2) {
        sqlite3_bind_int64(stmt.get(), i, from);
        sqlite3_bind_int64(stmt.get(), i + 1, to);
    }

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        spdlog::error("execute_sql_range step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

} // namespace yuzu::tar
