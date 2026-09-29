/**
 * command_dedup_store.cpp -- see command_dedup_store.hpp
 *
 * SQLite idioms (open flags, WAL, busy_timeout, StmtPtr RAII, the RETURNING
 * drain-to-DONE durability check) mirror kv_store.cpp deliberately — the two
 * stores share the agent's SQLite conventions. This store additionally sets
 * synchronous=FULL (host-failure durability) and prunes over terminal rows only.
 */

#include <yuzu/agent/command_dedup_store.hpp>

#include <sqlite3.h>

#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <format>

namespace yuzu::agent {

namespace {

std::int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

// RAII for the interim raw connection during open(): manual sqlite3_close on
// every early-return error path is exactly the "undocumented manual cleanup in
// new code" cpp-conventions flags, so the handle is owned by a guard and only
// released to the store on success.
struct DbCloser {
    void operator()(sqlite3* d) const {
        if (d)
            sqlite3_close(d);
    }
};
using DbGuard = std::unique_ptr<sqlite3, DbCloser>;

// Read a single-value PRAGMA back as lower-cased text. A REFUSED durability
// pragma (e.g. journal_mode=WAL on a filesystem that cannot support it) is
// reported by SQLite as SQLITE_OK with the *actual* mode in the result row, so
// setting a pragma is not proof it took — invariant (6) requires reading it back.
std::string query_pragma(sqlite3* db, const char* pragma_sql) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, pragma_sql, -1, &raw, nullptr) != SQLITE_OK)
        return {};
    StmtPtr stmt(raw);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return {};
    const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    std::string v = txt ? txt : "";
    for (auto& c : v)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return v;
}

// Persisted state values. Stored as INTEGER, never the enum's ABI value.
constexpr int kStateInFlight = 0;
constexpr int kStateTerminal = 1;

} // namespace

CommandDedupStore::CommandDedupStore(sqlite3* db) : db_{db} {}

CommandDedupStore::~CommandDedupStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

CommandDedupStore::CommandDedupStore(CommandDedupStore&& other) noexcept : db_{other.db_} {
    other.db_ = nullptr;
}

CommandDedupStore& CommandDedupStore::operator=(CommandDedupStore&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

std::expected<CommandDedupStore, CommandDedupError>
CommandDedupStore::open(const std::filesystem::path& db_path) {
    std::error_code ec;
    auto parent = db_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(CommandDedupError{
                std::format("failed to create directory {}: {}", parent.string(), ec.message())});
        }
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(db_path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db); // open_v2 may hand back a handle even on failure
        return std::unexpected(
            CommandDedupError{std::format("failed to open command_dedup.db: {}", err)});
    }
    DbGuard db_guard(raw_db); // owns the handle across every early return below

    // WAL + synchronous=FULL are load-bearing durability guarantees (invariant 6),
    // so SET then READ BACK: a *refused* pragma returns SQLITE_OK with the actual
    // mode in the result row, so a mismatch (WAL not "wal", synchronous not "2"=
    // FULL) means the guarantee is silently void — treat that as an open failure,
    // which takes the caller's observable fail-open path (degraded, not silent).
    sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    if (auto jm = query_pragma(raw_db, "PRAGMA journal_mode"); jm != "wal") {
        return std::unexpected(CommandDedupError{
            std::format("journal_mode=WAL not in effect (got '{}')", jm)});
    }
    // fsync every commit so a claim/terminal record survives a HOST power-loss,
    // not just a process crash. One write per command (not a hot path).
    sqlite3_exec(raw_db, "PRAGMA synchronous=FULL", nullptr, nullptr, nullptr);
    if (auto sy = query_pragma(raw_db, "PRAGMA synchronous"); sy != "2") {
        return std::unexpected(CommandDedupError{
            std::format("synchronous=FULL not in effect (got '{}')", sy)});
    }
    sqlite3_busy_timeout(raw_db, 5000);

    // Schema. `command_id` is the PRIMARY KEY so claim() can lean on ON CONFLICT
    // DO NOTHING for its atomic first-writer-wins check. `response` is a BLOB —
    // it holds a serialized protobuf (embedded NULs must survive). `claimed_at`
    // is DIAGNOSTIC ONLY: retention is a clock-free rowid ring (prune_locked),
    // so this column must NEVER become a wall-clock retention cutoff (that would
    // reintroduce the clock-guarded-retention hazard on a user-controlled clock).
    // A `meta` table carries schema_version for a future migration ladder (the
    // agent has no shared MigrationRunner; this mirrors tar_db's config-row
    // precedent).
    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS command_outcomes (
            command_id TEXT PRIMARY KEY,
            state      INTEGER NOT NULL,
            response   BLOB,
            claimed_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO meta(key, value) VALUES('schema_version', '1')
            ON CONFLICT(key) DO NOTHING;
    )";
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        return std::unexpected(
            CommandDedupError{std::format("failed to create command_dedup schema: {}", err)});
    }

    // Owner-only (0600), matching the security-hardening.md "chmod 600 *.db" rule
    // and the agent's cert-key posture. Best-effort per file: -wal/-shm may not
    // exist yet, and a chmod failure must not fail an otherwise-healthy open.
    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    for (const auto& suffix : {"", "-wal", "-shm"}) {
        std::error_code pec;
        std::filesystem::permissions(db_path.string() + suffix, owner_only,
                                     std::filesystem::perm_options::replace, pec);
    }

    spdlog::info("CommandDedupStore opened: {}", db_path.string());
    return CommandDedupStore{db_guard.release()};
}

ClaimResult CommandDedupStore::claim(std::string_view command_id) noexcept {
    if (command_id.empty())
        return ClaimResult{.status = ClaimStatus::Error};
    std::lock_guard lock(mu_);
    if (!db_)
        return ClaimResult{.status = ClaimStatus::Error};

    // Atomic first-writer-wins claim. A RETURNING row means WE inserted the
    // in-flight record; no row (DO NOTHING) means a prior claim already owns it.
    const char* insert_sql = R"(
        INSERT INTO command_outcomes (command_id, state, response, claimed_at)
        VALUES (?, ?, NULL, ?)
        ON CONFLICT(command_id) DO NOTHING
        RETURNING 1
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, insert_sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::claim prepare failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt.get(), 2, kStateInFlight);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // RETURNING row: inserted. Drain to DONE so a commit/WAL-fsync failure
        // (SQLITE_FULL / SQLITE_IOERR) surfaces as Error rather than a false
        // Claimed that would let a not-yet-durable claim proceed — matching
        // KvStore::insert_if_absent's durability contract.
        rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            spdlog::error("CommandDedupStore::claim commit failed: {}", sqlite3_errmsg(db_));
            return ClaimResult{.status = ClaimStatus::Error};
        }
        // NB: prune is NOT triggered here — it runs from record_terminal() (a
        // worker thread), off the latency-critical reader, since the ring evicts
        // terminal rows.
        return ClaimResult{.status = ClaimStatus::Claimed};
    }
    if (rc != SQLITE_DONE) {
        spdlog::error("CommandDedupStore::claim step failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }

    // Conflict: the id is already known. Read the existing record's state (+ the
    // terminal response, if any) so the caller can replay or answer RUNNING.
    const char* select_sql = "SELECT state, response FROM command_outcomes WHERE command_id = ?";
    sqlite3_stmt* raw_sel = nullptr;
    rc = sqlite3_prepare_v2(db_, select_sql, -1, &raw_sel, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::claim select prepare failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }
    StmtPtr sel(raw_sel);
    sqlite3_bind_text(sel.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    rc = sqlite3_step(sel.get());
    if (rc == SQLITE_ROW) {
        const int state = sqlite3_column_int(sel.get(), 0);
        if (state == kStateTerminal) {
            const auto* blob = static_cast<const char*>(sqlite3_column_blob(sel.get(), 1));
            const int bytes = sqlite3_column_bytes(sel.get(), 1);
            // The blob copy is the one unbounded allocation on this path; keep the
            // noexcept boundary honest — an OOM here degrades to "proceed without
            // dedup" (Error), it never std::terminate()s the agent.
            try {
                return ClaimResult{
                    .status = ClaimStatus::Duplicate,
                    .state = DedupState::Terminal,
                    .response = blob ? std::string(blob, static_cast<std::size_t>(bytes))
                                     : std::string{},
                };
            } catch (...) {
                spdlog::error("CommandDedupStore::claim: allocation failed copying stored "
                              "response for {}",
                              command_id);
                return ClaimResult{.status = ClaimStatus::Error};
            }
        }
        return ClaimResult{.status = ClaimStatus::Duplicate, .state = DedupState::InFlight};
    }
    if (rc == SQLITE_DONE) {
        // The row vanished between the failed insert and this select (a
        // concurrent prune of a just-evicted TERMINAL row is the only way, and it
        // cannot hit the in-flight row this claim would have inserted). Treat as
        // "proceed without dedup" rather than fabricate a state.
        spdlog::warn("CommandDedupStore::claim: conflicting row for {} not found on re-read",
                     command_id);
        return ClaimResult{.status = ClaimStatus::Error};
    }
    spdlog::error("CommandDedupStore::claim select step failed: {}", sqlite3_errmsg(db_));
    return ClaimResult{.status = ClaimStatus::Error};
}

RecordOutcome CommandDedupStore::record_terminal(std::string_view command_id,
                                                 std::string_view serialized_response) noexcept {
    if (command_id.empty())
        return RecordOutcome::Miss;
    std::lock_guard lock(mu_);
    if (!db_)
        return RecordOutcome::Error;

    // FIRST-WRITE-WINS: flip an IN-FLIGHT row to terminal only. A second terminal
    // (a spurious post-terminal throw) or a record against an evicted/never-
    // claimed id matches no in-flight row → RETURNING yields nothing → Miss. A
    // Miss on a command that WAS claimed is the signal a redelivery could
    // re-execute; the caller counts it. RETURNING (not sqlite3_changes) keeps the
    // rows-affected read #1033-safe on the shared FULLMUTEX connection.
    const char* sql = R"(
        UPDATE command_outcomes SET state = ?, response = ?
        WHERE command_id = ? AND state = ?
        RETURNING 1
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::record_terminal prepare failed: {}", sqlite3_errmsg(db_));
        return RecordOutcome::Error;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_int(stmt.get(), 1, kStateTerminal);
    sqlite3_bind_blob(stmt.get(), 2, serialized_response.data(),
                      static_cast<int>(serialized_response.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt.get(), 4, kStateInFlight);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // Drain to DONE so the WAL-fsync commit failure surfaces as Error.
        rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            spdlog::error("CommandDedupStore::record_terminal commit failed: {}",
                          sqlite3_errmsg(db_));
            return RecordOutcome::Error;
        }
        // A new terminal row was created — amortised prune of the terminal ring,
        // on this (worker) thread, keeping the reader off the DELETE.
        if (++records_since_prune_ >= kPruneInterval) {
            prune_locked();
            records_since_prune_ = 0;
        }
        return RecordOutcome::Recorded;
    }
    if (rc == SQLITE_DONE)
        return RecordOutcome::Miss; // no in-flight row matched (evicted / never claimed / already terminal)
    spdlog::error("CommandDedupStore::record_terminal step failed: {}", sqlite3_errmsg(db_));
    return RecordOutcome::Error;
}

ReleaseOutcome CommandDedupStore::release(std::string_view command_id) noexcept {
    if (command_id.empty())
        return ReleaseOutcome::Released; // nothing to leak
    std::lock_guard lock(mu_);
    if (!db_)
        return ReleaseOutcome::Released; // no store: the caller never claimed here

    // Only an in-flight row is releasable — never delete a terminal outcome (a
    // concurrent worker may have just recorded one for a redelivery).
    const char* sql = "DELETE FROM command_outcomes WHERE command_id = ? AND state = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::release prepare failed for {}: {}", command_id,
                      sqlite3_errmsg(db_));
        return ReleaseOutcome::Error;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt.get(), 2, kStateInFlight);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        // The in-flight row was NOT deleted — the claim leaks: the command answers
        // RUNNING to every redelivery and never re-runs. The caller counts this.
        spdlog::error("CommandDedupStore::release failed for {} — claim may be leaked: {}",
                      command_id, sqlite3_errmsg(db_));
        return ReleaseOutcome::Error;
    }
    return ReleaseOutcome::Released;
}

void CommandDedupStore::prune_locked() noexcept {
    // Clock-free ring over TERMINAL rows ONLY: keep the newest kMaxDedupRows
    // terminal rows by rowid (monotonic with insert order), evict older terminal
    // rows. No wall clock is consulted, so the clock-guarded-retention hazard
    // does not apply. IN-FLIGHT rows are NEVER evicted here — a live command's
    // claim can never be pruned out from under its still-running worker (which
    // would silently permit a re-execution). A crashed in-flight row (response
    // NULL, tiny) persists until reinstall; bounding that is a follow-up.
    const char* sql = R"(
        DELETE FROM command_outcomes
        WHERE state = ?
          AND rowid NOT IN (
              SELECT rowid FROM command_outcomes WHERE state = ? ORDER BY rowid DESC LIMIT ?
          )
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::prune prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_int(stmt.get(), 1, kStateTerminal);
    sqlite3_bind_int(stmt.get(), 2, kStateTerminal);
    sqlite3_bind_int64(stmt.get(), 3, max_dedup_rows_);
    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE)
        spdlog::error("CommandDedupStore::prune step failed: {}", sqlite3_errmsg(db_));
}

void CommandDedupStore::set_max_dedup_rows_for_test(std::int64_t n) {
    std::lock_guard lock(mu_);
    max_dedup_rows_ = n < 1 ? 1 : n; // a non-positive LIMIT would delete everything
}

std::optional<std::int64_t> CommandDedupStore::count() const {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM command_outcomes", -1, &raw_stmt, nullptr) !=
        SQLITE_OK)
        return std::nullopt;
    StmtPtr stmt(raw_stmt);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return std::nullopt;
    return sqlite3_column_int64(stmt.get(), 0);
}

} // namespace yuzu::agent
