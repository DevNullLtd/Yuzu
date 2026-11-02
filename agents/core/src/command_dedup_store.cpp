/**
 * command_dedup_store.cpp -- see command_dedup_store.hpp
 *
 * SQLite idioms (open flags, WAL, busy_timeout, StmtPtr RAII, the RETURNING
 * drain-to-DONE durability check) mirror kv_store.cpp deliberately — the two
 * stores share the agent's SQLite conventions. This store additionally sets
 * synchronous=FULL (host-failure durability) and prunes over terminal rows only.
 */

#include <yuzu/agent/command_dedup_store.hpp>

#include "command_dedup_quarantine.hpp"

#include <sqlite3.h>

#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

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
//
// `rc_out` (optional) receives the first non-OK/ROW result code, so the caller can tell a
// corruption-class failure (SQLITE_NOTADB / SQLITE_CORRUPT, #3665) from a plain unusable
// read. Left SQLITE_OK when the read succeeded.
std::string query_pragma(sqlite3* db, const char* pragma_sql, int* rc_out = nullptr) {
    if (rc_out)
        *rc_out = SQLITE_OK;
    sqlite3_stmt* raw = nullptr;
    if (int prc = sqlite3_prepare_v2(db, pragma_sql, -1, &raw, nullptr); prc != SQLITE_OK) {
        if (rc_out)
            *rc_out = prc;
        return {};
    }
    StmtPtr stmt(raw);
    if (int src = sqlite3_step(stmt.get()); src != SQLITE_ROW) {
        if (rc_out && src != SQLITE_DONE)
            *rc_out = src;
        return {};
    }
    const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    std::string v = txt ? txt : "";
    for (auto& c : v)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return v;
}

// Persisted state values. Stored as INTEGER, never the enum's ABI value.
constexpr int kStateInFlight = 0;
constexpr int kStateTerminal = 1;

// ---- Corruption recovery (#3665) -------------------------------------------------------
//
// command_dedup.db is a regenerable safety net: a file that cannot be opened protects nothing,
// and staying degraded forever (fail-open on every boot) is strictly worse than starting a fresh
// one. So a CORRUPTION-class OPEN failure moves the file aside and recreates it, as echo.db does
// (#559; the filesystem half is command_dedup_quarantine.hpp).
//
// "Cannot be opened" means: SQLITE_CORRUPT / SQLITE_NOTADB from sqlite3_open_v2, the
// journal_mode/synchronous pragmas, or creating the two tables. Damage confined to the unused
// `meta` table is tolerated (see the schema_version seed below).
//
// Deliberately STRICTER than echo's integrity_ok(), in two ways:
//  1. Only SQLITE_CORRUPT / SQLITE_NOTADB counts. BUSY / LOCKED / IOERR / FULL / CANTOPEN / PERM are
//     transient or environmental; quarantining on them would discard good history, which lets an
//     already-run command re-execute (the outcome invariants 4 and 5 forbid).
//  2. There is NO whole-file integrity scan (no PRAGMA quick_check / integrity_check). A file that
//     OPENS but has a few damaged pages is still mostly usable: in one experiment with a single
//     damaged leaf page nearly every id still resolved (damage to an interior or root page costs
//     many more), and only the claims that touch a bad page fail open (counted by
//     yuzu_agent_dedup_claim_errors_total). Quarantining it on an integrity scan would discard ALL
//     history, including in-flight claims, which is worse than the damage (owner ruling, #3665).
//     Do not add such a scan without re-opening that ruling.

// True for SQLITE_CORRUPT / SQLITE_NOTADB, including extended codes (SQLITE_CORRUPT_VTAB etc).
bool is_corruption_rc(int rc) noexcept {
    const int primary = rc & 0xFF;
    return primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB;
}

struct OpenFailure {
    std::string message;
    bool corrupt = false; ///< corruption-class: the caller may quarantine and retry ONCE
};

} // namespace

CommandDedupStore::CommandDedupStore(sqlite3* db) : db_{db} {}

CommandDedupStore::~CommandDedupStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

CommandDedupStore::CommandDedupStore(CommandDedupStore&& other) noexcept
    : db_{other.db_}, quarantined_file_{std::move(other.quarantined_file_)} {
    other.db_ = nullptr;
    other.quarantined_file_.reset();
}

CommandDedupStore& CommandDedupStore::operator=(CommandDedupStore&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        quarantined_file_ = std::move(other.quarantined_file_);
        other.db_ = nullptr;
        other.quarantined_file_.reset();
    }
    return *this;
}

namespace {

// One open-and-initialise attempt. On failure `corrupt` says whether the cause was
// corruption-class (the caller may quarantine and retry ONCE) or anything else (plain error,
// the file is left exactly as found). Does not create the parent directory.
std::expected<DbGuard, OpenFailure> open_and_init(const std::filesystem::path& db_path) {
    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(db_path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    // open_v2 may hand back a handle even on failure, and DbCloser is null-safe, so the guard owns
    // it from the first moment: no manual close on any path below.
    DbGuard db_guard(raw_db);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        return std::unexpected(OpenFailure{
            std::format("failed to open command_dedup.db: {}", err), is_corruption_rc(rc)});
    }

    // WAL + synchronous=FULL are load-bearing durability guarantees (invariant 6),
    // so SET then READ BACK: a *refused* pragma returns SQLITE_OK with the actual
    // mode in the result row, so a mismatch (WAL not "wal", synchronous not "2"=
    // FULL) means the guarantee is silently void — treat that as an open failure,
    // which takes the caller's observable fail-open path (degraded, not silent).
    // The rc of each step is kept (#3665) ONLY to classify corruption: a non-database
    // file reports SQLITE_NOTADB here, not at open_v2.
    int pragma_rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    int read_rc = SQLITE_OK;
    auto jm = query_pragma(raw_db, "PRAGMA journal_mode", &read_rc);
    if (jm != "wal") {
        return std::unexpected(OpenFailure{
            std::format("journal_mode=WAL not in effect (got '{}')", jm),
            is_corruption_rc(pragma_rc) || is_corruption_rc(read_rc)});
    }
    // fsync every commit so a claim/terminal record survives a HOST power-loss,
    // not just a process crash. One write per command (not a hot path).
    pragma_rc = sqlite3_exec(raw_db, "PRAGMA synchronous=FULL", nullptr, nullptr, nullptr);
    auto sy = query_pragma(raw_db, "PRAGMA synchronous", &read_rc);
    if (sy != "2") {
        return std::unexpected(OpenFailure{
            std::format("synchronous=FULL not in effect (got '{}')", sy),
            is_corruption_rc(pragma_rc) || is_corruption_rc(read_rc)});
    }
    sqlite3_busy_timeout(raw_db, 5000);

    // Schema. `command_id` is the PRIMARY KEY so claim() can lean on ON CONFLICT
    // DO NOTHING for its atomic first-writer-wins check. `response` is a BLOB —
    // it holds a serialized protobuf (embedded NULs must survive). `claimed_at`
    // is DIAGNOSTIC ONLY: retention is a clock-free rowid ring (prune_locked),
    // so this column must NEVER become a wall-clock retention cutoff (that would
    // reintroduce the clock-guarded-retention hazard on a user-controlled clock).
    // A `meta` table carries schema_version for a future migration ladder (the
    // agent has no shared MigrationRunner; this mirrors echo_db's config-row
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
    )";
    rc = sqlite3_exec(raw_db, create_sql, nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        return std::unexpected(OpenFailure{
            std::format("failed to create command_dedup schema: {}", sqlite3_errmsg(raw_db)),
            is_corruption_rc(rc)});
    }
    // The schema_version seed is NOT part of "can this file be opened": nothing reads `meta` yet,
    // and the INSERT probes the meta table's own b-tree pages, which command_outcomes never uses.
    // Damage confined to them must not make a file whose command table is intact get quarantined
    // (that would discard its in-flight claims, invariants 4 and 5; owner ruling, #3665). So a
    // failure here is a warning, whatever its cause, and never `corrupt`.
    rc = sqlite3_exec(raw_db,
                      "INSERT INTO meta(key, value) VALUES('schema_version', '1') "
                      "ON CONFLICT(key) DO NOTHING",
                      nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::warn("CommandDedupStore: could not seed meta.schema_version ({}); continuing — "
                     "nothing reads it yet",
                     sqlite3_errmsg(raw_db));
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

    return db_guard;
}

} // namespace

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

    auto attempt = open_and_init(db_path);
    std::optional<std::string> quarantined_file;
    if (!attempt && attempt.error().corrupt) {
        // #3665: corruption-class failure. Exactly ONE quarantine + ONE retry — never a loop, so
        // a disk that corrupts every fresh file degrades (observably) instead of spinning. The
        // failed attempt's handle is already closed (DbGuard) before the rename.
        const std::string reason = attempt.error().message;
        auto moved =
            dedup_quarantine::quarantine_corrupt_db(db_path, now_epoch_seconds());
        if (!moved) {
            // Fail-open, observable (invariant 7): the original file is untouched.
            return std::unexpected(CommandDedupError{
                std::format("command_dedup.db is corrupt ({}) and could not be quarantined: {}",
                            reason, db_path.string())});
        }
        spdlog::error("CommandDedupStore: command_dedup.db is corrupt ({}) — quarantined to {} "
                      "and re-initialising a fresh store",
                      reason, moved->string());
        quarantined_file = moved->filename().string();
        attempt = open_and_init(db_path);
        if (attempt) {
            // Owner ruling: keep the newest few only. Never throws (best effort).
            dedup_quarantine::prune_old_quarantines(db_path, *moved);
        }
    }
    if (!attempt) {
        return std::unexpected(CommandDedupError{
            quarantined_file
                ? std::format("command_dedup.db re-initialised after quarantine still failed: {}",
                              attempt.error().message)
                : attempt.error().message});
    }

    spdlog::info("CommandDedupStore opened: {}", db_path.string());
    CommandDedupStore store{attempt->release()};
    store.quarantined_file_ = std::move(quarantined_file);
    return store;
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
