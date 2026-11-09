/**
 * echo_db.cpp -- SQLite-backed Echo activity record database
 *
 * Tables:
 *   echo_state(collector PRIMARY KEY, state_json, updated_at)
 *   echo_config(key PRIMARY KEY, value)
 *   plus every typed warehouse tier the schema registry declares.
 *
 * The legacy tar_events log was retired by schema v3 and is no longer created;
 * see kCreateSchema below.
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "echo_schema_registry.hpp"
#include "echo_usage.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp> // yuzu::log_key_token: a registry key/value name is attacker-chosen (CWE-117)
#include <sqlite_quarantine.hpp> // the one no-overwrite quarantine move (#6914), shared with command_dedup

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <expected>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
// windows.h first; aclapi.h/sddl.h follow it. Confined to this TU (the owner-only DACL block).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h> // SetSecurityInfo, GetSecurityInfo
#include <sddl.h>   // the SDDL -> security descriptor conversion, ConvertSidToStringSidW
#include <win_str.hpp>
#include <win_echo_db_owner_probe.hpp> // the owner / hard-link test app_usage shares
#endif

namespace yuzu::echo {

namespace {

// Busy timeout of the main and read-only connections; checkpoint() drops the main one to 0 for
// the call and restores it from here.
constexpr int kBusyTimeoutMs = 5000;

using yuzu::shared::sqlite_quarantine::now_epoch_seconds;

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

// RAII owner of the raw connection while open() builds it (#6698): every error return closes it,
// and only the success path hands it to the EchoDatabase (release()). Same shape as DbGuard in
// agents/core/src/command_dedup_store.cpp.
struct DbCloser {
    void operator()(sqlite3* d) const {
        if (d)
            sqlite3_close(d);
    }
};
using DbGuard = std::unique_ptr<sqlite3, DbCloser>;

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
int echo_query_authorizer(void* /*ctx*/, int action, const char* arg1, const char* arg2,
                         const char* /*db_name*/, const char* inner_trigger_or_view) noexcept {
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
            if (!arg1)
                return SQLITE_DENY;
            if (is_queryable_table(arg1) || is_fold_view(arg1))
                return SQLITE_OK;
            // The roll-up views read echo_dict and their `_r` tables; operator SQL may
            // reach those ONLY through a roll-up view, never by name. The inner-most
            // view argument names a SQL context, not a persisted view: a CTE of that
            // name is reported the same way. This rule is sound ONLY because
            // validate_and_translate_sql rejects WITH, so no CTE can shadow a view
            // name. It is defence in depth behind that validator, not the closure.
            if (inner_trigger_or_view && is_fold_internal_table(arg1) &&
                is_fold_view(inner_trigger_or_view))
                return SQLITE_OK;
            // `SELECT COUNT(*) FROM <view>` is reported as a column-less read of the table
            // behind the view with no view context. Allow that for the row tables only: it
            // exposes a row count the view already exposes, never a column. The dictionary
            // and the replay ring stay denied outright. Sound only while every roll-up view
            // is a WHERE-less single-table projection (generate_fold_ddl, pinned by test);
            // a filter or JOIN in a view turns this count into an oracle.
            if (is_fold_row_table(arg1) && (!arg2 || *arg2 == '\0'))
                return SQLITE_OK;
            return SQLITE_DENY;
        default:
            return SQLITE_DENY;
        }
    } catch (...) {
        return SQLITE_DENY;
    }
}

/// Schema DDL for all Echo tables.
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
    CREATE TABLE IF NOT EXISTS echo_state (
        collector   TEXT PRIMARY KEY,
        state_json  TEXT NOT NULL DEFAULT '{}',
        updated_at  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS echo_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );

    -- Cursor-model seam (echo_cursor.hpp): one row per cursor-model source
    -- ("power", "removable" — wave 2), holding its last-persisted opaque
    -- versioned cursor JSON. Beside echo_state rather than folded into it —
    -- echo_state's state_json is a snapshot-diff BASELINE (the previous full
    -- enumeration); a cursor is a LOG POSITION, a different shape with a
    -- different persistence contract (always written atomically with the
    -- events it produced — see insert_power_events_and_cursor /
    -- insert_removable_events_and_cursor).
    CREATE TABLE IF NOT EXISTS echo_cursor (
        source      TEXT PRIMARY KEY,
        cursor_json TEXT NOT NULL,
        updated_at  INTEGER NOT NULL DEFAULT 0
    );
)";

// #559 — self-test a freshly-opened echo.db with PRAGMA integrity_check. A
// corrupt file (filesystem damage, partial restore, mid-write crash) must NOT
// be silently trusted: get_config() returns the caller's default on a read
// failure, so a corrupt DB would read every `<source>_enabled` key as its
// "true" default and silently re-enable sources an operator deliberately paused
// for forensic preservation — defeating the #539 retention guard with no
// telemetry.
//
// Four answers (#7286). Only an EXPLICIT integrity failure quarantines: a non-"ok" integrity row,
// or SQLITE_CORRUPT / SQLITE_NOTADB (the sibling store's rule, command_dedup_store.cpp
// is_corruption_rc). A database another connection holds past the busy timeout is BUSY, and
// quarantining it would move a healthy file (and the paused-source state in it) out from under its
// holder. Every other failure to read the file (an I/O error, CANTOPEN, PERM, READONLY, FULL,
// PROTOCOL, NOMEM) says nothing about the file's health, so it is UNREADABLE: the caller refuses to
// open and quarantines nothing. Quarantine plus a fresh file is the fail-OPEN side here (a fresh
// file re-enables every source an operator paused, #559); refusing to open is the fail-closed side,
// and the next start retries. The rc classifier is `classify_integrity_rc` (echo_db.hpp).
struct IntegrityResult {
    IntegrityCheck verdict;
    int rc; ///< the sqlite rc behind a non-ok verdict (SQLITE_ROW for a non-"ok" integrity row)
};

IntegrityResult check_integrity(sqlite3* db) noexcept {
    sqlite3_stmt* raw = nullptr;
    const int prc = sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &raw, nullptr);
    StmtPtr stmt(raw);
    if (prc != SQLITE_OK)
        return {classify_integrity_rc(prc), prc};
    const int src = sqlite3_step(stmt.get());
    if (src == SQLITE_ROW) {
        const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        const bool ok = txt && std::string_view{txt} == "ok";
        return {ok ? IntegrityCheck::ok : IntegrityCheck::corrupt, src};
    }
    return {classify_integrity_rc(src), src};
}

// The integer in an echo_config `schema_version` value; an unparseable one reads as 0.
int parse_schema_version(const std::string& text) {
    try {
        return std::stoi(text);
    } catch (...) {
        return 0;
    }
}

// #1527 — refuse a symlink (every OS) or reparse point (Windows: a junction is not a symlink to
// std::filesystem on every toolchain) at echo.db or one of its sidecars. SQLite follows a link, so a
// local user who can plant one in the state directory would steer the agent's database writes (and
// the quarantine's moves) at a file of their choosing. Fail closed: nothing is opened, moved or
// secured. A path that is absent is fine (the open creates it). Returns the refusal text.
std::optional<std::string> refuse_linked_db_files(const std::filesystem::path& db) {
    namespace fs = std::filesystem;
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
        fs::path file = db;
        file += suffix;
#ifdef _WIN32
        const std::string name = yuzu::win::from_wide(file.c_str());
#else
        const std::string name = file.string();
#endif
        std::error_code ec;
        const auto st = fs::symlink_status(file, ec);
        if (st.type() == fs::file_type::not_found)
            continue;
        if (ec) {
            return std::format("cannot examine {} ({}); echo.db was not opened", name,
                               ec.message());
        }
        bool linked = fs::is_symlink(st);
#ifdef _WIN32
        if (!linked) {
            const DWORD attrs = ::GetFileAttributesW(file.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                const DWORD err = ::GetLastError();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                    continue;
                return std::format("cannot read the attributes of {} (error {}); echo.db was not "
                                   "opened",
                                   name, err);
            }
            linked = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        }
#endif
        if (linked) {
            return std::format("{} is a symbolic link or reparse point, and echo.db was not "
                               "opened: remove it so the agent can create a regular file, then "
                               "restart the agent",
                               name);
        }
    }
    return std::nullopt;
}

/// Execute a multi-statement DDL batch inside ONE transaction.
///
/// SQLite gives every bare statement its own implicit transaction, and WAL
/// defaults to `synchronous=FULL` — so handing `sqlite3_exec` a ~75-statement
/// schema batch costs ~75 separate commits, each with its own fsync. Measured
/// on the Windows CI runner (91 iterations, best of 3, #2093): 72.4 ms per
/// `EchoDatabase::open()` unwrapped against 11.0 ms for the identical DDL in a
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
        spdlog::warn("EchoDatabase: could not open a transaction for the schema batch ({}) — "
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
            spdlog::error("EchoDatabase: schema transaction could neither commit nor roll back — "
                          "this connection is wedged and its writes will be discarded. Restart "
                          "the agent.");
        }
    }
    return rc;
}

#ifdef _WIN32
// ── Windows: protected owner-only DACL on echo.db, echo.db-wal, -shm and -journal ─────────────
//
// The state directory inherits C:\ProgramData's ACL (Users: read), and echo.db now holds every
// capture source. The four files SQLite reads for this database get a PROTECTED DACL (SYSTEM,
// Administrators and the agent's account, FILE_ALL_ACCESS, no inheritance) -- the counterpart of
// the 0600 pass in open(), built from one SDDL string as agents/core temp_file.cpp and updater.cpp
// do (explicit SIDs, not the Owner Rights alias "OW": execution_artifacts_win.cpp stores that one
// literally). It runs before each sqlite3_open_v2 and once at the end of open():
//  - a missing file is CREATED here with the protected DACL (no inheritance window; SQLite
//    then creates nothing, and a 0-byte echo.db is a valid empty database);
//  - an existing file is re-secured in place (an upgraded echo.db on its first open);
//  - the end pass exists because, on a FRESH (0-page) database, SQLite deletes the pre-created
//    -wal and recreates it with the inherited ACL on the first write.
// -journal is on the list because SQLite replays a HOT rollback journal found beside the
// database BEFORE it looks at the WAL, as the agent: a journal planted by a local user would
// otherwise rewrite echo_config (the #559 class). An empty journal is inert, so the one created
// here is.
// A file owned by anyone but SYSTEM, Administrators or the agent account, or carrying more than
// one hard link, is PLANTED: a foreign WAL or journal is replayed into echo.db, a foreign echo.db is
// attacker-controlled config (#559 class), and a hard link shares its target's owner and
// security descriptor, so re-securing or WAL-initialising it would rewrite the OTHER name's
// target (the owner test cannot see that). A sidecar is therefore deleted and re-created and
// such an echo.db refuses the open. Only POSITIVE evidence refuses; a failed owner read
// (FAT/exFAT: no ACL), link-count query or DACL apply is logged and never fails the open. The
// tests are yuzu::win::EchoDbOwnerProbe's, shared with app_usage, which reads the same files.
// A file that denies us WRITE_DAC (its owner can do that to dodge the checks) is looked at
// through a READ_CONTROL-only handle and gets the same two tests; if it passes it keeps its
// ACL, logged. SQLite's own GENERIC_READ includes READ_CONTROL, so a file we cannot look at
// that way SQLite cannot open either. FILE_FLAG_OPEN_REPARSE_POINT examines a planted symlink
// as the link, never its target. Lock-out: a later run under a different non-admin account
// cannot open echo.db. An account switch is not undone by `icacls /reset` (it rewrites the DACL,
// never the owner): the open fails until the new account holds an ACE for the files (the open
// asks FILE_READ_ATTRIBUTES, which owning a file does not grant) and, when the former owner is
// neither SYSTEM nor Administrators, until it owns them too, since the owner test refuses them
// first. A former owner of SYSTEM or Administrators passes the owner test, so no owner is named:
// the log shows "could not open ... (error 5)", then "failed to open echo.db". Not yet verified
// on a Windows host.

using LocalPtr = std::unique_ptr<void, decltype(&::LocalFree)>;
using HandlePtr = std::unique_ptr<void, decltype(&::CloseHandle)>;

class EchoDbDacl {
public:
    EchoDbDacl() { build(); }
    EchoDbDacl(const EchoDbDacl&) = delete;
    EchoDbDacl& operator=(const EchoDbDacl&) = delete;

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] DWORD build_error() const noexcept { return error_; } // set at the failing call
    // For CreateFileW: a file created with this SD has the protected DACL from creation.
    [[nodiscard]] SECURITY_ATTRIBUTES* sa() noexcept { return ok_ ? &sa_ : nullptr; }
    [[nodiscard]] PACL acl() const noexcept { return acl_; } // points into the SD; valid when ok()
    [[nodiscard]] const yuzu::win::EchoDbOwnerProbe& owner_probe() const noexcept { return probe_; }

private:
    void build() {
        if (!probe_.ok()) { // the token user could not be read
            error_ = probe_.error();
            return;
        }
        // "D:P" = SE_DACL_PROTECTED (a file created with it merges none of the parent's
        // inheritable ACEs); "FA" = FILE_ALL_ACCESS; an ACE with no flags is NO_INHERITANCE.
        LPWSTR raw_sid = nullptr;
        if (!::ConvertSidToStringSidW(probe_.user_sid(), &raw_sid)) {
            error_ = ::GetLastError();
            return;
        }
        const LocalPtr sid_text{raw_sid, ::LocalFree};
        std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;";
        sddl += raw_sid;
        sddl += L')';
        PSECURITY_DESCRIPTOR raw_sd = nullptr;
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                    &raw_sd, nullptr)) {
            error_ = ::GetLastError();
            return;
        }
        sd_.reset(raw_sd);
        BOOL present = FALSE;
        BOOL defaulted = FALSE;
        if (!::GetSecurityDescriptorDacl(sd_.get(), &present, &acl_, &defaulted)) {
            error_ = ::GetLastError();
            return;
        }
        if (!present || acl_ == nullptr) { // never hand SetSecurityInfo a NULL DACL (= everyone)
            error_ = ERROR_INVALID_ACL;
            return;
        }
        sa_.nLength = sizeof(sa_);
        sa_.lpSecurityDescriptor = sd_.get();
        sa_.bInheritHandle = FALSE;
        ok_ = true;
    }

    yuzu::win::EchoDbOwnerProbe probe_; // the token user the DACL names; also the owner test
    LocalPtr sd_{nullptr, ::LocalFree}; // the self-relative protected SD; acl_ points into it
    PACL acl_ = nullptr;
    SECURITY_ATTRIBUTES sa_ = {};
    DWORD error_ = ERROR_SUCCESS;
    bool ok_ = false;
};

// Delete a planted sidecar THROUGH a handle opened for DELETE (#6362): POSIX semantics unlink the
// name at once even while another process holds the file open, and the read-only attribute does
// not stop it. A plain DeleteFileW fails (sharing violation / access denied) for exactly those two
// shapes, which is how a planted read-only or held-open sidecar would refuse the open. The handle
// is opened no-follow, so a link is deleted as the link. Returns ERROR_SUCCESS, or the Win32 error.
// An OS without FileDispositionInfoEx (before Windows 10 1809) answers ERROR_INVALID_PARAMETER or
// ERROR_NOT_SUPPORTED, and the old call is tried instead.
//
// The struct and constants are declared here rather than taken from winbase.h/winnt.h, whose
// definitions sit behind an NTDDI_VERSION guard this build does not set: FileDispositionInfoEx is
// FILE_INFO_BY_HANDLE_CLASS 21, and the flags are FILE_DISPOSITION_FLAG_DELETE (0x1),
// _POSIX_SEMANTICS (0x2) and _IGNORE_READONLY_ATTRIBUTE (0x10).
DWORD delete_planted_file(const std::filesystem::path& file) {
    struct DispositionInfoEx {
        DWORD Flags;
    };
    constexpr auto kFileDispositionInfoEx = static_cast<FILE_INFO_BY_HANDLE_CLASS>(21);
    constexpr DWORD kDispositionFlags = 0x1 | 0x2 | 0x10;
    constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE raw = ::CreateFileW(file.c_str(), DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                               kShareAll, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw != INVALID_HANDLE_VALUE) {
        const HandlePtr h{raw, ::CloseHandle};
        DispositionInfoEx info{kDispositionFlags};
        if (::SetFileInformationByHandle(h.get(), kFileDispositionInfoEx, &info, sizeof(info)))
            return ERROR_SUCCESS;
        const DWORD err = ::GetLastError();
        if (err != ERROR_INVALID_PARAMETER && err != ERROR_NOT_SUPPORTED)
            return err;
    }
    return ::DeleteFileW(file.c_str()) ? ERROR_SUCCESS : ::GetLastError();
}

// Creates or re-secures echo.db, echo.db-wal, -shm and -journal (see the block comment above).
// Returns a refusal message when a planted file must stop the open, else nullopt.
std::optional<std::string> secure_echo_db_files(const std::filesystem::path& db,
                                               EchoDbDacl& dacl) {
    if (!dacl.ok())
        return std::nullopt; // open() warned once, when it built the DACL
    // FILE_READ_ATTRIBUTES is for the link count below. None of these asks for data or DELETE
    // access, so share arbitration never weighs the open: no holder's share mode can refuse it.
    constexpr DWORD kAccess = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES;
    constexpr DWORD kLookOnly = READ_CONTROL | FILE_READ_ATTRIBUTES; // no WRITE_DAC
    constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    constexpr DWORD kFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    const yuzu::win::EchoDbOwnerProbe& probe = dacl.owner_probe();
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
        std::filesystem::path file = db;
        file += suffix;
        // from_wide, not path::string(): that narrows through the ANSI code page and would
        // mangle a non-ASCII state directory in the log text and the remedy.
        const std::string name = yuzu::win::from_wide(file.c_str());

        HANDLE raw = ::CreateFileW(file.c_str(), kAccess, kShareAll, dacl.sa(), OPEN_ALWAYS,
                                   kFlags, nullptr);
        const DWORD open_err = ::GetLastError(); // ERROR_ALREADY_EXISTS when it pre-existed
        bool existed = open_err == ERROR_ALREADY_EXISTS;
        bool can_secure = true; // the handle carries WRITE_DAC
        if (raw == INVALID_HANDLE_VALUE && open_err == ERROR_ACCESS_DENIED) {
            // Either the file cannot be created, or it exists and its DACL withholds WRITE_DAC
            // from us. The second is how a planted file would dodge the checks below, so look
            // at it without WRITE_DAC; a file that is not there fails this open too.
            raw = ::CreateFileW(file.c_str(), kLookOnly, kShareAll, nullptr, OPEN_EXISTING,
                                kFlags, nullptr);
            if (raw != INVALID_HANDLE_VALUE) {
                existed = true;
                can_secure = false;
            }
        }
        if (raw == INVALID_HANDLE_VALUE) {
            spdlog::warn("EchoDatabase: could not open {} to secure it (error {}); it keeps its "
                         "current ACL",
                         name, open_err);
            continue;
        }
        HandlePtr h{raw, ::CloseHandle};
        if (!existed)
            continue; // created just now WITH the protected DACL

        // Positive evidence only: a foreign owner, or a second hard link (which shares the
        // target's owner and so passes the owner test). A failed owner read or link-count query
        // is no evidence.
        DWORD owner_rc = ERROR_SUCCESS;
        std::string why;
        std::string remedy;
        if (auto owned_by = probe.foreign_owner(h.get(), &owner_rc)) {
            why = std::move(*owned_by);
            remedy = "move it aside or remove it, then restart the agent; if its owner SID is a "
                     "former agent account's, take ownership of echo.db, echo.db-wal, echo.db-shm "
                     "and echo.db-journal and grant the agent account full access instead";
        } else if (auto linked = yuzu::win::EchoDbOwnerProbe::extra_links(h.get())) {
            why = std::move(*linked);
            remedy = std::format("remove the other links (fsutil hardlink list \"{}\" names "
                                 "them) or remove it, then restart the agent",
                                 name);
        }
        if (owner_rc != ERROR_SUCCESS) {
            spdlog::warn("EchoDatabase: could not read the owner of {} (error {}); the owner test "
                         "is skipped for it",
                         name, owner_rc);
        }
        if (!why.empty()) {
            if (suffix[0] == '\0')
                return std::format("echo.db at {} {}, and was not opened: {}", name, why, remedy);
            h.reset(); // release our handle before deleting; a link loses only OUR name
            if (const DWORD del_err = delete_planted_file(file); del_err != ERROR_SUCCESS) {
                return std::format("{} {}, and could not be removed (error {}): {}", name, why,
                                   del_err, remedy);
            }
            raw = ::CreateFileW(file.c_str(), kAccess, kShareAll, dacl.sa(), CREATE_NEW, kFlags,
                                nullptr);
            if (raw == INVALID_HANDLE_VALUE) {
                return std::format("{} {}; it was removed but could not be re-created (error "
                                   "{}), so echo.db was not opened",
                                   name, why, ::GetLastError());
            }
            h.reset(raw);
            spdlog::warn("EchoDatabase: replaced {}, which {}", name, why);
            continue; // re-created WITH the protected DACL
        }
        if (!can_secure) {
            // Ours by owner and link count, but its DACL withholds WRITE_DAC: nothing to apply.
            spdlog::warn("EchoDatabase: could not open {} to secure it (error {}); it keeps its "
                         "current ACL",
                         name, open_err);
            continue;
        }
        // Owner read failed (no ACL on this filesystem) or the owner is ours: re-secure in
        // place. Best-effort -- availability of a diagnostics DB over confidentiality.
        constexpr SECURITY_INFORMATION kDaclInfo =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        if (const DWORD rc = ::SetSecurityInfo(h.get(), SE_FILE_OBJECT, kDaclInfo, nullptr,
                                               nullptr, dacl.acl(), nullptr);
            rc != ERROR_SUCCESS) {
            spdlog::warn("EchoDatabase: could not apply the owner-only DACL to {} (error {}); it "
                         "keeps its current ACL",
                         name, rc);
        }
    }
    return std::nullopt;
}
#endif // _WIN32

} // namespace

IntegrityCheck classify_integrity_rc(int rc) noexcept {
    const int primary = rc & 0xff; // an extended code (SQLITE_BUSY_SNAPSHOT, ...) keeps it in the low byte
    if (primary == SQLITE_BUSY || primary == SQLITE_LOCKED)
        return IntegrityCheck::busy;
    if (primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB)
        return IntegrityCheck::corrupt;
    return IntegrityCheck::unreadable;
}

// ── Construction / destruction ───────────────────────────────────────────────

EchoDatabase::EchoDatabase(sqlite3* db) : db_{db} {}

EchoDatabase::~EchoDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    if (query_db_) {
        sqlite3_close(query_db_);
        query_db_ = nullptr;
    }
}

EchoDatabase::EchoDatabase(EchoDatabase&& other) noexcept
    : db_{other.db_.load()},
      query_db_{other.query_db_},
      quarantined_at_{other.quarantined_at_},
      fold_{std::move(other.fold_)} {
    other.quarantined_at_.reset();
    other.db_ = nullptr;
    other.query_db_ = nullptr;
}

EchoDatabase& EchoDatabase::operator=(EchoDatabase&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        if (query_db_)
            sqlite3_close(query_db_);
        db_ = other.db_.load();
        query_db_ = other.query_db_;
        quarantined_at_ = other.quarantined_at_;
        fold_ = std::move(other.fold_);
        other.quarantined_at_.reset();
        other.db_ = nullptr;
        other.query_db_ = nullptr;
    }
    return *this;
}

namespace {

// A failed lookup is an error, never "absent": reading a prepare/step failure as "no such table"
// would let open() create empty echo_* tables beside populated tar_* ones (the #559 class).
std::expected<bool, std::string> table_exists(sqlite3* db, const char* name) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", -1,
                           &raw, nullptr) != SQLITE_OK) {
        return std::unexpected(std::format("table lookup {}: {}", name, sqlite3_errmsg(db)));
    }
    StmtPtr stmt(raw);
    // An unbound `?` is NULL and would read as "no such table" (the #559 class), so check it.
    if (sqlite3_bind_text(stmt.get(), 1, name, -1, SQLITE_STATIC) != SQLITE_OK)
        return std::unexpected(std::format("table lookup {}: bind: {}", name, sqlite3_errmsg(db)));
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    return std::unexpected(std::format("table lookup {}: {}", name, sqlite3_errmsg(db)));
}

// True when `from` exists and `to` does not; an error when either lookup fails.
std::expected<bool, std::string> rename_pending(sqlite3* db, const char* from, const char* to) {
    auto have_from = table_exists(db, from);
    if (!have_from)
        return std::unexpected(std::move(have_from.error()));
    if (!*have_from)
        return false;
    auto have_to = table_exists(db, to);
    if (!have_to)
        return std::unexpected(std::move(have_to.error()));
    return !*have_to;
}

// Schema v9 (upgrade window, removed with the legacy-name shims): a database written before the
// rename holds tar_state / tar_config / tar_cursor. Rename whichever of them exist, atomically, in
// one transaction. Skipped when echo_config already exists (a fresh or already-renamed file).
// An error return makes the caller refuse the open.
std::expected<void, std::string> rename_legacy_tables(sqlite3* db) {
    auto legacy = rename_pending(db, "tar_config", "echo_config");
    if (!legacy)
        return std::unexpected(std::move(legacy.error()));
    if (!*legacy)
        return {};
    static constexpr std::array<std::pair<const char*, const char*>, 3> kPairs = {{
        {"tar_state", "echo_state"},
        {"tar_config", "echo_config"},
        {"tar_cursor", "echo_cursor"},
    }};
    // open() calls this on a fresh connection, so no transaction is open. IMMEDIATE, not
    // DEFERRED, for the reason given in exec_ddl_batch: ALTER TABLE is a write, and a deferred
    // BEGIN in WAL can fail SQLITE_BUSY_SNAPSHOT without the busy handler.
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(std::format("BEGIN: {}", sqlite3_errmsg(db)));
    std::expected<void, std::string> result;
    for (const auto& [from, to] : kPairs) {
        auto pending = rename_pending(db, from, to);
        if (!pending) {
            result = std::unexpected(std::move(pending.error()));
            break;
        }
        if (!*pending)
            continue;
        const std::string sql = std::format("ALTER TABLE {} RENAME TO {}", from, to);
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
            result = std::unexpected(std::format("{}: {}", sql, sqlite3_errmsg(db)));
            break;
        }
    }
    if (result && sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
        result = std::unexpected(std::format("COMMIT: {}", sqlite3_errmsg(db)));
    if (!result)
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
    return result;
}

} // namespace

std::expected<EchoDatabase, std::string> EchoDatabase::open(const std::filesystem::path& path) {
    return open(path, OpenSeams{});
}

std::expected<EchoDatabase, std::string> EchoDatabase::open(const std::filesystem::path& path,
                                                           const OpenSeams& seams) {
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

    // Upgrade window (removed with the legacy-name shims): agent core adopts a legacy tar.db as
    // echo.db at boot, before any plugin initialises (adopt_legacy_echo_db). If echo.db is absent
    // and an unadopted tar.db sits beside it, creating a fresh echo.db here would boot the agent
    // with default config and re-enable operator-paused sources (the #559 class). Fail closed.
    // A stat error on tar.db counts as present (`|| lec`): failing open here would create the
    // fresh echo.db this check exists to prevent, the same way the echo.db stat above is guarded.
    if (std::error_code lec; !std::filesystem::exists(path, lec) && !lec &&
                             (std::filesystem::exists(path.parent_path() / "tar.db", lec) || lec)) {
        return std::unexpected(
            std::format("legacy tar.db present at {} and not adopted - refusing to initialise a "
                        "fresh echo.db beside it",
                        (path.parent_path() / "tar.db").string()));
    }

    // #1527 — a link at echo.db or a sidecar is refused before anything touches the paths.
    if (auto refusal = refuse_linked_db_files(path))
        return std::unexpected(*refusal);

    // #1567 — set when this open quarantined a corrupt file; persisted into the
    // fresh DB's echo_config once it is fully initialised (see end of open()).
    std::optional<int64_t> quarantined_at;
    std::string quarantined_file;

#ifdef _WIN32
    // Create or re-secure echo.db, -wal, -shm and -journal BEFORE SQLite touches them, and
    // refuse a planted file (foreign owner or extra hard link); see the DACL block above.
    EchoDbDacl dacl;
    if (!dacl.ok()) {
        // Without the DACL there is no token user to compare owners against, so the foreign-owner
        // and hard-link checks on echo.db and its sidecars are skipped as well (U-11).
        spdlog::warn("EchoDatabase: owner-only DACL not built (error {}); echo.db keeps the "
                     "directory's inherited ACL, and the owner and hard-link checks are skipped",
                     dacl.build_error());
    }
    if (auto refusal = secure_echo_db_files(path, dacl))
        return std::unexpected(*refusal);
#endif

    // Open the main connection, give it its busy timeout at once (so the integrity check below
    // waits for a holder instead of reading "locked" as corrupt, #7286) and hand it to the guard.
    // SQLite returns a handle even when the open fails; the guard closes it either way.
    DbGuard guard;
    const auto open_main = [&]() -> std::expected<void, std::string> {
        sqlite3* opened = nullptr;
        const int orc = sqlite3_open_v2(
            path.string().c_str(), &opened,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        guard.reset(opened);
        if (orc != SQLITE_OK)
            return std::unexpected(opened ? sqlite3_errmsg(opened) : "unknown error");
        sqlite3_busy_timeout(opened, kBusyTimeoutMs);
        return {};
    };
    if (auto opened = open_main(); !opened)
        return std::unexpected(std::format("failed to open echo.db: {}", opened.error()));

    // #559 — corruption self-test BEFORE we trust the DB. A fresh/empty file
    // passes trivially; an existing corrupt one is quarantined aside and a clean
    // DB is re-opened in its place, so the agent never silently serves garbage
    // config (which would re-enable operator-paused sources, compounding #539).
    const auto checked = check_integrity(guard.get());
    switch (checked.verdict) {
    case IntegrityCheck::ok:
        break;
    case IntegrityCheck::unreadable:
        // The file could not be read for a reason that is not corruption (an I/O error, a
        // permission or space fault, WAL lock contention). Quarantine would replace it with a
        // fresh database that re-enables every paused source, so refuse to open instead and let
        // the next start retry (#7286).
        return std::unexpected(std::format(
            "echo.db could not be checked (sqlite rc {}): not quarantined and not opened; "
            "retried on the next start: {}",
            checked.rc, path.string()));
    case IntegrityCheck::busy:
        // Another connection holds the file past the busy timeout. That says nothing about its
        // health, so quarantine nothing (a quarantine would move a healthy file away from its
        // holder) and refuse to open: Echo fails closed rather than trusting a file it could not
        // check, and the next start retries (#7286).
        return std::unexpected(std::format(
            "echo.db is busy (another connection holds it for more than {} ms): not quarantined "
            "and not opened; it is retried on the next start: {}",
            kBusyTimeoutMs, path.string()));
    case IntegrityCheck::corrupt: {
        guard.reset();
        const auto quarantine = yuzu::shared::sqlite_quarantine::quarantine_corrupt_db(
            path, now_epoch_seconds());
        for (const auto& note : quarantine.notes)
            spdlog::warn("EchoDatabase: {}", note);
        const auto& quarantined = quarantine.dest;
        if (!quarantined) {
            // FAIL CLOSED (UP-1): the corrupt DB could not be moved aside, so we
            // must NOT re-open and trust it — doing so would silently serve the
            // "true" get_config default for every `<source>_enabled` key and
            // re-enable sources an operator paused for forensic preservation,
            // the exact failure #559 guards against. Refuse to open; the
            // operator must clear the underlying fault (read-only mount, locked
            // file, permissions, a filesystem without hard links) and restart.
            return std::unexpected(std::format(
                "echo.db failed integrity_check and could not be quarantined "
                "(corrupt and unmovable): {}",
                path.string()));
        }
        quarantined_at = now_epoch_seconds();
        quarantined_file = quarantined->filename().string();
        spdlog::error("ECHO: echo.db failed PRAGMA integrity_check (echo.db.corruption_detected) — "
                      "quarantined to {} and re-initialising a fresh database",
                      quarantined->string());
#ifdef _WIN32
        // The quarantine rename left no echo.db: pre-create it (and any sidecar) protected again.
        if (auto refusal = secure_echo_db_files(path, dacl))
            return std::unexpected(*refusal);
#endif
        if (auto reopened = open_main(); !reopened) {
            return std::unexpected(
                std::format("failed to re-open echo.db after quarantine: {}", reopened.error()));
        }
        // Backstop (UP-2): the freshly-created DB must itself be clean — this
        // also catches the case where a -wal/-shm sidecar belonging to the
        // quarantined file could neither be moved nor removed and was adopted by
        // the new file. If even the fresh DB is not clean (or is busy), fail closed.
        if (check_integrity(guard.get()).verdict != IntegrityCheck::ok) {
            return std::unexpected(std::format(
                "echo.db re-initialised after quarantine still fails integrity_check: {}",
                path.string()));
        }
        break;
    }
    }
    sqlite3* raw_db = guard.get();
    int rc = SQLITE_OK;

    // Incremental auto_vacuum, BEFORE journal_mode=WAL: SQLite fixes the mode when the first
    // table is created, and the WAL switch writes page 1 of an empty file. On a database that
    // already has tables this is a no-op until a VACUUM converts it (vacuum_to_incremental).
    // Best effort -- the byte budget works without it, only the file shrinks more slowly.
    SqliteErrMsg pragma_err;
    rc = sqlite3_exec(raw_db, "PRAGMA auto_vacuum=INCREMENTAL", nullptr, nullptr,
                      pragma_err.addr());
    if (rc != SQLITE_OK)
        spdlog::warn("EchoDatabase: PRAGMA auto_vacuum=INCREMENTAL failed: {}", pragma_err.text());

    // WAL mode for concurrent read performance -- required for correctness
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        return std::unexpected(std::format("failed to enable WAL mode: {}", err));
    }
    sqlite3_free(err_msg);

    // Secure delete -- zeroes deleted content; required for security
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA secure_delete=ON", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        return std::unexpected(std::format("failed to enable secure_delete: {}", err));
    }
    sqlite3_free(err_msg);

    // Cap the WAL file left behind after a checkpoint resets it. Without a limit a one-off
    // burst (a backlog drain, a large eviction) leaves the -wal file at its high-water mark
    // forever. Only bites when a checkpoint resets the WAL; a pinned reader defers it.
    rc = sqlite3_exec(raw_db,
                      std::format("PRAGMA journal_size_limit={}", kEchoWalAllowanceBytes).c_str(),
                      nullptr, nullptr, pragma_err.addr());
    if (rc != SQLITE_OK)
        spdlog::warn("EchoDatabase: PRAGMA journal_size_limit failed: {}", pragma_err.text());

    // Schema v9: the base tables were renamed tar_* -> echo_*. This must run BEFORE the base
    // schema below, which would otherwise create empty echo_* tables beside the populated tar_*
    // ones and boot the agent with default config. Failure is fail-closed for the same reason.
    if (auto renamed = rename_legacy_tables(raw_db); !renamed) {
        return std::unexpected(
            std::format("failed to rename legacy tar_* tables: {}", renamed.error()));
    }

    // Create schema — one transaction, not one per statement (see
    // exec_ddl_batch: ~75 fsync'd commits otherwise, #2093).
    err_msg = nullptr;
    rc = exec_ddl_batch(raw_db, kCreateSchema, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        return std::unexpected(std::format("failed to create Echo schema: {}", err));
    }

    // Set default retention if not already configured
    {
        const char* check_sql = "SELECT value FROM echo_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        rc = sqlite3_prepare_v2(raw_db, check_sql, -1, &raw_stmt, nullptr);
        if (rc == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
                // No retention_days configured -- set default
                const char* insert_sql =
                    "INSERT INTO echo_config (key, value) VALUES ('retention_days', '7')";
                sqlite3_exec(raw_db, insert_sql, nullptr, nullptr, nullptr);
            }
        }
    }

    auto db = EchoDatabase{guard.release()};
    db.fold_ = std::make_unique<EchoFold>();

    // Ensure every registry-declared warehouse table exists on EVERY open —
    // the DDL is IF-NOT-EXISTS-idempotent, and gating it on schema_version<2
    // left upgraded fleets without tables added by NEWER releases (the A1
    // perf tier never materialised on a pre-existing v3 echo.db, so
    // insert_perf_sample failed every 30 s; found during A2). The version
    // marker keeps its legacy meaning (>=2 = typed warehouse present).
    if (db.create_warehouse_tables()) {
        // One read, through try_get_config: a FAILED read falling to get_config's "0" default
        // would rewrite the version to 2 and replay the whole ladder (v8 included, which flips an
        // operator's disable back on). Only a confirmed-absent or unparseable row migrates.
        if (const auto stored = db.try_get_config("schema_version")) {
            if ((stored->has_value() ? parse_schema_version(**stored) : 0) < 2) {
                db.set_config("schema_version", "2");
                spdlog::info("EchoDatabase: migrated to schema version 2 (typed warehouse tables)");
            }
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
                std::string{"echo.db schema transaction could neither commit nor roll back; "
                            "refusing to open on a wedged connection"});
        }
        spdlog::warn("EchoDatabase: warehouse table creation failed{}",
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
            spdlog::info("EchoDatabase: migrated to schema version 3 (legacy tar_events retired)");
        } else {
            spdlog::warn("EchoDatabase: failed to drop tar_events: {}", emsg ? emsg : "unknown");
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
            // A database created by v10 or later has no such table (the roll-up views replaced
            // it), and this step runs for it on its way up the ladder: nothing to alter.
            const auto present = table_exists(raw_db, tbl);
            if (!present) {
                spdlog::error("EchoDatabase: v4 table probe failed: {}", present.error());
                ok = false;
                break;
            }
            if (!*present || has_version_col(tbl))
                continue;
            const auto alter =
                std::format("ALTER TABLE {} ADD COLUMN version TEXT NOT NULL DEFAULT ''", tbl);
            if (sqlite3_exec(raw_db, alter.c_str(), nullptr, nullptr, &emsg) != SQLITE_OK) {
                // ERROR, not warn: a stranded v4 is NOT a degraded-version state —
                // insert_proc_perf_samples and the hourly rollup both name the
                // `version` column unconditionally, so on a schema-v3 DB they fail
                // to prepare EVERY tick and ALL procperf collection stops. Give the
                // on-call operator the exact recovery, since the schema stays at v3.
                spdlog::error("EchoDatabase: v4 ALTER {} failed: {} — schema remains at v3; ALL "
                              "procperf collection will fail until the column is added. Recovery: "
                              "stop the agent and run `ALTER TABLE {} ADD COLUMN version TEXT NOT "
                              "NULL DEFAULT '';` on the echo.db, then restart.",
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
            spdlog::info("EchoDatabase: migrated to schema version 4 (procperf version column)");
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
            spdlog::info("EchoDatabase: retired the legacy tar_events table");
        } else {
            // WARN, not ERROR: nothing reads or writes tar_events, so the cost of
            // failing here is a residual empty table. The next open retries.
            spdlog::warn("EchoDatabase: could not drop the legacy tar_events table: {} — it will be "
                         "retried on the next open; to clear it by hand, stop the agent and run "
                         "`DROP TABLE tar_events;` against the echo.db",
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
        spdlog::info("EchoDatabase: migrated to schema version 5 (legacy tar_events retired)");
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
                spdlog::error("EchoDatabase: v6 migration statement failed: {} ({})",
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
                "EchoDatabase: migrated to schema version 6 (usage_daily_user + usage indexes)");
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
    // (sync_source_app_perf.cpp); see echo_proc_perf.hpp's "Kernel-thread
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
            const auto present = table_exists(raw_db, tbl); // absent on a database created by v10+
            if (!present) {
                spdlog::error("EchoDatabase: v7 table probe failed: {}", present.error());
                ok = false;
                break;
            }
            if (!*present || has_is_kthread_col(tbl))
                continue;
            const auto alter =
                std::format("ALTER TABLE {} ADD COLUMN is_kthread INTEGER NOT NULL DEFAULT 0", tbl);
            if (sqlite3_exec(raw_db, alter.c_str(), nullptr, nullptr, emsg.addr()) != SQLITE_OK) {
                // ERROR, not warn: insert_proc_perf_samples and the hourly rollup
                // both name `is_kthread` unconditionally, so a stranded v6 DB fails
                // to prepare EVERY tick and ALL procperf collection stops.
                spdlog::error("EchoDatabase: v7 ALTER {} failed: {} — schema remains at v6; ALL "
                              "procperf collection will fail until the column is added. Recovery: "
                              "stop the agent and run `ALTER TABLE {} ADD COLUMN is_kthread INTEGER "
                              "NOT NULL DEFAULT 0;` on the echo.db, then restart.",
                              tbl, emsg.text(), tbl);
                ok = false;
                break;
            }
        }
        if (ok) {
            db.set_config_locked("schema_version", "7");
            sqlite3_exec(raw_db, "RELEASE v7_migration", nullptr, nullptr, nullptr);
            spdlog::info("EchoDatabase: migrated to schema version 7 (procperf is_kthread column)");
        } else {
            sqlite3_exec(raw_db, "ROLLBACK TO v7_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v7_migration", nullptr, nullptr, nullptr);
        }
    }

    // Version 8: every capture source ships enabled. The eight sources that
    // were formerly opt-in (below) had `<src>_enabled` stored as "false" on
    // agents that seeded it (or whose operator wrote it); flip that stored
    // value to "true" ONCE and clear the paused marker, matching the enable
    // edge of apply_source_enabled_transition (flag + paused_at "0" in one
    // transaction; that function lives in echo_aggregator and cannot be called
    // from here — the aggregator depends on this file). Only the literal
    // "false" is touched: "true" / "errored" / absent rows are left alone, and
    // the eight already-on sources are not listed so a deliberate pause on
    // them survives. Version-gated, so an opt-out written after this migration
    // sticks; any failed step rolls the whole savepoint back and the version
    // stays 7 (retried on the next open).
    if (db.schema_version() == 7) {
        static constexpr std::string_view kFormerlyOptIn =
            "'procperf_enabled','netqual_enabled','module_enabled','software_enabled',"
            "'arp_enabled','dns_enabled','netconn_enabled','mapdrive_enabled'";
        // Order matters: the paused_at upsert keys on value = 'false', which the
        // flip then erases. The SELECT's WHERE also lets SQLite parse ON CONFLICT.
        const std::array<std::string, 2> steps = {
            std::format("INSERT INTO echo_config(key, value) "
                        "SELECT replace(key, '_enabled', '_paused_at'), '0' FROM echo_config "
                        "WHERE value = 'false' AND key IN ({}) "
                        "ON CONFLICT(key) DO UPDATE SET value = '0'",
                        kFormerlyOptIn),
            std::format("UPDATE echo_config SET value = 'true' "
                        "WHERE value = 'false' AND key IN ({})",
                        kFormerlyOptIn)};
        SqliteErrMsg emsg;
        std::lock_guard lock(db.mu_);
        if (sqlite3_exec(raw_db, "SAVEPOINT v8_migration", nullptr, nullptr, nullptr) !=
            SQLITE_OK) {
            spdlog::error("EchoDatabase: v8 SAVEPOINT failed: {} — schema remains at v7, retried "
                          "on the next open",
                          sqlite3_errmsg(raw_db));
        } else {
            bool ok = true;
            std::string failed_step;
            for (const auto& sql : steps) {
                if (sqlite3_exec(raw_db, sql.c_str(), nullptr, nullptr, emsg.addr()) !=
                    SQLITE_OK) {
                    ok = false;
                    failed_step = std::format("flip: {}", emsg.text());
                    break;
                }
            }
            if (ok && !db.set_config_locked("schema_version", "8")) {
                ok = false;
                failed_step = "write schema_version";
            }
            if (ok && sqlite3_exec(raw_db, "RELEASE v8_migration", nullptr, nullptr, nullptr) !=
                          SQLITE_OK) {
                ok = false;
                failed_step = std::format("RELEASE: {}", sqlite3_errmsg(raw_db));
            }
            if (ok) {
                spdlog::info("EchoDatabase: migrated to schema version 8 (capture sources "
                             "default-on)");
            } else {
                spdlog::error("EchoDatabase: v8 migration failed at '{}' — rolled back, schema "
                              "remains at v7, retried on the next open",
                              failed_step);
                // v8_migration is the outermost savepoint, so RELEASE COMMITS whatever the
                // failed steps left behind. Run it only after ROLLBACK TO has succeeded;
                // when ROLLBACK TO fails, go straight to a plain ROLLBACK.
                const int rollback_rc =
                    sqlite3_exec(raw_db, "ROLLBACK TO v8_migration", nullptr, nullptr, nullptr);
                int release_rc = -1; // -1 = not attempted
                if (rollback_rc == SQLITE_OK)
                    release_rc =
                        sqlite3_exec(raw_db, "RELEASE v8_migration", nullptr, nullptr, nullptr);
                if (rollback_rc != SQLITE_OK || release_rc != SQLITE_OK) {
                    // An open savepoint would leave every later write uncommitted until
                    // close. A plain ROLLBACK ends it; with no transaction open it fails
                    // harmlessly, so its result is ignored.
                    spdlog::error("EchoDatabase: v8 rollback incomplete (ROLLBACK TO rc={}, "
                                  "RELEASE rc={}, -1 = not attempted): {} — ending the "
                                  "transaction",
                                  rollback_rc, release_rc, sqlite3_errmsg(raw_db));
                    sqlite3_exec(raw_db, "ROLLBACK", nullptr, nullptr, nullptr);
                }
            }
        }
    }

    // Schema v9: the tar_* -> echo_* table rename ran above (before the base schema), so every
    // file that reaches this point has echo_* tables. Only the version marker is left. Fresh and
    // renamed databases both read 9; the roll-up migration that follows takes v10.
    if (db.schema_version() == 8) {
        db.set_config("schema_version", "9");
        spdlog::info("EchoDatabase: migrated to schema version 9 (tables renamed)");
    }

    // Schema v10: the roll-up flip. The retired raw `<src>_live` tables and the old summary
    // tiers move into the roll-up tables in ONE transaction (or, on a database with none of
    // them, the roll-up schema is simply installed). The step runs HERE, before the query
    // connection exists, so no reader pins the WAL while it checkpoints. A failure leaves the
    // retired tables intact; open() refuses and the next open retries from v9 -- Echo is
    // offline until it succeeds, which an operator sees in the agent log and `echo status`.
    if (const int version = db.schema_version(); version < 10) {
        // An earlier step that failed rolled itself back and is retried on the next open. The
        // roll-up step must not run past it: it would take the version to 10 and the step that
        // failed would never be retried (each is gated on its own version).
        if (version < 9)
            return std::unexpected(std::format("schema v{}: an earlier migration step did not finish "
                                               "(see the log); the roll-up step waits for it and the "
                                               "next open retries both",
                                               version));
        if (auto migrated = migrate_to_v10(db, path, seams); !migrated)
            return std::unexpected(std::format("v10 roll-up migration failed (the schema stays at "
                                               "v9; the retired tables are intact): {}",
                                               migrated.error()));
    }
    // B3 (#6889 review): never publish a connection that is inside a transaction. Writes on it
    // would be reported durable and discarded at close. `db` owns raw_db, so returning closes it.
    if (sqlite3_get_autocommit(raw_db) == 0) {
        return std::unexpected(
            std::string{"echo.db is inside an open transaction after the schema steps; refusing "
                        "to open on a wedged connection"});
    }

#ifndef _WIN32
    // Owner-only (0600) on the db and its WAL sidecars, as command_dedup_store does
    // (security-hardening.md "chmod 600 *.db"): the packaged state directory is not a
    // confidentiality boundary (agent-privilege-model.md), and echo.db now holds every
    // capture source. Best-effort per file (-wal/-shm/-journal may not exist yet); a chmod
    // failure never fails an otherwise-healthy open. SQLite derives later sidecar modes from
    // the db file. POSIX mode bits only; Windows applies a protected DACL in the #else arm.
    // `nofollow`: the link check ran at the start of open(), so a link swapped in since must not
    // have its target chmod'ed (a regular file is unaffected).
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
        std::error_code pec;
        std::filesystem::permissions(path.string() + suffix,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace |
                                         std::filesystem::perm_options::nofollow,
                                     pec);
    }
#else
    // The pre-open pass created or re-secured the four files, but on a FRESH (0-page)
    // database SQLite deletes the pre-created -wal and recreates it with the inherited ACL on
    // the first write. This end-of-open pass closes that one-time window and refuses a foreign
    // file raced in meanwhile. `db` owns raw_db, so returning here closes it.
    if (auto refusal = secure_echo_db_files(path, dacl))
        return std::unexpected(*refusal);
#endif

    // Open a dedicated read-only, authorizer-sandboxed connection for untrusted
    // operator SQL (the echo.sql action). On this handle writes are structurally
    // impossible and the authorizer restricts reads to registry-known warehouse
    // tables (#760). Internal trusted reads keep using db_. If this connection
    // can't be opened we continue without it; execute_user_query then fails
    // closed.
    {
        sqlite3* ro = nullptr;
        int rrc = sqlite3_open_v2(path.string().c_str(), &ro,
                                  SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rrc == SQLITE_OK) {
            sqlite3_busy_timeout(ro, kBusyTimeoutMs);
            sqlite3_db_config(ro, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);
            sqlite3_set_authorizer(ro, &echo_query_authorizer, nullptr);
            // Force the is_queryable_table allowlist's one-time static init now,
            // on a normal C++ stack — never lazily inside the authorizer callback
            // while it runs in SQLite's C prepare frames.
            (void)is_queryable_table("");
            (void)is_fold_view(""); // the view set; the fold-internal checks derive from it
            db.query_db_ = ro;
        } else {
            spdlog::warn("EchoDatabase: read-only query connection unavailable ({}); "
                         "echo.sql queries will be refused",
                         ro ? sqlite3_errmsg(ro) : "open failed");
            if (ro)
                sqlite3_close(ro);
        }
    }

    if (quarantined_at) {
        // Durable source of truth for the fleet-visible corruption fact; the
        // plugin reconciles it into its heartbeat KV keys (a crash between the
        // rename above and this write is one of two windows where the fact is lost;
        // the other is the config write below failing).
        // Basename only — never a full path in status or heartbeat.
        db.quarantined_at_ = quarantined_at;
        // A failed write loses the durable record (the plugin reconcile and the
        // status line read these two rows); name the key so it is visible.
        if (!db.set_config("db_health_last_quarantine_epoch", std::to_string(*quarantined_at)))
            spdlog::error("EchoDatabase: failed to persist db_health_last_quarantine_epoch");
        if (!db.set_config("db_health_last_quarantine_file", quarantined_file))
            spdlog::error("EchoDatabase: failed to persist db_health_last_quarantine_file");
    }

    spdlog::info("EchoDatabase opened: {} (schema v{})", path.string(), db.schema_version());
    return db;
}

// ── Statistics (queries typed warehouse tables) ─────────────────────────────

EchoStats EchoDatabase::stats() {
    std::lock_guard lock(mu_);
    EchoStats s{};
    if (!db_)
        return s;

    // Data-driven over the roll-up declarations, so a newly-declared source is counted
    // automatically instead of being silently omitted by a hand-maintained list. A source
    // counts through its FINEST physical tier (the one that holds every event once); its bucket
    // column stands in for a timestamp, so the range is in hour-start steps. Source and table
    // names come from the declaration, a compile-time allowlist, so the concatenation carries
    // no injection risk; an empty table contributes COUNT 0 / NULL MIN/MAX.
    std::string count_expr;
    std::string min_union;
    std::string max_union;
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        const std::string table = physical_table_name(def.name, def.tiers.front());
        const std::string col{ts_column_for_suffix(def.tiers.front())};
        const bool first = count_expr.empty();
        count_expr += (first ? "" : " + ") + std::format("(SELECT COUNT(*) FROM {})", table);
        min_union += (first ? "" : " UNION ALL ") + std::format("SELECT MIN({}) AS m FROM {}", col, table);
        max_union += (first ? "" : " UNION ALL ") + std::format("SELECT MAX({}) AS m FROM {}", col, table);
    }

    // Aggregate record count across the finest tiers
    {
        std::string sql = "SELECT " + count_expr;
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.record_count = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Oldest bucket across the finest tiers
    {
        std::string sql = "SELECT MIN(m) FROM (" + min_union + ")";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.oldest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Newest bucket
    {
        std::string sql = "SELECT MAX(m) FROM (" + max_union + ")";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.newest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // DB size: used pages (free pages are reusable) plus the WAL file.
    {
        const StorageBytes sb = storage_bytes_locked();
        s.db_size_bytes = sb.data_bytes() + sb.wal_bytes;
    }

    // Retention days from config
    {
        const char* sql = "SELECT value FROM echo_config WHERE key = 'retention_days'";
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

std::string EchoDatabase::get_state(const std::string& collector) {
    std::lock_guard lock(mu_);
    if (!db_)
        return {};

    const char* sql = "SELECT state_json FROM echo_state WHERE collector = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("EchoDatabase::get_state prepare failed: {}", sqlite3_errmsg(db_));
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

std::expected<std::optional<std::string>, std::string>
EchoDatabase::try_get_state(const std::string& collector) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("EchoDatabase::try_get_state: no open database");

    const char* sql = "SELECT state_json FROM echo_state WHERE collector = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        std::string err =
           std::string("EchoDatabase::try_get_state prepare failed: ") + sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);

    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return std::optional<std::string>(
           t ? std::string(t, static_cast<std::size_t>(sqlite3_column_bytes(stmt.get(), 0)))
             : std::string{});
    }
    if (rc != SQLITE_DONE) {
        std::string err =
           std::string("EchoDatabase::try_get_state step failed: ") + sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    return std::optional<std::string>{}; // succeeded, no row
}

// A standalone (non-transactional) write must not join a transaction that an exception unwound
// past on this connection: it would report success and then be discarded by the ROLLBACK that
// EchoPlugin::fail_internal runs once it re-takes mu_. Every BEGIN site holds mu_ for its whole
// span, so an open transaction seen by a caller that has just taken mu_ is abandoned by
// definition. Refuse; the caller reports the failure and the next attempt lands.
bool EchoDatabase::refuse_open_transaction_locked(const char* what) const {
    if (sqlite3_get_autocommit(db_) != 0)
        return false;
    spdlog::warn("EchoDatabase::{} refused: a transaction left open on the write connection is "
                 "about to be rolled back",
                 what);
    return true;
}

bool EchoDatabase::set_state(const std::string& collector, const std::string& json) {
    std::lock_guard lock(mu_);
    if (!db_ || refuse_open_transaction_locked("set_state"))
        return false;
    return upsert_state_locked(db_, collector, json);
}

bool EchoDatabase::upsert_state_locked(sqlite3* db, const std::string& collector,
                                      const std::string& json) {
    const char* sql = R"(
        INSERT INTO echo_state (collector, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(collector) DO UPDATE SET state_json = excluded.state_json,
                                             updated_at = excluded.updated_at
        WHERE echo_state.state_json IS NOT excluded.state_json
    )";
    // The WHERE makes an identical snapshot a true no-op: no page is dirtied, so a quiet
    // source stops writing a WAL frame per tick. Nothing reads updated_at.

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("EchoDatabase::set_state prepare failed: {}", sqlite3_errmsg(db));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("EchoDatabase::set_state step failed: {}", sqlite3_errmsg(db));
        return false;
    }
    return true;
}

// ── Cursor-model persistence (echo_cursor.hpp) ─────────────────────────────────

std::expected<std::optional<std::string>, std::string>
EchoDatabase::get_cursor(const std::string& source) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("EchoDatabase::get_cursor: no open database");

    const char* sql = "SELECT cursor_json FROM echo_cursor WHERE source = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::string err = std::string("EchoDatabase::get_cursor prepare failed: ") +
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
        std::string err = std::string("EchoDatabase::get_cursor step failed: ") +
                          sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    return std::optional<std::string>{};
}

namespace {

using Cursor = EchoDatabase::CursorInsertError;

Cursor to_cursor_error(CursorFoldError::Kind k) {
    switch (k) {
    case CursorFoldError::Kind::KeyCollision:
        return Cursor::KeyCollision;
    case CursorFoldError::Kind::Misuse:
        return Cursor::Misuse;
    case CursorFoldError::Kind::Transient:
        break;
    }
    return Cursor::Transient;
}

// A cursor source's wrapper: derive the contributions, fold them through the replay ring and
// commit the cursor (and any baselines) in the same transaction. A declaration typo in a delta
// throws; it is a permanent programming error, never a retry.
template <class Events, class Delta>
std::expected<void, Cursor> fold_cursor(EchoFold* fold, EchoDatabase& db, std::string_view source,
                                        const Events& events, Delta delta,
                                        const std::string& cursor_json,
                                        const std::vector<StateWrite>& baselines) {
    if (!fold)
        return std::unexpected(Cursor::Transient);
    try {
        const auto r = fold->fold_cursor_rows(db, source, delta(events), cursor_json, baselines);
        if (!r) {
            if (r.error().kind != CursorFoldError::Kind::KeyCollision)
                spdlog::error("EchoDatabase: {} fold failed: {}", source, r.error().text);
            return std::unexpected(to_cursor_error(r.error().kind));
        }
    } catch (const std::exception& e) {
        spdlog::error("EchoDatabase: {} fold threw: {}", source, e.what());
        return std::unexpected(Cursor::Misuse);
    }
    return {};
}

} // namespace

std::expected<void, EchoDatabase::CursorInsertError>
EchoDatabase::insert_power_events_and_cursor(const std::vector<PowerEvent>& events,
                                             const std::string& cursor_json) {
    return fold_cursor(fold_.get(), *this, "power", events, power_delta, cursor_json, {});
}

std::expected<void, EchoDatabase::CursorInsertError>
EchoDatabase::insert_removable_events_and_cursor(const std::vector<RemovableEvent>& events,
                                                 const std::string& cursor_json) {
    return fold_cursor(fold_.get(), *this, "removable", events, removable_delta, cursor_json, {});
}

std::expected<void, EchoDatabase::CursorInsertError> EchoDatabase::insert_registry_events_and_cursor(
    const std::vector<RegistryEvent>& events, const std::string& cursor_json,
    const std::vector<StateWrite>& baseline_writes) {
    return fold_cursor(fold_.get(), *this, "registry", events, registry_delta, cursor_json,
                       baseline_writes);
}

// ── Config management ────────────────────────────────────────────────────────

std::expected<std::optional<std::string>, std::string>
EchoDatabase::try_get_config(const std::string& key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("EchoDatabase::try_get_config: no open database");

    const char* sql = "SELECT value FROM echo_config WHERE key = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        std::string err =
           std::string("EchoDatabase::try_get_config prepare failed: ") + sqlite3_errmsg(db_);
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
           std::string("EchoDatabase::try_get_config step failed: ") + sqlite3_errmsg(db_);
        spdlog::error("{}", err);
        return std::unexpected(std::move(err));
    }
    return std::optional<std::string>{}; // succeeded, no row
}

std::string EchoDatabase::get_config(const std::string& key, const std::string& default_val) {
    std::lock_guard lock(mu_);
    if (!db_)
        return default_val;

    const char* sql = "SELECT value FROM echo_config WHERE key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("EchoDatabase::get_config prepare failed: {}", sqlite3_errmsg(db_));
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

bool EchoDatabase::set_config(const std::string& key, const std::string& value) {
    std::lock_guard lock(mu_);
    if (!db_ || refuse_open_transaction_locked("set_config"))
        return false;
    return set_config_locked(key, value);
}

bool EchoDatabase::set_config_locked(const std::string& key, const std::string& value) {
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO echo_config (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("EchoDatabase::set_config prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, value.c_str(), static_cast<int>(value.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("EchoDatabase::set_config step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

// ── Warehouse schema management ─────────────────────────────────────────────

int EchoDatabase::schema_version() {
    return parse_schema_version(get_config("schema_version", "0"));
}

bool EchoDatabase::create_warehouse_tables() {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    auto ddl = generate_warehouse_ddl();
    char* err_msg = nullptr;
    // One transaction for the whole registry DDL — the dominant cost of an
    // open, and the larger of the two batches (#2093). See exec_ddl_batch.
    int rc = exec_ddl_batch(db_, ddl.c_str(), &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("EchoDatabase::create_warehouse_tables failed: {}",
                      err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

std::expected<EchoDatabase::PurgeResult, std::string>
EchoDatabase::purge_source(const std::string& source,
                           std::chrono::steady_clock::duration dictionary_deadline) {
    // Resolve the source's tables from the schema registry -- never hardcode. A roll-up tier
    // name (`process_hourly`) is a VIEW; the rows live in its `_r` table. The tables the roll-up
    // does not own (netqual_boot, usage_live, usage_daily) are named as they are.
    const CaptureSourceDef* def = nullptr;
    for (const auto& s : capture_sources()) {
        if (s.name == source) {
            def = &s;
            break;
        }
    }
    if (!def)
        return std::unexpected("unknown source: " + source);

    std::vector<std::string> tables;
    for (const auto& g : def->granularities) {
        const std::string name = std::string(def->name) + "_" + std::string(g.suffix);
        tables.push_back(is_fold_view(name) ? name + "_r" : name);
    }
    // usage_daily_user (Wave 7 PR7.2b) has no tier of its own in the registry -- its shape
    // (PRIMARY KEY(day_ts, exe_key, user), no `id` column; see this file's v6 migration) does not
    // fit the generic per-tier layout -- so the granularity walk never reaches it and an
    // operator-initiated `echo.purge_source usage` would otherwise leave every username behind
    // (docs/echo-dashboard.md §3.4's purge promise). It must never resurrect on re-enable: the
    // lifecycle's PendingBaseline gate (echo_usage.cpp) always requires a fresh baseline first.
    if (source == "usage")
        tables.push_back("usage_daily_user");

    // registry (PR11.8): the source keeps captured content beyond its tiers. Each root's BASELINE
    // (`registry:<root>` echo_state rows) holds each value's type, size and hash, and the CURSOR
    // row holds the rendered new value of changes still waiting for their attribution to settle.
    // Erase them in THIS transaction too, or a purge the operator expects to be permanent leaves
    // the very values it removed. The cursor erase also means the next collect is a fresh
    // Baseline (zero rows), never a diff against a baseline that no longer exists. A cursor
    // source's replay ring goes as well: a ring entry for a key whose rows are gone would make a
    // re-offered record a silent no-op. Bookkeeping rows are not counted in `total`.
    std::vector<std::string> bookkeeping;
    if (source == "registry") {
        bookkeeping.push_back("DELETE FROM echo_cursor WHERE source = 'registry'");
        bookkeeping.push_back("DELETE FROM echo_state WHERE collector LIKE 'registry:%'");
    }
    if (const FoldSourceDef* fold = fold_source(source); fold && fold->cursor_source)
        bookkeeping.push_back(std::format("DELETE FROM {} WHERE source = '{}'", kSeenTable, source));
    // The identities of the historical mappings already folded (fold_mapdrive_events).
    if (source == "mapdrive")
        bookkeeping.push_back(
            std::format("DELETE FROM {} WHERE source = '{}'", kSeenTable, kMapdriveHistoricalSource));

    int64_t total = 0;
    const auto purged = checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        for (const auto& table : tables) {
            // Counted first, in the same transaction: a RETURNING row per deleted row of a large
            // table would cost more than the delete.
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(h.raw(), std::format("SELECT COUNT(*) FROM {}", table).c_str(), -1,
                                   &raw, nullptr) != SQLITE_OK) {
                h.fail(std::format("purge failed on {}: {}", table, sqlite3_errmsg(h.raw())));
                return std::unexpected(h.error());
            }
            {
                StmtPtr count(raw);
                if (sqlite3_step(count.get()) != SQLITE_ROW) {
                    h.fail(std::format("purge failed on {}: {}", table, sqlite3_errmsg(h.raw())));
                    return std::unexpected(h.error());
                }
                total += sqlite3_column_int64(count.get(), 0);
            }
            if (!h.exec("DELETE FROM " + table))
                return std::unexpected(std::format("purge failed on {}: {}", table, h.error()));
        }
        for (const auto& sql : bookkeeping)
            if (!h.exec(sql))
                return std::unexpected("purge failed on bookkeeping: " + h.error());
        return {};
    });
    if (!purged)
        return std::unexpected(purged.error());

    // The strings only this source's rows referenced (process names, users, DNS names, key paths)
    // are forensic data too: sweep the dictionary now rather than leave them to the weekly pass.
    // Operator-initiated and rare, so it gets a long deadline. If it still runs out or fails,
    // the result SAYS so and the starved counter moves (cmp-3): the action's audit row must not
    // record a complete erasure while the purged strings are still on disk. The weekly sweep
    // finishes the job.
    PurgeResult out{static_cast<int>(total), false};
    if (fold_) {
        const auto swept = fold_->gc_dictionary(*this, EchoFold::Clock::now() + dictionary_deadline);
        if (!swept) {
            out.dictionary_pending = true;
            spdlog::warn("purge_source({}): the dictionary sweep failed ({}); the purged strings "
                         "stay until the weekly sweep",
                         source, swept.error());
        } else if (swept->deadline_hit) {
            out.dictionary_pending = true;
            spdlog::warn("purge_source({}): the dictionary sweep ran out of time; the purged strings "
                         "stay until the weekly sweep",
                         source);
        }
        if (out.dictionary_pending) {
            int64_t starved = 0;
            const auto text = get_config("dict_gc_starved_total", "0");
            const auto [p, ec] = std::from_chars(text.data(), text.data() + text.size(), starved);
            if (ec != std::errc{} || p != text.data() + text.size())
                starved = 0;
            (void)set_config("dict_gc_starved_total", std::to_string(starved + 1));
        }
    }

    // Forensic-erasure completion: secure_delete=ON (open path) zeroes the deleted rows in the
    // MAIN-db pages, but under journal_mode=WAL the pre-delete page images (still bearing the
    // purged data) linger in the -wal file until a checkpoint truncates it. For a "permanent /
    // cannot be undone" purge that is a real residue window -- and the operator often purges to
    // reclaim disk, which a passive checkpoint won't do promptly. Force a TRUNCATE checkpoint
    // here so the erasure is complete and the WAL is reclaimed at return. Best-effort: the DELETE
    // already committed, so a checkpoint that can't fully complete (e.g. a lingering reader) is
    // logged, not fatal -- the residue clears at the next one.
    if (checkpoint(CheckpointMode::kTruncate) != CheckpointResult::kOk) {
        spdlog::warn("purge_source({}): WAL checkpoint(TRUNCATE) did not complete -- purged data may "
                     "persist in the WAL until the next checkpoint",
                     source);
    }
    return out;
}

// ── Roll-up folds ───────────────────────────────────────────────────────────

namespace {

// Derive `source`'s tiers from a batch with `fill` and fold them in ONE transaction. With nothing
// to fold and no baseline to write there is nothing to do (and no transaction). A declaration typo
// in a delta throws std::invalid_argument; it is logged and reported as a failed fold, never
// allowed to unwind into a collector.
template <class Fill>
bool fold_batch(EchoDatabase& db, EchoFold* fold, std::string_view source, bool no_events,
                const std::optional<StateWrite>& state, Fill&& fill,
                const EchoFold::ExtraFn& extra = {}) {
    if (no_events && !state)
        return true;
    if (!fold)
        return false;
    try {
        const FoldSourceDef* def = fold_source(source);
        if (!def) {
            spdlog::error("EchoDatabase: fold of unknown source '{}'", source);
            return false;
        }
        TierAccumulator acc(*def);
        fill(acc);
        const auto r = fold->fold_rows(db, source, acc, state, extra);
        if (!r) {
            spdlog::error("EchoDatabase: fold_{} failed: {}", source, r.error());
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        spdlog::error("EchoDatabase: fold_{} failed: {}", source, e.what());
        return false;
    }
}

} // namespace

bool EchoDatabase::fold_process_events(const std::vector<ProcessEvent>& events,
                                       const std::optional<StateWrite>& state,
                                       std::optional<int64_t> usage_now) {
    // The usage fold rides in the same transaction (EchoFold::fold_rows' `extra`): a failure of
    // either rolls both back, and the caller re-offers the same events to both.
    EchoFold::ExtraFn usage_fold;
    if (!events.empty()) {
        const int64_t now = usage_now.value_or(now_epoch_seconds());
        usage_fold = [&events, now](TransactionHandle& h) {
            return usage::usage_fold_in(h, now, events);
        };
    }
    return fold_batch(*this, fold_.get(), "process", events.empty(), state,
                      [&](TierAccumulator& acc) { process_delta(events, acc); }, usage_fold);
}

bool EchoDatabase::fold_network_events(const std::vector<NetworkEvent>& events,
                                       const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "tcp", events.empty(), state,
                      [&](TierAccumulator& acc) { tcp_delta(events, acc); });
}

bool EchoDatabase::fold_service_events(const std::vector<ServiceEvent>& events,
                                       const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "service", events.empty(), state,
                      [&](TierAccumulator& acc) { service_delta(events, acc); });
}

bool EchoDatabase::fold_user_events(const std::vector<UserEvent>& events,
                                    const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "user", events.empty(), state,
                      [&](TierAccumulator& acc) { user_delta(events, acc); });
}

bool EchoDatabase::fold_software_events(const std::vector<SoftwareEvent>& events,
                                        const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "software", events.empty(), state,
                      [&](TierAccumulator& acc) { software_delta(events, acc); });
}

bool EchoDatabase::fold_arp_events(const std::vector<ArpEvent>& events,
                                   const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "arp", events.empty(), state,
                      [&](TierAccumulator& acc) { arp_delta(events, acc); });
}

bool EchoDatabase::fold_dns_events(const std::vector<DnsEvent>& events,
                                   const std::optional<StateWrite>& state) {
    return fold_batch(*this, fold_.get(), "dns", events.empty(), state,
                      [&](TierAccumulator& acc) { dns_delta(events, acc); });
}

bool EchoDatabase::fold_mapdrive_events(const std::vector<MapDriveEvent>& events,
                                        const std::optional<StateWrite>& state,
                                        bool skip_known_historical) {
    // A `historical` event is a one-time backfill of a mapping the host already had, and its count
    // is ADDITIVE: folding the same mapping twice counts it twice. The raw store stopped that by
    // asking "does a historical row of this identity exist?"; there is no raw row now, so the
    // identity of every historical mapping folded is remembered, as a hash of (direction,
    // local_mount, remote_path, remote_host, username) -- the username is personal data and never
    // stored in the clear -- in the replay ring's table, in the SAME transaction as its count.
    // Under skip_known_historical (the bounded per-profile retry's own call) a mapping already
    // remembered is skipped, and so is a repeat inside the batch.
    std::vector<MapDriveEvent> fold_these;
    std::vector<std::string> new_keys;
    {
        std::unordered_set<std::string> known;
        std::vector<std::string> keyed(events.size()); // empty for a non-historical event
        std::string in_list;
        int n_keys = 0;
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (events[i].origin != "historical")
                continue;
            const auto& e = events[i];
            keyed[i] = identity_hex({e.direction, e.local_mount, e.remote_path, e.remote_host, e.username});
            in_list += (n_keys++ ? ",'" : "'") + keyed[i] + "'"; // hex digits only: safe to interpolate
        }
        if (skip_known_historical && n_keys > 0) {
            const auto rows = execute_query(
                std::format("SELECT record_key FROM {} WHERE source = '{}' AND record_key IN ({})",
                            kSeenTable, kMapdriveHistoricalSource, in_list),
                n_keys + 1);
            if (!rows) {
                spdlog::error("EchoDatabase: fold_mapdrive_events: the known-mapping lookup failed: {}",
                              rows.error());
                return false;
            }
            for (const auto& r : rows->rows)
                known.insert(r.at(0));
        }
        std::unordered_set<std::string> in_batch;
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (events[i].origin != "historical") {
                fold_these.push_back(events[i]);
                continue;
            }
            const bool repeat = !in_batch.insert(keyed[i]).second;
            if (skip_known_historical && (repeat || known.contains(keyed[i])))
                continue;
            fold_these.push_back(events[i]);
            if (!repeat)
                new_keys.push_back(keyed[i]);
        }
    }

    EchoFold::ExtraFn remember;
    if (!new_keys.empty()) {
        remember = [&new_keys, skip_known_historical](TransactionHandle& h) -> std::expected<void, std::string> {
            sqlite3_stmt* raw = nullptr;
            if (sqlite3_prepare_v2(h.raw(),
                                   std::format("INSERT INTO {} (source, record_key, digest, seq) "
                                               "VALUES ('{}', ?, 0, 0) ON CONFLICT DO NOTHING "
                                               "RETURNING record_key",
                                               kSeenTable, kMapdriveHistoricalSource)
                                       .c_str(),
                                   -1, &raw, nullptr) != SQLITE_OK) {
                h.fail(std::string("prepare failed: ") + sqlite3_errmsg(h.raw()));
                return std::unexpected(h.error());
            }
            StmtPtr stmt(raw); // finalised on every exit, before the caller commits
            for (const auto& key : new_keys) {
                // Back to ready (drops the previous pass's RETURNING row); the one parameter is rebound.
                sqlite3_reset(stmt.get());
                sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
                const int rc = sqlite3_step(stmt.get());
                if (rc == SQLITE_DONE) { // already remembered
                    if (skip_known_historical) { // ... between the lookup and the fold: do not count it twice
                        h.fail("a historical mapping was recorded between the lookup and the fold");
                        return std::unexpected(h.error());
                    }
                    continue;
                }
                if (rc != SQLITE_ROW) {
                    h.fail(std::string("step failed: ") + sqlite3_errmsg(h.raw()));
                    return std::unexpected(h.error());
                }
            }
            return {};
        };
    }
    return fold_batch(*this, fold_.get(), "mapdrive", fold_these.empty(), state,
                      [&](TierAccumulator& acc) { mapdrive_delta(fold_these, acc); }, remember);
}

bool EchoDatabase::fold_perf_sample(const PerfRow& row) {
    return fold_batch(*this, fold_.get(), "perf", false, std::nullopt,
                      [&](TierAccumulator& acc) { perf_delta(std::vector<PerfRow>{row}, acc); });
}

bool EchoDatabase::fold_proc_perf_samples(const std::vector<ProcPerfRow>& rows) {
    return fold_batch(*this, fold_.get(), "procperf", rows.empty(), std::nullopt,
                      [&](TierAccumulator& acc) { procperf_delta(rows, acc); });
}

bool EchoDatabase::fold_netqual_samples(const std::vector<NetQualRow>& rows) {
    return fold_batch(*this, fold_.get(), "netqual", rows.empty(), std::nullopt,
                      [&](TierAccumulator& acc) { netqual_delta(rows, acc); });
}

bool EchoDatabase::fold_netconn_events(const std::vector<NetConnRow>& rows) {
    return fold_batch(*this, fold_.get(), "netconn", rows.empty(), std::nullopt,
                      [&](TierAccumulator& acc) { netconn_delta(rows, acc); });
}

bool EchoDatabase::fold_module_events(const std::vector<ModuleRow>& rows) {
    return fold_batch(*this, fold_.get(), "module", rows.empty(), std::nullopt,
                      [&](TierAccumulator& acc) { module_delta(rows, acc); });
}

bool EchoDatabase::insert_netqual_boot_row(const NetQualBootRow& row) {
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

std::expected<QueryResult, std::string> EchoDatabase::execute_query(const std::string& sql,
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

std::expected<QueryResult, std::string> EchoDatabase::execute_user_query(const std::string& sql,
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

bool EchoDatabase::execute_sql(const std::string& sql) {
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

EchoDatabase::BatchResult
EchoDatabase::execute_atomic_batch(const std::vector<std::string>& statements) {
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
        spdlog::error("EchoDatabase::execute_atomic_batch BEGIN failed: {}", err.text());
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
        // deleted, and echo.db grew without bound on the endpoint behind a single
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
        spdlog::error("EchoDatabase::execute_atomic_batch statement failed: {} (rc={}, {})",
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
        spdlog::error("EchoDatabase::execute_atomic_batch COMMIT failed: {}", err.text());
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
            // EchoDatabase method already has, so all of them fail closed at once.
            //
            // close_v2 rather than close: it detaches immediately and defers
            // deallocation until any outstanding statements finalize, so this is
            // safe even though callers elsewhere may still hold prepared
            // statements. We hold `mu_`, and every primary-connection method
            // takes `mu_`, so no other thread is mid-statement here.
            spdlog::error("EchoDatabase: ROLLBACK failed and the connection is STILL in a "
                          "transaction ({}). Closing the Echo database: further writes would be "
                          "reported as durable and then lost. Echo storage is offline on this "
                          "endpoint until the agent restarts.",
                          err.text());
            sqlite3_close_v2(db_);
            db_ = nullptr;
        } else {
            spdlog::debug("EchoDatabase::execute_atomic_batch ROLLBACK: {}", err.text());
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

std::expected<void, std::string> EchoDatabase::checked_transaction(
    const std::function<std::expected<void, std::string>(TransactionHandle&)>& operation) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected("database not open");

    SqliteErrMsg err;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, err.addr()) != SQLITE_OK) {
        spdlog::error("EchoDatabase::checked_transaction BEGIN failed: {}", err.text());
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
        spdlog::error("EchoDatabase::checked_transaction COMMIT failed: {}", err.text());
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
        spdlog::error("EchoDatabase: checked_transaction ROLLBACK failed and the connection is "
                      "STILL in a transaction ({}). Closing the Echo database: further writes "
                      "would be reported as durable and then lost. Echo storage is offline on "
                      "this endpoint until the agent restarts.",
                      err.text());
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
    return std::unexpected(failure_reason);
}

bool EchoDatabase::execute_sql_range(const std::string& sql, int64_t from, int64_t to) {
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

// ── Storage budget primitives ───────────────────────────────────────────────

StorageBytes EchoDatabase::storage_bytes() {
    std::lock_guard lock(mu_);
    return storage_bytes_locked();
}

StorageBytes EchoDatabase::storage_bytes_locked() {
    StorageBytes out{};
    if (!db_)
        return out;

    const char* sql = "SELECT (SELECT page_count FROM pragma_page_count()), "
                      "(SELECT freelist_count FROM pragma_freelist_count()), "
                      "(SELECT page_size FROM pragma_page_size()), "
                      "(SELECT auto_vacuum FROM pragma_auto_vacuum())";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
        StmtPtr stmt(raw_stmt);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            out.page_count = sqlite3_column_int64(stmt.get(), 0);
            out.freelist_count = sqlite3_column_int64(stmt.get(), 1);
            out.page_size = sqlite3_column_int64(stmt.get(), 2);
            out.auto_vacuum = sqlite3_column_int64(stmt.get(), 3);
            out.ok = true;
        }
    }

    // The WAL file lives beside the main file; sqlite3_db_filename names the main file only. An
    // unreadable log is a failed measurement, not an empty one (B6): `ok` goes false.
    if (const char* main_file = sqlite3_db_filename(db_, "main"); main_file && *main_file) {
        if (const auto wal = wal_file_bytes(main_file))
            out.wal_bytes = *wal;
        else
            out.ok = false;
    }
    return out;
}

std::optional<int64_t> wal_file_bytes(const std::filesystem::path& main_file) {
    const std::filesystem::path wal{main_file.string() + "-wal"};
    std::error_code ec;
    // Only a regular file has a size: file_size() of a directory succeeds on Windows (it is an
    // error on POSIX), and a log that is not a file must fail the measurement, never read as 0.
    const auto type = std::filesystem::status(wal, ec).type();
    if (type == std::filesystem::file_type::not_found)
        return 0;
    if (ec || type != std::filesystem::file_type::regular)
        return std::nullopt;
    const auto size = std::filesystem::file_size(wal, ec);
    if (ec)
        return std::nullopt;
    return static_cast<int64_t>(size);
}

std::expected<int64_t, std::string> EchoDatabase::delete_counted(const std::string& sql,
                                                                 std::string_view counter_key) {
    int64_t deleted = 0;
    const auto result = checked_transaction(
        [&](TransactionHandle& h) -> std::expected<void, std::string> {
            sqlite3_stmt* raw_stmt = nullptr;
            if (sqlite3_prepare_v2(h.raw(), sql.c_str(), -1, &raw_stmt, nullptr) != SQLITE_OK) {
                h.fail(sqlite3_errmsg(h.raw()));
                return std::unexpected(h.error());
            }
            StmtPtr stmt(raw_stmt);
            // RETURNING rows are the count (never sqlite3_changes(), #1033).
            int64_t rows = 0;
            int rc = SQLITE_OK;
            while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW)
                ++rows;
            if (rc != SQLITE_DONE) {
                h.fail(sqlite3_errmsg(h.raw()));
                return std::unexpected(h.error());
            }
            stmt.reset(); // finalize before the bump so no statement is pending at COMMIT

            if (rows > 0) {
                const std::string n = std::to_string(rows);
                const std::string key{counter_key};
                sqlite3_stmt* raw_bump = nullptr;
                if (sqlite3_prepare_v2(
                        h.raw(),
                        "INSERT INTO echo_config (key, value) VALUES (?1, ?2) "
                        "ON CONFLICT(key) DO UPDATE SET "
                        "value = CAST(value AS INTEGER) + CAST(excluded.value AS INTEGER)",
                        -1, &raw_bump, nullptr) != SQLITE_OK) {
                    h.fail(sqlite3_errmsg(h.raw()));
                    return std::unexpected(h.error());
                }
                StmtPtr bump(raw_bump);
                sqlite3_bind_text(bump.get(), 1, key.c_str(), static_cast<int>(key.size()),
                                  SQLITE_STATIC);
                sqlite3_bind_text(bump.get(), 2, n.c_str(), static_cast<int>(n.size()),
                                  SQLITE_STATIC);
                if (sqlite3_step(bump.get()) != SQLITE_DONE) {
                    h.fail(sqlite3_errmsg(h.raw()));
                    return std::unexpected(h.error());
                }
            }
            deleted = rows;
            return {};
        });
    if (!result)
        return std::unexpected(result.error());
    return deleted;
}

bool EchoDatabase::incremental_vacuum(int pages) {
    std::lock_guard lock(mu_);
    if (!db_ || pages <= 0)
        return false;
    SqliteErrMsg err;
    if (sqlite3_exec(db_, std::format("PRAGMA incremental_vacuum({})", pages).c_str(), nullptr,
                     nullptr, err.addr()) != SQLITE_OK) {
        spdlog::warn("EchoDatabase: incremental_vacuum failed: {}", err.text());
        return false;
    }
    return true;
}

CheckpointResult EchoDatabase::checkpoint(CheckpointMode mode) {
    std::lock_guard lock(mu_);
    if (!db_)
        return CheckpointResult::kError;
    // Busy timeout 0 for this call: a TRUNCATE checkpoint that cannot restart the WAL because
    // a reader (the read-only echo.sql connection) pins it would otherwise sleep for the whole
    // 5 s timeout with mu_ held, stalling every collector. The caller retries next pass.
    sqlite3_busy_timeout(db_, 0);
    const int rc = sqlite3_wal_checkpoint_v2(
        db_, nullptr,
        mode == CheckpointMode::kTruncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
        nullptr, nullptr);
    sqlite3_busy_timeout(db_, kBusyTimeoutMs);
    if (rc == SQLITE_OK)
        return CheckpointResult::kOk;
    if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)
        return CheckpointResult::kBusy;
    spdlog::warn("EchoDatabase: WAL checkpoint returned {}", rc);
    return CheckpointResult::kError;
}

bool EchoDatabase::vacuum_to_incremental() {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;
    SqliteErrMsg err;
    if (sqlite3_exec(db_, "PRAGMA auto_vacuum=INCREMENTAL", nullptr, nullptr, err.addr()) !=
        SQLITE_OK) {
        spdlog::warn("EchoDatabase: VACUUM conversion: auto_vacuum pragma failed: {}", err.text());
        return false;
    }
    if (sqlite3_exec(db_, "VACUUM", nullptr, nullptr, err.addr()) != SQLITE_OK) {
        spdlog::warn("EchoDatabase: VACUUM failed: {}", err.text());
        return false;
    }
    return true;
}

void EchoDatabase::rollback_open_transaction() noexcept {
    try {
        std::lock_guard lock(mu_);
        sqlite3* db = db_;
        if (!db || sqlite3_get_autocommit(db) != 0)
            return;
        const int rc = sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        // Ask, never assume (the same rule checked_transaction applies): a ROLLBACK that reports an
        // error may mean SQLite already ended the transaction, or that the connection is stuck
        // inside one. A stuck connection would report every later write durable and lose it at
        // close, so it is closed -- every method then fails closed through its `if (!db_)` test.
        if (sqlite3_get_autocommit(db) == 0) {
            spdlog::error("EchoDatabase: ROLLBACK after an exception failed (rc={}) and the "
                          "connection is STILL in a transaction. Closing the Echo database: further "
                          "writes would be reported as durable and then lost. Echo storage is "
                          "offline on this endpoint until the agent restarts.",
                          rc);
            sqlite3_close_v2(db);
            db_ = nullptr;
            return;
        }
        if (rc == SQLITE_OK)
            spdlog::warn("EchoDatabase: rolled back a transaction left open by an exception");
        else
            spdlog::warn("EchoDatabase: ROLLBACK after an exception reported rc={} but the "
                         "transaction had ended",
                         rc);
    } catch (...) {
        // noexcept containment: a failed lock or log must not escape the catch handler.
    }
}

} // namespace yuzu::echo
