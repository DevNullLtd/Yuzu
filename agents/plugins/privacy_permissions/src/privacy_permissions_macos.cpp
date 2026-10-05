/**
 * privacy_permissions_macos.cpp -- macOS leg: TCC.db read-only, in-process: opened once by
 * descriptor, then sqlite3 over /dev/fd/N with immutable=1 (no lock, no -journal/-wal/-shm ever
 * opened or created) + PRAGMA query_only -- never a `sqlite3` CLI shellout.
 *
 * TWO KINDS OF SOURCE, both read the same way:
 *   - the SYSTEM db, /Library/Application Support/com.apple.TCC/TCC.db -- machine-wide
 *     services (full_disk_access); rows unqualified.
 *   - one PER-USER db per real home, /Users/<name>/Library/Application Support/com.apple.TCC/
 *     TCC.db -- camera and microphone grants normally live HERE, not in the system db (measured
 *     on this Mac, 2026-09-23: the per-user db held kTCCServiceMicrophone rows the system db
 *     never has; an MDM PPPC payload can add rows to the system db). Rows are qualified
 *     `<name>\<client>` (qualify_app_id, the same shape the Windows leg uses per profile).
 *     Homes are enumerated the autoruns_macos.cpp collect_user_launchagents way: directories
 *     directly under /Users, not followed through a symlink, owned by uid >= 500, the directory
 *     name as the user name (no Open Directory call).
 * A per-user db that does not exist is `absent` for that user; a refusal (EPERM/EACCES on the
 * open, SQLITE_AUTH/PERM, or SQLITE_CANTOPEN whose underlying syscall failed
 * EPERM/EACCES on a file that IS there) is `denied`; anything else -- including a failed
 * `PRAGMA query_only` or query bind -- is `unreadable` with a `<source>:<cause>` token
 * (macos_parsers.hpp decides; this file only reads).
 *
 * RESIDUALS, stated rather than assumed away:
 *   - Every TCC.db (system AND per-user) is TCC-protected. An agent identity without Full Disk
 *     Access reads `denied` for every source -- the expected outcome, recorded
 *     honestly; the production LaunchDaemon (root) is not known to hold FDA today.
 *   - A home outside /Users (a relocated or network home) is not read, and a user whose home
 *     directory is directly under /Users but owned by a uid < 500 is skipped as a system entry.
 *   - A per-user db is hostile input (its user owns it). It is REFUSED, never guessed, when it is
 *     not a regular file of plausible size, not SQLite, WAL-mode, has a -journal/-wal/-shm beside
 *     it, or changes while read (an immutable read ignores exactly that state): so a concurrent
 *     tccd commit reads `unreadable`. O_NOFOLLOW_ANY refuses a symlink anywhere in the path, and
 *     the open is the first syscall on it. Change detection sees write(2)-style writers (ctime);
 *     an owner holding a MAP_SHARED mapping is not seen -- the owner authors every row anyway.
 *     Schema text, rows per service, value and retained-text size, and time (per source and per
 *     run) are bounded; the clock starts before the open, but only SQLite's progress handler and
 *     the loop checks enforce it, so it does NOT interrupt open/read syscalls (README caveat 3).
 *     SQLite may spill a hostile query's temp data to $TMPDIR within that budget.
 *   - The `access` schema and `auth_value` mapping (0=denied/2=allowed/3=limited) are the
 *     commonly-documented shape, proven on macOS 26.6.2 only; any other value is
 *     prompt_undetermined, never guessed.
 *
 * `location` is NOT queried here at all -- ADR-3003's platform investigation
 * established macOS Location Services is administered by `locationd`, OUTSIDE TCC; it ships as
 * one explicit `unsupported` row on every collection, whatever else failed.
 *
 * REAL PROBE, this Mac (`braga`, macOS 26.6.2), 2026-09-22, via the unit test binary's own
 * ambient identity (a Terminal/VSCode-launched process with FDA, NOT the production agent
 * identity): open + query against the system db's `access` table returned real
 * `full_disk_access` rows (auth_value 2 and 0).
 */
#include "privacy_permissions_legs.hpp"

#if defined(__APPLE__)

#include "privacy_permissions_macos_parsers.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <unistd.h>

#include <sqlite3.h>

#include <posix_dir_walk.hpp>
#include <yuzu/agent/scoped_fd.hpp>

namespace yuzu::privacy_permissions {

namespace {

static_assert(macos::kSqlitePerm == SQLITE_PERM);
static_assert(macos::kSqliteCantOpen == SQLITE_CANTOPEN);
static_assert(macos::kSqliteAuth == SQLITE_AUTH);

constexpr std::string_view kTccDbPath = "/Library/Application Support/com.apple.TCC/TCC.db";
constexpr std::string_view kUsersDir = "/Users";
constexpr std::string_view kUserTccRelPath = "/Library/Application Support/com.apple.TCC/TCC.db";
// Outer cap on /Users entries -- the same bounded-walk shape autoruns uses for its own /Users
// walk; a host with more than this many entries reports `users:truncated`, never silently.
constexpr std::size_t kMaxUserHomes = 4096;

struct DbCloser {
    void operator()(sqlite3* db) const noexcept { sqlite3_close(db); }
};
struct StmtFinalizer {
    void operator()(sqlite3_stmt* stmt) const noexcept { sqlite3_finalize(stmt); }
};
using DbPtr = std::unique_ptr<sqlite3, DbCloser>;
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtFinalizer>;

/// The sqlite progress handler's state; it must outlive the connection it is installed on.
struct Deadline {
    std::chrono::steady_clock::time_point end;
    bool fired = false;
    bool expired() noexcept { return fired = fired || std::chrono::steady_clock::now() >= end; }
};

/// sqlite3_errmsg, or a fixed literal when sqlite3 could not even allocate a handle. The text can
/// echo hostile schema identifiers, so it is cut, scrubbed and stripped of control characters and
/// line separators (U+2028/2029). `|`, `\` and `,` become `/` here, once: this text is also a
/// comma-joined provenance token, so it must be delimiter-free before format_row's own escape
/// ever runs (a second escape would only mangle it).
std::string sqlite_errmsg(sqlite3* db) {
    if (!db) return "no_handle";
    auto msg = sanitize_utf8(std::string_view{sqlite3_errmsg(db)}.substr(0, 200));
    for (std::size_t i = 0; i < msg.size(); ++i) {
        const auto c = static_cast<unsigned char>(msg[i]);
        if (c < 0x20 || c == 0x7F) msg[i] = ' ';
        else if (c == '|' || c == '\\' || c == ',') msg[i] = '/';
        else if (msg.compare(i, 3, "\xE2\x80\xA8") == 0 || msg.compare(i, 3, "\xE2\x80\xA9") == 0)
            msg.replace(i, 3, " ");
    }
    return msg;
}

/// Opens `db_path` read-only through an immutable URI (no lock, so no
/// busy timeout either), bounds the schema parse, applies sqlite's untrusted-database posture and
/// makes the connection query-only. `deadline`, when given, is installed before the first prepare.
/// On failure returns the SourceFailure -- classified by
/// macos::classify_tcc_sqlite_failure from the real result code, the VFS's own failed-syscall
/// errno (sqlite3_system_errno) and sqlite3_errmsg, never a guessed diagnostic. A failed
/// `PRAGMA query_only=1` is a failure too: the source is never read without it. A unit test
/// can force the open-failure branch with a path this process genuinely cannot open.
std::expected<DbPtr, macos::SourceFailure> open_readonly(std::string_view db_path,
                                                         Deadline* deadline = nullptr) {
    sqlite3* raw = nullptr;
    const int rc = sqlite3_open_v2(macos::immutable_uri(db_path).c_str(), &raw,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX,
                                   nullptr);
    DbPtr db{raw}; // owns `raw` even on failure -- sqlite3 may allocate a handle just to
                   // carry the error message; RAII from here regardless of `rc`.
    if (rc != SQLITE_OK) {
        // The EXTENDED code: sqlite3_open_v2 returns only the primary one.
        return std::unexpected(macos::classify_tcc_sqlite_failure(
            macos::SqliteStage::open, db ? sqlite3_extended_errcode(db.get()) : rc,
            db ? sqlite3_system_errno(db.get()) : 0, sqlite_errmsg(db.get())));
    }
    // The schema is parsed at the first prepare, before any per-value limit could apply.
    sqlite3_limit(db.get(), SQLITE_LIMIT_LENGTH, macos::kMaxSchemaBytes);
    sqlite3_limit(db.get(), SQLITE_LIMIT_SQL_LENGTH, macos::kMaxSchemaBytes);
    if (sqlite3_db_config(db.get(), SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr) != SQLITE_OK ||
        sqlite3_db_config(db.get(), SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr) != SQLITE_OK) {
        return std::unexpected(
            macos::SourceFailure{macos::SourceOutcome::unreadable, "hardening_failed"});
    }
    if (deadline) {
        const auto check = +[](void* d) noexcept -> int {
            return static_cast<Deadline*>(d)->expired();
        };
        sqlite3_progress_handler(db.get(), 1000, check, deadline);
    }
    const int pragma_rc = sqlite3_exec(db.get(), "PRAGMA query_only=1; PRAGMA cell_size_check=ON",
                                       nullptr, nullptr, nullptr);
    if (pragma_rc != SQLITE_OK) {
        return std::unexpected(macos::classify_tcc_sqlite_failure(
            macos::SqliteStage::query_only, pragma_rc, sqlite3_system_errno(db.get()),
            sqlite_errmsg(db.get())));
    }
    return db;
}

/// Owns the DIR* fdopendir() returns; closedir() also closes the fd it adopted.
using DirHandle = std::unique_ptr<DIR, int (*)(DIR*)>;

/// One descriptor's state: fstat, and the SQLite header when it is a regular file.
struct FdSnapshot {
    macos::FileStamp stamp;
    bool regular = false;
    std::array<unsigned char, macos::kSqliteHeaderBytes> header{};
    std::size_t header_len = 0;
};

std::optional<FdSnapshot> snapshot_fd(int fd) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) return std::nullopt;
    FdSnapshot s;
    if ((s.regular = S_ISREG(st.st_mode))) {
        const ssize_t n = ::pread(fd, s.header.data(), s.header.size(), 0);
        if (n < 0) return std::nullopt;
        s.header_len = static_cast<std::size_t>(n);
    }
    s.stamp = {st.st_ino,
               st.st_size,
               st.st_mtimespec.tv_sec,
               st.st_mtimespec.tv_nsec,
               macos::header_change_counter({s.header.data(), s.header_len}),
               st.st_ctimespec.tv_sec,
               st.st_ctimespec.tv_nsec};
    return s;
}

/// True when a journal/WAL/shm file sits beside `name` in `dirfd`, or its absence cannot be shown.
/// fstatat with AT_SYMLINK_NOFOLLOW never opens its target (a planted FIFO is reported, not
/// opened) and resolves nothing but the one name against a directory descriptor the caller
/// already holds, so an owner swapping a path component for a symlink into a hung mount cannot
/// redirect it.
///
/// Test-coverage gap, stated rather than assumed away: the `errno != ENOENT && errno != ENOTDIR`
/// branch (a refused sidecar stat reported as "present", the conservative direction) has no direct
/// test; every other outcome is covered by the internals "not one quiescent rollback-mode SQLite
/// file" case.
bool sidecar_present(int dirfd, const std::string& name) {
    for (const auto suffix : macos::kSidecarSuffixes) {
        struct stat st{};
        if (::fstatat(dirfd, (name + std::string{suffix}).c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 ||
            (errno != ENOENT && errno != ENOTDIR))
            return true;
    }
    return false;
}

/// The per-service query over one prepared statement. A read that hits a bound stops there with
/// `cut` set and keeps what it had; `source` counts the scrubbed client text kept by the source.
std::vector<macos::TccServiceRead> read_services(sqlite3_stmt* stmt, Deadline& deadline,
                                                 std::size_t row_cap) {
    std::vector<macos::TccServiceRead> reads;
    yuzu::shared::RowByteBudget source{yuzu::shared::RowByteBudget::npos, macos::kMaxSourceBytes};
    for (const auto& svc : macos::kTccServices) {
        macos::TccServiceRead read{svc.category, {}, false, false, {}};
        if (deadline.expired()) {
            read.cut = macos::kCutTimeout;
            reads.push_back(std::move(read));
            continue;
        }
        sqlite3_reset(stmt); // a prior step failure is already recorded on its own read
        if (sqlite3_bind_text(stmt, 1, svc.service.data(), static_cast<int>(svc.service.size()),
                              SQLITE_STATIC) != SQLITE_OK) {
            read.bind_failed = true; // never run the statement with a stale or missing binding
            reads.push_back(std::move(read));
            continue;
        }
        for (;;) {
            const int step_rc = sqlite3_step(stmt);
            if (step_rc == SQLITE_DONE) break;
            if (step_rc != SQLITE_ROW) {
                if (deadline.fired) read.cut = macos::kCutTimeout;
                else if (step_rc == SQLITE_TOOBIG) read.cut = macos::kCutValueOversized;
                else read.step_failed = true;
                break;
            }
            if (read.grants.size() >= row_cap) {
                read.cut = macos::kCutRowCap;
                break;
            }
            const bool client_null = sqlite3_column_type(stmt, 1) == SQLITE_NULL;
            const auto* client = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (!client_null && client == nullptr) { // sqlite ran out of memory: not a NULL client
                read.step_failed = true;
                break;
            }
            std::optional<std::int64_t> auth_value;
            if (sqlite3_column_type(stmt, 2) == SQLITE_INTEGER)
                auth_value = sqlite3_column_int64(stmt, 2);
            // Scrubbed here so both output budgets count the bytes that reach the wire.
            // The whole column, by length: an embedded NUL must not truncate a client to its prefix
            // (`a\0x` and `a\0y` would collapse), and a NUL never reaches a row.
            std::string raw_text =
                client_null ? "-"
                            : std::string(client, static_cast<std::size_t>(
                                                      sqlite3_column_bytes(stmt, 1)));
            std::replace(raw_text.begin(), raw_text.end(), '\0', '?');
            auto text = sanitize_utf8(raw_text);
            if (!source.charge(text.size())) { // per-source bytes; non-sticky, as before
                read.cut = macos::kCutByteCap;
                break;
            }
            read.grants.push_back({std::move(text), auth_value});
        }
        macos::sort_grants(read.grants);
        reads.push_back(std::move(read));
    }
    return reads;
}

/// Reads ONE TCC.db source (`owner` empty = the system db) into `rows`. Every outcome lands as
/// rows: a whole-source row when the file is missing/refused/unopenable/unpreparable or not one
/// quiescent rollback-mode SQLite file, else every mapped category's rows
/// (macos::append_tcc_source_rows).
///
/// Untested gaps (no fault-injection seam): `read_failed` (fstat/pread on a descriptor that just
/// opened) and `hardening_failed` (sqlite3_db_config refusing a documented option).
void read_tcc_source(std::string_view owner, const std::string& path, bool missing_is_absent,
                     std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc,
                     const macos::ReadBounds& bounds = {}) {
    const auto fail = [&](macos::SourceFailure f) {
        rows.push_back(macos::tcc_source_failed_row(owner, f, acc));
    };
    constexpr auto unreadable = macos::SourceOutcome::unreadable;
    // Before ANY syscall on the path: a network-backed mount is never touched.
    if (macos::path_under_network_mount(path, bounds.mounts))
        return fail({unreadable, "network_mount"});
    const auto now = std::chrono::steady_clock::now();
    if (now >= bounds.run_end) return fail({unreadable, std::string{macos::kCutTimeout}});

    // The open is the FIRST syscall on the path. O_NOFOLLOW_ANY refuses a symlink anywhere in it
    // (ELOOP) without traversing it, so a link into a hung mount is never followed -- an lstat
    // would follow intermediate links -- and a dangling link reads `unreadable`, not `absent`. The
    // parent directory is opened once and the database and its sidecars are then named relative to
    // that descriptor: no later syscall re-resolves the path, so it cannot be re-pointed.
    const auto slash = path.rfind('/');
    const std::string parent =
        slash == std::string::npos ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    const auto open_failed = [&](int err) {
        return fail(err == ENOENT || err == ENOTDIR ? macos::classify_tcc_missing(missing_is_absent)
                                                    : macos::classify_tcc_open_errno(err));
    };
    yuzu::agent::ScopedFd dirfd{::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)};
    if (!dirfd) return open_failed(errno);
    yuzu::agent::ScopedFd fd{
        ::openat(dirfd.get(), name.c_str(), O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)};
    if (!fd) return open_failed(errno);
    if (sidecar_present(dirfd.get(), name)) return fail({unreadable, "sidecar_present"});
    const auto first = snapshot_fd(fd.get());
    if (!first) return fail({unreadable, "read_failed"});
    if (const auto f = macos::classify_tcc_file(first->regular, first->stamp.size)) return fail(*f);
    if (const auto f = macos::classify_tcc_header({first->header.data(), first->header_len}))
        return fail(*f);

    // Declared before `db`, so the progress handler's state outlives the connection.
    Deadline deadline{std::min(bounds.run_end, now + bounds.source_budget)};
    auto opened = open_readonly("/dev/fd/" + std::to_string(fd.get()), &deadline);
    if (!opened) return fail(std::move(opened.error()));
    const DbPtr db = std::move(*opened);

    sqlite3_stmt* raw_stmt = nullptr;
    static constexpr char kQuery[] =
        "SELECT service, client, auth_value FROM access WHERE service = ?";
    const int prep_rc = sqlite3_prepare_v2(db.get(), kQuery, -1, &raw_stmt, nullptr);
    const StmtPtr stmt{raw_stmt}; // owns it from here -- finalized on every path
    if (prep_rc != SQLITE_OK) {
        // A TCC refusal can surface lazily, at the first page read, as CANTOPEN/AUTH --
        // classified the same as an open failure, never a flat `unreadable`.
        if (deadline.fired) return fail({unreadable, std::string{macos::kCutTimeout}});
        return fail(macos::classify_tcc_sqlite_failure(
            macos::SqliteStage::prepare, sqlite3_extended_errcode(db.get()),
            sqlite3_system_errno(db.get()), sqlite_errmsg(db.get())));
    }
    // Only now that the schema has loaded: tighten to the per-value bound.
    sqlite3_limit(db.get(), SQLITE_LIMIT_LENGTH, macos::kMaxValueBytes);

    const auto reads = read_services(stmt.get(), deadline, bounds.row_cap);
    const auto last = snapshot_fd(fd.get());
    if (!last) return fail({unreadable, "read_failed"});
    if (first->stamp != last->stamp)
        return fail({unreadable, "changed_during_read"});
    if (sidecar_present(dirfd.get(), name)) return fail({unreadable, "sidecar_present"});
    macos::append_tcc_source_rows(owner, reads, rows, acc);
}

/// Real per-user homes directly under `users_dir` (autoruns_macos.cpp's
/// collect_user_launchagents rule, decided by macos::is_user_home_entry): a directory entry, not
/// a symlink, owned by uid >= 500, named by the directory itself. Failures that lose a whole
/// user or the whole walk are reported as rows (never silence); the returned names are sorted
/// for stable output. The fd and the DIR* are RAII-owned on every path.
///
/// Untested gaps: `users:fdopendir_errno_<n>`, `<user>:home_stat_errno_<n>`,
/// `<user>:home_vanished` and `users:readdir_error` (no fault-injection seam) and
/// `users:truncated` (`kMaxUserHomes` is not injected).
std::vector<std::string> enumerate_user_homes(std::vector<PermissionRow>& rows,
                                              yuzu::shared::ConstraintAccumulator& acc,
                                              const std::string& users_dir = std::string{kUsersDir},
                                              std::span<const macos::MountEntry> mounts = {}) {
    std::vector<std::string> names;
    if (macos::path_under_network_mount(users_dir, mounts)) {
        rows.push_back(failure_row("macos", "-", "-", false, "users:network_mount", acc));
        return names;
    }
    yuzu::agent::ScopedFd fd{
        ::open(users_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (!fd) {
        const int err = errno;
        rows.push_back(failure_row("macos", "-", "-", err == EPERM || err == EACCES,
                                   "users:open_errno_" + std::to_string(err), acc));
        return names;
    }
    DirHandle dir{::fdopendir(fd.get()), ::closedir};
    if (!dir) {
        const int err = errno;
        rows.push_back(failure_row("macos", "-", "-", false,
                                   "users:fdopendir_errno_" + std::to_string(err), acc));
        return names; // `fd` still owns the descriptor and closes it
    }
    static_cast<void>(fd.release()); // the DIR* adopted the fd; closedir() closes it
    const auto walk = yuzu::shared::walk_dir_capped(dir.get(), kMaxUserHomes,
                                                    [&](const struct dirent* e) {
        const std::string name{e->d_name};
        if (!macos::home_name_eligible(name)) return true;
        // A home that is itself a network mount point: even the fstatat below would block on it.
        if (macos::path_under_network_mount(users_dir + "/" + name, mounts)) {
            rows.push_back(failure_row("macos", qualify_app_id(name, "-"), "-", false,
                                       macos::token_safe(name) + ":network_mount", acc));
            return true;
        }
        struct stat st{};
        if (::fstatat(::dirfd(dir.get()), e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            const int err = errno;
            // A home that vanished between readdir and fstatat (renamed or removed under us) is
            // named, not dropped: a user missing from an OK/FULL run is a silent coverage loss.
            const std::string cause = err == ENOENT ? "home_vanished"
                                                    : "home_stat_errno_" + std::to_string(err);
            rows.push_back(failure_row("macos", qualify_app_id(name, "-"), "-",
                                       err == EPERM || err == EACCES,
                                       macos::token_safe(name) + ":" + cause, acc));
            return true;
        }
        if (macos::is_user_home_entry(name, S_ISDIR(st.st_mode),
                                      static_cast<std::uint32_t>(st.st_uid)))
            names.push_back(name);
        return true;
    });
    if (walk.truncated)
        rows.push_back(failure_row("macos", "-", "-", false, "users:truncated", acc));
    if (walk.enumeration_error)
        rows.push_back(failure_row("macos", "-", "-", false, "users:readdir_error", acc));
    std::sort(names.begin(), names.end());
    return names;
}

/// getmntinfo_r_np's shape: a caller-owned array, so no process-wide buffer is shared with the
/// other getmntinfo callers on the dispatch pool (disk_actions, filesystem_posture). A parameter
/// so a unit test can supply the table and observe the call.
using MountFetch = int (*)(struct statfs**, int);

/// The mount table, once per run, from the kernel's cache: MNT_NOWAIT never calls into a wedged
/// remote server. If it cannot be read the sources are still read, unguarded, and the run says so
/// (`mounts:getmntinfo_failed`, CONSTRAINED) rather than claiming a guard it did not have.
std::vector<macos::MountEntry> snapshot_mounts(std::vector<PermissionRow>& rows,
                                               yuzu::shared::ConstraintAccumulator& acc,
                                               MountFetch fetch) {
    std::vector<macos::MountEntry> out;
    struct statfs* raw = nullptr;
    const int n = fetch(&raw, MNT_NOWAIT);
    const std::unique_ptr<struct statfs, decltype(&::free)> mnt{raw, &::free};
    if (n <= 0 || raw == nullptr) {
        rows.push_back(failure_row("macos", "-", "-", false, "mounts:getmntinfo_failed", acc));
        return out;
    }
    for (int i = 0; i < n; ++i)
        out.push_back({mnt.get()[i].f_mntonname, mnt.get()[i].f_fstypename});
    return out;
}

/// The system db, then each home's db until the run-wide output budget is spent.
void read_all_sources(std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc,
                      const std::string& system_db, const std::string& users_dir,
                      const macos::ReadBounds& bounds, OutputBudget& output) {
    const auto read = [&](std::string_view owner, const std::string& path, bool missing_is_absent) {
        const auto first = rows.size();
        read_tcc_source(owner, path, missing_is_absent, rows, acc, bounds);
        output.charge({rows.data() + first, rows.size() - first});
    };
    // The system db keeps its unqualified rows; a missing system db is `unreadable`, never absent.
    read({}, system_db, /*missing_is_absent=*/false);
    const auto walked = rows.size();
    const auto users = enumerate_user_homes(rows, acc, users_dir, bounds.mounts);
    output.charge({rows.data() + walked, rows.size() - walked});
    for (const auto& user : users) {
        if (output.exhausted()) {
            rows.push_back(failure_row("macos", "-", "-", false,
                                       std::string{kBudgetExceededToken}, acc));
            break;
        }
        read(user, users_dir + "/" + user + std::string{kUserTccRelPath},
             /*missing_is_absent=*/true);
    }
}

/// One whole collection: the mount snapshot, then every source. The seam that pins the wiring
/// (snapshot -> guard -> reads); collect_macos_permissions only supplies the real paths and fetch.
void run_collection(std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc,
                    const std::string& system_db, const std::string& users_dir, MountFetch fetch,
                    macos::ReadBounds bounds = {}) {
    OutputBudget output;
    bounds.mounts = snapshot_mounts(rows, acc, fetch);
    output.charge(rows); // the snapshot's failure row, if any
    read_all_sources(rows, acc, system_db, users_dir, bounds, output);
}

} // namespace

// Excluded under YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY: the seam
// test_privacy_permissions_macos_internals.cpp uses to #include this TU and reach the
// internal-linkage helpers (mirrors autoruns_macos.cpp). Never defined by the real build.
#ifndef YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

int collect_macos_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    run_collection(rows, acc, std::string{kTccDbPath}, std::string{kUsersDir}, ::getmntinfo_r_np);

    // Fixed four-category vocabulary: location has no TCC service at all, so it
    // ships its own explicit `unsupported` row on EVERY collection -- including when every
    // TCC.db read above failed -- never silently omitted.
    rows.push_back({"macos", "-", "location", PermissionState::unsupported, "-", "-", "-", false});
    return emit_rows(ctx, rows, acc, false);
}

#endif // !YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
