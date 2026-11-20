#pragma once

/**
 * installed_apps_pkgdb_read.hpp -- the thin POSIX shell that reads the Linux
 * package databases in-process (SAM-45), replacing the `dpkg-query` and
 * `rpm -qa` subprocesses.
 *
 * The parsers are pure leaves in agents/shared (dpkg_status_parsers.hpp,
 * rpmdb_parsers.hpp, pkgdb_budget.hpp) and tested without a filesystem; this
 * header is the part that touches one: no-follow opens under an injected root
 * (a unit test passes a temporary directory, production passes "/"), format
 * detection by file, the read-only sqlite connection, and the before/after
 * change stamp. POSIX only -- the whole body is compiled out on Windows, where
 * the plugin walks the registry.
 *
 * Detection order (the old tool-binary order, now by DATABASE file):
 *   1. dpkg    <root>/var/lib/dpkg/status (+ status.d/): the text database. An absent
 *              status is "not dpkg"; an empty one (no installed package) falls through,
 *              so an rpm host that carries a stale dpkg tree is still read as rpm.
 *   2. rpm     the first of usr/lib/sysimage/rpm, var/lib/rpm, usr/share/rpm that is a
 *              real directory (a symlinked one is skipped: on current Fedora, RHEL and SUSE
 *              /var/lib/rpm links to the sysimage copy, which is tried first), and in it the
 *              first of rpmdb.sqlite, Packages.db, Packages that exists. A lone data.mdb
 *              (an LMDB rpmdb) is unsupported_format, not "no rpm".
 *   3. nothing the plugin's pacman and apk legs run as before (ecosystem none).
 *
 * Every failure is a "<source>:<cause>" token (HostPackages::failure) and returns NO packages:
 * one unreadable record fails the whole read, so the caller reports a degraded answer
 * (CONSTRAINED, rows kept by the server) and never publishes a smaller roster as complete.
 *
 * Hardening that is not in the parsers:
 *   - the file is opened O_NOFOLLOW relative to its directory descriptor, regular files only
 *     (posix_secure_read.hpp); the sqlite leg then reopens it BY PATH (sqlite needs the path to
 *     find its -wal/-shm siblings), a documented residual for root-owned directories;
 *   - size, mtime and ctime of the OPENED file are stamped before and after the read; a
 *     difference is changed_during_read whatever else happened;
 *   - sqlite is opened read-only with the untrusted-database posture (defensive, no trusted
 *     schema, a length limit, a progress-handler deadline, query_only, cell_size_check);
 *   - a WAL-mode database whose -wal sidecar is absent or empty is opened immutable=1: an
 *     unprivileged account cannot create the -shm a plain read-only WAL open needs (measured on
 *     alma9 as `nobody`: mode=ro fails, immutable reads every row), and an empty WAL means every
 *     committed page is already in the main file. A rollback-journal database is NOT opened
 *     immutable: it is read under a shared lock, exactly as `rpm -qa` read it.
 */

#if !defined(_WIN32)

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dpkg_status_parsers.hpp>
#include <pkgdb_budget.hpp>
#include <posix_secure_read.hpp>
#include <rpmdb_parsers.hpp>

namespace yuzu::installed_apps::pkgdb {

using yuzu::shared::DpkgPackage;
using yuzu::shared::PkgDbBudget;
using yuzu::shared::PkgDbCause;
using yuzu::shared::RpmPackage;

/// What one read may spend. The wall clock is applied by the caller (the plugin wraps the call in
/// bounded_call_ex with this duration and passes the same deadline as `expired`).
struct Limits {
    std::size_t max_packages = 50000;
    std::uint64_t dpkg_max_bytes = 32ull * 1024 * 1024;       ///< one dpkg text file
    std::uint64_t rpm_max_header_bytes = 32ull * 1024 * 1024; ///< one rpm header blob
    std::uint64_t rpm_max_total_bytes = 1ull << 30;           ///< all rpm headers of one read
    std::chrono::seconds wall{20};
    int sqlite_busy_ms = 2000;
};

/// The answer for one host. `failure` set means NOTHING was returned (ecosystem none and both
/// vectors empty); `ecosystem == none` with no failure means no dpkg or rpm database exists.
struct HostPackages {
    enum class Ecosystem { none, dpkg, rpm };
    Ecosystem ecosystem = Ecosystem::none;
    std::vector<DpkgPackage> dpkg;
    std::vector<RpmPackage> rpm;
    std::string failure; ///< "<source>:<cause>", source in dpkg_status, dpkg_status_d, rpm_sqlite, rpm_ndb, rpm_bdb, rpmdb
};

namespace detail {

[[nodiscard]] inline std::string failure_token(std::string_view source, PkgDbCause cause) {
    std::string out{source};
    out += ':';
    out += yuzu::shared::pkgdb_cause_token(cause);
    return out;
}

[[nodiscard]] inline PkgDbCause cause_of(yuzu::shared::ReadError e) noexcept {
    switch (e) {
    case yuzu::shared::ReadError::symlink_refused: return PkgDbCause::symlink_refused;
    case yuzu::shared::ReadError::not_regular: return PkgDbCause::not_regular;
    case yuzu::shared::ReadError::oversized: return PkgDbCause::oversized;
    case yuzu::shared::ReadError::none:
    case yuzu::shared::ReadError::io: break;
    }
    return PkgDbCause::unreadable;
}

/// <root>/<rel>, with a trailing separator on root dropped ("/" joins as "/rel").
[[nodiscard]] inline std::string join(const std::string& root, std::string_view rel) {
    std::string base = root;
    while (!base.empty() && base.back() == '/')
        base.pop_back();
    base += '/';
    base += rel;
    return base;
}

[[nodiscard]] inline struct timespec ctime_of(const struct stat& st) noexcept {
#if defined(__APPLE__)
    return st.st_ctimespec;
#else
    return st.st_ctim;
#endif
}

/// What identifies the opened file's state: taken from the descriptor before the first read and
/// again after the last. ctime moves on every write(2) and an unprivileged writer cannot restore
/// it, so a same-size, mtime-restoring in-place write still changes the stamp.
struct Stamp {
    std::uint64_t dev = 0;
    std::uint64_t ino = 0;
    std::int64_t size = 0;
    std::int64_t mtime_sec = 0;
    std::int64_t mtime_nsec = 0;
    std::int64_t ctime_sec = 0;
    std::int64_t ctime_nsec = 0;
    friend bool operator==(const Stamp&, const Stamp&) = default;
};

[[nodiscard]] inline std::optional<Stamp> stamp_of(int fd) noexcept {
    struct stat st {};
    if (::fstat(fd, &st) != 0)
        return std::nullopt;
    const struct timespec m = yuzu::shared::mtime_of(st);
    const struct timespec c = ctime_of(st);
    return Stamp{static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino),
                 static_cast<std::int64_t>(st.st_size), static_cast<std::int64_t>(m.tv_sec),
                 static_cast<std::int64_t>(m.tv_nsec), static_cast<std::int64_t>(c.tv_sec),
                 static_cast<std::int64_t>(c.tv_nsec)};
}

/// A ByteSource over an open descriptor: pread, EINTR retried, a short read (the file shrank under
/// us) is a failure. The descriptor must outlive the source.
[[nodiscard]] inline yuzu::shared::ByteSource fd_source(int fd, std::uint64_t size) {
    yuzu::shared::ByteSource s;
    s.size = size;
    s.read_at = [fd, size](std::uint64_t off, std::span<std::uint8_t> out) {
        if (off > size || out.size() > size - off)
            return false;
        std::size_t done = 0;
        while (done < out.size()) {
            const ssize_t n = ::pread(fd, out.data() + done, out.size() - done,
                                      static_cast<off_t>(off + done));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return false;
            }
            if (n == 0)
                return false;
            done += static_cast<std::size_t>(n);
        }
        return true;
    };
    return s;
}

[[nodiscard]] inline PkgDbBudget make_budget(std::size_t rows, std::uint64_t bytes,
                                             std::uint64_t item_cap,
                                             const std::function<bool()>& expired) {
    PkgDbBudget b;
    b.rows_left = rows;
    b.bytes_left = bytes;
    b.max_item_bytes = item_cap;
    b.expired = expired;
    return b;
}

// ── dpkg ────────────────────────────────────────────────────────────────────

struct DpkgRead {
    std::vector<DpkgPackage> packages;
    std::string failure;
};

/// Names in status.d that are not packages: hidden files, dpkg's own leftovers and editor backups.
[[nodiscard]] inline bool status_d_skips(std::string_view name) noexcept {
    const auto ends = [name](std::string_view suffix) {
        return name.size() >= suffix.size() && name.substr(name.size() - suffix.size()) == suffix;
    };
    return name.empty() || name.front() == '.' || ends(".dpkg-new") || ends(".dpkg-old") ||
           ends("~") || ends(".bak");
}

/// status.d: a directory of single-stanza control files (the layout minimal and distroless images use
/// in place of one status file; dpkg-query itself does not read it). One component per call through
/// the dir-fd forms; regular files only. A symlink entry fails the read (never followed), a
/// directory, FIFO or device entry is skipped, an oversized file fails it, and the number of files
/// is bounded by max_packages (row_cap). A missing directory is normal and benign.
[[nodiscard]] inline DpkgRead read_dpkg_status_d(const std::string& root, const Limits& lim,
                                                 PkgDbBudget& budget) {
    constexpr std::string_view kSource = "dpkg_status_d";
    DpkgRead out;
    const std::string path = join(root, "var/lib/dpkg/status.d");
    auto dir = yuzu::shared::open_dir_no_follow(path);
    if (!dir.opened()) {
        if (dir.err == ENOENT)
            return out; // benign absent
        struct stat st {};
        const bool is_link = ::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
        out.failure = failure_token(kSource, is_link ? PkgDbCause::symlink_refused
                                    : dir.err == ENOTDIR ? PkgDbCause::not_regular
                                                         : PkgDbCause::unreadable);
        return out;
    }

    std::vector<std::string> names;
    while (const struct dirent* e = ::readdir(dir.dir.get())) {
        const std::string_view name{e->d_name};
        if (name == "." || name == ".." || status_d_skips(name))
            continue;
        if (names.size() >= lim.max_packages) {
            out.failure = failure_token(kSource, PkgDbCause::row_cap);
            return out;
        }
        names.emplace_back(name);
    }
    std::sort(names.begin(), names.end()); // readdir order is arbitrary; the answer must not be

    for (const auto& name : names) {
        if (auto t = budget.check_time(); !t) {
            out.failure = failure_token(kSource, t.error());
            return out;
        }
        auto file = yuzu::shared::read_file_no_follow_at(dir.dir.fd(), name.c_str(), lim.dpkg_max_bytes);
        if (!file.ok()) {
            if (file.error == yuzu::shared::ReadError::not_regular)
                continue; // a directory, FIFO or device entry
            if (file.error == yuzu::shared::ReadError::io && file.err == ENOENT)
                continue; // removed between the listing and the open
            out.failure = failure_token(kSource, cause_of(file.error));
            return out;
        }
        if (auto r = budget.charge_bytes(file.data.size()); !r) {
            out.failure = failure_token(kSource, r.error());
            return out;
        }
        auto parsed = yuzu::shared::parse_dpkg_status(file.data, budget);
        if (!parsed) {
            out.failure = failure_token(kSource, parsed.error());
            return out;
        }
        yuzu::shared::merge_dpkg_status_d(out.packages, std::move(*parsed));
    }
    return out;
}

[[nodiscard]] inline DpkgRead read_dpkg(const std::string& root, const Limits& lim,
                                        const std::function<bool()>& expired) {
    constexpr std::string_view kSource = "dpkg_status";
    DpkgRead out;
    PkgDbBudget budget = make_budget(lim.max_packages, lim.dpkg_max_bytes, lim.dpkg_max_bytes, expired);

    auto file = yuzu::shared::read_file_no_follow(join(root, "var/lib/dpkg/status"), lim.dpkg_max_bytes);
    if (file.ok()) {
        if (auto r = budget.charge_bytes(file.data.size()); !r) {
            out.failure = failure_token(kSource, r.error());
            return out;
        }
        auto parsed = yuzu::shared::parse_dpkg_status(file.data, budget);
        if (!parsed) {
            out.failure = failure_token(kSource, parsed.error());
            return out;
        }
        out.packages = std::move(*parsed);
    } else if (!(file.error == yuzu::shared::ReadError::io && file.err == ENOENT)) {
        out.failure = failure_token(kSource, cause_of(file.error)); // present but unreadable
        return out;
    }

    auto status_d = read_dpkg_status_d(root, lim, budget);
    if (!status_d.failure.empty()) {
        out.packages.clear();
        out.failure = std::move(status_d.failure);
        return out;
    }
    yuzu::shared::merge_dpkg_status_d(out.packages, std::move(status_d.packages));
    return out;
}

// ── rpm ─────────────────────────────────────────────────────────────────────

struct RpmRead {
    bool found = false; ///< a database file (or an unsupported marker) exists in this directory
    std::vector<RpmPackage> packages;
    std::string failure;
};

/// One header blob -> one package, or the cause the whole read fails with.
[[nodiscard]] inline yuzu::shared::PkgDbVoid collect_header(std::span<const std::uint8_t> blob,
                                                            std::vector<RpmPackage>& out) {
    auto header = yuzu::shared::RpmHeader::parse(blob);
    if (!header)
        return std::unexpected(header.error());
    auto pkg = yuzu::shared::rpm_package_from_header(*header);
    if (!pkg)
        return std::unexpected(pkg.error());
    out.push_back(std::move(*pkg));
    return {};
}

/// sqlite's URI for `path`: `%`, `?` and `#` are the only characters a URI path reads specially.
[[nodiscard]] inline std::string sqlite_uri(std::string_view path, bool immutable) {
    std::string out{"file:"};
    for (const char c : path) {
        switch (c) {
        case '%': out += "%25"; break;
        case '?': out += "%3F"; break;
        case '#': out += "%23"; break;
        default: out += c; break;
        }
    }
    out += immutable ? "?mode=ro&immutable=1" : "?mode=ro";
    return out;
}

[[nodiscard]] inline PkgDbCause cause_of_sqlite(int rc) noexcept {
    switch (rc & 0xFF) {
    case SQLITE_BUSY:
    case SQLITE_LOCKED: return PkgDbCause::locked;
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
    case SQLITE_ERROR: return PkgDbCause::corrupt; // incl. a missing Packages table
    case SQLITE_TOOBIG: return PkgDbCause::oversized;
    case SQLITE_INTERRUPT: return PkgDbCause::timeout;
    default: return PkgDbCause::unreadable;
    }
}

struct SqliteCloser {
    void operator()(sqlite3* db) const noexcept { sqlite3_close(db); }
};
struct StmtFinalizer {
    void operator()(sqlite3_stmt* s) const noexcept { sqlite3_finalize(s); }
};

/// True when the sidecar `name` in `dir_fd` is absent or an empty regular file. Anything that
/// cannot be shown absent or empty (a link, a directory, an unreadable stat) is "not empty".
[[nodiscard]] inline bool sidecar_absent_or_empty(int dir_fd, const char* name) noexcept {
    struct stat st {};
    if (::fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT;
    return S_ISREG(st.st_mode) && st.st_size == 0;
}

[[nodiscard]] inline std::expected<std::vector<RpmPackage>, PkgDbCause>
read_rpm_sqlite(const std::string& db_path, int dir_fd, const char* name, int fd, const Limits& lim,
                PkgDbBudget& budget) {
    // The first bytes decide the open mode and refuse a file that is not sqlite at all.
    std::array<std::uint8_t, 20> head{};
    if (::pread(fd, head.data(), head.size(), 0) != static_cast<ssize_t>(head.size()))
        return std::unexpected(PkgDbCause::corrupt);
    if (std::memcmp(head.data(), "SQLite format 3\0", 16) != 0)
        return std::unexpected(PkgDbCause::corrupt);
    const bool wal_mode = head[18] == 2 && head[19] == 2;
    const std::string wal = std::string{name} + "-wal";
    const bool immutable = wal_mode && sidecar_absent_or_empty(dir_fd, wal.c_str());

    sqlite3* raw = nullptr;
    const int open_rc = sqlite3_open_v2(sqlite_uri(db_path, immutable).c_str(), &raw,
                                        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX,
                                        nullptr);
    std::unique_ptr<sqlite3, SqliteCloser> db{raw}; // owns the handle even on a failed open
    if (open_rc != SQLITE_OK)
        return std::unexpected(cause_of_sqlite(open_rc));

    // Untrusted-database posture. The length limit bounds every blob and the schema text alike.
    sqlite3_limit(db.get(), SQLITE_LIMIT_LENGTH, static_cast<int>(lim.rpm_max_header_bytes));
    if (sqlite3_db_config(db.get(), SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr) != SQLITE_OK ||
        sqlite3_db_config(db.get(), SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr) != SQLITE_OK)
        return std::unexpected(PkgDbCause::unreadable);
    sqlite3_busy_timeout(db.get(), lim.sqlite_busy_ms);
    sqlite3_progress_handler(
        db.get(), 1000,
        +[](void* p) noexcept -> int {
            return static_cast<const PkgDbBudget*>(p)->check_time().has_value() ? 0 : 1;
        },
        &budget);
    if (const int rc = sqlite3_exec(db.get(), "PRAGMA query_only=1; PRAGMA cell_size_check=ON",
                                    nullptr, nullptr, nullptr);
        rc != SQLITE_OK)
        return std::unexpected(cause_of_sqlite(rc));

    sqlite3_stmt* raw_stmt = nullptr;
    if (const int rc = sqlite3_prepare_v2(db.get(), "SELECT blob FROM Packages", -1, &raw_stmt, nullptr);
        rc != SQLITE_OK)
        return std::unexpected(cause_of_sqlite(rc));
    std::unique_ptr<sqlite3_stmt, StmtFinalizer> stmt{raw_stmt};

    std::vector<RpmPackage> out;
    for (;;) {
        const int rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_DONE)
            break;
        if (rc != SQLITE_ROW)
            return std::unexpected(cause_of_sqlite(rc));
        // The progress handler fires every 1000 VM steps, which a small table never reaches; poll
        // the deadline once per row as well so the cause is deterministic at any size.
        if (auto t = budget.check_time(); !t)
            return std::unexpected(t.error());
        if (sqlite3_column_type(stmt.get(), 0) != SQLITE_BLOB)
            return std::unexpected(PkgDbCause::corrupt);
        const int len = sqlite3_column_bytes(stmt.get(), 0);
        const void* data = sqlite3_column_blob(stmt.get(), 0);
        if (len <= 0 || data == nullptr)
            return std::unexpected(PkgDbCause::corrupt);
        if (static_cast<std::uint64_t>(len) > budget.max_item_bytes)
            return std::unexpected(PkgDbCause::oversized);
        if (auto r = budget.charge_row(); !r)
            return std::unexpected(r.error());
        if (auto r = budget.charge_bytes(static_cast<std::uint64_t>(len)); !r)
            return std::unexpected(r.error());
        if (auto r = collect_header(std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(data),
                                                                   static_cast<std::size_t>(len)),
                                    out);
            !r)
            return std::unexpected(r.error());
    }
    return out;
}

/// Reads the rpm database in `rel_dir`, if there is one. `found == false` with no failure means this
/// directory holds no database (try the next); a failure is final.
[[nodiscard]] inline RpmRead read_rpm_dir(const std::string& root, std::string_view rel_dir,
                                          const Limits& lim, const std::function<bool()>& expired) {
    RpmRead out;
    const std::string dir_path = join(root, rel_dir);
    auto dir = yuzu::shared::open_dir_no_follow(dir_path);
    if (!dir.opened()) {
        // Absent, or a symlink / non-directory (a symlinked var/lib/rpm is skipped on purpose): the next
        // location. Anything else (a permission refusal) is a database we cannot show absent.
        if (dir.err == ENOENT || dir.err == ENOTDIR || dir.err == ELOOP)
            return out;
        out.found = true;
        out.failure = failure_token("rpmdb", PkgDbCause::unreadable);
        return out;
    }

    struct Candidate {
        const char* file;
        const char* source;
    };
    static constexpr Candidate kCandidates[] = {
        {"rpmdb.sqlite", "rpm_sqlite"}, {"Packages.db", "rpm_ndb"}, {"Packages", "rpm_bdb"}};

    for (const auto& c : kCandidates) {
        auto file = yuzu::shared::open_file_no_follow_at(dir.dir.fd(), c.file);
        if (!file.opened() && file.error == yuzu::shared::ReadError::io && file.err == ENOENT)
            continue;
        out.found = true;
        if (!file.opened()) {
            out.failure = failure_token(c.source, cause_of(file.error));
            return out;
        }
        const int fd = file.file.fd();
        const auto before = stamp_of(fd);
        PkgDbBudget budget = make_budget(lim.max_packages, lim.rpm_max_total_bytes,
                                         lim.rpm_max_header_bytes, expired);
        std::expected<std::vector<RpmPackage>, PkgDbCause> result;
        if (std::string_view{c.source} == "rpm_sqlite") {
            result = read_rpm_sqlite(join(dir_path, c.file), dir.dir.fd(), c.file, fd, lim, budget);
        } else {
            std::vector<RpmPackage> packages;
            const auto src = fd_source(fd, file.size);
            const auto on_blob = [&packages](std::span<const std::uint8_t> blob) {
                return collect_header(blob, packages);
            };
            const auto r = std::string_view{c.source} == "rpm_ndb"
                               ? yuzu::shared::read_rpm_ndb(src, budget, on_blob)
                               : yuzu::shared::read_rpm_bdb(src, budget, on_blob);
            if (r)
                result = std::move(packages);
            else
                result = std::unexpected(r.error());
        }
        // A rpm transaction that rewrote the file under the read wins over whatever the read made of it.
        const auto after = stamp_of(fd);
        if (!before || !after || *before != *after) {
            out.failure = failure_token(c.source, PkgDbCause::changed_during_read);
            return out;
        }
        if (!result) {
            out.failure = failure_token(c.source, result.error());
            return out;
        }
        out.packages = std::move(*result);
        return out;
    }

    // No known database file: a lone LMDB data file means a database this reader does not decode.
    struct stat st {};
    if (::fstatat(dir.dir.fd(), "data.mdb", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        out.found = true;
        out.failure = failure_token("rpmdb", PkgDbCause::unsupported_format);
    }
    return out;
}

} // namespace detail

/// Reads the dpkg or rpm database under `root` ("/" in production). `expired` is polled by every
/// reader (rows, pages and sqlite VM steps); it may be empty (no deadline).
[[nodiscard]] inline HostPackages read_host_packages(const std::string& root, const Limits& lim,
                                                     const std::function<bool()>& expired) {
    HostPackages out;

    auto dpkg = detail::read_dpkg(root, lim, expired);
    if (!dpkg.failure.empty()) {
        out.failure = std::move(dpkg.failure);
        return out;
    }
    if (!dpkg.packages.empty()) {
        out.ecosystem = HostPackages::Ecosystem::dpkg;
        out.dpkg = std::move(dpkg.packages);
        return out;
    }

    static constexpr std::string_view kRpmDirs[] = {"usr/lib/sysimage/rpm", "var/lib/rpm",
                                                    "usr/share/rpm"};
    for (const auto dir : kRpmDirs) {
        auto rpm = detail::read_rpm_dir(root, dir, lim, expired);
        if (!rpm.failure.empty()) {
            out.failure = std::move(rpm.failure);
            return out;
        }
        if (rpm.found) {
            out.ecosystem = HostPackages::Ecosystem::rpm;
            out.rpm = std::move(rpm.packages);
            return out;
        }
    }
    return out; // neither: the plugin's pacman and apk legs run
}

} // namespace yuzu::installed_apps::pkgdb

#endif // !_WIN32
