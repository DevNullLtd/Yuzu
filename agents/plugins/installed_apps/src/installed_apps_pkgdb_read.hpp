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
 *              real directory (a symlinked one is never followed: on current Fedora, RHEL and SUSE
 *              /var/lib/rpm links to the sysimage copy, which is tried first), and in it the
 *              first of rpmdb.sqlite, Packages.db, Packages that exists. A lone data.mdb
 *              (an LMDB rpmdb) is unsupported_format, not "no rpm". A skipped symlink that has a
 *              database file behind it (a stat, nothing opened) is rpmdb:symlink_refused when no
 *              other candidate directory yields a database: a database that exists but may not be
 *              read is never an empty list.
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
#include <limits>
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

#include <bounded_wait.hpp>
#include <dpkg_status_parsers.hpp>
#include <pkgdb_budget.hpp>
#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>
#include <rpmdb_parsers.hpp>

namespace yuzu::installed_apps::pkgdb {

using yuzu::shared::DpkgPackage;
using yuzu::shared::PkgDbBudget;
using yuzu::shared::PkgDbCause;
using yuzu::shared::RpmPackage;

/// What one read may spend. The wall clock is applied by read_host_packages_bounded (one
/// bounded_call_ex with this duration; the same deadline is the readers' `expired`).
struct Limits {
    std::size_t max_packages = 50000;
    /// 32 MiB of dpkg text IN TOTAL: the status file and every status.d file share one budget. A
    /// single file over it is `oversized`; files that each fit but sum over it are `byte_cap`.
    std::uint64_t dpkg_max_bytes = 32ull * 1024 * 1024;
    std::uint64_t rpm_max_header_bytes = 32ull * 1024 * 1024; ///< one rpm header blob
    std::uint64_t rpm_max_total_bytes = 1ull << 30;           ///< all rpm headers of one read
    std::chrono::milliseconds wall{20000};                    ///< milliseconds so a test can use a short wall
    int sqlite_busy_ms = 2000;
};

/// The answer for one host. `failure` set means NOTHING was returned (ecosystem none and both
/// vectors empty); `ecosystem == none` with no failure means no dpkg or rpm database exists.
struct HostPackages {
    enum class Ecosystem { none, dpkg, rpm };
    Ecosystem ecosystem = Ecosystem::none;
    std::vector<DpkgPackage> dpkg;
    std::vector<RpmPackage> rpm;
    std::string failure; ///< "<source>:<cause>", source in dpkg_status, dpkg_status_d, rpm_sqlite, rpm_ndb, rpm_bdb, rpmdb, pkgdb
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
    const struct timespec c = yuzu::shared::ctime_of(st);
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

// ── dpkg ────────────────────────────────────────────────────────────────────

struct DpkgRead {
    std::vector<DpkgPackage> packages;
    std::string failure;
};

/// Names in status.d that are not packages: hidden files and the `<package>.md5sums` file image
/// builders write beside each package's control file.
[[nodiscard]] inline bool status_d_skips(std::string_view name) noexcept {
    return name.empty() || name.front() == '.' || name.ends_with(".md5sums");
}

/// status.d: a directory of single-stanza control files (the layout minimal images with no shell
/// and no package manager use in place of one status file; dpkg-query itself does not read it).
/// Each package is one control file named for it, plus a `<package>.md5sums` sibling that is
/// skipped. A real file has no Status field, so a stanza without one is read as
/// `install ok installed` (MissingStatus::installed); a stanza that does have one is held to the
/// three-word rule. One component per call through the dir-fd forms; regular files only. A symlink
/// entry fails the read (never followed), a directory, FIFO or device entry is skipped, an
/// oversized file fails it, and the number of packages is bounded by max_packages (row_cap). The
/// listing is bounded in entries too (twice max_packages: a package is one control file and one
/// .md5sums sibling; over it is row_cap) and polls the deadline on every entry, skipped or not. A
/// listing that fails part-way fails the read (unreadable), never a shorter list. A missing
/// directory is normal and benign. `readdir_fn` defaults to the real readdir and is overridable
/// only for tests.
template <typename ReadDirFn = yuzu::shared::detail::DefaultReadDirFn>
[[nodiscard]] inline DpkgRead
read_dpkg_status_d(const std::string& root, const Limits& lim, PkgDbBudget& budget,
                   ReadDirFn&& readdir_fn = &yuzu::shared::detail::default_readdir) {
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
    std::optional<PkgDbCause> stopped; // why the callback ended the walk early
    const std::size_t entry_bound = lim.max_packages > std::numeric_limits<std::size_t>::max() / 2
                                        ? std::numeric_limits<std::size_t>::max()
                                        : lim.max_packages * 2;
    const auto walk = yuzu::shared::walk_dir_capped(
        dir.dir.get(), entry_bound,
        [&](const struct dirent* e) {
            if (auto t = budget.check_time(); !t) {
                stopped = t.error();
                return false;
            }
            const std::string_view name{e->d_name};
            if (status_d_skips(name))
                return true;
            if (names.size() >= lim.max_packages) {
                stopped = PkgDbCause::row_cap;
                return false;
            }
            names.emplace_back(name);
            return true;
        },
        std::forward<ReadDirFn>(readdir_fn));
    if (stopped || walk.enumeration_error || walk.truncated) {
        out.failure = failure_token(kSource, stopped                ? *stopped
                                             : walk.enumeration_error ? PkgDbCause::unreadable
                                                                      : PkgDbCause::row_cap);
        return out;
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
        auto parsed = yuzu::shared::parse_dpkg_status(file.data, budget,
                                                      yuzu::shared::MissingStatus::installed);
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
    PkgDbBudget budget{.rows_left = lim.max_packages,
                       .bytes_left = lim.dpkg_max_bytes,
                       .max_item_bytes = lim.dpkg_max_bytes,
                       .expired = expired};

    auto file = yuzu::shared::read_file_no_follow(join(root, "var/lib/dpkg/status"), lim.dpkg_max_bytes);
    if (file.ok()) {
        if (auto r = budget.charge_bytes(file.data.size()); !r) {
            out.failure = failure_token(kSource, r.error());
            return out;
        }
        auto parsed = yuzu::shared::parse_dpkg_status(file.data, budget,
                                                      yuzu::shared::MissingStatus::corrupt);
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
        // Deliberate: the status packages parsed above are discarded. Answering with them alone would
        // publish a roster without the status.d-only packages as the host's complete one (the server
        // would record those as removed); no partial result is the readers' contract (pkgdb_budget.hpp).
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
    bool symlinked_db = false; ///< this candidate is a symlink with a database file behind it (never followed)
    std::vector<RpmPackage> packages;
    std::string failure;
};

/// One header blob -> one package, or the cause the whole read fails with.
[[nodiscard]] inline std::expected<RpmPackage, PkgDbCause>
collect_header(std::span<const std::uint8_t> blob) {
    auto header = yuzu::shared::RpmHeader::parse(blob);
    if (!header)
        return std::unexpected(header.error());
    return yuzu::shared::rpm_package_from_header(*header);
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
        auto pkg = collect_header(std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(data),
                                                                static_cast<std::size_t>(len)));
        if (!pkg)
            return std::unexpected(pkg.error());
        out.push_back(std::move(*pkg));
    }
    return out;
}

/// True when `dir_path` is a symlink and a database file exists behind it. stat only: nothing is
/// opened or read through the link.
[[nodiscard]] inline bool symlink_hides_database(const std::string& dir_path) {
    struct stat st {};
    if (::lstat(dir_path.c_str(), &st) != 0 || !S_ISLNK(st.st_mode))
        return false;
    for (const char* name : {"rpmdb.sqlite", "Packages.db", "Packages", "data.mdb"})
        if (::stat((dir_path + '/' + name).c_str(), &st) == 0)
            return true;
    return false;
}

/// Reads the rpm database in `rel_dir`, if there is one. `found == false` with no failure means this
/// directory holds no database (try the next); a failure is final.
[[nodiscard]] inline RpmRead read_rpm_dir(const std::string& root, std::string_view rel_dir,
                                          const Limits& lim, const std::function<bool()>& expired) {
    RpmRead out;
    const std::string dir_path = join(root, rel_dir);
    auto dir = yuzu::shared::open_dir_no_follow(dir_path);
    if (!dir.opened()) {
        // Absent, or a symlink / non-directory (a symlinked var/lib/rpm is skipped on purpose, never
        // followed): the next location. A symlink with a database behind it is remembered, so that when
        // no other location yields one the answer is a refusal, not an empty list. Anything else (a
        // permission refusal) is a database we cannot show absent.
        if (dir.err == ENOENT || dir.err == ENOTDIR || dir.err == ELOOP) {
            out.symlinked_db = symlink_hides_database(dir_path);
            return out;
        }
        out.found = true;
        out.failure = failure_token("rpmdb", PkgDbCause::unreadable);
        return out;
    }

    using BlobReader = yuzu::shared::PkgDbVoid (*)(const yuzu::shared::ByteSource&, PkgDbBudget&,
                                                   const yuzu::shared::RpmBlobFn&);
    struct Candidate {
        const char* file;
        const char* source;
        BlobReader read_blobs; ///< null for sqlite, which needs a connection rather than a byte source
    };
    static constexpr Candidate kCandidates[] = {
        {"rpmdb.sqlite", "rpm_sqlite", nullptr},
        {"Packages.db", "rpm_ndb", &yuzu::shared::read_rpm_ndb},
        {"Packages", "rpm_bdb", &yuzu::shared::read_rpm_bdb}};

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
        PkgDbBudget budget{.rows_left = lim.max_packages,
                           .bytes_left = lim.rpm_max_total_bytes,
                           .max_item_bytes = lim.rpm_max_header_bytes,
                           .expired = expired};
        std::expected<std::vector<RpmPackage>, PkgDbCause> result;
        if (!c.read_blobs) {
            result = read_rpm_sqlite(join(dir_path, c.file), dir.dir.fd(), c.file, fd, lim, budget);
        } else {
            std::vector<RpmPackage> packages;
            const auto r = c.read_blobs(
                fd_source(fd, file.size), budget,
                [&packages](std::span<const std::uint8_t> blob) -> yuzu::shared::PkgDbVoid {
                    auto pkg = collect_header(blob);
                    if (!pkg)
                        return std::unexpected(pkg.error());
                    packages.push_back(std::move(*pkg));
                    return {};
                });
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
    bool symlinked_db = false;
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
        symlinked_db = symlinked_db || rpm.symlinked_db;
    }
    if (symlinked_db) // a database exists only behind a link this reader never follows
        out.failure = detail::failure_token("rpmdb", PkgDbCause::symlink_refused);
    return out; // otherwise neither: the plugin's pacman and apk legs run
}

/// The reader the bounded form runs; a test injects its own (the boundary, so no real wedged volume).
using HostReader = std::function<HostPackages(const std::string&, const Limits&,
                                              const std::function<bool()>&)>;

/// read_host_packages under the wall clock: ONE bounded_call_ex of `lim.wall`, so a pread on a wedged
/// volume cannot park the caller. The reader's `expired` is `stop` OR the same deadline, so an
/// abandoned worker ends itself at its next poll. Every capture of the worker is by value (it may
/// outlive this call). Failures: pkgdb:timeout (the wall passed, no rows), pkgdb:busy (the process-wide
/// ceiling on abandoned workers refused the call; the reader never ran), pkgdb:unreadable (the reader
/// threw: bounded_call_ex would otherwise leave the caller waiting out the whole wall and report it as
/// a timeout, which points an operator at a slow disk).
[[nodiscard]] inline HostPackages read_host_packages_bounded(const std::string& root, const Limits& lim,
                                                             std::function<bool()> stop = {},
                                                             HostReader reader = read_host_packages) {
    const auto deadline = std::chrono::steady_clock::now() + lim.wall;
    auto call = yuzu::shared::bounded_call_ex(
        lim.wall, [root, lim, stop = std::move(stop), reader = std::move(reader), deadline]() -> HostPackages {
            try {
                return reader(root, lim, [&stop, deadline] {
                    return (stop && stop()) || std::chrono::steady_clock::now() >= deadline;
                });
            } catch (...) {
                HostPackages failed;
                failed.failure = detail::failure_token("pkgdb", PkgDbCause::unreadable);
                return failed;
            }
        });
    HostPackages out;
    switch (call.status) {
    case yuzu::shared::BoundedCallStatus::Completed: return std::move(*call.value);
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.failure = detail::failure_token("pkgdb", PkgDbCause::timeout);
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        out.failure = detail::failure_token("pkgdb", PkgDbCause::busy);
        break;
    }
    return out;
}

} // namespace yuzu::installed_apps::pkgdb

#endif // !_WIN32
