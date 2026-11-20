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
 *              status is "not dpkg". It is the answer only when at least one stanza is
 *              `installed` (what inv_record_from_dpkg requires, and the least app_record_from_dpkg
 *              requires: it also wants flag ok and want install or deinstall, so a host whose
 *              installed stanzas are all flagged reinstreq is dpkg with inventory rows and no list
 *              row, as on the old path); one with none (empty, or only config-files, half-installed
 *              and other non-installed states) falls through, so an rpm host that carries a stale
 *              dpkg tree is still read as rpm. A pending update journal (a digits-named file in
 *              var/lib/dpkg/updates) is dpkg_updates:locked, with no rows and no fall-through: see
 *              read_dpkg.
 *   2. rpm     the first of usr/lib/sysimage/rpm, var/lib/rpm, usr/share/rpm that holds a database
 *              file (a symlinked candidate directory is never followed: on current Fedora, RHEL and
 *              SUSE /var/lib/rpm links to the sysimage copy, which is tried first), and in it the
 *              first of rpmdb.sqlite, Packages.db, Packages that exists. A database that was read
 *              and holds no package does not end detection: the next candidate directory is tried,
 *              and when none yields a package the answer is ecosystem none. A lone data.mdb (an LMDB
 *              rpmdb) is unsupported_format, not "no rpm". A skipped symlink that has a database file
 *              behind it (a stat, nothing opened) is rpmdb:symlink_refused unless it resolves to a
 *              directory whose database this reader read itself (an empty one counts): on current
 *              Fedora, RHEL and SUSE /var/lib/rpm links to the sysimage directory that is read, and
 *              on the older layout the sysimage link points at var/lib/rpm. A database that exists
 *              but was never read is never an empty list.
 *   3. nothing the plugin's pacman and apk legs run as before (ecosystem none, no failure).
 *
 * Every failure is a "<source>:<cause>" token (HostPackages::failure) and returns NO packages:
 * one unreadable record fails the whole read, so the caller reports a degraded answer
 * (CONSTRAINED, rows kept by the server) and never publishes a smaller roster as complete.
 *
 * Hardening that is not in the parsers:
 *   - the LEAF is opened O_NOFOLLOW relative to its directory descriptor, regular files only
 *     (posix_secure_read.hpp); the directories above it are reached by path and their symlinks ARE
 *     followed, as the old tools followed them. The sqlite leg then reopens the file BY PATH
 *     (sqlite needs the path to find its -wal/-shm siblings), a documented residual for root-owned
 *     directories;
 *   - the RPM database file's size, mtime and ctime are stamped from the OPENED descriptor before and
 *     after the read; a difference is changed_during_read whatever else happened. (dpkg has no
 *     stamp: a text file read whole in one pass.) For the ndb and Berkeley DB files the stamp is
 *     not enough on its own, because rpm rewrites them in place, so the reader also refuses to read
 *     while rpm's transaction lock is held: see rpm_transaction_refusal;
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
#include <iterator>
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
    std::uint64_t rpm_max_total_bytes = 1ull << 30;           ///< all rpm headers of one read: bytes READ
    /// The strings the rpm readers KEEP, in total (PkgDbBudget::kept_left). Apart from the read bound
    /// because one stored string can be named by several fields: six copies of a 32 MiB header's
    /// text would otherwise be admitted under the 1 GiB read bound. 8 MiB is the old inner capture cap
    /// of the `rpm -qa` call (kToolOutputCap in installed_apps_plugin.cpp), above the collector's
    /// 3.5 MiB outer cap, so no host the old path could report is newly refused.
    std::uint64_t rpm_max_kept_bytes = 8ull * 1024 * 1024;
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
    std::string failure; ///< "<source>:<cause>", source in dpkg_status, dpkg_status_d, dpkg_updates, rpm_sqlite, rpm_ndb, rpm_bdb, rpmdb, pkgdb
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

/// Why a directory under the database tree could not be opened (the caller has already treated ENOENT
/// as "absent"): a link is refused by name, a non-directory is not_regular, anything else unreadable.
[[nodiscard]] inline PkgDbCause dir_open_cause(const std::string& path, int err) {
    struct stat st {};
    if (::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode))
        return PkgDbCause::symlink_refused;
    return err == ENOTDIR ? PkgDbCause::not_regular : PkgDbCause::unreadable;
}

/// The most entries one directory listing may visit: twice max_packages (a status.d package is one
/// control file and one `.md5sums` sibling). Over it is row_cap.
[[nodiscard]] inline std::size_t dir_entry_bound(const Limits& lim) noexcept {
    return lim.max_packages > std::numeric_limits<std::size_t>::max() / 2
               ? std::numeric_limits<std::size_t>::max()
               : lim.max_packages * 2;
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

/// Which directory, whatever path or link reached it: st_dev and st_ino, nothing else (a Stamp also
/// carries size and times, which a directory comparison must not).
struct DirId {
    std::uint64_t dev = 0;
    std::uint64_t ino = 0;
    friend bool operator==(const DirId&, const DirId&) = default;
};

[[nodiscard]] inline DirId dir_id_of(const struct stat& st) noexcept {
    return DirId{static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino)};
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
        out.failure = failure_token(kSource, dir_open_cause(path, dir.err));
        return out;
    }

    std::vector<std::string> names;
    std::optional<PkgDbCause> stopped; // why the callback ended the walk early
    const std::size_t entry_bound = dir_entry_bound(lim);
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

    // Merged once after the loop: the merge indexes every package already collected, so a per-file
    // merge is quadratic in the file count. A failure returns no rows (the readers' contract).
    std::vector<DpkgPackage> collected;
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
        collected.insert(collected.end(), std::make_move_iterator(parsed->begin()),
                         std::make_move_iterator(parsed->end()));
    }
    yuzu::shared::merge_dpkg_status_d(out.packages, std::move(collected));
    return out;
}

/// A name in var/lib/dpkg/updates that is an update-journal record: ASCII digits only. dpkg's own
/// rule (cleanupdates() in dbmodify.c); `tmp.i` and every other name is ignored.
[[nodiscard]] inline bool is_dpkg_journal_record(std::string_view name) noexcept {
    return !name.empty() && std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; });
}

/// Is a dpkg update journal pending? Returns the failure token, or "" when the directory holds no
/// record. `dpkg-query -W` printed the status file MERGED with these records (it replays them in
/// memory before it answers, whether or not it may write them back); this reader reads the status
/// file alone, so while a dpkg run is in progress, or after an interrupted one until dpkg next runs,
/// the status file alone is the PRE-journal roster. Merging means re-implementing dpkg's
/// record-replacement rules, a larger risk than the gap, so the answer is `dpkg_updates:locked` with
/// no rows. An absent directory means no journal; a link or non-directory in its place, or a listing
/// that fails, is a named failure and never "no journal". Nothing in the directory is opened or read:
/// only names are listed, through the same capped walk as status.d, the deadline polled per entry.
template <typename ReadDirFn = yuzu::shared::detail::DefaultReadDirFn>
[[nodiscard]] inline std::string
dpkg_updates_failure(const std::string& root, const Limits& lim, PkgDbBudget& budget,
                     ReadDirFn&& readdir_fn = &yuzu::shared::detail::default_readdir) {
    constexpr std::string_view kSource = "dpkg_updates";
    const std::string path = join(root, "var/lib/dpkg/updates");
    auto dir = yuzu::shared::open_dir_no_follow(path);
    if (!dir.opened())
        return dir.err == ENOENT ? std::string{} : failure_token(kSource, dir_open_cause(path, dir.err));

    std::optional<PkgDbCause> stopped; // why the callback ended the walk early
    const std::size_t entry_bound = dir_entry_bound(lim);
    const auto walk = yuzu::shared::walk_dir_capped(
        dir.dir.get(), entry_bound,
        [&](const struct dirent* e) {
            if (auto t = budget.check_time(); !t) {
                stopped = t.error();
                return false;
            }
            if (is_dpkg_journal_record(e->d_name)) {
                stopped = PkgDbCause::locked;
                return false;
            }
            return true;
        },
        std::forward<ReadDirFn>(readdir_fn));
    if (stopped)
        return failure_token(kSource, *stopped);
    if (walk.enumeration_error || walk.truncated)
        return failure_token(kSource, walk.enumeration_error ? PkgDbCause::unreadable : PkgDbCause::row_cap);
    return {};
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
    // A pending update journal makes the status file alone an incomplete roster (see
    // dpkg_updates_failure): refuse, discarding what was parsed, exactly as the status.d failure does.
    // Checked whether or not a status file or status.d exists: a journal record with no status beside
    // it is a dpkg tree this reader cannot interpret, and a named refusal beats a guessed "not dpkg".
    if (auto journal = dpkg_updates_failure(root, lim, budget); !journal.empty()) {
        out.packages.clear();
        out.failure = std::move(journal);
        return out;
    }
    yuzu::shared::merge_dpkg_status_d(out.packages, std::move(status_d.packages));
    return out;
}

// ── rpm ─────────────────────────────────────────────────────────────────────

struct RpmRead {
    bool found = false; ///< a database file (or an unsupported marker) exists in this directory
    /// The directory this candidate was opened as (fstat of the descriptor); empty when that failed,
    /// which can only turn a link to it into a refusal.
    std::optional<DirId> opened;
    /// This candidate is a symlink (never followed) with a database file behind it: the directory the
    /// link resolves to. read_host_packages refuses unless that directory is one it read itself.
    std::optional<DirId> symlinked_db;
    std::vector<RpmPackage> packages;
    std::string failure;
};

/// One header blob -> one package, or the cause the whole read fails with. The strings the package
/// keeps are charged to `budget`'s kept-text bound (Limits::rpm_max_kept_bytes).
[[nodiscard]] inline std::expected<RpmPackage, PkgDbCause>
collect_header(std::span<const std::uint8_t> blob, PkgDbBudget& budget) {
    auto header = yuzu::shared::RpmHeader::parse(blob);
    if (!header)
        return std::unexpected(header.error());
    return yuzu::shared::rpm_package_from_header(*header, budget);
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
                                                                static_cast<std::size_t>(len)),
                                  budget);
        if (!pkg)
            return std::unexpected(pkg.error());
        out.push_back(std::move(*pkg));
    }
    return out;
}

/// The lock query rpm_transaction_refusal makes: the real fcntl(F_GETLK). A function pointer type so a
/// test's own callable (a lambda with capture) overrides it through the template parameter.
using LockQueryFn = int (*)(int, struct flock*);
[[nodiscard]] inline int default_lock_query(int fd, struct flock* probe) noexcept {
    return ::fcntl(fd, F_GETLK, probe);
}

/// Is another process inside an rpm transaction? Answers the cause that refuses the read, or
/// nullopt when the database may be read. For the ndb and Berkeley DB files only: rpm rewrites them
/// IN PLACE (ndb clears a slot and zeroes its blob, moving neighbours; Berkeley DB pages reach the
/// file when a write cursor closes), and every writer holds rpm's transaction lock for the whole run
/// (rpmtsRun -> rpmtxnBegin(RPMTXN_WRITE): an fcntl write lock on `.rpm.lock`, created by rpm
/// beside the database). `rpm -qa` was isolated from a writer by the lock the library takes for it
/// (ndb: a shared flock on Packages.db; Berkeley DB: the shared environment), a read-only reader of
/// the raw file is not, and a read torn between a writer's steps can be a structurally valid, wrong
/// roster. So: ask fcntl(F_GETLK) whether a write lock would conflict, and read nothing if it would.
///
/// NEVER takes a lock (no flock, no F_SETLK): this reader must not delay rpm. The lock file is opened
/// through the database's own directory descriptor, the leaf not followed. ENOENT means no
/// transaction has ever run there: not locked. A link, a non-regular file or a failed fcntl is its own
/// cause, never "not locked". Residual: rpm's lock path is configurable (%_rpmlock_path); one moved
/// out of the database directory is not seen. The stamp stays as the second line of defence: with
/// the lock free after the first stamp, a writer already running has finished and a later one moves
/// the stamp.
///
/// The probe is a WRITE lock on purpose, so it also reports a SHARED holder. rpm 4.14's rpmlock.c only
/// ever asks for a write lock on the file, but rpm 4.20's rpmts.c takes a read lock for a transaction
/// begun without RPMTXN_WRITE (rpmtsVerifyDB, `rpmdb --verifydb`); other rpm files may do the same.
/// No query (`rpm -qa`) begins a transaction, so what a read-lock holder costs is one degraded read
/// while it runs (no rows, stored rows kept; the next read succeeds). A read-lock probe would be
/// exact, but it changes the mechanism and its kernel semantics cannot be shown on every host; this
/// is the conservative side. The probe type is pinned by test.
///
/// `lock_query` is fcntl(fd, F_GETLK, probe) and is overridable only for tests: no real filesystem
/// can be made to refuse the query, and a failed query must read as `unreadable`, never as free.
template <typename LockQuery = LockQueryFn>
[[nodiscard]] inline std::optional<PkgDbCause>
rpm_transaction_refusal(int dir_fd, LockQuery&& lock_query = &default_lock_query) {
    const auto lock = yuzu::shared::open_file_no_follow_at(dir_fd, ".rpm.lock");
    if (!lock.opened()) {
        if (lock.error == yuzu::shared::ReadError::io && lock.err == ENOENT)
            return std::nullopt;
        return cause_of(lock.error);
    }
    struct flock probe {};
    probe.l_type = F_WRLCK;
    probe.l_whence = SEEK_SET;
    probe.l_start = 0;
    probe.l_len = 0; // the whole file
    if (lock_query(lock.file.fd(), &probe) != 0)
        return PkgDbCause::unreadable;
    if (probe.l_type != F_UNLCK)
        return PkgDbCause::locked;
    return std::nullopt;
}

/// The directory `dir_path` resolves to when it is a symlink with a database file behind it, else
/// nothing (not a link, a dangling one, or no database file). stat only, which follows the whole
/// chain (a link to a link resolves to the same directory): nothing is opened or read through it.
[[nodiscard]] inline std::optional<DirId> symlink_hides_database(const std::string& dir_path) {
    struct stat st {};
    if (::lstat(dir_path.c_str(), &st) != 0 || !S_ISLNK(st.st_mode))
        return std::nullopt;
    struct stat target {};
    if (::stat(dir_path.c_str(), &target) != 0)
        return std::nullopt;
    for (const char* name : {"rpmdb.sqlite", "Packages.db", "Packages", "data.mdb"})
        if (::stat((dir_path + '/' + name).c_str(), &st) == 0)
            return dir_id_of(target);
    return std::nullopt;
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

    if (struct stat st {}; ::fstat(dir.dir.fd(), &st) == 0)
        out.opened = dir_id_of(st);

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
        // After the first stamp and before the first read: a writer already running has not finished,
        // and what it leaves is read by nobody. sqlite keeps its own isolation (a shared lock).
        if (c.read_blobs) {
            if (const auto refusal = rpm_transaction_refusal(dir.dir.fd())) {
                out.failure = failure_token(c.source, *refusal);
                return out;
            }
        }
        PkgDbBudget budget{.rows_left = lim.max_packages,
                           .bytes_left = lim.rpm_max_total_bytes,
                           .kept_left = lim.rpm_max_kept_bytes,
                           .max_item_bytes = lim.rpm_max_header_bytes,
                           .expired = expired};
        std::expected<std::vector<RpmPackage>, PkgDbCause> result;
        if (!c.read_blobs) {
            result = read_rpm_sqlite(join(dir_path, c.file), dir.dir.fd(), c.file, fd, lim, budget);
        } else {
            std::vector<RpmPackage> packages;
            const auto r = c.read_blobs(
                fd_source(fd, file.size), budget,
                [&packages, &budget](std::span<const std::uint8_t> blob) -> yuzu::shared::PkgDbVoid {
                    auto pkg = collect_header(blob, budget);
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
    // dpkg is the answer only when a stanza is `installed`: what inv_record_from_dpkg requires, and the
    // least app_record_from_dpkg requires (it also wants flag ok and want install or deinstall). A
    // status holding only config-files, half-installed and other non-installed states (a stale tree on
    // an rpm host) would yield no row, so it falls through. One whose installed stanzas all fail the
    // list mapper's extra test is still dpkg: inventory rows, no list row, as on the old path.
    if (std::any_of(dpkg.packages.begin(), dpkg.packages.end(),
                    [](const DpkgPackage& p) { return p.status == "installed"; })) {
        out.ecosystem = HostPackages::Ecosystem::dpkg;
        out.dpkg = std::move(dpkg.packages);
        return out;
    }

    static constexpr std::string_view kRpmDirs[] = {"usr/lib/sysimage/rpm", "var/lib/rpm",
                                                    "usr/share/rpm"};
    std::vector<detail::DirId> read_dirs; // directories whose database was read, even an empty one
    std::vector<detail::DirId> link_dirs; // directories behind the skipped links that hide a database
    for (const auto dir : kRpmDirs) {
        auto rpm = detail::read_rpm_dir(root, dir, lim, expired);
        if (!rpm.failure.empty()) {
            out.failure = std::move(rpm.failure);
            return out;
        }
        if (rpm.found) {
            if (rpm.opened)
                read_dirs.push_back(*rpm.opened);
            if (!rpm.packages.empty()) {
                out.ecosystem = HostPackages::Ecosystem::rpm;
                out.rpm = std::move(rpm.packages);
                return out;
            }
            continue; // a database with no package does not end detection
        }
        if (rpm.symlinked_db)
            link_dirs.push_back(*rpm.symlinked_db);
    }
    // A database that exists behind a link this reader never follows is a refusal, not an empty list,
    // unless the link resolves to a directory whose database was read here: on current Fedora, RHEL and
    // SUSE /var/lib/rpm links to the sysimage directory just read, and on the older layout the sysimage
    // link points at var/lib/rpm, which is read AFTER the link is seen. So the comparison is made once
    // the loop is done.
    const auto was_read = [&read_dirs](const detail::DirId& id) {
        return std::find(read_dirs.begin(), read_dirs.end(), id) != read_dirs.end();
    };
    if (!std::all_of(link_dirs.begin(), link_dirs.end(), was_read))
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
