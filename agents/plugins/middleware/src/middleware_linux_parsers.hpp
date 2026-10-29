/**
 * middleware_linux_parsers.hpp -- the Linux leg's file-walk layer for the middleware plugin, over
 * an INJECTED ROOT (production "/", the unit suite a materialized tree; runtimes_linux_parsers.hpp
 * shape). `#if !defined(_WIN32)`: built on POSIX openat. Rung 1, zero subprocess.
 *
 * WHAT IS READ is the product table (agents/shared/middleware_products.hpp), not this file. The
 * generic runner (middleware_runner.hpp) decides which files to read and in which order; this header
 * is the Fs it runs over (`LinuxFs`): it opens, reads and lists, and owns path safety.
 *
 *   read_abs     <root> + an absolute path, read whole (bounded), no symlink followed.
 *   list_under   the regular-file NAMES (never the content) of `<root><base>/<subdir>`.
 *
 * PATH DISCIPLINE. open_dir_no_follow / read_file_no_follow (path forms) follow INTERMEDIATE
 * symlinks (posix_secure_read.hpp), so they are never used. Every path, fixed or from file content
 * (a FilePath), is checked lexically (absolute; no empty, `.` or `..` component; no NUL; no
 * trailing '/'), then against the network mounts, then walked hop by hop with
 * openat(O_DIRECTORY|O_NOFOLLOW). A symlink at ANY hop is refused (no alias policy: there is no
 * candidate set); the leaf is read with read_file_no_follow_at. No std::filesystem iteration.
 *
 * REASON CLASSES (middleware_parsers.hpp). ENUMERATION failures (the fixed enumerator file
 * unreadable / oversized / behind a symlink / malformed, a dropped stanza, a cap,
 * `network_fs_skipped`, `mountinfo:unreadable`) are status tokens
 * `linux:middleware:<source>:<cause>`. PER-ITEM shortfalls (anything under ONE installation's
 * FilePath) degrade that row (version `-`), log one line, and never reach the status row.
 *
 * BOUNDS. ONE row/byte budget per action, built once by make_row_budget() from the injected
 * WalkLimits (clamped there to the production ceilings kMaxRows, kMaxRowBytes), and handed to the
 * runner, which charges it per row. The walk keeps only its own entries-visited allowance
 * (WalkBudget): 65536 directory entries across every listing of the action; the runner turns its
 * exhaustion into `walk:row_cap` and ends the walk. /proc/self/mountinfo is read once per dispatch;
 * a path on, under or containing a network mount of that snapshot is skipped before any syscall
 * touches it (a mount made later is not seen, and an unreadable table is reported as
 * `mountinfo:unreadable`).
 *
 * PRIVATE COPIES. These are copied from agents/plugins/runtimes/src/runtimes_linux_parsers.hpp
 * (adapted to this Fs): touches_network_mount, finish_dir_open, open_child, scan_mounts,
 * production_config and the kMountinfo* constants. Follow-up OWED, no tracking issue yet: once the
 * in-flight runtimes work (SAM.1) has landed, hoist them into agents/shared so both plugins include
 * one copy. Until then a fix to one copy is a fix to the other.
 */
#pragma once

#include "middleware_legs.hpp"
#include "middleware_parsers.hpp"
#include "middleware_runner.hpp"

#if !defined(_WIN32)

#include <network_fstype.hpp>      // yuzu::shared::is_network_fstype, network_mount_points
#include <posix_dir_walk.hpp>      // yuzu::shared::walk_dir_capped
#include <posix_secure_read.hpp>   // yuzu::shared::ScopedDir, read_file_no_follow_at

#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd (agents/core; POSIX-only header)

#include <spdlog/spdlog.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::middleware::lnx {

using yuzu::shared::ConstraintAccumulator;

// -- bounds ---------------------------------------------------------------------------------

inline constexpr std::size_t kMaxEntriesVisited = 65536;
/// /proc/self/mountinfo is STREAMED (procfs reports st_size 0 and a container host's table runs to
/// tens of megabytes); see runtimes_linux_parsers.hpp for the measurements behind these.
inline constexpr std::size_t kMountinfoChunk = 64 * 1024;
inline constexpr std::size_t kMaxMountinfoLine = 64 * 1024;
inline constexpr std::size_t kMaxMountinfoBytes = 256 * 1024 * 1024;

/// The bounds one action's walk runs under; a parameter so every bound is testable without
/// thousands of files. `rows` and `row_bytes` default to the production ceilings and are clamped to
/// them by make_row_budget(), so an injected value can lower a cap but never raise one.
/// `dir_entries` is THE per-listing cap (the Fs enforces it; there is no second one).
struct WalkLimits {
    std::size_t dir_entries = kMaxDirEntries;
    std::size_t rows = kMaxRows;
    std::size_t row_bytes = kMaxRowBytes;
    std::size_t entries_visited = kMaxEntriesVisited;
};

/// The walk's bounds plus the absolute mount points of the network filesystems to keep away from
/// (empty: no guard, the unit-suite default). `mountinfo_unreadable`: the mount table could not be
/// read in full (the walk still runs, guarded only by the mounts read).
struct WalkConfig {
    WalkLimits limits{};
    std::vector<std::string> network_mounts{};
    bool mountinfo_unreadable = false;
};

// -- path guards (pure) ----------------------------------------------------------------------

/// The components of an absolute path ("/a/b" -> a, b), unvalidated.
[[nodiscard]] inline std::vector<std::string_view> split_path(std::string_view path) {
    std::vector<std::string_view> out;
    std::size_t pos = 1;
    while (pos <= path.size()) {
        auto sl = path.find('/', pos);
        if (sl == std::string_view::npos) sl = path.size();
        out.push_back(path.substr(pos, sl - pos));
        pos = sl + 1;
    }
    return out;
}

/// True iff `path` is absolute with only plain components: no NUL, no empty component (so no "//"
/// and no trailing '/'), no `.` and no `..`. Nothing is resolved; "/" alone has no leaf: refused.
[[nodiscard]] inline bool lexically_plain(std::string_view path) {
    if (path.size() < 2 || path.front() != '/' || path.back() == '/') return false;
    if (path.find('\0') != std::string_view::npos) return false;
    for (const auto c : split_path(path))
        if (c.empty() || c == "." || c == "..") return false;
    return true;
}

/// True iff `path` (absolute, plain) is on or under a listed mount point, or contains one: a walk of
/// `path` then touches that mount. The root mount "/" contains everything.
[[nodiscard]] inline bool touches_network_mount(std::string_view path,
                                                std::span<const std::string> mounts) {
    const auto under = [](std::string_view inner, std::string_view outer) {
        if (outer == "/") return true;
        if (outer.size() > inner.size() || inner.substr(0, outer.size()) != outer) return false;
        return inner.size() == outer.size() || inner[outer.size()] == '/';
    };
    for (const auto& m : mounts)
        if (under(path, m) || under(m, path)) return true;
    return false;
}

// -- outcomes ---------------------------------------------------------------------------------

/// What one open or read came to. `refused` = lexically unacceptable path, `network` = the mount
/// guard, `symlink` = a symlink at some hop or leaf; the rest are the errno classes. It IS the
/// runner's Read::Outcome: one vocabulary from the syscall to the Fs the runner sees.
using Outcome = yuzu::middleware::Read::Outcome;

[[nodiscard]] inline Outcome outcome_from_errno(int err) noexcept {
    switch (err) {
    case ENOENT: return Outcome::absent;
    case EACCES:
    case EPERM:  return Outcome::denied;
    case ELOOP:  return Outcome::symlink;
    default:     return Outcome::failed;
    }
}

[[nodiscard]] inline Outcome guard(std::string_view path, const WalkConfig& cfg) {
    if (!lexically_plain(path)) return Outcome::refused;
    if (touches_network_mount(path, cfg.network_mounts)) return Outcome::network;
    return Outcome::ok;
}

// -- the walk ---------------------------------------------------------------------------------

inline constexpr int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

using FileId = std::pair<dev_t, ino_t>;

/// TEST SEAM, null in production: when set, the (st_dev, st_ino) of every directory the walk
/// opens is appended, so a unit test can prove a refused path was never touched -- the rows and
/// tokens of a refusal are the same whether or not the walk opened the path first, and a dead
/// network mount blocks on the open itself. Per thread: the unit suite runs the leg in-thread.
inline thread_local std::vector<FileId>* t_touch_log = nullptr;

struct Opened {
    yuzu::shared::ScopedDir dir;
    Outcome out = Outcome::absent; // ok iff `dir` is open
};

/// Completes an already-attempted open (`fd`, errno current if fd < 0) of `name` relative to
/// `stat_dirfd`. A symlink at that exact component is classified by fstatat rather than by errno:
/// O_DIRECTORY|O_NOFOLLOW on a symlink measures ENOTDIR on Darwin and on Linux (glibc and musl);
/// the ELOOP arm is kept for libcs that report it.
inline Opened finish_dir_open(int fd, int stat_dirfd, const char* name) {
    Opened o;
    if (fd < 0) {
        const int err = errno;
        if (err == ENOENT) return o;
        struct stat st{};
        if (::fstatat(stat_dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
            o.out = Outcome::symlink;
            return o;
        }
        o.out = outcome_from_errno(err);
        return o;
    }
    if (t_touch_log != nullptr) {
        struct stat st{};
        if (::fstat(fd, &st) == 0) t_touch_log->emplace_back(st.st_dev, st.st_ino);
    }
    DIR* d = ::fdopendir(fd);
    if (d == nullptr) {
        const int err = errno;
        ::close(fd);
        o.out = outcome_from_errno(err);
        return o;
    }
    o.dir = yuzu::shared::ScopedDir{d};
    o.out = Outcome::ok;
    return o;
}

/// The injected root itself (O_NOFOLLOW checks its final component only).
inline Opened open_root(const std::string& root) {
    return finish_dir_open(::open(root.c_str(), kDirFlags), AT_FDCWD, root.c_str());
}

/// One path component via openat from an already-open parent.
inline Opened open_child(DIR* parent, std::string_view name) {
    const std::string n{name};
    const int pfd = ::dirfd(parent);
    return finish_dir_open(::openat(pfd, n.c_str(), kDirFlags), pfd, n.c_str());
}

/// Walks `comps` hop by hop below `cur` (already open). Stops at the first hop that is not a
/// plain directory; the returned Opened carries that hop's outcome.
inline Opened descend(Opened cur, std::span<const std::string_view> comps) {
    for (const auto c : comps) {
        if (cur.out != Outcome::ok) break;
        cur = open_child(cur.dir.get(), c);
    }
    return cur;
}

/// <root>/<path> as an open directory, after the lexical and mount guards.
inline Opened open_dir_abs(const std::string& root, std::string_view path, const WalkConfig& cfg) {
    if (const auto g = guard(path, cfg); g != Outcome::ok) {
        Opened o;
        o.out = g;
        return o;
    }
    const auto comps = split_path(path);
    return descend(open_root(root), comps);
}

/// The regular file `name` under the open directory `d`: a symlink leaf, a non-regular file and
/// anything over `cap` bytes are refused (O_NOFOLLOW|O_NONBLOCK, so a FIFO cannot hang the agent).
inline Read read_leaf(DIR* d, std::string_view name, std::size_t cap) {
    Read r;
    const std::string n{name};
    auto f = yuzu::shared::read_file_no_follow_at(::dirfd(d), n.c_str(), cap);
    switch (f.error) {
    case yuzu::shared::ReadError::none:
        r.out = Outcome::ok;
        r.text = std::move(f.data);
        break;
    case yuzu::shared::ReadError::symlink_refused: r.out = Outcome::symlink; break;
    case yuzu::shared::ReadError::not_regular:     r.out = Outcome::failed; break;
    case yuzu::shared::ReadError::oversized:       r.out = Outcome::oversized; break;
    case yuzu::shared::ReadError::io:              r.out = outcome_from_errno(f.err); break;
    }
    return r;
}

/// <root>/<path> as a bounded file read: guards, then every parent hop O_NOFOLLOW, then the leaf.
inline Read read_abs(const std::string& root, std::string_view path, std::size_t cap,
                     const WalkConfig& cfg) {
    Read r;
    if (const auto g = guard(path, cfg); g != Outcome::ok) {
        r.out = g;
        return r;
    }
    auto comps = split_path(path);
    const std::string_view leaf = comps.back(); // lexically_plain guarantees at least one
    comps.pop_back();
    const Opened dir = descend(open_root(root), comps);
    if (dir.out != Outcome::ok) {
        r.out = dir.out;
        return r;
    }
    return read_leaf(dir.dir.get(), leaf, cap);
}

/// Running account of ONE action's directory walk against its entries-visited limit, across every
/// candidate and listing. `exhausted` is sticky; the runner reads it through LinuxFs::exhausted(),
/// records `walk:row_cap` and ends the walk. Rows and row bytes are NOT counted here: that budget
/// is the runner caller's.
struct WalkBudget {
    explicit WalkBudget(const WalkLimits& l) noexcept : entries_left(l.entries_visited) {}
    std::size_t entries_left;
    bool exhausted = false;
};

/// The regular-file names of one open directory, sorted. Reads at most the smaller of `dir_cap`
/// and what is left of the action's entries-visited budget, and charges every entry read to that
/// budget. `truncated`: the cap hit with entries unread -- the aggregate budget running out sets
/// `exhausted` (the runner records `walk:row_cap` and stops); the per-directory cap alone is left to
/// the caller, whose item it belongs to. `io_error`: readdir failed, or an entry could not be examined
/// for a reason other than having vanished (a readable, non-searchable directory).
struct Entries {
    std::vector<std::string> names;
    bool truncated = false;
    bool io_error = false;
};

inline Entries list_regular(DIR* d, WalkBudget& budget, std::size_t dir_cap) {
    Entries out;
    if (budget.exhausted) return out;
    const std::size_t cap = std::min(dir_cap, budget.entries_left);
    std::size_t seen = 0;
    const int fd = ::dirfd(d);
    const auto res = yuzu::shared::walk_dir_capped(d, cap, [&](const struct dirent* e) {
        ++seen;
        struct stat st{};
        if (::fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) out.io_error = true; // ENOENT: removed since readdir, benign
        } else if (S_ISREG(st.st_mode)) {
            out.names.emplace_back(e->d_name);
        }
        return true;
    });
    budget.entries_left -= seen; // seen <= cap <= entries_left
    out.truncated = res.truncated;
    out.io_error = out.io_error || res.enumeration_error;
    if (res.truncated && budget.entries_left == 0) budget.exhausted = true;
    std::sort(out.names.begin(), out.names.end());
    return out;
}

// -- the runner's Fs over a real tree ------------------------------------------------------------

/// The Fs concept of middleware_runner.hpp over `root` (production "/"). Holds the action's
/// entries-visited allowance; owns no row budget.
class LinuxFs {
public:
    LinuxFs(std::string root, WalkConfig cfg)
        : root_(std::move(root)), cfg_(std::move(cfg)), budget_(cfg_.limits) {}

    [[nodiscard]] Read read_abs(std::string_view path, std::size_t cap) {
        return lnx::read_abs(root_, path, cap, cfg_);
    }

    /// The file names of `<base>/<subdir>`: the guards judge `base` (an installer-supplied path),
    /// `subdir` is a table constant. At most limits.dir_entries entries are read.
    [[nodiscard]] Listing list_under(std::string_view base, std::string_view subdir) {
        Listing l;
        const Opened home = open_dir_abs(root_, base, cfg_);
        if (home.out != Outcome::ok) {
            l.out = home.out;
            return l;
        }
        const Opened sub = open_child(home.dir.get(), subdir);
        if (sub.out != Outcome::ok) {
            l.out = sub.out;
            return l;
        }
        Entries e = list_regular(sub.dir.get(), budget_, cfg_.limits.dir_entries);
        l.names = std::move(e.names);
        l.truncated = e.truncated;
        l.error = e.io_error;
        return l;
    }

    [[nodiscard]] bool exhausted() const noexcept { return budget_.exhausted; }
    [[nodiscard]] std::string_view os() const noexcept { return "linux"; }

private:
    std::string root_;
    WalkConfig cfg_;
    WalkBudget budget_;
};

static_assert(MiddlewareFs<LinuxFs>, "LinuxFs must satisfy the runner's Fs concept");

// -- the leg ---------------------------------------------------------------------------------

// -- mount table ------------------------------------------------------------------------------

/// The mount table at `path` (production: /proc/self/mountinfo) reduced to its network mount
/// points, streamed line-wise. `ok` is false when it cannot be read in full (absent, refused, not
/// a regular file, an I/O error, more than `max_total` bytes, or a line too long to keep, which is
/// skipped and the scan goes on): the caller then records `mountinfo:unreadable`.
struct MountScan {
    std::vector<std::string> network_mounts;
    bool ok = false;
};

inline MountScan scan_mounts(const char* path, std::size_t max_total = kMaxMountinfoBytes) {
    MountScan s;
    const int fd = ::open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return s;
    const yuzu::agent::ScopedFd guard_fd{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return s;
    const auto take = [&s](std::string_view lines) {
        for (auto& m : yuzu::shared::network_mount_points(lines)) s.network_mounts.push_back(std::move(m));
    };
    std::string chunk(kMountinfoChunk, '\0');
    std::string pending; // the unfinished last line of what has been read so far
    std::size_t total = 0;
    bool whole = true;     // false once a line was too long to keep
    bool skipping = false; // inside such a line: drop bytes up to its newline
    for (;;) {
        const ssize_t n = ::read(fd, chunk.data(), chunk.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return s;
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
        if (total > max_total) return s;
        std::string_view in{chunk.data(), static_cast<std::size_t>(n)};
        if (skipping) {
            const auto nl = in.find('\n');
            if (nl == std::string_view::npos) continue; // still inside the long line
            in.remove_prefix(nl + 1);
            skipping = false;
        }
        pending.append(in);
        if (const auto nl = pending.rfind('\n'); nl != std::string::npos) {
            take(std::string_view{pending}.substr(0, nl + 1));
            pending.erase(0, nl + 1);
        }
        if (pending.size() > kMaxMountinfoLine) {
            pending.clear();
            skipping = true;
            whole = false;
        }
    }
    if (!skipping) take(pending);
    s.ok = whole;
    return s;
}

/// Production's WalkConfig: the default bounds plus the network mount points read from
/// /proc/self/mountinfo (`mountinfo:unreadable` when it cannot be read in full).
[[nodiscard]] inline WalkConfig production_config(
    const char* mountinfo_path = "/proc/self/mountinfo") {
    auto scan = scan_mounts(mountinfo_path);
    WalkConfig cfg;
    cfg.network_mounts = std::move(scan.network_mounts);
    cfg.mountinfo_unreadable = !scan.ok;
    return cfg;
}

/// The Linux leg body with the filesystem root injected: the generic runner over a LinuxFs, then
/// `emit_read` (status row first, then every data row, then the typed result status).
/// middleware_linux.cpp's `run_linux` calls it with "/" and production_config(); the unit suite
/// drives it over a materialized tree through a real CommandContext. Returns 0 unconditionally: a
/// degraded read is not a failed command; the degradation rides the status row and
/// set_result_status.
///
/// THE row/byte budget of the action is built here, once, by make_row_budget (the injected limits
/// clamped to the production ceilings, so a test can lower a cap but never raise one). A per-item
/// shortfall is one log line (the installation's name is installer text, so it goes through the
/// wire escaper before it reaches the log) and degrades that row only.
inline int run_linux_at(yuzu::CommandContext& ctx, const Product& p,
                        const std::filesystem::path& root, const WalkConfig& cfg) {
    ConstraintAccumulator acc;
    if (cfg.mountinfo_unreadable) acc.add_failure(make_token("linux", "mountinfo", Cause::unreadable));
    auto budget = make_row_budget(cfg.limits.rows, cfg.limits.row_bytes);
    LinuxFs fs{root.string(), cfg};
    const auto rows = run_leg(
        p, p.linux, fs, acc, budget,
        [](std::string_view product, std::string_view probe, ItemReason reason,
           std::string_view item) {
            spdlog::info("middleware {}: {}: {} ({})", product, probe, item_reason_name(reason),
                         yuzu::util::safe_output_field(item));
        });
    emit_read(ctx, p, rows, acc);
    return 0;
}

} // namespace yuzu::middleware::lnx

#endif // !defined(_WIN32)
