/**
 * runtimes_linux_parsers.hpp -- the Linux leg's directory-walk layer for the
 * runtimes plugin, over an INJECTED ROOT (peripherals_linux_parsers.hpp shape:
 * production passes "/", the unit suite a materialized fixture tree).
 *
 * Two halves: a PORTABLE pure layer (failure tokens, errno -> token maps, path
 * helpers) that compiles on every OS, and a WALK SHELL (`#if !defined(_WIN32)`,
 * because agents/shared/posix_dir_walk.hpp is POSIX-only) holding
 * `dotnet_rows_at` / `jvm_rows_at` and the injected-root leg body
 * `run_linux_at`.
 *
 * WHAT IS READ (<root> + a literal, rung 1, zero subprocess):
 *   dotnet  usr/share/dotnet, usr/lib/dotnet, usr/lib64/dotnet:
 *           shared/<framework>/<version> and sdk/<version> directory names.
 *   jvm     usr/lib/jvm/<d>, opt/java/<d>, usr/lib64/jvm/<d> (openSUSE/SLES) and
 *           var/opt/java/<d> (rpm-ostree hosts, where /opt is a symlink to var/opt):
 *           <d>/release (parse_release_file). A home with no `release` file but a
 *           bin/java or jre/bin/java (some distro OpenJDK 8 packages, e.g. Ubuntu and
 *           Rocky, ship none) is reported with an unknown version and `release_missing`.
 *   NOT walked: any other location (an Oracle-RPM /usr/java, tarball installs under
 *   /usr/local or a home directory). "None found" covers the roots above only.
 *
 * SYMLINK SAFETY. Every directory is opened O_RDONLY|O_DIRECTORY|O_NOFOLLOW
 * (private copy of autoruns_macos.cpp's open_dir_no_follow_checked /
 * open_dir_no_follow_at_checked + dir_open_outcome_from_fd trichotomy),
 * hop-by-hop with openat from an already-open parent; entries are enumerated
 * with yuzu::shared::walk_dir_capped. The std::filesystem directory iterator is
 * never used. A symlink is never followed.
 *
 * A REFUSED SYMLINK IS NEVER AN EMPTY SUCCESS. A symlink at a candidate root
 * (or on the way to one) is a silent ALIAS only when its link text lexically
 * names ANOTHER candidate of the same action and that candidate is not itself
 * a symlink: whatever is there (a real directory, nothing at all, or an
 * unreadable directory that is then reported) is reached through that
 * candidate's own path, so the alias adds nothing (Fedora /usr/share/dotnet ->
 * ../lib64/dotnet; Arch /usr/lib64 -> lib, with or without a .NET install).
 * Any other refused candidate -- target outside the candidate set, a cycle or
 * a chain of aliases, an unreadable link, a symlinked injected root -- records
 * `symlink_refused` (constrained), as does a symlinked fixed `shared` / `sdk`
 * subdirectory and a symlinked `release` file.
 *
 * ENUMERATED ENTRY SYMLINKS ARE SKIPPED SILENTLY (a framework, version or JVM
 * home that is itself a symlink, including one swapped in between listing and
 * open, which the O_NOFOLLOW open classifies as an alias): distribution alias
 * entries (Debian default-java and java-1.17.0-openjdk-*, Fedora java ->
 * /etc/alternatives) are pervasive and their real directory is a sibling
 * entry. Documented gap: a runtime reachable ONLY through such an entry
 * symlink is not inventoried.
 *
 * FAILURE NEVER READS AS ABSENT. An absent candidate (ENOENT) is silent: with no
 * failure recorded the answer is `supported` + zero rows, meaning none found at
 * THESE roots. Any other failed open/stat/read, and every skip (a network mount,
 * a cap), records a `linux:runtimes:<reason>` token in the caller's
 * ConstraintAccumulator, shared across every root of an action, so a later
 * successful root never erases an earlier failure.
 *
 * BOUNDED WORK AND MEMORY. kMaxDirEntries per directory (`row_cap`, the walk goes
 * on); kMaxReleaseBytes per `release` file and kMaxReleaseValueBytes per recognised
 * value (`oversized`, `field_oversized`); and, across ALL roots and nesting levels
 * of one action, WalkLimits (rows, row bytes, entries visited) -- the per-directory
 * cap alone multiplies with nesting. Exhausting the row, row-byte or entries-visited
 * budget stops the walk with `row_cap`.
 *
 * NETWORK MOUNTS ARE NOT WALKED. An open/getdents on a hard NFS/CIFS/FUSE mount
 * whose server is down blocks in the kernel with no deadline and pins one of the
 * agent's shared command workers. The production leg reads /proc/self/mountinfo
 * once, at dispatch start (scan_mounts, streamed: a container host's table runs to
 * tens of megabytes); a candidate root that is on, under or contains a network
 * mount (yuzu::shared::is_network_fstype) is skipped BEFORE any syscall touches it
 * and records `network_fs_skipped`. A healthy network-mounted JDK is skipped too,
 * and a network-typed `/` skips every candidate. When the table cannot be read in
 * full the walk runs guarded only by the mounts read (`mountinfo_unreadable`).
 * Residuals a plugin cannot close: a mount that appears after the snapshot, a
 * STACKED filesystem (an overlay, ecryptfs or loop device over a dead network mount
 * reports its own local type), a network or FUSE type the deny-list does not name
 * (bare `fuse` among them), and a hang on a local block device.
 */
#pragma once

#include "runtimes_legs.hpp"
#include "runtimes_parsers.hpp"

#include <network_fstype.hpp> // yuzu::shared::is_network_fstype (agents/shared)

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd (agents/core; POSIX-only header)

#include <posix_dir_walk.hpp> // yuzu::shared::walk_dir_capped (agents/shared)

#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yuzu::runtimes::lnx {

// -- failure tokens ------------------------------------------------------------
//
// All match ^linux:[a-z0-9_]+(:[a-z0-9_]+)*$ (the plugin-wide leg-token grammar). The
// cause names shared with the sibling plugins (`oversized`, `not_regular`, `row_cap`,
// `open_failed`; see constraint_accumulator.hpp) keep those spellings so a consumer keys on
// one vocabulary.

inline constexpr std::string_view kTokPermissionDenied = "linux:runtimes:permission_denied";
inline constexpr std::string_view kTokSymlinkRefused = "linux:runtimes:symlink_refused";
inline constexpr std::string_view kTokNotADirectory = "linux:runtimes:not_a_directory";
inline constexpr std::string_view kTokOpenFailed = "linux:runtimes:open_failed";
inline constexpr std::string_view kTokStatFailed = "linux:runtimes:stat_failed";
inline constexpr std::string_view kTokReadFailed = "linux:runtimes:read_failed";
inline constexpr std::string_view kTokRowCap = "linux:runtimes:row_cap";
inline constexpr std::string_view kTokNotRegular = "linux:runtimes:not_regular";
inline constexpr std::string_view kTokOversized = "linux:runtimes:oversized";
inline constexpr std::string_view kTokFieldOversized = "linux:runtimes:field_oversized";
inline constexpr std::string_view kTokReleaseUnparsable = "linux:runtimes:release_unparsable";
inline constexpr std::string_view kTokReleaseMissing = "linux:runtimes:release_missing";
inline constexpr std::string_view kTokNetworkFsSkipped = "linux:runtimes:network_fs_skipped";
inline constexpr std::string_view kTokMountinfoUnreadable = "linux:runtimes:mountinfo_unreadable";

/// Per-directory entry cap (`row_cap` when more real entries remain).
inline constexpr std::size_t kMaxDirEntries = 16384;
/// `release` read bound.
inline constexpr std::size_t kMaxReleaseBytes = 64 * 1024;
/// `/proc/self/mountinfo` is STREAMED, not slurped: procfs reports st_size 0 and a container host's
/// table runs to tens of megabytes (16k mounts measured at 24.7 MB), so a whole-file cap fails the
/// guard OPEN on exactly the busiest hosts and a larger one multiplies memory by the command pool.
/// Bounds: kMountinfoChunk bytes per read; an unfinished line longer than kMaxMountinfoLine (a real
/// line is a few KiB, an overlay with hundreds of layers ~100 KiB) is dropped, not kept, and
/// scanning resumes at its newline (a line over 2 x the chunk is always dropped); and a runaway
/// bound on the whole read.
inline constexpr std::size_t kMountinfoChunk = 64 * 1024;
inline constexpr std::size_t kMaxMountinfoLine = 64 * 1024;
inline constexpr std::size_t kMaxMountinfoBytes = 256 * 1024 * 1024;

/// Aggregate bounds for ONE action's walk, shared by every root and nesting level. A real host
/// holds tens of runtimes; these leave two orders of magnitude of headroom while capping what a
/// tree planted under a writable root (a user-owned /opt/java) can make the agent hold or scan.
inline constexpr std::size_t kMaxRows = 4096;
inline constexpr std::size_t kMaxRowBytes = 1024 * 1024;
inline constexpr std::size_t kMaxEntriesVisited = 65536;

/// The bounds one walk runs under (production: the defaults; a parameter so every bound and its
/// `row_cap` propagation is testable without tens of thousands of files).
struct WalkLimits {
    std::size_t dir_entries = kMaxDirEntries;
    std::size_t rows = kMaxRows;
    std::size_t row_bytes = kMaxRowBytes;
    std::size_t entries_visited = kMaxEntriesVisited;
};

/// Everything a walk needs besides the root: its bounds and the absolute mount points of the
/// network filesystems to keep away from (empty: no guard, the unit-suite default).
/// `mountinfo_unreadable`: the mount table could not be read in full (the walk still runs, guarded
/// by the mounts read).
struct WalkConfig {
    WalkLimits limits{};
    std::vector<std::string> network_mounts{};
    bool mountinfo_unreadable = false;
};

// -- portable pure layer ---------------------------------------------------------

/// errno from a failed open/openat of a DIRECTORY -> reason token; nullopt for
/// ENOENT (genuinely absent: not a failure). ENOTDIR is a real constraint (a
/// non-directory where a directory was expected); the walk shell classifies a
/// symlink (an alias) BEFORE reaching this map.
[[nodiscard]] inline std::optional<std::string_view> dir_open_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    case ENOTDIR: return kTokNotADirectory;
    default:     return kTokOpenFailed;
    }
}

/// errno from a failed fstatat on a directory entry -> reason token; nullopt
/// for ENOENT (the entry vanished between listing and stat: a race, not a
/// failure).
[[nodiscard]] inline std::optional<std::string_view> stat_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    default:     return kTokStatFailed;
    }
}

/// errno from a failed open of a regular FILE (`release`) -> reason token;
/// nullopt for ENOENT (no such file: this directory is not a JVM home).
[[nodiscard]] inline std::optional<std::string_view> file_open_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    default:     return kTokReadFailed;
    }
}

/// `dir` + "/" + `name`, avoiding a doubled slash when dir is "/".
[[nodiscard]] inline std::string join_logical(std::string_view dir, std::string_view name) {
    std::string out{dir};
    if (out.empty() || out.back() != '/') out += '/';
    out.append(name);
    return out;
}

/// Candidate roots (root-relative, normalised), grouped by what they hold. A
/// symlinked candidate is an alias only of another candidate in ITS group.
inline constexpr std::array<std::string_view, 3> kDotnetRoots{"usr/share/dotnet", "usr/lib/dotnet",
                                                              "usr/lib64/dotnet"};
// usr/lib64/jvm: openSUSE/SLES keep their JVMs there and have no /usr/lib/jvm (measured on
// openSUSE Leap 15.6, provenance.txt). var/opt/java: on rpm-ostree hosts (Fedora CoreOS,
// Silverblue, RHCOS, RHEL Edge) /opt is a symlink to var/opt, so without this candidate every
// jvm dispatch would report `symlink_refused` for opt/java; with it the link is a covered alias.
inline constexpr std::array<std::string_view, 4> kJvmRoots{"usr/lib/jvm", "opt/java", "usr/lib64/jvm",
                                                           "var/opt/java"};

/// Lexically normalises a root-relative path: empty and `.` components dropped,
/// `..` pops one. nullopt when a `..` would climb above the root. Pure text --
/// nothing is resolved on disk.
[[nodiscard]] inline std::optional<std::string> normalize_rel(std::string_view path) {
    std::vector<std::string_view> parts;
    std::size_t pos = 0;
    while (pos <= path.size()) {
        auto sl = path.find('/', pos);
        if (sl == std::string_view::npos) sl = path.size();
        const auto comp = path.substr(pos, sl - pos);
        pos = sl + 1;
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") {
            if (parts.empty()) return std::nullopt;
            parts.pop_back();
            continue;
        }
        parts.push_back(comp);
    }
    std::string out;
    for (const auto c : parts) {
        if (!out.empty()) out += '/';
        out.append(c);
    }
    return out;
}

/// Where a symlink found at <parent_rel>/<name> (link text `target`) would send
/// a walk that still had `remaining` components to go, as a normalised
/// root-relative path. An absolute target is read from the injected root.
/// nullopt if it climbs above the root. Never touches the filesystem.
[[nodiscard]] inline std::optional<std::string> alias_target_rel(std::string_view parent_rel,
                                                                 std::string_view target,
                                                                 std::string_view remaining) {
    std::string joined;
    if (!target.empty() && target.front() == '/') joined = std::string{target};
    else joined = std::string{parent_rel} + "/" + std::string{target};
    if (!remaining.empty()) joined += "/" + std::string{remaining};
    return normalize_rel(joined);
}

// -- network-mount guard (pure) ---------------------------------------------------

/// Decodes the octal escapes /proc/self/mountinfo uses inside a field (\040 space, \011 tab,
/// \012 newline, \134 backslash). A malformed escape is kept verbatim.
[[nodiscard]] inline std::string unescape_mountinfo(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool octal = s[i] == '\\' && i + 3 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '3' &&
                           s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7';
        if (!octal) {
            out += s[i];
            continue;
        }
        out += static_cast<char>(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) | (s[i + 3] - '0'));
        i += 3;
    }
    return out;
}

/// The mount points of network-backed filesystems in /proc/self/mountinfo text. A line is
/// `id parent maj:min root mount_point options [optional...] - fstype source super_options`;
/// the mount point is field 5 and the filesystem type follows the ` - ` separator. A malformed
/// line is skipped (it names no mount we can avoid); a well-formed line of a local type is not
/// reported.
[[nodiscard]] inline std::vector<std::string> network_mount_points(std::string_view mountinfo) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < mountinfo.size()) {
        const auto nl = mountinfo.find('\n', pos);
        const std::string_view line =
            mountinfo.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? mountinfo.size() : nl + 1;
        const auto sep = line.find(" - ");
        if (sep == std::string_view::npos) continue;
        const std::string_view head = line.substr(0, sep);
        std::string_view mount_point; // the 5th space-separated field of the head
        std::size_t start = 0;
        for (int field = 0; field <= 4 && start <= head.size(); ++field) {
            const auto sp = head.find(' ', start);
            const auto end = sp == std::string_view::npos ? head.size() : sp;
            if (field == 4) mount_point = head.substr(start, end - start);
            start = end + 1;
        }
        if (mount_point.empty()) continue;
        const auto after = line.substr(sep + 3);
        const auto fstype = after.substr(0, after.find(' '));
        if (!yuzu::shared::is_network_fstype(fstype)) continue;
        out.push_back(unescape_mountinfo(mount_point));
    }
    return out;
}

/// True iff `path` (absolute, normalised) is on or under a listed mount point, or contains one:
/// a walk of `path` then touches that mount. The root mount "/" contains everything.
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

// -- POSIX walk shell ------------------------------------------------------------

#if !defined(_WIN32)

namespace walk {

using yuzu::shared::ConstraintAccumulator;

/// Move-only RAII owner for a POSIX DIR* (closes its fd too).
class DirHandle {
public:
    DirHandle() noexcept = default;
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() { reset(); }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    DirHandle(DirHandle&& o) noexcept : dir_(o.dir_) { o.dir_ = nullptr; }
    DirHandle& operator=(DirHandle&& o) noexcept {
        if (this != &o) {
            reset();
            dir_ = o.dir_;
            o.dir_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] explicit operator bool() const noexcept { return dir_ != nullptr; }

private:
    void reset() noexcept {
        if (dir_ != nullptr) ::closedir(dir_);
        dir_ = nullptr;
    }
    DIR* dir_ = nullptr;
};

/// Outcome of one directory open: `opened`, `absent` (ENOENT), `alias` (the
/// component is a symlink -- skipped, never followed) or `failed` (+ token).
enum class OpenStatus { opened, absent, alias, failed };

struct Opened {
    DirHandle dir;
    OpenStatus status = OpenStatus::absent;
    std::string_view token{}; // set iff status == failed
};

inline constexpr int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

/// Completes an already-attempted open (`fd`, errno current if fd < 0) of
/// `name` relative to `stat_dirfd`: fdopendir on success; on failure ENOENT =
/// absent, a symlink at that exact component = alias (classified by fstatat
/// rather than by errno: O_DIRECTORY|O_NOFOLLOW on a symlink measured ENOTDIR on
/// Darwin 25.6 and on Linux 7.0 (glibc and musl); the ELOOP arms elsewhere are
/// kept for libcs that report it), anything else = a constraint.
inline Opened finish_dir_open(int fd, int stat_dirfd, const char* name) {
    Opened o;
    if (fd < 0) {
        const int err = errno;
        if (err == ENOENT) return o; // absent
        struct stat st{};
        if (::fstatat(stat_dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
            o.status = OpenStatus::alias;
            return o;
        }
        o.status = OpenStatus::failed;
        o.token = dir_open_errno_token(err).value_or(kTokOpenFailed);
        return o;
    }
    yuzu::agent::ScopedFd owned{fd}; // closed on the failure path below
    DIR* d = ::fdopendir(owned.get());
    if (d == nullptr) {
        const int err = errno; // read before ScopedFd's close can disturb it
        o.status = OpenStatus::failed;
        o.token = dir_open_errno_token(err).value_or(kTokOpenFailed);
        return o;
    }
    (void)owned.release(); // fdopendir() succeeded: the DIR* owns the fd now
    o.dir = DirHandle{d};
    o.status = OpenStatus::opened;
    return o;
}

/// The injected root itself (O_NOFOLLOW checks its final component only).
inline Opened open_root(const std::string& root) {
    return finish_dir_open(::open(root.c_str(), kDirFlags), AT_FDCWD, root.c_str());
}

/// One path component via openat from an already-open parent.
inline Opened open_child(DIR* parent, const std::string& name) {
    const int pfd = ::dirfd(parent);
    return finish_dir_open(::openat(pfd, name.c_str(), kDirFlags), pfd, name.c_str());
}

/// Records a failed open in `acc`; absent is silent, and so is an alias unless
/// `refuse_alias` (a fixed subdirectory that nothing else covers). Returns the
/// handle (invalid unless the open succeeded).
inline DirHandle take_or_record(Opened&& o, ConstraintAccumulator& acc, bool refuse_alias = false) {
    if (o.status == OpenStatus::failed) acc.add_failure(o.token);
    else if (o.status == OpenStatus::alias && refuse_alias) acc.add_failure(kTokSymlinkRefused);
    return o.status == OpenStatus::opened ? std::move(o.dir) : DirHandle{};
}

/// Where a hop-by-hop path walk stopped.
struct PathWalk {
    DirHandle dir;                                 // the final directory iff status == opened
    OpenStatus status = OpenStatus::absent;
    std::string_view token{};                      // set iff status == failed
    DirHandle parent;                              // open holder of `comp` (alias / failure past the root)
    std::string parent_rel, comp, remaining;       // root-relative holder path, stopping component, the rest
};

/// Opens <root>/<rel> hop-by-hop ("usr/share/dotnet" -> usr, share, dotnet),
/// each hop O_NOFOLLOW from the previous fd, and reports where it stopped.
inline PathWalk walk_path(const std::string& root, std::string_view rel) {
    PathWalk w;
    Opened cur = open_root(root);
    if (cur.status != OpenStatus::opened) {
        w.status = cur.status; // the injected root itself: comp stays empty
        w.token = cur.token;
        return w;
    }
    std::string walked;
    std::size_t pos = 0;
    while (pos < rel.size()) {
        auto sl = rel.find('/', pos);
        if (sl == std::string_view::npos) sl = rel.size();
        const std::string comp{rel.substr(pos, sl - pos)};
        pos = sl + 1;
        if (comp.empty()) continue;
        Opened next = open_child(cur.dir.get(), comp);
        if (next.status != OpenStatus::opened) {
            w.status = next.status;
            w.token = next.token;
            w.parent = std::move(cur.dir);
            w.parent_rel = walked;
            w.comp = comp;
            if (pos < rel.size()) w.remaining = std::string{rel.substr(pos)};
            return w;
        }
        walked = walked.empty() ? comp : walked + "/" + comp;
        cur = std::move(next);
    }
    w.status = OpenStatus::opened;
    w.dir = std::move(cur.dir);
    return w;
}

/// True iff the symlink `w` stopped at is a benign alias: its link text
/// lexically names ANOTHER candidate in `candidates` and that candidate is not
/// itself a symlink, so whatever is (or is not) there is reached, and any
/// failure reported, through that candidate's own walk. Anything else
/// (unreadable or truncated link, a target outside the candidate set, a cycle
/// or a chain of aliases) is not covered. MUTATION: requiring the target to
/// OPEN (`== OpenStatus::opened`) turns a dangling in-set alias -- Arch's
/// /usr/lib64 -> lib with no .NET installed -- into a false `constrained`; the
/// dangling-alias case in test_runtimes_linux_parsers.cpp pins this.
inline bool alias_is_covered(const std::string& root, const PathWalk& w, std::string_view rel,
                             std::span<const std::string_view> candidates,
                             const WalkConfig& cfg) {
    if (!w.parent || w.comp.empty()) return false; // a symlinked injected root is never an alias
    char buf[4096];
    const ssize_t n = ::readlinkat(::dirfd(w.parent.get()), w.comp.c_str(), buf, sizeof buf);
    if (n <= 0 || static_cast<std::size_t>(n) == sizeof buf) return false;
    const auto target = alias_target_rel(w.parent_rel, std::string_view{buf, static_cast<std::size_t>(n)},
                                         w.remaining);
    if (!target || *target == rel) return false;
    if (std::find(candidates.begin(), candidates.end(), std::string_view{*target}) == candidates.end())
        return false;
    // The target is a candidate whose own walk records `network_fs_skipped`; do not touch it here.
    if (touches_network_mount("/" + *target, cfg.network_mounts)) return true;
    return walk_path(root, *target).status != OpenStatus::alias;
}

/// Opens candidate root <root>/<rel> (a member of `candidates`). Absent and a
/// covered alias are silent; a candidate on, under or containing a network mount
/// is skipped before any syscall touches it (`network_fs_skipped`); every other
/// refusal is recorded in `acc`.
inline DirHandle open_path(const std::string& root, std::string_view rel,
                           std::span<const std::string_view> candidates, const WalkConfig& cfg,
                           ConstraintAccumulator& acc) {
    if (touches_network_mount("/" + std::string{rel}, cfg.network_mounts)) {
        acc.add_failure(kTokNetworkFsSkipped);
        return DirHandle{};
    }
    PathWalk w = walk_path(root, rel);
    switch (w.status) {
    case OpenStatus::opened: return std::move(w.dir);
    case OpenStatus::absent: break;
    case OpenStatus::failed: acc.add_failure(w.token); break;
    case OpenStatus::alias:
        if (!alias_is_covered(root, w, rel, candidates, cfg)) acc.add_failure(kTokSymlinkRefused);
        break;
    }
    return DirHandle{};
}

/// Running account of ONE action's walk against its WalkLimits: rows and row bytes admitted, and
/// directory entries visited, across every root and nesting level. `exhausted` is sticky and tells
/// every loop to stop.
struct WalkBudget {
    explicit WalkBudget(const WalkLimits& l) noexcept
        : limits(l), rows_left(l.rows), bytes_left(l.row_bytes), entries_left(l.entries_visited) {}
    WalkLimits limits;
    std::size_t rows_left;
    std::size_t bytes_left;
    std::size_t entries_left;
    bool exhausted = false;
};

/// Appends `row` unless the row or byte budget is spent (then `row_cap`, and the walk stops).
inline bool push_row(std::vector<std::string>& rows, std::string&& row, WalkBudget& b,
                     ConstraintAccumulator& acc) {
    if (b.rows_left == 0 || row.size() > b.bytes_left) {
        b.exhausted = true;
        acc.add_failure(kTokRowCap);
        return false;
    }
    --b.rows_left;
    b.bytes_left -= row.size();
    rows.push_back(std::move(row));
    return true;
}

enum class EntryType { directory, symlink, other };

struct EntryInfo {
    std::string name;
    EntryType type = EntryType::other;
};

/// The real entries of an open directory, sorted by name (readdir order is
/// unspecified, and rows must be deterministic), reading at most the smaller of
/// the per-directory cap and what is left of the action's entries-visited
/// budget; every entry read is charged to that budget. A vanished entry
/// (ENOENT) is skipped; any other stat failure, a hit cap (`row_cap`) and a
/// readdir I/O error are recorded, and a cap that was the aggregate budget
/// exhausts the walk.
inline std::vector<EntryInfo> list_entries(DIR* d, ConstraintAccumulator& acc, WalkBudget& budget) {
    std::vector<EntryInfo> out;
    if (budget.exhausted) return out;
    const std::size_t cap = std::min(budget.limits.dir_entries, budget.entries_left);
    std::size_t seen = 0;
    const int fd = ::dirfd(d);
    const auto res = yuzu::shared::walk_dir_capped(d, cap, [&](const struct dirent* e) {
        ++seen;
        struct stat st{};
        if (::fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (const auto tok = stat_errno_token(errno)) acc.add_failure(*tok);
            return true;
        }
        EntryInfo info;
        info.name = std::string{e->d_name};
        info.type = S_ISDIR(st.st_mode)   ? EntryType::directory
                    : S_ISLNK(st.st_mode) ? EntryType::symlink
                                          : EntryType::other;
        out.push_back(std::move(info));
        return true;
    });
    budget.entries_left -= seen; // seen <= cap <= entries_left
    if (res.truncated) {
        acc.add_failure(kTokRowCap);
        if (budget.entries_left == 0) budget.exhausted = true;
    }
    if (res.enumeration_error) acc.add_failure(kTokReadFailed);
    std::sort(out.begin(), out.end(),
              [](const EntryInfo& a, const EntryInfo& b) { return a.name < b.name; });
    return out;
}

enum class ReadStatus { ok, absent, failed };

struct ReadResult {
    ReadStatus status = ReadStatus::absent;
    std::string text;
    std::string_view token{}; // set iff status == failed
};

/// Reads the regular file `name` under the open directory `dirfd`, refusing a
/// symlink (O_NOFOLLOW), a non-regular file, and anything over `max_bytes`.
/// O_NONBLOCK so a FIFO planted as `release` can never hang the agent (it is
/// then refused by the S_ISREG check).
inline ReadResult read_file_bounded_at(int dirfd, const char* name, std::size_t max_bytes) {
    ReadResult r;
    const int fd = ::openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        const auto tok = file_open_errno_token(errno);
        if (!tok) return r; // absent
        r.status = ReadStatus::failed;
        r.token = *tok;
        return r;
    }
    const yuzu::agent::ScopedFd guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        r.status = ReadStatus::failed;
        r.token = kTokReadFailed;
        return r;
    }
    if (!S_ISREG(st.st_mode)) {
        r.status = ReadStatus::failed;
        r.token = kTokNotRegular;
        return r;
    }
    if (static_cast<unsigned long long>(st.st_size) > max_bytes) {
        r.status = ReadStatus::failed;
        r.token = kTokOversized;
        return r;
    }
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            r.status = ReadStatus::failed;
            r.token = kTokReadFailed;
            r.text.clear();
            return r;
        }
        if (n == 0) break;
        r.text.append(buf, static_cast<std::size_t>(n));
        if (r.text.size() > max_bytes) { // grew past the fstat size
            r.status = ReadStatus::failed;
            r.token = kTokOversized;
            r.text.clear();
            return r;
        }
    }
    r.status = ReadStatus::ok;
    return r;
}

/// True iff <home>/bin/java or <home>/jre/bin/java is a regular file or a symlink (never followed):
/// the footprint of a JVM home whose installer wrote no `release` file (some distro OpenJDK 8
/// packages; Rocky's has only jre/bin/java). Each hop is opened O_NOFOLLOW. A failed open of
/// `bin`/`jre` or a failed stat of `java` (other than ENOENT) is recorded, never read as "no
/// java"; a symlinked `bin`/`jre` is refused visibly (`symlink_refused`) when no binary was found
/// through the other route; a directory or other special file named `java` is not a JVM.
inline bool home_has_java_binary(DIR* home, ConstraintAccumulator& acc) {
    bool alias_seen = false;
    const auto open_hop = [&](DIR* dir, const char* name) {
        Opened o = open_child(dir, name);
        alias_seen = alias_seen || o.status == OpenStatus::alias;
        return take_or_record(std::move(o), acc);
    };
    const auto java_in = [&](DIR* dir) {
        const DirHandle bin = open_hop(dir, "bin");
        if (!bin) return false;
        struct stat st{};
        if (::fstatat(::dirfd(bin.get()), "java", &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (const auto tok = stat_errno_token(errno)) acc.add_failure(*tok);
            return false;
        }
        return S_ISREG(st.st_mode) || S_ISLNK(st.st_mode);
    };
    if (java_in(home)) return true;
    const DirHandle jre = open_hop(home, "jre");
    if (jre && java_in(jre.get())) return true;
    if (alias_seen) acc.add_failure(kTokSymlinkRefused);
    return false;
}

/// The mount table at `path` (production: /proc/self/mountinfo) reduced to its network mount
/// points, streamed line-wise (see kMountinfoChunk). `ok` is false when it cannot be read in full
/// (absent, refused, not a regular file, an I/O error, more than `max_total` bytes, or a line too
/// long to keep, which is skipped and the scan goes on): the caller then records
/// `mountinfo_unreadable`, and the walk runs guarded only by the mounts read.
struct MountScan {
    std::vector<std::string> network_mounts;
    bool ok = false;
};

inline MountScan scan_mounts(const char* path, std::size_t max_total = kMaxMountinfoBytes) {
    MountScan s;
    const int fd = ::open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return s;
    const yuzu::agent::ScopedFd guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return s;
    const auto take = [&s](std::string_view lines) {
        for (auto& m : network_mount_points(lines)) s.network_mounts.push_back(std::move(m));
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

} // namespace walk

// -- the three action walks ----------------------------------------------------------
//
// `cfg` carries the bounds and the network-mount guard (default: production bounds, no guard).

/// dotnet: <root>/{usr/share,usr/lib,usr/lib64}/dotnet -> shared/<fw>/<ver> and
/// sdk/<ver>. Row order: candidate-root order, then framework name, then
/// version (sorted).
[[nodiscard]] inline std::vector<std::string> dotnet_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const WalkConfig& cfg = {}) {
    using namespace walk;
    std::vector<std::string> rows;
    WalkBudget budget{cfg.limits};
    const std::string root_s = root.string();
    for (const std::string_view rel : kDotnetRoots) {
        if (budget.exhausted) break;
        const DirHandle dotnet = open_path(root_s, rel, kDotnetRoots, cfg, acc);
        if (!dotnet) continue;
        const std::string logical = "/" + std::string{rel};

        if (const DirHandle shared =
                take_or_record(open_child(dotnet.get(), "shared"), acc, /*refuse_alias=*/true)) {
            for (const auto& fw : list_entries(shared.get(), acc, budget)) {
                if (budget.exhausted) break;
                if (fw.type != EntryType::directory) continue;
                const DirHandle fwh = take_or_record(open_child(shared.get(), fw.name), acc);
                if (!fwh) continue;
                for (const auto& ver : list_entries(fwh.get(), acc, budget)) {
                    if (ver.type != EntryType::directory) continue;
                    auto row = dotnet_row(fw.name, ver.name,
                                          join_logical(join_logical(logical + "/shared", fw.name),
                                                       ver.name));
                    if (row && !push_row(rows, std::move(*row), budget, acc)) break;
                }
            }
        }
        if (budget.exhausted) break;
        if (const DirHandle sdk =
                take_or_record(open_child(dotnet.get(), "sdk"), acc, /*refuse_alias=*/true)) {
            for (const auto& ver : list_entries(sdk.get(), acc, budget)) {
                if (ver.type != EntryType::directory) continue;
                auto row = dotnet_row("sdk", ver.name, join_logical(logical + "/sdk", ver.name));
                if (row && !push_row(rows, std::move(*row), budget, acc)) break;
            }
        }
    }
    return rows;
}

/// jvm: <root>/{usr/lib/jvm,opt/java,usr/lib64/jvm,var/opt/java}/<d>/release. A directory with
/// neither a `release` file nor a bin/java or jre/bin/java is not a JVM home (silent); one with a
/// java binary but no `release` (e.g. Ubuntu OpenJDK 8) is a row with an unknown version plus
/// `release_missing`; an unreadable / oversized / version-less `release` is a recorded constraint.
/// Symlinked homes are aliases.
[[nodiscard]] inline std::vector<std::string> jvm_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const WalkConfig& cfg = {}) {
    using namespace walk;
    std::vector<std::string> rows;
    WalkBudget budget{cfg.limits};
    const std::string root_s = root.string();
    for (const std::string_view rel : kJvmRoots) {
        if (budget.exhausted) break;
        const DirHandle jvm_dir = open_path(root_s, rel, kJvmRoots, cfg, acc);
        if (!jvm_dir) continue;
        const std::string logical = "/" + std::string{rel};
        for (const auto& home : list_entries(jvm_dir.get(), acc, budget)) {
            if (home.type != EntryType::directory) continue;
            const DirHandle hh = take_or_record(open_child(jvm_dir.get(), home.name), acc);
            if (!hh) continue;
            const std::string path = join_logical(logical, home.name);
            const auto rr = read_file_bounded_at(::dirfd(hh.get()), "release", kMaxReleaseBytes);
            if (rr.status == ReadStatus::absent) {
                if (!home_has_java_binary(hh.get(), acc)) continue;
                acc.add_failure(kTokReleaseMissing);
                if (!push_row(rows, jvm_row_release_missing(path), budget, acc)) break;
                continue;
            }
            if (rr.status == ReadStatus::failed) {
                acc.add_failure(rr.token);
                continue;
            }
            const auto fields = parse_release_file(rr.text);
            if (fields.oversized) acc.add_failure(kTokFieldOversized);
            auto row = jvm_row(fields, path);
            if (!row) {
                acc.add_failure(kTokReleaseUnparsable);
                continue;
            }
            if (!push_row(rows, std::move(*row), budget, acc)) break;
        }
    }
    return rows;
}

/// The Linux leg's dispatch: the rows for action `a` under `root`, failures
/// recorded in `acc`. run_linux_at is this plus emit_read; both live here so the
/// action -> walk -> emit wiring is unit-testable without linking the plugin TU.
/// An action with no arm here (a future one) is a visible failure, never `supported` + 0 rows.
[[nodiscard]] inline std::vector<std::string> action_rows_at(
    Action a, const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    const WalkConfig& cfg = {}) {
    switch (a) {
    case Action::dotnet: return dotnet_rows_at(root, acc, cfg);
    case Action::jvm:    return jvm_rows_at(root, acc, cfg);
    }
    acc.add_failure("internal_error");
    return {};
}

/// Production's WalkConfig: the default bounds plus the network mount points read from
/// /proc/self/mountinfo (`mountinfo_unreadable` when it cannot be read in full). The path is a
/// parameter so the unit suite can point it at a fixture.
[[nodiscard]] inline WalkConfig production_config(
    const char* mountinfo_path = "/proc/self/mountinfo") {
    auto scan = walk::scan_mounts(mountinfo_path);
    WalkConfig cfg;
    cfg.network_mounts = std::move(scan.network_mounts);
    cfg.mountinfo_unreadable = !scan.ok;
    return cfg;
}

/// The Linux leg body with the filesystem root injected: `action_rows_at` plus
/// `emit_read` (status row first, then every data row, then the typed result
/// status). runtimes_linux.cpp's `run_linux` calls it with "/" and
/// production_config(); the unit suite drives it over a materialized fixture tree through
/// a real CommandContext (LocalDispatcher), so what is asserted is the rows AND the status the
/// command actually reports. Returns 0 unconditionally: a degraded read is not a failed
/// command; the degradation rides the status row and set_result_status.
inline int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root,
                        const WalkConfig& cfg) {
    yuzu::shared::ConstraintAccumulator acc;
    if (cfg.mountinfo_unreadable) acc.add_failure(kTokMountinfoUnreadable);
    const auto rows = action_rows_at(a, root, acc, cfg);
    emit_read(ctx, a, rows, acc);
    return 0;
}

#endif // !defined(_WIN32)

} // namespace yuzu::runtimes::lnx
