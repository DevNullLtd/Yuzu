/**
 * component_legs.hpp -- what the POSIX leg of the component_inventory plugin walks, and the
 * filesystem it walks it through (component_fs_posix.cpp).
 *
 * POSIX only: the whole body is compiled out on Windows, where the shell answers `planned`.
 *
 * The flow the shell runs is  scan_targets()  ->  make_fs_ops(targets)  ->  walk(targets.roots, ...).
 * plan_targets() is the pure part of scan_targets() (no I/O), so the mount-table decisions are unit
 * tested over plain strings; drop_unreachable_roots() is the I/O part, exposed so the link decisions
 * are tested over a temporary tree without the live mount table.
 *
 * A root is dropped, never walked, when it sits on or under a network mount (counted in
 * roots_network_skipped), when it is missing (not counted: a host without a JVM directory is not a
 * gap) and when it is reached through a link at ANY component (counted in roots_link_skipped). An
 * unreadable mount table yields no roots at all and says so (mount_table_unreadable): a walk with no
 * mount guard could block on a dead server, so the leg walks nothing and the shell reports the
 * inventory as incomplete.
 *
 * The on-demand file search drives the same filesystem through make_search_leg() (below): one leg per
 * searched mount, with an opt-in descriptor stack, a prune set of mount points it never lists, and the
 * per-match and per-root facts the search driver asks for.
 *
 * Residuals are stated in component_fs_posix.cpp's banner.
 */
#pragma once

#if !defined(_WIN32)

#include "component_walk.hpp"

#include <network_fstype.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace yuzu::component_inventory {

struct Targets {
    std::vector<std::string> roots;          // absolute, no trailing '/', safe to hand to walk()
    std::vector<std::string> network_mounts; // mount points strictly below a kept root
    std::size_t roots_link_skipped{0};       // roots dropped for a link at any component
    std::size_t roots_network_skipped{0};    // roots dropped for sitting on or under a network mount
    bool mount_table_unreadable{false};      // the table could not be read: roots is empty
};

/// The machine roots worth walking on this OS, all inside the machine allowlist of
/// installed_software_v3.cpp (kMachineRoots), in walk order: cheap roots first, because the walk has
/// one entry budget that a large /opt or /Applications can spend. Linux: /usr/lib/jvm,
/// /usr/share/java, /usr/share/maven, /usr/local/lib, /usr/local/share, /opt. macOS: /Library/Java,
/// /usr/local, /opt/homebrew, /Applications.
[[nodiscard]] std::vector<std::string> candidate_roots();

/// The machine roots the `native` action walks, in walk order. Linux: /opt, /usr/local/lib (never
/// /usr/lib and the other trees the package manager owns: those are not roots at all). macOS:
/// /Applications, /usr/local, /opt/homebrew.
[[nodiscard]] std::vector<std::string> native_candidate_roots();

/// Directories the `native` walk must not list, by exact path: the macOS Homebrew package trees
/// (/usr/local/Cellar, /opt/homebrew/Cellar), which held most of a measured host's native libraries
/// and are the package manager's, not an application's. Empty on Linux, where the package-owned trees
/// are excluded by not being roots. Each one the walk meets is counted (WalkStats::dirs_excluded) and
/// reported, never skipped silently.
[[nodiscard]] std::vector<std::string> native_excluded_dirs();

/// Pure. Keeps the `candidates` that are not on or under one of `network_mount_points` (a segment
/// match: /opt/java2 is not under /opt/java), counting the rest; every mount strictly below a kept
/// root goes into network_mounts. `table_ok` false: no roots, mount_table_unreadable set.
[[nodiscard]] Targets plan_targets(const std::vector<std::string>& candidates,
                                   const std::vector<std::string>& network_mount_points, bool table_ok);

/// Test seam: called with the full path of every directory the leg opens and every entry it stats,
/// before the call is issued. A path under a network mount is never reported because it is never
/// issued.
using AccessLog = std::function<void(const std::string& path)>;

/// Drops from `t.roots` every root that is missing (silently) or reached through a link at any
/// component (counted in roots_link_skipped). A root that fails to open for any other reason stays,
/// so the walk lists it, fails, and reports dir_unreadable instead of the root vanishing.
void drop_unreachable_roots(Targets& t, AccessLog on_access = {});

/// A real mountinfo table runs to tens of megabytes on a container host; past this it is refused.
inline constexpr std::size_t kMaxMountTable = 256u * 1024 * 1024;

/// Test seam: one read(2) of the mount table. Bytes read, 0 at end of table, or -1 with errno set.
using ReadChunk = std::function<ssize_t(char* buf, std::size_t len)>;

/// Streams a /proc/<pid>/mountinfo-format table through `read_chunk` and returns the mount points of
/// the network filesystems in it. nullopt when the table cannot be had in full: a read fails (EINTR is
/// retried), the table runs past `max_total` bytes (kMaxMountTable; a parameter so a test can use a
/// tiny one), or one line is longer than 1 MiB. A failure after some of the table was parsed is
/// nullopt too, never the part read so far: a mount the guard did not see is not "no mount".
/// Platform-independent (it is also what the tests drive); only Linux feeds it a file.
[[nodiscard]] std::optional<std::vector<std::string>> read_mountinfo_stream(const ReadChunk& read_chunk,
                                                                            std::size_t max_total = kMaxMountTable);

/// The most distinct mount points one mount-table read keeps (the entries `keep` accepts, the last entry of
/// a mount point replacing an earlier one: an overmount shadows what it covers). A table with more is a
/// failed read, never a truncated one.
inline constexpr std::size_t kMaxKeptMounts = 16'384;

/// Predicate over one parsed mount: true keeps it.
using MountKeep = std::function<bool(const shared::MountEntry&)>;

/// Streams a /proc/<pid>/mountinfo-format table through `read_chunk` and returns the entries `keep`
/// accepts (an empty `keep` accepts all), with the malformed-line count of the whole table. It shares
/// one chunk and line loop with read_mountinfo_stream and hands every batch of complete lines to
/// shared::mount_entries(), so the table is never held whole. nullopt in the same cases as
/// read_mountinfo_stream (a failed read, a table over `max_total`, a line over 1 MiB) and when more
/// than `max_kept` distinct mount points are kept: a mount the caller did not see is not "no mount".
[[nodiscard]] std::optional<shared::MountTable>
read_mount_entries_stream(const ReadChunk& read_chunk, const MountKeep& keep,
                          std::size_t max_total = kMaxMountTable, std::size_t max_kept = kMaxKeptMounts);

/// Test seam: where scan_targets gets the network mount points. nullopt: the table could not be read.
using MountTableReader = std::function<std::optional<std::vector<std::string>>()>;

/// scan_targets over an injected candidate list and mount-table source (the live ones are the overload
/// below): nothing outside `candidates` is opened, so a unit test points it at a temporary tree and
/// never at the host's real roots.
[[nodiscard]] Targets scan_targets(const std::vector<std::string>& candidates,
                                   const MountTableReader& read_mounts, AccessLog on_access = {});

/// Reads the live mount table (Linux /proc/<pid>/mountinfo through yuzu::shared::network_mount_points,
/// macOS yuzu::shared::read_macos_network_mounts), plans candidate_roots() against it and drops the
/// unreachable ones.
[[nodiscard]] Targets scan_targets();

/// scan_targets for the `native` action: native_candidate_roots() against the same live mount table,
/// with the same mount-table guard, link refusal and network-mount skip.
[[nodiscard]] Targets scan_native_targets();

/// Types one entry of the directory `dir` (open as `dir_fd`). A path in `network_mounts` is
/// network_mount decided from the path alone, whatever d_type says: it is never passed to stat. DT_UNKNOWN
/// is otherwise resolved with fstatat(AT_SYMLINK_NOFOLLOW); nullopt when that fails for a reason other
/// than the entry having vanished (the caller then treats the listing as an error). Exposed so the
/// DT_UNKNOWN branch is tested: the filesystems a test can build always report d_type.
[[nodiscard]] std::optional<DirEntry::Type> classify_dirent(int dir_fd, const std::string& dir,
                                                            const struct dirent& e,
                                                            const std::unordered_set<std::string>& network_mounts,
                                                            const AccessLog& on_access);

/// The link-free filesystem for `targets`: every path is acquired hop by hop from "/" and no link is
/// followed at any component; an entry named in targets.network_mounts is typed network_mount
/// without being stat'ed or opened.
[[nodiscard]] FsOps make_fs_ops(const Targets& targets, AccessLog on_access = {});

// ---- the on-demand file search leg ----

/// Runs `lookup` and returns when it is done. The leg wraps EXACTLY three kinds of work in it and puts
/// nothing else inside: the whole of one path acquisition (every directory open and the link probe of a
/// failed hop), the enumeration of one directory (readdir and the stat of an untyped entry) and the
/// open of a match's leaf. No visitor, matcher, clock or row code runs inside it, so what a caller
/// holds around a lookup (the Linux plugin raises one thread capability there) covers lookups only.
using AroundLookup = std::function<void(const std::function<void()>& lookup)>;

/// Called with the descriptor of a match's leaf and its fstat, while the leaf is open and after
/// around_lookup has ended. The leg never interprets what the caller records and reads no byte of the
/// file. No extent or capability code lives in this file.
using ExtentReader = std::function<void(int fd, const struct stat& st)>;

struct SearchHooks {
    AroundLookup around_lookup; // empty: lookups run bare
    ExtentReader read_extents;  // empty: no extents are read
};

/// Test seam for the enumeration: replaces readdir(3). Production never sets it.
using ReadDirFn = std::function<struct dirent*(DIR*)>;

struct SearchLeg {
    /// list() fills the listed directory's identity (device and inode; a zero device is an error) and
    /// every entry's inode, never lists a pruned mount point and never reports one. open_file is a
    /// function that always refuses: the search never opens a file through FsOps.
    FsOps ops;
    /// Opens the match `name` of directory `dir` under the cached descriptor of `dir` with no link
    /// followed and the open non-blocking, reads size and time from the descriptor, hands the descriptor
    /// to the extent reader and closes it. Never reads the file.
    std::function<MatchFacts(const std::string& dir, const std::string& name)> facts;
    /// What `path` is when reached from "/" with no link followed at any component.
    std::function<RootState(const std::string& path)> root_state;
};

/// `prune` is the mount points strictly BELOW the unit's walk root (never an ancestor: acquiring a root
/// beneath its own mount point must work). A pruned mount point is never stat'ed, opened or listed, and no
/// listing names it: the search plan reports each of them once.
///
/// The descriptor stack is on: sibling and child directories open only the components the previous one
/// did not already hold, at most file_search::kMaxPositionDepth + 1 descriptors in all. Not thread-safe:
/// one walk at a time per leg, which is how the search drives it.
[[nodiscard]] SearchLeg make_search_leg(std::vector<std::string> prune, AccessLog on_access = {},
                                        SearchHooks hooks = {}, ReadDirFn read_dir = {});

} // namespace yuzu::component_inventory

#endif // !_WIN32
