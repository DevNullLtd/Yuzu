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
 * Residuals are stated in component_fs_posix.cpp's banner.
 */
#pragma once

#if !defined(_WIN32)

#include "component_walk.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <dirent.h>
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
/// installed_software_v3.cpp (kMachineRoots). Linux: /opt, /usr/share/java, /usr/lib/jvm,
/// /usr/local/lib, /usr/local/share, /usr/share/maven. macOS: /Applications, /Library/Java,
/// /usr/local, /opt/homebrew.
[[nodiscard]] std::vector<std::string> candidate_roots();

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

/// Test seam: one read(2) of the mount table. Bytes read, 0 at end of table, or -1 with errno set.
using ReadChunk = std::function<ssize_t(char* buf, std::size_t len)>;

/// Streams a /proc/<pid>/mountinfo-format table through `read_chunk` and returns the mount points of
/// the network filesystems in it. nullopt when the table cannot be had in full: a read fails (EINTR is
/// retried), the table runs past 256 MiB, or one line is longer than 1 MiB. A failure after some of the
/// table was parsed is nullopt too, never the part read so far: a mount the guard did not see is not
/// "no mount". Platform-independent (it is also what the tests drive); only Linux feeds it a file.
[[nodiscard]] std::optional<std::vector<std::string>> read_mountinfo_stream(const ReadChunk& read_chunk);

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

/// Types one entry of the directory `dir` (open as `dir_fd`). A path in `network_mounts` is
/// network_mount decided from the path alone, whatever d_type says: it is never passed to stat. DT_UNKNOWN
/// is otherwise resolved with fstatat(AT_SYMLINK_NOFOLLOW); `untyped` is set when that fails for a reason
/// other than the entry having vanished (the caller then treats the listing as an error). Exposed so the
/// DT_UNKNOWN branch is tested: the filesystems a test can build always report d_type.
[[nodiscard]] DirEntry::Type classify_dirent(int dir_fd, const std::string& dir, const struct dirent& e,
                                             const std::unordered_set<std::string>& network_mounts,
                                             const AccessLog& on_access, bool& untyped);

/// The link-free filesystem for `targets`: every path is acquired hop by hop from "/" and no link is
/// followed at any component; an entry named in targets.network_mounts is typed network_mount
/// without being stat'ed or opened.
[[nodiscard]] FsOps make_fs_ops(const Targets& targets, AccessLog on_access = {});

} // namespace yuzu::component_inventory

#endif // !_WIN32
