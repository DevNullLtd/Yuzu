/**
 * component_fs_posix.cpp -- the Linux and macOS leg of the component_inventory filesystem seam
 * (FsOps in component_walk.hpp) and the choice of what to walk (component_legs.hpp).
 *
 * Read-only: no write, no subprocess, no network.
 *
 * NO LINK IS FOLLOWED AT ANY COMPONENT. The application trees walked here (/opt, /Applications,
 * /usr/local, ...) are writable by accounts other than the one the agent runs as, which may be root,
 * so a link planted anywhere on a path would make the agent read what the planter cannot. The shared
 * path forms guard the leaf only and follow intermediates (posix_secure_read.hpp), so the one
 * path-string open in this file is open_dir_no_follow("/"). Every other directory is reached one
 * component at a time with open_dir_no_follow_at from the descriptor of its parent, and a file is
 * opened under its parent's descriptor with open_file_no_follow_at. The chain is re-acquired for
 * every list and every open, so a directory swapped for a link after it was listed is refused
 * (ENOTDIR) when it is listed itself, and nothing under the link's target is returned. A root that is
 * a link, or that is reached through one, is dropped and counted (roots_link_skipped).
 *
 * NETWORK MOUNTS. The mount table is read once per scan (Linux /proc/<pid>/mountinfo, reached hop by
 * hop because /proc/self is itself a link; macOS getmntinfo_r_np). A root on or under a network mount
 * is dropped and counted. A mount point below a kept root is typed network_mount from its path alone:
 * it is never passed to stat or open, because a stat of a dead or automounted mount point can block
 * or trigger the mount, and the acquisition of any path refuses to open a hop that is one. An
 * unreadable table yields no roots (the walk would have no guard) and is reported, never read as an
 * empty host.
 *
 * RESIDUALS, stated plainly:
 *  - open, readdir and pread carry no deadline of their own (posix_secure_read.hpp, "Blocking"). The
 *    45 s wall budget in WalkLimits is checked between directories and between archives; it is NOT a
 *    hard bound on one call, and a call that blocks stays blocked.
 *  - The network-mount guard is a snapshot of a deny-list. It does not see a mount that appears after
 *    the table was read, a stacked filesystem (an overlay, ecryptfs or loop device) over a dead
 *    network mount, or a network filesystem type the deny-list does not name (network_fstype.hpp).
 *  - A hang on a local device (a failing disk, a stuck USB or FUSE daemon not on the deny-list) is not
 *    closed here.
 *  - Each acquisition is a series of independent openat calls, so a directory renamed mid-walk can be
 *    reached under a stale name; what is returned is always a real directory or file opened with no
 *    link followed, never the target of a link.
 *
 * No Windows code: that leg is a later change and the shell answers `planned` there.
 */
#include "component_legs.hpp"

#if !defined(_WIN32)

#include <macos_network_mounts.hpp> // self-gated to __APPLE__
#include <network_fstype.hpp>
#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace yuzu::component_inventory {

namespace {

constexpr std::size_t kMaxReadAt = 16u * 1024 * 1024; // per read_at call; more is refused, never cut
constexpr std::size_t kMountChunk = 64 * 1024;
constexpr std::size_t kMaxMountLine = 1024 * 1024; // a real line is a few KiB; an overlay ~100 KiB

[[nodiscard]] bool within(const std::string& path, const std::string& base) {
    if (base == "/")
        return true;
    return path == base ||
           (path.size() > base.size() && path.compare(0, base.size(), base) == 0 && path[base.size()] == '/');
}

[[nodiscard]] std::string strip_trailing_slash(std::string p) {
    while (p.size() > 1 && p.back() == '/')
        p.pop_back();
    return p;
}

struct Acquired {
    shared::DirOpen dir;
    bool link{false}; // the hop that failed is a symlink
};

void note(const AccessLog& log, const std::string& path) {
    if (log)
        log(path);
}

[[nodiscard]] std::optional<std::string> pread_range(int fd, std::uint64_t offset, std::size_t len) {
    constexpr auto kMaxOffset = static_cast<std::uint64_t>(std::numeric_limits<off_t>::max());
    // A short answer means end of file to the caller, so an oversized request is refused, not cut.
    if (len > kMaxReadAt || offset > kMaxOffset || len > kMaxOffset - offset)
        return std::nullopt;
    std::string out(len, '\0');
    std::size_t got = 0;
    while (got < len) {
        const ssize_t n = ::pread(fd, out.data() + got, len - got, static_cast<off_t>(offset + got));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return std::nullopt;
        }
        if (n == 0)
            break;
        got += static_cast<std::size_t>(n);
    }
    out.resize(got);
    return out;
}

class PosixFs {
public:
    explicit PosixFs(const std::vector<std::string>& network_mounts = {}, AccessLog log = {})
        : mounts_(network_mounts.begin(), network_mounts.end()), log_(std::move(log)) {}

    // Opens `path` (absolute) one component at a time from "/". Never a path-string open below "/".
    [[nodiscard]] Acquired acquire(const std::string& path) const {
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
            return fail(EINVAL);
        note(log_, "/");
        shared::DirOpen cur = shared::open_dir_no_follow("/");
        std::string prefix;
        std::size_t pos = 1;
        while (cur.opened() && pos < path.size()) {
            std::size_t end = path.find('/', pos);
            if (end == std::string::npos)
                end = path.size();
            const std::string comp = path.substr(pos, end - pos);
            pos = end + 1;
            if (comp.empty())
                continue;
            prefix += '/';
            prefix += comp;
            if (mounts_.contains(prefix))
                return fail(EPERM);
            note(log_, prefix);
            shared::DirOpen next = shared::open_dir_no_follow_at(cur.dir.fd(), comp.c_str());
            if (!next.opened()) {
                const bool link = (next.err == ENOTDIR || next.err == ELOOP) && is_link(cur.dir.fd(), comp, prefix);
                return {std::move(next), link};
            }
            cur = std::move(next);
        }
        return {std::move(cur), false};
    }

    [[nodiscard]] ListResult list(const std::string& dir, std::size_t cap) const {
        ListResult out;
        Acquired a = acquire(dir);
        if (!a.dir.opened()) {
            out.error = true;
            return out;
        }
        const int fd = a.dir.dir.fd();
        bool untyped = false;
        const auto walked = shared::walk_dir_capped(a.dir.dir.get(), cap, [&](const struct dirent* e) {
            out.entries.push_back(DirEntry{e->d_name, classify_dirent(fd, dir, *e, mounts_, log_, untyped)});
            return true;
        });
        out.truncated = walked.truncated;
        if (walked.enumeration_error || untyped) {
            out.error = true;
            out.entries.clear();
        }
        return out;
    }

    [[nodiscard]] std::optional<FileView> open_file(const std::string& path) const {
        const std::size_t slash = path.rfind('/');
        if (slash == std::string::npos || slash + 1 == path.size() || path.find('\0') != std::string::npos ||
            mounts_.contains(path))
            return std::nullopt;
        const std::string leaf = path.substr(slash + 1);
        Acquired parent = acquire(slash == 0 ? std::string{"/"} : path.substr(0, slash));
        if (!parent.dir.opened())
            return std::nullopt;
        note(log_, path);
        shared::FileOpen f = shared::open_file_no_follow_at(parent.dir.dir.fd(), leaf.c_str());
        if (!f.opened())
            return std::nullopt;

        const auto held = std::make_shared<shared::FileOpen>(std::move(f));

        FileView v;
        v.size = held->size;
        v.mtime = static_cast<std::int64_t>(held->mtime.tv_sec);
        v.read_at = [held](std::uint64_t offset, std::size_t len) { return pread_range(held->file.fd(), offset, len); };
        v.unchanged = [held] {
            struct stat st {};
            if (::fstat(held->file.fd(), &st) != 0)
                return false;
            const struct timespec mt = shared::mtime_of(st);
            return static_cast<std::uint64_t>(st.st_size) == held->size && mt.tv_sec == held->mtime.tv_sec &&
                   mt.tv_nsec == held->mtime.tv_nsec;
        };
        return v;
    }

private:
    [[nodiscard]] static Acquired fail(int err) {
        Acquired a;
        a.dir.err = err;
        return a;
    }

    [[nodiscard]] bool is_link(int parent_fd, const std::string& name, const std::string& full) const {
        note(log_, full);
        struct stat st {};
        return ::fstatat(parent_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode);
    }

    std::unordered_set<std::string> mounts_;
    AccessLog log_;
};

#if defined(__APPLE__)

[[nodiscard]] std::optional<std::vector<std::string>> read_network_mounts() {
    return shared::read_macos_network_mounts();
}

#else

// /proc/<pid>/mountinfo, reached hop by hop (/proc/self is itself a link) and streamed.
[[nodiscard]] std::optional<std::vector<std::string>> read_network_mounts() {
    const Acquired proc = PosixFs{}.acquire("/proc/" + std::to_string(::getpid()));
    if (!proc.dir.opened())
        return std::nullopt;
    const shared::FileOpen f = shared::open_file_no_follow_at(proc.dir.dir.fd(), "mountinfo");
    if (!f.opened())
        return std::nullopt;
    return read_mountinfo_stream([fd = f.file.fd()](char* buf, std::size_t len) { return ::read(fd, buf, len); });
}

#endif

} // namespace

// A container host's table runs to tens of megabytes, so it is streamed line-wise rather than held
// whole. A line longer than kMaxMountLine is a failure, not skipped: skipping would hide a mount from
// the guard. Every completed line is length-checked, not just the unfinished tail.
std::optional<std::vector<std::string>> read_mountinfo_stream(const ReadChunk& read_chunk, std::size_t max_total) {
    std::vector<std::string> out;
    const auto take = [&out](std::string_view lines) {
        for (auto& m : shared::network_mount_points(lines))
            out.push_back(std::move(m));
    };
    std::string chunk(kMountChunk, '\0');
    std::string pending; // the unfinished last line of what has been read so far
    std::size_t total = 0;
    for (;;) {
        const ssize_t n = read_chunk(chunk.data(), chunk.size());
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return std::nullopt; // never the part read so far
        }
        if (n == 0)
            break;
        total += static_cast<std::size_t>(n);
        if (total > max_total)
            return std::nullopt;
        pending.append(chunk, 0, static_cast<std::size_t>(n));
        std::size_t start = 0;
        for (std::size_t nl; (nl = pending.find('\n', start)) != std::string::npos; start = nl + 1)
            if (nl - start > kMaxMountLine)
                return std::nullopt;
        if (start > 0) {
            take(std::string_view{pending}.substr(0, start));
            pending.erase(0, start);
        }
        if (pending.size() > kMaxMountLine)
            return std::nullopt;
    }
    take(pending);
    return out;
}

DirEntry::Type classify_dirent(int dir_fd, const std::string& dir, const struct dirent& e,
                               const std::unordered_set<std::string>& network_mounts, const AccessLog& on_access,
                               bool& untyped) {
    using Type = DirEntry::Type;
    const std::string full = walk_detail::join(dir, e.d_name);
    if (network_mounts.contains(full))
        return Type::network_mount; // decided from the path alone: never stat'ed
    switch (e.d_type) {
    case DT_DIR: return Type::dir;
    case DT_REG: return Type::file;
    case DT_LNK: return Type::link;
    case DT_UNKNOWN: break;
    default: return Type::other;
    }
    note(on_access, full);
    struct stat st {};
    if (::fstatat(dir_fd, e.d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != ENOENT)
            untyped = true;
        return Type::other;
    }
    if (S_ISDIR(st.st_mode))
        return Type::dir;
    if (S_ISREG(st.st_mode))
        return Type::file;
    return S_ISLNK(st.st_mode) ? Type::link : Type::other;
}

std::vector<std::string> candidate_roots() {
#if defined(__APPLE__)
    return {"/Applications", "/Library/Java", "/usr/local", "/opt/homebrew"};
#else
    return {"/opt", "/usr/share/java", "/usr/lib/jvm", "/usr/local/lib", "/usr/local/share", "/usr/share/maven"};
#endif
}

Targets plan_targets(const std::vector<std::string>& candidates, const std::vector<std::string>& network_mount_points,
                     bool table_ok) {
    Targets t;
    if (!table_ok) {
        t.mount_table_unreadable = true;
        return t;
    }
    std::vector<std::string> mounts;
    for (const auto& m : network_mount_points)
        if (!m.empty())
            mounts.push_back(strip_trailing_slash(m));

    for (const auto& root : candidates) {
        if (std::ranges::any_of(mounts, [&](const std::string& m) { return within(root, m); })) {
            ++t.roots_network_skipped;
            continue;
        }
        t.roots.push_back(root);
        for (const auto& m : mounts)
            if (within(m, root) && std::ranges::find(t.network_mounts, m) == t.network_mounts.end())
                t.network_mounts.push_back(m);
    }
    return t;
}

void drop_unreachable_roots(Targets& t, AccessLog on_access) {
    const PosixFs fs{t.network_mounts, std::move(on_access)};
    std::erase_if(t.roots, [&](const std::string& root) {
        const Acquired a = fs.acquire(root);
        if (a.dir.opened())
            return false;
        if (a.link) {
            ++t.roots_link_skipped;
            return true;
        }
        return a.dir.err == ENOENT || a.dir.err == ENOTDIR; // nothing to walk; any other failure stays to be reported
    });
}

Targets scan_targets(const std::vector<std::string>& candidates, const MountTableReader& read_mounts,
                     AccessLog on_access) {
    const auto mounts = read_mounts();
    Targets t = plan_targets(candidates, mounts.value_or(std::vector<std::string>{}), mounts.has_value());
    drop_unreachable_roots(t, std::move(on_access));
    return t;
}

Targets scan_targets() {
    return scan_targets(candidate_roots(), read_network_mounts);
}

FsOps make_fs_ops(const Targets& targets, AccessLog on_access) {
    const auto fs = std::make_shared<const PosixFs>(targets.network_mounts, std::move(on_access));
    FsOps ops;
    ops.list = [fs](const std::string& dir, std::size_t cap) { return fs->list(dir, cap); };
    ops.open_file = [fs](const std::string& path) { return fs->open_file(path); };
    ops.now = [] { return std::chrono::steady_clock::now(); };
    return ops;
}

} // namespace yuzu::component_inventory

#endif // !_WIN32
