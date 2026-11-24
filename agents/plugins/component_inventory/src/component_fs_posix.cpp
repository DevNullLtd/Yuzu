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
 * THE SEARCH LEG (make_search_leg). The on-demand file search drives the same filesystem through a leg
 * built per searched mount. It differs from the scan's leg in four ways, none of which changes the scan:
 * (1) an opt-in descriptor stack keeps the directories of the current path open, so sibling and child
 * listings open only the hops they have not yet held (a cached directory is read again from its start,
 * and a hop that has gone is met only when something below it is opened: the stale-name residual above
 * already covers this); (2) the mount points it is given are never opened, stat'ed or listed and no
 * listing names them; (3) every lookup that may need a capability the caller holds (a whole path
 * acquisition, one directory's enumeration, one leaf open) runs inside one injected hook and nothing
 * else does; (4) it reports the facts the search needs: a listed directory's device and inode, a match's
 * size and time from the opened descriptor, and what a root path is.
 *
 * No Windows code: that leg is a later change and the shell answers `planned` there.
 */
#include "component_legs.hpp"

#if !defined(_WIN32)

#include <macos_network_mounts.hpp> // self-gated to __APPLE__
#include <network_fstype.hpp>
#include <posix_dir_walk.hpp>
#include <posix_secure_read.hpp>

#include <file_search_position.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <unordered_map>
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

// What acquire() answers: the directory reached, or why not. With the descriptor stack on, `held` is a
// stream the stack owns, valid only until the next acquire() on the same PosixFs; otherwise `dir` owns it.
struct Acquired {
    shared::DirOpen dir;
    DIR* held{nullptr};
    int err{0};       // errno of the open that failed
    bool link{false}; // the hop that failed is a symlink

    [[nodiscard]] DIR* get() const noexcept { return held != nullptr ? held : dir.dir.get(); }
    [[nodiscard]] int fd() const noexcept { return get() != nullptr ? ::dirfd(get()) : -1; }
    [[nodiscard]] bool opened() const noexcept { return get() != nullptr; }
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

// A hop that is a mount point the leg was told to avoid is refused with this: a value no open(2) of a
// directory yields, so it never reads as a permission refusal.
constexpr int kMountHopRefused = EXDEV;

// A device number as an unsigned 64-bit value. macOS's dev_t is a signed 32-bit integer: it is widened
// through its unsigned type, never sign-extended.
[[nodiscard]] std::uint64_t device_of(const struct stat& st) noexcept {
    return static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<decltype(st.st_dev)>>(st.st_dev));
}

[[nodiscard]] ListError list_cause_of(int err) noexcept {
    if (err == EACCES || err == EPERM)
        return ListError::permission_denied;
#if defined(__APPLE__)
    if (err == EDEADLK)
        return ListError::dataless;
#endif
    return ListError::unreadable;
}

struct PosixFsOptions {
    bool descriptor_stack{false}; // keep the directories of the current path open (the search leg)
    AroundLookup around;          // wraps a path acquisition, one enumeration, one leaf open
    ReadDirFn read_dir;           // test seam; empty = readdir(3)
};

class PosixFs {
public:
    explicit PosixFs(const std::vector<std::string>& network_mounts = {}, AccessLog log = {},
                     PosixFsOptions opts = {})
        : mounts_(network_mounts.begin(), network_mounts.end()), log_(std::move(log)),
          opts_(std::move(opts)) {
        if (!opts_.read_dir)
            opts_.read_dir = [](DIR* d) { return ::readdir(d); };
    }

    // Opens `path` (absolute) one component at a time from "/". Never a path-string open below "/".
    [[nodiscard]] Acquired acquire(const std::string& path) const {
        Acquired out;
        guarded([&] { out = opts_.descriptor_stack ? acquire_stacked(path) : acquire_plain(path); });
        return out;
    }

    [[nodiscard]] ListResult list(const std::string& dir, std::size_t cap) const {
        ListResult out;
        const Acquired a = acquire(dir);
        if (!a.opened()) {
            out.error = true;
            out.cause = list_cause_of(a.err);
            return out;
        }
        if (a.held != nullptr)
            ::rewinddir(a.held); // a cached stream was read before; this listing starts from the top
        struct stat st {};
        const std::uint64_t dev = ::fstat(a.fd(), &st) == 0 ? device_of(st) : 0;
        if (dev == 0) { // identity is part of the answer: a listing without a device is not one
            out.error = true;
            return out;
        }
        out.dev = dev;
        out.file_id = static_cast<std::uint64_t>(st.st_ino);

        const int fd = a.fd();
        bool untyped = false;
        shared::DirWalkResult walked;
        guarded([&] {
            walked = shared::walk_dir_capped(a.get(), cap, [&](const struct dirent* e) {
                if (const auto type = classify_dirent(fd, dir, *e, mounts_, log_)) {
                    DirEntry de{e->d_name, *type};
                    de.file_id = static_cast<std::uint64_t>(e->d_ino);
                    out.entries.push_back(std::move(de));
                } else {
                    untyped = true;
                }
                return true;
            }, opts_.read_dir);
        });
        out.truncated = walked.truncated;
        if (walked.enumeration_error || untyped) {
            out.error = true;
            out.entries.clear();
        }
        // Sorting makes the order the walk consumes a listing independent of readdir order, so the
        // scan-wide caps (entry budget, row quotas) cut the same rows on the same tree. It runs after the
        // per-directory cut, so a listing truncated at max_dir_entries still holds whichever entries
        // readdir returned first.
        std::ranges::sort(out.entries, {}, &DirEntry::name);
        return out;
    }

    [[nodiscard]] std::optional<FileView> open_file(const std::string& path) const {
        const std::size_t slash = path.rfind('/');
        if (slash == std::string::npos || slash + 1 == path.size() || path.find('\0') != std::string::npos ||
            mounts_.contains(path))
            return std::nullopt;
        const std::string leaf = path.substr(slash + 1);
        Acquired parent = acquire(slash == 0 ? std::string{"/"} : path.substr(0, slash));
        if (!parent.opened())
            return std::nullopt;
        note(log_, path);
        shared::FileOpen f = shared::open_file_no_follow_at(parent.fd(), leaf.c_str());
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

    // The facts of the match `name` in `dir`: the leaf is opened under the (cached) descriptor of `dir`
    // with no link followed and without blocking, so a FIFO swapped in after the listing is refused
    // rather than waited on. Nothing is read from it.
    [[nodiscard]] MatchFacts match_facts(const std::string& dir, const std::string& name,
                                         const ExtentReader& read_extents) const {
        MatchFacts f;
        const std::string full = walk_detail::join(dir, name);
        if (mounts_.contains(full) || name.empty() || name.find('/') != std::string::npos ||
            name.find('\0') != std::string::npos)
            return f;
        const Acquired parent = acquire(dir);
        if (!parent.opened())
            return f;
        shared::FileOpen leaf;
        guarded([&] {
            note(log_, full);
            leaf = shared::open_file_no_follow_at(parent.fd(), name.c_str());
        });
        if (!leaf.opened())
            return f;
        f.opened = true;
        f.size = leaf.size;
        f.mtime = static_cast<std::int64_t>(leaf.mtime.tv_sec);
        if (read_extents) {
            struct stat st {};
            if (::fstat(leaf.file.fd(), &st) == 0)
                read_extents(leaf.file.fd(), st);
        }
        return f;
    }

    [[nodiscard]] RootState root_state(const std::string& path) const {
        const Acquired a = acquire(path);
        if (a.opened())
            return RootState::ok;
        if (a.link)
            return RootState::is_link;
        if (a.err == ENOENT)
            return RootState::not_found;
        if (a.err == ENOTDIR)
            return RootState::not_a_directory;
        return RootState::other;
    }

private:
    [[nodiscard]] static Acquired fail(int err) {
        Acquired a;
        a.err = err;
        return a;
    }

    void guarded(const std::function<void()>& body) const {
        if (opts_.around)
            opts_.around(body);
        else
            body();
    }

    [[nodiscard]] bool is_link(int parent_fd, const std::string& name, const std::string& full) const {
        note(log_, full);
        struct stat st {};
        return ::fstatat(parent_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode);
    }

    // Splits `path` into its components; nullopt for a path that is not absolute or holds a NUL.
    [[nodiscard]] static std::optional<std::vector<std::string>> components_of(const std::string& path) {
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
            return std::nullopt;
        std::vector<std::string> parts;
        for (std::size_t pos = 1; pos < path.size();) {
            std::size_t end = path.find('/', pos);
            if (end == std::string::npos)
                end = path.size();
            if (end > pos)
                parts.push_back(path.substr(pos, end - pos));
            pos = end + 1;
        }
        return parts;
    }

    [[nodiscard]] Acquired failed_hop(shared::DirOpen next, int parent_fd, const std::string& comp,
                                      const std::string& prefix) const {
        const bool link = (next.err == ENOTDIR || next.err == ELOOP) && is_link(parent_fd, comp, prefix);
        Acquired a;
        a.err = next.err;
        a.link = link;
        return a;
    }

    [[nodiscard]] Acquired acquire_plain(const std::string& path) const {
        const auto parts = components_of(path);
        if (!parts)
            return fail(EINVAL);
        note(log_, "/");
        shared::DirOpen cur = shared::open_dir_no_follow("/");
        if (!cur.opened())
            return fail(cur.err);
        std::string prefix;
        for (const auto& comp : *parts) {
            prefix += '/';
            prefix += comp;
            if (mounts_.contains(prefix))
                return fail(kMountHopRefused);
            note(log_, prefix);
            shared::DirOpen next = shared::open_dir_no_follow_at(cur.dir.fd(), comp.c_str());
            if (!next.opened())
                return failed_hop(std::move(next), cur.dir.fd(), comp, prefix);
            cur = std::move(next);
        }
        Acquired a;
        a.dir = std::move(cur);
        return a;
    }

    // The same walk over a stack of held directories: the hops the new path shares with the previous one
    // are kept, the rest are closed, and only the missing ones are opened, each from the deepest held
    // descriptor. The mount check and the no-follow open run for every hop that is opened here; a held
    // hop passed them when it was opened. Past kMaxHeld the deepest hops roll through one spare slot.
    [[nodiscard]] Acquired acquire_stacked(const std::string& path) const {
        const auto parts = components_of(path);
        if (!parts)
            return fail(EINVAL);
        if (stack_.empty()) {
            note(log_, "/");
            shared::DirOpen root = shared::open_dir_no_follow("/");
            if (!root.opened())
                return fail(root.err);
            stack_.push_back({"/", std::move(root)});
        }
        spare_ = {};
        std::string prefix;
        std::size_t i = 0;
        for (; i < parts->size() && i + 1 < stack_.size(); ++i) {
            const std::string next = prefix + '/' + (*parts)[i];
            if (stack_[i + 1].path != next)
                break;
            prefix = next;
        }
        stack_.erase(stack_.begin() + static_cast<std::ptrdiff_t>(i + 1), stack_.end());

        int cur_fd = stack_.back().dir.dir.fd();
        for (; i < parts->size(); ++i) {
            const std::string& comp = (*parts)[i];
            prefix += '/';
            prefix += comp;
            if (mounts_.contains(prefix))
                return fail(kMountHopRefused);
            note(log_, prefix);
            shared::DirOpen next = shared::open_dir_no_follow_at(cur_fd, comp.c_str());
            if (!next.opened())
                return failed_hop(std::move(next), cur_fd, comp, prefix);
            if (stack_.size() < kMaxHeld) {
                stack_.push_back({prefix, std::move(next)});
                cur_fd = stack_.back().dir.dir.fd();
            } else {
                spare_ = std::move(next); // the previous spare closes only after this one was opened
                cur_fd = spare_.dir.fd();
            }
        }
        Acquired a;
        a.held = spare_.opened() ? spare_.dir.get() : stack_.back().dir.dir.get();
        return a;
    }

    struct Held {
        std::string path; // "/" for the root, else the absolute path of this directory
        shared::DirOpen dir;
    };
    // Descriptors held for the current path: kMaxHeld here plus the spare slot, so at most
    // kMaxPositionDepth + 1 in all (a Position names at most kMaxPositionDepth directories).
    static constexpr std::size_t kMaxHeld = yuzu::shared::file_search::kMaxPositionDepth;

    std::unordered_set<std::string> mounts_;
    AccessLog log_;
    PosixFsOptions opts_;
    mutable std::vector<Held> stack_;
    mutable shared::DirOpen spare_;
};

#if defined(__APPLE__)

[[nodiscard]] std::optional<std::vector<std::string>> read_network_mounts() {
    return shared::read_macos_network_mounts();
}

#else

// /proc/<pid>/mountinfo, reached hop by hop (/proc/self is itself a link) and streamed.
[[nodiscard]] std::optional<std::vector<std::string>> read_network_mounts() {
    const Acquired proc = PosixFs{}.acquire("/proc/" + std::to_string(::getpid()));
    if (!proc.opened())
        return std::nullopt;
    const shared::FileOpen f = shared::open_file_no_follow_at(proc.fd(), "mountinfo");
    if (!f.opened())
        return std::nullopt;
    return read_mountinfo_stream([fd = f.file.fd()](char* buf, std::size_t len) { return ::read(fd, buf, len); });
}

#endif

// A container host's table runs to tens of megabytes, so it is streamed line-wise rather than held
// whole. A line longer than kMaxMountLine is a failure, not skipped: skipping would hide a mount from
// the guard. Every completed line is length-checked, not just the unfinished tail. `take` is handed each
// batch of COMPLETE lines (and last the unterminated tail) and answers false to abandon the read. false
// when the table cannot be had in full.
template <typename Take>
[[nodiscard]] bool stream_mount_lines(const ReadChunk& read_chunk, std::size_t max_total, Take&& take) {
    std::string chunk(kMountChunk, '\0');
    std::string pending; // the unfinished last line of what has been read so far
    std::size_t total = 0;
    for (;;) {
        const ssize_t n = read_chunk(chunk.data(), chunk.size());
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false; // never the part read so far
        }
        if (n == 0)
            break;
        total += static_cast<std::size_t>(n);
        if (total > max_total)
            return false;
        pending.append(chunk, 0, static_cast<std::size_t>(n));
        std::size_t start = 0;
        for (std::size_t nl; (nl = pending.find('\n', start)) != std::string::npos; start = nl + 1)
            if (nl - start > kMaxMountLine)
                return false;
        if (start > 0) {
            if (!take(std::string_view{pending}.substr(0, start)))
                return false;
            pending.erase(0, start);
        }
        if (pending.size() > kMaxMountLine)
            return false;
    }
    return take(std::string_view{pending});
}

} // namespace

std::optional<std::vector<std::string>> read_mountinfo_stream(const ReadChunk& read_chunk, std::size_t max_total) {
    std::vector<std::string> out;
    const bool ok = stream_mount_lines(read_chunk, max_total, [&out](std::string_view lines) {
        for (auto& m : shared::network_mount_points(lines))
            out.push_back(std::move(m));
        return true;
    });
    if (!ok)
        return std::nullopt;
    return out;
}

std::optional<shared::MountTable> read_mount_entries_stream(const ReadChunk& read_chunk, const MountKeep& keep,
                                                            std::size_t max_total, std::size_t max_kept) {
    shared::MountTable table;
    std::unordered_map<std::string, std::size_t> at; // mount point -> its index in table.entries
    const bool ok = stream_mount_lines(read_chunk, max_total, [&](std::string_view lines) {
        auto batch = shared::mount_entries(lines);
        table.malformed += batch.malformed;
        for (auto& e : batch.entries) {
            if (keep && !keep(e))
                continue;
            if (const auto it = at.find(e.mount_point); it != at.end()) {
                table.entries[it->second] = std::move(e); // a later mount of a point covers the earlier
                continue;
            }
            if (table.entries.size() >= max_kept)
                return false;
            at.emplace(e.mount_point, table.entries.size());
            table.entries.push_back(std::move(e));
        }
        return true;
    });
    if (!ok)
        return std::nullopt;
    return table;
}

std::optional<DirEntry::Type> classify_dirent(int dir_fd, const std::string& dir, const struct dirent& e,
                                              const std::unordered_set<std::string>& network_mounts,
                                              const AccessLog& on_access) {
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
            return std::nullopt;
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
    // Cheap roots first: the walk has one entry budget, and /Applications (app bundles) can spend it all.
    return {"/Library/Java", "/usr/local", "/opt/homebrew", "/Applications"};
#else
    // Cheap roots first, for the same reason: a large /opt must not starve /usr/lib/jvm.
    return {"/usr/lib/jvm", "/usr/share/java", "/usr/share/maven", "/usr/local/lib", "/usr/local/share", "/opt"};
#endif
}

std::vector<std::string> native_candidate_roots() {
#if defined(__APPLE__)
    return {"/Applications", "/usr/local", "/opt/homebrew"};
#else
    return {"/opt", "/usr/local/lib"};
#endif
}

std::vector<std::string> native_excluded_dirs() {
#if defined(__APPLE__)
    return {"/usr/local/Cellar", "/opt/homebrew/Cellar"};
#else
    return {};
#endif
}

namespace {

/// `python3` (when `bare`) or `python3.<digits>`: the name of an interpreter's library directory.
[[nodiscard]] bool is_python_dir_name(std::string_view n, bool bare) {
    constexpr std::string_view kPrefix = "python3";
    if (!n.starts_with(kPrefix))
        return false;
    n.remove_prefix(kPrefix.size());
    if (n.empty())
        return bare;
    if (n.size() < 2 || n.front() != '.')
        return false;
    return std::ranges::all_of(n.substr(1), [](char c) { return c >= '0' && c <= '9'; });
}

/// The `python3[.N]` children of `parent`, sorted so the walk order does not depend on the lister. A parent
/// that could not be listed is offered itself, so the root checks count a network mount or a link and the
/// walk reports an unreadable one, instead of the parent vanishing without a count.
void append_python_dirs(std::vector<std::string>& out, const ChildLister& children, const std::string& parent,
                        bool bare) {
    auto listed = children(parent);
    if (!listed) {
        out.push_back(parent);
        return;
    }
    std::vector<std::string> names;
    for (auto& n : *listed)
        if (is_python_dir_name(n, bare))
            names.push_back(std::move(n));
    std::ranges::sort(names);
    for (const auto& n : names)
        out.push_back(parent + '/' + n);
}

} // namespace

std::vector<std::string> python_candidate_roots(const ChildLister& children) {
    std::vector<std::string> roots;
#if defined(__APPLE__)
    roots.push_back("/Library/Frameworks/Python.framework/Versions");
    append_python_dirs(roots, children, "/opt/homebrew/lib", false);
    append_python_dirs(roots, children, "/usr/local/lib", false);
#else
    // /usr/lib is deliberately absent: the package manager owns the interpreter trees under it.
    append_python_dirs(roots, children, "/usr/local/lib", true);
    roots.push_back("/opt");
#endif
    return roots;
}

std::vector<std::string> node_candidate_roots() {
#if defined(__APPLE__)
    return {"/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules", "/Applications"};
#else
    return {"/usr/lib/node_modules", "/usr/local/lib/node_modules", "/opt"};
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
        if (a.opened())
            return false;
        if (a.link) {
            ++t.roots_link_skipped;
            return true;
        }
        return a.err == ENOENT || a.err == ENOTDIR; // nothing to walk; any other failure stays to be reported
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

Targets scan_native_targets() {
    return scan_targets(native_candidate_roots(), read_network_mounts);
}

ChildLister make_child_lister(const decltype(FsOps::list)& list) {
    return [list](const std::string& dir) -> std::optional<std::vector<std::string>> {
        const ListResult lr = list(dir, WalkLimits{}.max_dir_entries);
        // A listing cut at the walk's per-directory cap holds only some of the python3.N names, and the
        // walk reports the same cut as dir_truncated. Offering the parent as a root in their place makes
        // the answer say so; a partial root set must never read as the whole one.
        if (lr.error || lr.truncated)
            return std::nullopt;
        std::vector<std::string> names;
        for (const auto& e : lr.entries)
            // A network mount is kept too: it is never opened here, and as a root it is counted into
            // roots_network_skipped by plan_targets instead of vanishing uncounted.
            if (e.type == DirEntry::Type::dir || e.type == DirEntry::Type::link ||
                e.type == DirEntry::Type::network_mount)
                names.push_back(e.name);
        return names;
    };
}

Targets scan_python_targets() {
    const auto mounts = read_network_mounts();
    if (!mounts)
        return scan_targets({}, [] { return std::nullopt; }); // no table, no listing: reported as unreadable
    const PosixFs fs{*mounts};
    const ChildLister children = make_child_lister(
        [&fs](const std::string& dir, std::size_t cap) { return fs.list(dir, cap); });
    return scan_targets(python_candidate_roots(children), [&mounts] { return mounts; });
}

Targets scan_node_targets() {
    return scan_targets(node_candidate_roots(), read_network_mounts);
}

FsOps make_fs_ops(const Targets& targets, AccessLog on_access) {
    const auto fs = std::make_shared<const PosixFs>(targets.network_mounts, std::move(on_access));
    FsOps ops;
    ops.list = [fs](const std::string& dir, std::size_t cap) { return fs->list(dir, cap); };
    ops.open_file = [fs](const std::string& path) { return fs->open_file(path); };
    ops.now = [] { return std::chrono::steady_clock::now(); };
    return ops;
}

SearchLeg make_search_leg(std::vector<std::string> prune, AccessLog on_access, SearchHooks hooks,
                          ReadDirFn read_dir) {
    PosixFsOptions opts;
    opts.descriptor_stack = true;
    opts.around = std::move(hooks.around_lookup);
    opts.read_dir = std::move(read_dir);
    const auto fs = std::make_shared<const PosixFs>(prune, std::move(on_access), std::move(opts));

    SearchLeg leg;
    leg.ops.list = [fs](const std::string& dir, std::size_t cap) {
        ListResult r = fs->list(dir, cap);
        // A pruned mount point is typed network_mount from its path alone. It is the search plan's to
        // report, once, so it reaches neither the visitor nor the walker's gap and mount counters.
        std::erase_if(r.entries, [](const DirEntry& e) { return e.type == DirEntry::Type::network_mount; });
        return r;
    };
    leg.ops.open_file = [](const std::string&) -> std::optional<FileView> { return std::nullopt; };
    leg.ops.now = [] { return std::chrono::steady_clock::now(); };
    leg.facts = [fs, read = std::move(hooks.read_extents)](const std::string& dir, const std::string& name) {
        return fs->match_facts(dir, name, read);
    };
    leg.root_state = [fs](const std::string& path) { return fs->root_state(path); };
    return leg;
}

} // namespace yuzu::component_inventory

#endif // !_WIN32
