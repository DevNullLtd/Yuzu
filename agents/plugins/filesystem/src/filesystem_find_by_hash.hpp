#pragma once

// filesystem_find_by_hash.hpp -- the bounded, symlink-safe walk behind the filesystem plugin's
// find_by_hash action (#5624).
//
// The walk is a PURE CORE with every OS interaction injected (WalkEnv): a clock, a cancel
// predicate, a per-entry hasher, a directory-readability probe and the network mount list. The
// unit suites drive it with fakes -- no sleep, no real process, no network -- and the production
// hashers (hash_entry_posix / hash_entry_win, at the bottom) are the thin OS shells.
//
// What is bounded, and why the numbers are what they are:
//   * wall clock    kWalkDeadline 20 s -- the Instructions gate polls at 30 s and the result still
//                   has to travel agent -> server -> store -> poll; this leaves a 10 s margin.
//   * entries       kMaxFilesVisited 50,000 -- about 20 s of stat/open at ~2,500 entries/s on a
//                   cold spinning disk.
//   * bytes hashed  kMaxBytesHashed 4 GiB -- about 20 s of pure-C++ SHA-256 (~200 MB/s) on the one
//                   shared command worker; it also bounds page-cache churn.
//   * matches       kMaxResults 100.
// The three bounds are coupled, not independent: whichever trips first ends the walk. The deadline
// is polled between system calls, so a search ordinarily ends within 20 seconds; a single blocked
// read or directory listing is not interrupted (#4875). A file larger than the remaining byte
// budget is skipped and counted (skipped_oversize), so one big file cannot end the walk; the run
// then reports byte_cap, because that file went unexamined.
//
// An entry below the search root is NEVER followed through a symlink (whole path on macOS and
// Linux >= 5.6, leaf only on older Linux kernels and on Windows), a non-regular file is never
// opened, and the network-mount check runs on a path BEFORE any call that touches it. On Linux a
// directory on a pseudo-filesystem (/proc, /sys, ...) is never entered. Anything the walk could not
// examine, or stopped short of, is counted and reported by ONE trailing `truncated|...` row; a run
// that skipped nothing writes exactly the rows it always wrote.

#include "filesystem_acl_parsers.hpp" // yuzu::filesystem::acl::row_field (row-field escaping)

#include <sha256.hpp> // yuzu::shared::Sha256

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#include <yuzu/agent/confined_fs.hpp> // confined_fs::WinHandle, the shared HANDLE owner
#pragma comment(lib, "bcrypt.lib")
#else
#include <spdlog/spdlog.h>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/vfs.h> // fstatfs
// openat2 (Linux 5.6) is syscall 437 on x86, arm, arm64 and riscv. An old linux-libc-dev only lacks
// the SYS_ macro, not the kernel the agent runs on, so the whole-path no-follow must not depend on
// the build host's headers. Architectures with their own numbering (alpha, mips, ia64) are left
// undefined: they get the leaf-only fallback, never a wrong syscall.
#if !defined(SYS_openat2) && (defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) ||  \
                              defined(__arm__) || defined(__riscv))
#define SYS_openat2 437
#endif
#endif
#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd
#endif

namespace yuzu::filesystem::find_by_hash {

namespace fs = std::filesystem;

// -- Bounds -------------------------------------------------------------------------------------

inline constexpr std::chrono::milliseconds kWalkDeadline{20'000};
inline constexpr std::size_t kMaxFilesVisited = 50'000;
inline constexpr std::uint64_t kMaxBytesHashed = 4ULL * 1024 * 1024 * 1024;
inline constexpr int kMaxResults = 100;
/// Largest single file the plugin hashes (10 GB); file_hash shares it.
inline constexpr std::uintmax_t kMaxHashFileSize = 10ULL * 1024 * 1024 * 1024;
/// Read size of the streaming hasher; the deadline / cancel / byte cap are re-checked per chunk.
inline constexpr std::size_t kHashChunk = 64 * 1024;

struct WalkLimits {
    std::chrono::milliseconds deadline{kWalkDeadline};
    std::size_t max_files_visited{kMaxFilesVisited};
    std::uint64_t max_bytes_hashed{kMaxBytesHashed};
    int max_results{kMaxResults};
    std::uintmax_t max_file_bytes{kMaxHashFileSize};
};

// -- Outcome ------------------------------------------------------------------------------------

/// byte_cap is also the outcome of a walk that ran to its end after skipping a file larger than the
/// remaining byte budget (HashKind::over_budget): the bound kept that file from being examined.
enum class StopReason { none, deadline, file_cap, byte_cap, cancelled, max_results };

[[nodiscard]] constexpr std::string_view stop_reason_token(StopReason r) noexcept {
    switch (r) {
    case StopReason::none:
        return "none";
    case StopReason::deadline:
        return "deadline";
    case StopReason::file_cap:
        return "file_cap";
    case StopReason::byte_cap:
        return "byte_cap";
    case StopReason::cancelled:
        return "cancelled";
    case StopReason::max_results:
        return "max_results";
    }
    return "none";
}

struct WalkCounters {
    std::size_t visited{0};
    std::uint64_t hashed_bytes{0};
    std::size_t skipped_unreadable{0};
    std::size_t skipped_symlink{0};
    std::size_t skipped_not_regular{0};
    std::size_t skipped_oversize{0};
    std::size_t skipped_network_mount{0};
};

struct WalkOutcome {
    int matches{0};
    StopReason stop{StopReason::none};
    WalkCounters c;
    /// The mount table could not be read in full, so the network-mount guard was off for the whole
    /// walk (WalkEnv::mount_table_complete). Not a skip counter: nothing was refused or counted.
    bool mount_table_incomplete{false};

    /// True when anything was skipped or the walk stopped early: the one case that writes the
    /// trailing `truncated|...` row. By-design exclusions (a symlink, a FIFO, a file over 10 GB)
    /// are counted here, so the row is the operator's evidence that they were not examined.
    [[nodiscard]] bool trailer_needed() const noexcept {
        return stop != StopReason::none || c.skipped_unreadable > 0 || c.skipped_symlink > 0 ||
               c.skipped_not_regular > 0 || c.skipped_oversize > 0 || c.skipped_network_mount > 0;
    }
    /// True when something the operator would expect to be examined was not: a tripped bound, an
    /// entry that could not be read, a network mount that was refused, or a walk that ran without
    /// its mount guard. Drives CONSTRAINED/PARTIAL; a by-design exclusion alone (symlink, FIFO,
    /// file over 10 GB) does not.
    [[nodiscard]] bool constrained() const noexcept {
        return stop != StopReason::none || mount_table_incomplete || c.skipped_unreadable > 0 ||
               c.skipped_network_mount > 0;
    }
};

/// The CONSTRAINED result's provenance: `filesystem:<first applicable reason>`.
[[nodiscard]] inline std::string constrained_reason(const WalkOutcome& o) {
    if (o.stop != StopReason::none)
        return "filesystem:" + std::string{stop_reason_token(o.stop)};
    if (o.mount_table_incomplete)
        return "filesystem:mount_table_unreadable";
    if (o.c.skipped_unreadable > 0)
        return "filesystem:skipped_unreadable";
    return "filesystem:skipped_network_mount";
}

/// `truncated|<stop token or none>|visited=N|hashed=N|skipped_unreadable=N|skipped_symlink=N|
/// skipped_not_regular=N|skipped_oversize=N|skipped_network_mount=N` (one line). `none` means no
/// bound tripped; the counters say what was skipped.
[[nodiscard]] inline std::string format_trailer(const WalkOutcome& o) {
    return std::format("truncated|{}|visited={}|hashed={}|skipped_unreadable={}|skipped_symlink={}|"
                       "skipped_not_regular={}|skipped_oversize={}|skipped_network_mount={}",
                       stop_reason_token(o.stop), o.c.visited, o.c.hashed_bytes,
                       o.c.skipped_unreadable, o.c.skipped_symlink, o.c.skipped_not_regular,
                       o.c.skipped_oversize, o.c.skipped_network_mount);
}

/// The row written when the mount table could not be read in full. It has two fields, not the
/// three of a match row, so it is never a data row to a column matcher; the status number alone is
/// not visible on REST, MCP or CSV, so this row is the operator-visible signal.
inline constexpr std::string_view kMountGuardUnavailableRow = "network_mount_guard|unavailable";

/// The rows that close a walk, in order: the guard-off row when the mount table was unreadable,
/// the `truncated|...` trailer when anything was skipped or stopped short, then `matches_found|N`.
[[nodiscard]] inline std::vector<std::string> format_outcome_rows(const WalkOutcome& o) {
    std::vector<std::string> rows;
    if (o.mount_table_incomplete)
        rows.emplace_back(kMountGuardUnavailableRow);
    if (o.trailer_needed())
        rows.push_back(format_trailer(o));
    rows.push_back(std::format("matches_found|{}", o.matches));
    return rows;
}

/// `match|<path>|<size>`. The path takes the plugin's shared row-field escaping: CR/LF fold to a
/// space, '|' is escaped, an interior backslash is preserved (a Windows path is byte-identical to
/// what it always was) and ONLY a trailing backslash folds to '/', the one shape that would glue
/// onto the field separator as `\|`.
[[nodiscard]] inline std::string format_match_row(std::string_view path, std::uintmax_t size) {
    return std::format("match|{}|{}", acl::row_field(path), size);
}

/// The path as UTF-8 bytes for a match row. On Windows path::string() is the ANSI code page and
/// throws for a name it cannot hold; u8string() cannot, and is byte-identical for ASCII names.
[[nodiscard]] inline std::string path_utf8(const fs::path& p) {
#ifdef _WIN32
    const auto u8 = p.u8string();
    return std::string{reinterpret_cast<const char*>(u8.data()), u8.size()};
#else
    return p.string();
#endif
}

// -- Network mounts -----------------------------------------------------------------------------

/// True when `path` is a mount point in `mounts` or lies under one. A pure string comparison on a
/// path boundary ("/mnt/nfs" covers "/mnt/nfs/x" but not "/mnt/nfsx"), so it can run before any
/// call that touches the path. A mount of "/" covers everything.
[[nodiscard]] inline bool is_under_mount(std::string_view path,
                                         const std::vector<std::string>& mounts) {
    for (const auto& mount : mounts) {
        std::string_view m{mount};
        while (m.size() > 1 && m.back() == '/')
            m.remove_suffix(1);
        if (m.empty())
            continue;
        if (m == "/" || path == m)
            return true;
        if (path.size() > m.size() && path.compare(0, m.size(), m) == 0 &&
            (path[m.size()] == '/'
#ifdef _WIN32
             || path[m.size()] == '\\'
#endif
             ))
            return true;
    }
    return false;
}

/// macOS firmlinked volume: a mount the system creates is listed as `/System/Volumes/Data/<path>`
/// and is the same object as `/<path>`; a firmlink is not a symlink, so a prefix compare cannot
/// tell the spellings apart (docs/darwin-compat.md).
inline constexpr std::string_view kDataVolume = "/System/Volumes/Data";

/// Adds the other spelling of every mount (stripped / Data-volume form; never "/") so a root
/// matches under either. Pure: no stat, no realpath.
inline void add_data_volume_aliases(std::vector<std::string>& mounts) {
    std::vector<std::string> aliases;
    for (const std::string_view m : mounts) {
        if (m.size() <= kDataVolume.size() && m.starts_with(kDataVolume))
            continue; // the Data volume's own root: no alias
        if (m.starts_with(kDataVolume) && m[kDataVolume.size()] == '/')
            aliases.emplace_back(m.substr(kDataVolume.size()));
        else if (m.size() > 1 && m.front() == '/')
            aliases.push_back(std::string{kDataVolume} + std::string{m});
    }
    mounts.insert(mounts.end(), aliases.begin(), aliases.end());
}

/// The root as the pre-validation guard judges it: absolute (a lexical join with the working
/// directory; touches nothing) and lexically normalised, so "/mnt/nfs/", "/mnt//nfs",
/// "/mnt/./nfs", "/mnt/x/../nfs" and a relative spelling all name the mount. On failure `ec` is set
/// and the normalised spelling as given is returned.
[[nodiscard]] inline fs::path lexical_root(std::string_view raw_root, std::error_code& ec) {
    const fs::path raw{std::string{raw_root}};
    const fs::path absolute = fs::absolute(raw, ec);
    return (ec ? raw : absolute).lexically_normal();
}

/// The pre-validation refusal: the raw `directory` parameter, lexically resolved (see
/// lexical_root), under a network mount. It runs before validate_path's exists/canonical, which
/// would otherwise block on a dead hard mount.
[[nodiscard]] inline bool root_lexically_under_mount(std::string_view raw_root,
                                                     const std::vector<std::string>& mounts) {
    std::error_code ec;
    return is_under_mount(lexical_root(raw_root, ec).string(), mounts);
}

// -- Budget -------------------------------------------------------------------------------------

using Clock = std::chrono::steady_clock;

/// The shared wall-clock / cancel / byte-cap gate. The first bound to trip is remembered in
/// stop() and every later call answers false, so a hasher and the walk agree on the reason.
class HashBudget {
public:
    HashBudget(const WalkLimits& limits, std::function<Clock::time_point()> now,
               std::function<bool()> cancelled, WalkCounters& counters)
        : limits_(limits), now_(std::move(now)), cancelled_(std::move(cancelled)),
          counters_(counters), deadline_at_(now_() + limits.deadline) {}

    /// Cancel first, then the deadline. False once any bound has tripped.
    [[nodiscard]] bool check() {
        if (stop_ != StopReason::none)
            return false;
        if (cancelled_()) {
            stop_ = StopReason::cancelled;
            return false;
        }
        if (now_() >= deadline_at_) {
            stop_ = StopReason::deadline;
            return false;
        }
        return true;
    }

    /// Account `n` bytes about to be hashed: check() first, then the byte cap. Counts only bytes
    /// that were admitted, so `hashed=` in the trailer is what actually went through SHA-256.
    [[nodiscard]] bool consume(std::size_t n) {
        if (!check())
            return false;
        if (n > limits_.max_bytes_hashed - counters_.hashed_bytes) {
            stop_ = StopReason::byte_cap;
            return false;
        }
        counters_.hashed_bytes += n;
        return true;
    }

    /// Bytes still admissible under the cap: a hasher skips a file larger than this instead of
    /// letting it end the whole walk part-way through.
    [[nodiscard]] std::uint64_t remaining() const noexcept {
        return limits_.max_bytes_hashed - counters_.hashed_bytes;
    }

    [[nodiscard]] StopReason stop() const noexcept { return stop_; }

private:
    WalkLimits limits_;
    std::function<Clock::time_point()> now_;
    std::function<bool()> cancelled_;
    WalkCounters& counters_;
    Clock::time_point deadline_at_;
    StopReason stop_{StopReason::none};
};

// -- Walk ---------------------------------------------------------------------------------------

/// oversize: over the 10 GB per-file ceiling (by design). over_budget: within the ceiling but
/// larger than the byte budget that is left, so the bound kept it from being examined.
enum class HashKind { hashed, symlink, not_regular, oversize, over_budget, unreadable, stopped };

struct HashOutcome {
    HashKind kind{HashKind::unreadable};
    std::string hex;        ///< lowercase SHA-256, set when kind == hashed
    std::uintmax_t size{0}; ///< size of the file as opened, set when kind == hashed
};

struct WalkEnv {
    std::function<Clock::time_point()> now = [] {
        return Clock::now();
    };
    std::function<bool()> cancelled = [] {
        return false;
    };
    /// Hash one regular-file candidate. MUST open no-follow and decide regular-file-ness on the
    /// descriptor/handle it opened (the walk's own check is only a pre-filter).
    std::function<HashOutcome(const fs::directory_entry&, HashBudget&, const WalkLimits&)>
        hash_entry;
    /// Can the directory be listed? (access(R_OK|X_OK) / a directory_iterator probe.) Asked before
    /// the iterator opens a directory, so an unreadable one is counted, not silently skipped.
    std::function<bool(const fs::path&)> can_enter = [](const fs::path&) {
        return true;
    };
    /// Mount points whose subtrees are refused. Empty = no guard.
    std::vector<std::string> network_mounts;
    /// False when the mount table could not be read in full: the list above is then empty or
    /// partial and the walk runs unguarded, which the outcome reports.
    bool mount_table_complete{true};
};

/// The network mount points of this host and whether the table was read in full. `complete` is
/// false when it could not be (the list is then empty): the walk still runs, reported as
/// constrained, rather than looking like a clean unguarded success.
struct MountList {
    std::vector<std::string> mounts;
    bool complete{true};
};

/// Walk `root` to `max_depth` (root's children are depth 1), emitting one `match|...` row per
/// regular file whose SHA-256 equals `target_lower`. The ORDER of the checks is the safety
/// property: the mount check is a string comparison that precedes every call touching the path.
template <class Emit>
WalkOutcome walk_find_by_hash(const std::string& root, std::string_view target_lower, int max_depth,
                              const WalkLimits& limits, const WalkEnv& env, Emit emit) {
    WalkOutcome out;
    out.mount_table_incomplete = !env.mount_table_complete;
    WalkCounters& c = out.c;
    HashBudget budget{limits, env.now, env.cancelled, c};
    bool over_budget = false; // a file was skipped for want of byte budget

    // The root first: a root under a network mount is refused before any syscall names it, and an
    // unreadable root is counted -- skip_permission_denied would otherwise turn it into a clean,
    // empty end iterator.
    if (is_under_mount(root, env.network_mounts)) {
        c.skipped_network_mount = 1;
        return out;
    }
    if (!env.can_enter(fs::path{root})) {
        c.skipped_unreadable = 1;
        return out;
    }
    std::error_code ec;
    fs::recursive_directory_iterator it{fs::path{root},
                                        fs::directory_options::skip_permission_denied, ec};
    if (ec) {
        c.skipped_unreadable = 1;
        return out;
    }
    const fs::recursive_directory_iterator end;

    while (it != end) {
        if (!budget.check()) {
            out.stop = budget.stop();
            break;
        }
        if (c.visited >= limits.max_files_visited) {
            out.stop = StopReason::file_cap;
            break;
        }
        ++c.visited;

        const fs::directory_entry& entry = *it;
        const fs::path& path = entry.path();

        // A mount point under a walked directory is refused BEFORE lstat can block on it. With no
        // mount list there is nothing to compare, so the path is not even converted to a string
        // (on MSVC path::string() can throw for a name the ANSI code page cannot hold).
        if (!env.network_mounts.empty() && is_under_mount(path.string(), env.network_mounts)) {
            ++c.skipped_network_mount;
            it.disable_recursion_pending();
        } else if (const fs::file_status st = entry.symlink_status(ec); ec) {
            ++c.skipped_unreadable;
            it.disable_recursion_pending();
        } else if (fs::is_symlink(st)
#ifdef _WIN32
                   || st.type() == fs::file_type::junction
#endif
        ) {
            ++c.skipped_symlink;
            it.disable_recursion_pending();
        } else if (fs::is_directory(st)) {
            // Children of a directory at depth d sit at d + 1: a directory AT the limit is never
            // opened, and one we cannot list is counted instead of being skipped silently.
            if (it.depth() + 1 >= max_depth) {
                it.disable_recursion_pending();
            } else if (!env.can_enter(path)) {
                ++c.skipped_unreadable;
                it.disable_recursion_pending();
            }
        } else if (st.type() != fs::file_type::regular) {
            // FIFO, device, socket: never opened (an open of a FIFO can block).
            ++c.skipped_not_regular;
        } else {
            const HashOutcome h = env.hash_entry(entry, budget, limits);
            if (h.kind == HashKind::stopped) {
                out.stop = budget.stop();
                break;
            }
            switch (h.kind) {
            case HashKind::symlink:
                ++c.skipped_symlink;
                break;
            case HashKind::not_regular:
                ++c.skipped_not_regular;
                break;
            case HashKind::oversize:
                ++c.skipped_oversize;
                break;
            case HashKind::over_budget:
                ++c.skipped_oversize;
                over_budget = true;
                break;
            case HashKind::unreadable:
                ++c.skipped_unreadable;
                break;
            case HashKind::hashed:
            case HashKind::stopped:
                break;
            }
            if (h.kind == HashKind::hashed && h.hex == target_lower) {
                emit(format_match_row(path_utf8(path), h.size));
                if (++out.matches >= limits.max_results) {
                    // Stopping at the cap is only honest if nothing is left to look at: look one
                    // entry ahead, so exactly `max_results` matches in a fully walked tree is
                    // clean.
                    it.increment(ec);
                    if (ec)
                        ++c.skipped_unreadable; // the entry that could not be looked at
                    if (ec || it != end)
                        out.stop = StopReason::max_results;
                    break;
                }
            }
        }

        it.increment(ec);
        if (ec) { // an enumeration error ends the iterator on every STL
            ++c.skipped_unreadable;
            break;
        }
    }
    // The walk went on past a file the byte cap kept it from examining: that is a tripped bound,
    // unless an earlier one already ended the walk and named itself.
    if (over_budget && out.stop == StopReason::none)
        out.stop = StopReason::byte_cap;
    return out;
}

// -- POSIX hasher -------------------------------------------------------------------------------

#ifndef _WIN32

namespace detail {

/// Set once a Linux kernel (or seccomp profile) refuses openat2, so a host without it pays ONE
/// failed syscall per process rather than one per file. Exposed so a test can force the fallback.
inline std::atomic<bool>& openat2_unavailable() {
    static std::atomic<bool> unavailable{false};
    return unavailable;
}

/// Remember that openat2 cannot be used, and say so once: from here on the open is leaf-only
/// no-follow (a disclosed residual), which an operator debugging a symlink question needs to know.
inline void latch_openat2_unavailable() noexcept {
    // noexcept: the caller may hold a bare descriptor, and a logging failure must not leak it.
    try {
        if (!openat2_unavailable().exchange(true, std::memory_order_relaxed))
            spdlog::debug("filesystem find_by_hash: openat2 is unavailable; the no-follow open is "
                          "leaf-only from here on");
    } catch (...) {
    }
}

/// open(2) that refuses a symlink in ANY path component where the OS offers that as one call:
/// macOS O_NOFOLLOW_ANY; Linux >= 5.6 openat2(RESOLVE_NO_SYMLINKS). Elsewhere (and on a kernel
/// without openat2) only the leaf is no-follow, so a directory swapped for a link between
/// enumeration and open is a disclosed residual there. A refused symlink is ELOOP.
inline int open_no_follow_any(const char* path, int flags) {
#if defined(__APPLE__)
    return ::open(path, flags | O_NOFOLLOW_ANY);
#elif defined(__linux__) && defined(SYS_openat2)
    if (!openat2_unavailable().load(std::memory_order_relaxed)) {
        // struct open_how, declared locally so an old linux-libc-dev still compiles.
        struct OpenHow {
            std::uint64_t flags;
            std::uint64_t mode;
            std::uint64_t resolve;
        } how{};
        constexpr std::uint64_t kResolveNoSymlinks = 0x04;
        how.flags = static_cast<std::uint64_t>(flags | O_NOFOLLOW);
#ifdef O_LARGEFILE
        // glibc adds O_LARGEFILE to open() only; the raw syscall must ask, or a file over 2 GiB is
        // EOVERFLOW on a 32-bit build.
        how.flags |= static_cast<std::uint64_t>(O_LARGEFILE);
#endif
        how.resolve = kResolveNoSymlinks;
        const long fd = ::syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
        if (fd >= 0)
            return static_cast<int>(fd);
        // ENOSYS: kernel < 5.6. EINVAL / E2BIG: the how struct is not understood. These say the
        // SYSCALL is unusable. Anything else is a real open error.
        if (errno == EPERM) {
            // EPERM is ambiguous: a seccomp profile that does not know the syscall, or the FILE's
            // own refusal (/proc/kmsg without CAP_SYSLOG, a FUSE file). openat2 differs from open
            // only by RESOLVE_NO_SYMLINKS, whose refusal is ELOOP, so the plain open tells them
            // apart: latch only if it succeeds. A failure is the file's own and keeps its errno.
            const int plain = ::open(path, flags | O_NOFOLLOW);
            if (plain < 0)
                return -1;
            latch_openat2_unavailable();
            return plain;
        }
        if (errno != ENOSYS && errno != EINVAL && errno != E2BIG)
            return -1;
        latch_openat2_unavailable();
    }
    return ::open(path, flags | O_NOFOLLOW);
#else
    return ::open(path, flags | O_NOFOLLOW);
#endif
}

} // namespace detail

/// Stream `read_chunk(buf, len) -> n` (0 = EOF, < 0 = error with errno set) through SHA-256 under
/// `budget`. Every interrupted read re-checks cancel / deadline before it is retried, so a signal
/// storm cannot keep a cancelled or overdue hash alive. Returns hashed (hex set), unreadable or
/// stopped; `size` is only copied into the outcome.
template <class ReadChunk>
[[nodiscard]] HashOutcome hash_stream(ReadChunk&& read_chunk, HashBudget& budget,
                                      std::uintmax_t size) {
    yuzu::shared::Sha256 sha;
    unsigned char buf[kHashChunk];
    for (;;) {
        const long long n = read_chunk(buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                if (!budget.check())
                    return {HashKind::stopped, {}, 0};
                continue;
            }
            return {HashKind::unreadable, {}, 0};
        }
        if (n == 0)
            break;
        if (!budget.consume(static_cast<std::size_t>(n)))
            return {HashKind::stopped, {}, 0};
        sha.update(buf, static_cast<std::size_t>(n));
    }
    return {HashKind::hashed, sha.hex_digest(), size};
}

/// statfs f_type of a Linux pseudo-filesystem whose "files" are not data: reading one has side
/// effects (/proc/kmsg drains the kernel log), is endless (/proc/<pid>/pagemap) or is a control
/// surface (sysfs, debugfs, cgroups, ...). The values are linux/magic.h's ABI-stable constants as
/// plain numbers (no kernel header needed; the system_hardening plugin does the same).
[[nodiscard]] constexpr bool is_pseudo_fs_magic(std::uint64_t f_type) noexcept {
    switch (f_type) {
    case 0x9fa0:     // PROC_SUPER_MAGIC
    case 0x62656572: // SYSFS_MAGIC
    case 0x64626720: // DEBUGFS_MAGIC
    case 0x74726163: // TRACEFS_MAGIC
    case 0x73636673: // SECURITYFS_MAGIC
    case 0x62656570: // CONFIGFS_MAGIC
    case 0xcafe4a11: // BPF_FS_MAGIC
    case 0x27e0eb:   // CGROUP_SUPER_MAGIC
    case 0x63677270: // CGROUP2_SUPER_MAGIC
    case 0x1cd1:     // DEVPTS_SUPER_MAGIC
    case 0xde5e81e4: // EFIVARFS_MAGIC
    case 0x6165676c: // PSTOREFS_MAGIC
    case 0x6e736673: // NSFS_MAGIC
    case 0x42494e4d: // BINFMTFS_MAGIC
    case 0x19800202: // MQUEUE_MAGIC
        return true;
    default:
        return false;
    }
}

/// Can `dir` be listed? access() answers the permission bits; the no-follow directory open answers
/// everything else the directory iterator will meet -- a macOS TCC or SIP refusal is EPERM, which
/// skip_permission_denied does not swallow and which would end the whole walk at that directory.
/// On Linux a directory on a pseudo-filesystem is refused too (see is_pseudo_fs_magic): the check
/// is on the DIRECTORY, on the descriptor just opened, so it precedes the iterator naming a single
/// child and no file under it is ever opened. A filesystem that cannot be classified is refused
/// (fail-closed); either way the directory is counted unreadable, never silently skipped.
[[nodiscard]] inline bool can_enter_posix(const fs::path& dir) {
    if (::access(dir.c_str(), R_OK | X_OK) != 0)
        return false;
    const yuzu::agent::ScopedFd fd{
        detail::open_no_follow_any(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (!fd)
        return false;
#ifdef __linux__
    struct statfs info{};
    if (::fstatfs(fd.get(), &info) != 0)
        return false;
    // f_type is signed on some ABIs: widen from its unsigned twin so 0xcafe4a11 does not
    // sign-extend.
    using Raw = std::make_unsigned_t<decltype(info.f_type)>;
    if (is_pseudo_fs_magic(static_cast<std::uint64_t>(static_cast<Raw>(info.f_type))))
        return false;
#endif
    return true;
}

/// Hash one directory entry on POSIX: a whole-path no-follow open, fstat on THAT descriptor (the
/// authoritative regular-file and size check -- the walk's lstat is only a pre-filter), then a
/// bounded streaming SHA-256. O_NONBLOCK keeps an open of a FIFO that replaced the file after the
/// pre-filter from blocking.
[[nodiscard]] inline HashOutcome hash_entry_posix(const fs::directory_entry& entry,
                                                  HashBudget& budget, const WalkLimits& limits) {
    const std::string path = entry.path().string();
    yuzu::agent::ScopedFd fd{
        detail::open_no_follow_any(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)};
    if (!fd)
        return {errno == ELOOP ? HashKind::symlink : HashKind::unreadable, {}, 0};
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0)
        return {HashKind::unreadable, {}, 0};
    if (!S_ISREG(st.st_mode))
        return {HashKind::not_regular, {}, 0};
    const auto size = static_cast<std::uintmax_t>(st.st_size);
    if (size > limits.max_file_bytes)
        return {HashKind::oversize, {}, 0};
    if (size > budget.remaining())
        return {HashKind::over_budget, {}, 0};
    return hash_stream(
        [&](unsigned char* buf, std::size_t len) -> long long {
            return static_cast<long long>(::read(fd.get(), buf, len));
        },
        budget, size);
}

#else // _WIN32

/// A drive root this walk refuses before touching it: anything but a fixed disk. UNKNOWN fails
/// closed; REMOVABLE, CDROM, REMOTE and RAMDISK are refused (win_hive_file_guard.hpp refuses
/// `!= DRIVE_FIXED` the same way). NO_ROOT_DIR is the one other answer let through: no such drive
/// exists, so validate_path reports the honest `directory is not accessible` error instead of a
/// network-mount skip that never happened.
[[nodiscard]] inline bool win_root_drive_refused(UINT drive_type) noexcept {
    return drive_type != DRIVE_FIXED && drive_type != DRIVE_NO_ROOT_DIR;
}

namespace detail {

/// IO_REPARSE_TAG_WOF (CompactOS / Windows Overlay Filter) and IO_REPARSE_TAG_DEDUP: reparse points
/// whose filter serves the file's real data, so the file is hashed (through a reopened handle).
inline constexpr DWORD kReparseTagWof = 0x80000017;
inline constexpr DWORD kReparseTagDedup = 0x80000013;

/// BCrypt SHA-256 context with scope-exit cleanup on every path. Kept beside the hasher rather than
/// folded onto a shared helper: compute_hash_win (file_hash) drives BCrypt by hand and is outside
/// this change, so unifying the two is a file_hash refactor of its own.
struct BcryptSha256 {
    BCRYPT_ALG_HANDLE alg{nullptr};
    BCRYPT_HASH_HANDLE hash{nullptr};
    std::vector<UCHAR> object;
    bool ok{false};

    BcryptSha256() {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return;
        DWORD object_length = 0;
        DWORD got = 0;
        // BCryptGetProperty writes a DWORD through a PUCHAR; sizeof(object_length) bounds it.
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
                              sizeof(object_length), &got, 0) != 0)
            return;
        try {
            object.resize(object_length);
        } catch (...) {
            return; // ok stays false and the destructor closes `alg` (a throwing ctor would not)
        }
        ok = BCryptCreateHash(alg, &hash, object.data(), object_length, nullptr, 0, 0) == 0;
    }
    BcryptSha256(const BcryptSha256&) = delete;
    BcryptSha256& operator=(const BcryptSha256&) = delete;
    ~BcryptSha256() {
        if (hash)
            BCryptDestroyHash(hash);
        if (alg)
            BCryptCloseAlgorithmProvider(alg, 0);
    }
    bool update(const unsigned char* data, std::size_t len) {
        // BCryptHashData takes a non-const PUCHAR for its C signature but never writes the input.
        return BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) == 0;
    }
    bool finish(std::string& hex) {
        UCHAR digest[32]{};
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0)
            return false;
        static constexpr char hexc[] = "0123456789abcdef";
        hex.clear();
        for (const UCHAR b : digest) {
            hex += hexc[b >> 4];
            hex += hexc[b & 0xF];
        }
        return true;
    }
};

} // namespace detail

/// Hash one directory entry on Windows: open the entry itself (FILE_FLAG_OPEN_REPARSE_POINT -- a
/// reparse point is opened as itself, never its target) and classify on that handle BEFORE any
/// read: a cloud placeholder or offline file is counted unreadable (a read would recall it over
/// the network, which the deadline cannot interrupt); a name-surrogate reparse point (symlink,
/// junction) is a link; a WOF or Dedup file is hashed through a handle reopened WITHOUT the reparse
/// flag, so the filter serves real data; any other tag is counted unreadable. Nothing is ever read
/// through the reparse-point handle itself. The no-follow is LEAF-ONLY: an ancestor directory
/// swapped for a junction after enumeration is a disclosed residual.
[[nodiscard]] inline HashOutcome hash_entry_win(const fs::directory_entry& entry,
                                                HashBudget& budget, const WalkLimits& limits) {
    constexpr DWORD kShare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    yuzu::agent::confined_fs::WinHandle file{
        CreateFileW(entry.path().c_str(), GENERIC_READ, kShare, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (!file.valid())
        return {HashKind::unreadable, {}, 0};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.get(), &info))
        return {HashKind::unreadable, {}, 0};
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS |
                                 FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_OFFLINE))
        return {HashKind::unreadable, {}, 0};
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag)))
            return {HashKind::unreadable, {}, 0};
        if (IsReparseTagNameSurrogate(tag.ReparseTag))
            return {HashKind::symlink, {}, 0};
        if (tag.ReparseTag != detail::kReparseTagWof && tag.ReparseTag != detail::kReparseTagDedup)
            return {HashKind::unreadable, {}, 0};
        yuzu::agent::confined_fs::WinHandle data{
            ReOpenFile(file.get(), GENERIC_READ, kShare, FILE_FLAG_SEQUENTIAL_SCAN)};
        if (!data.valid() || !GetFileInformationByHandle(data.get(), &info))
            return {HashKind::unreadable, {}, 0};
        file = std::move(data);
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        GetFileType(file.get()) != FILE_TYPE_DISK)
        return {HashKind::not_regular, {}, 0};
    const std::uintmax_t size =
        (static_cast<std::uintmax_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (size > limits.max_file_bytes)
        return {HashKind::oversize, {}, 0};
    if (size > budget.remaining())
        return {HashKind::over_budget, {}, 0};

    detail::BcryptSha256 sha;
    if (!sha.ok)
        return {HashKind::unreadable, {}, 0};
    std::vector<unsigned char> buf(kHashChunk);
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(file.get(), buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr))
            return {HashKind::unreadable, {}, 0};
        if (n == 0)
            break;
        if (!budget.consume(n))
            return {HashKind::stopped, {}, 0};
        if (!sha.update(buf.data(), n))
            return {HashKind::unreadable, {}, 0};
    }
    std::string hex;
    if (!sha.finish(hex))
        return {HashKind::unreadable, {}, 0};
    return {HashKind::hashed, std::move(hex), size};
}

#endif // _WIN32

} // namespace yuzu::filesystem::find_by_hash
