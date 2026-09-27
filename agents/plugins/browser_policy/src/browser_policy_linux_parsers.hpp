/**
 * browser_policy_linux_parsers.hpp — INJECTED-ROOT Linux policy walk, plus
 * this plugin's private POSIX secure-read kit (namespace `posix`).
 *
 * The boundary (peripherals_linux_parsers.hpp is the precedent): every
 * filesystem access is relative to a `root` path parameter. Production
 * (browser_policy_linux.cpp) passes "/"; the unit suite passes a temp tree
 * materialized from tests/unit/fixtures/wave10/browser_policy/linux/
 * tree.manifest.
 *
 * WALK SAFETY. The policy directories are root-owned in production, but the
 * walk still refuses to be redirected: every component below the root is
 * opened with openat(O_NOFOLLOW|O_DIRECTORY) chained from the previous
 * component's fd (the hop-by-hop shape of autoruns_macos.cpp's
 * open_dir_no_follow_at_checked / collect_user_launchagents — a single
 * open() on a joined path would let the kernel resolve intermediate
 * components through symlinks), and each policy file is opened O_NOFOLLOW|
 * O_NONBLOCK and required to be a regular file (a FIFO can never block the
 * leg). Only the root itself is opened following symlinks (so an injected
 * root such as /tmp -> /private/tmp works). Directory enumeration is
 * yuzu::shared::walk_dir_capped (directory_iterator is deliberately not
 * used: it follows symlinks).
 *
 * ABSENT vs FAILED. ENOENT at any hop is a genuinely absent policy set
 * (browser not installed) — zero rows, no failure. Any other errno
 * (permission denied, a refused symlink, a non-directory component, an
 * unreadable / oversized / unparseable file) is recorded on the shared
 * ConstraintAccumulator and surfaces as CONSTRAINED: a failure never reads
 * as absent. Rows from the parts that DID read are kept.
 *
 * POSIX-only (posix_dir_walk.hpp does not exist on Windows): the whole header
 * is `#if !defined(_WIN32)`; the portable row parsing lives in
 * browser_policy_parsers.hpp and is tested on every OS. Namespace `lnx`, not
 * `linux` (a predefined macro under GNU extension modes).
 */
#pragma once

#if !defined(_WIN32)

#include "browser_policy_legs.hpp" // run_linux_at wires rows + status onto a CommandContext
#include "browser_policy_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::browser_policy {

namespace posix {

using Fd = yuzu::agent::ScopedFd; // the shared move-only fd owner (close on destruct, release())

/// Move-only owner of one DIR* (closedir also closes the underlying fd).
class Dir {
public:
    Dir() noexcept = default;
    explicit Dir(DIR* d) noexcept : d_(d) {}
    ~Dir() {
        if (d_ != nullptr)
            ::closedir(d_);
    }
    Dir(const Dir&) = delete;
    Dir& operator=(const Dir&) = delete;
    Dir(Dir&& o) noexcept : d_(std::exchange(o.d_, nullptr)) {}
    Dir& operator=(Dir&& o) noexcept {
        if (this != &o) {
            if (d_ != nullptr)
                ::closedir(d_);
            d_ = std::exchange(o.d_, nullptr);
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return d_; }
    [[nodiscard]] int fd() const noexcept { return d_ != nullptr ? ::dirfd(d_) : -1; }

private:
    DIR* d_ = nullptr;
};

enum class OpenStatus { ok, absent, failed };

/// `errno` from a failed open/openat/fdopendir -> a stable reason detail
/// (callers prefix the OS, e.g. `linux:`). Only called for a real
/// failure (ENOENT is `absent`, never routed here).
[[nodiscard]] constexpr std::string_view errno_detail(int err) noexcept {
    switch (err) {
    case EACCES:
    case EPERM:   return "permission_denied";
    case ELOOP:   return "symlink_refused";
    case ENOTDIR: return "not_a_directory";
    default:      return "open_failed";
    }
}

struct DirOpen {
    Dir dir;
    OpenStatus status = OpenStatus::absent;
    std::string_view detail{};
};

/// Turns the result of an `open`/`openat(O_DIRECTORY)` into a `DirOpen`. `open_errno` is the
/// errno of THAT call (captured by the caller before anything else can clobber it). On success
/// the fd is handed to `fdopendir`, which adopts it only if it succeeds; on failure `fd` is still
/// owned by the guard, so it is closed exactly once by its destructor and never by hand.
[[nodiscard]] inline DirOpen dir_from_fd(Fd fd, int open_errno) {
    int err = open_errno;
    if (fd.valid()) {
        if (DIR* d = ::fdopendir(fd.get()); d != nullptr) {
            Dir dir{d};                      // name the new owner before giving the old one up
            (void)fd.release();              // closedir() closes the fd from here on
            return DirOpen{std::move(dir), OpenStatus::ok, {}};
        }
        err = errno; // read before ~Fd's close() can overwrite it
    }
    if (err == ENOENT)
        return DirOpen{Dir{}, OpenStatus::absent, {}};
    return DirOpen{Dir{}, OpenStatus::failed, errno_detail(err)};
}

/// The injected root itself: opened WITHOUT O_NOFOLLOW (a caller-supplied
/// root such as /tmp may legitimately be a symlink).
[[nodiscard]] inline DirOpen open_root_dir(const std::filesystem::path& root) {
    Fd fd{::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    return dir_from_fd(std::move(fd), errno);
}

/// One component, never following a symlink. `O_DIRECTORY|O_NOFOLLOW` on a symlink fails with
/// ENOTDIR (not ELOOP) on Linux and macOS alike, which would report a refused symlink as "not a
/// directory"; a failed open with ENOTDIR is therefore looked at once more (`fstatat` without
/// following) so a symlinked directory is reported as what it is.
[[nodiscard]] inline DirOpen open_dir_at(int parent_fd, const char* name) {
    Fd fd{::openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    int err = errno;
    if (!fd.valid() && err == ENOTDIR) {
        struct stat st{};
        if (::fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode))
            return DirOpen{Dir{}, OpenStatus::failed, "symlink_refused"};
    }
    return dir_from_fd(std::move(fd), err);
}

/// Hop-by-hop chain of open_dir_at from `parent_fd`; stops at the first hop
/// that is not `ok` and returns its status. `parts` must be non-empty.
[[nodiscard]] inline DirOpen open_dir_chain(int parent_fd, std::span<const char* const> parts) {
    DirOpen cur;
    int fd = parent_fd;
    for (const char* part : parts) {
        DirOpen next = open_dir_at(fd, part);
        if (next.status != OpenStatus::ok)
            return next;
        cur = std::move(next);
        fd = cur.dir.fd();
    }
    return cur;
}

struct FileRead {
    OpenStatus status = OpenStatus::absent;
    std::string_view detail{};
    std::string bytes;
};

/// Reads one regular file below `dir_fd`, never following a symlink at the
/// leaf, bounded to `cap` bytes. Oversized is a FAILURE ("oversized"), never
/// a truncated read that would then fail to parse for the wrong reason. The
/// read runs to EOF rather than to the fstat size: a file that grows between
/// fstat and read must not surface as a valid prefix (a two-byte `{}` that
/// became `{}garbage` would otherwise read as an empty policy set instead of
/// `json_unparseable`), and growth past `cap` is `oversized`.
[[nodiscard]] inline FileRead read_file_at(int dir_fd, const char* name,
                                           std::size_t cap = kMaxPolicyFileBytes) {
    FileRead out;
    Fd fd{::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
    if (!fd.valid()) {
        const int err = errno;
        if (err == ENOENT)
            return out; // raced deletion / genuinely absent
        out.status = OpenStatus::failed;
        out.detail = errno_detail(err);
        return out;
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
        out.status = OpenStatus::failed;
        out.detail = "stat_failed";
        return out;
    }
    if (!S_ISREG(st.st_mode)) {
        out.status = OpenStatus::failed;
        out.detail = "not_regular";
        return out;
    }
    if (static_cast<std::uintmax_t>(st.st_size) > cap) {
        out.status = OpenStatus::failed;
        out.detail = "oversized";
        return out;
    }
    std::array<char, 16384> chunk{};
    for (;;) {
        const ssize_t n = ::read(fd.get(), chunk.data(), chunk.size());
        if (n < 0) {
            if (errno == EINTR)
                continue;
            out.status = OpenStatus::failed;
            out.detail = "read_failed";
            out.bytes.clear();
            return out;
        }
        if (n == 0)
            break;
        if (out.bytes.size() + static_cast<std::size_t>(n) > cap) {
            out.status = OpenStatus::failed;
            out.detail = "oversized";
            out.bytes.clear();
            return out;
        }
        out.bytes.append(chunk.data(), static_cast<std::size_t>(n));
    }
    out.status = OpenStatus::ok;
    return out;
}

/// Names in an open directory selected by `keep(name)`, sorted so the row
/// order never depends on readdir order. Records an entry-cap truncation
/// (`<prefix>:entry_cap`: the directory holds more entries than the cap —
/// distinct from the per-leg `row_cap`) and real readdir errors
/// (`<prefix>:readdir_error`) on `acc`.
template <typename Keep>
[[nodiscard]] std::vector<std::string> list_names(const Dir& dir, Keep&& keep,
                                                  yuzu::shared::ConstraintAccumulator& acc,
                                                  std::string_view prefix,
                                                  std::size_t max_entries = kMaxEntriesPerDir) {
    std::vector<std::string> names;
    const auto walk = yuzu::shared::walk_dir_capped(
        dir.get(), max_entries, [&](const struct dirent* entry) {
            if (keep(entry))
                names.emplace_back(entry->d_name);
            return true;
        });
    if (walk.truncated)
        acc.add_failure(std::string{prefix} + ":entry_cap");
    if (walk.enumeration_error)
        acc.add_failure(std::string{prefix} + ":readdir_error");
    std::sort(names.begin(), names.end());
    // A directory rewritten while it is listed can return an entry twice; one file is one file.
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

} // namespace posix

namespace lnx {

/// One vendor's policy directory: /etc/<parts...>/policies/{managed,recommended}.
struct VendorDir {
    Browser browser;
    std::array<const char*, 2> parts; // components below <root>/etc
    std::size_t n;                    // how many of `parts` are used
};

inline constexpr VendorDir kVendorDirs[] = {
    {Browser::chrome, {"opt", "chrome"}, 2},
    {Browser::chromium, {"chromium", nullptr}, 1},
    {Browser::edge, {"opt", "edge"}, 2},
};
static_assert(
    [] {
        for (const auto& v : kVendorDirs) {
            if (v.n == 0 || v.n > v.parts.size())
                return false;
            for (std::size_t i = 0; i < v.n; ++i)
                if (v.parts[i] == nullptr)
                    return false; // a used component is never the nullptr filler
        }
        return true;
    }(),
    "every VendorDir uses 1..parts.size() non-null components");

/// `linux:<detail>` — the failure-token spelling every leg failure shares.
[[nodiscard]] inline std::string linux_token(std::string_view detail) {
    return std::string{"linux:"} + std::string{detail};
}

struct LevelDir {
    Level level;
    const char* dir;
};

inline constexpr LevelDir kLevelDirs[] = {
    {Level::mandatory, "managed"},
    {Level::recommended, "recommended"},
};

/// Walks <root>/etc/{opt/chrome,chromium,opt/edge}/policies/{managed,
/// recommended}/*.json and returns one formatted `policy|` row per policy
/// key. `failure_reason` is set (comma-joined `linux:<detail>` tokens) iff
/// any directory, file or value could not be read/decoded; empty means the
/// read was complete (possibly with zero rows: nothing managed).
[[nodiscard]] inline std::vector<std::string>
linux_policy_rows_at(const std::filesystem::path& root, std::string& failure_reason,
                     const WalkLimits& limits = {}) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    std::size_t total_bytes = 0; // policy-file content read so far, against limits.max_total_bytes
    failure_reason.clear();

    auto finish = [&]() {
        failure_reason = acc.reason();
        return std::move(rows); // every caller returns straight after: hand the vector over, not a copy
    };

    posix::DirOpen root_open = posix::open_root_dir(root);
    if (root_open.status == posix::OpenStatus::absent)
        return finish(); // no such root: nothing managed
    if (root_open.status == posix::OpenStatus::failed) {
        acc.add_failure(linux_token(root_open.detail));
        return finish();
    }

    for (const auto& vendor : kVendorDirs) {
        std::vector<const char*> chain{"etc"};
        for (std::size_t i = 0; i < vendor.n; ++i)
            chain.push_back(vendor.parts[i]);
        chain.push_back("policies");
        // The display prefix is derived from the SAME chain the openat walk
        // follows, so the two cannot diverge.
        std::string base;
        for (const char* part : chain) {
            base += '/';
            base += part;
        }
        base += '/';

        posix::DirOpen policies = posix::open_dir_chain(root_open.dir.fd(), chain);
        if (policies.status == posix::OpenStatus::failed)
            acc.add_failure(linux_token(policies.detail));
        if (policies.status != posix::OpenStatus::ok)
            continue;

        for (const auto& lvl : kLevelDirs) {
            posix::DirOpen level_dir = posix::open_dir_at(policies.dir.fd(), lvl.dir);
            if (level_dir.status == posix::OpenStatus::failed)
                acc.add_failure(linux_token(level_dir.detail));
            if (level_dir.status != posix::OpenStatus::ok)
                continue;

            const auto names = posix::list_names(
                level_dir.dir,
                [](const struct dirent* e) { return std::string_view{e->d_name}.ends_with(".json"); }, acc,
                "linux", limits.max_entries_per_dir);
            for (const auto& fname : names) {
                auto file = posix::read_file_at(level_dir.dir.fd(), fname.c_str(),
                                                limits.max_file_bytes);
                if (file.status == posix::OpenStatus::absent)
                    continue;
                if (file.status == posix::OpenStatus::failed) {
                    acc.add_failure(linux_token(file.detail));
                    continue;
                }
                // The run's parser input (and, through it, the retained row text) scales with
                // this budget, not with the per-file and per-directory caps (whose product is
                // enormous). The file that crosses it has been read but is not parsed, and the
                // walk stops: rows already read stand, the result is a lower bound.
                total_bytes += file.bytes.size();
                if (total_bytes > limits.max_total_bytes) {
                    acc.add_failure("linux:byte_cap");
                    return finish();
                }
                const std::string source = base + lvl.dir + "/" + fname;
                // Build at most one row past the budget that is left: enough to notice an
                // overrun below, without turning every key of a huge file into a row first.
                // (Saturating: a max_rows of SIZE_MAX must not wrap to "build no rows".)
                const std::size_t rows_left = limits.max_rows - rows.size();
                const std::size_t rows_to_build =
                    rows_left < std::numeric_limits<std::size_t>::max() ? rows_left + 1 : rows_left;
                auto parsed = rows_from_json_policy_text(file.bytes, vendor.browser, lvl.level,
                                                         machine_scope(), source, rows_to_build);
                if (parsed.failure) {
                    acc.add_failure(*parsed.failure);
                    continue;
                }
                for (const auto& row : parsed.rows) {
                    if (rows.size() >= limits.max_rows) {
                        acc.add_failure("linux:row_cap");
                        return finish();
                    }
                    rows.push_back(format_policy_row(row));
                }
            }
        }
    }
    return finish();
}

} // namespace lnx

/// The Linux leg body with the filesystem root injected: run_linux passes
/// "/", the unit suite passes a temp tree through a real CommandContext (via
/// LocalDispatcher) so the failure -> CONSTRAINED/PARTIAL wiring is exercised
/// exactly as production runs it, not re-implemented in the test.
inline int run_linux_at(yuzu::CommandContext& ctx, const std::filesystem::path& root,
                        const WalkLimits& limits = {}) {
    std::string failure_reason;
    const auto rows = lnx::linux_policy_rows_at(root, failure_reason, limits);
    mark_result_read(ctx, failure_reason); // the outcome (status row + typed status) leads the stream
    write_rows(ctx, rows);
    return 0;
}

} // namespace yuzu::browser_policy

#endif // !defined(_WIN32)
