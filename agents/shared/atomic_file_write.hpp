#pragma once

/**
 * atomic_file_write.hpp — one shared atomic file replace (`yuzu::shared`).
 *
 * Promoted from asset_tags_store.hpp (#232) so every agent-side writer shares
 * one audited implementation. Header-only and logger-free: it returns
 * std::expected, so the lifecycle (create, replace, no leftover temp, mode
 * policy, failure path) is unit-testable without loading any plugin.
 *
 * Write path: sibling `<dest>.tmp.<16 hex>`, the suffix a process-unique
 * random value from `detail::temp_suffix()` (same salt scheme as
 * agents/shared/win_reg_handle.hpp's unique_hive_mount_name()). The temp is
 * created EXCLUSIVELY: POSIX opens it with O_CREAT|O_EXCL|O_NOFOLLOW directly (no
 * ofstream, no separate chmod-after-open window); Windows opens it with
 * `std::ios::noreplace` (C++23 P2467R1; CREATE_NEW semantics). Either way, a file already at the
 * exclusive-create temp path — planted or left over — makes the create FAIL,
 * rather than being followed or overwritten. The guard that removes the temp
 * on a later failure is armed only AFTER that exclusive create succeeds, so a
 * failed create never deletes a path this process did not create. Once
 * written, the temp is renamed over `dest`.
 * Missing parent directories of dest are created first (the asset_tags
 * contract; a no-op for callers that validate or create the parent themselves).
 *
 * Creation mode is policy-dependent (AtomicWriteOptions::owner_only_mode):
 *   - true  (default): POSIX creates the temp at 0600 — no umask window — and
 *     re-asserts 0600 via `fchmod` on the still-open fd (fd-bound, so it
 *     cannot race a writer that unlinked and replanted the temp's path), so
 *     the on-disk mode stays deterministic under an unusual umask. A failed
 *     fchmod is a WriteWarning{mode_reassert_failed}, not a write failure: the
 *     file cannot be wider than 0600 (created at 0600 & ~umask), only narrower.
 *   - false: POSIX creates the temp at 0666 (umask applies) — what the
 *     ofstream-based writers produced — and, when dest already exists as a
 *     regular file, carries its rwx bits (0777 mask) onto the open fd before the
 *     first byte is written, so replacing a file never changes its mode. Owner,
 *     group, ACLs, xattrs, hard links, setuid/setgid/sticky and a symlink at
 *     dest are NOT preserved: rename replaces the inode. A failed carry-over is
 *     a WriteWarning{mode_reassert_failed}.
 * On Windows owner_only_mode has no effect: the DACL is not tightened here
 * (documented follow-up).
 *
 * POSIX call order: [fchmod(fd) carry-over of an existing file's rwx bits, when
 * !owner_only_mode] -> write loop -> fchmod(fd) [owner_only_mode] -> fsync(fd)
 * (F_FULLFSYNC, then fsync, on macOS) -> close(fd) -> rename -> open/fsync/close
 * of the parent directory (same flush).
 *   - A failed file fsync is an IoError (#4727 decision: fsync adopted on
 *     POSIX); the temp is removed.
 *   - A failed parent-directory open, fsync or close is a
 *     WriteWarning{dir_fsync_failed}: the rename is complete but durable only
 *     after the next OS flush.
 * Windows has no flush-by-handle through ofstream. Documented residual: a
 * power loss immediately after a reported success can lose the write there.
 *
 * Orphan temps: the orphan sweep is DECLINED (#4727) — deleting `<dest>.tmp.*`
 * siblings this process did not create contradicts TempFileGuard's arming
 * rule. A leftover temp arises from (a) a write failure AND an unlink failure
 * in the same window, or (b) process death (crash, SIGKILL, power loss)
 * between the exclusive create and the rename — no destructor runs. Each such
 * event leaves at most one random-suffixed temp; there is no bound on
 * accumulation across repeated crashes, which is itself the operator signal.
 *
 * Residual: after the fd closes, the rename still addresses the temp by path,
 * so a writer already inside the destination directory can race it — unlink
 * the temp and replant something else before the rename resolves it. Bounded:
 * the payload this process wrote is never corrupted, no partially-written
 * file ever lands at `dest`, and the next successful write self-heals it.
 * #4723 decision: option 3 — accept and document, with ONE shared
 * implementation (asset_tags, agent_csr, filesystem, tags) so the shape cannot
 * diverge. Declined: O_TMPFILE+linkat (Linux-only) and a pre-write directory
 * ownership/mode check (an agents/core data_dir decision, deferred). The
 * Windows dangling-reparse-point CREATE_NEW question stays open under #4723.
 *
 * PosixFdOps / `forced_temp_suffix` are TEST SEAMS ONLY: production callers
 * pass neither. The suffix's unpredictability is not itself the security
 * boundary — the boundary is O_CREAT|O_EXCL|O_NOFOLLOW (or noreplace).
 */

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <win_str.hpp> // NOMINMAX/WIN32_LEAN_AND_MEAN-sanitised <windows.h> (ReplaceFileW)
#endif

namespace yuzu::shared {

/// A failed write; `message` is human-readable and names the path.
struct IoError {
    std::string message;
};

/// A non-fatal condition attached to a SUCCESSFUL write (the file was
/// replaced). Both flags may be set; `message` joins the causes with "; ".
struct WriteWarning {
    std::string message;
    /// fchmod on the open fd failed: the 0600 re-assert (owner_only_mode=true: the file is
    /// never WIDER than 0600, only narrower, even unreadable by the owner) or the existing-dest
    /// mode carry-over (owner_only_mode=false: the file lands at 0666 & ~umask instead of
    /// dest's prior rwx bits)
    bool mode_reassert_failed = false;
    bool dir_fsync_failed = false; ///< rename durable only after the next OS flush
};

#ifndef _WIN32
/// fsync that reaches the medium: on Darwin plain fsync stops at the drive cache, so
/// F_FULLFSYNC is tried first and fsync is the fallback where the volume rejects it (same
/// shape as server/core/src/key_provider.cpp).
inline int durable_fsync(int fd) noexcept {
#ifdef __APPLE__
    if (::fcntl(fd, F_FULLFSYNC) == 0)
        return 0;
#endif
    return ::fsync(fd);
}

/// Syscall seam (#4726): lets a test observe call order and inject failures.
struct PosixFdOps {
    int (*open)(const char*, int, mode_t) = [](const char* p, int f, mode_t m) {
        return ::open(p, f, m);
    };
    int (*fsync)(int) = &durable_fsync;
    int (*fchmod)(int, mode_t) = &::fchmod;
    int (*close)(int) = &::close;
};
inline constexpr PosixFdOps kRealFdOps{};
#else
struct PosixFdOps; // POSIX-only; the pointer in AtomicWriteOptions stays unused here
#endif

struct AtomicWriteOptions {
    bool owner_only_mode = true;           ///< POSIX 0600 (true) vs 0666 under umask (false)
    std::string_view forced_temp_suffix{}; ///< TEST SEAM, POSIX-tested only; empty = random
    const PosixFdOps* fd_ops = nullptr;    ///< TEST SEAM; nullptr = real syscalls
};

namespace detail {

/// A process-unique, cross-process-unpredictable 16-hex-digit suffix for a
/// staging temp name: a one-time random_device base XORed with a monotonic
/// atomic counter, so it is unique within the process and unpredictable
/// across processes without depending solely on random_device entropy.
inline std::string temp_suffix() {
    static constexpr char kHex[] = "0123456789abcdef";
    static const std::uint64_t base = [] {
        std::random_device rd;
        return (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    }();
    static std::atomic<std::uint64_t> counter{0};
    std::uint64_t v = base ^ counter.fetch_add(1, std::memory_order_relaxed);
    std::string s;
    for (int i = 0; i < 16; ++i) {
        s += kHex[v & 0xFU];
        v >>= 4;
    }
    return s;
}

/// Removes the staged temp file on every exit path until dismissed (after
/// the rename has consumed it). Constructed by the caller only AFTER the
/// exclusive create of that path has succeeded — never before: a failed
/// exclusive create means something is already at that path (planted or
/// left over) that this process did not create, and must never be deleted.
class TempFileGuard {
public:
    // Holds a reference, not a copy: constructing the guard right after the exclusive create
    // must not allocate, or a bad_alloc there would orphan the temp the create just made.
    // The caller's tmp outlives the guard.
    explicit TempFileGuard(const std::filesystem::path& p) noexcept : path_(p) {}
    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;
    ~TempFileGuard() {
        if (armed_) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }
    void dismiss() noexcept { armed_ = false; }

private:
    const std::filesystem::path& path_;
    bool armed_{true};
};

#ifndef _WIN32
/// Owns an open descriptor so an allocation that throws between open and the
/// explicit close cannot leak it. close() routes through the injected seam and
/// disowns the fd (the destructor then does nothing).
/// Not yuzu::agent::ScopedFd: agents/shared is a zero-dependency leaf
/// (docs/cpp-conventions.md, 'What belongs in agents/shared/') and cannot
/// include agents/core, and close() must route through the injected PosixFdOps
/// seam so the #4726 ordering test can observe it.
class FdOwner {
public:
    FdOwner(const PosixFdOps& ops, int fd) noexcept : ops_(ops), fd_(fd) {}
    FdOwner(const FdOwner&) = delete;
    FdOwner& operator=(const FdOwner&) = delete;
    ~FdOwner() {
        if (fd_ >= 0)
            ops_.close(fd_);
    }
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] int close() noexcept {
        const int fd = fd_;
        fd_ = -1;
        return ops_.close(fd);
    }

private:
    const PosixFdOps& ops_;
    int fd_;
};
#endif

} // namespace detail

/// Atomically replace `dest` with `bytes` (exclusive-create temp + rename).
/// On success the value is an optional WriteWarning (engaged only when the
/// file was replaced but a hardening step failed — see the banner). The temp is
/// removed on every failure path this process survives (best effort: see the
/// banner for the unlink-failure and process-death orphan sources).
[[nodiscard]] inline std::expected<std::optional<WriteWarning>, IoError>
write_file_atomic(const std::filesystem::path& dest, std::string_view bytes,
                  const AtomicWriteOptions& opts = {}) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const auto parent = dest.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec)
            return std::unexpected(
                IoError{"cannot create directory " + parent.string() + ": " + ec.message()});
        if (!fs::is_directory(parent, ec))
            return std::unexpected(IoError{"not a directory: " + parent.string()});
    }

    fs::path tmp = dest;
    tmp += ".tmp.";
    tmp += opts.forced_temp_suffix.empty() ? detail::temp_suffix()
                                           : std::string(opts.forced_temp_suffix);

    // Armed only once the exclusive create below has actually created this file.
    std::optional<detail::TempFileGuard> temp_guard;

    // Declared before the platform block so the POSIX block can set it on the
    // open fd, before the fd closes and the temp can only be addressed by path.
    std::optional<WriteWarning> warning;

#ifndef _WIN32
    const PosixFdOps& ops = opts.fd_ops ? *opts.fd_ops : kRealFdOps;
    {
        const int raw = ops.open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                                 opts.owner_only_mode ? 0600 : 0666);
        if (raw < 0)
            return std::unexpected(
                IoError{"cannot create " + tmp.string() + ": " + std::strerror(errno)});
        detail::FdOwner file(ops, raw); // before any allocation that can throw
        const int fd = file.get();
        temp_guard.emplace(tmp);

        // owner_only_mode=false replacing an EXISTING regular file: carry its rwx bits onto the
        // temp (fd-bound, before any byte lands) so a 0755 script keeps +x and a 0600 file is not
        // widened to the umask default. See the banner for what is not preserved.
        if (!opts.owner_only_mode) {
            struct stat st{};
            if (::stat(dest.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
                ops.fchmod(fd, st.st_mode & 0777) != 0) {
                warning = WriteWarning{"could not carry the mode of " + dest.string() + " onto " +
                                           tmp.string() + ": " + std::strerror(errno),
                                       true, false};
            }
        }

        const char* p = bytes.data();
        std::size_t remaining = bytes.size();
        bool ok = true;
        std::string fail = "write to " + tmp.string() + " failed";
        while (remaining > 0) {
            const ssize_t n = ::write(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue; // interrupted before any byte written -- retry
                ok = false;
                break;
            }
            if (n == 0) {
                ok = false;
                break;
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
        // Re-assert 0600 on the still-open fd BEFORE the fsync so the mode is persisted
        // with the data (fd-bound, see banner).
        if (ok && opts.owner_only_mode && ops.fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
            warning = WriteWarning{
                "could not restrict " + tmp.string() + " to 0600: " + std::strerror(errno), true,
                false};
        }
        // Flush file data before the rename can publish it (#4727: adopted).
        if (ok && ops.fsync(fd) != 0) {
            ok = false;
            fail = "fsync of " + tmp.string() + " failed: " + std::strerror(errno);
        }
        if (file.close() != 0 && ok) {
            ok = false;
            fail = "close of " + tmp.string() + " failed: " + std::strerror(errno);
        }
        if (!ok)
            return std::unexpected(IoError{std::move(fail)});
    }
#else
    {
        // First use of std::ios::noreplace (P2467R1) in this codebase, and its
        // exclusive-create behavior on real MSVC is unverified from this host (no
        // Windows toolchain available here) -- tracked for real-hardware
        // verification alongside issue #4723's Windows dangling-symlink question.
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc | std::ios::noreplace);
        if (!out)
            return std::unexpected(IoError{"cannot create " + tmp.string() + " for writing"});
        temp_guard.emplace(tmp);

        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.flush();
        out.close();
        if (!out)
            return std::unexpected(IoError{"write to " + tmp.string() + " failed"});
    }
    // fs::rename can fail if dest is open; ReplaceFileW first when it exists (#1681).
    // path::c_str() is the native wchar_t* on Windows: no code-page round trip (XP-2).
    if (fs::exists(dest, ec) &&
        ReplaceFileW(dest.c_str(), tmp.c_str(), nullptr, 0, nullptr, nullptr)) {
        temp_guard->dismiss();
        return warning;
    }
#endif

    std::error_code rename_ec;
    fs::rename(tmp, dest, rename_ec);
    if (rename_ec)
        return std::unexpected(IoError{"cannot rename " + tmp.string() + " over " + dest.string() +
                                       ": " + rename_ec.message()});
    temp_guard->dismiss();

#ifndef _WIN32
    // Make the rename itself durable; failure is a warning, never an error.
    {
        const std::string dir = parent.empty() ? "." : parent.string();
        std::string why;
        const int draw = ops.open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (draw < 0) {
            why = "cannot open " + dir + ": " + std::strerror(errno);
        } else {
            detail::FdOwner dfd(ops, draw);
            if (ops.fsync(dfd.get()) != 0)
                why = "fsync of " + dir + " failed: " + std::strerror(errno);
            if (dfd.close() != 0) {
                if (!why.empty())
                    why += "; ";
                why += "close of " + dir + " failed: " + std::strerror(errno);
            }
        }
        if (!why.empty()) {
            if (!warning)
                warning.emplace();
            if (!warning->message.empty())
                warning->message += "; ";
            warning->message += why;
            warning->dir_fsync_failed = true;
        }
    }
#endif
    return warning;
}

} // namespace yuzu::shared
