#pragma once

/**
 * asset_tags_store.hpp — state-file I/O for the asset_tags plugin (#232).
 *
 * Header-only and logger-free: both functions return std::expected, so the
 * persistence lifecycle (create, replace, no leftover temp, POSIX 0600,
 * failure path, restart reload) is unit-testable without loading the plugin.
 * The pure (de)serialisation lives in asset_tags_parsers.hpp.
 *
 * Write path (adversarial-review round 1, F1): sibling
 * `<dest>.tmp.<16 hex>`, the suffix a process-unique random value from
 * `detail::temp_suffix()` (mirrors agents/core/src/agent_csr.cpp's
 * random_suffix() and agents/shared/win_reg_handle.hpp's
 * unique_hive_mount_name() — neither is reachable from a plugin, so this is a
 * deliberate third copy of the small idiom rather than a new agents/shared
 * primitive). The temp is created EXCLUSIVELY: POSIX opens it with
 * O_CREAT|O_EXCL|O_NOFOLLOW at mode 0600 directly (no ofstream, no separate
 * chmod-after-open window — under a normal umask the file is 0600 from the
 * instant it exists; an unusual umask can only narrow that, never widen it,
 * which is what the fchmod re-tightening below is for); Windows opens it
 * with `std::ios::noreplace` (C++23 P2467R1; CREATE_NEW semantics). Either
 * way, a file already at the exclusive-create temp path — planted or left
 * over — makes the create FAIL, rather than being followed or overwritten.
 * The guard that removes the temp on a later failure is armed only AFTER
 * that exclusive create succeeds, so a failed create (because something is
 * already there) never deletes a path this process did not create. Once
 * written, the temp is renamed over `dest`.
 *
 * Permissions: on POSIX the exclusive create already leaves the temp at
 * 0600; it is re-tightened once more, via `fchmod` on the still-open fd
 * before it closes (adversarial-review round 2, F1 — the mode step is now
 * fd-bound, not addressed by path, so it cannot race a writer that has
 * already unlinked and replanted the temp's path), purely so the on-disk
 * mode stays deterministic under an unusual umask, mirroring
 * agent_csr.cpp's write_private_key. A failure here is reported as a
 * WriteWarning but does not block persistence. The Windows DACL is not
 * tightened here at all — a narrower gap than agent_csr.cpp's
 * write_private_key, which at least makes the same (Windows-ineffective)
 * fs::permissions call agent_csr.cpp does; both are the same open,
 * documented follow-up in practice, since neither actually restricts the
 * Windows ACL.
 *
 * Residual: after the fd closes, the rename below still addresses the temp
 * by path (`fs::rename(tmp, dest)`), so a writer already inside the agent's
 * private data directory can race it — unlink the temp and replant
 * something else at that exact path before the rename resolves it. Bounded:
 * the payload this process wrote is never corrupted, no partially-written
 * file ever lands at `dest`, and the next successful sync's write self-heals
 * it. Tracked, together with the identical shape in agent_csr.cpp's write
 * helpers and a related unverified Windows dangling-symlink CREATE_NEW
 * question, in #4723 — not fixed here.
 */

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
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
#endif

namespace yuzu::asset_tags {

/// A failed read or write; `message` is human-readable and names the path.
struct IoError {
    std::string message;
};

/// A non-fatal condition attached to a SUCCESSFUL write (the file was
/// replaced): today only the POSIX chmod-to-0600 failure.
struct WriteWarning {
    std::string message;
};

namespace detail {

/// A process-unique, cross-process-unpredictable 16-hex-digit suffix for a
/// staging temp name: a one-time random_device base (seeded once — no
/// per-call random_device fd churn) XORed with a monotonic atomic counter.
/// Unique within the process and unpredictable across processes, without
/// depending solely on random_device entropy (which can degrade on some
/// virtualised hosts). Mirrors agents/core/src/agent_csr.cpp's
/// random_suffix() and agents/shared/win_reg_handle.hpp's
/// unique_hive_mount_name() byte for byte; neither is reachable from a
/// plugin (agents/core isn't linked into plugins; win_reg_handle.hpp is
/// Windows-registry-specific), so this is a small, deliberate third copy —
/// promoting the idiom into agents/shared is a separate-PR primitive.
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
    explicit TempFileGuard(std::filesystem::path p) : path_(std::move(p)) {}
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
    std::filesystem::path path_;
    bool armed_{true};
};

} // namespace detail

/// Read the state file. A missing file is a normal first run: returns an
/// engaged expected holding nullopt. An unreadable file (or a non-regular
/// path) is an IoError.
[[nodiscard]] inline std::expected<std::optional<std::string>, IoError>
read_state_file(const std::filesystem::path& p) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const auto st = fs::status(p, ec);
    if (st.type() == fs::file_type::not_found)
        return std::nullopt;
    if (ec)
        return std::unexpected(IoError{"cannot stat " + p.string() + ": " + ec.message()});
    if (!fs::is_regular_file(st))
        return std::unexpected(IoError{p.string() + ": not a regular file"});

    std::ifstream f(p, std::ios::binary);
    if (!f)
        return std::unexpected(IoError{"cannot open " + p.string() + " for reading"});
    std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (f.bad())
        return std::unexpected(IoError{"read error on " + p.string()});
    return content;
}

/// Atomically replace `dest` with `bytes` (exclusive-create temp + rename).
/// On success the value is an optional WriteWarning (engaged only when the
/// POSIX chmod-to-0600 re-assertion failed; the file was still replaced).
/// The temp is created EXCLUSIVELY at a random, unpredictable sibling name
/// (detail::temp_suffix()) — a pre-existing file at that path, planted or
/// left over, fails the create instead of being followed or overwritten —
/// and never outlives a failure. The post-create rename is by path; see the
/// class comment above for that residual window.
///
/// `forced_temp_suffix` is a TEST SEAM ONLY: empty (the default, and the only
/// value any production caller passes) means the real unpredictable
/// `detail::temp_suffix()`; a non-empty value is used verbatim so a test can
/// plant something at the exact path the write will open. The suffix's
/// unpredictability is not itself the security boundary — the boundary is
/// `O_CREAT|O_EXCL|O_NOFOLLOW` (or Windows `std::ios::noreplace`) refusing to
/// follow or overwrite whatever is already there, forced path or not.
[[nodiscard]] inline std::expected<std::optional<WriteWarning>, IoError>
write_state_file_atomic(const std::filesystem::path& dest, std::string_view bytes,
                         std::string_view forced_temp_suffix = {}) {
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
    tmp += forced_temp_suffix.empty() ? detail::temp_suffix() : std::string(forced_temp_suffix);

    // Armed only once the exclusive create below has actually created this
    // file — see the class comment.
    std::optional<detail::TempFileGuard> temp_guard;

    // Engaged only when the POSIX chmod-to-0600 re-assertion below failed;
    // the file is still replaced. Declared here (rather than after the
    // platform block) so the POSIX block below can set it on the open fd,
    // before the fd closes and the temp can only be addressed by path.
    std::optional<WriteWarning> warning;

#ifndef _WIN32
    {
        const int fd =
            ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0)
            return std::unexpected(
                IoError{"cannot create " + tmp.string() + ": " + std::strerror(errno)});
        temp_guard.emplace(tmp);

        const char* p = bytes.data();
        std::size_t remaining = bytes.size();
        bool ok = true;
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
        // Re-assert 0600 on the still-open fd, before close: the exclusive
        // create above already left the temp at 0600, but re-tightening here
        // (rather than by path after close) keeps the mode step fd-bound, so
        // it cannot race a writer that has already unlinked and replanted the
        // temp's path (adversarial-review round 2, F1). A failure here is a
        // warning, not a write failure — the file is still replaced.
        if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0)
            warning = WriteWarning{"could not restrict " + tmp.string() + " to 0600: " +
                                    std::strerror(errno)};
        if (::close(fd) != 0)
            ok = false;
        if (!ok)
            return std::unexpected(IoError{"write to " + tmp.string() + " failed"});
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
#endif

    std::error_code rename_ec;
    fs::rename(tmp, dest, rename_ec);
    if (rename_ec)
        return std::unexpected(IoError{"cannot rename " + tmp.string() + " over " + dest.string() +
                                       ": " + rename_ec.message()});
    temp_guard->dismiss();
    return warning;
}

} // namespace yuzu::asset_tags
