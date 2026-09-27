/**
 * system_hardening_linux.cpp -- Linux leg: the allowlisted /proc/sys reads.
 *
 * SHAPE, NOT A COPY, of vuln_scan's config_checks.hpp:73-80 read_proc_value
 * (single path). That helper returns {} for ENOENT, EACCES and every other
 * failure alike; a posture plugin must not, so this reader uses
 * ::open(O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW|O_NOCTTY) + ::fstat + ::read and hands
 * the captured errno back to the pure collect loop (system_hardening_parsers.hpp),
 * which classifies it. Only a successful read of a REGULAR file yields a value:
 * O_NONBLOCK makes a FIFO or device mounted at an allowlisted path return from
 * open() at once, and opened_leaf_error() refuses to read anything fstat() does
 * not report as a regular file (`<key>:not_regular`), so a FIFO or device cannot
 * pin an agent worker or put device bytes in a row (O_NOCTTY keeps a tty from
 * becoming the agent's controlling terminal). A filesystem that never answers
 * (an unresponsive FUSE daemon, a stale hard NFS mount) mounted at or below
 * /proc/sys can still block open/statfs/read: that needs root or CAP_SYS_ADMIN in
 * the agent's mount namespace, and no in-plugin bound can cancel a hung syscall --
 * it is a platform-level per-command deadline concern. No shell, no sysctl binary, no
 * directory walk: the key -> path table is kLinuxAllowlist.
 *
 * A leaf ENOENT is only trusted as genuine absence when the nearest existing directory
 * above it (up to /proc/sys) is confirmed to be a procfs mount (surface_is_procfs, the
 * pure walk, over the real statfs below) -- otherwise it is remapped to ENODEV before it
 * reaches the pure layer (remap_enoent_for_surface), so a runtime that hides or
 * replaces /proc/sys or a subtree of it (ProcSubset=pid, a tmpfs overmount, a container or
 * chroot that does not expose it) never reports a clean absent/OK for hardening it never
 * probed. Same rule as the sibling platform_security plugin's efivarfs/securityfs
 * check. These eleven keys are kernel-global (not namespaced), so a containerised agent reads
 * the kernel the agent runs on: the host's for a shared-kernel runtime (runc), the guest
 * kernel's under Kata or a microVM, and gVisor's synthetic procfs (which reports the procfs
 * magic but implements only some of the keys; the rest read `absent`).
 */
#include "system_hardening_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::system_hardening {

namespace {

// The pure classifier keeps the POSIX file-type bits as plain numbers; pin them to the system's.
static_assert(static_cast<std::uint32_t>(S_IFMT) == kModeTypeMask);
static_assert(static_cast<std::uint32_t>(S_IFREG) == kModeRegular);

// A /proc/sys integer is a handful of bytes; anything longer is not a value
// this table models (it maps to `unmodelled`, not a failure).
constexpr std::size_t kMaxValueBytes = 256;

// The real statfs for surface_is_procfs; errno is read immediately after the failing call.
StatfsOutcome statfs_dir(const std::string& dir) {
    struct statfs buf {};
    if (::statfs(dir.c_str(), &buf) == 0) return {0, 0, static_cast<std::uint64_t>(buf.f_type)};
    return {-1, errno, 0};
}

ReadOutcome read_proc_sys(std::string_view path) {
    const std::string p{path};
    int raw;
    do {
        raw = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY);
    } while (raw < 0 && errno == EINTR);
    if (raw < 0) {
        const int open_errno = errno; // captured before the statfs probe can touch errno
        const SurfaceCheck surface =
            open_errno == ENOENT ? surface_is_procfs(path, statfs_dir) : SurfaceCheck{};
        return {resolve_leaf_errno(open_errno, surface), 0, {}};
    }
    yuzu::agent::ScopedFd fd(raw);

    struct stat st {};
    if (::fstat(fd.get(), &st) != 0) {
        const int stat_errno = errno; // captured before the owner closes the fd on return
        return {stat_errno, 0, {}};
    }
    if (const int err = opened_leaf_error(static_cast<std::uint32_t>(st.st_mode)); err != 0)
        return {err, 0, {}};

    char buf[kMaxValueBytes];
    ssize_t n;
    do {
        n = ::read(fd.get(), buf, sizeof buf);
    } while (n < 0 && errno == EINTR);
    const int read_errno = (n < 0) ? errno : 0; // captured before the owner closes the fd on return
    if (n < 0) return {read_errno, 0, {}};
    return {0, 0, std::string(buf, static_cast<std::size_t>(n))};
}

} // namespace

int collect_posture_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(read_proc_sys, acc);
    emit_posture(ctx, rows, acc);
    return 0;
}

} // namespace yuzu::system_hardening

#endif // defined(__linux__)
