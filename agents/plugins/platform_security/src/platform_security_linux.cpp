/**
 * platform_security_linux.cpp -- Linux leg: the efivarfs Secure Boot reads and
 * the securityfs LSM / lockdown reads (rung 1, no spawn).
 *
 * Every file read goes through ONE errno-capturing reader (read_file); the
 * pure loops in platform_security_parsers.hpp classify the errno (ENOENT ->
 * `absent`, no token; EACCES/EPERM -> `unreadable` + `:eacces`; other errno ->
 * `unreadable` + `:errno_<n>`). Paths are the constexpr tables in the parsers
 * header: the actions take no parameters, so no request text reaches a path.
 * efivarfs must be read from offset 0 into a buffer holding the whole
 * variable, so the reader loops read() into one bounded buffer; a file that
 * fills it is EFBIG (unreadable, never truncated into a value).
 *
 * A leaf ENOENT is only trusted as genuine absence when the PARENT pseudo-
 * filesystem (efivarfs / securityfs) is confirmed mounted via statfs's magic
 * number first (PR #4792 review, fjarvis) -- otherwise it's remapped to
 * ENODEV (`unreadable` + `:errno_19`) before it ever reaches the pure layer,
 * so a container running with neither mounted (a real, shipped deployment
 * path) never reports a clean absent/OK for a posture that was never
 * actually probed.
 */
#include "platform_security_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::platform_security {

namespace {

constexpr std::size_t kMaxFileBytes = 4096;

// linux/magic.h's ABI-stable pseudo-filesystem magic numbers, not included
// directly to avoid a kernel-header build dependency this TU otherwise has no
// need for.
constexpr decltype(std::declval<struct statfs>().f_type) kEfivarfsMagic = 0xde5e81e4;
constexpr decltype(std::declval<struct statfs>().f_type) kSecurityfsMagic = 0x73636673;

// True iff `dir` is currently mounted as the pseudo-filesystem carrying
// `expected_magic`. False on ANY statfs failure -- including the directory
// not existing at all -- never guessed true.
bool mount_matches(const char* dir, decltype(std::declval<struct statfs>().f_type) expected_magic) {
    struct statfs buf {};
    if (::statfs(dir, &buf) != 0) return false;
    return buf.f_type == expected_magic;
}

bool dir_exists(const char* dir) {
    struct stat st {};
    return ::stat(dir, &st) == 0;
}

// True iff a leaf ENOENT under `path` should be remapped to "surface
// unavailable" (ENODEV) rather than trusted as genuine absence.
//
// securityfs: one check suffices -- securityfs is kernel infrastructure with
// no hardware precondition, so `/sys/kernel/security` either IS securityfs
// (mounted) or it isn't; an unprivileged container leaves the directory
// present but backed by the outer sysfs mount (confirmed empirically:
// `stat -f` reports `Type: sysfs`, not `securityfs`, there), which
// `mount_matches` alone correctly catches.
//
// efivarfs needs a SECOND, prior check: `/sys/firmware/efi` not existing at
// all means genuinely non-UEFI firmware (a real, legitimate absence -- e.g.
// a BIOS/CSM-booted VM, the documented case this plugin's own fixture
// captures) and must NOT be reclassified. Only when `/sys/firmware/efi`
// exists (real UEFI firmware) but `/sys/firmware/efi/efivars` is not itself
// mounted as efivarfs is the surface unavailable, not absent -- exactly the
// container scenario PR #4792's own review (fjarvis, 5289352195, HIGH)
// found: this plugin's real Linux sample capture reported all four rows
// absent/OK/FULL on a host whose actual posture was never probed.
//
// KNOWN RESIDUAL GAP (fjarvis, review re-verification, same PR): a default
// container's /sys tree omits /sys/firmware/efi ENTIRELY, regardless of
// whether the underlying host is real UEFI -- so `dir_exists` above returns
// false there even on a genuine Secure-Boot host, and secure_boot/setup_mode
// still read absent/OK/FULL uncorrected. This is NOT fixable by more source
// logic here (there is no way to distinguish the two cases from inside the
// container's own /sys namespace); it needs deploy/docker/Dockerfile.agent
// (or the operator's own container config) to bind-mount /sys/firmware/efi
// read-only into the container. Documented in the README's "Caveats and
// known gaps" -- do not consider this row's ENOENT-vs-mount handling fully
// closed for secure_boot until that deploy-side gap is addressed too.
bool surface_unavailable(std::string_view path) {
    if (path.starts_with("/sys/firmware/efi/efivars/"))
        return dir_exists("/sys/firmware/efi") &&
               !mount_matches("/sys/firmware/efi/efivars", kEfivarfsMagic);
    return !mount_matches("/sys/kernel/security", kSecurityfsMagic);
}

ReadOutcome read_file(std::string_view path) {
    const std::string p{path};
    int raw;
    do {
        raw = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    } while (raw < 0 && errno == EINTR);
    if (raw < 0) {
        const int open_errno = errno; // capture before the mount probes' own syscalls touch errno
        if (open_errno == ENOENT && surface_unavailable(path)) return {ENODEV, {}};
        return {open_errno, {}};
    }
    yuzu::agent::ScopedFd fd(raw);

    std::string data;
    char buf[kMaxFileBytes];
    for (ssize_t n = 1; n != 0;) {
        do {
            n = ::read(fd.get(), buf, sizeof buf);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return {errno, {}}; // evaluated before the owner closes the fd on return
        data.append(buf, static_cast<std::size_t>(n));
        if (data.size() >= kMaxFileBytes) return {EFBIG, {}};
    }
    return {0, std::move(data)};
}

} // namespace

int collect_secure_boot_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    emit_rows(ctx, secure_boot_rows_linux(read_file, acc), acc);
    return 0;
}

int collect_code_integrity_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    emit_rows(ctx, code_integrity_rows_linux(read_file, acc), acc);
    return 0;
}

} // namespace yuzu::platform_security

#endif // defined(__linux__)
