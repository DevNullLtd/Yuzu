#pragma once
/// @file proc_access.hpp
/// WP13 governance UP14. A non-root agent that does not hold CAP_SYS_PTRACE cannot read
/// /proc/<pid>/exe or /proc/<pid>/fd of another user's processes: readlink/opendir fail with
/// EACCES. The /proc walkers (processes, procfetch, netstat) skipped those silently and still
/// reported a clean result, so a dev/UAT agent that lost the file capability (or the packaged
/// unit, which never had it) returned a partial list as `OK`. This tally lets each walker count
/// the permission refusals (and ONLY those: ENOENT/ESRCH are ordinary process churn and kernel
/// threads) so it can declare CONSTRAINED/PARTIAL honestly.
///
/// Pure + header-only; the single syscall helper is POSIX-only and failure-path only.

#include <cerrno>
#include <cstddef>

#if defined(__linux__)
#include <unistd.h>
#include <string>
#endif

namespace yuzu::shared {

/// True for an errno that means "the kernel refused this caller", not "the process is gone".
[[nodiscard]] constexpr bool proc_access_refused(int err) noexcept {
    return err == EACCES || err == EPERM;
}

struct ProcAccessTally {
    std::size_t refused{0};
    void note(int err) noexcept {
        if (proc_access_refused(err))
            ++refused;
    }
    [[nodiscard]] bool constrained() const noexcept { return refused != 0; }
};

#if defined(__linux__)
/// Call AFTER a /proc/<pid>/exe readlink failed (empty result): re-reads the failure's errno
/// from a second readlink so the walkers keep their existing helper signatures.
inline void note_exe_failure(ProcAccessTally& tally, unsigned long pid) {
    char buf[8];
    const std::string link = "/proc/" + std::to_string(pid) + "/exe";
    errno = 0;
    if (::readlink(link.c_str(), buf, sizeof(buf)) < 0)
        tally.note(errno);
}
#endif

} // namespace yuzu::shared
