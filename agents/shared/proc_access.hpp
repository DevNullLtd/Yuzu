#pragma once
/// @file proc_access.hpp
/// WP13 governance UP14. A non-root agent that does not hold CAP_SYS_PTRACE cannot read
/// /proc/<pid>/exe or /proc/<pid>/fd of another user's processes: readlink/opendir fail with
/// EACCES. The /proc walkers (processes, procfetch, netstat) skipped those silently and still
/// reported a clean result, so a dev/UAT agent that lost the file capability (or the packaged
/// unit, which carries none) returned a partial list as `OK`. This tally lets each walker count
/// the permission refusals (and ONLY those: ENOENT/ESRCH are ordinary process churn) so it can
/// declare CONSTRAINED/PARTIAL honestly. Without CAP_SYS_PTRACE an unprivileged agent gets EACCES
/// for nearly every /proc/<pid>/exe (kernel threads and root-owned processes included), so for
/// such an agent CONSTRAINED/PARTIAL is the steady state, not an incident. A /proc mounted with
/// hidepid=1|2 hides foreign pids from the listing altogether: nothing is refused, so the tally
/// stays 0 and the result is a shorter list that this tally cannot flag.
///
/// Pure + header-only; the single syscall helper is Linux-only.

#include <cerrno>
#include <cstddef>
#include <string>

#if defined(__linux__)
#include <unistd.h>
#include <sys/types.h>
#endif

namespace yuzu::shared {

/// True for an errno that means "the kernel refused this caller", not "the process is gone".
[[nodiscard]] constexpr bool proc_access_refused(int err) noexcept {
    return err == EACCES || err == EPERM;
}

struct ProcAccessTally {
    std::size_t refused{0};
    std::size_t truncated{0}; ///< a link target that filled the read buffer: degraded, not clean
    void note(int err) noexcept {
        if (proc_access_refused(err))
            ++refused;
    }
    void note_truncated() noexcept { ++truncated; }
    [[nodiscard]] bool constrained() const noexcept { return refused != 0 || truncated != 0; }
};

#if defined(__linux__)
/// Reads the symlink `link` (a /proc/<pid>/exe path) with ONE readlink call. On failure the
/// errno of THAT call is counted (a second read could see ENOENT after the process exited, or
/// a changed access decision, and erase a genuine EACCES) and "" is returned. `fn` is the
/// readlink implementation, a seam for tests.
template <class ReadlinkFn>
[[nodiscard]] inline std::string readlink_noting_with(ProcAccessTally& tally, const char* link,
                                                      ReadlinkFn fn) {
    char buf[4096];
    errno = 0;
    const ssize_t n = fn(link, buf, sizeof(buf) - 1);
    if (n < 0) {
        tally.note(errno);
        return {};
    }
    if (static_cast<std::size_t>(n) >= sizeof(buf) - 1) {
        // The buffer is full: readlink does not say whether the target was longer, so a path
        // this long is truncated or an exact fit; report degraded and emit no path.
        tally.note_truncated();
        return {};
    }
    return std::string(buf, static_cast<std::size_t>(n));
}

[[nodiscard]] inline std::string readlink_noting(ProcAccessTally& tally, const char* link) {
    return readlink_noting_with(tally, link, ::readlink);
}
#endif

} // namespace yuzu::shared
