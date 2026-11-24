// proc_snapshot_read.cpp -- bounded libproc read of one process. See proc_snapshot_read.hpp for
// why this lives in agent-core rather than in the process_introspect plugin.

#include <yuzu/agent/proc_snapshot_read.hpp>

#include <cerrno>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>

#include <cstring>
#endif

namespace yuzu::agent {

namespace {

// Process-wide: one read in flight. Static storage so an abandoned worker's releaser never
// touches a destroyed object.
std::atomic_flag g_snapshot_in_flight;

#if defined(__APPLE__)

ProcSnapshot read_snapshot(int pid) {
    ProcSnapshot out;
    struct proc_bsdinfo pbi;
    std::memset(&pbi, 0, sizeof(pbi));
    errno = 0;
    const int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbi, PROC_PIDTBSDINFO_SIZE);
    if (n != PROC_PIDTBSDINFO_SIZE) {
        out.err = errno != 0 ? errno : EIO;
        return out;
    }
    out.start_sec = pbi.pbi_start_tvsec;
    out.start_usec = pbi.pbi_start_tvusec;
    out.nice = pbi.pbi_nice;
    return out;
}

#else

ProcSnapshot read_snapshot(int) {
    ProcSnapshot out;
    out.err = ENOSYS; // non-Apple build: the only consumer (the macOS leg) never calls this
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

ProcSnapshotResult read_proc_snapshot_bounded(int pid, std::chrono::milliseconds deadline) {
    return detail::bounded_proc_snapshot(g_snapshot_in_flight, pid, deadline, read_snapshot);
}

ProcSnapshotResult
read_proc_snapshot_bounded_for_test(int pid, std::chrono::milliseconds deadline,
                                    const std::function<ProcSnapshot(int)>& reader) {
    return detail::bounded_proc_snapshot(g_snapshot_in_flight, pid, deadline, reader);
}

} // namespace yuzu::agent
