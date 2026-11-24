// proc_snapshot_read.cpp -- bounded libproc read of one process. See proc_snapshot_read.hpp for
// why this lives in agent-core rather than in the process_introspect plugin.

#include <yuzu/agent/proc_snapshot_read.hpp>

#include <cerrno>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/resource.h>

#include <cstring>
#endif

namespace yuzu::agent {

namespace {

// Process-wide: one read in flight. Static storage so an abandoned worker's releaser never
// touches a destroyed object.
ProcSnapshotSlot g_snapshot_slot;

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
    // Second call, same worker: the monotonic start stamp. If the pid were recycled between the
    // two calls the pair is mixed: a supplied token then fails (never matches), and an unguarded
    // inspect hands out a token that matches no process, which a later call reads as pid_reused.
    // It needs a pid wrap inside the gap between these two calls; a second proc_pidinfo and a
    // stamp compare would close it.
    struct rusage_info_v0 ru;
    std::memset(&ru, 0, sizeof(ru));
    errno = 0;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V0, reinterpret_cast<rusage_info_t*>(&ru)) != 0) {
        out.err = errno != 0 ? errno : EIO;
        return out;
    }
    out.start_sec = pbi.pbi_start_tvsec;
    out.start_usec = pbi.pbi_start_tvusec;
    out.nice = pbi.pbi_nice;
    out.start_abstime = ru.ri_proc_start_abstime;
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
    return detail::bounded_proc_snapshot(g_snapshot_slot, pid, deadline, read_snapshot);
}

ProcSnapshotResult
read_proc_snapshot_bounded_for_test(int pid, std::chrono::milliseconds deadline,
                                    const std::function<ProcSnapshot(int)>& reader) {
    return detail::bounded_proc_snapshot(g_snapshot_slot, pid, deadline, reader);
}

} // namespace yuzu::agent
