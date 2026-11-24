/**
 * process_introspect_macos.cpp -- the macOS shell: binds the kernel reads, decides nothing.
 *
 * The libproc call itself lives in agent-core (agents/core/src/proc_snapshot_read.cpp), behind a
 * deadline; this shell turns its answer into a MacBsdInfo and reads one sysctlbyname of
 * kern.bootsessionuuid per dispatch. No task port (task_for_pid and every mach_vm_* call are
 * banned and pinned by tests/test_process_introspect_no_task_port_lexical.py, which scans the
 * agent-core unit too), no file descriptor, no handle, no thread of its own, no subprocess, no
 * write. Every decision, including every errno comparison and every deadline answer, is in
 * process_introspect_legs.hpp (inspect_macos), unit-tested on every OS.
 *
 * One bounded read per dispatch: the wall-clock start stamp and the nice value are fields of ONE
 * proc_pidinfo snapshot, so there is nothing a second read of them could protect (the Linux
 * re-read exists because facet files are read after identity). The monotonic start stamp (UP-3)
 * is the one extra number, from proc_pid_rusage in the same worker, so a wall-clock step cannot
 * make two processes share an identity. Only numbers leave agent-core; the process name bytes in
 * proc_bsdinfo die with its stack frame, never copied.
 *
 * Bounded (SRE-1). Neither call takes the target's VM map lock, but proc_pidinfo does take a
 * reference on the target through proc_find, which waits uninterruptibly while the target is
 * inside the exec switch (proc_exec_switch_task, after the new image is loaded), so a third
 * thread that holds a reference on the target and is itself blocked at that instant could stall
 * the call, as it would ps and kill on that pid. That is read from the public XNU source
 * (xnu-12377.1.9: kern_proc.c proc_ref_wait_for_exec, kern_exec.c proc_exec_switch_task), not
 * the kernel on a test host, and not reproduced. The call therefore runs on ONE worker owned by
 * agent-core with a deadline; the worker cannot be cancelled, so at the deadline it is abandoned
 * (recorded in agent-core's single in-flight flag), the dispatch answers `deadline_exceeded`,
 * and the next dispatch answers `abandoned_call_pending` instead of starting a second blocked
 * thread, until the worker returns and releases the flag. The worker's code is agent-core's, so
 * an unloaded plugin cannot pull it out from under it (the dlclose hazard documented in
 * agents/core/include/yuzu/agent/passwd_lookup.hpp). A blocked worker still pins one thread of
 * the agent until the kernel releases it; that thread is not a command-pool worker.
 */
#if defined(__APPLE__)

#include "process_introspect_legs.hpp"

#include <sys/sysctl.h>

#include <yuzu/agent/proc_snapshot_read.hpp>

#include <cerrno>
#include <cstring>

namespace yuzu::process_introspect {

int run_macos(yuzu::CommandContext& ctx, const Request& req) {
    MacSource src;
    src.bsdinfo = [pid = static_cast<int>(req.pid)] {
        using yuzu::agent::ProcSnapshotStatus;
        MacBsdInfo out;
        const auto r =
            yuzu::agent::read_proc_snapshot_bounded(pid, yuzu::agent::kProcSnapshotDeadline);
        if (r.status == ProcSnapshotStatus::Busy) {
            out.bound = MacBsdInfo::Bound::abandoned_pending;
            return out;
        }
        // TimedOut, and Rejected (the call was never started): no answer arrived.
        if (r.status != ProcSnapshotStatus::Completed) {
            out.bound = MacBsdInfo::Bound::deadline_exceeded;
            return out;
        }
        out.err = r.snap.err;
        out.start_sec = r.snap.start_sec;
        out.start_usec = r.snap.start_usec;
        out.nice = r.snap.nice;
        out.start_abstime = r.snap.start_abstime;
        return out;
    };
    src.boot_session = [] {
        char buf[64];
        std::size_t len = sizeof(buf);
        if (sysctlbyname("kern.bootsessionuuid", buf, &len, nullptr, 0) != 0)
            return RawRead{{}, RawErr::io, errno};
        // The kernel's length includes the terminating NUL.
        return RawRead{std::string(buf, strnlen(buf, len)), RawErr::none, 0};
    };
    report(ctx, inspect_macos(req, src));
    return 0;
}

} // namespace yuzu::process_introspect

#endif // __APPLE__
