/**
 * process_introspect_macos.cpp -- the macOS shell: binds two kernel calls, decides nothing.
 *
 * libproc only: one proc_pidinfo(PROC_PIDTBSDINFO) call and one sysctlbyname of
 * kern.bootsessionuuid per dispatch. No task port (task_for_pid and every mach_vm_* call are
 * banned and pinned by tests/test_process_introspect_no_task_port_lexical.py), no file
 * descriptor, no handle, no thread, no subprocess, no write. Every decision, including every
 * errno comparison, is in process_introspect_legs.hpp (inspect_macos), unit-tested on every OS.
 *
 * One proc_pidinfo call per dispatch: the start time and the nice value are fields of the same
 * kernel snapshot of one process, so there is nothing a second read could protect (the Linux
 * re-read exists because facet files are read after identity). Only three numbers leave the
 * stack struct; the process name bytes in proc_bsdinfo die with the stack frame, never copied.
 *
 * No deadline wrapper: neither call takes the target's VM map lock.
 */
#if defined(__APPLE__)

#include "process_introspect_legs.hpp"

#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

#include <cerrno>
#include <cstring>

namespace yuzu::process_introspect {

int run_macos(yuzu::CommandContext& ctx, const Request& req) {
    MacSource src;
    src.bsdinfo = [pid = static_cast<int>(req.pid)] {
        MacBsdInfo out;
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
