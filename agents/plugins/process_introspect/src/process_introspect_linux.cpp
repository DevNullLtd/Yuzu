/**
 * process_introspect_linux.cpp -- the Linux shell: binds syscalls, decides nothing.
 *
 * Opens /proc/<pid> ONCE as a directory descriptor (the leaf is not followed) and binds
 * ProcSource's readers to the shared no-follow bounded readers; every decision, including every
 * errno comparison, is in process_introspect_legs.hpp (inspect_linux) where it is unit-tested on
 * every OS. No subprocess, no ptrace, no /proc/<pid>/mem, no write.
 *
 * No deadline wrapper: none of stat, status, limits, oom_score or oom_score_adj takes the
 * target's mmap lock (checked against upstream v4.18, v5.4, v5.15, v6.6 and v6.12: fs/proc/array.c
 * uses none, and in fs/proc/base.c only cmdline, environ, mem and map_files do). A facet that
 * reads maps, cmdline or environ must use yuzu::shared::bounded_call (bounded_wait.hpp).
 */
#if defined(__linux__)

#include "process_introspect_legs.hpp"

#include <posix_secure_read.hpp>

#include <string>
#include <utility>

namespace yuzu::process_introspect {

namespace {

RawErr to_raw_err(yuzu::shared::ReadError e) {
    switch (e) {
    case yuzu::shared::ReadError::none:
        return RawErr::none;
    case yuzu::shared::ReadError::symlink_refused:
        return RawErr::symlink_refused;
    case yuzu::shared::ReadError::not_regular:
        return RawErr::not_regular;
    case yuzu::shared::ReadError::oversized:
        return RawErr::oversized;
    case yuzu::shared::ReadError::io:
        return RawErr::io;
    }
    return RawErr::io;
}

RawRead to_raw(yuzu::shared::FileRead&& r) {
    RawRead out;
    out.error = to_raw_err(r.error);
    out.err = r.err;
    out.data = std::move(r.data);
    return out;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx, const Request& req) {
    // The descriptor lives for this dispatch only (released when `dir` goes out of scope).
    const auto dir = yuzu::shared::open_dir_no_follow("/proc/" + std::to_string(req.pid));
    ProcSource src;
    src.open_errno = dir.err;
    const int fd = dir.dir.fd();
    src.read = [fd](const char* name, std::size_t cap) {
        return to_raw(yuzu::shared::read_file_no_follow_at(fd, name, cap));
    };
    src.boot_id = [] {
        return to_raw(yuzu::shared::read_file_no_follow("/proc/sys/kernel/random/boot_id",
                                                        kBootIdCap));
    };
    src.mountinfo = [] {
        return to_raw(yuzu::shared::read_file_no_follow("/proc/self/mountinfo", kMountinfoCap));
    };
    report(ctx, inspect_linux(req, src));
    return 0;
}

} // namespace yuzu::process_introspect

#endif // __linux__
