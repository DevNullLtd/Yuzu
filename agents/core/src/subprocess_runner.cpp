/**
 * subprocess_runner.cpp -- agent-core bounded, fork-safe subprocess runner
 * (#2273 foundation), extended to the full ADR-3002 runner contract
 * (docs/adr/3002-acquisition-ladder.md:537-606) plus the best-practice
 * addendum (A1-A6, B1-B6).
 *
 * Merges two independently hardened bounded-subprocess implementations that
 * grew up in different plugins for the same underlying problem (no
 * built-in timeout on `log show`, `codesign`, `plutil`, and GNU `timeout`
 * is not available on macOS): the event_logs plugin's line-collecting
 * bounded_run() and the filesystem plugin's exit-code/output-capturing
 * run_macos_tool(). Both forked+execed directly (no shell), killed the
 * child's whole process group on a deadline, and reaped it without leaving
 * a zombie behind -- this file is that logic, once, serving both
 * consumption styles (SubprocessResult carries both `lines` and `output`).
 *
 * Fork-safety notes (why the child branch looks the way it does):
 *   - The C-style argv/envp are built entirely in the PARENT, before fork().
 *     Between fork() and execve() the child may only call async-signal-safe
 *     functions (POSIX 2.4.3) -- allocating via std::vector/std::string
 *     post-fork is unsafe in a multithreaded process, since another thread
 *     can hold the allocator lock at the moment of fork, which the child
 *     inherits already-locked and then deadlocks on.
 *   - Both the output pipe and the exec-error pipe are FD_CLOEXEC on both
 *     ends, so neither leaks into whatever the child execs into.
 *   - Setting FD_CLOEXEC is NOT atomic with pipe() on this platform (no
 *     pipe2()) -- a concurrent fork() on another thread landing between
 *     THIS invocation's pipe() and its fcntl(F_SETFD, FD_CLOEXEC) would
 *     otherwise inherit a not-yet-CLOEXEC write end into an unrelated
 *     child, starving this invocation's own EOF (a false timeout) for as
 *     long as that other child runs. BR-001: the process-wide
 *     yuzu::agent::global_fork_lock() (fork_lock.hpp) serializes
 *     [pipe()..fork()] across every launcher that PARTICIPATES in it — this
 *     runner plus the sites listed in fork_lock.hpp's coverage ledger — to
 *     close that window; the child inherits it already locked and never
 *     touches it. It is NOT automatic for every fork/popen in the agent: a
 *     raw popen() that doesn't take the lock still races this window until it
 *     is migrated (fork_lock.hpp tracks the residual uncovered sites).
 *   - The child calls setsid() so a timeout kill can take out the whole
 *     process group, not just the direct child (a CLI can spawn helpers
 *     that inherit the group).
 *   - A second pipe (also FD_CLOEXEC) distinguishes "the exec itself
 *     failed" from "the program ran and legitimately exited with some
 *     code": on a successful execve() the write end's CLOEXEC flag closes
 *     it automatically, so the parent sees EOF with nothing ever written;
 *     on failure -- either execve() itself or a load-bearing setup step
 *     before it, e.g. the stdout dup2 -- the child write()s its errno to
 *     it (async-signal-safe, no allocation) before _exit(127).
 *
 * Pipe EOF alone does not prove the child has exited (a descendant can
 * close its inherited copy of the write end while the direct child keeps
 * running), so the run loop tracks child-reap state independently via
 * non-blocking waitpid()/wait4() polls and only finishes once the child is
 * confirmed dead (or the post-kill grace period elapses, whichever is
 * first).
 *
 * ADR-3002 additions on top of the shipped core above (none of which touch
 * the fd sweep, fork_lock, the hard deadline, process-group kill + reap, the
 * line/output caps, the exec-error pipe, or the single-pipe stderr design):
 *   - build_launch_spec() (subprocess_launch_spec.hpp) now does argv/env
 *     validation and assembly; the runtime argv[0]/embedded-NUL rejection
 *     that used to be assert-only now applies in every build type.
 *   - TerminationReason is computed and surfaced on every return path.
 *   - A per-invocation CancellationToken is checked alongside the existing
 *     process-global cancel flag.
 *   - A1-A6/B2-B6 (Windows handle allow-list + quoting, POSIX signal/rlimit/
 *     umask/env hardening, close_range/pidfd fast paths, rusage capture, the
 *     optional TOCTOU-safe exec primitive) are implemented as ADDITIONS
 *     around the shipped mechanisms, per the addendum's "extend around
 *     these; do not rewrite them."
 *   - A real Windows Job-Object backend replaces the previous stub.
 */

#include <yuzu/agent/subprocess_runner.hpp>

#include <yuzu/agent/subprocess_launch_spec.hpp>

#include <atomic>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring> // std::memcpy (spawn_errno decode below)

// Unconditional (both platforms): BR-005's Windows-side inherit_parent_env
// filter logs a withheld-var line the same way the POSIX backend does, so
// spdlog must be visible on the Windows compile path too -- it was
// previously nested inside the #ifndef _WIN32 block below, which built fine
// on POSIX (where every spdlog:: call site lives) but left the later
// Windows-side spdlog::debug() call with no declaration at all, undetected
// locally because this TU is only actually Windows-compiled in CI.
#include <spdlog/spdlog.h>

#ifndef _WIN32
#include <yuzu/agent/fork_lock.hpp>

#include <cerrno>
#include <csignal>
#include <cstdio> // std::fopen/std::fgets — read Linux fs.nr_open for the fd ceiling
#include <cstdlib> // std::getenv (TZ passthrough), std::strtol (fs.nr_open)
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h> // umask, fstat, S_ISREG/S_IWGRP/S_IWOTH (A6, B6)
#include <sys/wait.h>
#if defined(__APPLE__)
#include <crt_externs.h> // _NSGetEnviron() -- BR-001 POSIX inherit_parent_env below: a
                         // dylib (this TU builds into yuzu_agent_core_lib, a
                         // shared_library) cannot rely on a directly-linked
                         // `environ` symbol the way a main executable can.
#include <sys/sysctl.h> // sysctlbyname(kern.maxfilesperproc) — per-process fd ceiling
#endif
#if defined(__linux__)
#include <sys/syscall.h> // SYS_close_range / SYS_pidfd_open / SYS_execveat (B2/B5/B6)
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC 4
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#endif
#include <thread>
#include <unistd.h>
#include <utility>
#else // _WIN32
// Hoisted out of the yuzu::agent-namespaced #else branch below (which used to
// #include these headers directly inside `namespace yuzu::agent { ... }`) --
// MSVC was compiling all of <array>'s std:: contents as yuzu::agent::std::,
// producing the class-template/syntax errors this fix eliminates. Every
// standard/system header belongs in the unnamespaced top-of-file preamble,
// never inside an open namespace.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <psapi.h>

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (CDX-R4-05, #1681)

// BR-003 (whole-branch review round 2): the env-sort comparator below used
// to hand-roll ASCII-only case folding via std::toupper/<cctype> here; it
// now calls Win32's own CompareStringOrdinal (windows.h, already included
// above) for a real locale-independent Unicode ordinal comparison, so
// neither <cctype> nor <cwctype> is needed in this branch any more.
#include <memory> // std::unique_ptr -- BR-004 GetEnvironmentStringsW RAII owner below
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
// POSIX guarantees this variable exists but NOT that any header declares
// it without a feature-test macro (glibc only exposes it via <unistd.h>
// under _GNU_SOURCE; musl/other libcs vary) -- declare it explicitly rather
// than depend on an include-order accident. Declared at TRUE FILE SCOPE,
// outside every namespace: libc's `environ` is a plain, unmangled C global.
// An `extern` re-declaration inside a C++ namespace -- named or anonymous --
// mangles into that namespace's own symbol name instead of binding to the
// real libc one, so a strict linker (mold) reports it undefined at link
// time rather than silently resolving to garbage. Caught only on Linux CI:
// this whole branch is `#if !defined(__APPLE__)`, so macOS never compiles
// it locally, and Windows never reaches this leg either.
extern char** environ;
#endif

namespace yuzu::agent {

namespace {
// Backs request_subprocess_cancel/subprocess_cancel_requested: a single
// process-wide flag (not per-call, not per-connection), set once at agent
// shutdown and never cleared -- see the agent.cpp call sites next to each
// stop_requested_ latch site.
//
// CONTRACT (UP-12): this latch is SHUTDOWN-ONLY. Because it is global and
// sticky, setting it kills EVERY in-flight and future subprocess for the
// process lifetime. A future caller MUST NOT repurpose it for a per-operation
// or per-connection cancel -- that would silently abort all concurrent capture
// (TAR, DEX, plugin shell-outs) agent-wide. A narrower per-call cancel is
// SubprocessOptions::cancel_token (CancellationToken) -- both are checked on
// every poll, independently.
std::atomic<bool> g_subprocess_cancel{false};
} // namespace

void request_subprocess_cancel(bool cancel) {
    // See the shutdown-only contract on g_subprocess_cancel above.
    g_subprocess_cancel.store(cancel, std::memory_order_release);
}

bool subprocess_cancel_requested() {
    return g_subprocess_cancel.load(std::memory_order_acquire);
}

#ifndef _WIN32

namespace {

// Bound on how long we'll keep waiting, after sending the hard kill, for the
// pipes to close AND the child to be reaped. Keeps the "drain" phase
// itself from hanging forever in a pathological case (e.g. an unkillable
// descendant holding a pipe open, or a kernel-uninterruptible child).
constexpr auto kDrainGrace = std::chrono::milliseconds(2000);

// Bound on how long the exception-safety backstop (ChildGuard) will poll
// non-blockingly for the child to be reaped before handing the wait off to
// an asynchronous background reaper. Keeps the guard's destructor itself
// from ever performing an unbounded blocking waitpid() -- the one case the
// run loop below cannot cover, since the loop only runs on the normal path
// and the guard exists specifically for early returns.
constexpr auto kGuardReapGrace = std::chrono::milliseconds(200);

void sleep_briefly(long nanos) {
    struct timespec ts{0, nanos};
    nanosleep(&ts, nullptr);
}

// Send SIGKILL to the child's process group; if that fails (e.g. ESRCH
// because the group is already gone, EPERM, or the child never reached its
// setsid() call before being reaped/killed) fall back to killing the
// direct child so a timeout always has a real chance of landing.
void kill_child_or_group(pid_t pid) {
    if (kill(-pid, SIGKILL) != 0)
        kill(pid, SIGKILL);
}

// ADR-3002 soft-terminate grace: SIGTERM (never SIGKILL) to the process
// group first, falling back to the direct child on the same ESRCH/EPERM
// reasoning as kill_child_or_group() above.
void soft_terminate_child_or_group(pid_t pid) {
    if (kill(-pid, SIGTERM) != 0)
        kill(pid, SIGTERM);
}

// Poll waitpid(pid, ..., WNOHANG) for up to `grace`, sleeping briefly
// between attempts. Returns true once the child is confirmed reaped (or
// already gone), false if `grace` elapses first. Never performs a blocking
// wait.
bool try_reap_bounded(pid_t pid, std::chrono::milliseconds grace) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid || (waited < 0 && errno == ECHILD))
            return true;
        if (std::chrono::steady_clock::now() - start >= grace)
            return false;
        sleep_briefly(5'000'000L); // 5ms
    }
}

// Reap `pid` on a detached background thread. Used when try_reap_bounded()
// above could not confirm the reap within its grace period -- rather than
// block the calling (worker) thread indefinitely, hand the wait off to a
// thread that is free to block as long as it needs to. The thread owns
// everything it touches: `pid` is captured by value, so nothing here
// references state on a stack that may already have unwound.
void reap_async(pid_t pid) {
    try {
        std::thread([pid]() {
            int status = 0;
            pid_t waited;
            do {
                waited = waitpid(pid, &status, 0);
            } while (waited < 0 && errno == EINTR);
        }).detach();
    } catch (...) {
        // Thread creation failed (e.g. under resource exhaustion, exactly
        // when this path is most likely to be reached). This can be called
        // from ChildGuard's destructor, which is implicitly noexcept -- an
        // exception escaping it would std::terminate() the whole agent. A
        // zombie left until the agent process itself exits (the kernel
        // reclaims it then regardless) is strictly preferable to that.
        //
        // Make the leak observable (UP-6): sustained detached-reaper spawn
        // failures mean accumulating zombies, which an operator should be able
        // to see rather than diagnose blind. spdlog is itself noexcept-ish, but
        // guard it so this destructor-reachable path can never throw.
        try {
            spdlog::warn("subprocess_runner: could not spawn detached reaper for pid {} "
                         "(resource exhaustion?); leaving it for process-exit reclamation",
                         static_cast<long>(pid));
        } catch (...) {
        }
    }
}

// RAII owner for a POSIX file descriptor in the parent process -- closes on
// destruction unless reset()/released first. Guards against leaking a pipe
// end if an allocating operation (e.g. std::bad_alloc from a string/vector
// op while collecting output) throws past this function.
//
// reset() has NO same-value guard, unlike yuzu/agent/scoped_fd.hpp's
// ScopedFd (see that header's doc comment for the three-way reset()-contract
// cross-reference across this codebase) -- never called with its own current
// value anywhere in this file, so the question never arises here.
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.release();
        }
        return *this;
    }
    ~UniqueFd() { reset(); }

    int get() const { return fd_; }

    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void reset(int fd = -1) {
        if (fd_ >= 0)
            close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

// RAII guard over a forked child: unless discharged, the destructor
// SIGKILLs the child (process group, falling back to the direct child) and
// reaps it. This is the exception-safety backstop for run_bounded_subprocess
// -- the normal path already kills-if-needed and reaps the child via the
// poll loop below and discharges the guard once that is confirmed, so the
// destructor only fires on an early return or an exception unwinding out
// of the function.
//
// The reap here is BOUNDED, never a raw blocking waitpid(): a SIGKILLed
// process usually dies promptly, but a child wedged in uninterruptible
// kernel I/O (or a kill that didn't fully land) would otherwise hang this
// destructor -- and therefore the calling thread -- forever. If the short
// foreground poll can't confirm the reap, the wait is hedged off to a
// detached background thread instead, so ChildGuard's destructor always
// returns promptly.
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (pid_ <= 0)
            return;
        if (child_reaped_) {
            // BR-002: the run loop's own try_reap() already confirmed this
            // PID is gone (waitpid returned it, or ECHILD) before an
            // exception unwound into this destructor -- e.g. std::bad_alloc
            // while collecting output after the child exited. The kernel is
            // free to have recycled the PID for an unrelated process by now,
            // so kill_child_or_group()'s direct-PID kill(pid_, SIGKILL)
            // fallback must never fire here (it would SIGKILL a stranger).
            // Only the process GROUP id is still meaningful, and only
            // best-effort -- a still-running descendant may have kept it
            // alive, but the pid itself is not safe to signal directly.
            (void)kill(-pid_, SIGKILL);
            return;
        }
        kill_child_or_group(pid_);
        if (!try_reap_bounded(pid_, kGuardReapGrace))
            reap_async(pid_);
    }
    void discharge() { pid_ = -1; }
    // BR-002: called from the run loop's try_reap() the instant the child is
    // confirmed reaped, so the guard's destructor knows -- if it still fires
    // after that point (an exception thrown before discharge()) -- that
    // pid_ may already have been recycled and must not be signalled
    // directly.
    void mark_child_reaped() noexcept { child_reaped_ = true; }

private:
    pid_t pid_;
    bool child_reaped_ = false;
};

// EINTR-retrying dup2() -- async-signal-safe (no allocation), safe to call
// from the forked child between fork() and execve(). dup2() is not
// documented to return EINTR on every platform, but where it can, this
// keeps a spurious interrupt from being mistaken for a real setup
// failure.
int dup2_retry(int oldfd, int newfd) {
    int rc;
    do {
        rc = dup2(oldfd, newfd);
    } while (rc == -1 && errno == EINTR);
    return rc;
}

// CDX-P1-001/K3: make a freshly created pipe end safe to use around the
// child's stdio wiring. pipe() returns the two LOWEST free descriptors, so a
// parent running with a standard fd closed (a daemonized service that closed
// 0/1/2 before re-opening, or a crashed-away stdio) gets a pipe end ON fd
// 0/1/2 -- the child's dup2-to-stdio + close-by-number sequence then silently
// destroys the capture wiring. Move any such end above the stdio range with
// F_DUPFD_CLOEXEC (atomic CLOEXEC, returns the lowest free fd >= 3); an end
// already >= 3 just gets CLOEXEC set in place, exactly as before. Fail closed
// on either fcntl -- CLOEXEC on every pipe end is load-bearing (it is what
// keeps the pipe from leaking into whatever the child execs into).
[[nodiscard]] bool secure_pipe_end(UniqueFd& fd) {
    if (fd.get() < 3) {
        const int raised = fcntl(fd.get(), F_DUPFD_CLOEXEC, 3);
        if (raised == -1)
            return false;
        fd.reset(raised); // closes the low original
        return true;
    }
    return fcntl(fd.get(), F_SETFD, FD_CLOEXEC) != -1;
}

// A true upper bound on any live fd NUMBER, computed in the PARENT (getrlimit /
// sysctl / fopen are not async-signal-safe, so they must never run post-fork).
// Used as the exclusive ceiling for the child's [3, ceiling) close-on-exec sweep.
// The HARD RLIMIT_NOFILE is the natural bound (soft <= hard always, so no fd can
// be allocated at or above it); when the hard limit is infinite — the macOS
// default, or a Linux `LimitNOFILE=infinity` unit — fall back to the kernel's
// actual per-process descriptor cap (macOS `kern.maxfilesperproc`, Linux
// `fs.nr_open`), above which the kernel refuses to allocate a descriptor, so the
// bound stays finite AND complete without an unbounded sweep.
long resolve_fd_ceiling() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY &&
        rl.rlim_max <= static_cast<rlim_t>(1L << 31))
        return static_cast<long>(rl.rlim_max);
#if defined(__APPLE__)
    int maxproc = 0;
    size_t sz = sizeof(maxproc);
    if (sysctlbyname("kern.maxfilesperproc", &maxproc, &sz, nullptr, 0) == 0 && maxproc > 0)
        return maxproc;
#elif defined(__linux__)
    if (FILE* f = std::fopen("/proc/sys/fs/nr_open", "re")) {
        // fgets+strtol rather than fscanf: glibc 2.38 redirects the scanf family
        // to versioned __isoc23_* symbols, which breaks loading on older-glibc
        // (RHEL-era) hosts. The value is a single decimal (max ~20 chars).
        char buf[32]{};
        const bool got = std::fgets(buf, sizeof(buf), f) != nullptr;
        std::fclose(f);
        if (got) {
            char* end{};
            const long v = std::strtol(buf, &end, 10);
            if (end != buf && v > 0)
                return v;
        }
    }
#endif
    return 1L << 20; // last-resort finite bound (Linux default fs.nr_open)
}

// Async-signal-safe: writes `err` to the exec-error pipe (retried across
// EINTR, no allocation) then terminates the child immediately via
// _exit(127). Shared by a failed execve() and by a load-bearing setup
// failure caught before execve() is ever reached (e.g. the child's own
// stdout dup2) -- either way the parent must see a definite failure on
// this pipe rather than an ambiguous EOF, and the child must never
// proceed to execve() with broken plumbing. A real write failure other
// than EINTR is still best-effort only: the parent's "no byte ever
// arrived" then stays inconclusive (tool_ran stays false) rather than
// assuming success.
[[noreturn]] void report_setup_failure_and_exit(int err_fd, int err) {
    // cpp-safety F3: reinterpret_cast to unsigned char* is the one aliasing
    // exception the standard itself carves out ([basic.lval]) -- reading any
    // object's representation through unsigned char* (or char*/std::byte*) is
    // always well-defined, regardless of `err`'s actual type, so this cast is
    // not UB.
    const auto* bytes = reinterpret_cast<const unsigned char*>(&err);
    std::size_t sent = 0;
    while (sent < sizeof(err)) {
        ssize_t w = write(err_fd, bytes + sent, sizeof(err) - sent);
        if (w > 0) {
            sent += static_cast<std::size_t>(w);
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    _exit(127);
}

// B2 (Linux >=5.11 fast path): the manual fcntl(F_GETFD)/F_SETFD loop this
// function contains is the SHIPPED, do-not-disturb fd sweep, unmodified --
// it is now called as an explicit fallback (see the close_range attempt
// beside its child-branch call site) rather than always being the only
// path, but its own body and semantics (mark-not-close, post-fork, complete
// to the parent-computed hard-limit ceiling) are untouched.
void sweep_fd_range_cloexec_fallback(long ceiling) {
    for (long fd = 3; fd < ceiling; ++fd) {
        const int flags = fcntl(static_cast<int>(fd), F_GETFD);
        if (flags != -1 && !(flags & FD_CLOEXEC))
            fcntl(static_cast<int>(fd), F_SETFD, flags | FD_CLOEXEC);
    }
}

// B6: content_dist's execute_verified_payload is the in-tree caller (Linux
// leg, is_linux=true). Async-signal-safe: opens argv[0] O_NOFOLLOW so a
// symlink swap between the probe and this open() can't redirect us, fstat()s
// the FD (never the path, closing the classic stat-vs-exec TOCTOU as far as
// an fd-based check can), and on Linux execs THAT SAME FD via a raw
// execveat(fd, "", ..., AT_EMPTY_PATH) syscall -- a direct syscall rather
// than glibc's fexecve() wrapper, which can fall back to an unsafe
// /proc/self/fd string-formatting path on kernels without execveat().
// Bounded ETXTBSY backoff (a binary still being written) — never unbounded.
//
// Deliberately NOT O_CLOEXEC: documented Linux kernel behavior is that
// execveat(fd, "", ..., AT_EMPTY_PATH) on an O_CLOEXEC-opened fd fails with
// ENOENT -- the CLOEXEC flag causes the fd to be torn down as part of the
// exec transition itself, before the kernel can read the target binary
// through it. This is the exact fd meant to be exec'd (not one that should
// be hidden from a child), so CLOEXEC has no protective purpose here and
// actively breaks the primitive. Reproduced directly (gcc-15/Linux 7.x,
// forked child, isolated per-flag-combination): O_RDONLY and
// O_RDONLY|O_NOFOLLOW both exec cleanly; adding O_CLOEXEC to either
// deterministically fails every attempt with ENOENT. Caught on the first
// Linux CI run of this code path to ever actually execute past compile
// time (2026-08-31) -- this primitive had never successfully exec'd
// anything on real Linux before this fix.
[[noreturn]] void toctou_verified_exec(char* const* c_argv, char* const* c_envp,
                                        const LaunchSpec::ExecVerification& v, int err_fd) {
    constexpr int kMaxRetries = 5;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        int fd = open(c_argv[0], O_RDONLY | O_NOFOLLOW);
        if (fd < 0)
            report_setup_failure_and_exit(err_fd, errno);
        struct stat st{};
        if (fstat(fd, &st) != 0) {
            int e = errno;
            close(fd);
            report_setup_failure_and_exit(err_fd, e);
        }
        const bool regular = S_ISREG(st.st_mode);
        const bool root_owned = !v.require_root_owned || st.st_uid == 0;
        const bool not_group_other_writable = (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
        const bool size_ok =
            !v.expected_size || static_cast<std::uint64_t>(st.st_size) == *v.expected_size;
        if (!regular || !root_owned || !not_group_other_writable || !size_ok) {
            close(fd);
            report_setup_failure_and_exit(err_fd, EPERM);
        }
#if defined(__linux__) && defined(SYS_execveat)
        syscall(SYS_execveat, fd, "", c_argv, c_envp, AT_EMPTY_PATH);
        if (errno == ETXTBSY && attempt + 1 < kMaxRetries) {
            close(fd);
            struct timespec ts{0, 20'000'000L * (attempt + 1)}; // bounded 20/40/60/80ms backoff
            nanosleep(&ts, nullptr);
            continue;
        }
        {
            int e = errno;
            close(fd);
            report_setup_failure_and_exit(err_fd, e);
        }
#else
        // sec-8: macOS/BSD (and any Linux build without SYS_execveat) has no
        // fd-based exec primitive here -- no execveat(), and glibc's
        // fexecve() is deliberately not used either (see this function's
        // header comment above). close(fd) followed by execve(path, ...)
        // would release the just-verified inode and let the kernel
        // RE-RESOLVE argv[0] from the filesystem, reopening exactly the
        // TOCTOU window the fstat-verify above exists to close: a swap of
        // the target between that verify and this exec is still
        // exploitable. Windows already fails CLOSED for the identical gap
        // (BR-004 -- the spec.exec_verify.enabled check ahead of
        // CreateProcessW in the Windows backend below). Match that here: a
        // security control that silently degrades to an unverified exec is
        // worse than an honest refusal, so report a setup failure instead of
        // ever calling execve() on this platform.
        close(fd);
        report_setup_failure_and_exit(err_fd, ENOSYS);
#endif
    }
    report_setup_failure_and_exit(err_fd, ETXTBSY);
}

// B5 (Linux, best-effort): pidfd_open() right after fork(), used ONLY to
// shorten the poll loop's wait latency below (see wait_for_activity()) --
// try_reap()'s waitpid()/wait4() remains the sole authority on "is the
// child actually reaped", and kill_child_or_group()'s process-group
// kill()/killpg() remains the sole termination mechanism (BR-002:
// pidfd_send_signal() is deliberately NOT used to signal the child here,
// only pidfd_open()+poll() for readiness). A kernel <5.3 (no pidfd_open()),
// a sandboxed/seccomp environment that blocks the syscall, or any non-Linux
// platform returns -1 here, and wait_for_activity() falls back to the
// historical fixed sleep -- exactly the behaviour before this feature
// existed.
int try_open_pidfd(pid_t pid) {
#if defined(__linux__) && defined(SYS_pidfd_open)
    long fd = syscall(SYS_pidfd_open, pid, 0);
    return fd >= 0 ? static_cast<int>(fd) : -1;
#else
    (void)pid;
    return -1;
#endif
}

// Waits up to `nanos` for read activity on either pipe or (if `pidfd` >= 0)
// the child's pidfd becoming readable -- whichever comes first -- rather
// than unconditionally sleeping the whole interval. Falls back to the
// historical fixed sleep when no pidfd is available. Never blocks longer
// than `nanos`.
void wait_for_activity(int read_fd, int err_read_fd, int pidfd, long nanos) {
    if (pidfd >= 0) {
        pollfd fds[3] = {{read_fd, POLLIN, 0}, {err_read_fd, POLLIN, 0}, {pidfd, POLLIN, 0}};
        poll(fds, 3, static_cast<int>(nanos / 1'000'000L));
        return;
    }
    sleep_briefly(nanos);
}

// BR-001 (whole-branch review round 2): this process' own live environment,
// as a char** NUL-terminated block -- the read side of POSIX
// inherit_parent_env below. Deliberately NOT a bare `extern char** environ;`
// used directly at the call site: this TU builds into yuzu_agent_core_lib
// (a shared_library, agents/core/meson.build), and on Apple platforms the
// `environ` symbol is reliably available only to a directly-linked main
// executable -- a dylib must go through _NSGetEnviron() instead
// (crt_externs.h, included above under __APPLE__) or risk an unresolved
// symbol / wrong-image environ at link or load time. glibc/other POSIX
// exposes `environ` to any translation unit that declares it extern, no
// such indirection needed. The `extern` declaration itself lives at true
// file scope, above -- see that declaration's own comment for why.
char** current_environ() {
#if defined(__APPLE__)
    return *_NSGetEnviron();
#else
    return ::environ;
#endif
}

} // namespace

SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                         const SubprocessOptions& opts) {
    SubprocessResult result;
    if (argv.empty())
        return result; // termination_reason stays its default spawn_error

    // B1: validate + assemble through the pure core (subprocess_launch_spec.hpp)
    // rather than hand-rolling the checks here. Runtime-rejects (in EVERY
    // build type, not just debug/assert builds) an empty/relative argv[0]
    // and an embedded NUL in any argv element -- promoting the old
    // assert-only check.
    LaunchOptions launch_opts;
    launch_opts.working_dir = opts.working_dir;
    launch_opts.merge_stderr = opts.merge_stderr;
    if (const char* tz = std::getenv("TZ"))
        launch_opts.tz = std::string(tz);
    // DESIGNATED, not positional: SubprocessOptions::RlimitCaps and
    // LaunchOptions' rlimits are field-identical but SEPARATE types (the
    // launch-spec header is deliberately independent of the runner header), so
    // a positional brace-init silently mis-maps if either side is ever
    // reordered. Designators must appear in declaration order, so a reorder
    // becomes a COMPILE ERROR here instead of a wrong rlimit at runtime.
    launch_opts.rlimits = {.cpu_seconds = opts.rlimits.cpu_seconds,
                           .address_space_bytes = opts.rlimits.address_space_bytes,
                           .fsize_bytes = opts.rlimits.fsize_bytes,
                           .nofile_count = opts.rlimits.nofile_count};
    launch_opts.exec_verify = {.enabled = opts.exec_verify.enabled,
                               .require_root_owned = opts.exec_verify.require_root_owned,
                               .expected_size = opts.exec_verify.expected_size};
    // extra_env: SubprocessOptions::extra_env (vector<pair<string,string>>)
    // and LaunchOptions::extra_env (vector<EnvVar>) are field-identical but
    // SEPARATE types -- same reason as rlimits/exec_verify above -- so this
    // is a manual element copy rather than a brace-init.
    launch_opts.extra_env.reserve(opts.extra_env.size());
    for (const auto& [key, value] : opts.extra_env)
        launch_opts.extra_env.push_back({key, value});
    // BR-001 (whole-branch review round 2): passed through for the pure
    // LaunchSpec passthrough/testability, AND now actually acted on below --
    // see the envp-construction block further down and
    // SubprocessOptions::inherit_parent_env's doc comment, point (c), for
    // the full contract this (POSIX) backend now honours.
    launch_opts.inherit_parent_env = opts.inherit_parent_env;

    LaunchSpec spec = build_launch_spec(argv, launch_opts);
    if (spec.error != LaunchSpecError::none)
        return result; // relative/empty argv[0] or an embedded NUL --
                        // termination_reason stays spawn_error, tool_ran stays false

    // ADR-3002: the output sanity cap is now caller-configurable (up to
    // 16 MiB); clamped rather than trusted verbatim so a caller-supplied 0
    // or an oversized value is corrected, never silently treated as
    // "unbounded".
    const std::size_t output_cap = std::clamp<std::size_t>(opts.output_cap_bytes, 1, 16 * 1024 * 1024);

    // Build the C-style argv/envp BEFORE fork() -- see the file header comment.
    std::vector<char*> c_argv;
    c_argv.reserve(spec.argv.size() + 1);
    for (const auto& arg : spec.argv)
        c_argv.push_back(const_cast<char*>(arg.c_str()));
    c_argv.push_back(nullptr);

    // A5 (ordinary case): explicit clear-and-allow-list envp, built here
    // from spec.env (which build_launch_spec assembled from nothing --
    // LD_*/DYLD_*/IFS/BASH_ENV/GCONV_PATH are stripped by construction,
    // never copied from this process' own environment).
    //
    // BR-001 (whole-branch review round 2, Alex ruling): when
    // inherit_parent_env is set, this backend now mirrors the Windows
    // backend's existing inherit_parent_env branch (see that code for the
    // twin structure) -- swap the BASE for this envp from the A5 allow-list
    // to a live read of THIS process' own real environment (POSIX
    // `environ`, via current_environ() above), with the ADR-3002 A5
    // injection class stripped via filter_inherited_env()
    // (subprocess_launch_spec.hpp) and extra_env layered on top via the
    // SAME merge_launch_env() replace-never-duplicate semantics used below
    // for the ordinary case. extra_env was already validated (denylist/
    // malformed-entry checks) by build_launch_spec() above UNCONDITIONALLY,
    // so nothing here can smuggle a denied name through just because this
    // flag is set -- that fail-closed behaviour is UNCHANGED.
    //
    // filter_inherited_env's strip, by contrast, is SILENT: an inherited
    // parent-environment variable that matches the injection class is
    // simply withheld from the child, never a reason to refuse the whole
    // launch -- see that function's own comment for why an inherited
    // variable's failure mode must differ from extra_env's. Log what was
    // stripped so the behaviour stays observable rather than silent at the
    // OPERATOR level, even though it is silent at the API level.
    std::vector<std::string> envp_strings;
    if (spec.inherit_parent_env) {
        std::vector<EnvVar> parent_env;
        for (char** e = current_environ(); e && *e != nullptr; ++e) {
            std::string_view entry(*e);
            auto eq = entry.find('=');
            if (eq == std::string_view::npos)
                continue; // malformed entry with no '=' at all -- skip, don't guess
            parent_env.push_back({std::string(entry.substr(0, eq)), std::string(entry.substr(eq + 1))});
        }
        EnvInheritResult filtered = filter_inherited_env(parent_env, /*windows=*/false);
        for (const auto& name : filtered.stripped) {
            spdlog::debug("run_bounded_subprocess: withholding inherited env var '{}' from the "
                         "child (ADR-3002 A5 injection class, inherit_parent_env)",
                         name);
        }
        std::vector<EnvVar> merged =
            merge_launch_env(filtered.env, launch_opts.extra_env, /*windows=*/false).env;
        envp_strings.reserve(merged.size());
        for (const auto& e : merged)
            envp_strings.push_back(e.key + "=" + e.value);
    } else {
        envp_strings.reserve(spec.env.size());
        for (const auto& e : spec.env)
            envp_strings.push_back(e.key + "=" + e.value);
    }
    std::vector<char*> c_envp;
    c_envp.reserve(envp_strings.size() + 1);
    for (auto& s : envp_strings)
        c_envp.push_back(const_cast<char*>(s.c_str()));
    c_envp.push_back(nullptr);

    // BR-001: serialize pipe-creation-through-fork against every other
    // fork/popen launcher in the agent, not just this file (see
    // fork_lock.hpp's contract) -- held from here through fork() below;
    // every early return in between releases it via this lock's destructor.
    std::unique_lock<std::mutex> fork_pipe_lock(global_fork_lock());

    int raw_pipe[2];
    if (pipe(raw_pipe) != 0)
        return result;
    UniqueFd read_fd(raw_pipe[0]);
    UniqueFd write_fd(raw_pipe[1]);
    // secure_pipe_end: CLOEXEC both ends AND lift either end off fds 0-2 if
    // the parent is running with a standard fd closed (CDX-P1-001/K3 -- see
    // the helper). Fail closed: a failed fcntl here is treated the same as a
    // failed pipe() above rather than silently continuing with a leaky or
    // stdio-colliding descriptor. RAII closes both ends on this early return.
    if (!secure_pipe_end(read_fd) || !secure_pipe_end(write_fd))
        return result;

    // PLAN-11: a second, CLOEXEC pipe used only to detect an exec()
    // failure. Its write end auto-closes the instant execve() succeeds (no
    // child-side code needed for that case), so the parent sees EOF with
    // nothing ever written; on failure the child writes its errno to it
    // before _exit()ing. tool_ran is derived from whether the parent ever
    // saw a byte on this pipe -- never from the child's exit code, so a
    // program that legitimately exits 127 is never confused with a
    // missing binary.
    int err_raw_pipe[2];
    if (pipe(err_raw_pipe) != 0)
        return result; // read_fd/write_fd close themselves
    UniqueFd err_read_fd(err_raw_pipe[0]);
    UniqueFd err_write_fd(err_raw_pipe[1]);
    if (!secure_pipe_end(err_read_fd) || !secure_pipe_end(err_write_fd))
        return result; // fail closed, same reasoning as the pipe above

    // Ceiling for the child's inherited-fd sweep, computed HERE in the parent
    // (getrlimit() is not async-signal-safe, so it must not run post-fork). The
    // child sweeps the whole [3, child_fd_ceiling) range (via the B2 close_range
    // fast path or the fcntl fallback) AFTER fork(), which is both:
    //   * COMPLETE — the bound is the HARD RLIMIT_NOFILE. soft <= hard always, so
    //     no descriptor can ever be allocated at or above the hard limit; the
    //     sweep therefore covers every possible live fd number (a soft-limit
    //     ceiling would miss a fd opened while the limit was higher, or under an
    //     RLIM_INFINITY soft limit).
    //   * RACE-FREE — running post-fork, it re-derives the live set from the
    //     child's own (frozen-at-fork) fd table, so it catches EVERY fd present
    //     at fork(), including one a different, unrelated thread opened without
    //     O_CLOEXEC in the window before fork(). A parent-side snapshot cannot
    //     make that guarantee (global_fork_lock() serialises launchers, not
    //     arbitrary socket()/open() callers). This is the round-4 fix: the prior
    //     pre-fork enumeration had exactly that TOCTOU gap.
    const long child_fd_ceiling = resolve_fd_ceiling();

    pid_t pid = fork();
    if (pid < 0)
        return result; // all four fds close themselves

    if (pid == 0) {
        // Child: inherits fork_pipe_lock already locked -- NEVER lock,
        // unlock, or otherwise touch it (see fork_lock.hpp's contract).
        // Safe specifically because this branch never returns
        // through a normal C++ path -- it always _exit()s or exec's
        // below -- so the lock's destructor never runs on this side of the
        // fork either.
        //
        // New session/process group so the whole group can be SIGKILLed as
        // a unit on timeout, even if the target CLI spawns helper
        // processes. Only async-signal-safe calls from here on. Result is
        // checked (rather than silently discarded) but treated as
        // non-load-bearing: a failure here only degrades the timeout kill
        // to the direct child (kill_child_or_group()'s existing
        // ESRCH/EPERM fallback), not the captured output/exit code below,
        // so it does not go through report_setup_failure_and_exit.
        if (setsid() == -1) {
            // no-op: intentionally not load-bearing, see comment above.
        }

        // A3: reset signal disposition/mask to the exec'd tool's defaults.
        // SIG_IGN survives exec (POSIX) -- the agent daemon ignores SIGPIPE,
        // which an exec'd child would otherwise silently inherit. SIGXCPU/
        // SIGXFSZ are the two resource-limit-exceeded signals (paired with
        // A4/B3's RLIMIT_CORE/RLIMIT_CPU/RLIMIT_FSIZE below) -- there is no
        // "SIGXFPE" in POSIX (arithmetic exceptions raise plain SIGFPE,
        // which nothing here ignores or need reset). Plain syscalls, no
        // allocation; slotted beside setsid()/the dup2 block like the rest
        // of this async-signal-safe setup.
        {
            sigset_t empty_mask;
            sigemptyset(&empty_mask);
            sigprocmask(SIG_SETMASK, &empty_mask, nullptr);
            struct sigaction sa{};
            sa.sa_handler = SIG_DFL;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            sigaction(SIGPIPE, &sa, nullptr);
            sigaction(SIGXFSZ, &sa, nullptr);
            sigaction(SIGXCPU, &sa, nullptr);
        }

        // A4: always-on core-dump suppression -- one syscall, prevents a
        // tool segfault from dumping a core built from the daemon's
        // COW-shared secret heap.
        // A4 core-dump suppression is a security control (a segfault must never
        // dump the daemon's COW-shared secret heap), so a failure to apply it is
        // load-bearing: fail closed over the exec-error pipe rather than run a
        // child that could core. (BR-009)
        {
            struct rlimit core_limit{0, 0};
            if (setrlimit(RLIMIT_CORE, &core_limit) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        }

        // B3: optional per-invocation resource caps, OFF unless the caller set
        // them on SubprocessOptions::rlimits (surfaced here via `spec`). When a
        // cap IS requested, honoring it is the contract -- a failure fails closed
        // rather than silently running the child uncapped. (BR-009)
        if (spec.rlimits.cpu_seconds) {
            struct rlimit r{*spec.rlimits.cpu_seconds, *spec.rlimits.cpu_seconds};
            if (setrlimit(RLIMIT_CPU, &r) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        }
        if (spec.rlimits.address_space_bytes) {
#if defined(RLIMIT_AS)
            struct rlimit r{*spec.rlimits.address_space_bytes, *spec.rlimits.address_space_bytes};
            if (setrlimit(RLIMIT_AS, &r) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
#elif defined(RLIMIT_DATA)
            struct rlimit r{*spec.rlimits.address_space_bytes, *spec.rlimits.address_space_bytes};
            if (setrlimit(RLIMIT_DATA, &r) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
#endif
        }
        if (spec.rlimits.fsize_bytes) {
            struct rlimit r{*spec.rlimits.fsize_bytes, *spec.rlimits.fsize_bytes};
            if (setrlimit(RLIMIT_FSIZE, &r) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        }
        if (spec.rlimits.nofile_count) {
            struct rlimit r{*spec.rlimits.nofile_count, *spec.rlimits.nofile_count};
            if (setrlimit(RLIMIT_NOFILE, &r) != 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        }

        // A6: restrictive umask + a known-safe cwd (blunts DLL/`.so`
        // side-loading and world-writable-drop attacks). The header contract
        // promises the child NEVER runs in the daemon's own cwd, so a failed
        // chdir is load-bearing: fail closed rather than silently degrade to the
        // inherited (possibly attacker-influenced) directory. (BR-009)
        umask(0077);
        if (chdir(spec.working_dir.c_str()) != 0)
            report_setup_failure_and_exit(err_write_fd.get(), errno);

        // Both dup2s below ARE the plumbing that makes this invocation's
        // captured output/exit-code contract correct, so a failure here is
        // load-bearing: report it over the exec-error pipe and exit rather
        // than exec'ing with the wrong fd wired to stdout/stderr.
        if (dup2_retry(write_fd.get(), STDOUT_FILENO) == -1)
            report_setup_failure_and_exit(err_write_fd.get(), errno);
        if (opts.merge_stderr) {
            if (dup2_retry(write_fd.get(), STDERR_FILENO) == -1)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        } else {
            // CDX-006: silencing stderr to /dev/null is part of the runner's
            // stdio-isolation contract, so a failure to open or dup2 it is
            // load-bearing: fail closed rather than leave the child writing to
            // the daemon's own inherited stderr (its service log / controlling
            // terminal). We already own the exec-error pipe, so reporting is
            // possible -- treating it as best-effort was a policy choice, not an
            // inability.
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull < 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
            if (dup2_retry(devnull, STDERR_FILENO) == -1)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
            // CDX-P1-001/K3: with the parent's fd 2 closed, open() itself can
            // return STDERR_FILENO -- the dup2 above was then a no-op and an
            // unconditional close would undo the wiring it just did.
            if (devnull != STDERR_FILENO)
                close(devnull);
        }

        // ADR-3002 stdio policy: stdin -> /dev/null. CDX-006: also load-bearing
        // for the same reason -- a spawned CLI must not inherit and read the
        // agent daemon's stdin (consuming its input or blocking on it). Fail
        // closed if /dev/null cannot be wired to fd 0.
        {
            int devnull_in = open("/dev/null", O_RDONLY);
            if (devnull_in < 0)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
            if (dup2_retry(devnull_in, STDIN_FILENO) == -1)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
            // Same self-collision guard as the stderr /dev/null above: with
            // the parent's fd 0 closed, open() can return STDIN_FILENO itself.
            if (devnull_in != STDIN_FILENO)
                close(devnull_in);
        }

        close(read_fd.get());
        close(write_fd.get());
        close(err_read_fd.get());
        // err_write_fd stays open here: its CLOEXEC flag closes it
        // automatically on a successful execve(); on failure the code
        // below writes to it explicitly before exiting.

        // Inherited-fd sanitisation (review blocker). A newly exec'd helper --
        // often a privileged tool (security, codesign, launchctl, pkgutil) --
        // must not inherit any descriptor this agent or a linked library opened
        // without O_CLOEXEC: a gRPC connection socket, a SQLite database fd, or
        // anything else would otherwise leak into an external, possibly-root
        // process (information exposure + resource-lifetime hazard). global_fork_lock()
        // closes only the CLOEXEC *race* window between concurrent launchers'
        // own pipe creation; by its own contract it does NOT sanitise
        // already-open inherited fds (fork_lock.hpp, "non-forking pipe creators
        // are exposed too"). Mark every inherited fd >= 3 close-on-exec so exec()
        // drops them all. Deliberately mark rather than close: err_write_fd is
        // already CLOEXEC, so it survives this sweep -- auto-closing only on a
        // *successful* exec (the parent's success signal) while staying writable
        // to report an exec failure just below. The three own pipe fds were closed
        // above (fcntl on them now returns EBADF and is skipped); stdio (0/1/2) is
        // never in the >= 3 set.
        //
        // B2: on Linux >= 5.11, close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) does
        // this whole sweep in ONE syscall instead of the O(ceiling) fcntl loop
        // -- CLOSE_RANGE_CLOEXEC is mark-not-close (identical semantics to the
        // loop) and still runs POST-fork (identically race-free). A pre-5.11
        // kernel, a header set without SYS_close_range, or a sandboxed
        // environment that blocks the syscall falls straight through to the
        // UNMODIFIED fcntl loop (sweep_fd_range_cloexec_fallback), which
        // remains the only path on every other platform.
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC) != 0)
            sweep_fd_range_cloexec_fallback(child_fd_ceiling);
#else
        sweep_fd_range_cloexec_fallback(child_fd_ceiling);
#endif

        // BR-003: execve(), not execvpe()/execvp() -- neither is on Darwin's
        // async-signal-safe list because both do a PATH search (fopen()
        // internally on some libc implementations); every production
        // caller already passes an absolute tool path (e.g. /bin/sh,
        // /usr/bin/codesign), so no PATH search is ever needed here. A5's
        // explicit c_envp replaces the implicit environ execv() used to
        // read -- the child NEVER inherits this process' actual environment.
        if (spec.exec_verify.enabled) {
            toctou_verified_exec(c_argv.data(), c_envp.data(), spec.exec_verify, err_write_fd.get());
        }
        execve(c_argv[0], c_argv.data(), c_envp.data());
        // exec failed -- report why and exit; see
        // report_setup_failure_and_exit's comment above for the
        // EINTR-retry and unconditional-_exit(127) reasoning (shared with
        // the load-bearing setup checks above).
        report_setup_failure_and_exit(err_write_fd.get(), errno);
    }

    // Parent: fork() has returned and this is not the child branch --
    // release the pipe-creation lock now (see fork_lock.hpp's contract).
    fork_pipe_lock.unlock();

    // Parent: guard the child from here on so an exception anywhere below
    // (e.g. std::bad_alloc while collecting output) cannot leave it
    // running/unreaped or leak the pipe fds (RAII on the UniqueFds).
    ChildGuard guard(pid);

    // B5: best-effort readiness fd (see try_open_pidfd's comment) -- -1 on
    // anything but a >=5.3 Linux kernel, in which case the loop below falls
    // back to its historical fixed sleep exactly as before this feature
    // existed.
    UniqueFd pidfd_owner(try_open_pidfd(pid));

    write_fd.reset();     // only needed by the child
    err_write_fd.reset(); // only needed by the child

    int flags = fcntl(read_fd.get(), F_GETFL, 0);
    if (flags == -1 || fcntl(read_fd.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
        // Fail closed: without a confirmed non-blocking pipe fd, the read()
        // below could block indefinitely. The still-armed guard above kills
        // the child when it unwinds. CDX-P2-014: report this as a spawn_error
        // ONLY, never timed_out -- a setup failure is not a deadline breach,
        // and conflating the two misleads an autonomous caller's retry choice.
        result.timed_out = false;
        result.termination_reason = TerminationReason::spawn_error;
        return result;
    }
    int err_flags = fcntl(err_read_fd.get(), F_GETFL, 0);
    if (err_flags == -1 || fcntl(err_read_fd.get(), F_SETFL, err_flags | O_NONBLOCK) == -1) {
        result.timed_out = false; // spawn_error, not a timeout (CDX-P2-014)
        result.termination_reason = TerminationReason::spawn_error;
        return result;
    }

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool pipe_eof = false;
    bool child_reaped = false;
    bool err_pipe_open = true; // becomes false once exec success/failure is known
    bool exec_failed = false;  // true iff the child reported a failed execve()
    // True once exec is POSITIVELY confirmed to have happened: either the
    // exec-error pipe cleanly resolved to EOF while `killed` was still
    // false (so the resolution cannot be an artifact of our own kill
    // reaching the child before it got to execve()), or real output
    // arrived on the main pipe (only possible after a successful exec, no
    // matter when). A child killed in the narrow fork()-to-execve() window
    // -- reachable in practice when a cancel is already pending the moment
    // this function is called -- closes both its pipes exactly like a
    // successful exec would, so EOF alone cannot be trusted once a kill is
    // already in flight.
    bool exec_confirmed_ok = false;

    // ADR-3002 termination-reason bookkeeping: at most one of these becomes
    // true (all three guarded by `!killed` at the moment they'd be set; the
    // deadline/cancel pair additionally by `!child_reaped`, the K-5 twin
    // guard line_cap already had -- K1/CDX-P2-002), and together with
    // exec_confirmed_ok/exec_failed/natural_signaled below they determine
    // the final TerminationReason after the loop.
    bool killed_by_deadline = false;
    bool killed_by_cancel = false;
    bool killed_by_line_cap = false;
    // True iff the child died from a signal it received ITSELF (e.g. a
    // crash) -- never one this runner sent (guarded by `!killed` at the
    // moment try_reap() observes it, mirroring exec_confirmed_ok's own
    // "resolved before any kill was ever sent" reasoning).
    bool natural_signaled = false;

    // K-5: true iff try_reap() ever observes WIFEXITED. SIGKILL/SIGTERM can
    // never produce a WIFEXITED status (only WIFSIGNALED) -- so this is
    // unconditional proof the child ran to completion and exited ON ITS OWN
    // strictly before any of our kills could have taken effect, regardless
    // of which kill category (line_cap/cancel/deadline) happened to be
    // in-flight when we noticed. Without this, a child that exits naturally
    // in the same instant its output trips killed_by_line_cap (or any other
    // kill trigger) races try_reap() against the kill-decision branch below:
    // if the kill decision runs one loop iteration before try_reap() catches
    // up, killed_by_line_cap latches true even though our kill lands on an
    // already-exited (zombie) pid and does nothing. Deciding purely from the
    // reaped status -- rather than from child_reaped's value at kill-decision
    // time -- closes that race outright instead of narrowing the window.
    bool child_exited_normally = false;

    // ADR-3002 soft-terminate grace (SubprocessOptions::soft_terminate_grace,
    // 0 by default): when set, a deadline/cancel trigger sends SIGTERM to the
    // process group and waits up to the grace period before escalating to
    // the UNMODIFIED hard SIGKILL path below. hard_kill_sent/hard_kill_time
    // (rather than merely `killed`) drive the kDrainGrace break check, so
    // the grace period itself is never mistaken for the post-kill drain
    // window -- with soft_terminate_grace == 0 (every existing caller),
    // hard_kill_sent is set in the very same branch as killed, at the same
    // `now`, so this is a no-op for all current behaviour.
    bool soft_terminating = false;
    // K1/CDX-P2-002: soft_terminating is CONSUMED (reset) when the grace
    // escalates to the hard kill, so it cannot answer the only question the
    // final reason resolution needs -- "was a catchable SIGTERM ever actually
    // delivered?", the one case where a WIFEXITED status may legitimately be
    // our kill's doing (a child that trapped SIGTERM and exited during the
    // grace) rather than proof of a natural exit. Set alongside
    // soft_terminating, never reset.
    bool soft_term_sent = false;
    std::chrono::steady_clock::time_point soft_term_deadline{};
    bool hard_kill_sent = false;
    std::chrono::steady_clock::time_point hard_kill_time{};

    std::string line_buf;
    // CDX-P2-005: bytes already committed to result.lines. When max_lines is
    // unarmed (0 == unlimited) this is the backstop that keeps the STORED lines
    // bounded by output_cap now that line materialization runs over every
    // drained byte (so on_line stays an uncapped streaming primitive) rather
    // than only the blob-cap-admitted prefix.
    std::size_t stored_line_bytes = 0;
    std::array<char, 512> buf{};
    // Set once opts.stop_after_max_lines is armed and result.lines has just
    // reached opts.max_lines -- triggers a clean early kill+reap below,
    // distinct from a deadline/cancel kill.
    bool line_cap_stop = false;

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        // ADR-3002 streaming primitive: every completed line reaches the
        // caller's callback (if any) UNCAPPED -- neither max_lines nor the
        // output_cap blob budget gates it (CDX-P2-005: the caller's live
        // stream must not silently stop when stored capture saturates), AND
        // a blank completed line is delivered too (A2-006: "every completed
        // line" means every one -- a script's blank stdout lines produced a
        // wire record under both spawn paths this runner replaced, and the
        // doc comment above has always promised it uncapped, not
        // uncapped-except-empty). Only STORAGE below excludes blank lines --
        // callback delivery must happen before that early return, not after.
        if (opts.on_line)
            opts.on_line(line);
        if (line.empty())
            return;
        // result.lines (the collect-at-end snapshot) STAYS bounded: by
        // max_lines when armed, else by the output_cap byte budget -- so an
        // unlimited-max_lines run past the blob cap can't grow it without end.
        // sec-7: the output_cap byte budget applies REGARDLESS of whether
        // max_lines is armed -- previously an armed max_lines consulted ONLY
        // the count cap, so stored_line_bytes was never checked and
        // result.lines could grow up to max_lines * output_cap (each stored
        // line is separately capped at output_cap bytes by the line_buf
        // accumulator below), independent of the output_cap budget this same
        // cap is supposed to enforce on result.output. Both caps now apply
        // together whenever max_lines is armed.
        // BR-008 (whole-branch review round 2): comparing stored_line_bytes
        // against output_cap with a strict `<` only proved SOME budget
        // remained, not that THIS line's bytes fit within it -- a single
        // stored line can be up to output_cap bytes long (line_buf's own
        // accumulator caps it there), so a one-byte remainder could still
        // admit a whole second cap-sized line, letting result.lines grow to
        // nearly 2x the documented output_cap budget. Require the line's
        // OWN source-byte count (+1 for the terminating newline, same
        // accounting as below) to fit in the REMAINING budget instead.
        const std::size_t source_bytes = line.size() + 1;
        const bool line_room = source_bytes <= output_cap - stored_line_bytes &&
                               (opts.max_lines == 0 || result.lines.size() < opts.max_lines);
        if (line_room) {
            // +1 for the terminating newline: count the SOURCE bytes the line
            // consumed, matching output_cap's blob accounting so result.lines
            // stays bounded by the same cap as result.output (BR-001).
            stored_line_bytes += source_bytes;
            result.lines.push_back(std::move(line));
            if (opts.stop_after_max_lines && opts.max_lines != 0 &&
                result.lines.size() >= opts.max_lines)
                line_cap_stop = true;
        }
    };

    auto try_reap = [&]() {
        if (child_reaped)
            return;
        int status = 0;
        // B4: wait4() over waitpid() to capture rusage on the same
        // WNOHANG-confirmed reap -- a strict superset of the shipped
        // waitpid() call (identical semantics on every other axis).
        struct rusage ru{};
        pid_t waited;
        do {
            waited = wait4(pid, &status, WNOHANG, &ru);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid) {
            child_reaped = true;
            // BR-002: tell the guard immediately -- if an exception unwinds
            // into ~ChildGuard anywhere after this point (e.g. std::bad_alloc
            // in the output-collection code below), it must not signal pid_
            // directly since the kernel may have already recycled it.
            guard.mark_child_reaped();
            // Only ever set on a normal exit -- a signal-killed child (the
            // deadline/cancel/line-cap path below) leaves this at its -1
            // sentinel; WIFEXITED is false for a signal death, so there is
            // no path here that fabricates a WEXITSTATUS for one.
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
                child_exited_normally = true; // see the K-5 comment above
            } else if (WIFSIGNALED(status) && !killed) {
                // A signal death this runner did NOT initiate (killed is
                // still false) -- the child crashed or was signalled by
                // something else entirely, distinct from our own
                // deadline/cancel/line-cap kills below.
                natural_signaled = true;
            }
            result.child_user_time = std::chrono::microseconds(
                static_cast<long long>(ru.ru_utime.tv_sec) * 1'000'000LL + ru.ru_utime.tv_usec);
            result.child_system_time = std::chrono::microseconds(
                static_cast<long long>(ru.ru_stime.tv_sec) * 1'000'000LL + ru.ru_stime.tv_usec);
#if defined(__APPLE__)
            result.child_max_rss_kb = static_cast<std::uint64_t>(ru.ru_maxrss) / 1024;
#else
            result.child_max_rss_kb = static_cast<std::uint64_t>(ru.ru_maxrss);
#endif
        } else if (waited < 0 && errno == ECHILD) {
            child_reaped = true;
            guard.mark_child_reaped(); // BR-002: see comment above
        }
    };

    auto poll_err_pipe = [&]() {
        if (!err_pipe_open)
            return;
        std::array<char, sizeof(int)> probe{};
        ssize_t n = read(err_read_fd.get(), probe.data(), probe.size());
        if (n > 0) {
            exec_failed = true;
            // Surface WHY, not just THAT: report_setup_failure_and_exit's
            // write() is a single sizeof(int) shot (well under PIPE_BUF, so
            // POSIX guarantees it lands atomically) -- only trust a
            // full-width read as the errno; a short read stays the honest
            // 0/"unknown" default rather than reinterpreting partial bytes.
            if (n == static_cast<ssize_t>(sizeof(int)))
                std::memcpy(&result.spawn_errno, probe.data(), sizeof(int));
            err_pipe_open = false; // outcome decided; nothing more to learn
        } else if (n == 0) {
            err_pipe_open = false; // EOF: write end closed (CLOEXEC-on-exec, or child died)
            if (!killed)
                // Resolved before any kill was ever sent -- unambiguously a
                // successful exec, not a side effect of us killing a
                // not-yet-exec'd child (see exec_confirmed_ok's comment).
                exec_confirmed_ok = true;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            // not ready yet -- retry next iteration
        } else {
            err_pipe_open = false; // real read error: outcome stays unknown (tool_ran=false)
        }
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();

        // Reap and poll the exec-error pipe opportunistically and
        // non-blockingly every iteration. Pipe EOF alone does not prove
        // the child exited (only that no one holds the write end open),
        // so the loop must not treat EOF as "done" until the child is
        // independently confirmed dead.
        try_reap();
        poll_err_pipe();

        const bool deadline_hit = !killed && (now - start >= opts.deadline);
        const bool cancel_hit =
            !killed && (subprocess_cancel_requested() ||
                        (opts.cancel_token && opts.cancel_token->cancelled()));

        if (deadline_hit || cancel_hit) {
            // K1/CDX-P2-002 (the deadline/cancel twin of line_cap's K-5
            // guard at its own kill decision below): credit the reason flags
            // and timed_out only when the child was NOT already reaped --
            // try_reap() at the top of THIS iteration confirming the child
            // gone means the exit strictly predates this kill decision, so
            // reporting deadline/cancelled would fabricate a kill that never
            // happened. The kill escalation below still runs unconditionally:
            // a descendant may have outlived the reaped leader and be holding
            // the pipe open (CDX-002), and arming hard_kill_sent is what
            // bounds the remaining drain.
            if (!child_reaped) {
                result.timed_out = true;
                killed_by_deadline = deadline_hit;
                killed_by_cancel = !deadline_hit && cancel_hit;
            }
            killed = true;
            if (opts.soft_terminate_grace.count() > 0 && !child_reaped) {
                // ADR-3002 soft-terminate grace: give a mutating tool a
                // chance to finish an in-flight transaction before the hard
                // group kill below. The existing kDrainGrace-bounded poll
                // loop keeps running underneath -- if the child exits on its
                // own within the grace window, the normal child_reaped path
                // picks it up like any other exit.
                soft_terminate_child_or_group(pid);
                soft_terminating = true;
                soft_term_sent = true; // sticky, unlike soft_terminating
                soft_term_deadline = now + opts.soft_terminate_grace;
            } else if (child_reaped) {
                // try_reap() just above already confirmed this PID is gone
                // -- the kernel is free to have reused it for an unrelated
                // process, so kill_child_or_group()'s direct-child fallback
                // must never fire once reaped. Only the process GROUP id is
                // still meaningful (and only if it outlived its leader,
                // e.g. a still-running descendant); if that kill fails
                // there is nothing left that is safe to signal.
                (void)kill(-pid, SIGKILL);
                hard_kill_sent = true;
                hard_kill_time = now;
            } else {
                // Whole process group, not just the child; falls back to
                // the still-unreaped direct child if the group kill fails.
                kill_child_or_group(pid);
                hard_kill_sent = true;
                hard_kill_time = now;
            }
        } else if (!killed && line_cap_stop) {
            // Caller only wants the first opts.max_lines lines and asked
            // for a clean bounded stop rather than draining to the
            // deadline -- kill+reap exactly like a deadline, but this is
            // NOT a timeout: result.timed_out stays false. killed_by_line_cap
            // is only credited when our kill is actually what ends the
            // child (child_reaped already true here means it exited
            // naturally on its own in the same instant the cap was hit --
            // see the K-5 unit test -- and termination_reason correctly
            // falls through to `exited` with the child's real exit code
            // instead).
            killed = true;
            killed_by_line_cap = !child_reaped;
            if (child_reaped) {
                (void)kill(-pid, SIGKILL);
            } else {
                kill_child_or_group(pid);
            }
            hard_kill_sent = true;
            hard_kill_time = now;
        } else if (soft_terminating && now >= soft_term_deadline) {
            // Grace elapsed -- escalate to the hard kill REGARDLESS of whether the
            // leader has already been reaped (CDX-002; the POSIX twin of the
            // Windows BR-003 fix). A mutating CLI can handle SIGTERM and exit
            // during the grace while a descendant that ignores it inherits and
            // holds the stdout pipe: pipe_eof then never arrives and, with the
            // old `!child_reaped` guard, no hard kill was ever armed, so neither
            // loop-exit condition could fire and the worker hung indefinitely.
            // Signal the whole process GROUP so a surviving descendant is reached;
            // once the leader is reaped its pid may be recycled, so target the
            // group directly rather than kill_child_or_group's direct-child
            // fallback (BR-002 lineage). Arming hard_kill_sent bounds the drain.
            soft_terminating = false;
            if (child_reaped)
                (void)kill(-pid, SIGKILL);
            else
                kill_child_or_group(pid);
            hard_kill_sent = true;
            hard_kill_time = now;
        }

        if (child_reaped && pipe_eof && !err_pipe_open)
            break; // child is gone, stdout is drained, exec outcome known
        if (hard_kill_sent && now - hard_kill_time >= kDrainGrace)
            // Bounded grace after the HARD kill (never the soft-terminate
            // grace, which is bounded separately by soft_term_deadline
            // above): something is still holding a pipe open or hasn't been
            // reaped yet -- stop waiting rather than block indefinitely.
            break;

        if (pipe_eof) {
            // Nothing left to read, but the child isn't confirmed reaped
            // yet (or the exec outcome isn't resolved yet) -- keep polling
            // above without spinning on read().
            //
            // K-07/M-d: do NOT poll read_fd here. A pipe at EOF reports
            // POLLHUP permanently, so poll() returns IMMEDIATELY every
            // iteration -- on the Linux pidfd fast path (pidfd >= 0) that is a
            // 100% CPU busy-spin until the child exits or the deadline fires
            // (a per-call, fleet-wide amplifiable DoS for a root daemon). Poll
            // only the still-open err pipe (if any) and the pidfd; pass -1 for
            // any EOF'd/closed fd so poll() skips it. With neither pollable and
            // no pidfd, wait_for_activity falls back to a brief sleep (the
            // macOS path, which never spun).
            wait_for_activity(-1, err_pipe_open ? err_read_fd.get() : -1,
                              pidfd_owner.get(), 5'000'000L);
            continue;
        }

        ssize_t n = read(read_fd.get(), buf.data(), buf.size());
        if (n > 0) {
            // Real bytes on the main pipe are only possible after a
            // successful execve() (the child produces nothing before it) --
            // unambiguous regardless of `killed`'s state, unlike the
            // err-pipe EOF check above.
            exec_confirmed_ok = true;

            // Cap the STORED blob at output_cap total (ADR-3002: caller-
            // configurable, clamped to [1, 16MiB] -- see output_cap above),
            // applied per-append so it never overshoots by up to one read's
            // worth. This bound governs result.output only.
            const auto avail =
                result.output.size() < output_cap ? output_cap - result.output.size() : std::size_t{0};
            const auto take = static_cast<std::size_t>(n) < avail ? static_cast<std::size_t>(n) : avail;
            if (take > 0)
                result.output.append(buf.data(), take);
            if (take < static_cast<std::size_t>(n))
                result.output_truncated = true;

            // CDX-P2-005: materialize lines over EVERY drained byte (all `n`,
            // not just the `take` prefix admitted to the blob) so on_line -- a
            // streaming primitive -- keeps firing after the blob cap saturates.
            // The line accumulator is separately bounded to output_cap with
            // explicit per-line truncation, and store_line keeps result.lines
            // bounded (see its byte budget), so neither grows without bound on
            // a newline-free or adversarially long stream.
            for (ssize_t i = 0; i < n; ++i) {
                char ch = buf[static_cast<std::size_t>(i)];
                if (ch == '\n') {
                    store_line(std::move(line_buf));
                    line_buf.clear();
                } else if (line_buf.size() < output_cap) {
                    line_buf += ch;
                } else {
                    result.output_truncated = true;
                }
            }
        } else if (n == 0) {
            pipe_eof = true; // EOF: writer(s) closed their end
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // K-03/CDX-R4-07: exclude the err pipe from the poll once it has
            // resolved to EOF -- a HUP'd fd polls ready forever and would busy-
            // spin the pidfd fast path here exactly as it did on the pipe_eof
            // branch (M-d). read_fd is still live (we just got EAGAIN on it), so
            // it stays in the set; pass -1 for the closed err pipe.
            wait_for_activity(read_fd.get(), err_pipe_open ? err_read_fd.get() : -1,
                              pidfd_owner.get(), killed ? 5'000'000L : 10'000'000L);
            continue;
        } else if (errno == EINTR) {
            continue;
        } else {
            pipe_eof = true; // real read error: stop trying to read further
        }
    }

    read_fd.reset();
    err_read_fd.reset();

    if (!line_buf.empty())
        store_line(std::move(line_buf));

    // The loop above exits with child_reaped == true except via the
    // kDrainGrace escape hatch -- one last non-blocking check covers that,
    // then the guard is discharged only once reap is confirmed. If the
    // child is somehow still alive, the guard's destructor forcibly kills
    // it and reaps it with its own bounded poll / async-thread fallback --
    // this worker thread is never held up past that bound, regardless of
    // how long the child takes to actually die.
    try_reap();
    if (child_reaped)
        guard.discharge();

    // tool_ran is true iff exec was positively confirmed (exec_confirmed_ok)
    // and the child never reported an execve() failure -- never inferred
    // from exit_code. exec_confirmed_ok stays false both for a genuinely
    // unresolved outcome (e.g. the loop exited via the kDrainGrace escape
    // hatch on a pathological hang) and for a child killed before it ever
    // reached execve(): either way, tool_ran stays false, an honest
    // "unknown" rather than a guess.
    result.tool_ran = exec_confirmed_ok && !exec_failed;

    // ADR-3002: the explicit termination reason. A GENUINE spawn failure is
    // exec_failed (the child positively reported a failed execve() on the
    // error pipe) -- that is checked first and always wins. A deliberate
    // kill by us (line_cap/cancel/deadline; mutually exclusive) is then
    // classified by its reason EVEN IF exec was never positively confirmed:
    // when a pre-armed cancel or a tight deadline kills the child on the very
    // first poll, poll_err_pipe() has not yet seen the CLOEXEC-on-exec EOF, so
    // exec_confirmed_ok (hence tool_ran) is still false -- but that is a
    // cancellation/deadline, NOT a spawn failure. Only once none of those
    // apply does a still-unconfirmed exec fall through to spawn_error.
    // Deliberately NOT fabricating an exit_code=0 for the line_cap case (the
    // removed pre-ADR-3002 sentinel fixup) -- callers distinguish "deliberate
    // clean stop" from "failure" via this field, never via a synthesized code.
    //
    // K-5: killed_by_line_cap is deliberately overridden by child_exited_
    // normally (WIFEXITED observed) -- see its declaration comment for why a
    // genuine WIFEXITED always outranks a killed_by_line_cap that raced it
    // (our kill decision can latch true one loop iteration before try_reap()
    // catches up to a child that already exited on its own).
    //
    // K1/CDX-P2-002: the SAME override now applies to killed_by_cancel/
    // killed_by_deadline, with one carve-out the line_cap path doesn't need:
    // those two can escalate via soft_terminate_grace's SIGTERM first, which
    // a child may legitimately trap and voluntarily exit(0) from -- a
    // WIFEXITED our own signal directly caused. soft_term_sent records
    // whether that catchable signal was ever actually delivered; when it was
    // not (the default soft_terminate_grace=0 path is SIGKILL-only, exactly
    // like line_cap), WIFEXITED is unconditional proof of a natural exit and
    // deadline/cancelled would be a fabricated kill. timed_out is re-cleared
    // on the override so callers keying on it (see SubprocessResult) never
    // see "timed out" paired with the honest `exited`.
    const bool natural_exit_overrides_kill = child_exited_normally && !soft_term_sent;
    if (exec_failed) {
        result.termination_reason = TerminationReason::spawn_error;
    } else if (killed_by_line_cap && !child_exited_normally) {
        result.termination_reason = TerminationReason::line_limit;
    } else if (killed_by_cancel && !natural_exit_overrides_kill) {
        result.termination_reason = TerminationReason::cancelled;
    } else if (killed_by_deadline && !natural_exit_overrides_kill) {
        result.termination_reason = TerminationReason::deadline;
    } else if (!result.tool_ran) {
        // exec never positively confirmed and we did not deliberately kill it
        // -- a real spawn failure the error pipe could not attribute.
        result.termination_reason = TerminationReason::spawn_error;
    } else if (natural_signaled) {
        result.termination_reason = TerminationReason::signaled;
    } else {
        result.termination_reason = TerminationReason::exited;
    }
    if ((killed_by_deadline || killed_by_cancel) && natural_exit_overrides_kill)
        result.timed_out = false;

    return result;
}

std::string probe_tool_path(const std::vector<std::string>& candidates) {
    for (const auto& c : candidates) {
        if (!detail::is_absolute_path(c))
            continue;
        struct stat st{};
        if (::stat(c.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(c.c_str(), X_OK) == 0)
            return c;
    }
    return {};
}

#else // _WIN32

// Windows system/standard headers live in the top-of-file preamble (see the
// #else _WIN32 branch there) -- NOT here, inside namespace yuzu::agent.

namespace {

// RAII HANDLE owner -- the Windows twin of the POSIX UniqueFd above. Also
// stands in for POSIX's ChildGuard: job_h below is created with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so simply destroying it (an ordinary
// RAII destructor, fired on any early return OR an exception unwinding
// through this function) terminates the process -- no separate guard class
// is needed on this platform.
//
// reset() has NO same-value guard, exactly like its POSIX UniqueFd twin
// above -- see yuzu/agent/scoped_fd.hpp's doc comment for the three-way
// reset()-contract cross-reference across this codebase.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE h) : h_(h) {}
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : h_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.release();
        }
        return *this;
    }
    ~UniqueHandle() { reset(); }

    HANDLE get() const { return h_; }
    HANDLE release() {
        HANDLE h = h_;
        h_ = nullptr;
        return h;
    }
    void reset(HANDLE h = nullptr) {
        if (h_ != nullptr && h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
        h_ = h;
    }

private:
    HANDLE h_ = nullptr;
};

// CDX-R4-05: delegate to the canonical shared helper rather than re-rolling
// MultiByteToWideChar (docs/cpp-conventions.md "Windows string conversion"),
// so a future fix in win_str.hpp reaches the subprocess backend too. Same
// precedent as dex_observer.cpp.
std::wstring utf8_to_wide(const std::string& s) {
    return yuzu::win::to_wide(s);
}

} // namespace

const std::string& windows_system_directory() {
    // BR3-001 (whole-branch review round 3): resolved once, cached for the
    // process's lifetime -- the system directory cannot change while this
    // process is running, and this is called on every Windows spawn whose
    // working_dir defaults ("/" sentinel, mapped below) plus every
    // Windows-plugin caller (e.g. script_exec's PowerShell path) that needs
    // a trusted absolute System32 path. Same pattern as
    // quarantine_plugin.cpp's netsh_path(): an honest empty return on
    // failure, never a guessed fallback -- callers fail closed on it.
    static const std::string dir = [] {
        wchar_t buf[MAX_PATH]{};
        UINT n = GetSystemDirectoryW(buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return std::string{};
        return yuzu::win::from_wide(buf);
    }();
    return dir;
}

SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                         const SubprocessOptions& opts) {
    SubprocessResult result;
    if (argv.empty())
        return result;

    LaunchOptions launch_opts;
    launch_opts.working_dir = opts.working_dir;
    launch_opts.merge_stderr = opts.merge_stderr;
    {
        wchar_t tz_buf[64];
        DWORD n = GetEnvironmentVariableW(L"TZ", tz_buf, 64);
        if (n > 0 && n < 64) {
            int u8len = WideCharToMultiByte(CP_UTF8, 0, tz_buf, static_cast<int>(n), nullptr, 0,
                                             nullptr, nullptr);
            if (u8len > 0) {
                std::string tz(static_cast<std::size_t>(u8len), '\0');
                WideCharToMultiByte(CP_UTF8, 0, tz_buf, static_cast<int>(n), tz.data(), u8len, nullptr,
                                     nullptr);
                launch_opts.tz = tz;
            }
        }
    }
    // DESIGNATED, not positional: SubprocessOptions::RlimitCaps and
    // LaunchOptions' rlimits are field-identical but SEPARATE types (the
    // launch-spec header is deliberately independent of the runner header), so
    // a positional brace-init silently mis-maps if either side is ever
    // reordered. Designators must appear in declaration order, so a reorder
    // becomes a COMPILE ERROR here instead of a wrong rlimit at runtime.
    launch_opts.rlimits = {.cpu_seconds = opts.rlimits.cpu_seconds,
                           .address_space_bytes = opts.rlimits.address_space_bytes,
                           .fsize_bytes = opts.rlimits.fsize_bytes,
                           .nofile_count = opts.rlimits.nofile_count};
    launch_opts.exec_verify = {.enabled = opts.exec_verify.enabled,
                               .require_root_owned = opts.exec_verify.require_root_owned,
                               .expected_size = opts.exec_verify.expected_size};
    // extra_env: SubprocessOptions::extra_env (vector<pair<string,string>>)
    // and LaunchOptions::extra_env (vector<EnvVar>) are field-identical but
    // SEPARATE types -- same reason as rlimits/exec_verify above -- so this
    // is a manual element copy rather than a brace-init.
    launch_opts.extra_env.reserve(opts.extra_env.size());
    for (const auto& [key, value] : opts.extra_env)
        launch_opts.extra_env.push_back({key, value});
    // A2-002: THIS backend is the one that actually honours the flag -- see
    // the env-block construction below and SubprocessOptions::
    // inherit_parent_env's doc comment for the full contract.
    launch_opts.inherit_parent_env = opts.inherit_parent_env;
    // BR4-007: THIS backend is the one that actually honours no_window --
    // see the create_flags computation below and SubprocessOptions::
    // no_window's doc comment for the full contract.
    launch_opts.no_window = opts.no_window;

    LaunchSpec spec = build_launch_spec(argv, launch_opts);
    if (spec.error != LaunchSpecError::none)
        return result; // relative argv[0], embedded NUL, or a banned .bat/.cmd/.com
                        // argv[0] (CVE-2024-24576; ADR-3002:537-606)

    // BR-004: the Windows TOCTOU-safe exec verification (share-mode open +
    // Authenticode/size check before CreateProcessW) is NOT implemented yet.
    // A security control that silently no-ops is worse than an honest refusal,
    // so fail closed when a caller enables it on Windows rather than launching
    // unverified. (No in-tree caller enables it in this PR.)
    if (spec.exec_verify.enabled) {
        result.termination_reason = TerminationReason::spawn_error;
        return result;
    }

    const std::size_t output_cap = std::clamp<std::size_t>(opts.output_cap_bytes, 1, 16 * 1024 * 1024);

    const std::wstring app = utf8_to_wide(spec.argv.front());
    std::wstring cmdline = utf8_to_wide(spec.windows_command_line);

    // A5 (ordinary case): explicit lpEnvironment built from the SAME
    // allow-list build_launch_spec assembled -- never NULL/never inherited.
    //
    // A2-002 (opt-in exception, script_exec's Windows-parity ruling): when
    // inherit_parent_env is set, swap the BASE for this merge from the A5
    // allow-list to a live read of this process' own real environment block
    // -- reproducing the deleted CreateProcessA call's null-lpEnvironment
    // behaviour (full parent-environment inheritance) -- and layer extra_env
    // on top of THAT base via the exact same merge_launch_env()
    // replace-never-duplicate semantics used below for the ordinary case.
    // extra_env was already validated (denylist/malformed-entry checks) by
    // build_launch_spec() above UNCONDITIONALLY, so nothing here can smuggle
    // a denied name through just because this flag is set. This whole block
    // is the impure boundary layer this flag's contract requires: reading
    // GetEnvironmentStringsW() is real OS I/O that subprocess_launch_spec.hpp
    // (a pure header) must never perform itself.
    std::vector<EnvVar> sorted_env;
    // BR-002 (whole-branch review round 2): the `=X:` per-drive current-
    // directory pseudo-entries below (e.g. "=C:=C:\Users\foo") are excluded
    // from `parent_env`/`sorted_env` (they are not real, settable
    // environment variable NAMES -- see the loop comment) but are still
    // part of process-environment inheritance semantics per the CreateProcess
    // contract: they carry each drive's current directory, and Windows
    // itself always emits them at the FRONT of GetEnvironmentStringsW()'s
    // block, ahead of the alphabetically sorted real variables. Dropping
    // them (the previous behaviour) meant a caller relying on `D:relative`
    // path resolution after this migration silently lost that state.
    // Collected as raw wide entries (never round-tripped through
    // EnvVar/UTF-8 -- they are not KEY=VALUE pairs in the ordinary sense)
    // and serialized verbatim ahead of `sorted_env` below.
    std::vector<std::wstring> drive_pseudo_vars;
    if (spec.inherit_parent_env) {
        std::vector<EnvVar> parent_env;
        // BR-004 (whole-branch review): GetEnvironmentStringsW() returns an
        // OWNED block that used to be released only by a later, lexically
        // paired FreeEnvironmentStringsW() call below -- lexical pairing is
        // not ownership proof, because std::wstring construction/append and
        // parent_env.push_back() between acquisition and that call are NOT
        // noexcept. An exception thrown from any of them (allocation
        // failure snapshotting a large service environment block, most
        // plausibly) would skip the free entirely and leak the block; the
        // agent's plugin exception firewall catches the exception, so the
        // process survives to leak it again on the next inherit_parent_env
        // call. Wrap the pointer in a scope-owning RAII guard immediately
        // on acquisition instead, so every exit path -- normal fall-through
        // OR an exception unwinding through this scope -- releases it
        // exactly once via the destructor, never a manual call.
        struct EnvironmentStringsDeleter {
            void operator()(wchar_t* value) const noexcept {
                if (value)
                    FreeEnvironmentStringsW(value);
            }
        };
        std::unique_ptr<wchar_t, EnvironmentStringsDeleter> env_strings{
            GetEnvironmentStringsW()};
        // BR-008 (whole-branch review): a null return here used to fall
        // through silently, launching the child with an EMPTY parent-env
        // base plus only opts.extra_env's few named overrides -- the
        // OPPOSITE of inherit_parent_env's contract (full parent-env
        // inheritance), with no error signalled anywhere. Fail the spawn
        // instead: a caller that opted into full inheritance and can't get
        // it should see spawn_error, not a child silently missing the
        // credentials/proxy/tool configuration the parent's real
        // environment would have carried.
        if (!env_strings) {
            result.termination_reason = TerminationReason::spawn_error;
            return result;
        }
        for (const wchar_t* p = env_strings.get(); *p != L'\0';) {
            std::wstring entry(p);
            p += entry.size() + 1;
            // BR-002: Windows' per-drive "=C:=C:\..." pseudo-variables are
            // not a real, settable environment variable NAME (a leading '='
            // means merge_launch_env/EnvVar's ordinary KEY=VALUE model does
            // not apply), so they never go through parent_env/merge_launch_env
            // -- but they ARE still part of what CreateProcessW's contract
            // means by "the parent's environment", so preserve them verbatim
            // for later, rather than discarding them entirely as the
            // previous version of this loop did.
            if (entry.empty() || entry.front() == L'=') {
                if (!entry.empty())
                    drive_pseudo_vars.push_back(std::move(entry));
                continue;
            }
            auto eq = entry.find(L'=');
            if (eq == std::wstring::npos)
                continue; // malformed entry with no '=' at all -- skip, don't guess
            parent_env.push_back({yuzu::win::from_wide(entry.substr(0, eq).c_str()),
                                  yuzu::win::from_wide(entry.substr(eq + 1).c_str())});
        }
        // env_strings releases here (scope exit), on every path including
        // an exception from the loop body above.
        //
        // BR-005 (adversarial review, HIGH): the POSIX backend above strips
        // the ADR-3002 A5 injection class (LD_*/DYLD_*/IFS/BASH_ENV/ENV/
        // GCONV_PATH/NLSPATH/LOCPATH) from an inherited parent environment
        // via filter_inherited_env() BEFORE merging -- this branch used to
        // merge the raw parent_env directly, so a Windows child opting into
        // inherit_parent_env received the agent process' full, unfiltered
        // environment (variables such as PROMPT/COMSPEC-adjacent injection
        // vectors this process itself never authored). Apply the identical
        // filter here so both backends enforce the same fail-closed
        // contract; log what was withheld the same way the POSIX backend
        // does, for the same observability reason (filter_inherited_env's
        // own comment above).
        EnvInheritResult filtered = filter_inherited_env(parent_env, /*windows=*/true);
        for (const auto& name : filtered.stripped) {
            spdlog::debug("run_bounded_subprocess: withholding inherited env var '{}' from the "
                         "child (ADR-3002 A5 injection class, inherit_parent_env)",
                         name);
        }
        sorted_env = merge_launch_env(filtered.env, launch_opts.extra_env, /*windows=*/true).env;
    } else {
        sorted_env.assign(spec.env.begin(), spec.env.end());
    }
    //
    // K-10/L-d: a CreateProcess environment block MUST be sorted (MSDN:
    // "the block must be sorted alphabetically by name, case-insensitively, as
    // in Unicode order"). Both branches above emit their result in a fixed
    // but not-necessarily-sorted order, so sort a copy by upper-cased key here
    // before serializing. The keys are unique (allow-list / merge dedup), so
    // a stable name sort is total.
    // BR-003 (whole-branch review round 2): CreateProcess's own contract
    // (MSDN) requires the block "sorted alphabetically... case-insensitively,
    // as in Unicode order" -- a locale-independent ORDINAL comparison. The
    // previous comparator upper-cased individual UTF-8 BYTES
    // (std::toupper, which is also C-locale-dependent -- see
    // to_upper_ascii's own comment in subprocess_launch_spec.hpp for why a
    // security-adjacent comparison must never depend on process locale
    // state), which is correct only for ASCII names and produces an
    // unspecified, non-ordinal order for any non-ASCII byte -- reachable
    // only via a genuinely non-ASCII INHERITED parent-environment variable
    // name (extra_env's own is_malformed_env_entry check already rejects a
    // non-ASCII name fail-closed, so this gap cannot come from there).
    // CompareStringOrdinal is the actual Win32 primitive CreateProcessW's
    // own contract is defined against -- use it directly on the wide form
    // rather than re-deriving ordinal comparison by hand.
    std::sort(sorted_env.begin(), sorted_env.end(), [](const EnvVar& a, const EnvVar& b) {
        const std::wstring wa = utf8_to_wide(a.key);
        const std::wstring wb = utf8_to_wide(b.key);
        return CompareStringOrdinal(wa.c_str(), -1, wb.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });
    std::wstring env_block;
    // BR-002: the `=X:` drive-current-directory pseudo-entries go FIRST,
    // matching the order Windows itself always uses in
    // GetEnvironmentStringsW()'s own block -- empty on the ordinary A5 case
    // (drive_pseudo_vars is only ever populated inside the inherit_parent_env
    // branch above), so this is a strict no-op there.
    for (const auto& raw : drive_pseudo_vars) {
        env_block += raw;
        env_block += L'\0';
    }
    for (const auto& e : sorted_env) {
        env_block += utf8_to_wide(e.key + "=" + e.value);
        env_block += L'\0';
    }
    env_block += L'\0'; // double-NUL terminator
    std::vector<wchar_t> env_buf(env_block.begin(), env_block.end());

    // A6: safe, non-writable working directory. BR3-001 (whole-branch
    // review round 3): resolved via windows_system_directory()
    // (GetSystemDirectoryW) rather than trusted as a hard-coded
    // "C:\Windows\System32" literal -- an install with Windows on a
    // non-C: volume would otherwise default every migrated action into an
    // untrusted, attacker-populatable directory tree. Fails the spawn
    // (never falls back to the old literal) if resolution fails, matching
    // the null-GetEnvironmentStringsW handling above.
    std::wstring cwd;
    if (spec.working_dir == "/") {
        const std::string& sys_dir = windows_system_directory();
        if (sys_dir.empty()) {
            result.termination_reason = TerminationReason::spawn_error;
            return result;
        }
        cwd = utf8_to_wide(sys_dir);
    } else {
        cwd = utf8_to_wide(spec.working_dir);
    }

    // Output pipe: only the WRITE end must ever be inheritable, and only it is
    // named in the handle allow-list below (A1) -- the read end must never be.
    //
    // xplat-A3: CreatePipe takes exactly ONE SECURITY_ATTRIBUTES that applies
    // to BOTH handles it returns -- there is no way to ask for one end
    // inheritable and the other not in the same call. Creating the pipe with
    // bInheritHandle=TRUE and then de-inheriting read_h with a SEPARATE,
    // later SetHandleInformation call (as this used to) leaves a real window
    // between the two calls where BOTH ends are inheritable: a concurrent
    // CreateProcess(bInheritHandles=TRUE) on another thread -- one that does
    // NOT restrict inheritance via its own PROC_THREAD_ATTRIBUTE_HANDLE_LIST
    // -- could inherit read_h into an unrelated child in that gap. Instead,
    // create BOTH ends non-inheritable (read_h therefore never passes
    // through an inheritable state at all) and produce the one inheritable
    // handle this invocation needs via DuplicateHandle, dropping the
    // non-inheritable original -- there is no window in which read_h is ever
    // inheritable.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    HANDLE read_raw = nullptr;
    HANDLE write_raw = nullptr;
    if (!CreatePipe(&read_raw, &write_raw, &sa, 0))
        return result;
    UniqueHandle read_h(read_raw);
    UniqueHandle write_noninherit_h(write_raw);
    HANDLE write_inheritable_raw = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), write_noninherit_h.get(), GetCurrentProcess(),
                          &write_inheritable_raw, 0, /*bInheritHandle=*/TRUE, DUPLICATE_SAME_ACCESS))
        return result;
    write_noninherit_h.reset(); // the non-inheritable original is no longer needed
    UniqueHandle write_h(write_inheritable_raw);

    // H3 / CDX-P2-002: stdin and (when unmerged) stderr must be backed by REAL
    // NUL handles, not null HANDLEs. Under STARTF_USESTDHANDLES a null handle is
    // NOT the NUL device -- a child that reads stdin or writes unmerged stderr
    // then sees invalid-handle behavior instead of the POSIX-equivalent
    // EOF/discard the ADR-3002 stdio policy promises. Open inheritable handles to
    // "NUL" and fail closed on error (the POSIX twin fail-closes on /dev/null).
    SECURITY_ATTRIBUTES nul_sa{};
    nul_sa.nLength = sizeof(nul_sa);
    nul_sa.bInheritHandle = TRUE;
    UniqueHandle nul_in(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    &nul_sa, OPEN_EXISTING, 0, nullptr));
    if (nul_in.get() == INVALID_HANDLE_VALUE)
        return result; // spawn_error, tool_ran false
    UniqueHandle nul_out;
    if (!spec.merge_stderr) {
        nul_out.reset(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &nul_sa, OPEN_EXISTING, 0, nullptr));
        if (nul_out.get() == INVALID_HANDLE_VALUE)
            return result;
    }

    // A1: STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming ONLY the
    // handles this launch actually inherits -- the stdout pipe plus the NUL std
    // handles above -- never a blanket "everything inheritable" pattern.
    // merge_stderr shares the SAME pipe as stdout.
    std::vector<HANDLE> inherit_list;
    inherit_list.push_back(write_h.get());
    inherit_list.push_back(nul_in.get());
    if (!spec.merge_stderr)
        inherit_list.push_back(nul_out.get());

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    if (attr_size == 0)
        return result;
    std::vector<unsigned char> attr_buf(attr_size);
    // cpp-safety F4: attr_buf.data() is guaranteed aligned to at least
    // alignof(std::max_align_t) -- the standard's guarantee for any
    // std::vector's dynamically-allocated storage, the same guarantee
    // malloc()/operator new make -- which meets or exceeds
    // PROC_THREAD_ATTRIBUTE_LIST's own alignment requirement, so this
    // reinterpret_cast never yields a misaligned pointer.
    auto* attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size))
        return result;
    struct AttrListGuard {
        LPPROC_THREAD_ATTRIBUTE_LIST list;
        ~AttrListGuard() { DeleteProcThreadAttributeList(list); }
    } attr_guard{attr_list};

    if (!UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    inherit_list.data(), inherit_list.size() * sizeof(HANDLE),
                                    nullptr, nullptr))
        return result;

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdOutput = write_h.get();
    si.StartupInfo.hStdError = spec.merge_stderr ? write_h.get() : nul_out.get();
    si.StartupInfo.hStdInput = nul_in.get(); // stdio policy: stdin -> NUL (POSIX /dev/null twin)
    si.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED: the child is created suspended and assigned to the
    // kill-on-close Job Object below BEFORE it is ever resumed (ADR-3002:
    // avoids the child-before-job race a create-then-assign order allows).
    // CREATE_NEW_PROCESS_GROUP gives the group a CTRL_BREAK target for
    // soft_terminate_grace -- the Windows twin of POSIX's process-group
    // SIGTERM.
    // BR4-007 (whole-branch review round 4): CREATE_NO_WINDOW, opt-in via
    // spec.no_window (SubprocessOptions::no_window's doc comment has the
    // full contract) -- suppresses a visible console window for a migrated
    // caller whose deleted private Windows launcher used to set this flag
    // itself. Does not otherwise change CREATE_NEW_PROCESS_GROUP's
    // CTRL_BREAK target.
    const DWORD create_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP |
                                (spec.no_window ? CREATE_NO_WINDOW : 0);

    std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
    cmdline_buf.push_back(L'\0'); // CreateProcessW requires a MUTABLE lpCommandLine buffer

    BOOL created =
        CreateProcessW(app.c_str(),        // explicit absolute lpApplicationName
                        cmdline_buf.data(), // CRT-compatible (Colascione) quoted command line
                        nullptr, nullptr,
                        TRUE, // required for the handle list above to take effect --
                              // PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricts what
                              // ACTUALLY inherits to exactly the one named handle,
                              // so this is NOT the banned blanket-inherit pattern
                              // (A1 bans inheriting everything WITHOUT a
                              // restricting handle list, which this call always
                              // supplies)
                        create_flags,
                        env_buf.data(), // A5: explicit lpEnvironment, never NULL
                        cwd.c_str(), &si.StartupInfo, &pi);
    write_h.reset(); // the parent's own copy of the write end is no longer needed
    if (!created)
        return result;
    UniqueHandle process_h(pi.hProcess);
    UniqueHandle thread_h(pi.hThread);

    // Kill-on-close Job Object, assigned BEFORE resume.
    HANDLE job_raw = CreateJobObjectW(nullptr, nullptr);
    if (job_raw == nullptr) {
        TerminateProcess(process_h.get(), 1);
        return result;
    }
    UniqueHandle job_h(job_raw);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // B3 (optional, off by default): the nearest Windows equivalent of POSIX
    // RLIMIT_AS, carried on the Job Object.
    if (spec.rlimits.address_space_bytes) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        jeli.ProcessMemoryLimit = static_cast<SIZE_T>(*spec.rlimits.address_space_bytes);
    }
    // K-10/L-d: honour the rest of the rlimit request Windows CAN enforce rather
    // than silently dropping it (POSIX applies all four). cpu_seconds maps to the
    // Job Object per-process user-time limit (100 ns units), the documented
    // Windows analogue of RLIMIT_CPU. fsize_bytes (RLIMIT_FSIZE) and nofile_count
    // (RLIMIT_NOFILE) have NO Job Object equivalent -- Windows offers no
    // per-process write-size or handle-count cap here -- so they are not
    // enforceable on this backend; this is documented rather than pretended.
    if (spec.rlimits.cpu_seconds) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart =
            static_cast<LONGLONG>(*spec.rlimits.cpu_seconds) * 10'000'000LL; // s -> 100 ns
    }
    // BR-003: without kill-on-close the Job cannot guarantee descendant cleanup
    // (and the deadline path below relies on TerminateJobObject reaching a
    // descendant that outlives the leader), so a failure to configure it is
    // load-bearing -- fail closed rather than launch an uncontained child.
    if (!SetInformationJobObject(job_h.get(), JobObjectExtendedLimitInformation, &jeli,
                                 sizeof(jeli))) {
        TerminateProcess(process_h.get(), 1);
        return result; // termination_reason stays spawn_error, tool_ran false
    }
    if (!AssignProcessToJobObject(job_h.get(), process_h.get())) {
        TerminateProcess(process_h.get(), 1);
        return result;
    }
    // CDX-007: a ResumeThread failure (returns DWORD(-1)) would leave the child
    // suspended until the deadline killed the Job, misreporting a launch failure
    // as `deadline`. Check it and fail closed as spawn_error, consistent with the
    // Job creation/config/assign checks above.
    if (ResumeThread(thread_h.get()) == static_cast<DWORD>(-1)) { // suspended -> assigned -> resumed, in that exact order
        TerminateJobObject(job_h.get(), 1);
        return result; // termination_reason stays spawn_error, tool_ran false
    }
    thread_h.reset();

    constexpr auto kDrainGrace = std::chrono::milliseconds(2000);

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool killed_by_deadline = false;
    bool killed_by_cancel = false;
    bool killed_by_line_cap = false;
    bool soft_terminating = false;
    std::chrono::steady_clock::time_point soft_term_deadline{};
    bool hard_kill_sent = false;
    std::chrono::steady_clock::time_point hard_kill_time{};
    bool pipe_eof = false;
    bool process_exited = false;
    bool line_cap_stop = false;
    std::string line_buf;
    // CDX-P2-005: see the POSIX loop -- byte budget that keeps STORED lines
    // bounded by output_cap when max_lines is unarmed, now that line
    // materialization runs over every drained byte.
    std::size_t stored_line_bytes = 0;
    // K-03/M-c: a 64 KiB drain buffer (vs the old 512 B) reads a full pipe's
    // worth per ReadFile so a high-output child drains in far fewer iterations.
    std::array<char, 65536> buf{};

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        // Uncapped streaming primitive (CDX-P2-005): every completed line
        // reaches the callback regardless of max_lines or the blob cap, AND
        // a blank completed line is delivered too (A2-006 -- see the POSIX
        // loop's store_line for the full reasoning; this is the same fix,
        // mirrored). Only STORAGE below excludes blank lines.
        if (opts.on_line)
            opts.on_line(line);
        if (line.empty())
            return;
        // result.lines stays bounded: by max_lines when armed, else by the
        // output_cap byte budget. sec-7: the byte budget applies REGARDLESS
        // of whether max_lines is armed -- see the POSIX loop's store_line
        // for the full reasoning (an armed max_lines used to skip the
        // stored_line_bytes check entirely, letting result.lines grow up to
        // max_lines * output_cap).
        // BR-008 (whole-branch review round 2): comparing stored_line_bytes
        // against output_cap with a strict `<` only proved SOME budget
        // remained, not that THIS line's bytes fit within it -- a single
        // stored line can be up to output_cap bytes long (line_buf's own
        // accumulator caps it there), so a one-byte remainder could still
        // admit a whole second cap-sized line, letting result.lines grow to
        // nearly 2x the documented output_cap budget. Require the line's
        // OWN source-byte count (+1 for the terminating newline, same
        // accounting as below) to fit in the REMAINING budget instead.
        const std::size_t source_bytes = line.size() + 1;
        const bool line_room = source_bytes <= output_cap - stored_line_bytes &&
                               (opts.max_lines == 0 || result.lines.size() < opts.max_lines);
        if (line_room) {
            // +1 for the terminating newline: count the SOURCE bytes the line
            // consumed, matching output_cap's blob accounting so result.lines
            // stays bounded by the same cap as result.output (BR-001).
            stored_line_bytes += source_bytes;
            result.lines.push_back(std::move(line));
            if (opts.stop_after_max_lines && opts.max_lines != 0 &&
                result.lines.size() >= opts.max_lines)
                line_cap_stop = true;
        }
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();

        if (!process_exited && WaitForSingleObject(process_h.get(), 0) == WAIT_OBJECT_0)
            process_exited = true;

        const bool deadline_hit = !killed && (now - start >= opts.deadline);
        const bool cancel_hit =
            !killed && (subprocess_cancel_requested() ||
                        (opts.cancel_token && opts.cancel_token->cancelled()));

        if (deadline_hit || cancel_hit) {
            // K1/CDX-P2-002 twin of the killed_by_line_cap = !process_exited
            // guard below: a process already observed exited at the top of
            // THIS iteration completed strictly before this kill decision, so
            // crediting deadline/cancelled (and timed_out) would fabricate a
            // kill that never happened. The Job termination below still runs
            // unconditionally -- a descendant may have outlived the leader
            // and be holding the pipe open (BR-003), and arming
            // hard_kill_sent bounds the remaining drain.
            if (!process_exited) {
                result.timed_out = true;
                killed_by_deadline = deadline_hit;
                killed_by_cancel = !deadline_hit && cancel_hit;
            }
            killed = true;
            if (opts.soft_terminate_grace.count() > 0 && !process_exited &&
                GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId)) {
                // Windows twin of POSIX's SIGTERM soft-terminate: CTRL_BREAK
                // to the whole process group (CREATE_NEW_PROCESS_GROUP
                // above), giving a mutating tool a chance to unwind before
                // the hard job-close kill below.
                soft_terminating = true;
                soft_term_deadline = now + opts.soft_terminate_grace;
            } else {
                // xplat-A2: reached either because no soft-terminate grace was
                // requested, or because GenerateConsoleCtrlEvent just FAILED.
                // The latter is not hypothetical: CTRL_BREAK_EVENT delivery
                // requires the target process group to share the caller's
                // console, and yuzu-agent runs as a Windows SERVICE with no
                // console at all -- the call reliably fails there, and
                // soft-terminate is UNSUPPORTED for a service-hosted agent
                // (documented limitation, not something to work around).
                // Previously the return value was discarded, so a failed
                // call still set soft_terminating/soft_term_deadline and
                // burned the ENTIRE grace window waiting for a signal that
                // could never arrive before falling through to the hard kill
                // anyway. Escalate immediately instead.
                // BR-003: terminate the whole Job, NOT just the leader. A
                // descendant that inherited the stdout pipe can outlive the
                // leader and keep the pipe open, so PeekNamedPipe never reports
                // EOF; if the leader has already exited the old
                // `!process_exited`-guarded TerminateProcess did nothing and the
                // loop span forever. TerminateJobObject reaps every process
                // still in the job even when the leader is gone, and arming
                // hard_kill_sent bounds the drain via kDrainGrace.
                TerminateJobObject(job_h.get(), 1);
                hard_kill_sent = true;
                hard_kill_time = now;
            }
        } else if (!killed && line_cap_stop) {
            killed = true;
            killed_by_line_cap = !process_exited;
            TerminateJobObject(job_h.get(), 1); // whole job, see BR-003 above
            hard_kill_sent = true;
            hard_kill_time = now;
        } else if (soft_terminating && now >= soft_term_deadline) {
            // Escalate regardless of process_exited: the leader may have unwound
            // during the grace while a descendant still holds the pipe. (BR-003)
            soft_terminating = false;
            TerminateJobObject(job_h.get(), 1);
            hard_kill_sent = true;
            hard_kill_time = now;
        }

        // Drain whatever is available without blocking.
        // K-03/M-c: track whether this iteration actually drained bytes so the
        // Sleep below fires ONLY when the pipe was empty. The old unconditional
        // Sleep(10) after a 512-byte read throttled Windows capture to ~50 KB/s,
        // so any child emitting more than ~500 KB inside the default 10 s
        // deadline was job-killed and falsely reported `deadline`/`timed_out`
        // though it ran fine (and script_exec's 16 MiB cap was unreachable).
        bool drained = false;
        DWORD avail_bytes = 0;
        bool have_peek =
            PeekNamedPipe(read_h.get(), nullptr, 0, nullptr, &avail_bytes, nullptr) != 0;
        if (have_peek && avail_bytes > 0) {
            DWORD to_read = static_cast<DWORD>(std::min<std::size_t>(buf.size(), avail_bytes));
            DWORD n = 0;
            if (ReadFile(read_h.get(), buf.data(), to_read, &n, nullptr) && n > 0) {
                drained = true;
                const auto avail = result.output.size() < output_cap ? output_cap - result.output.size()
                                                                      : std::size_t{0};
                const auto take = static_cast<std::size_t>(n) < avail ? static_cast<std::size_t>(n) : avail;
                if (take > 0)
                    result.output.append(buf.data(), take);
                if (take < static_cast<std::size_t>(n))
                    result.output_truncated = true;
                // CDX-P2-005: materialize over every drained byte (all `n`, not
                // the `take` blob prefix) so on_line keeps streaming past the
                // blob cap; store_line + the line_buf bound keep storage capped.
                for (std::size_t i = 0; i < static_cast<std::size_t>(n); ++i) {
                    char ch = buf[i];
                    if (ch == '\n') {
                        store_line(std::move(line_buf));
                        line_buf.clear();
                    } else if (line_buf.size() < output_cap) {
                        line_buf += ch;
                    } else {
                        result.output_truncated = true;
                    }
                }
            }
        } else if (!have_peek) {
            // The write end has closed (child exited/crashed) --
            // PeekNamedPipe fails once there is no writer left.
            pipe_eof = true;
        }

        if (process_exited && (pipe_eof || !have_peek))
            break;
        if (hard_kill_sent && now - hard_kill_time >= kDrainGrace)
            break;

        // Only idle-sleep when the pipe was empty this iteration; when data is
        // flowing, loop immediately to keep draining at full speed (K-03/M-c).
        if (!drained)
            Sleep(killed ? 5 : 10);
    }

    if (!line_buf.empty())
        store_line(std::move(line_buf));

    DWORD exit_code_raw = 0;
    if (GetExitCodeProcess(process_h.get(), &exit_code_raw) && exit_code_raw != STILL_ACTIVE) {
        result.tool_ran = true;
        if (!killed)
            result.exit_code = static_cast<int>(exit_code_raw);
        // else: terminated by us (TerminateProcess/job-close) -- exit_code
        // stays the -1 sentinel, never TerminateProcess's own arbitrary exit
        // value, matching the POSIX "never fabricate a status for a death
        // by [our own] signal" contract.
    }

    // B4: rusage-equivalent, best-effort.
    FILETIME creation_time{}, exit_time{}, kernel_time{}, user_time{};
    if (GetProcessTimes(process_h.get(), &creation_time, &exit_time, &kernel_time, &user_time)) {
        auto to_us = [](const FILETIME& ft) {
            ULARGE_INTEGER u{};
            u.LowPart = ft.dwLowDateTime;
            u.HighPart = ft.dwHighDateTime;
            return static_cast<long long>(u.QuadPart / 10); // 100ns ticks -> microseconds
        };
        result.child_user_time = std::chrono::microseconds(to_us(user_time));
        result.child_system_time = std::chrono::microseconds(to_us(kernel_time));
    }
    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(process_h.get(), &pmc, sizeof(pmc)))
        result.child_max_rss_kb = static_cast<std::uint64_t>(pmc.PeakWorkingSetSize) / 1024;

    // Same ordering as the POSIX chain: a deliberate kill (line_cap/cancel/
    // deadline) is classified by its reason even if the process never
    // confirmed output before we killed it (a pre-armed cancel racing the
    // launch). Genuine launch failures (CreateProcessW failure, banned
    // extension, argv validation) return spawn_error early, above -- so
    // reaching here with !tool_ran and no kill is the only residual
    // spawn_error case.
    if (killed_by_line_cap) {
        result.termination_reason = TerminationReason::line_limit;
    } else if (killed_by_cancel) {
        result.termination_reason = TerminationReason::cancelled;
    } else if (killed_by_deadline) {
        result.termination_reason = TerminationReason::deadline;
    } else if (!result.tool_ran) {
        result.termination_reason = TerminationReason::spawn_error;
    } else if (!killed && (exit_code_raw & 0xF0000000u) == 0xC0000000u) {
        // CDX-P2-014: an unhandled exception terminates the process with its
        // NTSTATUS exception code as the exit code -- severity ERROR, high
        // nibble 0xC (e.g. STATUS_ACCESS_VIOLATION 0xC0000005,
        // STATUS_STACK_OVERFLOW 0xC00000FD). That is a crash, not an ordinary
        // exit; classify it `signaled` to match the POSIX chain, which reports
        // a signal death distinctly so a caller can tell a crash (do not retry
        // blindly) from an ordinary nonzero rc. The raw code stays in
        // result.exit_code for callers that want the specific status.
        result.termination_reason = TerminationReason::signaled;
    } else {
        result.termination_reason = TerminationReason::exited;
    }

    return result;
}

std::string probe_tool_path(const std::vector<std::string>& candidates) {
    for (const auto& c : candidates) {
        if (!detail::is_absolute_path(c))
            continue;
        // K2/CDX-P2-003: the header promises "exists AND is executable" on
        // both platforms (the POSIX twin checks X_OK). "Executable" on this
        // backend means run_bounded_subprocess could actually spawn it:
        // never a banned .bat/.cmd/.com (the same build_launch_spec policy
        // the spawn path enforces -- a candidate the runner would refuse to
        // exec must not be probed as usable), and a real executable image
        // (GetBinaryTypeW -- which also rejects directories, non-PE files
        // and nonexistent paths, subsuming the old attribute check).
        if (detail::is_banned_windows_extension(c))
            continue;
        std::wstring wc = utf8_to_wide(c);
        DWORD binary_type = 0;
        if (GetBinaryTypeW(wc.c_str(), &binary_type) != 0)
            return c;
    }
    return {};
}

#endif // !_WIN32

} // namespace yuzu::agent
