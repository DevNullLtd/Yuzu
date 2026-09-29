#pragma once

/// @file shutdown_watcher.hpp
/// POSIX shutdown self-pipe shared by the agent and server binaries (#3007): a signal
/// handler writes ONE byte; a dedicated watcher thread wakes and runs the real teardown.
///
/// This is the one named `common/include` I/O exception — see CLAUDE.md "Project layout"
/// (#2549). The exception is this file specifically, not an open door for I/O generally: a
/// new I/O-bearing file placed here must be named in that annotation (amend it), not merely
/// pass ordinary review.
///
/// WHY IT IS IN A HEADER, not buried in main.cpp. An earlier version of this lived in
/// main.cpp, so the unit test could only RE-IMPLEMENT the pipe ("build it the same way the
/// watcher does") and pin a COPY. That copy passed while the real code was broken: the real
/// `pipe2()` call carried `O_CLOEXEC | O_NONBLOCK`, which sets O_NONBLOCK on BOTH ends, so
/// the watcher's blocking read() returned EAGAIN, the thread exited within microseconds, and
/// SIGTERM silently stopped triggering a graceful stop. Nothing looked broken — the process
/// still died via the default disposition. Testing a copy is not testing.
/// (governance Gate-8 cpp-safety.)
///
/// ── WHY THE SELF-PIPE EXISTS AT ALL ──────────────────────────────────────────────
/// The handler used to call `Agent::stop()` inline. stop() takes mutexes, joins worker
/// threads, calls sd_bus_unref (malloc/free) and logs through spdlog — none of which may run
/// in a signal handler. And a process-directed signal lands on an ARBITRARY unmasked thread,
/// so if it landed on a thread stop() JOINS, that join was a SELF-JOIN: std::system_error
/// out of a `noexcept` function -> std::terminate, on SIGTERM. Moving the teardown onto an
/// ordinary thread — one stop() never joins — makes the whole class structurally impossible,
/// and is what let SparkEngine delete its entire signal-mitigation layer.
///
/// ── SIX TRAPS. All hit for real. Do not "simplify" past them. ──
///   1. A bare joinable std::thread in main's scope: `agent->run()` is NOT wrapped in a try
///      at its call site, so a throw unwinds past it -> ~std::thread on a joinable thread ->
///      std::terminate. Hence RAII, declared AFTER the Agent so it is destroyed FIRST.
///   2. A throw from the CONSTRUCTOR BODY skips the destructor. std::thread's ctor throws
///      std::system_error under EAGAIN — on exactly the thread-exhausted host this is meant
///      to survive. RAII does not save you; the ctor must clean up by hand.
///   3. `pipe2(fds, O_CLOEXEC | O_NONBLOCK)` sets O_NONBLOCK on BOTH ends, so the watcher's
///      read() returns EAGAIN immediately and it exits at once. O_NONBLOCK belongs on the
///      WRITE end ONLY (so the handler can never block); the READ end must BLOCK.
///   4. Without O_CLOEXEC both fds are inherited by every popen()/fork+exec child — the
///      trigger engine plus the ioc / firewall / services / software_actions / wol /
///      license_scan plugins — handing every subprocess a lever to shut the agent down.
///   5. Closing the read end while the write end lives makes any late write raise SIGPIPE,
///      whose disposition here is SIG_DFL: it KILLS the agent (exit 141). The fds are never
///      closed; two held to process exit is the correct trade.
///   6. `ok()` MUST test liveness, never `joinable()` — which stays TRUE for a FINISHED thread.
///      If the watcher died on a read() error, a joinable()-based ok() went on reporting true,
///      the handlers stayed installed, and every later SIGTERM was written into a pipe with NO
///      READER: swallowed. The agent became UNKILLABLE by SIGTERM. Hence `alive_`, plus the
///      `on_watcher_died` callback that installs the hard-exit handler (NOT SIG_DFL — pid 1
///      discards default-action signals; see main.cpp's on_signal_hard_exit).
///
/// AND: nothing may throw out of the CONSTRUCTOR BODY (trap 2) — including a LOG. spdlog
/// rethrows non-std exceptions, so every failure-path log goes through log_quietly()'s
/// try/catch firewall. thread_pool.hpp carries the same firewall for the same reason.
///
/// AND: if construction fails, `ok()` is false and the caller MUST NOT install the signal
/// handlers — otherwise the handler catches the signal, finds no pipe, returns, and the
/// signal is SWALLOWED with no default disposition left, so SIGTERM stops working entirely.
///
/// ── THE SECOND-SIGNAL ESCALATION IS AN INTERACTIVE-OPERATOR FEATURE ONLY. ────────
/// It is NOT the production mitigation, and must never be relied on as one: systemd and
/// `docker stop` each send exactly ONE SIGTERM and then SIGKILL. No supervisor ever sends a
/// second. The OTA self-stop path (the update thread calls Agent::stop() itself) gets no
/// signal at all and no supervisor timeout, because nobody asked us to stop.
///
/// #2233 item 3 ("S+", agents/core/src/shutdown_deadline_guard.hpp) IS that internal bound —
/// this comment previously said "THIS PR DOES NOT ADD ONE... being built separately"; that is
/// no longer true. AgentImpl::stop() and run()'s teardown ScopeExit each arm a
/// ShutdownDeadlineGuard as their first statement and call hard_exit() if the wrapped call
/// hasn't returned within the grace period — bounding exactly the "stop() drains guardian_/
/// dex_observer_ with an unbounded wait" and "OTA self-stop path gets nothing at all" gaps this
/// comment used to describe. It does not need the running-command-holds-an-uncancellable-
/// plugin-ABI-worker caveat that sank three prior attempts: hard_exit()/TerminateProcess/_exit()
/// skip ALL normal teardown rather than trying to wait for or cancel anything, so a legitimately
/// in-flight worker being "still running" at the moment of hard_exit() is a non-issue by
/// construction — see shutdown_deadline_guard.hpp's own header comment for the full argument.

#ifndef _WIN32

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <thread>
#include <unistd.h>

#include <spdlog/spdlog.h>

namespace yuzu {

class ShutdownWatcher {
public:
    static constexpr char kSignal = 1; ///< written by the signal handler: tear the agent down
    static constexpr char kQuit = 0;   ///< written by the destructor: just retire

    /// `wfd_slot` is the atomic the signal handler reads the write-fd from (it must be
    /// lock-free — assert that at the definition site — and STATIC-STORAGE-DURATION in
    /// production: the destructor's detach path can touch the slot after any narrower
    /// scope has died; see WatcherState. Unit tests pass stack atomics, which is safe
    /// ONLY because they join in scope and never exercise the detach path). `on_shutdown` runs on the watcher
    /// thread, an ORDINARY thread, so it may lock, join, allocate and log freely. It is
    /// called at most once. If it returns false the watcher keeps waiting — used when the
    /// Agent is not published yet, so a signal arriving during boot cannot CONSUME the
    /// watcher and leave every later signal a no-op.
    /// `on_watcher_died` runs if the watcher thread exits UNEXPECTEDLY — a read() error, as
    /// opposed to the destructor's kQuit or a completed teardown. The caller MUST use it to make
    /// the process KILLABLE again (see trap 6). Note that "back to SIG_DFL" is NOT sufficient: the
    /// agent is pid 1 in every shipped container, and the kernel DISCARDS a default-disposition
    /// signal for pid 1 — main.cpp therefore installs a hard-exit handler instead.
    ShutdownWatcher(std::atomic<int>& wfd_slot, std::function<bool()> on_shutdown,
                    std::function<void()> on_watcher_died = {})
        : wfd_slot_{wfd_slot}, state_{std::make_shared<WatcherState>(&wfd_slot)} {
        // Trap 4: O_CLOEXEC on both ends. Trap 3: O_NONBLOCK on the WRITE end ONLY.
#ifdef __linux__
        if (::pipe2(fds_, O_CLOEXEC) != 0) {
#else
        if (::pipe(fds_) != 0) {
#endif
            const int err = errno;
            fds_[0] = fds_[1] = -1;
            // Route through degrade() so it really IS the single "we could not build a watcher"
            // exit — a previous comment here CLAIMED it was while this branch quietly did its
            // own thing. (No fd is open on this path, so degrade() only retracts the slot.)
            // (governance Gate-8 round 9 cpp-safety.)
            degrade();
            log_quietly("could not create the shutdown pipe", err);
            return;
        }
#ifndef __linux__
        // macOS has no pipe2, so CLOEXEC is set after the fact and a fork/exec racing this
        // window still inherits the fds — precisely why pipe2 exists. Check the results: a
        // silently-failed F_SETFD restores the subprocess-inherit lever it exists to remove.
        if (::fcntl(fds_[0], F_SETFD, FD_CLOEXEC) < 0 ||
            ::fcntl(fds_[1], F_SETFD, FD_CLOEXEC) < 0) {
            // Fail CLOSED: a pipe whose fds leak into every popen()/fork+exec child hands each
            // subprocess a lever to stop the agent. degrade() -> ok()==false -> the caller leaves
            // the hard-exit fallback standing (killable everywhere incl. pid 1, not graceful).
            const int err = errno;
            degrade();
            log_quietly("could not set FD_CLOEXEC on the shutdown pipe", err);
            return;
        }
#endif
        const int wfl = ::fcntl(fds_[1], F_GETFL);
        if (wfl < 0 || ::fcntl(fds_[1], F_SETFL, wfl | O_NONBLOCK) < 0) {
            // Fail CLOSED: a blocking write end can BLOCK THE SIGNAL HANDLER on a full pipe.
            const int err = errno;
            degrade();
            log_quietly("could not set O_NONBLOCK on the shutdown pipe's write end", err);
            return;
        }

        wfd_slot_.store(fds_[1], std::memory_order_release);

        // TRAP 7 — LIVENESS IS PUBLISHED BEFORE THE THREAD EXISTS, AND ONLY EVER CLEARED.
        //
        // It used to be published AFTER the std::thread ctor returned. A thread that died
        // immediately (a read() error on the very first pass) cleared `alive` and returned, and
        // then the ctor's store(true) RESURRECTED it — reinstating trap 6 through the very flag
        // added to close it: ok() reports a live watcher, main installs the handlers, and every
        // SIGTERM is written into a pipe with no reader. Publishing FIRST makes the flag
        // MONOTONIC (true -> false, never back), so whoever observes the death wins.
        // (governance round 2: cpp-expert, cpp-safety.)
        state_->alive.store(true, std::memory_order_release);

        // Trap 2: a throw from HERE (std::thread's ctor, EAGAIN) means the destructor never
        // runs, so RAII cannot save us — clean up by hand and degrade (which clears `alive`).
        try {
            // TRAP 8 — THE THREAD MUST NOT CAPTURE `this`. It used to, and the destructor has a
            // DETACH path (see below): after detaching, main returns, this stack-owned object
            // dies, and the thread then writes `alive_`/`wfd_slot_` through a dangling `this`.
            // The dtor's own comment says in capitals that the callback must not capture anything
            // that can die — while the watcher itself did exactly that. The state the thread
            // touches now lives on the HEAP and is captured BY VALUE, so it outlives the object
            // by construction. (governance round 2: cpp-safety BLOCKING-1, cpp-expert.)
            thread_ = std::thread([st = state_, rfd = fds_[0], cb = std::move(on_shutdown),
                                   died = std::move(on_watcher_died)] {
                for (;;) {
                    char byte = 0;
                    ssize_t n = 0;
                    do {
                        n = ::read(rfd, &byte, 1); // BLOCKS — trap 3
                    } while (n < 0 && errno == EINTR);

                    if (n == 1 && byte == kQuit)
                        return; // the destructor retiring us — the expected quiet exit

                    if (n != 1) {
                        // TRAP 6 — UNEXPECTED DEATH. `n < 0` (EBADF/EIO) or a short read used
                        // to take the same `return` as kQuit: the thread vanished, ok() went on
                        // reporting TRUE (it tested joinable(), which stays true for a FINISHED
                        // thread), the handlers stayed installed, and every later SIGTERM was
                        // written into a pipe with NO READER — swallowed. The agent became
                        // unkillable by SIGTERM, exactly the fail-open-to-hang this class exists
                        // to remove, reached through a different door.
                        // Retract the slot and make the process killable again — NOT via SIG_DFL,
                        // which pid 1 discards; main.cpp installs a hard-exit handler.
                        const int err = (n < 0) ? errno : 0;
                        st->wfd_slot->store(-1, std::memory_order_release);
                        st->alive.store(false, std::memory_order_release);
                        log_quietly("the shutdown watcher died unexpectedly — SIGINT/SIGTERM will "
                                    "now exit the process immediately and UNGRACEFULLY",
                                    err);
                        if (died)
                            died(); // caller installs the hard-exit handler
                        return;
                    }

                    if (cb && cb()) {
                        st->alive.store(false, std::memory_order_release);
                        return; // teardown ran (it BLOCKS until complete); nothing more to do
                    }
                    // cb() said "not yet" (the Agent is not published): keep waiting rather
                    // than being consumed, or every LATER signal becomes a silent no-op.
                }
            });
        } catch (const std::exception& e) {
            degrade();
            log_quietly("could not start the shutdown watcher", 0, e.what());
        } catch (...) {
            // Degrading is this class's whole purpose, and a throw escaping a CONSTRUCTOR BODY
            // skips the destructor (trap 2) — so nothing may escape, not even a non-std throw.
            // std::thread only throws std::system_error today, but a caller-supplied
            // std::function copy could throw anything. (Gate-8 round 7 cpp-expert S-3.)
            degrade();
            log_quietly("could not start the shutdown watcher (unknown exception)");
        }
    }

    ~ShutdownWatcher() {
        if (fds_[1] >= 0 && thread_.joinable()) {
            wfd_slot_.store(-1, std::memory_order_release);
            // THE JOIN BELOW DEPENDS ON THIS BYTE LANDING. The watcher is parked in a BLOCKING
            // read(); if the sentinel is lost, join() never returns and the agent hangs at
            // exit — the very failure this class exists to prevent, moved to the last line.
            // The write end is O_NONBLOCK, so retry EINTR/EAGAIN rather than discarding the
            // result as an earlier version did. (Gate-8 round 7 cpp-expert S-2.)
            const char quit = kQuit;
            bool retired = false;
            // Captured at the point of failure. Reading errno AFTER the loop would read it
            // after std::this_thread::yield() (sched_yield) and a loop re-test — and POSIX
            // permits a SUCCESSFUL call to set errno — so the diagnostic could name the wrong
            // error on precisely the path whose only purpose is diagnosis.
            // (governance Gate-8 round 9 cpp-safety.)
            int last_err = 0;
            bool stayed_full = false;
            for (int attempt = 0; attempt < 1000 && !retired; ++attempt) {
                const ssize_t n = ::write(fds_[1], &quit, 1);
                if (n == 1) {
                    retired = true;
                    break;
                }
                last_err = (n < 0) ? errno : 0;
                if (last_err == EINTR)
                    continue; // interrupted before writing — retry immediately
                if (last_err == EAGAIN) {
                    // Pipe full: the watcher has not drained it yet. It is alive and WILL
                    // wake, so yield and retry rather than spin.
                    stayed_full = true;
                    std::this_thread::yield();
                    continue;
                }
                stayed_full = false;
                break; // unrecoverable — fall through to the detach below
            }
            // EVERY WAY OUT OF THAT LOOP THAT DID NOT DELIVER THE BYTE ENDS HERE — the
            // unrecoverable error AND the 1000-attempt exhaustion. An earlier version handled
            // only the error and let exhaustion fall through to the join() below, which is the
            // one exit that cannot complete: the watcher is parked in a BLOCKING read() we can
            // no longer wake, so join() would hang process exit forever — the exact failure
            // this class exists to prevent, at the last line. Exhaustion is unreachable today
            // (the pipe buffer is ≥4 KiB on every target — Darwin defaults to 16 KiB,
            // Linux 64 KiB — and the second-signal _exit() caps the queue at one byte) but its
            // safety depended on an invariant in ANOTHER FILE, which is not a safety argument.
            // (governance Gate-8 round 8: cpp-safety + unhappy-path UP8-3, found independently.)
            //
            // DETACH IS SAFE HERE — but not for the reason an earlier comment gave. It claimed
            // "no byte can arrive because wfd_slot_ is already -1". That is wrong: a handler
            // that loaded the fd BEFORE the store(-1) above can still write() afterwards, and
            // the byte lands. Two things make a late-running detached thread safe:
            //   * IT NO LONGER TOUCHES `this`. Everything it writes lives in the heap-allocated
            //     WatcherState it captured BY VALUE (trap 8). The previous version captured
            //     `this` — a stack object in main() — so this very detach was a use-after-free
            //     waiting on a lost sentinel byte. (governance round 2: cpp-safety.)
            //   * THE CALLBACK MUST NOT CAPTURE ANYTHING THAT CAN DIE. main's is capture-free
            //     and g_agent is already null by then; the tests' `[&]` lambdas would not be
            //     safe here, and are not reachable (we own both fds and never close them, so
            //     write() cannot fail with anything but EINTR/EAGAIN).
            // (governance Gate-8 round 8 cpp-safety; round 2 of this branch.)
            if (!retired) {
                // The exhaustion case reports EAGAIN, so a bare `last_err ? strerror : "full"`
                // could never print the full-pipe message it named. Distinguish them properly —
                // another string that asserted a case it did not cover. (Gate-8 round 10.)
                // Firewalled like every other log here: ~ShutdownWatcher is implicitly noexcept,
                // and spdlog rethrows non-std exceptions — a throw from a destructor is an
                // immediate std::terminate. (governance: cpp-safety, this range.)
                log_quietly("could not retire the shutdown watcher — detaching it rather than "
                            "blocking process exit on a join that cannot complete",
                            stayed_full ? 0 : last_err,
                            stayed_full ? "pipe stayed full after 1000 attempts" : nullptr);
                thread_.detach();
                return;
            }
        }
        if (thread_.joinable())
            thread_.join();
        // THE FDS ARE DELIBERATELY NOT CLOSED. A signal may be in flight: a handler could
        // already have loaded the fd and be about to write(). Closing here would let that
        // write land in a RECYCLED descriptor — an SQLite file, a gRPC socket — belonging to
        // a thread still running during teardown. Two fds held to process exit is the
        // correct trade, and the standard self-pipe answer.
    }

    /// TRUE iff the watcher thread is actually running. If FALSE the caller MUST NOT install
    /// the signal handlers — see the header note (a swallowed signal leaves the agent
    /// unkillable by SIGTERM).
    [[nodiscard]] bool ok() const { return state_->alive.load(std::memory_order_acquire); }

    [[nodiscard]] int read_fd_for_test() const { return fds_[0]; }
    [[nodiscard]] int write_fd_for_test() const { return fds_[1]; }

    ShutdownWatcher(const ShutdownWatcher&) = delete;
    ShutdownWatcher& operator=(const ShutdownWatcher&) = delete;

private:
    /// The CONSTRUCTOR'S FAILURE PATH ONLY. Retract the fd from the handler's slot, then close
    /// both ends.
    ///
    /// Closing the fds is safe ONLY here — where the thread never started, so `ok()` is false
    /// and main installs the hard-exit handler (never touches the pipe), so no handler exists to write into a recycled
    /// descriptor (trap 5). Call it on a LIVE watcher and it is a guaranteed hang: closing an
    /// fd does not wake a thread already blocked in read(), the destructor then sees
    /// `fds_[1] < 0`, skips the kQuit write entirely, and joins a thread that can never be
    /// woken — the agent never exits. It was briefly public with only a comment to protect it,
    /// which is the shape of nearly every bug on this branch: a method safe on exactly one
    /// path, guarded by prose.
    /// (governance Gate-8 round 8: cpp-safety + unhappy-path UP8-2, found independently.)
    ///
    /// WHAT ACTUALLY ENFORCES THE PRECONDITION is that this is PRIVATE with exactly three call
    /// sites — the pipe()-failure branch and the two ctor catch blocks — in every one of which
    /// `thread_` is provably not joinable. NOT the assert below: that is compiled out under
    /// NDEBUG, i.e. in every release build. It documents the contract and catches a mistake in
    /// debug; it does not enforce anything in production. Do not add a call site on the
    /// strength of it. (governance Gate-8 round 9 cpp-safety.)
    void degrade() noexcept {
        assert(!thread_.joinable() && "degrade() on a live watcher would hang the agent at exit");
        // Clearing `alive` is the ONLY direction this flag ever moves after construction — see
        // trap 7. The ctor publishes it true BEFORE spawning, so the thread-creation failure
        // paths below must take it back down here.
        state_->alive.store(false, std::memory_order_release);
        wfd_slot_.store(-1, std::memory_order_release);
        for (int& fd : fds_) {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }
    }

    /// Every log on a failure path goes through here. spdlog RETHROWS non-std exceptions, and
    /// a throw escaping a CONSTRUCTOR BODY skips the destructor (trap 2) -- which would leak both
    /// pipe fds and then std::terminate, on precisely the exhausted host this class exists to
    /// survive. thread_pool.hpp carries the same firewall for the same reason.
    /// (governance: cpp-safety, this range.)
    static void log_quietly(const char* what, int err = 0, const char* extra = nullptr) noexcept {
        try {
            if (extra)
                spdlog::warn("{} ({})", what, extra);
            else if (err != 0)
                spdlog::warn("{} ({})", what, std::strerror(err));
            else
                spdlog::warn("{}", what);
        } catch (...) {
            // Nothing to do and nowhere to say it. Never let a logger kill the agent.
        }
    }

    /// EVERYTHING THE WATCHER THREAD TOUCHES, ON THE HEAP. Held by shared_ptr and captured BY
    /// VALUE by the thread, so a DETACHED watcher (see the destructor) cannot outlive the state
    /// it writes to — `this` is a stack object in main() and dies when main returns. Trap 8.
    ///
    /// `wfd_slot` points at the caller's signal-handler slot. It must outlive the process: in
    /// main.cpp it is a file-static atomic, which is the only supported shape.
    struct WatcherState {
        explicit WatcherState(std::atomic<int>* slot) noexcept : wfd_slot{slot} {}
        std::atomic<int>* wfd_slot;
        /// LIVENESS, not joinable(). Published BEFORE the thread is spawned and only ever
        /// cleared thereafter (trap 7 — publishing it after the spawn let the ctor resurrect a
        /// thread that had already died). ok() reads this.
        std::atomic<bool> alive{false};
    };

    std::atomic<int>& wfd_slot_;
    int fds_[2]{-1, -1};
    std::thread thread_;
    std::shared_ptr<WatcherState> state_;
};

} // namespace yuzu

#endif // !_WIN32
