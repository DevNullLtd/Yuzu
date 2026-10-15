#ifdef _WIN32

#include "service_win.hpp"

#include "hard_exit.hpp" // shared TerminateProcess + F3 orphan-drain poll (rung 7.6)
#include "service_completion.hpp" // #4666 PR-2: service_main/run_service completion handshake
#include "log_handoff.hpp"        // for drain_log_bounded()
#include "shutdown_deadline_guard.hpp" // kShutdownDeadlineExitCode (shared exit-code taxonomy)

#include <yuzu/agent/agent.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <semaphore>

namespace {

using yuzu::agent::Agent;

// SERVICE_TABLE_ENTRYW's ServiceMain callback takes no user context parameter, so
// the factory and mutable service state are process-global. This is fine: a given
// process hosts exactly one service (SERVICE_WIN32_OWN_PROCESS), so there is only
// ever one ServiceMain/handler pair alive. Plain (not atomic/mutex-guarded)
// because the only write happens in run_service() strictly before it calls
// StartServiceCtrlDispatcherW, and the only read happens in service_main() on the
// thread the SCM spawns as a *result* of that same call -- Windows thread
// creation provides the needed happens-before edge (unlike g_status_handle
// below, which is genuinely read/written from two independently-running,
// concurrently-active threads once the service is up).
std::move_only_function<std::unique_ptr<Agent>()> g_factory;

// atomic, not a plain pointer guarded by g_status_mu below: it's published once
// by RegisterServiceCtrlHandlerExW's return and then only ever READ by
// report_status() -- an unlocked write racing report_status()'s locked read
// under the C++ memory model is a data race even though it's single-writer and
// practically benign (Gate-2 finding, #1822).
std::atomic<SERVICE_STATUS_HANDLE> g_status_handle{nullptr};
// Guards both the SetServiceStatus call and the checkpoint counter: the control
// handler (SCM-invoked, its own thread) and ServiceMain can both report status
// concurrently -- e.g. a STOP arriving while ServiceMain is still transitioning
// out of START_PENDING/RUNNING -- so report_status() is not naturally single-
// threaded despite the state machine looking sequential on paper.
std::mutex g_status_mu;
DWORD g_checkpoint = 0; // guarded by g_status_mu; monotonic within a pending phase

std::mutex g_agent_mu;
Agent* g_agent = nullptr; // guarded by g_agent_mu; non-owning, published by ServiceMain
std::atomic<bool> g_stop_requested{false};

// Released by service_main's FIRST-declared local (a SemaphoreReleaseGuard, so it fires
// LAST by reverse-declaration-order destruction, after every other local and every catch
// block in that function) -- run_service() waits on this after the SCM control dispatcher
// returns, so main()'s log-handoff teardown (#4666 PR-2) never starts while service_main's
// thread might still be logging. See service_completion.hpp's own file banner for the full
// race this closes.
std::binary_semaphore g_service_main_done{0};
// Mirrors agent.cpp's kShutdownDeadlineGrace (20s, file-local there, not exported) -- if
// service_main is still running normal (non-hard_exit) cleanup this long after the SCM
// dispatcher has already returned, something past its own internal watchdogs is wedged.
constexpr std::chrono::milliseconds kServiceMainDrainGrace{20'000};

void report_status(DWORD current_state, DWORD win32_exit_code = NO_ERROR,
                    DWORD specific_exit_code = 0, DWORD wait_hint = 0) {
    std::lock_guard<std::mutex> lock(g_status_mu);

    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = current_state;
    status.dwWin32ExitCode = win32_exit_code;
    status.dwServiceSpecificExitCode = specific_exit_code;
    status.dwWaitHint = wait_hint;

    switch (current_state) {
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
        // No controls accepted while pending: MSDN requires it for START_PENDING,
        // and clearing it for STOP_PENDING means a duplicate STOP/SHUTDOWN control
        // simply isn't delivered again, instead of hitting the handler mid-teardown.
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = ++g_checkpoint;
        break;
    case SERVICE_RUNNING:
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        status.dwCheckPoint = 0;
        g_checkpoint = 0;
        break;
    default: // SERVICE_STOPPED
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 0;
        break;
    }

    if (auto handle = g_status_handle.load(std::memory_order_acquire))
        SetServiceStatus(handle, &status);
}

// noexcept for the same reason as service_main: a raw WINAPI callback the SCM
// invokes directly must not let an exception (however unlikely -- only source
// here is std::mutex::lock inside report_status()/this function) cross that C
// ABI boundary as UB; noexcept converts it into a defined std::terminate instead.
DWORD WINAPI handler_ex(DWORD control, DWORD /*event_type*/, LPVOID /*event_data*/,
                         LPVOID /*context*/) noexcept {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_stop_requested.store(true, std::memory_order_relaxed);
        // 30s to match the START_PENDING hint. The "Agent::stop() itself is non-blocking...
        // teardown is bounded well under that" claim this comment used to make here was
        // false - #2233 item 3 proved guardian_/dex_observer_ teardown can hang unboundedly,
        // which is exactly why AgentImpl::stop() now arms a ShutdownDeadlineGuard
        // (agents/core/src/shutdown_deadline_guard.hpp, kShutdownDeadlineGrace = 20s) as its
        // first statement. 20s leaves only a 10s margin under this 30s hint, not "well under"
        // it - a wedge diagnosed slowly by the guard's own worker dispatch could still cost
        // the SCM's patience in a worst case.
        //
        // That margin is for ONE watchdog. AgentImpl::stop() and run()'s teardown ScopeExit
        // each arm their own, independently-budgeted 20s watchdog, and in the worst case the
        // two compose SEQUENTIALLY in wall-clock time (agent.cpp's kShutdownDeadlineGrace
        // comment has the exact call-graph reasoning) - up to ~40s total, past this 30s hint,
        // with neither individual watchdog firing (external review, PR #3737). In that specific
        // composed-but-neither-fires case the outcome is a CLEAN stop, not a crash: teardown
        // eventually completes on its own and this handler reaches report_status(SERVICE_STOPPED)
        // below (line ~260) with its default NO_ERROR exit code. Per SERVICE_FAILURE_ACTIONS_FLAG's
        // documented semantics, --install-service's SC_ACTION_RESTART recovery actions (main.cpp,
        // #1822) fire ONLY on a process that terminates WITHOUT reporting SERVICE_STOPPED, or one
        // that reports it with a non-zero exit code - a slow-but-clean SERVICE_STOPPED/NO_ERROR
        // report satisfies neither condition, so no restart fires here (an earlier revision of
        // this comment claimed the opposite - corrected after direct verification against
        // Microsoft's own documented flag semantics, not just re-derivation from this PR's code).
        // The actual consequence of exceeding the 30s hint in this specific tail case is milder
        // than a restart, not worse: the service simply reports STOPPED later than the SCM
        // expected, with no automatic action taken either way.
        //
        // If EITHER watchdog instead genuinely FIRES (a real wedge, hard_exit(4)), the
        // auto-restart claim below (main.cpp, #1822) is unaffected and remains correct: a
        // TerminateProcess exit never reports SERVICE_STOPPED at all, which is exactly the
        // first triggering condition above.
        //
        // That STOP_PENDING-margin reasoning is about SERVICE_CONTROL_STOP specifically; on
        // SERVICE_CONTROL_SHUTDOWN the OS applies its own WaitToKillServiceTimeout instead,
        // which can be shorter and is outside this process's control either way. No
        // checkpoint-bumping thread added regardless: a wedge that outlives the 30s hint now
        // hard_exit()s the whole process before the SCM's own timeout would matter, rather than
        // needing a live checkpoint to survive it. --install-service's own
        // SERVICE_CONFIG_FAILURE_ACTIONS (main.cpp, #1822 - SC_ACTION_RESTART x3, with
        // SERVICE_CONFIG_FAILURE_ACTIONS_FLAG=TRUE so it fires on a clean exit with no
        // SERVICE_STOPPED report too, not just a crash) DOES auto-restart a watchdog-fired TerminateProcess,
        // similar to the Linux systemd Restart=always path (an earlier revision of this comment
        // claimed NO auto-restart existed at all - governance Gate 6 sre finding, corrected at
        // Gate 8 re-verify after direct code read; the SEPARATE correction above is about which
        // specific SHUTDOWN OUTCOME triggers it, not whether the mechanism exists).
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 30000);
        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            if (g_agent)
                g_agent->stop();
        }
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        // The SCM already has our most recent SetServiceStatus report; nothing to
        // resend.
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// Clears the published g_agent pointer on destruction, under g_agent_mu.
// service_main declares its unique_ptr<Agent>, THEN this guard: C++ destroys
// locals in reverse declaration order, so the guard fires -- unpublishing
// g_agent -- before the unique_ptr's own destructor runs, on EVERY exit path
// (normal return, exception unwind, everything). Without this, a manual
// "clear g_agent" statement placed only after a (fallible) agent->run() call
// only runs on the happy path; a SERVICE_CONTROL_STOP delivered on the SCM
// control-handler thread during exception unwind would see a stale non-null
// g_agent and call stop() on an already-destructing/destructed Agent (Gate-2
// finding, #1822).
struct AgentUnpublisher {
    ~AgentUnpublisher() {
        std::lock_guard<std::mutex> lock(g_agent_mu);
        g_agent = nullptr;
    }
};

void WINAPI service_main(DWORD, LPWSTR*) noexcept {
    // #4666 PR-2: constructed as the ABSOLUTE FIRST statement of this function, OUTSIDE
    // the try block below, so it is the LAST local to be destroyed (reverse-declaration-
    // order destruction) on every exit path this function has -- normal return, either
    // catch block below, or the early `return` inside the try. Its constructor
    // (service_completion.hpp) is noexcept and does nothing but store a reference, so
    // declaring it here cannot itself introduce a throw into this pre-try window.
    // run_service() only proceeds past its wait on g_service_main_done once this guard's
    // destructor has released it, i.e. only after this entire function has truly finished.
    yuzu::agent::SemaphoreReleaseGuard done_guard{g_service_main_done};

    // The try opens here, before RegisterServiceCtrlHandlerExW, not just around
    // the agent construction/run() below: spdlog::error/report_status (fmt
    // formatting, std::mutex::lock) are not statically noexcept, and nothing
    // may cross this raw WINAPI callback boundary uncaught (Gate-2 re-review
    // follow-up, #1822) -- even in this narrow pre-Agent window.
    try {
        auto handle =
            RegisterServiceCtrlHandlerExW(yuzu::agent::win::kServiceName, handler_ex, nullptr);
        if (!handle) {
            spdlog::error("RegisterServiceCtrlHandlerExW failed: {}", GetLastError());
            return;
        }
        g_status_handle.store(handle, std::memory_order_release);

        report_status(SERVICE_START_PENDING, NO_ERROR, 0, 30000);

        // No checkpoint-bumping thread runs during this call because it's cheap
        // today (make_agent() in main.cpp: an in-process flag check, one small
        // SQLite open/write, and a trivial in-memory constructor -- the real
        // startup cost, plugin load and KV/TAR store open, is deliberately deferred
        // into agent->run() below, past the RUNNING report). If a future change
        // ever moves real work into the factory ahead of run(), this single
        // 30s-hint START_PENDING report stops being long enough and needs either a
        // periodic checkpoint bump or a longer hint (Gate 6 sre finding, governance
        // re-run).
        auto agent = g_factory ? g_factory() : nullptr;
        if (!agent) {
            spdlog::critical(
                "Agent factory failed under SCM startup -- reporting service failure");
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
            return;
        }

        // Constructed here, BEFORE g_agent is published below, so the "guard exists"
        // invariant is structural rather than resting on every statement between
        // publish and construction happening to be non-throwing today (it is, but a
        // future edit inserting a throwing statement in that window would otherwise
        // silently reopen the pre-#1822 UAF gap this guard exists to close --
        // Gate 3 cpp-safety hardening, governance re-run). `agent` is still declared
        // first, so reverse-declaration-order destruction still runs this guard
        // before `agent`'s own destructor on every exit path below.
        AgentUnpublisher unpublisher;

        bool stop_already_requested = false;
        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            g_agent = agent.get();
            // Catch up on a SERVICE_CONTROL_STOP that arrived while g_factory()
            // was still running: handler_ex would have found g_agent==nullptr
            // (not yet published) and silently skipped calling stop(), which --
            // left unhandled -- would let the service unconditionally report
            // RUNNING below and un-stop itself from the SCM's perspective (Gate-4
            // UP-1). Both this check and handler_ex's read of g_agent are under
            // the same g_agent_mu, so the two can't both miss each other: either
            // handler_ex sees the just-published pointer and stops it directly,
            // or it ran first and set g_stop_requested, which we observe here.
            stop_already_requested = g_stop_requested.load(std::memory_order_relaxed);
            if (stop_already_requested)
                g_agent->stop();
        }

        // Report RUNNING now, before run() -- run()'s reconnect loop is unbounded
        // while the server is unreachable (agent.cpp), so waiting for it to return
        // would itself time out the SCM start (parity with the systemd
        // Type=simple unit, which has no readiness protocol either). Skipped if a
        // stop already landed above: the last report the SCM should see before
        // STOPPED is handler_ex's STOP_PENDING, not a RUNNING that immediately
        // reverses it.
        if (!stop_already_requested)
            report_status(SERVICE_RUNNING);

        // F3 fail-closed backstop (Sol rung-7.6 review round 3, finding 2 - and
        // round 4, which caught that this MUST be armed BEFORE agent->run()
        // below, not after: run() itself is not noexcept and has a substantial
        // throwing surface, so a guard constructed only after it returns would
        // miss an exception thrown FROM run() itself). Everything from here
        // through the explicit orphan check further down (run() itself, the
        // logger flush, the report_status() chain) could in principle throw and
        // unwind past that check entirely, which would let normal C++ teardown
        // run while a Guardian I/O worker might still be active - exactly what
        // F3 exists to prevent. Constructed AFTER `agent` (declared above), so
        // reverse-declaration-order destruction runs this guard BEFORE the
        // Agent's own destructor on every exit path, including an unwind into
        // the catch block below - the same pattern `AgentUnpublisher` already
        // relies on. Disarmed once the explicit check has run to completion on
        // the normal path; its destructor is a deliberately non-throwing,
        // unlogged fallback for every other path.
        yuzu::agent::OrphanExitGuard orphan_guard{
            [&] { return agent->guardian_active_io_workers(); }, yuzu::agent::kOrphanDrainGrace, 3};

        agent->run(); // blocks until stop() (via handler_ex, or the catch-up above) or a fatal startup error

        // #4666 PR-2: a bare logger flush() on the now-async logger only enqueues a
        // flush request, with no delivery guarantee. This bounded drain is a best-effort
        // attempt to actually land "Yuzu agent stopped" and similar lines before
        // SERVICE_STOPPED is reported below -- it is NOT a guarantee.
        //
        // Firewalled (governance hardening round, cpp-safety/unhappy-path UP-2 finding):
        // drain_log_bounded() is not declared noexcept. Left unguarded, an exception here
        // would skip the "AN EXPLICIT OPERATOR STOP ALWAYS WINS" report_status() chain
        // immediately below and fall into the outer catch blocks, which report
        // SERVICE_STOPPED with specific=3 -- misreporting a clean operator-initiated stop
        // as a failure and, per SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, potentially triggering
        // an unwanted SC_ACTION_RESTART of the service the operator just stopped (the exact
        // B-7 inversion the comment below exists to prevent).
        try {
            yuzu::agent::drain_log_bounded(std::chrono::milliseconds{200});
        } catch (...) {
        }

        // AN EXPLICIT OPERATOR STOP ALWAYS WINS, AND IT IS TESTED FIRST.
        //
        // A `sc stop` can RACE a fatal failure (a dispatch-pool re-creation that fails on the
        // reconnect path at the same moment). With the failure tested first, we would report a
        // service-specific error -- and because --install-service sets
        // SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, the SCM would then run its recovery actions and
        // RESTART THE SERVICE THE OPERATOR JUST STOPPED. An explicit stop is the one signal that is
        // unambiguously intentional; it must never be overridden by a failure that arrived with it.
        // (governance: unhappy-path B-7.)
        if (g_stop_requested.load(std::memory_order_relaxed)) {
            report_status(SERVICE_STOPPED);
        } else if (agent->startup_failed()) {
            // specific=1 now covers TWO causes: a fatal STARTUP failure (agent construction, or the
            // fail-closed TLS posture with no pinnable CA) AND a fatal MID-LIFE failure (the
            // dispatch pool could not be re-created -- host out of threads). Both mean "could not
            // continue", both should run the SCM's recovery actions, and the log file carries the
            // actual reason. Documented in server-admin.md. (governance: consistency-auditor.)
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
        } else {
            // run() returned on its own, without a STOP/SHUTDOWN control -- unexpected.
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/2);
        }

        // F3 orphan-exit obligation (ADR-0021 rung 7.6; guardian_io_executor.hpp's
        // "ORPHAN PROCESS-EXIT CONTRACT"), Windows SCM path. Mirrors main.cpp's
        // console-mode check: a detached Guardian bounded-I/O worker cannot be
        // joined or force-cancelled, so give it a short grace to actually finish
        // before this function returns and the process runs normal C++ teardown.
        //
        // DELIBERATELY AFTER the report_status chain above, not before it: "AN
        // EXPLICIT OPERATOR STOP ALWAYS WINS" (the comment above) must still hold
        // for what the SCM is TOLD, even when an orphan forces a hard exit right
        // after. hard_exit() only sets the process's raw exit code -- it cannot
        // itself call SetServiceStatus -- so the correct status must already be
        // reported before it runs, never after (Sol rung-7.6 review finding 3).
        {
            // Force synchronization against a possibly-still-in-flight handler_ex
            // or the catch-up block above: stop_requested_ is stop()'s FIRST
            // statement, so run()'s reconnect loop can return before stop()'s
            // LATER steps (guardian_->stop(), dex_observer_->stop()) have actually
            // completed. Both call sites hold g_agent_mu across their entire
            // stop() call; re-acquiring it here blocks until any in-flight call
            // has fully returned before the orphan count below is sampled -
            // otherwise a zero count is meaningless (Sol rung-7.6 review finding
            // 1 - mirrors main.cpp's console-path fix).
            std::lock_guard<std::mutex> lock(g_agent_mu);
        }
        if (const auto n = agent->guardian_active_io_workers(); n > 0) {
            if (!yuzu::agent::wait_for_workers_to_drain(
                    [&] { return agent->guardian_active_io_workers(); },
                    yuzu::agent::kOrphanDrainGrace)) {
                // Firewalled: a logging exception here (including the #4666 PR-2
                // best-effort drain below -- drain_log_bounded() is not declared
                // noexcept) must never skip hard_exit() below (Sol rung-7.6 review
                // finding 2). Both calls share this ONE try/catch, not two separate
                // ones, so nothing between the critical() log and hard_exit() can
                // unwind past this point uncaught.
                try {
                    // "Guardian I/O worker(s)" until PR-A (#2012/#3840): n is now
                    // a SUM (guardian_active_io_workers()'s own doc comment) of
                    // Guardian's own IO executors AND Spark mechanisms' detached
                    // probes - naming only the first source here would
                    // misattribute an incident's real cause once a live Spark
                    // consumer lands (Gate 6 sre finding, PR-A round 5; today
                    // n's Spark addend is provably always 0, so this was
                    // latent, not yet observable).
                    spdlog::critical("{} orphaned Guardian I/O / Spark worker(s) still active "
                                     "{}s after shutdown - forcing process exit rather than race "
                                     "static/DSO teardown against them",
                                     n, yuzu::agent::kOrphanDrainGrace.count());
                    // #4666 PR-2: same best-effort reasoning as the flush replacement
                    // above -- give the critical() line just logged a bounded chance to
                    // actually land before the process exits via hard_exit() below (no
                    // unwinding, no static/DSO teardown -- a queued-but-undelivered
                    // async log line would otherwise be lost).
                    yuzu::agent::drain_log_bounded(std::chrono::milliseconds{200});
                } catch (...) {
                }
                yuzu::agent::hard_exit(3); // the SCM status above already reported the real outcome
            }
        }
        orphan_guard.disarm(); // the explicit check above has run to completion
    } catch (const std::exception& e) {
        // service_main is a raw WINAPI callback invoked directly by the SCM
        // dispatcher thread -- an exception must never cross that C ABI boundary
        // (UB / std::terminate). AgentUnpublisher has already run by this point
        // (stack unwind destructs it before this catch runs), so g_agent is safely
        // cleared regardless of where inside the try the throw originated.
        //
        // Firewalled (governance hardening round, unhappy-path UP-2 finding): the
        // logging call itself is not guaranteed noexcept (async-logger formatting can
        // allocate). Left bare, a throw HERE would cross this catch block's own scope
        // and propagate out of service_main -- a noexcept function -- which calls
        // std::terminate()/aborts the whole process BEFORE report_status() below ever
        // runs. The SCM would then observe a raw crash instead of the coded
        // SERVICE_STOPPED(specific=3) this catch exists to report.
        try {
            spdlog::critical("Unhandled exception in ServiceMain: {}", e.what());
        } catch (...) {
        }
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    } catch (...) {
        // Same firewall as the sibling catch above, same reason.
        try {
            spdlog::critical("Unhandled non-standard exception in ServiceMain");
        } catch (...) {
        }
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    }
}

} // namespace

namespace yuzu::agent::win {

int run_service(std::move_only_function<std::unique_ptr<Agent>()> factory) {
    g_factory = std::move(factory);

    // const_cast is safe here: SERVICE_TABLE_ENTRYW.lpServiceName is only ever READ
    // by StartServiceCtrlDispatcherW for an OWN_PROCESS service (used to match the
    // ServiceMain callback to a name) -- nothing writes through it, so casting away
    // constness off the constexpr kServiceName array is not UB in practice, just an
    // artifact of the Win32 API predating const-correctness (Gate 3 cpp-safety/
    // cpp-expert finding, governance re-run).
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), service_main},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        auto err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // This specific error means the process was NOT launched by the SCM --
            // i.e. --service was passed at a real interactive console by mistake --
            // so a console is guaranteed present here. spdlog's stderr sink is
            // suppressed whenever --service is passed (service_mode gates it in
            // main.cpp, since it can't tell "really under the SCM" from "misused at
            // a console" until this exact call fails), so this specific message
            // would otherwise land only in the log file the operator isn't looking
            // at. Print directly so the one case where we KNOW a console exists
            // actually reaches it (Gate 4 unhappy-path finding, governance re-run).
            std::cerr << "--service is for use by the Windows Service Control Manager; "
                         "run without --service for interactive/console mode\n";
            spdlog::error(
                "--service is for use by the Windows Service Control Manager; "
                "run without --service for interactive/console mode");
        } else {
            spdlog::error("StartServiceCtrlDispatcherW failed: {}", err);
        }
        return EXIT_FAILURE;
    }

    // #4666 PR-2: the dispatcher is documented to return once ServiceMain has reported
    // SERVICE_STOPPED -- which service_main deliberately does BEFORE its own F3 orphan
    // check / ~Agent / catch-block logging finish (see the STOPPED-report comments
    // above). Without this wait, main()'s own async-log-handoff teardown could start
    // while service_main's thread is still an active log producer, racing spdlog's
    // registry (concurrent set_default_logger() vs. an ordinary log call is undefined
    // per spdlog's own documented contract). This wait forces main() to be the sole
    // teardown caller strictly after service_main has genuinely finished, under EITHER
    // possible dispatcher-return timing (if the dispatcher already waits for
    // ServiceMain to fully return, this wait is near-instantaneous). A timeout here
    // means service_main is itself wedged past its own grace -- hard-exit rather than
    // proceed into logger teardown blind.
    //
    // Deliberately NOT reached on the FALSE (failure) path above: that path means
    // ServiceMain may never have run at all (Microsoft documents ERROR_FAILED_
    // SERVICE_CONTROLLER_CONNECT / an invalid table / the dispatcher already running as
    // the only pre-callback failure causes), so there is nothing service_main-side to
    // wait for.
    if (!yuzu::agent::wait_for_service_main_completion(g_service_main_done,
                                                        kServiceMainDrainGrace)) {
        // Governance hardening round, sre finding: unlike the adjacent F3 site
        // (service_main, above), this timeout previously exited with no log line and no
        // drain attempt at all. On Windows this fires strictly AFTER SERVICE_STOPPED has
        // already been reported (no SCM/Event Viewer trace either), so the agent's own
        // log file is the ONLY diagnostic surface for this specific wedge -- leaving it
        // silent made this exit-4 cause indistinguishable, after the fact, from the other
        // two watchdogs that also exit 4. Mirror the F3 pattern: log, then a best-effort
        // bounded drain, both firewalled (this function is not noexcept, but an
        // unguarded throw here would still terminate less predictably than a deliberate
        // hard_exit).
        try {
            spdlog::critical("service_main did not complete within {}ms of the SCM dispatcher "
                              "returning -- hard-exiting rather than starting log teardown "
                              "against a possibly still-logging service_main thread",
                              kServiceMainDrainGrace.count());
            yuzu::agent::drain_log_bounded(std::chrono::milliseconds{200});
        } catch (...) {
        }
        yuzu::agent::hard_exit(yuzu::agent::kShutdownDeadlineExitCode);
    }

    return EXIT_SUCCESS;
}

} // namespace yuzu::agent::win

#endif // _WIN32
