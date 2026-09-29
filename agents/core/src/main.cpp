#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#pragma section(".CRT$XCB", read)
[[maybe_unused]] static void __cdecl diag_before_static_init() {
    const char msg[] = "[DIAG] EXE static-init starting (before C++ globals)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB")) [[maybe_unused]] static void(__cdecl* p_diag_init)() = diag_before_static_init;
#endif

#include <yuzu/agent/updater.hpp>
#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/env_util.hpp>
#include <yuzu/agent/identity_store.hpp>
#include <yuzu/json_log_formatter.hpp>
#include <yuzu/version.hpp>

#include "hard_exit.hpp" // shared TerminateProcess/_exit + F3 orphan-drain poll (rung 7.6)
#include <yuzu/shutdown_watcher.hpp> // POSIX self-pipe + watcher thread (the B2 root fix; shared with the server, #3007)
#include "service_win.hpp" // #1822: Windows SCM ServiceMain/control-handler dispatcher

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include "agent_log_options.hpp"
#include "agent_log_wiring.hpp"
#include "log_handoff.hpp"

#include <atomic>
#include <csignal>
#ifdef _WIN32
#include <win_sc_handle.hpp> // shared yuzu::win SC_HANDLE RAII owner (#1822)
#else
#include <fcntl.h>  // O_CLOEXEC / O_NONBLOCK / FD_CLOEXEC on the shutdown self-pipe
#include <unistd.h>
#endif

#include <cerrno>
#include <cstring>
#include <thread>
#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <optional>
#include <mutex>
#include <string>
#include <vector>

static std::atomic<yuzu::agent::Agent*> g_agent{nullptr};

// Both globals below are read FROM A SIGNAL HANDLER. Only a lock-free atomic is legal
// there ([support.signal]) — a non-lock-free one takes an internal spinlock, and a handler
// interrupting a thread that holds it deadlocks the process (governance Gate-8 cpp-safety).
static_assert(std::atomic<yuzu::agent::Agent*>::is_always_lock_free);

#ifdef _WIN32
/// WINDOWS ONLY. Serialises the console handler's `g_agent->stop()` against main()'s
/// unpublish-and-destroy, so the Agent cannot be destroyed while a stop() is still running on
/// it. Taken ONLY inside the `#ifdef _WIN32` branch of on_signal — where the CRT has already
/// handed us an ordinary thread, so locking is legal. It must NEVER be taken on the POSIX
/// path: a mutex in a real signal handler is not async-signal-safe, which is precisely why
/// POSIX uses the self-pipe and gets this barrier from ~ShutdownWatcher's join() instead.
///
/// This mirrors service_win.cpp's `g_agent_mu` + AgentUnpublisher (#1822), which solved the
/// same race for the SCM service path. The console path never had it.
/// (governance Gate-8 round 8 unhappy-path UP8-1.)
static std::mutex g_agent_mu;
#endif

/// Signals seen. The SECOND one escalates — see on_signal.
///
/// DELIBERATELY NOT inside `#ifndef _WIN32`. It used to be, which meant the escalation was
/// POSIX-only and Windows had NO way out of a wedged graceful stop at all. That became acute
/// once the console handler started holding g_agent_mu across `a->stop()` (round 8): a second
/// Ctrl-C would arrive on a fresh CRT thread and BLOCK on the mutex the first one holds across
/// an unbounded guardian_/dex_observer_ drain — so the operator's second Ctrl-C did nothing at
/// all, forever. Escalation must exist on BOTH platforms, and must run BEFORE any lock.
/// (governance Gate-8 round 9 — a defect introduced by round 8's own fix.)
static std::atomic<int> g_signal_count{0};
static_assert(std::atomic<int>::is_always_lock_free);

#ifndef _WIN32
/// Write end of the shutdown self-pipe. The handler's ONLY job is to poke this.
static std::atomic<int> g_shutdown_wfd{-1};
static_assert(std::atomic<int>::is_always_lock_free);
#endif

// ─────────────────────────────────────────────────────────────────────────────────
// SIGNAL HANDLING — the handler must do NOTHING but poke a pipe.
//
// It used to call `a->stop()` directly, under a comment that said "Only async-signal-safe
// calls allowed here". Agent::stop() is not remotely that: it takes mutexes, joins worker
// threads, calls sd_bus_unref() (malloc/free) and logs through spdlog. Calling any of them
// from a handler is undefined behaviour, and it had a concrete failure mode:
//
//   A process-directed signal is delivered on an ARBITRARY thread that has not blocked it,
//   and nothing blocked it anywhere. If it landed on a thread that stop() then JOINS — a
//   SparkEngine wheel/mechanism/consumer thread, a Guardian drift worker, the DEX observer,
//   the updater — that join is a SELF-JOIN. std::thread::join() throws
//   std::system_error(resource_deadlock_would_occur), the exception escapes Agent::stop()
//   (which is `noexcept`), and the agent std::terminate()s. On SIGTERM: on every
//   `systemctl stop`, every reboot, every OTA cycle. It could also self-DEADLOCK, by
//   re-entering a non-recursive mutex the interrupted thread already held.
//
// Fixing it here, at the root, is what lets SparkEngine DELETE its whole mitigation layer
// (signal masking on its threads, a same-thread re-entry guard, a lock-free self-join
// bail-out). Those existed only to survive stop() running on a spark thread; with the
// teardown moved off the handler, it cannot.
//
// FIVE TRAPS, all hit for real by an earlier attempt. Do not "simplify" past them:
//   1. A bare joinable std::thread in main()'s scope. `agent->run()` is NOT wrapped in a
//      try at its call site, so a throw unwinds past it → ~std::thread on a joinable
//      thread → std::terminate. Hence the RAII type below.
//   2. A throw from the RAII type's CONSTRUCTOR BODY skips its destructor. std::thread's
//      ctor throws std::system_error under EAGAIN — on exactly the thread-exhausted host
//      this is meant to survive. RAII does not save you; the ctor cleans up by hand.
//   3. pipe2(fds, O_CLOEXEC | O_NONBLOCK) sets O_NONBLOCK on BOTH ends. The watcher's
//      read() then returns EAGAIN immediately, the thread exits at once, and SIGTERM
//      silently stops triggering a graceful stop while still killing the process via the
//      default disposition — so nothing LOOKS broken. O_NONBLOCK goes on the WRITE end
//      only; the read end must BLOCK.
//   4. Without O_CLOEXEC both fds are inherited by every popen()/fork+exec child (the
//      trigger engine plus the ioc / firewall / services / software_actions / wol /
//      license_scan plugins) — handing every subprocess a lever to shut the agent down.
//   5. Closing the read end while keeping the write end open raises SIGPIPE, whose
//      disposition here is SIG_DFL — so a late handler write, or the destructor's own
//      sentinel write, KILLS the agent (exit 141). Leave BOTH ends open for the run.
//
// Windows keeps the direct call: the CRT dispatches console/CTRL signals on a freshly
// created thread, so it is already an ordinary thread context; SIGTERM is not meaningfully
// raised there, and the service path goes through service_win.cpp's SCM control thread.
// ─────────────────────────────────────────────────────────────────────────────────
/// LAST-RESORT HANDLER, used ONLY when the shutdown watcher could not be constructed (fd or thread
/// exhaustion at boot). It does not try to be graceful — it cannot, there is no watcher to run the
/// teardown — it only guarantees the process remains KILLABLE, including as PID 1 in a container
/// where a default disposition is discarded by the kernel. Async-signal-safe: no locks, no stdio.
/// spdlog allocates and RETHROWS non-std exceptions, and main() has NO enclosing handler — so a
/// throw from a log call on an OOM/exhausted host is a std::terminate WITHOUT unwinding, which is
/// the very thing the surrounding code exists to prevent. Every log on a failure path in this file
/// goes through here. (thread_pool.hpp and ShutdownWatcher::log_quietly carry the same firewall.)
static void log_quietly(const char* what) noexcept {
    try {
        spdlog::error("{}", what);
    } catch (...) {
        // Nothing to do, and nowhere to say it. A logger must never kill the agent.
    }
}

/// Same firewall as log_quietly() above, info level: used by on_signal's barriered
/// call sites (the watcher callback, the Windows g_agent_mu block) now that logging
/// is async and no longer safe to attempt inside the signal handler itself (#4666
/// PR-2 -- see R-PRODUCER in the callers below).
static void log_info_quietly(const char* what) noexcept {
    try {
        spdlog::info("{}", what);
    } catch (...) {
        // Nothing to do, and nowhere to say it. A logger must never kill the agent.
    }
}

static void on_signal_hard_exit(int sig) {
    (void)sig;
    // See hard_exit.hpp for why TerminateProcess (not ::_exit()) on Windows,
    // and why ::_exit() (not std::exit()) on POSIX. Async-signal-safe either way.
    yuzu::agent::hard_exit(1);
}

static void on_signal(int sig) {
    // A process-directed signal lands on an ARBITRARY unmasked thread — possibly one sitting
    // between a failing syscall and its `errno` check. Every write() below can set errno (the
    // O_NONBLOCK write end is *expected* to return EAGAIN), so clobbering it here would
    // silently rewrite an unrelated thread's error. Save and restore around the handler.
    // (Gate-8 round 7 cpp-expert. Not restored before _exit — nothing runs after it.)
    const int saved_errno = errno;

    // Only async-signal-safe calls allowed here — and now that is actually true.
    (void)sig;

    // ── SECOND SIGNAL => ESCALATE. BOTH PLATFORMS, AND BEFORE ANY LOCK. ──────────────
    //
    // WHY IT IS FIRST, above the platform split and above g_agent_mu. A wedged graceful stop
    // is exactly when escalation is needed, and it is also exactly when everything below can
    // block:
    //   * POSIX — the watcher thread cannot escalate: its callback IS Agent::stop(), which
    //     blocks until teardown completes (stop() drains guardian_/dex_observer_ with an
    //     UNBOUNDED wait), so a wedged teardown leaves it parked and it never reads another
    //     byte. The handler is the only thing still able to act.
    //   * WINDOWS — the console handler holds g_agent_mu across `a->stop()` (below). If the
    //     escalation sat after that lock, a second Ctrl-C would arrive on a fresh CRT thread
    //     and BLOCK on the mutex the first one is holding across the wedged drain. The
    //     operator's second Ctrl-C would do nothing, forever.
    //
    // Escalation used to live inside the POSIX branch only, so Windows had NO escape from a
    // wedged stop at all — and round 8's g_agent_mu turned "second Ctrl-C returns uselessly"
    // into "second Ctrl-C blocks forever". Hoisted here. `_exit()` is async-signal-safe and
    // takes no locks, so it works from either platform's handler context.
    // (governance Gate-8 round 9 — a defect introduced by round 8's own fix.)
    //
    // HONEST CAVEAT, WINDOWS, UNVERIFIED ON HARDWARE: the UCRT is documented to reset a
    // signal()-installed handler to SIG_DFL before invoking it for SIGINT. If it does, a
    // second Ctrl-C never re-enters here at all — it takes the default disposition, which also
    // terminates, so the OPERATOR still gets out either way. What this hoist guarantees is the
    // thing that actually mattered: IF the handler is re-entered, it CANNOT block on
    // g_agent_mu behind a wedged stop(). Do not upgrade this comment to "the escalation is what
    // rescues Windows" without a two-Ctrl-C-during-a-wedged-stop repro on a real Windows box.
    // (Deliberately NOT re-arming with std::signal(sig, on_signal) here: that would be new,
    // unverifiable behaviour on the one platform this session cannot build or test.)
    if (g_signal_count.fetch_add(1, std::memory_order_acq_rel) >= 1) {
        // NOTHING MAY PRECEDE THE EXIT — not even a log.
        //
        // This used to write a "Second signal ..." banner to stderr first. But stderr is a
        // BLOCKING pipe under Docker's json-logger and under journald, so a stalled collector or
        // a full log disk blocks the write INSIDE THE HANDLER — and the escape hatch whose whole
        // purpose is to work when everything else is wedged became the thing that wedged. The
        // operator still gets out: the process dies immediately. BE HONEST ABOUT WHAT IS LOST —
        // the banner is not relocated anywhere, it is GONE, and exit 1 here is indistinguishable
        // from a startup failure. A second signal therefore produces no diagnostic at all.
        // #2233 item 3 ("S+"): the internal shutdown deadline that was meant to carry that
        // diagnosis has landed (agents/core/src/shutdown_deadline_guard.hpp), but it fires
        // hard_exit(kShutdownDeadlineExitCode) from a DETACHED worker thread, not from an
        // "ordinary thread where logging is safe" in the sense this comment originally meant —
        // it still does not log, for the same blocking-pipe reason this handler doesn't. A
        // wedged stop is diagnosed from the supervisor's log, the absence of "Yuzu agent
        // stopped", and usually also the process's own exit code (4 = the deadline fired,
        // 5 = the log hand-off teardown deadline or a teardown failure — see log_handoff.hpp,
        // vs. this handler's exit 1, vs. F3's exit 3) — "usually", not reliably: a genuinely
        // wedged stop can trigger BOTH this handler (an operator sending a second signal) AND
        // the watchdog above for the SAME wedge, and whichever one's exit call the kernel
        // schedules first wins — governance Gate 5 chaos-injector reproduced this empirically
        // across many repeated trials: always exactly one of the two codes, never a third
        // value or a crash, but genuinely nondeterministic which one — see this PR's
        // governance record for the exact trial counts. Treat the
        // exit code as a useful hint, not a certain diagnosis, when both paths could plausibly
        // have fired.
        // (governance: security-guardian MEDIUM-2, unhappy-path UP-C7, chaos-injector; this PR.)
        // See hard_exit.hpp: TerminateProcess on Windows (no DllMain, no loader
        // lock), ::_exit() on POSIX (async-signal-safe, cannot block).
        yuzu::agent::hard_exit(1);
    }

#ifdef _WIN32
    // Windows: the CRT dispatches this on a freshly created ORDINARY thread, not in a real
    // signal context, so the teardown may run inline and a mutex is legal here (it would not
    // be on POSIX — that is the entire reason for the self-pipe below).
    //
    // HOLD g_agent_mu ACROSS a->stop(), not merely across the load. main() takes the same
    // mutex to unpublish, so it BLOCKS until an in-flight stop() has returned, and only then
    // destroys the Agent. Without that barrier, `stop()` (which drains guardian_/dex_observer_
    // with an unbounded wait) runs on THIS thread while main returns from run(), unpublishes
    // and destroys the Agent out from under it — reading guardian_, spark_engine_, updater_
    // and ctx_mu_ as they are destructed. Nulling an atomic pointer does NOT close that
    // window; it only closes the load-null race.
    //
    // POSIX gets this barrier for free from ~ShutdownWatcher's join() (the watcher thread is
    // the one running stop(), and it is joined before ~Agent). Windows has no watcher, so it
    // needs the lock. service_win.cpp's SCM path already does exactly this (g_agent_mu held
    // across g_agent->stop(), AgentUnpublisher taking the same mutex, #1822); the CONSOLE path
    // never got it — and an earlier version of the comment in main() below wrongly claimed
    // that unpublishing g_agent had closed this. (governance Gate-8 round 8 unhappy-path UP8-1.)
    //
    // Blocking here is SAFE ONLY BECAUSE the escalation above runs first: a wedged stop() can
    // park this thread indefinitely, and the second signal is what rescues the operator.
    {
        std::lock_guard<std::mutex> lock(g_agent_mu);
        if (auto* a = g_agent.load(std::memory_order_acquire)) {
            log_info_quietly("Received signal, shutting down...");
            a->stop();
        }
    }
#else
    // ── THE PIPE BYTE GOES FIRST. THE LOG IS NEVER ALLOWED TO GATE THE TEARDOWN. ──────
    //
    // stderr is a BLOCKING pipe under Docker's json-logger and under journald. A stalled log
    // consumer, a full log disk, or a wedged collector makes this write() block INSIDE THE
    // SIGNAL HANDLER — and glibc masks the signal while its handler runs, so the operator's
    // second SIGTERM cannot even be delivered. Logging first therefore defeated BOTH the
    // graceful stop AND the escalation that exists to rescue it, on a fleet-correlated fault
    // (disk-full hits every endpoint at once). The pipe write is O_NONBLOCK and cannot block;
    // the log is best-effort and comes after. (governance: security-guardian + unhappy-path.)
    const int wfd = g_shutdown_wfd.load(std::memory_order_acquire);
    if (wfd >= 0) {
        const char byte = yuzu::ShutdownWatcher::kSignal;
        ssize_t n = ::write(wfd, &byte, 1); // async-signal-safe, and CANNOT block (O_NONBLOCK)
        (void)n; // EAGAIN on a full pipe just means a shutdown is already pending — which is
                 // exactly what we wanted.
    }
#endif
    errno = saved_errno;
}


// Verifies preconditions and constructs the Agent. Shared by the console path and
// the Windows service path (service_win.cpp's ServiceMain calls this on its own
// thread, after reporting SERVICE_START_PENDING) so both go through identical
// startup checks. Returns nullptr on failure; the reason is already spdlog'd.
static std::unique_ptr<yuzu::agent::Agent> make_agent(yuzu::agent::Config cfg) {
    // Verify SQLite was compiled with thread-safety (FULLMUTEX requires SQLITE_THREADSAFE != 0)
    if (sqlite3_threadsafe() == 0) {
        spdlog::critical(
            "SQLite compiled with SQLITE_THREADSAFE=0 — FULLMUTEX disabled, concurrent access unsafe");
        return nullptr;
    }

    // Resolve persistent agent ID
    auto id_result = yuzu::agent::resolve_agent_id(cfg.agent_id, cfg.data_dir / "agent.db");
    if (!id_result) {
        spdlog::error("Failed to resolve agent ID: {}", id_result.error().message);
        return nullptr;
    }
    cfg.agent_id = std::move(*id_result);
    spdlog::info("Agent ID: {}", cfg.agent_id);
    // Unconditional so a service left running against the wrong address (e.g. a
    // manual --install-service re-run that reset binPath and dropped a prior
    // --server, or a fleet upgrade script that didn't replay --server on a silent
    // reinstall) is diagnosable from the log alone -- the reconnect loop in run()
    // is otherwise silent about what it's even trying to reach (Gate 4 unhappy-
    // path finding, governance re-run).
    spdlog::info("Server address: {}", cfg.server_address);

    return yuzu::agent::Agent::create(std::move(cfg));
}

int main(int argc, char* argv[]) {
    CLI::App app{"Yuzu Agent", "yuzu-agent"};
    app.set_version_flag("--version",
                         std::format("{}  ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash));

    yuzu::agent::Config cfg;
    std::string log_level = "info";
    std::string log_file;
    size_t log_max_size = 50 * 1024 * 1024; // 50 MB
    int log_max_files = 5;

    app.add_option("--server", cfg.server_address, "Server address (host:port)")
        ->default_val("localhost:50051")
        ->envname("YUZU_SERVER");
    app.add_option("--agent-id", cfg.agent_id, "Stable agent UUID (auto-generated if empty)")
        ->envname("YUZU_AGENT_ID");
    app.add_option("--data-dir", cfg.data_dir, "Directory for persistent agent state")
        ->default_val(yuzu::agent::default_data_dir().string())
        ->envname("YUZU_DATA_DIR");
    // Default plugin dir: <exe_dir>/../plugins (matches meson build layout)
    auto exe_dir = std::filesystem::path(argv[0]).parent_path();
    if (exe_dir.empty())
        exe_dir = std::filesystem::current_path();
    app.add_option("--plugin-dir", cfg.plugin_dir, "Directory containing plugin shared libraries")
        ->default_val((exe_dir / ".." / "plugins").string())
        ->envname("YUZU_PLUGIN_DIR");
    app.add_option("--heartbeat", cfg.heartbeat_interval, "Heartbeat interval in seconds")
        ->default_val(30)
        ->envname("YUZU_HEARTBEAT");
    app.add_flag("--no-tls", "Disable TLS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--ca-cert", cfg.tls_ca_cert, "PEM CA certificate for server verification")
        ->envname("YUZU_CA_CERT");
    // NOTE: no ->envname() here — CLI11 binds an env var as PRESENT/ABSENT and ignores
    // its value, so YUZU_TLS_SYSTEM_ROOTS=0 would still ENABLE the fallback (#1303 — a
    // footgun for a security flag). The env var is handled value-aware below (env_truthy),
    // seeded before parse so this CLI flag still wins (it can only ever opt IN, the secure
    // direction).
    app.add_flag("--tls-system-roots",
                 "Allow TLS verification against the SYSTEM trust store when no CA is pinned "
                 "(no --ca-cert and no install CA found). Use ONLY when the server certificate "
                 "chains to a public/corporate CA already in the system store — otherwise the "
                 "agent fails closed (#1303). Env: YUZU_TLS_SYSTEM_ROOTS=1/true/yes/on enables; "
                 "0/false/no/off/unset disables.")
        ->each([&cfg](const std::string&) { cfg.tls_allow_system_trust = true; });
    app.add_option("--client-cert", cfg.tls_client_cert, "PEM client certificate for mTLS")
        ->envname("YUZU_CLIENT_CERT");
    app.add_option("--client-key", cfg.tls_client_key, "PEM client private key for mTLS")
        ->envname("YUZU_CLIENT_KEY");
    app.add_option("--cert-store", cfg.cert_store,
                   "Windows certificate store name (e.g. MY) for mTLS")
        ->envname("YUZU_CERT_STORE");
    app.add_option("--cert-subject", cfg.cert_subject, "Subject CN match for cert store lookup")
        ->envname("YUZU_CERT_SUBJECT");
    app.add_option("--cert-thumbprint", cfg.cert_thumbprint,
                   "SHA-1 thumbprint for cert store lookup (hex)")
        ->envname("YUZU_CERT_THUMBPRINT");
    app.add_flag("--no-cert-discovery", "Disable auto-discovery of certs from well-known paths")
        ->each([&cfg](const std::string&) { cfg.cert_auto_discovery = false; });
    app.add_option("--cert-dir", cfg.cert_dir,
                   "Directory for the auto-provisioned per-agent mTLS credential "
                   "(default: <data-dir>/certs)")
        ->envname("YUZU_CERT_DIR");
    app.add_flag("--no-auto-provision-cert",
                 "Disable PKI auto-provisioning (do not generate a CSR / request a "
                 "per-agent client certificate at enrollment)")
        ->each([&cfg](const std::string&) { cfg.auto_provision_cert = false; });
    app.add_option("--enrollment-token", cfg.enrollment_token,
                   "Pre-shared enrollment token for server registration")
        ->envname("YUZU_ENROLLMENT_TOKEN");
    app.add_flag("--debug", "Enable debug mode (diagnostic features)")
        ->each([&cfg](const std::string&) { cfg.debug_mode = true; });
    app.add_flag("--verbose", "Enable verbose logging")->each([&cfg](const std::string&) {
        cfg.verbose_logging = true;
    });
    std::string log_format = "text";
    app.add_option("--log-level", log_level, "Log level: trace|debug|info|warn|error")
        ->default_val("info")
        ->envname("YUZU_LOG_LEVEL");
    app.add_option("--log-format", log_format, "Log format: text|json")
        ->default_val("text")
        ->envname("YUZU_LOG_FORMAT");
    app.add_option("--log-file", log_file, "Log file path (enables file logging)")
        ->envname("YUZU_LOG_FILE");
    app.add_option("--log-max-size", log_max_size, "Max log file size in bytes (default: 50MB)")
        ->default_val(50 * 1024 * 1024)
        ->envname("YUZU_LOG_MAX_SIZE");
    app.add_option("--log-max-files", log_max_files, "Max rotated log files (default: 5)")
        ->default_val(5)
        ->envname("YUZU_LOG_MAX_FILES");
    app.add_option("--plugin-allowlist", cfg.plugin_allowlist,
                   "Path to sha256sum-format allowlist file for plugin verification")
        ->envname("YUZU_PLUGIN_ALLOWLIST");
    app.add_option("--plugin-trust-bundle", cfg.plugin_trust_bundle,
                   "PEM CA bundle for plugin code-signing verification (operator-supplied "
                   "or pointing at the Yuzu self-managed CA root)")
        ->envname("YUZU_PLUGIN_TRUST_BUNDLE");
    app.add_flag("--plugin-require-signature", cfg.plugin_require_signature,
                 "Reject plugins that have no .sig sibling file (default: allow unsigned "
                 "if --plugin-trust-bundle is set, for transitional rollouts)")
        ->envname("YUZU_PLUGIN_REQUIRE_SIGNATURE");
    app.add_option("--update-trust-bundle", cfg.update_trust_bundle,
                   "PEM CA bundle for verifying the code-signing certificate on OTA update "
                   "binaries (#416). Place it at install time, NOT over the update channel: a "
                   "trust anchor delivered by the party being verified anchors nothing. Unset "
                   "disables signature checking entirely.")
        ->envname("YUZU_UPDATE_TRUST_BUNDLE");
    app.add_flag("--update-require-signature", cfg.update_require_signature,
                 "Reject OTA update packages that carry no signature (default: allow unsigned "
                 "if --update-trust-bundle is set, for transitional rollouts). A signature that "
                 "is PRESENT and fails to verify is rejected either way.")
        ->envname("YUZU_UPDATE_REQUIRE_SIGNATURE");
    app.add_flag("--no-auto-update", "Disable OTA auto-updates")->each([&cfg](const std::string&) {
        cfg.auto_update = false;
    });
    int update_interval_sec = 21600;
    app.add_option("--update-check-interval", update_interval_sec,
                   "Update check interval in seconds (default: 21600 = 6h)")
        ->default_val(21600)
        ->envname("YUZU_UPDATE_CHECK_INTERVAL");

    app.add_flag("--dex-disable", cfg.dex_disable,
                 "Disable the Guardian DEX crash recorder (collect no process-crash "
                 "telemetry). Deploy-time opt-out; not a server-side runtime toggle.")
        ->envname("YUZU_AGENT_DEX_DISABLE");

    app.add_flag("--inventory-disable", cfg.inventory_disable,
                 "Disable the daily installed-software inventory sync (ADR-0016): collect "
                 "and push no installed-software inventory. Deploy-time opt-out for "
                 "jurisdictions / works-council agreements that require it off; not a "
                 "server-side runtime toggle.")
        ->envname("YUZU_AGENT_INVENTORY_DISABLE");

    app.add_flag("--spark-disable", cfg.spark_disable,
                 "Disable the SparkEngine detection engine (ADR-0021 Stage-2): it is never "
                 "instantiated, watches nothing, and reports no capability or health "
                 "counters. The heartbeat still carries two facts — that spark is off, and "
                 "that this was deliberate (spark_running=0, spark_disabled=1) — so the "
                 "fleet can tell a deliberate opt-out apart from an engine that FAILED to "
                 "start. Deploy-time opt-out; the enforcing legacy Guardian path is "
                 "unaffected. Not a server-side runtime toggle.")
        ->envname("YUZU_AGENT_SPARK_DISABLE");

    // SLE (ADR-0024 Decision 11): how the software_licensing source records a
    // detected per-user licence's local profile name. hash (default) = a
    // per-agent keyed pseudonym HMAC-SHA256(k_agent, profile)/16-hex; collect =
    // the raw profile name (opt-in); omit = no identifier (user_scope still marks
    // the detection per-user). CLI::IsMember rejects anything else at parse.
    app.add_option("--license-scan-user-ref", cfg.license_scan_user_ref,
                   "How the software_licensing sync records per-user licence profile names: "
                   "collect|hash|omit (default hash — a per-agent keyed pseudonym). "
                   "Env: YUZU_AGENT_LICENSE_SCAN_USER_REF.")
        ->default_val("hash")
        ->check(CLI::IsMember({"collect", "hash", "omit"}))
        ->envname("YUZU_AGENT_LICENSE_SCAN_USER_REF");

    // Windows service management
    bool install_service = false;
    bool remove_service = false;
    bool service_mode = false;
    app.add_flag("--install-service", install_service, "Install as Windows service and exit");
    app.add_flag("--remove-service", remove_service, "Remove Windows service and exit");
    // Internal marker set by --install-service on the service binPath (and by the
    // installer) so the process knows to run under the SCM instead of as a console
    // program. Hidden from --help via the empty group; not meant for interactive use.
    app.add_flag("--service", service_mode, "Run under the Windows Service Control Manager")
        ->group("");

    // #1303: seed the security fallback from a VALUE-AWARE env var BEFORE parse so a
    // passed --tls-system-roots CLI flag still wins (it only opts in). Without this,
    // CLI11's presence-only envname would treat YUZU_TLS_SYSTEM_ROOTS=0 as "enabled" and
    // silently re-open the fail-open posture the operator believes is off.
    cfg.tls_allow_system_trust = yuzu::agent::env_truthy(std::getenv("YUZU_TLS_SYSTEM_ROOTS"));

    CLI11_PARSE(app, argc, argv);

    // Fail closed on a combination that would silently fail OPEN.
    //
    // Signature checking is gated on a trust bundle being configured, so
    // --update-require-signature with no --update-trust-bundle would set a flag
    // that is never read: every update would apply unverified while the operator
    // believed enforcement was on. Refuse to start instead. This mirrors the
    // guard --plugin-require-signature carries (agent.cpp, governance hardening
    // round 1, UP-7), but is sited HERE rather than beside the plugin scan so it
    // cannot be skipped by a deployment that loads no plugins.
    // Designated initialisers, matching agent.cpp: positional init here is
    // member-order-coupled, so a field inserted before signature_trust_bundle
    // would silently rebind this guard's operands.
    if (yuzu::agent::UpdateConfig{.signature_trust_bundle = cfg.update_trust_bundle,
                                  .require_signature = cfg.update_require_signature}
            .would_fail_open()) {
        std::cerr << "--update-require-signature is set but --update-trust-bundle is empty. "
                     "Refusing to start: this combination would silently fail open (every OTA "
                     "update would be applied unverified).\n";
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    if (install_service || remove_service) {
        yuzu::win::ScHandle scm;
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
        if (!scm) {
            std::cerr << "Failed to open SCM (run as administrator)\n";
            return EXIT_FAILURE;
        }
        if (install_service) {
            wchar_t exe_path[MAX_PATH];
            DWORD exe_path_len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            if (exe_path_len == 0 || exe_path_len == MAX_PATH) {
                std::cerr << "Failed to resolve the agent's own executable path\n";
                return EXIT_FAILURE;
            }
            // #1822: quote the path (a bare path containing spaces, e.g. under
            // "Program Files", is otherwise misparsed by the SCM) and append the
            // --service marker the SCM-launched process needs to find the
            // ServiceMain dispatcher instead of running the console main().
            std::wstring bin_path = yuzu::agent::win::make_service_binpath(exe_path);

            yuzu::win::ScHandle svc;
            svc.reset(CreateServiceW(scm.get(), yuzu::agent::win::kServiceName, L"Yuzu Agent",
                                     SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                     SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin_path.c_str(),
                                     nullptr, nullptr, nullptr, nullptr, nullptr));

            bool updated_existing = false;
            if (!svc) {
                DWORD create_err = GetLastError();
                if (create_err == ERROR_SERVICE_MARKED_FOR_DELETE) {
                    // 1072: the service was just deleted (e.g. a --remove-service
                    // moments earlier, or a concurrent uninstall) and stays in this
                    // state until every open handle to it closes -- typically the
                    // exiting old process's own SCM handle. Distinguished from the
                    // generic failure below so a scripted repair/reinstall doesn't
                    // read "Failed to create service" as an unrelated problem when a
                    // short retry would succeed (Gate 4 unhappy-path finding,
                    // governance re-run).
                    std::cerr << "Service is pending deletion from a recent removal -- "
                                 "wait a moment and retry --install-service\n";
                    return EXIT_FAILURE;
                }
                if (create_err != ERROR_SERVICE_EXISTS) {
                    std::cerr << "Failed to create service\n";
                    return EXIT_FAILURE;
                }
                // Idempotent re-install: heals a stale binPath from an earlier
                // (pre-#1822) install that lacks the --service marker, or one whose
                // args changed. SERVICE_NO_CHANGE preserves start type / error
                // control / everything else.
                svc.reset(OpenServiceW(scm.get(), yuzu::agent::win::kServiceName,
                                       SERVICE_CHANGE_CONFIG));
                if (!svc) {
                    std::cerr << "Service exists but could not be opened for update\n";
                    return EXIT_FAILURE;
                }
                if (!ChangeServiceConfigW(svc.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                          SERVICE_NO_CHANGE, bin_path.c_str(), nullptr, nullptr,
                                          nullptr, nullptr, nullptr, nullptr)) {
                    std::cerr << "Failed to update existing service configuration\n";
                    return EXIT_FAILURE;
                }
                updated_existing = true;
            }

            // Each of these is best-effort hardening on top of the core binPath fix
            // (description / delayed-start / crash-and-error recovery) -- a failure
            // here must not abort the install (the service is already usable
            // without it), but silently swallowing it would leave e.g. the
            // recovery-actions guarantee unconfigured while still printing
            // "installed successfully" (Gate-4 UP-6). Warn, don't abort.
            SERVICE_DESCRIPTIONW desc;
            desc.lpDescription = const_cast<wchar_t*>(L"Yuzu endpoint management agent");
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc))
                std::cerr << "Warning: failed to set service description (" << GetLastError()
                          << ")\n";
            SERVICE_DELAYED_AUTO_START_INFO delayed = {TRUE};
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                       &delayed))
                std::cerr << "Warning: failed to set delayed auto-start (" << GetLastError()
                          << ")\n";
            SC_ACTION actions[3] = {
                {SC_ACTION_RESTART, 60000},
                {SC_ACTION_RESTART, 60000},
                {SC_ACTION_RESTART, 60000}};
            SERVICE_FAILURE_ACTIONSW failure = {};
            failure.dwResetPeriod = 86400;
            failure.cActions = 3;
            failure.lpsaActions = actions;
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failure))
                std::cerr << "Warning: failed to configure crash-recovery actions ("
                          << GetLastError() << ")\n";
            // #1822: recovery actions only fire on a crash by default -- also fire
            // them on a clean exit with an error (e.g. the #1303 fail-closed
            // startup refusal), approximating systemd's Restart=always.
            SERVICE_FAILURE_ACTIONS_FLAG flag{TRUE};
            if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag))
                std::cerr << "Warning: failed to enable recovery-on-error-exit ("
                          << GetLastError() << ")\n";

            std::cout << (updated_existing ? "Service 'YuzuAgent' updated\n"
                                           : "Service 'YuzuAgent' installed successfully\n");
        }
        if (remove_service) {
            yuzu::win::ScHandle svc;
            svc.reset(
                OpenServiceW(scm.get(), yuzu::agent::win::kServiceName, DELETE | SERVICE_STOP));
            if (svc) {
                SERVICE_STATUS status;
                ControlService(svc.get(), SERVICE_CONTROL_STOP, &status);
                DeleteService(svc.get()) ? std::cout << "Service removed\n"
                                         : std::cerr << "Failed to delete service\n";
            } else {
                std::cerr << "Service not found\n";
                return EXIT_FAILURE;
            }
        }
        return EXIT_SUCCESS;
    }
#endif

    cfg.update_check_interval = std::chrono::seconds(update_interval_sec);

    cfg.log_level = log_level;
    if (cfg.verbose_logging) {
        log_level = "trace";
        cfg.log_level = "trace";
    }

    // Configure logging — async hand-off (#4666 PR-2), replacing the previous
    // synchronous spdlog setup that could wedge process shutdown on a blocked log
    // destination (reproduced empirically: a 4KiB-constrained stderr pipe under
    // SIGTERM left the pre-fix agent alive past 8s and requiring SIGKILL).
    spdlog::set_level(spdlog::level::from_str(log_level));

    // AgentLogCli::service_mode is caller-resolved (agent_log_options.hpp's own doc
    // comment: "pass `_WIN32 && cli_service_mode`") -- `service_mode` here is
    // unconditionally declared (Windows-meaningful only, main.cpp's --service flag
    // above), so on a non-Windows build it must be pinned to false rather than
    // forwarded raw, or a stray `--service` on Linux would silently flip the log
    // sink to file-only and invent a default log path that main.cpp's pre-#4666
    // behaviour never did outside `#ifdef _WIN32`.
    const yuzu::agent::AgentLogCli log_cli{
        .log_file = log_file,
        .log_max_size = log_max_size,
        .log_max_files = log_max_files,
#ifdef _WIN32
        .service_mode = service_mode,
#else
        .service_mode = false,
#endif
        .data_dir = cfg.data_dir,
    };
    const auto log_opts = yuzu::agent::make_log_handoff_options(log_cli);

    auto created_log_handoff = yuzu::agent::LogHandoff::create(log_opts);
    if (!created_log_handoff) {
        std::cerr << "cannot start the log hand-off thread: " << created_log_handoff.error()
                  << "\n";
        return EXIT_FAILURE;
    }
    // SINGLE OWNER, SINGLE TEARDOWN CALLER — main() only, via log_epilogue's
    // destructor below. Declared here, before `agent` and before the Windows
    // service early-return, so R-EPILOGUE's declaration-order guarantee covers
    // EVERY return path in this function. Never add an explicit teardown() call,
    // and never call teardown() from the watcher callback, a signal handler, a
    // watchdog action, or any hard_exit() path — see log_handoff.hpp's
    // THREAD-SAFETY CONTRACT (destructor-as-winner use-after-free) and
    // agent_log_wiring.hpp's R-LOGGER rule. Every new non-main log call this file
    // adds must run inside a barrier main() already waits on before this epilogue
    // (the watcher join, or the g_agent_mu critical section) — see R-PRODUCER.
    std::unique_ptr<yuzu::agent::LogHandoff> log_handoff = std::move(*created_log_handoff);
    yuzu::agent::LogHandoffEpilogue log_epilogue{*log_handoff};

    if (!yuzu::agent::install_log_handoff_in_this_image(
            *log_handoff, spdlog::level::from_str(log_level), log_format == "json")) {
        std::cerr << "cannot install the log hand-off logger\n";
        return EXIT_FAILURE; // log_epilogue's destructor still tears down cleanly here
    }
    if (log_handoff->used_log_file_fallback()) {
        // Format the RESOLVED path (log_opts.log_file), not the raw CLI log_file string:
        // for a Windows service using its implicit default (no --log-file given), the
        // default is resolved only into log_opts by make_log_handoff_options() above —
        // the CLI-local log_file stays empty, and formatting it here printed a
        // diagnostic naming no path at all, on exactly the configuration where an
        // operator has no other way to learn which path to fix (adversarial-review
        // finding, governance-hardening round). used_log_file_fallback() is true only
        // when create() actually attempted a file open, so log_opts.log_file is
        // guaranteed set here.
        const std::string attempted_path =
            log_opts.log_file ? log_opts.log_file->string() : log_file;
        std::cerr << "Failed to open log file '" << attempted_path << "': "
                  << log_handoff->log_file_fallback_reason()
                  << " — logging to console only\n";
        spdlog::warn("Failed to open log file '{}': {} — logging to console only", attempted_path,
                     log_handoff->log_file_fallback_reason());
    }

    spdlog::info("Yuzu Agent v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);
    // SLE (ADR-0024 D11): echo the effective user_ref mode ONCE at startup — the
    // per-agent HMAC key (k_agent) is NEVER logged (roadmap R16), only the mode.
    spdlog::info("software_licensing user_ref mode: {}", cfg.license_scan_user_ref);

#ifdef _WIN32
    // #1822: hand off to the SCM ServiceMain dispatcher instead of running the
    // console path below. run_service() blocks for the lifetime of the service.
    if (service_mode) {
        return yuzu::agent::win::run_service(
            [cfg = std::move(cfg)]() mutable { return make_agent(std::move(cfg)); });
    }
#endif

    auto agent = make_agent(std::move(cfg));
    if (!agent)
        return EXIT_FAILURE;

    // Signal handling — installed only once `agent` exists (right after
    // make_agent() returns, right before g_agent is published), so on_signal
    // (which no-ops when g_agent is null) never silently swallows a Ctrl-C/
    // SIGTERM that arrives during make_agent()'s work (a SQLite open/write in
    // resolve_agent_id() plus a trivial in-memory Agent construction -- the
    // actual heavy work, plugin load and KV/TAR store open, happens later
    // inside agent->run() below, which was already covered by this
    // registration point before make_agent() existed). Installing the
    // handlers any earlier -- e.g. before calling make_agent() -- would
    // widen that pre-existing signal gap to cover make_agent()'s work too
    // (Gate 3 cpp-expert finding, governance re-run).
#ifndef _WIN32
    // The handler only write()s a byte; THIS thread performs the teardown, so stop()'s
    // joins can never be a self-join and no mutex/malloc/spdlog ever runs in a signal
    // context. See the on_signal comment block for the five traps this avoids.
    //
    // Constructed BEFORE the handlers are installed, so `g_shutdown_wfd` is always live by
    // the time a handler can fire. The other way round leaves a window in which a SIGTERM
    // finds wfd == -1 and is SILENTLY SWALLOWED. (The watcher tolerates a signal arriving
    // before g_agent is published: it keeps waiting rather than being consumed.)
    //
    // RAII, and DECLARATION ORDER IS LOAD-BEARING: `agent` is declared ABOVE, so
    // reverse-order destruction destroys the watcher FIRST — joining its thread — before
    // the Agent it calls stop() on dies. Declare it above `agent` and the watcher could
    // call stop() on a destroyed Agent. RAII rather than a bare thread because
    // `agent->run()` below is NOT wrapped in a try at its call site: a throw would unwind
    // past a joinable std::thread and std::terminate. Do not reorder.
    // CONSTRUCTED INSIDE A TRY, in an optional, because its own construction can throw on exactly
    // the host it exists to survive. `state_`'s make_shared sits in the mem-init-list — OUTSIDE the
    // ctor body's firewall — and `main()` has no enclosing handler, so a bad_alloc/EAGAIN there
    // escaped main and std::terminate'd WITHOUT UNWINDING: no plugin shutdown(), no SQLite close.
    // That is the identical hole this branch wraps make_unique<ThreadPool> to close, in the same
    // file, for the same reason. If it throws, the !ok() branch below installs the hard-exit
    // handler — NOT SIG_DFL, which pid 1 would discard.
    // (governance: cpp-expert, this PR.)
    std::optional<yuzu::ShutdownWatcher> shutdown_watcher;
    try {
        shutdown_watcher.emplace(
        g_shutdown_wfd,
        [] {
            auto* a = g_agent.load(std::memory_order_acquire);
            if (!a)
                return false; // not published yet — keep waiting, do not consume the watcher
            log_info_quietly("Received signal, shutting down...");
            a->stop();        // ordinary thread: safe to lock, join, malloc, log
            return true;
        },
        [] {
            // TRAP 6 — the watcher died on a read() error. If we leave the handlers installed,
            // on_signal keeps writing bytes into a pipe with NO READER and every SIGTERM is
            // SWALLOWED: the agent becomes unkillable by anything but SIGKILL.
            //
            // AND SIG_DFL IS NOT THE ANSWER, for the same reason it is not the answer at the
            // construction-failure site: the agent is PID 1 in every shipped container image, and
            // the kernel DISCARDS a default-disposition signal for pid 1. Handing the signals
            // "back to the kernel" there means SIGTERM is IGNORED — the exact unkillable state
            // this callback exists to escape. Install the hard-exit handler instead: ungraceful,
            // but genuinely killable, on every platform and as pid 1.
            // (governance: security-guardian — the sibling site I fixed at one place and not here.)
            std::signal(SIGINT, on_signal_hard_exit);
            std::signal(SIGTERM, on_signal_hard_exit);
        });
    } catch (...) {
        // Firewalled: an unguarded spdlog call here would terminate WITHOUT unwinding on exactly
        // the OOM/exhausted host this try exists for. And the handlers are NOT left at SIG_DFL —
        // the `!ok()` branch below installs the hard-exit handler, because pid 1 discards SIG_DFL.
        log_quietly("could not construct the shutdown watcher (out of memory or threads) — SIGINT/"
                    "SIGTERM will exit the process immediately and UNGRACEFULLY (no plugin "
                    "shutdown, no clean DB close). That is the killable posture; a default "
                    "disposition would be IGNORED by pid 1 in a container.");
    }
#endif

    g_agent.store(agent.get(), std::memory_order_release);

    // UNPUBLISH ON EVERY PATH, INCLUDING AN UNWIND — and BEFORE the watcher is destroyed.
    //
    // ~ShutdownWatcher's detach path is justified in its own header by "g_agent is already null by
    // then". That was FALSE on the exception path: the explicit g_agent.store(nullptr) below sits
    // AFTER agent->run(), so a throw out of run() skips it, and a detached watcher's callback could
    // then load a LIVE g_agent and call stop() on an Agent that is being destroyed.
    // This guard is declared AFTER `agent` AND AFTER the watcher, so reverse-order destruction
    // runs it BEFORE ~ShutdownWatcher on every path — which makes the header's stated reason
    // actually true, structurally, instead of by argument. (Declared BEFORE the watcher it
    // would be destroyed AFTER it — the detach path could then observe a live g_agent, the
    // exact S1 UAF.) (governance: cpp-safety S1; order corrected in the gate-round fold.)
    struct AgentUnpublisher {
        ~AgentUnpublisher() { g_agent.store(nullptr, std::memory_order_release); }
    } agent_unpublisher;


#ifndef _WIN32
    // ONLY install the handlers if the watcher is live. If it is not (pipe or thread
    // creation failed), on_signal would catch the signal, find no pipe, and RETURN —
    // swallowing it, with no default disposition left. SIGTERM and Ctrl-C would stop
    // working entirely and `systemctl stop` would hang to TimeoutStopSec before SIGKILL:
    // a fail-open-to-hang regression, on exactly the exhausted host this path exists for.
    // The fallback is the hard-exit handler below (NOT SIG_DFL — pid 1 discards it).
    // (governance Gate-8 cpp-safety.)
    if (shutdown_watcher && shutdown_watcher->ok()) {
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        // RE-CHECK after the install (TOCTOU): a watcher dying between the ok() test above
        // and these installs runs died() FIRST — it retracts the wfd slot and installs the
        // hard-exit handler — and the two std::signal calls above then OVERWRITE it with
        // on_signal, which finds wfd < 0 and returns: signal swallowed, agent unkillable —
        // the exact trap-6 state this branch closes. Re-checking AFTER the install makes
        // every interleaving converge: a died() that runs after this re-check installs
        // last and wins; one that ran before is caught here.
        // (governance gate round: cpp-expert SHOULD-1, this branch.)
        if (!shutdown_watcher->ok()) {
            std::signal(SIGINT, on_signal_hard_exit);
            std::signal(SIGTERM, on_signal_hard_exit);
        }
    } else {
        // SIG_DFL IS NOT A SAFE FALLBACK IN A CONTAINER, AND THE AGENT IS PID 1 THERE.
        //
        // The kernel DISCARDS a default-action signal for PID 1 — a signal with no installed
        // handler is ignored, not fatal. So "leave SIG_DFL, the process still dies promptly" is
        // simply FALSE in every shipped agent image (exec-form ENTRYPOINT, no init): SIGTERM would
        // be swallowed and `docker stop` would hang the full grace before SIGKILL. That is WORSE
        // than the behaviour this branch replaced, which installed a handler unconditionally.
        //
        // Install a handler that does nothing but LEAVE. It needs no pipe and no watcher, and
        // _exit()/TerminateProcess are async-signal-safe, so it is >= SIG_DFL everywhere and
        // strictly better on PID 1. Ungraceful — but killable, which is the whole point.
        // (governance: unhappy-path A, this PR.)
        std::signal(SIGINT, on_signal_hard_exit);
        std::signal(SIGTERM, on_signal_hard_exit);
        spdlog::warn("shutdown watcher unavailable — SIGINT/SIGTERM will now exit the process "
                     "IMMEDIATELY and UNGRACEFULLY (no plugin shutdown, no clean DB close). A "
                     "default disposition would be IGNORED by PID 1 in a container, so this is "
                     "the killable posture.");
    }
#else
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
#endif

    // F3 fail-closed backstop (Sol rung-7.6 review round 3, finding 2 - and
    // round 4, which caught that this MUST be armed BEFORE agent->run() below,
    // not after: run() itself is not noexcept and has a substantial throwing
    // surface, so a guard constructed only after it returns would miss an
    // exception thrown FROM run() itself). Everything from here through the
    // explicit orphan check further down (run() itself, g_agent_mu acquisition
    // on Windows, report_status-equivalent logging) could in principle throw
    // and unwind past that check entirely, which would let normal C++ teardown
    // run while a Guardian I/O worker might still be active - exactly what F3
    // exists to prevent. Constructed AFTER `agent`, so reverse-declaration-
    // order destruction runs this guard BEFORE the Agent's own destructor on
    // every exit path, including an unwind - the same pattern
    // `shutdown_watcher`/`agent_unpublisher` below already rely on. Disarmed
    // once the explicit check has run to completion on the normal path (see
    // below); its destructor is a deliberately non-throwing, unlogged fallback
    // for every other path.
    yuzu::agent::OrphanExitGuard orphan_guard{
        [&] { return agent->guardian_active_io_workers(); }, yuzu::agent::kOrphanDrainGrace, 3};

    agent->run();
    // R-EXCEPTION (#4666 PR-2, accepted, out of scope): on this platform's toolchain
    // (GCC) an exception escaping run() above can reach std::terminate() without
    // unwinding -- main() has no top-level try/catch, so neither log_epilogue's
    // destructor nor ~Agent would run in that case. Pre-existing property of this
    // function, not introduced or fixed here.

    // ── THE HANDLERS MUST NOT OUTLIVE WHAT SERVES THEM ──────────────────────────────
    // From here on nothing can act on a signal: the watcher is about to be joined and
    // `g_shutdown_wfd` cleared, so on_signal would find wfd == -1 and simply RETURN —
    // SWALLOWING the signal, with no default disposition left. That window is not small: it
    // spans the whole of ~Agent, which still joins the Guardian/DEX worker threads and closes
    // the SQLite stores. An operator's `systemctl stop` landing there would do NOTHING, and
    // systemd would wait out TimeoutStopSec before SIGKILL — the exact fail-open-to-hang this
    // self-pipe exists to remove, reintroduced at the tail. (Gate-8 round 7, unhappy-path UP-2.)
    //
    // Run()'s ScopeExit has already done the operator-visible teardown (plugin shutdown(),
    // trigger engine, thread-pool drain) — the graceful path is spent, and SQLite's WAL is
    // crash-safe, so dying promptly here beats hanging silently.
    // NOT SIG_DFL — pid 1 discards it (see on_signal_hard_exit). This window is not small: it
    // spans the whole of ~Agent (the Guardian/DEX joins, the SQLite closes). A signal arriving here
    // means "you are taking too long", and on pid 1 a default disposition would simply be ignored,
    // so `docker stop` would hang the full grace. Leave a handler that guarantees we LEAVE.
    // (governance: security-guardian — the second sibling site.)
    std::signal(SIGINT, on_signal_hard_exit);
    std::signal(SIGTERM, on_signal_hard_exit);
    // Unpublish BEFORE ~Agent, and only once the handlers are already the hard-exit handler
    // (which never touches g_agent — so there is no instant where a g_agent-dereferencing
    // handler is installed while g_agent is null).
    //
    // ON WINDOWS THE STORE ALONE IS NOT ENOUGH, and an earlier version of this comment
    // wrongly claimed it was ("closes the Windows g_agent use-after-free"). Nulling an atomic
    // pointer closes only the load-null race. The console handler derefs g_agent and calls
    // `a->stop()` INLINE on a CRT-spawned thread; stop() drains guardian_/dex_observer_ with
    // an unbounded wait, so it can still be running here — and a bare store does not wait for
    // it. main would then return and destroy the Agent while stop() is reading its members.
    // Taking g_agent_mu (which on_signal holds ACROSS stop()) makes this BLOCK until any
    // in-flight stop() has returned. That is the barrier POSIX already gets from
    // ~ShutdownWatcher's join(), and the one service_win.cpp has had since #1822. #2233 item 3
    // ("S+") now bounds that in-flight stop() from the OUTSIDE too (a ShutdownDeadlineGuard
    // hard_exit()s the whole process if it doesn't return within the grace period) - this
    // g_agent_mu barrier is still required for the ORDINARY case where stop() returns in time.
    // (governance Gate-8 round 8 unhappy-path UP8-1.)
#ifdef _WIN32
    {
        std::lock_guard<std::mutex> lock(g_agent_mu);
        g_agent.store(nullptr, std::memory_order_release);
    }
#else
    g_agent.store(nullptr, std::memory_order_release);
    // F3's orphan check below needs guardian_->stop() to have DEFINITELY
    // completed before sampling guardian_active_io_workers() - a count of
    // zero is meaningless otherwise: it could mean "fully quiesced" just as
    // easily as "the watcher thread's a->stop() call has not even started
    // yet". ~ShutdownWatcher's destructor JOINS the watcher thread (whose
    // callback IS a->stop()) - waiting for main()'s natural scope exit to get
    // that join is too late, since the orphan check below runs first in
    // program order. Reset it explicitly here instead. g_agent is already
    // null (above), so this is safe even on the rare detach fallback path
    // (Sol rung-7.6 review finding 1). On Windows, g_agent_mu already
    // provides this ordering: the console handler holds it across a->stop(),
    // and the store above blocks until any in-flight call has returned.
    shutdown_watcher.reset();
#endif

    // F3 orphan-exit obligation (ADR-0021 rung 7.6; guardian_io_executor.hpp's
    // "ORPHAN PROCESS-EXIT CONTRACT"). guardian_->stop() above has already run as
    // part of Agent's own teardown, but a Guardian bounded-I/O read is spawned
    // DETACHED and cannot be joined or force-cancelled - a wedged SCM query, a
    // stalled sd-bus broker, or a hung FUSE/network mount can leave one still
    // running past its own per-class deadline (which only makes the SUBMITTER
    // stop waiting; the worker keeps running). Falling through to normal process
    // exit here would run C++ static/DSO teardown while that worker may still be
    // executing libsystemd/OpenSSL/Win32-RPC code through it - not safe. Give it
    // a short grace to actually finish, and if it hasn't, hard_exit() (skip
    // teardown entirely) with a code that is NEVER EXIT_SUCCESS, so the
    // supervisor sees a real failure instead of a silently-clean-looking exit.
    if (const auto n = agent->guardian_active_io_workers(); n > 0) {
        if (!yuzu::agent::wait_for_workers_to_drain(
                [&] { return agent->guardian_active_io_workers(); },
                yuzu::agent::kOrphanDrainGrace)) {
            // Firewalled: a logging exception here must never skip hard_exit()
            // below - same rationale as log_quietly() elsewhere in this file
            // (Sol rung-7.6 review finding 2). The #4666 PR-2 drain_log_bounded()
            // call below shares this SAME try/catch, not a separate one -
            // drain_log_bounded() is not declared noexcept (log_handoff.hpp), so
            // leaving it outside this firewall would let an exception there skip
            // hard_exit() entirely (caught in review; service_win.cpp's equivalent
            // F3 site hit and fixed the identical hazard independently).
            try {
                // "Guardian I/O worker(s)" until PR-A (#2012/#3840): n is now a
                // SUM (guardian_active_io_workers()'s own doc comment) of
                // Guardian's own IO executors AND Spark mechanisms' detached
                // probes - naming only the first source here would misattribute
                // an incident's real cause once a live Spark consumer lands
                // (Gate 6 sre finding, PR-A round 5; today n's Spark addend is
                // provably always 0, so this was latent, not yet observable).
                spdlog::critical("{} orphaned Guardian I/O / Spark worker(s) still active {}s "
                                 "after shutdown - forcing process exit rather than race "
                                 "static/DSO teardown against them",
                                 n, yuzu::agent::kOrphanDrainGrace.count());
                // Best-effort bounded attempt to land the critical() line above
                // before hard_exit() below throws the rest of the log queue away —
                // not a delivery guarantee (#4666 PR-2).
                yuzu::agent::drain_log_bounded(std::chrono::milliseconds{200});
            } catch (...) {
            }
            yuzu::agent::hard_exit(3); // distinct from EXIT_FAILURE(1) / signal-hard-exit(1)
        }
    }
    orphan_guard.disarm(); // the explicit check above has run to completion

    // #1303: a fatal STARTUP failure (e.g. the fail-closed TLS posture refused to
    // connect with no pinnable CA) must surface as a non-zero exit so systemd
    // Restart= / Docker / Windows SCM react, instead of a silent EXIT_SUCCESS.
    if (agent->startup_failed())
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
