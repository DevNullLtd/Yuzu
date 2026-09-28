/**
 * guard_service.cpp — see guard_service.hpp.
 *
 * Windows: a single watch thread opens the SCM + service handle and registers
 * NotifyServiceStatusChangeW (one-shot, re-armed after each delivery). The
 * notification is delivered as an APC on this thread while it sits in an ALERTABLE
 * wait on the stop event — WaitForSingleObjectEx(stop, …, TRUE) returns
 * WAIT_OBJECT_0 on stop() and WAIT_IO_COMPLETION once the callback has run. The
 * callback only records the latest status into the (same-thread) WatchCtx; the
 * loop classifies and acts on it. reconcile() re-resolves from scratch — reopen
 * the SCM + service handles and re-register — so it survives the two conditions
 * that invalidate a registration: ERROR_SERVICE_NOTIFY_CLIENT_LAGGING (the client
 * fell behind) and ERROR_SERVICE_MARKED_FOR_DELETE (the service was deleted).
 *
 * Pending states (START/STOP/CONTINUE/PAUSE_PENDING) are TRANSITIONAL: held, never
 * compared or enforced. Without this, issuing StartService would immediately see
 * the START_PENDING notification and re-issue the control call for the whole
 * startup window (redundant control calls + spurious drift flaps). Compare +
 * remediate only on a TERMINAL state (Running / Stopped / Paused) or absence.
 *
 * The immediate on-registration callback IS the initial compare (register-first,
 * no query-then-arm gap — same principle as RegistryGuard arming before it reads).
 * While the service is absent we cannot arm a service-level notify, so reconcile()
 * schedules a bounded degraded re-arm (poll only while broken; fully event-driven
 * while healthy) — real-time re-creation via an SCM SERVICE_NOTIFY_CREATED watch
 * is deferred.
 *
 * Enforce uses advapi32 service-control (StartServiceW / ControlService), never
 * sc.exe / net start, gated by the per-rule resilience strategy. On non-Windows
 * the class is a no-op (start() returns false) so the engine and tests build
 * everywhere; enforcement is Windows-only for the MVP.
 */

#include <yuzu/agent/guard_service.hpp>

#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <optional>
#include <string_view>

// ── Pure state / compliance / edge logic ─────────────────────────────────────
// Defined OUTSIDE the platform #ifdef so the agent test binary links and exercises
// them on every platform (the Windows SCM watch itself is integration-tested). These
// carry the compliant-edge decision that, before the fix, was an inline short-circuit
// that never reported a compliant service.
namespace yuzu::agent {

std::string_view service_state_token(ServiceState s) {
    switch (s) {
    case ServiceState::Running: return "running";
    case ServiceState::Stopped: return "stopped";
    case ServiceState::Paused:  return "paused";
    case ServiceState::Absent:  return "absent";
    }
    return "unknown";
}

bool service_is_compliant(ServiceGuard::Desired want, ServiceState got) {
    if (want == ServiceGuard::Desired::Running)
        return got == ServiceState::Running;
    return got == ServiceState::Stopped || got == ServiceState::Absent;
}

ServiceEmit service_classify_edge(ServiceGuard::Desired want, ServiceState got,
                                  std::optional<bool>& last_compliant) {
    if (service_is_compliant(want, got)) {
        // guard.compliant fires ONCE on the edge into compliant (incl. the first
        // compare, last_compliant == nullopt); steady compliant stays silent.
        const bool edge = (last_compliant != true);
        last_compliant = true;
        return edge ? ServiceEmit::CompliantEdge : ServiceEmit::CompliantSteady;
    }
    last_compliant = false;
    return ServiceEmit::Drift;
}

} // namespace yuzu::agent

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Self-sufficient link (#1287): this TU calls advapi32 directly (OpenSCManagerW,
// NotifyServiceStatusChangeW, StartServiceW, ControlService). Don't rely on a
// sibling TU's pragma to carry advapi32 across the whole yuzu_agent_core link
// line — mirrors updater.cpp / process_enum.cpp / temp_file.cpp.
#pragma comment(lib, "advapi32.lib")

#include <algorithm>
#include <cctype>
#include <string>
#include <utility> // std::pair (remediate() return)

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)

namespace yuzu::agent {
namespace {

// Service names reach OpenServiceW directly (a Win32 API, not a shell), so this is
// hygiene/defence-in-depth rather than an injection gate — but it keeps the agent
// honest if a malformed name slips past the server-side authoring validator. Same
// charset as TriggerEngine::is_valid_service_name (the trigger engine's Linux/macOS
// paths DO shell out, so the rule is shared by convention).
bool valid_service_name(const std::string& name) {
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-' &&
            c != '@')
            return false;
    }
    return true;
}

// to_wide now delegates to the shared agents/shared/win_str.hpp helper (#1681);
// the removed local copy popped the trailing NUL the -1 convert appends, exactly
// matching yuzu::win::to_wide's size-based (NUL-excluded) result.
using yuzu::win::to_wide;

// RAII owner for an SC_HANDLE (OpenSCManager / OpenService). Closes via
// CloseServiceHandle — NOT CloseHandle, so guard_win_handle.hpp's ScopedWinHandle
// is the wrong owner here. Leak/double-close proof across the reopen churn of the
// reconcile loop (Gate-3 ownership).
class ScHandle {
public:
    ScHandle() = default;
    ~ScHandle() { reset(); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    void reset(SC_HANDLE h = nullptr) {
        if (h_ && h_ != h)
            CloseServiceHandle(h_);
        h_ = h;
    }
    SC_HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    SC_HANDLE h_ = nullptr;
};

// All run-state transitions. Pending states are included so the immediate callback
// always reports the current state regardless of how the OS interprets the mask at
// registration time; the loop HOLDS on pending and only acts on a terminal state.
// NOT SERVICE_NOTIFY_DELETED / _CREATED / _DELETE_PENDING: those are SCM-handle-only
// flags — combining any of them with a SERVICE handle makes NotifyServiceStatusChange
// fail with ERROR_INVALID_PARAMETER (87), silently dropping the watch to the degraded
// poll (caught in Windows UAT, not by the fail-closed unit test). Deletion is still
// handled: a deleted service transitions to STOPPED (a run-state notify) and/or the
// next delivery carries dwNotificationStatus == ERROR_SERVICE_MARKED_FOR_DELETE, both
// of which drive reconcile() → the absent path.
constexpr DWORD kNotifyMask = SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED |
                              SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
                              SERVICE_NOTIFY_CONTINUE_PENDING | SERVICE_NOTIFY_PAUSE_PENDING |
                              SERVICE_NOTIFY_PAUSED;

// Compile-time guard against the rc=87 regression: the SCM-handle-only flags
// (CREATED / DELETED / DELETE_PENDING) must NEVER appear in a mask registered on a
// SERVICE handle — NotifyServiceStatusChange rejects the combination with
// ERROR_INVALID_PARAMETER (87), silently dropping the real-time watch to the degraded
// poll (the bug was found only in Windows UAT, not by the fail-closed unit test).
static_assert((kNotifyMask & (SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED |
                              SERVICE_NOTIFY_DELETE_PENDING)) == 0,
              "kNotifyMask must not contain SCM-handle-only notify flags (CREATED/DELETED/"
              "DELETE_PENDING) — they fail with ERROR_INVALID_PARAMETER on a service handle");

// Degraded re-arm cadence used ONLY while the watched service is absent (cannot arm
// a service-level notify) or a notify could not be armed. The healthy watch stays
// fully event-driven (no poll). Mirrors RegistryGuard's kArmFailRetryMs.
constexpr std::uint64_t kAbsentRetryMs = 30000;

bool is_pending(DWORD s) {
    return s == SERVICE_START_PENDING || s == SERVICE_STOP_PENDING ||
           s == SERVICE_CONTINUE_PENDING || s == SERVICE_PAUSE_PENDING;
}

// The detected terminal class is the public ServiceState (lifted to
// guard_service.hpp so the pure compliance + compliant-edge logic — service_token /
// service_is_compliant / service_classify_edge — is unit-tested off-Windows).
// Aliased so the Windows watch loop keeps its terse `Det::Running` spelling.
using Det = ServiceState;

Det det_from_state(DWORD s) {
    switch (s) {
    case SERVICE_RUNNING: return Det::Running;
    case SERVICE_PAUSED:  return Det::Paused;
    default:              return Det::Stopped; // SERVICE_STOPPED (pending handled before here)
    }
}

// Same-thread state the APC callback fills and the loop drains. No synchronisation
// needed: the callback runs as an APC on the watch thread DURING its alertable
// wait, never concurrently with the loop body. PRECONDITION: the drift sink must
// not itself enter an alertable wait — if it did, a queued APC could re-enter and
// mutate ctx mid-processing. The gRPC sink does not alertable-wait, so this holds.
struct WatchCtx {
    DWORD notify_status = ERROR_SUCCESS; ///< SERVICE_NOTIFY.dwNotificationStatus
    DWORD current_state = SERVICE_STOPPED;
    bool fired = false;
};

void CALLBACK notify_cb(PVOID param) {
    auto* n = static_cast<SERVICE_NOTIFYW*>(param);
    auto* ctx = static_cast<WatchCtx*>(n->pContext);
    ctx->notify_status = n->dwNotificationStatus;
    ctx->current_state = n->ServiceStatus.dwCurrentState;
    ctx->fired = true;
}

} // namespace

ServiceGuard::ServiceGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

ServiceGuard::~ServiceGuard() { stop(); }

bool ServiceGuard::start() {
    if (!valid_service_name(cfg_.service_name)) {
        spdlog::warn("Guardian ServiceGuard[{}]: invalid service name '{}'",
                     yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(cfg_.service_name));
        return false;
    }
    HANDLE evt = CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr);
    if (!evt)
        return false;
    stop_event_ = evt;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void ServiceGuard::stop() {
    if (thread_.joinable()) {
        stop_.store(true, std::memory_order_release);
        if (stop_event_)
            SetEvent(static_cast<HANDLE>(stop_event_));
        thread_.join();
    }
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
}

void ServiceGuard::run() try {
    const std::wstring wname = to_wide(cfg_.service_name);
    const char* expected_token = (cfg_.desired == Desired::Running) ? "running" : "stopped";

    ScHandle scm;
    ScHandle svc;
    SERVICE_NOTIFYW notify{}; // MUST outlive each registration until its callback runs
    WatchCtx ctx;

    // On a SERVICE_NOTIFY_DELETED (or CREATED) delivery the SCM allocates
    // notify.pszServiceNames and the caller MUST LocalFree it — otherwise the watch
    // leaks that buffer every time the service is deleted. Run-state deliveries leave
    // it null. Idempotent; called after draining each callback and before any reset.
    auto free_names = [&] {
        if (notify.pszServiceNames) {
            LocalFree(notify.pszServiceNames);
            notify.pszServiceNames = nullptr;
        }
    };

    // Sink-debounce state (H3 / #1209). Only this run() thread touches these.
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;

    // Compliance-edge state (Slice B), mirroring RegistryGuard: nullopt until the
    // first compare, then tracks the last-reported compliant/drifted state so a
    // guard.compliant event fires ONCE on the compliant↔drift edge — a steady
    // compliant service stays silent. Only this run() thread touches it.
    std::optional<bool> last_compliant;

    // C3: per-rule retry policy. Consulted ONLY in enforce mode and ONLY to gate the
    // control call — detection + emission happen regardless. next_wake_ms carries a
    // strategy-scheduled self-wake (Backoff retry / Bounded resume) OR the degraded
    // absent re-arm to the wait loop; reset at the top of each reconcile().
    ResilienceStrategy strategy{cfg_.resilience};
    std::optional<std::uint64_t> next_wake_ms;
    auto now_ms = [] {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    };

    // Drive the service back to `desired` from the detected state. Returns
    // (success, action-name). Treats "already in the desired state" race results
    // (1056 ALREADY_RUNNING / 1062 NOT_ACTIVE) as success. Never sc.exe / net.
    auto remediate = [&](Det got) -> std::pair<bool, const char*> {
        SERVICE_STATUS ss{};
        if (cfg_.desired == Desired::Running) {
            if (got == Det::Stopped) {
                bool ok = StartServiceW(svc.get(), 0, nullptr) ||
                          GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
                return {ok, "service-start"};
            }
            if (got == Det::Paused)
                return {ControlService(svc.get(), SERVICE_CONTROL_CONTINUE, &ss) != 0,
                        "service-continue"};
            return {false, "service-start"}; // Absent: cannot start a non-existent service
        }
        // Desired::Stopped — got is Running or Paused (Stopped/Absent are compliant)
        bool ok = ControlService(svc.get(), SERVICE_CONTROL_STOP, &ss) != 0 ||
                  GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
        return {ok, "service-stop"};
    };

    // Classify the terminal observation via the pure, unit-tested service_classify_edge
    // (mirrors RegistryGuard's last_compliant edge logic): a compliant EDGE emits
    // guard.compliant ONCE and bypasses the drift debounce (a compliant edge ends a
    // drift, it is not another drift to fold); steady compliant is silent (NFR); a
    // drift is reported through the resilience-gated enforce + collapse-with-count
    // debounce below. Without the compliant edge a compliant service never produced a
    // census signal and read as "pending" forever in the per-(agent,rule) status table.
    auto emit = [&](Det got, std::uint64_t latency_us) {
        const ServiceEmit decision = service_classify_edge(cfg_.desired, got, last_compliant);
        if (decision == ServiceEmit::CompliantSteady)
            return; // already compliant — silent
        if (decision == ServiceEmit::CompliantEdge) {
            ServiceDrift c;
            c.guard_type = "service";
            c.rule_id = cfg_.rule_id;
            c.rule_name = cfg_.rule_name;
            c.detected_value = std::string(service_state_token(got));
            c.expected_value = expected_token;
            c.detection_latency_us = latency_us;
            c.compliant = true;
            if (sink_)
                sink_(c);
            return;
        }
        // decision == ServiceEmit::Drift — service_classify_edge set last_compliant=false.
        ServiceDrift d;
        d.guard_type = "service";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = std::string(service_state_token(got));
        d.expected_value = expected_token;
        // #1286: every caller passes latency_us=0 by design. Unlike RegistryGuard
        // (which times a steady_clock read), a service run-state change is delivered
        // by the SCM via NotifyServiceStatusChangeW in an APC — kernel-push, with no
        // agent-side read step to measure. 0 is honest here, not an unfilled field.
        d.detection_latency_us = latency_us;
        if (cfg_.enforce) {
            const ResilienceDecision dec = strategy.decide(now_ms());
            next_wake_ms = dec.next_wake_ms;
            if (dec.remediate) {
                d.remediation_attempted = true;
                const auto r0 = std::chrono::steady_clock::now();
                auto [ok, action] = remediate(got);
                d.remediation_action = action;
                d.remediation_success = ok;
                d.remediation_latency_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - r0)
                        .count());
                if (ok)
                    spdlog::info("Guardian ServiceGuard[{}]: {} '{}' {} -> {} ({}us)",
                                 yuzu::log_id_token(cfg_.rule_id), action,
                                 yuzu::log_key_token(cfg_.service_name), d.detected_value,
                                 expected_token, d.remediation_latency_us);
                else
                    spdlog::warn("Guardian ServiceGuard[{}]: enforce {} FAILED for '{}' "
                                 "(detected={}, err={})",
                                 yuzu::log_id_token(cfg_.rule_id), action,
                                 yuzu::log_key_token(cfg_.service_name), d.detected_value,
                                 GetLastError());
            } else {
                spdlog::info("Guardian ServiceGuard[{}]: drift '{}' detected={} -- {}, not "
                             "remediating",
                             yuzu::log_id_token(cfg_.rule_id),
                             yuzu::log_key_token(cfg_.service_name), d.detected_value,
                             dec.gave_up ? "given up (alert)" : "backing off");
            }
        }
        // A successful control call drove the service to `desired`: the resulting SCM
        // notify will re-reconcile and read compliant. drift.remediated already carries
        // that "now compliant" meaning, so pre-set the edge to avoid a redundant
        // guard.compliant chasing every remediation (mirrors RegistryGuard, Slice B).
        if (d.remediation_attempted && d.remediation_success)
            last_compliant = true;
        const auto now = std::chrono::steady_clock::now();
        if (last_emit && (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed;
            return;
        }
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        if (sink_)
            sink_(d);
    };

    // Open the SCM + service fresh with the access detection (and, in enforce mode,
    // control) need. A write-access open that fails falls back to query-only so we
    // still DETECT drift and report failed control calls rather than disarming.
    auto reopen = [&]() -> bool {
        svc.reset();
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) {
            spdlog::warn("Guardian ServiceGuard[{}]: OpenSCManager failed (err={})",
                         yuzu::log_id_token(cfg_.rule_id), GetLastError());
            return false;
        }
        DWORD access = SERVICE_QUERY_STATUS;
        if (cfg_.enforce)
            access |= (cfg_.desired == Desired::Running) ? (SERVICE_START | SERVICE_PAUSE_CONTINUE)
                                                         : SERVICE_STOP;
        SC_HANDLE h = OpenServiceW(scm.get(), wname.c_str(), access);
        if (!h && cfg_.enforce && GetLastError() == ERROR_ACCESS_DENIED) {
            spdlog::warn("Guardian ServiceGuard[{}]: control-access open of '{}' denied — "
                         "query-only watch; enforcement will report failures",
                         yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(cfg_.service_name));
            h = OpenServiceW(scm.get(), wname.c_str(), SERVICE_QUERY_STATUS);
        }
        if (!h)
            return false; // absent (ERROR_SERVICE_DOES_NOT_EXIST) or other
        svc.reset(h);
        return true;
    };

    // Single source of truth. Re-resolve from scratch and ARM the notify BEFORE we
    // depend on any reported state (the immediate on-registration callback is the
    // initial compare). Carries no incremental state across calls.
    auto reconcile = [&]() {
        next_wake_ms.reset();
        ctx.fired = false;
        if (!reopen()) {
            // Service absent (or SCM unavailable): report drift now and poll for its
            // return on a bounded cadence (no service handle to arm a notify on).
            emit(Det::Absent, 0);
            next_wake_ms = kAbsentRetryMs;
            return;
        }
        free_names();
        notify = SERVICE_NOTIFYW{};
        notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        notify.pfnNotifyCallback = &notify_cb;
        notify.pContext = &ctx;
        DWORD rc = NotifyServiceStatusChangeW(svc.get(), kNotifyMask, &notify);
        if (rc != ERROR_SUCCESS) {
            // Could not arm (e.g. CLIENT_LAGGING): drop handles and retry on a bounded
            // cadence rather than blocking forever.
            spdlog::warn("Guardian ServiceGuard[{}]: NotifyServiceStatusChange failed for '{}' "
                         "(rc={}) — degraded re-arm in {}ms",
                         yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(cfg_.service_name),
                         rc, kAbsentRetryMs);
            svc.reset();
            next_wake_ms = kAbsentRetryMs;
            return;
        }
        // Registered: the immediate callback (and every later transition) is delivered
        // as an APC at the next alertable wait. Stay fully event-driven (INFINITE).
    };

    spdlog::info("Guardian ServiceGuard[{}]: watching service '{}' (expect {}){}",
                 yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(cfg_.service_name),
                 expected_token, cfg_.enforce ? " [enforce]" : "");

    reconcile(); // initial arm; immediate callback delivers the initial compare

    HANDLE stop_h = static_cast<HANDLE>(stop_event_);
    while (!stop_.load(std::memory_order_acquire)) {
        const DWORD timeout =
            next_wake_ms ? static_cast<DWORD>(std::min<std::uint64_t>(*next_wake_ms, 0xFFFFFFFEull))
                         : INFINITE;
        DWORD r = WaitForSingleObjectEx(stop_h, timeout, /*alertable=*/TRUE);
        if (r == WAIT_OBJECT_0)
            break; // stop() signalled
        if (r == WAIT_TIMEOUT) {
            // Degraded absent re-arm OR a strategy-scheduled enforce retry: re-resolve.
            reconcile();
            continue;
        }
        if (r != WAIT_IO_COMPLETION)
            break; // WAIT_FAILED — unrecoverable
        if (!ctx.fired)
            continue; // spurious wake (some other APC)
        ctx.fired = false;
        free_names(); // release any SCM-allocated name buffer from this delivery
        if (ctx.notify_status != ERROR_SUCCESS) {
            // Deleted (ERROR_SERVICE_MARKED_FOR_DELETE) or otherwise invalidated — the
            // ServiceStatus is not trustworthy. Re-resolve from scratch (→ absent path).
            reconcile();
            continue;
        }
        if (is_pending(ctx.current_state)) {
            // Transitional: hold (no compare / no enforce), just re-arm the one-shot
            // so we see the terminal state when it lands.
            if (NotifyServiceStatusChangeW(svc.get(), kNotifyMask, &notify) != ERROR_SUCCESS)
                reconcile();
            continue;
        }
        // Terminal state: compare / emit / enforce, then ALWAYS re-arm the one-shot.
        // Unlike RegNotifyChangeKeyValue (which stays armed until it fires), the SCM
        // notify is CONSUMED on delivery — so even when the resilience strategy scheduled
        // a timed enforce retry (next_wake_ms set, Backoff/Bounded), we must re-register
        // now, or the watch goes event-blind for the whole backoff window (up to 60s) and
        // a real transition is missed until the timer wakes (UP-1). The scheduled
        // next_wake_ms still drives the timed enforce retry via WAIT_TIMEOUT in parallel;
        // a transition during the window is now detected in real time and re-evaluated.
        emit(det_from_state(ctx.current_state), 0);
        if (NotifyServiceStatusChangeW(svc.get(), kNotifyMask, &notify) != ERROR_SUCCESS)
            reconcile();
    }

    free_names(); // release any name buffer left from the final delivery before unwind

    // RAII: scm / svc close on scope exit, including an exception unwind. Any
    // outstanding notify registration is cancelled when its service handle closes.
} catch (const std::exception& e) {
    spdlog::error("Guardian ServiceGuard[{}]: watch thread exception: {} — watch stopping",
                  yuzu::log_id_token(cfg_.rule_id), e.what());
} catch (...) {
    spdlog::error("Guardian ServiceGuard[{}]: watch thread unknown exception — watch stopping",
                  yuzu::log_id_token(cfg_.rule_id));
}

} // namespace yuzu::agent

#else // ── Non-Windows: no-op (no SCM) ─────────────────────────────────────────

namespace yuzu::agent {

ServiceGuard::ServiceGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
ServiceGuard::~ServiceGuard() {}
bool ServiceGuard::start() { return false; }
void ServiceGuard::stop() {}
void ServiceGuard::run() {}

} // namespace yuzu::agent

#endif
