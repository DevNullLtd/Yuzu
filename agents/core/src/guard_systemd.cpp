/**
 * guard_systemd.cpp — see guard_systemd.hpp.
 *
 * Linux: a single watch thread opens the system D-Bus, Subscribes to the systemd
 * Manager, resolves the watched unit's object path (LoadUnit force-loads it so the
 * path is valid even when the unit is inactive), reads `ActiveState` (the initial
 * compare), and arms a PropertiesChanged match on the unit object. A poll loop over
 * { bus fd, stop eventfd } services the match: on each notification it re-reads
 * ActiveState and, on a TERMINAL state CHANGE, compares to the rule's desired state
 * and emits a GuardDrift. A bounded safety reconcile (and the absent re-poll) catch
 * a missed signal or the unit being removed / re-created — fully event-driven while
 * healthy, bounded-poll only while degraded (mirrors the Windows guard).
 *
 * v1 is OBSERVE ONLY: enforce-mode rules are detected + reported but NOT remediated
 * (no MaskUnit / StopUnit). Enforcement is a separate, governance-gated change.
 *
 * The pure state-mapping helpers (parse_active_state / systemd_is_compliant / …) are
 * compiled on EVERY platform so they are unit-testable off Linux against captured
 * ActiveState strings (mirrors dex_observer.hpp's extract_named_data). Only the
 * sd-bus engine is Linux-gated; off Linux the guard is a no-op (start() → false).
 */

#include <yuzu/agent/guard_systemd.hpp>

#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

// ── Pure state-mapping helpers (compiled on every platform) ──────────────────

SystemdState parse_active_state(std::string_view s) {
    if (s == "active")
        return SystemdState::Active;
    if (s == "reloading")
        return SystemdState::Reloading;
    if (s == "inactive")
        return SystemdState::Inactive;
    if (s == "failed")
        return SystemdState::Failed;
    if (s == "activating")
        return SystemdState::Activating;
    if (s == "deactivating")
        return SystemdState::Deactivating;
    if (s == "maintenance")
        return SystemdState::Maintenance;
    return SystemdState::Unknown;
}

bool systemd_error_name_is_absence(std::string_view name) {
    // Only the "does not exist" D-Bus error names mean the unit/object is genuinely
    // gone (→ Absent). Every other named error (AccessDenied, NoReply, TimedOut,
    // Disconnected, …) is transient and must NOT read as absence — otherwise a
    // permission or timeout blip fabricates a false "stopped" drift / false-compliant
    // (fjarvis review #2 / UP-4). An empty name is a bare transport failure → not
    // absence (the caller reopens).
    return name == "org.freedesktop.systemd1.NoSuchUnit" ||
           name == "org.freedesktop.DBus.Error.UnknownObject" ||
           name == "org.freedesktop.DBus.Error.ServiceUnknown" ||
           name == "org.freedesktop.DBus.Error.FileNotFound";
}

bool systemd_state_is_transitional(SystemdState s) {
    switch (s) {
    case SystemdState::Reloading:
    case SystemdState::Activating:
    case SystemdState::Deactivating:
    case SystemdState::Maintenance:
    case SystemdState::Unknown: // a state we do not understand is held, never drifted
        return true;
    case SystemdState::Active:
    case SystemdState::Inactive:
    case SystemdState::Failed:
    case SystemdState::Absent:
        return false;
    }
    return true;
}

bool systemd_is_compliant(ServiceGuard::Desired want, SystemdState got) {
    if (want == ServiceGuard::Desired::Running)
        return got == SystemdState::Active;
    // Desired::Stopped — anything not active counts as stopped; a failed or absent
    // unit is, definitionally, not running.
    return got == SystemdState::Inactive || got == SystemdState::Failed ||
           got == SystemdState::Absent;
}

std::string_view systemd_state_token(SystemdState s) {
    switch (s) {
    case SystemdState::Active:       return "running";
    case SystemdState::Inactive:     return "stopped";
    case SystemdState::Failed:       return "failed";
    case SystemdState::Absent:       return "absent";
    case SystemdState::Reloading:    return "reloading";
    case SystemdState::Activating:   return "activating";
    case SystemdState::Deactivating: return "deactivating";
    case SystemdState::Maintenance:  return "maintenance";
    case SystemdState::Unknown:      return "unknown";
    }
    return "unknown";
}

std::string normalize_unit_name(std::string_view unit) {
    std::string out(unit);
    if (out.find('.') == std::string::npos)
        out += ".service";
    return out;
}

bool valid_unit_name(std::string_view unit) {
    if (unit.empty() || unit.size() > 256)
        return false;
    for (char c : unit) {
        const auto uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '.' && c != '_' && c != '-' && c != '@')
            return false;
    }
    return true;
}

EmitDecision systemd_decide_emit(ServiceGuard::Desired want, SystemdState got, EmitState& state,
                                 std::uint64_t debounce_ms,
                                 std::chrono::steady_clock::time_point now) {
    if (systemd_state_is_transitional(got))
        return {EmitAction::Hold, 0}; // mid-transition / not understood — never commit
    if (got == state.last_terminal)
        return {EmitAction::NoChange, 0}; // already committed this terminal state
    if (systemd_is_compliant(want, got)) {
        // Compliant edge: commit so a LATER drift back to a previously-drifted state
        // reads as a real change (re-drift-after-recovery). Drift-only sink → silent.
        state.last_terminal = got;
        return {EmitAction::CompliantSilent, 0};
    }
    // Non-compliant terminal change → a drift, subject to the collapse debounce.
    if (state.last_emit &&
        (now - *state.last_emit) < std::chrono::milliseconds(debounce_ms)) {
        // Fold into the count but do NOT commit last_terminal — leaving it uncommitted
        // lets this drift re-surface at the next reconcile instead of being deduped
        // away if the unit settles back into this same state.
        ++state.suppressed;
        return {EmitAction::Suppressed, 0};
    }
    state.last_terminal = got; // commit on emit
    const std::uint64_t collapsed = state.suppressed;
    state.suppressed = 0;
    state.last_emit = now;
    return {EmitAction::Emit, collapsed};
}

std::unique_ptr<IGuard> make_service_guard(ServiceGuard::Config cfg, GuardSink sink) {
#if defined(__linux__)
    return std::make_unique<SystemdServiceGuard>(std::move(cfg), std::move(sink));
#else
    return std::make_unique<ServiceGuard>(std::move(cfg), std::move(sink));
#endif
}

} // namespace yuzu::agent

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

#include <systemd/sd-bus.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>     // free
#include <ctime>
#include <memory>      // unique_ptr (sd_bus_slot RAII)
#include <optional>
#include <string>
#include <system_error> // std::generic_category — thread-safe strerror replacement

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace yuzu::agent {
namespace {

constexpr const char* kDest      = "org.freedesktop.systemd1";
constexpr const char* kMgrPath   = "/org/freedesktop/systemd1";
constexpr const char* kMgrIface  = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnitIface = "org.freedesktop.systemd1.Unit";
constexpr const char* kPropsIface = "org.freedesktop.DBus.Properties";

// Degraded re-poll cadence while the unit is absent (no object to match a signal
// on) — mirrors the Windows guard's kAbsentRetryMs. The healthy watch is fully
// event-driven via PropertiesChanged; the longer backstop only guards against a
// missed signal or the unit object being destroyed/re-created.
constexpr std::uint64_t kAbsentRetryMs = 30000;
constexpr std::uint64_t kHealthyReconcileMs = 60000;

// Thread-safe strerror: std::strerror returns a pointer into a shared global buffer,
// which races across the N watch threads (one per rule). generic_category().message
// returns an owned std::string. `e` is a POSITIVE errno (negate sd-bus's -errno).
std::string err_str(int e) { return std::generic_category().message(e); }

// Outcome of resolving a unit's object path — distinguishes "the unit genuinely is
// not loadable" (a real Absent drift) from "the bus call failed at the transport
// layer" (reopen the connection, do NOT report a false Absent). Without this split a
// systemd daemon-reexec / dbus restart would emit a spurious "service stopped" drift
// fleet-wide (UP-4) on top of going deaf (sec-M1).
enum class ResolveResult { Resolved, NotFound, BusError };

std::uint64_t monotonic_us() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ull +
           static_cast<std::uint64_t>(ts.tv_nsec) / 1000ull;
}

// PropertiesChanged match callback. Runs synchronously inside sd_bus_process() on
// the watch thread (never concurrently), so it just flips a plain bool the loop
// drains — the loop re-reads ActiveState rather than parsing the changed-property
// set, which is both simpler and robust to PropertiesChanged batching.
int on_props_changed(sd_bus_message* /*m*/, void* userdata, sd_bus_error* /*ret*/) {
    if (userdata)
        *static_cast<bool*>(userdata) = true;
    return 0;
}

} // namespace

SystemdServiceGuard::SystemdServiceGuard(Config cfg, Sink sink)
    : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

SystemdServiceGuard::~SystemdServiceGuard() { stop(); }

bool SystemdServiceGuard::start() {
    if (!valid_unit_name(cfg_.service_name)) {
        spdlog::warn("Guardian SystemdServiceGuard[{}]: invalid unit name '{}'",
                     yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(cfg_.service_name));
        return false;
    }
    sd_bus* bus = nullptr;
    int r = sd_bus_open_system(&bus);
    if (r < 0 || !bus) {
        // No system bus → not a systemd host (or no access). v1 degrades to
        // unarmed (detect-only requires the /proc fallback, a later slice).
        spdlog::warn("Guardian SystemdServiceGuard[{}]: system bus unavailable ({}) — unit '{}' "
                     "unwatched (non-systemd host?)",
                     yuzu::log_id_token(cfg_.rule_id), (r < 0 ? err_str(-r) : std::string("no bus")),
                     yuzu::log_key_token(cfg_.service_name));
        if (bus)
            sd_bus_unref(bus);
        return false;
    }
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (efd < 0) {
        sd_bus_unref(bus);
        return false;
    }
    bus_ = bus;
    wake_fd_ = efd;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void SystemdServiceGuard::stop() {
    if (thread_.joinable()) {
        stop_.store(true, std::memory_order_release);
        if (wake_fd_ >= 0) {
            const std::uint64_t one = 1;
            ssize_t w = ::write(wake_fd_, &one, sizeof(one));
            (void)w; // wake is best-effort; the thread also re-checks stop_ each iteration
        }
        thread_.join();
    }
    if (bus_) {
        sd_bus_flush(static_cast<sd_bus*>(bus_));
        sd_bus_unref(static_cast<sd_bus*>(bus_));
        bus_ = nullptr;
    }
    if (wake_fd_ >= 0) {
        ::close(wake_fd_);
        wake_fd_ = -1;
    }
}

void SystemdServiceGuard::run() try {
    auto* bus = static_cast<sd_bus*>(bus_); // working pointer; reopen_bus() reseats it
    const std::string unit = normalize_unit_name(cfg_.service_name);
    const char* expected_token = (cfg_.desired == Desired::Running) ? "running" : "stopped";

    if (cfg_.enforce)
        spdlog::warn("Guardian SystemdServiceGuard[{}]: enforce-mode not yet supported on Linux — "
                     "observing unit '{}' only (drift reported, not remediated)",
                     yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit));

    int bus_fd = sd_bus_get_fd(bus);
    bool bus_ok = true; // false after a transport failure, until reopen_bus() succeeds

    std::string unit_path;     // resolved object path of the watched unit
    // `dirty` MUST out-live `match_slot` (the match callback holds &dirty as its
    // userdata). It is declared first so it destructs LAST — reordering these two
    // would leave the callback pointing at freed stack. Reinforced by: no
    // sd_bus_process runs during teardown, so the callback can't fire post-scope.
    bool dirty = false;        // set by on_props_changed; drained each loop iteration
    EmitState emit_state;      // change-dedup + collapse debounce (this thread only)

    // RAII for the PropertiesChanged match slot. The slot holds a ref on `bus`, so its
    // unref MUST happen before the bus it belongs to is unref'd — the unique_ptr's
    // scope-exit unref (and reset() in reopen_bus / reconcile) guarantees that on every
    // path, including an exception unwind (cppsafe-B: the old manual unref leaked on a
    // throwing sink, holding a bus ref → fd exhaustion over guard churn).
    std::unique_ptr<sd_bus_slot, decltype(&sd_bus_slot_unref)> match_slot{nullptr,
                                                                          &sd_bus_slot_unref};

    auto emit = [&](SystemdState got) {
        const EmitDecision d = systemd_decide_emit(cfg_.desired, got, emit_state,
                                                   cfg_.event_debounce_ms,
                                                   std::chrono::steady_clock::now());
        if (d.action != EmitAction::Emit)
            return;
        ServiceDrift drift;
        drift.guard_type = "service";
        drift.rule_id = cfg_.rule_id;
        drift.rule_name = cfg_.rule_name;
        drift.detected_value = std::string(systemd_state_token(got));
        drift.expected_value = expected_token;
        drift.detection_latency_us = 0; // v1: not measured (sd-bus gives no kernel event time)
        drift.collapsed_count = d.collapsed_count;
        spdlog::info("Guardian SystemdServiceGuard[{}]: drift unit '{}' detected={} expected={}",
                     yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit),
                     drift.detected_value, expected_token);
        if (sink_)
            sink_(drift);
    };

    // Subscribe so the Manager emits unit signals to us. systemd only sends change
    // signals (including a unit's PropertiesChanged) while at least one client has
    // Subscribed — so this is NOT optional for the event-driven path, despite being
    // non-fatal: if it fails we silently lose PropertiesChanged and fall back entirely
    // to the bounded reconcile, i.e. latency degrades from ~ms to kHealthyReconcileMs.
    // Hence warn (not debug) so a degraded watch is visible. Re-run after every reopen.
    auto subscribe = [&] {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        if (sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "Subscribe", &err, &reply, "") < 0)
            spdlog::warn("Guardian SystemdServiceGuard[{}]: Subscribe failed ({}) — losing the "
                         "PropertiesChanged event stream, falling back to bounded reconcile only",
                         yuzu::log_id_token(cfg_.rule_id), err.message ? err.message : "(none)");
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
    };

    // LoadUnit force-loads the unit and returns its object path (valid even when
    // inactive). A remote D-Bus error (NoSuchUnit / LoadFailed) means the unit is
    // genuinely Absent; a bare transport failure (no error name) means the bus is
    // gone — reopen rather than report a false Absent.
    auto resolve_path = [&]() -> ResolveResult {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        // Fail-safe default: if a future branch forgets to assign, reopen the bus
        // rather than fabricate a false Absent drift (cpp-safety Gate-8).
        ResolveResult res = ResolveResult::BusError;
        int r = sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "LoadUnit", &err, &reply, "s",
                                   unit.c_str());
        if (r >= 0 && reply) {
            const char* p = nullptr;
            if (sd_bus_message_read(reply, "o", &p) >= 0 && p && *p) {
                unit_path = p; // copied into our std::string before the reply is unref'd
                res = ResolveResult::Resolved;
            } else {
                res = ResolveResult::NotFound;
            }
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            spdlog::debug("Guardian SystemdServiceGuard[{}]: unit '{}' absent (name='{}')",
                          yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit),
                          err.name ? err.name : "(none)");
            res = ResolveResult::NotFound;
        } else {
            // A named-but-transient error (AccessDenied/NoReply/TimedOut/…) or a bare
            // transport failure — neither proves the unit is gone, so reopen rather than
            // fabricate a false Absent drift (fjarvis #2 / UP-4).
            spdlog::warn("Guardian SystemdServiceGuard[{}]: LoadUnit '{}' transient error "
                         "(name='{}', {}) — reopening, no false Absent",
                         yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit),
                         err.name ? err.name : "(none)",
                         err.message ? err.message : err_str(r < 0 ? -r : 0));
            res = ResolveResult::BusError;
        }
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
        return res;
    };

    // Read the unit's live ActiveState. Returns nullopt on a bare TRANSPORT failure
    // (bus gone) so the caller reopens instead of emitting — the read_state twin of
    // resolve_path's BusError split. Without it a dbus-restart / daemon-reexec read
    // fails, falls through to Absent, and fabricates a false "stopped" drift (the same
    // UP-4 fleet-wide-spurious-drift hazard the resolve_path fix closed, in a sibling
    // function). A remote D-Bus error (the unit's object was removed) IS a genuine
    // Absent terminal state; only a no-error-name transport failure yields nullopt.
    auto read_state = [&]() -> std::optional<SystemdState> {
        if (unit_path.empty())
            return SystemdState::Absent;
        sd_bus_error err = SD_BUS_ERROR_NULL;
        char* s = nullptr;
        std::optional<SystemdState> st;
        int r = sd_bus_get_property_string(bus, kDest, unit_path.c_str(), kUnitIface, "ActiveState",
                                           &err, &s);
        if (r >= 0 && s) {
            st = parse_active_state(s);
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            st = SystemdState::Absent; // unit object genuinely removed/unknown — absent
        } else {
            // Named-but-transient (AccessDenied/NoReply/TimedOut/…) or a bare transport
            // failure — reopen, never a false "stopped" (fjarvis #2 / UP-4).
            spdlog::warn("Guardian SystemdServiceGuard[{}]: ActiveState read transient error "
                         "(name='{}', {}) — reopening, no false drift",
                         yuzu::log_id_token(cfg_.rule_id), err.name ? err.name : "(none)",
                         err_str(r < 0 ? -r : 0));
            // leave nullopt → caller flips bus_ok and reopens
        }
        if (s)
            free(s);
        sd_bus_error_free(&err);
        return st;
    };

    // Re-resolve from scratch: drop the old match, LoadUnit, arm a PropertiesChanged
    // match on the (possibly new) object path, and do the compare. Returns the backstop
    // cadence; sets bus_ok=false on a transport failure so the loop reopens the bus.
    auto reconcile = [&]() -> std::uint64_t {
        match_slot.reset(); // drop the old match (and its bus ref) first
        switch (resolve_path()) {
        case ResolveResult::BusError:
            bus_ok = false; // loop reopens; do NOT emit a false Absent
            return kAbsentRetryMs;
        case ResolveResult::NotFound:
            unit_path.clear();
            emit(SystemdState::Absent);
            return kAbsentRetryMs;
        case ResolveResult::Resolved:
            break;
        }
        sd_bus_slot* slot = nullptr;
        int r = sd_bus_match_signal(bus, &slot, kDest, unit_path.c_str(), kPropsIface,
                                    "PropertiesChanged", &on_props_changed, &dirty);
        if (r < 0) {
            spdlog::warn("Guardian SystemdServiceGuard[{}]: match arm failed for '{}': {}",
                         yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit), err_str(-r));
            if (auto st = read_state())
                emit(*st);
            else
                bus_ok = false; // transport failure — reopen, never a false Absent
            return kAbsentRetryMs;
        }
        match_slot.reset(slot);
        if (auto st = read_state()) { // initial / re-resolved compare
            emit(*st);
        } else {
            bus_ok = false; // transport failure between arm and read — reopen
            return kAbsentRetryMs;
        }
        return kHealthyReconcileMs;
    };

    // Reopen the system bus after a transport failure (systemd daemon-reexec / dbus
    // restart). Reset the match slot BEFORE unref'ing the old bus — the slot holds a
    // ref on it, so the order matters (cppsafe / advisor: reversing it trades the
    // leak for a use-after-free). Updates `bus_` so stop()'s post-join unref frees the
    // live connection.
    auto reopen_bus = [&]() -> bool {
        match_slot.reset();
        if (bus) {
            sd_bus_flush(bus);
            sd_bus_unref(bus);
        }
        bus = nullptr;
        bus_ = nullptr;
        sd_bus* nb = nullptr;
        if (sd_bus_open_system(&nb) < 0 || !nb) {
            if (nb)
                sd_bus_unref(nb);
            return false;
        }
        bus = nb;
        bus_ = nb;
        bus_fd = sd_bus_get_fd(bus);
        subscribe();
        return true;
    };

    spdlog::info("Guardian SystemdServiceGuard[{}]: watching unit '{}' (expect {})",
                 yuzu::log_id_token(cfg_.rule_id), yuzu::log_key_token(unit), expected_token);

    subscribe();
    std::uint64_t backstop_ms = reconcile();
    auto next_backstop = std::chrono::steady_clock::now() + std::chrono::milliseconds(backstop_ms);

    while (!stop_.load(std::memory_order_acquire)) {
        // 1) While the bus is healthy, drain all queued messages (dispatches the match
        //    → may set dirty). A transport failure flips bus_ok and triggers a reopen.
        if (bus_ok) {
            for (;;) {
                int r = sd_bus_process(bus, nullptr);
                if (r < 0) {
                    spdlog::warn("Guardian SystemdServiceGuard[{}]: bus lost ({}) — reconnecting",
                                 yuzu::log_id_token(cfg_.rule_id), err_str(-r));
                    bus_ok = false;
                    next_backstop = std::chrono::steady_clock::now(); // reopen promptly
                    break;
                }
                if (stop_.load(std::memory_order_acquire) || r == 0)
                    break;
            }
            if (stop_.load(std::memory_order_acquire))
                break;
            if (bus_ok && dirty) {
                dirty = false;
                if (auto st = read_state()) {
                    emit(*st);
                } else {
                    bus_ok = false; // transport failure — reopen promptly, no false drift
                    next_backstop = std::chrono::steady_clock::now();
                }
            }
        }
        if (stop_.load(std::memory_order_acquire))
            break;

        // 2) Poll timeout: until the next backstop, capped (when healthy) by sd-bus's
        //    own next-operation deadline (an ABSOLUTE CLOCK_MONOTONIC us value).
        const auto now = std::chrono::steady_clock::now();
        long long timeout_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(next_backstop - now).count();
        if (timeout_ms < 0)
            timeout_ms = 0;
        if (bus_ok) {
            std::uint64_t bus_to_us = UINT64_MAX;
            if (sd_bus_get_timeout(bus, &bus_to_us) >= 0 && bus_to_us != UINT64_MAX) {
                const std::uint64_t now_us = monotonic_us();
                const long long bus_ms =
                    bus_to_us > now_us ? static_cast<long long>((bus_to_us - now_us) / 1000) : 0;
                if (bus_ms < timeout_ms)
                    timeout_ms = bus_ms;
            }
        }

        // While the bus is dead we poll ONLY the wake eventfd — never the stale bus fd
        // (polling a closed/HUP fd would busy-spin, the sec-M1/UP-3 CPU risk).
        struct pollfd fds[2];
        int wake_idx;
        if (bus_ok) {
            fds[0] = {bus_fd, static_cast<short>(sd_bus_get_events(bus)), 0};
            fds[1] = {wake_fd_, POLLIN, 0};
            wake_idx = 1;
        } else {
            fds[0] = {wake_fd_, POLLIN, 0};
            wake_idx = 0;
        }
        const int nfds = bus_ok ? 2 : 1;
        int pr = ::poll(fds, nfds, static_cast<int>(timeout_ms));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            spdlog::warn("Guardian SystemdServiceGuard[{}]: poll: {}", yuzu::log_id_token(cfg_.rule_id),
                         err_str(errno));
            break;
        }
        if (fds[wake_idx].revents & POLLIN)
            break; // stop() signalled

        if (std::chrono::steady_clock::now() >= next_backstop) {
            if (!bus_ok) {
                if (reopen_bus()) {
                    bus_ok = true;
                    spdlog::info("Guardian SystemdServiceGuard[{}]: system bus reconnected",
                                 yuzu::log_id_token(cfg_.rule_id));
                    backstop_ms = reconcile();
                } else {
                    backstop_ms = kAbsentRetryMs; // retry reopen next tick
                }
            } else {
                backstop_ms = reconcile(); // may itself flip bus_ok on a transport error
            }
            if (!bus_ok)
                backstop_ms = kAbsentRetryMs;
            next_backstop =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(backstop_ms);
        }
        // Otherwise the bus fd is readable → loop; sd_bus_process drains it.
    }

    // match_slot RAII unref's on scope exit here — BEFORE stop() unrefs bus_ after the
    // join — so the slot's bus ref is always dropped first, on every path incl. throw.
} catch (const std::exception& e) {
    spdlog::error("Guardian SystemdServiceGuard[{}]: watch thread exception: {} — watch stopping",
                  yuzu::log_id_token(cfg_.rule_id), e.what());
} catch (...) {
    spdlog::error("Guardian SystemdServiceGuard[{}]: watch thread unknown exception — stopping",
                  yuzu::log_id_token(cfg_.rule_id));
}

} // namespace yuzu::agent

#else // ── No sd-bus (non-Linux, or Linux built without libsystemd): no-op stub ──

namespace yuzu::agent {

SystemdServiceGuard::SystemdServiceGuard(Config cfg, Sink sink)
    : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
SystemdServiceGuard::~SystemdServiceGuard() {}
bool SystemdServiceGuard::start() { return false; }
void SystemdServiceGuard::stop() {}
void SystemdServiceGuard::run() {}

} // namespace yuzu::agent

#endif
