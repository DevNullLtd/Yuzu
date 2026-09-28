/**
 * spark_service.cpp — the Service spark mechanism (ADR-0021 Stage 1 PR 1c).
 *
 * Third and last event-driven mechanism, completing Stage 1's detection triad
 * (File/IOCP + Registry/TP_WAIT from PR 1b). Multiplexes N systemd-unit /
 * Windows-service run-state watches onto ONE sd-bus connection + ONE thread
 * (Linux) or ONE alertable-wait thread + ONE SCM connection (Windows) —
 * O(mechanism) resources, never O(rules). This is a REWRITE of the per-unit
 * guard_systemd.cpp / guard_service.cpp watch loops (those stay Guardian's;
 * this is the Spark layer), reusing their PURE state-mapping/validation
 * helpers and error-classification rules but replacing "one thread + one
 * connection per watch" with a single poll-thread-confined mechanism.
 *
 * PORTS THE WATCH, NOT THE ASSERTION: a fired spark carries the resolved
 * terminal ServiceRunState (see spark.hpp — Service is the one event-driven
 * type that DOES carry a payload, unlike File/Registry's monostate) but does
 * NO compare-to-desired, NO enforce. That is Guardian's, Stage 2.
 *
 * Resource contract (the acceptance bar, stricter than 1b — thread count alone
 * over-reports the collapse):
 *   Linux:   1 sd_bus connection (1 fd) + 1 eventfd + 1 thread, for ANY N.
 *   Windows: 1 thread + 1 SCM handle + 1 wake event + N service handles
 *            (unavoidable — NotifyServiceStatusChangeW needs one per service).
 *
 * Command marshaling (both platforms) is FIRE-AND-FORGET, not a synchronous
 * handshake: watch()/unwatch() enqueue a command and wake the mechanism
 * thread; they never block waiting for the thread to act on it. This is
 * deliberate, not merely convenient — the emit_/fault_ callbacks run ON the
 * mechanism thread (sd-bus process loop / SCM APC), and an INLINE consumer's
 * handler is allowed to call arm() from inside its own delivery, which calls
 * back into watch() — on the SAME thread that would have to service a
 * handshake. A synchronous wait-for-ack design would self-deadlock (or
 * spuriously time out) on every inline re-arm. There is also nothing genuine
 * to wait for: an absent unit/service is not an arm failure (arm succeeds,
 * the mechanism polls for its return — the guards' own precedent), and every
 * later failure surfaces through the fault channel, not a watch() return.
 *
 * Off macOS and off a Linux build without libsystemd (`systemd_guard` meson
 * option) the factory returns nullptr → SparkEngine rejects arm(Service),
 * preserving "armed == a watcher is running".
 */

#include "spark_mechanism.hpp"

#include <yuzu/agent/guard_systemd.hpp> // parse_active_state, systemd_error_name_is_absence,
                                        // systemd_state_is_transitional, normalize_unit_name,
                                        // valid_unit_name — pure, all-platform, shared with the guard
#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

// ═══════════════════════════════════════════════════════════════════════════
// Linux: one sd-bus connection + one poll thread, multiplexing N unit watches.
// ═══════════════════════════════════════════════════════════════════════════

#include <systemd/sd-bus.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>      // free
#include <ctime>        // clock_gettime
#include <system_error> // std::generic_category — thread-safe strerror replacement

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace yuzu::agent {
namespace {

constexpr const char* kDest       = "org.freedesktop.systemd1";
constexpr const char* kMgrPath    = "/org/freedesktop/systemd1";
constexpr const char* kMgrIface   = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnitIface  = "org.freedesktop.systemd1.Unit";
constexpr const char* kPropsIface = "org.freedesktop.DBus.Properties";

// Degraded re-poll cadence for an absent/unresolved unit; healthy-watch backstop
// reconcile cadence otherwise. Mirrors guard_systemd.cpp's identical constants —
// the event-driven path is fully push-based while healthy; these are only the
// bounded safety net against a missed signal or a genuinely dead connection.
constexpr std::uint64_t kAbsentRetryMs = 30000;
constexpr std::uint64_t kHealthyReconcileMs = 60000;

std::string err_str(int e) { return std::generic_category().message(e); }

std::uint64_t monotonic_us() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ull +
           static_cast<std::uint64_t>(ts.tv_nsec) / 1000ull;
}

// Outcome of LoadUnit — mirrors guard_systemd.cpp's ResolveResult split so a
// transient bus error never fabricates a false "stopped" (UP-4 class).
enum class ResolveResult { Resolved, NotFound, BusError };

ServiceRunState map_terminal(SystemdState st) {
    // Only reached for a non-transitional state (caller gates on
    // systemd_state_is_transitional first). Active -> Running; every other
    // terminal value (Inactive/Failed/Absent) -> Stopped, per spark.hpp's
    // documented mapping.
    return st == SystemdState::Active ? ServiceRunState::Running : ServiceRunState::Stopped;
}

// PropertiesChanged match callback. Runs synchronously inside sd_bus_process()
// on the poll thread (never concurrently with the rest of the loop), so it
// just flags the unit dirty — the loop re-reads ActiveState rather than
// parsing the changed-property set, which is both simpler and robust to
// PropertiesChanged batching (mirrors guard_systemd.cpp's on_props_changed).
struct UnitWatch;
int on_props_changed(sd_bus_message*, void* userdata, sd_bus_error*);

struct PendingEmit {
    std::string key;
    ServiceRunState state;
};
struct PendingFault {
    std::string key;
    bool faulted;
    std::string reason;
};
/// A staged establishment-signal report (rung 9c PR-6 item 1) — see
/// SparkEstablishedFn's own doc comment for the field semantics. `incarnation`
/// is this key's recorded value in `key_incarnation_` AT THE MOMENT this entry
/// was staged (Linux has no cross-tick staleness window to guard against — see
/// drop_stale()'s doc comment for the same-tick Remove+Add staging race
/// Windows's separate `key_epoch` exists to close; Linux's on_props_changed
/// runs synchronously on the poll thread (see the Cmd::Remove handling
/// above) so no such window exists — so unlike Windows's twin there is no
/// separate `key_epoch` to carry).
struct PendingEstablished {
    std::string key;
    SparkIncarnation incarnation;
    std::chrono::steady_clock::time_point at;
    SparkCoverage coverage;
};

/// One watched systemd unit, poll-thread-confined (no lock — see the class
/// comment on LinuxServiceMechanism). Distinct spark keys ("ssh" vs
/// "ssh.service") may coalesce onto the same UnitWatch; a fire fans out to
/// every key in `keys`.
struct UnitWatch {
    std::string unit; ///< normalized name (normalize_unit_name); map key in units_
    std::set<std::string> keys;
    std::string path; ///< resolved object path; empty = absent/unresolved
    std::unique_ptr<sd_bus_slot, decltype(&sd_bus_slot_unref)> slot{nullptr, &sd_bus_slot_unref};
    bool dirty{false};
    std::optional<ServiceRunState> last; ///< edge-dedup baseline; nullopt until the first terminal
    bool faulted{false};
    std::chrono::steady_clock::time_point next_backstop{};
    /// Last-STAGED establishment coverage (rung 9c PR-6 item 1) — the per-watch
    /// cache a coalescing/adopting key's unconditional report reads back; written
    /// by every row of the coverage table, never read for any gating decision.
    SparkCoverage coverage{SparkCoverage::None};
};

int on_props_changed(sd_bus_message*, void* userdata, sd_bus_error*) {
    if (userdata)
        static_cast<UnitWatch*>(userdata)->dirty = true;
    return 0;
}

/// Linux Service spark mechanism: ONE sd-bus connection + ONE poll thread
/// service every armed unit watch. `watch()`/`unwatch()` (called from
/// engine/consumer threads) never touch the bus directly — sd-bus handles are
/// strictly single-thread-confined, so they enqueue a command under `mu_` and
/// wake the poll thread via an eventfd. `mu_` protects ONLY `pending_` and the
/// start/stop flags; `units_` and all per-unit state are poll-thread-confined
/// (stronger than spark_registry.cpp's collect-under-lock/dispatch-released —
/// here there is nothing to collect a lock for, so emit_/fault_ are trivially
/// never invoked under any lock).
class LinuxServiceMechanism final : public ISparkMechanism {
public:
    ~LinuxServiceMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        // teardown_mu_ before mu_ (see the member note). start() must exclude stop(), not
        // just stop-vs-stop: start() assigns thread_/bus_/wake_fd_ while stop() joins the
        // thread and frees those same members holding only teardown_mu_. Without this the
        // mechanism would still be relying on SparkEngine::lifecycle_mu_ to keep them
        // apart — and ISparkMechanism is a public interface that must not depend on a
        // caller's lock. (Gate-8 round 2 cpp-safety.)
        std::lock_guard teardown(teardown_mu_);
        std::lock_guard lk(mu_);
        // One-way seal (rung 9c PR-6 item 1): start() being CALLED is what seals
        // the establishment sink, whether or not this call does anything else —
        // set first, before the idempotent early-return, so a repeat start()
        // can never re-open the window. Never cleared by stop(): SparkEngine
        // itself is single-shot (spark_engine.hpp's own header doc), so no
        // production caller ever needs to re-arm the sink after a stop().
        sink_sealed_ = true;
        // Governance UP-1(B) hazard (security-guardian Gate-8): this guard reads
        // the SAME started_ this class's run()-catch blocks now flip to false on
        // an uncaught worker-thread exception. ISparkMechanism::start() is
        // documented "called exactly once by SparkEngine::start()" and has
        // exactly one production call site — E6-capped, not reachable today —
        // but a hypothetical second start() after a thread death would fall
        // through here instead of early-returning: it would open a fresh
        // sd_bus/eventfd over the still-live bus_/wake_fd_ (leaking them) and
        // then move-assign thread_ over a still-joinable std::thread, which
        // calls std::terminate(). Do not add a second production call to
        // SparkEngine::start() without also hardening this guard to match
        // stop()'s resource-conjunction shape.
        if (started_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        sd_bus* bus = nullptr;
        int r = sd_bus_open_system(&bus);
        if (r < 0 || !bus) {
            spdlog::warn("spark_service: system bus unavailable ({}) — service sparks inert on "
                         "this host (non-systemd host?)",
                         r < 0 ? err_str(-r) : std::string("no bus"));
            if (bus)
                sd_bus_unref(bus);
            inert_.store(true, std::memory_order_release);
            started_ = true; // "started" so watch() reaches the inert_ rejection, not "not started"
            return;
        }
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0) {
            sd_bus_unref(bus);
            inert_.store(true, std::memory_order_release);
            started_ = true;
            return;
        }
        bus_ = bus;
        wake_fd_ = efd;
        stop_.store(false, std::memory_order_release);
        thread_ = std::thread([this] { run(); });
        started_ = true;
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        // The engine never calls this overload in production (it always calls
        // watch_incarnation() below) — kept for direct/test callers that predate
        // the establishment signal. kNoSparkIncarnation is a valid, harmless
        // identity: nothing rejects it, it simply never matches a real engine
        // incarnation.
        return watch_incarnation(key, params, kNoSparkIncarnation);
    }

    std::expected<void, std::string> watch_incarnation(const std::string& key,
                                                        const SparkParams& params,
                                                        SparkIncarnation incarnation) override {
        const auto* sp = std::get_if<ServiceSparkParams>(&params);
        if (!sp)
            return std::unexpected("service mechanism: params are not ServiceSparkParams");
        // Defence-in-depth parity with the Windows mechanism's valid_service_name
        // check (governance Gate-2 finding): production arms are already gated
        // by the engine's valid_unit_name call in validate_and_floor, but this
        // watch() is directly callable in tests, bypassing the engine.
        if (!valid_unit_name(sp->service_name))
            return std::unexpected("service mechanism: invalid unit name '" + sp->service_name +
                                   "'");
        std::lock_guard lk(mu_);
        if (!started_)
            return std::unexpected("service mechanism not started");
        if (inert_)
            return std::unexpected("system bus unavailable — service sparks unsupported on this "
                                   "host");
        pending_.push_back(Cmd{Cmd::Add, key, normalize_unit_name(sp->service_name), incarnation});
        wake();
        return {};
    }

    bool set_established_sink(SparkEstablishedFn sink) override {
        std::lock_guard lk(mu_);
        if (sink_sealed_)
            return false;
        established_ = std::move(sink);
        return true;
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        if (!started_ || inert_)
            return;
        pending_.push_back(Cmd{Cmd::Remove, key, {}});
        wake();
    }

    void stop() override {
        // CLAIM the resources under mu_, in one atomic step: move them into locals and
        // null the members. Whoever wins the lock owns the teardown; every later caller
        // finds a cleared object and returns.
        //
        // Guarding on the RESOURCES rather than on started_ is what fixes the original
        // leak: start() publishes bus_/wake_fd_ BEFORE spawning the poll thread, and the
        // std::thread ctor throws std::system_error under EAGAIN — the very
        // thread-exhaustion case agent.cpp's degrade-to-no-spark guard exists to survive.
        // started_ is never reached on that throw, so a bool-only guard early-returned
        // here and leaked the sd_bus connection AND the eventfd for the process lifetime
        // (~this calls the same stop(), so it could not recover either). bus_/wake_fd_ are
        // RAW members (void*/int) — unlike the Windows SCM twin below, whose scm_/wake_
        // are RAII handles that self-release even on an early return, and unlike
        // spark_file.cpp (guards on iocp_) / spark_registry.cpp (guards on pool_), which
        // already guard on the resource. This mechanism was the only one that could leak.
        //
        // But a resource guard that READS the members while they are only cleared LATE,
        // outside the lock, is merely SEQUENTIALLY idempotent: two concurrent stop()s
        // would both see a live bus_ and both fall through — double sd_bus_unref, double
        // close(), double join. The old !started_ guard was concurrency-safe precisely
        // because started_ flipped under mu_. SparkEngine::lifecycle_mu_ happens to
        // serialise stop() today, but ISparkMechanism::stop() is a public interface
        // documented as idempotent and must not depend on a caller's lock. Claiming under
        // mu_ restores that. (Gate-8 cpp-safety — a regression in the B1 fix itself.)
        // teardown_mu_ serialises stop() END TO END — the same shape as
        // SparkEngine::lifecycle_mu_, one level down. A second caller (the destructor, or
        // a concurrent engine stop()) BLOCKS here until the first has finished, then finds
        // a fully-cleared object and early-returns below. That is what makes the resource
        // guard safe under concurrency without touching the resources early.
        //
        // Do NOT be tempted to "claim" bus_/wake_fd_ into locals under mu_ instead: the
        // poll thread READS wake_fd_ in run() for as long as it is alive, so nulling the
        // members before the join is a data race (TSan caught exactly that). The
        // resources may only be released AFTER the thread has joined — which is precisely
        // why the original code cleared them late, and why the fix belongs in a teardown
        // lock rather than in an earlier claim.
        std::lock_guard teardown(teardown_mu_);
        {
            std::lock_guard lk(mu_);
            if (!started_ && !bus_ && wake_fd_ < 0 && !thread_.joinable())
                return; // nothing was ever acquired, or a previous stop() already cleared it
            started_ = false;
        }
        if (thread_.joinable()) {
            stop_.store(true, std::memory_order_release);
            wake();
            thread_.join();
        }
        // The poll thread has joined — units_/bus_/wake_fd_ are now safe to touch without
        // a lock, and nothing can be reading them. Clearing units_ runs every UnitWatch's
        // slot RAII (unref) BEFORE the bus itself is unref'd below (a slot holds a ref on
        // the bus it matched against — the same ordering guard_systemd.cpp's reopen_bus
        // enforces).
        units_.clear();
        key_unit_.clear();
        if (bus_) {
            sd_bus_flush(static_cast<sd_bus*>(bus_));
            sd_bus_unref(static_cast<sd_bus*>(bus_));
            bus_ = nullptr;
        }
        if (wake_fd_ >= 0) {
            ::close(wake_fd_);
            wake_fd_ = -1;
        }
        std::lock_guard lk(mu_);
        emit_ = nullptr;
        fault_ = nullptr;
        // established_ is cleared here too (nulled only after the poll thread has
        // joined, mirroring emit_/fault_) but sink_sealed_ is DELIBERATELY left
        // set — an ordinary stop() reports NOTHING further (R4: matches
        // subscription_health's stale-after-stop precedent), and the seal itself
        // is one-way for this instance's life, not a per-lifecycle latch.
        established_ = nullptr;
        inert_.store(false, std::memory_order_release);
        pending_.clear();
    }

    /// This mechanism tracks none of the File-mechanism counters (retiring/quarantine/
    /// slow-op are ReadDirectoryChangesW-specific — #1979/#1980/#1982); its own
    /// fault-tiering and retry counters are tracked separately (#1929/#1931). What it
    /// MUST publish is `inert`, so the fleet can tell a service mechanism that bound
    /// the system bus from one that never did (the container case). `inert_` here is
    /// ENTIRELY boot-time (#4685) — Linux Service has no runtime-inert concept, unlike
    /// File/Registry — so `.boot_inert` is the same atomic, not a separate flag.
    [[nodiscard]] SparkMechanismStats stats() const override {
        const bool boot = inert_.load(std::memory_order_acquire);
        return {.inert = boot, .boot_inert = boot};
    }

private:
    struct Cmd {
        enum Op { Add, Remove } op;
        std::string key;
        std::string unit; // only meaningful for Add
        SparkIncarnation incarnation{kNoSparkIncarnation}; // only meaningful for Add
    };

    void wake() {
        if (wake_fd_ < 0)
            return;
        const std::uint64_t one = 1;
        ssize_t w = ::write(wake_fd_, &one, sizeof(one));
        (void)w; // best-effort; the poll thread also re-checks pending_/stop_ each loop
    }

    // ── Poll-thread-confined helpers (called only from run()) ──────────────

    ResolveResult resolve_path(sd_bus* bus, UnitWatch& uw) {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        ResolveResult res = ResolveResult::BusError; // fail-safe default (cpp-safety Gate-8)
        int r = sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "LoadUnit", &err, &reply, "s",
                                   uw.unit.c_str());
        if (r >= 0 && reply) {
            const char* p = nullptr;
            if (sd_bus_message_read(reply, "o", &p) >= 0 && p && *p) {
                uw.path = p;
                res = ResolveResult::Resolved;
            } else {
                res = ResolveResult::NotFound;
            }
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            res = ResolveResult::NotFound;
        } else {
            spdlog::warn("spark_service: LoadUnit '{}' transient error (name='{}', {}) — "
                         "reopening, no false Stopped",
                         ::yuzu::log_key_token(uw.unit), err.name ? err.name : "(none)",
                         err.message ? err.message : err_str(r < 0 ? -r : 0));
            res = ResolveResult::BusError;
        }
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
        return res;
    }

    // nullopt only on a bare TRANSPORT failure (bus gone) — never on a genuine
    // Absent, which is a real terminal state (mirrors guard_systemd.cpp).
    std::optional<SystemdState> read_state(sd_bus* bus, UnitWatch& uw) {
        if (uw.path.empty())
            return SystemdState::Absent;
        sd_bus_error err = SD_BUS_ERROR_NULL;
        char* s = nullptr;
        std::optional<SystemdState> st;
        int r = sd_bus_get_property_string(bus, kDest, uw.path.c_str(), kUnitIface, "ActiveState",
                                           &err, &s);
        if (r >= 0 && s) {
            st = parse_active_state(s);
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            st = SystemdState::Absent;
        } else {
            spdlog::warn("spark_service: ActiveState read transient error for '{}' (name='{}') — "
                         "reopening, no false drift",
                         ::yuzu::log_key_token(uw.unit), err.name ? err.name : "(none)");
        }
        if (s)
            free(s);
        sd_bus_error_free(&err);
        return st;
    }

    // Collects an emit for every key on `uw` if the mapped terminal state is a
    // real edge vs. `uw.last`; transitional states are held (no compare, no
    // commit) per spark.hpp's documented contract.
    void set_terminal(UnitWatch& uw, ServiceRunState mapped, std::vector<PendingEmit>& out) {
        if (uw.last && *uw.last == mapped)
            return; // no-edge, silent
        uw.last = mapped;
        for (const auto& k : uw.keys)
            out.push_back({k, mapped});
    }

    void set_terminal_from_systemd(UnitWatch& uw, SystemdState st, std::vector<PendingEmit>& out) {
        if (systemd_state_is_transitional(st))
            return; // HELD — never emitted, never moves the edge-dedup baseline
        set_terminal(uw, map_terminal(st), out);
    }

    // (Re)resolve + (re)arm the PropertiesChanged match for `uw` from scratch —
    // drops any prior slot first. Collects an initial/re-resolved emit for
    // every current key on `uw`. Sets bus_ok_=false on a transport failure
    // (caller reopens); never fabricates a false Stopped on that path.
    // `faults` lets arm_unit report a bus failure it discovers itself
    // (governance Gate-4 unhappy-path finding, UP-1): the three call sites
    // below previously only fed a fresh BusError into `bus_ok_`, relying on
    // the main loop's OWN process/read failure sites to call fault_all — but
    // a re-arm invoked from Cmd::Add, the healthy-reconcile backstop loop, or
    // the reopen-success re-arm-all pass could discover the SAME class of
    // failure without ever routing through those two call sites, silently
    // swallowing the fault signal for every unit on the connection.
    void arm_unit(sd_bus* bus, UnitWatch& uw, std::vector<PendingEmit>& emits,
                  std::vector<PendingFault>& faults, std::vector<PendingEstablished>& established) {
        uw.slot.reset(); // drop the old match (and its bus ref) first
        // Unconditional (rung 9c PR-6 item 1, round-4 MF1): discarding the old
        // match genuinely means coverage is None until re-established below,
        // even when re-establishment resolves microseconds later in this same
        // synchronous call — mirrors Windows's begin_probe() staging None right
        // after its own teardown_watch().
        stage_coverage(uw, SparkCoverage::None, established);
        switch (resolve_path(bus, uw)) {
        case ResolveResult::BusError:
            bus_ok_ = false;
            fault_all(true, "system bus lost", faults);
            drop_coverage_all(established);
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        case ResolveResult::NotFound:
            uw.path.clear();
            set_terminal(uw, ServiceRunState::Stopped, emits);
            stage_coverage(uw, SparkCoverage::Poll, established);
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        case ResolveResult::Resolved:
            break;
        }
        sd_bus_slot* slot = nullptr;
        int r = sd_bus_match_signal(bus, &slot, kDest, uw.path.c_str(), kPropsIface,
                                    "PropertiesChanged", &on_props_changed, &uw);
        if (r < 0) {
            spdlog::warn("spark_service: match arm failed for '{}': {}",
                         ::yuzu::log_key_token(uw.unit), err_str(-r));
            if (auto st = read_state(bus, uw)) {
                set_terminal_from_systemd(uw, *st, emits);
                stage_coverage(uw, SparkCoverage::Poll, established);
            } else {
                bus_ok_ = false;
                fault_all(true, "system bus lost", faults);
                drop_coverage_all(established);
            }
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        uw.slot.reset(slot);
        if (auto st = read_state(bus, uw)) {
            set_terminal_from_systemd(uw, *st, emits);
            // Notification only if the mechanism-wide Subscribe() call itself
            // succeeded (H7) — a bare successful match-rule registration alone
            // never delivers a signal without it; falls back to Poll (the
            // bounded backstop reconcile) otherwise.
            stage_coverage(uw, subscribed_ ? SparkCoverage::Notification : SparkCoverage::Poll,
                          established);
        } else {
            bus_ok_ = false;
            fault_all(true, "system bus lost", faults);
            drop_coverage_all(established);
        }
        uw.next_backstop = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds(kHealthyReconcileMs);
    }

    // Edge-gated per-unit fault fan-out: fires fault_(key,faulted,reason) for
    // every key on a unit whose faulted state is actually changing (never every
    // tick), mirroring spark_registry.cpp's per-key fault edge discipline.
    void fault_all(bool faulted, std::string_view reason, std::vector<PendingFault>& out) {
        for (auto& [name, uwp] : units_) {
            if (uwp->faulted == faulted)
                continue;
            uwp->faulted = faulted;
            for (const auto& k : uwp->keys)
                out.push_back({k, faulted, std::string(reason)});
        }
    }

    // Stage an establishment report for EVERY key on `uw`, UNCONDITIONALLY
    // (rung 9c PR-6 item 1, round-4 MF1: every row of the coverage table stages
    // regardless of whether this is an "edge" — the engine is idempotent on
    // repeated coverage and first-wins on established_at, so a redundant report
    // costs nothing worse than a wasted round trip). `uw.coverage` is written
    // here as the LAST-STAGED value and read only by a later coalescing/
    // adopting key's own unconditional report. Fresh Clock::now() taken HERE,
    // at the statement — never a loop-top local (MF4: a stale `now` could stamp
    // established_at before armed_at).
    void stage_coverage(UnitWatch& uw, SparkCoverage cov, std::vector<PendingEstablished>& out) {
        uw.coverage = cov;
        for (const auto& k : uw.keys)
            out.push_back({k, key_incarnation_.at(k), std::chrono::steady_clock::now(), cov});
    }

    // The coverage twin of fault_all's connection-wide broadening (F2: kept
    // INDEPENDENT of fault_all's own edge-gating) — every call site that
    // discovers a connection-wide bus loss calls both. Unlike fault_all, this
    // is NEVER edge-gated: a unit already faulted from a prior loss still gets
    // its coverage re-confirmed None on a second, independent loss discovery,
    // or a stale positive value could survive under an already-faulted key.
    void drop_coverage_all(std::vector<PendingEstablished>& out) {
        for (auto& [name, uwp] : units_)
            stage_coverage(*uwp, SparkCoverage::None, out);
    }

    void dispatch(std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults,
                 std::vector<PendingEstablished>& established) {
        // Established first (no ordering requirement from the plan; picked so a
        // consumer observing a Fired/Faulted event for a key can already see its
        // establishment report land no later than the same dispatch batch).
        for (auto& e : established)
            if (established_)
                established_(e.key, e.incarnation, e.at, e.coverage);
        established.clear();
        for (auto& e : emits)
            if (emit_)
                emit_(e.key, SparkData{ServiceSparkData{e.state}});
        emits.clear();
        for (auto& f : faults)
            if (fault_)
                fault_(f.key, f.faulted, f.reason);
        faults.clear();
    }

    // MF3: invalidate every currently-tracked key's coverage to None, by
    // reference (no SparkEstablishedFn copy, no allocation) — called as the
    // FIRST statement of each of run()'s exception catch blocks, before any
    // log call, so a worker-thread exception leaves no stale positive coverage
    // for the engine to keep trusting. Hard constraint: zero spdlog calls
    // inside the per-key loop (#2270 is exactly logging breaking a guarantee
    // like this one). noexcept: every fallible call inside is caught, and
    // std::terminate is the honest outcome if that invariant is ever wrong.
    void invalidate_established_noexcept() noexcept {
        const SparkEstablishedFn& sink = established_; // reference: no copy; nulled only after join
        if (!sink)
            return;
        const auto now = std::chrono::steady_clock::now(); // noexcept
        for (const auto& [key, inc] : key_incarnation_) {
            try {
                sink(key, inc, now, SparkCoverage::None);
            } catch (...) {
            }
        }
    }

    void run() try {
        auto* bus = static_cast<sd_bus*>(bus_);
        bus_ok_ = true;
        std::vector<PendingEmit> emits;
        std::vector<PendingFault> faults;
        std::vector<PendingEstablished> established;

        // Subscribe so systemd emits unit signals to us at all — non-fatal if
        // it fails (degrades to the bounded backstop reconcile only), mirrors
        // guard_systemd.cpp's subscribe(). Re-run after every reopen.
        // subscribed_ (H7, rung 9c PR-6 item 1) records the OUTCOME — a
        // per-unit PropertiesChanged match registering successfully means
        // nothing for real Notification coverage if the daemon was never told
        // to emit unit signals to this connection in the first place.
        auto subscribe = [&] {
            sd_bus_error err = SD_BUS_ERROR_NULL;
            sd_bus_message* reply = nullptr;
            subscribed_ =
                sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "Subscribe", &err, &reply, "") >=
                0;
            if (!subscribed_)
                spdlog::warn("spark_service: Subscribe failed ({}) — falling back to bounded "
                             "reconcile only",
                             err.message ? err.message : "(none)");
            if (reply)
                sd_bus_message_unref(reply);
            sd_bus_error_free(&err);
        };
        subscribe();

        while (!stop_.load(std::memory_order_acquire)) {
            // 1) Drain queued bus messages while healthy (dispatches matches ->
            //    sets dirty). A transport failure flips bus_ok_ and faults every
            //    watched key at once.
            if (bus_ok_) {
                for (;;) {
                    int r = sd_bus_process(bus, nullptr);
                    if (r < 0) {
                        spdlog::warn("spark_service: bus lost ({}) — reconnecting", err_str(-r));
                        bus_ok_ = false;
                        fault_all(true, "system bus lost", faults);
                        drop_coverage_all(established);
                        break;
                    }
                    if (stop_.load(std::memory_order_acquire) || r == 0)
                        break;
                }
                if (stop_.load(std::memory_order_acquire))
                    break;
            }

            // 2) Re-read every dirty unit.
            if (bus_ok_) {
                for (auto& [name, uwp] : units_) {
                    if (!uwp->dirty)
                        continue;
                    uwp->dirty = false;
                    if (auto st = read_state(bus, *uwp)) {
                        set_terminal_from_systemd(*uwp, *st, emits);
                    } else {
                        bus_ok_ = false;
                        fault_all(true, "system bus lost", faults);
                        drop_coverage_all(established);
                        break;
                    }
                }
            }

            // 3) Drain pending watch()/unwatch() commands.
            std::deque<Cmd> cmds;
            {
                std::lock_guard lk(mu_);
                cmds.swap(pending_);
            }
            for (auto& cmd : cmds) {
                if (cmd.op == Cmd::Add) {
                    auto it = units_.find(cmd.unit);
                    const bool is_new_unit = (it == units_.end());
                    UnitWatch* uw;
                    if (is_new_unit) {
                        auto owned = std::make_unique<UnitWatch>();
                        owned->unit = cmd.unit;
                        uw = owned.get();
                        units_.emplace(cmd.unit, std::move(owned));
                    } else {
                        uw = it->second.get();
                    }
                    // Exception-safety (governance UP-1(A), adjudicated
                    // LOW-today/MEDIUM-post-flip): populate every map
                    // stage_coverage()'s .at() later reads FIRST, insert into
                    // .keys LAST — a bad_alloc between these statements now
                    // leaves a harmless orphan map entry (persists for this
                    // mechanism instance's lifetime — neither platform's
                    // stop() clears key_incarnation_/key_epoch_, and no
                    // Remove/Add for this key ever runs afterward: the SAME
                    // exception that creates the orphan also propagates
                    // straight to run()'s own outer catch, permanently
                    // admission-gating the mechanism via UP-1(B)'s fix below)
                    // instead of a .keys member .at() will trip on, killing
                    // the whole mechanism worker thread.
                    // Forward-only rebind (H1): a stale/duplicate Add can
                    // never regress this key's recorded incarnation — H1's
                    // submission ordering (the engine holds this type's
                    // mech-ops lock across check+submit) means one should never
                    // actually arrive here below the current value in
                    // production; this is defence-in-depth, not a live path.
                    auto& inc_slot = key_incarnation_[cmd.key];
                    if (cmd.incarnation > inc_slot)
                        inc_slot = cmd.incarnation;
                    key_unit_.emplace(cmd.key, cmd.unit);
                    // no-op if cmd.key is already present — see the unified
                    // branch below for why that ("adoption") is now handled
                    // rather than skipped.
                    uw->keys.insert(cmd.key);
                    if (is_new_unit) {
                        if (bus_ok_) {
                            arm_unit(bus, *uw, emits, faults, established);
                        } else {
                            // Bus is down: this key is faulted from the moment
                            // it arms; reopen's re-arm-all pass will resolve it.
                            // MUST set next_backstop — a fresh UnitWatch's
                            // default-constructed time_point{} sentinel sorts
                            // before `now` in the poll-timeout computation
                            // below, collapsing it to 0 and busy-looping
                            // sd_bus_open_system every iteration until the bus
                            // recovers (governance Gate-3 cpp-expert finding).
                            uw->faulted = true;
                            uw->coverage = SparkCoverage::None;
                            uw->next_backstop = std::chrono::steady_clock::now() +
                                                std::chrono::milliseconds(kAbsentRetryMs);
                            faults.push_back({cmd.key, true, "system bus lost"});
                            established.push_back(
                                {cmd.key, inc_slot, std::chrono::steady_clock::now(),
                                 SparkCoverage::None});
                        }
                    } else {
                        // F4: ONE unconditional branch covers both COALESCE
                        // (cmd.key is genuinely new to this unit) and ADOPTION
                        // (cmd.key was already mapped to this exact unit — its
                        // disarm's unwatch() was skipped by
                        // SparkEngine::disarm()'s M2 staleness recheck and a
                        // fresh arm() landed on the still-live watch). Both need
                        // the SAME honest report of the unit's CURRENT coverage,
                        // whether or not this is an "edge" for the emit/fault
                        // channels below — round-4 MF1's unconditional-staging
                        // rule.
                        established.push_back(
                            {cmd.key, inc_slot, std::chrono::steady_clock::now(), uw->coverage});
                        // An existing (already-resolved) unit gains a new
                        // subscriber key — give it the initial state too, since
                        // engine subscribers are keyed per-spec.
                        if (uw->last)
                            emits.push_back({cmd.key, *uw->last});
                        // Hoisted OUT of the `uw->last` guard (round-4 fix,
                        // alongside the established push above): a unit that is
                        // faulted but has NEVER resolved a terminal state
                        // (bus-down since arm, no `last` yet) previously told a
                        // coalescing/adopting key NOTHING about the fault — the
                        // same "silently withheld" shape this whole fix exists
                        // to close (UP-2, governance Gate-4 unhappy-path).
                        if (uw->faulted)
                            faults.push_back({cmd.key, true, "system bus lost"});
                    }
                } else { // Cmd::Remove
                    auto kit = key_unit_.find(cmd.key);
                    if (kit == key_unit_.end())
                        continue; // unknown/already-removed key — idempotent
                    const std::string unit = kit->second;
                    key_unit_.erase(kit);
                    key_incarnation_.erase(cmd.key);
                    auto uit = units_.find(unit);
                    if (uit == units_.end())
                        continue;
                    uit->second->keys.erase(cmd.key);
                    // Freed synchronously, no Windows-style retiring_/quiescence list
                    // needed here: on_props_changed() runs synchronously inside
                    // sd_bus_process() on this SAME poll thread that also processes
                    // Cmd::Remove, so there is no in-flight-callback window an async
                    // APC (Windows's NotifyServiceStatusChangeW hazard) could land in.
                    if (uit->second->keys.empty())
                        units_.erase(uit); // slot RAII releases the match here
                }
            }

            // 4) Dispatch everything collected above — with NO lock held.
            dispatch(emits, faults, established);
            if (stop_.load(std::memory_order_acquire))
                break;

            // 5) Compute the poll timeout: soonest per-unit backstop, capped by
            //    sd-bus's own next-operation deadline while healthy.
            const auto now = std::chrono::steady_clock::now();
            auto next = now + std::chrono::milliseconds(kHealthyReconcileMs);
            for (auto& [name, uwp] : units_)
                if (uwp->next_backstop < next)
                    next = uwp->next_backstop;
            long long timeout_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count();
            if (timeout_ms < 0)
                timeout_ms = 0;
            if (!bus_ok_)
                timeout_ms = std::min<long long>(timeout_ms, static_cast<long long>(kAbsentRetryMs));
            if (bus_ok_) {
                std::uint64_t bus_to_us = UINT64_MAX;
                if (sd_bus_get_timeout(bus, &bus_to_us) >= 0 && bus_to_us != UINT64_MAX) {
                    const std::uint64_t now_us = monotonic_us();
                    const long long bus_ms = bus_to_us > now_us
                                                 ? static_cast<long long>((bus_to_us - now_us) / 1000)
                                                 : 0;
                    if (bus_ms < timeout_ms)
                        timeout_ms = bus_ms;
                }
            }

            // While the bus is dead we poll ONLY the wake eventfd — never the
            // stale bus fd (would busy-spin on a closed/HUP fd).
            struct pollfd fds[2];
            int wake_idx;
            int nfds;
            if (bus_ok_) {
                fds[0] = {sd_bus_get_fd(bus), static_cast<short>(sd_bus_get_events(bus)), 0};
                fds[1] = {wake_fd_, POLLIN, 0};
                wake_idx = 1;
                nfds = 2;
            } else {
                fds[0] = {wake_fd_, POLLIN, 0};
                wake_idx = 0;
                nfds = 1;
            }
            int pr = ::poll(fds, nfds, static_cast<int>(timeout_ms));
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                // Unrecoverable — the mechanism thread is about to exit and
                // every currently-armed key will silently stop updating
                // forever. Report it: without this, mechanism death is
                // indistinguishable from "healthy and quiet" in the engine's
                // stats (governance Gate-6 sre finding — a more severe
                // version of the re-arm fault-swallowing bug fixed earlier
                // this round).
                spdlog::error("spark_service: poll failed ({}) — mechanism thread exiting, "
                             "every armed key is now silently dead",
                             err_str(errno));
                fault_all(true, "mechanism thread terminating", faults);
                drop_coverage_all(established);
                // fault_all only covers already-armed units — a watch() that
                // landed in pending_ this same tick was never armed at all,
                // so it has no units_ entry for fault_all to find. Without
                // this, a consumer whose arm() call raced the mechanism's
                // death would get no signal whatsoever (governance Gate-4
                // unhappy-path finding UP-8). Cmd::Remove entries need no
                // signal — nothing was ever told they existed.
                {
                    std::lock_guard lk(mu_);
                    for (auto& cmd : pending_)
                        if (cmd.op == Cmd::Add)
                            faults.push_back({cmd.key, true, "mechanism thread terminating"});
                    pending_.clear();
                }
                dispatch(emits, faults, established);
                break;
            }
            if (fds[wake_idx].revents & POLLIN) {
                // eventfd is counter-semantics + level-triggered: an unread
                // write leaves it readable forever, busy-spinning poll() at
                // 100% CPU and starving the backstop/reopen block below on
                // every subsequent iteration (governance finding, PR #1927
                // review). Drain the counter before looping back to the top.
                std::uint64_t drained = 0;
                ssize_t n;
                do {
                    n = ::read(wake_fd_, &drained, sizeof(drained));
                } while (n < 0 && errno == EINTR);
                continue; // a command was enqueued or stop() signalled — loop re-checks at the top
            }

            // 6) Backstop expiry: reopen the bus if down, else re-arm any unit
            //    whose reconcile deadline passed.
            if (!bus_ok_) {
                sd_bus* nb = nullptr;
                if (sd_bus_open_system(&nb) >= 0 && nb) {
                    // Slot-before-bus: drop every unit's match (each holds a
                    // ref on the OLD connection) before releasing our own
                    // reference to it — mirrors guard_systemd.cpp's
                    // reopen_bus ordering. Without this, `bus = nb` below
                    // loses the only pointer that could ever unref the old
                    // connection, permanently leaking it + its fd on every
                    // reconnect (governance Gate-2 security-guardian finding)
                    // — arm_unit()'s own slot.reset() runs against the NEW
                    // bus pointer by the time it executes below, too late to
                    // release the old one.
                    for (auto& [name, uwp] : units_)
                        uwp->slot.reset();
                    if (bus) {
                        sd_bus_flush(bus);
                        sd_bus_unref(bus);
                    }
                    bus = nb;
                    bus_ = nb;
                    subscribe();
                    bus_ok_ = true;
                    // Don't declare "recovered" until the re-arm pass below
                    // actually confirms the connection is still usable — a
                    // bus that reopens but is dead-on-first-use would
                    // otherwise flap recovered→faulted within the same
                    // dispatch batch (governance Gate-6 sre finding).
                    for (auto& [name, uwp] : units_) {
                        arm_unit(bus, *uwp, emits, faults, established);
                        if (!bus_ok_)
                            break; // the connection died again mid-pass — fault_all(true)
                                   // inside arm_unit already covers every unit including
                                   // the ones not yet reached; re-trying them against the
                                   // same known-broken connection would be redundant and,
                                   // if one happened to transiently succeed, would leave it
                                   // stuck reporting faulted=true (set for ALL units by that
                                   // fault_all call) despite emitting healthy data — no
                                   // per-unit success clears a fault, only the NEXT reopen's
                                   // recovered edge does (governance Gate-3 cpp-expert finding)
                    }
                    if (bus_ok_)
                        fault_all(false, "recovered", faults); // only now confirmed still up
                    dispatch(emits, faults, established);
                    spdlog::info("spark_service: system bus reconnected");
                } else {
                    if (nb)
                        sd_bus_unref(nb);
                    // stays down; retried again after kAbsentRetryMs
                }
            } else {
                const auto now2 = std::chrono::steady_clock::now();
                for (auto& [name, uwp] : units_) {
                    if (uwp->next_backstop > now2)
                        continue;
                    arm_unit(bus, *uwp, emits, faults, established);
                    if (!bus_ok_)
                        break; // same reasoning as the reopen-rearm-all loop above
                }
                dispatch(emits, faults, established);
            }
        }
    } catch (const std::exception& e) {
        // MF3, first statement of the catch block: invalidate every currently-
        // tracked key's coverage to None BEFORE anything else, so an exception
        // mid-loop can never leave a stale positive coverage the engine keeps
        // trusting after this thread is gone.
        invalidate_established_noexcept();
        // Governance UP-1(B): mark this mechanism no longer accepting new watches.
        // Without this, watch_incarnation() (gated only on started_/inert_, neither
        // of which this catch block otherwise touches) would keep silently queuing
        // Cmd::Add into a pending_ deque nobody will ever drain again, returning
        // SUCCESS to the engine forever — a zombie mechanism indistinguishable
        // from a healthy idle one (I6 false-assurance). started_, NOT inert_: the
        // heartbeat's stats() publishes inert_ fleet-wide ("no system bus" is the
        // documented common-case meaning) — flipping it here would misreport a
        // worker-thread-death fault as a boot-time bus-unavailable condition, a
        // DIFFERENT false diagnostic. started_ is unpublished and mu_-guarded like
        // every other write to it in this class.
        {
            std::lock_guard lk(mu_);
            started_ = false;
        }
        try {
            spdlog::error("spark_service: poll thread exception: {} — mechanism stopping",
                          e.what());
        } catch (...) {
        }
    } catch (...) {
        invalidate_established_noexcept();
        // Governance UP-1(B): mark this mechanism no longer accepting new watches.
        // Without this, watch_incarnation() (gated only on started_/inert_, neither
        // of which this catch block otherwise touches) would keep silently queuing
        // Cmd::Add into a pending_ deque nobody will ever drain again, returning
        // SUCCESS to the engine forever — a zombie mechanism indistinguishable
        // from a healthy idle one (I6 false-assurance). started_, NOT inert_: the
        // heartbeat's stats() publishes inert_ fleet-wide ("no system bus" is the
        // documented common-case meaning) — flipping it here would misreport a
        // worker-thread-death fault as a boot-time bus-unavailable condition, a
        // DIFFERENT false diagnostic. started_ is unpublished and mu_-guarded like
        // every other write to it in this class.
        {
            std::lock_guard lk(mu_);
            started_ = false;
        }
        try {
            spdlog::error("spark_service: poll thread unknown exception — mechanism stopping");
        } catch (...) {
        }
    }

    /// Serialises start() and stop() END TO END against each other and against themselves,
    /// so a second stop() (typically ~LinuxServiceMechanism) WAITS for an in-flight
    /// teardown instead of racing it into a double sd_bus_unref / double close(), and a
    /// start() cannot assign thread_/bus_/wake_fd_ while a stop() is joining and freeing
    /// them. Held across the join; mu_ is NOT (the poll thread needs it).
    /// LOCK ORDER: teardown_mu_ → mu_. Never the reverse.
    std::mutex teardown_mu_;
    std::mutex mu_;                    ///< guards ONLY pending_, emit_/fault_/established_, started_, sink_sealed_ (inert_ is atomic)
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    /// Establishment-signal sink (rung 9c PR-6 item 1) — set once via
    /// set_established_sink() before start(), read WITHOUT mu_ from run() (the
    /// poll thread), exactly like emit_/fault_ above: the write happens-before
    /// the thread is spawned and the clear in stop() happens-after it joins, so
    /// there is never a concurrent access to race.
    SparkEstablishedFn established_;
    /// One-way latch (rung 9c PR-6 item 1): set true by start() being called,
    /// never cleared. See set_established_sink()'s own doc comment.
    bool sink_sealed_{false};
    std::deque<Cmd> pending_;
    bool started_{false};
    /// The system bus never opened at start() — permanent for this instance. THE
    /// COMMON CASE IS A CONTAINER: Dockerfile.agent ships libsystemd0, but a container
    /// has no system bus, so every containerized Linux agent lands here. Atomic so
    /// stats() (const, heartbeat thread) can publish it without mu_ — otherwise the
    /// mechanism stays REGISTERED and the fleet reads a service capability that can
    /// never watch anything (governance Gate-3 cross-platform / Gate-6 sre).
    std::atomic<bool> inert_{false};
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* bus_{nullptr};               ///< sd_bus* (void* keeps sd-bus.h out of the mechanism's shape)
    int wake_fd_{-1};

    // Poll-thread-confined (no lock): touched only from run(), and from stop()
    // after the thread has joined.
    bool bus_ok_{true};
    /// Whether the mechanism-wide Subscribe() call currently holds (H7, rung 9c
    /// PR-6 item 1) — set by the `subscribe` lambda in run(), on every call
    /// (initial connect AND every reopen). A per-unit PropertiesChanged match
    /// registering successfully means nothing for real Notification coverage
    /// without this: systemd never emits unit signals to a connection that
    /// never subscribed.
    bool subscribed_{false};
    std::unordered_map<std::string, std::unique_ptr<UnitWatch>> units_; ///< keyed by normalized unit name
    std::unordered_map<std::string, std::string> key_unit_;            ///< spark key -> normalized unit name
    /// spark key -> the SparkEngine-minted incarnation of its CURRENT
    /// subscription (rung 9c PR-6 item 1) — forward-only rebind on Cmd::Add
    /// (H1), erased in lockstep with key_unit_ on Cmd::Remove. This is the
    /// identity an established report is stamped with and the identity the
    /// engine's report_established checks before trusting one.
    std::unordered_map<std::string, SparkIncarnation> key_incarnation_;
};

} // namespace

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return std::make_unique<LinuxServiceMechanism>();
}

// #2012/#3840 PR-B3 restructured the WINDOWS SCM half only — Linux's
// mechanism has no detached workers of its own (its ONE poll thread already
// multiplexes every watch with no per-service blocking call to isolate), so
// this overload just accepts and ignores `f3_counter`, mirroring how the
// zero-argument form already behaves. Same object, same platform contract.
std::unique_ptr<ISparkMechanism>
make_service_mechanism(std::shared_ptr<std::atomic<std::size_t>> /*f3_counter*/) {
    return std::make_unique<LinuxServiceMechanism>();
}

bool set_service_test_controls_for_test(ISparkMechanism&, ServiceMechanismTestControls) {
    return false; // nothing to control on Linux — no probe lane exists here
}

std::optional<ServiceMechanismDebugCounters> service_debug_counters_for_test(const ISparkMechanism&) {
    return std::nullopt;
}

} // namespace yuzu::agent

#elif defined(_WIN32)

// ═══════════════════════════════════════════════════════════════════════════
// Windows: one SCM connection + one alertable-wait thread, multiplexing N
// service watches. NotifyServiceStatusChangeW delivers via APC to the
// REGISTERING thread, so every registration must happen on the one mechanism
// thread — the same fire-and-forget command queue as Linux, and for the same
// reason: the APC-processing thread IS the emit thread, so a synchronous
// watch() that waited on itself would deadlock on every inline re-arm.
//
// #2012/#3840 PR-B3: watch()/unwatch() were ALREADY O(1) queue pushes (see
// above) — the actual gap #3840 tracks is that OpenServiceW (the per-service
// establishment call) ran synchronously, head-of-line, on this ONE mechanism
// thread: a hung SCM call for one service delayed establishment, retries, AND
// APC dispatch for every OTHER watched service sharing this thread. Establish-
// ment is now isolated onto a bounded, F3-counted probe_lane_
// (SparkDetachedLane, spark_detached_call.hpp) — mirroring spark_registry.cpp's
// probe half, PROBE-ONLY, deliberately no drain-lane twin: unlike Registry's
// WaitForThreadpoolWaitCallbacks(...,TRUE), Service's teardown
// (CloseServiceHandle + a zero-timeout SleepEx(0,TRUE) APC pump) has no
// documented cross-thread reclamation ownership problem to isolate a close
// FOR, so isolating one anyway would trade a real, known hazard (Registry's
// #4181 same-type deadlock edge) for an invented one with no measured
// benefit. NotifyServiceStatusChangeW and CloseServiceHandle DELIBERATELY
// stay on this thread — the former by Win32's own thread-affinity
// requirement (see notify_cb's own comment), the latter by this design
// decision (see begin_probe()'s doc comment). Neither call's own blocking
// behavior is isolated by this restructure — only OpenServiceW establishment
// is. NotifyServiceStatusChangeW's measured cost is small (see
// docs/spark-rebuild-baselines/stage2-watch-establish-latency.md) but that is
// not a hard bound; CloseServiceHandle is the same LRPC transport as
// OpenServiceW and is UNVERIFIED either way — governance review (round 3)
// found no evidence CloseServiceHandle cannot itself hang under the same
// wedged-SCM condition #3840 exists to fix, so a wedge on close (four routine
// paths call it with a live handle: fired-scan re-arm-failure and
// MARKED_FOR_DELETE, Cmd::Remove's last-key teardown, and mechanism-thread
// exit) remains a residual of the ORIGINAL #3840 hazard shape, not one this
// restructure widens or introduces. This residual must not be read as
// "closed" by #3840.
// ═══════════════════════════════════════════════════════════════════════════

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp"    // detail::EventHandle
#include "spark_detached_call.hpp" // SparkDetachedLane, DetachedCall (#2012/#3840 PR-B3)

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <win_sc_handle.hpp> // shared yuzu::win::ScHandle — CloseServiceHandle RAII (#1822)
#include <win_str.hpp>       // shared yuzu::win wide<->UTF-8 helpers (#1681)

#pragma comment(lib, "advapi32.lib")

namespace yuzu::agent {
namespace {

using yuzu::win::to_wide;

// Identical charset gate to guard_service.cpp's local valid_service_name —
// defence-in-depth if a malformed name slips past the server-side authoring
// validator (the engine's own valid_unit_name check already rejects it first
// on this shared Linux/Windows token vocabulary, so this is redundant-safe).
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

// Locale-independent case fold for the service-name map key (SCM names are
// case-insensitive) — mirrors spark_file.cpp's fold_ci via LCMapStringEx.
std::wstring fold_ci(std::wstring_view s) {
    if (s.empty())
        return {};
    const int n = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr, 0);
    if (n <= 0)
        return std::wstring(s);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(), static_cast<int>(s.size()),
                    out.data(), n, nullptr, nullptr, 0);
    return out;
}

// All run-state transitions; deliberately NOT SERVICE_NOTIFY_CREATED / DELETED
// / DELETE_PENDING — those are SCM-handle-only flags that make
// NotifyServiceStatusChange fail with ERROR_INVALID_PARAMETER (87) on a
// SERVICE handle (found only in Windows UAT). Copied verbatim from
// guard_service.cpp, including the regression-guard static_assert.
constexpr DWORD kNotifyMask = SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED |
                              SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
                              SERVICE_NOTIFY_CONTINUE_PENDING | SERVICE_NOTIFY_PAUSE_PENDING |
                              SERVICE_NOTIFY_PAUSED;

static_assert((kNotifyMask & (SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED |
                              SERVICE_NOTIFY_DELETE_PENDING)) == 0,
              "kNotifyMask must not contain SCM-handle-only notify flags (CREATED/DELETED/"
              "DELETE_PENDING) — they fail with ERROR_INVALID_PARAMETER on a service handle");

constexpr std::uint64_t kAbsentRetryMs = 30000;

// ── PR-B3 (#2012/#3840): probe-lane policy constants. Initial policy
// references copied from spark_registry.cpp's probe half (its already-
// reviewed values), NOT measured Service capacity — retune after a real
// synthetic-storm measurement (tracked as a pre-flip follow-up, issue #4218). ──
using Clock = std::chrono::steady_clock;
constexpr std::size_t kServiceProbeLaneCap = 16; ///< concurrent detached probe workers
/// How long an accepted establishment/re-establishment obligation may stay
/// unresolved before the watch is reported faulted (mirrors
/// spark_registry.cpp's kRegHealthGrace) — a grace window, not a timeout that
/// abandons the probe; the probe itself keeps running past this point.
constexpr std::chrono::milliseconds kServiceHealthGrace{50};
/// First delay after a probe-lane admission refusal (cap full / launch
/// failed): D, 2D, 4D, ... capped at kServiceAdmissionBackoffCap, never
/// counted as a backend (OpenServiceW) attempt — mirrors
/// spark_registry.cpp's kRegAdmissionBackoffSeed/-Cap.
constexpr std::chrono::milliseconds kServiceAdmissionBackoffSeed{50};
constexpr std::chrono::milliseconds kServiceAdmissionBackoffCap{30'000};
/// Poll cadence while ANY watch has a probe outstanding — this mechanism
/// never wait_take()s on its own probe lane (it must keep pumping APCs for
/// every OTHER watch while one establishes), so the main loop's own wait
/// timeout is capped at this cadence whenever a probe is Pending, or a
/// completed-but-unpolled result could sit unnoticed until some UNRELATED
/// event next woke the thread. Provisional value, same order of magnitude as
/// spark_registry.cpp's kRegSweepCadence; a candidate for the same pre-flip
/// tuning pass as the constants above.
constexpr std::chrono::milliseconds kServicePollCadence{50};

/// How many main-loop passes a retired SvcWatch survives in `retiring_`
/// before being freed for real, once it stops observing any further APC
/// delivery. Reset back to this value any time a stale APC DOES land during
/// retirement, so a watch that keeps firing (an SCM that queued several
/// notifications before the close landed) never gets freed mid-delivery.
constexpr int kRetireGracePasses = 3;

/// Bounds the fired-flag fixed-point scan (see its call site in run()) so a
/// pathologically flapping service can't monopolize the mechanism thread.
constexpr int kMaxFiredScanPasses = 16;

bool is_pending(DWORD s) {
    return s == SERVICE_START_PENDING || s == SERVICE_STOP_PENDING ||
           s == SERVICE_CONTINUE_PENDING || s == SERVICE_PAUSE_PENDING;
}

ServiceRunState map_terminal(DWORD s) {
    switch (s) {
    case SERVICE_RUNNING: return ServiceRunState::Running;
    case SERVICE_PAUSED:  return ServiceRunState::Paused;
    default:              return ServiceRunState::Stopped; // SERVICE_STOPPED (pending handled earlier)
    }
}

struct PendingEmit {
    std::string key;
    ServiceRunState state;
    /// `key`'s subscription epoch (`key_epoch_[key]`) at push time
    /// (#2012/#3840 PR-B3 review, round 2: `probe_gen` was the wrong
    /// identity here — it tracks PROBE launches, not subscription
    /// lifetime, so a same-watch re-arm-failure retry after a state was
    /// already staged could drop a real, already-true transition, and a
    /// fold_ci-coalesced same-object Remove+Add could fail to drop an
    /// actually-stale one). `drop_stale()` compares this against `key`'s
    /// CURRENT epoch right before dispatch, so a same-tick remove+re-add
    /// of `key` (staged under the OLD subscription) is discarded, while a
    /// same-watch probe relaunch that does NOT touch `key`'s own
    /// subscription lifetime never invalidates already-staged data.
    std::uint64_t key_epoch{0};
};
struct PendingFault {
    std::string key;
    bool faulted;
    std::string reason;
    std::uint64_t key_epoch{0}; ///< see PendingEmit::key_epoch
};
/// A staged establishment-signal report (rung 9c PR-6 item 1) — see
/// SparkEstablishedFn's own doc comment for the field semantics. `key_epoch`
/// is PendingEmit::key_epoch's twin, checked by the SAME drop_stale() this
/// key's emits/faults already go through — Windows's async establishment
/// path has the same same-tick staleness window those two guard against.
struct PendingEstablished {
    std::string key;
    SparkIncarnation incarnation;
    std::chrono::steady_clock::time_point at;
    SparkCoverage coverage;
    std::uint64_t key_epoch{0}; ///< see PendingEmit::key_epoch
};

/// Pending-operation state of one watch's establishment — INDEPENDENT of its
/// health/armed status (mirrors spark_registry.cpp's ProbeState). Idle: no
/// establishment outstanding (either healthy+registered, or a definite
/// terminal Stopped needing only its next_retry poll). Pending: a probe is
/// reserved or in flight on probe_lane_ (`call` engaged once launched).
/// Deferred: a (re)probe will be launched at `next_retry` — covers admission
/// backoff, a backend (OpenServiceW/Notify) failure's retry, and an absent-
/// service re-poll (there is no notification for "a not-yet-existing service
/// now exists").
enum class ProbeState : std::uint8_t { Idle, Pending, Deferred };

/// Shared, ref-counted ownership of the mechanism's OpenSCManagerW handle, so
/// a detached probe holding a copy keeps the SCM connection alive even if
/// stop() runs (and would otherwise close the mechanism's own handle) while
/// that probe is still parked — mirrors spark_registry.cpp's PoolCore lease
/// pattern (#2012/#3840 PR-B1). Concurrent OpenServiceW calls against the SAME
/// hSCManager from different threads are a documented-safe SCM RPC pattern
/// (every Windows service-control tool that enumerates+queries concurrently
/// relies on it); this struct only owns the CLOSE, it never serialises
/// callers against each other.
struct ScmCore {
    SC_HANDLE handle{nullptr};
    ScmCore() = default;
    ScmCore(const ScmCore&) = delete;
    ScmCore& operator=(const ScmCore&) = delete;
    ~ScmCore() {
        if (handle)
            ::CloseServiceHandle(handle);
    }
};

/// What one detached establishment probe produced. Every OS resource it
/// opened is owned here (RAII), so a discarded result closes itself on
/// whichever thread drops it — never under any lock by construction of the
/// call sites (this mechanism has no lock guarding svcs_/retiring_ at all;
/// see the class comment). `scm` is declared FIRST so it outlives `svc` on
/// destruction (a service handle opened against a connection is logically
/// scoped by that connection, though CloseServiceHandle itself does not
/// require ordering — this mirrors ProbeResult's own ordering discipline in
/// spark_registry.cpp for the same defensive reason). nothrow-move by
/// construction (SparkDetachedLane::launch() static_asserts it).
struct ServiceProbeResult {
    std::shared_ptr<ScmCore> scm;
    yuzu::win::ScHandle svc; ///< opened SERVICE_QUERY_STATUS handle; empty on failure
    bool ok{false};
    DWORD err{0};
};
static_assert(std::is_nothrow_move_constructible_v<ServiceProbeResult>);

using ServiceProbeHook = std::function<void(std::wstring_view name)>;

/// The detached probe: OpenServiceW only. NotifyServiceStatusChangeW is
/// DELIBERATELY not called here — Win32 requires the REGISTERING thread to
/// pump the alertable wait that delivers its APC (this mechanism's own
/// notify_cb/WaitForSingleObjectEx(...,TRUE) comment), so a detached worker
/// that registered and then exited immediately could never receive one.
/// Registration happens on the mechanism thread, in resolve_probe(), exactly
/// as it did synchronously before PR-B3.
struct ServiceProbeJob {
    std::shared_ptr<ScmCore> scm;
    std::wstring name; ///< original (unfolded) service name — OpenServiceW's own lookup key
    std::shared_ptr<const ServiceProbeHook> hook; ///< test seam; may be null

    ServiceProbeResult operator()() {
        ServiceProbeResult r;
        r.scm = scm;
        if (hook && *hook)
            (*hook)(name); // test seam: may park (a "hung SCM") or throw
        SC_HANDLE h = ::OpenServiceW(scm->handle, name.c_str(), SERVICE_QUERY_STATUS);
        if (!h) {
            r.err = ::GetLastError();
            r.ok = false;
            return r;
        }
        r.svc.reset(h);
        r.ok = true;
        return r;
    }
};
static_assert(std::is_nothrow_move_constructible_v<ServiceProbeJob>);

/// One watched Windows service, mechanism-thread-confined. `notify` MUST
/// outlive each one-shot registration (the SCM writes into it via APC);
/// `pContext` points back at this struct so the APC callback can identify
/// which service fired among N multiplexed on the one thread.
struct SvcWatch {
    // RAII for pszServiceNames: teardown_watch()/the reap loop free it on
    // their own paths, but WAIT_FAILED and the run()-exit catch blocks tear
    // svcs_/retiring_ down without ever reaping a still-fired entry first —
    // this destructor makes every teardown path safe uniformly, rather than
    // relying on the reap loop alone (governance re-review LOW finding).
    ~SvcWatch() {
        if (notify.pszServiceNames)
            LocalFree(notify.pszServiceNames);
    }

    std::wstring name; ///< folded (case-insensitive); map key in svcs_
    std::set<std::string> keys;
    yuzu::win::ScHandle svc; ///< SERVICE_QUERY_STATUS
    SERVICE_NOTIFYW notify{};
    bool registered{false};
    // APC-filled; same-thread invariant (guard_service.cpp's WatchCtx precedent)
    // — the callback runs only during THIS thread's alertable wait, never
    // concurrently with the rest of the loop.
    bool fired{false};
    DWORD notify_status{ERROR_SUCCESS};
    DWORD current_state{0};
    std::optional<ServiceRunState> last;
    bool faulted{false};
    /// The reason `faulted` was last set (or "recovered" once cleared) —
    /// governance review: a key coalescing onto an already-faulted watch was
    /// previously handed a hardcoded "OpenService failed" regardless of the
    /// watch's actual cause (could be a Notify-registration failure or a
    /// health-grace timeout instead); storing the real reason here, mirroring
    /// spark_registry.cpp's/spark_file.cpp's RegWatch::fault_reason /
    /// FileWatch::fault_reason, lets the coalescing-Add branch hand every
    /// subscriber the same, accurate explanation.
    const char* fault_reason{""};
    std::chrono::steady_clock::time_point next_retry{};
    /// >0 while parked in `retiring_` awaiting quiescence before real free;
    /// 0 for a live (non-retiring) watch. See `retiring_`'s doc comment.
    int retire_grace{0};

    // ── PR-B3 (#2012/#3840): async establishment state ─────────────────────
    ProbeState probe{ProbeState::Idle};
    /// Engaged from an admitted launch until resolve_probe() consumes it.
    std::optional<DetachedCall<ServiceProbeResult>> call;
    /// When the CURRENT obligation was accepted — set ONLY on a fresh
    /// obligation (Idle->Pending: a brand-new Add, or a live watch's re-arm
    /// after full success), NEVER reset by a retry of an already-Deferred
    /// obligation (mirrors spark_registry.cpp's accepted_at: "grace runs
    /// from the MOST RECENT ACCEPTANCE, not the most recent attempt" — a
    /// governance review finding: resetting on every retry let a
    /// persistently lane-rejected watch push its own grace deadline forward
    /// forever, so it never faulted).
    Clock::time_point accepted_at{};
    bool grace_counted{false};
    /// Admission (lane-rejection) retry count, for the backoff doubling —
    /// distinct from backend (OpenServiceW/Notify) failures, which retry on
    /// the existing fixed kAbsentRetryMs cadence.
    unsigned admission_attempts{0};
    /// Last-STAGED establishment coverage (rung 9c PR-6 item 1) — the
    /// per-watch cache a coalescing/adopting key's unconditional report reads
    /// back; written by every row of the coverage table, never read for any
    /// gating decision.
    SparkCoverage coverage{SparkCoverage::None};
};

void CALLBACK notify_cb(PVOID param) {
    auto* n = static_cast<SERVICE_NOTIFYW*>(param);
    auto* w = static_cast<SvcWatch*>(n->pContext);
    w->notify_status = n->dwNotificationStatus;
    w->current_state = n->ServiceStatus.dwCurrentState;
    w->fired = true;
}

/// Windows Service spark mechanism: ONE SCM connection + ONE alertable-wait
/// thread service every armed service watch (N service handles are
/// unavoidable — NotifyServiceStatusChangeW needs one per service). Same
/// fire-and-forget command queue as the Linux mechanism, for the identical
/// inline-re-arm-safety reason (see the file header comment).
class WindowsServiceMechanism final : public ISparkMechanism {
public:
    /// `f3_counter` (may be null) is the agent-lifetime orphan-exit counter
    /// every detached probe this mechanism launches is admitted against
    /// (#2012/#3840 PR-B3, F3) — mirrors WindowsRegistryMechanism's
    /// constructor. probe_lane_ is constructed here, once, and keeps its
    /// identity across start()/stop() (SparkDetachedLane is non-movable).
    explicit WindowsServiceMechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter)
        : probe_lane_(std::move(f3_counter), kServiceProbeLaneCap) {}
    ~WindowsServiceMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        // One-way seal (rung 9c PR-6 item 1): start() being CALLED is what
        // seals the establishment sink, whether or not this call does
        // anything else — set first, before the idempotent early-return, so
        // a repeat start() can never re-open the window. Never cleared by
        // stop(): SparkEngine itself is single-shot (spark_engine.hpp's own
        // header doc), so no production caller ever needs to re-arm the sink
        // after a stop().
        sink_sealed_ = true;
        if (started_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        // Construct the lease EMPTY first, acquire the OS handle into it only
        // after construction succeeds — mirrors spark_registry.cpp's PoolCore
        // start() ordering. If make_shared's own allocation throws, nothing
        // has been acquired yet, so nothing leaks; if OpenSCManagerW itself
        // fails, `core` (still empty) destructs harmlessly below.
        auto core = std::make_shared<ScmCore>();
        core->handle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!core->handle) {
            spdlog::warn("spark_service: OpenSCManager failed (err={}) — service sparks inert on "
                         "this host",
                         GetLastError());
            scm_ok_ = false;
            started_inert_.store(true, std::memory_order_release);
            started_ = true;
            return;
        }
        wake_.reset(CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr));
        if (!wake_) {
            // `core` destructs here, closing the just-opened SCM handle via ~ScmCore.
            scm_ok_ = false;
            started_inert_.store(true, std::memory_order_release);
            started_ = true;
            return;
        }
        scm_core_ = std::move(core);
        scm_ok_ = true;
        started_inert_.store(false, std::memory_order_release);
        stop_.store(false, std::memory_order_release);
        thread_ = std::thread([this] { run(); });
        started_ = true;
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        // The engine never calls this overload in production (it always calls
        // watch_incarnation() below) — kept for direct/test callers that predate
        // the establishment signal. kNoSparkIncarnation is a valid, harmless
        // identity: nothing rejects it, it simply never matches a real engine
        // incarnation.
        return watch_incarnation(key, params, kNoSparkIncarnation);
    }

    std::expected<void, std::string> watch_incarnation(const std::string& key,
                                                        const SparkParams& params,
                                                        SparkIncarnation incarnation) override {
        const auto* sp = std::get_if<ServiceSparkParams>(&params);
        if (!sp)
            return std::unexpected("service mechanism: params are not ServiceSparkParams");
        if (!valid_service_name(sp->service_name))
            return std::unexpected("service mechanism: invalid service name '" +
                                   sp->service_name + "'");
        std::lock_guard lk(mu_);
        if (!started_)
            return std::unexpected("service mechanism not started");
        if (!scm_ok_)
            return std::unexpected("SCM unavailable — service sparks unsupported on this host");
        pending_.push_back(Cmd{Cmd::Add, key, to_wide(sp->service_name), incarnation});
        wake_signal();
        return {};
    }

    bool set_established_sink(SparkEstablishedFn sink) override {
        std::lock_guard lk(mu_);
        if (sink_sealed_)
            return false;
        established_ = std::move(sink);
        return true;
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        if (!started_ || !scm_ok_)
            return;
        pending_.push_back(Cmd{Cmd::Remove, key, {}});
        wake_signal();
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!started_)
                return; // idempotent
            started_ = false;
        }
        if (thread_.joinable()) {
            stop_.store(true, std::memory_order_release);
            wake_signal();
            thread_.join();
        }
        // The mechanism thread has joined — every SvcWatch's registration was
        // already torn down by the thread's own exit path (see run(), and its
        // duplication into both catch blocks); svcs_/retiring_ are now safe
        // to touch without a lock.
        svcs_.clear();
        retiring_.clear();
        key_svc_.clear();
        // Drops the mechanism's own reference; a probe still parked on
        // probe_lane_ (the F3-counted orphan case) holds its own ScmCore
        // copy via ServiceProbeJob/ServiceProbeResult, so the SCM connection
        // itself stays open until that probe's own result is disposed —
        // never closed out from under it (#2012/#3840 PR-B3).
        scm_core_.reset();
        wake_.reset();
        std::lock_guard lk(mu_);
        emit_ = nullptr;
        fault_ = nullptr;
        // established_ is cleared here too (nulled only after the mechanism
        // thread has joined, mirroring emit_/fault_) but sink_sealed_ is
        // DELIBERATELY left set — an ordinary stop() reports NOTHING further
        // (R4: matches subscription_health's stale-after-stop precedent), and
        // the seal itself is one-way for this instance's life.
        established_ = nullptr;
        scm_ok_ = false;
        started_inert_.store(false, std::memory_order_release);
        pending_.clear();
    }

    /// See the Linux twin: this mechanism tracks none of the File-mechanism counters,
    /// but it MUST publish `inert` so an SCM-denied service mechanism is distinguishable
    /// from a healthy idle one. `started_inert_` here is ENTIRELY boot-time (#4685) —
    /// Windows Service has no runtime-inert concept either — so `.boot_inert` is the
    /// same atomic, not a separate flag.
    [[nodiscard]] SparkMechanismStats stats() const override {
        const bool boot = started_inert_.load(std::memory_order_acquire);
        return {.inert = boot, .boot_inert = boot};
    }

private:
    struct Cmd {
        enum Op { Add, Remove } op;
        std::string key;
        std::wstring name; // only meaningful for Add
        SparkIncarnation incarnation{kNoSparkIncarnation}; // only meaningful for Add
    };

    void wake_signal() {
        if (wake_)
            SetEvent(wake_.get());
    }

    // ── tunables (atomics so the test seam can override without a rebuild,
    //    mirrors spark_registry.cpp's identical pattern) ─────────────────────
    [[nodiscard]] std::chrono::milliseconds health_grace() const {
        return std::chrono::milliseconds(health_grace_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds admission_seed() const {
        return std::chrono::milliseconds(admission_seed_ms_.load(std::memory_order_relaxed));
    }

    // ── Mechanism-thread-confined helpers ───────────────────────────────────

    // Cancels the outstanding registration (closing the handle invalidates it),
    // drains any APC already queued for it via an alertable no-op wait (the
    // SERVICE_NOTIFYW UAF hazard — a queued APC must never run after the
    // struct is freed), then releases the name buffer.
    void teardown_watch(SvcWatch& w) {
        w.svc.reset();
        SleepEx(0, TRUE); // drain any already-queued APC for this registration
        if (w.notify.pszServiceNames) {
            LocalFree(w.notify.pszServiceNames);
            w.notify.pszServiceNames = nullptr;
        }
    }

    // Kicks off (re-)establishment for `w`: cancels any live registration/
    // handle (cheap, synchronous — no OS call here can block for long), then
    // launches OpenServiceW on probe_lane_ and returns IMMEDIATELY — never
    // blocks on the OS call itself (#2012/#3840 PR-B3; before this, this
    // function — then named arm_watch — made the OpenServiceW call inline,
    // synchronously, head-of-line on this mechanism's one thread, per the
    // file header comment). Every call site only reaches here from
    // ProbeState::Idle or a due ProbeState::Deferred retry, so at most one
    // probe is ever outstanding per watch; the guard below is defense-in-
    // depth against that invariant being violated by a future change, not a
    // path exercised today.
    void begin_probe(SvcWatch& w, std::vector<PendingEstablished>& established) {
        if (w.probe == ProbeState::Pending) {
            spdlog::error("spark_service: begin_probe() called with a probe already outstanding "
                         "for a watched service — ignoring (an admission invariant was violated)");
            return;
        }
        teardown_watch(w);
        // Unconditional (rung 9c PR-6 item 1, round-4 MF1): tearing the old
        // registration down genuinely means coverage is None until
        // re-established below, whether that happens synchronously-feeling
        // (probe launches, resolves later) or fails to launch at all.
        stage_coverage(w, SparkCoverage::None, established);

        // A retry of an obligation already Deferred (admission backoff OR a
        // resolved backend/absent retry cadence) is NOT a fresh obligation —
        // accepted_at/grace_counted must NOT reset here (#2012/#3840 PR-B3
        // review): resetting on every retry let a persistently-rejected
        // watch push its own grace deadline forward forever, starving the
        // health-grace fault this field exists to produce. Only Idle->Pending
        // (a brand-new Add, or a live watch's re-arm after full success) is a
        // fresh obligation. Mirrors spark_registry.cpp: "grace runs from the
        // MOST RECENT ACCEPTANCE, not the most recent attempt."
        const bool fresh_obligation = (w.probe != ProbeState::Deferred);

        std::shared_ptr<const ServiceProbeHook> hook;
        {
            // See apply_test_controls()'s own comment — probe_hook_ needs
            // mu_ specifically because, unlike spark_registry.cpp, nothing
            // else on this thread's path already holds it.
            std::lock_guard lk(mu_);
            hook = probe_hook_;
        }

        // Construct the job (copies w.name) and launch it BEFORE mutating any
        // watch state (#2012/#3840 PR-B3 review): the lane's OWN allocation
        // failures already convert to LaunchFailed internally, but building
        // the ServiceProbeJob aggregate argument itself runs in THIS frame,
        // outside that containment — an uncaught throw here would propagate
        // into run()'s outer catch and tear down the WHOLE mechanism over one
        // watch's transient allocation failure. Contain it exactly like an
        // admission rejection: this watch's obligation is retried, nothing
        // else is affected.
        bool launched = false;
        DetachedLaunch status = DetachedLaunch::LaunchFailed;
        try {
            auto lr = probe_lane_.launch(ServiceProbeJob{scm_core_, w.name, std::move(hook)});
            status = lr.status;
            if (status == DetachedLaunch::Launched) {
                w.call = std::move(lr.call);
                launched = true;
            }
        } catch (...) {
            status = DetachedLaunch::LaunchFailed;
        }

        if (fresh_obligation) {
            w.accepted_at = Clock::now();
            w.grace_counted = false;
        }

        if (launched) {
            w.probe = ProbeState::Pending;
            // Clear a stale due-in-the-past deadline (#2012/#3840 PR-B3
            // review): left unchanged, a Deferred->Pending transition kept
            // its just-expired next_retry, which the wait-timeout computation
            // below (Pending or not) keeps seeing as a past deadline and
            // clamps the alertable wait to 0 — a busy-spin for the entire
            // duration of a hung OpenServiceW (#3840's own incident class).
            // The kServicePollCadence "any_pending" cap already bounds a
            // Pending watch's polling interval; this deadline would only
            // ever make that WORSE, never better.
            w.next_retry = {};
            probe_launched_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // Admission refused (lane cap), the OS refused the worker thread, or
        // job construction itself threw — never a backend (OpenServiceW)
        // attempt, so this is NOT a fault edge: the obligation is retained
        // and retried on a short doubling backoff, distinct from a genuine
        // backend failure's fixed kAbsentRetryMs cadence below.
        if (status == DetachedLaunch::Rejected)
            probe_admission_rejected_.fetch_add(1, std::memory_order_relaxed);
        else
            probe_launch_failed_.fetch_add(1, std::memory_order_relaxed);
        w.probe = ProbeState::Deferred;
        ++w.admission_attempts;
        w.next_retry = Clock::now() + doubled(admission_seed(), w.admission_attempts,
                                              kServiceAdmissionBackoffCap);
    }

    // Stage an establishment report for EVERY key on `w`, UNCONDITIONALLY
    // (rung 9c PR-6 item 1, round-4 MF1: every row of the coverage table
    // stages regardless of whether this is an "edge" — the engine is
    // idempotent on repeated coverage and first-wins on established_at, so a
    // redundant report costs nothing but a wasted round trip). `w.coverage`
    // is written here as the LAST-STAGED value and read only by a later
    // coalescing/adopting key's own unconditional report. Fresh Clock::now()
    // taken HERE, at the statement — never a loop-top local (MF4: a stale
    // `now` could stamp established_at before armed_at).
    void stage_coverage(SvcWatch& w, SparkCoverage cov, std::vector<PendingEstablished>& out) {
        w.coverage = cov;
        for (const auto& k : w.keys)
            out.push_back({k, key_incarnation_.at(k), Clock::now(), cov, key_epoch_.at(k)});
    }

    // Connection-wide coverage loss — every call site that discovers the
    // mechanism thread itself is about to die (WAIT_FAILED) calls this for
    // every currently-watched key, unconditionally (never edge-gated, unlike
    // the fault channel's own per-watch faulted check).
    void drop_coverage_all(std::vector<PendingEstablished>& out) {
        for (auto& [name, wp] : svcs_)
            stage_coverage(*wp, SparkCoverage::None, out);
    }

    // base * 2^(attempts-1), saturating at cap (attempts >= 1) — copied
    // verbatim from spark_registry.cpp's own already-reviewed helper rather
    // than a bit-shift reimplementation, deliberately: this restructure
    // cannot be compiled/verified on this box (Windows-only), so matching
    // proven, already-compiled arithmetic exactly is lower-risk than a new
    // expression whose duration/rep type inference has not been checked
    // against a real MSVC build.
    static std::chrono::milliseconds doubled(std::chrono::milliseconds base, unsigned attempts,
                                             std::chrono::milliseconds cap) {
        std::chrono::milliseconds d = base;
        for (unsigned i = 1; i < attempts && d < cap; ++i)
            d *= 2;
        return std::min(d, cap);
    }

    // Consumes a completed establishment probe for `w` (called only from
    // run()'s completion-poll scan, immediately after it try_take()s
    // w.call). (Re)registers NotifyServiceStatusChangeW on THIS thread if
    // OpenServiceW succeeded — exactly as arm_watch did synchronously before
    // PR-B3 (Win32 requires the registering thread to pump the alertable
    // wait that delivers the APC; see ServiceProbeJob's own doc comment) —
    // or classifies the open failure (absent vs backend) and schedules the
    // existing kAbsentRetryMs retry, byte-for-byte the same classification
    // and cadence as before this restructure. `ERROR_SERVICE_DOES_NOT_EXIST`
    // is a genuine terminal Stopped, never a fault; every other open/
    // register failure is a fault (never a false Stopped — the UP-4 class
    // guard_systemd.cpp's ResolveResult split guards against on Linux).
    void resolve_probe(SvcWatch& w, DetachedResult<ServiceProbeResult> r,
                       std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults,
                       std::vector<PendingEstablished>& established) {
        w.probe = ProbeState::Idle;
        if (!r.has_value()) {
            // WorkerThrew or ResultAllocFailed — contained inside the lane;
            // the OS call never reached a definite outcome. Treated as a
            // backend failure (never a false Stopped), same retry cadence as
            // a genuine OpenServiceW error below.
            probe_backend_failed_.fetch_add(1, std::memory_order_relaxed);
            // Split into two distinct consumer-visible reasons (governance
            // review: was one collapsed string here, unlike
            // spark_registry.cpp's/spark_file.cpp's "probe threw" vs
            // "probe result could not be boxed" split) - the log line already
            // carried the distinction, only the fault channel didn't.
            const char* reason = r.error() == DetachedCallError::WorkerThrew
                                     ? "OpenService probe threw"
                                     : "OpenService probe result could not be boxed";
            spdlog::warn("spark_service: establishment probe for a watched service did not "
                        "complete cleanly ({})",
                        r.error() == DetachedCallError::WorkerThrew ? "threw"
                                                                    : "result alloc failed");
            if (!w.faulted) {
                w.faulted = true;
                w.fault_reason = reason;
                for (const auto& k : w.keys)
                    faults.push_back({k, true, reason, key_epoch_.at(k)});
            }
            stage_coverage(w, SparkCoverage::None, established);
            // ProbeState::Deferred (not Idle) — a due next_retry with probe
            // still Idle would never be picked up by run()'s retry scan,
            // which gates specifically on Deferred (#2012/#3840 PR-B3, found
            // in this session's own review before landing: the ONLY prior
            // arm_watch()-based design had no ProbeState to get out of sync).
            w.probe = ProbeState::Deferred;
            // Already resolved (definitively, if unsuccessfully) — the retry
            // scan's Deferred grace-check exists to surface an obligation
            // that never even got a chance to run, not to re-grace one that
            // already has a classified outcome and its own fault signal
            // above (#2012/#3840 PR-B3 review).
            w.grace_counted = true;
            w.next_retry = Clock::now() + std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        ServiceProbeResult& res = *r;
        if (!res.ok) {
            probe_backend_failed_.fetch_add(1, std::memory_order_relaxed);
            if (res.err == ERROR_SERVICE_DOES_NOT_EXIST) {
                set_terminal(w, ServiceRunState::Stopped, emits);
                if (w.faulted) {
                    w.faulted = false;
                    w.fault_reason = "recovered";
                    for (const auto& k : w.keys)
                        faults.push_back({k, false, "recovered", key_epoch_.at(k)});
                }
                stage_coverage(w, SparkCoverage::Poll, established);
            } else {
                spdlog::warn("spark_service: OpenService failed for a watched service (err={})",
                             res.err);
                if (!w.faulted) {
                    w.faulted = true;
                    w.fault_reason = "OpenService failed";
                    for (const auto& k : w.keys)
                        faults.push_back({k, true, "OpenService failed", key_epoch_.at(k)});
                }
                stage_coverage(w, SparkCoverage::None, established);
            }
            // Deferred, not Idle — an absent service needs its periodic
            // re-poll picked up by the retry scan too; see the comment above.
            w.probe = ProbeState::Deferred;
            // See the grace_counted comment on the branch above — this
            // outcome (including the deliberately-non-faulted "genuinely
            // absent" case) is already definitively classified.
            w.grace_counted = true;
            w.next_retry = Clock::now() + std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        w.svc = std::move(res.svc);
        w.notify = SERVICE_NOTIFYW{};
        w.notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        w.notify.pfnNotifyCallback = &notify_cb;
        w.notify.pContext = &w;
        const DWORD rc = NotifyServiceStatusChangeW(w.svc.get(), kNotifyMask, &w.notify);
        if (rc != ERROR_SUCCESS) {
            spdlog::warn("spark_service: NotifyServiceStatusChange failed (rc={}) — degraded "
                         "re-arm in {}ms",
                         rc, kAbsentRetryMs);
            w.svc.reset();
            if (!w.faulted) {
                w.faulted = true;
                w.fault_reason = "NotifyServiceStatusChange failed";
                for (const auto& k : w.keys)
                    faults.push_back({k, true, "NotifyServiceStatusChange failed", key_epoch_.at(k)});
            }
            stage_coverage(w, SparkCoverage::None, established);
            // Deferred, not Idle — see the comment on the two branches above.
            w.probe = ProbeState::Deferred;
            // See the grace_counted comment above — already definitively
            // classified (faulted), nothing left for grace to surface.
            w.grace_counted = true;
            w.next_retry = Clock::now() + std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        // Registered — the immediate callback (and every later terminal
        // transition) delivers as an APC at the next alertable wait.
        // Resets ONLY on this full-success path, mirroring
        // spark_registry.cpp's commit_locked() — a successfully-LAUNCHED
        // probe that then failed at the OS call itself does NOT reset the
        // admission backoff schedule, only a genuine establishment does.
        w.admission_attempts = 0;
        if (w.faulted) {
            w.faulted = false;
            w.fault_reason = "recovered";
            for (const auto& k : w.keys)
                faults.push_back({k, false, "recovered", key_epoch_.at(k)});
        }
        // Notification coverage, timestamped right after this ERROR_SUCCESS —
        // live OS-level notification genuinely exists for this watch from this
        // statement (H10, rung 9c PR-6 item 1).
        stage_coverage(w, SparkCoverage::Notification, established);
        w.next_retry = {}; // event-driven now; no polling backstop needed while armed
    }

    // Marks `w` faulted if its CURRENT establishment obligation has been
    // outstanding past kServiceHealthGrace without resolving — the probe
    // itself keeps running past this point; this only surfaces the delay to
    // consumers instead of leaving them silently waiting (mirrors
    // spark_registry.cpp's grace_check_locked). Called while w.probe==Pending
    // with no result yet available, OR while w.probe==Deferred and not yet
    // due (#2012/#3840 PR-B3 review) — the Deferred call site only reaches a
    // watch that is STILL AWAITING ITS FIRST RESOLUTION (admission-rejected,
    // never launched a probe at all): resolve_probe() sets grace_counted on
    // every Deferred it itself produces from a DEFINITIVE outcome, so this
    // never re-fires for an already-classified absent/backend-failed watch.
    void grace_check(SvcWatch& w, Clock::time_point now, std::vector<PendingFault>& faults) {
        if (w.grace_counted || now - w.accepted_at <= health_grace())
            return;
        w.grace_counted = true;
        if (!w.faulted) {
            w.faulted = true;
            w.fault_reason = "service watch establishment pending past grace";
            health_edges_.fetch_add(1, std::memory_order_relaxed);
            for (const auto& k : w.keys)
                faults.push_back(
                    {k, true, "service watch establishment pending past grace", key_epoch_.at(k)});
        }
    }

    void set_terminal(SvcWatch& w, ServiceRunState mapped, std::vector<PendingEmit>& out) {
        if (w.last && *w.last == mapped)
            return;
        w.last = mapped;
        for (const auto& k : w.keys)
            out.push_back({k, mapped, key_epoch_.at(k)});
    }

    // Drops any staged emit/fault whose `key_epoch` no longer matches `key`'s
    // CURRENT subscription epoch (#2012/#3840 PR-B3 review, round 2) — closes
    // the same-tick window where a probe/grace/fired-scan result is staged
    // BEFORE the command drain processes a Remove+Add of that same key: the
    // stale entry would otherwise be delivered to the REPLACEMENT
    // subscription instead of being discarded (the kickoff doc's own
    // required stale-generation guard, ~/.claude/plans/spark-2012-3840-prb3-
    // service-KICKOFF.md:254-255).
    //
    // DELIBERATELY keyed on the per-KEY subscription epoch (`key_epoch_`),
    // NOT `SvcWatch::probe_gen` — an earlier version of this check used
    // probe_gen and was wrong in both directions, found in this same
    // adversarial-review round: (1) probe_gen is bumped by ANY begin_probe()
    // call on a watch, including a re-arm-failure retry that has nothing to
    // do with `key`'s own subscription lifetime — staging a real, already-
    // true state transition and then launching such a retry in the SAME
    // iteration (fired-scan: set_terminal() then begin_probe() when re-arm
    // fails) would have dropped that already-observed, never-to-recur
    // transition. (2) case-insensitive name coalescing means two DIFFERENT
    // keys can share one SvcWatch (and therefore one probe_gen); a same-tick
    // Remove+Add of ONE of those keys leaves the shared watch's probe_gen
    // completely unchanged, so the old check would have let a genuinely
    // stale entry straight through — the exact leak this function exists to
    // close. `key_epoch_` tracks neither of those unrelated events: it
    // bumps ONLY when `key_svc_` actually gains a fresh entry for `key`
    // (see the Add-drain branch below), which is precisely "is this still
    // the subscription this entry was produced for." Only called right
    // before the ONE dispatch() that follows a command drain in the same
    // iteration (other dispatch() call sites have no drain in between, so
    // nothing to filter).
    template <typename T>
    void drop_stale(std::vector<T>& v) {
        v.erase(std::remove_if(v.begin(), v.end(),
                               [this](const T& e) {
                                   if (!key_svc_.contains(e.key))
                                       return true; // no longer watched at all
                                   auto kit = key_epoch_.find(e.key);
                                   return kit == key_epoch_.end() ||
                                          kit->second != e.key_epoch;
                               }),
                v.end());
    }

    void dispatch(std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults,
                 std::vector<PendingEstablished>& established) {
        // Established first (no ordering requirement from the plan; picked so a
        // consumer observing a Fired/Faulted event for a key can already see its
        // establishment report land no later than the same dispatch batch).
        for (auto& e : established)
            if (established_)
                established_(e.key, e.incarnation, e.at, e.coverage);
        established.clear();
        for (auto& e : emits)
            if (emit_)
                emit_(e.key, SparkData{ServiceSparkData{e.state}});
        emits.clear();
        for (auto& f : faults)
            if (fault_)
                fault_(f.key, f.faulted, f.reason);
        faults.clear();
    }

    void run() try {
        std::vector<PendingEmit> emits;
        std::vector<PendingFault> faults;
        std::vector<PendingEstablished> established;

        while (!stop_.load(std::memory_order_acquire)) {
            // Compute the wait timeout: soonest per-service retry deadline,
            // capped by kServicePollCadence whenever any probe is Pending —
            // this mechanism never wait_take()s on probe_lane_ (it must keep
            // pumping APCs for every OTHER watch while one establishes), so
            // without this cap a completed-but-unpolled probe result could
            // sit unnoticed until some UNRELATED command/APC next woke this
            // thread (#2012/#3840 PR-B3).
            const auto now = std::chrono::steady_clock::now();
            bool have_deadline = false;
            auto next = now;
            bool any_pending = false;
            for (auto& [name, wp] : svcs_) {
                if (wp->probe == ProbeState::Pending)
                    any_pending = true;
                if (wp->probe == ProbeState::Deferred && !wp->grace_counted) {
                    // An admission-rejected obligation may not be due for
                    // retry (a doubling backoff) well past when its grace
                    // deadline elapses — without this, the thread could sleep
                    // straight through it and only notice on some unrelated
                    // wake (#2012/#3840 PR-B3 review, mirrors
                    // spark_registry.cpp's next_wake_locked).
                    const auto grace_deadline = wp->accepted_at + health_grace();
                    if (!have_deadline || grace_deadline < next) {
                        next = grace_deadline;
                        have_deadline = true;
                    }
                }
                if (wp->next_retry == std::chrono::steady_clock::time_point{})
                    continue; // event-driven, no polling backstop
                if (!have_deadline || wp->next_retry < next) {
                    next = wp->next_retry;
                    have_deadline = true;
                }
            }
            if (any_pending) {
                const auto poll_deadline = now + kServicePollCadence;
                if (!have_deadline || poll_deadline < next) {
                    next = poll_deadline;
                    have_deadline = true;
                }
            }
            DWORD timeout = INFINITE;
            if (have_deadline) {
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next - now)
                                    .count();
                timeout = static_cast<DWORD>(std::clamp<long long>(ms, 0, 0xFFFFFFFEll));
            }

            const DWORD r = WaitForSingleObjectEx(wake_.get(), timeout, /*alertable=*/TRUE);
            if (stop_.load(std::memory_order_acquire))
                break;

            if (r != WAIT_OBJECT_0 && r != WAIT_TIMEOUT && r != WAIT_IO_COMPLETION) {
                // WAIT_FAILED — unrecoverable. The mechanism thread is about
                // to exit and every currently-armed key will silently stop
                // updating forever; report it (governance Gate-6 sre
                // finding — this path previously had no log line at all).
                spdlog::error("spark_service: WaitForSingleObjectEx failed (err={}) — mechanism "
                             "thread exiting, every armed key is now silently dead",
                             GetLastError());
                for (auto& [name, wp] : svcs_) {
                    if (wp->faulted)
                        continue;
                    wp->faulted = true;
                    wp->fault_reason = "mechanism thread terminating";
                    for (const auto& k : wp->keys)
                        faults.push_back({k, true, "mechanism thread terminating"});
                }
                drop_coverage_all(established);
                // Same reasoning as the Linux mechanism: a watch() that
                // landed in pending_ this same tick was never armed at all,
                // so the loop above (which only walks svcs_) can't find it —
                // without this, a consumer whose arm() call raced the
                // mechanism's death would get no signal whatsoever
                // (governance Gate-4 unhappy-path finding UP-8).
                {
                    std::lock_guard lk(mu_);
                    for (auto& cmd : pending_)
                        if (cmd.op == Cmd::Add)
                            faults.push_back({cmd.key, true, "mechanism thread terminating"});
                    pending_.clear();
                }
                dispatch(emits, faults, established);
                break;
            }

            // Poll every outstanding establishment probe and launch any due
            // Deferred (re-)probe — regardless of what `r` was (#2012/#3840
            // PR-B3; the pre-PR-B3 code only ran the equivalent retry scan on
            // WAIT_TIMEOUT, which was fine when arm_watch was the retry
            // itself — now that begin_probe() is a cheap, non-blocking call,
            // there is no reason to defer noticing a due retry just because a
            // command or an APC also woke this same iteration). A probe can
            // complete at any time with no OS notification for it (unlike an
            // APC) — this is what actually notices completion; the
            // wait-timeout computation above caps the wait specifically so
            // this scan runs promptly instead of only on some unrelated wake.
            {
                const auto now2 = std::chrono::steady_clock::now();
                for (auto& [name, wp] : svcs_) {
                    if (wp->probe == ProbeState::Pending) {
                        if (!wp->call)
                            continue; // defensive: begin_probe always pairs
                                     // Pending with an engaged call on Launched
                        if (auto res = wp->call->try_take()) {
                            wp->call.reset();
                            resolve_probe(*wp, std::move(*res), emits, faults,
                                         established); // may deliver APCs via its own
                                                        // NotifyServiceStatusChangeW registration
                        } else {
                            grace_check(*wp, now2, faults);
                        }
                    } else if (wp->probe == ProbeState::Deferred) {
                        if (wp->next_retry <= now2) {
                            begin_probe(*wp, established); // may deliver APCs via its own
                                                            // SleepEx(0,TRUE) (teardown_watch)
                        } else {
                            // Not yet due for retry — still grace-check it
                            // (#2012/#3840 PR-B3 review): a no-op once
                            // resolve_probe() has already classified this
                            // Deferred definitively (grace_counted set there),
                            // but for an admission-rejected obligation that
                            // has never actually run a probe, this is the
                            // ONLY path that can ever surface its grace fault.
                            grace_check(*wp, now2, faults);
                        }
                    }
                }
            }

            // Drain pending watch()/unwatch() commands. Add's begin_probe
            // (via its teardown_watch call) and Remove's teardown_watch may
            // ALSO deliver queued APCs via their internal SleepEx(0,TRUE) —
            // the fired-flag scan below runs AFTER this drain so it catches
            // those too.
            std::deque<Cmd> cmds;
            {
                std::lock_guard lk(mu_);
                cmds.swap(pending_);
            }
            for (auto& cmd : cmds) {
                if (cmd.op == Cmd::Add) {
                    const std::wstring folded = fold_ci(cmd.name);
                    auto it = svcs_.find(folded);
                    const bool is_new = (it == svcs_.end());
                    SvcWatch* w;
                    if (is_new) {
                        auto owned = std::make_unique<SvcWatch>();
                        owned->name = cmd.name;
                        w = owned.get();
                        svcs_.emplace(folded, std::move(owned));
                    } else {
                        w = it->second.get();
                    }
                    // Exception-safety (governance UP-1(A), adjudicated
                    // LOW-today/MEDIUM-post-flip): populate every map
                    // stage_coverage()'s .at() later reads FIRST, insert into
                    // .keys LAST — a bad_alloc between these statements now
                    // leaves a harmless orphan map entry (persists for this
                    // mechanism instance's lifetime — neither platform's
                    // stop() clears key_incarnation_/key_epoch_, and no
                    // Remove/Add for this key ever runs afterward: the SAME
                    // exception that creates the orphan also propagates
                    // straight to run()'s own outer catch, permanently
                    // admission-gating the mechanism via UP-1(B)'s fix below)
                    // instead of a .keys member .at() will trip on, killing
                    // the whole mechanism worker thread.
                    // A fresh subscription epoch for `cmd.key` specifically —
                    // NOT `w->probe_gen` (#2012/#3840 PR-B3 review, round 2):
                    // this is the identity drop_stale() checks, and it must
                    // track THIS key's own Add/Remove lifecycle, independent
                    // of the shared watch's probe activity or of any other
                    // key coalesced onto the same watch. Bumped UNCONDITIONALLY
                    // (including the adoption case, now that the early
                    // idempotent-continue above is gone) — an adopted key is a
                    // genuinely new subscription lifecycle from the engine's
                    // own perspective (a fresh SubscriptionId/incarnation), so
                    // any not-yet-dispatched entry staged under the OLD epoch
                    // must still be considered stale.
                    const std::uint64_t this_key_epoch = ++gen_;
                    key_epoch_[cmd.key] = this_key_epoch;
                    // Forward-only rebind (H1): a stale/duplicate Add can
                    // never regress this key's recorded incarnation — H1's
                    // submission ordering means one should never actually
                    // arrive here below the current value in production; this
                    // is defence-in-depth, not a live path.
                    auto& inc_slot = key_incarnation_[cmd.key];
                    if (cmd.incarnation > inc_slot)
                        inc_slot = cmd.incarnation;
                    key_svc_.emplace(cmd.key, folded);
                    // no-op if cmd.key is already present — see the unified
                    // branch below for why that ("adoption") is now handled
                    // rather than skipped.
                    w->keys.insert(cmd.key);
                    if (is_new) {
                        begin_probe(*w, established);
                    } else {
                        // F4: ONE unconditional branch covers both COALESCE
                        // (cmd.key is genuinely new to this watch) and
                        // ADOPTION (cmd.key was already mapped to this exact
                        // watch — its disarm's unwatch() was skipped by
                        // SparkEngine::disarm()'s M2 staleness recheck and a
                        // fresh arm() landed on the still-live watch). Both
                        // need the SAME honest report of the watch's CURRENT
                        // coverage, whether or not this is an "edge" for the
                        // emit/fault channels below — round-4 MF1's
                        // unconditional-staging rule.
                        //
                        // w->fired guard (adversarial-review finding, post-
                        // round-4): the one-shot NotifyServiceStatusChangeW
                        // registration is CONSUMED the instant the OS
                        // delivers it (notify_cb sets `fired`), but this
                        // drain runs BEFORE the fired-flag scan below that
                        // re-arms it and corrects `w->coverage` — an APC for
                        // THIS watch can land during an unrelated Add's own
                        // begin_probe/teardown_watch SleepEx(0,TRUE) earlier
                        // in THIS SAME drain. Between those two points
                        // `w->coverage` still reads the stale pre-fire value
                        // (typically Notification) even though no live
                        // registration currently exists for it. Reporting
                        // that stale value here would first-wins-stamp the
                        // adopting incarnation's established_at from a
                        // registration that was already consumed — a
                        // timestamp the later fired-scan's own correction
                        // (None on a failed re-arm) can never retract. Fold
                        // `fired` into the reported value rather than
                        // `w->coverage` alone: the fired-scan itself re-
                        // stages the truth once it actually re-arms.
                        established.push_back({cmd.key, inc_slot, Clock::now(),
                                               w->fired ? SparkCoverage::None : w->coverage,
                                               this_key_epoch});
                        // Same UP-2 fix as the Linux mechanism: hand a
                        // newly-coalescing key the fault status too, not just
                        // the cached state.
                        if (w->last)
                            emits.push_back({cmd.key, *w->last, this_key_epoch});
                        // Hoisted OUT of the `w->last` guard (round-4 fix,
                        // alongside the established push above): a watch that
                        // is faulted but has NEVER resolved a terminal state
                        // previously told a coalescing/adopting key NOTHING
                        // about the fault. Uses w->fault_reason (governance
                        // review) rather than a hardcoded literal — the
                        // watch's actual fault cause may be a Notify-
                        // registration failure or a health-grace timeout, not
                        // an OpenService failure; spark_file.cpp's own
                        // "review finding 9" fixed the identical class of bug
                        // for its coalescing joins.
                        if (w->faulted)
                            faults.push_back({cmd.key, true, w->fault_reason, this_key_epoch});
                    }
                } else { // Cmd::Remove
                    auto kit = key_svc_.find(cmd.key);
                    if (kit == key_svc_.end())
                        continue;
                    const std::wstring folded = kit->second;
                    key_svc_.erase(kit);
                    key_epoch_.erase(cmd.key);
                    key_incarnation_.erase(cmd.key);
                    auto sit = svcs_.find(folded);
                    if (sit == svcs_.end())
                        continue;
                    sit->second->keys.erase(cmd.key);
                    if (sit->second->keys.empty()) {
                        // Don't free the SvcWatch synchronously: CloseServiceHandle
                        // cancelling a pending NotifyServiceStatusChangeW
                        // registration is not documented as a synchronous
                        // barrier against an already-in-flight APC (governance
                        // Gate-2 security-guardian finding) — a queued
                        // notification could still land microseconds after
                        // teardown_watch's drain. Relocate to retiring_ (kept
                        // alive, never re-armed, no keys so nothing to notify)
                        // and free only once quiescent for a few loop passes.
                        teardown_watch(*sit->second);
                        sit->second->retire_grace = kRetireGracePasses;
                        retiring_.push_back(std::move(sit->second));
                        svcs_.erase(sit);
                    }
                }
            }

            // Unconditionally scan every watch for a delivered APC notification
            // — regardless of what `r` was. An APC is NOT only delivered by the
            // WaitForSingleObjectEx above (which used to be the only trigger
            // this scan ran on, r==WAIT_IO_COMPLETION): arm_watch/teardown_watch
            // call SleepEx(0,TRUE) to drain a registration's queued APC, and
            // THAT alertable point can just as easily deliver an unrelated
            // watch's fresh notification. That happens inside the WAIT_TIMEOUT
            // reconcile above and inside this iteration's Add/Remove command
            // drain — gating the scan on r==WAIT_IO_COMPLETION silently missed
            // those, leaving a watch's one-shot consumed-but-unprocessed until
            // some unrelated later fire happened to re-scan it. Loop until a
            // full pass finds nothing new: this scan's OWN arm_watch calls
            // (the MARKED_FOR_DELETE / re-arm-failed branches) can themselves
            // deliver another watch's queued APC via the same SleepEx path.
            // Bounded to kMaxFiredScanPasses (governance Gate-3 cpp-expert
            // finding): a service flapping externally faster than this thread
            // can re-arm+drain could otherwise re-seed `fired` every pass
            // indefinitely, monopolizing the mechanism thread. A self-wake on
            // hitting the cap defers any straggler to the next outer-loop
            // iteration rather than looping unbounded here.
            for (int pass = 0; pass < kMaxFiredScanPasses; ++pass) {
                bool any = false;
                for (auto& [name, wp] : svcs_) {
                    if (!wp->fired)
                        continue;
                    any = true;
                    wp->fired = false;
                    if (wp->notify.pszServiceNames) {
                        LocalFree(wp->notify.pszServiceNames);
                        wp->notify.pszServiceNames = nullptr;
                    }
                    // MF1 (rung 9c PR-6 item 1, round-4): observing `fired`
                    // itself stages/mutates NOTHING — the fired-scan's own
                    // clear-then-gate shape was exactly the defect round 3's
                    // review caught. Every outcome below is staged by the
                    // SAME unconditional table every other site uses: a
                    // failed re-arm routes through begin_probe() (-> None,
                    // its own unconditional stage); a successful re-arm
                    // stages Notification explicitly at the two sites below.
                    if (wp->notify_status != ERROR_SUCCESS) {
                        // MARKED_FOR_DELETE / CLIENT_LAGGING or similar — the
                        // ServiceStatus is not trustworthy; re-resolve from
                        // scratch (-> absent path if truly gone).
                        begin_probe(*wp, established);
                        continue;
                    }
                    if (is_pending(wp->current_state)) {
                        // Transitional: HOLD (no compare), just re-arm the
                        // one-shot so the terminal state is still seen.
                        if (NotifyServiceStatusChangeW(wp->svc.get(), kNotifyMask, &wp->notify) !=
                            ERROR_SUCCESS)
                            begin_probe(*wp, established);
                        else
                            stage_coverage(*wp, SparkCoverage::Notification, established);
                        continue;
                    }
                    // Terminal: re-arm the one-shot FIRST (it is consumed on
                    // delivery — never leave the watch deaf while dispatching
                    // arbitrary consumer code), then map + edge-dedup.
                    const bool rearmed = NotifyServiceStatusChangeW(wp->svc.get(), kNotifyMask,
                                                                    &wp->notify) == ERROR_SUCCESS;
                    set_terminal(*wp, map_terminal(wp->current_state), emits);
                    if (!rearmed)
                        begin_probe(*wp, established);
                    else
                        stage_coverage(*wp, SparkCoverage::Notification, established);
                }
                if (!any) {
                    break; // converged — nothing fired this pass
                }
                if (pass == kMaxFiredScanPasses - 1) {
                    // Hit the cap with more still pending — self-wake so any
                    // straggler is picked up on the next outer-loop iteration
                    // instead of looping unbounded on this thread.
                    wake_signal();
                }
            }

            // Reap retiring watches: absorb any stale APC silently (no keys
            // left, so no consumer to notify — just clear the flag and free
            // the name buffer) and free the SvcWatch for real once quiescent
            // for kRetireGracePasses consecutive passes. This is what makes
            // the "don't free synchronously on removal" fix above safe
            // regardless of exactly when CloseServiceHandle's cancellation
            // takes effect — the object stays alive (just never re-armed)
            // until nothing has touched it for a few loop iterations.
            for (auto& rw : retiring_) {
                if (rw->fired) {
                    rw->fired = false;
                    if (rw->notify.pszServiceNames) {
                        LocalFree(rw->notify.pszServiceNames);
                        rw->notify.pszServiceNames = nullptr;
                    }
                    rw->retire_grace = kRetireGracePasses; // still live — reset the countdown
                } else if (rw->retire_grace > 0) {
                    --rw->retire_grace;
                }
            }
            retiring_.erase(std::remove_if(retiring_.begin(), retiring_.end(),
                                           [](const std::unique_ptr<SvcWatch>& rw) {
                                               return rw->retire_grace == 0 && !rw->fired;
                                           }),
                            retiring_.end());

            // Drop anything staged above (poll-scan, fired-scan) whose key
            // was remapped to a different watch — or whose SAME watch
            // already relaunched a newer probe — by the command drain that
            // ran in between (#2012/#3840 PR-B3 review, kickoff doc's
            // required stale-generation discard). No-op for the common case
            // where nothing changed underneath a staged entry. `established`
            // goes through the SAME filter (rung 9c PR-6 item 1) — Windows's
            // async establishment path has the identical same-tick staleness
            // window emits/faults already guard against.
            drop_stale(emits);
            drop_stale(faults);
            drop_stale(established);
            dispatch(emits, faults, established);
        }

        // Thread exit path: tear down every outstanding registration on THIS
        // thread (the registering thread — SERVICE_NOTIFYW/APC ownership).
        // Duplicated into both catch blocks below (not just here) so an
        // exception mid-loop can't skip it and leave stop()'s "already torn
        // down" assumption false (governance Gate-3 cpp-safety finding).
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
    } catch (const std::exception& e) {
        // MF3, first statement of the catch block: invalidate every
        // currently-tracked key's coverage to None BEFORE anything else, so
        // an exception mid-loop can never leave a stale positive coverage the
        // engine keeps trusting after this thread is gone — THEN the existing
        // teardown, THEN the existing log (now wrapped).
        invalidate_established_noexcept();
        // Governance UP-1(B): mark this mechanism no longer accepting new watches.
        // scm_ok_, NOT started_: WindowsServiceMechanism::stop() early-returns on a
        // bare `if (!started_) return` (unlike Linux's resource-conjunction guard)
        // — flipping started_ here would make a later stop() skip thread_.join()
        // entirely, and the eventual ~thread() on a still-joinable thread calls
        // std::terminate(). scm_ok_ is atomic (no lock needed), unpublished by
        // stats() (which reads the distinct started_inert_ flag, untouched here),
        // and is already one of watch_incarnation()'s two admission guards —
        // flipping it alone correctly makes a future arm() return "SCM unavailable"
        // instead of silently queuing into a dead thread.
        scm_ok_.store(false, std::memory_order_release);
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
        try {
            spdlog::error("spark_service: mechanism thread exception: {} — mechanism stopping",
                          e.what());
        } catch (...) {
        }
    } catch (...) {
        invalidate_established_noexcept();
        // Governance UP-1(B): mark this mechanism no longer accepting new watches.
        // scm_ok_, NOT started_: WindowsServiceMechanism::stop() early-returns on a
        // bare `if (!started_) return` (unlike Linux's resource-conjunction guard)
        // — flipping started_ here would make a later stop() skip thread_.join()
        // entirely, and the eventual ~thread() on a still-joinable thread calls
        // std::terminate(). scm_ok_ is atomic (no lock needed), unpublished by
        // stats() (which reads the distinct started_inert_ flag, untouched here),
        // and is already one of watch_incarnation()'s two admission guards —
        // flipping it alone correctly makes a future arm() return "SCM unavailable"
        // instead of silently queuing into a dead thread.
        scm_ok_.store(false, std::memory_order_release);
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
        try {
            spdlog::error("spark_service: mechanism thread unknown exception — mechanism stopping");
        } catch (...) {
        }
    }

    // MF3: invalidate every currently-tracked key's coverage to None, by
    // reference (no SparkEstablishedFn copy, no allocation) — called as the
    // FIRST statement of each of run()'s exception catch blocks, before any
    // teardown or log call, so a worker-thread exception leaves no stale
    // positive coverage for the engine to keep trusting. Hard constraint:
    // zero spdlog calls inside the per-key loop (#2270 is exactly logging
    // breaking a guarantee like this one). noexcept: every fallible call
    // inside is caught, and std::terminate is the honest outcome if that
    // invariant is ever wrong.
    void invalidate_established_noexcept() noexcept {
        const SparkEstablishedFn& sink = established_; // reference: no copy; nulled only after join
        if (!sink)
            return;
        const auto now = std::chrono::steady_clock::now(); // noexcept
        for (const auto& [key, inc] : key_incarnation_) {
            try {
                sink(key, inc, now, SparkCoverage::None);
            } catch (...) {
            }
        }
    }

    std::mutex mu_; ///< guards ONLY pending_, emit_/fault_/established_, started_, sink_sealed_ (scm_ok_ is atomic)
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    /// Establishment-signal sink (rung 9c PR-6 item 1) — set once via
    /// set_established_sink() before start(), read WITHOUT mu_ from run() (the
    /// mechanism thread), exactly like emit_/fault_: the write happens-before
    /// the thread is spawned and the clear in stop() happens-after it joins.
    SparkEstablishedFn established_;
    /// One-way latch (rung 9c PR-6 item 1): set true by start() being called,
    /// never cleared. See set_established_sink()'s own doc comment.
    bool sink_sealed_{false};
    std::deque<Cmd> pending_;
    bool started_{false};
    std::atomic<bool> scm_ok_{false};
    /// Started, but the SCM / wake-event could not be acquired — every watch() will be
    /// refused. Published separately from scm_ok_ (which is also false pre-start) so
    /// stats() can report the mechanism as inert WITHOUT mu_, and so a never-started
    /// mechanism is not misreported as inert. An SCM-denied mechanism stays REGISTERED
    /// and would otherwise be indistinguishable from a healthy idle one on the wire
    /// (governance Gate-3 cross-platform / Gate-6 sre).
    std::atomic<bool> started_inert_{false};
    std::atomic<bool> stop_{false};
    std::thread thread_;
    /// Shared SCM connection lease — see ScmCore's own doc comment. Set once
    /// per start()ed lifetime, cleared in stop(); a probe holding its own
    /// copy keeps the connection open independent of this member's lifetime
    /// (#2012/#3840 PR-B3).
    std::shared_ptr<ScmCore> scm_core_;
    detail::EventHandle wake_;

    // Mechanism-thread-confined (no lock): touched only from run(), and from
    // stop() after the thread has joined.
    std::unordered_map<std::wstring, std::unique_ptr<SvcWatch>> svcs_; ///< keyed by folded name
    std::unordered_map<std::string, std::wstring> key_svc_;           ///< spark key -> folded name
    /// spark key -> subscription epoch, bumped in `++gen_` EVERY time an Add
    /// for that key is processed (rung 9c PR-6 item 1: this now includes the
    /// adoption case — a key that was already in key_svc_ — since removing
    /// the old idempotent-continue there; an adopted key is a genuinely new
    /// subscription lifecycle from the engine's own perspective, so any
    /// not-yet-dispatched entry staged under the OLD epoch must still be
    /// considered stale). This is the identity `drop_stale()` checks —
    /// deliberately NOT `SvcWatch::probe_gen`, which tracks probe LAUNCHES and
    /// is bumped by events (a same-watch re-arm-failure retry) that have
    /// nothing to do with whether `key`'s own subscription is still the one a
    /// staged emit/fault/established was produced for (#2012/#3840 PR-B3
    /// review, round 2).
    std::unordered_map<std::string, std::uint64_t> key_epoch_;
    /// spark key -> the SparkEngine-minted incarnation of its CURRENT
    /// subscription (rung 9c PR-6 item 1) — forward-only rebind on Cmd::Add
    /// (H1), erased in lockstep with key_svc_/key_epoch_ on Cmd::Remove. This
    /// is the identity an established report is stamped with and the identity
    /// the engine's report_established checks before trusting one. A
    /// DIFFERENT identity from key_epoch_ above: this one names WHICH watch
    /// (from the engine's perspective) a report is about; key_epoch_ names
    /// whether a staged-but-not-yet-dispatched entry is still current within
    /// THIS mechanism's own same-tick window.
    std::unordered_map<std::string, SparkIncarnation> key_incarnation_;
    /// Removed watches awaiting quiescence before real free — see the
    /// Cmd::Remove handling and the reap loop in run() for why a watch isn't
    /// freed synchronously on removal.
    std::vector<std::unique_ptr<SvcWatch>> retiring_;

    // ── PR-B3 (#2012/#3840): probe-only establishment lane ──────────────────
    /// Mechanism-global monotonic source, consumed by `key_epoch_` (see its
    /// own doc comment) each time a key's subscription is freshly
    /// (re-)established. An earlier version of this counter also stamped a
    /// per-watch `SvcWatch::probe_gen` field bumped on every probe launch;
    /// that field was removed (#2012/#3840 PR-B3 review, round 2) once
    /// `drop_stale()` moved off it — it had no other reader once its one
    /// use turned out to be the wrong identity (probe-launch, not
    /// subscription-lifetime) for that check.
    std::uint64_t gen_{0};
    std::shared_ptr<const ServiceProbeHook> probe_hook_; ///< test seam
    SparkDetachedLane probe_lane_;

    std::atomic<std::uint64_t> probe_launched_{0};
    std::atomic<std::uint64_t> probe_admission_rejected_{0};
    std::atomic<std::uint64_t> probe_launch_failed_{0};
    std::atomic<std::uint64_t> probe_backend_failed_{0};
    std::atomic<std::uint64_t> probe_discarded_{0}; ///< reserved for future use — see debug_counters()
    std::atomic<std::uint64_t> health_edges_{0};

public:
    // ── test seams (spark_mechanism.hpp free functions forward here) ────────
    void apply_test_controls(ServiceMechanismTestControls c) {
        // probe_hook_ is read by begin_probe() on the mechanism's OWN thread
        // (run()), outside any lock in the ordinary case — unlike
        // spark_registry.cpp, where every reader of its equivalent
        // probe_hook_ already runs under mu_. mu_ here otherwise guards only
        // pending_/start-stop, so this write (and begin_probe's read, below)
        // take it JUST for this one shared_ptr, rather than serialising the
        // whole control path against it.
        {
            std::lock_guard lk(mu_);
            if (c.probe_hook)
                probe_hook_ = std::make_shared<const ServiceProbeHook>(std::move(c.probe_hook));
            else
                probe_hook_.reset();
        }
        if (c.probe_lane_cap)
            probe_lane_.set_cap_for_test(c.probe_lane_cap);
        if (c.health_grace.count() > 0)
            health_grace_ms_.store(c.health_grace.count(), std::memory_order_relaxed);
        if (c.admission_backoff_seed.count() > 0)
            admission_seed_ms_.store(c.admission_backoff_seed.count(), std::memory_order_relaxed);
        wake_signal(); // nudge run() in case a lowered cap/grace should apply promptly
    }

    [[nodiscard]] ServiceMechanismDebugCounters debug_counters() const {
        ServiceMechanismDebugCounters d;
        d.probe_launched = probe_launched_.load(std::memory_order_relaxed);
        d.probe_admission_rejected = probe_admission_rejected_.load(std::memory_order_relaxed);
        d.probe_launch_failed = probe_launch_failed_.load(std::memory_order_relaxed);
        d.probe_backend_failed = probe_backend_failed_.load(std::memory_order_relaxed);
        d.probe_discarded = probe_discarded_.load(std::memory_order_relaxed);
        d.health_edges = health_edges_.load(std::memory_order_relaxed);
        // probe_lane_'s own counters are lock-free/atomic by construction
        // (SparkDetachedLane). svcs_/retiring_ are mechanism-thread-confined
        // with NO lock (unlike Registry's watches_, which is mu_-guarded) —
        // deliberately NOT exposed here: reading their .size() from this
        // (arbitrary caller) thread while run() concurrently inserts/erases
        // would be a real data race, not merely a point-in-time skew. A test
        // that needs to observe watch-count-shaped behavior does so through
        // Collector/emit counts, matching every existing Service test.
        d.probe_workers_active = probe_lane_.active_workers();
        return d;
    }

private:
    std::atomic<std::int64_t> health_grace_ms_{kServiceHealthGrace.count()};
    std::atomic<std::int64_t> admission_seed_ms_{kServiceAdmissionBackoffSeed.count()};
};

} // namespace

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return std::make_unique<WindowsServiceMechanism>(nullptr); // no shared F3 counter (tests)
}

std::unique_ptr<ISparkMechanism>
make_service_mechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter) {
    return std::make_unique<WindowsServiceMechanism>(std::move(f3_counter));
}

bool set_service_test_controls_for_test(ISparkMechanism& mech, ServiceMechanismTestControls controls) {
    auto* real = dynamic_cast<WindowsServiceMechanism*>(&mech);
    if (!real)
        return false;
    real->apply_test_controls(std::move(controls));
    return true;
}

std::optional<ServiceMechanismDebugCounters>
service_debug_counters_for_test(const ISparkMechanism& mech) {
    const auto* real = dynamic_cast<const WindowsServiceMechanism*>(&mech);
    if (!real)
        return std::nullopt;
    return real->debug_counters();
}

} // namespace yuzu::agent

#else // ── macOS, or a Linux build without libsystemd: no mechanism ──────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(Service)
}

std::unique_ptr<ISparkMechanism>
make_service_mechanism(std::shared_ptr<std::atomic<std::size_t>> /*f3_counter*/) {
    return nullptr; // same platform contract as the zero-argument form
}

bool set_service_test_controls_for_test(ISparkMechanism&, ServiceMechanismTestControls) {
    return false; // nothing to control off Windows and off Linux-with-libsystemd
}

std::optional<ServiceMechanismDebugCounters> service_debug_counters_for_test(const ISparkMechanism&) {
    return std::nullopt;
}

} // namespace yuzu::agent

#endif
