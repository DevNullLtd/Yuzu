/**
 * spark_registry.cpp - the Registry spark mechanism (ADR-0021 Stage 1 PR 1b;
 * watch establishment moved off the engine's per-type lock in #2012/#3840 PR-B1).
 *
 * Windows: one PRIVATE threadpool wait-group (TP_WAIT, min=2/max=4) servicing
 * RegNotifyChangeKeyValue across every watched key — O(mechanism), never
 * O(rules). This is the #1907-spike mechanism, NOT a port of guard_registry's
 * one-dedicated-thread-per-guard + 64-handle WaitForMultipleObjects model
 * (which is the O(rules)-capped ceiling the SparkEngine removes). Two spike
 * facts are load-bearing:
 *   - REG_NOTIFY_THREAD_AGNOSTIC on every RegNotifyChangeKeyValue: TP_WAIT
 *     recycles pool threads, and a notification registered without the flag is
 *     bound to the (transient) registering thread and dies when the pool
 *     recycles it. Since PR-B1 the registration is issued from a detached probe
 *     worker that EXITS right after, so the flag is now what keeps every
 *     notification alive at all, not only across pool recycling.
 *   - Re-arm before processing (spike condition 4) is now split: the known-good
 *     Target-mode fire is delivered immediately from the callback, the re-arm is
 *     a detached probe committed later by the sweeper, and the window between
 *     the two is covered by a synthetic fire on commit (`needs_resync`) - see
 *     "Ownership / dispatch protocol" below.
 *
 * PORTS THE WATCH, NOT THE ASSERTION: no expected-value compare, no write-back,
 * no ResilienceStrategy retry — a fired spark is a raw "this key changed" fact
 * (the old TriggerEngine RegistryChange shape). Compare + enforce are
 * Guardian's, Stage 2. It DOES port guard_registry's nearest-ancestor resilience
 * (survive a deleted+recreated key) and arm-before-check ordering.
 *
 * WHY THE PR-B1 SHAPE (issues #2012/#3840, T6 = #4181). The engine serialises
 * every watch()/unwatch() of one SparkType under SparkEngine::mech_ops_mu_by_type_
 * [type]. Before PR-B1, watch() ran five OS calls (open, notify, the unbounded
 * nearest-ancestor walk) under that lock and unwatch() blocked in
 * WaitForThreadpoolWaitCallbacks(TRUE) under it - so one slow hive stalled every
 * other Registry arm/disarm, and (#4181) a disarm racing an in-flight callback
 * whose Inline consumer re-entered the same type deadlocked outright: the
 * disarmer held the per-type lock waiting for the callback, the callback waited
 * for the per-type lock. Now:
 *   - watch(): reserve under mu_ -> release -> launch the probe on a detached,
 *     F3-counted worker (`probe_lane_`) -> wait at most kRegCallerWaitBudget ->
 *     relock, re-validate, commit; a probe still outstanding is PUBLISHED to the
 *     sweeper and watch() returns success-with-pending. Per-type lock hold is
 *     <= budget + microseconds, never an OS-call duration.
 *   - unwatch(): mark inactive, disarm the wait, hand the whole RegWatch to a
 *     detached drain worker (`drain_lane_`) that performs the blocking callback
 *     drain and closes the handles. O(microseconds) on the control path.
 *   - on_fire(): records the observation gap and launches the re-arm probe
 *     (launch-and-poll, never a bounded wait on the pool thread - amendment
 *     8), then emits the known-good fire with mu_ released; a timed retry
 *     backstop replaces the old code's deaf-forever failure.
 *   - a joined `sweeper_` thread polls outstanding probes/drains, commits late
 *     results, retries on a schedule, and is the SINGLE producer of fault()
 *     edges and synthetic fires (dispatched with mu_ released).
 *
 * OWNERSHIP / DISPATCH PROTOCOL (plan amendment 5 - the same rules PR-B2/B3
 * apply to File/Service):
 *   1. Reserve the obligation under mu_ (probe state + a mechanism-global
 *      generation stamped on the watch), release, launch off-lock.
 *   2. Only the initiating control-path caller (watch()) performs a bounded
 *      wait; the sweeper and on_fire only poll (try_take), never block for D.
 *   3. Reacquire mu_, re-validate key + generation + lifecycle, then commit,
 *      hand off (publish as Pending) or discard - the discard's handle closes
 *      run after mu_ is released.
 *   4. Neither watch() nor unwatch() calls emit()/fault() synchronously on ANY
 *      path, immediate success included: the engine's per-type lock is still on
 *      that call stack even though our own mu_ is not.
 *   5. Caller and sweeper never touch the same DetachedCall concurrently: the
 *      launching thread owns the handle until it commits or publishes it under
 *      mu_; a retirement racing that window cancels the reservation and the
 *      launcher observes cancellation (generation/active mismatch), not a
 *      stolen value.
 *   6. `needs_resync` carries an epoch: set (epoch bumped) whenever an accepted
 *      watch has an observation gap (a Target-mode fire consumed, an initial
 *      probe published past the caller budget, or an Ancestor -> Target
 *      appearance found at commit); cleared by the sweeper when the synthetic
 *      fire is SUBMITTED through emit (SparkEmitFn returns void - there is no
 *      delivery acknowledgement to wait for); restored if that submit threw and
 *      the epoch is unchanged, then re-staged on a D-doubling backoff (30 s cap)
 *      rather than at the sweep cadence. REGISTRY-SPECIFIC consequence of this
 *      point under launch-and-poll (not a protocol requirement File/Service
 *      must copy): a consumed TARGET-mode notification produces two emit
 *      SUBMISSIONS (immediate + synthetic), not two changes - an Ancestor-mode
 *      notification produces none or one (appearance at commit).
 *      RegNotifyChangeKeyValue is one-shot, so N writes before the re-arm
 *      coalesce into one notification, and the consumer's own dedup decides
 *      what reaches the wire.
 *
 * LIFETIME INVARIANT that makes the raw `RegWatch*` TP_WAIT context safe: a
 * RegWatch whose wait was ever armed is destroyed ONLY after that wait has been
 * disarmed and drained (drain_watch), on a thread that is not the callback
 * itself - so on_fire(w) always runs against a live object. A wait created by a
 * probe but never committed is never armed, so its (possibly dangling) context
 * is never dereferenced; it is simply closed.
 *
 * D (50 ms) is the #2012/#3840 series' chosen initial policy value, not a proven statistical
 * bound - the measured inputs (docs/spark-rebuild-baselines/stage2-watch-
 * establish-latency.md: Registry direct-target summed per-call p99 82 us, R2
 * ancestor-walk total p99 1264 us, R4 unmeasured) sit far below it. Its five
 * meanings are separate named constants below so they can be tuned apart.
 *
 * Off Windows the factory returns nullptr → SparkEngine rejects arm(Registry).
 */

#include "spark_mechanism.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp" // detail::EventHandle
#include "spark_detached_call.hpp"
#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace yuzu::agent {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr DWORD kNotifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;
#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Win8+; define for older SDK headers
#endif

// ── D and its five meanings (PR-B1 initial policy: all 50 ms, tuned apart) ──
/// How long watch() waits for its own probe before publishing it to the
/// sweeper and returning success-with-pending. The per-type lock hold bound.
constexpr std::chrono::milliseconds kRegCallerWaitBudget{50};
/// How long an accepted obligation (initial establishment or re-arm) may stay
/// unestablished before the watch is reported Faulted and slow_op_total bumps.
constexpr std::chrono::milliseconds kRegHealthGrace{50};
/// Sweeper poll cadence while any probe or drain is outstanding - a CEILING on
/// how long a completed probe waits to be committed, not an added latency:
/// every launch and state change nudges the sweeper, so the common case is
/// committed on the next pass.
constexpr std::chrono::milliseconds kRegSweepCadence{50};
/// First delay after an admission refusal (lane cap / launch failure): D, 2D,
/// 4D, ... capped at kRegAdmissionBackoffCap, never counted as a backend attempt.
constexpr std::chrono::milliseconds kRegAdmissionBackoffSeed{50};
/// Elapsed budget for the nearest-ancestor walk once the target open failed:
/// a dead hive costs ~one OS timeout plus this, not depth x timeout.
constexpr std::chrono::milliseconds kRegProbeTraversalBudget{50};

constexpr std::chrono::milliseconds kRegAdmissionBackoffCap{30'000};
/// Genuine backend failure (open/notify refused, probe threw): 30 s doubling to
/// a 300 s cap, attempts reset on a successful establishment.
constexpr std::chrono::milliseconds kRegBackendRetryBase{30'000};
constexpr std::chrono::milliseconds kRegBackendRetryCap{300'000};

constexpr std::size_t kProbeLaneCap = 16; ///< concurrent detached probe workers
constexpr std::size_t kDrainLaneCap = 8;  ///< concurrent detached drain workers
/// Retirements (drains launched or backlogged, not yet completed) past which
/// watch() refuses new watches - the same bound spark_file.cpp places on its
/// retiring_ (#1979); teardown itself is never gated.
constexpr std::size_t kRetiringCap = 256;
/// Per-sweep budget under mu_: items visited / wall time before the sweeper
/// yields and re-nudges itself (not N x D per pass - Astra correction).
constexpr std::size_t kSweepMaxItems = 256;
constexpr std::chrono::milliseconds kSweepTimeBudget{5};
/// Consecutive failed sweeper passes after which the mechanism reports itself
/// inert on the heartbeat (the existing capability-gap signal) - a dark sweeper
/// must never read as a healthy idle one (governance sre6-1).
constexpr unsigned kSweeperInertAfterFailures = 3;

// The caller wait budget is the only one of the five that a Guardian control-path
// caller can be made to wait through under the per-type lock; it must sit inside
// Guardian's backend_op deadline. This is a configuration check, not a proof that
// an arbitrary same-type caller completes inside that deadline (lock waiters are
// not bounded by the lane cap).
static_assert(spark_deadline_below_guardian_backend_op(kRegCallerWaitBudget),
              "kRegCallerWaitBudget must be strictly below Guardian's backend_op deadline");

/// Hand-rolled HKEY owner (the ScopedWinHandle template is HANDLE-typed;
/// mirrors guard_registry.cpp's RegKeyHandle). Movable since PR-B1 so a probe
/// result can carry an opened key across threads (by move; nothing releases).
class RegKeyHandle {
public:
    RegKeyHandle() = default;
    ~RegKeyHandle() { reset(); }
    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;
    RegKeyHandle(RegKeyHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    RegKeyHandle& operator=(RegKeyHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h_ = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }
    void reset(HKEY h = nullptr) {
        if (h_ && h_ != h)
            ::RegCloseKey(h_);
        h_ = h;
    }
    [[nodiscard]] HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    HKEY h_ = nullptr;
};

/// Owner of a TP_WAIT that has NEVER been armed (SetThreadpoolWait never called
/// with a handle) - closing it needs no drain. An armed wait lives as a raw
/// PTP_WAIT inside RegWatch and is closed only by drain_watch().
class TpWaitHandle {
public:
    TpWaitHandle() = default;
    ~TpWaitHandle() { reset(); }
    TpWaitHandle(const TpWaitHandle&) = delete;
    TpWaitHandle& operator=(const TpWaitHandle&) = delete;
    TpWaitHandle(TpWaitHandle&& o) noexcept : w_(o.w_) { o.w_ = nullptr; }
    TpWaitHandle& operator=(TpWaitHandle&& o) noexcept {
        if (this != &o) {
            reset();
            w_ = o.w_;
            o.w_ = nullptr;
        }
        return *this;
    }
    void reset(PTP_WAIT w = nullptr) {
        if (w_ && w_ != w)
            ::CloseThreadpoolWait(w_);
        w_ = w;
    }
    [[nodiscard]] PTP_WAIT release() noexcept {
        PTP_WAIT w = w_;
        w_ = nullptr;
        return w;
    }
    [[nodiscard]] PTP_WAIT get() const { return w_; }
    explicit operator bool() const { return w_ != nullptr; }

private:
    PTP_WAIT w_ = nullptr;
};

std::wstring to_wide(const std::string& s) {
    if (s.empty())
        return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

HKEY root_for(const std::string& hive) {
    if (hive == "HKLM")
        return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU")
        return HKEY_CURRENT_USER;
    if (hive == "HKCR")
        return HKEY_CLASSES_ROOT;
    if (hive == "HKU")
        return HKEY_USERS;
    return nullptr;
}

std::string parent_path(const std::string& key) {
    const auto pos = key.find_last_of('\\');
    return pos == std::string::npos ? std::string{} : key.substr(0, pos);
}

/// The private pool + its callback environment, shared by lease: the mechanism
/// holds one reference for its started lifetime, every probe worker that must
/// call CreateThreadpoolWait(&env) holds another for the duration of its call
/// and of the (unarmed) wait it produced. The pool is therefore closed by
/// whichever holder is last - normally stop(), otherwise a probe worker that was
/// still parked when the mechanism stopped (the F3-counted orphan case).
struct PoolCore {
    PTP_POOL pool{nullptr};
    TP_CALLBACK_ENVIRON env{};
    PoolCore() = default;
    PoolCore(const PoolCore&) = delete;
    PoolCore& operator=(const PoolCore&) = delete;
    ~PoolCore() {
        if (pool) {
            ::DestroyThreadpoolEnvironment(&env);
            ::CloseThreadpool(pool);
        }
    }
};

enum class WatchMode { Target, Ancestor };

/// Pending-operation state of one watch - INDEPENDENT of its health (a watch
/// can be Faulted with a retry in flight, or healthy with a re-arm pending).
enum class ProbeState : std::uint8_t {
    Idle,     ///< nothing outstanding; `armed` says whether a notify is live
    Pending,  ///< a probe is reserved or in flight (call engaged once published)
    Deferred, ///< a probe will be relaunched at next_retry_at
};

/// What one detached probe produced. Every OS resource it opened is owned here
/// (RAII), so a discarded result closes itself on whichever thread drops it -
/// never under mu_ by construction of the call sites. `core` is declared FIRST
/// so it is destroyed LAST, after `wait` (a TP_WAIT must be closed before its
/// pool). nothrow-move by construction (launch() static_asserts it).
struct ProbeResult {
    std::shared_ptr<PoolCore> core;
    TpWaitHandle wait; ///< created (never armed) only for an initial establishment
    detail::EventHandle event; ///< the per-probe auto-reset event the notify is bound to
    RegKeyHandle key;          ///< target (Target mode) or nearest ancestor (Ancestor mode)
    WatchMode mode{WatchMode::Target};
    bool ok{false};
    DWORD err{0};
    const char* stage{""}; ///< which step failed, for the log / fault reason
};
static_assert(std::is_nothrow_move_constructible_v<ProbeResult>);

class WindowsRegistryMechanism;
struct RegWatch;
void CALLBACK reg_on_wait_cb(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WAIT, TP_WAIT_RESULT);

using ProbeHook = std::function<void(std::string_view subkey)>;

/// The detached probe: reconcile()'s old body minus the final SetThreadpoolWait,
/// run on a counted worker off every lock. Owns its own auto-reset event, and
/// for an initial establishment also creates the (unarmed) TP_WAIT - so nothing
/// that can block, and no allocation of a pool object, happens on the control
/// path. `wait_ctx` is an opaque RegWatch* handed to CreateThreadpoolWait and
/// NEVER dereferenced here (the watch may already be retired by the time this
/// runs; an uncommitted wait is never armed, so that context is never used).
struct ProbeJob {
    HKEY root{nullptr};
    std::wstring subkey_w; ///< pre-widened on the launching thread
    std::string subkey;
    std::shared_ptr<PoolCore> core;
    void* wait_ctx{nullptr};
    bool create_wait{false};
    std::shared_ptr<const ProbeHook> hook; ///< test seam; may be null
    std::chrono::milliseconds traversal_budget{kRegProbeTraversalBudget};

    ProbeResult operator()() {
        ProbeResult r;
        r.core = core;
        if (hook && *hook)
            (*hook)(subkey); // test seam: may park (a "hung hive") or throw
        r.event.reset(::CreateEventW(nullptr, FALSE, FALSE, nullptr)); // auto-reset
        if (!r.event) {
            r.err = ::GetLastError();
            r.stage = "CreateEventW";
            return r;
        }
        if (create_wait) {
            r.wait.reset(::CreateThreadpoolWait(&reg_on_wait_cb, wait_ctx, &core->env));
            if (!r.wait) {
                r.err = ::GetLastError();
                r.stage = "CreateThreadpoolWait";
                return r;
            }
        }
        // Prefer the target key. KEY_NOTIFY is all RegNotifyChangeKeyValue needs
        // (the value read is Guardian's, on its own handle). REG_NOTIFY_THREAD_
        // AGNOSTIC is a dwNotifyFilter bit (3rd arg), NOT the fAsynchronous flag
        // (5th) - it must be OR'd into the filter or it is silently dropped and
        // the notification dies with this very worker thread, which exits as soon
        // as it returns.
        HKEY h = nullptr;
        const LONG trc = ::RegOpenKeyExW(root, subkey_w.c_str(), 0, KEY_NOTIFY, &h);
        if (trc == ERROR_SUCCESS) {
            r.key.reset(h);
            const LONG nrc = ::RegNotifyChangeKeyValue(r.key.get(), FALSE,
                                                       kNotifyFilter | REG_NOTIFY_THREAD_AGNOSTIC,
                                                       r.event.get(), TRUE /*async*/);
            if (nrc == ERROR_SUCCESS) {
                r.mode = WatchMode::Target;
                r.ok = true;
                return r;
            }
            // The key EXISTS and refused a notify: that is a backend failure to be
            // reported and retried, never a fall-back to the ancestor watch (which
            // would leave an existing key silently unobserved - UP-2).
            r.key.reset();
            r.err = static_cast<DWORD>(nrc);
            r.stage = "RegNotifyChangeKeyValue(target)";
            return r;
        }
        if (trc != ERROR_FILE_NOT_FOUND && trc != ERROR_PATH_NOT_FOUND) {
            // Same rule for the open: only ABSENCE means "watch the ancestor for its
            // creation". Access denied, a locked hive, or any other refusal on an
            // existing key is a Faulted watch on the backend ladder, so the operator
            // sees a deaf key instead of a healthy one (UP-2; the pre-PR-B1 code
            // fell through here too).
            r.err = static_cast<DWORD>(trc);
            r.stage = "RegOpenKeyExW(target, KEY_NOTIFY)";
            return r;
        }
        // Target absent: watch the nearest existing ancestor for its (re)creation.
        // The hive root opens for every caller that reached this far, so the walk
        // ends. The elapsed budget bounds the WALK (started here, after the target
        // open, so a slow-but-healthy hive is not pushed onto the backend ladder by
        // its target open alone - UP-5); a single blocked OS call is not
        // interruptible and holds its lane slot until it returns (UP-3, documented
        // limit; the pre-PR-B1 code held the whole per-type lock for it instead).
        const auto t0 = Clock::now();
        std::string p = parent_path(subkey);
        for (;;) {
            if (Clock::now() - t0 > traversal_budget) {
                r.err = ERROR_TIMEOUT;
                r.stage = "ancestor walk exceeded its traversal budget";
                return r;
            }
            HKEY a = nullptr;
            const std::wstring wp = to_wide(p);
            const LONG rc =
                ::RegOpenKeyExW(root, p.empty() ? nullptr : wp.c_str(), 0, KEY_NOTIFY, &a);
            if (rc == ERROR_SUCCESS) {
                r.key.reset(a);
                const LONG nrc = ::RegNotifyChangeKeyValue(
                    r.key.get(), FALSE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
                    r.event.get(), TRUE /*async*/);
                if (nrc == ERROR_SUCCESS) {
                    r.mode = WatchMode::Ancestor;
                    r.ok = true;
                    return r;
                }
                r.key.reset();
                r.err = static_cast<DWORD>(nrc);
                r.stage = "RegNotifyChangeKeyValue(ancestor)";
                return r;
            }
            if (p.empty()) {
                r.err = static_cast<DWORD>(rc);
                r.stage = "RegOpenKeyExW(hive root, KEY_NOTIFY)";
                return r;
            }
            p = parent_path(p);
        }
    }
};
static_assert(std::is_nothrow_move_constructible_v<ProbeJob>);

/// One watched registry key. Every field is guarded by the mechanism's mu_
/// EXCEPT that a retired watch (active=false, moved into a DrainJob) is owned
/// by its drain worker, which touches only the OS handles - and only after the
/// callback that could be reading the other fields has been drained.
struct RegWatch {
    std::string spark_key;
    HKEY root{nullptr};
    std::string subkey;
    std::wstring subkey_w;
    // committed live resources
    detail::EventHandle event; ///< auto-reset EVENT the live notify signals; `wait` waits on it
    RegKeyHandle open_key;      ///< target in Target mode, ancestor in Ancestor mode
    PTP_WAIT wait{nullptr};     ///< armed at least once => drain before destroy
    WatchMode mode{WatchMode::Target};
    bool armed{false}; ///< a notify + wait is currently established
    bool active{true}; ///< false once retired (unwatch / stop)
    // health (single producer: the sweeper dispatches the edges)
    bool faulted_now{false};
    bool faulted_reported{false};
    const char* fault_reason{""};
    // pending operation
    ProbeState probe{ProbeState::Idle};
    std::uint64_t probe_gen{0}; ///< mechanism-global gen stamped at reservation
    std::optional<DetachedCall<ProbeResult>> call; ///< engaged once a launch is PUBLISHED
    /// Obligation acceptance - grace runs from here and a retry never resets it.
    Clock::time_point accepted_at{};
    Clock::time_point next_retry_at{};
    unsigned backend_attempts{0};
    unsigned admission_attempts{0};
    bool grace_counted{false};
    bool needs_resync{false};
    std::uint64_t resync_epoch{0};
    /// Establishment-signal state (rung 9c PR-6 item 1), all under mu_ like
    /// everything else in this struct. `incarnation` identifies WHICH watch a
    /// staged/dispatched report is about — forward-only rebind (never
    /// decreases); `coverage`/`coverage_at` are the LAST-MARKED transition (set
    /// by every coverage-transition site, never gated on the prior value);
    /// `coverage_report_due` is the sweep's staging flag, cleared only after
    /// the entry is pushed into SweepWork::established.
    SparkIncarnation incarnation{kNoSparkIncarnation};
    SparkCoverage coverage{SparkCoverage::None};
    Clock::time_point coverage_at{};
    bool coverage_report_due{false};
    /// The outstanding re-arm was fire-triggered while in Ancestor mode. If it
    /// commits in Target mode the key APPEARED, which the base mechanism emitted
    /// (`old_mode == Target || w.mode == Target`) and this one must too. Kept as
    /// its own bit, NOT derived from `armed` (on_fire clears `armed` before the
    /// probe is even launched, so `armed` cannot tell a fire-triggered commit
    /// from an initial establishment). Survives a failed probe; cleared only by
    /// a successful commit.
    bool rearm_from_ancestor{false};
    /// Resync debt whose Emit submit THREW (SparkEmitFn can - see its declaration)
    /// is restored and re-staged on this schedule, never at the sweep cadence.
    unsigned resync_attempts{0};
    Clock::time_point resync_retry_at{};
    WindowsRegistryMechanism* owner{nullptr};
    /// Intrusive link while this RETIRED watch waits for a drain worker: the
    /// allocation-free backlog a refused or untrackable drain launch parks it on
    /// (governance sg-1/cs-1: no inline drain anywhere, ever). Guarded by mu_; a
    /// listed watch is owned by the list.
    RegWatch* lost_next{nullptr};

    ~RegWatch(); // drain_watch() safety net - see below
};

/// Disarm + drain + close a watch's wait, then close its handles. Blocking
/// (WaitForThreadpoolWaitCallbacks waits for a running callback), so it runs
/// only on a drain worker, or inline in stop(), never under mu_. Idempotent.
/// A pending probe call inside the watch is destroyed with the watch: that is
/// an abandon(), so its worker self-disposes whatever it eventually produced.
void drain_watch(RegWatch& w) noexcept {
    if (w.wait) {
        ::SetThreadpoolWait(w.wait, nullptr, nullptr);
        ::WaitForThreadpoolWaitCallbacks(w.wait, TRUE);
        ::CloseThreadpoolWait(w.wait);
        w.wait = nullptr;
    }
    w.open_key.reset();
    w.event.reset();
}

RegWatch::~RegWatch() {
    // Safety net only: every designed destruction path (DrainJob, stop()) has
    // already drained. Kept so a future path that forgets cannot leave an
    // armed wait pointing at freed memory.
    drain_watch(*this);
}

/// The detached retirement: owns the RegWatch, drains it, frees it. The result
/// is a unit value - the sweeper only needs to learn "done" to shrink retiring_.
struct DrainJob {
    std::unique_ptr<RegWatch> w;
    std::monostate operator()() noexcept {
        if (w)
            drain_watch(*w);
        w.reset();
        return {};
    }
};
static_assert(std::is_nothrow_move_constructible_v<DrainJob>);

/// Everything one sweep pass wants to do OUTSIDE mu_: launches, dispatch, and
/// the disposal of anything whose destructor closes an OS handle or abandons a
/// call. Destroyed only with mu_ released.
struct SweepWork {
    struct ProbeLaunch {
        std::string key;
        std::uint64_t gen{0};
        std::optional<ProbeJob> job;
        DetachedLaunch status{DetachedLaunch::LaunchFailed};
        std::optional<DetachedCall<ProbeResult>> call;
    };
    struct Action {
        enum class Kind : std::uint8_t { Fault, Emit } kind{Kind::Emit};
        std::string key;
        bool faulted{false};
        const char* reason{""};
        std::uint64_t epoch{0};
        /// Fault actions only: the watch this edge was recorded FOR. The engine
        /// keys health by spark key, so a Fault staged for W1 and dispatched after
        /// Guardian re-created the key (detach + arm = W1') would land on W1' and
        /// stick (UP-1). run_off_lock() re-validates identity under mu_ right
        /// before the call and skips a stale edge.
        RegWatch* watch{nullptr};
    };
    /// A staged establishment-signal report (rung 9c PR-6 item 1). Mirrors
    /// spark_service.cpp's PendingEstablished, minus `key_epoch`: Registry's
    /// staged incarnation IS the identity check (SparkEngine::report_established
    /// drops a report whose incarnation no longer names the key's current
    /// watch), so no separate staleness token is needed here. A SEPARATE
    /// vector, not a new Action::Kind — Action's
    /// positional-brace-init layout stays untouched.
    struct PendingEstablished {
        std::string key;
        SparkIncarnation incarnation{kNoSparkIncarnation};
        Clock::time_point at{};
        SparkCoverage coverage{SparkCoverage::None};
    };
    std::vector<ProbeLaunch> probe_launches;
    std::vector<DrainJob> drain_launches;
    std::vector<Action> actions; ///< in recorded order - per-watch ordering matters
    std::vector<PendingEstablished> established; ///< staged coverage reports, dispatch-first order
    // discards (destroyed off-lock)
    std::vector<detail::EventHandle> old_events;
    std::vector<RegKeyHandle> old_keys;
    std::vector<ProbeResult> dead_results;
    std::vector<DetachedCall<ProbeResult>> stale_calls;
    std::vector<std::unique_ptr<RegWatch>> dead_watches;
    std::vector<std::pair<std::string, std::uint64_t>> failed_emits;    ///< restore needs_resync
    std::vector<std::pair<std::string, std::uint64_t>> succeeded_emits; ///< reset the retry schedule
    /// Captured under mu_ at the top of sweep_locked() (the live member can be
    /// rewritten off-lock by a test at any time - this is the pass's own
    /// snapshot, race-free to read in run_off_lock()). Null outside tests.
    std::shared_ptr<const std::function<void()>> emit_bookkeeping_hook;
};

class WindowsRegistryMechanism final : public ISparkMechanism {
public:
    /// `f3_counter` (may be null) is the agent-lifetime orphan-exit counter every
    /// detached worker this mechanism launches is admitted against (#2012/#3840
    /// PR-B1, F3). Both lanes are constructed here, once - SparkDetachedLane is
    /// non-movable - and keep their identity across start()/stop().
    explicit WindowsRegistryMechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter)
        : probe_lane_(f3_counter, kProbeLaneCap),
          drain_lane_(std::move(f3_counter), kDrainLaneCap) {}
    ~WindowsRegistryMechanism() override {
        stop();
        reap_residual_drains(); // nothing may outlive `this` while holding `owner`
    }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        // One-way seal (rung 9c PR-6 item 1): start() being CALLED is what seals
        // the establishment sink, whether or not this call does anything else —
        // set first, before the idempotent early-return, so a repeat start()
        // can never re-open the window (mirrors spark_service.cpp). Never
        // cleared by stop(): SparkEngine is single-shot, so no production
        // caller ever re-arms the sink after a stop().
        sink_sealed_ = true;
        if (core_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        auto core = std::make_shared<PoolCore>();
        core->pool = ::CreateThreadpool(nullptr);
        if (!core->pool) {
            spdlog::error("spark_registry: CreateThreadpool failed (err={}) — registry sparks inert",
                          ::GetLastError());
            // Publish the inertness: without this the mechanism stays REGISTERED and
            // reports byte-identically to a healthy idle one on the heartbeat, so the
            // fleet sees a registry capability that can never watch anything
            // (governance Gate-3 cross-platform / Gate-6 sre).
            inert_.store(true, std::memory_order_release);
            return;
        }
        // #1907 condition 2: a pinned PRIVATE pool, bounded min=2/max=4 — the
        // watch count, not the thread count, is what scales.
        // Symmetric with spark_file.cpp: clear inert on the SUCCESS path too, or a
        // failed-then-successful start() would report a working mechanism as inert forever
        // and silently drop it from the capability CSV (governance Gate-3 cpp-expert).
        inert_.store(false, std::memory_order_release);
        ::SetThreadpoolThreadMinimum(core->pool, 2);
        ::SetThreadpoolThreadMaximum(core->pool, 4);
        ::InitializeThreadpoolEnvironment(&core->env);
        ::SetThreadpoolCallbackPool(&core->env, core->pool);
        // Every allocation start() needs happens BEFORE core_ is published: a
        // throw here leaves core_ null, so a retried start() is a real retry and
        // never the silent `if (core_) return` no-op (governance sg-7).
        drains_in_flight_.reserve(2 * kDrainLaneCap + 16);
        // PR #4225 review (LOW, test-seam-only): reserved against the
        // COMPILE-TIME cap, but sweep_locked() batches drain_launches against
        // the RUNTIME-overridable drain_lane_cap_ (set_registry_test_controls_
        // for_test). No test today raises drain_lane_cap above kDrainLaneCap
        // (verified - the one override in test_spark_mechanism.cpp sets it to
        // 1, below this constant), so run_off_lock()'s drain_outcomes_.emplace_
        // back stays within this reservation in every case exercised. A future
        // test that raises the cap above kDrainLaneCap would need this reserve
        // raised to match drain_lane_cap_'s new value.
        drain_outcomes_.reserve(kDrainLaneCap);
        core_ = std::move(core);
        stopping_ = false;
        sweeper_stop_ = false;
        nudged_ = false;
        drain_refusals_ = 0;
        drain_retry_at_ = {};
        try {
            sweeper_ = std::thread([this] { sweeper_main(); });
        } catch (...) {
            // No sweeper => no late commits, no retries, no health edges: refuse to
            // run half-alive. The caller (agent boot) treats a throw here as
            // "spark unavailable", which is the honest posture.
            core_.reset();
            throw;
        }
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
        const auto* rp = std::get_if<RegistrySparkParams>(&params);
        if (!rp)
            return std::unexpected("registry mechanism: params are not RegistrySparkParams");
        HKEY root = root_for(rp->hive);
        if (!root)
            return std::unexpected("registry mechanism: unknown hive '" + rp->hive + "'");
        std::wstring subkey_w = to_wide(rp->key); // allocation off mu_

        // 1) Reserve under mu_: the watch exists (so stop() can retire it) but
        //    owns no OS resource yet.
        RegWatch* w = nullptr;
        std::uint64_t gen = 0;
        std::optional<ProbeJob> job;
        {
            std::lock_guard lk(mu_);
            if (!started_ || stopping_)
                return std::unexpected("registry mechanism not started");
            if (auto existing = watches_.find(key); existing != watches_.end()) {
                // Adoption / join (rung 9c PR-6 item 1): the engine
                // skips unwatch() on a renewed key (SparkEngine::disarm() /
                // unregister_consumer()), so without this the fresh incarnation
                // would never be reported and subscription_establishment() would
                // stay default-None for it forever. Forward-only rebind (never
                // decreases); the re-report carries the watch's CURRENT coverage
                // against the NEW incarnation, re-stamped `now()` so a first-wins
                // established_at on the adopting incarnation can never predate its
                // own armed_at. Unlike spark_service.cpp there is no `fired`
                // guard here: the watch's raw coverage is re-reported, so an
                // adoption landing between the OS signal and on_fire() taking
                // mu_ can briefly report Notification for a watch whose
                // notification has already fired (None follows).
                RegWatch& existing_w = *existing->second;
                if (incarnation > existing_w.incarnation)
                    existing_w.incarnation = incarnation;
                existing_w.coverage_at = Clock::now();
                existing_w.coverage_report_due = true;
                nudge_locked();
                return {}; // idempotent (engine dedups, but stay safe)
            }
            if (sweep_cursor_.capacity() < key.size()) {
                // The sweeper assigns the visited key into sweep_cursor_ under mu_;
                // growing it HERE (a throw is an ordinary arm() failure, before any
                // state changed) is what makes that assignment allocation-free.
                try {
                    sweep_cursor_.reserve(key.size() * 2 + 16);
                } catch (...) {
                    return std::unexpected("registry mechanism: allocation failure");
                }
            }
            if (retiring_count_ >= retiring_cap()) {
                watch_rejected_.fetch_add(1, std::memory_order_relaxed);
                return std::unexpected(std::string("registry mechanism: ") +
                                       std::to_string(retiring_count_) +
                                       " watch(es) awaiting callback drain (cap " +
                                       std::to_string(retiring_cap()) +
                                       ") - refusing new watches until the backlog clears");
            }
            auto uw = std::make_unique<RegWatch>();
            uw->spark_key = key;
            uw->root = root;
            uw->subkey = rp->key;
            uw->subkey_w = subkey_w;
            uw->owner = this;
            uw->incarnation = incarnation;
            uw->accepted_at = Clock::now();
            uw->probe = ProbeState::Pending;
            uw->probe_gen = ++gen_;
            gen = uw->probe_gen;
            w = uw.get();
            job.emplace(ProbeJob{root, std::move(subkey_w), rp->key, core_, w, /*create_wait=*/true,
                                 probe_hook_, traversal_budget()});
            watches_.emplace(key, std::move(uw));
        }

        // 2) Launch off-lock; the deadline is computed BEFORE launch so launch
        //    overhead cannot silently extend the wait.
        const auto deadline = Clock::now() + caller_wait_budget();
        auto lr = probe_lane_.launch(std::move(*job));
        std::optional<DetachedCall<ProbeResult>> call;
        std::optional<DetachedResult<ProbeResult>> taken;
        if (lr.status == DetachedLaunch::Launched) {
            probe_launched_.fetch_add(1, std::memory_order_relaxed);
            call = std::move(lr.call);
            taken = call->wait_take(deadline); // the ONE bounded wait - control-path caller only
        }

        // 3) Relock, re-validate, commit / publish / retire.
        std::optional<std::string> error;
        SweepWork discards;
        // This call ever produces AT MOST one of each: reserve before the lock so
        // a push_back below cannot throw AFTER a state change it would then leave
        // half-done (governance cs-8-1 - the same class cf6e96792 closed for the
        // sweeper's own SweepWork, missed here because this one is local to watch()).
        discards.stale_calls.reserve(1);
        discards.dead_results.reserve(1);
        discards.dead_watches.reserve(1);
        {
            std::lock_guard lk(mu_);
            auto it = watches_.find(key);
            const bool live = it != watches_.end() && it->second.get() == w &&
                              w->probe_gen == gen && w->active && !stopping_;
            if (!live) {
                // Reservation cancelled underneath us (stop()). Whatever we hold is
                // ours to discard - off-lock, below.
                if (call) {
                    if (stopping_ && !call->done())
                        quarantined_.fetch_add(1, std::memory_order_relaxed); // sg-6
                    discards.stale_calls.push_back(std::move(*call));
                }
                if (taken && taken->has_value())
                    discards.dead_results.push_back(std::move(**taken));
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
                error = "registry mechanism stopped during watch establishment";
            } else if (lr.status != DetachedLaunch::Launched) {
                // Admission refused: keep the obligation, retry on the admission
                // schedule (never an inline probe under the per-type lock - that
                // would reinstate the unbounded stall on exactly the contended path).
                defer_admission_locked(*w, lr.status);
                w->needs_resync = true;
                w->resync_epoch = ++resync_epoch_;
                nudge_locked();
            } else if (taken) {
                if (taken->has_value() && (*taken)->ok) {
                    // `discards` (this call's local SweepWork) is destroyed
                    // unread at the end of this scope — staging
                    // into it here would be silently dropped. commit_locked()
                    // marks coverage on `w` itself, which survives past this
                    // function's return, so the mark is what carries the
                    // establishment report forward, not anything pushed here.
                    commit_locked(*w, std::move(**taken), discards);
                    // Without this nudge a fast-established watch
                    // would wait up to next_wake_locked()'s 1h idle ceiling
                    // before the sweeper ever visits it to stage the report.
                    nudge_locked();
                } else {
                    // Definite failure while the caller is still here: retire the
                    // insertion and report it - the engine rolls the arm back.
                    error = describe_failure(*taken);
                    if (taken->has_value())
                        discards.dead_results.push_back(std::move(**taken));
                    probe_backend_failed_.fetch_add(1, std::memory_order_relaxed);
                    // No wait was ever armed on it: a plain destroy, off-lock.
                    discards.dead_watches.push_back(std::move(it->second));
                    watches_.erase(it);
                }
            } else {
                // Still outstanding past the caller budget: publish to the sweeper.
                // From here the watch is armed-from-the-engine's-view but not yet
                // watching; a change in this window is caught by the synthetic fire
                // the sweeper emits on commit.
                w->call = std::move(call);
                mark_coverage_locked(*w, SparkCoverage::None);
                w->needs_resync = true;
                w->resync_epoch = ++resync_epoch_;
                nudge_locked();
            }
        }
        // `discards` destroyed here, with mu_ released.
        if (error)
            return std::unexpected(std::move(*error));
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
        auto it = watches_.find(key);
        if (it == watches_.end())
            return;
        // Deliberately NOT reported: the engine has
        // already erased armed_[key] before calling unwatch() (or skipped the
        // call entirely on adoption — watch_incarnation()'s rebind branch
        // above), so a None report from here would be dropped by
        // SparkEngine::report_established's identity check by construction.
        // unwatch() also runs under the engine's per-type lock and must not
        // call established_() synchronously (spark_mechanism.hpp's mechanism
        // contract, the same reentrancy prohibition as emit()/fault()).
        std::unique_ptr<RegWatch> victim = std::move(it->second);
        watches_.erase(it);
        victim->active = false; // no re-arm, no commit, no dispatch from here on
        ++gen_;
        ++retiring_count_;
        retiring_gauge_.fetch_add(1, std::memory_order_relaxed);
        if (victim->call && !victim->call->done())
            probe_discarded_.fetch_add(1, std::memory_order_relaxed); // abandoned with the watch
        // Disarm (cheap, non-blocking; a callback already running keeps running and
        // observes active=false). The blocking drain is the worker's. Held under
        // mu_ TOGETHER with the launch below (governance cs-2): stop()'s swap of
        // drains_in_flight_ either sees this drain or finds the watch already
        // gone, so a drain can never land untracked after stop() took the set.
        if (victim->wait)
            ::SetThreadpoolWait(victim->wait, nullptr, nullptr);
        retire_locked(std::move(victim));
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!core_ && !sweeper_.joinable())
                return;
            stopping_ = true;
            sweeper_stop_ = true;
            nudged_ = true;
        }
        cv_.notify_all();
        if (sweeper_.joinable())
            sweeper_.join(); // outside mu_: the sweeper may be mid-dispatch into the engine

        std::map<std::string, std::unique_ptr<RegWatch>> victims;
        std::vector<DetachedCall<std::monostate>> drains;
        RegWatch* lost = nullptr;
        {
            std::lock_guard lk(mu_);
            for (auto& [k, w] : watches_)
                w->active = false;
            victims.swap(watches_);
            drains.swap(drains_in_flight_);
            lost = take_lost_locked();
            ++gen_;
        }
        // Drain every callback-bearing watch OUTSIDE mu_ - an UNBOUNDED drain, on
        // purpose (parity with spark_file; the #3737 shutdown watchdog is the
        // backstop). These contexts hold `owner`, so they must be gone before the
        // mechanism is. Only an UNCOMMITTED probe - whose captures are independent
        // of this object - may outlive stop(): it is leaked-and-counted.
        for (auto& [k, w] : victims)
            if (w->wait)
                ::SetThreadpoolWait(w->wait, nullptr, nullptr);
        std::uint64_t orphaned = 0;
        for (auto& [k, w] : victims) {
            if (w->call && !w->call->done())
                ++orphaned;
            drain_watch(*w); // explicit: stop() drains; the destructor is only a net
            w.reset();       // a pending call is abandoned with the watch
        }
        while (lost) { // retirements that never got a worker: drain them here
            std::unique_ptr<RegWatch> w(lost);
            lost = w->lost_next;
            if (w->call && !w->call->done())
                ++orphaned; // UP-7: a published probe parked on a backlogged retirement
            drain_watch(*w);
        }
        for (auto& d : drains) {
            unsigned waited_s = 0;
            for (;;) { // wait for the drain worker (unbounded - see above)
                if (d.wait_take(Clock::now() + 1s)) {
                    drains_completed_.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
                if (d.done())
                    break; // already taken (cannot happen - only stop() reaps these)
                if (++waited_s == 5 || waited_s % 30 == 0) // sre-3: a stuck drain is named, not silent
                    spdlog::warn("spark_registry: stop() still waiting for a callback drain after "
                                 "{} s (a callback is parked inside a consumer)",
                                 waited_s);
            }
        }
        if (orphaned)
            quarantined_.fetch_add(orphaned, std::memory_order_relaxed);
        std::lock_guard lk(mu_);
        retiring_count_ = 0;
        retiring_gauge_.store(0, std::memory_order_relaxed);
        core_.reset(); // closes the pool now, or when the last leased worker finishes
        started_ = false;
        emit_ = nullptr;
        fault_ = nullptr;
        established_ = nullptr; // after the sweeper is joined, like emit_/fault_ above
        stopping_ = false;
        sweeper_stop_ = false;
        nudged_ = false;
        sweep_cursor_.clear();
    }

    [[nodiscard]] SparkMechanismStats stats() const override {
        return {
            .retiring = retiring_gauge_.load(std::memory_order_relaxed),
            .retiring_cap = retiring_cap(),
            .watch_rejected_total = watch_rejected_.load(std::memory_order_relaxed),
            .quarantined_total = quarantined_.load(std::memory_order_relaxed),
            .slow_op_total = slow_op_.load(std::memory_order_relaxed),
            .inert = inert_.load(std::memory_order_acquire),
        };
    }

    // ── test seams (spark_mechanism.hpp free functions forward here) ─────────
    void apply_test_controls(RegistryMechanismTestControls c) {
        std::lock_guard lk(mu_);
        if (c.probe_hook)
            probe_hook_ = std::make_shared<const ProbeHook>(std::move(c.probe_hook));
        else
            probe_hook_.reset();
        if (c.sweep_hook)
            sweep_hook_ = std::make_shared<const std::function<void()>>(std::move(c.sweep_hook));
        else
            sweep_hook_.reset();
        if (c.emit_bookkeeping_hook)
            emit_bookkeeping_hook_ =
                std::make_shared<const std::function<void()>>(std::move(c.emit_bookkeeping_hook));
        else
            emit_bookkeeping_hook_.reset();
        if (c.probe_lane_cap)
            probe_lane_.set_cap_for_test(c.probe_lane_cap);
        if (c.drain_lane_cap) {
            drain_lane_.set_cap_for_test(c.drain_lane_cap);
            drain_lane_cap_.store(c.drain_lane_cap, std::memory_order_relaxed);
        }
        if (c.retiring_cap)
            retiring_cap_.store(c.retiring_cap, std::memory_order_relaxed);
        if (c.caller_wait_budget.count() > 0)
            caller_wait_ms_.store(c.caller_wait_budget.count(), std::memory_order_relaxed);
        if (c.health_grace.count() > 0)
            health_grace_ms_.store(c.health_grace.count(), std::memory_order_relaxed);
        if (c.backend_retry_base.count() > 0)
            backend_retry_base_ms_.store(c.backend_retry_base.count(), std::memory_order_relaxed);
        if (c.admission_backoff_seed.count() > 0)
            admission_seed_ms_.store(c.admission_backoff_seed.count(), std::memory_order_relaxed);
        if (c.sweep_cadence.count() > 0)
            sweep_cadence_ms_.store(c.sweep_cadence.count(), std::memory_order_relaxed);
        nudge_locked();
    }

    [[nodiscard]] RegistryMechanismDebugCounters debug_counters() const {
        RegistryMechanismDebugCounters d;
        d.probe_launched = probe_launched_.load(std::memory_order_relaxed);
        d.probe_admission_rejected = probe_admission_rejected_.load(std::memory_order_relaxed);
        d.probe_launch_failed = probe_launch_failed_.load(std::memory_order_relaxed);
        d.probe_backend_failed = probe_backend_failed_.load(std::memory_order_relaxed);
        d.probe_discarded = probe_discarded_.load(std::memory_order_relaxed);
        d.drains_launched = drains_launched_.load(std::memory_order_relaxed);
        d.drains_completed = drains_completed_.load(std::memory_order_relaxed);
        d.drains_admission_rejected = drains_admission_rejected_.load(std::memory_order_relaxed);
        d.synthetic_fires = synthetic_fires_.load(std::memory_order_relaxed);
        d.health_edges = health_edges_.load(std::memory_order_relaxed);
        d.emit_failed = emit_failed_.load(std::memory_order_relaxed);
        d.resync_retries = resync_retries_.load(std::memory_order_relaxed);
        d.established_failed = established_failed_.load(std::memory_order_relaxed);
        d.probe_workers_active = probe_lane_.active_workers();
        d.drain_workers_active = drain_lane_.active_workers();
        std::lock_guard lk(mu_);
        d.live_watches = watches_.size();
        d.retiring = retiring_count_;
        d.drain_backlog = lost_count_;
        d.drains_untracked = drains_untracked_.load(std::memory_order_relaxed);
        d.fault_failed = fault_failed_.load(std::memory_order_relaxed);
        d.sweep_pass_failed = sweep_pass_failed_.load(std::memory_order_relaxed);
        return d;
    }

    // Called from the TP_WAIT callback (reg_on_wait_cb) with `w` guaranteed live.
    void on_fire(RegWatch& w) {
        bool do_emit = false;
        std::optional<ProbeJob> job;
        std::uint64_t gen = 0;
        {
            std::lock_guard lk(mu_);
            if (!w.active || stopping_)
                return; // being torn down - no re-arm, no dispatch
            const WatchMode old_mode = w.mode;
            // Build the re-arm job (two string copies) BEFORE any state changes: this
            // runs inside a TP_WAIT callback where an escaping std::bad_alloc is
            // process death (ce-1/cs-3). On failure the notification is consumed
            // into a Deferred re-arm with scalar-only bookkeeping and the sweeper
            // retries; the observation gap is recorded as usual and covered by the
            // synthetic fire on commit.
            if (w.probe == ProbeState::Idle) {
                try {
                    job.emplace(ProbeJob{w.root, w.subkey_w, w.subkey, core_, &w,
                                         /*create_wait=*/w.wait == nullptr, probe_hook_,
                                         traversal_budget()});
                } catch (...) {
                    w.armed = false;
                    if (old_mode == WatchMode::Target) {
                        w.needs_resync = true;
                        w.resync_epoch = ++resync_epoch_;
                    } else {
                        w.rearm_from_ancestor = true;
                    }
                    w.accepted_at = Clock::now();
                    w.grace_counted = false;
                    defer_admission_locked(w, DetachedLaunch::LaunchFailed);
                    nudge_locked();
                    return;
                }
            }
            w.armed = false; // this notification is consumed; the watch must re-establish
            // RegNotifyChangeKeyValue is one-shot: every
            // consumed notification is a genuine coverage loss, Target mode or
            // Ancestor mode alike, until the re-arm below commits. Unconditional
            // - the mode gate lives only at commit_locked's positive site.
            mark_coverage_locked(w, SparkCoverage::None);
            // Emit when the key existed before this fire (it changed / was deleted).
            // The (re)appearance case - Ancestor mode resolving to Target - is only
            // knowable at commit: `rearm_from_ancestor` carries it there. Pure-
            // ancestor noise (a sibling changed while our target stays absent)
            // emits nowhere.
            do_emit = (old_mode == WatchMode::Target);
            if (old_mode == WatchMode::Target) {
                // Observation gap: from now until the re-arm commits, a change on
                // the key is not observed - the commit's synthetic fire covers it.
                w.needs_resync = true;
                w.resync_epoch = ++resync_epoch_;
            } else {
                w.rearm_from_ancestor = true;
            }
            if (job) {
                w.probe = ProbeState::Pending;
                w.probe_gen = ++gen_;
                gen = w.probe_gen;
                w.accepted_at = Clock::now();
                w.grace_counted = false;
            } else {
                // A probe is already outstanding (Pending/Deferred) - it will
                // re-establish; launching a second one would duplicate the
                // obligation. Nothing else in this branch wakes the sweeper for
                // the coverage mark just staged above (the `if (job)` branch's
                // own off-lock launch reaches its own nudge further down), so
                // nudge explicitly here.
                nudge_locked();
            }
        }
        std::optional<DetachedCall<ProbeResult>> stale;
        if (job) {
            // Launch-and-poll (amendment 8): never park one of the four pool
            // threads waiting on a probe. The sweeper commits the result.
            auto lr = probe_lane_.launch(std::move(*job));
            std::lock_guard lk(mu_);
            if (w.active && !stopping_ && w.probe == ProbeState::Pending && w.probe_gen == gen &&
                !w.call) {
                if (lr.status == DetachedLaunch::Launched) {
                    probe_launched_.fetch_add(1, std::memory_order_relaxed);
                    w.call = std::move(lr.call);
                } else {
                    defer_admission_locked(w, lr.status);
                }
                nudge_locked();
            } else if (lr.call) {
                stale = std::move(lr.call); // reservation cancelled (retired) - abandon off-lock
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
                if (stopping_ && !stale->done())
                    quarantined_.fetch_add(1, std::memory_order_relaxed); // sg-6: parked across stop
            }
        }
        // Fire with mu_ RELEASED: emit re-enters the engine under its own lock, and
        // an inline consumer re-arming would take our mu_ -> deadlock if held.
        // GUARDED: this runs inside a TP_WAIT callback, where an escaping exception
        // is process death, and SparkEmitFn can throw (std::bad_alloc from the
        // engine's own copies / queue push - see its declaration). The debt is
        // already recorded under mu_ above (`needs_resync`, set on exactly the
        // `do_emit` path), so a lost immediate fire is covered by the commit's
        // synthetic fire.
        // emit_ is read without a copy: stop() nulls it only after every callback
        // has been drained, so no write can race this read (ce-1).
        if (do_emit && emit_) {
            try {
                emit_(w.spark_key, SparkData{std::monostate{}});
            } catch (...) {
                emit_failed_.fetch_add(1, std::memory_order_relaxed);
                try {
                    spdlog::warn("spark_registry: emit for '{}' threw from the fire callback - "
                                 "the re-arm's synthetic fire covers it",
                                 ::yuzu::log_key_token(w.spark_key));
                } catch (...) {
                }
            }
        }
        // `stale` (if any) destroyed here: an abandon, the worker self-disposes.
    }

private:
    // ── tunables (atomics so the test seam can override without a rebuild) ──
    [[nodiscard]] std::chrono::milliseconds caller_wait_budget() const {
        return std::chrono::milliseconds(caller_wait_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds health_grace() const {
        return std::chrono::milliseconds(health_grace_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds sweep_cadence() const {
        return std::chrono::milliseconds(sweep_cadence_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds backend_retry_base() const {
        return std::chrono::milliseconds(backend_retry_base_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds admission_seed() const {
        return std::chrono::milliseconds(admission_seed_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds traversal_budget() const {
        return kRegProbeTraversalBudget;
    }
    [[nodiscard]] std::size_t retiring_cap() const {
        return retiring_cap_.load(std::memory_order_relaxed);
    }

    void nudge_locked() {
        nudged_ = true;
        cv_.notify_one();
    }

    /// Coverage-transition marker (rung 9c PR-6 item 1):
    /// every coverage-transition site calls this and nothing else — three
    /// scalar writes, unconditional, never gated on the watch's prior
    /// coverage (there is no "edge" logic anywhere in this mechanism).
    /// Staging into SweepWork::established happens exactly once, later, at
    /// the sweep visit (sweep_locked()); dispatch happens exactly once, later
    /// still, in run_off_lock() with mu_ released (the established_ sink is
    /// never called from here, or from any of this function's callers).
    /// noexcept: reached from the noexcept recovery paths
    /// (reconcile_probe_launches_locked(), on_fire()'s TP_WAIT-callback catch)
    /// where an escaping exception is process death; std::chrono::steady_clock::now()
    /// is itself noexcept, so three scalar writes is all this may ever be.
    static void mark_coverage_locked(RegWatch& w, SparkCoverage c) noexcept {
        w.coverage = c;
        w.coverage_at = Clock::now();
        w.coverage_report_due = true;
    }

    static std::string describe_failure(const DetachedResult<ProbeResult>& r) {
        if (!r.has_value()) {
            switch (r.error()) {
            case DetachedCallError::WorkerThrew:
                return "registry mechanism: probe threw";
            case DetachedCallError::ResultAllocFailed:
                return "registry mechanism: probe result could not be boxed";
            }
            return "registry mechanism: probe failed";
        }
        return std::string("registry mechanism: could not arm any watch for the key (") + r->stage +
               ", err=" + std::to_string(r->err) + ")";
    }

    static std::chrono::milliseconds doubled(std::chrono::milliseconds base, unsigned attempts,
                                             std::chrono::milliseconds cap) {
        // base * 2^(attempts-1), saturating at cap (attempts >= 1).
        std::chrono::milliseconds d = base;
        for (unsigned i = 1; i < attempts && d < cap; ++i)
            d *= 2;
        return std::min(d, cap);
    }

    /// Admission refused (lane cap / launch failure): keep the obligation, retry
    /// on the admission schedule. Never counts as a backend attempt. Under mu_.
    void defer_admission_locked(RegWatch& w, DetachedLaunch status) {
        if (status == DetachedLaunch::Rejected)
            probe_admission_rejected_.fetch_add(1, std::memory_order_relaxed);
        else
            probe_launch_failed_.fetch_add(1, std::memory_order_relaxed);
        w.probe = ProbeState::Deferred;
        w.call.reset(); // nothing published (a launched call is never handed here)
        ++w.admission_attempts;
        w.next_retry_at = Clock::now() + doubled(admission_seed(), w.admission_attempts,
                                                 kRegAdmissionBackoffCap);
        // No coverage established on this path, in every calling context
        // (watch_incarnation's admission-refused branch, on_fire's job-throw
        // catch and re-arm-launch-refused branch, reconcile_probe_launches_
        // locked()'s noexcept recovery) - mark unconditionally.
        mark_coverage_locked(w, SparkCoverage::None);
    }

    /// Genuine backend failure: retry on the 30 s doubling schedule, report the
    /// watch Faulted (the sweeper dispatches the edge). Under mu_.
    void fail_backend_locked(RegWatch& w, const char* reason) {
        probe_backend_failed_.fetch_add(1, std::memory_order_relaxed);
        w.probe = ProbeState::Deferred;
        w.call.reset();
        ++w.backend_attempts;
        w.next_retry_at = Clock::now() + doubled(backend_retry_base(), w.backend_attempts,
                                                 kRegBackendRetryCap);
        if (!w.faulted_now) {
            w.faulted_now = true;
            w.fault_reason = reason;
        }
        // Genuine backend failure - no coverage, in every calling context
        // (commit_locked's no-TP_WAIT branch, resolve_probe_locked's failure
        // branch) - mark unconditionally.
        mark_coverage_locked(w, SparkCoverage::None);
        spdlog::warn("spark_registry: establishing '{}' failed ({}) - watch is deaf until the retry",
                     ::yuzu::log_key_token(w.spark_key), reason);
    }

    /// A probe result for a LIVE watch, matched by generation. Under mu_; every
    /// handle it supersedes goes into `work` for off-lock disposal.
    void commit_locked(RegWatch& w, ProbeResult res, SweepWork& work) {
        w.probe = ProbeState::Idle;
        w.call.reset();
        if (!w.wait)
            w.wait = res.wait.release(); // initial establishment brought its own wait
        if (!w.wait) {
            work.dead_results.push_back(std::move(res));
            fail_backend_locked(w, "no TP_WAIT to arm");
            return;
        }
        // Retire the superseded key/event (closing the old key signals the OLD
        // event, which is exactly why each probe brings its own) - off-lock.
        if (w.event)
            work.old_events.push_back(std::move(w.event));
        if (w.open_key)
            work.old_keys.push_back(std::move(w.open_key));
        w.event = std::move(res.event);
        w.open_key = std::move(res.key);
        w.mode = res.mode;
        ::SetThreadpoolWait(w.wait, w.event.get(), nullptr); // the ONLY place a wait is armed
        w.armed = true;
        w.backend_attempts = 0;
        w.admission_attempts = 0;
        w.grace_counted = false;
        // The one positive coverage site: Target mode has live OS-level
        // notification coverage, Ancestor mode does not (it watches the PARENT
        // for the target's appearance, not the target itself) - unconditional
        // gate on res.mode alone, never special-cased away for Ancestor:
        // a Target -> Ancestor transition (the target was deleted; the re-arm
        // resolved to the parent) is a real coverage loss that must overwrite
        // whatever Notification the engine has cached. This single line also
        // covers the Ancestor -> Target appearance case below (w.mode is
        // already the new mode here) and the ordinary re-arm-stays-Target case.
        mark_coverage_locked(w, w.mode == WatchMode::Target ? SparkCoverage::Notification
                                                             : SparkCoverage::None);
        if (w.faulted_now) {
            w.faulted_now = false;
            w.fault_reason = "recovered";
        }
        // Appearance: a fire-triggered re-arm that left Ancestor mode and landed on
        // the target. Folded into the resync obligation (fresh epoch) so it takes
        // the one Emit staging path below - and its restore-on-throw handling.
        // An initial establishment never sets the bit, so it never emits here.
        if (w.rearm_from_ancestor && w.mode == WatchMode::Target) {
            w.needs_resync = true;
            w.resync_epoch = ++resync_epoch_;
        }
        w.rearm_from_ancestor = false;
        if (w.needs_resync) {
            work.actions.push_back(
                {SweepWork::Action::Kind::Emit, w.spark_key, false, "", w.resync_epoch});
            w.needs_resync = false; // submitted below; restored only if the submit throws
            synthetic_fires_.fetch_add(1, std::memory_order_relaxed);
        }
        // `res` (now holding only the pool lease) drops here - not the last ref.
    }

    void resolve_probe_locked(RegWatch& w, DetachedResult<ProbeResult> r, SweepWork& work) {
        if (r.has_value() && r->ok) {
            commit_locked(w, std::move(*r), work);
            return;
        }
        // The fault channel carries the CLASS (fault_reason is a static const
        // char*); the specific stage and Win32 error go to the log line, read
        // BEFORE the result is moved out for off-lock disposal (ca-1).
        const char* reason = "registry establishment failed";
        if (!r.has_value()) {
            reason = r.error() == DetachedCallError::WorkerThrew
                         ? "registry probe threw"
                         : "registry probe result could not be boxed";
        } else {
            reason = w.wait ? "registry re-arm failed" : "registry establishment failed";
            spdlog::warn("spark_registry: probe for '{}' failed at {} (err={})",
                         ::yuzu::log_key_token(w.spark_key), r->stage, r->err);
            work.dead_results.push_back(std::move(*r));
        }
        fail_backend_locked(w, reason);
    }

    void grace_check_locked(RegWatch& w, Clock::time_point now) {
        if (w.grace_counted || now - w.accepted_at <= health_grace())
            return;
        w.grace_counted = true;
        // slow_op_total has exactly one meaning here: an obligation missed its grace.
        slow_op_.fetch_add(1, std::memory_order_relaxed);
        if (!w.faulted_now) {
            w.faulted_now = true;
            w.fault_reason = "registry watch establishment pending past grace";
        }
    }

    [[nodiscard]] Clock::time_point next_wake_locked(Clock::time_point now) const {
        auto wake = now + std::chrono::hours(1);
        const auto cadence = sweep_cadence();
        const auto grace = health_grace();
        for (const auto& [k, w] : watches_) {
            // A marked-but-not-yet-staged coverage report must be
            // picked up on the very next pass, never left for an idle watch's
            // 1h default ceiling. Checked BEFORE the switch (not after it,
            // like the grace check below) because the Idle case `continue`s
            // past everything that follows the switch.
            if (w->coverage_report_due)
                wake = std::min(wake, now);
            switch (w->probe) {
            case ProbeState::Pending:
                wake = std::min(wake, now + cadence);
                break;
            case ProbeState::Deferred:
                wake = std::min(wake, w->next_retry_at);
                break;
            case ProbeState::Idle:
                if (w->armed && w->needs_resync)
                    wake = std::min(wake, w->resync_retry_at); // restored debt, on its backoff
                continue;
            }
            if (!w->grace_counted)
                wake = std::min(wake, w->accepted_at + grace);
        }
        if (!drains_in_flight_.empty())
            wake = std::min(wake, now + cadence);
        if (lost_head_)
            wake = std::min(wake, std::max(drain_retry_at_, now + cadence));
        return wake;
    }

    /// One pass under mu_: reap finished drains, pick backlog drains to relaunch,
    /// visit watches under an item/time budget (rotating cursor), record health
    /// edges. Everything blocking or dispatching is deferred into `work`.
    void sweep_locked(SweepWork& work) {
        const auto t_start = Clock::now();
        work.emit_bookkeeping_hook = emit_bookkeeping_hook_; // shared_ptr copy: nothrow
        // RESERVE BEFORE MUTATE (governance sg-7/cs-3): every container this pass
        // can push into is sized here, before any state changes (including the lost-list unlink below), so a
        // std::bad_alloc surfaces with nothing half-done - the pass-level catch in
        // sweeper_main() then retries with the state exactly as it was. Bounds: at
        // most `cap` watches are visited per pass; each visit stages <= 2 actions
        // (one Emit, one Fault edge), <= 1 launch, <= 1 superseded event/key, <= 1
        // dead result, <= 1 stale call.
        const std::size_t cap = std::min(watches_.size(), kSweepMaxItems) + 1;
        work.actions.reserve(2 * cap); // Emit + health edge per visit
        work.succeeded_emits.reserve(2 * cap);
        work.failed_emits.reserve(2 * cap);
        work.probe_launches.reserve(cap);
        work.old_events.reserve(cap);
        work.old_keys.reserve(cap);
        work.dead_results.reserve(cap);
        work.stale_calls.reserve(cap + kDrainLaneCap);
        work.drain_launches.reserve(drain_lane_cap_.load(std::memory_order_relaxed));
        work.established.reserve(cap); // rung 9c PR-6 item 1: one entry per visited watch
        if (sweep_hook_ && *sweep_hook_)
            (*sweep_hook_)(); // test seam: a throw here models an allocation failure

        for (auto it = drains_in_flight_.begin(); it != drains_in_flight_.end();) {
            if (it->try_take()) {
                it = drains_in_flight_.erase(it);
                if (retiring_count_)
                    --retiring_count_;
                retiring_gauge_.fetch_sub(1, std::memory_order_relaxed);
                drains_completed_.fetch_add(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
        if (lost_head_ && Clock::now() >= drain_retry_at_) {
            // Batch size is the lane's OWN cap (overridable for tests), never the
            // compile-time constant: relaunching more than the lane can actually
            // admit wastes a launch()/reject()/re-park round trip per excess item.
            const std::size_t lane_cap = drain_lane_cap_.load(std::memory_order_relaxed);
            // Tracking capacity BEFORE unlinking: a throw here leaves the list intact.
            if (drains_in_flight_.size() + lane_cap > drains_in_flight_.capacity())
                drains_in_flight_.reserve(drains_in_flight_.size() + 2 * lane_cap);
            while (lost_head_ && work.drain_launches.size() < lane_cap) {
                RegWatch* w = lost_head_;
                lost_head_ = w->lost_next;
                w->lost_next = nullptr;
                --lost_count_;
                work.drain_launches.push_back(DrainJob{std::unique_ptr<RegWatch>(w)}); // in capacity
            }
        }

        if (watches_.empty())
            return;
        auto it = sweep_cursor_.empty() ? watches_.begin() : watches_.upper_bound(sweep_cursor_);
        std::size_t visited = 0;
        for (std::size_t n = 0; n < watches_.size(); ++n) {
            if (it == watches_.end())
                it = watches_.begin();
            // Budget check BEFORE the cursor moves past this entry, so a truncated
            // pass resumes AT the unprocessed watch, never one past it (ce-2).
            if (++visited > kSweepMaxItems || Clock::now() - t_start > kSweepTimeBudget) {
                nudged_ = true; // resume from the cursor without sleeping
                break;
            }
            RegWatch& w = *it->second;
            sweep_cursor_ = it->first; // capacity pre-grown in watch(): no allocation here
            ++it;
            const auto now = Clock::now();
            // Drain the coverage marker BEFORE the switch: if the switch below
            // commits Notification in
            // this SAME visit (a Deferred retry resolving synchronously would
            // not - probe launches are always off-lock - but a future direct
            // caller must not silently break this), draining after would
            // overwrite the just-staged None and it would never be reported.
            // push_back (the key string copy, can throw) BEFORE clearing
            // `due` (mirrors the Fault-edge staging below):
            // a throw here leaves the marker set, so the NEXT pass re-attempts
            // rather than silently believing the report already went out.
            if (w.coverage_report_due) {
                work.established.push_back(
                    {w.spark_key, w.incarnation, w.coverage_at, w.coverage});
                w.coverage_report_due = false;
            }
            switch (w.probe) {
            case ProbeState::Pending:
                if (w.call) {
                    if (auto r = w.call->try_take()) {
                        w.call.reset(); // taken: dispose_or_abandon is a no-op now
                        resolve_probe_locked(w, std::move(*r), work);
                    } else {
                        grace_check_locked(w, now);
                    }
                }
                // Pending with no call: a launch is in progress on another thread.
                break;
            case ProbeState::Deferred:
                if (now >= w.next_retry_at) {
                    // Build + stage the launch FIRST (the ProbeJob copies two strings):
                    // a throw leaves the watch Deferred and retried next pass, never
                    // Pending-with-no-call (sg-7's own warning against a bare catch).
                    work.probe_launches.push_back(
                        {w.spark_key, gen_ + 1,
                         ProbeJob{w.root, w.subkey_w, w.subkey, core_, &w,
                                  /*create_wait=*/w.wait == nullptr, probe_hook_,
                                  traversal_budget()},
                         DetachedLaunch::LaunchFailed, std::nullopt});
                    w.probe = ProbeState::Pending;
                    w.probe_gen = ++gen_;
                } else {
                    grace_check_locked(w, now);
                }
                break;
            case ProbeState::Idle:
                // Restored resync debt (its Emit submit threw): re-stage on the
                // backoff publish_locked() set, not at every sweep. Only while the
                // watch is established - an un-armed watch has a probe outstanding
                // and its commit stages the debt itself.
                if (w.armed && w.needs_resync && now >= w.resync_retry_at) {
                    work.actions.push_back(
                        {SweepWork::Action::Kind::Emit, w.spark_key, false, "", w.resync_epoch});
                    w.needs_resync = false;
                    resync_retries_.fetch_add(1, std::memory_order_relaxed);
                }
                break;
            }
            if (w.faulted_now != w.faulted_reported) {
                // Stage the record BEFORE flipping state (PR #4225 review,
                // same root cause as the probe-launch fix above): push_back's
                // capacity is reserved but the Action's own string-key copy
                // can still throw. Ordered this way, a throw here leaves
                // faulted_reported untouched, so the NEXT pass simply
                // re-attempts this same edge instead of believing (wrongly)
                // that it was already reported.
                work.actions.push_back({SweepWork::Action::Kind::Fault, w.spark_key, w.faulted_now,
                                        w.fault_reason, 0, &w});
                w.faulted_reported = w.faulted_now;
                health_edges_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    /// Off-lock half of a pass: launches, then dispatch in recorded order.
    void run_off_lock(SweepWork& work) {
        const bool had_probe_launches = !work.probe_launches.empty();
        for (auto& pl : work.probe_launches) {
            auto lr = probe_lane_.launch(std::move(*pl.job));
            pl.job.reset();
            pl.status = lr.status;
            pl.call = std::move(lr.call);
        }
        // PR #4225 review: nothing below this point is wrapped in a try/catch
        // that would keep a throw from escaping run_off_lock() entirely - the
        // actions loop's own try/catch(...) absorbs a throw from emit_()/
        // fault_() or from staging succeeded_emits/failed_emits, but a throw
        // from drain-outcome bookkeeping, or ANY throw at this exact point,
        // propagates straight out. If a probe launch above already succeeded
        // (its `pl.job` is now reset), the caller's catch handler must still
        // reconcile it - see reconcile_probe_launches_locked()'s doc comment.
        // The test-only hook below (fired only on a pass that actually staged
        // a launch, so a test can arm it once, up front, with no timing race
        // against the sweeper) models exactly that interleaving without
        // needing a genuine allocation failure.
        if (had_probe_launches && work.emit_bookkeeping_hook && *work.emit_bookkeeping_hook)
            (*work.emit_bookkeeping_hook)();
        // drain_outcomes_ is reserved to kDrainLaneCap in start() and cleared by
        // publish_locked(); drain_launches never exceeds that cap, so these
        // emplacements do not allocate (sweeper-private scratch).
        for (auto& dj : work.drain_launches) {
            auto lr = drain_lane_.launch(std::move(dj));
            if (lr.status == DetachedLaunch::Launched)
                drain_outcomes_.emplace_back(lr.status, std::move(*lr.call));
            else
                drain_outcomes_.emplace_back(lr.status, std::move(*lr.fn));
        }
        work.drain_launches.clear();

        // Dispatch establishment reports before this pass's emits/faults
        // (rung 9c PR-6 item 1; same order as spark_service.cpp). What that
        // order guarantees: within ONE dispatch pass, `work.established` is
        // delivered before that pass's own emits/faults. It does NOT cover a
        // commit's own Notification: the commit stages its Emit in this visit
        // but re-marks coverage after the visit's drain, so the Notification
        // is staged one pass AFTER that Emit. Nor does it cover the immediate
        // emit from on_fire(). established_ is read by
        // reference, no copy, no mu_ - the write happens-before this thread
        // exists (set_established_sink(), pre-seal, under mu_) and the only
        // later write is stop()'s null-out, after this thread has been
        // joined. A throw on one report is counted (established_failed_; the
        // first one is also logged) and the report is dropped, NOT re-staged:
        // the engine's cache keeps the last delivered value until the next
        // transition of that key, and a persistent throw would otherwise spin
        // the sweeper.
        // This DIVERGES from spark_service.cpp by design: Service has no
        // per-call catch, so a throw there reaches its run() catch, which
        // invalidates every key to None; here the sweeper never exits on an
        // exception, so no such invalidation exists. (A throw elsewhere in the
        // pass is different: unwind_pass_locked re-marks every staged report.)
        // No key_epoch/staleness re-check is needed: the staged incarnation IS
        // the identity, and SparkEngine::report_established drops any report
        // whose incarnation no longer names the key's current watch.
        if (established_) {
            for (const auto& e : work.established) {
                try {
                    established_(e.key, e.incarnation, e.at, e.coverage);
                } catch (...) {
                    // Log only the FIRST drop; the rest are counted. The log
                    // itself must never throw out of this handler.
                    if (established_failed_.fetch_add(1, std::memory_order_relaxed) == 0) {
                        try {
                            spdlog::warn("spark_registry: an establishment report for '{}' was "
                                         "dropped (sink threw); further drops are not logged",
                                         ::yuzu::log_key_token(e.key));
                        } catch (...) {
                        }
                    }
                }
            }
        }

        // emit_/fault_ are read here with mu_ released: they are written only by
        // start() (before this thread exists) and by stop() after this thread has
        // been joined, so no copy is needed - and a std::function copy under mu_
        // was an allocation the sweeper must not make (governance cs-3).
        for (const auto& a : work.actions) {
            try {
                if (a.kind == SweepWork::Action::Kind::Fault) {
                    if (!fault_action_still_current(a))
                        continue; // UP-1: the key was re-created since this edge was staged
                    if (fault_)
                        fault_(a.key, a.faulted, a.reason);
                } else if (emit_) {
                    emit_(a.key, SparkData{std::monostate{}});
                    // PR #4225 review: the vector's CAPACITY is reserved (no
                    // reallocation), but constructing the pair's std::string
                    // key here is a separate heap allocation reserve() does
                    // not cover - this can throw, and IS caught by this
                    // action's own catch(...) below (converted to a counted
                    // failed_emits entry) rather than escaping run_off_lock()
                    // - the run_off_lock()-escaping case this PR fixes is
                    // modelled by the hook near the top of that function
                    // instead, since only a throw with no enclosing catch
                    // reaches unwind_pass_locked() with a probe already
                    // launched.
                    work.succeeded_emits.emplace_back(a.key, a.epoch);
                }
            } catch (...) {
                if (a.kind == SweepWork::Action::Kind::Emit) {
                    emit_failed_.fetch_add(1, std::memory_order_relaxed);
                    work.failed_emits.emplace_back(a.key, a.epoch); // same allocation caveat as above
                } else {
                    fault_failed_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    }

    /// A staged health edge is dispatched only if the key still maps to the very
    /// watch it was recorded for and that watch still wants that state reported
    /// (a same-key re-arm in between would otherwise inherit W1's edge - UP-1).
    /// A short mu_ acquisition off the sweeper's own lock; never blocks.
    [[nodiscard]] bool fault_action_still_current(const SweepWork::Action& a) {
        std::lock_guard lk(mu_);
        auto it = watches_.find(a.key);
        if (it == watches_.end() || it->second.get() != a.watch)
            return false;
        const RegWatch& w = *it->second;
        return w.active && w.faulted_reported == a.faulted && w.faulted_now == a.faulted;
    }

    /// Resolve every staged probe launch, under mu_. Shared by the normal-pass
    /// path (publish_locked, where run_off_lock() ran its launch loop to
    /// completion so every entry's `pl.job` is already reset) and the
    /// threw-mid-pass recovery path (unwind_pass_locked, where the launch loop
    /// may have been aborted partway through - some entries launched, some
    /// not). An entry whose `pl.job` is still populated never reached the
    /// launch call at all: defer it exactly as sweep_locked staged it, same as
    /// before. An entry whose `pl.job` is empty already ran the real launch
    /// (`pl.status`/`pl.call` are its actual outcome) - `publish_locked` would
    /// have committed that outcome; if a LATER throw in the same pass
    /// (fault-edge/emit-action string copies, drain-outcome bookkeeping)
    /// preempted it, this must still do so, not skip it (PR #4225 review
    /// finding: skipping left the watch stuck ProbeState::Pending with
    /// w.call == nullptr forever - sweep_locked's Pending case is then a
    /// permanent no-op, unrescuable by on_fire, which only relaunches from
    /// Idle, or watch(), which is an idempotent no-op on an already-watched
    /// key - nothing signals the operator, and the key reports
    /// last-known-healthy indefinitely).
    /// noexcept: every operation here is scalar/atomic or a noexcept optional
    /// move (DetachedCall's move ops are noexcept) - no allocation, so this is
    /// safe to call from the noexcept recovery path too. `pl.call`, if it
    /// exists on the never-launched branch, is abandoned right here (never
    /// launched, so nothing to close). On the `!live` branch it is instead
    /// MOVED into `work.stale_calls` (pre-reserved by sweep_locked - the move
    /// itself cannot throw) so its handle-closing destructor runs when `work`
    /// is destroyed by the caller, off-lock - never destroyed here, under mu_.
    void reconcile_probe_launches_locked(SweepWork& work) noexcept {
        for (auto& pl : work.probe_launches) {
            if (pl.job) {
                // Never reached run_off_lock's launch call for this entry.
                auto it = watches_.find(pl.key);
                if (it != watches_.end() && it->second->probe == ProbeState::Pending &&
                    it->second->probe_gen == pl.gen && !it->second->call)
                    defer_admission_locked(*it->second, DetachedLaunch::LaunchFailed);
                continue;
            }
            auto it = watches_.find(pl.key);
            RegWatch* w = it != watches_.end() ? it->second.get() : nullptr;
            const bool live = w && w->active && !stopping_ && w->probe == ProbeState::Pending &&
                              w->probe_gen == pl.gen && !w->call;
            if (!live) {
                if (pl.call)
                    work.stale_calls.push_back(std::move(*pl.call)); // reserved: nothrow
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (pl.status == DetachedLaunch::Launched) {
                probe_launched_.fetch_add(1, std::memory_order_relaxed);
                w->call = std::move(pl.call);
            } else {
                defer_admission_locked(*w, pl.status);
            }
        }
        work.probe_launches.clear();
    }

    /// Relock half: publish launched probes with re-validation; file drain
    /// outcomes; restore any resync obligation whose submit threw.
    void publish_locked(SweepWork& work) {
        reconcile_probe_launches_locked(work);
        for (auto& [status, payload] : drain_outcomes_) {
            if (status == DetachedLaunch::Launched) {
                drains_launched_.fetch_add(1, std::memory_order_relaxed);
                drain_refusals_ = 0;
                try {
                    drains_in_flight_.push_back(
                        std::move(std::get<DetachedCall<std::monostate>>(payload)));
                } catch (...) {
                    // Capacity was reserved under mu_ before the launch, so this needs
                    // another thread to have consumed it in between AND a fresh reserve
                    // to fail. The worker still drains and frees the watch; stop() can
                    // no longer wait for it - counted and logged, never silent (sg-2).
                    drains_untracked_.fetch_add(1, std::memory_order_relaxed);
                    if (retiring_count_)
                        --retiring_count_;
                    retiring_gauge_.fetch_sub(1, std::memory_order_relaxed);
                    spdlog::warn("spark_registry: a launched drain could not be tracked "
                                 "(allocation failure) - stop() will not wait for it");
                }
            } else {
                park_lost_locked(std::get<DrainJob>(payload).w.release(), status);
            }
        }
        drain_outcomes_.clear();
        for (const auto& [key, epoch] : work.succeeded_emits) {
            auto it = watches_.find(key);
            if (it != watches_.end() && it->second->resync_epoch == epoch)
                it->second->resync_attempts = 0;
        }
        work.succeeded_emits.clear();
        for (const auto& [key, epoch] : work.failed_emits) {
            auto it = watches_.find(key);
            if (it == watches_.end() || !it->second->active || it->second->resync_epoch != epoch)
                continue; // retired, or a newer obligation already superseded this one
            RegWatch& w = *it->second;
            w.needs_resync = true;
            ++w.resync_attempts;
            const auto delay = doubled(admission_seed(), w.resync_attempts, kRegAdmissionBackoffCap);
            w.resync_retry_at = Clock::now() + delay;
            spdlog::warn("spark_registry: synthetic fire for '{}' threw on submit (attempt {}) - "
                         "retrying in {} ms",
                         ::yuzu::log_key_token(w.spark_key), w.resync_attempts,
                         std::chrono::duration_cast<std::chrono::milliseconds>(delay).count());
        }
        work.failed_emits.clear();
    }

    /// Undo a pass that threw, under mu_, without allocating: retirements it
    /// unlinked go back on the lost list; launches it staged but never made go
    /// back to Deferred on the admission schedule; if nothing was dispatched yet,
    /// resync debt it cleared is restored and health edges it marked reported are
    /// un-marked so the next pass re-stages them (the engine dedups repeats).
    void unwind_pass_locked(SweepWork& work, bool dispatched) noexcept {
        for (auto& dj : work.drain_launches) {
            if (dj.w) {
                RegWatch* w = dj.w.release();
                w->lost_next = lost_head_;
                lost_head_ = w;
                ++lost_count_;
            }
        }
        work.drain_launches.clear();
        // PR #4225 review fix (BLOCKING): reconcile EVERY staged launch the
        // same way publish_locked() would have, whether or not
        // run_off_lock() reached its launch call for a given entry - the
        // previous inline logic here skipped any entry whose `pl.job` was
        // already reset (i.e. actually launched), on the assumption
        // publish_locked()'s re-validation would still run for it - which it
        // does not, on exactly this (threw-mid-pass) path, permanently
        // stranding that entry's watch. See reconcile_probe_launches_locked()'s
        // doc comment for the full failure chain and why it is safe to call
        // unconditionally here.
        reconcile_probe_launches_locked(work);
        // Re-mark every staged establishment report REGARDLESS of `dispatched`:
        // `dispatched == true` only means run_off_lock()
        // was ENTERED, not that it reached this pass's established-dispatch
        // loop before the throw that brought us here - the same distinction
        // work.actions' own `dispatched` guard cannot make either. Do NOT
        // restore the staged value: the next pass re-stages the watch's
        // CURRENT coverage, which is at least as fresh as what was lost here.
        // map::find on a const std::string& does not allocate, so this stays
        // safe for the noexcept contract.
        for (const auto& e : work.established) {
            auto it = watches_.find(e.key);
            if (it != watches_.end())
                it->second->coverage_report_due = true;
        }
        work.established.clear();
        if (!dispatched) {
            for (const auto& a : work.actions) {
                auto it = watches_.find(a.key);
                if (it == watches_.end())
                    continue;
                RegWatch& w = *it->second;
                if (a.kind == SweepWork::Action::Kind::Emit) {
                    if (w.resync_epoch == a.epoch)
                        w.needs_resync = true;
                } else {
                    w.faulted_reported = !w.faulted_now; // re-stage the edge next pass
                }
            }
            work.actions.clear();
        }
        nudged_ = false; // the backoff wait below decides when the next pass runs
    }

    void sweeper_main() {
        std::unique_lock lk(mu_);
        unsigned failures = 0; // consecutive failed passes
        for (;;) {
            const auto wake = next_wake_locked(Clock::now());
            cv_.wait_until(lk, wake, [&] { return sweeper_stop_ || nudged_; });
            if (sweeper_stop_)
                return;
            nudged_ = false;
            SweepWork work;
            bool ok = true;
            bool dispatched = false; // run_off_lock reached: every staged action was offered
            try {
                sweep_locked(work);
                lk.unlock();
                dispatched = true;
                run_off_lock(work);
                lk.lock();
                publish_locked(work);
            } catch (...) {
                // A pass threw (std::bad_alloc is the only expected source). This
                // thread is the SOLE producer of health edges and late commits, so an
                // escaping exception was agent death (sg-7) and a silently-retrying
                // loop would be a mechanism that reads healthy while it is dark
                // (sre6-1). Neither: put back what this pass took, count, back off,
                // and after kSweeperInertAfterFailures consecutive failures publish
                // inertness through the existing wire signal (the capability CSV).
                ok = false;
                if (!lk.owns_lock())
                    lk.lock();
                unwind_pass_locked(work, dispatched);
            }
            if (ok) {
                if (failures) {
                    spdlog::info("spark_registry: sweeper pass recovered after {} failure(s)",
                                 failures);
                    failures = 0;
                    if (core_)
                        inert_.store(false, std::memory_order_release);
                }
                lk.unlock();
                {
                    SweepWork dead = std::move(work); // handle closes + abandons run off-lock
                }
                lk.lock();
                continue;
            }
            sweep_pass_failed_.fetch_add(1, std::memory_order_relaxed);
            ++failures;
            const auto delay = doubled(sweep_cadence(), failures, kRegAdmissionBackoffCap);
            if ((failures & (failures - 1)) == 0) // 1, 2, 4, 8 ... : bounded log rate (sre6-2)
                spdlog::error("spark_registry: sweeper pass failed (consecutive #{}) - retrying in {} ms",
                              failures, delay.count());
            if (failures >= kSweeperInertAfterFailures && !inert_.load(std::memory_order_acquire)) {
                inert_.store(true, std::memory_order_release);
                spdlog::error("spark_registry: sweeper failing persistently - registry sparks "
                              "reported inert until a pass succeeds");
            }
            lk.unlock();
            {
                SweepWork dead = std::move(work);
            }
            lk.lock();
            cv_.wait_until(lk, Clock::now() + delay, [&] { return sweeper_stop_; });
            if (sweeper_stop_)
                return;
        }
    }

    /// Hand an already-inactive watch to the drain lane. Under mu_: a thread
    /// creation, not an OS wait (microseconds, inside the per-type-lock bound).
    /// Never blocks and never drains inline: a refused launch parks the watch on
    /// the allocation-free lost list for the sweeper to relaunch on a backoff, and
    /// a tracking-vector growth failure parks it the same way BEFORE any launch,
    /// so a launched drain is always tracked and stop() can wait for it.
    void retire_locked(std::unique_ptr<RegWatch> victim) {
        if (drains_in_flight_.size() == drains_in_flight_.capacity()) {
            try {
                drains_in_flight_.reserve(drains_in_flight_.capacity() * 2 + kDrainLaneCap);
            } catch (...) {
                park_lost_locked(victim.release(), DetachedLaunch::LaunchFailed);
                nudge_locked();
                return;
            }
        }
        auto lr = drain_lane_.launch(DrainJob{std::move(victim)});
        if (lr.status == DetachedLaunch::Launched) {
            drains_launched_.fetch_add(1, std::memory_order_relaxed);
            drain_refusals_ = 0;
            drains_in_flight_.push_back(std::move(*lr.call)); // within capacity: nothrow
        } else {
            park_lost_locked(lr.fn->w.release(), lr.status);
        }
        nudge_locked();
    }

    /// Park a retired watch on the lost list (allocation-free) and advance the
    /// relaunch backoff (D, 2D, 4D ... capped, the admission schedule). Under mu_.
    /// Logs on the first refusal and at every doubling of the refusal count, so a
    /// thread-exhausted box is visible without a per-cadence log storm (UP-4).
    void park_lost_locked(RegWatch* w, DetachedLaunch why) {
        w->lost_next = lost_head_;
        lost_head_ = w;
        ++lost_count_;
        drains_admission_rejected_.fetch_add(1, std::memory_order_relaxed);
        ++drain_refusals_;
        drain_retry_at_ =
            Clock::now() + doubled(admission_seed(), drain_refusals_, kRegAdmissionBackoffCap);
        if ((drain_refusals_ & (drain_refusals_ - 1)) == 0) {
            spdlog::warn("spark_registry: drain worker for '{}' {} ({} retirement(s) backlogged, "
                         "refusal #{}) - relaunching on a backoff",
                         ::yuzu::log_key_token(w->spark_key),
                         why == DetachedLaunch::Rejected ? "refused by the lane cap"
                                                          : "could not be started",
                         lost_count_, drain_refusals_);
        }
    }

    /// Take the whole lost list. Under mu_.
    [[nodiscard]] RegWatch* take_lost_locked() {
        RegWatch* head = lost_head_;
        lost_head_ = nullptr;
        lost_count_ = 0;
        return head;
    }

    /// Wait for any drain still tracked after stop() - there should be none (the
    /// mu_-held launch in retire_locked closes the stop()/unwatch() window), so
    /// this is the destructor's belt and braces. Unbounded, like stop()'s own
    /// drain wait, for the same reason: those workers own watches whose
    /// callbacks hold `owner`.
    void reap_residual_drains() {
        std::vector<DetachedCall<std::monostate>> drains;
        {
            std::lock_guard lk(mu_);
            drains.swap(drains_in_flight_);
        }
        for (auto& d : drains)
            while (!d.wait_take(Clock::now() + 1s) && !d.done()) {
            }
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    /// Establishment-signal sink (rung 9c PR-6 item 1) - written once by
    /// set_established_sink() before start(), read only by run_off_lock() on
    /// the sweeper thread with mu_ released (same happens-before argument as
    /// emit_/fault_ above: the write happens-before the sweeper thread spawns
    /// in start(), and stop() nulls it only after the sweeper has been
    /// joined).
    SparkEstablishedFn established_;
    /// One-way latch (rung 9c PR-6 item 1): set as the FIRST statement of
    /// start(), never cleared by stop() - SparkEngine itself is single-shot,
    /// so no production caller ever needs to re-arm the sink after a stop().
    bool sink_sealed_{false};
    std::shared_ptr<PoolCore> core_;
    bool started_{false};
    bool stopping_{false};
    bool sweeper_stop_{false};
    bool nudged_{false};
    std::thread sweeper_;
    /// Ordered (not unordered_) so the sweep cursor can rotate over it by key.
    std::map<std::string, std::unique_ptr<RegWatch>> watches_;
    std::vector<DetachedCall<std::monostate>> drains_in_flight_;
    /// Allocation-free retirement backlog (intrusive via RegWatch::lost_next):
    /// watches whose drain launch was refused or could not be tracked, owned by
    /// the list until the sweeper relaunches them or stop() drains them.
    RegWatch* lost_head_{nullptr};
    std::size_t lost_count_{0};
    unsigned drain_refusals_{0}; ///< consecutive refusals; drives the relaunch backoff
    Clock::time_point drain_retry_at_{};
    std::atomic<std::size_t> drain_lane_cap_{kDrainLaneCap}; ///< mirrors drain_lane_'s cap (test-overridable)
    std::size_t retiring_count_{0};
    /// Mechanism-global (never per-watch, so a stale pointer cannot alias a fresh
    /// watch): bumped at every probe reservation and every retirement.
    std::uint64_t gen_{0};
    /// Mechanism-global: bumped whenever an observation gap is recorded.
    std::uint64_t resync_epoch_{0};
    std::string sweep_cursor_;
    std::vector<std::pair<DetachedLaunch, std::variant<DetachedCall<std::monostate>, DrainJob>>>
        drain_outcomes_; ///< sweeper-thread private scratch between run_off_lock and publish_locked
    std::shared_ptr<const ProbeHook> probe_hook_;                ///< test seam
    std::shared_ptr<const std::function<void()>> sweep_hook_; ///< test seam (sre6-1 coverage)
    std::shared_ptr<const std::function<void()>> emit_bookkeeping_hook_; ///< test seam (PR #4225 review)
    SparkDetachedLane probe_lane_;
    SparkDetachedLane drain_lane_;

    /// Started, but the mechanism cannot service watches: CreateThreadpool failed
    /// (every watch() refused), or the sweeper has failed kSweeperInertAfterFailures
    /// passes in a row (no late commit, no health edge would be produced). Cleared
    /// by a successful start() and by the first successful pass after failures.
    /// Atomic so stats() (const, heartbeat thread) reads it without mu_.
    std::atomic<bool> inert_{false};
    std::atomic<std::uint64_t> retiring_gauge_{0};
    std::atomic<std::uint64_t> watch_rejected_{0};
    std::atomic<std::uint64_t> quarantined_{0};
    std::atomic<std::uint64_t> slow_op_{0};
    std::atomic<std::uint64_t> probe_launched_{0};
    std::atomic<std::uint64_t> probe_admission_rejected_{0};
    std::atomic<std::uint64_t> probe_launch_failed_{0};
    std::atomic<std::uint64_t> probe_backend_failed_{0};
    std::atomic<std::uint64_t> probe_discarded_{0};
    std::atomic<std::uint64_t> drains_launched_{0};
    std::atomic<std::uint64_t> drains_completed_{0};
    std::atomic<std::uint64_t> drains_admission_rejected_{0};
    std::atomic<std::uint64_t> drains_untracked_{0}; ///< launched, tracking alloc failed (sg-2)
    std::atomic<std::uint64_t> synthetic_fires_{0};
    std::atomic<std::uint64_t> health_edges_{0};
    std::atomic<std::uint64_t> emit_failed_{0};    ///< an emit() submit threw (either path)
    std::atomic<std::uint64_t> resync_retries_{0}; ///< restored debt re-staged by the sweeper
    std::atomic<std::uint64_t> established_failed_{0}; ///< an established() call threw
    std::atomic<std::uint64_t> fault_failed_{0};     ///< a fault() submit threw (sweeper path)
    std::atomic<std::uint64_t> sweep_pass_failed_{0}; ///< sweeper passes that threw (sg-7/sre6-1)
    std::atomic<std::size_t> retiring_cap_{kRetiringCap};
    std::atomic<std::int64_t> caller_wait_ms_{kRegCallerWaitBudget.count()};
    std::atomic<std::int64_t> health_grace_ms_{kRegHealthGrace.count()};
    std::atomic<std::int64_t> sweep_cadence_ms_{kRegSweepCadence.count()};
    std::atomic<std::int64_t> backend_retry_base_ms_{kRegBackendRetryBase.count()};
    std::atomic<std::int64_t> admission_seed_ms_{kRegAdmissionBackoffSeed.count()};
};

void CALLBACK reg_on_wait_cb(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WAIT, TP_WAIT_RESULT) {
    auto* w = static_cast<RegWatch*>(ctx);
    w->owner->on_fire(*w);
}

} // namespace

std::unique_ptr<ISparkMechanism> make_registry_mechanism() {
    return std::make_unique<WindowsRegistryMechanism>(nullptr); // no shared F3 counter (tests)
}

std::unique_ptr<ISparkMechanism>
make_registry_mechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter) {
    return std::make_unique<WindowsRegistryMechanism>(std::move(f3_counter));
}

bool set_registry_test_controls_for_test(ISparkMechanism& mech,
                                         RegistryMechanismTestControls controls) {
    auto* real = dynamic_cast<WindowsRegistryMechanism*>(&mech);
    if (!real)
        return false;
    real->apply_test_controls(std::move(controls));
    return true;
}

std::optional<RegistryMechanismDebugCounters>
registry_debug_counters_for_test(const ISparkMechanism& mech) {
    const auto* real = dynamic_cast<const WindowsRegistryMechanism*>(&mech);
    if (!real)
        return std::nullopt;
    return real->debug_counters();
}

} // namespace yuzu::agent

#else // ── Non-Windows: registry-change spark is Windows-only ─────────────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_registry_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(Registry) off Windows
}

std::unique_ptr<ISparkMechanism>
make_registry_mechanism(std::shared_ptr<std::atomic<std::size_t>> /*f3_counter*/) {
    return nullptr; // same platform contract as the zero-argument form
}

bool set_registry_test_controls_for_test(ISparkMechanism&, RegistryMechanismTestControls) {
    return false; // nothing to control off Windows
}

std::optional<RegistryMechanismDebugCounters>
registry_debug_counters_for_test(const ISparkMechanism&) {
    return std::nullopt;
}

} // namespace yuzu::agent

#endif // _WIN32
