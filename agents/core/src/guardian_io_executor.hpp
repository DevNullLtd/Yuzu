#pragma once

/**
 * guardian_io_executor.hpp - a bounded, cancellable, single-flight I/O executor
 * for the Guardian spark state reader (ADR-0021 Stage 2 rung 5, F3) and, since
 * rung 9c (R5.1), the non-waiting dispatch form Guardian's arm/disarm consumer uses.
 *
 * WHY: the IStateReader contract (guardian_spark_runtime.hpp) requires every read
 * be bounded/cancellable - a convergence-lane join and the consumer detach both
 * wait on an in-flight read, so a platform call that can block indefinitely (a
 * wedged SCM, a stalled sd-bus broker, a FUSE/network filesystem hang) must carry
 * a deadline and degrade to Unknown rather than hang agent shutdown. A thread
 * wedged in a D-state syscall CANNOT be cancelled or joined; we do NOT force-cancel
 * the kernel call. Instead we DECOUPLE the caller from it: run the blocking read on
 * a detached worker, wait with an absolute deadline + a stop signal, and degrade to
 * a typed failure the reader maps to Unknown. Spawn-per-read (not a pool): the
 * workload is cold (convergence 60s/5-15min lanes, events debounced) and a pool
 * only adds a stale-job queue plus the same wedged-worker problem.
 *
 * TWO DISPATCH FORMS (rung 9c R5.1):
 *  - run(): the caller BLOCKS for the result with an absolute deadline; a late
 *    result is routed to the optional on_abandoned callback (#3816).
 *  - submit(): the caller does NOT block. Admission is still synchronous and
 *    identical; the result is handed to on_complete(IoResult<T>&&) on the worker
 *    thread after fn() returns. A non-waiting call can dispatch a fresh operation
 *    from inside its completion ("refill"), and that refill must not be starved by
 *    its own predecessor's still-held slot - which is why submit() releases quota
 *    at fn() return (below), and why a separate PHYSICAL ceiling exists.
 *
 * INVARIANTS (each is a Sol BLOCKING/SHOULD fix, code-verified; R5.1 additions marked):
 *  - Keyed single-flight: an op key = (IoClass, spark_key) is held from admission
 *    until the RELEASE POINT of the dispatch form (table below). A run/submit for an
 *    already-active key returns AlreadyRunning WITHOUT spawning. The key is the
 *    canonical spark_key (length-prefixed, injective) and EXCLUDES the file hash-cap
 *    and the registry value plan - those can change while the same physical read
 *    is stuck, and letting that change bypass single-flight recreates the
 *    wedged-slot bug. The caller never releases a key in either form.
 *  - TWO COUNTS, not one (R5.1): a QUOTA-HELD count (per class + total, what
 *    admission checks against the class quotas) and a PHYSICAL ALIVE count (every
 *    worker whose payload has not yet been destroyed in the trampoline - the latest
 *    self-observable point before its OS thread exits - what active_worker_count() /
 *    Stats::active_* report and what GuardianEngine::active_io_workers() sums for
 *    the F3 orphan grace - #4147). They diverge only for submit(): its worker frees quota
 *    at fn() return but stays alive through on_complete.
 *  - Per-type bulkheads: per-class quota-held quotas (File/Registry/Service) PLUS a
 *    total bound derived as their sum (rung 9a R3, exact bulkheads), so a dead
 *    mount saturating the file lane never starves a healthy service reconcile.
 *    Combined with single-flight so one key cannot eat its whole type budget.
 *  - PHYSICAL CEILING (R5.1): admission is also refused (CeilingExhausted) once
 *    alive_total >= alive_ceiling = kAliveCeilingFactor * total_quota, regardless
 *    of quota availability. Quota alone no longer bounds alive workers once a
 *    completion callback can outlive its slot. The factor is a policy allowance,
 *    not a structural proof (successive submissions can reuse released quota while
 *    earlier callbacks are still alive), so the ceiling is a per-instance backstop
 *    that can impose cross-class back-pressure; a hit means workers are outstanding
 *    past fn() with quota free (slow or wedged callbacks, delayed ticket release),
 *    NOT that a backend target is dead. Provably inert for run()-only workloads:
 *    run() holds quota until its payload is destroyed, so alive == quota_held <= total_quota <
 *    ceiling. The quota check runs before the ceiling check, so CeilingExhausted is
 *    only ever reported when quota has room - the one diagnostically distinct case.
 *  - RAII admission ticket: admission is a transaction (the one throwing mutation,
 *    set::insert, runs before the nothrow counter increments; the ticket is armed
 *    last). A shared_ptr<TicketCore> owns the slot + active key. Release points:
 *
 *        form                 | single-flight key        | quota slot            | physical (alive)
 *        run(), published     | worker publish           | ~TicketCore (payload dtor) | ~TicketCore
 *        run(), abandoned     | ~TicketCore              | ~TicketCore           | ~TicketCore
 *        submit()             | release_quota_locked() at fn() return, before on_complete | same call | ~TicketCore
 *
 *    ~TicketCore runs when the LAST holder dies - the worker's own captured copy,
 *    destroyed by the trampoline after the worker lambda has fully returned: the
 *    latest point the detached thread can self-observe before it exits. The tail
 *    after that decrement - the State handle release, cv.notify_all, payload
 *    deallocation, the trampoline epilogue and the CRT thread exit - runs only
 *    process-lifetime runtime code (libstdc++/libc/pthread or the CRT), never the
 *    Guardian, OpenSSL, libsystemd or Win32-RPC code F3 exists to keep out of DSO
 *    teardown. NO grace covers that tail: wait_for_workers_to_drain() returns on
 *    the first zero it reads and main.cpp/service_win.cpp skip the wait outright
 *    when the initial sample is zero (hard_exit.hpp). The exposure is identical for
 *    every run() worker since rung 7 and is accepted; a self-decremented count
 *    cannot certify its own thread's exit (adversarial review rounds 1-3, C3/C1).
 *    A timed-out run() submitter does NOT release
 *    anything - the worker does, on its own schedule. Exactly-once decrement
 *    handshake: `quota_released` flips under the same State::mu acquisition as the
 *    quota decrement, and the destructor decrements quota only if it is still
 *    false, so no path can double-decrement (a double-decrement would inflate the
 *    quota and silently oversubscribe the lane).
 *  - No std::terminate path: the worker is launched DETACHED-at-creation
 *    (pthread_create PTHREAD_CREATE_DETACHED / _beginthreadex + CloseHandle), so
 *    there is no joinable std::thread whose destructor could terminate and no
 *    detach() that could throw. The worker trampoline is fully exception-contained
 *    (only the user fn() may throw, and it is caught). run() heap-boxes its result
 *    and publishes into the cell by a nothrow unique_ptr move, so publication
 *    cannot throw for any result type (including MSVC's std::unordered_map, whose
 *    move is not noexcept). submit() has no cross-thread publication: its result
 *    lives on the worker's own stack (std::optional, in-place) and is moved into
 *    on_complete directly, so it has neither a box nor a null-box case.
 *  - Typed outcome: std::expected<T, IoFailure>; the reader maps each IoFailure to
 *    a precise bounded Unknown string (it lands in guard.unhealthy detail).
 *  - Absolute deadline captured at run() ENTRY (per-class deadline chosen by the
 *    reader), so allocation + launch time counts against the caller's budget.
 *    submit() takes NO deadline: there is no waiter to time out, a non-returning
 *    fn() holds its slot and key for as long as it stays stuck (the dead-target
 *    bulkhead is unchanged), and per-key deadlines/wedge marking are the consumer's
 *    (design doc R5.2/R5.3, rung 9c PR-5).
 *  - Exactly-once result delivery (#3816, run()): every result fn() returns normally
 *    goes to exactly one of run()'s return value (caller still waiting) or the
 *    optional on_abandoned(T&&) callback (caller already timed out / the executor
 *    is stopping). The wait-side lock is acquired ONCE, before spawn_detached, and
 *    held across launch into cv.wait_until - so the caller's abandon decision and
 *    the worker's publish decision always serialize on the SAME mutex acquisition
 *    (a plain ResultCell::abandoned bool, no atomics needed) and there is no
 *    window after a caller gives up where a late success has nowhere race-free to
 *    go. A mutex-lock failure on this ONE acquisition can only happen before the
 *    worker exists (folds into IoFailure::LaunchFailed, #saf3821-5's test seam is
 *    set_throw_before_wait_lock_for_test); cv.wait_until's own internal re-lock on
 *    wake is not a throwing failure mode (std::terminate per the standard if it
 *    cannot reacquire), so there is no catchable post-launch failure to guard.
 *  - Exactly-once completion (R5.1, submit()): if submit() returns success, then
 *    on_complete fires exactly once, on the worker thread, if and when the admitted
 *    operation finishes (a WorkerThrew is delivered through the same callback; a
 *    permanently stuck fn() never delivers). It never fires on an admission
 *    failure, not even synchronously - so a caller's rollback of pre-dispatch
 *    bookkeeping can never double up with a callback. It DOES fire after stop()
 *    (counted as completed_after_stop): this executor is T-agnostic and cannot
 *    clean up a late-succeeding arm, so suppressing the callback would be the
 *    #3816 leak class; the consumer's own stopping branch decides what a late
 *    result means (R5.5). It may run BEFORE submit() returns to the caller (a fast
 *    fn()), so every piece of caller-side bookkeeping the callback relies on must
 *    exist before submit() is called. There is no wait-lock held across spawn on
 *    the submit side: run() needs that to serialize the caller's abandon decision
 *    with the worker's publish decision, and submit() has no caller-side decision
 *    after admission. The caller drops its ticket copy unlocked after launch; in
 *    the worst case it is the last holder and the physical decrement runs on the
 *    caller thread LATE (after the worker already returned), never early - safe
 *    for F3 and the ceiling. A throwing on_complete is contained and counted
 *    (completion_failures); the slot and key were already released before it ran.
 *  - Nested dispatch from on_complete is legal (R5.1 refill): the predecessor's
 *    slot and key are already released and the callback thread holds no executor
 *    lock, so a run()/submit() on the same executor (same key included) from inside
 *    on_complete admits normally. A callback that BLOCKS in a nested run() counts
 *    as one alive worker holding no quota for as long as it blocks.
 *  - Every worker body wears GuardianDetachedWorkerRole (both forms) from its first
 *    statement, and destroys its owned user callables (fn, on_abandoned /
 *    on_complete) inside that marked scope, so fn(), the callbacks and their
 *    capture destructors all run marked: any GuardianEngine::mtx_ acquisition on the
 *    thread aborts in debug/sanitizer builds (WorkerHostileMutex's second role,
 *    guardian_detached_worker_role.hpp). The ticket's own destruction, by the
 *    trampoline after the lambda returns, is outside the marked scope and takes
 *    only State::mu.
 *
 * ORPHAN PROCESS-EXIT CONTRACT (rung-5 scope: expose + document; ENFORCEMENT
 * LANDED rung 7, see below):
 *  A shared_ptr keeps State (and, for run(), the result cell) alive for a wedged
 *  detached worker, so there is no use-after-free. It does NOT make it safe for
 *  that worker to run libc / OpenSSL / libsystemd / Win32-RPC code THROUGH normal
 *  C++ static/DSO teardown. The process MUST NOT perform normal C++ teardown while
 *  active_worker_count() > 0. That count is the PHYSICAL ALIVE count (#4147): it
 *  includes a submit() worker that has already returned from fn() and released
 *  its quota but is still inside on_complete, and it is bounded per instance by
 *  alive_ceiling. Rung 5 exposed that count (total + per class) here and
 *  re-exposed it through GuardianStateReader; rung 7's hard_exit.hpp is the
 *  enforcement: main.cpp/service_win.cpp construct an OrphanExitGuard before
 *  Agent::run(), sample guardian_active_io_workers() after it returns, and
 *  hard_exit() (TerminateProcess/_exit, skipping normal teardown entirely) if
 *  still nonzero after a bounded grace. Verified on POSIX (full test suite +
 *  TSan + real boot/SIGTERM smoke tests); the Windows SCM path
 *  (service_win.cpp) needs a DGRHP build+run before it's considered verified
 *  the same way. GuardianEngine's spark path is wired at agent boot since rung
 *  7.7a (agent.cpp, the wire_spark_engine() call site) with prefer_spark false,
 *  so the arm/disarm executor exists in production but sees no traffic until the
 *  flip; the state-read executor is live wherever spark state reads run.
 */

#include "guardian_detached_worker_role.hpp" // rung 9c R5.1: worker role marker

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <process.h> // _beginthreadex
#else
#include <pthread.h>
#endif

namespace yuzu::agent {

/// Which reader lane a read belongs to. Values 0/1/2 index the per-class arrays.
enum class IoClass { File = 0, Registry = 1, Service = 2 };

inline constexpr std::size_t kIoClassCount = 3;

[[nodiscard]] constexpr std::size_t io_class_index(IoClass c) noexcept {
    return static_cast<std::size_t>(c);
}

[[nodiscard]] constexpr const char* io_class_token(IoClass c) noexcept {
    switch (c) {
    case IoClass::File:     return "file";
    case IoClass::Registry: return "registry";
    case IoClass::Service:  return "service";
    }
    return "unknown";
}

/// Why a bounded operation did not return a value. Seven materially different
/// operational meanings (they end up in guard.unhealthy detail, so the reader maps
/// each to a precise string rather than a single "timed out or cancelled").
enum class IoFailure {
    Timeout,           ///< the per-class deadline elapsed before the worker published (run() only)
    Stopped,           ///< the executor is stopping (shutdown); the submitter was woken / rejected
    CapacityExhausted, ///< the per-class or total QUOTA was full (a backend call is holding a slot)
    AlreadyRunning,    ///< an op for this exact (class, key) is already in flight (single-flight)
    LaunchFailed,      ///< the OS refused to create the worker thread, an allocation failed, or
                       ///< the pre-launch wait-lock acquisition failed (#3816 - folded here
                       ///< rather than a new enumerator, since it is now provably pre-launch)
    WorkerThrew,       ///< the body threw (should not happen; contained, never terminates)
    CeilingExhausted,  ///< rung 9c R5.1: the per-instance PHYSICAL alive-worker ceiling is hit
                       ///< while quota has room - workers are outstanding past fn() (slow or
                       ///< wedged completion callbacks), a runtime-side condition, not a dead
                       ///< backend target; remediation differs from CapacityExhausted
};

template <class T>
using IoResult = std::expected<T, IoFailure>;

namespace io_detail {

template <class Fn>
struct DetachedPayload {
    Fn fn;
};

#ifdef _WIN32
template <class Fn>
unsigned __stdcall detached_trampoline(void* arg) noexcept {
    std::unique_ptr<DetachedPayload<Fn>> p{static_cast<DetachedPayload<Fn>*>(arg)};
    p->fn();
    return 0;
}
#else
template <class Fn>
void* detached_trampoline(void* arg) noexcept {
    std::unique_ptr<DetachedPayload<Fn>> p{static_cast<DetachedPayload<Fn>*>(arg)};
    p->fn();
    return nullptr;
}
#endif

/// Launch `fn` on a thread that is DETACHED at creation. There is no joinable
/// std::thread whose destructor could std::terminate and no detach() that could
/// throw. Returns false ONLY if the OS refused to create the thread (the caller
/// maps that to IoFailure::LaunchFailed and rolls admission back). May throw
/// std::bad_alloc from the single payload allocation, which the caller's
/// admission transaction also rolls back. On success the worker owns the payload
/// and deletes it when it returns.
template <class Fn>
[[nodiscard]] bool spawn_detached(Fn&& fn) {
    using P = DetachedPayload<std::decay_t<Fn>>;
    std::unique_ptr<P> payload{new P{std::forward<Fn>(fn)}};
#ifdef _WIN32
    const std::uintptr_t h = _beginthreadex(nullptr, 0, &detached_trampoline<std::decay_t<Fn>>,
                                            payload.get(), 0, nullptr);
    if (h == 0)
        return false;
    payload.release();
    ::CloseHandle(reinterpret_cast<HANDLE>(h));
    return true;
#else
    pthread_attr_t attr;
    if (::pthread_attr_init(&attr) != 0)
        return false;
    ::pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    const int rc =
        ::pthread_create(&tid, &attr, &detached_trampoline<std::decay_t<Fn>>, payload.get());
    ::pthread_attr_destroy(&attr);
    if (rc != 0)
        return false;
    payload.release();
    return true;
#endif
}

} // namespace io_detail

class GuardianIoExecutor {
public:
    /// Ceiling on QUOTA-HELD bounded-I/O workers PER EXECUTOR INSTANCE (renamed in
    /// spirit but not in name - sre Gate 6, #2233 item 3: this was a genuine
    /// process-wide ceiling until that PR added a second, deliberately-independent
    /// GuardianIoExecutor instance for Guardian spark arm/disarm alongside
    /// GuardianStateReader's own state-read instance - real process-wide worst case
    /// is now the SUM across every live instance, not this constant alone), and the
    /// compile-time tripwire for the per-class quotas. The bound is DERIVED as the
    /// sum of the class quotas (see the ctor), which makes the per-class bulkheads
    /// EXACT within one instance: a class cap always binds before the instance
    /// bound can, so no class is ever starved by another saturating a different
    /// lane (ADR-0021 rung 9a, R3 - this replaces the prior independent
    /// `total_quota{8} < sum(10)`, which let File+Registry starve Service to 1 of
    /// its 3 slots with nothing wedged). A new IoClass or a raised default that
    /// pushes the sum past this ceiling fails the static_assert below: raise the
    /// ceiling deliberately, or shrink a class - never silently oversubscribe.
    /// Since rung 9c R5.1 this bounds QUOTA, not alive threads: a submit() worker
    /// frees its quota at fn() return and stays alive through its completion
    /// callback, so alive threads are bounded by kMaxAliveIoWorkers instead.
    static constexpr int kMaxProcessIoWorkers = 10;

    /// rung 9c R5.1: alive_ceiling = kAliveCeilingFactor * total_quota per instance.
    /// A policy allowance, pinned here and in the implementing PR's description (per
    /// §7.7b item 5): at most one quota holder plus one predecessor still in its
    /// callback per slot is the STRUCTURAL population under the consumer's
    /// one-nested-refill-per-callback shape, but successive submissions can reuse
    /// released quota while earlier callbacks are still alive, so the factor is a
    /// backstop rather than a proof. Derived from the CLAMPED total_quota, never a
    /// Config knob (an injected ceiling <= sum(quotas) would recreate the R3
    /// starvation).
    static constexpr int kAliveCeilingFactor = 2;
    /// The ceiling for the shipped Config (2 x 10 = 20), per executor instance - not
    /// a process-wide total across instances.
    static constexpr int kMaxAliveIoWorkers = kAliveCeilingFactor * kMaxProcessIoWorkers;

    struct Config {
        int file_quota{4};
        int registry_quota{3};
        int service_quota{3};
    };
    // (The tripwire static_assert lives just after this class - a Config{} default
    // member initializer cannot be read inside the still-incomplete enclosing class.)

    /// Cumulative, rate-safe per-class counters (no per-rejection / per-retry log).
    struct Counters {
        std::uint64_t timed_out{0};
        std::uint64_t rejected_capacity{0};
        std::uint64_t rejected_key{0};
        std::uint64_t launch_failures{0};
        std::uint64_t worker_exceptions{0};
        /// #3816: every result routed to on_abandoned (a late completion after the
        /// caller gave up), success or failure of fn() alike - this class is
        /// T-agnostic and cannot discriminate a "success" for an arbitrary T; a
        /// caller wanting that distinction (e.g. GuardianSparkRuntime's late-arm
        /// count) must derive it from within its own on_abandoned callback.
        std::uint64_t abandoned{0};
        /// on_abandoned itself threw; contained here (never propagated - the
        /// worker lambda is noexcept). Counted IN ADDITION to `abandoned` above
        /// (that delivery still happened; this counts that its cleanup failed),
        /// not instead of it - the two are not mutually exclusive.
        std::uint64_t abandonment_cleanup_failures{0};
        /// rung 9c R5.1: admission refused at the physical alive-worker ceiling
        /// while quota had room (CeilingExhausted).
        std::uint64_t rejected_ceiling{0};
        /// rung 9c R5.1: a submit() worker reached its completion after stop() had
        /// been called; on_complete still fired (the analogue of `abandoned`).
        std::uint64_t completed_after_stop{0};
        /// rung 9c R5.1: on_complete itself threw; contained, counted in addition to
        /// the delivery (which happened), mirroring abandonment_cleanup_failures.
        std::uint64_t completion_failures{0};
    };

    /// A by-value snapshot (never a reference into State after the lock releases).
    struct Stats {
        /// PHYSICAL alive workers (payload not yet destroyed; the latest
        /// self-observable point before OS-thread exit) - the F3 count.
        std::size_t active_total{0};
        std::array<std::size_t, kIoClassCount> active_by_class{};
        std::array<std::size_t, kIoClassCount> active_at_shutdown{};
        /// rung 9c R5.1: QUOTA-HELD slots, what admission checks against the quotas.
        std::size_t quota_held_total{0};
        std::array<std::size_t, kIoClassCount> quota_held_by_class{};
        std::size_t alive_ceiling{0};
        std::array<Counters, kIoClassCount> counters{};
        bool stopping{false};
    };

    GuardianIoExecutor() : GuardianIoExecutor(Config{}) {}
    explicit GuardianIoExecutor(Config cfg) : state_(std::make_shared<State>()) {
        // Clamp each class quota to [1, kMaxProcessIoWorkers]: a class must be able to
        // admit at least one read (a 0 or negative quota would silently reject every
        // read of that class), and no single class may exceed the process ceiling.
        // Production uses the static-asserted defaults; this guards an injected Config.
        const auto clamp_q = [](int q) {
            return q < 1 ? 1 : (q > kMaxProcessIoWorkers ? kMaxProcessIoWorkers : q);
        };
        const int f = clamp_q(cfg.file_quota);
        const int r = clamp_q(cfg.registry_quota);
        const int s = clamp_q(cfg.service_quota);
        state_->class_quota[io_class_index(IoClass::File)] = f;
        state_->class_quota[io_class_index(IoClass::Registry)] = r;
        state_->class_quota[io_class_index(IoClass::Service)] = s;
        // Derive the process bound from the class quotas so the bulkheads are EXACT:
        // total == sum(class quotas) means the process check can never bind before a
        // class cap does, so it never starves a lane. But an injected Config whose
        // quotas sum past the ceiling (tests) must still never spawn more than
        // kMaxProcessIoWorkers - so clamp. For a well-formed Config sum <= ceiling, so
        // the clamp is inert and the bulkheads stay exact. Kept as a live admission
        // guard (belt-and-braces, provably inert for a well-formed Config).
        const int sum = f + r + s;
        state_->total_quota = sum <= kMaxProcessIoWorkers ? sum : kMaxProcessIoWorkers;
        // rung 9c R5.1: the physical ceiling is derived from the CLAMPED quota total, so
        // it is always strictly above it (factor >= 2, static-asserted below).
        state_->alive_ceiling = kAliveCeilingFactor * state_->total_quota;
    }
    GuardianIoExecutor(const GuardianIoExecutor&) = delete;
    GuardianIoExecutor& operator=(const GuardianIoExecutor&) = delete;
    // Move is implicitly deleted (user-declared copy + atomic member); the reader
    // owns it by value and is never moved.

    /// Run `fn()` (the blocking read body) on a detached worker, bounded by
    /// `deadline` (absolute, captured at entry). `key` is the canonical spark_key
    /// of the target. Returns the worker's result on success, or a typed IoFailure.
    /// Forwarding callable (no std::function alloc); the worker captures a decayed
    /// OWNING copy of `fn`. No constraint on `T`'s own move-throwing-ness - the
    /// worker heap-boxes its result and publishes by a nothrow unique_ptr move
    /// (see below). 4-arg form: no abandonment callback (state reads - a late
    /// result is pure wasted work, nothing escapes to clean up).
    template <class F>
    auto run(IoClass cls, std::string key, std::chrono::milliseconds deadline, F&& fn) {
        using T = std::decay_t<std::invoke_result_t<F&>>;
        return run(cls, std::move(key), deadline, std::forward<F>(fn), [](T&&) {});
    }

    /// 5-arg form (#3816): `on_abandoned` is invoked, on the worker thread, with
    /// fn()'s result WHEN that result would otherwise have nowhere race-free to
    /// go - the caller already decided Timeout/Stopped before the worker reached
    /// its publish decision. It fires only when fn() returned normally (never for
    /// WorkerThrew or an alloc-starved null box - there is no T to hand it in
    /// either case). See the class INVARIANTS block for the exactly-once contract
    /// and why a plain mutex-guarded bool is sufficient (no atomics).
    template <class F, class OnAbandoned>
    auto run(IoClass cls, std::string key, std::chrono::milliseconds deadline, F&& fn,
             OnAbandoned&& on_abandoned) {
        using T = std::decay_t<std::invoke_result_t<F&>>;
        // The worker heap-boxes its result (unique_ptr<IoResult<T>>) and publishes
        // it into the cell by a pointer move, which is nothrow for ANY result type -
        // including one whose own move is potentially-throwing (MSVC's
        // std::unordered_map move ctor is NOT noexcept, unlike libstdc++/libc++), so
        // no nothrow-move constraint on T is needed here. Result construction (the
        // only potentially-throwing step) happens on the worker BEFORE the publish
        // lock and is fully contained.
        const auto abs_deadline = std::chrono::steady_clock::now() + deadline;
        const std::size_t ci = io_class_index(cls);

        Ticket ticket;                          // function scope: armed under the lock; its RAII
                                                // destructor rolls admission back on any unwind
        std::shared_ptr<ResultCell<T>> cell;
        // Constructed inside the try, held across spawn_detached, reused for
        // cv.wait_until - see INVARIANTS. owns_lock() tells the catch block
        // whether the failure happened before or after this was acquired.
        std::unique_lock<std::mutex> wait_lk;
        try {
            cell = std::make_shared<ResultCell<T>>();
            ticket = std::make_shared<TicketCore>(state_); // unarmed until admitted
            {
                std::unique_lock<std::mutex> lk{state_->mu};
                if (const auto rejected = admit_locked(ci, key, ticket))
                    return IoResult<T>{std::unexpect, *rejected};
            }

            // #saf3821-5 test seam: simulate the wait-lock acquisition failing,
            // without corrupting state_->mu for the rest of the process. Thrown
            // BEFORE wait_lk exists, so owns_lock() is false in the catch below.
            if (throw_before_wait_lock_for_test_.load(std::memory_order_relaxed))
                throw std::runtime_error(
                    "guardian_io_executor: injected wait-lock failure (test seam)");

            // Acquired once, held across spawn_detached, reused for wait_until
            // below - see INVARIANTS. This is the ONLY lock construction in the
            // function that can outlive the admission block.
            wait_lk = std::unique_lock<std::mutex>{state_->mu};

            auto st = state_;
            // The user callables are held in optionals so the worker can destroy them
            // INSIDE its role-marked scope (rung 9c R5.1) - their destructors are
            // consumer code. The decayed copy/move still happens here, in capture-init,
            // exactly as before (ThrowOnCopyFunctor's owns_lock()==true seam relies on it).
            auto worker = [st, cell, ticket, ci,
                           on_abandoned = std::optional<std::decay_t<OnAbandoned>>(
                               std::in_place, std::forward<OnAbandoned>(on_abandoned)),
                           fn = std::optional<std::decay_t<F>>(std::in_place,
                                                               std::forward<F>(fn))]() mutable noexcept {
                const GuardianDetachedWorkerRole role_marker; // first statement, see INVARIANTS
                // Construct the result on the heap OUTSIDE the publish lock; this is
                // the only potentially-throwing step (fn() itself, or the boxing
                // allocation) and it is fully contained. A null box means even the
                // WorkerThrew fallback could not allocate -> the submitter maps it to
                // WorkerThrew.
                std::unique_ptr<IoResult<T>> boxed;
                bool threw = false;
                try {
                    boxed = std::make_unique<IoResult<T>>((*fn)());
                } catch (...) {
                    threw = true;
                    try {
                        boxed = std::make_unique<IoResult<T>>(std::unexpect, IoFailure::WorkerThrew);
                    } catch (...) {
                        boxed.reset();
                    }
                }
                // Decide abandoned-vs-published under st->mu FIRST, before touching
                // cell->result - deciding after would mean handing on_abandoned a
                // `boxed` that publication had already moved from (#3816 design
                // review caught this ordering bug). Both this decision and the
                // caller's own Timeout/Stopped decision (guardian_io_executor.hpp's
                // run()) serialize on this SAME mutex, so a plain bool is enough.
                bool was_abandoned = false;
                {
                    std::lock_guard<std::mutex> lk{st->mu};
                    if (threw)
                        ++st->counters[ci].worker_exceptions;
                    was_abandoned = cell->abandoned;
                    if (!was_abandoned) {
                        cell->result = std::move(boxed); // nothrow: unique_ptr pointer move
                        cell->done = true;
                        ticket->release_key_locked(); // free the single-flight key now;
                                                       // the quota + alive counts stay held
                                                       // until this ticket's destructor
                                                       // runs (worker's own copy, at
                                                       // payload destruction, the latest
                                                       // self-observable pre-exit point)
                    } else if (boxed && boxed->has_value()) {
                        ++st->counters[ci].abandoned;
                    }
                    // On the abandoned branch, deliberately do NOT call
                    // release_key_locked() here - a second lock acquisition after
                    // on_abandoned returns would be a new throwing call inside this
                    // noexcept lambda. TicketCore's own destructor (already a single
                    // unconditional acquisition, already runs at true worker-thread-
                    // exit) frees the key together with the counters instead - no
                    // new lock acquisition on this, the ORDINARY abandoned-publish
                    // path (the separate, rare cleanup-failure sub-path below DOES
                    // take one more, to count the failure).
                }
                st->cv.notify_all(); // after releasing the lock (unconditional,
                                     // matching the pre-existing idiom - harmless
                                     // for any other waiter sharing this cv)
                if (was_abandoned && boxed && boxed->has_value()) {
                    try {
                        (*on_abandoned)(std::move(boxed->value()));
                    } catch (...) {
                        try {
                            std::lock_guard<std::mutex> lk{st->mu};
                            ++st->counters[ci].abandonment_cleanup_failures;
                        } catch (...) {
                        }
                    }
                }
                // Destroy the user callables inside the marked scope (R5.1).
                on_abandoned.reset();
                fn.reset();
                // `ticket` copy destroyed when the trampoline destroys the payload (the
                // captures), after this lambda returns -> releases the physical counts
                // (and, on the abandoned branch, the key too - see above)
            };

            bool launched = false;
            if (!fail_launch_for_test_.load(std::memory_order_relaxed))
                launched = io_detail::spawn_detached(std::move(worker));
            if (!launched) {
                // wait_lk is already held - reuse it, do NOT take a fresh lock here
                // (a second acquisition of the same non-recursive mutex by this
                // thread would self-deadlock).
                ++state_->counters[ci].launch_failures;
                return IoResult<T>{std::unexpect, IoFailure::LaunchFailed}; // ticket rolls back
            }
        } catch (...) {
            // bad_alloc from cell / ticket / worker allocation, from set::insert, or
            // the injected test-seam throw above. wait_lk may or may not be held
            // depending on where the throw happened - owns_lock() tells us which,
            // so we never try to lock state_->mu twice on the same thread. An armed
            // ticket's function-scope destructor rolls admission back on return
            // (wait_lk, declared after ticket, destructs FIRST - unlocking before
            // the ticket destructor's own acquisition, if wait_lk was held).
            try {
                if (wait_lk.owns_lock()) {
                    ++state_->counters[ci].launch_failures;
                } else {
                    std::lock_guard<std::mutex> lk{state_->mu};
                    ++state_->counters[ci].launch_failures;
                }
            } catch (...) {
            }
            return IoResult<T>{std::unexpect, IoFailure::LaunchFailed};
        }

        ticket.reset(); // success: drop the caller copy; the worker now owns the reservation
        // Safe only because every worker code path first blocks on THIS SAME
        // state_->mu (the caller's own wait_lk, held continuously from before this
        // point) before it can reach a publish/abandon decision - no worker path
        // bypasses that lock_guard to race TicketCore's destructor against the
        // caller. A future worker early-return that skipped the lock would
        // self-deadlock (or worse, race) here instead.

        state_->cv.wait_until(wait_lk, abs_deadline,
                              [&] { return cell->done || state_->stopping; });
        if (cell->done) {
            if (cell->result)
                return std::move(*cell->result); // real result wins over a concurrent stop
            return IoResult<T>{std::unexpect, IoFailure::WorkerThrew}; // null box: alloc-starved worker
        }
        // Giving up: mark abandoned under the still-held wait_lk BEFORE returning -
        // this is the caller-side half of the exactly-once decision (#3816). A
        // worker that reaches its own publish decision after this either sees
        // `abandoned` already true (routes to on_abandoned) or is still mid-fn()
        // and will see it the moment it takes st->mu.
        if (state_->stopping) {
            cell->abandoned = true;
            return IoResult<T>{std::unexpect, IoFailure::Stopped};
        }
        ++state_->counters[ci].timed_out;
        cell->abandoned = true;
        return IoResult<T>{std::unexpect, IoFailure::Timeout};
    }

    /// rung 9c R5.1 - the NON-WAITING dispatch form. Runs `fn()` on a detached
    /// worker exactly like run(), with the same synchronous admission (Stopped /
    /// AlreadyRunning / CapacityExhausted / CeilingExhausted / LaunchFailed returned
    /// here, nothing launched, `on_complete` never invoked), but the caller does
    /// NOT block: on success `on_complete(IoResult<T>&&)` fires exactly once on the
    /// worker thread after fn() returns (WorkerThrew is delivered through it too).
    /// The quota slot AND the single-flight key are released at fn() return, BEFORE
    /// on_complete runs; the physical alive count is released only when the worker
    /// payload is destroyed in the trampoline (the latest self-observable point before
    /// OS-thread exit). No deadline: see the INVARIANTS block for the contract in full (fires
    /// after stop(), may fire before this returns, nested dispatch from the callback
    /// is legal, a throwing callback is contained and counted). `T` must not be
    /// void (same limitation as run(); `emplace(fn())` cannot express it).
    template <class F, class OnComplete>
    [[nodiscard]] IoResult<void> submit(IoClass cls, std::string key, F&& fn,
                                        OnComplete&& on_complete) {
        using T = std::decay_t<std::invoke_result_t<F&>>;
        static_assert(!std::is_void_v<T>,
                      "GuardianIoExecutor::submit(): fn must return a value (not void), same "
                      "as run(); return a dummy int for a fire-and-forget body");
        static_assert(std::is_invocable_v<std::decay_t<OnComplete>&, IoResult<T>&&>,
                      "GuardianIoExecutor::submit(): on_complete must accept IoResult<T>&&");
        const std::size_t ci = io_class_index(cls);

        Ticket ticket; // function scope: armed under the lock; RAII rollback on unwind
        try {
            ticket = std::make_shared<TicketCore>(state_); // unarmed until admitted
            auto st = state_;
            // Build the worker BEFORE admission: every fallible preparation (the two
            // decayed callable copies, the closure) has already happened by the time
            // a slot is reserved, so an admitted operation is never later reported
            // LaunchFailed because its own preparation threw. `ticket` is shared, so
            // arming it under the lock below is visible to this closure's copy.
            auto worker = [st, ticket, ci,
                           on_complete = std::optional<std::decay_t<OnComplete>>(
                               std::in_place, std::forward<OnComplete>(on_complete)),
                           fn = std::optional<std::decay_t<F>>(std::in_place,
                                                               std::forward<F>(fn))]() mutable noexcept {
                const GuardianDetachedWorkerRole role_marker; // first statement, see INVARIANTS
                // The result lives on THIS stack: no cross-thread publication, no box,
                // no null-box case. A throwing fn() leaves `r` disengaged and the
                // fallback emplace (an enum, nothrow) fills it.
                std::optional<IoResult<T>> r;
                bool threw = false;
                try {
                    r.emplace((*fn)());
                } catch (...) {
                    threw = true;
                }
                if (!r)
                    r.emplace(std::unexpect, IoFailure::WorkerThrew);
                // ONE lock acquisition = the worker's whole decision point: count, read
                // `stopping` for completed_after_stop, release the quota slot and the
                // single-flight key. on_complete then runs OFF the lock, so a refill it
                // dispatches admits against an already-freed slot and key.
                {
                    std::lock_guard<std::mutex> lk{st->mu};
                    if (threw)
                        ++st->counters[ci].worker_exceptions;
                    if (st->stopping)
                        ++st->counters[ci].completed_after_stop;
                    ticket->release_quota_locked(); // slot + key; alive stays until ~TicketCore
                }
                // No cv notify: nothing waits on quota (run() waiters wait on their
                // own cell->done / stopping).
                try {
                    (*on_complete)(std::move(*r));
                } catch (...) {
                    try {
                        std::lock_guard<std::mutex> lk{st->mu};
                        ++st->counters[ci].completion_failures;
                    } catch (...) {
                    }
                }
                // Destroy the user callables inside the marked scope (R5.1).
                on_complete.reset();
                fn.reset();
                // `ticket` copy destroyed at worker scope end (by the trampoline, after
                // this lambda returns) -> physical alive decrement, the F3 moment.
            };

            {
                std::unique_lock<std::mutex> lk{state_->mu};
                if (const auto rejected = admit_locked(ci, key, ticket))
                    return IoResult<void>{std::unexpect, *rejected};
            }

            bool launched = false;
            if (!fail_launch_for_test_.load(std::memory_order_relaxed))
                launched = io_detail::spawn_detached(std::move(worker));
            if (!launched) {
                {
                    std::lock_guard<std::mutex> lk{state_->mu};
                    ++state_->counters[ci].launch_failures;
                }
                return IoResult<void>{std::unexpect, IoFailure::LaunchFailed}; // ticket rolls back
            }
        } catch (...) {
            // bad_alloc from the ticket / worker allocation, from set::insert, or from
            // spawn_detached's payload. No lock is held at any throw site here, so a
            // fresh acquisition is safe; the armed ticket's destructor rolls admission
            // back on return.
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                ++state_->counters[ci].launch_failures;
            } catch (...) {
            }
            return IoResult<void>{std::unexpect, IoFailure::LaunchFailed};
        }

        // Success: drop the caller copy UNLOCKED. Unlike run() there is no caller-side
        // decision left to serialize with the worker. If the worker already finished
        // and dropped its copy, this reset runs the destructor here - the physical
        // decrement lands LATE (after the worker returned), never early, which is
        // safe for F3 and the ceiling.
        ticket.reset();
        return {};
    }

    /// Wake every waiting submitter and reject new submissions. Idempotent,
    /// nonblocking; does NOT cancel the detached OS calls (they run to completion
    /// or their own per-call timeout), and does NOT suppress a submit() worker's
    /// on_complete (counted as completed_after_stop instead). Snapshots the
    /// per-class PHYSICAL alive count at the first stop for telemetry (F3: worker
    /// payloads still alive at stop; quota-held is meaningless once admission is
    /// closed).
    void stop() {
        {
            std::lock_guard<std::mutex> lk{state_->mu};
            if (!state_->stopping) {
                state_->stopping = true;
                for (std::size_t i = 0; i < kIoClassCount; ++i)
                    state_->active_at_shutdown[i] =
                        static_cast<std::size_t>(state_->alive_by_class[i] > 0
                                                     ? state_->alive_by_class[i]
                                                     : 0);
            }
        }
        state_->cv.notify_all();
    }

    /// PHYSICAL alive workers (payload not yet destroyed in the trampoline, the
    /// latest self-observable point before OS-thread exit), the F3 orphan-grace
    /// count (#4147). Includes a submit() worker still inside on_complete after its quota
    /// was released. Never the quota-held count.
    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->alive_total);
    }
    [[nodiscard]] std::size_t active_worker_count(IoClass c) const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->alive_by_class[io_class_index(c)]);
    }
    /// rung 9c R5.1: the derived per-instance physical ceiling (kAliveCeilingFactor x
    /// the clamped quota total).
    [[nodiscard]] std::size_t alive_ceiling() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->alive_ceiling);
    }
    [[nodiscard]] bool stopping() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->stopping;
    }
    [[nodiscard]] Stats stats() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        Stats s;
        s.active_total = static_cast<std::size_t>(state_->alive_total);
        for (std::size_t i = 0; i < kIoClassCount; ++i)
            s.active_by_class[i] = static_cast<std::size_t>(state_->alive_by_class[i]);
        s.active_at_shutdown = state_->active_at_shutdown;
        s.quota_held_total = static_cast<std::size_t>(state_->quota_held_total);
        for (std::size_t i = 0; i < kIoClassCount; ++i)
            s.quota_held_by_class[i] = static_cast<std::size_t>(state_->quota_held_by_class[i]);
        s.alive_ceiling = static_cast<std::size_t>(state_->alive_ceiling);
        s.counters = state_->counters;
        s.stopping = state_->stopping;
        return s;
    }

    /// Test seam: force the next launch to fail, exercising the LaunchFailed
    /// rollback path without depending on real thread-resource exhaustion. Gates
    /// both run() and submit().
    void set_fail_launch_for_test(bool v) { fail_launch_for_test_.store(v); }

    /// Test seam (#3816/#saf3821-5): force every run() to throw immediately
    /// before its wait-lock acquisition, exercising the pre-launch LaunchFailed
    /// rollback path this specific failure now folds into - without corrupting
    /// state_->mu (a real std::mutex::lock() failure cannot be induced portably).
    /// Sticky until reset (same semantics as set_fail_launch_for_test above) - a
    /// test that sets this must reset it before any later run() on this instance.
    /// run()-only by construction: submit() has no wait lock.
    void set_throw_before_wait_lock_for_test(bool v) {
        throw_before_wait_lock_for_test_.store(v);
    }

private:
    /// Heap state shared (via shared_ptr) by the executor AND every worker + ticket,
    /// so a wedged detached worker keeps it alive past the executor's destruction.
    struct State {
        mutable std::mutex mu;
        std::condition_variable cv;
        bool stopping{false};
        // PHYSICAL alive workers (F3): incremented at admission, decremented ONLY in
        // ~TicketCore when the trampoline destroys the worker payload (the latest
        // self-observable point before OS-thread exit). What active_worker_count() reports.
        int alive_total{0};                                   // guarded by mu
        std::array<int, kIoClassCount> alive_by_class{};      // guarded by mu
        // QUOTA-HELD slots (rung 9c R5.1): what admission checks against the quotas.
        // run() frees these in ~TicketCore too; submit() frees them at fn() return.
        int quota_held_total{0};                              // guarded by mu
        std::array<int, kIoClassCount> quota_held_by_class{}; // guarded by mu
        std::set<std::pair<int, std::string>> active_keys;    // (classIdx, spark_key); guarded by mu
        std::array<std::size_t, kIoClassCount> active_at_shutdown{};
        std::array<Counters, kIoClassCount> counters{};
        std::array<int, kIoClassCount> class_quota{};         // immutable after ctor
        int total_quota{0};                                   // immutable after ctor
        int alive_ceiling{0};                                 // immutable after ctor (R5.1)
    };

    /// RAII admission slot. THREE release moments, deliberately not merged:
    ///   - release_key_locked() frees only the single-flight KEY, called by the run()
    ///     worker in its publish critical section, so a fast sequential re-read of
    ///     the same key is not spuriously single-flighted the instant the result is
    ///     visible to a waiting submitter.
    ///   - release_quota_locked() (rung 9c R5.1) frees the QUOTA slot and the key
    ///     together, called by the submit() worker the moment fn() returns, before
    ///     on_complete runs, so a refill dispatched from the callback is never
    ///     starved by its own predecessor. `quota_released` flips under the same
    ///     lock acquisition as the decrement and the destructor skips the quota
    ///     decrement when it is set: the exactly-once handshake §7.7b item 5 asked
    ///     for (a double-decrement would inflate the quota).
    ///   - the PHYSICAL alive counts (alive_total / alive_by_class - what
    ///     active_worker_count() reports) are freed ONLY in the destructor, i.e.
    ///     when the LAST shared holder dies. The worker's own captured copy is that
    ///     last holder, and it is destroyed by the trampoline AFTER the worker
    ///     lambda body has fully returned (on_abandoned / on_complete and the
    ///     explicit user-callable resets included) - the latest SELF-observable
    ///     point before the OS thread exits. What runs after the decrement is only
    ///     the tail this destructor itself ends with (cv.notify_all), the remaining
    ///     capture releases (the State shared_ptr), the payload deallocation, the
    ///     trampoline epilogue and the CRT thread exit - process-lifetime runtime
    ///     code, never Guardian / OpenSSL / libsystemd / Win32-RPC code, which is
    ///     the hazard F3 names. No grace covers that tail (the drain loop returns
    ///     on the first zero); the exposure is identical for every run() worker
    ///     since rung 7 and is accepted (adversarial rounds 1/3/4, governance
    ///     pass 3). Splitting the moments lets the key-reuse fix, the refill
    ///     guarantee and the orphan-count accuracy all hold - merging them (as an
    ///     earlier revision did) freed the count at the QUOTA moment, while fn()
    ///     or the callback could still be running.
    /// `armed` is false until admission succeeds, so a ticket destroyed before /
    /// without admission is a no-op. A ticket destroyed WITHOUT either release
    /// having run first (the rollback / never-launched / never-published paths)
    /// still frees the key and the quota here - `key_released` / `quota_released`
    /// guard against a double release.
    struct TicketCore {
        explicit TicketCore(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~TicketCore() {
            if (!armed)
                return;
            {
                std::lock_guard<std::mutex> lk{state->mu};
                if (!quota_released) {
                    if (state->quota_held_total > 0)
                        --state->quota_held_total;
                    if (state->quota_held_by_class[ci] > 0)
                        --state->quota_held_by_class[ci];
                    quota_released = true;
                }
                if (state->alive_total > 0)
                    --state->alive_total;
                if (state->alive_by_class[ci] > 0)
                    --state->alive_by_class[ci];
                if (!key_released)
                    state->active_keys.erase(key_it); // nothrow: erase by valid iterator
            }
            state->cv.notify_all(); // after releasing the lock
        }
        void arm(std::size_t c, std::set<std::pair<int, std::string>>::iterator it) noexcept {
            ci = c;
            key_it = it;
            armed = true;
        }
        // Free ONLY the single-flight key; the CALLER must hold State::mu. Does NOT
        // touch the counts (see the class comment above) - a wedged run() worker
        // never reaches this call (it never publishes), preserving the dead-target
        // single-flight guard.
        void release_key_locked() noexcept {
            if (!armed || key_released)
                return;
            state->active_keys.erase(key_it);
            key_released = true;
        }
        // rung 9c R5.1: free the QUOTA slot and the key; the CALLER must hold
        // State::mu. Idempotent via `quota_released`; the alive counts stay held
        // until the destructor.
        void release_quota_locked() noexcept {
            if (!armed || quota_released)
                return;
            if (state->quota_held_total > 0)
                --state->quota_held_total;
            if (state->quota_held_by_class[ci] > 0)
                --state->quota_held_by_class[ci];
            quota_released = true;
            release_key_locked();
        }
        TicketCore(const TicketCore&) = delete;
        TicketCore& operator=(const TicketCore&) = delete;

        std::shared_ptr<State> state;
        std::size_t ci{0};
        std::set<std::pair<int, std::string>>::iterator key_it{};
        bool armed{false};
        bool key_released{false};
        bool quota_released{false};
    };
    using Ticket = std::shared_ptr<TicketCore>;

    /// Shared admission transaction for both dispatch forms; the CALLER holds
    /// State::mu. Order: stopping -> single-flight key -> quota -> physical ceiling
    /// (quota before ceiling so CeilingExhausted is only ever reported when quota
    /// has room). The two throwing steps - the contains() probe's pair key (a string
    /// copy) and set::insert - both run BEFORE the nothrow count bumps, so a bad_alloc
    /// in either leaves State unmutated; the ticket is armed last (pass-3 cx-2).
    /// On success `key` has been moved into the active set. Returns the rejection,
    /// or nullopt when admitted.
    [[nodiscard]] std::optional<IoFailure> admit_locked(std::size_t ci, std::string& key,
                                                        const Ticket& ticket) {
        if (state_->stopping)
            return IoFailure::Stopped;
        if (state_->active_keys.contains({static_cast<int>(ci), key})) {
            ++state_->counters[ci].rejected_key;
            return IoFailure::AlreadyRunning;
        }
        if (state_->quota_held_total >= state_->total_quota ||
            state_->quota_held_by_class[ci] >= state_->class_quota[ci]) {
            ++state_->counters[ci].rejected_capacity;
            return IoFailure::CapacityExhausted;
        }
        if (state_->alive_total >= state_->alive_ceiling) {
            ++state_->counters[ci].rejected_ceiling;
            return IoFailure::CeilingExhausted;
        }
        auto it = state_->active_keys.insert({static_cast<int>(ci), std::move(key)}).first;
        ++state_->quota_held_total;
        ++state_->quota_held_by_class[ci];
        ++state_->alive_total;
        ++state_->alive_by_class[ci];
        ticket->arm(ci, it);
        return std::nullopt;
    }

    /// Per-run() result slot. `done` + `result` are written once by the worker under
    /// State::mu; the submitter reads them under the same lock. The result is held
    /// by unique_ptr so publication is an unconditional nothrow pointer move (a
    /// result type whose own move is potentially-throwing, e.g. MSVC's
    /// std::unordered_map, would otherwise terminate the noexcept worker). A null
    /// pointer with done == true means the worker could not allocate its result box.
    /// `abandoned` (#3816): set by the caller, under State::mu, when it decides
    /// Timeout/Stopped instead of consuming a result; read by the worker, under the
    /// SAME lock, to decide whether to publish or route to on_abandoned. A plain
    /// bool is sufficient - both writers/readers always hold State::mu, there is no
    /// lock-free path to this cell. submit() has no cell: its result never crosses
    /// a thread boundary.
    template <class T>
    struct ResultCell {
        bool done{false};
        bool abandoned{false};
        std::unique_ptr<IoResult<T>> result;
    };

    std::shared_ptr<State> state_;
    std::atomic<bool> fail_launch_for_test_{false};
    std::atomic<bool> throw_before_wait_lock_for_test_{false};
};

// Tripwires (ADR-0021 rung 9a R3), at namespace scope so Config{}'s default member
// initializers are readable (they are not, inside the still-incomplete class).
//
// (1) Config carries EXACTLY the current IoClass set: adding an IoClass (which bumps
// kIoClassCount) fails this assert, forcing whoever adds it to give the class a quota
// AND extend the oversubscription sum below - so a new class can neither default to a
// 0 quota (silent never-admit) nor escape the ceiling check.
static_assert(kIoClassCount == 3,
              "A new IoClass was added: give it a Config quota and extend the "
              "oversubscription tripwire below to include it (ADR-0021 rung 9a R3).");
// (2) The default per-class quotas must not oversubscribe the process worker ceiling.
// A raised default (or the new class from (1)) that pushes the sum past
// kMaxProcessIoWorkers fails here - raise the ceiling deliberately or shrink a class,
// never silently oversubscribe.
static_assert(GuardianIoExecutor::Config{}.file_quota
                      + GuardianIoExecutor::Config{}.registry_quota
                      + GuardianIoExecutor::Config{}.service_quota
                  <= GuardianIoExecutor::kMaxProcessIoWorkers,
              "per-class I/O quotas oversubscribe kMaxProcessIoWorkers");
// (3) rung 9c R5.1: the physical alive-worker ceiling must sit STRICTLY above the
// quota total, or a full complement of callback-phase workers re-creates the exact
// cross-class starvation R3 eliminated (§7.7b item 5).
static_assert(GuardianIoExecutor::kAliveCeilingFactor >= 2,
              "kAliveCeilingFactor must be >= 2 so the alive ceiling exceeds the quota sum");
static_assert(GuardianIoExecutor::kMaxAliveIoWorkers > GuardianIoExecutor::kMaxProcessIoWorkers,
              "kMaxAliveIoWorkers must be strictly greater than kMaxProcessIoWorkers");

} // namespace yuzu::agent
