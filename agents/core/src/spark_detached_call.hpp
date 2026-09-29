#pragma once

/**
 * spark_detached_call.hpp - a bounded, detached "launch and let the owner
 * sweep" call primitive for Spark mechanisms (ADR-0021 Stage 2, #2012/#3840
 * plan: "bound File/Registry/Service watch establishment off the per-type
 * lock" - PR-A, "Shared primitive" section).
 *
 * WHY: within one mechanism type, a blocking OS call inside watch()/unwatch()
 * today holds SparkEngine::mech_ops_mu_by_type_[type] for its full, unbounded
 * duration and starves every other same-type arm/disarm. PR-B (a later,
 * separate piece of work) restructures File/Registry/Service to reserve
 * under their own mu_, unlock, run the blocking OS call on a detached,
 * counted worker bounded by a deadline D, relock, re-check staleness, and
 * commit or discard. THIS FILE is the primitive PR-B's mechanisms build on -
 * it does not itself touch any mechanism.
 *
 * PULL MODEL: the detached worker touches ONLY its own result cell; the
 * OWNER sweeps (try_take/wait_take/abandon). No callback ever runs on the
 * worker thread touching owner state - unlike GuardianIoExecutor::run's
 * on_abandoned callback (see "Versus GuardianIoExecutor::run" below), this
 * design has no push path at all, so there is no window where a worker
 * thread could reach into a mechanism's own mu_-guarded state.
 *
 * OWNERSHIP FIX (round-3 plan finding, replacing an earlier "launch_forget"
 * design this file does NOT ship): launch() takes ownership of the caller's
 * `Fn` ONLY on DetachedLaunch::Launched. On Rejected (lane cap) or
 * LaunchFailed (OS refused the thread, or an allocation failed), `Fn` is
 * handed back to the caller UNCONSUMED via the returned
 * DetachedLaunchResult::fn. The earlier "launch_forget" sketch took
 * ownership of a moved-in RAII payload unconditionally and could destroy it
 * SYNCHRONOUSLY ON THE CALLING THREAD on the rejected/failed path - exactly
 * the "blocking close under a lock" hazard the whole design exists to avoid.
 * See launch()'s own comments for how this is achieved even across every
 * allocation-failure path (not just the common OS-refused-thread path).
 *
 * F3 / §24 (`docs/yuzu-guardian-design-v1.1.md:2478-2487`): the process must
 * not run normal C++ teardown while any detached worker is alive - "a source
 * left out of the sum would silently reinstate the use-after-free the
 * joined-thread rule used to prevent by a different mechanism." Every
 * SparkDetachedLane is constructed with a shared `f3_counter` (agent-
 * lifetime-scoped, NOT lane- or SparkEngine-scoped - see agent.cpp's
 * spark_detached_workers_ member and its own doc comment for why it must
 * never be read through spark_engine_/spark_boot_done_). The counter is
 * incremented at admission and decremented ONLY when the worker's own
 * closure (Payload<T, DFn>, below) is fully destroyed - which, by
 * construction (see "Ticketing" below), is strictly after every piece of
 * worker-side code has finished running, including a self-disposed
 * (abandoned-before-publish) result's own destructor and any RAII state
 * `Fn` itself still holds after being called once. A lane's OWN
 * active_workers() count is a separate, lane-scoped mirror of the same
 * lifetime, incremented/decremented in lockstep with the shared F3 counter.
 *
 * TICKETING (mirrors GuardianIoExecutor's TicketCore admission-slot rule in
 * SPIRIT, guardian_io_executor.hpp:586-597 - read-only reference, this file does
 * not include or modify that class, and does NOT copy its shared_ptr-based
 * ownership shape; see launch()'s own "Payload is a std::unique_ptr, NOT a
 * shared_ptr" comment for why that specific difference is load-bearing,
 * found via a real TSan failure during this file's own development, not by
 * inspection): CountGuard (below) decrements the lane's active count + the
 * shared F3 counter when it is destroyed, at true OS-thread-exit time -
 * Payload<T, DFn> is owned via a raw-pointer handoff into a unique_ptr
 * reclaimed INSIDE the worker's own closure (launch()'s Phase 3), so
 * Payload is destroyed exactly once, unconditionally on the worker thread,
 * when that closure's own `owned` unique_ptr goes out of scope after the
 * worker's operator()() has fully returned (same "OS-thread-exit" wording
 * GuardianIoExecutor already uses for the equivalent case, now genuinely
 * true by construction rather than by which side of a shared_ptr race
 * happens to run last). CountGuard is deliberately the FIRST-declared
 * member of Payload<T, DFn> (cell and fn follow it) - struct members
 * destroy in REVERSE declaration order (specified by the standard, unlike
 * lambda-capture destruction order, which is UNSPECIFIED - an earlier
 * draft of this file captured {cell, ticket, fn} directly in a worker
 * lambda and relied on compiler behavior for the ordering; do not copy
 * that shape elsewhere), so `fn` (which may still hold live RAII state of
 * its own, separate from whatever T it returned) is ALWAYS destroyed
 * BEFORE CountGuard's destructor runs and decrements the counters. A
 * self-disposed T (the abandoned-before-publish path) is disposed even
 * earlier still - inside Payload::operator()()'s own local scope, before
 * that function even returns - so it is unconditionally covered by the same
 * property.
 *
 * EXACTLY-ONCE DELIVERY: the result lands in exactly one of {owner
 * try_take()/wait_take(), owner abandon()-returned-for-disposal, worker
 * self-disposes}. Cell<T> (mutex + cv + an atomic<bool> done HINT only +
 * `taken`/`abandoned` under the mutex + a boxed result) is shared between
 * the worker (via Payload) and the owner (via DetachedCall<T>) by
 * shared_ptr; every state transition is decided under cell.mu, so the
 * atomic done flag is never load-bearing for correctness, only for a
 * lock-free done() poll. DISPOSAL of the delivered value (running T's own
 * destructor) always happens OUTSIDE cell.mu, on whichever thread ends up
 * owning it - the worker's self-dispose path (Payload::operator()()'s own
 * local scope, after releasing the lock) and the owner's abandon()/handle-
 * destruction path (DetachedCall<T>::dispose_or_abandon() moves the boxed
 * result out of the cell under the lock, then lets it destruct after the
 * lock scope ends) both hold to this; only the CELL STATE TRANSITION itself
 * (publish/take/abandon) is ever decided under the lock, never T's teardown.
 *
 * Versus GuardianIoExecutor::run - deliberately omitted (that class solves
 * a related but different problem: a bounded, single-flight, keyed,
 * quota'd, WAIT-until-deadline read; this primitive is a bounded LAUNCH the
 * owner polls/sweeps later, potentially well past any per-call deadline):
 *   - per-class quotas: one SparkDetachedLane per mechanism concern already
 *     IS the bulkhead - a mechanism owning multiple lanes (e.g. Registry's
 *     probe lane + drain lane, PR-B) gets the same effect by construction.
 *   - keyed single-flight: the owner's own per-entry Pending/Arming state
 *     (PR-B's DirWatch/RegWatch/SvcWatch) IS the single-flight - this file
 *     has no notion of a "key" at all.
 *   - stop()/Stopped: GuardianIoExecutor wakes every waiter and rejects new
 *     submissions on stop(). This file has no stop() - the owning
 *     mechanism's own mu_-guarded stop() decides when to stop calling
 *     launch() and to abandon() every outstanding DetachedCall<T>; a lane
 *     that outlives its mechanism (destroyed while a worker is still
 *     parked - the F3 regression scenario) is a supported, tested state.
 *   - push-style on_abandoned callback: would run on the worker thread and
 *     touch owner state - the whole reason the pull model exists is to
 *     avoid this. A mechanism wanting "do something when a late result
 *     shows up" polls for it (PR-B's sweeper threads).
 *   - DetachedWaiter (an earlier design-round sketch of a returned waitable
 *     handle): omitted - PR-B's sweepers are poll-based (try_take() in a
 *     loop against their own cadence), so there is no present consumer for
 *     a separate wait-composition primitive. Add one if/when a real
 *     multi-waiter or cv-composition need arises; wait_take(deadline)
 *     already covers the single-waiter case this file's own tests need.
 *
 * NOT REUSABLE: agents/shared/bounded_wait.hpp::bounded_call_ex - discards
 * late results (a leaked handle from this primitive's point of view),
 * shares a process-global cap with DNS/discovery work unrelated to Spark,
 * and its worker count is invisible to F3. Left untouched; this file
 * deliberately avoids the "BoundedCall" name to avoid implying kinship.
 */

#include "guardian_io_executor.hpp" // io_detail::spawn_detached - reused as a
                                    // low-level primitive ONLY; this file does
                                    // not otherwise depend on GuardianIoExecutor.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <new> // std::bad_alloc - fail_first_box_alloc_for_test seam
#include <optional>
#include <type_traits>
#include <utility>

namespace yuzu::agent {

/// Outcome of one launch() call.
enum class DetachedLaunch : std::uint8_t {
    Launched,     ///< admitted and spawned; a DetachedCall<T> handle is returned
    Rejected,     ///< the lane's cap was full - Fn is returned, unconsumed
    LaunchFailed, ///< the OS refused the thread, or an allocation failed -
                 ///< Fn is returned, unconsumed
};

/// Why a launched call's result is not a plain T.
enum class DetachedCallError : std::uint8_t {
    WorkerThrew,       ///< fn() threw; contained, the worker never terminates
    ResultAllocFailed, ///< the worker could not box a result - EITHER fn()
                       ///< succeeded and only its result's own box allocation
                       ///< failed (the more likely real-world cause, no
                       ///< antecedent exception needed), OR fn() threw and
                       ///< the WorkerThrew error box itself then also failed
                       ///< to allocate (Gate 4 consistency-auditor finding,
                       ///< PR-A round 5: this comment named only the second
                       ///< cause) - done() is still true either way
};

template <class T>
using DetachedResult = std::expected<T, DetachedCallError>;

namespace detached_detail {

/// Per-run result slot, shared by the worker (via Payload) and the owner
/// (via DetachedCall<T>). `done_hint` is a lock-free HINT only - every
/// actual state transition (publish, take, abandon) is decided under `mu`;
/// `done_hint` exists solely so DetachedCall<T>::done() can poll without
/// taking the lock.
template <class T>
struct Cell {
    std::mutex mu;
    std::condition_variable cv;
    std::atomic<bool> done_hint{false};
    bool done{false};      // guarded by mu
    bool taken{false};     // guarded by mu
    bool abandoned{false}; // guarded by mu
    std::unique_ptr<DetachedResult<T>> result; // guarded by mu. `taken` is the SOLE re-entry/
                                               // validity gate for this field, independent of
                                               // its nullness. Exactly two states are reachable
                                               // once `taken` is true (colleague review, PR
                                               // #4190: take_locked() used to leave this
                                               // engaged-but-moved-from on a successful take -
                                               // a THIRD state this comment used to document -
                                               // until that shape was found to force T's
                                               // disposal under this same lock via a different
                                               // route; take_locked() now moves the WHOLE box
                                               // out on every taking path, so "moved-from-non-
                                               // null" is no longer reachable here at all):
                                               // null (never boxed, a ResultAllocFailed
                                               // publish - take_locked() never touches this
                                               // field), or null-because-moved-out (an ordinary
                                               // take_locked() success, or dispose_or_abandon()'s
                                               // published-but-untaken path - both move the
                                               // unique_ptr itself out under this lock; see
                                               // take_locked()'s and dispose_or_abandon()'s own
                                               // comments)
};

/// Shared per-lane state: the admission cap/count, the shared agent-lifetime
/// F3 counter, and cumulative counters. Held by shared_ptr so a worker's
/// CountGuard (below) keeps it alive even after the owning SparkDetachedLane
/// (and the mechanism that owns THAT) is destroyed - the exact scenario the
/// F3 regression test exercises: a lane destroyed while a worker is still
/// parked must not silently stop counting that worker.
struct LaneState {
    std::shared_ptr<std::atomic<std::size_t>> f3_counter; // may be null (tests)
    std::atomic<std::size_t> active{0};
    std::atomic<std::size_t> cap{0};
    std::atomic<std::uint64_t> rejected_total{0};
    std::atomic<std::uint64_t> launch_failed_total{0};
    std::atomic<std::uint64_t> worker_threw_total{0};
    std::atomic<bool> fail_launch_for_test{false};
    // Test seam only: forces Payload::operator()() to discard its own
    // successfully-boxed result immediately after computing it, so a test
    // can reach the ResultAllocFailed path deterministically. There is no
    // portable way to make std::make_unique<DetachedResult<T>> itself fail
    // (it would need a global operator-new hook), so this is one of two
    // seams that exercise take_locked()'s null-result branch (the other is
    // fail_first_box_alloc_for_test below, which reaches the SAME branch by
    // a different route - the fn()-succeeded path's inner catch, not this
    // seam's post-hoc discard, which runs unconditionally after both catch
    // blocks resolve, regardless of which outcome occurred; Gate 4
    // consistency-auditor finding, PR-A round 5, wording tightened at pass
    // 5: this comment previously claimed to be the ONLY way, which
    // fail_first_box_alloc_for_test's own later addition made false, and
    // then briefly mischaracterized this seam as gated to one branch).
    // NOTE: this seam's discard happens OUTSIDE operator()()'s try/catch, so
    // it never itself SETS worker_threw_total (whether the counter ends up
    // 0 depends only on whether fn() threw, same as without this seam
    // active) - it cannot exercise the FIRST box's own allocation failing
    // INSIDE the try/catch (see fail_first_box_alloc_for_test below for
    // that path specifically).
    std::atomic<bool> fail_result_alloc_for_test{false};
    // Test seam only: makes the FIRST box allocation (wrapping fn()'s real
    // return value) throw std::bad_alloc from inside operator()()'s inner
    // try, deterministically exercising the fix that separates fn()'s own
    // throw from its result's box-allocation failure - the two are
    // DELIBERATELY classified differently (ResultAllocFailed here, never
    // WorkerThrew, since fn() itself ran to completion). Checked only on
    // the success path (fn() didn't throw); the WorkerThrew error box's own
    // allocation has no equivalent seam - fail_result_alloc_for_test above
    // already covers "even the error box didn't fit" via its post-hoc
    // discard, which is adequate there since that path's classification
    // (WorkerThrew) doesn't depend on distinguishing which allocation
    // failed.
    std::atomic<bool> fail_first_box_alloc_for_test{false};
};

/// Decrements the lane's active-worker count and the shared F3 counter when
/// destroyed. See this file's header comment ("Ticketing") for why its
/// position as Payload's FIRST-declared member (destroyed LAST) is
/// load-bearing, not cosmetic. Move-only (needed so a temporary can be
/// forwarded into Payload's constructor - see launch()'s "Ownership fix"
/// comments for why this specific shape lets a failed make_unique leave the
/// caller's Fn provably untouched).
struct CountGuard {
    std::shared_ptr<LaneState> lane;
    bool armed{false};

    CountGuard() = default;
    explicit CountGuard(std::shared_ptr<LaneState> l) noexcept : lane(std::move(l)), armed(true) {}
    CountGuard(const CountGuard&) = delete;
    CountGuard& operator=(const CountGuard&) = delete;
    CountGuard(CountGuard&& other) noexcept : lane(std::move(other.lane)), armed(other.armed) {
        other.armed = false;
    }
    CountGuard& operator=(CountGuard&&) = delete; // not needed - constructed in place once
    ~CountGuard() {
        if (!armed)
            return;
        lane->active.fetch_sub(1, std::memory_order_acq_rel);
        if (lane->f3_counter)
            lane->f3_counter->fetch_sub(1, std::memory_order_acq_rel);
    }
};

} // namespace detached_detail

/// Owner-side handle to one launched call. Move-only. Destroying a handle
/// while its call is still in flight ("parked") is safe (no data races,
/// TSan-confirmed - zero races across the full [spark] tag; UAF-freedom
/// argued by construction - see this file's "Ticketing"/exactly-once
/// commentary above - but NOT independently confirmed by a sanitizer:
/// ASan was attempted this session and blocked on this box by a pre-
/// existing, unrelated protobuf/abseil static-init false-positive that
/// reproduces for ANY test in this binary, confirmed via an unrelated tag
/// - governance finding, PR-A round 2, tightened at Gate 8 - TSan proves
/// race-freedom, not UAF-freedom, and conflating the two overclaimed what
/// was actually verified here) and behaves like an implicit abandon() - a not-yet-
/// published result is disposed by the WORKER when it eventually completes;
/// an already-published-but-untaken result is disposed right here, on
/// whichever thread destroys the handle (fast: T is a result value or an
/// RAII handle to close, never the original blocking OS call itself).
template <class T>
class DetachedCall {
public:
    DetachedCall() noexcept = default; // empty handle; every method is then a safe no-op
    DetachedCall(const DetachedCall&) = delete;
    DetachedCall& operator=(const DetachedCall&) = delete;
    DetachedCall(DetachedCall&&) noexcept = default;
    // User-defined, NOT = default (governance finding, PR-A round 2): a
    // defaulted move-assignment would overwrite cell_ without ever calling
    // dispose_or_abandon() on the handle's PRIOR cell - silently discarding
    // whatever that older call's result was (or leaving it perpetually
    // un-abandoned if not yet published), a fourth, undocumented delivery
    // path outside this class's own "exactly-once" enumeration above. No
    // UAF/leak either way (the worker's own Payload::cell reference keeps
    // the old Cell<T> alive independently, and it self-tears-down via
    // ~Cell on the worker thread once that worker eventually finishes) -
    // but a caller reassigning a live handle (`pending_[key] = lane.launch(
    // ...).call`, the exact shape PR-B's per-key sweepers use) deserves the
    // same disposal/abandonment semantics destruction already gives it.
    DetachedCall& operator=(DetachedCall&& other) noexcept {
        if (this != &other) {
            dispose_or_abandon();
            cell_ = std::move(other.cell_);
        }
        return *this;
    }

    ~DetachedCall() { dispose_or_abandon(); }

    /// Lock-free poll - a HINT only (see Cell<T>'s doc comment). Never
    /// blocks, never mutates state.
    [[nodiscard]] bool done() const noexcept {
        return !cell_ || cell_->done_hint.load(std::memory_order_acquire);
    }

    /// Non-blocking. Returns the result exactly once - nullopt if not yet
    /// done, or if it was already taken (by a prior try_take/wait_take/
    /// abandon call).
    [[nodiscard]] std::optional<DetachedResult<T>> try_take() {
        if (!cell_)
            return std::nullopt;
        std::optional<std::unique_ptr<DetachedResult<T>>> boxed;
        {
            std::lock_guard<std::mutex> lk(cell_->mu);
            boxed = take_locked();
        }
        return unbox(std::move(boxed));
    }

    /// Blocks until `deadline` or the result is published, whichever comes
    /// first. A timeout returns nullopt WITHOUT abandoning the call - a
    /// later wait_take()/try_take() can still take the late result exactly
    /// once (this is the "gated fn -> Timeout then exactly-once late take"
    /// contract).
    [[nodiscard]] std::optional<DetachedResult<T>>
    wait_take(std::chrono::steady_clock::time_point deadline) {
        if (!cell_)
            return std::nullopt;
        std::optional<std::unique_ptr<DetachedResult<T>>> boxed;
        {
            std::unique_lock<std::mutex> lk(cell_->mu);
            cell_->cv.wait_until(lk, deadline, [this] { return cell_->done; });
            boxed = take_locked();
        }
        return unbox(std::move(boxed));
    }

    /// Give up on this call. Published-but-untaken -> the result is
    /// returned to the caller here (for disposal); not-yet-published -> the
    /// worker is told to self-dispose when it eventually completes, and
    /// nullopt is returned. Exactly once - a second abandon() (or a
    /// try_take/wait_take after one) always returns nullopt. noexcept:
    /// take_locked() only pointer-moves the boxed result (see its own
    /// comment) and unbox() only runs after cell_->mu is released, so no
    /// exception-under-lock path exists here; unbox()'s own T-move is
    /// COMPILE-TIME ENFORCED nothrow by launch()'s own
    /// static_assert(is_nothrow_move_constructible_v<T>).
    [[nodiscard]] std::optional<DetachedResult<T>> abandon() noexcept {
        if (!cell_)
            return std::nullopt;
        std::optional<std::unique_ptr<DetachedResult<T>>> boxed;
        {
            std::lock_guard<std::mutex> lk(cell_->mu);
            boxed = take_locked();
            cell_->abandoned = true;
        }
        return unbox(std::move(boxed));
    }

    /// Constructs a handle directly over an existing cell. PUBLIC (not
    /// friend-restricted to SparkDetachedLane) deliberately: std::optional<
    /// DetachedCall<T>>::emplace(...) - which DetachedLaunchResult's
    /// construction inside launch() relies on - performs its placement-new
    /// from INSIDE <optional>'s own implementation, not from SparkDetachedLane's
    /// lexical scope, so friendship granted to SparkDetachedLane does not
    /// propagate through that call (a well-known C++ access-control gotcha:
    /// friendship is not transitive through a library helper). `cell` lives
    /// in the detached_detail:: implementation-namespace, which is
    /// sufficient practical protection against external misuse without the
    /// access-control complexity of befriending std::optional's
    /// instantiation itself.
    explicit DetachedCall(std::shared_ptr<detached_detail::Cell<T>> cell) noexcept
        : cell_(std::move(cell)) {}

private:
    /// Caller must hold cell_->mu. Returns nullopt if not yet done or
    /// already taken. Otherwise sets `taken` and hands back OWNERSHIP OF
    /// THE BOX ITSELF (a pointer move only - T is never touched, moved, or
    /// destroyed here), which may itself be null: a null cell_->result (the
    /// worker could not box a result - EITHER of Payload::operator()'s two
    /// catch blocks, see DetachedCallError::ResultAllocFailed's own comment
    /// for both causes - Gate 4 consistency-auditor finding, PR-A round 5:
    /// this comment previously named only the second/outer catch) is a
    /// real, reachable state, not a defect: `done` is still true (Cell<T>'s
    /// doc comment), so take_locked() must not assume `result` is engaged
    /// just because `done` is. Mirrors the SHAPE of GuardianIoExecutor::
    /// run's own null-check (guardian_io_executor.hpp, its `if (cell->
    /// result) ... return IoResult<T>{...WorkerThrew};` - confirmed by
    /// reading that file directly, not from memory) - the MAPPING differs
    /// deliberately: that file folds an alloc-starved worker into its
    /// existing WorkerThrew, since its IoFailure enum has no separate case
    /// for it; this file's DetachedCallError does, so it maps to
    /// ResultAllocFailed instead, decided by unbox() (below) once the box
    /// this function returns is examined OUTSIDE the lock. Neither is
    /// independently tested against a real allocation failure (no portable
    /// operator-new hook); this file adds a dedicated test seam
    /// (LaneState::fail_result_alloc_for_test) to reach the same
    /// null-`result` STATE deterministically, which GuardianIoExecutor's
    /// own test suite does not have an equivalent for.
    ///
    /// MUST NOT touch T: an earlier version of this function moved T out of
    /// the box itself (`auto out = std::move(*cell_->result); return out;`)
    /// and returned `std::optional<DetachedResult<T>>` directly. That is a
    /// genuine bug, not a style choice - colleague review on PR #4190 (the
    /// finding this rewrite fixes) traced it precisely: the return
    /// statement's type (optional<DetachedResult<T>>) differs from `out`'s
    /// type (DetachedResult<T>), so NRVO cannot apply; `out` is move-
    /// constructed into the returned optional, and the MOVED-FROM `out`
    /// (a std::expected, which - unlike optional/unique_ptr - does NOT
    /// reset itself to an empty/no-value state on move; see the old
    /// comment this replaced) is then destroyed at this function's own
    /// scope exit, running ~T() on a moved-from T - and that destruction
    /// happens BEFORE the caller's lock_guard releases cell_->mu, since
    /// this function's stack frame unwinds strictly before try_take()/
    /// wait_take()/abandon() return to release it. For a T whose moved-from
    /// destructor does blocking or lock-taking work, that violates this
    /// file's own "DISPOSAL ... always happens OUTSIDE cell.mu" contract
    /// (see the file header comment). This function now only pointer-moves
    /// the box (a nothrow, non-blocking unique_ptr move, same as
    /// dispose_or_abandon()'s already-correct `to_dispose = std::move(
    /// cell_->result)` below) - T is moved out of the box, and the box's
    /// own moved-from remnant destroyed, only inside unbox(), which every
    /// caller runs strictly after releasing cell_->mu.
    std::optional<std::unique_ptr<DetachedResult<T>>> take_locked() {
        if (!cell_->done || cell_->taken)
            return std::nullopt;
        cell_->taken = true;
        return std::move(cell_->result); // pointer move only; may itself be
                                          // null (ResultAllocFailed state) -
                                          // unbox() resolves both cases.
    }

    /// Converts a take_locked() box into the public DetachedResult<T>
    /// optional. MUST be called with cell_->mu already released - this is
    /// where T is actually moved out of the box (if present) and where the
    /// box's own moved-from remnant is destroyed, at this function's own
    /// return. noexcept: T's move is compile-time enforced nothrow by
    /// launch()'s static_assert(is_nothrow_move_constructible_v<T>), and
    /// DetachedCallError is a trivially-movable enum, so DetachedResult<T>'s
    /// (std::expected's) move ctor is standard-specified noexcept given
    /// those two - nothing in this function's body can throw either way it
    /// resolves, which is what this function's own noexcept relies on (the
    /// standard does not itself mandate optional's converting constructor
    /// carry a matching conditional-noexcept the way optional's own move
    /// constructor does; not load-bearing here, since the move it performs
    /// cannot throw regardless).
    static std::optional<DetachedResult<T>>
    unbox(std::optional<std::unique_ptr<DetachedResult<T>>> boxed) noexcept {
        if (!boxed)
            return std::nullopt; // not yet done, or already taken
        if (!*boxed)
            return DetachedResult<T>{std::unexpect, DetachedCallError::ResultAllocFailed};
        return std::move(**boxed);
    }

    /// Disposes a published-but-untaken result OUTSIDE cell_->mu - matching
    /// this file's own "EXACTLY-ONCE DELIVERY" contract that disposal never
    /// runs under the cell's lock (only the worker's self-dispose path and
    /// the owner's abandon()-then-later-destroy path were exercised under
    /// that rule before; this is the third, and it held the lock across
    /// T's destructor in an earlier draft - a mistake for the same reason
    /// the primitive avoids running arbitrary teardown under any lock at
    /// all). The unique_ptr is moved out under the lock (a nothrow pointer
    /// move) and destroyed after the lock scope ends.
    void dispose_or_abandon() noexcept {
        if (!cell_)
            return;
        std::unique_ptr<DetachedResult<T>> to_dispose;
        {
            std::lock_guard<std::mutex> lk(cell_->mu);
            if (cell_->taken)
                return;
            if (cell_->done) {
                cell_->taken = true;
                to_dispose = std::move(cell_->result); // disposed below, outside cell_->mu
            } else {
                cell_->abandoned = true; // tell the worker to self-dispose later
                return;
            }
        }
        // to_dispose's destructor (T's, if engaged) runs here, on the
        // destructing thread, outside cell_->mu.
    }

    std::shared_ptr<detached_detail::Cell<T>> cell_;
};

namespace detached_detail {

/// The worker's own closure. Members declared in this EXACT order -
/// `guard` first, `fn` last - so reverse-declaration-order destruction
/// destroys `fn` (and any RAII state it still holds) before `guard`
/// decrements the lane/F3 counters. See this file's header comment
/// ("Ticketing") for the full argument. The templated constructor exists
/// (rather than a plain by-value `DFn fn` parameter) so launch() can pass
/// `std::forward<Fn>(fn_in)` all the way through to `make_unique`, which
/// only performs the actual move INSIDE the placement-new it runs strictly
/// after its own allocation succeeds - the property launch()'s "Ownership
/// fix" comments rely on to guarantee Fn is untouched on every allocation-
/// failure path, not just the OS-refused-thread one.
template <class T, class DFn>
struct Payload {
    CountGuard guard;
    std::shared_ptr<Cell<T>> cell;
    DFn fn;

    template <class F>
    Payload(CountGuard g, std::shared_ptr<Cell<T>> c, F&& f)
        : guard(std::move(g)), cell(std::move(c)), fn(std::forward<F>(f)) {}

    /// Runs on the detached worker thread. noexcept: fn() itself is the
    /// only thing here that may throw, and it is fully contained. fn()'s
    /// invocation and the allocation of its result box are DELIBERATELY
    /// separate try blocks (adversarial-review finding, PR-A round 2): a
    /// single enclosing try around `make_unique<DetachedResult<T>>(fn())`
    /// would classify a first-box bad_alloc AFTER a successful fn() call as
    /// WorkerThrew - the callable didn't throw, only its result's boxing
    /// did, and that is exactly what ResultAllocFailed exists to name. The
    /// outer try covers ONLY fn(); a caught exception there is a genuine
    /// callable throw. The inner try covers ONLY boxing (T's move into the
    /// box is nothrow per the class static_assert below, so a throw there
    /// can only be the allocation itself) and never sets `threw`.
    void operator()() noexcept {
        std::unique_ptr<DetachedResult<T>> boxed;
        bool threw = false;
        try {
            T value = fn();
            try {
                if (guard.lane->fail_first_box_alloc_for_test.load(std::memory_order_relaxed))
                    throw std::bad_alloc{}; // test seam only - see its own doc comment
                boxed = std::make_unique<DetachedResult<T>>(std::move(value));
            } catch (...) {
                boxed.reset(); // ResultAllocFailed - fn() succeeded; only its
                              // result's box allocation failed
            }
        } catch (...) {
            threw = true;
            try {
                boxed = std::make_unique<DetachedResult<T>>(std::unexpect,
                                                            DetachedCallError::WorkerThrew);
            } catch (...) {
                boxed.reset(); // ResultAllocFailed - even the error box didn't fit
            }
        }
        if (guard.lane->fail_result_alloc_for_test.load(std::memory_order_relaxed)) {
            // Test seam only (LaneState::fail_result_alloc_for_test's doc
            // comment) - discard whatever was successfully boxed above so a
            // test can reach the ResultAllocFailed path deterministically,
            // without a global operator-new hook.
            boxed.reset();
        }
        bool was_abandoned = false;
        {
            std::lock_guard<std::mutex> lk(cell->mu);
            was_abandoned = cell->abandoned;
            if (!was_abandoned) {
                cell->result = std::move(boxed); // nothrow: unique_ptr pointer move
                cell->done = true;
                cell->done_hint.store(true, std::memory_order_release);
            }
        }
        if (threw)
            guard.lane->worker_threw_total.fetch_add(1, std::memory_order_relaxed);
        cell->cv.notify_all(); // after releasing the lock - harmless if no one is waiting
        // If was_abandoned, `boxed` is still held LOCALLY here (never moved
        // into the cell) - it is disposed when this function returns (T's
        // destructor runs as part of this function's own stack unwind),
        // strictly BEFORE `guard` (this object's own first-declared, thus
        // last-destroyed, member) can decrement the lane/F3 counters. This
        // is the self-dispose path's whole safety argument - it does not
        // depend on member-destruction order at all, only on this function
        // fully completing before Payload itself is destroyed (true by
        // construction: Payload is destroyed by spawn_detached's trampoline
        // strictly after operator()() returns).
    }
};

} // namespace detached_detail

/// Result of one launch() call. `call` is engaged iff status == Launched;
/// `fn` is engaged iff status != Launched (Rejected or LaunchFailed) and
/// holds the caller's ORIGINAL, unconsumed callable - see this file's
/// header comment ("Ownership fix").
template <class T, class DFn>
struct DetachedLaunchResult {
    DetachedLaunch status{DetachedLaunch::LaunchFailed};
    std::optional<DetachedCall<T>> call;
    std::optional<DFn> fn;
};

/// One lane: an admission cap + a lock-free active-worker count, backed by
/// LaneState shared with every in-flight worker (so a lane destroyed while a
/// worker is still parked does not stop that worker from being counted -
/// see this file's header comment on F3). A mechanism owns one
/// SparkDetachedLane per detached-call concern (PR-B: one per mechanism, or
/// two for Registry's separate probe/drain lanes) - the lane itself IS the
/// per-concern bulkhead; see "Versus GuardianIoExecutor::run" above for why
/// no separate quota/keying layer is added on top.
class SparkDetachedLane {
public:
    /// `f3_counter` is the process/agent-lifetime-scoped counter every lane
    /// in the process shares (may be null in a test that only cares about
    /// the lane's own active_workers()). `cap` is the maximum number of
    /// concurrently in-flight workers this lane admits; 0 is a valid,
    /// well-defined "never admit" configuration (used by the cap-rejection
    /// regression test), not clamped up to 1.
    explicit SparkDetachedLane(std::shared_ptr<std::atomic<std::size_t>> f3_counter,
                               std::size_t cap)
        : state_(std::make_shared<detached_detail::LaneState>()) {
        state_->f3_counter = std::move(f3_counter);
        state_->cap.store(cap, std::memory_order_relaxed);
    }

    // Deliberately non-movable, not just non-copyable (colleague review,
    // PR #4190): a lane is a bulkhead identity for one mechanism concern
    // (the file header's "Versus GuardianIoExecutor::run" section), not a
    // value - and the defaulted move this used to have left the moved-from
    // lane's state_ null while every other method (launch(), active_
    // workers(), etc.) derefs state_ unconditionally, so a moved-from lane
    // was a live use-after-move footgun with no production caller today to
    // catch it. No caller in this file, PR-B's plan, or any test moves a
    // SparkDetachedLane - it is always constructed once, in place, and
    // owned for the lifetime of the mechanism/lane owner - so deleting the
    // move ops removes the footgun rather than defending against a need
    // that does not exist.
    SparkDetachedLane(const SparkDetachedLane&) = delete;
    SparkDetachedLane& operator=(const SparkDetachedLane&) = delete;
    SparkDetachedLane(SparkDetachedLane&&) = delete;
    SparkDetachedLane& operator=(SparkDetachedLane&&) = delete;

    /// Launches `fn` (a nullary callable) on a detached worker if the lane
    /// has capacity. `fn`'s return type T becomes the call's result type.
    ///
    /// OWNERSHIP: `fn` is consumed (moved from) ONLY on DetachedLaunch::
    /// Launched. On Rejected or LaunchFailed, the returned
    /// DetachedLaunchResult::fn holds the caller's original, unconsumed
    /// callable - see this file's header comment for the full argument,
    /// including why this holds even across an allocation failure deep
    /// inside launch()'s own admission machinery, not merely the common
    /// OS-refused-thread case.
    template <class Fn>
    [[nodiscard]] auto launch(Fn&& fn_in) {
        using DFn = std::decay_t<Fn>;
        static_assert(std::is_invocable_v<DFn&>,
                      "SparkDetachedLane::launch: Fn must be callable with no arguments - "
                      "it is invoked as fn() on the detached worker.");
        using T = std::invoke_result_t<DFn&>;
        static_assert(
            std::is_nothrow_move_constructible_v<T>,
            "SparkDetachedLane::launch: the result type T must be nothrow-move-constructible "
            "- the worker publishes its result into the cell by a move (boxed inside a "
            "unique_ptr, so the move itself happens once, at construction of the box); a "
            "throwing move there has no defined recovery in this design.");
        static_assert(
            std::is_nothrow_move_constructible_v<DFn>,
            "SparkDetachedLane::launch: Fn itself must be nothrow-move-constructible - a "
            "rejected or failed launch hands Fn back to the caller by a move, and a "
            "throwing move there would leave that handoff in an indeterminate state (see "
            "this file's header comment, 'Ownership fix').");
        static_assert(
            std::is_same_v<Fn, DFn>,
            "SparkDetachedLane::launch: fn must be passed as an rvalue of exactly its own "
            "value type (a temporary, or an lvalue wrapped in std::move()) - colleague "
            "review, PR #4190, tightened twice: an lvalue Fn deduces Fn = DFn&, and the "
            "Rejected/LaunchFailed hand-back path (r.fn.emplace(std::forward<Fn>(fn_in))) "
            "would then COPY-construct DFn instead of moving it - only DFn's MOVE "
            "constructor is required nothrow above, its copy constructor is unconstrained "
            "and may throw, which would make launch() itself throw on the Rejected/"
            "LaunchFailed path, contradicting this function's documented {status, fn} "
            "contract (see 'Ownership fix' in the file header comment). A first version of "
            "this assert used is_rvalue_reference_v<Fn&&>, which a CONST-qualified rvalue "
            "(e.g. `const auto fn = ...; lane.launch(std::move(fn));`, deducing Fn = const "
            "DFn, so Fn&& = const DFn&&) still satisfies while silently falling back to the "
            "same unconstrained copy constructor this assert exists to foreclose, since a "
            "const rvalue cannot bind DFn's move constructor - is_same_v<Fn, DFn> forecloses "
            "both the lvalue-reference and the const-qualified-rvalue case in one predicate "
            "(two independent Gate 8 reviewers found the same gap in the same session). "
            "Every caller in this file's own tests already passes a plain prvalue lambda, so "
            "this closes a hazard with no current caller, not a live defect.");

        using Result = DetachedLaunchResult<T, DFn>;
        using P = detached_detail::Payload<T, DFn>;

        // Phase 1: admission. fn_in is NOT touched anywhere in this phase -
        // see the header comment. active.fetch_add(1)+1 > cap -> Rejected,
        // rolled back, fn_in returned unconsumed.
        const std::size_t prev = state_->active.fetch_add(1, std::memory_order_acq_rel);
        if (prev + 1 > state_->cap.load(std::memory_order_acquire)) {
            state_->active.fetch_sub(1, std::memory_order_acq_rel);
            state_->rejected_total.fetch_add(1, std::memory_order_relaxed);
            Result r;
            r.status = DetachedLaunch::Rejected;
            r.fn.emplace(std::forward<Fn>(fn_in));
            return r;
        }
        if (state_->f3_counter)
            state_->f3_counter->fetch_add(1, std::memory_order_acq_rel);

        const auto roll_back_admission = [this] {
            state_->active.fetch_sub(1, std::memory_order_acq_rel);
            if (state_->f3_counter)
                state_->f3_counter->fetch_sub(1, std::memory_order_acq_rel);
        };

        // Test seam: force a deterministic LaunchFailed before touching
        // fn_in or spawning anything real (set_fail_launch_for_test).
        if (state_->fail_launch_for_test.load(std::memory_order_relaxed)) {
            roll_back_admission();
            state_->launch_failed_total.fetch_add(1, std::memory_order_relaxed);
            Result r;
            r.status = DetachedLaunch::LaunchFailed;
            r.fn.emplace(std::forward<Fn>(fn_in));
            return r;
        }

        // Phase 2: construct the Cell + Payload. If EITHER allocation
        // throws (bad_alloc), fn_in is guaranteed untouched: Cell's
        // allocation never involves fn at all, and Payload's constructor
        // only moves fn from within the placement-new make_unique performs
        // STRICTLY AFTER its own allocation succeeds - see Payload's own
        // doc comment. The temporary CountGuard{state_} constructed as
        // make_unique's first argument is, if the allocation fails,
        // destroyed by ordinary exception-unwind of the failed full-
        // expression - which itself performs exactly the rollback
        // roll_back_admission() would, so this catch block does NOT call
        // roll_back_admission() a second time on this path either (see the
        // comment at the catch site).
        //
        // Payload is a std::unique_ptr, NOT a shared_ptr - this is
        // LOAD-BEARING, not a style choice (round-3-of-implementation
        // correction, found via a real TSan failure, not by inspection: an
        // earlier draft used shared_ptr here, mirroring GuardianIoExecutor's
        // `ticket` idiom below in spirit, keeping a copy alive in `launch()`
        // across spawn_detached and dropping it via `payload.reset()` on
        // success. shared_ptr's destroy-on-last-reference semantics do not
        // care WHICH side drops the last reference - under TSan's different
        // scheduling (and, more rarely, on a fast unsanitized run too), the
        // worker could finish and drop ITS copy BEFORE `launch()` reached
        // its own `.reset()`, making `launch()`'s `.reset()` - running on
        // the CALLING thread - the one that hits refcount-zero and
        // therefore runs Payload's ENTIRE destructor chain, including fn's
        // arbitrary user-supplied teardown, SYNCHRONOUSLY INSIDE launch().
        // That is exactly the "blocking close under a lock" hazard class
        // this whole primitive exists to avoid - launch() must never be
        // able to block on a completed worker's cleanup. unique_ptr fixes
        // this structurally: ownership is handed off via a RAW POINTER
        // (spawn_detached's own DetachedPayload<Fn> does the identical
        // thing internally), reclaimed into a FRESH unique_ptr INSIDE the
        // worker's own closure body - so the worker is the sole,
        // unambiguous owner from the moment its closure starts running, and
        // `launch()`'s own `.release()` on the success path (see below)
        // NEVER dereferences or deletes anything, so it can never race.
        std::shared_ptr<detached_detail::Cell<T>> cell;
        std::unique_ptr<P> payload;
        bool countguard_temporary_may_have_rolled_back = false;
        try {
            cell = std::make_shared<detached_detail::Cell<T>>();
            countguard_temporary_may_have_rolled_back = true; // past this point, a throw
                                                               // unwinds a constructed
                                                               // CountGuard temporary
            payload =
                std::make_unique<P>(detached_detail::CountGuard{state_}, cell, std::forward<Fn>(fn_in));
        } catch (...) {
            if (!countguard_temporary_may_have_rolled_back)
                roll_back_admission(); // threw before the CountGuard temporary
                                       // existed (Cell's own allocation) - no
                                       // auto-rollback happened, so do it here
            state_->launch_failed_total.fetch_add(1, std::memory_order_relaxed);
            Result r;
            r.status = DetachedLaunch::LaunchFailed;
            r.fn.emplace(std::forward<Fn>(fn_in));
            return r;
        }

        // Phase 3: spawn. Hand off via a RAW pointer - the closure below
        // reclaims sole ownership into ITS OWN unique_ptr the moment it
        // starts running (on the worker thread), so there is exactly one
        // owner at every instant after this point, never two racing to be
        // "last". `payload` (still held here, in launch()) is untouched by
        // whatever the worker does with the raw pointer - see below.
        P* raw = payload.get();
        bool launched = false;
        try {
            launched = io_detail::spawn_detached([raw]() noexcept {
                std::unique_ptr<P> owned{raw}; // sole ownership from HERE, on the worker thread
                (*owned)();
                // `owned` destructs at the end of THIS scope, on the WORKER
                // thread, unconditionally - fn's teardown and CountGuard's
                // decrement both happen here, never on any other thread.
            });
        } catch (...) {
            // spawn_detached's own doc comment: "May throw std::bad_alloc
            // from the single payload allocation" - that allocation (`new
            // P{...}` inside spawn_detached, guardian_io_executor.hpp)
            // happens STRICTLY BEFORE pthread_create/_beginthreadex, so a
            // throw here means the OS thread was never created and the
            // closure above never ran - `raw` was never reclaimed by
            // anyone, so `payload` (still ours, untouched) remains the sole
            // owner, exactly like the `!launched` case below. Treating a
            // thrown bad_alloc identically to an OS-refused-thread
            // LaunchFailed (rather than letting it escape launch()) is what
            // the plan's own enum comment already documents: `LaunchFailed
            // /* OS refused | bad_alloc */`. Not exercised by a live test
            // (there is no portable, non-global way to force this specific
            // allocation to fail) - GuardianIoExecutor::run wraps its own
            // spawn_detached call the same way (guardian_io_executor.hpp,
            // one try/catch(...) spanning its whole admission block,
            // confirmed by reading it directly) and has no dedicated test
            // forcing that specific allocation to fail either.
            launched = false;
        }
        if (!launched) {
            // spawn_detached returned false, or threw, ONLY if the OS never
            // created the thread at all - the closure above never ran, so
            // `raw` was never reclaimed by anyone; `payload` (still ours,
            // untouched) is the sole owner. Recover fn, then let `payload`
            // destruct normally below (guard rolls the admission back via
            // its own destructor, single-threaded, no race possible here
            // since no worker thread ever existed).
            state_->launch_failed_total.fetch_add(1, std::memory_order_relaxed);
            Result r;
            r.status = DetachedLaunch::LaunchFailed;
            r.fn.emplace(std::move(payload->fn));
            return r;
        }

        // Success: RELEASE (not reset/delete) - the closure spawn_detached
        // just launched has already reclaimed (or will reclaim, or already
        // has fully finished with) sole ownership via its own unique_ptr;
        // release() only forgets the pointer here, it never dereferences or
        // deletes it, so this is safe regardless of how far the worker has
        // already gotten.
        payload.release();
        Result r;
        r.status = DetachedLaunch::Launched;
        r.call.emplace(std::move(cell));
        return r;
    }

    /// This LANE's own outstanding-worker count (mirrors the shared F3
    /// counter's contribution from this lane specifically). Lock-free.
    [[nodiscard]] std::size_t active_workers() const noexcept {
        return state_->active.load(std::memory_order_acquire);
    }
    [[nodiscard]] std::uint64_t rejected_total() const noexcept {
        return state_->rejected_total.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t launch_failed_total() const noexcept {
        return state_->launch_failed_total.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t worker_threw_total() const noexcept {
        return state_->worker_threw_total.load(std::memory_order_relaxed);
    }

    /// Test seam: change the admission cap live. A cap of 0 always rejects
    /// - a deliberate, well-defined configuration (the cap-rejection
    /// regression test uses it to force Rejected deterministically, without
    /// needing a real concurrent saturating worker), not clamped up to 1.
    void set_cap_for_test(std::size_t cap) noexcept {
        state_->cap.store(cap, std::memory_order_relaxed);
    }
    /// Test seam: force the next launch() to fail immediately after
    /// admission, before touching Fn or spawning anything real. Sticky
    /// until reset (matches GuardianIoExecutor::set_fail_launch_for_test's
    /// convention) - a test that sets this must reset it before any later
    /// launch() on this lane that is expected to succeed.
    void set_fail_launch_for_test(bool v) noexcept {
        state_->fail_launch_for_test.store(v, std::memory_order_relaxed);
    }
    /// Test seam: see LaneState::fail_result_alloc_for_test's doc comment.
    /// Sticky until reset, same convention as set_fail_launch_for_test.
    void set_fail_result_alloc_for_test(bool v) noexcept {
        state_->fail_result_alloc_for_test.store(v, std::memory_order_relaxed);
    }
    /// Test seam: see LaneState::fail_first_box_alloc_for_test's doc
    /// comment. Sticky until reset, same convention as the other two.
    void set_fail_first_box_alloc_for_test(bool v) noexcept {
        state_->fail_first_box_alloc_for_test.store(v, std::memory_order_relaxed);
    }

private:
    std::shared_ptr<detached_detail::LaneState> state_;
};

/// Mirrors GuardianSparkRuntimeConfig::backend_op_deadline's default
/// (agents/core/src/guardian_spark_runtime.hpp:198 - GuardianEngine's own
/// wall-clock bound on one backend arm/disarm call). Copied here as a VALUE,
/// not read from that struct: backend_op_deadline is a runtime-configurable
/// std::chrono::milliseconds MEMBER, not a compile-time constant, so a
/// static_assert cannot reach across that header boundary - and this file
/// must not start depending on guardian_spark_runtime.hpp (Spark's
/// mechanism layer and Guardian's runtime layer are deliberately separate;
/// see this file's own top comment). If guardian_spark_runtime.hpp's
/// default ever changes, this mirror needs a matching update by hand - it
/// is a documentation tripwire, not a functional coupling.
inline constexpr std::chrono::milliseconds kGuardianBackendOpDeadlineMirror{5000};

/// Compile-time tripwire pattern for a per-mechanism deadline constant D.
/// PR-A does not define any real D value itself - those come from the
/// PR-A latency harness's measured output (docs/spark-rebuild-baselines/
/// stage2-watch-establish-latency.md), consumed by PR-B. PR-B's
/// Registry/Service/File deadline constants should each carry, at the
/// point they are defined:
///   static_assert(spark_deadline_below_guardian_backend_op(kSomeD), "...");
[[nodiscard]] constexpr bool
spark_deadline_below_guardian_backend_op(std::chrono::milliseconds d) noexcept {
    return d.count() > 0 && d < kGuardianBackendOpDeadlineMirror;
}

/// Overload matching the plan's ceiling note ("per-type queue-depth × D
/// must stay inside Guardian's 5000ms") - e.g. PR-B's Registry re-arm path
/// bounds "≤ 4 stalled re-arms park the private pool for D", so the
/// relevant check there is queue_depth * D, not D alone.
[[nodiscard]] constexpr bool
spark_deadline_below_guardian_backend_op(std::chrono::milliseconds d,
                                         std::size_t queue_depth) noexcept {
    return queue_depth > 0 && d.count() > 0 &&
          (d * static_cast<std::chrono::milliseconds::rep>(queue_depth)) <
              kGuardianBackendOpDeadlineMirror;
}

} // namespace yuzu::agent
