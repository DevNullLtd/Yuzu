#pragma once

/**
 * guardian_outbox_send_executor.hpp - a bounded, single-flight, detached sink
 * for GuardianOutboxDrainWorker's send() call (ADR-0021 Stage 2, #2233 item 4).
 *
 * WHY: GuardianOutboxDrainWorker's own thread also runs journal maintenance
 * (prune/page, guardian_outbox_drain_worker.hpp) and is the sole reader of the
 * outbox/lifecycle logs. Calling `send()` synchronously on that thread means a
 * stalled sink (a gRPC Write() that blocks on a half-open TCP connection - the
 * agent's channel keepalive bounds detection to ~80s, not the seconds this
 * worker's own kGuardianDrainMaxWall implies) wedges maintenance and every
 * later drain for the stall's duration. #3847's acceptance bar is explicit:
 * "the drain worker's next tick proceeds while a prior send is artificially
 * stalled" - dropping drain_mu_ around send() does not achieve that (one
 * production caller; the worker thread is still inside Write() either way).
 * This decouples the caller from the blocking call, mirroring
 * guardian_io_executor.hpp's detached-worker shape (reusing its
 * io_detail::spawn_detached, not its run() - run() DISCARDS a late result on
 * timeout, which is correct for an idempotent read and wrong for a send: a
 * discarded Sent means the entry is dropped without ever being retried).
 *
 * NOT a fix for `stream_write_mu_` contention (agent.cpp): a detached send
 * still holds that mutex for the stall's duration, so another sender sharing
 * the same stream (a response, a DEX signal) still blocks on IT, regardless of
 * which thread is inside Write(). This class only frees the DRAIN WORKER's own
 * thread - maintenance and the next-tick cadence - from that stall. The send
 * path is unreachable in production today (prefer_spark_ is false at rung
 * 7.7a; see guardian_engine.cpp wire_spark_engine()), so this is pre-flip
 * hardening, not a live-traffic fix.
 *
 * SINGLE-FLIGHT BY CONSTRUCTION: exactly one send may be in flight at a time
 * (the underlying gRPC stream requires serialized Write() calls; concurrent
 * sends would also reorder delivery). offer() enforces this itself - it never
 * spawns a second worker while one is running. When the caller offers a
 * DIFFERENT entry than the one in flight (by `event_id`, the wire idempotency
 * key already fixed at enqueue - guardian_outbox.hpp - a generation-supersede
 * purge or a withdrawal moved the log's head while the old head's send was
 * still running), offer() does NOT touch that orphaned worker - no second
 * concurrent Write() on the same stream - but it MUST eventually reclaim the
 * slot once the orphan finishes, discarding its now-unattributable result, or
 * every later offer() call would find in_flight permanently true against an
 * event_id that can never recur and never launch again (found in governance
 * review of this file's first draft, independently by two reviewers; direct
 * regression coverage: tests/unit/test_guardian_outbox_send_executor.cpp).
 *
 * ORPHAN-EXIT CONTRACT: reuses the exact hazard guardian_io_executor.hpp
 * documents - a worker wedged in a blocking syscall cannot be joined or
 * force-cancelled, so normal C++ teardown must not run while one is alive.
 * active_worker_count() MUST be summed into GuardianEngine::active_io_workers()
 * (guardian_engine.cpp) alongside the state-reader and arm/disarm executors -
 * a source left out of that sum lets a detached send survive teardown
 * undetected (the same comment guards that call site).
 */

#include "guardian_io_executor.hpp" // io_detail::spawn_detached
#include "guardian_outbox.hpp"      // OutboxEntry, SendResult

#include <yuzu/log_token.hpp> // log_id_token
#include <yuzu/plugin.h>      // YUZU_EXPORT

#include <spdlog/spdlog.h> // #3953 items 1+2 - firewalled stall/orphan-exception logging

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace yuzu::agent {

// #4223: the worker-to-caller exception hand-off (see offer()'s worker lambda below)
// uses std::exchange, NOT std::move, to empty the worker's local `eptr` after handing
// its value to `state_->eptr` - this is NOT stylistic. A `static_assert(is_nothrow_
// move_assignable_v<exception_ptr>)` was tried here first (governance Gate 3
// cpp-expert) and PASSES on every target toolchain, but that trait is satisfied by a
// NOEXCEPT COPY-ASSIGNMENT accepting an rvalue by const& - it cannot distinguish a
// real move from a copy that happens to bind - so it caught nothing. Verified against
// actual toolchain sources, not assumed: libstdc++ (GCC 13+, this repo's only locally
// buildable toolchain) has always had a real move ctor/assign that nulls the source.
// libc++ (Clang 18+, Apple Clang 15+) does NOT: checked the exception_ptr.h shipped in
// llvmorg-18.1.0 through llvmorg-21.1.0 and release/21.x directly - none declare a
// move ctor or move-assignment operator, only copy. A move ctor/assign was added to
// libc++ upstream on 2025-11-03 (llvm/llvm-project@f02b661054, "Add move constructor &
// assignment to exception_ptr") but has not reached ANY numbered LLVM release as of
// this writing - so `std::move(eptr)` on Clang/Apple Clang/libc++ TODAY silently binds
// the copy-assignment operator: `st->eptr` gets a valid new reference, but the
// worker's own `eptr` is NOT emptied, and the #4223 race this file exists to fix is
// NOT closed on that platform. (Governance Gate 3 cpp-expert's original claim that all
// four target toolchains have "shipped real move ctor/assignment for exception_ptr for
// well over a decade" was wrong for libc++ - caught at Gate 8 re-review, verified
// against primary source rather than trusted.) std::exchange(eptr, nullptr) sidesteps
// this entirely: its `eptr = nullptr;` step is an assignment-from-nullptr, which
// exception_ptr supports unconditionally on every toolchain regardless of move
// support - so the worker's local is guaranteed empty here no matter which assignment
// operator got selected above it. MSVC STL was not locally checkable; treated as
// `likely` correct (matches the class of stdlib that has long supported this), not
// `verified` - but no longer load-bearing, since std::exchange doesn't depend on it.

class YUZU_EXPORT GuardianOutboxSendExecutor {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    /// Test-only fault injection for launch()'s admission path (#3966 fold-in - no
    /// regression coverage existed for either failure mode). `SpawnRefused` mirrors
    /// `io_detail::spawn_detached` returning false (the OS refused to create the
    /// thread); `Throw` mirrors a `std::bad_alloc` from anywhere in launch()'s guarded
    /// region, AFTER the ticket is armed and the worker lambda is built (the ARMED
    /// rollback path); `ThrowBeforeCommit` mirrors the same failure at the EARLIEST
    /// point in the guarded region - before any State mutation, before the ticket is
    /// armed (the UNARMED rollback path). All three take the SAME outer rollback (see
    /// launch()).
    enum class LaunchFaultForTest { None, SpawnRefused, Throw, ThrowBeforeCommit };

    /// #3953 item 2: a send still in flight this long (measured from admission to
    /// completion, or to "still running" if not yet complete) is counted and logged
    /// once as a stall - matches the production periodic backstop, so this fires only
    /// once a send has already missed every ordinary re-check. Tests pass a short
    /// threshold to exercise the path without a real multi-second wait.
    static constexpr std::chrono::milliseconds kGuardianSendStallThreshold{5'000};

    explicit GuardianOutboxSendExecutor(
        std::chrono::milliseconds stall_threshold = kGuardianSendStallThreshold)
        : state_(std::make_shared<State>()), stall_threshold_(stall_threshold) {}
    GuardianOutboxSendExecutor(const GuardianOutboxSendExecutor&) = delete;
    GuardianOutboxSendExecutor& operator=(const GuardianOutboxSendExecutor&) = delete;

    /// Called once per drain attempt for the current head entry. `send` is invoked
    /// on a DETACHED worker, never on the caller's thread. Returns the completed
    /// result if a send finished within `wait` (the common case on a healthy
    /// connection), or std::nullopt if none is available yet - the caller MUST
    /// treat that as SendResult::Retain and stop draining this pass (matches the
    /// existing "Retain stops the drain" contract - see guardian_outbox.hpp), then
    /// offer the SAME head entry again on its next tick. Never blocks longer than
    /// `wait`, regardless of how long the underlying send actually takes.
    ///
    /// RE-THROWS on this call if the completed send itself threw: drain_log_unlocked
    /// (guardian_spark_runtime.cpp) has its own catch around `send(entry)` that counts
    /// send_exceptions_ and retains the head - swallowing the throw here instead (e.g.
    /// mapping it to Retain) would silently lose that counter, which is how a
    /// permanently-unsendable entry is distinguished from an ordinary down stream.
    std::optional<SendResult> offer(const OutboxEntry& entry, const SendFn& send,
                                    std::chrono::milliseconds wait) {
        // offer() has exactly one caller thread (the drain worker's own loop), so
        // there is no concurrent-submitter race to guard against here - only
        // against the detached worker thread, which the lock below still covers.
        // The launch-decision read and the launch() call itself are deliberately
        // NOT done under one held lock: launch() itself re-locks state_->mu for its
        // own bookkeeping (see below), and that mutex is not recursive.
        bool need_launch = false;
        bool mismatch_still_running = false;
        bool stopping_retain = false;
        bool log_mismatch_stall = false;   ///< item 2: A itself just crossed the threshold
        bool log_orphan_exception = false; ///< item 1: A's reclaimed result was a throw (first occurrence)
        bool log_orphan_recovery = false;  ///< item 2: A had stalled earlier and just resolved
        // The orphan's OWN event_id, captured under the lock before it can be
        // overwritten by a later launch() - the mismatch-stall and orphan-recovery
        // logs below are about the OLD (orphaned) entry, never about `entry` (the
        // NEWLY offered one), so they must not use entry.event_id.
        std::string orphan_event_id;
        {
            // Every branch below sets a FLAG rather than `return`ing directly, so the
            // lock is always released the ordinary way (this block's closing brace)
            // before any post-lock logging or return - an orphan reclaimed in the SAME
            // call that also observes `stopping` must still get its diagnostic logged
            // (#3953 items 1+2), which an early return from inside the lock would skip.
            std::lock_guard<std::mutex> lk{state_->mu};
            if (state_->in_flight && state_->in_flight_event_id != entry.event_id) {
                orphan_event_id = state_->in_flight_event_id;
                // The head entry changed under us (generation-supersede purge or a
                // withdrawal - both ORDINARY operations, not a rare race) while a
                // send for the OLD head was still running. That worker is orphaned
                // (still holds stream_write_mu_ until it finishes).
                if (!state_->done) {
                    // Still genuinely running. Cannot touch it and must not submit a
                    // second concurrent Write() on the same stream - try again next
                    // tick. Once it finishes, the branch below reclaims the slot; NOT
                    // reclaiming here unconditionally (an earlier version of this
                    // function never reclaimed at all) would otherwise wedge every
                    // future send permanently, since `event_id` never repeats.
                    //
                    // #3953 item 2: this is exactly the case a mismatched orphan can be
                    // stalled indefinitely without ever being observed by the timeout
                    // path below (that path only runs for the SAME entry) - checked
                    // here too, under the same lock, so an orphan stuck this long is
                    // still counted even though nothing ever waits on it directly.
                    log_mismatch_stall = check_stall_locked();
                    mismatch_still_running = true;
                } else {
                    // The stale worker already finished. Its result (Sent/Retain, or a
                    // thrown exception now sitting in eptr) applies to an entry that no
                    // longer exists in the log - there is nothing correct to do with it
                    // except discard it; reporting it against THIS entry would
                    // misattribute a success/failure that never happened to it. Reclaim
                    // the slot and fall through to launch a fresh worker below.
                    //
                    // #3953 item 1: the discard itself is still correct (nothing else
                    // to do with an orphan's result), but a THROWN result is real
                    // evidence of a problem and is worth a diagnostic signal - count it
                    // (first occurrence only logs; see the firewalled pattern this
                    // mirrors in guardian_outbox_drain_worker.cpp).
                    if (state_->eptr) {
                        ++state_->orphan_exceptions_discarded;
                        log_orphan_exception = (state_->orphan_exceptions_discarded == 1);
                    }
                    // #3953 item 2 follow-up: check_stall_locked() FIRST, before reading
                    // stall_logged - an orphan that crosses stall_threshold_ only in its
                    // final stretch (never observed "still running" past threshold by
                    // the branch above) would otherwise reach here with stall_logged
                    // still false, silently undercounting a real stall (governance Gate
                    // 6 sre finding). done==true here, so this correctly uses
                    // completed_at, not now(). Recovery then logs whenever THIS orphan
                    // had stalled - whether just detected here or on an earlier "still
                    // running" poll - it never reaches the normal consumption path below.
                    check_stall_locked();
                    log_orphan_recovery = state_->stall_logged;
                    state_->in_flight = false;
                    state_->done = false;
                    state_->eptr = nullptr;
                }
            }
            if (!mismatch_still_running) {
                if (!state_->in_flight) {
                    if (state_->stopping)
                        stopping_retain = true; // do not spawn new work once stopping
                    else
                        need_launch = true;
                }
                // else: in_flight for THIS SAME entry - fall through to the wait below.
            }
        }
        // Lock released above (the block's closing brace) - every path funnels
        // through here now, logging is done with no lock held.
        if (log_orphan_exception)
            log_orphan_exception_discarded();
        if (log_orphan_recovery)
            log_send_recovery(orphan_event_id);
        if (mismatch_still_running) {
            if (log_mismatch_stall)
                log_send_stall(orphan_event_id);
            return SendResult::Retain;
        }
        if (stopping_retain)
            return SendResult::Retain; // do not spawn new work once stopping
        if (need_launch) {
            // Test seam: fires in the real race window between offer()'s decision
            // (need_launch=true, state_->mu already released above) and the launch()
            // call below - the exact gap a concurrent stop() can land in. Deterministic
            // regression coverage for that race (the adversarial-review pass's C1/F3
            // finding, #3847 item 4 hardening) sets this to call stop() synchronously,
            // on this same thread, right here, then asserts launch() below observes it
            // and bails - the hook is what makes the interleave deterministic via call
            // ordering, so it does not need (or use) a second real thread.
            if (pre_launch_race_hook_for_test_)
                pre_launch_race_hook_for_test_();
            if (!launch(entry, send))
                // launch failed - thread exhaustion (retried next tick), or stop() won
                // the race (no next tick follows; the entry stays durable in the log
                // for replay on the next boot, same as any other Retain at shutdown).
                return SendResult::Retain;
        }

        std::unique_lock<std::mutex> lk{state_->mu};
        const auto deadline = std::chrono::steady_clock::now() + wait;
        // Deliberately does NOT also wake on `stopping`, unlike guardian_io_executor.hpp's
        // run(): an earlier draft did, so a parked offer() call would wake as soon as
        // stop() fired instead of riding out the rest of `wait` (governance Gate 4
        // consistency-auditor SHOULD finding - up to kGuardianSendOfferWait of avoidable
        // shutdown latency). That made GuardianOutboxDrainWorker::stop() fast enough to
        // race ahead of test_guardian_engine_spark_reconcile.cpp's PRE-EXISTING "pending
        // records are durable BEFORE stop() joins the drain worker" test, which polls for
        // a still-joining window from a separate thread - that window is what got raced
        // away. The underlying property that test guards (persist runs before the join
        // starts, unconditionally, in GuardianEngine::stop()'s source order) is untouched
        // either way; only the OBSERVABLE join duration would have shrunk. Reverted rather
        // than redesign that test's synchronization under this PR's own time budget - the
        // SHOULD finding's cost (a bounded, already-small per-shutdown latency) is smaller
        // than the risk of touching a load-bearing pre-existing shutdown-ordering test's
        // timing assumptions. Left here as a note for whoever revisits this trade-off.
        state_->cv.wait_until(lk, deadline, [&] { return state_->done; });
        // #3953 item 2: evaluated UNCONDITIONALLY here, before checking `done` below -
        // not gated on the timeout, so a send that crosses stall_threshold_ but still
        // finishes DURING this same bounded wait is still counted (Fable's review: the
        // original design gated this on `!state_->done`, which missed exactly that
        // case). check_stall_locked() itself picks completed_at vs now() correctly for
        // either outcome.
        const bool log_new_stall = check_stall_locked();
        if (!state_->done) {
            lk.unlock();
            if (log_new_stall)
                log_send_stall(entry.event_id);
            return std::nullopt; // still running; caller retains and comes back
        }
        auto result = state_->result;
        auto eptr = std::move(state_->eptr);
        // A recovery log fires whenever THIS entry had stalled - whether the crossing
        // was just detected above (log_new_stall) or on an earlier call (the same-entry
        // timeout path) - exactly once, since the next launch() resets stall_logged for
        // whatever entry takes this slot next.
        const bool log_recovery = state_->stall_logged;
        state_->in_flight = false;
        state_->done = false;
        state_->eptr = nullptr;
        lk.unlock();
        if (log_new_stall)
            log_send_stall(entry.event_id);
        if (log_recovery)
            log_send_recovery(entry.event_id);
        if (eptr)
            std::rethrow_exception(eptr); // never rethrow while holding a lock a catch handler cannot see
        return result;
    }

    /// Idempotent. Marks the executor stopping so no NEW send is launched; does
    /// NOT cancel a send already in flight (matches guardian_io_executor.hpp - a
    /// thread wedged in a blocking syscall cannot be force-cancelled). Never
    /// blocks: a caller wanting to know when the last worker is truly gone polls
    /// active_worker_count(), the same orphan-exit contract as the state reader.
    /// Does NOT wake a caller currently parked in offer()'s wait_until - see the
    /// comment on offer()'s wait_until call for why that was tried and reverted.
    void stop() {
        std::lock_guard<std::mutex> lk{state_->mu};
        state_->stopping = true;
    }

    // NOT PROVIDED: a callback fired after every completed send (#3953 item 3, revised).
    // Built and wired once (a WakeFn stored in State, called right after this class's
    // own state_->cv.notify_all() in launch()'s worker lambda) - but it made every
    // completed send bump the drain worker's sig_->gen and wake loop() immediately,
    // which broke "R4: a refill re-arm does not wait out the periodic bound"
    // (test_guardian_outbox_drain_worker.cpp): that test's whole point is proving the
    // loop re-arms a forced page from its OWN internal logic with NO external wake, and
    // an unrelated wake source let it pass for the wrong reason. Fixed instead with
    // has_in_flight_send() (below) plus a WAIT clamp on the drain worker's own side
    // (guardian_outbox_drain_worker.cpp's loop()) - the drain worker polls it after
    // every pass and shortens its OWN wait while anything is in flight, rather than this
    // class waking the drain worker itself. Closes the same cadence cliff (a send
    // finishing between offer()'s bounded wait and the drain worker's periodic bound
    // used to wait out the whole bound before being noticed) without adding a wake
    // source, so R4 is untouched.

    /// For GuardianEngine::active_io_workers() (the orphan-exit contract's sole
    /// source of truth) - normally 0 or 1 (this executor is single-flight in the
    /// sense that at most one send is ever ADMITTED), but can transiently read 2:
    /// offer() reclaiming a finished-but-orphaned worker (a stale event_id whose
    /// AliveTicket has not yet reached its thread-exit decrement) can launch a new
    /// one before the old ticket's count-1 has run. Harmless for the orphan-exit
    /// contract itself, which only distinguishes zero from nonzero.
    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->worker_count);
    }

    /// True whenever ANY send is admitted and not yet consumed - the same-entry
    /// timeout case AND the mismatched-orphan-still-running case both set
    /// in_flight, so this reads true in either (#3953 item 3: the caller cannot
    /// tell them apart from offer()'s return value alone, since wrapped_send()'s
    /// `.value_or(SendResult::Retain)` collapses both to the same value). Used by
    /// the drain worker's loop() to re-check sooner than the full periodic bound
    /// while something is genuinely in flight on this lane.
    [[nodiscard]] bool has_in_flight_send() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->in_flight;
    }

    /// #3953 item 1: an orphan's thrown exception, discarded because it belongs to a
    /// superseded entry with nowhere correct to attribute it - see the reclaim branch
    /// in offer(). Diagnostic-signal only; the discard itself is correct behavior.
    [[nodiscard]] std::uint64_t orphan_exception_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->orphan_exceptions_discarded;
    }

    /// #3953 item 2: cumulative count of sends (same-entry or mismatched-orphan) that
    /// crossed kGuardianSendStallThreshold before completing or being reclaimed.
    [[nodiscard]] std::uint64_t send_stall_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->stalls;
    }

    /// Test-only synchronization seam - see the call site in offer() for what race it
    /// exists to make deterministic. Production callers never set this.
    void set_pre_launch_race_hook_for_test(std::function<void()> hook) {
        pre_launch_race_hook_for_test_ = std::move(hook);
    }

    /// Test-only synchronization seam - see the call site in launch() for what race it
    /// exists to make deterministic (#3966). Production callers never set this.
    void set_post_admission_race_hook_for_test(std::function<void()> hook) {
        post_admission_race_hook_for_test_ = std::move(hook);
    }

    /// Test-only fault injection - see LaunchFaultForTest. Production callers never
    /// set this (defaults to None, a no-op).
    void set_launch_fault_for_test(LaunchFaultForTest fault) {
        launch_fault_for_test_.store(fault, std::memory_order_relaxed);
    }

    /// Test-only synchronization seam (#4223): parks the worker thread right after
    /// notify_all(), before its local `eptr` destructs, until `*gate` reads true - see
    /// the worker lambda's call site. `gate` MUST be polled/stored with
    /// memory_order_relaxed on both sides (never a mutex/condvar/acq_rel atomic): this
    /// seam exists to make the #4223 race's OWN interleaving deterministic, and a
    /// synchronizing handoff would itself supply the happens-before edge the bug is
    /// about the absence of, hiding the exact race it is meant to reproduce. Set to
    /// nullptr (the default) to disable - production callers never set this. `gate`
    /// must outlive every in-flight send while set; call with nullptr before letting it
    /// go out of scope. The pointer FIELD itself (as opposed to what it points to) is
    /// written here with no lock and read unlocked by the worker - safe only because
    /// this is called before any worker for this executor exists (thread creation is
    /// itself a happens-before edge) and reset only after draining to
    /// active_worker_count()==0; never call this concurrently with an in-flight
    /// offer()/launch(). Housed on `State` (governance Gate 4 consistency-auditor
    /// finding), not beside the class-level seams below (`pre_launch_race_hook_for_test_`
    /// etc.), because it is read from the DETACHED WORKER lambda, which captures `st`,
    /// never `this`, per this class's own ORPHAN-EXIT CONTRACT (top-of-file doc
    /// comment) - a class member here would need a `this` capture on that lambda,
    /// exactly what that contract forbids.
    void set_eptr_race_release_gate_for_test(std::atomic<bool>* gate) {
        state_->eptr_race_release_gate_for_test = gate;
    }

private:
    struct State {
        std::mutex mu;
        std::condition_variable cv;
        bool in_flight{false};      ///< a send has been submitted and not yet consumed by offer()
        bool done{false};           ///< the worker published a result
        int worker_count{0};        ///< normally 0 or 1, transiently 2 - see active_worker_count()
        bool stopping{false};
        std::string in_flight_event_id;
        SendResult result{SendResult::Retain};
        std::exception_ptr eptr; ///< set instead of `result` if `send` itself threw
        // #3953 items 1+2 - observability. orphan_exceptions_discarded/stalls are
        // CUMULATIVE for the life of this executor (see the accessor doc comments) -
        // launch()'s locked admission block resets only launched_at/stall_logged
        // below, which apply to the CURRENT in-flight send only (governance Gate 2/3
        // truth finding: an earlier revision of this comment wrongly claimed both
        // counters reset there too).
        std::uint64_t orphan_exceptions_discarded{0}; ///< a reclaimed orphan's throw, discarded (item 1)
        std::uint64_t stalls{0};                      ///< sends that crossed stall_threshold_ (item 2)
        std::chrono::steady_clock::time_point launched_at{};  ///< set by launch(), under the lock
        std::chrono::steady_clock::time_point completed_at{}; ///< set by the worker, under the publish lock
        bool stall_logged{false}; ///< this in-flight send already counted/logged as stalled
        std::atomic<bool>* eptr_race_release_gate_for_test{nullptr}; ///< #4223 test seam; null = no-op (set-then-use)
    };

    /// Called with state_->mu HELD. Returns true iff THIS call is the one that newly
    /// crosses stall_threshold_ (so the caller logs exactly once, outside the lock).
    /// Compares against completed_at once the send is done, `now()` only while it is
    /// still genuinely running (#3953 item 2, Fable's review) - comparing against
    /// `now()` unconditionally would overstate elapsed time for a send that actually
    /// finished earlier but whose caller was scheduled late to notice, which can flake
    /// a short test threshold and conflates "how long did this take" with "how long has
    /// the caller been checking".
    bool check_stall_locked() {
        if (!state_->in_flight || state_->stall_logged)
            return false;
        const auto reference = state_->done ? state_->completed_at : std::chrono::steady_clock::now();
        if (reference - state_->launched_at < stall_threshold_)
            return false;
        ++state_->stalls;
        state_->stall_logged = true;
        return true;
    }

    /// Called with NO lock held. All three logging helpers are firewalled: an
    /// observability failure (e.g. spdlog itself throwing) must never escape offer(),
    /// be miscounted as a send exception, or delay delivery - matches the established
    /// pattern at guardian_outbox_drain_worker.cpp's `firewalled` lambda.
    static void log_send_stall(const std::string& event_id) {
        try {
            spdlog::warn("Guardian outbox send stalled past its threshold (event_id {}); "
                         "drain continues, the send stays running detached.",
                         ::yuzu::log_id_token(event_id));
        } catch (...) {
        }
    }
    static void log_send_recovery(const std::string& event_id) {
        try {
            spdlog::info("Guardian outbox send (event_id {}) completed after having "
                         "stalled past its threshold.",
                         ::yuzu::log_id_token(event_id));
        } catch (...) {
        }
    }
    static void log_orphan_exception_discarded() {
        try {
            spdlog::warn("Guardian outbox send: a reclaimed orphan's result was a thrown "
                         "exception, discarded (it belongs to a superseded entry with "
                         "nowhere correct to attribute it). Further occurrences counted "
                         "only.");
        } catch (...) {
        }
    }

    /// RAII orphan-exit marker, mirroring guardian_io_executor.hpp's TicketCore split
    /// (guardian_io_executor.hpp:474-513): the worker's OWN captured copy is the one
    /// that decrements worker_count, and it is destroyed by the detached-thread
    /// trampoline AFTER the worker lambda body has fully returned (notify_all
    /// included) - the latest point observable before the OS thread itself exits.
    ///
    /// UNARMED BY DEFAULT (#3966): the ctor is lock-free/noexcept, and `arm()` - the
    /// nothrow ++worker_count - is called by launch() as the LAST statement of the
    /// SAME locked block that commits in_flight/done, under the SAME state_->mu stop()
    /// takes to set `stopping`. The prior shape armed via a SECOND, independent
    /// self-locking ctor, called after that locked block had already released the
    /// lock - so a stop() landing in the gap between the two could return with
    /// stopping=true while worker_count still read 0, even though admission was
    /// already committed (the falsified-zero window #3966 reports; falsifier:
    /// tests/unit/test_guardian_outbox_send_executor.cpp). Mirrors
    /// GuardianIoExecutor::run()'s own "armed under the lock" pattern
    /// (guardian_io_executor.hpp:291-317), which this class had deviated from at
    /// exactly this point. A ticket destroyed before/without `arm()` (the rollback /
    /// launch-failed path) is a no-op, since no count was ever incremented for it.
    struct AliveTicket {
        explicit AliveTicket(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~AliveTicket() {
            if (!armed)
                return;
            std::lock_guard<std::mutex> lk{state->mu};
            if (state->worker_count > 0)
                --state->worker_count;
        }
        /// CALLER MUST HOLD state->mu.
        void arm() noexcept {
            ++state->worker_count;
            armed = true;
        }
        AliveTicket(const AliveTicket&) = delete;
        AliveTicket& operator=(const AliveTicket&) = delete;
        std::shared_ptr<State> state;
        bool armed{false};
    };

    /// Called from offer() with state_->mu NOT held. Spawns a detached worker that
    /// calls send(entry) and publishes the result. Returns false for either of two
    /// reasons: the OS refused to create the thread (mirrors
    /// guardian_io_executor.hpp's LaunchFailed path), or a concurrent stop() won the
    /// race against offer()'s decision to call this function (see the re-check just
    /// inside the try block below).
    bool launch(const OutboxEntry& entry, const SendFn& send) {
        // Bookkeeping FIRST, under its own lock, BEFORE the worker is spawned - not
        // after. A fast `send` can complete, lock state_->mu, and publish done=true
        // before this function ever reaches a post-spawn lock acquisition (verified:
        // reproduced ~1-in-1000 with a fast, always-succeeding send in a tight loop).
        // Writing in_flight/in_flight_event_id/done=false only AFTER spawn_detached()
        // returns would then let this write clobber the worker's already-published
        // done=true back to false, and nothing ever sets it true again - the entry
        // wedges permanently, silently, for the life of the process. in_flight/
        // in_flight_event_id/done have exactly one writer (this function, called only
        // from offer(), which has exactly one caller thread), so writing them before
        // the worker can possibly touch `done` is race-free by construction.
        //
        // Everything from here through spawn_detached() can throw std::bad_alloc: the
        // AliveTicket allocation, the in_flight_event_id string copy (governance Gate 8
        // cpp-safety finding - an earlier draft placed this bookkeeping BEFORE the try,
        // so a thrown bad_alloc on the copy itself left in_flight=true uncaught, the
        // same wedge class one statement earlier than the guarded region started),
        // copying `entry`/`send` into the worker lambda's captures, and
        // spawn_detached's own payload allocation (guardian_io_executor.hpp's own
        // doc). ALL of it is inside one try, and any failure - a thrown bad_alloc OR
        // spawn_detached returning false for an OS-level refusal - takes the SAME
        // rollback path below. An uncaught throw here would unwind with in_flight left
        // true and no worker ever created to set done=true, wedging this entry exactly
        // like the ordering bug this function's rewrite fixed (verified in review) -
        // just triggered by allocation failure instead of a timing race. None of these
        // failures are specific to `entry` (they are thread/memory exhaustion, not an
        // unsendable payload), so all are mapped to a plain launch failure - the caller
        // retries next tick - rather than let a bad_alloc escape into
        // drain_log_unlocked's catch and be miscounted as a send_exceptions_ hit.
        bool launched = false;
        try {
            // Constructed UNARMED, before any lock (its ctor is lock-free/noexcept -
            // #3966) - a shared_ptr so a launch failure's synchronous destruction and a
            // launched worker's eventual thread-exit destruction both go through the
            // same self-locking decrement path.
            auto ticket = std::make_shared<AliveTicket>(state_);
            {
                std::lock_guard<std::mutex> lk{state_->mu};
                // Re-check stopping here, under the SAME lock stop() sets it under and
                // offer() already read it under (above, before releasing state_->mu to
                // call this function) - offer()'s own check has a gap between deciding
                // need_launch and reaching this point, during which a concurrent stop()
                // can run (adversarial review finding, #3847 item 4 hardening: no
                // internal governance round caught this, both external reviewers did,
                // independently). This return precedes every State mutation below -
                // in_flight is still false, the ticket is still unarmed - so it reaches
                // neither the catch(...) block (nothing thrown) nor the post-try
                // `if (!launched)` rollback further down (nothing was set that needs
                // unsetting); it is exactly as if offer() had seen stopping=true itself,
                // one step earlier.
                if (state_->stopping)
                    return false;
                // Fault injection (#3966 fold-in, governance Gate 5 chaos CH-1):
                // exercises the EARLIEST point in this locked block that could throw -
                // before ANY State mutation, before the ticket is armed - the UNARMED
                // rollback path. Distinct from LaunchFaultForTest::Throw below, which
                // fires after both. Rollback here is trivial by construction (nothing
                // was set, the ticket's destructor is a no-op), but nothing previously
                // exercised this exact point directly.
                if (launch_fault_for_test_.load(std::memory_order_relaxed) ==
                    LaunchFaultForTest::ThrowBeforeCommit)
                    throw std::bad_alloc{};
                state_->in_flight_event_id = entry.event_id; // the ONE throwing step,
                                                              // FIRST - strong guarantee,
                                                              // in_flight still false
                state_->in_flight = true;
                state_->done = false;
                // #3953 items 1+2: reset for the NEW entry this admission is for -
                // launched_at/stall_logged apply to whichever entry currently holds
                // the slot.
                state_->launched_at = std::chrono::steady_clock::now();
                state_->stall_logged = false;
                // Armed LAST, in this SAME locked block (#3966) - see AliveTicket::arm().
                ticket->arm();
            }
            // Test seam: fires with NO lock held, after admission is committed AND
            // counted (the SAME locked block above) - production callers never set
            // this.
            if (post_admission_race_hook_for_test_)
                post_admission_race_hook_for_test_();
            auto st = state_;
            auto worker = [st, ticket, entry, send]() mutable noexcept {
                SendResult r = SendResult::Retain;
                std::exception_ptr eptr;
                try {
                    r = send(entry);
                } catch (...) {
                    // Preserve the throw for offer() to re-raise on the CALLER's thread -
                    // drain_log_unlocked's own catch is what counts send_exceptions_ and
                    // distinguishes a permanently-unsendable entry from an ordinary Retain
                    // (guardian_spark_runtime.cpp); swallowing it here would silently lose
                    // that signal. current_exception() is noexcept; the copy into `eptr`
                    // is not documented noexcept by the standard, so it gets its own
                    // firewall - a double-fault here degrades to an ordinary Retain rather
                    // than escaping this noexcept lambda and terminating the agent.
                    try {
                        eptr = std::current_exception();
                    } catch (...) {
                        eptr = nullptr;
                    }
                }
                {
                    std::lock_guard<std::mutex> lk{st->mu};
                    st->result = r;
                    // std::exchange, not a plain copy or std::move (#4223 - see the
                    // file-scope comment above this class for why std::move alone is
                    // NOT sufficient on every target toolchain): a copy (or a move that
                    // silently falls back to copy semantics) leaves this worker holding
                    // its own live reference to the shared exception control block,
                    // destroyed at this lambda's scope exit - OFF this lock, ordered
                    // against nothing. Under starvation the worker can be descheduled
                    // there while offer()'s caller thread moves state_->eptr out,
                    // rethrows, and reads e.what(); when the worker resumes and its
                    // local `eptr` destructs, that can be the reference that brings the
                    // control block's refcount to zero and frees the exception object -
                    // racing the caller's already-finished read with no happens-before
                    // edge either thread's code establishes. std::exchange(eptr,
                    // nullptr) unconditionally empties this worker's `eptr` (its
                    // destructor becomes a no-op) regardless of which assignment
                    // operator the stdlib selects for the returned old value, so the
                    // sole reference travels lock -> state_->eptr -> the caller's local
                    // under offer()'s own lock - the caller is left the sole owner, and
                    // every subsequent destruction runs on its thread.
                    st->eptr = std::exchange(eptr, nullptr);
                    st->completed_at = std::chrono::steady_clock::now(); // #3953 item 2
                    st->done = true;
                }
                st->cv.notify_all();
                // #4223 test-only seam: reads with memory_order_relaxed only - see
                // set_eptr_race_release_gate_for_test()'s doc comment for why a
                // synchronizing wait here would hide the exact race this exists to
                // reproduce. `nullptr` in production, so this is a single relaxed load
                // per completed send and nothing else.
                if (auto* gate = st->eptr_race_release_gate_for_test) {
                    while (!gate->load(std::memory_order_relaxed))
                        std::this_thread::yield();
                }
                // `ticket` destructs at lambda-scope exit, after notify_all - the last
                // observable point before this OS thread actually exits. Its dtor
                // self-locks, so this runs safely with no lock held on this thread. Same
                // for `eptr` (#4223): std::exchange'd to nullptr above, so its destructor
                // here is a no-op regardless of scheduling OR which assignment operator
                // the stdlib actually selected - this worker no longer owns a reference
                // to race the caller with.
            };
            // Fault injection (#3966 fold-in): SpawnRefused mirrors an OS-level
            // thread-creation refusal without depending on real resource exhaustion;
            // Throw mirrors a bad_alloc anywhere in this guarded region - both take the
            // SAME rollback path below via the surrounding try/catch and `if
            // (!launched)`. Production always takes the plain spawn_detached() branch
            // (LaunchFaultForTest::None).
            const auto fault = launch_fault_for_test_.load(std::memory_order_relaxed);
            if (fault == LaunchFaultForTest::Throw)
                throw std::bad_alloc{};
            launched = (fault == LaunchFaultForTest::SpawnRefused)
                           ? false
                           : io_detail::spawn_detached(std::move(worker));
        } catch (...) {
            launched = false;
        }
        if (!launched) {
            // Any partially-constructed ticket's local copy has already dropped by now
            // (try/catch unwound it, or the false-return path never released it) ->
            // worker_count is back to 0 either way (the ticket was never armed, or its
            // armed destructor already ran and decremented).
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->in_flight = false;
            return false;
        }
        return true;
    }

    std::shared_ptr<State> state_;
    std::chrono::milliseconds stall_threshold_;
    std::function<void()> pre_launch_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::function<void()> post_admission_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::atomic<LaunchFaultForTest> launch_fault_for_test_{LaunchFaultForTest::None}; ///< test seam
};

} // namespace yuzu::agent
