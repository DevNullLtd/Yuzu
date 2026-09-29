// test_spark_detached_call.cpp - SparkDetachedLane/DetachedCall<T>
// (agents/core/src/spark_detached_call.hpp), the PR-A shared primitive
// (#2012/#3840 plan, "Shared primitive" section). Cross-platform: this file
// exercises the primitive alone, not any Windows mechanism (those are PR-B).
//
// Each case is a caught-it test for one plan-required invariant: the
// ownership fix (Fn returned unconsumed on Rejected/LaunchFailed - the
// defect an earlier "launch_forget" design had), exactly-once delivery,
// the tightened F3-timing property (the lane/F3 counter stays nonzero
// until the WORKER's own disposal work fully completes, not merely until
// it decides not to publish), no-UAF on early handle destruction, and the
// Guardian-backend_op_deadline compile-time tripwire pattern.
//
// This file is also this primitive's TSan checkpoint (shared mutable state
// across threads) - full [spark] tag, zero races. An ASan+UBSan run was
// also attempted (governance finding, PR-A round 2 - correcting an earlier
// overclaim here) but is blocked on this box by a pre-existing, unrelated
// protobuf/abseil static-initialization false-positive that reproduces for
// ANY test in this binary (confirmed via an unrelated tag) - not a claim
// this file's own code is unverified under ASan, just that ASan could not
// be run here at all.

#include "spark_detached_call.hpp"

#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::Config, for the deadline-mirror pinning test
#include "test_helpers.hpp"           // yuzu::test::spin_until

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace yuzu::agent;
using namespace std::chrono_literals;
using yuzu::test::spin_until;

namespace {

// A worker gate: a launched fn blocks on wait() until the test releases it,
// so a test can hold a call "parked" (in flight) and observe admission/
// count state deterministically. Mirrors test_guardian_io_executor.cpp's
// own Gate exactly (that file's own header comment: this is also this
// primitive's TSan checkpoint).
struct Gate {
    std::mutex m;
    std::condition_variable cv;
    bool go{false};
    void wait() {
        std::unique_lock<std::mutex> lk{m};
        cv.wait(lk, [&] { return go; });
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk{m};
            go = true;
        }
        cv.notify_all();
    }
};

// A move-only result type whose destructor records WHEN it started (an
// atomic<bool> flag) and ON WHICH THREAD, then sleeps `hold_for` before
// returning. Used to make the "disposal, not publication, is what the F3
// counter waits for" property directly observable: a poller on another
// thread can watch the flag flip and then confirm the lane/F3 counter stays
// nonzero for the FULL duration of the destructor's own run, not just up to
// the moment the worker decided whether to publish or self-dispose.
struct SlowDtor {
    std::atomic<bool>* started{nullptr};
    std::atomic<std::thread::id>* thread_id{nullptr};
    std::chrono::milliseconds hold_for{0};
    int value{0};

    SlowDtor() = default;
    SlowDtor(std::atomic<bool>* s, std::atomic<std::thread::id>* tid,
             std::chrono::milliseconds hold, int v)
        : started(s), thread_id(tid), hold_for(hold), value(v) {}
    SlowDtor(const SlowDtor&) = delete;
    SlowDtor& operator=(const SlowDtor&) = delete;
    SlowDtor(SlowDtor&& o) noexcept
        : started(o.started), thread_id(o.thread_id), hold_for(o.hold_for), value(o.value) {
        o.started = nullptr; // moved-from: its destructor becomes a no-op
        o.thread_id = nullptr;
    }
    SlowDtor& operator=(SlowDtor&& o) noexcept {
        if (this != &o) {
            started = o.started;
            thread_id = o.thread_id;
            hold_for = o.hold_for;
            value = o.value;
            o.started = nullptr;
            o.thread_id = nullptr;
        }
        return *this;
    }
    ~SlowDtor() {
        if (!started)
            return; // moved-from - nothing to record, nothing to hold
        started->store(true, std::memory_order_relaxed);
        if (thread_id)
            thread_id->store(std::this_thread::get_id(), std::memory_order_relaxed);
        if (hold_for.count() > 0)
            std::this_thread::sleep_for(hold_for);
    }
};

// A move-only result type whose MOVED-FROM remnant ALSO performs slow,
// observable destructor work - unlike SlowDtor above, which nulls itself on
// move so its moved-from copy's destructor is an inert no-op (see SlowDtor's
// own comment). Regresses the colleague-review finding on PR #4190:
// take_locked() used to move T out of the box into a named local `out` and
// `return out;` - and because the enclosing function's return type
// (optional<DetachedResult<T>>) differs from `out`'s type, NRVO couldn't
// apply, so `out` itself became a SECOND moved-from remnant, destroyed at
// take_locked()'s own scope exit, still inside the caller's lock_guard on
// cell_->mu. The fix (spark_detached_call.hpp's take_locked()/unbox() split)
// moves only the BOX (a unique_ptr pointer move) under the lock, and defers
// the actual T-move - and the moved-from remnant's destructor - to unbox(),
// which every caller runs strictly AFTER releasing cell_->mu.
//
// This type makes that difference OBSERVABLE: its moved-from destructor
// sleeps for `hold_for`. The regression test below races a second,
// concurrent try/wait_take() against the one that "wins" (takes the real
// value and thus runs this slow destructor inside its own call) - the LOSER
// must see cell_->mu released almost immediately (an uncontended lock,
// already-taken -> nullopt) rather than blocking for the winner's entire
// slow-destructor duration, which is exactly what the pre-fix code would
// have done (mutation-tested: reverting take_locked()/unbox() to the
// pre-fix shape makes this test's loser_elapsed assertion fail).
struct SlowMoveObservableDtor {
    std::chrono::milliseconds hold_for{0};
    bool moved_from{false};

    SlowMoveObservableDtor() = default;
    explicit SlowMoveObservableDtor(std::chrono::milliseconds hold) : hold_for(hold) {}
    SlowMoveObservableDtor(const SlowMoveObservableDtor&) = delete;
    SlowMoveObservableDtor& operator=(const SlowMoveObservableDtor&) = delete;
    SlowMoveObservableDtor(SlowMoveObservableDtor&& o) noexcept : hold_for(o.hold_for) {
        o.moved_from = true; // o (the SOURCE) becomes the probed remnant;
                              // `this` (the destination) is the live value
                              // and stays moved_from == false (its own
                              // default), so ITS eventual teardown is fast
    }
    SlowMoveObservableDtor& operator=(SlowMoveObservableDtor&&) = delete;
    ~SlowMoveObservableDtor() {
        if (!moved_from)
            return; // the live (moved-to) value's teardown isn't probed
        if (hold_for.count() > 0)
            std::this_thread::sleep_for(hold_for);
    }
};

// A move-only, non-invokable-until-called-once marker used to prove a
// closure handed back on Rejected/LaunchFailed is genuinely the SAME,
// never-consumed object - not a fresh default-constructed stand-in and not
// a moved-from husk.
struct Marker {
    int tag{0};
    Marker() = default;
    explicit Marker(int t) : tag(t) {}
    Marker(const Marker&) = delete;
    Marker& operator=(const Marker&) = delete;
    Marker(Marker&&) noexcept = default;
    Marker& operator=(Marker&&) noexcept = default;
};

} // namespace

TEST_CASE("launch: a fast fn returns before the deadline", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { return 42; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    REQUIRE(res.call.has_value());
    CHECK_FALSE(res.fn.has_value());

    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 2s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 42);

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: a gated fn times out on wait_take, then a later take delivers exactly once",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;

    auto res = lane.launch([&gate]() -> int {
        gate.wait();
        return 99;
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    CHECK(lane.active_workers() == 1);
    CHECK(f3->load() == 1);

    auto early = res.call->wait_take(std::chrono::steady_clock::now() + 50ms);
    CHECK_FALSE(early.has_value()); // Timeout - still gated, NOT abandoned

    gate.release();
    auto late = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(late.has_value());
    REQUIRE(late->has_value());
    CHECK(**late == 99);

    // Exactly once - a further take after the late one is empty.
    CHECK_FALSE(res.call->try_take().has_value());

    // The lane/F3 counter reaches 0 once the worker is done - no ordering
    // claim is made here relative to the late take itself (F3 protects a
    // LIVE WORKER THREAD, not an inert parked value already delivered to
    // the owner; see spark_detached_call.hpp's own header comment).
    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: cap rejection returns Fn unconsumed", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/0); // 0: a deliberate, well-defined "never admit" lane

    auto res = lane.launch([m = Marker(11)]() mutable -> int { return m.tag; });
    CHECK(res.status == DetachedLaunch::Rejected);
    CHECK_FALSE(res.call.has_value());
    REQUIRE(res.fn.has_value());

    CHECK(lane.active_workers() == 0);
    CHECK(f3->load() == 0);
    CHECK(lane.rejected_total() == 1);

    // fn is genuinely the original, unconsumed closure - invoking it now
    // returns the original captured value, not a moved-from husk's garbage.
    CHECK((*res.fn)() == 11);
}

TEST_CASE("launch: OS launch failure returns Fn unconsumed", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    lane.set_fail_launch_for_test(true);

    auto res = lane.launch([m = Marker(23)]() mutable -> int { return m.tag; });
    CHECK(res.status == DetachedLaunch::LaunchFailed);
    CHECK_FALSE(res.call.has_value());
    REQUIRE(res.fn.has_value());

    CHECK(lane.active_workers() == 0);
    CHECK(f3->load() == 0);
    CHECK(lane.launch_failed_total() == 1);
    CHECK((*res.fn)() == 23);

    // The lane recovers once the test seam is cleared - a real launch after
    // a simulated failure succeeds normally.
    lane.set_fail_launch_for_test(false);
    auto res2 = lane.launch([]() -> int { return 1; });
    REQUIRE(res2.status == DetachedLaunch::Launched);
    auto v = res2.call->wait_take(std::chrono::steady_clock::now() + 2s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 1);
    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
}

TEST_CASE("launch: a throwing fn maps to WorkerThrew and the process stays alive",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { throw std::runtime_error("boom"); });
    REQUIRE(res.status == DetachedLaunch::Launched);
    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    CHECK_FALSE(v->has_value());
    CHECK(v->error() == DetachedCallError::WorkerThrew);

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
    CHECK(lane.worker_threw_total() == 1);
}

TEST_CASE("launch: a result-alloc failure maps to ResultAllocFailed, not a null deref",
          "[spark][detachedcall]") {
    // Exercises take_locked()'s null-result branch (Cell<T>::result can be
    // null even though `done` is true - Payload::operator()()'s own doc
    // comment: the worker publishes a null box when even the WorkerThrew
    // error box could not be allocated). There is no portable way to force
    // the real allocation to fail, so this uses the dedicated test seam
    // (set_fail_result_alloc_for_test) to reach the same state
    // deterministically. MUTATION-TESTED: with the take_locked() null check
    // temporarily removed, this test actually failed - not a hypothetical -
    // via libstdc++'s debug unique_ptr guard ("Assertion 'get() !=
    // pointer()' failed", SIGABRT), not a silent crash-on-sight; the
    // sibling abandon() test below hit the same assertion first and aborted
    // the whole binary before this case even ran. Restoring the null check
    // returns both to green. Not re-verified under ASan specifically (the
    // libstdc++ assertion already gave a clear, reproducible red).
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    lane.set_fail_result_alloc_for_test(true);

    auto res = lane.launch([]() -> int { return 7; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value()); // done() is still true - the outer optional is engaged
    CHECK_FALSE(v->has_value()); // but the boxed DetachedResult<T> itself is the error
    CHECK(v->error() == DetachedCallError::ResultAllocFailed);

    // Not WorkerThrew here - this seam discards the box AFTER
    // Payload::operator()()'s try/catch already ran (boxed.reset() sits
    // outside it), so it cannot itself distinguish "fn() threw" from
    // "fn() succeeded but boxing failed" - see the next test case for that
    // distinction, which IS load-bearing in production since the fix below.
    CHECK(lane.worker_threw_total() == 0);

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);

    lane.set_fail_result_alloc_for_test(false);
}

TEST_CASE("launch: fn() succeeding but its result's box allocation failing is "
          "ResultAllocFailed, never WorkerThrew",
          "[spark][detachedcall]") {
    // adversarial-review finding (PR-A round 2, both external reviewers
    // independently): an earlier version of operator()() wrapped fn() and
    // its result's make_unique<DetachedResult<T>> allocation in ONE try, so
    // a first-box bad_alloc AFTER a successful fn() call was misclassified
    // as WorkerThrew - the callable didn't throw, only its result's boxing
    // did. Fixed by splitting fn()'s invocation from the box allocation
    // into two nested try blocks (spark_detached_call.hpp's operator()()).
    // MUTATION-TESTED: reverting to the single-try shape turns this red -
    // `error() == WorkerThrew` and `worker_threw_total() == 1` where this
    // test expects ResultAllocFailed and 0.
    auto observed_fn_ran = std::make_shared<std::atomic<bool>>(false);
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    lane.set_fail_first_box_alloc_for_test(true);

    auto res = lane.launch([observed_fn_ran]() -> int {
        observed_fn_ran->store(true, std::memory_order_relaxed); // fn() ran to
                                                                  // completion -
                                                                  // it did NOT throw
        return 7;
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    CHECK(observed_fn_ran->load(std::memory_order_relaxed)); // the callable really did run
    CHECK_FALSE(v->has_value());
    CHECK(v->error() == DetachedCallError::ResultAllocFailed); // NOT WorkerThrew

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
    CHECK(lane.worker_threw_total() == 0); // the fix: fn() succeeding is never conflated
                                           // with its result's box allocation failing

    lane.set_fail_first_box_alloc_for_test(false);
}

TEST_CASE("launch: an abandon()'d, published-but-untaken result-alloc failure is a safe "
          "no-op, not a null deref",
          "[spark][detachedcall]") {
    // Same defect class as above, reached through abandon() rather than
    // wait_take() - both call take_locked() internally, so this mostly
    // re-confirms the same fix from a second call site (the mutation test
    // in the previous commit actually aborted on THIS case first, before
    // the wait_take() one even ran). Also exercises that a subsequent
    // DetachedCall destructor (dispose_or_abandon() again, now with
    // cell_->taken already true from the abandon() above) takes its
    // early-return `if (cell_->taken) return;` branch - a clean no-op,
    // not a second dispose.
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    lane.set_fail_result_alloc_for_test(true);

    auto res = lane.launch([]() -> int { return 9; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    CHECK(spin_until([&] { return res.call->done(); }));

    auto abandoned = res.call->abandon();
    REQUIRE(abandoned.has_value());
    CHECK_FALSE(abandoned->has_value());
    CHECK(abandoned->error() == DetachedCallError::ResultAllocFailed);

    // Handle destruction after an already-taken abandon() must be a no-op.
    res.call.reset();

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);

    lane.set_fail_result_alloc_for_test(false);
}

TEST_CASE("launch: owner handle destroyed while parked - no UAF, disposal happens on the "
          "WORKER thread",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;
    std::atomic<bool> dtor_ran{false};
    std::atomic<std::thread::id> dtor_thread{};

    auto res = lane.launch([&gate, &dtor_ran, &dtor_thread]() -> SlowDtor {
        gate.wait();
        return SlowDtor(&dtor_ran, &dtor_thread, 0ms, 3);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);

    {
        // Destroying the handle WHILE the call is still parked (fn is
        // blocked on the gate) - this is the implicit-abandon path: the
        // worker discovers `abandoned` under cell.mu once it finally
        // completes, and self-disposes the SlowDtor LOCALLY (never
        // publishing it into the cell).
        [[maybe_unused]] auto dropped = std::move(*res.call);
    }
    // `res.call` (the optional) is still engaged but now holds a
    // moved-from, cell_==nullptr handle - deliberately not touched again.

    gate.release();
    REQUIRE(spin_until([&] { return dtor_ran.load(); }, 5s));
    CHECK(dtor_thread.load() != std::this_thread::get_id()); // disposed on the WORKER thread

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: abandon() after publish returns the result exactly once",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { return 55; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    REQUIRE(spin_until([&] { return res.call->done(); }, 5s));

    auto first = res.call->abandon();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK(**first == 55);

    auto second = res.call->abandon();
    CHECK_FALSE(second.has_value());

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("take_locked: the box itself is moved out of the cell (pointer-only) under the "
          "lock - T is never touched there",
          "[spark][detachedcall]") {
    // White-box regression, twice over now. Originally (Gate 8 fix,
    // pre-PR-4190): an earlier version called cell_->result.reset() while
    // still holding cell_->mu, running ~T() on the moved-from remnant UNDER
    // THE LOCK; the fix at the time left cell_->result deliberately engaged
    // (moved-from, non-null) so no reset ran under the lock at all.
    //
    // Colleague review on PR #4190 found a SECOND, subtler way the same
    // contract broke: take_locked() itself moved T out of the box into a
    // named local `out` and `return`ed it - and because the enclosing
    // function's return type didn't match `out`'s type, NRVO couldn't
    // apply, so `out` became a fresh moved-from remnant destroyed at
    // take_locked()'s own scope exit, STILL under the caller's lock_guard.
    // The real fix (this test now pins) is to never touch T under the lock
    // at all: take_locked() moves the BOX ITSELF (the unique_ptr) out of
    // the cell - a pointer move, T untouched - leaving cell_->result null
    // immediately, and the actual T-move (plus the moved-from box's own
    // teardown) happens in unbox(), which every caller runs strictly after
    // releasing cell_->mu. See spark_detached_call.hpp's take_locked()/
    // unbox() comments for the full argument, and the "take_locked()/
    // unbox(): a concurrent second take is not blocked..." test in this
    // file for the threaded proof this doesn't merely LOOK right on one
    // thread.
    //
    // Constructs a Cell<T> directly (DetachedCall's cell-wrapping
    // constructor is deliberately public - see its own doc comment) rather
    // than going through a real launch(), so the take can be observed
    // synchronously with no worker thread involved at all.
    // MUTATION-TESTED: reinstating the pre-#4190 take_locked() shape (move
    // T into a local `out` and return it directly, cell_->result left
    // engaged) turns CHECK(cell->result == nullptr) below red.
    auto cell = std::make_shared<detached_detail::Cell<int>>();
    cell->done = true;
    cell->done_hint.store(true, std::memory_order_relaxed);
    cell->result = std::make_unique<DetachedResult<int>>(42);

    DetachedCall<int> handle(cell);
    auto out = handle.try_take();
    REQUIRE(out.has_value());
    REQUIRE(out->has_value());
    CHECK(**out == 42);
    CHECK(cell->taken); // exactly-once gate - this, not result's nullness, is authoritative
    CHECK(cell->result == nullptr); // the box itself was moved out whole, not reset in place

    // A second take on the same handle is still correctly exactly-once.
    CHECK_FALSE(handle.try_take().has_value());
}

TEST_CASE("move-assign: overwriting a live, published-but-untaken handle disposes the OLD "
          "call, not just the new one",
          "[spark][detachedcall]") {
    // Regression for the Gate 8 fix (DetachedCall::operator=(DetachedCall&&),
    // changed from `= default` to a user-defined version): the defaulted
    // version silently overwrote cell_ without ever calling
    // dispose_or_abandon() on the PRIOR cell - a fourth, undocumented
    // delivery path outside this class's own exactly-once enumeration.
    // White-box (same technique as the take_locked test above): two
    // Cell<T>s constructed directly, no lane/worker/thread involved, so
    // the assignment's effect is observable synchronously. This case
    // exercises dispose_or_abandon()'s published-but-untaken branch.
    // MUTATION-TESTED: reverting operator= to `= default` turns
    // CHECK(old_cell->taken) below red (stays false).
    auto old_cell = std::make_shared<detached_detail::Cell<int>>();
    old_cell->done = true;
    old_cell->done_hint.store(true, std::memory_order_relaxed);
    old_cell->result = std::make_unique<DetachedResult<int>>(1);

    auto new_cell = std::make_shared<detached_detail::Cell<int>>();
    new_cell->done = true;
    new_cell->done_hint.store(true, std::memory_order_relaxed);
    new_cell->result = std::make_unique<DetachedResult<int>>(2);

    DetachedCall<int> old_handle(old_cell);
    DetachedCall<int> new_handle(new_cell);

    old_handle = std::move(new_handle); // the move-assignment under test

    CHECK(old_cell->taken); // the OLD (published) call was disposed by the assignment
    auto out = old_handle.try_take();
    REQUIRE(out.has_value());
    REQUIRE(out->has_value());
    CHECK(**out == 2); // the handle now genuinely holds the NEW call's result
}

TEST_CASE("move-assign: overwriting a live, not-yet-published handle abandons the OLD call",
          "[spark][detachedcall]") {
    // Same regression, the not-yet-published branch of dispose_or_abandon():
    // `done` stays false, so the correct outcome is `abandoned = true`
    // (telling a would-be worker to self-dispose later), never `taken`.
    auto old_cell = std::make_shared<detached_detail::Cell<int>>(); // done=false: not published

    auto new_cell = std::make_shared<detached_detail::Cell<int>>();
    new_cell->done = true;
    new_cell->done_hint.store(true, std::memory_order_relaxed);
    new_cell->result = std::make_unique<DetachedResult<int>>(2);

    DetachedCall<int> old_handle(old_cell);
    DetachedCall<int> new_handle(new_cell);

    old_handle = std::move(new_handle);

    CHECK(old_cell->abandoned); // told to self-dispose once/if it eventually completes
    CHECK_FALSE(old_cell->taken);
    auto out = old_handle.try_take();
    REQUIRE(out.has_value());
    REQUIRE(out->has_value());
    CHECK(**out == 2); // the handle now genuinely holds the NEW call's result
}

TEST_CASE("launch: an abandoned-before-publish result's disposal keeps the lane/F3 counter "
          "nonzero until the captured object's OWN destructor completes - not merely until "
          "the worker decides not to publish",
          "[spark][detachedcall]") {
    // This is the tightened F3-timing regression test (plan's "Ownership
    // fix" section, Astra table-12): a buggy implementation that decrements
    // the counters as soon as the worker records `abandoned` (i.e., right
    // when it would have published, had the owner not given up first) -
    // rather than only once the self-disposed value's OWN destructor has
    // fully finished running - would fail this test.
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;
    std::atomic<bool> dtor_started{false};
    std::atomic<std::thread::id> dtor_thread{};
    constexpr auto kHold = 300ms;

    auto res = lane.launch([&gate, &dtor_started, &dtor_thread, kHold]() -> SlowDtor {
        gate.wait();
        return SlowDtor(&dtor_started, &dtor_thread, kHold, 1);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    CHECK(lane.active_workers() == 1);
    CHECK(f3->load() == 1);

    // Abandon BEFORE the worker has even called fn() (still gated) - a
    // not-yet-published call, per this file's own contract, so the worker
    // self-disposes when it eventually completes.
    auto pre_abandon = res.call->abandon();
    CHECK_FALSE(pre_abandon.has_value());

    gate.release();

    REQUIRE(spin_until([&] { return dtor_started.load(); }, 5s));
    // The destructor has STARTED (and is now sleeping for kHold) - poll for
    // a window comfortably inside that sleep and assert the counters never
    // read 0 during it. A premature-decrement bug would show 0 almost
    // immediately after dtor_started flips, well inside this window.
    const auto poll_until = std::chrono::steady_clock::now() + kHold - 50ms;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    CHECK_FALSE(saw_zero_early);

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
    CHECK(dtor_thread.load() != std::this_thread::get_id()); // disposed on the WORKER thread
}

TEST_CASE("launch: fn's OWN captured RAII state outlives fn() returning, and the lane/F3 "
          "counter stays nonzero until IT is destroyed too",
          "[spark][detachedcall]") {
    // Pins the Payload<T,DFn> member-declaration-order fix directly (this
    // file's header comment, "Ticketing"): `held` is captured by the
    // closure and is unrelated to the returned T (an int) - it is only
    // destroyed when the closure itself (Payload's `fn` member) is
    // destroyed, which happens as part of Payload's own teardown AFTER
    // operator()() has already returned and the result has already been
    // published/taken. An implementation that captured the count-guard
    // ticket alongside fn in a lambda-capture list (UNSPECIFIED destruction
    // order - the shape this file's header comment says not to copy)
    // could destroy `held` AFTER the counters had already reached 0.
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    std::atomic<bool> dtor_started{false};
    std::atomic<std::thread::id> dtor_thread{};
    constexpr auto kHold = 300ms;

    SlowDtor held(&dtor_started, &dtor_thread, kHold, 2);
    auto res = lane.launch([held = std::move(held)]() -> int { return held.value; });
    REQUIRE(res.status == DetachedLaunch::Launched);

    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 2);
    // fn() has returned and the result has been taken - `held` (fn's own
    // capture) is NOT destroyed yet; it lives inside Payload's `fn` member
    // until Payload itself is torn down, which happens strictly after this.

    REQUIRE(spin_until([&] { return dtor_started.load(); }, 5s));
    const auto poll_until = std::chrono::steady_clock::now() + kHold - 50ms;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    CHECK_FALSE(saw_zero_early);

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
    CHECK(dtor_thread.load() != std::this_thread::get_id());
}

// ── Guardian-backend_op_deadline compile-time tripwire (the "audit this at
//    implementation time" note in the plan's "Shared primitive" section) ──
static_assert(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(200)));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5000)));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(6000)));
static_assert(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(100), 4));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(2000), 4));

TEST_CASE("spark_deadline_below_guardian_backend_op: tripwire matches the mirrored constant",
          "[spark][detachedcall]") {
    CHECK(kGuardianBackendOpDeadlineMirror == std::chrono::milliseconds(5000));
    CHECK(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(4999)));
    CHECK_FALSE(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5000)));
    CHECK_FALSE(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5001)));
}

TEST_CASE("kGuardianBackendOpDeadlineMirror: pinned against the REAL, live-constructed "
          "GuardianSparkRuntime::Config default, not just the literal it happens to equal",
          "[spark][detachedcall]") {
    // Gate 6 sre finding, PR-A round 5: kGuardianBackendOpDeadlineMirror's own
    // header comment calls itself "a documentation tripwire, not a functional
    // coupling" - nothing previously cross-checked it against the config it
    // claims to mirror, only against a second literal (the test above, and
    // the static_asserts before it) that could drift in lockstep with it and
    // never be caught. Default-constructing the real config here is what
    // makes this test capable of failing if Guardian's own default ever
    // changes without a matching update to the mirror.
    CHECK(kGuardianBackendOpDeadlineMirror == GuardianSparkRuntime::Config{}.backend_op_deadline);
}

// ── F3 regression: the counter survives its OWNING OBJECT's destruction
//    while a worker is still parked (agent.cpp accounting) ─────────────────
//
// This is the direct regression test for the round-3 F3 finding (plan's "F3
// orphan-exit accounting - Route A (corrected)" section): Astra found that
// summing F3 through GuardianEngine's wired SparkEngine pointer (an earlier
// "Route B" design) misses a detached worker in the window between the
// worker's own launch and whatever later, separate step wires or frees
// that pointer - agent.cpp's real spark boot block resets spark_engine_ on
// an exception AFTER a mechanism (and thus a lane) may already have spawned
// workers. Route A's fix is a counter that is summed directly in AgentImpl
// (agent.cpp's guardian_active_io_workers(), verified by compile + code
// inspection in this session - not exercised by a source-grepping test or
// a new test seam on the exported Agent interface, deliberately, per the
// same "don't test the mechanism, test the property" spirit as the rest of
// this file) and is NEVER read through spark_engine_/spark_boot_done_.
//
// PR-A has no real mechanism yet to reproduce agent.cpp's exact
// SparkEngine→mechanism→lane ownership chain (that is PR-B's job) - this
// test reproduces the SHAPE of the hazard directly against the primitive
// itself: construct a lane with a shared F3 counter (standing in for
// agent.cpp's spark_detached_workers_, which a real mechanism's
// SparkDetachedLane will be constructed with in PR-B), launch a gated
// (still in-flight) worker, then destroy the LANE OBJECT ITSELF - standing
// in for a mechanism, and thus SparkEngine, being torn down (agent.cpp's
// exception-reset path resets spark_engine_ while a mechanism's own
// threads may still be running) - while the worker is still parked. The
// counter must stay nonzero throughout, readable via the SAME independent
// shared_ptr<atomic<size_t>> the whole time, without going through
// anything the destroyed lane owned.
TEST_CASE("F3: the shared counter survives its lane's destruction while a worker is still "
          "parked - the exact shape of agent.cpp's SparkEngine-exception-reset hazard",
          "[spark][detachedcall][f3]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    Gate gate;

    {
        SparkDetachedLane lane(f3, /*cap=*/4);
        auto res = lane.launch([&gate]() -> int {
            gate.wait();
            return 1;
        });
        REQUIRE(res.status == DetachedLaunch::Launched);
        CHECK(f3->load() == 1);
        [[maybe_unused]] auto call = std::move(*res.call); // drop the handle too - the
                                                            // hazard is about the WORKER
                                                            // staying counted, not about
                                                            // any owner-side handle
        // `lane` (and `call`) go out of scope HERE - the worker is still
        // gated/in-flight. This is the moment agent.cpp's exception-reset
        // path (spark_engine_.reset() in the boot block's catch clauses)
        // stands in for: whatever owned the lane is gone, but the counter
        // it was constructed with must not silently lose track of a still-
        // running worker.
    }

    // The lane object no longer exists at all - read the counter through
    // ONLY the independent shared_ptr the test itself still holds, exactly
    // as AgentImpl::guardian_active_io_workers() reads spark_detached_workers_
    // without ever touching spark_engine_.
    CHECK(f3->load() == 1);

    gate.release();
    REQUIRE(spin_until([&] { return f3->load() == 0; }, 5s));
}

// ── Regression: take_locked() must not touch T - a concurrent take is not
//    blocked by a slow moved-from destructor (colleague review, PR #4190) ──
TEST_CASE("take_locked()/unbox(): a concurrent second take is not blocked by the winner's "
          "own slow moved-from-T destructor",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    constexpr auto kHold = 400ms;

    auto res = lane.launch([kHold]() -> SlowMoveObservableDtor {
        return SlowMoveObservableDtor(kHold);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);

    // Wait for the worker to publish. The worker's OWN local `value` (see
    // Payload::operator()()) is itself a moved-from remnant of the move
    // into the box - its slow destructor runs here too, but on the WORKER
    // thread, before `done` is even set, and has nothing to do with
    // cell_->mu (the worker never holds it during this phase) - this just
    // means `done` may take a little over kHold to become true.
    REQUIRE(spin_until([&] { return res.call->done(); }, 5s));

    // Race two takers. Whichever wins runs the box's real moved-from T
    // destructor (this type's slow path) inside unbox() - AFTER the fix,
    // strictly outside cell_->mu; before the fix, still inside it (see the
    // type's own comment above). The LOSER must see an uncontended lock and
    // return promptly regardless of which side wins the race.
    std::array<std::chrono::steady_clock::duration, 2> elapsed{};
    std::array<bool, 2> got_value{false, false};
    auto racer = [&](std::size_t idx) {
        auto start = std::chrono::steady_clock::now();
        auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
        elapsed[idx] = std::chrono::steady_clock::now() - start;
        got_value[idx] = v.has_value();
    };
    std::thread t0([&] { racer(0); });
    std::thread t1([&] { racer(1); });
    t0.join();
    t1.join();

    // Exactly one racer took the value; the other saw nullopt.
    REQUIRE(got_value[0] != got_value[1]);
    const auto loser_elapsed = got_value[0] ? elapsed[1] : elapsed[0];
    // The loser must not have blocked anywhere near the winner's slow
    // destructor duration - a generous margin (kHold/3) well clear of
    // ordinary scheduling jitter, but far enough under kHold that this
    // assertion FAILS if cell_->mu is held across the slow destructor
    // (verified: reverting the take_locked()/unbox() fix makes this fail,
    // with loser_elapsed landing close to kHold instead).
    CHECK(loser_elapsed < kHold / 3);
}

// ── Regression: two lanes sharing one F3 counter add/subtract correctly and
//    independently (§24 sum-integrity - no test previously composed two
//    lanes over one counter; every prior F3 case is single-lane) ──────────
TEST_CASE("F3: two independent lanes sharing one counter add and subtract correctly, "
          "including across independent teardown",
          "[spark][detachedcall][f3]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    Gate gate_a, gate_b;

    auto lane_a = std::make_unique<SparkDetachedLane>(f3, /*cap=*/4);
    auto lane_b = std::make_unique<SparkDetachedLane>(f3, /*cap=*/4);

    auto res_a = lane_a->launch([&gate_a]() -> int {
        gate_a.wait();
        return 1;
    });
    REQUIRE(res_a.status == DetachedLaunch::Launched);
    CHECK(f3->load() == 1);

    auto res_b = lane_b->launch([&gate_b]() -> int {
        gate_b.wait();
        return 2;
    });
    REQUIRE(res_b.status == DetachedLaunch::Launched);
    CHECK(f3->load() == 2); // additive across lanes, not per-lane-scoped

    // Release + retire lane A's worker; lane B's stays parked throughout.
    gate_a.release();
    REQUIRE(spin_until([&] { return res_a.call->done(); }, 5s));
    auto va = res_a.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(va.has_value());
    REQUIRE(va->has_value());
    CHECK(**va == 1);
    REQUIRE(spin_until([&] { return f3->load() == 1; }, 5s)); // A's exit only

    // Destroying lane A entirely must not disturb lane B's still-parked
    // worker's contribution to the SHARED counter.
    lane_a.reset();
    CHECK(f3->load() == 1);
    CHECK(lane_b->active_workers() == 1);

    gate_b.release();
    REQUIRE(spin_until([&] { return f3->load() == 0; }, 5s));
    CHECK(lane_b->active_workers() == 0);
}
