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

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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

// Bounded park on a Gate: returns when the test releases it, or after kDtorGateSafetyNet
// (never reached by a passing run - it only keeps a regressed run from hanging the suite).
constexpr auto kDtorGateSafetyNet = 30s;
// How long the F3 timing cases watch the counters while a destructor is held on its gate.
// Negative-evidence window only: the destructor cannot finish inside it, so it carries no
// timer-margin risk; a premature-decrement defect is visible at once (it precedes disposal).
constexpr auto kHeldWindow = 100ms;
void wait_gate_bounded(Gate& g) {
    std::unique_lock<std::mutex> lk{g.m};
    g.cv.wait_for(lk, kDtorGateSafetyNet, [&] { return g.go; });
}

// A move-only result type whose destructor records WHEN it started (an
// atomic<bool> flag) and ON WHICH THREAD, then - if given a `hold_gate` -
// parks on it until the test releases it (or sleeps `hold_for` when no gate
// is given) before returning. Used to make the "disposal, not publication,
// is what the F3 counter waits for" property directly observable: a poller
// on another thread can watch the flag flip and then confirm the lane/F3
// counter stays nonzero for the FULL duration of the destructor's own run,
// not just up to the moment the worker decided whether to publish or
// self-dispose. The gate makes "the destructor is still running" a state the
// test CONTROLS rather than a sleep it has to out-wait, so the observation
// window is not tied to a timer's duration or granularity.
struct SlowDtor {
    std::atomic<bool>* started{nullptr};
    std::atomic<std::thread::id>* thread_id{nullptr};
    std::chrono::milliseconds hold_for{0};
    int value{0};
    Gate* hold_gate{nullptr};

    SlowDtor() = default;
    SlowDtor(std::atomic<bool>* s, std::atomic<std::thread::id>* tid,
             std::chrono::milliseconds hold, int v, Gate* gate = nullptr)
        : started(s), thread_id(tid), hold_for(hold), value(v), hold_gate(gate) {}
    SlowDtor(const SlowDtor&) = delete;
    SlowDtor& operator=(const SlowDtor&) = delete;
    SlowDtor(SlowDtor&& o) noexcept
        : started(o.started), thread_id(o.thread_id), hold_for(o.hold_for), value(o.value),
          hold_gate(o.hold_gate) {
        o.started = nullptr; // moved-from: its destructor becomes a no-op
        o.thread_id = nullptr;
    }
    SlowDtor& operator=(SlowDtor&& o) noexcept {
        if (this != &o) {
            started = o.started;
            thread_id = o.thread_id;
            hold_for = o.hold_for;
            value = o.value;
            hold_gate = o.hold_gate;
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
        if (hold_gate)
            wait_gate_bounded(*hold_gate);
        else if (hold_for.count() > 0)
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
// This type makes that difference OBSERVABLE: once `armed`, its moved-from
// destructor flags `entered` and parks on `gate` until the test releases it.
// The regression test below can then watch a loser's take complete while
// the winner is PROVABLY still inside that destructor, instead of timing
// the loser against a sleeping destructor. Disarmed (the worker's own
// remnant, destroyed before `done` is set), it is inert so publication is
// not delayed.
struct MovedFromProbe {
    std::atomic<bool> armed{false};
    std::atomic<bool> entered{false};
    Gate gate;
};

struct SlowMoveObservableDtor {
    MovedFromProbe* probe{nullptr};
    bool moved_from{false};

    SlowMoveObservableDtor() = default;
    explicit SlowMoveObservableDtor(MovedFromProbe* p) : probe(p) {}
    SlowMoveObservableDtor(const SlowMoveObservableDtor&) = delete;
    SlowMoveObservableDtor& operator=(const SlowMoveObservableDtor&) = delete;
    SlowMoveObservableDtor(SlowMoveObservableDtor&& o) noexcept : probe(o.probe) {
        o.moved_from = true; // o (the SOURCE) becomes the probed remnant;
                              // `this` (the destination) is the live value
                              // and stays moved_from == false (its own
                              // default), so ITS eventual teardown is fast
    }
    SlowMoveObservableDtor& operator=(SlowMoveObservableDtor&&) = delete;
    ~SlowMoveObservableDtor() {
        if (!moved_from || !probe || !probe->armed.load(std::memory_order_acquire))
            return; // the live (moved-to) value's teardown isn't probed
        probe->entered.store(true, std::memory_order_release);
        wait_gate_bounded(probe->gate);
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
    // The destructor parks here once it starts (see SlowDtor), so "the destructor is still
    // running" is a state this test holds for as long as it needs and then ends, not a
    // sleep it has to out-wait. Declared AFTER everything the worker touches so that it is
    // released FIRST on any exit path. The cleanup also releases `gate` and waits (bounded) for
    // the worker to retire, because the worker holds by-reference captures of this frame's
    // locals: without the wait a failed REQUIRE could unwind the frame under a live worker.
    Gate dtor_gate;
    yuzu::test::ScopeExit release_dtor{[&] {
        gate.release();
        dtor_gate.release();
        spin_until([&] { return lane.active_workers() == 0; }, 5s);
    }};

    auto res = lane.launch([&gate, &dtor_started, &dtor_thread, &dtor_gate]() -> SlowDtor {
        gate.wait();
        return SlowDtor(&dtor_started, &dtor_thread, 0ms, 1, &dtor_gate);
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
    // The destructor has STARTED and is now parked on dtor_gate - poll for a
    // window while it is held and assert the counters never read 0 during it.
    // A premature-decrement bug would show 0 almost immediately after
    // dtor_started flips (the decrement it models happens BEFORE disposal
    // begins), well inside this window. The destructor cannot finish during
    // the window whatever the scheduler does, so no timer margin is involved.
    const auto poll_until = std::chrono::steady_clock::now() + kHeldWindow;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(5ms);
    }
    CHECK_FALSE(saw_zero_early);

    dtor_gate.release(); // let the destructor finish; only now may the counters reach 0
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
    // See the previous case: the destructor parks on this gate, released first on any exit,
    // and the cleanup waits (bounded) for the worker to retire.
    Gate dtor_gate;
    yuzu::test::ScopeExit release_dtor{[&] {
        dtor_gate.release();
        spin_until([&] { return lane.active_workers() == 0; }, 5s);
    }};

    SlowDtor held(&dtor_started, &dtor_thread, 0ms, 2, &dtor_gate);
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
    // The capture's destructor is now parked on dtor_gate: poll a window while it is held
    // (see the previous case) and assert the counters never read 0 during it.
    const auto poll_until = std::chrono::steady_clock::now() + kHeldWindow;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(5ms);
    }
    CHECK_FALSE(saw_zero_early);

    dtor_gate.release(); // let the destructor finish; only now may the counters reach 0
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
    MovedFromProbe probe;
    std::array<std::atomic<bool>, 2> finished{};
    std::array<bool, 2> got_value{false, false};
    std::vector<std::thread> racers;
    racers.reserve(2);

    auto res = lane.launch([&probe]() -> SlowMoveObservableDtor {
        return SlowMoveObservableDtor(&probe);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    // Declared AFTER everything the destructor and the racers touch (including `res`): runs
    // FIRST on any exit path, so a failed REQUIRE (or a regression that wedges a racer)
    // releases the parked destructor and joins the racers instead of stranding them.
    yuzu::test::ScopeExit cleanup{[&] {
        probe.gate.release();
        for (auto& t : racers)
            if (t.joinable())
                t.join();
    }};

    // Wait for the worker to publish. The worker's OWN local `value` (see
    // Payload::operator()()) is itself a moved-from remnant of the move
    // into the box, but the probe is not armed yet, so its destructor is
    // inert and publication is not delayed.
    REQUIRE(spin_until([&] { return res.call->done(); }, 5s));
    probe.armed.store(true, std::memory_order_release);

    // Race two takers. Whichever wins runs the box's real moved-from T
    // destructor inside unbox() - AFTER the fix, strictly outside cell_->mu;
    // before the fix, still inside it (see the type's own comment above) -
    // and that destructor now PARKS on the probe's gate. So the winner cannot
    // return until this test releases the gate, and the first racer to
    // finish can only be the loser. The LOSER must see an uncontended lock
    // and return (nullopt, already taken) while the winner is still parked
    // inside the destructor; if cell_->mu were held across that destructor
    // the loser would block behind it and never finish. Event-driven: no
    // sleep, no elapsed-time margin.
    auto racer = [&](std::size_t idx) {
        auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
        got_value[idx] = v.has_value();
        finished[idx].store(true, std::memory_order_release);
    };
    racers.emplace_back([&] { racer(0); });
    racers.emplace_back([&] { racer(1); });

    REQUIRE(spin_until([&] { return finished[0].load() || finished[1].load(); }, 5s));
    // The winner is parked in the slow destructor (it cannot have finished); the racer that
    // did finish is therefore the loser and must have seen "already taken".
    REQUIRE(spin_until([&] { return probe.entered.load(std::memory_order_acquire); }, 5s));
    const std::size_t loser = finished[0].load() ? 0 : 1;
    CHECK_FALSE(got_value[loser]);
    CHECK_FALSE(finished[1 - loser].load()); // the winner is still held by the destructor

    probe.gate.release();
    for (auto& t : racers)
        t.join();

    // Exactly one racer took the value; the other saw nullopt.
    CHECK(got_value[0] != got_value[1]);
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

// ---------------------------------------------------------------------------
// Admission is a compare-exchange loop (#4660): the lane's active_workers()
// gauge must never read above the cap in effect at admission.
//
// The defect these cases pin: launch() used to admit with fetch_add(1), compare
// prev+1 to the cap, and roll a rejected launch back with fetch_sub(1). No worker
// beyond the cap was ever admitted, but between the add and the sub the gauge read
// cap+1 (or more, under concurrent rejected launches) - which every lane-local
// active_workers() reader (the probe_workers_active debug counters and the storm
// test that samples one) saw as real. The shared F3 counter was never exposed: it
// is incremented only after admission. A sampler thread polling the gauge while
// many threads are rejected is what makes the transient visible; a
// single-threaded launch/assert sequence cannot see it.
//
// The F3 counter is sampled too, but only as a sanity bound while workers stay
// parked: under worker churn it can legitimately read cap+1 (CountGuard drops
// active, then f3, while a launch raises active, then f3), so no case here
// asserts that bound once workers retire.
// ---------------------------------------------------------------------------
namespace {

// Joins every thread it holds on destruction, so a failing assertion elsewhere in the
// test can never unwind past a joinable std::thread (which would std::terminate).
struct ThreadJoiner {
    std::vector<std::thread> threads;
    ThreadJoiner() = default;
    ThreadJoiner(const ThreadJoiner&) = delete;
    ThreadJoiner& operator=(const ThreadJoiner&) = delete;
    ~ThreadJoiner() {
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

// Everything a detached worker of an admission case touches. It is owned by shared_ptr and
// every worker closure holds a reference, so a worker that outlives the test frame (a failed
// drain after a REQUIRE unwind) can never touch a destroyed Gate or counter: nothing a
// worker reads or writes lives on a test's stack.
struct WorkerShared {
    Gate gate;
    std::atomic<int> running{0};     // ChurnWork: workers executing right now
    std::atomic<int> max_running{0}; // ChurnWork: the most that ever ran at once
    std::atomic<std::uint64_t> spin_sink{0}; // ChurnWork: the busy-spin's side effect
};

// One lane, its shared F3 counter, and the WorkerShared its workers use, with the cleanup
// every admission case needs: on ANY exit path (including a failed REQUIRE) the gate is
// released and the workers are waited for. A drain that times out fails the test loudly
// (CHECK, never REQUIRE: this runs from a destructor); the workers keep what they touch
// alive through their own references. The F3 counter is awaited first: CountGuard lowers
// `active` and then F3, so F3 == 0 means the last worker has finished.
struct AdmissionRig {
    std::shared_ptr<std::atomic<std::size_t>> f3 =
        std::make_shared<std::atomic<std::size_t>>(0);
    std::shared_ptr<WorkerShared> shared = std::make_shared<WorkerShared>();
    SparkDetachedLane lane;

    explicit AdmissionRig(std::size_t cap) : lane(f3, cap) {}
    AdmissionRig(const AdmissionRig&) = delete;
    AdmissionRig& operator=(const AdmissionRig&) = delete;
    ~AdmissionRig() {
        shared->gate.release();
        CHECK(spin_until([&] { return f3->load() == 0; }, 5s));
        CHECK(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    }

    // Launches one worker that parks on the gate until the rig is destroyed or released.
    [[nodiscard]] DetachedLaunch launch_parked();
};

// The worker body most cases launch: park on the rig's gate until it is released.
struct ParkedWork {
    std::shared_ptr<WorkerShared> state;
    int operator()() const {
        state->gate.wait();
        return 0;
    }
};

DetachedLaunch AdmissionRig::launch_parked() {
    auto r = lane.launch(ParkedWork{shared});
    return r.status;
}

// Fills the lane with `n` parked workers on the calling thread. No other thread is alive.
struct FillResult {
    std::size_t launched{0};
    std::size_t launch_failed{0};
};
FillResult fill(AdmissionRig& rig, std::size_t n) {
    FillResult f;
    for (std::size_t i = 0; i < n; ++i) {
        const DetachedLaunch s = rig.launch_parked();
        if (s == DetachedLaunch::Launched)
            ++f.launched;
        else if (s == DetachedLaunch::LaunchFailed)
            ++f.launch_failed;
    }
    return f;
}

// A short-lived worker that records how many workers are running AT THE SAME TIME, so an
// implementation that over-admits (two threads both seeing the last free slot) is caught by
// real concurrency, not only by the gauge, which a lost update can also under-count.
struct ChurnWork {
    std::shared_ptr<WorkerShared> state;
    int operator()() const {
        const int now = state->running.fetch_add(1, std::memory_order_acq_rel) + 1;
        int seen = state->max_running.load(std::memory_order_relaxed);
        while (now > seen &&
               !state->max_running.compare_exchange_weak(seen, now, std::memory_order_relaxed)) {
        }
        // Linger briefly so overlapping admissions overlap in time. A busy spin, not a yield:
        // on a loaded runner a yield gives up the whole timeslice and stretches the case from
        // milliseconds to minutes.
        for (int i = 0; i < 2000; ++i)
            state->spin_sink.fetch_add(1, std::memory_order_relaxed);
        state->running.fetch_sub(1, std::memory_order_acq_rel);
        return 0;
    }
};

struct HammerResult {
    std::uint64_t launched{0};
    std::uint64_t rejected{0};
    std::uint64_t other{0}; // LaunchFailed: the OS refused a worker thread
    std::size_t max_active_seen{0}; // highest lane.active_workers() the sampler ever read
    std::size_t max_f3_seen{0};     // highest shared F3 counter the sampler ever read
    std::uint64_t samples_after_go{0}; // sampler reads taken while the launchers were running
    std::string thread_error;          // non-empty: a thread could not be started (resource limit)
};

// What an optional controller thread sees while a hammer runs.
struct HammerCtl {
    const std::atomic<std::uint64_t>& calls; // launch() calls completed so far, all launchers
    const std::atomic<bool>& abort; // set once every launcher has finished, or on teardown
};

// Optional behaviour a case adds to a hammer; every member may be left empty.
struct HammerHooks {
    // Runs on its own thread alongside the launchers. It must return once `abort` is set.
    std::function<void(const HammerCtl&)> controller;
    // Each launcher waits (bounded by the hammer deadline) while this returns true.
    std::function<bool()> hold;
    // Launchers keep going until this many launches were admitted (bounded by the deadline).
    std::uint64_t min_launched{0};
};

// Every launcher keeps going past `iters` until the sampler has taken at least this many reads
// after `go`, so a runner that deschedules the sampler for the whole of a fixed iteration
// count does not turn the check into a false green; the deadline bounds that extension.
constexpr std::uint64_t kMinSamples = 50000;
// Scaled by kSpinScale where it is used.
constexpr auto kHammerDeadline = 10s;

// Runs `threads` launcher threads, each calling lane.launch() at least `iters` times with a
// callable that parks on the rig's gate, while one sampler thread polls the lane gauge and
// the shared F3 counter flat out for the whole run, and an optional controller thread
// runs alongside. Joins everything before returning and asserts nothing itself (no
// REQUIRE/CHECK is reachable while a thread is joinable). A thread that cannot be started
// is reported in `thread_error`, never as an admission failure; the caller asserts on the
// returned counts.
template <class Work>
HammerResult hammer(AdmissionRig& rig, const Work& work, int threads, int iters,
                    const HammerHooks& hooks = {}) {
    HammerResult res;
    std::atomic<bool> go{false};
    std::atomic<bool> abort{false};
    std::atomic<bool> sampler_stop{false};
    std::atomic<std::uint64_t> samples_before_go{0};
    std::atomic<std::uint64_t> samples_after_go{0};
    std::atomic<std::uint64_t> calls{0};
    std::atomic<std::uint64_t> launched{0};
    std::atomic<std::uint64_t> rejected{0};
    std::atomic<std::uint64_t> other{0};
    std::atomic<bool> ctl_done{!hooks.controller};
    std::size_t max_active = 0;
    std::size_t max_f3 = 0;
    SparkDetachedLane& lane = rig.lane;
    const auto f3 = rig.f3;

    {
        ThreadJoiner sampler;
        ThreadJoiner launchers;
        ThreadJoiner ctl;
        // Declared AFTER the joiners so it runs BEFORE them on every exit path (including a
        // throwing std::thread constructor): the spinning launchers see `go`/`abort`, the
        // sampler sees `sampler_stop`, and the joiners then cannot block forever.
        yuzu::test::ScopeExit unblock{[&] {
            abort.store(true, std::memory_order_release);
            go.store(true, std::memory_order_release);
            sampler_stop.store(true, std::memory_order_release);
        }};
        try {
            launchers.threads.reserve(static_cast<std::size_t>(threads));
            sampler.threads.emplace_back([&] {
                std::uint64_t before = 0;
                std::uint64_t after = 0;
                while (!sampler_stop.load(std::memory_order_acquire)) {
                    max_active = std::max(max_active, lane.active_workers());
                    max_f3 = std::max(max_f3, f3->load(std::memory_order_acquire));
                    if (go.load(std::memory_order_acquire))
                        samples_after_go.store(++after, std::memory_order_relaxed);
                    else
                        samples_before_go.store(++before, std::memory_order_relaxed);
                }
            });
            // Handshake: do not release the launchers until the sampler has demonstrably run.
            if (!spin_until([&] { return samples_before_go.load(std::memory_order_relaxed) > 0; },
                            5s))
                throw std::runtime_error("the sampler thread did not start within 5 s");
            for (int t = 0; t < threads; ++t) {
                launchers.threads.emplace_back([&] {
                    while (!go.load(std::memory_order_acquire))
                        std::this_thread::yield();
                    const auto deadline = std::chrono::steady_clock::now() +
                                          kHammerDeadline * yuzu::test::kSpinScale;
                    const auto past_deadline = [&] {
                        return std::chrono::steady_clock::now() >= deadline;
                    };
                    for (int i = 0; !abort.load(std::memory_order_acquire); ++i) {
                        if (hooks.hold) {
                            while (!abort.load(std::memory_order_acquire) && !past_deadline() &&
                                   hooks.hold())
                                std::this_thread::yield();
                        }
                        const bool enough =
                            samples_after_go.load(std::memory_order_relaxed) >= kMinSamples &&
                            ctl_done.load(std::memory_order_acquire) &&
                            launched.load(std::memory_order_relaxed) >= hooks.min_launched;
                        if (i >= iters && (enough || past_deadline()))
                            break;
                        auto r = lane.launch(Work(work));
                        switch (r.status) {
                        case DetachedLaunch::Launched:
                            launched.fetch_add(1, std::memory_order_relaxed);
                            break;
                        case DetachedLaunch::Rejected:
                            rejected.fetch_add(1, std::memory_order_relaxed);
                            break;
                        default:
                            // The OS refused a worker thread: stop every launcher and any
                            // controller now; the caller reports it as a resource failure.
                            other.fetch_add(1, std::memory_order_relaxed);
                            abort.store(true, std::memory_order_release);
                            break;
                        }
                        calls.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }
            if (hooks.controller)
                ctl.threads.emplace_back([&] {
                    hooks.controller(HammerCtl{calls, abort});
                    ctl_done.store(true, std::memory_order_release);
                });
            go.store(true, std::memory_order_release);
            for (auto& t : launchers.threads)
                t.join();
            // Every launcher is done: release a controller still waiting for a condition
            // BEFORE joining it, so no join below can wait on a flag that is set later.
            abort.store(true, std::memory_order_release);
            for (auto& t : ctl.threads)
                t.join();
            sampler_stop.store(true, std::memory_order_release);
            for (auto& t : sampler.threads)
                t.join();
        } catch (const std::exception& e) {
            res.thread_error = std::string("hammer could not run (a thread could not be started "
                                           "- resource limit such as ulimit -u?): ") +
                               e.what();
        }
    } // unblock, then every joiner

    res.launched = launched.load();
    res.rejected = rejected.load();
    res.other = other.load();
    res.max_active_seen = max_active;
    res.max_f3_seen = max_f3;
    res.samples_after_go = samples_after_go.load();
    return res;
}

// The assertions every hammer shares. Called only after hammer() returned, so no thread is
// joinable and REQUIRE may unwind.
void require_hammer_ran(const HammerResult& h) {
    INFO(h.thread_error);
    REQUIRE(h.thread_error.empty());
    INFO("sampler reads taken while the launchers ran: " << h.samples_after_go);
    REQUIRE(h.samples_after_go >= kMinSamples); // a sampler that never ran cannot false-green
    // LaunchFailed means the OS refused a worker thread, which is a resource problem, not
    // an admission result.
    INFO("launches that returned LaunchFailed (OS refused a worker thread): " << h.other);
    REQUIRE(h.other == 0);
}

constexpr int kHammerThreads = 16;
constexpr int kHammerIters = 20000;

} // namespace

TEST_CASE("admission: a saturated lane's gauge never reads above its cap while many threads are "
          "rejected (#4660)",
          "[spark][detachedcall]") {
    constexpr std::size_t kCap = 4;
    AdmissionRig rig(kCap);

    // Fill the lane exactly to its cap with parked workers. No thread is joinable here.
    const FillResult filled = fill(rig, kCap);
    INFO("LaunchFailed while filling (OS refused a worker thread): " << filled.launch_failed);
    REQUIRE(filled.launched == kCap);
    REQUIRE(rig.lane.active_workers() == kCap);

    // The lane is full: every launch below must be rejected, and the gauge must stay at the
    // cap for the whole run - not "usually", every sample.
    const HammerResult h =
        hammer(rig, ParkedWork{rig.shared}, kHammerThreads, kHammerIters);
    require_hammer_ran(h);

    CHECK(h.launched == 0);
    CHECK(h.rejected >= static_cast<std::uint64_t>(kHammerThreads) * kHammerIters);
    CHECK(rig.lane.rejected_total() == h.rejected);
    INFO("max sampled active_workers()=" << h.max_active_seen << " f3=" << h.max_f3_seen
                                         << " (cap=" << kCap << ")");
    CHECK(h.max_active_seen <= kCap);
    CHECK(h.max_f3_seen <= kCap); // holds here only because no worker retires during the run
    CHECK(rig.lane.active_workers() == kCap); // rejected launches left no residue
    CHECK(rig.f3->load() == kCap);
}

TEST_CASE("admission: a cap of 0 never publishes a nonzero gauge under concurrent rejected "
          "launches (#4660)",
          "[spark][detachedcall]") {
    AdmissionRig rig(/*cap=*/0);

    const HammerResult h =
        hammer(rig, ParkedWork{rig.shared}, kHammerThreads, kHammerIters);
    require_hammer_ran(h);

    CHECK(h.launched == 0);
    CHECK(h.rejected >= static_cast<std::uint64_t>(kHammerThreads) * kHammerIters);
    INFO("max sampled active_workers()=" << h.max_active_seen << " (cap=0)");
    CHECK(h.max_active_seen == 0);
    CHECK(h.max_f3_seen == 0);
    CHECK(rig.lane.active_workers() == 0);
    CHECK(rig.f3->load() == 0);
}

// Mutation record for the next two cases (author-measured, scratch copies of the header):
// "no cap re-check after a failed CAS", "load + store instead of CAS" and "check, then
// fetch_add" are only caught when the launchers really run in parallel. They die on an idle
// multi-core box and SURVIVE when the process is pinned to two CPUs under load, so a green
// run on such a runner says nothing about those races. The old fetch_add-and-rollback scheme
// and the ">" for ">=" mutant die in both modes.
TEST_CASE("admission: threads racing for a lane's slots admit exactly `cap` workers, never more, "
          "and the gauge never exceeds the cap (#4660)",
          "[spark][detachedcall]") {
    constexpr std::size_t kCap = 3;
    AdmissionRig rig(kCap);

    // The lane starts EMPTY: this is the compare-exchange's own race (several threads each
    // observing a count below the cap), not just the rejection path. Fewer iterations - the
    // lane is full after the first kCap admissions and every later launch is a rejection.
    const HammerResult h = hammer(rig, ParkedWork{rig.shared}, kHammerThreads, 2000);
    require_hammer_ran(h);

    CHECK(h.launched == kCap);
    CHECK(h.rejected >= static_cast<std::uint64_t>(kHammerThreads) * 2000 - kCap);
    INFO("max sampled active_workers()=" << h.max_active_seen << " f3=" << h.max_f3_seen
                                         << " (cap=" << kCap << ")");
    CHECK(h.max_active_seen <= kCap);
    CHECK(h.max_f3_seen <= kCap); // holds here only because no worker retires during the run
    CHECK(rig.lane.active_workers() == kCap);
    CHECK(rig.f3->load() == kCap);
}

TEST_CASE("admission: slots that free and refill under contention never run more than `cap` "
          "workers at once (#4660)",
          "[spark][detachedcall]") {
    constexpr std::size_t kCap = 3;
    // Enough admissions that slots are freed and refilled many times even on a runner with
    // two CPUs, where the launchers alone would admit only a handful before the iteration
    // count ran out.
    constexpr std::uint64_t kMinAdmissions = 300;
    AdmissionRig rig(kCap);

    // Workers retire on their own here, so slots are released and re-raced continuously: this
    // is the compare-exchange's contended path (a failed exchange must re-check the cap, and
    // two threads must never both take the last slot).
    HammerHooks hooks;
    hooks.min_launched = kMinAdmissions;
    const HammerResult h = hammer(rig, ChurnWork{rig.shared}, kHammerThreads, 200, hooks);
    require_hammer_ran(h);

    const int max_running = rig.shared->max_running.load();
    INFO("admitted=" << h.launched << " max workers running at once=" << max_running
                     << " max sampled active_workers()=" << h.max_active_seen
                     << " (cap=" << kCap << ")");
    CHECK(h.launched >= kMinAdmissions); // the refill path was exercised, not only rejection
    CHECK(max_running <= static_cast<int>(kCap));
    CHECK(h.max_active_seen <= kCap);
    // CountGuard lowers `active` and then the F3 counter: wait for F3 first.
    REQUIRE(spin_until([&] { return rig.f3->load() == 0; }, 5s));
    CHECK(rig.lane.active_workers() == 0);
}

// Mutation record: an implementation that reads the cap ONCE before the CAS loop instead of
// on every iteration survives this case (and every other here). It differs from the fixed
// code only inside a single call's retry loop, and any admission it makes after a lowering is
// one an in-flight call may also make legally, so no count or gauge assertion separates the
// two without a test seam between the cap load and the exchange.
TEST_CASE("admission: a cap lowered while launchers race bounds the later admissions and the "
          "gauge never exceeds the original cap (#4660)",
          "[spark][detachedcall]") {
    constexpr std::size_t kCapOld = 64;
    constexpr std::size_t kCapNew = 2;
    constexpr std::size_t kTrigger = 8;  // the controller lowers the cap at this many workers
    constexpr std::size_t kStall = 12;   // launchers wait here until the cap is lowered
    AdmissionRig rig(kCapOld);
    std::atomic<std::size_t> active_at_lowering{0};
    std::atomic<bool> lowered{false};

    // The launchers must not run the lane up to kCapOld before the controller is scheduled,
    // or (on a runner with two CPUs) the lowering lands on an already-full lane and the case
    // checks nothing: they stall at kStall workers until it is lowered. Between kTrigger and
    // kStall they still race the lowering.
    HammerHooks hooks;
    hooks.hold = [&] {
        return !lowered.load(std::memory_order_acquire) && rig.lane.active_workers() >= kStall;
    };
    hooks.controller = [&](const HammerCtl& ctl) {
        // Event-driven: poll the gauge, bounded by the hammer's own abort flag.
        while (!ctl.abort.load(std::memory_order_acquire) && rig.lane.active_workers() < kTrigger)
            std::this_thread::yield();
        if (ctl.abort.load(std::memory_order_acquire))
            return;
        rig.lane.set_cap_for_test(kCapNew);
        // Read AFTER set_cap_for_test returned.
        active_at_lowering.store(rig.lane.active_workers(), std::memory_order_relaxed);
        lowered.store(true, std::memory_order_release);
    };
    const HammerResult h = hammer(rig, ParkedWork{rig.shared}, kHammerThreads, 2000, hooks);
    require_hammer_ran(h);
    REQUIRE(lowered.load());
    const std::size_t at_lowering = active_at_lowering.load();
    INFO("active at lowering=" << at_lowering << " final=" << h.launched
                               << " max sampled=" << h.max_active_seen);
    // The lowering must have landed on a lane that still had room, or the case is vacuous.
    REQUIRE(at_lowering < kCapOld);

    // Workers stay parked for the whole run, so launched == the gauge at the end. A launch
    // admitted after set_cap_for_test returned must have read the old cap before the
    // lowering: at most one per launcher thread can be in flight at that instant. The
    // documented worst case is cap_old - cap_new; the bound asserted here is the tighter
    // per-launcher one, which an implementation that ignored the lowered cap would blow
    // through (it would keep admitting until the lane held kCapOld workers).
    CHECK(h.max_active_seen <= kCapOld);
    CHECK(h.launched <= kCapOld);
    CHECK(h.launched - std::min<std::uint64_t>(h.launched, at_lowering) <=
          static_cast<std::uint64_t>(kHammerThreads));
    CHECK(rig.lane.active_workers() == h.launched);
}

TEST_CASE("admission: cap boundaries - 1 admits one then rejects, a freed slot is reusable, and "
          "Fn comes back unconsumed (#4660)",
          "[spark][detachedcall]") {
    AdmissionRig rig(/*cap=*/1);
    auto& lane = rig.lane;

    const FillResult filled = fill(rig, 1);
    INFO("LaunchFailed while filling (OS refused a worker thread): " << filled.launch_failed);
    REQUIRE(filled.launched == 1);
    CHECK(lane.active_workers() == 1);

    auto second = lane.launch([m = Marker(7)]() mutable -> int { return m.tag; });
    CHECK(second.status == DetachedLaunch::Rejected);
    CHECK_FALSE(second.call.has_value());
    REQUIRE(second.fn.has_value());
    CHECK((*second.fn)() == 7); // the original, unconsumed closure
    CHECK(lane.active_workers() == 1);
    CHECK(rig.f3->load() == 1);
    CHECK(lane.rejected_total() == 1);

    // Free the slot; a later launch is admitted again (the count came back down). CountGuard
    // lowers `active` and THEN the F3 counter, so wait for F3 first: once it reads 0 both
    // have been lowered.
    rig.shared->gate.release();
    REQUIRE(spin_until([&] { return rig.f3->load() == 0; }, 5s));
    CHECK(lane.active_workers() == 0);
    auto third = lane.launch([]() -> int { return 3; });
    REQUIRE(third.status == DetachedLaunch::Launched);
    auto v = third.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 3);
    REQUIRE(spin_until([&] { return rig.f3->load() == 0; }, 5s));
    CHECK(lane.active_workers() == 0);
}

TEST_CASE("admission: a cap lowered live is honoured, and a cap below the current count rejects "
          "without raising the gauge (#4660)",
          "[spark][detachedcall]") {
    AdmissionRig rig(/*cap=*/4);
    auto& lane = rig.lane;

    const FillResult filled = fill(rig, 3);
    INFO("LaunchFailed while filling (OS refused a worker thread): " << filled.launch_failed);
    REQUIRE(filled.launched == 3);
    REQUIRE(lane.active_workers() == 3);

    lane.set_cap_for_test(2); // below the 3 already running
    auto below = lane.launch([]() -> int { return 0; });
    CHECK(below.status == DetachedLaunch::Rejected);
    CHECK(lane.active_workers() == 3); // not 4: a rejected launch never raised it

    lane.set_cap_for_test(3); // exactly equal to the running count: full
    auto equal = lane.launch([]() -> int { return 0; });
    CHECK(equal.status == DetachedLaunch::Rejected);
    CHECK(lane.active_workers() == 3);

    lane.set_cap_for_test(4); // one slot free again
    CHECK(rig.launch_parked() == DetachedLaunch::Launched);
    CHECK(lane.active_workers() == 4);
    CHECK(rig.f3->load() == 4);
}
