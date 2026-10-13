// test_guardian_outbox_send_executor.cpp - direct, isolated coverage of
// GuardianOutboxSendExecutor (#2233 item 4), independent of GuardianOutboxDrainWorker's
// own call graph. Fast and deterministic: every "stall" here is a test-controlled
// condition_variable, never a real network wait.

#include "guardian_outbox_send_executor.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

using namespace yuzu::agent;
using namespace std::chrono_literals;

using yuzu::test::ScopeExit;
using yuzu::test::spin_until;

namespace {

OutboxEntry lifecycle_entry(const std::string& event_id) {
    return OutboxEntry::lifecycle("r1", /*generation=*/1, event_id,
                                  /*enqueued_ns=*/1'700'000'000'000'000'000, "armed");
}

/// A send that blocks until release() is called, then returns `result`.
struct StallingSend {
    std::mutex mu;
    std::condition_variable cv;
    bool release_flag{false};
    std::atomic<int> invocations{0};
    SendResult result{SendResult::Sent};

    SendResult operator()(const OutboxEntry&) {
        invocations.fetch_add(1);
        std::unique_lock<std::mutex> lk{mu};
        cv.wait(lk, [&] { return release_flag; });
        return result;
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk{mu};
            release_flag = true;
        }
        cv.notify_all();
    }
};

} // namespace

TEST_CASE("offer() completes synchronously for a fast send", "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    auto instant = [](const OutboxEntry&) -> SendResult { return SendResult::Sent; };
    auto result = exec.offer(entry, instant, 200ms);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Sent);
    // done=true publishes before AliveTicket's destructor decrements worker_count (the
    // worker still has to notify_all + return + let its captures unwind), so a
    // same-thread check right after offer() observes done can race worker_count still
    // reading 1 - spin_until it, matching every other active_worker_count()==0 check in
    // this file (empirically confirmed flaky without this: governance Gate 4 happy-path).
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("offer() returns nullopt while the send is still stalled, then the result once released",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    auto entry = lifecycle_entry("e1");

    auto first = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(first.has_value()); // still running
    CHECK(spin_until([&] { return send.invocations.load() >= 1; }));

    // Re-offering the SAME entry does not resubmit - single-flight.
    auto second = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(second.has_value());
    CHECK(send.invocations.load() == 1);

    send.release();
    // The next offer() for the SAME entry consumes the published result.
    std::optional<SendResult> consumed;
    REQUIRE(spin_until([&] {
        consumed = exec.offer(entry, std::ref(send), 20ms);
        return consumed.has_value();
    }));
    CHECK(*consumed == SendResult::Sent);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("item 4 regression: a head change during a stall does not wedge the executor "
          "(#3847/#2233 item 4 - both security-guardian and cpp-safety independently found "
          "this in governance review of the fix's first draft)",
          "[spark][guardian][send_executor][chaos]") {
    // This is the exact scenario BOTH reviewers described: entry A's send is still running
    // (a stalled sink) when the log's head changes out from under it - a generation-supersede
    // purge or an ordinary withdrawal, not a rare race. offer() must not wedge on entry B
    // forever just because A's stale event_id will never recur.
    GuardianOutboxSendExecutor exec;
    StallingSend send_a;
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    auto first = exec.offer(entry_a, std::ref(send_a), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send_a.invocations.load() >= 1; })); // A is now stuck

    // The head changed to B while A is still in flight. The orphaned A worker cannot be
    // touched (a second concurrent Write() on the same stream would be wrong); this must
    // Retain, not launch B's send yet, and must NOT invoke B's send function at all.
    std::atomic<int> b_invocations{0};
    auto send_b = [&](const OutboxEntry&) -> SendResult {
        b_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto while_stalled = exec.offer(entry_b, send_b, 20ms);
    REQUIRE(while_stalled.has_value()); // Retain, not "still running" - a mismatch is decided
    CHECK(*while_stalled == SendResult::Retain);
    CHECK(b_invocations.load() == 0); // never touched the orphaned worker's stream

    // Unblock A. THE regression: once A's orphaned worker finishes, offer()ing B again must
    // reclaim the slot and actually launch B - not return Retain forever because "event-a"
    // will never again match a future entry's event_id (each is unique at enqueue).
    send_a.release();
    std::optional<SendResult> b_result;
    REQUIRE(spin_until(
        [&] {
            b_result = exec.offer(entry_b, send_b, 20ms);
            return b_result.has_value() && *b_result == SendResult::Sent;
        },
        3s));
    CHECK(b_invocations.load() == 1);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("a throwing send is re-thrown by the next offer() call, not swallowed as Retain",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    auto throwing = [](const OutboxEntry&) -> SendResult {
        throw std::runtime_error("send boom");
    };
    bool threw = false;
    // The throw may surface on the launching call (fast completion) or a later poll -
    // either is a correct outcome of the bounded wait; only silently mapping it to a
    // plain Retain with no throw at all would be wrong.
    REQUIRE(spin_until([&] {
        try {
            auto r = exec.offer(entry, throwing, 20ms);
            return r.has_value(); // got Sent/Retain with no throw: wrong, but let REQUIRE below catch it
        } catch (const std::runtime_error& e) {
            threw = true;
            CHECK(std::string(e.what()) == "send boom");
            return true;
        }
    }));
    CHECK(threw);
}

TEST_CASE("#4223 regression: the worker relinquishes eptr before scope exit, so a "
          "descheduled worker's cleanup never races the caller's already-finished read",
          "[spark][guardian][send_executor][chaos][tsan]") {
    // Reproduces the exact interleaving TSan caught under CPU starvation, deterministically,
    // via the #4223 test seam rather than relying on OS scheduling luck: park the worker
    // right after it publishes done=true+eptr and calls notify_all() - exactly where a
    // starved worker would be descheduled - until the caller has already consumed the
    // result, rethrown it, and finished reading e.what(). Pre-fix (a COPY into st->eptr at
    // the worker's publish site), the worker still owns a live second reference to the
    // shared exception control block at this point, and releasing the gate lets its local
    // `eptr` destruct - potentially the reference that frees the exception object - with no
    // happens-before edge to the caller's already-completed read (the gate itself is
    // relaxed-only by design; see set_eptr_race_release_gate_for_test()). That is a real
    // TSan-flagged race pre-fix; this test does not itself assert failure (TSan aborts the
    // process on its own report), so it is a no-op assertion on a non-TSan build and a red
    // TSan build is the actual pre-fix signal. Post-fix (std::exchange(eptr, nullptr) at
    // the publish site - see the header's file-scope comment for why plain std::move is
    // NOT sufficient here on every target toolchain), the worker's `eptr` is already
    // empty by the time it reaches the gate, so this passes identically under TSan or not.
    GuardianOutboxSendExecutor exec;
    std::atomic<bool> release_gate{false};
    exec.set_eptr_race_release_gate_for_test(&release_gate);
    // Declared AFTER release_gate/exec so it destructs FIRST on any exit path,
    // including a REQUIRE/CHECK unwind below (#4223 adversarial review, K1/C2-1):
    // release_gate is a stack local the detached worker may still be spinning on
    // (set_eptr_race_release_gate_for_test()'s own documented contract), so a fatal
    // assertion must release + drain the worker before release_gate (or exec) can be
    // destroyed - matches test_thread_pool.cpp's ScopeExit precedent for the same
    // fatal-unwind-vs-parked-worker hazard. CHECK, not REQUIRE, inside it: this may
    // run during unwind, where a second throw would terminate.
    ScopeExit release_on_exit{[&] {
        release_gate.store(true, std::memory_order_relaxed);
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
        exec.set_eptr_race_release_gate_for_test(nullptr);
    }};
    auto entry = lifecycle_entry("e1");
    auto throwing = [](const OutboxEntry&) -> SendResult {
        throw std::runtime_error("send boom #4223");
    };
    bool threw = false;
    REQUIRE(spin_until([&] {
        try {
            auto r = exec.offer(entry, throwing, 20ms);
            return r.has_value();
        } catch (const std::runtime_error& e) {
            threw = true;
            CHECK(std::string(e.what()) == "send boom #4223");
            return true;
        }
    }));
    CHECK(threw);
    // The seam's whole point is that the worker is STILL PARKED on the gate right here -
    // assert that precondition directly (governance Gate 3 quality-engineer finding),
    // not just the absence of a TSan report: without this, a future refactor that
    // relocates or removes the gate check would leave the test silently exercising
    // nothing, passing even under TSan for the wrong reason. Deterministic, no race
    // window: the detached trampoline only decrements worker_count after the worker
    // lambda body returns, which cannot happen while release_gate still reads false.
    CHECK(exec.active_worker_count() == 1);
}

TEST_CASE("item 4 regression: stop() closes the offer()-to-launch() admission race "
          "(adversarial-review C1/F3 finding, found independently by both external reviewers "
          "and missed by every internal governance round)",
          "[spark][guardian][send_executor][chaos]") {
    // offer() decides need_launch=true and releases state_->mu BEFORE calling launch() -
    // a real gap a concurrent stop() can land in. set_pre_launch_race_hook_for_test()
    // fires exactly in that gap, on the SAME calling thread, so this reproduces the race
    // deterministically via call ordering rather than relying on actual thread scheduling.
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };

    exec.set_pre_launch_race_hook_for_test([&] { exec.stop(); });

    auto result = exec.offer(entry, instant, 200ms);
    // launch()'s recheck of state_->stopping under state_->mu must see stop() having
    // already run and bail - `instant` must never be called as a result of THIS call,
    // and offer() must surface the ordinary launch-failed path (Retain), not a
    // spuriously successful send.
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Retain);
    CHECK(invocations.load() == 0);
    // Unlike every other active_worker_count()==0 check in this file, this one does NOT
    // need spin_until: no AliveTicket is ever constructed on this path (the bail-out in
    // launch() precedes it), so there is no worker-thread-exit decrement to race against.
    CHECK(exec.active_worker_count() == 0);
}

TEST_CASE("#3966: admission (in_flight) and the AliveTicket count are one atomic transaction "
          "under stop() - active_worker_count() must not transiently read 0 once admission "
          "is committed",
          "[spark][guardian][send_executor][chaos]") {
    // set_post_admission_race_hook_for_test() fires in the gap between launch()'s
    // bookkeeping lock closing and AliveTicket's own construction - the exact window
    // #3966 reports. On unfixed code the ticket (and therefore active_worker_count()) is
    // not counted yet at that point, even though `stopping` is already true and admission
    // is already committed - the finding's falsified-zero window. On fixed code (the
    // ticket armed inside the SAME locked block as the bookkeeping) this window cannot be
    // observed via this hook at all, since the count is already 1 by the time control
    // reaches a point where a hook could fire after the lock.
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };

    std::size_t observed_count = 999;
    bool observed_stopping_first = false;
    exec.set_post_admission_race_hook_for_test([&] {
        exec.stop();
        observed_count = exec.active_worker_count();
        observed_stopping_first = true;
    });

    auto result = exec.offer(entry, instant, 200ms);

    REQUIRE(observed_stopping_first);
    // The send WAS admitted before stop() ran (unlike the pre-launch race test above) -
    // stop() only prevents a FUTURE launch, so this call still completes normally.
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Sent);
    CHECK(invocations.load() == 1);
    CHECK(observed_count == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3966 fold-in: a refused thread spawn rolls admission back and frees the slot",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec;
    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::SpawnRefused);
    auto entry = lifecycle_entry("e1");
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };

    auto result = exec.offer(entry, instant, 200ms);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Retain);
    CHECK(invocations.load() == 0);
    // Nothing was ever launched on this path - no spin needed.
    CHECK(exec.active_worker_count() == 0);

    // The slot was freed by the rollback: the SAME event_id can now launch for real.
    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::None);
    std::optional<SendResult> retried;
    REQUIRE(spin_until([&] {
        retried = exec.offer(entry, instant, 200ms);
        return retried.has_value();
    }));
    CHECK(*retried == SendResult::Sent);
    CHECK(invocations.load() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3966 fold-in: a thrown bad_alloc during admission rolls back and frees the slot",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec;
    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::Throw);
    auto entry = lifecycle_entry("e1");
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };

    auto result = exec.offer(entry, instant, 200ms);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Retain);
    CHECK(invocations.load() == 0);
    CHECK(exec.active_worker_count() == 0);

    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::None);
    std::optional<SendResult> retried;
    REQUIRE(spin_until([&] {
        retried = exec.offer(entry, instant, 200ms);
        return retried.has_value();
    }));
    CHECK(*retried == SendResult::Sent);
    CHECK(invocations.load() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3966 fold-in: a thrown bad_alloc at the EARLIEST admission point (before any "
          "State mutation, before the ticket is armed) also rolls back cleanly",
          "[spark][guardian][send_executor][chaos]") {
    // Distinct from the sibling test above: LaunchFaultForTest::Throw fires AFTER
    // ticket->arm() and the worker lambda are already built, exercising the ARMED
    // rollback (the ticket's own decrement). This fires right after the `stopping`
    // recheck, before state_->in_flight_event_id is even written - the region the
    // surrounding launch() comment calls "the ONE throwing step, FIRST" - exercising
    // the UNARMED rollback (the ticket's no-op destructor) instead. No observable
    // difference in outcome versus the sibling test is expected or asserted here (the
    // surrounding try/catch's rollback is uniform regardless of exactly where within
    // the guarded region a throw lands) - this exists for direct coverage of the
    // earlier point, not because a defect was found there.
    GuardianOutboxSendExecutor exec;
    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::ThrowBeforeCommit);
    auto entry = lifecycle_entry("e1");
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };

    auto result = exec.offer(entry, instant, 200ms);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Retain);
    CHECK(invocations.load() == 0);
    CHECK(exec.active_worker_count() == 0); // no thread was ever spawned - no spin needed

    exec.set_launch_fault_for_test(GuardianOutboxSendExecutor::LaunchFaultForTest::None);
    std::optional<SendResult> retried;
    REQUIRE(spin_until([&] {
        retried = exec.offer(entry, instant, 200ms);
        return retried.has_value();
    }));
    CHECK(*retried == SendResult::Sent);
    CHECK(invocations.load() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 3: has_in_flight_send() reads true for a mismatched orphan too, "
          "not only the same-entry timeout case",
          "[spark][guardian][send_executor][chaos]") {
    // wrapped_send()'s `.value_or(SendResult::Retain)` collapses the same-entry-timeout
    // case (offer() returns nullopt) and the mismatched-orphan-still-running case
    // (offer() returns a POPULATED Retain) to the identical value - the caller cannot
    // tell them apart from the return alone. has_in_flight_send() must read true in
    // BOTH, since in_flight is set for whichever entry currently owns the slot.
    GuardianOutboxSendExecutor exec;
    StallingSend send_a;
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    auto first = exec.offer(entry_a, std::ref(send_a), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send_a.invocations.load() >= 1; }));
    CHECK(exec.has_in_flight_send()); // same-entry timeout case

    // The head changed to B while A is still in flight - the mismatch/orphan branch.
    auto while_stalled = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
    REQUIRE(while_stalled.has_value());
    CHECK(*while_stalled == SendResult::Retain);
    CHECK(exec.has_in_flight_send()); // mismatched-orphan-still-running case, too

    send_a.release();
    // Drain the reclaim + a fresh launch for B to completion so the test frame doesn't
    // outlive a detached worker.
    std::optional<SendResult> b_result;
    REQUIRE(spin_until(
        [&] {
            b_result = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
            return b_result.has_value() && *b_result == SendResult::Sent;
        },
        3s));
    // The real property this test's earlier vacuous predicate meant to assert
    // (quality-engineer review): once B's send has actually completed, the slot has
    // cleared - has_in_flight_send() must read false, not merely "invocations >= 1"
    // (which was already REQUIRE'd true above and never decreases).
    CHECK_FALSE(exec.has_in_flight_send());
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 1: a reclaimed orphan's thrown exception is counted, not just "
          "silently discarded",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send_a;
    send_a.result = SendResult::Sent; // unused: A throws instead, see below
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    // A's send throws once released, instead of returning a SendResult.
    std::atomic<bool> a_release{false};
    std::mutex a_mu;
    std::condition_variable a_cv;
    auto throwing_a = [&](const OutboxEntry&) -> SendResult {
        std::unique_lock<std::mutex> lk{a_mu};
        a_cv.wait(lk, [&] { return a_release.load(); });
        throw std::runtime_error("orphan boom");
    };

    auto first = exec.offer(entry_a, throwing_a, 20ms);
    CHECK_FALSE(first.has_value());

    // Head changes to B while A is still running - the mismatch/orphan branch.
    auto while_stalled = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
    REQUIRE(while_stalled.has_value());
    CHECK(*while_stalled == SendResult::Retain);
    CHECK(exec.orphan_exception_count() == 0); // not yet reclaimed

    {
        std::lock_guard<std::mutex> lk{a_mu};
        a_release = true;
    }
    a_cv.notify_all();

    // Once A's orphaned worker finishes (with a throw this time), reclaiming it must
    // count the discard - the throw is real evidence of a problem, and silently losing
    // it entirely (as pre-#3953) is a diagnostic-signal narrowing versus pre-item-4
    // behavior (drain_log_unlocked's own catch used to count every such throw).
    std::optional<SendResult> b_result;
    REQUIRE(spin_until(
        [&] {
            b_result = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
            return b_result.has_value() && *b_result == SendResult::Sent;
        },
        3s));
    CHECK(exec.orphan_exception_count() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 2: a same-entry send stalled past the threshold is counted once, "
          "and a recovery log fires on eventual completion",
          "[spark][guardian][send_executor][chaos]") {
    // Threshold is 300ms, not the file's usual 50ms: the very next line's "not yet
    // stalled" check must survive ONE 20ms-bounded offer() call actually taking
    // meaningfully longer than 20ms of wall clock (detached-thread spawn overhead,
    // scheduling jitter) - observed flaking on a loaded macOS CI runner at 50ms
    // (2.5x margin was not enough; 15x is).
    GuardianOutboxSendExecutor exec{300ms};
    StallingSend send;
    auto entry = lifecycle_entry("e1");

    auto first = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(first.has_value());
    CHECK(exec.send_stall_count() == 0); // not stalled yet - under the threshold

    // Repeated 20ms offers on the SAME entry until the threshold is crossed.
    // NON-fatal (CHECK, not REQUIRE): send.release() below MUST run regardless, or the
    // detached worker - still blocked in send.cv.wait() - outlives this stack frame's
    // synchronization primitives once the test function returns.
    CHECK(spin_until([&] {
        exec.offer(entry, std::ref(send), 20ms);
        return exec.send_stall_count() == 1;
    }));
    // Stays 1 across further nullopts - counted once, not once per re-check.
    exec.offer(entry, std::ref(send), 20ms);
    CHECK(exec.send_stall_count() == 1);

    send.release();
    std::optional<SendResult> result;
    CHECK(spin_until([&] {
        result = exec.offer(entry, std::ref(send), 20ms);
        return result.has_value();
    }));
    if (result.has_value())
        CHECK(*result == SendResult::Sent);
    CHECK(exec.send_stall_count() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 2: a send crossing the threshold DURING one bounded wait is still "
          "counted, not only the timeout-gated case",
          "[spark][guardian][send_executor][chaos]") {
    // Proves the unconditional check (right after wait_until, before the done branch),
    // not merely the timeout-gated one: this send finishes just PAST the threshold
    // inside a single offer() call, so `done` is already true by the time offer() would
    // otherwise decide whether to count a stall.
    GuardianOutboxSendExecutor exec{50ms};
    auto entry = lifecycle_entry("e1");
    auto slow_but_completes = [](const OutboxEntry&) -> SendResult {
        std::this_thread::sleep_for(80ms); // sleeps AT LEAST 80ms — over the 50ms threshold
        return SendResult::Sent;
    };

    // The wait is a LIVENESS bound, not a tight one, and that distinction is the
    // point. This case needs the send to cross the 50ms threshold and still
    // finish inside ONE offer() call. sleep_for guarantees the lower half — it
    // sleeps at least 80ms — but nothing guarantees the upper half, because a
    // loaded runner can stretch an 80ms sleep plus a detached-thread spawn past
    // any tight ceiling. At 200ms this failed on macOS CI (PR #4009): offer()
    // timed out, returned nullopt, and REQUIRE(result.has_value()) fired.
    //
    // Widening 200ms to some larger tight number is the fix that does not hold:
    // the sibling case at line ~435 was already widened 50ms -> 300ms for this
    // same reason one day earlier, and this case then flaked anyway. A margin
    // chosen against observed jitter is a bet on the next runner being no
    // slower. So the ceiling is instead set far beyond any scheduling delay,
    // which makes it a bound on the send COMPLETING AT ALL rather than on how
    // quickly: the assertions below still prove exactly what they did (the send
    // completed within one wait, having crossed the threshold), and the only way
    // to fail now is a send that never returns — a real defect, not load.
    // The case still takes ~80ms; the ceiling is never reached in a passing run.
    auto result = exec.offer(entry, slow_but_completes, 30s);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Sent);
    CHECK(exec.send_stall_count() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 2: a mismatched orphan stalled past the threshold is counted too",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec{50ms};
    StallingSend send_a;
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    auto first = exec.offer(entry_a, std::ref(send_a), 20ms);
    CHECK_FALSE(first.has_value());

    // Poll the mismatch branch (offering B) until A - still running, past the
    // threshold - gets counted as stalled BEFORE it is ever released. NON-fatal: A's
    // detached worker is still blocked in send_a.cv.wait() until the release below,
    // which must run regardless of whether the count reaches 1.
    CHECK(spin_until([&] {
        exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
        return exec.send_stall_count() == 1;
    }));

    send_a.release();
    std::optional<SendResult> b_result;
    REQUIRE(spin_until(
        [&] {
            b_result = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 20ms);
            return b_result.has_value() && *b_result == SendResult::Sent;
        },
        3s));
    // A's orphan is reclaimed somewhere in the polling loop above (state_->done becomes
    // true once send_a.release() lets it finish), which now also runs check_stall_locked()
    // (governance Gate 8 unhappy-path finding, this fix round). That reclaim-branch call
    // must be a no-op here - A was already counted by the "still running" poll earlier -
    // so this pins the stall_logged double-count guard actually holds across the two call
    // sites, not just at each one in isolation.
    CHECK(exec.send_stall_count() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3953 item 2 follow-up: an orphan that crosses the stall threshold only AFTER "
          "it stopped being polled 'still running' is still counted at reclaim",
          "[spark][guardian][send_executor][chaos]") {
    // The 'still running' mismatch branch calls check_stall_locked() itself (see the
    // sibling test above), but only when offer() is actually called while the orphan
    // is still in flight. If nothing polls the mismatch branch again before the
    // orphan finishes, the ONLY chance to count its stall is at reclaim time - this
    // pins that the reclaim branch (state_->done already true) also runs the check,
    // rather than only reading a stall_logged flag that a "still running" poll never
    // had the chance to set (governance Gate 6 sre finding: on today's code this
    // orphan is silently, unboundedly undercounted).
    GuardianOutboxSendExecutor exec{50ms};
    StallingSend send_a;
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    auto first = exec.offer(entry_a, std::ref(send_a), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send_a.invocations.load() >= 1; }));

    // Cross the 50ms threshold with NO interim offer() call on any entry - the
    // mismatch branch's own check_stall_locked() must never fire for this orphan.
    std::this_thread::sleep_for(80ms);
    send_a.release();
    // Wait for A's worker to fully finish and tear down WITHOUT ever calling offer()
    // again, which would itself exercise the branch under test.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));

    // The FIRST offer() call for a different entry now reaches the reclaim branch
    // directly - A is a mismatched orphan that is already done.
    auto reclaimed = exec.offer(entry_b, [](const OutboxEntry&) { return SendResult::Sent; }, 200ms);
    REQUIRE(reclaimed.has_value());
    CHECK(*reclaimed == SendResult::Sent);
    CHECK(exec.send_stall_count() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("stop() prevents a new launch but does not disturb one already in flight",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    auto entry = lifecycle_entry("e1");

    auto first = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    exec.stop();
    // Still waits out the ALREADY-launched worker rather than abandoning it.
    auto still_waiting = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(still_waiting.has_value());

    send.release();
    std::optional<SendResult> result;
    REQUIRE(spin_until([&] {
        result = exec.offer(entry, std::ref(send), 20ms);
        return result.has_value();
    }));
    CHECK(*result == SendResult::Sent);

    // A DIFFERENT entry, offered after stop(), is never launched.
    std::atomic<int> b_invocations{0};
    auto send_b = [&](const OutboxEntry&) -> SendResult {
        b_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto after_stop = exec.offer(lifecycle_entry("e2"), send_b, 20ms);
    REQUIRE(after_stop.has_value());
    CHECK(*after_stop == SendResult::Retain);
    CHECK(b_invocations.load() == 0);
}

// ---------------------------------------------------------------------------------------
// #3972/#3980 C2: in-flight snapshot, orphan probe, gated launch, detached-worker role.
// ---------------------------------------------------------------------------------------

namespace {

OutboxEntry stamped_entry(const std::string& event_id, std::uint64_t seq) {
    auto e = lifecycle_entry(event_id);
    e.seq = seq;
    return e;
}

} // namespace

TEST_CASE("#3980 in_flight_snapshot(): idle, running, monotone remaining_to_stall, seq, done",
          "[spark][guardian][send_executor]") {
    // 300ms for the same loaded-runner margin as the sibling stall cases above.
    GuardianOutboxSendExecutor exec{300ms};
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};

    const auto idle = exec.in_flight_snapshot();
    CHECK_FALSE(idle.in_flight);
    CHECK_FALSE(idle.running);
    CHECK_FALSE(idle.stall_counted);
    CHECK(idle.seq == 0);
    CHECK(idle.remaining_to_stall == 0ms);

    auto entry = stamped_entry("e1", 7);
    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value());
    const auto first = exec.in_flight_snapshot();
    CHECK(first.in_flight);
    CHECK(first.running);
    CHECK_FALSE(first.stall_counted);
    CHECK(first.seq == 7);
    CHECK(first.remaining_to_stall > 0ms);
    CHECK(first.remaining_to_stall <= 300ms);

    // Monotone toward 0 while running and uncounted. NON-fatal: the ScopeExit above must
    // run regardless so the parked worker is released.
    auto previous = first.remaining_to_stall;
    CHECK(spin_until([&] {
        const auto s = exec.in_flight_snapshot();
        CHECK(s.remaining_to_stall <= previous);
        previous = s.remaining_to_stall;
        return s.remaining_to_stall == 0ms;
    }));
    // The snapshot is READ-ONLY: crossing the threshold does not count the stall by itself.
    CHECK_FALSE(exec.in_flight_snapshot().stall_counted);
    CHECK(exec.send_stall_count() == 0);

    // Counting happens only via offer()/probe_orphan(); then remaining stays 0.
    const auto counted = exec.probe_orphan(false);
    CHECK(counted.newly_stalled);
    CHECK(counted.snapshot.stall_counted);
    CHECK(counted.snapshot.remaining_to_stall == 0ms);
    CHECK(exec.in_flight_snapshot().remaining_to_stall == 0ms);

    // `running` goes false once the worker published, while in_flight stays true until
    // the result is consumed or reclaimed.
    send.release();
    CHECK(spin_until([&] { return !exec.in_flight_snapshot().running; }));
    const auto done = exec.in_flight_snapshot();
    CHECK(done.in_flight);
    CHECK_FALSE(done.running);
    CHECK(done.seq == 7);
}

TEST_CASE("#3972 in_flight_snapshot(): an unstamped entry (seq 0) reports seq 0",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    auto entry = lifecycle_entry("e1"); // seq defaults to 0
    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value());
    const auto s = exec.in_flight_snapshot();
    CHECK(s.in_flight);
    CHECK(s.running);
    CHECK(s.seq == 0); // never reported as a blocker position
}

TEST_CASE("#3980 probe_orphan(): counts a stall with NO offer() ever called again",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec{300ms};
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    auto entry = lifecycle_entry("e1");

    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value());
    CHECK(exec.offer_calls_for_test() == 1);
    CHECK(exec.send_stall_count() == 0); // under the threshold

    bool saw_newly_stalled = false;
    int newly_stalled_count = 0;
    CHECK(spin_until([&] {
        const auto p = exec.probe_orphan(/*lane_empty=*/false);
        CHECK_FALSE(p.reclaimed); // the send is still running, nothing to reclaim
        if (p.newly_stalled) {
            saw_newly_stalled = true;
            ++newly_stalled_count;
        }
        return exec.send_stall_count() == 1;
    }));
    CHECK(saw_newly_stalled);
    // Counted once, not once per probe.
    CHECK(exec.probe_orphan(false).newly_stalled == false);
    CHECK(newly_stalled_count == 1);
    CHECK(exec.send_stall_count() == 1);
    CHECK(exec.in_flight_snapshot().stall_counted);
    // The probe never goes through offer(): the stall was counted by the probe alone.
    CHECK(exec.offer_calls_for_test() == 1);
    // And a still-running send is never reclaimed, even for an empty lane.
    const auto empty_lane = exec.probe_orphan(/*lane_empty=*/true);
    CHECK_FALSE(empty_lane.reclaimed);
    CHECK(empty_lane.snapshot.in_flight);
}

TEST_CASE("#3980 probe_orphan(): reclaims a done orphan only for an empty lane; a non-empty "
          "lane's done entry is left for offer() to consume",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    auto entry = lifecycle_entry("e1");

    // Nothing in flight: nothing to do.
    const auto idle = exec.probe_orphan(true);
    CHECK_FALSE(idle.reclaimed);
    CHECK_FALSE(idle.newly_stalled);
    CHECK_FALSE(idle.snapshot.in_flight);

    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value());
    send.release();
    REQUIRE(spin_until([&] { return !exec.in_flight_snapshot().running; }));

    // The lane still has a head: the probe MUST NOT reclaim (its result belongs to the head
    // offer() will be called with next); offer() still consumes it as Sent.
    const auto non_empty = exec.probe_orphan(/*lane_empty=*/false);
    CHECK_FALSE(non_empty.reclaimed);
    CHECK(non_empty.snapshot.in_flight);
    CHECK(exec.has_in_flight_send());
    const auto consumed = exec.offer(entry, std::ref(send), 20ms);
    REQUIRE(consumed.has_value());
    CHECK(*consumed == SendResult::Sent);
    CHECK_FALSE(exec.has_in_flight_send());
}

TEST_CASE("#3980 probe_orphan(): an orphan on an emptied lane is reclaimed with no new offer(), "
          "counting a stall first and a thrown result once; the slot then launches again",
          "[spark][guardian][send_executor][chaos]") {
    // 300 ms, like the sibling case above: the "stall not counted yet" check below must survive a
    // 20 ms-bounded offer() taking much longer than 20 ms on a loaded runner, since an offer()
    // that returns past the threshold would count the stall itself.
    GuardianOutboxSendExecutor exec{300ms};
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    // Throws once released, so the reclaim branch's orphan-exception count is exercised
    // through the probe too (one copy of the reclaim logic).
    auto throwing = [&](const OutboxEntry& e) -> SendResult {
        (void)send(e);
        throw std::runtime_error("orphan boom");
    };
    auto entry_a = lifecycle_entry("event-a");

    CHECK_FALSE(exec.offer(entry_a, throwing, 20ms).has_value());
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    // Cross the threshold with the send still running, but do NOT count it yet: the
    // snapshot is read-only, so the stall is still unobserved when the send finishes.
    REQUIRE(spin_until([&] { return exec.in_flight_snapshot().remaining_to_stall == 0ms; }));
    CHECK(exec.send_stall_count() == 0);
    send.release();
    REQUIRE(spin_until([&] { return !exec.in_flight_snapshot().running; }));

    const auto p = exec.probe_orphan(/*lane_empty=*/true);
    CHECK(p.reclaimed);
    CHECK(p.newly_stalled); // check_stall_locked() runs BEFORE the reclaim clears the state
    CHECK_FALSE(p.snapshot.in_flight);
    CHECK(exec.send_stall_count() == 1);
    CHECK(exec.orphan_exception_count() == 1);
    CHECK_FALSE(exec.has_in_flight_send());

    // The slot is free: a fresh entry launches and completes.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    auto fresh = exec.offer(lifecycle_entry("event-b"),
                            [](const OutboxEntry&) { return SendResult::Sent; }, 200ms);
    REQUIRE(fresh.has_value());
    CHECK(*fresh == SendResult::Sent);
    CHECK(exec.send_stall_count() == 1); // not re-counted
}

TEST_CASE("#3980 probe_orphan(): a reclaim never touches worker_count - a done-but-physically-"
          "alive worker still reads as alive (routed clause 4 / F3)",
          "[spark][guardian][send_executor][chaos][tsan]") {
    GuardianOutboxSendExecutor exec;
    std::atomic<bool> release_gate{false};
    exec.set_eptr_race_release_gate_for_test(&release_gate);
    // Same unwind discipline as the #4223 case above: release + drain before release_gate
    // or exec can be destroyed.
    ScopeExit release_on_exit{[&] {
        release_gate.store(true, std::memory_order_relaxed);
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
        exec.set_eptr_race_release_gate_for_test(nullptr);
    }};
    StallingSend send;
    ScopeExit release_send{[&] { send.release(); }}; // destructs BEFORE release_on_exit
    auto entry = lifecycle_entry("e1");

    // The send is CV-parked, so this offer() is deterministically a timeout (nullopt); on
    // release the worker publishes done=true and then parks on the gate while its ticket
    // is still held. Probe BEFORE any consuming offer() so the result is still in the slot.
    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value());
    send.release();
    REQUIRE(spin_until([&] {
        const auto s = exec.in_flight_snapshot();
        return s.in_flight && !s.running;
    }));
    // done, yet the worker thread is physically alive (parked on the gate).
    CHECK(exec.active_worker_count() == 1);

    const auto p = exec.probe_orphan(/*lane_empty=*/true);
    CHECK(p.reclaimed);
    CHECK_FALSE(p.snapshot.in_flight);
    // The slot is reclaimed but the worker is not: no join, no cancel, no decrement.
    CHECK(exec.active_worker_count() == 1);

    release_gate.store(true, std::memory_order_relaxed);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
}

TEST_CASE("#3972 offer(): launch_permitted=false on a NEW entry retains without launching",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    std::atomic<int> invocations{0};
    auto instant = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto entry = lifecycle_entry("e1");

    GuardianOutboxSendExecutor::OfferTrace denied;
    const auto r = exec.offer(entry, instant, 200ms, /*launch_permitted=*/false, &denied);
    REQUIRE(r.has_value());
    CHECK(*r == SendResult::Retain);
    CHECK(denied.launch_denied);
    CHECK_FALSE(denied.launched);
    CHECK(invocations.load() == 0);
    CHECK_FALSE(exec.has_in_flight_send());
    CHECK(exec.active_worker_count() == 0); // no ticket was ever armed

    // Permitted (the default) launches the same entry.
    GuardianOutboxSendExecutor::OfferTrace allowed;
    const auto r2 = exec.offer(entry, instant, 200ms, true, &allowed);
    REQUIRE(r2.has_value());
    CHECK(*r2 == SendResult::Sent);
    CHECK_FALSE(allowed.launch_denied);
    CHECK(allowed.launched);
    CHECK(invocations.load() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("#3972 offer(): the gate never affects the same in-flight entry's wait or consume",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    ScopeExit release_on_exit{[&] {
        send.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    auto entry = lifecycle_entry("e1");

    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms).has_value()); // launched, running
    GuardianOutboxSendExecutor::OfferTrace waiting;
    CHECK_FALSE(exec.offer(entry, std::ref(send), 20ms, /*launch_permitted=*/false, &waiting)
                    .has_value()); // still waits (nullopt), not a Retain-by-denial
    CHECK_FALSE(waiting.launch_denied);
    CHECK_FALSE(waiting.launched);
    CHECK(send.invocations.load() == 1);

    send.release();
    GuardianOutboxSendExecutor::OfferTrace consuming;
    std::optional<SendResult> consumed;
    REQUIRE(spin_until([&] {
        consumed = exec.offer(entry, std::ref(send), 20ms, false, &consuming);
        return consumed.has_value();
    }));
    CHECK(*consumed == SendResult::Sent);
    CHECK_FALSE(consuming.launch_denied);
}

TEST_CASE("#3972 offer(): the gate never affects a done orphan's reclaim; only the launch after "
          "it is gated",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send_a;
    ScopeExit release_on_exit{[&] {
        send_a.release();
        CHECK(spin_until([&] { return exec.active_worker_count() == 0; }, 3s));
    }};
    auto entry_a = lifecycle_entry("event-a");
    std::atomic<int> b_invocations{0};
    auto send_b = [&](const OutboxEntry&) -> SendResult {
        b_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto entry_b = lifecycle_entry("event-b");

    CHECK_FALSE(exec.offer(entry_a, std::ref(send_a), 20ms).has_value());
    send_a.release();
    REQUIRE(spin_until([&] { return !exec.in_flight_snapshot().running; }));

    GuardianOutboxSendExecutor::OfferTrace trace;
    const auto r = exec.offer(entry_b, send_b, 200ms, /*launch_permitted=*/false, &trace);
    REQUIRE(r.has_value());
    CHECK(*r == SendResult::Retain);
    CHECK(trace.launch_denied); // the reclaim ran, then the NEW launch was denied
    CHECK(b_invocations.load() == 0);
    CHECK_FALSE(exec.has_in_flight_send()); // orphan reclaimed despite the gate

    GuardianOutboxSendExecutor::OfferTrace allowed;
    const auto r2 = exec.offer(entry_b, send_b, 200ms, true, &allowed);
    REQUIRE(r2.has_value());
    CHECK(*r2 == SendResult::Sent);
    CHECK_FALSE(allowed.launch_denied);
    CHECK(b_invocations.load() == 1);
}

TEST_CASE("#3980 offer_calls_for_test() counts every offer() entry, including denied and "
          "mismatch-retain calls",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    CHECK(exec.offer_calls_for_test() == 0);
    auto instant = [](const OutboxEntry&) -> SendResult { return SendResult::Sent; };
    (void)exec.offer(lifecycle_entry("e1"), instant, 200ms, /*launch_permitted=*/false);
    CHECK(exec.offer_calls_for_test() == 1);
    (void)exec.offer(lifecycle_entry("e1"), instant, 200ms);
    CHECK(exec.offer_calls_for_test() == 2);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("R5: the detached send worker wears GuardianDetachedWorkerRole; the caller does not",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    std::atomic<int> role_inside_send{-1};
    auto probe_role = [&](const OutboxEntry&) -> SendResult {
        role_inside_send.store(on_guardian_detached_worker_thread() ? 1 : 0);
        return SendResult::Sent;
    };
    auto entry = lifecycle_entry("e1");

    CHECK_FALSE(on_guardian_detached_worker_thread()); // the offering thread
    std::optional<SendResult> r;
    REQUIRE(spin_until([&] {
        r = exec.offer(entry, probe_role, 200ms);
        return r.has_value();
    }));
    CHECK(*r == SendResult::Sent);
    CHECK(role_inside_send.load() == 1);
    CHECK_FALSE(on_guardian_detached_worker_thread()); // still unmarked after offer() returns
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("R5: a throwing send under the detached-worker marker is re-thrown to the caller, "
          "and neither thread is left marked",
          "[spark][guardian][send_executor][chaos]") {
    GuardianOutboxSendExecutor exec;
    std::atomic<int> role_inside_send{-1};
    auto throwing = [&](const OutboxEntry&) -> SendResult {
        role_inside_send.store(on_guardian_detached_worker_thread() ? 1 : 0);
        throw std::runtime_error("marked boom");
    };
    auto entry = lifecycle_entry("e1");

    CHECK_FALSE(on_guardian_detached_worker_thread());
    bool rethrown = false;
    REQUIRE(spin_until([&] {
        try {
            (void)exec.offer(entry, throwing, 200ms);
        } catch (const std::runtime_error&) {
            rethrown = true;
        }
        return rethrown;
    }));
    CHECK(role_inside_send.load() == 1);                // the throw happened under the marker
    CHECK_FALSE(on_guardian_detached_worker_thread());  // and never leaked onto the caller
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));

    // The marker is a one-shot thread-local on a fresh detached thread per launch, so a later
    // launch cannot inherit anything from the throwing one: it is marked on its own.
    std::atomic<int> second_role{-1};
    auto probe_role = [&](const OutboxEntry&) -> SendResult {
        second_role.store(on_guardian_detached_worker_thread() ? 1 : 0);
        return SendResult::Sent;
    };
    std::optional<SendResult> r;
    REQUIRE(spin_until([&] {
        r = exec.offer(lifecycle_entry("e2"), probe_role, 200ms);
        return r.has_value();
    }));
    CHECK(*r == SendResult::Sent);
    CHECK(second_role.load() == 1);
    CHECK(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("R5: GuardianDetachedWorkerRole clears on every exit path, including an unwinding throw",
          "[spark][guardian][send_executor]") {
    // The RAII marker itself, on a thread of its own so a failure cannot leak into the runner's
    // threads: set inside the scope, cleared after a normal exit, cleared after an exception
    // unwinds through it.
    std::atomic<int> inside{-1}, after_normal{-1}, after_throw{-1}, thrown{0};
    std::thread t([&] {
        {
            const GuardianDetachedWorkerRole role;
            inside.store(on_guardian_detached_worker_thread() ? 1 : 0);
        }
        after_normal.store(on_guardian_detached_worker_thread() ? 1 : 0);
        try {
            const GuardianDetachedWorkerRole role;
            throw std::runtime_error("unwind");
        } catch (const std::runtime_error&) {
            thrown.store(1);
        }
        after_throw.store(on_guardian_detached_worker_thread() ? 1 : 0);
    });
    t.join();
    CHECK(inside.load() == 1);
    CHECK(after_normal.load() == 0);
    CHECK(thrown.load() == 1);
    CHECK(after_throw.load() == 0);
    CHECK_FALSE(on_guardian_detached_worker_thread());
}

TEST_CASE("destroying the executor while its detached worker is still parked is safe once the "
          "worker is released (State outlives the executor)",
          "[spark][guardian][send_executor][chaos]") {
    // GuardianOutboxSendExecutor has no destructor of its own: the worker holds the shared State
    // and never `this`. Destroy the executor with the worker CV-parked inside send(), release it,
    // and wait for the send capture to be destroyed. ASan/TSan turn any use of a freed executor
    // or State into a failure; a plain run proves the worker still completes its send. The
    // weak_ptr expiring means only that the send capture is destroyed (it is destroyed before
    // the worker's ticket and state reference), not that the worker has finished: the executor
    // cannot be asked once it is gone, and the send capture holds the only strong reference.
    struct Gate {
        std::mutex mu;
        std::condition_variable cv;
        bool open{false};
        std::atomic<int> invocations{0};
    };
    auto gate = std::make_shared<Gate>();
    std::weak_ptr<int> worker_closure; // expires when the send capture is destroyed
    ScopeExit release_on_exit{[&] {
        {
            std::lock_guard<std::mutex> lk{gate->mu};
            gate->open = true;
        }
        gate->cv.notify_all();
        CHECK(spin_until([&] { return worker_closure.expired(); }, 5s));
    }};

    auto exec = std::make_unique<GuardianOutboxSendExecutor>();
    {
        auto sentinel = std::make_shared<int>(0);
        worker_closure = sentinel;
        const GuardianOutboxSendExecutor::SendFn parked = [gate, sentinel = std::move(sentinel)](
                                                              const OutboxEntry&) -> SendResult {
            gate->invocations.fetch_add(1);
            std::unique_lock<std::mutex> lk{gate->mu};
            gate->cv.wait(lk, [&] { return gate->open; });
            return SendResult::Sent;
        };
        CHECK_FALSE(exec->offer(lifecycle_entry("e1"), parked, 20ms).has_value());
    } // `parked` is gone: the worker's send capture holds the only remaining reference to the sentinel
    REQUIRE(spin_until([&] { return gate->invocations.load() == 1; }));
    CHECK_FALSE(worker_closure.expired());
    CHECK(exec->active_worker_count() == 1);

    exec.reset(); // destroyed with the worker alive and parked inside send()

    {
        std::lock_guard<std::mutex> lk{gate->mu};
        gate->open = true;
    }
    gate->cv.notify_all();
    // The worker publishes into the surviving State; the send capture is then destroyed.
    CHECK(spin_until([&] { return worker_closure.expired(); }, 5s));
}
