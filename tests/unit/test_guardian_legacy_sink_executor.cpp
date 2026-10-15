// test_guardian_legacy_sink_executor.cpp - direct, isolated coverage of
// GuardianLegacySinkExecutor (#4783 commit 2), independent of GuardianEngine's own
// call graph (GuardianEngine IS wired to this class in production as of #4783 commit
// 3/4 - see test_guardian_engine_legacy_sink.cpp for that engine-level coverage; this
// file exercises the executor standalone). Fast and deterministic: every
// "stall"/"block" here is a test-controlled condition_variable, never a real
// network wait.

#include "guardian_legacy_sink_executor.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

using namespace yuzu::agent;
using namespace std::chrono_literals;

using yuzu::test::kSpinScale;
using yuzu::test::ScopeExit;
using yuzu::test::spin_until;

namespace {

using Event = GuardianLegacySinkExecutor::Event;
using OfferOutcome = GuardianLegacySinkExecutor::OfferOutcome;
using LaunchFaultForTest = GuardianLegacySinkExecutor::LaunchFaultForTest;
using AdmissionFaultForTest = GuardianLegacySinkExecutor::AdmissionFaultForTest;
using WorkerFaultForTest = GuardianLegacySinkExecutor::WorkerFaultForTest;
using GapSnapshotEntry = GuardianLegacySinkExecutor::GapSnapshotEntry;
using Snapshot = GuardianLegacySinkExecutor::Snapshot;

Event make_event(const std::string& rule_id, const std::string& event_type,
                 const std::string& guard_type = "file", const std::string& rule_name = "rn") {
    Event ev;
    ev.set_rule_id(rule_id);
    ev.set_event_type(event_type);
    ev.set_guard_type(guard_type);
    ev.set_rule_name(rule_name);
    ev.set_event_id(rule_id + "-" + event_type);
    return ev;
}

/// A use-after-destruction tripwire for the send functors below (#4783).
///
/// EVERY functor in this file is handed to the executor by `std::ref(...)` and
/// then invoked on a DETACHED worker thread, so it MUST outlive the moment that
/// worker drains the queue. The way to get this wrong is declaration order: a
/// functor declared AFTER the `ScopeExit` that releases a blocking send is
/// destroyed FIRST (reverse declaration order), and that ScopeExit then releases
/// the worker straight into a dead object.
///
/// That mistake was fatal on Windows and SILENT on Linux, for a measured reason
/// rather than luck of timing: under MSVC's debug STL (`_ITERATOR_DEBUG_LEVEL=2`,
/// which `buildtype=debug` selects) even an EMPTY std::vector owns one heap block
/// - its `_Container_proxy` - so the destructor frees real memory, the debug CRT
/// dead-fills it, and the next `emplace_back` faults (0xC0000005). Under
/// libstdc++ - and under MSVC's own RELEASE STL - an empty vector owns no
/// allocation at all, its destructor frees nothing, and the identical
/// use-after-destruction appears to work. So the only configuration that
/// reported this bug did so by allocator policy, not by design.
///
/// This check restores a loud, deterministic failure on every platform and
/// buildtype: a destroyed functor's operator() aborts with a specific message
/// instead of quietly corrupting the heap. `std::abort()` rather than a Catch2
/// assertion because it fires on a detached worker and Catch2's assertion macros
/// are not thread-safe. Reading `alive_` after destruction is itself formally UB
/// - but the storage is a still-live stack slot at that point, so it reads the
/// value the destructor wrote, which is precisely the signal wanted here.
struct DestroyedFunctorTripwire {
    DestroyedFunctorTripwire() = default;
    ~DestroyedFunctorTripwire() { alive_.store(false, std::memory_order_relaxed); }
    DestroyedFunctorTripwire(const DestroyedFunctorTripwire&) = delete;
    DestroyedFunctorTripwire& operator=(const DestroyedFunctorTripwire&) = delete;

    /// Call as the FIRST statement of the owning functor's operator().
    void check(const char* what) const {
        if (alive_.load(std::memory_order_relaxed))
            return;
        std::fprintf(stderr,
                     "FATAL: %s::operator() ran AFTER the functor was destroyed. This is a "
                     "declaration-order bug in this test file: a send functor handed to the "
                     "executor by std::ref() is invoked on a DETACHED worker, so it must be "
                     "declared BEFORE (and therefore outlive) the ScopeExit that releases the "
                     "blocking send and drains the queue.\n",
                     what);
        std::fflush(stderr);
        std::abort();
    }

private:
    std::atomic<bool> alive_{true};
};

/// A send that blocks until release() is called, then returns `result`. Mirrors
/// test_guardian_outbox_send_executor.cpp's StallingSend.
struct StallingSend {
    std::mutex mu;
    std::condition_variable cv;
    bool release_flag{false};
    std::atomic<int> invocations{0};
    LegacySendOutcome result{LegacySendOutcome::Sent};
    /// Declared LAST so it is destroyed FIRST among the members - `alive_` is
    /// already false by the time any member the send path touches is torn down.
    DestroyedFunctorTripwire tripwire;

    LegacySendOutcome operator()(const Event&) {
        tripwire.check("StallingSend");
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

/// A send that records every invocation (rule_id, event_type) in order, thread-safely,
/// and returns a fixed outcome. Used for the FIFO/ordering tests.
struct RecordingSend {
    std::mutex mu;
    std::vector<std::pair<std::string, std::string>> invocations;
    LegacySendOutcome result{LegacySendOutcome::Sent};
    /// Declared LAST - see StallingSend::tripwire.
    DestroyedFunctorTripwire tripwire;

    LegacySendOutcome operator()(const Event& ev) {
        tripwire.check("RecordingSend");
        std::lock_guard<std::mutex> lk{mu};
        invocations.emplace_back(ev.rule_id(), ev.event_type());
        return result;
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lk{mu};
        return invocations.size();
    }
};

/// A send that records every invocation's rule_id in order, thread-safely, and
/// returns WriteFailed for any rule_id in `fail_ids`, Sent otherwise. Used by the
/// #4783 Gate 4 UP-2 rotation tests to simulate a chronically-failing rule mixed
/// in among rules that repair successfully first try.
struct MixedOutcomeSend {
    std::mutex mu;
    std::vector<std::string> invocations;
    std::set<std::string> fail_ids;
    /// Declared LAST - see StallingSend::tripwire.
    DestroyedFunctorTripwire tripwire;

    LegacySendOutcome operator()(const Event& ev) {
        tripwire.check("MixedOutcomeSend");
        std::lock_guard<std::mutex> lk{mu};
        invocations.push_back(ev.rule_id());
        return fail_ids.count(ev.rule_id()) ? LegacySendOutcome::WriteFailed
                                            : LegacySendOutcome::Sent;
    }
};

/// Zero-padded "r000".."r099"-shaped rule_id, so lexicographic string order
/// matches numeric order - used by the #4783 Gate 4 UP-2 rotation tests so the
/// rule_id tie-break in gapped_rules_needing_repair()'s sort is predictable.
std::string padded_rule_id(int i) {
    std::string n = std::to_string(i);
    return "r" + std::string(3 - n.size(), '0') + n;
}

/// Runs `fn` on a detached helper thread and requires it to complete within
/// `timeout` (sanitizer-scaled, matching spin_until's convention). If `fn` never
/// returns - a suspected self-deadlock in the code under test, not an ordinary
/// test failure - this logs via spdlog::critical and std::abort()s, so CI reports
/// a clean, diagnosable crash rather than relying on meson's outer `timeout:` to
/// silently kill the whole binary with nothing to point at (matches this repo's
/// WorkerHostileMutex "crash with a diagnostic beats a silent kill" posture). The
/// helper thread is intentionally leaked/detached on the failure path: if `fn()`
/// truly never returns, the process is about to abort() anyway.
void require_completes_within(std::chrono::milliseconds timeout, const char* what,
                              std::function<void()> fn) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread t([fn = std::move(fn), done]() mutable {
        fn();
        done->store(true, std::memory_order_release);
    });
    t.detach();
    const auto deadline = std::chrono::steady_clock::now() + timeout * kSpinScale;
    while (!done->load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            try {
                spdlog::critical("test watchdog: '{}' did not complete within {}ms - "
                                 "suspected hang/deadlock in the code under test",
                                 what, timeout.count());
            } catch (...) {
            }
            std::abort();
        }
        std::this_thread::sleep_for(1ms);
    }
}

} // namespace

TEST_CASE("offer() delivers a fast send and physical count returns to 0",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("r1", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    auto s = exec.stats();
    CHECK(s.events_lost == 0);
    CHECK(s.send_failures == 0);
}

TEST_CASE("a blocked send is observable via has_in_flight_send() and active_worker_count()",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    auto outcome = exec.offer(make_event("r1", "drift.detected"), std::ref(send));
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    CHECK(exec.has_in_flight_send());
    CHECK(exec.active_worker_count() == 1);
}

TEST_CASE("FIFO: A-drift, A-compliant, A-drift are delivered in admission order, "
          "never coalesced",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send;

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "guard.compliant"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send.count() == 3; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 3);
    CHECK(send.invocations[0] == std::pair<std::string, std::string>{"A", "drift.detected"});
    CHECK(send.invocations[1] == std::pair<std::string, std::string>{"A", "guard.compliant"});
    CHECK(send.invocations[2] == std::pair<std::string, std::string>{"A", "drift.detected"});
}

TEST_CASE("mixed rules interleaved keep each rule's own event ordering",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send;

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "guard.compliant"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "drift.remediated"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "guard.unhealthy"), std::ref(send)) == OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send.count() == 4; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 4);
    // Overall admission order preserved (single FIFO queue, no per-rule reordering).
    CHECK(send.invocations[0] == std::pair<std::string, std::string>{"A", "drift.detected"});
    CHECK(send.invocations[1] == std::pair<std::string, std::string>{"B", "guard.compliant"});
    CHECK(send.invocations[2] == std::pair<std::string, std::string>{"A", "drift.remediated"});
    CHECK(send.invocations[3] == std::pair<std::string, std::string>{"B", "guard.unhealthy"});
}

TEST_CASE("count-bound refusal counts, gaps, and leaves earlier events untouched",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    // First offer is admitted and immediately picked up by the worker (blocked in
    // the send), so the queue is empty again by the time the second offer checks
    // the bound - spin until the worker has actually dequeued it before offering
    // the second event, or the count bound never actually triggers.
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    // Now queue capacity is exhausted by a second event sitting in the (max_events=1)
    // queue while A is in flight; a THIRD offer must be refused.
    CHECK(exec.offer(make_event("B", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);
    auto refused = exec.offer(make_event("C", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto s = exec.stats();
    CHECK(s.backpressure_drops == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "C");
}

TEST_CASE("bytes-bound refusal counts, gaps, and leaves earlier events untouched",
          "[guardian][legacy_sink]") {
    Event probe = make_event("A", "drift.detected");
    const auto one_event_bytes = probe.ByteSizeLong();

    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 100;
    cfg.max_bytes = one_event_bytes; // room for exactly one queued event
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    CHECK(exec.offer(make_event("B", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);
    auto refused = exec.offer(make_event("C", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto s = exec.stats();
    CHECK(s.backpressure_drops == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
}

TEST_CASE("admission-fault injection (ThrowOnTicket) refuses admission, leaves state "
          "unchanged, records a gap, and the next ordinary offer succeeds",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnTicket);

    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::RefusedAdmission);
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.active_worker_count() == 0);
    auto s = exec.stats();
    CHECK(s.admission_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);

    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("admission-fault injection (ThrowOnNode) refuses admission, leaves state "
          "unchanged, records a gap, and the next ordinary offer succeeds",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnNode);

    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::RefusedAdmission);
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.active_worker_count() == 0);
    auto s = exec.stats();
    CHECK(s.admission_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);

    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("launch retry: a same-key repeat offer relaunches after SpawnRefused",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    auto first = exec.offer(make_event("A", "drift.detected"),
                            [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(first == OfferOutcome::Queued);
    // The launch failed - nothing is running, but the item stays queued.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);
    CHECK(exec.stats().launch_failures >= 1);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    RecordingSend send;
    // Same key ("A") offered again - launch eligibility is re-evaluated on THIS
    // offer's own outcome regardless of key. This second offer's own event is
    // what drains via `send`; the first (stranded) item drains via its own
    // lambda, ahead of it in FIFO order.
    auto second = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(second == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.pending_count_for_test() == 0); // both items (stranded + this one) drained
}

TEST_CASE("launch retry: a capacity-refused offer still relaunches the stranded worker",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    auto first = exec.offer(make_event("A", "drift.detected"),
                            [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(first == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);

    // Queue is now full (max_events=1) - this offer is refused on capacity, but
    // launch eligibility is STILL evaluated for it (property 3: "regardless of
    // outcome").
    auto refused = exec.offer(make_event("B", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    // A THIRD offer, still refused on capacity (queue still full of A), must
    // relaunch the worker that will drain A.
    RecordingSend send;
    auto refused2 = exec.offer(make_event("C", "drift.detected"), std::ref(send));
    CHECK(refused2 == OfferOutcome::RefusedCapacity);
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.pending_count_for_test() == 0);
}

TEST_CASE("launch retry: kick() alone relaunches a stranded queue with zero new offers",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    RecordingSend send;
    auto first = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(first == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);
    CHECK(send.count() == 0); // never launched

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick(); // no new offer() call at all
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("B offered while A's launch is still outstanding does not double-launch, "
          "and both drain once the retried launch succeeds",
          "[guardian][legacy_sink][chaos]") {
    // Design note (documented per the task instructions - the delivery plan's
    // §3.1 sketch does not spell out a mechanism for this specific interleaving):
    // set_pre_launch_race_hook_for_test() fires on the calling thread, with
    // state_->mu NOT held, right before attempt_launch()'s actual spawn attempt -
    // i.e. exactly in the window the plan describes as "A's launch outstanding".
    // The hook synchronously offers B from inside A's own offer() call, so B's
    // offer() observes worker_running already true (set by A's offer before
    // releasing the lock) and simply enqueues without attempting a second launch -
    // deterministic via call ordering, no real thread race needed.
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);
    RecordingSend send;

    bool hook_fired = false;
    exec.set_pre_launch_race_hook_for_test([&] {
        hook_fired = true;
        auto outcome = exec.offer(make_event("B", "drift.detected"), std::ref(send));
        // B must be queued (not itself attempt a launch - if it did, and launch
        // is still faulted, it would just also fail harmlessly, but the point of
        // this test is that it does not need to: worker_running is already true).
        CHECK(outcome == OfferOutcome::Queued);
    });

    auto a_outcome = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(a_outcome == OfferOutcome::Queued);
    CHECK(hook_fired);
    exec.set_pre_launch_race_hook_for_test(nullptr);

    // A's launch failed (SpawnRefused); both A and B are stranded in the queue.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 2);
    CHECK(send.count() == 0);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick();
    REQUIRE(spin_until([&] { return send.count() == 2; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 2);
    CHECK(send.invocations[0].first == "A");
    CHECK(send.invocations[1].first == "B");
}

TEST_CASE("stop() discards the backlog (counted) but does not touch an in-flight send",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; })); // A is in flight

    RecordingSend send_b;
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued); // B is queued behind A
    CHECK(exec.pending_count_for_test() == 1);

    require_completes_within(5s, "stop() while a send is in flight", [&] { exec.stop(); });

    auto s = exec.stats();
    CHECK(s.discarded_at_stop == 1); // B was discarded, not sent
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.has_in_flight_send()); // A is untouched by stop()
    CHECK(exec.active_worker_count() == 1);
    CHECK(send_b.count() == 0);

    // A offer after stop() is refused, never queued.
    auto after_stop = exec.offer(make_event("C", "drift.detected"),
                                 [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(after_stop == OfferOutcome::RefusedStopping);
}

TEST_CASE("a worker thread can still be spawned just after stopping() becomes true - "
          "documented safe case, it retires without touching the cleared backlog",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    // Admission committed BEFORE stop(), with the launch itself held back by a
    // SpawnRefused fault - reproducing "admission committed -> stop() -> spawn"
    // deterministically: worker_running is already true and the item is queued,
    // then stop() clears the (already-admitted) backlog, then a later kick()
    // (with the fault cleared) is the "spawn after stopping=true" moment.
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));

    exec.stop();
    CHECK(exec.pending_count_for_test() == 0);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    // kick() itself does not spawn once stopping (worker_running is false but the
    // queue is empty), so directly exercise the actually-interesting case: a
    // worker created after stopping observes stopping+empty and retires cleanly.
    exec.kick();
    CHECK_FALSE(spin_until([&] { return send.count() >= 1; }, 200ms));
    CHECK(exec.active_worker_count() == 0);
}

TEST_CASE("a send already dequeued keeps running to completion after stop() returns",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    require_completes_within(5s, "stop() must not block on an in-flight send",
                             [&] { exec.stop(); });
    CHECK(exec.active_worker_count() == 1); // still counted - not yet retired

    send.release();
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.active_worker_count() == 0);
    // The completion still ran its normal accounting (Sent, no failure counters).
    auto s = exec.stats();
    CHECK(s.send_failures == 0);
    CHECK(s.send_exceptions == 0);
}

TEST_CASE("a quiet, fully-stalled queue (no new offers) is observed via kick()",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.stall_threshold = 30ms;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    CHECK(exec.stats().stalls == 0); // not yet past the threshold

    std::this_thread::sleep_for(60ms * kSpinScale);
    // NO new offer() call anywhere in this test up to this point - kick() is the
    // ONLY thing that can notice the stall.
    exec.kick();
    CHECK(exec.stats().stalls == 1);

    // A second kick() before completion does not double-count.
    exec.kick();
    CHECK(exec.stats().stalls == 1);
}

TEST_CASE("WriteFailed counts send_failures and records a gap", "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::WriteFailed; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().send_failures == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "A");
    CHECK(gaps[0].second.guard_type == "file");
}

TEST_CASE("LinkDown counts dropped_link_down with NO gap recorded",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::LinkDown; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().dropped_link_down == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.dropped_link_down == 1);
    CHECK(s.events_lost == 0); // NOT a loss - D4b
    CHECK(s.gap_rules == 0);   // NOT a gap - D4b
}

TEST_CASE("a throwing send counts send_exceptions, records a gap, and the worker "
          "continues to the next item",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send_b;
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) -> LegacySendOutcome {
                         throw std::runtime_error("send boom");
                     }) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send_b.count() == 1; })); // worker survived A's throw
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_exceptions == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    CHECK(s.worker_faults == 0); // the send's own throw is caught locally, not a
                                 // whole-iteration fault
}

TEST_CASE("#4783 Gate 3 finding, 2026-09-24: a throw DURING worker_loop's post-pop "
          "item-identity capture still counts as a loss and opens a gap - the item "
          "is never silently dropped uncounted",
          "[guardian][legacy_sink]") {
    // Three independent Gate 3 reviewers (cpp-safety, cpp-expert, security-guardian)
    // converged on the same finding against the ORIGINAL folded-in worker_loop fix:
    // have_unaccounted_item was set AFTER the throw-capable capture copies, not
    // before, reproducing (inside that very fix) the defect class it existed to
    // close. Fixed by setting the flag first. This test proves the fix: a throw
    // injected right after popped_rule_id is captured (the realistic worst case -
    // one capture succeeded, a later one didn't) still reaches the outer catch
    // with have_unaccounted_item already true, so the loss is counted and a gap
    // opens under the CORRECT rule_id (captured before the throw), not dropped.
    GuardianLegacySinkExecutor exec;
    exec.set_worker_fault_for_test(WorkerFaultForTest::ThrowDuringCapture);

    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return exec.stats().send_exceptions == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_exceptions == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1); // NOT 0 - the whole point: this loss is NOT silently
                             // dropped uncounted, unlike the pre-fix defect
    CHECK(s.worker_faults == 1); // the outer catch(...) bumps this unconditionally
                                 // for ANY whole-iteration throw, same as before
                                 // this fix - the new behavior is send_exceptions/
                                 // events_lost/gap_rules ALSO firing, not instead

    // The gap opened under the CORRECT rule_id (captured before the injected
    // throw hit) - confirms popped_rule_id's early-capture placement, not just
    // that *some* gap was recorded.
    auto gaps = exec.all_gaps_for_test();
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "A");

    // Worker survives and continues serving new offers afterward.
    exec.set_worker_fault_for_test(WorkerFaultForTest::None);
    RecordingSend send_b;
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send_b.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("#4783 Gate 4 unhappy-path finding, 2026-09-24: a throw BEFORE any "
          "post-pop capture still counts as a loss globally but does NOT open a "
          "phantom empty-rule_id gap",
          "[guardian][legacy_sink]") {
    // The unhappy-path reviewer traced a real amplification chain from the
    // accepted "misattribution to an empty rule_id" residual: a phantom
    // empty-rule_id GapRecord would (a) never resolve on its own (no real
    // rule is ever named "" - guardian_engine.cpp rejects that at load), (b)
    // enter the normal repair rotation and get dispatched over the wire, and
    // (c) if persisted before it cleared, poison the ENTIRE restart snapshot
    // (read_legacy_sink_loss_record() rejected the whole record on any single
    // empty-rule_id entry - see the sibling engine-level test for that half).
    // Fixed at the root: the catch's record_gap_locked() call is now guarded
    // on a non-empty popped_rule_id. This test proves that guard directly.
    GuardianLegacySinkExecutor exec;
    exec.set_worker_fault_for_test(WorkerFaultForTest::ThrowOnFirstCapture);

    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return exec.stats().send_exceptions == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_exceptions == 1); // the loss IS counted globally...
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 0); // ...but NO gap was opened - no phantom "" entry
    CHECK(exec.all_gaps_for_test().empty());

    // Worker survives and continues serving new offers afterward.
    exec.set_worker_fault_for_test(WorkerFaultForTest::None);
    RecordingSend send_b;
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send_b.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("a gap-ledger fault degrades gap_ledger_degraded instead of crashing the "
          "worker, which continues to the next item",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnGapLedger);

    RecordingSend send_b;
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return exec.stats().send_failures == 1; }));
    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send_b.count() == 1; })); // worker kept going
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.gap_ledger_faults >= 1);
    CHECK(s.gap_rules == 0); // the gap itself never got recorded - the ledger
                             // write is exactly what failed
}

TEST_CASE("ticket rollback on a refused launch has no self-deadlock",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    require_completes_within(5s, "offer() after a SpawnRefused launch rollback", [&] {
        auto outcome = exec.offer(make_event("A", "drift.detected"),
                                  [](const Event&) { return LegacySendOutcome::Sent; });
        CHECK(outcome == OfferOutcome::Queued);
    });
    // If attempt_launch()'s rollback self-deadlocked on the executor's own
    // mutex, THIS call would hang forever - it must be callable immediately.
    require_completes_within(5s, "active_worker_count() right after a SpawnRefused rollback",
                             [&] { CHECK(exec.active_worker_count() == 0); });

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick();
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("gap repair lifecycle: recorded, listed, Sent clears it, anything else "
          "leaves the gap but resets repair_seq to 0",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Create a gap via a WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "A");
    CHECK(gaps[0].second.repair_seq == 0);

    // A repair that fails (WriteFailed again) leaves the gap but resets
    // repair_seq to 0 so the NEXT kick can retry.
    CHECK(exec.offer(make_event("A", "guard.unhealthy"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; },
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().send_failures == 2; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].second.repair_seq == 0);
    CHECK(gaps[0].second.lost == 2);

    // A repair that succeeds (Sent) clears the gap entirely.
    CHECK(exec.offer(make_event("A", "guard.unhealthy"),
                     [](const Event&) { return LegacySendOutcome::Sent; },
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 0; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.gapped_rules_needing_repair(10).empty());
}

// ── #4783 follow-up review: seq-guarded clearing + dequeue-time supersession ─
//
// These four cases prove the fix's parts (a) (seq-guarded clearing) and (b)
// (dequeue-time supersession) at the executor level, independently of one
// another - see this file's own header comment and the class doc comment in
// guardian_legacy_sink_executor.hpp for the full design. Test 1 and test 4
// would each fail under the REJECTED "clear on any Sent" naive fix (part (a)
// alone, without the seq guard); test 3 would fail if supersession were only
// checked at kick/fire time instead of at dequeue (part (b)).

TEST_CASE("#4783 gap: an in-flight OLDER send completing Sent does not clear a "
          "NEWER loss recorded for the same rule while it was still in flight",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend blocking;
    ScopeExit cleanup{[&] {
        blocking.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    // A1: dequeued into flight almost immediately - the queue is empty again by
    // the time A2 is offered.
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(blocking)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return blocking.invocations.load() >= 1; }));

    // A2: admitted into the now-empty (max_events=1) queue - a filler that
    // drains normally once A1 completes.
    RecordingSend filler;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(filler)) ==
         OfferOutcome::Queued);

    // A3: the queue already holds A2 -> refused capacity, opening a gap whose
    // lost_seq is A3's own (newest) admission-time seq.
    auto refused = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto gaps_before = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_before.size() == 1);
    const auto lost_seq_before = gaps_before[0].second.lost_seq;

    // Release A1 - both A1's and A2's Sent completions carry a STRICTLY OLDER
    // seq than A3's refusal, so NEITHER may clear the gap A3 opened. Under the
    // rejected "clear on any Sent" fix, A1 alone (let alone A2) would have
    // erased it here.
    blocking.release();
    REQUIRE(spin_until([&] { return filler.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps_after = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_after.size() == 1);
    CHECK(gaps_after[0].second.lost_seq == lost_seq_before);
    CHECK(gaps_after[0].second.lost == 1); // still just the one recorded loss (A3)
}

TEST_CASE("#4783 gap: a fresh real Sent that postdates the loss clears the gap, "
          "and a subsequent kick() does not resurrect it",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Open a gap for A via a WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // A fresh, ORDINARY (non-repair) event for A that succeeds - its
    // admission-time seq is strictly newer than the loss that opened the gap.
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    CHECK(exec.gapped_rules_needing_repair(10).empty());
    CHECK(exec.stats().gap_rules == 0);

    // kick() must not resurrect a gap a real delivery already closed - it only
    // relaunches a stranded worker / observes a stall, never rebuilds gaps.
    exec.kick();
    CHECK(exec.gapped_rules_needing_repair(10).empty());
    CHECK(exec.stats().gap_rules == 0);
}

TEST_CASE("#4783 gap: a queued repair superseded by a newer real Sent before "
          "reaching the front is suppressed at dequeue, never sent",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Open a gap for A.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // A fresh REAL event for A that will block - dequeued into flight
    // immediately (the queue is otherwise empty).
    StallingSend real_send;
    ScopeExit cleanup{[&] {
        real_send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(real_send)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return real_send.invocations.load() >= 1; }));

    // Queue a repair for A behind the in-flight real event - its repair_seq is
    // stamped as the (currently) live one. #4783 Gate 4 UP-2:
    // gapped_rules_needing_repair() now excludes mid-repair gaps (repair_seq !=
    // 0) - it is production SELECTION, not raw introspection - so checking that
    // exclusion here goes through all_gaps_for_test() instead.
    RecordingSend repair_send;
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(repair_send),
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    auto gaps_mid = exec.all_gaps_for_test();
    REQUIRE(gaps_mid.size() == 1);
    CHECK(gaps_mid[0].second.repair_seq != 0);
    CHECK(exec.gapped_rules_needing_repair(10).empty()); // ineligible - mid-repair

    // Release the real event - it completes Sent with a NEWER seq than the
    // gap's lost_seq, clearing the gap per the previous test's mechanism.
    real_send.release();
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 0; }));

    // The queued repair now reaches the front of the FIFO - the gap it was
    // meant to repair is already gone, so it must be suppressed at dequeue,
    // never actually sent. A kick/fire-time-only check could not have caught
    // this: the repair was already queued (and thus already past any
    // kick-time check) before the real event's Sent cleared the gap.
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(repair_send.count() == 0);
    CHECK(exec.stats().repairs_suppressed == 1);
}

TEST_CASE("#4783 gap: a repair's own Sent does not clear a loss NEWER than the "
          "repair, and resets repair_seq so the next kick requeues a fresh one",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};

    // Open a gap for A via an ordinary WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // Queue a repair R for A - dequeued into flight immediately (queue empty).
    StallingSend blocking_repair;
    ScopeExit cleanup{[&] {
        blocking_repair.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(blocking_repair),
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return blocking_repair.invocations.load() >= 1; }));

    // #4783 Gate 4 UP-2: R is still mid-repair (repair_seq != 0) here, which now
    // makes it ineligible/invisible to gapped_rules_needing_repair() - inspect
    // the raw gap via all_gaps_for_test() instead.
    auto gaps_mid = exec.all_gaps_for_test();
    REQUIRE(gaps_mid.size() == 1);
    REQUIRE(gaps_mid[0].second.repair_seq != 0);
    const auto repair_seq = gaps_mid[0].second.repair_seq;

    // A filler for A, admitted into the now-empty (max_events=1) queue.
    RecordingSend filler;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(filler)) ==
         OfferOutcome::Queued);

    // A fresh real offer for A - the queue is already full (filler) -> refused,
    // bumping lost_seq past R's own seq.
    auto refused = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto gaps_before_release = exec.all_gaps_for_test();
    REQUIRE(gaps_before_release.size() == 1);
    CHECK(gaps_before_release[0].second.lost_seq > repair_seq);

    // Release R - its Sent carries an OLDER seq than the newest loss, so it
    // must NOT clear the gap; the repair itself completed, so repair_seq
    // resets to 0 so the next kick requeues a fresh repair covering the newer
    // loss. Under the rejected "clear on any Sent" fix, this Sent would have
    // erased the gap and silently lost the newer loss's evidence.
    blocking_repair.release();
    REQUIRE(spin_until([&] { return filler.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps_after = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_after.size() == 1);
    CHECK(gaps_after[0].second.repair_seq == 0);
}

TEST_CASE("#4783 adversarial-review finding (2026-09-24): a repair captured for "
          "an OLD loss episode must not bind to / clear a NEWER gap opened for "
          "the same rule after selection - ADMISSION-TIME EPISODE BINDING",
          "[guardian][legacy_sink]") {
    // Reproduces the reported reachable interleaving directly: kick() selects a
    // gap for loss L1 via gapped_rules_needing_repair() (capturing lost_seq),
    // then - before the corresponding offer() ever runs - a real Sent clears
    // that gap outright, and a fresh loss L2 for the SAME rule reopens it. The
    // paused kick's repair for L1 only reaches offer() after all of that. Before
    // the fix, offer()'s is_gap_repair branch stamped repair_seq on whatever gap
    // was live for the rule_id with no check that it was still L1 - and because
    // the repair's own admission seq necessarily postdates L2's lost_seq (offer()
    // always runs after the episode it is racing against), SEQ-GUARDED
    // CLEARING's `it.seq > lost_seq` check passed trivially on a later Sent and
    // silently erased L2, a loss the repair never actually observed.
    GuardianLegacySinkExecutor exec;

    // Episode 1 (L1): open a gap for A.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // legacy_sink_kick()'s own shape: capture the gap's lost_seq via
    // gapped_rules_needing_repair() - what a real kick would build the repair
    // event AND expected_gap_lost_seq from - well BEFORE actually offering it.
    const auto captured = exec.gapped_rules_needing_repair(10);
    REQUIRE(captured.size() == 1);
    REQUIRE(captured[0].first == "A");
    const auto captured_lost_seq = captured[0].second.lost_seq;

    // Before the captured repair is ever offered: episode 1 resolves for real -
    // a genuine Sent clears the gap outright.
    CHECK(exec.offer(make_event("A", "drift.remediated"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 0; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // Episode 2 (L2): a fresh, unrelated loss for the SAME rule reopens the gap.
    // Its lost_seq is necessarily a later seq than L1's (State::next_seq is
    // monotonic across every offer(), admitted or refused, regardless of rule).
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    const auto episode2 = exec.all_gaps_for_test();
    REQUIRE(episode2.size() == 1);
    CHECK(episode2[0].second.lost_seq > captured_lost_seq);
    CHECK(episode2[0].second.repair_seq == 0); // nothing mid-repair yet

    // NOW offer the STALE repair captured back at episode 1, passing the
    // CAPTURED lost_seq as expected_gap_lost_seq, exactly as a delayed
    // legacy_sink_kick() call would.
    RecordingSend stale_repair_send;
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(stale_repair_send),
                     /*is_gap_repair=*/true, captured_lost_seq) == OfferOutcome::Queued);
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // The stale repair must NEVER have been sent - ADMISSION-TIME EPISODE
    // BINDING refused to stamp repair_seq (captured_lost_seq no longer matches
    // the live gap's lost_seq), so DEQUEUE-TIME SUPERSESSION suppressed it
    // before send() ever ran. Episode 2's gap must still be open, still
    // describing episode 2's OWN lost_seq - not silently erased by a repair
    // that never actually observed it.
    CHECK(stale_repair_send.count() == 0);
    CHECK(exec.stats().repairs_suppressed == 1);
    const auto after_stale = exec.all_gaps_for_test();
    REQUIRE(after_stale.size() == 1);
    CHECK(after_stale[0].second.lost_seq == episode2[0].second.lost_seq);
    CHECK(after_stale[0].second.repair_seq == 0);

    // A LIVE (correctly-scoped) repair for episode 2, using ITS OWN lost_seq,
    // still works normally - the fix refuses only a MISMATCHED episode, not gap
    // repair in general.
    RecordingSend live_repair_send;
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(live_repair_send),
                     /*is_gap_repair=*/true, episode2[0].second.lost_seq) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return live_repair_send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.stats().gap_rules == 0); // the live repair correctly cleared it
}

// ── #4783 Gate 4 UP-2: fair, eligibility-filtered gap-repair rotation ───────
//
// gapped_rules_needing_repair()'s selection used to be "the first `max` gaps in
// unordered_map iteration order, unfiltered by repair_seq" - with a STABLE set
// of more than `max` gapped rules, that returned the SAME subset every call
// (bug (a): a fixed subset gets repaired, forever, everything else starves),
// and the caller's own repair_seq filter meant an already-busy kick could offer
// fewer than `max` NEW repairs (bug (b): the cap counted LISTED entries,
// including ones already mid-repair, rather than ELIGIBLE ones). These three
// tests exercise the fix directly against the executor, independently of
// GuardianEngine::legacy_sink_kick() (engine-level coverage is
// test_guardian_engine_legacy_sink.cpp) - each test's own offer()/kick() loop
// mirrors legacy_sink_kick()'s real shape: kick(); take up to the cap from
// gapped_rules_needing_repair(); offer() a repair for each (skipping any with a
// non-zero repair_seq, which is now always a no-op - the eligibility filter
// already excluded those - but is kept here to mirror the real caller exactly).

TEST_CASE("#4783 Gate 4 UP-2: 100 gapped rules rotate fairly across kicks - "
          "every rule is offered a repair exactly once within ceil(100/32)=4 "
          "kicks, none twice before all 100 have had a turn",
          "[guardian][legacy_sink]") {
    constexpr std::size_t kCap = 32; // mirrors kMaxGapRepairsPerKick (guardian_engine.cpp);
                                     // not includable here (guardian_engine.cpp-local),
                                     // hand-kept in sync
    constexpr int kRules = 100;

    GuardianLegacySinkExecutor exec;

    // Open 100 gaps via WriteFailed, sequentially. The single detached worker
    // processes FIFO, so first_lost ends up non-decreasing in the SAME order
    // these are offered (r000..r099) - the rule_id tie-break in
    // gapped_rules_needing_repair()'s sort makes selection deterministic
    // regardless, but this keeps the expected per-kick counts easy to reason
    // about below.
    for (int i = 0; i < kRules; ++i) {
        CHECK(exec.offer(make_event(padded_rule_id(i), "drift.detected"),
                         [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
             OfferOutcome::Queued);
    }
    REQUIRE(
        spin_until([&] { return exec.stats().gap_rules == static_cast<std::size_t>(kRules); }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // Block the single worker on a sentinel rule_id OUTSIDE the 100, so every
    // repair offered below stays QUEUED (never dequeued/sent) for the rest of
    // the selection phase - repair_seq is stamped at OFFER time regardless of
    // when (or whether) the send itself runs, so this keeps every one of the
    // 100 gaps present in the map across all 4 kicks without a Sent repair
    // erasing (and thus trivially "rotating away") a gap before the next kick's
    // selection - which would defeat the point of this test (see the class doc
    // comment's SEQ-GUARDED CLEARING section for why Sent erases a gap outright
    // rather than just clearing repair_seq).
    StallingSend sentinel;
    ScopeExit cleanup{[&] {
        sentinel.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("ZZZ_sentinel", "drift.detected"), std::ref(sentinel)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return sentinel.invocations.load() >= 1; }));

    RecordingSend repair_send;
    std::vector<std::vector<std::string>> offered_per_kick(4);
    for (int k = 0; k < 4; ++k) {
        exec.kick();
        auto gaps = exec.gapped_rules_needing_repair(kCap);
        for (const auto& [rule_id, gap] : gaps) {
            if (gap.repair_seq != 0) // mirrors legacy_sink_kick()'s own guard - now a no-op
                continue;
            CHECK(exec.offer(make_event(rule_id, "guard.unhealthy"), std::ref(repair_send),
                             /*is_gap_repair=*/true) == OfferOutcome::Queued);
            offered_per_kick[k].push_back(rule_id);
        }
    }

    // 32 + 32 + 32 + 4 == 100, and every rule_id appears in exactly one kick's list.
    std::set<std::string> seen;
    std::size_t total = 0;
    for (const auto& v : offered_per_kick) {
        total += v.size();
        for (const auto& rid : v)
            CHECK(seen.insert(rid).second); // false == already seen == offered twice - FAIL
    }
    CHECK(total == static_cast<std::size_t>(kRules));
    CHECK(seen.size() == static_cast<std::size_t>(kRules));
    for (int i = 0; i < kRules; ++i)
        CHECK(seen.count(padded_rule_id(i)) == 1);
    CHECK(offered_per_kick[0].size() == kCap);
    CHECK(offered_per_kick[1].size() == kCap);
    CHECK(offered_per_kick[2].size() == kCap);
    CHECK(offered_per_kick[3].size() == static_cast<std::size_t>(kRules) - 3 * kCap);

    // Release the sentinel: all 100 queued repairs now drain and succeed.
    sentinel.release();
    REQUIRE(spin_until([&] { return repair_send.count() == static_cast<std::size_t>(kRules); }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.stats().gap_rules == 0); // every repair's own seq postdated its rule's loss
}

TEST_CASE("#4783 Gate 4 UP-2: a chronically-failing rule does not starve the "
          "other 95 gapped rules, and is retried only after all 95 have had "
          "their own turn",
          "[guardian][legacy_sink]") {
    constexpr std::size_t kCap = 32; // mirrors kMaxGapRepairsPerKick
    constexpr int kRules = 100;
    const std::set<std::string> failing = {padded_rule_id(0), padded_rule_id(1),
                                           padded_rule_id(2), padded_rule_id(3),
                                           padded_rule_id(4)};

    GuardianLegacySinkExecutor exec;

    for (int i = 0; i < kRules; ++i) {
        CHECK(exec.offer(make_event(padded_rule_id(i), "drift.detected"),
                         [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
             OfferOutcome::Queued);
    }
    REQUIRE(
        spin_until([&] { return exec.stats().gap_rules == static_cast<std::size_t>(kRules); }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // Unlike the rotation test above, repairs here are allowed to actually
    // drain BETWEEN kicks - a WriteFailed repair must reset repair_seq to 0
    // (become eligible again) for the starvation-avoidance property to be
    // exercised at all; a permanently-stalled queue would never let that happen.
    MixedOutcomeSend send;
    send.fail_ids = failing;

    std::vector<std::string> offer_log; // global order, across all 4 kicks
    for (int k = 0; k < 4; ++k) {
        exec.kick();
        auto gaps = exec.gapped_rules_needing_repair(kCap);
        for (const auto& [rule_id, gap] : gaps) {
            if (gap.repair_seq != 0)
                continue;
            CHECK(exec.offer(make_event(rule_id, "guard.unhealthy"), std::ref(send),
                             /*is_gap_repair=*/true) == OfferOutcome::Queued);
            offer_log.push_back(rule_id);
        }
        REQUIRE(exec.wait_workers_retired_for_test(5s));
    }

    // Every one of the 100 rule_ids was offered at least once; the 5 failing
    // ones were offered exactly twice (the initial attempt plus one retry),
    // every other rule exactly once.
    std::map<std::string, int> offer_count;
    for (const auto& rid : offer_log)
        ++offer_count[rid];
    REQUIRE(offer_count.size() == static_cast<std::size_t>(kRules));
    for (int i = 0; i < kRules; ++i) {
        const auto rid = padded_rule_id(i);
        CHECK(offer_count[rid] == (failing.count(rid) ? 2 : 1));
    }

    // The 95 non-failing rules each complete within the 4 kicks; the 5 failing
    // ones are retried only AFTER every one of the 95 has already been offered
    // its (successful) repair - i.e. in global offer order, the LAST first-time
    // offer of a non-failing rule precedes the SECOND offer of every failing one.
    std::size_t last_non_failing_index = 0;
    std::vector<std::size_t> failing_retry_index;
    std::map<std::string, int> seen_so_far;
    for (std::size_t idx = 0; idx < offer_log.size(); ++idx) {
        const auto& rid = offer_log[idx];
        const int occurrence = ++seen_so_far[rid];
        if (failing.count(rid) != 0) {
            if (occurrence == 2)
                failing_retry_index.push_back(idx);
        } else {
            last_non_failing_index = idx; // every non-failing id is offered exactly once
        }
    }
    REQUIRE(failing_retry_index.size() == failing.size());
    for (auto idx : failing_retry_index)
        CHECK(idx > last_non_failing_index);

    CHECK(exec.stats().gap_rules == failing.size()); // only the 5 chronic failures remain open
    auto remaining = exec.all_gaps_for_test();
    std::set<std::string> remaining_ids;
    for (const auto& [rid, gap] : remaining)
        remaining_ids.insert(rid);
    CHECK(remaining_ids == failing);
}

TEST_CASE("#4783 Gate 4 UP-2: the repair cap applies to ELIGIBLE gaps only - 20 "
          "of 40 already mid-repair still yields exactly 20 NEW offers, not 12 "
          "(the old cap-counts-listed-entries bug) and not 40 (cap ignored)",
          "[guardian][legacy_sink]") {
    constexpr std::size_t kCap = 32; // mirrors kMaxGapRepairsPerKick
    constexpr int kRules = 40;
    constexpr int kAlreadyMidRepair = 20;

    GuardianLegacySinkExecutor exec;

    for (int i = 0; i < kRules; ++i) {
        CHECK(exec.offer(make_event(padded_rule_id(i), "drift.detected"),
                         [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
             OfferOutcome::Queued);
    }
    REQUIRE(
        spin_until([&] { return exec.stats().gap_rules == static_cast<std::size_t>(kRules); }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // DECLARATION ORDER IS LOAD-BEARING (#4783). `repair_send` is handed to the
    // executor below by std::ref() and, unlike every other test in this file,
    // the 20 items holding that reference are still QUEUED when this TEST_CASE's
    // scope exits - nothing here drains them first, because the point of the
    // test is that they stay mid-repair. `cleanup` then releases the sentinel
    // and waits for the worker to retire, which drains all 20 through
    // `repair_send`. So `repair_send` must be declared BEFORE `sentinel`/
    // `cleanup` in order to be destroyed AFTER them (reverse declaration order).
    // Declared the other way round it was destroyed first and the worker called
    // into a dead object - silent on libstdc++, a hard 0xC0000005 on the MSVC
    // debug STL; see DestroyedFunctorTripwire's own comment for the measured
    // reason those two platforms disagreed. `cleanup` itself deliberately stays
    // immediately after `sentinel`, BEFORE the offer() that blocks the worker,
    // so an early REQUIRE failure still releases a worker parked in cv.wait()
    // rather than destroying the StallingSend underneath it.
    RecordingSend repair_send;

    // Block the worker so every repair offered below stays queued (mid-repair,
    // repair_seq != 0) for the rest of the test - it must never actually
    // complete, or it would clear its own eligibility state the normal way
    // rather than via the explicit already-in-flight setup this test is for.
    StallingSend sentinel;
    ScopeExit cleanup{[&] {
        sentinel.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("ZZZ_sentinel", "drift.detected"), std::ref(sentinel)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return sentinel.invocations.load() >= 1; }));

    // Queue a repair for the first 20 rules via the normal offer()/is_gap_repair
    // mechanism - each becomes mid-repair (repair_seq != 0) and stays that way,
    // since the sentinel above blocks the worker from ever reaching them.
    std::set<std::string> already_mid_repair;
    for (int i = 0; i < kAlreadyMidRepair; ++i) {
        const auto rid = padded_rule_id(i);
        CHECK(exec.offer(make_event(rid, "guard.unhealthy"), std::ref(repair_send),
                         /*is_gap_repair=*/true) == OfferOutcome::Queued);
        already_mid_repair.insert(rid);
    }
    REQUIRE(exec.all_gaps_for_test().size() == static_cast<std::size_t>(kRules));

    exec.kick();
    auto gaps = exec.gapped_rules_needing_repair(kCap);

    // Exactly the 20 NOT already mid-repair - the cap (32) never binds because
    // only 20 are eligible. The old "cap counts listed entries" bug would have
    // returned 32 raw entries (in whatever order unordered_map iteration
    // happened to produce) and left the caller to filter out the ones already
    // mid-repair - offering as few as 32 - 20 == 12 NEW repairs if all 20
    // already-mid-repair entries happened to be among that raw 32.
    CHECK(gaps.size() == static_cast<std::size_t>(kRules - kAlreadyMidRepair));
    for (const auto& [rule_id, gap] : gaps) {
        CHECK(gap.repair_seq == 0);
        CHECK(already_mid_repair.count(rule_id) == 0);
    }
}

TEST_CASE("wait_idle_for_test can read true while a retiring worker is still "
          "physically counted",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    // Not idle yet: a send is in flight.
    CHECK_FALSE(exec.wait_idle_for_test(50ms));

    send.release();
    // Once the send returns, the queue empties and in_flight clears - idle
    // becomes true - but the worker's own trampoline may not have physically
    // retired (destroyed the ticket) at that exact instant. Both must eventually
    // hold; the distinction this test pins is that idle does not itself IMPLY
    // physical retirement.
    REQUIRE(exec.wait_idle_for_test(5s));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.active_worker_count() == 0);
}

// ── #4783 Gate 4 UP-3/UP-4: snapshot()/restore() + the per-loss log ─────────

TEST_CASE("snapshot(): change_gen stays flat across repeated no-op kick() calls when "
          "nothing has been lost or cleared (#4783 Gate 4 UP-3)",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    const Snapshot initial = exec.snapshot();
    CHECK(initial.change_gen == 0);
    CHECK(initial.counters.events_lost == 0);
    CHECK(initial.gaps.empty());

    for (int i = 0; i < 5; ++i)
        exec.kick(); // empty queue, nothing in flight, nothing gapped - a pure no-op

    const Snapshot after = exec.snapshot();
    CHECK(after.change_gen == initial.change_gen);
    CHECK(after.counters.events_lost == 0);
    CHECK(after.gaps.empty());
}

TEST_CASE("restore(): seeds Stats so a subsequent loss continues counting from the "
          "restored value, never from 0 (#4783 Gate 4 UP-3)",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    GuardianLegacySinkExecutor::Stats seed{};
    seed.events_lost = 41;
    seed.backpressure_drops = 7;
    exec.restore(seed, {});
    CHECK(exec.stats().events_lost == 41);
    CHECK(exec.stats().backpressure_drops == 7);

    // A deterministic fresh loss via admission-fault injection - no threading
    // needed (mirrors this file's other AdmissionFaultForTest cases).
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnNode);
    CHECK(exec.offer(make_event("r1", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::RefusedAdmission);
    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);

    CHECK(exec.stats().events_lost == 42); // continues from the restored 41, not from 0
    CHECK(exec.stats().admission_failures == 1); // this counter, unlike events_lost, was never seeded
}

TEST_CASE("restore(): restored gaps are immediately eligible for repair (repair_seq==0, "
          "fresh last_attempt_kick==0) and preserve the original first_lost/last_lost "
          "(#4783 Gate 4 UP-3)",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    GapSnapshotEntry g;
    g.rule_id = "r-restored";
    g.guard_type = "file";
    g.rule_name = "rn";
    g.lost = 5;
    g.first_lost_ms = 1000;
    g.last_lost_ms = 9000;
    exec.restore(GuardianLegacySinkExecutor::Stats{}, {g});

    const auto gaps = exec.all_gaps_for_test();
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "r-restored");
    CHECK(gaps[0].second.guard_type == "file");
    CHECK(gaps[0].second.rule_name == "rn");
    CHECK(gaps[0].second.lost == 5);
    CHECK(gaps[0].second.repair_seq == 0);
    CHECK(gaps[0].second.last_attempt_kick == 0);
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(
              gaps[0].second.first_lost.time_since_epoch())
              .count() == 1000);
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(
              gaps[0].second.last_lost.time_since_epoch())
              .count() == 9000);

    // Eligible for repair immediately - not excluded as "already mid-repair".
    const auto eligible = exec.gapped_rules_needing_repair(10);
    REQUIRE(eligible.size() == 1);
    CHECK(eligible[0].first == "r-restored");
}

TEST_CASE("restore(): a restored gap clears on the first subsequent Sent delivery for "
          "that rule - the same seq-guard mechanism as any other gap (#4783 Gate 4 UP-3)",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    GapSnapshotEntry g;
    g.rule_id = "r-restored";
    g.guard_type = "file";
    g.rule_name = "rn";
    g.lost = 1;
    g.first_lost_ms = 1000;
    g.last_lost_ms = 1000;
    exec.restore(GuardianLegacySinkExecutor::Stats{}, {g});
    REQUIRE(exec.all_gaps_for_test().size() == 1);

    RecordingSend send;
    CHECK(exec.offer(make_event("r-restored", "guard.compliant"), std::ref(send)) ==
         OfferOutcome::Queued);
    REQUIRE(exec.wait_idle_for_test(5s));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    CHECK(exec.all_gaps_for_test().empty()); // cleared - lost_seq==0 is < any real seq (>=1)
    CHECK(send.count() == 1);
}

TEST_CASE("Per-loss attribution log: fires exactly once (warn) on a rule_id's first loss "
          "this process, then again (info) only on its 100th loss - never LogCapture, "
          "cross-image hazard (test_guardian_arm_ack.cpp) (#4783 Gate 4 UP-4)",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    struct Observed {
        std::string rule_id;
        std::string kind;
        std::string event_type;
        spdlog::level::level_enum level;
    };
    std::mutex mu;
    std::vector<Observed> observed;
    exec.set_loss_log_hook_for_test([&](const std::string& rule_id, const char* kind,
                                        const std::string& event_type,
                                        spdlog::level::level_enum level) {
        std::lock_guard<std::mutex> lk{mu};
        observed.push_back(Observed{rule_id, kind, event_type, level});
    });

    // 150 deterministic losses for the SAME rule_id via admission-fault
    // injection (never queues, so the capacity branch never trips - every
    // single offer() takes the RefusedAdmission path).
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnNode);
    for (int i = 0; i < 150; ++i) {
        CHECK(exec.offer(make_event("r-loss", "drift.detected"),
                         [](const Event&) { return LegacySendOutcome::Sent; }) ==
             OfferOutcome::RefusedAdmission);
    }
    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);

    std::lock_guard<std::mutex> lk{mu};
    std::vector<Observed> warns;
    std::vector<Observed> infos;
    for (const auto& o : observed) {
        if (o.level == spdlog::level::warn)
            warns.push_back(o);
        else if (o.level == spdlog::level::info)
            infos.push_back(o);
    }
    // Loss #1 -> warn; loss #100 -> info; losses #2-99 and #101-150 -> nothing.
    REQUIRE(warns.size() == 1);
    CHECK(warns[0].rule_id == "r-loss");
    CHECK(warns[0].kind == "RefusedAdmission");
    CHECK(warns[0].event_type == "drift.detected");
    REQUIRE(infos.size() == 1);
    CHECK(infos[0].rule_id == "r-loss");
    CHECK(infos[0].kind == "RefusedAdmission");
    CHECK(observed.size() == 2); // nothing else fired across all 150 losses
}
