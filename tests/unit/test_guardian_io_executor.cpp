// test_guardian_io_executor.cpp - the bounded/cancellable single-flight I/O
// executor behind the Guardian state reader (ADR-0021 rung 5, F3). Each case is a
// caught-it test for one Sol-required invariant: deadline + late-result discard,
// keyed single-flight, per-type + total bulkheads, stop wake/reject + shutdown
// snapshot, launch-failure rollback, contained worker exceptions, and
// destroy-then-release lifetime safety (the ASan case). This is also the executor's
// TSan checkpoint (shared mutable state + threads).

#include "guardian_io_executor.hpp"

#include "guardian_detached_worker_role.hpp"
#include "guardian_joined_thread_role.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

// A worker gate: the fake read body blocks on wait() until the test releases it,
// so a test can hold a worker in flight and observe admission/slot state.
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

// spin_until / kSpinScale promoted to yuzu::test (test_helpers.hpp) — #2238 adversarial
// review follow-up (CON-S4 third user, missed by the original promotion).
using yuzu::test::spin_until;

// A functor whose COPY constructor throws - passed as an LVALUE (forcing run()'s
// `std::decay_t<F>(std::forward<F>(fn))` capture-init to copy, not move), this
// throws AFTER run()'s wait_lk is acquired (guardian_io_executor.hpp:375) but
// still inside the worker-lambda's own construction - the owns_lock()==true path
// through run()'s outer catch block, distinct from the pre-lock
// set_throw_before_wait_lock_for_test seam.
struct ThrowOnCopyFunctor {
    ThrowOnCopyFunctor() = default;
    ThrowOnCopyFunctor(const ThrowOnCopyFunctor&) {
        throw std::runtime_error("fn copy boom (test seam)");
    }
    ThrowOnCopyFunctor(ThrowOnCopyFunctor&&) = default;
    int operator()() const { return 1; }
};

constexpr std::size_t kFile = io_class_index(IoClass::File);
constexpr std::size_t kSvc = io_class_index(IoClass::Service);

} // namespace

TEST_CASE("run: a read that completes before its deadline returns its value", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto r = ex.run(IoClass::File, "k", 5s, [] { return 7; });
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    // Not necessarily zero the instant run() returns (the ticket destructor runs
    // after the worker's notify) - wait boundedly.
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: exceeding the deadline returns Timeout and discards the late result",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(IoClass::File, "k", 30ms, [gate]() -> int {
        gate->wait();
        return 99;
    });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(ex.active_worker_count() == 1); // the worker is still blocked
    gate->release();                      // its late write goes to the abandoned cell -> discarded
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].timed_out == 1);
}

TEST_CASE("run: a second read for the same (class,key) returns AlreadyRunning without spawning",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto spawns = std::make_shared<std::atomic<int>>(0);
    auto first_started = std::make_shared<std::promise<void>>();
    auto first_started_fut = first_started->get_future();
    std::thread caller([&] {
        ex.run(IoClass::File, "dup", 30s, [gate, spawns, first_started] {
            spawns->fetch_add(1);
            first_started->set_value(); // proves the worker body, not just admission, ran
            gate->wait();
            return 1;
        });
    });
    // Wait for the FIRST worker to genuinely start executing, not merely for
    // admission to succeed - active_worker_count() flips before the OS thread is
    // ever scheduled, so gating on that alone could race a not-yet-running first
    // worker and let a would-be-erroneous second spawn slip past unobserved.
    REQUIRE(first_started_fut.wait_for(5s) == std::future_status::ready);
    auto r2 = ex.run(IoClass::File, "dup", 1s, [spawns] {
        spawns->fetch_add(1);
        return 2;
    });
    CHECK_FALSE(r2.has_value());
    CHECK(r2.error() == IoFailure::AlreadyRunning);
    // Give a hypothetical erroneously-spawned second worker ample time to run and
    // increment spawns before asserting it never did - an instant read here would
    // let a real single-flight regression pass if that second thread simply hadn't
    // been scheduled yet.
    std::this_thread::sleep_for(100ms);
    CHECK(spawns->load() == 1); // the second call never spawned a worker
    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: file-lane saturation does not block a service read (per-type bulkhead)",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex{GuardianIoExecutor::Config{
        .file_quota = 2, .registry_quota = 2, .service_quota = 2}};
    auto gate = std::make_shared<Gate>();
    std::vector<std::thread> callers;
    auto park = [&](IoClass c, std::string k) {
        callers.emplace_back([&ex, gate, c, k] {
            ex.run(c, k, 30s, [gate] {
                gate->wait();
                return 0;
            });
        });
    };
    park(IoClass::File, "f1");
    park(IoClass::File, "f2");
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::File) == 2; }));

    // A third file read hits the per-type quota.
    auto rf = ex.run(IoClass::File, "f3", 1s, [gate] {
        gate->wait();
        return 0;
    });
    CHECK(rf.error() == IoFailure::CapacityExhausted);

    // A service read is unaffected: the file lane is full but the service quota is
    // free, and the derived process bound (2+2+2=6) never binds before a class cap.
    auto rs = ex.run(IoClass::Service, "s1", 5s, [] { return 5; });
    REQUIRE(rs.has_value());
    CHECK(*rs == 5);

    gate->release();
    for (auto& t : callers)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("Config: an oversubscribing injected quota is clamped to the process ceiling",
          "[spark][ioexecutor]") {
    // A pathological injected Config (100/100/100) must NOT let the executor spawn 300
    // workers - the derived process bound is clamped to kMaxProcessIoWorkers. (The
    // DEFAULT config is static-asserted safe; this guards runtime-injected values.)
    GuardianIoExecutor ex{GuardianIoExecutor::Config{
        .file_quota = 100, .registry_quota = 100, .service_quota = 100}};
    auto gate = std::make_shared<Gate>();
    std::vector<std::thread> callers;
    for (int i = 0; i < GuardianIoExecutor::kMaxProcessIoWorkers; ++i) {
        callers.emplace_back([&ex, gate, i] {
            ex.run(IoClass::File, "f" + std::to_string(i), 30s, [gate] {
                gate->wait();
                return 0;
            });
        });
    }
    REQUIRE(spin_until(
        [&] { return ex.active_worker_count() == GuardianIoExecutor::kMaxProcessIoWorkers; }));
    // The (ceiling+1)-th read is rejected: the process bound was clamped to the ceiling,
    // not the injected sum of 300.
    auto over = ex.run(IoClass::File, "f-over", 1s, [gate] {
        gate->wait();
        return 0;
    });
    CHECK(over.error() == IoFailure::CapacityExhausted);

    gate->release();
    for (auto& t : callers)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: a saturated file+registry lane never starves the service lane (R3 exact bulkheads)",
          "[spark][ioexecutor]") {
    // The default config is the shipped-bug shape: File 4 + Registry 3 = 7 workers.
    // Under the old independent total_quota{8} that left Service just 1 of its 3
    // slots. With the derived process bound (== sum of class quotas, so exact
    // bulkheads) a saturated file+registry lane leaves Service its full 3 slots.
    GuardianIoExecutor ex; // defaults: 4 / 3 / 3
    auto gate = std::make_shared<Gate>();
    std::vector<std::thread> callers;
    auto park = [&](IoClass c, std::string k) {
        callers.emplace_back([&ex, gate, c, k] {
            ex.run(c, k, 30s, [gate] {
                gate->wait();
                return 0;
            });
        });
    };
    // Saturate File (4) and Registry (3): 7 workers, the exact old-total-quota point.
    park(IoClass::File, "f1");
    park(IoClass::File, "f2");
    park(IoClass::File, "f3");
    park(IoClass::File, "f4");
    park(IoClass::Registry, "r1");
    park(IoClass::Registry, "r2");
    park(IoClass::Registry, "r3");
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 7; }));

    // All THREE service reads are admitted - the service lane keeps its full quota,
    // no cross-lane starvation. (Under the old total_quota{8} the 8th worker would
    // admit and the 9th+ reject, capping service at 1.)
    park(IoClass::Service, "s1");
    park(IoClass::Service, "s2");
    park(IoClass::Service, "s3");
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::Service) == 3; }));

    // A 4th service read hits the service class cap (3), not the process bound.
    auto rs4 = ex.run(IoClass::Service, "s4", 1s, [gate] {
        gate->wait();
        return 0;
    });
    CHECK(rs4.error() == IoFailure::CapacityExhausted);

    gate->release();
    for (auto& t : callers)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("stop wakes an in-flight submitter, snapshots the shutdown count, and rejects new reads",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    std::promise<IoResult<int>> pr;
    auto fut = pr.get_future();
    std::thread caller([&] {
        pr.set_value(ex.run(IoClass::File, "k", 30s, [gate] {
            gate->wait();
            return 3;
        }));
    });
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 1; }));

    ex.stop();
    REQUIRE(fut.wait_for(2s) == std::future_status::ready);
    CHECK(fut.get().error() == IoFailure::Stopped); // the parked submitter was woken
    CHECK(ex.stats().active_at_shutdown[kFile] == 1); // per-class shutdown snapshot

    auto r2 = ex.run(IoClass::File, "k2", 1s, [] { return 9; }); // every post-stop call is Stopped
    CHECK(r2.error() == IoFailure::Stopped);

    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("stop racing concurrent admission never crashes and yields only valid outcomes",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&ex, &start, i] {
            while (!start.load())
                std::this_thread::yield();
            for (int j = 0; j < 20; ++j) {
                auto r = ex.run(IoClass::Registry, "k" + std::to_string(i), 50ms, [] { return 1; });
                (void)r; // any outcome is acceptable; the point is no crash / terminate
            }
        });
    }
    start.store(true);
    std::this_thread::sleep_for(5ms);
    ex.stop();
    for (auto& t : threads)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    SUCCEED("no crash under the stop/admission race");
}

TEST_CASE("a failed worker launch rolls admission back and frees the key", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    ex.set_fail_launch_for_test(true);
    auto r = ex.run(IoClass::File, "k", 1s, [] { return 1; });
    CHECK(r.error() == IoFailure::LaunchFailed);
    CHECK(ex.active_worker_count() == 0); // rolled back, not leaked
    CHECK(ex.stats().counters[kFile].launch_failures == 1);

    // The key was freed by the rollback: a real read for the same key now succeeds.
    ex.set_fail_launch_for_test(false);
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 2; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 2);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("a throwing read body maps to WorkerThrew and never terminates", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto r = ex.run(IoClass::Service, "k", 5s, []() -> int { throw std::runtime_error("boom"); });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::WorkerThrew);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kSvc].worker_exceptions == 1);
}

TEST_CASE("the executor may be destroyed while a worker is still blocked (no UAF)",
          "[spark][ioexecutor]") {
    auto gate = std::make_shared<Gate>();
    auto done = std::make_shared<std::promise<void>>();
    auto fut = done->get_future();
    {
        GuardianIoExecutor ex;
        auto r = ex.run(IoClass::File, "k", 20ms, [gate, done]() -> int {
            gate->wait();
            done->set_value();
            return 1;
        });
        CHECK(r.error() == IoFailure::Timeout);
        CHECK(ex.active_worker_count() == 1);
        // ex is destroyed here while the worker is still blocked; State stays alive
        // through the worker's shared_ptr, so its later publish + ticket release do
        // not use-after-free.
    }
    gate->release();
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    // Let the trampoline epilogue (publish + ticket release against the still-alive
    // State) finish before the test returns - no orphan worker at process exit.
    std::this_thread::sleep_for(50ms);
    SUCCEED("worker released after executor destruction without UAF");
}

TEST_CASE("a slot and its key are reclaimed after a timed-out worker finally finishes",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(IoClass::File, "k", 20ms, [gate] {
        gate->wait();
        return 1;
    });
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(ex.active_worker_count() == 1);

    // Still single-flighted while the worker is wedged.
    auto dup = ex.run(IoClass::File, "k", 20ms, [] { return 2; });
    CHECK(dup.error() == IoFailure::AlreadyRunning);

    gate->release();
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 0; }));

    // Reclaimed: a fresh same-key read runs.
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 3; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 3);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

// --- #3816: exactly-once result delivery (on_abandoned) ---------------------

TEST_CASE("run: a late result after Timeout is delivered to on_abandoned exactly once",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto abandoned_calls = std::make_shared<std::atomic<int>>(0);
    auto abandoned_value = std::make_shared<std::atomic<int>>(-1);
    auto r = ex.run(
        IoClass::File, "k", 30ms,
        [gate]() -> int {
            gate->wait();
            return 99;
        },
        [abandoned_calls, abandoned_value](int&& v) {
            abandoned_calls->fetch_add(1);
            abandoned_value->store(v);
        });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(abandoned_calls->load() == 0); // worker still parked, on_abandoned not yet called
    gate->release();
    REQUIRE(spin_until([&] { return abandoned_calls->load() == 1; }));
    CHECK(abandoned_value->load() == 99);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].timed_out == 1);
    CHECK(ex.stats().counters[kFile].abandoned == 1);
}

TEST_CASE("run: a late FAILED (not thrown) result also reaches on_abandoned, counted the same",
          "[spark][ioexecutor]") {
    // The executor is T-agnostic (agents/core/src/guardian_io_executor.hpp:
    // Counters::abandoned's own doc): a late result that fn() RETURNED (never
    // threw) is routed to on_abandoned regardless of whether T itself represents
    // a success or failure - the success/failure distinction only exists one
    // layer up, at a consumer that knows what T means (GuardianSparkRuntime's
    // backend_op_late_arms_, tested in test_guardian_spark_runtime.cpp). This
    // case proves that at THIS layer, an inner-failure result is delivered to
    // on_abandoned exactly the same as an inner-success one - not silently
    // dropped for having the "wrong" has_value().
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto abandoned_calls = std::make_shared<std::atomic<int>>(0);
    auto abandoned_had_value = std::make_shared<std::atomic<bool>>(true);
    using T = std::expected<int, std::string>;
    auto r = ex.run(
        IoClass::File, "k", 30ms,
        [gate]() -> T {
            gate->wait();
            return std::unexpected(std::string{"backend arm failed"});
        },
        [abandoned_calls, abandoned_had_value](T&& v) {
            abandoned_calls->fetch_add(1);
            abandoned_had_value->store(v.has_value());
        });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(abandoned_calls->load() == 0); // worker still parked, on_abandoned not yet called
    gate->release();
    REQUIRE(spin_until([&] { return abandoned_calls->load() == 1; }));
    CHECK_FALSE(abandoned_had_value->load()); // on_abandoned DID fire, with the inner failure
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].timed_out == 1);
    // The executor's own T-agnostic counter increments for a late FAILURE exactly
    // as it does for a late success - see this file's other on_abandoned tests.
    CHECK(ex.stats().counters[kFile].abandoned == 1);
}

TEST_CASE("run: a result published before the deadline never invokes on_abandoned",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto abandoned_calls = std::make_shared<std::atomic<int>>(0);
    auto r = ex.run(
        IoClass::File, "k", 5s, [] { return 7; },
        [abandoned_calls](int&&) { abandoned_calls->fetch_add(1); });
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(abandoned_calls->load() == 0);
    CHECK(ex.stats().counters[kFile].abandoned == 0);
}

TEST_CASE("run: stop() during the wait routes a still-in-flight late result to on_abandoned",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto abandoned_calls = std::make_shared<std::atomic<int>>(0);
    std::promise<IoResult<int>> pr;
    auto fut = pr.get_future();
    std::thread caller([&] {
        pr.set_value(ex.run(
            IoClass::File, "k", 30s,
            [gate]() -> int {
                gate->wait();
                return 42;
            },
            [abandoned_calls](int&&) { abandoned_calls->fetch_add(1); }));
    });
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 1; }));
    ex.stop();
    REQUIRE(fut.wait_for(2s) == std::future_status::ready);
    CHECK(fut.get().error() == IoFailure::Stopped);
    CHECK(abandoned_calls->load() == 0); // worker still parked
    gate->release();
    REQUIRE(spin_until([&] { return abandoned_calls->load() == 1; }));
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: a throwing on_abandoned is contained, counted, and does not stop key reclamation",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(
        IoClass::File, "k", 20ms,
        [gate]() -> int {
            gate->wait();
            return 1;
        },
        [](int&&) -> void { throw std::runtime_error("on_abandoned boom"); });
    CHECK(r.error() == IoFailure::Timeout);
    gate->release();
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].abandoned == 1);
    CHECK(ex.stats().counters[kFile].abandonment_cleanup_failures == 1);
    // The key was still reclaimed despite the throwing callback.
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 2; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 2);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: the single-flight key is held until on_abandoned returns, then reclaimed",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto cleanup_gate = std::make_shared<Gate>();
    auto cleanup_entered = std::make_shared<std::promise<void>>();
    auto cleanup_entered_fut = cleanup_entered->get_future();
    auto r = ex.run(
        IoClass::File, "k", 20ms,
        [gate]() -> int {
            gate->wait();
            return 1;
        },
        [cleanup_gate, cleanup_entered](int&&) {
            cleanup_entered->set_value();
            cleanup_gate->wait(); // hold the key open until the test releases it
        });
    CHECK(r.error() == IoFailure::Timeout);
    gate->release();
    REQUIRE(cleanup_entered_fut.wait_for(5s) == std::future_status::ready);

    // The cleanup callback is still running - the key is still held.
    auto dup = ex.run(IoClass::File, "k", 20ms, [] { return 2; });
    CHECK(dup.error() == IoFailure::AlreadyRunning);

    cleanup_gate->release();
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 0; }));

    // Reclaimed: a fresh same-key read now runs.
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 3; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 3);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: on_abandoned never fires for a worker exception or an alloc-starved null box",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto abandoned_calls = std::make_shared<std::atomic<int>>(0);
    auto r = ex.run(
        IoClass::Service, "k", 5s, []() -> int { throw std::runtime_error("boom"); },
        [abandoned_calls](int&&) { abandoned_calls->fetch_add(1); });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::WorkerThrew);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(abandoned_calls->load() == 0);
    CHECK(ex.stats().counters[kSvc].abandoned == 0);
}

TEST_CASE("run: the wait-lock throw seam is a pre-launch LaunchFailed, no worker ever ran",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto spawns = std::make_shared<std::atomic<int>>(0);
    ex.set_throw_before_wait_lock_for_test(true);
    auto r = ex.run(IoClass::File, "k", 5s, [spawns] {
        spawns->fetch_add(1);
        return 1;
    });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::LaunchFailed);
    CHECK(ex.active_worker_count() == 0); // rolled back, not leaked
    CHECK(ex.stats().counters[kFile].launch_failures == 1);
    CHECK(spawns->load() == 0); // fn() never ran - the throw fires before spawn_detached

    // The key was freed by the rollback: a real read for the same key now succeeds.
    ex.set_throw_before_wait_lock_for_test(false);
    auto r2 = ex.run(IoClass::File, "k", 5s, [spawns] {
        spawns->fetch_add(1);
        return 2;
    });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 2);
    CHECK(spawns->load() == 1);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: a throw during post-lock worker-capture construction is the "
          "owns_lock()==true catch path, and rolls back cleanly",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    ThrowOnCopyFunctor fn_obj; // named lvalue: run()'s capture-init copies it, not moves
    auto r = ex.run(IoClass::File, "k", 5s, fn_obj);
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::LaunchFailed); // same outcome as the pre-lock seam -
                                                  // both are launch-time failures from
                                                  // the caller's point of view
    CHECK(ex.active_worker_count() == 0);        // rolled back, not leaked
    CHECK(ex.stats().counters[kFile].launch_failures == 1);

    // The key was freed by the rollback (the owns_lock()==true branch correctly
    // unlocks wait_lk on unwind before TicketCore's destructor tries to acquire
    // the same mutex - a wrong declaration order here would self-deadlock this
    // very call): a real read for the same key now succeeds.
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 2; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 2);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("the executor may be destroyed while on_abandoned cleanup is still pending (no UAF)",
          "[spark][ioexecutor]") {
    auto gate = std::make_shared<Gate>();
    auto cleanup_gate = std::make_shared<Gate>();
    auto cleanup_entered = std::make_shared<std::promise<void>>();
    auto cleanup_entered_fut = cleanup_entered->get_future();
    auto done = std::make_shared<std::promise<void>>();
    auto fut = done->get_future();
    {
        GuardianIoExecutor ex;
        auto r = ex.run(
            IoClass::File, "k", 20ms,
            [gate]() -> int {
                gate->wait();
                return 1;
            },
            [cleanup_gate, cleanup_entered, done](int&&) {
                cleanup_entered->set_value(); // proves on_abandoned itself is running,
                                               // not merely that fn() unblocked
                cleanup_gate->wait();
                done->set_value();
            });
        CHECK(r.error() == IoFailure::Timeout);
        CHECK(ex.active_worker_count() == 1);
        gate->release();
        // Wait for the worker to genuinely be INSIDE on_abandoned before destroying
        // ex - without this barrier, destruction could race ahead of the worker
        // resuming from gate->wait(), degenerating into the plain "destroyed while
        // blocked" case above rather than exercising mid-cleanup destruction.
        REQUIRE(cleanup_entered_fut.wait_for(5s) == std::future_status::ready);
        // ex is destroyed here while the worker is confirmed mid-cleanup (parked in
        // on_abandoned, past cleanup_entered); State stays alive through the
        // worker's own shared_ptr, so its later cleanup + ticket release do not
        // use-after-free.
    }
    cleanup_gate->release();
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    std::this_thread::sleep_for(50ms);
    SUCCEED("worker released after executor destruction, mid-cleanup, without UAF");
}

TEST_CASE("the same key string under different IoClass values is independent",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    std::thread caller([&] {
        ex.run(IoClass::File, "same", 30s, [gate] {
            gate->wait();
            return 0;
        });
    });
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::File) == 1; }));

    // A Registry read with the SAME key string is a different op key -> admitted.
    auto r = ex.run(IoClass::Registry, "same", 5s, [] { return 8; });
    REQUIRE(r.has_value());
    CHECK(*r == 8);

    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("the detached-worker role marker is set on the marked thread and nowhere else",
          "[spark][ioexecutor]") {
    // rung 9c R5.1: the PREDICATE GuardianEngine::WorkerHostileMutex consults for its
    // second role. The abort itself is proven by the forked-child death test in
    // test_guardian_engine_spark_reconcile.cpp; this isolates the flag. Mutation: drop
    // set_guardian_detached_worker_thread(true) from the RAII ctor -> marked_true false.
    CHECK_FALSE(on_guardian_detached_worker_thread()); // the test thread is not a worker

    std::atomic<bool> marked_true{false};
    std::atomic<bool> joined_seen{true}; // default true so a missed read fails loudly
    std::atomic<bool> cleared_after{true};
    std::thread marked_thread([&] {
        {
            GuardianDetachedWorkerRole role_marker;
            marked_true.store(on_guardian_detached_worker_thread());
            joined_seen.store(on_guardian_joined_thread()); // the two roles are independent
        }
        cleared_after.store(on_guardian_detached_worker_thread()); // RAII clears on exit
    });
    marked_thread.join();
    CHECK(marked_true.load());
    CHECK_FALSE(joined_seen.load());
    CHECK_FALSE(cleared_after.load());
    CHECK_FALSE(on_guardian_detached_worker_thread()); // still false here after the join
}

// ---------------------------------------------------------------------------
// rung 9c R5.1: submit(), the non-waiting dispatch form. Each case names the
// mutation that makes it RED (recorded in the PR's mutation table).
// ---------------------------------------------------------------------------

namespace {
constexpr std::size_t kReg = io_class_index(IoClass::Registry);

// Shared observation cell for a submit() completion: value, thread identity,
// invocation count - all written by the worker, read by the test after spin_until.
struct Completion {
    std::atomic<int> calls{0};
    std::atomic<int> value{-1};
    std::atomic<bool> had_value{false};
    std::atomic<int> error{-1};
    std::atomic<bool> on_test_thread{true}; // default true so a missed write fails loudly
    std::thread::id test_thread{std::this_thread::get_id()};
    // governance qe-1 (policy floor: a flaky test leg introduced by this change):
    // `calls` is the terminal atomic every case polls on, so the result fields MUST
    // be published BEFORE it. The original order (++calls first) let a poller observe
    // calls==1 and read value==-1 under --order rand (seed 1, :979 `-1 == 4`,
    // reproduced on the TSan binary). The release increment pairs with the pollers'
    // (seq_cst, hence acquire) loads of `calls`, so every field written above it is
    // visible once calls reads 1.
    void record(IoResult<int>&& r) {
        had_value.store(r.has_value());
        if (r)
            value.store(*r);
        else
            error.store(static_cast<int>(r.error()));
        on_test_thread.store(std::this_thread::get_id() == test_thread);
        calls.fetch_add(1, std::memory_order_release); // publish LAST
    }
};
} // namespace

TEST_CASE("submit: delivers fn's value to on_complete exactly once, on the worker thread",
          "[spark][ioexecutor]") {
    // Mutation: invoke on_complete twice, or call it synchronously on the caller.
    GuardianIoExecutor ex;
    auto c = std::make_shared<Completion>();
    auto adm = ex.submit(IoClass::File, "k", [] { return 7; },
                         [c](IoResult<int>&& r) { c->record(std::move(r)); });
    REQUIRE(adm.has_value());
    REQUIRE(spin_until([&] { return c->calls.load() == 1; }));
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; })); // worker fully exited
    std::this_thread::sleep_for(50ms);                                // no second delivery
    CHECK(c->calls.load() == 1);
    CHECK(c->had_value.load());
    CHECK(c->value.load() == 7);
    CHECK_FALSE(c->on_test_thread.load());
    CHECK(ex.stats().quota_held_total == 0);
}

TEST_CASE("submit: a throwing fn is delivered as WorkerThrew through on_complete",
          "[spark][ioexecutor]") {
    // Mutation: skip the callback on throw (or let the exception escape).
    GuardianIoExecutor ex;
    auto c = std::make_shared<Completion>();
    auto adm = ex.submit(
        IoClass::Service, "k", []() -> int { throw std::runtime_error("boom"); },
        [c](IoResult<int>&& r) { c->record(std::move(r)); });
    REQUIRE(adm.has_value());
    REQUIRE(spin_until([&] { return c->calls.load() == 1; }));
    CHECK_FALSE(c->had_value.load());
    CHECK(c->error.load() == static_cast<int>(IoFailure::WorkerThrew));
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kSvc].worker_exceptions == 1);
    CHECK(c->calls.load() == 1);
}

TEST_CASE("submit: the quota slot and single-flight key release at fn() return, before "
          "on_complete runs",
          "[spark][ioexecutor]") {
    // Mutation: move release_quota_locked() to after on_complete -> the same-key submit
    // returns AlreadyRunning and the run() on the other key returns CapacityExhausted.
    GuardianIoExecutor ex{{.file_quota = 1, .registry_quota = 1, .service_quota = 1}};
    auto park = std::make_shared<Gate>();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_fut = entered->get_future();
    auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                         [park, entered](IoResult<int>&&) {
                             entered->set_value(); // proves on_complete is running
                             park->wait();
                         });
    REQUIRE(adm.has_value());
    REQUIRE(entered_fut.wait_for(5s) == std::future_status::ready);

    // Inside the parked-callback window: no quota held, but the thread is alive.
    auto s = ex.stats();
    CHECK(s.quota_held_total == 0);
    CHECK(s.quota_held_by_class[kFile] == 0);
    CHECK(s.active_total == 1);
    CHECK(ex.active_worker_count() >= 1);

    // Same key, same class: ADMITTED (the key was freed at fn() return).
    auto second = std::make_shared<Completion>();
    auto adm2 = ex.submit(IoClass::File, "k", [] { return 2; },
                          [second](IoResult<int>&& r) { second->record(std::move(r)); });
    REQUIRE(adm2.has_value());
    REQUIRE(spin_until([&] { return second->calls.load() == 1; }));
    CHECK(second->value.load() == 2);

    // Same class, other key, blocking form: the single File slot is free (the parked
    // worker released it), so this returns a value rather than CapacityExhausted.
    auto r = ex.run(IoClass::File, "k2", 5s, [] { return 3; });
    REQUIRE(r.has_value());
    CHECK(*r == 3);
    CHECK(ex.stats().counters[kFile].rejected_key == 0);
    CHECK(ex.stats().counters[kFile].rejected_capacity == 0);

    park->release();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: the physical alive-worker ceiling refuses admission while quota is free",
          "[spark][ioexecutor]") {
    // Mutation: drop the alive_total >= alive_ceiling check in admit_locked -> the 7th
    // submit is admitted and rejected_ceiling stays 0.
    GuardianIoExecutor ex{{.file_quota = 1, .registry_quota = 1, .service_quota = 1}};
    REQUIRE(ex.alive_ceiling() == 6); // 2 x (1+1+1)
    auto park = std::make_shared<Gate>();
    auto entered = std::make_shared<std::atomic<int>>(0);
    auto done = std::make_shared<std::atomic<int>>(0);
    for (int i = 0; i < 6; ++i) {
        auto adm = ex.submit(IoClass::File, "c" + std::to_string(i), [] { return 1; },
                             [park, entered, done](IoResult<int>&&) {
                                 ++*entered;
                                 park->wait();
                                 ++*done;
                             });
        REQUIRE(adm.has_value());
        // Each worker frees its File slot at fn() return; waiting for the callback to
        // be ENTERED before the next submit guarantees the quota check cannot be the
        // one that fires (the slot is provably free), isolating the ceiling.
        REQUIRE(spin_until([&] { return entered->load() == i + 1; }));
    }
    CHECK(ex.active_worker_count() == 6);
    CHECK(ex.stats().quota_held_total == 0);

    auto c7 = std::make_shared<Completion>();
    auto adm7 = ex.submit(IoClass::File, "c7", [] { return 1; },
                          [c7](IoResult<int>&& r) { c7->record(std::move(r)); });
    REQUIRE_FALSE(adm7.has_value());
    CHECK(adm7.error() == IoFailure::CeilingExhausted);
    // The blocking form is refused the same way, and a Registry op too (the ceiling
    // is per instance, not per class).
    auto r = ex.run(IoClass::Registry, "reg", 5s, [] { return 1; });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::CeilingExhausted);
    auto s = ex.stats();
    CHECK(s.counters[kFile].rejected_ceiling == 1);
    CHECK(s.counters[kReg].rejected_ceiling == 1);
    CHECK(s.counters[kFile].rejected_capacity == 0);
    CHECK(s.counters[kReg].rejected_capacity == 0);
    std::this_thread::sleep_for(50ms);
    CHECK(c7->calls.load() == 0); // a refused submit never fires its callback

    park->release();
    REQUIRE(spin_until([&] { return done->load() == 6; }));
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    // Recovery: admitted again once the callback-phase workers have exited.
    auto c8 = std::make_shared<Completion>();
    auto adm8 = ex.submit(IoClass::File, "c8", [] { return 8; },
                          [c8](IoResult<int>&& r) { c8->record(std::move(r)); });
    REQUIRE(adm8.has_value());
    REQUIRE(spin_until([&] { return c8->calls.load() == 1; }));
    CHECK(c8->value.load() == 8);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: active_worker_count() stays nonzero across the completion-callback "
          "window after the quota slot released (#4147)",
          "[spark][ioexecutor]") {
    // Mutation: report quota_held_total from active_worker_count() -> reads 0 while the
    // callback is parked, the exact F3 regression #4147 guards against.
    GuardianIoExecutor ex;
    auto park = std::make_shared<Gate>();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_fut = entered->get_future();
    auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                         [park, entered](IoResult<int>&&) {
                             entered->set_value();
                             park->wait();
                         });
    REQUIRE(adm.has_value());
    REQUIRE(entered_fut.wait_for(5s) == std::future_status::ready);
    CHECK(ex.active_worker_count() == 1);
    CHECK(ex.active_worker_count(IoClass::File) == 1);
    auto s = ex.stats();
    CHECK(s.active_total == 1);
    CHECK(s.active_by_class[kFile] == 1);
    CHECK(s.quota_held_total == 0);
    CHECK(s.quota_held_by_class[kFile] == 0);
    park->release();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: stop() snapshots the alive count, rejects new submits, and does not "
          "suppress a late completion (completed_after_stop)",
          "[spark][ioexecutor]") {
    // Mutation: skip on_complete when st->stopping is set -> calls stays 0.
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto started = std::make_shared<std::promise<void>>();
    auto started_fut = started->get_future();
    auto c = std::make_shared<Completion>();
    auto adm = ex.submit(
        IoClass::File, "k",
        [gate, started] {
            started->set_value(); // the body genuinely started (not just admitted)
            gate->wait();
            return 1;
        },
        [c](IoResult<int>&& r) { c->record(std::move(r)); });
    REQUIRE(adm.has_value());
    REQUIRE(started_fut.wait_for(5s) == std::future_status::ready);

    ex.stop();
    CHECK(ex.stats().active_at_shutdown[kFile] == 1);
    auto late = std::make_shared<Completion>();
    auto adm2 = ex.submit(IoClass::File, "k2", [] { return 2; },
                          [late](IoResult<int>&& r) { late->record(std::move(r)); });
    REQUIRE_FALSE(adm2.has_value());
    CHECK(adm2.error() == IoFailure::Stopped);
    std::this_thread::sleep_for(50ms);
    CHECK(late->calls.load() == 0); // refused: never fires

    gate->release();
    REQUIRE(spin_until([&] { return c->calls.load() == 1; }));
    CHECK(c->value.load() == 1);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].completed_after_stop == 1);
    CHECK(c->calls.load() == 1);
}

TEST_CASE("submit: a throwing on_complete is contained and counted; the slot and key were "
          "already released",
          "[spark][ioexecutor]") {
    // Mutation: remove the try/catch around on_complete -> std::terminate (the worker
    // lambda is noexcept), observed as a crashed test binary.
    GuardianIoExecutor ex;
    auto calls = std::make_shared<std::atomic<int>>(0);
    auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                         [calls](IoResult<int>&&) {
                             ++*calls;
                             throw std::runtime_error("callback boom");
                         });
    REQUIRE(adm.has_value());
    REQUIRE(spin_until([&] { return ex.stats().counters[kFile].completion_failures == 1; }));
    CHECK(calls->load() == 1);
    // Same key, blocking form: admitted (key + slot released before the callback ran).
    auto r = ex.run(IoClass::File, "k", 5s, [] { return 9; });
    REQUIRE(r.has_value());
    CHECK(*r == 9);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: a failed launch rolls admission back and never fires on_complete",
          "[spark][ioexecutor]") {
    // Mutation: in ~TicketCore skip the quota decrement when !quota_released -> the
    // quota leaks and the retry on a {1,1,1} Config returns CapacityExhausted.
    GuardianIoExecutor ex{{.file_quota = 1, .registry_quota = 1, .service_quota = 1}};
    auto c = std::make_shared<Completion>();
    ex.set_fail_launch_for_test(true);
    auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                         [c](IoResult<int>&& r) { c->record(std::move(r)); });
    REQUIRE_FALSE(adm.has_value());
    CHECK(adm.error() == IoFailure::LaunchFailed);
    std::this_thread::sleep_for(50ms);
    CHECK(c->calls.load() == 0);
    auto s = ex.stats();
    CHECK(s.counters[kFile].launch_failures == 1);
    CHECK(s.active_total == 0);
    CHECK(s.quota_held_total == 0);
    ex.set_fail_launch_for_test(false);
    // Same key, same class: the rollback freed slot + key + alive count.
    auto adm2 = ex.submit(IoClass::File, "k", [] { return 4; },
                          [c](IoResult<int>&& r) { c->record(std::move(r)); });
    REQUIRE(adm2.has_value());
    REQUIRE(spin_until([&] { return c->calls.load() == 1; }));
    CHECK(c->value.load() == 4);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: a nested run() from inside on_complete on the same key is admitted (refill)",
          "[spark][ioexecutor]") {
    // Mutation: release the slot/key after on_complete instead of before -> the nested
    // run() returns AlreadyRunning and nested_value stays -1.
    GuardianIoExecutor ex{{.file_quota = 1, .registry_quota = 1, .service_quota = 1}};
    auto nested_done = std::make_shared<std::atomic<bool>>(false);
    auto nested_value = std::make_shared<std::atomic<int>>(-1);
    auto nested_error = std::make_shared<std::atomic<int>>(-1);
    auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                         [&ex, nested_done, nested_value, nested_error](IoResult<int>&&) {
                             auto r = ex.run(IoClass::File, "k", 5s, [] { return 2; });
                             if (r)
                                 nested_value->store(*r);
                             else
                                 nested_error->store(static_cast<int>(r.error()));
                             nested_done->store(true);
                         });
    REQUIRE(adm.has_value());
    REQUIRE(spin_until([&] { return nested_done->load(); }));
    INFO("nested error code (if any): " << nested_error->load());
    CHECK(nested_value->load() == 2);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].rejected_key == 0);
    CHECK(ex.stats().counters[kFile].rejected_capacity == 0);
}

TEST_CASE("the detached-worker role marker is worn by run() and submit() workers, fn and "
          "callbacks included",
          "[spark][ioexecutor]") {
    // Mutation: drop the GuardianDetachedWorkerRole from either worker lambda -> the
    // corresponding flag reads false.
    GuardianIoExecutor ex;
    auto in_submit_fn = std::make_shared<std::atomic<bool>>(false);
    auto in_on_complete = std::make_shared<std::atomic<bool>>(false);
    auto joined_on_worker = std::make_shared<std::atomic<bool>>(true);
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto adm = ex.submit(
        IoClass::File, "s",
        [in_submit_fn, joined_on_worker] {
            in_submit_fn->store(on_guardian_detached_worker_thread());
            joined_on_worker->store(on_guardian_joined_thread());
            return 1;
        },
        [in_on_complete, done](IoResult<int>&&) {
            in_on_complete->store(on_guardian_detached_worker_thread());
            done->store(true);
        });
    REQUIRE(adm.has_value());
    REQUIRE(spin_until([&] { return done->load(); }));
    CHECK(in_submit_fn->load());
    CHECK(in_on_complete->load());
    CHECK_FALSE(joined_on_worker->load());

    // run(): fn and the on_abandoned path (a late result after the caller timed out).
    auto in_run_fn = std::make_shared<std::atomic<bool>>(false);
    auto in_on_abandoned = std::make_shared<std::atomic<bool>>(false);
    auto abandoned_seen = std::make_shared<std::atomic<bool>>(false);
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(
        IoClass::Service, "r", 30ms,
        [in_run_fn, gate] {
            in_run_fn->store(on_guardian_detached_worker_thread());
            gate->wait();
            return 1;
        },
        [in_on_abandoned, abandoned_seen](int&&) {
            in_on_abandoned->store(on_guardian_detached_worker_thread());
            abandoned_seen->store(true);
        });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::Timeout);
    gate->release();
    REQUIRE(spin_until([&] { return abandoned_seen->load(); }));
    CHECK(in_run_fn->load());
    CHECK(in_on_abandoned->load());
    CHECK_FALSE(on_guardian_detached_worker_thread()); // never leaks onto the caller
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("submit: the executor may be destroyed while a completion callback is still "
          "parked (no UAF)",
          "[spark][ioexecutor]") {
    // ASan/TSan checkpoint (mirror of the run()/on_abandoned case above). State stays
    // alive through the worker's own shared_ptr.
    auto park = std::make_shared<Gate>();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_fut = entered->get_future();
    auto done = std::make_shared<std::promise<void>>();
    auto fut = done->get_future();
    {
        GuardianIoExecutor ex;
        auto adm = ex.submit(IoClass::File, "k", [] { return 1; },
                             [park, entered, done](IoResult<int>&&) {
                                 entered->set_value(); // confirmed INSIDE on_complete
                                 park->wait();
                                 done->set_value();
                             });
        REQUIRE(adm.has_value());
        REQUIRE(entered_fut.wait_for(5s) == std::future_status::ready);
        CHECK(ex.active_worker_count() == 1);
        // ex is destroyed here while the worker is parked mid-callback.
    }
    park->release();
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    std::this_thread::sleep_for(50ms); // let the trampoline destroy the captures + ticket
    SUCCEED("submit worker released after executor destruction, mid-callback, without UAF");
}
