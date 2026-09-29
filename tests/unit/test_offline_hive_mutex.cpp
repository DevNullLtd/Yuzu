// Unit tests for ScopedOfflineHiveLock (agents/core/include/yuzu/agent/offline_hive_mutex.hpp):
// the RAII wrapper around the process-wide offline-hive-mount mutex shared by five plugins
// (autoruns, installed_apps, license_scan, registry, tar) via with_user_hive().
//
// Scope note: this covers B1 (acquire-on-construct / release-on-destruct / mutual exclusion)
// only. The wait/hold-time logging behaviour (constructor and destructor spdlog calls) is
// deliberately NOT exercised here with a throwing-sink or capturing-sink fixture:
//   - offline_hive_mutex.cpp is compiled into libyuzu_agent_core (a separate .dylib/.so from
//     this test binary), and tests/unit/test_log_capture.hpp's own header documents an
//     observed, unresolved (#3355) cross-image hazard where a default-logger swap made from
//     the test binary's image does not reliably reach spdlog:: calls made from code compiled
//     into that separate library on every toolchain -- a throwing/capturing-sink test here
//     would risk passing vacuously (false-green) rather than actually exercising the
//     destructor's try/catch.
//   - the exception-safety property itself (a `catch (...)` around a log call cannot let that
//     call's exception escape) is a language-level guarantee, not a runtime behaviour that
//     needs a dynamic proof; code-review verified both the constructor's and destructor's
//     guards directly.
// The lock/unlock and RAII-scope contract below has no such hazard and is fully proven here.

#include <yuzu/agent/offline_hive_mutex.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

using namespace yuzu::agent;

TEST_CASE("ScopedOfflineHiveLock acquires on construction and releases on destruction",
          "[agent][offline_hive_mutex]") {
    {
        const ScopedOfflineHiveLock guard("test_offline_hive_mutex");
        // Held for the guard's whole scope: a second, non-blocking attempt from another
        // thread must fail while `guard` is alive. The probe is a std::unique_lock with
        // std::try_to_lock (never a bare try_lock()/unlock() pair -- docs/cpp-conventions.md's
        // Concurrency section, and see tests/unit/fake_journal_store.hpp for the same
        // try_to_lock-by-RAII shape) so an unexpected successful acquisition -- were this test
        // ever to catch a real regression -- still releases via RAII instead of leaking the
        // process-wide mutex out of this test's own failure path. The result is published to
        // an atomic and asserted on the main thread after join(): Catch2 assertion macros are
        // not thread-safe (tests/unit/test_kv_store.cpp uses the same publish-then-assert-
        // after-join pattern for a worker-thread probe).
        std::atomic<bool> contender_acquired{false};
        std::thread contender([&] {
            std::unique_lock<std::mutex> probe(offline_hive_mutex(), std::try_to_lock);
            contender_acquired = probe.owns_lock();
        });
        contender.join();
        CHECK_FALSE(contender_acquired.load());
    }
    // Released on scope exit: the mutex must be free again.
    std::unique_lock<std::mutex> probe(offline_hive_mutex(), std::try_to_lock);
    REQUIRE(probe.owns_lock());
}

TEST_CASE("ScopedOfflineHiveLock serialises two overlapping guards", "[agent][offline_hive_mutex]") {
    int in_critical_section = 0;
    int max_concurrent = 0;
    std::mutex counter_mtx;

    auto worker = [&] {
        const ScopedOfflineHiveLock guard("test_offline_hive_mutex");
        {
            const std::lock_guard<std::mutex> counter_lock(counter_mtx);
            ++in_critical_section;
            max_concurrent = std::max(max_concurrent, in_critical_section);
        }
        {
            const std::lock_guard<std::mutex> counter_lock(counter_mtx);
            --in_critical_section;
        }
    };

    std::thread a(worker);
    std::thread b(worker);
    a.join();
    b.join();

    // Never both inside the guarded section at once -- offline_hive_mutex() is exclusive.
    CHECK(max_concurrent == 1);
}
