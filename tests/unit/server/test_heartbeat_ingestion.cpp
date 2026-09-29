/**
 * test_heartbeat_ingestion.cpp — Guardian heartbeat-reconcile seam (#1209 M5 +
 * hardening). Pins the `yuzu.guardian_generation` tag → reconcile-callback path:
 * a valid generation fires the callback with the parsed value; a malformed,
 * trailing-garbage, or absent tag does NOT (the from_chars ptr==end strictness).
 *
 * The reconcile path in ingest() touches neither the health store, the fleet
 * topology store, nor the registry, so all three can be null / default — the
 * callback is the only observable.
 */

#include "heartbeat_ingestion.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <latch>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using yuzu::server::HeartbeatIngestion;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;

namespace {

struct ReconcileCapture {
    bool called{false};
    std::string agent_id;
    std::uint64_t generation{0};
};

::yuzu::agent::v1::HeartbeatRequest make_hb(const std::string& gen_value, bool set_tag = true) {
    ::yuzu::agent::v1::HeartbeatRequest hb;
    if (set_tag)
        (*hb.mutable_status_tags())["yuzu.guardian_generation"] = gen_value;
    return hb;
}

} // namespace

TEST_CASE("HeartbeatIngestion: reconcile fires on a valid generation tag",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, /*health=*/nullptr, /*fleet_topology=*/nullptr,
                                 &metrics};

    ReconcileCapture cap;
    ingestion.set_guardian_reconcile_fn([&](std::string_view aid, std::uint64_t gen) {
        cap.called = true;
        cap.agent_id = std::string(aid);
        cap.generation = gen;
    });

    ingestion.ingest(make_hb("42"), "agent-x", "direct");

    REQUIRE(cap.called);
    CHECK(cap.agent_id == "agent-x");
    CHECK(cap.generation == 42u);
}

TEST_CASE("HeartbeatIngestion: reconcile NOT fired on malformed / partial / absent tag",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    SECTION("non-numeric") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("abc"), "agent-x", "direct");
        CHECK_FALSE(called);
    }
    SECTION("trailing garbage — whole tag must parse (ptr==end)") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("123abc"), "agent-x", "direct");
        CHECK_FALSE(called);
    }
    SECTION("absent tag") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct");
        CHECK_FALSE(called);
    }
}

TEST_CASE("HeartbeatIngestion: no reconcile callback set is a no-op",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};
    // No set_guardian_reconcile_fn — must not crash even with a valid tag.
    ingestion.ingest(make_hb("7"), "agent-x", "direct");
    SUCCEED();
}

// ── #3425: quarantine reconnect reconciler seam ────────────────────────────
//
// Unlike the guardian hook above, this one carries no tag to gate on —
// reconnect itself is the signal, so it must fire on EVERY ingested
// heartbeat, tag or no tag.

TEST_CASE("HeartbeatIngestion: quarantine reconcile fires once per heartbeat, unconditionally",
          "[heartbeat_ingestion][quarantine]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    std::vector<std::string> calls;
    ingestion.set_quarantine_reconcile_fn(
        [&](std::string_view aid) { calls.push_back(std::string(aid)); });

    // No guardian_generation tag at all — the quarantine hook must still fire.
    ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct");
    REQUIRE(calls.size() == 1);
    CHECK(calls[0] == "agent-x");

    ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-y", "gateway");
    REQUIRE(calls.size() == 2);
    CHECK(calls[1] == "agent-y");
}

TEST_CASE("HeartbeatIngestion: unset quarantine reconcile fn is a no-op",
          "[heartbeat_ingestion][quarantine]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};
    // No set_quarantine_reconcile_fn — must not crash.
    ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct");
    SUCCEED();
}

TEST_CASE("HeartbeatIngestion: a throwing quarantine reconcile fn does not abort ingestion",
          "[heartbeat_ingestion][quarantine]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    ingestion.set_quarantine_reconcile_fn(
        [](std::string_view) { throw std::runtime_error("boom"); });
    // Must not propagate — a bad reconcile must not knock the rest of
    // ingestion (or the gRPC handler thread) over.
    CHECK_NOTHROW(ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct"));
}

// #3425 governance Gate 3 (cpp-safety, 2026-08-24): `set_quarantine_reconcile_fn(nullptr)`
// must be an actual drain barrier — it must not return while a concurrent
// `ingest()` call is still inside the fn, or server.cpp's stop() sequence can
// `.reset()` the QuarantineContainmentReconciler the fn's closure captures
// while that closure is still running (a use-after-free). Deterministic via
// two single-count latches — no sleep-based timing, no TSan dependency: a
// bug here can be reintroduced by simply deleting the shared_mutex, and this
// test fails DETERMINISTICALLY (not via a rare race) once it is, because
// `set_returned` is only ever true after the shared_lock protecting the
// in-flight call has released, which is provably before or after the
// exclusive lock — never both possible at once for a correct implementation.
TEST_CASE("HeartbeatIngestion: set_quarantine_reconcile_fn(nullptr) blocks until an in-flight "
          "ingest() call completes",
          "[heartbeat_ingestion][quarantine][regression]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    std::latch fn_started{1};
    std::latch fn_may_return{1};
    ingestion.set_quarantine_reconcile_fn([&](std::string_view) {
        fn_started.count_down();
        fn_may_return.wait(); // block "inside the callback" until told to proceed
    });

    std::thread ingest_thread(
        [&] { ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct"); });

    fn_started.wait(); // the callback is now genuinely in flight

    std::atomic<bool> set_returned{false};
    std::thread set_thread([&] {
        ingestion.set_quarantine_reconcile_fn(nullptr); // must block here
        set_returned.store(true);
    });

    // The callback is still parked on fn_may_return — set_thread must not
    // have been able to return yet. A short, generous margin: a false
    // failure here (flakiness) is possible only if the scheduler starves
    // set_thread for the whole window even though the lock is NOT held,
    // which a correct implementation never requires; a broken
    // implementation (no lock) would return near-instantly and this would
    // reliably catch it.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK_FALSE(set_returned.load());

    fn_may_return.count_down(); // let the in-flight callback finish
    ingest_thread.join();
    set_thread.join();
    CHECK(set_returned.load()); // now it has returned — the barrier held
}
