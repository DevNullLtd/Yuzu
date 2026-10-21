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
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
using yuzu::server::OfflineEndpoint;
using yuzu::server::OfflineEndpointStore;
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

// Same key + identical setup as test_offline_endpoint_store.cpp's template
// (shared pre-migrated template; replay-verified per docs/postgres-store-playbook.md).
yuzu::test::PgTestTemplate offline_tpl{"offline", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("offline template: store failed to migrate");
}};

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

// #5513 T14: an agent with an unresolved boot re-arm reports generation "0" (plus the sparse
// companion tag yuzu.guardian_boot_rearm_unresolved). There is deliberately NO zero special
// case server-side: "0" parses like any value and reaches the reconcile fn, which compares it
// numerically against the server's current generation and pushes if behind. The companion tag
// is not read here and must not change that.
TEST_CASE("HeartbeatIngestion: a reported generation of \"0\" reaches the reconcile fn (#5513)",
          "[heartbeat_ingestion][guardian][5513]") {
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

    SECTION("generation 0 alone") {
        ingestion.ingest(make_hb("0"), "agent-x", "direct");
    }
    SECTION("generation 0 with the boot re-arm companion tag") {
        auto hb = make_hb("0");
        (*hb.mutable_status_tags())["yuzu.guardian_boot_rearm_unresolved"] = "1";
        ingestion.ingest(hb, "agent-x", "direct");
    }

    REQUIRE(cap.called);
    CHECK(cap.agent_id == "agent-x");
    CHECK(cap.generation == 0u);
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

// #5513: the quarantine hook's catch log neutralises the agent id and the exception text with
// ::yuzu::log_id_token, like the guardian hook's catch. Control bytes in either must not reach
// the log line (one warn call -> exactly one line, no raw ESC / CR / embedded LF).
TEST_CASE("HeartbeatIngestion: a throwing quarantine reconcile fn logs neutralised text (#5513)",
          "[heartbeat_ingestion][quarantine]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    ingestion.set_quarantine_reconcile_fn(
        [](std::string_view) { throw std::runtime_error("boom\nFORGED-LINE\r\x1b[31m"); });

    std::string logs;
    {
        yuzu::test::LogCapture capture{spdlog::level::warn};
        CHECK_NOTHROW(ingestion.ingest(make_hb("", /*set_tag=*/false), "agent\nx\x1b", "direct"));
        capture.stop();
        logs = capture.text();
    }
    CHECK(logs.find("agent_x_") != std::string::npos);
    CHECK(logs.find("boom_FORGED-LINE__[31m") != std::string::npos);
    CHECK(logs.find('\x1b') == std::string::npos);
    // A lone mid-line CR counts everywhere; Windows spdlog's trailing "\r\n" does not.
    CHECK(yuzu::test::stray_control_bytes(logs) == 0);
    // The single trailing eol is the only newline.
    CHECK(std::count(logs.begin(), logs.end(), '\n') == 1);
}

// #5513: the guardian reconcile hook is caught at the ingestion call site like the quarantine
// hook (and additionally catch(...) and token-neutralised logging), and the rest of ingestion
// still runs. Evidence that it ran: the quarantine hook (which executes after the guardian
// hook) is still invoked.
TEST_CASE("HeartbeatIngestion: a throwing guardian reconcile fn does not abort ingestion (#5513)",
          "[heartbeat_ingestion][reconcile]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    int quarantine_calls = 0;
    ingestion.set_quarantine_reconcile_fn([&](std::string_view) { ++quarantine_calls; });
    const auto exceptions = [&] {
        return metrics.counter("yuzu_server_guardian_reconcile_exceptions_total").value();
    };

    SECTION("std::exception") {
        ingestion.set_guardian_reconcile_fn(
            [](std::string_view, std::uint64_t) { throw std::runtime_error("boom"); });
        CHECK_NOTHROW(ingestion.ingest(make_hb("7"), "agent-x", "direct"));
        CHECK(quarantine_calls == 1);
        CHECK(exceptions() == 1.0);
        CHECK_NOTHROW(ingestion.ingest(make_hb("8"), "agent-x", "direct"));
        CHECK(exceptions() == 2.0);
    }
    SECTION("a non-std exception") {
        ingestion.set_guardian_reconcile_fn([](std::string_view, std::uint64_t) { throw 42; });
        CHECK_NOTHROW(ingestion.ingest(make_hb("7"), "agent-x", "direct"));
        CHECK(quarantine_calls == 1);
        CHECK(exceptions() == 1.0);
    }
    SECTION("a hook that returns, or a heartbeat without the tag, is not counted") {
        ingestion.set_guardian_reconcile_fn([](std::string_view, std::uint64_t) {});
        ingestion.ingest(make_hb("7"), "agent-x", "direct");
        ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct");
        CHECK(exceptions() == 0.0);
    }
    SECTION("a throwing quarantine hook is not counted as a guardian reconcile exception") {
        ingestion.set_quarantine_reconcile_fn(
            [](std::string_view) { throw std::runtime_error("boom"); });
        ingestion.set_guardian_reconcile_fn([](std::string_view, std::uint64_t) {});
        CHECK_NOTHROW(ingestion.ingest(make_hb("7"), "agent-x", "direct"));
        CHECK(exceptions() == 0.0);
    }
    SECTION("without a metrics registry a throwing hook is still contained") {
        HeartbeatIngestion unmetered{registry, nullptr, nullptr, nullptr};
        unmetered.set_guardian_reconcile_fn(
            [](std::string_view, std::uint64_t) { throw std::runtime_error("boom"); });
        CHECK_NOTHROW(unmetered.ingest(make_hb("7"), "agent-x", "direct"));
    }
    SECTION("the hook stays installed: a later non-throwing heartbeat still reaches it") {
        bool throw_now = true;
        ReconcileCapture cap;
        ingestion.set_guardian_reconcile_fn([&](std::string_view aid, std::uint64_t gen) {
            if (throw_now)
                throw std::runtime_error("boom");
            cap.called = true;
            cap.agent_id = std::string(aid);
            cap.generation = gen;
        });
        CHECK_NOTHROW(ingestion.ingest(make_hb("7"), "agent-x", "direct"));
        throw_now = false;
        ingestion.ingest(make_hb("8"), "agent-x", "direct");
        CHECK(cap.called);
        CHECK(cap.generation == 8);
        CHECK(quarantine_calls == 2);
    }
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

// HA WS-5: on a replica holding no local AgentSession for a gateway-fronted
// agent, the caller resolves the session id from the route store and threads
// it into ingest() so the durable presence row carries the session id (needed
// by the session-guarded remove_if_session on a later graceful disconnect).
TEST_CASE("HeartbeatIngestion: resolved_session_id is recorded on the presence row when the "
          "registry has no session",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    // Seed what the OWNING replica wrote earlier: a known hostname/os.
    REQUIRE(store.upsert("yuzu_test_hb_nonowner", "known-host", "linux", 1, 0, "1.0.0", "arm64",
                         "sess-owner"));

    ingestion.ingest(make_hb("", /*set_tag=*/false), "yuzu_test_hb_nonowner", "gateway",
                     "sess-resolved");

    // Hostname/os are blank on this replica (no local session) -> preserved.
    const auto roster = store.query_stale_within(std::chrono::hours(1));
    REQUIRE(roster.has_value()); // #5531: the read is typed
    const OfflineEndpoint* row = nullptr;
    for (const auto& e : *roster)
        if (e.agent_id == "yuzu_test_hb_nonowner")
            row = &e;
    REQUIRE(row != nullptr);
    CHECK(row->hostname == "known-host");
    CHECK(row->os == "linux");

    // The presence row now carries the RESOLVED session id: the old session
    // no longer matches, the resolved one does (and the clear is consumed).
    CHECK_FALSE(store.remove_if_session("yuzu_test_hb_nonowner", "sess-owner"));
    CHECK(store.remove_if_session("yuzu_test_hb_nonowner", "sess-resolved"));
}

TEST_CASE("HeartbeatIngestion: resolved_session_id overrides the local session's id; blank "
          "falls back to it",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    ::yuzu::agent::v1::AgentInfo info;
    info.set_agent_id("yuzu_test_hb_local");
    info.set_hostname("local-host");
    auto sess = registry.register_agent(info);
    REQUIRE(sess.has_value());
    // The session id is assigned by the Subscribe path via map_session().
    const std::string local_sid = "yuzu_test_hb_local_sess";
    registry.map_session(local_sid, "yuzu_test_hb_local");
    REQUIRE((*sess)->session_id == local_sid);

    SECTION("blank resolved id -> local session id is recorded (unchanged behaviour)") {
        ingestion.ingest(make_hb("", false), "yuzu_test_hb_local", "direct");
        CHECK(store.remove_if_session("yuzu_test_hb_local", local_sid));
    }
    SECTION("non-empty resolved id wins over the local session id") {
        ingestion.ingest(make_hb("", false), "yuzu_test_hb_local", "gateway", "sess-store-says");
        CHECK_FALSE(store.remove_if_session("yuzu_test_hb_local", local_sid));
        CHECK(store.remove_if_session("yuzu_test_hb_local", "sess-store-says"));
    }
}

// #5686: with a batch context, a failed presence upsert trips the batch and
// later entries skip theirs EXCEPT half-open probes; with no batch context
// (the direct path) every heartbeat still attempts its own.
//
// Probe schedule with the store failing throughout: entry 1 is attempted (the
// batch is not yet tripped) and fails -> next_probe=1, so entry 2 is the probe
// (an isolated failure costs only itself); it fails too -> next_probe=2; entry
// 3 is skipped; entry 4 is the probe and fails -> next_probe=4; entries 5-7 are
// skipped; entry 8 is the next probe. Attempts land on entries 1, 2, 4, 8, 16,
// 32, ...
TEST_CASE("HeartbeatIngestion: a batch skips presence upserts after a failure except spaced "
          "probes and the direct path still attempts each one",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    // Declared before the store: the store holds &metrics (set_metrics) and
    // must not outlive it.
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    auto held = pool.acquire(); // the pool's only connection: every upsert times out
    REQUIRE(held);
    auto failed = [&] {
        return metrics
            .counter("yuzu_server_agent_presence_store_failed_total",
                     {{"op", "upsert"}, {"reason", "store_unavailable"}})
            .value();
    };
    auto received = [&](const char* via) {
        return metrics.counter("yuzu_heartbeats_received_total", {{"via", via}}).value();
    };

    SECTION("batched") {
        HeartbeatIngestion::PresenceBatch batch;
        for (int i = 0; i < 3; ++i)
            ingestion.ingest(make_hb("", false), "yuzu_test_hb_batch_" + std::to_string(i),
                             "gateway", "sess-batch", &batch);
        CHECK(batch.store_failed);
        // Entry 2 was the second consecutive failure, so the spacing doubled
        // from 1 to 2: this pins the F1 schedule (a pre-F1 build probed later).
        CHECK(batch.next_probe == 2);
        CHECK(batch.failed == 2);  // entries 1 and 2 (the probe right after the first failure)
        CHECK(batch.skipped == 1); // entry 3
        CHECK(failed() == 2);
        CHECK(received("gateway") == 3); // the rest of ingest() still ran for every entry
    }
    SECTION("direct") {
        for (int i = 0; i < 2; ++i)
            ingestion.ingest(make_hb("", false), "yuzu_test_hb_direct_" + std::to_string(i),
                             "direct");
        CHECK(failed() == 2);
        CHECK(received("direct") == 2);
    }
}

// #5686 governance G-1: the trip is half-open, not sticky. A store that
// recovers mid-batch is detected by the next probe and later entries are
// written again. Two consecutive failures (entries 1 and 2) leave entry 3 to be
// skipped and entry 4 to be the probe.
TEST_CASE("HeartbeatIngestion: a presence store that recovers mid-batch is detected by the "
          "next probe and later entries are written",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    auto present = [&](const std::string& agent) {
        const auto roster = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(roster.has_value());
        for (const auto& e : *roster)
            if (e.agent_id == agent)
                return true;
        return false;
    };
    const auto name = [](int i) { return "yuzu_test_hb_recover_" + std::to_string(i); };

    HeartbeatIngestion::PresenceBatch batch;
    {
        auto held = pool.acquire();
        REQUIRE(held);
        ingestion.ingest(make_hb("", false), name(0), "gateway", "sess-r", &batch); // fails
        ingestion.ingest(make_hb("", false), name(1), "gateway", "sess-r", &batch); // probe: fails
        ingestion.ingest(make_hb("", false), name(2), "gateway", "sess-r", &batch); // skipped
    } // the store recovers here, between ingest() calls (no sleeps, no clocks)
    REQUIRE(batch.store_failed);
    REQUIRE(batch.failed == 2);
    REQUIRE(batch.skipped == 1);
    REQUIRE(batch.next_probe == 2);

    ingestion.ingest(make_hb("", false), name(3), "gateway", "sess-r", &batch); // probe: succeeds
    CHECK_FALSE(batch.store_failed);
    CHECK(batch.next_probe == 1);
    CHECK(batch.skips_since_fail == 0);

    ingestion.ingest(make_hb("", false), name(4), "gateway", "sess-r", &batch); // written again
    CHECK(batch.skipped == 1);
    CHECK(batch.failed == 2); // history is kept: the caller still sees the batch hit trouble

    CHECK_FALSE(present(name(0)));
    CHECK_FALSE(present(name(1)));
    CHECK_FALSE(present(name(2)));
    CHECK(present(name(3)));
    CHECK(present(name(4)));
}

// #5686 governance F1: an ISOLATED failure costs only the failed entry. The
// very next entry after the first failure is the probe (next_probe stays 1),
// so when the store has recovered by then nothing else is skipped.
TEST_CASE("HeartbeatIngestion: an isolated presence failure skips nothing when the next entry "
          "probes successfully",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    auto present = [&](const std::string& agent) {
        const auto roster = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(roster.has_value());
        for (const auto& e : *roster)
            if (e.agent_id == agent)
                return true;
        return false;
    };
    const auto name = [](int i) { return "yuzu_test_hb_isolated_" + std::to_string(i); };

    HeartbeatIngestion::PresenceBatch batch;
    {
        auto held = pool.acquire();
        REQUIRE(held);
        ingestion.ingest(make_hb("", false), name(0), "gateway", "sess-i", &batch); // fails
    }
    REQUIRE(batch.store_failed);
    REQUIRE(batch.failed == 1);
    CHECK(batch.next_probe == 1); // the very next entry is the probe

    ingestion.ingest(make_hb("", false), name(1), "gateway", "sess-i", &batch); // probe: written
    CHECK_FALSE(batch.store_failed);
    CHECK(batch.skipped == 0);
    CHECK(batch.failed == 1);
    ingestion.ingest(make_hb("", false), name(2), "gateway", "sess-i", &batch);
    CHECK(batch.skipped == 0);

    CHECK_FALSE(present(name(0)));
    CHECK(present(name(1)));
    CHECK(present(name(2)));
}

// A failure on the LAST entry leaves nothing to skip, but `failed` still tells
// the caller the batch hit presence trouble (store_failed alone is also set
// here, but a recovered probe clears it, `failed` is never cleared).
TEST_CASE("HeartbeatIngestion: a presence failure on the last entry is visible in "
          "PresenceBatch::failed",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    HeartbeatIngestion::PresenceBatch batch;
    ingestion.ingest(make_hb("", false), "yuzu_test_hb_last_0", "gateway", "sess-l", &batch);
    CHECK_FALSE(batch.store_failed);
    {
        auto held = pool.acquire();
        REQUIRE(held);
        ingestion.ingest(make_hb("", false), "yuzu_test_hb_last_1", "gateway", "sess-l", &batch);
    }
    CHECK(batch.failed == 1);
    CHECK(batch.skipped == 0);
}

// Bound under TOTAL saturation: a batch of N makes at most floor(log2 N)+1
// attempted upserts (each a bounded 250 ms acquire), not N.
TEST_CASE("HeartbeatIngestion: total presence saturation makes at most floor(log2 N)+1 attempts "
          "per batch",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    auto held = pool.acquire();
    REQUIRE(held);
    constexpr int kN = 40;
    // The exact schedule gives floor(log2 40)+1 = 6 (asserted below); kBound is
    // the looser pre-F1 ceil(log2 40)+1 ceiling.
    constexpr std::size_t kBound = 7;
    HeartbeatIngestion::PresenceBatch batch;
    for (int i = 0; i < kN; ++i)
        ingestion.ingest(make_hb("", false), "yuzu_test_hb_sat_" + std::to_string(i), "gateway",
                         "sess-sat", &batch);
    CHECK(batch.failed >= 1);
    CHECK(batch.failed <= kBound);
    CHECK(batch.failed + batch.skipped == static_cast<std::size_t>(kN));
    // Attempts land on entries 1, 2, 4, 8, 16, 32 -> exactly 6 of 40.
    CHECK(batch.failed == 6);
}

// #5686 governance F1: pin the exact attempted-entry sequence under total
// saturation, one entry at a time: the 1-based indices at which
// PresenceBatch::failed increments must be 1, 2, 4, 8, 16, 32.
TEST_CASE("HeartbeatIngestion: total presence saturation attempts entries 1, 2, 4, 8, 16, 32",
          "[heartbeat_ingestion][ws5][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics, &store};

    auto held = pool.acquire();
    REQUIRE(held);
    HeartbeatIngestion::PresenceBatch batch;
    std::vector<int> attempted;
    for (int i = 1; i <= 40; ++i) {
        const auto before = batch.failed;
        ingestion.ingest(make_hb("", false), "yuzu_test_hb_seq_" + std::to_string(i), "gateway",
                         "sess-seq", &batch);
        if (batch.failed > before)
            attempted.push_back(i);
    }
    CHECK(attempted == std::vector<int>{1, 2, 4, 8, 16, 32});
    CHECK(batch.skipped == 34);
}
