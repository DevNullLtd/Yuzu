// #4990: the caller-keyed fast-fail on the dispatch-record write (dispatch_record_policy.hpp).
//
// `ServerImpl::build_classified_command` writes the server's record of every dispatch before the
// command is sent. A loop that builds one command per target (the operator Guardian push, the
// heartbeat reconcile push) used to pay the tracker's full lease budget per agent when the record
// store was degraded. These cases pin the replacement, at the `AgentServiceImpl` seam the
// chokepoint calls: a loop-local latch selects a short lease budget and skips the rest of THAT
// loop's writes after the first failure, while an unlatched (operator) write keeps the long
// budget. `ServerImpl` cannot be constructed in a unit test; which call sites pass a latch is
// pinned lexically in tests/test_forensics_tier_wiring_lexical.py.
//
// What these cases do NOT cover: that every agent of a loop still receives its command. The
// record write is `void` and is made before any send, so it cannot influence the send set; the
// wiring gate pins that `build_classified_command` hands the command back unconditionally after
// the write, and no test here pretends otherwise.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "dispatch_record_policy.hpp"
#include "event_bus.hpp"
#include "execution_tracker.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "../test_helpers.hpp"
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using namespace std::chrono_literals;
namespace pg = yuzu::server::pg;

namespace {

yuzu::test::PgTestTemplate dispatch_record_tpl{"dispatchrecord", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ExecutionTracker tracker{pool};
    if (!tracker.is_open())
        throw std::runtime_error("dispatch-record template: the tracker failed to migrate");
}};

constexpr const char* kPlugin = "echo";
constexpr std::size_t kPoolSize = 4;
// The pool's own clamp on an already-saturated bounded acquire is raised well above both budgets
// under test, so the budget a write was GIVEN is the one that decides, not the pool's clamp.
constexpr std::chrono::milliseconds kOrdinaryBudgetInTest{2000};

/// A tracker and a service wired like the dispatch chokepoint's: records go through
/// `AgentServiceImpl::record_command_dispatch` into a real ExecutionTracker on a small pool, with
/// a short server-side lock_timeout so a held table lock resolves inside a test.
struct Fixture {
    yuzu::server::pg::PgPool pool;
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::unique_ptr<ExecutionTracker> tracker;

    explicit Fixture(const std::string& dsn)
        : pool({.conninfo = dsn,
                .size = kPoolSize,
                .lock_timeout_ms = 500,
                .saturated_fast_fail = kOrdinaryBudgetInTest}) {
        tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());
        svc.set_execution_tracker(tracker.get());
    }
    ~Fixture() {
        svc.set_execution_tracker(nullptr);
        tracker.reset();
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    [[nodiscard]] double degrades() {
        return metrics.counter("yuzu_exec_correlation_write_degrade_total").value();
    }
    [[nodiscard]] bool recorded(const std::string& id) const {
        return tracker->lookup_command_record(id).has_value();
    }
    [[nodiscard]] static std::string id_of(const char* tag, std::size_t i) {
        return std::string{kPlugin} + "-" + tag + std::to_string(i);
    }

    /// Takes every connection of the pool, so the next bounded acquire has to wait.
    [[nodiscard]] std::vector<yuzu::server::pg::PgPool::Lease> exhaust() {
        std::vector<yuzu::server::pg::PgPool::Lease> held;
        for (std::size_t i = 0; i < kPoolSize; ++i) {
            auto lease = pool.acquire();
            REQUIRE(lease);
            held.push_back(std::move(lease));
        }
        return held;
    }
};

template <class F> std::chrono::milliseconds timed(F&& f) {
    const auto t0 = std::chrono::steady_clock::now();
    f();
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 t0);
}

} // namespace

TEST_CASE("dispatch record latch: trips once, counts what it skipped, and carries the short budget",
          "[server][forensics_tier][provenance][dispatch_record]") {
    DispatchRecordLatch latch{"test loop"};
    CHECK_FALSE(latch.tripped());
    CHECK(latch.skipped() == 0);
    latch.trip();
    CHECK(latch.tripped());
    latch.trip(); // idempotent
    CHECK(latch.tripped());
    latch.note_skipped();
    latch.note_skipped();
    CHECK(latch.skipped() == 2);
    // Independent per loop: a second latch is untouched by the first (never process-global).
    DispatchRecordLatch other{"other loop"};
    CHECK_FALSE(other.tripped());
    CHECK(other.skipped() == 0);

    // The fan-out budget is short next to the ordinary 2 s lease budget and sits BELOW the pool's
    // own clamp on an already-saturated acquire, so it is the bound in both cases.
    CHECK(DispatchRecordLatch::lease_timeout() == kFanOutRecordLeaseTimeout);
    CHECK(kFanOutRecordLeaseTimeout > 0ms);
    CHECK(kFanOutRecordLeaseTimeout < yuzu::server::pg::PgPool::Options{}.saturated_fast_fail);
}

TEST_CASE("dispatch record: with the pool exhausted, a latched loop costs one short wait, not one per agent",
          "[pg][server][forensics_tier][provenance][dispatch_record]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_record_tpl);
    Fixture f(db.dsn());
    constexpr std::size_t kAgents = 20;

    std::vector<std::string> ids;
    for (std::size_t i = 0; i < kAgents; ++i)
        ids.push_back(Fixture::id_of("loopa", i));

    std::size_t skipped = 0;
    {
        auto held = f.exhaust();
        DispatchRecordLatch latch{"test loop"};
        const auto took = timed([&] {
            for (const auto& id : ids)
                f.svc.record_command_dispatch(id, kPlugin, "", &latch);
        });
        skipped = latch.skipped();
        // One short wait for the first agent. Unlatched, 20 agents would wait 20 x the fan-out
        // budget (5 s) at the very least; the bound has a wide margin on both sides.
        CHECK(took >= kFanOutRecordLeaseTimeout - 30ms);
        CHECK(took < 2s);
        CHECK(latch.tripped());
        CHECK(skipped == kAgents - 1);
        // Every agent's record is a counted degrade: the one that failed and the 19 that were
        // skipped.
        CHECK(f.degrades() == static_cast<double>(kAgents));
    }
    // Nothing was written for any of them (their responses would be labelled unverified).
    for (const auto& id : ids)
        CHECK_FALSE(f.recorded(id));

    // The latch is not sticky: the pool is released, and the next loop records normally.
    {
        DispatchRecordLatch next{"next loop"};
        for (std::size_t i = 0; i < kAgents; ++i)
            f.svc.record_command_dispatch(Fixture::id_of("loopb", i), kPlugin, "", &next);
        CHECK_FALSE(next.tripped());
        CHECK(next.skipped() == 0);
    }
    for (std::size_t i = 0; i < kAgents; ++i)
        CHECK(f.recorded(Fixture::id_of("loopb", i)));
    CHECK(f.degrades() == static_cast<double>(kAgents)); // unchanged by the healthy loop
}

TEST_CASE("dispatch record: a held table lock costs a latched loop one lock wait, not one per agent",
          "[pg][server][forensics_tier][provenance][dispatch_record]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_record_tpl);
    Fixture f(db.dsn());
    constexpr std::size_t kAgents = 20;

    std::size_t skipped = 0;
    {
        auto holder = f.pool.acquire();
        REQUIRE(holder);
        REQUIRE(pg::exec_params(holder.get(), "BEGIN", std::vector<std::string>{}).status() ==
                PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(holder.get(),
                                "LOCK TABLE execution_tracker.command_execution IN ACCESS "
                                "EXCLUSIVE MODE",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);

        DispatchRecordLatch latch{"test loop"};
        const auto took = timed([&] {
            for (std::size_t i = 0; i < kAgents; ++i)
                f.svc.record_command_dispatch(Fixture::id_of("locka", i), kPlugin, "", &latch);
        });
        skipped = latch.skipped();
        // The connection is leased at once, then the upsert waits for the server-side
        // lock_timeout (500 ms in this fixture; 10 s in production) and fails. Latched, that is
        // paid once. Unlatched it is 20 x 500 ms = 10 s.
        CHECK(took < 4s);
        CHECK(skipped == kAgents - 1);
        CHECK(f.degrades() == static_cast<double>(kAgents));
        (void)pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{});
    }
    // Lock released: the next loop records normally.
    DispatchRecordLatch next{"next loop"};
    for (std::size_t i = 0; i < kAgents; ++i)
        f.svc.record_command_dispatch(Fixture::id_of("lockb", i), kPlugin, "", &next);
    CHECK_FALSE(next.tripped());
    for (std::size_t i = 0; i < kAgents; ++i)
        CHECK(f.recorded(Fixture::id_of("lockb", i)));
}

TEST_CASE("dispatch record: an unlatched (operator) dispatch keeps the ordinary lease budget",
          "[pg][server][forensics_tier][provenance][dispatch_record]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_record_tpl);
    Fixture f(db.dsn());

    auto held = std::make_shared<std::vector<yuzu::server::pg::PgPool::Lease>>(f.exhaust());

    // The same exhausted pool: a latched write gives up at the short budget...
    {
        DispatchRecordLatch latch{"test loop"};
        const auto took = timed(
            [&] { f.svc.record_command_dispatch(Fixture::id_of("opa", 0), kPlugin, "", &latch); });
        CHECK(took >= kFanOutRecordLeaseTimeout - 30ms);
        CHECK(took < 1500ms);
        CHECK(latch.tripped());
        CHECK(f.degrades() == 1.0);
    }

    // ...while an unlatched one waits well past it and succeeds once a connection is released.
    std::atomic<bool> release_started{false};
    std::thread releaser([&] {
        release_started = true;
        std::this_thread::sleep_for(800ms);
        held->clear();
    });
    while (!release_started)
        std::this_thread::yield();
    const auto took = timed(
        [&] { f.svc.record_command_dispatch(Fixture::id_of("opb", 0), kPlugin, "", nullptr); });
    releaser.join();
    CHECK(took > kFanOutRecordLeaseTimeout + 200ms);
    CHECK(took < kOrdinaryBudgetInTest);
    CHECK(f.recorded(Fixture::id_of("opb", 0)));
    CHECK(f.degrades() == 1.0); // only the latched write above degraded
}

TEST_CASE("dispatch record: no tracker wired trips the latch and counts every write",
          "[pg][server][forensics_tier][provenance][dispatch_record]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dispatch_record_tpl);
    Fixture f(db.dsn());
    f.svc.set_execution_tracker(nullptr);
    DispatchRecordLatch latch{"test loop"};
    for (std::size_t i = 0; i < 5; ++i)
        f.svc.record_command_dispatch(Fixture::id_of("nt", i), kPlugin, "", &latch);
    CHECK(latch.tripped());
    CHECK(latch.skipped() == 4);
    CHECK(f.degrades() == 5.0);
    f.svc.set_execution_tracker(f.tracker.get()); // restored for the destructor's contract
}
