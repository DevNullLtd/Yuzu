/**
 * test_analytics_event.cpp — Unit tests for AnalyticsEvent and
 * AnalyticsEventStore (ADR-0049, Postgres-backed outbox spool).
 *
 * Covers: JSON serialization, severity enum, store lifecycle, emit/query,
 * drain to sinks (claim/send/revert), concurrent emit, schema version
 * preservation. The JSON/severity cases construct no store and stay
 * untagged; every case that touches AnalyticsEventStore is [pg]-gated
 * (SKIPs when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken —
 * test_helpers.hpp's skip-vs-fail contract) and uses the pre-migrated
 * "analytics" PgTestTemplate, shared with test_analytics_pg_helper.hpp's
 * AnalyticsEventStorePg bundle used by other fixtures.
 */

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// ── Mock sink for testing ──────────────────────────────────────────────────

class MockSink : public AnalyticsEventSink {
public:
    bool send(std::span<const AnalyticsEvent> batch) override {
        std::lock_guard lock(mu_);
        for (const auto& e : batch) {
            received_.push_back(e);
        }
        ++send_count_;
        return should_succeed_;
    }

    std::string name() const override { return "mock"; }

    std::vector<AnalyticsEvent> received() const {
        std::lock_guard lock(mu_);
        return received_;
    }

    int send_count() const {
        std::lock_guard lock(mu_);
        return send_count_;
    }

    void set_should_succeed(bool v) { should_succeed_ = v; }

private:
    mutable std::mutex mu_;
    std::vector<AnalyticsEvent> received_;
    int send_count_{0};
    bool should_succeed_{true};
};

namespace {

// Shared with test_analytics_pg_helper.hpp's AnalyticsEventStorePg (same
// key, same single-store setup) — the registry builds "analytics" once per
// suite run regardless of which TU asks first (PgTestTemplate contract,
// docs/postgres-store-playbook.md).
yuzu::test::PgTestTemplate analytics_tpl{"analytics", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AnalyticsEventStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("analytics template: store failed to migrate");
}};

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate a corrupt row / hold the advisory lock directly.
// Mirrors test_response_store.cpp's helper of the same name.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

} // namespace

// ── JSON Serialization ─────────────────────────────────────────────────────

TEST_CASE("AnalyticsEvent: JSON round-trip with all fields", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.tenant_id = "acme";
    event.agent_id = "agent-001";
    event.session_id = "sess-xyz";
    event.event_type = "command.completed";
    event.event_time = 1700000000000;
    event.ingest_time = 1700000001000;
    event.plugin = "netstat";
    event.capability = "list_connections";
    event.correlation_id = "cmd-abc123";
    event.severity = Severity::kWarn;
    event.source = "server";
    event.hostname = "host-01";
    event.os = "linux";
    event.arch = "x86_64";
    event.agent_version = "1.2.3";
    event.principal = "admin";
    event.principal_role = "admin";
    event.attributes = {{"target_count", 5}};
    event.payload = {{"status", "SUCCESS"}, {"exit_code", 0}};
    event.schema_version = 1;

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();

    CHECK(restored.tenant_id == "acme");
    CHECK(restored.agent_id == "agent-001");
    CHECK(restored.session_id == "sess-xyz");
    CHECK(restored.event_type == "command.completed");
    CHECK(restored.event_time == 1700000000000);
    CHECK(restored.ingest_time == 1700000001000);
    CHECK(restored.plugin == "netstat");
    CHECK(restored.capability == "list_connections");
    CHECK(restored.correlation_id == "cmd-abc123");
    CHECK(restored.severity == Severity::kWarn);
    CHECK(restored.source == "server");
    CHECK(restored.hostname == "host-01");
    CHECK(restored.os == "linux");
    CHECK(restored.arch == "x86_64");
    CHECK(restored.agent_version == "1.2.3");
    CHECK(restored.principal == "admin");
    CHECK(restored.principal_role == "admin");
    CHECK(restored.attributes["target_count"] == 5);
    CHECK(restored.payload["status"] == "SUCCESS");
    CHECK(restored.payload["exit_code"] == 0);
    CHECK(restored.schema_version == 1);
}

TEST_CASE("AnalyticsEvent: JSON round-trip with defaults", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "auth.login";

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();

    CHECK(restored.tenant_id == "default");
    CHECK(restored.agent_id.empty());
    CHECK(restored.event_type == "auth.login");
    CHECK(restored.event_time == 0);
    CHECK(restored.severity == Severity::kInfo);
    CHECK(restored.source == "server");
    CHECK(restored.schema_version == 1);
    CHECK(restored.attributes.is_object());
    CHECK(restored.payload.is_object());
}

TEST_CASE("AnalyticsEvent: JSON with empty optional fields", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "agent.registered";
    event.agent_id = "agent-002";

    nlohmann::json j = event;

    // All fields present in JSON even if empty
    CHECK(j.contains("plugin"));
    CHECK(j.contains("principal"));
    CHECK(j["plugin"] == "");
    CHECK(j["principal"] == "");

    auto restored = j.get<AnalyticsEvent>();
    CHECK(restored.plugin.empty());
    CHECK(restored.principal.empty());
}

// ── Severity Enum ──────────────────────────────────────────────────────────

TEST_CASE("Severity: serialization round-trip", "[analytics_event][severity]") {
    CHECK(severity_to_string(Severity::kDebug) == "debug");
    CHECK(severity_to_string(Severity::kInfo) == "info");
    CHECK(severity_to_string(Severity::kWarn) == "warn");
    CHECK(severity_to_string(Severity::kError) == "error");
    CHECK(severity_to_string(Severity::kCritical) == "critical");

    CHECK(severity_from_string("debug") == Severity::kDebug);
    CHECK(severity_from_string("info") == Severity::kInfo);
    CHECK(severity_from_string("warn") == Severity::kWarn);
    CHECK(severity_from_string("error") == Severity::kError);
    CHECK(severity_from_string("critical") == Severity::kCritical);
    CHECK(severity_from_string("unknown") == Severity::kInfo); // default
}

TEST_CASE("AnalyticsEvent: schema_version preserved", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "test";
    event.schema_version = 42;

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();
    CHECK(restored.schema_version == 42);
}

// ── Store Lifecycle ────────────────────────────────────────────────────────

TEST_CASE("AnalyticsEventStore: migrates and opens", "[pg][analytics_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());
}

TEST_CASE("AnalyticsEventStore: a failed open stays constructed-but-degraded, "
          "not reset (ADR-0049 construction-posture regression guard)",
          "[analytics_store][construction]") {
    // Unroutable DSN (TEST-NET-1, RFC 5737) with a tight connect_timeout so
    // this case fails fast instead of eating the default connect timeout
    // (governance Gate 4 unhappy-path UP-9's fixture advisory) — matches
    // the ResponseStore precedent (test_response_store.cpp, #1634 UP-2).
    // No PgTestTemplate/real Postgres needed: this exercises the
    // never-opens path, not real query behavior, so it is intentionally
    // NOT [pg]-tagged and runs unconditionally.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AnalyticsEventStore store(bad_pool);

    // The regression this guards: an earlier version of ServerImpl's
    // wiring code (server.cpp, not this store's own constructor) called
    // analytics_store_.reset() on this exact failed-open path, which this
    // test cannot observe directly since a caller here holds the object
    // itself rather than through ServerImpl's unique_ptr — the contract
    // under test is that the OBJECT ITSELF stays usable-but-degraded.
    REQUIRE_FALSE(store.is_open());

    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    AnalyticsEvent event;
    event.event_type = "test.event";
    store.emit(event); // must fail-soft, never throw/block

    CHECK(metrics
              .counter("yuzu_server_analytics_emit_dropped_total",
                       {{"reason", "store_not_open"}})
              .value() == 1);

    auto pending = store.pending_count();
    CHECK_FALSE(pending.has_value());
    auto recent = store.query_recent();
    CHECK_FALSE(recent.has_value());
    CHECK(metrics
              .counter("yuzu_server_analytics_read_degrade_total",
                       {{"method", "pending_count"}, {"reason", "store_not_open"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_analytics_read_degrade_total",
                       {{"method", "query_recent"}, {"reason", "store_not_open"}})
              .value() == 1);
}

TEST_CASE("AnalyticsEventStore: emit and query_recent", "[pg][analytics_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    AnalyticsEvent event;
    event.event_type = "agent.registered";
    event.agent_id = "agent-001";
    store.emit(event);

    auto results = store.query_recent();
    REQUIRE(results.has_value()); // degrade-distinguishable seam: not nullopt
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].event_type == "agent.registered");
    CHECK((*results)[0].agent_id == "agent-001");
    CHECK((*results)[0].ingest_time > 0);
}

TEST_CASE("AnalyticsEventStore: pending_count and total_emitted", "[pg][analytics_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    auto pending0 = store.pending_count();
    REQUIRE(pending0.has_value());
    REQUIRE(*pending0 == 0);
    REQUIRE(store.total_emitted() == 0);

    for (int i = 0; i < 5; ++i) {
        AnalyticsEvent event;
        event.event_type = "test.event";
        store.emit(event);
    }

    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 5);
    CHECK(store.total_emitted() == 5);
}

// ── Drain to Sink (claim / send / revert, ADR-0049) ────────────────────────

TEST_CASE("AnalyticsEventStore: drain to mock sink", "[pg][analytics_store][drain]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    // Use drain_interval=1 for fast test
    AnalyticsEventStore store(pool, /*drain_interval=*/1, /*batch_size=*/100);
    REQUIRE(store.is_open());

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    for (int i = 0; i < 3; ++i) {
        AnalyticsEvent event;
        event.event_type = "test.event";
        event.correlation_id = "id-" + std::to_string(i);
        store.emit(event);
    }

    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 3);

    store.start_drain();
    // Wait for drain cycle
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    auto received = sink_ptr->received();
    REQUIRE(received.size() == 3);
    pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 0);
}

TEST_CASE("AnalyticsEventStore: drained events not re-sent", "[pg][analytics_store][drain]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool, 1, 100);
    REQUIRE(store.is_open());

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    AnalyticsEvent event;
    event.event_type = "test.once";
    store.emit(event);

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    // Should have been sent exactly once
    auto received = sink_ptr->received();
    REQUIRE(received.size() == 1);
    CHECK(received[0].event_type == "test.once");

    // Total emitted is still 1
    CHECK(store.total_emitted() == 1);
    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 0);
}

TEST_CASE("AnalyticsEventStore: sink failure reverts claim, event stays pending",
          "[pg][analytics_store][drain]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool, 1, 100);
    REQUIRE(store.is_open());

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    sink_ptr->set_should_succeed(false);
    store.add_sink(std::move(sink));

    AnalyticsEvent event;
    event.event_type = "test.fail";
    store.emit(event);

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    // Sink received the batch but failed — phase C reverts the claim, so the
    // event is still pending for the next tick to retry.
    CHECK(sink_ptr->send_count() > 0);
    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 1);
}

// Governance Gate 3 quality-engineer finding, 2026-08-16: a batch row whose
// event_json fails to parse is claimed (drained=true) in phase A but never
// added to the send/revert sets — it drains exactly once and is dropped,
// unlike the SQLite predecessor which re-selected (and re-failed to parse)
// the same poison-pill row every tick, forever. Emit two events, corrupt one
// directly, and confirm: the sink receives only the valid one, and nothing
// is left pending after one drain tick (the corrupt row is gone, not stuck).
TEST_CASE("AnalyticsEventStore: a batch row with unparseable JSON drains once and is dropped",
          "[pg][analytics_store][drain]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool, 1, 100);
    REQUIRE(store.is_open());

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    AnalyticsEvent good;
    good.event_type = "test.valid";
    store.emit(good);
    AnalyticsEvent bad;
    bad.event_type = "test.poison";
    store.emit(bad);

    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    REQUIRE(*pending == 2);

    exec_sql(db.dsn(), "UPDATE analytics_event_store.analytics_buffer SET event_json = "
                       "'{not valid json' WHERE event_json LIKE '%test.poison%'");

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    auto received = sink_ptr->received();
    REQUIRE(received.size() == 1);
    CHECK(received[0].event_type == "test.valid");

    pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 0); // the poison row is gone, not stuck retrying forever
}

// Governance Gate 3 quality-engineer finding, 2026-08-16 (copy of
// test_response_store.cpp's "reap_expired skips quietly when a sibling holds
// the advisory lock" — same primitive, different key). Single-sweeper
// exclusion: a sibling replica already draining holds the fleet-wide
// try-advisory-xact-lock, so this store's own drain tick must skip quietly —
// never claim, never send, never revert.
TEST_CASE("AnalyticsEventStore: drain skips quietly when a sibling holds the advisory lock",
          "[pg][analytics_store][drain]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool, 1, 100);
    REQUIRE(store.is_open());

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    AnalyticsEvent event;
    event.event_type = "test.locked";
    store.emit(event);

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult begin{PQexec(locker.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        PgResult lock{PQexec(locker.get(),
                             "SELECT pg_advisory_xact_lock(hashtextextended("
                             "'analytics_event_store:drain', 0))")};
        REQUIRE(lock.status() == PGRES_TUPLES_OK);
    }

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    CHECK(sink_ptr->send_count() == 0); // never reached phase B — the lock was held
    auto pending = store.pending_count();
    REQUIRE(pending.has_value());
    CHECK(*pending == 1); // nothing claimed — the sibling held the lock

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.status() == PGRES_COMMAND_OK);
}

TEST_CASE("AnalyticsEventStore: concurrent emit from multiple threads",
          "[pg][analytics_store][threads]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    constexpr int kThreads = 4;
    // Pool sized above the writer thread count so bounded try_acquire_for
    // never contends its way into a fail-soft drop under normal local-test
    // latency — this test asserts an EXACT total_emitted count.
    PgPool pool{{.conninfo = db.dsn(), .size = kThreads + 2}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    constexpr int kPerThread = 25;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&store, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                AnalyticsEvent event;
                event.event_type = "thread.event";
                event.correlation_id = std::to_string(t) + "-" + std::to_string(i);
                store.emit(event);
            }
        });
    }
    for (auto& th : threads)
        th.join();

    CHECK(store.total_emitted() == kThreads * kPerThread);
}

TEST_CASE("AnalyticsEventStore: concurrent emit and query_recent",
          "[pg][analytics_store][threads]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    std::atomic<bool> done{false};
    constexpr int kEmits = 100;

    // Writer thread
    std::thread writer([&]() {
        for (int i = 0; i < kEmits; ++i) {
            AnalyticsEvent event;
            event.event_type = "race.test";
            store.emit(event);
        }
        done = true;
    });

    // Reader thread — exercises query_recent, pending_count, total_emitted
    std::thread reader([&]() {
        while (!done.load()) {
            auto results = store.query_recent(10);
            auto pending = store.pending_count();
            auto total = store.total_emitted();
            (void)results;
            (void)pending;
            (void)total;
        }
    });

    writer.join();
    reader.join();

    CHECK(store.total_emitted() == kEmits);
}

TEST_CASE("AnalyticsEventStore: stress test — high contention",
          "[pg][analytics_store][threads][stress]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    constexpr int kWriterThreads = 8;
    constexpr int kReaderThreads = 4;
    // Sized above writers + readers combined (advisor guidance) so bounded
    // try_acquire_for never fail-soft-drops an emit under ordinary local-test
    // contention — this test asserts an EXACT total_emitted count.
    PgPool pool{{.conninfo = db.dsn(), .size = kWriterThreads + kReaderThreads + 4}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    constexpr int kEventsPerWriter = 250;
    std::atomic<bool> writers_done{false};
    std::atomic<int> total_reads{0};

    // 8 writer threads hammering emit()
    std::vector<std::thread> writers;
    for (int t = 0; t < kWriterThreads; ++t) {
        writers.emplace_back([&store, t]() {
            for (int i = 0; i < kEventsPerWriter; ++i) {
                AnalyticsEvent event;
                event.event_type = "stress.write";
                event.correlation_id = std::to_string(t) + "-" + std::to_string(i);
                store.emit(event);
            }
        });
    }

    // 4 reader threads hammering query_recent, pending_count, total_emitted
    std::vector<std::thread> readers;
    for (int t = 0; t < kReaderThreads; ++t) {
        readers.emplace_back([&store, &writers_done, &total_reads]() {
            while (!writers_done.load()) {
                auto results = store.query_recent(10);
                auto pending = store.pending_count();
                auto total = store.total_emitted();
                (void)results;
                (void)pending;
                (void)total;
                total_reads.fetch_add(1);
            }
            // Final read after writers finish — total must be consistent
            auto final_total = store.total_emitted();
            (void)final_total;
        });
    }

    for (auto& th : writers)
        th.join();
    writers_done = true;
    for (auto& th : readers)
        th.join();

    CHECK(store.total_emitted() == kWriterThreads * kEventsPerWriter);
    CHECK(total_reads.load() > 0); // readers actually ran concurrently
}

TEST_CASE("AnalyticsEvent: event_time auto-stamped by emit", "[pg][analytics_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool);
    REQUIRE(store.is_open());

    AnalyticsEvent event;
    event.event_type = "test.autotime";
    // event_time left at 0 — should be stamped by emit()
    store.emit(event);

    auto results = store.query_recent();
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].event_time > 0);
    CHECK((*results)[0].ingest_time > 0);
    CHECK((*results)[0].event_time == (*results)[0].ingest_time);
}

TEST_CASE("AnalyticsEventStore: stop_drain() latches shutdown -- emit/start_drain refuse "
          "pool_ access afterward, reads stay answerable "
          "(PR #3350 review regression guard, fjarvis/security-guardian/cpp-safety/"
          "architect, 2026-08-20)",
          "[pg][analytics_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, analytics_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AnalyticsEventStore store(pool, /*drain_interval=*/1, /*batch_size=*/100);
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    // A pre-shutdown emit must still work normally.
    AnalyticsEvent before;
    before.event_type = "test.pre_shutdown";
    store.emit(before);
    auto pending_before = store.pending_count();
    REQUIRE(pending_before.has_value());
    CHECK(*pending_before == 1);

    // stop_drain() with no drain thread ever started is a plain latch-set —
    // this is exactly the AnalyticsEventStore-internal half of what a real
    // ServerImpl::stop() does (server.cpp calls stop_drain() long before
    // pg_pool_.reset(); this test proves the latch's own contract without
    // needing to construct a whole ServerImpl).
    store.stop_drain();

    // emit() must drop via the shutdown path, never touch pool_.
    AnalyticsEvent after;
    after.event_type = "test.post_shutdown";
    store.emit(after);
    CHECK(metrics
              .counter("yuzu_server_analytics_emit_dropped_total",
                       {{"reason", "store_not_open"}})
              .value() == 1);

    // Reads must stay answerable after stop_drain() -- they are NOT gated
    // on shutting_down_ (a first cut of this fix gated them too, which
    // broke this exact pattern: reading pending_count() right after
    // stop_drain() to observe final state is this store's own established
    // drain-test convention, exercised throughout this file). The pending
    // event from before shutdown must still be visible.
    auto pending_after = store.pending_count();
    REQUIRE(pending_after.has_value());
    CHECK(*pending_after == 1);
    auto recent_after = store.query_recent();
    REQUIRE(recent_after.has_value());
    CHECK(recent_after->size() == 1);

    // start_drain() is sticky-stop: a caller after shutdown must not spin up
    // a fresh drain thread against a pool the owner may already be tearing
    // down. Deliberately never called start_drain() before stop_drain()
    // above (keeps this deterministic instead of racing a real drain
    // cycle) — so the sink must still be empty: completing this call
    // without hanging/crashing plus zero sink activity is the guard.
    store.start_drain();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK(sink_ptr->received().empty());
}
