// test_command_outbox_delivery.cpp — WS-3 slice 3.3 (ADR-2002 §6): the
// leader-gated delivery loop that drains the command outbox. Real Postgres
// store + real fenced LeaderElector; the dispatch/authority seams are faked so
// the test binds the loop's DECISIONS:
//   * a pending occurrence is dispatched with its STABLE command_id and marked
//     sent (so it is not re-driven);
//   * re-authorization at send time — arming denied → mark_failed, no dispatch;
//   * a transient containment_unreadable → reschedule (stays pending, backed
//     off, attempts bumped), never mark_sent;
//   * approval provenance carried from the row's approval_id is stamped on the
//     re-resolved caller (#1398);
//   * not-leader (elector resigned) → the loop no-ops (nothing dispatched).

#include "audit_store.hpp"
#include "command_outbox_delivery.hpp"
#include "command_outbox_store.hpp"
#include "execution_tracker.hpp"
#include "leader_elector.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

yuzu::test::PgTestTemplate delivery_tpl{"cmdoutboxdeliver", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::CommandOutboxStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("delivery template: outbox store failed to migrate");
    yuzu::server::LeaderElector le{
        yuzu::server::LeaderElector::Config{.dsn = dsn, .holder_id = "template"}};
    if (!le.is_open())
        throw std::runtime_error("delivery template: leader_elector failed to migrate");
}};

// Records what the fake dispatch fn saw, and lets a test steer the outcome.
struct DispatchProbe {
    int calls{0};
    std::string last_command_id;
    std::string last_plugin;
    std::string last_action;
    ApprovalProvenance last_provenance{ApprovalProvenance::None};
    ConfinedDispatchOutcome next{}; // returned each call; test sets .sent etc.
    std::function<void()> on_call;  // #3678: runs INSIDE dispatch_fn, to observe state at send time
};

class DeliveryPg {
public:
    // #4982 round 6: `lock_timeout_ms` defaults to the pool's own normal
    // 10000ms; a round-6 fault-injection test (below) passes a short value so
    // a row lock it deliberately holds open makes the outbox store's own
    // write fail FAST (a `55P03 lock_timeout` query error) rather than
    // hanging for the default 10s — the same technique the round-2 Fix-5
    // test above already uses for `ExecutionTracker`'s own pool.
    explicit DeliveryPg(int lock_timeout_ms = 10000) {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(delivery_tpl);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{
            .conninfo = db_->dsn(), .size = 4, .lock_timeout_ms = lock_timeout_ms});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<CommandOutboxStore>(*pool_);
        REQUIRE(store_->is_open());
        elector_ = std::make_unique<LeaderElector>(
            LeaderElector::Config{.dsn = db_->dsn(), .holder_id = "test-leader"});
        REQUIRE(elector_->is_open());
        REQUIRE(elector_->try_acquire());
        epoch_ = *elector_->epoch();
    }
    DeliveryPg(const DeliveryPg&) = delete;
    DeliveryPg& operator=(const DeliveryPg&) = delete;

    CommandOutboxStore& store() { return *store_; }
    const std::string& dsn() const { return db_->dsn(); }
    LeaderElector& elector() { return *elector_; }
    std::int64_t epoch() const { return epoch_; }
    static std::string lock() { return kServerBackgroundLeaderLock; }

    // #3678 (R4): the fleet-wide dispatch sequence the delivery loop reads. `seq` is what the
    // tests advance; nullopt models an unreadable sequence; `seq_wired=false` models a server
    // that never wired the reader (the loop must HOLD, not send).
    std::optional<std::int64_t> seq{1000};
    bool seq_wired{true};
    // Runs INSIDE the sequence read, i.e. between list_pending's snapshot and the stamp write:
    // lets a test model another writer stamping the row first.
    std::function<void()> before_seq_read;
    // The reading process's own unrecorded-dispatch count (the second term of the position).
    std::int64_t unrecorded{0};
    CommandOutboxDelivery::DispatchSeqFn seq_fn() {
        if (!seq_wired)
            return {};
        return [this]() -> std::optional<yuzu::server::DispatchPosition> {
            if (before_seq_read)
                before_seq_read();
            if (!seq)
                return std::nullopt;
            return yuzu::server::DispatchPosition{*seq, unrecorded};
        };
    }
    // Overwrite a row's stamp directly (models a stamp written by an earlier term/process).
    void set_stamp(const std::string& occ, std::int64_t shared, std::int64_t unrec,
                   std::int64_t epoch) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    conn.get(),
                    "UPDATE command_outbox_store.outbox SET dispatch_seq_first_sent=$2::bigint, "
                    "dispatch_unrecorded_first_sent=$3::bigint, dispatch_stamp_epoch=$4::bigint "
                    "WHERE occurrence_id=$1",
                    std::vector<std::string>{occ, std::to_string(shared), std::to_string(unrec),
                                             std::to_string(epoch)})
                    .status() == PGRES_COMMAND_OK);
    }
    yuzu::server::pg::PgPool& pool() { return *pool_; }

    // Make a backed-off pending row due again (reschedule pushes next_attempt_at out by 30 s).
    void make_due(const std::string& occ) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    conn.get(),
                    "UPDATE command_outbox_store.outbox SET next_attempt_at = now() "
                    "WHERE occurrence_id=$1",
                    std::vector<std::string>{occ})
                    .status() == PGRES_COMMAND_OK);
    }

    // Raw read of one text/bigint column; "<null>" for SQL NULL, "<absent>" for no such row.
    std::string raw_col(const std::string& occ, const char* column) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql = std::string("SELECT ") + column +
                                " FROM command_outbox_store.outbox WHERE occurrence_id=$1";
        yuzu::server::pg::PgResult r =
            yuzu::server::pg::exec_params(conn.get(), sql.c_str(), std::vector<std::string>{occ});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) != 1)
            return "<absent>";
        return PQgetisnull(r.get(), 0, 0) ? std::string("<null>")
                                           : std::string(PQgetvalue(r.get(), 0, 0));
    }

    // Build a delivery loop whose dispatch/arming seams the test controls.
    // `metrics` is optional (defaulted) - most tests here assert on the
    // OutboxCommand state machine, not on observability, and don't need it.
    CommandOutboxDelivery make_delivery(DispatchProbe& probe, bool arming_allow,
                                        yuzu::MetricsRegistry* metrics = nullptr,
                                        std::int64_t horizon =
                                            yuzu::kMaxOutboxRedeliveryHorizonCommands,
                                        yuzu::server::AuditStore* audit = nullptr) {
        CommandOutboxDelivery::Deps d;
        d.outbox = store_.get();
        d.audit_store = audit;
        d.dispatch_seq_fn = seq_fn(); // #3678 R4: required, fail-closed
        d.redelivery_horizon_commands = horizon;
        d.leader = elector_.get();
        d.metrics = metrics;
        d.dispatch_fn = [&probe](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>&, const std::string&,
                                 const std::unordered_map<std::string, std::string>&,
                                 const std::string&, const DispatchCaller& caller,
                                 const std::string& command_id) {
            probe.calls++;
            probe.last_command_id = command_id;
            probe.last_plugin = plugin;
            probe.last_action = action;
            probe.last_provenance = caller.approval_provenance;
            if (probe.on_call)
                probe.on_call();
            auto out = probe.next;
            out.command_id = command_id;
            return out;
        };
        d.resolve_caller = [](const std::string& principal) {
            DispatchCaller c;
            c.principal = principal;
            return c;
        };
        d.arming_check = [arming_allow](const std::string&, const std::string&,
                                        const std::string&) { return arming_allow; };
        return CommandOutboxDelivery{std::move(d)};
    }

    OutboxEnqueueRequest req(const std::string& occ, const std::string& cmd,
                             const std::string& approval = "") {
        OutboxEnqueueRequest r;
        r.occurrence_id = occ;
        r.command_id = cmd;
        r.source = "schedule_runner";
        r.plugin = "power_health";
        r.action = "report";
        r.scope_expr = "tag:linux";
        r.parameters = R"({"k":"v"})";
        r.execution_id = "exec-1";
        r.principal = "svc-scheduler";
        r.approval_id = approval;
        return r;
    }

    std::string raw_state(const std::string& occ) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p = occ.c_str();
        yuzu::server::pg::PgResult r{
            PQexecParams(conn.get(),
                         "SELECT state FROM command_outbox_store.outbox WHERE occurrence_id=$1", 1,
                         nullptr, &p, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get()) == 1 ? PQgetvalue(r.get(), 0, 0) : std::string("<absent>");
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<CommandOutboxStore> store_;
    std::unique_ptr<LeaderElector> elector_;
    std::int64_t epoch_{0};
};

} // namespace

TEST_CASE("CommandOutboxDelivery[pg]: delivers a pending occurrence with its stable command_id",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-1", "cmd-STABLE"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 3;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(probe.last_command_id == "cmd-STABLE"); // the stored id, not a fresh mint
    CHECK(probe.last_plugin == "power_health");
    CHECK(fx.raw_state("occ-1") == "sent"); // not re-driven

    // A second tick finds nothing pending — no double dispatch.
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: arming denied at delivery fails the occurrence, no dispatch",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-deny", "cmd-x"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/false);
    loop.tick();

    CHECK(probe.calls == 0); // re-authorization denied before any send
    CHECK(fx.raw_state("occ-deny") == "failed");
}

TEST_CASE("CommandOutboxDelivery[pg]: containment_unreadable reschedules, never marks sent",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-retry", "cmd-r"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.containment_unreadable = true;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-retry") == "pending"); // still owed, backed off
    // Backed off (next_attempt_at pushed) → not due, so a same-second re-tick
    // does not redeliver.
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: route_unreadable reschedules, never marks sent (WS-4 "
          "4.2b Task D — mirrors containment_unreadable exactly)",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-route-retry", "cmd-rr"), fx.lock(),
                                         fx.epoch()) == OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.route_unreadable = true;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    // A degraded gateway routing-directory read is NOT a delivered
    // occurrence -- same as containment_unreadable, the row stays pending
    // rather than being marked sent/no_agents (which would silently drop a
    // command that never actually reached the wire).
    CHECK(fx.raw_state("occ-route-retry") == "pending"); // still owed, backed off
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: os_gate_unreadable reschedules, never marks sent (#5294 "
          "-- presence unreadable while a per-OS kill switch is OFF)",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-os-retry", "cmd-or"), fx.lock(),
                                         fx.epoch()) == OutboxEnqueueOutcome::Enqueued);

    yuzu::MetricsRegistry metrics;
    const auto cause_value = [&] {
        return metrics
            .counter("yuzu_server_command_outbox_deliver_retry_cause_total",
                     {{"cause", "os_gate_unreadable"}})
            .value();
    };
    CHECK(cause_value() == 0.0);

    DispatchProbe probe;
    probe.next.os_gate_unreadable = true; // refused before targeting: sent == 0, no per-id data
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics);
    loop.tick();

    CHECK(cause_value() == 1.0);
    CHECK(probe.calls == 1);
    // Not a delivered occurrence: marking it sent/skipped would silently drop
    // a scheduled command on a transient presence read.
    CHECK(fx.raw_state("occ-os-retry") == "pending");
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: carries approval provenance from the row",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-appr", "cmd-a", /*approval=*/"ticket-77"),
                                         fx.lock(), fx.epoch()) == OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 1;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();
    CHECK(probe.last_provenance == ApprovalProvenance::Ticket);

    // An occurrence with no approval_id stamps None.
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-noappr", "cmd-b"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    loop.tick();
    CHECK(probe.last_provenance == ApprovalProvenance::None);
}

TEST_CASE("CommandOutboxDelivery[pg]: a malformed payload fails the occurrence, no dispatch",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    // Enqueue an occurrence whose agent_ids is not valid JSON — decode_payload
    // must fail CLOSED (mark_failed), never dispatch with a silently-empty target
    // set. (safety-S1)
    auto bad = fx.req("occ-bad", "cmd-bad");
    bad.agent_ids = "{not-json";
    REQUIRE(fx.store().claim_and_enqueue(bad, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 0); // decode failed before any send
    CHECK(fx.raw_state("occ-bad") == "failed");
}

// json-dump-depth-guard fix (#2437-class): `c.parameters` is sourced from
// ScheduleRunner's `parameter_values`. Schedule CREATION already guards this
// text (schedule_routes.cpp:94), but a row written before that write-side
// guard shipped, or via any other write path that bypasses it, still reaches
// this READ path on every tick with no operator action in the loop at all.
TEST_CASE("CommandOutboxDelivery[pg]: a parameters payload nested past the depth guard fails "
          "the occurrence; another pending occurrence in the same tick still delivers normally",
          "[command_outbox][pg][delivery][depth]") {
    DeliveryPg fx;
    // A raw string, never materialised as a live nlohmann::json object at
    // this depth. kMcpMaxJsonDepth is 32; the 40-deep array below is
    // comfortably past it and still trivially safe to construct/parse/dump
    // directly in this test process, orders of magnitude short of the
    // ~100,000-level depth that actually SIGSEGVs the real background worker
    // this guard exists to protect.
    auto poisoned = fx.req("occ-depth", "cmd-depth");
    poisoned.parameters = R"({"nested":)" + std::string(40, '[') + std::string(40, ']') + R"(})";
    REQUIRE(fx.store().claim_and_enqueue(poisoned, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // A second, healthy occurrence enqueued right after: the tick must not
    // stop processing the rest of the batch just because one occurrence up
    // front is poisoned.
    auto healthy = fx.req("occ-depth-ok", "cmd-depth-ok");
    REQUIRE(fx.store().claim_and_enqueue(healthy, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 1;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(fx.raw_state("occ-depth") == "failed");  // marked failed, never dispatched
    CHECK(fx.raw_state("occ-depth-ok") == "sent");  // the OTHER occurrence still delivered
    CHECK(probe.calls == 1);                        // only the healthy occurrence dispatched
    CHECK(probe.last_command_id == "cmd-depth-ok");
}

TEST_CASE("CommandOutboxDelivery[pg]: a repeated tick against the same depth-poisoned "
          "occurrence behaves identically each time, no crash, no re-drive",
          "[command_outbox][pg][delivery][depth]") {
    DeliveryPg fx;
    auto poisoned = fx.req("occ-depth-repeat", "cmd-depth-repeat");
    poisoned.parameters = R"({"nested":)" + std::string(40, '[') + std::string(40, ']') + R"(})";
    REQUIRE(fx.store().claim_and_enqueue(poisoned, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);

    // mark_failed is a PERMANENT transition (mirrors the malformed-payload
    // case above): once failed, list_pending no longer returns it, so a
    // second/third tick must not re-process, re-count, or re-dispatch it (no
    // unbounded retry loop for this failure class).
    for (int attempt = 0; attempt < 3; ++attempt) {
        INFO("attempt " << attempt);
        loop.tick();
        CHECK(fx.raw_state("occ-depth-repeat") == "failed");
        CHECK(probe.calls == 0);  // never dispatched, on any attempt
    }
}

// Governance Gate 4/6 finding: the bare yuzu_server_command_outbox_deliver_decode_failed_total
// counter fires identically for a depth-exceeded rejection and a genuinely
// malformed payload, contradicting its own documented meaning
// (docs/user-manual/metrics.md said "a malformed row failed to decode"). This
// proves the labeled companion counter distinguishes the two causes, mirroring
// the structurally identical gateway_service_impl.cpp fix
// (outcome="rejected_depth").
TEST_CASE("CommandOutboxDelivery[pg]: depth-exceeded and genuinely-malformed payloads increment "
          "DISTINCT cause labels on the companion counter, not the same one",
          "[command_outbox][pg][delivery][depth][observability]") {
    DeliveryPg fx;
    yuzu::MetricsRegistry metrics;

    auto poisoned = fx.req("occ-depth-metric", "cmd-depth-metric");
    poisoned.parameters = R"({"nested":)" + std::string(40, '[') + std::string(40, ']') + R"(})";
    REQUIRE(fx.store().claim_and_enqueue(poisoned, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    auto malformed = fx.req("occ-malformed-metric", "cmd-malformed-metric");
    malformed.parameters = "not json{{{";
    REQUIRE(fx.store().claim_and_enqueue(malformed, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    CHECK(metrics
              .counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                       {{"cause", "payload_depth_exceeded"}})
              .value() == 0.0);
    CHECK(metrics
              .counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                       {{"cause", "payload_decode_failed"}})
              .value() == 0.0);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics);
    loop.tick();

    CHECK(fx.raw_state("occ-depth-metric") == "failed");
    CHECK(fx.raw_state("occ-malformed-metric") == "failed");
    CHECK(metrics
              .counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                       {{"cause", "payload_depth_exceeded"}})
              .value() == 1.0);
    CHECK(metrics
              .counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                       {{"cause", "payload_decode_failed"}})
              .value() == 1.0);
    // The pre-existing bare counter still fires for both causes unchanged -
    // this is what created the ambiguity the labeled counter above resolves.
    CHECK(metrics.counter("yuzu_server_command_outbox_deliver_decode_failed_total").value() ==
          2.0);
}

TEST_CASE("CommandOutboxDelivery[pg]: does nothing when this replica is not leader",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-nolead", "cmd-n"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    fx.elector().resign(); // epoch() now nullopt

    loop.tick();
    CHECK(probe.calls == 0);
    CHECK(fx.raw_state("occ-nolead") == "pending"); // left for the true leader
}

// #4982 fix round 2 (Fix 5): the identical swallowed-mark_cancelled-failure
// pattern this issue's own metric was built to observe (REST/MCP, Part A)
// also existed, uninstrumented, at this file's five call sites — none of
// them wired an ExecutionTracker in this file's own tests above (every
// `make_delivery` call leaves `d.execution_tracker` null, so those tests
// never reach the code this fix touches). This test wires a REAL
// ExecutionTracker (a second PgPool over the SAME already-migrated database,
// with a short lock_timeout_ms so a forced lock contention fails fast rather
// than hangs — the established technique from
// test_rest_result_sets_async.cpp's own #4982 tests) and forces the
// "authority_denied" branch's mark_cancelled to genuinely FAIL by locking
// execution_tracker.executions before ticking.
TEST_CASE("CommandOutboxDelivery[pg]: mark_cancelled failing after an "
          "authority-denied delivery is now observable via "
          "yuzu_exec_tracker_bookkeeping_failed_total{op=mark_cancelled,surface=outbox} "
          "(#4982 fix round 2, Fix 5)",
          "[command_outbox][pg][delivery][4982]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{
        {.conninfo = fx.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    auto req = fx.req("occ-deny-metric", "cmd-deny-metric");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // Lock the executions row's table from a raw connection BEFORE ticking —
    // the authority_denied branch never calls dispatch_fn, so there is no
    // mid-flow hook to lock from; locking up front is equivalent here since
    // mark_failed (a different schema, command_outbox_store) is unaffected.
    yuzu::server::pg::PgConn locker{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE execution_tracker.executions IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    yuzu::MetricsRegistry metrics;
    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.metrics = &metrics;
    d.dispatch_fn = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&, const DispatchCaller&, const std::string&) {
        return ConfinedDispatchOutcome{};
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return false; // deny — the authority_denied branch, no dispatch attempted
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    CHECK(fx.raw_state("occ-deny-metric") == "failed"); // mark_failed itself unaffected
    CHECK(metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "mark_cancelled"}, {"surface", "outbox"}})
              .value() == 1.0);

    // The execution row is still 'running' — mark_cancelled genuinely failed.
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->status == "running");
}

// PR #5226 review round 2 (Doomgoose, minor): decline_or_cancel_exec used to
// call the plain bool-returning mark_cancelled and treat ANY `false` as a
// failure — conflating a real pool/statement failure with the benign no-op
// of a row that reached a terminal state via some OTHER writer before this
// call ever ran (an operator cancel, the stuck-reap sweep, a different
// occurrence's own cancel of the same execution_id). This drives the
// authority_denied branch against an execution ALREADY cancelled by a
// direct `mark_cancelled` call made before the tick, so decline_or_cancel_exec
// sees a genuine no-op, not a failure — and asserts the bookkeeping-failure
// counter does NOT fire for it (the pre-fix behaviour would have incremented
// it and logged an error for a row that was never actually broken).
TEST_CASE("CommandOutboxDelivery[pg]: an already-terminal execution reaching "
          "the authority_denied cancel path does NOT count as a bookkeeping "
          "failure (#5226 review round 2)",
          "[command_outbox][pg][delivery][4982][5226]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{
        {.conninfo = fx.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    // Some OTHER writer (an operator, the stuck-reap sweep) got here first.
    REQUIRE(tracker.mark_cancelled(*exec_id, "someone-else"));
    auto pre = tracker.get_execution(*exec_id);
    REQUIRE(pre.has_value());
    REQUIRE(pre->status == "cancelled");

    auto req = fx.req("occ-already-terminal", "cmd-already-terminal");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    yuzu::MetricsRegistry metrics;
    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.metrics = &metrics;
    d.dispatch_fn = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&, const DispatchCaller&, const std::string&) {
        return ConfinedDispatchOutcome{};
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return false; // deny — the authority_denied branch, no dispatch attempted
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    CHECK(fx.raw_state("occ-already-terminal") == "failed");
    // The core assertion: this must stay at 0, not 1 — nothing failed.
    CHECK(metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "mark_cancelled"}, {"surface", "outbox"}})
              .value() == 0.0);

    // Still cancelled, by the earlier writer — untouched by this tick.
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->status == "cancelled");
}

// #4982 round 5 (both round-4 adversarial reviewers, SHOULD): no test in this
// file previously drove `deliver()`'s `bookkeep_target && outcome.sent > 0`
// branch end-to-end. Every `fx.make_delivery(...)` call above leaves
// `d.execution_tracker` null, so `bookkeep_target` is always false and the
// plain `mark_sent` branch is all any of those tests exercise; the round-2
// Fix-5 test just above wires a real `ExecutionTracker` but only for the
// DENIED branch (arming_check returns false — dispatch_fn is never called,
// so `outcome.sent` never matters). `test_command_outbox_store.cpp` tests
// `CommandOutboxStore::mark_sent_with_target` directly, and
// `test_execution_tracker.cpp`'s #4982 round 3 test manually replicates its
// two statements via raw SQL on a second connection — neither proves
// `command_outbox_delivery.cpp`'s own call site actually calls the atomic
// method for a genuine dispatch. A regression reverting that call site back
// to a plain `mark_sent` + a separate `set_agents_targeted` (leaving the new
// `CommandDeliveryFinalizationOwner::mark_sent_with_target` itself intact but
// unused) would leave every test in this file green before this one.
//
// This test wires a REAL `ExecutionTracker` (a second `PgPool` over the SAME
// already-migrated database, mirroring the Fix-5 test's own technique),
// creates a REAL running execution row, and drives an actual successful
// dispatch (`sent > 0`) through `CommandOutboxDelivery::deliver()`/`tick()`,
// asserting BOTH halves of the atomic write land together: the outbox row
// reaches `state='sent'` AND `agents_targeted` reflects the real dispatched
// count. This DOES pin the call site to the atomic method's correct FINAL
// output, and does catch a regression that drops the target-count write
// entirely (that leaves `agents_targeted` at 0, which this test would catch).
//
// #4982 round 6 correction (Kimi, round-6 adversarial review — a real,
// confirmed defect in the ORIGINAL round-5 text this comment used to carry):
// this test does NOT, on its own, prove atomicity, and the round-5 commit
// message's claim that it was "empirically verified to FAIL ... when the
// call site is temporarily reverted to the old two-call split" was checked
// and is FALSE. This test is single-threaded with nothing creating a window
// for a third party to observe an intermediate state, so a sequential
// `mark_sent()` then `ExecutionTracker::set_agents_targeted()` — with NO
// atomic wrapping at all — produces the exact same final row this test
// checks (`state='sent'`, `agents_targeted=4`) as the real atomic call. The
// round-6 test immediately below this one closes that gap: it forces the
// SECOND write inside `mark_sent_with_target`'s transaction to fail and
// asserts the FIRST write (the sent-transition) rolls back WITH it — a
// real-call-site proof of atomicity a happy-path final-state check like this
// one cannot provide. See that test's own comment for what was actually
// verified, and how.
TEST_CASE("CommandOutboxDelivery[pg]: a genuine successful dispatch (sent>0) commits the outbox "
          "sent-transition AND the execution's real agents_targeted atomically, via the actual "
          "delivery call site (#4982 round 5)",
          "[command_outbox][pg][delivery][4982]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{{.conninfo = fx.dsn(), .size = 2}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    auto req = fx.req("occ-target-live", "cmd-target-live");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 4;

    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.dispatch_fn = [&probe](const std::string& plugin, const std::string& action,
                             const std::vector<std::string>&, const std::string&,
                             const std::unordered_map<std::string, std::string>&,
                             const std::string&, const DispatchCaller& caller,
                             const std::string& command_id) {
        probe.calls++;
        probe.last_command_id = command_id;
        probe.last_plugin = plugin;
        probe.last_action = action;
        probe.last_provenance = caller.approval_provenance;
        auto out = probe.next;
        out.command_id = command_id;
        return out;
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return true; // re-authorization passes — the dispatch proceeds
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-target-live") == "sent");

    // Both halves landed in the row's final state: the outbox row is 'sent'
    // AND the execution's real target count is set. This is the correct
    // happy-path OUTPUT of the atomic call site — see the #4982 round-6
    // correction above this test for what it does NOT prove (call-site
    // atomicity under a failure) and where that proof actually lives.
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->agents_targeted == 4);
    CHECK(after->status == "running"); // untouched — a successful dispatch, not a cancel

    // A second tick finds nothing pending — no double dispatch, no re-write
    // of the target count.
    loop.tick();
    CHECK(probe.calls == 1);
    auto still = tracker.get_execution(*exec_id);
    REQUIRE(still.has_value());
    CHECK(still->agents_targeted == 4);
}

// #4982 round 6 (Kimi K1/Codex C2, round-6 adversarial review): the real
// call-site atomicity proof the test above cannot provide (see the #4982
// round-6 correction on its own comment). This forces the SECOND statement
// inside `mark_sent_with_target`'s transaction — `UPDATE
// execution_tracker.executions SET agents_targeted=... WHERE id=...` — to
// fail, and asserts the FIRST statement (the outbox `pending -> sent`
// transition) rolls back WITH it.
//
// Fault-injection technique: a raw connection takes a row-level `SELECT ...
// FOR UPDATE` lock on the execution row and holds it open (no COMMIT) across
// `loop.tick()`. `fx`'s own pool (where `mark_sent_with_target`'s write
// actually runs, via `CommandDeliveryFinalizationOwner{pool_}` sharing
// `CommandOutboxStore`'s pool) carries a short `lock_timeout_ms` so the
// blocked `UPDATE` fails fast (`55P03 lock_timeout`) instead of hanging —
// the SAME technique the round-2 Fix-5 test above already established for
// `ExecutionTracker`'s own pool. `tracker_pool` here also carries a short
// `lock_timeout_ms`, for the same reason: it is what a HYPOTHETICAL reverted
// two-call split would issue the second write through instead (see below).
//
// This is a genuine, real-call-site distinguishing test: it is only possible
// for the sent-transition to revert together with the failed target write if
// BOTH statements commit or roll back as ONE transaction. Under the old
// (pre-round-3) two-call split — `CommandOutboxStore::mark_sent()` as its own
// independent autocommit statement, followed by a SEPARATE
// `ExecutionTracker::set_agents_targeted()` call — `mark_sent()` commits on
// its own, unconditionally, before the second call even starts; a failure in
// the second call cannot un-commit the first. So under that split this test
// would observe the outbox row already `state='sent'` with `agents_targeted`
// still 0 — precisely the swallowed-bookkeeping race #4982 round 3 closed.
//
// Verified empirically, per this round's own required before/after
// discipline (not merely asserted): temporarily reverting
// `command_outbox_delivery.cpp`'s `deliver()` call site to that exact
// two-call split and rebuilding makes THIS test fail —
// `fx.raw_state("occ-target-race")` observed `"sent"` instead of the expected
// `"pending"` — while the test above it (checked at the same time) stays
// green under the same revert, exactly reproducing the round-5 false-claim
// gap this test exists to close. Reverting the temporary change back to the
// committed atomic call site makes this test pass again.
TEST_CASE("CommandOutboxDelivery[pg]: a genuine dispatch whose target-count write is forced to "
          "fail rolls the outbox sent-transition back WITH it, proving mark_sent_with_target's "
          "atomicity through the real delivery call site (#4982 round 6)",
          "[command_outbox][pg][delivery][4982]") {
    DeliveryPg fx{200}; // short lock_timeout_ms — see comment above

    yuzu::server::pg::PgPool tracker_pool{
        {.conninfo = fx.dsn(), .size = 2, .lock_timeout_ms = 200}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    auto req = fx.req("occ-target-race", "cmd-target-race");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // Take and hold the row lock BEFORE ticking, on a dedicated connection —
    // the second write inside `mark_sent_with_target`'s transaction will
    // block on this and time out.
    yuzu::server::pg::PgConn locker{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "SELECT id FROM execution_tracker.executions WHERE id=$1 FOR UPDATE",
                std::vector<std::string>{*exec_id})
                .status() == PGRES_TUPLES_OK);

    DispatchProbe probe;
    probe.next.sent = 4;

    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.dispatch_fn = [&probe](const std::string& plugin, const std::string& action,
                             const std::vector<std::string>&, const std::string&,
                             const std::unordered_map<std::string, std::string>&,
                             const std::string&, const DispatchCaller& caller,
                             const std::string& command_id) {
        probe.calls++;
        probe.last_command_id = command_id;
        probe.last_plugin = plugin;
        probe.last_action = action;
        probe.last_provenance = caller.approval_provenance;
        auto out = probe.next;
        out.command_id = command_id;
        return out;
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return true; // re-authorization passes — the dispatch proceeds
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // The wire send already happened (dispatch_fn was called) — harmless,
    // the agent's command_id dedup absorbs a re-drive next tick.
    CHECK(probe.calls == 1);

    // THE assertion: the sent-transition did NOT survive on its own — it
    // rolled back together with the failed target-count write, because both
    // are one transaction. A two-call split would leave this "sent".
    CHECK(fx.raw_state("occ-target-race") == "pending");

    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->agents_targeted == 0); // never written — rolled back with the sent-transition
    CHECK(after->status == "running");
}

// governance Gate 4 fix (unhappy-path, BLOCKING, independently discovered second
// path to the Gate 2 false-cancel class): the round-6 test above proves a genuine
// sent>0 dispatch whose target-count write fails rolls BOTH writes back, re-driving
// the occurrence next tick. This test proves the NEXT tick's own sent==0 branch
// correctly declines to cancel when the execution_id already carries a real
// agent_exec_status response from that earlier, genuinely-dispatched attempt --
// reproducing the scenario directly (seed a real response, then redrive to
// sent==0) rather than orchestrating the full two-tick rollback sequence.
TEST_CASE("CommandOutboxDelivery[pg]: a redrive to sent==0 does NOT cancel an "
          "execution that already has a real agent_exec_status response from an "
          "earlier dispatch attempt (governance Gate 4 fix)",
          "[command_outbox][pg][delivery][4982]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{{.conninfo = fx.dsn(), .size = 2}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    // Seed a REAL agent response, as if an earlier dispatch attempt genuinely
    // reached this agent before this occurrence's bookkeeping write failed and
    // rolled back (round 3's own atomic rollback-on-degrade design).
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.first_response_at = 1001;
    as.completed_at = 1002;
    as.exit_code = 0;
    tracker.update_agent_status(*exec_id, as);

    auto req = fx.req("occ-redrive-zero", "cmd-redrive-zero");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    yuzu::MetricsRegistry metrics;
    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.metrics = &metrics;
    d.dispatch_fn = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&, const DispatchCaller&, const std::string&) {
        return ConfinedDispatchOutcome{}; // sent==0 — the redrive's current zero-reach
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return true;
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    // mark_cancelled must NEVER have been called — the row stays 'running', not
    // 'cancelled', and no bookkeeping-failure metric fires (the guard short-
    // circuits before mark_cancelled is ever reached, it is not a failed call).
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->status == "running");
    CHECK(metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "mark_cancelled"}, {"surface", "outbox"}})
              .value() == 0.0);

    // The genuine response is still there, untouched.
    auto statuses = tracker.get_agent_statuses(*exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "success");

    // The occurrence itself still reaches a terminal outbox state (sent==0 is a
    // real, distinct outcome from a bookkeeping decision) — this fix only changes
    // whether the EXECUTION gets force-cancelled, not the outbox's own bookkeeping.
    CHECK(fx.raw_state("occ-redrive-zero") == "sent");
}

// governance sibling-sweep fix (security-guardian, BLOCKING, found by a
// systematic audit of every mark_cancelled call site in this file after the
// sent==0 fix above): the authority_denied branch had the identical gap —
// a redrive that reaches "authority revoked since enqueue" for an
// execution_id that already has a real agent_exec_status response from an
// EARLIER attempt (route_unreadable/containment_unreadable rescheduling even
// when that earlier attempt reached agents, or a mark_sent_with_target
// degrade rolling it back) must not force-cancel it either.
TEST_CASE("CommandOutboxDelivery[pg]: authority denied at redelivery does NOT "
          "cancel an execution that already has a real agent_exec_status "
          "response from an earlier dispatch attempt (governance sibling-"
          "sweep fix)",
          "[command_outbox][pg][delivery][4982]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{{.conninfo = fx.dsn(), .size = 2}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());

    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    // Seed a REAL agent response, as if an earlier dispatch attempt genuinely
    // reached this agent before authority was revoked and this occurrence
    // redrove into the authority_denied branch.
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.first_response_at = 1001;
    as.completed_at = 1002;
    as.exit_code = 0;
    tracker.update_agent_status(*exec_id, as);

    auto req = fx.req("occ-denied-with-response", "cmd-denied-with-response");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    yuzu::MetricsRegistry metrics;
    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.dispatch_seq_fn = fx.seq_fn(); // #3678 R4: required, fail-closed
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.metrics = &metrics;
    d.dispatch_fn = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&, const DispatchCaller&, const std::string&) {
        return ConfinedDispatchOutcome{};
    };
    d.resolve_caller = [](const std::string& principal) {
        DispatchCaller c;
        c.principal = principal;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return false; // authority revoked since enqueue
    };
    CommandOutboxDelivery loop{std::move(d)};
    loop.tick();

    // mark_cancelled must NEVER have been called.
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->status == "running");
    CHECK(metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "mark_cancelled"}, {"surface", "outbox"}})
              .value() == 0.0);

    auto statuses = tracker.get_agent_statuses(*exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "success");

    // The occurrence itself is still durably marked failed — the denial is
    // permanent at the outbox level regardless of the exec-cancel decision.
    CHECK(fx.raw_state("occ-denied-with-response") == "failed");
}


// ---------------------------------------------------------------------------------------------
// #3678 (R4): the redelivery horizon. A stable command_id re-sent after the agent's dedup ring
// could have evicted it re-executes, so a redrive is bounded by a COUNT of dispatch calls (the
// sequence ExecutionTracker exposes), stamped on the row before its first attempt.
// What these prove: the gate's decisions against a FAKE sequence and fake dispatch. What they do
// NOT prove: that a real agent absorbs a redrive at the production ring size -- that is the
// bound argued in command_replay_horizon.hpp, not something a unit test can observe.
//
// A retry that KEEPS its stamp is modelled as `route_unreadable` with `sent > 0` (some agents
// were reached, so the stamp guards a real send). `containment_unreadable` reaches nobody, so the
// stamp it wrote is cleared (tested separately).
// ---------------------------------------------------------------------------------------------

namespace {
void make_partial_send(DispatchProbe& probe) {
    probe.next.route_unreadable = true;
    probe.next.sent = 3;
}
} // namespace

TEST_CASE("CommandOutboxDelivery[pg]: the first send stamps the dispatch sequence BEFORE dispatch "
          "(#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-stamp", "cmd-stamp"), fx.lock(),
                                         fx.epoch()) == OutboxEnqueueOutcome::Enqueued);
    CHECK(fx.raw_col("occ-stamp", "dispatch_seq_first_sent") == "<null>");

    DispatchProbe probe;
    std::string stamp_seen_at_send;
    probe.on_call = [&] { stamp_seen_at_send = fx.raw_col("occ-stamp", "dispatch_seq_first_sent"); };
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(stamp_seen_at_send == "1000"); // committed before the wire send, not after
    CHECK(fx.raw_col("occ-stamp", "dispatch_stamp_epoch") == std::to_string(fx.epoch()));
    CHECK(fx.raw_col("occ-stamp", "dispatch_unrecorded_first_sent") == "0");
    CHECK(fx.raw_state("occ-stamp") == "sent");
}

TEST_CASE("CommandOutboxDelivery[pg]: a redrive is sent while inside the horizon (including with "
          "NO dispatch in between) and dead-lettered, audited and never sent AT the horizon "
          "(#3678)",
          "[command_outbox][pg][delivery][3678]") {
    constexpr std::int64_t kHorizon = 10;
    DeliveryPg fx;
    yuzu::server::AuditStore audit{fx.pool()};
    REQUIRE(audit.is_open());
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-h", "cmd-h", "abcdef0123456789"), fx.lock(),
                                         fx.epoch()) == OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    make_partial_send(probe); // first attempt: reaches some agents, retried -- the stamp stays
    yuzu::MetricsRegistry metrics;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics, kHorizon, &audit);
    loop.tick();
    REQUIRE(probe.calls == 1);
    REQUIRE(fx.raw_state("occ-h") == "pending");
    REQUIRE(fx.raw_col("occ-h", "dispatch_seq_first_sent") == "1000");

    // The common production case: a quiet fleet, so the sequence has NOT moved. Still sent.
    fx.make_due("occ-h");
    loop.tick();
    CHECK(probe.calls == 2);
    CHECK(fx.raw_state("occ-h") == "pending");

    // One short of the horizon: still redriven (and the stamp is NOT moved).
    fx.seq = 1000 + kHorizon - 1;
    fx.make_due("occ-h");
    loop.tick();
    CHECK(probe.calls == 3);
    CHECK(fx.raw_state("occ-h") == "pending");
    CHECK(fx.raw_col("occ-h", "dispatch_seq_first_sent") == "1000");

    // At the horizon: dead-lettered, dispatch_fn NOT called again, one audit row, one count.
    fx.seq = 1000 + kHorizon;
    fx.make_due("occ-h");
    loop.tick();
    CHECK(probe.calls == 3);
    CHECK(fx.raw_state("occ-h") == "failed");
    CHECK(fx.raw_col("occ-h", "note") == "redelivery_horizon_exceeded");
    CHECK(metrics.counter("yuzu_server_command_outbox_deliver_horizon_exceeded_total").value() ==
          1);
    yuzu::server::AuditQuery q;
    q.action = "command.outbox_delivered";
    auto rows = audit.query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1); // the partial-send retries wrote none: only the dead-letter did
    CHECK((*rows)[0].result == "failure");
    CHECK((*rows)[0].detail.find("redelivery_horizon_exceeded first_seq=1000 current_seq=1010 "
                                 "local_delta=0 horizon=10 execution_id=exec-1 "
                                 "approval_id=abcdef01 (") != std::string::npos);
    // An approval id is a bearer capability: only an 8-character prefix is recorded.
    CHECK((*rows)[0].detail.find("abcdef0123456789") == std::string::npos);

    // Terminal: a further tick never re-drives it, and writes no second row.
    fx.make_due("occ-h");
    loop.tick();
    CHECK(probe.calls == 3);
    auto rows2 = audit.query(q);
    REQUIRE(rows2.has_value());
    CHECK(rows2->size() == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: a sequence that went BACKWARDS dead-letters the redrive "
          "under its own reason (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-back", "cmd-back"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe);
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();
    REQUIRE(probe.calls == 1);

    fx.seq = 5; // e.g. a restore from backup, or a new leader whose local term is smaller
    fx.make_due("occ-back");
    loop.tick();
    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-back") == "failed");
    CHECK(fx.raw_col("occ-back", "note") == "redelivery_sequence_regressed");
}

TEST_CASE("CommandOutboxDelivery[pg]: a first attempt that provably reached NO agent clears its "
          "stamp, so a row blocked by an unreadable gate is never aged toward a dead-letter "
          "(#3678)",
          "[command_outbox][pg][delivery][3678]") {
    constexpr std::int64_t kHorizon = 10;
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-clr", "cmd-clr"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    probe.next.containment_unreadable = true; // reaches nobody (sent == 0)
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, nullptr, kHorizon);
    loop.tick();
    REQUIRE(probe.calls == 1);
    REQUIRE(fx.raw_state("occ-clr") == "pending");
    CHECK(fx.raw_col("occ-clr", "dispatch_seq_first_sent") == "<null>"); // cleared in the reschedule
    CHECK(fx.raw_col("occ-clr", "dispatch_unrecorded_first_sent") == "<null>");
    CHECK(fx.raw_col("occ-clr", "dispatch_stamp_epoch") == "<null>");

    // The fleet dispatches far more than the horizon while the gate stays unreadable. The row
    // never reached an agent, so it must still be sent (and re-stamped from the NEW origin).
    fx.seq = 1000 + 100 * kHorizon;
    probe.next = {};            // gate readable again; no agents currently in scope
    fx.make_due("occ-clr");
    loop.tick();
    CHECK(probe.calls == 2);
    CHECK(fx.raw_col("occ-clr", "dispatch_seq_first_sent") == std::to_string(*fx.seq));
    CHECK(fx.raw_state("occ-clr") == "sent");
}

TEST_CASE("CommandOutboxDelivery[pg]: a stamp that PREDATES the attempt is never cleared, even by a "
          "retry that reaches nobody (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-keep", "cmd-keep"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe); // attempt 1 really sent to some agents; the stamp guards that
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();
    REQUIRE(fx.raw_col("occ-keep", "dispatch_seq_first_sent") == "1000");

    probe.next = {};
    probe.next.containment_unreadable = true; // attempt 2 reaches nobody
    fx.seq = 1002;
    fx.make_due("occ-keep");
    loop.tick();
    REQUIRE(probe.calls == 2);
    REQUIRE(fx.raw_state("occ-keep") == "pending");
    CHECK(fx.raw_col("occ-keep", "dispatch_seq_first_sent") == "1000"); // origin NOT moved
}

TEST_CASE("CommandOutboxDelivery[pg]: an unreadable or unwired dispatch sequence HOLDS every row and "
          "ends the tick after ONE log and one count -- no send, no stamp, no reschedule (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-a", "cmd-a"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-b", "cmd-b"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    yuzu::MetricsRegistry metrics;
    auto hold_cause = [&](const char* cause) {
        return metrics
            .counter("yuzu_server_command_outbox_deliver_hold_cause_total", {{"cause", cause}})
            .value();
    };

    SECTION("sequence unreadable") {
        fx.seq = std::nullopt;
        auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics);
        loop.tick();
        CHECK(probe.calls == 0);
        for (const char* occ : {"occ-a", "occ-b"}) {
            CHECK(fx.raw_state(occ) == "pending");
            CHECK(fx.raw_col(occ, "dispatch_seq_first_sent") == "<null>");
            CHECK(fx.raw_col(occ, "attempts") == "0");
        }
        // Two rows were pending but the SYSTEMIC hold ended the tick at the first.
        CHECK(hold_cause("sequence_unreadable") == 1);
        CHECK(metrics.counter("yuzu_server_command_outbox_deliver_degrade_total").value() == 1);

        // Held, not lost: once the sequence is readable again both are delivered.
        fx.seq = 1000;
        loop.tick();
        CHECK(probe.calls == 2);
        CHECK(fx.raw_state("occ-a") == "sent");
        CHECK(fx.raw_state("occ-b") == "sent");
    }
    SECTION("reader never wired (fail closed like an unset arming_check)") {
        fx.seq_wired = false;
        auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics);
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-a") == "pending");
        CHECK(fx.raw_col("occ-a", "dispatch_seq_first_sent") == "<null>");
        CHECK(hold_cause("sequence_unwired") == 1);
    }
}

TEST_CASE("CommandOutboxDelivery[pg]: a first-send stamp that cannot commit HOLDS the row -- the "
          "delivery loop sends nothing (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-pre", "cmd-pre"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    yuzu::MetricsRegistry metrics;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, &metrics);

    // Another writer (a second replica, or a leader handover) stamps the row between
    // list_pending's snapshot -- which showed it unstamped -- and this loop's own stamp write.
    bool raced = false;
    fx.before_seq_read = [&] {
        if (raced)
            return;
        raced = true;
        auto other = fx.store().stamp_first_send("occ-pre", fx.lock(), fx.epoch(), 1000, 0);
        REQUIRE(other.has_value());
        REQUIRE(*other);
    };
    loop.tick();

    CHECK(probe.calls == 0); // the stamp write returned "already stamped" => HOLD, not send
    CHECK(fx.raw_state("occ-pre") == "pending");
    CHECK(fx.raw_col("occ-pre", "attempts") == "0");
    CHECK(metrics
              .counter("yuzu_server_command_outbox_deliver_hold_cause_total",
                       {{"cause", "stamp_not_committed"}})
              .value() == 1);

    // Next tick sees the committed stamp (1000) and the sequence inside the horizon: delivered.
    loop.tick();
    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-pre") == "sent");
}

TEST_CASE("CommandOutboxStore[pg]: stamp_first_send is epoch-fenced and first-stamp-wins (#3678)",
          "[command_outbox][pg][store][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-fence", "cmd-fence"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // A stale ex-leader presents an older epoch: the fenced stamp matches no row.
    auto stale = fx.store().stamp_first_send("occ-fence", fx.lock(), fx.epoch() - 1, 1000, 0);
    REQUIRE(stale.has_value());
    CHECK_FALSE(*stale);
    CHECK(fx.raw_col("occ-fence", "dispatch_seq_first_sent") == "<null>");

    // The true leader stamps; a second stamp (any epoch) cannot move the origin.
    auto first = fx.store().stamp_first_send("occ-fence", fx.lock(), fx.epoch(), 1000, 7);
    REQUIRE(first.has_value());
    CHECK(*first);
    auto again = fx.store().stamp_first_send("occ-fence", fx.lock(), fx.epoch(), 9999, 0);
    REQUIRE(again.has_value());
    CHECK_FALSE(*again);
    CHECK(fx.raw_col("occ-fence", "dispatch_seq_first_sent") == "1000");
    // All three columns are written together, by the same UPDATE, from the winning stamp.
    CHECK(fx.raw_col("occ-fence", "dispatch_unrecorded_first_sent") == "7");
    CHECK(fx.raw_col("occ-fence", "dispatch_stamp_epoch") == std::to_string(fx.epoch()));

    // A negative sequence is refused, never written.
    auto neg = fx.store().stamp_first_send("occ-fence", fx.lock(), fx.epoch(), -1, 0);
    CHECK_FALSE(neg.has_value());
}

TEST_CASE("CommandOutboxDelivery[pg]: a horizon dead-letter keeps the approval ticket spent and "
          "leaves the execution row alone (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    DeliveryPg fx;

    yuzu::server::pg::PgPool tracker_pool{{.conninfo = fx.dsn(), .size = 2}};
    REQUIRE(tracker_pool.valid());
    ExecutionTracker tracker{tracker_pool};
    REQUIRE(tracker.is_open());
    Execution exec;
    exec.definition_id = "power_health.report";
    exec.status = "running";
    exec.dispatched_by = "svc-scheduler";
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    auto req = fx.req("occ-ticket", "cmd-ticket", /*approval=*/"appr-1");
    req.execution_id = *exec_id;
    REQUIRE(fx.store().claim_and_enqueue(req, fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    make_partial_send(probe); // the stamp is kept: attempt 1 reached some agents
    CommandOutboxDelivery::Deps d;
    d.outbox = &fx.store();
    d.leader = &fx.elector();
    d.execution_tracker = &tracker;
    d.dispatch_seq_fn = fx.seq_fn();
    d.redelivery_horizon_commands = 5;
    d.dispatch_fn = [&probe](const std::string&, const std::string&,
                             const std::vector<std::string>&, const std::string&,
                             const std::unordered_map<std::string, std::string>&,
                             const std::string&, const DispatchCaller&, const std::string& cid) {
        probe.calls++;
        auto out = probe.next;
        out.command_id = cid;
        return out;
    };
    d.resolve_caller = [](const std::string& p) {
        DispatchCaller c;
        c.principal = p;
        return c;
    };
    d.arming_check = [](const std::string&, const std::string&, const std::string&) {
        return true;
    };
    CommandOutboxDelivery loop{std::move(d)};

    loop.tick();
    REQUIRE(probe.calls == 1);
    fx.seq = 1000 + 5;
    fx.make_due("occ-ticket");
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-ticket") == "failed");
    // `failed` is NOT a state filter on the spent-ticket ledger: the first attempt happened.
    auto spent = fx.store().occurrences_for_approval("appr-1");
    REQUIRE(spent.has_value());
    CHECK(*spent == std::vector<std::string>{"occ-ticket"});
    // An earlier attempt may have reached agents: the execution row is NOT force-cancelled.
    auto after = tracker.get_execution(*exec_id);
    REQUIRE(after.has_value());
    CHECK(after->status == "running");
}

TEST_CASE("CommandOutboxDelivery[pg]: in the SAME leadership term the unrecorded count is "
          "differenced; the shared sequence never moves it (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    constexpr std::int64_t kHorizon = 10;
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-term", "cmd-term"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe); // keeps the stamp
    // Large PRE-EXISTING unrecorded history in this process must not count against the row.
    fx.unrecorded = 500;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, nullptr, kHorizon);
    loop.tick();
    REQUIRE(probe.calls == 1);
    REQUIRE(fx.raw_col("occ-term", "dispatch_unrecorded_first_sent") == "500");

    // Same term: only the unrecorded dispatches AFTER the stamp count. 9 < 10 => still sent.
    fx.unrecorded = 509;
    fx.make_due("occ-term");
    loop.tick();
    CHECK(probe.calls == 2);
    CHECK(fx.raw_state("occ-term") == "pending");

    // 10 unrecorded since the stamp reaches the horizon even though the shared sequence is flat:
    // those dispatches took ring slots and never reached the database.
    fx.unrecorded = 510;
    fx.make_due("occ-term");
    loop.tick();
    CHECK(probe.calls == 2);
    CHECK(fx.raw_state("occ-term") == "failed");
    CHECK(fx.raw_col("occ-term", "note") == "redelivery_horizon_exceeded");
}

TEST_CASE("CommandOutboxDelivery[pg]: a stamp from ANOTHER leadership term is compared on the "
          "shared sequence plus the reader's WHOLE local count -- never differenced against a "
          "count from another process (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    constexpr std::int64_t kHorizon = 10;
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-x", "cmd-x"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe);
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, nullptr, kHorizon);

    SECTION("KNOWN RESIDUAL (characterisation, not a guarantee): a previous process's post-stamp "
            "unrecorded dispatches are FORGOTTEN, so the row reads young and is SENT") {
        // The old leader stamped when ITS count was 12,000, and may have gone on to make any number
        // of unrecorded dispatches before it restarted. This process starts near zero and has no
        // way to know. A summed encoding would instead have read 3 as 11,997 BELOW the stamp (the
        // scale-mixing defect the redesign removed); the separate encoding reads 0 shared + 3
        // local, which is SAFE FROM THAT DEFECT but is an UNDER-count for the forgotten failures.
        // The sound close is agent-side (refuse ids older than the ring): see
        // command_replay_horizon.hpp, "an earlier process lifetime". This test pins today's
        // behaviour so it cannot change silently in either direction.
        fx.set_stamp("occ-x", 1000, 12000, fx.epoch() - 1);
        fx.unrecorded = 3;
        loop.tick();
        CHECK(probe.calls == 1); // elapsed = 0 + 3 < 10: sent
        CHECK(fx.raw_state("occ-x") == "pending");
    }
    SECTION("the DISCRIMINATOR: the same numbers dead-letter in another term and are sent in the "
            "same term") {
        // stamp unrecorded = 5, reader unrecorded = 10, horizon 10.
        //   another term  -> the reader charges its WHOLE count: 10 >= 10 -> dead-letter
        //   the same term -> differenced: 10 - 5 = 5 < 10 -> sent
        // If the epoch comparison were deleted (every stamp treated as same-term) the first half
        // would be sent, which is exactly the scale-mixing defect: every other section in this
        // test happens to give the same verdict either way.
        fx.set_stamp("occ-x", 1000, 5, fx.epoch() - 1);
        fx.unrecorded = 10;
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-x") == "failed");
        CHECK(fx.raw_col("occ-x", "note") == "redelivery_horizon_exceeded");
    }
    SECTION("the same numbers inside ONE term are differenced and the row is sent") {
        fx.set_stamp("occ-x", 1000, 5, fx.epoch());
        fx.unrecorded = 10;
        loop.tick();
        CHECK(probe.calls == 1);
        CHECK(fx.raw_state("occ-x") == "pending");
    }
    SECTION("a huge local count with the shared sequence advanced dead-letters instead of "
            "wrapping negative") {
        fx.set_stamp("occ-x", 1000, 0, fx.epoch() - 1);
        fx.seq = 1005;
        fx.unrecorded = std::numeric_limits<std::int64_t>::max();
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-x") == "failed");
        CHECK(fx.raw_col("occ-x", "note") == "redelivery_horizon_exceeded");
    }
    SECTION("a local count that went DOWN inside one epoch is charged whole, not clamped to zero") {
        // Cannot happen unless an epoch were reused (the elector documents that as not covered),
        // but clamping the difference to zero would then silently under-count.
        fx.set_stamp("occ-x", 1000, 500, fx.epoch());
        fx.unrecorded = 10;
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-x") == "failed");
    }
    SECTION("this process's whole local count is charged, which can only over-count") {
        fx.set_stamp("occ-x", 1000, 0, fx.epoch() - 1);
        fx.unrecorded = 10; // 10 >= horizon, even though they may all predate the stamp
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-x") == "failed");
        CHECK(fx.raw_col("occ-x", "note") == "redelivery_horizon_exceeded");
    }
    SECTION("a stamp missing its companion columns is treated as another term, conservatively") {
        fx.set_stamp("occ-x", 1000, 0, fx.epoch());
        yuzu::server::pg::PgConn conn{PQconnectdb(fx.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    conn.get(),
                    "UPDATE command_outbox_store.outbox SET dispatch_unrecorded_first_sent = NULL "
                    "WHERE occurrence_id='occ-x'",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        fx.unrecorded = 10;
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_state("occ-x") == "failed");
    }
    SECTION("only the SHARED sequence going backwards is 'regressed'; a smaller local count is not") {
        fx.set_stamp("occ-x", 1000, 0, fx.epoch() - 1);
        fx.seq = 999;
        loop.tick();
        CHECK(probe.calls == 0);
        CHECK(fx.raw_col("occ-x", "note") == "redelivery_sequence_regressed");
    }
}

TEST_CASE("CommandOutboxDelivery[pg]: a REAL leadership change (resign then re-acquire) is "
          "another term -- the reader charges its whole unrecorded count (#3678)",
          "[command_outbox][pg][delivery][3678]") {
    constexpr std::int64_t kHorizon = 10;
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-flap", "cmd-flap"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe); // keeps the stamp
    fx.unrecorded = 500;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true, nullptr, kHorizon);
    loop.tick();
    REQUIRE(probe.calls == 1);
    REQUIRE(fx.raw_col("occ-flap", "dispatch_stamp_epoch") == std::to_string(fx.epoch()));

    // The same process loses and regains leadership: a genuinely NEW epoch from the real elector.
    const std::int64_t old_epoch = fx.epoch();
    fx.elector().resign();
    REQUIRE(fx.elector().try_acquire());
    REQUIRE(fx.elector().epoch().has_value());
    REQUIRE(*fx.elector().epoch() != old_epoch);

    // 9 unrecorded dispatches since the stamp would be 509 - 500 = 9 < 10 if differenced (same
    // term). Across a term change the reader charges its whole count, 509 >= 10, and refuses --
    // a safe-direction early dead-letter, which is the documented cost of using the epoch as the
    // "same process" discriminator (a boot nonce would avoid it; a follow-up).
    fx.unrecorded = 509;
    fx.make_due("occ-flap");
    loop.tick();
    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-flap") == "failed");
    CHECK(fx.raw_col("occ-flap", "note") == "redelivery_horizon_exceeded");
}

TEST_CASE("CommandOutboxDelivery[pg]: KNOWN RESIDUAL (characterisation, not a guarantee): a stale "
          "leader acting on an old snapshot still sends a row a peer has just dead-lettered (#3678)",
          "[command_outbox][pg][delivery][3678][residual]") {
    // The send happens BEFORE any fenced write for the sent path (see the "ORDERING" comment in
    // deliver()), so a replica that read the row as stamped-and-inside-the-horizon can send it even
    // though a peer dead-lettered it in between. Only the bookkeeping is fenced out. That is the
    // pre-existing ADR-2002 section 6 gap, absorbed by the agent's dedup UNLESS the id has been
    // evicted -- which is exactly the case the horizon exists for, so this is worth pinning.
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-stale", "cmd-stale"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    DispatchProbe probe;
    make_partial_send(probe);
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick(); // attempt 1: stamps, partial send, rescheduled
    REQUIRE(probe.calls == 1);
    fx.make_due("occ-stale");

    // A peer dead-letters the row between this replica's list_pending snapshot and its decision.
    fx.before_seq_read = [&] {
        auto peer = fx.store().mark_failed("occ-stale", fx.lock(), fx.epoch(),
                                           "redelivery_horizon_exceeded");
        REQUIRE(peer.has_value());
        REQUIRE(*peer);
    };
    loop.tick();

    CHECK(fx.raw_state("occ-stale") == "failed"); // the peer's verdict stands in the store...
    CHECK(probe.calls == 2);                      // ...but this replica still sent on its snapshot
}

TEST_CASE("CommandOutboxStore[pg]: the stamp-clear only touches a stamp written in THIS term "
          "(#3678)",
          "[command_outbox][pg][store][3678]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-c", "cmd-c"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // A stamp from an EARLIER term: asking for the clear must leave it alone.
    fx.set_stamp("occ-c", 1000, 4, fx.epoch() - 1);
    auto kept = fx.store().reschedule("occ-c", fx.lock(), fx.epoch(), std::chrono::seconds(30),
                                      /*clear_first_send_stamp=*/true);
    REQUIRE(kept.has_value());
    CHECK(*kept); // the reschedule itself happened
    CHECK(fx.raw_col("occ-c", "dispatch_seq_first_sent") == "1000");
    CHECK(fx.raw_col("occ-c", "dispatch_unrecorded_first_sent") == "4");
    CHECK(fx.raw_col("occ-c", "dispatch_stamp_epoch") == std::to_string(fx.epoch() - 1));

    // A stamp from THIS term: cleared, all three columns together.
    fx.set_stamp("occ-c", 1000, 4, fx.epoch());
    auto cleared = fx.store().reschedule("occ-c", fx.lock(), fx.epoch(), std::chrono::seconds(30),
                                         /*clear_first_send_stamp=*/true);
    REQUIRE(cleared.has_value());
    CHECK(fx.raw_col("occ-c", "dispatch_seq_first_sent") == "<null>");
    CHECK(fx.raw_col("occ-c", "dispatch_unrecorded_first_sent") == "<null>");
    CHECK(fx.raw_col("occ-c", "dispatch_stamp_epoch") == "<null>");

    // And without the flag a same-term stamp is kept.
    fx.set_stamp("occ-c", 1000, 4, fx.epoch());
    auto noclear = fx.store().reschedule("occ-c", fx.lock(), fx.epoch(), std::chrono::seconds(30),
                                         /*clear_first_send_stamp=*/false);
    REQUIRE(noclear.has_value());
    CHECK(fx.raw_col("occ-c", "dispatch_seq_first_sent") == "1000");
}

TEST_CASE("CommandOutboxDelivery: the constructor clamps a Deps horizon into [1, the ring-derived "
          "constant] (#3678)",
          "[command_outbox][delivery][3678]") {
    // No database needed: the clamp is constructor-local. (tick() never runs.)
    auto horizon_after = [](std::int64_t requested) {
        CommandOutboxDelivery::Deps d;
        d.redelivery_horizon_commands = requested;
        CommandOutboxDelivery loop{std::move(d)};
        return loop.redelivery_horizon_for_test();
    };
    CHECK(horizon_after(yuzu::kMaxOutboxRedeliveryHorizonCommands * 100) ==
          yuzu::kMaxOutboxRedeliveryHorizonCommands);
    CHECK(horizon_after(0) == 1);
    CHECK(horizon_after(-7) == 1);
    CHECK(horizon_after(42) == 42);
}
