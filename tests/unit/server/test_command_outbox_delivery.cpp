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
};

class DeliveryPg {
public:
    DeliveryPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(delivery_tpl);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
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

    // Build a delivery loop whose dispatch/arming seams the test controls.
    // `metrics` is optional (defaulted) - most tests here assert on the
    // OutboxCommand state machine, not on observability, and don't need it.
    CommandOutboxDelivery make_delivery(DispatchProbe& probe, bool arming_allow,
                                        yuzu::MetricsRegistry* metrics = nullptr) {
        CommandOutboxDelivery::Deps d;
        d.outbox = store_.get();
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
// count. Empirically verified (per this round's own required before/after
// discipline) to FAIL — `agents_targeted` observed still 0 while
// `state='sent'` — when the call site is temporarily reverted to the old
// two-call split, and to PASS with the call site as committed.
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

    // Both halves landed together: the outbox row is 'sent' AND the
    // execution's real target count is set — the exact atomicity guarantee
    // this test exists to pin at the call-site level.
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
