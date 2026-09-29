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
#include "leader_elector.hpp"

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
