// test_command_outbox_store.cpp — WS-3 slice 3.3 (ADR-2002 §6): the durable
// transactional command outbox. These [pg] tests take real Postgres backends
// and bind the two structural guarantees an adversarial review of the plan made
// load-bearing (see command_outbox_store.hpp):
//   1. the occurrence key is a UNIQUE/PRIMARY key — a second enqueue of the same
//      occurrence is an idempotent AlreadyEnqueued, never a double row (R2);
//   2. the epoch fence, embedded in every claim's WRITE, rejects a stale
//      ex-leader's epoch atomically — a stale enqueue is FencedOut (0 rows), a
//      stale mark_sent leaves the row pending for the true leader to re-drive.
// Plus the pending-list / mark_sent / mark_failed / reschedule state machine the
// leader-gated delivery loop drives.
//
// The fence reads `leader_elector.leader_state`, so the fixture migrates BOTH
// this store and the LeaderElector schema and seeds a REAL epoch by acquiring on
// a live elector (mirrors test_leader_elector.cpp's own fence cases).

#include "command_outbox_store.hpp"
#include "leader_elector.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

using namespace yuzu::server;

namespace {

// One migration run, cloned per fixture: migrates the command_outbox_store
// schema AND the leader_elector schema (the fence subquery targets the latter).
// The template does NOT acquire leadership — each fixture mints its own epoch on
// its own clone, so leader_state starts empty here.
yuzu::test::PgTestTemplate command_outbox_tpl{"commandoutbox", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::CommandOutboxStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("command_outbox template: store failed to migrate");
    yuzu::server::LeaderElector le{
        yuzu::server::LeaderElector::Config{.dsn = dsn, .holder_id = "template"}};
    if (!le.is_open())
        throw std::runtime_error("command_outbox template: leader_elector failed to migrate");
}};

// RAII bundle: ephemeral DB + pool + store + a LIVE elector holding leadership,
// so `epoch()` is a real minted epoch the store's fence will accept. Destruction
// order: elector_/store_ (own connections) before pool_ before db_.
class CommandOutboxPg {
public:
    CommandOutboxPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(command_outbox_tpl);
        INFO("[CommandOutboxPg] fixture status (blank == OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<CommandOutboxStore>(*pool_);
        REQUIRE(store_->is_open());
        elector_ = std::make_unique<LeaderElector>(
            LeaderElector::Config{.dsn = db_->dsn(), .holder_id = "test-leader"});
        REQUIRE(elector_->is_open());
        REQUIRE(elector_->try_acquire());
        REQUIRE(elector_->epoch().has_value());
        epoch_ = *elector_->epoch();
    }

    CommandOutboxPg(const CommandOutboxPg&) = delete;
    CommandOutboxPg& operator=(const CommandOutboxPg&) = delete;

    CommandOutboxStore& store() noexcept { return *store_; }
    std::string dsn() const { return db_->dsn(); }
    std::int64_t epoch() const noexcept { return epoch_; }
    static std::string lock() { return kServerBackgroundLeaderLock; }

    // Raw read of a stored row's (state, attempts) on a second connection —
    // for assertions the public API deliberately does not expose.
    struct RowState {
        bool present{false};
        std::string state;
        int attempts{0};
    };
    RowState raw_row(const std::string& occurrence_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p = occurrence_id.c_str();
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "SELECT state, attempts FROM command_outbox_store.outbox WHERE occurrence_id=$1", 1,
            nullptr, &p, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        RowState rs;
        if (PQntuples(r.get()) == 1) {
            rs.present = true;
            rs.state = PQgetvalue(r.get(), 0, 0);
            rs.attempts = std::atoi(PQgetvalue(r.get(), 0, 1));
        }
        return rs;
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<CommandOutboxStore> store_;
    std::unique_ptr<LeaderElector> elector_;
    std::int64_t epoch_{0};
};

OutboxEnqueueRequest make_req(const std::string& occurrence_id, const std::string& command_id) {
    OutboxEnqueueRequest r;
    r.occurrence_id = occurrence_id;
    r.command_id = command_id;
    r.source = "schedule_runner";
    r.plugin = "power_health";
    r.action = "report";
    r.scope_expr = "tag:linux";
    r.agent_ids = "";
    r.parameters = R"({"k":"v"})";
    r.execution_id = "sched-exec-1";
    r.principal = "svc-scheduler";
    return r;
}

} // namespace

TEST_CASE("CommandOutboxStore[pg]: opens and migrates", "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    CHECK(fx.store().is_open());
}

TEST_CASE("CommandOutboxStore[pg]: enqueue then list_pending", "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    CHECK(fx.store().claim_and_enqueue(make_req("occ-1", "cmd-1"), fx.lock(), fx.epoch()) ==
          OutboxEnqueueOutcome::Enqueued);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    REQUIRE(pending->size() == 1);
    const auto& c = (*pending)[0];
    CHECK(c.occurrence_id == "occ-1");
    CHECK(c.command_id == "cmd-1");
    CHECK(c.source == "schedule_runner");
    CHECK(c.plugin == "power_health");
    CHECK(c.action == "report");
    CHECK(c.scope_expr == "tag:linux");
    CHECK(c.parameters == R"({"k":"v"})");
    CHECK(c.execution_id == "sched-exec-1");
    CHECK(c.principal == "svc-scheduler");
    CHECK(c.attempts == 0);
}

TEST_CASE("CommandOutboxStore[pg]: duplicate occurrence is AlreadyEnqueued, one row (R2)",
          "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    // First enqueue wins; the second, same occurrence_id (a racing leader
    // computing the identical key), no-ops on the PK and reads as an idempotent
    // success — NOT a failure, and NOT a second row.
    CHECK(fx.store().claim_and_enqueue(make_req("occ-dup", "cmd-a"), fx.lock(), fx.epoch()) ==
          OutboxEnqueueOutcome::Enqueued);
    CHECK(fx.store().claim_and_enqueue(make_req("occ-dup", "cmd-b"), fx.lock(), fx.epoch()) ==
          OutboxEnqueueOutcome::AlreadyEnqueued);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    REQUIRE(pending->size() == 1);
    // The first writer's command_id is the durable one (ON CONFLICT DO NOTHING).
    CHECK((*pending)[0].command_id == "cmd-a");
}

TEST_CASE("CommandOutboxStore[pg]: a stale epoch is FencedOut and inserts nothing (R2 fence)",
          "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    // A stale ex-leader (epoch below the current one) is rejected by the fence
    // embedded in the INSERT — zero rows, occurrence NOT present.
    CHECK(fx.store().claim_and_enqueue(make_req("occ-stale", "cmd-x"), fx.lock(), fx.epoch() - 1) ==
          OutboxEnqueueOutcome::FencedOut);
    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    CHECK(pending->empty());
    CHECK_FALSE(fx.raw_row("occ-stale").present);
}

TEST_CASE("CommandOutboxStore[pg]: mark_sent transitions pending->sent and stops re-drive",
          "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    REQUIRE(fx.store().claim_and_enqueue(make_req("occ-s", "cmd-s"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    auto sent = fx.store().mark_sent("occ-s", fx.lock(), fx.epoch());
    REQUIRE(sent.has_value());
    CHECK(*sent);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    CHECK(pending->empty()); // no longer re-driven
    CHECK(fx.raw_row("occ-s").state == "sent");

    // A second mark_sent is a no-op (already terminal): false, not an error.
    auto again = fx.store().mark_sent("occ-s", fx.lock(), fx.epoch());
    REQUIRE(again.has_value());
    CHECK_FALSE(*again);
}

TEST_CASE("CommandOutboxStore[pg]: a stale mark_sent is fenced out; row stays pending",
          "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    REQUIRE(fx.store().claim_and_enqueue(make_req("occ-f", "cmd-f"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // A stale ex-leader's mark_sent is fenced out (0 rows) — the row stays
    // pending so the true leader re-drives it (the duplicate wire send it may
    // already have made is absorbed by the agent's command_id dedup, WS-0).
    auto stale = fx.store().mark_sent("occ-f", fx.lock(), fx.epoch() - 1);
    REQUIRE(stale.has_value());
    CHECK_FALSE(*stale);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    REQUIRE(pending->size() == 1);
    CHECK((*pending)[0].occurrence_id == "occ-f");
}

TEST_CASE("CommandOutboxStore[pg]: mark_failed is terminal", "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    REQUIRE(fx.store().claim_and_enqueue(make_req("occ-x", "cmd-x"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    auto failed = fx.store().mark_failed("occ-x", fx.lock(), fx.epoch(), "authority revoked");
    REQUIRE(failed.has_value());
    CHECK(*failed);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    CHECK(pending->empty());
    CHECK(fx.raw_row("occ-x").state == "failed");
}

TEST_CASE("CommandOutboxStore[pg]: reschedule backs off and bumps attempts",
          "[command_outbox][pg][store]") {
    CommandOutboxPg fx;
    REQUIRE(fx.store().claim_and_enqueue(make_req("occ-r", "cmd-r"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    // Push next_attempt_at out; the row stays pending but is no longer due, so
    // list_pending (which honours next_attempt_at <= now()) omits it.
    auto res = fx.store().reschedule("occ-r", fx.lock(), fx.epoch(), std::chrono::seconds(3600));
    REQUIRE(res.has_value());
    CHECK(*res);

    auto pending = fx.store().list_pending();
    REQUIRE(pending.has_value());
    CHECK(pending->empty());

    auto row = fx.raw_row("occ-r");
    CHECK(row.present);
    CHECK(row.state == "pending");
    CHECK(row.attempts == 1);
}

TEST_CASE("CommandOutboxStore[pg]: migrates from an empty database",
          "[command_outbox][pg][store][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CommandOutboxStore store{pool};
    REQUIRE(store.is_open());
    // A projection smoke-read against the fresh schema resolves every selected
    // column (playbook §Runner-guards second-line-of-defence shape).
    auto pending = store.list_pending();
    REQUIRE(pending.has_value());
    CHECK(pending->empty());
}
