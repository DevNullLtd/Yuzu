/**
 * test_approval_manager_bound.cpp -- the bound-approval primitive (#6062, four-eyes
 * MVP PR2): migration v3 columns and old-row compatibility; origin-declared consume
 * (origin mismatch, kUnspecified/kUnrecognised, the caller-held-connection overload);
 * submit_bound's frozen request/digest/excluded roots and its refusals; approve()'s
 * excluded-root refusal; and the precondition-denial counter + audit observer.
 *
 * Every TEST_CASE here needs Postgres and SKIPs silently without
 * YUZU_TEST_POSTGRES_DSN (see test_approval_manager_pg_helper.hpp).
 */

#include "approval_denial_audit.hpp"
#include "approval_manager.hpp"
#include "approval_model.hpp"
#include "audit_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "reserved_definition_id.hpp"
#include "sha256_hex.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// Direct SQL on a leased connection. The caller REQUIREs the status it expects.
pg::PgResult run_sql(pg::PgPool& pool, const std::string& sql,
                     const std::vector<std::string>& params = {}) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    return pg::exec_params(lease.get(), sql.c_str(), params);
}

} // namespace

// -- Migration v3 / old-row compatibility -------------------------------------
//
// The bound columns are migration v3: #6096's data-only v2 (a legacy scheduled-ticket
// retire) claimed v2 first and ships unchanged, so v3 must be ordered after it.

namespace {

// schema_meta.version for the approval store, or -1 if unreadable.
int approval_store_version(pg::PgPool& pool) {
    auto r = run_sql(pool, "SELECT version FROM public.schema_meta WHERE store = "
                           "'approval_manager'");
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return -1;
    return std::stoi(PQgetvalue(r.get(), 0, 0));
}

// Does approval_manager.approvals have `col`? 1 / 0, or -1 if unreadable.
int approvals_has_column(pg::PgPool& pool, const std::string& col) {
    auto r = run_sql(pool,
                     "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
                     "'approval_manager' AND table_name = 'approvals' AND column_name = $1",
                     {col});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return -1;
    return std::string(PQgetvalue(r.get(), 0, 0)) == "1" ? 1 : 0;
}

void drop_bound_columns(pg::PgPool& pool) {
    REQUIRE(run_sql(pool,
                    "ALTER TABLE approval_manager.approvals DROP COLUMN request_json, "
                    "DROP COLUMN request_digest, DROP COLUMN excluded_roots")
                .status() == PGRES_COMMAND_OK);
}

void set_approval_store_version(pg::PgPool& pool, int v) {
    REQUIRE(run_sql(pool, "UPDATE public.schema_meta SET version = $1::int WHERE store = "
                          "'approval_manager'",
                    {std::to_string(v)})
                .status() == PGRES_COMMAND_OK);
}

} // namespace

TEST_CASE("ApprovalManager bound: a row minted before migration v3 survives it and reads "
          "as binding nothing",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    auto& pool = bundle.pool();
    REQUIRE(approval_store_version(pool) == 3);

    // Rewind the live schema to the state of a database already at #6096's v2: drop the
    // three bound columns and reset the recorded version, then mint an "old" row with only
    // the pre-v3 columns.
    drop_bound_columns(pool);
    set_approval_store_version(pool, 2);
    REQUIRE(run_sql(pool,
                    "INSERT INTO approval_manager.approvals (id, definition_id, status, "
                    "submitted_by, submitted_at, reviewed_by, reviewed_at, scope_expression, "
                    "origin) VALUES ('old-row','mcp.tool','approved','alice',1,'bob',"
                    "extract(epoch from now())::bigint,'{}','mcp')")
                .status() == PGRES_COMMAND_OK);
    // A schedule ticket the v2 step had retired, and one it had not (approved after v2 ran):
    // v3 must run ONLY the ALTERs, so neither is touched.
    REQUIRE(run_sql(pool,
                    "INSERT INTO approval_manager.approvals (id, definition_id, status, "
                    "schedule_id, consumed_at, consumed_by, origin) VALUES "
                    "('sched-retired','d','approved','sched-a',42,'schedule:legacy-6096',"
                    "'schedule'),"
                    "('sched-open','d','approved','sched-a',0,'','schedule')")
                .status() == PGRES_COMMAND_OK);

    // A fresh manager re-runs the ladder: v3 (and only v3) applies to a POPULATED table.
    ApprovalManager upgraded{pool};
    REQUIRE(upgraded.is_open());
    CHECK(approval_store_version(pool) == 3);
    CHECK(approvals_has_column(pool, "request_json") == 1);
    CHECK(approvals_has_column(pool, "request_digest") == 1);
    CHECK(approvals_has_column(pool, "excluded_roots") == 1);

    auto old = upgraded.get("old-row");
    REQUIRE(old.has_value());
    CHECK(old->request_json.empty());
    CHECK(old->request_digest.empty());
    CHECK(old->excluded_roots.empty());
    CHECK_FALSE(old->excluded_roots_unreadable);

    auto retired = upgraded.get("sched-retired");
    REQUIRE(retired.has_value());
    CHECK(retired->consumed_at == 42);
    CHECK(retired->consumed_by == "schedule:legacy-6096");
    auto open = upgraded.get("sched-open");
    REQUIRE(open.has_value());
    CHECK(open->consumed_at == 0); // v2's data step did not run a second time
    CHECK(open->request_json.empty());

    // ...and it is still redeemable through the normal MCP path.
    auto consumed = upgraded.consume_ticket("old-row", "alice", ApprovalOrigin::kMcp, {});
    CHECK(consumed.has_value());
}

TEST_CASE("ApprovalManager bound: a database at v1 runs #6096's v2 and then v3, in that order",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    auto& pool = bundle.pool();

    drop_bound_columns(pool);
    set_approval_store_version(pool, 1);
    REQUIRE(run_sql(pool,
                    "INSERT INTO approval_manager.approvals (id, definition_id, status, "
                    "submitted_by, submitted_at, reviewed_by, reviewed_at, scope_expression, "
                    "schedule_id, origin) VALUES "
                    "('sched-old','d','approved','alice',1,'bob',"
                    "extract(epoch from now())::bigint,'{}','sched-a','schedule'),"
                    "('mcp-old','mcp.tool','approved','alice',1,'bob',"
                    "extract(epoch from now())::bigint,'{}','','mcp')")
                .status() == PGRES_COMMAND_OK);

    ApprovalManager upgraded{pool};
    REQUIRE(upgraded.is_open());
    CHECK(approval_store_version(pool) == 3);
    CHECK(approvals_has_column(pool, "request_json") == 1);
    CHECK(approvals_has_column(pool, "excluded_roots") == 1);

    // v2 ran: the unsettled schedule ticket is retired; the MCP one is untouched.
    auto sched = upgraded.get("sched-old");
    REQUIRE(sched.has_value());
    CHECK(sched->consumed_at != 0);
    CHECK(sched->consumed_by == "schedule:legacy-6096");
    CHECK(sched->request_json.empty());
    auto mcp = upgraded.get("mcp-old");
    REQUIRE(mcp.has_value());
    CHECK(mcp->consumed_at == 0);
    CHECK(upgraded.consume_ticket("mcp-old", "alice", ApprovalOrigin::kMcp, {}).has_value());
}

// A development or UAT database that ran an EARLIER build of this branch recorded the bound
// columns as migration v2, before #6096's data-only v2 claimed that number. It is at version 2
// WITH the three columns already present, so v3 must tolerate them.
TEST_CASE("ApprovalManager bound: a database at v2 that already has the bound columns reaches v3 "
          "and keeps its rows",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    auto& pool = bundle.pool();
    ApprovalManager& first = *bundle;

    auto bound = first.submit_bound("guardian.d", "alice", "scope", "",
                                    ApprovalOrigin::kGuardianDeploy,
                                    BoundRequest{R"({"k":"v","n":[1,2]})", {"carol"}});
    REQUIRE(bound.has_value());
    REQUIRE(first.approve(*bound, "bob", "").has_value());
    const auto before = first.get(*bound);
    REQUIRE(before.has_value());
    auto unbound = first.submit("mcp.tool", "alice", "scope", "", ApprovalOrigin::kMcp);
    REQUIRE(unbound.has_value());

    // The columns stay; only the recorded version goes back to 2.
    set_approval_store_version(pool, 2);
    REQUIRE(approvals_has_column(pool, "request_json") == 1);

    ApprovalManager upgraded{pool};
    REQUIRE(upgraded.is_open());
    CHECK(approval_store_version(pool) == 3);

    const auto after = upgraded.get(*bound);
    REQUIRE(after.has_value());
    CHECK(after->request_json == before->request_json);
    CHECK(after->request_digest == before->request_digest);
    CHECK(after->excluded_roots == before->excluded_roots);
    CHECK(after->excluded_roots == std::vector<std::string>{"carol"});
    CHECK_FALSE(after->excluded_roots_unreadable);
    CHECK(after->status == "approved");
    CHECK(upgraded.get(*unbound).has_value());
    // And the bound ticket still redeems on its own surface.
    CHECK(upgraded.consume_ticket(*bound, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
}

// -- Reserved definition-id namespaces ----------------------------------------

TEST_CASE("reserved definition ids: guardian. is reserved beside mcp., with its own message",
          "[approval_manager][bound][reserved]") {
    CHECK(is_reserved_definition_id("mcp.quarantine_device"));
    CHECK(is_reserved_definition_id("guardian.deploy.rules"));
    CHECK(is_mcp_definition_id("mcp.x"));
    // A guardian id is reserved but is NOT an MCP tool call: the page keys its MCP
    // tag and its tool-name display off is_mcp_definition_id.
    CHECK_FALSE(is_mcp_definition_id("guardian.deploy.rules"));

    // Exact, case-sensitive prefix; the dot is part of it.
    CHECK_FALSE(is_reserved_definition_id("guardian"));
    CHECK_FALSE(is_reserved_definition_id("guardianx.y"));
    CHECK_FALSE(is_reserved_definition_id("Guardian.x"));
    CHECK_FALSE(is_reserved_definition_id("my.guardian.x"));
    CHECK(reserved_definition_id_error("plain").empty());

    // The #2442 SIEM token is unchanged; guardian has a distinct one.
    CHECK(reserved_definition_id_error("mcp.x") == kReservedDefinitionIdError);
    CHECK(reserved_definition_id_error("guardian.x") == kReservedGuardianDefinitionIdError);
    CHECK(kReservedGuardianDefinitionIdError != kReservedDefinitionIdError);
}

// -- origin_redeemable_as: the full matrix --------------------------------------

TEST_CASE("origin_redeemable_as: all 36 (stored, expected) pairs; true ONLY for equal concrete surfaces",
          "[approval_manager][bound]") {
    using O = ApprovalOrigin;
    // Rows = stored, columns = expected, in this order. Written out rather than derived
    // from the predicate's own rule, so a rule change cannot silently move the table.
    constexpr std::array<O, 6> order{O::kUnspecified, O::kInstruction,    O::kSchedule,
                                     O::kMcp,         O::kGuardianDeploy, O::kUnrecognised};
    constexpr bool expect[6][6] = {
        //            Unspec Instr  Sched  Mcp    Guard  Unrec
        /* Unspec */ {false, false, false, false, false, false},
        /* Instr  */ {false, true,  false, false, false, false},
        /* Sched  */ {false, false, true,  false, false, false},
        /* Mcp    */ {false, false, false, true,  false, false},
        /* Guard  */ {false, false, false, false, true,  false},
        /* Unrec  */ {false, false, false, false, false, false},
    };
    for (std::size_t i = 0; i < order.size(); ++i) {
        for (std::size_t j = 0; j < order.size(); ++j) {
            INFO("stored=" << to_string(order[i]) << " expected=" << to_string(order[j]));
            CHECK(origin_redeemable_as(order[i], order[j]) == expect[i][j]);
        }
    }
}

// -- Origin-declared consume --------------------------------------------------

namespace {

// Mint an approved ticket on `origin` (submitted by alice, approved by bob).
std::string approved_ticket(ApprovalManager& mgr, ApprovalOrigin origin,
                            const std::string& def = "def-1") {
    auto id = mgr.submit(def, "alice", "scope", "", origin);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    return *id;
}

} // namespace

TEST_CASE("consume_ticket: kUnspecified / kUnrecognised as the declared surface ALWAYS refuse",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    for (const auto declared : {ApprovalOrigin::kUnspecified, ApprovalOrigin::kUnrecognised}) {
        auto r = mgr.consume_ticket(id, "alice", declared, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        // Same uniform wording as every other refusal: no oracle on WHY.
        CHECK(r.error().message == kNotConsumableMessage);
    }
    // The refusals touched nothing: the rightful surface still redeems it.
    REQUIRE(mgr.get(id).has_value());
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());
}

TEST_CASE("consume_ticket: a ticket redeems only on the surface that minted it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    for (const auto declared : {ApprovalOrigin::kInstruction, ApprovalOrigin::kSchedule,
                                ApprovalOrigin::kGuardianDeploy}) {
        auto r = mgr.consume_ticket(id, "alice", declared, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
    }
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());

    // And the other direction: an instruction-origin ticket is not an MCP ticket.
    const auto inst = approved_ticket(mgr, ApprovalOrigin::kInstruction, "def-2");
    auto cross = mgr.consume_ticket(inst, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(cross.has_value());
    CHECK(cross.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.consume_ticket(inst, "alice", ApprovalOrigin::kInstruction, {}).has_value());
}

TEST_CASE("consume_ticket: a stored kUnspecified / kUnrecognised origin refuses whoever asks",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    // A row minted with no declared surface ('') and one written by a "newer binary".
    for (const char* stored : {"", "some_future_surface"}) {
        const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp, std::string("def-") + stored);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET origin = $1 WHERE id = $2",
                        {stored, id})
                    .status() == PGRES_COMMAND_OK);
        for (const auto declared : {ApprovalOrigin::kMcp, ApprovalOrigin::kInstruction,
                                    ApprovalOrigin::kGuardianDeploy}) {
            auto r = mgr.consume_ticket(id, "alice", declared, {});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        }
    }
}

// -- Caller-held-connection overload ------------------------------------------

namespace {
// Run `body(conn)` inside BEGIN ... then ROLLBACK or COMMIT. If `body` throws (a failed
// REQUIRE), the transaction is rolled back before the exception leaves, so a failing
// assertion cannot hand the pool a connection that is still mid-transaction.
template <typename F>
void in_txn(pg::PgPool& pool, bool commit, F&& body) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    try {
        body(lease.get());
    } catch (...) {
        (void)pg::exec_params(lease.get(), "ROLLBACK", std::vector<std::string>{});
        throw;
    }
    REQUIRE(pg::exec_params(lease.get(), commit ? "COMMIT" : "ROLLBACK",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
}

// Joins a std::thread on every exit path, running `release` first (whatever the thread is
// parked on). Not std::jthread: Apple Clang 15's libc++ lacks it.
struct JoinGuard {
    std::thread& thread;
    std::function<void()> release;
    JoinGuard(std::thread& t, std::function<void()> r) : thread(t), release(std::move(r)) {}
    JoinGuard(const JoinGuard&) = delete;
    JoinGuard& operator=(const JoinGuard&) = delete;
    ~JoinGuard() {
        try {
            if (release)
                release();
        } catch (...) {
        }
        if (thread.joinable())
            thread.join();
    }
};

// The SQLSTATE of a failed statement ("" when there is none).
std::string sqlstate_of(const pg::PgResult& r) {
    const char* p = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return p ? p : "";
}

// Try to take `id`'s row on a SECOND connection without waiting. "55P03" == lock_not_available,
// i.e. someone else holds the row lock; "" == the row was free (the probe's own txn is closed
// again immediately).
std::string probe_row_lock(pg::PgPool& pool, const std::string& id) {
    auto other = pool.acquire();
    REQUIRE(other);
    auto probe = pg::exec_params(other.get(),
                                 "SELECT 1 FROM approval_manager.approvals WHERE id = $1 "
                                 "FOR UPDATE NOWAIT",
                                 std::vector<std::string>{id});
    return probe.status() == PGRES_TUPLES_OK ? std::string{} : sqlstate_of(probe);
}
} // namespace

TEST_CASE("consume_ticket(PGconn*): the caller's rollback rolls the consume back; commit keeps it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {});
        CHECK(r.has_value());
    });
    // Rolled back: the one-time capability is NOT spent.
    REQUIRE(mgr.get(id).has_value());
    CHECK(mgr.get(id)->consumed_at == 0);
    CHECK(mgr.get(id)->consumed_by.empty());

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
    CHECK(mgr.get(id)->consumed_at != 0);
    CHECK(mgr.get(id)->consumed_by == "alice");

    // Spent for good: a replay (pooled or held) loses.
    auto replay = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
}

TEST_CASE("consume_ticket(PGconn*): refusals leave the caller's transaction healthy and the row "
          "untouched",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        // Wrong surface, no surface, wrong principal, failed precondition.
        auto foreign = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(foreign.has_value());
        CHECK(foreign.error().kind == ConsumeFailure::kForeignOrigin);
        auto none = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kUnspecified, {});
        REQUIRE_FALSE(none.has_value());
        CHECK(none.error().kind == ConsumeFailure::kForeignOrigin);
        auto other = mgr.consume_ticket(conn, id, "mallory", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(other.has_value());
        CHECK(other.error().kind == ConsumeFailure::kForeignSubmitter);
        auto pre = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp,
                                      [](const Approval&) -> std::expected<void, std::string> {
                                          return std::unexpected("state moved");
                                      });
        REQUIRE_FALSE(pre.has_value());
        CHECK(pre.error().kind == ConsumeFailure::kPrecondition);

        // None of that aborted the transaction: it can still run SQL and consume.
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
        CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
    CHECK(mgr.get(id)->consumed_at != 0);
}

TEST_CASE("consume_ticket(PGconn*): a FAILED binding read is a store error flagged unevaluated, "
          "never 'already used'",
          "[pg][approval_manager][bound]") {
    // The held-path twin of the pooled-path fault test in test_approval_manager.cpp: the
    // binding check's own read (`read_row`, FOR UPDATE) is the one that faults here.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    auto lease = bundle.pool().acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    // Abort the caller's transaction: every further statement fails with 25P02.
    REQUIRE(pg::exec_params(lease.get(), "SELECT 1/0", std::vector<std::string>{}).status() ==
            PGRES_FATAL_ERROR);

    auto r = mgr.consume_ticket(lease.get(), id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kStoreError);
    CHECK(r.error().binding_check_unevaluated);
    CHECK(r.error().sqlstate == "25P02");
    REQUIRE(pg::exec_params(lease.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    CHECK(mgr.get(id)->consumed_at == 0); // nothing was spent
}

TEST_CASE("consume_ticket(PGconn*): a null connection is refused, never an autocommit consume",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    auto r = mgr.consume_ticket(static_cast<PGconn*>(nullptr), id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kStoreError);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume_ticket(PGconn*): the binding check's own read takes the row lock, with no write "
          "yet",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    // A refusal AT the binding check (wrong surface) issues no UPDATE at all, so any lock the
    // row carries afterwards was taken by that check's own `FOR UPDATE` read.
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        CHECK(probe_row_lock(bundle.pool(), id) == "55P03"); // lock_not_available
    });
    // The caller's rollback released it, and the row was never touched.
    CHECK(probe_row_lock(bundle.pool(), id).empty());
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume_ticket(PGconn*): the row is locked WHILE the precondition decides, and stays "
          "locked after it denies",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    std::string seen_inside_precondition = "unset";
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(
            conn, id, "alice", ApprovalOrigin::kMcp,
            [&](const Approval&) -> std::expected<void, std::string> {
                // Runs on the precondition's critical section: a second connection must
                // already be unable to take the row, so state read here cannot move before
                // the CAS.
                seen_inside_precondition = probe_row_lock(bundle.pool(), id);
                return std::unexpected("state moved");
            });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kPrecondition);
        // The denial wrote nothing, yet the lock is still held to the caller's txn end.
        CHECK(probe_row_lock(bundle.pool(), id) == "55P03");
    });
    CHECK(seen_inside_precondition == "55P03");
    CHECK(probe_row_lock(bundle.pool(), id).empty());
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume_ticket(PGconn*): a successful consume holds the lock to the caller's commit",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        REQUIRE(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
        CHECK(probe_row_lock(bundle.pool(), id) == "55P03");
    });
    CHECK(probe_row_lock(bundle.pool(), id).empty());
    CHECK(mgr.get(id)->consumed_at != 0);
}

TEST_CASE("consume_ticket(PGconn*): a replay after a successful consume is refused, inside the same "
          "transaction and after the commit",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        REQUIRE(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {}).has_value());
        auto again = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(again.has_value());
        CHECK(again.error().kind == ConsumeFailure::kNotConsumable);
        CHECK(again.error().message == kNotConsumableMessage);
        // ...and the refusal left the caller's transaction usable.
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
    });
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto later = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(later.has_value());
        CHECK(later.error().kind == ConsumeFailure::kNotConsumable);
    });
}

TEST_CASE("consume_ticket(PGconn*): a ticket past its lifetime is refused as expired and the "
          "caller's transaction stays healthy",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    // Reviewed 8 days ago (database time): past the 7-day lifetime, not yet swept.
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET reviewed_at = "
                    "extract(epoch from now())::bigint - 8*24*3600 WHERE id = $1",
                    {id})
                .status() == PGRES_COMMAND_OK);

    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kExpired);
        CHECK(r.error().message == kTicketExpiredMessage);
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
    });
    CHECK(mgr.get(id)->consumed_at == 0);
}

// -- submit_bound: the frozen request, digest and excluded roots -------------------

namespace {

const char* const kRequest =
    R"({"definition":{"name":"Block RDP","hash":"abc123"},"params":{"port":3389},"targets":["host-1"]})";

BoundRequest bound_request(std::vector<std::string> excluded = {}) {
    return BoundRequest{kRequest, std::move(excluded)};
}

} // namespace

TEST_CASE("submit_bound: freezes request_json, its digest and the excluded roots on the row",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    auto id = mgr.submit_bound("guardian.deploy.r1", "alice", "scope", "",
                               ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol", "dave"}));
    REQUIRE(id.has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->origin == ApprovalOrigin::kGuardianDeploy);
    CHECK(row->request_json == kRequest);
    REQUIRE(sha256_hex(kRequest).has_value());
    CHECK(row->request_digest == *sha256_hex(kRequest));
    CHECK(row->request_digest.size() == 64);
    CHECK(row->excluded_roots == std::vector<std::string>{"carol", "dave"});
    CHECK_FALSE(row->excluded_roots_unreadable);

    // Frozen: review and consumption never touch the three columns.
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    auto after = mgr.get(*id);
    CHECK(after->request_json == row->request_json);
    CHECK(after->request_digest == row->request_digest);
    CHECK(after->excluded_roots == row->excluded_roots);
}

TEST_CASE("submit_bound: the same bytes always digest the same; different bytes differ",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto a = mgr.submit_bound("guardian.a", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":1})", {}});
    auto b = mgr.submit_bound("guardian.b", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":1})", {}});
    auto c = mgr.submit_bound("guardian.c", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              BoundRequest{R"({"k":2})", {}});
    REQUIRE((a && b && c));
    CHECK(mgr.get(*a)->request_digest == mgr.get(*b)->request_digest);
    CHECK(mgr.get(*a)->request_digest != mgr.get(*c)->request_digest);
}

TEST_CASE("submit_bound: a bound ticket redeems only on its declared surface",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.deploy.r1", "alice", "", "",
                               ApprovalOrigin::kGuardianDeploy, bound_request());
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());

    auto as_mcp = mgr.consume_ticket(*id, "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(as_mcp.has_value());
    CHECK(as_mcp.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.consume_ticket(*id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
}

TEST_CASE("submit: an origin that requires a bound request cannot be minted unbound",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    CHECK(requires_bound_request(ApprovalOrigin::kGuardianDeploy));
    CHECK_FALSE(requires_bound_request(ApprovalOrigin::kMcp));

    auto r = mgr.submit("guardian.deploy.r1", "alice", "", "", ApprovalOrigin::kGuardianDeploy);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == kBoundRequestRequiredMessage);
    CHECK(mgr.pending_count() == 0);
}

TEST_CASE("submit_bound: an engine principal cannot submit a gated effect (typed refusal)",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    for (const char* engine : {"engine:vuln", "engine:x"}) {
        auto r = mgr.submit_bound("guardian.deploy.r1", engine, "", "",
                                  ApprovalOrigin::kGuardianDeploy, bound_request());
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kEnginePrincipal);
        CHECK(r.error().message == kEnginePrincipalSubmitMessage);
    }
    CHECK(mgr.pending_count() == 0); // nothing written

    // A human whose name merely CONTAINS the word is not an engine principal.
    auto human = mgr.submit_bound("guardian.deploy.r1", "engineer:ann", "", "",
                                  ApprovalOrigin::kGuardianDeploy, bound_request());
    CHECK(human.has_value());
}

namespace {

// `{"k":[[...[1]...]]}` with `containers` container levels in total (the object counts).
std::string nested_request(std::size_t containers) {
    std::string out = R"({"k":)";
    out.append(containers - 1, '[');
    out += "1";
    out.append(containers - 1, ']');
    out += "}";
    return out;
}

// A request of exactly `total` bytes: {"k":"aaa..."}.
std::string request_of_size(std::size_t total) {
    return std::string(R"({"k":")") + std::string(total - 8, 'a') + "\"}";
}

} // namespace

// One boundary per SECTION (Catch2 re-runs the case for each), each asserting the typed kind AND
// that the refusal is for the stated reason: a refusal for the wrong reason must not pass, and
// the first failure must not hide the others.
TEST_CASE("submit_bound: every validation bound, at the edge and one past it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto submit = [&](BoundRequest b, ApprovalOrigin o = ApprovalOrigin::kGuardianDeploy) {
        return mgr.submit_bound("guardian.d", "alice", "", "", o, b);
    };
    const auto refused_for = [&](BoundRequest b, const std::string& reason,
                                 ApprovalOrigin o = ApprovalOrigin::kGuardianDeploy) {
        auto r = submit(std::move(b), o);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kInvalidRequest);
        CHECK(r.error().message.find(reason) != std::string::npos);
        CHECK(mgr.pending_count() == 0); // nothing written
    };

    SECTION("nesting: exactly the limit is accepted") {
        CHECK(submit(BoundRequest{nested_request(kMaxRequestJsonDepth), {}}).has_value());
    }
    SECTION("nesting: one past the limit is refused for its depth") {
        refused_for(BoundRequest{nested_request(kMaxRequestJsonDepth + 1), {}}, "levels deep");
    }
    SECTION("size: exactly kMaxRequestJsonBytes is accepted") {
        const auto body = request_of_size(kMaxRequestJsonBytes);
        REQUIRE(body.size() == kMaxRequestJsonBytes);
        CHECK(submit(BoundRequest{body, {}}).has_value());
    }
    SECTION("size: one byte over is refused for its size") {
        const auto body = request_of_size(kMaxRequestJsonBytes + 1);
        REQUIRE(body.size() == kMaxRequestJsonBytes + 1);
        refused_for(BoundRequest{body, {}}, "at most");
    }
    SECTION("roots: exactly kMaxExcludedRoots is accepted") {
        CHECK(submit(BoundRequest{R"({"k":1})",
                                  std::vector<std::string>(kMaxExcludedRoots, "r")})
                  .has_value());
    }
    SECTION("roots: one past kMaxExcludedRoots is refused for the count") {
        refused_for(BoundRequest{R"({"k":1})", std::vector<std::string>(kMaxExcludedRoots + 1, "r")},
                    "at most " + std::to_string(kMaxExcludedRoots) + " excluded roots");
    }
    SECTION("root length: exactly kMaxExcludedRootBytes is accepted") {
        CHECK(submit(BoundRequest{R"({"k":1})", {std::string(kMaxExcludedRootBytes, 'r')}})
                  .has_value());
    }
    SECTION("root length: one byte over is refused for its length") {
        refused_for(BoundRequest{R"({"k":1})", {std::string(kMaxExcludedRootBytes + 1, 'r')}},
                    "each excluded root must be 1-");
    }
    SECTION("root length: an empty root is refused for its length") {
        refused_for(BoundRequest{R"({"k":1})", {""}}, "each excluded root must be 1-");
    }
    SECTION("a root that is not valid UTF-8 is refused as such") {
        refused_for(BoundRequest{R"({"k":1})", {std::string("bad\xff\xfe")}}, "valid UTF-8");
    }
    SECTION("request: empty") {
        refused_for(BoundRequest{"", {}}, "required");
    }
    SECTION("request: not JSON") {
        refused_for(BoundRequest{"not json", {}}, "JSON object");
    }
    SECTION("request: an array is not an object") {
        refused_for(BoundRequest{"[1,2]", {}}, "JSON object");
    }
    SECTION("request: a string is not an object") {
        refused_for(BoundRequest{"\"str\"", {}}, "JSON object");
    }
    SECTION("origin: kUnspecified is refused for naming no surface") {
        refused_for(bound_request(), "concrete origin", ApprovalOrigin::kUnspecified);
    }
    SECTION("origin: kUnrecognised is refused for naming no surface") {
        refused_for(bound_request(), "concrete origin", ApprovalOrigin::kUnrecognised);
    }
}

TEST_CASE("submit_bound: a NUL byte in request_json or a control character in a root is "
          "refused, nothing written",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto refused = [&](BoundRequest b) {
        auto r = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == SubmitFailure::kInvalidRequest);
    };

    // The parser reads a NUL after a complete value as end of input, so this PARSES as
    // {"k":1}; the digest would cover all 8 bytes while the column keeps 7.
    refused(BoundRequest{std::string(R"({"k":1})") + '\0' + "tail", {}});
    refused(BoundRequest{std::string(R"({"k":1})") + '\0', {}});
    refused(BoundRequest{std::string("\0", 1) + R"({"k":1})", {}});
    // A raw NUL inside a string literal is not valid JSON either; still refused.
    refused(BoundRequest{std::string("{\"k\":\"a") + '\0' + "b\"}", {}});
    // A control character or NUL inside an excluded root.
    refused(BoundRequest{R"({"k":1})", {std::string("car") + '\0' + "ol"}});
    refused(BoundRequest{R"({"k":1})", {"car\nol"}});
    refused(BoundRequest{R"({"k":1})", {"car\x7f"}});
    refused(BoundRequest{R"({"k":1})", {"ok", "tab\there"}});
    CHECK(mgr.pending_count() == 0);

    // Still-valid inputs are unchanged: an ESCAPED NUL (the six characters \u0000) is
    // ordinary text, and a root with punctuation or non-ASCII UTF-8 is fine.
    auto escaped = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                    BoundRequest{R"({"k":"a\u0000b"})", {"oidc:carol@example.org",
                                                                          "d\xC3\xA9j\xC3\xA0"}});
    REQUIRE(escaped.has_value());
    auto row = mgr.get(*escaped);
    REQUIRE(row.has_value());
    CHECK(row->request_json == R"({"k":"a\u0000b"})");
    CHECK(row->request_digest == *sha256_hex(row->request_json));
    CHECK(row->excluded_roots.size() == 2);
}

TEST_CASE("submit_bound: the pending cap refuses with the typed queue-full kind",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::test::seed_pending(bundle.pool(), "cap-", ApprovalManager::kMaxPendingApprovals,
                             /*age_seconds=*/60);
    auto r = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              bound_request());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == SubmitFailure::kQueueFull);
}

// -- approve(): excluded roots -------------------------------------------------

TEST_CASE("approve: a reviewer in excluded_roots is refused; others are not",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol", "dave"}));
    REQUIRE(id.has_value());

    for (const char* barred : {"carol", "dave"}) {
        auto r = mgr.approve(*id, barred, "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kExcludedReviewerMessage);
    }
    // The submitter stays barred by the original rule.
    auto self = mgr.approve(*id, "alice", "");
    REQUIRE_FALSE(self.has_value());
    CHECK(self.error() == "reviewer cannot be the same as the submitter");
    CHECK(mgr.get(*id)->status == "pending");

    // Byte-for-byte: a case variant is a different account, so it is not excluded.
    // (It would be if the compare folded case; see same_human_root.)
    CHECK(mgr.approve(*id, "Carol", "").has_value());
}

TEST_CASE("reviewer_is_excluded: byte-for-byte membership, the one predicate approve() and the "
          "dashboard share",
          "[approval_manager][bound]") {
    const std::vector<std::string> roots{"carol", "oidc:dave"};
    CHECK(reviewer_is_excluded("carol", roots));
    CHECK(reviewer_is_excluded("oidc:dave", roots));
    CHECK_FALSE(reviewer_is_excluded("Carol", roots)); // case-sensitive: a different account
    CHECK_FALSE(reviewer_is_excluded("dave", roots));
    CHECK_FALSE(reviewer_is_excluded("carol ", roots));
    CHECK_FALSE(reviewer_is_excluded("carol", {}));
    CHECK_FALSE(reviewer_is_excluded("", roots));
}

TEST_CASE("reject: an excluded root may still reject", "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol"}));
    REQUIRE(id.has_value());
    CHECK(mgr.reject(*id, "carol", "withdrawn").has_value());
    CHECK(mgr.get(*id)->status == "rejected");
}

TEST_CASE("approve: an unreadable excluded_roots column fails CLOSED", "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    for (const char* garbage : {"not json", R"({"a":1})", R"(["ok", 3])"}) {
        auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                   bound_request({"carol"}));
        REQUIRE(id.has_value());
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET excluded_roots = $1 WHERE id = $2",
                        {garbage, *id})
                    .status() == PGRES_COMMAND_OK);
        auto row = mgr.get(*id);
        REQUIRE(row.has_value());
        CHECK(row->excluded_roots_unreadable);

        auto r = mgr.approve(*id, "bob", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kExcludedRootsUnreadableMessage);
        CHECK(mgr.get(*id)->status == "pending");
        // Rejecting is still possible: it grants nothing.
        CHECK(mgr.reject(*id, "bob", "").has_value());
    }
}

TEST_CASE("approve: a bound request that cannot be read or verified is refused; reject still works",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string deep(kMaxRequestJsonDepth + 2, '[');
    const std::vector<std::pair<std::string, std::string>> edits = {
        {"request_json", "not json"},
        {"request_json", "[1,2]"},
        {"request_json", R"({"k":2})"},                                  // digest now stale
        {"request_json", std::string(R"({"k":)") + deep + std::string(deep.size(), ']') + "}"},
        {"request_digest", std::string(64, '0')},
        {"request_digest", ""},
    };
    for (const auto& [column, value] : edits) {
        auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                   bound_request());
        REQUIRE(id.has_value());
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET " + column + " = $1 WHERE id = $2",
                        {value, *id})
                    .status() == PGRES_COMMAND_OK);
        auto r = mgr.approve(*id, "bob", "");
        INFO(column << " = " << value.substr(0, 40));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kBoundRequestUnreadableMessage);
        CHECK(mgr.get(*id)->status == "pending");
        CHECK(mgr.reject(*id, "bob", "").has_value()); // the way to clear it from the queue
    }
    // And an untouched bound ticket still approves.
    auto ok = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request());
    REQUIRE(ok.has_value());
    CHECK(mgr.approve(*ok, "bob", "").has_value());
}

TEST_CASE("approve: an unreadable request whose digest still MATCHES it is refused for being "
          "unreadable, not for the digest",
          "[pg][approval_manager][bound]") {
    // Isolates the readability line of approve()'s request check. The tamper tests above all
    // leave a stale digest, so the digest comparison fires first and the uniform message hides
    // which branch refused; here the digest is recomputed over the stored bytes, so ONLY the
    // readability test can refuse.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string deep(kMaxRequestJsonDepth + 2, '[');
    const std::vector<std::string> unreadable = {
        "not json",
        "[1,2]",                                                         // not an object
        std::string(R"({"k":)") + deep + std::string(deep.size(), ']') + "}", // too deep
        std::string(R"({"k":")") + std::string(kMaxRequestJsonBytes, 'a') + "\"}", // too big
    };
    for (const auto& bad : unreadable) {
        auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                                   bound_request());
        REQUIRE(id.has_value());
        const auto digest = sha256_hex(bad);
        REQUIRE(digest.has_value());
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_json = $1, "
                        "request_digest = $2 WHERE id = $3",
                        {bad, *digest, *id})
                    .status() == PGRES_COMMAND_OK);
        INFO(bad.substr(0, 30));
        // Premise: digest and bytes agree, so a digest-only check would let this through.
        REQUIRE(mgr.get(*id)->request_digest == *sha256_hex(mgr.get(*id)->request_json));
        auto r = mgr.approve(*id, "bob", "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == kBoundRequestUnreadableMessage);
        CHECK(mgr.get(*id)->status == "pending");
    }
}

TEST_CASE("approve: an unbound ticket is unaffected by the exclusion machinery",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto id = mgr.submit("def", "alice", "", "", ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());
    CHECK(mgr.approve(*id, "carol", "").has_value());
}

// -- consume: the stored approval is re-checked, not trusted --------------------

namespace {

// An approved, unconsumed bound ticket (alice -> bob) excluding carol.
std::string approved_bound(ApprovalManager& mgr, const std::string& def = "guardian.d") {
    auto id = mgr.submit_bound(def, "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol"}));
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "bob", "").has_value());
    return *id;
}

// Both overloads must refuse with the same kind and message and leave the row unspent.
void check_refused_on_both_overloads(yuzu::test::ApprovalManagerPg& bundle, const std::string& id) {
    ApprovalManager& mgr = *bundle;
    auto pooled = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
    REQUIRE_FALSE(pooled.has_value());
    CHECK(pooled.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(pooled.error().message == kNotConsumableMessage); // uniform: no oracle
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        auto held = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(held.has_value());
        CHECK(held.error().kind == ConsumeFailure::kForeignOrigin);
        CHECK(held.error().message == kNotConsumableMessage);
        // A refusal that is not a store error leaves the caller's transaction healthy.
        CHECK(pg::exec_params(conn, "SELECT 1", std::vector<std::string>{}).status() ==
              PGRES_TUPLES_OK);
    });
    CHECK(mgr.get(id)->consumed_at == 0);
}

} // namespace

TEST_CASE("consume: a sound bound ticket still redeems on both overloads",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto pooled = approved_bound(mgr, "guardian.p");
    CHECK(mgr.consume_ticket(pooled, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    const auto held = approved_bound(mgr, "guardian.h");
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, held, "alice", ApprovalOrigin::kGuardianDeploy, {})
                  .has_value());
    });
    CHECK(mgr.get(held)->consumed_at != 0);
}

TEST_CASE("consume: a ticket whose stored reviewer is an excluded root or the submitter is "
          "refused, whoever reviewed it",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    for (const char* forced : {"carol", "alice"}) {
        // A row approved by something that did not run approve()'s checks: forced by SQL.
        const auto id = approved_bound(mgr, std::string("guardian.") + forced);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_by = $1 WHERE id = $2",
                        {forced, id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
}

TEST_CASE("consume: an unreadable excluded_roots column on an approved ticket refuses",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    const auto id = approved_bound(*bundle);
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET excluded_roots = 'not json' "
                    "WHERE id = $1",
                    {id})
                .status() == PGRES_COMMAND_OK);
    check_refused_on_both_overloads(bundle, id);
}

TEST_CASE("consume: a request_json that no longer hashes to request_digest refuses",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    SECTION("tampered digest") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_digest = repeat('0', 64) "
                        "WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("tampered request") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_json = '{\"k\":2}' "
                        "WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("digest cleared while the request stays") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_digest = '' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
    SECTION("a digest with no request behind it") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET request_json = '' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        check_refused_on_both_overloads(bundle, id);
    }
}

TEST_CASE("consume: a legacy row (no request, no digest, no roots) is not re-checked into "
          "a refusal",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto pooled = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-pooled");
    CHECK(mgr.consume_ticket(pooled, "alice", ApprovalOrigin::kMcp, {}).has_value());
    const auto held = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-held");
    in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
        CHECK(mgr.consume_ticket(conn, held, "alice", ApprovalOrigin::kMcp, {}).has_value());
    });
}

TEST_CASE("consume: a replay of a SPENT ticket whose row was later tampered still reads as "
          "an ordinary replay",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_bound(mgr);
    REQUIRE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET request_digest = repeat('0', 64) "
                    "WHERE id = $1",
                    {id})
                .status() == PGRES_COMMAND_OK);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
}

// -- consume: the check and the CAS are one decision (Gate 8 g8-sg-1) -------------------

namespace {

// Mutate a stored column on a SECOND lease, autocommit: what an out-of-band writer (an
// old-build replica, a hand edit) does between the integrity read and the consuming CAS.
void rewrite_column(yuzu::test::ApprovalManagerPg& bundle, const std::string& id,
                    const std::string& column, const std::string& value) {
    REQUIRE(run_sql(bundle.pool(),
                    "UPDATE approval_manager.approvals SET " + column + " = $1 WHERE id = $2",
                    {value, id})
                .status() == PGRES_COMMAND_OK);
}

} // namespace

TEST_CASE("consume (pooled): a reviewer rewrite committed BETWEEN the integrity read and the CAS "
          "is not consumed (CH2-1 leg A)",
          "[pg][approval_manager][bound][race]") {
    // Gate 5 sketched this leg with a PENDING row flipped to approved. That cannot be made
    // deterministic: the CAS requires status = 'approved', so against the pre-commit snapshot
    // it does not match, never waits on the writer's lock, and simply finds nothing. The
    // reachable deterministic shape is an already-approved row (the integrity read passes)
    // whose reviewer is rewritten by a writer that holds an uncommitted UPDATE: the CAS matches
    // the old tuple, parks on the lock, and re-evaluates against the NEW tuple when it commits.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_bound(mgr); // excludes carol; approved by bob

    auto x = bundle.pool().acquire();
    REQUIRE(x);
    REQUIRE(pg::exec_params(x.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(x.get(),
                            "UPDATE approval_manager.approvals SET reviewed_by = 'carol' WHERE id = $1",
                            std::vector<std::string>{id})
                .status() == PGRES_COMMAND_OK);

    std::expected<void, ConsumeError> result;
    std::thread consumer([&] {
        result = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
    });
    // A failing REQUIRE below throws; a joinable std::thread destroyed during that unwind
    // calls std::terminate and takes the whole test binary with it. This releases the writer's
    // lock first (the consumer is parked on it, so joining without that would hang) and joins.
    JoinGuard guard{consumer, [&] {
                        (void)pg::exec_params(x.get(), "ROLLBACK", std::vector<std::string>{});
                    }};
    // Wait (bounded) until the consumer is parked on the lock, then let X commit.
    bool blocked = false;
    for (int i = 0; i < 200 && !blocked; ++i) {
        auto q = run_sql(bundle.pool(),
                         "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                         "AND query LIKE 'UPDATE approval_manager.approvals SET consumed_at%'");
        blocked = q.status() == PGRES_TUPLES_OK && std::string(PQgetvalue(q.get(), 0, 0)) != "0";
        if (!blocked)
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    REQUIRE(pg::exec_params(x.get(), "COMMIT", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    consumer.join();
    CHECK(blocked); // the premise: the CAS really was waiting on the writer

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(result.error().message == kNotConsumableMessage);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume (pooled): a precondition that rewrites the examined row from a second lease "
          "cannot make the consume succeed (CH2-1 leg B)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto rewrites = std::vector<std::pair<std::string, std::string>>{
        {"reviewed_by", "carol"},                         // an excluded root
        {"reviewed_by", "alice"},                         // the submitter
        {"request_digest", std::string(64, '0')},         // digest no longer matches
        {"request_json", R"({"k":"swapped"})"},           // request swapped under the digest
        {"excluded_roots", R"(["bob"])"},                 // roots now name the reviewer
    };
    for (const auto& [column, value] : rewrites) {
        DYNAMIC_SECTION(column << " := " << value.substr(0, 20)) {
            const auto id = approved_bound(mgr, "guardian." + column + value.substr(0, 4));
            auto r = mgr.consume_ticket(
                id, "alice", ApprovalOrigin::kGuardianDeploy,
                [&](const Approval&) -> std::expected<void, std::string> {
                    rewrite_column(bundle, id, column, value); // after the check, before the CAS
                    return {};
                });
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == ConsumeFailure::kNotConsumable); // uniform, not a store error
            CHECK(r.error().message == kNotConsumableMessage);
            CHECK(mgr.get(id)->consumed_at == 0);
        }
    }
}

TEST_CASE("consume (held, AUTOCOMMIT connection): the FOR UPDATE lock drops per statement, so the "
          "CAS pin must still refuse a rewritten row (CH2-2)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_bound(mgr);
    auto lease = bundle.pool().acquire(); // no BEGIN: every statement commits on its own
    REQUIRE(lease);
    auto r = mgr.consume_ticket(
        lease.get(), id, "alice", ApprovalOrigin::kGuardianDeploy,
        [&](const Approval&) -> std::expected<void, std::string> {
            rewrite_column(bundle, id, "reviewed_by", "carol");
            return {};
        });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("consume: an untouched ticket still consumes with a precondition that only reads",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto bound = approved_bound(mgr, "guardian.p");
    CHECK(mgr.consume_ticket(bound, "alice", ApprovalOrigin::kGuardianDeploy,
                             [](const Approval&) -> std::expected<void, std::string> { return {}; })
              .has_value());
    const auto legacy = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-legacy-race");
    CHECK(mgr.consume_ticket(legacy, "alice", ApprovalOrigin::kMcp,
                             [](const Approval&) -> std::expected<void, std::string> { return {}; })
              .has_value());
}

// -- consume: the checks and the CAS apply to the SAME examined row (Gate 8 round 3) ------
//
// Deterministic interleavings through ApprovalManager's test seam: `kBetweenReads` runs after
// the first read and before the precondition's fresher read, `kBeforeCas` after every check
// has passed and immediately before the consuming statement.

namespace {

using Stage = ApprovalManager::ConsumeTestStage;

// How many times the interleaving hook of the CURRENT test reached its stage. A test that
// expects a refusal checks this is 1: a refusal that happens because the hook was moved or
// removed is not evidence about the race.
int g_fired = 0;

// Run `change` (autocommit SQL on a second lease) each time `stage` is reached (once per consume).
void interleave(ApprovalManager& mgr, yuzu::test::ApprovalManagerPg& bundle, Stage at,
                const std::string& sql, const std::string& id,
                const std::vector<std::string>& extra = {}) {
    g_fired = 0;
    mgr.set_consume_test_hook_for_test([&bundle, at, sql, id, extra](Stage got) {
        if (got != at)
            return;
        ++g_fired;
        std::vector<std::string> params{id};
        params.insert(params.end(), extra.begin(), extra.end());
        auto lease = bundle.pool().acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), sql.c_str(), params).status() == PGRES_COMMAND_OK);
    });
}

constexpr const char* kFlipToApproved =
    "UPDATE approval_manager.approvals SET status = 'approved', "
    "reviewed_at = extract(epoch from now())::bigint WHERE id = $1";

// A pending bound ticket (alice, excluding carol) after `setup` SQL.
std::string pending_bound(ApprovalManager& mgr, yuzu::test::ApprovalManagerPg& bundle,
                          const std::string& setup_sql = {}) {
    auto id = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                               bound_request({"carol"}));
    REQUIRE(id.has_value());
    if (!setup_sql.empty())
        REQUIRE(run_sql(bundle.pool(), setup_sql, {*id}).status() == PGRES_COMMAND_OK);
    return *id;
}

void require_refused(ApprovalManager& mgr, const std::string& id, ConsumeFailure kind,
                     const ConsumePrecondition& pre = {}, bool hooked = false) {
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, pre);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == kind);
    CHECK(r.error().message == kNotConsumableMessage);
    CHECK(mgr.get(id)->consumed_at == 0);
    if (hooked) // only a test that installed an interleaving hook has a count to check
        CHECK(g_fired == 1);
}

const ConsumePrecondition kPass = [](const Approval&) -> std::expected<void, std::string> {
    return {};
};

} // namespace

TEST_CASE("consume: a row examined as not-approved cannot be spent after a status-only flip "
          "(CH3-1 cells A1, A2, A4, C)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    SECTION("A1: pending, reviewer == submitter") {
        const auto id = pending_bound(mgr, bundle,
            "UPDATE approval_manager.approvals SET reviewed_by = 'alice' WHERE id = $1");
        interleave(mgr, bundle, Stage::kBeforeCas, kFlipToApproved, id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("A2: pending, reviewer is an excluded root") {
        const auto id = pending_bound(mgr, bundle,
            "UPDATE approval_manager.approvals SET reviewed_by = 'carol' WHERE id = $1");
        interleave(mgr, bundle, Stage::kBeforeCas, kFlipToApproved, id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("A4: pending, no reviewer recorded") {
        const auto id = pending_bound(mgr, bundle);
        interleave(mgr, bundle, Stage::kBeforeCas, kFlipToApproved, id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("C: rejected by an excluded root, then flipped to approved") {
        const auto id = pending_bound(mgr, bundle);
        REQUIRE(mgr.reject(id, "carol", "withdrawn").has_value());
        interleave(mgr, bundle, Stage::kBeforeCas, kFlipToApproved, id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("an expired row flipped to approved is refused too") {
        const auto id = pending_bound(mgr, bundle,
            "UPDATE approval_manager.approvals SET status = 'expired', reviewed_by = 'bob' WHERE id = $1");
        interleave(mgr, bundle, Stage::kBeforeCas, kFlipToApproved, id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(mgr.get(id)->consumed_at == 0);
        CHECK(g_fired == 1);
    }
}

// -- consume vs #6096's schedule retire: a retire is a writer like any other -----------------
//
// `retire_schedule_tickets` settles a scheduled ticket (consumed_at, consumed_by) and so moves
// the row to a new version. A consume that examined the row before the retire must be refused
// by the pinned consuming statement, never spend a settled ticket. consume_ticket has no
// production caller that declares kSchedule (the tripwire pins that); the declaration is used
// here only to get past the origin check and reach the CAS, which is the part under test.

TEST_CASE("consume: a schedule retire between the read and the CAS makes the consume refuse "
          "(row moved; #6096 x #6062)",
          "[pg][approval_manager][bound][race][6096]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    const auto mint = [&] {
        auto id = mgr.submit("def-sched", "alice", "scope", "sched-a", ApprovalOrigin::kSchedule,
                             "procs", "list");
        REQUIRE(id.has_value());
        REQUIRE(mgr.approve(*id, "bob", "").has_value());
        return *id;
    };
    const auto retire_it = [&](const std::string& id) {
        auto n = mgr.retire_schedule_tickets("sched-a", "sched-a:1", {id});
        REQUIRE(n.has_value());
        CHECK(*n == 1);
    };

    for (const auto stage : {Stage::kBeforeFirstRead, Stage::kBeforeCas, Stage::kBetweenReads}) {
        INFO("stage " << static_cast<int>(stage));
        const auto id = mint();
        int fired = 0;
        mgr.set_consume_test_hook_for_test([&](Stage got) {
            if (got != stage)
                return;
            ++fired;
            retire_it(id);
        });
        // kBetweenReads only runs when a precondition is supplied.
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kSchedule, kPass);
        mgr.set_consume_test_hook_for_test({});
        CHECK(fired == 1);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message == kNotConsumableMessage);
        // The row is the RETIRE's, not the consume's: settled once, by the schedule.
        const auto row = mgr.get(id);
        REQUIRE(row.has_value());
        CHECK(row->consumed_at != 0);
        CHECK(row->consumed_by == "schedule:sched-a:1");
    }

    SECTION("a ticket retired BEFORE the consume starts is refused, and a second retire is a no-op") {
        const auto id = mint();
        retire_it(id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kSchedule, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message == kNotConsumableMessage);
        auto again = mgr.retire_schedule_tickets("sched-a", "sched-a:2", {id});
        REQUIRE(again.has_value());
        CHECK(*again == 0);
        CHECK(mgr.get(id)->consumed_by == "schedule:sched-a:1");
    }

    SECTION("the legacy retire marker is as final as a normal retire") {
        const auto id = mint();
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET consumed_at = 7, consumed_by = "
                        "'schedule:legacy-6096' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kSchedule, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(mgr.get(id)->consumed_at == 7);
    }
}

TEST_CASE("consume: the fix must not turn ordinary refusals into integrity refusals (CH3-2)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    int observed = 0;
    mgr.set_precondition_denial_observer([&](const PreconditionDenial&) { ++observed; });

    // A ticket legitimately REJECTED by an excluded root (allowed: rejecting grants nothing).
    const auto rejected = pending_bound(mgr, bundle);
    REQUIRE(mgr.reject(rejected, "carol", "").has_value());
    require_refused(mgr, rejected, ConsumeFailure::kNotConsumable);          // no precondition
    require_refused(mgr, rejected, ConsumeFailure::kNotConsumable, kPass);   // with one
    // Pending and EXPIRED rows are ordinary refusals too, and expired still reaches the
    // diagnostic read (kExpired, "submit a new request").
    const auto pending = pending_bound(mgr, bundle);
    require_refused(mgr, pending, ConsumeFailure::kNotConsumable);
    const auto expired = pending_bound(mgr, bundle,
        "UPDATE approval_manager.approvals SET status = 'expired' WHERE id = $1");
    auto r = mgr.consume_ticket(expired, "alice", ApprovalOrigin::kGuardianDeploy, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kExpired);
    CHECK(observed == 0);
}

TEST_CASE("consume: origin, submitter and integrity are re-checked on the precondition's fresher "
          "read, not only the first (CH3-1 cells B1, B2)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    SECTION("B1: origin rewritten between the reads") {
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBetweenReads,
                   "UPDATE approval_manager.approvals SET origin = 'mcp' WHERE id = $1", id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, kPass);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        CHECK(mgr.get(id)->consumed_at == 0);
        CHECK(g_fired == 1);
    }
    SECTION("B2: submitter rewritten between the reads") {
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBetweenReads,
                   "UPDATE approval_manager.approvals SET submitted_by = 'mallory' WHERE id = $1", id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, kPass);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignSubmitter);
        CHECK(mgr.get(id)->consumed_at == 0);
        CHECK(g_fired == 1);
    }
    SECTION("integrity: reviewer becomes an excluded root between the reads") {
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBetweenReads,
                   "UPDATE approval_manager.approvals SET reviewed_by = 'carol' WHERE id = $1", id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, kPass);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        CHECK(mgr.get(id)->consumed_at == 0);
        CHECK(g_fired == 1);
    }
}

TEST_CASE("consume: the CAS pins origin and submitter themselves (a change AFTER every check)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    SECTION("origin") {
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET origin = 'mcp' WHERE id = $1", id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("submitted_by") {
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET submitted_by = 'mallory' WHERE id = $1", id);
        require_refused(mgr, id, ConsumeFailure::kNotConsumable, {}, /*hooked=*/true);
    }
    SECTION("the same holds on the held overload, in a real transaction") {
        const auto id = approved_bound(mgr);
        // Inside the caller's txn the FOR UPDATE lock blocks the second lease's UPDATE, so the
        // hook would deadlock; the lock IS the protection there, asserted elsewhere. Here only
        // that the pinned statement is still correct for an untouched row on this overload.
        in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
            CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {})
                      .has_value());
        });
    }
}

TEST_CASE("consume: the CAS pins the WHOLE row version, so any change after the checks is refused "
          "(g8r4-sg-1, g8r4-up-1, g8r4-up-3)",
          "[pg][approval_manager][bound][race]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string consume_now =
        "extract(epoch from now())::bigint";

    SECTION("QE-d: a consumed, integrity-faulted row un-consumed before the CAS is not spent") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_by = submitted_by, "
                        "consumed_at = " + consume_now + ", consumed_by = 'earlier' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET consumed_at = 0, consumed_by = '' "
                   "WHERE id = $1",
                   id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty()); // the CAS would have stamped "alice"
    }
    SECTION("QE-d2: the same with no recorded reviewer") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_by = '', consumed_at = " +
                            consume_now + ", consumed_by = 'earlier' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET consumed_at = 0, consumed_by = '' "
                   "WHERE id = $1",
                   id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty());
    }
    SECTION("the same un-consume on the held overload over an AUTOCOMMIT connection") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_by = submitted_by, "
                        "consumed_at = " + consume_now + ", consumed_by = 'earlier' WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET consumed_at = 0, consumed_by = '' "
                   "WHERE id = $1",
                   id);
        auto lease = bundle.pool().acquire(); // no BEGIN: the lock does not outlive the SELECT
        REQUIRE(lease);
        auto r = mgr.consume_ticket(lease.get(), id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty());
    }
    SECTION("reviewed_at rewritten on an expired ticket makes it live again: refused") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(),
                        "UPDATE approval_manager.approvals SET reviewed_at = " + consume_now +
                            " - 8*24*3600 WHERE id = $1",
                        {id})
                    .status() == PGRES_COMMAND_OK);
        // Unchanged, the ticket is expired.
        {
            auto control = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
            REQUIRE_FALSE(control.has_value());
            CHECK(control.error().kind == ConsumeFailure::kExpired);
        }
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET reviewed_at = " + consume_now +
                       " WHERE id = $1",
                   id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty());
    }
    SECTION("a column the checks never read (definition, scope, target, schedule)") {
        for (const char* change : {"definition_id = 'guardian.other'", "scope_expression = 'all'",
                                   "target_plugin = 'other'", "target_action = 'other'",
                                   "schedule_id = 'sched-1'"}) {
            DYNAMIC_SECTION(change) {
                const auto id = approved_bound(mgr, std::string("guardian.") + change[0] + change[1]);
                interleave(mgr, bundle, Stage::kBeforeCas,
                           std::string("UPDATE approval_manager.approvals SET ") + change +
                               " WHERE id = $1",
                           id);
                auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
                REQUIRE_FALSE(r.has_value());
                CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
                CHECK(g_fired == 1);
                CHECK(mgr.get(id)->consumed_by.empty());
            }
        }
    }
    SECTION("a no-op rewrite changes the row version and is refused, fail closed") {
        // `SET reviewed_by = reviewed_by` writes a new tuple with the same values. The pin cannot
        // tell that from a real change, so it refuses; the ticket is intact and a retry (a fresh
        // read of the new version) succeeds. The cost of a whole-row pin is this false refusal.
        const auto id = approved_bound(mgr);
        interleave(mgr, bundle, Stage::kBeforeCas,
                   "UPDATE approval_manager.approvals SET reviewed_by = reviewed_by WHERE id = $1",
                   id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
        CHECK(g_fired == 1);
        mgr.set_consume_test_hook_for_test({});
        CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    }
    SECTION("a row frozen by VACUUM FREEZE reads the same version at the check and at the CAS") {
        const auto id = approved_bound(mgr);
        // Not inside a transaction block, as VACUUM requires; autocommit on a leased connection.
        REQUIRE(run_sql(bundle.pool(), "VACUUM (FREEZE) approval_manager.approvals").status() ==
                PGRES_COMMAND_OK);
        CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    }
    SECTION("an untouched row is consumed by every overload that can run it") {
        const auto pooled = approved_bound(mgr, "guardian.pooled");
        CHECK(mgr.consume_ticket(pooled, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
        const auto pre = approved_bound(mgr, "guardian.pre");
        CHECK(mgr.consume_ticket(pre, "alice", ApprovalOrigin::kGuardianDeploy, kPass).has_value());
        const auto held = approved_bound(mgr, "guardian.held");
        in_txn(bundle.pool(), /*commit=*/true, [&](PGconn* conn) {
            CHECK(mgr.consume_ticket(conn, held, "alice", ApprovalOrigin::kGuardianDeploy, kPass)
                      .has_value());
        });
    }
}

TEST_CASE("consume: the held overload refuses a row its OWN transaction rewrote after the "
          "checks (g8r5-sg-2)",
          "[pg][approval_manager][bound][race]") {
    // A version pinned by `xmin` alone cannot see this: every write a transaction makes to a row
    // carries that transaction's xid, so once the caller's transaction has written the row, a
    // second write by it presents the SAME xmin. The pin also carries the tuple position (`ctid`),
    // which differs for every version, so the second write still moves it.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string now_sql = "extract(epoch from now())::bigint";
    const std::string upd = "UPDATE approval_manager.approvals SET ";

    // `prior` runs in the caller's transaction BEFORE the consume (so the examined version's xmin
    // is already the caller's own); `change` runs on the SAME connection at kBeforeCas. The
    // consume must then refuse uniformly and must not spend the ticket.
    const auto run_cell = [&](const std::string& prior, const std::string& change, bool with_pre) {
        const auto id = approved_bound(mgr);
        in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
            auto prior_res = pg::exec_params(conn, (upd + prior + " WHERE id = $1").c_str(),
                                             std::vector<std::string>{id});
            REQUIRE(prior_res.status() == PGRES_COMMAND_OK);
            REQUIRE(std::string(PQcmdTuples(prior_res.get())) == "1"); // the prior write happened
            // ... and it made this transaction the row's writer, which is what lets a second
            // write keep the xmin (without it, xmin alone would refuse and prove nothing here).
            auto mine = pg::exec_params(conn,
                                        "SELECT xmin::text = txid_current()::text FROM "
                                        "approval_manager.approvals WHERE id = $1",
                                        std::vector<std::string>{id});
            REQUIRE(mine.status() == PGRES_TUPLES_OK);
            REQUIRE(PQntuples(mine.get()) == 1);
            REQUIRE(std::string(PQgetvalue(mine.get(), 0, 0)) == "t");
            g_fired = 0;
            mgr.set_consume_test_hook_for_test([&](Stage got) {
                if (got != Stage::kBeforeCas)
                    return;
                ++g_fired;
                auto res = pg::exec_params(conn, (upd + change + " WHERE id = $1").c_str(),
                                           std::vector<std::string>{id});
                REQUIRE(res.status() == PGRES_COMMAND_OK);
                CHECK(std::string(PQcmdTuples(res.get())) == "1"); // the rewrite really happened
            });
            auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy,
                                        with_pre ? kPass : ConsumePrecondition{});
            mgr.set_consume_test_hook_for_test({});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
            CHECK(r.error().message == kNotConsumableMessage);
            CHECK(g_fired == 1);
            // Read through the caller's own transaction: the consuming statement stamped nothing.
            auto who = pg::exec_params(conn,
                                       "SELECT consumed_by FROM approval_manager.approvals "
                                       "WHERE id = $1",
                                       std::vector<std::string>{id});
            REQUIRE(who.status() == PGRES_TUPLES_OK);
            REQUIRE(PQntuples(who.get()) == 1);
            CHECK(std::string(PQgetvalue(who.get(), 0, 0)).find("alice") == std::string::npos);
        });
    };

    SECTION("consumed_at reset to 0 after an integrity-faulted row was consumed") {
        // No precondition variant: a precondition re-reads the row and refuses a consumed one
        // before the statement under test, so the hook (the point of the cell) is never reached.
        run_cell("reviewed_by = submitted_by, consumed_at = " + now_sql + ", consumed_by = 'earlier'",
                 "consumed_at = 0, consumed_by = ''", /*with_pre=*/false);
    }

    for (const bool with_pre : {false, true}) {
        DYNAMIC_SECTION(std::string(with_pre ? "with" : "without") + " a precondition") {
            SECTION("reviewed_at rewritten on an expired ticket makes it live again") {
                run_cell("reviewed_at = " + now_sql + " - 8*24*3600", "reviewed_at = " + now_sql,
                         with_pre);
            }
            SECTION("a column the checks never read (definition, scope, target, schedule)") {
                for (const char* change :
                     {"definition_id = 'guardian.other'", "scope_expression = 'all'",
                      "target_plugin = 'other'", "target_action = 'other'",
                      "schedule_id = 'sched-1'"}) {
                    DYNAMIC_SECTION(change) {
                        run_cell("reviewed_by = reviewed_by", change, with_pre);
                    }
                }
            }
        }
    }

    SECTION("control: a row the caller's transaction wrote, then consumed, is spent") {
        // The same prior write with no second write after the checks: the position read by the
        // consume is the position the CAS sees, so a transaction that wrote the row first is
        // not refused for having done so.
        const auto id = approved_bound(mgr);
        in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
            auto prior_res = pg::exec_params(conn, (upd + "reviewed_by = reviewed_by WHERE id = $1").c_str(),
                                             std::vector<std::string>{id});
            REQUIRE(prior_res.status() == PGRES_COMMAND_OK);
            REQUIRE(std::string(PQcmdTuples(prior_res.get())) == "1");
            CHECK(mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, kPass)
                      .has_value());
        });
    }
}

TEST_CASE("consume: the xmin leg of the version pin refuses a rewrite that returns the examined "
          "tuple position (g8r6-qe-1)",
          "[pg][approval_manager][bound][race]") {
    // `ctid` alone is not a version: two writes by OTHER transactions with a plain VACUUM between
    // them put the new tuple back in the slot the examined version occupied (the first write
    // vacates it, the VACUUM frees it, the second write reuses it). Only `xmin` tells the two
    // tuples apart. The hook performs exactly that sequence, REQUIREs that the position really
    // came back with a different xmin (so the case cannot go green by the race not happening),
    // and the consume must still refuse; a pin on ctid alone would spend the ticket on a row
    // whose definition was changed.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;

    const auto position = [&](const std::string& id) {
        auto lease = bundle.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(),
                                   "SELECT ctid::text, xmin::text FROM "
                                   "approval_manager.approvals WHERE id = $1",
                                   std::vector<std::string>{id});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        return std::make_pair(std::string(PQgetvalue(res.get(), 0, 0)),
                              std::string(PQgetvalue(res.get(), 0, 1)));
    };
    const auto aba_hook = [&](const std::string& id, const std::pair<std::string, std::string>& examined) {
        g_fired = 0;
        mgr.set_consume_test_hook_for_test([&bundle, &position, id, examined](Stage got) {
            if (got != Stage::kBeforeCas)
                return;
            ++g_fired;
            auto lease = bundle.pool().acquire();
            REQUIRE(lease);
            const auto exec = [&](const char* sql, bool with_id = true) {
                auto res = pg::exec_params(lease.get(), sql,
                                           with_id ? std::vector<std::string>{id}
                                                   : std::vector<std::string>{});
                REQUIRE(res.status() == PGRES_COMMAND_OK);
                return std::string(PQcmdTuples(res.get()));
            };
            // Rewrite, VACUUM, rewrite ... until the new tuple lands back in the examined slot.
            // Each rewrite vacates the slot of the version before it; a plain VACUUM (autocommit;
            // the examined read has finished) frees it for the next. Every rewrite also changes
            // a column no explicit pin reads, so the row that comes back is not the one examined.
            for (int round = 0; round < 8; ++round) {
                const auto sql = "UPDATE approval_manager.approvals SET definition_id = "
                                 "'guardian.other', review_comment = 'round " +
                                 std::to_string(round) + "' WHERE id = $1";
                CHECK(exec(sql.c_str()) == "1");
                if (position(id).first == examined.first)
                    break;
                exec("VACUUM approval_manager.approvals", /*with_id=*/false);
            }
            const auto now = position(id);
            REQUIRE(now.first == examined.first);  // the tuple position came back ...
            REQUIRE(now.second != examined.second); // ... under a different writer
        });
    };

    SECTION("pooled overload") {
        const auto id = approved_bound(mgr);
        aba_hook(id, position(id));
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        mgr.set_consume_test_hook_for_test({});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
        CHECK(r.error().message == kNotConsumableMessage);
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty());
        // The row was never spent, so a retry reads the new version and succeeds.
        CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    }
    SECTION("held overload over an autocommit connection") {
        const auto id = approved_bound(mgr);
        aba_hook(id, position(id));
        auto lease = bundle.pool().acquire(); // no BEGIN: the lock does not outlive the SELECT
        REQUIRE(lease);
        auto r = mgr.consume_ticket(lease.get(), id, "alice", ApprovalOrigin::kGuardianDeploy, {});
        mgr.set_consume_test_hook_for_test({});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
        CHECK(g_fired == 1);
        CHECK(mgr.get(id)->consumed_by.empty());
    }
}

TEST_CASE("consume: a rewrite between a caller's own read and the first read is the row examined, "
          "so a request-match precondition sees it (g8r7-astra-D)",
          "[pg][approval_manager][race]") {
    // The MCP recall matches a ticket to its request with a read of its own, then calls
    // consume_ticket, which reads the row again. A rewrite of the matched fields in between is
    // examined (and its version pinned) by consume_ticket, not by the caller's earlier match, so
    // the caller must re-check the row consume_ticket hands its precondition.
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto minted = [&] {
        auto id = mgr.submit("tool.a", "alice", "args-a", "", ApprovalOrigin::kMcp);
        REQUIRE(id.has_value());
        REQUIRE(mgr.approve(*id, "bob", "").has_value());
        return *id;
    };
    const std::string rewrite =
        "UPDATE approval_manager.approvals SET scope_expression = 'args-b' WHERE id = $1";

    SECTION("without a precondition the rewritten row is consumed (why the MCP recall supplies one)") {
        const auto id = minted();
        interleave(mgr, bundle, Stage::kBeforeFirstRead, rewrite, id);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {});
        mgr.set_consume_test_hook_for_test({});
        CHECK(g_fired == 1);
        REQUIRE(r.has_value());
        CHECK(mgr.get(id)->scope_expression == "args-b"); // spent under content the caller never matched
    }
    SECTION("a precondition that compares the row to the request refuses it, ticket untouched") {
        const auto id = minted();
        interleave(mgr, bundle, Stage::kBeforeFirstRead, rewrite, id);
        const ConsumePrecondition matches = [](const Approval& row) -> std::expected<void, std::string> {
            if (row.definition_id != "tool.a" || row.scope_expression != "args-a")
                return std::unexpected("request does not match the approval");
            return {};
        };
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, matches);
        mgr.set_consume_test_hook_for_test({});
        CHECK(g_fired == 1);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kPrecondition);
        CHECK(mgr.get(id)->consumed_at == 0);
        CHECK(mgr.get(id)->consumed_by.empty());
    }
    SECTION("the same precondition consumes an unmoved row") {
        const auto id = minted();
        g_fired = 0;
        const ConsumePrecondition matches = [](const Approval& row) -> std::expected<void, std::string> {
            if (row.definition_id != "tool.a" || row.scope_expression != "args-a")
                return std::unexpected("request does not match the approval");
            return {};
        };
        CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, matches).has_value());
    }
}

TEST_CASE("consume: an absent id is an ordinary not-consumable, with or without a precondition",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    auto r = mgr.consume_ticket("does-not-exist", "alice", ApprovalOrigin::kMcp, {});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(r.error().message == kNotConsumableMessage);
    auto held = mgr.consume_ticket("does-not-exist", "alice", ApprovalOrigin::kMcp, kPass);
    REQUIRE_FALSE(held.has_value());
    CHECK(held.error().kind == ConsumeFailure::kNotConsumable);
}

TEST_CASE("consume: an approved row with NO recorded reviewer is refused, legacy or bound",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const std::string clear =
        "UPDATE approval_manager.approvals SET reviewed_by = '' WHERE id = $1";

    SECTION("bound, pooled") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(), clear, {id}).status() == PGRES_COMMAND_OK);
        require_refused(mgr, id, ConsumeFailure::kForeignOrigin);
    }
    SECTION("bound, pooled with a precondition (the fresher read checks it too)") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(), clear, {id}).status() == PGRES_COMMAND_OK);
        require_refused(mgr, id, ConsumeFailure::kForeignOrigin, kPass);
    }
    SECTION("legacy unbound MCP ticket") {
        const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-no-reviewer");
        REQUIRE(run_sql(bundle.pool(), clear, {id}).status() == PGRES_COMMAND_OK);
        auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
    }
    SECTION("held overload") {
        const auto id = approved_bound(mgr);
        REQUIRE(run_sql(bundle.pool(), clear, {id}).status() == PGRES_COMMAND_OK);
        in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
            auto r = mgr.consume_ticket(conn, id, "alice", ApprovalOrigin::kGuardianDeploy, {});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == ConsumeFailure::kForeignOrigin);
        });
    }
    SECTION("a ticket approve() produced always has one") {
        const auto id = approved_bound(mgr);
        CHECK_FALSE(mgr.get(id)->reviewed_by.empty());
        CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, {}).has_value());
    }
}

// -- kPrecondition denial: counted and observed at the store --------------------

namespace {
const ConsumePrecondition kDeny = [](const Approval&) -> std::expected<void, std::string> {
    return std::unexpected("state moved");
};
} // namespace

TEST_CASE("a precondition denial is counted per origin and reported to the observer, for every "
          "origin and both overloads",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    std::vector<PreconditionDenial> seen;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer(
        [&](const PreconditionDenial& d) { seen.push_back(d); });

    const auto count = [&](const char* origin) {
        return reg.counter("yuzu_approval_precondition_denied_total", {{"origin", origin}})
            .value();
    };

    const auto mcp = approved_ticket(mgr, ApprovalOrigin::kMcp, "def-m");
    auto d1 = mgr.consume_ticket(mcp, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(d1.has_value());
    CHECK(d1.error().kind == ConsumeFailure::kPrecondition);
    CHECK(count("mcp") == 1);
    CHECK(count("guardian_deploy") == 0);
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].approval_id == mcp);
    CHECK(seen[0].origin == ApprovalOrigin::kMcp);
    CHECK(seen[0].consumed_by == "alice");
    CHECK(seen[0].reason == "state moved");

    auto g = mgr.submit_bound("guardian.d", "alice", "", "", ApprovalOrigin::kGuardianDeploy,
                              bound_request());
    REQUIRE(g.has_value());
    REQUIRE(mgr.approve(*g, "bob", "").has_value());
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto d2 = mgr.consume_ticket(conn, *g, "alice", ApprovalOrigin::kGuardianDeploy, kDeny);
        REQUIRE_FALSE(d2.has_value());
        CHECK(d2.error().kind == ConsumeFailure::kPrecondition);
    });
    CHECK(count("guardian_deploy") == 1);
    REQUIRE(seen.size() == 2);
    CHECK(seen[1].origin == ApprovalOrigin::kGuardianDeploy);

    // Neither denial consumed anything.
    CHECK(mgr.get(mcp)->consumed_at == 0);
    CHECK(mgr.get(*g)->consumed_at == 0);
}

TEST_CASE("only a precondition denial is counted: other refusals and successes are not",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    int observed = 0;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer([&](const PreconditionDenial&) { ++observed; });

    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kGuardianDeploy, kDeny).has_value());
    CHECK_FALSE(mgr.consume_ticket(id, "mallory", ApprovalOrigin::kMcp, kDeny).has_value());
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kUnspecified, kDeny).has_value());
    CHECK(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    // Spent: the precondition does not even run on a replay.
    CHECK_FALSE(mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny).has_value());

    CHECK(observed == 0);
    CHECK(reg.counter("yuzu_approval_precondition_denied_total", {{"origin", "mcp"}}).value() == 0);
}

TEST_CASE("a throwing denial observer never escapes consume_ticket and the denial stands",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    yuzu::MetricsRegistry reg;
    mgr.set_metrics(&reg);
    mgr.set_precondition_denial_observer(
        [](const PreconditionDenial&) { throw std::runtime_error("audit store down"); });

    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kPrecondition);
    CHECK(reg.counter("yuzu_approval_precondition_denied_total", {{"origin", "mcp"}}).value() == 1);
    CHECK(mgr.get(id)->consumed_at == 0);
}

TEST_CASE("a precondition denial works with no metrics and no observer installed",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);
    auto r = mgr.consume_ticket(id, "alice", ApprovalOrigin::kMcp, kDeny);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kPrecondition);
}

TEST_CASE("a precondition denial writes an approval.precondition_denied audit row that survives "
          "the redeemer's rollback",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    AuditStore audit{bundle.pool()};
    REQUIRE(audit.is_open());
    mgr.set_precondition_denial_observer(
        make_precondition_denial_audit_observer([&audit]() -> AuditStore* { return &audit; }));

    auto g = mgr.submit_bound("guardian.secret-def", "alice", "secret-scope", "",
                              ApprovalOrigin::kGuardianDeploy, bound_request());
    REQUIRE(g.has_value());
    REQUIRE(mgr.approve(*g, "bob", "").has_value());

    // The denial happens inside a caller transaction that is then ROLLED BACK.
    in_txn(bundle.pool(), /*commit=*/false, [&](PGconn* conn) {
        auto r = mgr.consume_ticket(conn, *g, "alice", ApprovalOrigin::kGuardianDeploy, kDeny);
        REQUIRE_FALSE(r.has_value());
    });

    auto rows = audit.query(AuditQuery{.action = kApprovalPreconditionDeniedAction});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& ev = (*rows)[0];
    CHECK(ev.principal == "alice");
    CHECK(ev.result == "denied");
    CHECK(ev.target_type == "approval");
    CHECK(ev.target_id == *g);
    CHECK(ev.detail.find("origin=guardian_deploy") != std::string::npos);
    CHECK(ev.detail.find("reason=state moved") != std::string::npos);
    // Caller-supplied ticket text never reaches the audit detail.
    CHECK(ev.detail.find("secret-def") == std::string::npos);
    CHECK(ev.detail.find("secret-scope") == std::string::npos);
}

TEST_CASE("the denial audit observer tolerates an absent audit store",
          "[approval_manager][bound]") {
    // No Postgres needed: the provider yields nullptr, so the observer returns quietly.
    auto obs = make_precondition_denial_audit_observer([]() -> AuditStore* { return nullptr; });
    REQUIRE(obs);
    CHECK_NOTHROW(obs(PreconditionDenial{"id", ApprovalOrigin::kMcp, "alice", "why"}));
    auto none = make_precondition_denial_audit_observer({});
    CHECK_NOTHROW(none(PreconditionDenial{"id", ApprovalOrigin::kMcp, "alice", "why"}));
}

// -- approval_row_json: the A4 read shape for a bound ticket -------------------------

namespace {
Approval base_approval() {
    Approval a;
    a.id = "id1";
    a.definition_id = "guardian.d";
    a.status = "pending";
    a.submitted_by = "alice";
    a.submitted_at = 100;
    return a;
}
} // namespace

TEST_CASE("approval_row_json: an unbound row is the nine legacy fields and nothing else",
          "[approval_manager][bound][a4]") {
    const auto row = approval_row_json(base_approval());
    CHECK(row.size() == 9);
    for (const char* key : {"request", "request_digest", "excluded_roots", "request_unreadable",
                            "excluded_roots_unreadable"})
        CHECK_FALSE(row.contains(key));
    // And the exact legacy bytes: a refactor that adds a key to unbound rows fails here.
    CHECK(row.dump() ==
          R"({"definition_id":"guardian.d","id":"id1","review_comment":"","reviewed_at":0,)"
          R"("reviewed_by":"","scope_expression":"","status":"pending","submitted_at":100,)"
          R"("submitted_by":"alice"})");
}

TEST_CASE("approval_row_json: a bound row carries the request as an OBJECT, its digest and the "
          "excluded roots",
          "[approval_manager][bound][a4]") {
    auto a = base_approval();
    a.request_json = R"({"definition":{"name":"Block RDP","hash":"abc"},"targets":["host-1"]})";
    a.request_digest = *sha256_hex(a.request_json);
    a.excluded_roots = {"carol", "dave"};
    const auto row = approval_row_json(a);
    CHECK(row.size() == 12);
    REQUIRE(row["request"].is_object());
    CHECK(row["request"]["definition"]["name"] == "Block RDP");
    CHECK(row["request"]["targets"][0] == "host-1");
    CHECK(row["request_digest"] == a.request_digest);
    CHECK(row["excluded_roots"] == nlohmann::json::array({"carol", "dave"}));
    CHECK_FALSE(row.contains("request_unreadable"));
    CHECK_FALSE(row.contains("excluded_roots_unreadable"));
}

TEST_CASE("approval_row_json: a bound row with no excluded roots still shows an empty array",
          "[approval_manager][bound][a4]") {
    auto a = base_approval();
    a.request_json = R"({"k":1})";
    a.request_digest = *sha256_hex(a.request_json);
    const auto row = approval_row_json(a);
    REQUIRE(row.contains("excluded_roots"));
    CHECK(row["excluded_roots"].is_array());
    CHECK(row["excluded_roots"].empty());
}

TEST_CASE("approval_row_json: an unreadable stored request is null + request_unreadable, never "
          "a crash, never a partial object",
          "[approval_manager][bound][a4]") {
    const std::string deep = std::string(8192, '[') + std::string(8192, ']');
    for (const std::string& bad : {std::string("not json"), std::string("[1,2]"), deep,
                                   std::string(R"({"k":")") + std::string(20000, 'a') + "\"}"}) {
        auto a = base_approval();
        a.request_json = bad;
        a.request_digest = std::string(64, 'a');
        const auto row = approval_row_json(a);
        CHECK(row["request"].is_null());
        CHECK(row["request_unreadable"] == true);
        CHECK(row["request_digest"] == a.request_digest);
        CHECK_NOTHROW(row.dump());
    }
}

TEST_CASE("approval_row_json: an unreadable excluded_roots list is flagged, not shown as empty",
          "[approval_manager][bound][a4]") {
    auto a = base_approval();
    a.request_json = R"({"k":1})";
    a.request_digest = *sha256_hex(a.request_json);
    a.excluded_roots_unreadable = true;
    const auto row = approval_row_json(a);
    CHECK(row["excluded_roots_unreadable"] == true);
    CHECK(row["excluded_roots"].empty());
}

TEST_CASE("approval_row_json: a digest with no request (an inconsistent row) is visible, not dropped",
          "[approval_manager][bound][a4]") {
    auto a = base_approval();
    a.request_digest = std::string(64, 'b');
    const auto row = approval_row_json(a);
    CHECK(row["request"].is_null());
    CHECK_FALSE(row.contains("request_unreadable")); // there was no request to be unreadable
    CHECK(row["request_digest"] == a.request_digest);
}

// -- server.cpp wiring ------------------------------------------------------------

TEST_CASE("server.cpp still wires the precondition-denial counter, its audit observer and the "
          "series pre-seed (LEXICAL pin: the wiring itself needs a whole ServerImpl, which no "
          "unit test builds)",
          "[approval_manager][bound][wiring]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    // What this covers: that the three statements exist and still point at each other (the
    // observer is built by the audit factory from the audit store, the manager is handed the
    // registry). What it does NOT cover: that ServerImpl runs them in a constructor path
    // reached with a live store. The observer and the counter themselves are tested for real
    // above; only this assembly is compile-and-grep covered.
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};

    const auto at_set_metrics = src.find("approval_manager_->set_metrics(&metrics_);");
    REQUIRE(at_set_metrics != std::string::npos);
    const auto at_observer =
        src.find("approval_manager_->set_precondition_denial_observer(", at_set_metrics);
    REQUIRE(at_observer != std::string::npos);
    // The observer is the audit factory's, fed by the audit store, within the same statement.
    const auto statement = src.substr(at_observer, 400);
    CHECK(statement.find("make_precondition_denial_audit_observer(") != std::string::npos);
    CHECK(statement.find("audit_store_.get()") != std::string::npos);

    CHECK(src.find("metrics_.describe(\"yuzu_approval_precondition_denied_total\"") !=
          std::string::npos);
    // All four writable surfaces are pre-seeded, so a first denial is a delta, not a new series.
    const auto at_seed = src.find("metrics_.counter(\"yuzu_approval_precondition_denied_total\"");
    REQUIRE(at_seed != std::string::npos);
    const auto before_seed = src.substr(at_seed > 400 ? at_seed - 400 : 0, 400);
    for (const char* origin : {"kInstruction", "kSchedule", "kMcp", "kGuardianDeploy"})
        CHECK(before_seed.find(origin) != std::string::npos);
}

TEST_CASE("approval_state_is_approvable: the one predicate the dashboard and approve() share",
          "[approval_manager][bound]") {
    const auto bound = [] {
        Approval a;
        a.request_json = R"({"k":1})";
        a.request_digest = *sha256_hex(a.request_json);
        return a;
    };
    CHECK(approval_state_is_approvable(Approval{}));                // unbound: nothing to verify
    CHECK(approval_state_is_approvable(bound()));
    { auto a = bound(); a.request_digest = std::string(64, '0'); CHECK_FALSE(approval_state_is_approvable(a)); }
    { auto a = bound(); a.request_digest.clear(); CHECK_FALSE(approval_state_is_approvable(a)); }
    { auto a = bound(); a.request_json.clear(); CHECK_FALSE(approval_state_is_approvable(a)); }
    { auto a = bound(); a.request_json = "[1]"; a.request_digest = *sha256_hex(a.request_json);
      CHECK_FALSE(approval_state_is_approvable(a)); }               // matches its digest, unreadable
    { auto a = bound(); a.excluded_roots_unreadable = true; CHECK_FALSE(approval_state_is_approvable(a)); }
}
