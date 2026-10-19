/**
 * test_approval_manager_bound.cpp -- the bound-approval primitive (#6062, four-eyes
 * MVP PR2): migration v2 columns and old-row compatibility; origin-declared consume
 * (origin mismatch, kUnspecified/kUnrecognised, the caller-held-connection overload);
 * submit_bound's frozen request/digest/excluded roots and its refusals; approve()'s
 * excluded-root refusal; and the precondition-denial counter + audit observer.
 *
 * Every TEST_CASE here needs Postgres and SKIPs silently without
 * YUZU_TEST_POSTGRES_DSN (see test_approval_manager_pg_helper.hpp).
 */

#include "approval_manager.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "reserved_definition_id.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

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

// -- Migration v2 / old-row compatibility -------------------------------------

TEST_CASE("ApprovalManager bound: a row minted before migration v2 survives it and reads "
          "as binding nothing",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    auto& pool = bundle.pool();

    // Rewind the live schema to its v1 shape: drop the three v2 columns and reset
    // the recorded version, then mint an "old" row with only the v1 columns.
    REQUIRE(run_sql(pool,
                    "ALTER TABLE approval_manager.approvals DROP COLUMN request_json, "
                    "DROP COLUMN request_digest, DROP COLUMN excluded_roots")
                .status() == PGRES_COMMAND_OK);
    REQUIRE(run_sql(pool, "UPDATE public.schema_meta SET version = 1 WHERE store = "
                          "'approval_manager'")
                .status() == PGRES_COMMAND_OK);
    REQUIRE(run_sql(pool,
                    "INSERT INTO approval_manager.approvals (id, definition_id, status, "
                    "submitted_by, submitted_at, reviewed_by, reviewed_at, scope_expression, "
                    "origin) VALUES ('old-row','mcp.tool','approved','alice',1,'bob',"
                    "extract(epoch from now())::bigint,'{}','mcp')")
                .status() == PGRES_COMMAND_OK);

    // A fresh manager re-runs the ladder: v2 applies to a POPULATED table.
    ApprovalManager upgraded{pool};
    REQUIRE(upgraded.is_open());

    auto old = upgraded.get("old-row");
    REQUIRE(old.has_value());
    CHECK(old->request_json.empty());
    CHECK(old->request_digest.empty());
    CHECK(old->excluded_roots.empty());
    CHECK_FALSE(old->excluded_roots_unreadable);

    // ...and it is still redeemable through the normal MCP path.
    auto consumed = upgraded.consume_ticket("old-row", "alice", ApprovalOrigin::kMcp, {});
    CHECK(consumed.has_value());
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
// Run `body(conn)` inside BEGIN ... then ROLLBACK or COMMIT.
template <typename F>
void in_txn(pg::PgPool& pool, bool commit, F&& body) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    body(lease.get());
    REQUIRE(pg::exec_params(lease.get(), commit ? "COMMIT" : "ROLLBACK",
                            std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
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

TEST_CASE("consume_ticket(PGconn*): the row lock is held to the caller's end of transaction",
          "[pg][approval_manager][bound]") {
    yuzu::test::ApprovalManagerPg bundle;
    ApprovalManager& mgr = *bundle;
    const auto id = approved_ticket(mgr, ApprovalOrigin::kMcp);

    auto holder = bundle.pool().acquire();
    auto other = bundle.pool().acquire();
    REQUIRE(holder);
    REQUIRE(other);
    REQUIRE(pg::exec_params(holder.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(mgr.consume_ticket(holder.get(), id, "alice", ApprovalOrigin::kMcp, {}).has_value());
    // A second connection cannot take the row while the first transaction is open.
    auto probe = pg::exec_params(other.get(),
                                 "SELECT 1 FROM approval_manager.approvals WHERE id = $1 "
                                 "FOR UPDATE NOWAIT",
                                 std::vector<std::string>{id});
    CHECK(probe.status() == PGRES_FATAL_ERROR); // 55P03 lock_not_available
    REQUIRE(pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}
