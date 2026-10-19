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
}
