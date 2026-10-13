#pragma once

/// Test helper: write a `parameter_schema` straight into the Postgres row, bypassing every
/// InstructionStore write gate. It reproduces a LEGACY row (one stored before the size cap and
/// the write-time schema check existed, or edited at the data layer), which no store write
/// path can now create.

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace yuzu::server::test {

inline void force_parameter_schema(pg::PgPool& pool, const std::string& id,
                                   const std::string& schema_text) {
    auto lease = pool.try_acquire_for(std::chrono::milliseconds(4000));
    REQUIRE(lease);
    auto res = pg::exec_params(
        lease.get(),
        "UPDATE instruction_store.instruction_definitions SET parameter_schema=$1 "
        "WHERE id=$2 RETURNING id",
        std::vector<std::string>{schema_text, id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
}

}  // namespace yuzu::server::test
