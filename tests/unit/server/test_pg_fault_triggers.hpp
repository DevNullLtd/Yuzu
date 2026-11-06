#pragma once

/// @file test_pg_fault_triggers.hpp
///
/// Test-only SQL fault injection shared by the MFA route tests (#6995).

#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <string>

namespace yuzu::test {

/// Installs a BEFORE UPDATE trigger on auth.users that raises only when `when_cond` holds, so one
/// specific write (the TOTP-secret mint, the enrolment stamp) fails as a genuine STORE fault while
/// every other write (login bookkeeping) passes. Used as the control that proves a database fault is
/// still counted as a store outage and never as a CSPRNG fault. Run it against a per-test cloned
/// database only (the function and trigger live in that clone and are dropped with it).
inline void block_users_update_when(const std::string& dsn, const std::string& when_cond) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult fn{PQexec(
        conn.get(),
        "CREATE OR REPLACE FUNCTION test_block_users_update_when() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION 'test-induced write failure'; END; $$ LANGUAGE plpgsql")};
    REQUIRE(fn.ok());
    const std::string trg_sql =
        "CREATE TRIGGER test_block_users_update_when_trg BEFORE UPDATE ON auth.users "
        "FOR EACH ROW WHEN (" +
        when_cond + ") EXECUTE FUNCTION test_block_users_update_when()";
    yuzu::server::pg::PgResult trg{PQexec(conn.get(), trg_sql.c_str())};
    REQUIRE(trg.ok());
}

} // namespace yuzu::test
