// pg::exec_params parameter validation: a bound text parameter that carries
// an embedded NUL byte is refused with a clear error before it reaches the
// server, instead of being silently cut at the NUL by libpq's C-string bind.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::exec_params;

namespace {

std::string cell(const PgResult& r, int row, int col) {
    return PQgetvalue(r.get(), row, col);
}

int count_rows(PGconn* conn) {
    PgResult r{PQexec(conn, "SELECT count(*) FROM pg_exec_params_t")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    return std::stoi(cell(r, 0, 0));
}

} // namespace

TEST_CASE("exec_params: a parameter with an embedded NUL is refused, nothing is executed",
          "[pg][pg_exec]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    auto lease = pool.acquire();
    REQUIRE(static_cast<bool>(lease));
    {
        PgResult c{PQexec(lease.get(), "CREATE TABLE pg_exec_params_t (k text PRIMARY KEY)")};
        REQUIRE(c.ok());
    }

    const std::string with_nul("abc\0def", 7);

    SECTION("a write is refused and stores nothing, not even the prefix") {
        auto r = exec_params(lease.get(), "INSERT INTO pg_exec_params_t (k) VALUES ($1)",
                             std::vector<std::string>{with_nul});
        CHECK_FALSE(r.ok());
        CHECK(r.status() == PGRES_FATAL_ERROR);
        CHECK(count_rows(lease.get()) == 0);
    }

    SECTION("a delete keyed on a NUL-bearing value does not act on the prefix row") {
        {
            auto ins = exec_params(lease.get(), "INSERT INTO pg_exec_params_t (k) VALUES ($1)",
                                   std::vector<std::string>{"abc"});
            REQUIRE(ins.ok());
        }
        auto r = exec_params(lease.get(), "DELETE FROM pg_exec_params_t WHERE k = $1 RETURNING k",
                             std::vector<std::string>{with_nul});
        CHECK_FALSE(r.ok());
        CHECK(count_rows(lease.get()) == 1);
    }

    SECTION("the error names the parameter position, carries SQLSTATE 22021 and never the value") {
        auto r = exec_params(lease.get(), "SELECT $1::text, $2::text",
                             std::vector<std::string>{"fine", with_nul});
        REQUIRE_FALSE(r.ok());
        const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
        REQUIRE(state != nullptr);
        CHECK(std::string(state) == "22021");
        const std::string msg = PQresultErrorMessage(r.get());
        CHECK(msg.find("$2") != std::string::npos);
        CHECK(msg.find("NUL") != std::string::npos);
        CHECK(msg.find("def") == std::string::npos);
    }

    SECTION("the optional-vector overload applies the same rule") {
        std::vector<std::optional<std::string>> params{std::nullopt, with_nul};
        auto r = exec_params(lease.get(), "SELECT $1::text, $2::text", params);
        CHECK_FALSE(r.ok());
    }

    SECTION("the connection stays usable after a refusal") {
        auto bad = exec_params(lease.get(), "SELECT $1::text", std::vector<std::string>{with_nul});
        REQUIRE_FALSE(bad.ok());
        auto good = exec_params(lease.get(), "SELECT $1::text", std::vector<std::string>{"ok"});
        REQUIRE(good.ok());
        CHECK(cell(good, 0, 0) == "ok");
    }
}

TEST_CASE("exec_params: ordinary text, NULL and whitespace/control text still bind unchanged",
          "[pg][pg_exec]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    auto lease = pool.acquire();
    REQUIRE(static_cast<bool>(lease));

    SECTION("a NULL optional binds SQL NULL") {
        std::vector<std::optional<std::string>> params{std::nullopt};
        auto r = exec_params(lease.get(), "SELECT $1::text IS NULL", params);
        REQUIRE(r.ok());
        CHECK(cell(r, 0, 0) == "t");
    }

    SECTION("an empty string binds as an empty string") {
        auto r = exec_params(lease.get(), "SELECT length($1::text)", std::vector<std::string>{""});
        REQUIRE(r.ok());
        CHECK(cell(r, 0, 0) == "0");
    }

    SECTION("tab, newline, carriage return, escape and non-ASCII text round-trip exactly") {
        // Multi-line documents and captured process output legitimately carry these bytes; the
        // guard is deliberately limited to the byte that cannot be bound as text.
        const std::string text = "line1\nline2\r\n\tcol\x1b[0m \xC3\xA9";
        auto r = exec_params(lease.get(), "SELECT $1::text", std::vector<std::string>{text});
        REQUIRE(r.ok());
        CHECK(cell(r, 0, 0) == text);
    }
}
