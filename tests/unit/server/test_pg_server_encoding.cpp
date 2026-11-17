/// WP07 gate-8 UP1: the boot-time PostgreSQL database-encoding check (warn-only).
/// The pure decision plus the libpq-reported `server_encoding` against a real UTF8 database and a
/// real SQL_ASCII one (created from template0 on the test cluster).

#include "pg/pg_raii.hpp"
#include "pg/pg_server_encoding.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <string>

using namespace yuzu::server::pg;

TEST_CASE("server_encoding_is_utf8: UTF8 spellings pass, everything else (and unknown) fails",
          "[pg][pg_server_encoding]") {
    CHECK(server_encoding_is_utf8("UTF8"));
    CHECK(server_encoding_is_utf8("utf-8"));
    CHECK_FALSE(server_encoding_is_utf8("SQL_ASCII"));
    CHECK_FALSE(server_encoding_is_utf8("LATIN1"));
    CHECK_FALSE(server_encoding_is_utf8("")); // unknown fails loud
    CHECK(server_encoding_of(nullptr).empty());
}

TEST_CASE("server_encoding_of: reports UTF8 for the test database and SQL_ASCII for a "
          "SQL_ASCII one",
          "[pg][pg_server_encoding]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn utf8_conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(utf8_conn.get()) == CONNECTION_OK);
    INFO("test cluster database encoding = " << server_encoding_of(utf8_conn.get()));
    CHECK(server_encoding_is_utf8(server_encoding_of(utf8_conn.get())));

    // A SQL_ASCII database is the case the check exists for. template0 is the only template that
    // permits a different encoding. Named from this fixture's unique name; dropped below.
    const std::string ascii_db = db.db_name() + "_enc";
    {
        PgResult c{PQexec(utf8_conn.get(),
                          ("CREATE DATABASE \"" + ascii_db +
                           "\" ENCODING 'SQL_ASCII' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0")
                              .c_str())};
        if (!c.ok())
            SKIP("cannot create a SQL_ASCII database on this cluster: "
                 << PQerrorMessage(utf8_conn.get()));
    }
    {
        PgConn ascii_conn{PQconnectdb((db.dsn() + " dbname=" + ascii_db).c_str())};
        REQUIRE(PQstatus(ascii_conn.get()) == CONNECTION_OK);
        const auto enc = server_encoding_of(ascii_conn.get());
        CHECK(enc == "SQL_ASCII");
        CHECK_FALSE(server_encoding_is_utf8(enc));
    }
    PgResult d{PQexec(utf8_conn.get(),
                      ("DROP DATABASE IF EXISTS \"" + ascii_db + "\" WITH (FORCE)").c_str())};
    CHECK(d.ok());
}
