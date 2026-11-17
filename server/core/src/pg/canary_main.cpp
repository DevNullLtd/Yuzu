// Postgres link canary (#1317 F0, rewritten onto the F1 RAII owners, ADR-0008).
//
// Connects to the DSN given as argv[1] (or YUZU_POSTGRES_DSN), runs SELECT 1,
// and prints the result plus libpq/server versions. Its original job — proving
// libpq builds at the pinned vcpkg baseline and links on every platform
// (static .a on Linux/macOS, DLL + import lib on Windows; ADR-0008 Correction)
// — still stands: the CI link-provenance assertions on every Tier-1 leg
// inspect this binary, so the `yuzu_pg_canary` target must keep existing even
// though the substrate (#1320 PR 1) has landed. It now dogfoods `pg_raii.hpp`
// instead of manual PQfinish/PQclear (F1 conditions ledger #1).
//
// Exit codes: 0 = SELECT 1 succeeded, 1 = connect/query failure, 2 = no DSN.
// The exit codes are the only stable contract; stdout format is not. Note for
// CI wiring (#1318/#1336): PQconnectdb/PQexec have no client-side timeout —
// include connect_timeout=<s> in the DSN or wrap in timeout(1) before using
// as a smoke step, or a black-holed host wedges the job.

#include "pg_raii.hpp"

#include <cstdio>
#include <cstdlib>
#include <format>

#include <libpq-fe.h>

int main(int argc, char** argv) {
    using yuzu::server::pg::PgConn;
    using yuzu::server::pg::PgResult;
    using yuzu::server::pg::connect_failure_cause;

    const char* dsn = argc > 1 ? argv[1] : std::getenv("YUZU_POSTGRES_DSN");
    if (dsn == nullptr || dsn[0] == '\0') {
        std::fputs("usage: yuzu_pg_canary <dsn>  (or set YUZU_POSTGRES_DSN)\n"
                   "e.g.   yuzu_pg_canary \"postgresql://yuzu:yuzu@localhost:5432/yuzu\"\n",
                   stderr);
        return 2;
    }

    PgConn conn{PQconnectdb(dsn)};
    if (PQstatus(conn.get()) != CONNECTION_OK) {
        std::fputs(std::format("canary: connect failed: {}\n", connect_failure_cause(PQerrorMessage(conn.get()))).c_str(),
                   stderr);
        return 1;
    }

    PgResult res{PQexec(conn.get(), "SELECT 1")};
    if (res.status() != PGRES_TUPLES_OK) {
        std::fputs(std::format("canary: SELECT 1 failed: {}", PQerrorMessage(conn.get())).c_str(),
                   stderr);
        return 1;
    }
    if (PQntuples(res.get()) < 1 || PQnfields(res.get()) < 1) {
        std::fputs("canary: SELECT 1 returned an empty result set\n", stderr);
        return 1;
    }

    std::fputs(std::format("canary: SELECT 1 -> {} (libpq {}, server {})\n",
                           PQgetvalue(res.get(), 0, 0), PQlibVersion(), PQserverVersion(conn.get()))
                   .c_str(),
               stdout);
    return 0;
}
