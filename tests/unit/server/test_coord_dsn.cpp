// test_coord_dsn.cpp — WS-3: build_coord_dsn (the LeaderElector's dedicated
// coordination DSN augmentation, ADR-2002 §10 + #4013). Pure string logic, no
// Postgres. Extracted to a header specifically so these branches can be pinned
// (adversarial review K3/CDX-P2-03): a malformed augmentation would silently pause
// every FencedLeaderOnly loop, so the keyword/URI split, the operator-wins
// suppression, the six dead-connection-detection params, and the leading-whitespace
// URI edge all get direct coverage here.

#include "coord_dsn.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::build_coord_dsn;

namespace {
bool has(const std::string& s, const std::string& sub) {
    return s.find(sub) != std::string::npos;
}
} // namespace

TEST_CASE("build_coord_dsn: empty in, empty out (elector fails closed itself)", "[coord-dsn][unit]") {
    CHECK(build_coord_dsn("").empty());
}

TEST_CASE("build_coord_dsn: keyword form appends space-separated params", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("host=db.internal dbname=yuzu");
    CHECK(out.rfind("host=db.internal dbname=yuzu", 0) == 0); // original preserved, prefix
    CHECK(has(out, " connect_timeout=5"));
    CHECK(has(out, " keepalives=1"));
    CHECK(has(out, " keepalives_idle=15"));
    CHECK(has(out, " keepalives_interval=5"));
    CHECK(has(out, " keepalives_count=3"));
    CHECK(has(out, " tcp_user_timeout=15000"));
    CHECK(out.find('?') == std::string::npos); // never introduces a URI query separator
}

TEST_CASE("build_coord_dsn: URI form appends ?/& query params, never a space", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("postgresql://u:p@db/yuzu");
    CHECK(has(out, "?connect_timeout=5")); // first param uses '?'
    CHECK(has(out, "&keepalives=1"));      // subsequent use '&'
    CHECK(has(out, "&tcp_user_timeout=15000"));
    CHECK(out.find(' ') == std::string::npos); // no keyword-syntax corruption of a URI
}

TEST_CASE("build_coord_dsn: URI with an existing query appends with '&'", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("postgresql://db/yuzu?sslmode=require");
    CHECK(has(out, "sslmode=require"));
    CHECK(has(out, "&connect_timeout=5"));
    CHECK(out.find("?connect_timeout") == std::string::npos);
}

TEST_CASE("build_coord_dsn: leading whitespace is still a URI (K3)", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("  postgresql://db/yuzu");
    CHECK(has(out, "?connect_timeout=5"));                    // detected as URI despite the blanks
    CHECK(out.find(" connect_timeout=5") == std::string::npos); // NOT the keyword form
}

TEST_CASE("build_coord_dsn: an operator-set value wins", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("host=db connect_timeout=99");
    CHECK(has(out, "connect_timeout=99"));
    CHECK(out.find("connect_timeout=5") == std::string::npos); // ours is not appended
    CHECK(has(out, " keepalives=1"));                          // the others still are
}

TEST_CASE("build_coord_dsn: keepalives= does not cross-match keepalives_idle=", "[coord-dsn][unit]") {
    const auto out = build_coord_dsn("host=db keepalives_idle=99");
    CHECK(has(out, "keepalives_idle=99"));
    CHECK(out.find("keepalives_idle=15") == std::string::npos); // operator value wins for idle
    CHECK(has(out, " keepalives=1")); // bare keepalives NOT suppressed by keepalives_idle
}
