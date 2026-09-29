/// HA WS-8: the multi-host DSN guard (pg/multi_host_dsn.hpp). A multi-host DSN
/// without target_session_attrs lets libpq put the pool's connections on a
/// standby; the guard rebuilds the DSN with read-write, and refuses a weaker
/// explicit value. No database needed — these run on every leg (not [pg]).

#include "pg/multi_host_dsn.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <string>

using yuzu::server::pg::enforce_multi_host_read_write;

namespace {

/// libpq's own reading of a DSN: every option it sets. nullopt if unparseable.
std::optional<std::map<std::string, std::string>> libpq_reads(const std::string& dsn) {
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    if (!opts)
        return std::nullopt;
    std::map<std::string, std::string> m;
    for (const PQconninfoOption* o = opts.get(); o->keyword != nullptr; ++o)
        if (o->val != nullptr)
            m.emplace(o->keyword, o->val);
    return m;
}

/// The guard's output must say exactly what the input said, plus read-write.
void require_same_plus_read_write(const std::string& in, const std::string& out) {
    auto before = libpq_reads(in);
    const auto after = libpq_reads(out);
    REQUIRE(before.has_value());
    REQUIRE(after.has_value());
    (*before)["target_session_attrs"] = "read-write";
    CHECK(*after == *before);
}

/// Process environment is shared by the whole test binary: set, run, restore —
/// the restore in a destructor, so it also runs if `f` throws.
#ifndef _WIN32
template <typename F>
auto with_env(const char* name, const char* value, F&& f) {
    struct Restore {
        const char* name;
        std::optional<std::string> saved;
        ~Restore() {
            if (saved)
                ::setenv(name, saved->c_str(), 1);
            else
                ::unsetenv(name);
        }
    } restore{name, std::getenv(name) ? std::optional<std::string>(std::getenv(name))
                                      : std::nullopt};
    ::setenv(name, value, 1);
    return f();
}
#endif

} // namespace

TEST_CASE("multi-host DSN guard: a single host is left alone", "[server][multi_host_dsn]") {
    for (const std::string dsn :
         {"host=db port=5432 dbname=yuzu user=yuzu", "postgresql://yuzu:pw@db:5432/yuzu",
          "host=db target_session_attrs=any"}) {
        INFO(dsn);
        const auto r = enforce_multi_host_read_write(dsn);
        REQUIRE(r.has_value());
        CHECK(r->dsn == dsn);
        CHECK_FALSE(r->appended);
        CHECK(r->hosts == 1);
    }
}

TEST_CASE("multi-host DSN guard: an empty DSN stays empty, even with a PGHOST list",
          "[server][multi_host_dsn]") {
    // Rewriting "" would defeat the fail-closed "no DSN" refusal (ADR-0007).
    const auto r = enforce_multi_host_read_write("");
    REQUIRE(r.has_value());
    CHECK(r->dsn.empty());
    CHECK_FALSE(r->appended);
#ifndef _WIN32
    const auto e = with_env("PGHOST", "a,b", [] { return enforce_multi_host_read_write(""); });
    REQUIRE(e.has_value());
    CHECK(e->dsn.empty());
    CHECK_FALSE(e->appended);
#endif
}

TEST_CASE("multi-host DSN guard: no target_session_attrs gets read-write",
          "[server][multi_host_dsn]") {
    SECTION("keyword form") {
        const std::string in = "host=a,b,c dbname=yuzu";
        const auto r = enforce_multi_host_read_write(in);
        REQUIRE(r.has_value());
        CHECK(r->appended);
        CHECK(r->hosts == 3);
        CHECK_FALSE(r->hosts_from_env);
        require_same_plus_read_write(in, r->dsn);
    }
    SECTION("URI form, with and without an existing query string") {
        for (const std::string in :
             {"postgresql://u:p@a:5432,b:5432/yuzu", "postgresql://u:p@a,b/yuzu?sslmode=require"}) {
            INFO(in);
            const auto r = enforce_multi_host_read_write(in);
            REQUIRE(r.has_value());
            CHECK(r->appended);
            require_same_plus_read_write(in, r->dsn);
        }
    }
    SECTION("an empty target_session_attrs counts as absent") {
        const std::string in = "host=a,b target_session_attrs=";
        const auto r = enforce_multi_host_read_write(in);
        REQUIRE(r.has_value());
        CHECK(r->appended);
        require_same_plus_read_write(in, r->dsn);
    }
    SECTION("a hostaddr list counts as multi-host") {
        const auto r = enforce_multi_host_read_write("hostaddr=10.0.0.1,10.0.0.2 dbname=yuzu");
        REQUIRE(r.has_value());
        CHECK(r->appended);
        CHECK(r->hosts == 2);
    }
}

TEST_CASE("multi-host DSN guard: load_balance_hosts is refused, whatever else the DSN says",
          "[server][multi_host_dsn]") {
    // Gate 8 round 6 (operator decision): libpq would shuffle hosts for every new
    // pool connection while the /readyz probe holds one.
    for (const std::string dsn :
         {"host=a load_balance_hosts=random", "host=a,b load_balance_hosts=random",
          "host=a,b load_balance_hosts=random target_session_attrs=read-write",
          "postgresql://u:s3cret@a,b/yuzu?load_balance_hosts=random"}) {
        INFO(dsn);
        const auto r = enforce_multi_host_read_write(dsn);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("load_balance_hosts=random") != std::string::npos);
        CHECK(r.error().find("s3cret") == std::string::npos);
    }
    SECTION("an unrecognised value is refused and not echoed") {
        const auto r =
            enforce_multi_host_read_write("host=a,b load_balance_hosts='x password=hunter2'");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("hunter2") == std::string::npos);
    }
    SECTION("disable is the default and is accepted") {
        const auto off = enforce_multi_host_read_write("host=a load_balance_hosts=disable");
        REQUIRE(off.has_value());
        CHECK_FALSE(off->appended);
        const auto multi = enforce_multi_host_read_write("host=a,b load_balance_hosts=disable");
        REQUIRE(multi.has_value());
        CHECK(multi->appended);
    }
}

TEST_CASE("multi-host DSN guard: shapes a text append broke keep their meaning",
          "[server][multi_host_dsn]") {
    // Gate 8 round 5, each reproduced against libpq 16 with the old append:
    //   - an unquoted keyword value ending in '\' swallowed the appended pair;
    //   - a raw '?' in a URI password put the pair inside the host or port list;
    //   - a URI ending in '?' or '&' stopped parsing once a separator was added.
    for (const std::string in : {
             "host=a,b application_name=x\\",
             "host=a,b password='it\\'s' dbname='a b\\\\c'",
             "postgresql://u:p?w@a,b",
             "postgresql://u:p?w@a:5432,b:5433/yuzu",
             "postgresql://u:p@a,b/yuzu?",
             "postgresql://u:p@a,b/yuzu?sslmode=disable&",
             // Round 6: shapes whose values carry '=', spaces or quotes, and
             // repeated keywords (libpq keeps the last).
             "host=a,b options='-c statement_timeout=5000 -c lock_timeout=100'",
             "host=a,b passfile=/etc/yuzu/pgpass dbname='host=evil user=x'",
             "host=a,b dbname=one dbname=two port=5432 port=5433,5434",
         }) {
        INFO(in);
        const auto before = libpq_reads(in);
        if (!before) // libpq itself rejects it: the guard must hand it back unchanged
        {
            const auto r = enforce_multi_host_read_write(in);
            REQUIRE(r.has_value());
            CHECK(r->dsn == in);
            continue;
        }
        const auto r = enforce_multi_host_read_write(in);
        REQUIRE(r.has_value());
        if (r->hosts < 2) { // the '?' put the host list somewhere else: nothing to do
            CHECK(r->dsn == in);
            continue;
        }
        CHECK(r->appended);
        require_same_plus_read_write(in, r->dsn);
    }
}

TEST_CASE("multi-host DSN guard: read-write and primary are accepted as given",
          "[server][multi_host_dsn]") {
    for (const std::string dsn :
         {"host=a,b target_session_attrs=read-write", "host=a,b target_session_attrs=primary"}) {
        INFO(dsn);
        const auto r = enforce_multi_host_read_write(dsn);
        REQUIRE(r.has_value());
        CHECK(r->dsn == dsn);
        CHECK_FALSE(r->appended);
    }
}

TEST_CASE("multi-host DSN guard: a weaker explicit target_session_attrs is refused, without "
          "echoing the DSN",
          "[server][multi_host_dsn]") {
    for (const std::string tsa : {"any", "read-only", "standby", "prefer-standby"}) {
        INFO(tsa);
        const auto r =
            enforce_multi_host_read_write("host=a,b password=s3cret target_session_attrs=" + tsa);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("'" + tsa + "'") != std::string::npos);
        CHECK(r.error().find("s3cret") == std::string::npos);
    }
    SECTION("an unrecognised value is refused and NOT echoed (it could be a DSN fragment)") {
        const auto r = enforce_multi_host_read_write(
            "host=a,b target_session_attrs='any password=hunter2'");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("hunter2") == std::string::npos);
        CHECK(r.error().find("the value given") != std::string::npos);
    }
}

TEST_CASE("multi-host DSN guard: an unparseable DSN is returned unchanged for the pool to report",
          "[server][multi_host_dsn]") {
    const auto r = enforce_multi_host_read_write("host=a,b sslmode=");
    // Whatever libpq makes of it, the guard must not throw or invent a DSN.
    REQUIRE(r.has_value());
    const auto bad = enforce_multi_host_read_write("postgresql://u:s3cr%zzt@a,b/yuzu");
    REQUIRE(bad.has_value());
    CHECK(bad->dsn == "postgresql://u:s3cr%zzt@a,b/yuzu");
    CHECK_FALSE(bad->appended);
}

#ifndef _WIN32
TEST_CASE("multi-host DSN guard: a host list or load balancing from the environment counts",
          "[server][multi_host_dsn]") {
    const auto r = with_env("PGHOST", "a,b",
                            [] { return enforce_multi_host_read_write("dbname=yuzu user=yuzu"); });
    REQUIRE(r.has_value());
    CHECK(r->appended);
    CHECK(r->hosts == 2);
    CHECK(r->hosts_from_env);
    // The env list is not written into the DSN: libpq still reads it from PGHOST.
    const auto reads = libpq_reads(r->dsn);
    REQUIRE(reads.has_value());
    CHECK_FALSE(reads->contains("host"));
    CHECK(reads->at("target_session_attrs") == "read-write");

    const auto lb = with_env("PGLOADBALANCEHOSTS", "random",
                             [] { return enforce_multi_host_read_write("host=a dbname=yuzu"); });
    REQUIRE_FALSE(lb.has_value());
    CHECK(lb.error().find("PGLOADBALANCEHOSTS") != std::string::npos);
}
#endif
