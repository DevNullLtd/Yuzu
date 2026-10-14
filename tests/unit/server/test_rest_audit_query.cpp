/**
 * test_rest_audit_query.cpp — HTTP-level coverage for the filter/paging
 * parameters of `GET /api/v1/audit` (since, until, target_type, target_id,
 * offset) and its pagination envelope. TestRouteSink dispatch (no acceptor
 * thread) over a populated Postgres-template AuditStore. The 400 table and the
 * closed-store 503 arm need no Postgres.
 */

#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>

using namespace yuzu::server;

namespace {

yuzu::test::PgTestTemplate rest_audit_query_tpl{"queryaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("queryaudit template: store failed to migrate");
}};

struct QueryHarness {
    yuzu::server::test::TestRouteSink sink;
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    RestApiV1 api;

    // populated=false wires a closed store (unroutable pool): no DSN needed.
    explicit QueryHarness(bool populated = true) {
        if (!populated) {
            audit_pool.emplace(yuzu::server::pg::PgPool::Options{
                .conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1});
            audit_store = std::make_unique<AuditStore>(*audit_pool);
        } else {
            if (yuzu::test::pg_admin_dsn_env() == nullptr) {
                SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
            }
            audit_db.emplace(rest_audit_query_tpl);
            REQUIRE(audit_db->available());
            audit_pool.emplace(
                yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
            audit_store = std::make_unique<AuditStore>(*audit_pool);
            auto log = [&](const char* action, const char* tt, const char* tid, int64_t ts) {
                AuditEvent e;
                e.principal = "admin";
                e.principal_role = "admin";
                e.source_ip = "10.0.0.9";
                e.action = action;
                e.result = "success";
                e.target_type = tt;
                e.target_id = tid;
                e.timestamp = ts;
                REQUIRE(audit_store->log(e));
            };
            log("a.one", "Tag", "t1", 1000);
            log("a.two", "Tag", "t2", 2000);
            log("a.three", "User", "t1", 3000);
            // Three rows sharing one timestamp: paging must still be exact.
            log("tie.a", "Tie", "x", 5000);
            log("tie.b", "Tie", "x", 5000);
            log("tie.c", "Tie", "x", 5000);
            // Re-version the OLDEST tie row with an indexed column changed (non-HOT):
            // its idx_audit_ts entry moves to the end of the tie group, so a bare
            // `ORDER BY timestamp DESC` no longer yields ids in descending order by
            // accident of insertion order. Only the `id DESC` tiebreak does.
            auto lease = audit_pool->acquire();
            REQUIRE(lease);
            PGresult* up = PQexec(lease.get(), "UPDATE audit_store.audit_events "
                                               "SET principal = 'admin2' WHERE action = 'tie.a'");
            REQUIRE(PQresultStatus(up) == PGRES_COMMAND_OK);
            REQUIRE(std::string(PQcmdTuples(up)) == "1");
            PQclear(up);
        }
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                            /*audit_store=*/audit_store.get());
    }

    nlohmann::json get(const std::string& q, int expect = 200) {
        auto r = sink.Get("/api/v1/audit" + q);
        REQUIRE(r);
        INFO(r->body);
        CHECK(r->status == expect);
        return nlohmann::json::parse(r->body);
    }
};

} // namespace

TEST_CASE("v1 audit: target filters narrow and rows carry id without legacy-only fields",
          "[pg][audit][rest]") {
    QueryHarness h;
    auto j = h.get("?target_type=Tag&target_id=t1");
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["action"] == "a.one");
    CHECK(j["data"][0].contains("id"));
    // Hermes M-2: the machine surfaces stay narrower than the legacy route.
    CHECK_FALSE(j["data"][0].contains("source_ip"));
    CHECK_FALSE(j["data"][0].contains("principal_role"));
    CHECK(h.get("?target_type=Tag")["data"].size() == 2);
}

TEST_CASE("v1 audit: since/until are inclusive", "[pg][audit][rest]") {
    QueryHarness h;
    CHECK(h.get("?since=2000&until=3000")["data"].size() == 2);
    CHECK(h.get("?since=3001&until=4999")["data"].size() == 0);
    CHECK(h.get("?until=1000")["data"].size() == 1);
    // 0 means unbounded on that side.
    CHECK(h.get("?since=0&until=0")["data"].size() == 6);
}

TEST_CASE("v1 audit: offset pages with real start and page_size and ties are stable",
          "[pg][audit][rest]") {
    QueryHarness h;
    std::set<int64_t> seen;
    int total_rows = 0;
    for (int off = 0; off < 6; off += 2) {
        auto j = h.get("?limit=2&offset=" + std::to_string(off));
        CHECK(j["pagination"]["start"] == off);
        CHECK(j["pagination"]["page_size"] == 2);
        CHECK(j["pagination"]["total"] == 2);
        for (const auto& row : j["data"]) {
            seen.insert(row["id"].get<int64_t>());
            ++total_rows;
        }
    }
    // Three rows share timestamp 5000: no repeat and no skip across pages.
    CHECK(total_rows == 6);
    CHECK(seen.size() == 6);
    CHECK(h.get("?limit=2&offset=6")["data"].size() == 0);

    // Ties break on id DESC: the whole log is strictly newest-first by (timestamp, id).
    auto all = h.get("?limit=6");
    REQUIRE(all["data"].size() == 6);
    for (size_t i = 1; i < all["data"].size(); ++i) {
        const auto& prev = all["data"][i - 1];
        const auto& cur = all["data"][i];
        INFO("row " << i);
        CHECK((prev["timestamp"] > cur["timestamp"] ||
               (prev["timestamp"] == cur["timestamp"] && prev["id"] > cur["id"])));
    }
}

TEST_CASE("v1 audit: malformed filters are 400 and never silently dropped", "[audit][rest]") {
    QueryHarness h(/*populated=*/false); // validation precedes the store read
    for (const char* q : {"?since=abc", "?since=-1", "?until=1.5", "?since=2000&until=1000",
                          "?offset=-1", "?offset=10001", "?offset=x", "?target_id=t1", "?target_type=a%00b"}) {
        INFO(q);
        h.get(q, 400);
    }
}

TEST_CASE("v1 audit: offset 10000 passes validation and a degraded store is 503",
          "[audit][rest]") {
    QueryHarness h(/*populated=*/false);
    h.get("?offset=10000", 503); // passed validation, hit the closed store
    h.get("?offset=5", 503);     // never data:[]
}
