/**
 * test_discovery_scan_route.cpp -- route-level regression test for
 * POST /api/discovery/scan (gov fjarvis BLOCKING, PR #3064 re-review).
 *
 * The bug: upsert_device's std::expected failure was dropped silently in the
 * batch loop (no else branch), and the handler unconditionally audited
 * "success" and returned {"status":"ok"} even when every device in the batch
 * failed to persist. Under the pre-migration SQLite store this needed a rare
 * local-disk error to trigger; under the shared Postgres pool it also fires
 * on an ordinary acquire-timeout under load, so the trigger rate rose
 * materially with the Postgres migration.
 *
 * This dispatches synthesized requests through the captured route closure
 * against an in-process TestRouteSink (same pattern as test_rest_tag_routes.cpp),
 * with a REAL DiscoveryStore against a live Postgres template DB -- DROPping
 * the table mid-test forces a genuine query failure (the same technique
 * test_deployment_store.cpp and test_result_set_store.cpp use). Note this
 * exercises upsert_device's query-failure return path specifically, not the
 * pool-acquire-timeout path named above as the materially-raised trigger
 * under Postgres -- both return the same std::expected failure to the route
 * handler, so the handler-level assertions here hold either way; the
 * timeout path itself is exercised separately by test_pg_pool.cpp.
 */

#include "discovery_routes.hpp"
#include "discovery_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate discovery_scan_route_tpl{
    "discoveryscanroute", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        DiscoveryStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("discovery_scan_route template: store failed to migrate");
    }};

// A harness that registers ONLY the DiscoveryRoutes' scan handler (via the
// full class -- DirectorySync/PatchManager/DeploymentStore are unrelated to
// this handler and passed nullptr) against a TestRouteSink, with a real
// PG-backed DiscoveryStore.
struct DiscoveryScanRouteHarness {
    // Declaration order is destruction order (reverse): pool/discovery_store
    // must outlive sink, since sink's registered handlers capture
    // discovery_store.get() and (via audit_fn) this->audit_outcomes --
    // fixtures must declare the sink after the route owner/objects it
    // registers (CLAUDE.md test conventions; contract pinned by
    // test_route_sink_harness.cpp).
    std::unique_ptr<PgPool> pool;
    std::unique_ptr<DiscoveryStore> discovery_store;
    DiscoveryRoutes routes;
    std::vector<std::string> audit_outcomes;
    yuzu::server::test::TestRouteSink sink;

    explicit DiscoveryScanRouteHarness(const std::string& dsn) {
        pool = std::make_unique<PgPool>(PgPool::Options{.conninfo = dsn, .size = 4});
        discovery_store = std::make_unique<DiscoveryStore>(*pool);
        REQUIRE(discovery_store->is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "scanner-agent";
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string&,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string&) { audit_outcomes.push_back(result); };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn,
                               /*directory_sync=*/nullptr, /*patch_manager=*/nullptr,
                               /*deployment_store=*/nullptr, discovery_store.get());
    }

    auto scan(const std::string& body) { return sink.Post("/api/discovery/scan", body, "application/json"); }
};

} // namespace

TEST_CASE("POST /api/discovery/scan: all devices stored -> ok, audit success",
          "[discovery_store][pg][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_scan_route_tpl);
    DiscoveryScanRouteHarness h{db.dsn()};

    auto res = h.scan(R"({"subnet":"10.0.0.0/24","discovered_by":"agent-1","devices":[
        {"ip_address":"10.0.0.5","mac_address":"aa:bb","hostname":"host5"},
        {"ip_address":"10.0.0.6","mac_address":"cc:dd","hostname":"host6"}
    ]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["status"] == "ok");
    CHECK(body["devices_stored"] == 2);
    CHECK(body["devices_failed"] == 0);
    REQUIRE(h.audit_outcomes.size() == 1);
    CHECK(h.audit_outcomes[0] == "success");

    auto listed = h.discovery_store->list_devices();
    REQUIRE(listed.has_value());
    CHECK(listed->size() == 2);
}

TEST_CASE("POST /api/discovery/scan: a device with an empty ip_address is skipped, not counted "
          "as a failure",
          "[discovery_store][pg][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_scan_route_tpl);
    DiscoveryScanRouteHarness h{db.dsn()};

    auto res = h.scan(R"({"subnet":"10.0.0.0/24","devices":[
        {"ip_address":"","hostname":"no-ip"},
        {"ip_address":"10.0.0.7","hostname":"host7"}
    ]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["status"] == "ok");
    CHECK(body["devices_stored"] == 1);
    CHECK(body["devices_failed"] == 0); // skipped, not failed -- honest count
    REQUIRE(h.audit_outcomes.size() == 1);
    CHECK(h.audit_outcomes[0] == "success");
}

TEST_CASE("POST /api/discovery/scan: every device fails to persist -> 503, audit failure, "
          "never a false status=ok (gov fjarvis BLOCKING)",
          "[discovery_store][pg][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_scan_route_tpl);
    DiscoveryScanRouteHarness h{db.dsn()};

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE discovery_store.discovered_devices CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.scan(R"({"subnet":"10.0.0.0/24","devices":[
        {"ip_address":"10.0.0.8","hostname":"host8"},
        {"ip_address":"10.0.0.9","hostname":"host9"}
    ]})");
    REQUIRE(res);
    // The BLOCKING defect: this used to be 200 {"status":"ok","devices_stored":0}
    // with an unconditional "success" audit row -- a scan that stored NOTHING
    // reported identically to one that stored everything.
    CHECK(res->status == 503);
    REQUIRE(h.audit_outcomes.size() == 1);
    CHECK(h.audit_outcomes[0] == "failure");
}

TEST_CASE("POST /api/discovery/scan: one device of two fails to persist -> 200 partial, "
          "audit partial, honest per-device counts",
          "[discovery_store][pg][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_scan_route_tpl);
    DiscoveryScanRouteHarness h{db.dsn()};

    // Force a genuine, per-row failure for exactly one ip_address, leaving
    // every other row's INSERT/ON CONFLICT path unaffected -- unlike the
    // all-fail test's DROP TABLE, this reproduces the mixed-outcome branch
    // (some succeed, some fail in the SAME request) that a table-wide
    // failure structurally cannot exercise.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult fn{PQexec(conn.get(),
                           "CREATE FUNCTION discovery_store.reject_one_ip() RETURNS trigger AS $$ "
                           "BEGIN IF NEW.ip_address = '10.0.0.13' THEN "
                           "RAISE EXCEPTION 'forced failure for test'; END IF; "
                           "RETURN NEW; END; $$ LANGUAGE plpgsql")};
        REQUIRE(fn.ok());
        PgResult trig{PQexec(
            conn.get(), "CREATE TRIGGER reject_one_ip BEFORE INSERT ON "
                        "discovery_store.discovered_devices FOR EACH ROW EXECUTE FUNCTION "
                        "discovery_store.reject_one_ip()")};
        REQUIRE(trig.ok());
    }

    auto res = h.scan(R"({"subnet":"10.0.0.0/24","devices":[
        {"ip_address":"10.0.0.12","hostname":"host12"},
        {"ip_address":"10.0.0.13","hostname":"host13"}
    ]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["status"] == "partial");
    CHECK(body["devices_stored"] == 1);
    CHECK(body["devices_failed"] == 1);
    REQUIRE(h.audit_outcomes.size() == 1);
    CHECK(h.audit_outcomes[0] == "partial");

    auto listed = h.discovery_store->list_devices();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK(listed->front().ip_address == "10.0.0.12");
}
