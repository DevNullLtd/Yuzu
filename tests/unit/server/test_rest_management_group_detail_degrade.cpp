/**
 * test_rest_management_group_detail_degrade.cpp — governance round-1 finding
 * (sec-1/arch-1, #1762): `GET /api/v1/management-groups/{id}` used to call the
 * LEGACY fail-soft `ManagementGroupStore::get_members()`, which collapses a
 * store-not-open / pool-acquire-timeout / query-error degrade into the SAME
 * empty vector a genuinely-empty group returns — so a degraded member read
 * rendered as an authoritative "this group has zero members" 200 response.
 *
 * The route now calls `get_members_checked()` and fails closed with a
 * retryable 503 (A4 envelope, `retry_after_ms: 2000`) on `nullopt`, matching
 * the sibling `GET /api/v1/dex/perf/group` degrade shape. This test proves
 * both halves: a healthy read still returns the real member list, and a
 * degraded member-table read no longer answers `200` with an empty list.
 *
 * PG-gated: ManagementGroupStore is a Postgres store (ADR-0042).
 */

#include "management_group_store.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

using namespace yuzu::server;

namespace {

struct GroupDetailHarness {
    // Declared FIRST: mgmt_bundle's store borrows it via set_metrics(), so
    // it must outlive the store (destroyed last).
    yuzu::MetricsRegistry metrics;
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac = *rbac_bundle;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    GroupDetailHarness() {
        REQUIRE(rbac.is_open());
        // Wire the same metrics registry production does
        // (server.cpp's `mgmt_group_store_->set_metrics(&metrics_)`) so the
        // degrade-counter assertions below observe real bumps.
        mgmt_bundle->set_metrics(&metrics);

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&,
                           const std::string&) -> bool { return true; };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/&rbac,
                            /*mgmt_store=*/&*mgmt_bundle,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr);
    }
};

} // namespace

TEST_CASE("GET /management-groups/{id}: a healthy member read returns the real member list",
          "[pg][rest][management_group][degraded]") {
    GroupDetailHarness h;

    ManagementGroup g;
    g.name = "degrade-test-healthy";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    auto res = h.sink.Get("/api/v1/management-groups/" + gid);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["members"].is_array());
    REQUIRE(body["data"]["members"].size() == 1);
    CHECK(body["data"]["members"][0]["agent_id"] == "agent-1");
}

TEST_CASE("GET /management-groups/{id}: a degraded member read fails closed with a retryable "
          "503, never an authoritative empty member list (#1762)",
          "[pg][rest][management_group][degraded]") {
    GroupDetailHarness h;

    ManagementGroup g;
    g.name = "degrade-test-degraded";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    // Drop the member table (group metadata itself stays readable) so
    // get_members_checked() degrades while get_group() still succeeds —
    // isolating the member-read failure the fix targets.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE management_group_store.management_group_members")};
        REQUIRE(d.ok());
    }

    auto res = h.sink.Get("/api/v1/management-groups/" + gid);
    REQUIRE(res);
    // Before this fix: 200 with data.members == [] (indistinguishable from a
    // genuinely empty group). After: a retryable 503 A4 envelope.
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"] == "management group store read degraded");
    CHECK(body["error"]["retry_after_ms"] == 2000);
}

// Governance round-2 (G8-1, #1762): GET /api/v1/management-groups/{id} used to
// call the LEGACY fail-soft ManagementGroupStore::get_group(), whose nullopt
// collapses a store-not-open / pool-acquire-timeout / query-error degrade with
// a genuine "no such group" — so a degraded GROUP-ROW read (not just the
// member read the round-1 fix above covers) rendered as a flat 404, hiding a
// store outage behind "not found". The route now calls get_group_checked()
// and fails closed with the SAME retryable 503 A4 envelope on a group-row
// degrade; a genuine not-found still 404s (covered by the store-level test in
// test_management_group_store.cpp).
TEST_CASE("GET /management-groups/{id}: a degraded GROUP-ROW read fails closed with a "
          "retryable 503, never a flat 404 (#1762 G8-1)",
          "[pg][rest][management_group][degraded]") {
    GroupDetailHarness h;

    ManagementGroup g;
    g.name = "degrade-test-group-row";
    g.membership_type = "static";
    g.created_by = "tester";
    auto grp = h.mgmt_bundle->create_group(g);
    REQUIRE(grp.has_value());
    const std::string gid = *grp;

    // Drop the groups table itself (CASCADE also drops the members/roles FK
    // constraints that reference it) so get_group_checked() degrades — this
    // must be reported BEFORE the route ever reaches get_members_checked().
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.mgmt_bundle.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{PQexec(
            conn.get(), "DROP TABLE management_group_store.management_groups CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.sink.Get("/api/v1/management-groups/" + gid);
    REQUIRE(res);
    // Before this fix: get_group()'s nullopt collapsed "no such group" with
    // "store degraded" -> a flat 404. After: a retryable 503 A4 envelope.
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"] == "management group store read degraded");
    CHECK(body["error"]["retry_after_ms"] == 2000);
    // sre G8-4: the degrade counter bumps on the group-row read path too
    // (same counter get_members_checked already fed — reason=query_error
    // here, since the table itself no longer exists).
    CHECK(h.metrics
              .counter("yuzu_server_mgmt_group_read_degrade_total",
                       {{"reason", "query_error"}})
              .value() >= 1.0);
}
