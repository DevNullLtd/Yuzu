/**
 * test_service_scope_refusal.cpp -- #5557: the service-scoped unrestricted-authority refusal,
 * counter seed and the list-read gate through a real consumer route.
 *
 * The gates' own cases live in test_engine_principal_integration.cpp (sections 6c-1/6c-2); the
 * execution list surfaces are covered beside their routes (test_execution_owner_*.cpp and
 * test_mcp_server.cpp). This file adds what neither owns:
 *   1. the counter is described and zero-seeded, all four series, ASCII help text;
 *   2. `GET /api/v1/plugin-config`, bound to what server.cpp binds (`require_global_list_read`,
 *      which wraps `require_list_read`), refuses a corrupted service-scoped engine row with the
 *      same body, audit row and counter, RBAC on and off, while a legit engine and a
 *      service-scoped human token behave as before.
 */

#include "authz_gates.hpp"
#include "plugin_config_routes.hpp"
#include "test_execution_owner_engine.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <memory>
#include <string>

using namespace yuzu::server;
using yuzu::test::ExecutionOwnerRig;
using yuzu::test::OwnerEngineCreds;

TEST_CASE("service-scope refusal counter: seeded at 0 for all four series, with ASCII help",
          "[service_scope][authz_gates][5557]") {
    yuzu::MetricsRegistry m;
    authz::seed_service_scope_unrestricted_refusal_metrics(m);
    const auto body = m.serialize();
    const std::string name = "yuzu_server_authz_service_scope_unrestricted_refused_total";
    CHECK(body.find("# HELP " + name + " ") != std::string::npos);
    CHECK(body.find("# TYPE " + name + " counter") != std::string::npos);
    for (const char* gate : {"fleet_read", "list_read"})
        for (const char* site : {"engine_entry", "postcondition"}) {
            INFO(gate << "/" << site);
            CHECK(body.find(name + "{gate=\"" + gate + "\",site=\"" + site + "\"} 0\n") !=
                  std::string::npos);
        }
    CHECK(std::all_of(body.begin(), body.end(), [](unsigned char c) { return c < 0x80; }));
    // Seeding twice is idempotent (the responder's lazy create must keep working).
    authz::seed_service_scope_unrestricted_refusal_metrics(m);
    CHECK(m.counter(name, {{"gate", "list_read"}, {"site", "engine_entry"}}).value() == 0.0);
}

namespace {

// GET /api/v1/plugin-config with the gate production binds (server.cpp: the list route's SOLE
// gate is `AuthRoutes::require_global_list_read`). The store is left null: a refused request
// never reaches it, and an ADMITTED one answers the store-unavailable 503, which is exactly how
// admission is told apart from a refusal here.
struct PluginConfigList {
    ExecutionOwnerRig& r;
    yuzu::server::test::TestRouteSink sink;

    explicit PluginConfigList(ExecutionOwnerRig& rig) : r(rig) {
        plugin_config::Deps d;
        d.list_read_fn = [this](const httplib::Request& req, httplib::Response& res,
                                const std::string& type, const std::string& op) {
            return r.auth->require_global_list_read(req, res, type, op);
        };
        d.auth_fn = r.auth_fn();
        d.perm_fn = r.perm_fn();
        d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                        const std::string&, const std::string&, const std::string&) {
            return true;
        };
        plugin_config::register_plugin_config_routes(sink, std::move(d));
    }
    std::unique_ptr<httplib::Response> get(const std::string& token) {
        auto res = sink.dispatch("GET", "/api/v1/plugin-config", {}, "application/json",
                                 ExecutionOwnerRig::bearer(token));
        REQUIRE(res);
        return res;
    }
};

void check_plugin_config_list_read(bool rbac_on) {
    yuzu::MetricsRegistry metrics; // before the rig: AuthManager keeps a pointer to it
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    OwnerEngineCreds e{r, metrics};
    PluginConfigList L{r};
    r.rbac.set_rbac_enabled(rbac_on);
    REQUIRE(r.rbac.create_role({"PluginConfigReader5557", "", false, 0}).has_value());
    REQUIRE(r.rbac.set_permission({"PluginConfigReader5557", "PluginConfig", "Read", "allow"})
                .has_value());
    const auto ctl = e.mint("engine:ctl", "PluginConfigReader5557");
    const auto bad = e.mint("engine:bad", "PluginConfigReader5557", "A");
    const auto bad_no_grant = e.mint("engine:badnogrant", {}, "A");
    auto corrupted_rows = [&] {
        const auto rows = r.audit("auth.permission_required");
        return std::count(rows.begin(), rows.end(), std::string(yuzu::test::kCorruptedEngineAuditRow));
    };

    // Control: a legit engine with the grant is admitted when RBAC is on (the 503 is the null
    // store, past the gate) and refused as today when it is off (engines are RBAC-only).
    const auto control = L.get(ctl);
    CHECK(control->status == (rbac_on ? 503 : 403));
    if (rbac_on) // the ROUTE's null-store 503, not a gate 503 ("authorization store unavailable")
        CHECK(control->body.find("plugin config store unavailable") != std::string::npos);
    CHECK(e.refused_total() == 0.0);
    CHECK(corrupted_rows() == 0);

    int expected = 0;
    for (const auto& token : {bad, bad_no_grant}) {
        const auto got = L.get(token);
        ++expected;
        INFO("refusal " << expected << ", rbac_on=" << rbac_on);
        CHECK(got->status == 403);
        CHECK(got->body.find("permission denied: PluginConfig:Read") != std::string::npos);
        CHECK(got->body.find("\"permission\"") == std::string::npos);
        CHECK(corrupted_rows() == expected);
        CHECK(e.refused("list_read", "engine_entry") == static_cast<double>(expected));
        CHECK(e.refused_total() == static_cast<double>(expected));
    }

    // A service-scoped HUMAN token keeps the existing blanket deny (its own text and audit
    // detail); the new refusal does not shadow it and nothing is counted.
    if (rbac_on) {
        const auto human = L.get(r.creds.svc_a);
        CHECK(human->status == 403);
        CHECK(human->body.find("service-scoped tokens cannot read the fleet-wide status rollup") !=
              std::string::npos);
        CHECK(human->body.find("\"permission\"") == std::string::npos);
        const auto rows = r.audit("auth.permission_required");
        CHECK(std::count_if(rows.begin(), rows.end(), [](const std::string& row) {
                  return row.find("service-scoped token 'A' cannot read the fleet-wide") !=
                         std::string::npos;
              }) == 1);
        CHECK(e.refused_total() == static_cast<double>(expected));
    }
}

} // namespace

TEST_CASE("plugin-config list (require_global_list_read): a service-scoped engine row is refused "
          "403, RBAC on",
          "[pg][service_scope][authz_gates][engine_principal][5557]") {
    check_plugin_config_list_read(/*rbac_on=*/true);
}

TEST_CASE("plugin-config list (require_global_list_read): a service-scoped engine row is refused "
          "403, RBAC off",
          "[pg][service_scope][authz_gates][engine_principal][5557]") {
    check_plugin_config_list_read(/*rbac_on=*/false);
}
