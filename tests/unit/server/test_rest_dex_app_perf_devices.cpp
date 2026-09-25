// test_rest_dex_app_perf_devices.cpp — HTTP-level tests for the version-row
// "which devices" drill, GET /api/v1/dex/perf/app/devices.
//
// Unlike GET /api/v1/dex/perf/app (a fleet aggregate, no agent_id), each row
// here names an agent_id — a fleet-wide fan-out of identified per-device
// data — so this route uses AuthRoutes::require_fleet_read as its SOLE gate
// (never stacked with a bare permission check) and fails closed on a dropped
// audit row, mirroring GET /api/v1/dex/devices/{id}/app-perf and GET
// /api/v1/inventory/software's own unit-test shape (test_rest_inventory_
// software.cpp's InvHarness — this harness is the same lightweight pattern:
// a fake authz::FleetReadGate the harness controls per-test, no real
// AuthRoutes/RBAC/ManagementGroup needed to prove the ROUTE's own reaction).
//
// The tests pin:
//   - Gate deny / unwired → whatever the gate wrote reaches the wire, no read,
//     no success audit.
//   - Missing/invalid app or version → 400 (version is REQUIRED-PRESENT,
//     unlike /dex/perf/app's "omit = all versions" convention).
//   - Provider absent → 503; store degrade → 503 + "failure" audit.
//   - Success: rows + truncated flag serialize; the gate's VisibleSet reaches
//     the provider UNCHANGED (never widened to nullopt, never post-filtered).
//   - FAIL-CLOSED audit: a dropped `dex.app_perf.devices.view` row → 503 +
//     Sec-Audit-Failed, no device data on the wire.

#include "app_perf_daily_store.hpp" // AppPerfVersionDeviceRow
#include "authz_gates.hpp"
#include "rest_api_v1.hpp"
#include "test_dex_perf_api_double.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Mirrors test_rest_inventory_software.cpp's InvHarness: a fake
// authz::FleetReadGate the harness controls per-test, everything else
// nullptr/stub (this route touches none of it — require_fleet_read is the
// sole gate, and version_devices is the sole data path).
struct Harness {
    yuzu::server::test::TestRouteSink sink;

    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope;
    int fleet_deny_status{403};

    bool audit_ok{true};
    std::vector<AuditRecord> audit_log;

    // What the fake provider returns; nullopt = AUTHORITATIVE degrade.
    std::optional<std::vector<AppPerfVersionDeviceRow>> provider_rows{
        std::vector<AppPerfVersionDeviceRow>{}};
    bool provider_truncated{false};
    // What the provider actually SAW — proves the gate's scope reaches the
    // store query unchanged (never post-filtered, never widened).
    std::optional<std::vector<std::string>> seen_visible_ids;
    bool provider_called{false};

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    explicit Harness(bool wire_provider = true, bool wire_fleet_read_fn = true) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_ok;
        };

        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read_fn) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&,
                                   const std::string&) -> authz::FleetReadGate {
                if (!fleet_admitted) {
                    res.status = fleet_deny_status;
                    res.set_content(R"({"error":{"message":"denied"}})", "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }

        yuzu::server::test::FnDexPerfApi::Providers providers;
        if (wire_provider) {
            providers.version_devices =
                [this](std::string_view, std::string_view,
                       const std::optional<std::vector<std::string>>& visible_ids,
                       bool& truncated) -> std::optional<std::vector<AppPerfVersionDeviceRow>> {
                provider_called = true;
                seen_visible_ids = visible_ids;
                truncated = provider_truncated;
                return provider_rows;
            };
        }

        // ADR-0031 WS-A4 (sixth family): the route now calls the DexPerfApi
        // seam, not `providers` directly — wrap the SAME `providers` struct
        // (FnDexPerfApi, mirrors FnVerifyApi) so `wire_provider=false` still
        // reaches the "provider unavailable" 503 exactly as before (this
        // route's own `app_version_devices` degrades to nullopt when
        // `providers.version_devices` is unset).
        auto dex_perf_api_local =
            std::make_shared<yuzu::server::test::FnDexPerfApi>(yuzu::server::DexPerfFn{}, providers);

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{}, std::move(fleet_read_fn),
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{},
                            /*dex_visible_fn=*/{}, /*verify_api=*/nullptr,
                            /*device_api=*/nullptr, /*dex_api=*/nullptr, dex_perf_api_local);
    }

    bool has_audit(const std::string& result) const {
        for (const auto& a : audit_log)
            if (a.action == "dex.app_perf.devices.view" && a.result == result)
                return true;
        return false;
    }
};

} // namespace

TEST_CASE("REST dex/perf/app/devices: gate denies -> its status reaches the wire, "
          "no read, no success audit",
          "[rest][dex][app_perf][security]") {
    Harness h;
    h.fleet_admitted = false;
    h.fleet_deny_status = 403;
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.provider_called);
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST dex/perf/app/devices: unwired fleet_read_fn -> 503, never a fallback admit",
          "[rest][dex][app_perf][security]") {
    Harness h{/*wire_provider=*/true, /*wire_fleet_read_fn=*/false};
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(h.provider_called);
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST dex/perf/app/devices: missing app -> 400, gate never reached", "[rest][dex][app_perf]") {
    Harness h;
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?version=1.0");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(h.provider_called);
}

TEST_CASE("REST dex/perf/app/devices: version absent -> 400 (NOT treated as \"all "
          "versions\")",
          "[rest][dex][app_perf]") {
    Harness h;
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(h.provider_called);
}

TEST_CASE("REST dex/perf/app/devices: version=\"\" (present, empty) is ACCEPTED -- the "
          "unknown-version bucket",
          "[rest][dex][app_perf]") {
    Harness h;
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.provider_called);
}

TEST_CASE("REST dex/perf/app/devices: provider absent -> 503", "[rest][dex][app_perf]") {
    Harness h{/*wire_provider=*/false};
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST dex/perf/app/devices: store degrade -> 503 + failure audit, never success+[]",
          "[rest][dex][app_perf]") {
    Harness h;
    h.provider_rows = std::nullopt; // AUTHORITATIVE degrade
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.has_audit("failure"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST dex/perf/app/devices: success serializes rows + truncated, the gate's "
          "VisibleSet reaches the provider unchanged",
          "[rest][dex][app_perf]") {
    Harness h;
    h.fleet_scope = std::unordered_set<std::string>{"WS-1"}; // engaged, non-empty scope
    AppPerfVersionDeviceRow r;
    r.agent_id = "WS-1";
    r.last_day = 1'700'000'000;
    r.samples = 7;
    r.cpu_avg = 55.5;
    r.ws_avg_bytes = 999;
    h.provider_rows = std::vector<AppPerfVersionDeviceRow>{r};
    h.provider_truncated = true;

    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=119.0.0.0");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("app").get<std::string>() == "chrome.exe");
    CHECK(data.at("version").get<std::string>() == "119.0.0.0");
    CHECK(data.at("truncated").get<bool>() == true);
    REQUIRE(data.at("devices").size() == 1);
    CHECK(data.at("devices")[0].at("agent_id").get<std::string>() == "WS-1");
    CHECK(data.at("devices")[0].at("samples").get<int64_t>() == 7);

    REQUIRE(h.seen_visible_ids.has_value());
    REQUIRE(h.seen_visible_ids->size() == 1);
    CHECK((*h.seen_visible_ids)[0] == "WS-1");
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST dex/perf/app/devices: nullopt gate scope threads through as nullopt "
          "(unfiltered), not an empty vector",
          "[rest][dex][app_perf]") {
    Harness h; // fleet_scope defaults to nullopt (unfiltered)
    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.provider_called);
    CHECK_FALSE(h.seen_visible_ids.has_value());
}

// FAIL-CLOSED audit: a dropped evidence row must withhold the data, mirroring
// GET /api/v1/inventory/software and GET /dex/devices/{id}/app-perf.
TEST_CASE("REST dex/perf/app/devices: dropped audit row -> 503 + Sec-Audit-Failed, "
          "no device data on the wire",
          "[rest][dex][app_perf][security]") {
    Harness h;
    h.audit_ok = false;
    AppPerfVersionDeviceRow r;
    r.agent_id = "WS-secret";
    h.provider_rows = std::vector<AppPerfVersionDeviceRow>{r};

    auto res = h.sink.Get("/api/v1/dex/perf/app/devices?app=chrome.exe&version=1.0");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("WS-secret") == std::string::npos);
}

TEST_CASE("REST dex/perf/app/devices: path is in the OpenAPI spec (A1 discoverability)",
          "[rest][dex][app_perf]") {
    Harness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].contains("/dex/perf/app/devices"));
    CHECK(spec["paths"]["/dex/perf/app/devices"].contains("get"));
}
