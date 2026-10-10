// test_rest_devices.cpp — HTTP-level tests for the #4033 (#2146 API-parity
// Batch A) device REST twins: GET /api/v1/devices (list), GET
// /api/v1/devices/{id} (detail), and GET /api/v1/management-groups/
// agent-count-preview (the create-group agent-count preview).
//
// GET /api/v1/devices[/{id}] are migrated onto AuthRoutes::require_fleet_read
// (via the injected FleetReadFn, same seam GET /api/v1/inventory/software
// uses — see test_rest_inventory_software.cpp's InvHarness for the pattern
// this file borrows) as their SOLE gate; this harness fakes that gate the
// same way. No Postgres substrate is needed for the paths under test here:
// ADR-0031 WS-A4 wave 2 sources both routes from a `FakeDeviceApi` test double
// (this file's own DeviceApi implementation) instead of a raw registry
// snapshot — `agents_fn` stays wired (still used by POST /api/v1/scope/preview,
// untested in this file) but is no longer these two routes' data source.
//
// What's covered:
//   - GET /api/v1/devices: gate deny (401/403/503-unwired) -> no rows; gate
//     admit + scope filter -> only in-scope rows, correct devices_omitted
//     count; row shape matches list_agents' 5-field contract.
//   - GET /api/v1/devices/{id}: found in-scope -> 200 w/ fields (tags key
//     always present, possibly empty — see the PURE builder section below for
//     why); out-of-scope match collapses to the SAME 404 as a genuinely
//     nonexistent agent_id (#1700-style existence-oracle closure).
//   - device_agent_row_json / device_agent_detail_json (PURE, no HTTP/store):
//     5-field row shape; tags array populated (key/value/source per entry)
//     — the DeviceApi seam (device_api.hpp) always returns an (possibly
//     empty) tags vector, so the emitted JSON always carries the key.
//   - GET /api/v1/management-groups/agent-count-preview: perm_fn/auth_fn gate;
//     empty filters -> agent_count 0 with NO store call (works even with
//     response_store == nullptr); non-empty filters + response_store ==
//     nullptr -> 503 (degrade posture, never a false 200).

#include "device_routes.hpp"
#include "rest_api_v1.hpp"
#include "authz_gates.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <expected>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_id, detail;
};

// Minimal DeviceApi test double (ADR-0031 WS-A4 wave 2) — backs GET
// /api/v1/devices[/{id}] in place of the retired raw `agents_fn` read on this
// pair. `rows` is UNSCOPED (fleet_read_fn's own gate.scope is the sole filter,
// matching the real seam's contract); `details` backs the point lookup by id.
class FakeDeviceApi : public DeviceApi {
public:
    std::vector<DeviceListRow> rows;
    std::unordered_map<std::string, DeviceDetail> details;
    bool degrade = false;         ///< when true, lookup_device returns kDegraded (tag-store outage)
    mutable int lookup_calls = 0; ///< #3564: assert an out-of-scope id short-circuits BEFORE any read

    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override { return rows; }

    [[nodiscard]] std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string& id) const override {
        ++lookup_calls;
        if (degrade)
            return std::unexpected(DeviceReadError::kDegraded);
        if (auto it = details.find(id); it != details.end())
            return std::optional<DeviceDetail>{it->second};
        return std::optional<DeviceDetail>{std::nullopt};
    }
};

// Minimal harness wiring only what the three routes under test need. Every
// OTHER register_routes dependency stays nullptr/{} — none of those routes
// are dispatched by this file's tests.
struct DeviceRestHarness {
    yuzu::server::test::TestRouteSink sink;

    bool auth_ok{true};
    bool perm_grant{true};

    // Fleet-read gate control (GET /api/v1/devices[/{id}]).
    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope{std::nullopt}; // nullopt = TOP/unfiltered
    int fleet_deny_status{403};

    // Raw agent registry snapshot — still wired for POST /api/v1/scope/preview
    // (agents_fn's other live consumer); NOT this file's device-route tests'
    // data source any more (see device_api below).
    nlohmann::json agents = nlohmann::json::array();

    // ADR-0031 WS-A4 wave 2: the DeviceApi seam backing GET
    // /api/v1/devices[/{id}] under test in this file.
    std::shared_ptr<FakeDeviceApi> device_api = std::make_shared<FakeDeviceApi>();

    // D3 Response:Read-visible scope for the group-preview route.
    std::optional<std::set<std::string>> response_visible_scope; // nullopt = TOP

    std::vector<AuditRecord> audit_log;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    explicit DeviceRestHarness(bool wire_fleet_read_fn = true) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_ok) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "operator1";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
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
        RestApiV1::AgentsJsonFn agents_fn = [this]() -> nlohmann::json { return agents; };
        RestApiV1::ResponseVisibleSetFn response_visible_set_fn =
            [this](const std::string&) -> std::optional<std::set<std::string>> {
            return response_visible_scope;
        };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{}, /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr, /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{}, /*list_read_fn=*/{},
            std::move(fleet_read_fn), std::move(agents_fn), std::move(response_visible_set_fn),
            /*verify_api=*/{}, /*device_api=*/device_api,
            /*dex_api=*/{});
    }

    void add_agent(const std::string& id, const std::string& hostname) {
        agents.push_back({{"agent_id", id},
                          {"hostname", hostname},
                          {"os", "linux"},
                          {"arch", "x86_64"},
                          {"agent_version", "1.0.0"}});
        DeviceListRow row{.agent_id = id, .hostname = hostname, .os = "linux", .arch = "x86_64",
                         .agent_version = "1.0.0"};
        device_api->rows.push_back(row);
        device_api->details[id] = DeviceDetail{.row = row, .tags = {}};
    }
};

} // namespace

TEST_CASE("GET /api/v1/devices — unwired fleet_read_fn fails closed (503)", "[rest][devices]") {
    DeviceRestHarness h(/*wire_fleet_read_fn=*/false);
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}

TEST_CASE("GET /api/v1/devices — gate denial forwards the gate's own status, no rows served",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_admitted = false;
    h.fleet_deny_status = 403;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/devices — admitted + unfiltered scope returns every agent, 5-field rows",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt; // TOP
    h.add_agent("a1", "host1");
    h.add_agent("a2", "host2");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& devices = body["data"]["devices"];
    REQUIRE(devices.size() == 2);
    CHECK(body["data"]["count"].get<int64_t>() == 2);
    CHECK(body["data"]["devices_omitted"].get<int64_t>() == 0);
    // Row shape: exactly the 5 list_agents fields.
    CHECK(devices[0]["agent_id"] == "a1");
    CHECK(devices[0]["hostname"] == "host1");
    CHECK(devices[0]["os"] == "linux");
    CHECK(devices[0]["arch"] == "x86_64");
    CHECK(devices[0]["agent_version"] == "1.0.0");
    CHECK_FALSE(devices[0].contains("tags"));
    CHECK_FALSE(devices[0].contains("online"));
}

TEST_CASE("GET /api/v1/devices — engaged scope filters rows and reports devices_omitted",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::unordered_set<std::string>{"a1"}; // engaged, admits only a1
    h.add_agent("a1", "host1");
    h.add_agent("a2", "host2");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& devices = body["data"]["devices"];
    REQUIRE(devices.size() == 1);
    CHECK(devices[0]["agent_id"] == "a1");
    CHECK(body["data"]["devices_omitted"].get<int64_t>() == 1);
}

TEST_CASE("GET /api/v1/devices/{id} — found and in-scope returns the row", "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["agent_id"] == "a1");
    CHECK(body["data"]["hostname"] == "host1");
    // ADR-0031 WS-A4 wave 2: DeviceApi always returns a (possibly empty) tags
    // vector — "tags" is now ALWAYS present, never omitted (deliberate,
    // already-committed wave-1 seam decision; see device_routes.hpp's doc
    // comment on device_agent_detail_json).
    REQUIRE(body["data"].contains("tags"));
    CHECK(body["data"]["tags"].empty());
}

TEST_CASE("GET /api/v1/devices/{id} — nonexistent agent_id is a 404", "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices/does-not-exist");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
}

TEST_CASE("GET /api/v1/devices/{id} — out-of-scope match collapses to the SAME 404 as "
          "nonexistent (#1700-style existence-oracle closure)",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::unordered_set<std::string>{}; // engaged-empty: nothing in scope
    h.add_agent("a1", "host1"); // exists in the registry, but outside the caller's scope
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);

    // Byte-identical body to the genuinely-nonexistent case (same code path).
    DeviceRestHarness h2;
    h2.fleet_scope = std::nullopt;
    auto res2 = h2.sink.Get("/api/v1/devices/does-not-exist-either");
    REQUIRE(res2 != nullptr);
    CHECK(res2->status == 404);
}

TEST_CASE("GET /api/v1/devices/{id} — an out-of-scope id is denied with ZERO backing read "
          "(#3564 timing-oracle closure; security-guardian + architect)",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::unordered_set<std::string>{}; // engaged-empty: nothing in scope
    h.add_agent("a1", "host1"); // EXISTS in the registry + device_api->details, but out of scope
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
    // The fix: `in_scope` is checked FIRST, so an out-of-scope id short-circuits
    // to 404 without ever calling lookup_device — no registry/tag-store read, so
    // an existent-but-out-of-scope id is indistinguishable from a nonexistent one
    // by TIMING as well as by response. This assertion fails against a
    // lookup-then-scope ordering (which would read for the existent id).
    CHECK(h.device_api->lookup_calls == 0);
}

TEST_CASE("GET /api/v1/devices/{id} — in-scope degraded tag-store read is a 503, not a false 404/200",
          "[rest][devices]") {
    DeviceRestHarness h; // fleet_scope defaults to nullopt = in scope
    h.add_agent("a1", "host1");
    h.device_api->degrade = true; // tag-store outage on the detail read
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
    CHECK(h.device_api->lookup_calls == 1); // in-scope DOES reach the lookup (only out-of-scope skips it)
}

// ── PURE builder coverage: device_agent_row_json / device_agent_detail_json ──
// No HTTP, no store — direct calls against the pure functions declared in
// device_routes.hpp, now over DeviceApi's typed rows (ADR-0031 WS-A4 wave 2).
// `tags` is ALWAYS present in the emitted JSON post-rewire (never omitted) —
// see device_routes.hpp's doc comment on device_agent_detail_json for why
// this is a deliberate, already-committed (wave 1) seam decision.

TEST_CASE("device_agent_row_json: exactly the 5 list_agents fields", "[devices][pure]") {
    DeviceListRow agent{.agent_id = "a1", .hostname = "host1", .os = "linux", .arch = "x86_64",
                       .agent_version = "1.0.0"};
    auto row = device_agent_row_json(agent);
    CHECK(row["agent_id"] == "a1");
    CHECK(row["hostname"] == "host1");
    CHECK(row["os"] == "linux");
    CHECK(row["arch"] == "x86_64");
    CHECK(row["agent_version"] == "1.0.0");
    CHECK(row.size() == 5);
}

TEST_CASE("device_agent_row_json: a default-constructed row degrades to empty fields",
          "[devices][pure]") {
    DeviceListRow agent{.agent_id = "a1"}; // hostname/os/arch/agent_version all default-empty
    auto row = device_agent_row_json(agent);
    CHECK(row["agent_id"] == "a1");
    CHECK(row["hostname"] == "");
    CHECK(row["os"] == "");
}

TEST_CASE("device_agent_detail_json: an empty tags vector produces an empty array",
          "[devices][pure]") {
    DeviceDetail detail_in{.row = {.agent_id = "a1"}, .tags = {}};
    auto detail = device_agent_detail_json(detail_in);
    REQUIRE(detail.contains("tags"));
    CHECK(detail["tags"].is_array());
    CHECK(detail["tags"].empty());
}

TEST_CASE("device_agent_detail_json: a populated tags vector serialises key/value/source per "
          "entry",
          "[devices][pure]") {
    DeviceDetail detail_in{
        .row = {.agent_id = "a1", .hostname = "host1", .os = "linux", .arch = "x86_64",
               .agent_version = "1.0.0"},
        .tags = {DeviceTagRow{.key = "environment", .value = "production", .source = "server"},
                DeviceTagRow{.key = "owner", .value = "sre-team", .source = "agent"}},
    };
    auto detail = device_agent_detail_json(detail_in);
    REQUIRE(detail.contains("tags"));
    REQUIRE(detail["tags"].size() == 2);
    CHECK(detail["tags"][0]["key"] == "environment");
    CHECK(detail["tags"][0]["value"] == "production");
    CHECK(detail["tags"][0]["source"] == "server");
    CHECK(detail["tags"][1]["key"] == "owner");
    CHECK(detail["tags"][1]["value"] == "sre-team");
    CHECK(detail["tags"][1]["source"] == "agent");
    // Detail still carries the base 5 row fields alongside tags.
    CHECK(detail["agent_id"] == "a1");
    CHECK(detail["hostname"] == "host1");
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — perm_fn denial blocks the route",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — no filters is a genuine 0, "
          "no store call needed",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["agent_count"].get<int64_t>() == 0);
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — a real filter against an "
          "unwired store degrades (503), never a false-empty 200",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&pid=1234");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}

// #5623: a facet value over kMaxFacetValueBytes (2048) is never stored, so a filter on it
// matches no agent. The preview must refuse it (400, non-retryable) rather than answer an
// exact 0. The harness's response_store is nullptr, so reaching the store would be the 503
// above: a 400 proves the refusal came before any store access. Literal sizes pin the bound.
TEST_CASE("GET /api/v1/management-groups/agent-count-preview: a filter value over the facet "
          "bound is refused (400), not answered as 0",
          "[rest][devices]") {
    DeviceRestHarness h;
    const std::string over(2049, 'a');
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&name=" +
                          over);
    REQUIRE(res != nullptr);
    CHECK(res->status == 400);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["code"].get<int>() == 400);
    CHECK(body["error"]["retry_after_ms"].is_null()); // non-retryable
    const auto message = body["error"]["message"].get<std::string>();
    CHECK(message.find("2048 bytes") != std::string::npos);
    CHECK(message.find(over) == std::string::npos); // the value is never echoed
    CHECK(body["error"].contains("remediation"));
    CHECK(res->body.find(over) == std::string::npos);
}

// A misspelled key is skipped by the filter resolver, which used to leave an empty filter set
// and an exact 0. The bound is checked on the raw value, so the key does not matter.
TEST_CASE("GET /api/v1/management-groups/agent-count-preview: an over-bound value under an "
          "unrecognised key is refused (400), not answered as 0",
          "[rest][devices]") {
    DeviceRestHarness h;
    const std::string over(2049, 'a');
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&no_such_column=" +
                          over);
    REQUIRE(res != nullptr);
    CHECK(res->status == 400);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["message"].get<std::string>().find("2048 bytes") != std::string::npos);
    CHECK(res->body.find(over) == std::string::npos);
}

// A NUL or invalid UTF-8 byte in a filter can never equal a stored value (ingest rewrites each
// to U+FFFD), and a NUL is C-string-truncated by the libpq bind, so `short%00zzz` used to
// match the rows of `short` and be reported as an exact count. Refused like an over-bound
// value, before any store access (the harness store is nullptr: 503 would mean it was reached).
TEST_CASE("GET /api/v1/management-groups/agent-count-preview: a NUL or invalid UTF-8 filter "
          "value is refused (400), not matched as a prefix or answered as 0",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    const std::string base = "/api/v1/management-groups/agent-count-preview"
                             "?command_id=cmd-1&plugin=procfetch&";
    const std::vector<std::string> bad_queries = {
        "name=short%00zzz",                // NUL in the middle: a prefix match presented as exact
        "name=%00",                        // NUL as the only content
        "name=%FF",                        // invalid lead byte
        "name=%C0%80",                     // overlong NUL
        "name=%ED%A0%80",                  // surrogate U+D800
        "name=ok%C3",                      // truncated multibyte at the end
        "no_such_column=short%00zzz",      // under an unrecognised key too
    };
    for (const auto& q : bad_queries) {
        INFO(q);
        auto res = h.sink.Get(base + q);
        REQUIRE(res != nullptr);
        CHECK(res->status == 400);
        auto body = nlohmann::json::parse(res->body);
        CHECK(body["error"]["code"].get<int>() == 400);
        CHECK(body["error"]["retry_after_ms"].is_null()); // non-retryable
        CHECK(body["error"]["message"].get<std::string>().find("NUL") != std::string::npos);
        CHECK(body["error"].contains("remediation"));
    }
    // 683 NULs (percent-encoded): under the raw bound, 2049 bytes once ingest widens them.
    std::string nuls;
    for (int i = 0; i < 683; ++i)
        nuls += "%00";
    auto res = h.sink.Get(base + "name=" + nuls);
    REQUIRE(res != nullptr);
    CHECK(res->status == 400);
}

// Positive control: a valid multibyte value at exactly 2048 bytes is not refused (it reaches
// the unwired store: 503).
TEST_CASE("GET /api/v1/management-groups/agent-count-preview: a valid multibyte filter value "
          "of exactly 2048 bytes is accepted",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    std::string enc;
    for (int i = 0; i < 1024; ++i)
        enc += "%C3%A9"; // U+00E9, 2 bytes each => 2048 bytes
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&name=" +
                          enc);
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview: a filter value exactly at the "
          "facet bound is accepted (reaches the store, 503 when unwired)",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    const std::string at(2048, 'a');
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&name=" +
                          at);
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}
