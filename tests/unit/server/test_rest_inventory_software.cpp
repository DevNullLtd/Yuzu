// test_rest_inventory_software.cpp — HTTP-level tests for the typed
// installed-software fleet read GET /api/v1/inventory/software (ADR-0016).
//
// This is the REST sibling of the governed MCP query_installed_software tool; the
// route mirrors that handler 1:1. #3290 Phase 2 migrated it onto
// AuthRoutes::require_fleet_read as the SOLE gate — perm_fn/auth_fn/
// InventoryScopeFn are no longer consulted by this route at all. The
// unit-level tests below (InvHarness) fake that gate with a plain
// authz::FleetReadGate the harness controls per-test; the real per-caller-
// class composition (service-scoped token vs. management-group-confined
// operator vs. unscoped) is proven against a REAL AuthRoutes in the [pg]
// "end-to-end confinement" section near the bottom of this file — the unit
// tests below only need to prove the ROUTE's own handling of whatever the
// gate decided.
//
// The tests pin:
//   - Gate deny (401/403) → no data, no success audit; unwired gate → 503.
//   - Two DISTINCT 503 paths, both asserted "never an empty 200":
//       * null/closed store → 503 "not available", NO audit (the store was never
//         consulted, so there is no access to record);
//       * OPEN store, query_software → std::nullopt (pool-acquire timeout / query
//         error) → 503 "degraded" AND a "failure" audit row (CC7.2: a triage caller
//         under a sustained outage still leaves a who/when/what trail). These are
//         NOT the same path — they differ precisely in the audit emission — so both
//         are tested here (the degrade path via a size-1 pool whose only lease is
//         held in-test, forcing try_acquire_for to time out).
//   - The gate's own composed scope FILTER (drops out-of-scope agents) +
//     devices_omitted + a distinct "denied" audit row.
//   - limit cap → result_truncated_by_cap; bad limit → 400.
//   - OpenAPI discoverability (A1): the path appears in /api/v1/openapi.json.
//
// Fixture mirrors the in-process TestRouteSink pattern (no socket, no acceptor
// thread, no TSan risk) from test_rest_software_packages.cpp.

#include "rest_api_v1.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "authz_gates.hpp"
#include "device_ci_kinds.hpp"
#include "hardware_list_model.hpp"
#include "openapi_spec_access.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "software_catalogue_model.hpp"
#include "software_inventory_store.hpp"
#include "software_list_model.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp"  // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {
int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): same key +
// identical setup as test_software_inventory_store.cpp (first build wins) —
// the store set here is exactly {SoftwareInventoryStore}.
yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore store{pool};
    // Throw, don't return: a silently-unmigrated template would make every
    // clone fall back to in-test migration — correct but slow, defeating the
    // point. PgTestTemplate::build records the throw as a fixture error.
    if (!store.is_open())
        throw std::runtime_error("swinv template: store failed to migrate");
}};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Wires GET /api/v1/inventory/software with a (borrowed, possibly null) typed
// store + a fake authz::FleetReadGate the harness controls per-test.
// `fleet_admitted`/`fleet_scope`/`fleet_deny_status` are mutable so a single
// fixture instance can drive each branch; `wire_fleet_read_fn` is ctor-only
// (registration-time, unlike the others — matches production's "unwired ==
// misconfiguration" contract, which is decided once at wiring, not per
// request).
struct InvHarness {
    yuzu::server::test::TestRouteSink sink;

    // Whatever the fake gate decides: true → the request proceeds with
    // fleet_scope (nullopt = TOP/unfiltered, matching a real global grant or
    // RBAC-off); false → the route returns immediately, whatever status/body
    // the fake gate wrote (fleet_deny_status/fleet_deny_message below).
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope;
    int fleet_deny_status{403};
    std::string fleet_deny_message{"permission denied"};
    // When false, audit_fn reports a persistence failure (returns false) so a test can
    // exercise the set-and-proceed `audit_persisted:false` honesty field.
    bool audit_ok{true};
    // Non-empty: only an audit row with this `result` (e.g. "denied") reports a persistence
    // failure; every other row persists. Isolates one row's contribution to audit_persisted.
    std::string audit_fail_result;
    // When true, audit_fn THROWS (bad_alloc-class / locked audit DB) — exercises the
    // #1647 throw-safe kernel: the route must not 500, it must serve with
    // audit_persisted:false (gov chaos CH-3, parity with the MCP sibling).
    bool audit_throws{false};
    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    // The device table's roster the lookup rows' hostname reads: agent_id -> hostname, one read
    // per page.
    std::unordered_map<std::string, std::string> hostnames;
    int hostname_reads{0};
    RestApiV1 api;

    explicit InvHarness(SoftwareInventoryStore* store, bool wire_fleet_read_fn = true) {
        // Neither is called by GET /api/v1/inventory/software any more
        // (require_fleet_read is now its sole gate) — kept only because
        // register_routes still needs a value for its OTHER routes, none of
        // which this file's tests exercise.
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
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audit_log.push_back({action, result, target_id, detail});
            return audit_ok && result != audit_fail_result;
        };
        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read_fn) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&,
                                   const std::string&) -> authz::FleetReadGate {
                if (!fleet_admitted) {
                    res.status = fleet_deny_status;
                    res.set_content(R"({"error":{"message":")" + fleet_deny_message + R"("}})",
                                    "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }

        api.set_hostnames_fn([this]() -> std::unordered_map<std::string, std::string> {
            ++hostname_reads;
            return hostnames;
        });
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
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, store,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{}, std::move(fleet_read_fn),
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{}, /*verify_api=*/{},
                            /*device_api=*/{}, /*dex_api=*/{});
    }

    bool has_audit(const std::string& result) const {
        for (const auto& a : audit_log)
            if (a.action == "inventory.software.query" && a.result == result)
                return true;
        return false;
    }
};

} // namespace

// ── No-PG branches (always run) ──────────────────────────────────────────────

TEST_CASE("REST inventory/software: null store → 503, never an empty 200",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 error envelope + correlation id echoed on every path. Structural assert (not a
    // substring search): the body is a JSON object with an `error` key and — crucially —
    // NO `data` key, so it can never be mistaken for a success-with-empty-list (the
    // fail-open ADR-0016 §7 closes): a vuln-triage caller must read "unknown", not
    // "installed nowhere".
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
}

// #3290 Phase 2: the route's own auth is gone — require_fleet_read is the
// SOLE gate. This proves the route respects the gate's decision (whatever
// caller class produced it: RBAC deny, service-scope default-deny, RBAC-off,
// etc. — all resolved by the real gate, tested in the [pg] end-to-end
// section below and in test_authz_gates.cpp). At the unit level, only the
// route's OWN reaction to !admitted needs proving: no data leaked, no
// success audit, whatever status/body the gate wrote reaches the wire
// unmodified.
TEST_CASE("REST inventory/software: gate denies → its status/body reach the wire, "
          "no success audit",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    h.fleet_deny_status = 403;
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: gate 401s (unauthenticated) → no data leaked",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    h.fleet_deny_status = 401;
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.has_audit("success"));
}

// require_fleet_read's own doc comment: unwired = misconfiguration, FAILS
// CLOSED (503) — never silently falls back to an unfiltered read.
TEST_CASE("REST inventory/software: unwired fleet_read_fn → 503, never a fallback admit",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr, /*wire_fleet_read_fn=*/false};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: path is in the OpenAPI spec (A1 discoverability)",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].contains("/inventory/software"));
    REQUIRE(spec["paths"]["/inventory/software"].contains("get"));
    // the csv export's response headers are discoverable: a client reads them off the spec
    const auto& ok = spec["paths"]["/inventory/software"]["get"]["responses"]["200"];
    REQUIRE(ok.contains("headers"));
    for (const char* header :
         {"Content-Disposition", "X-Result-Truncated-By-Cap", "Sec-Audit-Failed"})
        CHECK(ok["headers"].contains(header));
    // ...and so is the export's media type (carried in the 200 description)
    CHECK(ok["description"].get<std::string>().find("text/csv") != std::string::npos);
}

TEST_CASE("REST inventory/software: the 200 body is typed in the OpenAPI spec and matches the row model",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());

    const auto& ok = spec["paths"]["/inventory/software"]["get"]["responses"]["200"];
    REQUIRE(ok.contains("content"));
    CHECK(ok["content"]["application/json"]["schema"]["$ref"] ==
          "#/components/schemas/InstalledSoftwarePage");
    CHECK(ok["content"].contains("text/csv"));

    const auto& schemas = spec["components"]["schemas"];
    REQUIRE(schemas.contains("InstalledSoftwarePage"));
    REQUIRE(schemas.contains("InstalledSoftwareRow"));

    // The schema's row keys are exactly the keys the route serialises: a field added to or dropped
    // from device_row_json without the spec following fails here.
    const auto row = software_catalogue::device_row_json(SoftwareFleetRow{});
    std::set<std::string> served;
    for (const auto& [k, v] : row.items())
        served.insert(k);
    std::set<std::string> properties;
    for (const auto& [k, v] : schemas["InstalledSoftwareRow"]["properties"].items())
        properties.insert(k);
    std::set<std::string> required;
    for (const auto& k : schemas["InstalledSoftwareRow"]["required"])
        required.insert(k.get<std::string>());
    CHECK(properties == served);
    CHECK(required == served);

    // The row's ecosystem description points at the generated filter enum rather than carrying a
    // hand-typed list that drifts behind the vocabulary table (it once named nine of seventeen).
    const auto eco = schemas["InstalledSoftwareRow"]["properties"]["ecosystem"]["description"]
                         .get<std::string>();
    CHECK(eco.find("ecosystem filter enum") != std::string::npos);
    CHECK(eco.find("macos_pkgutil") == std::string::npos);

    // The page envelope's keys are those devices_response_json emits (result_truncated_by_cap is
    // conditional, so it is a property but not required).
    const auto page = software_catalogue::devices_response_json({}, "", 0, true);
    const auto& data = schemas["InstalledSoftwarePage"]["properties"]["data"];
    for (const auto& [k, v] : page.items())
        CHECK(data["properties"].contains(k));
    CHECK(data["properties"]["next_cursor"]["nullable"] == true);
}

// The Hardware routes' typed 200/202 bodies. Same drift guard as above: the schema's keys must be
// exactly the keys the serialisers in hardware_list_model.cpp emit.
TEST_CASE("REST hardware: the 200/202 bodies are typed in the OpenAPI spec and match the serialisers",
          "[rest][hardware]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());

    const auto ref_of = [&](const char* path, const char* verb, const char* status) {
        const auto& r = spec["paths"][path][verb]["responses"][status];
        REQUIRE(r.contains("content"));
        return r["content"]["application/json"]["schema"]["$ref"].get<std::string>();
    };
    CHECK(ref_of("/hardware", "get", "200") == "#/components/schemas/HardwareListPage");
    CHECK(ref_of("/hardware/{id}", "get", "200") == "#/components/schemas/HardwareRecordResponse");
    CHECK(ref_of("/hardware/{id}/sync", "post", "202") ==
          "#/components/schemas/HardwareSyncAccepted");

    const auto& schemas = spec["components"]["schemas"];
    const auto keys_of = [](const nlohmann::json& obj) {
        std::set<std::string> out;
        for (const auto& [k, v] : obj.items())
            out.insert(k);
        return out;
    };
    const auto required_of = [](const nlohmann::json& schema) {
        std::set<std::string> out;
        for (const auto& k : schema["required"])
            out.insert(k.get<std::string>());
        return out;
    };

    // List row.
    const auto row = keys_of(hardware_row_json(InventoryDeviceRow{}));
    REQUIRE(schemas.contains("HardwareListRow"));
    CHECK(keys_of(schemas["HardwareListRow"]["properties"]) == row);
    CHECK(required_of(schemas["HardwareListRow"]) == row);

    // List page: data keys, kpis keys, query keys.
    const auto page_json = hardware_list_json(HardwareListPage{}, false, 0, false);
    const auto& page = schemas["HardwareListPage"]["properties"]["data"];
    CHECK(keys_of(page["properties"]) == keys_of(page_json));
    CHECK(required_of(page) == keys_of(page_json));
    CHECK(keys_of(page["properties"]["kpis"]["properties"]) == keys_of(page_json["kpis"]));
    CHECK(keys_of(page["properties"]["query"]["properties"]) == keys_of(page_json["query"]));

    // Record: top-level keys and the ci object.
    HardwareCiDetail detail;
    detail.identity = InventoryDeviceRow{};
    detail.ci = std::optional<DeviceCiRecord>(DeviceCiRecord{});
    detail.software = std::vector<SoftwareEntry>{};
    detail.tags = std::vector<DeviceTag>{};
    const auto rec = hardware_ci_json(detail, 0);
    REQUIRE(schemas.contains("HardwareRecord"));
    CHECK(keys_of(schemas["HardwareRecord"]["properties"]) == keys_of(rec));
    CHECK(required_of(schemas["HardwareRecord"]) == keys_of(rec));
    REQUIRE(schemas.contains("HardwareCiRecord"));
    CHECK(keys_of(schemas["HardwareCiRecord"]["properties"]) == keys_of(rec["ci"]));
    CHECK(required_of(schemas["HardwareCiRecord"]) == keys_of(rec["ci"]));

    // The v2 sections (H.7): the section element's schema keys are exactly the keys a served
    // section carries, for every registered kind (status-only and list alike) and every level.
    REQUIRE(schemas.contains("HardwareCiSection"));
    HardwareCiDetail v2;
    v2.identity = InventoryDeviceRow{};
    v2.ci = std::optional<DeviceCiRecord>(DeviceCiRecord{});
    std::vector<std::string> kinds;
    for (const auto& def : kDeviceCiSections)
        kinds.emplace_back(def.section);
    std::vector<DeviceCiSection> all;
    for (const auto& k : kinds) {
        DeviceCiSection sec;
        sec.kind = k;
        sec.level = "constrained";
        sec.reason = "r";
        all.push_back(sec);
    }
    v2.ci_sections = all;
    const auto v2j = hardware_ci_json(v2, 0);
    REQUIRE(v2j["ci"]["sections"].size() == kDeviceCiSectionCount);
    for (const auto& served : v2j["ci"]["sections"]) {
        INFO(served["kind"].get<std::string>());
        CHECK(keys_of(schemas["HardwareCiSection"]["properties"]) == keys_of(served));
        CHECK(required_of(schemas["HardwareCiSection"]) == keys_of(served));
    }
    // `kind` is an OPEN string (the registry can grow, and a client must ignore kinds it does not
    // know), so the schema carries no enum; its description lists every registered kind and says so.
    const auto& kind_schema = schemas["HardwareCiSection"]["properties"]["kind"];
    CHECK_FALSE(kind_schema.contains("enum"));
    const auto kind_desc = kind_schema["description"].get<std::string>();
    for (const auto& k : kinds) {
        INFO(k);
        // whole-word match: `volume` must not pass because `volumes` appears, nor `disk` via `disks`
        const auto at = kind_desc.find(k);
        REQUIRE(at != std::string::npos);
        const auto after = at + k.size();
        CHECK((after >= kind_desc.size() || !(std::isalnum(static_cast<unsigned char>(kind_desc[after])) ||
                                              kind_desc[after] == '_')));
    }
    CHECK(kind_desc.find("must ignore kinds it does not know") != std::string::npos);
    // The other direction: every kind the description lists is registered (a kind removed from
    // the registry, or a typo, cannot linger in the documentation).
    {
        const std::string kmark = "Registered kinds today: ";
        const auto kat = kind_desc.find(kmark);
        REQUIRE(kat != std::string::npos);
        std::string list = kind_desc.substr(kat + kmark.size());
        list.resize(list.find('.')); // the kind list carries no '.', the next sentence starts at one
        std::set<std::string> listed;
        std::string_view rest = list;
        while (!rest.empty()) {
            const auto comma = rest.find(", ");
            listed.emplace(rest.substr(0, comma));
            if (comma == std::string_view::npos)
                break;
            rest.remove_prefix(comma + 2);
        }
        std::set<std::string> registered(kinds.begin(), kinds.end());
        CHECK(listed == registered);
    }
    // The rows description lists, per list kind, its exact column list in a parseable form -
    // `Columns: <kind>: <col>, <col>; <kind>: ...` - and the parse equals the registry in BOTH
    // directions: the same kinds and the same columns in the same order. A column added to,
    // removed from or renamed in the registry without the schema following fails here, and a
    // column name that merely appears in another kind's clause cannot satisfy it.
    const auto rows_desc =
        schemas["HardwareCiSection"]["properties"]["rows"]["items"]["description"].get<std::string>();
    const std::string marker = "Columns: ";
    const auto mk = rows_desc.find(marker);
    REQUIRE(mk != std::string::npos);
    std::string clauses = rows_desc.substr(mk + marker.size());
    if (const auto dot = clauses.find('.'); dot != std::string::npos)
        clauses.resize(dot); // the columns text carries no '.', the sentence after it starts at one
    std::map<std::string, std::vector<std::string>> documented;
    {
        std::string_view rest = clauses;
        while (!rest.empty()) {
            const auto semi = rest.find(';');
            std::string_view clause = rest.substr(0, semi);
            const auto colon = clause.find(": ");
            REQUIRE(colon != std::string_view::npos);
            const std::string kind{clause.substr(0, colon)};
            std::vector<std::string> cols;
            std::string_view list = clause.substr(colon + 2);
            while (!list.empty()) {
                const auto comma = list.find(", ");
                cols.emplace_back(list.substr(0, comma));
                if (comma == std::string_view::npos)
                    break;
                list.remove_prefix(comma + 2);
            }
            const bool first_clause_for_kind = documented.emplace(kind, std::move(cols)).second;
            CHECK(first_clause_for_kind); // each kind once
            if (semi == std::string_view::npos)
                break;
            rest.remove_prefix(semi + 1);
            while (!rest.empty() && rest.front() == ' ')
                rest.remove_prefix(1);
        }
    }
    std::map<std::string, std::vector<std::string>> registry;
    for (const auto& def : kDeviceCiSections) {
        if (def.table == nullptr)
            continue;
        std::vector<std::string> cols;
        std::string_view list = def.columns;
        while (!list.empty()) {
            const auto comma = list.find(',');
            cols.emplace_back(list.substr(0, comma));
            if (comma == std::string_view::npos)
                break;
            list.remove_prefix(comma + 1);
        }
        registry.emplace(def.section, std::move(cols));
    }
    REQUIRE_FALSE(registry.empty());
    CHECK(documented == registry);
    // sections and its state are the nullable / enumerated members the description promises.
    CHECK(schemas["HardwareCiRecord"]["properties"]["sections"]["nullable"] == true);
    CHECK(schemas["HardwareRecord"]["properties"]["sections_state"]["enum"] ==
          nlohmann::json::array({"found", "absent", "degraded"}));

    // The route documents the sections 503.
    const auto& r503 = spec["paths"]["/hardware/{id}"]["get"]["responses"]["503"]["description"];
    CHECK(r503.get<std::string>().find("sections could not be read") != std::string::npos);
}

// The per-group guides are for people reading /swagger. The default document, and so the MCP resource
// yuzu://openapi and the discover tools that serve the same string, leaves them out.
TEST_CASE("REST openapi.json: guides are opt-in; the default document is the lean form",
          "[rest][openapi]") {
    InvHarness h{/*store=*/nullptr};

    auto lean = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(lean);
    REQUIRE(lean->status == 200);
    CHECK(lean->body == openapi_spec_json());
    auto lean_doc = nlohmann::json::parse(lean->body, nullptr, false);
    REQUIRE_FALSE(lean_doc.is_discarded());
    REQUIRE(lean_doc["tags"].is_array());
    CHECK_FALSE(lean_doc["tags"].empty());
    for (const auto& t : lean_doc["tags"]) {
        CHECK(t.contains("name"));
        CHECK(t.contains("description")); // the one-line summary stays
        CHECK_FALSE(t.contains("x-yuzu-guide"));
    }

    for (const char* q : {"/api/v1/openapi.json?guides=true", "/api/v1/openapi.json?guides=1"}) {
        INFO(q);
        auto full = h.sink.Get(q);
        REQUIRE(full);
        REQUIRE(full->status == 200);
        CHECK(full->body == openapi_spec_with_guides_json());
        auto doc = nlohmann::json::parse(full->body, nullptr, false);
        REQUIRE_FALSE(doc.is_discarded());
        for (const auto& t : doc["tags"])
            CHECK(t.contains("x-yuzu-guide"));
        CHECK(full->body.size() > lean->body.size());
    }

    // Anything else is the default.
    auto other = h.sink.Get("/api/v1/openapi.json?guides=no");
    REQUIRE(other);
    CHECK(other->body == lean->body);

    // Lean and full describe the same operations.
    auto full_doc = nlohmann::json::parse(h.sink.Get("/api/v1/openapi.json?guides=true")->body);
    CHECK(full_doc["paths"] == lean_doc["paths"]);
    CHECK(full_doc["components"] == lean_doc["components"]);
}

// ── Live-PG branches ─────────────────────────────────────────────────────────

namespace {
// A confined scope WIDER than the SQL push-down bound (software_catalogue::kScopePushdownMaxIds),
// so the route takes the in-process post-filter arm. `keep` are the agents it admits.
std::unordered_set<std::string> wide_scope(std::initializer_list<std::string> keep) {
    std::unordered_set<std::string> ids;
    for (std::size_t i = 0; i <= software_catalogue::kScopePushdownMaxIds; ++i)
        ids.insert("pad-" + std::to_string(i));
    ids.insert(keep);
    return ids;
}

// Seed one agent's machine-scope software via the store's own ingest path.
void seed(SoftwareInventoryStore& store, const std::string& agent,
          std::vector<SoftwareEntry> rows) {
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software(agent, h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
}
} // namespace

TEST_CASE("REST inventory/software: fleet read returns rows, count, devices_omitted=0",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", "2026-01-01"},
                          {"Firefox", "120", "Mozilla", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 2);
    CHECK(data.at("devices_omitted").get<int>() == 0);
    CHECK(data.at("software").size() == 2);
    CHECK_FALSE(data.contains("result_truncated_by_cap"));
    CHECK(h.has_audit("success"));
    CHECK_FALSE(h.has_audit("denied"));
}

TEST_CASE("REST inventory/software: rows carry the blob-v2 package fields",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    SoftwareEntry rpm;
    rpm.name = "bash";
    rpm.version = "5.2.21";
    rpm.publisher = "Fedora Project";
    rpm.install_date = "Mon 01 Jan 2026";
    rpm.kind = "package";
    rpm.ecosystem = "rpm";
    rpm.epoch = "0";
    rpm.release = "3.fc40";
    rpm.arch = "x86_64";
    rpm.signature_status = "signed";
    rpm.distro_id = "fedora";
    rpm.distro_version = "40";
    // A v1-shaped row (only the 4 legacy fields) beside it: the v2 keys must
    // still be present in the JSON, as empty strings (honest-empty contract).
    seed(store, "dev-v2", {rpm, {"Google Chrome", "126", "Google", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=bash");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 1);
    const auto& row = sw.at(0);
    CHECK(row.at("kind").get<std::string>() == "package");
    CHECK(row.at("ecosystem").get<std::string>() == "rpm");
    CHECK(row.at("epoch").get<std::string>() == "0");
    CHECK(row.at("release").get<std::string>() == "3.fc40");
    CHECK(row.at("arch").get<std::string>() == "x86_64");
    CHECK(row.at("signature_status").get<std::string>() == "signed");
    CHECK(row.at("distro_id").get<std::string>() == "fedora");
    CHECK(row.at("distro_version").get<std::string>() == "40");

    auto res2 = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res2);
    auto body2 = nlohmann::json::parse(res2->body);
    const auto& row2 = body2.at("data").at("software").at(0);
    CHECK(row2.at("kind").get<std::string>().empty());
    CHECK(row2.at("ecosystem").get<std::string>().empty());
    CHECK(row2.at("signature_status").get<std::string>().empty());
    CHECK(row2.at("distro_version").get<std::string>().empty());
}

TEST_CASE("REST inventory/software: name filter narrows the fleet result",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}, {"Slack", "4.0", "Slack", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 2); // one per agent, both Chrome
    for (const auto& row : sw)
        CHECK(row.at("name").get<std::string>() == "Google Chrome");
}

TEST_CASE("REST inventory/software: a scope wider than the push-down bound post-filters; "
          "reports devices_omitted and audits denied",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    h.fleet_scope = wide_scope({"dev-a"});

    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto data = nlohmann::json::parse(res->body).at("data");
    REQUIRE(data.at("software").size() == 1);
    CHECK(data.at("software")[0].at("agent_id").get<std::string>() == "dev-a");
    CHECK(data.at("devices_omitted").get<int>() == 1);
    CHECK(h.has_audit("denied"));
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: limit cap flags result_truncated_by_cap",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"AAA", "1", "", ""}, {"BBB", "1", "", ""}, {"CCC", "1", "", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 1);
    CHECK(data.at("result_truncated_by_cap").get<bool>() == true);
}

TEST_CASE("REST inventory/software: non-integer limit → 400", "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
    // #4644: a numeric prefix is not an integer (`100abc` was read as 100).
    for (const char* bad : {"limit=100abc", "limit=1e3", "limit=0x10"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/v1/inventory/software?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
    }
}

TEST_CASE("REST inventory/software: ?agent_id= narrows to one device",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});
    seed(store, "dev-b", {{"Zoom", "5.0", "Zoom", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?agent_id=dev-a");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 1);
    CHECK(sw[0].at("agent_id").get<std::string>() == "dev-a");
    CHECK(sw[0].at("name").get<std::string>() == "Slack");
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: over-max limit clamps (no error, no cap defeat)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"AAA", "1", "", ""}, {"BBB", "1", "", ""}, {"CCC", "1", "", ""}});

    InvHarness h{&store};
    // limit=5000 > 1000 cap: must clamp (200, all rows), NOT error, NOT bind 5000. The
    // lower bind is proven by the limit=1 truncation test; both share the same
    // std::clamp<int64_t>(want,1,1000) call, so this guards the upper bound + the
    // "negative/wrapped value defeats the cap" hazard.
    auto res = h.sink.Get("/api/v1/inventory/software?limit=5000");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("count").get<int>() == 3);
    CHECK_FALSE(body.at("data").contains("result_truncated_by_cap"));

    // The FLOOR arm of the clamp (gov Gate-8 N1): a negative/zero limit must NOT bind
    // `LIMIT -1` (unbounded in Postgres — the exact cap-defeat the int64 clamp guards).
    // Both clamp to 1 → exactly one row, no error.
    for (const char* q : {"limit=-1", "limit=0"}) {
        auto r = h.sink.Get(std::string("/api/v1/inventory/software?") + q);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(nlohmann::json::parse(r->body).at("data").at("count").get<int>() == 1);
    }
}

TEST_CASE("REST inventory/software: failed audit surfaces audit_persisted:false (set-and-proceed)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});

    InvHarness h{&store};
    h.audit_ok = false; // audit_fn reports a persistence failure
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    // Set-and-proceed: data STILL served (machine-scope, non-behavioural), but the body
    // honestly flags the lost evidence row — never withheld (distinct from the fail-closed
    // per-device behavioural routes).
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.at("data").at("software").size() == 1);
    CHECK(body.at("data").at("audit_persisted").get<bool>() == false);
}

TEST_CASE("REST inventory/software: store degrade → 503 + failure audit, never empty",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    // size-1 pool: after the ctor migration releases its lease, the single connection
    // is free. We hold it for the duration of the request, so query_software's
    // try_acquire_for(kQueryAcquireTimeout) times out → std::nullopt → the route's
    // DEGRADE branch (distinct from null-store: it audits "failure"). This is the
    // authoritative-read contract (ADR-0016 §7) that drew a BLOCKING last round.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire(); // starve the pool — the only connection is now ours
    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 503);
    // NEVER a success-with-empty-list — structural assert: an A4 error envelope, no `data`.
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    // The degrade path is distinct from null-store precisely in this audit emission.
    CHECK(h.has_audit("failure"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: throwing audit_fn does not 500 (throw-safe set-and-proceed)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});

    InvHarness h{&store};
    h.audit_throws = true; // audit sink throws (bad_alloc-class / locked audit DB)
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    // The throw is caught by detail::try_persist_audit → returns false → the route STILL
    // serves 200 with audit_persisted:false, NEVER a 500 with no trail (gov chaos CH-3 —
    // throw-safety parity with the MCP sibling's mcp_audit, which wraps the same kernel).
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.at("data").at("software").size() == 1);
    CHECK(body.at("data").at("audit_persisted").get<bool>() == false);
}

// ═══════════════════════════════════════════════════════════════════════════
// [pg] end-to-end confinement — a REAL AuthRoutes::require_fleet_read, not
// InvHarness's fake gate above. Proves the actual meet(management-group,
// service-scope) composition this route exists to serve (#3290), against a
// real RbacStore/TagStore/ManagementGroupStore — coverage that exists
// NOWHERE else at the route level (test_authz_gates.cpp proves the
// primitive in isolation; this proves the ROUTE wires it correctly end to
// end, including the store query + JSON shape).
// ═══════════════════════════════════════════════════════════════════════════

namespace {

yuzu::test::PgTestTemplate inv_e2e_tpl{
    "rbacstore_inv_e2e", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        RbacStore rbac{pool};
        if (!rbac.is_open())
            throw std::runtime_error("inv e2e template: rbac store failed to migrate/seed");
        TagStore tags{pool};
        if (!tags.is_open())
            throw std::runtime_error("inv e2e template: tag store failed to migrate");
        SoftwareInventoryStore sw{pool};
        if (!sw.is_open())
            throw std::runtime_error("inv e2e template: software inventory store failed to migrate");
    }};

// Real end-to-end rig: RbacStorePg + ManagementGroupStorePg + ApiTokenStorePg
// + TagStore + SoftwareInventoryStore, all sharing one clone, wired into a
// real AuthRoutes + RestApiV1 exactly as server.cpp wires them (the
// fleet_read_fn lambda below is the SAME conversion ServerImpl::
// require_fleet_read performs). Management-group tree mirrors
// test_authz_gates.cpp's GatesRig:
//   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
//      └─ C2
// service "printers" == {a_p, a_c1, a_s}; a_c2 is mgmt-scoped but untagged.
struct InvE2ERig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    TagStore tags;
    SoftwareInventoryStore sw;
    // Real AuditStore (shares the rig's database via a second pool, its own
    // `audit_store` schema — same pattern as GatesRig in test_authz_gates.cpp)
    // so a gate-deny's audit_log call is regression-testable, not silently
    // discarded by a null store (quality-engineer, governance run 2026-08-20).
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    // Declared AFTER its route owner (`api`) per the fixture convention this
    // file's own test_route_sink_harness.cpp pins: the sink holds the
    // registered handler closures, so it must destruct BEFORE the owner
    // whose `this` those handlers might capture (cpp-safety, governance run
    // 2026-08-20 — non-exploitable today since RestApiV1::register_routes
    // never captures `this`, but the declaration order should not rely on
    // that staying true).
    yuzu::server::test::TestRouteSink sink;
    std::string gP, gC1, gC2, gS;

    explicit InvE2ERig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, tags{pool}, sw{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(sw.is_open());
        REQUIRE(audit_store.is_open());
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"InvReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"InvReader", "Inventory", "Read", "allow"}).has_value());

        gP = make_group("P", "");
        gC1 = make_group("C1", gP);
        gC2 = make_group("C2", gP);
        gS = make_group("S", "");

        REQUIRE(mgmt.add_member(gP, "a_p").has_value());
        REQUIRE(mgmt.add_member(gC1, "a_c1").has_value());
        REQUIRE(mgmt.add_member(gC2, "a_c2").has_value());
        REQUIRE(mgmt.add_member(gS, "a_s").has_value());

        REQUIRE(tags.set_tag("a_p", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_c1", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_s", "service", "printers").has_value());
        // a_c2 deliberately untagged: inside mgmt scope, outside service scope.

        REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                          &audit_store, &mgmt, &tags,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

        // The SAME conversion ServerImpl::require_fleet_read performs
        // (server.cpp) — production wires REST/MCP through this identical
        // shape, so a drift here would be a drift in production too.
        RestApiV1::FleetReadFn fleet_read_fn =
            [this](const httplib::Request& req, httplib::Response& res, const std::string& type,
                  const std::string& op) -> authz::FleetReadGate {
            auto r = ar->require_fleet_read(req, res, type, op);
            if (!r)
                return {};
            return {true, r->visible_for_query()};
        };
        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response& res) -> std::optional<auth::Session> {
            return ar->require_auth(req, res);
        };
        auto perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            return ar->require_permission(req, res, type, op);
        };

        api.register_routes(sink, auth_fn, perm_fn, /*audit_fn=*/{},
                            /*rbac_store=*/&rbac, /*mgmt_store=*/&mgmt,
                            /*token_store=*/api_tokens.get(), /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/&tags,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, &sw,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{}, std::move(fleet_read_fn));
    }

    std::string make_group(const std::string& name, const std::string& parent) {
        ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.parent_id = parent;
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }

    void group_assign(const std::string& group, const std::string& user, const std::string& role) {
        REQUIRE(mgmt.assign_role({group, "user", user, role}).has_value());
    }

    /// Mint a token as "minter" — scope_service empty ⇒ a non-service token.
    std::string mint(const std::string& scope_service = {}) {
        auto raw =
            api_tokens->create_token("inv-e2e", "minter", now_epoch() + 3600, scope_service);
        REQUIRE(raw.has_value());
        return *raw;
    }

    void seed_one(const std::string& agent) {
        std::vector<SoftwareEntry> rows{{"Chrome", "119", "Google", ""}};
        REQUIRE(sw.apply_installed_software(agent, SoftwareInventoryStore::canonical_hash(rows),
                                            rows, 1000) == InventoryIngestOutcome::kStored);
    }
};

std::unordered_map<std::string, std::string> bearer(const std::string& token) {
    return {{"Authorization", "Bearer " + token}};
}

} // namespace

TEST_CASE("REST inventory/software [e2e]: service-scoped token gets a real filtered "
          "200 — never the old blanket 403",
          "[pg][rest][inventory_software][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_c1");
    r.seed_one("a_s");
    r.seed_one("a_c2"); // in mgmt scope, outside service scope — must be dropped

    // require_fleet_read's mgmt-group axis is evaluated for EVERY caller,
    // service-scoped or not (unlike require_permission's separate
    // ITServiceOwner-only service branch) — a DenyAll mgmt axis short-
    // circuits to Forbidden before the service axis is even consulted
    // (test_authz_gates.cpp's "Deny × service S" case). So the minting
    // identity needs its own global grant; the service axis then narrows
    // it further via meet() (the "never unfiltered despite the global
    // grant" CDX-001 property).
    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value()); // GLOBAL allow
    auto token = r.mint("printers");
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    std::unordered_set<std::string> seen;
    for (const auto& row : sw)
        seen.insert(row.at("agent_id").get<std::string>());
    CHECK(seen == std::unordered_set<std::string>{"a_p", "a_c1", "a_s"});
    CHECK(body.at("data").at("devices_omitted").get<int>() == 0); // pushed into SQL: a_c2 never scanned
}

TEST_CASE("REST inventory/software [e2e]: management-group-confined operator gets a "
          "real filtered 200 (ADR-0017 World A gap closed for this route)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_c1");
    r.seed_one("a_c2");
    r.seed_one("a_s"); // outside P's subtree — must be dropped

    r.group_assign(r.gP, "minter", "InvReader"); // group-scoped grant, no global grant
    auto token = r.mint(); // non-service
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    std::unordered_set<std::string> seen;
    for (const auto& row : sw)
        seen.insert(row.at("agent_id").get<std::string>());
    CHECK(seen == std::unordered_set<std::string>{"a_p", "a_c1", "a_c2"}); // INV-4 descendant expansion
    CHECK(body.at("data").at("devices_omitted").get<int>() == 0); // pushed into SQL: a_s never scanned
}

TEST_CASE("REST inventory/software [e2e]: unscoped operator (global grant) sees the "
          "whole fleet unchanged",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_s");

    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value()); // GLOBAL allow
    auto token = r.mint(); // non-service
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("software").size() == 2);
    CHECK(body.at("data").at("devices_omitted").get<int>() == 0);
}

TEST_CASE("REST inventory/software [e2e]: tag-store degraded on a service token ⇒ 503",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value());
    auto token = r.mint("printers");

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult res{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(res.ok());
    }

    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST inventory/software [e2e]: service-scoped token, RBAC genuinely "
          "disabled ⇒ 403 (never let the tag axis alone admit a narrowed result)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.rbac.set_rbac_enabled(false);
    auto token = r.mint("printers");
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST inventory/software [e2e]: a genuine gate deny gets exactly one "
          "X-Correlation-Id header and audits under the gate's own taxonomy, "
          "not the retired route-specific fleet target",
          "[pg][rest][inventory_software]") {
    // Restores the class of coverage quality-engineer flagged as dropped
    // (governance run 2026-08-20) — but for the CURRENT taxonomy, not the
    // pre-#3290 one: the old blanket-deny path (deny_fleet_wide_service_
    // scoped) audited as inventory.software.query/target_id=fleet with a
    // cid embedded in its detail string; require_fleet_read's own deny
    // branches audit as auth.fleet_read_required with EMPTY target_type/
    // target_id (matching require_permission's/require_list_read's
    // convention, authdb-confirmed Gate 3) and do not embed a cid in the
    // audit detail at all — a4_denial mints its own cid for the header
    // independently. Asserting the old cid-embedded-in-detail shape here
    // would pin a property this gate's convention does not provide, not a
    // regression; this test proves the property that DOES hold instead.
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    // "minter" holds no Inventory:Read grant at all ⇒ authorize_list_read
    // DenyAll ⇒ require_fleet_read's own 403 branch.
    auto token = r.mint();
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 403);

    // Exactly one value, not duplicated (the httplib multimap-append class
    // of bug: set_header appends rather than overwrites if called twice).
    auto cids = res->get_header_value_count("X-Correlation-Id");
    CHECK(cids == 1);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& row = (*rows)[0];
    CHECK(row.action == "auth.fleet_read_required");
    CHECK(row.result == "denied");
    CHECK(row.target_type.empty());
    CHECK(row.target_id.empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// M.9 PR-2: version filter, source, keyset cursor, push-down completeness, export
// ═══════════════════════════════════════════════════════════════════════════

namespace {

std::size_t count_audit(const InvHarness& h, const std::string& action, const std::string& result,
                        const std::string& needle = {}) {
    std::size_t n = 0;
    for (const auto& a : h.audit_log)
        if (a.action == action && a.result == result &&
            (needle.empty() || a.detail.find(needle) != std::string::npos))
            ++n;
    return n;
}

} // namespace

TEST_CASE("REST inventory/software: ?version= selects an exact version; present-empty selects the "
          "empty bucket",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"App", "1.0", "", ""}, {"Bare", "", "", ""}});
    seed(store, "dev-b", {{"App", "2.0", "", ""}});

    InvHarness h{&store};
    auto exact = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?version=2.0")->body);
    REQUIRE(exact.at("data").at("software").size() == 1);
    CHECK(exact.at("data").at("software")[0].at("agent_id") == "dev-b");
    auto empty = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?version=")->body);
    REQUIRE(empty.at("data").at("software").size() == 1);
    CHECK(empty.at("data").at("software")[0].at("name") == "Bare");
    auto any = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software")->body);
    CHECK(any.at("data").at("software").size() == 3);
}

TEST_CASE("REST inventory/software: keyset walk pages without duplicates or gaps; and every page "
          "is audited",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}, {"B", "1", "", ""}, {"C", "1", "", ""}});
    seed(store, "dev-b", {{"A", "1", "", ""}, {"B", "1", "", ""}});

    InvHarness h{&store};
    std::vector<std::string> seen;
    std::string cursor;
    int pages = 0;
    for (;;) {
        std::string url = "/api/v1/inventory/software?limit=2";
        if (!cursor.empty())
            url += "&cursor=" + cursor;
        auto res = h.sink.Get(url);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        const auto data = nlohmann::json::parse(res->body).at("data");
        REQUIRE(data.at("software").size() <= 2);
        for (const auto& r : data.at("software"))
            seen.push_back(r.at("agent_id").get<std::string>() + "/" + r.at("name").get<std::string>());
        ++pages;
        if (data.at("next_cursor").is_null())
            break;
        cursor = data.at("next_cursor").get<std::string>();
        REQUIRE(pages < 10);
    }
    CHECK(seen.size() == 5);
    CHECK(std::set<std::string>(seen.begin(), seen.end()).size() == 5); // no duplicates
    CHECK(pages == 3);
    // success on EVERY call; continuation pages tagged
    CHECK(count_audit(h, "inventory.software.query", "success") == 3);
    CHECK(count_audit(h, "inventory.software.query", "success", "page=continuation") == 2);
}

TEST_CASE("REST inventory/software: cursor refusals — tampered; wrong filter set; forged head "
          "cursor works but is audited",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}, {"B", "1", "", ""}, {"C", "1", "", ""}});

    InvHarness h{&store};
    const auto first = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?limit=1")->body);
    const auto cursor = first.at("data").at("next_cursor").get<std::string>();

    CHECK(h.sink.Get("/api/v1/inventory/software?limit=1&cursor=" + cursor + "!")->status == 400);
    CHECK(h.sink.Get("/api/v1/inventory/software?limit=1&cursor=garbage")->status == 400);
    auto wrong = h.sink.Get("/api/v1/inventory/software?limit=1&name=A&cursor=" + cursor);
    REQUIRE(wrong);
    CHECK(wrong->status == 400);
    CHECK(wrong->body.find("different filter set") != std::string::npos);

    // the version VALUE is part of the binding, not only its presence
    const auto versioned =
        nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?limit=1&version=1")->body);
    const auto vcursor = versioned.at("data").at("next_cursor").get<std::string>();
    CHECK(h.sink.Get("/api/v1/inventory/software?limit=1&version=1&cursor=" + vcursor)->status ==
          200);
    CHECK(h.sink.Get("/api/v1/inventory/software?limit=1&version=2&cursor=" + vcursor)->status ==
          400);

    // A hand-made head cursor (name "", agent "", id 0) over the unfiltered query is accepted by
    // design — opaque is not authenticated — so the audit row is what keeps it from being silent.
    const auto fp = software_catalogue::devices_fingerprint(SoftwareFleetQuery{});
    const auto before = count_audit(h, "inventory.software.query", "success", "page=continuation");
    auto forged = h.sink.Get("/api/v1/inventory/software?limit=1&cursor=" +
                             software_catalogue::encode_devices_cursor({}, fp));
    REQUIRE(forged);
    CHECK(forged->status == 200);
    CHECK(nlohmann::json::parse(forged->body).at("data").at("software")[0].at("name") == "A");
    CHECK(count_audit(h, "inventory.software.query", "success", "page=continuation") == before + 1);
}

TEST_CASE("REST inventory/software: push-down returns COMPLETE pages of the caller's own scope",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // Five agents; the two in scope sort AFTER three out-of-scope agents, so a post-filter over a
    // limit-2 scan would return an empty page. Push-down returns the full 2.
    for (const char* a : {"a1", "a2", "a3", "z1", "z2"})
        seed(store, a, {{"Common", "1", "", ""}});

    InvHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"z1", "z2"};
    const auto data = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?limit=2")->body).at("data");
    CHECK(data.at("software").size() == 2);
    std::vector<std::string> ids; // exactly the caller's own two, not merely "two rows"
    for (const auto& r : data.at("software"))
        ids.push_back(r.at("agent_id").get<std::string>());
    std::ranges::sort(ids);
    CHECK(ids == std::vector<std::string>{"z1", "z2"});
    CHECK(data.at("devices_omitted") == 0);
    CHECK_FALSE(h.has_audit("denied"));

    // Engaged-empty scope: deny-all -> 200, empty, nothing omitted, no oracle.
    InvHarness none{&store};
    none.fleet_scope = std::unordered_set<std::string>{};
    const auto empty = nlohmann::json::parse(none.sink.Get("/api/v1/inventory/software")->body).at("data");
    CHECK(empty.at("software").empty());
    CHECK(empty.at("devices_omitted") == 0);
}

TEST_CASE("REST inventory/software: text a store cannot bind is a 400; never a retryable 503",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}});

    InvHarness h{&store};
    // A hand-minted cursor whose decoded agent id is not valid UTF-8 (well-formed otherwise, over
    // the matching fingerprint), so only the decoded-text refusal can answer 400.
    const auto fp = software_catalogue::devices_fingerprint(SoftwareFleetQuery{});
    const std::string forged = software_catalogue::encode_devices_cursor(
        {SoftwareCursor{"A", "\xFF", 1}, 0}, fp);
    // The handler has two 400 mappings (parameter parse and cursor decode); the model tests loop
    // every key and bound, so one query per mapping proves 400-not-503 here.
    for (const std::string& query : std::vector<std::string>{"agent_id=%FF", "cursor=" + forged}) {
        CAPTURE(query);
        auto r = h.sink.Get("/api/v1/inventory/software?" + query);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(nlohmann::json::parse(r->body).at("error").at("retry_after_ms").is_null());
    }
    CHECK(count_audit(h, "inventory.software.query", "failure") == 0);
    CHECK(count_audit(h, "inventory.software.query", "success") == 0);
}

TEST_CASE("REST inventory/software: exports — csv; truncation; json; bad format; audit verb",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}, {"B", "1", "", ""}, {"C", "1", "", ""}});
    // seed() never refreshes the catalogue rollup (refreshed_at 0, the building state): the raw
    // route never reads it, so every export below is served at that state, not blocked or emptied.
    const auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    REQUIRE(meta->refreshed_at == 0);

    InvHarness h{&store};
    auto csv = h.sink.Get("/api/v1/inventory/software?format=csv");
    REQUIRE(csv);
    CHECK(csv->status == 200);
    CHECK(csv->get_header_value("Content-Type").find("text/csv") == 0);
    CHECK(csv->get_header_value("Content-Disposition").find("software-installs.csv") != std::string::npos);
    CHECK(csv->body.starts_with(std::string(software_list::kListCsvHeader) + "\n")); // 22 columns
    CHECK(csv->get_header_value("X-Result-Truncated-By-Cap").empty());

    // An uncapped export carries neither the continuation header nor the trailer.
    CHECK(csv->get_header_value("X-Next-Cursor").empty());
    CHECK(csv->body.find("# result_truncated_by_cap") == std::string::npos);

    auto cut = h.sink.Get("/api/v1/inventory/software?format=csv&limit=2");
    REQUIRE(cut);
    CHECK(cut->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(std::ranges::count(cut->body, '\n') == 4); // header + 2 rows + the trailer record
    CHECK(cut->body.ends_with("# result_truncated_by_cap cause=row_cap" +
                              std::string(software_list::kListCsvColumns - 1, ',') +
                              "\r\n"));
    // The continuation is in X-Next-Cursor: feeding it back reads on, with no overlap.
    const auto next_cursor = cut->get_header_value("X-Next-Cursor");
    REQUIRE_FALSE(next_cursor.empty());
    auto page2 = h.sink.Get("/api/v1/inventory/software?format=csv&limit=2&cursor=" + next_cursor);
    REQUIRE(page2);
    CHECK(page2->status == 200);
    CHECK(page2->body.find("dev-a,C,") != std::string::npos);
    CHECK(page2->body.find("dev-a,A,") == std::string::npos);
    CHECK(page2->body.find("dev-a,B,") == std::string::npos);
    CHECK(page2->get_header_value("X-Next-Cursor").empty()); // short page: the end
    CHECK(page2->body.find("# result_truncated_by_cap") == std::string::npos);

    auto json = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?format=json&limit=2")->body);
    CHECK(json.at("data").at("result_truncated_by_cap") == true);

    CHECK(h.sink.Get("/api/v1/inventory/software?format=xml")->status == 400);
    CHECK(count_audit(h, "inventory.software.export", "success") == 4);
    CHECK(count_audit(h, "inventory.software.export", "success", "truncated=true") == 2);

    // A dropped audit row is flagged on the csv (a body-less channel for the honesty flag);
    // the export is still served.
    CHECK(csv->get_header_value("Sec-Audit-Failed").empty());
    h.audit_ok = false;
    auto unaudited = h.sink.Get("/api/v1/inventory/software?format=csv");
    REQUIRE(unaudited);
    CHECK(unaudited->status == 200);
    CHECK(unaudited->get_header_value("Sec-Audit-Failed") == "true");
}

namespace {

// The keyset position inside a minted cursor, decoded by the model's own codec (default filters).
software_catalogue::DevicesCursor decode_cursor(const std::string& token) {
    auto cur = software_catalogue::decode_devices_cursor(
        token, software_catalogue::devices_fingerprint(SoftwareFleetQuery{}));
    REQUIRE(cur);
    return *cur;
}

// dev-a (in scope) sorts first, then six out-of-scope devices whose software has a name and a
// version no served row has, so any dropped-row byte in a response or token is detectable.
void seed_wide_fixture(SoftwareInventoryStore& store) {
    seed(store, "dev-a", {{"Common", "1", "", ""}});
    for (const char* a : {"dev-b", "dev-c", "dev-d", "dev-e", "dev-f", "dev-g"})
        seed(store, a, {{"Common-dropped", "9.9", "", ""}});
}

bool leaks_dropped(const std::string& text) {
    return text.find("Common-dropped") != std::string::npos || text.find("9.9") != std::string::npos;
}

} // namespace

TEST_CASE("REST inventory/software: a wide-scope cursor never names an out-of-scope device",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_wide_fixture(store);

    InvHarness h{&store};
    h.fleet_scope = wide_scope({"dev-a"});

    auto first = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?limit=1")->body).at("data");
    REQUIRE(first.at("software").size() == 1);
    CHECK(first.at("software")[0].at("agent_id") == "dev-a");
    const auto c1 = decode_cursor(first.at("next_cursor").get<std::string>());
    CHECK(c1.after.name == "Common");
    CHECK(c1.after.agent_id == "dev-a");
    CHECK(c1.skip == 0);

    // Page 2 scans four dropped rows (one per bounded read) and finds nothing in scope: an EMPTY
    // page that still continues, anchored where the caller already is, never at a dropped row.
    auto second = nlohmann::json::parse(
        h.sink.Get("/api/v1/inventory/software?limit=1&cursor=" + first.at("next_cursor").get<std::string>())
            ->body).at("data");
    CHECK(second.at("software").empty());
    CHECK(second.at("devices_omitted") == software_catalogue::kWideScopeMaxReads);
    CHECK(second.at("result_truncated_by_cap") == true);
    REQUIRE(second.at("next_cursor").is_string());
    const auto c2 = decode_cursor(second.at("next_cursor").get<std::string>());
    CHECK(c2.after.name == "Common"); // the served row's name, not the last scanned row's
    CHECK(c2.after.agent_id == "dev-a");
    CHECK(c2.after.install_id == c1.after.install_id);
    CHECK(c2.skip == software_catalogue::kWideScopeMaxReads);
    CHECK(second.dump().find("dev-b") == std::string::npos); // nothing out of scope is echoed
    CHECK_FALSE(leaks_dropped(second.dump()));

    // The continuation passes the skipped rows in SQL and reaches the end: 7 - 1 - 4 = 2 left.
    auto third = nlohmann::json::parse(
        h.sink.Get("/api/v1/inventory/software?limit=1&cursor=" + second.at("next_cursor").get<std::string>())
            ->body).at("data");
    CHECK(third.at("software").empty());
    CHECK(third.at("next_cursor").is_null());
    CHECK(third.at("devices_omitted") == 2);

    // A wide-scope csv page that read four windows and found nothing in scope still says it was
    // cut: capped header, continuation header and the trailer, with no data row.
    auto csv = h.sink.Get("/api/v1/inventory/software?format=csv&limit=1&cursor=" +
                          first.at("next_cursor").get<std::string>());
    REQUIRE(csv);
    CHECK(csv->status == 200);
    CHECK(csv->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(decode_cursor(csv->get_header_value("X-Next-Cursor")).skip ==
          software_catalogue::kWideScopeMaxReads);
    CHECK(std::ranges::count(csv->body, '\n') == 2); // header + the trailer record
    CHECK(csv->body.find("dev-b") == std::string::npos);
    CHECK_FALSE(leaks_dropped(csv->body));
    for (const auto& [name, value] : csv->headers)
        CHECK_FALSE(leaks_dropped(name + ": " + value));
    for (const auto& a : h.audit_log)
        CHECK_FALSE(leaks_dropped(a.target_id + a.detail));
}

TEST_CASE("REST inventory/software: an explicit out-of-scope agent_id is audited as one denied row",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}});
    seed(store, "dev-z", {{"A", "1", "", ""}});

    InvHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-a"}; // push-down: nothing is "omitted"

    auto res = h.sink.Get("/api/v1/inventory/software?agent_id=dev-z");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto data = nlohmann::json::parse(res->body).at("data");
    CHECK(data.at("software").empty());
    CHECK(data.at("devices_omitted") == 0); // the response bytes are unchanged
    CHECK_FALSE(data.contains("audit_persisted"));
    CHECK(count_audit(h, "inventory.software.query", "denied", "agent_id outside the caller's scope") == 1);
    CHECK(count_audit(h, "inventory.software.query", "success") == 1);

    // exports write the same one denied row, under the export verb, whatever the format
    auto csv = h.sink.Get("/api/v1/inventory/software?agent_id=dev-z&format=csv");
    REQUIRE(csv);
    CHECK(csv->get_header_value("Sec-Audit-Failed").empty());
    auto json = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?agent_id=dev-z&format=json")->body);
    CHECK_FALSE(json.at("data").contains("audit_persisted"));
    CHECK(count_audit(h, "inventory.software.export", "denied", "agent_id outside the caller's scope") == 2);
    CHECK(count_audit(h, "inventory.software.query", "denied") == 1);

    // an in-scope agent_id, or none, writes no denied row
    CHECK(h.sink.Get("/api/v1/inventory/software?agent_id=dev-a")->status == 200);
    CHECK(h.sink.Get("/api/v1/inventory/software")->status == 200);
    CHECK(count_audit(h, "inventory.software.query", "denied") == 1);

    // the denied row's own persistence failure alone reaches the honesty flags
    h.audit_fail_result = "denied";
    auto flagged = nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?agent_id=dev-z")->body);
    CHECK(flagged.at("data").at("audit_persisted") == false);
    auto flagged_csv = h.sink.Get("/api/v1/inventory/software?agent_id=dev-z&format=csv");
    REQUIRE(flagged_csv);
    CHECK(flagged_csv->get_header_value("Sec-Audit-Failed") == "true");
    // ...and a read that wrote no denied row is not flagged by a failing denied sink
    CHECK_FALSE(nlohmann::json::parse(h.sink.Get("/api/v1/inventory/software?agent_id=dev-a")->body)
                    .at("data").contains("audit_persisted"));

    // over a wide scope the filtered-N wording wins and there is still exactly one row
    InvHarness wide{&store};
    wide.fleet_scope = wide_scope({"dev-a"});
    CHECK(wide.sink.Get("/api/v1/inventory/software?name=A")->status == 200);
    CHECK(count_audit(wide, "inventory.software.query", "denied", "filtered 1 out-of-scope") == 1);
    CHECK(count_audit(wide, "inventory.software.query", "denied") == 1);
    CHECK(wide.sink.Get("/api/v1/inventory/software?name=A&agent_id=dev-z")->status == 200);
    CHECK(count_audit(wide, "inventory.software.query", "denied") == 2);
    wide.audit_fail_result = "denied"; // the post-filter's own denied row feeds the flag too
    auto wide_flagged = nlohmann::json::parse(wide.sink.Get("/api/v1/inventory/software?name=A")->body);
    CHECK(wide_flagged.at("data").at("audit_persisted") == false);
}

TEST_CASE("REST inventory/software: success audit target equals audit_target(query)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"A", "1", "", ""}});
    InvHarness h{&store};
    REQUIRE(h.sink.Get("/api/v1/inventory/software?agent_id=dev-a&q=A")->status == 200);
    REQUIRE_FALSE(h.audit_log.empty());
    SoftwareFleetQuery q;
    q.agent_id = "dev-a";
    q.q = "A";
    CHECK(h.audit_log.back().target_id == software_catalogue::audit_target(q));
}

// ── SAM-17 lookup: status, hostname, match, version range, totals ────────────

namespace {

constexpr const char* kLookupFacet = "pkg_inventory.packages";

SoftwareEntry lookup_entry(const std::string& name, const std::string& version,
                           const std::string& arch = "") {
    SoftwareEntry e;
    e.name = name;
    e.version = version;
    e.arch = arch;
    e.kind = "package";
    e.ecosystem = "deb";
    e.source = kLookupFacet;
    return e;
}

// One agent's section through the v3 apply path (the only path that records facet state).
void seed_v3(SoftwareInventoryStore& store, const std::string& agent, V3Status status,
             std::vector<SoftwareEntry> rows = {}) {
    V3Section s;
    s.facet = kLookupFacet;
    s.status = status;
    s.rows = std::move(rows);
    s.duration_ms = 1;
    s.bytes_read = 1;
    V3Report rep;
    rep.sections.push_back(std::move(s));
    const auto out = store.apply_installed_software_v3(agent, std::move(rep));
    REQUIRE(out.size() == 1);
    REQUIRE((out[0].outcome == V3SectionOutcome::kStored ||
             out[0].outcome == V3SectionOutcome::kStatusOnly));
}

nlohmann::json get_lookup(InvHarness& h, const std::string& query, int expect = 200) {
    auto res = h.sink.Get("/api/v1/inventory/software" + query);
    REQUIRE(res);
    CHECK(res->status == expect);
    return nlohmann::json::parse(res->body, nullptr, false);
}

} // namespace

TEST_CASE("REST inventory/software: the lookup row schema is typed in the OpenAPI spec and matches the serialiser",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto& schemas = spec["components"]["schemas"];
    REQUIRE(schemas.contains("InstalledSoftwareLookupRow"));
    const auto& extra = schemas["InstalledSoftwareLookupRow"]["allOf"][1];
    std::set<std::string> properties;
    for (const auto& [k, v] : extra["properties"].items())
        properties.insert(k);
    // The lookup keys are exactly those list_row_json adds to device_row_json.
    std::set<std::string> added;
    const auto base = software_catalogue::device_row_json(SoftwareFleetRow{});
    for (const auto& [k, v] : software_list::list_row_json(SoftwareFleetRow{}, {}).items())
        if (!base.contains(k))
            added.insert(k);
    CHECK(properties == added);
    CHECK(added.size() == 8);
    // The page carries the totals block and its omission reason.
    const auto& data = schemas["InstalledSoftwarePage"]["properties"]["data"];
    CHECK(data["properties"]["totals"]["nullable"] == true);
    CHECK(data["properties"]["totals_omitted"]["enum"] ==
          nlohmann::json::array({"scope", "filters", "building"}));
    CHECK(schemas["InstalledSoftwarePage"]["properties"]["data"]["properties"]["software"]["items"]
                 ["$ref"] == "#/components/schemas/InstalledSoftwareLookupRow");
    // The new query parameters are discoverable.
    std::set<std::string> params;
    for (const auto& p : spec["paths"]["/inventory/software"]["get"]["parameters"])
        params.insert(p["name"].get<std::string>());
    for (const char* k : {"match", "version_min", "version_max", "status"})
        CHECK(params.contains(k));
}

TEST_CASE("REST inventory/software: lookup rows carry hostname, last_seen, status and install fields",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_v3(store, "dev-a", V3Status::kFull, {lookup_entry("git", "2.1", "amd64")});
    InvHarness h{&store};
    h.hostnames["dev-a"] = "host-a";
    h.hostnames["dev-elsewhere"] = "host-elsewhere"; // on the roster, not on this page

    const auto body = get_lookup(h, "?name=git");
    const auto& rows = body.at("data").at("software");
    REQUIRE(rows.size() == 1);
    CHECK(h.hostname_reads == 1); // one roster read per page
    const auto& r = rows[0];
    CHECK(r["hostname"] == "host-a");
    // last_seen is exactly the store's own figure for the device's installed_software poll.
    const auto seen = store.source_last_seen_bulk("installed_software", {"dev-a"});
    REQUIRE(seen.has_value());
    REQUIRE(seen->contains("dev-a"));
    CHECK(r["last_seen"].is_number());
    CHECK(r["last_seen"].get<std::int64_t>() == seen->at("dev-a"));
    CHECK(r["status"] == "current");
    CHECK(r["last_confirmed_at"].is_number());
    CHECK(r["install_type"] == "package_manager");
    CHECK(r["install_scope"] == "machine");
    CHECK(r.contains("install_location"));
    CHECK(r["instance_key"].get<std::string>().size() == 64);
    // The original 14 fields are unchanged.
    CHECK(r["name"] == "git");
    CHECK(r["version"] == "2.1");
    CHECK(r["source"] == kLookupFacet);
}

TEST_CASE("REST inventory/software: status is current/unconfirmed/disabled and status= filters; totals say filters",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_v3(store, "dev-ok", V3Status::kFull, {lookup_entry("git", "2.1")});
    seed_v3(store, "dev-slow", V3Status::kFull, {lookup_entry("git", "2.1")});
    seed_v3(store, "dev-off", V3Status::kFull, {lookup_entry("git", "2.1")});
    seed_v3(store, "dev-slow", V3Status::kTimeout); // rows stay, the facet is no longer confirmed
    seed_v3(store, "dev-off", V3Status::kDisabled);
    seed(store, "dev-v2", {{"git", "2.1", "", ""}}); // a v2 row: no facet record at all

    InvHarness h{&store};
    const auto all = get_lookup(h, "?name=git");
    std::map<std::string, std::string> status;
    for (const auto& r : all.at("data").at("software"))
        status[r["agent_id"].get<std::string>()] = r["status"].get<std::string>();
    CHECK(status.size() == 4); // the default filter drops nothing
    CHECK(status["dev-ok"] == "current");
    CHECK(status["dev-slow"] == "unconfirmed");
    CHECK(status["dev-off"] == "disabled");
    CHECK(status["dev-v2"] == "unconfirmed"); // a missing facet record is unconfirmed

    for (const auto& [filter, expect] :
         std::vector<std::pair<std::string, std::string>>{{"current", "dev-ok"},
                                                          {"disabled", "dev-off"}}) {
        CAPTURE(filter);
        const auto body = get_lookup(h, "?name=git&status=" + filter);
        REQUIRE(body.at("data").at("software").size() == 1);
        CHECK(body.at("data").at("software")[0]["agent_id"] == expect);
        CHECK(body.at("data").at("totals_omitted") == "filters");
    }
    const auto unconfirmed = get_lookup(h, "?name=git&status=unconfirmed");
    CHECK(unconfirmed.at("data").at("software").size() == 2);
}

TEST_CASE("REST inventory/software: match=prefix and contains filter; exact is unchanged; totals say filters",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // "Git" differs from "git" only by case: exact and prefix are case-sensitive (documented in
    // the OpenAPI parameter), contains is not.
    seed(store, "dev-a", {{"git", "1", "", ""}, {"Git", "1", "", ""}, {"gitk", "1", "", ""},
                          {"libgit2", "1", "", ""}, {"g_t%", "1", "", ""}});
    InvHarness h{&store};
    auto names = [&](const std::string& query) {
        std::set<std::string> out;
        const auto body = get_lookup(h, query);
        for (const auto& r : body.at("data").at("software"))
            out.insert(r["name"].get<std::string>());
        return out;
    };
    CHECK(names("?name=git") == std::set<std::string>{"git"});
    CHECK(names("?name=git&match=exact") == std::set<std::string>{"git"});
    CHECK(names("?name=Git") == std::set<std::string>{"Git"});
    CHECK(names("?name=GIT").empty());
    CHECK(names("?name=git&match=prefix") == std::set<std::string>{"git", "gitk"});
    CHECK(names("?name=Git&match=prefix") == std::set<std::string>{"Git"});
    CHECK(names("?name=GIT&match=prefix").empty());
    CHECK(names("?name=GIT&match=contains") ==
          std::set<std::string>{"git", "Git", "gitk", "libgit2"});
    // LIKE metacharacters in the term are literal.
    CHECK(names("?name=g_t&match=prefix") == std::set<std::string>{"g_t%"});
    CHECK(names("?name=%25&match=contains") == std::set<std::string>{"g_t%"});
    CHECK(get_lookup(h, "?name=git&match=prefix").at("data").at("totals_omitted") == "filters");
    CHECK(get_lookup(h, "?name=git&match=regex", 400).contains("error"));
}

TEST_CASE("REST inventory/software: a failed last-poll read after a good page read is a 503 with one failure audit row, never a page with null last_seen",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"git", "2.1", "", ""}});
    { // The page read joins installed_software and the facet state only; the per-page bulk
      // last-poll read is the request's first statement over inventory_state, so dropping that
      // table degrades exactly the facts read, after the page read succeeded.
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease.get(), "DROP TABLE software_inventory_store.inventory_state",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    InvHarness h{&store};
    h.hostnames = {{"dev-a", "host-a"}};
    auto res = h.sink.Get("/api/v1/inventory/software?name=git");
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("message") ==
          "software inventory store degraded — last-poll read failed");
    CHECK(body.at("error").at("retry_after_ms") == 5000);
    std::size_t failures = 0;
    std::size_t successes = 0;
    for (const auto& a : h.audit_log) {
        if (a.action != "inventory.software.query")
            continue;
        failures += a.result == "failure";
        successes += a.result == "success";
    }
    CHECK(failures == 1);
    CHECK(successes == 0);
}

TEST_CASE("REST inventory/software: version_min/version_max resolve through the title's live versions, with or without a catalogue refresh",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"git", "1.9", "", ""}});
    seed(store, "dev-b", {{"git", "1.10", "", ""}});
    seed(store, "dev-c", {{"git", "2.0-rc1", "", ""}});
    seed(store, "dev-d", {{"git", "2.0", "", ""}});
    InvHarness h{&store};
    auto agents = [&](const std::string& query) {
        std::set<std::string> out;
        const auto body = get_lookup(h, query);
        for (const auto& r : body.at("data").at("software"))
            out.insert(r["agent_id"].get<std::string>());
        return out;
    };

    // No catalogue refresh yet: the range resolves against the live versions, so it serves rows
    // (and live totals) rather than a building 503.
    REQUIRE(store.catalog_rollup_meta()->refreshed_at == 0);
    CHECK(agents("?name=git&version_min=2.0") == std::set<std::string>{"dev-d"});
    const auto early = get_lookup(h, "?name=git&version_min=1.9&version_max=1.10").at("data");
    REQUIRE(early.at("totals").is_object());
    CHECK(early.at("totals").at("installs") == 2);
    CHECK(early.at("totals").at("devices") == 2);
    CHECK(early.at("totals").at("as_of").is_null());

    REQUIRE(store.refresh_catalog_rollup());
    // 1.9 < 1.10 (numeric), 2.0-rc1 < 2.0; bounds are inclusive.
    CHECK(agents("?name=git&version_min=1.9&version_max=2.0-rc1") ==
          std::set<std::string>{"dev-a", "dev-b", "dev-c"});
    CHECK(agents("?name=git&version_min=2.0") == std::set<std::string>{"dev-d"});
    CHECK(agents("?name=git&version_max=1.9") == std::set<std::string>{"dev-a"});
    CHECK(agents("?name=git&version_min=5") == std::set<std::string>{}); // an empty range is empty, not an error
    CHECK(get_lookup(h, "?version_min=1.0", 400).contains("error"));
    CHECK(get_lookup(h, "?name=git&match=prefix&version_max=1.0", 400).contains("error"));
}

TEST_CASE("REST inventory/software: a range sees a version first reported after the last refresh (never a false zero)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"git", "1.0", "", ""}});
    REQUIRE(store.refresh_catalog_rollup());
    seed(store, "dev-b", {{"git", "2.5", "", ""}}); // after the refresh: the hourly rollups lack 2.5

    InvHarness h{&store};
    const auto exact = get_lookup(h, "?name=git&version=2.5").at("data");
    CHECK(exact.at("totals").at("devices") == 1);
    const auto range = get_lookup(h, "?name=git&version_min=2.0").at("data");
    REQUIRE(range.at("software").size() == 1);
    CHECK(range.at("software")[0]["agent_id"] == "dev-b");
    REQUIRE(range.at("totals").is_object());
    CHECK(range.at("totals").at("installs") == 1);
    CHECK(range.at("totals").at("devices") == 1);
    CHECK(range.at("totals").at("as_of").is_null()); // live and exact, as the manual states
    // An open lower bound with the upper bound below the new version still excludes it.
    CHECK(get_lookup(h, "?name=git&version_max=2.0").at("data").at("software").size() == 1);
}

TEST_CASE("REST inventory/software: a range over a title with kCatalogRowCap distinct versions is a 400 and writes no audit row",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // One device carrying a distinct version per cap slot: the live distinct-version read comes
    // back exactly full, so it may have been cut and the range cannot be resolved against it.
    std::vector<SoftwareEntry> rows;
    rows.reserve(static_cast<std::size_t>(kCatalogRowCap));
    for (int i = 0; i < kCatalogRowCap; ++i)
        rows.push_back(lookup_entry("git", std::to_string(i)));
    seed_v3(store, "dev-a", V3Status::kFull, std::move(rows));

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=git&version_min=1");
    REQUIRE(res);
    CHECK(res->status == 400);
    const auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("message") == std::string(software_list::kRangeNotResolvable));
    CHECK(h.audit_log.empty()); // a refused request is not a read, so it writes nothing

    // The documented way out: an exact version is a plain equality predicate and still serves.
    const auto exact = get_lookup(h, "?name=git&version=7").at("data");
    CHECK(exact.at("software").size() == 1);
}

TEST_CASE("REST inventory/software: a confined caller's range is resolved over its own rows: a title with "
          "kCatalogRowCap versions outside its scope answers exactly as an unknown title, never a 400",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // Every one of the cap's worth of distinct versions lives on a device OUTSIDE the caller's
    // scope. A fleet-wide distinct-version read would fill the cap and answer the range 400
    // (kRangeNotResolvable): one bit about the fleet a confined caller must not learn.
    std::vector<SoftwareEntry> rows;
    rows.reserve(static_cast<std::size_t>(kCatalogRowCap));
    for (int i = 0; i < kCatalogRowCap; ++i)
        rows.push_back(lookup_entry("git", std::to_string(i)));
    seed_v3(store, "dev-out", V3Status::kFull, std::move(rows));
    seed_v3(store, "dev-in", V3Status::kFull, {lookup_entry("other", "1.0")});

    InvHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-in"};
    const auto capped = get_lookup(h, "?name=git&version_min=1");
    const auto unknown = get_lookup(h, "?name=no-such-title&version_min=1");
    CHECK(capped.at("data") == unknown.at("data")); // byte-for-byte the unknown-title answer
    CHECK(capped.at("data").at("software").empty());
    CHECK(capped.at("data").at("totals_omitted") == "scope");
    CHECK_FALSE(h.has_audit("failure"));

    // Deny-all (engaged-empty) is the same answer, with no store read for the range.
    h.fleet_scope = std::unordered_set<std::string>{};
    CHECK(get_lookup(h, "?name=git&version_min=1").at("data").at("software").empty());

    // The unfiltered caller still sees the fleet-wide cut: for it the refusal is the truth.
    h.fleet_scope.reset();
    CHECK(get_lookup(h, "?name=git&version_min=1", 400).contains("error"));
}

TEST_CASE("REST inventory/software: a confined caller's range serves its own in-range rows, under push-down "
          "and above the push-down bound, where the fleet-wide read would have refused it",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // dev-in holds git 1.0, 2.0 and 9.0; dev-out holds git 1.0 and enough other distinct versions
    // that the FLEET-wide distinct-version read fills kCatalogRowCap. Resolved over the caller's
    // scope the range [1, 5] is {1.0, 2.0} and those rows are served (9.0 is outside the range,
    // dev-out's versions outside the scope do not matter); resolved over the fleet it would be
    // the cut read and the 400 the unfiltered caller gets below.
    std::vector<SoftwareEntry> out_rows;
    out_rows.push_back(lookup_entry("git", "1.0"));
    for (int i = 0; out_rows.size() < static_cast<std::size_t>(kCatalogRowCap); ++i)
        out_rows.push_back(lookup_entry("git", "3000." + std::to_string(i)));
    seed_v3(store, "dev-out", V3Status::kFull, std::move(out_rows));
    seed_v3(store, "dev-in", V3Status::kFull,
            {lookup_entry("git", "1.0"), lookup_entry("git", "2.0"), lookup_entry("git", "9.0")});

    InvHarness h{&store};
    const auto expect_in_range = [](const nlohmann::json& body, int devices_omitted) {
        const auto& rows = body.at("data").at("software");
        REQUIRE(rows.size() == 2);
        std::set<std::string> versions;
        for (const auto& r : rows) {
            CHECK(r.at("agent_id") == "dev-in");
            versions.insert(r.at("version").get<std::string>());
        }
        CHECK(versions == std::set<std::string>{"1.0", "2.0"});
        CHECK(body.at("data").at("devices_omitted") == devices_omitted);
        CHECK(body.at("data").at("totals_omitted") == "scope");
    };
    // Push-down: the scope is in the page read and in the version read.
    h.fleet_scope = std::unordered_set<std::string>{"dev-in"};
    expect_in_range(get_lookup(h, "?name=git&version_min=1&version_max=5"), 0);
    CHECK_FALSE(h.has_audit("denied"));
    // Above kScopePushdownMaxIds the page is post-filtered, but the version read still takes the
    // WHOLE scope (no bound): the set is {1.0, 2.0}, so dev-out's git 1.0 is scanned and dropped
    // (devices_omitted 1, a denied row) while its cap's worth of other versions is never read.
    h.fleet_scope = wide_scope({"dev-in"});
    expect_in_range(get_lookup(h, "?name=git&version_min=1&version_max=5"), 1);
    CHECK(h.has_audit("denied"));
    // The unfiltered caller reads the fleet: the cut read is its truth.
    h.fleet_scope.reset();
    CHECK(get_lookup(h, "?name=git&version_min=1&version_max=5", 400).contains("error"));
}

TEST_CASE("REST inventory/software: a failed version read for a range is a 503 with retry_after_ms and one failure audit row",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    // size-1 pool held by the test: the range's distinct-version read is the first store read of
    // the request and times out, so the route must answer 503, never an empty or unresolved 200.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire();
    REQUIRE(held);
    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=git&version_min=1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    const auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("retry_after_ms") == 5000);
    CHECK(h.audit_log.size() == 1);
    CHECK(count_audit(h, "inventory.software.query", "failure") == 1);
}

TEST_CASE("REST inventory/software: the audit target carries the lookup filters",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"git", "1.9", "", ""}});
    InvHarness h{&store};
    const std::vector<std::pair<std::string, std::string>> cases{
        {"?name=git&match=prefix", "name=git;match=prefix"},
        {"?name=git&status=current", "name=git;status=current"},
        {"?name=git&version_min=1.0&version_max=2.0", "name=git;version_min=1.0;version_max=2.0"},
        {"?name=git&match=prefix&status=disabled", "name=git;match=prefix;status=disabled"},
    };
    for (const auto& [query, target] : cases) {
        CAPTURE(query);
        h.audit_log.clear();
        get_lookup(h, query);
        REQUIRE_FALSE(h.audit_log.empty());
        CHECK(h.audit_log.back().target_id == target);
    }
}

TEST_CASE("REST inventory/software: totals - exact name, global admission; install rows vs distinct devices",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // dev-a holds the title twice on one version (two architectures) and again on another version.
    seed_v3(store, "dev-a", V3Status::kFull,
            {lookup_entry("git", "1.9", "amd64"), lookup_entry("git", "1.9", "arm64"),
             lookup_entry("git", "1.10", "amd64")});
    seed_v3(store, "dev-b", V3Status::kFull, {lookup_entry("git", "1.10", "amd64")});
    seed_v3(store, "dev-c", V3Status::kFull, {lookup_entry("git", "3.0", "amd64")});
    InvHarness h{&store};

    // Before the first catalogue refresh a rollup-served total is not available: building.
    const auto early = get_lookup(h, "?name=git");
    CHECK(early.at("data").at("totals").is_null());
    CHECK(early.at("data").at("totals_omitted") == "building");

    REQUIRE(store.refresh_catalog_rollup());
    const auto whole = get_lookup(h, "?name=git").at("data");
    REQUIRE(whole.at("totals").is_object());
    CHECK(whole.at("totals").at("installs") == 5);  // install ROWS
    CHECK(whole.at("totals").at("devices") == 3);   // distinct devices
    CHECK(whole.at("totals").at("as_of").is_number());
    CHECK_FALSE(whole.contains("totals_omitted"));

    // One exact version: live and exact (the same definitions).
    const auto one = get_lookup(h, "?name=git&version=1.9").at("data");
    CHECK(one.at("totals").at("installs") == 2);
    CHECK(one.at("totals").at("devices") == 1);
    CHECK(one.at("totals").at("as_of").is_null());

    // A range over two versions: dev-a is on both and counts ONCE as a device.
    const auto range = get_lookup(h, "?name=git&version_min=1.9&version_max=1.10").at("data");
    CHECK(range.at("totals").at("installs") == 4);
    CHECK(range.at("totals").at("devices") == 2);

    // Any other filter: no totals, and the reason says so.
    for (const char* q : {"?name=git&agent_id=dev-a", "?name=git&q=gi", "?name=git&ecosystem=deb"}) {
        CAPTURE(q);
        const auto body = get_lookup(h, q).at("data");
        CHECK(body.at("totals").is_null());
        CHECK(body.at("totals_omitted") == "filters");
    }
    // A request with no name at all is not a lookup.
    CHECK(get_lookup(h, "").at("data").at("totals_omitted") == "filters");
}

TEST_CASE("REST inventory/software: a confined caller gets scoped rows and NO totals",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_v3(store, "dev-in", V3Status::kFull, {lookup_entry("git", "1.0")});
    seed_v3(store, "dev-out", V3Status::kFull, {lookup_entry("git", "1.0")});
    seed_v3(store, "dev-out2", V3Status::kFull, {lookup_entry("git", "1.0")});
    REQUIRE(store.refresh_catalog_rollup());

    InvHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-in"};
    for (const char* q : {"?name=git", "?name=git&version=1.0", "?name=git&version_min=0.1"}) {
        CAPTURE(q);
        const auto body = get_lookup(h, q).at("data");
        REQUIRE(body.at("software").size() == 1);
        CHECK(body.at("software")[0]["agent_id"] == "dev-in");
        CHECK(body.at("totals").is_null());
        CHECK(body.at("totals_omitted") == "scope");
        // No fleet figure (3 installs / 3 devices) reaches a confined caller in any form: the
        // body has exactly the documented keys, and no number in it is the fleet's 3.
        std::set<std::string> keys;
        for (const auto& [k, v] : body.items()) {
            keys.insert(k);
            if (v.is_number())
                CHECK(v.get<std::int64_t>() != 3);
        }
        CHECK(keys == std::set<std::string>{"software", "count", "next_cursor", "devices_omitted",
                                            "totals", "totals_omitted"});
        CHECK(body.at("count") == 1);
        CHECK(body.dump().find("dev-out") == std::string::npos);
    }
    h.fleet_scope.reset(); // the same request, unfiltered
    const auto global = get_lookup(h, "?name=git").at("data");
    CHECK(global.at("totals").at("devices") == 3);
}

TEST_CASE("REST inventory/software: a degraded totals read alone is a 503 with retry_after_ms",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"git", "1.0", "", ""}});
    REQUIRE(store.refresh_catalog_rollup());
    { // The page read does not touch catalog_rollup's row_count; the title-totals read does.
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "ALTER TABLE software_inventory_store.catalog_rollup RENAME COLUMN row_count TO rc_gone",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=git");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("retry_after_ms") == 5000);
    CHECK(body.at("error").at("message") ==
          "software inventory store degraded — totals read failed");
    CHECK(h.has_audit("failure"));
}
