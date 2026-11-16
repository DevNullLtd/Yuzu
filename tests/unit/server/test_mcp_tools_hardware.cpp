/// @file test_mcp_tools_hardware.cpp
/// The MCP twins of GET /api/v1/hardware and GET /api/v1/hardware/{id}
/// (`list_hardware_ci`, `get_hardware_ci`, mcp_tools_hardware.cpp).
///
/// One fixture (`Twin`) feeds the SAME fakes into a real `HardwareRoutes` (driven through
/// TestRouteSink) and a real `McpServer` (driven through its in-process handler), so the
/// byte-identity cases compare two real transports over one data set. The fixture is local
/// on purpose: `HwHarness` (test_hardware_routes.cpp) and `McpTestServer`
/// (test_mcp_server.cpp) are TU-private, and neither is worth hoisting for this file.
///
/// Matrix: tier admission, gate denial (no handler audit row), confined scope with
/// devices_omitted and the identical "not found", unwired providers, degraded roster, audit
/// failure withholds the data, strict argument bounds, REST byte identity, output-schema
/// conformance, and the audit-row contents.

#include "device_ci_kinds.hpp"
#include "device_ci_section_digest.hpp"
#include "hardware_list_model.hpp"
#include "hardware_section_integrity.hpp"
#include "hardware_routes.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "mcp_tool_deps.hpp"
#include "mcp_tool_registry.hpp"
#include "test_fake_ci_keyset_store.hpp"
#include "test_json_schema_subset.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
namespace mcp = yuzu::server::mcp;
using yuzu::test::schema_violation;

namespace {

InventoryDeviceRow make_row(std::string id, std::string host, std::string os, bool online) {
    InventoryDeviceRow r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = std::move(os);
    r.online = online;
    r.last_seen = online ? "now" : "1h ago";
    r.last_seen_ms = online ? 1'700'000'000'000 : 1'699'990'000'000;
    r.ci_serial = "SN-" + r.agent_id;
    r.ci_model = "Model-" + r.agent_id;
    r.ci_manufacturer = "Acme";
    r.ci_cpu_model = "Acme CPU";
    r.ci_cpu_cores = "8";
    r.ci_cpu_threads = "16";
    r.ci_ram_bytes = "17179869184";
    r.ci_os_name = "OS";
    r.ci_os_version = "1.2";
    r.ci_primary_mac = "aa:bb:cc:dd:ee:ff";
    r.agent_version = "0.13.1";
    r.ips = {"10.0.0.1"};
    r.tags = {{"role", "web"}};
    return r;
}

HardwareCiDetail full_detail(const std::string& id) {
    HardwareCiDetail d;
    d.identity = make_row(id, "host-" + id, "linux", true);
    DeviceCiRecord ci;
    ci.agent_id = id;
    ci.manufacturer = "Acme";
    ci.model = "Model-" + id;
    ci.serial = "SN-" + id;
    ci.system_uuid = "uuid-" + id;
    ci.cpu_cores = "8";
    ci.ram_bytes = "17179869184";
    ci.nic_count = "2";
    ci.first_seen = 1'690'000'000;
    ci.last_seen = 1'700'000'000;
    d.ci = std::optional<DeviceCiRecord>{ci};
    SoftwareEntry sw;
    sw.name = "pkg";
    sw.version = "1.0";
    sw.publisher = "Acme";
    sw.install_date = "2026-01-01";
    d.software = std::vector<SoftwareEntry>{sw};
    DeviceTag t;
    t.agent_id = id;
    t.key = "role";
    t.value = "web";
    t.source = "api";
    t.updated_at = 1'700'000'000;
    d.tags = std::vector<DeviceTag>{t};
    d.agent_version = "0.13.1";
    d.software_last_seen = 1'700'000'000;
    return d;
}

// A device the store answered about and holds nothing for: the genuine "not found". Every
// read ANSWERED (CI, software and tags are engaged-and-empty, not nullopt): a nullopt software
// or tag list means "degraded or unwired", and get_hardware_ci refuses to call that absent.
HardwareCiDetail absent_detail() {
    HardwareCiDetail d;
    d.ci = std::optional<DeviceCiRecord>{}; // read succeeded, no record
    d.software = std::vector<SoftwareEntry>{};
    d.tags = std::vector<DeviceTag>{};
    return d;
}

struct Twin {
    // ── shared fakes ──
    std::vector<InventoryDeviceRow> roster_rows;
    bool roster_degraded = false;
    bool roster_truncated = false; // #5712: the roster read was a typed partial
    bool ci_degraded = false;
    bool tags_degraded = false;
    std::map<std::string, HardwareCiDetail> ci_by_id; // an id not here reads as absent
    authz::VisibleSet scope;                           // nullopt = unfiltered
    bool allow_fleet_read = true;
    // The MCP-side perm_fn: counts calls and (by default) allows. The confined-read twins are
    // gated by fleet_read_fn ALONE, so a test flips perm_result to false and expects no change.
    bool perm_result = true;
    int perm_calls = 0;
    // fleet_read_fn calls as "<securable>:<operation>" (both transports share the closure).
    std::vector<std::string> gate_calls;
    std::map<std::string, int> dex_by_id;
    int roster_calls = 0;
    int ci_calls = 0;
    std::vector<CiRead> ci_reads; // the `CiRead` argument of every ci_detail_fn call
    yuzu::MetricsRegistry metrics; // the integrity counter the fake ci_detail_fn below feeds
    std::vector<std::string> dex_calls_for;
    // The keyset store behind GET /api/v1/hardware-ci and list_hardware_ci_records.
    yuzu::server::test::FakeCiKeysetStore ci_store;
    // The collation gate both transports hand to read_page (production wires &collation_gate_).
    // Trusted by default; Opts::wire_ci_gate = false leaves the deps pointer null (no gate).
    std::atomic<pg::CollationGate> ci_gate{pg::CollationGate::Trusted};

    // Domain-verb audit sink (deps.audit_fn on both transports).
    bool domain_audit_ok = true;
    std::vector<std::string> domain_rows;    // action|result|type|id
    std::vector<std::string> domain_details; // detail, parallel
    // Generic mcp.<tool> sink (McpServer's own audit_fn).
    bool generic_audit_ok = true;
    std::vector<std::string> generic_rows; // action|result
    std::vector<std::string> generic_details;

    std::string tier = "operator";
    bool read_only = false;
    bool disabled = false;

    test::TestRouteSink sink;
    HardwareRoutes routes;
    mcp::McpServer server;
    mcp::McpServer::HandlerFn handler;

    struct Opts {
        bool wire_fleet = true;
        bool wire_roster = true;
        bool wire_ci = true;
        bool wire_dex = true;
        bool wire_audit = true;
        bool wire_ci_page = true;
        bool wire_ci_gate = true;
    };

    Twin() : Twin(Opts{}) {}
    explicit Twin(Opts o) {
        HardwareRoutes::FleetReadFn fleet_read = [this](const httplib::Request&, httplib::Response& res,
                                                        const std::string& securable,
                                                        const std::string& operation)
            -> authz::FleetReadGate {
            gate_calls.push_back(securable + ":" + operation);
            authz::FleetReadGate g;
            if (!allow_fleet_read) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return g; // admitted=false: the response is already written
            }
            g.admitted = true;
            g.scope = scope;
            return g;
        };
        HardwareRoutes::RosterFn roster_fn = [this]() -> InventoryDevicesResult {
            ++roster_calls;
            InventoryDevicesResult out;
            out.rows = roster_rows;
            out.roster_degraded = roster_degraded;
            out.roster_truncated = roster_truncated;
            out.ci_degraded = ci_degraded;
            out.tags_degraded = tags_degraded;
            return out;
        };
        HardwareRoutes::CiDetailFn ci_fn = [this](const std::string& id, CiRead ci_read) {
            ++ci_calls;
            ci_reads.push_back(ci_read);
            const auto it = ci_by_id.find(id);
            HardwareCiDetail detail = it != ci_by_id.end() ? it->second : absent_detail();
            // Mirrors the hw_ci_detail_fn closure in server.cpp (the real one is pinned lexically
            // by test_hw_ci_detail_wiring_lexical.cpp): count after the sections read, for
            // WithSections only, and only for a READ list.
            if (ci_read == CiRead::WithSections && detail.ci_sections && *detail.ci_sections)
                record_section_integrity(**detail.ci_sections, id, &metrics);
            return detail;
        };
        HardwareRoutes::DexScoreFn dex_fn = [this](const std::string& id) {
            dex_calls_for.push_back(id);
            const auto it = dex_by_id.find(id);
            return it != dex_by_id.end() ? it->second : 42;
        };
        HardwareRoutes::AuditFn domain_audit = [this](const httplib::Request&, const std::string& a,
                                                      const std::string& r, const std::string& tt,
                                                      const std::string& tid,
                                                      const std::string& detail) {
            domain_rows.push_back(a + "|" + r + "|" + tt + "|" + tid);
            domain_details.push_back(detail);
            return domain_audit_ok;
        };

        // REST side.
        HardwareRoutes::Deps deps;
        deps.auth_fn = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        deps.scoped_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                 const std::string&, const std::string&) { return true; };
        deps.fleet_read_fn = fleet_read;
        deps.audit_fn = domain_audit;
        deps.roster_fn = roster_fn;
        deps.ci_detail_fn = ci_fn;
        deps.ci_page_reader = ci_store.reader();
        if (o.wire_ci_gate)
            deps.ci_collation_gate = &ci_gate;
        deps.dex_score_fn = dex_fn;
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        routes.register_routes(sink, deps);

        // MCP side: the SAME closure instances through ToolDeps.
        mcp::ToolDeps td;
        if (o.wire_fleet)
            td.fleet_read_fn = fleet_read;
        if (o.wire_audit)
            td.audit_fn = domain_audit;
        if (o.wire_roster)
            td.roster_fn = roster_fn;
        if (o.wire_ci)
            td.ci_detail_fn = ci_fn;
        if (o.wire_ci_page)
            td.ci_page_reader = ci_store.reader();
        if (o.wire_ci_gate)
            td.ci_collation_gate = &ci_gate;
        if (o.wire_dex)
            td.dex_score_fn = dex_fn;
        server.set_tool_deps(std::move(td));

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            s.mcp_tier = tier;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) {
            ++perm_calls;
            return perm_result;
        };
        auto generic_audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                                    const std::string&, const std::string&, const std::string& detail) {
            generic_rows.push_back(a + "|" + r);
            generic_details.push_back(detail);
            return generic_audit_ok;
        };
        auto agents_fn = []() { return json::array(); };
        handler = server.build_handler(
            std::move(auth_fn), std::move(perm_fn), std::move(generic_audit), std::move(agents_fn),
            /*rbac_store=*/nullptr, /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr, /*audit_store=*/nullptr, /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr, /*policy_store=*/nullptr, /*mgmt_store=*/nullptr,
            /*approval_manager=*/nullptr, /*schedule_engine=*/nullptr, read_only, disabled);
    }

    // POST a JSON-RPC body; returns the response (status + body).
    std::unique_ptr<httplib::Response> post(const std::string& body) {
        httplib::Request req;
        req.method = "POST";
        req.path = "/mcp/v1/";
        req.body = body;
        req.set_header("Content-Type", "application/json");
        auto res = std::make_unique<httplib::Response>();
        res->status = 200;
        handler(req, *res);
        return res;
    }

    // tools/call -> parsed JSON-RPC body.
    json call(const std::string& tool, const json& arguments = json::object()) {
        json params = {{"name", tool}, {"arguments", arguments}};
        auto res = post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 7}, {"params", params}}
                            .dump());
        REQUIRE(res);
        return json::parse(res->body);
    }

    void clear_audit() {
        gate_calls.clear();
        domain_rows.clear();
        domain_details.clear();
        generic_rows.clear();
        generic_details.clear();
    }

    // The REST body's `data` for GET path.
    json rest_data(const std::string& path) {
        auto res = sink.Get(path);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        return json::parse(res->body)["data"];
    }
};

bool has(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}


const json& tool_entry(const json& tools_list_result, const std::string& name) {
    for (const auto& t : tools_list_result["result"]["tools"])
        if (t["name"] == name)
            return t;
    FAIL("tool not served: " << name);
    static const json none;
    return none;
}

} // namespace

// ───────────────────────── catalogue / registration ────────────────────────────

TEST_CASE("mcp hardware twins: both are served, confined Inventory:Read reads with typed schemas",
          "[mcp][hardware][registry_seam]") {
    Twin t;
    for (const char* name : {"list_hardware_ci", "get_hardware_ci"}) {
        INFO(name);
        const auto rows = mcp::tool_security_rows_for_test();
        const auto it = std::find_if(rows.begin(), rows.end(),
                                     [&](const auto& r) { return r.name == name; });
        REQUIRE(it != rows.end());
        CHECK(it->securable == "Inventory");
        CHECK(it->operation == "Read");
        CHECK(it->service_scope == mcp::ServiceScopeClassForTest::kConfined);
    }

    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const json& list_tool = tool_entry(listed, "list_hardware_ci");
    const json& get_tool = tool_entry(listed, "get_hardware_ci");
    for (const json* tool : {&list_tool, &get_tool}) {
        CHECK((*tool)["annotations"]["readOnlyHint"] == true);
        CHECK((*tool)["annotations"]["idempotentHint"] == true);
        CHECK((*tool)["outputSchema"]["type"] == "object");
        CHECK((*tool)["outputSchema"]["required"].is_array());
    }
    // Bounded, typed inputs (the advertised contract the handlers enforce strictly).
    const auto& lp = list_tool["inputSchema"]["properties"];
    CHECK(lp["limit"]["minimum"] == 1);
    CHECK(lp["limit"]["maximum"] == 200);
    CHECK(lp["offset"]["minimum"] == 0);
    CHECK(lp["q"]["maxLength"] == 256);
    CHECK(lp["tag"]["maxLength"] == 256);
    CHECK(lp["os"]["enum"] == json::array({"all", "windows", "linux", "macos"}));
    CHECK(lp["status"]["enum"] == json::array({"all", "online", "offline"}));
    CHECK(lp["dir"]["enum"] == json::array({"asc", "desc"}));
    CHECK(lp["sort"]["enum"].size() == 12);
    const auto& gi = get_tool["inputSchema"];
    CHECK(gi["required"] == json::array({"agent_id"}));
    CHECK(gi["properties"]["agent_id"]["minLength"] == 1);
    CHECK(gi["properties"]["agent_id"]["maxLength"] == 256);
}

TEST_CASE("mcp hardware twins: Read is admitted at every MCP tier", "[mcp][hardware]") {
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        INFO("tier " << tier);
        Twin t;
        t.tier = tier;
        t.roster_rows = {make_row("a", "host-a", "linux", true)};
        t.ci_by_id["a"] = full_detail("a");
        const json list = t.call("list_hardware_ci");
        REQUIRE_FALSE(list.contains("error"));
        CHECK(list["result"]["structuredContent"]["count"] == 1);
        const json get = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE_FALSE(get.contains("error"));
        CHECK(get["result"]["structuredContent"]["agent_id"] == "a");
    }
}

// ───────────────────────── the single gate ─────────────────────────────────────

TEST_CASE("mcp hardware twins: a fleet-read refusal is the gate's own body, and the handler audits nothing",
          "[mcp][hardware][security]") {
    Twin t;
    t.allow_fleet_read = false;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");

    for (const auto& [tool, args] : std::vector<std::pair<std::string, json>>{
             {"list_hardware_ci", json::object()}, {"get_hardware_ci", {{"agent_id", "a"}}}}) {
        INFO(tool);
        t.clear_audit();
        json params = {{"name", tool}, {"arguments", args}};
        auto res = t.post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3}, {"params", params}}
                              .dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == R"({"error":"forbidden"})");
        CHECK(t.domain_rows.empty());
        CHECK(t.generic_rows.empty());
        CHECK(t.roster_calls == 0);
        CHECK(t.ci_calls == 0);
    }
}

// ───────────────────────── confinement ─────────────────────────────────────────

TEST_CASE("mcp hardware twins: a confined caller sees only its scope, and a hidden id reads as not found",
          "[mcp][hardware][security]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    t.ci_by_id["b"] = full_detail("b"); // exists, but outside the caller's scope
    t.scope = std::unordered_set<std::string>{"a", "zzz"};

    const json list = t.call("list_hardware_ci");
    REQUIRE_FALSE(list.contains("error"));
    const auto& sc = list["result"]["structuredContent"];
    REQUIRE(sc["devices"].size() == 1);
    CHECK(sc["devices"][0]["agent_id"] == "a");
    // A confined caller is never told how many devices lie outside its scope (an existence
    // oracle, ADR-0032/0033/0017 INV-3): the count is absent and the status says why.
    CHECK_FALSE(sc.contains("devices_omitted"));
    CHECK(sc["scope_basis"] == "authority_scoped");
    CHECK(sc["count"] == 1);
    CHECK(sc["kpis"]["total"] == 1); // KPIs describe the caller's fleet, not the whole one
    CHECK(t.dex_calls_for == std::vector<std::string>{"a"});

    t.clear_audit();
    t.ci_calls = 0;
    const json hidden = t.call("get_hardware_ci", {{"agent_id", "b"}});
    const json missing = t.call("get_hardware_ci", {{"agent_id", "zzz"}});
    REQUIRE(hidden.contains("error"));
    REQUIRE(missing.contains("error"));
    CHECK(hidden["error"]["code"] == mcp::kInvalidParams);
    CHECK(hidden["error"]["message"] == "not found");
    // The two answers are indistinguishable apart from the per-request correlation id: the
    // whole error object is compared, so a field added to one branch only turns this red.
    {
        json h = hidden["error"], m = missing["error"];
        for (json* e : {&h, &m})
            if (e->contains("data") && (*e)["data"].is_object())
                (*e)["data"].erase("correlation_id");
        CHECK(h == m);
    }
    CHECK(hidden["error"]["code"] == missing["error"]["code"]);
    CHECK(hidden["error"]["message"] == missing["error"]["message"]);
    CHECK(hidden["error"]["data"]["remediation"] == missing["error"]["data"]["remediation"]);
    CHECK(missing["error"]["data"]["remediation"].get<std::string>().find("list_hardware_ci") !=
          std::string::npos);
    CHECK(hidden["error"]["data"]["retry_after_ms"] == missing["error"]["data"]["retry_after_ms"]);
    // A hidden device's record is never even composed, and neither miss writes the domain row.
    CHECK(t.ci_calls == 1); // only "zzz"
    CHECK(t.domain_rows.empty());

    const json visible = t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE_FALSE(visible.contains("error"));
}

// ───────────────────────── unwired providers ───────────────────────────────────

TEST_CASE("mcp hardware twins: an unwired provider is an internal error with no data and no retry hint",
          "[mcp][hardware]") {
    SECTION("no roster provider") {
        Twin t(Twin::Opts{.wire_roster = false});
        const json r = t.call("list_hardware_ci");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci|failure"));
        CHECK(has(t.domain_rows, "inventory.devices|failure|Inventory|fleet"));
    }
    SECTION("no CI provider") {
        Twin t(Twin::Opts{.wire_ci = false});
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(has(t.generic_rows, "mcp.get_hardware_ci|failure"));
    }
    SECTION("no gate closure") {
        Twin t(Twin::Opts{.wire_fleet = false});
        for (const char* tool : {"list_hardware_ci", "get_hardware_ci"}) {
            INFO(tool);
            const json r = t.call(tool, {{"agent_id", "a"}});
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        }
        CHECK(t.roster_calls == 0);
        CHECK(t.ci_calls == 0);
    }
    SECTION("a null ToolDeps pointer on the context") {
        std::vector<std::string> rows;
        httplib::Request req;
        httplib::Response res;
        const json id = 1;
        const json args = json::object();
        const std::string tier = "operator";
        const mcp::ToolCallContext::PermFn perm;
        const mcp::ToolCallContext::AuditFn audit = [&](const std::string& r, const std::string&) {
            rows.push_back(r);
            return true;
        };
        const mcp::ToolCallContext::A4ErrorFn a4 = [](int code, std::string_view, std::string_view,
                                                       long retry, std::string_view, bool) {
            return json{{"code", code}, {"retry", retry}}.dump();
        };
        const mcp::ToolCallContext ctx{req,   res, id, args, tier, perm,
                                       audit, a4,  [](std::string_view payload, const char*) {
                                           return std::string(payload);
                                       }};
        REQUIRE(ctx.deps == nullptr);
        for (const auto& rec : mcp::hardware_tool_records()) {
            INFO(rec.name);
            res.body.clear();
            rec.handler(ctx);
            const json out = json::parse(res.body);
            CHECK(out["code"] == mcp::kInternalError);
            CHECK(out["retry"] == -1);
        }
        CHECK(rows.size() == mcp::hardware_tool_records().size());
    }
}

// ───────────────────────── truncated roster (#5712) ────────────────────────────

// A truncated roster is a SUCCESS carrying the typed bit, not a retryable error (#5371).
// Kills: reusing the roster-unavailable arm for a partial; dropping the field from the shared
// REST/MCP body; a MCP answer that disagrees with REST; a missing audit marker in either audit row;
// the flag appearing on a complete roster; and a confined caller NOT seeing the bit (one bit, and
// their own rows can be among the missing).
TEST_CASE("mcp hardware twins: a truncated roster is served with roster_truncated, never an error",
          "[mcp][hardware][roster_truncated]") {
    SECTION("global read") {
        Twin t;
        t.roster_truncated = true;
        t.roster_rows = {make_row("a", "host-a", "linux", true)};
        const json r = t.call("list_hardware_ci");
        REQUIRE_FALSE(r.contains("error"));
        const auto& sc = r["result"]["structuredContent"];
        CHECK(sc["roster_truncated"] == true);
        CHECK(sc["roster_cap"] == 100000);
        CHECK(sc["count"] == 1);
        CHECK(sc["ci_degraded"] == false);
        REQUIRE_FALSE(t.domain_details.empty());
        CHECK(t.domain_details.back().find("roster_truncated=1") != std::string::npos);
        REQUIRE_FALSE(t.generic_details.empty());
        CHECK(t.generic_details.back().find("roster_truncated=1") != std::string::npos);
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci|success"));
        // Same bytes as the REST twin: one shared builder.
        const json rest = t.rest_data("/api/v1/hardware");
        CHECK(sc["roster_truncated"] == rest["roster_truncated"]);
        CHECK(sc["roster_cap"] == rest["roster_cap"]);
    }
    SECTION("confined read still reports the one-bit fact, never a count") {
        Twin t;
        t.roster_truncated = true;
        t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "linux", true)};
        t.scope = std::unordered_set<std::string>{"a"};
        const json r = t.call("list_hardware_ci");
        REQUIRE_FALSE(r.contains("error"));
        const auto& sc = r["result"]["structuredContent"];
        CHECK(sc["roster_truncated"] == true);
        CHECK(sc["scope_basis"] == "authority_scoped");
        CHECK_FALSE(sc.contains("devices_omitted")); // no existence-oracle count
    }
    SECTION("complete roster") {
        Twin t;
        t.roster_rows = {make_row("a", "host-a", "linux", true)};
        const json r = t.call("list_hardware_ci");
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["roster_truncated"] == false);
        REQUIRE_FALSE(t.domain_details.empty());
        CHECK(t.domain_details.back().find("roster_truncated") == std::string::npos);
    }
}

// ───────────────────────── degraded reads ──────────────────────────────────────

TEST_CASE("mcp hardware twins: a failed roster read is a retryable error, never success plus empty",
          "[mcp][hardware]") {
    SECTION("list") {
        Twin t;
        t.roster_degraded = true;
        const json r = t.call("list_hardware_ci");
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(has(t.domain_rows, "inventory.devices|failure|Inventory|fleet"));
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci|failure"));
    }
    SECTION("get: nothing known and the identity fallback failed") {
        Twin t;
        HardwareCiDetail d = absent_detail();
        d.identity_degraded = true;
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(has(t.domain_rows, "inventory.device.ci|failure|Agent|a"));
        CHECK(t.domain_details.back() == "hardware CI record (MCP) state=roster unreadable");
    }
    SECTION("get: nothing known but the software read failed is a retryable fault, never not found") {
        Twin t;
        HardwareCiDetail d = absent_detail();
        d.software.reset(); // software store degraded or unwired
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["message"] != "not found");
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(t.domain_rows == std::vector<std::string>{"inventory.device.ci|failure|Agent|a"});
        CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_hardware_ci|failure"});
        CHECK(t.domain_details.back() == "hardware CI record (MCP) state=software or tags unreadable");
    }
    SECTION("get: nothing known but the tag read failed is a retryable fault, never not found") {
        Twin t;
        HardwareCiDetail d = absent_detail();
        d.tags.reset(); // tag store degraded or unwired
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["message"] != "not found");
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(t.domain_rows == std::vector<std::string>{"inventory.device.ci|failure|Agent|a"});
        CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_hardware_ci|failure"});
    }
    SECTION("get: both reads degraded is the same retryable fault") {
        Twin t;
        HardwareCiDetail d = absent_detail();
        d.software.reset();
        d.tags.reset();
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    }
    SECTION("get: a genuinely absent device (every read answered, all empty) stays a terminal not found") {
        Twin t;
        t.ci_by_id["a"] = absent_detail();
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"] == "not found");
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(t.domain_rows.empty());
        CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_hardware_ci|failure"});
    }
    SECTION("get: a degraded software read beside a known CI record is still served (the guard is NotFound-only)") {
        Twin t;
        HardwareCiDetail d = full_detail("a");
        d.software.reset();
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["software"].is_null());
    }
    SECTION("get: a degraded identity beside a readable CI record is served, audited as a failure") {
        Twin t;
        HardwareCiDetail d = full_detail("a");
        d.identity.reset();
        d.identity_degraded = true;
        t.ci_by_id["a"] = d;
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE_FALSE(r.contains("error"));
        const auto& sc = r["result"]["structuredContent"];
        CHECK(sc["identity_state"] == "degraded");
        CHECK(sc["ci_state"] == "found");
        CHECK(t.domain_rows.back() == "inventory.device.ci|failure|Agent|a");
        CHECK(t.domain_details.back() ==
              "hardware CI record (MCP) state=found identity=roster unreadable");
    }
    SECTION("get: a degraded CI read keeps the record found and says so") {
        Twin t;
        t.ci_by_id["a"] = HardwareCiDetail{}; // the struct default: ci degraded, nothing else
        const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["ci_state"] == "degraded");
        CHECK(t.domain_details.back() == "hardware CI record (MCP) state=store degraded");
    }
}

// ───────────────────────── fail-closed audit ───────────────────────────────────

TEST_CASE("mcp hardware twins: if either access row does not persist the data is withheld",
          "[mcp][hardware][security]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");

    struct Case {
        const char* tool;
        json args;
        const char* domain_row;
        const char* generic_row;
    };
    const std::vector<Case> cases = {
        {"list_hardware_ci", json::object(), "inventory.devices|success|Inventory|fleet",
         "mcp.list_hardware_ci|success"},
        {"get_hardware_ci", {{"agent_id", "a"}}, "inventory.device.ci|success|Agent|a",
         "mcp.get_hardware_ci|success"},
    };
    for (const auto& c : cases) {
        for (const bool drop_domain : {true, false}) {
            INFO(c.tool << (drop_domain ? " (domain row dropped)" : " (generic row dropped)"));
            t.clear_audit();
            t.domain_audit_ok = !drop_domain;
            t.generic_audit_ok = drop_domain;
            const json r = t.call(c.tool, c.args);
            REQUIRE(r.contains("error"));
            CHECK_FALSE(r.contains("result"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
            // No personal data and no audit_persisted escape hatch anywhere in the answer.
            const std::string body = r.dump();
            CHECK(body.find("SN-a") == std::string::npos);
            CHECK(body.find("uuid-a") == std::string::npos);
            CHECK(body.find("aa:bb:cc") == std::string::npos);
            CHECK(body.find("audit_persisted") == std::string::npos);
            // Both rows were attempted: a drop of one never hides the other.
            CHECK(has(t.domain_rows, c.domain_row));
            CHECK(has(t.generic_rows, c.generic_row));
        }
    }

    // And with both rows persisting the same call serves.
    t.domain_audit_ok = true;
    t.generic_audit_ok = true;
    CHECK_FALSE(t.call("list_hardware_ci").contains("error"));
    CHECK_FALSE(t.call("get_hardware_ci", {{"agent_id", "a"}}).contains("error"));
}

// ───────────────────────── strict arguments ────────────────────────────────────

TEST_CASE("mcp hardware twins: arguments are refused, never clamped or coerced", "[mcp][hardware]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");

    SECTION("list_hardware_ci") {
        const std::vector<json> bad = {
            {{"limit", 0}},        {{"limit", 201}},      {{"limit", "50"}},
            {{"limit", 1.5}},      {{"limit", nullptr}},  {{"limit", true}},
            {{"offset", -1}},      {{"offset", "0"}},     {{"os", "bsd"}},
            {{"os", "Linux"}},     {{"status", "up"}},    {{"sort", "dex"}},
            {{"dir", "up"}},       {{"q", 5}},            {{"q", std::string(257, 'x')}},
            {{"tag", 7}},          {{"tag", "bad key!"}}, {{"tag", std::string(257, 'x')}},
        };
        for (const auto& args : bad) {
            INFO("arguments: " << args.dump());
            t.clear_audit();
            const int roster_before = t.roster_calls;
            const json r = t.call("list_hardware_ci", args);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
            // Judged before the roster is read, and no domain row is written.
            CHECK(t.roster_calls == roster_before);
            CHECK(t.domain_rows.empty());
        }
        // The bounds themselves are accepted, and an unknown key is ignored (REST parity).
        for (const auto& args : std::vector<json>{{{"limit", 1}},
                                                  {{"limit", 200}},
                                                  {{"offset", 0}},
                                                  {{"tag", "role=web"}},
                                                  {{"tag", "role"}},
                                                  {{"bogus", 1}},
                                                  {{"dir", "desc"}, {"sort", "ram"}}}) {
            INFO("arguments: " << args.dump());
            CHECK_FALSE(t.call("list_hardware_ci", args).contains("error"));
        }
    }

    SECTION("get_hardware_ci") {
        const std::vector<json> bad = {
            json::object(),
            {{"agent_id", ""}},
            {{"agent_id", 5}},
            {{"agent_id", nullptr}},
            {{"agent_id", "a\nb"}},
            {{"agent_id", std::string("a\0b", 3)}},
            {{"agent_id", std::string(257, 'x')}},
        };
        for (const auto& args : bad) {
            INFO("arguments: " << args.dump());
            t.clear_audit();
            const json r = t.call("get_hardware_ci", args);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
            CHECK(t.ci_calls == 0);
            CHECK(t.domain_rows.empty());
        }
        // 256 bytes is the inclusive bound: it reaches the store (and reads as not found).
        const json edge = t.call("get_hardware_ci", {{"agent_id", std::string(256, 'x')}});
        CHECK(t.ci_calls == 1);
        REQUIRE(edge.contains("error"));
        CHECK(edge["error"]["message"] == "not found");
    }
}

// ───────────────────────── REST byte identity ──────────────────────────────────

TEST_CASE("mcp hardware twins: list_hardware_ci is the REST data object byte for byte",
          "[mcp][hardware][parity]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "windows", false),
                     make_row("c", "host-c", "linux", true), make_row("d", "host-d", "macos", true)};
    t.roster_rows[1].ci_serial = "unknown"; // a sentinel that must render as null on both
    t.roster_rows[2].ips.clear();
    t.tags_degraded = true;
    t.dex_by_id = {{"a", 90}, {"c", -1}};

    struct Pair {
        std::string rest_query;
        json mcp_args;
    };
    const std::vector<Pair> pairs = {
        {"", json::object()},
        {"?os=linux&status=online&sort=ram&dir=desc", {{"os", "linux"}, {"status", "online"},
                                                        {"sort", "ram"}, {"dir", "desc"}}},
        {"?q=host-b", {{"q", "host-b"}}},
        {"?limit=2&offset=1&sort=name", {{"limit", 2}, {"offset", 1}, {"sort", "name"}}},
        {"?tag=role%3Dweb&limit=3", {{"tag", "role=web"}, {"limit", 3}}},
    };
    for (const auto scope_case : {false, true}) {
        if (scope_case)
            t.scope = std::unordered_set<std::string>{"a", "b", "c"};
        for (const auto& p : pairs) {
            INFO("scoped=" << scope_case << " query: " << p.rest_query);
            const json rest = t.rest_data("/api/v1/hardware" + p.rest_query);
            const json mcp = t.call("list_hardware_ci", p.mcp_args);
            REQUIRE_FALSE(mcp.contains("error"));
            const auto& result = mcp["result"];
            // Global read: the REST bytes exactly. Confined: the REST object with the omitted
            // count replaced by the scope status, the single deliberate difference.
            json expected = rest;
            if (scope_case) {
                expected.erase("devices_omitted");
                expected["scope_basis"] = "authority_scoped";
            }
            if (!scope_case) {
                CHECK(result["structuredContent"]["devices_omitted"] == 0);
                CHECK_FALSE(result["structuredContent"].contains("scope_basis"));
            }
            CHECK(result["structuredContent"].dump() == expected.dump());
            CHECK(result["content"][0]["text"].get<std::string>() == expected.dump());
        }
    }
    CHECK(t.scope.has_value());
    const auto confined = t.call("list_hardware_ci")["result"]["structuredContent"];
    CHECK_FALSE(confined.contains("devices_omitted"));
    CHECK(confined["scope_basis"] == "authority_scoped");
}

TEST_CASE("mcp hardware twins: get_hardware_ci is the REST data object byte for byte",
          "[mcp][hardware][parity]") {
    Twin t;
    t.ci_by_id["full"] = full_detail("full");
    HardwareCiDetail no_sw = full_detail("nosw");
    no_sw.software.reset();
    no_sw.tags.reset();
    no_sw.software_truncated = true;
    no_sw.agent_version.reset();
    no_sw.software_last_seen.reset();
    t.ci_by_id["nosw"] = no_sw;
    HardwareCiDetail ci_only = full_detail("ci");
    ci_only.identity.reset(); // not in the roster, but a CI blob exists
    t.ci_by_id["ci"] = ci_only;
    t.ci_by_id["degraded"] = HardwareCiDetail{};

    for (const char* id : {"full", "nosw", "ci", "degraded"}) {
        INFO("device " << id);
        const json rest = t.rest_data(std::string("/api/v1/hardware/") + id);
        const json mcp = t.call("get_hardware_ci", {{"agent_id", id}});
        REQUIRE_FALSE(mcp.contains("error"));
        CHECK(mcp["result"]["structuredContent"].dump() == rest.dump());
        CHECK(mcp["result"]["content"][0]["text"].get<std::string>() == rest.dump());
    }
}

// ───────────────────────── output schema conformance ───────────────────────────

TEST_CASE("mcp hardware twins: every answer conforms to the published output schema",
          "[mcp][hardware]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "windows", false)};
    t.roster_rows[1].ci_serial = "";
    t.roster_rows[1].ci_cpu_cores = "not-a-number";
    t.roster_rows[1].agent_version.clear();
    t.roster_rows[1].ips.clear();
    t.ci_by_id["a"] = full_detail("a");
    HardwareCiDetail sparse = full_detail("s");
    sparse.identity.reset();
    sparse.software.reset();
    sparse.tags.reset();
    sparse.agent_version.reset();
    sparse.software_last_seen.reset();
    t.ci_by_id["s"] = sparse;
    t.ci_by_id["d"] = HardwareCiDetail{};
    // a v2 record with a populated, a constrained and a failed section, a v2 record whose ci could
    // not be read (sections_state degraded), and one whose sections read failed (an error, below)
    HardwareCiDetail v2 = full_detail("v2");
    {
        DeviceCiSection cpu;
        cpu.kind = "cpu";
        cpu.level = "constrained";
        cpu.reason = "agent:partial";
        cpu.rows = {{"0", "Xeon", "8", "16", "2400", "CPU0", ""}};
        DeviceCiSection swap;
        swap.kind = "swap";
        swap.level = "unavailable";
        swap.reason = "linux:planned";
        v2.ci_sections = std::vector<DeviceCiSection>{cpu, swap};
    }
    t.ci_by_id["v2"] = v2;
    HardwareCiDetail v2_ci_degraded = full_detail("v2d");
    v2_ci_degraded.ci = std::unexpected(CiReadError::kDegraded);
    t.ci_by_id["v2d"] = v2_ci_degraded;

    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const json list_schema = tool_entry(listed, "list_hardware_ci")["outputSchema"];
    const json get_schema = tool_entry(listed, "get_hardware_ci")["outputSchema"];

    for (const bool degraded : {false, true}) {
        t.ci_degraded = degraded;
        const json r = t.call("list_hardware_ci");
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(list_schema, r["result"]["structuredContent"]) == "");
    }
    CHECK(schema_violation(list_schema, t.call("list_hardware_ci", {{"limit", 1}})
                                            ["result"]["structuredContent"]) == "");
    for (const char* id : {"a", "s", "d", "v2", "v2d"}) {
        INFO("device " << id);
        const json r = t.call("get_hardware_ci", {{"agent_id", id}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(get_schema, r["result"]["structuredContent"]) == "");
    }
    // sections_state degraded means ci itself could not be read (ci is null), never a failed
    // sections read: that one is a retryable error (its own test below), as the REST 503 is.
    const json degraded = t.call("get_hardware_ci", {{"agent_id", "v2d"}})["result"]["structuredContent"];
    CHECK(degraded["sections_state"] == "degraded");
    CHECK(degraded["ci"].is_null());
    const json ok = t.call("get_hardware_ci", {{"agent_id", "v2"}})["result"]["structuredContent"];
    CHECK(ok["sections_state"] == "found");
    CHECK(ok["ci"]["sections"].size() == 2);
}

// The REST twin answers a failed sections read 503 + retry_after_ms 5000 and withholds the record:
// MCP answers the same condition with the same kind of failure (a retryable error, the record
// withheld, a failure audit row on both the domain verb and the generic row), never a result.
// Kills: serving the record with `sections: null` as a 200.
TEST_CASE("mcp hardware twins: a failed sections read is a retryable error and withholds the record",
          "[mcp][hardware][sections]") {
    Twin t;
    HardwareCiDetail d = full_detail("a");
    DeviceCiRecord rec = **d.ci;
    rec.blob_version = 2;
    d.ci = std::optional<DeviceCiRecord>(rec);
    d.ci_sections = std::unexpected(CiReadError::kDegraded);
    t.ci_by_id["a"] = d;
    const json r = t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(r.contains("error"));
    CHECK_FALSE(r.contains("result"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["message"] == "hardware sections unavailable");
    CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(mcp::kMcpStoreFaultRetryMs == 5000);
    CHECK(t.domain_rows == std::vector<std::string>{"inventory.device.ci|failure|Agent|a"});
    CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_hardware_ci|failure"});
    CHECK(t.domain_details.back() == "hardware CI record (MCP) state=sections unreadable");
    // the sections arm is reached only after the scope check: an out-of-scope id stays "not found"
    t.clear_audit();
    t.scope = std::unordered_set<std::string>{"other"};
    const json hidden = t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(hidden.contains("error"));
    CHECK(hidden["error"]["message"] == "not found");
    // a lost audit row on the failure path is reported, not hidden
    Twin w;
    w.ci_by_id["a"] = d;
    w.domain_audit_ok = false;
    const json lost = w.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(lost.contains("error"));
    CHECK(lost["error"]["message"] == "hardware sections unavailable");
    CHECK(lost["error"]["data"]["audit_persisted"] == false);
}

// Only the REST record route and this tool ask for the sections.
TEST_CASE("mcp hardware twins: get_hardware_ci asks for the sections and list_hardware_ci never composes a record",
          "[mcp][hardware][sections]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    (void)t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(t.ci_reads.size() == 1);
    CHECK(t.ci_reads.back() == CiRead::WithSections);
    (void)t.call("list_hardware_ci");
    CHECK(t.ci_reads.size() == 1);
}

// The tool description is machine metadata (A5): it names the retryable error and the meaning of
// complete:false, and the output schema describes sections_state.
TEST_CASE("mcp hardware twins: the get_hardware_ci description states the sections contract",
          "[mcp][hardware][sections]") {
    Twin t;
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const json& tool = tool_entry(listed, "get_hardware_ci");
    const std::string desc = tool["description"].get<std::string>();
    const json& schema = tool["outputSchema"];
    REQUIRE_FALSE(desc.empty());
    CHECK(desc.find("not a full read") != std::string::npos);
    CHECK(desc.find("failed sections read") != std::string::npos);
    CHECK(desc.find("retry_after_ms") != std::string::npos);
    CHECK(desc.find("complete false means constrained") == std::string::npos); // the old, wrong wording
    CHECK(schema["properties"]["sections_state"]["description"].get<std::string>().find("retryable") !=
          std::string::npos);
    CHECK_FALSE(schema["properties"]["ci"]["properties"]["sections"]["items"]["properties"]["kind"].contains("enum"));
}

// ───────────────────────── audit row contents ──────────────────────────────────

TEST_CASE("mcp hardware twins: the domain and generic rows carry the REST verbs and comparable details",
          "[mcp][hardware]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    t.scope = std::unordered_set<std::string>{"a"};

    REQUIRE_FALSE(t.call("list_hardware_ci").contains("error"));
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.devices|success|Inventory|fleet");
    // The audit detail carries the scope status, never the hidden-device count.
    CHECK(t.domain_details[0] == "hardware list (MCP): devices=1 scope=authority_scoped");
    CHECK(t.generic_rows == std::vector<std::string>{"mcp.list_hardware_ci|success"});

    // REST writes the same verb, target and detail shape for the same read.
    t.clear_audit();
    (void)t.rest_data("/api/v1/hardware");
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.devices|success|Inventory|fleet");
    CHECK(t.domain_details[0] == "hardware list (REST): devices=1 omitted=1");

    t.clear_audit();
    REQUIRE_FALSE(t.call("get_hardware_ci", {{"agent_id", "a"}}).contains("error"));
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.device.ci|success|Agent|a");
    CHECK(t.domain_details[0] == "hardware CI record (MCP) state=found");
    CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_hardware_ci|success"});

    t.clear_audit();
    (void)t.rest_data("/api/v1/hardware/a");
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.device.ci|success|Agent|a");
    CHECK(t.domain_details[0] == "hardware CI record (REST) state=found");
}

// ───────────────────────── fleet_read_fn is the sole gate ──────────────────────

TEST_CASE("mcp hardware twins: perm_fn is never consulted, a denying perm_fn changes nothing",
          "[mcp][hardware][security]") {
    Twin t;
    t.perm_result = false; // would refuse every call if the handler stacked a second gate
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");

    const json list = t.call("list_hardware_ci");
    REQUIRE_FALSE(list.contains("error"));
    CHECK(list["result"]["structuredContent"]["count"] == 1);
    const json get = t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE_FALSE(get.contains("error"));
    CHECK(get["result"]["structuredContent"]["agent_id"] == "a");
    // Refusal paths do not reach it either.
    (void)t.call("list_hardware_ci", {{"limit", 0}});
    (void)t.call("get_hardware_ci", {{"agent_id", "nope"}});
    CHECK(t.perm_calls == 0);

    // Positive control: in this same harness a registry tool that DOES gate on ctx.perm_fn
    // moves the counter, so the zero above means "not consulted", not "counter never wired".
    (void)t.call("discover_routes");
    CHECK(t.perm_calls >= 1);
}

TEST_CASE("mcp hardware twins: the gate is asked for exactly Inventory:Read, once per call, on every path that reaches it",
          "[mcp][hardware][security]") {
    const std::vector<std::string> once = {"Inventory:Read"};
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    t.ci_by_id["gone"] = absent_detail();
    HardwareCiDetail unreadable = absent_detail();
    unreadable.identity_degraded = true;
    t.ci_by_id["unreadable"] = unreadable;
    t.scope = std::unordered_set<std::string>{"a", "gone", "unreadable"};

    const auto expect_once = [&](const char* what, const char* tool, const json& args) {
        INFO(what);
        t.clear_audit();
        (void)t.call(tool, args);
        CHECK(t.gate_calls == once);
    };
    expect_once("list: served", "list_hardware_ci", json::object());
    expect_once("list: invalid argument", "list_hardware_ci", {{"limit", 0}});
    expect_once("list: invalid tag key", "list_hardware_ci", {{"tag", "bad key!"}});
    expect_once("get: served", "get_hardware_ci", {{"agent_id", "a"}});
    expect_once("get: missing agent_id", "get_hardware_ci", json::object());
    expect_once("get: out of scope", "get_hardware_ci", {{"agent_id", "b"}});
    expect_once("get: absent", "get_hardware_ci", {{"agent_id", "gone"}});
    expect_once("get: roster unreadable", "get_hardware_ci", {{"agent_id", "unreadable"}});

    t.roster_degraded = true;
    expect_once("list: roster degraded", "list_hardware_ci", json::object());
    t.roster_degraded = false;

    t.domain_audit_ok = false;
    expect_once("list: audit withheld", "list_hardware_ci", json::object());
    expect_once("get: audit withheld", "get_hardware_ci", {{"agent_id", "a"}});
    t.domain_audit_ok = true;

    // A refusal by the gate itself is still exactly one ask.
    t.allow_fleet_read = false;
    expect_once("list: gate refused", "list_hardware_ci", json::object());
    expect_once("get: gate refused", "get_hardware_ci", {{"agent_id", "a"}});
    t.allow_fleet_read = true;

    // The unwired checks run before the gate, so they never ask it.
    {
        Twin u(Twin::Opts{.wire_roster = false, .wire_ci = false});
        (void)u.call("list_hardware_ci");
        (void)u.call("get_hardware_ci", {{"agent_id", "a"}});
        CHECK(u.gate_calls.empty());
    }
}

// ───────────────────────── every refusal leaves one generic row ────────────────

TEST_CASE("mcp hardware twins: every refusal path writes exactly one generic row and no stray domain row",
          "[mcp][hardware][audit]") {
    struct Case {
        const char* what;
        const char* tool;
        json args;
        const char* generic_row;
        bool expect_domain_row;
    };
    const auto run = [](Twin& t, const Case& c) {
        t.clear_audit();
        const json r = t.call(c.tool, c.args);
        REQUIRE(r.contains("error"));
        CHECK(t.generic_rows == std::vector<std::string>{c.generic_row});
        CHECK(t.domain_rows.empty() == !c.expect_domain_row);
        return r;
    };

    SECTION("argument and lookup refusals: generic row only") {
        Twin t;
        t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "linux", true)};
        t.ci_by_id["a"] = full_detail("a");
        t.ci_by_id["b"] = full_detail("b");
        t.scope = std::unordered_set<std::string>{"a", "zzz"};
        const std::vector<Case> cases = {
            {"bad list argument", "list_hardware_ci", {{"limit", 0}}, "mcp.list_hardware_ci|denied", false},
            {"bad list tag key", "list_hardware_ci", {{"tag", "bad key!"}}, "mcp.list_hardware_ci|denied",
             false},
            {"missing agent_id", "get_hardware_ci", json::object(), "mcp.get_hardware_ci|denied", false},
            {"control byte in agent_id", "get_hardware_ci", {{"agent_id", "a\nb"}},
             "mcp.get_hardware_ci|denied", false},
            {"out of scope", "get_hardware_ci", {{"agent_id", "b"}}, "mcp.get_hardware_ci|denied", false},
            {"in scope but absent", "get_hardware_ci", {{"agent_id", "zzz"}},
             "mcp.get_hardware_ci|failure", false},
        };
        for (const auto& c : cases) {
            INFO(c.what);
            (void)run(t, c);
        }
    }
    SECTION("unwired and degraded: generic row plus the domain failure row") {
        {
            Twin t(Twin::Opts{.wire_roster = false});
            (void)run(t, {"no roster", "list_hardware_ci", json::object(), "mcp.list_hardware_ci|failure",
                          true});
        }
        {
            Twin t(Twin::Opts{.wire_ci = false});
            (void)run(t, {"no ci", "get_hardware_ci", {{"agent_id", "a"}}, "mcp.get_hardware_ci|failure",
                          true});
        }
        {
            Twin t;
            t.roster_degraded = true;
            (void)run(t, {"roster degraded", "list_hardware_ci", json::object(),
                          "mcp.list_hardware_ci|failure", true});
        }
    }
}

TEST_CASE("mcp hardware twins: get_hardware_ci names an audit-safe id in the refusal rows, never an unsafe one",
          "[mcp][hardware][audit]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    t.scope = std::unordered_set<std::string>{"a", "zzz", "x y=z,w"};

    t.clear_audit();
    (void)t.call("get_hardware_ci", {{"agent_id", "b"}}); // out of scope
    REQUIRE(t.generic_details.size() == 1);
    CHECK(t.generic_details[0] == "device out of the caller's scope id=b");

    t.clear_audit();
    (void)t.call("get_hardware_ci", {{"agent_id", "zzz"}}); // in scope, absent
    REQUIRE(t.generic_details.size() == 1);
    CHECK(t.generic_details[0] == "not found id=zzz");

    // Structured-detail delimiters in the id are neutralised, never forging a field.
    t.clear_audit();
    (void)t.call("get_hardware_ci", {{"agent_id", "x y=z,w"}});
    REQUIRE(t.generic_details.size() == 1);
    CHECK(t.generic_details[0] == "not found id=x_y_z_w");

    // An id that fails the audit-safety check is refused before any row can name it.
    t.clear_audit();
    (void)t.call("get_hardware_ci", {{"agent_id", "a\nforged=1"}});
    REQUIRE(t.generic_details.size() == 1);
    CHECK(t.generic_details[0] == "invalid arguments: agent_id");
}

// ───────────────────────── deny-all scope ──────────────────────────────────────

TEST_CASE("mcp hardware twins: a present-empty scope is deny-all, never the whole fleet",
          "[mcp][hardware][security]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true), make_row("b", "host-b", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");
    t.scope = std::unordered_set<std::string>{};

    const json list = t.call("list_hardware_ci");
    REQUIRE_FALSE(list.contains("error"));
    const auto& sc = list["result"]["structuredContent"];
    CHECK(sc["devices"].empty());
    CHECK(sc["count"] == 0);
    CHECK_FALSE(sc.contains("devices_omitted"));
    CHECK(sc["scope_basis"] == "authority_scoped");
    CHECK(sc["kpis"]["total"] == 0);
    CHECK(t.dex_calls_for.empty());

    const json get = t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(get.contains("error"));
    CHECK(get["error"]["message"] == "not found");
    CHECK(t.ci_calls == 0); // the record of a hidden device is never composed
    CHECK(get.dump().find("SN-a") == std::string::npos);
}

// ───────────────────────── missing audit sink fails closed ─────────────────────

TEST_CASE("mcp hardware twins: a missing domain audit sink is unwired, not audit off",
          "[mcp][hardware][security][audit]") {
    Twin t(Twin::Opts{.wire_audit = false});
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.ci_by_id["a"] = full_detail("a");

    for (const auto& [tool, args, generic_row] : std::vector<std::tuple<std::string, json, std::string>>{
             {"list_hardware_ci", json::object(), "mcp.list_hardware_ci|failure"},
             {"get_hardware_ci", {{"agent_id", "a"}}, "mcp.get_hardware_ci|failure"}}) {
        INFO(tool);
        t.clear_audit();
        const json r = t.call(tool, args);
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null()); // misconfiguration, not transient
        CHECK(r.dump().find("SN-a") == std::string::npos);
        CHECK(t.generic_rows == std::vector<std::string>{generic_row});
    }
    // The unwired check precedes the read: nothing was fetched.
    CHECK(t.roster_calls == 0);
    CHECK(t.ci_calls == 0);
}

// ───────────────────────── a dropped denial row is reported ────────────────────

TEST_CASE("mcp hardware twins: a dropped refusal row surfaces as audit_persisted:false in the envelope",
          "[mcp][hardware][audit]") {
    Twin t;
    t.roster_rows = {make_row("a", "host-a", "linux", true)};
    t.scope = std::unordered_set<std::string>{"a"};
    const std::vector<std::pair<std::string, json>> refusals = {
        {"list_hardware_ci", {{"limit", 0}}},
        {"list_hardware_ci", {{"tag", "bad key!"}}},
        {"get_hardware_ci", json::object()},
        {"get_hardware_ci", {{"agent_id", "b"}}},   // out of scope
        {"get_hardware_ci", {{"agent_id", "a"}}},   // in scope, absent
    };
    for (const bool persisted : {true, false}) {
        t.generic_audit_ok = persisted;
        for (const auto& [tool, args] : refusals) {
            INFO(tool << " " << args.dump() << " persisted=" << persisted);
            const json r = t.call(tool, args);
            REQUIRE(r.contains("error"));
            // The key is present (false) only when the row was dropped.
            if (persisted)
                CHECK_FALSE(r["error"]["data"].contains("audit_persisted"));
            else
                CHECK(r["error"]["data"]["audit_persisted"] == false);
        }
    }
}

TEST_CASE("mcp hardware twins: unwired and roster-unreadable answers report audit_persisted:false when EITHER row drops",
          "[mcp][hardware][audit]") {
    // answer_unwired and answer_roster_unreadable both attempt the domain row AND the generic
    // row (no short-circuit) and pass `domain_ok && generic_ok`: the flag is present (false)
    // exactly when at least one of the two was dropped, never when both persisted.
    struct Setup {
        const char* what;
        const char* tool;
        json args;
        std::function<void(Twin&)> degrade;
        bool wire_roster = true;
        bool wire_ci = true;
    };
    const std::vector<Setup> setups = {
        {"list: unwired", "list_hardware_ci", json::object(), [](Twin&) {}, false, true},
        {"get: unwired", "get_hardware_ci", {{"agent_id", "a"}}, [](Twin&) {}, true, false},
        {"list: roster degraded", "list_hardware_ci", json::object(),
         [](Twin& t) { t.roster_degraded = true; }},
        {"get: identity fallback failed", "get_hardware_ci", {{"agent_id", "a"}},
         [](Twin& t) {
             HardwareCiDetail d = absent_detail();
             d.identity_degraded = true;
             t.ci_by_id["a"] = d;
         }},
        {"get: nothing known and software unreadable", "get_hardware_ci", {{"agent_id", "a"}},
         [](Twin& t) {
             HardwareCiDetail d = absent_detail();
             d.software.reset();
             t.ci_by_id["a"] = d;
         }},
        {"get: nothing known and tags unreadable", "get_hardware_ci", {{"agent_id", "a"}},
         [](Twin& t) {
             HardwareCiDetail d = absent_detail();
             d.tags.reset();
             t.ci_by_id["a"] = d;
         }},
    };
    for (const auto& su : setups) {
        for (const bool domain_ok : {true, false}) {
            for (const bool generic_ok : {true, false}) {
                INFO(su.what << " domain_ok=" << domain_ok << " generic_ok=" << generic_ok);
                Twin t(Twin::Opts{.wire_roster = su.wire_roster, .wire_ci = su.wire_ci});
                su.degrade(t);
                t.domain_audit_ok = domain_ok;
                t.generic_audit_ok = generic_ok;
                const json r = t.call(su.tool, su.args);
                REQUIRE(r.contains("error"));
                // Both rows were attempted whichever one dropped.
                CHECK(t.domain_rows.size() == 1);
                CHECK(t.generic_rows.size() == 1);
                if (domain_ok && generic_ok)
                    CHECK_FALSE(r["error"]["data"].contains("audit_persisted"));
                else
                    CHECK(r["error"]["data"]["audit_persisted"] == false);
            }
        }
    }
}

// ───────────────────────── invalid UTF-8 in agent-reported text ────────────────

TEST_CASE("mcp hardware twins: invalid UTF-8 in a roster or CI field degrades to U+FFFD, never throws",
          "[mcp][hardware]") {
    Twin t;
    InventoryDeviceRow row = make_row("a", "host-\xff", "linux", true);
    row.ci_serial = "SN-\xc3(";
    t.roster_rows = {row};
    HardwareCiDetail d = full_detail("a");
    (*d.ci)->serial = "SN-\xff\xfe";
    (*d.ci)->model = "M\x80";
    t.ci_by_id["a"] = d;

    const std::string replacement = "\xEF\xBF\xBD";

    json list;
    REQUIRE_NOTHROW(list = t.call("list_hardware_ci"));
    REQUIRE_FALSE(list.contains("error"));
    const std::string list_text = list["result"]["content"][0]["text"].get<std::string>();
    CHECK(list_text.find(replacement) != std::string::npos);
    CHECK(list["result"]["structuredContent"]["devices"][0]["hostname"].get<std::string>().find(
              replacement) != std::string::npos);
    CHECK(has(t.generic_rows, "mcp.list_hardware_ci|success"));

    json get;
    REQUIRE_NOTHROW(get = t.call("get_hardware_ci", {{"agent_id", "a"}}));
    REQUIRE_FALSE(get.contains("error"));
    const std::string get_text = get["result"]["content"][0]["text"].get<std::string>();
    CHECK(get_text.find(replacement) != std::string::npos);
    CHECK(get["result"]["structuredContent"]["ci"]["serial"].get<std::string>().find(replacement) !=
          std::string::npos);
    CHECK(has(t.generic_rows, "mcp.get_hardware_ci|success"));
}

// ───────────────────────── schema vs parser round trip ─────────────────────────

TEST_CASE("mcp hardware twins: the advertised enum tokens and the argument parser accept the same set",
          "[mcp][hardware][args]") {
    Twin t;
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const auto& props = tool_entry(listed, "list_hardware_ci")["inputSchema"]["properties"];

    const auto tokens_of = [&](const char* prop) {
        std::set<std::string> out;
        for (const auto& e : props[prop]["enum"])
            out.insert(e.get<std::string>());
        return out;
    };

    // Forward: every advertised token is accepted by the parser AND survives normalisation,
    // and lands in the field it names.
    for (const char* prop : {"os", "status", "sort", "dir"}) {
        for (const auto& tok : tokens_of(prop)) {
            INFO(prop << "=" << tok);
            const auto q = hardware_query_from_args(json{{prop, tok}});
            REQUIRE(q.has_value());
            REQUIRE(normalise_hardware_query(*q).has_value());
            const std::string p = prop;
            if (p == "os")
                CHECK(q->os == tok);
            else if (p == "status")
                CHECK(q->status == tok);
            else if (p == "sort")
                CHECK(q->sort == tok);
            else
                CHECK(q->desc == (tok == "desc"));
        }
    }

    // Reverse: sort is pinned to the model's own key enum (every HwSortKey token is
    // advertised, and nothing else is), so a new key without a schema edit fails here.
    // The loop is bounded by the enum's last enumerator, never by the fallthrough, so a changed
    // fallthrough cannot hang it. The CHECK below pins "Ip is last": the value one past it must
    // still read as the out-of-range fallthrough, so a key added after Ip fails here.
    constexpr int kHwSortKeyCount = static_cast<int>(HwSortKey::Ip) + 1;
    static_assert(kHwSortKeyCount == 12, "HwSortKey changed: update the schema enum and this count");
    std::set<std::string> model_sort_tokens;
    for (int i = 0; i < kHwSortKeyCount; ++i)
        model_sort_tokens.insert(std::string(hw_sort_token(static_cast<HwSortKey>(i))));
    CHECK(hw_sort_token(static_cast<HwSortKey>(kHwSortKeyCount)) == "name");
    CHECK(model_sort_tokens == tokens_of("sort"));

    // Reverse for os / status / dir: the accepted set is private to the parser, so probe a
    // universe of plausible tokens (case variants, synonyms, empty) and require that exactly
    // the advertised ones are accepted.
    const std::vector<std::string> universe = {
        "",        "all",     "ALL",    "All",    "windows", "Windows", "win",     "linux",
        "Linux",   "macos",   "MacOS",  "mac",    "darwin",  "bsd",     "online", "Online",
        "offline", "up",      "down",   "asc",    "desc",    "ASC",     "DESC",   "ascending",
        "descending", "name", "ip",     "none",   "any"};
    for (const char* prop : {"os", "status", "dir"}) {
        const auto advertised = tokens_of(prop);
        for (const auto& tok : universe) {
            INFO(prop << "=" << tok);
            CHECK(hardware_query_from_args(json{{prop, tok}}).has_value() == (advertised.count(tok) == 1));
        }
    }
}

TEST_CASE("mcp hardware twins: the schema states the byte bound and the case rule in prose",
          "[mcp][hardware]") {
    Twin t;
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const auto& lp = tool_entry(listed, "list_hardware_ci")["inputSchema"]["properties"];
    const auto& gp = tool_entry(listed, "get_hardware_ci")["inputSchema"]["properties"];
    for (const json* p : {&lp["q"], &lp["tag"], &gp["agent_id"]}) {
        CHECK((*p)["maxLength"] == 256);
        CHECK((*p)["description"].get<std::string>().find("256 bytes") != std::string::npos);
    }
    for (const char* prop : {"os", "status", "sort", "dir"})
        CHECK(lp[prop]["description"].get<std::string>().find("Case-sensitive lowercase") !=
              std::string::npos);
    CHECK(tool_entry(listed, "get_hardware_ci")["description"].get<std::string>().find(
              "only the audit row") == std::string::npos);
}

// ───────────────────── served section integrity faults are counted (#7159) ─────────────────────

namespace {
// A cpu section whose stored digest and row count describe `good` rows, served with `served` rows.
DeviceCiSection cpu_section_serving(std::vector<std::vector<std::string>> good,
                                    std::vector<std::vector<std::string>> served) {
    DeviceCiSection s;
    s.kind = "cpu";
    s.level = "ok";
    const auto idx = device_ci_section_index("cpu");
    s.row_count = static_cast<int>(good.size());
    s.content_digest = section_content_digest(kDeviceCiSections[*idx], good);
    s.rows = std::move(served);
    return s;
}

double integrity(Twin& t, const char* reason) {
    return t.metrics.counter("yuzu_hardware_section_integrity_total", {{"reason", reason}}).value();
}
} // namespace

// Kills: counting in a place only one transport reaches, counting a section the body does not
// serve as faulted, and a counted cause that differs from the served token. REST and MCP read the
// same device, so each read moves the counter by exactly one and the body carries the same token.
TEST_CASE("mcp hardware twins: a served integrity fault is counted once per read and agrees with "
          "the body",
          "[mcp][hardware][sections][metrics]") {
    const std::vector<std::vector<std::string>> r2 = {{"0", "Xeon", "8", "16", "2400", "CPU0", ""},
                                                      {"1", "Xeon", "8", "16", "2400", "CPU1", ""}};
    Twin t;
    t.roster_rows = {make_row("rc", "h", "linux", true), make_row("cd", "h", "linux", true),
                     make_row("ok", "h", "linux", true)};
    auto with_cpu = [&](const char* id, DeviceCiSection cpu) {
        HardwareCiDetail d = full_detail(id);
        d.ci_sections = std::vector<DeviceCiSection>{std::move(cpu)};
        t.ci_by_id[id] = d;
    };
    with_cpu("rc", cpu_section_serving(r2, {r2[0]})); // one row lost: the count disagrees
    auto edited = r2;
    edited[1][1] = "Edited";
    with_cpu("cd", cpu_section_serving(r2, edited)); // same count, different content
    with_cpu("ok", cpu_section_serving(r2, r2));     // intact

    const auto served_reason = [&](const json& sc) {
        return sc["ci"]["sections"][0]["reason"].get<std::string>();
    };

    // MCP: row-count fault.
    const json rc = t.call("get_hardware_ci", {{"agent_id", "rc"}})["result"]["structuredContent"];
    CHECK(served_reason(rc) == section_fault_token(SectionFault::RowCount));
    CHECK(integrity(t, "row_count_mismatch") == 1.0);
    CHECK(integrity(t, "content_digest_mismatch") == 0.0);
    // REST reads the same record: counted again (served reads, not distinct defects).
    const json rest_rc = t.rest_data("/api/v1/hardware/rc");
    CHECK(served_reason(rest_rc) == served_reason(rc)); // the transports agree byte for byte
    // The rows of a faulted section are withheld on BOTH transports, identically (#7165).
    CHECK(rc["ci"]["sections"][0]["rows"].empty());
    CHECK(rest_rc["ci"]["sections"][0] == rc["ci"]["sections"][0]);
    CHECK(integrity(t, "row_count_mismatch") == 2.0);

    // Content fault, both transports.
    const json cd = t.call("get_hardware_ci", {{"agent_id", "cd"}})["result"]["structuredContent"];
    CHECK(served_reason(cd) == section_fault_token(SectionFault::Content));
    const json rest_cd = t.rest_data("/api/v1/hardware/cd"); // one read: each composed read is counted
    CHECK(rest_cd["ci"]["sections"][0]["reason"] == served_reason(cd));
    CHECK(cd["ci"]["sections"][0]["rows"].empty());
    CHECK(rest_cd["ci"]["sections"][0] == cd["ci"]["sections"][0]);
    // An intact section keeps its rows (the withholding is per fault, not per read).
    const json intact = t.call("get_hardware_ci", {{"agent_id", "ok"}})["result"]["structuredContent"];
    CHECK(intact["ci"]["sections"][0]["rows"].size() == 2);
    CHECK(integrity(t, "content_digest_mismatch") == 2.0);
    CHECK(integrity(t, "row_count_mismatch") == 2.0);
    CHECK(integrity(t, "digest_unverifiable") == 0.0);

    // An intact device and a list read count nothing.
    (void)t.call("get_hardware_ci", {{"agent_id", "ok"}});
    (void)t.rest_data("/api/v1/hardware/ok");
    (void)t.call("list_hardware_ci");
    CHECK(integrity(t, "row_count_mismatch") == 2.0);
    CHECK(integrity(t, "content_digest_mismatch") == 2.0);
}

// Kills: a tool or route that reaches its ci_detail_fn before the scope check - the fake records
// every call, so a fetch for an out-of-scope id shows in `ci_reads` (and, were it counted, would
// move a fleet-wide counter and let a caller probe which hidden ids carry damage). Each transport
// is checked on its own, and the in-scope read afterwards proves the recorder is not vacuous.
TEST_CASE("mcp hardware twins: an out-of-scope read does not fetch the record or move the "
          "integrity counter",
          "[mcp][hardware][sections][metrics][security]") {
    const std::vector<std::vector<std::string>> r2 = {{"0", "Xeon", "8", "16", "2400", "CPU0", ""},
                                                      {"1", "Xeon", "8", "16", "2400", "CPU1", ""}};
    Twin t;
    t.roster_rows = {make_row("a", "h", "linux", true), make_row("hidden", "h", "linux", true)};
    HardwareCiDetail d = full_detail("hidden");
    d.ci_sections = std::vector<DeviceCiSection>{cpu_section_serving(r2, {r2[0]})}; // faulted
    t.ci_by_id["hidden"] = d;
    HardwareCiDetail in_scope = full_detail("a");
    in_scope.ci_sections =
        std::vector<DeviceCiSection>{cpu_section_serving(r2, {r2[0]})}; // faulted
    t.ci_by_id["a"] = in_scope;
    t.scope = std::unordered_set<std::string>{"a"};

    const json mcp = t.call("get_hardware_ci", {{"agent_id", "hidden"}});
    REQUIRE(mcp.contains("error"));
    CHECK(mcp["error"]["code"] == mcp::kInvalidParams);
    CHECK(mcp["error"]["message"] == "not found");
    CHECK(t.ci_reads.empty()); // the MCP twin never fetched
    CHECK(integrity(t, "row_count_mismatch") == 0.0);
    auto res = t.sink.Get("/api/v1/hardware/hidden");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(t.ci_reads.empty()); // nor did the REST route
    CHECK(integrity(t, "row_count_mismatch") == 0.0);
    // The in-scope (faulted) device fetches exactly once and counts once.
    (void)t.call("get_hardware_ci", {{"agent_id", "a"}});
    REQUIRE(t.ci_reads.size() == 1);
    CHECK(t.ci_reads[0] == CiRead::WithSections);
    CHECK(integrity(t, "row_count_mismatch") == 1.0);
}

// ───────────────────── list_hardware_ci_records: the bulk keyset twin ─────────────────────
// The MCP twin of GET /api/v1/hardware-ci. It is a separate tool, not a mode of
// list_hardware_ci: that tool is roster-driven with offset paging and one output schema, and
// the bulk page reads the CI table with cursor paging and a different row.

namespace {

void seed(Twin& t, std::initializer_list<const char*> ids) {
    for (const char* id : ids)
        t.ci_store.add(std::string(id));
}

std::vector<std::string> record_ids(const json& structured) {
    std::vector<std::string> out;
    for (const auto& d : structured["devices"])
        out.push_back(d["agent_id"].get<std::string>());
    return out;
}

} // namespace

TEST_CASE("mcp list_hardware_ci_records: served as a confined Inventory:Read read with typed, bounded schemas",
          "[mcp][hardware][ci_page][registry_seam]") {
    Twin t;
    const auto rows = mcp::tool_security_rows_for_test();
    const auto it = std::find_if(rows.begin(), rows.end(),
                                 [](const auto& r) { return r.name == "list_hardware_ci_records"; });
    REQUIRE(it != rows.end());
    CHECK(it->securable == "Inventory");
    CHECK(it->operation == "Read");
    CHECK(it->service_scope == mcp::ServiceScopeClassForTest::kConfined);

    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    const json& tool = tool_entry(listed, "list_hardware_ci_records");
    CHECK(tool["annotations"]["readOnlyHint"] == true);
    CHECK(tool["annotations"]["idempotentHint"] == true);
    CHECK(tool["outputSchema"]["type"] == "object");
    CHECK(tool["outputSchema"]["required"] == json::array({"devices", "next_cursor"}));
    const auto& p = tool["inputSchema"]["properties"];
    CHECK(p["limit"]["minimum"] == 1);
    CHECK(p["limit"]["maximum"] == 1000);
    CHECK(p["limit"]["default"] == 20); // the handler's default (agents), not REST's 100
    CHECK(p["cursor"]["maxLength"] == 2048);
    CHECK(p["agent_id"]["minLength"] == 1);
    CHECK(p["agent_id"]["maxLength"] == 256);
    const std::string desc = tool["description"].get<std::string>();
    CHECK(desc.find("retry_after_ms") != std::string::npos);
    // the decision-grade facts a worker needs before it calls
    for (const char* needle : {"more than 10000 devices", "-32602", "scope_basis", "daily-sync snapshot",
                               "from list_hardware_ci", "indistinguishable", "limit up to 20",
                               "GET /api/v1/hardware-ci", "byte order", "not a snapshot",
                               "confirm a device with agent_id before you retire it",
                               "empty devices array without agent_id"})
        CHECK(desc.find(needle) != std::string::npos);
    // The agentic guidance LEADS (it comes before the CMDB walk instructions), and the retired
    // "built for a daily pull" lead and the old default are gone.
    CHECK(desc.find("For agentic workers") < desc.find("To walk the records"));
    CHECK(desc.find("Built for a daily pull") == std::string::npos);
    CHECK(desc.find("(default 100)") != std::string::npos); // REST's default, named as REST's
    CHECK(desc.find("limit is 1..1000 (default 20)") != std::string::npos);
    CHECK(desc.find("Rows are in agent_id order") == std::string::npos);
    // the retired wide-scope remark is gone
    CHECK(desc.find("can be empty while next_cursor is not") == std::string::npos);
    CHECK(desc.find("devices_omitted") == std::string::npos);
    CHECK(tool["outputSchema"]["properties"].contains("scope_basis"));
    CHECK_FALSE(tool["outputSchema"]["properties"].contains("devices_omitted"));
    // and the roster tool points at the bulk one
    CHECK(tool_entry(listed, "list_hardware_ci")["description"].get<std::string>().find(
              "list_hardware_ci_records") != std::string::npos);
}

TEST_CASE("mcp list_hardware_ci_records: the page is the REST data object byte for byte, and walks to the end",
          "[mcp][hardware][ci_page]") {
    Twin t;
    seed(t, {"a", "b", "c", "d", "e"});

    std::vector<std::string> seen;
    std::string cursor;
    for (int pages = 0; pages < 10; ++pages) {
        json args = {{"limit", 2}};
        std::string url = "/api/v1/hardware-ci?limit=2";
        if (!cursor.empty()) {
            args["cursor"] = cursor;
            url += "&cursor=" + cursor;
        }
        const json mcp_r = t.call("list_hardware_ci_records", args);
        REQUIRE_FALSE(mcp_r.contains("error"));
        const json mcp_page = mcp_r["result"]["structuredContent"];
        const json rest_page = t.rest_data(url);
        CHECK(mcp_page == rest_page); // global read: the MCP body is the REST data object
        for (const auto& id : record_ids(mcp_page))
            seen.push_back(id);
        cursor = mcp_page["next_cursor"].get<std::string>();
        if (cursor.empty())
            break;
    }
    CHECK(seen == std::vector<std::string>{"a", "b", "c", "d", "e"});
}

TEST_CASE("mcp list_hardware_ci_records: output conforms to its schema, v1 and v2 rows alike",
          "[mcp][hardware][ci_page]") {
    Twin t;
    auto v1 = yuzu::server::test::make_ci_record("old");
    v1.blob_version = 1;
    t.ci_store.add(v1);
    seed(t, {"new"});
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json schema = tool_entry(json::parse(res->body), "list_hardware_ci_records")["outputSchema"];
    const json r = t.call("list_hardware_ci_records");
    REQUIRE_FALSE(r.contains("error"));
    CHECK(schema_violation(schema, r["result"]["structuredContent"]) == "");
    // an empty store is a valid, empty page
    Twin empty;
    CHECK(schema_violation(schema, empty.call("list_hardware_ci_records")["result"]["structuredContent"]) ==
          "");
}

TEST_CASE("mcp list_hardware_ci_records: a confined caller sees only its scope and is not told what was hidden",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"in-a", "in-b", "out-c", "out-d"});
    t.scope = std::unordered_set<std::string>{"in-a", "in-b"};

    std::vector<std::string> seen;
    std::string cursor;
    for (int pages = 0; pages < 10; ++pages) {
        json args = {{"limit", 1}};
        if (!cursor.empty())
            args["cursor"] = cursor;
        const json r = t.call("list_hardware_ci_records", args);
        REQUIRE_FALSE(r.contains("error"));
        const json sc = r["result"]["structuredContent"];
        CHECK(sc["scope_basis"] == "authority_scoped");
        CHECK_FALSE(sc.contains("devices_omitted")); // no count of what lies outside the scope
        CHECK(r.dump().find("out-") == std::string::npos);
        for (const auto& id : record_ids(sc))
            seen.push_back(id);
        cursor = sc["next_cursor"].get<std::string>();
        if (cursor.empty())
            break;
    }
    CHECK(seen == std::vector<std::string>{"in-a", "in-b"});

    // A named device outside the scope reads as an empty page and carries none of its bytes; the
    // audit rows (domain verb and generic) record a refusal, not a served page.
    t.clear_audit();
    const int reads_before = t.ci_store.reads;
    const json named = t.call("list_hardware_ci_records", {{"agent_id", "out-c"}});
    REQUIRE_FALSE(named.contains("error"));
    CHECK(record_ids(named["result"]["structuredContent"]).empty());
    CHECK(named.dump().find("out-c") == std::string::npos);
    CHECK(t.ci_store.reads == reads_before); // no SQL for a device outside the scope
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.devices.ci|denied|Agent|out-c");
    CHECK(t.domain_details[0] == "hardware CI records (MCP) state=agent_id outside the caller's scope");
    REQUIRE(t.generic_rows.size() == 1);
    CHECK(t.generic_rows[0] == "mcp.list_hardware_ci_records|denied");

    // A global-read caller gets no scope_basis, and nobody gets a count of hidden devices.
    Twin g;
    seed(g, {"a"});
    const json gr = g.call("list_hardware_ci_records");
    CHECK_FALSE(gr["result"]["structuredContent"].contains("devices_omitted"));
    CHECK_FALSE(gr["result"]["structuredContent"].contains("scope_basis"));
}

// The audit detail grammar, as exact strings, on this transport.
TEST_CASE("mcp list_hardware_ci_records: audit detail is the exact documented grammar",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"a", "b", "c"});

    const auto last = [&]() {
        REQUIRE_FALSE(t.domain_details.empty());
        REQUIRE(t.generic_details.size() == t.domain_details.size());
        CHECK(t.generic_details.back() == t.domain_details.back()); // the same text on both rows
        return t.domain_details.back();
    };
    t.clear_audit();
    json first = t.call("list_hardware_ci_records", {{"limit", 2}});
    CHECK(last() == "hardware CI records (MCP): rows=2 scope=fleet");
    CHECK(t.domain_rows.back() == "inventory.devices.ci|success|Inventory|fleet");
    CHECK(t.generic_rows.back() == "mcp.list_hardware_ci_records|success");

    const std::string cursor = first["result"]["structuredContent"]["next_cursor"];
    REQUIRE_FALSE(cursor.empty());
    t.clear_audit();
    (void)t.call("list_hardware_ci_records", {{"limit", 2}, {"cursor", cursor}});
    CHECK(last() == "hardware CI records (MCP): rows=1 page=continuation scope=fleet");

    t.clear_audit();
    (void)t.call("list_hardware_ci_records", {{"agent_id", "b"}});
    CHECK(last() == "hardware CI records (MCP): rows=1 scope=fleet");
    CHECK(t.domain_rows.back() == "inventory.devices.ci|success|Agent|b");

    t.scope = std::unordered_set<std::string>{"a", "b"};
    t.clear_audit();
    (void)t.call("list_hardware_ci_records");
    CHECK(last() == "hardware CI records (MCP): rows=2 scope=authority_scoped");

    t.ci_store.degraded = true;
    t.clear_audit();
    (void)t.call("list_hardware_ci_records");
    CHECK(t.domain_rows.back() == "inventory.devices.ci|failure|Inventory|fleet");
    CHECK(t.domain_details.back() == "hardware CI records (MCP) state=store unreadable");
}

// An out-of-scope id that exists and an in-scope id with no record are the
// same bytes (apart from the per-request correlation id); only the audit outcome differs.
TEST_CASE("mcp list_hardware_ci_records: an out-of-scope id and an unknown id answer identically",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"in-a", "out-b"});
    t.scope = std::unordered_set<std::string>{"in-a", "in-ghost"};

    t.clear_audit();
    json hidden = t.call("list_hardware_ci_records", {{"agent_id", "out-b"}});
    const std::string hidden_row = t.domain_rows.back() + " / " + t.domain_details.back();
    t.clear_audit();
    json ghost = t.call("list_hardware_ci_records", {{"agent_id", "in-ghost"}});
    const std::string ghost_row = t.domain_rows.back() + " / " + t.domain_details.back();

    REQUIRE_FALSE(hidden.contains("error"));
    REQUIRE_FALSE(ghost.contains("error"));
    CHECK(hidden["result"] == ghost["result"]);
    CHECK(hidden["result"]["structuredContent"]["devices"].empty());
    CHECK(hidden["result"]["structuredContent"]["next_cursor"] == "");
    CHECK(hidden_row ==
          "inventory.devices.ci|denied|Agent|out-b / hardware CI records (MCP) state=agent_id outside the caller's scope");
    CHECK(ghost_row ==
          "inventory.devices.ci|success|Agent|in-ghost / hardware CI records (MCP): rows=0 scope=authority_scoped");
}

// A denied named read is still a fail-closed audit on this transport.
TEST_CASE("mcp list_hardware_ci_records: a denied named read is withheld when either audit row is dropped",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"out-b"});
    t.scope = std::unordered_set<std::string>{"in-a"};
    for (const bool drop_domain : {true, false}) {
        t.clear_audit();
        t.domain_audit_ok = !drop_domain;
        t.generic_audit_ok = drop_domain;
        const json r = t.call("list_hardware_ci_records", {{"agent_id", "out-b"}});
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
    }
}

namespace {

authz::VisibleSet mcp_scope_of_size(std::initializer_list<const char*> real, std::size_t n) {
    std::unordered_set<std::string> ids;
    for (const char* r : real)
        ids.insert(r);
    for (int i = 0; ids.size() < n; ++i)
        ids.insert("pad-" + std::to_string(i));
    return ids;
}

} // namespace

// Kills: a `>=` ceiling, and a scope at the ceiling not reaching SQL as the full id list.
TEST_CASE("mcp list_hardware_ci_records: a scope of exactly 10000 ids is pushed into SQL and pages exactly",
          "[mcp][hardware][ci_page][ceiling]") {
    Twin t;
    seed(t, {"in-a", "out-b", "in-d"});
    t.scope = mcp_scope_of_size({"in-a", "in-d"}, 10000);
    const json r = t.call("list_hardware_ci_records", {{"limit", 1}});
    REQUIRE_FALSE(r.contains("error"));
    CHECK(record_ids(r["result"]["structuredContent"]) == std::vector<std::string>{"in-a"});
    CHECK(r["result"]["structuredContent"]["next_cursor"] != "");
    REQUIRE(t.ci_store.queries.size() == 1);
    REQUIRE(t.ci_store.queries[0].agent_ids.has_value());
    CHECK(t.ci_store.queries[0].agent_ids->size() == 10000);
}

// Kills: reading a scope above the ceiling; answering it as retryable; dropping the audit row or
// putting a count in it.
TEST_CASE("mcp list_hardware_ci_records: a scope of 10001 ids and no agent_id is a terminal -32602 with zero reads",
          "[mcp][hardware][ci_page][ceiling]") {
    Twin t;
    seed(t, {"in-a", "out-b", "in-d"});
    t.scope = mcp_scope_of_size({"in-a", "in-d"}, 10001);
    t.clear_audit();
    const json r = t.call("list_hardware_ci_records");
    REQUIRE(r.contains("error"));
    CHECK_FALSE(r.contains("result"));
    CHECK(r["error"]["code"] == mcp::kInvalidParams);
    CHECK(r["error"]["message"] ==
          "the caller's scope covers more than 10000 devices and no agent_id was given; a credential with global read has no such limit");
    CHECK(r["error"]["data"]["remediation"] == "use a credential with global read, pass agent_id, or ask an administrator to narrow the caller's scope");
    CHECK(r["error"]["data"]["retry_after_ms"].is_null()); // terminal: nothing to wait for
    // The control for the dropped-row test below: both rows persisted here, so the flag is absent.
    CHECK_FALSE(r["error"]["data"].contains("audit_persisted"));
    CHECK(t.ci_store.reads == 0);
    CHECK(r.dump().find("in-a") == std::string::npos);
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "inventory.devices.ci|denied|Inventory|fleet");
    CHECK(t.domain_details[0] == "hardware CI records (MCP) state=scope too wide");
    REQUIRE(t.generic_rows.size() == 1);
    CHECK(t.generic_rows[0] == "mcp.list_hardware_ci_records|denied");

    // distinct from the store-degrade answer, even with a degraded store
    Twin d;
    d.scope = mcp_scope_of_size({"x"}, 10001);
    d.ci_store.degraded = true;
    const json dr = d.call("list_hardware_ci_records");
    REQUIRE(dr.contains("error"));
    CHECK(dr["error"]["code"] == mcp::kInvalidParams);
    CHECK(d.ci_store.reads == 0);
}

// The scope refusal serves nothing, so its two audit rows are best effort: when either does not
// persist the -32602 stands and the error data says audit_persisted:false. Kills: turning the
// refusal into a retryable kInternalError like a withheld page, or hiding the dropped row.
TEST_CASE("mcp list_hardware_ci_records: scope-too-wide -32602 stands, audit_persisted false, when a row is dropped",
          "[mcp][hardware][ci_page][ceiling][security]") {
    for (const bool drop_domain : {true, false}) {
        INFO((drop_domain ? "domain row dropped" : "generic row dropped"));
        Twin t;
        seed(t, {"in-a", "in-d"});
        t.scope = mcp_scope_of_size({"in-a", "in-d"}, 10001);
        t.clear_audit();
        t.domain_audit_ok = !drop_domain;
        t.generic_audit_ok = drop_domain;
        const json r = t.call("list_hardware_ci_records");
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
        CHECK(t.ci_store.reads == 0);
        CHECK(r.dump().find("in-a") == std::string::npos);
    }
}

TEST_CASE("mcp list_hardware_ci_records: a scope of 10001 ids with an agent_id reads that one device by key",
          "[mcp][hardware][ci_page][ceiling]") {
    Twin t;
    seed(t, {"in-a", "out-b", "in-d"});
    t.scope = mcp_scope_of_size({"in-a", "in-d"}, 10001);

    const json ok = t.call("list_hardware_ci_records", {{"agent_id", "in-d"}});
    REQUIRE_FALSE(ok.contains("error"));
    CHECK(record_ids(ok["result"]["structuredContent"]) == std::vector<std::string>{"in-d"});
    REQUIRE(t.ci_store.queries.size() == 1);
    CHECK(t.ci_store.queries[0].agent_id == std::optional<std::string>("in-d"));
    CHECK_FALSE(t.ci_store.queries[0].agent_ids.has_value());

    const int reads = t.ci_store.reads;
    t.clear_audit();
    const json hidden = t.call("list_hardware_ci_records", {{"agent_id", "out-b"}});
    REQUIRE_FALSE(hidden.contains("error"));
    CHECK(record_ids(hidden["result"]["structuredContent"]).empty());
    CHECK(t.ci_store.reads == reads);
    CHECK(t.domain_rows.back() == "inventory.devices.ci|denied|Agent|out-b");
}

// Kills: the MCP default staying at REST's 100 (each page lands in an agent's context) and the
// two transports sharing one default; both limits are observable as the store's limit + 1.
TEST_CASE("mcp list_hardware_ci_records: the default page is 20 rows, REST's stays 100",
          "[mcp][hardware][ci_page]") {
    Twin t;
    for (int i = 0; i < 130; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "d%03d", i);
        t.ci_store.add(std::string(buf));
    }
    t.ci_store.queries.clear();
    const json r = t.call("list_hardware_ci_records");
    REQUIRE_FALSE(r.contains("error"));
    CHECK(record_ids(r["result"]["structuredContent"]).size() == 20);
    CHECK_FALSE(r["result"]["structuredContent"]["next_cursor"].get<std::string>().empty());
    REQUIRE(t.ci_store.queries.size() == 1);
    CHECK(t.ci_store.queries[0].limit == 21);

    t.ci_store.queries.clear();
    const json rest = t.rest_data("/api/v1/hardware-ci");
    CHECK(record_ids(rest).size() == 100);
    REQUIRE(t.ci_store.queries.size() == 1);
    CHECK(t.ci_store.queries[0].limit == 101);
    // an explicit limit is honoured on both, up to 1000
    CHECK(record_ids(t.call("list_hardware_ci_records", {{"limit", 130}})["result"]["structuredContent"])
              .size() == 130);
}

// Kills: REST and MCP answering a present-but-empty agent_id differently (REST used to read the
// whole fleet where MCP refused), and either transport touching the store or auditing a page.
TEST_CASE("route and mcp agree: a present-but-empty agent_id is refused with the same words, before any read",
          "[mcp][hardware][ci_page]") {
    Twin t;
    seed(t, {"a", "b"});
    t.clear_audit();
    const int reads = t.ci_store.reads;
    auto rest = t.sink.Get("/api/v1/hardware-ci?agent_id=");
    REQUIRE(rest);
    CHECK(rest->status == 400);
    const json mcp_r = t.call("list_hardware_ci_records", {{"agent_id", ""}});
    REQUIRE(mcp_r.contains("error"));
    CHECK(mcp_r["error"]["code"] == mcp::kInvalidParams);
    const std::string expected = "agent_id must be a non-empty string when given";
    CHECK(json::parse(rest->body)["error"]["message"] == expected);
    CHECK(mcp_r["error"]["message"] == expected);
    CHECK(t.ci_store.reads == reads);
    CHECK(t.domain_rows.empty());
    CHECK_FALSE(rest->body.find("\"devices\"") != std::string::npos);
}

// A confined caller walks the same pages on both transports: the same ids, in the same order,
// with the same cursors, and nothing outside the scope on either. (The ids are chosen so the
// scope is not a prefix of the byte order.)
TEST_CASE("route and mcp agree for a confined caller: same ids, same order, same cursors, nothing hidden",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"Zeta", "agent-3", "out-1", "agent-1", "out-2", "_underscore", "agent-2", "out-3"});
    t.scope = std::unordered_set<std::string>{"Zeta", "agent-3", "agent-1", "_underscore", "agent-2"};

    std::vector<std::string> mcp_seen, rest_seen;
    std::string cursor;
    for (int pages = 0; pages < 20; ++pages) {
        json args = {{"limit", 2}};
        std::string url = "/api/v1/hardware-ci?limit=2";
        if (!cursor.empty()) {
            args["cursor"] = cursor;
            url += "&cursor=" + cursor;
        }
        const json mcp_r = t.call("list_hardware_ci_records", args);
        REQUIRE_FALSE(mcp_r.contains("error"));
        const json mcp_page = mcp_r["result"]["structuredContent"];
        const json rest_page = t.rest_data(url);
        CHECK(mcp_page == rest_page); // same ids, order, next_cursor and scope_basis
        CHECK(mcp_page["scope_basis"] == "authority_scoped");
        for (const auto& id : record_ids(mcp_page))
            mcp_seen.push_back(id);
        for (const auto& id : record_ids(rest_page))
            rest_seen.push_back(id);
        cursor = mcp_page["next_cursor"].get<std::string>();
        if (cursor.empty())
            break;
    }
    const std::vector<std::string> visible = {"Zeta", "_underscore", "agent-1", "agent-2", "agent-3"};
    CHECK(mcp_seen == visible);
    CHECK(rest_seen == visible);
}

TEST_CASE("mcp list_hardware_ci_records: arguments are refused, never clamped, and a bad cursor is -32602",
          "[mcp][hardware][ci_page]") {
    Twin t;
    seed(t, {"a"});
    const std::vector<json> bad = {
        {{"limit", 0}},     {{"limit", 1001}},     {{"limit", "5"}},   {{"limit", 1.5}},
        {{"limit", INT64_MAX}}, {{"limit", static_cast<std::uint64_t>(INT64_MAX) + 1}},
        {{"limit", UINT64_MAX}}, {{"limit", INT64_MIN}}, {{"limit", -1}},
        {{"limit", nullptr}}, {{"limit", true}},   {{"agent_id", ""}}, {{"agent_id", 7}},
        {{"agent_id", "a\nb"}}, {{"cursor", 7}},   {{"cursor", std::string(2049, 'x')}},
        {{"cursor", "garbage"}},
    };
    for (const auto& args : bad) {
        INFO(args.dump());
        t.clear_audit();
        const int reads = t.ci_store.reads;
        const json r = t.call("list_hardware_ci_records", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(t.ci_store.reads == reads); // judged before the store is read
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci_records|denied"));
        CHECK(t.domain_rows.empty()); // nothing was served, so no served-page row
    }
    // limit at both bounds is accepted
    CHECK_FALSE(t.call("list_hardware_ci_records", {{"limit", 1}}).contains("error"));
    CHECK_FALSE(t.call("list_hardware_ci_records", {{"limit", 1000}}).contains("error"));

    // A cursor issued without a filter is refused once an agent_id is added.
    seed(t, {"b"});
    const json page = t.call("list_hardware_ci_records", {{"limit", 1}});
    const std::string cursor = page["result"]["structuredContent"]["next_cursor"];
    REQUIRE_FALSE(cursor.empty());
    const json cross = t.call("list_hardware_ci_records", {{"agent_id", "a"}, {"cursor", cursor}});
    REQUIRE(cross.contains("error"));
    CHECK(cross["error"]["code"] == mcp::kInvalidParams);
}

// Kills: the two cursor refusals drifting apart again. An over-long cursor (refused while the
// arguments are read) and one that fails to decode (refused by the page read) give ONE
// remediation and ONE audit detail, and the same A4 message. A wrongly typed cursor and the
// other argument refusals keep their own remediation and detail.
TEST_CASE("mcp list_hardware_ci_records: every refused cursor has one remediation and one audit detail",
          "[mcp][hardware][ci_page]") {
    Twin t;
    seed(t, {"a", "b"});
    const json page = t.call("list_hardware_ci_records", {{"limit", 1}});
    const std::string good = page["result"]["structuredContent"]["next_cursor"];
    REQUIRE_FALSE(good.empty());

    const std::vector<json> refused_cursors = {
        {{"cursor", std::string(2049, 'x')}},               // over-long, refused at parse time
        {{"cursor", std::string("a\0b", 3)}},               // NUL: not valid text, same refusal
        {{"cursor", std::string("a\0b", 3)}, {"agent_id", "a\nb"}}, // judged before the agent_id
        {{"cursor", "garbage"}},                            // fails to decode
        {{"agent_id", "a"}, {"cursor", good}},              // issued for another agent_id filter
    };
    for (const auto& args : refused_cursors) {
        INFO(args.dump().substr(0, 80));
        t.clear_audit();
        const json r = t.call("list_hardware_ci_records", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"] == "invalid cursor; restart from the first page");
        CHECK(r["error"]["data"]["remediation"] == "omit cursor to restart from the first page");
        REQUIRE(t.generic_details.size() == 1);
        CHECK(t.generic_details.back() == "invalid arguments: cursor");
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci_records|denied"));
        CHECK(t.domain_rows.empty());
    }

    // The other argument refusals keep "fix the argument and re-call" and their own reason.
    struct Other {
        json args;
        const char* detail;
    };
    const std::vector<Other> others = {
        {{{"limit", 0}}, "invalid arguments: limit must be between 1 and 1000"},
        {{{"agent_id", ""}}, "invalid arguments: agent_id must be a non-empty string when given"},
        {{{"agent_id", "a\nb"}}, "invalid arguments: invalid agent_id"},
        {{{"cursor", 7}}, "invalid arguments: cursor must be a JSON string"},
    };
    for (const auto& o : others) {
        INFO(o.args.dump());
        t.clear_audit();
        const json r = t.call("list_hardware_ci_records", o.args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["data"]["remediation"] == "fix the argument and re-call");
        REQUIRE(t.generic_details.size() == 1);
        CHECK(t.generic_details.back() == o.detail);
    }
}

TEST_CASE("mcp list_hardware_ci_records: if either access row does not persist the data is withheld",
          "[mcp][hardware][ci_page][security]") {
    Twin t;
    seed(t, {"a"});
    for (const bool drop_domain : {true, false}) {
        INFO((drop_domain ? "domain row dropped" : "generic row dropped"));
        t.clear_audit();
        t.domain_audit_ok = !drop_domain;
        t.generic_audit_ok = drop_domain;
        const json r = t.call("list_hardware_ci_records");
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        const std::string body = r.dump();
        CHECK(body.find("SN-a") == std::string::npos);
        CHECK(body.find("host-a") == std::string::npos);
        CHECK(body.find("audit_persisted") == std::string::npos);
        // both rows were attempted
        CHECK(has(t.domain_rows, "inventory.devices.ci|success|Inventory|fleet"));
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci_records|success"));
    }
    t.domain_audit_ok = true;
    t.generic_audit_ok = true;
    CHECK_FALSE(t.call("list_hardware_ci_records").contains("error"));
}

TEST_CASE("mcp list_hardware_ci_records: a store degrade is a retryable error, never an empty page",
          "[mcp][hardware][ci_page]") {
    Twin t;
    seed(t, {"a"});
    t.ci_store.degraded = true;
    const json r = t.call("list_hardware_ci_records");
    REQUIRE(r.contains("error"));
    CHECK_FALSE(r.contains("result"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(has(t.domain_rows, "inventory.devices.ci|failure|Inventory|fleet"));
    CHECK(has(t.generic_rows, "mcp.list_hardware_ci_records|failure"));
}

TEST_CASE("mcp list_hardware_ci_records: unwired providers and a gate refusal",
          "[mcp][hardware][ci_page]") {
    {
        Twin::Opts o;
        o.wire_ci_page = false;
        Twin t(o);
        const json r = t.call("list_hardware_ci_records");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK_FALSE(r.contains("result"));
    }
    {
        Twin::Opts o;
        o.wire_audit = false;
        Twin t(o);
        seed(t, {"a"});
        const json r = t.call("list_hardware_ci_records");
        REQUIRE(r.contains("error")); // a missing audit sink is unwired, not "audit off"
        CHECK(r.dump().find("SN-a") == std::string::npos);
    }
    {
        Twin t;
        seed(t, {"a"});
        t.allow_fleet_read = false;
        json params = {{"name", "list_hardware_ci_records"}, {"arguments", json::object()}};
        auto res = t.post(
            json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3}, {"params", params}}.dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(t.ci_store.reads == 0);
        CHECK(t.domain_rows.empty());
        CHECK(t.generic_rows.empty());
        CHECK(t.perm_calls == 0); // fleet_read_fn alone; no second gate stacked
    }
}

// ─────────────── list_hardware_ci_records: the collation read gate (#7730) ───────────────

// Kills: the bulk MCP read served while the gate is not Trusted, a refusal that asks the store, a
// refusal that is the 5 s store-fault hint (it must be the 60 s recheck interval), and a refusal
// that is audited on one row only.
TEST_CASE("mcp list_hardware_ci_records: refused as a retryable error while the collation gate is not Trusted",
          "[mcp][hardware][ci_page][collation_gate]") {
    for (const auto refused : {pg::CollationGate::Mismatch, pg::CollationGate::Unproven}) {
        Twin t;
        seed(t, {"a", "b"});
        t.ci_gate.store(refused);
        const json r = t.call("list_hardware_ci_records");
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r.contains("result"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == 60000);
        const std::string msg = r["error"]["message"].get<std::string>();
        CHECK(msg.find("collation version") != std::string::npos);
        CHECK(msg.find("server-admin.md") != std::string::npos);
        CHECK(r["error"]["data"]["remediation"].get<std::string>().find("repair") != std::string::npos);
        CHECK(r.dump().find("SN-a") == std::string::npos);
        CHECK(t.ci_store.reads == 0);
        CHECK(has(t.domain_rows, "inventory.devices.ci|failure|Inventory|fleet"));
        CHECK(t.domain_details.back() == "hardware CI records (MCP) state=collation ordering unverified");
        CHECK(has(t.generic_rows, "mcp.list_hardware_ci_records|failure"));
    }
}

TEST_CASE("mcp list_hardware_ci_records: serves under a Trusted gate, and with no gate wired",
          "[mcp][hardware][ci_page][collation_gate]") {
    {
        Twin t;
        seed(t, {"a"});
        t.ci_gate.store(pg::CollationGate::Mismatch);
        CHECK(t.call("list_hardware_ci_records").contains("error"));
        t.ci_gate.store(pg::CollationGate::Trusted);
        const json ok = t.call("list_hardware_ci_records");
        REQUIRE_FALSE(ok.contains("error"));
        CHECK(ok["result"]["structuredContent"]["devices"].size() == 1);
    }
    {
        Twin::Opts o;
        o.wire_ci_gate = false;
        Twin t(o);
        seed(t, {"a"});
        t.ci_gate.store(pg::CollationGate::Mismatch); // not wired, so never consulted
        CHECK_FALSE(t.call("list_hardware_ci_records").contains("error"));
    }
}

TEST_CASE("mcp list_hardware_ci_records: the description names the refusal and its hint",
          "[mcp][hardware][ci_page][collation_gate]") {
    Twin t;
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const std::string d = tool_entry(json::parse(res->body), "list_hardware_ci_records")["description"];
    CHECK(d.find("retry_after_ms 60000") != std::string::npos);
    CHECK(d.find("collation") != std::string::npos);
}
