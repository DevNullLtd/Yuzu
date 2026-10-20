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

#include "hardware_list_model.hpp"
#include "hardware_routes.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "mcp_tool_deps.hpp"
#include "mcp_tool_registry.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
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
    std::vector<std::string> dex_calls_for;

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
            out.ci_degraded = ci_degraded;
            out.tags_degraded = tags_degraded;
            return out;
        };
        HardwareRoutes::CiDetailFn ci_fn = [this](const std::string& id) {
            ++ci_calls;
            const auto it = ci_by_id.find(id);
            return it != ci_by_id.end() ? it->second : absent_detail();
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

// A subset JSON-Schema check sufficient for the output schemas these tools publish: type
// (string or array of strings), properties (no extra keys), required, items, enum. Returns
// the first violation, or "" when `v` conforms.
std::string schema_violation(const json& schema, const json& v, const std::string& path = "") {
    if (schema.contains("type")) {
        std::vector<std::string> types;
        if (schema["type"].is_array())
            for (const auto& t : schema["type"])
                types.push_back(t.get<std::string>());
        else
            types.push_back(schema["type"].get<std::string>());
        bool ok = false;
        for (const auto& t : types) {
            if ((t == "object" && v.is_object()) || (t == "array" && v.is_array()) ||
                (t == "string" && v.is_string()) || (t == "integer" && v.is_number_integer()) ||
                (t == "number" && v.is_number()) || (t == "boolean" && v.is_boolean()) ||
                (t == "null" && v.is_null()))
                ok = true;
        }
        if (!ok)
            return path + ": type mismatch, value " + v.dump();
    }
    if (schema.contains("enum")) {
        bool ok = false;
        for (const auto& e : schema["enum"])
            ok = ok || e == v;
        if (!ok)
            return path + ": not in enum, value " + v.dump();
    }
    if (v.is_object() && schema.contains("properties")) {
        for (const auto& [k, sub] : v.items()) {
            if (!schema["properties"].contains(k))
                return path + "/" + k + ": key not declared in the schema";
            if (auto r = schema_violation(schema["properties"][k], sub, path + "/" + k); !r.empty())
                return r;
        }
        if (schema.contains("required"))
            for (const auto& req : schema["required"])
                if (!v.contains(req.get<std::string>()))
                    return path + ": required key " + req.get<std::string>() + " is missing";
    }
    if (v.is_array() && schema.contains("items"))
        for (std::size_t i = 0; i < v.size(); ++i)
            if (auto r = schema_violation(schema["items"], v[i], path + "/" + std::to_string(i));
                !r.empty())
                return r;
    return "";
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
    CHECK(sc["devices_omitted"] == 1);
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
    // The two answers are indistinguishable apart from the per-request correlation id.
    CHECK(hidden["error"]["code"] == missing["error"]["code"]);
    CHECK(hidden["error"]["message"] == missing["error"]["message"]);
    CHECK(hidden["error"]["data"]["remediation"] == missing["error"]["data"]["remediation"]);
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
        CHECK(rows.size() == 2);
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
            CHECK(result["structuredContent"].dump() == rest.dump());
            CHECK(result["content"][0]["text"].get<std::string>() == rest.dump());
        }
    }
    CHECK(t.scope.has_value());
    CHECK(t.call("list_hardware_ci")["result"]["structuredContent"]["devices_omitted"] == 1);
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
    for (const char* id : {"a", "s", "d"}) {
        INFO("device " << id);
        const json r = t.call("get_hardware_ci", {{"agent_id", id}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(get_schema, r["result"]["structuredContent"]) == "");
    }
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
    CHECK(t.domain_details[0] == "hardware list (MCP): devices=1 omitted=1");
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
    CHECK(sc["devices_omitted"] == 2);
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
