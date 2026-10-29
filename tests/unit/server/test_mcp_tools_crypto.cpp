/// @file test_mcp_tools_crypto.cpp
/// The seven /crypto MCP tools (mcp_tools_crypto.cpp): `get_crypto_libraries`,
/// `list_crypto_library_devices`, `export_crypto_cbom`, `list_crypto_widgets`,
/// `get_crypto_dashboard_layout`, `set_crypto_dashboard_layout` and `get_crypto_ca_stats`,
/// carved out of mcp_server.cpp (#6558 PR 2).
///
/// The fixture (`Twin`) drives a real `McpServer` through its in-process handler with a
/// `ToolDeps` whose closures forward to ONE fake `CryptoApi`, the way server.cpp forwards its
/// `crypto_api_`. It is local on purpose: `McpTestServer` (test_mcp_server.cpp) is TU-private.
/// The long-standing inline /crypto tests in test_mcp_server.cpp keep running against the
/// carved handlers (the fixture forwards `crypto_api_for_test` into ToolDeps) and are the
/// before/after behaviour net; this file adds the registry-seam contract.
///
/// Matrix: registration (security rows, annotations, typed output schemas), success + output
/// schema conformance + audit rows per tool, the single fleet-read gate (a refusal is the gate's
/// own body and audits nothing), confinement (scope handed to the seam; the Yuzu-issued counts
/// withheld from a confined caller), degraded / capacity / pool-too-small answers and their
/// retry hints, the audit-first layout write ("no audit row, no mutation"), the layout failure
/// kinds, strict arguments, the dispatch chain's central non-object refusal, and every unwired
/// provider.

#include "crypto_api.hpp"
#include "crypto_library_model.hpp"
#include "crypto_widget_catalogue.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_retry.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "mcp_tool_deps.hpp"
#include "mcp_tool_registry.hpp"
#include "test_json_schema_subset.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
namespace mcp = yuzu::server::mcp;
namespace cw = yuzu::server::crypto_widgets;
using yuzu::test::schema_violation;

namespace {

class FakeCryptoApi final : public CryptoApi {
public:
    std::expected<CryptoSummary, CryptoReadError> summary{CryptoSummary{}};
    std::expected<CryptoDevicesPage, CryptoReadError> devices{CryptoDevicesPage{}};
    std::expected<CaCertStats, CryptoReadError> stats{CaCertStats{}};
    std::expected<CaCertPage, CryptoReadError> certs{CaCertPage{}};
    std::expected<CryptoDashboardLayout, CryptoReadError> layout{
        CryptoDashboardLayout{{"ca.active"}, false, 3, 0}};
    std::optional<CryptoReadError> set_error;

    mutable std::vector<authz::VisibleSet> scopes;
    mutable std::vector<CryptoSummaryQuery> summary_queries;
    mutable std::vector<CryptoDevicesQuery> devices_queries;
    mutable std::vector<std::optional<std::int64_t>> stats_as_of;
    mutable std::vector<std::string> layout_reads;
    mutable std::vector<std::pair<std::string, std::vector<std::string>>> layout_writes;
    mutable std::vector<std::optional<std::int64_t>> layout_expected;

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        scopes.push_back(scope);
        summary_queries.push_back(q);
        return summary;
    }
    std::expected<CryptoDevicesPage, CryptoReadError>
    library_devices(const CryptoDevicesQuery& q, const authz::VisibleSet& scope) const override {
        scopes.push_back(scope);
        devices_queries.push_back(q);
        return devices;
    }
    std::expected<CaCertStats, CryptoReadError>
    ca_stats(std::optional<std::int64_t> as_of) const override {
        stats_as_of.push_back(as_of);
        return stats;
    }
    std::expected<CaCertPage, CryptoReadError> ca_certificates(const CaCertQuery&) const override {
        return certs;
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const override {
        layout_reads.push_back(username);
        return layout;
    }
    std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username, const std::vector<std::string>& widgets,
                         std::optional<std::int64_t> expected) const override {
        layout_writes.emplace_back(username, widgets);
        layout_expected.push_back(expected);
        if (set_error)
            return std::unexpected(*set_error);
        return CryptoDashboardLayout{widgets, false, 4, 0};
    }

    [[nodiscard]] std::size_t calls() const {
        return scopes.size() + stats_as_of.size() + layout_reads.size() + layout_writes.size();
    }
};

std::shared_ptr<FakeCryptoApi> fake_with_data() {
    auto f = std::make_shared<FakeCryptoApi>();
    CryptoSummary s;
    CryptoFamilyRow fam;
    fam.id = "openssl";
    fam.display = "OpenSSL";
    fam.device_count = 3;
    fam.versions.push_back({"3.0.13", "deb", 3, {"libssl3"}});
    s.families.push_back(fam);
    s.coverage = {10, 3};
    s.names_from_catalogue = true;
    s.names_as_of = 1760000000;
    f->summary = s;
    CryptoDevicesPage p;
    p.family = "openssl";
    p.devices.push_back({"agent-1", "", "libssl3", "3.0.13", "1", "deb", "package"});
    p.next_cursor = "k1:abc";
    f->devices = p;

    CaCertStats st;
    st.as_of = 1792368000;
    st.active = 2;
    for (const int d : cw::kExpiringWindowDays)
        st.expiring.push_back({d, 1});
    for (const int d : cw::kExpiredWindowDays)
        st.expired.push_back({d, 0});
    for (const int d : cw::kRevokedWindowDays)
        st.revoked.push_back({d, 1, 2, 3});
    st.issued = {7, 1};
    CaWeekCount w;
    w.week_start = cw::week_start_of(st.as_of);
    w.label = cw::iso_week_label(w.week_start);
    w.issued = 1;
    w.partial = true;
    st.weeks.push_back(w);
    f->stats = st;
    return f;
}

CryptoReadError degraded(CryptoReadCause cause = CryptoReadCause::kStoreDegraded) {
    return CryptoReadError{CryptoReadError::Kind::kDegraded, "crypto read degraded", cause};
}

struct Twin {
    std::shared_ptr<FakeCryptoApi> api = fake_with_data();

    // ── fakes the closures read ──
    authz::VisibleSet scope; // nullopt = unfiltered
    bool allow_fleet_read = true;
    std::vector<std::string> gate_calls; // "<securable>:<operation>"
    cw::Access access = cw::Access::kAvailable;
    int access_calls = 0;
    std::string username = "tester";
    // When set, username_fn answers THIS while the authenticated session keeps `username`, so a
    // test can tell which of the two a handler actually keys on (they are one value in
    // production, so only an independent fake can observe the wiring).
    std::optional<std::string> resolved_username;

    // Domain-verb audit sink (ToolDeps::audit_fn).
    bool domain_audit_ok = true;
    std::string domain_fail_result; // when set, ONLY a row with this result fails to persist
    std::vector<std::string> domain_rows;    // action|result|type|id
    std::vector<std::string> domain_details; // detail, parallel
    // Generic mcp.<tool> sink (McpServer's own audit_fn).
    bool generic_audit_ok = true;
    std::vector<std::string> generic_rows; // action|result
    std::vector<std::string> generic_details;

    // "supervised" so the Infrastructure:Write layout tool is admitted by the generic tier gate
    // ("operator" is refused there, before the handler); the reads pass at every tier.
    std::string tier = "supervised";
    int perm_calls = 0;
    // build_handler keeps ADDRESSES of these two (const bool& parameters, dereferenced per
    // request), so they must be members that outlive the handler, never temporaries.
    bool read_only_mode_ = false;
    bool mcp_disabled_ = false;
    bool domain_audit_throws = false; // the domain sink throws AFTER recording the row
    std::string scope_service;        // a service-scoped token's tag, "" = an ordinary session

    mcp::McpServer server;
    mcp::McpServer::HandlerFn handler;

    struct Opts {
        bool wire_api = true;
        bool wire_fleet = true;
        bool wire_access = true;
        bool wire_audit = true;
        bool wire_username = true;
    };

    Twin() : Twin(Opts{}) {}
    explicit Twin(Opts o) {
        mcp::ToolDeps td;
        if (o.wire_fleet)
            td.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                      const std::string& securable,
                                      const std::string& operation) -> authz::FleetReadGate {
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
        if (o.wire_audit)
            td.audit_fn = [this](const httplib::Request&, const std::string& action,
                                 const std::string& result, const std::string& target_type,
                                 const std::string& target_id, const std::string& detail) -> bool {
                domain_rows.push_back(action + "|" + result + "|" + target_type + "|" + target_id);
                domain_details.push_back(detail);
                if (domain_audit_throws)
                    throw std::runtime_error("audit sink blew up");
                if (!domain_fail_result.empty())
                    return result != domain_fail_result;
                return domain_audit_ok;
            };
        if (o.wire_api) {
            const std::shared_ptr<const CryptoApi> a = api;
            td.crypto_library_summary_fn = [a](const CryptoSummaryQuery& q,
                                               const authz::VisibleSet& s) {
                return a->library_summary(q, s);
            };
            td.crypto_library_devices_fn = [a](const CryptoDevicesQuery& q,
                                               const authz::VisibleSet& s) {
                return a->library_devices(q, s);
            };
            td.crypto_ca_stats_fn = [a](std::optional<std::int64_t> as_of) {
                return a->ca_stats(as_of);
            };
            td.crypto_dashboard_layout_fn = [a](const std::string& user) {
                return a->dashboard_layout(user);
            };
            td.crypto_set_dashboard_layout_fn =
                [a](const std::string& user, const std::vector<std::string>& widgets,
                    std::optional<std::int64_t> expected_version) {
                    return a->set_dashboard_layout(user, widgets, expected_version);
                };
        }
        if (o.wire_access)
            td.crypto_access_fn = [this](const httplib::Request&, cw::WidgetGate,
                                         const std::string&, const std::string&) {
                ++access_calls;
                return access;
            };
        if (o.wire_username)
            td.username_fn = [this](const httplib::Request&) -> std::optional<std::string> {
                return resolved_username ? resolved_username : std::optional<std::string>{username};
            };
        server.set_tool_deps(std::move(td));

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = username;
            s.role = auth::Role::admin;
            s.mcp_tier = tier;
            s.token_scope_service = scope_service;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) {
            ++perm_calls;
            return true;
        };
        auto generic_audit = [this](const httplib::Request&, const std::string& a,
                                    const std::string& r, const std::string&, const std::string&,
                                    const std::string& detail) {
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
            /*approval_manager=*/nullptr, /*schedule_engine=*/nullptr, read_only_mode_,
            mcp_disabled_);
    }

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

    // tools/call -> the raw response (status + body).
    std::unique_ptr<httplib::Response> call_raw(const std::string& tool, const json& arguments) {
        json params = {{"name", tool}, {"arguments", arguments}};
        return post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 7}, {"params", params}}
                        .dump());
    }

    // tools/call -> parsed JSON-RPC body.
    json call(const std::string& tool, const json& arguments = json::object()) {
        auto res = call_raw(tool, arguments);
        REQUIRE(res);
        return json::parse(res->body);
    }

    json output_schema(const std::string& tool) {
        auto res = post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
        REQUIRE(res);
        const json listed = json::parse(res->body); // named: a range-for over a temporary dangles
        for (const auto& t : listed["result"]["tools"])
            if (t["name"] == tool)
                return t["outputSchema"];
        FAIL("tool not served: " << tool);
        return json::object();
    }

    void clear_audit() {
        gate_calls.clear();
        domain_rows.clear();
        domain_details.clear();
        generic_rows.clear();
        generic_details.clear();
    }
};

// Counts of an audit row in a sink (the name carries "audit" so an assertion on it reads as the
// audit-row assertion it is).
int audit_count(const std::vector<std::string>& rows, const std::string& row) {
    return static_cast<int>(std::count(rows.begin(), rows.end(), row));
}

const std::vector<std::string> kAllTools{"get_crypto_libraries",         "list_crypto_library_devices",
                                         "export_crypto_cbom",           "list_crypto_widgets",
                                         "get_crypto_dashboard_layout",  "set_crypto_dashboard_layout",
                                         "get_crypto_ca_stats"};

json args_for(const std::string& tool) {
    if (tool == "set_crypto_dashboard_layout")
        return {{"widgets", json::array({"ca.active"})}};
    if (tool == "list_crypto_library_devices")
        return {{"family", "openssl"}}; // the drill requires a family
    return json::object();
}

} // namespace

// ───────────────────────── catalogue / registration ────────────────────────────

TEST_CASE("mcp crypto tools: all seven are served with the legacy security rows, annotations and "
          "typed output schemas",
          "[mcp][crypto][registry_seam]") {
    Twin t;
    struct Row {
        const char* name;
        const char* securable;
        const char* operation;
        mcp::ServiceScopeClassForTest scope;
    };
    const Row rows[] = {
        {"get_crypto_libraries", "Inventory", "Read", mcp::ServiceScopeClassForTest::kConfined},
        {"list_crypto_library_devices", "Inventory", "Read", mcp::ServiceScopeClassForTest::kConfined},
        {"export_crypto_cbom", "Inventory", "Read", mcp::ServiceScopeClassForTest::kConfined},
        {"list_crypto_widgets", "Infrastructure", "Read", mcp::ServiceScopeClassForTest::kDenied},
        {"get_crypto_dashboard_layout", "Infrastructure", "Read", mcp::ServiceScopeClassForTest::kDenied},
        {"set_crypto_dashboard_layout", "Infrastructure", "Write", mcp::ServiceScopeClassForTest::kDenied},
        {"get_crypto_ca_stats", "Inventory", "Read", mcp::ServiceScopeClassForTest::kDenied},
    };
    const auto sec = mcp::tool_security_rows_for_test();
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    for (const auto& r : rows) {
        INFO(r.name);
        const auto it = std::find_if(sec.begin(), sec.end(), [&](const auto& s) { return s.name == r.name; });
        REQUIRE(it != sec.end());
        CHECK(it->securable == r.securable);
        CHECK(it->operation == r.operation);
        CHECK(it->service_scope == r.scope);
        const json* tool = nullptr;
        for (const auto& e : listed["result"]["tools"])
            if (e["name"] == r.name)
                tool = &e;
        REQUIRE(tool != nullptr);
        CHECK((*tool)["outputSchema"]["type"] == "object");
        CHECK((*tool)["annotations"]["idempotentHint"] == true);
        const bool is_set = std::string(r.name) == "set_crypto_dashboard_layout";
        CHECK((*tool)["annotations"]["readOnlyHint"] == !is_set);
        CHECK((*tool)["annotations"]["destructiveHint"] == is_set);
    }
    // The strict input contract the handlers enforce: the layout write bounds its list.
    for (const auto& e : listed["result"]["tools"])
        if (e["name"] == "set_crypto_dashboard_layout") {
            CHECK(e["inputSchema"]["required"] == json::array({"widgets"}));
            CHECK(e["inputSchema"]["properties"]["widgets"]["maxItems"] == 64);
            CHECK(e["inputSchema"]["additionalProperties"] == false);
        }
}

TEST_CASE("mcp crypto tools: a read-only token reads every tool but cannot set a layout",
          "[mcp][crypto][security]") {
    Twin t;
    t.tier = "readonly";
    for (const auto& tool : kAllTools) {
        INFO(tool);
        const json r = t.call(tool, args_for(tool));
        if (tool == "set_crypto_dashboard_layout") {
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kTierDenied); // the generic tier gate, before the handler
        } else {
            CHECK_FALSE(r.contains("error"));
        }
    }
    CHECK(t.api->layout_writes.empty());
    CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|denied") == 1);
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 0);
}

TEST_CASE("mcp crypto tools: the operator tier reads but cannot set a layout (Infrastructure:Write)",
          "[mcp][crypto][security]") {
    Twin t;
    t.tier = "operator";
    REQUIRE_FALSE(t.call("get_crypto_dashboard_layout").contains("error"));
    const json r = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kTierDenied);
    CHECK(t.api->layout_writes.empty());
    CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|denied") == 1);
}

// ───────────────────────── success: output schema + audit rows ──────────────────────

TEST_CASE("mcp crypto tools: the three Inventory reads serve the seam's rows, schema-valid, and audit",
          "[mcp][crypto]") {
    Twin t;
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom"}) {
        INFO(tool);
        t.clear_audit();
        t.api->scopes.clear();
        const json schema = t.output_schema(tool);
        const json args = std::string(tool) == "list_crypto_library_devices"
                              ? json{{"family", "openssl"}}
                              : json{{"family", "openssl"}, {"ecosystem", "deb"}};
        const json r = t.call(tool, args);
        INFO(r.dump());
        REQUIRE_FALSE(r.contains("error"));
        const auto& sc = r["result"]["structuredContent"];
        CHECK(schema_violation(schema, sc) == "");
        // fleet_read_fn is the SOLE gate: the tool names exactly Inventory:Read and asks once.
        CHECK(t.gate_calls == std::vector<std::string>{"Inventory:Read"});
        CHECK(t.perm_calls == 0);
        REQUIRE(t.api->scopes.size() == 1);
        CHECK_FALSE(t.api->scopes[0].has_value()); // an unfiltered caller reads unfiltered
        CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|success") == 1);
        CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|failure") == 0);
    }
    // The BOM envelope is a JSON string plus the count and the truncation flag.
    const json cbom = t.call("export_crypto_cbom")["result"]["structuredContent"];
    CHECK(cbom["components"].is_number());
    CHECK(cbom["result_truncated"].is_boolean());
    CHECK(json::parse(cbom["bom"].get<std::string>()).contains("components"));
}

TEST_CASE("mcp crypto tools: the widget catalogue, layout read and CA stats serve schema-valid bodies "
          "and audit",
          "[mcp][crypto][widgets]") {
    Twin t;
    {
        const json r = t.call("list_crypto_widgets");
        INFO(r.dump());
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(t.output_schema("list_crypto_widgets"), r["result"]["structuredContent"]) == "");
        CHECK(t.access_calls == 3); // one probe per distinct (gate, securable, operation)
        CHECK(audit_count(t.generic_rows, "mcp.list_crypto_widgets|success") == 1);
        CHECK(t.gate_calls.empty()); // the generic C8/tier check gates this one, not fleet_read_fn
    }
    {
        const json r = t.call("get_crypto_dashboard_layout");
        INFO(r.dump());
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(t.output_schema("get_crypto_dashboard_layout"),
                               r["result"]["structuredContent"]) == "");
        // The layout is the SESSION user's own, re-resolved through username_fn.
        CHECK(t.api->layout_reads == std::vector<std::string>{"tester"});
        CHECK(audit_count(t.generic_rows, "mcp.get_crypto_dashboard_layout|success") == 1);
    }
    {
        t.clear_audit();
        const json r = t.call("get_crypto_ca_stats");
        INFO(r.dump());
        REQUIRE_FALSE(r.contains("error"));
        CHECK(schema_violation(t.output_schema("get_crypto_ca_stats"), r["result"]["structuredContent"]) == "");
        CHECK(t.gate_calls == std::vector<std::string>{"Inventory:Read"});
        REQUIRE(t.api->stats_as_of.size() == 1);
        CHECK_FALSE(t.api->stats_as_of[0].has_value()); // the database clock, never the replica's
        CHECK(r["result"]["structuredContent"]["as_of"] == 1792368000);
        CHECK(audit_count(t.domain_rows, "crypto.ca.stats.view|success|Inventory|yuzu_ca") == 1);
        CHECK(audit_count(t.generic_rows, "mcp.get_crypto_ca_stats|success") == 1);
    }
}

TEST_CASE("mcp crypto tools: set layout writes the session user's own layout, audit row first",
          "[mcp][crypto][widgets]") {
    Twin t;
    t.username = "alice";
    const json r = t.call("set_crypto_dashboard_layout",
                          {{"widgets", json::array({"ca.active"})}, {"expected_version", 3}});
    INFO(r.dump());
    REQUIRE_FALSE(r.contains("error"));
    CHECK(schema_violation(t.output_schema("set_crypto_dashboard_layout"), r["result"]["structuredContent"]) == "");
    REQUIRE(t.api->layout_writes.size() == 1);
    CHECK(t.api->layout_writes[0].first == "alice");
    CHECK(t.api->layout_writes[0].second == std::vector<std::string>{"ca.active"});
    CHECK(t.api->layout_expected[0] == std::optional<std::int64_t>{3});
    // The attempted row precedes the write; the success row follows it, then the generic row.
    CHECK(t.domain_rows == std::vector<std::string>{
                               "crypto.dashboard.layout.update|attempted|CryptoDashboard|alice",
                               "crypto.dashboard.layout.update|success|CryptoDashboard|alice"});
    CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|success") == 1);
    CHECK_FALSE(r["result"]["structuredContent"].contains("audit_persisted"));

    // A lost SUCCESS row is flagged in the body, not fatal (set-and-proceed after the write).
    Twin lost;
    lost.domain_fail_result = "success";
    const json r2 = lost.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE_FALSE(r2.contains("error"));
    CHECK(r2["result"]["structuredContent"]["audit_persisted"] == false);
    CHECK(lost.api->layout_writes.size() == 1);
}

// ───────────────────────── the single gate and confinement ─────────────────────────

TEST_CASE("mcp crypto tools: a fleet-read refusal is the gate's own body; nothing is audited or read",
          "[mcp][crypto][security]") {
    Twin t;
    t.allow_fleet_read = false;
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom",
                             "get_crypto_ca_stats"}) {
        INFO(tool);
        t.clear_audit();
        auto res = t.call_raw(tool, json::object());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == R"({"error":"forbidden"})");
        CHECK(t.domain_rows.empty());
        CHECK(t.generic_rows.empty()); // the audit rows are absent: the gate answered
    }
    CHECK(t.api->calls() == 0);
}

TEST_CASE("mcp crypto tools: the scope the gate composes reaches the seam, and the Yuzu-issued counts "
          "are withheld from a confined caller",
          "[mcp][crypto][security]") {
    Twin t;
    t.scope = std::unordered_set<std::string>{"agent-1"};
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom"}) {
        INFO(tool);
        t.api->scopes.clear();
        REQUIRE_FALSE(t.call(tool, args_for(tool)).contains("error"));
        REQUIRE(t.api->scopes.size() == 1);
        REQUIRE(t.api->scopes[0].has_value());
        CHECK(t.api->scopes[0]->count("agent-1") == 1);
    }
    t.clear_audit();
    const json r = t.call("get_crypto_ca_stats");
    INFO(r.dump());
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kPermissionDenied);
    // No permission is named: none would admit a confined caller, so no false self-remediation.
    CHECK_FALSE(r["error"]["data"].contains("permission"));
    CHECK(t.api->stats_as_of.empty());
    CHECK(t.domain_rows == std::vector<std::string>{"crypto.ca.stats.view|denied|Inventory|yuzu_ca"});
    CHECK(t.generic_rows == std::vector<std::string>{"mcp.get_crypto_ca_stats|denied"});
    CHECK(t.generic_details == std::vector<std::string>{"withheld=confined"});
}

// ───────────────────────── failures and retry hints ─────────────────────────────────

TEST_CASE("mcp crypto tools: a degraded read is a retryable error with an audit row, never an empty "
          "result; a too-small pool names the flag and has no hint",
          "[mcp][crypto]") {
    Twin t;
    t.api->summary = std::unexpected(degraded());
    t.api->devices = std::unexpected(degraded(CryptoReadCause::kCapacity));
    t.api->stats = std::unexpected(degraded());
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom",
                             "get_crypto_ca_stats"}) {
        INFO(tool);
        t.clear_audit();
        const json r = t.call(tool, args_for(tool));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|failure") == 1);
        CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|success") == 0);
    }
    CHECK(audit_count(t.domain_rows, "crypto.ca.stats.view|failure|Inventory|yuzu_ca") == 1);

    CryptoReadError pool = degraded();
    pool.unavailable_until_restart = true;
    pool.message = "pool too small";
    t.api->summary = std::unexpected(pool);
    t.api->devices = std::unexpected(pool);
    t.api->stats = std::unexpected(pool);
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom",
                             "get_crypto_ca_stats"}) {
        INFO(tool);
        const json r = t.call(tool, args_for(tool));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(r["error"]["data"]["remediation"].get<std::string>() ==
              std::string(mcp::kCryptoPoolTooSmallRemedy));
    }

    // A seam-level caller refusal (a bad cursor) is invalid-params, not a store fault: no failure row.
    Twin bad;
    bad.api->devices = std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "bad cursor"});
    const json r = bad.call("list_crypto_library_devices", {{"family", "openssl"}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInvalidParams);
    CHECK(audit_count(bad.generic_rows, "mcp.list_crypto_library_devices|failure") == 0);
}

TEST_CASE("mcp crypto tools: a degraded or corrupt layout read is an error with an audit row, never "
          "the default served as if nothing were stored",
          "[mcp][crypto][widgets]") {
    using K = CryptoReadError::Kind;
    Twin t;
    t.api->layout = std::unexpected(degraded());
    json r = t.call("get_crypto_dashboard_layout");
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(audit_count(t.generic_rows, "mcp.get_crypto_dashboard_layout|failure") == 1);

    CryptoReadError corrupt{K::kCorrupt, "stored layout unreadable"};
    corrupt.version = 9;
    t.api->layout = std::unexpected(corrupt);
    t.clear_audit();
    r = t.call("get_crypto_dashboard_layout");
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["data"]["retry_after_ms"].is_null());
    CHECK(r["error"]["data"]["remediation"].get<std::string>().find("expected_version=9") != std::string::npos);
    CHECK(t.generic_details == std::vector<std::string>{"outcome=corrupt"});
}

TEST_CASE("mcp crypto tools: set layout - no audit row, no mutation; failure kinds map to the REST codes",
          "[mcp][crypto][widgets][security]") {
    using K = CryptoReadError::Kind;
    {
        Twin t;
        t.domain_audit_ok = false; // the attempted row cannot persist
        const json r = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(t.api->layout_writes.empty()); // the layout was NOT changed
        CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 1);
        CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|failure") == 1);
        CHECK(t.generic_details == std::vector<std::string>{"audit unavailable; layout not changed"});
    }
    struct Case {
        K kind;
        int code;
        bool retry;
        const char* tag;
    };
    for (const auto& c : {Case{K::kConflict, mcp::kInvalidParams, false, "outcome=conflict"},
                          Case{K::kCorrupt, mcp::kInternalError, false, "outcome=corrupt"},
                          Case{K::kOutcomeUnknown, mcp::kInternalError, true, "outcome=unknown"},
                          Case{K::kDegraded, mcp::kInternalError, true, "outcome=degraded"}}) {
        INFO(c.tag);
        Twin t;
        CryptoReadError e{c.kind, "write refused"};
        e.version = 5;
        t.api->set_error = e;
        const json r = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == c.code);
        if (c.retry)
            CHECK(r["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        else
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        // attempted, then a failure row carrying the tag; never a success row.
        CHECK(t.domain_rows == std::vector<std::string>{
                                   "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester",
                                   "crypto.dashboard.layout.update|failure|CryptoDashboard|tester"});
        CHECK(t.domain_details.back().find(c.tag) != std::string::npos);
        CHECK(t.generic_rows == std::vector<std::string>{"mcp.set_crypto_dashboard_layout|failure"});
    }
    // A conflict names the stored version so the caller can re-read and save again.
    {
        Twin t;
        CryptoReadError e{K::kConflict, "the layout changed"};
        e.version = 5;
        t.api->set_error = e;
        const json r = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["data"]["remediation"].get<std::string>().find("stored version 5") != std::string::npos);
    }
}

// ───────────────────────── arguments ──────────────────────────────────────────────

TEST_CASE("mcp crypto tools: strict arguments are refused before any read or write",
          "[mcp][crypto]") {
    Twin t;
    const std::vector<std::pair<std::string, json>> bad = {
        {"get_crypto_libraries", {{"family", "notalib"}}},
        {"list_crypto_library_devices", {{"family", 3}}},
        {"export_crypto_cbom", {{"ecosystem", 7}}},
        {"list_crypto_widgets", {{"x", 1}}},
        {"get_crypto_dashboard_layout", {{"x", 1}}},
        {"get_crypto_ca_stats", {{"x", 1}}},
        {"set_crypto_dashboard_layout", json::object()},
        {"set_crypto_dashboard_layout", {{"widgets", "ca.active"}}},
        {"set_crypto_dashboard_layout", {{"widgets", json::array({1})}}},
        {"set_crypto_dashboard_layout", {{"widgets", json::array({"nope"})}}},
        {"set_crypto_dashboard_layout", {{"widgets", json::array({"ca.active", "ca.active"})}}},
        {"set_crypto_dashboard_layout", {{"widgets", json::array()}, {"username", "bob"}}},
        {"set_crypto_dashboard_layout", {{"widgets", json::array()}, {"expected_version", -1}}},
    };
    for (const auto& [tool, args] : bad) {
        INFO(tool << " " << args.dump());
        const json r = t.call(tool, args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK_FALSE(r.contains("result"));
    }
    CHECK(t.api->calls() == 0);
    // No attempted row for a write refused on its arguments.
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 0);
}

TEST_CASE("mcp crypto tools: a non-object `arguments` is refused by the dispatch chain, before the "
          "handler, with a denial row",
          "[mcp][crypto][registry_seam]") {
    // The carve moves the seven tools behind the registry path's central is_object() check, so
    // the refusal for a scalar, array or null `arguments` is the generic -32602 (not the legacy
    // per-tool message) and it precedes the Inventory:Read gate: the error code is unchanged.
    Twin t;
    for (const auto& tool : kAllTools)
        for (const json& args : {json::array(), json("openssl"), json(3), json(nullptr)}) {
            INFO(tool << " " << args.dump());
            t.clear_audit();
            const json r = t.call(tool, args);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            CHECK(audit_count(t.generic_rows, "mcp." + tool + "|denied") == 1);
            CHECK(audit_count(t.generic_rows, "mcp." + tool + "|success") == 0);
            CHECK(t.gate_calls.empty());
        }
    CHECK(t.api->calls() == 0);
}

// ───────────────────────── unwired providers ──────────────────────────────────────

TEST_CASE("mcp crypto tools: an unwired provider is an internal error, never an empty result",
          "[mcp][crypto][security]") {
    SECTION("no CryptoApi: every data tool answers an internal error and audits no success") {
        Twin::Opts o;
        o.wire_api = false;
        Twin t(o);
        for (const auto& tool : kAllTools) {
            if (tool == "list_crypto_widgets")
                continue; // reads only the access closure
            INFO(tool);
            t.clear_audit();
            const json r = t.call(tool, args_for(tool));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            // Every unwired answer leaves the generic failure row (the registry seam contract).
            CHECK(audit_count(t.generic_rows, "mcp." + tool + "|failure") == 1);
            CHECK(audit_count(t.generic_rows, "mcp." + tool + "|success") == 0);
        }
        CHECK(audit_count(t.generic_rows, "mcp.get_crypto_libraries|success") == 0);
        CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 0);
        CHECK(t.api->calls() == 0);
    }
    SECTION("no fleet-read gate: the four gated tools fail closed before any read") {
        Twin::Opts o;
        o.wire_fleet = false;
        Twin t(o);
        for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom",
                                 "get_crypto_ca_stats"}) {
            INFO(tool);
            t.clear_audit();
            const json r = t.call(tool, args_for(tool));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|failure") == 1);
        }
        CHECK(t.api->calls() == 0);
    }
    SECTION("no audit sink: the four domain-row readers fail closed instead of succeeding row-less") {
        Twin::Opts o;
        o.wire_audit = false;
        Twin t(o);
        for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom",
                                 "get_crypto_ca_stats"}) {
            INFO(tool);
            t.clear_audit();
            const json r = t.call(tool, args_for(tool));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|failure") == 1);
            CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|success") == 0);
        }
        CHECK(t.api->calls() == 0);
    }
    SECTION("no access closure: list_crypto_widgets fails closed") {
        Twin::Opts o;
        o.wire_access = false;
        Twin t(o);
        const json r = t.call("list_crypto_widgets");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(audit_count(t.generic_rows, "mcp.list_crypto_widgets|success") == 0);
        CHECK(audit_count(t.generic_rows, "mcp.list_crypto_widgets|failure") == 1);
    }
    SECTION("no username closure: the layout tools fail closed and write nothing") {
        Twin::Opts o;
        o.wire_username = false;
        Twin t(o);
        for (const char* tool : {"get_crypto_dashboard_layout", "set_crypto_dashboard_layout"}) {
            INFO(tool);
            t.clear_audit();
            const json r = t.call(tool, args_for(tool));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|failure") == 1);
        }
        CHECK(t.api->layout_reads.empty());
        CHECK(t.api->layout_writes.empty());
        CHECK(t.domain_rows.empty()); // no attempted row: the user was never resolved
    }
}

// ───────────────────────── service-scoped tokens (C8) ─────────────────────────────

TEST_CASE("mcp crypto tools: a service-scoped token is refused at C8 for the four `denied` tools and "
          "reaches the three `confined` reads",
          "[mcp][crypto][security]") {
    Twin t;
    t.scope_service = "printers";
    for (const char* tool : {"list_crypto_widgets", "get_crypto_dashboard_layout",
                             "set_crypto_dashboard_layout", "get_crypto_ca_stats"}) {
        INFO(tool);
        t.clear_audit();
        const json r = t.call(tool, args_for(tool));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kPermissionDenied);
        // Refused before the handler: it read, wrote and audited nothing.
        CHECK(t.domain_rows.empty());
    }
    CHECK(t.api->calls() == 0);
    CHECK(t.access_calls == 0);
    // `confined` means the call may REACH the handler (its own fleet gate then decides).
    for (const char* tool : {"get_crypto_libraries", "list_crypto_library_devices", "export_crypto_cbom"}) {
        INFO(tool);
        t.api->scopes.clear();
        const json r = t.call(tool, args_for(tool));
        CHECK_FALSE(r.contains("error"));
        CHECK(t.api->scopes.size() == 1);
    }
}

// ───────────────────────── audit sink failure modes ────────────────────────────────

TEST_CASE("mcp crypto tools: a throwing domain audit sink fails the layout write closed and never "
          "escapes the handler",
          "[mcp][crypto][widgets][security]") {
    Twin t;
    t.domain_audit_throws = true;
    // The "attempted" row throws: caught by the shared audit kernel, so the write is refused.
    const json w = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE(w.contains("error"));
    CHECK(w["error"]["code"] == mcp::kInternalError);
    CHECK(w["error"]["data"]["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(t.api->layout_writes.empty()); // no audit row, no mutation
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 1);
    CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|failure") == 1);
    // A read's success row that throws is a dropped row (audit_persisted:false), not a 500.
    const json s = t.call("get_crypto_ca_stats");
    REQUIRE_FALSE(s.contains("error"));
    CHECK(s["result"]["structuredContent"]["audit_persisted"] == false);
}

TEST_CASE("mcp crypto tools: with no audit sink wired the layout write is refused, not made",
          "[mcp][crypto][widgets][security]") {
    Twin::Opts o;
    o.wire_audit = false;
    Twin t(o);
    const json w = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE(w.contains("error"));
    CHECK(w["error"]["code"] == mcp::kInternalError);
    CHECK(t.api->layout_writes.empty()); // "no audit row, no mutation" needs a sink to write the row to
    CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|success") == 0);
}

// ───────────────────────── identity keying ────────────────────────────────────────

TEST_CASE("mcp crypto tools: the layout is keyed on the username_fn identity, and an empty or "
          "unresolvable one is refused before any row or write",
          "[mcp][crypto][widgets][security]") {
    {
        Twin t;
        t.username = "session-user";
        t.resolved_username = "resolved-user"; // the two differ ONLY in this fake
        REQUIRE_FALSE(t.call("get_crypto_dashboard_layout").contains("error"));
        REQUIRE_FALSE(t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"))
                          .contains("error"));
        CHECK(t.api->layout_reads == std::vector<std::string>{"resolved-user"});
        REQUIRE(t.api->layout_writes.size() == 1);
        CHECK(t.api->layout_writes[0].first == "resolved-user");
        CHECK(audit_count(t.domain_rows,
                          "crypto.dashboard.layout.update|attempted|CryptoDashboard|resolved-user") == 1);
    }
    {
        Twin t;
        t.resolved_username = ""; // resolves, but to no one
        for (const char* tool : {"get_crypto_dashboard_layout", "set_crypto_dashboard_layout"}) {
            INFO(tool);
            const json r = t.call(tool, args_for(tool));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
        }
        CHECK(t.api->layout_reads.empty());
        CHECK(t.api->layout_writes.empty());
        CHECK(t.domain_rows.empty()); // no "attempted" row naming no one
        // The refused destructive call still leaves a generic row.
        CHECK(audit_count(t.generic_rows, "mcp.set_crypto_dashboard_layout|failure") == 1);
    }
}

// ───────────────────────── compound audit failures (Gate 5 chaos, CH-3 / CH-6 / CH-8) ──────────

TEST_CASE("mcp crypto tools: writes never outnumber 'attempted' rows across an audit sink that throws "
          "and then recovers",
          "[mcp][crypto][widgets][security]") {
    Twin t;
    t.domain_audit_throws = true; // the sink records the row, then throws
    REQUIRE(t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout")).contains("error"));
    CHECK(t.api->layout_writes.empty());
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 1);

    t.domain_audit_throws = false; // the sink recovers; the retry is an ordinary save
    const json ok = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE_FALSE(ok.contains("error"));
    CHECK(t.api->layout_writes.size() == 1);
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester") == 2);
    CHECK(audit_count(t.domain_rows, "crypto.dashboard.layout.update|success|CryptoDashboard|tester") == 1);
    // Invariant: a committed write is always preceded by its own persisted "attempted" row.
    CHECK(t.api->layout_writes.size() <= static_cast<std::size_t>(audit_count(
                                             t.domain_rows,
                                             "crypto.dashboard.layout.update|attempted|CryptoDashboard|tester")));
}

TEST_CASE("mcp crypto tools: losing both the 'attempted' row and the generic row still refuses the write, "
          "without throwing, and recovers",
          "[mcp][crypto][widgets][security]") {
    Twin t;
    t.domain_fail_result = "attempted";
    t.generic_audit_ok = false;
    const json r = t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"));
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(t.api->layout_writes.empty());

    t.domain_fail_result.clear();
    t.generic_audit_ok = true;
    REQUIRE_FALSE(t.call("set_crypto_dashboard_layout", args_for("set_crypto_dashboard_layout"))
                      .contains("error"));
    CHECK(t.api->layout_writes.size() == 1);
}

TEST_CASE("mcp crypto tools: a flood of malformed `arguments` is refused before any read, one denial row "
          "each, whether or not the audit sink works",
          "[mcp][crypto][registry_seam]") {
    Twin t;
    constexpr int kRounds = 40;
    for (int i = 0; i < kRounds; ++i) {
        t.generic_audit_ok = (i % 2 == 0); // a failing sink must not change the answer
        for (const char* tool : {"get_crypto_libraries", "get_crypto_ca_stats", "set_crypto_dashboard_layout"}) {
            const json r = t.call(tool, json(nullptr));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
        }
        if (i % 10 == 9) { // a valid call interleaved still succeeds and is audited
            t.generic_audit_ok = true;
            t.clear_audit();
            REQUIRE_FALSE(t.call("get_crypto_libraries").contains("error"));
            CHECK(audit_count(t.generic_rows, "mcp.get_crypto_libraries|success") == 1);
            t.api->scopes.clear();
        }
    }
    CHECK(t.api->layout_writes.empty());
    CHECK(t.api->stats_as_of.empty());
}
