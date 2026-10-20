/**
 * test_mcp_tools_containment.cpp -- the registry tool `list_quarantined_devices`, the MCP twin
 * of GET /api/v1/quarantine (Seam PR2). Dispatches synthesized JSON-RPC requests through
 * McpServer::build_handler() with a fake ToolDeps (provider closures, no store), the same
 * in-process pattern as test_mcp_engine_principal_roles.cpp.
 *
 * Covered: tier admission and the confined classification, the fleet gate as the SOLE gate
 * (a denial writes no handler audit row and reads nothing), confinement by the gate's scope,
 * unwired dependencies, a degraded store (a retryable error, never an empty list), the
 * set-and-proceed `audit_persisted:false` posture, strict `limit` bounds, and byte identity
 * of the `quarantined` array with the REST route's `data` array. The REST half of the byte
 * test needs the real QuarantineStore and so is [pg]-gated (it SKIPs, not passes, without
 * YUZU_TEST_POSTGRES_DSN); the always-on layer compares against the shared builder the REST
 * route calls.
 */

#include "authz_gates.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "mcp_tool_deps.hpp"
#include "quarantine_read_model.hpp"
#include "quarantine_visible.hpp"
#include "rest_api_v1.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <httplib.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::mcp;

namespace {

constexpr const char* kTool = "list_quarantined_devices";

QuarantineRecord make_record(const std::string& agent, std::int64_t at, const std::string& reason = "r",
                             const std::string& whitelist = "10.0.0.1") {
    QuarantineRecord r;
    r.id = at; // internal id: never on the wire
    r.agent_id = agent;
    r.status = "active";
    r.quarantined_by = "seed";
    r.quarantined_at = at;
    r.whitelist = whitelist;
    r.reason = reason;
    return r;
}

struct ContainmentHarness {
    McpServer mcp;
    McpServer::HandlerFn handler;

    // Session: an MCP token of this tier ("" = not an MCP token).
    std::string tier{"readonly"};
    std::vector<std::string> audit_log; // "action|result"
    bool audit_succeeds{true};

    // The fake store behind quarantine_list_fn: newest first, filtered by the pushed-down
    // id list and cut to the pushed-down limit exactly as QuarantineStore::list_quarantined_in
    // does, so a scope or cap bug is observable.
    std::vector<QuarantineRecord> records;
    bool store_degraded{false};
    int list_calls{0};
    std::optional<std::vector<std::string>> last_ids;
    std::size_t last_limit{0};

    // The fleet gate (require_fleet_read twin). gate_status != 0 denies with that status AND a
    // body, as the real gate does; gate_scope is the composed visibility (nullopt = TOP).
    int gate_status{0};
    authz::VisibleSet gate_scope;
    int gate_calls{0};
    std::string gate_type_op;

    // Wiring switches for the unwired cases.
    bool wire_fleet{true};
    bool wire_list{true};

    // The MCP-side perm_fn: counts calls and (by default) allows. The tool is gated by
    // fleet_read_fn ALONE, so a test flips perm_result to false and expects no change.
    bool perm_result{true};
    int perm_calls{0};

    void start() {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "alice";
            s.role = auth::Role::admin;
            s.mcp_tier = tier;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                              const std::string&) -> bool {
            ++perm_calls;
            return perm_result;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string&) -> bool {
            audit_log.push_back(action + "|" + result);
            return audit_succeeds;
        };
        auto agents_fn = []() -> nlohmann::json { return nlohmann::json::array(); };

        ToolDeps deps;
        if (wire_fleet)
            deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                        const std::string& t,
                                        const std::string& op) -> authz::FleetReadGate {
                ++gate_calls;
                gate_type_op = t + ":" + op;
                if (gate_status != 0) {
                    res.status = gate_status;
                    res.set_content(R"({"error":{"code":403,"message":"gate says no"}})",
                                    "application/json");
                    return {};
                }
                return {true, gate_scope};
            };
        if (wire_list)
            deps.quarantine_list_fn = [this](const std::vector<std::string>* ids,
                                             std::size_t limit)
                -> std::optional<std::vector<QuarantineRecord>> {
                ++list_calls;
                last_ids = ids ? std::optional<std::vector<std::string>>(*ids) : std::nullopt;
                last_limit = limit;
                if (store_degraded)
                    return std::nullopt;
                std::vector<QuarantineRecord> out;
                for (const auto& r : records) {
                    if (ids && std::find(ids->begin(), ids->end(), r.agent_id) == ids->end())
                        continue;
                    out.push_back(r);
                    if (limit != 0 && out.size() >= limit)
                        break;
                }
                return out;
            };
        mcp.set_tool_deps(std::move(deps));

        handler = mcp.build_handler(
            std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), std::move(agents_fn),
            /*rbac_store=*/nullptr, /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr, /*audit_store=*/nullptr, /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr, /*policy_store=*/nullptr, /*mgmt_store=*/nullptr,
            /*approval_manager=*/nullptr, /*schedule_engine=*/nullptr, read_only_mode_,
            mcp_disabled_, /*dispatch_fn=*/nullptr);
    }

    std::unique_ptr<httplib::Response> call(const nlohmann::json& args) {
        if (!handler)
            start();
        const nlohmann::json req = {{"jsonrpc", "2.0"},
                                    {"id", 1},
                                    {"method", "tools/call"},
                                    {"params", {{"name", kTool}, {"arguments", args}}}};
        httplib::Request r;
        r.method = "POST";
        r.path = "/mcp/v1/";
        r.body = req.dump();
        r.set_header("Content-Type", "application/json");
        auto res = std::make_unique<httplib::Response>();
        res->status = 200;
        handler(r, *res);
        return res;
    }

    static nlohmann::json result_of(const httplib::Response& res) {
        const auto body = nlohmann::json::parse(res.body);
        REQUIRE(body.contains("result"));
        return body["result"];
    }

    static std::vector<std::string> agent_ids(const nlohmann::json& structured) {
        std::vector<std::string> out;
        for (const auto& row : structured["quarantined"])
            out.push_back(row["agent_id"].get<std::string>());
        return out;
    }

    // How many generic rows for this tool were written (the only audit rows it may write).
    std::size_t tool_audit_rows() const {
        return static_cast<std::size_t>(
            std::count_if(audit_log.begin(), audit_log.end(), [](const std::string& a) {
                return a.rfind("mcp.list_quarantined_devices|", 0) == 0;
            }));
    }

private:
    bool read_only_mode_{false};
    bool mcp_disabled_{false};
};

} // namespace

TEST_CASE("list_quarantined_devices: served as a confined Security:Read read-only tool",
          "[mcp][quarantine][containment_twin]") {
    const auto rows = tool_security_rows_for_test();
    const auto it = std::find_if(rows.begin(), rows.end(),
                                 [](const ToolSecurityRow& r) { return r.name == kTool; });
    REQUIRE(it != rows.end());
    CHECK(it->securable == "Security");
    CHECK(it->operation == "Read");
    CHECK(it->service_scope == ServiceScopeClassForTest::kConfined);

    const auto writes = write_tool_names_for_test();
    CHECK(std::find(writes.begin(), writes.end(), kTool) == writes.end());
}

TEST_CASE("list_quarantined_devices: readonly, operator and supervised tiers are admitted",
          "[mcp][quarantine][containment_twin]") {
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        INFO("tier: " << tier);
        ContainmentHarness h;
        h.tier = tier;
        h.records = {make_record("a", 200), make_record("b", 100)};
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        const auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("result"));
        CHECK_FALSE(body.contains("error"));
        const auto structured = body["result"]["structuredContent"];
        CHECK(ContainmentHarness::agent_ids(structured) == std::vector<std::string>{"a", "b"});
        CHECK(structured["count"] == 2);
        CHECK(structured["more"] == false);
        CHECK_FALSE(structured.contains("audit_persisted"));
        // The fleet gate is the single decision, asked for Security:Read exactly once.
        CHECK(h.gate_calls == 1);
        CHECK(h.gate_type_op == "Security:Read");
    }
}

TEST_CASE("list_quarantined_devices: perm_fn is never consulted, a denying perm_fn changes nothing",
          "[mcp][quarantine][containment_twin][security]") {
    ContainmentHarness h;
    h.perm_result = false; // would refuse the call if the handler stacked a second gate
    h.records = {make_record("a", 200), make_record("b", 100)};
    auto res = h.call(nlohmann::json::object());
    REQUIRE(res);
    const auto body = nlohmann::json::parse(res->body);
    REQUIRE_FALSE(body.contains("error"));
    CHECK(ContainmentHarness::agent_ids(body["result"]["structuredContent"]) ==
          std::vector<std::string>{"a", "b"});
    // Refusal paths do not reach it either.
    (void)h.call({{"limit", 0}});
    CHECK(h.perm_calls == 0);
}

TEST_CASE("list_quarantined_devices: a gate denial is the gate's body, with no read and no handler audit row",
          "[mcp][quarantine][containment_twin]") {
    ContainmentHarness h;
    h.records = {make_record("a", 100)};
    h.gate_status = 403;
    auto res = h.call(nlohmann::json::object());
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("gate says no") != std::string::npos);
    CHECK(h.list_calls == 0);
    CHECK(h.tool_audit_rows() == 0);
}

TEST_CASE("list_quarantined_devices: a confined caller sees only the gate's visible agents",
          "[mcp][quarantine][containment_twin][authz]") {
    ContainmentHarness h;
    h.records = {make_record("a", 300), make_record("b", 200), make_record("c", 100)};

    SECTION("scope {a, c} hides b and is pushed into the read") {
        h.gate_scope = std::unordered_set<std::string>{"a", "c"};
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        const auto structured = ContainmentHarness::result_of(*res)["structuredContent"];
        CHECK(ContainmentHarness::agent_ids(structured) == std::vector<std::string>{"a", "c"});
        CHECK(res->body.find("\"b\"") == std::string::npos);
        // The scope reached the query itself (not a post-filter): the fake saw an id list.
        REQUIRE(h.last_ids.has_value());
        std::vector<std::string> ids = *h.last_ids;
        std::sort(ids.begin(), ids.end());
        CHECK(ids == std::vector<std::string>{"a", "c"});
    }
    SECTION("a present-but-empty scope is deny-all, never the whole list") {
        h.gate_scope = std::unordered_set<std::string>{};
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        const auto structured = ContainmentHarness::result_of(*res)["structuredContent"];
        CHECK(structured["quarantined"].empty());
        CHECK(structured["count"] == 0);
    }
    SECTION("an unfiltered scope reads without an id restriction") {
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        CHECK_FALSE(h.last_ids.has_value());
        CHECK(ContainmentHarness::agent_ids(ContainmentHarness::result_of(*res)["structuredContent"])
                  .size() == 3);
    }
}

TEST_CASE("list_quarantined_devices: unwired dependencies answer an internal error with no hint and no data",
          "[mcp][quarantine][containment_twin]") {
    const auto expect_unwired = [](ContainmentHarness& h) {
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        const auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == -32603);
        CHECK(body["error"]["data"]["retry_after_ms"].is_null());
        CHECK(res->body.find("quarantined") == std::string::npos);
        // The misconfiguration leaves exactly one failure row (and no success row).
        CHECK(h.audit_log == std::vector<std::string>{"mcp.list_quarantined_devices|failure"});
    };
    SECTION("no fleet gate") {
        ContainmentHarness h;
        h.wire_fleet = false;
        expect_unwired(h);
    }
    SECTION("no list closure") {
        ContainmentHarness h;
        h.wire_list = false;
        h.records = {make_record("a", 100)};
        expect_unwired(h);
        CHECK(h.gate_calls == 0); // checked before the gate, so an unwired list is never hinted as retryable
    }
    SECTION("a null ToolDeps pointer") {
        const ToolRecord& rec = containment_tool_records()[0];
        httplib::Request req;
        httplib::Response res;
        const nlohmann::json id = 1;
        const nlohmann::json args = nlohmann::json::object();
        const std::string tier = "readonly";
        const ToolCallContext::PermFn perm = [](const httplib::Request&, httplib::Response&,
                                                const std::string&, const std::string&) {
            return true;
        };
        int audits = 0;
        const ToolCallContext::AuditFn audit = [&](const std::string&, const std::string&) {
            ++audits;
            return true;
        };
        const ToolCallContext::A4ErrorFn a4 = [](int code, std::string_view, std::string_view,
                                                 long retry, std::string_view, bool) {
            return std::to_string(code) + "|" + std::to_string(retry);
        };
        const ToolCallContext ctx{req, res, id, args, tier, perm, audit, a4, nullptr, nullptr};
        rec.handler(ctx);
        CHECK(res.body == "-32603|-1");
        CHECK(audits == 1); // one failure row
    }
}

TEST_CASE("list_quarantined_devices: a degraded store is a retryable error, never an empty list",
          "[mcp][quarantine][containment_twin]") {
    ContainmentHarness h;
    h.records = {make_record("a", 100)};
    h.store_degraded = true;
    auto res = h.call(nlohmann::json::object());
    REQUIRE(res);
    const auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK_FALSE(body.contains("result"));
    CHECK(body["error"]["code"] == -32603);
    CHECK(body["error"]["data"]["retry_after_ms"] == 5000);
    CHECK(res->body.find("\"quarantined\"") == std::string::npos);
    CHECK(h.tool_audit_rows() == 1); // the degraded read is recorded as a failure
    CHECK(h.audit_log.back() == "mcp.list_quarantined_devices|failure");
}

TEST_CASE("list_quarantined_devices: writes only the generic audit row, and a dropped row still returns the data",
          "[mcp][quarantine][containment_twin][audit]") {
    SECTION("persisted: exactly one generic success row, no audit_persisted key") {
        ContainmentHarness h;
        h.records = {make_record("a", 100)};
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        CHECK(h.audit_log == std::vector<std::string>{"mcp.list_quarantined_devices|success"});
        CHECK_FALSE(ContainmentHarness::result_of(*res)["structuredContent"].contains("audit_persisted"));
    }
    SECTION("dropped: audit_persisted:false and the records are still served") {
        ContainmentHarness h;
        h.records = {make_record("a", 100), make_record("b", 50)};
        h.audit_succeeds = false;
        auto res = h.call(nlohmann::json::object());
        REQUIRE(res);
        const auto structured = ContainmentHarness::result_of(*res)["structuredContent"];
        CHECK(structured["audit_persisted"] == false);
        CHECK(ContainmentHarness::agent_ids(structured) == std::vector<std::string>{"a", "b"});
        CHECK(structured["count"] == 2);
    }
}

TEST_CASE("list_quarantined_devices: limit is a strict 1..500 integer, default 200",
          "[mcp][quarantine][containment_twin]") {
    SECTION("refused values answer -32602 with no hint and read nothing") {
        for (const nlohmann::json& bad :
             {nlohmann::json(0), nlohmann::json(501), nlohmann::json(-1), nlohmann::json("5"),
              nlohmann::json(5.0), nlohmann::json(nullptr), nlohmann::json(true),
              nlohmann::json::array()}) {
            INFO("limit: " << bad.dump());
            ContainmentHarness h;
            h.records = {make_record("a", 100)};
            auto res = h.call({{"limit", bad}});
            REQUIRE(res);
            const auto body = nlohmann::json::parse(res->body);
            REQUIRE(body.contains("error"));
            CHECK(body["error"]["code"] == -32602);
            CHECK(body["error"]["data"]["retry_after_ms"].is_null());
            CHECK(h.list_calls == 0);
            // One generic denial row, persisted, so the envelope carries no audit_persisted key.
            CHECK(h.audit_log == std::vector<std::string>{"mcp.list_quarantined_devices|denied"});
            CHECK_FALSE(body["error"]["data"].contains("audit_persisted"));
        }
    }
    SECTION("a dropped denial row is reported in the error envelope") {
        ContainmentHarness h;
        h.audit_succeeds = false;
        h.records = {make_record("a", 100)};
        auto res = h.call({{"limit", 0}});
        REQUIRE(res);
        const auto body = nlohmann::json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == -32602);
        CHECK(body["error"]["data"]["audit_persisted"] == false);
        CHECK(h.audit_log == std::vector<std::string>{"mcp.list_quarantined_devices|denied"});
        CHECK(h.list_calls == 0);
    }
    SECTION("the bounds 1 and 500 are accepted; one extra row is requested to detect more") {
        ContainmentHarness h;
        h.records = {make_record("a", 300), make_record("b", 200), make_record("c", 100)};
        auto one = h.call({{"limit", 1}});
        REQUIRE(one);
        const auto s1 = ContainmentHarness::result_of(*one)["structuredContent"];
        CHECK(ContainmentHarness::agent_ids(s1) == std::vector<std::string>{"a"});
        CHECK(s1["count"] == 1);
        CHECK(s1["more"] == true);
        CHECK(h.last_limit == 2);

        auto max = h.call({{"limit", 500}});
        REQUIRE(max);
        const auto s500 = ContainmentHarness::result_of(*max)["structuredContent"];
        CHECK(s500["count"] == 3);
        CHECK(s500["more"] == false);
        CHECK(h.last_limit == 501);
    }
    SECTION("exactly limit visible records is not more") {
        ContainmentHarness h;
        h.records = {make_record("a", 200), make_record("b", 100)};
        auto res = h.call({{"limit", 2}});
        REQUIRE(res);
        CHECK(ContainmentHarness::result_of(*res)["structuredContent"]["more"] == false);
    }
    SECTION("the default cap is 200 and unknown keys are ignored") {
        ContainmentHarness h;
        for (int i = 0; i < 250; ++i)
            h.records.push_back(make_record("agent-" + std::to_string(i), 1000 - i));
        auto res = h.call({{"unknown_key", "x"}});
        REQUIRE(res);
        const auto structured = ContainmentHarness::result_of(*res)["structuredContent"];
        CHECK(structured["count"] == 200);
        CHECK(structured["more"] == true);
        CHECK(h.last_limit == 201);
    }
}

TEST_CASE("list_quarantined_devices: the quarantined array is byte-identical to the shared builder REST calls",
          "[mcp][quarantine][containment_twin][byte_pin]") {
    ContainmentHarness h;
    h.records = {make_record("agent-1", 200, std::string("line1\nq\"b\\s\tt\x01") + "x\xc3\xa9/",
                             "10.0.0.1,10.0.0.2"),
                 make_record("agent-2", 100)};
    h.records[1].last_applied_at = 1710849600;
    h.records[1].last_confirmed_at = 1710849675;
    auto res = h.call(nlohmann::json::object());
    REQUIRE(res);
    const auto result = ContainmentHarness::result_of(*res);
    const std::string text = result["content"][0]["text"].get<std::string>();

    // The REST route serves exactly quarantine_dump(quarantine_list_data_json(records)).
    const std::string expected = quarantine_dump(quarantine_list_data_json(h.records));
    const std::string head = R"({"quarantined":)";
    REQUIRE(text.rfind(head, 0) == 0);
    const std::size_t tail = text.rfind(R"(,"count":)");
    REQUIRE(tail != std::string::npos);
    CHECK(text.substr(head.size(), tail - head.size()) == expected);
    CHECK(text.substr(tail) == R"(,"count":2,"more":false})");
    // structuredContent is the same payload, parsed.
    CHECK(result["structuredContent"] == nlohmann::json::parse(text));
    // The eight wire keys, in order, and no internal id.
    const auto first = result["structuredContent"]["quarantined"][0];
    CHECK(first.size() == 8);
    CHECK_FALSE(first.contains("id"));
    CHECK_FALSE(first.contains("released_at"));
}

namespace {

// QuarantineStore is Postgres (ADR-0006/0047); SAME key and setup as
// test_rest_quarantine_routes.cpp (the registry replay-verifies the fingerprints agree).
yuzu::test::PgTestTemplate quarantine_twin_tpl{"quarantinestore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantinestore template: store failed to migrate");
}};

} // namespace

TEST_CASE("list_quarantined_devices: MCP array equals the REST GET /api/v1/quarantine data array over one real store",
          "[mcp][quarantine][containment_twin][byte_pin][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_twin_tpl);
    pg::PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore store(qpool);
    REQUIRE(store.is_open());
    REQUIRE(store.quarantine_device("agent-1", "seed", std::string("line1\nq\"b\\s\tt\x01") + "x\xc3\xa9/",
                                    "10.0.0.1,10.0.0.2"));
    REQUIRE(store.quarantine_device("agent-2", "seed2", "plain", ""));

    // REST: the real route over the real store, TOP-scope gate.
    test::TestRouteSink sink;
    RestApiV1 api;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "alice";
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) -> bool {
        return true;
    };
    RestApiV1::FleetReadFn fleet_fn = [](const httplib::Request&, httplib::Response&,
                                         const std::string&,
                                         const std::string&) -> authz::FleetReadGate {
        return {true, std::nullopt};
    };
    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                        /*token_store=*/nullptr, &store,
                        /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                        /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                        /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                        /*audit_store=*/nullptr, /*service_group_fn=*/{},
                        /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                        /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                        /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                        /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/nullptr,
                        /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                        /*result_set_store=*/nullptr, /*command_dispatch_fn=*/{},
                        /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                        /*network_api=*/{}, /*lockout_clear_fn=*/{},
                        /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                        /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
                        /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                        /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                        /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                        /*list_read_fn=*/{}, fleet_fn);
    auto rest = sink.Get("/api/v1/quarantine");
    REQUIRE(rest);
    REQUIRE(rest->status == 200);
    const std::string data_head = R"({"data":)";
    REQUIRE(rest->body.rfind(data_head, 0) == 0);
    const std::size_t rest_tail = rest->body.rfind(R"(,"pagination")");
    REQUIRE(rest_tail != std::string::npos);
    const std::string rest_array = rest->body.substr(data_head.size(), rest_tail - data_head.size());

    // MCP: the same store behind the same provider closure the server wires.
    ContainmentHarness h;
    h.start();
    {
        ToolDeps deps;
        deps.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                const std::string&) -> authz::FleetReadGate {
            return {true, std::nullopt};
        };
        deps.quarantine_list_fn = [&store](const std::vector<std::string>* ids, std::size_t limit) {
            return store.list_quarantined_in(ids, limit);
        };
        h.mcp.set_tool_deps(std::move(deps));
    }
    auto res = h.call(nlohmann::json::object());
    REQUIRE(res);
    const std::string text =
        ContainmentHarness::result_of(*res)["content"][0]["text"].get<std::string>();
    const std::string head = R"({"quarantined":)";
    REQUIRE(text.rfind(head, 0) == 0);
    const std::size_t tail = text.rfind(R"(,"count":)");
    REQUIRE(tail != std::string::npos);
    const std::string mcp_array = text.substr(head.size(), tail - head.size());

    CHECK(mcp_array == rest_array);
    CHECK(mcp_array.find("agent-1") != std::string::npos);
    CHECK(mcp_array.find("agent-2") != std::string::npos);
}
