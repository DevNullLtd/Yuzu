/// @file test_mcp_instruction_authoring.cpp
/// #2146 batch C: the nine MCP twins of the instruction-definition and instruction-set authoring
/// routes (`create_definition`, `update_definition`, `delete_definition`, `import_definition`,
/// `save_definition_yaml`, `validate_definition_yaml`, `list_instruction_sets`,
/// `create_instruction_set`, `delete_instruction_set`; mcp_instruction_authoring.cpp and the
/// dispatch branches in mcp_server.cpp), driven through `tools/call` on a real `McpServer`.
///
/// The fixture is local on purpose (`McpTestServer` in test_mcp_server.cpp is TU-private). One
/// audit sink records every row, domain (`instruction.create` ...) and generic (`mcp.<tool>`),
/// in order, so the audit-first contract is asserted on the sequence: an `attempted` row BEFORE
/// the mutation, one outcome row after, and, when the `attempted` row cannot be stored, NO
/// mutation. Cases that reach a real `InstructionStore` or `ApprovalManager` are `[pg]` (they
/// skip without YUZU_TEST_POSTGRES_DSN); the catalogue, bound, tier, gate and validation cases
/// run without Postgres.
///
/// Matrix: catalogue (annotations, security pairs, write set, approval_id, closed schemas, typed
/// outputs, step-up rows, the closed approval list); schema-vs-constant bounds; tiers (readonly
/// and operator refused, no ticket minted, supervised ticket flow for the definition writes and
/// both deletes, create_instruction_set unticketed); service-scoped default-deny; RBAC gate
/// denial; per-tool happy path, validation refusal, store refusal; audit-first refusal with no
/// mutation; a lost outcome row (`audit_persisted:false`); the import signature gate.

#include "approval_manager.hpp"
#include "event_emit.hpp"
#include "instruction_definition_model.hpp"
#include "instruction_store.hpp"
#include "mcp_instruction_authoring.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_policy.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "pg/pg_pool.hpp"
#include "service_scope_policy.hpp"
#include "step_up_mcp_policy.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "test_expected_twins.hpp"
#include "test_instruction_store_faults.hpp" // ExistsProbeFault

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
namespace mcp = yuzu::server::mcp;
namespace iauth = yuzu::server::mcp::instruction_authoring;

namespace {

constexpr const char* kWriteTools[] = {"create_definition", "update_definition",
                                       "delete_definition", "import_definition",
                                       "save_definition_yaml", "create_instruction_set",
                                       "delete_instruction_set"};
/// The write tools that are approval-gated at the supervised tier (InstructionDefinition:Write and
/// every Delete). create_instruction_set (InstructionSet:Write) is deliberately not.
constexpr const char* kTicketedTools[] = {"create_definition", "update_definition",
                                          "delete_definition", "import_definition",
                                          "save_definition_yaml", "delete_instruction_set"};
constexpr const char* kAllTools[] = {"create_definition",       "update_definition",
                                     "delete_definition",       "import_definition",
                                     "save_definition_yaml",    "validate_definition_yaml",
                                     "list_instruction_sets",   "create_instruction_set",
                                     "delete_instruction_set"};

constexpr const char* kYaml = "---\n"
                              "apiVersion: yuzu.io/v1alpha1\n"
                              "kind: InstructionDefinition\n"
                              "metadata:\n"
                              "  id: test.mcp.yaml\n"
                              "  displayName: MCP YAML\n"
                              "spec:\n"
                              "  plugin: os_info\n"
                              "  action: os_name\n"
                              "  type: question\n";

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
    std::string key() const { return action + "|" + result; }
};

struct EmitRow {
    std::string event_type;
    json attrs;
    json payload_data;
};

/// A referrer lookup that finds nothing (the default wiring of the delete guard).
DefinitionReferrersFn no_referrers() {
    return [](const std::string&) -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        return std::vector<DefinitionReferrer>{};
    };
}

/// Declaration order: `server` before `handler` (the handler captures the fixture by reference).
struct Mcp {
    InstructionStore* store{nullptr};
    ApprovalManager* approvals{nullptr};

    std::string tier{"supervised"};
    std::string token_scope_service;
    std::string username{"tester"};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perms; ///< every (securable, operation) asked

    std::vector<AuditRow> audits;
    /// Rows for which this returns true report "not stored" (the sink answers false).
    std::function<bool(const AuditRow&)> audit_fails;
    /// Rows for which this returns true make the sink THROW (the row is still recorded first).
    std::function<bool(const AuditRow&)> audit_throws;
    std::vector<EmitRow> emits;
    bool emit_throws{false}; ///< the event hook records the emission, then throws

    bool read_only{false};
    bool disabled{false};
    bool audit_wired{true}; ///< false hands build_handler an EMPTY audit sink
    /// The delete guard's referrer lookup (UP-6). Wired by default to "nothing references it";
    /// `referrers` overrides, `referrers_wired = false` leaves it unset (a fail-closed refusal).
    bool referrers_wired{true};
    DefinitionReferrersFn referrers;

    mcp::McpServer server;
    mcp::McpServer::HandlerFn handler;

    Mcp() = default;

    /// Builds the handler. Called after the pointers above are set.
    void wire() {
        if (referrers_wired)
            server.set_definition_referrers_fn(referrers ? referrers : no_referrers());
        server.set_emit_event_fn([this](const std::string& event_type, const httplib::Request&,
                                        const json& attrs, const json& payload_data) {
            emits.push_back({event_type, attrs, payload_data});
            if (emit_throws)
                throw std::runtime_error("event bus down");
        });
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = username;
            s.role = auth::Role::admin;
            s.mcp_tier = tier;
            s.token_scope_service = token_scope_service;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& operation) {
            perms.emplace_back(securable, operation);
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            AuditRow row{action, result, target_type, target_id, detail};
            const bool stored = !(audit_fails && audit_fails(row));
            const bool throws = audit_throws && audit_throws(row);
            audits.push_back(std::move(row)); // a row that failed to store is still recorded here
            if (throws)
                throw std::runtime_error("audit sink down");
            return stored;
        };
        auto agents_fn = []() { return json::array(); };
        handler = server.build_handler(
            std::move(auth_fn), std::move(perm_fn),
            audit_wired ? mcp::McpServer::AuditFn(std::move(audit_fn)) : mcp::McpServer::AuditFn{},
            std::move(agents_fn),
            /*rbac_store=*/nullptr, store, /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr, /*audit_store=*/nullptr, /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr, /*policy_store=*/nullptr, /*mgmt_store=*/nullptr,
            approvals, /*schedule_engine=*/nullptr, read_only, disabled);
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

    json call(const std::string& tool, const json& arguments = json::object()) {
        json params = {{"name", tool}, {"arguments", arguments}};
        auto res = post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 7}, {"params", params}}
                            .dump());
        REQUIRE(res);
        return json::parse(res->body);
    }

    /// The supervised ticket flow: mint, a different principal approves, re-call with the id.
    /// Returns the re-call's response. `ticket_out` (optional) receives the approval id.
    json call_ticketed(const std::string& tool, json arguments, std::string* ticket_out = nullptr) {
        REQUIRE(approvals != nullptr);
        const json first = call(tool, arguments);
        REQUIRE(first.contains("error"));
        REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
        const std::string approval_id = first["error"]["data"]["approval_id"].get<std::string>();
        REQUIRE_FALSE(approval_id.empty());
        REQUIRE(approvals->approve(approval_id, "reviewer-bob", "ok"));
        if (ticket_out != nullptr)
            *ticket_out = approval_id;
        arguments["approval_id"] = approval_id;
        return call(tool, arguments);
    }

    bool has_row(const std::string& action, const std::string& result) const {
        return std::any_of(audits.begin(), audits.end(), [&](const AuditRow& r) {
            return r.action == action && r.result == result;
        });
    }
    /// The domain rows (everything but the generic `mcp.<tool>` ones), as "action|result".
    std::vector<std::string> domain_keys() const {
        std::vector<std::string> out;
        for (const auto& r : audits)
            if (r.action.rfind("mcp.", 0) != 0)
                out.push_back(r.key());
        return out;
    }
    void clear() {
        audits.clear();
        emits.clear();
        perms.clear();
    }
};

const json& tool_entry(const json& tools_list_result, const std::string& name) {
    for (const auto& t : tools_list_result["result"]["tools"])
        if (t["name"] == name)
            return t;
    FAIL("tool not served: " << name);
    static const json none;
    return none;
}

/// The structured result of a successful call.
json ok_result(const json& r) { // by value: callers pass temporaries
    REQUIRE_FALSE(r.contains("error"));
    return r["result"]["structuredContent"];
}

json error_data(const json& r) {
    REQUIRE(r.contains("error"));
    return r["error"]["data"];
}

/// The newest domain row's "action|result"; an empty list fails the test, not the process.
std::string last_domain_key(const Mcp& m) {
    const auto keys = m.domain_keys();
    REQUIRE_FALSE(keys.empty());
    return keys.back();
}

} // namespace

// ───────────────────────── catalogue (no Postgres) ────────────────────────────────

TEST_CASE("mcp instruction authoring: the nine tools are served with the ruled annotations",
          "[mcp][instruction_authoring]") {
    Mcp m;
    m.wire();
    auto res = m.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);

    struct Expect {
        const char* name;
        bool read_only;
        bool destructive;
        bool idempotent;
    };
    // Ruling 11: create_* Additive,false; update/import/save_yaml Destructive,false; deletes
    // Destructive (idempotent: a second delete only answers not found); list/validate ReadOnly.
    const Expect expect[] = {
        {"create_definition", false, false, false},  {"update_definition", false, true, false},
        {"delete_definition", false, true, true},    {"import_definition", false, true, false},
        {"save_definition_yaml", false, true, false}, {"validate_definition_yaml", true, false, true},
        {"list_instruction_sets", true, false, true}, {"create_instruction_set", false, false, false},
        {"delete_instruction_set", false, true, true},
    };
    for (const auto& e : expect) {
        INFO(e.name);
        const json& t = tool_entry(listed, e.name);
        CHECK(t["annotations"]["readOnlyHint"] == e.read_only);
        CHECK(t["annotations"]["destructiveHint"] == e.destructive);
        CHECK(t["annotations"]["idempotentHint"] == e.idempotent);
        CHECK(t["annotations"]["openWorldHint"] == false);
        // Typed output (A5), closed.
        CHECK(t["outputSchema"]["type"] == "object");
        CHECK(t["outputSchema"]["required"].is_array());
        CHECK(t["outputSchema"]["additionalProperties"] == false);
        // Closed input (C8 pre-validates it before any ticket is minted).
        CHECK(t["inputSchema"]["additionalProperties"] == false);
        // The description is decision-grade prose naming its REST twin and its securable pair.
        const std::string desc = t["description"].get<std::string>();
        CHECK(desc.find("Mirrors ") != std::string::npos);
        CHECK(desc.find("Requires ") != std::string::npos);
    }
}

TEST_CASE("mcp instruction authoring: security pairs; write set; twin rows and step-up rows agree",
          "[mcp][instruction_authoring][stepup]") {
    const auto rows = mcp::tool_security_rows_for_test();
    const auto pair_of = [&](std::string_view name) {
        const auto it = std::find_if(rows.begin(), rows.end(),
                                     [&](const auto& r) { return r.name == name; });
        REQUIRE(it != rows.end());
        // Never confined, never global_safe: kServiceScopeGlobalSafe stays empty (ADR-1006).
        CHECK(it->service_scope == mcp::ServiceScopeClassForTest::kDenied);
        return std::pair<std::string, std::string>{std::string(it->securable),
                                                   std::string(it->operation)};
    };
    using P = std::pair<std::string, std::string>;
    CHECK(pair_of("create_definition") == P{"InstructionDefinition", "Write"});
    CHECK(pair_of("update_definition") == P{"InstructionDefinition", "Write"});
    CHECK(pair_of("delete_definition") == P{"InstructionDefinition", "Delete"});
    CHECK(pair_of("import_definition") == P{"InstructionDefinition", "Write"});
    CHECK(pair_of("save_definition_yaml") == P{"InstructionDefinition", "Write"});
    CHECK(pair_of("validate_definition_yaml") == P{"InstructionDefinition", "Read"});
    CHECK(pair_of("list_instruction_sets") == P{"InstructionSet", "Read"});
    CHECK(pair_of("create_instruction_set") == P{"InstructionSet", "Write"});
    CHECK(pair_of("delete_instruction_set") == P{"InstructionSet", "Delete"});

    // The --mcp-read-only guard keys on this set: exactly the seven non-Read tools are in it.
    std::set<std::string> writes;
    for (const auto sv : mcp::write_tool_names_for_test())
        writes.insert(std::string(sv));
    for (const char* name : kAllTools) {
        const bool is_write = std::find_if(std::begin(kWriteTools), std::end(kWriteTools),
                                           [&](const char* w) { return std::string_view(w) == name; }) !=
                              std::end(kWriteTools);
        INFO(name);
        CHECK((writes.count(name) == 1) == is_write);
    }

    // Twin table (test_expected_twins.hpp): one row per tool, same pair.
    for (const char* name : kAllTools) {
        INFO(name);
        const auto it = std::find_if(std::begin(twin_table::kExpectedTwins),
                                     std::end(twin_table::kExpectedTwins),
                                     [&](const auto& r) { return r.tool == name; });
        REQUIRE(it != std::end(twin_table::kExpectedTwins));
        const auto p = pair_of(name);
        CHECK(std::string(it->securable) == p.first);
        CHECK(std::string(it->operation) == p.second);
        CHECK(it->is_read == (p.second == "Read"));
    }

    // Step-up: every non-Read tool has a kExempt kContentAuthoring row naming its REST twin; the
    // Read tools have none (a stale row would fail the policy self-check).
    for (const char* name : kWriteTools) {
        INFO(name);
        const auto* row = mcp_step_up_policy_for(name);
        REQUIRE(row != nullptr);
        CHECK(row->cls == StepUpClass::kExempt);
        CHECK(row->reason == step_up_detail::kContentAuthoring);
        CHECK_FALSE(row->rest_pattern.empty());
    }
    CHECK(mcp_step_up_policy_for("validate_definition_yaml") == nullptr);
    CHECK(mcp_step_up_policy_for("list_instruction_sets") == nullptr);
}

TEST_CASE("mcp instruction authoring: every write tool declares approval_id; the ticketed set is closed",
          "[mcp][instruction_authoring][policy]") {
    std::map<std::string, std::string> schemas;
    for (const auto& r : mcp::input_schemas_for_test())
        schemas.emplace(r.name, r.schema_json);
    for (const char* name : kWriteTools) {
        INFO(name);
        const json s = json::parse(schemas.at(name));
        CHECK(s["properties"].contains("approval_id"));
        CHECK(s["properties"]["approval_id"]["type"] == "string");
    }

    // requires_approval: InstructionDefinition:Write (ruling 2) and every Delete at the supervised
    // tier; InstructionSet:Write and every Read are not. validate stays Read-gated and ungated.
    for (const char* name : kTicketedTools) {
        INFO(name);
        const auto rows = mcp::tool_security_rows_for_test();
        const auto it = std::find_if(rows.begin(), rows.end(),
                                     [&](const auto& r) { return r.name == name; });
        REQUIRE(it != rows.end());
        CHECK(mcp::requires_approval_for_tool("supervised", name, std::string(it->securable),
                                              std::string(it->operation)));
        // The operator tier never reaches a ticket for these: tier_allows refuses first.
        CHECK_FALSE(mcp::tier_allows("operator", std::string(it->securable),
                                     std::string(it->operation)));
    }
    CHECK_FALSE(mcp::requires_approval("supervised", "InstructionSet", "Write"));
    CHECK_FALSE(mcp::requires_approval("supervised", "InstructionDefinition", "Read"));
    CHECK_FALSE(mcp::requires_approval("supervised", "InstructionSet", "Read"));
    // The closed lists are untouched: kApprovalExemptTools is still exactly {cancel_execution} and
    // none of the nine tools is on it; kServiceScopeGlobalSafe is still seeded empty.
    CHECK(mcp::kApprovalExemptTools.size() == 1);
    CHECK(mcp::kApprovalExemptTools[0] == "cancel_execution");
    for (const char* name : kAllTools)
        CHECK_FALSE(mcp::tool_exempt_from_approval(name));
    CHECK(authz::kServiceScopeGlobalSafe.size() == 0);
    CHECK_FALSE(authz::service_scope_global_safe("InstructionDefinition", "Write"));
    CHECK_FALSE(authz::service_scope_global_safe("InstructionSet", "Write"));
}

TEST_CASE("mcp instruction authoring: served schema bounds equal the handler constants",
          "[mcp][instruction_authoring][bounds]") {
    std::map<std::string, json> schemas;
    for (const auto& r : mcp::input_schemas_for_test())
        schemas.emplace(r.name, json::parse(r.schema_json));
    const auto& create = schemas.at("create_definition")["properties"];
    const auto& update = schemas.at("update_definition")["properties"];
    for (const json* p : {&create, &update}) {
        CHECK((*p)["id"]["maxLength"] == iauth::kIdMaxLen);
        CHECK((*p)["name"]["maxLength"] == iauth::kNameMaxLen);
        CHECK((*p)["version"]["maxLength"] == iauth::kVersionMaxLen);
        CHECK((*p)["description"]["maxLength"] == iauth::kDescriptionMaxLen);
        CHECK((*p)["plugin"]["maxLength"] == iauth::kDispatchIdentMaxLen);
        CHECK((*p)["action"]["maxLength"] == iauth::kDispatchIdentMaxLen);
        CHECK((*p)["plugin"]["pattern"] == "^[A-Za-z0-9_.-]+$");
        CHECK((*p)["action"]["pattern"] == "^[A-Za-z0-9_.-]+$");
        CHECK((*p)["instruction_set_id"]["maxLength"] == iauth::kIdMaxLen);
        CHECK((*p)["gather_ttl_seconds"]["minimum"] == 1);
        CHECK((*p)["gather_ttl_seconds"]["maximum"] == iauth::kMaxGatherTtlSeconds);
        CHECK((*p)["response_ttl_days"]["minimum"] == 1);
        CHECK((*p)["response_ttl_days"]["maximum"] == iauth::kMaxResponseTtlDays);
        CHECK((*p)["approval_mode"]["enum"] == json::array({"auto", "role-gated", "always"}));
        CHECK((*p)["type"]["enum"] == json::array({"question", "action"}));
    }
    // The REST twins and these tools enforce ONE set of numbers: the shared builder's. The iauth
    // constants alias them (so they cannot diverge), and the served schema literals above are
    // compared to the iauth constants, so a schema edit that moves a bound fails here.
    CHECK(iauth::kNameMaxLen == kMaxDefinitionNameLen);
    CHECK(iauth::kVersionMaxLen == kMaxDefinitionVersionLen);
    CHECK(iauth::kDescriptionMaxLen == kMaxDefinitionDescriptionLen);
    CHECK(iauth::kInstructionSetIdMaxLen == kMaxDefinitionInstructionSetIdLen);
    for (const json* p : {&create, &update}) {
        CHECK((*p)["name"]["maxLength"] == kMaxDefinitionNameLen);
        CHECK((*p)["version"]["maxLength"] == kMaxDefinitionVersionLen);
        CHECK((*p)["description"]["maxLength"] == kMaxDefinitionDescriptionLen);
        CHECK((*p)["instruction_set_id"]["maxLength"] == kMaxDefinitionInstructionSetIdLen);
        CHECK((*p)["name"]["minLength"] == 1);
        CHECK((*p)["version"]["minLength"] == 1);
        // The schema's `type` enum is exactly what the shared builder accepts.
        for (const auto& t : (*p)["type"]["enum"])
            CHECK(is_valid_definition_type(t.get<std::string>()));
        CHECK_FALSE(is_valid_definition_type("bogus"));
    }
    // The twin-only dispatch-identifier bound is the shared builder's.
    CHECK(iauth::kDispatchIdentMaxLen == kMaxDefinitionDispatchIdentifierLen);
    CHECK(iauth::kMaxGatherTtlSeconds == kMaxDefinitionGatherTtlSeconds);
    CHECK(iauth::kMaxResponseTtlDays == kMaxDefinitionResponseTtlDays);
    CHECK(schemas.at("create_definition")["required"] == json::array({"name", "type", "plugin"}));
    CHECK(schemas.at("update_definition")["required"] == json::array({"id"}));
    CHECK(update["expected_updated_at"]["minimum"] == 0);
    CHECK(schemas.at("delete_definition")["properties"]["id"]["maxLength"] == iauth::kIdMaxLen);
    // M3-2: the version token the supervised tier requires; optional in the schema (the tier check
    // answers -32602 before any ticket), non-negative like update's.
    CHECK(schemas.at("delete_definition")["required"] == json::array({"id"}));
    CHECK(schemas.at("delete_definition")["properties"]["expected_updated_at"]["type"] ==
          "integer");
    CHECK(schemas.at("delete_definition")["properties"]["expected_updated_at"]["minimum"] == 0);
    CHECK(schemas.at("delete_instruction_set")["properties"]["id"]["maxLength"] ==
          iauth::kIdMaxLen);

    const auto& yaml = schemas.at("save_definition_yaml")["properties"];
    CHECK(yaml["yaml_source"]["maxLength"] == iauth::kYamlSourceMaxBytes);
    CHECK(yaml["yaml_source"]["minLength"] == 1);
    CHECK(yaml["id"]["maxLength"] == iauth::kIdMaxLen);
    CHECK(schemas.at("validate_definition_yaml")["properties"]["yaml_source"]["maxLength"] ==
          iauth::kYamlSourceMaxBytes);
    CHECK(schemas.at("import_definition")["properties"]["document"]["type"] == "object");
    CHECK(schemas.at("import_definition")["required"] == json::array({"document"}));
    CHECK(schemas.at("validate_definition_yaml")["required"] == json::array({"yaml_source"}));

    const auto& set = schemas.at("create_instruction_set")["properties"];
    CHECK(set["name"]["maxLength"] == kMaxInstructionSetNameLen);
    CHECK(set["description"]["maxLength"] == kMaxInstructionSetDescriptionLen);
    // The store's own YAML cap is what the schema advertises.
    CHECK(iauth::kYamlSourceMaxBytes == 1024u * 1024u);
}

// ───────────────────────── tiers, gates (no Postgres) ─────────────────────────────

TEST_CASE("mcp instruction authoring: readonly and operator tokens are refused every write; and no "
          "ticket or row is created",
          "[mcp][instruction_authoring][security]") {
    for (const char* tier : {"readonly", "operator"}) {
        for (const char* tool : kWriteTools) {
            INFO(tier << " " << tool);
            Mcp m;
            m.tier = tier;
            m.wire();
            const json r = m.call(tool, {{"id", "x"}, {"name", "n"}, {"type", "question"},
                                         {"plugin", "p"}, {"document", json::object()},
                                         {"yaml_source", "y"}});
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kTierDenied);
            // Only the generic denial row; no domain row, no store touched (store is null).
            CHECK(m.domain_keys().empty());
            CHECK(m.emits.empty());
            CHECK(m.perms.empty());
        }
    }
}

TEST_CASE("mcp instruction authoring: the Read tools are admitted at every tier",
          "[mcp][instruction_authoring]") {
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        INFO(tier);
        Mcp m;
        m.tier = tier;
        m.wire();
        const json r = m.call("validate_definition_yaml", {{"yaml_source", kYaml}});
        const auto sc = ok_result(r);
        CHECK(sc["valid"] == true);
        CHECK(sc["errors"].empty());
        REQUIRE(m.perms.size() == 1);
        CHECK(m.perms[0] == std::make_pair(std::string("InstructionDefinition"), std::string("Read")));
        // No store, no domain audit row: the generic mcp.validate_definition_yaml row only.
        CHECK(m.domain_keys().empty());
        CHECK(m.has_row("mcp.validate_definition_yaml", "success"));
    }
}

TEST_CASE("mcp instruction authoring: a service-scoped token is denied every tool at C8; before any "
          "gate; row or ticket",
          "[mcp][instruction_authoring][security]") {
    for (const char* tool : kAllTools) {
        INFO(tool);
        Mcp m;
        m.token_scope_service = "printers";
        m.wire();
        const json r = m.call(tool, {{"id", "x"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kPermissionDenied);
        CHECK(m.perms.empty());
        CHECK(m.domain_keys().empty());
        CHECK(m.emits.empty());
    }
}

TEST_CASE("mcp instruction authoring: an RBAC denial is the gate's own body and writes no domain row",
          "[mcp][instruction_authoring][security]") {
    // create_instruction_set is the one write that is neither tier-refused here nor ticketed, so
    // the handler's own perm_fn is the first gate it meets; the Read tools likewise.
    Mcp m;
    m.perm_allow = false;
    m.wire();
    for (const auto& [tool, args, pair] : std::vector<std::tuple<std::string, json, std::pair<std::string, std::string>>>{
             {"create_instruction_set", {{"name", "n"}}, {"InstructionSet", "Write"}},
             {"validate_definition_yaml", {{"yaml_source", kYaml}}, {"InstructionDefinition", "Read"}},
             {"list_instruction_sets", json::object(), {"InstructionSet", "Read"}}}) {
        INFO(tool);
        m.clear();
        json params = {{"name", tool}, {"arguments", args}};
        auto res = m.post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3}, {"params", params}}
                              .dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == R"({"error":"forbidden"})");
        REQUIRE(m.perms.size() == 1);
        CHECK(m.perms[0] == pair);
        CHECK(m.domain_keys().empty());
        CHECK(m.emits.empty());
    }
}

TEST_CASE("mcp instruction authoring: a supervised ticketed tool with no approval manager is refused "
          "without a ticket; and an unwired store is a retryable error",
          "[mcp][instruction_authoring]") {
    Mcp m;
    m.wire();
    const json denied = m.call("delete_definition", {{"id", "d1"}});
    REQUIRE(denied.contains("error"));
    CHECK(denied["error"]["code"] == mcp::kTierDenied);
    CHECK(error_data(denied)["approval_id"].is_null());
    CHECK(m.domain_keys().empty());

    // create_instruction_set is unticketed: with no store it answers the retryable store error.
    const json r = m.call("create_instruction_set", {{"name", "n"}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(error_data(r)["reason"] == "store_unavailable");
    CHECK(error_data(r)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(m.domain_keys().empty());
}

// ───────────────────────── ticket subject and version token (no Postgres) ────────

// UP-1: the bytes of a 4 MiB document must not become the ticket subject. Turns red if
// ticket_subject stops replacing the large field with its length and digest.
TEST_CASE("mcp ticket_subject: a 4 MiB import and a 1 MiB YAML bind a fixed-size digest; one "
          "changed byte changes it; approval_id is the only argument stripped",
          "[mcp][instruction_authoring][security]") {
    CHECK(iauth::ticket_binds_digest("import_definition"));
    CHECK(iauth::ticket_binds_digest("save_definition_yaml"));
    CHECK_FALSE(iauth::ticket_binds_digest("update_definition"));
    CHECK_FALSE(iauth::ticket_binds_digest("create_definition"));

    json big = {{"document",
                 {{"id", "big"}, {"name", "n"}, {"pad", std::string(4u * 1024 * 1024, 'p')}}}};
    const auto a = iauth::ticket_subject("import_definition", big);
    REQUIRE(a.has_value());
    CHECK(a->size() < 300);
    CHECK(a->find("pppp") == std::string::npos);
    CHECK(a->find("\"tool\":\"import_definition\"") != std::string::npos);
    CHECK(a->find("\"document_sha256\":\"") != std::string::npos);
    CHECK(a->find("\"document_bytes\":") != std::string::npos);
    const json parsed = json::parse(*a);
    const std::string hex = parsed["document_sha256"].get<std::string>();
    CHECK(hex.size() == 64);
    CHECK(std::all_of(hex.begin(), hex.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }));

    // The same document: the same subject, with or without the recall's approval_id.
    json recall = big;
    recall["approval_id"] = "ticket-1";
    CHECK(*iauth::ticket_subject("import_definition", recall) == *a);
    // One changed byte anywhere in the document: a different subject.
    json changed = big;
    changed["document"]["pad"].get_ref<std::string&>()[1000] = 'q';
    CHECK(*iauth::ticket_subject("import_definition", changed) != *a);
    // A document of a different length too.
    json longer = big;
    longer["document"]["pad"].get_ref<std::string&>() += 'p';
    CHECK(*iauth::ticket_subject("import_definition", longer) != *a);

    // The YAML twin: the id and the version token stay in the subject verbatim.
    const std::string yaml = std::string(kYaml) + "# " + std::string(1024 * 1024 - 400, 'y') + "\n";
    json y = {{"yaml_source", yaml}, {"id", "some.id"}, {"updated_at", 7}};
    const auto ys = iauth::ticket_subject("save_definition_yaml", y);
    REQUIRE(ys.has_value());
    CHECK(ys->size() < 400);
    CHECK(ys->find("yyyy") == std::string::npos);
    const json yp = json::parse(*ys);
    CHECK(yp["id"] == "some.id");
    CHECK(yp["updated_at"] == 7);
    CHECK(yp["tool"] == "save_definition_yaml");
    CHECK(yp["yaml_source_bytes"] == yaml.size());
    json y2 = y;
    y2["updated_at"] = 8;
    CHECK(*iauth::ticket_subject("save_definition_yaml", y2) != *ys);
    json y3 = y;
    y3["yaml_source"].get_ref<std::string&>().back() = ' ';
    CHECK(*iauth::ticket_subject("save_definition_yaml", y3) != *ys);
}

// F4 (Gate 8): an approver shown only a digest approves blind. Turns red if ticket_subject stops
// carrying the definition's plain fields, or stops folding them.
TEST_CASE("mcp ticket_subject: the approver reads the definition's id; name; plugin; action and "
          "approval_mode; bounded and folded; beside the digest",
          "[mcp][instruction_authoring][security]") {
    const json doc = {{"id", "sub.one"},        {"name", "Sub One"}, {"plugin", "os_info"},
                      {"action", "os_name"},    {"approval_mode", "always"},
                      {"yaml_source", kYaml}};
    const auto a = iauth::ticket_subject("import_definition", {{"document", doc}});
    REQUIRE(a.has_value());
    const json pa = json::parse(*a);
    CHECK(pa["tool"] == "import_definition");
    CHECK(pa["definition_id"] == "sub.one");
    CHECK(pa["name"] == "Sub_One"); // log_token folds a space
    CHECK(pa["plugin"] == "os_info");
    CHECK(pa["action"] == "os_name");
    CHECK(pa["approval_mode"] == "always");
    CHECK_FALSE(pa.contains("parse_error"));
    // The page's short cell shows only the START of the subject, so it opens with the tool and
    // the dispatch-relevant fields (approval_mode first: the one a downgrade flips), never with
    // the id, the name or the hash.
    CHECK(a->find("\"document_sha256\"") > a->find("\"approval_mode\""));
    CHECK(a->rfind("{\"tool\":\"import_definition\",\"approval_mode\":\"always\","
                   "\"plugin\":\"os_info\",\"action\":\"os_name\",\"definition_id\":\"sub.one\","
                   "\"name\":\"Sub_One\"",
                   0) == 0);

    // Two documents differing ONLY in approval_mode: different subjects AND different digests.
    json doc2 = doc;
    doc2["approval_mode"] = "auto";
    const json pb = json::parse(*iauth::ticket_subject("import_definition", {{"document", doc2}}));
    CHECK(pb["approval_mode"] == "auto");
    CHECK(pb["document_sha256"] != pa["document_sha256"]);
    CHECK(pb != pa);

    // A dispatch field a SIGNED document omits (plugin, action, approval_mode) is read from its
    // yaml_source (what a signed import runs); its id and name are NOT: the store takes them from
    // the document only. The subject builder does not verify, so placeholder strings stand for
    // the signature.
    json bare = {{"id", "sub.two"},
                 {"yaml_source", kYaml},
                 {"signature", std::string(128, 'a')},
                 {"publicKey", std::string(64, 'b')}};
    const json pc = json::parse(*iauth::ticket_subject("import_definition", {{"document", bare}}));
    CHECK(pc["definition_id"] == "sub.two"); // the document's own id wins over the YAML's
    CHECK(pc["plugin"] == "os_info");
    CHECK(pc["action"] == "os_name");
    CHECK_FALSE(pc.contains("name")); // kYaml's displayName is never the imported name
    json no_id = bare;
    no_id.erase("id");
    const json pni = json::parse(*iauth::ticket_subject("import_definition", {{"document", no_id}}));
    CHECK_FALSE(pni.contains("definition_id")); // kYaml's metadata.id is never the imported id
    CHECK(pni["plugin"] == "os_info");

    // The store lowercases the action of every non-trusted import, so the subject shows that.
    json upper = doc;
    upper["action"] = "OS_Name";
    CHECK(json::parse(*iauth::ticket_subject("import_definition", {{"document", upper}}))["action"] ==
          "os_name");

    // The YAML twin: the same fields from the YAML, beside the target id and the version token.
    const json py = json::parse(*iauth::ticket_subject(
        "save_definition_yaml", {{"yaml_source", kYaml}, {"id", "target.id"}, {"updated_at", 5}}));
    CHECK(py["definition_id"] == "test.mcp.yaml");
    CHECK(py["plugin"] == "os_info");
    CHECK(py["action"] == "os_name");
    CHECK(py["name"] == "MCP_YAML");
    CHECK(py["id"] == "target.id");
    CHECK(py["updated_at"] == 5);
    CHECK(py.contains("yaml_source_sha256"));

    // Hostile free text: no raw CR/LF, ESC or U+2028 survives, and each field is bounded.
    const std::string hostile = std::string("a\r\nforged") + "\x1b[31m" + "\xe2\x80\xa8" + "z";
    json evil = doc;
    evil["name"] = hostile + std::string(1000, 'n');
    evil["plugin"] = hostile;
    const auto es = iauth::ticket_subject("import_definition", {{"document", evil}});
    REQUIRE(es.has_value());
    for (const char bad : {'\r', '\n', '\x1b'})
        CHECK(es->find(bad) == std::string::npos);
    CHECK(es->find("\xe2\x80\xa8") == std::string::npos);
    CHECK(es->size() < 1500);

    // Nothing readable: parse_error, still the digest, no validation text.
    const json pn = json::parse(*iauth::ticket_subject("import_definition", {{"document", json::array()}}));
    CHECK(pn["parse_error"] == true);
    CHECK(pn.contains("document_sha256"));
    const json pn2 = json::parse(
        *iauth::ticket_subject("save_definition_yaml", {{"yaml_source", "kind: nope\n"}}));
    CHECK(pn2["parse_error"] == true);
    CHECK(pn2.contains("yaml_source_sha256"));
    const json pn3 = json::parse(*iauth::ticket_subject(
        "save_definition_yaml", {{"yaml_source", std::string("a\0b", 3)}}));
    CHECK(pn3["parse_error"] == true);

    // An unknown argument cannot paint a false field over a real one.
    const json pf = json::parse(*iauth::ticket_subject(
        "import_definition", {{"document", doc}, {"plugin", "remediation"}}));
    CHECK(pf["plugin"] == "os_info");
    CHECK(pf["arg_plugin"] == "remediation");
    CHECK_FALSE(pf.contains("arg_arg_plugin"));

    // The mint and the recall compute the identical subject (the recall adds approval_id).
    CHECK(*iauth::ticket_subject("import_definition", {{"document", doc}, {"approval_id", "t"}}) == *a);
}

// H1 (Gate 8 pass 2, 5 agents): the subject must show the approval_mode the STORE will write. An
// unsigned import never reads its yaml_source for the dispatch columns (only the signed branch
// does), so a YAML stating `approval: always` beside a document with no approval_mode stores
// `auto`; the subject once showed `always`. Turns red if summarise_ticket_argument fills a field
// from the yaml_source of an unsigned document again, or stops emitting the effective
// approval_mode.
TEST_CASE("mcp ticket_subject: an unsigned import shows the approval_mode it stores; never the "
          "one its unread yaml_source states; a signed one shows the YAML's",
          "[mcp][instruction_authoring][security]") {
    const std::string yaml_always = std::string(kYaml) + "  approval: always\n";
    const auto subject = [](const char* tool, const json& args) {
        return json::parse(*iauth::ticket_subject(tool, args));
    };
    const json unsigned_doc = {{"id", "h1.one"}, {"name", "n"}, {"yaml_source", yaml_always}};
    const json s_unsigned = subject("import_definition", {{"document", unsigned_doc}});
    CHECK(s_unsigned["approval_mode"] == "auto");
    CHECK_FALSE(s_unsigned.contains("plugin")); // the unsigned store does not read it either
    CHECK_FALSE(s_unsigned.contains("action"));
    CHECK(s_unsigned["definition_id"] == "h1.one");

    json signed_doc = unsigned_doc;
    signed_doc["signature"] = std::string(128, 'a');
    signed_doc["publicKey"] = std::string(64, 'b');
    const json s_signed = subject("import_definition", {{"document", signed_doc}});
    CHECK(s_signed["approval_mode"] == "always"); // bind_signed_dispatch_columns takes the YAML's
    CHECK(s_signed["plugin"] == "os_info");
    CHECK(s_signed["action"] == "os_name");

    // One of the two signing fields (or an empty one) is not the signed branch.
    for (const char* only : {"signature", "publicKey"}) {
        json half = unsigned_doc;
        half[only] = std::string(std::string_view(only) == "signature" ? 128 : 64, 'c');
        CHECK(subject("import_definition", {{"document", half}})["approval_mode"] == "auto");
    }
    json empty_sig = signed_doc;
    empty_sig["signature"] = "";
    CHECK(subject("import_definition", {{"document", empty_sig}})["approval_mode"] == "auto");

    // Omitted everywhere: `auto`, still present. Stated by the document: the document's.
    const json s_none = subject("import_definition", {{"document", {{"id", "h1.two"}}}});
    CHECK(s_none["approval_mode"] == "auto");
    CHECK(subject("import_definition",
                  {{"document", {{"id", "h1.two"}, {"approval_mode", "role-gated"}}}})["approval_mode"] ==
          "role-gated");

    // The subjects differ, so a ticket minted for the one cannot be redeemed for the other.
    CHECK(s_unsigned != s_signed);

    // A YAML CREATE (no or an empty `id`) stores the YAML's approval, else `auto`; an UPDATE keeps
    // the stored value when the YAML states none, so shows none.
    const std::string yaml_auto = std::string(kYaml) + "  approval: auto\n";
    CHECK(subject("save_definition_yaml", {{"yaml_source", yaml_always}})["approval_mode"] ==
          "always");
    CHECK(subject("save_definition_yaml", {{"yaml_source", kYaml}})["approval_mode"] == "auto");
    CHECK(subject("save_definition_yaml", {{"yaml_source", kYaml}, {"id", ""}})["approval_mode"] ==
          "auto");
    const json upd_none = {{"yaml_source", kYaml}, {"id", "target.id"}, {"updated_at", 5}};
    CHECK_FALSE(subject("save_definition_yaml", upd_none).contains("approval_mode"));
    json upd_auto = upd_none;
    upd_auto["yaml_source"] = yaml_auto;
    CHECK(subject("save_definition_yaml", upd_auto)["approval_mode"] == "auto");
    json upd_always = upd_none;
    upd_always["yaml_source"] = yaml_always;
    CHECK(subject("save_definition_yaml", upd_always)["approval_mode"] == "always");
    // A create and an update of the same YAML are different tickets.
    CHECK(subject("save_definition_yaml", {{"yaml_source", kYaml}}) !=
          subject("save_definition_yaml", upd_none));
}

// A non-string `id` on a YAML save is not a create: no throw, the subject is still produced with
// the argument verbatim, and `approval_mode` is NOT shown (kYaml states none; a create would show
// `auto`). Turns red if `yaml_creates` is computed as `id_it == end || !is_string()` (a wrong-typed
// id would then read as a create and paint `approval_mode: auto`).
TEST_CASE("mcp ticket_subject: a YAML save with a non-string id is no create and shows no "
          "approval_mode",
          "[mcp][instruction_authoring][security]") {
    const json create = json::parse(
        *iauth::ticket_subject("save_definition_yaml", {{"yaml_source", kYaml}}));
    REQUIRE(create.contains("approval_mode")); // the control: a real create shows `auto`
    CHECK(create["approval_mode"] == "auto");
    for (const json& bad : {json(5), json(nullptr), json::array({"a"}), json::object({{"k", "v"}})}) {
        INFO(bad.dump());
        std::optional<std::string> subject;
        REQUIRE_NOTHROW(subject = iauth::ticket_subject("save_definition_yaml",
                                                        {{"yaml_source", kYaml}, {"id", bad}}));
        REQUIRE(subject.has_value());
        const json p = json::parse(*subject);
        CHECK(p["tool"] == "save_definition_yaml");
        CHECK(p["id"] == bad);
        CHECK(p.contains("yaml_source_sha256"));
        CHECK_FALSE(p.contains("approval_mode"));
    }
}

// H3: a client argument named like an OMITTED summary key must not paint that field. Turns red if
// the reserved set shrinks back to "keys already in the output".
TEST_CASE("mcp ticket_subject: an argument named like any summary key is kept under arg_; "
          "whether or not the subject emitted that key",
          "[mcp][instruction_authoring][security]") {
    const json doc = {{"id", "h3.one"}};
    json args = {{"document", doc}};
    for (const char* k : {"approval_mode", "plugin", "action", "name", "definition_id", "tool",
                          "parse_error", "document_bytes", "document_sha256"})
        args[k] = "painted";
    const json p = json::parse(*iauth::ticket_subject("import_definition", args));
    CHECK(p["approval_mode"] == "auto"); // the effective value, not the painted one
    CHECK(p["tool"] == "import_definition");
    CHECK_FALSE(p.contains("plugin"));
    CHECK_FALSE(p.contains("action"));
    CHECK_FALSE(p.contains("name"));
    CHECK_FALSE(p.contains("parse_error"));
    CHECK(p["definition_id"] == "h3.one");
    CHECK(p["document_bytes"].is_number());
    CHECK(p["document_sha256"].get<std::string>().size() == 64);
    for (const char* k : {"approval_mode", "plugin", "action", "name", "definition_id", "tool",
                          "parse_error", "document_bytes", "document_sha256"}) {
        INFO(k);
        CHECK(p[std::string("arg_") + k] == "painted");
    }
    // The YAML twin: an UPDATE of a YAML stating no approval emits none, and a painted one stays
    // arg_ (a create shows its effective `auto`, also not the painted value).
    const json py = json::parse(*iauth::ticket_subject(
        "save_definition_yaml",
        {{"yaml_source", kYaml}, {"id", "t.id"}, {"updated_at", 1}, {"approval_mode", "painted"}}));
    CHECK_FALSE(py.contains("approval_mode"));
    CHECK(py["arg_approval_mode"] == "painted");
    const json pcreate = json::parse(*iauth::ticket_subject(
        "save_definition_yaml", {{"yaml_source", kYaml}, {"approval_mode", "painted"}}));
    CHECK(pcreate["approval_mode"] == "auto");
    CHECK(pcreate["arg_approval_mode"] == "painted");
    // Chained collisions stay deterministic and distinct.
    const json pc = json::parse(*iauth::ticket_subject(
        "import_definition", {{"document", doc}, {"plugin", "a"}, {"arg_plugin", "b"}}));
    CHECK(pc["arg_plugin"] == "b");
    CHECK(pc["arg_arg_plugin"] == "a");
}

// H2: the argument merge was O(N^2) on nlohmann::ordered_json (80,000 keys took 10 s of one handler
// thread, twice per ticketed call, before any argument-count check). Turns red if the subject is
// built through ordered_json inserts again: 10,000 -> 40,000 keys is ~16x there, ~4x when linear.
// A ratio (best of 3, the small time floored at 1 ms), not an absolute bound, so a slow or
// sanitizer box stays green; the 30 s backstop only catches a hang.
TEST_CASE("mcp ticket_subject: 40000 arguments cost under 10x of 10000 (linear; not quadratic); "
          "deterministically",
          "[mcp][instruction_authoring][security]") {
    const auto args_of = [](int n) {
        json args = {{"document", {{"id", "h2.one"}}}};
        for (int i = 0; i < n; ++i)
            args["k" + std::to_string(i)] = i;
        return args;
    };
    const auto best_of_3 = [](const json& args) {
        auto best = std::chrono::steady_clock::duration::max();
        for (int r = 0; r < 3; ++r) {
            const auto t0 = std::chrono::steady_clock::now();
            const auto a = iauth::ticket_subject("import_definition", args);
            best = std::min(best, std::chrono::steady_clock::now() - t0);
            REQUIRE(a.has_value());
        }
        return best;
    };
    const json small = args_of(10000);
    const json large = args_of(40000);
    const auto a = iauth::ticket_subject("import_definition", small);
    const auto b = iauth::ticket_subject("import_definition", small);
    REQUIRE(a.has_value());
    CHECK(a == b);
    const json p = json::parse(*a);
    CHECK(p.size() == 10000 + 5); // tool, approval_mode, definition_id, the two digest keys, the args
    CHECK(p["k9999"] == 9999);

    const auto t_small = std::max(best_of_3(small), std::chrono::steady_clock::duration(
                                                       std::chrono::milliseconds(1)));
    const auto t_large = best_of_3(large);
    using Ms = std::chrono::duration<double, std::milli>;
    const double small_ms = Ms(t_small).count();
    const double large_ms = Ms(t_large).count();
    INFO("t(10k)=" << small_ms << " ms, t(40k)=" << large_ms << " ms, ratio=" << large_ms / small_ms);
    CHECK(t_large < 10 * t_small);
    CHECK(t_large < std::chrono::seconds(30));
}

// UP-2: the version token the supervised tier requires. Turns red if missing_version_token stops
// asking for it (or asks for it on a create / delete / import).
TEST_CASE("mcp missing_version_token: update_definition and an id-bearing save_definition_yaml "
          "need the version; create; delete and import do not",
          "[mcp][instruction_authoring][security]") {
    const auto missing = [](const char* tool, const json& args) {
        return iauth::missing_version_token(tool, args);
    };
    const auto upd = missing("update_definition", {{"id", "x"}, {"name", "n"}});
    REQUIRE(upd.has_value());
    CHECK(upd->find("expected_updated_at") != std::string::npos);
    CHECK(upd->find("supervised") != std::string::npos);
    CHECK(upd->find("get_definition") != std::string::npos);
    CHECK_FALSE(missing("update_definition", {{"id", "x"}, {"expected_updated_at", 0}}).has_value());

    const auto yml = missing("save_definition_yaml", {{"yaml_source", kYaml}, {"id", "x"}});
    REQUIRE(yml.has_value());
    CHECK(yml->find("updated_at") != std::string::npos);
    CHECK_FALSE(missing("save_definition_yaml", {{"yaml_source", kYaml}, {"id", "x"}, {"updated_at", 5}})
                    .has_value());
    // No id (or an empty one) is a create: nothing to version.
    CHECK_FALSE(missing("save_definition_yaml", {{"yaml_source", kYaml}}).has_value());
    CHECK_FALSE(missing("save_definition_yaml", {{"yaml_source", kYaml}, {"id", ""}}).has_value());

    CHECK_FALSE(missing("create_definition", {{"name", "n"}}).has_value());
    // M3-3: a delete approves one version too.
    const auto del = missing("delete_definition", {{"id", "x"}});
    REQUIRE(del.has_value());
    CHECK(del->find("delete_definition requires expected_updated_at") != std::string::npos);
    CHECK(del->find("supervised") != std::string::npos);
    CHECK(del->find("get_definition") != std::string::npos);
    CHECK_FALSE(missing("delete_definition", {{"id", "x"}, {"expected_updated_at", 0}}).has_value());
    // A non-integer token is not a token.
    CHECK(missing("delete_definition", {{"id", "x"}, {"expected_updated_at", "5"}}).has_value());
    CHECK_FALSE(missing("import_definition", {{"document", json::object()}}).has_value());
}

// ───────────────────────── validate_definition_yaml (no Postgres) ─────────────────

TEST_CASE("mcp validate_definition_yaml: {valid; errors}; strict argument shape; no store and no "
          "domain audit row",
          "[mcp][instruction_authoring]") {
    Mcp m;
    m.wire();
    {
        const json bad = m.call("validate_definition_yaml", {{"yaml_source", "not: a definition"}});
        const auto sc = ok_result(bad);
        CHECK(sc["valid"] == false);
        CHECK_FALSE(sc["errors"].empty());
        for (const auto& e : sc["errors"])
            CHECK(e.is_string());
    }
    for (const json& args : {json{{"yaml_source", 5}}, json{{"yaml_source", kYaml}, {"id", "x"}},
                             json{{"nope", 1}}, json::object()}) {
        INFO(args.dump());
        const json r = m.call("validate_definition_yaml", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(error_data(r)["reason"] == "invalid");
    }
    CHECK(m.domain_keys().empty());
    // approval_id is the control-plane key: stripped, never "an unknown field".
    const json with_ticket = m.call("validate_definition_yaml",
                                    {{"yaml_source", kYaml}, {"approval_id", "ignored"}});
    CHECK(ok_result(with_ticket)["valid"] == true);
}

namespace {

/// A definition YAML whose plugin and action are spliced in raw (quote them for odd values).
std::string yaml_with_dispatch(const std::string& plugin, const std::string& action) {
    return "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n"
           "  id: test.mcp.dispatch\n  displayName: D\nspec:\n  plugin: " + plugin +
           "\n  action: " + action + "\n  type: question\n";
}

} // namespace

TEST_CASE("mcp validate_definition_yaml: a plugin or action save_definition_yaml would refuse is "
          "not valid",
          "[mcp][instruction_authoring]") {
    Mcp m;
    m.wire();
    const std::vector<std::pair<std::string, std::string>> bad = {
        {yaml_with_dispatch("\"my plugin\"", "os_name"), "plugin"},
        {yaml_with_dispatch(std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'p'), "os_name"),
         "plugin"},
        {yaml_with_dispatch("os_info", std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'a')),
         "action"},
        {yaml_with_dispatch("os_info", "\"bad action\""), "action"},
    };
    for (const auto& [y, field] : bad) {
        INFO(field);
        const auto sc = ok_result(m.call("validate_definition_yaml", {{"yaml_source", y}}));
        CHECK(sc["valid"] == false);
        REQUIRE_FALSE(sc["errors"].empty());
        CHECK(sc["errors"].dump().find(field) != std::string::npos);
    }
    CHECK(ok_result(m.call("validate_definition_yaml",
                           {{"yaml_source", yaml_with_dispatch("os_info", "os_name")}}))["valid"] ==
          true);
    CHECK(m.domain_keys().empty());
}

// ───────────────────────── Postgres-backed cases ──────────────────────────────────

namespace {

yuzu::test::PgTestTemplate mcp_authoring_tpl{
    "instructionstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instructionstore mcp authoring template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    InstructionStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
    }

    std::optional<InstructionDefinition> get(const std::string& id) {
        auto r = store.get_definition(id);
        REQUIRE(r.has_value());
        return *r;
    }
    /// The stored row for `id`; the row being absent fails the test (no unchecked dereference).
    InstructionDefinition row(const std::string& id) {
        auto r = get(id);
        REQUIRE(r.has_value());
        return *r;
    }
    std::vector<InstructionSet> sets() {
        auto r = store.list_sets();
        REQUIRE(r.has_value());
        return *r;
    }
    /// The supervised-tier delete arguments: the id plus the version token read from the store
    /// (a delete without it is refused before a ticket exists).
    json delete_args(const std::string& id) {
        return {{"id", id}, {"expected_updated_at", row(id).updated_at}};
    }
};

// H1 against the REAL store: the approval_mode the subject displays equals the one stored, for an
// unsigned import (the stricter YAML value is NOT applied). Turns red if either side moves alone.
TEST_CASE("mcp ticket_subject: the displayed approval_mode equals the stored one for an unsigned "
          "import",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false); // --allow-unsigned-definitions
    const json doc = {{"id", "h1.real"},
                      {"name", "n"},
                      {"type", "question"},
                      {"plugin", "os_info"},
                      {"action", "os_name"},
                      {"yaml_source", std::string(kYaml) + "  approval: always\n"}};
    const json shown = json::parse(*iauth::ticket_subject("import_definition", {{"document", doc}}));
    const auto imported = w.store.import_definition_json(doc.dump());
    REQUIRE(imported.has_value());
    CHECK(w.row("h1.real").approval_mode == shown["approval_mode"].get<std::string>());
    CHECK(shown["approval_mode"] == "auto");
}

/// A supervised fixture with the approval manager wired (its own template database).
struct Supervised {
    yuzu::test::ApprovalManagerPg appr_bundle;
    Mcp m;
    explicit Supervised(InstructionStore* store) {
        appr_bundle->create_tables();
        m.store = store;
        m.approvals = appr_bundle.get();
        m.wire();
    }
};

json minimal_create() {
    return {{"name", "Hostname"}, {"type", "question"}, {"plugin", "os_info"}, {"action", "OS_Name"}};
}

} // namespace

TEST_CASE("mcp create_definition: ticket flow; legacy defaults; created_by; audit-first rows and event",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    // First call: a ticket, and NOTHING created, no domain row yet.
    const json first = m.call("create_definition", minimal_create());
    REQUIRE(first.contains("error"));
    CHECK(first["error"]["code"] == mcp::kApprovalRequired);
    CHECK(m.domain_keys().empty());
    CHECK(m.emits.empty());

    m.clear();
    std::string ticket;
    const json r = m.call_ticketed("create_definition", minimal_create(), &ticket);
    const auto sc = ok_result(r);
    const std::string id = sc["id"].get<std::string>();
    REQUIRE_FALSE(id.empty());
    CHECK_FALSE(sc.contains("audit_persisted"));
    // The control-plane approval_id is stripped: the strict builder never saw it.

    const auto stored = w.get(id);
    REQUIRE(stored.has_value());
    CHECK(stored->name == "Hostname");
    CHECK(stored->action == "os_name"); // lowercased, as the legacy route does
    CHECK(stored->version == "1.0");
    CHECK(stored->approval_mode == "auto"); // the legacy default
    CHECK(stored->enabled);
    CHECK(stored->gather_ttl_seconds == 300);
    CHECK(stored->response_ttl_days == 90);
    CHECK(stored->created_by == "tester");

    // Audit-first order: attempted BEFORE the success row, same action, domain rows only.
    const auto keys = m.domain_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "instruction.create|attempted");
    CHECK(keys[1] == "instruction.create|success");
    // The attempted row records what is about to be created, including the approval mode.
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r2) {
        return r2.action == "instruction.create" && r2.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail.find("approval_mode=auto") != std::string::npos);
    CHECK(attempt->target_type == "InstructionDefinition");
    CHECK(m.has_row("mcp.create_definition", "success"));
    // C-6: the row that records the change names the approval that authorised it (the attempted
    // row, written before the change, stays as it was).
    CHECK(attempt->detail.find("approval_id") == std::string::npos);
    const auto success_row = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r2) {
        return r2.action == "instruction.create" && r2.result == "success";
    });
    REQUIRE(success_row != m.audits.end());
    CHECK(success_row->detail.ends_with(" approval_id=" + ticket));

    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.created");
    CHECK(m.emits[0].payload_data["instruction_id"] == id);
}

TEST_CASE("mcp create_definition: schema refusals are -32602 BEFORE any ticket is minted; "
          "store refusals are audited denied",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    const std::vector<std::pair<std::string, json>> bad = {
        {"unknown key", {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"yaml_source", "x"}}},
        {"parameter_schema is not accepted",
         {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"parameter_schema", "{}"}}},
        {"bad type", {{"name", "n"}, {"type", "weird"}, {"plugin", "p"}}},
        {"plugin charset", {{"name", "n"}, {"type", "question"}, {"plugin", "bad plugin!"}}},
        {"action too long",
         {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"action", std::string(129, 'a')}}},
        {"ttl zero", {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"gather_ttl_seconds", 0}}},
        {"ttl too big",
         {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"response_ttl_days", 3651}}},
        {"approval_mode vocabulary",
         {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"approval_mode", "never"}}},
        {"missing required", {{"name", "n"}}},
        {"name too long", {{"name", std::string(129, 'n')}, {"type", "question"}, {"plugin", "p"}}},
        {"description too long",
         {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"description", std::string(513, 'd')}}},
        {"float ttl", {{"name", "n"}, {"type", "question"}, {"plugin", "p"}, {"gather_ttl_seconds", 5.5}}},
    };
    for (const auto& [label, args] : bad) {
        INFO(label);
        m.clear();
        const json r = m.call("create_definition", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        // Pre-mint: no approval id in the error, no domain row, nothing created.
        CHECK(error_data(r)["approval_id"].is_null());
        CHECK(m.domain_keys().empty());
    }
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());

    // A store-level refusal (the store owns the id charset): reaches the handler via the ticket,
    // writes attempted + denied, creates nothing, never echoes anything but the store's text.
    m.clear();
    const json r = m.call_ticketed("create_definition",
                                   {{"id", "mcp.reserved"}, {"name", "n"}, {"type", "question"},
                                    {"plugin", "p"}});
    // `mcp.`-prefixed ids are reserved (reserved_definition_id.hpp).
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(r)["reason"] == "invalid");
    const auto keys = m.domain_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "instruction.create|attempted");
    CHECK(keys[1] == "instruction.create|denied");
    CHECK_FALSE(w.get("mcp.reserved").has_value());

    // A duplicate id is a conflict.
    m.clear();
    const json ok1 = m.call_ticketed("create_definition", {{"id", "dup.one"}, {"name", "n"},
                                                           {"type", "question"}, {"plugin", "p"}});
    REQUIRE_FALSE(ok1.contains("error"));
    m.clear();
    const json dup = m.call_ticketed("create_definition", {{"id", "dup.one"}, {"name", "n"},
                                                           {"type", "question"}, {"plugin", "p"}});
    REQUIRE(dup.contains("error"));
    CHECK(dup["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(dup)["reason"] == "conflict");
    CHECK(last_domain_key(m) == "instruction.create|denied");
    REQUIRE(m.audits.size() >= 2);
    CHECK(m.audits[m.audits.size() - 2].detail == "duplicate_id");
}

/// The attempt-row refusal contract for every write twin: the `attempted` row is not stored
/// (the sink answers false, or throws) so the call is refused `audit_unavailable`, nothing is
/// mutated, no outcome row and no event follow.
static void check_attempt_row_refusal(PgWired& w, Mcp& m, bool throws) {
    // A seed definition and set, created with the sink healthy.
    REQUIRE(w.store
                .create_definition([] {
                    InstructionDefinition d;
                    d.id = "af.seed";
                    d.name = "Seed";
                    d.version = "1.0";
                    d.type = "question";
                    d.plugin = "os_info";
                    d.action = "os_name";
                    d.approval_mode = "always";
                    d.enabled = true;
                    d.gather_ttl_seconds = 300;
                    d.response_ttl_days = 90;
                    return d;
                }())
                .has_value());
    InstructionSet seed_set;
    seed_set.id = "af-set";
    seed_set.name = "Seed set";
    REQUIRE(w.store.create_set(seed_set).has_value());

    const auto attempted = [](const AuditRow& r) { return r.result == "attempted"; };
    // A returned-false sink and a THROWING sink refuse the write identically.
    if (throws)
        m.audit_throws = attempted;
    else
        m.audit_fails = attempted;

    struct Case {
        const char* tool;
        json args;
    };
    const Case cases[] = {
        {"create_definition", {{"id", "af.new"}, {"name", "n"}, {"type", "question"}, {"plugin", "p"}}},
        {"update_definition",
         {{"id", "af.seed"}, {"approval_mode", "auto"},
          {"expected_updated_at", w.row("af.seed").updated_at}}},
        {"delete_definition", w.delete_args("af.seed")},
        {"save_definition_yaml", {{"yaml_source", kYaml}}},
        {"import_definition",
         {{"document", {{"id", "af.imp"}, {"name", "I"}, {"version", "1.0"}, {"type", "question"},
                         {"plugin", "os_info"}, {"action", "os_name"}, {"yaml_source", kYaml}}}}},
        {"create_instruction_set", {{"name", "af new set"}}},
        {"delete_instruction_set", {{"id", "af-set"}}},
    };
    for (const auto& c : cases) {
        INFO(c.tool);
        m.clear();
        const bool ticketed = std::string_view(c.tool) != "create_instruction_set";
        const json r = ticketed ? m.call_ticketed(c.tool, c.args) : m.call(c.tool, c.args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(error_data(r)["reason"] == "audit_unavailable");
        CHECK(error_data(r)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        CHECK(r["error"]["message"].get<std::string>().find("NOT") != std::string::npos);
        // Exactly the one attempted row; no outcome row, no event.
        const auto keys = m.domain_keys();
        REQUIRE(keys.size() == 1);
        CHECK(keys[0].find("|attempted") != std::string::npos);
        CHECK(m.emits.empty());
    }
    // Nothing was mutated.
    CHECK_FALSE(w.get("af.new").has_value());
    CHECK_FALSE(w.get("af.imp").has_value());
    CHECK_FALSE(w.get("test.mcp.yaml").has_value());
    const auto seed = w.get("af.seed");
    REQUIRE(seed.has_value());
    CHECK(seed->approval_mode == "always"); // the update did not run
    REQUIRE(w.sets().size() == 1);          // the set create did not run, the delete did not run
    CHECK(w.sets()[0].id == "af-set");
}

TEST_CASE("mcp definition writes: an attempt row that is not stored refuses and mutates nothing",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    check_attempt_row_refusal(w, s.m, /*throws=*/false);
}

TEST_CASE("mcp definition writes: an attempt row whose sink THROWS refuses exactly like a failed "
          "row and mutates nothing",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    check_attempt_row_refusal(w, s.m, /*throws=*/true);
}

TEST_CASE("mcp definition writes: a lost OUTCOME row keeps the change and flags audit_persisted:false",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    m.audit_fails = [](const AuditRow& r) { return r.result == "success"; };

    const json r = m.call_ticketed("create_definition", {{"id", "lost.row"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}});
    const auto sc = ok_result(r);
    CHECK(sc["id"] == "lost.row");
    CHECK(sc["audit_persisted"] == false);
    CHECK(w.get("lost.row").has_value()); // the mutation stands

    // create_instruction_set (unticketed): the same flag.
    const json set = m.call("create_instruction_set", {{"name", "lost row set"}});
    CHECK(ok_result(set)["audit_persisted"] == false);
    CHECK_FALSE(w.sets().empty());

    // A sink that THROWS on the outcome row is the same as one that returns false: the completed
    // write stands and the flag is set, never a bare error that hides a mutation that happened.
    m.audit_fails = nullptr;
    m.audit_throws = [](const AuditRow& row) {
        return row.action == "instruction_set.create" && row.result == "success";
    };
    m.clear();
    const json thrown = m.call("create_instruction_set", {{"name", "thrown row set"}});
    CHECK(ok_result(thrown)["audit_persisted"] == false);
    CHECK(w.sets().size() == 2); // both creates stand
    m.audit_throws = [](const AuditRow& row) {
        return row.action == "instruction.create" && row.result == "success";
    };
    const json thrown_def = m.call_ticketed("create_definition", {{"id", "thrown.row"}, {"name", "n"},
                                                                  {"type", "question"}, {"plugin", "p"}});
    CHECK(ok_result(thrown_def)["audit_persisted"] == false);
    CHECK(w.get("thrown.row").has_value());

    // A returned-false attempt row on the ungated create is refused (the throwing-attempt case is
    // pinned across all seven writes by the check_attempt_row_refusal twins above).
    m.audit_throws = nullptr;
    m.audit_fails = [](const AuditRow& row) { return row.result == "attempted"; };
    m.clear();
    const json refused = m.call("create_instruction_set", {{"name", "never"}});
    REQUIRE(refused.contains("error"));
    CHECK(error_data(refused)["reason"] == "audit_unavailable");
}

TEST_CASE("mcp definition writes: a lost OUTCOME row on an ERROR path flags audit_persisted:false "
          "in the error data (a healthy sink never does)",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "err.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    REQUIRE_FALSE(m.call("create_instruction_set", {{"name", "dup set"}}).contains("error"));

    // Only the DOMAIN outcome rows fail: a lost generic `mcp.<tool>` row would set the flag
    // through another path and make this test green without the per-path capture.
    const auto fail_domain_outcomes = [](const AuditRow& r) {
        return r.action.rfind("mcp.", 0) != 0 && r.result != "attempted";
    };
    struct Case {
        const char* what;
        const char* reason;
        std::function<json()> call;
    };
    const std::vector<Case> cases = {
        {"create duplicate id (conflict)", "conflict",
         [&] {
             return m.call_ticketed("create_definition", {{"id", "err.one"}, {"name", "n"},
                                                          {"type", "question"}, {"plugin", "p"}});
         }},
        {"create id '.' (invalid)", "invalid",
         [&] {
             return m.call_ticketed("create_definition", {{"id", "."}, {"name", "n"},
                                                          {"type", "question"}, {"plugin", "p"}});
         }},
        // An update or delete of a stale or absent row is refused before a ticket exists (UP-12)
        // and never reaches an outcome row; its handler-level twin is the test below.
        {"import unsigned (invalid)", "invalid",
         [&] {
             return m.call_ticketed(
                 "import_definition",
                 {{"document", {{"id", "err.imp"}, {"name", "n"}, {"version", "1.0"},
                                {"type", "question"}, {"plugin", "p"}, {"action", "a"}}}});
         }},
        {"import duplicate id (conflict)", "conflict",
         [&] {
             // --allow-unsigned-definitions for this one call, so the duplicate id (not the
             // signature gate) is what refuses it.
             w.store.set_require_signed_definitions(false);
             auto r = m.call_ticketed(
                 "import_definition",
                 {{"document", {{"id", "err.one"}, {"name", "n"}, {"version", "1.0"},
                                {"type", "question"}, {"plugin", "p"}, {"action", "a"}}}});
             w.store.set_require_signed_definitions(true);
             return r;
         }},
        // The store refuses an over-long set name (the builder does not bound it). A set conflict
        // needs a duplicate id, and ids are generated, so that settle site is unreachable here.
        // InstructionSet:Write is not ticketed, so a plain call reaches the handler.
        {"create set, name too long (invalid)", "invalid",
         [&] { return m.call("create_instruction_set", {{"name", std::string(4096, 'x')}}); }},
        {"delete unknown set (not_found)", "not_found",
         [&] { return m.call_ticketed("delete_instruction_set", {{"id", "no-such-set"}}); }},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        m.audit_fails = nullptr;
        m.clear();
        const json healthy = c.call();
        REQUIRE(healthy.contains("error"));
        CHECK(error_data(healthy)["reason"] == c.reason);
        CHECK_FALSE(error_data(healthy).contains("audit_persisted"));

        m.audit_fails = fail_domain_outcomes;
        m.clear();
        const json lost = c.call();
        REQUIRE(lost.contains("error"));
        CHECK(error_data(lost)["reason"] == c.reason);
        CHECK(error_data(lost)["audit_persisted"] == false);
    }
}

TEST_CASE("mcp update_definition: partial update; binding change recorded old -> new; concurrency; "
          "not found",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    const json created = m.call_ticketed("create_definition",
                                         {{"id", "up.one"}, {"name", "Before"}, {"type", "question"},
                                          {"plugin", "os_info"}, {"action", "os_name"},
                                          {"approval_mode", "always"}, {"description", "keep me"}});
    REQUIRE_FALSE(created.contains("error"));
    const auto before = w.get("up.one");
    REQUIRE(before.has_value());

    m.clear();
    const json r = m.call_ticketed("update_definition",
                                   {{"id", "up.one"}, {"name", "After"}, {"approval_mode", "auto"},
                                    {"plugin", "system_info"},
                                    {"expected_updated_at", before->updated_at}});
    const auto sc = ok_result(r);
    CHECK(sc["id"] == "up.one");
    CHECK(sc["updated"] == true);
    const auto after = w.get("up.one");
    REQUIRE(after.has_value());
    CHECK(after->name == "After");
    CHECK(after->approval_mode == "auto");
    CHECK(after->plugin == "system_info");
    CHECK(after->description == "keep me"); // an absent key is untouched
    CHECK(after->action == "os_name");

    // The audit rows carry the plugin / approval_mode change (the privilege-relevant edit).
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& row) {
        return row.action == "instruction.update" && row.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail.find("approval_mode: always -> auto") != std::string::npos);
    CHECK(attempt->detail.find("plugin: os_info -> system_info") != std::string::npos);
    CHECK(m.has_row("instruction.update", "success"));
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.updated");

    // expected_updated_at mismatch -> conflict, nothing written.
    m.clear();
    // The early version check (UP-12) refuses it before a ticket exists: no domain row.
    const json stale = m.call("update_definition",
                              {{"id", "up.one"}, {"name", "Stale"},
                               {"expected_updated_at", after->updated_at + 99999}});
    REQUIRE(stale.contains("error"));
    CHECK(stale["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(stale)["reason"] == "conflict");
    CHECK(w.row("up.one").name == "After");
    CHECK(m.domain_keys().empty());

    // A matching expected_updated_at applies.
    m.clear();
    const json fresh = m.call_ticketed("update_definition",
                                       {{"id", "up.one"}, {"enabled", false},
                                        {"expected_updated_at", w.row("up.one").updated_at}});
    REQUIRE_FALSE(fresh.contains("error"));
    CHECK_FALSE(w.row("up.one").enabled);

    // Unknown id -> not_found, and NO row (the id was unknown before the attempt).
    m.clear();
    const json missing = m.call("update_definition", {{"id", "no.such"}, {"name", "x"},
                                                      {"expected_updated_at", 1}});
    REQUIRE(missing.contains("error"));
    CHECK(error_data(missing)["reason"] == "not_found");
    CHECK(m.domain_keys().empty());

    // The strict builder still refuses what the schema cannot express: an id is not editable.
    m.clear();
    const json empty_name = m.call("update_definition", {{"id", "up.one"}, {"name", ""}});
    REQUIRE(empty_name.contains("error"));
    CHECK(empty_name["error"]["code"] == mcp::kInvalidParams);
}

TEST_CASE("mcp delete_definition: ticketed; deletes; event; unknown id is not_found and audited denied",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "del.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));

    // First call mints a ticket and deletes nothing.
    m.clear();
    const json first = m.call("delete_definition", w.delete_args("del.one"));
    REQUIRE(first.contains("error"));
    CHECK(first["error"]["code"] == mcp::kApprovalRequired);
    CHECK(w.get("del.one").has_value());
    CHECK(m.domain_keys().empty());

    m.clear();
    const json r = m.call_ticketed("delete_definition", w.delete_args("del.one"));
    const auto sc = ok_result(r);
    CHECK(sc["id"] == "del.one");
    CHECK(sc["deleted"] == true);
    CHECK_FALSE(w.get("del.one").has_value());
    const auto keys = m.domain_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "instruction.delete|attempted");
    CHECK(keys[1] == "instruction.delete|success");
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.deleted");

    // A retry of the landed delete is refused not_found BEFORE any ticket is minted (M3-4: the
    // early version check reads the absent row), with one generic row and no domain row.
    m.clear();
    const json missing =
        m.call("delete_definition", {{"id", "del.one"}, {"expected_updated_at", 1}});
    REQUIRE(missing.contains("error"));
    CHECK(missing["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(missing)["reason"] == "not_found");
    CHECK(m.domain_keys().empty());
    CHECK(m.has_row("mcp.delete_definition", "denied"));
    CHECK(m.emits.empty());

    // A ticket minted for one id does not delete another (the ticket binds the arguments).
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "del.two"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "del.three"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    std::string ticket;
    const json first_two = m.call("delete_definition", w.delete_args("del.two"));
    ticket = first_two["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));
    m.clear();
    json wrong_args = w.delete_args("del.three");
    wrong_args["approval_id"] = ticket;
    const json wrong = m.call("delete_definition", wrong_args);
    REQUIRE(wrong.contains("error"));
    // The C8 mismatch refusal specifically: permission denied, with the fixed anti-oracle text (it
    // never says why), not a store fault or any other error that would also leave the rows alone.
    CHECK(wrong["error"]["code"] == mcp::kPermissionDenied);
    CHECK(wrong["error"]["message"] == "approval_id does not match this tool and arguments");
    CHECK(m.domain_keys().empty()); // refused before the tool body: no attempted row, no event
    CHECK(m.emits.empty());
    CHECK(w.get("del.three").has_value());
    CHECK(w.get("del.two").has_value());
}

// UP-6. The referrer guard runs BEFORE a ticket is minted or consumed (a delete that is going to be
// refused burns no approval) and again in the handler. Turns red if the pre-ticket block in
// mcp_server.cpp or the guard in iauth::delete_definition is removed.
TEST_CASE("mcp delete_definition: a referenced definition is refused before any ticket is minted "
          "or consumed; and deletes once the referrer is gone",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    yuzu::test::ApprovalManagerPg appr_bundle;
    appr_bundle->create_tables();
    Mcp m;
    m.store = &w.store;
    m.approvals = appr_bundle.get();
    bool referenced = false;
    m.referrers = [&](const std::string& id)
        -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        if (referenced)
            return std::vector<DefinitionReferrer>{{"schedule", "sched-" + id}, {"workflow", "wf-1"}};
        return std::vector<DefinitionReferrer>{};
    };
    m.wire();
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "ref.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const auto pending = [&] {
        auto r = appr_bundle->query_checked(ApprovalQuery{.status = "pending"});
        REQUIRE(r.has_value());
        return r->approvals.size();
    };

    // Mint and approve a ticket while nothing references the definition.
    m.clear();
    const json del_args = w.delete_args("ref.one");
    const json first = m.call("delete_definition", del_args);
    REQUIRE(first.contains("error"));
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const auto ticket = first["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));

    // A schedule now names it: the recall is refused BEFORE the ticket is consumed.
    referenced = true;
    m.clear();
    json recall_args = del_args;
    recall_args["approval_id"] = ticket;
    const json refused = m.call("delete_definition", recall_args);
    REQUIRE(refused.contains("error"));
    CHECK(refused["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(refused)["reason"] == "referenced");
    CHECK(refused["error"]["message"].get<std::string>().find("schedule sched-ref.one") !=
          std::string::npos);
    CHECK(w.get("ref.one").has_value());
    CHECK(m.domain_keys().empty()); // no attempted row, no event
    CHECK(m.emits.empty());
    // The generic row records WHY (Gate 8 F8): the definition is referenced.
    const auto refused_row = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "mcp.delete_definition";
    });
    REQUIRE(refused_row != m.audits.end());
    CHECK(refused_row->detail.find("reason=referenced") != std::string::npos);
    // A first call (no ticket yet) is refused too, and mints nothing.
    const auto before = pending();
    const json no_mint = m.call("delete_definition", del_args);
    REQUIRE(no_mint.contains("error"));
    CHECK(error_data(no_mint)["reason"] == "referenced");
    CHECK(pending() == before);

    // Unlinked: the SAME approved ticket still works (it was never consumed).
    referenced = false;
    m.clear();
    const json done = m.call("delete_definition", recall_args);
    CHECK_FALSE(done.contains("error"));
    CHECK_FALSE(w.get("ref.one").has_value());
}

// Gate 8 F8 (sre F2) and QE #8: the pre-ticket referrer branch with the lookup unwired or failing.
// Turns red if the pre-mint audit reason goes back to the hard-coded `referenced`, or if the
// branch stops refusing (a ticket would then be minted for a delete the handler must refuse).
TEST_CASE("mcp delete_definition: an unwired or failing referrer lookup is refused before any "
          "ticket is minted; audited as lookup_unavailable; and deletes nothing",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    yuzu::test::ApprovalManagerPg appr_bundle;
    appr_bundle->create_tables();
    const auto pending = [&] {
        auto r = appr_bundle->query_checked(ApprovalQuery{.status = "pending"});
        REQUIRE(r.has_value());
        return r->approvals.size();
    };
    for (const bool wired : {false, true}) {
        INFO(std::string(wired ? "lookup failing" : "lookup unwired"));
        Mcp m;
        m.store = &w.store;
        m.approvals = appr_bundle.get();
        m.referrers_wired = wired;
        if (wired)
            m.referrers = [](const std::string&)
                -> std::expected<std::vector<DefinitionReferrer>, std::string> {
                return std::unexpected(std::string("schedule read failed"));
            };
        m.wire();
        const std::string id = wired ? "lookup.two" : "lookup.one";
        // Create the definition straight through the store: the point is the delete branch.
        InstructionDefinition def;
        def.id = id;
        def.name = "n";
        def.type = "question";
        def.plugin = "p";
        REQUIRE(w.store.create_definition(def).has_value());

        const auto before = pending();
        m.clear();
        const json r = m.call("delete_definition", w.delete_args(id));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(error_data(r)["reason"] == "store_unavailable");
        // H14: a lookup that FAILED is transient (hint kept); an UNWIRED one is a deployment fault
        // (no hint), the same as the REST twin. Turns red if Result::not_retryable stops being set
        // in delete_referrer_refusal or render() stops honouring it.
        if (wired)
            CHECK(error_data(r)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
        else
            CHECK(error_data(r)["retry_after_ms"].is_null());
        CHECK(w.get(id).has_value());
        CHECK(pending() == before); // no ticket minted
        CHECK(m.domain_keys().empty());
        const auto row = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& a) {
            return a.action == "mcp.delete_definition";
        });
        REQUIRE(row != m.audits.end());
        CHECK(row->result == "error");
        CHECK(row->detail.find("reason=lookup_unavailable") != std::string::npos);
        CHECK(row->detail.find("reason=referenced") == std::string::npos);
    }
}

TEST_CASE("mcp delete_definition handler: referenced is kReferenced with one denied/referenced row; "
          "a failing or unwired lookup is kStoreUnavailable and deletes nothing",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    std::vector<AuditRow> audits;
    bool audit_stored = true; // false: the sink records the row and answers "not stored"
    int emitted = 0;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.created_by = "tester";
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt,
                      const std::string& ti, const std::string& d) {
        audits.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return audit_stored;
    };
    ports.emit = [&](std::string_view, const json&, const json&) { ++emitted; };
    ports.referrers_fn = no_referrers();
    const auto created = iauth::create_definition(minimal_create(), ports);
    REQUIRE(created.kind == iauth::Kind::kOk);
    const std::string id = created.payload["id"].get<std::string>();
    audits.clear();
    emitted = 0;

    SECTION("referenced") {
        ports.referrers_fn = [](const std::string&)
            -> std::expected<std::vector<DefinitionReferrer>, std::string> {
            std::vector<DefinitionReferrer> r;
            for (int i = 0; i < 25; ++i)
                r.push_back({"policy fragment", "f" + std::to_string(i)});
            return r;
        };
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kReferenced);
        CHECK(out.message.find("referenced by 25 items") != std::string::npos);
        CHECK(out.message.find("and 5 more") != std::string::npos);
        CHECK(out.message.find("f19") != std::string::npos);
        CHECK(out.message.find("f20") == std::string::npos);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].action == "instruction.delete");
        CHECK(audits[0].result == "denied");
        CHECK(audits[0].detail == "referenced");
        CHECK(emitted == 0);
    }
    SECTION("failing") {
        ports.referrers_fn = [](const std::string&)
            -> std::expected<std::vector<DefinitionReferrer>, std::string> {
            return std::unexpected(std::string("workflow read failed"));
        };
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kStoreUnavailable);
        CHECK_FALSE(out.not_retryable);
        // One `error` row (no attempted row), the vocabulary the legacy DELETE writes (sre F3).
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].action == "instruction.delete");
        CHECK(audits[0].result == "error");
        CHECK(audits[0].detail == "referrer_check_unavailable");
        CHECK(out.audit_persisted);
    }
    // A refusal whose row was lost must say so (audit_persisted:false), for each of the three
    // referrer refusals. Turns red if the matching `refusal->audit_persisted = audit.outcome(...)`
    // in iauth::delete_definition goes back to `(void)audit.outcome(...)`.
    SECTION("referenced, audit row lost") {
        audit_stored = false;
        ports.referrers_fn = [](const std::string&)
            -> std::expected<std::vector<DefinitionReferrer>, std::string> {
            return std::vector<DefinitionReferrer>{{"schedule", "s1"}};
        };
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kReferenced);
        REQUIRE(audits.size() == 1);
        CHECK_FALSE(out.audit_persisted);
    }
    SECTION("failing, audit row lost") {
        audit_stored = false;
        ports.referrers_fn = [](const std::string&)
            -> std::expected<std::vector<DefinitionReferrer>, std::string> {
            return std::unexpected(std::string("workflow read failed"));
        };
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kStoreUnavailable);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail == "referrer_check_unavailable");
        CHECK_FALSE(out.audit_persisted);
    }
    SECTION("unwired, audit row lost") {
        audit_stored = false;
        ports.referrers_fn = nullptr;
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kStoreUnavailable);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].detail == "referrer_check_unwired");
        CHECK_FALSE(out.audit_persisted);
    }
    SECTION("unwired") {
        ports.referrers_fn = nullptr;
        const auto out = iauth::delete_definition(json{{"id", id}}, ports);
        CHECK(out.kind == iauth::Kind::kStoreUnavailable);
        CHECK(out.not_retryable);
        REQUIRE(audits.size() == 1);
        CHECK(audits[0].result == "error");
        CHECK(audits[0].detail == "referrer_check_unwired");
        audits.clear();
        // A definition that is already gone is still not_found, not a lookup fault.
        CHECK(iauth::delete_definition(json{{"id", "no.such.id"}}, ports).kind ==
              iauth::Kind::kNotFound);
    }
    CHECK(w.get(id).has_value());
}

// M2-3: the packs that contain the definition are noted on the success row (bounded at five plus
// `+N`); a failing or throwing pack lookup changes neither the result nor the row. Turns red if
// iauth::delete_definition stops appending pack_advisory_note, or lets the lookup affect the delete.
TEST_CASE("mcp delete_definition handler: the success row notes the containing packs (bounded); a "
          "failing or throwing pack lookup leaves the delete untouched",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    std::vector<AuditRow> audits;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.created_by = "tester";
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt,
                      const std::string& ti, const std::string& d) {
        audits.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return true;
    };
    ports.emit = [&](std::string_view, const json&, const json&) {};
    ports.referrers_fn = no_referrers();
    const auto created = iauth::create_definition(minimal_create(), ports);
    REQUIRE(created.kind == iauth::Kind::kOk);
    const std::string id = created.payload["id"].get<std::string>();
    audits.clear();

    bool expect_note = false;
    bool existed_at_lookup = false; // N1-5: the pack read happens BEFORE the delete
    SECTION("seven packs") {
        ports.pack_advisory_fn = [&](const std::string& asked)
            -> std::expected<std::vector<std::string>, std::string> {
            CHECK(asked == id);
            const auto row = w.store.get_definition(asked);
            existed_at_lookup = row.has_value() && row->has_value();
            return std::vector<std::string>{"p1", "p2", "p3", "p4", "p5", "p6", "p7"};
        };
        expect_note = true;
    }
    SECTION("failing") {
        ports.pack_advisory_fn = [](const std::string&)
            -> std::expected<std::vector<std::string>, std::string> {
            return std::unexpected(std::string("pack read failed"));
        };
    }
    SECTION("throwing") {
        ports.pack_advisory_fn = [](const std::string&)
            -> std::expected<std::vector<std::string>, std::string> {
            throw std::runtime_error("boom");
        };
    }
    const auto out = iauth::delete_definition(json{{"id", id}}, ports);
    CHECK(out.kind == iauth::Kind::kOk);
    REQUIRE(audits.size() == 2); // attempted, then success
    CHECK(audits[1].result == "success");
    if (expect_note) {
        CHECK(audits[1].detail.ends_with(" enabled=true packs=p1,p2,p3,p4,p5,+2"));
        CHECK(existed_at_lookup);
    } else {
        CHECK(audits[1].detail.find("packs=") == std::string::npos);
    }
    CHECK_FALSE(w.get(id).has_value());
}

// UP-5 (MCP twin of the PUT rule). Turns red if iauth::update_definition stops calling
// clear_stale_yaml_source.
TEST_CASE("mcp update_definition: an edit to a column the YAML merge takes clears a stored "
          "yaml_source and audits it; an enabled toggle does not",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    std::vector<AuditRow> audits;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt,
                      const std::string& ti, const std::string& d) {
        audits.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return true;
    };
    const auto saved = iauth::save_definition_yaml(json{{"yaml_source", kYaml}}, ports);
    REQUIRE(saved.kind == iauth::Kind::kOk);
    const std::string id = saved.payload["id"].get<std::string>();
    REQUIRE_FALSE(w.row(id).yaml_source.empty());

    // M1-5: name, description, version and type are columns the YAML merge also takes, so an
    // edit to any of them clears the YAML too (it would be reverted by a round trip otherwise).
    // Turns red if clear_stale_yaml_source drops one. `enabled` is the one column that does not.
    const auto restore_yaml = [&] {
        const auto back = iauth::save_definition_yaml(
            json{{"yaml_source", kYaml}, {"id", id}, {"updated_at", w.row(id).updated_at}}, ports);
        REQUIRE(back.kind == iauth::Kind::kOk);
        REQUIRE(w.row(id).yaml_source == kYaml);
        audits.clear();
    };
    const std::vector<std::pair<std::string, json>> edits = {
        {"name", "Renamed"}, {"description", "new words"}, {"version", "9.9"}, {"type", "action"}};
    for (const auto& [field, value] : edits) {
        INFO(field);
        restore_yaml();
        const auto r = iauth::update_definition(json{{"id", id}, {field, value}}, ports);
        REQUIRE(r.kind == iauth::Kind::kOk);
        CHECK(w.row(id).yaml_source.empty());
        REQUIRE(audits.size() == 2);
        for (const auto& row : audits) {
            CHECK(row.detail.find("yaml_source cleared") != std::string::npos);
            CHECK(row.detail.find(field + ": ") != std::string::npos);
        }
    }
    restore_yaml();
    const auto toggled = iauth::update_definition(json{{"id", id}, {"enabled", false}}, ports);
    REQUIRE(toggled.kind == iauth::Kind::kOk);
    CHECK(w.row(id).yaml_source == kYaml);
    REQUIRE_FALSE(audits.empty());
    CHECK(audits.back().detail.find("yaml_source cleared") == std::string::npos);

    audits.clear();
    const auto appr = iauth::update_definition(json{{"id", id}, {"approval_mode", "always"}}, ports);
    REQUIRE(appr.kind == iauth::Kind::kOk);
    CHECK(w.row(id).yaml_source.empty());
    CHECK(w.row(id).approval_mode == "always");
    REQUIRE(audits.size() == 2);
    CHECK(audits[0].detail.find("yaml_source cleared") != std::string::npos);
    CHECK(audits[1].detail.find("yaml_source cleared") != std::string::npos);

    // A YAML save is the YAML authority: it writes the YAML it was given and never clears.
    const auto back = iauth::save_definition_yaml(
        json{{"yaml_source", kYaml}, {"id", id}, {"updated_at", w.row(id).updated_at}}, ports);
    REQUIRE(back.kind == iauth::Kind::kOk);
    CHECK(w.row(id).yaml_source == kYaml);
}

TEST_CASE("mcp import_definition: unsigned refused by default; accepted when the operator opted out; "
          "the refusal is audited denied",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.require_signed_definitions()); // the default
    Supervised s{&w.store};
    Mcp& m = s.m;

    const json document{{"id", "imp.unsigned"}, {"name", "Unsigned"}, {"version", "1.0"},
                        {"type", "question"},   {"plugin", "os_info"}, {"action", "os_name"},
                        {"yaml_source", kYaml}};
    m.clear();
    const json refused = m.call_ticketed("import_definition", {{"document", document}});
    REQUIRE(refused.contains("error"));
    CHECK(refused["error"]["code"] == mcp::kInvalidParams);
    CHECK_FALSE(w.get("imp.unsigned").has_value());
    const auto keys = m.domain_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "instruction.import|attempted");
    CHECK(keys[1] == "instruction.import|denied");
    REQUIRE(m.audits.size() >= 2);
    CHECK_FALSE(m.audits[m.audits.size() - 2].detail.empty()); // the store's stable error text

    w.store.set_require_signed_definitions(false); // --allow-unsigned-definitions
    m.clear();
    const json ok_r = m.call_ticketed("import_definition", {{"document", document}});
    CHECK(ok_result(ok_r)["id"] == "imp.unsigned");
    CHECK(w.get("imp.unsigned").has_value());
    CHECK(m.has_row("instruction.import", "success"));

    m.clear();
    const json dup = m.call_ticketed("import_definition", {{"document", document}});
    REQUIRE(dup.contains("error"));
    CHECK(error_data(dup)["reason"] == "conflict");

    // Shape refusals: a non-object document costs no domain row. (The schema refuses the type
    // before a ticket for the ticketed path.)
    m.clear();
    const json shape = m.call("import_definition", {{"document", "not an object"}});
    REQUIRE(shape.contains("error"));
    CHECK(shape["error"]["code"] == mcp::kInvalidParams);
    CHECK(m.domain_keys().empty());
}

TEST_CASE("mcp import_definition: a wrong-typed document field is a typed refusal with an outcome "
          "row; never an uncaught exception",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;

    const json base{{"id", "imp.badtype"},    {"name", "n"},
                    {"type", "question"},     {"plugin", "os_info"},
                    {"yaml_source", kYaml}};
    const std::vector<std::pair<std::string, json>> cases{
        {"id", 7},
        {"name", json::object()},
        {"enabled", "yes"},
        {"gather_ttl_seconds", "300"},
        {"response_ttl_days", 1.5},
        {"parameter_schema", json::object()},
        {"approval_mode", nullptr}};
    for (const auto& [field, value] : cases) {
        INFO(field);
        json doc = base;
        doc[field] = value;
        m.clear();
        const json r = m.call_ticketed("import_definition", {{"document", doc}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        const auto keys = m.domain_keys();
        REQUIRE(keys.size() == 2);
        CHECK(keys[0] == "instruction.import|attempted");
        CHECK(keys[1] == "instruction.import|denied");
        CHECK_FALSE(w.get("imp.badtype").has_value());
    }
}

namespace {
struct Ed25519Pair {
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> pkey{nullptr, &EVP_PKEY_free};
    std::string public_key_hex;
};

std::string to_hex(const unsigned char* p, std::size_t n) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(hex[p[i] >> 4]);
        out.push_back(hex[p[i] & 0x0F]);
    }
    return out;
}

Ed25519Pair generate_ed25519() {
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> kctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free);
    REQUIRE(kctx);
    REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
    Ed25519Pair p{std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(raw, &EVP_PKEY_free), {}};
    unsigned char pub[32];
    std::size_t pub_len = sizeof(pub);
    REQUIRE(EVP_PKEY_get_raw_public_key(p.pkey.get(), pub, &pub_len) == 1);
    p.public_key_hex = to_hex(pub, pub_len);
    return p;
}

std::string sign_hex(EVP_PKEY* pkey, std::string_view content) {
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    REQUIRE(ctx);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey) == 1);
    std::size_t sig_len = 64;
    unsigned char sig[64];
    REQUIRE(EVP_DigestSign(ctx.get(), sig, &sig_len,
                           reinterpret_cast<const unsigned char*>(content.data()),
                           content.size()) == 1);
    return to_hex(sig, sig_len);
}
} // namespace

TEST_CASE("mcp import_definition: a validly signed import is accepted; a tampered document and an "
          "incomplete signature are refused (the signature gate is the store's; never bypassed)",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.require_signed_definitions());
    Supervised s{&w.store};
    Mcp& m = s.m;

    const std::string yaml = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                             "metadata:\n  id: sig.signed\n  displayName: Signed\n"
                             "spec:\n  type: question\n  execution:\n    plugin: system_info\n"
                             "    action: os_name\n";
    auto kp = generate_ed25519();
    const auto sig = sign_hex(kp.pkey.get(), yaml);
    const auto doc = [&](const std::string& id, const std::string& y, const std::string& s2,
                         const std::string& pub) {
        json j{{"id", id},   {"name", id},        {"version", "1.0"}, {"type", "question"},
               {"plugin", "system_info"}, {"action", "os_name"}, {"yaml_source", y}};
        if (!s2.empty())
            j["signature"] = s2;
        if (!pub.empty())
            j["publicKey"] = pub;
        return json{{"document", j}};
    };

    const json ok_r = m.call_ticketed("import_definition", doc("sig.signed", yaml, sig, kp.public_key_hex));
    CHECK(ok_result(ok_r)["id"] == "sig.signed");
    CHECK(w.get("sig.signed").has_value());

    m.clear();
    const json tampered = m.call_ticketed(
        "import_definition", doc("sig.tampered", yaml + "  # tampered\n", sig, kp.public_key_hex));
    REQUIRE(tampered.contains("error"));
    CHECK_FALSE(w.get("sig.tampered").has_value());
    CHECK(last_domain_key(m) == "instruction.import|denied");

    const json incomplete = m.call_ticketed("import_definition", doc("sig.incomplete", yaml, sig, ""));
    REQUIRE(incomplete.contains("error"));
    CHECK_FALSE(w.get("sig.incomplete").has_value());
}

// J1 against the REAL store, signed branch: the subject's plugin, action and approval_mode equal the
// stored row's, and its id and name are the DOCUMENT's (the store never reads them from the
// yaml_source: a document with no id gets a generated one). Turns red if the subject fills
// definition_id or name from a signed yaml_source again, or stops lowercasing the action.
TEST_CASE("mcp ticket_subject: a signed import's subject matches the stored row; the yaml_source's "
          "metadata.id and displayName are never shown",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    const std::string yaml = std::string(kYaml) + "  approval: always\n"; // metadata.id test.mcp.yaml
    auto kp = generate_ed25519();
    const json doc = {{"name", "SignedName"},
                      {"version", "1.0"},
                      {"type", "question"},
                      {"plugin", "os_info"},
                      {"action", "OS_NAME"}, // the store lowercases it
                      {"yaml_source", yaml},
                      {"signature", sign_hex(kp.pkey.get(), yaml)},
                      {"publicKey", kp.public_key_hex}};
    const json shown = json::parse(*iauth::ticket_subject("import_definition", {{"document", doc}}));
    const auto imported = w.store.import_definition_json(doc.dump());
    REQUIRE(imported.has_value());
    const auto row = w.row(*imported);
    CHECK(*imported != "test.mcp.yaml"); // the generated id, not the YAML's metadata.id
    CHECK_FALSE(w.get("test.mcp.yaml").has_value());
    CHECK(row.approval_mode == "always");
    CHECK(shown["approval_mode"] == row.approval_mode);
    CHECK(shown["plugin"] == row.plugin);
    CHECK(shown["action"] == row.action);
    CHECK(shown["action"] == "os_name");
    CHECK(shown["name"] == row.name);
    CHECK_FALSE(shown.contains("definition_id"));

    // Unlike the signed YAML's id/name: a document's own id and name are what is stored and shown.
    json with_id = doc;
    with_id["id"] = "j1.doc.id";
    const json shown2 = json::parse(*iauth::ticket_subject("import_definition", {{"document", with_id}}));
    REQUIRE(w.store.import_definition_json(with_id.dump()).has_value());
    CHECK(shown2["definition_id"] == w.row("j1.doc.id").id);
}

TEST_CASE("mcp save_definition_yaml: create then update; columns the YAML cannot express are kept; "
          "validation; divergent metadata.id; unknown id and stale updated_at are refused",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    // CREATE: the YAML's metadata.id is honoured.
    const json created = m.call_ticketed("save_definition_yaml", {{"yaml_source", kYaml}});
    const auto csc = ok_result(created);
    CHECK(csc["id"] == "test.mcp.yaml");
    CHECK(csc["created"] == true);
    auto stored = w.get("test.mcp.yaml");
    REQUIRE(stored.has_value());
    CHECK(stored->plugin == "os_info");
    CHECK(stored->version == "1.0.0");
    CHECK(stored->approval_mode == "auto");
    CHECK(stored->created_by == "tester");
    CHECK(m.has_row("instruction.create", "attempted"));
    CHECK(m.has_row("instruction.create", "success"));

    // Columns the YAML cannot express are carried forward across an UPDATE.
    {
        InstructionDefinition d = *stored;
        d.enabled = false;
        d.gather_ttl_seconds = 777;
        d.parameter_schema.clear();
        REQUIRE(w.store.update_definition(d, d.updated_at).has_value());
    }
    const std::string edited = std::string(kYaml) + "  approval: always\n";
    m.clear();
    const json updated = m.call_ticketed(
        "save_definition_yaml", {{"yaml_source", edited}, {"id", "test.mcp.yaml"},
                                 {"updated_at", w.row("test.mcp.yaml").updated_at}});
    const auto usc = ok_result(updated);
    CHECK(usc["id"] == "test.mcp.yaml");
    CHECK(usc["created"] == false);
    stored = w.get("test.mcp.yaml");
    REQUIRE(stored.has_value());
    CHECK(stored->approval_mode == "always");
    CHECK_FALSE(stored->enabled);
    CHECK(stored->gather_ttl_seconds == 777);
    CHECK(m.has_row("instruction.update", "attempted"));
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.updated");
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& row) {
        return row.action == "instruction.update" && row.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail.find("approval_mode: auto -> always") != std::string::npos);

    // Validation: a list in error.data.errors, nothing saved, no domain row.
    m.clear();
    const json invalid = m.call_ticketed("save_definition_yaml", {{"yaml_source", "kind: nope"}});
    REQUIRE(invalid.contains("error"));
    CHECK(invalid["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(invalid)["reason"] == "validation_failed");
    CHECK_FALSE(error_data(invalid)["errors"].empty());
    CHECK(m.domain_keys().empty());

    // A YAML naming a different metadata.id than the update target forks nothing: refused.
    // (The target must exist with a current token to get past the early version check.)
    {
        InstructionDefinition other;
        other.id = "some.other.id";
        other.name = "other";
        other.type = "question";
        other.plugin = "p";
        REQUIRE(w.store.create_definition(other).has_value());
    }
    const json fork = m.call_ticketed("save_definition_yaml",
                                      {{"yaml_source", kYaml}, {"id", "some.other.id"},
                                       {"updated_at", w.row("some.other.id").updated_at}});
    REQUIRE(fork.contains("error"));
    CHECK(fork["error"]["message"].get<std::string>().find("metadata.id") != std::string::npos);

    // Unknown id on update: not_found, no row.
    const std::string anon_yaml = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                                  "metadata:\n  displayName: Anon\nspec:\n  plugin: os_info\n"
                                  "  action: os_name\n  type: question\n";
    m.clear();
    // Since UP-12 both refusals come from the early version check, before any ticket exists.
    const json missing = m.call("save_definition_yaml", {{"yaml_source", anon_yaml},
                                                         {"id", "absent.id"}, {"updated_at", 1}});
    REQUIRE(missing.contains("error"));
    CHECK(missing["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(missing)["reason"] == "not_found");
    CHECK(m.domain_keys().empty());
    CHECK(*m.approvals->pending_count_for_checked("tester") == 0);

    // Stale updated_at: conflict, nothing written, no ticket.
    m.clear();
    const json stale = m.call(
        "save_definition_yaml", {{"yaml_source", kYaml}, {"id", "test.mcp.yaml"},
                                 {"updated_at", w.row("test.mcp.yaml").updated_at + 99999}});
    REQUIRE(stale.contains("error"));
    CHECK(stale["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(stale)["reason"] == "conflict");
    CHECK(w.row("test.mcp.yaml").approval_mode == "always");
    CHECK(*m.approvals->pending_count_for_checked("tester") == 0);

    // A create without metadata.id generates one.
    m.clear();
    const json gen = m.call_ticketed("save_definition_yaml", {{"yaml_source", anon_yaml}});
    const auto gsc = ok_result(gen);
    CHECK_FALSE(gsc["id"].get<std::string>().empty());
    CHECK(gsc["created"] == true);
}

TEST_CASE("mcp instruction sets: create (unticketed); list; delete (ticketed) unsets members and "
          "keeps them",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    // Empty list first.
    {
        const auto sc = ok_result(m.call("list_instruction_sets"));
        CHECK(sc["sets"].empty());
        CHECK(sc["count"] == 0);
    }

    // Unticketed: runs on the first call; attempted then success; created_by stamped.
    m.clear();
    const json created = m.call("create_instruction_set", {{"name", "Ops"}, {"description", "d"}});
    const auto csc = ok_result(created);
    const std::string set_id = csc["id"].get<std::string>();
    REQUIRE_FALSE(set_id.empty());
    const auto keys = m.domain_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "instruction_set.create|attempted");
    CHECK(keys[1] == "instruction_set.create|success");
    REQUIRE(w.sets().size() == 1);
    CHECK(w.sets()[0].created_by == "tester");
    CHECK(m.emits.empty()); // the legacy route emits no set event either

    // A member definition, then the listing shape.
    REQUIRE_FALSE(m.call_ticketed("create_definition",
                                  {{"id", "member.one"}, {"name", "n"}, {"type", "question"},
                                   {"plugin", "p"}, {"instruction_set_id", set_id}})
                      .contains("error"));
    CHECK(w.row("member.one").instruction_set_id == set_id);
    const json listed = m.call("list_instruction_sets");
    const auto lsc = ok_result(listed);
    REQUIRE(lsc["sets"].size() == 1);
    CHECK(lsc["count"] == 1);
    for (const char* k : {"id", "name", "description", "created_by", "created_at"})
        CHECK(lsc["sets"][0].contains(k));
    CHECK(lsc["sets"][0]["name"] == "Ops");

    // Delete: ticket first, then it unsets the member and keeps it.
    m.clear();
    const json first = m.call("delete_instruction_set", {{"id", set_id}});
    REQUIRE(first.contains("error"));
    CHECK(first["error"]["code"] == mcp::kApprovalRequired);
    CHECK(w.sets().size() == 1);
    const json del = m.call_ticketed("delete_instruction_set", {{"id", set_id}});
    const auto dsc = ok_result(del);
    CHECK(dsc["deleted"] == true);
    CHECK(dsc["id"] == set_id);
    CHECK(w.sets().empty());
    const auto member = w.get("member.one");
    REQUIRE(member.has_value());
    CHECK(member->instruction_set_id.empty());
    CHECK(m.has_row("instruction_set.delete", "attempted"));
    CHECK(m.has_row("instruction_set.delete", "success"));

    // Unknown id.
    m.clear();
    const json missing = m.call_ticketed("delete_instruction_set", {{"id", "no-such-set"}});
    REQUIRE(missing.contains("error"));
    CHECK(error_data(missing)["reason"] == "not_found");
    CHECK(last_domain_key(m) == "instruction_set.delete|denied");
}

TEST_CASE("mcp create_instruction_set: shape and bound refusals cost no domain row and create nothing",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    // create_instruction_set is not ticketed, so the handler (not C8) validates every argument.
    const std::vector<json> bad = {
        json::object(),
        {{"name", ""}},
        {{"name", 5}},
        {{"name", "ok"}, {"description", 5}},
        {{"name", "ok"}, {"id", "forced-id"}},
        {{"name", std::string(129, 'n')}},
        {{"name", "ok"}, {"description", std::string(513, 'd')}},
    };
    for (const auto& args : bad) {
        INFO(args.dump().substr(0, 80));
        m.clear();
        const json r = m.call("create_instruction_set", args);
        REQUIRE(r.contains("error"));
        // The store's own refusals (empty name) are audited denied after the attempt; shape and
        // bound refusals cost none. Either way: -32602 and nothing created.
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(error_data(r)["reason"] == "invalid");
        CHECK(m.emits.empty());
    }
    CHECK(w.sets().empty());
    // approval_id is accepted and ignored (the schema declares it for uniformity).
    const json with_ticket = m.call("create_instruction_set",
                                    {{"name", "fine"}, {"approval_id", "ignored"}});
    CHECK_FALSE(with_ticket.contains("error"));
}

TEST_CASE("mcp instruction authoring: an id argument with a control byte is refused before any row",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    // The schema pattern would refuse it pre-mint for the ticketed tools; the shared id check is
    // the defence in depth and the only check on the ungated path. Call the helper directly.
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.audit = [&](std::string_view, std::string_view, std::string_view, const std::string&,
                      const std::string&) { return true; };
    for (const char* bad : {"a\nb", "a\x01z", "\xff\xfe"}) {
        INFO(json(std::string(bad)).dump(-1, ' ', false, json::error_handler_t::replace));
        for (auto fn : {&iauth::delete_definition, &iauth::update_definition,
                        &iauth::delete_instruction_set}) {
            const auto out = fn(json{{"id", bad}}, ports);
            CHECK(out.kind == iauth::Kind::kInvalid);
        }
    }
    // And an over-long one.
    const auto out = iauth::delete_definition(json{{"id", std::string(129, 'a')}}, ports);
    CHECK(out.kind == iauth::Kind::kInvalid);
    // An unwired audit sink refuses every write: never "audit off".
    ports.audit = nullptr;
    const auto refused = iauth::create_instruction_set(json{{"name", "x"}}, ports);
    CHECK(refused.kind == iauth::Kind::kAuditRefused);
    CHECK(refused.not_retryable);
    CHECK(w.sets().empty());
    // A wired sink that answers false is retryable: the hint stays.
    ports.audit = [](std::string_view, std::string_view, std::string_view, const std::string&,
                     const std::string&) { return false; };
    const auto failing = iauth::create_instruction_set(json{{"name", "x"}}, ports);
    CHECK(failing.kind == iauth::Kind::kAuditRefused);
    CHECK_FALSE(failing.not_retryable);
    const auto rendered = iauth::render(failing, "cid", false);
    CHECK(json::parse(rendered.data_json)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    const auto unwired = iauth::render(refused, "cid", false);
    CHECK(json::parse(unwired.data_json)["retry_after_ms"].is_null());
}

TEST_CASE("mcp save_definition_yaml: a source validate_definition_yaml flags (plugin/action charset "
          "or length) is refused with the same error list; before any row",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    for (const std::string& y :
         {yaml_with_dispatch("\"my plugin\"", "os_name"),
          yaml_with_dispatch(std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'p'), "os_name"),
          yaml_with_dispatch("os_info", std::string(kMaxDefinitionDispatchIdentifierLen + 1, 'a'))}) {
        m.clear();
        const auto validated = ok_result(m.call("validate_definition_yaml", {{"yaml_source", y}}));
        REQUIRE(validated["valid"] == false);
        m.clear();
        const json r = m.call_ticketed("save_definition_yaml", {{"yaml_source", y}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(error_data(r)["errors"] == validated["errors"]);
        CHECK(m.domain_keys().empty()); // refused before the attempt row
    }
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

TEST_CASE("mcp definition handlers re-enforce the shared bounds without the schema layer: refused "
          "before any store call or audit row",
          "[pg][mcp][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    int audit_rows = 0;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    ports.audit = [&](std::string_view, std::string_view, std::string_view, const std::string&,
                      const std::string&) {
        ++audit_rows;
        return true;
    };
    const auto created = iauth::create_definition(minimal_create(), ports);
    REQUIRE(created.kind == iauth::Kind::kOk);
    const std::string id = created.payload["id"].get<std::string>();
    const auto before = w.get(id);
    REQUIRE(before.has_value());
    audit_rows = 0;

    const std::vector<json> bad_fields = {
        json{{"name", std::string(1024 * 1024, 'n')}}, json{{"name", ""}}, json{{"type", "bogus"}},
        json{{"description", std::string(kMaxDefinitionDescriptionLen + 1, 'd')}},
        json{{"version", std::string(kMaxDefinitionVersionLen + 1, 'v')}},
        json{{"instruction_set_id", std::string(kMaxDefinitionInstructionSetIdLen + 1, 's')}}};
    for (const auto& f : bad_fields) {
        json u = f;
        u["id"] = id;
        CHECK(iauth::update_definition(u, ports).kind == iauth::Kind::kInvalid);
        json c = minimal_create();
        c.update(f);
        CHECK(iauth::create_definition(c, ports).kind == iauth::Kind::kInvalid);
    }
    CHECK(audit_rows == 0);
    const auto after = w.get(id);
    REQUIRE(after.has_value());
    CHECK(after->updated_at == before->updated_at);
    CHECK(after->name == before->name);
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->size() == 1);
}

// ── Version-token integrity, import TTL range, probe fault, delete pre-image (batch C gov) ──

TEST_CASE("mcp import_definition: a TTL outside the create/update range is a typed refusal naming "
          "the field; audited attempted then denied; and stores nothing",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if the range check in InstructionStore::import_definition_json is removed.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;

    const json base{{"id", "imp.ttl"},      {"name", "n"},
                    {"type", "question"},   {"plugin", "os_info"},
                    {"yaml_source", kYaml}};
    const std::vector<std::pair<std::string, json>> cases{
        {"gather_ttl_seconds", 3000000000LL},
        {"gather_ttl_seconds", 0},
        {"gather_ttl_seconds", -5},
        {"gather_ttl_seconds", 86401},
        {"gather_ttl_seconds", 300.0},
        {"gather_ttl_seconds", nullptr},
        {"response_ttl_days", 0},
        {"response_ttl_days", 3651},
        {"response_ttl_days", 90.0},
        {"response_ttl_days", nullptr}};
    for (const auto& [field, value] : cases) {
        INFO(field << " = " << value.dump());
        json doc = base;
        doc[field] = value;
        m.clear();
        const json r = m.call_ticketed("import_definition", {{"document", doc}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().find("'" + field + "'") !=
              std::string::npos);
        const auto keys = m.domain_keys();
        REQUIRE(keys.size() == 2);
        CHECK(keys[0] == "instruction.import|attempted");
        CHECK(keys[1] == "instruction.import|denied");
        CHECK_FALSE(w.get("imp.ttl").has_value());
    }
}

// Handler level: since UP-12 the server refuses a stale token before the ticket, so the CAS
// zero-row probe is only reachable when the row moves between the early check and the handler.
// Driving the handler directly is that window. Turns red if update_definition's probe failure is
// read as not_found (a false statement about a row that exists), or render() sends a retry hint.
TEST_CASE("mcp update_definition: a failed existence probe after a zero-row compare-and-set is a "
          "retryable store fault with outcome-unknown wording; never not_found",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    std::vector<AuditRow> audits;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.created_by = "tester";
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt,
                      const std::string& ti, const std::string& d) {
        audits.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return true;
    };
    ports.emit = [](std::string_view, const json&, const json&) {};
    ports.referrers_fn = no_referrers();
    REQUIRE(iauth::create_definition({{"id", "probe.one"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     ports)
                .kind == iauth::Kind::kOk);
    const std::int64_t token = w.row("probe.one").updated_at;
    yuzu::test::ExistsProbeFault fault(w.pool);
    fault.arm();
    audits.clear();

    const auto out = iauth::update_definition(
        {{"id", "probe.one"}, {"name", "x"}, {"expected_updated_at", token + 1000}}, ports);
    CHECK(out.kind == iauth::Kind::kStoreUnavailable);
    CHECK(out.outcome_unknown);
    CHECK(out.message.find("outcome unknown: read the definition before retrying") !=
          std::string::npos);
    const auto rendered = iauth::render(out, "cid-1", false);
    CHECK(rendered.code == mcp::kInternalError);
    const json data = json::parse(rendered.data_json);
    CHECK(data["reason"] == "store_unavailable");
    // Outcome unknown: no retry hint. Turns red if render() sends one for outcome_unknown.
    CHECK(data["retry_after_ms"].is_null());
    CHECK(data["remediation"].get<std::string>().find("may or may not have been applied") !=
          std::string::npos);
    REQUIRE(audits.size() == 2);
    CHECK(audits[0].result == "attempted");
    CHECK(audits[1].action == "instruction.update");
    CHECK(audits[1].result == "error");
    CHECK(audits[1].detail == "db_error");
    fault.repair();
    CHECK(w.row("probe.one").name == "n");
}

TEST_CASE("mcp delete_definition: the audit rows carry the deleted definition's dispatch tuple",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if the tool stops reading the pre-image or the rows stop carrying it.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition",
                                  {{"id", "pre.image"}, {"name", "Pre image"}, {"type", "question"},
                                   {"plugin", "os_info"}, {"action", "os_name"},
                                   {"approval_mode", "role-gated"}, {"enabled", false}})
                      .contains("error"));
    m.clear();
    std::string ticket;
    REQUIRE_FALSE(
        m.call_ticketed("delete_definition", w.delete_args("pre.image"), &ticket).contains("error"));
    const std::string tuple = "name=Pre_image plugin=os_info action=os_name "
                              "approval_mode=role-gated concurrency_mode=per-device enabled=false";
    std::vector<AuditRow> rows;
    for (const auto& r : m.audits)
        if (r.action == "instruction.delete")
            rows.push_back(r);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].detail == tuple);
    CHECK(rows[1].result == "success");
    // C-6: the row that records the change ends with the approval that authorised it; the
    // attempted row keeps the bare tuple.
    CHECK(rows[1].detail == tuple + " approval_id=" + ticket);
}

// UP-3 / C-7: RBAC runs BEFORE a ticket is minted. Turns red if the pre-mint perm_fn in the C8
// block is removed: the call then mints a ticket (-32006) and the pending count is 1.
TEST_CASE("mcp ticketed definition tools: a principal without the grant gets the gate's refusal "
          "and no approval is created",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    m.perm_allow = false;

    const json import_doc = {{"id", "rbac.imp"}, {"name", "I"}, {"version", "1.0"},
                             {"type", "question"}, {"plugin", "os_info"}, {"action", "os_name"},
                             {"yaml_source", kYaml}};
    struct Case {
        const char* tool;
        json args;
        std::pair<const char*, const char*> pair;
    };
    const Case cases[] = {
        {"create_definition", {{"name", "n"}, {"type", "question"}, {"plugin", "p"}},
         {"InstructionDefinition", "Write"}},
        {"update_definition", {{"id", "x"}, {"expected_updated_at", 1}},
         {"InstructionDefinition", "Write"}},
        {"delete_definition", {{"id", "x"}, {"expected_updated_at", 1}}, {"InstructionDefinition", "Delete"}},
        {"import_definition", {{"document", import_doc}}, {"InstructionDefinition", "Write"}},
        {"save_definition_yaml", {{"yaml_source", kYaml}}, {"InstructionDefinition", "Write"}},
        {"delete_instruction_set", {{"id", "x"}}, {"InstructionSet", "Delete"}},
    };
    for (const auto& c : cases) {
        INFO(c.tool);
        m.clear();
        auto res = m.post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3},
                               {"params", {{"name", c.tool}, {"arguments", c.args}}}}
                              .dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == R"({"error":"forbidden"})");
        REQUIRE_FALSE(m.perms.empty());
        CHECK(m.perms[0] == std::make_pair(std::string(c.pair.first), std::string(c.pair.second)));
        CHECK(m.domain_keys().empty());
        const auto pending = m.approvals->pending_count_for_checked("tester");
        REQUIRE(pending.has_value());
        CHECK(*pending == 0); // no approval row was created
    }

    // RBAC is asked BEFORE the version token: a no-grant caller who also forgot it learns nothing
    // about the argument shape.
    m.clear();
    auto res = m.post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3},
                           {"params", {{"name", "update_definition"},
                                       {"arguments", {{"id", "x"}, {"name", "n"}}}}}}
                          .dump());
    REQUIRE(res);
    CHECK(res->status == 403);

    // And with the grant the same calls do mint (the gate above is not simply refusing them all).
    m.perm_allow = true;
    m.clear();
    REQUIRE(w.store.create_definition([] {
                InstructionDefinition d;
                d.id = "x";
                d.name = "n";
                d.type = "question";
                d.plugin = "p";
                return d;
            }())
                .has_value());
    const json minted = m.call("delete_definition", w.delete_args("x"));
    REQUIRE(minted.contains("error"));
    CHECK(minted["error"]["code"] == mcp::kApprovalRequired);
    CHECK(*m.approvals->pending_count_for_checked("tester") == 1);
}

// UP-2 / C-2 / M3-3: at the supervised tier the human approves ONE VERSION. Turns red if the
// missing_version_token check in the C8 block is removed (the update then mints a ticket), or if
// the `delete_definition` arm of missing_version_token is removed (the token-less delete mints).
TEST_CASE("mcp update_definition / delete_definition / save_definition_yaml: the supervised tier "
          "requires the version token BEFORE a ticket is minted; create needs none",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "ver.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const std::int64_t token = w.row("ver.one").updated_at;
    const auto pending = [&] { return *m.approvals->pending_count_for_checked("tester"); };
    REQUIRE(pending() == 0);

    // update_definition without expected_updated_at: -32602 naming the version token, no ticket,
    // no domain row, nothing consumed.
    m.clear();
    const json no_token = m.call("update_definition", {{"id", "ver.one"}, {"name", "Renamed"}});
    REQUIRE(no_token.contains("error"));
    CHECK(no_token["error"]["code"] == mcp::kInvalidParams);
    CHECK(no_token["error"]["message"].get<std::string>().find("expected_updated_at") !=
          std::string::npos);
    CHECK(no_token["error"]["message"].get<std::string>().find("supervised") != std::string::npos);
    CHECK(error_data(no_token)["reason"] == "version_token_required");
    CHECK(error_data(no_token)["remediation"].get<std::string>().find("get_definition") !=
          std::string::npos);
    CHECK(error_data(no_token)["remediation"].get<std::string>().find("no approval ticket") !=
          std::string::npos);
    CHECK(pending() == 0);
    CHECK(m.domain_keys().empty());
    CHECK(w.row("ver.one").name == "n");

    // An id-bearing save_definition_yaml without updated_at: the same refusal.
    m.clear();
    const json yaml_no_token =
        m.call("save_definition_yaml", {{"yaml_source", kYaml}, {"id", "ver.one"}});
    REQUIRE(yaml_no_token.contains("error"));
    CHECK(yaml_no_token["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(yaml_no_token)["reason"] == "version_token_required");
    CHECK(pending() == 0);
    CHECK(m.domain_keys().empty());

    // The refusal precedes a RECALL too: a ticket minted for the delete (which needs no token)
    // is irrelevant here, but a recall of the token-less update must not reach consume. Nothing
    // was minted for it, so there is no ticket to spend.
    // With the token, the update mints a ticket as before.
    m.clear();
    const json with_token = m.call("update_definition", {{"id", "ver.one"}, {"name", "Renamed"},
                                                          {"expected_updated_at", token}});
    REQUIRE(with_token.contains("error"));
    CHECK(with_token["error"]["code"] == mcp::kApprovalRequired);
    CHECK(pending() == 1);

    // A create (no id) needs no version token and mints. A delete needs one (M3-3): without it,
    // refused before a ticket exists; with it, it mints.
    const json yaml_create = m.call("save_definition_yaml", {{"yaml_source", kYaml}});
    REQUIRE(yaml_create.contains("error"));
    CHECK(yaml_create["error"]["code"] == mcp::kApprovalRequired);
    CHECK(pending() == 2);
    m.clear();
    const json del_no_token = m.call("delete_definition", {{"id", "ver.one"}});
    REQUIRE(del_no_token.contains("error"));
    CHECK(del_no_token["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(del_no_token)["reason"] == "version_token_required");
    CHECK(del_no_token["error"]["message"].get<std::string>().find("delete_definition requires "
                                                                    "expected_updated_at") !=
          std::string::npos);
    CHECK(pending() == 2);
    CHECK(m.domain_keys().empty());
    CHECK(w.get("ver.one").has_value());
    const json del = m.call("delete_definition", w.delete_args("ver.one"));
    REQUIRE(del.contains("error"));
    CHECK(del["error"]["code"] == mcp::kApprovalRequired);
    CHECK(pending() == 3);
}

// The base row moves between approval and recall. The early version check (UP-12) reads the row
// BEFORE the ticket is consumed, so the recall is refused as a conflict with the approval still
// UNSPENT: nothing is written and no domain row is made. Turns red if the stale_version_refusal
// block in mcp_server.cpp is removed: the recall then consumes the ticket and the handler refuses.
TEST_CASE("mcp update_definition: a row that changed between approval and recall is refused as a "
          "conflict before the ticket is consumed; nothing is mutated",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "race.one"}, {"name", "Base"},
                                                         {"type", "question"}, {"plugin", "p"},
                                                         {"approval_mode", "always"}})
                      .contains("error"));
    const std::int64_t token = w.row("race.one").updated_at;

    // The human approves "approval_mode=auto on the version read at `token`".
    json args = {{"id", "race.one"}, {"approval_mode", "auto"}, {"expected_updated_at", token}};
    const json first = m.call("update_definition", args);
    REQUIRE(first.contains("error"));
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));

    // Meanwhile another writer repoints the definition (the token advances).
    {
        InstructionDefinition d = *w.get("race.one");
        d.plugin = "someone_else";
        d.parameter_schema.clear();
        REQUIRE(w.store.update_definition(d, d.updated_at).has_value());
    }
    CHECK(w.row("race.one").updated_at > token);

    m.clear();
    args["approval_id"] = ticket;
    const json recall = m.call("update_definition", args);
    REQUIRE(recall.contains("error"));
    CHECK(recall["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(recall)["reason"] == "conflict");
    CHECK(recall["error"]["message"].get<std::string>().find("get_definition") !=
          std::string::npos);
    // Nothing from the approved update was applied: the other writer's repoint stands and the
    // approval_mode the human approved was NOT written. No domain row, one generic denied row.
    const auto after = w.get("race.one");
    REQUIRE(after.has_value());
    CHECK(after->plugin == "someone_else");
    CHECK(after->approval_mode == "always");
    CHECK(m.domain_keys().empty());
    const auto pre_row = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "mcp.update_definition";
    });
    REQUIRE(pre_row != m.audits.end());
    CHECK(pre_row->result == "denied");
    CHECK(pre_row->detail.find("reason=stale_version") != std::string::npos);
    // The ticket is NOT spent: it is still approved and unconsumed, and the same recall is
    // refused the same way again.
    const auto kept = m.approvals->get(ticket);
    REQUIRE(kept.has_value());
    CHECK(kept->consumed_at == 0);
    const json again = m.call("update_definition", args);
    REQUIRE(again.contains("error"));
    CHECK(error_data(again)["reason"] == "conflict");
    // With the row's CURRENT version the approval is for a different subject (the token is
    // bound into it), so a fresh mint is needed: the old ticket never admits it.
    json fresh = {{"id", "race.one"}, {"approval_mode", "auto"},
                  {"expected_updated_at", w.row("race.one").updated_at}, {"approval_id", ticket}};
    const json mismatch = m.call("update_definition", fresh);
    REQUIRE(mismatch.contains("error"));
    CHECK(mismatch["error"]["code"] == mcp::kPermissionDenied);
    CHECK(w.row("race.one").approval_mode == "always");
}

// UP-1: the import ticket binds a digest of the document. Turns red if the `canon = *subject`
// assignment in the C8 block is removed: the stored scope_expression is then the whole document
// and a one-byte-different document is still refused only because the bytes differ.
TEST_CASE("mcp import_definition: a 3 MiB document mints a small ticket bound to its exact bytes",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    json doc = {{"id", "dig.imp"}, {"name", "I"}, {"version", "1.0"}, {"type", "question"},
                {"plugin", "os_info"}, {"action", "os_name"}, {"yaml_source", kYaml},
                {"pad", std::string(3u * 1024 * 1024, 'p')}};
    const json first = m.call("import_definition", {{"document", doc}});
    REQUIRE(first.contains("error"));
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    const auto row = m.approvals->get(ticket);
    REQUIRE(row.has_value());
    // The stored subject is the digest, not 3 MiB.
    CHECK(row->scope_expression.size() < 400);
    CHECK(row->scope_expression.find("pppp") == std::string::npos);
    CHECK(row->scope_expression.find("import_definition") != std::string::npos);
    CHECK(row->scope_expression.find("document_sha256") != std::string::npos);
    // The approver reads what is being approved, not a bare digest (F4).
    const json subject = json::parse(row->scope_expression);
    CHECK(subject["definition_id"] == "dig.imp");
    CHECK(subject["name"] == "I");
    CHECK(subject["plugin"] == "os_info");
    CHECK(subject["action"] == "os_name");
    // A second identical mint is deduplicated onto the same ticket (same digest).
    const json again = m.call("import_definition", {{"document", doc}});
    CHECK(again["error"]["data"]["approval_id"] == ticket);

    // The list surfaces carry the digest, not the document.
    const auto listed = m.approvals->query();
    REQUIRE_FALSE(listed.empty());
    for (const auto& a : listed)
        CHECK(a.scope_expression.size() < 400);

    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));

    // One byte different: refused as a mismatch, the ticket is NOT consumed, nothing imported.
    json other = doc;
    other["pad"].get_ref<std::string&>()[500] = 'q';
    m.clear();
    const json wrong = m.call("import_definition", {{"document", other}, {"approval_id", ticket}});
    REQUIRE(wrong.contains("error"));
    CHECK(wrong["error"]["code"] == mcp::kPermissionDenied);
    CHECK(wrong["error"]["message"] == "approval_id does not match this tool and arguments");
    CHECK(m.approvals->get(ticket)->consumed_at == 0);
    CHECK(m.domain_keys().empty());

    // A document differing ONLY in approval_mode is a different request too (F4).
    json other_mode = doc;
    other_mode["approval_mode"] = "always";
    m.clear();
    const json wrong_mode =
        m.call("import_definition", {{"document", other_mode}, {"approval_id", ticket}});
    REQUIRE(wrong_mode.contains("error"));
    CHECK(wrong_mode["error"]["code"] == mcp::kPermissionDenied);
    CHECK(m.approvals->get(ticket)->consumed_at == 0);

    // The identical document redeems it: the call reaches the handler (the store refuses the
    // unsigned import, an audited denial) and the ticket is consumed.
    m.clear();
    const json redeem = m.call("import_definition", {{"document", doc}, {"approval_id", ticket}});
    REQUIRE(redeem.contains("error"));
    CHECK(redeem["error"]["code"] == mcp::kInvalidParams);
    CHECK(m.has_row("instruction.import", "attempted"));
    CHECK(m.has_row("instruction.import", "denied"));
    CHECK(m.approvals->get(ticket)->consumed_at != 0);
    // The attempted row names the document and its size (SG F-6).
    const auto attempted = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.import" && r.result == "attempted";
    });
    REQUIRE(attempted != m.audits.end());
    CHECK(attempted->target_id == "dig.imp");
    // MCP's unit is the document as sent (`document_bytes`), not REST's request body.
    CHECK(attempted->detail ==
          "document_bytes=" +
              std::to_string(doc.dump(-1, ' ', false, json::error_handler_t::replace).size()));
}

// Gate 8 F10 (C-6): the success row of an update and of an import names the approval that allowed
// it; the attempted row does not (a SIEM rule keys on its exact detail). Turns red if Audit stops
// appending approval_id on the update or import path.
TEST_CASE("mcp update_definition and import_definition: the success row names the approval; the "
          "attempted row does not",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "apid.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const auto row = [&](const char* action, const char* result) {
        return std::find_if(m.audits.begin(), m.audits.end(), [&](const AuditRow& r) {
            return r.action == action && r.result == result;
        });
    };

    m.clear();
    std::string update_ticket;
    const json upd = m.call_ticketed("update_definition",
                                     {{"id", "apid.one"},
                                      {"approval_mode", "always"},
                                      {"expected_updated_at", w.row("apid.one").updated_at}},
                                     &update_ticket);
    REQUIRE_FALSE(upd.contains("error"));
    const auto update_success = row("instruction.update", "success");
    REQUIRE(update_success != m.audits.end());
    CHECK(update_success->detail.ends_with(" approval_id=" + update_ticket));
    const auto update_attempt = row("instruction.update", "attempted");
    REQUIRE(update_attempt != m.audits.end());
    CHECK(update_attempt->detail.find("approval_id") == std::string::npos);

    m.clear();
    const json document{{"id", "apid.imp"},     {"name", "I"},          {"version", "1.0"},
                        {"type", "question"},   {"plugin", "os_info"},  {"action", "os_name"},
                        {"yaml_source", kYaml}};
    std::string import_ticket;
    const json imp = m.call_ticketed("import_definition", {{"document", document}}, &import_ticket);
    REQUIRE_FALSE(imp.contains("error"));
    const auto import_success = row("instruction.import", "success");
    REQUIRE(import_success != m.audits.end());
    CHECK(import_success->detail == "approval_id=" + import_ticket);
    const auto import_attempt = row("instruction.import", "attempted");
    REQUIRE(import_attempt != m.audits.end());
    CHECK(import_attempt->detail.find("approval_id") == std::string::npos);
}

TEST_CASE("mcp save_definition_yaml: a ~1 MiB YAML mints a small ticket bound to its exact bytes; "
          "and the change row names the approval (C-6)",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;

    const std::string yaml = std::string(kYaml) + "# " + std::string(900 * 1024, 'y') + "\n";
    const json first = m.call("save_definition_yaml", {{"yaml_source", yaml}});
    REQUIRE(first.contains("error"));
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    CHECK(m.approvals->get(ticket)->scope_expression.size() < 300);
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));

    m.clear();
    const json wrong =
        m.call("save_definition_yaml", {{"yaml_source", yaml + "#"}, {"approval_id", ticket}});
    REQUIRE(wrong.contains("error"));
    CHECK(wrong["error"]["code"] == mcp::kPermissionDenied);
    CHECK(m.approvals->get(ticket)->consumed_at == 0);
    CHECK(m.domain_keys().empty());

    m.clear();
    const json ok = m.call("save_definition_yaml", {{"yaml_source", yaml}, {"approval_id", ticket}});
    CHECK(ok_result(ok)["created"] == true);
    const auto success = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.create" && r.result == "success";
    });
    REQUIRE(success != m.audits.end());
    CHECK(success->detail.ends_with(" approval_id=" + ticket));
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.create" && r.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail.find("approval_id") == std::string::npos);
}

// ── Batch C governance fix round C: audit completeness, validation bounds, hygiene ──────

TEST_CASE("mcp import_definition: a hostile approval_mode never reaches the audit detail raw; the "
          "stable prefix stays",
          "[pg][mcp][instruction_authoring][security]") {
    // Turns red if audit_store_error_text is replaced by the old CR/LF-only flatten in the MCP
    // import twin: ESC and U+2028 would persist.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    const std::string hostile = std::string("\r\nforged") + "\x1b[31m" + "\xe2\x80\xa8" + "x";
    const json document{{"id", "imp.hostile"},   {"name", "N\r\nforgedname\x1b"},
                        {"version", "1.0"},      {"type", "question"},
                        {"plugin", "os_info"},   {"action", "os_name"},
                        {"approval_mode", hostile}, {"yaml_source", kYaml}};
    m.clear();
    const json r = m.call_ticketed("import_definition", {{"document", document}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInvalidParams);
    const auto it = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& row) {
        return row.action == "instruction.import" && row.result == "denied";
    });
    REQUIRE(it != m.audits.end());
    CHECK(it->detail.rfind("invalid approval_mode: ", 0) == 0);
    for (const char* bad : {"\r", "\n", "\x1b", "\xe2\x80\xa8"})
        CHECK(it->detail.find(bad) == std::string::npos);
    CHECK(it->detail.find("forgedname") == std::string::npos); // the name is never echoed
    CHECK_FALSE(w.get("imp.hostile").has_value());
}

TEST_CASE("mcp import_definition: created_by is the authenticated principal; whatever the "
          "document claims; the operator import bounds name/plugin/action",
          "[pg][mcp][instruction_authoring][security][bounds]") {
    // Turns red if `document["created_by"] = p.created_by` is removed from import_definition, or
    // the check_signature block in InstructionStore::import_definition_json_impl is removed.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    const json document{{"id", "imp.creator"},   {"name", "n"},
                        {"version", "1.0"},      {"type", "question"},
                        {"plugin", "os_info"},   {"action", "OS_Name"},
                        {"created_by", "mallory"}, {"yaml_source", kYaml}};
    m.clear();
    const json ok_r = m.call_ticketed("import_definition", {{"document", document}});
    CHECK(ok_result(ok_r)["id"] == "imp.creator");
    const auto stored = w.get("imp.creator");
    REQUIRE(stored.has_value());
    CHECK(stored->created_by == "tester");
    CHECK(stored->action == "os_name"); // lowercased, as every other writer does

    for (const auto& [field, value] : std::vector<std::pair<std::string, json>>{
             {"name", std::string(kMaxDefinitionNameLen + 1, 'n')},
             {"version", std::string(kMaxDefinitionVersionLen + 1, 'v')},
             {"instruction_set_id", std::string(kMaxDefinitionInstructionSetIdLen + 1, 's')},
             {"plugin", "bad plugin"},
             {"action", "a/b"}}) {
        INFO(field);
        json bad = document;
        bad["id"] = "imp.bounds";
        bad[field] = value;
        m.clear();
        const json r = m.call_ticketed("import_definition", {{"document", bad}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(m.has_row("instruction.import", "denied"));
        CHECK_FALSE(w.get("imp.bounds").has_value());
    }
}

TEST_CASE("mcp definition handlers: a present but empty plugin is refused (REST agrees); an empty "
          "action stays storable",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if the `if (!def.plugin.empty())` guard returns in apply_definition_fields. The
    // MCP schema's minLength is bypassed here on purpose: the handler re-enforces it.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    ports.audit = [](std::string_view, std::string_view, std::string_view, const std::string&,
                     const std::string&) { return true; };
    const auto created = iauth::create_definition(minimal_create(), ports);
    REQUIRE(created.kind == iauth::Kind::kOk);
    const std::string id = created.payload["id"].get<std::string>();

    const auto blank = iauth::update_definition(json{{"id", id}, {"plugin", ""}}, ports);
    CHECK(blank.kind == iauth::Kind::kInvalid);
    CHECK(blank.message == "plugin must be 1 to 128 characters");
    CHECK(w.row(id).plugin == "os_info");
    json c = minimal_create();
    c["plugin"] = "";
    CHECK(iauth::create_definition(c, ports).kind == iauth::Kind::kInvalid);

    CHECK(iauth::update_definition(json{{"id", id}, {"action", ""}}, ports).kind ==
          iauth::Kind::kOk);
    CHECK(w.row(id).action.empty());
}

TEST_CASE("mcp validate_definition_yaml / save_definition_yaml: an oversize source is refused on its "
          "bytes alone; and name/description bounds give one verdict",
          "[pg][mcp][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    ports.audit = [](std::string_view, std::string_view, std::string_view, const std::string&,
                     const std::string&) { return true; };
    // A bad plugin inside an oversize document: exactly the one byte-level error, no parse.
    const std::string head = "metadata:\n  id: a\n  displayName: A\nspec:\n  plugin: \"bad plugin\"\n"
                             "  action: os_name\n";
    const std::string oversize = head + "# " + std::string(iauth::kYamlSourceMaxBytes, 'y') + "\n";
    const auto v = iauth::validate_definition_yaml(json{{"yaml_source", oversize}});
    REQUIRE(v.kind == iauth::Kind::kOk);
    CHECK(v.payload["errors"].size() == 1);
    const auto sv = iauth::save_definition_yaml(json{{"yaml_source", oversize}}, ports);
    CHECK(sv.kind == iauth::Kind::kInvalid);
    REQUIRE(sv.errors.size() == 1);
    CHECK(sv.errors[0] == "yaml_source too large (max 1MB)");

    // a name past the builders' bound: validate and save refuse with the same list.
    const std::string y = "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                          "metadata:\n  id: bounds.mcp\n  displayName: \"" +
                          std::string(kMaxDefinitionNameLen + 1, 'n') + "\"\n  description: \"" +
                          std::string(kMaxDefinitionDescriptionLen + 1, 'd') +
                          "\"\nspec:\n  plugin: os_info\n  action: os_name\n  type: question\n";
    const auto v2 = iauth::validate_definition_yaml(json{{"yaml_source", y}});
    REQUIRE(v2.kind == iauth::Kind::kOk);
    CHECK(v2.payload["valid"] == false);
    // The name only: the YAML path has no description bound (bundled content exceeds 512 bytes).
    CHECK(v2.payload["errors"].size() == 1);
    const auto s2 = iauth::save_definition_yaml(json{{"yaml_source", y}}, ports);
    CHECK(s2.kind == iauth::Kind::kInvalid);
    CHECK(json(s2.errors) == v2.payload["errors"]);
    CHECK_FALSE(w.get("bounds.mcp").has_value());
}

TEST_CASE("mcp definition writes: a throwing event hook never changes the answer",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if emit() in mcp_instruction_authoring.cpp stops going through emit_event_guarded:
    // a hook that is not the request binder's has no other guard, and the throw would escape a
    // call whose effect and outcome row are already done.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    ports.audit = [](std::string_view, std::string_view, std::string_view, const std::string&,
                     const std::string&) { return true; };
    int emitted = 0;
    ports.emit = [&](std::string_view, const json&, const json&) {
        ++emitted;
        throw std::runtime_error("event bus down");
    };
    const auto created = iauth::create_definition(minimal_create(), ports);
    REQUIRE(created.kind == iauth::Kind::kOk);
    const std::string id = created.payload["id"].get<std::string>();
    CHECK(iauth::update_definition(json{{"id", id}, {"name", "renamed"}}, ports).kind ==
          iauth::Kind::kOk);
    CHECK(iauth::delete_definition(json{{"id", id}}, ports).kind == iauth::Kind::kOk);
    CHECK(emitted == 3);
}

TEST_CASE("mcp save_definition_yaml: a concurrency_mode change is in the update audit detail",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if the concurrency_mode line is removed from describe_dispatch_binding_change.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    const json created = m.call_ticketed("save_definition_yaml", {{"yaml_source", kYaml}});
    CHECK(ok_result(created)["created"] == true);
    const auto before = w.get("test.mcp.yaml");
    REQUIRE(before.has_value());
    m.clear();
    const std::string yaml2 = std::string(kYaml) + "  concurrency: per-fleet\n";
    const json updated = m.call_ticketed(
        "save_definition_yaml",
        {{"yaml_source", yaml2}, {"id", "test.mcp.yaml"}, {"updated_at", before->updated_at}});
    CHECK(ok_result(updated)["created"] == false);
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.update" && r.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail == "concurrency_mode: per-device -> per-fleet");
}

TEST_CASE("mcp instruction authoring: an UNWIRED audit sink refuses every definition write like a "
          "failed attempted row; and mutates nothing",
          "[pg][mcp][instruction_authoring]") {
    // Turns red if the `if (audit_fn)` guard around the Ports.audit assignment in mcp_server.cpp
    // is removed: try_persist_audit reads a null sink as "audit off" and returns true, so the
    // create would proceed with no attempted row. The unset port is a configuration fault: the
    // error carries NO retry hint (a wired sink that fails keeps kMcpStoreFaultRetryMs, asserted
    // in check_attempt_row_refusal). Removing the `not_retryable` set in Audit::refused turns the
    // null check red.
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    yuzu::test::ApprovalManagerPg appr_bundle;
    appr_bundle->create_tables();
    Mcp m;
    m.store = &w.store;
    m.approvals = appr_bundle.get();
    m.audit_wired = false;
    m.wire();
    const json r = m.call_ticketed("create_definition", minimal_create());
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(error_data(r)["reason"] == "audit_unavailable");
    CHECK(error_data(r)["retry_after_ms"].is_null());
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch C fix round E1: the quality-engineer gaps, MCP transport. Each case names the production
// line whose removal turns it red.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

InstructionDefinition seed_row(const std::string& id) {
    InstructionDefinition d;
    d.id = id;
    d.name = "Seed";
    d.version = "1.0";
    d.type = "question";
    d.plugin = "os_info";
    d.action = "os_name";
    d.approval_mode = "always";
    d.enabled = true;
    d.gather_ttl_seconds = 300;
    d.response_ttl_days = 90;
    return d;
}

void seed_def(PgWired& w, const InstructionDefinition& d) {
    REQUIRE(w.store.create_definition(d).has_value());
}

std::string yaml_for(const std::string& id) {
    std::string y = kYaml;
    const std::string from = "test.mcp.yaml";
    y.replace(y.find(from), from.size(), id);
    return y;
}

/// A source of exactly `total` bytes: kYaml followed by a comment line padded to size.
std::string yaml_of_size(std::size_t total) {
    std::string y = kYaml;
    y += "# ";
    REQUIRE(y.size() + 1 < total);
    y.append(total - y.size() - 1, 'y');
    y += "\n";
    REQUIRE(y.size() == total);
    return y;
}

json import_base(const std::string& id) {
    return {{"id", id},
            {"name", "n"},
            {"type", "question"},
            {"plugin", "os_info"},
            {"yaml_source", kYaml}};
}

/// Every JSON key the import scalar gate (InstructionStore::import_definition_json_impl,
/// `kStringFields`) refuses when it is not a string. Mirrors the REST test's list.
constexpr auto kImportStringKeys = std::to_array<const char*>(
    {"id",          "name",           "version",           "type",
     "plugin",      "action",         "description",       "instruction_set_id",
     "created_by",  "yaml_source",    "parameter_schema",  "result_schema",
     "approval_mode", "concurrency_mode", "platforms",     "min_agent_version",
     "required_plugins", "readable_payload"});

struct BadImportField {
    std::string key;
    json value;
};

/// The scalar-type matrix of the import gate, minus `created_by` (the handler stamps the caller
/// over it, so a wrong-typed value is ignored on this transport: its own case below).
std::vector<BadImportField> bad_import_fields() {
    std::vector<BadImportField> out;
    for (const char* key : kImportStringKeys) {
        if (std::string_view(key) == "created_by")
            continue;
        for (const auto& v : std::vector<json>{7, json::object(), json::array(), nullptr, true})
            out.push_back({key, v});
    }
    for (const char* key : {"signature", "publicKey"})
        for (const auto& v : std::vector<json>{7, json::object(), json::array(), true})
            out.push_back({key, v});
    for (const char* key : {"gather_ttl_seconds", "response_ttl_days"})
        for (const auto& v :
             std::vector<json>{"300", nullptr, 1.5, true, json::object(), json::array()})
            out.push_back({key, v});
    for (const auto& v : std::vector<json>{"yes", nullptr, 1, json::array()})
        out.push_back({"enabled", v});
    return out;
}

bool carries_forgery(const std::string& s) {
    return s.find_first_of("\r\n\x1b") != std::string::npos ||
           s.find("\xe2\x80\xa8") != std::string::npos ||
           s.find("\xe2\x80\xa9") != std::string::npos;
}

/// No recorded row, domain or generic, carries a line-forging byte in its detail or target.
void expect_no_forgery(const std::vector<AuditRow>& rows) {
    for (const auto& r : rows) {
        INFO(r.action << "|" << r.result);
        CHECK_FALSE(carries_forgery(r.detail));
        CHECK_FALSE(carries_forgery(r.target_id));
    }
}

std::string nested_json(int depth) {
    std::string s;
    for (int i = 0; i < depth; ++i)
        s += "{\"a\":";
    s += "1";
    s.append(static_cast<std::size_t>(depth), '}');
    return s;
}

} // namespace

// 1. The import scalar type gate on MCP. Turns red if a key is dropped from kStringFields (the
// wrong-typed value reaches get<std::string>() and throws out of the tool), or the TTL / enabled
// checks are removed. Each refusal is typed -32602 with the attempted + denied rows and no
// mutation; created_by is covered by the next case.
TEST_CASE("mcp import_definition: every gated document key refuses a wrong-typed value; audited "
          "attempted + denied; nothing stored; no emit",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;

    // Control: the base document imports, so each refusal below is its one wrong-typed key.
    const json ok_r = m.call_ticketed("import_definition", {{"document", import_base("imp.control")}});
    CHECK(ok_result(ok_r)["id"] == "imp.control");
    CHECK(m.emits.empty()); // an import emits no platform event
    REQUIRE(w.store.delete_definition("imp.control").has_value());

    std::size_t driven = 0;
    for (const auto& c : bad_import_fields()) {
        INFO(c.key << " = " << c.value.dump());
        json doc = import_base("imp.badtype");
        doc[c.key] = c.value;
        m.clear();
        const json r = m.call_ticketed("import_definition", {{"document", doc}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        const auto keys = m.domain_keys();
        REQUIRE(keys.size() == 2);
        CHECK(keys[0] == "instruction.import|attempted");
        CHECK(keys[1] == "instruction.import|denied");
        CHECK(m.emits.empty());
        ++driven;
    }
    CHECK(driven > 75);
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

// Turns red if the handler stops stamping the authenticated caller over the document's created_by
// (a number there would then reach the store gate and be refused).
TEST_CASE("mcp import_definition: a document created_by of any type is ignored; the principal is "
          "stamped",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    int n = 0;
    for (const auto& v : std::vector<json>{7, json::object(), json::array(), nullptr, "mallory"}) {
        INFO(v.dump());
        const std::string id = "imp.cb" + std::to_string(n++);
        json doc = import_base(id);
        doc["created_by"] = v;
        const json r = s.m.call_ticketed("import_definition", {{"document", doc}});
        CHECK(ok_result(r)["id"] == id);
        CHECK(w.row(id).created_by == "tester");
    }
}

// 2. save_definition_yaml request shape, driven with the VALID fixture so each arm is the only
// reason for the refusal. Through the server the schema layer refuses first (no ticket); the
// handler is then called directly so its own parse_yaml_save_body arms are exercised too. Turns
// red if the unknown-key or `updated_at` arm of parse_yaml_save_body is removed (the handler would
// then save the valid source).
TEST_CASE("mcp save_definition_yaml: strict argument shape with a valid source; at the schema and at "
          "the handler",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    std::vector<AuditRow> sink_rows;
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt, const std::string& ti,
                      const std::string& d) {
        sink_rows.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return true;
    };

    const std::vector<std::pair<std::string, json>> bad{
        {"unknown key", {{"yaml_source", kYaml}, {"z", 1}}},
        {"updated_at is a string", {{"yaml_source", kYaml}, {"updated_at", "1"}}},
        {"updated_at is negative", {{"yaml_source", kYaml}, {"updated_at", -5}}},
        {"updated_at is a float", {{"yaml_source", kYaml}, {"updated_at", 1.5}}},
        {"updated_at is null", {{"yaml_source", kYaml}, {"updated_at", nullptr}}},
        {"id is not a string", {{"yaml_source", kYaml}, {"id", 7}}},
        {"yaml_source is not a string", {{"yaml_source", 3}}},
        {"no yaml_source", json::object()}};
    for (const auto& [label, args] : bad) {
        INFO(label);
        m.clear();
        const json r = m.call("save_definition_yaml", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(m.domain_keys().empty());

        const auto direct = iauth::save_definition_yaml(args, ports);
        CHECK(direct.kind == iauth::Kind::kInvalid);
        CHECK(sink_rows.empty()); // refused before the attempt row
    }
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

// 3. Audit degradation: the OUTCOME row is lost after the mutation (returned false, then thrown):
// the change stands and the answer says audit_persisted:false. Create and the sets are pinned by
// the case above; this adds update, delete, import and the YAML save, each on its domain row (the
// generic mcp.<tool> row is left healthy so the flag is attributable). Turns red if a tool's
// Audit::outcome result is dropped from `ok(..., persisted)`, or a lost row undoes the write.
namespace {
void check_outcome_row_lost_mcp(PgWired& w, Mcp& m, bool throws) {
    w.store.set_require_signed_definitions(false);
    seed_def(w, seed_row("lost.update"));
    seed_def(w, seed_row("lost.delete"));
    const auto domain_success = [](const AuditRow& r) {
        return r.action.rfind("instruction", 0) == 0 && r.result == "success";
    };
    if (throws)
        m.audit_throws = domain_success;
    else
        m.audit_fails = domain_success;

    const json upd = m.call_ticketed("update_definition",
                                     {{"id", "lost.update"}, {"description", "changed"},
                                      {"expected_updated_at", w.row("lost.update").updated_at}});
    CHECK(ok_result(upd)["audit_persisted"] == false);
    CHECK(w.row("lost.update").description == "changed");

    const json del = m.call_ticketed("delete_definition", w.delete_args("lost.delete"));
    CHECK(ok_result(del)["audit_persisted"] == false);
    CHECK_FALSE(w.get("lost.delete").has_value());

    const json imp = m.call_ticketed("import_definition", {{"document", import_base("lost.import")}});
    CHECK(ok_result(imp)["audit_persisted"] == false);
    CHECK(w.get("lost.import").has_value());

    const json y_new = m.call_ticketed("save_definition_yaml", {{"yaml_source", yaml_for("lost.yaml")}});
    CHECK(ok_result(y_new)["audit_persisted"] == false);
    CHECK(w.get("lost.yaml").has_value());

    const json y_upd = m.call_ticketed(
        "save_definition_yaml",
        {{"yaml_source", yaml_for("lost.yaml") + "  approval: auto\n"},
         {"id", "lost.yaml"},
         {"updated_at", w.row("lost.yaml").updated_at}});
    CHECK(ok_result(y_upd)["audit_persisted"] == false);
    CHECK(w.row("lost.yaml").approval_mode == "auto");
}
} // namespace

TEST_CASE("mcp update; delete; import and YAML save: a lost outcome row keeps the change and flags "
          "audit_persisted:false",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    check_outcome_row_lost_mcp(w, s.m, /*throws=*/false);
}

TEST_CASE("mcp update; delete; import and YAML save: an outcome row whose sink THROWS keeps the "
          "change and flags audit_persisted:false",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    check_outcome_row_lost_mcp(w, s.m, /*throws=*/true);
}

// 4. CWE-117 through the MCP twins. See the REST case: the hostile bytes are proven to survive into
// the store first, then every recorded row (domain and generic) is read.
TEST_CASE("mcp definition writes: hostile name; description; plugin and id never reach an audit "
          "row raw (CWE-117)",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    const std::string hostile_name = "a\r\nforged";
    const std::string hostile_desc = "d\x1b[31m\xe2\x80\xa8x\xe2\x80\xa9y";
    const std::string hostile_plugin = "p\r\nforged\xe2\x80\xa8";

    const json created = m.call_ticketed("create_definition",
                                         {{"name", hostile_name}, {"description", hostile_desc},
                                          {"type", "question"}, {"plugin", "os_info"},
                                          {"action", "os_name"}});
    const std::string created_id = ok_result(created)["id"].get<std::string>();
    CHECK(w.row(created_id).name == hostile_name); // raw in the store
    CHECK(m.has_row("instruction.create", "success"));
    const auto attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.create" && r.result == "attempted";
    });
    REQUIRE(attempt != m.audits.end());
    CHECK(attempt->detail.find("forged") != std::string::npos); // visible, neutralised
    expect_no_forgery(m.audits);

    // A hostile id: refused at the schema pattern or the store charset; any rows are clean.
    m.clear();
    const json bad_id = m.call("create_definition", {{"id", "x\r\nforged"}, {"name", "n"},
                                                     {"type", "question"}, {"plugin", "p"}});
    CHECK(bad_id.contains("error"));
    expect_no_forgery(m.audits);

    // Update: the stored hostile plugin is the OLD value of the binding change.
    InstructionDefinition seeded = seed_row("cwe.seed");
    seeded.name = hostile_name;
    seeded.plugin = hostile_plugin;
    seeded.description = hostile_desc;
    seed_def(w, seeded);
    REQUIRE(w.row("cwe.seed").plugin == hostile_plugin);
    m.clear();
    const json upd = m.call_ticketed("update_definition",
                                     {{"id", "cwe.seed"}, {"name", hostile_name},
                                      {"description", hostile_desc}, {"plugin", "os_info"},
                                      {"expected_updated_at", w.row("cwe.seed").updated_at}});
    CHECK(ok_result(upd)["updated"] == true);
    const auto upd_attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.update" && r.result == "attempted";
    });
    REQUIRE(upd_attempt != m.audits.end());
    CHECK(upd_attempt->detail.find("forged") != std::string::npos);
    expect_no_forgery(m.audits);

    // Delete: the pre-image tuple carries the hostile name.
    m.clear();
    const json del = m.call_ticketed("delete_definition", w.delete_args("cwe.seed"));
    CHECK(ok_result(del)["deleted"] == true);
    const auto del_attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.delete" && r.result == "attempted";
    });
    REQUIRE(del_attempt != m.audits.end());
    CHECK(del_attempt->detail.find("forged") != std::string::npos);
    expect_no_forgery(m.audits);

    // YAML save, create: ESC and the Unicode separators raw inside the scalars.
    const std::string yaml_create =
        "---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n"
        "  id: cwe.yaml\n  displayName: a\x1b[31mforged\xe2\x80\xa8x\n"
        "  description: d\xe2\x80\xa9y\x1b[0m\n"
        "spec:\n  plugin: os_info\n  action: os_name\n  type: question\n";
    m.clear();
    const json y = m.call_ticketed("save_definition_yaml", {{"yaml_source", yaml_create}});
    CHECK(ok_result(y)["created"] == true);
    CHECK(w.row("cwe.yaml").name.find('\x1b') != std::string::npos); // raw in the store
    const auto y_attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.create" && r.result == "attempted";
    });
    REQUIRE(y_attempt != m.audits.end());
    CHECK(y_attempt->detail.find("forged") != std::string::npos);
    expect_no_forgery(m.audits);

    // YAML save, update over a stored hostile plugin.
    InstructionDefinition ydef = seed_row("cwe.yaml2");
    ydef.plugin = hostile_plugin;
    seed_def(w, ydef);
    m.clear();
    const json yu = m.call_ticketed("save_definition_yaml",
                                    {{"yaml_source", yaml_for("cwe.yaml2")}, {"id", "cwe.yaml2"},
                                     {"updated_at", w.row("cwe.yaml2").updated_at}});
    CHECK(ok_result(yu)["created"] == false);
    const auto yu_attempt = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& r) {
        return r.action == "instruction.update" && r.result == "attempted";
    });
    REQUIRE(yu_attempt != m.audits.end());
    CHECK(yu_attempt->detail.find("forged") != std::string::npos);
    expect_no_forgery(m.audits);
}

// 5. The 1 MiB yaml_source cap on MCP, N and N+1, at the handler (direct) and through the server.
// Turns red if kMaxDefinitionYamlSourceBytes is raised, the byte check is dropped, or the schema
// maxLength is widened past the handler constant.
TEST_CASE("mcp yaml_source cap: exactly 1 MiB is accepted; one byte more is refused without a store "
          "call (validate; save) or as a denied import",
          "[pg][mcp][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    const std::string at_cap = yaml_of_size(kMaxDefinitionYamlSourceBytes);
    const std::string over_cap = yaml_of_size(kMaxDefinitionYamlSourceBytes + 1);
    constexpr const char* kTooLarge = "yaml_source too large (max 1MB)";

    iauth::Ports ports;
    ports.store = &w.store;
    ports.referrers_fn = no_referrers();
    ports.created_by = "tester";
    std::vector<AuditRow> sink_rows;
    ports.audit = [&](std::string_view a, std::string_view r, std::string_view tt, const std::string& ti,
                      const std::string& d) {
        sink_rows.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
        return true;
    };

    // Handler level.
    const auto v_ok = iauth::validate_definition_yaml(json{{"yaml_source", at_cap}});
    REQUIRE(v_ok.kind == iauth::Kind::kOk);
    CHECK(v_ok.payload["valid"] == true);
    const auto v_big = iauth::validate_definition_yaml(json{{"yaml_source", over_cap}});
    REQUIRE(v_big.kind == iauth::Kind::kOk);
    CHECK(v_big.payload["valid"] == false);
    REQUIRE(v_big.payload["errors"].size() == 1);
    CHECK(v_big.payload["errors"][0] == kTooLarge);

    const auto save_big = iauth::save_definition_yaml(json{{"yaml_source", over_cap}}, ports);
    CHECK(save_big.kind == iauth::Kind::kInvalid);
    REQUIRE(save_big.errors.size() == 1);
    CHECK(save_big.errors[0] == kTooLarge);
    CHECK(sink_rows.empty()); // no attempt row: refused before the store was touched
    auto none = w.store.query_definitions(InstructionQuery{});
    REQUIRE(none.has_value());
    CHECK(none->empty());
    const auto save_ok = iauth::save_definition_yaml(json{{"yaml_source", at_cap}}, ports);
    CHECK(save_ok.kind == iauth::Kind::kOk);
    CHECK(w.row("test.mcp.yaml").yaml_source.size() == kMaxDefinitionYamlSourceBytes);

    json big_doc = import_base("imp.big");
    big_doc["yaml_source"] = over_cap;
    sink_rows.clear();
    const auto imp_big = iauth::import_definition(json{{"document", big_doc}}, ports);
    CHECK(imp_big.kind == iauth::Kind::kInvalid);
    CHECK(imp_big.message.find("too large") != std::string::npos);
    REQUIRE(sink_rows.size() == 2);
    CHECK(sink_rows[1].result == "denied");
    CHECK_FALSE(w.get("imp.big").has_value());
    json fit_doc = import_base("imp.fits");
    fit_doc["yaml_source"] = at_cap;
    CHECK(iauth::import_definition(json{{"document", fit_doc}}, ports).kind == iauth::Kind::kOk);
    CHECK(w.row("imp.fits").yaml_source.size() == kMaxDefinitionYamlSourceBytes);

    // Through the server. validate_definition_yaml is a read tool, so no schema layer runs: the
    // handler's byte check is the whole defence, answered as {valid:false, errors}. save is
    // ticketed, so its schema maxLength refuses N+1 before any ticket is minted.
    m.clear();
    const json sv_big = m.call("validate_definition_yaml", {{"yaml_source", over_cap}});
    CHECK(ok_result(sv_big)["valid"] == false);
    REQUIRE(ok_result(sv_big)["errors"].size() == 1);
    CHECK(ok_result(sv_big)["errors"][0] == kTooLarge);
    const json sv_ok = m.call("validate_definition_yaml", {{"yaml_source", at_cap}});
    CHECK(ok_result(sv_ok)["valid"] == true);
    const json ss_big = m.call("save_definition_yaml", {{"yaml_source", over_cap}});
    REQUIRE(ss_big.contains("error"));
    CHECK(ss_big["error"]["code"] == mcp::kInvalidParams); // no ticket: not -32007
    CHECK(m.domain_keys().empty());
}

// 6. The JSON nesting guard on the MCP write tools. The guard is the transport's: the whole
// JSON-RPC body is depth-checked before it is parsed, so arguments nested past
// mcp::kMcpMaxJsonDepth never reach a tool. The request itself is 2 levels deep before
// `arguments`, so the largest admitted argument nesting is kMcpMaxJsonDepth - 2. Turns red if
// parse_request's json_exceeds_depth check is removed.
TEST_CASE("mcp write tools: arguments nested past the JSON depth limit are a -32700 parse error "
          "before any tool; row or ticket; the limit itself is admitted",
          "[pg][mcp][instruction_authoring][bounds]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    const auto raw_call = [&](const std::string& tool, const std::string& nested_value) {
        const std::string body = std::string(R"({"jsonrpc":"2.0","method":"tools/call","id":7,)") +
                                 R"("params":{"name":")" + tool + R"(","arguments":{"name":)" +
                                 nested_value + "}}}";
        auto res = m.post(body);
        REQUIRE(res);
        return json::parse(res->body);
    };
    const std::string too_deep = nested_json(mcp::kMcpMaxJsonDepth);
    const std::string at_limit = nested_json(mcp::kMcpMaxJsonDepth - 3);
    for (const char* tool : {"create_definition", "update_definition", "import_definition",
                             "save_definition_yaml", "create_instruction_set",
                             "validate_definition_yaml", "delete_definition"}) {
        INFO(tool);
        m.clear();
        const json deep = raw_call(tool, too_deep);
        REQUIRE(deep.contains("error"));
        CHECK(deep["error"]["code"] == -32700);
        CHECK(m.audits.empty());
        CHECK(m.emits.empty());

        const json limit = raw_call(tool, at_limit);
        REQUIRE(limit.contains("error"));
        CHECK(limit["error"]["code"] != -32700); // admitted by the guard, refused on its content
    }
    auto all = w.store.query_definitions(InstructionQuery{});
    REQUIRE(all.has_value());
    CHECK(all->empty());
}

// 8. Events. The full tools/call path (not the Ports seam): create, update and delete emit exactly
// one event each and a throwing hook changes nothing (no error, no audit_persisted:false, the
// rows complete); an import emits none. Turns red if any twin's emit() stops going through
// emit_event_guarded, if an emit is added to import, or if a twin emits twice.
TEST_CASE("mcp create; update; delete emit exactly one event each; a throwing hook never changes the "
          "answer; and an import emits none",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    Supervised s{&w.store};
    Mcp& m = s.m;
    m.emit_throws = true;

    const json created = m.call_ticketed("create_definition", {{"id", "ev.one"}, {"name", "n"},
                                                               {"type", "question"}, {"plugin", "p"}});
    const auto csc = ok_result(created);
    CHECK(csc["id"] == "ev.one");
    CHECK_FALSE(csc.contains("audit_persisted"));
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.created");
    CHECK(m.has_row("instruction.create", "success"));

    m.clear();
    const json updated = m.call_ticketed("update_definition",
                                         {{"id", "ev.one"}, {"name", "renamed"},
                                          {"expected_updated_at", w.row("ev.one").updated_at}});
    CHECK_FALSE(ok_result(updated).contains("audit_persisted"));
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.updated");
    CHECK(w.row("ev.one").name == "renamed");

    m.clear();
    const json imported = m.call_ticketed("import_definition", {{"document", import_base("ev.imp")}});
    CHECK(ok_result(imported)["id"] == "ev.imp");
    CHECK(m.emits.empty());

    m.clear();
    const json deleted = m.call_ticketed("delete_definition", w.delete_args("ev.one"));
    CHECK(ok_result(deleted)["deleted"] == true);
    CHECK_FALSE(ok_result(deleted).contains("audit_persisted"));
    REQUIRE(m.emits.size() == 1);
    CHECK(m.emits[0].event_type == "instruction.deleted");
    CHECK_FALSE(w.get("ev.one").has_value());
}

// ───────────────────── M3: delete tickets bind the version; stale tokens burn nothing ─────────────

namespace {

/// Handler-level Ports over a real store: audit rows collected, a switch to lose the OUTCOME rows.
struct HandlerPorts {
    std::vector<AuditRow> audits;
    bool lose_outcomes = false;
    iauth::Ports ports;
    explicit HandlerPorts(InstructionStore* store) {
        ports.store = store;
        ports.created_by = "tester";
        ports.audit = [this](std::string_view a, std::string_view r, std::string_view tt,
                             const std::string& ti, const std::string& d) {
            audits.push_back({std::string(a), std::string(r), std::string(tt), ti, d});
            return !(lose_outcomes && r != "attempted");
        };
        ports.emit = [](std::string_view, const json&, const json&) {};
        ports.referrers_fn = no_referrers();
    }
};

} // namespace

// M3-2. Turns red if the handler stops passing expected_updated_at to the store (the stale delete
// then succeeds), or maps the store's conflict to anything but kConflict.
TEST_CASE("mcp delete_definition handler: a stale expected_updated_at is kConflict and the row "
          "survives; a matching one deletes; an absent id is kNotFound; a bad token is kInvalid",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    HandlerPorts hp{&w.store};
    REQUIRE(iauth::create_definition({{"id", "hd.one"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     hp.ports)
                .kind == iauth::Kind::kOk);
    const std::int64_t token = w.row("hd.one").updated_at;

    hp.audits.clear();
    const auto stale = iauth::delete_definition({{"id", "hd.one"}, {"expected_updated_at", token + 1}},
                                                hp.ports);
    CHECK(stale.kind == iauth::Kind::kConflict);
    CHECK(stale.message.find("get_definition") != std::string::npos);
    CHECK(stale.message.find("conflict:") == std::string::npos); // the store prefix is stripped
    CHECK(w.get("hd.one").has_value());
    REQUIRE(hp.audits.size() == 2);
    CHECK(hp.audits[0].result == "attempted");
    CHECK(hp.audits[1].action == "instruction.delete");
    CHECK(hp.audits[1].result == "denied");
    CHECK(hp.audits[1].detail == "conflict");

    for (const json& bad : {json(-1), json("5"), json(1.5), json(nullptr),
                            json(std::numeric_limits<std::uint64_t>::max())}) {
        INFO(bad.dump());
        hp.audits.clear();
        const auto out = iauth::delete_definition({{"id", "hd.one"}, {"expected_updated_at", bad}},
                                                  hp.ports);
        CHECK(out.kind == iauth::Kind::kInvalid);
        CHECK(out.message == "expected_updated_at must be a non-negative integer");
        CHECK(hp.audits.empty());
        CHECK(w.get("hd.one").has_value());
    }

    // An absent id is not_found whether or not a token is sent; a lost outcome row is flagged.
    hp.lose_outcomes = true;
    const auto gone = iauth::delete_definition({{"id", "hd.none"}, {"expected_updated_at", 3}},
                                               hp.ports);
    CHECK(gone.kind == iauth::Kind::kNotFound);
    CHECK_FALSE(gone.audit_persisted);
    hp.lose_outcomes = false;

    const auto ok = iauth::delete_definition({{"id", "hd.one"}, {"expected_updated_at", token}},
                                             hp.ports);
    CHECK(ok.kind == iauth::Kind::kOk);
    CHECK_FALSE(w.get("hd.one").has_value());

    // No token at the handler = unconditional (an unticketed caller; the tier gate is upstream).
    REQUIRE(iauth::create_definition({{"id", "hd.two"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     hp.ports)
                .kind == iauth::Kind::kOk);
    CHECK(iauth::delete_definition({{"id", "hd.two"}}, hp.ports).kind == iauth::Kind::kOk);
}

// Handler level: the audit_persisted flag on a conflict / not_found whose outcome row is lost (the
// server-level twin was removed from the ticketed table because the early check now refuses a stale
// or absent row before a ticket exists).
TEST_CASE("mcp update/delete handlers: a stale or absent row with a lost outcome row flags "
          "audit_persisted:false",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    HandlerPorts hp{&w.store};
    REQUIRE(iauth::create_definition({{"id", "lo.one"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     hp.ports)
                .kind == iauth::Kind::kOk);
    const std::int64_t token = w.row("lo.one").updated_at;
    hp.lose_outcomes = true;
    const auto upd = iauth::update_definition(
        {{"id", "lo.one"}, {"name", "x"}, {"expected_updated_at", token - 1}}, hp.ports);
    CHECK(upd.kind == iauth::Kind::kConflict);
    CHECK_FALSE(upd.audit_persisted);
    const auto del = iauth::delete_definition({{"id", "lo.one"}, {"expected_updated_at", token - 1}},
                                              hp.ports);
    CHECK(del.kind == iauth::Kind::kConflict);
    CHECK_FALSE(del.audit_persisted);
    CHECK(w.row("lo.one").name == "n");
}

// M3-1 + handler: a failed existence probe after a zero-row conditional delete is a store fault
// with outcome-unknown wording, never not_found or conflict, and the row survives. Turns red if the
// probe's failure is folded into the zero-row answer.
TEST_CASE("mcp delete_definition handler: a failed existence probe after a zero-row conditional "
          "delete is an outcome-unknown store fault; the row survives",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    HandlerPorts hp{&w.store};
    REQUIRE(iauth::create_definition({{"id", "pf.one"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     hp.ports)
                .kind == iauth::Kind::kOk);
    const std::int64_t token = w.row("pf.one").updated_at;
    yuzu::test::ExistsProbeFault fault(w.pool);
    fault.arm();
    hp.audits.clear();
    const auto out = iauth::delete_definition({{"id", "pf.one"}, {"expected_updated_at", token + 5}},
                                              hp.ports);
    CHECK(out.kind == iauth::Kind::kStoreUnavailable);
    CHECK(out.outcome_unknown);
    REQUIRE(hp.audits.size() == 2);
    CHECK(hp.audits[1].result == "error");
    CHECK(hp.audits[1].detail == "db_error");
    fault.repair();
    CHECK(w.get("pf.one").has_value());
}

// M3-4 / M3-7. The server-level contract of the early version check, at the supervised tier.
// Turns red if the stale_version_refusal block in mcp_server.cpp is removed (a ticket is minted for
// the stale token: pending moves), or if it moves after the mint.
TEST_CASE("mcp supervised tier: a stale or absent version token is refused before a ticket is "
          "minted for update and delete and an id-bearing yaml save",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "st.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const std::int64_t token = w.row("st.one").updated_at;
    const auto pending = [&] { return *m.approvals->pending_count_for_checked("tester"); };
    REQUIRE(pending() == 0);

    struct Case {
        const char* what;
        const char* tool;
        json args;
        const char* reason;
        const char* detail_reason;
    };
    const Case cases[] = {
        {"update, stale", "update_definition",
         {{"id", "st.one"}, {"name", "x"}, {"expected_updated_at", token + 1}}, "conflict",
         "stale_version"},
        {"update, absent", "update_definition",
         {{"id", "st.none"}, {"name", "x"}, {"expected_updated_at", token}}, "not_found",
         "not_found"},
        {"delete, stale", "delete_definition",
         {{"id", "st.one"}, {"expected_updated_at", token + 1}}, "conflict", "stale_version"},
        {"delete, absent", "delete_definition",
         {{"id", "st.none"}, {"expected_updated_at", token}}, "not_found", "not_found"},
        {"yaml save, stale", "save_definition_yaml",
         {{"yaml_source", kYaml}, {"id", "st.one"}, {"updated_at", token + 1}}, "conflict",
         "stale_version"},
        {"yaml save, absent", "save_definition_yaml",
         {{"yaml_source", kYaml}, {"id", "st.none"}, {"updated_at", token}}, "not_found",
         "not_found"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        m.clear();
        const json r = m.call(c.tool, c.args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(error_data(r)["reason"] == c.reason);
        if (std::string_view(c.reason) == "conflict")
            CHECK(r["error"]["message"].get<std::string>().find("get_definition") !=
                  std::string::npos);
        CHECK(pending() == 0); // no ticket minted
        CHECK(m.domain_keys().empty());
        const std::string generic = std::string("mcp.") + c.tool;
        const auto row = std::find_if(m.audits.begin(), m.audits.end(), [&](const AuditRow& a) {
            return a.action == generic;
        });
        REQUIRE(row != m.audits.end());
        CHECK(row->result == "denied");
        CHECK(row->detail.find(std::string("reason=") + c.detail_reason) != std::string::npos);
        CHECK(row->detail.find("correlation_id=") != std::string::npos);
    }
    CHECK(w.row("st.one").name == "n");

    // The matching token mints (the gate is not simply refusing everything).
    for (const Case& ok : {Case{"update", "update_definition",
                               {{"id", "st.one"}, {"name", "x"}, {"expected_updated_at", token}},
                               "", ""},
                          Case{"delete", "delete_definition",
                               {{"id", "st.one"}, {"expected_updated_at", token}}, "", ""}}) {
        INFO(ok.what);
        const json r = m.call(ok.tool, ok.args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kApprovalRequired);
    }
    CHECK(pending() == 2);
}

// M3-4: the recall path. The id is deleted and re-created between approval and recall: the old
// token no longer matches, the recall is refused as a conflict and the approval is NOT consumed.
// Turns red if the stale check runs after consume_ticket (consumed_at would be nonzero).
TEST_CASE("mcp delete_definition: a definition re-created between approval and recall is refused "
          "as a conflict and the approval is not consumed",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "rc.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    json args = w.delete_args("rc.one");
    const json first = m.call("delete_definition", args);
    REQUIRE(first.contains("error"));
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));

    // Delete (out of band) and re-create the same id.
    REQUIRE(w.store.delete_definition("rc.one").has_value());
    InstructionDefinition d;
    d.id = "rc.one";
    d.name = "new owner";
    d.type = "question";
    d.plugin = "p";
    REQUIRE(w.store.create_definition(d).has_value());
    CHECK(w.row("rc.one").updated_at > args["expected_updated_at"].get<std::int64_t>());

    m.clear();
    args["approval_id"] = ticket;
    const json recall = m.call("delete_definition", args);
    REQUIRE(recall.contains("error"));
    CHECK(recall["error"]["code"] == mcp::kInvalidParams);
    CHECK(error_data(recall)["reason"] == "conflict");
    CHECK(w.row("rc.one").name == "new owner");
    CHECK(m.domain_keys().empty());
    const auto kept = m.approvals->get(ticket);
    REQUIRE(kept.has_value());
    CHECK(kept->consumed_at == 0); // burned nothing
}

// M3-4 (delete): an unreadable store fails closed (retryable store_unavailable) and consumes
// nothing. For delete_definition this is decided by the pre-mint EXISTENCE guard
// (delete_referrer_refusal reads the row first), which now shadows the early version check: the
// next test is the one that reaches stale_version_refusal's own unreadable-store branch. Turns red
// if either guard treats a failed read as "matches".
TEST_CASE("mcp supervised tier: an unreadable definition at the pre-mint check of a delete is a "
          "retryable store fault and the approval is not consumed",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "uf.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    json args = w.delete_args("uf.one");
    const json first = m.call("delete_definition", args);
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));
    args["approval_id"] = ticket;

    // Break the instruction store's relation: every read fails.
    yuzu::test::SqlFault broken(
        w.pool,
        "ALTER TABLE instruction_store.instruction_definitions RENAME TO "
        "instruction_definitions_gone",
        "ALTER TABLE instruction_store.instruction_definitions_gone RENAME TO "
        "instruction_definitions");
    broken.arm();
    m.clear();
    const json r = m.call("delete_definition", args);
    broken.repair();
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(error_data(r)["reason"] == "store_unavailable");
    CHECK(error_data(r)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    CHECK(m.domain_keys().empty());
    const auto kept = m.approvals->get(ticket);
    REQUIRE(kept.has_value());
    CHECK(kept->consumed_at == 0);
    CHECK(w.get("uf.one").has_value());

    // The store is back: the SAME approved ticket still deletes it.
    const json done = m.call("delete_definition", args);
    CHECK_FALSE(done.contains("error"));
    CHECK_FALSE(w.get("uf.one").has_value());
}

// M3-4 (update): update_definition has no existence guard ahead of the early version check, so an
// unreadable store here reaches stale_version_refusal's own `!stored` branch. Turns red if that
// branch treats a failed read as "matches" (the call would go on to consume the approval).
TEST_CASE("mcp supervised tier: an unreadable definition at the early version check of an update "
          "is a retryable store fault and the approval is not consumed",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "uf.upd"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    json args = {{"id", "uf.upd"}, {"name", "renamed"},
                 {"expected_updated_at", w.row("uf.upd").updated_at}};
    const json first = m.call("update_definition", args);
    REQUIRE(first["error"]["code"] == mcp::kApprovalRequired);
    const std::string ticket = first["error"]["data"]["approval_id"].get<std::string>();
    REQUIRE(m.approvals->approve(ticket, "reviewer-bob", "ok"));
    args["approval_id"] = ticket;

    yuzu::test::SqlFault broken(
        w.pool,
        "ALTER TABLE instruction_store.instruction_definitions RENAME TO "
        "instruction_definitions_gone",
        "ALTER TABLE instruction_store.instruction_definitions_gone RENAME TO "
        "instruction_definitions");
    broken.arm();
    m.clear();
    const json r = m.call("update_definition", args);
    broken.repair();
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(error_data(r)["reason"] == "store_unavailable");
    CHECK(error_data(r)["retry_after_ms"] == mcp::kMcpStoreFaultRetryMs);
    const auto kept = m.approvals->get(ticket);
    REQUIRE(kept.has_value());
    CHECK(kept->consumed_at == 0);
    CHECK(w.row("uf.upd").name == "n");

    // The store is back: the SAME approved ticket still applies the update.
    const json done = m.call("update_definition", args);
    CHECK_FALSE(done.contains("error"));
    CHECK(w.row("uf.upd").name == "renamed");
}

// N1-4 (a pin, not a fix). 2^63 is a valid JSON integer above INT64_MAX that the handler would
// refuse as malformed AFTER the approval is spent. The tool input-schema validation that runs in
// the approval path already refuses it -32602 ("integer is outside the signed 64-bit range"),
// before a ticket is minted or consumed, so nothing is burned. Turns red if that validation stops
// covering the version-token fields (a ticket would then be minted: pending moves).
TEST_CASE("mcp supervised tier: a version token above INT64_MAX is refused -32602 before a ticket "
          "is minted for update and delete and an id-bearing yaml save",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    Supervised s{&w.store};
    Mcp& m = s.m;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "ov.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const auto pending = [&] { return *m.approvals->pending_count_for_checked("tester"); };
    REQUIRE(pending() == 0);
    const std::uint64_t too_big = 9223372036854775808ULL; // INT64_MAX + 1

    struct Case {
        const char* tool;
        json args;
    };
    const Case cases[] = {
        {"update_definition", {{"id", "ov.one"}, {"name", "x"}, {"expected_updated_at", too_big}}},
        {"delete_definition", {{"id", "ov.one"}, {"expected_updated_at", too_big}}},
        {"save_definition_yaml", {{"yaml_source", kYaml}, {"id", "ov.one"}, {"updated_at", too_big}}},
    };
    for (const auto& c : cases) {
        INFO(c.tool);
        m.clear();
        const json r = m.call(c.tool, c.args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["remediation"].get<std::string>().find(
                  "no approval ticket was created or consumed") != std::string::npos);
        CHECK(pending() == 0); // no ticket minted, so nothing to burn
        CHECK(m.domain_keys().empty());
    }
    CHECK(w.row("ov.one").name == "n");
}

// N1-5 / N1-6a. A store fault after the attempted row settles into an `error` outcome row that is
// reported as audit_persisted:false when it is lost. Only the `db_error` settle() sites are pinned,
// one per case below (create, update, delete, import, create set, delete set and the delete
// pre-image read): reverting one to `(void)audit.outcome(...)` makes its case red. The `denied`
// sites (duplicate_id, invalid, conflict, not_found, the import signature refusals) need a store
// answer these faults cannot produce, or a concurrent writer between the handler's read and its
// write, and are NOT pinned here; they share the one `settle` body, so the db_error cases cover
// that body, not each call site.
TEST_CASE("mcp handlers: an outcome row lost on a store-fault path is flagged audit_persisted:false "
          "at every settle site",
          "[pg][mcp][instruction_authoring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    w.store.set_require_signed_definitions(false);
    HandlerPorts hp{&w.store};
    REQUIRE(iauth::create_definition({{"id", "kd.one"}, {"name", "n"}, {"type", "question"},
                                      {"plugin", "p"}},
                                     hp.ports)
                .kind == iauth::Kind::kOk);
    const auto set = iauth::create_instruction_set({{"name", "kd-set"}}, hp.ports);
    REQUIRE(set.kind == iauth::Kind::kOk);
    const std::string set_id = set.payload["id"].get<std::string>();
    const std::int64_t token = w.row("kd.one").updated_at;

    // Runs `call` twice against the armed fault: with the outcome row lost (flagged) and stored
    // (not flagged), and checks the row that was written.
    const auto both = [&](const char* what, const std::function<iauth::Result()>& call) {
        INFO(what);
        hp.lose_outcomes = true;
        hp.audits.clear();
        const auto lost = call();
        CHECK(lost.kind == iauth::Kind::kStoreUnavailable);
        CHECK_FALSE(lost.audit_persisted);
        hp.lose_outcomes = false;
        hp.audits.clear();
        const auto kept = call();
        CHECK(kept.kind == iauth::Kind::kStoreUnavailable);
        CHECK(kept.audit_persisted);
        REQUIRE_FALSE(hp.audits.empty());
        CHECK(hp.audits.back().result == "error");
        CHECK(hp.audits.back().detail == "db_error");
    };

    SECTION("definition writes fail") {
        yuzu::test::WriteFault fault(w.pool, "instruction_store.instruction_definitions", "def");
        fault.arm();
        both("create", [&] {
            return iauth::create_definition(
                {{"id", "kd.new"}, {"name", "n"}, {"type", "question"}, {"plugin", "p"}}, hp.ports);
        });
        both("update", [&] {
            return iauth::update_definition(
                {{"id", "kd.one"}, {"name", "x"}, {"expected_updated_at", token}}, hp.ports);
        });
        both("delete", [&] {
            return iauth::delete_definition({{"id", "kd.one"}, {"expected_updated_at", token}},
                                            hp.ports);
        });
        both("import", [&] {
            return iauth::import_definition(
                {{"document", {{"id", "kd.imp"}, {"name", "n"}, {"version", "1.0"},
                               {"type", "question"}, {"plugin", "p"}, {"action", "a"}}}},
                hp.ports);
        });
        fault.repair();
        CHECK(w.get("kd.one").has_value());
        CHECK_FALSE(w.get("kd.new").has_value());
    }
    SECTION("set writes fail") {
        yuzu::test::WriteFault fault(w.pool, "instruction_store.instruction_sets", "set");
        fault.arm();
        both("create set", [&] {
            return iauth::create_instruction_set({{"name", "kd-other"}}, hp.ports);
        });
        both("delete set", [&] {
            return iauth::delete_instruction_set({{"id", set_id}}, hp.ports);
        });
        fault.repair();
        CHECK(w.sets().size() == 1);
    }
    SECTION("delete: an unreadable pre-image is one db_error row, not silence") {
        yuzu::test::SqlFault broken(
            w.pool,
            "ALTER TABLE instruction_store.instruction_definitions RENAME TO "
            "instruction_definitions_gone",
            "ALTER TABLE instruction_store.instruction_definitions_gone RENAME TO "
            "instruction_definitions");
        broken.arm();
        both("delete pre-image read", [&] {
            return iauth::delete_definition({{"id", "kd.one"}, {"expected_updated_at", token}},
                                            hp.ports);
        });
        broken.repair();
        // No attempted row was written: the fault is decided before the attempt.
        hp.audits.clear();
        broken.arm();
        (void)iauth::delete_definition({{"id", "kd.one"}, {"expected_updated_at", token}}, hp.ports);
        broken.repair();
        REQUIRE(hp.audits.size() == 1);
        CHECK(hp.audits[0].action == "instruction.delete");
    }
}

// M3-3 ordering: RBAC, then the version token, then referrers, then the stale check. Turns red if
// any two of those blocks swap (each case pins which refusal wins when two apply).
TEST_CASE("mcp supervised delete: the pre-mint order is RBAC then version token then referrers then stale",
          "[pg][mcp][instruction_authoring][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mcp_authoring_tpl);
    PgWired w{db.dsn()};
    yuzu::test::ApprovalManagerPg appr_bundle;
    appr_bundle->create_tables();
    Mcp m;
    m.store = &w.store;
    m.approvals = appr_bundle.get();
    bool referenced = true;
    m.referrers = [&referenced](const std::string& id)
        -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        if (referenced)
            return std::vector<DefinitionReferrer>{{"schedule", "sched-" + id}};
        return std::vector<DefinitionReferrer>{};
    };
    m.wire();
    referenced = false;
    REQUIRE_FALSE(m.call_ticketed("create_definition", {{"id", "od.one"}, {"name", "n"},
                                                         {"type", "question"}, {"plugin", "p"}})
                      .contains("error"));
    const std::int64_t token = w.row("od.one").updated_at;

    // Referenced AND stale: the referrer refusal wins (referrers run before the stale check).
    referenced = true;
    m.clear();
    json r = m.call("delete_definition", {{"id", "od.one"}, {"expected_updated_at", token + 1}});
    REQUIRE(r.contains("error"));
    CHECK(error_data(r)["reason"] == "referenced");

    // Referenced AND no token: the version-token refusal wins.
    m.clear();
    r = m.call("delete_definition", {{"id", "od.one"}});
    REQUIRE(r.contains("error"));
    CHECK(error_data(r)["reason"] == "version_token_required");

    // Not referenced, stale: the stale refusal.
    referenced = false;
    m.clear();
    r = m.call("delete_definition", {{"id", "od.one"}, {"expected_updated_at", token + 1}});
    REQUIRE(r.contains("error"));
    CHECK(error_data(r)["reason"] == "conflict");

    // An ABSENT id that a dangling referrer still names is not_found (as REST answers it), never
    // `referenced`: only a row that exists can be referenced, and the refusal must not mask the
    // documented "a landed delete retries as not_found".
    referenced = true;
    m.clear();
    r = m.call("delete_definition", {{"id", "od.none"}, {"expected_updated_at", token}});
    REQUIRE(r.contains("error"));
    CHECK(error_data(r)["reason"] == "not_found");
    CHECK(*m.approvals->pending_count_for_checked("tester") == 0);
    const auto absent_row = std::find_if(m.audits.begin(), m.audits.end(), [](const AuditRow& a) {
        return a.action == "mcp.delete_definition";
    });
    REQUIRE(absent_row != m.audits.end());
    CHECK(absent_row->detail.find("reason=not_found") != std::string::npos);
    CHECK(absent_row->detail.find("reason=referenced") == std::string::npos);
    referenced = false;

    // No RBAC grant, no token, stale: RBAC wins (403, nothing learned about the arguments).
    m.perm_allow = false;
    m.clear();
    auto res = m.post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 3},
                           {"params", {{"name", "delete_definition"},
                                       {"arguments", {{"id", "od.one"}}}}}}
                          .dump());
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(*m.approvals->pending_count_for_checked("tester") == 0);
}
