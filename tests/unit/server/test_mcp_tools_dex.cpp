/// @file test_mcp_tools_dex.cpp
/// The DEX score policy MCP twins (mcp_tools_dex.cpp, #6087): `get_dex_score_policy`,
/// `set_dex_score_policy` and `reset_dex_score_policy`, plus the pure helpers in
/// dex_score_policy_mcp.hpp.
///
/// The fixture (`Twin`) drives a real `McpServer` through its in-process handler with a
/// `ToolDeps` whose read and apply closures forward to an in-memory fake store through the REAL
/// `apply_dex_score_policy` and `DexScorePolicyProvider`, the way server.cpp wires them, so the
/// tests exercise the production records and the one write path, not a stub. It is local on
/// purpose: `McpTestServer` (test_mcp_server.cpp) is TU-private.
///
/// Matrix: pure helpers, registration (security rows, annotations, typed output schemas), the
/// read, the write (stored text, dry run, refusals, tiers, audit-first, the audit_persisted
/// accumulator, store faults), the reset (empty-tier body cases, then the approval ticket round
/// trip and the spent-ticket recovery, which need Postgres and skip without it), strict
/// arguments and every unwired closure. No sleeps, no real files or sockets.

#include "dex_score_policy_mcp.hpp"
#include "dex_score_policy_writer.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "mcp_server_testonly.hpp"
#include "mcp_tool_deps.hpp"
#include "mcp_tool_registry.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "test_json_schema_subset.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
namespace mcp = yuzu::server::mcp;
using yuzu::test::schema_violation;
using Op = DexScorePolicyWriteRequest::Op;
using St = DexScorePolicyWriteStatus;

namespace {

std::string doc_with_excellent(double e) {
    DexScorePolicy p;
    p.tiers.edges.excellent = e;
    return dex_score_policy_canonical(p);
}

json doc_json(double e) {
    return json::parse(doc_with_excellent(e));
}

std::string rev_of(const std::string& text) {
    return dex_score_policy_revision(text);
}

const std::string kDbError = std::string(kDbErrorPrefix) + "database write failed";

struct Twin {
    // ── the fake store (apply_dex_score_policy runs for real over it) ──
    std::optional<std::string> stored;
    bool read_fails = false;
    int read_calls = 0;
    int cas_calls = 0;
    int car_calls = 0;
    // The store reports an error AFTER the write: `intended` leaves the intended state in the
    // store (observed_after_store_error), `other` leaves a different document there.
    enum class AfterError { none, intended, other };
    AfterError cas_after_error = AfterError::none;
    AfterError car_after_error = AfterError::none;
    std::shared_ptr<DexScorePolicyProvider> provider;

    // ── the seams ──
    std::vector<std::string> perm_calls;     // "<securable>:<operation>", in call order
    std::string perm_deny;                   // "<securable>:<operation>" the gate refuses
    bool domain_audit_ok = true;
    std::string domain_fail_result;          // when set, ONLY a row with this result fails
    bool domain_audit_throws = false;
    std::vector<std::string> domain_rows;    // action|result|type|id
    std::vector<std::string> domain_details; // parallel
    bool generic_audit_ok = true;
    std::vector<std::string> generic_rows;   // action|result
    std::string username = "tester";
    std::string tier = "supervised";
    std::string scope_service;
    bool read_only_mode_ = false; // build_handler keeps ADDRESSES of these two
    bool mcp_disabled_ = false;

    mcp::McpServer server;
    mcp::McpServer::HandlerFn handler;

    struct Opts {
        bool wire_read = true;
        bool wire_apply = true;
        bool wire_audit = true;
        bool wire_username = true;
        yuzu::server::ApprovalManager* approval = nullptr;
    };

    Twin() : Twin(Opts{}) {}
    explicit Twin(Opts o) {
        provider = std::make_shared<DexScorePolicyProvider>(
            [this]() -> std::expected<std::optional<std::string>, std::string> { return stored; },
            [] { return std::int64_t{1'000'000}; }, std::chrono::milliseconds{1});

        DexScorePolicyWriteDeps d;
        d.read_stored = [this]() -> std::expected<std::optional<std::string>, std::string> {
            ++read_calls;
            if (read_fails)
                return std::unexpected(std::string("store down"));
            return stored;
        };
        d.compare_and_set = [this](const std::optional<std::string>& expected,
                                   const std::string& canonical,
                                   const std::string&) -> std::expected<bool, std::string> {
            ++cas_calls;
            if (stored != expected)
                return false;
            switch (cas_after_error) {
            case AfterError::none:
                stored = canonical;
                return true;
            case AfterError::intended:
                stored = canonical;
                return std::unexpected(kDbError);
            case AfterError::other:
                stored = doc_with_excellent(70.0);
                return std::unexpected(kDbError);
            }
            return false;
        };
        d.compare_and_remove = [this](const std::string& expected) -> std::expected<bool, std::string> {
            ++car_calls;
            if (stored != expected)
                return false;
            switch (car_after_error) {
            case AfterError::none:
                stored.reset();
                return true;
            case AfterError::intended:
                stored.reset();
                return std::unexpected(kDbError);
            case AfterError::other:
                stored = doc_with_excellent(70.0);
                return std::unexpected(kDbError);
            }
            return false;
        };
        d.provider = provider;

        mcp::ToolDeps td;
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
        if (o.wire_read)
            td.dex_score_policy_read_fn = d.read_stored;
        if (o.wire_apply)
            td.dex_score_policy_apply_fn =
                [deps = d](const DexScorePolicyWriteRequest& rq,
                           mcp::ToolDeps::DexScorePolicyAuditFn audit) {
                    auto copy = deps;
                    copy.audit = std::move(audit);
                    return apply_dex_score_policy(rq, copy);
                };
        if (o.wire_username)
            td.username_fn = [this](const httplib::Request&) -> std::optional<std::string> {
                return username;
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
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& operation) {
            const std::string key = securable + ":" + operation;
            perm_calls.push_back(key);
            if (!perm_deny.empty() && key == perm_deny) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto generic_audit = [this](const httplib::Request&, const std::string& a,
                                    const std::string& r, const std::string&, const std::string&,
                                    const std::string&) {
            generic_rows.push_back(a + "|" + r);
            return generic_audit_ok;
        };
        auto agents_fn = []() { return json::array(); };
        handler = server.build_handler(
            std::move(auth_fn), std::move(perm_fn), std::move(generic_audit), std::move(agents_fn),
            /*rbac_store=*/nullptr, /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*response_store=*/nullptr, /*audit_store=*/nullptr, /*tag_store=*/nullptr,
            /*inventory_store=*/nullptr, /*policy_store=*/nullptr, /*mgmt_store=*/nullptr,
            /*approval_manager=*/o.approval, /*schedule_engine=*/nullptr, read_only_mode_,
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

    json call(const std::string& tool, const json& arguments = json::object()) {
        json params = {{"name", tool}, {"arguments", arguments}};
        auto res = post(json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 7}, {"params", params}}
                            .dump());
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
        perm_calls.clear();
        domain_rows.clear();
        domain_details.clear();
        generic_rows.clear();
    }
};

int audit_count(const std::vector<std::string>& rows, const std::string& row) {
    return static_cast<int>(std::count(rows.begin(), rows.end(), row));
}

/// A handler-level argument refusal is the A4 envelope, never a bare -32602 (agentic-first
/// principle A5 item 5): a fresh correlation id, a null retry hint (resending fails
/// identically), the remediation text, and `audit_persisted` named only when the denial row was
/// dropped.
void check_a4_refusal(const json& r, std::string_view remediation_has, bool audit_persisted = true) {
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInvalidParams);
    const json& d = r["error"]["data"];
    REQUIRE(d.contains("correlation_id"));
    REQUIRE(d["correlation_id"].is_string());
    CHECK_FALSE(d["correlation_id"].get<std::string>().empty());
    CHECK(d["retry_after_ms"].is_null());
    REQUIRE(d["remediation"].is_string());
    CHECK(d["remediation"].get<std::string>().find(remediation_has) != std::string::npos);
    if (audit_persisted)
        CHECK_FALSE(d.contains("audit_persisted"));
    else
        CHECK(d["audit_persisted"] == false);
}

json set_args(double excellent, const std::string& if_match) {
    return {{"document", doc_json(excellent)}, {"if_match", if_match}};
}

const std::string kAttemptedUpdate = "dex.score_policy.update|attempted|RuntimeConfig|dex_score_policy";
const std::string kSuccessUpdate = "dex.score_policy.update|success|RuntimeConfig|dex_score_policy";
const std::string kAttemptedReset = "dex.score_policy.reset|attempted|RuntimeConfig|dex_score_policy";

} // namespace

// ───────────────────────── pure helpers ─────────────────────────────────────────

TEST_CASE("dex score policy mcp: the request builder is strict and maps dry_run to the raw strings",
          "[mcp][dex][score_policy][pure]") {
    SECTION("a valid put") {
        const auto rq = dex_score_policy_mcp_request(
            Op::Put, {{"document", doc_json(95.0)}, {"if_match", "default"}, {"dry_run", true}});
        REQUIRE(rq);
        CHECK(rq->op == Op::Put);
        CHECK(rq->actor.empty()); // the handler sets the actor from the resolved caller
        CHECK(rq->if_match == std::optional<std::string>("default"));
        CHECK(rq->dry_run == std::optional<std::string>("true"));
        CHECK(json::parse(rq->body) == doc_json(95.0));
    }
    SECTION("dry_run false maps to the raw string 'false'; absent stays nullopt") {
        const auto f = dex_score_policy_mcp_request(
            Op::Put, {{"document", doc_json(95.0)}, {"dry_run", false}});
        REQUIRE(f);
        CHECK(f->dry_run == std::optional<std::string>("false"));
        const auto n = dex_score_policy_mcp_request(Op::Put, {{"document", doc_json(95.0)}});
        REQUIRE(n);
        CHECK_FALSE(n->dry_run.has_value());
        CHECK_FALSE(n->if_match.has_value()); // absent if_match is left to apply's 428-class refusal
    }
    SECTION("refusals") {
        const json doc = doc_json(95.0);
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, json::array()));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, {{"document", doc}, {"bogus", 1}}));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, {{"document", "text"}}));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, {{"document", json::array()}}));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, json::object())); // no document
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Put, {{"document", doc}, {"if_match", 5}}));
        CHECK_FALSE(dex_score_policy_mcp_request(
            Op::Put, {{"document", doc}, {"if_match", std::string(65, 'a')}}));
        CHECK_FALSE(dex_score_policy_mcp_request(
            Op::Put, {{"document", doc}, {"dry_run", "true"}})); // a string, not a boolean
    }
    SECTION("approval_id is accepted on a reset only; dry_run and document never on a reset") {
        CHECK(dex_score_policy_mcp_request(Op::Reset, {{"if_match", "default"}, {"approval_id", "x"}}));
        CHECK_FALSE(dex_score_policy_mcp_request(
            Op::Put, {{"document", doc_json(95.0)}, {"approval_id", "x"}}));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Reset, {{"dry_run", true}}));
        CHECK_FALSE(dex_score_policy_mcp_request(Op::Reset, {{"document", doc_json(95.0)}}));
    }
    SECTION("an unknown key is named, neutralised and capped, and no value is echoed") {
        const auto rq = dex_score_policy_mcp_request(
            Op::Reset, {{std::string("evil key\n") + std::string(200, 'z'), "SECRET-VALUE"}});
        REQUIRE_FALSE(rq);
        CHECK(rq.error().starts_with("unknown argument '"));
        CHECK(rq.error().size() < 100);
        CHECK(rq.error().find('\n') == std::string::npos);
        CHECK(rq.error().find("SECRET-VALUE") == std::string::npos);
    }
}

TEST_CASE("dex score policy mcp: every write status maps to a JSON-RPC code and a token",
          "[mcp][dex][score_policy][pure]") {
    for (const auto s : {St::IfMatchMissing, St::IfMatchMalformed, St::Invalid, St::Stale}) {
        CHECK(dex_score_policy_mcp_code(s) == mcp::kInvalidParams);
        CHECK(dex_score_policy_http_status(s) < 500);
    }
    for (const auto s :
         {St::WriterBusy, St::StoreUnavailable, St::OutcomeUnknown, St::AuditUnavailable}) {
        CHECK(dex_score_policy_mcp_code(s) == mcp::kInternalError);
        CHECK(dex_score_policy_http_status(s) == 503);
    }
    CHECK(dex_score_policy_mcp_code(St::Ok) == 0);
    for (const auto s : {St::Ok, St::IfMatchMissing, St::IfMatchMalformed, St::Stale, St::Invalid,
                         St::WriterBusy, St::StoreUnavailable, St::OutcomeUnknown,
                         St::AuditUnavailable})
        CHECK_FALSE(dex_score_policy_mcp_status_token(s).empty());
}

TEST_CASE("dex score policy mcp: the success payload names audit_persisted only when false",
          "[mcp][dex][score_policy][pure]") {
    DexScorePolicyWriteResult r;
    r.status = St::Ok;
    r.in_force = dex_policy_in_force_from_stored(std::optional<std::string>(doc_with_excellent(95.0)));
    r.previous_revision = "default";

    const json ok = dex_score_policy_mcp_success_json(r, true);
    CHECK_FALSE(ok.contains("audit_persisted"));
    CHECK_FALSE(ok.contains("dry_run"));
    CHECK(ok["previous_revision"] == "default");
    CHECK(ok["revision"] == r.in_force.revision);
    CHECK(ok["source"] == "custom");

    const json dropped = dex_score_policy_mcp_success_json(r, false);
    CHECK(dropped["audit_persisted"] == false); // never `true`
    r.dry_run = true;
    CHECK(dex_score_policy_mcp_success_json(r, true)["dry_run"] == true);

    CHECK(dex_score_policy_mcp_remediation("GET /api/v1/dex/score-policy and send the revision")
              .find("get_dex_score_policy") != std::string::npos);
    CHECK(dex_score_policy_mcp_remediation("retry shortly") == "retry shortly");
}

// ───────────────────────── registration ─────────────────────────────────────────

TEST_CASE("dex score policy mcp: the three tools are served with their security rows, annotations "
          "and typed output schemas",
          "[mcp][dex][score_policy][registry_seam]") {
    Twin t;
    struct Row {
        const char* name;
        const char* securable;
        const char* operation;
        bool read_only;
    };
    const Row rows[] = {{"get_dex_score_policy", "GuaranteedState", "Read", true},
                        {"set_dex_score_policy", "Infrastructure", "Write", false},
                        {"reset_dex_score_policy", "Infrastructure", "Delete", false}};
    const auto sec = mcp::tool_security_rows_for_test();
    auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const json listed = json::parse(res->body);
    for (const auto& r : rows) {
        INFO(r.name);
        const auto it =
            std::find_if(sec.begin(), sec.end(), [&](const auto& s) { return s.name == r.name; });
        REQUIRE(it != sec.end());
        CHECK(it->securable == r.securable);
        CHECK(it->operation == r.operation);
        CHECK(it->service_scope == mcp::ServiceScopeClassForTest::kDenied);
        const json* tool = nullptr;
        for (const auto& e : listed["result"]["tools"])
            if (e["name"] == r.name)
                tool = &e;
        REQUIRE(tool != nullptr);
        CHECK((*tool)["annotations"]["readOnlyHint"] == r.read_only);
        CHECK((*tool)["annotations"]["destructiveHint"] == !r.read_only);
        CHECK((*tool)["annotations"]["idempotentHint"] == true);
        // A typed schema with the policy keys, never the free-form placeholder.
        const json& out = (*tool)["outputSchema"];
        CHECK(out["properties"].contains("document"));
        CHECK(out["properties"].contains("revision"));
        CHECK(out["properties"].contains("source"));
        CHECK(out["properties"].contains("audit_persisted") == !r.read_only);
    }
    // The write set holds set and reset only.
    const auto writes = mcp::write_tool_names_for_test();
    CHECK(std::count(writes.begin(), writes.end(), std::string("set_dex_score_policy")) == 1);
    CHECK(std::count(writes.begin(), writes.end(), std::string("reset_dex_score_policy")) == 1);
    CHECK(std::count(writes.begin(), writes.end(), std::string("get_dex_score_policy")) == 0);
    for (const auto& e : listed["result"]["tools"]) {
        if (e["name"] == "get_dex_score_policy") // the handler refuses any argument: say so
            CHECK(e["inputSchema"]["additionalProperties"] == false);
        if (e["name"] == "set_dex_score_policy") {
            CHECK(e["inputSchema"]["required"] == json::array({"document", "if_match"}));
            CHECK(e["inputSchema"]["additionalProperties"] == false);
        }
        if (e["name"] == "reset_dex_score_policy") {
            CHECK(e["inputSchema"]["required"] == json::array({"if_match"}));
            CHECK(e["inputSchema"]["properties"].contains("approval_id"));
        }
    }
}

// ───────────────────────── get_dex_score_policy ─────────────────────────────────

TEST_CASE("get_dex_score_policy: serves the stored policy byte-identically to the REST data, "
          "schema-valid, with the generic row and no domain row",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.stored = doc_with_excellent(95.0);
    const json r = t.call("get_dex_score_policy");
    REQUIRE_FALSE(r.contains("error"));
    const json& sc = r["result"]["structuredContent"];
    CHECK(sc == dex_score_policy_in_force_json(dex_policy_in_force_from_stored(t.stored)));
    CHECK(sc["source"] == "custom");
    CHECK(sc["revision"] == rev_of(*t.stored));
    CHECK(schema_violation(t.output_schema("get_dex_score_policy"), sc) == "");
    CHECK(audit_count(t.generic_rows, "mcp.get_dex_score_policy|success") == 1);
    CHECK(t.domain_rows.empty());
    REQUIRE(t.perm_calls.size() == 1);
    CHECK(t.perm_calls[0] == "GuaranteedState:Read");
}

TEST_CASE("get_dex_score_policy: nothing stored serves the defaults at revision 'default'",
          "[mcp][dex][score_policy]") {
    Twin t;
    const json r = t.call("get_dex_score_policy");
    REQUIRE_FALSE(r.contains("error"));
    const json& sc = r["result"]["structuredContent"];
    CHECK(sc["source"] == "default");
    CHECK(sc["revision"] == "default");
    CHECK(schema_violation(t.output_schema("get_dex_score_policy"), sc) == "");
}

TEST_CASE("get_dex_score_policy: invalid stored text serves the defaults with the fault and the "
          "revision of the text as stored",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.stored = R"({"version":3})"; // newer than this server reads: refused, never half-applied
    const json r = t.call("get_dex_score_policy");
    REQUIRE_FALSE(r.contains("error"));
    const json& sc = r["result"]["structuredContent"];
    CHECK(sc["source"] == "default");
    CHECK(sc["fault"] == "unsupported_version at version: 3 above the supported 2");
    CHECK(sc["revision"] == rev_of(*t.stored)); // the refused document's own revision, not 'default'
    CHECK(sc == dex_score_policy_in_force_json(dex_policy_in_force_from_stored(t.stored)));
    CHECK(schema_violation(t.output_schema("get_dex_score_policy"), sc) == "");
    CHECK(audit_count(t.generic_rows, "mcp.get_dex_score_policy|success") == 1);
    CHECK(t.domain_rows.empty());
}

TEST_CASE("get_dex_score_policy: any argument is refused, every tier reads, a refused gate and a "
          "failed read answer as documented",
          "[mcp][dex][score_policy]") {
    SECTION("an argument is refused before the read, with a denial row") {
        Twin t;
        const json r = t.call("get_dex_score_policy", {{"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().find("takes no arguments") != std::string::npos);
        check_a4_refusal(r, "correct the arguments and call again");
        CHECK(t.read_calls == 0);
        CHECK(audit_count(t.generic_rows, "mcp.get_dex_score_policy|denied") == 1);
    }
    SECTION("a dropped denial row is reported in the refusal's envelope") {
        Twin t;
        t.generic_audit_ok = false;
        const json r = t.call("get_dex_score_policy", {{"if_match", "default"}});
        check_a4_refusal(r, "correct the arguments and call again", /*audit_persisted=*/false);
        CHECK(t.read_calls == 0);
    }
    SECTION("the readonly and operator tiers are admitted") {
        for (const char* tier : {"readonly", "operator"}) {
            INFO(tier);
            Twin t;
            t.tier = tier;
            CHECK_FALSE(t.call("get_dex_score_policy").contains("error"));
        }
    }
    SECTION("a gate refusal is the gate's own body and reads nothing") {
        Twin t;
        t.perm_deny = "GuaranteedState:Read";
        auto res = t.post(R"({"jsonrpc":"2.0","method":"tools/call","id":7,)"
                          R"("params":{"name":"get_dex_score_policy","arguments":{}}})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(t.read_calls == 0);
    }
    SECTION("an unreadable store is retryable with the store's retry hint, never the defaults") {
        Twin t;
        t.read_fails = true;
        const json r = t.call("get_dex_score_policy");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        CHECK(audit_count(t.generic_rows, "mcp.get_dex_score_policy|failure") == 1);
        CHECK_FALSE(r["error"]["data"].contains("audit_persisted"));
    }
    SECTION("an unreadable store with a dropped failure row reports the drop") {
        Twin t;
        t.read_fails = true;
        t.generic_audit_ok = false;
        const json r = t.call("get_dex_score_policy");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
    }
    SECTION("an unwired read closure is a non-retryable internal error with a failure row") {
        Twin::Opts o;
        o.wire_read = false;
        Twin t(o);
        const json r = t.call("get_dex_score_policy");
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(audit_count(t.generic_rows, "mcp.get_dex_score_policy|failure") == 1);
    }
}

// ───────────────────────── set_dex_score_policy ─────────────────────────────────

TEST_CASE("set_dex_score_policy: a supervised token stores the canonical text, audits attempted "
          "then success before the generic row, and gates Write then Read",
          "[mcp][dex][score_policy]") {
    Twin t;
    const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
    REQUIRE_FALSE(r.contains("error"));
    CHECK(t.cas_calls == 1);
    REQUIRE(t.stored.has_value());
    CHECK(*t.stored == doc_with_excellent(95.0));
    const json& sc = r["result"]["structuredContent"];
    CHECK(schema_violation(t.output_schema("set_dex_score_policy"), sc) == "");
    CHECK(sc["previous_revision"] == "default");
    CHECK(sc["revision"] == rev_of(*t.stored));
    CHECK_FALSE(sc.contains("audit_persisted"));
    CHECK_FALSE(sc.contains("dry_run"));
    REQUIRE(t.domain_rows.size() == 2);
    CHECK(t.domain_rows[0] == kAttemptedUpdate);
    CHECK(t.domain_rows[1] == kSuccessUpdate);
    CHECK(audit_count(t.generic_rows, "mcp.set_dex_score_policy|success") == 1);
    // The tier gate is the generic one; the handler repeats the loud pair, then the Read gate.
    REQUIRE(t.perm_calls.size() >= 2);
    CHECK(t.perm_calls[t.perm_calls.size() - 2] == "Infrastructure:Write");
    CHECK(t.perm_calls[t.perm_calls.size() - 1] == "GuaranteedState:Read");
}

TEST_CASE("set_dex_score_policy: dry_run validates, audits one validate row and stores nothing",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.stored = doc_with_excellent(80.0);
    json args = set_args(95.0, rev_of(*t.stored));
    args["dry_run"] = true;
    const json r = t.call("set_dex_score_policy", args);
    REQUIRE_FALSE(r.contains("error"));
    CHECK(t.cas_calls == 0);
    CHECK(*t.stored == doc_with_excellent(80.0));
    const json& sc = r["result"]["structuredContent"];
    CHECK(sc["dry_run"] == true);
    CHECK(sc["previous_revision"] == rev_of(*t.stored));
    CHECK(sc["revision"] == rev_of(doc_with_excellent(95.0)));
    CHECK(schema_violation(t.output_schema("set_dex_score_policy"), sc) == "");
    REQUIRE(t.domain_rows.size() == 1);
    CHECK(t.domain_rows[0] == "dex.score_policy.validate|success|RuntimeConfig|dex_score_policy");
}

TEST_CASE("set_dex_score_policy: caller refusals are non-retryable invalid-params errors with a "
          "denied row and no store write",
          "[mcp][dex][score_policy]") {
    SECTION("a missing If-Match") {
        Twin t;
        const json r = t.call("set_dex_score_policy", {{"document", doc_json(95.0)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().starts_with("If-Match"));
        CHECK(r["error"]["data"]["remediation"].get<std::string>().find("get_dex_score_policy") !=
              std::string::npos);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(audit_count(t.domain_rows, "dex.score_policy.update|denied|RuntimeConfig|dex_score_policy") == 1);
        CHECK(t.cas_calls == 0);
    }
    SECTION("a stale If-Match names the stored revision") {
        Twin t;
        t.stored = doc_with_excellent(80.0);
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().find(rev_of(*t.stored)) != std::string::npos);
        CHECK(t.cas_calls == 0);
    }
    SECTION("an invalid document names the field") {
        Twin t;
        const json r = t.call("set_dex_score_policy",
                              {{"document", {{"version", 3}}}, {"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().find("version") != std::string::npos);
        CHECK(t.cas_calls == 0);
    }
    SECTION("a string dry_run is refused before apply: only the generic denied row") {
        Twin t;
        json args = set_args(95.0, "default");
        args["dry_run"] = "true";
        const json r = t.call("set_dex_score_policy", args);
        check_a4_refusal(r, "correct the arguments and call again");
        CHECK(t.domain_rows.empty());
        CHECK(audit_count(t.generic_rows, "mcp.set_dex_score_policy|denied") == 1);
    }
    SECTION("an unknown argument and a non-object document") {
        Twin t;
        json args = set_args(95.0, "default");
        args["bogus"] = 1;
        check_a4_refusal(t.call("set_dex_score_policy", args), "correct the arguments and call again");
        check_a4_refusal(t.call("set_dex_score_policy", {{"document", "x"}, {"if_match", "default"}}),
                         "correct the arguments and call again");
        CHECK(t.domain_rows.empty());
        CHECK(t.cas_calls == 0);
    }
    SECTION("a dropped denial row is reported in the refusal's envelope") {
        Twin t;
        t.generic_audit_ok = false;
        json args = set_args(95.0, "default");
        args["bogus"] = 1;
        check_a4_refusal(t.call("set_dex_score_policy", args), "correct the arguments and call again",
                         /*audit_persisted=*/false);
        CHECK(t.cas_calls == 0);
    }
}

TEST_CASE("set_dex_score_policy: the generic tier gate refuses readonly and operator tokens and a "
          "service-scoped token before the handler",
          "[mcp][dex][score_policy][security]") {
    for (const char* tier : {"readonly", "operator"}) {
        INFO(tier);
        Twin t;
        t.tier = tier;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kTierDenied);
        CHECK(t.domain_rows.empty());
        CHECK(t.cas_calls == 0);
        const json rr = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE(rr.contains("error"));
        CHECK(rr["error"]["code"] == mcp::kTierDenied);
        CHECK(t.car_calls == 0);
    }
    Twin t;
    t.scope_service = "printers";
    for (const char* tool : {"get_dex_score_policy", "set_dex_score_policy", "reset_dex_score_policy"}) {
        INFO(tool);
        const json r = t.call(tool, std::string(tool) == "get_dex_score_policy"
                                        ? json::object()
                                        : json{{"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kPermissionDenied);
    }
    CHECK(t.domain_rows.empty());
    CHECK(t.read_calls == 0);
}

TEST_CASE("set_dex_score_policy: each loud RBAC gate refuses with its own body and writes nothing",
          "[mcp][dex][score_policy][security]") {
    for (const char* denied : {"Infrastructure:Write", "GuaranteedState:Read"}) {
        INFO(denied);
        Twin t;
        t.perm_deny = denied;
        auto res = t.post(
            json{{"jsonrpc", "2.0"}, {"method", "tools/call"}, {"id", 7},
                 {"params", {{"name", "set_dex_score_policy"},
                             {"arguments", set_args(95.0, "default")}}}}
                .dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(t.domain_rows.empty());
        CHECK(t.cas_calls == 0);
    }
}

TEST_CASE("set_dex_score_policy: no audit row, no mutation", "[mcp][dex][score_policy][security]") {
    SECTION("a sink that refuses the attempted row: retryable with the audit hint, nothing stored") {
        Twin t;
        t.domain_fail_result = "attempted";
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyAuditRetryMs);
        CHECK(t.cas_calls == 0);
        CHECK_FALSE(t.stored.has_value());
    }
    SECTION("a throwing sink is caught and fails the write closed") {
        Twin t;
        t.domain_audit_throws = true;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(t.cas_calls == 0);
    }
    SECTION("an unwired audit sink, apply closure or username resolver is refused, nothing stored") {
        for (int which = 0; which < 3; ++which) {
            INFO(which);
            Twin::Opts o;
            o.wire_audit = which != 0;
            o.wire_apply = which != 1;
            o.wire_username = which != 2;
            Twin t(o);
            const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
            CHECK(r["error"]["data"]["remediation"].is_null()); // set spends no ticket
            CHECK(t.cas_calls == 0);
            CHECK_FALSE(t.stored.has_value());
            CHECK(audit_count(t.generic_rows, "mcp.set_dex_score_policy|failure") == 1);
        }
    }
}

TEST_CASE("set_dex_score_policy: a dropped audit row after the change is reported, not hidden",
          "[mcp][dex][score_policy]") {
    SECTION("a sink that accepts attempted but refuses success: the write stands, audit_persisted false") {
        Twin t;
        t.domain_fail_result = "success";
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.cas_calls == 1);
        const json& sc = r["result"]["structuredContent"];
        CHECK(sc["audit_persisted"] == false);
        CHECK(schema_violation(t.output_schema("set_dex_score_policy"), sc) == "");
    }
    SECTION("a refused denied row on a refusal reaches the A4 envelope's audit flag") {
        Twin t;
        t.domain_fail_result = "denied";
        const json r = t.call("set_dex_score_policy", {{"document", doc_json(95.0)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
        CHECK(t.cas_calls == 0);
    }
    SECTION("a sink that accepts everything leaves no audit_persisted key anywhere") {
        Twin t;
        const json ok = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE_FALSE(ok.contains("error"));
        CHECK_FALSE(ok["result"]["structuredContent"].contains("audit_persisted"));
        const json refused = t.call("set_dex_score_policy", {{"document", doc_json(95.0)}});
        REQUIRE(refused.contains("error"));
        CHECK_FALSE(refused["error"]["data"].contains("audit_persisted"));
    }
}

TEST_CASE("set_dex_score_policy: store faults are retryable; the outcome after a store error is "
          "judged by a re-read",
          "[mcp][dex][score_policy]") {
    SECTION("an unreadable store") {
        Twin t;
        t.read_fails = true;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        CHECK(t.cas_calls == 0);
    }
    SECTION("the store errors after writing the intended text: success, recorded as observed") {
        Twin t;
        t.cas_after_error = Twin::AfterError::intended;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["revision"] == rev_of(doc_with_excellent(95.0)));
        bool observed = false;
        for (const auto& d : t.domain_details)
            observed = observed || d.find("observed_after_store_error") != std::string::npos;
        CHECK(observed);
    }
    SECTION("the store errors with a different document in place: outcome unknown, retryable") {
        Twin t;
        t.cas_after_error = Twin::AfterError::other;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        const std::string rem = r["error"]["data"]["remediation"].get<std::string>();
        CHECK(rem.find("compare its revision") != std::string::npos);
        CHECK(rem.find("get_dex_score_policy") != std::string::npos);
    }
}

TEST_CASE("set_dex_score_policy: a second writer in this process is told to retry, through the "
          "adapter",
          "[mcp][dex][score_policy]") {
    Twin t;
    // The first write parks inside its commit holding the provider's writer lock. It runs on its
    // own deps and sink, sharing with the Twin only the provider and the stored text (read, not
    // written, until it is released), so the two calls touch no common mutable state.
    std::promise<void> entered_p;
    std::promise<void> release_p;
    auto entered = entered_p.get_future();
    const auto gate = release_p.get_future().share();
    DexScorePolicyWriteDeps d1;
    d1.read_stored = [&t]() -> std::expected<std::optional<std::string>, std::string> {
        return t.stored;
    };
    d1.compare_and_set = [&](const std::optional<std::string>&, const std::string&,
                             const std::string&) -> std::expected<bool, std::string> {
        entered_p.set_value();
        gate.wait();
        return true;
    };
    d1.compare_and_remove = [](const std::string&) -> std::expected<bool, std::string> {
        return true;
    };
    d1.provider = t.provider;
    d1.audit = [](std::string_view, std::string_view, const std::string&) { return true; };
    DexScorePolicyWriteRequest rq1;
    rq1.if_match = "default";
    rq1.body = doc_with_excellent(95.0);
    rq1.actor = "first";
    std::optional<DexScorePolicyWriteResult> first;
    std::thread parked([&] { first = apply_dex_score_policy(rq1, d1); });
    // Bounded: a first write that never reaches its commit fails the case instead of hanging it.
    if (entered.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
        release_p.set_value();
        parked.join();
        FAIL("the first write never reached its commit");
    }
    const json r = t.call("set_dex_score_policy", set_args(96.0, "default"));
    release_p.set_value();
    parked.join();

    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
    CHECK(t.cas_calls == 0); // this call's commit never ran
    CHECK_FALSE(t.stored.has_value());
    REQUIRE(t.domain_rows.size() == 2);
    CHECK(t.domain_rows[0] == kAttemptedUpdate);
    CHECK(t.domain_rows[1] == "dex.score_policy.update|failure|RuntimeConfig|dex_score_policy");
    CHECK(audit_count(t.generic_rows, "mcp.set_dex_score_policy|failure") == 1);
    REQUIRE(first);
    CHECK(first->status == St::Ok);
}

TEST_CASE("set_dex_score_policy: a dropped generic mcp.<tool> row is reported on the success body "
          "and on the error envelope, on every write",
          "[mcp][dex][score_policy]") {
    SECTION("a set: the write stands, audit_persisted false, both domain rows written") {
        Twin t;
        t.generic_audit_ok = false;
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.cas_calls == 1);
        const json& sc = r["result"]["structuredContent"];
        CHECK(sc["audit_persisted"] == false);
        CHECK(schema_violation(t.output_schema("set_dex_score_policy"), sc) == "");
        CHECK(t.domain_rows.size() == 2);
    }
    SECTION("a dry run") {
        Twin t;
        t.generic_audit_ok = false;
        json args = set_args(95.0, "default");
        args["dry_run"] = true;
        const json r = t.call("set_dex_score_policy", args);
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["dry_run"] == true);
        CHECK(r["result"]["structuredContent"]["audit_persisted"] == false);
    }
    SECTION("a refused set reaches the A4 envelope's audit flag") {
        Twin t;
        t.generic_audit_ok = false;
        const json r = t.call("set_dex_score_policy", {{"document", doc_json(95.0)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
        CHECK(t.cas_calls == 0);
    }
    SECTION("a reset") {
        Twin t;
        t.tier = ""; // not ticket-gated: the body is under test, the round trip is below
        t.generic_audit_ok = false;
        t.stored = doc_with_excellent(80.0);
        const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.car_calls == 1);
        CHECK(r["result"]["structuredContent"]["audit_persisted"] == false);
    }
}

TEST_CASE("set_dex_score_policy: resending the same document with the current revision is a second "
          "success that stores the same policy",
          "[mcp][dex][score_policy]") {
    Twin t;
    const json first = t.call("set_dex_score_policy", set_args(95.0, "default"));
    REQUIRE_FALSE(first.contains("error"));
    const std::string rev = first["result"]["structuredContent"]["revision"];
    const json again = t.call("set_dex_score_policy", set_args(95.0, rev));
    REQUIRE_FALSE(again.contains("error"));
    const json& sc = again["result"]["structuredContent"];
    CHECK(sc["revision"] == rev);
    CHECK(sc["previous_revision"] == rev);
    CHECK(schema_violation(t.output_schema("set_dex_score_policy"), sc) == "");
    CHECK(t.cas_calls == 2);
    REQUIRE(t.stored.has_value());
    CHECK(*t.stored == doc_with_excellent(95.0));
    CHECK(audit_count(t.domain_rows, kAttemptedUpdate) == 2);
    CHECK(audit_count(t.domain_rows, kSuccessUpdate) == 2);
}

// ───────────────────────── reset_dex_score_policy ───────────────────────────────

TEST_CASE("reset_dex_score_policy: removes the stored text with attempted then success rows; "
          "a never-written policy is attempted then no_change",
          "[mcp][dex][score_policy]") {
    // The empty tier is a non-ticket session (tier_allows / requires_approval defer), so the
    // body cases run without an approval manager; the ticket round trip is below.
    SECTION("a stored policy") {
        Twin t;
        t.tier = "";
        t.stored = doc_with_excellent(80.0);
        const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.car_calls == 1);
        CHECK_FALSE(t.stored.has_value());
        const json& sc = r["result"]["structuredContent"];
        CHECK(sc["source"] == "default");
        CHECK(sc["revision"] == "default");
        CHECK(sc["previous_revision"] == rev_of(doc_with_excellent(80.0)));
        CHECK(schema_violation(t.output_schema("reset_dex_score_policy"), sc) == "");
        REQUIRE(t.domain_rows.size() == 2);
        CHECK(t.domain_rows[0] == kAttemptedReset);
        CHECK(t.domain_rows[1] == "dex.score_policy.reset|success|RuntimeConfig|dex_score_policy");
        REQUIRE(t.perm_calls.size() >= 2);
        CHECK(t.perm_calls[t.perm_calls.size() - 2] == "Infrastructure:Delete");
        CHECK(t.perm_calls[t.perm_calls.size() - 1] == "GuaranteedState:Read");
    }
    SECTION("a never-written policy") {
        Twin t;
        t.tier = "";
        const json r = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.car_calls == 0);
        CHECK(r["result"]["structuredContent"]["source"] == "default");
        REQUIRE(t.domain_rows.size() == 2);
        CHECK(t.domain_rows[0] == kAttemptedReset);
        CHECK(t.domain_rows[1] == "dex.score_policy.reset|no_change|RuntimeConfig|dex_score_policy");
    }
    SECTION("a no_change row the sink drops is reported") {
        Twin t;
        t.tier = "";
        t.domain_fail_result = "no_change";
        const json r = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE_FALSE(r.contains("error"));
        CHECK(r["result"]["structuredContent"]["audit_persisted"] == false);
    }
}

TEST_CASE("reset_dex_score_policy: dry_run and any other argument are refused; refusals carry the "
          "spent-ticket recovery",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.tier = "";
    const json dry = t.call("reset_dex_score_policy", {{"if_match", "default"}, {"dry_run", true}});
    REQUIRE(dry.contains("error"));
    CHECK(dry["error"]["message"].get<std::string>().find("unknown argument") != std::string::npos);
    check_a4_refusal(dry, "correct the arguments and call again");
    // The parse refusal is a post-consumption refusal like any other: it carries the recovery.
    check_a4_refusal(dry, "fresh ticket");
    CHECK(t.domain_rows.empty());

    t.stored = doc_with_excellent(80.0);
    const json stale = t.call("reset_dex_score_policy", {{"if_match", "default"}});
    REQUIRE(stale.contains("error"));
    CHECK(stale["error"]["code"] == mcp::kInvalidParams);
    CHECK(stale["error"]["data"]["remediation"].get<std::string>().find("fresh ticket") !=
          std::string::npos);
    CHECK(t.car_calls == 0);
}

TEST_CASE("reset_dex_score_policy: a store error after the remove with another document in place "
          "is retryable and names the recovery",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.tier = "";
    t.stored = doc_with_excellent(80.0);
    t.car_after_error = Twin::AfterError::other;
    const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
    const std::string rem = r["error"]["data"]["remediation"].get<std::string>();
    CHECK(rem.find("get_dex_score_policy") != std::string::npos);
    CHECK(rem.find("compare its revision") != std::string::npos);
    CHECK(rem.find("without approval_id") != std::string::npos);
}

TEST_CASE("reset_dex_score_policy: a sink that refuses the attempted row removes nothing, is "
          "retryable with the audit hint and names the ticket recovery",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.tier = "";
    t.stored = doc_with_excellent(80.0);
    t.domain_fail_result = "attempted";
    const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kInternalError);
    CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyAuditRetryMs);
    const std::string rem = r["error"]["data"]["remediation"].get<std::string>();
    CHECK(rem.find("retry the request") != std::string::npos); // apply's own remediation first
    CHECK(rem.find("fresh ticket") != std::string::npos);
    CHECK(rem.find("without approval_id") != std::string::npos);
    CHECK(t.car_calls == 0);
    CHECK(t.stored.has_value());
    CHECK(audit_count(t.generic_rows, "mcp.reset_dex_score_policy|failure") == 1);
}

TEST_CASE("reset_dex_score_policy: at the supervised tier it is approval-gated, and without an "
          "approval manager the gate denies honestly before any write",
          "[mcp][dex][score_policy][security]") {
    Twin t; // supervised
    t.stored = doc_with_excellent(80.0);
    const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
    REQUIRE(r.contains("error"));
    CHECK(r["error"]["code"] == mcp::kTierDenied);
    CHECK_FALSE(r["error"]["data"].contains("approval_id"));
    CHECK(t.car_calls == 0);
    CHECK(t.stored.has_value());
    CHECK(t.domain_rows.empty());
}

TEST_CASE("reset_dex_score_policy: the approval ticket round trip, and a spent ticket recovers "
          "through a fresh request",
          "[mcp][dex][score_policy][pg]") {
    yuzu::test::ApprovalManagerPg appr_bundle; // SKIPs without YUZU_TEST_POSTGRES_DSN
    yuzu::server::ApprovalManager& appr = *appr_bundle;
    Twin::Opts o;
    o.approval = &appr;
    Twin t(o);
    t.stored = doc_with_excellent(80.0);
    const json args = {{"if_match", rev_of(*t.stored)}};

    auto mint = [&]() {
        const json r = t.call("reset_dex_score_policy", args);
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kApprovalRequired);
        const std::string id = r["error"]["data"]["approval_id"].get<std::string>();
        REQUIRE(appr.approve(id, "reviewer-bob", ""));
        return id;
    };

    SECTION("the first call mints a ticket and removes nothing; the repeat with it resets") {
        const std::string id = mint();
        CHECK(t.car_calls == 0);
        CHECK(t.domain_rows.empty());
        json again = args;
        again["approval_id"] = id;
        const json r = t.call("reset_dex_score_policy", again);
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.car_calls == 1);
        CHECK_FALSE(t.stored.has_value());
        REQUIRE(t.domain_rows.size() == 2);
        CHECK(t.domain_rows[0] == kAttemptedReset);
        CHECK(t.domain_rows[1] == "dex.score_policy.reset|success|RuntimeConfig|dex_score_policy");
    }
    SECTION("a retryable failure after approval spends the ticket; a repeat is refused, a fresh "
            "request recovers") {
        const std::string id = mint();
        t.car_after_error = Twin::AfterError::other;
        json again = args;
        again["approval_id"] = id;
        const json failed = t.call("reset_dex_score_policy", again);
        REQUIRE(failed.contains("error"));
        CHECK(failed["error"]["code"] == mcp::kInternalError);
        const std::string rem = failed["error"]["data"]["remediation"].get<std::string>();
        CHECK(rem.find("get_dex_score_policy") != std::string::npos);
        CHECK(rem.find("without approval_id") != std::string::npos);

        // The same approval_id is spent: refused by the gate before the handler.
        t.clear_audit();
        const int car_before = t.car_calls;
        const json replay = t.call("reset_dex_score_policy", again);
        REQUIRE(replay.contains("error"));
        CHECK(replay["error"]["code"] == mcp::kPermissionDenied);
        CHECK(t.car_calls == car_before);
        CHECK(t.domain_rows.empty());

        // Reconcile (the other document is in place), then a new request mints a new ticket.
        t.car_after_error = Twin::AfterError::none;
        const json read = t.call("get_dex_score_policy");
        REQUIRE_FALSE(read.contains("error"));
        const std::string current = read["result"]["structuredContent"]["revision"];
        const json fresh_args = {{"if_match", current}};
        const json r2 = t.call("reset_dex_score_policy", fresh_args);
        REQUIRE(r2.contains("error"));
        CHECK(r2["error"]["code"] == mcp::kApprovalRequired);
        const std::string id2 = r2["error"]["data"]["approval_id"].get<std::string>();
        CHECK(id2 != id);
        REQUIRE(appr.approve(id2, "reviewer-bob", ""));
        json redeem = fresh_args;
        redeem["approval_id"] = id2;
        const int car_calls_before = t.car_calls;
        const json done = t.call("reset_dex_score_policy", redeem);
        REQUIRE_FALSE(done.contains("error"));
        CHECK(t.car_calls == car_calls_before + 1);
        CHECK_FALSE(t.stored.has_value());
    }
}

// ───────────────────────── dispatch chain, unwired ──────────────────────────────

TEST_CASE("dex score policy mcp: a non-object `arguments` is refused by the dispatch chain before "
          "the handler, with a denial row",
          "[mcp][dex][score_policy][registry_seam]") {
    Twin t;
    t.tier = ""; // reset is then not ticket-gated, so it reaches the registry's central check
    for (const char* tool : {"get_dex_score_policy", "set_dex_score_policy", "reset_dex_score_policy"})
        for (const json& args : {json::array(), json("x"), json(3), json(nullptr)}) {
            INFO(tool << " " << args.dump());
            t.clear_audit();
            const json r = t.call(tool, args);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            CHECK(audit_count(t.generic_rows, std::string("mcp.") + tool + "|denied") == 1);
            CHECK(t.domain_rows.empty());
            CHECK(t.perm_calls.empty());
        }
    CHECK(t.cas_calls == 0);
    CHECK(t.car_calls == 0);
}

TEST_CASE("reset_dex_score_policy: an unwired apply closure, audit sink or username resolver is "
          "refused with nothing removed",
          "[mcp][dex][score_policy]") {
    for (int which = 0; which < 3; ++which) {
        INFO(which);
        Twin::Opts o;
        o.wire_audit = which != 0;
        o.wire_apply = which != 1;
        o.wire_username = which != 2;
        Twin t(o);
        t.tier = "";
        t.stored = doc_with_excellent(80.0);
        const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        // The approval ticket was consumed before the handler ran, so this refusal spent it:
        // the recovery is carried even though the policy was never touched.
        const std::string rem = r["error"]["data"]["remediation"].get<std::string>();
        CHECK(rem.find("spent") != std::string::npos);
        CHECK(rem.find("without approval_id") != std::string::npos);
        CHECK(rem.find("fresh ticket") != std::string::npos);
        CHECK(audit_count(t.generic_rows, "mcp.reset_dex_score_policy|failure") == 1);
        CHECK(t.car_calls == 0);
        CHECK(t.stored.has_value());
    }
}
