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

#include "../test_helpers.hpp" // ScopeExit

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
    std::vector<std::string> cas_actors; // the `updated_by` each compare-and-set was handed
    bool clock_throws = false;           // the provider's clock fails (an install after the commit)
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
    std::vector<std::string> domain_principals; // parallel: the session each row was stamped from
    std::vector<std::string> domain_roles;      // parallel: the effective role captured once
    // The session resolver counts its calls; when set it resolves NO ONE after the first call (a
    // credential that lapsed mid-request).
    int session_calls = 0;
    bool session_lapses_after_first = false;
    bool session_unresolved = false; // the caller resolves to no session at all
    // The base role the resolved session carries, and whether a live JIT elevation (an hour from
    // now, so it cannot lapse mid-test) sits on top: an elevated `user` session's effective role
    // is `admin`, an unelevated one's is `user`.
    auth::Role session_role = auth::Role::admin;
    bool session_elevated = false;
    // The per-row resolvers the write tools must NOT use for domain rows: ToolDeps::audit_fn and
    // ToolDeps::username_fn. Both are wired as traps (a row written through audit_fn lands here;
    // username_fn names someone else).
    std::vector<std::string> legacy_rows;
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
        bool wire_audit = true;   // the session-bound audit writer (audit_as_session_fn)
        bool wire_session = true; // the session resolver (session_fn)
        yuzu::server::ApprovalManager* approval = nullptr;
    };

    Twin() : Twin(Opts{}) {}
    explicit Twin(Opts o) {
        provider = std::make_shared<DexScorePolicyProvider>(
            [this]() -> std::expected<std::optional<std::string>, std::string> { return stored; },
            [this] {
                if (clock_throws)
                    throw std::runtime_error("clock failed");
                return std::int64_t{1'000'000};
            },
            std::chrono::milliseconds{1});

        DexScorePolicyWriteDeps d;
        d.read_stored = [this]() -> std::expected<std::optional<std::string>, std::string> {
            ++read_calls;
            if (read_fails)
                return std::unexpected(std::string("store down"));
            return stored;
        };
        d.compare_and_set = [this](const std::optional<std::string>& expected,
                                   const std::string& canonical,
                                   const std::string& actor) -> std::expected<bool, std::string> {
            ++cas_calls;
            cas_actors.push_back(actor);
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
        // The session-bound writer: the only path the domain rows may take. It records the
        // session it was handed, so a test asserts WHO each row was stamped as.
        if (o.wire_audit)
            td.audit_as_session_fn =
                [this](const httplib::Request&, const auth::Session& session,
                       const std::string& role, const std::string& action,
                       const std::string& result, const std::string& target_type,
                       const std::string& target_id, const std::string& detail) -> bool {
                domain_rows.push_back(action + "|" + result + "|" + target_type + "|" + target_id);
                domain_details.push_back(detail);
                domain_principals.push_back(session.username);
                domain_roles.push_back(role);
                if (domain_audit_throws)
                    throw std::runtime_error("audit sink blew up");
                if (!domain_fail_result.empty())
                    return result != domain_fail_result;
                return domain_audit_ok;
            };
        if (o.wire_session)
            td.session_fn = [this](const httplib::Request&) -> std::optional<auth::Session> {
                ++session_calls;
                if (session_unresolved || (session_lapses_after_first && session_calls > 1))
                    return std::nullopt;
                auth::Session s;
                s.username = username;
                s.role = session_role;
                if (session_elevated) {
                    // The pair is_elevated() accepts: a steady deadline plus the absolute
                    // authored instant.
                    s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
                    s.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
                }
                return s;
            };
        // Traps: the per-row re-resolving sink and username resolver the write tools used to
        // call. Neither may be reached by a domain row.
        td.audit_fn = [this](const httplib::Request&, const std::string& action,
                             const std::string& result, const std::string&, const std::string&,
                             const std::string&) -> bool {
            legacy_rows.push_back(action + "|" + result);
            return true;
        };
        td.username_fn = [](const httplib::Request&) -> std::optional<std::string> {
            return std::string("intruder");
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
        domain_principals.clear();
        domain_roles.clear();
        generic_rows.clear();
        legacy_rows.clear();
    }

    /// Every domain row was stamped from the one session this write resolved, with the
    /// effective role captured once (`role`: "admin" for the default admin session), and none
    /// went through the per-row resolving sink.
    void check_rows_stamped_as_session(const std::string& role = "admin") const {
        CHECK_FALSE(domain_rows.empty());
        for (const auto& p : domain_principals)
            CHECK(p == username);
        for (const auto& r : domain_roles)
            CHECK(r == role);
        CHECK(domain_principals.size() == domain_rows.size());
        CHECK(domain_roles.size() == domain_rows.size());
        CHECK(legacy_rows.empty());
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
    SECTION("the if_match cap is 64 bytes inclusive; apply judges what the builder lets through") {
        const json doc = doc_json(95.0);
        const auto at_cap = dex_score_policy_mcp_request(
            Op::Put, {{"document", doc}, {"if_match", std::string(64, 'a')}});
        REQUIRE(at_cap);
        CHECK(at_cap->if_match == std::optional<std::string>(std::string(64, 'a')));
        CHECK_FALSE(dex_score_policy_mcp_request(
            Op::Put, {{"document", doc}, {"if_match", std::string(65, 'a')}}));
    }
    SECTION("an unknown key cut inside a multibyte character stays valid UTF-8") {
        // 64 bytes of key survive the cap. Put a 2-, 3- and 4-byte character so that the cap cuts
        // between its bytes at every interior position (log_token neutralises each stray byte,
        // and each truncated lead byte is a distinct shape of utf8_sequence_length returning 0).
        // The message must still be valid UTF-8 (json::dump refuses a string that is not), still
        // the unknown-argument refusal, and must not echo the stray lead byte.
        struct Shape {
            const char* name;
            std::string ch;
        };
        const Shape shapes[] = {{"2-byte U+00E9", "\xC3\xA9"},
                                {"3-byte U+20AC", "\xE2\x82\xAC"},
                                {"4-byte U+1F600", "\xF0\x9F\x98\x80"}};
        for (const auto& shape : shapes) {
            for (std::size_t kept = 1; kept < shape.ch.size(); ++kept) {
                INFO(shape.name << " cut after " << kept << " byte(s)");
                const std::string key = std::string(64 - kept, 'k') + shape.ch + "b";
                const auto rq = dex_score_policy_mcp_request(Op::Reset, json::object({{key, 1}}));
                REQUIRE_FALSE(rq);
                CHECK(rq.error().starts_with("unknown argument '"));
                CHECK_NOTHROW(json(rq.error()).dump());
                // The stray lead byte is neutralised, not echoed.
                CHECK(rq.error().find(shape.ch[0]) == std::string::npos);
            }
            // A whole character inside the cap passes through unchanged.
            const std::string whole = "caf" + shape.ch;
            INFO(shape.name << " whole inside the cap");
            const auto kept = dex_score_policy_mcp_request(Op::Reset, json::object({{whole, 1}}));
            REQUIRE_FALSE(kept);
            CHECK(kept.error() == "unknown argument '" + whole + "'");
        }
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

    // apply words its If-Match refusals for the REST header; over MCP the value is an argument.
    CHECK(dex_score_policy_mcp_message("If-Match header required: send the revision") ==
          "If-Match (the if_match argument) required: send the revision");
    CHECK(dex_score_policy_mcp_message("If-Match must not be empty") ==
          "If-Match (the if_match argument) must not be empty");
    CHECK(dex_score_policy_mcp_message("If-Match: send exactly one revision") ==
          "If-Match (the if_match argument): send exactly one revision");
    CHECK(dex_score_policy_mcp_message("the stored policy's revision is abc") ==
          "the stored policy's revision is abc");
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
        const std::string desc = e.value("description", "");
        if (e["name"] == "get_dex_score_policy") {
            // Where else the stored text is listed, and what a fault means for a read-edit-set.
            CHECK(desc.find("get_runtime_config") != std::string::npos);
            CHECK(desc.find("NOT your stored policy") != std::string::npos);
        }
        if (e["name"] == "set_dex_score_policy") {
            CHECK(desc.find("rolling upgrade") != std::string::npos);
        }
        if (e["name"] == "reset_dex_score_policy") {
            CHECK(desc.find("gates this MCP tool, not the capability") != std::string::npos);
            CHECK(desc.find("NEW request (no approval_id)") != std::string::npos);
            // The schema refuses a missing if_match before any ticket exists: never "spends" one.
            CHECK(desc.find("stale or missing if_match") == std::string::npos);
            // The if_match schema mirrors what the writer accepts, so a malformed value is
            // refused before the approval ticket is created or consumed.
            CHECK(e["inputSchema"]["properties"]["if_match"]["pattern"] ==
                  "^(default|[0-9a-f]{16})$");
        }
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
    // Attribution: `updated_by` and every domain row come from the ONE session resolved for
    // this write; the per-row resolving sink was never reached.
    REQUIRE(t.cas_actors.size() == 1);
    CHECK(t.cas_actors[0] == "tester");
    CHECK(t.session_calls == 1);
    t.check_rows_stamped_as_session();
    // The policy is installed on this instance, not just stored.
    const auto in_force = t.provider->current();
    REQUIRE(in_force);
    CHECK(in_force->source == "custom");
    CHECK(in_force->revision == rev_of(*t.stored));
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

TEST_CASE("set and reset: every domain row and updated_by come from the session resolved once, "
          "even when the caller no longer resolves mid-request",
          "[mcp][dex][score_policy][security]") {
    SECTION("a set") {
        Twin t;
        t.session_lapses_after_first = true; // any SECOND resolution names no one
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.session_calls == 1);
        REQUIRE(t.cas_actors.size() == 1);
        CHECK(t.cas_actors[0] == "tester");
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session();
    }
    SECTION("a dry run and a refusal") {
        Twin t;
        t.session_lapses_after_first = true;
        json args = set_args(95.0, "default");
        args["dry_run"] = true;
        REQUIRE_FALSE(t.call("set_dex_score_policy", args).contains("error"));
        REQUIRE(t.domain_rows.size() == 1);
        t.check_rows_stamped_as_session();
        t.clear_audit();
        t.session_calls = 0;
        REQUIRE(t.call("set_dex_score_policy", {{"document", doc_json(95.0)}}).contains("error"));
        REQUIRE(t.domain_rows.size() == 1); // the denied row
        t.check_rows_stamped_as_session();
    }
    SECTION("a reset") {
        Twin t;
        t.tier = ""; // not ticket-gated: the body is under test, the round trip is below
        t.session_lapses_after_first = true;
        t.stored = doc_with_excellent(80.0);
        REQUIRE_FALSE(
            t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}}).contains("error"));
        CHECK(t.session_calls == 1);
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session();
        const auto in_force = t.provider->current();
        REQUIRE(in_force);
        CHECK(in_force->source == "default"); // the reset is installed, not just stored
    }
    SECTION("a caller that resolves to no session is refused before any row, on both writes") {
        Twin t;
        t.tier = "";
        t.session_unresolved = true;
        t.stored = doc_with_excellent(80.0);
        for (const char* tool : {"set_dex_score_policy", "reset_dex_score_policy"}) {
            INFO(tool);
            const json r = t.call(tool, std::string(tool) == "set_dex_score_policy"
                                            ? set_args(95.0, rev_of(*t.stored))
                                            : json{{"if_match", rev_of(*t.stored)}});
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInternalError);
            CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        }
        CHECK(t.domain_rows.empty());
        CHECK(t.cas_calls == 0);
        CHECK(t.car_calls == 0);
        CHECK(t.stored.has_value());
    }
}

// The role every domain row carries is the caller's EFFECTIVE role (a live JIT elevation makes a
// `user` session `admin`), read once with the session. Not simulated: an elevation whose deadline
// lapses BETWEEN two rows of one request. auth::is_elevated reads steady_clock::now() directly
// (no injectable clock), and WriterIdentity holds the Session by value, so a per-row recompute
// from that copy could differ from the captured string only after a real deadline passed
// mid-request, which a test cannot cause without sleeping. What this case does pin is the other
// way to get the role wrong: reading the base `role` instead of the effective one, or hard-coding
// "admin".
TEST_CASE("set and reset: every domain row carries the caller's effective role, elevated or not",
          "[mcp][dex][score_policy][security]") {
    SECTION("a base-role caller with a live elevation is stamped admin; updated_by stays the username") {
        Twin t;
        t.tier = ""; // reset is then not ticket-gated; set is not ticket-gated at any tier
        t.session_role = auth::Role::user;
        t.session_elevated = true;
        REQUIRE_FALSE(t.call("set_dex_score_policy", set_args(95.0, "default")).contains("error"));
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session("admin");
        REQUIRE(t.cas_actors.size() == 1);
        CHECK(t.cas_actors[0] == "tester");
        t.clear_audit();
        REQUIRE_FALSE(
            t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}}).contains("error"));
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session("admin");
    }
    SECTION("an unelevated base-role caller is stamped with that role on both writes") {
        Twin t;
        t.tier = "";
        t.session_role = auth::Role::user;
        REQUIRE_FALSE(t.call("set_dex_score_policy", set_args(95.0, "default")).contains("error"));
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session("user");
        t.clear_audit();
        REQUIRE_FALSE(
            t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}}).contains("error"));
        REQUIRE(t.domain_rows.size() == 2);
        t.check_rows_stamped_as_session("user");
    }
}

TEST_CASE("set_dex_score_policy: caller refusals are non-retryable invalid-params errors with a "
          "denied row and no store write",
          "[mcp][dex][score_policy]") {
    SECTION("a missing If-Match") {
        Twin t;
        const json r = t.call("set_dex_score_policy", {{"document", doc_json(95.0)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        // apply's REST wording ("If-Match header required") is rewritten for the argument.
        CHECK(r["error"]["message"].get<std::string>().starts_with(
            "If-Match (the if_match argument)"));
        CHECK(r["error"]["message"].get<std::string>().find("header") == std::string::npos);
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

TEST_CASE("reset_dex_score_policy: each loud RBAC gate refuses with its own body and removes "
          "nothing",
          "[mcp][dex][score_policy][security]") {
    for (const char* denied : {"Infrastructure:Delete", "GuaranteedState:Read"}) {
        INFO(denied);
        Twin t;
        t.tier = ""; // not ticket-gated: the handler's own gate pair is under test
        t.stored = doc_with_excellent(80.0);
        t.perm_deny = denied;
        auto res = t.post(json{{"jsonrpc", "2.0"},
                               {"method", "tools/call"},
                               {"id", 7},
                               {"params", {{"name", "reset_dex_score_policy"},
                                           {"arguments", {{"if_match", rev_of(*t.stored)}}}}}}
                              .dump());
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(t.domain_rows.empty());
        CHECK(t.car_calls == 0);
        CHECK(t.stored.has_value());
        CHECK(t.session_calls == 0); // refused before the caller's session was resolved
        // Delete is asked first, Read second: a refused Read means Delete was already passed.
        REQUIRE_FALSE(t.perm_calls.empty());
        CHECK(std::count(t.perm_calls.begin(), t.perm_calls.end(), "Infrastructure:Delete") >= 1);
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
    SECTION("an unwired session-bound audit writer, apply closure or session resolver is refused, "
            "nothing stored") {
        for (int which = 0; which < 3; ++which) {
            INFO(which);
            Twin::Opts o;
            o.wire_audit = which != 0;
            o.wire_apply = which != 1;
            o.wire_session = which != 2;
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
    SECTION("a retryable failure whose failure row is dropped reaches the envelope's audit flag") {
        Twin t;
        t.cas_after_error = Twin::AfterError::other; // outcome unknown: a failure row follows
        t.domain_fail_result = "failure";
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
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

TEST_CASE("set_dex_score_policy: boundaries of if_match, the document and dry_run",
          "[mcp][dex][score_policy]") {
    SECTION("an if_match of exactly 64 bytes reaches apply, which refuses it as malformed") {
        Twin t;
        const json r = t.call("set_dex_score_policy", set_args(95.0, std::string(64, 'a')));
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["message"].get<std::string>().starts_with("If-Match"));
        REQUIRE(t.domain_rows.size() == 1);
        CHECK(t.domain_rows[0] == "dex.score_policy.update|denied|RuntimeConfig|dex_score_policy");
        CHECK(t.domain_details[0].find("if_match_malformed") != std::string::npos);
        CHECK(t.cas_calls == 0);
        t.check_rows_stamped_as_session();
    }
    SECTION("one byte past the cap is refused before apply: only the generic denied row") {
        Twin t;
        check_a4_refusal(t.call("set_dex_score_policy", set_args(95.0, std::string(65, 'a'))),
                         "correct the arguments and call again");
        CHECK(t.domain_rows.empty());
        CHECK(t.cas_calls == 0);
    }
    SECTION("a document over the size cap is an invalid-params error and stores nothing") {
        Twin t;
        const json big = {{"padding", std::string(kDexScorePolicyMaxBytes + 1, 'x')}};
        const json r = t.call("set_dex_score_policy", {{"document", big}, {"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["retry_after_ms"].is_null());
        CHECK(t.cas_calls == 0);
        CHECK_FALSE(t.stored.has_value());
        REQUIRE(t.domain_rows.size() == 1);
        CHECK(t.domain_rows[0] == "dex.score_policy.update|denied|RuntimeConfig|dex_score_policy");
    }
    SECTION("dry_run false is a real write, and the answer carries no dry_run key") {
        Twin t;
        json args = set_args(95.0, "default");
        args["dry_run"] = false;
        const json r = t.call("set_dex_score_policy", args);
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.cas_calls == 1);
        REQUIRE(t.stored.has_value());
        CHECK_FALSE(r["result"]["structuredContent"].contains("dry_run"));
        REQUIRE(t.domain_rows.size() == 2);
        CHECK(t.domain_rows[0] == kAttemptedUpdate);
    }
    SECTION("a failure after the commit (the install throws) is judged by a re-read: observed") {
        Twin t;
        t.clock_throws = true; // the provider's install reads the clock AFTER the commit
        const json r = t.call("set_dex_score_policy", set_args(95.0, "default"));
        t.clock_throws = false;
        REQUIRE_FALSE(r.contains("error"));
        CHECK(t.cas_calls == 1);
        REQUIRE(t.stored.has_value());
        CHECK(*t.stored == doc_with_excellent(95.0));
        CHECK(r["result"]["structuredContent"]["revision"] == rev_of(*t.stored));
        bool observed = false;
        for (const auto& d : t.domain_details)
            observed = observed || d.find("observed_after_store_error") != std::string::npos;
        CHECK(observed);
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

    // Runs `body` while the first write is parked in its commit. The guard is the only release
    // path: it runs on EVERY exit from this scope, a throwing REQUIRE, json::parse or `body`
    // included (destroying a joinable std::thread would terminate the binary, and joining one
    // still parked on the gate would hang). A second set_value throws, hence the swallow. It also
    // publishes `first` before the checks read it. Each SECTION re-runs the setup above, so the
    // thread and the promises are fresh every time.
    const auto while_first_is_parked = [&](const std::function<void()>& body) {
        std::thread parked([&] { first = apply_dex_score_policy(rq1, d1); });
        yuzu::test::ScopeExit release_and_join{[&] {
            try {
                release_p.set_value();
            } catch (...) { // NOLINT(bugprone-empty-catch)
            }
            if (parked.joinable())
                parked.join();
        }};
        // Bounded: a first write that never reaches its commit fails the case instead of hanging it.
        if (entered.wait_for(std::chrono::seconds(30)) != std::future_status::ready)
            FAIL("the first write never reached its commit");
        body();
    };

    SECTION("the second writer is refused as busy while the first is parked") {
        json r;
        while_first_is_parked([&] { r = t.call("set_dex_score_policy", set_args(96.0, "default")); });

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
    SECTION("an exception unwinding while the first write is parked still releases and joins it") {
        // The guard's only other exercise is the normal exit above. Here something throws after
        // the writer has entered its commit; the exception is caught OUTSIDE the guarded scope,
        // so the release-and-join has already run during the unwind (a missing guard terminates
        // the binary on the joinable thread's destructor, or hangs on the gate).
        bool unwound = false;
        try {
            while_first_is_parked([] { throw std::runtime_error("probe"); });
        } catch (const std::runtime_error&) {
            unwound = true;
        }
        CHECK(unwound);
        REQUIRE(first);
        CHECK(first->status == St::Ok);
    }
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

// At the supervised tier the input schema refuses an unknown argument before the approval gate
// (see the round trip below); the handler's own strict check is defence in depth, reached here
// by the empty tier. A STALE revision is the refusal that IS reachable after the ticket is spent.
TEST_CASE("reset_dex_score_policy: dry_run and any other argument are refused; refusals carry the "
          "spent-ticket recovery",
          "[mcp][dex][score_policy]") {
    Twin t;
    t.tier = "";
    SECTION("an argument the tool does not take") {
        const json dry = t.call("reset_dex_score_policy", {{"if_match", "default"}, {"dry_run", true}});
        REQUIRE(dry.contains("error"));
        CHECK(dry["error"]["message"].get<std::string>().find("unknown argument") != std::string::npos);
        check_a4_refusal(dry, "correct the arguments and call again");
        // The parse refusal is a post-consumption refusal like any other: it carries the recovery.
        check_a4_refusal(dry, "fresh ticket");
        CHECK(t.domain_rows.empty());
    }
    SECTION("a stale revision") {
        t.stored = doc_with_excellent(80.0);
        const json stale = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE(stale.contains("error"));
        CHECK(stale["error"]["code"] == mcp::kInvalidParams);
        CHECK(stale["error"]["data"]["remediation"].get<std::string>().find("fresh ticket") !=
              std::string::npos);
        CHECK(t.car_calls == 0);
    }
    SECTION("a missing or empty if_match is worded for the argument, not the REST header") {
        // The empty tier skips the dispatch chain's schema check, so the handler (and apply
        // behind it) judges the value: apply's REST wording must be rewritten for the argument.
        for (const json& args : {json::object(), json{{"if_match", ""}}}) {
            INFO(args.dump());
            t.clear_audit();
            const json r = t.call("reset_dex_score_policy", args);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            const std::string msg = r["error"]["message"].get<std::string>();
            CHECK(msg.starts_with("If-Match (the if_match argument)"));
            CHECK(msg.find("header") == std::string::npos);
            CHECK(r["error"]["data"]["remediation"].get<std::string>().find("fresh ticket") !=
                  std::string::npos);
        }
        CHECK(t.car_calls == 0);
    }
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
    // The spent-ticket note is appended whole, fallback for an error that names no revision included.
    CHECK(rem.find("(or with your if_match when none is named)") != std::string::npos);
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

TEST_CASE("reset_dex_score_policy: a dropped refusal or failure row reaches the envelope's audit "
          "flag",
          "[mcp][dex][score_policy]") {
    SECTION("a stale revision whose denied row is dropped") {
        Twin t;
        t.tier = "";
        t.stored = doc_with_excellent(80.0);
        t.domain_fail_result = "denied";
        const json r = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInvalidParams);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
        CHECK(t.car_calls == 0);
    }
    SECTION("an unknown-outcome failure whose failure row is dropped") {
        Twin t;
        t.tier = "";
        t.stored = doc_with_excellent(80.0);
        t.car_after_error = Twin::AfterError::other;
        t.domain_fail_result = "failure";
        const json r = t.call("reset_dex_score_policy", {{"if_match", rev_of(*t.stored)}});
        REQUIRE(r.contains("error"));
        CHECK(r["error"]["code"] == mcp::kInternalError);
        CHECK(r["error"]["data"]["retry_after_ms"] == kDexScorePolicyRetryMs);
        CHECK(r["error"]["data"]["audit_persisted"] == false);
    }
    SECTION("rows that all persist leave the flag off the envelope") {
        Twin t;
        t.tier = "";
        t.stored = doc_with_excellent(80.0);
        const json r = t.call("reset_dex_score_policy", {{"if_match", "default"}});
        REQUIRE(r.contains("error"));
        CHECK_FALSE(r["error"]["data"].contains("audit_persisted"));
    }
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
    SECTION("a malformed, over-long or unknown argument is refused by the input schema before any "
            "ticket is created or consumed") {
        for (const json& bad : {json{{"if_match", "0123456789abcdeg"}}, // 16 characters, not hex
                                json{{"if_match", "DEFAULT"}},
                                json{{"if_match", std::string(65, 'a')}},
                                json{{"if_match", rev_of(*t.stored)}, {"dry_run", true}},
                                json::object()}) {
            INFO(bad.dump());
            const json r = t.call("reset_dex_score_policy", bad);
            REQUIRE(r.contains("error"));
            CHECK(r["error"]["code"] == mcp::kInvalidParams);
            CHECK_FALSE(r["error"]["data"].contains("approval_id"));
            CHECK(r["error"]["data"]["remediation"].get<std::string>().find(
                      "no approval ticket was created or consumed") != std::string::npos);
        }
        CHECK(t.car_calls == 0);
        CHECK(t.domain_rows.empty());
        (void)mint(); // the gate is untouched: a valid call still mints a ticket
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

TEST_CASE("reset_dex_score_policy: an unwired apply closure, session-bound audit writer or "
          "session resolver is refused with nothing removed",
          "[mcp][dex][score_policy]") {
    for (int which = 0; which < 3; ++which) {
        INFO(which);
        Twin::Opts o;
        o.wire_audit = which != 0;
        o.wire_apply = which != 1;
        o.wire_session = which != 2;
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
        // No revision is named here, so the fallback to the caller's own if_match is what the
        // recovery relies on.
        CHECK(rem.find("(or with your if_match when none is named)") != std::string::npos);
        CHECK(audit_count(t.generic_rows, "mcp.reset_dex_score_policy|failure") == 1);
        CHECK(t.car_calls == 0);
        CHECK(t.stored.has_value());
    }
}
