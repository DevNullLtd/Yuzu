/**
 * test_mgmt_group_agent_known.cpp — #6967 / #7074: the "is this agent id a known device?" flag on
 * the add-member surfaces (`mgmt_group_agent_known.hpp`).
 *
 * Pure: no store, no network, no Postgres. The handlers that use it (REST and MCP add member) are
 * covered against a real AuthDB by the [pg] cases in test_rest_mgmt_group_audit_first.cpp and
 * test_mcp_server.cpp.
 */

#include "mgmt_group_agent_known.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_set>

using yuzu::server::add_member_success_detail;
using yuzu::server::agent_known_flag_value;
using yuzu::server::AgentKnown;
using yuzu::server::caller_may_see_agent_known;
using yuzu::server::classify_agent_known;
using yuzu::server::lookup_agent_known;
using yuzu::server::StoreError;
using yuzu::server::auth::PendingStatus;

namespace {
using Answer = std::expected<std::optional<PendingStatus>, StoreError>;
} // namespace

TEST_CASE("classify_agent_known: a value of any enrolment status is Known",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    for (const auto st : {PendingStatus::pending, PendingStatus::approved, PendingStatus::denied}) {
        INFO("status " << static_cast<int>(st));
        CHECK(classify_agent_known(Answer{std::optional<PendingStatus>{st}}) == AgentKnown::Known);
    }
}

TEST_CASE("classify_agent_known: an absent row is Unknown",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    CHECK(classify_agent_known(Answer{std::optional<PendingStatus>{}}) == AgentKnown::Unknown);
}

TEST_CASE("classify_agent_known: InvalidInput is Unknown, a caller-input outcome not an outage",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    CHECK(classify_agent_known(Answer{std::unexpected(StoreError::InvalidInput)}) ==
          AgentKnown::Unknown);
}

TEST_CASE("classify_agent_known: every other error is Unreadable, never Unknown",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    for (const auto e : {StoreError::Unavailable, StoreError::QueryFailed,
                         StoreError::CharsetRefused}) {
        INFO("error " << static_cast<int>(e));
        const auto k = classify_agent_known(Answer{std::unexpected(e)});
        CHECK(k == AgentKnown::Unreadable);
        CHECK(k != AgentKnown::Unknown);
    }
}

TEST_CASE("lookup_agent_known: a null AuthDB is Unreadable",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    CHECK(lookup_agent_known(nullptr, "agent-1") == AgentKnown::Unreadable);
    CHECK(lookup_agent_known(nullptr, "") == AgentKnown::Unreadable);
}

TEST_CASE("agent_known_flag_value: the three fixed audit values",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    CHECK(agent_known_flag_value(AgentKnown::Known) == "1");
    CHECK(agent_known_flag_value(AgentKnown::Unknown) == "0");
    CHECK(agent_known_flag_value(AgentKnown::Unreadable) == "unreadable");
}

TEST_CASE("add_member_success_detail: the raw id then the flag as the last token",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    CHECK(add_member_success_detail("agent-1", AgentKnown::Known) == "agent-1 agent_known=1");
    CHECK(add_member_success_detail("agent-1", AgentKnown::Unknown) == "agent-1 agent_known=0");
    CHECK(add_member_success_detail("agent-1", AgentKnown::Unreadable) ==
          "agent-1 agent_known=unreadable");
}

TEST_CASE("add_member_success_detail: an id that spells the flag cannot forge it",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    const auto last_token = [](const std::string& s) { return s.substr(s.rfind(' ') + 1); };
    const std::string forged = "x agent_known=1";
    const auto d = add_member_success_detail(forged, AgentKnown::Unknown);
    CHECK(d == "x agent_known=1 agent_known=0");
    CHECK(last_token(d) == "agent_known=0");
    // The raw id is carried verbatim, spaces included.
    CHECK(add_member_success_detail("agent \xc3\xa9 2", AgentKnown::Unreadable) ==
          "agent \xc3\xa9 2 agent_known=unreadable");
    CHECK(last_token(add_member_success_detail("agent \xc3\xa9 2", AgentKnown::Known)) ==
          "agent_known=1");
}

// ---- caller_may_see_agent_known: the gate on showing the answer (Enrollment:Read fleet read) ----

namespace {
using yuzu::server::authz::FleetReadGate;
using Gate = std::function<FleetReadGate(const httplib::Request&, httplib::Response&,
                                         const std::string&, const std::string&)>;
} // namespace

TEST_CASE("caller_may_see_agent_known: asks the Enrollment:Read fleet-read check, once",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    httplib::Request req;
    std::string type, op;
    int calls = 0;
    const Gate gate = [&](const httplib::Request&, httplib::Response&, const std::string& t,
                          const std::string& o) -> FleetReadGate {
        ++calls;
        type = t;
        op = o;
        return {true, std::nullopt};
    };
    const std::string probe_id = "agent-1";
    static_assert(noexcept(caller_may_see_agent_known(gate, req, probe_id)));
    CHECK(caller_may_see_agent_known(gate, req, "agent-1"));
    CHECK(calls == 1);
    CHECK(type == "Enrollment");
    CHECK(op == "Read");
}

TEST_CASE("caller_may_see_agent_known: an unconfined admit sees every id, a scoped admit only its "
          "own, an empty scope none",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    httplib::Request req;
    const Gate top = [](const httplib::Request&, httplib::Response&, const std::string&,
                        const std::string&) -> FleetReadGate { return {true, std::nullopt}; };
    CHECK(caller_may_see_agent_known(top, req, "anything"));

    const Gate scoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                           const std::string&) -> FleetReadGate {
        return {true, std::unordered_set<std::string>{"agent-in"}};
    };
    CHECK(caller_may_see_agent_known(scoped, req, "agent-in"));
    CHECK_FALSE(caller_may_see_agent_known(scoped, req, "agent-out"));

    const Gate empty = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> FleetReadGate {
        return {true, yuzu::server::authz::deny_all()};
    };
    CHECK_FALSE(caller_may_see_agent_known(empty, req, "agent-in"));
}

TEST_CASE("caller_may_see_agent_known: fails closed on a refusal, a degraded answer, an unwired "
          "check and an exception",
          "[mgmt-audit-first][mgmt_group_agent_known]") {
    httplib::Request req;
    // A refusal is admitted=false, whatever scope the aggregate happens to carry.
    const Gate refused = [](const httplib::Request&, httplib::Response& res, const std::string&,
                            const std::string&) -> FleetReadGate {
        res.status = 403;
        return {false, std::nullopt};
    };
    CHECK_FALSE(caller_may_see_agent_known(refused, req, "agent-1"));

    const Gate degraded = [](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&) -> FleetReadGate {
        res.status = 503;
        return {};
    };
    CHECK_FALSE(caller_may_see_agent_known(degraded, req, "agent-1"));

    const Gate unwired; // empty std::function
    CHECK_FALSE(caller_may_see_agent_known(unwired, req, "agent-1"));

    const Gate throws = [](const httplib::Request&, httplib::Response&, const std::string&,
                           const std::string&) -> FleetReadGate {
        throw std::runtime_error("authorization store fault");
    };
    CHECK_FALSE(caller_may_see_agent_known(throws, req, "agent-1"));
}
