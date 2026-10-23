#pragma once

// test_approver_route_fixture.hpp - the REAL approve/reject routes behind the REAL approver MFA
// gate, for the route suites that mint a session proof and then ask whether it decides a ticket
// (#6079). Shared by test_auth_routes_mfa.cpp and test_settings_routes_mfa.cpp.
//
// What is real: `approval::register_approval_routes`, an `ApprovalManager` on its own Postgres
// database, `require_enrolled_fresh_mfa` over the caller's AuthDB, and the durable proof read
// from the session store. The closure is the shape server.cpp binds as `approver_mfa_fn`
// (`durable_fn` is what that closure reads the stored proof with). What is stubbed: the
// permission gate (allow), the session resolution (the cookie through `AuthManager::
// validate_session`, as the production resolver does for a cookie session) and the generic
// `step_up_fn` (always passes: it is the central chokepoint's job and not what these cases
// pin; the approver gate is the one under test and runs after it).

#include "approval_manager.hpp"
#include "approval_routes.hpp"
#include "auth_routes.hpp"
#include "mfa_step_up.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::test {

struct ApproverRouteFixture {
    using DurableFn = std::function<yuzu::server::auth::DurableMfaProof(
        const httplib::Request&, const yuzu::server::auth::Session&)>;

    struct AuditRow {
        std::string action;
        std::string result;
        std::string detail;
    };

    ApprovalManagerPg mgr;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    int window_secs{300};

    ApproverRouteFixture(yuzu::server::auth::AuthManager& auth_mgr, yuzu::server::AuthDB& db,
                         DurableFn durable_fn) {
        using namespace yuzu::server;
        approval::Deps deps;
        deps.approval_manager = mgr.get();
        deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        deps.resolve_session_fn =
            [&auth_mgr](const httplib::Request& req) -> std::optional<auth::Session> {
            return auth_mgr.validate_session(AuthRoutes::extract_session_cookie(req));
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string&, const std::string&,
                               const std::string& d) -> bool {
            audits.push_back({a, r, d});
            return true;
        };
        deps.emit_event_fn = [](const std::string&, const httplib::Request&,
                                const nlohmann::json&, const nlohmann::json&) {};
        deps.step_up_fn = [](const httplib::Request&, httplib::Response&, const auth::Session&,
                             const std::string&) { return true; };
        deps.approver_mfa_fn = [this, &db, durable = std::move(durable_fn)](
                                   const httplib::Request& req, httplib::Response& res,
                                   const auth::Session& session,
                                   const std::string& label) -> ApproverMfaOutcome {
            return require_enrolled_fresh_mfa(
                req, res, session, db, window_secs,
                [this](const httplib::Request&, const std::string& a, const std::string& r,
                       const std::string&, const std::string&, const std::string& d) {
                    audits.push_back({a, r, d});
                    return true;
                },
                label, durable(req, session));
        };
        // A browser's same-site write: the cookie-write gate wants a matching Origin.
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        approval::register_approval_routes(sink, deps);
    }

    std::string submit() {
        static int n = 0;
        auto s = mgr->submit("def-binding-" + std::to_string(++n), "submitter1", "group:x", "",
                             yuzu::server::ApprovalOrigin::kInstruction);
        REQUIRE(s.has_value());
        return *s;
    }

    /// `verb` is "approve" or "reject"; `token` is the raw session cookie value.
    std::unique_ptr<httplib::Response> decide(const std::string& verb, const std::string& ticket,
                                              const std::string& token) {
        return sink.dispatch("POST", "/api/approvals/" + ticket + "/" + verb, "{}",
                             "application/json", {{"Cookie", "yuzu_session=" + token}});
    }

    std::string status_of(const std::string& ticket) const {
        auto row = mgr->get(ticket);
        REQUIRE(row.has_value());
        return row->status;
    }
};

} // namespace yuzu::test
