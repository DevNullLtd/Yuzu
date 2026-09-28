/**
 * test_settings_routes_enrollment.cpp — HTTP-level tests for the dashboard
 * enrollment mutations in SettingsRoutes (WS-6 slice 6.2): token create / batch
 * create / revoke and pending-agent approve / deny / bulk approve / bulk deny /
 * remove.
 *
 * What these pin:
 *  - every mutation writes an audit row (SOC 2 CC7.2) carrying the acting
 *    principal (`by=<operator>`), and NEVER the raw token (token_id only);
 *  - a store outage is a 503 + an `outcome=failure` audit row, never an empty
 *    success;
 *  - bulk approve/deny is one atomic `UPDATE .. WHERE status='pending'`, so a row
 *    that is already denied/approved is never overwritten and the reported count
 *    is exactly the rows THIS call moved.
 *
 * Audit posture: `SettingsRoutes::AuditFn` is void (set-and-proceed) like every
 * neighbouring dashboard settings mutation, so a dropped audit row is logged but
 * does not fail the operator action.
 *
 * Pattern: in-process TestRouteSink (test_settings_routes_users.cpp), no socket.
 */

#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"

#include "test_auth_db_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

constexpr const char* kForm = "application/x-www-form-urlencoded";

/// SettingsRoutes over an AuthManager that is (optionally) wired to a PG-backed
/// AuthDB. Declared so the sink comes AFTER the route owner it registers.
struct EnrollRoutesHarness {
    std::unique_ptr<yuzu::test::AuthDbPgShared> auth_db; // null => store unavailable
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::string session_user{"admin"};
    std::vector<AuditCall> audit_calls;

    explicit EnrollRoutesHarness(bool with_store = true) {
        if (with_store) {
            auth_db = std::make_unique<yuzu::test::AuthDbPgShared>();
            auth_mgr.set_auth_db(auth_db->get());
        }
        auto auth_fn = [this](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = session_user;
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_calls.push_back({action, result, target_type, target_id, detail});
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }

    /// The single audit row for `action` (fails the test if there isn't exactly one).
    AuditCall only(const std::string& action) const {
        std::vector<AuditCall> hits;
        for (const auto& a : audit_calls)
            if (a.action == action)
                hits.push_back(a);
        REQUIRE(hits.size() == 1);
        return hits.front();
    }

    /// True if any audit field of any row contains `needle` (raw-token leak check).
    bool audit_mentions(const std::string& needle) const {
        for (const auto& a : audit_calls)
            for (const auto* f : {&a.action, &a.result, &a.target_type, &a.target_id, &a.detail})
                if (f->find(needle) != std::string::npos)
                    return true;
        return false;
    }

    void queue(const std::string& id) {
        REQUIRE(auth_mgr.add_pending_agent(id, "host-" + id, "linux", "x86_64", "1.0").value());
    }
    auth::PendingStatus status_of(const std::string& id) {
        auto st = auth_mgr.get_pending_status(id);
        REQUIRE(st.has_value());
        REQUIRE(st->has_value());
        return **st;
    }
};

/// The 64-hex raw token shown in the dashboard's one-time reveal block.
std::string raw_token_in(const std::string& html) {
    const std::string marker = "<code>";
    for (std::size_t pos = html.find(marker); pos != std::string::npos;
         pos = html.find(marker, pos + 1)) {
        const auto start = pos + marker.size();
        const auto end = html.find("</code>", start);
        if (end != std::string::npos && end - start == 64)
            return html.substr(start, 64);
    }
    return {};
}

} // namespace

TEST_CASE("settings enrollment: token create audits token_id + principal, never the raw token",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    auto res = h.sink.Post("/api/settings/enrollment-tokens",
                           "label=NYC+rollout&max_uses=2&ttl_hours=1", kForm);
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto raw = raw_token_in(res->body);
    REQUIRE(raw.size() == 64);

    const auto tokens = h.auth_mgr.list_enrollment_tokens().value();
    REQUIRE(tokens.size() == 1);
    const auto row = h.only("enrollment.token_create");
    CHECK(row.result == "success");
    CHECK(row.target_type == "EnrollmentToken");
    CHECK(row.target_id == tokens[0].token_id);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(row.detail.find("max_uses=2") != std::string::npos);
    CHECK_FALSE(h.audit_mentions(raw)); // the shown-once secret never reaches the audit store
}

TEST_CASE("settings enrollment: token create with the store down is 503 + a failure audit row",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    auto res = h.sink.Post("/api/settings/enrollment-tokens", "label=x&max_uses=1", kForm);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(raw_token_in(res->body).empty());
    const auto row = h.only("enrollment.token_create");
    CHECK(row.result == "failure");
    CHECK(row.detail.find("store_unavailable") != std::string::npos);
}

TEST_CASE("settings enrollment: invalid numeric parameters are audited as denied",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    auto res = h.sink.Post("/api/settings/enrollment-tokens", "label=x&max_uses=abc", kForm);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.only("enrollment.token_create").result == "denied");
}

TEST_CASE("settings enrollment: revoke audits success, and denied for an unknown id",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    auto created = h.auth_mgr.create_enrollment_token("t", 1, std::chrono::hours(1), "admin");
    REQUIRE(created.has_value());

    auto res = h.sink.Delete("/api/settings/enrollment-tokens/" + created->token_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto row = h.only("enrollment.token_revoke");
    CHECK(row.result == "success");
    CHECK(row.target_id == created->token_id);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(h.auth_mgr.list_enrollment_tokens().value()[0].revoked);

    h.audit_calls.clear();
    auto res2 = h.sink.Delete("/api/settings/enrollment-tokens/ffffffff");
    REQUIRE(res2);
    row = h.only("enrollment.token_revoke");
    CHECK(row.result == "denied");
    CHECK(row.detail.find("token_not_found") != std::string::npos);
}

TEST_CASE("settings enrollment: revoke with the store down is 503 and audited as failure",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    auto res = h.sink.Delete("/api/settings/enrollment-tokens/abcd1234");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.only("enrollment.token_revoke").result == "failure");
}

TEST_CASE("settings enrollment: batch create returns N tokens and audits ids only",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    auto res = h.sink.Post("/api/settings/enrollment-tokens/batch",
                           R"({"label":"rollout","count":"3","max_uses":"1","ttl_hours":"1"})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["tokens"].size() == 3);
    CHECK(j["count"] == 3);

    const auto row = h.only("enrollment.token_create_batch");
    CHECK(row.result == "success");
    CHECK(row.detail.find("count=3") != std::string::npos);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    for (const auto& t : j["tokens"])
        CHECK_FALSE(h.audit_mentions(t.get<std::string>()));
    // The ids listed in the audit row are real token ids.
    for (const auto& t : h.auth_mgr.list_enrollment_tokens().value())
        CHECK(row.detail.find(t.token_id) != std::string::npos);
}

TEST_CASE("settings enrollment: batch create with the store down is a 503 A4 error + failure audit",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    auto res = h.sink.Post("/api/settings/enrollment-tokens/batch",
                           R"({"count":"2","max_uses":"1"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("error"));
    CHECK(j["count"] == 0);
    const auto row = h.only("enrollment.token_create_batch");
    CHECK(row.result == "failure");
    CHECK(row.detail.find("minted_before_failure=0") != std::string::npos);
}

TEST_CASE("settings enrollment: single approve / deny / remove each write an audit row with the "
          "principal",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    h.queue("a1");
    h.queue("a2");
    h.queue("a3");

    REQUIRE(h.sink.Post("/api/settings/pending-agents/a1/approve", "", kForm)->status == 200);
    auto row = h.only("enrollment.approve");
    CHECK(row.result == "success");
    CHECK(row.target_type == "Agent");
    CHECK(row.target_id == "a1");
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(h.status_of("a1") == auth::PendingStatus::approved);

    REQUIRE(h.sink.Post("/api/settings/pending-agents/a2/deny", "", kForm)->status == 200);
    row = h.only("enrollment.deny");
    CHECK(row.result == "success");
    CHECK(row.target_id == "a2");
    CHECK(h.status_of("a2") == auth::PendingStatus::denied);

    REQUIRE(h.sink.Delete("/api/settings/pending-agents/a3")->status == 200);
    row = h.only("enrollment.remove");
    CHECK(row.result == "success");
    CHECK(row.target_id == "a3");
    CHECK_FALSE(h.auth_mgr.get_pending_status("a3").value().has_value());

    // Unknown agent: an audited no-op, not silent success.
    h.audit_calls.clear();
    REQUIRE(h.sink.Post("/api/settings/pending-agents/ghost/approve", "", kForm));
    row = h.only("enrollment.approve");
    CHECK(row.result == "denied");
    CHECK(row.detail.find("agent_not_found") != std::string::npos);
}

TEST_CASE("settings enrollment: approve/deny/remove with the store down are 503 + failure audit",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    CHECK(h.sink.Post("/api/settings/pending-agents/a1/approve", "", kForm)->status == 503);
    CHECK(h.only("enrollment.approve").result == "failure");
    CHECK(h.sink.Post("/api/settings/pending-agents/a1/deny", "", kForm)->status == 503);
    CHECK(h.only("enrollment.deny").result == "failure");
    CHECK(h.sink.Delete("/api/settings/pending-agents/a1")->status == 503);
    CHECK(h.only("enrollment.remove").result == "failure");
}

TEST_CASE("settings enrollment: bulk approve moves only PENDING rows, never overwrites a deny, "
          "and reports the RETURNING set",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    for (const char* id : {"p1", "p2", "d1", "ok1"})
        h.queue(id);
    // d1 was denied (e.g. by another admin / replica) BEFORE the bulk statement runs.
    REQUIRE(h.auth_mgr.deny_pending_agent("d1", "other-admin").value());
    REQUIRE(h.auth_mgr.approve_pending_agent("ok1", "other-admin").value());

    auto res = h.sink.Post("/api/settings/pending-agents/bulk-approve", "", kForm);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("HX-Trigger").find("2 agent(s) approved") != std::string::npos);

    CHECK(h.status_of("p1") == auth::PendingStatus::approved);
    CHECK(h.status_of("p2") == auth::PendingStatus::approved);
    CHECK(h.status_of("d1") == auth::PendingStatus::denied); // NOT overwritten

    const auto row = h.only("enrollment.bulk_approve");
    CHECK(row.result == "success");
    CHECK(row.detail.find("count=2") != std::string::npos);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(row.detail.find("p1") != std::string::npos);
    CHECK(row.detail.find("d1") == std::string::npos);
}

TEST_CASE("settings enrollment: bulk deny moves only PENDING rows and audits the RETURNING set",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    for (const char* id : {"p1", "p2", "ok1"})
        h.queue(id);
    REQUIRE(h.auth_mgr.approve_pending_agent("ok1", "other-admin").value());

    auto res = h.sink.Post("/api/settings/pending-agents/bulk-deny", "", kForm);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("HX-Trigger").find("2 agent(s) denied") != std::string::npos);
    CHECK(h.status_of("p1") == auth::PendingStatus::denied);
    CHECK(h.status_of("ok1") == auth::PendingStatus::approved); // untouched
    const auto row = h.only("enrollment.bulk_deny");
    CHECK(row.result == "success");
    CHECK(row.detail.find("count=2") != std::string::npos);
}

TEST_CASE("settings enrollment: bulk approve/deny with the store down are 503 + failure audit",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    CHECK(h.sink.Post("/api/settings/pending-agents/bulk-approve", "", kForm)->status == 503);
    CHECK(h.only("enrollment.bulk_approve").result == "failure");
    CHECK(h.sink.Post("/api/settings/pending-agents/bulk-deny", "", kForm)->status == 503);
    CHECK(h.only("enrollment.bulk_deny").result == "failure");
}
