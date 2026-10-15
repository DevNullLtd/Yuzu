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

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
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
    std::vector<AuditCall> audit_calls;   ///< AuditFn (void): outcome / denied rows
    std::vector<AuditCall> attempt_calls; ///< AuditReadFn (bool): the fail-closed `attempt` rows
    bool audit_persists{true};            ///< false: the bool hook reports a persist failure
    std::vector<auth::AutoApproveRule> rules_at_attempt; ///< engine state seen BY the attempt hook
    bool mode_at_attempt{false};

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
        auto audit_read_fn = [this](const httplib::Request&, const std::string& action,
                                    const std::string& result, const std::string& target_type,
                                    const std::string& target_id,
                                    const std::string& detail) -> bool {
            attempt_calls.push_back({action, result, target_type, target_id, detail});
            rules_at_attempt = auto_approve.list_rules();
            mode_at_attempt = auto_approve.require_all();
            return audit_persists;
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider, /*metrics_registry=*/nullptr,
                               /*step_up_fn=*/{}, audit_read_fn);
        // A browser sends these on every same-origin post; the cross-origin tests clear them.
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
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

    const auto row = h.only("enrollment.bulk_token_create");
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
    const auto row = h.only("enrollment.bulk_token_create");
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

TEST_CASE("settings enrollment: remove REFUSES a denied/approved row — 409, denied audit, row "
          "persists",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    h.queue("a-denied");
    h.queue("a-approved");
    REQUIRE(h.auth_mgr.deny_pending_agent("a-denied", "admin").value());
    REQUIRE(h.auth_mgr.approve_pending_agent("a-approved", "admin").value());
    h.audit_calls.clear();

    // Removing the DENIED row is refused: 409, "denied" audit outcome, the
    // row is still there and still denied (governance Finding 1).
    auto res = h.sink.Delete("/api/settings/pending-agents/a-denied");
    REQUIRE(res);
    CHECK(res->status == 409);
    auto row = h.only("enrollment.remove");
    CHECK(row.result == "denied");
    CHECK(row.detail.find("refused_wrong_status") != std::string::npos);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(h.status_of("a-denied") == auth::PendingStatus::denied);

    // Removing the APPROVED row is refused too.
    h.audit_calls.clear();
    res = h.sink.Delete("/api/settings/pending-agents/a-approved");
    REQUIRE(res);
    CHECK(res->status == 409);
    row = h.only("enrollment.remove");
    CHECK(row.result == "denied");
    CHECK(row.detail.find("refused_wrong_status") != std::string::npos);
    CHECK(h.status_of("a-approved") == auth::PendingStatus::approved);
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

// #4644: `stoi("0x5")` is 0 and max_uses 0 means UNLIMITED, so a mistyped limit used to
// mint an unlimited token. Only an EMPTY field or a literal 0 may mean "unlimited"/"no expiry";
// anything else must be ONE base-10 integer, otherwise 400, audited denied, nothing minted.
TEST_CASE("settings enrollment: a malformed max_uses or ttl_hours mints nothing",
          "[pg][settings_routes][enrollment][numeric_params]") {
    for (const char* body : {"label=x&max_uses=0x5", "label=x&max_uses=5abc",
                             "label=x&max_uses=1e1", "label=x&max_uses=%2B3",
                             "label=x&max_uses=1&ttl_hours=24h", "label=x&ttl_hours=0x18",
                             // A negative TTL computes 0 = NEVER EXPIRES: refused, not minted.
                             "label=x&ttl_hours=-1", "label=x&max_uses=1&ttl_hours=-24"}) {
        EnrollRoutesHarness h;
        INFO(body);
        auto res = h.sink.Post("/api/settings/enrollment-tokens", body, kForm);
        REQUIRE(res);
        CHECK(res->status == 400);
        // The dashboard drops 4xx bodies, so the operator is told by the toast.
        CHECK(res->get_header_value("HX-Trigger").find("showToast") != std::string::npos);
        CHECK(h.only("enrollment.token_create").result == "denied");
        CHECK(h.auth_mgr.list_enrollment_tokens().value().empty());
        CHECK(raw_token_in(res->body).empty());
    }
}

TEST_CASE("settings enrollment: an empty or literal-zero limit still means unlimited",
          "[pg][settings_routes][enrollment][numeric_params]") {
    // `-0` and `00` parse to a literal 0, so they keep the documented meaning; only an empty
    // field or a value that parses to 0 is "unlimited" / "no expiry".
    for (const char* body : {"label=x&max_uses=0&ttl_hours=0", "label=x&max_uses=&ttl_hours=",
                             "label=x", "label=x&max_uses=00&ttl_hours=-0"}) {
        EnrollRoutesHarness h;
        INFO(body);
        auto res = h.sink.Post("/api/settings/enrollment-tokens", body, kForm);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.auth_mgr.list_enrollment_tokens().value().size() == 1);
    }
}

TEST_CASE("settings enrollment: the batch route honours JSON numbers AND numeric strings "
          "(the documented curl example mints what it says, #4644)",
          "[pg][settings_routes][enrollment][numeric_params]") {
    using std::chrono::hours;
    using std::chrono::system_clock;
    const auto near_hours = [](system_clock::time_point tp, int h) {
        const auto want = system_clock::now() + hours(h);
        return tp > want - std::chrono::minutes(2) && tp < want + std::chrono::minutes(2);
    };

    SECTION("JSON numbers (the documented example shape)") {
        EnrollRoutesHarness h;
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch",
                               R"({"label":"site-deploy","count":3,"max_uses":50,"ttl_hours":24})");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto tokens = h.auth_mgr.list_enrollment_tokens().value();
        REQUIRE(tokens.size() == 3);
        for (const auto& t : tokens) {
            CHECK(t.max_uses == 50);
            CHECK(near_hours(t.expires_at, 24));
        }
    }
    SECTION("numeric strings (qa-stack.sh and the unit-test shape), and a mix") {
        EnrollRoutesHarness h;
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch",
                               R"({"count":"2","max_uses":7,"ttl_hours":"2"})");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto tokens = h.auth_mgr.list_enrollment_tokens().value();
        REQUIRE(tokens.size() == 2);
        for (const auto& t : tokens) {
            CHECK(t.max_uses == 7);
            CHECK(near_hours(t.expires_at, 2));
        }
    }
    SECTION("an empty string or an absent key keeps the documented default") {
        EnrollRoutesHarness h;
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch",
                               R"({"count":2,"max_uses":"","ttl_hours":""})");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto tokens = h.auth_mgr.list_enrollment_tokens().value();
        REQUIRE(tokens.size() == 2);
        for (const auto& t : tokens) {
            CHECK(t.max_uses == 1);
            CHECK(t.expires_at == system_clock::time_point::max());
        }
    }
    SECTION("a blank body keeps every default (10 single-use tokens)") {
        EnrollRoutesHarness h;
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch", "");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.auth_mgr.list_enrollment_tokens().value().size() == 10);
    }
}

TEST_CASE("settings enrollment: the batch route refuses every non-integer, out-of-range or "
          "wrapped number and a bad body, and mints nothing (#4644)",
          "[pg][settings_routes][enrollment][numeric_params]") {
    EnrollRoutesHarness h;
    // `detail` is pinned because docs/user-manual/audit-log.md documents these strings as the
    // SIEM-filterable contract; a prefix match covers the store-refusal row, whose detail carries
    // the actor and counts after the token.
    const auto expect_refused = [&h](const std::string& body,
                                     const std::string& detail = "invalid_numeric_parameter") {
        INFO(body);
        h.audit_calls.clear();
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.auth_mgr.list_enrollment_tokens().value().empty());
        const auto row = h.only("enrollment.bulk_token_create");
        CHECK(row.result == "denied");
        CHECK(row.detail.rfind(detail, 0) == 0);
        CHECK((detail == "invalid_input" || row.detail == detail));
    };

    // The same probe set for each key. A numeric string and a JSON integer in range are valid
    // (previous test), so only values no reading can make valid appear here. 0 is valid for
    // max_uses (unlimited) and ttl_hours (no expiry), so it is only a probe for count.
    const std::vector<std::string> common = {
        "4294967297", "9223372036854775808", "18446744073709551615", "1e3", "5.5", "true",
        "null", "[]", "{}", R"("7x")", R"("0x1")", R"("1e1")", R"("5.5")", R"("+3")", R"(" 3")"};
    for (const char* key : {"count", "max_uses", "ttl_hours"}) {
        for (const auto& v : common) {
            nlohmann::json j = {{"count", 2}};
            j[key] = nlohmann::json::parse(v); // replaces the base value when key == "count"
            expect_refused(j.dump());
        }
    }
    // A negative TTL computes 0 = never expires; a negative max_uses and a count outside
    // 1..10000 are refused by the existing rules, now for numbers as well as strings.
    for (const char* v : {"-1", R"("-1")"}) {
        expect_refused(std::string(R"({"count":2,"ttl_hours":)") + v + "}");
        expect_refused(std::string(R"({"count":2,"max_uses":)") + v + "}", "invalid_input");
        expect_refused(std::string(R"({"count":)") + v + "}", "count_out_of_range");
    }
    for (const char* v : {"0", R"("0")", "10001"})
        expect_refused(std::string(R"({"count":)") + v + "}", "count_out_of_range");

    // A body that is not one JSON object is not "all defaults": it used to mint 10 single-use
    // tokens that never expire.
    for (const char* bad : {R"({"count":2)", "[]", "5", R"("x")", "null", "not json"})
        expect_refused(bad, "invalid_body");
}

TEST_CASE("settings enrollment: the batch route refuses a malformed count or limit too",
          "[pg][settings_routes][enrollment][numeric_params]") {
    for (const char* body : {R"({"count":"3x"})", R"({"count":"2","max_uses":"0x1"})",
                             R"({"count":"2","ttl_hours":"1e1"})",
                             R"({"count":"2","ttl_hours":"-1"})"}) {
        EnrollRoutesHarness h;
        INFO(body);
        auto res = h.sink.Post("/api/settings/enrollment-tokens/batch", body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("HX-Trigger").find("showToast") != std::string::npos);
        CHECK(h.auth_mgr.list_enrollment_tokens().value().empty());
    }
}

// A token still in date is Active, and its pill must never wear the green OK colour (role-ok),
// which would assert health for a credential an operator is meant to watch.
TEST_CASE("settings enrollment: the Active token pill is not the green OK pill",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    REQUIRE(h.sink.Post("/api/settings/enrollment-tokens", "label=x&max_uses=1&ttl_hours=1",
                        kForm));

    auto res = h.sink.Get("/fragments/settings/tokens");
    REQUIRE(res);
    CHECK(res->body.find("role-badge role-admin\">Active") != std::string::npos);
    CHECK(res->body.find("role-ok\">Active") == std::string::npos);
}

// ── Auto-approve rule writes (B4 hardening): validated, fail-closed, audited ──
// No PG store involved: the rule engine is in-memory, so these run in the plain suite.

TEST_CASE("settings auto-approve: a valid add persists and audits exactly one rule_add row",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    auto r = h.sink.Post("/api/settings/auto-approve",
                         "type=ip_subnet&value=10.0.0.0%2F8&label=lan", kForm);
    REQUIRE(r);
    CHECK(r->status == 200);
    REQUIRE(h.auto_approve.list_rules().size() == 1);
    const auto row = h.only("enrollment.auto_approve.rule_add");
    CHECK(row.result == "success");
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(h.audit_calls.size() == 1);
    // ... preceded by one fail-closed `attempt` row carrying the same detail.
    REQUIRE(h.attempt_calls.size() == 1);
    CHECK(h.attempt_calls[0].action == "enrollment.auto_approve.rule_add");
    CHECK(h.attempt_calls[0].result == "attempt");
    CHECK(h.attempt_calls[0].detail == row.detail);
}

TEST_CASE("settings auto-approve: injection, bad CIDR and unknown type are 400, audited denied, "
          "and nothing is persisted",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    const char* bodies[] = {
        // newline in the label injects a second rule line into the delimited file
        "type=hostname_glob&value=a.example.com&label=x%0Ahostname_glob%3A*%3Ainj%3A1",
        "type=hostname_glob&value=a.example.com&label=has%3Acolon", // ':' truncates on reload
        "type=ip_subnet&value=10.0.0.0%2Fabc&label=x",               // stoi throw in evaluate()
        "type=ip_subnet&value=10.0.0.0%2F33&label=x",
        "type=trusted_ca&value=abcd&label=x",
        "type=hostname_glob&value=&label=x",
        "type=subnet&value=*&label=x", // unknown type used to default to hostname_glob
    };
    for (const char* body : bodies) {
        INFO(body);
        h.audit_calls.clear();
        auto r = h.sink.Post("/api/settings/auto-approve", body, kForm);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(h.only("enrollment.auto_approve.rule_add").result == "denied");
        CHECK(h.auto_approve.list_rules().empty());
        CHECK(h.attempt_calls.empty()); // refused before any attempt row
        // The dashboard reads the toast; an API caller reads the A4 envelope.
        CHECK(r->get_header_value("HX-Trigger").find("showToast") != std::string::npos);
        CHECK(nlohmann::json::parse(r->body)["error"]["code"] == 400);
    }
}

TEST_CASE("settings auto-approve: toggle, delete and mode each audit exactly one row",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    h.auto_approve.add_rule({auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true});

    REQUIRE(h.sink.Post("/api/settings/auto-approve/0/toggle", "", kForm)->status == 200);
    CHECK(h.only("enrollment.auto_approve.rule_toggle").detail.find("enabled=0") !=
          std::string::npos);
    CHECK_FALSE(h.auto_approve.list_rules()[0].enabled);

    h.audit_calls.clear();
    REQUIRE(h.sink.Post("/api/settings/auto-approve/mode", "mode=all", kForm)->status == 200);
    CHECK(h.only("enrollment.auto_approve.mode").detail.find("mode=all") != std::string::npos);
    CHECK(h.auto_approve.require_all());

    h.audit_calls.clear();
    CHECK(h.sink.Post("/api/settings/auto-approve/mode", "mode=bogus", kForm)->status == 400);
    CHECK(h.only("enrollment.auto_approve.mode").result == "denied");
    CHECK(h.auto_approve.require_all()); // unchanged

    h.audit_calls.clear();
    REQUIRE(h.sink.Delete("/api/settings/auto-approve/0")->status == 200);
    CHECK(h.only("enrollment.auto_approve.rule_remove").result == "success");
    CHECK(h.auto_approve.list_rules().empty());

    h.audit_calls.clear();
    REQUIRE(h.sink.Delete("/api/settings/auto-approve/7")->status == 200);
    CHECK(h.only("enrollment.auto_approve.rule_remove").result == "denied");
}

TEST_CASE("settings auto-approve: every rule type is accepted and stored as that type",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    const std::string ca(64, 'a');
    REQUIRE(h.sink.Post("/api/settings/auto-approve",
                        "type=trusted_ca&value=" + ca + "&label=ca", kForm)->status == 200);
    REQUIRE(h.sink.Post("/api/settings/auto-approve",
                        "type=cloud_provider&value=aws&label=cp", kForm)->status == 200);
    REQUIRE(h.sink.Post("/api/settings/auto-approve",
                        "type=hostname_glob&value=*.corp&label=hg", kForm)->status == 200);
    const auto rules = h.auto_approve.list_rules();
    REQUIRE(rules.size() == 3);
    CHECK(rules[0].type == auth::AutoApproveRuleType::trusted_ca);
    CHECK(rules[1].type == auth::AutoApproveRuleType::cloud_provider);
    CHECK(rules[2].type == auth::AutoApproveRuleType::hostname_glob);
}

TEST_CASE("settings auto-approve: toggle, remove and mode audit rows carry the full contract",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    h.auto_approve.add_rule({auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true});

    REQUIRE(h.sink.Post("/api/settings/auto-approve/0/toggle", "", kForm)->status == 200);
    REQUIRE(h.audit_calls.size() == 1);
    auto row = h.only("enrollment.auto_approve.rule_toggle");
    CHECK(row.result == "success");
    CHECK(row.target_type == "AutoApproveRule");
    CHECK(row.target_id == "0");
    CHECK(row.detail == "enabled=0 by=admin");

    // Unknown index: denied, state untouched, exactly one row.
    h.audit_calls.clear();
    REQUIRE(h.sink.Post("/api/settings/auto-approve/9/toggle", "", kForm)->status == 200);
    REQUIRE(h.audit_calls.size() == 1);
    row = h.only("enrollment.auto_approve.rule_toggle");
    CHECK(row.result == "denied");
    CHECK(row.target_id == "9");
    CHECK(row.detail == "rule_not_found by=admin");
    CHECK_FALSE(h.auto_approve.list_rules()[0].enabled);

    h.audit_calls.clear();
    REQUIRE(h.sink.Post("/api/settings/auto-approve/mode", "mode=all", kForm)->status == 200);
    REQUIRE(h.audit_calls.size() == 1);
    row = h.only("enrollment.auto_approve.mode");
    CHECK(row.result == "success");
    CHECK(row.detail == "mode=all by=admin");

    h.audit_calls.clear();
    REQUIRE(h.sink.Delete("/api/settings/auto-approve/0")->status == 200);
    REQUIRE(h.audit_calls.size() == 1);
    row = h.only("enrollment.auto_approve.rule_remove");
    CHECK(row.result == "success");
    CHECK(row.target_id == "0");
    CHECK(row.detail == "value=*.corp label=corp by=admin");
}

TEST_CASE("settings auto-approve: an overlong numeric index is a denied no-op, not an exception",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    h.auto_approve.add_rule({auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true});
    const std::string huge(40, '9');

    auto r = h.sink.Post("/api/settings/auto-approve/" + huge + "/toggle", "", kForm);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.only("enrollment.auto_approve.rule_toggle").result == "denied");

    h.audit_calls.clear();
    r = h.sink.Delete("/api/settings/auto-approve/" + huge);
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto row = h.only("enrollment.auto_approve.rule_remove");
    CHECK(row.result == "denied");
    CHECK(row.target_id == huge);
    CHECK(h.auto_approve.list_rules().size() == 1);
    CHECK(h.auto_approve.list_rules()[0].enabled);
}

// ── Fail-closed on audit (ADR-0033 section 9): no persisted `attempt` row -> no mutation ──

namespace {
/// Seeds one enabled rule and mode `any`, then runs `drive` against each of the four writes.
struct AutoApproveWrite {
    const char* name;
    std::function<std::shared_ptr<httplib::Response>(EnrollRoutesHarness&)> run;
    const char* action;
};

std::vector<AutoApproveWrite> auto_approve_writes() {
    return {
        {"add",
         [](EnrollRoutesHarness& h) {
             return h.sink.Post("/api/settings/auto-approve",
                                "type=hostname_glob&value=new.corp&label=n", kForm);
         },
         "enrollment.auto_approve.rule_add"},
        {"mode",
         [](EnrollRoutesHarness& h) {
             return h.sink.Post("/api/settings/auto-approve/mode", "mode=all", kForm);
         },
         "enrollment.auto_approve.mode"},
        {"toggle",
         [](EnrollRoutesHarness& h) {
             return h.sink.Post("/api/settings/auto-approve/0/toggle", "", kForm);
         },
         "enrollment.auto_approve.rule_toggle"},
        {"remove",
         [](EnrollRoutesHarness& h) { return h.sink.Delete("/api/settings/auto-approve/0"); },
         "enrollment.auto_approve.rule_remove"},
    };
}
} // namespace

TEST_CASE("settings auto-approve: an audit row that is not persisted refuses the write (503), "
          "and policy memory and file are unchanged",
          "[settings_routes][enrollment][auto_approve][audit]") {
    for (const auto& w : auto_approve_writes()) {
        INFO(w.name);
        EnrollRoutesHarness h(/*with_store=*/false);
        yuzu::test::TempDbFile cfg{"yuzu_test_auto_approve_audit-"};
        h.auto_approve.load(cfg.path);
        REQUIRE(h.auto_approve.add_rule(
            {auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true}));
        const auto file_before = [&] {
            std::ifstream f(cfg.path);
            return std::string(std::istreambuf_iterator<char>(f), {});
        }();
        h.audit_persists = false;

        auto r = w.run(h);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(nlohmann::json::parse(r->body)["error"]["code"] == 503);
        REQUIRE(h.attempt_calls.size() == 1);
        CHECK(h.attempt_calls[0].action == w.action);
        CHECK(h.attempt_calls[0].result == "attempt");
        CHECK(h.audit_calls.empty()); // no outcome row: nothing happened
        const auto rules = h.auto_approve.list_rules();
        REQUIRE(rules.size() == 1);
        CHECK(rules[0].enabled);
        CHECK(rules[0].value == "*.corp");
        CHECK_FALSE(h.auto_approve.require_all());
        const std::string file_after = [&] {
            std::ifstream f(cfg.path);
            return std::string(std::istreambuf_iterator<char>(f), {});
        }();
        CHECK(file_after == file_before);
    }
}

TEST_CASE("settings auto-approve: the attempt row is written BEFORE the policy changes",
          "[settings_routes][enrollment][auto_approve][audit]") {
    // Observed from inside the audit hook: at the moment the attempt row is written the
    // engine still holds the pre-write policy; afterwards it holds the post-write one.
    for (const auto& w : auto_approve_writes()) {
        INFO(w.name);
        EnrollRoutesHarness h(/*with_store=*/false);
        REQUIRE(h.auto_approve.add_rule(
            {auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true}));
        auto r = w.run(h);
        REQUIRE(r);
        CHECK(r->status == 200);
        REQUIRE(h.attempt_calls.size() == 1);
        REQUIRE(h.rules_at_attempt.size() == 1);
        CHECK(h.rules_at_attempt[0].value == "*.corp");
        CHECK(h.rules_at_attempt[0].enabled);
        CHECK_FALSE(h.mode_at_attempt);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].result == "success");
        // ... and the write did happen afterwards.
        const std::string name = w.name;
        if (name == "add")
            CHECK(h.auto_approve.list_rules().size() == 2);
        else if (name == "mode")
            CHECK(h.auto_approve.require_all());
        else if (name == "toggle")
            CHECK_FALSE(h.auto_approve.list_rules()[0].enabled);
        else
            CHECK(h.auto_approve.list_rules().empty());
    }
}

TEST_CASE("settings auto-approve: a failed policy write is a 500 with an error outcome row and no "
          "change",
          "[settings_routes][enrollment][auto_approve][audit]") {
    for (const auto& w : auto_approve_writes()) {
        INFO(w.name);
        EnrollRoutesHarness h(/*with_store=*/false);
        REQUIRE(h.auto_approve.add_rule(
            {auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true}));
        // From here every write fails: the directory of the config path does not exist.
        h.auto_approve.load(std::filesystem::temp_directory_path() /
                            "yuzu_test_no_such_dir_auto_approve_route" / "aa.cfg");
        // load() of a missing file leaves the in-memory rule alone (returns false).
        REQUIRE(h.auto_approve.list_rules().size() == 1);

        auto r = w.run(h);
        REQUIRE(r);
        CHECK(r->status == 500);
        CHECK(nlohmann::json::parse(r->body)["error"]["code"] == 500);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == w.action);
        CHECK(h.audit_calls[0].result == "error");
        const auto rules = h.auto_approve.list_rules();
        REQUIRE(rules.size() == 1);
        CHECK(rules[0].enabled);
        CHECK_FALSE(h.auto_approve.require_all());
    }
}

TEST_CASE("settings auto-approve: a cross-site write is refused before any audit attempt or change",
          "[settings_routes][enrollment][auto_approve][csrf]") {
    // Same helper as the MFA POSTs: a request naming another site is a 403; one with neither
    // Origin nor Referer is a non-browser client (curl / automation) and passes.
    const std::unordered_map<std::string, std::string> cross_site[] = {
        {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}},
        {{"Host", "yuzu.test"}, {"Referer", "https://evil.test/page"}},
    };
    for (const auto& hdrs : cross_site) {
        for (const auto& w : auto_approve_writes()) {
            INFO(w.name);
            EnrollRoutesHarness h(/*with_store=*/false);
            REQUIRE(h.auto_approve.add_rule(
                {auth::AutoApproveRuleType::hostname_glob, "*.corp", "corp", true}));
            h.sink.default_headers = hdrs;
            auto r = w.run(h);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(h.attempt_calls.empty());
            REQUIRE(h.audit_calls.size() == 1);
            CHECK(h.audit_calls[0].action == "csrf.denied");
            const auto rules = h.auto_approve.list_rules();
            REQUIRE(rules.size() == 1);
            CHECK(rules[0].enabled);
            CHECK_FALSE(h.auto_approve.require_all());
        }
    }
}

TEST_CASE("settings auto-approve: caller text cannot forge adjacent audit fields",
          "[settings_routes][enrollment][auto_approve][audit]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    // Spaces and '=' pass validation (they are legal in a glob); the audit detail must not
    // let them open a second `k=v` pair.
    auto r = h.sink.Post("/api/settings/auto-approve",
                         "type=hostname_glob&value=x+result%3Ddenied+by%3Dother&label=a+b%3Dc",
                         kForm);
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto row = h.only("enrollment.auto_approve.rule_add");
    CHECK(row.detail.find("result=denied") == std::string::npos);
    CHECK(row.detail.find("by=other") == std::string::npos);
    CHECK(row.detail.find("by=admin") != std::string::npos);
    CHECK(h.attempt_calls.at(0).detail == row.detail);

    h.audit_calls.clear();
    REQUIRE(h.sink.Delete("/api/settings/auto-approve/0")->status == 200);
    const auto rm = h.only("enrollment.auto_approve.rule_remove");
    CHECK(rm.detail.find("result=denied") == std::string::npos);
    CHECK(rm.detail.find("by=other") == std::string::npos);
}

TEST_CASE("settings auto-approve: match-everything rules and oversized text are refused",
          "[settings_routes][enrollment][auto_approve]") {
    EnrollRoutesHarness h(/*with_store=*/false);
    const std::string big(auth::kMaxRuleValueLen + 1, 'a');
    const std::string biglabel(auth::kMaxRuleLabelLen + 1, 'b');
    for (const std::string body :
         {std::string("type=hostname_glob&value=*&label=x"),
          std::string("type=ip_subnet&value=0.0.0.0%2F0&label=x"),
          "type=hostname_glob&value=" + big + "&label=x",
          "type=hostname_glob&value=ok&label=" + biglabel}) {
        INFO(body.substr(0, 60));
        h.audit_calls.clear();
        auto r = h.sink.Post("/api/settings/auto-approve", body, kForm);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(h.only("enrollment.auto_approve.rule_add").result == "denied");
    }
    CHECK(h.auto_approve.list_rules().empty());
    CHECK(h.attempt_calls.empty());
}

// A lapsed token cannot be minted without waiting out a TTL, so the store row's expiry is
// pushed into the past the way test_auth.cpp does for the consume path. It must list Expired
// (neutral pill), not Active; an exhausted-and-lapsed token keeps Exhausted, and a token that
// never expires stays Active.
TEST_CASE("settings enrollment: a lapsed token is listed as Expired and never as Active",
          "[pg][settings_routes][enrollment]") {
    EnrollRoutesHarness h;
    auto lapsed = h.auth_mgr.create_enrollment_token("lapsed-one", 0, std::chrono::hours(1), "admin");
    REQUIRE(lapsed.has_value());
    auto never = h.auth_mgr.create_enrollment_token("never-one", 0, std::chrono::seconds(0), "admin");
    REQUIRE(never.has_value());
    {
        auto lease = h.auth_db->pool().try_acquire_for(std::chrono::seconds(2));
        REQUIRE(lease);
        auto upd = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE auth.enrollment_tokens SET expires_at = now() - interval '1 hour' "
            "WHERE token_id = $1",
            std::vector<std::string>{lapsed->token_id});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    auto res = h.sink.Get("/fragments/settings/tokens");
    REQUIRE(res);
    // The pill that follows a row's id cell.
    const auto pill_of = [&](const std::string& id) {
        const auto row = res->body.find("<code>" + id + "</code>");
        REQUIRE(row != std::string::npos);
        const auto pill = res->body.find("role-badge ", row);
        REQUIRE(pill != std::string::npos);
        return res->body.substr(pill, res->body.find("</span>", pill) - pill);
    };
    CHECK(pill_of(lapsed->token_id) == "role-badge role-user\">Expired");
    CHECK(pill_of(never->token_id) == "role-badge role-admin\">Active");
    CHECK(res->body.find("role-ok") == std::string::npos);
}

// The pure decision behind that pill, with the clock injected: no Postgres, no TTL wait.
TEST_CASE("settings enrollment: enrollment_token_expired compares expiry with the injected now",
          "[settings_routes][enrollment]") {
    using clock = std::chrono::system_clock;
    const auto now = clock::time_point{std::chrono::seconds(1'800'000'000)};
    CHECK_FALSE(enrollment_token_expired((clock::time_point::max)(), now)); // never expires
    CHECK(enrollment_token_expired(now - std::chrono::hours(1), now));
    CHECK(enrollment_token_expired(now, now)); // the consume path needs expires_at > now()
    CHECK_FALSE(enrollment_token_expired(now + std::chrono::seconds(1), now));
}
