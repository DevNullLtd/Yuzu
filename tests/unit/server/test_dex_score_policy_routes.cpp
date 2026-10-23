/**
 * test_dex_score_policy_routes.cpp -- the GET / PUT / DELETE /api/v1/dex/score-policy route
 * shell, driven in-process through TestRouteSink with the writer deps faked: the unwired 503,
 * gate pinning, session-bound audit attribution, the same-site gate, If-Match and dry_run
 * answers, ETag semantics, and the fail-closed audit and outcome-unknown 503s. The apply
 * function's own cases are in test_dex_score_policy_writer.cpp. No store, no sleeps, no I/O.
 */
#include "dex_score_policy_writer.hpp"
#include "rest_api_v1.hpp"

#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

constexpr const char* kPath = "/api/v1/dex/score-policy";

std::string doc_with_excellent(double e) {
    DexScorePolicy p;
    p.tiers.edges.excellent = e;
    return dex_score_policy_canonical(p);
}

struct Row {
    std::string via; // "session" or "fn"
    std::string principal, role, action, result, target_type, target_id, detail;
};

struct Harness {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink; // after the owner (test_route_sink.hpp invariant 1)

    // The fake store.
    std::optional<std::string> stored;
    bool read_fails{false};  // the store cannot be read
    std::string store_error; // non-empty: compare-and-set applies, then reports this
    int cas_calls{0};
    std::shared_ptr<DexScorePolicyProvider> provider;

    // The seams.
    std::vector<std::pair<std::string, std::string>> perm_calls;
    bool perm_allow{true};
    std::string auth_source{"api_token"};
    std::vector<Row> rows;
    std::string refuse_result; // an audit result the audit store refuses

    explicit Harness(bool wire_writer = true, bool wire_session_writer = true) {
        provider = std::make_shared<DexScorePolicyProvider>(
            [this]() -> std::expected<std::optional<std::string>, std::string> { return stored; },
            [] { return std::int64_t{1'000'000}; }, std::chrono::milliseconds{1});
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};

        RestApiV1::AuthFn auth_fn = [this](const httplib::Request&,
                                           httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "alice";
            s.role = auth::Role::admin;
            s.auth_source = auth_source;
            return s;
        };
        RestApiV1::PermFn perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                           const std::string& type, const std::string& op) {
            perm_calls.emplace_back(type, op);
            if (!perm_allow) {
                res.status = 403;
                return false;
            }
            return true;
        };
        RestApiV1::AuditFn audit_fn = [this](const httplib::Request&, const std::string& action,
                                             const std::string& result,
                                             const std::string& target_type,
                                             const std::string& target_id,
                                             const std::string& detail) {
            rows.push_back({"fn", "", "", action, result, target_type, target_id, detail});
            return true;
        };
        if (wire_session_writer)
            api.set_audit_as_session_fn(
                [this](const httplib::Request&, const auth::Session& s, const std::string& role,
                       const std::string& action, const std::string& result,
                       const std::string& target_type, const std::string& target_id,
                       const std::string& detail) {
                    if (!refuse_result.empty() && result == refuse_result)
                        return false;
                    rows.push_back({"session", s.username, role, action, result, target_type,
                                    target_id, detail});
                    return true;
                });
        if (wire_writer) {
            DexScorePolicyWriteDeps d;
            d.read_stored = [this]() -> std::expected<std::optional<std::string>, std::string> {
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
                if (!store_error.empty()) {
                    // applied, then another writer replaced it before the re-read
                    stored = doc_with_excellent(70.0);
                    return std::unexpected(store_error);
                }
                stored = canonical;
                return true;
            };
            d.compare_and_remove = [this](const std::string& expected)
                -> std::expected<bool, std::string> {
                if (stored != expected)
                    return false;
                stored.reset();
                return true;
            };
            d.provider = provider;
            api.set_dex_score_policy_writer(std::move(d));
        }
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr);
    }

    std::unique_ptr<httplib::Response>
    send(const std::string& method, const std::string& target, const std::string& body = {},
         std::unordered_map<std::string, std::string> headers = {}) {
        auto res = sink.dispatch(method, target, body, "application/json", headers);
        REQUIRE(res);
        return res;
    }
    static std::unordered_map<std::string, std::string> if_match(const std::string& v) {
        return {{"If-Match", v}};
    }
};

std::string etag_of(const std::string& rev) { return "\"" + rev + "\""; }

} // namespace

TEST_CASE("score-policy routes: with no writer wired all three answer 503 with an A4 body",
          "[server][routes][dex][score_policy]") {
    Harness h(/*wire_writer=*/false);
    for (const char* method : {"GET", "PUT", "DELETE"}) {
        INFO(method);
        const auto res = h.send(method, kPath, "{}", Harness::if_match("default"));
        CHECK(res->status == 503);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["message"] == "runtime config store unavailable");
        CHECK(j["error"]["retry_after_ms"] == 2000);
        CHECK(j["error"].contains("correlation_id"));
    }
    CHECK(h.rows.empty());
}

TEST_CASE("score-policy routes: the permission gates are pinned and short-circuit",
          "[server][routes][dex][score_policy]") {
    Harness h;
    h.send("GET", kPath);
    h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"));
    h.send("DELETE", kPath, {}, Harness::if_match("default"));
    REQUIRE(h.perm_calls.size() == 3);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"GuaranteedState", "Read"});
    CHECK(h.perm_calls[1] == std::pair<std::string, std::string>{"Infrastructure", "Write"});
    CHECK(h.perm_calls[2] == std::pair<std::string, std::string>{"Infrastructure", "Write"});

    Harness denied;
    denied.perm_allow = false;
    for (const char* method : {"GET", "PUT", "DELETE"})
        CHECK(denied.send(method, kPath, "{}", Harness::if_match("default"))->status == 403);
    CHECK(denied.rows.empty());
    CHECK(denied.cas_calls == 0);
}

TEST_CASE("score-policy routes: GET returns the policy in force with its ETag and no audit row",
          "[server][routes][dex][score_policy]") {
    Harness h;
    SECTION("nothing stored") {
        const auto res = h.send("GET", kPath);
        CHECK(res->status == 200);
        const auto j = json::parse(res->body);
        CHECK(j["data"]["revision"] == "default");
        CHECK(j["data"]["source"] == "default");
        CHECK_FALSE(j["data"].contains("fault"));
        CHECK(res->get_header_value("ETag") == "\"default\"");
        CHECK(j["data"]["document"]["version"] == 1);
    }
    SECTION("a stored policy") {
        h.stored = doc_with_excellent(95.0);
        const auto res = h.send("GET", kPath);
        const auto j = json::parse(res->body);
        const std::string rev = dex_score_policy_revision(*h.stored);
        CHECK(j["data"]["revision"] == rev);
        CHECK(j["data"]["source"] == "custom");
        CHECK(res->get_header_value("ETag") == etag_of(rev));
        CHECK(j["data"]["document"]["tiers"]["edges"]["excellent"] == 95.0);
    }
    SECTION("a stored invalid text: defaults with the fault, and its own revision") {
        h.stored = R"({"version":2})";
        const auto res = h.send("GET", kPath);
        const auto j = json::parse(res->body);
        CHECK(j["data"]["source"] == "default");
        CHECK(j["data"]["fault"] == "unsupported_version at version: 2 above the supported 1");
        CHECK(j["data"]["revision"] == dex_score_policy_revision(*h.stored));
    }
    SECTION("an unreadable store is a 503 with retry_after_ms, never a default policy") {
        h.read_fails = true;
        const auto res = h.send("GET", kPath);
        CHECK(res->status == 503);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["message"] == "runtime config store unavailable");
        CHECK(j["error"]["retry_after_ms"] == 2000);
        CHECK_FALSE(j.contains("data"));
        CHECK(res->get_header_value("ETag").empty());
    }
    CHECK(h.rows.empty());
}

TEST_CASE("score-policy routes: every write row is stamped from the resolved session",
          "[server][routes][dex][score_policy]") {
    Harness h;
    h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"));
    h.send("PUT", kPath, "{}", Harness::if_match("default")); // stale now: denied
    h.send("PUT", kPath, doc_with_excellent(96.0), Harness::if_match("default"));
    h.send("DELETE", kPath, {}, Harness::if_match("default"));
    REQUIRE_FALSE(h.rows.empty());
    auth::Session expect;
    expect.role = auth::Role::admin;
    for (const auto& r : h.rows) {
        INFO(r.action << "/" << r.result);
        CHECK(r.via == "session");
        CHECK(r.principal == "alice");
        CHECK(r.role == auth::role_to_string(auth::effective_role(expect)));
        CHECK(r.target_type == "RuntimeConfig");
        CHECK(r.target_id == "dex_score_policy");
    }
}

TEST_CASE("score-policy routes: an unwired session writer is a 500 with one failure row",
          "[server][routes][dex][score_policy]") {
    Harness h(/*wire_writer=*/true, /*wire_session_writer=*/false);
    for (const char* method : {"PUT", "DELETE"}) {
        h.rows.clear();
        const auto res =
            h.send(method, kPath, doc_with_excellent(95.0), Harness::if_match("default"));
        CHECK(res->status == 500);
        CHECK(json::parse(res->body)["error"]["message"] == "audit identity writer not configured");
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].via == "fn");
        CHECK(h.rows[0].result == "failure");
    }
    CHECK(h.cas_calls == 0);
}

TEST_CASE("score-policy routes: a cross-site cookie write is refused with csrf.denied",
          "[server][routes][dex][score_policy]") {
    Harness h;
    h.auth_source = "local"; // a cookie session
    h.sink.default_headers["Origin"] = "https://evil.test";
    const auto res = h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"));
    CHECK(res->status == 403);
    CHECK(json::parse(res->body)["error"]["message"] == "cross-site request refused");
    REQUIRE(h.rows.size() == 1);
    CHECK(h.rows[0].action == "csrf.denied");
    CHECK(h.rows[0].target_id == "dex_score_policy");
    CHECK(h.rows[0].via == "session");
    CHECK(h.cas_calls == 0);

    SECTION("a token session is exempt") {
        h.auth_source = "api_token";
        h.rows.clear();
        CHECK(h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"))
                  ->status == 200);
    }
}

TEST_CASE("score-policy routes: If-Match and dry_run refusals",
          "[server][routes][dex][score_policy]") {
    Harness h;
    SECTION("no If-Match is 428 naming the header") {
        const auto res = h.send("PUT", kPath, doc_with_excellent(95.0));
        CHECK(res->status == 428);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find("If-Match") !=
              std::string::npos);
    }
    SECTION("If-Match: * is 400 naming the header") {
        const auto res = h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("*"));
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find("If-Match") !=
              std::string::npos);
    }
    SECTION("dry_run=yes is 400 naming dry_run, with one denied row") {
        const auto res = h.send("PUT", std::string(kPath) + "?dry_run=yes",
                                doc_with_excellent(95.0), Harness::if_match("default"));
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find("dry_run") !=
              std::string::npos);
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].result == "denied");
        CHECK(json::parse(h.rows[0].detail)["field"] == "dry_run");
    }
    SECTION("a stale If-Match is 409") {
        h.stored = doc_with_excellent(90.0);
        CHECK(h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"))
                  ->status == 409);
    }
    SECTION("two If-Match headers are refused like a list, with one denied row") {
        // The sink's header maps hold one value per name, so the second header goes in under
        // another spelling of the name (httplib compares header names without case).
        h.sink.default_headers["If-Match"] = "default";
        h.sink.default_headers["if-match"] = "default";
        const auto res = h.send("PUT", kPath, doc_with_excellent(95.0));
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["message"] == "If-Match: send exactly one revision");
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].result == "denied");
        CHECK(json::parse(h.rows[0].detail)["reason"] == "if_match_malformed");
    }
    SECTION("two dry_run parameters are refused, with one denied row") {
        // (httplib itself collapses a repeat of an identical name=value pair, so the two differ)
        const auto res = h.send("PUT", std::string(kPath) + "?dry_run=true&dry_run=false",
                                doc_with_excellent(95.0), Harness::if_match("default"));
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["message"] == "dry_run must be true or false");
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].result == "denied");
        CHECK(json::parse(h.rows[0].detail)["field"] == "dry_run");
    }
    CHECK(h.cas_calls == 0);
}

TEST_CASE("score-policy routes: PUT happy path answers 200 with the new revision and ETag",
          "[server][routes][dex][score_policy]") {
    Harness h;
    const std::string body = doc_with_excellent(95.0);
    const std::string rev = dex_score_policy_revision(body);
    const auto res = h.send("PUT", kPath, body, Harness::if_match("\"default\""));
    CHECK(res->status == 200);
    const auto j = json::parse(res->body);
    CHECK(j["data"]["revision"] == rev);
    CHECK(j["data"]["previous_revision"] == "default");
    CHECK(j["data"]["source"] == "custom");
    CHECK(j["data"]["document"] == json::parse(body));
    CHECK_FALSE(j["data"].contains("dry_run"));
    CHECK(res->get_header_value("ETag") == etag_of(rev));
    REQUIRE(h.rows.size() == 2);
    CHECK(h.rows[0].action == "dex.score_policy.update");
    CHECK(h.rows[0].result == "attempted");
    CHECK(h.rows[1].result == "success");
    CHECK(h.stored == body);
}

TEST_CASE("score-policy routes: a dry run's ETag is the current revision and not the would-be one",
          "[server][routes][dex][score_policy]") {
    Harness h;
    h.stored = doc_with_excellent(90.0);
    const std::string current = dex_score_policy_revision(*h.stored);
    const std::string body = doc_with_excellent(95.0);
    const auto res = h.send("PUT", std::string(kPath) + "?dry_run=true", body,
                            Harness::if_match(current));
    CHECK(res->status == 200);
    const auto j = json::parse(res->body);
    CHECK(j["data"]["dry_run"] == true);
    CHECK(j["data"]["revision"] == dex_score_policy_revision(body));
    CHECK(j["data"]["previous_revision"] == current);
    CHECK(res->get_header_value("ETag") == etag_of(current));
    REQUIRE(h.rows.size() == 1);
    CHECK(h.rows[0].action == "dex.score_policy.validate");
    CHECK(h.stored == doc_with_excellent(90.0));
    CHECK(h.cas_calls == 0);
}

TEST_CASE("score-policy routes: DELETE", "[server][routes][dex][score_policy]") {
    Harness h;
    SECTION("dry_run is refused with a denied row") {
        const auto res = h.send("DELETE", std::string(kPath) + "?dry_run=true", {},
                                Harness::if_match("default"));
        CHECK(res->status == 400);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find("dry_run") !=
              std::string::npos);
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].action == "dex.score_policy.reset");
        CHECK(h.rows[0].result == "denied");
    }
    SECTION("removing a stored policy answers 200 with revision default") {
        h.stored = doc_with_excellent(90.0);
        const std::string prior = dex_score_policy_revision(*h.stored);
        const auto res = h.send("DELETE", kPath, {}, Harness::if_match(prior));
        CHECK(res->status == 200);
        const auto j = json::parse(res->body);
        CHECK(j["data"]["revision"] == "default");
        CHECK(j["data"]["previous_revision"] == prior);
        CHECK(res->get_header_value("ETag") == "\"default\"");
        CHECK_FALSE(h.stored);
    }
    SECTION("removing nothing is idempotent") {
        const auto res = h.send("DELETE", kPath, {}, Harness::if_match("default"));
        CHECK(res->status == 200);
        CHECK(res->get_header_value("ETag") == "\"default\"");
        REQUIRE(h.rows.size() == 2);
        CHECK(h.rows[1].result == "no_change");
    }
}

TEST_CASE("score-policy routes: a refused audit row is a fail-closed 503 with Sec-Audit-Failed",
          "[server][routes][dex][score_policy]") {
    Harness h;
    SECTION("the attempted row") {
        h.refuse_result = "attempted";
        const auto res =
            h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"));
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(json::parse(res->body)["error"]["retry_after_ms"] == 5000);
        CHECK(h.cas_calls == 0);
    }
    SECTION("the dry-run validate row") {
        h.refuse_result = "success";
        const auto res = h.send("PUT", std::string(kPath) + "?dry_run=true",
                                doc_with_excellent(95.0), Harness::if_match("default"));
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(json::parse(res->body)["error"]["retry_after_ms"] == 5000);
    }
    SECTION("a refused outcome row after a committed write keeps the 200") {
        h.refuse_result = "success";
        const std::string body = doc_with_excellent(95.0);
        const auto res = h.send("PUT", kPath, body, Harness::if_match("default"));
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.stored == body);
        CHECK(json::parse(res->body)["data"]["revision"] == dex_score_policy_revision(body));
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].result == "attempted");
    }
}

TEST_CASE("score-policy routes: an ambiguous outcome is a 503 that names the stored revision",
          "[server][routes][dex][score_policy]") {
    Harness h;
    h.store_error = std::string(kDbErrorPrefix) + "database write failed";
    const auto res = h.send("PUT", kPath, doc_with_excellent(95.0), Harness::if_match("default"));
    CHECK(res->status == 503);
    const auto j = json::parse(res->body);
    CHECK(j["error"]["retry_after_ms"] == 2000);
    CHECK(j["error"]["remediation"].get<std::string>().find("GET") != std::string::npos);
    const std::string msg = j["error"]["message"];
    CHECK(msg.find(dex_score_policy_revision(doc_with_excellent(70.0))) != std::string::npos);
    CHECK(msg.find("not changed") == std::string::npos);
}
