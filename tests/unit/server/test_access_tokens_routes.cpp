/**
 * @file test_access_tokens_routes.cpp
 * @brief HTTP-level coverage of access_tokens_routes.{hpp,cpp}, driven in-process through
 *        TestRouteSink. Every closure is injected, counted and re-read per call.
 *
 * Pinned, in order of consequence:
 *   - the token filter: "" (every owner) only for a cookie administrator; an MCP-tier admin
 *     session gets its own tokens (mutation probe: drop the `mcp_tier.empty()` clause);
 *   - an empty session username can never reach the every-owner filter;
 *   - the EnginePrincipal:Read gate and the engine/MCP belt run BEFORE any principal store read;
 *   - an unanswered store is a 200 red box, never an empty table, and its text is log-only;
 *   - a malformed principal id costs no store read;
 *   - fragment audit rows match the REST twin's verbs, and a dropped row sets Sec-Audit-Failed
 *     while the fragment still renders;
 *   - the page makes no gate call and no store read of its own;
 *   - `register_access_tokens_routes` binds the REAL `require_admin` (source scan of
 *     server.cpp), because every case here stubs the gate.
 */

#include "access_tokens_render.hpp"
#include "access_tokens_routes.hpp"
#include "access_tokens_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuCss;
} // namespace yuzu::server

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;

namespace {

constexpr const char* kDenyBody = R"({"error":{"code":403,"message":"admin role required"}})";

ApiToken tok(std::string id, std::string owner) {
    ApiToken t;
    t.token_id = std::move(id);
    t.name = "n-" + t.token_id;
    t.principal_id = std::move(owner);
    return t;
}

EnginePrincipalRow principal(std::string slug, std::string state = "active") {
    EnginePrincipalRow p;
    p.principal_id = "engine:" + slug;
    p.display_name = slug;
    p.owner_username = "alice";
    p.lifecycle_state = std::move(state);
    return p;
}

// `sink` is LAST: its handlers capture `this` and must not outlive the other members.
struct Harness {
    // session
    bool session_present{true};
    auth::Session session;
    // gates
    bool perm_allow{true};
    std::set<std::string> perm_deny;  // "Securable:Op" refused even when perm_allow
    int revoke_calls{0};
    std::vector<std::pair<std::string, std::string>> perm_calls;
    // audit
    bool audit_ok{true};
    std::vector<std::string> audit_actions;
    std::vector<std::string> audit_details;
    // reads
    std::vector<std::string> token_filters;
    std::expected<std::vector<ApiToken>, std::string> tokens{
        std::vector<ApiToken>{tok("aaa", "alice"), tok("bbb", "bob")}};
    int principal_list_calls{0};
    std::expected<std::vector<EnginePrincipalRow>, std::string> principals{
        std::vector<EnginePrincipalRow>{principal("bot")}};
    std::expected<std::vector<PrincipalRole>, std::string> all_roles{std::vector<PrincipalRole>{}};
    std::vector<std::string> get_calls;
    std::expected<std::optional<EnginePrincipalRow>, std::string> got{principal("bot")};
    std::expected<std::vector<ApiToken>, std::string> creds{std::vector<ApiToken>{}};
    std::expected<std::vector<PrincipalRole>, std::string> roles{std::vector<PrincipalRole>{}};
    std::expected<access_tokens::RevokeDetail, std::string> revoke_detail{access_tokens::RevokeDetail{}};
    bool rbac{false};  // RBAC view shown to the page (write controls follow it)
    std::expected<std::vector<std::string>, std::string> custom_roles{std::vector<std::string>{}};
    yuzu::server::test::TestRouteSink sink;

    Harness() {
        session.username = "alice";
        session.role = auth::Role::admin;
        session.auth_source = "local";
    }

    access_tokens::Deps deps() {
        access_tokens::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            return session;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            perm_calls.emplace_back(t, o);
            if (perm_allow && !perm_deny.contains(t + ":" + o))
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action, const std::string&,
                            const std::string&, const std::string&, const std::string& detail) {
            audit_actions.push_back(action);
            audit_details.push_back(detail);
            return audit_ok;
        };
        d.rbac_enforced_fn = [this] { return rbac; };
        d.now_fn = [] { return std::int64_t{1'800'000'000}; };
        d.list_tokens_fn = [this](const std::string& filter) {
            token_filters.push_back(filter);
            return tokens;
        };
        d.list_principals_fn = [this]() {
            ++principal_list_calls;
            return principals;
        };
        d.all_roles_fn = [this]() { return all_roles; };
        d.get_principal_fn = [this](const std::string& id) {
            get_calls.push_back(id);
            return got;
        };
        d.active_credentials_fn = [this](const std::string&) { return creds; };
        d.principal_roles_fn = [this](const std::string&) { return roles; };
        d.revoke_detail_fn = [this](const std::string&) {
            ++revoke_calls;
            return revoke_detail;
        };
        d.custom_roles_fn = [this]() { return custom_roles; };
        return d;
    }
    void wire() { access_tokens::register_access_tokens_routes(sink, deps()); }
};

} // namespace

TEST_CASE("tokens routes: registration fails fast when any dependency is unbound",
          "[access-tokens][routes]") {
    using Member = std::function<void(access_tokens::Deps&)>;
    const std::vector<Member> unbind = {
        [](auto& d) { d.auth_fn = nullptr; },
        [](auto& d) { d.perm_fn = nullptr; },       [](auto& d) { d.audit_fn = nullptr; },
        [](auto& d) { d.rbac_enforced_fn = nullptr; }, [](auto& d) { d.now_fn = nullptr; },
        [](auto& d) { d.list_tokens_fn = nullptr; }, [](auto& d) { d.list_principals_fn = nullptr; },
        [](auto& d) { d.all_roles_fn = nullptr; },  [](auto& d) { d.get_principal_fn = nullptr; },
        [](auto& d) { d.active_credentials_fn = nullptr; },
        [](auto& d) { d.principal_roles_fn = nullptr; },
        [](auto& d) { d.revoke_detail_fn = nullptr; },
        [](auto& d) { d.custom_roles_fn = nullptr; },
    };
    for (const auto& f : unbind) {
        Harness h;
        auto d = h.deps();
        f(d);
        CHECK_THROWS_AS(access_tokens::register_access_tokens_routes(h.sink, d), std::invalid_argument);
    }
}

TEST_CASE("tokens routes: the page redirects without a session and makes no gate or store call",
          "[access-tokens][routes]") {
    Harness h;
    h.wire();
    h.session_present = false;
    auto res = h.sink.dispatch("GET", "/access/tokens");
    REQUIRE(res);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login");

    h.session_present = true;
    res = h.sink.dispatch("GET", "/access/tokens");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("/fragments/access/tokens/list"));
    CHECK(h.perm_calls.empty());
    CHECK(h.token_filters.empty());
    CHECK(h.principal_list_calls == 0);
}

TEST_CASE("tokens routes: the token filter is every-owner only for a cookie administrator",
          "[access-tokens][routes]") {
    struct Case {
        const char* name;
        std::function<void(auth::Session&)> shape;
        std::string expected_filter;
        const char* expected_flag;
    };
    const std::vector<Case> cases = {
        {"cookie admin", [](auto&) {}, "", "data-effective-admin=\"1\""},
        {"plain user", [](auth::Session& s) { s.role = auth::Role::user; }, "alice",
         "data-effective-admin=\"0\""},
        // Mutation probe: dropping the mcp_tier.empty() clause in sees_all_owners fails this.
        {"admin MCP readonly token", [](auth::Session& s) { s.mcp_tier = "readonly"; s.auth_source = "mcp_token"; },
         "alice", "data-effective-admin=\"0\""},
        {"admin session carrying a tier only", [](auth::Session& s) { s.mcp_tier = "operator"; }, "alice",
         "data-effective-admin=\"0\""},
        {"admin service-scoped", [](auth::Session& s) { s.token_scope_service = "billing"; }, "alice",
         "data-effective-admin=\"0\""},
        {"admin API bearer", [](auth::Session& s) { s.auth_source = "api_token"; }, "alice",
         "data-effective-admin=\"0\""},
    };
    for (const auto& c : cases) {
        INFO(c.name);
        Harness h;
        c.shape(h.session);
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(h.token_filters.size() == 1);
        CHECK(h.token_filters[0] == c.expected_filter);
        CHECK_THAT(res->body, ContainsSubstring(c.expected_flag));
        // The ApiToken:Read gate ran first, and it is the only gate on this fragment.
        REQUIRE(h.perm_calls.size() == 1);
        CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"ApiToken", "Read"});
    }
}

TEST_CASE("tokens routes: an empty username never reaches the every-owner filter",
          "[access-tokens][routes]") {
    Harness h;
    h.session.role = auth::Role::user;
    h.session.username.clear();
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(h.token_filters.empty());
}

TEST_CASE("tokens routes: a denied or unauthenticated caller costs no store read",
          "[access-tokens][routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body == kDenyBody);
    CHECK(h.token_filters.empty());

    h.perm_allow = true;
    h.session_present = false;
    res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.token_filters.empty());
}

TEST_CASE("tokens routes: state is exactly 'all' or active; the fragment is not cacheable",
          "[access-tokens][routes]") {
    Harness h;
    auto revoked = tok("rev", "alice");
    revoked.revoked = true;
    h.tokens = std::vector<ApiToken>{tok("act", "alice"), revoked};
    h.wire();

    auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_THAT(res->body, ContainsSubstring("act</span>"));
    CHECK_THAT(res->body, !ContainsSubstring("rev</span>"));

    for (const char* junk : {"?state=ALL", "?state=1", "?state=all%27"}) {
        res = h.sink.dispatch("GET", std::string("/fragments/access/tokens/list") + junk);
        REQUIRE(res);
        CHECK_THAT(res->body, !ContainsSubstring("rev</span>"));
    }
    res = h.sink.dispatch("GET", "/fragments/access/tokens/list?state=all");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("rev</span>"));
}

TEST_CASE("tokens routes: an unanswered token store is a 200 red box and its text is log-only",
          "[access-tokens][routes]") {
    Harness h;
    h.tokens = std::unexpected(std::string("pq: connection refused at 10.0.0.5"));
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(res->body, !ContainsSubstring("<table"));
    CHECK_THAT(res->body, !ContainsSubstring("connection refused"));
    CHECK_THAT(res->body, ContainsSubstring("data-effective-admin=\"1\""));
    CHECK(h.audit_actions.empty());  // token reads write no audit row (as the twin)
}

TEST_CASE("principals routes: the EnginePrincipal:Read gate and the engine/MCP belt run before any read",
          "[access-tokens][routes]") {
    for (const char* path : {"/fragments/access/principals/list",
                             "/fragments/access/principals/detail?id=engine:bot"}) {
        INFO(path);
        {
            Harness h;
            h.perm_deny.insert("EnginePrincipal:Read");
            h.wire();
            const auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(res->body == kDenyBody);
            // The EnginePrincipal securable is the only gate asked (not the account role).
            CHECK(h.perm_calls ==
                  std::vector<std::pair<std::string, std::string>>{{"EnginePrincipal", "Read"}});
            CHECK(h.principal_list_calls == 0);
            CHECK(h.get_calls.empty());
            CHECK(h.audit_actions.empty());
        }
        for (const char* shape : {"principal_kind", "auth_source", "mcp_tier"}) {
            Harness h;
            if (std::string(shape) == "principal_kind")
                h.session.principal_kind = "engine";
            else if (std::string(shape) == "auth_source")
                h.session.auth_source = "engine_token";
            else
                h.session.mcp_tier = "readonly";  // an admin-owned MCP bearer that holds the grant
            h.wire();
            const auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            INFO(shape);
            CHECK(res->status == 403);
            CHECK(h.principal_list_calls == 0);
            CHECK(h.get_calls.empty());
            CHECK(h.audit_actions.size() == 1);  // the denial is recorded
            // The A4 envelope (correlation id in body and header), not a hand-built string.
            CHECK_THAT(res->body, ContainsSubstring("this credential cannot access this endpoint"));
            CHECK_THAT(res->body, ContainsSubstring("\"correlation_id\""));
            CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
            CHECK(h.audit_details.at(0) ==
                  (std::string(shape) == "mcp_tier" ? "mcp_session_denied" : "engine_session_denied"));
        }
    }
}

TEST_CASE("principals routes: list renders, audits the twin's verb and reads once",
          "[access-tokens][routes]") {
    Harness h;
    h.all_roles = std::vector<PrincipalRole>{{"engine", "engine:bot", "Reader"}};
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/principals/list");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK_THAT(res->body, ContainsSubstring("data-count=\"1\""));
    CHECK_THAT(res->body, ContainsSubstring("Reader"));
    CHECK(h.principal_list_calls == 1);
    // The Roles column is a bulk privilege enumeration and is audited as the REST twin does.
    CHECK(h.audit_actions ==
          std::vector<std::string>{"engine_principal.list", "engine_principal.role.listed"});
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
}

TEST_CASE("principals routes: the list is newest first so the 500 cap keeps the newest",
          "[access-tokens][routes]") {
    Harness h;
    h.principals = std::vector<EnginePrincipalRow>{principal("oldest"), principal("middle"),
                                                   principal("newest")};
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/principals/list");
    REQUIRE(res);
    const auto a = res->body.find("data-principal-id=\"engine:newest\"");
    const auto b = res->body.find("data-principal-id=\"engine:middle\"");
    const auto c = res->body.find("data-principal-id=\"engine:oldest\"");
    REQUIRE(a != std::string::npos);
    CHECK(a < b);
    CHECK(b < c);
}

TEST_CASE("principals routes: a dropped audit row sets Sec-Audit-Failed and still renders",
          "[access-tokens][routes]") {
    Harness h;
    h.audit_ok = false;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/principals/list");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_THAT(res->body, ContainsSubstring("data-count=\"1\""));
}

TEST_CASE("principals routes: unanswered stores degrade to a fixed sentence, never to empty",
          "[access-tokens][routes]") {
    {
        Harness h;
        h.principals = std::unexpected(std::string("pq: relation engine_principals missing"));
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/list");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("relation"));
        CHECK_THAT(res->body, !ContainsSubstring("No engine principals."));
        CHECK(h.audit_actions.empty());  // no success row for a read that did not happen
    }
    {
        Harness h;
        h.all_roles = std::unexpected(std::string("rbac down"));
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/list");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("Not shown"));
        CHECK_THAT(res->body, !ContainsSubstring("rbac down"));
        CHECK_THAT(res->body, !ContainsSubstring("<td>None</td>"));
        // No role enumeration happened, so none is audited.
        CHECK(h.audit_actions == std::vector<std::string>{"engine_principal.list"});
    }
}

TEST_CASE("principals routes: a malformed id is a placeholder and costs no store read",
          "[access-tokens][routes]") {
    Harness h;
    h.wire();
    for (const char* q : {"", "?id=", "?id=engine:", "?id=bot", "?id=engine:A", "?id=engine:a%2Fb",
                          "?id=user:alice",
                          // dot segments and query smuggling: the charset has no '/', '?', '#'
                          "?id=engine:./bulk-approve%3F", "?id=engine:../x", "?id=engine:..%2Fx",
                          "?id=engine:a%3Fb", "?id=engine:a%23b", "?id=engine:a%00b",
                          "?id=engine:a%5Cb"}) {
        INFO(q);
        const auto res =
            h.sink.dispatch("GET", std::string("/fragments/access/principals/detail") + q);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("Select a principal from the list."));
    }
    CHECK(h.get_calls.empty());
    CHECK(h.audit_actions.empty());
}

TEST_CASE("principals routes: detail is found, missing or unreadable", "[access-tokens][routes]") {
    {
        Harness h;
        h.roles = std::vector<PrincipalRole>{{"engine", "engine:bot", "Reader"}};
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("Reader"));
        CHECK(h.get_calls == std::vector<std::string>{"engine:bot"});
        CHECK(h.audit_actions ==
              std::vector<std::string>{"engine_principal.get", "engine_principal.role.listed"});
    }
    {
        Harness h;
        h.got = std::optional<EnginePrincipalRow>{};
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("This principal no longer exists."));
        CHECK(h.audit_actions.empty());
    }
    {
        Harness h;
        h.got = std::unexpected(std::string("pq: boom"));
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring(access_tokens::kDetailUnavailable));
        CHECK_THAT(res->body, !ContainsSubstring("boom"));
    }
    {
        // Roles unreadable: the get row is still audited, the role-listed row is not (no roles
        // were disclosed), and the panel says so instead of "No roles."
        Harness h;
        h.roles = std::unexpected(std::string("rbac down"));
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("Roles could not be read."));
        CHECK(h.audit_actions == std::vector<std::string>{"engine_principal.get"});
    }
}

TEST_CASE("principals routes: the revoke audit lookup runs for revoked principals only",
          "[access-tokens][routes]") {
    int calls = 0;
    Harness h;
    h.got = std::optional<EnginePrincipalRow>{principal("bot", "revoked")};
    h.wire();
    // Active: no lookup. (Counted through a wrapper registered on a second sink.)
    auto d = h.deps();
    d.revoke_detail_fn = [&](const std::string&) -> std::expected<access_tokens::RevokeDetail, std::string> {
        ++calls;
        return access_tokens::RevokeDetail{"credentials_revoked=1", true};
    };
    yuzu::server::test::TestRouteSink s2;
    access_tokens::register_access_tokens_routes(s2, d);
    auto res = s2.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(calls == 1);
    CHECK_THAT(res->body, ContainsSubstring("credentials_revoked=1"));
    CHECK_THAT(res->body, ContainsSubstring("oldest success among the newest 200"));  // truncated flag carried

    h.got = std::optional<EnginePrincipalRow>{principal("bot", "active")};
    res = s2.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(calls == 1);
}

TEST_CASE("principals routes: the audit trail's text and the REST check need AuditLog:Read",
          "[access-tokens][routes]") {
    Harness h;
    h.got = std::optional<EnginePrincipalRow>{principal("bot", "revoked")};
    h.revoke_detail = access_tokens::RevokeDetail{"operator typed reason", false};
    h.perm_deny.insert("AuditLog:Read");
    h.wire();
    // Without AuditLog:Read the detail is withheld and the audit store is not asked.
    auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("withheld: needs the AuditLog:Read permission, or it could not be confirmed"));
    CHECK_THAT(res->body, !ContainsSubstring("operator typed reason"));
    // ... and the list tells the script not to call the loud REST check.
    res = h.sink.dispatch("GET", "/fragments/access/principals/list");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("data-check=\"0\""));

    CHECK(h.revoke_calls == 0);  // the audit store is not asked at all

    h.perm_deny.clear();
    res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("operator typed reason"));
    res = h.sink.dispatch("GET", "/fragments/access/principals/list");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("data-check=\"1\""));
}

TEST_CASE("principals routes: an unanswered audit store for the revoke detail is unavailable not withheld",
          "[access-tokens][routes]") {
    Harness h;
    h.got = std::optional<EnginePrincipalRow>{principal("bot", "revoked")};
    h.revoke_detail = std::unexpected(std::string("audit down"));
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("(unavailable)"));
    CHECK_THAT(res->body, !ContainsSubstring("withheld"));
    CHECK_THAT(res->body, !ContainsSubstring("audit down"));
    CHECK(h.revoke_calls == 1);
}

TEST_CASE("tokens routes: the static glue is served uncached as JavaScript",
          "[access-tokens][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/static/yuzu-tokens.js");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/javascript; charset=utf-8");
    CHECK_THAT(res->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    CHECK_THAT(res->body, ContainsSubstring("principal-select"));
}

TEST_CASE("tokens routes: server.cpp binds the quiet probe, rbac view and checked reads",
          "[access-tokens][routes]") {
    // Every case above stubs the gate and would pass with a permissive lambda; pin the wiring.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    namespace fs = std::filesystem;
    const fs::path src = fs::path(YUZU_SERVER_SRC_DIR) / "server.cpp";
    REQUIRE(fs::exists(src));
    std::ifstream in(src, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto at = text.find("register_access_tokens_routes(");
    REQUIRE(at != std::string::npos);
    const auto end = text.find("revoke_detail_fn", at);
    REQUIRE(end != std::string::npos);
    const std::string blk = text.substr(at, end - at);
    CHECK_THAT(blk, ContainsSubstring(".perm_fn = draw_perm_fn"));
    CHECK_THAT(blk, !ContainsSubstring("require_admin"));
    CHECK_THAT(blk, ContainsSubstring("rbac_enforcement_in_effect(rbac_store_.get())"));
    CHECK_THAT(blk, ContainsSubstring("list_all_checked(true)"));
    CHECK_THAT(blk, ContainsSubstring("list_active_for_principal_checked(id)"));
    CHECK_THAT(blk, ContainsSubstring("list_all_principal_roles_checked()"));
    CHECK_THAT(blk, ContainsSubstring("get_principal_roles_checked(\"engine\", id)"));
    CHECK_THAT(text.substr(end, 1500), ContainsSubstring("revoke_detail_from(std::move(*events))"));
    // One row past the window, or `truncated` could never be set (the 201/200 boundary).
    CHECK_THAT(text.substr(end, 1500),
               ContainsSubstring("q.limit = yuzu::server::access_tokens::kRevokeHistoryQueryLimit"));
}

// The fragments are swapped into #tokens-body / #principals-body, so their header and body are
// not direct children of .panel and the `.panel > .hd` / `.panel > .pb` rules never match them.
// Without these rules the panel header stacks (title, owner label, toggle in a column).
TEST_CASE("tokens page: the header and body rules reach the swapped fragment bodies",
          "[access-tokens][css]") {
    const auto& css = yuzu::server::kYuzuCss;
    const auto at = css.find("/* -- Tokens page");
    REQUIRE(at != std::string::npos);
    const auto end = css.find("/* -- end Tokens page", at);
    REQUIRE(end != std::string::npos);
    const std::string block = css.substr(at, end - at);
    for (const char* sel : {":is(#tokens-body, #principals-body) > .hd {",
                            ":is(#tokens-body, #principals-body) > .hd h2 {",
                            ":is(#tokens-body, #principals-body) > .hd .sub {",
                            ":is(#tokens-body, #principals-body) > .hd .end {",
                            ":is(#tokens-body, #principals-body) > .pb {"})
        CHECK_THAT(block, ContainsSubstring(sel));
    // Both bodies the rules name exist in the page template.
    CHECK_THAT(std::string(::kAccessTokensHtml),
               ContainsSubstring("id=\"tokens-body\""));
    CHECK_THAT(std::string(::kAccessTokensHtml),
               ContainsSubstring("id=\"principals-body\""));
}

// ---- write controls: what each fragment decides to draw, and the gates it runs first --------

namespace {

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

} // namespace

TEST_CASE("tokens routes: RBAC off - controls follow the account role and no probe is made",
          "[access-tokens][routes][writes]") {
    {
        Harness h;  // effective administrator: everything, and the owner's own rotate
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("data-tk=\"token-new\""));
        CHECK_THAT(res->body, ContainsSubstring("data-tk=\"token-revoke\""));
        CHECK_THAT(res->body, ContainsSubstring("data-tk=\"token-rotate\""));
        // The only gate call is the read gate itself: no write probe when RBAC is off.
        REQUIRE(h.perm_calls.size() == 1);
        CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"ApiToken", "Read"});
    }
    {
        Harness h;  // plain user, RBAC off: ApiToken:Rotate is the one self-service action
        h.session.role = auth::Role::user;
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
        REQUIRE(res);
        CHECK_THAT(res->body, !ContainsSubstring("token-new"));
        CHECK_THAT(res->body, !ContainsSubstring("token-revoke"));
        CHECK_THAT(res->body, ContainsSubstring("data-tk=\"token-rotate\""));
        CHECK_THAT(res->body, ContainsSubstring("Creating tokens needs an Administrator browser session."));
        CHECK(h.perm_calls.size() == 1);
    }
}

TEST_CASE("tokens routes: RBAC on - one probe per permission per render, results decide the controls",
          "[access-tokens][routes][writes]") {
    Harness h;
    h.rbac = true;
    h.perm_deny = {"ApiToken:Write", "ApiToken:Rotate"};
    h.tokens = std::vector<ApiToken>{tok("aaa", "alice"), tok("bbb", "alice"), tok("ccc", "alice")};
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/tokens/list");
    REQUIRE(res);
    // The read gate, then exactly one probe per permission - not one per row.
    const std::vector<std::pair<std::string, std::string>> expect{
        {"ApiToken", "Read"}, {"ApiToken", "Write"}, {"ApiToken", "Delete"}, {"ApiToken", "Rotate"}};
    CHECK(h.perm_calls == expect);
    // A refused probe is a scratch response: the real one stays 200 and carries the fragment.
    CHECK(res->status == 200);
    CHECK_THAT(res->body, !ContainsSubstring("token-new"));
    CHECK_THAT(res->body, !ContainsSubstring("token-rotate"));
    CHECK(count_of(res->body, "data-tk=\"token-revoke\"") == 3);
    CHECK_THAT(res->body, ContainsSubstring("Creating tokens needs the ApiToken:Write permission."));
}

TEST_CASE("tokens routes: every fragment is never cached and varies on the cookie",
          "[access-tokens][routes][writes]") {
    Harness h;
    h.wire();
    for (const char* url : {"/fragments/access/tokens/list", "/fragments/access/principals/list",
                            "/fragments/access/principals/detail?id=engine:bot"}) {
        INFO(url);
        const auto res = h.sink.dispatch("GET", url);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Cache-Control") == "no-store, private");
        CHECK(res->get_header_value("Vary") == "Cookie");
    }
}

TEST_CASE("principals routes: capability is a Security:Write probe only when RBAC is enforced",
          "[access-tokens][routes][writes]") {
    {
        Harness h;  // RBAC off: the EnginePrincipal:Read floor already proved the role - no Security:Write probe
        h.wire();
        const auto list = h.sink.dispatch("GET", "/fragments/access/principals/list");
        const auto det = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(list);
        REQUIRE(det);
        CHECK_THAT(list->body, ContainsSubstring("data-tk=\"principal-new\""));
        CHECK_THAT(det->body, ContainsSubstring("data-tk=\"principal-mint\""));
        CHECK(std::ranges::count(h.perm_calls, std::pair<std::string, std::string>{"Security", "Write"}) == 0);
    }
    {
        Harness h;  // RBAC on, Security:Write granted: the controls are drawn after exactly one probe each
        h.rbac = true;
        h.wire();
        const auto list = h.sink.dispatch("GET", "/fragments/access/principals/list");
        const auto det = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(list);
        REQUIRE(det);
        CHECK_THAT(list->body, ContainsSubstring("data-tk=\"principal-new\""));
        CHECK_THAT(det->body, ContainsSubstring("data-tk=\"principal-mint\""));
        CHECK(std::ranges::count(h.perm_calls, std::pair<std::string, std::string>{"Security", "Write"}) == 2);
    }
    {
        Harness h;
        h.rbac = true;
        h.perm_deny.insert("Security:Write");
        h.wire();
        const auto list = h.sink.dispatch("GET", "/fragments/access/principals/list");
        const auto det = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
        REQUIRE(list);
        REQUIRE(det);
        CHECK_THAT(list->body, !ContainsSubstring("principal-new"));
        CHECK_THAT(det->body, !ContainsSubstring("principal-mint"));
        CHECK_THAT(det->body, ContainsSubstring("Changing principals needs the Security:Write permission."));
        // One probe per fragment render, nothing per row.
        CHECK(std::ranges::count(h.perm_calls, std::pair<std::string, std::string>{"Security", "Write"}) == 2);
        CHECK(list->status == 200);
        CHECK(det->status == 200);
    }
}

TEST_CASE("principals routes: Assign offers custom roles only; an unreadable role list disables it",
          "[access-tokens][routes][writes]") {
    Harness h;
    h.custom_roles = std::vector<std::string>{"Auditor"};
    h.wire();
    auto res = h.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("<option value=\"Auditor\">Auditor</option>"));

    Harness bad;
    bad.custom_roles = std::unexpected(std::string("rbac exploded"));
    bad.wire();
    res = bad.sink.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("disabled title=\"The role list could not be read."));
    CHECK_THAT(res->body, !ContainsSubstring("No custom roles exist"));
    CHECK_THAT(res->body, !ContainsSubstring("exploded"));
}

TEST_CASE("tokens routes: the write glue is served uncached as JavaScript", "[access-tokens][routes][writes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/static/yuzu-tokens-actions.js");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/javascript; charset=utf-8");
    CHECK_THAT(res->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    CHECK_THAT(res->body, ContainsSubstring("reveal-stored"));
}
