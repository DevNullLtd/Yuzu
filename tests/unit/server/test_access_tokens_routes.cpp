/**
 * @file test_access_tokens_routes.cpp
 * @brief HTTP-level coverage of access_tokens_routes.{hpp,cpp}, driven in-process through
 *        TestRouteSink. Every closure is injected, counted and re-read per call.
 *
 * Pinned, in order of consequence:
 *   - the token filter: "" (every owner) only for a cookie administrator; an MCP-tier admin
 *     session gets its own tokens (mutation probe: drop the `mcp_tier.empty()` clause);
 *   - an empty session username can never reach the every-owner filter;
 *   - the loud admin gate and the engine belt run BEFORE any principal store read;
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

#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

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
    bool admin_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;
    int admin_calls{0};
    // audit
    bool audit_ok{true};
    std::vector<std::string> audit_actions;
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
    std::expected<std::string, std::string> revoke_detail{std::string{}};
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
        d.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (admin_allow)
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            perm_calls.emplace_back(t, o);
            if (perm_allow)
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
            audit_actions.push_back(action);
            return audit_ok;
        };
        d.rbac_enforced_fn = [] { return false; };
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
        d.revoke_detail_fn = [this](const std::string&) { return revoke_detail; };
        return d;
    }
    void wire() { access_tokens::register_access_tokens_routes(sink, deps()); }
};

} // namespace

TEST_CASE("tokens routes: registration fails fast when any dependency is unbound",
          "[access-tokens][routes]") {
    using Member = std::function<void(access_tokens::Deps&)>;
    const std::vector<Member> unbind = {
        [](auto& d) { d.auth_fn = nullptr; },       [](auto& d) { d.admin_fn = nullptr; },
        [](auto& d) { d.perm_fn = nullptr; },       [](auto& d) { d.audit_fn = nullptr; },
        [](auto& d) { d.rbac_enforced_fn = nullptr; }, [](auto& d) { d.now_fn = nullptr; },
        [](auto& d) { d.list_tokens_fn = nullptr; }, [](auto& d) { d.list_principals_fn = nullptr; },
        [](auto& d) { d.all_roles_fn = nullptr; },  [](auto& d) { d.get_principal_fn = nullptr; },
        [](auto& d) { d.active_credentials_fn = nullptr; },
        [](auto& d) { d.principal_roles_fn = nullptr; },
        [](auto& d) { d.revoke_detail_fn = nullptr; },
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
    CHECK(h.admin_calls == 0);
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
        CHECK(h.admin_calls == 0);
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

TEST_CASE("principals routes: the admin gate and the engine belt run before any read",
          "[access-tokens][routes]") {
    for (const char* path : {"/fragments/access/principals/list",
                             "/fragments/access/principals/detail?id=engine:bot"}) {
        INFO(path);
        {
            Harness h;
            h.admin_allow = false;
            h.wire();
            const auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(res->body == kDenyBody);
            CHECK(h.principal_list_calls == 0);
            CHECK(h.get_calls.empty());
            CHECK(h.audit_actions.empty());
        }
        for (const char* shape : {"principal_kind", "auth_source"}) {
            Harness h;
            if (std::string(shape) == "principal_kind")
                h.session.principal_kind = "engine";
            else
                h.session.auth_source = "engine_token";
            h.wire();
            const auto res = h.sink.dispatch("GET", path);
            REQUIRE(res);
            INFO(shape);
            CHECK(res->status == 403);
            CHECK(h.principal_list_calls == 0);
            CHECK(h.get_calls.empty());
            CHECK(h.audit_actions.size() == 1);  // the denial is recorded
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
    CHECK(h.audit_actions == std::vector<std::string>{"engine_principal.list"});
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
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
    d.revoke_detail_fn = [&](const std::string&) -> std::expected<std::string, std::string> {
        ++calls;
        return std::string("credentials_revoked=1");
    };
    yuzu::server::test::TestRouteSink s2;
    access_tokens::register_access_tokens_routes(s2, d);
    auto res = s2.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(calls == 1);
    CHECK_THAT(res->body, ContainsSubstring("credentials_revoked=1"));

    h.got = std::optional<EnginePrincipalRow>{principal("bot", "active")};
    res = s2.dispatch("GET", "/fragments/access/principals/detail?id=engine:bot");
    REQUIRE(res);
    CHECK(calls == 1);
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

TEST_CASE("tokens routes: server.cpp binds the real admin gate, rbac view and checked reads",
          "[access-tokens][routes]") {
    // Every case above stubs the gate and would pass with a permissive lambda; pin the wiring.
    namespace fs = std::filesystem;
    fs::path p = fs::path(__FILE__).parent_path();
    for (int i = 0; i < 6 && !fs::exists(p / "server/core/src/server.cpp"); ++i)
        p = p.parent_path();
    const fs::path src = p / "server/core/src/server.cpp";
    REQUIRE(fs::exists(src));
    std::ifstream in(src, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto at = text.find("register_access_tokens_routes(");
    REQUIRE(at != std::string::npos);
    const auto end = text.find("revoke_detail_fn", at);
    REQUIRE(end != std::string::npos);
    const std::string blk = text.substr(at, end - at);
    CHECK_THAT(blk, ContainsSubstring("return require_admin(req, res);"));
    CHECK_THAT(blk, ContainsSubstring("rbac_enforcement_in_effect(rbac_store_.get())"));
    CHECK_THAT(blk, ContainsSubstring("list_all_checked(true)"));
    CHECK_THAT(blk, ContainsSubstring("list_active_for_principal_checked(id)"));
    CHECK_THAT(blk, ContainsSubstring("list_all_principal_roles_checked()"));
    CHECK_THAT(blk, ContainsSubstring("get_principal_roles_checked(\"engine\", id)"));
    CHECK_THAT(blk, ContainsSubstring(".perm_fn = perm_fn"));
    CHECK_THAT(text.substr(end, 1500), ContainsSubstring("committed_revoke_detail(*events)"));
}
