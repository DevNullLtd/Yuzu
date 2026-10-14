/**
 * @file test_access_tokens_render.cpp
 * @brief Pure-renderer coverage for access_tokens_render.{hpp,cpp}: every state is built from
 *        a fixture value, nothing touches a store, a clock or a socket.
 *
 * Pinned, in order of consequence:
 *   - an unanswered read is a fixed sentence and never "no tokens" / "no roles" / `0`;
 *   - a hostile string in any store-sourced field is escaped in every cell it can reach;
 *   - the store's own error text is not renderable (there is no parameter that carries it);
 *   - which sessions get the all-owner view (cookie admin only, never a bearer or tier);
 *   - the principal id charset is closed before any store read.
 */

#include "access_tokens_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access_tokens;

namespace {

constexpr std::int64_t kNow = 1'800'000'000;
const std::string kXss = "<img src=x onerror=1>\"'&";

ApiToken tok(std::string id, std::string name = "ci", std::string owner = "alice") {
    ApiToken t;
    t.token_id = std::move(id);
    t.name = std::move(name);
    t.principal_id = std::move(owner);
    t.created_at = kNow - 1000;
    return t;
}

TokensView view(std::vector<ApiToken> rows, bool all_owners = true, bool show_all = false) {
    TokensView v;
    v.rows = std::move(rows);
    v.all_owners = all_owners;
    v.show_all = show_all;
    return v;
}

PageFlags flags(bool admin = true, bool rbac = false) { return {kNow, admin, rbac}; }

EnginePrincipalRow principal(std::string slug, std::string state = "active") {
    EnginePrincipalRow p;
    p.principal_id = "engine:" + slug;
    p.display_name = slug;
    p.owner_username = "alice";
    p.classification = "internal";
    p.lifecycle_state = std::move(state);
    p.created_at = kNow - 5000;
    return p;
}

} // namespace

TEST_CASE("tokens render: the root carries the caller facts the page script keys on",
          "[access-tokens][render]") {
    const auto html = render_tokens_list(view({tok("aaa")}), flags(true, true));
    CHECK_THAT(html, ContainsSubstring("data-now=\"1800000000\""));
    CHECK_THAT(html, ContainsSubstring("data-effective-admin=\"1\""));
    CHECK_THAT(html, ContainsSubstring("data-rbac-enforced=\"1\""));
    const auto plain = render_tokens_list(view({tok("aaa")}, false), flags(false, false));
    CHECK_THAT(plain, ContainsSubstring("data-effective-admin=\"0\""));
    CHECK_THAT(plain, ContainsSubstring("data-rbac-enforced=\"0\""));
    // Even a failed read keeps the flags: the principals panel decision does not depend on it.
    const auto bad = render_tokens_list(Unavailable{}, flags(true));
    CHECK_THAT(bad, ContainsSubstring("data-effective-admin=\"1\""));
}

TEST_CASE("tokens render: an unanswered store is a red box, never an empty state",
          "[access-tokens][render]") {
    const auto html = render_tokens_list(Unavailable{}, flags());
    CHECK_THAT(html, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(html, ContainsSubstring(kTokensUnavailable));
    CHECK_THAT(html, ContainsSubstring("data-tk=\"reload\""));
    CHECK_THAT(html, !ContainsSubstring("<table"));
    CHECK_THAT(html, !ContainsSubstring("You have no API tokens"));
    CHECK_THAT(html, !ContainsSubstring("No API tokens"));
}

TEST_CASE("tokens render: honest empty states per audience and view", "[access-tokens][render]") {
    CHECK_THAT(render_tokens_list(view({}, false), flags(false)),
               ContainsSubstring("You have no API tokens."));
    CHECK_THAT(render_tokens_list(view({}, true), flags(true)), ContainsSubstring("No API tokens."));

    // Only revoked rows in the Active view: say so and offer All, do not claim there are none.
    auto revoked = tok("rrr");
    revoked.revoked = true;
    const auto html = render_tokens_list(view({revoked}), flags());
    CHECK_THAT(html, ContainsSubstring("No active API tokens."));
    CHECK_THAT(html, ContainsSubstring("data-state=\"all\""));
    // ...and All shows it.
    const auto all = render_tokens_list(view({revoked}, true, true), flags());
    CHECK_THAT(all, ContainsSubstring("rrr"));
    CHECK_THAT(all, ContainsSubstring("Revoked"));
}

TEST_CASE("tokens render: status and type cover rotation, expiry and engine credentials",
          "[access-tokens][render]") {
    auto expired = tok("exp");
    expired.expires_at = kNow - 1;
    auto rotating = tok("rot");
    rotating.overlap_expires_at = kNow + 3600;
    rotating.rotation_group = "g1";
    auto successor = tok("suc");
    successor.supersedes_token_id = "rot";
    auto mcp = tok("mcp");
    mcp.mcp_tier = "operator";
    auto eng = tok("eng", "cred", "engine:bot");
    eng.principal_kind = "engine";
    auto scoped = tok("scp");
    scoped.scope_service = "billing";

    const auto html =
        render_tokens_list(view({expired, rotating, successor, mcp, eng, scoped}, true, true), flags());
    CHECK_THAT(html, ContainsSubstring("Expired"));
    CHECK_THAT(html, ContainsSubstring("Rotating, retires"));
    CHECK_THAT(html, ContainsSubstring("Awaiting confirmation"));
    CHECK_THAT(html, ContainsSubstring("MCP operator"));
    CHECK_THAT(html, ContainsSubstring("Engine"));
    CHECK_THAT(html, ContainsSubstring("scoped to billing"));
    // Active view hides the expired row but keeps the rest.
    const auto active = render_tokens_list(view({expired, rotating}), flags());
    CHECK_THAT(active, !ContainsSubstring("exp</span>"));
    CHECK_THAT(active, ContainsSubstring("rot</span>"));
}

TEST_CASE("tokens render: read-only means no action control of any kind", "[access-tokens][render]") {
    auto t = tok("aaa");
    t.supersedes_token_id = "bbb";
    const auto html = render_tokens_list(view({t, tok("bbb")}), flags(true, true));
    for (const char* bad : {"Revoke", "Rotate", "Confirm rotation", "New API token", "hx-delete",
                            "hx-post", "<form", "<input"})
        CHECK_THAT(html, !ContainsSubstring(bad));
}

TEST_CASE("tokens render: hostile strings are escaped in every cell they reach",
          "[access-tokens][render]") {
    auto t = tok("id1", kXss, kXss);
    t.mcp_tier = "readonly";
    t.scope_service = kXss;
    const auto html = render_tokens_list(view({t}), flags());
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

TEST_CASE("tokens render: a capped list says how many exist", "[access-tokens][render]") {
    std::vector<ApiToken> rows;
    for (std::size_t i = 0; i < kRenderCap + 7; ++i)
        rows.push_back(tok("t" + std::to_string(i)));
    const auto html = render_tokens_list(view(std::move(rows)), flags());
    CHECK_THAT(html, ContainsSubstring("Showing the newest 500 of 507 tokens."));
    CHECK_THAT(html, ContainsSubstring("t499</span>"));
    CHECK_THAT(html, !ContainsSubstring("t500</span>"));
}

TEST_CASE("principals render: roles column is None, a list, or Not shown, never blank",
          "[access-tokens][render]") {
    PrincipalsView v;
    v.rows = {principal("a"), principal("b"), principal("c")};
    v.roles = std::vector<PrincipalRole>{{"engine", "engine:a", "Reader"},
                                         {"user", "engine:b", "Admin"},  // wrong principal type
                                         {"engine", "engine:a", "Auditor"}};
    const auto html = render_principals_list(v);
    CHECK_THAT(html, ContainsSubstring("Reader, Auditor"));
    CHECK_THAT(html, ContainsSubstring("<td>None</td>"));
    CHECK_THAT(html, !ContainsSubstring("Admin"));

    v.roles = Unavailable{};
    const auto degraded = render_principals_list(v);
    CHECK_THAT(degraded, ContainsSubstring("Not shown"));
    CHECK_THAT(degraded, !ContainsSubstring("<td>None</td>"));
}

TEST_CASE("principals render: unavailable, empty, revoked and selection control",
          "[access-tokens][render]") {
    const auto bad = render_principals_list(Unavailable{});
    CHECK_THAT(bad, ContainsSubstring(kPrincipalsUnavailable));
    CHECK_THAT(bad, ContainsSubstring("data-count=\"\""));  // the page must not run the strip
    CHECK_THAT(bad, !ContainsSubstring("No engine principals."));

    PrincipalsView none;
    none.roles = std::vector<PrincipalRole>{};
    CHECK_THAT(render_principals_list(none), ContainsSubstring("No engine principals."));

    PrincipalsView v;
    auto gone = principal("old", "revoked");
    gone.superseded_by = "engine:new";
    v.rows = {principal("live"), gone, principal("lost", "revoked")};
    v.roles = std::vector<PrincipalRole>{};
    const auto html = render_principals_list(v);
    CHECK_THAT(html, ContainsSubstring("data-count=\"3\""));
    CHECK_THAT(html, ContainsSubstring("superseded by engine:new"));
    CHECK_THAT(html, ContainsSubstring("no successor recorded"));
    // Selection is a real button carrying the id in a data attribute.
    CHECK_THAT(html, ContainsSubstring("<button type=\"button\" class=\"btn link\" "
                                       "data-tk=\"principal-select\" data-principal-id=\"engine:live\""));
}

TEST_CASE("principal detail: states and revoked block", "[access-tokens][render]") {
    CHECK_THAT(render_principal_detail(NotFound{}, "engine:x"),
               ContainsSubstring("This principal no longer exists."));
    const auto bad = render_principal_detail(Unavailable{}, "engine:x");
    CHECK_THAT(bad, ContainsSubstring(kDetailUnavailable));
    CHECK_THAT(bad, ContainsSubstring("data-principal-id=\"engine:x\""));
    CHECK_THAT(render_select_principal(), ContainsSubstring("Select a principal from the list."));

    PrincipalDetail d;
    d.row = principal("gone", "revoked");
    d.row.revoked_at = kNow - 10;
    d.credentials = std::vector<ApiToken>{};
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = std::string("credentials_revoked=2");
    d.now = kNow;
    auto html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("credentials_revoked=2"));
    CHECK_THAT(html, ContainsSubstring("No active credentials."));
    CHECK_THAT(html, ContainsSubstring("No roles."));

    d.revoke_detail = std::string{};
    CHECK_THAT(render_principal_detail(d, d.row.principal_id), ContainsSubstring("(not recorded)"));
    d.revoke_detail = Unavailable{};
    CHECK_THAT(render_principal_detail(d, d.row.principal_id), ContainsSubstring("(unavailable)"));
}

TEST_CASE("principal detail: unreadable credentials and roles are not 'none'",
          "[access-tokens][render]") {
    PrincipalDetail d;
    d.row = principal("live");
    d.credentials = Unavailable{};
    d.roles = Unavailable{};
    d.revoke_detail = std::string{};
    const auto html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("Credentials could not be read."));
    CHECK_THAT(html, ContainsSubstring("Roles could not be read."));
    CHECK_THAT(html, !ContainsSubstring("No active credentials."));
    CHECK_THAT(html, !ContainsSubstring("No roles."));
}

TEST_CASE("principal detail: hostile strings are escaped; no action controls", "[access-tokens][render]") {
    PrincipalDetail d;
    d.row = principal("x");
    d.row.display_name = kXss;
    d.row.owner_username = kXss;
    d.row.justification = kXss;
    d.row.created_by = kXss;
    ApiToken c = tok("c1", kXss);
    c.supersedes_token_id = "c0";
    d.credentials = std::vector<ApiToken>{c};
    d.roles = std::vector<PrincipalRole>{{"engine", d.row.principal_id, kXss}};
    d.revoke_detail = std::string{};
    const auto html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, ContainsSubstring("Awaiting confirmation"));
    for (const char* bad : {"Mint", "Rotate", "Revoke principal", "Transfer", "Assign role", "<form"})
        CHECK_THAT(html, !ContainsSubstring(bad));
}

TEST_CASE("principal id charset is closed before any store read", "[access-tokens][render]") {
    CHECK(valid_principal_id("engine:patch-bot"));
    CHECK(valid_principal_id("engine:a.b_c-1"));
    CHECK(valid_principal_id("engine:" + std::string(128, 'a')));
    CHECK_FALSE(valid_principal_id("engine:" + std::string(129, 'a')));
    for (const char* bad : {"", "engine:", "patch-bot", "engine:Upper", "engine:a b", "engine:a/b",
                            "engine:a#b", "engine:../x", "user:alice", "engine:a\n"})
        CHECK_FALSE(valid_principal_id(bad));
    CHECK_FALSE(valid_principal_id(std::string("engine:a\0b", 10)));
}

TEST_CASE("all-owner view is for a cookie administrator only", "[access-tokens][render]") {
    auth::Session admin;
    admin.username = "root";
    admin.role = auth::Role::admin;
    admin.auth_source = "local";
    CHECK(sees_all_owners(admin));

    auto user = admin;
    user.role = auth::Role::user;
    CHECK_FALSE(sees_all_owners(user));

    // Each narrowing clause is independently sufficient (so dropping any one fails here).
    auto tier = admin;
    tier.mcp_tier = "readonly";
    CHECK_FALSE(sees_all_owners(tier));
    auto svc = admin;
    svc.token_scope_service = "billing";
    CHECK_FALSE(sees_all_owners(svc));
    auto eng = admin;
    eng.principal_kind = "engine";
    CHECK_FALSE(sees_all_owners(eng));
    for (const char* src : {"api_token", "mcp_token", "engine_token"}) {
        auto b = admin;
        b.auth_source = src;
        INFO(src);
        CHECK_FALSE(sees_all_owners(b));
    }
}

TEST_CASE("legacy stored ids never become a URL, a path or an attribute other than data-principal-id",
          "[access-tokens][render][urlsafety]") {
    // Rows written before the creation charset existed (or by a future writer) can hold any
    // string. The id must reach the DOM only as an escaped data-* value; the page script
    // percent-encodes it into a query. No renderer emits an hx-* verb or an href.
    const std::vector<std::string> ids = {"engine:./bulk-approve?", "engine:../x", "engine:a/b/../c",
                                          "engine:a\"onmouseover=\"1", "engine:a b#c"};
    PrincipalsView pv;
    for (const auto& id : ids) {
        EnginePrincipalRow r = principal("x");
        r.principal_id = id;
        r.display_name = id;
        pv.rows.push_back(r);
    }
    pv.roles = std::vector<PrincipalRole>{};
    const auto list = render_principals_list(pv);
    for (const char* bad : {"hx-", "href", "<a ", "action=", "onmouseover=\"1", "src="}) {
        INFO(bad);
        CHECK_THAT(list, !ContainsSubstring(bad));
    }
    CHECK_THAT(list, ContainsSubstring("data-principal-id=\"engine:./bulk-approve?\""));
    CHECK_THAT(list, ContainsSubstring("engine:a&quot;onmouseover=&quot;1"));

    for (const auto& id : ids) {
        PrincipalDetail d;
        d.row = principal("x");
        d.row.principal_id = id;
        d.credentials = std::vector<ApiToken>{};
        d.roles = std::vector<PrincipalRole>{};
        d.revoke_detail = std::string{};
        const auto detail = render_principal_detail(d, id);
        const auto retry = render_principal_detail(Unavailable{}, id);
        for (const auto* html : {&detail, &retry}) {
            CHECK_THAT(*html, !ContainsSubstring("hx-"));
            CHECK_THAT(*html, !ContainsSubstring("href"));
            CHECK_THAT(*html, !ContainsSubstring("onmouseover=\"1"));
        }
    }
}

TEST_CASE("token rows render metadata only: hash, rotation group and initiator never appear",
          "[access-tokens][render][secrets]") {
    auto t = tok("tid123", "ci");
    t.token_hash = "SECRETHASHVALUE";
    t.rotation_group = "ROTGROUPVALUE";
    t.rotation_initiator = "INITIATORVALUE";
    t.supersedes_token_id = "tidOLD";
    t.mcp_tier = "operator";
    PrincipalDetail d;
    d.row = principal("bot");
    d.credentials = std::vector<ApiToken>{t};
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = std::string{};
    d.now = kNow;
    const std::string html = render_tokens_list(view({t}), flags()) +
                             render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("tid123"));
    for (const char* secret : {"SECRETHASHVALUE", "ROTGROUPVALUE", "INITIATORVALUE", "token_hash"})
        CHECK_THAT(html, !ContainsSubstring(secret));
}
