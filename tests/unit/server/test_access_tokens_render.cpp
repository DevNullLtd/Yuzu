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
#include "web_utils.hpp"

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
    auto elapsed = tok("ovr");
    elapsed.overlap_expires_at = kNow - 60;
    elapsed.rotation_group = "g2";
    const auto late = render_tokens_list(view({elapsed}), flags());
    CHECK_THAT(late, ContainsSubstring("Overlap ended, still valid until retired"));
    CHECK_THAT(late, !ContainsSubstring("Rotating, retires"));
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

    // Withheld is its own state (never "not recorded"); it hides the text it was handed.
    d.revoke_detail = Withheld{};
    html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("withheld: needs the AuditLog:Read permission"));
    CHECK_THAT(html, !ContainsSubstring("(not recorded)"));
    CHECK_THAT(html, !ContainsSubstring("oldest success"));

    // A full history window says the detail may not be the original.
    d.revoke_detail = std::string("credentials_revoked=0 (retry)");
    d.revoke_truncated = true;
    html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("credentials_revoked=0 (retry)"));
    CHECK_THAT(html, ContainsSubstring("oldest success among the newest 200"));
}

TEST_CASE("principals render: data-check tells the script whether to run the REST check",
          "[access-tokens][render]") {
    PrincipalsView v;
    v.rows = {principal("live")};
    v.roles = std::vector<PrincipalRole>{};
    CHECK_THAT(render_principals_list(v), ContainsSubstring("data-check=\"0\""));
    v.can_run_check = true;
    CHECK_THAT(render_principals_list(v), ContainsSubstring("data-check=\"1\""));
    CHECK_THAT(render_principals_list(Unavailable{}), ContainsSubstring("data-check=\"0\""));
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

TEST_CASE("principal surfaces show display name, revoke date and credential creation; the list caps at 500",
          "[access-tokens][render]") {
    PrincipalDetail d;
    d.row = principal("old", "revoked");
    d.row.display_name = "Patch Bot";
    d.row.revoked_at = kNow - 100;
    ApiToken c = tok("c1");
    c.created_at = kNow - 4000;
    d.credentials = std::vector<ApiToken>{c};
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = std::string{};
    d.now = kNow;
    const auto detail = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(detail, ContainsSubstring("<span>Display name</span><b>Patch Bot</b>"));
    CHECK_THAT(detail, ContainsSubstring("<th>Created</th>"));
    CHECK_THAT(detail, ContainsSubstring(format_iso_utc(kNow - 4000).substr(0, 10)));

    PrincipalsView v;
    v.roles = std::vector<PrincipalRole>{};
    auto gone = principal("old", "revoked");
    gone.revoked_at = kNow - 100;
    v.rows = {gone};
    CHECK_THAT(render_principals_list(v), ContainsSubstring("revoked <span title=\"" + format_iso_utc(kNow - 100)));

    PrincipalsView big;
    big.roles = std::vector<PrincipalRole>{};
    for (int i = 0; i < 501; ++i)
        big.rows.push_back(principal("p" + std::to_string(i)));
    const auto html = render_principals_list(big);
    CHECK_THAT(html, ContainsSubstring("Showing the newest 500 of 501 principals."));
    CHECK_THAT(html, ContainsSubstring("engine:p499"));
    CHECK_THAT(html, !ContainsSubstring("data-principal-id=\"engine:p500\""));
}

TEST_CASE("revoke detail is the newest committed revoke; a later failure's error text is never used",
          "[access-tokens][render]") {
    AuditEvent fail;
    fail.result = "failure";
    fail.detail = "pq: db_error=secret-marker";
    AuditEvent denied;
    denied.result = "denied";
    denied.detail = "denied-marker";
    AuditEvent ok;
    ok.result = "success";
    ok.detail = "credentials_revoked=2";
    AuditEvent older;
    older.result = "success";
    older.detail = "older-success";
    // Newest first: the original revoke is the OLDEST success (an idempotent retry on a revoked
    // principal writes a newer success row with credentials_revoked=0).
    ok.detail = "credentials_revoked=0 (retry)";
    older.detail = "credentials_revoked=2; superseded_by=engine:new";
    CHECK(committed_revoke_detail({fail, denied, ok, older}) == "credentials_revoked=2; superseded_by=engine:new");
    CHECK(committed_revoke_detail({fail, denied}).empty());
    CHECK(committed_revoke_detail({fail, ok}) == "credentials_revoked=0 (retry)");
    CHECK(committed_revoke_detail({}).empty());
}

TEST_CASE("every store-sourced field is escaped in every cell it reaches",
          "[access-tokens][render]") {
    PrincipalsView v;
    auto gone = principal("x", "revoked");
    gone.owner_username = kXss;
    gone.superseded_by = kXss;
    v.rows = {gone};
    v.roles = std::vector<PrincipalRole>{{"engine", gone.principal_id, kXss}};
    CHECK_THAT(render_principals_list(v), !ContainsSubstring("<img"));

    PrincipalDetail d;
    d.row = gone;
    d.row.classification = kXss;
    d.credentials = std::vector<ApiToken>{};
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = kXss;
    const auto detail = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(detail, !ContainsSubstring("<img"));
    CHECK_THAT(detail, ContainsSubstring("&lt;img src=x onerror=1&gt;"));

    auto t = tok("t1");
    t.mcp_tier = kXss;
    CHECK_THAT(render_tokens_list(view({t}), flags()), !ContainsSubstring("<img"));
}

TEST_CASE("revoke history: truncated only when the query returned the row past the window",
          "[access-tokens][render]") {
    AuditEvent ok;
    ok.result = "success";
    ok.detail = "newest";
    // Newest first; the oldest success is the LAST element, so a 201st row would be a different one.
    for (const std::size_t n : {std::size_t{199}, std::size_t{200}}) {
        INFO(n);
        std::vector<AuditEvent> ev(n, ok);
        ev.back().detail = "oldest-in-window";
        const auto r = revoke_detail_from(ev);
        CHECK_FALSE(r.truncated);
        CHECK(r.text == "oldest-in-window");
    }
    std::vector<AuditEvent> over(201, ok);
    over[199].detail = "oldest-in-window";
    over[200].detail = "beyond-window";  // dropped: the window is the newest 200
    const auto r = revoke_detail_from(over);
    CHECK(r.truncated);
    CHECK(r.text == "oldest-in-window");
    CHECK(revoke_detail_from({}).text.empty());
}

TEST_CASE("principal detail: a full history window with no success is not worded as a success",
          "[access-tokens][render]") {
    PrincipalDetail d;
    d.row = principal("gone", "revoked");
    d.credentials = std::vector<ApiToken>{};
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = std::string{};
    d.revoke_truncated = true;
    const auto html = render_principal_detail(d, d.row.principal_id);
    CHECK_THAT(html, ContainsSubstring("none of the newest 200 succeeded"));
    CHECK_THAT(html, !ContainsSubstring("oldest success among"));
}
