/**
 * @file test_access_tokens_writes_render.cpp
 * @brief Pure-renderer coverage of the write controls on the Tokens and principals page: which
 *        control is drawn for which caller and row, and that no stored string can reach a
 *        request path. Nothing touches a store, a clock or a socket.
 *
 * Pinned, in order of consequence:
 *   - a control is drawn only when the caller's capability says the server will allow it
 *     (default flags draw none, so the read-only page is byte-for-byte unchanged);
 *   - a row whose id is outside the charset its route accepts gets NO action control, so a
 *     hostile id ("./bulk-approve?", "../x") can never be spliced into a path;
 *   - rotate and confirm are owner-only and human-only; engine credentials offer Revoke only;
 *   - the 120 s recovery window offers Rotate on a predecessor and never outside it;
 *   - every stored string in a button attribute is escaped;
 *   - Assign role is disabled with the reason when no custom role exists, and built-in roles
 *     are never offered.
 */

#include "access_tokens_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access_tokens;

namespace {

constexpr std::int64_t kNow = 1'800'000'000;
const std::string kXss = "<img src=x onerror=1>\"'&";

ApiToken tok(std::string id, std::string owner = "alice", std::string name = "ci") {
    ApiToken t;
    t.token_id = std::move(id);
    t.name = std::move(name);
    t.principal_id = std::move(owner);
    t.created_at = kNow - 1000;
    t.expires_at = kNow + 30 * 86400;
    return t;
}

TokensView view(std::vector<ApiToken> rows, bool all_owners = true) {
    TokensView v;
    v.rows = std::move(rows);
    v.all_owners = all_owners;
    v.show_all = true;
    return v;
}

PageFlags flags(TokenCaps caps, bool admin = true, std::string caller = "alice", bool rbac = false) {
    PageFlags f{kNow, admin, rbac, std::move(caller), caps};
    return f;
}

constexpr TokenCaps kAll{true, true, true};

std::size_t count(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

EnginePrincipalRow principal(std::string slug, std::string state = "active") {
    EnginePrincipalRow p;
    p.principal_id = "engine:" + slug;
    p.display_name = slug;
    p.owner_username = "alice";
    p.classification = "internal";
    p.lifecycle_state = std::move(state);
    return p;
}

PrincipalDetail detail(std::vector<ApiToken> creds, bool can_write = true) {
    PrincipalDetail d;
    d.row = principal("bot");
    d.credentials = std::move(creds);
    d.roles = std::vector<PrincipalRole>{};
    d.revoke_detail = std::string{};
    d.now = kNow;
    d.can_write = can_write;
    return d;
}

ApiToken cred(std::string id, std::int64_t created) {
    ApiToken c = tok(std::move(id), "engine:bot");
    c.principal_kind = "engine";
    c.created_at = created;
    return c;
}

} // namespace

// ---- API tokens ---------------------------------------------------------------------------

TEST_CASE("tokens write render: default flags draw no control at all (the read-only page is unchanged)",
          "[access-tokens][render][writes]") {
    const auto html = render_tokens_list(view({tok("aaa")}), PageFlags{kNow, true, false});
    CHECK_THAT(html, !ContainsSubstring("data-tk=\"token-"));
    CHECK_THAT(html, !ContainsSubstring("class=\"acts\""));
    CHECK_THAT(html, !ContainsSubstring("Actions"));
    CHECK_THAT(html, ContainsSubstring("Creating tokens needs an Administrator browser session."));
}

TEST_CASE("tokens write render: the header shows New API token only when create is allowed, else says what is missing",
          "[access-tokens][render][writes]") {
    CHECK_THAT(render_tokens_list(view({tok("aaa")}), flags(kAll)), ContainsSubstring("data-tk=\"token-new\""));
    const auto no = render_tokens_list(view({tok("aaa")}), flags({false, true, true}, true, "alice", true));
    CHECK_THAT(no, !ContainsSubstring("token-new"));
    CHECK_THAT(no, ContainsSubstring("Creating tokens needs the ApiToken:Write permission."));
    // An empty list still offers the control to a caller who may use it.
    CHECK_THAT(render_tokens_list(view({}), flags(kAll)), ContainsSubstring("Use New API token to create one."));
}

TEST_CASE("tokens write render: row action matrix (owner x kind x state x caps)",
          "[access-tokens][render][writes]") {
    struct Row {
        const char* name;
        std::function<ApiToken()> make;
        TokenCaps caps;
        bool admin;
        std::string caller;
        bool rotate, confirm, revoke;
    };
    auto pending = [] {  // a successor awaiting confirmation
        auto t = tok("succ");
        t.supersedes_token_id = "pred";
        t.rotation_group = "g";
        return t;
    };
    auto revoked = [] { auto t = tok("rev"); t.revoked = true; return t; };
    auto engine = [] { auto t = tok("eng", "engine:bot"); t.principal_kind = "engine"; return t; };
    auto soon = [] { auto t = tok("soon"); t.expires_at = kNow + 3600; return t; };
    auto expired = [] { auto t = tok("old"); t.expires_at = kNow - 1; return t; };
    const std::vector<Row> rows = {
        {"own plain, all caps", [] { return tok("own"); }, kAll, true, "alice", true, false, true},
        {"own plain, no caps", [] { return tok("own"); }, {}, true, "alice", false, false, false},
        {"not owner, admin: revoke only", [] { return tok("oth", "bob"); }, kAll, true, "alice", false, false, true},
        {"not owner, not admin: nothing", [] { return tok("oth", "bob"); }, kAll, false, "alice", false, false, false},
        {"own, rotate cap only", [] { return tok("own"); }, {false, false, true}, false, "alice", true, false, false},
        {"own, revoke cap only", [] { return tok("own"); }, {false, true, false}, false, "alice", false, false, true},
        {"pending successor: confirm, not rotate", pending, kAll, true, "alice", false, true, true},
        {"revoked: nothing", revoked, kAll, true, "alice", false, false, false},
        {"expired: revoke only", expired, kAll, true, "alice", false, false, true},
        {"engine credential: revoke only (admin)", engine, kAll, true, "alice", false, false, true},
        {"within 24h of expiry: rotate disabled", soon, kAll, true, "alice", true, false, true},
        {"empty caller never owns", [] { return tok("own", ""); }, kAll, false, "", false, false, false},
    };
    for (const auto& r : rows) {
        INFO(r.name);
        std::vector<ApiToken> all{r.make()};
        const auto html = render_tokens_list(view(all), flags(r.caps, r.admin, r.caller));
        CHECK((html.find("data-tk=\"token-rotate\"") != std::string::npos) == r.rotate);
        CHECK((html.find("data-tk=\"token-confirm\"") != std::string::npos) == r.confirm);
        CHECK((html.find("data-tk=\"token-revoke\"") != std::string::npos) == r.revoke);
    }
}

TEST_CASE("tokens write render: a token within 24 hours of expiry has Rotate disabled with the reason",
          "[access-tokens][render][writes]") {
    auto t = tok("soon");
    t.expires_at = kNow + 3600;
    const auto html = render_tokens_list(view({t}), flags(kAll));
    CHECK_THAT(html, ContainsSubstring("disabled title=\"A token within 24 hours of expiry cannot be rotated."));
}

TEST_CASE("tokens write render: the 120 s recovery window offers Rotate on a predecessor, and only inside it",
          "[access-tokens][render][writes]") {
    auto make = [](std::int64_t succ_age) {
        auto pred = tok("pred");
        pred.rotation_group = "g";
        pred.overlap_expires_at = kNow + 86400;
        auto succ = tok("succ");
        succ.rotation_group = "g";
        succ.supersedes_token_id = "pred";
        succ.created_at = kNow - succ_age;
        return std::vector<ApiToken>{pred, succ};
    };
    // Inside the window: the predecessor row carries Rotate (the way to get the secret again).
    // The window and the 24 h floor are the store's own values (the page keeps no copy).
    constexpr std::int64_t kGrace = ApiTokenStore::rotation_grace_secs();
    static_assert(kGrace == 120 && ApiTokenStore::overlap_floor_secs() == 24 * 3600);
    auto in = render_tokens_list(view(make(60)), flags(kAll));
    CHECK(count(in, "data-tk=\"token-rotate\"") == 1);
    CHECK_THAT(in, ContainsSubstring("data-token-id=\"pred\" data-name=\"ci\">Rotate"));
    // The successor always offers Confirm.
    CHECK(count(in, "data-tk=\"token-confirm\"") == 1);
    // Outside the window the predecessor shows only its status.
    auto out = render_tokens_list(view(make(kGrace + 1)), flags(kAll));
    CHECK(count(out, "data-tk=\"token-rotate\"") == 0);
    // Exactly at the window is still inside (the server answers 409 only when older than it).
    CHECK(count(render_tokens_list(view(make(kGrace)), flags(kAll)), "data-tk=\"token-rotate\"") == 1);
    // Confirm names the predecessor, not the successor.
    CHECK_THAT(in, ContainsSubstring("data-predecessor=\"ci\""));
}

TEST_CASE("tokens write render: a hostile token id gets no control and reaches no attribute",
          "[access-tokens][render][writes][urlsafety]") {
    for (const char* bad : {"./bulk-approve?", "../x", "a/b", "a b", "a?b", "a#b", "a%2fb", ".", "..", "-x", "",
                            "a\"b", "a<b>", "a\nb"}) {
        INFO(bad);
        const auto html = render_tokens_list(view({tok(bad)}), flags(kAll));
        for (const char* tk : {"token-rotate", "token-confirm", "token-revoke"})
            CHECK_THAT(html, !ContainsSubstring(std::string("data-tk=\"") + tk));
        CHECK_THAT(html, !ContainsSubstring("data-token-id="));
        // And nothing ever builds a path server-side.
        CHECK_THAT(html, !ContainsSubstring("hx-delete"));
        CHECK_THAT(html, !ContainsSubstring("hx-post"));
        CHECK_THAT(html, !ContainsSubstring("href="));
        // The row itself is still drawn: refusing the controls does not hide the data.
        CHECK_THAT(html, ContainsSubstring("alice</td>"));
    }
    CHECK(safe_token_id("a1b2c3"));
    CHECK(safe_token_id("Ab.c_d-e"));
    CHECK_FALSE(safe_token_id(std::string(129, 'a')));
}

TEST_CASE("tokens write render: stored strings in button attributes are escaped",
          "[access-tokens][render][writes][xss]") {
    auto t = tok("aaa", "alice", kXss);
    auto pend = tok("bbb");
    pend.supersedes_token_id = "aaa";
    pend.rotation_group = "g";
    const auto html = render_tokens_list(view({t, pend}), flags(kAll));
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, !ContainsSubstring("data-name=\"" + kXss));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;&quot;&#39;&amp;"));
    // The name rides in a data attribute that the page script reads with dataset + textContent.
    CHECK_THAT(html, ContainsSubstring("data-predecessor=\"&lt;img"));
}

// ---- engine principals --------------------------------------------------------------------

TEST_CASE("principals write render: New principal only with the capability, else the reason",
          "[access-tokens][render][writes]") {
    PrincipalsView v;
    v.rows = {principal("bot")};
    v.roles = std::vector<PrincipalRole>{};
    CHECK_THAT(render_principals_list(v), !ContainsSubstring("principal-new"));
    CHECK_THAT(render_principals_list(v), ContainsSubstring("Creating principals needs an Administrator browser session."));
    v.rbac_enforced = true;
    CHECK_THAT(render_principals_list(v), ContainsSubstring("Creating principals needs the Security:Write permission."));
    v.can_write = true;
    CHECK_THAT(render_principals_list(v), ContainsSubstring("data-tk=\"principal-new\""));
    v.rows.clear();
    CHECK_THAT(render_principals_list(v), ContainsSubstring("data-tk=\"principal-new\""));
    // Rows carry no action: every principal action lives in the detail panel.
    v.rows = {principal("bot")};
    CHECK_THAT(render_principals_list(v), !ContainsSubstring("principal-revoke"));
}

TEST_CASE("principals write render: the detail draws the credential actions the facts allow",
          "[access-tokens][render][writes]") {
    auto has = [](const std::string& html, const char* tk) {
        return html.find(std::string("data-tk=\"") + tk + "\"") != std::string::npos;
    };
    // Zero active credentials: Mint only.
    auto none = render_principal_detail(detail({}), "engine:bot");
    CHECK(has(none, "principal-mint"));
    CHECK_FALSE(has(none, "principal-rotate"));
    CHECK(has(none, "principal-transfer"));
    CHECK(has(none, "principal-revoke"));
    // One credential: Rotate, never Mint.
    auto one = render_principal_detail(detail({cred("c1", kNow - 9999)}), "engine:bot");
    CHECK(has(one, "principal-rotate"));
    CHECK_FALSE(has(one, "principal-mint"));
    CHECK_FALSE(has(one, "principal-confirm"));
    // Pair, successor older than 120 s: Confirm only.
    auto s_old = cred("c2", kNow - 500);
    s_old.supersedes_token_id = "c1";
    auto two = render_principal_detail(detail({cred("c1", kNow - 9999), s_old}), "engine:bot");
    CHECK(has(two, "principal-confirm"));
    CHECK_THAT(two, ContainsSubstring("data-token-id=\"c2\""));
    CHECK_FALSE(has(two, "principal-rotate"));
    // Pair, successor inside the grace window: Confirm and the recovery Rotate.
    auto s_new = cred("c2", kNow - 30);
    s_new.supersedes_token_id = "c1";
    auto fresh = render_principal_detail(detail({cred("c1", kNow - 9999), s_new}), "engine:bot");
    CHECK(has(fresh, "principal-confirm"));
    CHECK(has(fresh, "principal-rotate"));
    // Credentials unreadable: Mint and Rotate are disabled with the reason, not drawn live.
    PrincipalDetail d = detail({});
    d.credentials = Unavailable{};
    auto unread = render_principal_detail(d, "engine:bot");
    CHECK_THAT(unread, ContainsSubstring("disabled title=\"Credentials could not be read.\""));
    CHECK(has(unread, "principal-transfer"));
}

TEST_CASE("principals write render: without the capability no action is drawn and the reason is stated",
          "[access-tokens][render][writes]") {
    PrincipalDetail d = detail({}, false);
    d.rbac_enforced = true;
    d.roles = std::vector<PrincipalRole>{{"engine", "engine:bot", "Reader"}};
    const auto html = render_principal_detail(d, "engine:bot");
    for (const char* tk : {"principal-mint", "principal-rotate", "principal-confirm", "principal-transfer",
                           "principal-revoke", "role-assign", "role-remove"})
        CHECK_THAT(html, !ContainsSubstring(std::string("data-tk=\"") + tk));
    CHECK_THAT(html, ContainsSubstring("Changing principals needs the Security:Write permission."));
    // A revoked principal is terminal: no principal action even with the capability.
    PrincipalDetail r = detail({});
    r.row = principal("bot", "revoked");
    CHECK_THAT(render_principal_detail(r, "engine:bot"), !ContainsSubstring("principal-revoke"));
    CHECK_THAT(render_principal_detail(r, "engine:bot"), !ContainsSubstring("role-assign"));
}

TEST_CASE("principals write render: roles - Assign lists custom roles only and is disabled with the reason when none",
          "[access-tokens][render][writes]") {
    PrincipalDetail d = detail({});
    d.roles = std::vector<PrincipalRole>{{"engine", "engine:bot", "Auditor"}};
    // None exist: disabled with the reason; no option list at all.
    auto none = render_principal_detail(d, "engine:bot");
    CHECK_THAT(none, ContainsSubstring("data-tk=\"role-assign\""));
    CHECK_THAT(none, ContainsSubstring("disabled title=\"No custom roles exist."));
    CHECK_THAT(none, !ContainsSubstring("role-options"));
    // Some exist: they, and only they, are options; names are escaped.
    d.custom_roles = std::vector<std::string>{"Auditor-2", kXss};
    auto some = render_principal_detail(d, "engine:bot");
    CHECK_THAT(some, ContainsSubstring("<select id=\"role-options\" hidden>"));
    CHECK_THAT(some, ContainsSubstring("<option value=\"Auditor-2\">Auditor-2</option>"));
    CHECK_THAT(some, !ContainsSubstring("<img"));
    CHECK_THAT(some, !ContainsSubstring("Administrator</option>"));
    // Remove rides the bare slug, never the full id, and the role as data.
    CHECK_THAT(some, ContainsSubstring("data-tk=\"role-remove\" data-slug=\"bot\" data-role=\"Auditor\""));
    // An unreadable role list is its own sentence: never "no custom roles", no option list.
    d.custom_roles = Unavailable{};
    const auto bad = render_principal_detail(d, "engine:bot");
    CHECK_THAT(bad, ContainsSubstring("disabled title=\"The role list could not be read."));
    CHECK_THAT(bad, !ContainsSubstring("No custom roles exist"));
    CHECK_THAT(bad, !ContainsSubstring("role-options"));
}

TEST_CASE("principals write render: only non-system roles are offered to an engine principal",
          "[access-tokens][render][writes]") {
    RbacRole sys;
    sys.name = "Administrator";
    sys.is_system = true;
    RbacRole mine;
    mine.name = "Auditor";
    mine.is_system = false;
    const auto names = custom_role_names({sys, mine});
    REQUIRE(names.size() == 1);
    CHECK(names[0] == "Auditor");
    CHECK(custom_role_names({}).empty());
}

TEST_CASE("principals write render: a hostile principal id draws no action and no role control",
          "[access-tokens][render][writes][urlsafety]") {
    for (const char* bad : {"engine:../x", "engine:a/b", "engine:A", "engine:", "x", "engine:a b"}) {
        INFO(bad);
        PrincipalDetail d = detail({});
        d.row.principal_id = bad;
        d.custom_roles = std::vector<std::string>{"r"};
        d.roles = std::vector<PrincipalRole>{{"engine", bad, "r"}};
        const auto html = render_principal_detail(d, bad);
        CHECK_THAT(html, !ContainsSubstring("data-tk=\"principal-"));
        CHECK_THAT(html, !ContainsSubstring("data-tk=\"role-"));
        CHECK_THAT(html, !ContainsSubstring("data-slug="));
    }
    CHECK(principal_slug("engine:bot") == "bot");
    CHECK(principal_slug("engine:../x").empty());
    CHECK(principal_slug("bot").empty());
}

TEST_CASE("tokens write render: Rotate carries the old token's expiry so the dialog offers only overlaps that fit",
          "[access-tokens][render][writes]") {
    const auto t = tok("aaa");
    const auto html = render_tokens_list(view({t}), flags(kAll));
    CHECK_THAT(html, ContainsSubstring("data-tk=\"token-rotate\" data-token-id=\"aaa\" data-name=\"ci\" data-expires-at=\"" +
                                      std::to_string(t.expires_at) + "\""));
    auto never = tok("bbb");
    never.expires_at = 0;
    CHECK_THAT(render_tokens_list(view({never}), flags(kAll)), ContainsSubstring("data-expires-at=\"0\""));
}

TEST_CASE("principals write render: a dot-only slug draws no role control (its URL segment would be resolved away)",
          "[access-tokens][render][writes][urlsafety]") {
    for (const char* id : {"engine:.", "engine:.."}) {
        INFO(id);
        PrincipalDetail d = detail({});
        d.row.principal_id = id;
        d.custom_roles = std::vector<std::string>{"Auditor"};
        d.roles = std::vector<PrincipalRole>{{"engine", id, "Auditor"}};
        const auto html = render_principal_detail(d, id);
        CHECK_THAT(html, !ContainsSubstring("data-tk=\"role-"));
        CHECK_THAT(html, !ContainsSubstring("data-slug="));
        // The role itself is still listed, and the principal's own actions are unaffected.
        CHECK_THAT(html, ContainsSubstring("Auditor"));
        CHECK_THAT(html, ContainsSubstring("data-tk=\"principal-revoke\""));
    }
    CHECK(principal_slug("engine:.").empty());
    CHECK(principal_slug("engine:..").empty());
    CHECK(principal_slug("engine:a.b") == "a.b");
}
