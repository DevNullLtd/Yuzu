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
 *   - every stored string in a button attribute is escaped.
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

} // namespace

// ---- API tokens ---------------------------------------------------------------------------

TEST_CASE("tokens write render: default flags draw no control at all (the read-only page is unchanged)",
          "[access-tokens][render][writes]") {
    const auto html = render_tokens_list(view({tok("aaa")}), PageFlags{kNow, true, false});
    CHECK_THAT(html, !ContainsSubstring("data-tk=\"token-"));
    CHECK_THAT(html, !ContainsSubstring("class=\"acts\""));
    CHECK_THAT(html, !ContainsSubstring("Actions"));
    CHECK_THAT(html, ContainsSubstring("Creating tokens needs the Administrator account role."));
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
    auto in = render_tokens_list(view(make(60)), flags(kAll));
    CHECK(count(in, "data-tk=\"token-rotate\"") == 1);
    CHECK_THAT(in, ContainsSubstring("data-token-id=\"pred\" data-name=\"ci\">Rotate"));
    // The successor always offers Confirm.
    CHECK(count(in, "data-tk=\"token-confirm\"") == 1);
    // Outside the window the predecessor shows only its status.
    auto out = render_tokens_list(view(make(121)), flags(kAll));
    CHECK(count(out, "data-tk=\"token-rotate\"") == 0);
    // Exactly at 120 s is outside (the server answers 409 from then on).
    CHECK(count(render_tokens_list(view(make(120)), flags(kAll)), "data-tk=\"token-rotate\"") == 0);
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
