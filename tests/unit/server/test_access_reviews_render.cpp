/**
 * @file test_access_reviews_render.cpp
 * @brief Exact-output coverage of access_reviews_render.{hpp,cpp}: the campaign list, one
 *        campaign with its summary card, and the live grant population. Pure functions.
 *
 * Pinned, in order of consequence:
 *   - controls (Open, Close, Attest, Flag, justification) exist only for an attester on an OPEN
 *     campaign; Attest and Flag carry their decision in the DOM so they cannot be swapped;
 *   - undecided grants are listed first, so the render cap never hides one;
 *   - an unreadable store, an unknown campaign and an empty list are three different outputs;
 *   - a hostile campaign id (`./x?`, `../y`) is percent-encoded in every URL and never reaches
 *     one raw; every stored string is escaped;
 *   - nothing here can revoke: no RBAC or engine-principal route is named in any output.
 */

#include "access_reviews_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access_reviews;

namespace {

AccessReviewCampaignRow camp(std::string id, std::string title, std::string status = "open") {
    AccessReviewCampaignRow c;
    c.campaign_id = std::move(id);
    c.title = std::move(title);
    c.status = std::move(status);
    c.created_by = "dave.rae";
    c.created_at_ms = 1791884472000;
    c.rbac_enforcement = "enabled";
    if (c.status == "closed") {
        c.closed_by = "svc-audit";
        c.closed_at_ms = 1791888072000;
    }
    return c;
}

AccessReviewAttestationRow att(std::string type, std::string id, std::string role, std::string decision,
                               std::string reviewer = "", std::string just = "") {
    AccessReviewAttestationRow a;
    a.principal_type = std::move(type);
    a.principal_id = std::move(id);
    a.role_name = std::move(role);
    a.decision = std::move(decision);
    a.reviewer = std::move(reviewer);
    a.decided_at_ms = a.reviewer.empty() ? 0 : 1791884472000;
    a.justification = std::move(just);
    return a;
}

CampaignView view(AccessReviewCampaignRow c, std::vector<AccessReviewAttestationRow> rows) {
    CampaignView v;
    v.campaign = std::move(c);
    v.attestations = std::move(rows);
    return v;
}

std::vector<AccessReviewAttestationRow> five() {
    return {att("user", "dave.rae", "Administrator", "attested", "svc-audit"),
            att("user", "m.graham", "Viewer", "attested", "svc-audit", "Confirmed with line manager"),
            att("user", "j.okafor", "PlatformEngineer", "flagged_revoke", "svc-audit", "Moved teams"),
            att("user", "a2.operator", "Operator", "pending"),
            att("group", "it-ops", "Operator", "pending")};
}

int count_of(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

std::string campaign_html(const CampaignView& v, bool can) {
    return render_campaign(v, can);
}

} // namespace

TEST_CASE("reviews render: campaign list shows state, opener and a Close only for an attester",
          "[access-reviews][render]") {
    const std::vector<AccessReviewCampaignRow> rows = {camp("a41c0e92d7b3f518", "Q4 admin access"),
                                                       camp("7be2c95a10d4e863", "Q3 admin access", "closed")};
    auto out = render_campaigns(rows, true);
    CHECK_THAT(out, ContainsSubstring("<button type=\"button\" class=\"btn primary sm\" "
                                      "data-act=\"ar-open\">Open review</button>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill info\">Open</span>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill idle\">Closed</span><span class=\"sub\">"));
    CHECK_THAT(out, ContainsSubstring("by svc-audit"));
    CHECK_THAT(out, ContainsSubstring("hx-get=\"/fragments/access/reviews/campaign?id=a41c0e92d7b3f518\""));
    CHECK_THAT(out, ContainsSubstring("hx-push-url=\"/access/audit?campaign=a41c0e92d7b3f518\""));
    CHECK(count_of(out, "data-act=\"ar-close\"") == 1);  // the open row only
    CHECK_THAT(out, ContainsSubstring("data-act=\"ar-close\" data-campaign-id=\"a41c0e92d7b3f518\""));

    out = render_campaigns(rows, false);
    CHECK_THAT(out, !ContainsSubstring("data-act=\"ar-open\""));
    CHECK_THAT(out, !ContainsSubstring("data-act=\"ar-close\""));
}

TEST_CASE("reviews render: empty, unavailable and populated lists are three different outputs",
          "[access-reviews][render]") {
    const auto empty = render_campaigns(std::vector<AccessReviewCampaignRow>{}, false);
    CHECK_THAT(empty, ContainsSubstring("No review campaigns yet"));
    CHECK_THAT(empty, !ContainsSubstring("role=\"alert\""));
    CHECK_THAT(empty, !ContainsSubstring("<table"));

    const auto un = render_campaigns(access::Unavailable{}, true);
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kCampaignsUnavailable)));
    CHECK_THAT(un, ContainsSubstring("data-act=\"reload\" data-target=\"ar-campaigns\""));
    CHECK_THAT(un, !ContainsSubstring("<table"));
    CHECK_THAT(un, !ContainsSubstring("No review campaigns yet"));
}

TEST_CASE("reviews render: controls need an attester AND an open campaign, and carry their decision",
          "[access-reviews][render]") {
    for (const bool can : {false, true})
        for (const char* status : {"open", "closed"}) {
            INFO("can_attest=" << can << " status=" << status);
            const auto out = campaign_html(view(camp("c1", "T", status), five()), can);
            const bool expect = can && std::string(status) == "open";
            CHECK(count_of(out, "data-act=\"ar-attest\"") == (expect ? 2 : 0));
            CHECK(count_of(out, "data-act=\"ar-flag\"") == (expect ? 2 : 0));
            CHECK(count_of(out, "data-ar-justification") == (expect ? 2 : 0));
            CHECK(count_of(out, "data-act=\"ar-close\"") == (expect ? 1 : 0));  // side card button
        }
    const auto out = campaign_html(view(camp("c1", "T"), five()), true);
    // Attest and Flag cannot be swapped without a test going red.
    CHECK_THAT(out, ContainsSubstring("data-act=\"ar-attest\" data-decision=\"attested\""));
    CHECK_THAT(out, ContainsSubstring("data-act=\"ar-flag\" data-decision=\"flagged_revoke\""));
    CHECK_THAT(out, ContainsSubstring("Flag for revocation. Records evidence; does not revoke the grant."));
    // Decided rows get no controls and show their justification as text.
    CHECK_THAT(out, ContainsSubstring("Confirmed with line manager"));
}

TEST_CASE("reviews render: the campaign root always carries its id so the list can mark the selection",
          "[access-reviews][render]") {
    for (const bool can : {false, true})
        for (const char* status : {"open", "closed"}) {
            const auto out = campaign_html(view(camp("c9d8e7", "T", status), five()), can);
            CHECK_THAT(out, ContainsSubstring("<div class=\"ar-root\" data-campaign-id=\"c9d8e7\" "
                                              "data-status=\"" + std::string(status) + "\">"));
        }
}

TEST_CASE("reviews render: derived counts", "[access-reviews][render]") {
    const auto d = derive_campaign_counts(view(camp("c", "T"), five()));
    CHECK(d.total == 5);
    CHECK(d.decided == 3);
    CHECK(d.flagged == 1);
    CHECK(d.reviewers == 1);
    const auto out = campaign_html(view(camp("c", "T"), five()), true);
    CHECK_THAT(out, ContainsSubstring("3 of 5 decided"));
    CHECK_THAT(out, ContainsSubstring("<span>Grants decided</span><b>3 of 5</b>"));
    CHECK_THAT(out, ContainsSubstring("<span>Flagged for revocation</span><b>1</b>"));
    CHECK_THAT(out, ContainsSubstring("<span>Reviewers who have acted</span><b>1</b>"));
}

TEST_CASE("reviews render: undecided grants come first and the cap never hides one",
          "[access-reviews][render]") {
    const auto tbody_rows = [](const std::string& out) { return count_of(out, "<tr data-principal-type="); };
    auto make = [](int total, int pending) {
        std::vector<AccessReviewAttestationRow> r;
        // Decided rows sort first in store order; the pending ones sit at the END.
        for (int i = 0; i < total - pending; ++i)
            r.push_back(att("user", "dec" + std::to_string(i), "Viewer", "attested", "rev"));
        for (int i = 0; i < pending; ++i)
            r.push_back(att("user", "pen" + std::to_string(i), "Viewer", "pending"));
        return r;
    };
    // Boundary: exactly the cap draws everything with no banner.
    auto out = campaign_html(view(camp("c", "T"), make(1000, 3)), true);
    CHECK(tbody_rows(out) == 1000);
    CHECK_THAT(out, !ContainsSubstring("Showing the first"));
    // One over: banner with the true count.
    out = campaign_html(view(camp("c", "T"), make(1001, 3)), true);
    CHECK(tbody_rows(out) == 1000);
    CHECK_THAT(out, ContainsSubstring("Showing the first 1000 of 1001 frozen grants, undecided first. "
                                      "The complete set is the JSON from GET /api/v1/access-reviews/{id}."));
    // 1,200 grants of which 1,100 are pending: every drawn row is pending.
    out = campaign_html(view(camp("c", "T"), make(1200, 1100)), true);
    CHECK(tbody_rows(out) == 1000);
    CHECK(count_of(out, "<span class=\"pill idle\">pending</span>") == 1000);
    CHECK_THAT(out, !ContainsSubstring("class=\"pill ok\">attested"));
    CHECK_THAT(out, ContainsSubstring("100 of 1200 decided"));
    // The first pending row is drawn before the first decided one.
    out = campaign_html(view(camp("c", "T"), make(10, 2)), true);
    CHECK(out.find("pen0") < out.find("dec0"));
}

TEST_CASE("reviews render: the summary card is an out-of-band swap with honest controls",
          "[access-reviews][render]") {
    auto out = campaign_html(view(camp("c1", "Q4 admin access"), five()), true);
    CHECK(count_of(out, "id=\"ar-campaign-side\" hx-swap-oob=\"true\"") == 1);
    CHECK_THAT(out, ContainsSubstring("<span>Enforcement when opened</span><b>enabled</b>"));
    // The two placeholders are honest: no due-date field exists, and the decisions are available
    // as JSON from the campaign route, which the title names (it must never claim otherwise).
    CHECK_THAT(out, ContainsSubstring("<span>Due date</span><b><span class=\"hint\">Not available "
                                      "yet</span></b>"));
    CHECK_THAT(out, ContainsSubstring("<button type=\"button\" class=\"btn\" disabled title=\"Not "
                                      "available yet. The decisions are in the JSON from GET "
                                      "/api/v1/access-reviews/{id}.\">Export decisions</button>"));
    CHECK_THAT(out, !ContainsSubstring("no route exports"));
    // A campaign frozen before the stamp existed says so; it never prints an empty cell.
    auto c = camp("c1", "T");
    c.rbac_enforcement = "";
    out = campaign_html(view(c, five()), false);
    CHECK_THAT(out, ContainsSubstring("<span>Enforcement when opened</span><b>not recorded</b>"));
    // Closed: a Closed line replaces the Close button, and an open campaign prints no Closed line.
    out = campaign_html(view(camp("c1", "T", "closed"), five()), true);
    CHECK_THAT(out, ContainsSubstring("<span>Closed</span><b>"));
    CHECK_THAT(out, ContainsSubstring("by svc-audit"));
    CHECK_THAT(out, !ContainsSubstring("data-act=\"ar-close\""));
    out = campaign_html(view(camp("c1", "T"), five()), true);
    CHECK_THAT(out, !ContainsSubstring("<span>Closed</span>"));
}

TEST_CASE("reviews render: not found, unavailable and unselected are distinct and never leak",
          "[access-reviews][render]") {
    const auto nf = render_campaign(access::NotFound{}, true);
    CHECK_THAT(nf, ContainsSubstring("No campaign with that id"));
    CHECK_THAT(nf, !ContainsSubstring("role=\"alert\""));
    CHECK(count_of(nf, "id=\"ar-campaign-side\" hx-swap-oob=\"true\"") == 1);

    const auto un = render_campaign(access::Unavailable{}, true, "7be2c95a10d4e863");
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kCampaignUnavailable)));
    CHECK_THAT(un, ContainsSubstring("hx-get=\"/fragments/access/reviews/campaign?id=7be2c95a10d4e863\""));
    CHECK_THAT(un, !ContainsSubstring("No campaign with that id"));
    CHECK_THAT(un, !ContainsSubstring("<table"));
    // No id, no Retry button (never an empty-id request).
    CHECK_THAT(render_campaign(access::Unavailable{}, true), !ContainsSubstring("hx-get"));

    const auto sel = render_campaign_unselected();
    CHECK_THAT(sel, ContainsSubstring(std::string(kSelectCampaign)));
    CHECK(count_of(sel, "id=\"ar-campaign-side\" hx-swap-oob=\"true\"") == 1);
}

TEST_CASE("reviews render: an unknown decision token is escaped and never drawn as attested",
          "[access-reviews][render]") {
    const auto out = campaign_html(
        view(camp("c", "T"), {att("user", "u", "Viewer", "approved<x>", "r")}), true);
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill idle\">approved&lt;x&gt;</span>"));
    CHECK_THAT(out, !ContainsSubstring("pill ok"));
    // Not pending, so it offers no controls either.
    CHECK_THAT(out, !ContainsSubstring("data-act=\"ar-attest\""));
}

TEST_CASE("reviews render: hostile stored strings are escaped everywhere they appear",
          "[access-reviews][render]") {
    const std::string evil = "<script>alert(1)</script>\"'&";
    auto c = camp(evil, evil);
    c.created_by = evil;
    c.rbac_enforcement = evil;
    const auto out = campaign_html(view(c, {att(evil, evil, evil, "pending")}), true);
    CHECK_THAT(out, !ContainsSubstring("<script"));
    CHECK_THAT(out, ContainsSubstring("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;"));
    const auto list = render_campaigns(std::vector<AccessReviewCampaignRow>{c}, true);
    CHECK_THAT(list, !ContainsSubstring("<script"));
    // 10 KB of text in every free-text field stays bounded and inert.
    const std::string big(10 * 1024, 'A');
    const auto out2 = campaign_html(view(camp("c", big), {att("user", big, big, "attested", big, big)}),
                                    true);
    CHECK(out2.size() < 100 * 1024);
}

TEST_CASE("reviews render: a hostile campaign id is percent-encoded in every URL, never raw",
          "[access-reviews][render]") {
    for (const auto& [id, enc] : std::vector<std::pair<std::string, std::string>>{
             {"./x?", ".%2Fx%3F"}, {"../y", "..%2Fy"}, {"a#b", "a%23b"}, {"a b/c", "a%20b%2Fc"},
             {"a\"><img src=x onerror=1>", "a%22%3E%3Cimg%20src%3Dx%20onerror%3D1%3E"}}) {
        INFO(id);
        const auto out = render_campaigns(std::vector<AccessReviewCampaignRow>{camp(id, "T")}, true);
        CHECK_THAT(out, ContainsSubstring("reviews/campaign?id=" + enc + "\""));
        CHECK_THAT(out, ContainsSubstring("/access/audit?campaign=" + enc + "\""));
        CHECK_THAT(out, !ContainsSubstring("id=" + id));
        CHECK_THAT(out, !ContainsSubstring("<img"));
        const auto un = render_campaign(access::Unavailable{}, true, id);
        CHECK_THAT(un, ContainsSubstring("reviews/campaign?id=" + enc + "\""));
    }
}

TEST_CASE("reviews render: only ids a URL can carry unchanged are valid", "[access-reviews][render]") {
    for (const char* ok : {"a41c0e92d7b3f518", "A_b-9", "x"})
        CHECK(valid_campaign_id(ok));
    CHECK(valid_campaign_id(std::string(64, 'a')));
    CHECK_FALSE(valid_campaign_id(std::string(65, 'a')));
    for (const char* bad : {"", ".", "..", "./x?", "../y", "a/b", "a b", "a#b", "a%20", "a.b", "a\n",
                            "ä"})
        CHECK_FALSE(valid_campaign_id(bad));
    CHECK_FALSE(valid_campaign_id(std::string("a\0b", 3)));
}

TEST_CASE("reviews render: nothing here can revoke and nothing mutates through htmx",
          "[access-reviews][render]") {
    GrantsView g;
    g.rbac_enforcement = "enabled";
    const std::vector<std::string> outs = {
        campaign_html(view(camp("c", "T"), five()), true),
        render_campaigns(std::vector<AccessReviewCampaignRow>{camp("c", "T")}, true),
        render_grants(g), render_campaign_unselected()};
    for (const auto& o : outs)
        for (const char* bad : {"/api/v1/rbac", "engine-principals", "hx-post", "hx-put", "hx-delete",
                                "hx-patch", "<form", "hx-on", "javascript:", " onclick=", "innerHTML"}) {
            INFO(bad);
            CHECK_THAT(o, !ContainsSubstring(bad));
        }
}

TEST_CASE("reviews render: current grants keep orphans, flag them and state the enforcement stamp",
          "[access-reviews][render]") {
    GrantsView g;
    g.rbac_enforcement = "degraded";
    AccessReviewRow u;
    u.principal_type = "user";
    u.principal_id = "dave.rae";
    u.display_name = "dave.rae";
    u.roles = {"Administrator"};
    u.effective_permission_count = 193;
    u.last_activity_kind = "n/a";
    u.classification = "internal";
    u.lifecycle_state = "active";
    u.source = "local";
    AccessReviewRow orphan;
    orphan.principal_type = "user";
    orphan.principal_id = "ex.contractor";
    orphan.display_name = "ex.contractor";
    orphan.roles = {"Viewer"};
    orphan.lifecycle_state = "unknown";
    orphan.source = "orphan";
    AccessReviewRow dis = u;
    dis.principal_id = dis.display_name = "gone";
    dis.lifecycle_state = "disabled";
    g.rows = {u, orphan, dis};
    const auto out = render_grants(g);
    CHECK_THAT(out, ContainsSubstring("href=\"/api/v1/access-reviews/export?format=csv\""));
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill warn\" title=\"Grant with no matching "
                                      "account\">orphan</span>"));
    CHECK_THAT(out, ContainsSubstring("<span class=\"pill warn\">disabled</span>"));
    CHECK_THAT(out, ContainsSubstring("<td class=\"r\">193</td>"));
    CHECK_THAT(out, ContainsSubstring("RBAC enforcement when read: degraded."));
    CHECK_THAT(out, ContainsSubstring("ex.contractor"));
    CHECK_THAT(out, ContainsSubstring("n/a"));
}

TEST_CASE("reviews render: current grants cap, empty and unavailable", "[access-reviews][render]") {
    GrantsView g;
    g.rbac_enforcement = "enabled";
    AccessReviewRow r;
    r.principal_type = "user";
    r.principal_id = "p";
    g.rows.assign(1000, r);
    auto out = render_grants(g);
    CHECK(count_of(out, "<tr><td class=\"long\">") == 1000);
    CHECK_THAT(out, !ContainsSubstring("Showing the first"));
    g.rows.assign(1001, r);
    out = render_grants(g);
    CHECK(count_of(out, "<tr><td class=\"long\">") == 1000);
    CHECK_THAT(out, ContainsSubstring("Showing the first 1000 of 1001 principals."));

    g.rows.clear();
    out = render_grants(g);
    CHECK_THAT(out, ContainsSubstring("No grants"));
    CHECK_THAT(out, !ContainsSubstring("role=\"alert\""));

    out = render_grants(access::Unavailable{});
    CHECK_THAT(out, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(out, ContainsSubstring(std::string(kGrantsUnavailable)));
    CHECK_THAT(out, !ContainsSubstring("<table"));
    CHECK_THAT(out, !ContainsSubstring("export?format=csv"));
    CHECK_THAT(out, !ContainsSubstring("No grants"));
}
