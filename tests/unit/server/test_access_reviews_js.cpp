/**
 * @file test_access_reviews_js.cpp
 * @brief String pins on the Access reviews half of the Audit and reviews page: the glue script's
 *        write calls and the template's panels. The repo has no JS runner, so these prove a token
 *        is present, not that a branch executes; the behaviour is exercised by the headless
 *        browser run recorded in the PR body.
 */

#include "access_audit_ui.hpp"
#include "access_reviews_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cctype>
#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuAuditJs;
}

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access_reviews;

TEST_CASE("reviews glue: every write is an existing REST v1 route and reads the nested envelope",
          "[access-reviews][js]") {
    const std::string& js = yuzu::server::kYuzuAuditJs;
    for (const char* token :
         {"'/api/v1/access-reviews'", "'/close'", "'/attestations'", "YuzuDialog.request",
          // The REST envelope nests the new id: reading data.campaign_id is the Settings bug.
          "r.data.data.campaign_id", "btn.dataset.decision", "data-ar-justification",
          "ID_RE.test(id)", "encodeURIComponent(id)", "r.auditFailed"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
    // Flag is evidence only: the dialog says so, and nothing here can revoke.
    CHECK_THAT(js, ContainsSubstring("This records evidence only. It does NOT revoke the grant."));
    for (const char* bad : {"/api/v1/rbac", "engine-principals", "innerHTML", "insertAdjacentHTML",
                            "eval(", "new Function", "document.write", "hx-on", "XMLHttpRequest",
                            "fetch("}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
}

TEST_CASE("reviews glue: every control the renderer draws has a handler; and the decision is not hard-coded",
          "[access-reviews][js]") {
    const std::string& js = yuzu::server::kYuzuAuditJs;
    CampaignView v;
    v.campaign.campaign_id = "c1";
    v.campaign.status = "open";
    AccessReviewAttestationRow a;
    a.principal_type = "user";
    a.principal_id = "u";
    a.role_name = "r";
    a.decision = "pending";
    v.attestations = {a};
    const std::string drawn = render_campaign(v, true) +
                              render_campaigns(std::vector<AccessReviewCampaignRow>{v.campaign}, true);
    const std::regex act(R"re(data-act="(ar-[a-z]+)")re");
    int seen = 0;
    for (std::sregex_iterator it(drawn.begin(), drawn.end(), act), end; it != end; ++it, ++seen) {
        INFO((*it)[1].str());
        CHECK_THAT(js, ContainsSubstring("'" + (*it)[1].str() + "'"));
    }
    CHECK(seen >= 4);
    // The script sends whatever decision the server drew, so Attest and Flag cannot be swapped here.
    CHECK_THAT(js, !ContainsSubstring("decision: 'attested'"));
    CHECK_THAT(js, !ContainsSubstring("decision: 'flagged_revoke'"));
}

TEST_CASE("reviews page: the panels carry the renderer's sentences and nothing loads the grants",
          "[access-reviews][js]") {
    const std::string t = kAccessAuditTemplate;
    const auto attr = [&](const char* name, std::string_view v) {
        CHECK_THAT(t, ContainsSubstring(std::string(name) + "=\"" + std::string(v) + "\""));
    };
    attr("data-denied", kReviewsDenied);
    attr("data-unavailable", kCampaignsUnavailable);
    attr("data-unavailable", kCampaignUnavailable);
    attr("data-unavailable", kGrantsUnavailable);
    CHECK_THAT(t, ContainsSubstring(std::string(kSelectCampaign)));
    for (const char* id : {"id=\"ar-campaigns\"", "id=\"ar-campaign\"", "id=\"ar-grants\"",
                           "id=\"ar-campaign-side\"", "id=\"ar-banner\""}) {
        INFO(id);
        CHECK_THAT(t, ContainsSubstring(id));
    }
    // The grant population is read on request (it is a bulk read and an audit row), never on load.
    CHECK_THAT(t, !ContainsSubstring("id=\"ar-grants\" hx-get"));
    CHECK_THAT(t, !ContainsSubstring("hx-get=\"/fragments/access/reviews/grants\" hx-trigger"));
}

TEST_CASE("reviews page: htmx history is off before htmx loads; because campaign rows push a URL",
          "[access-reviews][js]") {
    // A campaign row carries hx-push-url, which makes htmx snapshot the whole page (audit rows,
    // campaigns, grants) into localStorage unless history is disabled. The meta is read once, at
    // htmx load, so it must come first.
    const std::string rows = render_campaigns(std::vector<AccessReviewCampaignRow>{[] {
                                                  AccessReviewCampaignRow c;
                                                  c.campaign_id = "c1";
                                                  c.status = "open";
                                                  return c;
                                              }()},
                                              false);
    CHECK_THAT(rows, ContainsSubstring("hx-push-url="));
    for (const std::string t : {std::string(kAccessAuditTemplate), std::string(kAccessAuditHtml)}) {
        const auto meta = t.find("<meta name=\"htmx-config\"");
        const auto htmx = t.find("<script src=\"/static/htmx.js\">");
        REQUIRE(meta != std::string::npos);
        REQUIRE(htmx != std::string::npos);
        CHECK(meta < htmx);
        CHECK_THAT(t, ContainsSubstring("{\"allowEval\":false,\"historyEnabled\":false}"));
    }
}

TEST_CASE("reviews glue: a read fragment whose audit row failed is flagged in its own persistent note",
          "[access-reviews][js]") {
    const std::string& js = yuzu::server::kYuzuAuditJs;
    for (const char* token : {"'htmx:afterRequest'", "getResponseHeader('Sec-Audit-Failed')",
                              "'/fragments/access/reviews/'", "'ar-audit-failed'",
                              "note.setAttribute('role', 'alert')"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
    // The note is not #ar-banner: written() clears the banner after every write, so a note kept
    // there would vanish on the next successful change. Everything from written() onward (the
    // write flows) must never name the note, so nothing can clear or replace it.
    const auto w = js.find("function written(");
    REQUIRE(w != std::string::npos);
    CHECK_THAT(js.substr(w), !ContainsSubstring("ar-audit-failed"));
    CHECK_THAT(js.substr(w), ContainsSubstring("banner(r.auditFailed"));
}

TEST_CASE("reviews glue: the attributes on a drawn grant row are exactly the dataset fields the script reads",
          "[access-reviews][js]") {
    const std::string& js = yuzu::server::kYuzuAuditJs;
    CampaignView v;
    v.campaign.campaign_id = "c1";
    v.campaign.status = "open";
    AccessReviewAttestationRow a;
    a.principal_type = "group";
    a.principal_id = "it-ops";
    a.role_name = "Operator";
    a.decision = "pending";
    v.attestations = {a};
    const std::string drawn = render_campaign(v, true);

    // The row carries the whole frozen tuple, in three separate attributes (no joined key, so a
    // comma or a colon in a value cannot blur two grants together).
    const std::string tr = "<tr data-principal-type=\"group\" data-principal-id=\"it-ops\" "
                           "data-role-name=\"Operator\">";
    CHECK_THAT(drawn, ContainsSubstring(tr));

    // Each data-* attribute on that row becomes a camelCase dataset name; the script must read
    // every one, or Attest and Flag would post an undefined field and the write would be refused.
    const auto row_at = drawn.find(tr);
    REQUIRE(row_at != std::string::npos);
    const std::string tag = drawn.substr(row_at, tr.size());
    const std::regex attr(R"re(data-([a-z]+(?:-[a-z]+)*)=)re");
    int seen = 0;
    for (std::sregex_iterator it(tag.begin(), tag.end(), attr), end; it != end; ++it, ++seen) {
        std::string camel;
        bool up = false;
        for (const char c : (*it)[1].str()) {
            if (c == '-') { up = true; continue; }
            camel += up ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : c;
            up = false;
        }
        INFO("dataset." << camel);
        CHECK_THAT(js, ContainsSubstring("d." + camel));
    }
    CHECK(seen == 3);
    // ... and the request body names them in the shape the REST route validates.
    for (const char* field : {"principal_type: d.principalType", "principal_id: d.principalId",
                              "role_name: d.roleName"})
        CHECK_THAT(js, ContainsSubstring(field));
}
