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

TEST_CASE("reviews glue: every control the renderer draws has a handler, and the decision is not hard-coded",
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
