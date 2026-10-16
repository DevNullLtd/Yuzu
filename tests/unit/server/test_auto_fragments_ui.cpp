/// @file test_auto_fragments_ui.cpp
/// Pure-renderer pins for the three `/auto` fragments (pre-flight, deploy, verify): the ids the
/// page scripts and htmx swaps target, and each button's hx wiring. Markup only; the route
/// behaviour (gates, scope, audit) lives in test_{preflight,deployment,verify}_routes.cpp.

#include "deployment_routes.hpp"
#include "preflight_routes.hpp"
#include "verify_ui.hpp"
#include "url_attr_scan.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {
bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

// These fragments are swapped in by htmx and their wrappers are concatenated by hand, so one
// dropped or extra </div> pulls the neighbouring page content into, or out of, the wrong panel.
void require_balanced(const std::string& html) {
    INFO(html);
    REQUIRE(count_of(html, "<div ") + count_of(html, "<div>") == count_of(html, "</div>"));
}

PairedComparison one_pair() {
    PairedComparison c;
    c.paired = 1;
    c.window_days = 7;
    MachinePair p;
    p.agent_id = "a1";
    c.pairs.push_back(p);
    return c;
}
} // namespace

TEST_CASE("auto fragments: pre-flight keeps its swap targets and button wiring", "[preflight][ui]") {
    const std::string cfg = render_auto_config({{"g1", "Group"}}, {{"run1", "Run one"}});
    for (const char* pin : {"id=\"auto-cfg\"", "id=\"auto-results\"", "id=\"auto-deploy\"", "id=\"auto-rail\"",
                            "id=\"auto-verify\" hx-get=\"/fragments/auto/verify\" hx-trigger=\"load\""}) {
        INFO(pin);
        REQUIRE(has(cfg, pin));
    }
    REQUIRE(has(cfg, "hx-post=\"/fragments/auto/run\" hx-include=\"#auto-cfg input, #auto-cfg select\" "
                     "hx-target=\"#auto-results\" hx-swap=\"innerHTML\">Run pre-flight</button>"));
    REQUIRE(has(cfg, "hx-get=\"/fragments/auto/result?run=run1&amp;n=1\" hx-target=\"#auto-results\""));
    REQUIRE(has(cfg, "hx-post=\"/fragments/auto/delete?run=run1\" hx-confirm=\"Delete this pre-flight run? "
                     "This cannot be undone.\" hx-target=\"#auto-rail\" hx-swap=\"outerHTML\""));

    preflight::PreflightDeviceResult go;
    go.agent_id = "a1";
    go.bucket = preflight::Bucket::kPass;
    const std::string res = render_auto_results({go}, "cfg", "Group", "/fragments/auto/result?run=run1&n=1",
                                                false, "run1");
    REQUIRE(has(res, "<div id=\"auto-grid\" hx-get=\"/fragments/auto/result?run=run1&amp;n=1\" "
                     "hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\">"));
    REQUIRE(has(res, "hx-get=\"/fragments/auto/deploy?run=run1\" hx-target=\"#auto-deploy\" "
                     "hx-swap=\"innerHTML\">Deploy go-cohort (1)"));
}

TEST_CASE("auto fragments: pre-flight wrappers stay balanced under the Deployments title",
          "[preflight][ui]") {
    for (const auto& cfg : {render_auto_config({{"g1", "Group"}}, {{"run1", "Run one"}}),
                            render_auto_config({}, {})}) {
        require_balanced(cfg);
        REQUIRE(has(cfg, "<div class=\"af-ph\"><h1>Deployments</h1><p>Check software rollouts first, "
                         "deploy them, then verify the result.</p></div>"));
    }

    preflight::PreflightDeviceResult go;
    go.agent_id = "a1";
    go.bucket = preflight::Bucket::kPass;
    require_balanced(render_auto_results({go}, "cfg", "Group", "/fragments/auto/result?run=run1&n=1", false,
                                         "run1"));
    require_balanced(render_auto_results({go}, "cfg", "Group", "", true, "run1", "store degraded"));
}

TEST_CASE("auto fragments: deploy keeps its swap targets and button wiring", "[deployment][ui]") {
    const std::string cfg = render_deploy_config("run1", "Run one", 3, 2);
    for (const char* pin : {"id=\"deploy-cfg\"", "id=\"auto-deploy-grid\"", "name=\"run\" value=\"run1\""}) {
        INFO(pin);
        REQUIRE(has(cfg, pin));
    }
    REQUIRE(has(cfg, "hx-post=\"/fragments/auto/deploy/run\" hx-include=\"#deploy-cfg input\" "
                     "hx-confirm=\"Deploy to 5 devices from &quot;Run one&quot;? "));
    REQUIRE(has(cfg, "hx-target=\"#auto-deploy-grid\" hx-swap=\"innerHTML\">Stage + deploy to cohort"));

    DeploymentRow dep;
    DeploymentDeviceRow dev;
    dev.agent_id = "a1";
    dev.step = "failed";
    const std::string res = render_deploy_results(dep, {dev}, "/fragments/auto/deploy/result?dep=d1&n=1");
    REQUIRE(has(res, "<div id=\"dp-grid\" hx-get=\"/fragments/auto/deploy/result?dep=d1&amp;n=1\" "
                     "hx-trigger=\"load delay:900ms\" hx-swap=\"outerHTML\">"));
    // The filter script and the markup must agree on the class names (a rename on one side
    // alone silently stops the KPI filter from hiding anything).
    for (const char* cls : {"af-grp", "af-empty"}) {
        INFO(cls);
        REQUIRE(has(res, std::string("class=\"") + cls + "\""));
        REQUIRE(has(res, std::string("querySelector") + (cls[3] == 'g' ? "All" : "") + "('." + cls + "')"));
    }
}

TEST_CASE("auto fragments: deploy wrappers stay balanced", "[deployment][ui]") {
    require_balanced(render_deploy_config("run1", "Run one", 3, 2));

    DeploymentRow dep;
    DeploymentDeviceRow dev;
    dev.agent_id = "a1";
    dev.step = "failed";
    require_balanced(render_deploy_results(dep, {dev}, "/fragments/auto/deploy/result?dep=d1&n=1"));
    require_balanced(render_deploy_results(dep, {}, ""));
}

TEST_CASE("auto fragments: verify keeps its swap targets and button wiring", "[verify][ui]") {
    const std::string cfg = render_verify_config({{"g1", "Group"}});
    REQUIRE(has(cfg, "id=\"verify-cfg\""));
    REQUIRE(has(cfg, "<div id=\"verify-results\">"));
    REQUIRE(has(cfg, "hx-get=\"/fragments/auto/verify/run\" hx-include=\"#verify-cfg input, #verify-cfg select\" "
                     "hx-target=\"#verify-results\" hx-swap=\"innerHTML\">Compare</button>"));

    PairedComparison c;
    c.paired = 40;
    c.window_days = 7;
    const std::string res = render_verify_result(c, 45, false, "App", "1.0", "2.0", 7, "/fragments/auto/verify/drill?x=1");
    REQUIRE(has(res, "hx-get=\"/fragments/auto/verify/drill?x=1\" hx-target=\"#verify-drill\" "
                     "hx-swap=\"innerHTML\">Show per-machine pairs</button>"));
    REQUIRE(has(res, "id=\"verify-drill\""));
}

TEST_CASE("auto fragments: verify wrappers stay balanced and the truncation banner leads the result",
          "[verify][ui]") {
    require_balanced(render_verify_config({{"g1", "Group"}}));

    PairedComparison c;
    c.paired = 40;
    c.window_days = 7;
    const std::string plain = render_verify_result(c, 45, false, "App", "1.0", "2.0", 7, "/fragments/auto/verify/drill?x=1");
    const std::string cut = render_verify_result(c, 45, true, "App", "1.0", "2.0", 7, "/fragments/auto/verify/drill?x=1");
    require_balanced(plain);
    require_balanced(cut);
    REQUIRE_FALSE(has(plain, "vf-ind bad"));
    REQUIRE(has(cut, "<div class=\"vf-ind bad\">"));
    // The banner sits above the comparison it warns about.
    REQUIRE(cut.find("vf-ind bad") < cut.find("class=\"vf-shift\""));
}

TEST_CASE("auto fragments: verify drill keeps its table wrapper and truncation banner", "[verify][ui]") {
    const PairedComparison c = one_pair();
    const std::string plain = render_verify_drill(c, false);
    const std::string cut = render_verify_drill(c, true);
    require_balanced(plain);
    require_balanced(cut);
    require_balanced(render_verify_drill(PairedComparison{}, true));

    REQUIRE(has(plain, "<div class=\"af-panel vf-tw\"><table class=\"vf-tbl\">"));
    REQUIRE(has(plain, "</tbody></table></div><div class=\"vf-audit\">Audited read"));
    REQUIRE_FALSE(has(plain, "vf-ind bad"));
    REQUIRE(has(cut, "<div class=\"vf-ind bad\">"));
    REQUIRE(has(cut, "Truncated \xE2\x80\x94 the cohort exceeded the read cap"));
    // Banner first, then the table panel.
    REQUIRE(cut.find("vf-ind bad") < cut.find("af-panel vf-tw"));
}

// ── URL encoding of the agent id in the device links (/hardware/ci?id=) ──────

namespace {
const std::vector<std::string> kHostileAgentIds = {
    "a&lens=x#y", "../../fragments/device/live/run?id=z", "a/b", "x y", "%2e%2e", "caf\xC3\xA9",
};

void check_device_links(const std::string& html, const std::string& id) {
    INFO("id=" << id);
    const auto urls = yuzu::test::url_attr_values(html);
    const std::string want = "/hardware/ci?id=" + yuzu::server::url_query_value(id);
    CHECK(yuzu::test::has_url(urls, want));
    for (const auto& u : urls) {
        if (u.rfind("/hardware/ci", 0) != 0)
            continue;
        // one '?', one parameter, no fragment: the id can neither add a parameter nor truncate.
        CHECK(std::count(u.begin(), u.end(), '?') == 1);
        CHECK(std::count(u.begin(), u.end(), '&') == 0);
        CHECK(std::count(u.begin(), u.end(), '#') == 0);
        CHECK(yuzu::test::path_slashes(u) == 2); // /hardware/ci
    }
}
} // namespace

TEST_CASE("auto fragments: a hostile agent id is query-encoded in the pre-flight, deploy and "
          "verify device links",
          "[preflight][deployment][verify][ui][url_path_segment]") {
    for (const auto& id : kHostileAgentIds) {
        preflight::PreflightDeviceResult go;
        go.agent_id = id;
        go.bucket = preflight::Bucket::kPass;
        check_device_links(render_auto_results({go}, "cfg", "Group", "", true, "run1"), id);

        DeploymentRow dep;
        DeploymentDeviceRow dev;
        dev.agent_id = id;
        dev.step = "failed";
        check_device_links(render_deploy_results(dep, {dev}, ""), id);

        PairedComparison c;
        c.paired = 1;
        c.window_days = 7;
        MachinePair p;
        p.agent_id = id;
        c.pairs.push_back(p);
        check_device_links(render_verify_drill(c, false), id);
    }
}
