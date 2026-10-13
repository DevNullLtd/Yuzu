/// @file test_auto_fragments_ui.cpp
/// Pure-renderer pins for the three `/auto` fragments (pre-flight, deploy, verify): the ids the
/// page scripts and htmx swaps target, and each button's hx wiring. Markup only; the route
/// behaviour (gates, scope, audit) lives in test_{preflight,deployment,verify}_routes.cpp.

#include "deployment_routes.hpp"
#include "preflight_routes.hpp"
#include "verify_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

namespace {
bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
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
