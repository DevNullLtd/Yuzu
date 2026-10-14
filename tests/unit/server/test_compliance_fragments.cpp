/**
 * test_compliance_fragments.cpp — pure renderer tests for the Compliance page
 * fragments (compliance_fragments.hpp). Fixtures in, markup out: no store, no
 * request, no clock (the renderer takes `now`).
 */

#include "compliance_fragments.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;
namespace ch = yuzu::server::compliance_html;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

ch::PolicyRow row(const std::string& name, int64_t compliant, int64_t non_compliant,
                  int64_t unknown = 0, int64_t fixing = 0, int64_t error = 0, bool enabled = true) {
    ch::PolicyRow r;
    r.id = "pol-" + name;
    r.name = name;
    r.scope = "tag:env == 'prod'";
    r.enabled = enabled;
    r.compliant = compliant;
    r.non_compliant = non_compliant;
    r.unknown = unknown;
    r.fixing = fixing;
    r.error = error;
    r.total = compliant + non_compliant + unknown + fixing + error;
    return r;
}

} // namespace

TEST_CASE("compliance summary: status pill follows one definition", "[compliance][fragments]") {
    CHECK(has(ch::policy_status_pill(row("a", 5, 0)), "Compliant"));
    // failing = non_compliant + error, so an error-only policy is failing, not compliant
    CHECK(has(ch::policy_status_pill(row("b", 3, 1, 0, 0, 2)), "3 failing"));
    CHECK(has(ch::policy_status_pill(row("c", 3, 0, 0, 2)), "2 fixing"));
    CHECK(has(ch::policy_status_pill(row("d", 3, 0, 4)), "4 unknown"));
    CHECK(has(ch::policy_status_pill(row("e", 0, 0)), "No results"));
    // disabled wins over any tally
    CHECK(has(ch::policy_status_pill(row("f", 0, 9, 0, 0, 0, false)), "Disabled"));
}

TEST_CASE("compliance summary: Failing checks tile counts non_compliant plus error, like the pill",
          "[compliance][fragments]") {
    ch::SummaryView v;
    v.policies.push_back(row("a", 5, 2, 0, 0, 3));
    v.fleet.total_checks = 10;
    v.fleet.compliant = 5;
    v.fleet.non_compliant = 2;
    v.fleet.error = 3;
    v.fleet.compliance_pct = 50.0;

    const auto html = ch::render_summary(v);
    CHECK(has(html, "<div class=\"v\">5</div><div class=\"l\">Failing checks</div>"));
    CHECK(has(html, "5 failing")); // the row pill agrees with the tile
    CHECK(has(html, "of 10 device checks"));
}

TEST_CASE("compliance summary: policies tile counts enabled with the total as detail",
          "[compliance][fragments]") {
    ch::SummaryView v;
    v.policies.push_back(row("a", 1, 0));
    v.policies.push_back(row("b", 1, 0, 0, 0, 0, false));
    const auto html = ch::render_summary(v);
    CHECK(has(html, "<div class=\"v\">1</div><div class=\"l\">Policies enabled</div>"));
    CHECK(has(html, "2 total"));
}

TEST_CASE("compliance summary: the 100-policy cap is stated, not silent", "[compliance][fragments]") {
    ch::SummaryView v;
    v.policy_limit = 3;
    for (int i = 0; i < 3; ++i)
        v.policies.push_back(row("p" + std::to_string(i), 1, 0));
    CHECK(has(ch::render_summary(v), "Showing the first 3 policies."));
    v.policies.pop_back();
    CHECK_FALSE(has(ch::render_summary(v), "Showing the first"));
}

TEST_CASE("compliance summary: names and scopes are escaped, empty state keeps its text",
          "[compliance][fragments][security]") {
    ch::SummaryView v;
    auto r = row("<script>x</script>", 1, 0);
    r.scope = "\"><img src=x onerror=alert(1)>";
    r.id = "p\"q";
    v.policies.push_back(r);
    const auto html = ch::render_summary(v);
    CHECK_FALSE(has(html, "<script>x"));
    CHECK_FALSE(has(html, "<img src=x"));
    CHECK(has(html, "&lt;script&gt;"));
    CHECK_FALSE(has(html, "hx-get=\"/fragments/compliance/p\"q"));

    ch::SummaryView empty;
    CHECK(has(ch::render_summary(empty), "No policies defined"));
}

TEST_CASE("compliance detail: an unrecognised status string is escaped, never raw",
          "[compliance][fragments][security]") {
    CHECK(has(ch::agent_status_pill("<b>boom</b>"), "&lt;b&gt;boom&lt;/b&gt;"));
    CHECK_FALSE(has(ch::agent_status_pill("<b>boom</b>"), "<b>boom"));
    CHECK(has(ch::agent_status_pill("non_compliant"), "Non-compliant"));
    CHECK(has(ch::agent_status_pill("error"), "Error"));
}

TEST_CASE("compliance detail: kv panel has Applies to, Check, Remediation and no Owner",
          "[compliance][fragments]") {
    ch::DetailView v;
    v.policy_id = "p1";
    v.policy_name = "Disk <encrypted>";
    v.have_policy = true;
    v.applies_to = "ostype == 'windows'";
    v.check = "result.encrypted == true";
    v.remediation_available = true;
    v.agents.push_back({"a1", "host-1", "windows", "compliant", "3 min ago", "{\"ok\":true}"});
    v.summary.compliant = 1;
    v.summary.total = 1;

    const auto html = ch::render_detail(v);
    CHECK(has(html, "Applies to"));
    CHECK(has(html, "ostype == &#39;windows&#39;"));
    CHECK(has(html, "<span>Check</span>"));
    CHECK(has(html, "<span>Remediation</span><b>Available</b>"));
    CHECK_FALSE(has(html, "Owner"));
    CHECK_FALSE(has(html, "needs approval"));
    CHECK(has(html, "Disk &lt;encrypted&gt;"));
    CHECK(has(html, "host-1"));
}

TEST_CASE("compliance detail: a missing fragment lookup renders a dash; no policy omits the panel",
          "[compliance][fragments]") {
    ch::DetailView v;
    v.policy_id = "p1";
    v.policy_name = "p1";
    v.have_policy = true;
    v.agents.push_back({"a1", "a1", "", "unknown", "never", ""});
    CHECK(has(ch::render_detail(v), "<span>Check</span><b class=\"mono-id\">-</b>"));
    CHECK(has(ch::render_detail(v), "<span>Remediation</span><b>None</b>"));

    v.have_policy = false;
    CHECK_FALSE(has(ch::render_detail(v), "<span>Applies to</span>"));
}

TEST_CASE("compliance detail: degraded is not 'no data yet'; confined states its scope",
          "[compliance][fragments]") {
    ch::DetailView v;
    v.policy_id = "p1";
    v.policy_name = "p1";
    v.degraded = true;
    auto degraded = ch::render_detail(v);
    CHECK(has(degraded, "temporarily unavailable"));
    CHECK_FALSE(has(degraded, "No compliance data yet"));

    v.degraded = false;
    v.confined = true;
    auto empty = ch::render_detail(v);
    CHECK(has(empty, "No compliance data yet"));
    CHECK(has(empty, "Rows cover devices in your scope."));

    v.confined = false;
    CHECK_FALSE(has(ch::render_detail(v), "Rows cover devices in your scope."));
}

TEST_CASE("compliance detail: format_age", "[compliance][fragments]") {
    CHECK(ch::format_age(1000, 0) == "never");
    CHECK(ch::format_age(1000, 970) == "30s ago");
    CHECK(ch::format_age(1000, 1000 - 180) == "3 min ago");
    CHECK(ch::format_age(10000, 10000 - 7300) == "2h ago");
    CHECK(ch::format_age(1000, 2000) == "0s ago"); // clock skew never goes negative
}

TEST_CASE("policy fragments: used-by, cap note and empty state", "[compliance][fragments]") {
    ch::FragmentsView v;
    CHECK(has(ch::render_fragments(v), "No policy fragments"));

    v.fragment_limit = 2;
    v.fragments.push_back({"f1", "Svc <running>", "get_service", 0, false});
    v.fragments.push_back({"f2", "Disk", "get_disk", 100, true});
    const auto html = ch::render_fragments(v);
    CHECK(has(html, "Svc &lt;running&gt;"));
    CHECK(has(html, "0 policies"));
    CHECK(has(html, "100+ policies"));
    CHECK(has(html, "Showing the first 2 fragments."));
}

TEST_CASE("tag compliance: Display Name and Free-form marker kept, every cell escaped",
          "[compliance][fragments][security]") {
    std::vector<ch::TagRow> rows;
    rows.push_back({"role", "Role <b>", 3, 1, {"web", "<db>"}});
    rows.push_back({"service", "Service", 0, 0, {}});
    const auto html = ch::render_tag_compliance(rows, 4, 3);

    CHECK(has(html, "<th>Display name</th>"));
    CHECK(has(html, "Role &lt;b&gt;"));
    CHECK(has(html, "web, &lt;db&gt;"));
    CHECK_FALSE(has(html, "<db>"));
    CHECK(has(html, "Free-form"));
    CHECK(has(html, "class=\"pill bad\">1</span>"));
    CHECK(has(html, "class=\"pill ok\">0</span>"));
    CHECK(has(html, "Compliance: 3/4 agents have all required tags"));
    // the settings-only classes must not leak into the hosted markup
    CHECK_FALSE(has(html, "user-table"));
    CHECK_FALSE(has(html, "role-badge"));

    CHECK_FALSE(has(ch::render_tag_compliance(rows, 0, 0), "agents have all required tags"));
}

TEST_CASE("compliance summary: controls follow the probed flags", "[compliance][fragments]") {
    ch::SummaryView v;
    v.policies.push_back(row("A", 1, 0));
    // Read-only viewer: no switch, no Evaluate, no Delete, no New policy.
    auto html = ch::render_summary(v);
    CHECK_FALSE(has(html, "class=\"sw\""));
    CHECK_FALSE(has(html, "data-act=\"evaluate\""));
    CHECK_FALSE(has(html, "data-act=\"delete-policy\""));
    CHECK_FALSE(has(html, "data-act=\"new-policy\""));
    CHECK(has(html, "data-can-write=\"0\""));

    v.can_write = true;
    html = ch::render_summary(v);
    CHECK(has(html, "class=\"sw\""));
    CHECK(has(html, "data-act=\"new-policy\""));
    CHECK_FALSE(has(html, "data-act=\"evaluate\""));
    CHECK_FALSE(has(html, "data-act=\"invalidate-all\""));

    v.can_execute = true;
    v.can_delete = true;
    html = ch::render_summary(v);
    CHECK(has(html, "data-act=\"evaluate\""));
    CHECK(has(html, "data-act=\"invalidate-all\""));
    CHECK(has(html, "data-act=\"delete-policy\""));
    // Names reach attributes only escaped.
    v.policies[0].name = "x\" onmouseover=\"1";
    html = ch::render_summary(v);
    CHECK_FALSE(has(html, "onmouseover=\"1"));
}

TEST_CASE("compliance detail: actions render only for a read policy; Remediate needs remediation",
          "[compliance][fragments]") {
    ch::DetailView d;
    d.policy_id = "p1";
    d.policy_name = "P <1>";
    d.have_policy = true;
    d.summary.non_compliant = 7;
    auto html = ch::render_detail(d);
    CHECK_FALSE(has(html, "data-act=\"remediate\""));
    CHECK(has(html, "data-act=\"invalidate\""));
    CHECK(has(html, "data-act=\"delete-policy\""));
    CHECK(has(html, "P &lt;1&gt;"));

    d.remediation_available = true;
    html = ch::render_detail(d);
    CHECK(has(html, "data-act=\"remediate\""));
    CHECK(has(html, "data-n=\"7\""));

    d.confined = true; // counts cover only the viewer's scope: do not state N
    CHECK_FALSE(has(ch::render_detail(d), "data-n="));

    d.degraded = true;
    CHECK_FALSE(has(ch::render_detail(d), "data-act="));
}

TEST_CASE("policy fragments: Delete is disabled while a policy uses the fragment",
          "[compliance][fragments]") {
    ch::FragmentsView v;
    v.fragments.push_back({"f1", "Idle", "c", 0, false});
    v.fragments.push_back({"f2", "Used", "c", 3, false});
    v.fragments.push_back({"f3", "Capped", "c", 100, true});
    const auto html = ch::render_fragments(v);
    CHECK(has(html, "data-act=\"new-fragment\""));
    const auto f1 = html.find("data-id=\"f1\"");
    const auto f2 = html.find("data-id=\"f2\"");
    const auto f3 = html.find("data-id=\"f3\"");
    REQUIRE(f1 != std::string::npos);
    CHECK(html.substr(f1, f2 - f1).find("disabled") == std::string::npos);
    CHECK(html.substr(f2, f3 - f2).find("disabled") != std::string::npos);
    CHECK(html.substr(f3).find("disabled") != std::string::npos);
}
