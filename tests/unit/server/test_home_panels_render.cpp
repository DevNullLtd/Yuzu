/// @file test_home_panels_render.cpp
/// Pure renderers for the HM-2 Home panels (policies, activity, health).
/// Fixtures are constructed from the handler value shapes, not captured.

#include "home_panels_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;
using namespace yuzu::server::home_panels;

namespace {
bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }

Policy pol(std::string id, std::string name, bool enabled = true) {
    Policy p;
    p.id = std::move(id);
    p.name = std::move(name);
    p.enabled = enabled;
    return p;
}
ComplianceSummary sum(std::string id, std::int64_t ok, std::int64_t total) {
    ComplianceSummary s;
    s.policy_id = std::move(id);
    s.compliant = ok;
    s.total = total;
    return s;
}
constexpr std::int64_t kNow = 1'760'000'000; // 2025-10-09 08:53 UTC
} // namespace

TEST_CASE("home_panels: pass_percent clamps to 0..100", "[server][home]") {
    CHECK(pass_percent(0, 0) == 0);
    CHECK(pass_percent(5, 0) == 0);
    CHECK(pass_percent(-3, 10) == 0);
    CHECK(pass_percent(250, 10) == 100);
    CHECK(pass_percent(99, 100) == 99);
    CHECK(pass_percent(1, 3) == 33);
}

TEST_CASE("home_panels: compliance_level thresholds are 90 and 70", "[server][home]") {
    CHECK(std::string(compliance_level(100)) == "ok");
    CHECK(std::string(compliance_level(90)) == "ok");
    CHECK(std::string(compliance_level(89)) == "warn");
    CHECK(std::string(compliance_level(70)) == "warn");
    CHECK(std::string(compliance_level(69)) == "bad");
}

TEST_CASE("home_panels: select_lowest_policies ranks, drops disabled, keeps no-result last",
          "[server][home]") {
    std::vector<Policy> p{pol("a", "Alpha"), pol("b", "Beta"), pol("c", "Gamma"),
                          pol("d", "Delta", false), pol("e", "Fresh"), pol("f", "Zeta"),
                          pol("g", "Eta"),  pol("h", "Theta")};
    std::vector<ComplianceSummary> s{sum("a", 9, 10), sum("b", 1, 10), sum("c", 5, 10),
                                     sum("d", 0, 10), sum("f", 10, 10), sum("g", 8, 10),
                                     sum("h", 7, 10)};
    auto out = select_lowest_policies(p, s);
    REQUIRE(out.enabled_total == 7); // Delta is disabled
    REQUIRE(out.lowest.size() == 5);
    CHECK(out.lowest[0].name == "Beta");
    CHECK(out.lowest[1].name == "Gamma");
    CHECK(out.lowest[2].name == "Theta");
    CHECK(out.lowest[3].name == "Eta");
    CHECK(out.lowest[4].name == "Alpha");
    // "Fresh" (no results) never outranks a policy that has results.
    for (const auto& b : out.lowest) CHECK(b.name != "Fresh");
}

TEST_CASE("home_panels: no-result policies fill remaining rows and never read as 0 percent",
          "[server][home]") {
    auto out = select_lowest_policies({pol("a", "Alpha"), pol("e", "Fresh")}, {sum("a", 3, 4)});
    REQUIRE(out.lowest.size() == 2);
    CHECK(out.lowest[1].name == "Fresh");
    auto html = render_policies_panel(Fact<PolicyPanel>::make_ok(out), kNow);
    CHECK(has(html, "No results yet"));
    CHECK(has(html, "3/4 (75%)"));
    CHECK(has(html, "Lowest 2 of 2 policies"));
    CHECK(has(html, "As of 08:53 UTC"));
}

TEST_CASE("home_panels: equal percentages tie-break by name then id", "[server][home]") {
    auto out = select_lowest_policies({pol("2", "Same"), pol("1", "Same"), pol("3", "Aaa")},
                                      {sum("1", 1, 2), sum("2", 2, 4), sum("3", 5, 10)});
    REQUIRE(out.lowest.size() == 3);
    CHECK(out.lowest[0].name == "Aaa");
}

TEST_CASE("home_panels: policies panel states are distinct sentences", "[server][home]") {
    auto d = render_policies_panel(Fact<PolicyPanel>::with(FactState::Denied, "Policy:Read"), kNow);
    auto l = render_policies_panel(Fact<PolicyPanel>::with(FactState::Limited), kNow);
    auto u = render_policies_panel(Fact<PolicyPanel>::with(FactState::Unavailable), kNow);
    CHECK(has(d, "It needs Policy:Read."));
    CHECK(has(l, "limited to a group of devices"));
    CHECK(has(u, "This is not zero."));
    CHECK_FALSE(has(u, "No policies are defined."));
    PolicyPanel empty;
    CHECK(has(render_policies_panel(Fact<PolicyPanel>::make_ok(empty), kNow), "No policies are defined."));
}

TEST_CASE("home_panels: bar width is clamped and level class follows thresholds", "[server][home]") {
    PolicyPanel p;
    p.enabled_total = 3;
    p.lowest = {{"Hi", 95, 100}, {"Mid", 75, 100}, {"Over", 500, 10}};
    auto html = render_policies_panel(Fact<PolicyPanel>::make_ok(p), kNow);
    CHECK(has(html, "style=\"width:95%\""));
    CHECK(has(html, "style=\"width:75%\""));
    CHECK(has(html, "style=\"width:100%\""));
    CHECK(has(html, "class=\"bar w\""));
    CHECK_FALSE(has(html, "width:500%"));
}

TEST_CASE("home_panels: hostile policy name is escaped", "[server][home]") {
    PolicyPanel p;
    p.enabled_total = 1;
    p.lowest = {{"<script>alert(1)</script>", 1, 2}};
    auto html = render_policies_panel(Fact<PolicyPanel>::make_ok(p), kNow);
    CHECK_FALSE(has(html, "<script>"));
    CHECK(has(html, "&lt;script&gt;"));
}

TEST_CASE("home_panels: to_activity_rows copies only the five safe fields", "[server][home]") {
    AuditEvent e;
    e.timestamp = kNow;
    e.principal = "alice";
    e.principal_role = "admin-secret-role";
    e.action = "policy.update";
    e.target_type = "Policy";
    e.target_id = "p1";
    e.detail = "DETAIL-LEAK";
    e.source_ip = "10.9.9.9";
    e.user_agent = "UA-LEAK";
    e.session_id = "SESSION-LEAK";
    e.result = "success";
    auto rows = to_activity_rows({e});
    REQUIRE(rows.size() == 1);
    auto html = render_activity_panel(Fact<std::vector<ActivityRow>>::make_ok(rows), kNow, "/access/audit");
    for (const char* leak : {"DETAIL-LEAK", "10.9.9.9", "UA-LEAK", "SESSION-LEAK", "admin-secret-role"})
        CHECK_FALSE(has(html, leak));
    CHECK(has(html, "Policy:p1"));
    CHECK(has(html, "alice"));
    CHECK(has(html, "08:53"));
    CHECK(has(html, "title=\"2025-10-09T08:53:20Z\""));
    CHECK(has(html, "pill ok"));
    CHECK(has(html, "href=\"/access/audit\""));
}

TEST_CASE("home_panels: activity result pill classes and escaping", "[server][home]") {
    std::vector<ActivityRow> rows;
    rows.push_back({kNow, "<script>x</script>", "a", std::string(130, 'T'), "failure"});
    rows.push_back({kNow, "u", "a", "", "denied"});
    rows.push_back({kNow, "u", "a", "", "weird"});
    auto html = render_activity_panel(Fact<std::vector<ActivityRow>>::make_ok(rows), kNow, "");
    CHECK(has(html, "pill bad"));
    CHECK(has(html, "pill warn"));
    CHECK(has(html, "pill idle"));
    CHECK_FALSE(has(html, "<script>"));
    CHECK_FALSE(has(html, "Audit log")); // button omitted when the page does not exist
    // 130-char target is truncated in the cell (48 chars + ellipsis) but whole in title.
    CHECK_FALSE(has(html, ">" + std::string(130, 'T') + "<"));
    CHECK(has(html, std::string(48, 'T')));
    CHECK(has(html, ">-<")); // empty target
}

TEST_CASE("home_panels: activity states", "[server][home]") {
    using R = Fact<std::vector<ActivityRow>>;
    CHECK(has(render_activity_panel(R::make_ok({}), kNow, ""), "No activity recorded yet."));
    CHECK(has(render_activity_panel(R::with(FactState::Denied, kAdminOnlyNeed), kNow, ""),
              "administrators only"));
    CHECK(has(render_activity_panel(R::with(FactState::Denied, "AuditLog:Read"), kNow, ""),
              "It needs AuditLog:Read."));
    CHECK(has(render_activity_panel(R::with(FactState::Unavailable), kNow, ""),
              "This is not zero."));
}

TEST_CASE("home_panels: parse_health_json reads the document's real fields", "[server][home]") {
    const std::string ok = R"({"status":"healthy","uptime_seconds":90061,"agents":{"online":12,"pending":3},
        "stores":{"pg_pool":"ok","pg_reachable":"ok","audit":"ok"},"version":"1.2.3",
        "executions":{"in_flight":4},"system":{"cpu_percent":55}})";
    auto h = parse_health_json(ok);
    REQUIRE(h);
    CHECK(h->healthy);
    CHECK(h->pg_reachable);
    CHECK(h->agents_online == 12);
    CHECK(h->uptime_seconds == 90061);
    CHECK(h->version == "1.2.3");
    REQUIRE(h->executions_running);
    CHECK(*h->executions_running == 4);
    CHECK(h->failing_stores.empty());

    CHECK_FALSE(parse_health_json("not json"));
    CHECK_FALSE(parse_health_json("{}"));
    CHECK_FALSE(parse_health_json(R"({"status":"healthy","stores":{},"uptime_seconds":1})")); // no agents
}

TEST_CASE("home_panels: degraded health names the failing stores and never renders hidden fields",
          "[server][home]") {
    const std::string body = R"({"status":"degraded","uptime_seconds":30,"agents":{"online":0},
        "stores":{"pg_pool":"ok","pg_reachable":"error","audit":"error","policies":"ok"},
        "system":{"cpu_percent":99,"rss_bytes":1}})";
    auto h = parse_health_json(body);
    REQUIRE(h);
    CHECK_FALSE(h->healthy);
    CHECK_FALSE(h->pg_reachable);
    REQUIRE(h->failing_stores.size() == 2);
    auto html = render_health_panel(Fact<HealthPanel>::make_ok(*h), kNow);
    CHECK(has(html, "Degraded"));
    CHECK(has(html, "audit, pg_reachable")); // nlohmann object keys are sorted
    CHECK(has(html, "PostgreSQL not reachable"));
    CHECK_FALSE(has(html, "cpu_percent"));
    CHECK_FALSE(has(html, "Executions running")); // executions absent in this document
    CHECK(has(html, "Agents connected to this server"));
}

TEST_CASE("home_panels: health executions row follows the optional value", "[server][home]") {
    HealthPanel h;
    h.healthy = true;
    h.pg_reachable = true;
    h.executions_running = 7;
    CHECK(has(render_health_panel(Fact<HealthPanel>::make_ok(h), kNow), "Executions running"));
    h.executions_running.reset();
    CHECK_FALSE(has(render_health_panel(Fact<HealthPanel>::make_ok(h), kNow), "Executions running"));
}

TEST_CASE("home_panels: unreadable health is a distinct sentence", "[server][home]") {
    auto html = render_health_panel(Fact<HealthPanel>::with(FactState::Unavailable), kNow);
    CHECK(has(html, "Server health could not be read."));
    CHECK_FALSE(has(html, "Healthy"));
}

TEST_CASE("home_panels: hhmm_utc is UTC, zero padded", "[server][home]") {
    CHECK(hhmm_utc(0) == "00:00");
    CHECK(hhmm_utc(3600 * 5 + 60 * 7) == "05:07");
}
