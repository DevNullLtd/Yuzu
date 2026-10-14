/// @file test_home_panels_routes.cpp
/// /fragments/dashboard/policies and /fragments/dashboard/activity through TestRouteSink:
/// gate order, caller classes, 200-note refusals, no-store, and the pinned
/// "a non-admin writes zero denial rows from the activity fragment" rule.

#include "home_panels_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }

struct Harness {
    bool deny_scoped{false};
    bool session{true};
    auth::Role role{auth::Role::admin};
    bool fleet_admit{true};
    int fleet_status{403};
    bool fleet_scoped{false};
    bool perm_admit{true};
    bool audit_degraded{false};
    bool policies_degraded{false};
    std::string audit_href;

    std::vector<std::string> order; // call order
    int policies_calls{0};
    int audit_calls{0};
    int perm_calls{0};
    int perm_denial_rows{0}; // what the real require_permission would have written
    std::string last_deny_verb;

    home_panels::Deps deps() {
        home_panels::Deps d;
        d.deny_service_scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                                          const std::string& verb, const std::string&,
                                          const std::string&, const std::string&) {
            order.push_back("deny");
            last_deny_verb = verb;
            if (deny_scoped) {
                res.status = 403;
                res.set_content("GATE-BODY-TEXT", "text/plain");
                return true;
            }
            return false;
        };
        d.auth_fn = [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<auth::Session> {
            order.push_back("auth");
            if (!session) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "u";
            s.role = role;
            return s;
        };
        d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                 const std::string& sec, const std::string& op) {
            order.push_back("fleet:" + sec + ":" + op);
            authz::FleetReadGate g;
            if (!fleet_admit) {
                res.status = fleet_status;
                res.set_content("GATE-BODY-TEXT", "text/plain");
                return g;
            }
            g.admitted = true;
            g.scope = fleet_scoped ? authz::VisibleSet{std::unordered_set<std::string>{"a"}}
                                   : authz::VisibleSet{std::nullopt};
            return g;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& sec,
                           const std::string& op) {
            order.push_back("perm:" + sec + ":" + op);
            ++perm_calls;
            if (!perm_admit) {
                ++perm_denial_rows;
                res.status = 403;
                return false;
            }
            return true;
        };
        d.policies_fn = [this]() -> std::optional<home_panels::PolicyPanel> {
            ++policies_calls;
            if (policies_degraded) return std::nullopt;
            home_panels::PolicyPanel p;
            p.enabled_total = 1;
            p.lowest = {{"Disk encryption", 8, 10}};
            return p;
        };
        d.audit_fn = [this](int limit) -> std::optional<std::vector<AuditEvent>> {
            ++audit_calls;
            CHECK(limit == 8);
            if (audit_degraded) return std::nullopt;
            AuditEvent e;
            e.timestamp = 1'760'000'000;
            e.principal = "alice";
            e.action = "login";
            e.result = "success";
            e.detail = "DETAIL-LEAK";
            e.source_ip = "10.1.2.3";
            return std::vector<AuditEvent>{e};
        };
        d.now_fn = [] { return std::int64_t{1'760'000'000}; };
        d.audit_href = audit_href;
        return d;
    }
};

} // namespace

TEST_CASE("home_panels_routes: registers exactly two routes and rejects unbound closures",
          "[server][routes][home]") {
    Harness h;
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    CHECK(sink.route_count() == 2);

    auto d = h.deps();
    d.audit_fn = nullptr;
    test::TestRouteSink s2;
    CHECK_THROWS_AS(home_panels::register_dashboard_panel_routes(s2, d), std::invalid_argument);
}

TEST_CASE("home_panels_routes: policies gate order, exact securable, no-store", "[server][routes][home]") {
    Harness h;
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Cache-Control") == "no-store");
    CHECK(r->get_header_value("Content-Type").find("text/html") != std::string::npos);
    CHECK(has(r->body, "Disk encryption"));
    CHECK(has(r->body, "8/10 (80%)"));
    REQUIRE(h.order.size() == 3);
    CHECK(h.order[0] == "deny");
    CHECK(h.order[1] == "auth");
    CHECK(h.order[2] == "fleet:Policy:Read");
    CHECK(h.last_deny_verb == "dashboard.fragment.access_denied");
}

TEST_CASE("home_panels_routes: policies refusals are 200 notes, never the gate body",
          "[server][routes][home]") {
    SECTION("service-scoped token") {
        Harness h;
        h.deny_scoped = true;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(has(r->body, "GATE-BODY-TEXT"));
        CHECK(has(r->body, "It needs Policy:Read."));
        CHECK(h.policies_calls == 0);
        CHECK(h.order.size() == 1); // auth_fn never ran
    }
    SECTION("RBAC denied") {
        Harness h;
        h.fleet_admit = false;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(has(r->body, "GATE-BODY-TEXT"));
        CHECK(has(r->body, "It needs Policy:Read."));
        CHECK(h.policies_calls == 0);
    }
    SECTION("gate 503 is Unavailable, not Denied") {
        Harness h;
        h.fleet_admit = false;
        h.fleet_status = 503;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
        REQUIRE(r);
        CHECK(has(r->body, "This is not zero."));
    }
    SECTION("no session") {
        Harness h;
        h.session = false;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(h.policies_calls == 0);
    }
}

TEST_CASE("home_panels_routes: engaged scope is Limited and the aggregate read never runs",
          "[server][routes][home]") {
    Harness h;
    h.fleet_scoped = true;
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
    REQUIRE(r);
    CHECK(has(r->body, "limited to a group of devices"));
    CHECK_FALSE(has(r->body, "Disk encryption"));
    CHECK(h.policies_calls == 0);
}

TEST_CASE("home_panels_routes: a degraded policies read is Unavailable, never zero",
          "[server][routes][home]") {
    Harness h;
    h.policies_degraded = true;
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    auto r = sink.dispatch("GET", "/fragments/dashboard/policies");
    REQUIRE(r);
    CHECK(has(r->body, "This is not zero."));
    CHECK_FALSE(has(r->body, "No policies are defined."));
    CHECK_FALSE(has(r->body, "0%"));
}

TEST_CASE("home_panels_routes: activity for an effective admin reads 8 rows, safe fields only",
          "[server][routes][home]") {
    Harness h;
    h.audit_href = "/access/audit";
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    auto r = sink.dispatch("GET", "/fragments/dashboard/activity");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Cache-Control") == "no-store");
    CHECK(has(r->body, "alice"));
    CHECK(has(r->body, "href=\"/access/audit\""));
    CHECK_FALSE(has(r->body, "DETAIL-LEAK"));
    CHECK_FALSE(has(r->body, "10.1.2.3"));
    REQUIRE(h.order.size() == 3);
    CHECK(h.order[2] == "perm:AuditLog:Read");
}

TEST_CASE("home_panels_routes: a non-admin writes ZERO denial rows from the activity fragment",
          "[server][routes][home]") {
    Harness h;
    h.role = auth::Role::user;
    h.perm_admit = false; // would deny AND write an auth.permission_required row if asked
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    for (int i = 0; i < 3; ++i) {
        auto r = sink.dispatch("GET", "/fragments/dashboard/activity");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(has(r->body, "administrators only"));
    }
    CHECK(h.perm_calls == 0);
    CHECK(h.perm_denial_rows == 0);
    CHECK(h.audit_calls == 0);
}

TEST_CASE("home_panels_routes: an admin without AuditLog:Read gets a Denied note",
          "[server][routes][home]") {
    Harness h;
    h.perm_admit = false;
    test::TestRouteSink sink;
    home_panels::register_dashboard_panel_routes(sink, h.deps());
    auto r = sink.dispatch("GET", "/fragments/dashboard/activity");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(has(r->body, "It needs AuditLog:Read."));
    CHECK(h.audit_calls == 0);
}

TEST_CASE("home_panels_routes: activity degraded and service-scoped states", "[server][routes][home]") {
    SECTION("degraded") {
        Harness h;
        h.audit_degraded = true;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/activity");
        REQUIRE(r);
        CHECK(has(r->body, "This is not zero."));
        CHECK_FALSE(has(r->body, "No activity recorded yet."));
    }
    SECTION("service-scoped token short-circuits before auth, role and reads") {
        Harness h;
        h.deny_scoped = true;
        test::TestRouteSink sink;
        home_panels::register_dashboard_panel_routes(sink, h.deps());
        auto r = sink.dispatch("GET", "/fragments/dashboard/activity");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_FALSE(has(r->body, "GATE-BODY-TEXT"));
        CHECK(h.order.size() == 1);
        CHECK(h.audit_calls == 0);
    }
}

// ── read_policy_panel: the production policies_fn body ────────────────────

namespace {

struct CountingComplianceApi final : ComplianceApi {
    mutable int list_policies_calls{0};
    mutable int by_policy_calls{0};
    mutable int summary_calls{0};
    mutable bool enabled_only_seen{false};
    bool policies_ok{true};
    bool by_policy_ok{true};

    std::expected<std::vector<PolicyFragment>, PolicyReadError>
    list_fragments(const FragmentQuery&) const override {
        return std::vector<PolicyFragment>{};
    }
    std::expected<std::vector<Policy>, PolicyReadError>
    list_policies(const PolicyQuery& q) const override {
        ++list_policies_calls;
        enabled_only_seen = q.enabled_only;
        if (!policies_ok)
            return std::unexpected(PolicyReadError::kDegraded);
        Policy a;
        a.id = "a";
        a.name = "Alpha";
        a.enabled = true;
        Policy b = a;
        b.id = "b";
        b.name = "Beta";
        return std::vector<Policy>{a, b};
    }
    std::expected<std::optional<PolicyDetail>, PolicyReadError>
    get_policy(const std::string&) const override {
        return std::optional<PolicyDetail>{};
    }
    std::expected<FleetCompliance, PolicyReadError> fleet_compliance() const override {
        return FleetCompliance{};
    }
    std::expected<ComplianceSummary, PolicyReadError>
    compliance_summary(const std::string&) const override {
        ++summary_calls;
        return ComplianceSummary{};
    }
    std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
    policy_agent_statuses(const std::string&) const override {
        return std::vector<PolicyAgentStatus>{};
    }
    std::expected<std::vector<ComplianceSummary>, PolicyReadError>
    compliance_by_policy() const override {
        ++by_policy_calls;
        if (!by_policy_ok)
            return std::unexpected(PolicyReadError::kDegraded);
        ComplianceSummary s;
        s.policy_id = "b";
        s.compliant = 1;
        s.total = 4;
        return std::vector<ComplianceSummary>{s};
    }
};

} // namespace

TEST_CASE("read_policy_panel: one list, one batched read, zero per-policy reads",
          "[home][route][policies]") {
    // Kills: a revert to the per-policy compliance_summary loop, and a disabled-policy leak.
    CountingComplianceApi api;
    auto p = home_panels::read_policy_panel(api);
    REQUIRE(p.has_value());
    CHECK(api.list_policies_calls == 1);
    CHECK(api.enabled_only_seen);
    CHECK(api.by_policy_calls == 1);
    CHECK(api.summary_calls == 0);
    REQUIRE(p->lowest.size() == 2);
    CHECK(p->lowest[0].name == "Beta"); // has results, ranked before the no-result policy
    CHECK(p->lowest[1].total == 0);
}

TEST_CASE("read_policy_panel: a degraded read is nullopt, never an empty panel",
          "[home][route][policies]") {
    CountingComplianceApi a;
    a.policies_ok = false;
    CHECK_FALSE(home_panels::read_policy_panel(a).has_value());
    CHECK(a.by_policy_calls == 0);
    CountingComplianceApi b;
    b.by_policy_ok = false;
    CHECK_FALSE(home_panels::read_policy_panel(b).has_value());
}
