/// @file test_home_routes.cpp
/// GET /home and GET /fragments/home/summary through TestRouteSink: the exact
/// (securable, op) per figure, 403 -> 200 note without gate text, scope-engaged
/// confinement, degrade -> Unavailable (never 0), service-scoped denial first, and
/// no store scan for non-admins. Every closure is a fake; nothing spawns or sleeps.

#include "home_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::home;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

InventoryDeviceRow row(std::string id, std::string os, bool online, bool stale = false) {
    InventoryDeviceRow r;
    r.agent_id = std::move(id);
    r.hostname = "HOST-" + r.agent_id;
    r.os = std::move(os);
    r.online = online;
    r.stale = stale;
    return r;
}

struct HomeHarness {
    test::TestRouteSink sink;
    HomeRoutes routes;

    // Caller.
    bool signed_in = true;
    auth::Role role = auth::Role::admin;
    bool service_scoped = false;

    // Gates.
    bool allow_inventory = true, allow_policy = true, allow_execution = true, allow_approval = true,
         allow_enrollment = true;
    int gate_status = 403; // status the refused gate writes
    authz::VisibleSet scope;       // nullopt = TOP
    std::vector<std::pair<std::string, std::string>> gate_calls;
    std::vector<std::string> order;

    // Closures.
    InventoryDevicesResult roster;
    bool wire_roster = true;
    std::optional<EstateCounts> estate;
    bool wire_estate = false;
    std::optional<ComplianceFigure> compliance = ComplianceFigure{100, 90, 5, 5, 90.0};
    std::optional<std::vector<FailedRow>> failed = std::vector<FailedRow>{};
    std::optional<ApprovalFigure> approvals = ApprovalFigure{0, std::nullopt};
    std::optional<std::int64_t> enrolment = 0;
    int roster_calls = 0, estate_calls = 0, compliance_calls = 0, failed_calls = 0, approvals_calls = 0,
        enrolment_calls = 0, service_denials = 0;

    HomeHarness() {
        Deps d;
        d.auth_fn = [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<auth::Session> {
            order.push_back("auth");
            if (!signed_in) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.role = role;
            return s;
        };
        d.deny_service_scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                                          const std::string& action, const std::string&,
                                          const std::string&, const std::string&) {
            order.push_back("deny_service");
            if (!service_scoped)
                return false;
            ++service_denials;
            CHECK(action == "home.fragment.access_denied");
            res.status = 403;
            return true;
        };
        d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                 const std::string& sec, const std::string& op) {
            gate_calls.emplace_back(sec, op);
            authz::FleetReadGate g;
            const bool ok = (sec == "Inventory" && allow_inventory) ||
                            (sec == "Policy" && allow_policy) || (sec == "Execution" && allow_execution) ||
                            (sec == "Enrollment" && allow_enrollment);
            if (!ok) {
                res.status = gate_status;
                res.set_content("SECRET-GATE-BODY", "text/plain");
                return g;
            }
            g.admitted = true;
            g.scope = scope;
            return g;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& sec,
                           const std::string& op) {
            gate_calls.emplace_back(sec, op);
            if (sec == "Approval" && allow_approval)
                return true;
            res.status = gate_status;
            res.set_content("SECRET-GATE-BODY", "text/plain");
            return false;
        };
        d.now_fn = [] { return std::int64_t{1'760'000'000}; };
        d.roster_fn = [this]() {
            ++roster_calls;
            return roster;
        };
        d.fleet_estate_fn = [this](std::int64_t) {
            ++estate_calls;
            return estate;
        };
        d.compliance_fn = [this]() {
            ++compliance_calls;
            return compliance;
        };
        d.failed_fn = [this]() {
            ++failed_calls;
            return failed;
        };
        d.approvals_fn = [this]() {
            ++approvals_calls;
            return approvals;
        };
        d.enrolment_fn = [this]() {
            ++enrolment_calls;
            return enrolment;
        };
        wire(std::move(d));
    }

    void wire(Deps d) {
        if (!wire_roster)
            d.roster_fn = {};
        if (!wire_estate)
            d.fleet_estate_fn = {};
        routes.register_routes(sink, std::move(d));
    }

    bool gated(const std::string& sec, const std::string& op) const {
        for (const auto& c : gate_calls)
            if (c.first == sec && c.second == op)
                return true;
        return false;
    }
};

} // namespace

// ── page ──────────────────────────────────────────────────────────────────

TEST_CASE("/home: signed-out redirects to /login, signed-in serves the baked page", "[home][route]") {
    HomeHarness h;
    h.signed_in = false;
    auto out = h.sink.Get("/home");
    REQUIRE(out);
    CHECK(out->status == 302);
    CHECK(out->get_header_value("Location") == "/login");

    h.signed_in = true;
    auto page = h.sink.Get("/home");
    REQUIRE(page);
    CHECK(page->status == 200);
    CHECK(has(page->body, "<h1>Home</h1>"));
    CHECK(has(page->body, "hx-get=\"/fragments/home/summary\""));
    CHECK(has(page->get_header_value("Cache-Control"), "no-store"));
}

// ── fragment: ordering and headers ────────────────────────────────────────

// Kills: dropping deny_service_scoped_fn, or running a figure gate before it.
TEST_CASE("summary: service-scoped denial runs first and nothing is read", "[home][route]") {
    HomeHarness h;
    h.service_scoped = true;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(out->status == 403);
    CHECK(h.service_denials == 1);
    CHECK(h.gate_calls.empty());
    CHECK(h.roster_calls == 0);
    CHECK(h.compliance_calls == 0);
    CHECK(h.order.front() == "deny_service");
}

TEST_CASE("summary: no-store, html, one gate call per figure with the exact securable", "[home][route]") {
    HomeHarness h;
    h.roster.rows = {row("a", "windows", true)};
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(out->status == 200);
    CHECK(has(out->get_header_value("Cache-Control"), "no-store"));
    CHECK(has(out->get_header_value("Content-Type"), "text/html"));
    CHECK(h.gated("Inventory", "Read"));
    CHECK(h.gated("Policy", "Read"));
    CHECK(h.gated("Execution", "Read"));
    CHECK(h.gated("Approval", "Read"));
    CHECK(h.gated("Enrollment", "Read"));
    CHECK(h.gate_calls.size() == 5);
}

// ── denial ────────────────────────────────────────────────────────────────

// Kills: forwarding the gate's own response body, or surfacing its 4xx status.
TEST_CASE("summary: a refused gate becomes a 200 note that names the securable only", "[home][route]") {
    HomeHarness h;
    h.allow_inventory = h.allow_policy = h.allow_execution = h.allow_approval = false;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(out->status == 200);
    CHECK_FALSE(has(out->body, "SECRET-GATE-BODY"));
    CHECK(has(out->body, "Inventory:Read"));
    CHECK(has(out->body, "Policy:Read"));
    CHECK(has(out->body, "Execution:Read"));
    CHECK(has(out->body, "Approval:Read"));
    // A denied figure never reached its reader.
    CHECK(h.roster_calls == 0);
    CHECK(h.compliance_calls == 0);
    CHECK(h.failed_calls == 0);
    CHECK(h.approvals_calls == 0);
    // And never reads as the green "all clear".
    CHECK_FALSE(has(out->body, "Nothing needs attention"));
}

TEST_CASE("summary: a 503 gate is Unavailable, not Denied", "[home][route]") {
    HomeHarness h;
    h.allow_policy = false;
    h.gate_status = 503;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(has(out->body, "Could not read Compliance. This is not zero."));
    CHECK_FALSE(has(out->body, "You do not have access to this figure. It needs <span class=\"mono\">Policy"));
}

// ── scope ─────────────────────────────────────────────────────────────────

// Kills: dropping the scope check in the devices figure, and rendering a fleet
// aggregate for a confined caller.
TEST_CASE("summary: an engaged scope narrows devices and limits fleet aggregates", "[home][route]") {
    HomeHarness h;
    h.scope = std::unordered_set<std::string>{"a", "b"};
    h.wire_estate = false;
    h.roster.rows = {row("a", "windows", true), row("b", "linux", false, true),
                     row("c", "darwin", true), row("d", "windows", true)};
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(has(out->body, "<div class=\"v\">1</div>"));        // online: only "a" is in scope
    CHECK(has(out->body, "of 2 seen in the last 30 days"));   // total narrowed to the scope
    CHECK(has(out->body, "Fleet totals are not shown to accounts limited to a group of devices."));
    CHECK(h.compliance_calls == 0);
    CHECK(h.failed_calls == 0);
    CHECK(h.estate_calls == 0);
    // Limited is a non-Ok contributor: no green row.
    CHECK_FALSE(has(out->body, "Nothing needs attention"));
}

// A TOP (unconfined) caller over fakes; the tests set only the closures they probe.
Deps top_deps() {
    Deps d;
    d.auth_fn = [](const httplib::Request&, httplib::Response&) { return std::optional<auth::Session>(auth::Session{}); };
    d.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) {
        authz::FleetReadGate g;
        g.admitted = true;
        g.scope = std::nullopt;
        return g;
    };
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) { return true; };
    d.now_fn = [] { return std::int64_t{1'760'000'000}; };
    return d;
}

TEST_CASE("summary: TOP uses the SQL estate seam and never loads the roster", "[home][route]") {
    Deps d = top_deps();
    int roster_calls = 0, estate_calls = 0;
    d.roster_fn = [&]() { ++roster_calls; return InventoryDevicesResult{}; };
    d.fleet_estate_fn = [&](std::int64_t now_ms) -> std::optional<EstateCounts> {
        ++estate_calls;
        CHECK(now_ms == 1'760'000'000LL * 1000);
        return EstateCounts{250000, 240000, 5000, 5000};
    };
    test::TestRouteSink sink;
    HomeRoutes r;
    r.register_routes(sink, std::move(d));
    auto out = sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(estate_calls == 1);
    CHECK(roster_calls == 0);
    CHECK(has(out->body, "240,000"));
    CHECK(has(out->body, "of 250,000 seen in the last 30 days"));
}

// Kills: a failed SQL estate read rendered as an empty or zero fleet, or silently
// falling back to the roster (the 100k-capped path TOP callers must never take).
TEST_CASE("summary: a failed TOP estate read is Unavailable, never zero, and never the roster",
          "[home][route]") {
    Deps d = top_deps();
    int roster_calls = 0, estate_calls = 0;
    d.roster_fn = [&]() { ++roster_calls; return InventoryDevicesResult{}; };
    d.fleet_estate_fn = [&](std::int64_t) -> std::optional<EstateCounts> {
        ++estate_calls;
        return std::nullopt;
    };
    test::TestRouteSink sink;
    HomeRoutes r;
    r.register_routes(sink, std::move(d));
    auto out = sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(out->status == 200);
    CHECK(estate_calls == 1);
    CHECK(roster_calls == 0);
    CHECK(has(out->body, "Could not read The device roster. This is not zero."));
    CHECK_FALSE(has(out->body, "No devices have reported"));
    CHECK_FALSE(has(out->body, "<div class=\"v\">0</div>"));
    CHECK_FALSE(has(out->body, "Nothing needs attention"));
}

// Kills: a cache that never expires, expires early, or keys on anything but the injected
// server clock (the SQL scan costs seconds at fleet scale, so TOP callers share one read).
TEST_CASE("summary: the TOP estate read is cached 60 s on the server clock", "[home][route][cache]") {
    Deps d = top_deps();
    std::int64_t now = 1'760'000'000;
    d.now_fn = [&] { return now; };
    int estate_calls = 0;
    d.fleet_estate_fn = [&](std::int64_t now_ms) -> std::optional<EstateCounts> {
        ++estate_calls;
        CHECK(now_ms == now * 1000);
        return EstateCounts{100 + estate_calls, 90, 5, 5};
    };
    test::TestRouteSink sink;
    HomeRoutes r;
    r.register_routes(sink, std::move(d));

    REQUIRE(sink.Get("/fragments/home/summary"));
    CHECK(estate_calls == 1);
    now += 59;
    auto hit = sink.Get("/fragments/home/summary");
    REQUIRE(hit);
    CHECK(estate_calls == 1);
    CHECK(has(hit->body, "of 101 seen in the last 30 days"));
    now += 1; // 60 s after the read
    auto miss = sink.Get("/fragments/home/summary");
    REQUIRE(miss);
    CHECK(estate_calls == 2);
    CHECK(has(miss->body, "of 102 seen in the last 30 days"));
    now -= 5; // a clock that stepped backwards is a miss, never a stale hit
    REQUIRE(sink.Get("/fragments/home/summary"));
    CHECK(estate_calls == 3);
}

// Kills: a failed read cached (or an expired value served in its place), which would render
// an outage as a stale or zero fleet for a minute.
TEST_CASE("summary: a failed TOP estate read is never cached", "[home][route][cache]") {
    Deps d = top_deps();
    std::int64_t now = 1'760'000'000;
    d.now_fn = [&] { return now; };
    int estate_calls = 0;
    bool fail = true;
    d.fleet_estate_fn = [&](std::int64_t) -> std::optional<EstateCounts> {
        ++estate_calls;
        if (fail)
            return std::nullopt;
        return EstateCounts{200, 190, 5, 5};
    };
    test::TestRouteSink sink;
    HomeRoutes r;
    r.register_routes(sink, std::move(d));

    auto down = sink.Get("/fragments/home/summary");
    REQUIRE(down);
    CHECK(has(down->body, "Could not read The device roster. This is not zero."));
    fail = false; // same second: the failure was not remembered
    auto up = sink.Get("/fragments/home/summary");
    REQUIRE(up);
    CHECK(estate_calls == 2);
    CHECK(has(up->body, "of 200 seen in the last 30 days"));
    fail = true; // expired entry + failed read: Unavailable, not the old figure
    now += 60;
    auto again = sink.Get("/fragments/home/summary");
    REQUIRE(again);
    CHECK(estate_calls == 3);
    CHECK(has(again->body, "Could not read The device roster. This is not zero."));
    CHECK_FALSE(has(again->body, "of 200 seen"));
    fail = false; // the failed read did not restart the window or leave the old figure behind
    auto recovered = sink.Get("/fragments/home/summary");
    REQUIRE(recovered);
    CHECK(estate_calls == 4);
    CHECK(has(recovered->body, "of 200 seen in the last 30 days"));
}

// Kills: a scoped caller reading (or being served) the fleet-wide cached figure.
TEST_CASE("summary: a scoped caller never touches the estate seam or its cache", "[home][route][cache]") {
    Deps d = top_deps();
    d.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) {
        authz::FleetReadGate g;
        g.admitted = true;
        g.scope = std::unordered_set<std::string>{"a"};
        return g;
    };
    int estate_calls = 0;
    d.fleet_estate_fn = [&](std::int64_t) -> std::optional<EstateCounts> {
        ++estate_calls;
        return EstateCounts{999999, 999999, 0, 0};
    };
    d.roster_fn = [] { return InventoryDevicesResult{}; };
    test::TestRouteSink sink;
    HomeRoutes r;
    r.register_routes(sink, std::move(d));
    for (int i = 0; i < 3; ++i) {
        auto out = sink.Get("/fragments/home/summary");
        REQUIRE(out);
        CHECK_FALSE(has(out->body, "999,999"));
    }
    CHECK(estate_calls == 0);
}

// Kills: a scoped caller's capped roster presented as an exact count (PLAN section 2:
// "bounded at 100k and labelled"). Below the cap the figure stays exact.
TEST_CASE("summary: a scoped roster read at the row cap is labelled a lower bound",
          "[home][route]") {
    auto render = [](std::size_t n) {
        HomeHarness h;
        h.scope = std::unordered_set<std::string>{"a", "b"};
        h.roster.rows.assign(n, row("z", "linux", true));
        h.roster.rows[0] = row("a", "windows", true);
        h.roster.rows[1] = row("b", "linux", false, true);
        auto out = h.sink.Get("/fragments/home/summary");
        REQUIRE(out);
        return out->body;
    };
    const std::string capped = render(kRosterReadCap);
    CHECK(has(capped, "<div class=\"v\">at least 1</div>"));
    CHECK(has(capped, "of at least 2 seen in the last 30 days"));
    CHECK(has(capped, "At least 1 device has not reported for 2 days or more"));
    const std::string exact = render(kRosterReadCap - 1);
    CHECK(has(exact, "of 2 seen in the last 30 days"));
    CHECK_FALSE(has(exact, "at least"));
}

// ── degrade ───────────────────────────────────────────────────────────────

// Kills: mapping a degraded read to zero.
TEST_CASE("summary: degraded readers are Unavailable, never zero", "[home][route]") {
    HomeHarness h;
    h.roster.roster_degraded = true;
    h.compliance = std::nullopt;
    h.failed = std::nullopt;
    h.approvals = std::nullopt;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(out->status == 200);
    CHECK(has(out->body, "Could not read The device roster. This is not zero."));
    CHECK(has(out->body, "Could not read Compliance. This is not zero."));
    CHECK(has(out->body, "Could not read Executions. This is not zero."));
    CHECK(has(out->body, "Could not read Approvals. This is not zero."));
    CHECK_FALSE(has(out->body, "<div class=\"v\">0</div>"));
    CHECK_FALSE(has(out->body, "No devices have reported"));
    CHECK_FALSE(has(out->body, "Nothing needs attention"));
}

TEST_CASE("summary: an unwired roster is not an empty fleet", "[home][route]") {
    HomeHarness h;
    h.roster.rows.clear();
    h.roster.ci_degraded = true; // what build_hw_roster returns with no offline store
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK_FALSE(has(out->body, "No devices have reported"));
    CHECK(has(out->body, "This is not zero."));
}

TEST_CASE("summary: a genuinely empty fleet says so", "[home][route]") {
    HomeHarness h;
    h.roster.rows.clear();
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(has(out->body, "No devices have reported in the last 30 days."));
}

// ── figures ───────────────────────────────────────────────────────────────

TEST_CASE("summary: failed executions use the 24 h window and the read cap", "[home][route]") {
    HomeHarness h;
    const std::int64_t now = 1'760'000'000;
    std::vector<FailedRow> rows;
    for (int i = 0; i < 100; ++i)
        rows.push_back({now - 60, now - 70});
    h.failed = rows;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(has(out->body, "100+"));
}

TEST_CASE("summary: approvals print the exact count; oldest only when known", "[home][route]") {
    HomeHarness h;
    h.approvals = ApprovalFigure{137, std::nullopt}; // truncated list: no honest oldest
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(has(out->body, "<div class=\"v\">137</div>"));
    CHECK_FALSE(has(out->body, "oldest submitted"));
    CHECK_FALSE(has(out->body, "100+ waiting"));
}

// ── enrolment ─────────────────────────────────────────────────────────────

// Kills: gating the row on the legacy role instead of Enrollment:Read (the REST twin's
// gate), and running the pending-agent scan for a caller who will never see the row.
TEST_CASE("summary: the enrolment scan runs only for an Enrollment:Read caller", "[home][route]") {
    HomeHarness h;
    h.role = auth::Role::admin; // the legacy role alone must not open the row
    h.allow_enrollment = false;
    h.enrolment = 4;
    auto out = h.sink.Get("/fragments/home/summary");
    REQUIRE(out);
    CHECK(h.gated("Enrollment", "Read"));
    CHECK(h.enrolment_calls == 0);
    CHECK_FALSE(has(out->body, "awaiting enrolment"));
    CHECK_FALSE(has(out->body, "Pending enrolments"));

    HomeHarness a;
    a.role = auth::Role::user; // and a non-admin role with the grant sees it
    a.enrolment = 4;
    auto granted = a.sink.Get("/fragments/home/summary");
    REQUIRE(granted);
    CHECK(a.enrolment_calls == 1);
    CHECK(has(granted->body, "4 agents are awaiting enrolment"));

    HomeHarness u;
    u.gate_status = 503; // a degraded gate is a note, never silence and never a scan
    u.allow_enrollment = false;
    auto degraded = u.sink.Get("/fragments/home/summary");
    REQUIRE(degraded);
    CHECK(u.enrolment_calls == 0);
    CHECK(has(degraded->body, "Could not read Pending enrolments. This is not zero."));
}

// ── links ─────────────────────────────────────────────────────────────────

TEST_CASE("resolve_links falls back to today's pages and follows the nav when a key exists",
          "[home][route]") {
    // Kills: a swapped or mistyped fallback, a dropped failed-status suffix, and a lookup
    // that ignores the nav (every target asserted exactly, in both directions).
    const auto fallback = resolve_links({});
    CHECK(fallback.approvals == "/instructions");
    CHECK(fallback.executions == "/instructions");
    CHECK(fallback.devices == "/hardware");
    CHECK(fallback.enrolment == "/settings#pending-section");
    CHECK(fallback.audit.empty()); // no audit nav item: the Activity button is omitted

    static const shell::NavItem items[] = {
        {"approvals", "Approvals", "/ap", ""},
        {"executions", "Executions", "/ex", ""},
        {"hardware", "Hardware", "/hw", ""},
        {"groups", "Groups", "/gr", ""},
        {"audit", "Audit", "/au", ""},
    };
    static const shell::NavGroup groups[] = {{"All", items}};
    const auto followed = resolve_links(groups);
    CHECK(followed.approvals == "/ap");
    CHECK(followed.executions == "/ex?status=failed");
    CHECK(followed.devices == "/hw");
    CHECK(followed.enrolment == "/gr");
    CHECK(followed.audit == "/au");
}

// ── pure roster tally ─────────────────────────────────────────────────────

// Kills: double-counted states (F1): an online-and-stale row is online, once.
TEST_CASE("tally_roster partitions state exactly", "[home][route]") {
    std::vector<InventoryDeviceRow> rows = {
        row("1", "windows", true),        row("2", "linux", true),
        row("3", "darwin", false),        row("4", "freebsd", false, true),
        row("5", "?", false, true),       row("6", "windows", true, true), // online-and-stale
    };
    const auto c = tally_roster(rows);
    CHECK(c.total == 6);
    CHECK(c.online + c.not_seen + c.offline == c.total);
    CHECK(c.online == 3);
    CHECK(c.not_seen == 2);
    CHECK(c.offline == 1);
}

// ── production wiring ─────────────────────────────────────────────────────

// Kills: every case above passing while server.cpp drops the HomeRoutes registration or
// one of its seams (the real server would 404 both routes, or render a figure Unwired).
// Precedent: test_health_routes.cpp's wiring tripwire.
TEST_CASE("home_routes: wiring -- server.cpp registers HomeRoutes and binds every seam",
          "[home][route]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto at = src.find("home_routes_->register_routes(");
    REQUIRE(at != std::string::npos);
    const std::string block = src.substr(at, 6000);
    for (const char* seam :
         {".auth_fn", ".deny_service_scoped_fn", ".fleet_read_fn", ".perm_fn", ".now_fn",
          ".roster_fn", ".fleet_estate_fn", ".compliance_fn", ".failed_fn", ".approvals_fn",
          ".enrolment_fn"})
        CHECK(has(block, seam));
}
