/// @file test_device_containment.cpp
/// Device containment (quarantine) on /hardware: the shared admit-then-filter read
/// (quarantine_visible.hpp), the PURE renderers (device_containment_render.cpp), the two
/// fragments (device_containment_routes.cpp) driven through TestRouteSink, and the pins
/// on static/yuzu-estate.js. The list pill / lens allowlist / banner placeholder live in
/// test_hardware_routes.cpp beside the list harness they need.

#include "device_containment_render.hpp"
#include "device_containment_routes.hpp"
#include "device_estate_render.hpp"
#include "device_estate_routes.hpp"
#include "quarantine_visible.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace yuzu::server {
extern const std::string kYuzuEstateJs;
}

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

QuarantineRecord rec(const std::string& id, std::int64_t applied = 0, std::int64_t confirmed = 0) {
    QuarantineRecord r;
    r.agent_id = id;
    r.status = "active";
    r.quarantined_by = "alice";
    r.quarantined_at = 1700000000;
    r.reason = "malware";
    r.last_applied_at = applied;
    r.last_confirmed_at = confirmed;
    return r;
}

// A gate whose per-id outcome is table-driven: absent = pass, else the Response status.
struct Gate {
    std::unordered_map<std::string, int> fail_status;
    std::vector<std::string> probed;
    QuarantineScopedPermFn fn() {
        return [this](const httplib::Request&, httplib::Response& res, const std::string& type,
                      const std::string& op, const std::string& id) {
            probed.push_back(type + ":" + op + ":" + id);
            auto it = fail_status.find(id);
            if (it == fail_status.end())
                return true;
            res.status = it->second;
            return false;
        };
    }
};

const std::string kEvil = "<img src=x onerror=1>";

} // namespace

// ───────────────────────── quarantine_visible_records ─────────────────────────

// Kills: dropping the status-bearing rule — a bare 401/503 from a per-record probe
// silently filtering the record is a fail-open on a degraded authz check.
TEST_CASE("quarantine_visible: 403 filters the record, any other failing probe fails the whole read closed",
          "[quarantine][visible]") {
    httplib::Request req;
    const QuarantineListFn list = [] {
        return std::optional<std::vector<QuarantineRecord>>{{rec("a"), rec("b"), rec("c")}};
    };
    {
        Gate g;
        g.fail_status["b"] = 403;
        auto v = quarantine_visible_records(req, list, g.fn());
        REQUIRE(v.status == QuarantineReadStatus::Ok);
        REQUIRE(v.records.size() == 2);
        CHECK(v.records[0].agent_id == "a");
        CHECK(v.records[1].agent_id == "c");
    }
    for (int status : {401, 500, 503}) {
        Gate g;
        g.fail_status["b"] = status;
        auto v = quarantine_visible_records(req, list, g.fn());
        CHECK(v.status == QuarantineReadStatus::ProbeDegraded);
        CHECK(v.records.empty());
    }
}

// Kills: nullopt rendering as an empty list; an unwired gate serving an unfiltered list.
TEST_CASE("quarantine_visible: a nullopt store read is StoreDegraded; an unwired gate is ScopeUnwired",
          "[quarantine][visible]") {
    httplib::Request req;
    Gate g;
    auto v = quarantine_visible_records(
        req, [] { return std::optional<std::vector<QuarantineRecord>>{}; }, g.fn());
    CHECK(v.status == QuarantineReadStatus::StoreDegraded);
    CHECK(v.records.empty());
    auto u = quarantine_visible_records(
        req, [] { return std::optional<std::vector<QuarantineRecord>>{{rec("a")}}; },
        QuarantineScopedPermFn{});
    CHECK(u.status == QuarantineReadStatus::ScopeUnwired);
    CHECK(u.records.empty());
    // present-empty is a genuinely empty result, distinct from the two above
    auto e = quarantine_visible_records(
        req, [] { return std::optional<std::vector<QuarantineRecord>>{std::vector<QuarantineRecord>{}}; },
        g.fn());
    CHECK(e.status == QuarantineReadStatus::Ok);
    CHECK(e.records.empty());
}

// Kills: probing records outside only_ids, and the cap not stopping the walk.
TEST_CASE("quarantine_visible: only_ids bounds the probes; max_visible stops the walk and sets more",
          "[quarantine][visible]") {
    httplib::Request req;
    const QuarantineListFn list = [] {
        return std::optional<std::vector<QuarantineRecord>>{{rec("a"), rec("b"), rec("c"), rec("d")}};
    };
    {
        Gate g;
        const std::unordered_set<std::string> only{"b", "d"};
        QuarantineVisibleOptions opt;
        opt.only_ids = &only;
        auto v = quarantine_visible_records(req, list, g.fn(), opt);
        CHECK(g.probed == std::vector<std::string>{"Security:Read:b", "Security:Read:d"});
        CHECK(v.records.size() == 2);
    }
    {
        Gate g;
        QuarantineVisibleOptions opt;
        opt.max_visible = 2;
        auto v = quarantine_visible_records(req, list, g.fn(), opt);
        CHECK(v.records.size() == 2);
        CHECK(v.more);
        CHECK(g.probed.size() == 2); // c and d were never probed
    }
    {
        Gate g;
        QuarantineVisibleOptions opt;
        opt.max_visible = 4;
        auto v = quarantine_visible_records(req, list, g.fn(), opt);
        CHECK(v.records.size() == 4);
        CHECK_FALSE(v.more);
    }
}

// ───────────────────────── Renderers ──────────────────────────────────────────

// Kills: collapsing the three states into one, or claiming "isolated" from the record alone.
TEST_CASE("containment_state: record, applied and confirmed are distinct", "[quarantine][render]") {
    CHECK(containment_state(rec("a")) == ContainmentState::Recorded);
    CHECK(containment_state(rec("a", 100)) == ContainmentState::Applied);
    CHECK(containment_state(rec("a", 100, 200)) == ContainmentState::Confirmed);
    CHECK(containment_state(rec("a", 0, 200)) == ContainmentState::Confirmed);
}

TEST_CASE("quarantine panel: escapes every agent-supplied string", "[quarantine][render]") {
    QuarantinePanelView v;
    QuarantinePanelRow row;
    row.record = rec("agent-1");
    row.record.reason = kEvil;
    row.record.whitelist = kEvil;
    row.record.quarantined_by = kEvil;
    row.hostname = kEvil;
    v.rows.push_back(row);
    const std::string html = render_quarantine_panel(v);
    CHECK_FALSE(contains(html, kEvil));
    CHECK(contains(html, "&lt;img src=x onerror=1&gt;"));
}

// Kills: a degraded read rendering as an empty panel.
TEST_CASE("quarantine panel: degraded reads are banners, never an empty list", "[quarantine][render]") {
    QuarantinePanelView v;
    v.read = QuarantinePanelView::Read::StoreDegraded;
    auto store = render_quarantine_panel(v);
    CHECK(contains(store, "could not be read"));
    CHECK(contains(store, "not an empty list"));
    CHECK_FALSE(contains(store, "No device is quarantined"));
    v.read = QuarantinePanelView::Read::ProbeDegraded;
    auto probe = render_quarantine_panel(v);
    CHECK(contains(probe, "not an empty list"));
    CHECK_FALSE(contains(probe, "No device is quarantined"));
    v.read = QuarantinePanelView::Read::Ok;
    CHECK(contains(render_quarantine_panel(v), "No device is quarantined in your scope."));
}

TEST_CASE("quarantine panel: states, hostname fallback and the cap note", "[quarantine][render]") {
    QuarantinePanelView v;
    v.cap = 2;
    v.more = true;
    QuarantinePanelRow a;
    a.record = rec("id-with-host", 5, 6);
    a.hostname = "HOST-A";
    QuarantinePanelRow b;
    b.record = rec("id-no-host");
    v.rows = {a, b};
    const std::string html = render_quarantine_panel(v);
    CHECK(contains(html, "HOST-A"));
    CHECK(contains(html, ">id-no-host</a>")); // agent id shown when no hostname
    CHECK(contains(html, "Confirmed on device"));
    CHECK(contains(html, "Recorded"));
    CHECK(contains(html, "Showing the newest 2 records you can see; older records exist."));
    CHECK(contains(html, "lens=containment"));
}

// Kills: offering Quarantine/Release to a caller without Security:Execute, and a lens that
// claims a state the record does not prove.
TEST_CASE("containment lens: states and honest copy", "[quarantine][render]") {
    ContainmentLensView v;
    v.agent_id = "agent-1";
    v.hostname = "HOST-1";
    v.online = true;
    v.identity_known = true;
    v.can_execute = true;
    {
        auto html = render_containment_lens(v); // no record
        CHECK(contains(html, "No active quarantine record."));
        CHECK(contains(html, "does not show whether the device's firewall rules were removed"));
        CHECK(contains(html, "data-act=\"quarantine\""));
        CHECK_FALSE(contains(html, "data-act=\"release\""));
        CHECK_FALSE(contains(html, "Not quarantined"));
    }
    v.record = rec("agent-1");
    {
        auto html = render_containment_lens(v);
        CHECK(contains(html, "not yet applied or confirmed"));
        CHECK(contains(html, "data-act=\"release\""));
    }
    v.record = rec("agent-1", 100);
    CHECK(contains(render_containment_lens(v), "Applied to the device but not yet confirmed"));
    v.record = rec("agent-1", 100, 200);
    CHECK(contains(render_containment_lens(v), "confirmed on the device"));
    v.record = rec("agent-1");
    v.online = false;
    CHECK(contains(render_containment_lens(v), "Waiting for device to connect"));
    // identity unreadable: the lens never claims the device is offline
    v.identity_known = false;
    CHECK_FALSE(contains(render_containment_lens(v), "Waiting for device to connect"));
    CHECK(contains(render_containment_lens(v), "data-online=\"?\""));
}

TEST_CASE("containment lens: no Security:Execute disables both actions and names the permission",
          "[quarantine][render]") {
    ContainmentLensView v;
    v.agent_id = "a";
    v.can_execute = false;
    auto none = render_containment_lens(v);
    CHECK_FALSE(contains(none, "data-act=\"quarantine\""));
    CHECK(contains(none, "needs the Security:Execute permission"));
    v.record = rec("a");
    auto rel = render_containment_lens(v);
    CHECK_FALSE(contains(rel, "data-act=\"release\""));
    CHECK(contains(rel, "needs the Security:Execute permission"));
}

TEST_CASE("containment lens: states the approval-gate asymmetry and that release ends the record only",
          "[quarantine][render]") {
    ContainmentLensView v;
    v.agent_id = "a";
    auto html = render_containment_lens(v);
    CHECK(contains(html, "do not go through the approval step"));
    CHECK(contains(html, "releasing ends the record only"));
    CHECK(contains(html, "lens=actions"));
    CHECK_FALSE(contains(html, "always reachable"));
}

TEST_CASE("containment lens: denied and degraded reads", "[quarantine][render]") {
    ContainmentLensView v;
    v.agent_id = "a";
    v.read = ContainmentLensView::Read::Denied;
    auto denied = render_containment_lens(v);
    CHECK(contains(denied, "data-denied=\"1\""));
    CHECK(contains(denied, "Security:Read"));
    v.read = ContainmentLensView::Read::Degraded;
    auto degraded = render_containment_lens(v);
    CHECK(contains(degraded, "not \"not quarantined\""));
    CHECK_FALSE(contains(degraded, "No active quarantine record"));
}

TEST_CASE("containment banner: empty unless an active record or a degraded read; keeps its id",
          "[quarantine][render]") {
    ContainmentLensView v;
    v.agent_id = "agent 1";
    CHECK(render_containment_banner(v) == "<div id=\"hw-quarantine-banner\"></div>");
    v.record = rec("agent 1");
    auto on = render_containment_banner(v);
    CHECK(contains(on, "id=\"hw-quarantine-banner\""));
    CHECK(contains(on, "This device is quarantined."));
    CHECK(contains(on, "Instructions to it are withheld until it is released"));
    CHECK(contains(on, "id=agent%201"));
    v.record.reset();
    v.read = ContainmentLensView::Read::Degraded;
    CHECK(contains(render_containment_banner(v), "not \"not quarantined\""));
    v.read = ContainmentLensView::Read::Denied;
    CHECK(render_containment_banner(v) == "<div id=\"hw-quarantine-banner\"></div>");
}

// ───────────────────────── Fragments ──────────────────────────────────────────

namespace {

struct ContainmentHarness {
    DeviceContainmentRoutes routes;
    yuzu::server::test::TestRouteSink sink; // after the owner (TestRouteSink invariant 1)

    bool authenticated = true;
    std::optional<std::vector<QuarantineRecord>> list = std::vector<QuarantineRecord>{};
    std::expected<std::optional<QuarantineRecord>, std::string> status{std::optional<QuarantineRecord>{}};
    std::unordered_map<std::string, int> read_fail;    // Security:Read outcome per id
    std::unordered_map<std::string, int> execute_fail; // Security:Execute outcome per id
    std::vector<std::string> probed;
    std::optional<InventoryDeviceRow> identity;
    bool identity_degraded = false;
    int hostnames_calls = 0;

    ContainmentHarness() {
        DeviceContainmentRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<auth::Session> {
            if (!authenticated) {
                res.status = 401;
                return std::nullopt;
            }
            return auth::Session{};
        };
        d.scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                                  const std::string& op, const std::string& id) {
            probed.push_back(t + ":" + op + ":" + id);
            auto& tbl = op == "Execute" ? execute_fail : read_fail;
            if (auto it = tbl.find(id); it != tbl.end()) {
                res.status = it->second;
                return false;
            }
            return true;
        };
        d.list_fn = [this] { return list; };
        d.status_fn = [this](const std::string&) { return status; };
        d.identity_fn = [this](const std::string&)
            -> std::expected<std::optional<InventoryDeviceRow>, PresenceReadError> {
            if (identity_degraded)
                return std::unexpected(PresenceReadError::StoreUnavailable);
            return identity;
        };
        d.hostnames_fn = [this] {
            ++hostnames_calls;
            return std::unordered_map<std::string, std::string>{{"a", "HOST-A"}};
        };
        d.now_secs_fn = [] { return std::int64_t{1700000500}; };
        routes.register_routes(sink, d);
    }
};

} // namespace

TEST_CASE("fragment: quarantined panel — filters per record, names hosts, 401 stays 401",
          "[quarantine][route]") {
    ContainmentHarness h;
    h.list = std::vector<QuarantineRecord>{rec("a"), rec("hidden"), rec("c")};
    h.read_fail["hidden"] = 403;
    auto res = h.sink.Get("/fragments/hardware/quarantine");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "HOST-A"));
    CHECK(contains(res->body, ">c</a>"));
    CHECK_FALSE(contains(res->body, "hidden"));

    h.authenticated = false;
    auto anon = h.sink.Get("/fragments/hardware/quarantine");
    REQUIRE(anon);
    CHECK(anon->status == 401);
}

// Kills: answering the degraded states with a non-2xx body htmx would drop, or an empty panel.
TEST_CASE("fragment: quarantined panel — degraded store and a failing probe answer 200 with a banner",
          "[quarantine][route]") {
    {
        ContainmentHarness h;
        h.list = std::nullopt;
        auto res = h.sink.Get("/fragments/hardware/quarantine");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(contains(res->body, "could not be read"));
        CHECK_FALSE(contains(res->body, "No device is quarantined"));
    }
    {
        ContainmentHarness h;
        h.list = std::vector<QuarantineRecord>{rec("a")};
        h.read_fail["a"] = 503;
        auto res = h.sink.Get("/fragments/hardware/quarantine");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(contains(res->body, "could not be checked against your permissions"));
        CHECK_FALSE(contains(res->body, "No device is quarantined"));
    }
}

TEST_CASE("fragment: quarantined panel — caps at 200 visible records and does not probe past the cap",
          "[quarantine][route]") {
    ContainmentHarness h;
    std::vector<QuarantineRecord> many;
    for (int i = 0; i < 205; ++i)
        many.push_back(rec("d" + std::to_string(i)));
    h.list = many;
    auto res = h.sink.Get("/fragments/hardware/quarantine");
    REQUIRE(res);
    CHECK(contains(res->body, "Showing the newest 200 records you can see; older records exist."));
    CHECK(h.probed.size() == 200);
}

TEST_CASE("fragment: containment — id validation comes before any gate", "[quarantine][route]") {
    ContainmentHarness h;
    auto missing = h.sink.Get("/fragments/hardware/ci/containment");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    auto ctrl = h.sink.Get("/fragments/hardware/ci/containment?id=a%0Ab");
    REQUIRE(ctrl);
    CHECK(ctrl->status == 400);
    auto longid = h.sink.Get("/fragments/hardware/ci/containment?id=" + std::string(300, 'x'));
    REQUIRE(longid);
    CHECK(longid->status == 400);
    CHECK(h.probed.empty());
}

// Kills: a 403 body (dropped by htmx) instead of a 200 note; an unauthenticated 401 swallowed.
TEST_CASE("fragment: containment — denied is a 200 data-denied note, degraded is a 200 note, 401 is 401",
          "[quarantine][route]") {
    ContainmentHarness h;
    h.read_fail["a"] = 403;
    auto denied = h.sink.Get("/fragments/hardware/ci/containment?id=a");
    REQUIRE(denied);
    CHECK(denied->status == 200);
    CHECK(contains(denied->body, "data-denied=\"1\""));

    h.read_fail["b"] = 503;
    auto degraded = h.sink.Get("/fragments/hardware/ci/containment?id=b");
    REQUIRE(degraded);
    CHECK(degraded->status == 200);
    CHECK(contains(degraded->body, "could not be read"));

    h.read_fail["c"] = 401;
    auto anon = h.sink.Get("/fragments/hardware/ci/containment?id=c");
    REQUIRE(anon);
    CHECK(anon->status == 401);

    ContainmentHarness s;
    s.status = std::unexpected(std::string("db_error: x"));
    auto store = s.sink.Get("/fragments/hardware/ci/containment?id=a");
    REQUIRE(store);
    CHECK(store->status == 200);
    CHECK(contains(store->body, "could not be read"));
    CHECK_FALSE(contains(store->body, "No active quarantine record"));
}

TEST_CASE("fragment: containment lens — record, execute probe and identity feed the view",
          "[quarantine][route]") {
    ContainmentHarness h;
    h.status = std::optional<QuarantineRecord>(rec("a", 10));
    InventoryDeviceRow row;
    row.agent_id = "a";
    row.hostname = "MAC-1";
    row.os = "darwin";
    row.online = false;
    h.identity = row;
    auto res = h.sink.Get("/fragments/hardware/ci/containment?id=a");
    REQUIRE(res);
    CHECK(contains(res->body, "data-act=\"release\""));
    CHECK(contains(res->body, "data-host=\"MAC-1\""));
    CHECK(contains(res->body, "data-online=\"0\""));
    CHECK(contains(res->body, "data-mac=\"1\""));
    CHECK(contains(res->body, "Waiting for device to connect"));

    h.execute_fail["a"] = 403;
    auto no_exec = h.sink.Get("/fragments/hardware/ci/containment?id=a");
    REQUIRE(no_exec);
    CHECK_FALSE(contains(no_exec->body, "data-act=\"release\""));
    CHECK(contains(no_exec->body, "needs the Security:Execute permission"));
}

// Kills: the banner taking the Execute probe / identity read (denied-audit noise per record view).
TEST_CASE("fragment: containment banner — one Security:Read probe, no Execute probe, no identity",
          "[quarantine][route]") {
    ContainmentHarness h;
    h.status = std::optional<QuarantineRecord>(rec("a"));
    auto res = h.sink.Get("/fragments/hardware/ci/containment?id=a&banner=1");
    REQUIRE(res);
    CHECK(contains(res->body, "This device is quarantined."));
    CHECK(h.probed == std::vector<std::string>{"Security:Read:a"});

    ContainmentHarness none;
    auto empty = none.sink.Get("/fragments/hardware/ci/containment?id=a&banner=1");
    REQUIRE(empty);
    CHECK(empty->body == "<div id=\"hw-quarantine-banner\"></div>");
}

// ───────────────────────── JS pins ────────────────────────────────────────────

TEST_CASE("yuzu-estate.js: no markup sinks, encoded ids, one delegated listener", "[quarantine][static-js]") {
    const std::string& js = yuzu::server::kYuzuEstateJs;
    CHECK(js.size() >= 2000);
    CHECK(js.find("innerHTML") == std::string::npos);
    CHECK(js.find("insertAdjacentHTML") == std::string::npos);
    CHECK(js.find("outerHTML =") == std::string::npos);
    CHECK(js.find("eval(") == std::string::npos);
    CHECK(js.find("new Function") == std::string::npos);
    CHECK(js.find("hx-on") == std::string::npos);
    CHECK(js.find("document.write") == std::string::npos);
    CHECK(contains(js, "encodeURIComponent"));
    CHECK(contains(js, "'/api/v1/quarantine/' + enc(agent)"));
    // exactly one addEventListener call (the delegated click listener)
    std::size_t n = 0;
    for (auto p = js.find("addEventListener("); p != std::string::npos; p = js.find("addEventListener(", p + 1))
        ++n;
    CHECK(n == 1);
    // no path interpolates a raw id
    CHECK_FALSE(contains(js, "/api/v1/quarantine/' + agent"));
    CHECK_FALSE(contains(js, "id=' + agent"));
}

// ───────────────────────── Stored data panel ──────────────────────────────────

namespace {

struct EstateHarness {
    DeviceEstateRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    int deny_status = 0; // 0 = allow
    std::vector<std::string> probed;
    std::optional<InventoryDeviceRow> identity;

    EstateHarness() {
        DeviceEstateRoutes::Deps d;
        d.scoped_perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                                  const std::string& op, const std::string& id) {
            probed.push_back(t + ":" + op + ":" + id);
            if (deny_status != 0) {
                res.status = deny_status;
                return false;
            }
            return true;
        };
        d.identity_fn = [this](const std::string&)
            -> std::expected<std::optional<InventoryDeviceRow>, PresenceReadError> { return identity; };
        routes.register_routes(sink, d);
    }
};

} // namespace

// Kills: dropping id_is_safe (control byte reaches the audit trail), a second probe.
TEST_CASE("fragment: stored data — id safety, one Decommission:Delete probe, allow",
          "[quarantine][route]") {
    EstateHarness h;
    auto bad = h.sink.Get("/fragments/hardware/ci/stored-data?id=a%0Ab");
    REQUIRE(bad);
    CHECK(bad->status == 400);
    CHECK(h.probed.empty());

    InventoryDeviceRow row;
    row.agent_id = "a";
    row.hostname = "HOST-A";
    h.identity = row;
    auto ok = h.sink.Get("/fragments/hardware/ci/stored-data?id=a");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.probed == std::vector<std::string>{"Decommission:Delete:a"});
    CHECK(contains(ok->body, "data-act=\"stored-data-remove\""));
    CHECK(contains(ok->body, "data-confirm=\"HOST-A\""));
    CHECK(contains(ok->body, "data-agent=\"a\""));
    CHECK(contains(ok->body, "Tags, custom properties, quarantine records and property schemas are "
                             "not removed."));
    CHECK(contains(ok->body, "does <b>not</b> unenrol"));
    CHECK(contains(ok->body, "nothing is erased"));
}

// Kills: swallowing a 403 as non-2xx (htmx drops it), treating a non-403 probe failure as Denied.
TEST_CASE("fragment: stored data — 403 is a 200 note, non-403 is 'could not be checked', 401 stays",
          "[quarantine][route]") {
    EstateHarness h;
    h.deny_status = 403;
    auto denied = h.sink.Get("/fragments/hardware/ci/stored-data?id=a");
    REQUIRE(denied);
    CHECK(denied->status == 200);
    CHECK(contains(denied->body, "Decommission:Delete"));
    CHECK_FALSE(contains(denied->body, "data-act=\"stored-data-remove\""));
    CHECK(contains(denied->body, "disabled"));

    h.deny_status = 500;
    auto degraded = h.sink.Get("/fragments/hardware/ci/stored-data?id=a");
    REQUIRE(degraded);
    CHECK(degraded->status == 200);
    CHECK(contains(degraded->body, "Permission could not be checked"));
    CHECK_FALSE(contains(degraded->body, "data-act=\"stored-data-remove\""));

    h.deny_status = 401;
    auto anon = h.sink.Get("/fragments/hardware/ci/stored-data?id=a");
    REQUIRE(anon);
    CHECK(anon->status == 401);
}

// Kills: no hostname -> empty confirmation value (a blank typed field would match).
TEST_CASE("fragment: stored data — agent id is the confirmation value when no hostname",
          "[quarantine][route]") {
    EstateHarness h;
    auto res = h.sink.Get("/fragments/hardware/ci/stored-data?id=agent-9");
    REQUIRE(res);
    CHECK(contains(res->body, "data-confirm=\"agent-9\""));
}

TEST_CASE("stored data: placeholder is click-to-load and encodes the id", "[quarantine]") {
    const std::string p = stored_data_placeholder("a b");
    CHECK(contains(p, "hx-trigger=\"click\""));
    CHECK(contains(p, "id=a%20b"));
}

TEST_CASE("yuzu-estate.js: stored data removal pins", "[quarantine][static-js]") {
    const std::string& js = yuzu::server::kYuzuEstateJs;
    CHECK(contains(js, "'/api/v1/sle/agents/' + enc(agent)"));
    CHECK_FALSE(contains(js, "/api/v1/sle/agents/' + agent"));
    CHECK(contains(js, "(v.typed || '') === expected"));       // exact, case-sensitive
    CHECK(contains(js, "location.assign('/hardware')"));
    CHECK(contains(js, "err.details.stores"));
    CHECK(contains(js, "res.auditFailed"));
    CHECK(contains(js, "Re-issue to retry the failures"));
    CHECK(contains(js, "danger: true"));
}
