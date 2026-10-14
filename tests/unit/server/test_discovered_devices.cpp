/**
 * test_discovered_devices.cpp — the discovered-devices read twin (Estate E-2):
 * GET /api/v1/network/discovered-devices and GET /fragments/network/discovered
 * over the shared builders in discovered_devices_model.hpp.
 *
 * Pure: the read seam (DiscoveredDevicesReadFn) is injected, so nothing here
 * touches Postgres. The MCP twin's cases live in test_mcp_server.cpp and the
 * store's SQL in test_discovery_store.cpp ([pg]).
 */

#include "discovered_devices_model.hpp"
#include "discovered_devices_reader.hpp"
#include "network_routes.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

DiscoveredDevice device(const std::string& ip, const std::string& host = "host") {
    DiscoveredDevice d;
    d.id = 1;
    d.ip_address = ip;
    d.mac_address = "aa:bb:cc:dd:ee:ff";
    d.hostname = host;
    d.subnet = "10.0.0.0/24";
    d.discovered_by = "agent-a";
    d.discovered_at = 1000;
    d.last_seen = 1700000000;
    d.managed = true; // the flag is never surfaced
    d.agent_id = "stale";
    return d;
}

DiscoveredDevicesPage one_page() {
    DiscoveredDevicesPage p;
    p.devices.push_back(device("10.0.0.5", "printer-1"));
    p.summary = {.total = 1, .subnets = 1};
    return p;
}

struct Harness {
    std::vector<std::string> audit;
    bool audit_ok{true};
    bool perm_ok{true};
    bool signed_in{true};
    std::string token_scope;
    int reads{0};
    std::string seen_subnet;
    int seen_limit{-1};
    std::expected<DiscoveredDevicesPage, std::string> result{one_page()};
    yuzu::server::test::TestRouteSink sink;
    NetworkRoutes routes;

    Harness() {
        routes.register_routes(
            sink,
            [this](const httplib::Request&, httplib::Response& res) {
                if (!signed_in) {
                    res.status = 401;
                    return std::optional<auth::Session>{};
                }
                auth::Session s;
                s.token_scope_service = token_scope;
                return std::optional<auth::Session>(s);
            },
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&) {
                if (!perm_ok)
                    res.status = 403;
                return perm_ok;
            },
            [this](const httplib::Request&, const std::string& action, const std::string& result,
                   const std::string&, const std::string&, const std::string&) {
                audit.push_back(action + ":" + result);
                return audit_ok;
            },
            nullptr,
            [this](const std::string& subnet, int limit) {
                ++reads;
                seen_subnet = subnet;
                seen_limit = limit;
                return result;
            });
    }
};

} // namespace

// ── pure model ───────────────────────────────────────────────────────────────

TEST_CASE("discovered devices: limit parsing defaults, clamps and refuses",
          "[discovery][twin][model]") {
    CHECK(parse_discovered_limit("") == kDiscoveredDevicesMaxLimit);
    CHECK(parse_discovered_limit("7") == 7);
    CHECK(parse_discovered_limit("500") == 500);
    CHECK(parse_discovered_limit("501") == 500);
    CHECK(parse_discovered_limit("99999999999") == 500);
    for (const char* bad : {"0", "-1", "abc", "5x", " 5", "1.5"})
        CHECK_FALSE(parse_discovered_limit(bad).has_value());
    CHECK_FALSE(clamp_discovered_limit(0).has_value());
    CHECK(clamp_discovered_limit(9999999999LL) == 500);
}

TEST_CASE("discovered devices: the row shape never carries the managed flag",
          "[discovery][twin][model]") {
    const auto row = discovered_device_row_json(device("10.0.0.5", "printer-1"));
    CHECK(row["ip_address"] == "10.0.0.5");
    CHECK(row["hostname"] == "printer-1");
    CHECK(row["discovered_by"] == "agent-a");
    CHECK(row["last_seen"] == 1700000000);
    CHECK_FALSE(row.contains("managed"));
    CHECK_FALSE(row.contains("agent_id"));

    DiscoveredDevicesPage page = one_page();
    page.truncated = true;
    page.summary = {.total = 501, .subnets = 3};
    const auto j = discovered_devices_json(page);
    CHECK(j["data"].size() == 1);
    CHECK(j["summary"]["total"] == 501);
    CHECK(j["summary"]["subnets"] == 3);
    CHECK(j["truncated"] == true);
}

TEST_CASE("discovered devices: the fragment escapes every free-text column",
          "[discovery][twin][model][security]") {
    DiscoveredDevicesPage page = one_page();
    auto& d = page.devices[0];
    d.hostname = "<script>alert(1)</script>";
    d.mac_address = "\"><img src=x>";
    d.ip_address = "1.2.3.4'<b>";
    d.discovered_by = "<i>agent</i>";
    d.subnet = "<u>net</u>";
    const auto html = render_discovered_devices_fragment(page);
    for (const char* raw : {"<script>", "<img", "<b>", "<i>", "<u>"})
        CHECK(html.find(raw) == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("discovered devices: fragment states are distinct and never draw managed",
          "[discovery][twin][model]") {
    SECTION("empty store reads as empty, not as an error") {
        const auto html = render_discovered_devices_fragment({});
        CHECK(html.find("No hosts discovered yet") != std::string::npos);
        CHECK(html.find("failbox") == std::string::npos);
        CHECK(html.find("<table") == std::string::npos);
    }
    SECTION("rows plus counts, with a truncation note") {
        DiscoveredDevicesPage page = one_page();
        page.truncated = true;
        page.summary = {.total = 600, .subnets = 4};
        const auto html = render_discovered_devices_fragment(page);
        CHECK(html.find("600 hosts across 4 subnets") != std::string::npos);
        CHECK(html.find("showing the 1 most recently seen") != std::string::npos);
        CHECK(html.find("Managed") == std::string::npos);
        CHECK(html.find("managed") == std::string::npos);
    }
    SECTION("an unreadable store is a failbox") {
        CHECK(render_discovered_devices_unavailable().find("failbox") != std::string::npos);
    }
}

TEST_CASE("discovered devices: a missing store reads as an error, not as no rows",
          "[discovery][twin][model]") {
    auto read = make_discovered_devices_reader(nullptr);
    REQUIRE(read);
    CHECK_FALSE(read("", 10).has_value());
}

// ── REST route ───────────────────────────────────────────────────────────────

TEST_CASE("discovered devices REST: success body, limit default and audited row",
          "[discovery][twin][routes]") {
    Harness h;
    auto res = h.sink.Get("/api/v1/network/discovered-devices?subnet=10.0.0.0/24");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"].size() == 1);
    CHECK(body["data"][0]["hostname"] == "printer-1");
    CHECK(body["summary"]["total"] == 1);
    CHECK(body["truncated"] == false);
    CHECK(body["meta"]["api_version"] == "v1");
    CHECK(h.seen_subnet == "10.0.0.0/24");
    CHECK(h.seen_limit == 500);
    REQUIRE(h.audit.size() == 1);
    CHECK(h.audit[0] == "network.discovered.view:success");
}

TEST_CASE("discovered devices REST: limit is clamped at the cap and 0 or junk is a 400",
          "[discovery][twin][routes]") {
    Harness h;
    auto big = h.sink.Get("/api/v1/network/discovered-devices?limit=9000");
    REQUIRE(big);
    CHECK(big->status == 200);
    CHECK(h.seen_limit == 500);

    h.reads = 0;
    for (const char* q : {"?limit=0", "?limit=abc", "?limit=-4"}) {
        auto bad = h.sink.Get(std::string("/api/v1/network/discovered-devices") + q);
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    auto long_subnet = h.sink.Get("/api/v1/network/discovered-devices?subnet=" +
                                  std::string(kDiscoveredSubnetMaxLen + 1, '1'));
    REQUIRE(long_subnet);
    CHECK(long_subnet->status == 400);
    CHECK(h.reads == 0); // validation precedes the read
}

TEST_CASE("discovered devices REST: gates run before the read",
          "[discovery][twin][routes][security]") {
    SECTION("unauthenticated") {
        Harness h;
        h.signed_in = false;
        auto res = h.sink.Get("/api/v1/network/discovered-devices");
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(h.reads == 0);
    }
    SECTION("service-scoped token: 403, audited denial, no read, no row leaked") {
        Harness h;
        h.token_scope = "printers";
        auto res = h.sink.Get("/api/v1/network/discovered-devices");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("printer-1") == std::string::npos);
        CHECK(h.reads == 0);
        REQUIRE(h.audit.size() == 1);
        CHECK(h.audit[0] == "network.discovered.view:denied");
    }
    SECTION("RBAC refusal") {
        Harness h;
        h.perm_ok = false;
        auto res = h.sink.Get("/api/v1/network/discovered-devices");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.reads == 0);
        CHECK(h.audit.empty());
    }
}

TEST_CASE("discovered devices REST: a store fault is a 503, never an empty list",
          "[discovery][twin][routes]") {
    Harness h;
    h.result = std::unexpected("discovery read degraded");
    auto res = h.sink.Get("/api/v1/network/discovered-devices");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"data\":[") == std::string::npos);
    CHECK(h.audit.empty()); // a failed read leaves no "success" row
}

TEST_CASE("discovered devices REST: fails closed when the audit row cannot persist",
          "[discovery][twin][routes][security]") {
    Harness h;
    h.audit_ok = false;
    auto res = h.sink.Get("/api/v1/network/discovered-devices");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("printer-1") == std::string::npos);
}

TEST_CASE("discovered devices REST: no reader wired is a 503",
          "[discovery][twin][routes]") {
    yuzu::server::test::TestRouteSink sink;
    NetworkRoutes routes;
    routes.register_routes(
        sink,
        [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        },
        [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) {
            return true;
        },
        [](const httplib::Request&, const std::string&, const std::string&, const std::string&,
           const std::string&, const std::string&) { return true; });
    for (const char* path : {"/api/v1/network/discovered-devices", "/fragments/network/discovered"}) {
        auto res = sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

// ── dashboard fragment ───────────────────────────────────────────────────────

TEST_CASE("discovered devices fragment: renders rows, set-and-proceed audit",
          "[discovery][twin][routes]") {
    Harness h;
    h.audit_ok = false; // a hiccup must not blank the operator's view
    auto res = h.sink.Get("/fragments/network/discovered");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("printer-1") != std::string::npos);
    CHECK(res->body.find("10.0.0.5") != std::string::npos);
    REQUIRE(h.audit.size() == 1);
    CHECK(h.audit[0] == "network.discovered.view:success");
}

TEST_CASE("discovered devices fragment: store fault shows a failbox, not an empty table",
          "[discovery][twin][routes]") {
    Harness h;
    h.result = std::unexpected("discovery read degraded");
    auto res = h.sink.Get("/fragments/network/discovered");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("failbox") != std::string::npos);
    CHECK(res->body.find("<table") == std::string::npos);
}

TEST_CASE("discovered devices fragment: shares the REST gates",
          "[discovery][twin][routes][security]") {
    Harness h;
    h.token_scope = "printers";
    auto denied = h.sink.Get("/fragments/network/discovered");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(h.reads == 0);

    Harness g;
    g.perm_ok = false;
    auto forbidden = g.sink.Get("/fragments/network/discovered");
    REQUIRE(forbidden);
    CHECK(forbidden->status == 403);
    CHECK(g.reads == 0);

    Harness i;
    auto bad = i.sink.Get("/fragments/network/discovered?limit=0");
    REQUIRE(bad);
    CHECK(bad->status == 400);
    CHECK(i.reads == 0);
}
