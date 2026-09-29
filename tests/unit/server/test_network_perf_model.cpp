/**
 * test_network_perf_model.cpp — /network fleet read model (N1 slice 1).
 *
 *  - network_perf_rules: forged-value posture (reject inf/nan/negative/garbage,
 *    clamp retransmit %, reject absurd-but-finite RTT/throughput); net_degraded
 *    bool parse; the MEASURED perf-pressure co-occurrence threshold.
 *  - fleet_now: absent-not-zero; reporting vs rtt_reporting denominators (RTT
 *    carries its own smaller denominator by design); co-occurrence counts.
 *  - device_list: cross-platform not-reporting complement, co-occurrence band
 *    filter, worst-first metric sort, cohort filter, limit cap.
 *
 * The model COUNTS co-occurrence; it never asserts a cause (no verdict).
 */
#include "network_perf_model.hpp"
#include "network_perf_rules.hpp"
#include "network_routes.hpp"
#include "rest_api_v1.hpp"
#include "test_network_api_double.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
namespace rules = yuzu::server::detail;

// TAG-KEY PIN: these server-side constants MUST equal the literal strings the
// agent emits in agents/core/src/agent.cpp (the yuzu.net_* heartbeat block).
// The agent can't include this header, so the literals are duplicated — a drift
// here means silent zero-reporting (it already cost a live-UAT debug cycle). If
// you change a constant, change the agent emit site too.
static_assert(std::string_view(rules::kNetTagRttP50Ms) == "yuzu.net_rtt_p50_ms");
static_assert(std::string_view(rules::kNetTagRetransPct) == "yuzu.net_retrans_pct");
static_assert(std::string_view(rules::kNetTagThroughputBps) == "yuzu.net_throughput_bps");
// net_degraded is RETIRED — agents no longer emit this tag (measurement-first;
// the gauge is dormant). The server still parses it defensively for mixed-version
// rolling upgrades, so the constant + this pin stay; it is NOT a live-emit guarantee.
static_assert(std::string_view(rules::kNetTagDegraded) == "yuzu.net_degraded");

namespace {

NetPerfDevice dev(const std::string& id, std::optional<double> rtt, std::optional<double> retx,
                  std::optional<double> tput, bool degraded = false,
                  const std::string& platform = "linux", const std::string& cohort = "") {
    NetPerfDevice d;
    d.agent_id = id;
    d.platform = platform;
    d.rtt_ms = rtt;
    d.retrans_pct = retx;
    d.throughput_bps = tput;
    d.net_degraded = degraded;
    d.cohort = cohort;
    return d;
}

/// A degraded device with a known perf/app co-occurrence shape (always reports
/// a metric so it counts as reporting).
NetPerfDevice degraded(const std::string& id, std::optional<double> cpu, bool app) {
    NetPerfDevice d;
    d.agent_id = id;
    d.platform = "linux";
    d.rtt_ms = 300.0;
    d.net_degraded = true;
    d.cpu_pct = cpu;
    d.app_unstable = app;
    return d;
}

/// Test-only wrapper preserving the pre-ADR-0031-WS-A4 call shape: resolve
/// the device list + available_keys/cohort_key from a raw NetPerfSnapshot,
/// then call the seam-split renderer (rows + available_keys + cohort_key are
/// now separate, already-resolved inputs — see network_routes.hpp).
std::string render_devices(const NetPerfSnapshot& snap, NetPerfMetric metric, bool not_reporting,
                           NetCoocFilter cooc, const std::optional<std::string>& cohort_filter,
                           int limit) {
    const auto rows = net_perf_device_list(snap, metric, not_reporting, cooc, cohort_filter, limit);
    return render_network_devices_fragment(rows, snap.available_keys, snap.cohort_key, metric,
                                           not_reporting, cooc, cohort_filter, limit);
}

} // namespace

// ── network_perf_rules ───────────────────────────────────────────────────────

TEST_CASE("network tag parsing: forged-value posture", "[network][rules]") {
    // Normal values pass.
    CHECK(rules::parse_net_rtt_ms("38.5") == 38.5);
    CHECK(rules::parse_net_retrans_pct("0.4") == 0.4);
    CHECK(rules::parse_net_throughput_bps("3100000") == 3100000.0);
    // Percentage lie clamps to 100 (not an outlier — a lie).
    CHECK(rules::parse_net_retrans_pct("250") == 100.0);
    // Absurd-but-finite rejected above the sanity ceiling.
    CHECK(rules::parse_net_rtt_ms("1e9") == std::nullopt);
    CHECK(rules::parse_net_throughput_bps("1e15") == std::nullopt);
    // Non-finite / negative / garbage / empty → nullopt (never 0).
    CHECK(rules::parse_net_rtt_ms("inf") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("nan") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("-5") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("38xyz") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("") == std::nullopt);
}

TEST_CASE("net_degraded bool parse", "[network][rules]") {
    CHECK(rules::parse_net_degraded("1") == true);
    CHECK(rules::parse_net_degraded("true") == true);
    CHECK(rules::parse_net_degraded("0") == false);
    CHECK(rules::parse_net_degraded("false") == false);
    CHECK(rules::parse_net_degraded("yes") == std::nullopt); // unknown, not false
}

TEST_CASE("perf-pressure co-occurrence threshold", "[network][rules]") {
    using rules::net_device_under_pressure;
    CHECK(net_device_under_pressure(90.0, std::nullopt, std::nullopt));  // cpu arm
    CHECK(net_device_under_pressure(std::nullopt, 95.0, std::nullopt));  // commit arm
    CHECK(net_device_under_pressure(std::nullopt, std::nullopt, 30.0));  // disk arm
    CHECK_FALSE(net_device_under_pressure(10.0, 40.0, 1.0));
    CHECK_FALSE(net_device_under_pressure(std::nullopt, std::nullopt, std::nullopt)); // absent != strain
}

// ── fleet_now ────────────────────────────────────────────────────────────────

TEST_CASE("fleet_now: absent-not-zero + honest denominators", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("a", 40.0, 0.5, 3.0e6));
    snap.devices.push_back(dev("b", 80.0, 1.0, 5.0e6));
    snap.devices.push_back(dev("c", std::nullopt, 2.0, std::nullopt)); // windows-coarse: retrans only
    snap.devices.push_back(dev("d", std::nullopt, std::nullopt, std::nullopt)); // silent

    const auto f = net_perf_fleet_now(snap);
    CHECK(f.online == 4);
    CHECK(f.reporting == 3);     // a, b, c
    CHECK(f.rtt_reporting == 2); // a, b only — the honest RTT denominator
    REQUIRE(f.rtt.has_value());
    CHECK(f.rtt->n == 2);
    CHECK(f.rtt->max == 80.0);
    REQUIRE(f.retrans.has_value());
    CHECK(f.retrans->n == 3);
}

TEST_CASE("fleet_now: empty population → all stats absent", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("d", std::nullopt, std::nullopt, std::nullopt));
    const auto f = net_perf_fleet_now(snap);
    CHECK(f.online == 1);
    CHECK(f.reporting == 0);
    CHECK_FALSE(f.rtt.has_value());
    CHECK_FALSE(f.retrans.has_value());
    CHECK_FALSE(f.throughput.has_value());
}

TEST_CASE("co-occurrence: counts over degraded devices, overlap allowed", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(degraded("net-only", 10.0, false)); // degraded, no pressure, no app
    snap.devices.push_back(degraded("dev", 95.0, false));      // degraded + pressure
    snap.devices.push_back(degraded("app", 10.0, true));       // degraded + app
    snap.devices.push_back(degraded("both", 95.0, true));      // degraded + pressure + app (overlap)
    snap.devices.push_back(degraded("healthy", 95.0, true));   // ... but flip net_degraded off:
    snap.devices.back().net_degraded = false;                  //   NOT degraded → excluded entirely

    const auto f = net_perf_fleet_now(snap);
    CHECK(f.cooc.degraded == 4);
    CHECK(f.cooc.also_device == 2);  // dev, both
    CHECK(f.cooc.also_app == 2);     // app, both
    CHECK(f.cooc.network_only == 1); // net-only
}

// ── device_list ──────────────────────────────────────────────────────────────

TEST_CASE("device_list: not-reporting complement is cross-platform", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("rep", 40.0, std::nullopt, std::nullopt, false, "windows"));
    snap.devices.push_back(dev("silent-win", std::nullopt, std::nullopt, std::nullopt, false, "windows"));
    snap.devices.push_back(dev("silent-lnx", std::nullopt, std::nullopt, std::nullopt, false, "linux"));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, /*not_reporting=*/true,
                                           NetCoocFilter::kNone, std::nullopt, 50);
    REQUIRE(rows.size() == 2); // both silent, regardless of OS (unlike Windows-only perf)
    CHECK(rows[0].agent_id == "silent-lnx"); // sorted by agent_id
    CHECK(rows[1].agent_id == "silent-win");
}

TEST_CASE("device_list: worst-first by metric, percentile ranked", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("low", 40.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("high", 600.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("mid", 200.0, std::nullopt, std::nullopt));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false, NetCoocFilter::kNone,
                                           std::nullopt, 50);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].agent_id == "high");
    CHECK(rows[1].agent_id == "mid");
    CHECK(rows[2].agent_id == "low");
    CHECK(rows[0].fleet_pctile >= rows[2].fleet_pctile);
}

TEST_CASE("device_list: co-occurrence band filter flags the facts", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(degraded("net-only", 10.0, false));
    snap.devices.push_back(degraded("dev", 95.0, false));
    snap.devices.push_back(degraded("healthy", 10.0, false));
    snap.devices.back().net_degraded = false;

    const auto dev_rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false,
                                               NetCoocFilter::kAlsoDevice, std::nullopt, 50);
    REQUIRE(dev_rows.size() == 1);
    CHECK(dev_rows[0].agent_id == "dev");
    CHECK(dev_rows[0].under_pressure);

    const auto only = net_perf_device_list(snap, NetPerfMetric::kRtt, false,
                                           NetCoocFilter::kNetworkOnly, std::nullopt, 50);
    REQUIRE(only.size() == 1);
    CHECK(only[0].agent_id == "net-only");
    CHECK_FALSE(only[0].under_pressure);
}

TEST_CASE("device_list: cohort filter + limit cap", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("a1", 40.0, std::nullopt, std::nullopt, false, "linux", "site-a"));
    snap.devices.push_back(dev("a2", 50.0, std::nullopt, std::nullopt, false, "linux", "site-a"));
    snap.devices.push_back(dev("b1", 60.0, std::nullopt, std::nullopt, false, "linux", "site-b"));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false, NetCoocFilter::kNone,
                                           std::optional<std::string>("site-a"), 1);
    REQUIRE(rows.size() == 1);       // limit cap honoured
    CHECK(rows[0].cohort == "site-a");
    CHECK(rows[0].agent_id == "a2"); // worst-first within cohort (50 > 40 ms)
}

TEST_CASE("metric token round-trips", "[network][model]") {
    CHECK(net_perf_metric_from_token("retrans") == NetPerfMetric::kRetrans);
    CHECK(net_perf_metric_from_token("throughput") == NetPerfMetric::kThroughput);
    CHECK(net_perf_metric_from_token("rtt") == NetPerfMetric::kRtt);
    CHECK(net_perf_metric_from_token("garbage") == NetPerfMetric::kRtt); // default
    CHECK(std::string(net_perf_metric_token(NetPerfMetric::kRetrans)) == "retrans");
}

// ── renderers ────────────────────────────────────────────────────────────────

TEST_CASE("overview render: cards, co-occurrence, honesty", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("lnx-1", 40.0, 0.4, 3.0e6));
    snap.devices.push_back(dev("lnx-2", 600.0, 9.0, 2.0e5));
    snap.devices.push_back(degraded("deg-dev", 95.0, false)); // degraded + device pressure
    snap.devices.push_back(degraded("deg-app", 10.0, true));  // degraded + app instability

    const auto html = render_network_overview_fragment(net_perf_fleet_now(snap));
    CHECK(html.find("Network quality") != std::string::npos);
    // IA: Network is a DEX sub-view — the overview renders the shared DEX sub-nav
    // (a sibling DEX tab link is present) with the Network tab marked active,
    // rather than a standalone network sub-nav.
    CHECK(html.find("/fragments/dex/catalogue") != std::string::npos); // DEX sub-nav rendered
    CHECK(html.find("class=\"on\" hx-get=\"/fragments/network/overview") !=
          std::string::npos); // Network tab is the active one
    CHECK(html.find("Round-trip time") != std::string::npos);
    CHECK(html.find("TCP_INFO") != std::string::npos);                // Linux/Windows honesty note
    // Measurement-first (4b.3): the retransmit fact is an INTERVAL rate, and the
    // degraded classification + the co-occurrence headline it gates are a later
    // slice (a hard threshold needs real-fleet baseline data) — the overview must
    // say so honestly, never imply "0 degraded == healthy".
    CHECK(html.find("interval rate") != std::string::npos);           // not the lifetime ratio
    CHECK(html.find("co-occurrence") != std::string::npos);           // section still named...
    CHECK(html.find("later slice") != std::string::npos);             // ...but explicitly deferred
    CHECK(html.find("Measurement-first") != std::string::npos);
    CHECK(html.find("baseline") != std::string::npos);                // threshold needs a real-fleet baseline
    CHECK(html.find("not a verdict") != std::string::npos);           // honest evidence, never a verdict
}

TEST_CASE("overview render: empty population is honest", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("silent", std::nullopt, std::nullopt, std::nullopt));
    const auto html = render_network_overview_fragment(net_perf_fleet_now(snap));
    CHECK(html.find("No network telemetry yet") != std::string::npos);
}

TEST_CASE("devices render: worst-first + co-occurrence flags inline", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("lnx-low", 40.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("lnx-high", 600.0, std::nullopt, std::nullopt));
    snap.devices.push_back(degraded("deg-dev", 95.0, false));

    const auto html = render_devices(snap, NetPerfMetric::kRtt, false,
                                                      NetCoocFilter::kNone, std::nullopt, 50);
    CHECK(html.find("lnx-high") != std::string::npos);
    CHECK(html.find("Worst devices by RTT") != std::string::npos);
    CHECK(html.find("device &#9679;") != std::string::npos); // deg-dev pressure flag inline
    CHECK(html.find("&mdash;") != std::string::npos);        // absent metric cell, never 0
}

// ── routes ───────────────────────────────────────────────────────────────────

TEST_CASE("network routes: perm gating + provider degradation", "[network][routes][rbac]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    std::vector<std::string> auditLog;
    auto okAudit = [&](const httplib::Request&, const std::string& action,
                       const std::string& result, const std::string&, const std::string&,
                       const std::string&) {
        auditLog.push_back(action + ":" + result);
        return true;
    };
    NetworkRoutes::NetworkApiPtr perf =
        std::make_shared<yuzu::server::test::FnNetworkApi>([](const std::string&) {
            NetPerfSnapshot snap;
            snap.devices.push_back(degraded("deg-dev", 95.0, false)); // degraded + pressure
            snap.devices.push_back(degraded("deg-app", 10.0, true));  // degraded + app
            return snap;
        });

    SECTION("permitted: overview + devices render through the provider") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okAudit, perf);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("Network quality") != std::string::npos);

        // The device co-occurrence band shows only degraded+pressure devices.
        auto drill = sink.Get("/fragments/network/devices?cooc=device");
        REQUIRE(drill);
        CHECK(drill->status == 200);
        CHECK(drill->body.find("deg-dev") != std::string::npos);
        CHECK(drill->body.find("deg-app") == std::string::npos);
    }

    SECTION("denied without GuaranteedState:Read") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, okAudit, perf);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 403);
    }

    SECTION("no provider wired → honest unavailable placeholder") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okAudit);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("unavailable") != std::string::npos);
    }

    SECTION("page shell loads the overview fragment") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okAudit, perf);
        auto page = sink.Get("/network");
        REQUIRE(page);
        CHECK(page->status == 200);
        CHECK(page->body.find("/fragments/network/overview") != std::string::npos);
        // IA: Network is a DEX sub-view — the /network page shell marks DEX active
        // in the global nav, and there is NO standalone Network top-nav link.
        // Assert on the href (structurally stable) so a reintroduced top-nav link
        // with any class/attribute spelling still trips this. The Network tab in
        // the DEX sub-nav uses hx-get (not href="/network"), so this stays clean.
        CHECK(page->body.find("class=\"nav-link active\">DEX</a>") != std::string::npos);
        CHECK(page->body.find("href=\"/network\"") == std::string::npos);
    }
}

// ── SEC-3 sibling-gap coverage: /fragments/network/devices previously had NO
// service-token confinement and NO audit capability at all — this fragment
// names every reporting agent's identity fleet-wide. Gate 8 governance review
// found this as a 4th instance of the same vulnerability class already fixed
// on GET /api/v1/network/devices and 5 other surfaces on this branch. ────────

TEST_CASE("network devices fragment: service-scoped token denied, denial audited",
          "[network][routes][rbac][security]") {
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> auditLog;
    auto recordingAudit = [&](const httplib::Request&, const std::string& action,
                              const std::string& result, const std::string&, const std::string&,
                              const std::string&) {
        auditLog.push_back(action + ":" + result);
        return true;
    };
    NetworkRoutes::NetworkApiPtr perf =
        std::make_shared<yuzu::server::test::FnNetworkApi>([](const std::string&) {
            NetPerfSnapshot snap;
            snap.devices.push_back(degraded("deg-dev", 95.0, false));
            return snap;
        });

    NetworkRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, recordingAudit, perf);

    // The overview fragment (aggregate, no agent_id) is UNAFFECTED — only the
    // devices drill (identity-linked) gets the new deny.
    auto ov = sink.Get("/fragments/network/overview");
    REQUIRE(ov);
    CHECK(ov->status == 200);

    auto drill = sink.Get("/fragments/network/devices");
    REQUIRE(drill);
    CHECK(drill->status == 403);
    CHECK(drill->body.find("deg-dev") == std::string::npos); // no identity leaked
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto body = nlohmann::json::parse(drill->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(drill->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    REQUIRE(auditLog.size() == 1);
    CHECK(auditLog[0] == "network.device.view:denied");
}

TEST_CASE("network devices fragment: ordinary session reaches the route, audited success",
          "[network][routes][security]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> auditLog;
    auto recordingAudit = [&](const httplib::Request&, const std::string& action,
                              const std::string& result, const std::string&, const std::string&,
                              const std::string&) {
        auditLog.push_back(action + ":" + result);
        return true;
    };
    NetworkRoutes::NetworkApiPtr perf =
        std::make_shared<yuzu::server::test::FnNetworkApi>([](const std::string&) {
            NetPerfSnapshot snap;
            snap.devices.push_back(degraded("deg-dev", 95.0, false));
            return snap;
        });

    NetworkRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, recordingAudit, perf);

    auto drill = sink.Get("/fragments/network/devices");
    REQUIRE(drill);
    CHECK(drill->status == 200);
    CHECK(drill->body.find("deg-dev") != std::string::npos);
    REQUIRE(auditLog.size() == 1);
    CHECK(auditLog[0] == "network.device.view:success");
}

TEST_CASE("devices render: hostile agent_id is HTML-escaped", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("<b>x</b>&\"", 600.0, std::nullopt, std::nullopt));
    const auto html = render_devices(snap, NetPerfMetric::kRtt, false,
                                                      NetCoocFilter::kNone, std::nullopt, 50);
    CHECK(html.find("<b>x</b>") == std::string::npos); // raw markup never emitted
    CHECK(html.find("&lt;b&gt;") != std::string::npos); // escaped form present
}

TEST_CASE("devices render: cohort picker + drillable cohort cell (available_keys branch)",
          "[network][ui]") {
    NetPerfSnapshot snap;
    snap.available_keys = {"site", "region"}; // non-empty → the picker branch renders
    snap.cohort_key = "site";                 // the active key
    snap.devices.push_back(dev("d1", 40.0, std::nullopt, std::nullopt, false, "linux", "site-b"));
    const auto html = render_devices(snap, NetPerfMetric::kRtt, false,
                                                      NetCoocFilter::kNone, std::nullopt, 50);
    // Picker present (htmx core attrs only — no hx-on), active key selected, both keys offered.
    CHECK(html.find("<select name=\"key\"") != std::string::npos);
    CHECK(html.find("hx-on") == std::string::npos); // CSP: never compiles a handler
    CHECK(html.find("value=\"site\" selected") != std::string::npos);
    CHECK(html.find(">region</option>") != std::string::npos);
    // Cohort cell is a drill carrying cohort_value (NOT the muted no-key "—" form).
    CHECK(html.find("cohort_value=site-b") != std::string::npos);

    SECTION("requested key absent from available_keys → honest fallback option") {
        NetPerfSnapshot s2;
        s2.available_keys = {"region"}; // "site" is NOT among them
        s2.cohort_key = "site";
        s2.devices.push_back(dev("d2", 40.0, std::nullopt, std::nullopt));
        const auto h2 = render_devices(s2, NetPerfMetric::kRtt, false,
                                                        NetCoocFilter::kNone, std::nullopt, 50);
        CHECK(h2.find("no devices tagged") != std::string::npos); // honest fallback option shown
    }

    SECTION("no cohort key chosen → cohort cell is the muted '—', not a drill") {
        NetPerfSnapshot s3;
        s3.devices.push_back(dev("d3", 40.0, std::nullopt, std::nullopt)); // cohort_key empty
        const auto h3 = render_devices(s3, NetPerfMetric::kRtt, false,
                                                        NetCoocFilter::kNone, std::nullopt, 50);
        CHECK(h3.find("cohort_value=") == std::string::npos); // no drill without a key
    }
}

TEST_CASE("device_list: kAlsoApp band filters to app-co-occurring degraded", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(degraded("appdev", 10.0, true));  // degraded + app, no pressure
    snap.devices.push_back(degraded("devdev", 95.0, false)); // degraded + pressure, no app
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false,
                                           NetCoocFilter::kAlsoApp, std::nullopt, 50);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].agent_id == "appdev");
    CHECK(rows[0].app_unstable);
}

// ── REST surface (/api/v1/network/*) ─────────────────────────────────────────

namespace {

/// Registers RestApiV1 with every dep nulled except the network-perf provider —
/// the /network endpoints depend on nothing else. net_perf_fn is the LAST
/// register_routes param (just after dex_perf_fn), so dex is passed {} here.
struct RestNetHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    bool grant_perms{true};

    explicit RestNetHarness(NetPerfFn perf) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            return auth::Session{};
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };
        // Wrap the plain NetPerfSnapshot(cohort_key) function this file's tests
        // already build in the NetworkApi seam (ADR-0031 WS-A4) — an unset
        // `perf` stays null (the "no provider wired" 503 branch).
        std::shared_ptr<const yuzu::server::NetworkApi> network_api;
        if (perf)
            network_api = std::make_shared<yuzu::server::test::FnNetworkApi>(std::move(perf));
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, {}, {},
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, {},
                            nullptr, nullptr, {}, {}, {}, {}, std::move(network_api));
    }
};

/// Two cohorts, distinct descending RTT so worst-first is deterministic.
NetPerfSnapshot net_two(int n_lo, int n_hi) {
    NetPerfSnapshot snap;
    for (int i = 0; i < n_lo; ++i)
        snap.devices.push_back(
            dev("lo-" + std::to_string(i), 20.0 + i, 0.5, 5.0e6, false, "linux", "site-a"));
    for (int i = 0; i < n_hi; ++i)
        snap.devices.push_back(
            dev("hi-" + std::to_string(i), 500.0 - i, 8.0, 1.0e5, false, "linux", "site-b"));
    return snap;
}

} // namespace

TEST_CASE("REST /network/fleet: stats + denominators + co-occurrence, absent is null",
          "[network][rest]") {
    NetPerfFn perf = [](const std::string&) {
        NetPerfSnapshot snap;
        snap.devices.push_back(dev("w1", 10.0, std::nullopt, std::nullopt));
        snap.devices.push_back(dev("w2", 30.0, std::nullopt, std::nullopt));
        snap.devices.push_back(dev("w3", std::nullopt, std::nullopt, std::nullopt));
        return snap;
    };
    RestNetHarness h(perf);
    auto res = h.sink.Get("/api/v1/network/fleet");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["rtt_ms"]["n"] == 2);
    CHECK(j["data"]["rtt_ms"]["avg"] == 20.0);
    CHECK(j["data"]["rtt_ms"]["max"] == 30.0);
    CHECK(j["data"]["retrans_pct"].is_null()); // nobody reported — null, never 0
    CHECK(j["data"]["reporting"] == 2);
    CHECK(j["data"]["rtt_reporting"] == 2); // the honest RTT denominator
    CHECK(j["data"]["online"] == 3);
    REQUIRE(j["data"].contains("cooccurrence"));
    CHECK(j["data"]["cooccurrence"]["degraded"] == 0);
}

TEST_CASE("REST /network/devices: sort, filters, validation", "[network][rest]") {
    RestNetHarness h([](const std::string&) { return net_two(3, 3); });

    auto res = h.sink.Get("/api/v1/network/devices?metric=rtt&limit=2");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].size() == 2);
    CHECK(j["data"][0]["agent_id"] == "hi-0"); // worst (highest RTT) first
    CHECK(j["data"][0]["platform"] == "linux");
    CHECK(j["data"][0]["fleet_pctile"] == 100); // the worst RTT is the 100th percentile

    SECTION("non-empty cohort_value filters to that cohort only") {
        auto site_b = h.sink.Get("/api/v1/network/devices?key=site&cohort_value=site-b");
        REQUIRE(site_b);
        auto jb = nlohmann::json::parse(site_b->body);
        CHECK(jb["data"].size() == 3); // the 3 site-b (hi-*) devices, none of the site-a
        for (const auto& d : jb["data"])
            CHECK(d["cohort"] == "site-b");
    }
    SECTION("metric=throughput sorts busiest (highest bps) first") {
        // lo-* (site-a) carry 5.0e6 bps vs hi-* (site-b) 1.0e5 → site-a is busiest.
        auto busy = h.sink.Get("/api/v1/network/devices?metric=throughput&limit=2");
        REQUIRE(busy);
        auto jt = nlohmann::json::parse(busy->body);
        REQUIRE(jt["data"].size() == 2);
        CHECK(jt["data"][0]["cohort"] == "site-a");
    }

    SECTION("cohort key resolves the cohort column but does NOT filter") {
        auto all = h.sink.Get("/api/v1/network/devices?key=site");
        REQUIRE(all);
        auto ja = nlohmann::json::parse(all->body);
        CHECK(ja["data"].size() == 6); // both cohorts present — no implicit filter
    }
    SECTION("empty cohort_value present = the untagged residual filter") {
        auto none = h.sink.Get("/api/v1/network/devices?key=site&cohort_value=");
        REQUIRE(none);
        auto jn = nlohmann::json::parse(none->body);
        CHECK(jn["data"].empty()); // net_two has no untagged devices
    }
    SECTION("invalid limit → 400") {
        auto bad = h.sink.Get("/api/v1/network/devices?limit=0");
        REQUIRE(bad);
        CHECK(bad->status == 400);
    }
    SECTION("perm denied → 403") {
        h.grant_perms = false;
        auto denied = h.sink.Get("/api/v1/network/fleet");
        REQUIRE(denied);
        CHECK(denied->status == 403);
    }
}

TEST_CASE("REST /network/*: no provider wired → 503", "[network][rest]") {
    RestNetHarness h({});
    for (const char* path : {"/api/v1/network/fleet", "/api/v1/network/devices"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
}

TEST_CASE("OpenAPI spec lists the network endpoints (A2 discovery), stays valid JSON",
          "[network][rest][discovery][a2]") {
    RestNetHarness h({});
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE_NOTHROW(nlohmann::json::parse(res->body)); // whole doc stays valid JSON
    CHECK(res->body.find(R"("/network/fleet":)") != std::string::npos);
    CHECK(res->body.find(R"("/network/devices":)") != std::string::npos);
}
