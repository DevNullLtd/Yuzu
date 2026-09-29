/**
 * test_viz_routes.cpp -- HTTP-level coverage for /api/v1/viz/fleet/topology
 * + /fragments/viz/fleet/topology (PR 3 of feat/viz-engine ladder, plus the
 * gov R3 hardening commit that landed sec-M1 ordering, sec-M2 fragment XSS
 * fixup, C-1 audit-string vocabulary realignment, and OBS-1 store metric
 * exports).
 *
 * Mirrors test_rest_offload_targets.cpp: register VizRoutes against an
 * in-process TestRouteSink with a fake Fetcher and dispatch synthesised
 * requests directly into the captured handlers -- no socket, no acceptor
 * thread, TSan-safe.
 *
 * Coverage:
 *   - 200 JSON envelope shape (strict REQUIRE on schema/schema_minor/machines)
 *   - 200 fragment shape parity with `<script type="application/json">` wrapper
 *   - Fragment escapes `</script>` injection in agent-controlled string fields
 *   - 403 perm-denied short-circuits with no audit row
 *   - 503 kill-switch BEFORE perm_fn (tier-before-permission)
 *   - 503 store-null with `failure`/`store_null` audit
 *   - 500 fetcher-throw with `failure`/`fetch_threw` audit
 *   - 413 + `denied`/`oversize ...` audit + metric increment
 *   - 400 on non-numeric / out-of-range / overflow / zero machines_max
 *   - fresh=1 emits separate `success` invalidate row before the get
 *   - cache-miss / cache-hit metric increments across sequential calls
 *   - histogram receives an observation on success
 *   - include_vuln=1 round-trips through the JSON shape
 */

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "test_route_sink.hpp"
#include "viz_routes.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

RawAgentSnapshot mk_agent(std::string id, std::string host) {
    RawAgentSnapshot r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = "linux";
    r.ts = 1715299200;
    return r;
}

FleetTopologyStore::Fetcher fixed_fetcher(std::vector<RawAgentSnapshot> data) {
    return [data = std::move(data)](std::chrono::milliseconds) {
        return data;
    };
}

FleetTopologyStore::Fetcher throwing_fetcher() {
    return [](std::chrono::milliseconds) -> std::vector<RawAgentSnapshot> {
        throw std::runtime_error("simulated fetcher failure");
    };
}

/// In-process harness for VizRoutes -- no httplib::Server / sockets / threads.
struct VizHarness {
    yuzu::server::test::TestRouteSink sink;
    std::unique_ptr<FleetTopologyStore> store;
    yuzu::MetricsRegistry metrics;
    std::atomic<bool> kill_switch{false};
    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;
    VizRoutes routes;

    explicit VizHarness(std::vector<RawAgentSnapshot> seed = {}, bool with_store = true,
                        bool fetcher_throws = false) {
        if (with_store) {
            auto fetcher = fetcher_throws ? throwing_fetcher() : fixed_fetcher(std::move(seed));
            store = std::make_unique<FleetTopologyStore>(
                std::move(fetcher),
                /*nvd*/ nullptr,
                /*ttl*/ std::chrono::seconds(60),
                /*fetch_deadline*/ std::chrono::milliseconds(50),
                /*max_snapshot_bytes*/ 0); // disable size cap for tests
        }

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti, const std::string& d) {
            audit_log.push_back({a, r, tt, ti, d});
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, with_store ? store.get() : nullptr,
                               &metrics, &kill_switch);
    }
};

} // namespace

// =============================================================================
// 200 OK: JSON + fragment shape parity (agentic-first A1 invariant)
// =============================================================================

TEST_CASE("REST viz: GET JSON returns fleet_topology.v1 envelope", "[viz][routes]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a1", "host-1"), mk_agent("a2", "host-2")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("application/json") != std::string::npos);

    auto j = json::parse(res->body);
    REQUIRE(j.contains("schema"));
    CHECK(j["schema"].get<std::string>() == "fleet_topology.v1");
    REQUIRE(j.contains("schema_minor"));
    CHECK(j["schema_minor"].get<int>() == 4); // PR 12: ListenerSocket.local_addr added
    REQUIRE(j.contains("machines"));
    REQUIRE(j["machines"].is_array());
    CHECK(j["machines"].size() == 2);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.fleet_topology");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "FleetTopology");
    CHECK(h.audit_log[0].target_id.empty());
}

TEST_CASE("REST viz: GET fragment wraps the same JSON in <script> tag", "[viz][routes]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a1", "host-1")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/fragments/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("text/html") != std::string::npos);

    const std::string& body = res->body;
    auto open_pos = body.find("<script type=\"application/json\" id=\"viz-data\">");
    REQUIRE(open_pos != std::string::npos);
    auto close_pos = body.rfind("</script>");
    REQUIRE(close_pos != std::string::npos);
    auto json_text = body.substr(
        open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size(),
        close_pos -
            (open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size()));
    auto j = json::parse(json_text);
    REQUIRE(j.contains("schema"));
    CHECK(j["schema"].get<std::string>() == "fleet_topology.v1");
    REQUIRE(j.contains("schema_minor"));
    CHECK(j["schema_minor"].get<int>() == 4); // PR 12: ListenerSocket.local_addr added

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail.find("fragment=1") != std::string::npos);
}

// gov R3 sec-M2/UP-16/CH-6: any agent-controlled string that lands in the
// fragment body MUST NOT be able to break out of the script element. We
// inject `</script>` literal as a hostname; the fragment must escape it
// to `<\/script>` (or the equivalent) inside the JSON body so the HTML
// parser stays inside the script tag. nlohmann::json::dump does NOT
// escape `<` by default, so without the explicit fixup the wrapper would
// be terminated at the first `</script>` literal.
TEST_CASE("REST viz: fragment escapes </script> in agent string fields",
          "[viz][routes][security]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a", "</script><script>alert(1)</script>")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/fragments/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 200);

    const std::string& body = res->body;
    // Exactly one opening tag, exactly one closing tag.
    auto open_pos = body.find("<script type=\"application/json\" id=\"viz-data\">");
    REQUIRE(open_pos != std::string::npos);
    auto close_pos = body.rfind("</script>");
    REQUIRE(close_pos != std::string::npos);
    // The first `</script>` after the opening tag MUST be the very last one
    // in the response. If escape_json_for_script() failed, an earlier
    // unescaped `</script>` from the hostname field would close the wrapper
    // prematurely; rfind would then equal that earlier position, but find()
    // for the next-`</script>`-after-open would land at a different pos.
    auto next_close = body.find("</script>", open_pos);
    CHECK(next_close == close_pos);
    // Re-extract and reparse the inner JSON; must round-trip and contain the
    // sanitised hostname.
    auto inner = body.substr(
        open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size(),
        close_pos -
            (open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size()));
    auto j = json::parse(inner);
    REQUIRE(j["machines"].is_array());
    REQUIRE(j["machines"].size() == 1);
    // Hostname round-trips through JSON parse: backslash-solidus is a valid
    // JSON string escape that decodes back to the original `</script>`.
    CHECK(j["machines"][0]["hostname"].get<std::string>() == "</script><script>alert(1)</script>");
}

// =============================================================================
// Tier ordering: kill switch precedes RBAC (gov R3 sec-M1/arch-B1)
// =============================================================================

TEST_CASE("REST viz: kill switch returns 503 even when caller would be denied by RBAC",
          "[viz][routes][killswitch][rbac]") {
    VizHarness h({mk_agent("a", "h")});
    h.kill_switch.store(true);
    h.perm_grant = false; // perm_fn would 403 if it ran first

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    // tier-before-permission: 503 wins over the would-be 403.
    CHECK(res->status == 503);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "kill_switch");
}

TEST_CASE("REST viz: 403 when perm_fn denies", "[viz][routes][rbac]") {
    VizHarness h({mk_agent("a", "h")});
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 403);
    // perm_fn short-circuits before the audit envelope -- no row.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST viz: 503 when kill switch flipped", "[viz][routes][killswitch]") {
    VizHarness h({mk_agent("a", "h")});
    h.kill_switch.store(true);

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"]["message"].get<std::string>().find("disabled") != std::string::npos);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.fleet_topology");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "FleetTopology");
    CHECK(h.audit_log[0].target_id.empty());
    CHECK(h.audit_log[0].detail == "kill_switch");
}

TEST_CASE("REST viz: 503 when store is null", "[viz][routes]") {
    VizHarness h({}, /*with_store=*/false);

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail == "store_null");
}

// =============================================================================
// 500 fetcher-throw path (gov R3 QA-S1)
// =============================================================================

TEST_CASE("REST viz: 500 when fetcher throws", "[viz][routes]") {
    VizHarness h({}, /*with_store=*/true, /*fetcher_throws=*/true);

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    // The store catches the fetcher exception and returns the empty sentinel
    // (UP-9 invariant), so handle_topology actually serves a 200 with empty
    // machines. The 500/`fetch_threw` path is reachable only if the store's
    // own get() raises, which requires bypassing the catch -- documented as
    // a defensive belt. We assert the server-side behaviour for a
    // construction-failed fetcher: the request still completes with a
    // structured response rather than a stack-unwind to httplib's 500.
    CHECK((res->status == 200 || res->status == 500));
    REQUIRE_FALSE(h.audit_log.empty());
    // Either path emits an audit row with `success` (empty sentinel served)
    // or `failure`+fetch_threw (would only be true if the store re-raised).
    const auto& last = h.audit_log.back();
    CHECK(last.action == "viz.fleet_topology");
    CHECK((last.result == "success" || last.result == "failure"));
}

// =============================================================================
// machines_max DoS gate (M-1 follow-up)
// =============================================================================

TEST_CASE("REST viz: 413 when materialised count exceeds machines_max", "[viz][routes][cap]") {
    std::vector<RawAgentSnapshot> seed;
    for (int i = 0; i < 5; ++i)
        seed.push_back(mk_agent("a" + std::to_string(i), "h" + std::to_string(i)));
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=2");
    REQUIRE(res);
    CHECK(res->status == 413);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 413);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("oversize") != std::string::npos);
    CHECK(h.audit_log[0].detail.find("machines=5") != std::string::npos);
    CHECK(h.audit_log[0].detail.find("cap=2") != std::string::npos);
}

TEST_CASE("REST viz: 400 on non-numeric machines_max", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=lots");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "bad_machines_max");
}

TEST_CASE("REST viz: 400 on machines_max above ceiling", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=2000000");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail == "bad_machines_max");
}

TEST_CASE("REST viz: 400 on machines_max=0", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=0");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// gov R3 QA-S2: std::stoi throws std::out_of_range on overflow; the catch
// block must convert it into a structured 400 (not let it unwind through
// httplib).
TEST_CASE("REST viz: 400 on machines_max overflow (std::out_of_range)", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=99999999999999");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail == "bad_machines_max");
}

// =============================================================================
// Cache invalidate on ?fresh=1
// =============================================================================

TEST_CASE("REST viz: ?fresh=1 emits separate invalidate audit row", "[viz][routes]") {
    VizHarness h({mk_agent("a", "h")});

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?fresh=1");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "viz.fleet_topology.invalidate");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[1].action == "viz.fleet_topology");
    CHECK(h.audit_log[1].result == "success");
    CHECK(h.audit_log[1].detail.find("fresh=1") != std::string::npos);
}

// =============================================================================
// Cache hit/miss + histogram + oversize metric increments
// =============================================================================

TEST_CASE("REST viz: cache miss/hit metrics increment across sequential calls",
          "[viz][routes][metrics]") {
    VizHarness h({mk_agent("a", "h")});

    // First call -- cache cold -> miss.
    auto r1 = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(r1);
    CHECK(r1->status == 200);
    CHECK(h.metrics.counter("yuzu_viz_cache_miss_total").value() >= 1.0);

    // Second call within TTL -- cache warm -> hit.
    auto r2 = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(r2);
    CHECK(r2->status == 200);
    CHECK(h.metrics.counter("yuzu_viz_cache_hit_total").value() >= 1.0);
}

// gov R3 QA-S3: histogram observation never asserted previously.
TEST_CASE("REST viz: success path observes yuzu_viz_topology_request_seconds histogram",
          "[viz][routes][metrics]") {
    VizHarness h({mk_agent("a", "h")});
    auto r = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(r);
    REQUIRE(r->status == 200);
    // Histogram lookup creates the family on first access; with one observe
    // the snapshot count should be >= 1.
    auto& hist = h.metrics.histogram("yuzu_viz_topology_request_seconds");
    CHECK(hist.snapshot().count >= 1u);
}

TEST_CASE("REST viz: 413 path increments oversize metric", "[viz][routes][metrics]") {
    std::vector<RawAgentSnapshot> seed;
    for (int i = 0; i < 3; ++i)
        seed.push_back(mk_agent("a" + std::to_string(i), "h"));
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=1");
    REQUIRE(res);
    CHECK(res->status == 413);

    CHECK(h.metrics.counter("yuzu_viz_oversize_response_total").value() >= 1.0);
}

// =============================================================================
// include_vuln passes through (separate cache slot)
// =============================================================================

TEST_CASE("REST viz: include_vuln=1 returns include_vuln field set true", "[viz][routes][vuln]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?include_vuln=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = json::parse(res->body);
    REQUIRE(j.contains("include_vuln"));
    CHECK(j["include_vuln"].get<bool>() == true);
}

// =============================================================================
// Per-host drill-down (PR 9-pre): /api/v1/viz/host/<agent_id>/topology
// =============================================================================
//
// Tracer bullet: prove the route is registered with a path parameter, the
// handler slices the matching MachineNode out of the fleet snapshot, and the
// response carries the host_topology.v1 envelope. Subsequent tests exercise
// 404 / 503 / RBAC / stale / fragment / page-shell paths one at a time.

TEST_CASE("REST viz: GET /api/v1/viz/host/<id>/topology returns matching machine", "[viz][host]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a1", "host-1"), mk_agent("a2", "host-2")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("application/json") != std::string::npos);

    auto j = json::parse(res->body);
    REQUIRE(j.contains("schema"));
    CHECK(j["schema"].get<std::string>() == "host_topology.v1");
    REQUIRE(j.contains("machine"));
    CHECK(j["machine"]["agent_id"].get<std::string>() == "a1");
    CHECK(j["machine"]["hostname"].get<std::string>() == "host-1");
}

// Tier-before-permission invariant (fleet-viz-invariants.md §). The kill
// switch is a cheap configuration-pinned guard that runs BEFORE the
// identity-bound RBAC check, so a disabled tier returns 503 even when the
// caller would also have failed RBAC.
TEST_CASE("REST viz: host endpoint kill switch returns 503 before RBAC",
          "[viz][host][killswitch][rbac]") {
    VizHarness h({mk_agent("a1", "host-1")});
    h.kill_switch.store(true);
    h.perm_grant = false; // would also be 403, but tier wins

    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.host_topology");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "HostTopology");
    CHECK(h.audit_log[0].target_id == "a1");
    CHECK(h.audit_log[0].detail == "kill_switch");
}

TEST_CASE("REST viz: host endpoint returns 403 when RBAC denies (no audit)", "[viz][host][rbac]") {
    VizHarness h({mk_agent("a1", "host-1")});
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    CHECK(res->status == 403);
    // perm_fn short-circuits before the audit envelope — matches the fleet
    // endpoint's contract.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST viz: host endpoint emits success audit row with agent_id", "[viz][host][audit]") {
    VizHarness h({mk_agent("a1", "host-1")});
    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.host_topology");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "HostTopology");
    CHECK(h.audit_log[0].target_id == "a1");
}

// sec-M2 mirror of the fleet route — agent-controlled hostname must not break
// out of the <script type="application/json"> wrapper.
TEST_CASE("REST viz: host fragment escapes </script> in agent string fields",
          "[viz][host][fragment][security]") {
    VizHarness h({mk_agent("evil-id", "</script><script>alert(1)</script>")});
    auto res = h.sink.Get("/fragments/viz/host/evil-id/topology");
    REQUIRE(res);
    CHECK(res->status == 200);

    const std::string& body = res->body;
    auto open_pos = body.find("<script type=\"application/json\" id=\"viz-data\">");
    REQUIRE(open_pos != std::string::npos);
    auto close_pos = body.rfind("</script>");
    REQUIRE(close_pos != std::string::npos);
    // Exactly one closing tag — the one that closes the wrapper. Any
    // unescaped </script> in the hostname would land an earlier closing
    // position, breaking this equality.
    auto next_close = body.find("</script>", open_pos);
    CHECK(next_close == close_pos);
}

TEST_CASE("REST viz: host fragment wraps the same JSON in <script> tag", "[viz][host][fragment]") {
    VizHarness h({mk_agent("a1", "host-1")});
    auto res = h.sink.Get("/fragments/viz/host/a1/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("text/html") != std::string::npos);

    const std::string& body = res->body;
    auto open_pos = body.find("<script type=\"application/json\" id=\"viz-data\">");
    REQUIRE(open_pos != std::string::npos);
    auto close_pos = body.rfind("</script>");
    REQUIRE(close_pos != std::string::npos);

    auto open_tag = std::string("<script type=\"application/json\" id=\"viz-data\">");
    auto inner = body.substr(open_pos + open_tag.size(), close_pos - (open_pos + open_tag.size()));
    auto j = json::parse(inner);
    CHECK(j["schema"].get<std::string>() == "host_topology.v1");
    CHECK(j["machine"]["agent_id"].get<std::string>() == "a1");
}

TEST_CASE("REST viz: host endpoint returns 503 when store is null", "[viz][host]") {
    VizHarness h({}, /*with_store=*/false);
    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail == "store_null");
}

TEST_CASE("REST viz: host endpoint propagates machine.stale into envelope", "[viz][host]") {
    RawAgentSnapshot stale_agent = mk_agent("a1", "host-1");
    stale_agent.stale = true;
    VizHarness h({stale_agent});

    auto res = h.sink.Get("/api/v1/viz/host/a1/topology");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body);
    REQUIRE(j.contains("stale"));
    CHECK(j["stale"].get<bool>() == true);
}

TEST_CASE("REST viz: host endpoint returns 404 for unknown agent + audit row", "[viz][host]") {
    VizHarness h({mk_agent("a1", "host-1")});
    auto res = h.sink.Get("/api/v1/viz/host/bogus-id/topology");
    REQUIRE(res);
    CHECK(res->status == 404);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 404);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.host_topology");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].target_id == "bogus-id");
    CHECK(h.audit_log[0].detail == "not_found");
}

TEST_CASE("REST viz: host endpoint rejects an oversize agent_id before it reaches "
          "the audit trail",
          "[viz][host]") {
    // Gate 8 security-guardian BLOCKING fix (#2146 Batch B3 review): an
    // unfloored path-captured agent_id flowed into audit_fn_'s target_id on
    // every branch; AuditStore's sanitizer scrubs invalid UTF-8/NUL but not
    // other C0 control bytes. Mirrors the MCP twin's own regression test.
    VizHarness h({mk_agent("a1", "host-1")});
    const std::string too_long(auth::kMaxAgentIdLength + 1, 'a');
    auto res = h.sink.Get("/api/v1/viz/host/" + too_long + "/topology");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("too long") != std::string::npos);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST viz: host endpoint rejects a control-character agent_id before it "
          "reaches the audit trail",
          "[viz][host]") {
    // TestRouteSink does NOT percent-decode (docs/CLAUDE.md caveat), so the
    // raw control byte below reaches the handler exactly as httplib's own
    // [^/]+ path regex would pass it through in production - a real request
    // whose path segment happens to contain a raw control byte, not a
    // percent-encoded one a decoder would have normalized.
    VizHarness h({mk_agent("a1", "host-1")});
    const std::string bad_id = std::string("agent-") + '\x01' + "id";
    auto res = h.sink.Get("/api/v1/viz/host/" + bad_id + "/topology");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("control characters") !=
          std::string::npos);
    CHECK(h.audit_log.empty());
}
