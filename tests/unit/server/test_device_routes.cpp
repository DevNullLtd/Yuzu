/// @file test_device_routes.cpp
/// Route-level tests for the shared device page's list/page/info surfaces and
/// the "Get live info" dispatch/poll routes (/fragments/device/live{,/run,/result}).
/// Driven in-process through TestRouteSink (no httplib acceptor, #438), with stub
/// auth/perm/dispatch/responses/audit fns and a `FakeDeviceApi` (ADR-0031 WS-A4
/// wave 2 — DeviceRoutes now takes a `shared_ptr<const DeviceApi>` instead of the
/// old DevicesFn/LookupFn provider pair). The DEX/Guardian device-lens tests moved
/// to test_device_lens_routes.cpp (DeviceLensRoutes, split out of DeviceRoutes).
///
/// These complement the pure-renderer tests in test_device_ui.cpp: the renderer
/// tests are data-in/HTML-out, but the result-route poll keeps POINTERS into the
/// responses vector across the scan loop — a use-after-free crashed the server
/// the instant live output arrived (the temporary returned by responses_fn_ was
/// iterated directly). The "data renders" sections below drive that exact path,
/// so the bug is caught here (deterministically under ASan in nightly CI).

#include "device_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <expected>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

// Minimal test double for the DeviceApi seam (ADR-0031 WS-A4 wave 2). `rows`
// backs list_devices() (UNSCOPED — DeviceRoutes applies its own visible_set_fn
// filter, matching the real seam's contract); `details` backs lookup_device()
// by agent_id (explicit per-id entries take precedence). `device_os_ptr`, when
// wired and non-empty, makes lookup_device(ANY id without an explicit `details`
// entry) resolve to a bare identity row carrying that OS — the K-4 live-result
// os-lookup tests' idiom, read dynamically (not snapshotted at harness
// construction) so a test can flip `device_os` after construction. `degraded_ids`
// makes lookup_device(id) return DeviceReadError::kDegraded for that id.
class FakeDeviceApi : public DeviceApi {
public:
    std::vector<DeviceListRow> rows;
    std::unordered_map<std::string, DeviceDetail> details;
    std::vector<std::string> degraded_ids;
    const std::string* device_os_ptr = nullptr;

    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override { return rows; }

    [[nodiscard]] std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string& id) const override {
        if (std::find(degraded_ids.begin(), degraded_ids.end(), id) != degraded_ids.end())
            return std::unexpected(DeviceReadError::kDegraded);
        if (auto it = details.find(id); it != details.end())
            return std::optional<DeviceDetail>{it->second};
        if (device_os_ptr && !device_os_ptr->empty()) {
            DeviceDetail d;
            d.row.agent_id = id;
            d.row.os = *device_os_ptr;
            return std::optional<DeviceDetail>{d};
        }
        return std::optional<DeviceDetail>{std::nullopt};
    }
};

// A confinement provider that ignores `username` and always returns the SAME
// fixed set — matches the pre-rewire tests' username-agnostic DevicesFn fakes.
DeviceRoutes::VisibleSetFn fixed_scope(std::set<std::string> ids) {
    return [ids = std::move(ids)](const std::string&) -> std::optional<std::set<std::string>> {
        return ids;
    };
}

// A live-route harness: stub fns + a registered DeviceRoutes over a TestRouteSink.
struct LiveHarness {
    yuzu::server::test::TestRouteSink sink;
    DeviceRoutes routes;

    int dispatched = 0;
    int fake_sent = 1;
    std::string seen_plugin, seen_action, seen_id;            // LAST dispatch (compat)
    std::vector<std::pair<std::string, std::string>> seen_dispatches; // ALL (plugin,action)
    std::vector<DexAgentResponse> fake_rows;                  // default response store contents
    std::unordered_map<std::string, std::vector<DexAgentResponse>> rows_by_cmd; // per-command override
    std::string audited;                                      // "action|result|target_id"
    bool allow_execute = true;
    bool audit_ok = true;      // #1647: flip to drop the evidence row (audit_fn → false)
    bool audit_throws = false; // #1647: flip to throw a bad_alloc-class fault from audit_fn
    std::string device_os;     // K-4: lookup_fn returns a DeviceRow with this os when non-empty

    LiveHarness() {
        auto okAuth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&) { return true; };
        // The live routes gate per-device via scoped_perm (not the unscoped perm):
        // Read always allowed; Execute toggled by allow_execute.
        auto scoped_perm = [this](const httplib::Request&, httplib::Response&, const std::string&,
                                  const std::string& op, const std::string&) {
            return op == "Execute" ? allow_execute : true;
        };
        // device_os empty by default: exercises the content-sniff fallback.
        auto api = std::make_shared<FakeDeviceApi>();
        api->device_os_ptr = &device_os;
        auto dispatch = [this](const std::string& plugin, const std::string& action,
                               const std::vector<std::string>& ids, const std::string&,
                               const std::unordered_map<std::string, std::string>&)
            -> yuzu::server::ConfinedDispatchOutcome {
            ++dispatched;
            seen_plugin = plugin;
            seen_action = action;
            seen_id = ids.empty() ? "" : ids.front();
            seen_dispatches.emplace_back(plugin, action);
            // command_id prefix MUST be <plugin>- so the result route accepts it.
            return {.sent = fake_sent, .command_id = plugin + "-test"};
        };
        auto responses = [this](const std::string& cmd, const std::string& /*agent_id*/) {
            // #1634: production scopes by agent_id at the store seam; the stub returns
            // by command_id and relies on the route's post-filter for isolation tests.
            auto it = rows_by_cmd.find(cmd);
            return it != rows_by_cmd.end() ? it->second : fake_rows;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
            audited = a + "|" + r + "|" + tid;
            // #1647: the row is recorded before the throw so `audited` still proves the
            // site was reached; the throw then exercises the shared helper's catch-arm.
            if (audit_throws)
                throw std::runtime_error("audit DB write blew up");
            return audit_ok; // DexRoutes::AuditFn (aliased by DeviceRoutes) is bool-returning (#1549)
        };
        routes.register_routes(sink, okAuth, perm, scoped_perm, api, /*visible_set_fn=*/{},
                               /*dex_score_fn=*/{}, dispatch, responses, audit);
    }
};

} // namespace

TEST_CASE("device live shell: serves a collapsible card per kind + chrome", "[device][routes]") {
    LiveHarness h;
    auto r = h.sink.Get("/fragments/device/live?id=a-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // uptime is the hidden KPI loader; the cards cover the rest of the snapshot.
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=uptime") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=process_tree") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=services") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=arp") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=dns_cache") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=capture_sources") != std::string::npos);
    // Snapshot chrome: collapsible cards + expand-all + pop-out (CSP-safe inline handlers).
    CHECK(r->body.find("class=\"ls-card\"") != std::string::npos);
    CHECK(r->body.find("lsToggleAll(this)") != std::string::npos);
    CHECK(r->body.find("lsPopOut(event,this)") != std::string::npos);
}

TEST_CASE("device live run: dispatches the right plugin and audits per-kind", "[device][routes]") {
    SECTION("uptime -> os_info/uptime, audited as device.live.uptime") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(h.dispatched == 1);
        CHECK(h.seen_plugin == "os_info");
        CHECK(h.seen_action == "uptime");
        CHECK(h.seen_id == "a-1");
        // Polling stub points back at the result route with the command_id + kind.
        CHECK(r->body.find("/fragments/device/live/result?command_id=os_info-test") !=
              std::string::npos);
        CHECK(r->body.find("kind=uptime") != std::string::npos);
        // Usage vs machine-health audit split (works-council posture). The result
        // is "dispatched" (not "success") — the outcome isn't known at dispatch time
        // and this stays in lockstep with the REST sibling.
        CHECK(h.audited == "device.live.uptime|dispatched|a-1");
    }
    SECTION("processes -> processes/list_hashed, audited as device.live.processes") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=processes");
        REQUIRE(r);
        CHECK(h.seen_plugin == "processes");
        CHECK(h.seen_action == "list_hashed"); // hashed variant carries the SHA-256
        CHECK(h.audited == "device.live.processes|dispatched|a-1");
    }
    SECTION("offline device (sent=0): honest note, no polling, no auto-fire") {
        LiveHarness h;
        h.fake_sent = 0;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->body.find("Device offline") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
        CHECK(h.audited == "device.live.uptime|no_agents|a-1");
    }
    SECTION("unknown kind is rejected (allowlist) before any dispatch") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=bogus");
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(h.dispatched == 0);
    }
    SECTION("Execute denied: honest note, no dispatch") {
        LiveHarness h;
        h.allow_execute = false;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->body.find("Execute") != std::string::npos);
        CHECK(h.dispatched == 0);
    }
}

// #1647 catch-arm parity: the device.live.* DISPATCH audit set Sec-Audit-Failed on a
// returns-false but had NO try/catch — a throwing audit_fn escaped the handler (httplib
// → 500). Routed through the shared rest_audit.hpp chokepoint, a throw is now caught and
// flags the header, while the post-dispatch SET-AND-PROCEED posture is unchanged (the
// dispatch already happened; the panel still polls for the result).
TEST_CASE("device live run: audit-persist gap surfaces Sec-Audit-Failed, still polls",
          "[device][routes][audit]") {
    SECTION("a dropped audit row (audit_fn → false)") {
        LiveHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->status == 200); // set-and-proceed
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.dispatched == 1); // the audit failure did not block the dispatch
        CHECK(r->body.find("/fragments/device/live/result") != std::string::npos);
    }
    SECTION("a throwing audit_fn is caught, never escapes the handler") {
        LiveHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.dispatched == 1);
        CHECK(r->body.find("/fragments/device/live/result") != std::string::npos);
    }
    SECTION("clean path sets NO Sec-Audit-Failed header") {
        LiveHarness h; // audit_ok=true, audit_throws=false
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
        CHECK(h.audited == "device.live.uptime|dispatched|a-1");
    }
}

// The regression centrepiece: the result poll keeps pointers into the responses
// vector across the scan, then renders AFTER the loop. Iterating the temporary
// (the original bug) is a use-after-free; these sections drive that path with
// real output and assert the rendered result.
TEST_CASE("device live result: output renders, server survives the poll", "[device][routes]") {
    SECTION("uptime output -> KPI out-of-band swap, polling stops") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "uptime_seconds|181740\nuptime_display|2d 2h 29m", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);
        CHECK(r->body.find("id=\"ls-kpi-uptime\"") != std::string::npos); // fills the KPI tile
        CHECK(r->body.find("hx-swap-oob=\"true\"") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos); // resolved, no re-poll
    }
    SECTION("processes output -> PID/name/hash table (proc|pid|name|sha256|path)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0,
                        "proc|0|[System Process]||\n"
                        "proc|4|System||\n"
                        "proc|123|sh|"
                        "deadbeefcafe0000111122223333444455556666777788889999aaaabbbbccccdddd|"
                        "/bin/sh",
                        ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=processes-test&agent_id=a-1&kind=processes&n=1");
        REQUIRE(r);
        CHECK(r->body.find("running processes") != std::string::npos);
        CHECK(r->body.find("[System Process]") != std::string::npos);
        CHECK(r->body.find("123") != std::string::npos);
        CHECK(r->body.find("deadbeefcafe0000") != std::string::npos); // truncated hash rendered
        CHECK(r->body.find("/bin/sh") != std::string::npos);          // path rendered
    }
    SECTION("pending (no rows yet) -> re-poll with n+1") {
        LiveHarness h; // fake_rows empty
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("&amp;n=2") != std::string::npos);
    }
    SECTION("another agent's rows never render here") {
        LiveHarness h;
        h.fake_rows = {{"OTHER", 0, "uptime_display|9d 9h", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("9d 9h") == std::string::npos); // filtered by agent_id
    }
    SECTION("agent error payload is surfaced, escaped") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "error|<b>boom</b>", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("reported an error") != std::string::npos);
        CHECK(r->body.find("<b>boom</b>") == std::string::npos); // escaped, not raw
    }
    SECTION("terminal failure frame -> honest failure note") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 2, "", "plugin crashed"}}; // status>=2, no output
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("failed on the device") != std::string::npos);
    }
    SECTION("terminal SUCCESS with empty output renders now, no false timeout (UP-1)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "", ""}}; // SUCCESS (status 1), no output
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=processes-test&agent_id=a-1&kind=processes&n=1");
        REQUIRE(r);
        CHECK(r->body.find("No processes returned") != std::string::npos); // empty result rendered
        CHECK(r->body.find("hx-trigger") == std::string::npos);            // not re-polled
        CHECK(r->body.find("timed out") == std::string::npos);             // NOT a false timeout
    }
    SECTION("command_id whose prefix doesn't match the kind's plugin is rejected") {
        LiveHarness h;
        // kind=uptime expects os_info-; a tar- id must not be pollable here.
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=tar-deadbeef&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    SECTION("timeout (attempt cap) is honest, stops polling") {
        LiveHarness h; // empty rows
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=40");
        REQUIRE(r);
        CHECK(r->body.find("timed out") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
    }
    SECTION("below the attempt cap keeps polling (cap raised for hash latency)") {
        LiveHarness h; // empty rows
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=20");
        REQUIRE(r);
        CHECK(r->body.find("timed out") == std::string::npos); // 20 < 40 -> still polling
        CHECK(r->body.find("&amp;n=21") != std::string::npos);
    }
}

// #1703: the RESULT poll — where the real process-tree/DNS/connections/users PII
// actually reaches the operator — must funnel through the behavioural-PII audit
// chokepoint, not only the /run dispatch. These assert the audit fires when
// output is served, stays silent on the error/failure/timeout notes, and adopts
// the dashboard set-and-proceed posture (renders anyway, raises Sec-Audit-Failed).
TEST_CASE("device live result: rendering PII audits at the result chokepoint",
          "[device][routes][audit]") {
    SECTION("real output audits device.live.<kind>|rendered and renders") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "uptime_display|2d 2h 29m", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);
        CHECK(h.audited == "device.live.uptime|rendered|a-1");
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
    }
    SECTION("terminal success-empty output audits device.live.<kind>|rendered_empty") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "", ""}}; // SUCCESS, no output
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=processes-test&agent_id=a-1&kind=processes&n=1");
        REQUIRE(r);
        CHECK(r->body.find("No processes returned") != std::string::npos);
        CHECK(h.audited == "device.live.processes|rendered_empty|a-1");
    }
    SECTION("a dropped audit row on a result poll still renders but sets Sec-Audit-Failed") {
        LiveHarness h;
        h.audit_ok = false; // audit_fn → false (evidence row dropped)
        h.fake_rows = {{"a-1", 0, "uptime_display|2d 2h 29m", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);          // set-and-proceed
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("a throwing audit_fn on a result poll is caught, still renders") {
        LiveHarness h;
        h.audit_throws = true;
        h.fake_rows = {{"a-1", 0, "uptime_display|2d 2h 29m", ""}};
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1"));
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }
    SECTION("the error/failure/timeout notes render NO PII and are not audited") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "error|boom", ""}}; // agent error payload
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("reported an error") != std::string::npos);
        CHECK(h.audited.empty()); // no PII served -> no result-chokepoint audit
    }
}

// The expanded live-snapshot kinds each map to ONE real plugin action with its own
// audit verb. process_tree additionally dual-dispatches its connection join.
TEST_CASE("device live run: expanded kinds map to the right plugin/action + audit",
          "[device][routes]") {
    struct Case { const char* kind; const char* plugin; const char* action; const char* verb; };
    const Case cases[] = {
        {"services", "services", "list", "device.live.services"},
        {"users", "users", "logged_on", "device.live.users"},
        {"netconfig", "network_config", "ip_addresses", "device.live.netconfig"},
        {"arp", "network_config", "arp", "device.live.arp"},
        {"dns_cache", "network_config", "dns_cache", "device.live.dns_cache"},
        {"listening", "network_diag", "listening", "device.live.listening"},
        {"connections", "network_diag", "connections", "device.live.connections"},
        {"capture_sources", "tar", "status", "device.live.capture_sources"},
        {"disk", "disk_space", "free", "device.live.disk"},
        // Round-3 item 11: ten physical-hardware "generic pipe-row" kinds
        // (live_kinds.hpp LiveKind::columns/.row_prefix + device_ui.cpp
        // render_device_live_generic). Same plugin/action/verb mapping as the
        // canonical kind table — see test_device_live_generic_kinds below for
        // render-path coverage of hw_disks + thermal.
        {"hw_disks", "hardware", "disks", "device.live.hw_disks"},
        {"hw_memory", "hardware", "memory", "device.live.hw_memory"},
        {"hw_processors", "hardware", "processors", "device.live.hw_processors"},
        {"hw_drivers", "hardware", "drivers", "device.live.hw_drivers"},
        {"battery", "power_health", "battery", "device.live.battery"},
        {"thermal", "power_health", "thermal", "device.live.thermal"},
        {"smart", "disk_actions", "smart", "device.live.smart"},
        {"volumes", "disk_actions", "volumes", "device.live.volumes"},
        {"adapters", "network_config", "adapters", "device.live.adapters"},
        {"wifi", "wifi", "connected", "device.live.wifi"},
    };
    for (const auto& c : cases) {
        LiveHarness h;
        auto r = h.sink.Get(std::string("/fragments/device/live/run?id=a-1&kind=") + c.kind);
        REQUIRE(r);
        CHECK(h.seen_plugin == c.plugin);
        CHECK(h.seen_action == c.action);
        // Post-dispatch audit result is "dispatched" (dev's #1549 convention; the
        // browser polls /result separately), uniform across all live kinds.
        CHECK(h.audited == std::string(c.verb) + "|dispatched|a-1");
    }
}

TEST_CASE("device live process_tree: dual-dispatch (list_tree + connections), joined",
          "[device][routes]") {
    SECTION("run dispatches BOTH the tree and the connections, audited as process_tree") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=process_tree");
        REQUIRE(r);
        CHECK(h.dispatched == 2);
        bool tree = false, conns = false;
        for (const auto& [p, a] : h.seen_dispatches) {
            if (p == "processes" && a == "list_tree") tree = true;
            if (p == "network_diag" && a == "connections") conns = true;
        }
        CHECK(tree);
        CHECK(conns);
        CHECK(h.audited == "device.live.process_tree|dispatched|a-1");
        // The poll URL carries BOTH command ids so the result can join them.
        CHECK(r->body.find("command_id=processes-test") != std::string::npos);
        CHECK(r->body.find("command_id2=network_diag-test") != std::string::npos);
    }
    SECTION("result reconstructs the tree and joins connections by pid") {
        LiveHarness h;
        h.rows_by_cmd["processes-test"] = {
            {"a-1", 1, "proc|4|0|System||\nproc|800|4|svchost.exe|abc123|C:\\\\svchost.exe", ""}};
        h.rows_by_cmd["network_diag-test"] = {
            {"a-1", 1, "conn|tcp|10.0.0.5|52000|140.82.112.4|443|800", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=network_diag-test&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->body.find("svchost.exe") != std::string::npos);
        CHECK(r->body.find("140.82.112.4:443") != std::string::npos); // joined connection chip
        CHECK(r->body.find("abc123") != std::string::npos);           // hash on the node
        CHECK(r->body.find("id=\"ls-kpi-procs\"") != std::string::npos); // OOB process count
    }
    SECTION("a network_diag- secondary id is the ONLY accepted command_id2 prefix") {
        LiveHarness h;
        // A foreign secondary prefix (e.g. tar-) must be rejected.
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=tar-evil&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    SECTION("secondary not ready: tree renders best-effort WITHOUT connections, no re-poll") {
        LiveHarness h;
        // Primary terminal-SUCCESS with output; secondary has no rows yet (empty).
        h.rows_by_cmd["processes-test"] = {{"a-1", 1, "proc|800|4|svchost.exe|abc|", ""}};
        // command_id2 present in the URL but rows_by_cmd has no network_diag-test entry → empty.
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=network_diag-test&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->body.find("svchost.exe") != std::string::npos); // tree still renders
        CHECK(r->body.find("tt-net") == std::string::npos);      // no connection chips (best-effort)
        CHECK(r->body.find("hx-trigger") == std::string::npos);  // primary terminal -> not re-polled
    }
}

// Result-route render coverage for the table kinds (the B1 macOS services field-shape
// divergence + the arp honest-error path were governance Gate-4 findings).
TEST_CASE("device live result: table kinds parse + render", "[device][routes]") {
    SECTION("services Windows 5-field shape: state + running count") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|Spooler|Print Spooler|Running|Automatic\n"
                                  "svc|wuauserv|Windows Update|Stopped|Manual", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("Print Spooler") != std::string::npos);
        CHECK(r->body.find("1 run") != std::string::npos);      // OOB count: 1 running
        CHECK(r->body.find("id=\"ls-kpi-svc\"") != std::string::npos);
    }
    SECTION("services macOS 4-field svc|label|pid|status: State shows status, not PID (B1)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|com.apple.mdworker|1234|running", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("com.apple.mdworker") != std::string::npos);
        CHECK(r->body.find("running") != std::string::npos); // status, from f[3]
        CHECK(r->body.find("1 run") != std::string::npos);   // counted as running (not the PID)
    }
    SECTION("services macOS 5-field svc|label|pid|status|startup: honest startup, PID not the name (C-1.12, P10 fix)") {
        LiveHarness h;
        // A macOS agent's OS is authoritative in production (the device record
        // exists), so drive the OS-authoritative path (K-4) rather than the
        // sniff — which for a 5-field row with an unknown OS now defaults to
        // Windows (UP-5). The fixture is the real macOS shape.
        h.device_os = "darwin";
        // Stopped launchd rows report pid "-" (not a number) per launchctl list's
        // real output -- the fixture must exercise that, not an impossible
        // running-style numeric PID on a stopped row.
        h.fake_rows = {{"a-1", 1, "svc|com.apple.mdworker|1234|running|automatic\n"
                                  "svc|com.example.helper|-|stopped|disabled", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("com.apple.mdworker") != std::string::npos);
        CHECK(r->body.find("com.example.helper") != std::string::npos); // not misrendered as "-"
        CHECK(r->body.find("1234") == std::string::npos); // PID never rendered as the display name
        CHECK(r->body.find("running") != std::string::npos);  // status, from f[3]
        CHECK(r->body.find("automatic") != std::string::npos); // startup, from f[4]
        CHECK(r->body.find("disabled") != std::string::npos);
        CHECK(r->body.find("1 run") != std::string::npos); // only the running row counted
    }
    SECTION("services Windows 5-field with an all-digit display name: OS-authoritative, not PID-sniffed (K-4)") {
        // A Windows service whose display name is purely numeric (e.g. "3389")
        // would trip the content-sniff heuristic into the macOS branch and drop
        // the display name. With the agent's OS known to be Windows, the display
        // name must render.
        LiveHarness h;
        h.device_os = "windows";
        h.fake_rows = {{"a-1", 1, "svc|TermService|3389|Running|Automatic", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("3389") != std::string::npos);   // display name rendered, not dropped
        CHECK(r->body.find("Running") != std::string::npos); // status from f[3]
        CHECK(r->body.find("1 run") != std::string::npos);
    }
    SECTION("services macOS 5-field: OS-authoritative keeps PID out of the name column (K-4)") {
        // The mirror case: OS known to be darwin, a numeric pid must not become
        // the display name even though the sniff would also have got this right.
        LiveHarness h;
        h.device_os = "darwin";
        h.fake_rows = {{"a-1", 1, "svc|com.apple.mdworker|1234|running|automatic", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("com.apple.mdworker") != std::string::npos);
        CHECK(r->body.find("1234") == std::string::npos);   // PID never the display name
        CHECK(r->body.find("automatic") != std::string::npos);
    }
    SECTION("services Linux 4-field svc|name|status|desc: State shows status") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|sshd|running|OpenSSH server", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("sshd") != std::string::npos);
        CHECK(r->body.find("running") != std::string::npos);
        CHECK(r->body.find("1 run") != std::string::npos);
    }
    SECTION("arp non-Windows not_available sentinel -> honest empty-state note, not an error") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "arp|not_available", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=network_config-test"
                            "&agent_id=a-1&kind=arp&n=1");
        REQUIRE(r);
        CHECK(r->body.find("reported an error") == std::string::npos);
        CHECK(r->body.find("not available on this platform") != std::string::npos);
    }
    SECTION("listening rows render with proto/port/pid") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "listen|tcp|0.0.0.0|445|4", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=network_diag-test"
                            "&agent_id=a-1&kind=listening&n=1");
        REQUIRE(r);
        CHECK(r->body.find("445") != std::string::npos);
        CHECK(r->body.find("id=\"ls-kpi-listen\"") != std::string::npos);
    }
    SECTION("disk well-formed line: table + free-% KPI (100 - used)") {
        LiveHarness h;
        // 100 GiB total, 25 GiB free, 75% used.
        h.fake_rows = {{"a-1", 1, "disk|C:\\|107374182400|26843545600|75", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=disk_space-test"
                            "&agent_id=a-1&kind=disk&n=1");
        REQUIRE(r);
        CHECK(r->body.find("id=\"ls-kpi-disk\"") != std::string::npos);
        CHECK(r->body.find("25%") != std::string::npos);       // KPI free% = 100 - 75
        CHECK(r->body.find("100.0 GiB") != std::string::npos); // human()-formatted total
    }
    SECTION("disk: short line skipped; unmeasured total<=0 dashed + off the KPI; bad field zeros") {
        LiveHarness h;
        // line1 (3 fields) -> skipped; line2 total 0 -> dash, excluded from worst-used;
        // line3 non-numeric pct -> zero-default, no crash, drives the KPI.
        h.fake_rows = {{"a-1", 1, "disk|C:\\|123\n"
                                  "disk|D:\\|0|0|0\n"
                                  "disk|/|107374182400|107374182400|x", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=disk_space-test"
                            "&agent_id=a-1&kind=disk&n=1");
        REQUIRE(r);
        CHECK(r->body.find("&mdash;") != std::string::npos);        // D: total 0 -> dash
        CHECK(r->body.find("id=\"ls-cnt-disk\"") != std::string::npos);
        CHECK(r->body.find(">2<") != std::string::npos);            // 2 rows parsed (short line skipped)
    }
}

TEST_CASE("device live capture_sources: tar status -> read-only source table", "[device][routes]") {
    LiveHarness h;
    h.fake_rows = {{"a-1", 1,
                    "config|process_enabled|true\nconfig|process_live_rows|1234\n"
                    "config|arp_enabled|false\nconfig|arp_live_rows|0",
                    ""}};
    auto r = h.sink.Get("/fragments/device/live/result?command_id=tar-test"
                        "&agent_id=a-1&kind=capture_sources&n=1");
    REQUIRE(r);
    CHECK(r->body.find("$Process_Live") != std::string::npos);
    CHECK(r->body.find("1234") != std::string::npos);                  // live-row count
    CHECK(r->body.find("id=\"ls-cnt-capture_sources\"") != std::string::npos); // OOB "X of N on"
    CHECK(r->body.find("/tar") != std::string::npos);                  // configure-on-TAR link
}

// Round-3 item 11: the ten new physical-hardware live kinds share ONE generic
// pipe-row path (live_kinds.hpp LiveKind::columns/.row_prefix -> device_routes.cpp
// render_live_result's `!lk.columns.empty()` branch -> device_ui.cpp
// render_device_live_generic) instead of a bespoke render_device_live_KIND
// function each. hw_disks gets the straightforward well-formed-row case;
// thermal is the one kind whose row width VARIES (the "no zones" shape omits
// celsius), so it gets both shapes exercised explicitly, matching the shared
// renderer's pad-short-rows contract (device_routes.cpp: `f.resize(lk.columns.size())`).
TEST_CASE("device live: physical-hardware generic-table kinds dispatch + render",
          "[device][routes]") {
    SECTION("hw_disks dispatches hardware/disks, audited, polls hardware-<id>") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=hw_disks");
        REQUIRE(r);
        CHECK(h.dispatched == 1);
        CHECK(h.seen_plugin == "hardware");
        CHECK(h.seen_action == "disks");
        CHECK(h.audited == "device.live.hw_disks|dispatched|a-1");
        CHECK(r->body.find("/fragments/device/live/result?command_id=hardware-test") !=
              std::string::npos);
        CHECK(r->body.find("kind=hw_disks") != std::string::npos);
    }
    SECTION("hw_disks result: disk|... row renders index/model/size/media/interface") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "disk|0|Samsung 970 EVO|931|SSD|NVMe", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=hardware-test"
                            "&agent_id=a-1&kind=hw_disks&n=1");
        REQUIRE(r);
        CHECK(r->body.find("<th>Model</th>") != std::string::npos);
        CHECK(r->body.find("<th>Size (GB)</th>") != std::string::npos);
        CHECK(r->body.find("<th>Media</th>") != std::string::npos);
        CHECK(r->body.find("<th>Interface</th>") != std::string::npos);
        // Full row rendered in column order, no padding/truncation (5 fields in,
        // 5 declared columns).
        CHECK(r->body.find("<td>0</td><td>Samsung 970 EVO</td><td>931</td><td>SSD</td>"
                            "<td>NVMe</td>") != std::string::npos);
        CHECK(h.audited == "device.live.hw_disks|rendered|a-1"); // #1703 result-poll audit
    }
    SECTION("hw_disks: a wrong-prefix row is preserved as a raw diagnostic row, "
            "not silently dropped") {
        LiveHarness h;
        // hw_disks' row_prefix is "disk"; a row under any other prefix is not
        // structured data (matching every other kind's
        // `if (!l.starts_with(prefix))` branch), but the original approved design
        // (parse_generic_rows) preserves it verbatim as an honest raw/diagnostic
        // row -- e.g. a plugin emitting a "warning|..."/"error|..." line alongside
        // its data rows -- rather than silently discarding it.
        h.fake_rows = {{"a-1", 1, "wrongprefix|1|2|3", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=hardware-test"
                            "&agent_id=a-1&kind=hw_disks&n=1");
        REQUIRE(r);
        CHECK(r->body.find("<table") != std::string::npos); // a table IS rendered
        // Full raw line text in a full-width (colspan=5, hw_disks' column count)
        // muted diagnostic row -- not parsed into data columns.
        CHECK(r->body.find("<td colspan=\"5\" class=\"gp-mute\">wrongprefix|1|2|3</td>") !=
              std::string::npos);
    }
    SECTION("hw_disks: a well-formed row and a wrong-prefix row both render, "
            "structured row first then the raw row") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1,
                        "disk|0|Samsung 970 EVO|931|SSD|NVMe\nwrongprefix|1|2|3", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=hardware-test"
                            "&agent_id=a-1&kind=hw_disks&n=1");
        REQUIRE(r);
        const auto structured_pos =
            r->body.find("<td>0</td><td>Samsung 970 EVO</td><td>931</td><td>SSD</td>"
                         "<td>NVMe</td>");
        const auto raw_pos =
            r->body.find("<td colspan=\"5\" class=\"gp-mute\">wrongprefix|1|2|3</td>");
        CHECK(structured_pos != std::string::npos);
        CHECK(raw_pos != std::string::npos);
        CHECK(structured_pos < raw_pos); // structured rows render before raw rows
    }
    SECTION("thermal dispatches power_health/thermal, audited, polls power_health-<id>") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=thermal");
        REQUIRE(r);
        CHECK(h.seen_plugin == "power_health");
        CHECK(h.seen_action == "thermal");
        CHECK(h.audited == "device.live.thermal|dispatched|a-1");
        CHECK(r->body.find("/fragments/device/live/result?command_id=power_health-test") !=
              std::string::npos);
        CHECK(r->body.find("kind=thermal") != std::string::npos);
    }
    SECTION("thermal full 3-field shape (status|zone|celsius) renders every column") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "thermal|ok|CPU|45.2", ""}};
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/device/live/result?command_id=power_health-test"
                                     "&agent_id=a-1&kind=thermal&n=1"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("<td>ok</td><td>CPU</td><td>45.2</td>") != std::string::npos);
        CHECK(r->body.find("gp-mute") == std::string::npos); // every column populated, no dash
    }
    SECTION("thermal short 2-field shape (no zones) pads celsius as a blank cell, "
            "not a truncated row or an exception") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "thermal|unavailable|pdh_query_failed", ""}};
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/device/live/result?command_id=power_health-test"
                                     "&agent_id=a-1&kind=thermal&n=1"));
        REQUIRE(r);
        CHECK(r->status == 200);
        // Still a full 3-cell row -- the missing celsius field is a blank/em-dash
        // cell, never a 2-cell truncated row.
        CHECK(r->body.find("<td>unavailable</td><td>pdh_query_failed</td>"
                            "<td><span class=\"gp-mute\">&mdash;</span></td>") !=
              std::string::npos);
    }
}

// The DEX/Guardian device lenses render per-device behavioral/compliance PII, so
// they must gate GuaranteedState:Read and audit-on-open (parity with the sibling
// /fragments/dex/device). Governance Gate-2/3/4 BLOCKING.
// (The DEX/Guardian device-lens "Read-gated + audited on open" coverage moved
// to test_device_lens_routes.cpp — DeviceLensRoutes, split out of DeviceRoutes
// by ADR-0031 WS-A4 wave 2.)

// SCOPE-ESCAPE regression (governance Gate-2/4 BLOCKING; both adversarial reviewers
// found it independently). Every per-device route must refuse a device OUTSIDE the
// caller's management scope: not listed, not openable, and — the load-bearing
// security property — NO live command dispatched to it. (The DEX-lens leg of this
// regression moved to test_device_lens_routes.cpp alongside the lens routes.)
// scoped_perm_fn_ is the chokepoint (here it denies "other-team", allows "mine");
// the list is scoped by visible_set_fn_ over the API's unscoped rows.
TEST_CASE("device routes: out-of-scope device is not listed/openable/live-queryable",
          "[device][routes][scope]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    // Global Infrastructure:Read (the list gate) is granted.
    auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    // Management-group scope: every op allowed EXCEPT on the out-of-scope agent.
    // "ancestor-child" is authorized (a parent-group role grants it) but is NOT in
    // the flat scoped LIST below — modelling the ancestor-walk divergence.
    auto scoped_perm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                          const std::string&, const std::string& agent_id) {
        if (agent_id == "other-team") { res.status = 403; return false; }
        return true;
    };
    // The API's list_devices() is UNSCOPED (both "mine" and "other-team" resolve);
    // visible_set_fn_ below is this test's OWN confinement filter, matching a flat
    // get_visible_agents JOIN with no ancestor walk — "ancestor-child" is absent
    // from it even though scoped_perm authorizes it (an ancestor-group role).
    auto api = std::make_shared<FakeDeviceApi>();
    api->rows = {DeviceListRow{.agent_id = "mine", .hostname = "mine-host"},
                DeviceListRow{.agent_id = "other-team", .hostname = "other-host"}};
    // The point lookup resolves the identity row for any connected device (authz
    // is scoped_perm, applied first) — incl. the ancestor-authorized one.
    api->details["mine"] = DeviceDetail{.row = {.agent_id = "mine", .hostname = "mine-host"}};
    api->details["ancestor-child"] =
        DeviceDetail{.row = {.agent_id = "ancestor-child", .hostname = "ancestor-child-host"}};
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string& plugin, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&)
        -> yuzu::server::ConfinedDispatchOutcome {
        ++dispatched;
        return {.sent = 1, .command_id = plugin + "-x"};
    };
    auto responses = [](const std::string&, const std::string&) {
        return std::vector<DexAgentResponse>{};
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceRoutes routes;
    routes.register_routes(sink, okAuth, perm, scoped_perm, api, fixed_scope({"mine"}), {},
                           dispatch, responses, {});

    SECTION("list shows only the caller's visible device") {
        auto r = sink.Get("/fragments/devices/list");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("mine-host") != std::string::npos);
        CHECK(r->body.find("other-team") == std::string::npos);
    }
    SECTION("out-of-scope device page is 403, not opened") {
        auto r = sink.Get("/fragments/device/page?id=other-team");
        REQUIRE(r);
        CHECK(r->status == 403);
    }
    SECTION("out-of-scope live dispatch is refused — NO command sent") {
        auto r = sink.Get("/fragments/device/live/run?id=other-team&kind=processes");
        REQUIRE(r);
        CHECK(dispatched == 0); // the security property: no cross-scope dispatch
        CHECK(r->status == 403);
    }
    SECTION("in-scope device stays openable + live-queryable") {
        auto pg = sink.Get("/fragments/device/page?id=mine");
        REQUIRE(pg);
        CHECK(pg->status == 200);
        auto run = sink.Get("/fragments/device/live/run?id=mine&kind=uptime");
        REQUIRE(run);
        CHECK(dispatched == 1); // in-scope dispatch proceeds
    }
    // Ancestor-authz regression: a device authorized by scoped_perm (e.g. via a
    // parent-group role) but ABSENT from the flat scoped list must still open — the
    // page row comes from the UNSCOPED point lookup post-authz, not a re-scoped
    // list scan.
    SECTION("ancestor-authorized device opens via unscoped lookup though not in the list") {
        auto pg = sink.Get("/fragments/device/page?id=ancestor-child");
        REQUIRE(pg);
        CHECK(pg->status == 200);
        CHECK(pg->body.find("ancestor-child-host") != std::string::npos); // row rendered
        // ...and it is NOT in the scoped list (proves list scoping is independent).
        auto list = sink.Get("/fragments/devices/list");
        REQUIRE(list);
        CHECK(list->body.find("ancestor-child") == std::string::npos);
    }
}

// SEC-2/SEC-3 confinement-gap class (found during a docs sweep): the fleet-wide
// list must deny a service-scoped API token whose principal resolves to an
// unscoped grant BEFORE any device data is read — the full device roster would
// still be fleet-wide otherwise.
TEST_CASE("device routes: /fragments/devices/list denies a service-scoped "
          "token, denial audited",
          "[device][routes][security]") {
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    auto api = std::make_shared<FakeDeviceApi>();
    api->rows = {DeviceListRow{.agent_id = "mine", .hostname = "mine-host"}};
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };
    DeviceRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, perm, /*scoped_perm_fn=*/{}, api,
                           /*visible_set_fn=*/{}, /*dex_score_fn=*/{}, /*dispatch_fn=*/{},
                           /*responses_fn=*/{}, audit);

    auto r = sink.Get("/fragments/devices/list");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(r->body.find("mine-host") == std::string::npos);
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto body = nlohmann::json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(r->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    REQUIRE(audit_log.size() == 1);
    CHECK(audit_log[0] == "device.list.view|denied");
}

// Round-3 merge: /devices and /device?id= are retired in favour of the Hardware CI
// list/record (302, not route removal — bookmarks and the API-parity ledger's
// history stay intact). The DEX/Guardian bare=1 tab-bar-suppression coverage moved
// to test_device_lens_routes.cpp alongside the lens routes.
TEST_CASE("device routes: /devices + /device redirect to Hardware CI",
          "[device][routes]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto noAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(std::nullopt);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };
    auto noApi = std::make_shared<FakeDeviceApi>();

    SECTION("GET /devices while authed -> 302 /hardware") {
        yuzu::server::test::TestRouteSink sink;
        DeviceRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okScoped, noApi);
        auto r = sink.Get("/devices");
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/hardware");
    }
    SECTION("GET /devices while UNauthed -> 302 /login (auth_fn_ runs first)") {
        yuzu::server::test::TestRouteSink sink;
        DeviceRoutes routes;
        routes.register_routes(sink, noAuth, okPerm, okScoped, noApi);
        auto r = sink.Get("/devices");
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/login");
    }
    SECTION("GET /device?id=a-1 while authed -> 302 /hardware/ci?id=a-1") {
        yuzu::server::test::TestRouteSink sink;
        DeviceRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okScoped, noApi);
        auto r = sink.Get("/device?id=a-1");
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/hardware/ci?id=a-1");
    }
    SECTION("GET /device?id=<space/#> -> Location percent-encodes it") {
        yuzu::server::test::TestRouteSink sink;
        DeviceRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okScoped, noApi);
        // Sent pre-encoded (a raw space/'#' in a URL is themselves ambiguous);
        // TestRouteSink's parse_query_text decodes it to "a 1#b" exactly as
        // httplib::Server would, so the assertion below exercises the SAME
        // re-encoding step device_routes.cpp runs in production: alnum/
        // -/_/./~ pass through literal, everything else becomes uppercase %XX.
        auto r = sink.Get("/device?id=a%201%23b");
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/hardware/ci?id=a%201%23b");
    }
    SECTION("GET /device with no id -> 302 /hardware/ci (no ?id= suffix)") {
        yuzu::server::test::TestRouteSink sink;
        DeviceRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, okScoped, noApi);
        auto r = sink.Get("/device");
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/hardware/ci");
    }
}
