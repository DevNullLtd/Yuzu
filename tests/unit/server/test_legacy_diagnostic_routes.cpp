/**
 * test_legacy_diagnostic_routes.cpp — route-handler coverage for the
 * 5-route Chargen + Procfetch diagnostic API (`diagnostics_routes.{hpp,cpp}`,
 * #2542 PR-12), driven in-process through TestRouteSink (no httplib
 * acceptor, #438).
 *
 * NAMED AWAY FROM `test_diagnostics_*`/`test_chargen_*`/`test_procfetch_*`
 * DELIBERATELY: `tools/plugin-doc-gen/plugin_doc_gen.py`'s test-discovery
 * heuristic (`collect_source`) associates a test file with an AGENT PLUGIN
 * by filename prefix alone (`p.name.startswith(f"test_{name}")`) — and
 * `agents/plugins/{chargen,procfetch,diagnostics}/` are three real,
 * unrelated agent plugins. A `test_diagnostics_routes.cpp` name here would
 * false-positive-associate this SERVER route-handler test with the AGENT
 * diagnostics plugin's generated README/plugin-doc JSON (confirmed: this
 * exact collision reddened the `docs` suite's `plugin readme gate` during
 * this PR's own verification). `chargen`/`procfetch` themselves aren't in
 * the filename at all for the same reason.
 *
 * `forward_legacy_command` itself stays a `ServerImpl`-private member in
 * server.cpp (see diagnostics_routes.hpp's header comment for why) — this
 * file therefore tests `register_diagnostics_routes`' OWN contract: the
 * gate pinning (start/stop/fetch -> Execution:Execute, both status routes
 * -> Infrastructure:Read), that `forward_legacy_command_fn` is invoked with
 * exactly the right (plugin, action) pair for each of the 3 POST routes and
 * NOT invoked when perm_fn denies, and that the two GET status routes
 * reflect `deps.registry->has_any()` verbatim. No Postgres needed anywhere
 * in this module.
 */

#include "diagnostics_routes.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using json = nlohmann::json;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

json body(const std::string& s) { return json::parse(s); }

agent_pb::AgentInfo make_agent_info(const std::string& id) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname("test-host");
    a.mutable_platform()->set_os("linux");
    a.mutable_platform()->set_arch("x86_64");
    a.set_agent_version("0.13.0");
    return a;
}

struct ForwardCall {
    std::string plugin, action;
};

/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    std::vector<ForwardCall> forward_calls;
    int forward_status{200};
    std::string forward_body{R"({"command_id":"cmd-1"})"};

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        diagnostics::Deps deps;
        deps.registry = &registry;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            perm_calls.push_back({type, op});
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.forward_legacy_command_fn = [this](const httplib::Request&,
                                                const std::string& plugin,
                                                const std::string& action,
                                                httplib::Response& res) {
            forward_calls.push_back({plugin, action});
            res.status = forward_status;
            res.set_content(forward_body, "application/json");
        };
        diagnostics::register_diagnostics_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("diagnostics_routes: registers exactly 5 routes",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 5);
}

// ── Gate pinning + forward-dispatch args, per route ─────────────────────

TEST_CASE("diagnostics_routes: POST /api/chargen/start gates on Execution:Execute and "
          "forwards plugin=chargen action=chargen_start",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/api/chargen/start", "{}");
    REQUIRE(res);
    CHECK(res->status == h.forward_status);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Execution", "Execute"});
    REQUIRE(h.forward_calls.size() == 1);
    CHECK(h.forward_calls[0].plugin == "chargen");
    CHECK(h.forward_calls[0].action == "chargen_start");
}

TEST_CASE("diagnostics_routes: POST /api/chargen/stop gates on Execution:Execute and "
          "forwards plugin=chargen action=chargen_stop",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/api/chargen/stop", "{}");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Execution", "Execute"});
    REQUIRE(h.forward_calls.size() == 1);
    CHECK(h.forward_calls[0].plugin == "chargen");
    CHECK(h.forward_calls[0].action == "chargen_stop");
}

TEST_CASE("diagnostics_routes: POST /api/procfetch/fetch gates on Execution:Execute and "
          "forwards plugin=procfetch action=procfetch_fetch",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/api/procfetch/fetch", "{}");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Execution", "Execute"});
    REQUIRE(h.forward_calls.size() == 1);
    CHECK(h.forward_calls[0].plugin == "procfetch");
    CHECK(h.forward_calls[0].action == "procfetch_fetch");
}

TEST_CASE("diagnostics_routes: a perm_fn denial on a POST route 403s and never calls "
          "forward_legacy_command_fn",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Post("/api/chargen/start", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.forward_calls.empty());
}

TEST_CASE("diagnostics_routes: GET /api/chargen/status gates on Infrastructure:Read and "
          "reflects registry->has_any()",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();

    auto res_empty = h.sink.Get("/api/chargen/status");
    REQUIRE(res_empty);
    CHECK(res_empty->status == 200);
    CHECK(body(res_empty->body)["agent_connected"] == false);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Read"});

    (void)h.registry.register_agent(make_agent_info("agent-1"));
    auto res_present = h.sink.Get("/api/chargen/status");
    REQUIRE(res_present);
    CHECK(body(res_present->body)["agent_connected"] == true);
}

TEST_CASE("diagnostics_routes: GET /api/procfetch/status gates on Infrastructure:Read and "
          "reflects registry->has_any()",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.wire();

    auto res_empty = h.sink.Get("/api/procfetch/status");
    REQUIRE(res_empty);
    CHECK(res_empty->status == 200);
    CHECK(body(res_empty->body)["agent_connected"] == false);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Infrastructure", "Read"});

    (void)h.registry.register_agent(make_agent_info("agent-1"));
    auto res_present = h.sink.Get("/api/procfetch/status");
    REQUIRE(res_present);
    CHECK(body(res_present->body)["agent_connected"] == true);
}

TEST_CASE("diagnostics_routes: a perm_fn denial on a GET status route 403s",
          "[server][routes][diagnostics_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Get("/api/chargen/status");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("diagnostics_routes: wiring -- server.cpp still calls register_diagnostics_routes",
          "[server][routes][diagnostics_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_diagnostics_routes(") != std::string::npos);
}
