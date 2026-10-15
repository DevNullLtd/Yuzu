/// @file test_mcp_route_registration.cpp
/// Registration-shape coverage for McpServer's HttpRouteSink seam (#2542 PR-6)
/// -- driven in-process through TestRouteSink (no httplib acceptor, #438).
///
/// This file deliberately does NOT re-test JSON-RPC handler behaviour --
/// that is already exhaustively covered in test_mcp_server.cpp via
/// McpServer::build_handler()/build_get_handler()/build_delete_handler()
/// called directly (bypassing route registration entirely). What was NOT
/// covered anywhere before this file: that
/// McpServer::register_routes(HttpRouteSink&, ...) actually WIRES those
/// handlers onto GET/POST/DELETE /mcp/v1/ -- a regression that dropped one
/// of the three sink.{Get,Post,Delete} calls (or mis-registered the path)
/// would leave every test_mcp_server.cpp case green while the real server
/// 404s the route. This is the same class of gap #2542 PR-4's
/// custom_properties_routes.cpp wiring tripwire closed for that module --
/// see this file's own tripwire case at the bottom, generalizing the
/// pattern across the campaign per #4078.
///
/// Coverage:
///   - register_routes(HttpRouteSink&, ...) registers exactly 3 routes:
///     GET/POST/DELETE /mcp/v1/.
///   - The --mcp-disable kill switch answers on all three verbs BEFORE
///     auth_fn (and therefore before any RBAC check) ever runs -- the
///     standing kill-switch-before-auth ordering invariant (the rejection
///     itself is docs/mcp-server.md's "Kill switch" bullet; the specific
///     before-auth ordering is CLAUDE.md's MCP routed concern) -- proven
///     end-to-end through the REGISTERED sink dispatch, not just at the
///     handler-construction level test_mcp_server.cpp
///     already covers.
///   - A non-vacuousness check: with the kill switch off, every verb is
///     still reachable (405/reaches auth_fn), so the disabled-path
///     assertions above are not trivially true because the route simply
///     isn't wired at all.
///   - Wiring tripwire: server.cpp still calls `mcp_server_->register_routes(`.
///
/// Every dependency register_routes() takes beyond auth_fn/perm_fn/audit_fn/
/// agents_fn is nullptr/default here (mirrors how test_mcp_server.cpp's own
/// McpTestServer wires McpServer::build_handler()'s trailing store params in
/// tests that don't need them) -- safe with the kill switch ON because the
/// mcp_disabled gate itself is checked before any of those dependencies is
/// ever touched, and safe in the non-vacuousness case (kill switch OFF, see
/// below) because GET/DELETE stop at the sessions==nullptr 405 gate and POST
/// stops at auth_fn's 401 -- neither path reaches a store pointer either.

#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::mcp;
using json = nlohmann::json;

namespace {

/// Minimal registration-shape harness. Declaration order: `sink` LAST
/// (CLAUDE.md / test_route_sink.hpp convention) -- the registered handlers
/// capture `mcp` and this struct's callback lambdas by value, so `mcp` must
/// outlive `sink`.
struct Harness {
    McpServer mcp;

    bool mcp_disabled{false};
    bool read_only_mode{false};

    bool auth_called{false};
    bool audit_called{false};

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        McpServer::AuthFn auth_fn = [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<auth::Session> {
            auth_called = true;
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
            return std::nullopt;
        };
        McpServer::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&) -> bool {
            return true;
        };
        McpServer::AuditFn audit_fn = [this](const httplib::Request&, const std::string&,
                                             const std::string&, const std::string&,
                                             const std::string&, const std::string&) -> bool {
            audit_called = true;
            return true;
        };
        McpServer::AgentsJsonFn agents_fn = []() -> json { return json::array(); };

        mcp.register_routes(sink, auth_fn, perm_fn, audit_fn, agents_fn,
                            /*rbac_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*response_store=*/nullptr,
                            /*audit_store=*/nullptr, /*tag_store=*/nullptr,
                            /*inventory_store=*/nullptr, /*policy_store=*/nullptr,
                            /*mgmt_store=*/nullptr, /*approval_manager=*/nullptr,
                            /*schedule_engine=*/nullptr, read_only_mode, mcp_disabled);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("mcp route registration: register_routes(HttpRouteSink&) registers exactly 3 "
          "routes -- GET/POST/DELETE /mcp/v1/",
          "[server][routes][mcp]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);

    auto routes = h.sink.registered_routes();
    auto has = [&](const std::string& method) {
        return std::find(routes.begin(), routes.end(),
                         std::make_pair(method, std::string("/mcp/v1/"))) != routes.end();
    };
    CHECK(has("GET"));
    CHECK(has("POST"));
    CHECK(has("DELETE"));
}

// ── Kill-switch-before-auth ordering (the standing invariant) ─────────────

TEST_CASE("mcp route registration: --mcp-disable answers GET before auth_fn runs",
          "[server][routes][mcp]") {
    Harness h;
    h.mcp_disabled = true;
    h.wire();

    auto res = h.sink.Get("/mcp/v1/");
    REQUIRE(res != nullptr);
    CHECK_FALSE(h.auth_called);
    CHECK_FALSE(h.audit_called);
    auto body = json::parse(res->body);
    CHECK(body["error"]["code"] == kMcpDisabled);
}

TEST_CASE("mcp route registration: --mcp-disable answers DELETE before auth_fn runs",
          "[server][routes][mcp]") {
    Harness h;
    h.mcp_disabled = true;
    h.wire();

    auto res = h.sink.Delete("/mcp/v1/");
    REQUIRE(res != nullptr);
    CHECK_FALSE(h.auth_called);
    CHECK_FALSE(h.audit_called);
    auto body = json::parse(res->body);
    CHECK(body["error"]["code"] == kMcpDisabled);
}

TEST_CASE("mcp route registration: --mcp-disable answers POST before auth_fn runs",
          "[server][routes][mcp]") {
    Harness h;
    h.mcp_disabled = true;
    h.wire();

    auto res = h.sink.Post("/mcp/v1/", R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res != nullptr);
    CHECK_FALSE(h.auth_called);
    CHECK_FALSE(h.audit_called);
    auto body = json::parse(res->body);
    CHECK(body["error"]["code"] == kMcpDisabled);
}

// ── Non-vacuousness: the disabled-path checks above are not trivially true
//    because the route simply isn't wired ──────────────────────────────────

TEST_CASE("mcp route registration: an ENABLED server still reaches its next gate on "
          "every verb (proves the disabled-path checks above are not vacuous)",
          "[server][routes][mcp]") {
    Harness h;
    h.mcp_disabled = false;
    h.wire();

    SECTION("GET") {
        // No McpSessionRegistry wired here -> streaming is off -> the GET
        // handler 405s at the very next gate, before auth_fn. A registration
        // regression that dropped this route from the sink would return
        // nullptr (no match), not a real 405 -- so this still distinguishes
        // "registered but streaming off" from "not registered".
        auto res = h.sink.Get("/mcp/v1/");
        REQUIRE(res != nullptr);
        CHECK(res->status == 405);
    }
    SECTION("DELETE") {
        auto res = h.sink.Delete("/mcp/v1/");
        REQUIRE(res != nullptr);
        CHECK(res->status == 405);
    }
    SECTION("POST") {
        // POST does not gate on the session registry the way GET/DELETE do
        // (streaming-off POST is the pre-2f stateless path), so it reaches
        // auth_fn directly.
        auto res = h.sink.Post("/mcp/v1/", R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
        REQUIRE(res != nullptr);
        CHECK(h.auth_called);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_routes()'s OWN handlers
// are correctly wired to a sink, but nothing above reads server.cpp -- a
// future edit that drops the production `mcp_server_->register_routes(...)`
// call at server.cpp's registration site would leave every case above green
// while the real server 404s all three /mcp/v1/ verbs. Same pattern as
// test_custom_properties_routes.cpp's tripwire (#2542 PR-4), generalized to
// this module per #4078.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("mcp route registration: wiring -- server.cpp still calls "
          "mcp_server_->register_routes",
          "[server][routes][mcp]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("mcp_server_->register_routes(") != std::string::npos);
}

// The handler tests in test_mcp_server.cpp call these two setters themselves, so
// deleting either production line would leave every one of them green while the real
// server answers "unavailable" for list_deployments / get_deployment (deployment run
// store) or list_discovered_devices (discovery reader). Same source-text tripwire as
// above; both setters must also precede register_routes, which freezes the handlers.
// A call that has been commented out must not count, so only a call that begins its
// line (leading whitespace only) is a live one.
namespace {
std::size_t find_live_call(const std::string& src, const std::string& call) {
    for (auto at = src.find(call); at != std::string::npos; at = src.find(call, at + 1)) {
        const auto bol = src.rfind('\n', at);
        const auto from = bol == std::string::npos ? 0 : bol + 1;
        if (src.find_first_not_of(" \t", from) == at)
            return at;
    }
    return std::string::npos;
}
} // namespace

TEST_CASE("mcp route registration: wiring -- server.cpp wires the software sync runner before "
          "register_routes",
          "[server][routes][mcp]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto reg = find_live_call(src, "mcp_server_->register_routes(");
    const auto run =
        find_live_call(src, "mcp_server_->set_software_sync_runner(software_sync_runner())");
    REQUIRE(reg != std::string::npos);
    REQUIRE(run != std::string::npos);
    CHECK(run < reg);
}

// The fleet "Sync now" composition cannot be built in a unit test (it lives in ServerImpl), so the
// two guarantees the unit tests cannot see are pinned on the source: (1) the Runner's send goes
// through the dispatch_confined_arms system-reserved arm, so reach is decided by the seam; (2) REST
// and MCP receive the SAME memoised Runner, so one cooldown and one in-flight lease bind both.
TEST_CASE("mcp route registration: wiring -- the sync runner is one shared instance whose send goes "
          "through the confined-dispatch seam",
          "[server][routes][mcp]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    // (1) the Runner env dispatches via push_sync_now_confined, which calls the seam helper.
    CHECK(find_live_call(src, "return push_sync_now_confined(") != std::string::npos);
    const auto confined = find_live_call(src, "push_sync_now_confined(const auth::Session& sess");
    REQUIRE(confined != std::string::npos);
    // The helper call sits inside push_sync_now_confined, before the next member function.
    const auto seam = src.find("yuzu::server::dispatch_system_reserved_ids(", confined);
    REQUIRE(seam != std::string::npos);
    CHECK(seam - confined < 2500);
    // (2) one memoised runner handed to both surfaces.
    CHECK(find_live_call(src, "if (!sync_runner_) {") != std::string::npos);
    CHECK(find_live_call(src, ".sync_runner = software_sync_runner()") != std::string::npos);
    CHECK(find_live_call(src, "mcp_server_->set_software_sync_runner(software_sync_runner())") !=
          std::string::npos);
    // Exactly one construction site: a second would be a second cooldown.
    const auto first = src.find("software_sync::Runner>(std::move(env))");
    REQUIRE(first != std::string::npos);
    CHECK(src.find("software_sync::Runner>(std::move(env))", first + 1) == std::string::npos);
}

TEST_CASE("mcp route registration: wiring -- server.cpp wires the deployment store and "
          "the discovery reader before register_routes",
          "[server][routes][mcp]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto reg = find_live_call(src, "mcp_server_->register_routes(");
    const auto dep =
        find_live_call(src, "mcp_server_->set_deployment_run_store(deployment_run_store_.get())");
    const auto disc =
        find_live_call(src, "mcp_server_->set_discovered_devices_reader(discovered_reader)");
    REQUIRE(reg != std::string::npos);
    REQUIRE(dep != std::string::npos);
    REQUIRE(disc != std::string::npos);
    CHECK(dep < reg);
    CHECK(disc < reg);
}
