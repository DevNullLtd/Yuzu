/**
 * test_mcp_disabled_routes.cpp — route-handler coverage for the 3-route
 * MCP-disabled stub triple (#2542 PR-12), driven in-process through
 * TestRouteSink (no httplib acceptor, #438).
 *
 * The handler is a single stateless lambda registered under all three
 * verbs, so "the authorization gate" this module exercises (per #2542's
 * acceptance criteria) is the ABSENCE of one — every caller, authenticated
 * or not, gets the identical honest-disabled JSON-RPC error (C8/CH-7(c)).
 * No Postgres, no Deps struct, no mock closures needed anywhere in this
 * module.
 */

#include "mcp_disabled_routes.hpp"
#include "mcp_jsonrpc.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <string>

using namespace yuzu::server;

namespace {

struct Harness {
    yuzu::server::test::TestRouteSink sink;
    void wire() { mcp_disabled::register_mcp_disabled_routes(sink); }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("mcp_disabled_routes: registers exactly 3 routes",
          "[server][routes][mcp_disabled_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 3);
}

// ── All three verbs answer the identical honest-disabled JSON-RPC error ──

TEST_CASE("mcp_disabled_routes: POST /mcp/v1/ answers a kMcpDisabled JSON-RPC error, not a "
          "generic 404",
          "[server][routes][mcp_disabled_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/mcp/v1/", R"({"jsonrpc":"2.0","method":"initialize","id":1})");
    REQUIRE(res);
    CHECK(res->get_header_value("Content-Type") == "application/json");
    CHECK(res->body ==
          mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"));
}

TEST_CASE("mcp_disabled_routes: GET /mcp/v1/ (Streamable HTTP probe) answers the same "
          "honest-disabled error, not a bare 404 (CH-7(c))",
          "[server][routes][mcp_disabled_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Get("/mcp/v1/");
    REQUIRE(res);
    CHECK(res->body ==
          mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"));
}

TEST_CASE("mcp_disabled_routes: DELETE /mcp/v1/ (Streamable HTTP probe) answers the same "
          "honest-disabled error, not a bare 404 (CH-7(c))",
          "[server][routes][mcp_disabled_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Delete("/mcp/v1/");
    REQUIRE(res);
    CHECK(res->body ==
          mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire. NOTE: unlike every other #2542 PR-12 module, this call is
// CONDITIONAL (`if (cfg_.mcp_disable) { ... }` in server.cpp) -- the
// production call site is still a plain source-text match here, same
// contract as every sibling tripwire; the conditionality itself is not
// (and cannot be) exercised by a source-text grep.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("mcp_disabled_routes: wiring -- server.cpp still calls "
          "register_mcp_disabled_routes",
          "[server][routes][mcp_disabled_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_mcp_disabled_routes(") != std::string::npos);
}
