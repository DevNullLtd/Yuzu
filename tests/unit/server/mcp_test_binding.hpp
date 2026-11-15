#pragma once

// Shared MCP session-binding fixture for the registry, stream and bridge tests.
//
// `bound()` builds a binding that carries ONLY the principal (an empty credential class).
// McpSessionBinding is an aggregate, so this compiles by design; it is the right fixture
// for tests of principal-keyed behaviour (caps, TTL, ring, pumps). It proves nothing about
// the class dimension: a test of that builds an McpSessionBinding explicitly (see the
// class-bearing fixtures in test_mcp_session.cpp and test_mcp_stream_bridge.cpp), and
// test_mcp_server.cpp keeps its own production-shaped helpers.

#include "../../../server/core/src/mcp_session.hpp"

#include <string>
#include <utility>

namespace yuzu::test::mcp_session {

[[nodiscard]] inline yuzu::server::mcp::McpSessionBinding bound(std::string principal) {
    return yuzu::server::mcp::McpSessionBinding{.principal = std::move(principal)};
}

}  // namespace yuzu::test::mcp_session
