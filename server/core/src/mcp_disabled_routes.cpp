#include "mcp_disabled_routes.hpp"

#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp"

namespace yuzu::server::mcp_disabled {

void register_mcp_disabled_routes(HttpRouteSink& sink) {
    // C8: Return a proper JSON-RPC error instead of a generic 404.
    // CH-7(c): the disabled stub must ANSWER GET/DELETE too (not a bare
    // 404), so Streamable HTTP probes get the same honest disabled error.
    auto mcp_disabled_stub = [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Content-Type", "application/json");
        res.set_content(
            mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"),
            "application/json");
    };
    sink.Post("/mcp/v1/", mcp_disabled_stub);
    sink.Get("/mcp/v1/", mcp_disabled_stub);
    sink.Delete("/mcp/v1/", mcp_disabled_stub);
}

} // namespace yuzu::server::mcp_disabled
