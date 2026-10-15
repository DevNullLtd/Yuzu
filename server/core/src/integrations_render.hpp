#pragma once

/// @file integrations_render.hpp
/// Pure renderers and the MCP settings form parser for the System "Integrations" page.
///
/// The MCP and Gateway panels are existing fragments (`GET /fragments/settings/mcp`,
/// `GET /fragments/settings/gateway`, ids `#mcp-section` / `#gateway-section`); their
/// markup is rebuilt here on `yuzu.css` classes only, so it renders identically on the new
/// page and on the `/settings` monolith that still hosts the same two URLs. Both take
/// plain view structs (built by `SettingsRoutes` from the shared `settings_model` builders)
/// so a test feeds fixtures and needs no `Config` or route.
///
/// The parser is the one place the MCP POST body is read. It parses at a key boundary and
/// refuses a body that omits, repeats or mangles `enabled` / `read_only`: the previous
/// handler took the first match and treated an absent field as `false`, so a partial body
/// silently switched MCP off or flipped Read-only to Full access.

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace yuzu::server::integrations {

struct McpView {
    bool enabled{false};
    bool read_only{false};
    std::string endpoint_url;
};

struct GatewayView {
    bool enabled{false};
    std::string listen_address;
    bool gateway_mode{false};
    std::int64_t active_sessions{0};
};

/// The three Save confirms (one per resulting state). Emitted as data attributes on the
/// form, so the page script holds no policy text and tests pin them here.
inline constexpr std::string_view kMcpConfirmFull =
    "Allow agentic workers to run write and execute tools? Anyone holding an operator or "
    "supervised MCP token can change the fleet. This stays in effect until the server restarts.";
inline constexpr std::string_view kMcpConfirmReadOnly =
    "Turn the MCP endpoint on in read-only mode? Agentic workers with an MCP token can read "
    "fleet data but cannot run write or execute tools. This stays in effect until the server "
    "restarts.";
inline constexpr std::string_view kMcpConfirmOff =
    "Stop the MCP endpoint? Connected agentic workers are refused immediately. This stays in "
    "effect until the server restarts.";
/// What the form's own `hx-confirm` asks where the page script is not loaded (`/settings`).
inline constexpr std::string_view kMcpConfirmGeneric =
    "Save the MCP settings? Turning MCP on, or choosing Full access, lets agentic workers with "
    "a write-tier token change the fleet; turning it off refuses connected workers immediately. "
    "The change stays in effect until the server restarts.";

/// The MCP fragment body: status, endpoint, the settings form, caveats and the client
/// connection note. One control per field and no hidden fallback input, so a submit always
/// carries exactly one `enabled` and one `read_only`.
std::string render_mcp_panel(const McpView& v);

/// The Gateway fragment body: read-out rows, the not-running flag guidance, and the
/// environment-variable reference (collapsed).
std::string render_gateway_panel(const GatewayView& v);

struct McpForm {
    bool enabled{false};
    bool read_only{false};
};

/// Parse a URL-encoded `POST /api/settings/mcp` body. Each of `enabled` and `read_only`
/// must appear exactly once with the value `true` or `false`; anything else is an error
/// whose text is safe to return to the caller.
std::expected<McpForm, std::string> parse_mcp_form(std::string_view body);

} // namespace yuzu::server::integrations
