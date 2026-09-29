#pragma once

#include <string>
#include <string_view>
#include <vector>

// MCP Streamable HTTP transport helpers (ADR-1005 Decision 15, track 2f).
//
// Pure, dependency-free predicates used by the /mcp/v1/ POST/GET/DELETE
// handlers for spec-mandated transport pre-checks. Deliberately free of
// httplib / auth / store types so they are unit-testable in isolation
// (tests/unit/server/test_mcp_transport.cpp).
namespace yuzu::server::mcp::transport {

// Protocol revision assumed when the `MCP-Protocol-Version` header is absent
// (MCP spec: absent → 2025-03-26).
inline constexpr std::string_view kProtocolDefault = "2025-03-26";

// True if `version` is an MCP protocol revision this server supports.
// The supported set is {2025-03-26, 2025-06-18}; an empty/absent value is NOT
// this function's concern (callers treat absent as kProtocolDefault before
// calling — a present-but-unsupported header is a 400).
bool protocol_version_supported(std::string_view version);

// Origin validation — DNS-rebinding defence (MCP spec MUST).
//   - absent Origin (empty string) → allowed. Non-browser MCP clients send no
//     Origin; the per-request auth credential is what actually defeats
//     rebinding, so an absent Origin on a credential-gated endpoint is safe.
//   - present Origin → allowed only on an exact match against an allowlist
//     entry (scheme+host+port compared verbatim, no heuristics).
//   - an EMPTY allowlist rejects every *present* Origin — the secure default.
//     Browser-based MCP clients require an explicit `--mcp-allowed-origin`.
bool origin_allowed(std::string_view origin, const std::vector<std::string>& allowlist);

// True if the client `Accept` header opts into a Server-Sent-Events response,
// i.e. lists `text/event-stream` as a whole media range (case-insensitive,
// `;`-parameters and OWS ignored) — NOT a bare substring, so
// `application/json; q=text/event-stream` and `not-text/event-stream` do not
// match. The `,` split honours RFC 9110 quoted-strings (#2073), so a comma
// inside a quoted parameter value cannot forge a match; an unterminated quote
// fails closed. Wildcards (`*/*`, `text/*`) do not match — SSE needs an
// explicit opt-in. Gates the GET SSE channel (2f PR 2) and SSE-on-POST (PR 3).
bool accept_wants_sse(std::string_view accept_header);

}  // namespace yuzu::server::mcp::transport
