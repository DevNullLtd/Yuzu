#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>   // std::snprintf in detail::json_escape (was transitively included)
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {

// ── JSON-RPC 2.0 error codes ─────────────────────────────────────────────
constexpr int kParseError      = -32700;
constexpr int kInvalidRequest  = -32600;
constexpr int kMethodNotFound  = -32601;
constexpr int kInvalidParams   = -32602;
constexpr int kInternalError   = -32603;
// Application-defined codes
constexpr int kPermissionDenied = -32003;
constexpr int kTierDenied       = -32004;
constexpr int kMcpDisabled      = -32005;
constexpr int kApprovalRequired = -32006;
// MCP Streamable HTTP transport (ADR-1005 Decision 15, track 2f)
constexpr int kMcpUnknownSession     = -32007;  // unknown/expired/wrong-principal id  → HTTP 404
constexpr int kMcpOriginRejected     = -32008;  // Origin not in allowlist             → HTTP 403
constexpr int kMcpBadProtocolVersion = -32009;  // MCP-Protocol-Version unsupported     → HTTP 400
constexpr int kMcpSessionCap         = -32010;  // per-principal/global session cap hit → HTTP 429
constexpr int kMcpNotAcceptable      = -32011;  // GET without Accept: text/event-stream → HTTP 406
constexpr int kMcpStreamCap          = -32012;  // per-principal/global stream cap hit   → HTTP 429
constexpr int kMcpStreamPoisoned     = -32013;  // terminal delivery failed twice        → HTTP 410
constexpr int kMcpTerminalUnavailable = -32014;  // parked result forced-expired under pressure -
                                                 // fetch by execution_id (bridge sweep, 2f PR 3)
constexpr int kMcpShuttingDown = -32015;  // registry refused mint(): ServerImpl::stop() is
                                          // draining sessions (#3042) → HTTP 503

// ── Request ───────────────────────────────────────────────────────────────

struct JsonRpcRequest {
    std::string method;
    nlohmann::json params;                // object or array (default: empty object)
    std::optional<nlohmann::json> id;     // null → notification (no response expected)
};

// ── Parsing ───────────────────────────────────────────────────────────────

/// Aggregate cap on a `/mcp/` request body (#2437).
///
/// WHY IT EXISTS: httplib is not unbounded without a `set_payload_max_length`
/// call — it falls back to CPPHTTPLIB_PAYLOAD_MAX_LENGTH (100 MB) and enforces
/// it. But 100 MB is a default nobody chose, far above what any MCP tool
/// needs, and it is buffered per connection before the parser below sees a
/// byte. Enforced per-path in the pre-routing chokepoint (server.cpp), which
/// httplib invokes BEFORE it reads the body; the server-global knob is
/// deliberately untouched because it would also cap the multipart certificate
/// upload and content distribution on the same httplib instance.
///
/// 4 MiB is a DELIBERATE CLAMP, not a ceiling derived from every tool: it sits
/// well above a maximal `execute_instruction` but below what
/// `execute_bundle`'s own step validator would accept, so a multi-MiB bundle
/// the REST twin still admits is refused over MCP. Documented in
/// docs/mcp-server.md as a stated clamp rather than a silent regression.
inline constexpr std::size_t kMcpMaxRequestBodyBytes = 4 * 1024 * 1024;

/// Maximum JSON nesting a request body may declare (#2437, governance Gate 5
/// CH-1). The deepest LEGITIMATE MCP request is `execute_bundle` at roughly
/// seven levels — envelope, params, arguments, steps, step, params, value — so
/// 32 is generous headroom while staying four orders of magnitude below the
/// depth that kills the process.
inline constexpr int kMcpMaxJsonDepth = 32;

/// True when `body` nests deeper than `max_depth`.
///
/// WHY THIS EXISTS, measured not assumed: `nlohmann::json::parse` handles very
/// deep input fine and the destructor is iterative, but `dump()` is RECURSIVE.
/// A 0.95 MiB body of `[[[[...]]]]` — a quarter of the 4 MiB transport cap —
/// SIGSEGVs the process on `dump()`, and `execute_instruction`'s bound check
/// calls `v.dump()` on any non-string `params` value. So the check meant to
/// reject an oversized argument was itself the crash, reachable by any
/// authenticated operator-tier caller, taking down the control plane.
///
/// Guarding at the individual `dump()` call site would be the wrong fix:
/// `dump()` is not the only recursive traversal and `execute_instruction` is
/// not the only tool. Rejecting here means the deep tree is never CONSTRUCTED,
/// which closes every downstream traversal at once — including ones nobody has
/// written yet.
///
/// Iterative by necessity: a recursive depth-checker would crash on exactly
/// the input it exists to reject. Scans the raw text, so it runs before any
/// allocation, and skips string literals (with escapes) so brackets inside a
/// string value are not counted as structure.
[[nodiscard]] inline bool json_exceeds_depth(std::string_view body, int max_depth) noexcept {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char c : body) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                in_string = false;
            continue;
        }
        switch (c) {
        case '"':
            in_string = true;
            break;
        case '[':
        case '{':
            if (++depth > max_depth)
                return true;
            break;
        case ']':
        case '}':
            --depth;
            break;
        default:
            break;
        }
    }
    return false;
}

/// Parse a JSON-RPC 2.0 request from the raw HTTP body.
/// Returns the parsed request, or an error-response string ready to send.
inline std::expected<JsonRpcRequest, std::string> parse_request(std::string_view body) {
    // Depth BEFORE parse: see json_exceeds_depth. A -32700 parse error is the
    // honest answer - the body is not something this server will parse.
    if (json_exceeds_depth(body, kMcpMaxJsonDepth)) {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: input nests too deeply"},"id":null})");
    }
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(body);
    } catch (...) {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null})");
    }

    if (!doc.is_object() || !doc.contains("jsonrpc") || doc["jsonrpc"] != "2.0") {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request: missing jsonrpc 2.0"},"id":null})");
    }
    if (!doc.contains("method") || !doc["method"].is_string()) {
        return std::unexpected(
            R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request: missing method"},"id":null})");
    }

    JsonRpcRequest req;
    req.method = doc["method"].get<std::string>();
    req.params = doc.value("params", nlohmann::json::object());
    if (doc.contains("id"))
        req.id = doc["id"];
    return req;
}

// ── Response building (string-based, no nlohmann template bloat) ──────────

namespace detail {

inline void json_escape(std::string& out, std::string_view sv) {
    out.reserve(out.size() + sv.size());
    for (char c : sv) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
        }
    }
}

inline std::string json_quoted(std::string_view sv) {
    std::string out;
    out.reserve(sv.size() + 2);
    out += '"';
    json_escape(out, sv);
    out += '"';
    return out;
}

} // namespace detail

/// Build a JSON-RPC 2.0 success response.  `result_json` is a pre-serialized JSON fragment.
inline std::string success_response(const nlohmann::json& id, std::string_view result_json) {
    std::string r = R"({"jsonrpc":"2.0","result":)";
    r += result_json;
    r += R"(,"id":)";
    r += id.dump();
    r += '}';
    return r;
}

/// Build a JSON-RPC 2.0 error response.
inline std::string error_response(const nlohmann::json& id, int code, std::string_view message,
                                  std::string_view data_json = {}) {
    std::string r = R"({"jsonrpc":"2.0","error":{"code":)";
    r += std::to_string(code);
    r += R"(,"message":)";
    r += detail::json_quoted(message);
    if (!data_json.empty()) {
        r += R"(,"data":)";
        r += data_json;
    }
    r += R"(},"id":)";
    r += id.dump();
    r += '}';
    return r;
}

/// Build an error response for notifications (no id → id is null).
inline std::string error_response_null(int code, std::string_view message) {
    std::string r = R"({"jsonrpc":"2.0","error":{"code":)";
    r += std::to_string(code);
    r += R"(,"message":)";
    r += detail::json_quoted(message);
    r += R"(},"id":null})";
    return r;
}

/// A4-shaped JSON-RPC 2.0 error response for the /mcp/v1/ Streamable-HTTP
/// transport denials (Origin / protocol-version / unknown-session / session-cap
/// on POST, GET, DELETE). `error.data` always carries `correlation_id` plus the
/// nullable `retry_after_ms`; `remediation` is emitted only when non-empty (the
/// §A4 convention — absence carries the "no recovery hint" meaning). This is the
/// SINGLE builder for every transport denial's error.data, keeping the shape
/// uniform with the REST A4 envelope (docs/agentic-first-principle.md §A4;
/// ADR-1005 exec-plan Decision 15(j) makes the A4 shape the cap-hit merge gate).
///
/// The correlation id is minted by the caller
/// (yuzu::server::detail::make_correlation_id()) and passed in, so this header
/// stays free of the rest_a4_envelope dependency. Delegates to error_response()
/// so there is ONE wire shape; pass `id = nullptr` for the pre-parse (Origin /
/// protocol) and bodyless (GET/DELETE) denials, or use error_response_null_a4.
inline std::string error_response_a4(const nlohmann::json& id, int code, std::string_view message,
                                     std::string_view correlation_id,
                                     std::string_view remediation = {},
                                     std::optional<std::int64_t> retry_after_ms = std::nullopt) {
    std::string data = R"({"correlation_id":)";
    data += detail::json_quoted(correlation_id);
    data += R"(,"retry_after_ms":)";
    if (retry_after_ms) {
        data += std::to_string(*retry_after_ms);
    } else {
        data += "null";
    }
    if (!remediation.empty()) {
        data += R"(,"remediation":)";
        data += detail::json_quoted(remediation);
    }
    data += '}';
    return error_response(id, code, message, data);
}

/// A4-shaped transport denial with a null JSON-RPC id — the pre-parse
/// (Origin / protocol) and bodyless (GET/DELETE) sites. Byte-identical to
/// error_response_null() plus the shared A4 `error.data`.
inline std::string error_response_null_a4(int code, std::string_view message,
                                          std::string_view correlation_id,
                                          std::string_view remediation = {},
                                          std::optional<std::int64_t> retry_after_ms = std::nullopt) {
    return error_response_a4(nlohmann::json(nullptr), code, message, correlation_id, remediation,
                             retry_after_ms);
}

// ── Progress (track 2f PR 3, notifications/progress) ──────────────────────

/// Longest string `progressToken` accepted. The token is opaque and echoed verbatim into
/// EVERY notifications/progress frame; an unbounded token would inflate every frame (and,
/// once oversized, trip the ring's frame-size cap so live progress silently never works)
/// and is stored per bridge record. A caller-controlled amplifier, so it is bounded at
/// extraction: an over-long token reads as "no progress requested" (governance security-LOW
/// / unhappy-path UP-1). 512 bytes is far beyond any real correlation id.
inline constexpr std::size_t kMaxProgressTokenBytes = 512;

/// Extract a caller-supplied `_meta.progressToken` from a tools/call params object.
///
/// MCP Streamable HTTP: `progressToken` is `string | integer`. It is opaque and echoed
/// verbatim in every `notifications/progress`. Anything else - absent, a non-object
/// `_meta`, a token that is neither a string nor an integer (e.g. a float, bool, null,
/// object), or a string longer than kMaxProgressTokenBytes - returns nullopt, which the
/// caller treats as "no progress requested" (the spec lets a server decline to emit
/// progress, so an unusable token is simply ignored, never an error). Returned by value so
/// the token outlives the parsed request document.
inline std::optional<nlohmann::json> extract_progress_token(const nlohmann::json& params) {
    if (!params.is_object()) {
        return std::nullopt;
    }
    auto meta_it = params.find("_meta");
    if (meta_it == params.end() || !meta_it->is_object()) {
        return std::nullopt;
    }
    auto tok_it = meta_it->find("progressToken");
    if (tok_it == meta_it->end()) {
        return std::nullopt;
    }
    // is_number_integer() is true for both signed and unsigned integers; floats are rejected.
    if (tok_it->is_string()) {
        if (tok_it->get_ref<const nlohmann::json::string_t&>().size() > kMaxProgressTokenBytes) {
            return std::nullopt;  // caller-controlled amplifier - decline oversize (UP-1)
        }
        std::optional<nlohmann::json> out;
        out.emplace(*tok_it);
        return out;
    }
    if (tok_it->is_number_integer()) {
        // emplace, not `return *tok_it`: nlohmann's implicit `operator ValueType()` makes the
        // json -> optional<json> conversion ambiguous; an in-place copy-construct is explicit.
        std::optional<nlohmann::json> out;
        out.emplace(*tok_it);
        return out;
    }
    return std::nullopt;
}

/// Build a JSON-RPC `notifications/progress` message for a streamed tool call.
///
/// `progress_token` is echoed verbatim (dump()) so a string token stays a string and an
/// integer token stays an integer - never stringified. `progress`/`total` are the monotone
/// agents-responded / agents-targeted counts. `execution_id` is carried in `_meta` so the
/// client holds the durable fetch handle (get_execution_status / query_responses) BEFORE any
/// terminal or close frame - a broken stream is then always recoverable (K3 H5).
inline std::string progress_notification(const nlohmann::json& progress_token,
                                         std::uint64_t progress, std::uint64_t total,
                                         std::string_view message, std::string_view execution_id) {
    std::string r =
        R"({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":)";
    r += progress_token.dump();
    r += R"(,"progress":)";
    r += std::to_string(progress);
    r += R"(,"total":)";
    r += std::to_string(total);
    r += R"(,"message":)";
    r += detail::json_quoted(message);
    r += R"(,"_meta":{"yuzu.execution_id":)";
    r += detail::json_quoted(execution_id);
    r += R"(}}})";
    return r;
}

} // namespace yuzu::server::mcp
