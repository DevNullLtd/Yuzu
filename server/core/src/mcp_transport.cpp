#include "mcp_transport.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>

namespace yuzu::server::mcp::transport {

bool protocol_version_supported(std::string_view version) {
    static constexpr std::array<std::string_view, 2> kSupported{"2025-03-26", "2025-06-18"};
    return std::find(kSupported.begin(), kSupported.end(), version) != kSupported.end();
}

bool origin_allowed(std::string_view origin, const std::vector<std::string>& allowlist) {
    if (origin.empty()) {
        return true;  // absent → allowed (see header rationale)
    }
    // Exact scheme+host+port match, verbatim — never a prefix/suffix heuristic.
    return std::find(allowlist.begin(), allowlist.end(), origin) != allowlist.end();
}

namespace {

// Case-insensitive whole-token compare against `text/event-stream`.
bool is_sse_media_type(std::string_view token) {
    constexpr std::string_view needle = "text/event-stream";
    if (token.size() != needle.size()) {
        return false;
    }
    for (std::size_t i = 0; i < needle.size(); ++i) {
        if (static_cast<char>(std::tolower(static_cast<unsigned char>(token[i]))) != needle[i]) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool accept_wants_sse(std::string_view accept_header) {
    // Parse the Accept header as a comma-separated list of media ranges and look
    // for `text/event-stream` as a WHOLE media type — never a bare substring.
    // A substring scan false-positives on `application/json; q=text/event-stream`
    // (the token appears in a parameter value) and `not-text/event-stream`
    // (a prefix), so each range is split off, its `;`-delimited parameters are
    // dropped, OWS is trimmed, and the remaining media type is compared exactly
    // (case-insensitive per RFC 9110 — media types are case-insensitive).
    //
    // The `,` split is RFC-9110 quoted-string aware (#2073): a comma inside a
    // quoted parameter value (`application/json;x=",text/event-stream,"`) is
    // part of that value, not a range separator, and must NOT mis-split into a
    // false SSE match — this function gates the GET SSE channel (2f PR 2), so a
    // false positive would hand an SSE stream to a client that asked for JSON.
    // Quoted-pair (`\"`) inside a quoted-string is honoured. An unterminated
    // quote swallows the rest of the header into one range, which then fails the
    // whole-type compare — fail-closed, the direction a parse ambiguity must go.
    //
    // Wildcards (`*/*`, `text/*`) deliberately do NOT match — SSE requires an
    // explicit `text/event-stream` opt-in, so this fails closed to JSON.
    std::size_t pos = 0;
    const std::size_t n = accept_header.size();
    while (pos <= n) {
        // Scan to the next range-separating comma, tracking quoted-string state.
        // The media type/subtype grammar admits no `"`, so the first `;` we meet
        // outside quotes always ends the type — parameters are all that follow.
        bool in_quotes = false;
        std::size_t i = pos;
        for (; i < n; ++i) {
            const char c = accept_header[i];
            if (in_quotes) {
                if (c == '\\' && i + 1 < n) {
                    ++i;  // quoted-pair: skip the escaped octet
                } else if (c == '"') {
                    in_quotes = false;
                }
            } else if (c == '"') {
                in_quotes = true;
            } else if (c == ',') {
                break;
            }
        }
        const bool last = i >= n;
        std::string_view token = accept_header.substr(pos, i - pos);
        // Drop any `;`-delimited parameters (q=, charset, etc.) — only the type matters.
        if (const std::size_t semi = token.find(';'); semi != std::string_view::npos) {
            token = token.substr(0, semi);
        }
        // Trim optional leading/trailing whitespace (OWS).
        std::size_t b = 0, e = token.size();
        while (b < e && std::isspace(static_cast<unsigned char>(token[b]))) ++b;
        while (e > b && std::isspace(static_cast<unsigned char>(token[e - 1]))) --e;
        if (is_sse_media_type(token.substr(b, e - b))) {
            return true;
        }
        if (last) {
            break;
        }
        pos = i + 1;
    }
    return false;
}

}  // namespace yuzu::server::mcp::transport
