/**
 * test_mcp_transport.cpp — MCP Streamable HTTP transport pre-check helpers
 * (ADR-1005 Decision 15, track 2f). Pure predicates, no httplib/auth deps.
 * Covers the CH-9 (Origin) pure core + protocol-version negotiation clamp.
 */

#include "mcp_transport.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using namespace yuzu::server::mcp::transport;

TEST_CASE("MCP transport: protocol version support set", "[mcp][transport]") {
    CHECK(protocol_version_supported("2025-03-26"));
    CHECK(protocol_version_supported("2025-06-18"));
    CHECK_FALSE(protocol_version_supported("2024-11-05")); // older, unsupported
    CHECK_FALSE(protocol_version_supported("9999-99-99"));
    CHECK_FALSE(protocol_version_supported("")); // absent is the caller's concern, not "supported"
    CHECK(kProtocolDefault == "2025-03-26");
}

TEST_CASE("MCP transport: Origin allowlist (CH-9 pure core)", "[mcp][transport]") {
    SECTION("absent Origin is always allowed (credential-gated endpoint)") {
        CHECK(origin_allowed("", {}));                             // empty allowlist
        CHECK(origin_allowed("", {"https://ui.example.com"}));     // populated allowlist
    }
    SECTION("empty allowlist rejects ANY present Origin (secure default)") {
        CHECK_FALSE(origin_allowed("https://ui.example.com", {}));
        CHECK_FALSE(origin_allowed("http://localhost:8080", {}));
    }
    SECTION("present Origin must match an allowlist entry exactly") {
        const std::vector<std::string> allow{"https://ui.example.com", "http://localhost:8080"};
        CHECK(origin_allowed("https://ui.example.com", allow));
        CHECK(origin_allowed("http://localhost:8080", allow));
        // scheme / host / port mismatches all reject — no heuristics
        CHECK_FALSE(origin_allowed("http://ui.example.com", allow));   // scheme
        CHECK_FALSE(origin_allowed("https://evil.example.com", allow)); // host
        CHECK_FALSE(origin_allowed("http://localhost:9090", allow));    // port
        CHECK_FALSE(origin_allowed("https://ui.example.com/", allow));  // trailing slash ≠ exact
    }
}

TEST_CASE("MCP transport: Accept opts into SSE (case-insensitive)", "[mcp][transport]") {
    CHECK(accept_wants_sse("text/event-stream"));
    CHECK(accept_wants_sse("application/json, text/event-stream"));
    CHECK(accept_wants_sse("TEXT/EVENT-STREAM"));
    CHECK(accept_wants_sse("application/json,Text/Event-Stream;q=0.9"));
    CHECK(accept_wants_sse("  text/event-stream ; charset=utf-8")); // OWS + params trimmed
    // `q=0` means "not acceptable" in RFC 9110, and this function IGNORES it -
    // parameters are stripped before the compare, so this opts IN. Pinned as
    // INTENDED, not overlooked: from the streamed-POST rung on, this predicate
    // decides whether a tools/call gets an SSE stream instead of a plain JSON
    // response, and _meta.progressToken is the real opt-in gate. A client that
    // sends a progressToken AND lists text/event-stream at q=0 is contradicting
    // itself; honouring the token is the useful reading, and the spec requires
    // conformant clients to accept both types anyway. Change this only with the
    // streamed-POST eligibility rule in hand - it is not a local decision.
    CHECK(accept_wants_sse("text/event-stream;q=0"));
    CHECK(accept_wants_sse("application/json, text/event-stream;q=0"));
    CHECK(accept_wants_sse("text/plain, application/json, text/event-stream")); // last range
    CHECK_FALSE(accept_wants_sse("application/json"));
    CHECK_FALSE(accept_wants_sse(""));
    CHECK_FALSE(accept_wants_sse("text/event")); // partial, not the full media type
    // Boundary: the media type must be a WHOLE range, never a bare substring —
    // a parameter value or a prefixed type must not false-positive (PR-1 review LOW).
    CHECK_FALSE(accept_wants_sse("application/json; q=text/event-stream")); // param value
    CHECK_FALSE(accept_wants_sse("not-text/event-stream"));                 // prefixed type
    CHECK_FALSE(accept_wants_sse("text/event-stream-plus"));                // suffixed type
    // Wildcards fail closed — SSE needs an explicit opt-in (not */* or text/*).
    CHECK_FALSE(accept_wants_sse("*/*"));
    CHECK_FALSE(accept_wants_sse("text/*"));
    // Degenerate but well-formed: leading / doubled / trailing commas parse safely.
    CHECK(accept_wants_sse(",text/event-stream"));
    CHECK(accept_wants_sse("application/json,,text/event-stream"));
    CHECK(accept_wants_sse("text/event-stream,"));
}

TEST_CASE("MCP transport: the Accept comma-split honours RFC-9110 quoted-strings (#2073)",
          "[mcp][transport]") {
    // This function GATES the GET SSE channel (2f PR 2). A comma inside a quoted
    // parameter value is part of that value, not a range separator — splitting on
    // it naively would hand an SSE stream to a client that asked for JSON, purely
    // because the token appeared inside a quoted string it controls.
    //
    // Every input is hoisted into a named `std::string_view` rather than written
    // inline in the CHECK macro. These headers contain commas inside raw-string
    // literals, and MSVC's default (non-conformant) preprocessor is not
    // raw-string-aware: it splits the macro argument on those commas, handing the
    // compiler garbage tokens (`error C2065: 'text' undeclared`). GCC/Clang parse
    // it fine, which is why this only broke on the Windows leg. A named local takes
    // the comma out of the macro argument entirely, so it is portable.
    constexpr std::string_view kQuotedCommaBeforeType = R"(application/json;x=",text/event-stream,")";
    constexpr std::string_view kQuotedCommaInValue = R"(application/json;x="a,text/event-stream")";
    // A quoted-pair (\") does not end the quoted-string, so the comma after it is
    // still inside the value. Written as an ESCAPED normal string, not a raw string:
    // the specific MSVC preprocessor defect that broke this test is a `\"` INSIDE a raw
    // string literal (it is the only line here that hard-errored), so this input avoids
    // a raw string entirely. The bytes are identical to R"(application/json;x="a\",...b")".
    constexpr std::string_view kQuotedPair = "application/json;x=\"a\\\",text/event-stream,b\"";
    // Unterminated quote: the rest of the header is swallowed into one range, which
    // then fails the whole-type compare. Fail-closed is the only safe direction for
    // a parse ambiguity on a security-relevant gate.
    constexpr std::string_view kUnterminatedQuote = R"(application/json;x=",text/event-stream)";
    CHECK_FALSE(accept_wants_sse(kQuotedCommaBeforeType));
    CHECK_FALSE(accept_wants_sse(kQuotedCommaInValue));
    CHECK_FALSE(accept_wants_sse(kQuotedPair));
    CHECK_FALSE(accept_wants_sse(kUnterminatedQuote));

    // A genuine SSE opt-in still matches even when a LATER range carries a quoted
    // comma — the fix must not make the header un-parseable in the honest case.
    constexpr std::string_view kSseFirstThenQuotedComma = R"(text/event-stream, application/json;x="a,b")";
    constexpr std::string_view kQuotedCommaThenSse = R"(application/json;x="a,b", text/event-stream)";
    // …including when the SSE range itself carries a quoted parameter.
    constexpr std::string_view kSseWithQuotedParam = R"(text/event-stream;note=",json,")";
    CHECK(accept_wants_sse(kSseFirstThenQuotedComma));
    CHECK(accept_wants_sse(kQuotedCommaThenSse));
    CHECK(accept_wants_sse(kSseWithQuotedParam));
}
