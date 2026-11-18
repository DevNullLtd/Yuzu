/**
 * test_http_client_get_output.cpp -- the pure decision layer behind http_client `get`/`head`
 * output (http_client_get_output.hpp). The plugin's SSRF filter refuses loopback, so the action
 * cannot be driven against a local server; these cases pin the rows it writes for a peer that
 * answers with a Content-Encoding (the client decodes nothing) and for bodies carrying NUL or
 * control bytes, which write_output would otherwise truncate or mis-frame.
 */
#include "http_client_get_output.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::http_client;

TEST_CASE("http_client get: a peer Content-Encoding is refused, never written as a body",
          "[agent][http_client][wp14a]") {
    // What a brotli-compressed reply looks like once nothing decodes it: raw bytes incl. NUL.
    const std::string raw("\x1b\x0e\x00\x80zz\x03", 7);
    const auto out = build_get_output(200, "br", raw);
    REQUIRE(out.lines.size() == 2);
    CHECK(out.lines[0] == "status|200");
    CHECK(out.lines[1] == "error|peer sent Content-Encoding br; body not decoded");
    CHECK(out.rc == 1);
    for (const auto& l : out.lines)
        CHECK(l.rfind("body|", 0) != 0);

    // Even a clean-looking body is refused when the peer declared an encoding.
    const auto gz = build_get_output(200, "gzip", "plain text");
    CHECK(gz.lines.back() == "error|peer sent Content-Encoding gzip; body not decoded");
    CHECK(gz.rc == 1);
}

TEST_CASE("http_client get: the Content-Encoding token cannot inject framing",
          "[agent][http_client][wp14a]") {
    const auto out = build_get_output(200, "br\r\nbody|evil|x y", "ok");
    REQUIRE(out.lines.size() == 2);
    CHECK(out.lines[1] == "error|peer sent Content-Encoding brbodyevilxy; body not decoded");
    CHECK(out.lines[1].find('\n') == std::string::npos);
}

TEST_CASE("http_client get: identity, absent and mixed-case identity pass the body through",
          "[agent][http_client][wp14a]") {
    for (const char* ce : {"", "identity", " Identity ", "IDENTITY"}) {
        const auto out = build_get_output(200, ce, "hello\tworld\r\nline2");
        REQUIRE(out.lines.size() == 2);
        CHECK(out.lines[1] == "body|hello\tworld\r\nline2");
        CHECK(out.rc == 0);
    }
    CHECK(build_get_output(404, "", "nope").rc == 1);
    CHECK(build_get_output(302, "", "moved").rc == 0);
}

TEST_CASE("http_client get: a body with NUL or control bytes never reaches write_output",
          "[agent][http_client][wp14a]") {
    const std::string with_nul("abc\0def", 7);
    for (const std::string& bad : {with_nul, std::string("a\x01z"), std::string("a\x7f" "z"),
                                   std::string("a\x1b[31mz")}) {
        const auto out = build_get_output(200, "", bad);
        REQUIRE(out.lines.size() == 2);
        CHECK(out.lines[1] == "error|response body contains NUL or control bytes");
        CHECK(out.rc == 1);
    }
}

TEST_CASE("http_client get: a status-0 plugin error text is written as before",
          "[agent][http_client][wp14a]") {
    const auto out = build_get_output(0, "", "connection failed");
    REQUIRE(out.lines.size() == 2);
    CHECK(out.lines[0] == "status|0");
    CHECK(out.lines[1] == "body|connection failed");
    CHECK(out.rc == 1);
}

TEST_CASE("http_client: has_unsafe_bytes allows TAB, CR and LF only", "[agent][http_client][wp14a]") {
    CHECK_FALSE(has_unsafe_bytes("a\tb\r\nc"));
    CHECK(has_unsafe_bytes(std::string("\0", 1)));
    CHECK(has_unsafe_bytes("\x08"));
    CHECK(has_unsafe_bytes("\x7f"));
}
