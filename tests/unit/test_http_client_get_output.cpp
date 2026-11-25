/**
 * test_http_client_get_output.cpp -- the pure decision behind http_client `get` and a peer
 * Content-Encoding (http_client_get_output.hpp). The plugin's SSRF filter refuses loopback, so the
 * action cannot be driven against a local server; these cases pin the refusal row. The body's own
 * bytes are covered by the prepare_get_body tests, not here.
 */
#include "http_client_download.hpp"
#include "http_client_get_output.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::http_client;

TEST_CASE("http_client get: a peer Content-Encoding is refused with a named token",
          "[agent][http_client][wp14a]") {
    CHECK(encoding_refusal_row("br") == "error|peer sent Content-Encoding br; body not decoded");
    CHECK(encoding_refusal_row("gzip") == "error|peer sent Content-Encoding gzip; body not decoded");
}

TEST_CASE("http_client get: the Content-Encoding token cannot inject framing",
          "[agent][http_client][wp14a]") {
    const auto row = encoding_refusal_row("br\r\nbody|evil|x y");
    CHECK(row == "error|peer sent Content-Encoding brbodyevilxy; body not decoded");
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find('\r') == std::string::npos);
}

TEST_CASE("http_client get: absent and identity encodings are accepted, any case, any spacing",
          "[agent][http_client][wp14a]") {
    for (const char* ce : {"", "identity", " Identity ", "IDENTITY", "identity,identity",
                           "identity , IDENTITY", ","}) {
        CHECK(is_identity_encoding(ce));
        CHECK(encoding_refusal_row(ce).empty());
    }
}

TEST_CASE("http_client get: a list is accepted only when every coding is identity",
          "[agent][http_client][wp14a]") {
    // The plugin joins ALL Content-Encoding header lines with ',': `identity` then `br` must not pass.
    for (const char* ce : {"identity,br", "br,identity", "identity, gzip", "identityx", "ident"}) {
        CHECK_FALSE(is_identity_encoding(ce));
        CHECK_FALSE(encoding_refusal_row(ce).empty());
    }
}

TEST_CASE("http_client get: NUL and control bytes are replaced in place, never a cut of the rest",
          "[agent][http_client][wp14a]") {
    // Bytes AFTER a mid-stream NUL must still be returned (a C-string cut would drop them).
    std::string raw("head\0middle\0tail-after-two-nuls", 31);
    const auto row = yuzu::http_client::prepare_get_body(raw, false);
    CHECK(row.body == "head?middle?tail-after-two-nuls");
    CHECK(row.body.size() == raw.size());
    CHECK(row.replaced == 2);

    // Control bytes and an invalid byte mid-stream: same in-place rule, length preserved.
    const auto ctl = yuzu::http_client::prepare_get_body(std::string("a\x01" "b\x1b" "c\xff" "d\0e", 9), false);
    CHECK(ctl.body == "a?b?c?d?e");
    CHECK(ctl.replaced == 4);
}

TEST_CASE("http_client get: compressed bytes WITHOUT a Content-Encoding header are not refused",
          "[agent][http_client][wp14a]") {
    // Known limit, no content sniffing: a peer that sends Brotli bytes and no Content-Encoding is
    // indistinguishable from any binary body. The encoding check passes (header absent) and the
    // body is returned scrubbed, status unchanged.
    CHECK(encoding_refusal_row("").empty());
    const std::string wire("\x1b\x0e\x00\x80zz\x03tail", 11);
    const auto row = yuzu::http_client::prepare_get_body(wire, false);
    CHECK(row.body.size() == wire.size());
    CHECK(row.body.find("tail") != std::string::npos);
    CHECK(row.replaced > 0);
}
