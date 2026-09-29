/**
 * test_web_utils.cpp — Unit tests for server web utility functions
 *
 * Covers: base64_decode, html_escape, url_decode, extract_form_value,
 *         form_value_supplied, extract_plugin
 */

#include "mcp_jsonrpc.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace yuzu::server;

// ── base64_decode ───────────────────────────────────────────────────────────

TEST_CASE("base64_decode: empty string", "[web_utils][base64]") {
    REQUIRE(base64_decode("") == "");
}

TEST_CASE("base64_decode: basic text", "[web_utils][base64]") {
    // "Hello" = "SGVsbG8="
    REQUIRE(base64_decode("SGVsbG8=") == "Hello");
}

TEST_CASE("base64_decode: 'Hello, World!'", "[web_utils][base64]") {
    // "Hello, World!" = "SGVsbG8sIFdvcmxkIQ=="
    REQUIRE(base64_decode("SGVsbG8sIFdvcmxkIQ==") == "Hello, World!");
}

TEST_CASE("base64_decode: single character", "[web_utils][base64]") {
    // "A" = "QQ=="
    REQUIRE(base64_decode("QQ==") == "A");
}

TEST_CASE("base64_decode: two characters", "[web_utils][base64]") {
    // "AB" = "QUI="
    REQUIRE(base64_decode("QUI=") == "AB");
}

TEST_CASE("base64_decode: three characters (no padding)", "[web_utils][base64]") {
    // "ABC" = "QUJD"
    REQUIRE(base64_decode("QUJD") == "ABC");
}

TEST_CASE("base64_decode: binary data (null bytes)", "[web_utils][base64]") {
    // "\x00\x01\x02" = "AAEC"
    auto result = base64_decode("AAEC");
    REQUIRE(result.size() == 3);
    CHECK(result[0] == '\x00');
    CHECK(result[1] == '\x01');
    CHECK(result[2] == '\x02');
}

TEST_CASE("base64_decode: ignores whitespace", "[web_utils][base64]") {
    // Base64 should skip non-alphabet characters including whitespace
    REQUIRE(base64_decode("QUJD\n") == "ABC");
}

TEST_CASE("base64_decode: longer string", "[web_utils][base64]") {
    // "The quick brown fox jumps over the lazy dog"
    REQUIRE(base64_decode("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==") ==
            "The quick brown fox jumps over the lazy dog");
}

TEST_CASE("base64_decode: without padding still works", "[web_utils][base64]") {
    // Some encoders omit padding; our decoder should handle it
    REQUIRE(base64_decode("SGVsbG8") == "Hello");
}

// ── html_escape ─────────────────────────────────────────────────────────────

TEST_CASE("html_escape: plain text unchanged", "[web_utils][html]") {
    REQUIRE(html_escape("Hello World 123") == "Hello World 123");
}

TEST_CASE("html_escape: empty string", "[web_utils][html]") {
    REQUIRE(html_escape("") == "");
}

TEST_CASE("html_escape: ampersand", "[web_utils][html]") {
    REQUIRE(html_escape("A & B") == "A &amp; B");
}

TEST_CASE("html_escape: less-than", "[web_utils][html]") {
    REQUIRE(html_escape("x < y") == "x &lt; y");
}

TEST_CASE("html_escape: greater-than", "[web_utils][html]") {
    REQUIRE(html_escape("x > y") == "x &gt; y");
}

TEST_CASE("html_escape: double quote", "[web_utils][html]") {
    REQUIRE(html_escape(R"(say "hi")") == "say &quot;hi&quot;");
}

TEST_CASE("html_escape: single quote", "[web_utils][html]") {
    REQUIRE(html_escape("it's") == "it&#39;s");
}

TEST_CASE("html_escape: all special chars in one string", "[web_utils][html]") {
    REQUIRE(html_escape("<script>alert('xss' & \"test\")</script>") ==
            "&lt;script&gt;alert(&#39;xss&#39; &amp; &quot;test&quot;)&lt;/script&gt;");
}

TEST_CASE("html_escape: already-escaped text gets double-escaped", "[web_utils][html]") {
    REQUIRE(html_escape("&amp;") == "&amp;amp;");
}

// ── json_escape (Phase 15.A — issue #547, hardening round 3) ───────────────
//
// json_escape is the defense against the HTMX hx-vals JSON-injection vector.
// The browser un-HTML-escapes the attribute value *before* HTMX's JSON
// parser sees it, so the correct ordering for a JSON-string-in-HTML-
// attribute is `json_escape` FIRST, `html_escape` SECOND. These tests pin
// the JSON-escape half — corruption in either direction silently re-opens
// sec-M3 from the Gate 2 governance review.

TEST_CASE("json_escape: empty string", "[web_utils][json][issue547]") {
    REQUIRE(json_escape("") == "");
}

TEST_CASE("json_escape: plain ASCII unchanged", "[web_utils][json][issue547]") {
    REQUIRE(json_escape("agent-abc-123") == "agent-abc-123");
    REQUIRE(json_escape("Hello, world! 0123456789")
            == "Hello, world! 0123456789");
}

TEST_CASE("json_escape: double-quote escapes to backslash-quote",
          "[web_utils][json][issue547]") {
    // The exact sec-M3 vector — a `"` in device_id would otherwise close
    // the JSON string in an hx-vals='{"device_id":"..."}' attribute and
    // inject keys that the operator's browser would submit on Re-enable.
    REQUIRE(json_escape("a\"b") == "a\\\"b");
    REQUIRE(json_escape("\"") == "\\\"");
    REQUIRE(json_escape("evil\",\"cmd\":\"exec")
            == "evil\\\",\\\"cmd\\\":\\\"exec");
}

TEST_CASE("json_escape: backslash escapes to double-backslash",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape("\\") == "\\\\");
    REQUIRE(json_escape("a\\b") == "a\\\\b");
}

TEST_CASE("json_escape: named escapes for \\b \\f \\n \\r \\t",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape("\b") == "\\b");
    REQUIRE(json_escape("\f") == "\\f");
    REQUIRE(json_escape("\n") == "\\n");
    REQUIRE(json_escape("\r") == "\\r");
    REQUIRE(json_escape("\t") == "\\t");
    REQUIRE(json_escape("line1\nline2\tcol") == "line1\\nline2\\tcol");
}

TEST_CASE("json_escape: C0 control bytes encode as \\u00xx",
          "[web_utils][json][issue547]") {
    // A malicious agent registering with `device_id` containing
    // 0x00-0x1F could log-inject if downstream sinks didn't escape.
    // json_escape is one of the layers; verify every C0 byte that
    // doesn't have a named escape produces \u00xx.
    REQUIRE(json_escape(std::string{static_cast<char>(0x00)}) == "\\u0000");
    REQUIRE(json_escape(std::string{static_cast<char>(0x01)}) == "\\u0001");
    REQUIRE(json_escape(std::string{static_cast<char>(0x1f)}) == "\\u001f");
    // Bytes 0x08 (\b), 0x09 (\t), 0x0a (\n), 0x0c (\f), 0x0d (\r) take
    // the named form, verified by the prior test — not duplicated here.
}

TEST_CASE("json_escape: bytes 0x20 and above pass through unchanged",
          "[web_utils][json][issue547]") {
    REQUIRE(json_escape(std::string{static_cast<char>(0x20)}) == " ");
    REQUIRE(json_escape(std::string{static_cast<char>(0x7e)}) == "~");
    // High-bit bytes (UTF-8 continuation, etc.) pass through. JSON does
    // not require U+2028 / U+2029 escaping outside `eval`-style contexts.
    REQUIRE(json_escape(std::string{static_cast<char>(0xc3),
                                     static_cast<char>(0xa9)}) ==
            std::string{static_cast<char>(0xc3),
                         static_cast<char>(0xa9)});
}

TEST_CASE("json_escape: result is safe to surround with html_escape",
          "[web_utils][json][issue547]") {
    // The full PR-A pipeline is `html_escape(json_escape(value))`. After
    // browser un-HTML-escape the attribute value reads back as the
    // json_escape output, which the JSON parser handles correctly.
    auto value = std::string{"\"\\\n"};
    auto js   = json_escape(value);
    auto html = html_escape(js);
    // The html-escaped form must contain no bare " (would close the
    // attribute), no bare < / > (would break HTML parser), no bare &
    // (would corrupt entity decode beyond the ones we emitted).
    REQUIRE(html.find('"') == std::string::npos);
    REQUIRE(html.find('<') == std::string::npos);
    REQUIRE(html.find('>') == std::string::npos);
    // And the raw JSON-escape output is the parseable JSON literal we
    // expect: \"\\\n
    REQUIRE(js == "\\\"\\\\\\n");
}

// ── url_decode ──────────────────────────────────────────────────────────────

TEST_CASE("url_decode: plain text unchanged", "[web_utils][url]") {
    REQUIRE(url_decode("hello") == "hello");
}

TEST_CASE("url_decode: empty string", "[web_utils][url]") {
    REQUIRE(url_decode("") == "");
}

TEST_CASE("url_decode: plus sign becomes space", "[web_utils][url]") {
    REQUIRE(url_decode("hello+world") == "hello world");
}

TEST_CASE("url_decode: percent-encoded space", "[web_utils][url]") {
    REQUIRE(url_decode("hello%20world") == "hello world");
}

TEST_CASE("url_decode: percent-encoded special chars", "[web_utils][url]") {
    REQUIRE(url_decode("%26") == "&");
    REQUIRE(url_decode("%3D") == "=");
    REQUIRE(url_decode("%3F") == "?");
    REQUIRE(url_decode("%2F") == "/");
}

TEST_CASE("url_decode: multiple encoded sequences", "[web_utils][url]") {
    REQUIRE(url_decode("key%3Dvalue%26other%3D123") == "key=value&other=123");
}

TEST_CASE("url_decode: mixed encoded and plain", "[web_utils][url]") {
    REQUIRE(url_decode("hello%21+world%3F") == "hello! world?");
}

TEST_CASE("url_decode: malformed escapes do not throw (#1241 UP-12)", "[web_utils][url]") {
    // A non-hex or truncated escape previously called std::stoul → threw
    // std::invalid_argument → 500 on a form-encoded POST. Now decode only a
    // well-formed %HH and pass malformed bytes through literally.
    REQUIRE(url_decode("%zz") == "%zz");        // non-hex pair → literal
    REQUIRE(url_decode("%2") == "%2");          // truncated at end → literal
    REQUIRE(url_decode("%") == "%");            // bare percent → literal
    REQUIRE(url_decode("a%g1b") == "a%g1b");    // first nibble non-hex
    REQUIRE(url_decode("a%1gb") == "a%1gb");    // second nibble non-hex
    REQUIRE(url_decode("ok%41done") == "okAdone"); // valid escape still decodes
    REQUIRE(url_decode("%2ztail") == "%2ztail");    // malformed mid-string, then plain
}

// ── origin_is_same_site (shared CSRF helper, #1241 H-1) ──────────────────────

TEST_CASE("origin_is_same_site: same-origin passes, cross-origin fails", "[web_utils][csrf]") {
    CHECK(origin_is_same_site("yuzu.example", "https://yuzu.example", ""));
    CHECK(origin_is_same_site("yuzu.example", "", "https://yuzu.example/settings"));
    CHECK_FALSE(origin_is_same_site("yuzu.example", "https://attacker.example", ""));
    CHECK_FALSE(origin_is_same_site("yuzu.example", "", "https://attacker.example/x"));
}

TEST_CASE("origin_is_same_site: no Origin AND no Referer passes (non-browser client)",
          "[web_utils][csrf]") {
    CHECK(origin_is_same_site("yuzu.example", "", ""));
}

TEST_CASE("origin_is_same_site: default ports are stripped for comparison", "[web_utils][csrf]") {
    CHECK(origin_is_same_site("yuzu.example", "https://yuzu.example:443", ""));
    CHECK(origin_is_same_site("yuzu.example:443", "https://yuzu.example", ""));
    // A non-default port is a real difference → fail.
    CHECK_FALSE(origin_is_same_site("yuzu.example", "https://yuzu.example:8443", ""));
}

TEST_CASE("origin_is_same_site: userinfo in Origin is rejected (RFC 6454)", "[web_utils][csrf]") {
    CHECK_FALSE(origin_is_same_site("yuzu.example", "https://yuzu.example@attacker.example", ""));
}

TEST_CASE("origin_is_same_site: Origin takes precedence over Referer", "[web_utils][csrf]") {
    // When both are present, only Origin is consulted (it is the stronger signal).
    CHECK(origin_is_same_site("yuzu.example", "https://yuzu.example",
                              "https://attacker.example/ref"));
    CHECK_FALSE(origin_is_same_site("yuzu.example", "https://attacker.example",
                                    "https://yuzu.example/ref"));
}

// ── #2537: operator-declared external origins (reverse-proxy support) ────────

TEST_CASE("normalise_trusted_origins: splitting, trimming, casing, ports", "[web_utils][csrf]") {
    SECTION("a single token may be comma-separated (the --cert-san contract)") {
        const std::vector<std::string> raw{"https://a.example, b.example ,,https://c.example"};
        const auto got = normalise_trusted_origins(raw);
        REQUIRE(got.size() == 3);
        CHECK(got[0] == "https://a.example");
        CHECK(got[1] == "b.example");
        CHECK(got[2] == "https://c.example");
    }
    SECTION("repeated flags accumulate") {
        const std::vector<std::string> raw{"a.example", "b.example"};
        CHECK(normalise_trusted_origins(raw).size() == 2);
    }
    SECTION("lowercased, path stripped, default port stripped, scheme preserved") {
        const std::vector<std::string> raw{"HTTPS://Yuzu.Example:443/dashboard?x=1"};
        const auto got = normalise_trusted_origins(raw);
        REQUIRE(got.size() == 1);
        CHECK(got[0] == "https://yuzu.example");
    }
    SECTION("a non-default port is significant and kept") {
        const auto got = normalise_trusted_origins(std::vector<std::string>{"yuzu.example:8443"});
        REQUIRE(got.size() == 1);
        CHECK(got[0] == "yuzu.example:8443");
    }
    SECTION("empty and whitespace-only entries are dropped, not kept as ''") {
        // An '' entry would match an unparseable Origin and silently widen the gate.
        const auto got = normalise_trusted_origins(std::vector<std::string>{" , ,\t", ""});
        CHECK(got.empty());
    }
    SECTION("a BARE entry with an explicit default port is refused as ambiguous") {
        // This section previously asserted the OPPOSITE — that `h:443` collapsing
        // to `h` was "deliberate". It was not: `h` then admitted BOTH `http://h`
        // and `https://h`, which is verbatim the defect the scheme-aware strip
        // was added to close, surviving on the axis its own tests did not cover.
        // A test that blesses a defect is worse than no test, so this pins the
        // refusal instead.
        //
        // Refusal, not a guess: `h:443` cannot say which scheme it means, and
        // keeping the port would make it unmatchable (the request side
        // canonicalises `https://h:443` to `h`). The operator writes the scheme.
        CHECK(normalise_trusted_origins(std::vector<std::string>{"h:443"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{"h:80"}).empty());
        // A non-default port is unambiguous under either scheme and is kept.
        {
            const auto got = normalise_trusted_origins(std::vector<std::string>{"h:8443"});
            REQUIRE(got.size() == 1);
            CHECK(got[0] == "h:8443");
        }
        // And the scheme-qualified forms are the documented way to say it.
        {
            const auto got = normalise_trusted_origins(std::vector<std::string>{"https://h:443"});
            REQUIRE(got.size() == 1);
            CHECK(got[0] == "https://h");
        }
    }
    SECTION("a bare entry still matches its host under either scheme") {
        // The looseness that IS deliberate: no port means no port, and the
        // request side canonicalises the scheme's own default away, so one bare
        // entry covers `https://h`, `https://h:443`, `http://h` and `http://h:80`
        // — while `https://h:80` stays a different origin.
        const auto trusted = normalise_trusted_origins(std::vector<std::string>{"h"});
        REQUIRE(trusted.size() == 1);
        CHECK(origin_is_same_site("proxy:8080", "https://h", "", trusted));
        CHECK(origin_is_same_site("proxy:8080", "https://h:443", "", trusted));
        CHECK(origin_is_same_site("proxy:8080", "http://h", "", trusted));
        CHECK(origin_is_same_site("proxy:8080", "http://h:80", "", trusted));
        CHECK_FALSE(origin_is_same_site("proxy:8080", "https://h:80", "", trusted));
    }
    SECTION("guards run on the CANONICAL form, so port suffixes cannot smuggle") {
        // Each of these reached the allowlist before the guard order was fixed:
        // `null:443` normalised to `null` and admitted every opaque origin;
        // `:443` normalised to `""` and matched a host-less source.
        CHECK(normalise_trusted_origins(std::vector<std::string>{"null:443"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{"null:80"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{"NULL:443"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{":443"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{"https://:443"}).empty());
    }
    SECTION("userinfo is refused here as well as on the request side") {
        // Kept verbatim before, so the boot log advertised an entry that the
        // request side would always fail closed on — dishonest deployment evidence.
        CHECK(normalise_trusted_origins(std::vector<std::string>{"https://evil@h"}).empty());
    }
    SECTION("default-port stripping is SCHEME-AWARE (#2641 review)") {
        // The two sections above pin the cases where scheme and default port
        // AGREE. These are the cases where they DISAGREE, and the first version
        // of this feature collapsed them: `https://h:80` normalised to
        // `https://h`, which IS `https://h:443`. An operator who declared one
        // origin got a second one trusted as well.
        //
        // RFC 6454: an origin is (scheme, host, port), and the port is omitted
        // from the canonical form only when it is that SCHEME's default.
        // Bound and size-checked before indexing: `normalise_trusted_origins`
        // legitimately DROPS entries, so a bare `[0]` on a regression would be
        // out-of-range UB presenting as a crash or a false pass, not a clean
        // failure. The sections above use the same shape.
        const auto https_80 = normalise_trusted_origins(std::vector<std::string>{"https://h:80"});
        REQUIRE(https_80.size() == 1);
        CHECK(https_80[0] == "https://h:80");
        const auto http_443 = normalise_trusted_origins(std::vector<std::string>{"http://h:443"});
        REQUIRE(http_443.size() == 1);
        CHECK(http_443[0] == "http://h:443");
        // ...while the scheme's OWN default still collapses.
        const auto https_443 = normalise_trusted_origins(std::vector<std::string>{"https://h:443"});
        REQUIRE(https_443.size() == 1);
        CHECK(https_443[0] == "https://h");
        const auto http_80 = normalise_trusted_origins(std::vector<std::string>{"http://h:80"});
        REQUIRE(http_80.size() == 1);
        CHECK(http_80[0] == "http://h");
    }
    SECTION("the reserved token `null` is refused as an entry (#2641 review)") {
        // `Origin: null` is what every sandboxed iframe, redirected POST and
        // file:// document sends. It is an OPAQUE origin, not a host, so an
        // allowlist entry of `null` would admit all of them at once. Requires an
        // operator to type it, but a security control should not hand out that
        // foot-gun.
        CHECK(normalise_trusted_origins(std::vector<std::string>{"null"}).empty());
        CHECK(normalise_trusted_origins(std::vector<std::string>{"NULL"}).empty());
        // A host that merely CONTAINS the token is a real host and is kept,
        // and so is a SCHEME-QUALIFIED `null` — the opaque serialisation is the
        // bare token only, so refusing `https://null` was a false refusal.
        const auto contains = normalise_trusted_origins(std::vector<std::string>{"null.example"});
        REQUIRE(contains.size() == 1);
        CHECK(contains[0] == "null.example");
        const auto qualified = normalise_trusted_origins(std::vector<std::string>{"https://null"});
        REQUIRE(qualified.size() == 1);
        CHECK(qualified[0] == "https://null");
    }
}

TEST_CASE("origin_is_same_site: scheme-aware ports close the over-admission (#2641)",
          "[web_utils][csrf]") {
    const auto trusted = normalise_trusted_origins(std::vector<std::string>{"https://h:80"});
    // The operator declared https-on-port-80. That, and only that, is admitted.
    CHECK(origin_is_same_site("proxy:8080", "https://h:80", "", trusted));
    // Before the fix both of these were ADMITTED, because the entry had
    // collapsed to `https://h` and the request side stripped identically.
    CHECK_FALSE(origin_is_same_site("proxy:8080", "https://h", "", trusted));
    CHECK_FALSE(origin_is_same_site("proxy:8080", "https://h:443", "", trusted));
    // The scheme half of the contract still holds on the same entry.
    CHECK_FALSE(origin_is_same_site("proxy:8080", "http://h:80", "", trusted));
}

TEST_CASE("origin_is_same_site: `Origin: null` is never admitted", "[web_utils][csrf]") {
    // Pinned as a regression: an opaque origin must not satisfy the gate under
    // any allowlist, and `null` can no longer BE an allowlist entry.
    const auto trusted = normalise_trusted_origins(
        std::vector<std::string>{"https://yuzu.customer.example"});
    CHECK_FALSE(origin_is_same_site("yuzu-server:8080", "null", "", trusted));
    CHECK_FALSE(origin_is_same_site("yuzu-server:8080", "null", "", {}));
}

TEST_CASE("origin_is_same_site: allowlist admits a proxied Origin", "[web_utils][csrf]") {
    // The #2537 shape: proxy rewrote Host, so Host and Origin legitimately differ.
    const auto trusted = normalise_trusted_origins(
        std::vector<std::string>{"https://yuzu.customer.example"});
    CHECK(origin_is_same_site("yuzu-server:8080", "https://yuzu.customer.example", "", trusted));
    // ...and it is the ALLOWLIST doing it, not a general relaxation.
    CHECK_FALSE(origin_is_same_site("yuzu-server:8080", "https://attacker.example", "", trusted));
}

TEST_CASE("origin_is_same_site: empty allowlist is byte-for-byte the old behaviour",
          "[web_utils][csrf]") {
    // Regression guard for the defaulted parameter: a caller that never learned
    // about #2537 must behave exactly as it did before.
    const std::vector<std::string> none;
    CHECK(origin_is_same_site("yuzu.example", "https://yuzu.example", "", none));
    CHECK_FALSE(origin_is_same_site("yuzu-server:8080", "https://yuzu.customer.example", "", none));
    CHECK(origin_is_same_site("yuzu.example", "", "", none)); // non-browser client
}

TEST_CASE("origin_is_same_site: a scheme-qualified entry is matched on scheme too",
          "[web_utils][csrf]") {
    const auto https_only =
        normalise_trusted_origins(std::vector<std::string>{"https://yuzu.example"});
    CHECK(origin_is_same_site("proxy-internal", "https://yuzu.example", "", https_only));
    // The weaker half of #2537: http:// must NOT satisfy an https:// entry.
    CHECK_FALSE(origin_is_same_site("proxy-internal", "http://yuzu.example", "", https_only));

    // A bare-host entry is scheme-agnostic by design, for operators who do not
    // want to pin it. Documented, and the reason the two forms both exist.
    const auto bare = normalise_trusted_origins(std::vector<std::string>{"yuzu.example"});
    CHECK(origin_is_same_site("proxy-internal", "http://yuzu.example", "", bare));
    CHECK(origin_is_same_site("proxy-internal", "https://yuzu.example", "", bare));
}

TEST_CASE("origin_is_same_site: allowlist matching is case-insensitive", "[web_utils][csrf]") {
    // A config value's case is the operator's typing; a silent no-match there is
    // an opaque 403 that costs a support round-trip.
    const auto trusted =
        normalise_trusted_origins(std::vector<std::string>{"HTTPS://Yuzu.Example"});
    CHECK(origin_is_same_site("proxy-internal", "https://YUZU.example", "", trusted));
}

TEST_CASE("origin_is_same_site: allowlist cannot rescue a malformed Origin", "[web_utils][csrf]") {
    // userinfo fails closed BEFORE the allowlist is consulted — otherwise
    // "https://yuzu.example@attacker.example" could be talked into matching.
    const auto trusted =
        normalise_trusted_origins(std::vector<std::string>{"https://yuzu.example"});
    CHECK_FALSE(
        origin_is_same_site("proxy-internal", "https://yuzu.example@attacker.example", "", trusted));
}

TEST_CASE("origin_is_same_site: wildcards are not supported and match nothing",
          "[web_utils][csrf]") {
    // Kept verbatim rather than expanded: a wildcard silently accepted into a
    // CSRF allowlist would be the entire control undone by one character.
    const auto star = normalise_trusted_origins(std::vector<std::string>{"*", "*.example"});
    CHECK_FALSE(origin_is_same_site("proxy-internal", "https://anything.example", "", star));
    CHECK_FALSE(origin_is_same_site("proxy-internal", "https://evil.example", "", star));
}

TEST_CASE("url_decode: percent at end of string (incomplete sequence)", "[web_utils][url]") {
    // '%' at end without two hex digits should be kept as-is
    auto result = url_decode("test%");
    CHECK(result == "test%");
}

TEST_CASE("url_decode: percent with one hex digit", "[web_utils][url]") {
    auto result = url_decode("test%2");
    CHECK(result == "test%2");
}

// ── extract_form_value ──────────────────────────────────────────────────────

TEST_CASE("extract_form_value: single key-value pair", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin", "username") == "admin");
}

TEST_CASE("extract_form_value: multiple pairs, first key", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin&password=secret", "username") == "admin");
}

TEST_CASE("extract_form_value: multiple pairs, second key", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin&password=secret", "password") == "secret");
}

TEST_CASE("extract_form_value: key not found returns empty", "[web_utils][form]") {
    REQUIRE(extract_form_value("username=admin", "email") == "");
}

TEST_CASE("extract_form_value: URL-encoded value decoded", "[web_utils][form]") {
    REQUIRE(extract_form_value("msg=hello+world", "msg") == "hello world");
    REQUIRE(extract_form_value("path=%2Fhome%2Fuser", "path") == "/home/user");
}

TEST_CASE("extract_form_value: empty value", "[web_utils][form]") {
    REQUIRE(extract_form_value("key=", "key") == "");
}

TEST_CASE("extract_form_value: empty body", "[web_utils][form]") {
    REQUIRE(extract_form_value("", "key") == "");
}

TEST_CASE("extract_form_value: three pairs", "[web_utils][form]") {
    std::string body = "a=1&b=2&c=3";
    CHECK(extract_form_value(body, "a") == "1");
    CHECK(extract_form_value(body, "b") == "2");
    CHECK(extract_form_value(body, "c") == "3");
}

TEST_CASE("extract_form_value: value with special chars", "[web_utils][form]") {
    REQUIRE(extract_form_value("q=c%2B%2B+programming", "q") == "c++ programming");
}

// ── form_value_supplied (QE-4) ──────────────────────────────────────────────
//
// This is the CDX-R8-01 refusal's load-bearing predicate: it must tell an
// OMITTED key apart from a SUPPLIED-but-empty one, which extract_form_value
// cannot do (it returns "" for both — see its own doc comment). Every case
// below is chosen to bind the key-boundary guard
// (`pos == 0 || body[pos - 1] == '&'`) specifically: deleting that guard
// leaves every one of these still green EXCEPT the two unanchored-match
// cases, which is exactly the mutation this file exists to catch.

TEST_CASE("form_value_supplied: key absent from empty body", "[web_utils][form]") {
    CHECK_FALSE(form_value_supplied("", "scope"));
}

TEST_CASE("form_value_supplied: key absent entirely", "[web_utils][form]") {
    CHECK_FALSE(form_value_supplied("instruction=run", "scope"));
}

TEST_CASE("form_value_supplied: key present with a value", "[web_utils][form]") {
    CHECK(form_value_supplied("scope=dev-A", "scope"));
}

TEST_CASE("form_value_supplied: key present but empty is still SUPPLIED", "[web_utils][form]") {
    // The exact distinction extract_form_value erases: "" for a supplied
    // empty value must still read as supplied.
    CHECK(form_value_supplied("scope=", "scope"));
}

TEST_CASE("form_value_supplied: key present but empty, first of several pairs",
          "[web_utils][form]") {
    CHECK(form_value_supplied("scope=&instruction=run", "scope"));
}

TEST_CASE("form_value_supplied: key present but empty, last of several pairs",
          "[web_utils][form]") {
    CHECK(form_value_supplied("instruction=run&scope=", "scope"));
}

TEST_CASE("form_value_supplied: key present but empty, in the middle", "[web_utils][form]") {
    CHECK(form_value_supplied("a=1&scope=&b=2", "scope"));
}

TEST_CASE("form_value_supplied: a longer key sharing the same suffix is NOT a match",
          "[web_utils][form]") {
    // THE mutation target: without the `pos == 0 || body[pos - 1] == '&'`
    // key-boundary guard, `body.find("scope=")` matches INSIDE "myscope="
    // too, so a request naming an unrelated field would be misread as
    // supplying `scope`. Deleting the guard flips this CHECK_FALSE to true.
    CHECK_FALSE(form_value_supplied("myscope=dev-A", "scope"));
}

TEST_CASE("form_value_supplied: a longer key sharing the same suffix, empty value, still NOT a "
          "match",
          "[web_utils][form]") {
    CHECK_FALSE(form_value_supplied("myscope=", "scope"));
}

TEST_CASE("form_value_supplied: the real key after a decoy suffix key IS a match",
          "[web_utils][form]") {
    // Companion to the two decoy cases above: once the real, boundary-anchored
    // `scope=` key also appears, it must be found even though the unanchored
    // decoy occurs first in the string.
    CHECK(form_value_supplied("myscope=x&scope=", "scope"));
}

// ── extract_plugin ──────────────────────────────────────────────────────────

TEST_CASE("extract_plugin: standard command_id with timestamp", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("chargen-12345") == "chargen");
    REQUIRE(extract_plugin("netstat-98765") == "netstat");
    REQUIRE(extract_plugin("hardware-1234567890") == "hardware");
}

TEST_CASE("extract_plugin: no dash returns whole string", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("chargen") == "chargen");
    REQUIRE(extract_plugin("netstat") == "netstat");
}

TEST_CASE("extract_plugin: empty string", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("") == "");
}

TEST_CASE("extract_plugin: multiple dashes uses first", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("my-plugin-12345") == "my");
}

TEST_CASE("extract_plugin: dash at start", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("-12345") == "");
}

TEST_CASE("extract_plugin: underscore plugin name", "[web_utils][plugin]") {
    REQUIRE(extract_plugin("vuln_scan-12345") == "vuln_scan");
    REQUIRE(extract_plugin("script_exec-12345") == "script_exec");
}

// ── Time formatters ─────────────────────────────────────────────────────────
//
// format_iso_utc and format_relative_time anchor the executions surface; the
// list shows relative time and the title= attribute shows ISO-8601 UTC for
// forensic copy/paste. Mixing local time anywhere on this surface is a known
// failure mode (BST/UTC drift) — these tests pin the format.

TEST_CASE("format_iso_utc: zero returns dash sentinel", "[web_utils][time]") {
    REQUIRE(format_iso_utc(0) == "—");
    REQUIRE(format_iso_utc(-1) == "—");
}

TEST_CASE("format_iso_utc: epoch 0 sentinel vs known UTC moment",
          "[web_utils][time]") {
    // 2025-01-01T00:00:00Z — no DST, no timezone trickery.
    REQUIRE(format_iso_utc(1735689600) == "2025-01-01T00:00:00Z");
    // 2026-04-29T12:34:56Z — middle-of-day UTC moment, well-formed leap-year-aware.
    REQUIRE(format_iso_utc(1777466096) == "2026-04-29T12:34:56Z");
}

TEST_CASE("format_iso_utc: format is fixed-width", "[web_utils][time]") {
    auto s = format_iso_utc(1735689600);
    REQUIRE(s.size() == 20); // "YYYY-MM-DDTHH:MM:SSZ"
    REQUIRE(s[4]  == '-');
    REQUIRE(s[7]  == '-');
    REQUIRE(s[10] == 'T');
    REQUIRE(s[13] == ':');
    REQUIRE(s[16] == ':');
    REQUIRE(s[19] == 'Z');
}

TEST_CASE("format_relative_time: zero return dash sentinel", "[web_utils][time]") {
    REQUIRE(format_relative_time(0, 1000) == "—");
    REQUIRE(format_relative_time(-1, 1000) == "—");
}

TEST_CASE("format_relative_time: bucketing", "[web_utils][time]") {
    // Argument order is (then, now), matching dashboard_routes.cpp's format_age.
    REQUIRE(format_relative_time(1000, 1000) == "0s ago");
    REQUIRE(format_relative_time(1000, 1059) == "59s ago");
    REQUIRE(format_relative_time(1000, 1060) == "1m ago");
    REQUIRE(format_relative_time(1000, 4599) == "59m ago");
    REQUIRE(format_relative_time(1000, 4600) == "1h 0m ago");
    REQUIRE(format_relative_time(1000, 87400) == "1d 0h ago");
}

TEST_CASE("format_relative_time: future then is clamped to zero",
          "[web_utils][time]") {
    // If the recorded `then` is in the future relative to `now` (clock skew),
    // the helper must not produce a negative-string output that confuses the
    // operator. It clamps delta to 0 so the cell reads "0s ago".
    REQUIRE(format_relative_time(2000, 1000) == "0s ago");
}

TEST_CASE("now_epoch_seconds: monotonic", "[web_utils][time]") {
    int64_t a = now_epoch_seconds();
    int64_t b = now_epoch_seconds();
    REQUIRE(b >= a);
}

// ── UTF-8 truncation ────────────────────────────────────────────────────────
//
// truncate_utf8 is used for the first-error preview in the executions list.
// Cutting in the middle of a multi-byte sequence produces invalid UTF-8 that
// breaks browser title= rendering and screen readers. The walk-back logic
// must always land on a codepoint boundary.

TEST_CASE("truncate_utf8: ASCII pass-through under limit",
          "[web_utils][utf8]") {
    REQUIRE(truncate_utf8("hello", 80) == "hello");
}

TEST_CASE("truncate_utf8: ASCII truncation appends ellipsis",
          "[web_utils][utf8]") {
    auto out = truncate_utf8("0123456789ABCDEF", 8);
    // Cut at byte 8, then append the 3-byte UTF-8 ellipsis (U+2026).
    REQUIRE(out == std::string("01234567") + "\xE2\x80\xA6");
}

TEST_CASE("truncate_utf8: walks back across multi-byte boundary",
          "[web_utils][utf8]") {
    // "café" — c,a,f,é where é is two bytes (0xC3 0xA9). Total = 5 bytes.
    // A 4-byte cut would land mid-codepoint — must walk back to byte 3.
    std::string s = "caf\xC3\xA9";
    auto out = truncate_utf8(s, 4);
    // Expected: "caf" + ellipsis.
    REQUIRE(out == std::string("caf") + "\xE2\x80\xA6");
}

TEST_CASE("truncate_utf8: walks back across emoji boundary",
          "[web_utils][utf8]") {
    // U+1F525 FIRE is 4 bytes UTF-8 (F0 9F 94 A5). Cutting after byte 9 lands
    // mid-emoji; walk-back must arrive at the next codepoint start at byte 7.
    std::string s = "abc\xF0\x9F\x94\xA5\xF0\x9F\x94\xA5";
    auto out = truncate_utf8(s, 9);
    REQUIRE(out == std::string("abc\xF0\x9F\x94\xA5") + "\xE2\x80\xA6");
}

// ── Status sparkbar ─────────────────────────────────────────────────────────
//
// render_status_sparkbar produces inline SVG with one <rect> per non-zero
// bucket. Widths must always sum to exactly 120 (kWidth) so the bar aligns
// in the table grid even with rounding. role="img" + summary aria-label
// carries the data to screen readers; individual rects are aria-hidden.

TEST_CASE("render_status_sparkbar: zero total emits hatched empty state",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(0, 0, 0, 0);
    REQUIRE(svg.find("<svg") != std::string::npos);
    REQUIRE(svg.find("empty-hatch") != std::string::npos);
    REQUIRE(svg.find("no agents") != std::string::npos);
    // No data rects should be emitted — only the hatch pattern fill rect.
    auto rect_count = std::count(svg.begin(), svg.end(), '<') -
                      std::count(svg.begin(), svg.begin() + 1, '<');
    (void)rect_count; // silence unused — count is a smoke check below.
    // The hatched empty SVG must NOT contain segment fills (token names).
    REQUIRE(svg.find("--mds-color-bg-success-emphasis") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-error") == std::string::npos);
}

TEST_CASE("render_status_sparkbar: zero-count buckets emit no <rect>",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(50, 0, 0, 0);
    // Only the success-emphasis fill should appear. UP-13 added two-arg
    // var(...) fallbacks, so the substring carries a comma-separated
    // fallback tail; assert on the token name only.
    REQUIRE(svg.find("--mds-color-bg-success-emphasis") != std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-error") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-indicator-stable") == std::string::npos);
    REQUIRE(svg.find("--mds-color-theme-text-tertiary") == std::string::npos);
}

TEST_CASE("render_status_sparkbar: aria-label summarises the four counts",
          "[web_utils][sparkbar]") {
    auto svg = render_status_sparkbar(47, 3, 0, 0);
    REQUIRE(svg.find("aria-label=\"47 succeeded, 3 failed, 0 running, 0 pending of 50\"")
            != std::string::npos);
}

TEST_CASE("render_status_sparkbar: widths sum to 120 with rounding edge case",
          "[web_utils][sparkbar]") {
    // 1/1/1/0 of 3 → each segment "should be" 40px; 40+40+40 = 120 exact.
    auto svg = render_status_sparkbar(1, 1, 1, 0);
    int width_sum = 0;
    std::size_t pos = 0;
    while ((pos = svg.find("width=\"", pos)) != std::string::npos) {
        pos += 7;
        auto end = svg.find('"', pos);
        if (end == std::string::npos) break;
        auto val = svg.substr(pos, end - pos);
        // Skip the outer SVG width="120".
        if (val == "120") { pos = end; continue; }
        if (val == "10") { pos = end; continue; } // height attr re-used as width
        if (val == "4") { pos = end; continue; } // pattern width 4
        try { width_sum += std::stoi(val); } catch (...) {}
        pos = end;
    }
    REQUIRE(width_sum == 120);
}

TEST_CASE("render_status_sparkbar: rounding-residue absorbed by last non-zero "
          "segment",
          "[web_utils][sparkbar]") {
    // 1/1/1/1 of 7 doesn't divide evenly; 7*kWidth = 840; 840/7 = 120; each
    // gets 120/7 = 17.14, rounded to 17 → 17*4=68; residue 120-68=52 must
    // land entirely on the last non-zero segment.
    auto svg = render_status_sparkbar(2, 2, 2, 1);
    // Sum the rect widths and assert == 120; if any segment is missing or
    // the residue is misallocated this fails.
    int width_sum = 0;
    std::size_t pos = 0;
    int rect_count = 0;
    while ((pos = svg.find("<rect ", pos)) != std::string::npos) {
        ++rect_count;
        auto wpos = svg.find("width=\"", pos);
        if (wpos == std::string::npos) break;
        wpos += 7;
        auto end = svg.find('"', wpos);
        if (end == std::string::npos) break;
        auto val = svg.substr(wpos, end - wpos);
        try { width_sum += std::stoi(val); } catch (...) {}
        pos = end;
    }
    REQUIRE(rect_count == 4);
    REQUIRE(width_sum == 120);
}

// ── Duration bar ────────────────────────────────────────────────────────────

TEST_CASE("render_duration_bar_html: width clamps to 100%",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(2000, 1000, "succeeded");
    REQUIRE(html.find("width:100%") != std::string::npos);
}

TEST_CASE("render_duration_bar_html: zero max yields zero width",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(500, 0, "running");
    REQUIRE(html.find("width:0%") != std::string::npos);
}

TEST_CASE("render_duration_bar_html: status class flows through",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(500, 1000, "failed");
    REQUIRE(html.find("duration-bar--failed") != std::string::npos);
    REQUIRE(html.find("aria-label=\"500 ms\"") != std::string::npos);
}

// ── UP-13: sparkbar fills carry CSS-variable fallbacks ─────────────────────

TEST_CASE("render_status_sparkbar: every fill has a two-arg var() fallback (UP-13)",
          "[web_utils][sparkbar][fallback]") {
    auto svg = render_status_sparkbar(1, 1, 1, 1);
    // All four token-named fills carry a fallback so a yuzu.css load failure
    // doesn't render the bar invisible.
    REQUIRE(svg.find("var(--mds-color-bg-success-emphasis,var(--green))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-indicator-error,var(--red))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-indicator-stable,var(--accent))")
            != std::string::npos);
    REQUIRE(svg.find("var(--mds-color-theme-text-tertiary,var(--muted))")
            != std::string::npos);
}

TEST_CASE("render_duration_bar_html: negative duration clamped to zero",
          "[web_utils][duration]") {
    auto html = render_duration_bar_html(-100, 1000, "succeeded");
    REQUIRE(html.find("aria-label=\"0 ms\"") != std::string::npos);
}

TEST_CASE("audit_token: neutralises k=v structural delimiters + control bytes",
          "[web_utils][audit]") {
    // ASCII-clean values pass through verbatim.
    CHECK(audit_token("Acme.exe") == "Acme.exe");
    CHECK(audit_token("4.3.0.0") == "4.3.0.0");
    CHECK(audit_token("") == "");
    // The field-confusion characters (space, '=', ',') become '_' so a value cannot
    // forge an adjacent k=v field — the H1 fix the VERIFY audit details rely on.
    CHECK(audit_token("a paired=99 cohort=99") == "a_paired_99_cohort_99");
    CHECK(audit_token("x,y") == "x_y");
    // Line-splitting control bytes (CR/LF, < 0x20) and DEL (0x7F) are neutralised too.
    CHECK(audit_token(std::string("a\r\nb")) == "a__b");
    CHECK(audit_token(std::string("a\x7F" "b")) == "a_b");
    CHECK(audit_token(std::string("a\tb")) == "a_b");
}

// ── mcp_body_exceeds_cap (#2437) ────────────────────────────────────────────
//
// The pre-routing transport cap's DECISION. Extracted from server.cpp's
// pre-routing lambda precisely so it is testable here; the wire behaviour it
// drives (413 without the body ever being read) is pinned separately in
// test_mcp_body_cap.cpp against a real httplib::Server.

TEST_CASE("mcp_body_exceeds_cap: only /mcp/v1/ is capped", "[web_utils][mcp][bounds]") {
    constexpr std::uint64_t kCap = 1024;
    // Other surfaces on the same httplib instance keep httplib's global
    // default — capping them here would break the multipart certificate
    // upload and content distribution, which is why this is per-path and not
    // Server::set_payload_max_length.
    CHECK_FALSE(mcp_body_exceeds_cap("/api/v1/bundles", kCap * 100, kCap));
    CHECK_FALSE(mcp_body_exceeds_cap("/api/settings/certificates", kCap * 100, kCap));
    CHECK_FALSE(mcp_body_exceeds_cap("/", kCap * 100, kCap));
    // Prefix match, not exact: every method and sub-path under /mcp/v1/.
    CHECK(mcp_body_exceeds_cap("/mcp/v1/", kCap + 1, kCap));
    CHECK(mcp_body_exceeds_cap("/mcp/v1/anything", kCap + 1, kCap));
    // A path that merely CONTAINS the prefix elsewhere is not capped.
    CHECK_FALSE(mcp_body_exceeds_cap("/proxy/mcp/v1/x", kCap + 1, kCap));
}

TEST_CASE("mcp_body_exceeds_cap: exactly at the cap is admitted", "[web_utils][mcp][bounds]") {
    constexpr std::uint64_t kCap = 1024;
    // Strictly greater-than. The docs publish a "<= cap" contract, so an
    // off-by-one here would reject a request the documentation promises to
    // accept.
    CHECK_FALSE(mcp_body_exceeds_cap("/mcp/v1/", kCap - 1, kCap));
    CHECK_FALSE(mcp_body_exceeds_cap("/mcp/v1/", kCap, kCap));
    CHECK(mcp_body_exceeds_cap("/mcp/v1/", kCap + 1, kCap));
}

TEST_CASE("is_mcp_path: scoped to match the auth chokepoint, not narrower",
          "[web_utils][mcp][bounds]") {
    // The cap must cover EVERYTHING the auth chokepoint admits, or a path is
    // authenticated-but-uncapped. Auth and the engine quota gate both scope on
    // "/mcp/", so this does too: scoping to "/mcp/v1/" alone left "/mcp/v1"
    // and "/mcp/v1x" reachable and unbounded, evadable by editing one
    // character (governance Gate 4 UP-5, Gate 8 security LOW-4).
    CHECK(is_mcp_path("/mcp/v1/"));
    CHECK(is_mcp_path("/mcp/v1"));
    CHECK(is_mcp_path("/mcp/v1/anything"));
    CHECK(is_mcp_path("/mcp/v1x"));
    // A future /mcp/v2/ is capped BY DEFAULT rather than shipping uncapped and
    // waiting for someone to notice - the whole point of matching the auth
    // scope instead of a version-specific one.
    CHECK(is_mcp_path("/mcp/v2/"));

    // Still bounded: the prefix must be a real path segment, and an unrelated
    // route that merely contains it is untouched.
    CHECK_FALSE(is_mcp_path("/mcp"));
    CHECK_FALSE(is_mcp_path("/mcpx/v1/"));
    CHECK_FALSE(is_mcp_path("/proxy/mcp/v1/"));
    CHECK_FALSE(is_mcp_path("/api/v1/bundles"));
}

TEST_CASE("mcp_body_unmeasurable: refuses any framing or encoding we do not solely interpret",
          "[web_utils][mcp][bounds]") {
    // Signature takes header VALUES, not a pre-computed "is it chunked" bool.
    // That is the whole fix: the previous version matched httplib's decision by
    // hand with a case-SENSITIVE find("chunked") while httplib uses
    // case_ignore::equal, so one capital letter admitted a body that was then
    // read as chunked under the 100 MB global default.
    auto unmeasurable = [](std::string_view method, bool has_cl, std::string_view te,
                           std::string_view ce) {
        return mcp_body_unmeasurable("/mcp/v1/", method, has_cl, te, ce);
    };

    SECTION("Transfer-Encoding is refused in ANY case, on ANY method") {
        for (auto te : {"chunked", "Chunked", "CHUNKED", "cHuNkEd", "identity, chunked",
                        "gzip", "anything-at-all"}) {
            INFO("Transfer-Encoding: " << te);
            // Declaring a Content-Length alongside must not buy admission -
            // httplib consults Transfer-Encoding first and ignores the length.
            CHECK(unmeasurable("POST", /*has_cl=*/true, te, ""));
            // httplib's expect_content treats chunking independently of the
            // method, so a chunked GET/DELETE reaches the same reader.
            CHECK(unmeasurable("GET", false, te, ""));
            CHECK(unmeasurable("DELETE", false, te, ""));
            CHECK(unmeasurable("OPTIONS", false, te, ""));
        }
    }

    SECTION("non-identity Content-Encoding is refused") {
        // This build compiles CPPHTTPLIB_BROTLI_SUPPORT: httplib decompresses
        // transparently and bounds only the DECOMPRESSED size against its 100
        // MB global, so Content-Length measures the wrong thing entirely.
        for (auto ce : {"br", "gzip", "deflate", "BR", "Gzip"}) {
            INFO("Content-Encoding: " << ce);
            CHECK(unmeasurable("POST", /*has_cl=*/true, "", ce));
        }
        // identity IS the no-op encoding, in any case, and stays admissible.
        for (auto ce : {"identity", "Identity", "IDENTITY"}) {
            INFO("Content-Encoding: " << ce);
            CHECK_FALSE(unmeasurable("POST", /*has_cl=*/true, "", ce));
        }
    }

    SECTION("a body-bearing method with no Content-Length is refused") {
        CHECK(unmeasurable("POST", /*has_cl=*/false, "", ""));
        CHECK(unmeasurable("PUT", false, "", ""));
        CHECK(unmeasurable("PATCH", false, "", ""));
    }

    SECTION("a plain measurable request is admitted") {
        CHECK_FALSE(unmeasurable("POST", /*has_cl=*/true, "", ""));
        // Bodyless methods carry nothing to measure - the GET SSE channel and
        // DELETE session teardown must not be refused by a rule aimed at
        // bodies. DELETE is the load-bearing one: httplib's expect_content is
        // true for it, so it is TEMPTING to require a Content-Length there,
        // but MCP teardown sends no body and many clients omit the header
        // entirely - 411-ing it would break a shipped route to close a hazard
        // that is currently unreachable. See mcp_body_unmeasurable's contract.
        CHECK_FALSE(unmeasurable("GET", false, "", ""));
        CHECK_FALSE(unmeasurable("DELETE", false, "", ""));
        // ...but a DELETE that carries real framing IS refused.
        CHECK(unmeasurable("DELETE", false, "chunked", ""));
        CHECK(unmeasurable("DELETE", true, "", "br"));
    }

    SECTION("other surfaces keep httplib's global default - this rule is per-path") {
        CHECK_FALSE(mcp_body_unmeasurable("/api/v1/bundles", "POST", false, "chunked", "br"));
    }
}

// ── upload chunk body cap ───────────────────────────────────────────────────
//
// HISTORY: three predicate tests lived here for a hand-rolled BR-008
// pre-routing branch (is_upload_chunk_path / upload_chunk_body_exceeds_cap /
// upload_chunk_body_unmeasurable). #2407's `kBodyCapTable` landed on dev as
// the SINGLE per-route body-cap chokepoint (routed-concern: catastrophic if
// forked), so the branch and its helpers were deleted and the upload surface
// registered as the `upload_session` table row instead. Coverage moved with
// it: test_body_cap_policy.cpp asserts the row's cap/measurability/boundary
// behaviour, and file_retrieval_routes.cpp's static_assert binds the row's
// cap to `upload_grant::kDefaultChunkMaxBytes`.

// ── JSON depth guard (#2437, governance Gate 5 CH-1) ─────────────────────

TEST_CASE("json_exceeds_depth: rejects the nesting that SIGSEGVs dump()",
          "[web_utils][mcp][bounds]") {
    using yuzu::server::mcp::json_exceeds_depth;
    using yuzu::server::mcp::kMcpMaxJsonDepth;

    // MEASURED, not assumed: nlohmann parses very deep input fine and its
    // destructor is iterative, but dump() is RECURSIVE - 500k levels (0.95 MiB
    // raw, a quarter of the transport cap) segfaults the process, and
    // execute_instruction's bound check calls v.dump() on a non-string params
    // value. This guard exists so the tree is never constructed.
    SECTION("deep input is rejected") {
        const std::string deep = std::string(kMcpMaxJsonDepth + 1, '[') +
                                 std::string(kMcpMaxJsonDepth + 1, ']');
        CHECK(json_exceeds_depth(deep, kMcpMaxJsonDepth));
    }
    SECTION("exactly at the limit is admitted") {
        const std::string ok =
            std::string(kMcpMaxJsonDepth, '[') + std::string(kMcpMaxJsonDepth, ']');
        CHECK_FALSE(json_exceeds_depth(ok, kMcpMaxJsonDepth));
    }
    SECTION("a realistic execute_bundle envelope is nowhere near the limit") {
        // The deepest legitimate shape: envelope > params > arguments > steps >
        // step > params > value. If this ever trips, the limit is too tight.
        CHECK_FALSE(json_exceeds_depth(
            R"({"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"execute_bundle",)"
            R"("arguments":{"agent_id":"a","steps":[{"plugin":"p","action":"a",)"
            R"("params":{"k":"v"}}]}}})",
            kMcpMaxJsonDepth));
    }
    SECTION("brackets INSIDE a string are not structure") {
        // The scanner must not be fooled into rejecting a legitimate payload
        // whose string values happen to contain brackets - a scope expression
        // or a script body will.
        std::string s = R"({"scope":")" + std::string(200, '[') + R"("})";
        CHECK_FALSE(json_exceeds_depth(s, kMcpMaxJsonDepth));
        // ...nor into ACCEPTING real nesting that follows an ESCAPED quote.
        // The value is the one-character string `"`, after which the brackets
        // ARE structure. A scanner that treated the escaped quote as closing
        // the string would mis-track depth from here on.
        std::string evil = R"({"k":"\"")" + std::string(kMcpMaxJsonDepth + 1, '[') + "}";
        CHECK(json_exceeds_depth(evil, kMcpMaxJsonDepth));
    }
    SECTION("an escaped backslash does not swallow the closing quote") {
        // The value is the string `a\`; the quote AFTER the escaped backslash
        // closes it, so the brackets are structure. Getting this wrong the
        // other way - treating that quote as escaped - would let a deep
        // payload hide inside what the scanner believes is still a string.
        std::string s = R"({"k":"a\\")" + std::string(kMcpMaxJsonDepth + 1, '[') + "}";
        CHECK(json_exceeds_depth(s, kMcpMaxJsonDepth));
    }
}

TEST_CASE("parse_request refuses the depth bomb instead of dying on it",
          "[web_utils][mcp][bounds]") {
    // THE regression test for governance Gate 5 CH-1. Reproduces the measured
    // crash payload: 500k nesting levels, 0.95 MiB raw - a QUARTER of the
    // 4 MiB transport cap, so the cap admits it.
    //
    // BE PRECISE ABOUT WHAT DIES, because the first version of this comment
    // was wrong: nlohmann's parse() handles 500k levels fine and its destructor
    // is iterative, so removing the guard makes THIS test fail cleanly rather
    // than crash. The SIGSEGV comes later, from the recursive dump() - and
    // execute_instruction's bound check calls v.dump() on any non-string
    // params value. The guard exists so the deep tree is never constructed and
    // no downstream traversal, present or future, can reach it.
    const std::string bomb = std::string(500000, '[') + std::string(500000, ']');
    REQUIRE(bomb.size() < 4u * 1024 * 1024); // the transport cap would admit it

    auto parsed = yuzu::server::mcp::parse_request(bomb);
    REQUIRE_FALSE(parsed.has_value());
    CHECK(parsed.error().find("-32700") != std::string::npos);
    CHECK(parsed.error().find("nests too deeply") != std::string::npos);

    // And the ordinary parse errors still behave - the guard runs before the
    // parser but must not shadow it.
    auto bad = yuzu::server::mcp::parse_request("{not json");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().find("-32700") != std::string::npos);

    // A legitimate request is untouched.
    auto ok = yuzu::server::mcp::parse_request(
        R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(ok.has_value());
    CHECK(ok->method == "tools/list");
}

TEST_CASE("mcp_body_exceeds_cap: absent Content-Length is not a SIZE violation",
          "[web_utils][mcp][bounds]") {
    // 0 is what the caller passes when the header is absent. This predicate
    // answers "is the declared size over the cap", and an absent size is not
    // an over-size — refusing that shape is mcp_body_unmeasurable's job (411),
    // tested above. This pins only that the size predicate stays
    // single-purpose; the two must not be collapsed, or the 411 rule and the
    // 413 rule start answering each other's questions.
    CHECK_FALSE(mcp_body_exceeds_cap("/mcp/v1/", 0, 1024));
}

// ── is_login_exempt_path (H1, 2026-07-08 SCIM review) ───────────────────────

TEST_CASE("is_login_exempt_path: /scim/v2/* is exempt (prefix match)",
          "[web_utils][login_exempt][scim]") {
    // The concrete bug (H1): every IdP call was 302-redirected to /login
    // before ScimRoutes' own bearer gate ever ran.
    CHECK(is_login_exempt_path("/scim/v2/Users"));
    CHECK(is_login_exempt_path("/scim/v2/Users/deadbeef"));
    CHECK(is_login_exempt_path("/scim/v2/ServiceProviderConfig"));
    CHECK(is_login_exempt_path("/scim/v2/ResourceTypes"));
    CHECK(is_login_exempt_path("/scim/v2/Schemas"));
    // Prefix, not exact — the bare "/scim/v2" (no trailing slash) does NOT
    // match any real route and is deliberately not exempted.
    CHECK_FALSE(is_login_exempt_path("/scim/v2"));
}

TEST_CASE("is_login_exempt_path: unrelated API paths are NOT exempt",
          "[web_utils][login_exempt]") {
    CHECK_FALSE(is_login_exempt_path("/api/v1/foo"));
    CHECK_FALSE(is_login_exempt_path("/api/v1/ca/issued"));
    CHECK_FALSE(is_login_exempt_path("/api/v1/ca/revoke"));
    CHECK_FALSE(is_login_exempt_path("/mcp/v1/tools"));
    CHECK_FALSE(is_login_exempt_path("/dashboard"));
    CHECK_FALSE(is_login_exempt_path("/scimv2/Users")); // no slash — not a prefix match
    // #2057: /api/v1/openapi.json used to be listed here (see the removed
    // "regression" assertion below's git history) — it no longer is. The
    // route now gates Infrastructure:Read itself (rest_api_v1.cpp), so the
    // pre-routing chokepoint must resolve a session for it like every other
    // /api/v1/* route rather than skip straight to the handler.
    CHECK_FALSE(is_login_exempt_path("/api/v1/openapi.json"));
}

TEST_CASE("is_login_exempt_path: every pre-existing exempt path is unchanged",
          "[web_utils][login_exempt][regression]") {
    CHECK(is_login_exempt_path("/login"));
    CHECK(is_login_exempt_path("/login/mfa"));
    CHECK(is_login_exempt_path("/login/mfa/enroll"));
    CHECK(is_login_exempt_path("/health"));
    CHECK(is_login_exempt_path("/api/health"));
    CHECK(is_login_exempt_path("/auth/oidc/start"));
    CHECK(is_login_exempt_path("/auth/callback"));
    CHECK(is_login_exempt_path("/auth/saml/start"));
    CHECK(is_login_exempt_path("/saml/acs"));
    CHECK(is_login_exempt_path("/api/v1/ca/root"));
    CHECK(is_login_exempt_path("/api/v1/ca/crl"));
    CHECK(is_login_exempt_path("/static/app.css"));
    // Deliberately NOT exempt (requires a session): step-up MFA.
    CHECK_FALSE(is_login_exempt_path("/login/mfa/stepup"));
}

TEST_CASE("agent_error_display bounds the FIRST record, not a byte window",
          "[web_utils][agent-error]") {
    // Sol adversarial review. Agent replies are newline-separated records, so a
    // byte-count truncation of the raw output is wrong in both directions.
    // `tar status`'s offline reply is `error|<long line>` followed by
    // `storage_state|offline`, and the 300-byte window that replaced a 200-byte
    // one ran PAST the newline and rendered a trailing `storage_stat` as debris.
    const std::string offline =
        "error|TAR storage is offline on this endpoint; the database was closed after a "
        "transaction could not be rolled back. Collection and retention are both stopped. The "
        "read-only query connection is unavailable too, so `tar sql` cannot read the historical "
        "data either. Restart the agent to recover.\nstorage_state|offline";

    const auto shown = yuzu::server::agent_error_display(offline);
    CHECK(shown.starts_with("TAR storage is offline")); // prefix stripped
    CHECK(shown.ends_with("Restart the agent to recover."));
    // The whole point: no debris from the NEXT record, at any length.
    CHECK(shown.find("storage_state") == std::string::npos);
    CHECK(shown.find('\n') == std::string::npos);

    // A message longer than the bound is still cut, but never mid-codepoint.
    const std::string wide = "error|" + std::string(60, 'x') + "\xC3\xA9" + std::string(60, 'y');
    const auto cut = yuzu::server::agent_error_display(wide, 61);
    CHECK(cut.size() == 60); // stepped back off the 2-byte sequence, not split
    CHECK(cut == std::string(60, 'x'));

    // No prefix and no newline: returned as-is.
    CHECK(yuzu::server::agent_error_display("plain text") == "plain text");

    // Degenerate shapes must not render an EMPTY message -- the operator would
    // see "The device reported an error: " with nothing after it. The leading
    // newline case is a regression the byte window did not have.
    CHECK(yuzu::server::agent_error_display("error|\ndetail here") == "detail here");
    CHECK(yuzu::server::agent_error_display("error|line one\r\nline two") == "line one");
    // A malformed all-continuation run truncates rather than erasing everything.
    const std::string junk = "error|A" + std::string(50, '\x80');
    CHECK_FALSE(yuzu::server::agent_error_display(junk, 10).empty());
    // Genuinely empty input stays empty without reading out of bounds.
    CHECK(yuzu::server::agent_error_display("error|").empty());
    CHECK(yuzu::server::agent_error_display("").empty());
}
