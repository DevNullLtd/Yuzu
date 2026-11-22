/**
 * test_http_response_policy.cpp: the HEAD refusal and the measured-quality brotli encode that
 * `HttplibRouteSink` composes around every handler (server/core/src/http_response_policy.hpp).
 *
 * Pure cases over a hand-built httplib::Request and Response: no socket, no sleep. The same rules
 * through a real httplib::Server are pinned by one loopback case in test_post_read_stage.cpp.
 */

#include "../../../server/core/src/http_response_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <brotli/decode.h>

#include <cstdint>
#include <random>
#include <string>
#include <string_view>

using namespace yuzu::server;

namespace {

std::string decode(const std::string& in, size_t expect_size) {
    std::string out(expect_size, '\0');
    size_t n = out.size();
    const auto rc = BrotliDecoderDecompress(in.size(), reinterpret_cast<const uint8_t*>(in.data()), &n,
                                            reinterpret_cast<uint8_t*>(out.data()));
    REQUIRE(rc == BROTLI_DECODER_RESULT_SUCCESS);
    out.resize(n);
    return out;
}

std::string synthetic_page(size_t bytes) {
    std::string page;
    page.reserve(bytes + 128);
    size_t i = 0;
    while (page.size() < bytes) {
        const size_t app = i++; // its own statement: the two operands below must not race on `i`
        page += "<tr><td>app" + std::to_string(app % 977) + ".exe</td><td class=\"gp-num\">" +
                std::to_string(i * 31 % 1000) + "</td></tr>\n";
    }
    return page;
}

httplib::Request req_for(const char* method, const char* path, const char* accept_encoding = nullptr) {
    httplib::Request r;
    r.method = method;
    r.path = path;
    if (accept_encoding)
        r.set_header("Accept-Encoding", accept_encoding);
    return r;
}

struct Counted {
    int calls = 0;
    httplib::Server::Handler handler(std::string body, const char* type) {
        return [this, body = std::move(body), type](const httplib::Request&, httplib::Response& res) {
            ++calls;
            res.status = 200;
            res.set_content(body, type);
        };
    }
};

} // namespace

TEST_CASE("brotli_compress: round trip for an empty body, a short body, a page and arbitrary bytes",
          "[http_response_policy][brotli]") {
    std::mt19937 rng(7);
    std::string noise(4096, '\0');
    for (auto& c : noise)
        c = static_cast<char>(rng() & 0xFF);
    // Quality 11 costs about a millisecond per kilobyte, so its leg runs on a body of about 20 KB;
    // the 2.5 MB body is encoded at the configured quality only (a few milliseconds).
    const std::string page = synthetic_page(20'000);
    for (const std::string& in : {std::string{}, std::string("hello"), page, noise}) {
        for (const int q : {kDynamicBrotliQuality, 11}) {
            INFO("quality " << q << ", " << in.size() << " bytes");
            std::string out;
            REQUIRE(brotli_compress(in, q, out));
            CHECK(decode(out, in.size()) == in);
        }
    }
    const std::string big = synthetic_page(2'500'000);
    std::string out;
    REQUIRE(brotli_compress(big, kDynamicBrotliQuality, out));
    CHECK(decode(out, big.size()) == big);
    // The result holds the encoded bytes, not the encoder's worst-case allocation (about the size of
    // the input): every standard library gives a freshly assigned string a capacity within a small
    // rounding of its size, so a generous bound still fails on a kept MaxCompressedSize buffer.
    INFO("encoded " << out.size() << " bytes, capacity " << out.capacity());
    CHECK(out.capacity() <= out.size() * 2 + 64);
}

TEST_CASE("dynamic compression uses the configured quality", "[http_response_policy][brotli]") {
    // The literal 5 is the measured choice documented beside kDynamicBrotliQuality: this case fails
    // if the constant moves (for instance back to the 11 that httplib would use) without that
    // table being redone. The two independent encodes must differ, or the comparison below could not
    // tell the qualities apart.
    constexpr int kMeasuredQuality = 5;
    constexpr int kHttplibQuality = 11;
    const std::string page = synthetic_page(20'000);
    std::string at_measured, at_httplib;
    REQUIRE(brotli_compress(page, kMeasuredQuality, at_measured));
    REQUIRE(brotli_compress(page, kHttplibQuality, at_httplib));
    // Double parentheses: the operands are binary, so a failure must not print them.
    REQUIRE((at_measured != at_httplib));

    Counted c;
    const auto h = with_response_policy(c.handler(page, "text/html; charset=utf-8"));
    httplib::Response res;
    h(req_for("GET", "/fragments/dex/apps", "br"), res);
    REQUIRE(res.get_header_value("Content-Encoding") == "br");
    INFO("encoded " << res.body.size() << " bytes; quality " << kMeasuredQuality << " gives "
                    << at_measured.size() << " and quality " << kHttplibQuality << " gives "
                    << at_httplib.size());
    CHECK((res.body == at_measured));
}

TEST_CASE("head_runs_handler: probes, static assets, sign-in pages and the public CA files",
          "[http_response_policy]") {
    for (const char* p : {"/health", "/livez", "/readyz", "/api/health", "/static/yuzu.css", "/login",
                          "/home", "/api/v1/ca/root", "/api/v1/ca/crl"})
        CHECK(head_runs_handler(p));
    for (const char* p : {"/fragments/dex/apps", "/api/v1/dex/apps", "/metrics", "/", "/api/v1/ca/issued",
                          "/healthz"})
        CHECK_FALSE(head_runs_handler(p));
}

TEST_CASE("with_response_policy: HEAD on a dynamic path is 405 with Allow GET and the handler never runs",
          "[http_response_policy]") {
    Counted c;
    const auto h = with_response_policy(c.handler("page", "text/html"));
    httplib::Response res;
    h(req_for("HEAD", "/fragments/dex/apps"), res);
    CHECK(res.status == 405);
    CHECK(res.get_header_value("Allow") == "GET");
    CHECK(c.calls == 0);
}

TEST_CASE("with_response_policy: HEAD on an exempt path runs the handler", "[http_response_policy]") {
    for (const char* p : {"/health", "/livez", "/static/x.css", "/api/v1/ca/root"}) {
        INFO(p);
        Counted c;
        const auto h = with_response_policy(c.handler("ok", "text/plain"));
        httplib::Response res;
        h(req_for("HEAD", p), res);
        CHECK(res.status == 200);
        CHECK(c.calls == 1);
    }
}

TEST_CASE("with_response_policy: GET with Accept-Encoding br is encoded once and decodes to the original",
          "[http_response_policy]") {
    const std::string page = synthetic_page(200'000);
    Counted c;
    const auto h = with_response_policy(c.handler(page, "text/html; charset=utf-8"));
    httplib::Response res;
    h(req_for("GET", "/fragments/dex/apps", "br"), res);
    CHECK(c.calls == 1);
    CHECK(res.get_header_value("Content-Encoding") == "br");
    CHECK(res.get_header_value_count("Content-Encoding") == 1);
    CHECK(res.get_header_value("Vary") == "Accept-Encoding");
    CHECK(res.body.size() < page.size());
    CHECK(decode(res.body, page.size()) == page);
}

TEST_CASE("with_response_policy: every case that must stay untouched is left alone",
          "[http_response_policy]") {
    const std::string page = synthetic_page(50'000);

    SECTION("no Accept-Encoding") {
        Counted c;
        httplib::Response res;
        with_response_policy(c.handler(page, "text/html"))(req_for("GET", "/x"), res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body == page);
    }
    SECTION("the handler already named a Content-Encoding") {
        httplib::Response res;
        with_response_policy([&](const httplib::Request&, httplib::Response& r) {
            r.set_content(page, "text/html");
            r.set_header("Content-Encoding", "identity");
        })(req_for("GET", "/x", "br"), res);
        CHECK(res.get_header_value("Content-Encoding") == "identity");
        CHECK(res.get_header_value_count("Content-Encoding") == 1);
        CHECK(res.body == page);
    }
    SECTION("a Range request") {
        Counted c;
        auto req = req_for("GET", "/x", "br");
        req.ranges.emplace_back(0, 99);
        httplib::Response res;
        with_response_policy(c.handler(page, "text/html"))(req, res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body == page);
    }
    SECTION("an empty body") {
        Counted c;
        httplib::Response res;
        with_response_policy(c.handler("", "text/html"))(req_for("GET", "/x", "br"), res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body.empty());
    }
    SECTION("a content provider") {
        httplib::Response res;
        with_response_policy([](const httplib::Request&, httplib::Response& r) {
            r.set_content_provider(3, "text/html", [](size_t, size_t, httplib::DataSink& sink) {
                sink.write("abc", 3);
                return true;
            });
        })(req_for("GET", "/x", "br"), res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body.empty());
    }
    SECTION("text/event-stream") {
        Counted c;
        httplib::Response res;
        with_response_policy(c.handler(page, "text/event-stream"))(req_for("GET", "/x", "br"), res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body == page);
    }
    SECTION("an Accept-Encoding that does not offer br") {
        Counted c;
        httplib::Response res;
        with_response_policy(c.handler(page, "text/html"))(req_for("GET", "/x", "identity"), res);
        CHECK_FALSE(res.has_header("Content-Encoding"));
        CHECK(res.body == page);
    }
}

// Security floor (docs/build-guide.md, "Security dependency pins"): vcpkg.json overrides brotli to
// 1.2.1 for CVE-2026-111497, a decoder overflow reached through every httplib client that
// decompresses a response. BrotliDecoderVersion() packs MAJOR << 24 | MINOR << 12 | PATCH, so
// 1.2.1 is 0x1002001. Raise the number when the pin moves; never lower it.
TEST_CASE("brotli: linked decoder is at least the security-pinned 1.2.1", "[deps][security]") {
    const std::uint32_t v = BrotliDecoderVersion();
    INFO("BrotliDecoderVersion() = " << (v >> 24) << '.' << ((v >> 12) & 0xFFF) << '.' << (v & 0xFFF));
    CHECK(v >= 0x1002001u);
}
