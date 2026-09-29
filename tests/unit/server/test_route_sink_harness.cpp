/**
 * test_route_sink_harness.cpp — self-test for TestRouteSink itself (#1786).
 *
 * `tests/unit/server/test_route_sink.hpp` is shared by 41 test files, and #1786
 * changed its request-parsing contract: a urlencoded body is now parsed into
 * `req.params` the way httplib::Server does it. Until now nothing verified the
 * harness's own behaviour — every assertion about it was indirect, via whichever
 * route owner a fixture happened to drive. A harness that silently drifts from
 * production turns every test built on it into false confidence, which is the
 * exact failure #1786 was opened to fix.
 *
 * These cases pin the parsing contract directly, with a trivial handler that
 * simply reports what it saw:
 *   - a urlencoded body populates req.params; a JSON body does not,
 *   - `Post(path, body)` DEFAULTS to application/json, so omitting the
 *     content-type argument re-arms the original false-green,
 *   - query params are parsed before body params, so query wins,
 *   - media-type matching follows httplib (`;`-parameters and surrounding
 *     whitespace ignored; a longer look-alike type is NOT a match),
 *   - an oversized urlencoded body is refused 413 without reaching the handler,
 *   - `req.matches` capture groups survive, and alias the request's own path.
 */

#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::test::TestRouteSink;

namespace {

/// Registers one echo route and records what the handler observed.
struct SinkProbe {
    TestRouteSink sink;
    bool saw_param{false};
    std::string source;
    std::string captured; ///< req.matches[1] for the regex route
    std::string path_seen;
    int calls{0};

    SinkProbe() {
        sink.Post("/probe", [this](const httplib::Request& req, httplib::Response& res) {
            ++calls;
            saw_param = req.has_param("source");
            source = req.get_param_value("source");
            path_seen = req.path;
            res.status = 200;
        });
        sink.Get(R"(/probe/([A-Za-z0-9._-]+)/detail)",
                 [this](const httplib::Request& req, httplib::Response& res) {
                     ++calls;
                     // Read the capture AFTER copying the request, to exercise the
                     // iterators rather than just their initial value.
                     const httplib::Request copy = req;
                     captured = copy.matches[1].str();
                     res.status = 200;
                 });
    }

    auto form(const std::string& body) {
        return sink.dispatch("POST", "/probe", body, "application/x-www-form-urlencoded");
    }
};

constexpr const char* kForm = "application/x-www-form-urlencoded";

} // namespace

TEST_CASE("TestRouteSink: a urlencoded body populates req.params", "[server][routesink]") {
    SinkProbe p;
    auto res = p.form("source=tcp");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(p.saw_param);
    CHECK(p.source == "tcp");
}

TEST_CASE("TestRouteSink: a JSON body does NOT populate req.params", "[server][routesink]") {
    // Mirrors httplib: only urlencoded bodies feed req.params. A handler wanting
    // JSON fields parses req.body itself.
    SinkProbe p;
    auto res = p.sink.dispatch("POST", "/probe", R"({"source":"tcp"})", "application/json");
    REQUIRE(res != nullptr);
    CHECK_FALSE(p.saw_param);
    CHECK(p.source.empty());
}

TEST_CASE("TestRouteSink: Post(path, body) defaults to JSON — the re-armable trap",
          "[server][routesink]") {
    // This is not desirable behaviour, it is DOCUMENTED behaviour: the two-arg
    // convenience overload defaults to application/json, so a form-body test
    // that omits the content-type silently exercises whatever fallback the
    // handler has instead of its req.params branch. That is the false-green
    // #1786 fixed, and it is one omitted argument away from returning. If this
    // test ever fails because the default changed to urlencoded, that is an
    // improvement — delete the test and update the sink header comment.
    SinkProbe p;
    auto res = p.sink.Post("/probe", "source=tcp");
    REQUIRE(res != nullptr);
    CHECK_FALSE(p.saw_param);
}

TEST_CASE("TestRouteSink: query params are parsed before body params, so query wins",
          "[server][routesink]") {
    SinkProbe p;
    auto res = p.sink.dispatch("POST", "/probe?source=process", "source=user", kForm);
    REQUIRE(res != nullptr);
    CHECK(p.source == "process");
}

TEST_CASE("TestRouteSink: media type follows httplib's extract_media_type rules",
          "[server][routesink]") {
    SECTION("charset parameter is ignored") {
        SinkProbe p;
        p.sink.dispatch("POST", "/probe", "source=tcp", "application/x-www-form-urlencoded; charset=utf-8");
        CHECK(p.saw_param);
    }
    SECTION("a whitespace-padded value cannot be injected at all — set_header drops it") {
        // NOT a media-type rule: httplib::Request::set_header (httplib.h:9436)
        // silently discards any value failing is_field_value, and surrounding
        // whitespace fails it. On the wire httplib trims the value long before
        // set_header, so this padding is unreachable in production — the sink
        // ends up with NO Content-Type and therefore does not parse the body.
        // Pinned because "the header I set is not the header the handler sees"
        // is a silent-drop trap for any future header-driven test.
        SinkProbe p;
        p.sink.dispatch("POST", "/probe", "source=tcp", " application/x-www-form-urlencoded ");
        CHECK_FALSE(p.saw_param);
    }
    SECTION("a longer look-alike media type is NOT a match") {
        SinkProbe p;
        p.sink.dispatch("POST", "/probe", "source=tcp", "application/x-www-form-urlencoded-x");
        CHECK_FALSE(p.saw_param);
    }
}

TEST_CASE("TestRouteSink: an oversized urlencoded body is refused 413 before the handler",
          "[server][routesink]") {
    // httplib 413s past CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH before
    // routing, so the handler must not run — otherwise a fixture could "prove"
    // behaviour production never reaches (and, for an audited endpoint, a
    // request that leaves no audit row at all).
    SinkProbe p;
    const std::string huge = "source=" + std::string(CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH, 'x');
    auto res = p.form(huge);
    REQUIRE(res != nullptr);
    CHECK(res->status == 413);
    CHECK(p.calls == 0);
}

TEST_CASE("TestRouteSink: regex captures survive a copy of the request", "[server][routesink]") {
    // req.matches must alias the request's OWN path, as it does in httplib. When
    // it aliased a dispatch()-local instead, copying the request (as a deferred
    // or streaming handler would) left the capture pointing at a dead string.
    SinkProbe p;
    auto res = p.sink.Get("/probe/dev-A.1/detail");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(p.captured == "dev-A.1");
}

TEST_CASE("TestRouteSink: an unmatched route returns nullptr", "[server][routesink]") {
    SinkProbe p;
    CHECK(p.sink.dispatch("POST", "/nope", "", kForm) == nullptr);
    CHECK(p.sink.dispatch("GET", "/probe", "") == nullptr); // right path, wrong method
    CHECK(p.calls == 0);
}
