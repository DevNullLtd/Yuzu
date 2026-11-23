/// @file test_live_result_json.cpp
/// live_result_json.{hpp,cpp}: the ONE `data` JSON builder shared by the REST live route and the
/// MCP tool. Pins the wire shape (key order included, because the REST body is byte-compared by
/// clients), the row cap and `truncated` flag, the short row forms, and the refusal of any kind
/// other than the two rest_v1 ones.

#include "live_model.hpp"
#include "live_result_json.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace live = yuzu::server::live;
using json = nlohmann::json;

TEST_CASE("live_result_json: uptime renders display and seconds in wire order", "[live][json]") {
    const auto r = live::live_result_json("uptime", "uptime_display|3d 4h\nuptime_seconds|273600\n");
    REQUIRE(r);
    CHECK(r->body == R"({"kind":"uptime","uptime_display":"3d 4h","uptime_seconds":273600})");
    CHECK_FALSE(r->truncated);
    CHECK(r->count == 0);
}

TEST_CASE("live_result_json: uptime with only one field, and with empty output", "[live][json]") {
    const auto only_seconds = live::live_result_json("uptime", "uptime_seconds|42\n");
    REQUIRE(only_seconds);
    CHECK(only_seconds->body == R"({"kind":"uptime","uptime_seconds":42})");

    const auto empty = live::live_result_json("uptime", "");
    REQUIRE(empty);
    CHECK(empty->body == R"({"kind":"uptime"})");
}

TEST_CASE("live_result_json: processes renders the full and the short row forms", "[live][json]") {
    const std::string out =
        "proc|100|sshd|aabbcc|/usr/sbin/sshd\n"
        "proc|200|bash|ddeeff\n"
        "proc|300|init\n";
    const auto r = live::live_result_json("processes", out);
    REQUIRE(r);
    CHECK(r->count == 3);
    CHECK_FALSE(r->truncated);
    const auto j = json::parse(r->body);
    CHECK(j["kind"] == "processes");
    REQUIRE(j["processes"].size() == 3);
    CHECK(j["processes"][0] == json{{"pid", 100}, {"name", "sshd"}, {"sha256", "aabbcc"}, {"path", "/usr/sbin/sshd"}});
    CHECK(j["processes"][1] == json{{"pid", 200}, {"name", "bash"}, {"sha256", "ddeeff"}, {"path", ""}});
    CHECK(j["processes"][2] == json{{"pid", 300}, {"name", "init"}, {"sha256", ""}, {"path", ""}});
    // Row key order is part of the wire shape.
    CHECK(r->body.find(R"({"kind":"processes","processes":[{"pid":100,"name":"sshd","sha256":"aabbcc","path":"/usr/sbin/sshd"})") == 0);
}

TEST_CASE("live_result_json: empty processes output is an empty list, not an error", "[live][json]") {
    const auto r = live::live_result_json("processes", "");
    REQUIRE(r);
    CHECK(r->body == R"({"kind":"processes","processes":[]})");
    CHECK(r->count == 0);
    CHECK_FALSE(r->truncated);
}

TEST_CASE("live_result_json: row cap cuts the rows and sets truncated", "[live][json]") {
    std::string out;
    for (int i = 1; i <= 25; ++i)
        out += "proc|" + std::to_string(i) + "|p" + std::to_string(i) + "\n";

    SECTION("no cap (REST) keeps every row") {
        const auto r = live::live_result_json("processes", out, 0);
        REQUIRE(r);
        CHECK(r->count == 25);
        CHECK_FALSE(r->truncated);
    }
    SECTION("a cap below the row count truncates to the first rows") {
        const auto r = live::live_result_json("processes", out, 10);
        REQUIRE(r);
        CHECK(r->count == 10);
        CHECK(r->truncated);
        const auto j = json::parse(r->body);
        REQUIRE(j["processes"].size() == 10);
        CHECK(j["processes"][0]["pid"] == 1);
        CHECK(j["processes"][9]["pid"] == 10);
    }
    SECTION("a cap equal to the row count is not truncation") {
        const auto r = live::live_result_json("processes", out, 25);
        REQUIRE(r);
        CHECK(r->count == 25);
        CHECK_FALSE(r->truncated);
    }
    SECTION("a cap above the row count is not truncation") {
        const auto r = live::live_result_json("processes", out, 1000);
        REQUIRE(r);
        CHECK(r->count == 25);
        CHECK_FALSE(r->truncated);
    }
}

TEST_CASE("live_result_json: a kind other than the two rest_v1 kinds is refused, never rendered as processes",
          "[live][json]") {
    // process_tree and services are real dashboard kinds but not rest_v1.
    CHECK_FALSE(live::live_result_json("process_tree", "proc|1|a|b|c|d\n"));
    CHECK_FALSE(live::live_result_json("services", ""));
    CHECK_FALSE(live::live_result_json("", ""));
    CHECK_FALSE(live::live_result_json("UPTIME", ""));
    CHECK_FALSE(live::live_result_json("nope", "proc|1|a\n"));
}

TEST_CASE("live_result_json: the served kinds are exactly the rest_v1 rows of the kind table", "[live][json]") {
    // If a kind is flagged rest_v1 in live_model without teaching the builder, this fails.
    for (const char* kind : {"uptime", "processes"}) {
        CAPTURE(kind);
        REQUIRE(live::resolve_rest_kind(kind));
        CHECK(live::live_result_json(kind, ""));
    }
}

TEST_CASE("live_result_json: agent bytes that are not valid UTF-8 never make invalid JSON", "[live][json]") {
    const std::string out = std::string("proc|7|bad\xff") + "name|ab|/p\xc3\n";
    const auto r = live::live_result_json("processes", out);
    REQUIRE(r);
    CHECK_NOTHROW(json::parse(r->body));
}

TEST_CASE("live_result_json: quotes, backslashes and controls in a field are escaped", "[live][json]") {
    const auto r = live::live_result_json("processes", "proc|9|a\"b\\c|h|/p\ta\n");
    REQUIRE(r);
    const auto j = json::parse(r->body);
    CHECK(j["processes"][0]["name"] == "a\"b\\c");
    CHECK(j["processes"][0]["path"] == "/p\ta");
}
