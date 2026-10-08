/**
 * test_instruction_canonical_schema.cpp - instr::canonicalise_param_schema(), the canonical
 * JSON-Schema form of a stored `parameter_schema` that discovery publishes as `input_schema`.
 *
 * PG-free and route-free. The point of the accessor is that discovery and enforcement share ONE
 * canonicaliser, so these cases pin (a) what it produces, (b) that it agrees with
 * prepare_param_validator() on the limits and on every shipped definition, and (c) that it does
 * not compile RE2 patterns. No test asserts a wall-clock bound.
 */

#include "bundled_content.hpp"
#include "instruction_param_schema.hpp"
#include "mcp_input_schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using nlohmann::json;
using namespace yuzu::server::instr;

namespace {

json canonical_of(const std::string& stored) {
    auto r = canonicalise_param_schema(stored);
    if (!r)
        FAIL("canonicalise failed: " << (r.error().empty() ? "(no detail)" : r.error().front()));
    if (!*r)
        FAIL("expected a schema, got the no-schema form");
    return **r;
}

// "n" is an int32 with a display name (DSL-only keyword), inline-required.
const std::string kInt32Schema =
    R"({"type":"object","properties":{"n":{"type":"int32","displayName":"Count",)"
    R"("description":"how many","required":true}}})";

}  // namespace

TEST_CASE("canonical-schema: empty, whitespace and {} mean no schema stored",
          "[instr][param-schema][canonical]") {
    for (const char* stored : {"", "   \n\t ", "{}", "  {}  "}) {
        INFO("stored=[" << stored << "]");
        auto r = canonicalise_param_schema(stored);
        REQUIRE(r.has_value());
        CHECK_FALSE(r->has_value());
    }
}

TEST_CASE("canonical-schema: DSL types become JSON Schema, DSL-only keys are dropped",
          "[instr][param-schema][canonical]") {
    const json c = canonical_of(kInt32Schema);
    CHECK(c["type"] == "object");
    CHECK(c.value("additionalProperties", true) == false);
    CHECK(c["required"] == json::array({"n"}));
    const json& n = c["properties"]["n"];
    CHECK(n["type"] == "integer");  // int32 is not a JSON Schema type
    CHECK(n["minimum"] == -2147483648LL);
    CHECK(n["maximum"] == 2147483647LL);
    CHECK(n["description"] == "how many");
    CHECK_FALSE(n.contains("displayName"));
    CHECK_FALSE(n.contains("required"));  // hoisted to the root
}

TEST_CASE("canonical-schema: the published schema decides what the validator decides",
          "[instr][param-schema][canonical]") {
    // The canonical object compiled by the shared MCP compiler and the validator built from the
    // same stored text agree on the int32 boundary and on a missing required name.
    auto compiled = yuzu::server::mcp::compile_input_schema(canonical_of(kInt32Schema).dump());
    REQUIRE(compiled.has_value());
    auto validator = prepare_param_validator(kInt32Schema);
    REQUIRE(validator.has_value());

    const std::vector<json> probes = {
        json{{"n", 2147483647LL}},   // top of the range: accepted
        json{{"n", 2147483648LL}},   // one past: refused
        json{{"n", -2147483648LL}},  // bottom: accepted
        json{{"n", -2147483649LL}},  // one below: refused
        json::object(),              // required name missing: refused
        json{{"n", 1}, {"x", 2}},    // undeclared name: refused
    };
    for (const auto& p : probes) {
        INFO("params=" << p.dump());
        CHECK(compiled->validate(p).has_value() == validator->check(p).has_value());
    }
    CHECK_FALSE(validator->check(probes[0]).has_value());
    CHECK(validator->check(probes[1]).has_value());
    CHECK(validator->check(probes[4]).has_value());
}

TEST_CASE("canonical-schema: patterns are carried but never compiled",
          "[instr][param-schema][canonical]") {
    // "(" is not a valid RE2 pattern: enforcement refuses the schema, canonicalisation does not
    // look (this is what keeps discovery cheap per request).
    const std::string bad_pattern =
        R"({"type":"object","properties":{"p":{"type":"string","pattern":"("}}})";
    CHECK_FALSE(prepare_param_validator(bad_pattern).has_value());
    const json c = canonical_of(bad_pattern);
    CHECK(c["properties"]["p"]["pattern"] == "(");

    // datetime and guid get their fixed pattern without sizing it.
    const json dt = canonical_of(
        R"({"type":"object","properties":{"when":{"type":"datetime"},"id":{"type":"guid"}}})");
    CHECK(dt["properties"]["when"]["type"] == "string");
    CHECK(dt["properties"]["when"].contains("pattern"));
    CHECK(dt["properties"]["id"].contains("pattern"));

    // The pattern length cap is a shape limit, so it still applies.
    const std::string long_pattern(1025, 'a');
    auto r = canonicalise_param_schema(
        R"({"type":"object","properties":{"p":{"type":"string","pattern":")" + long_pattern +
        R"("}}})");
    REQUIRE_FALSE(r.has_value());
}

TEST_CASE("canonical-schema: the limits and errors are the enforcement path's own",
          "[instr][param-schema][canonical]") {
    std::string many = R"({"type":"object","properties":{)";
    for (int i = 0; i < 129; ++i)
        many += (i ? "," : "") + std::string("\"p") + std::to_string(i) + "\":{\"type\":\"string\"}";
    many += "}}";

    std::string deep = R"({"type":"object","x":)";
    for (int i = 0; i < 40; ++i)
        deep += "[";
    for (int i = 0; i < 40; ++i)
        deep += "]";
    deep += "}";

    const std::vector<std::string> bad = {
        std::string(kMaxParameterSchemaBytes + 1, ' ') + "{}",     // over the raw-size cap
        deep,                                                       // over the depth cap
        "not json",                                                 // not JSON
        "[1,2]",                                                    // not an object
        R"({"properties":{"p":{"type":"string"}}})",                // no root type
        R"({"type":"object","properties":{"p":{"type":"nope"}}})",  // unknown type
        R"({"type":"object","properties":{"p":{"type":"string"}},"required":["q"]})",
        many,                                                       // too many properties
    };
    for (const auto& stored : bad) {
        INFO("stored size=" << stored.size());
        auto canonical = canonicalise_param_schema(stored);
        auto prepared = prepare_param_validator(stored);
        REQUIRE_FALSE(canonical.has_value());
        REQUIRE_FALSE(prepared.has_value());
        CHECK(canonical.error() == prepared.error());
    }
}

TEST_CASE("canonical-schema: every shipped definition canonicalises exactly when it prepares",
          "[instr][param-schema][canonical]") {
    std::size_t with_schema = 0;
    for (const auto& raw : yuzu::server::kBundledDefinitions) {
        const json env = json::parse(raw, nullptr, false);
        REQUIRE_FALSE(env.is_discarded());
        const std::string id = env.value("id", std::string{});
        const std::string stored =
            (env.contains("parameter_schema") && env["parameter_schema"].is_string())
                ? env["parameter_schema"].get<std::string>()
                : std::string{};
        INFO("definition " << id);

        auto prepared = prepare_param_validator(stored);
        auto canonical = canonicalise_param_schema(stored);
        REQUIRE(prepared.has_value());
        REQUIRE(canonical.has_value());
        CHECK(canonical->has_value() == !prepared->absent());
        if (canonical->has_value()) {
            ++with_schema;
            CHECK((**canonical).value("additionalProperties", true) == false);
            CHECK(yuzu::server::mcp::compile_input_schema((**canonical).dump()).has_value());
        }
    }
    CHECK(with_schema > 0);
}
