/**
 * test_instruction_param_schema.cpp - the pure server-side validator for an
 * InstructionDefinition's stored `parameter_schema` (instruction_param_schema.*).
 *
 * PG-free and route-free: every case drives prepare_param_validator() and
 * ParamValidator::check() or ParamValidatorCache directly. No test asserts a wall-clock
 * bound: the debug RE2 these tests link is far slower than release.
 */

#include "bundled_content.hpp"
#include "instruction_param_schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <re2/re2.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using nlohmann::json;
using namespace yuzu::server::instr;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::string joined(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v)
        out += s + "\n";
    return out;
}

ParamValidator build(const std::string& schema) {
    auto r = prepare_param_validator(schema);
    if (!r)
        FAIL("prepare failed: " << joined(r.error()));
    return std::move(*r);
}

// `schema` is refused AND one error carries `fragment`: pins WHICH rule fired.
void refused(const std::string& schema, const std::string& fragment) {
    auto r = prepare_param_validator(schema);
    REQUIRE_FALSE(r.has_value());
    INFO("fragment=" << fragment << " got=" << joined(r.error()));
    CHECK(has(joined(r.error()), fragment));
}

// {type:object, properties:{p: <prop>}}
std::string one_prop(const std::string& prop_json) {
    return R"({"type":"object","properties":{"p":)" + prop_json + "}}";
}

std::string prop(const json& p) {
    return one_prop(p.dump());
}

bool accepts(const std::string& prop_json, const json& value) {
    return !build(one_prop(prop_json)).check(json{{"p", value}}).has_value();
}

// N properties p0..pN-1, each `{type:string, pattern:<pattern>}` (and `extra` merged in).
std::string many_props(std::size_t n, const std::string& pattern,
                       const json& extra = json::object()) {
    json props = json::object();
    for (std::size_t i = 0; i < n; ++i) {
        json p = {{"type", "string"}, {"pattern", pattern}};
        p.update(extra);
        props["p" + std::to_string(i)] = p;
    }
    return json{{"type", "object"}, {"properties", props}}.dump();
}

std::size_t program_size(const std::string& pattern) {
    RE2::Options o;
    o.set_max_mem(yuzu::server::mcp::kPatternMaxMem);
    const RE2 re(pattern, o);
    REQUIRE(re.ok());
    return static_cast<std::size_t>(re.ProgramSize());
}

// `a{1000}` repeated `reps` times, then `a{tail}`: a single-byte pattern whose RE2 program
// size is exactly 1000 * reps + tail + 4.
std::string rep_pattern(int reps, int tail = 0) {
    std::string p;
    for (int i = 0; i < reps; ++i)
        p += "a{1000}";
    if (tail > 0)
        p += "a{" + std::to_string(tail) + "}";
    return p;
}

}  // namespace

TEST_CASE("param-schema: absent forms skip validation", "[instr][param-schema]") {
    for (const char* text : {"", "  \n\t", "{}", " {} "}) {
        INFO("stored=[" << text << "]");
        auto v = build(text);
        CHECK(v.absent());
        CHECK_FALSE(v.check(json{{"anything", 1}}).has_value());
        CHECK_FALSE(v.check(json::array({1})).has_value());
    }
    CHECK_FALSE(build(R"({"type":"object"})").absent());
}

TEST_CASE("param-schema: malformed stored schemas are errors", "[instr][param-schema]") {
    refused("not json", "not valid JSON");
    refused("[]", "not a JSON object");
    refused("null", "not a JSON object");
    refused(R"({"properties":{}})", "'type' must be \"object\"");  // lost its type: fail closed
    refused(R"({"type":"array"})", "'type' must be \"object\"");
    refused(R"({"type":"object","examples":[]})", "unsupported keyword");
    refused(R"({"type":"object","required":"p"})", "'required' must be an array");
    refused(R"({"type":"object","required":["nope"]})", "not a declared parameter");
    refused(R"({"type":"object","required":[1]})", "entries must be strings");
    refused(std::string(R"({"type":"object","properties":)") + std::string(200, '[') + "}",
            "nests deeper");
    const std::vector<std::pair<std::string, std::string>> props = {
        {R"({"type":"number"})", "unsupported type"},
        {R"({"type":"object"})", "unsupported type"},
        {R"({})", "'type' is missing"},
        {R"({"type":"string","oneOf":[]})", "unsupported keyword"},
        {R"({"type":"string","validation":{"format":"x"}})", "'validation' has an unsupported"},
        {R"({"type":"string","validation":5})", "'validation' must be an object"},
        {R"({"type":"integer","enum":["a"]})", "only supported on string-typed"},
        {R"({"type":"string","enum":[1]})", "non-empty array of strings"},
        {R"({"type":"string","enum":[]})", "non-empty array of strings"},
        {R"({"type":"string","required":"yes"})", "inline 'required' must be a boolean"},
        {R"({"type":"string","items":{"type":"string"}})", "only supported on array"},
        {R"({"type":"array","items":{"type":"integer"}})", "only supported item type"},
        {R"({"type":"array","items":{"type":"string","minimum":1}})", "'items' has an unsupported"},
        {R"({"type":"datetime","pattern":"x"})", "not allowed on a datetime or guid"},
        {R"({"type":"string","pattern":"("})", "'pattern' does not compile as RE2"},
        {R"({"type":"string","minimum":1})", "minimum"},
    };
    for (const auto& [p, fragment] : props) {
        INFO(p);
        refused(one_prop(p), fragment);
    }
}

TEST_CASE("param-schema: names are restricted and never echoed", "[instr][param-schema]") {
    const std::string secret = "SECRET NAME";  // space: not a legal name
    refused(json{{"type", "object"}, {"properties", {{secret, {{"type", "string"}}}}}}.dump(),
            "a parameter name is not");
    auto r = prepare_param_validator(
        json{{"type", "object"}, {"properties", {{secret, {{"type", "string"}}}}}}.dump());
    CHECK_FALSE(has(joined(r.error()), "SECRET"));
    for (const char* ok : {"a", "A_1", "x.y-z", "_u"})
        CHECK(prepare_param_validator(json{{"type", "object"},
                                           {"properties", {{ok, {{"type", "string"}}}}}}.dump())
                  .has_value());
    for (const std::string& bad : {std::string(""), std::string(65, 'a'), std::string("-a"),
                                  std::string(".a"), std::string("a=b"), std::string("a\nb")})
        CHECK_FALSE(prepare_param_validator(json{{"type", "object"},
                                                 {"properties", {{bad, {{"type", "string"}}}}}}.dump())
                        .has_value());
    CHECK(prepare_param_validator(json{{"type", "object"},
                                       {"properties", {{std::string(64, 'a'), {{"type", "string"}}}}}}
                                      .dump())
              .has_value());
}

TEST_CASE("param-schema: declared-empty rejects any param, undeclared reports /*",
          "[instr][param-schema]") {
    for (const char* text : {R"({"type":"object"})", R"({"type":"object","properties":{}})"}) {
        const auto v = build(text);
        CHECK_FALSE(v.check(json::object()).has_value());
        CHECK_FALSE(v.check(nullptr).has_value());
        const auto bad = v.check(json{{"SECRET-KEY", "SECRET-VALUE"}});
        REQUIRE(bad.has_value());
        CHECK(bad->path == "/*");
        CHECK_FALSE(has(bad->reason, "SECRET"));
    }
    // An undeclared key next to declared ones is reported, last, and still never echoed.
    const auto v = build(one_prop(R"({"type":"string"})"));
    const auto bad = v.check(json{{"p", "ok"}, {"junk", "SECRET"}});
    REQUIRE(bad.has_value());
    CHECK(bad->path == "/*");
}

TEST_CASE("param-schema: a moved-from validator is not absent and never passes",
          "[instr][param-schema]") {
    auto v = build(one_prop(R"({"type":"string"})"));
    CHECK_FALSE(v.check(json::object()).has_value());  // a live validator passes an empty object
    const ParamValidator taken = std::move(v);
    CHECK_FALSE(taken.absent());
    CHECK_FALSE(taken.check(json::object()).has_value());
    // NOLINTBEGIN(bugprone-use-after-move): the moved-from contract is what is under test
    CHECK_FALSE(v.absent());
    CHECK(v.check(json::object()).has_value());
    // NOLINTEND(bugprone-use-after-move)
}

TEST_CASE("param-schema: params must be an object, null reads as empty", "[instr][param-schema]") {
    const auto v = build(R"({"type":"object","properties":{"p":{"type":"string"}},"required":["p"]})");
    for (const json& bad : {json::array(), json("x"), json(5), json(true)}) {
        const auto r = v.check(bad);
        REQUIRE(r.has_value());
        CHECK(r->path.empty());
    }
    const auto missing = v.check(nullptr);  // null == omitted: required still applies
    REQUIRE(missing.has_value());
    CHECK(missing->path.empty());  // a missing property is reported at the root, by name
    CHECK(has(missing->reason, "'p'"));
}

TEST_CASE("param-schema: flat keys beat nested validation, inline required hoists, default "
          "satisfies required",
          "[instr][param-schema]") {
    const auto v = build(R"({"type":"object","properties":{
        "n":{"type":"string","maxLength":3,"validation":{"maxLength":10,"minLength":2}},
        "r":{"type":"string","required":true},
        "d":{"type":"string","default":"x"}},
        "required":["n","d"]})");
    CHECK_FALSE(v.check(json{{"n", "abc"}, {"r", "x"}}).has_value());     // flat maxLength 3 wins
    CHECK(v.check(json{{"n", "abcd"}, {"r", "x"}}).has_value());
    CHECK(v.check(json{{"n", "a"}, {"r", "x"}}).has_value());             // nested minLength kept
    CHECK(v.check(json{{"n", "abc"}}).has_value());                       // inline required r
    CHECK(v.check(json{{"r", "x"}}).has_value());                         // n required, no default
    // `d` has a default: omission is fine, a supplied value is still validated, and nothing
    // is injected into the caller's JSON.
    json params = {{"n", "abc"}, {"r", "x"}};
    const json before = params;
    CHECK_FALSE(v.check(params).has_value());
    CHECK(params == before);
    CHECK(v.check(json{{"n", "abc"}, {"r", "x"}, {"d", 5}}).has_value() == false);  // 5 -> "5"
}

TEST_CASE("param-schema: integer, int32, boolean and string coercion", "[instr][param-schema]") {
    SECTION("int32 range") {
        const auto v = build(one_prop(R"({"type":"int32"})"));
        CHECK_FALSE(v.check(json{{"p", 2147483647}}).has_value());
        CHECK_FALSE(v.check(json{{"p", -2147483648LL}}).has_value());
        CHECK(v.check(json{{"p", 2147483648LL}}).has_value());
        CHECK(v.check(json{{"p", -2147483649LL}}).has_value());
        CHECK(v.check(json{{"p", "2147483648"}}).has_value());
        // A declared bound is tightened, never loosened.
        const auto t = build(one_prop(R"({"type":"int32","minimum":5,"maximum":9})"));
        CHECK_FALSE(t.check(json{{"p", 9}}).has_value());
        CHECK(t.check(json{{"p", 10}}).has_value());
        const auto loose = build(one_prop(R"({"type":"int32","maximum":99999999999})"));
        CHECK(loose.check(json{{"p", 2147483648LL}}).has_value());
    }
    SECTION("integer string forms") {
        const auto v = build(one_prop(R"({"type":"integer"})"));
        for (const json& ok : {json("5"), json("-5"), json("007"), json("-0"), json(5),
                              json("9223372036854775807"), json("-9223372036854775808")})
            CHECK_FALSE(v.check(json{{"p", ok}}).has_value());
        for (const json& bad : {json("+5"), json(" 5"), json("5 "), json("5.0"), json(""), json("-"),
                               json("0x10"), json("1e2"), json("\xD9\xA3"), json(5.0), json(5.5),
                               json(nullptr), json(true), json("9223372036854775808"),
                               json("123456789012345678901")})
            CHECK(v.check(json{{"p", bad}}).has_value());
    }
    SECTION("boolean forms") {
        const auto v = build(one_prop(R"({"type":"boolean"})"));
        for (const json& ok : {json(true), json(false), json("true"), json("false")})
            CHECK_FALSE(v.check(json{{"p", ok}}).has_value());
        for (const json& bad : {json("True"), json("1"), json("yes"), json(""), json(1), json(nullptr)})
            CHECK(v.check(json{{"p", bad}}).has_value());
    }
    SECTION("string kinds take JSON numbers and bools as their string form, refuse null") {
        CHECK(accepts(R"({"type":"string","pattern":"^[0-9]+$"})", 42));
        CHECK(accepts(R"({"type":"string","enum":["true","false"]})", true));
        CHECK_FALSE(accepts(R"({"type":"string","enum":["true","false"]})", "True"));
        for (const char* p : {R"({"type":"string"})", R"({"type":"string","enum":["a"]})",
                              R"({"type":"string","pattern":"^a*$"})", R"({"type":"datetime"})",
                              R"({"type":"guid"})"})
            CHECK_FALSE(accepts(p, nullptr));
    }
}

TEST_CASE("param-schema: constraints, arrays, datetime and guid", "[instr][param-schema]") {
    const auto v = build(one_prop(R"({"type":"integer","minimum":1,"maximum":10})"));
    auto bad = v.check(json{{"p", 11}});
    REQUIRE(bad.has_value());
    CHECK(bad->path == "/p");
    CHECK_FALSE(has(bad->reason, "11"));
    CHECK_FALSE(v.check(json{{"p", "10"}}).has_value());

    const auto arr = build(one_prop(R"({"type":"array","items":{"type":"string","enum":["a","b"]}})"));
    CHECK_FALSE(arr.check(json{{"p", json::array({"a", "b"})}}).has_value());
    const auto el = arr.check(json{{"p", json::array({"a", "z"})}});
    REQUIRE(el.has_value());
    CHECK(el->path == "/p/1");
    CHECK(arr.check(json{{"p", "a"}}).has_value());
    CHECK(arr.check(json{{"p", json::array({1})}}).has_value());
    CHECK(arr.check(json{{"p", nullptr}}).has_value());

    for (const char* ok : {"2026-01-02T03:04:05Z", "2026-01-02T03:04:05.123+01:00",
                           "2026-12-31T23:59:60-05:30"})
        CHECK(accepts(R"({"type":"datetime"})", ok));
    for (const char* no : {"2026-01-02", "2026-01-02T03:04:05", "2026-01-02 03:04:05Z",
                           "2026-13-02T03:04:05Z", "2026-01-02T24:00:00Z", "2026-01-02T03:04:05Z\n"})
        CHECK_FALSE(accepts(R"({"type":"datetime"})", no));
    CHECK(accepts(R"({"type":"guid"})", "123e4567-E89B-12d3-a456-426614174000"));
    CHECK_FALSE(accepts(R"({"type":"guid"})", "{123e4567-e89b-12d3-a456-426614174000}"));
    CHECK_FALSE(accepts(R"({"type":"guid"})", "123e4567e89b12d3a456426614174000"));
}

TEST_CASE("param-schema: an embedded NUL is rejected at the top level, in arrays and in defaults",
          "[instr][param-schema][nul]") {
    const std::string nul = std::string("a") + '\0' + "b";
    const auto s = build(R"({"type":"object","properties":{
        "p":{"type":"string"},"q":{"type":"array","items":{"type":"string"}}}})");
    const auto top = s.check(json{{"p", nul}});
    REQUIRE(top.has_value());
    CHECK(top->path == "/p");
    CHECK(has(top->reason, "NUL"));
    const auto in_array = s.check(json{{"q", json::array({"ok", nul})}});
    REQUIRE(in_array.has_value());
    CHECK(in_array->path == "/q/1");
    CHECK_FALSE(s.check(json{{"p", "ab"}, {"q", json::array({"ok"})}}).has_value());
    refused(prop(json{{"type", "string"}, {"default", nul}}), "'default' is not accepted");
}

TEST_CASE("param-schema limits: raw text, property, enum and pattern-length caps",
          "[instr][param-schema][limits]") {
    const std::string marker = "SECRET-SCHEMA-MARKER";
    const std::string base = R"({"type":"object","description":")" + marker + R"("})";
    auto padded = [&](std::size_t total) {
        std::string s = base;
        s.append(total - s.size(), ' ');
        return s;
    };
    CHECK(prepare_param_validator(padded(kMaxParameterSchemaBytes)).has_value());
    auto over = prepare_param_validator(padded(kMaxParameterSchemaBytes + 1));
    REQUIRE_FALSE(over.has_value());
    REQUIRE(over.error().size() == 1);
    CHECK(has(over.error()[0], std::to_string(kMaxParameterSchemaBytes)));
    CHECK_FALSE(has(over.error()[0], marker));
    CHECK_FALSE(prepare_param_validator(std::string(kMaxParameterSchemaBytes + 1, ' ')).has_value());
    CHECK(prepare_param_validator(std::string(kMaxParameterSchemaBytes, ' '))->absent());

    auto with_props = [](std::size_t n) {
        json props = json::object();
        for (std::size_t i = 0; i < n; ++i)
            props["p" + std::to_string(i)] = json{{"type", "string"}};
        return json{{"type", "object"}, {"properties", props}};
    };
    CHECK(prepare_param_validator(with_props(kMaxSchemaProperties).dump()).has_value());
    refused(with_props(kMaxSchemaProperties + 1).dump(),
            "more than " + std::to_string(kMaxSchemaProperties) + " properties");
    json beyond = with_props(kMaxSchemaProperties + 1);
    beyond["required"] = json::array({"p0"});  // not reported as undeclared
    auto r = prepare_param_validator(beyond.dump());
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(has(joined(r.error()), "not a declared"));

    auto enum_of = [](std::size_t n) {
        json e = json::array();
        for (std::size_t i = 0; i < n; ++i)
            e.push_back("m" + std::to_string(i));
        return e;
    };
    CHECK(prepare_param_validator(prop({{"type", "string"}, {"enum", enum_of(kMaxEnumMembers)}})).has_value());
    refused(prop({{"type", "string"}, {"enum", enum_of(kMaxEnumMembers + 1)}}),
            "'enum' has more than " + std::to_string(kMaxEnumMembers));
    refused(prop({{"type", "string"}, {"validation", {{"enum", enum_of(kMaxEnumMembers + 1)}}}}),
            "'enum' has more than");
    auto items = [&](std::size_t n) {
        return prop({{"type", "array"}, {"items", {{"type", "string"}, {"enum", enum_of(n)}}}});
    };
    CHECK(prepare_param_validator(items(kMaxEnumMembers)).has_value());
    refused(items(kMaxEnumMembers + 1), "'items' enum has more than");

    const std::string pat_marker = "SECRETPAT";
    auto pattern_of = [&](std::size_t n) {
        std::string p = pat_marker;
        p.append(n - p.size(), 'a');
        return p;
    };
    CHECK(prepare_param_validator(prop({{"type", "string"}, {"pattern", pattern_of(kMaxPatternBytes)}}))
              .has_value());
    refused(prop({{"type", "string"}, {"pattern", pattern_of(kMaxPatternBytes + 1)}}),
            "'pattern' is longer than " + std::to_string(kMaxPatternBytes));
    CHECK(prepare_param_validator(
              prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", std::string(kMaxPatternBytes, 'a')}}}}))
              .has_value());
    refused(prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", std::string(kMaxPatternBytes + 1, 'a')}}}}),
            "'items' pattern is longer than");
    auto e = prepare_param_validator(prop({{"type", "string"}, {"pattern", pattern_of(kMaxPatternBytes + 1)}}));
    CHECK_FALSE(has(joined(e.error()), pat_marker));
}

TEST_CASE("param-schema limits: integer bounds must be strictly inside 2^53",
          "[instr][param-schema][limits]") {
    for (const char* key : {"minimum", "maximum"}) {
        auto schema = [&](const std::string& v) {
            return one_prop(std::string(R"({"type":"integer",")") + key + R"(":)" + v + "}");
        };
        for (const char* ok : {"9007199254740991", "-9007199254740991", "0"})
            CHECK(prepare_param_validator(schema(ok)).has_value());
        for (const char* bad : {"9007199254740992", "-9007199254740992", "9007199254740992.0",
                                "18446744073709551615", "1e300"})
            refused(schema(bad), "exactly representable");
    }
    refused(one_prop(R"({"type":"int64","validation":{"maximum":9007199254740992}})"),
            "exactly representable");
    // int64 VALUES stay exact: only bounds are limited.
    const auto v = build(one_prop(R"({"type":"integer"})"));
    CHECK_FALSE(v.check(json{{"p", "9223372036854775807"}}).has_value());
}

TEST_CASE("param-schema limits: pattern program size, per-pattern and per-schema",
          "[instr][param-schema][limits][patterns]") {
    // The shipped-size patterns and the fixed ones stay accepted.
    CHECK(prepare_param_validator(prop({{"type", "string"}, {"pattern", "^[A-Za-z0-9._-]{1,256}$"}})).has_value());
    CHECK(prepare_param_validator(prop({{"type", "datetime"}})).has_value());

    // Exactly kMaxPatternProgramSize instructions is accepted, one more is refused.
    const std::string at_cap = rep_pattern(32, 764);
    const std::string over_cap = rep_pattern(32, 765);
    REQUIRE(program_size(at_cap) == kMaxPatternProgramSize);
    REQUIRE(program_size(over_cap) == kMaxPatternProgramSize + 1);
    CHECK(prepare_param_validator(prop({{"type", "string"}, {"pattern", at_cap}})).has_value());
    refused(prop({{"type", "string"}, {"pattern", "SECRETPAT" + over_cap}}),
            "compiles to a program larger than " + std::to_string(kMaxPatternProgramSize));

    // The per-schema sum: two patterns at the cap total exactly kMaxSchemaPatternProgramSize
    // and are accepted; a third (even a tiny one) is refused.
    static_assert(2 * kMaxPatternProgramSize == kMaxSchemaPatternProgramSize);
    json two = {{"type", "object"},
                {"properties", {{"a", {{"type", "string"}, {"pattern", at_cap}}},
                                {"b", {{"type", "string"}, {"pattern", at_cap}}}}}};
    CHECK(prepare_param_validator(two.dump()).has_value());
    two["properties"]["c"] = {{"type", "string"}, {"pattern", "^a$"}};
    refused(two.dump(), "compiled instructions in total");
}

TEST_CASE("param-schema limits: the RE2 memory budget and unusable patterns are refused cheaply",
          "[instr][param-schema][limits][patterns]") {
    // `\pL{300}` is 8 bytes but a ~359k-instruction program: refused by the memory budget
    // after ONE failed compile, so 128 of them yield one error entry and no pattern text.
    auto r = prepare_param_validator(many_props(128, R"(SECRETPAT\pL{300})"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().size() == 1);
    CHECK(has(joined(r.error()), "bytes of RE2 memory to compile"));
    CHECK_FALSE(has(joined(r.error()), "SECRETPAT"));
    refused(prop({{"type", "string"}, {"validation", {{"pattern", R"(\pL{300})"}}}}),
            "'pattern' needs more than");
    refused(prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", R"(\pL{300})"}}}}),
            "'items' pattern needs more than");
    refused(prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", "SECRETPAT("}}}}),
            "'items' pattern does not compile as RE2");
    refused(many_props(2, "^(.{1000}){50}$"), "does not compile as RE2");
}

TEST_CASE("param-schema limits: the shared MCP compiler applies the RE2 memory budget too",
          "[instr][param-schema][limits][patterns]") {
    // Prepare pre-compiles every pattern under the budget, but the shared compiler compiles
    // it again and is what a cached validator retains, so it carries the budget itself.
    auto r = yuzu::server::mcp::compile_input_schema(
        R"({"type":"object","properties":{"p":{"type":"string","pattern":"\\pL{300}"}}})");
    REQUIRE_FALSE(r.has_value());
    CHECK(has(joined(r.error()), "does not compile as RE2"));
    CHECK(yuzu::server::mcp::compile_input_schema(
              R"({"type":"object","properties":{"p":{"type":"string","pattern":"^[a-z]+$"}}})")
              .has_value());
}

TEST_CASE("param-schema match cost: the matched-string cap and the work budget",
          "[instr][param-schema][limits][match]") {
    SECTION("a string matched against a pattern is capped at 64 KiB") {
        const auto v = build(prop({{"type", "string"}, {"pattern", "^[a-z]+$"}}));
        CHECK_FALSE(v.check(json{{"p", std::string(kMaxPatternMatchedStringBytes, 'a')}}).has_value());
        auto over = v.check(json{{"p", std::string(kMaxPatternMatchedStringBytes + 1, 'a')}});
        REQUIRE(over.has_value());
        CHECK(has(over->reason, std::to_string(kMaxPatternMatchedStringBytes)));
        CHECK_FALSE(has(over->reason, "aaaa"));
        // The fixed datetime pattern and an items pattern are covered too.
        CHECK(build(prop({{"type", "datetime"}})).check(json{{"p", std::string(70000, '1')}}).has_value());
        auto el = build(prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", "^[a-z]+$"}}}}))
                      .check(json{{"p", json::array({"ok", std::string(70000, 'a')})}});
        REQUIRE(el.has_value());
        CHECK(el->path == "/p/1");
        // A property WITHOUT a pattern keeps its own maxLength.
        CHECK_FALSE(build(prop({{"type", "string"}, {"maxLength", 131072}}))
                        .check(json{{"p", std::string(100000, 'a')}}).has_value());
    }
    SECTION("(bytes + 1) x program is budgeted across one params object, at the exact boundary") {
        // An array of n strings against `^[a-z]{1000}$`: element 0 is "z" (charged 2 x S, and
        // refused by the pattern at once) and the rest are empty (charged S each), so n
        // elements cost (n + 1) x S units. Matching the empty ones is never reached.
        const std::string pat = "^[a-z]{1000}$";
        const std::uint64_t S = program_size(pat);
        const auto v = build(prop({{"type", "array"}, {"items", {{"type", "string"}, {"pattern", pat}}}}));
        const std::uint64_t fits = kMaxPatternMatchWork / S - 1;  // (fits + 1) * S <= budget
        REQUIRE((fits + 1) * S <= kMaxPatternMatchWork);
        REQUIRE((fits + 2) * S > kMaxPatternMatchWork);
        auto arr = [&](std::uint64_t n) {
            json a = json::array_t(static_cast<std::size_t>(n), json(""));
            a[0] = "z";
            return json{{"p", a}};
        };
        auto at = v.check(arr(fits));
        REQUIRE(at.has_value());
        CHECK(has(at->reason, "required pattern"));  // the guard admitted it: the pattern refused
        auto over = v.check(arr(fits + 1));
        REQUIRE(over.has_value());
        CHECK(has(over->reason, "matching budget"));
        CHECK(over->path == "/p/" + std::to_string(fits));
    }
    SECTION("a string compared against an enum is charged one unit per member") {
        std::vector<std::string> members;
        for (std::size_t i = 0; i < kMaxEnumMembers; ++i)
            members.push_back("m" + std::to_string(i));
        const auto v = build(prop({{"type", "array"}, {"items", {{"type", "string"}, {"enum", members}}}}));
        const std::size_t fits = kMaxPatternMatchWork / kMaxEnumMembers;
        auto arr = [&](std::size_t n) { return json{{"p", json::array_t(n, json("m0"))}}; };
        CHECK_FALSE(v.check(arr(fits)).has_value());
        auto over = v.check(arr(fits + 1));
        REQUIRE(over.has_value());
        CHECK(has(over->reason, "matching budget"));
    }
}

TEST_CASE("param-schema defaults: validated, bounded, never echoed", "[instr][param-schema][defaults]") {
    const std::vector<std::string> bad = {
        R"({"type":"integer","default":"abc-SECRET"})",
        R"({"type":"integer","minimum":10,"default":5})",
        R"({"type":"int32","default":2147483648})",
        R"({"type":"string","enum":["a","b"],"default":"z-SECRET"})",
        R"({"type":"string","pattern":"^a+$","default":"xyz-SECRET"})",
        R"({"type":"string","maxLength":3,"default":"toolong-SECRET"})",
        R"({"type":"boolean","default":"maybe-SECRET"})",
        R"({"type":"array","default":"x-SECRET"})",
        R"({"type":"array","items":{"type":"string","enum":["a"]},"default":["b-SECRET"]})",
        R"({"type":"datetime","default":"yesterday-SECRET"})",
    };
    for (const auto& p : bad) {
        INFO(p);
        auto r = prepare_param_validator(one_prop(p));
        REQUIRE_FALSE(r.has_value());
        CHECK(has(joined(r.error()), "parameter 'p': 'default'"));
        CHECK_FALSE(has(joined(r.error()), "SECRET"));
    }
    for (const char* ok : {R"({"type":"integer","default":5})", R"({"type":"integer","default":"5"})",
                           R"({"type":"boolean","default":"false"})", R"({"type":"string","default":5})",
                           R"({"type":"string","enum":["a","b"],"default":"b"})",
                           R"({"type":"array","items":{"type":"string"},"default":["x"]})",
                           R"({"type":"guid","default":"123e4567-e89b-12d3-a456-426614174000"})"})
        CHECK(prepare_param_validator(one_prop(ok)).has_value());
    // A bad default fails the schema even when another required param exists.
    CHECK_FALSE(prepare_param_validator(R"({"type":"object","properties":{
        "p":{"type":"integer","default":"abc"},"q":{"type":"string"}},"required":["q"]})").has_value());

    // Defaults go through the same guard as a caller value: the matched-string cap, and ONE
    // work budget shared by every default of the schema. 16 defaults of 1000 chars against
    // `^[a-z]{1000}$` fit (1001 x S each); 17 do not.
    const std::string pat = "^[a-z]{1000}$";
    const std::uint64_t S = program_size(pat);
    REQUIRE(16 * 1001 * S <= kMaxPatternMatchWork);
    REQUIRE(17 * 1001 * S > kMaxPatternMatchWork);
    CHECK(prepare_param_validator(many_props(16, pat, {{"default", std::string(1000, 'a')}})).has_value());
    refused(many_props(17, pat, {{"default", std::string(1000, 'a')}}), "matching budget");
    refused(prop({{"type", "string"}, {"pattern", "^[a-z]+$"},
                  {"default", std::string(kMaxPatternMatchedStringBytes + 1, 'a')}}),
            "'default' is not accepted");
}

TEST_CASE("param-schema: check() leaves the caller's JSON untouched and violations never echo it",
          "[instr][param-schema]") {
    const auto v = build(R"({"type":"object","properties":{
        "i":{"type":"integer"},"s":{"type":"string","enum":["a"]}}})");
    json params = {{"i", "7"}, {"s", 5}, {"extra", "SECRET-EXTRA"}};
    const json before = params;
    const auto r = v.check(params);
    REQUIRE(r.has_value());
    CHECK(params == before);
    for (const json& bad : {json{{"i", "SECRET-VAL"}}, json{{"s", "SECRET-VAL"}},
                            json{{"SECRET-KEY", 1}}}) {
        const auto x = v.check(bad);
        REQUIRE(x.has_value());
        CHECK_FALSE(has(x->path + x->reason, "SECRET"));
    }
}

TEST_CASE("param-schema cache: hit, edit, failure, absent, oversize", "[instr][param-schema][cache]") {
    ParamValidatorCache cache;
    const std::string s1 = one_prop(R"({"type":"string"})");
    const std::string s2 = one_prop(R"({"type":"integer"})");

    auto a = cache.get("def-a", s1);
    REQUIRE(a.has_value());
    CHECK(cache.get("def-a", s1)->get() == a->get());  // a hit returns the same validator
    CHECK(cache.size() == 1);

    auto edited = cache.get("def-a", s2);  // an edited schema is a new key
    REQUIRE(edited.has_value());
    CHECK(edited->get() != a->get());
    CHECK((*edited)->check(json{{"p", "x"}}).has_value());
    CHECK_FALSE((*a)->check(json{{"p", "x"}}).has_value());  // the old validator stays usable
    CHECK(cache.get("def-b", s1)->get() != a->get());       // the id is part of the key

    const auto before = cache.size();
    CHECK_FALSE(cache.get("def-bad", "not json").has_value());
    CHECK_FALSE(cache.get("def-bad", "not json").has_value());
    CHECK(cache.get("def-abs", "{}")->get()->absent());
    CHECK(cache.size() == before);  // a failure and an absent validator are never cached

    const std::string huge(kMaxParameterSchemaBytes + 1, ' ');
    auto over = cache.get("def-over", huge);
    REQUIRE_FALSE(over.has_value());
    CHECK(has(joined(over.error()), std::to_string(kMaxParameterSchemaBytes)));
    CHECK(cache.size() == before);
}

TEST_CASE("param-schema cache: LRU eviction at the entry cap", "[instr][param-schema][cache]") {
    ParamValidatorCache cache(2);
    const std::string s = one_prop(R"({"type":"string"})");
    auto a = cache.get("a", s);
    auto b = cache.get("b", s);
    REQUIRE((a && b));
    CHECK(cache.get("a", s)->get() == a->get());  // touch a: b is now least recent
    auto c = cache.get("c", s);
    REQUIRE(c.has_value());
    CHECK(cache.size() == 2);
    CHECK(cache.get("a", s)->get() == a->get());   // survived
    CHECK(cache.get("b", s)->get() != b->get());   // evicted, rebuilt
    ParamValidatorCache one(0);
    REQUIRE(one.get("a", s).has_value());
    REQUIRE(one.get("b", s).has_value());
    CHECK(one.size() == 1);
}

TEST_CASE("param-schema cache: many threads first-calling one schema all get a validator",
          "[instr][param-schema][cache]") {
    ParamValidatorCache cache;
    const std::string s = one_prop(R"({"type":"integer","minimum":1})");
    std::atomic<int> bad{0};
    // Joins on scope exit: a throw while spawning workers leaves the already-started threads
    // joinable, and the destructor joins them.
    struct Joiner {
        std::vector<std::thread> ts;
        ~Joiner() {
            for (auto& t : ts)
                if (t.joinable())
                    t.join();
        }
    } pool;
    for (int t = 0; t < 12; ++t)
        pool.ts.emplace_back([&, t] {
            auto r = cache.get(t % 2 ? "x" : "y", s);
            if (!r || (*r)->absent() || (*r)->check(json{{"p", 5}}).has_value() ||
                !(*r)->check(json{{"p", 0}}).has_value())
                ++bad;
        });
    for (auto& t : pool.ts)
        t.join();
    CHECK(bad == 0);
    CHECK(cache.size() == 2);
}

namespace {

using yuzu::server::mcp::kPatternMaxMem;

std::size_t weight_of(const std::string& schema) {
    return build(schema).estimated_retained_bytes();
}

// `weight` is the documented formula, term by term.
std::size_t expected_weight(const std::string& schema, std::size_t props, std::size_t members,
                            std::size_t patterns) {
    return kParamValidatorFixedBytes + props * kParamValidatorPerPropertyBytes +
           members * kParamValidatorPerEnumMemberBytes + schema.size() +
           patterns * static_cast<std::size_t>(kPatternMaxMem);
}

// kMaxSchemaProperties array properties, each carrying one `items` pattern: the most patterns
// a schema may declare. `salt` lengthens one pattern so the text (so the cache key) differs.
std::string hostile_schema(std::size_t salt) {
    json props = json::object();
    for (std::size_t i = 0; i < kMaxSchemaProperties; ++i)
        props["p" + std::to_string(i)] = {
            {"type", "array"},
            {"items", {{"type", "string"}, {"pattern", "^a" + std::string(i == 0 ? salt : 0, 'b') + "$"}}}};
    return json{{"type", "object"}, {"properties", props}}.dump();
}

}  // namespace

TEST_CASE("param-schema weight: text plus fixed, per-property, per-enum-member and per-pattern terms",
          "[instr][param-schema][cache]") {
    const std::string plain = one_prop(R"({"type":"string"})");
    CHECK(weight_of(plain) == expected_weight(plain, 1, 0, 0));
    // A pattern-free schema weighs its text plus small allowances, nowhere near a pattern.
    CHECK(weight_of(plain) < static_cast<std::size_t>(kPatternMaxMem));

    const std::string enum2 = one_prop(R"({"type":"string","enum":["a","bb"]})");
    CHECK(weight_of(enum2) == expected_weight(enum2, 1, 2, 0));

    for (std::size_t n : {1u, 3u, 8u}) {
        const std::string s = many_props(n, "^a$");
        CHECK(weight_of(s) == expected_weight(s, n, 0, n));
        CHECK(weight_of(s) >= n * static_cast<std::size_t>(kPatternMaxMem));
    }
    // The fixed datetime and guid patterns are compiled per validator, and an array's `items`
    // pattern counts like a property's own.
    const std::string fixed = json{{"type", "object"},
                                   {"properties",
                                    {{"t", {{"type", "datetime"}}},
                                     {"g", {{"type", "guid"}}},
                                     {"a", {{"type", "array"},
                                            {"items", {{"type", "string"}, {"pattern", "x"}}}}}}}}
                                  .dump();
    CHECK(weight_of(fixed) == expected_weight(fixed, 3, 0, 3));

    // Surrounding whitespace is trimmed before the text is measured; absent weighs nothing.
    CHECK(weight_of("  " + plain + "\n") == expected_weight(plain, 1, 0, 0));
    CHECK(build("{}").estimated_retained_bytes() == 0);
    CHECK(build("").estimated_retained_bytes() == 0);

    // The most patterns a schema may declare weighs tens of MiB, never a few KiB.
    CHECK(weight_of(hostile_schema(0)) >=
          (kMaxSchemaProperties - 1) * static_cast<std::size_t>(kPatternMaxMem));
}

TEST_CASE("param-schema cache: eviction is by bytes, least recently used first",
          "[instr][param-schema][cache]") {
    const std::string s = one_prop(R"({"type":"string"})");
    const std::size_t w = weight_of(s);
    REQUIRE(w > 0);

    ParamValidatorCache cache(kParamValidatorCacheEntries, 2 * w + w / 2);
    auto a = cache.get("a", s);
    auto b = cache.get("b", s);
    REQUIRE((a && b));
    CHECK(cache.size() == 2);
    CHECK(cache.bytes() == 2 * w);

    CHECK(cache.get("a", s)->get() == a->get());  // touch a: b is now least recent
    auto c = cache.get("c", s);                    // 3w > budget: b goes
    REQUIRE(c.has_value());
    CHECK(cache.size() == 2);
    CHECK(cache.bytes() == 2 * w);
    CHECK(cache.get("a", s)->get() == a->get());  // survived
    CHECK(cache.get("c", s)->get() == c->get());
    CHECK(cache.get("b", s)->get() != b->get());  // evicted, rebuilt
    CHECK(cache.bytes() <= 2 * w + w / 2);

    // A heavier entry evicts the least recent light ones until the total fits again.
    const std::string two_enum = one_prop(R"({"type":"string","enum":["a","bb"]})");
    const std::size_t w2 = weight_of(two_enum);
    REQUIRE(w2 > w);
    REQUIRE(w + w2 <= 2 * w + w / 2);
    ParamValidatorCache mixed(kParamValidatorCacheEntries, 2 * w + w / 2);
    auto ma = mixed.get("a", s);
    auto mb = mixed.get("b", s);
    REQUIRE((ma && mb));
    REQUIRE(mixed.get("c", two_enum).has_value());  // 2w + w2 > budget: only a goes
    CHECK(mixed.size() == 2);
    CHECK(mixed.bytes() == w + w2);
    CHECK(mixed.get("b", s)->get() == mb->get());
    CHECK(mixed.get("a", s)->get() != ma->get());  // evicted, rebuilt
}

TEST_CASE("param-schema cache: an entry heavier than the whole budget is returned, not retained",
          "[instr][param-schema][cache]") {
    const std::string light = one_prop(R"({"type":"string"})");
    const std::string heavy = many_props(2, "^a$");  // two patterns
    const std::size_t w_light = weight_of(light);
    const std::size_t w_heavy = weight_of(heavy);
    REQUIRE(w_heavy > 4 * w_light);

    ParamValidatorCache cache(kParamValidatorCacheEntries, 2 * w_light);
    auto kept = cache.get("light", light);
    REQUIRE(kept.has_value());
    REQUIRE(cache.size() == 1);

    auto big = cache.get("heavy", heavy);
    REQUIRE(big.has_value());
    CHECK_FALSE((*big)->check(json{{"p0", "a"}, {"p1", "a"}}).has_value());  // fully usable
    CHECK((*big)->check(json{{"p0", "b"}}).has_value());
    CHECK(cache.size() == 1);                              // not retained
    CHECK(cache.bytes() == w_light);                       // nothing was evicted for it
    CHECK(cache.get("light", light)->get() == kept->get());  // the resident entry survived
    CHECK(cache.get("heavy", heavy)->get() != big->get());   // asking again rebuilds

    // A budget of exactly the entry's weight retains it; one byte less does not.
    ParamValidatorCache exact(kParamValidatorCacheEntries, w_light);
    REQUIRE(exact.get("a", light).has_value());
    CHECK(exact.size() == 1);
    ParamValidatorCache under(kParamValidatorCacheEntries, w_light - 1);
    REQUIRE(under.get("a", light).has_value());
    CHECK(under.size() == 0);
    CHECK(under.bytes() == 0);
    ParamValidatorCache none(kParamValidatorCacheEntries, 0);
    REQUIRE(none.get("a", light).has_value());
    CHECK(none.size() == 0);
}

TEST_CASE("param-schema cache: the entry ceiling is a safety net on top of the byte budget",
          "[instr][param-schema][cache]") {
    const std::string s = one_prop(R"({"type":"string"})");
    const std::size_t w = weight_of(s);
    ParamValidatorCache cache(2, 1000 * w);  // bytes would allow 1000 entries
    for (const char* id : {"a", "b", "c", "d"})
        REQUIRE(cache.get(id, s).has_value());
    CHECK(cache.size() == 2);
    CHECK(cache.bytes() == 2 * w);
    CHECK(kParamValidatorCacheEntries > 128);
}

TEST_CASE("param-schema cache: hostile max-pattern schemas cannot push the total past the budget",
          "[instr][param-schema][cache]") {
    ParamValidatorCache cache;  // the production bounds
    const std::string small = one_prop(R"({"type":"string"})");
    for (const char* id : {"s1", "s2", "s3"})
        REQUIRE(cache.get(id, small).has_value());

    std::size_t admitted = 0;
    for (std::size_t salt = 0; salt < 4; ++salt) {
        auto r = cache.get("hostile-" + std::to_string(salt), hostile_schema(salt));
        REQUIRE(r.has_value());
        CHECK_FALSE((*r)->check(json{{"p1", json::array({"a"})}}).has_value());
        CHECK(cache.bytes() <= kParamValidatorCacheMaxBytes);
        ++admitted;
    }
    // Each hostile schema weighs 128 patterns' worth, so they cannot all stay.
    CHECK(cache.size() < 3 + admitted);
    CHECK(cache.size() >= 1);
}

TEST_CASE("param-schema cache: the shipped catalogue fits in half the production budget",
          "[instr][param-schema][cache]") {
    ParamValidatorCache cache;
    std::size_t total = 0;
    std::size_t cached = 0;
    std::size_t definitions = 0;
    for (const auto& raw : yuzu::server::kBundledDefinitions) {
        const json env = json::parse(raw, nullptr, false);
        REQUIRE_FALSE(env.is_discarded());
        ++definitions;
        if (!env.contains("parameter_schema") || !env["parameter_schema"].is_string())
            continue;
        const auto id = env.value("id", std::string{});
        const auto schema = env["parameter_schema"].get<std::string>();
        auto r = cache.get(id, schema);
        REQUIRE(r.has_value());
        if ((*r)->absent())
            continue;
        total += (*r)->estimated_retained_bytes();
        ++cached;
    }
    INFO("definitions=" << definitions << " cached=" << cached << " total=" << total);
    REQUIRE(cached > 0);
    CHECK(total <= kParamValidatorCacheMaxBytes / 2);
    // Nothing was evicted: a catalogue sweep after the first pass would hit every entry.
    CHECK(cache.size() == cached);
    CHECK(cache.bytes() == total);
    CHECK(cached <= kParamValidatorCacheEntries);
}
