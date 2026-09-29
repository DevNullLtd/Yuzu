/**
 * test_response_templates_engine.cpp — unit coverage for the response-templates
 * engine introduced in issue #254 (Phase 8.2).
 *
 * Engine responsibilities the tests pin:
 *   - parse() round-trips storage-form JSON arrays, tolerates singular form,
 *     surfaces invalid JSON as an error
 *   - synthesise_default() prefers result_schema over plugin column lists
 *   - resolve() falls back to synthesised default for unknown / empty ids,
 *     prefers operator-marked default when no template_id is supplied
 *   - validate_payload() rejects __default__ as an authored id, missing name,
 *     unknown filter ops, id collisions, multiple is_default=true entries
 *   - serialise() output is consumable by parse() (round-trip)
 */

#include "response_templates_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

using namespace yuzu::server;

TEST_CASE("ResponseTemplatesEngine: parse empty / null / [] yields empty list",
          "[response_templates][engine][parse]") {
    ResponseTemplatesEngine eng;
    CHECK(eng.parse("").value().empty());
    CHECK(eng.parse("[]").value().empty());
    CHECK(eng.parse("{}").value().empty());
    CHECK(eng.parse("null").value().empty());
}

TEST_CASE("ResponseTemplatesEngine: parse rejects malformed JSON",
          "[response_templates][engine][parse][error]") {
    ResponseTemplatesEngine eng;
    auto r = eng.parse("not-a-json");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("not valid JSON") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: parse accepts a singular object form",
          "[response_templates][engine][parse]") {
    ResponseTemplatesEngine eng;
    auto r = eng.parse(R"({"id":"abc","name":"Solo"})");
    REQUIRE(r);
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].id == "abc");
    CHECK((*r)[0].name == "Solo");
}

TEST_CASE("ResponseTemplatesEngine: parse round-trips canonical array form",
          "[response_templates][engine][parse]") {
    ResponseTemplatesEngine eng;
    auto json_in = R"([
        {"id":"a","name":"A","columns":["X","Y"],
         "sort":{"column":"X","dir":"desc"},
         "filters":[{"column":"Y","op":"contains","value":"foo"}],
         "default":true},
        {"id":"b","name":"B"}
    ])";
    auto r = eng.parse(json_in);
    REQUIRE(r);
    REQUIRE(r->size() == 2);
    auto& t0 = (*r)[0];
    CHECK(t0.id == "a");
    CHECK(t0.name == "A");
    CHECK(t0.columns == std::vector<std::string>{"X", "Y"});
    CHECK(t0.sort_column == "X");
    CHECK(t0.sort_dir == "desc");
    REQUIRE(t0.filters.size() == 1);
    CHECK(t0.filters[0].column == "Y");
    CHECK(t0.filters[0].op == "contains");
    CHECK(t0.filters[0].value == "foo");
    CHECK(t0.is_default == true);
    CHECK((*r)[1].id == "b");
    CHECK((*r)[1].is_default == false);
}

TEST_CASE("ResponseTemplatesEngine: synthesise_default uses result_schema when present",
          "[response_templates][engine][default]") {
    ResponseTemplatesEngine eng;
    auto schema = R"([
        {"name":"hostname","type":"string"},
        {"name":"uptime","type":"int64"}
    ])";
    auto t = eng.synthesise_default(schema, "any-plugin");
    CHECK(t.id == ResponseTemplatesEngine::kDefaultId);
    CHECK(t.is_default == true);
    REQUIRE(t.columns.size() == 2);
    CHECK(t.columns[0] == "hostname");
    CHECK(t.columns[1] == "uptime");
    CHECK(t.sort_column.empty());
    CHECK(t.filters.empty());
}

TEST_CASE("ResponseTemplatesEngine: synthesise_default handles the "
          "object-wrapped 'columns' shape real content YAML produces "
          "(PR1.7 dashboard-rendering fix)",
          "[response_templates][engine][default]") {
    // embed_content.py's `env["result_schema"] = json.dumps(spec["result"])`
    // dumps the WHOLE `result:` YAML block, i.e. an object with a top-level
    // "columns" key -- not the bare array the other synthesise_default
    // tests above use (that bare-array shape is legacy_shim.cpp's
    // auto-generated-definition form, never what a real content/*.yaml
    // `result.columns:` list produces). This is registry.yaml's real
    // list_profiles result_schema, byte-shaped as embed_content.py would
    // emit it -- the object-form branch in columns_from_result_schema was
    // reachable but had no test exercising it until this PR's dashboard-
    // rendering remediation surfaced the gap.
    ResponseTemplatesEngine eng;
    auto schema = R"({"columns":[
        {"name":"sid","type":"string"},
        {"name":"profile_name","type":"string"},
        {"name":"profile_path","type":"string"},
        {"name":"hive_state","type":"string"}
    ]})";
    auto t = eng.synthesise_default(schema, "registry");
    CHECK(t.id == ResponseTemplatesEngine::kDefaultId);
    CHECK(t.is_default == true);
    REQUIRE(t.columns.size() == 4);
    CHECK(t.columns[0] == "sid");
    CHECK(t.columns[1] == "profile_name");
    CHECK(t.columns[2] == "profile_path");
    CHECK(t.columns[3] == "hive_state");
}

TEST_CASE("ResponseTemplatesEngine: synthesise_default falls back to plugin schema",
          "[response_templates][engine][default]") {
    ResponseTemplatesEngine eng;
    // procfetch ships ["Agent", "PID", "Name", "Path", "SHA-1"] in
    // result_parsing.hpp; the synth default skips Agent and lists the rest.
    auto t = eng.synthesise_default(/*result_schema=*/"", "procfetch");
    CHECK(t.id == ResponseTemplatesEngine::kDefaultId);
    REQUIRE(t.columns.size() == 4);
    CHECK(t.columns[0] == "PID");
    CHECK(t.columns[1] == "Name");
    CHECK(t.columns[2] == "Path");
    CHECK(t.columns[3] == "SHA-1");
}

TEST_CASE("ResponseTemplatesEngine: resolve picks operator default over synth",
          "[response_templates][engine][resolve]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> templates;
    {
        ResponseTemplate t;
        t.id = "t-op";
        t.name = "Operator default";
        t.is_default = true;
        templates.push_back(std::move(t));
    }
    auto r = eng.resolve(templates, /*template_id=*/"", /*schema=*/"", "any");
    CHECK(r.id == "t-op");
}

TEST_CASE("ResponseTemplatesEngine: resolve falls back to synth on unknown id",
          "[response_templates][engine][resolve]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> templates;
    {
        ResponseTemplate t;
        t.id = "real";
        t.name = "Real one";
        templates.push_back(std::move(t));
    }
    auto r = eng.resolve(templates, "nonexistent", /*schema=*/"", "procfetch");
    CHECK(r.id == ResponseTemplatesEngine::kDefaultId);
}

TEST_CASE("ResponseTemplatesEngine: resolve returns named template by id",
          "[response_templates][engine][resolve]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> templates;
    {
        ResponseTemplate t;
        t.id = "alpha";
        t.name = "Alpha";
        templates.push_back(t);
        t.id = "beta";
        t.name = "Beta";
        templates.push_back(t);
    }
    auto r = eng.resolve(templates, "beta", /*schema=*/"", "any");
    CHECK(r.id == "beta");
    CHECK(r.name == "Beta");
}

TEST_CASE("ResponseTemplatesEngine: validate rejects '__default__' as authored id",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    nlohmann::json p = {{"id", ResponseTemplatesEngine::kDefaultId}, {"name", "x"}};
    auto r = eng.validate_payload(p, /*existing=*/{}, /*expected_id=*/"", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("reserved") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate requires non-empty name",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    nlohmann::json p = nlohmann::json::object();
    auto r = eng.validate_payload(p, {}, "", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("name") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate auto-generates id on POST",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    nlohmann::json p = {{"name", "auto-id"}};
    auto r = eng.validate_payload(p, {}, /*expected_id=*/"", /*assign_id=*/true);
    REQUIRE(r);
    CHECK(r->id.size() == 32);
    CHECK(r->name == "auto-id");
}

TEST_CASE("ResponseTemplatesEngine: validate enforces sort.column when sort.dir set",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    nlohmann::json p = {{"name", "x"},
                        {"sort", {{"dir", "asc"}}}};
    auto r = eng.validate_payload(p, {}, "", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("sort.column") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate rejects unknown filter op",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    nlohmann::json p = {
        {"name", "x"},
        {"filters", nlohmann::json::array({{{"column", "Y"}, {"op", "wat"}, {"value", "z"}}})}};
    auto r = eng.validate_payload(p, {}, "", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("filter.op") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate rejects multiple is_default",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> existing;
    ResponseTemplate t;
    t.id = "a";
    t.name = "A";
    t.is_default = true;
    existing.push_back(std::move(t));

    nlohmann::json p = {{"name", "B"}, {"default", true}};
    auto r = eng.validate_payload(p, existing, "", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("default") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate detects id collisions on POST",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> existing;
    ResponseTemplate t;
    t.id = "abc123";
    t.name = "A";
    existing.push_back(std::move(t));

    nlohmann::json p = {{"id", "abc123"}, {"name", "B"}};
    auto r = eng.validate_payload(p, existing, /*expected_id=*/"", true);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("collision") != std::string::npos);
}

TEST_CASE("ResponseTemplatesEngine: validate allows update-in-place via expected_id",
          "[response_templates][engine][validate]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> existing;
    ResponseTemplate t;
    t.id = "abc123";
    t.name = "old";
    existing.push_back(t);

    nlohmann::json p = {{"id", "abc123"}, {"name", "new"}};
    auto r = eng.validate_payload(p, existing, /*expected_id=*/"abc123", false);
    REQUIRE(r);
    CHECK(r->name == "new");
}

TEST_CASE("ResponseTemplatesEngine: serialise round-trips through parse",
          "[response_templates][engine][round_trip]") {
    ResponseTemplatesEngine eng;
    std::vector<ResponseTemplate> input;
    {
        ResponseTemplate t;
        t.id = "x";
        t.name = "X";
        t.columns = {"A", "B"};
        t.sort_column = "A";
        t.sort_dir = "asc";
        t.filters.push_back({"B", "equals", "v1"});
        t.is_default = true;
        input.push_back(std::move(t));
    }
    auto s = eng.serialise(input);
    auto parsed = eng.parse(s);
    REQUIRE(parsed);
    REQUIRE(parsed->size() == 1);
    auto& t = (*parsed)[0];
    CHECK(t.id == "x");
    CHECK(t.columns == std::vector<std::string>{"A", "B"});
    CHECK(t.sort_column == "A");
    CHECK(t.is_default == true);
    REQUIRE(t.filters.size() == 1);
    CHECK(t.filters[0].column == "B");
    CHECK(t.filters[0].op == "equals");
}
