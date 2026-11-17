/**
 * test_result_envelope.cpp — Unit tests for InstructionResult envelope
 *
 * Covers: parse_column_type, column_type_to_string, parse_result (raw and
 *         structured), to_json serialization, validate_types.
 */

#include "result_envelope.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

// ── parse_column_type ───────────────────────────────────────────────────────

TEST_CASE("ResultEnvelope: parse_column_type maps lowercase strings", "[result_envelope]") {
    CHECK(parse_column_type("bool") == ColumnType::Bool);
    CHECK(parse_column_type("int32") == ColumnType::Int32);
    CHECK(parse_column_type("int64") == ColumnType::Int64);
    CHECK(parse_column_type("string") == ColumnType::String);
    CHECK(parse_column_type("datetime") == ColumnType::Datetime);
    CHECK(parse_column_type("guid") == ColumnType::Guid);
    CHECK(parse_column_type("clob") == ColumnType::Clob);
}

TEST_CASE("ResultEnvelope: parse_column_type defaults to String for unknown", "[result_envelope]") {
    CHECK(parse_column_type("unknown") == ColumnType::String);
    CHECK(parse_column_type("") == ColumnType::String);
    CHECK(parse_column_type("integer") == ColumnType::String);
    CHECK(parse_column_type("FLOAT") == ColumnType::String);
}

TEST_CASE("ResultEnvelope: parse_column_type is case-insensitive", "[result_envelope]") {
    CHECK(parse_column_type("Bool") == ColumnType::Bool);
    CHECK(parse_column_type("INT32") == ColumnType::Int32);
    CHECK(parse_column_type("DateTime") == ColumnType::Datetime);
    CHECK(parse_column_type("GUID") == ColumnType::Guid);
}

// ── column_type_to_string roundtrip ─────────────────────────────────────────

TEST_CASE("ResultEnvelope: column_type_to_string roundtrips", "[result_envelope]") {
    CHECK(column_type_to_string(ColumnType::Bool) == "bool");
    CHECK(column_type_to_string(ColumnType::Int32) == "int32");
    CHECK(column_type_to_string(ColumnType::Int64) == "int64");
    CHECK(column_type_to_string(ColumnType::String) == "string");
    CHECK(column_type_to_string(ColumnType::Datetime) == "datetime");
    CHECK(column_type_to_string(ColumnType::Guid) == "guid");
    CHECK(column_type_to_string(ColumnType::Clob) == "clob");

    // Roundtrip: string -> enum -> string
    for (const auto& name : {"bool", "int32", "int64", "string", "datetime", "guid", "clob"}) {
        CHECK(column_type_to_string(parse_column_type(name)) == name);
    }
}

// ── parse_result: raw text ──────────────────────────────────────────────────

TEST_CASE("ResultEnvelope: parse_result wraps raw text in output column", "[result_envelope]") {
    auto result = parse_result("Hello, world!", "");

    REQUIRE(result.columns.size() == 1);
    CHECK(result.columns[0].name == "output");
    CHECK(result.columns[0].type == ColumnType::String);

    REQUIRE(result.rows.size() == 1);
    CHECK(result.rows[0].values.at("output") == "Hello, world!");
}

TEST_CASE("ResultEnvelope: parse_result wraps non-JSON text", "[result_envelope]") {
    auto result = parse_result("line1\nline2\nline3", "");

    REQUIRE(result.columns.size() == 1);
    CHECK(result.columns[0].name == "output");
    REQUIRE(result.rows.size() == 1);
    CHECK(result.rows[0].values.at("output") == "line1\nline2\nline3");
}

// ── parse_result: structured JSON ───────────────────────────────────────────

TEST_CASE("ResultEnvelope: parse_result with JSON columns/rows", "[result_envelope]") {
    nlohmann::json input = {
        {"columns",
         {{{"name", "hostname"}, {"type", "string"}}, {{"name", "cpu_count"}, {"type", "int32"}}}},
        {"rows",
         {{{"hostname", "srv-01"}, {"cpu_count", "8"}},
          {{"hostname", "srv-02"}, {"cpu_count", "16"}}}}};

    auto result = parse_result(input.dump(), "");

    REQUIRE(result.columns.size() == 2);
    CHECK(result.columns[0].name == "hostname");
    CHECK(result.columns[0].type == ColumnType::String);
    CHECK(result.columns[1].name == "cpu_count");
    CHECK(result.columns[1].type == ColumnType::Int32);

    REQUIRE(result.rows.size() == 2);
    CHECK(result.rows[0].values.at("hostname") == "srv-01");
    CHECK(result.rows[0].values.at("cpu_count") == "8");
    CHECK(result.rows[1].values.at("hostname") == "srv-02");
    CHECK(result.rows[1].values.at("cpu_count") == "16");
}

TEST_CASE("ResultEnvelope: parse_result extracts metadata from JSON", "[result_envelope]") {
    nlohmann::json input = {{"columns", {{{"name", "output"}, {"type", "string"}}}},
                            {"rows", {{{"output", "ok"}}}},
                            {"execution_id", "exec-001"},
                            {"definition_id", "def-001"},
                            {"agent_id", "agent-001"},
                            {"timestamp", 1700000000000},
                            {"status", "success"},
                            {"error_code", 0},
                            {"duration_ms", 150},
                            {"stdout", "some stdout"},
                            {"stderr", "some stderr"},
                            {"warnings", {"warn1", "warn2"}}};

    auto result = parse_result(input.dump(), "");

    CHECK(result.execution_id == "exec-001");
    CHECK(result.definition_id == "def-001");
    CHECK(result.agent_id == "agent-001");
    CHECK(result.timestamp == 1700000000000);
    CHECK(result.status == "success");
    CHECK(result.error_code == 0);
    CHECK(result.duration_ms == 150);
    CHECK(result.stdout_text == "some stdout");
    CHECK(result.stderr_text == "some stderr");
    REQUIRE(result.warnings.size() == 2);
    CHECK(result.warnings[0] == "warn1");
    CHECK(result.warnings[1] == "warn2");
}

// ── parse_result: schema override ───────────────────────────────────────────

TEST_CASE("ResultEnvelope: parse_result with schema override applies schema types",
          "[result_envelope]") {
    nlohmann::json input = {
        {"columns",
         {{{"name", "uptime_s"}, {"type", "string"}}, {{"name", "healthy"}, {"type", "string"}}}},
        {"rows", {{{"uptime_s", "86400"}, {"healthy", "true"}}}}};

    // Schema overrides: uptime_s is int64, healthy is bool
    nlohmann::json schema = {{{"name", "uptime_s"}, {"type", "int64"}},
                             {{"name", "healthy"}, {"type", "bool"}}};

    auto result = parse_result(input.dump(), schema.dump());

    REQUIRE(result.columns.size() == 2);
    CHECK(result.columns[0].name == "uptime_s");
    CHECK(result.columns[0].type == ColumnType::Int64);
    CHECK(result.columns[1].name == "healthy");
    CHECK(result.columns[1].type == ColumnType::Bool);
}

// ── to_json ─────────────────────────────────────────────────────────────────

TEST_CASE("ResultEnvelope: to_json serializes all fields", "[result_envelope]") {
    InstructionResult result;
    result.execution_id = "exec-42";
    result.definition_id = "def-07";
    result.agent_id = "agent-99";
    result.timestamp = 1700000000000;
    result.status = "success";
    result.error_code = 0;
    result.duration_ms = 250;
    result.columns.push_back(ResultColumn{"name", ColumnType::String});
    result.columns.push_back(ResultColumn{"count", ColumnType::Int32});
    ResultRow row;
    row.values["name"] = "test";
    row.values["count"] = "42";
    result.rows.push_back(std::move(row));
    result.stdout_text = "stdout here";
    result.stderr_text = "stderr here";
    result.warnings = {"w1"};

    auto j = to_json(result);

    CHECK(j["execution_id"] == "exec-42");
    CHECK(j["definition_id"] == "def-07");
    CHECK(j["agent_id"] == "agent-99");
    CHECK(j["timestamp"] == 1700000000000);
    CHECK(j["status"] == "success");
    CHECK(j["error_code"] == 0);
    CHECK(j["duration_ms"] == 250);

    REQUIRE(j["columns"].size() == 2);
    CHECK(j["columns"][0]["name"] == "name");
    CHECK(j["columns"][0]["type"] == "string");
    CHECK(j["columns"][1]["name"] == "count");
    CHECK(j["columns"][1]["type"] == "int32");

    REQUIRE(j["rows"].size() == 1);
    CHECK(j["rows"][0]["name"] == "test");
    CHECK(j["rows"][0]["count"] == "42");

    CHECK(j["stdout"] == "stdout here");
    CHECK(j["stderr"] == "stderr here");
    REQUIRE(j["warnings"].size() == 1);
    CHECK(j["warnings"][0] == "w1");
}

// ── validate_types ──────────────────────────────────────────────────────────

TEST_CASE("ResultEnvelope: validate_types catches int32 mismatch", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"count", ColumnType::Int32});
    ResultRow row;
    row.values["count"] = "not_a_number";
    result.rows.push_back(std::move(row));

    auto errors = validate_types(result);
    REQUIRE(errors.size() == 1);
    CHECK(errors[0].find("count") != std::string::npos);
    CHECK(errors[0].find("not_a_number") != std::string::npos);
}

TEST_CASE("ResultEnvelope: validate_types accepts valid bool values", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"flag", ColumnType::Bool});

    for (const auto& val : {"true", "false", "1", "0"}) {
        result.rows.clear();
        ResultRow row;
        row.values["flag"] = val;
        result.rows.push_back(std::move(row));

        auto errors = validate_types(result);
        CHECK(errors.empty());
    }
}

TEST_CASE("ResultEnvelope: validate_types rejects invalid bool", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"flag", ColumnType::Bool});
    ResultRow row;
    row.values["flag"] = "yes";
    result.rows.push_back(std::move(row));

    auto errors = validate_types(result);
    REQUIRE(errors.size() == 1);
}

TEST_CASE("ResultEnvelope: validate_types accepts datetime formats", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"ts", ColumnType::Datetime});

    SECTION("ISO 8601 date") {
        ResultRow row;
        row.values["ts"] = "2024-01-15";
        result.rows.push_back(std::move(row));
        CHECK(validate_types(result).empty());
    }

    SECTION("ISO 8601 datetime") {
        ResultRow row;
        row.values["ts"] = "2024-01-15T10:30:00";
        result.rows.push_back(std::move(row));
        CHECK(validate_types(result).empty());
    }

    SECTION("ISO 8601 datetime with Z") {
        ResultRow row;
        row.values["ts"] = "2024-01-15T10:30:00Z";
        result.rows.push_back(std::move(row));
        CHECK(validate_types(result).empty());
    }

    SECTION("ISO 8601 datetime with timezone offset") {
        ResultRow row;
        row.values["ts"] = "2024-01-15T10:30:00+05:00";
        result.rows.push_back(std::move(row));
        CHECK(validate_types(result).empty());
    }

    SECTION("Epoch milliseconds") {
        ResultRow row;
        row.values["ts"] = "1700000000000";
        result.rows.push_back(std::move(row));
        CHECK(validate_types(result).empty());
    }
}

TEST_CASE("ResultEnvelope: validate_types accepts valid int32", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"num", ColumnType::Int32});
    ResultRow row;
    row.values["num"] = "42";
    result.rows.push_back(std::move(row));

    CHECK(validate_types(result).empty());
}

TEST_CASE("ResultEnvelope: validate_types string/guid/clob always valid", "[result_envelope]") {
    InstructionResult result;
    result.columns.push_back(ResultColumn{"s", ColumnType::String});
    result.columns.push_back(ResultColumn{"g", ColumnType::Guid});
    result.columns.push_back(ResultColumn{"c", ColumnType::Clob});
    ResultRow row;
    row.values["s"] = "anything";
    row.values["g"] = "anything goes";
    row.values["c"] = "really anything at all";
    result.rows.push_back(std::move(row));

    CHECK(validate_types(result).empty());
}

TEST_CASE("ResultEnvelope: parse_result is total over wrong-typed agent JSON (F6)",
          "[result_envelope]") {
    const std::string hostile =
        R"({"columns":[5,{"name":7,"type":[]},{"name":"ok","type":"string"}],)"
        R"("rows":[{"ok":1,"n":{"a":[1]}},"str",3],)"
        R"("execution_id":1,"definition_id":[],"agent_id":{},"timestamp":"t","status":false,)"
        R"("error_code":"x","duration_ms":1.5,"stdout":null,"stderr":7,"warnings":[1,null,"w"]})";
    InstructionResult r;
    REQUIRE_NOTHROW(r = parse_result(hostile, ""));
    CHECK(r.warnings == std::vector<std::string>{"w"});
    CHECK(r.timestamp == 0);
    CHECK(r.error_code == 0);
    REQUIRE(r.rows.size() == 3);
    CHECK(r.rows[0].values.at("ok") == "1");

    // Out-of-int-range error_code must not wrap or throw.
    REQUIRE_NOTHROW(parse_result(R"({"columns":[],"rows":[],"error_code":99999999999})", ""));
    // Malformed schema entries too.
    REQUIRE_NOTHROW(parse_result(R"({"columns":[],"rows":[]})", R"([{"name":1,"type":2}])"));
}
