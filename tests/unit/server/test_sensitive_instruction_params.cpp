/**
 * test_sensitive_instruction_params.cpp — the pure redaction/rejection rule
 * that closes PR3136's review blocker: `content_dist.upload_file`'s one-time
 * `grant_secret` bearer credential was being persisted in cleartext into
 * `executions.parameter_values` (workflow_routes.cpp, mcp_server.cpp,
 * rest_api_v1.cpp's result-set producer) and readable by any principal
 * holding the broadly-granted `Execution:Read` permission — a direct
 * violation of docs/adr/3004-artifact-blob-storage.md's promise that the raw
 * secret "never appears in a log line, an audit detail field, or a second
 * database column."
 *
 * Two distinct fixes, because the two families of caller have different
 * shapes (see sensitive_instruction_params.hpp's file header for why):
 * one-shot dispatch paths REDACT the persisted copy while still dispatching
 * with the raw in-memory map; schedules REFUSE to persist at all, since a
 * schedule's parameter_values is the sole record re-dispatched on every
 * future occurrence.
 */

#include "sensitive_instruction_params.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

TEST_CASE("redact_sensitive_instruction_params strips grant_secret and grant_id",
         "[server][sensitive_params]") {
    std::unordered_map<std::string, std::string> params{
        {"grant_secret", "deadbeef"}, {"grant_id", "abc123"}, {"path", "/tmp/file.bin"}};
    auto redacted = redact_sensitive_instruction_params(params);
    CHECK(redacted.count("grant_secret") == 0);
    CHECK(redacted.count("grant_id") == 0);
    REQUIRE(redacted.count("path") == 1);
    CHECK(redacted.at("path") == "/tmp/file.bin");
}

TEST_CASE("redact_sensitive_instruction_params is a no-op when no sensitive key is present",
         "[server][sensitive_params]") {
    std::unordered_map<std::string, std::string> params{{"path", "/tmp/file.bin"},
                                                         {"max_size_mb", "100"}};
    auto redacted = redact_sensitive_instruction_params(params);
    CHECK(redacted.size() == 2);
    CHECK(redacted.at("path") == "/tmp/file.bin");
    CHECK(redacted.at("max_size_mb") == "100");
}

TEST_CASE("redact_sensitive_instruction_params on an empty map returns empty",
         "[server][sensitive_params]") {
    std::unordered_map<std::string, std::string> params;
    CHECK(redact_sensitive_instruction_params(params).empty());
}

TEST_CASE("is_redacted_instruction_param_key recognizes exactly the closed set",
         "[server][sensitive_params]") {
    CHECK(is_redacted_instruction_param_key("grant_secret"));
    CHECK(is_redacted_instruction_param_key("grant_id"));
    CHECK_FALSE(is_redacted_instruction_param_key("path"));
    CHECK_FALSE(is_redacted_instruction_param_key("Grant_Secret")); // case-sensitive
    CHECK_FALSE(is_redacted_instruction_param_key(""));
}

TEST_CASE("schedule_params_contain_sensitive_key detects grant_secret in a canonical object",
         "[server][sensitive_params]") {
    CHECK(schedule_params_contain_sensitive_key(R"({"grant_secret":"deadbeef"})"));
    CHECK(schedule_params_contain_sensitive_key(R"({"path":"/x","grant_id":"abc"})"));
}

TEST_CASE("schedule_params_contain_sensitive_key is false for ordinary params",
         "[server][sensitive_params]") {
    CHECK_FALSE(schedule_params_contain_sensitive_key(R"({"path":"/x","max_size_mb":"100"})"));
    CHECK_FALSE(schedule_params_contain_sensitive_key("{}"));
}

TEST_CASE("schedule_params_contain_sensitive_key fails closed-to-false on malformed/non-object "
         "input (a separate validator's job to reject)",
         "[server][sensitive_params]") {
    CHECK_FALSE(schedule_params_contain_sensitive_key("not json"));
    CHECK_FALSE(schedule_params_contain_sensitive_key("[1,2,3]"));
    CHECK_FALSE(schedule_params_contain_sensitive_key(""));
}
