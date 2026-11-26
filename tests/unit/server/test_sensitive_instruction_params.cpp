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

TEST_CASE("client_secret (the shipped Entra directory-sync parameter) is classified like the "
          "grant keys: redacted from a persisted copy and refused in a schedule",
          "[server][sensitive_params]") {
    std::unordered_map<std::string, std::string> params{{"tenant_id", "t"},
                                                         {"client_id", "c"},
                                                         {"client_secret", "s3cret"}};
    auto redacted = redact_sensitive_instruction_params(params);
    CHECK(redacted.count("client_secret") == 0);
    CHECK(redacted.count("tenant_id") == 1);
    CHECK(redacted.count("client_id") == 1);
    CHECK(is_redacted_instruction_param_key("client_secret"));
    CHECK_FALSE(is_redacted_instruction_param_key("oidc_client_secret")); // exact keys only
    const std::string entra_schedule_params = R"({"tenant_id":"t","client_secret":"s3cret"})";
    CHECK(schedule_params_contain_sensitive_key(entra_schedule_params));
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

// ── WP06 F12: approval-ticket subject redaction ──────────────────────────

TEST_CASE("redact_tool_args_for_ticket replaces every secret-bearing value at any depth",
          "[server][sensitive_params]") {
    const std::string kSecret = "yuzu_test_sentinel_secret_value";
    auto args = nlohmann::json::parse(R"({
        "secret": ")" + kSecret + R"(",
        "name": "keep-me",
        "params": {"grant_secret": ")" + kSecret + R"(", "client_secret": ")" + kSecret + R"(", "path": "/x"},
        "steps": [{"params": {"x": 1}}, {"params": {"grant_id": ")" + kSecret + R"("}},
                  [{"deep": {"secret": ")" + kSecret + R"("}}]]
    })");
    auto out = redact_tool_args_for_ticket(args);
    REQUIRE(out.has_value());
    const std::string dumped = out->dump();
    CHECK(dumped.find(kSecret) == std::string::npos);
    CHECK(dumped.find("keep-me") != std::string::npos);
    CHECK(dumped.find("/x") != std::string::npos);
    CHECK((*out)["secret"].get<std::string>().starts_with("<redacted:sha256:"));
    // Deterministic, and the input is untouched (taken by value).
    CHECK(redact_tool_args_for_ticket(args)->dump() == dumped);
    CHECK(args["secret"] == kSecret);
}

TEST_CASE("key matching is exact and lower-case: other spellings are NOT redacted (recorded "
          "residual, widening is a security decision)",
          "[server][sensitive_params]") {
    // The header's KEY-SPELLING RESIDUAL. If this test goes red, the matcher was widened: record
    // that decision in the header and the ledger, do not just update the expectation.
    for (std::string_view k : {"Secret", "SECRET", "clientSecret", "client-secret", "Client_Secret",
                               "grantSecret", "GRANT_ID", "password", "token", "my_grant_secret",
                               "grant_secret_x", " grant_secret", "grant_secret "}) {
        CAPTURE(k);
        CHECK_FALSE(is_redacted_instruction_param_key(k));
        CHECK_FALSE(is_redacted_tool_arg_key(k));
    }
    const std::string kValue = "yuzu_test_sentinel_other_spelling";
    nlohmann::json args = {{"clientSecret", kValue}, {"Secret", kValue}, {"password", kValue}};
    auto out = redact_tool_args_for_ticket(args);
    REQUIRE(out.has_value());
    CHECK(out->dump().find(kValue) != std::string::npos);
    // The listed spellings still redact.
    CHECK(is_redacted_tool_arg_key("secret"));
    CHECK(is_redacted_instruction_param_key("client_secret"));
}

TEST_CASE("redact_tool_args_for_ticket binds the secret: a different value gives a different "
          "subject, the same value the same",
          "[server][sensitive_params]") {
    nlohmann::json a = {{"secret", "one"}}, b = {{"secret", "two"}}, c = {{"secret", "one"}};
    CHECK(redact_tool_args_for_ticket(a)->dump() != redact_tool_args_for_ticket(b)->dump());
    CHECK(redact_tool_args_for_ticket(a)->dump() == redact_tool_args_for_ticket(c)->dump());
    // Non-string secret values are redacted too.
    nlohmann::json n = {{"secret", {{"k", "sentinel_obj"}}}};
    CHECK(redact_tool_args_for_ticket(n)->dump().find("sentinel_obj") == std::string::npos);
}

TEST_CASE("redact_tool_args_for_ticket fails closed past the depth bound",
          "[server][sensitive_params]") {
    nlohmann::json deep = "leaf";
    for (int i = 0; i < kTicketRedactMaxDepth + 5; ++i)
        deep = nlohmann::json{{"k", deep}};
    CHECK_FALSE(redact_tool_args_for_ticket(deep).has_value());
}

TEST_CASE("redact_tool_args_for_ticket reports over-depth as a caller fault, and pins the "
          "documented residual: a secret inside a string VALUE is not parsed",
          "[server][sensitive_params]") {
    nlohmann::json deep = "leaf";
    for (int i = 0; i < kTicketRedactMaxDepth + 5; ++i)
        deep = nlohmann::json{{"k", deep}};
    bool over = false;
    CHECK_FALSE(redact_tool_args_for_ticket(deep, &over).has_value());
    CHECK(over);

    // Residual (documented in the header): text embedded in a string value is not interpreted.
    nlohmann::json embedded = {{"features_json", R"({"secret":"yuzu_test_embedded"})"}};
    auto out = redact_tool_args_for_ticket(embedded);
    REQUIRE(out.has_value());
    CHECK(out->dump().find("yuzu_test_embedded") != std::string::npos);
}

TEST_CASE("redact_tool_args_for_ticket: the string \"5\" and the number 5 bind different markers; "
          "invalid UTF-8 in a secret does not throw",
          "[server][sensitive_params]") {
    nlohmann::json as_string = {{"secret", "5"}}, as_number = {{"secret", 5}},
                   as_string2 = {{"secret", "5"}};
    CHECK(redact_tool_args_for_ticket(as_string)->dump() !=
          redact_tool_args_for_ticket(as_number)->dump());
    CHECK(redact_tool_args_for_ticket(as_string)->dump() ==
          redact_tool_args_for_ticket(as_string2)->dump());
    // A non-string secret holding an invalid-UTF-8 string: dump() must not raise type_error 316.
    nlohmann::json bad = {{"secret", {{"k", std::string("\xff\xfe bad")}}}};
    CHECK_NOTHROW(redact_tool_args_for_ticket(bad));
}

TEST_CASE("redact_tool_args_for_ticket: a url's userinfo never reaches the ticket subject, the rest "
          "of the url stays and a different userinfo binds a different subject (WP06 F12)",
          "[server][sensitive_params]") {
    const std::string kCred = "yuzu_test_user:yuzu_test_pw";
    nlohmann::json a = {{"crl_urls", nlohmann::json::array({{{"url", "https://" + kCred + "@crl.example.test:8443/a.crl?x=1"}}})}};
    nlohmann::json b = {{"crl_urls", nlohmann::json::array({{{"url", "https://other:cred@crl.example.test:8443/a.crl?x=1"}}})}};
    auto ra = redact_tool_args_for_ticket(a);
    auto rb = redact_tool_args_for_ticket(b);
    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    const std::string da = ra->dump();
    CHECK(da.find("yuzu_test_pw") == std::string::npos);
    CHECK(da.find("yuzu_test_user") == std::string::npos);
    CHECK(da.find("@crl.example.test:8443/a.crl?x=1") != std::string::npos); // the rest stays readable
    CHECK(da.find("<redacted:sha256:") != std::string::npos);
    CHECK(da != rb->dump());
    // A url without userinfo (including an '@' in its path or query) is untouched.
    nlohmann::json plain = {{"url", "https://crl.example.test/a@b?c=d@e"}};
    CHECK(redact_tool_args_for_ticket(plain)->dump() == plain.dump());
}

// ── Unretained keys: an agent-issued resume token is not a secret, and is never kept ─────────────

TEST_CASE("redact_sensitive_instruction_params drops the resume token and keeps the request itself",
          "[server][sensitive_params]") {
    std::unordered_map<std::string, std::string> params{{"root", "/data"},
                                                         {"pattern", "*.bin"},
                                                         {"kinds", "file"},
                                                         {"cursor", "fsv1.sealed-token"}};
    auto kept = redact_sensitive_instruction_params(params);
    CHECK(kept.count("cursor") == 0);
    REQUIRE(kept.count("root") == 1);
    CHECK(kept.at("root") == "/data");
    CHECK(kept.at("pattern") == "*.bin");
    CHECK(kept.at("kinds") == "file");
    // The live dispatch still uses the raw map: the helper takes a copy and never touches the caller's.
    CHECK(params.count("cursor") == 1);
}

TEST_CASE("cursor is an unretained key and NOT a secret key", "[server][sensitive_params]") {
    CHECK(is_unretained_instruction_param_key("cursor"));
    CHECK_FALSE(is_unretained_instruction_param_key("Cursor")); // exact keys only
    CHECK_FALSE(is_unretained_instruction_param_key("root"));
    CHECK_FALSE(is_unretained_instruction_param_key(""));
    // The secret classification (read by the Console mask, the definition hint and the hardware form)
    // must not gain it: a resume token must not make a form mask its field.
    CHECK_FALSE(is_redacted_instruction_param_key("cursor"));
    for (const auto key : kRedactedInstructionParamKeys)
        CHECK_FALSE(is_unretained_instruction_param_key(key));
    for (const auto key : kUnretainedInstructionParamKeys)
        CHECK_FALSE(is_redacted_instruction_param_key(key));
}

TEST_CASE("schedule_params_contain_unretained_key is true for a cursor and false without one",
          "[server][sensitive_params]") {
    CHECK(schedule_params_contain_unretained_key(R"({"root":"/data","cursor":"fsv1.x"})"));
    CHECK(schedule_params_contain_unretained_key(R"({"cursor":""})"));
    CHECK_FALSE(schedule_params_contain_unretained_key(R"({"root":"/data","pattern":"*.bin"})"));
    CHECK_FALSE(schedule_params_contain_unretained_key("{}"));
    CHECK_FALSE(schedule_params_contain_unretained_key("not json"));
    CHECK_FALSE(schedule_params_contain_unretained_key("[1,2,3]"));
    CHECK_FALSE(schedule_params_contain_unretained_key(""));
    // The two refusals are independent: a secret is not an unretained key, and the reverse.
    CHECK_FALSE(schedule_params_contain_unretained_key(R"({"grant_secret":"x"})"));
    CHECK_FALSE(schedule_params_contain_sensitive_key(R"({"cursor":"fsv1.x"})"));
}
