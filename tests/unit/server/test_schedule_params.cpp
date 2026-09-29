/**
 * test_schedule_params.cpp — pure validation + canonicalisation tests for
 * schedule_params_parsers.hpp (PR1.5a).
 *
 * Header-only and I/O-free (no sqlite, no clock) — the firewall_parsers.hpp /
 * interaction_parsers.hpp pattern applied to schedule parameters. Every case
 * here is decision-shaped: given this JSON text, what does the validator
 * decide, and does canonicalisation stay order-invariant.
 */

#include "schedule_params_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

using namespace yuzu::server;

// ── Acceptance ───────────────────────────────────────────────────────────────

TEST_CASE("schedule params: an omitted (empty) blob canonicalizes to the empty object",
          "[schedule][params]") {
    auto r = validate_and_canonicalize_schedule_params("");
    REQUIRE(r.has_value());
    CHECK(*r == "{}");
}

TEST_CASE("schedule params: an explicit empty object round-trips unchanged",
          "[schedule][params]") {
    auto r = validate_and_canonicalize_schedule_params("{}");
    REQUIRE(r.has_value());
    CHECK(*r == "{}");
}

TEST_CASE("schedule params: string, number, and boolean scalar values are all accepted",
          "[schedule][params]") {
    auto r = validate_and_canonicalize_schedule_params(
        R"({"target":"prod","retries":3,"dry_run":false})");
    REQUIRE(r.has_value());
    CHECK(*r == R"({"dry_run":false,"retries":3,"target":"prod"})");
}

// ── Canonicalisation is order-invariant ─────────────────────────────────────

TEST_CASE("schedule params: two objects with the same pairs in different key order serialize "
          "byte-identically",
          "[schedule][params]") {
    auto a = validate_and_canonicalize_schedule_params(R"({"zeta":"1","alpha":"2","mid":"3"})");
    auto b = validate_and_canonicalize_schedule_params(R"({"mid":"3","alpha":"2","zeta":"1"})");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(*a == *b);
    CHECK(*a == R"({"alpha":"2","mid":"3","zeta":"1"})");
}

// ── Rejections — one pure case each ─────────────────────────────────────────

TEST_CASE("schedule params: malformed JSON is rejected", "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params("{not json");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kMalformedJson);
}

TEST_CASE("schedule params: a non-object top-level value is rejected",
          "[schedule][params][reject]") {
    for (std::string_view non_object : {"[1,2,3]", R"("just a string")", "42", "true", "null"}) {
        auto r = validate_and_canonicalize_schedule_params(non_object);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == ScheduleParamsError::kNotObject);
    }
}

TEST_CASE("schedule params: a nested object value is rejected as non-scalar",
          "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params(R"({"config":{"a":1}})");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kNonScalarValue);
}

TEST_CASE("schedule params: an array value is rejected as non-scalar",
          "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params(R"({"tags":["a","b"]})");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kNonScalarValue);
}

TEST_CASE("schedule params: a null value is rejected as non-scalar",
          "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params(R"({"target":null})");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kNonScalarValue);
}

TEST_CASE("schedule params: exceeding the key cap is rejected", "[schedule][params][reject]") {
    std::string blob = "{";
    for (std::size_t i = 0; i <= kMaxScheduleParamKeys; ++i) {
        if (i > 0)
            blob += ",";
        blob += "\"k" + std::to_string(i) + "\":\"v\"";
    }
    blob += "}";

    auto r = validate_and_canonicalize_schedule_params(blob);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kTooManyKeys);
}

TEST_CASE("schedule params: exceeding the size cap is rejected", "[schedule][params][reject]") {
    // One key whose value alone pushes the canonical serialization past
    // kMaxScheduleParamsBytes — under the key cap, so this exercises the
    // size check specifically, not the key-count check.
    std::string big_value(kMaxScheduleParamsBytes + 1, 'x');
    auto blob = R"({"big":")" + big_value + R"("})";

    auto r = validate_and_canonicalize_schedule_params(blob);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kTooLarge);
}

TEST_CASE("schedule params: an underscore-prefixed key is rejected as reserved",
          "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params(R"({"_principal":"admin"})");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kReservedKey);
}

TEST_CASE("schedule params: an empty-string key is rejected as reserved",
          "[schedule][params][reject]") {
    auto r = validate_and_canonicalize_schedule_params(R"({"":"v"})");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == ScheduleParamsError::kReservedKey);
}

TEST_CASE("schedule params: is_reserved_schedule_param_key covers empty and underscore-prefixed",
          "[schedule][params]") {
    CHECK(is_reserved_schedule_param_key(""));
    CHECK(is_reserved_schedule_param_key("_x"));
    CHECK_FALSE(is_reserved_schedule_param_key("x"));
    CHECK_FALSE(is_reserved_schedule_param_key("x_y"));
}

// ── to_string coverage — every enumerator maps to non-empty prose ──────────

TEST_CASE("schedule params: to_string covers every ScheduleParamsError enumerator",
          "[schedule][params]") {
    CHECK_FALSE(to_string(ScheduleParamsError::kMalformedJson).empty());
    CHECK_FALSE(to_string(ScheduleParamsError::kNotObject).empty());
    CHECK_FALSE(to_string(ScheduleParamsError::kNonScalarValue).empty());
    CHECK_FALSE(to_string(ScheduleParamsError::kTooManyKeys).empty());
    CHECK_FALSE(to_string(ScheduleParamsError::kTooLarge).empty());
    CHECK_FALSE(to_string(ScheduleParamsError::kReservedKey).empty());
}

// ── schedule_params_to_map ───────────────────────────────────────────────────

TEST_CASE("schedule_params_to_map: string values are unwrapped, other scalars stringify to "
          "their JSON literal",
          "[schedule][params][decode]") {
    auto m = schedule_params_to_map(R"({"target":"prod","retries":3,"dry_run":true})");
    REQUIRE(m.size() == 3);
    CHECK(m.at("target") == "prod");   // unwrapped, no quotes
    CHECK(m.at("retries") == "3");
    CHECK(m.at("dry_run") == "true");
}

TEST_CASE("schedule_params_to_map: empty and canonical-empty both decode to an empty map",
          "[schedule][params][decode]") {
    CHECK(schedule_params_to_map("").empty());
    CHECK(schedule_params_to_map("{}").empty());
}

TEST_CASE("schedule_params_to_map: malformed or non-object input degrades to an empty map "
          "rather than throwing",
          "[schedule][params][decode]") {
    CHECK(schedule_params_to_map("{not json").empty());
    CHECK(schedule_params_to_map("[1,2,3]").empty());
    CHECK(schedule_params_to_map(R"("a string")").empty());
}

TEST_CASE("schedule_params_to_map: round-trips the output of "
          "validate_and_canonicalize_schedule_params",
          "[schedule][params][decode]") {
    auto canon = validate_and_canonicalize_schedule_params(
        R"({"zeta":"last","alpha":"first","count":7})");
    REQUIRE(canon.has_value());

    auto m = schedule_params_to_map(*canon);
    REQUIRE(m.size() == 3);
    CHECK(m.at("alpha") == "first");
    CHECK(m.at("zeta") == "last");
    CHECK(m.at("count") == "7");
}
