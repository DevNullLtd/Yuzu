// Direct unit tests for the shared strict integer primitive (query_int_parse.hpp, #4644).
//
// The route-level tests prove each call site answers 400; this file pins the primitive's own
// contract so a change to it fails here, with the offending input named, rather than
// surfacing as a vague route failure. No store, no Postgres.
#include "query_int_parse.hpp"
#include "rollout_pct_reject.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

using yuzu::server::parse_query_int;
using yuzu::server::strict_stoi;
using yuzu::server::strict_stoll;

TEST_CASE("parse_query_int: accepts exactly one base-10 integer", "[query_int_parse]") {
    CHECK(parse_query_int<int>("0") == 0);
    CHECK(parse_query_int<int>("-0") == 0); // a signed zero is zero, not malformed
    CHECK(parse_query_int<int>("007") == 7); // zero padding is accepted
    CHECK(parse_query_int<int>("-007") == -7);
    CHECK(parse_query_int<int>("1") == 1);
    CHECK(parse_query_int<long long>("123456789012") == 123456789012LL);
}

TEST_CASE("parse_query_int: rejects every shape that is not one integer", "[query_int_parse]") {
    const char* bad = GENERATE("", "-", "+", "+1", "+0", "- 1", "-+1", "--1", "1-", " 1", "1 ", " ",
                               "\t1", "1\n", "1\r", "100abc", "abc", "1e9", "1E9", "1.0", "1.5",
                               ".5", "0x1", "0x10", "0b1", "1,000", "1_000", "\xD9\xA1" /*Arabic 1*/);
    INFO("input=[" << bad << "]");
    CHECK_FALSE(parse_query_int<int>(bad).has_value());
    CHECK_FALSE(parse_query_int<long long>(bad).has_value());
    CHECK_THROWS_AS(strict_stoi(bad), std::invalid_argument);
    CHECK_THROWS_AS(strict_stoll(bad), std::invalid_argument);
}

TEST_CASE("parse_query_int: an embedded or trailing NUL is garbage not a terminator",
          "[query_int_parse]") {
    // %00 in a query string becomes a real NUL in the parameter value; a parser that stopped at
    // the first NUL (strtol over a c_str) would read the prefix.
    CHECK_FALSE(parse_query_int<int>(std::string_view("12\0" "34", 5)).has_value());
    CHECK_FALSE(parse_query_int<int>(std::string_view("12\0", 3)).has_value());
    CHECK_FALSE(parse_query_int<int>(std::string_view("\0" "12", 3)).has_value());
    CHECK_FALSE(parse_query_int<long long>(std::string_view("5\0", 2)).has_value());
}

TEST_CASE("parse_query_int: a default-constructed string_view is rejected", "[query_int_parse]") {
    CHECK_FALSE(parse_query_int<int>(std::string_view{}).has_value());
    CHECK_FALSE(parse_query_int<long long>(std::string_view{}).has_value());
}

TEST_CASE("parse_query_int: exact int32 boundaries no wrap and no clamp", "[query_int_parse]") {
    CHECK(parse_query_int<int>("2147483647") == std::numeric_limits<int>::max());
    CHECK(parse_query_int<int>("-2147483648") == std::numeric_limits<int>::min());
    CHECK_FALSE(parse_query_int<int>("2147483648").has_value());
    CHECK_FALSE(parse_query_int<int>("-2147483649").has_value());
    // The values a static_cast<int> would alias to 0 or to a small number.
    CHECK_FALSE(parse_query_int<int>("4294967296").has_value());
    CHECK_FALSE(parse_query_int<int>("4294967297").has_value());
    CHECK_FALSE(parse_query_int<int>("18446744073709551615").has_value());
}

TEST_CASE("parse_query_int: exact int64 boundaries no wrap and no clamp", "[query_int_parse]") {
    CHECK(parse_query_int<long long>("9223372036854775807") ==
          std::numeric_limits<long long>::max());
    CHECK(parse_query_int<long long>("-9223372036854775808") ==
          std::numeric_limits<long long>::min());
    CHECK_FALSE(parse_query_int<long long>("9223372036854775808").has_value());
    CHECK_FALSE(parse_query_int<long long>("-9223372036854775809").has_value());
    // UINT64_MAX wrapped to -1 (the documented "any" sentinel on several filters) before the fix.
    CHECK_FALSE(parse_query_int<long long>("18446744073709551615").has_value());
    CHECK_FALSE(parse_query_int<long long>("99999999999999999999999").has_value());
}

TEST_CASE("parse_query_int: other signed widths follow their own range", "[query_int_parse]") {
    CHECK(parse_query_int<std::int16_t>("32767") == 32767);
    CHECK(parse_query_int<std::int16_t>("-32768") == -32768);
    CHECK_FALSE(parse_query_int<std::int16_t>("32768").has_value());
    CHECK(parse_query_int<std::int64_t>("-1") == -1);
}

TEST_CASE("strict_stoi/strict_stoll: the throwing drop-ins agree with the primitive",
          "[query_int_parse]") {
    CHECK(strict_stoi("2147483647") == 2147483647);
    CHECK(strict_stoi("-1") == -1);
    CHECK(strict_stoll("-9223372036854775807") == -9223372036854775807LL);
    CHECK_THROWS_AS(strict_stoi("2147483648"), std::invalid_argument);
    CHECK_THROWS_AS(strict_stoll("9223372036854775808"), std::invalid_argument);
    // std::stoi would have returned the numeric prefix; that silent truncation is the defect.
    CHECK(std::stoi("100abc") == 100);
    CHECK_THROWS_AS(strict_stoi("100abc"), std::invalid_argument);
}

// The OTA upload route is multipart (TestRouteSink cannot drive it) and the rollout route is a
// form: both call this one helper, so these cases cover BOTH. A typo must never become a
// full-fleet rollout: malformed is nullopt (the routes answer 400 and store nothing), EMPTY is the
// route's documented default, a valid integer is clamped to 0..100 as documented.
TEST_CASE("parse_rollout_pct: malformed is rejected; empty is the default; valid is clamped",
          "[query_int_parse][numeric_params]") {
    for (const char* bad : {"0x5", "5abc", "1e1", "+5", " 5", "5 ", "-", "99999999999999999999"})
        CHECK_FALSE(yuzu::server::parse_rollout_pct(bad).has_value());
    CHECK(yuzu::server::parse_rollout_pct("") == 100);
    CHECK(yuzu::server::parse_rollout_pct("", 0) == 0);
    CHECK(yuzu::server::parse_rollout_pct("0") == 0);
    CHECK(yuzu::server::parse_rollout_pct("-0") == 0);
    CHECK(yuzu::server::parse_rollout_pct("007") == 7);
    CHECK(yuzu::server::parse_rollout_pct("50") == 50);
    CHECK(yuzu::server::parse_rollout_pct("100") == 100);
    CHECK(yuzu::server::parse_rollout_pct("101") == 100);   // clamped, documented
    CHECK(yuzu::server::parse_rollout_pct("-5") == 0);      // clamped, documented
    CHECK(yuzu::server::parse_rollout_pct("2147483647") == 100);
}

TEST_CASE("sse_cursor_from_header: the cursor is one non-negative integer or live only",
          "[query_int_parse][numeric_params]") {
    CHECK(yuzu::server::sse_cursor_from_header("0").since_id == 0);
    CHECK_FALSE(yuzu::server::sse_cursor_from_header("0").live_only);
    CHECK(yuzu::server::sse_cursor_from_header("42").since_id == 42);
    CHECK(yuzu::server::sse_cursor_from_header("9223372036854775807").since_id == 9223372036854775807ULL);
    for (const char* bad : {"-1", "5abc", "", "0x10", "+3", " 3", "9223372036854775808"}) {
        INFO(bad);
        const auto c = yuzu::server::sse_cursor_from_header(bad);
        CHECK(c.live_only);
        CHECK(c.since_id == std::numeric_limits<std::uint64_t>::max());
    }
}

// The shared 400 for a malformed OTA rollout_pct. The upload route is multipart (the unit route sink
// cannot drive it), so this is the closest real seam to its rejection path: both OTA routes call this
// one function, and a regression that drops the status, the toast or the A4 body goes red here.
TEST_CASE("reject_bad_rollout_pct answers 400 with a constant toast and an A4 body",
          "[query_int_parse][numeric_params][ota]") {
    for (const auto effect : {yuzu::server::RolloutRejectEffect::kStored,
                              yuzu::server::RolloutRejectEffect::kChanged}) {
        httplib::Response res;
        yuzu::server::reject_bad_rollout_pct(res, effect);
        CHECK(res.status == 400);
        CHECK(res.get_header_value("Content-Type").find("application/json") != std::string::npos);
        const auto toast = res.get_header_value("HX-Trigger");
        CHECK(toast.find("\"showToast\"") != std::string::npos);
        CHECK(toast.find("\"level\":\"error\"") != std::string::npos);
        CHECK(toast.find(effect == yuzu::server::RolloutRejectEffect::kStored ? "nothing was stored"
                                                                              : "nothing was changed") !=
              std::string::npos);
        CHECK(res.body.find("rollout_pct") != std::string::npos);
        CHECK(res.body.find("\"error\"") != std::string::npos);
    }
}
