// Pure-parser coverage for the macOS `last -y` last-login path (qe-M1).
// The functions live in agents/plugins/users/src/users_macos_last.hpp and are
// reachable at runtime from users_plugin.cpp's local_users action; this pins
// every rejection branch the governance quality gate flagged as untested.
#include "users_macos_last.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::users_macos::is_weekday;
using yuzu::users_macos::parse_last_timestamp;

TEST_CASE("users macOS: is_weekday recognises the seven day markers", "[users][macos]") {
    for (auto d : {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"})
        CHECK(is_weekday(d));
    CHECK_FALSE(is_weekday(""));
    CHECK_FALSE(is_weekday("Mona"));   // not an exact match
    CHECK_FALSE(is_weekday("mon"));    // case-sensitive
    CHECK_FALSE(is_weekday("Jan"));    // a month, not a weekday
}

TEST_CASE("users macOS: parse_last_timestamp accepts a well-formed `last -y` fragment",
          "[users][macos]") {
    CHECK(parse_last_timestamp("Jan", "5", "2026", "09:07") == "2026-01-05 09:07:00");
    CHECK(parse_last_timestamp("Dec", "31", "1999", "23:59") == "1999-12-31 23:59:00");
    CHECK(parse_last_timestamp("Jul", "09", "2026", "00:00") == "2026-07-09 00:00:00");
}

TEST_CASE("users macOS: parse_last_timestamp rejects every malformed fragment", "[users][macos]") {
    // month-map miss
    CHECK(parse_last_timestamp("Xxx", "5", "2026", "09:07").empty());
    CHECK(parse_last_timestamp("jan", "5", "2026", "09:07").empty()); // wrong case
    // day out of range / non-numeric
    CHECK(parse_last_timestamp("Jan", "0", "2026", "09:07").empty());
    CHECK(parse_last_timestamp("Jan", "32", "2026", "09:07").empty());
    CHECK(parse_last_timestamp("Jan", "x", "2026", "09:07").empty());
    // missing colon in time
    CHECK(parse_last_timestamp("Jan", "5", "2026", "0907").empty());
    // hour/minute out of range
    CHECK(parse_last_timestamp("Jan", "5", "2026", "24:00").empty());
    CHECK(parse_last_timestamp("Jan", "5", "2026", "09:60").empty());
    // non-numeric hour/minute
    CHECK(parse_last_timestamp("Jan", "5", "2026", "aa:07").empty());
    CHECK(parse_last_timestamp("Jan", "5", "2026", "09:bb").empty());
    // year below the floor / non-numeric
    CHECK(parse_last_timestamp("Jan", "5", "1969", "09:07").empty());
    CHECK(parse_last_timestamp("Jan", "5", "yyyy", "09:07").empty());
}
