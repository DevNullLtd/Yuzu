/**
 * test_wire_utf8.cpp -- unit tests for agents/shared/wire_utf8.hpp: the strict RFC 3629
 * scrubber a plugin runs over OS-supplied bytes before they enter a row. Pure and portable:
 * no filesystem, process or clock, so it runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <wire_utf8.hpp>

#include <string>
#include <string_view>

namespace shared = yuzu::shared;

TEST_CASE("scrub_wire_bytes: valid scalars survive, NUL and malformed bytes are replaced in place",
          "[wire_utf8]") {
    std::string ok = "plain caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80";
    CHECK(shared::scrub_wire_bytes(ok) == 0); // 2-, 3- and 4-byte scalars survive
    CHECK(ok == "plain caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80");
    // NUL, a lone 0xFF, an overlong NUL (C0 80), a surrogate (ED A0 80), a code
    // point above U+10FFFF (F4 90 ...), a stray continuation byte and a truncated
    // sequence are each replaced byte by byte.
    for (std::string_view bad : {std::string_view("a\0b", 3), std::string_view("a\xff" "b"),
                                 std::string_view("a\xc0\x80" "b"), std::string_view("a\xed\xa0\x80" "b"),
                                 std::string_view("a\xf4\x90\x80\x80" "b"), std::string_view("a\x80" "b"),
                                 std::string_view("a\xe2\x82")}) {
        std::string t{bad};
        CHECK(shared::scrub_wire_bytes(t) > 0);
        CHECK(t.find('\0') == std::string::npos);
        CHECK(t.front() == 'a');
        CHECK(t.size() == bad.size()); // replaced in place: the row keeps its shape
    }
}

TEST_CASE("scrub_wire_bytes accepts exactly RFC 3629 (boundaries of every lead-byte range)",
          "[wire_utf8]") {
    // The sole guard for a response the receiver would reject whole: each boundary of
    // the table, valid and one step past it. MUTATION: any loosened lead range or
    // continuation check flips one of these.
    for (std::string_view ok : {std::string_view("\xc2\x80"), std::string_view("\xdf\xbf"),
                                std::string_view("\xe0\xa0\x80"), std::string_view("\xed\x9f\xbf"),
                                std::string_view("\xef\xbf\xbd"), std::string_view("\xf0\x90\x80\x80"),
                                std::string_view("\xf4\x8f\xbf\xbf")}) {
        std::string t{ok};
        CHECK(shared::scrub_wire_bytes(t) == 0);
        CHECK(t == ok);
    }
    for (std::string_view bad : {std::string_view("\xc1\xbf"), std::string_view("\xe0\x9f\xbf"),
                                 std::string_view("\xf0\x8f\xbf\xbf"), std::string_view("\xf5\x80\x80\x80"),
                                 std::string_view("\xe2\x28\xa1"), std::string_view("\xf1\x28\x80\x80"),
                                 std::string_view("\xf0\x9f\x28\x8c"), std::string_view("\xc3\x28"),
                                 std::string_view("\xc3\xc3"), std::string_view("\xe2\x82\xe2"),
                                 std::string_view("\xf0\x9f\x98"), std::string_view("\xc3")}) {
        std::string t{bad};
        CHECK(shared::scrub_wire_bytes(t) > 0);
        CHECK(shared::count_invalid_wire_bytes(bad) > 0);
        for (const char c : t)
            CHECK(static_cast<unsigned char>(c) < 0x80);
    }
}

TEST_CASE("count_invalid_wire_bytes agrees with what scrub_wire_bytes replaces", "[wire_utf8]") {
    for (std::string_view s : {std::string_view(""), std::string_view("plain"),
                               std::string_view("a\0b", 3), std::string_view("a\xff" "b\xc0\x80"),
                               std::string_view("caf\xc3\xa9\xe2\x82")}) {
        std::string t{s};
        CHECK(shared::count_invalid_wire_bytes(s) == shared::scrub_wire_bytes(t));
    }
}
