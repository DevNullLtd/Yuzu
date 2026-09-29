// host_arg.hpp is the ONE validator for every action that passes an
// operator-supplied host to a network tool or probe (ADR-3002 Decision 6):
// a leading '-' is the option-injection shape Decision 6 names, so it must
// be rejected even though every other charset byte it allows is otherwise
// unremarkable.
#include <catch2/catch_test_macros.hpp>

#include <host_arg.hpp>

#include <string>

using yuzu::shared::is_safe_host_arg;
using yuzu::shared::kMaxHostArgLen;

TEST_CASE("is_safe_host_arg rejects a leading '-' (option injection)", "[agent][host_arg]") {
    CHECK_FALSE(is_safe_host_arg("-f"));
    CHECK_FALSE(is_safe_host_arg("-n"));
}

TEST_CASE("is_safe_host_arg accepts a leading ':' (IPv6 loopback '::1')", "[agent][host_arg]") {
    CHECK(is_safe_host_arg("::1"));
    CHECK(is_safe_host_arg(":1"));
}

TEST_CASE("is_safe_host_arg rejects an empty host", "[agent][host_arg]") {
    CHECK_FALSE(is_safe_host_arg(""));
}

TEST_CASE("is_safe_host_arg: 253-byte host accepted, 254-byte host rejected",
         "[agent][host_arg]") {
    REQUIRE(kMaxHostArgLen == 253);
    const std::string at_limit(kMaxHostArgLen, 'a');
    const std::string over_limit(kMaxHostArgLen + 1, 'a');
    CHECK(is_safe_host_arg(at_limit));
    CHECK_FALSE(is_safe_host_arg(over_limit));
}

TEST_CASE("is_safe_host_arg accepts a plausible hostname and IPv4/IPv6 literal",
         "[agent][host_arg]") {
    CHECK(is_safe_host_arg("example.com"));
    CHECK(is_safe_host_arg("192.168.1.1"));
    CHECK(is_safe_host_arg("fe80::1"));
}

TEST_CASE("is_safe_host_arg rejects every non-alnum/./-/: byte", "[agent][host_arg]") {
    CHECK_FALSE(is_safe_host_arg("host name"));  // space
    CHECK_FALSE(is_safe_host_arg("host/name"));  // slash
    CHECK_FALSE(is_safe_host_arg(std::string("host\0name", 9))); // embedded NUL
    CHECK_FALSE(is_safe_host_arg("host$name")); // dollar
    CHECK_FALSE(is_safe_host_arg("host`name")); // backtick
    CHECK_FALSE(is_safe_host_arg("host;name")); // semicolon
    CHECK_FALSE(is_safe_host_arg("host|name")); // pipe
}
