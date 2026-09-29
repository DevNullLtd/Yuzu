/**
 * test_server_address_parsers.cpp — pure host:port / IP-literal helpers
 * (server_address_parsers.hpp, #3429 round 4). server_address_resolver.cpp's
 * real getaddrinfo() call is deliberately NOT exercised end to end here
 * (same "no network in the unit suite" discipline as this repo's other
 * I/O-performing shells) — but its deadline-wrapper behavior IS covered,
 * with the resolve step injected, in test_server_address_resolver.cpp
 * (round 4's blocker fix). These two pure functions are the parsing layer's
 * entire testable core.
 */
#include <yuzu/agent/server_address_parsers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::agent;

TEST_CASE("extract_server_host strips a port suffix from a gRPC-style target, "
         "handling bracketed and bracket-less IPv6",
         "[agent][server_address_parsers]") {
    CHECK(extract_server_host("10.0.0.5:50051") == "10.0.0.5");
    CHECK(extract_server_host("server.example.com:50051") == "server.example.com");
    CHECK(extract_server_host("[::1]:50051") == "::1");
    CHECK(extract_server_host("[2001:db8::1]:50051") == "2001:db8::1");
    // Bracket-less IPv6 with no port -- splitting on the last ':' would
    // truncate it, so the whole string is returned instead.
    CHECK(extract_server_host("2001:db8::1") == "2001:db8::1");
    CHECK(extract_server_host("::1") == "::1");
    // No ':' at all -- a bare host, returned unchanged.
    CHECK(extract_server_host("localhost") == "localhost");
    CHECK(extract_server_host("") == "");
    // Malformed bracket (no closing ']') -- no safe host to extract.
    CHECK(extract_server_host("[::1:50051") == "");
}

TEST_CASE("looks_like_ip_literal accepts IPv4/IPv6-shaped charsets and rejects "
         "hostnames, over-length strings, and empty input",
         "[agent][server_address_parsers]") {
    CHECK(looks_like_ip_literal("10.0.0.5"));
    CHECK(looks_like_ip_literal("::1"));
    CHECK(looks_like_ip_literal("2001:db8::1"));
    CHECK_FALSE(looks_like_ip_literal("server.example.com"));
    CHECK_FALSE(looks_like_ip_literal(""));
    CHECK_FALSE(looks_like_ip_literal(std::string(46, '1'))); // over the 45-char cap
}
