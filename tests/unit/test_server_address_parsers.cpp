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

TEST_CASE("grpc_peer_literal reduces a gRPC peer string to the host:port literal the agent "
          "publishes as agent.server_peer, and to nothing for anything that is not one",
          "[agent][server_address_parsers]") {
    // what ClientContext::peer() reports after a call
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:50051") == "198.51.100.7:50051");
    CHECK(grpc_peer_literal("ipv4:10.0.0.5:443") == "10.0.0.5:443");
    CHECK(grpc_peer_literal("ipv6:[2001:db8::1]:50051") == "[2001:db8::1]:50051");
    CHECK(grpc_peer_literal("ipv6:[::1]:8443") == "[::1]:8443");
    // some gRPC versions percent-encode the brackets; both spellings read the same
    CHECK(grpc_peer_literal("ipv6:%5B2001:db8::1%5D:50051") == "[2001:db8::1]:50051");
    CHECK(grpc_peer_literal("ipv6:%5b2001:db8::1%5d:50051") == "[2001:db8::1]:50051");
    // a v4-mapped v6 address keeps its dotted tail
    CHECK(grpc_peer_literal("ipv6:[::ffff:198.51.100.7]:50051") == "[::ffff:198.51.100.7]:50051");

    // a peer that is not a usable literal publishes nothing: never a guess, never a name
    CHECK(grpc_peer_literal("").empty());
    CHECK(grpc_peer_literal("dns:server.example.com:50051").empty());
    CHECK(grpc_peer_literal("unix:/run/yuzu.sock").empty());
    CHECK(grpc_peer_literal("uds:/run/yuzu.sock").empty());
    CHECK(grpc_peer_literal("198.51.100.7:50051").empty()); // no scheme
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:50051,ipv4:198.51.100.8:50051").empty()); // a list
    // ports: present, numeric, 1..65535
    CHECK(grpc_peer_literal("ipv4:198.51.100.7").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:0").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:65536").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:http").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7:65535") == "198.51.100.7:65535");
    // v4 shape: four octets of at most 255
    CHECK(grpc_peer_literal("ipv4:198.51.100:50051").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.7.1:50051").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.256:50051").empty());
    CHECK(grpc_peer_literal("ipv4:198.51.100.x:50051").empty());
    CHECK(grpc_peer_literal("ipv4:server.example.com:50051").empty());
    // v6 shape: bracketed, hex/colon/dot only, a zone id or any other escape is refused
    CHECK(grpc_peer_literal("ipv6:2001:db8::1:50051").empty());              // no brackets
    CHECK(grpc_peer_literal("ipv6:[2001:db8::1:50051").empty());              // unclosed
    CHECK(grpc_peer_literal("ipv6:[fe80::1%25eth0]:50051").empty());          // zone id
    CHECK(grpc_peer_literal("ipv6:[fe80::1%eth0]:50051").empty());
    CHECK(grpc_peer_literal("ipv6:[2001:db8::g]:50051").empty());
    CHECK(grpc_peer_literal("ipv6:[1.2.3.4]:50051").empty());                 // not a v6 literal
    CHECK(grpc_peer_literal("ipv6:[]:50051").empty());
    CHECK(grpc_peer_literal("ipv6:[2001:db8::1]").empty());
    CHECK(grpc_peer_literal("ipv6:[2001:db8::1]:0").empty());
    CHECK(grpc_peer_literal("ipv6:%5B2001:db8::1]:50051").empty());           // mixed spellings
}
