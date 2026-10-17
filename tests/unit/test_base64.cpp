/**
 * test_base64.cpp -- RFC 4648 section 10 vectors and the strict-reject rules of
 * agents/shared/base64.hpp. The ed25519 blob below is the base64 body of a REAL public key
 * line (REAL CAPTURE: `ssh-keygen -t ed25519` on Debian 13, OpenSSH_10.0p2, 2026-10-17).
 */

#include <catch2/catch_test_macros.hpp>

#include <base64.hpp>

#include <string>

using yuzu::shared::base64_decode;
using yuzu::shared::base64_encode;

TEST_CASE("base64: RFC 4648 vectors round-trip", "[shared][base64]") {
    const struct {
        const char* plain;
        const char* enc;
    } v[] = {{"", ""},       {"f", "Zg=="},       {"fo", "Zm8="},         {"foo", "Zm9v"},
             {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
    for (const auto& c : v) {
        CHECK(base64_encode(c.plain) == c.enc);
        const auto d = base64_decode(c.enc);
        REQUIRE(d.has_value());
        CHECK(*d == c.plain);
    }
}

TEST_CASE("base64: strict decode rejects malformed input", "[shared][base64]") {
    CHECK_FALSE(base64_decode("Zm9v!A==").has_value());   // non-alphabet byte
    CHECK_FALSE(base64_decode("Zm9v\n").has_value());     // whitespace is not tolerated
    CHECK_FALSE(base64_decode("Zg=A").has_value());       // '=' before the end
    CHECK_FALSE(base64_decode("Zg=").has_value());        // length % 4 != 0
    CHECK_FALSE(base64_decode("Zm9").has_value());        // length % 4 != 0
    CHECK_FALSE(base64_decode("Z===").has_value());       // three padding characters
    CHECK_FALSE(base64_decode("====").has_value());       // nothing but padding
    CHECK_FALSE(base64_decode("Zg==Zg==").has_value());   // padding mid-string
    CHECK_FALSE(base64_decode("Zm9v-_8=").has_value());   // URL-safe alphabet is not accepted
    CHECK_FALSE(base64_decode("Zh==").has_value());       // non-canonical trailing bits (ssh-keygen refuses these)
    CHECK_FALSE(base64_decode("Zm9=").has_value());       // non-canonical trailing bits, one '='
    CHECK(base64_decode("Zm8=").has_value());             // the canonical form is fine
}

TEST_CASE("base64: encode with pad=false carries no '=' (the ssh-keygen fingerprint form)",
          "[shared][base64]") {
    CHECK(base64_encode("f", false) == "Zg");
    CHECK(base64_encode("fo", false) == "Zm8");
    CHECK(base64_encode("foo", false) == "Zm9v");
    CHECK(base64_encode("f", true) == "Zg==");
}

TEST_CASE("base64: a real ssh-ed25519 blob decodes to its leading ssh-string", "[shared][base64]") {
    // REAL CAPTURE: the key blob of an ssh-keygen -t ed25519 public key.
    const auto d = base64_decode("AAAAC3NzaC1lZDI1NTE5AAAAIEfwkBaM2u8m02IuUZ4wuvCPggDaq5R5MqdQWA82+WdV");
    REQUIRE(d.has_value());
    REQUIRE(d->size() == 51); // 4 + 11 + 4 + 32
    CHECK(d->substr(0, 4) == std::string("\0\0\0\x0b", 4));
    CHECK(d->substr(4, 11) == "ssh-ed25519");
}
