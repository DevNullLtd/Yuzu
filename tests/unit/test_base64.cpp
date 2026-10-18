/**
 * test_base64.cpp -- RFC 4648 section 10 vectors and the strict-reject rules of
 * agents/shared/base64.hpp. Real key blobs are decoded by test_remote_access_audit_keys_parsers.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <base64.hpp>

#include <string>

using yuzu::shared::base64_decode;
using yuzu::shared::base64_encode;

TEST_CASE("base64: RFC 4648 vectors round-trip, padded and unpadded", "[shared][base64]") {
    const struct {
        const char* plain;
        const char* enc;
    } v[] = {{"", ""},       {"f", "Zg=="},       {"fo", "Zm8="},         {"foo", "Zm9v"},
             {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
    for (const auto& c : v) {
        CHECK(base64_encode(c.plain) == c.enc);
        std::string unpadded = c.enc;
        std::erase(unpadded, '=');
        CHECK(base64_encode(c.plain, false) == unpadded); // the ssh-keygen fingerprint form
        const auto d = base64_decode(c.enc);
        REQUIRE(d.has_value());
        CHECK(*d == c.plain);
    }
}

TEST_CASE("base64: strict decode rejects malformed input", "[shared][base64]") {
    for (const char* bad : {"Zm9v!A==",   // non-alphabet byte
                            "Zm9v\n",     // whitespace is not tolerated
                            "Zg=A",       // '=' before the end
                            "Zg=",        // length % 4 != 0
                            "Zm9",        // length % 4 != 0
                            "Z===",       // three padding characters
                            "====",       // nothing but padding
                            "Zg==Zg==",   // padding mid-string
                            "Zm9v-_8=",   // URL-safe alphabet is not accepted
                            "Zh==",       // non-canonical trailing bits (ssh-keygen refuses these)
                            "Zm9="}) {    // non-canonical trailing bits, one '='
        INFO(bad);
        CHECK_FALSE(base64_decode(bad).has_value());
    }
    CHECK(base64_decode("Zm8=").has_value()); // the canonical form is fine
}
