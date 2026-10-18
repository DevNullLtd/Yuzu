/**
 * test_sha256.cpp — FIPS 180-4 vectors for agents/shared/sha256.hpp.
 * The 64/65-byte cases straddle the block boundary; expected digests were
 * computed with Python hashlib.
 */

#include <catch2/catch_test_macros.hpp>

#include <sha256.hpp>

#include <string>

using yuzu::shared::Sha256;
using yuzu::shared::sha256_hex;

TEST_CASE("sha256: FIPS 180-4 vectors", "[shared][sha256]") {
    CHECK(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("sha256: block boundary inputs", "[shared][sha256]") {
    const std::string digits = "0123456789";
    std::string in64, in65;
    for (int i = 0; i < 7; ++i)
        in64 += digits;
    in65 = in64.substr(0, 65);
    in64.resize(64);
    CHECK(sha256_hex(in64) == "9674d9e078535b7cec43284387a6ee39956188e735a85452b0050b55341cda56");
    CHECK(sha256_hex(in65) == "52774b57c10e45040a61c14d35c1c8ebefe880082313aa0a21ebb077734cd067");
}

TEST_CASE("sha256: split update equals one-shot", "[shared][sha256]") {
    const std::string msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    Sha256 s;
    s.update(msg.data(), 10);
    s.update(msg.data() + 10, msg.size() - 10);
    CHECK(s.hex_digest() == sha256_hex(msg));
}
