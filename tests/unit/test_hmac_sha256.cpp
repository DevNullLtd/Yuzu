/**
 * test_hmac_sha256.cpp -- shared HMAC-SHA-256 (agents/shared/hmac_sha256.hpp) against the RFC 4231
 * vectors, and the machine-id hash contract (agents/shared/machine_id_hash.hpp) that rides on it.
 * Portable: runs on every OS, spawns nothing, reads no hardware.
 */
#include <catch2/catch_test_macros.hpp>

#include <hmac_sha256.hpp>
#include <machine_id_hash.hpp>

#include <string>

using yuzu::shared::hmac_sha256_hex;
using yuzu::shared::hash_machine_id;
using yuzu::shared::normalise_machine_id;

TEST_CASE("hmac_sha256: RFC 4231 test vectors", "[hmac_sha256]") {
    // Test case 1
    CHECK(hmac_sha256_hex(std::string(20, '\x0b'), "Hi There") ==
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    // Test case 2 (key shorter than the block)
    CHECK(hmac_sha256_hex("Jefe", "what do ya want for nothing?") ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    // Test case 3
    CHECK(hmac_sha256_hex(std::string(20, '\xaa'), std::string(50, '\xdd')) ==
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    // Test case 6 (key longer than the block: hashed first)
    CHECK(hmac_sha256_hex(std::string(131, '\xaa'),
                          "Test Using Larger Than Block-Size Key - Hash Key First") ==
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    // Test case 7 (long key and long data)
    CHECK(hmac_sha256_hex(std::string(131, '\xaa'),
                          "This is a test using a larger than block-size key and a larger than "
                          "block-size data. The key needs to be hashed before being used by the "
                          "HMAC algorithm.") ==
          "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

TEST_CASE("hmac_sha256: empty key and message are defined", "[hmac_sha256]") {
    CHECK(hmac_sha256_hex("", "") ==
          "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

TEST_CASE("hmac_sha256: a key exactly one block long is used as-is, not hashed", "[hmac_sha256]") {
    // 64-byte key vs the same key with one extra byte (hashed): the boundary must not collide.
    const std::string k64(64, 'k');
    const std::string k65(65, 'k');
    CHECK(hmac_sha256_hex(k64, "m") != hmac_sha256_hex(k65, "m"));
    CHECK(hmac_sha256_hex(k64, "m").size() == 64);
}

TEST_CASE("machine_id_hash: the label and algorithm token are a pinned cross-OS contract",
          "[machine_id_hash]") {
    // Changing either re-keys every stored machine_id; this test makes that a deliberate act.
    CHECK(yuzu::shared::kMachineIdHashKey == "yuzu.machine-id.v1");
    CHECK(yuzu::shared::kMachineIdHashAlgorithm == "hmac-sha256-app-v1");
}

TEST_CASE("machine_id_hash: pinned digest of a fixed id", "[machine_id_hash]") {
    // Independently computed: HMAC-SHA256(key="yuzu.machine-id.v1", msg=the id), lowercase hex.
    const auto h = hash_machine_id("3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6");
    REQUIRE(h.has_value());
    CHECK(*h == "40ac51d528153ea3962cfd69f25d3a9d8c918da8e824fc223d5c96a1c1a2b51c");
}

TEST_CASE("machine_id_hash: formatting differences do not fork the digest", "[machine_id_hash]") {
    const auto base = hash_machine_id("3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6");
    REQUIRE(base.has_value());
    CHECK(hash_machine_id("3F2A9C1E-77B4-4D0A-9A51-0C5BE1D2A8F6") == base);
    CHECK(hash_machine_id("{3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6}") == base);
    CHECK(hash_machine_id("  3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6\r\n") == base);
    CHECK(hash_machine_id(std::string("3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6") + '\0') == base);
}

TEST_CASE("machine_id_hash: no id means no hash", "[machine_id_hash]") {
    CHECK_FALSE(hash_machine_id("").has_value());
    CHECK_FALSE(hash_machine_id("   \r\n").has_value());
    CHECK_FALSE(hash_machine_id("{}").has_value());
    CHECK_FALSE(hash_machine_id("{ }").has_value()); // braces around only whitespace
    CHECK(normalise_machine_id("{ }").empty());
}

TEST_CASE("machine_id_hash: the digest never contains the raw id", "[machine_id_hash]") {
    const std::string raw = "3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6";
    const auto h = hash_machine_id(raw);
    REQUIRE(h.has_value());
    CHECK(h->find("3f2a9c1e") == std::string::npos);
    CHECK(h->size() == 64);
    for (char c : *h)
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
}
