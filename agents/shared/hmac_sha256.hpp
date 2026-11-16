/**
 * hmac_sha256.hpp -- HMAC-SHA-256 (RFC 2104 / FIPS 198-1) over the in-memory SHA-256 in
 * sha256.hpp.
 *
 * Header-only, portable, no OS call and no OpenSSL dependency, so a plugin that has neither
 * (the hardware plugin) can still key a hash. Pinned against the RFC 4231 test vectors in
 * tests/unit/test_hmac_sha256.cpp.
 *
 * This is a MAC primitive, not a password hash and not a KDF; it carries no secrecy of its own.
 * What the key buys depends on the caller -- see machine_id_hash.hpp for the one current use.
 */
#pragma once

#include "sha256.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::shared {

inline constexpr std::size_t kSha256BlockBytes = 64;

/// The 32 raw HMAC-SHA-256 bytes of `msg` under `key`. A key longer than the SHA-256 block is
/// hashed first, a shorter one zero-padded (RFC 2104 section 2). Either may be empty.
[[nodiscard]] inline std::array<unsigned char, 32> hmac_sha256_raw(std::string_view key,
                                                                    std::string_view msg) {
    std::array<unsigned char, kSha256BlockBytes> k{};
    if (key.size() > kSha256BlockBytes) {
        Sha256 kh;
        kh.update(key.data(), key.size());
        const auto d = kh.raw_digest();
        for (std::size_t i = 0; i < d.size(); ++i)
            k[i] = d[i];
    } else {
        for (std::size_t i = 0; i < key.size(); ++i)
            k[i] = static_cast<unsigned char>(key[i]);
    }

    std::array<unsigned char, kSha256BlockBytes> ipad{}, opad{};
    for (std::size_t i = 0; i < kSha256BlockBytes; ++i) {
        ipad[i] = static_cast<unsigned char>(k[i] ^ 0x36u);
        opad[i] = static_cast<unsigned char>(k[i] ^ 0x5Cu);
    }

    Sha256 inner;
    inner.update(ipad.data(), ipad.size());
    inner.update(msg.data(), msg.size());
    const auto inner_digest = inner.raw_digest();

    Sha256 outer;
    outer.update(opad.data(), opad.size());
    outer.update(inner_digest.data(), inner_digest.size());
    return outer.raw_digest();
}

/// Lowercase 64-character hex of hmac_sha256_raw.
[[nodiscard]] inline std::string hmac_sha256_hex(std::string_view key, std::string_view msg) {
    static constexpr char hexc[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (const unsigned char b : hmac_sha256_raw(key, msg)) {
        out += hexc[b >> 4];
        out += hexc[b & 0xF];
    }
    return out;
}

} // namespace yuzu::shared
