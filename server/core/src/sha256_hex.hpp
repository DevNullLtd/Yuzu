#pragma once

/**
 * sha256_hex.hpp — a CHECKED SHA-256 of a byte string as 64 lowercase hex
 * characters (ADR-3006 enablement store).
 *
 * Returns nullopt when the digest provider fails, never a digest of zeros. The
 * callers (the desired-state hash, the overlay hash, the inventory hash) compare
 * the result for equality: a failure that hashed as 64 zero bytes would compare
 * equal to itself and let a row be stamped as resolved against a hash that does
 * not exist. A digest failure is process-wide, so callers abort the whole unit
 * of work on nullopt rather than skipping one row.
 *
 * ApiTokenStore::sha256_hex (api_token_store.cpp) is deliberately NOT reused:
 * its BCrypt branch ignores the NTSTATUS and starts from a zero-initialised
 * digest, which is exactly the failure shape described above. The OpenSSL EVP
 * one-shot below is the pattern app_usage_raw_hash follows (OpenSSL is present
 * on every leg, Windows included).
 */

#include <openssl/evp.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

[[nodiscard]] inline std::optional<std::string> sha256_hex(std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr) != 1 || len != 32)
        return std::nullopt;
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

} // namespace yuzu::server
