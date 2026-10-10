/**
 * sha256.hpp — dependency-free, in-memory SHA-256 (FIPS 180-4).
 *
 * Portable on every OS: no OS headers, no yuzu/ includes, no crypto library.
 * Bytes in, lowercase 64-char hex out. Pinned against the NIST vectors in
 * tests/unit/test_sha256.cpp.
 *
 * This is the IN-MEMORY twin of agents/core/include/yuzu/agent/file_hash.hpp,
 * which hashes an open fd/HANDLE (bounded streaming read). Use this one when
 * the bytes are already in a buffer (key material, parsed strings).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace yuzu::shared {

struct Sha256 {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    unsigned char buf[64] = {};
    std::size_t buf_len = 0;
    std::uint64_t total = 0;

    static constexpr std::uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

    static std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

    void process_block(const unsigned char* p) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(p[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(p[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = hh + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    void update(const void* data, std::size_t len) {
        const auto* p = static_cast<const unsigned char*>(data);
        total += len;
        while (len > 0) {
            const std::size_t take = (64 - buf_len) < len ? (64 - buf_len) : len;
            std::memcpy(buf + buf_len, p, take);
            buf_len += take;
            p += take;
            len -= take;
            if (buf_len == 64) {
                process_block(buf);
                buf_len = 0;
            }
        }
    }

    std::string hex_digest() {
        const std::uint64_t bit_len = total * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        const unsigned char zero = 0x00;
        while (buf_len != 56)
            update(&zero, 1);
        unsigned char len_be[8];
        for (int i = 0; i < 8; ++i)
            len_be[i] = static_cast<unsigned char>(bit_len >> (56 - i * 8));
        // update() counts these framing bytes into `total`, but bit_len was
        // latched before padding began, so the encoded length is correct.
        update(len_be, 8);
        static constexpr char hexc[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (std::uint32_t v : h) {
            for (int shift = 28; shift >= 0; shift -= 4)
                out += hexc[(v >> shift) & 0xF];
        }
        return out;
    }
};

inline std::string sha256_hex(std::string_view data) {
    Sha256 s;
    s.update(data.data(), data.size());
    return s.hex_digest();
}

} // namespace yuzu::shared
