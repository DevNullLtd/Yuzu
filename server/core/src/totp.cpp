#include "totp.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <format>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/hmac.h>
#endif

namespace yuzu::server::mfa {

namespace {

constexpr char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void hmac_sha1(std::string_view key, std::string_view data, uint8_t (&out)[20]) {
    // Pre-zero so any partial-failure path leaves a deterministic
    // (zero) MAC rather than uninitialised stack bytes — the verifier
    // constant-time compares against this, and a partially-written
    // buffer would be undefined behaviour on read (Gate 3 cpp-safety
    // BLOCKING).
    std::memset(out, 0, sizeof(out));
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        return;
    }
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(alg, &hHash, nullptr, 0,
                              reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
                              static_cast<ULONG>(key.size()), 0);
    if (BCRYPT_SUCCESS(status)) {
        // Check every BCrypt return — silently swallowing them would
        // mint a half-computed MAC. Any failure path leaves `out` zero
        // so the verifier deterministically rejects.
        auto rc_data =
            BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                           static_cast<ULONG>(data.size()), 0);
        if (BCRYPT_SUCCESS(rc_data)) {
            auto rc_fin = BCryptFinishHash(hHash, out, 20, 0);
            if (!BCRYPT_SUCCESS(rc_fin)) {
                std::memset(out, 0, sizeof(out));
            }
        } else {
            std::memset(out, 0, sizeof(out));
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
#else
    unsigned int len = 20;
    auto* result = HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
                        reinterpret_cast<const unsigned char*>(data.data()), data.size(), out,
                        &len);
    if (!result) {
        std::memset(out, 0, sizeof(out));
    }
#endif
}

constexpr bool ascii_ieq(char a, char b) noexcept {
    auto upper = [](char c) {
        return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    };
    return upper(a) == upper(b);
}

constexpr int decode_b32_char(char c) noexcept {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '2' && c <= '7')
        return 26 + (c - '2');
    return -1;
}

std::string pct_encode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

} // namespace

std::string base32_encode(std::string_view bytes) {
    std::string out;
    out.reserve(((bytes.size() + 4) / 5) * 8);

    uint64_t buffer = 0;
    int bits = 0;
    for (unsigned char b : bytes) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += kBase32Alphabet[(buffer >> bits) & 0x1f];
        }
    }
    if (bits > 0) {
        out += kBase32Alphabet[(buffer << (5 - bits)) & 0x1f];
    }
    return out;
}

std::optional<std::vector<uint8_t>> base32_decode(std::string_view encoded) {
    std::vector<uint8_t> out;
    out.reserve((encoded.size() * 5) / 8);

    uint64_t buffer = 0;
    int bits = 0;
    bool seen_pad = false;
    for (char c : encoded) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-')
            continue;
        if (c == '=') {
            seen_pad = true;
            continue;
        }
        if (seen_pad)
            return std::nullopt;
        int v = decode_b32_char(c);
        if (v < 0)
            return std::nullopt;
        buffer = (buffer << 5) | static_cast<uint64_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

int64_t current_counter(std::chrono::system_clock::time_point now) noexcept {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return static_cast<int64_t>(secs) / kTotpStepSeconds;
}

std::string generate(std::string_view secret_bytes, int64_t counter) {
    // RFC 4226 §5.1: HMAC input is the counter as a big-endian 8-byte int.
    std::array<uint8_t, 8> msg{};
    uint64_t c = static_cast<uint64_t>(counter);
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<uint8_t>(c & 0xff);
        c >>= 8;
    }
    uint8_t mac[20];
    hmac_sha1(secret_bytes, std::string_view(reinterpret_cast<const char*>(msg.data()), msg.size()),
              mac);

    // RFC 4226 §5.3 dynamic truncation.
    int offset = mac[19] & 0x0f;
    uint32_t bin = (static_cast<uint32_t>(mac[offset] & 0x7f) << 24) |
                   (static_cast<uint32_t>(mac[offset + 1]) << 16) |
                   (static_cast<uint32_t>(mac[offset + 2]) << 8) |
                   static_cast<uint32_t>(mac[offset + 3]);

    uint32_t mod = 1;
    for (int i = 0; i < kTotpDigits; ++i)
        mod *= 10;
    return std::format("{:0{}}", bin % mod, kTotpDigits);
}

std::optional<int64_t> verify_window(std::string_view secret_bytes, std::string_view code,
                                     int64_t current, int64_t min_counter_exclusive,
                                     int skew_steps) {
    if (code.size() != static_cast<std::size_t>(kTotpDigits))
        return std::nullopt;
    for (char c : code) {
        if (c < '0' || c > '9')
            return std::nullopt;
    }
    // Walk ±skew; reject any matched counter that is not strictly greater
    // than min_counter_exclusive to defeat same-step replay.
    for (int delta = -skew_steps; delta <= skew_steps; ++delta) {
        int64_t candidate = current + delta;
        if (candidate <= min_counter_exclusive)
            continue;
        auto produced = generate(secret_bytes, candidate);
        // Defensive size check — if `generate` ever returns a string
        // narrower than `code` (e.g. an internal cast went wrong) the
        // per-char compare would otherwise read past the end of
        // `produced`. Fail closed on any width mismatch (Gate 3
        // cpp-expert BLOCKING).
        if (produced.size() != code.size())
            continue;
        // Constant-time string compare — `code` and `produced` are both
        // 6 chars so length-leak is moot, but timing on the per-char
        // compare would otherwise help an online attacker.
        unsigned char diff = 0;
        for (std::size_t i = 0; i < code.size(); ++i) {
            diff |= static_cast<unsigned char>(code[i]) ^ static_cast<unsigned char>(produced[i]);
        }
        if (diff == 0)
            return candidate;
    }
    return std::nullopt;
}

std::string otpauth_uri(std::string_view issuer, std::string_view account,
                        std::string_view secret_base32) {
    std::string out = "otpauth://totp/";
    out += pct_encode(issuer);
    out += ':';
    out += pct_encode(account);
    out += "?secret=";
    out += std::string(secret_base32);
    out += "&issuer=";
    out += pct_encode(issuer);
    out += "&algorithm=SHA1&digits=";
    out += std::to_string(kTotpDigits);
    out += "&period=";
    out += std::to_string(kTotpStepSeconds);
    return out;
}

std::expected<std::vector<uint8_t>, SecureRandomError> random_secret() {
    std::vector<uint8_t> out(kTotpSecretBytes); // zero-initialised: never returned on failure
    if (auto rc = fill_random(out); !rc.has_value())
        return std::unexpected(rc.error());
    return out;
}

std::expected<std::string, SecureRandomError> random_recovery_code() {
    // 10 bytes of CSPRNG entropy → 16 base32 chars = 80 bits. Up from
    // 50 bits in PR1's first cut (enterprise-readiness ASSURANCE-3 +
    // unhappy-path UP-7) — single-use bypass tokens for an MFA-strip
    // primitive must clear the 80-bit "look-up secret" floor for SOC 2
    // and NIST SP 800-63B Authentication Assurance Level 2. Format
    // remains hyphen-grouped for human transcription.
    // Value-initialised as defence in depth: `raw` is never read on the failure
    // path below, but a future edit must not be able to reach indeterminate stack.
    uint8_t raw[10]{};
    if (auto rc = fill_random(std::span<uint8_t>{raw}); !rc.has_value())
        return std::unexpected(rc.error());
    auto enc = base32_encode(std::string_view(reinterpret_cast<const char*>(raw), sizeof(raw)));
    // base32 of 10 bytes is 16 chars. Group 4-4-4-4 for readability.
    enc.resize(16);
    return enc.substr(0, 4) + "-" + enc.substr(4, 4) + "-" + enc.substr(8, 4) + "-" +
           enc.substr(12, 4);
}

} // namespace yuzu::server::mfa
