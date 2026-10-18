/**
 * base64.hpp -- dependency-free, portable, strict RFC 4648 base64 (standard alphabet).
 *
 * base64_decode is STRICT, as OpenSSH's sshbuf_b64tod is: alphabet only, length a multiple of
 * four, padding only as the final one or two characters, no whitespace tolerance, and
 * non-canonical trailing bits ("Zh==" for "f") rejected (b64_pton's "subliminal channel").
 * Any deviation answers nullopt, never a partial decode: the caller parses attacker-writable
 * files and must tell "malformed" from "empty". base64_encode(bytes, false) is the unpadded
 * form `ssh-keygen -l` prints after `SHA256:`.
 */
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::shared {

namespace detail {

inline constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Value of one alphabet character, or -1.
inline int b64_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

} // namespace detail

[[nodiscard]] inline std::string base64_encode(std::string_view bytes, bool pad = true) {
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) |
                           (static_cast<unsigned char>(bytes[i + 1]) << 8) |
                           static_cast<unsigned char>(bytes[i + 2]);
        out += detail::kB64Alphabet[(v >> 18) & 63];
        out += detail::kB64Alphabet[(v >> 12) & 63];
        out += detail::kB64Alphabet[(v >> 6) & 63];
        out += detail::kB64Alphabet[v & 63];
    }
    const std::size_t rest = bytes.size() - i;
    if (rest == 1) {
        const unsigned v = static_cast<unsigned char>(bytes[i]) << 16;
        out += detail::kB64Alphabet[(v >> 18) & 63];
        out += detail::kB64Alphabet[(v >> 12) & 63];
        if (pad)
            out += "==";
    } else if (rest == 2) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) |
                           (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out += detail::kB64Alphabet[(v >> 18) & 63];
        out += detail::kB64Alphabet[(v >> 12) & 63];
        out += detail::kB64Alphabet[(v >> 6) & 63];
        if (pad)
            out += '=';
    }
    return out;
}

[[nodiscard]] inline std::optional<std::string> base64_decode(std::string_view in) {
    if (in.size() % 4 != 0)
        return std::nullopt;
    std::size_t pad = 0;
    if (!in.empty() && in.back() == '=')
        pad = (in.size() >= 2 && in[in.size() - 2] == '=') ? 2 : 1;
    const std::size_t body = in.size() - pad;
    std::string out;
    out.reserve(in.size() / 4 * 3);
    for (std::size_t i = 0; i < in.size(); i += 4) {
        int v[4];
        int real = 4;
        for (int j = 0; j < 4; ++j) {
            const std::size_t at = i + static_cast<std::size_t>(j);
            if (at >= body) {
                v[j] = 0; // a padding position: only legal in the final quantum (checked above)
                --real;
            } else {
                v[j] = detail::b64_value(in[at]);
                if (v[j] < 0)
                    return std::nullopt; // non-alphabet byte, or '=' before the end
            }
        }
        // The bits that slopped past the last whole byte must be zero (canonical encoding).
        if ((real == 2 && (v[1] & 0x0F) != 0) || (real == 3 && (v[2] & 0x03) != 0))
            return std::nullopt;
        const unsigned w = (static_cast<unsigned>(v[0]) << 18) | (static_cast<unsigned>(v[1]) << 12) |
                           (static_cast<unsigned>(v[2]) << 6) | static_cast<unsigned>(v[3]);
        out += static_cast<char>((w >> 16) & 0xFF);
        if (real > 2)
            out += static_cast<char>((w >> 8) & 0xFF);
        if (real > 3)
            out += static_cast<char>(w & 0xFF);
    }
    return out;
}

} // namespace yuzu::shared
