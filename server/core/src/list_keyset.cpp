#include "list_keyset.hpp"

#include <charconv>
#include <limits>
#include <utility>

namespace yuzu::server::keyset {

namespace {

constexpr std::string_view kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

} // namespace

std::string b64url_encode(std::string_view in) {
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        acc = acc << 8 | static_cast<std::uint8_t>(c);
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += kB64[(acc >> bits) & 63];
        }
    }
    if (bits > 0)
        out += kB64[(acc << (6 - bits)) & 63];
    return out;
}

std::optional<std::string> b64url_decode(std::string_view in) {
    if (in.size() % 4 == 1 || in.find_first_not_of(kB64) != std::string_view::npos)
        return std::nullopt;
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        acc = acc << 6 | static_cast<std::uint32_t>(kB64.find(c));
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return out;
}

std::optional<std::int64_t> parse_int(std::string_view s, std::int64_t lo, std::int64_t hi) {
    if (s.empty())
        return std::nullopt;
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size() || v < lo || v > hi)
        return std::nullopt;
    return v;
}

std::string encode_cursor(std::string_view prefix, const Position& p) {
    std::string out(prefix);
    out += std::to_string(p.key);
    out += ':';
    out += b64url_encode(p.id);
    return out;
}

std::optional<Position> decode_cursor(std::string_view prefix, std::string_view cursor) {
    if (cursor.size() > kCursorMaxBytes || !cursor.starts_with(prefix))
        return std::nullopt;
    const auto rest = cursor.substr(prefix.size());
    const auto colon = rest.find(':');
    if (colon == std::string_view::npos)
        return std::nullopt;
    const auto key = parse_int(rest.substr(0, colon), 0, std::numeric_limits<std::int64_t>::max());
    auto id = b64url_decode(rest.substr(colon + 1));
    if (!key || !id || id->empty() || id->size() > kIdMaxBytes ||
        id->find('\0') != std::string::npos)
        return std::nullopt;
    Position p{*key, std::move(*id)};
    if (encode_cursor(prefix, p) != cursor)
        return std::nullopt;
    return p;
}

} // namespace yuzu::server::keyset
