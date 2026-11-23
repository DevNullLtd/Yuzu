// file_search_names.hpp -- reversible name encoding, file identity and the match row of the
// on-demand file search.
//
// encode_name keeps a byte verbatim only when it belongs to a well-formed UTF-8 scalar
// (utf8_scalar_len) and is not '%', '|', '\\', 0x7F or below 0x20; every other byte becomes %XX
// with UPPERCASE hex. The result therefore never contains the row delimiter, an ASCII control or
// anything that is not well-formed UTF-8, and decode_name gives back the exact original bytes,
// including NUL and invalid UTF-8. decode_name is strict: it accepts a string only when
// encode_name(decoded) equals the input, so every name has exactly ONE encoding.
// Well-formed scalars above 0x7F pass verbatim, C1 controls, U+2028, U+2029, bidirectional controls
// and noncharacters included: split rows on '\n' only, and isolate bidirectional text on display.
//
// '/' is never encoded, so a '/'-joined path encodes component-wise for free.
//
// The identity column of a match row ("dev:file_id", 16 lowercase hex digits each, "-" when both
// are zero) is the key a later extent row will reference. Nothing here builds extents.
//
// Pure C++: nothing here takes or produces a path that is opened. Platform-agnostic, no OS call,
// no I/O: the zero-dependency leaf-helper convention of this directory.
#pragma once

#include "wire_utf8.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::shared::file_search {

namespace detail {

inline constexpr char kHexUpper[] = "0123456789ABCDEF";
inline constexpr char kHexLower[] = "0123456789abcdef";

[[nodiscard]] inline bool name_byte_needs_escape(unsigned char c) noexcept {
    return c < 0x20 || c == 0x7F || c == '%' || c == '|' || c == '\\';
}

/// Value of one UPPERCASE hex digit, or -1 (lowercase is not a canonical spelling).
[[nodiscard]] inline int hex_upper_value(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

} // namespace detail

[[nodiscard]] inline std::string encode_name(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (std::size_t i = 0; i < raw.size();) {
        const std::size_t n = utf8_scalar_len(raw, i);
        const auto c = static_cast<unsigned char>(raw[i]);
        if (n == 0 || (n == 1 && detail::name_byte_needs_escape(c))) {
            out += '%';
            out += detail::kHexUpper[c >> 4];
            out += detail::kHexUpper[c & 0x0F];
            ++i;
        } else {
            out.append(raw.substr(i, n));
            i += n;
        }
    }
    return out;
}

[[nodiscard]] inline std::optional<std::string> decode_name(std::string_view enc) {
    std::string out;
    out.reserve(enc.size());
    for (std::size_t i = 0; i < enc.size(); ++i) {
        if (enc[i] != '%') {
            out += enc[i];
            continue;
        }
        if (enc.size() - i < 3)
            return std::nullopt; // lone '%' or truncated escape
        const int hi = detail::hex_upper_value(enc[i + 1]);
        const int lo = detail::hex_upper_value(enc[i + 2]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out += static_cast<char>((hi << 4) | lo);
        i += 2;
    }
    if (encode_name(out) != enc)
        return std::nullopt; // not the one canonical spelling (e.g. "%41", a raw NUL)
    return out;
}

/// (device, file id) of a file or directory as seen by the walk; 0/0 = unknown.
struct FileIdentity {
    std::uint64_t dev{0};
    std::uint64_t file_id{0};
};

[[nodiscard]] inline std::string format_file_identity(FileIdentity id) {
    if (id.dev == 0 && id.file_id == 0)
        return "-";
    std::string out(33, ':');
    for (int k = 0; k < 16; ++k) {
        out[static_cast<std::size_t>(k)] = detail::kHexLower[(id.dev >> (60 - 4 * k)) & 0xF];
        out[static_cast<std::size_t>(17 + k)] = detail::kHexLower[(id.file_id >> (60 - 4 * k)) & 0xF];
    }
    return out;
}

enum class EntryKind { file, directory };

/// `match|<encoded path>|<file|directory>|<identity>`. The identity column is the key a later
/// extent row will reference.
[[nodiscard]] inline std::string format_match_row(std::string_view raw_path, EntryKind kind, FileIdentity id) {
    std::string row = "match|";
    row += encode_name(raw_path);
    row += kind == EntryKind::directory ? "|directory|" : "|file|";
    row += format_file_identity(id);
    return row;
}

} // namespace yuzu::shared::file_search
