// wire_utf8.hpp -- one shared "may these bytes cross the plugin ABI" scrubber.
//
// A plugin row travels as a C string over the plugin ABI and is then parsed as UTF-8 by the
// server: a NUL cuts the row at the host's strlen, and a byte outside well-formed UTF-8 makes the
// whole CommandResponse unparseable downstream (the receiver rejects it whole, so one bad byte in
// one file name costs the host's entire result). Plugins that put OS-supplied bytes (file names,
// file text) into a row scrub them here first.
//
// The accepted set is exactly RFC 3629 (Unicode Table 3-7): no overlong forms, no UTF-16
// surrogates, nothing above U+10FFFF, no truncated sequence. Each offending byte is replaced in
// place with '?', so a row keeps its length and its field boundaries. This is stricter than
// yuzu::util::sanitize_utf8, which passes overlong, surrogate and out-of-range sequences that
// protobuf then rejects (#4864); it is a separate header rather than a change to that public SDK
// function so it cannot alter any other plugin's output.
//
// Platform-agnostic pure C++, no OS call, no I/O: the zero-dependency leaf-helper convention of
// this directory.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::shared {

/// Length of the well-formed UTF-8 scalar starting at s[i] (1-4), or 0 when the
/// byte there is NUL or does not start one (stray continuation byte, overlong
/// form, surrogate, above U+10FFFF, truncated sequence).
/// Precondition: i < s.size() (s[i] is read before any bounds check).
[[nodiscard]] inline std::size_t utf8_scalar_len(std::string_view s, std::size_t i) noexcept {
    const auto at = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const auto cont = [&](std::size_t k) { return k < s.size() && (at(k) & 0xC0u) == 0x80u; };
    const unsigned c = at(i);
    if (c == 0)
        return 0;
    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return cont(i + 1) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (!cont(i + 1) || !cont(i + 2))
            return 0;
        if ((c == 0xE0 && at(i + 1) < 0xA0) || (c == 0xED && at(i + 1) >= 0xA0))
            return 0; // overlong / UTF-16 surrogate
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3))
            return 0;
        if ((c == 0xF0 && at(i + 1) < 0x90) || (c == 0xF4 && at(i + 1) >= 0x90))
            return 0; // overlong / above U+10FFFF
        return 4;
    }
    return 0;
}

/// How many bytes scrub_wire_bytes would replace in `s`, without changing it.
[[nodiscard]] inline std::size_t count_invalid_wire_bytes(std::string_view s) noexcept {
    std::size_t bad = 0;
    for (std::size_t i = 0; i < s.size();) {
        const std::size_t n = utf8_scalar_len(s, i);
        if (n == 0) {
            ++bad;
            ++i;
        } else {
            i += n;
        }
    }
    return bad;
}

/// Replaces every byte that may not reach the wire -- NUL (the plugin ABI
/// carries C strings, so a NUL cuts the row) and anything outside well-formed
/// UTF-8 (the ABI is UTF-8; an invalid byte makes the whole response
/// unparseable downstream) -- with '?'. Returns how many bytes were replaced.
inline std::size_t scrub_wire_bytes(std::string& s) {
    std::size_t replaced = 0;
    for (std::size_t i = 0; i < s.size();) {
        const std::size_t n = utf8_scalar_len(s, i);
        if (n == 0) {
            s[i] = '?';
            ++replaced;
            ++i;
        } else {
            i += n;
        }
    }
    return replaced;
}

} // namespace yuzu::shared
