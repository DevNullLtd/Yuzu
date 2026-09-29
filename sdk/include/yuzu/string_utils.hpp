#pragma once

/// @file string_utils.hpp
/// Pure utility functions shared across Yuzu agent plugins.
/// Extracted here for testability and to avoid duplication.

#include <algorithm>
#include <cctype>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::util {

/// Case-insensitive substring match.
inline bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

/// Replace invalid UTF-8 bytes with '?' to avoid protobuf serialization errors.
/// Windows registry strings may contain Latin-1 or other non-UTF-8 data.
inline std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            // ASCII
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            // Valid 2-byte sequence
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            // Valid 3-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            // Valid 4-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

/// Escape pipe characters in output values.
inline std::string escape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '|')
            out += "\\|";
        else
            out += c;
    }
    return out;
}

/// Escape a value for a pipe-delimited output field, safely.
///
/// The shared server decoder (server/core/src/result_parsing.hpp) only knows
/// how to undo a single backslash before a pipe ("\|" -> "|"); it treats any
/// other backslash, including a doubled one, as literal data. Making this
/// function fully reversible would require changing that shared decoder,
/// which would silently corrupt '\\' values already emitted by every other
/// producer on the wire. So this is intentionally LOSSY on literal
/// backslashes: a literal '\' folds to '/' before pipe-escaping, and CR/LF
/// fold to spaces (newlines are the row separator and have no escape
/// representation in this grammar). A fully reversible escape grammar is
/// deferred to a versioned protocol migration that updates the decoder and
/// every producer together.
inline std::string safe_output_field(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '\\')
            out += '/';
        else if (ch == '\r' || ch == '\n')
            out += ' ';
        else
            out += ch;
    }
    return escape_pipes(out);
}

/// Sanitize input: only allow alphanumeric, spaces, dots, hyphens, underscores,
/// and slashes. Used to prevent command injection in subprocess arguments.
inline std::string sanitize_input(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (char ch : input) {
        if (std::isalnum(static_cast<unsigned char>(ch)) || ch == ' ' || ch == '.' || ch == '-' ||
            ch == '_' || ch == '/') {
            out += ch;
        }
    }
    return out;
}

/// Convert total seconds to human-readable uptime string "Xd Yh Zm".
inline std::string format_uptime(long long total_seconds) {
    long long days = total_seconds / 86400;
    long long hours = (total_seconds % 86400) / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    return std::format("{}d {}h {}m", days, hours, minutes);
}

/// Split a string into arguments with shell-like quote handling.
/// Handles double quotes, single quotes, and whitespace splitting.
inline std::vector<std::string> split_args(std::string_view s) {
    std::vector<std::string> result;
    std::string current;
    bool in_quote = false;
    char quote_char = 0;

    for (size_t i = 0; i < s.size(); ++i) {
        char ch = s[i];
        if (in_quote) {
            if (ch == quote_char) {
                in_quote = false;
            } else {
                current += ch;
            }
        } else if (ch == '"' || ch == '\'') {
            in_quote = true;
            quote_char = ch;
        } else if (ch == ' ' || ch == '\t') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += ch;
        }
    }
    if (!current.empty()) {
        result.push_back(std::move(current));
    }
    return result;
}

/// Generate one RFC 864 line starting at the given offset into the character set.
/// Produces a 72-character line of rotating printable ASCII (' ' through '~').
inline std::string chargen_line(int offset) {
    constexpr int kFirstChar = 32;                         // ' '
    constexpr int kLastChar = 126;                         // '~'
    constexpr int kCharRange = kLastChar - kFirstChar + 1; // 95
    constexpr int kLineLength = 72;

    std::string line;
    line.reserve(kLineLength);
    for (int i = 0; i < kLineLength; ++i) {
        line.push_back(static_cast<char>(kFirstChar + ((offset + i) % kCharRange)));
    }
    return line;
}

} // namespace yuzu::util
