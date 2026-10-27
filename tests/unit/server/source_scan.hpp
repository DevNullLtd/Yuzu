#pragma once

// Shared helpers for the source-scan tripwires (test_shutdown_join_order.cpp,
// test_store_wiring_order.cpp, test_legacy_executions_scope_authz.cpp, and line_of for
// route_inventory_scan.hpp and test_step_up_route_inventory.cpp): read a file
// under server/core/src, cut its `//` comments, and locate literal anchors by plain
// substring search.
//
// Keep the C++ regular-expression library out of this file: a pattern pass over a
// ~0.76 MB source file costs seconds on libc++ and expected to cost far more on MSVC debug (not measured there), and
// test_store_wiring_order.cpp fails if the library's short name appears here in any
// case, comments included. Everything below is a linear find plus a copy.
//
// strip_line_comments cuts from every `//` to the end of its line and keeps the
// newline, so line numbers are unchanged. Its output is byte-identical to the
// pattern-based strip it replaced. Its limits, all inherited: it cuts a line at a
// `//` inside a string literal (a URL in a literal loses the rest of its line), and
// it does not understand block comments (a `//` inside one is cut, and the rest of
// the block survives).
//
// stripped_source(basename) reads and strips a file under YUZU_SERVER_SRC_DIR once
// per test process. The cache and its counter have external linkage (named namespace,
// inline) so every translation unit that includes this header shares the one copy.

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build (meson.project_source_root() / 'server' / 'core' / 'src') -- see the server_test_exe cpp_args block."
#endif

namespace yuzu::test::source_scan {

inline std::string strip_line_comments(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t cut = text.find("//", pos);
        if (cut == std::string_view::npos) {
            out.append(text.substr(pos));
            break;
        }
        out.append(text.substr(pos, cut - pos));
        const std::size_t eol = text.find('\n', cut);
        if (eol == std::string_view::npos)
            break;
        pos = eol; // the newline itself is copied by the next pass
    }
    return out;
}

// Comment-evasion-proof variant for scans that must not be satisfied by commented-out code
// (#6079 qe-S2): drops `//` and `/* */` comments, keeps every newline (line numbers are
// unchanged), and leaves string, character and raw-string literals untouched, so a `//`
// inside a literal is not a comment. A single linear pass; no pattern library.
inline std::string strip_comments(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    const std::size_t n = text.size();
    std::size_t i = 0;
    while (i < n) {
        const char c = text[i];
        if (c == '/' && i + 1 < n && text[i + 1] == '/') {
            while (i < n && text[i] != '\n')
                ++i; // the newline is copied by the next pass
        } else if (c == '/' && i + 1 < n && text[i + 1] == '*') {
            i += 2;
            while (i < n && !(text[i] == '*' && i + 1 < n && text[i + 1] == '/')) {
                if (text[i] == '\n')
                    out.push_back('\n');
                ++i;
            }
            i = (i < n) ? i + 2 : n;
            out.push_back(' ');
        } else if (c == 'R' && i + 1 < n && text[i + 1] == '"') {
            // Raw string: R"delim( ... )delim"
            const std::size_t open = text.find('(', i + 2);
            if (open == std::string_view::npos) {
                out.push_back(c);
                ++i;
                continue;
            }
            const std::string close =
                ")" + std::string(text.substr(i + 2, open - (i + 2))) + "\"";
            const std::size_t end = text.find(close, open);
            const std::size_t stop =
                (end == std::string_view::npos) ? n : end + close.size();
            out.append(text.substr(i, stop - i));
            i = stop;
        } else if (c == '"' || c == '\'') {
            out.push_back(c);
            ++i;
            while (i < n && text[i] != c && text[i] != '\n') {
                if (text[i] == '\\' && i + 1 < n)
                    out.push_back(text[i++]);
                out.push_back(text[i++]);
            }
            if (i < n && text[i] == c) {
                out.push_back(c);
                ++i;
            }
        } else {
            out.push_back(c);
            ++i;
        }
    }
    return out;
}

inline std::string read_text_file(const std::filesystem::path& path) {
    INFO("reading " << path.string());
    REQUIRE(std::filesystem::is_regular_file(path));
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// 1-based line of byte offset `pos`.
inline int line_of(std::string_view text, std::size_t pos) {
    int line = 1;
    for (std::size_t i = 0; i < pos && i < text.size(); ++i)
        if (text[i] == '\n')
            ++line;
    return line;
}

// Line of every non-overlapping occurrence of the literal `needle`, in order.
inline std::vector<int> occurrence_lines(std::string_view text, std::string_view needle) {
    std::vector<int> lines;
    if (needle.empty())
        return lines;
    for (std::size_t at = text.find(needle); at != std::string_view::npos;
         at = text.find(needle, at + needle.size()))
        lines.push_back(line_of(text, at));
    return lines;
}

inline int count_occurrences(std::string_view text, std::string_view needle) {
    return static_cast<int>(occurrence_lines(text, needle).size());
}

// Returns the line of the SOLE occurrence of `needle`, failing loudly if it is found
// zero or more than once. A vacuous pass would be worse than a hard failure: it would
// mean the scan broke, not that the ordering is fine, and a second occurrence earlier
// in the file (a hoisted helper, say) would satisfy every ordering check while the
// real order regressed.
inline int require_one_line(std::string_view text, std::string_view needle, const char* label) {
    INFO("looking for: " << label);
    const auto lines = occurrence_lines(text, needle);
    REQUIRE(lines.size() == 1);
    return lines[0];
}

// Times stripped_source() has read a file. Plain int: Catch2 runs cases serially.
inline int stripped_source_loads = 0;

// `<YUZU_SERVER_SRC_DIR>/<basename>` with every `//` comment stripped, read once per
// process. A reference into a std::map stays valid as later files are added. A failed
// read throws before the entry is stored, so the next call retries.
inline const std::string& stripped_source(std::string_view basename) {
    static std::map<std::string, std::string, std::less<>> cache;
    auto it = cache.find(basename);
    if (it == cache.end()) {
        std::string stripped = strip_line_comments(
            read_text_file(std::filesystem::path(YUZU_SERVER_SRC_DIR) / std::string(basename)));
        ++stripped_source_loads;
        it = cache.emplace(std::string(basename), std::move(stripped)).first;
    }
    return it->second;
}

// `<YUZU_SERVER_SRC_DIR>/<basename>` with every C and C++ comment stripped
// (strip_comments), read once per process. Use it for a scan whose pass must not be
// satisfiable by commented-out code.
inline const std::string& comment_free_source(std::string_view basename) {
    static std::map<std::string, std::string, std::less<>> cache;
    auto it = cache.find(basename);
    if (it == cache.end()) {
        std::string stripped = strip_comments(
            read_text_file(std::filesystem::path(YUZU_SERVER_SRC_DIR) / std::string(basename)));
        it = cache.emplace(std::string(basename), std::move(stripped)).first;
    }
    return it->second;
}

} // namespace yuzu::test::source_scan
