#pragma once

// Finds the `ConfinedDispatchSink{...}` constructions in a source text, for the
// HA wiring guard in test_store_wiring_order.cpp. Pure and lexical: no I/O, and the
// caller strips `//` comments first (block comments and string literals are not
// understood).
//
// Keep the C++ regular-expression library out of this file: scanning server.cpp
// with it takes minutes on MSVC debug (seconds at most on libstdc++ and libc++), and
// test_store_wiring_order.cpp fails if it appears here.

#include <cstddef>
#include <string_view>
#include <vector>

namespace yuzu::test::wiring_scan {

struct ConfinedSinkSite {
    std::size_t start; // the qualifier when there is one, else the type name
    bool has_remote_presence;
    bool has_prepare_route_fallback;
};

// Bytes after a site's start searched for the two field markers. The real
// initializers run roughly 740-840 bytes from start to closing brace, so this covers
// them with room to spare; the same room lets a marker that belongs to what
// follows a site be credited to it (none does today).
inline constexpr std::size_t kFieldWindow = 1200;
inline constexpr std::string_view kTypeName = "ConfinedDispatchSink";
inline constexpr std::string_view kQualifier = "yuzu::server::";

// ASCII-only on purpose: identical results whatever the locale or standard library.
inline bool is_space(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}
inline bool is_word(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

// Recognises `[yuzu::server::]ConfinedDispatchSink [identifier] {`: whitespace and
// identifier runs are unbounded, with at most one identifier. A `->` before the
// (qualified) type name is a lambda's trailing-return-type annotation whose brace
// opens a function body, so it is skipped. A match consumes its whole span before
// the search resumes. Parentheses, `= {`, a type alias, or a block comment between
// the type name and its brace are not recognised. A site reports whether the next
// kFieldWindow bytes mention `has_remote_presence` and call `->prepare(` (the
// `prepare_route_fallback` field is positional at every real site, so its lambda
// body's call is the stable marker).
inline std::vector<ConfinedSinkSite> find_confined_dispatch_sink_sites(std::string_view text) {
    std::vector<ConfinedSinkSite> sites;
    const std::size_t n = text.size();
    std::size_t search_from = 0;
    while (true) {
        const std::size_t at = text.find(kTypeName, search_from);
        if (at == std::string_view::npos)
            break;
        const std::size_t after_name = at + kTypeName.size();

        // Suffix: whitespace, at most one identifier, whitespace, then `{`.
        std::size_t i = after_name;
        while (i < n && is_space(text[i]))
            ++i;
        std::size_t word_end = i;
        while (word_end < n && is_word(text[word_end]))
            ++word_end;
        if (word_end > i) {
            i = word_end;
            while (i < n && is_space(text[i]))
                ++i;
        }
        if (i >= n || text[i] != '{') {
            search_from = after_name; // a mention, not a construction
            continue;
        }

        // Prefix: an optional qualifier directly before the name, then optional
        // whitespace and `->`.
        std::size_t start = at;
        if (at >= kQualifier.size() &&
            text.compare(at - kQualifier.size(), kQualifier.size(), kQualifier) == 0)
            start -= kQualifier.size();
        std::size_t arrow_end = start;
        while (arrow_end > 0 && is_space(text[arrow_end - 1]))
            --arrow_end;
        const bool trailing_return =
            arrow_end >= 2 && text[arrow_end - 2] == '-' && text[arrow_end - 1] == '>';

        search_from = i + 1;
        if (trailing_return)
            continue;

        const std::string_view field = text.substr(start, kFieldWindow);
        sites.push_back(ConfinedSinkSite{
            start,
            field.find("has_remote_presence") != std::string_view::npos,
            field.find("->prepare(") != std::string_view::npos,
        });
    }
    return sites;
}

} // namespace yuzu::test::wiring_scan
