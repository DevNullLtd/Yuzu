#pragma once

// Finds HTTP route registrations in a source text, for the body-cap route inventory
// (test_body_cap_route_inventory.cpp). Pure and lexical: no I/O, no comment stripping
// (a registration inside a comment is counted), and string literals other than the
// first argument are not understood.
//
// Keep the C++ regular-expression library out of this file: a pattern pass over every
// server source file took 24 s on libc++ for the registrations and 10 s for the
// receiver-call spans (minutes on MSVC debug), and test_store_wiring_order.cpp fails
// if the library's short name appears here in any case, comments included. Everything
// below is a linear find per method name.

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "confined_sink_scan.hpp"

namespace yuzu::test::route_scan {

using yuzu::test::wiring_scan::is_space;
using yuzu::test::wiring_scan::is_word;

struct RouteRegistration {
    std::size_t pos;      // start of the receiver (`sink`, `svr`, `web_server_`)
    std::string method;   // as spelled in source: "Post", "Put", ...
    std::string raw_path; // the first argument's body, escapes kept verbatim
};

struct ReceiverCall {
    std::string verb;
    std::size_t pos; // start of the receiver
};

inline constexpr std::initializer_list<std::string_view> kMutatingMethods = {"Post", "Put", "Patch",
                                                                             "Delete"};
inline constexpr std::initializer_list<std::string_view> kAllVerbs = {"Get",   "Post",   "Put",
                                                                      "Patch", "Delete", "Options"};

namespace detail {

// True when text[start, end) is `name` and the byte before it is not an identifier
// character (the word boundary the former pattern placed before each receiver).
inline bool word_at(std::string_view text, std::size_t start, std::string_view name) {
    if (start + name.size() > text.size() || text.compare(start, name.size(), name) != 0)
        return false;
    return start == 0 || !is_word(text[start - 1]);
}

// Receiver start for a method name beginning at `at`, when the bytes before it are
// `sink.` / `svr.` (and, if `with_web_server`, `web_server_->`); npos otherwise.
inline std::size_t receiver_start(std::string_view text, std::size_t at, bool with_web_server) {
    if (at >= 1 && text[at - 1] == '.') {
        for (const std::string_view name : {std::string_view("sink"), std::string_view("svr")}) {
            if (at - 1 >= name.size() && word_at(text, at - 1 - name.size(), name))
                return at - 1 - name.size();
        }
        return std::string::npos;
    }
    constexpr std::string_view kWeb = "web_server_";
    if (with_web_server && at >= 2 && text[at - 1] == '>' && text[at - 2] == '-' &&
        at - 2 >= kWeb.size() && word_at(text, at - 2 - kWeb.size(), kWeb))
        return at - 2 - kWeb.size();
    return std::string::npos;
}

// Parses the first argument starting at `j` (after the opening parenthesis):
// optional whitespace, then `R"(...)"` or `"..."`. Returns false if neither shape.
inline bool first_argument(std::string_view text, std::size_t j, std::string& out) {
    while (j < text.size() && is_space(text[j]))
        ++j;
    if (j >= text.size())
        return false;
    if (text.compare(j, 3, "R\"(") == 0) {
        const std::size_t body = j + 3;
        const std::size_t close = text.find(")\"", body);
        if (close == std::string_view::npos)
            return false;
        out.assign(text.substr(body, close - body));
        return true;
    }
    if (text[j] != '"')
        return false;
    std::size_t k = j + 1;
    while (k < text.size()) {
        const char c = text[k];
        if (c == '\\') {
            // A backslash escapes any byte except a line break.
            if (k + 1 >= text.size() || text[k + 1] == '\n' || text[k + 1] == '\r')
                return false;
            k += 2;
        } else if (c == '"') {
            out.assign(text.substr(j + 1, k - (j + 1)));
            return true;
        } else {
            ++k;
        }
    }
    return false;
}

} // namespace detail

// Every `<receiver>.<Method>(<literal>` for `Method` in `methods`, where the receiver
// is `sink.` / `svr.` / `web_server_->` and starts at a word boundary (`mysink.Post(`,
// `cli.Post(` and `client.Post(` are not registrations), in ascending position.
inline std::vector<RouteRegistration>
find_route_registrations(std::string_view text, std::initializer_list<std::string_view> methods) {
    std::vector<RouteRegistration> out;
    for (const std::string_view method : methods) {
        const std::string needle = std::string(method) + "(";
        for (std::size_t at = text.find(needle); at != std::string_view::npos;
             at = text.find(needle, at + 1)) {
            const std::size_t recv = detail::receiver_start(text, at, true);
            if (recv == std::string::npos)
                continue;
            std::string path;
            if (!detail::first_argument(text, at + needle.size(), path))
                continue;
            out.push_back({recv, std::string(method), std::move(path)});
        }
    }
    // One list in source order: the methods were searched one at a time.
    std::stable_sort(
        out.begin(), out.end(),
        [](const RouteRegistration& a, const RouteRegistration& b) { return a.pos < b.pos; });
    return out;
}

// Every `sink.<Verb>(` / `svr.<Verb>(` for `Verb` in `verbs` (no `web_server_->`), as
// ONE list in ascending position across all verbs. The caller reads each call's span
// as the text up to the next call in the list, so a per-verb list concatenated would
// put an earlier call after a later one and make that span end before it starts.
inline std::vector<ReceiverCall>
find_receiver_calls(std::string_view text, std::initializer_list<std::string_view> verbs) {
    std::vector<ReceiverCall> out;
    for (const std::string_view verb : verbs) {
        const std::string needle = std::string(verb) + "(";
        for (std::size_t at = text.find(needle); at != std::string_view::npos;
             at = text.find(needle, at + 1)) {
            const std::size_t recv = detail::receiver_start(text, at, false);
            if (recv != std::string::npos)
                out.push_back({std::string(verb), recv});
        }
    }
    std::stable_sort(out.begin(), out.end(),
                     [](const ReceiverCall& a, const ReceiverCall& b) { return a.pos < b.pos; });
    return out;
}

// A representative concrete path for a registered (possibly pattern) path: each
// parenthesised group with no parenthesis inside it becomes `X`. A group that nests
// another keeps its outer text and has only the inner group replaced.
inline std::string probe_path(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    std::size_t i = 0;
    while (i < raw.size()) {
        if (raw[i] == '(') {
            const std::size_t j = raw.find_first_of("()", i + 1);
            if (j != std::string_view::npos && raw[j] == ')') {
                out += 'X';
                i = j + 1;
                continue;
            }
        }
        out += raw[i++];
    }
    return out;
}

} // namespace yuzu::test::route_scan
