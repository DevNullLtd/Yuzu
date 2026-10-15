#pragma once

// url_attr_scan.hpp — test-only scanner for the URL-bearing attributes of a
// rendered HTML fragment, used by the URL path-segment encoding tests: every
// hx-get / hx-post / hx-put / hx-patch / hx-delete / href / action value is
// returned so a test can assert that an agent- or author-supplied id reached
// each one only as ONE percent-encoded segment (or not at all).

#include "web_utils.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::test {

/// `&amp;`/`&quot;`/`&lt;`/`&gt;`/`&#39;` back to the characters a browser sees.
inline std::string html_unescape(std::string s) {
    auto rep = [&](std::string_view from, std::string_view to) {
        for (std::size_t p = s.find(from); p != std::string::npos; p = s.find(from, p + to.size()))
            s.replace(p, from.size(), to);
    };
    rep("&lt;", "<");
    rep("&gt;", ">");
    rep("&quot;", "\"");
    rep("&#39;", "'");
    rep("&amp;", "&");
    return s;
}

/// Percent-decode like the server's router does before regex matching.
inline std::string pct_decode(const std::string& s) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
            out += static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

/// Every URL attribute value in `html`, HTML-unescaped, in document order.
inline std::vector<std::string> url_attr_values(const std::string& html) {
    static constexpr std::string_view kAttrs[] = {"hx-get=\"",   "hx-post=\"",  "hx-put=\"",
                                                  "hx-patch=\"", "hx-delete=\"", "href=\"",
                                                  "action=\"",   "data-yuzu-chart-url=\""};
    std::vector<std::string> out;
    for (const auto attr : kAttrs) {
        for (std::size_t p = html.find(attr); p != std::string::npos;
             p = html.find(attr, p + attr.size())) {
            const std::size_t start = p + attr.size();
            const std::size_t end = html.find('"', start);
            if (end == std::string::npos)
                break;
            out.push_back(html_unescape(html.substr(start, end - start)));
        }
    }
    return out;
}

/// True if the URL's PATH (before `?`/`#`) has a `.`/`..` segment (browsers collapse it).
inline bool path_has_dot_segment(const std::string& url) {
    const auto qpos = url.find_first_of("?#");
    const std::string path = url.substr(0, qpos);
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto slash = path.find('/', start);
        const auto seg = path.substr(start, slash == std::string::npos ? std::string::npos
                                                                      : slash - start);
        if (yuzu::server::is_dot_segment(seg))
            return true;
        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }
    return false;
}

/// Number of `/` in the URL path (before `?`/`#`).
inline std::size_t path_slashes(const std::string& url) {
    const auto qpos = url.find_first_of("?#");
    return static_cast<std::size_t>(std::count(url.begin(), url.begin() +
                                              static_cast<std::ptrdiff_t>(
                                                  qpos == std::string::npos ? url.size() : qpos),
                                              '/'));
}

inline bool has_url(const std::vector<std::string>& urls, const std::string& wanted) {
    return std::find(urls.begin(), urls.end(), wanted) != urls.end();
}

} // namespace yuzu::test
