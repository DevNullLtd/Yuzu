/**
 * uri_userinfo_redact.hpp -- portable URI userinfo (`user[:pass]@`) redaction.
 * No OS call, no plugin include. Hoisted from update_source_trust's
 * redact_apt_word (which now forwards here) so network_config's `proxy`
 * action scrubs proxy credentials with the SAME logic: extend, never fork.
 * Consumers: update_source_trust, network_config.
 */
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::shared {

/// One word of a URI list with the `user[:pass]@` userinfo replaced by
/// `REDACTED@`. Every position below is a RAW byte offset into `word` -- NOTHING
/// is percent-decoded before the split. An earlier version decoded the whole
/// word first, so a %XX-encoded byte in the password (`bob:%2fSEKR3T@host`)
/// could be read as the path separator and stop the authority scan short,
/// missing the '@' entirely and returning the WHOLE credential unredacted; real
/// apt does not decode %XX when it locates the authority either (verified: its
/// own resolved URI still shows `%2fSEKR3T` literally), so working on raw bytes
/// matches apt AND cannot under-run. The one place apt's lexer does recognise a
/// percent form is the scheme separator itself (`http%3a//u:pw@h/` resolves as
/// `http://u:pw@h/`, verified), so ':' and "%3a"/"%3A" are both accepted there,
/// whichever comes first. From there the authority ends at the first raw '/'
/// OUTSIDE a `[...]` group -- an encoded slash (%2f/%2F) does NOT end it, which
/// is what makes the authority span reach the real '@' even when a password
/// contains one. The userinfo is everything in that authority before its LAST
/// '@'; a query string or path holding a secret is not syntactically a userinfo
/// and is emitted as written (documented) -- widening the search past the
/// authority boundary would redact a bare '@' in a path (`h.example/a@b`),
/// which is not a credential and must stay untouched.
[[nodiscard]] inline std::string redact_uri_word(std::string_view word) {
    std::size_t colon = word.find(':');
    std::size_t colon_len = 1;
    for (const std::string_view enc : {std::string_view{"%3a"}, std::string_view{"%3A"}}) {
        const std::size_t p = word.find(enc);
        if (p != std::string_view::npos && (colon == std::string_view::npos || p < colon)) {
            colon = p;
            colon_len = 3;
        }
    }
    if (colon == std::string_view::npos)
        return std::string{word}; // no scheme, so no authority
    std::size_t begin = colon + colon_len;
    if (word.compare(begin, 2, "//") == 0)
        begin += 2;
    std::size_t end = begin;
    bool in_bracket = false;
    for (; end < word.size() && (word[end] != '/' || in_bracket); ++end) {
        if (word[end] == '[')
            in_bracket = true;
        else if (word[end] == ']')
            in_bracket = false;
    }
    const std::size_t at = std::string_view{word}.substr(begin, end - begin).rfind('@');
    if (at == std::string_view::npos)
        return std::string{word};
    return std::string{word.substr(0, begin)} + "REDACTED@" + std::string{word.substr(begin + at + 1)};
}


namespace proxy_detail {
// ^[A-Za-z][A-Za-z0-9+.-]*$ -- the only shape a `key=` or `scheme` prefix may have.
[[nodiscard]] inline bool is_plain_name(std::string_view n) {
    if (n.empty() || !((n[0] >= 'A' && n[0] <= 'Z') || (n[0] >= 'a' && n[0] <= 'z')))
        return false;
    for (const char c : n) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

// One entry (never split): everything up to the LAST '@' anywhere in it is
// userinfo, whatever characters (`; , space = : /`) it holds. Only a plain
// `key=` and/or plain `scheme://` prefix that precedes that '@' survives.
[[nodiscard]] inline std::string redact_entry(std::string_view e) {
    const std::size_t at = e.rfind('@');
    if (at == std::string_view::npos)
        return std::string{e};
    std::size_t keep = 0;
    const std::size_t eq = e.find('=');
    if (eq != std::string_view::npos && eq < at && is_plain_name(e.substr(0, eq)))
        keep = eq + 1;
    const std::size_t sch = e.find("://", keep);
    if (sch != std::string_view::npos && sch < at && is_plain_name(e.substr(keep, sch - keep)))
        keep = sch + 3;
    return std::string{e.substr(0, keep)} + "REDACTED@" + std::string{e.substr(at + 1)};
}

[[nodiscard]] inline bool is_sep(char c) {
    return c == ';' || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// A piece starts a NEW list entry only if it carries a scheme or a plain `key=`.
[[nodiscard]] inline bool starts_entry(std::string_view piece) {
    if (piece.find("://") != std::string_view::npos)
        return true;
    const std::size_t eq = piece.find('=');
    return eq != std::string_view::npos && is_plain_name(piece.substr(0, eq));
}
} // namespace proxy_detail

/// A SINGLE proxy URL / `host:port` / PAC URL (an `*_proxy` environment value, a
/// macOS address, a PAC URL): never split. Fails toward redaction: everything up
/// to the LAST '@' of the whole value is dropped (a path '@' is over-redacted on
/// purpose).
[[nodiscard]] inline std::string redact_proxy_single(std::string_view text) {
    return proxy_detail::redact_entry(text);
}

/// A proxy LIST (a WinHTTP `ProxyServer` string such as
/// `http=u:p@h:80;https=h2:443`). Userinfo is located BEFORE any splitting: a
/// piece that does not start a new entry (no scheme, no plain `key=`) is glued to
/// the previous entry, so a `;`, `,` or space inside a password cannot detach the
/// credential from its '@'. Known residual: a password that itself contains
/// `;key=` or `;scheme://` is indistinguishable from a real entry boundary.
[[nodiscard]] inline std::string redact_proxy_value(std::string_view text) {
    using namespace proxy_detail;
    std::string out;
    std::string cur;      // current (possibly merged) entry text
    std::string pending;  // separators seen since cur's last piece
    bool have = false;
    std::size_t i = 0;
    while (i < text.size()) {
        std::size_t j = i;
        const bool sep = is_sep(text[i]);
        while (j < text.size() && is_sep(text[j]) == sep)
            ++j;
        const std::string_view run = text.substr(i, j - i);
        i = j;
        if (sep) {
            pending.append(run);
            continue;
        }
        if (!have) {
            out += pending;
            pending.clear();
            cur.assign(run);
            have = true;
        } else if (starts_entry(run)) {
            out += redact_entry(cur);
            out += pending;
            pending.clear();
            cur.assign(run);
        } else {
            cur += pending;
            pending.clear();
            cur.append(run);
        }
    }
    if (have)
        out += redact_entry(cur);
    out += pending;
    return out;
}

} // namespace yuzu::shared
