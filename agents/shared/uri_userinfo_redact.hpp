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


/// A proxy setting (an `*_proxy` environment value, a WinHTTP `ProxyServer` list
/// such as `http=h:80;https=h2:443`, a PAC URL, a macOS address) with any
/// credential removed. FAIL-CLOSED and deliberately simple: if the value holds
/// ANY '@', the output is `REDACTED@` followed by the text after the LAST '@' of
/// the WHOLE value, and NOTHING before it survives. No scheme, key, entry or
/// separator parsing is attempted: a password may contain `; , space = : /` and
/// even `;key=` or `;scheme://`, so every attempt to find "the credential" by
/// splitting was a bypass. The cost is deliberate over-redaction: a list with a
/// credential in one entry loses the readable host/port of every entry before
/// it, and a path '@' in a PAC URL is treated as userinfo. A value with no '@'
/// anywhere is returned unchanged (`http=h:80;https=h:443;socks=h4:1080`).
/// Linear in the input.
[[nodiscard]] inline std::string redact_proxy_value(std::string_view text) {
    const std::size_t at = text.rfind('@');
    if (at == std::string_view::npos)
        return std::string{text};
    return "REDACTED@" + std::string{text.substr(at + 1)};
}

/// VESTIGIAL alias of redact_proxy_value: an earlier design treated a single URL
/// differently from a list; both are now the one fail-closed rule above. Kept
/// only so existing call sites (including a Windows-only one) need no edit.
[[nodiscard]] inline std::string redact_proxy_single(std::string_view text) {
    return redact_proxy_value(text);
}

} // namespace yuzu::shared
