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


/// A proxy setting (an `*_proxy` environment value, a WinHTTP proxy string such
/// as `http=u:p@h:80;https=h2:443`, a PAC URL) with every userinfo redacted.
/// Split on ';', ',' and whitespace; a leading `key=` is kept. A token with a
/// scheme goes through redact_uri_word; a scheme-less `[user[:pass]@]host:port`
/// token loses everything before its LAST '@' in the authority. Fails toward
/// redaction: any '@' before the first '/' of the authority is treated as a
/// userinfo terminator.
[[nodiscard]] inline std::string redact_proxy_value(std::string_view text) {
    std::string out;
    std::size_t i = 0;
    const auto is_sep = [](char c) {
        return c == ';' || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    while (i < text.size()) {
        if (is_sep(text[i])) {
            out += text[i++];
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && !is_sep(text[j]))
            ++j;
        std::string_view tok = text.substr(i, j - i);
        i = j;
        std::string prefix;
        const std::size_t scheme = tok.find("://");
        const std::size_t eq = tok.find('=');
        const std::size_t first_at = tok.find('@');
        if (eq != std::string_view::npos && (scheme == std::string_view::npos || eq < scheme) &&
            (first_at == std::string_view::npos || eq < first_at)) {
            prefix.assign(tok.substr(0, eq + 1));
            tok.remove_prefix(eq + 1);
        }
        if (tok.find("://") != std::string_view::npos) {
            out += prefix;
            out += redact_uri_word(tok);
            continue;
        }
        // Scheme-less authority: strip up to the last '@' before the first '/'.
        const std::size_t slash = tok.find('/');
        const std::string_view auth = tok.substr(0, slash);
        const std::size_t at = auth.rfind('@');
        out += prefix;
        if (at == std::string_view::npos) {
            out.append(tok);
        } else {
            out.append("REDACTED@").append(tok.substr(at + 1));
        }
    }
    return out;
}

} // namespace yuzu::shared
