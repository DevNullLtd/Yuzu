/**
 * email_redaction.hpp -- portable e-mail-address detection and the
 * placeholder substituted for a redacted field. No OS call, no yuzu/
 * include, no plugin include. Consumer today: browser_inventory.
 */
#pragma once

#include <cstddef>
#include <string_view>

namespace yuzu::shared {

/// Substituted for `profile_dir`/`display_name` when the raw value
/// contains an e-mail address (see `looks_like_email_address` below).
/// Irreversible by construction -- unlike the accepted personal-name
/// residual risk on `display_name`, an e-mail address is a
/// browsing-account identifier and the PRIVACY CONTRACT above forbids it
/// unconditionally, so this is a filter, not a documented exception.
inline constexpr std::string_view kRedactedEmailPlaceholder = "[redacted-email]";

/// True when `value` CONTAINS an e-mail-shaped substring anywhere -- bare
/// (`account@example.com`), decorated (`Alice <alice@example.com>`,
/// `alice@example.com (Work)`), embedded (`x alice@example.com`),
/// several (`a@x.org,b@y.org`), quoted (`"alice.smith"@example.com`),
/// RFC 5322 comment-syntax (`alice(comment)@example.com`), or separated
/// from the domain by folding whitespace/control characters
/// (`alice\n@example.com`); coarse by design, over-match is the safe
/// direction. Round-2 governance finding G-1 (2026-09-23): the earlier
/// local-part exclusion list rejected exactly the whitespace/quote/
/// comment characters a decorated or folded address puts immediately
/// before '@', which is backwards for a filter whose stated principle is
/// over-match-is-safe -- the ONLY local-side condition is now that '@' is
/// not at position 0. The domain side still has to look email-shaped, but
/// CFWS (folding whitespace and/or a parenthesized comment, possibly
/// nested) is skipped both immediately after '@' and around each domain
/// dot before that check runs: a dotted label (label '.' label, non-empty
/// either side once CFWS is skipped; domain bytes are ASCII alnum/-/._ or
/// any byte >= 0x80, so a raw non-punycode IDN domain still matches), or a
/// non-empty bracketed domain literal (`@[203.0.113.5]`, itself reachable
/// through leading CFWS); any hit redacts the whole field. Round-2
/// adversarial finding 2026-09-23 (domain-side mirror of G-3): the earlier
/// domain scan started matching immediately at '@', so CFWS before the
/// domain or around a dot (`alice@ (comment)example.com`,
/// `alice@example . com`) produced an empty or truncated domain and
/// returned false. (An unterminated comment consumes the rest of `value`
/// and yields no match by the same pre-existing contract `skip_cfws`
/// documents below -- not something this finding changed.) Round-3
/// code-review finding F1 (2026-09-23): a backslash-escaped byte inside a
/// comment is consumed as one RFC 5322 quoted-pair and never changes depth,
/// so an escaped `(`/`)` (`alice@(a\(b)example.com`,
/// `alice@(escaped\)paren)example.com`) does not open/close the comment
/// early and truncate the domain scan that follows.
[[nodiscard]] inline bool looks_like_email_address(std::string_view value) {
    auto is_domain_char = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_' || static_cast<unsigned char>(c) >= 0x80;
    };
    // Skips a run of folding whitespace and/or a parenthesized comment
    // (nested comments tracked by depth) starting at `i`, repeating until
    // neither advances. An unterminated comment consumes the rest of
    // `value` (depth never returns to 0), which is intentional: the caller
    // then finds an empty domain and reports no match. Inside a comment, a
    // backslash and the byte immediately after it are consumed together as
    // one RFC 5322 quoted-pair -- that byte is never itself tested as a
    // depth-changing '(' or ')' (round-3 finding F1, 2026-09-23: an escaped
    // ')' inside a comment was closing the comment early, truncating the
    // domain scan that follows).
    auto skip_cfws = [value](std::size_t& i) {
        for (;;) {
            bool advanced = false;
            while (i < value.size()) {
                const char c = value[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v') {
                    ++i;
                    advanced = true;
                } else {
                    break;
                }
            }
            if (i < value.size() && value[i] == '(') {
                std::size_t depth = 0;
                while (i < value.size()) {
                    if (value[i] == '\\') {
                        // Quoted-pair: consume the backslash and the next
                        // byte as one unit, never as a depth-changing
                        // paren. A trailing lone backslash must not step
                        // past the end -- it then reads as an unterminated
                        // comment (depth stays open), same as before.
                        i += (i + 1 < value.size()) ? 2 : 1;
                    } else if (value[i] == '(') {
                        ++depth;
                        ++i;
                    } else if (value[i] == ')') {
                        --depth;
                        ++i;
                        if (depth == 0) {
                            break;
                        }
                    } else {
                        ++i;
                    }
                }
                advanced = true;
            }
            if (!advanced) {
                break;
            }
        }
    };

    for (auto at = value.find('@'); at != std::string_view::npos; at = value.find('@', at + 1)) {
        if (at == 0) {
            continue;
        }
        std::size_t i = at + 1;
        skip_cfws(i);
        if (i < value.size() && value[i] == '[') {
            const auto close = value.find(']', i + 1);
            if (close != std::string_view::npos && close > i + 1) {
                return true;
            }
            continue;
        }
        std::size_t label_len = 0;
        bool pending_dot = false;
        while (i < value.size()) {
            skip_cfws(i);
            if (i >= value.size()) {
                break;
            }
            const char c = value[i];
            if (is_domain_char(c) && c != '.') {
                if (pending_dot) {
                    return true;
                }
                ++label_len;
                ++i;
            } else if (c == '.') {
                pending_dot = (label_len > 0);
                label_len = 0;
                ++i;
            } else {
                break;
            }
        }
    }
    return false;
}

} // namespace yuzu::shared
