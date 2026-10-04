/**
 * email_redaction.hpp -- portable e-mail-address detection and the
 * placeholder substituted for a redacted field. No OS call, no yuzu/
 * include, no plugin include. First consumer: browser_inventory; next:
 * remote_access_audit.
 */
#pragma once

#include <cstddef>
#include <string_view>

namespace yuzu::shared {

/// Substituted for a field whose raw value contains an e-mail address
/// (see `looks_like_email_address`). Irreversible by construction: an
/// e-mail address is an account identifier, so callers filter it, they do
/// not document an exception.
inline constexpr std::string_view kRedactedEmailPlaceholder = "[redacted-email]";

/// True when `value` CONTAINS an e-mail-shaped substring anywhere: bare,
/// decorated (`Alice <alice@example.com>`), embedded, several, quoted
/// (`"alice.smith"@example.com`), with RFC 5322 comments or folding
/// whitespace around the '@' (`alice(comment)@example.com`,
/// `alice\n@example.com`). Coarse by design; over-match is the safe
/// direction. The only local-side condition is that '@' is not at position
/// 0. The domain side must look email-shaped after CFWS (folding
/// whitespace and nested parenthesized comments) is skipped after '@' and
/// around each dot: a dotted label pair (ASCII alnum/-/._ or any byte >=
/// 0x80, so a raw IDN domain matches) or a non-empty bracketed literal
/// (`@[203.0.113.5]`). An unterminated comment consumes the rest of
/// `value` and yields no match.
[[nodiscard]] inline bool looks_like_email_address(std::string_view value) {
    auto is_domain_char = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_' || static_cast<unsigned char>(c) >= 0x80;
    };
    // Skips folding whitespace and parenthesized comments (nested, tracked
    // by depth) from `i`. A backslash and the next byte are one quoted-pair,
    // never a depth change; an unterminated comment eats the rest of `value`.
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
                        // Quoted-pair; a trailing lone backslash must not pass the end.
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
