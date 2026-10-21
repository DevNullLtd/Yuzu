#pragma once

// Shared enrollment-token shape predicate, token-file text parser and the
// public token-refusal message.
//
// `enrollment_token_shape_valid` is the exact wire shape of an enrollment
// token (64 lowercase hex characters, a 32-byte CSPRNG value). It moved here
// from server/core/src/enrollment_token_rejection.hpp (which re-exports it via
// a using-declaration) so the agent's token-file reader can gate on exactly
// the same predicate the server applies at Register, without the agent
// including any server header.
//
// `kEnrollmentTokenRejectionPublicMessage` moved here for the same reason: the
// agent recognises a refusal of its token by the exact reply the server sends,
// and compares against the server's own constant, not a copy.
//
// Pure: no I/O, no store or wire types, so this stays inside the
// common/include firewall (CLAUDE.md "Project layout") and both agent and
// server tests can bind it directly.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu {

/// Public wire message for a refused enrollment token -- one string regardless
/// of why (unknown, malformed, revoked, expired, exhausted). The Register RPC's
/// `reject_reason` carries this value verbatim, alongside enrollment_status
/// "denied". Do not vary it by variant (the wire-collapse contract in
/// server/core/src/enrollment_token_rejection.hpp, which re-exports this
/// constant for the server handlers).
inline constexpr std::string_view kEnrollmentTokenRejectionPublicMessage =
    "invalid, expired, or exhausted enrollment token";

/// Exact wire shape of an enrollment token: 64 lowercase hex characters (32
/// CSPRNG bytes). A token that fails it cannot exist, so the server rejects it
/// before touching the store (an unauthenticated caller must not turn arbitrary
/// junk into a database write each) and answers it exactly like a well-formed
/// token that matched nothing, so the check is not an oracle. The check is O(64)
/// and stateless. The agent applies the same predicate to a token file so that a
/// stray non-token file is ignored rather than relayed as a candidate token.
[[nodiscard]] inline bool enrollment_token_shape_valid(std::string_view token) noexcept {
    if (token.size() != 64)
        return false;
    for (const char c : token) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower_hex = c >= 'a' && c <= 'f';
        if (!digit && !lower_hex)
            return false;
    }
    return true;
}

/// Extract an enrollment token from the text content of a token file: strip a
/// leading UTF-8 BOM, take up to the first '\n', trim ASCII whitespace and a
/// trailing '\r', then accept the result only if it passes
/// `enrollment_token_shape_valid` — anything else (empty, wrong length, wrong
/// charset, two tokens on one line, a non-token string) returns nullopt. The
/// caller (the agent's token-file reader) warns and does not send on nullopt,
/// so a file holding junk is ignored rather than relayed to the server as a
/// candidate token.
[[nodiscard]] inline std::optional<std::string> enrollment_token_from_file_text(
    std::string_view text) {
    // Strip a UTF-8 BOM (EF BB BF) if present.
    constexpr std::string_view kBom = "\xEF\xBB\xBF";
    if (text.size() >= kBom.size() && text.substr(0, kBom.size()) == kBom)
        text.remove_prefix(kBom.size());

    // Take up to the first newline.
    const std::size_t nl = text.find('\n');
    std::string_view line = (nl == std::string_view::npos) ? text : text.substr(0, nl);

    // Trim ASCII whitespace (space, tab, CR) from both ends; the line holds no
    // '\n', and an all-whitespace line has no token.
    constexpr std::string_view kTrim = " \t\r";
    const std::size_t begin = line.find_first_not_of(kTrim);
    if (begin == std::string_view::npos)
        return std::nullopt;
    const std::size_t end = line.find_last_not_of(kTrim);
    const std::string_view trimmed = line.substr(begin, end - begin + 1);

    if (!enrollment_token_shape_valid(trimmed))
        return std::nullopt;
    return std::string(trimmed);
}

} // namespace yuzu
