#pragma once

/// @file utf8_clamp.hpp
/// A byte-count cut that never ends inside a UTF-8 sequence. Pure, header-only; the only
/// dependency is `utf8_sanitize.hpp`, for `utf8_clean_clamp`.
///
/// The live read cuts untrusted device text to a byte bound in several places (failure and error
/// detail, the audit/metric key, the REST and MCP error text). A bare `substr(0, n)` can end in
/// the middle of a multi-byte character, and the JSON writers do not repair that, so the cut goes
/// through this helper at every site. It mirrors the agent's `clamp_output_line`
/// (agents/core/src/command_frames.hpp), which is not reachable from the server tree.
///
/// `utf8_clamp_prefix` only moves the CUT point: bytes that were already invalid UTF-8 stay as they
/// are. The success-path JSON builder replaces those, but the A4 error envelopes (REST and MCP)
/// escape control characters only, so error text built from untrusted bytes goes through
/// `utf8_clean_clamp`, which also repairs them.

#include "utf8_sanitize.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server {

/// The longest prefix of `s` that is at most `max_bytes` long and ends on a character boundary
/// (the cut backs up over continuation bytes, `10xxxxxx`). A view into `s`; `s` is returned whole
/// when it already fits.
[[nodiscard]] constexpr std::string_view utf8_clamp_prefix(std::string_view s,
                                                           std::size_t max_bytes) noexcept {
    if (s.size() <= max_bytes)
        return s;
    std::size_t cut = max_bytes;
    // s[cut] is the first byte that would be dropped: if it is a continuation byte the cut would
    // split its character, so back up to that character's lead byte and drop the whole thing.
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0U) == 0x80U)
        --cut;
    return s.substr(0, cut);
}

/// Untrusted device or caller text made safe to put on a JSON wire: every byte that is not part of
/// a valid UTF-8 sequence is replaced with U+FFFD (`sanitize_utf8_strict`), THEN the result is cut
/// to at most `max_bytes` on a character boundary. Sanitising first matters: U+FFFD is three
/// bytes, so a clamp-then-sanitise order could exceed the bound.
[[nodiscard]] inline std::string utf8_clean_clamp(std::string_view s, std::size_t max_bytes) {
    const std::string clean = sanitize_utf8_strict(s);
    return std::string(utf8_clamp_prefix(clean, max_bytes));
}

} // namespace yuzu::server
