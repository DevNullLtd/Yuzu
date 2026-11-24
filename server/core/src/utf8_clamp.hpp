#pragma once

/// @file utf8_clamp.hpp
/// A byte-count cut that never ends inside a UTF-8 sequence. Pure, header-only, no dependencies.
///
/// The live read cuts untrusted device text to a byte bound in several places (failure and error
/// detail, the audit/metric key, the REST and MCP error text). A bare `substr(0, n)` can end in
/// the middle of a multi-byte character, and the JSON writers do not repair that, so the cut goes
/// through this helper at every site. It mirrors the agent's `clamp_output_line`
/// (agents/core/src/command_frames.hpp), which is not reachable from the server tree.
///
/// This helper only moves the CUT point. It does not validate the rest of the text: bytes that
/// were already invalid UTF-8 stay as they are (the JSON builders replace those).

#include <cstddef>
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

} // namespace yuzu::server
