#pragma once

/// @file sync_canonical.hpp
/// Shared canonicalization helpers for the ADR-0016 daily-sync sources.
///
/// Extracted byte-identically from sync_source_installed_software.cpp (which
/// carried the original copies; sync_source_device_ci.cpp held a verbatim
/// duplicate). One agent-side implementation now serves every source; the
/// SERVER-side copies (utf8_sanitize.hpp + the per-seam clamps) remain
/// comment-coordinated with this file — the bytes MUST stay identical across
/// agent and server, or the agent- and server-recomputed canonical hashes
/// diverge → permanent need_full (always-full resend) for that source.
///
/// Load-bearing rules preserved from the original sites:
///  - sanitize_utf8_strict accepts exactly what PostgreSQL's UTF8 server
///    encoding accepts (no overlong forms, no surrogates, nothing above
///    U+10FFFF); every invalid byte becomes U+FFFD. An invalid byte reaching
///    PG is SQLSTATE 22021, which rolls back the full-replace transaction and
///    makes the agent resend the identical poison forever (governance UP-IN1).
///  - clamp_field runs the scrub BEFORE the length clamp (U+FFFD is 3 bytes,
///    so scrubbing can grow a field; clamping first would apply a different
///    byte budget on each side), truncates on a codepoint boundary, and strips
///    the canonical framing bytes (0x1F field / 0x1E record separators, NUL)
///    so a value can never corrupt the wire blob's structure.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::agent {

/// Replace every byte that is not part of a valid PostgreSQL-UTF8 sequence
/// with U+FFFD (EF BF BD). See the file header for why this must stay
/// byte-identical to the server seams' copies.
YUZU_EXPORT std::string sanitize_utf8_strict(std::string_view s);

/// Scrub (sanitize_utf8_strict) then clamp to `max_field_len` bytes on a UTF-8
/// codepoint boundary, then strip 0x1F / 0x1E / NUL. `max_field_len` is each
/// source's comment-coordinated cap (it MUST equal the matching server seam's
/// field cap for that source's wire key).
YUZU_EXPORT std::string clamp_field(std::string_view raw, std::size_t max_field_len);

/// SHA-256 hex of a byte string (matches the server's local sha256_hex).
YUZU_EXPORT std::string sha256_hex(const std::string& in);

} // namespace yuzu::agent
