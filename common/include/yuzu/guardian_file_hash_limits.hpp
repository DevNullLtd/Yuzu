#pragma once

/// @file guardian_file_hash_limits.hpp
/// #2233 item 6: the hard ceiling on an authored Guaranteed State `file-hash-equals`
/// `max_bytes`, single-sourced between the agent (which enforces it,
/// `agents/core/src/guardian_rule_eval.hpp`) and the server (which now also rejects
/// an over-ceiling value at authoring time, `server/core/src/guardian_rule_spec.cpp`)
/// so the two cannot drift apart on the ceiling value the way two independent
/// hand-rolled clamps would (this repo's established pattern for exactly this class
/// of bug; see `common/include/yuzu/audit_retention_rules.hpp`'s `classify` for the
/// precise same-directory precedent of a server+agent shared decision constant).
///
/// A footgun guard, not a tight resource limit: an authored value previously had NO
/// upper bound on either side, so an operator (deliberately or by typo) could direct
/// the detached hashing worker to read to EOF or an effectively-unbounded cap, which
/// can saturate the file bulkhead and trip the F3 hard-exit grace at shutdown. Picked
/// with headroom under `guard_file.cpp`'s own `static_cast<std::size_t>` truncation
/// point (4 GiB on a 32-bit `size_t`, e.g. 32-bit ARM) - comfortably generous (16x
/// the 64 MiB default) for any legitimate file-integrity target while staying well
/// clear of that boundary. Flagged in this PR's body for review, not asserted as
/// definitively correct - there is no measured fleet requirement pinning this exact
/// figure.
///
/// Pure decision code only (#2549 firewall): no I/O, no store/wire types, no
/// server-trust-boundary authority.

#include <cstdint>

namespace yuzu::guardian {

inline constexpr std::uint64_t kMaxFileHashBytes = 1024ull * 1024 * 1024; // 1 GiB

/// Clamp an already-normalised (0->default) max_bytes to kMaxFileHashBytes. Used by
/// the agent's arm-time paths (spark + legacy), which enforce the ceiling silently.
[[nodiscard]] constexpr std::uint64_t clamp_max_hash_bytes(std::uint64_t v) noexcept {
    return v > kMaxFileHashBytes ? kMaxFileHashBytes : v;
}

} // namespace yuzu::guardian
