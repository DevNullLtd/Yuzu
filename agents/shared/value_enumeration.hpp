// value_enumeration.hpp -- pure decision for whether a bounded, capped
// enumeration (of registry value names, or any similarly-shaped bounded
// walk) collected EVERY item that existed, or was cut short.
//
// windows.h-free by design (mirrors user_profile_model.hpp's split from
// win_profiles.hpp): the Win32 shell (agents/shared/win_profiles.hpp's
// enumerate_value_names) gathers the three raw facts below -- how many
// items the provider reported existing, the safety cap applied, and how
// far the walk actually got before stopping -- and this pure function
// turns them into the single completeness decision, so it is unit-tested
// on every host without a live registry.
//
// Adversarial-review finding (gate 2, PR3.3-b): a test that only checks
// enumerate_value_names()'s OUTPUT VECTOR is false-green for the
// completeness fix -- neither the cap-truncation nor the
// mid-enumeration-failure branch is reachable without injecting more than
// kMaxEnumeratedValueNames real registry values, or a live transient
// RegEnumValueW failure, neither of which a fixture can produce against a
// live key. Extracting the DECISION here (mirroring
// profile_list_actually_truncated's split) closes that: a fixture drives
// the three input facts directly.

#pragma once

#include <cstdint>

namespace yuzu::win {

/// `reported_count` -- how many values the provider (RegQueryInfoKeyW)
/// said exist. `cap` -- the enumeration's own safety ceiling, already
/// clamped to `reported_count` when the count is smaller than the ceiling.
/// `collected` -- how many the walk actually gathered before it stopped
/// (via the cap being reached, or via a mid-enumeration call failure that
/// breaks the loop early).
///
/// Enumeration is COMPLETE only when nothing was cut short by either
/// mechanism: the cap itself must not have been below the reported count,
/// and the walk must have reached the cap (collected < cap means a
/// mid-enumeration call failed before the cap was reached).
[[nodiscard]] constexpr bool value_enumeration_is_complete(std::uint32_t reported_count,
                                                            std::uint32_t cap,
                                                            std::uint32_t collected) noexcept {
    if (cap < reported_count)
        return false; // the safety ceiling itself cut off real entries
    return collected >= cap;
}

} // namespace yuzu::win
