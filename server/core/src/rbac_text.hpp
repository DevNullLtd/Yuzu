#pragma once

/// @file rbac_text.hpp
/// Shared check for free-text RBAC identifiers (a role name, a principal id) that reach a
/// comparison and a SQL bind. The rule is one function so the places that decide on a value and
/// the place that acts on it cannot disagree about what the value is.
///
/// Despite the name, this is no longer RBAC-only: the same predicate guards the id fields of the
/// OTA package routes (update_registry.hpp) and the schedule routes (schedule_routes.cpp), the
/// platform and architecture fields of the settings uploads, and the management-group id fields.
/// The name is kept on purpose (it began as the RBAC rule and renaming it touches every caller);
/// read "identifier" for "RBAC identifier" wherever the predicate is used outside RBAC.
///
/// EXTEND this, never fork it: this is the single clean-text predicate for identifiers.
/// Near-duplicates exist in outbound_url_policy.hpp and instruction_execute.hpp for other
/// fields; do not add another copy for an RBAC identifier.

#include <string_view>

namespace yuzu::server {

/// True when `s` holds no NUL byte, no other C0 control byte (0x01-0x1F) and no DEL (0x7F).
/// UTF-8 multi-byte sequences are untouched. This is a check for identifiers, not for
/// descriptive text: callers refuse a failing value instead of rewriting it.
[[nodiscard]] constexpr bool rbac_text_is_clean(std::string_view s) noexcept {
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F)
            return false;
    }
    return true;
}

// Boundary pins: the accepted range is exactly 0x20-0x7E plus every byte at or above 0x80.
static_assert(!rbac_text_is_clean(std::string_view("\x01", 1)));
static_assert(!rbac_text_is_clean(std::string_view("\x1f", 1)));
static_assert(rbac_text_is_clean(std::string_view(" ", 1)));
static_assert(rbac_text_is_clean(std::string_view("~", 1)));
static_assert(!rbac_text_is_clean(std::string_view("\x7f", 1)));
static_assert(rbac_text_is_clean(std::string_view("\x80", 1)));

} // namespace yuzu::server
