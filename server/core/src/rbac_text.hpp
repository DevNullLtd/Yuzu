#pragma once

/// @file rbac_text.hpp
/// Shared check for free-text RBAC identifiers (a role name, a principal id) that reach a
/// comparison and a SQL bind. The rule is one function so the places that decide on a value and
/// the place that acts on it cannot disagree about what the value is.

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

} // namespace yuzu::server
