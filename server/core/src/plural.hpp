#pragma once

/// @file plural.hpp
/// PURE singular/plural word choice for dashboard text: one place for the "n == 1" rule the
/// render files each re-spelled. Header-only, no dependencies beyond `<string>`.
///
/// Both helpers return `std::string`, never a view or `const char*`: `std::string + string_view`
/// has no `operator+` before C++26, so a view result would compile on one toolchain and not
/// another at the concatenation sites.

#include <concepts>
#include <string>
#include <string_view>

namespace yuzu::server {

/// `one` when `n == 1`, otherwise `many` (zero and negative counts take `many`). For text where
/// the count is printed separately or the word carries more than a noun (a verb form).
[[nodiscard]] inline std::string plural_word(std::integral auto n, std::string_view one,
                                             std::string_view many) {
    return std::string(n == 1 ? one : many);
}

/// "N word": the count, a space, then the singular or plural form.
[[nodiscard]] inline std::string plural_count(std::integral auto n, std::string_view one,
                                              std::string_view many) {
    return std::to_string(n) + " " + std::string(n == 1 ? one : many);
}

}  // namespace yuzu::server
