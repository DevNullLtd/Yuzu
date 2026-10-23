#pragma once

/// #4990: the bounded shape of a Forensics-tier plugin's per-agent `error_detail`.
///
/// The execution tracker stores one `error_detail` per (execution, agent). It is shown to every
/// holder of `Execution:Read` (drawer list title, `get_execution_status`, the event stream), a
/// lower tier than the Forensics rows themselves. A Forensics plugin's failure message can carry
/// free text, so the tracker keeps such a message ONLY when it is a machine token, the shape the
/// plugins' own failure tokens already have (`<scope>:<cause>[:<detail>...]`, for example
/// `windows:amcache:hive_locked`); anything else is replaced by the fixed literal
/// `forensics_error`. The status and exit code are untouched.
///
/// The same function is applied at WRITE time (so the durable column, the outbox and the bus are
/// clean) and at READ time in the tracker (so rows written before the upgrade are covered).

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server {

inline constexpr std::string_view kForensicsErrorPlaceholder = "forensics_error";
inline constexpr std::size_t kForensicsErrorMaxBytes = 96;

namespace detail {
[[nodiscard]] constexpr bool is_token_head_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}
[[nodiscard]] constexpr bool is_token_tail_char(char c) noexcept {
    return is_token_head_char(c) || c == '.' || c == '-';
}
} // namespace detail

/// True iff `s` matches `^[a-z0-9_]{1,32}(:[a-z0-9_.-]{1,48}){1,3}$` and is at most 96 bytes.
[[nodiscard]] constexpr bool is_bounded_error_token(std::string_view s) noexcept {
    if (s.empty() || s.size() > kForensicsErrorMaxBytes)
        return false;
    std::size_t i = 0;
    while (i < s.size() && detail::is_token_head_char(s[i]))
        ++i;
    if (i == 0 || i > 32)
        return false;
    int segments = 0;
    while (i < s.size()) {
        if (s[i] != ':')
            return false;
        ++i;
        const std::size_t start = i;
        while (i < s.size() && detail::is_token_tail_char(s[i]))
            ++i;
        const std::size_t len = i - start;
        if (len < 1 || len > 48)
            return false;
        ++segments;
    }
    return segments >= 1 && segments <= 3;
}

/// The value to store or return for a Forensics-tier plugin's `error_detail`. Empty stays empty
/// (nothing to hide, and a success row must not gain an error).
[[nodiscard]] inline std::string sanitize_forensics_error_detail(std::string_view detail) {
    if (detail.empty())
        return {};
    if (is_bounded_error_token(detail))
        return std::string{detail};
    return std::string{kForensicsErrorPlaceholder};
}

} // namespace yuzu::server
