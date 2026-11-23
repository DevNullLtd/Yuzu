// ioc_examined.hpp -- what examining one file_paths entry produced, and how a bounded call's outcome
// maps onto it (pure, so the timeout / refused-helper / threw mapping is testable without a stall).
#pragma once

#include <bounded_wait.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::ioc {

/// What examining one path produced. Plain value type (it crosses the helper-thread boundary).
struct Examined {
    std::string path;
    std::string cause;      ///< non-empty: the path was NOT examined (or not hashed), and why
    bool absent{false};     ///< a definitive "no such file" (never a coverage gap)
    bool exists{false};
    std::uint64_t size{0};
    bool hashed{false};
    std::string hex;        ///< sha256, only when hashed
};

/// Map the outcome of the bounded examine call: only a Completed call that produced a value is
/// trusted; a timeout, a call refused at the helper ceiling and a call that threw are all "not
/// examined, cause timeout" (never absent, never clean).
[[nodiscard]] inline Examined examined_from_call(const std::string& path,
                                                 yuzu::shared::BoundedCallStatus status,
                                                 std::optional<Examined> value) {
    if (status != yuzu::shared::BoundedCallStatus::Completed || !value) {
        Examined e;
        e.path = path;
        e.cause = "timeout";
        return e;
    }
    return std::move(*value);
}

} // namespace yuzu::ioc
