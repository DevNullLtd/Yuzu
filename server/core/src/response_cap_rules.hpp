#pragma once

/// @file response_cap_rules.hpp
/// Pure admit decision for the per-(instruction_id, agent_id) response row cap (#561).
/// No I/O: ResponseStore::store() gathers the two facts from PostgreSQL and asks here.
///
/// The bound, exactly:
///   - total rows per pair are capped at `cap`; below the cap every frame (RUNNING or
///     terminal) is admitted;
///   - at the cap, ONE overflow terminal row is admitted, and only while no terminal row
///     exists for the pair (so a capped command still shows its outcome; bound = cap + 1);
///   - `finalize_terminal_status` converts retained RUNNING rows in place (no new row), after
///     which a further terminal insert at the cap is refused as a replay;
///   - concurrent writers for one pair (direct stream + gateway forward) are not serialised
///     and can overshoot by the number of concurrent writers.
///
/// "Terminal" is `status != 0` everywhere (CommandResponse.Status is an open proto3 enum, so a
/// value outside 0..4 is terminal too): the caller must compute `is_terminal` and
/// `terminal_exists` with that one definition, or such a frame is admitted past the cap forever.
///
/// `rows_at_or_below_cap` is the LIMIT-bounded count (never a full count): it is only ever
/// compared with `cap`.

#include <cstdint>

namespace yuzu::server {

[[nodiscard]] constexpr bool per_agent_cap_admits(std::int64_t rows_at_or_below_cap, int cap,
                                                  bool is_terminal,
                                                  bool terminal_exists) noexcept {
    if (rows_at_or_below_cap < cap)
        return true;
    return is_terminal && !terminal_exists;
}

} // namespace yuzu::server
