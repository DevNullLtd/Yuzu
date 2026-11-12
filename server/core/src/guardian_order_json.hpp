#pragma once

/// @file guardian_order_json.hpp
/// The one JSON rendering of a `GuardianAgentOrder` (the `ordering` object of the per-device
/// all-guards read). REST (`GET /api/v1/guaranteed-state/agents/{agent_id}/rules`) and MCP
/// (`get_guardian_device_guards`) both call this, so the two surfaces cannot drift on a key, a
/// null or the `currently_unordered` derivation. Pure: no store, no I/O.

#include "guardian_types.hpp"

#include <format>
#include <string>

namespace yuzu::server {

namespace detail {

/// `null` for an unset column, the integer otherwise. The values are database-clock nanoseconds
/// and agent-asserted epochs, so they can exceed 2^53: a client that parses JSON numbers as IEEE
/// doubles must read them as 64-bit integers.
[[nodiscard]] inline std::string order_json_int(const std::optional<std::int64_t>& v) {
    return v ? std::format("{}", *v) : std::string("null");
}

} // namespace detail

/// `{"epoch":..,"emit_seq_hwm":..,"epoch_recv_ns":..,"retired_epoch":..,"unpaired_recv_ns":..,
/// "currently_unordered":..,"unpaired_events":..,"unpaired_held":..,"pair_regressions":..,
/// "pair_stragglers":..,"pair_recoveries":..,"pair_duplicates":..,"retired_events":..}`. Every key is
/// always present; an unset nullable column is `null`.
[[nodiscard]] inline std::string render_guardian_agent_order_json(const GuardianAgentOrder& o) {
    return std::format(
        "{{\"epoch\":{},\"emit_seq_hwm\":{},\"epoch_recv_ns\":{},\"retired_epoch\":{},"
        "\"unpaired_recv_ns\":{},\"currently_unordered\":{},\"unpaired_events\":{},"
        "\"unpaired_held\":{},\"pair_regressions\":{},\"pair_stragglers\":{},"
        "\"pair_recoveries\":{},\"pair_duplicates\":{},\"retired_events\":{}}}",
        detail::order_json_int(o.epoch), detail::order_json_int(o.emit_seq_hwm),
        detail::order_json_int(o.epoch_recv_ns), detail::order_json_int(o.retired_epoch),
        detail::order_json_int(o.unpaired_recv_ns), o.currently_unordered() ? "true" : "false",
        o.unpaired_events, o.unpaired_held, o.pair_regressions, o.pair_stragglers,
        o.pair_recoveries, o.pair_duplicates, o.retired_events);
}

} // namespace yuzu::server
