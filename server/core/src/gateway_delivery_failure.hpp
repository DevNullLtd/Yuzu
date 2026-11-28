#pragma once

// gateway_delivery_failure.hpp -- #2673: recognise a terminal FAILURE frame that the SERVER or
// the GATEWAY made up because a command could not be delivered, as opposed to a device's answer.
// Pure: no I/O.
//
// The two sources: `build_gateway_forward_terminal_failure` (gateway_mgmt_stub_pool.hpp), whose
// error codes are the closed lists below, and the gateway's own `not_connected` /
// `agent_disconnected` frame (`yuzu_gw_mgmt_service.erl`). Both carry exit code -1.
//
// Two outcomes. `not_delivered`: the command certainly never reached the device. `undetermined`
// (shown as `unknown`): it may have, for example a forward that ran past its time limit or an
// agent that disconnected while the answer was awaited.
//
// Asked ONLY on the gateway ingest path. A direct agent frame is always the device's answer; an
// agent behind a gateway that copied this shape would only relabel its own failure, and its
// later answer would replace the label.

#include "agent.pb.h"

#include <algorithm>
#include <array>
#include <string_view>

namespace yuzu::server {

inline constexpr std::array<std::string_view, 3> kGatewayNotDeliveredCodes{
    "gateway_forward_spawn_failed", "gateway_unauthenticated", "gateway_unknown_cluster"};
inline constexpr std::array<std::string_view, 3> kGatewayUndeterminedCodes{
    "gateway_agent_mismatch", "gateway_forward_failed", "gateway_unavailable"};

/// The stored outcome of a made-up failure frame: "not_delivered", "undetermined", or empty
/// when the frame is a device's answer.
[[nodiscard]] inline std::string_view
gateway_delivery_outcome(const ::yuzu::agent::v1::CommandResponse& resp) {
    if (resp.status() != ::yuzu::agent::v1::CommandResponse::FAILURE || resp.exit_code() != -1)
        return {};
    if (resp.output() == "not_connected")
        return "not_delivered";
    if (resp.output() == "agent_disconnected")
        return "undetermined";
    if (!resp.has_error())
        return {};
    const std::string_view code{resp.error().code()};
    if (std::ranges::find(kGatewayNotDeliveredCodes, code) != kGatewayNotDeliveredCodes.end())
        return "not_delivered";
    if (std::ranges::find(kGatewayUndeterminedCodes, code) != kGatewayUndeterminedCodes.end())
        return "undetermined";
    return {};
}

} // namespace yuzu::server
