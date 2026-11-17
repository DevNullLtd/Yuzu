#pragma once

/// @file session_log_token.hpp
/// WP06 F55: the agent's session id is a control-plane credential (it authenticates the agent's
/// Heartbeat / ReportInventory streams), so it must never be written to a log. The agent's own
/// log file is readable through `agent_logging.get_log` and, before the path guard, through
/// `filesystem.read`. This returns a short non-reversible token for correlation instead:
/// the first 8 hex of SHA-256(session_id). A gateway-issued id keeps its non-secret
/// `gw-session` scheme marker as a prefix (`gw-session~<fp>`) so existing log readers that
/// classify the registration path by that marker keep working.

#include "sha256.hpp"

#include <string>
#include <string_view>

namespace yuzu::shared {

[[nodiscard]] inline std::string session_log_token(std::string_view session_id) {
    if (session_id.empty())
        return "none";
    std::string fp = sha256_hex(session_id).substr(0, 8);
    constexpr std::string_view kGw = "gw-session";
    if (session_id.starts_with(kGw))
        return std::string(kGw) + "~" + fp;
    return fp;
}

} // namespace yuzu::shared
