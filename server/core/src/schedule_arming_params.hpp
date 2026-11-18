#pragma once

/// @file schedule_arming_params.hpp
/// `decode_arming_parameters`: the stored-parameters decoder the schedule and outbox arming checks
/// share (sg10). Its own header, not `schedule_arming_check.hpp`, so the `mcp_jsonrpc.hpp` it needs
/// (its `mcp::detail` namespace collides with `using namespace` in tests) stays out of the
/// arming decision header.

#include "command_capability.hpp" // parameters_well_formed
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <unordered_map>

namespace yuzu::server {

/// Decode a stored dispatch-parameters JSON text (a schedule's `parameter_values`, an outbox
/// row's `parameters`) to the flat string map the arming check judges, EXACTLY as the outbox
/// delivery decodes it for the send (a non-string value is its `dump()`, so a `null`, a list or
/// an object counts as a supplied, non-empty value). Empty text is an empty map. Returns
/// `nullopt` for text that is over the depth guard, not valid JSON, not an object, or holding a malformed parameter key or value (`parameters_well_formed`): a caller
/// that is deciding AUTHORITY treats that as a denial (fail closed), never as "no parameters".
[[nodiscard]] inline std::optional<std::unordered_map<std::string, std::string>>
decode_arming_parameters(const std::string& json_text) {
    std::unordered_map<std::string, std::string> out;
    if (json_text.empty())
        return out;
    if (mcp::json_exceeds_depth(json_text, mcp::kMcpMaxJsonDepth))
        return std::nullopt;
    try {
        const auto obj = nlohmann::json::parse(json_text);
        if (!obj.is_object())
            return std::nullopt;
        for (auto it = obj.begin(); it != obj.end(); ++it)
            out[it.key()] = it.value().is_string() ? it.value().get<std::string>()
                                                   : it.value().dump();
        // A key the agent would truncate (NUL / control byte / invalid UTF-8) is a denial.
        if (!parameters_well_formed(out))
            return std::nullopt;
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
    return out;
}

} // namespace yuzu::server
