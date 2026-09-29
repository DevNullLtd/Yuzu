#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include "authz_model.hpp"
#include "execution_event_bus.hpp"

namespace yuzu::server {

enum class ExecutionEventVerdict { kPass, kDrop, kSanitize };

/// Classify one execution event for a caller's fleet-read scope. Unknown or
/// malformed data-bearing events fail closed for confined callers.
[[nodiscard]] inline ExecutionEventVerdict
classify_execution_event_for_scope(const ExecutionEvent& ev, const authz::VisibleSet& scope) {
    if (!scope)
        return ExecutionEventVerdict::kPass;

    if (ev.event_type == "agent-transition") {
        const auto payload = nlohmann::json::parse(ev.data, nullptr, false);
        if (payload.is_discarded() || !payload.is_object())
            return ExecutionEventVerdict::kDrop;
        const auto it = payload.find("agent_id");
        if (it == payload.end() || !it->is_string())
            return ExecutionEventVerdict::kDrop;
        return authz::in_scope(scope, it->get_ref<const std::string&>())
                   ? ExecutionEventVerdict::kPass
                   : ExecutionEventVerdict::kDrop;
    }
    if (ev.event_type == "execution-progress")
        return ExecutionEventVerdict::kDrop;
    if (ev.event_type == "execution-completed")
        return ExecutionEventVerdict::kSanitize;
    if (ev.event_type == "replay-gap" || ev.event_type == "events-dropped" ||
        ev.event_type == "heartbeat")
        return ExecutionEventVerdict::kPass;
    return ExecutionEventVerdict::kDrop;
}

/// Preserve the event identity and the REAL terminal status while removing
/// execution-wide counts and per-agent detail from a confined caller's
/// completed event. Publishers (`ExecutionTracker::refresh_counts_once`,
/// `mark_cancelled`) stamp a string `status` field — `succeeded`/`completed`
/// or `cancelled` — that a confined subscriber must still see truthfully:
/// hard-coding "completed" here would tell an operator a cancelled or failed
/// execution succeeded, exactly the terminal signal the caller is watching
/// this stream for. Only when the field is absent or the payload itself is
/// malformed do we fall back to a fixed value, rather than fail closed and
/// drop the caller's only terminal signal outright.
[[nodiscard]] inline ExecutionEvent sanitize_execution_event_for_scope(const ExecutionEvent& ev) {
    ExecutionEvent sanitized = ev;
    std::string status = "completed";
    if (const auto payload = nlohmann::json::parse(ev.data, nullptr, false);
        !payload.is_discarded() && payload.is_object()) {
        if (const auto it = payload.find("status"); it != payload.end() && it->is_string())
            status = it->get_ref<const std::string&>();
    }
    sanitized.data = nlohmann::json{{"status", status}}.dump();
    return sanitized;
}

} // namespace yuzu::server
