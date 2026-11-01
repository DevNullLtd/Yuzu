#pragma once

/// @file event_emit_hook.hpp
/// The REQUEST-FREE half of the best-effort event hook the v1 REST and MCP twins use to publish
/// the SAME events their legacy routes publish (#2146). No DIRECT `<httplib.h>` include: the
/// transport-free cores (`instruction_execute.hpp`, `execution_mutation.hpp`) take an
/// `EventEmitHook` and this header adds no dependency on the HTTP library. (It is not absent from
/// those cores' include graph: `instruction_execute.hpp` still reaches `<httplib.h>` transitively
/// through `agent_registry.hpp` -> `event_bus.hpp`, which predates this header.) The adapter that binds the legacy 4-argument emitter to one
/// request (`EmitEventFn`, `bind_event_emit`) needs `httplib::Request` and lives in
/// `event_emit.hpp`, which includes this file.
///
/// BEST EFFORT, AFTER THE EFFECT. A hook is called once the effect (and its outcome audit row) is
/// done. It must never block or fail the request: `emit_event_guarded` swallows anything a hook
/// throws, and the binder in `event_emit.hpp` catches, logs and counts a throw itself.

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <array>
#include <functional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// The platform-event emitter with the request already bound by the surface: what the
/// transport-free sequences (`apply_execution_mutation`, the instruction-execute core) take.
/// Empty = no event.
using EventEmitHook = std::function<void(std::string_view event_type, const nlohmann::json& attrs,
                                         const nlohmann::json& payload_data)>;

/// `yuzu_server_event_emit_failed_total{event_type}`: an emission that THREW. The `event_type`
/// label is a closed set (`kEmittedEvents`), pre-seeded at boot; any other name counts as
/// `other`. NOT named `event`: docs/observability-conventions.md routes SIEM filters on a label
/// called `event` (`event="security"`), and this counter must never match one.
inline constexpr char kEventEmitFailedMetric[] = "yuzu_server_event_emit_failed_total";
inline constexpr std::array<std::string_view, 6> kEmittedEvents{
    "execution.created", "execution.completed", "command.dispatched",
    "instruction.executed", "approval.created", "other"};

/// Logs and counts one emission that threw. Never throws: observability must not fail a request.
inline void report_event_emit_failure(yuzu::MetricsRegistry* metrics,
                                      std::string_view event) noexcept {
    try {
        spdlog::error("event emit '{}' threw; the request is unaffected",
                      ::yuzu::log_token(std::string(event)));
        if (metrics != nullptr) {
            std::string label = "other";
            for (const auto known : kEmittedEvents)
                if (known == event)
                    label = std::string(known);
            metrics->counter(kEventEmitFailedMetric, {{"event_type", label}}).increment();
        }
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

/// Calls `hook` if set, swallowing anything it throws (for hooks not made by `bind_event_emit`).
inline void emit_event_guarded(const EventEmitHook& hook, std::string_view event,
                               const nlohmann::json& attrs = nlohmann::json(),
                               const nlohmann::json& payload = nlohmann::json()) noexcept {
    if (!hook)
        return;
    try {
        hook(event, attrs, payload);
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

} // namespace yuzu::server
