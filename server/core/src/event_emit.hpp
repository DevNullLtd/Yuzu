#pragma once

/// @file event_emit.hpp
/// The request-free, best-effort event hook the v1 REST and MCP twins use to publish the SAME
/// events their legacy routes publish (#2146). ONE bus, ONE taxonomy: an event is
/// `ServerImpl::emit_event` -> `AuthRoutes::emit_event` -> the analytics event store, exactly as
/// `execution_routes.cpp` / `command_routes.cpp` / `workflow_routes.cpp` emit it. A twin names an
/// event type and its legacy attributes/payload; it never invents a per-route format, and it adds
/// NO bus consumer (the payloads below carry only what the legacy route already carried, so the
/// confinement rules in `execution_event_scope.hpp` are unaffected).
///
/// BEST EFFORT, AFTER THE EFFECT. A hook is called once the effect (and its outcome audit row) is
/// done. It must never block or fail the request: the binder below catches everything, logs it and
/// counts it; the shared sequences that call a hook wrap it again, so a test hook that throws
/// cannot escape either.

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <array>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// The emitter as the legacy route modules receive it (`ServerImpl::emit_event`'s 4-argument
/// shape, `execution_routes.hpp` and friends).
using EmitEventFn = std::function<void(const std::string& event_type, const httplib::Request& req,
                                       const nlohmann::json& attrs,
                                       const nlohmann::json& payload_data)>;

/// The same emitter with the request already bound by the surface: what the transport-free
/// sequences (`apply_execution_mutation`, the instruction-execute core) take. Empty = no event.
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

/// Binds `fn` to one request. An unwired `fn` yields an empty hook (no event, no error). The hook
/// borrows `fn` and `req` and is for use inside that one handler invocation only.
///
/// Empty attributes/payload are JSON null (`nlohmann::json()`), exactly what the legacy routes'
/// `{}` arguments produce, so a twin's row is byte-identical to its legacy sibling's.
[[nodiscard]] inline EventEmitHook bind_event_emit(const EmitEventFn& fn,
                                                   const httplib::Request& req,
                                                   yuzu::MetricsRegistry* metrics) {
    if (!fn)
        return {};
    return [&fn, &req, metrics](std::string_view event, const nlohmann::json& attrs,
                                const nlohmann::json& payload) noexcept {
        try {
            fn(std::string(event), req, attrs, payload);
        } catch (...) {
            // Never an escape: the effect has already happened and the caller is answered.
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
    };
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
