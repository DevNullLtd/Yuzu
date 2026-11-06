#pragma once

/// @file event_emit.hpp
/// The httplib ADAPTER half of the best-effort event hook the v1 REST and MCP twins use to publish
/// the SAME events their legacy routes publish (#2146). ONE bus, ONE taxonomy: an event is
/// `ServerImpl::emit_event` -> `AuthRoutes::emit_event` -> the analytics event store, exactly as
/// `execution_routes.cpp` / `command_routes.cpp` / `workflow_routes.cpp` emit it. A twin names an
/// event type and its legacy attributes/payload; it never invents a per-route format, and it adds
/// NO bus consumer (the payloads below carry only what the legacy route already carried, so the
/// confinement rules in `execution_event_scope.hpp` are unaffected).
///
/// The request-free parts (`EventEmitHook`, `emit_event_guarded`, the failure counter and its
/// closed label set) are in `event_emit_hook.hpp`, so the transport-free cores never see
/// `<httplib.h>`. Only a REST/MCP adapter, which has a `httplib::Request` to bind, includes this.
///
/// BEST EFFORT, AFTER THE EFFECT. A hook is called once the effect (and its outcome audit row) is
/// done. It must never block or fail the request: the binder below catches everything, logs it and
/// counts it; the shared sequences that call a hook wrap it again, so a test hook that throws
/// cannot escape either.

#include "event_emit_hook.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// The emitter as the legacy route modules receive it (`ServerImpl::emit_event`'s 4-argument
/// shape, `execution_routes.hpp` and friends).
using EmitEventFn = std::function<void(const std::string& event_type, const httplib::Request& req,
                                       const nlohmann::json& attrs,
                                       const nlohmann::json& payload_data)>;

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
            report_event_emit_failure(metrics, event);
        }
    };
}

} // namespace yuzu::server
