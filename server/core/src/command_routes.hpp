#pragma once

/// @file command_routes.hpp
/// POST /api/command - the generic instruction-dispatch route (#2557). Extracted
/// from server.cpp's inline registration onto the HttpRouteSink seam so its
/// authorization, targeting-shape, and audit-emission properties are testable
/// via the in-process TestRouteSink harness (#438: a real acceptor thread
/// crashes under TSan). This extraction also fixes 6 confirmed-live defects
/// found by review of the prior (unmerged) extraction attempt against
/// origin/dev - each documented at its fix site in command_routes.cpp.

#include "dispatch_caller.hpp"           // DispatchCaller
#include "dispatch_confined_arms.hpp"    // ConfinedDispatchSink, ContainmentGate

#include "http_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>

#include <expected>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {
class ManagementGroupStore;
class ResultSetStore;
class TagStore;
class CustomPropertiesStore;
class CommandCapabilityRegistry;
namespace detail {
class AgentRegistry;
class ClassifiedCommand;
struct DispatchDenial;
} // namespace detail
} // namespace yuzu::server

namespace yuzu::server::command {

/// Construction deps. Every closure is bound to `this` at registration in
/// server.cpp; none of these ever changes identity after start_web_server()
/// begins (verified - every backing member is set exactly once, before the
/// web server starts).
struct Deps {
    // -- Tier A: raw pointers/references, never reseated --
    yuzu::MetricsRegistry* metrics{nullptr};
    yuzu::server::detail::AgentRegistry* registry{nullptr};
    const yuzu::server::CommandCapabilityRegistry* capability_registry{nullptr};
    ManagementGroupStore* mgmt_group_store{nullptr};
    ResultSetStore* result_set_store{nullptr};
    const TagStore* tag_store{nullptr};
    const CustomPropertiesStore* custom_properties_store{nullptr};

    // -- Tier B: closures wrapping ServerImpl-private logic --
    using AuthFn = std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&, const std::string&, const std::string&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string&, const std::string&, const std::string&, const std::string&, const std::string&)>;
    using EmitEventFn = std::function<void(const std::string&, const httplib::Request&, const nlohmann::json&, const nlohmann::json&)>;
    using PublishFn = std::function<void(const std::string&, const std::string&)>;
    using AuditStoreConfiguredFn = std::function<bool()>;
    using DeriveDispatchCallerFn = std::function<yuzu::server::DispatchCaller(const auth::Session&)>;
    using BuildClassifiedCommandFn = std::function<std::expected<yuzu::server::detail::ClassifiedCommand, yuzu::server::detail::DispatchDenial>(
        const yuzu::server::DispatchCaller&, const std::string&, const std::string&, const std::string&,
        const std::unordered_map<std::string, std::string>&, const std::string&, int, int, const std::string&, const std::string&)>;
    using MakeContainmentGateFn = std::function<yuzu::server::ContainmentGate(const std::string&, const std::string&)>;
    using MakeConfinedDispatchSinkFn = std::function<yuzu::server::ConfinedDispatchSink(const yuzu::server::detail::ClassifiedCommand&)>;
    using DiscardSendTimeFn = std::function<bool(const std::string&)>;
    using RecordSendTimeFn = std::function<void(const std::string&)>;
    using TheadForPluginFn = std::function<std::string(const std::string&)>;
    using ForwardGatewayPendingFn = std::function<void()>;
    using AuditQuarantineFailClosedFn = std::function<void(std::string_view, const std::string&, const std::string&, const std::string&, std::size_t)>;
    using AuditQuarantineDeniedBatchFn = std::function<void(std::string_view, const std::string&, const std::string&, const std::string&, const std::vector<std::string>&)>;
    using AuditUnknownPluginFn = std::function<void(std::string_view, const std::string&, const std::string&, const std::string&, const std::string&, std::size_t)>;
    using AuditScopeResolutionFailedFn = std::function<void(const std::string&, const std::string&, const std::string&, const std::string&)>;
    using AuditScopeEvaluationAbortedFn = std::function<void(const std::string&, const std::string&, const std::string&, const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
    EmitEventFn emit_event_fn;
    PublishFn publish_fn;
    AuditStoreConfiguredFn audit_store_configured_fn;
    DeriveDispatchCallerFn derive_dispatch_caller_fn;
    BuildClassifiedCommandFn build_classified_command_fn;
    MakeContainmentGateFn make_containment_gate_fn;
    MakeConfinedDispatchSinkFn make_confined_dispatch_sink_fn;
    DiscardSendTimeFn discard_send_time_fn;
    RecordSendTimeFn record_send_time_fn;
    TheadForPluginFn thead_for_plugin_fn;
    ForwardGatewayPendingFn forward_gateway_pending_fn;
    AuditQuarantineFailClosedFn audit_quarantine_dispatch_fail_closed_fn;
    AuditQuarantineDeniedBatchFn audit_quarantine_dispatch_denied_batch_fn;
    AuditUnknownPluginFn audit_unknown_plugin_dispatch_fn;
    AuditScopeResolutionFailedFn audit_scope_resolution_failed_fn;
    AuditScopeEvaluationAbortedFn audit_scope_evaluation_aborted_fn;
};

/// Register POST /api/command against `sink`.
void register_command_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::command
