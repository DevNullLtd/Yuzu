#pragma once

/// @file diagnostics_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the 5-route legacy
/// agent-diagnostic-tool API: Chargen (start/stop/status) and Procfetch
/// (fetch/status). Bundled together (rather than split into two
/// one-route-each modules) because both are near-identical thin wrappers
/// over the same `forward_legacy_command` dispatch helper with no
/// meaningful difference in shape. Every handler body is copied verbatim
/// from server.cpp; the changes are the receiver (`web_server_->` ->
/// `sink.`), the gate closure (`require_permission` -> `deps.perm_fn`), the
/// dispatch call (`forward_legacy_command(...)` ->
/// `deps.forward_legacy_command_fn(...)`), and the member access
/// (`registry_.has_any()` -> `deps.registry->has_any()`).
///
/// `forward_legacy_command` ITSELF stays a private `ServerImpl` member in
/// server.cpp — it is a large, multi-dependency dispatch helper
/// (`require_auth`, `derive_dispatch_caller`, `build_classified_command`,
/// `make_containment_gate`, three audit helpers, `agent_service_.
/// record_send_time`) shared with no other route in this bundle, and moving
/// its BODY here would either duplicate that whole dependency surface in
/// `Deps` (defeating the point of a small bundle module) or require
/// threading every one of those closures through just to answer 3 of this
/// module's 5 routes. Matches the `command_routes.cpp` precedent of
/// wrapping a `ServerImpl`-private dispatch helper behind a single closure
/// (there, several finer-grained closures; here, one, since the helper's
/// call sites pass only 3 literal arguments and never touch the response
/// shape directly).
///
/// Routes (5) — gate in parens:
///   POST /api/chargen/start      (perm_fn Execution:Execute)
///   POST /api/chargen/stop       (perm_fn Execution:Execute)
///   POST /api/procfetch/fetch    (perm_fn Execution:Execute)
///   GET  /api/chargen/status     (perm_fn Infrastructure:Read)
///   GET  /api/procfetch/status   (perm_fn Infrastructure:Read)
///
/// AUDIT: preserved verbatim — the 3 POST routes' audit trail lives entirely
/// inside `forward_legacy_command` (a denial audits `command.dispatch`
/// "denied"; success is not separately audited by this route, matching the
/// original inline code). Both GET status routes are pure reads, never
/// audited.

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
namespace detail {
class AgentRegistry;
} // namespace detail
} // namespace yuzu::server

namespace yuzu::server::diagnostics {

/// Construction deps for `register_diagnostics_routes`. Every closure/
/// pointer is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Wraps `ServerImpl::forward_legacy_command` — see this file's header
    /// comment for why the helper itself stays in server.cpp rather than
    /// moving into this module.
    using ForwardLegacyCommandFn = std::function<void(
        const httplib::Request&, const std::string& plugin, const std::string& action,
        httplib::Response&)>;

    PermFn perm_fn;
    ForwardLegacyCommandFn forward_legacy_command_fn;
    /// `ServerImpl::registry_`. Backs the two GET status routes'
    /// `agent_connected` field only — `forward_legacy_command_fn` does its
    /// own registry check internally.
    yuzu::server::detail::AgentRegistry* registry{nullptr};
};

/// Register all 5 Chargen + Procfetch diagnostic routes against `sink`.
void register_diagnostics_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::diagnostics
