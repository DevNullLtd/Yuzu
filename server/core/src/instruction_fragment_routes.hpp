#pragma once

/// @file instruction_fragment_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the 2-route Instructions HTMX
/// fragment pair: the definitions-list fragment and the server-side YAML
/// syntax-highlight + validate preview. Deliberately NOT part of PR-7's
/// `instruction_routes.cpp` (the JSON Instruction Definitions + Instruction
/// Sets API) — `instruction_routes.hpp`'s own header comment named both of
/// these routes as staying inline "outside #2542's route list for this
/// extraction" at PR-7 time; PR-12 is that deferred extraction, now that the
/// campaign has reached its bundle-PR phase for the remaining scattered
/// routes with no single owning store large enough to justify their own PR.
///
/// Every handler body is copied verbatim from server.cpp; the changes are
/// the receiver (`web_server_->` -> `sink.`), the gate closures
/// (`auth_routes_->deny_service_scoped_session`/`require_auth`/
/// `require_permission` -> `deps.deny_service_scoped_fn`/`deps.auth_fn`/
/// `deps.perm_fn`), and the member access (`instruction_store_.` ->
/// `deps.store->`).
///
/// `highlight_yaml`/`highlight_yaml_value`/`highlight_yaml_kv` MOVE (not
/// duplicate) into this module's .cpp as file-local (anonymous-namespace)
/// functions — they were `static ServerImpl` members with exactly ONE
/// external call site (`POST /fragments/instructions/yaml-preview`, this
/// module's own route), so unlike `validate_yaml_source` (promoted to a
/// free function in `instruction_store.hpp` at PR-7 time because it had
/// call sites straddling BOTH `instruction_routes.cpp` and this
/// still-inline route), these three have no second caller to keep in sync
/// with and no reason to live in a shared header. PR-7's own header comment
/// asserted these were "already shared" with `instruction_routes.cpp` — on
/// inspection at PR-12 time that was not the case: `instruction_routes.cpp`
/// calls `validate_yaml_source` only, never `highlight_yaml`. A SEPARATE,
/// independent copy already exists in `settings_routes.cpp` (anonymous
/// namespace, `[[maybe_unused]]`, single-argument `highlight_yaml_value`)
/// for the unrelated Settings YAML preview feature — that copy is a
/// genuinely different function (no `key`-based semantic-class dispatch)
/// and is left untouched; this move does not attempt to unify the two.
///
/// `validate_yaml_source` is CALLED, not moved — it stays in
/// `instruction_store.hpp`/`.cpp` (the PR-7 promotion), reused here exactly
/// as `instruction_routes.cpp`'s own two YAML endpoints reuse it. `html_escape`
/// is likewise called from its existing free-function home in
/// `web_utils.hpp`, unchanged.
///
/// Routes (2) — gate in parens:
///   GET  /fragments/instructions               (deny_service_scoped_fn
///                                                 "instructions.fragment.access_denied",
///                                                 THEN auth_fn — the role
///                                                 check inside the handler
///                                                 body gates only the
///                                                 New/Edit buttons, not the
///                                                 list itself)
///   POST /fragments/instructions/yaml-preview   (perm_fn
///                                                 InstructionDefinition:Read)
///
/// AUDIT: preserved verbatim — neither route is audited (both are read-only
/// rendering; the definitions-list fragment's mutating siblings, Delete via
/// `hx-delete`, are the extracted `instruction_routes.cpp` JSON API's own
/// audited routes, not this module's).
///
/// STORE-UNAVAILABLE (preserved verbatim): a null/closed
/// `deps.store`, or a genuine `query_definitions()` DB error, both degrade
/// the list fragment to the same "Not available" HTML — not distinguished,
/// matching the original inline code exactly.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class InstructionStore;
} // namespace yuzu::server

namespace yuzu::server::instruction_fragment {

/// Construction deps for `register_instruction_fragment_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Shared 6-arg shape with `result_set_routes.hpp`/`legacy_events_routes.hpp`'s
    /// identical closure — wraps `AuthRoutes::deny_service_scoped_session`,
    /// called here with an explicit `""` for `target_type`/`target_id`.
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&, const std::string& action,
                           const std::string& message, const std::string& target_type,
                           const std::string& target_id)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    DenyServiceScopedFn deny_service_scoped_fn;
    /// `ServerImpl::instruction_store_`. Null, or a genuine DB error on
    /// `query_definitions()`, both degrade the list fragment to "Not
    /// available" — see this file's header "STORE-UNAVAILABLE" note. The
    /// yaml-preview route never touches this store at all.
    InstructionStore* store{nullptr};
};

/// Register both Instructions HTMX fragment routes against `sink`.
void register_instruction_fragment_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::instruction_fragment
