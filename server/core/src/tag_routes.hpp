#pragma once

/// @file tag_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-11) — the 4-route Tags API: free-form + structured
/// per-agent device tags (`docs/asset-tagging-guide.md`) over `TagStore`.
/// Every handler body is copied verbatim from server.cpp; the changes are
/// the receiver (`web_server_->` -> `sink.`), the gate closures
/// (`require_permission`/`require_auth`/`require_scoped_permission` ->
/// `deps.perm_fn`/`deps.auth_fn`/`deps.scoped_perm_fn`), the member access
/// (`tag_store_.` -> `deps.store->`), the audit call (`audit_log(...)` ->
/// `deps.audit_fn(...)`), and the two `ServerImpl`-member side-effect calls
/// (`ensure_service_management_group(...)` ->
/// `deps.ensure_service_management_group_fn(...)`,
/// `push_asset_tags_to_agent(...)` -> `deps.push_asset_tags_to_agent_fn(...)`).
///
/// NEW DEPS FIELD — `deny_service_scoped_tag_mutation_fn`. Wraps
/// `AuthRoutes::deny_service_scoped_service_tag_mutation` (#3289) — a
/// service-scoped token must not rewrite/delete its own cohort's `service`
/// tag and move an agent out of (or a different agent into) its own
/// confinement (the tag-write TOCTOU `require_scoped_permission`'s service
/// branch has on its own — see `AuthRoutes`'s doc comment on the wrapped
/// method for the full rationale). Called BEFORE `deps.scoped_perm_fn`,
/// right after the key is parsed/normalized, on both POST /set and
/// POST /delete — value-blind by design, never a membership oracle.
///
/// `kCategoryKeys` / `kTagDbErrorPrefix` (tag_store.hpp) and
/// `TagStore::validate_key` / `extract_json_string` (json_extract.hpp) are
/// used directly — none of the 4 handlers' use of them touches `ServerImpl`
/// state, so no `Deps` closure wraps them.
///
/// Routes (4) — gate in parens, all backed by `deps.store`
/// (`TagStore`; GET checks `!store || !store->is_open()`. The 3 POST
/// routes check ONLY `!store`, never `is_open()` — matches the
/// pre-extraction inline code's per-route asymmetry exactly):
///   GET  /api/tags         (perm_fn Tag:Read)
///   POST /api/tags/set     (auth_fn, then deny_service_scoped_tag_mutation_fn,
///                            then scoped_perm_fn Tag:Write agent_id)
///   POST /api/tags/delete  (auth_fn, then deny_service_scoped_tag_mutation_fn,
///                            then scoped_perm_fn Tag:Delete agent_id)
///   POST /api/tags/query   (perm_fn Tag:Read)
///
/// #3289/K-04/CDX-R4-08: /set and /delete gate on PER-TARGET
/// `require_scoped_permission`, never a bare global `require_permission` —
/// the old global `Tag:Write` gate admitted a service-scoped token with no
/// target check, letting it rewrite the `service` tag on an out-of-scope
/// agent and escape its own dispatch confinement. GET and /query stay
/// global `Tag:Read` (a caller enumerating/querying tags fleet-wide, not
/// mutating a specific agent's row) — matches server.cpp's original code
/// exactly.
///
/// AUDIT ASYMMETRY (preserved verbatim, not a defect introduced by this
/// move): GET and POST /query are UNAUDITED (pure reads). POST /set audits
/// a store-level write failure (`"tag.set"`/`"failure"`, distinguishing a
/// `kTagDbErrorPrefix`-prefixed DB error -> 503 from a caller/validation
/// error -> 400) and a genuine success (`"tag.set"`/`"success"`); its own
/// early body-validation 400s (`agent_id`/`key` required, invalid key) are
/// unaudited. POST /delete audits a store-level degrade
/// (`"tag.delete"`/`"failure"`) and every resolved outcome past that point
/// (`"tag.delete"`/`"success"` or `"not_found"`, matching whether a row was
/// actually deleted); its own early body-validation 400 is unaudited. This
/// is the pre-existing server.cpp behaviour, copied as-is; it is not this
/// extraction's place to change it.
///
/// `deps.audit_fn` (a `std::function`) has no default arguments, unlike the
/// `ServerImpl::audit_log` member it replaces (`detail = {}`) — matching
/// every other #2542 module's convention. POST /delete's two original
/// `audit_log` calls were 5-arg (relying on that default); this move makes
/// both 6-arg with an explicit `""` for `detail`, same observable behaviour.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class TagStore;
} // namespace yuzu::server

namespace yuzu::server::tag {

/// Construction deps for `register_tag_routes`. Every closure/pointer is
/// bound once at start_web_server() time in server.cpp and never reseated.
struct Deps {
    using AuthFn = std::function<std::optional<auth::Session>(const httplib::Request&,
                                                               httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Per-target authorization gate (wraps `require_scoped_permission`) —
    /// same shape as `custom_properties::Deps::ScopedPermFn`.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    /// Wraps `AuthRoutes::deny_service_scoped_service_tag_mutation` — see
    /// this file's header comment.
    using DenyServiceScopedTagMutationFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& action, const std::string& agent_id,
                           const std::string& key)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Wraps `ServerImpl::ensure_service_management_group`.
    using EnsureServiceManagementGroupFn = std::function<void(const std::string& service_value)>;
    /// Wraps `ServerImpl::push_asset_tags_to_agent`.
    using PushAssetTagsToAgentFn = std::function<void(const std::string& agent_id)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    ScopedPermFn scoped_perm_fn;
    DenyServiceScopedTagMutationFn deny_service_scoped_tag_mutation_fn;
    AuditFn audit_fn;
    EnsureServiceManagementGroupFn ensure_service_management_group_fn;
    PushAssetTagsToAgentFn push_asset_tags_to_agent_fn;
    /// `ServerImpl::tag_store_`. Null -> every route answers 503 without
    /// touching it; GET additionally checks `is_open()` (see this file's
    /// header comment for the per-route asymmetry).
    TagStore* store{nullptr};
};

/// Register all 4 Tags API routes against `sink`.
void register_tag_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::tag
