#pragma once

/// @file approvals_fragment_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the single-route Approvals
/// HTMX fragment (`GET /fragments/approvals`). Deliberately NOT part of
/// PR-9's `approval_routes.cpp` (the JSON Approval API) — that module's own
/// header comment covers only the 4 `/api/approvals*` JSON routes; this is
/// the legacy dashboard fragment, a distinct rendering path that calls
/// `ApprovalManager::query()` directly and renders HTML rather than JSON.
///
/// Every handler body is copied verbatim from server.cpp; the changes are
/// the receiver (`web_server_->` -> `sink.`), the gate closures
/// (`require_auth`/`require_permission` -> `deps.auth_fn`/`deps.perm_fn`),
/// and the member access (`approval_manager_.` -> `deps.approval_manager->`).
///
/// Route (1) — gate in parens:
///   GET /fragments/approvals   (auth_fn, THEN perm_fn Approval:Read —
///                                mirrors the REST sibling GET /api/approvals,
///                                #3040: this fragment renders the full
///                                approvals population — submitted_by,
///                                status, scope_expression — so it is gated
///                                on Approval:Read, not a bare `auth_fn`
///                                alone. Approvals are workflow rows, not
///                                per-agent fleet data, so a plain
///                                `perm_fn` is correct here, not
///                                `authorize_list_read`/`scoped_perm_fn`.)
///
/// AUDIT: preserved verbatim — this route is a pure read, never audited.
///
/// STORE-UNAVAILABLE (preserved verbatim): a null `deps.approval_manager`
/// degrades to the same "Not available" HTML the equivalent null-check
/// produces on `approval_routes.cpp`'s JSON siblings (there, a 503 JSON
/// envelope instead — the two routes diverge in RESPONSE SHAPE, not in
/// which condition triggers the degrade, matching the original inline
/// code's own fragment-vs-JSON convention, same as
/// `instruction_fragment_routes.cpp`'s analogous split from
/// `instruction_routes.cpp`).

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class ApprovalManager;
} // namespace yuzu::server

namespace yuzu::server::approvals_fragment {

/// Construction deps for `register_approvals_fragment_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    /// `ServerImpl::approval_manager_`. Null -> the fragment renders "Not
    /// available" without touching it. No `is_open()` check — matches the
    /// original inline code exactly (unlike `approval_routes.cpp`'s JSON
    /// siblings, which also check only nullness, not `is_open()`).
    ApprovalManager* approval_manager{nullptr};
};

/// Register the Approvals HTMX fragment route against `sink`.
void register_approvals_fragment_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::approvals_fragment
