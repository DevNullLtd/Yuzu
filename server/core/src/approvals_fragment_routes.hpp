#pragma once

/// @file approvals_fragment_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the single-route Approvals
/// HTMX fragment (`GET /fragments/approvals`). Deliberately NOT part of
/// PR-9's `approval_routes.cpp` (the JSON Approval API) — that module's own
/// header comment covers only the 4 `/api/approvals*` JSON routes; this is
/// the legacy dashboard fragment, a distinct rendering path that calls
/// `ApprovalManager::query_checked()` directly and renders HTML rather than JSON.
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
/// Query params and degraded states (the Instructions tab and the Approvals page
/// share this prelude):
///   status=pending|approved|rejected|expired   filter; absent = every status for
///                       the tab, `pending` for `view=page`; present-but-empty =
///                       every status; anything else = a 200 `data-invalid` note.
///   view=page           the Approvals page's list (approvals_page_render.hpp)
///                       instead of the tab's table.
/// Every non-happy answer is a 200 note, never a 4xx/5xx body (htmx drops those and
/// the panel would sit on "Loading..."): a perm_fn 403 becomes a `data-denied`
/// note (the gate's own audit row is already written; its reason text never
/// reaches the body), a store read failure becomes a `data-degraded` note and is
/// NEVER rendered as "No approval requests.". Any other perm_fn status (401, 503)
/// passes through exactly as the gate wrote it.
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
class InstructionStore;
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

    /// Side-effect-free permission probe for RENDERING decisions only (never a gate): bound in
    /// server.cpp to `perm_fn` with a throwaway Response, so the denial's response body is
    /// discarded (the gate still writes one `auth.permission_required` audit row per probe
    /// for a caller without the grant). The fragment keeps gating on `perm_fn`; the probe
    /// only decides whether to RENDER a decision control. Unwired = cannot decide: no
    /// control is rendered (the server still refuses the POST).
    using ProbePermFn = std::function<bool(const httplib::Request&, const std::string&,
                                           const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    ProbePermFn probe_perm_fn;
    /// `ServerImpl::approval_manager_`. Null -> the fragment renders "Not
    /// available" without touching it. No `is_open()` check — matches the
    /// original inline code exactly (unlike `approval_routes.cpp`'s JSON
    /// siblings, which also check only nullness, not `is_open()`).
    ApprovalManager* approval_manager{nullptr};
    /// `ServerImpl::instruction_store_`, for the page view's instruction names only
    /// (a display lookup, never a gate). Null or not open -> ids are shown as names.
    InstructionStore* instruction_store{nullptr};
};

/// Register the Approvals HTMX fragment route against `sink`.
void register_approvals_fragment_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::approvals_fragment
