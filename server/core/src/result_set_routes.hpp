#pragma once

/// @file result_set_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-5) — the 6-route Result Sets fragment API (scope walking,
/// capability §30, `docs/scope-walking-design.md`): the HTMX dashboard
/// sidebar + detail-pane fragments over the operator's owner-scoped result
/// sets (list/pin/unpin/delete/create), paired with the already-extracted
/// `/result-sets` page shell (`page_routes.cpp`, #2542 PR-2) and
/// `result_sets_ui.{hpp,cpp}`'s pure rendering functions. One owning store
/// (`ResultSetStore`), genuinely cohesive — matching `custom_properties_routes`'
/// single-subsystem grouping precedent rather than `dashboard_api_routes`'s
/// explicitly-heterogeneous one. Every handler body is copied verbatim from
/// server.cpp; the changes are the receiver (`web_server_->` -> `sink.`), the
/// member access (`result_set_store_.` -> `deps.store->`), the audit call
/// (`audit_log(...)` -> `deps.audit_fn(...)`, already hoisted in server.cpp
/// as `audit_fn`), the session gate (`require_auth(...)` -> `deps.auth_fn(...)`,
/// already hoisted as `auth_fn`), the metrics counter
/// (`metrics_.counter(...)` -> a null-checked `deps.metrics->counter(...)` —
/// see the Deps::metrics doc comment below), and the two LOCAL helper
/// closures `rs_get_owned` / `rs_detail_after`, which move verbatim into
/// `register_result_set_routes`'s body (they were server.cpp locals with no
/// `ServerImpl` dependency beyond the store, not `ServerImpl` methods, so
/// there is no second-caller risk in moving them).
///
/// NEW DEPS FIELD — `deny_service_scoped_fn`: the first of the four #2542
/// extractions to date whose routes call `AuthRoutes::deny_service_scoped_session`
/// (guardian-confinement-2298 PR3 §3e — every route reachable via `auth_fn`
/// alone, with no `perm_fn`/`scoped_perm_fn` gate at all, must deny a
/// service-scoped token explicitly, since the §3a default-deny flip never
/// runs for them). None of PR-2's page routes, PR-3's dashboard_api/nvd
/// routes, or PR-4's custom_properties routes needed this call, so no
/// existing hoisted server.cpp closure wraps it — this extraction adds
/// `deny_service_scoped_fn`, a NEW hoisted closure defined alongside
/// `auth_fn`/`perm_fn`/`scoped_perm_fn`/`audit_fn`, wrapping
/// `auth_routes_->deny_service_scoped_session(...)` with the same signature
/// shape as `auth_fn`/`audit_fn` (a bound closure over 6 explicit
/// arguments — the original call's optional 5th/6th positional args
/// (`target_type`, `target_id`) are always passed explicitly here, `""`
/// where the original call omitted them; the original's unused 7th
/// `permission` arg is not exposed at all, since no call site in this
/// module ever passes it).
///
/// DOUBLE SESSION RESOLUTION (preserved verbatim, not introduced by this
/// move): every one of the 6 handlers calls `deps.deny_service_scoped_fn(...)`
/// FIRST, then `deps.auth_fn(...)` (`require_auth`) SECOND. This is because
/// `AuthRoutes::deny_service_scoped_session` resolves its own session
/// internally (via its own `require_auth` call) to check
/// `token_scope_service`, discards it, and returns `true` (caller must
/// return) on either "no session" or "service-scoped" — so a genuinely
/// authenticated, non-service-scoped caller falls through to the handler's
/// own SEPARATE `deps.auth_fn(...)` call, which resolves the session again.
/// This is pre-existing server.cpp behaviour (auth_routes.cpp's
/// `deny_service_scoped_session` doc comment), copied as-is; it is not this
/// extraction's place to collapse it into one resolution.
///
/// FAIL-CLOSED OWNERSHIP READ (ADR-0036, preserved verbatim): the local
/// `rs_get_owned` closure folds a `ResultSetStore::get` runtime `DbError`
/// into the SAME `std::nullopt` outcome as a genuine not-found or
/// not-owned-by-this-principal row (`std::expected`'s `operator!` catches
/// the error case; the `!row->has_value()` check catches the not-found
/// case). A DB error on this authorization-relevant read must never look
/// like a silent success, so every caller of `rs_get_owned` treats all
/// three outcomes identically — the detail/pin/unpin/delete handlers all
/// render the "empty" detail-pane state, never a 200 with real data, on any
/// of the three.
///
/// THREE-WAY DEGRADE ASYMMETRY (preserved verbatim, not a defect introduced
/// by this move — flagged here so it is not later "discovered" as one):
///   - GET /fragments/result-sets/sidebar: a null `deps.store` renders a
///     LITERALLY EMPTY body (`res.set_content("", ...)`), status 200.
///   - GET .../detail and every POST mutation's "not found / not owned /
///     DbError" branch (via `rs_get_owned`): renders `render_result_set_
///     detail_empty()`'s markup (a non-empty "nothing selected" fragment),
///     status 200.
///   - POST pin/unpin/delete/create: a null `deps.store` is checked
///     BEFORE `rs_get_owned` is even called (`!session || !deps.store`, or
///     for create, the same combined check) and returns with NOTHING set on
///     `res` at all — no content, no content-type — which both production
///     httplib and `TestRouteSink` default to a plain 200 empty response.
/// Three distinct "degraded" response bodies for what is conceptually the
/// same failure mode, none of them a 503 JSON envelope (unlike
/// `custom_properties_routes`/the Tags API's pattern) — this module is HTML
/// fragments, not a JSON API, and the pre-existing code never unified the
/// three. Not this extraction's place to change.
///
/// PER-MUTATION AUDIT/TOAST ASYMMETRY (preserved verbatim):
///   - pin failure: audited (`"denied"` if the store error is `PinLimit`,
///     else `"failure"`) + an error toast (`HX-Trigger`) + re-renders the
///     STALE pre-attempt row (not re-fetched).
///   - unpin failure: audited (ALWAYS `"failure"` — no `PinLimit`-style
///     split; unpin has no analogous limit) + an error toast + re-renders
///     the stale pre-attempt row, same shape as pin.
///   - delete failure: NOT audited at all (no audit_fn call on this branch)
///     and NO toast — silently re-renders the still-existing detail pane
///     (a set failing to delete because it is still pinned is not treated
///     as an auditable/toast-worthy event by the pre-existing code).
///   - create failure: audited (ALWAYS `"denied"`, regardless of whether
///     the store error is `QuotaExceeded`/`TooManyMembers`/other) + an
///     error toast + re-renders the SIDEBAR (not a detail pane — no id
///     exists yet). `QuotaExceeded`/`TooManyMembers` additionally increment
///     `yuzu_result_set_quota_rejected` (guarded on `deps.metrics` being
///     non-null — see the Deps::metrics doc comment).
///   - pin/unpin/delete/create SUCCESS: all four audit `"success"` first, but
///     `HX-Trigger: resultSetsChanged` is NOT uniformly guaranteed after
///     that. Delete and create set it unconditionally. Pin/unpin delegate
///     to the shared `rs_detail_after` closure, which does a SECOND
///     `rs_get_owned` read post-mutation to build the fresh detail pane —
///     if that re-read fails (a transient ADR-0036 DbError, or a
///     concurrent delete racing the just-completed pin/unpin), it renders
///     `detail_empty()` and returns BEFORE the `HX-Trigger` line, so the
///     audit row says "success" but the sidebar never reloads. Pre-existing
///     (verbatim), not introduced by this move (governance Gate 2 finding).
///   - GET sidebar/detail: never audited (pure reads), matching every prior
///     extraction's read/write audit split.
///
/// Routes (6) — every route gates on `deps.deny_service_scoped_fn` (target
/// varies per-route below) THEN `deps.auth_fn`; none uses `perm_fn`/
/// `scoped_perm_fn` (this is an owner-scoped surface, not an RBAC-securable
/// one — every visibility/mutation check is "does the session's own
/// username own this row", not a permission grant):
///   GET  /fragments/result-sets/sidebar                (target_type="ResultSet", no target_id)
///   GET  /fragments/result-sets/(rs_[0-9a-f]+)/detail  (target_type="ResultSet", target_id=id)
///   POST /fragments/result-sets/(rs_[0-9a-f]+)/pin     (target_type="ResultSet", target_id=id)
///   POST /fragments/result-sets/(rs_[0-9a-f]+)/unpin   (target_type="ResultSet", target_id=id)
///   POST /fragments/result-sets/(rs_[0-9a-f]+)/delete  (target_type="ResultSet", target_id=id)
///   POST /fragments/result-sets/create                 (target_type="ResultSet", no target_id)

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class ResultSetStore;
} // namespace yuzu::server

namespace yuzu::server::result_set {

/// Construction deps for `register_result_set_routes`. Every closure/pointer
/// is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Wraps `AuthRoutes::deny_service_scoped_session` — see this file's
    /// header comment ("NEW DEPS FIELD") for why this is a new closure
    /// rather than a reused one, and ("DOUBLE SESSION RESOLUTION") for why
    /// every handler also separately calls `auth_fn` right after this
    /// returns `false`. `target_id` is passed `""` at the two call sites
    /// (sidebar, create) that have no result-set id yet — matching the
    /// original inline call, which omitted the (defaulted-empty) argument
    /// entirely at those two sites.
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& action, const std::string& message,
                           const std::string& target_type, const std::string& target_id)>;
    /// Bool-returning audit contract, same shape as
    /// `custom_properties::Deps::AuditFn` — server.cpp's hoisted `audit_fn`
    /// closure. This module's callers do NOT act on a `false` return
    /// (matches the original inline code's bare `audit_log(...)` calls,
    /// whose `[[nodiscard]]` return value was likewise discarded without a
    /// `(void)` cast — preserved, not hardened, by this move).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    AuthFn auth_fn;
    DenyServiceScopedFn deny_service_scoped_fn;
    AuditFn audit_fn;
    /// `ServerImpl::result_set_store_`. Null -> every route degrades per
    /// this file's "THREE-WAY DEGRADE ASYMMETRY" doc comment above (there is
    /// no `is_open()` check anywhere in this module — matches the original
    /// inline code, which never called it either; unlike
    /// `custom_properties_store_`/`CustomPropertiesStore`, whose routes DO
    /// check `is_open()`).
    ResultSetStore* store{nullptr};
    /// `&ServerImpl::metrics_`. UNLIKE the original inline code (where
    /// `metrics_` is a non-pointer `ServerImpl` member, always valid), this
    /// field is a nullable pointer — the create route's quota-rejection
    /// counter increment is therefore guarded with `if (deps.metrics)`, a
    /// defensive addition this extraction makes so a test harness may
    /// legitimately leave it unset. Production always binds `&metrics_`
    /// (non-null), so production behaviour is byte-identical to the
    /// pre-extraction code.
    yuzu::MetricsRegistry* metrics{nullptr};
};

/// Register all 6 Result Sets fragment routes against `sink`.
void register_result_set_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::result_set
