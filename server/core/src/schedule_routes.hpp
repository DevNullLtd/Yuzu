#pragma once

/// @file schedule_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-8) — the 4-route Schedules API: operator-authored
/// recurring `InstructionSchedule` rows (once/daily/weekly/monthly +
/// interval_minutes), fired unattended by `ScheduleRunner::tick()` with NO
/// per-fire operator session in the loop — see the H-01 note below. One
/// owning store (`ScheduleEngine`), genuinely cohesive — matching
/// `custom_properties_routes`'/`result_set_routes`' single-subsystem
/// grouping precedent rather than `dashboard_api_routes`'s explicitly-
/// heterogeneous one. Every handler body is copied verbatim from
/// server.cpp; the changes are the receiver (`web_server_->` -> `sink.`),
/// the gate closure (`require_permission` -> `deps.perm_fn`), the post-gate
/// session lookup (`auth_routes_->resolve_session` ->
/// `deps.resolve_session_fn` — see below), the audit call
/// (`audit_log(...)` -> `deps.audit_fn(...)`), and the member access
/// (`schedule_engine_.` -> `deps.schedule_engine->`). `Deps::AuditFn` (like
/// every other #2542 module's) takes all 6 positional arguments with no
/// defaults — the DELETE and POST-enable routes' original `audit_log` calls
/// were 5-arg (relying on `AuthRoutes::audit_log`'s defaulted `detail = {}`);
/// this move makes both 6-arg with an explicit `""` for `detail`, same
/// observable behaviour, no default to lean on at the closure boundary (the
/// same class of fix — a defaulted method-call arg becoming mandatory at
/// the closure boundary — appears in `result_set_routes.hpp` for
/// `DenyServiceScopedFn`'s `target_id`, not this file's `AuditFn` `detail`).
///
/// CREATE-ONLY (PR1.5a, preserved from the pre-#2542 file this extraction
/// folds in): this module's POST `/api/schedules` handler is the only
/// place a schedule's `parameters` (`schedule_params_parsers.hpp`) are ever
/// written. They are immutable after creation — there is no update route,
/// and none should be added here without a deliberate design pass
/// (`parameters` feed p8's plan hash, so an in-place mutation path needs
/// its own re-validation and audit story). Changing a schedule's
/// parameters today means delete-and-recreate.
///
/// PRE-EXISTING PARTIAL EXTRACTION FOLDED IN: `handle_create_schedule` and
/// `parse_schedule_enabled` used to live in this same file as a narrower,
/// interim extraction (PR #1806, H-01) — the create-route's whole body, and
/// the enable-route's body-parsing helper only, each still invoked from an
/// inline server.cpp lambda (`web_server_->Post(...)` / `web_server_->
/// Post(.../enable, ...)`). This PR-8 pass folds `handle_create_schedule`'s
/// logic directly into `register_schedule_routes`'s POST `/api/schedules`
/// handler — its `AuthRoutes&` parameter is replaced by `deps.perm_fn` /
/// `deps.resolve_session_fn` / `deps.audit_fn`, matching every other #2542
/// module's convention (no other extracted module threads a raw
/// `AuthRoutes*` through Deps) — and retires the free function; every
/// assertion the interim extraction's direct-call tests made is preserved
/// in `test_schedule_routes.cpp`, now driven through `TestRouteSink`
/// instead of calling a bare function. `parse_schedule_enabled` stays a
/// standalone free function — it takes no Deps at all (pure body parsing,
/// no session/permission/store dependency) — and keeps its own direct unit
/// coverage unchanged.
///
/// `resolve_session_fn`: routes call `AuthRoutes::resolve_session` directly,
/// rather than `require_auth`/the hoisted `auth_fn`'s
/// `(req,res)->optional<Session>` shape (which gates and writes a 401 on
/// failure). `resolve_session` takes ONLY `req` (no `res`) and is used
/// strictly as a post-gate "who is calling" lookup, after
/// `perm_fn`/`require_permission` above it has already proven a valid
/// session exists — see `auth_routes.hpp`'s own doc comment on the method.
/// This closure is shared with PR-7's `instruction_routes.cpp`/
/// `execution_routes.cpp` (hoisted once, alongside `auth_fn`/`perm_fn`/
/// `audit_fn`, in server.cpp's shared closure block at `start_web_server()`
/// time) — no module-local closure is defined here.
///
/// KNOWN GAP (#4131, pre-existing, confirmed byte-identical on origin/dev
/// before this extraction): the create route calls this closure a SECOND
/// time, independent of `perm_fn`'s own internal session resolution used for
/// the gate check. On `nullopt` (a concurrent session eviction, or a
/// Postgres session-store brownout), `created_by` silently stays `""`
/// rather than failing closed — and `""` can never match a real username,
/// so the owner-scoped DELETE/enable routes below can never reach that row
/// again, and (under RBAC legacy-open) it still arms and fires unattended
/// forever with no kill switch. Not fixed by this mechanical move; see
/// #4131 for the real remedy.
///
/// Routes (4) — gate in parens, all backed by `deps.schedule_engine` (null
/// -> 503 on every route; no `is_open()` check anywhere in this module —
/// matches the pre-extraction inline code exactly, unlike
/// `custom_properties_routes`'s `CustomPropertiesStore`, which does check
/// it):
///   GET    /api/schedules              (perm_fn Schedule:Read)
///   POST   /api/schedules              (perm_fn Schedule:Write AND
///                                        Execution:Execute — both required,
///                                        H-01 #1806)
///   DELETE /api/schedules/:id          (perm_fn Schedule:Delete;
///                                        owner-scoped delete via
///                                        created_by — M-01 #1806)
///   POST   /api/schedules/:id/enable   (perm_fn Schedule:Write always,
///                                        PLUS Execution:Execute iff the
///                                        parsed body requests enabled=true
///                                        — H-01; owner-scoped — M-01)
///
/// AUDIT ASYMMETRY (preserved verbatim, not a defect introduced by this
/// move): GET is unaudited (pure read). POST create audits ONLY success
/// (`schedule.create`) — its own body/parameter-validation 400s and the
/// store-level `create_schedule` failure are both unaudited. DELETE audits
/// only an actual deletion (`schedule.delete`, `success`) — a
/// nonexistent-or-wrong-owner id (`delete_schedule` returns false) is NOT
/// audited. POST enable audits only an actual state change
/// (`schedule.enable`/`schedule.disable`, `success`) — a no-op
/// (`set_enabled` returns false) is NOT audited. This is the pre-existing
/// server.cpp behaviour, copied as-is; it is not this extraction's place to
/// change it.
///
/// SERVICE-SCOPED TOKEN NOTE (guardian-confinement-2298, retired dead
/// code): server.cpp's inline routes used to carry an explicit
/// `deny_service_scoped_schedule()` call on each of these 4 routes; PR 3
/// ("the flip") made every one of them provably dead — `require_permission`
/// above already denies any service-scoped token outright for
/// `(Schedule, *)`/`(Execution, Execute)` (`kServiceScopeGlobalSafe` is
/// compile-time-empty for both), so a service-scoped session can never
/// reach the deny call. All 4 were retired #3290 Phase 2 bucket 1a — this
/// move carries no such call forward (there was none left to carry). The
/// observable 403-for-a-service-scoped-token behaviour is still directly
/// pinned by this module's PG-backed test coverage, now produced by
/// `perm_fn`/`require_permission` alone.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class ScheduleEngine;
} // namespace yuzu::server

namespace yuzu::server::schedule {

/// Construction deps for `register_schedule_routes`. Every closure/pointer
/// is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Wraps `AuthRoutes::resolve_session` — see this file's header comment
    /// for why this differs from `auth_fn`'s shape, and for the closure's
    /// shared ownership with PR-7's instruction/execution modules.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;
    /// Bool-returning audit contract, same shape as
    /// `custom_properties::Deps::AuditFn` / `result_set::Deps::AuditFn` —
    /// server.cpp's hoisted `audit_fn` closure. This module's callers do
    /// NOT act on a `false` return (matches the original inline code's
    /// `(void)audit_log(...)` discards — preserved, not hardened, by this
    /// move).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    PermFn perm_fn;
    ResolveSessionFn resolve_session_fn;
    AuditFn audit_fn;
    /// `ServerImpl::schedule_engine_`. Null -> every route answers 503
    /// without touching it.
    ScheduleEngine* schedule_engine{nullptr};
};

/// Register all 4 Schedules API routes against `sink`.
void register_schedule_routes(HttpRouteSink& sink, Deps deps);

/// Parses the `enabled` field of a `POST /api/schedules/{id}/enable` body.
/// Extracted from the inline server.cpp lambda (guardian-confinement-2298
/// hardening sweep) so the parsing has direct unit coverage — accepts BOTH
/// a genuine JSON boolean and the legacy string encoding
/// (`"true"`/`"false"`); a missing key or a body that fails to parse
/// defaults to `true`, matching the pre-existing contract (disable is an
/// explicit opt-in, never inferred from absence). A real JSON boolean used
/// to fall through this default silently — `extract_json_string` only
/// matches a JSON *string* value — so `{"enabled": false}`, the encoding
/// every standards-compliant JSON client library produces for a boolean
/// field, computed to `enabled=true`: inverting the request and, worse,
/// defeating the disable-always-reachable kill switch (H-01, #1806) for any
/// such caller.
bool parse_schedule_enabled(const std::string& body);

} // namespace yuzu::server::schedule
