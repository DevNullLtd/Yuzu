#pragma once

#include <yuzu/server/auth.hpp>

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "authz_gates.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "saml_provider.hpp"
#include "rbac_store.hpp"
#include "service_scope_policy.hpp" // authz::PermPair — the test-override seam's element type
#include "tag_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

namespace detail {

/// Sanitises an externally-controlled string (the motivating case is an
/// OIDC `display`/`email`/`sub` claim — a hostile or misconfigured IdP, or a
/// user-set display name, is not trusted input) before it is concatenated
/// into an audit `detail` string or an emit_event JSON attribute. `detail`
/// is a flat "k=v;k=v" string parsed by SIEM tooling and rendered on the
/// dashboard audit log; an unsanitised value could inject `;`/`=` to forge
/// additional fields, or `\r`/`\n`/other control bytes to inject fake log
/// lines or corrupt terminal/log-viewer rendering. Replaces `;`, `=`, `\r`,
/// `\n`, and any control byte (incl. DEL) with `_`, then truncates to 128
/// bytes — backing up to a UTF-8 code-point boundary so a multi-byte value
/// never ends mid-sequence. Dependency-free by design. Exposed in
/// `yuzu::server::detail` (mirrors the rest_a4_envelope.hpp pattern) so unit
/// tests can call it directly.
///
/// This is audit-detail-field-injection defense ONLY — it does NOT strip
/// HTML markup, so it is not by itself a stored-XSS defense. An IdP-supplied
/// value with no control bytes (e.g. `<script>...</script>` as a display
/// name) passes through unchanged; the audit-log dashboard render layer's
/// HTML-escaping (`html_escape`) is what neutralises markup when this value
/// is later rendered. Never rely on this function alone to make a value
/// HTML-safe.
std::string sanitize_detail_value(std::string_view v);

} // namespace detail

struct Config;
class EnginePrincipalStore;
class ScimStore;

/// Result of `AuthRoutes::require_list_read` — the transport-layer twin of
/// `RbacStore::ListReadAuthorization` (ADR-0017). Lives here, not in
/// rbac_store.hpp, because it carries a `Session` (an auth/transport concept;
/// RbacStore is a data-layer primitive and must not depend on it) and at
/// namespace scope, not nested in `AuthRoutes`, for consistency with its
/// sibling `ListReadDecision`/`ListReadAuthorization`.
struct ListReadGate {
    /// false ⇒ the response is already fully rendered (401/403/503) —
    /// mirrors require_permission/require_scoped_permission's bool contract.
    bool admitted{false};
    /// nullopt = unfiltered (whole fleet); engaged (including empty, INV-2)
    /// = filter to exactly these agents.
    std::optional<std::vector<std::string>> scope;
    /// The resolved session, so a caller doesn't have to re-resolve it.
    std::optional<auth::Session> session;
};

/// Extracted auth helpers and route handlers (Phase 2 of god-object decomposition).
///
/// AuthRoutes owns the core authentication/authorization/audit primitives that
/// are used throughout the server: require_auth, require_admin, require_permission,
/// require_scoped_permission, audit_log, emit_event, etc.
///
/// ServerImpl creates an AuthRoutes instance early, then builds lightweight lambda
/// callbacks from its public methods to inject into RestApiV1, McpServer,
/// SettingsRoutes, and its own remaining route handlers.
class AuthRoutes {
public:
    AuthRoutes(Config& cfg, auth::AuthManager& auth_mgr, RbacStore* rbac_store,
               ApiTokenStore* api_token_store, AuditStore* audit_store,
               ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
               AnalyticsEventStore* analytics_store, std::shared_mutex& oidc_mu,
               std::unique_ptr<oidc::OidcProvider>& oidc_provider,
               saml::SamlProvider* saml_provider = nullptr);

    // -- Auth helpers (called by server.cpp to create callbacks for other modules) --

    /// Validate session cookie, Bearer token, or X-Yuzu-Token header.
    /// Returns a Session on success, or sets 401 and returns nullopt.
    std::optional<auth::Session> require_auth(const httplib::Request& req, httplib::Response& res);

    /// Resolve the authenticated session from a request without writing a response.
    /// Tries cookie, then `Authorization: Bearer`, then `X-Yuzu-Token`. Returns
    /// nullopt if none match. Use this when you need the principal name for
    /// provenance (e.g. `created_by`, audit event annotation) on a code path
    /// that has already cleared its authorization gate via require_auth or
    /// require_permission and just needs to know who's calling.
    std::optional<auth::Session> resolve_session(const httplib::Request& req);

    /// Re-validate the credential on a HELD-OPEN stream (MCP `GET /mcp/v1/`),
    /// against the principal that stream is bound to. Called once per heartbeat
    /// tick from the SSE pump, so a revoked credential cuts a LIVE stream — not
    /// merely future attaches (ADR-1005 Decision 15(c)).
    ///
    /// Tri-state on purpose (Decision 15(i) / chaos CH-4): an unreachable auth
    /// backend is NOT a revocation, and must not cut every stream on the fleet at
    /// the same instant — it yields kIndeterminate, which the pump rides out for a
    /// bounded grace window. Anything definitive (no credential, unknown/expired
    /// cookie, revoked/expired token, credential now bound to a DIFFERENT
    /// principal) is kRevoked and kills the stream on the spot.
    ///
    /// Credential precedence mirrors `resolve_session` (cookie → Bearer →
    /// X-Yuzu-Token) but deliberately skips its lazy elevation-reap side effect —
    /// re-validation is a read, not a request.
    ///
    /// NOTE (accepted, documented for security review): a cookie-authenticated
    /// stream slides the session's INACTIVITY window on every tick, so a live
    /// stream keeps its cookie session alive. The absolute session lifetime still
    /// terminates it. MCP clients authenticate with API tokens in practice; if the
    /// inactivity semantics matter for a future browser-side MCP client, the fix is
    /// a non-touching `peek_session` on AuthManager.
    auth::CredentialCheck revalidate_stream(const httplib::Request& req,
                                            const std::string& expected_principal);

    /// Calls require_auth, then checks session.role == admin.
    /// Returns true if admin; sets 403 and returns false otherwise.
    bool require_admin(const httplib::Request& req, httplib::Response& res);

    /// RBAC-aware permission check. Falls back to legacy admin/user check if RBAC is disabled.
    bool require_permission(const httplib::Request& req, httplib::Response& res,
                            const std::string& securable_type, const std::string& operation);

    /// Scoped RBAC-aware permission check for device-specific operations.
    bool require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                   const std::string& securable_type, const std::string& operation,
                                   const std::string& agent_id);

    /// The transport-layer ADR-0017 admit-then-filter list-read gate — the
    /// SOLE authorization gate for a list/fan-out route reading per-agent
    /// data under management-group confinement. Replicates the SAME
    /// session-class ladder as `require_permission` (auth → elevation →
    /// engine → MCP tier → service-scoped token → legacy/RBAC) but the
    /// ordinary-RBAC-enforced case delegates to `RbacStore::authorize_list_read`
    /// instead of `check_permission`, because `check_permission` never
    /// consults `ManagementGroupStore` — stacking the two gates (one calling
    /// the other) does NOT compose; a caller whose only grant is
    /// management-group-scoped is denied by `require_permission` before
    /// `authorize_list_read` is ever reached. This method must be the
    /// route's ONLY gate — no `perm_fn` in front of or behind it.
    ///
    /// Structurally Read-only: `operation != "Read"` is denied outright, so
    /// the MCP approval-ticket branch (`mcp::requires_approval`) never
    /// applies — approval gating exists only for destructive operations.
    ///
    /// A JIT-elevated session is admitted unfiltered WITHOUT calling
    /// `authorize_list_read` — elevation intentionally needs no underlying
    /// RBAC grant, and consulting the primitive anyway would deny a
    /// legitimately-elevated caller who holds no base grant (the regression
    /// the first #3038 fix attempt shipped).
    ///
    /// Route-class distinction from `authz::AuthRoutes::require_fleet_read`
    /// (#2298 PR 3 §3f, closes #3218): this method is the sole gate on
    /// fleet-wide ROLLUP routes — it refuses a service-scoped session
    /// outright, since a rollup has no per-service slice to narrow to.
    /// `require_fleet_read` (`authz_gates.hpp`) REPLACES `require_permission`
    /// (never pairs with it — see its own doc comment's BLOCKING note) on
    /// routes migrating toward real per-request service-scope confinement
    /// (#3290 Phase 2). They are not interchangeable.
    ///
    /// An engine principal is special-cased (RBAC-only, never legacy-open)
    /// rather than delegated to `authorize_list_read` directly:
    /// `authorize_list_read`'s legacy-open branch returns `AdmitAll` when
    /// RBAC is disabled, which would hand an engine credential fleet-wide
    /// read — forbidden by the engine default-deny model (design §4.2).
    ///
    /// CONSTRAINT for future callers: `authorize_list_read`'s legacy-open
    /// branch does not apply `authz_topology_floor.hpp`'s `kTopologyFloor`
    /// (that floor is applied only inside `require_permission`'s own legacy
    /// branch). This is moot for every caller today (GuaranteedState:Read is
    /// not a floored securable) but a FUTURE floored securable routed
    /// through `require_list_read` must re-apply the floor explicitly —
    /// do not assume this wrapper inherits it for free.
    ListReadGate require_list_read(const httplib::Request& req, httplib::Response& res,
                                   const std::string& securable_type,
                                   const std::string& operation);

    // -- Phase 0 confinement primitives (service-scope-confinement design doc
    //    §7.2/§8) — wired here; first live caller landed #3290 Phase 2
    //    (GET /api/v1/inventory/software + its MCP twin). See
    //    authz_gates.hpp for `ListAuthority`/`GateFailure`, authz_gates.cpp
    //    for bodies. RELATED BUT DISTINCT from `require_list_read` above:
    //    both compose `RbacStore::authorize_list_read`, but for different
    //    purposes (general ADR-0017 confinement vs. service-scope
    //    confinement) and with different return shapes. #3218 (this
    //    shared-name-prefix confusability) is CLOSED as of #2298 PR 3,
    //    ADR-1006 "Decision 2 — closes #3218": the two gates stay
    //    deliberately separate, not merged — see `require_list_read`'s own
    //    doc comment above ("Route-class distinction") and
    //    `docs/adr/1006-service-scope-default-deny.md` for the resolution.
    //    The rename below (authorize_* -> require_*/confine_*, fjarvis/Kimi
    //    K2.7 follow-up review) moved `require_fleet_read` into the same
    //    `require_*` family as `require_list_read` — a naming proximity
    //    that is safe only because the closed #3218 discussion already
    //    settled the two gates are not interchangeable. #3290 Phase 2
    //    closed the remaining per-caller-class gap this comment used to
    //    warn about: `require_fleet_read` now carries its own
    //    elevated/engine/mcp_tier branches (mirroring
    //    `require_list_read`'s, not `require_permission`'s — see its own
    //    doc comment) rather than calling `authorize_list_read` directly
    //    with no caller-class handling. ------------------------------------

    /// The two-axis list-read gate. Named `require_*`, not `authorize_*`
    /// (renamed post-#3216, fjarvis/Kimi K2.7 follow-up review): it is a
    /// self-sufficient authority gate that writes `res` on every failure
    /// path itself, same contract as `require_permission`/
    /// `require_scoped_permission` — a caller does not need, and must not
    /// add, a second decision on top of it. Management-group visibility (the
    /// existing ADR-0017 `RbacStore::authorize_list_read` chokepoint, reused
    /// as the subordinate primitive here, never rewritten) intersected
    /// (`authz::meet`) with service-scope visibility (a service-scoped
    /// session's `service`-tagged agents; TOP/unfiltered for a non-service
    /// session, so the result is byte-identical to `authorize_list_read`
    /// alone in that case). Per-axis fail-closed BEFORE the intersection,
    /// each axis's own infrastructure-unavailable case landing on
    /// `GateFailure::Degraded` (503, retryable): a null/not-open RBAC store
    /// on the management axis, and a null or query-failed tag store on the
    /// service axis. Only a genuine `ListReadDecision::DenyAll` — real "no
    /// grant," or an in-query store error surfacing through it, the one
    /// residual weakening of `authorize_list_read`'s own promise this gate
    /// does not add a discriminator for (implementation plan §2c) — lands on
    /// `GateFailure::Forbidden` (403).
    ///
    /// SELF-SUFFICIENT for the RBAC/management-group authority decision — do
    /// NOT additionally gate the same `(securable_type, operation)` on
    /// `require_permission` before or after calling this. `require_permission`'s
    /// ordinary RBAC branch decides on `check_permission` ALONE (a global-grant
    /// check) and never consults `mgmt_group_store_` — pairing it with this gate
    /// rejects a management-group-scoped-only caller before this gate's own
    /// `authorize_list_read` call ever runs, making the `AdmitScoped` branch
    /// below permanently unreachable for exactly the confined reader ADR-0017
    /// exists to serve. Confirmed BLOCKING in code review (2026-08-17,
    /// reviewer `fjarvis`, PR #3216) — the prior text here prescribed that
    /// exact broken sequence; see `test_authz_gates.cpp`'s "documented pairing"
    /// test for the falsifier (the broken sequence denies a management-group-
    /// scoped-only caller; this gate alone, correctly, does not).
    ///
    /// Caller-class coverage (#3290 Phase 2 — this paragraph previously
    /// listed several gaps here; all are now closed, largely mirroring
    /// `require_list_read`'s ladder — but NOT identically; two deliberate
    /// divergences, both correct, are called out below rather than left for
    /// a reader to assume full interchangeability (architect, governance run
    /// 2026-08-20)): a JIT-elevated non-service session is admitted
    /// unfiltered (TOP) without consulting `authorize_list_read` at all,
    /// same rationale as `require_list_read` — the regression the first
    /// #3038 fix attempt shipped. DIVERGENCE 1: this gate's elevated branch
    /// keeps the `token_scope_service.empty()` guard, which matches
    /// `require_permission`'s elevated branch, NOT `require_list_read`'s
    /// (which has no such guard) — deliberate defense-in-depth, since
    /// `elevate_session` never runs for a service-scoped session anyway. An
    /// engine principal is resolved RBAC-only (never the legacy-open branch,
    /// which would otherwise hand it a fleet-wide read the moment RBAC is
    /// disabled) and, on a grant, gets a TOP admit — engine authority has no
    /// per-tag scoping concept, so it is never routed through the meet(mgmt,
    /// service) composition below. `mcp_tier` enforcement
    /// (`mcp::tier_allows`) denies-or-falls-through before the
    /// management-group axis, same as `require_permission`/
    /// `require_list_read`; `mcp::requires_approval` is moot here, same as
    /// `require_list_read`, because this gate is structurally Read-only
    /// (approval gating exists only for destructive operations). DIVERGENCE
    /// 2 has THREE distinct sub-cases, not one shared shape (authdb +
    /// security-guardian, governance run 2026-08-20 — two successive drafts
    /// of this paragraph each conflated a pair of these): (a) `rbac_store_ ==
    /// nullptr` — `require_permission`/`require_list_read` both short-circuit
    /// their `rbac_store_ && ...`-guarded RBAC-enforced branch and fall to
    /// their LEGACY-OPEN path (unfiltered admit) on this condition
    /// (`auth_routes.cpp` — `require_permission`'s `#1717` comment; `require_
    /// list_read`'s own `!rbac_store_` short-circuit) — this gate fails
    /// CLOSED (503) instead, a genuine, pre-existing gap from Phase 0 (#3216)
    /// this migration deliberately did not widen to match. (b) `rbac_store_`
    /// NON-NULL but `!is_open()` (degraded) — the siblings do NOT fall open
    /// here: `rbac_enforcement_in_effect()` (`rbac_store.cpp:1608`) returns
    /// `true` for a non-null-but-not-open store, routing both siblings INTO
    /// their RBAC-enforced branch, where `check_permission`/`authorize_list_
    /// read` fail on the dead handle and 403 (fail CLOSED, matching this
    /// gate's posture) — the only divergence here is STATUS-CODE
    /// GRANULARITY: a permanent-looking 403 indistinguishable from "no
    /// grant" in the siblings vs this gate's correct retryable 503. (c) a
    /// null OR not-open `mgmt_group_store_` — NEITHER sibling distinguishes
    /// null from not-open for this store the way (a)/(b) do for
    /// `rbac_store_`; both already fail CLOSED via `RbacStore::resolve_perm_
    /// groups`/`expand_visible_set`/`check_scoped_permission`'s pointer
    /// null-check (a not-open-but-non-null pointer isn't caught by that
    /// check and instead fails at the query layer — the SAME status-code-
    /// only divergence as (b), not a further split). Sub-case (c) was closed
    /// in THIS governance round (unhappy-path finding UP-1) — see the
    /// null-store branches in `authz_gates.cpp`. The RBAC-enabled requirement
    /// for service-scoped sessions
    /// remains covered (#2298 PR 3, decision 1): a disabled-RBAC
    /// service-scoped session hard-403s here too, same predicate
    /// (`rbac_enforcement_in_effect`) and same outcome as
    /// `require_permission`'s service branch, so the two gates cannot
    /// disagree on this axis. #3218 (the shared-name-prefix confusability
    /// between these two gates) stays CLOSED — see the "Phase 0 confinement
    /// primitives" comment above: the two gates remain deliberately separate
    /// types serving different route classes (rollup vs. per-agent list),
    /// and their caller-class ladders are similar in SHAPE, not identical in
    /// every branch's guard condition.
    ///
    /// #4031 UPDATE: unlike `require_list_read` (whose own doc comment above
    /// still names this as an open gap a future caller must close itself),
    /// this gate DOES now apply `authz_topology_floor.hpp`'s floor: a
    /// non-admin session is denied a floored securable
    /// (`topology_floor_applies`) whenever RBAC enforcement is not in effect,
    /// mirroring `require_permission`'s own legacy-branch floor check
    /// (same audit-reason prefix, same `yuzu_auth_topology_floor_denied_total`
    /// counter — see `authz_gates.cpp`). `RbacStore::authorize_list_read`'s
    /// own legacy-open branch has no floor concept of its own (a data-layer
    /// primitive must not depend on `Session`), so this gate's own
    /// pre-check is the only thing standing between a disabled-RBAC install
    /// and a silent full-fleet AdmitAll on a securable seeded admin-only —
    /// `Enrollment:Read` (GET /api/v1/enrollment/pending-agents) is the
    /// first floored securable ever routed through this gate.
    [[nodiscard]] std::expected<authz::ListAuthority, authz::GateFailure>
    require_fleet_read(const httplib::Request& req, httplib::Response& res,
                       const std::string& securable_type, const std::string& operation);

    /// The single-agent confinement gate: does `agent_id` carry the
    /// `service` tag matching this session's `token_scope_service`?
    /// CONFINEMENT-AXIS ONLY — this is NOT a full authority decision and
    /// does not re-check the RBAC grant a caller must independently verify
    /// for the same `(securable_type, operation)`. Named `confine_*`, not
    /// `authorize_*` (renamed post-#3216, fjarvis/Kimi K2.7 follow-up
    /// review) precisely because it is not self-sufficient the way
    /// `require_fleet_read` is — the name itself now carries the "you still
    /// need an RBAC check alongside this" constraint instead of relying on
    /// a reader finding this paragraph. Pair with
    /// `require_scoped_permission`, NOT `require_permission` — this gate is
    /// single-agent-shaped, and `require_scoped_permission` (unlike
    /// `require_permission`) correctly passes `mgmt_group_store_` to
    /// `check_scoped_permission` in the branch such a caller reaches (the
    /// RBAC-enforced default; the `engine` branch also passes it correctly
    /// but is reachable only by an `engine`-`principal_kind` session, a
    /// structurally separate default-deny caller class a management-group-
    /// scoped caller cannot be) — so such a caller is not incorrectly
    /// rejected before ever reaching this gate's own check — the exact
    /// BLOCKING defect found in
    /// `require_fleet_read`'s sibling comment (2026-08-17, reviewer
    /// `fjarvis`, PR #3216) does not apply here, but corrected proactively
    /// since the wrong function name was named for the same reason. For a
    /// NON-service session the axis is TOP (unfiltered) by definition, so
    /// this returns `true` unconditionally — it answers only "is this
    /// target inside the token's service scope," never "is this caller
    /// authorized at all."
    ///
    /// Empty `agent_id` is a 400, never an admit — the shape
    /// `require_scoped_permission`'s service branch had before #2298 PR 3
    /// §3b closed it there (an empty `agent_id` used to skip the only
    /// comparison that could deny and fall through to `return true`); this
    /// gate was built to not repeat that degenerate shape, not to fix a bug
    /// still live in that function. Fail-closed 503 on a null or degraded
    /// tag store, matching that same function's tag-store-unavailable case.
    [[nodiscard]] bool confine_agent_target(const httplib::Request& req, httplib::Response& res,
                                            const std::string& securable_type,
                                            const std::string& operation,
                                            const std::string& agent_id);

    /// Build a synthetic session from a validated API token. Two-branch on the
    /// token's persisted `principal_kind` (design doc §6):
    ///  - "human" (or any legacy/unset value): exactly the pre-#2021 behavior
    ///    — attribute to the creating user, re-resolve their current role.
    ///    Always returns a session.
    ///  - "engine": the session IS the engine principal (`auth_source =
    ///    "engine_token"`); role/authority resolve from RBAC assignments, never
    ///    `get_user_role`. Consults `engine_principal_store_` — a missing/
    ///    revoked or unreachable-store outcome returns `nullopt` (fail-closed;
    ///    no session), as does a null `engine_principal_store_` (not yet wired).
    std::optional<auth::Session> synthesize_token_session(const ApiToken& api_token);

    /// Inject the engine-principal auth-lookup store (nullable — a null
    /// pointer makes every engine-kind token fail closed with no session,
    /// which is the correct posture before this is wired). Setter rather than
    /// a ctor param to keep the stacked-PR wiring in server.cpp low-risk.
    void set_engine_principal_store(EnginePrincipalStore* store) {
        engine_principal_store_ = store;
    }

    /// Inject the ScimStore identity-link store (nullable — ADR-2001 §2 link
    /// formation at OIDC login is fail-OPEN by design, so a null store here
    /// simply skips the link/observation writes rather than failing the
    /// login). Setter rather than a ctor param for the same low-risk
    /// stacked-wiring reason as set_engine_principal_store.
    void set_scim_store(ScimStore* store) { scim_store_ = store; }

    /// Cookie attribute string: "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800" + optional ";
    /// Secure".
    std::string session_cookie_attrs() const;

    /// Construct an AuditEvent from HTTP request context.
    AuditEvent make_audit_event(const httplib::Request& req, const std::string& action,
                                const std::string& result);

    /// Write an audit event to the audit store. Returns true iff the row
    /// was persisted; returns true (no-op success) when no AuditStore is
    /// configured (operator-chosen audit-off mode). Returns false on a
    /// silent persist failure (audit DB locked / disk full / corruption).
    /// SOC 2 CC6.6 evidence-emitting handlers MUST capture the return so
    /// they can surface partial-success on the response (HIGH-2 on PR #883,
    /// UP-H1 on PR W1.1). The bool is [[nodiscard]] on the AuditStore
    /// primitive but not on this wrapper — most call sites legitimately
    /// fire-and-forget.
    bool audit_log(const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type = {},
                   const std::string& target_id = {}, const std::string& detail = {});

    /// Variant that stamps `principal` + `principal_role` explicitly
    /// rather than resolving from `resolve_session(req)`. Used at the
    /// three "mint a fresh session" sites (`POST /login` no-MFA,
    /// `POST /login/mfa` TOTP/recovery success, OIDC `/auth/callback`)
    /// where the request itself carries no session cookie yet but the
    /// authenticating principal IS known to the handler. Without this,
    /// `make_audit_event` writes an empty `principal` and the SOC 2
    /// CC6.6 query "every privileged session-creation row names the
    /// principal" returns false negatives (Gate 4 consistency B3).
    ///
    /// `principal_class_override`: `make_audit_event` re-stamps the class from the
    /// resolved session's `principal_kind`, so an engine principal audits as "engine"
    /// rather than the "agent" its bearer-token presentation implies. A caller that
    /// already knows the class (because it captured it while the session was live) must
    /// pass it, or its rows will disagree with the request-time rows for the same actor.
    /// Empty keeps the credential-presentation default, which is right for the
    /// pre-session login/MFA/OIDC sites.
    bool audit_log_for_principal(const httplib::Request& req, const std::string& action,
                                 const std::string& result, const std::string& principal,
                                 const std::string& principal_role,
                                 const std::string& target_type = {},
                                 const std::string& target_id = {},
                                 const std::string& detail = {},
                                 const std::string& principal_class_override = {});

    /// guardian-confinement-2298 PR3 §3e — server.cpp's shared deny gate for
    /// routes that reach agent/fleet/execution data via `require_auth`
    /// alone, with no `require_permission`/`require_scoped_permission` call
    /// at all (so the §3a flip never runs for them). Same
    /// resolve-then-check-`token_scope_service`-then-403+audit shape and
    /// throw-safety ordering (403 written before the audit call) as the
    /// per-file `deny_service_scoped_*` family in guardian_routes.cpp /
    /// dex_routes.cpp / deployment_routes.cpp / preflight_routes.cpp / etc.
    /// — server.cpp gets its own copy here (rather than a free function)
    /// because it already holds `auth_routes_` and delegates every other
    /// auth primitive through it. Returns true iff the caller must return
    /// immediately (either a written 401/redirect from `require_auth`, or
    /// the 403 deny itself); false means the session is present and is not
    /// service-scoped, so the caller proceeds. Deliberately does NOT touch
    /// the §3a `yuzu_auth_service_scope_default_denied_total` metric — that
    /// metric counts `require_permission`'s own default-deny branch, and
    /// these routes never call it; counting them there would misrepresent
    /// what "default denied at the flip" means.
    ///
    /// `permission` defaults EMPTY, not a securable pair — every route this
    /// gate covers is a blanket deny with no RBAC grant that would admit a
    /// service-scoped token (that's the whole point of §3e). A4's
    /// `permission` field names "the missing grant" for a caller to
    /// self-remediate; naming one that doesn't exist would be a false claim
    /// (the A4 builder omits the field entirely when this is empty — see
    /// `A4ErrorOpts::permission`'s doc comment). Pass a real securable pair
    /// explicitly only if a future caller of this gate genuinely has one.
    [[nodiscard]] bool deny_service_scoped_session(const httplib::Request& req,
                                                   httplib::Response& res,
                                                   const std::string& action,
                                                   const std::string& message,
                                                   const std::string& target_type = {},
                                                   const std::string& target_id = {},
                                                   const std::string& permission = {});

    /// #3289 — the legacy dashboard tag-mutation family's guard against the
    /// tag-write TOCTOU `require_scoped_permission`'s service branch has on
    /// its own: that branch authorizes a mutation of tag `key` using the
    /// PRE-WRITE value of that same tag (`agent's service tag == token's
    /// scope`), so a service-scoped token can rewrite/delete its own
    /// cohort's `service` tag and move an agent out of (or a different
    /// agent into) its own confinement. Call this BEFORE
    /// `require_scoped_permission("Tag", "Write"|"Delete", agent_id)`, right
    /// after the key is parsed/normalized. Value-blind by design (see
    /// `authz::service_scope_may_mutate_tag_key`) — this deny does not
    /// become a membership oracle: it is identical whether `agent_id` is in
    /// or out of the token's scope, unlike `require_scoped_permission`'s own
    /// mismatch deny (`auth_routes.cpp:1084-1087`), which still discloses
    /// membership for non-service keys — that disclosure is pre-existing and
    /// out of this guard's scope. Returns true iff the caller must return
    /// immediately; false means either the session is not service-scoped or
    /// `key` is not the service tag, so the caller proceeds to its normal
    /// gate. No `.permission` in the A4 body — no grant admits a
    /// service-scoped session past this rule (routed-concern clause 5).
    [[nodiscard]] bool deny_service_scoped_service_tag_mutation(const httplib::Request& req,
                                                                 httplib::Response& res,
                                                                 const std::string& action,
                                                                 const std::string& agent_id,
                                                                 const std::string& key);

    /// Emit an analytics event with HTTP request context.
    void emit_event(const std::string& event_type, const httplib::Request& req,
                    const nlohmann::json& attrs = {}, const nlohmann::json& payload_data = {},
                    Severity sev = Severity::kInfo);

    // -- Route registration ---------------------------------------------------

    /// Register auth-related routes: GET/POST /login, POST /login/mfa,
    /// POST /logout, GET /auth/oidc/start, GET /auth/callback.
    ///
    /// Production callers use this overload; it constructs an
    /// `HttplibRouteSink` over `svr` and delegates to the sink-based
    /// overload below. Same handlers, same lambdas, same behaviour.
    void register_routes(httplib::Server& svr);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process `TestRouteSink` and dispatch synthesized requests
    /// directly, avoiding `httplib::Server`'s TSan-hostile acceptor
    /// thread (#438). Matches the pattern already in use by
    /// `SettingsRoutes::register_routes`.
    void register_routes(class HttpRouteSink& sink);

    // -- Static utilities (also used by server.cpp pre-routing handler) --------

    /// Extract the yuzu_session cookie value from a request.
    static std::string extract_session_cookie(const httplib::Request& req);

    /// URL-decode a percent-encoded string.
    static std::string url_decode(const std::string& s);

    /// Extract a form-urlencoded value by key from a POST body.
    static std::string extract_form_value(const std::string& body, const std::string& key);

private:
    /// The gates `synthesize_token_session` applies AFTER the api_tokens row itself
    /// validates: the `principal_kind` allowlist, and — for an engine token — that the
    /// backing engine principal is still Active. `revalidate_stream` must apply them
    /// too, or a deleted/revoked engine principal keeps its live stream while every
    /// fresh request it makes is refused. Returns kIndeterminate (never kRevoked) when
    /// the engine store cannot answer, so a store blip defers rather than mass-kills.
    ///
    /// PRIVATE ON PURPOSE (#2367). This is the ONLY site that reads the engine
    /// principal through `EnginePrincipalStore::get_for_auth_revalidate`, i.e. the
    /// 15 s cached path. That is sound here and only here, because the stream
    /// revalidation this serves already tolerates staleness of the same order by
    /// design (on StoreUnreachable the pump rides out a ~60 s grace window,
    /// Decision 15(i)/CH-4). A FRESH authorization decision tolerates none, so
    /// widening access to this method would silently hand a caller a cached
    /// answer to a question that must be asked of Postgres every time. If you
    /// need the engine-principal gate somewhere new, call
    /// `EnginePrincipalStore::get_for_auth` directly — do not make this public.
    [[nodiscard]] auth::CredentialCheck engine_credential_state(const ApiToken& token) const;

    Config& cfg_;
    auth::AuthManager& auth_mgr_;
    RbacStore* rbac_store_;
    ApiTokenStore* api_token_store_;
    // Nullable — see set_engine_principal_store(). Non-owning; lifetime is
    // guaranteed by ServerImpl (T8 wiring), which outlives AuthRoutes.
    EnginePrincipalStore* engine_principal_store_{nullptr};
    // Nullable — see set_scim_store(). Non-owning; lifetime is guaranteed by
    // ServerImpl (constructed well before AuthRoutes), which outlives
    // AuthRoutes. Used ONLY at the OIDC login site (ADR-2001 §2/§D2) to form
    // an identity link and record the login observation, both fail-OPEN.
    ScimStore* scim_store_{nullptr};
    AuditStore* audit_store_;
    ManagementGroupStore* mgmt_group_store_;
    TagStore* tag_store_;
    AnalyticsEventStore* analytics_store_;
    std::shared_mutex& oidc_mu_;
    std::unique_ptr<oidc::OidcProvider>& oidc_provider_;
    // Non-owning pointer — lifetime is guaranteed by ServerImpl which holds the
    // unique_ptr<SamlProvider> and outlives AuthRoutes. No mutex needed: the
    // provider is constructed once at startup (xmlsec global init is not thread-safe;
    // the startup phase is single-threaded) and never mutated afterward.
    saml::SamlProvider* saml_provider_{nullptr};

    /// Pending MFA challenge issued after a successful password verify on
    /// /login when the user has TOTP enrolled. Keyed by an opaque random
    /// `mfa_pending_token` returned to the browser; resolved by the
    /// matching POST /login/mfa request. Expires after
    /// `cfg.mfa_login_pending_secs`; entries are reaped lazily on every
    /// access. SOC 2 CC6.6 — see docs/auth-mfa-design.md.
    ///
    /// `attempts` caps online TOTP guessing per challenge to
    /// `kMfaMaxAttemptsPerPending` (default 5). Once exceeded the entry
    /// is erased and the operator must restart with a fresh password
    /// submission. Closes Gate 2 H1 + unhappy-path UP-11 (rate-limit
    /// gap → CPU DoS via PBKDF2 amplification).
    /// Discriminates the two pending-token flavours that share the
    /// `mfa_pending_` map (PR3). An enum rather than a bool so a third kind
    /// (e.g. a future password-reset or WebAuthn challenge) is an additive
    /// variant rather than a second bool — and so the cross-endpoint guards
    /// read as `kind != PendingKind::enrollment` (self-documenting).
    enum class PendingKind {
        /// Login challenge for an already-enrolled user, resolved by
        /// POST /login/mfa (verify a TOTP/recovery code vs the live secret).
        login_challenge,
        /// Enrollment challenge issued when `mfa_enforcement` blocks an
        /// un-enrolled login, resolved by POST /login/mfa/enroll (confirm the
        /// provisional secret's first code, then mint the session).
        enrollment,
    };

    struct MfaPending {
        std::string username;
        auth::Role role{auth::Role::user};
        std::chrono::steady_clock::time_point expires_at{};
        int attempts{0};
        /// Default is a login challenge. Each endpoint rejects the other's
        /// kind, so an enrollment token can't be replayed at the
        /// login-challenge endpoint or vice versa.
        PendingKind kind{PendingKind::login_challenge};
    };
    static constexpr int kMfaMaxAttemptsPerPending = 5;
    /// Hard cap on the in-memory pending-token map. `reap_mfa_pending_locked`
    /// is an O(n) scan held under `mfa_pending_mu_`, so an unbounded map
    /// turns a distributed /login flood (many IPs, each bypassing the per-IP
    /// login rate-limiter) into an O(n²) lock-contention / CPU DoS that
    /// serialises all logins (Hermes adversarial H-2). At the cap, new
    /// challenges are load-shed with a 503 rather than growing the map.
    /// 50k entries × ~120 s TTL tolerates a very large legitimate burst.
    static constexpr std::size_t kMaxPendingTokens = 50'000;

public:
    /// Lower the pending-token cap for tests (the production default 50k is
    /// impractical to fill in a unit test). Test-only seam — governance
    /// qe-B: the load-shed branch must be exercised.
    void set_mfa_pending_cap_for_test(std::size_t cap) { mfa_pending_cap_ = cap; }

    /// Override the service-scope global-safe allow-list for a test
    /// (`kServiceScopeGlobalSafe` is seeded EMPTY in production, #2298 PR 3 —
    /// see `service_scope_policy.hpp` — so `require_permission`'s
    /// "cleared the allow-list -> admit" wiring has no real-table path to
    /// exercise otherwise). `std::nullopt` reverts to the real, empty,
    /// production table. Test-only seam, same shape as
    /// `set_mfa_pending_cap_for_test` above.
    ///
    /// `PermPair` holds `string_view` fields, stored by value here — a
    /// caller MUST construct entries from string literals or otherwise
    /// program-lifetime storage (every current call site does). A
    /// `std::string` temporary would dangle the moment the constructing
    /// expression ends (PR review, fjarvis — checked no current call site
    /// does this, but the risk is real for a future one).
    void set_service_scope_global_safe_override_for_test(
        std::optional<std::vector<authz::PermPair>> table) {
        service_scope_global_safe_override_for_test_ = std::move(table);
    }

private:
    /// Whether `(securable_type, operation)` clears the service-scope
    /// default-deny gate: the test override if one is set, else the real
    /// `authz::kServiceScopeGlobalSafe` table via
    /// `authz::service_scope_global_safe`. Shared by `require_permission`'s
    /// service branch and its engine-branch belt-and-braces so both consult
    /// the identical decision.
    [[nodiscard]] bool service_scope_admits(std::string_view securable_type,
                                            std::string_view operation) const;

    std::optional<std::vector<authz::PermPair>> service_scope_global_safe_override_for_test_;

    std::size_t mfa_pending_cap_{kMaxPendingTokens};
    mutable std::mutex mfa_pending_mu_;
    std::unordered_map<std::string, MfaPending> mfa_pending_;

    /// Drop every pending row whose deadline has passed. Called under
    /// `mfa_pending_mu_` from each insert/lookup; constant-time on an
    /// empty map and bounded by the configured rate limit.
    void reap_mfa_pending_locked();

    // ── Per-username login serialization (account-lockout race close) ──────
    //
    // Closes the check-then-act lockout race (adversarial C1): without it a
    // synchronized burst of requests for ONE username could all pass the
    // stale `lockout_status` pre-check and all reach `verify_password` before
    // any failure was recorded, so the effective guess budget was the in-flight
    // concurrency rather than `auth_lockout_threshold`. Holding the per-username
    // lock across the pre-check → verify_password → record/clear sequence
    // serializes attempts for that username, so at most `threshold` reach
    // password verification before the lock arms.
    //
    // Striped (fixed array; `hash(username) % N` picks the lock) so there is no
    // per-username allocation or cleanup and memory is bounded. Distinct
    // usernames that collide on a stripe serialize harmlessly and rarely
    // (N=256). Other usernames (different stripes) log in fully in parallel —
    // only an attacker bursting one account is serialized, which is the intended
    // throttle. Scope is single-process; the HA-replica-correct form is a
    // DB-atomic attempt reservation, landing with the auth store's Postgres
    // migration (see docs/security-reviews/account-lockout-2026-06-12.md).
    static constexpr std::size_t kLoginLockStripes = 256;
    std::array<std::mutex, kLoginLockStripes> login_locks_;
    std::mutex& login_lock_for(const std::string& username);
};

} // namespace yuzu::server
