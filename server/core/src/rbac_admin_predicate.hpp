#pragma once

#include <string_view>

#include "rbac_store.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

/// @file rbac_admin_predicate.hpp
/// THE gate for "is this caller allowed to author a fleet-wide RBAC role
/// grant" (A2, `.claude/plans/rbac-industry-leading-DELIVERY-PLAN.md` §2 "A2
/// — Global human role assignment/unassignment").
///
/// WHY THIS EXISTS: granting (or revoking) a role — especially `Administrator`
/// itself — is a stronger security decision than an ordinary permission
/// check. An `Administrator` grant is not merely a `Security:Write`-gated
/// mutation; it is the act of minting NEW standing Administrator authority
/// (or removing the last of it), so `POST/DELETE
/// /api/v1/rbac/roles/{name}/assignments` and their MCP twins are gated on
/// this dedicated predicate INSTEAD OF `perm_fn`/`require_permission`, not in
/// addition to it. A future PR in this same delivery plan (A1's
/// enable/disable toggle, §2 "A1 — Enable/disable toggle") reuses this
/// predicate verbatim — EXTEND it, never fork it, exactly like
/// `authz_topology_floor.hpp`'s own rule.
///
/// THE RULE: a caller passes iff they hold a DURABLE `Administrator`
/// authority right now, re-read fresh from the store rather than trusted
/// from the session's cached view:
///
///   - **RBAC enforcement OFF** (`!rbac_enforcement_in_effect(rbac_store)`):
///     re-read `auth_db->get_user(session.username)` and require
///     `.role == auth::Role::admin`. This is a DURABLE re-read, not
///     `session.role` — a session minted before an admin was demoted must
///     not keep authoring role grants for the lifetime of that session.
///   - **RBAC enforcement ON** (enabled, OR degraded — see
///     `rbac_enforcement_in_effect`'s own fail-closed doc comment):
///     require a `principal_roles` row for
///     `(principal_type="user", principal_id=session.username,
///     role_name="Administrator")`, via `get_principal_roles_checked`. The
///     enabled-vs-degraded distinction (`RbacEnforcementLabel`,
///     `rbac_store.hpp`) matters for the "row absent" outcome specifically:
///     genuinely enabled + absent is a confirmed `kDenied`; degraded + absent
///     is `kUnavailable` (we could not confirm either way), never collapsed
///     into the same terminal denial — see below.
///
/// Four decisions this predicate makes explicit, each deliberate and
/// documented HERE rather than left implicit at a call site:
///
/// 1. **JIT elevation does NOT satisfy this predicate.** `auth::is_elevated`/
///    `auth::effective_role` are deliberately NOT consulted — both branches
///    above read a DURABLE role/grant, and an elevated `user`-role session's
///    durable row still reads `role='user'` (off) or carries no
///    `Administrator` `principal_roles` row (on). A time-boxed elevation
///    authorizing a temporary admin action must never be laundered into a
///    standing role grant that outlives the elevation window.
/// 2. **A group-held `Administrator` grant does NOT satisfy this
///    predicate**, even with RBAC on. `get_principal_roles_checked` is
///    called with `principal_type="user"` only — a caller whose only path to
///    `Administrator` is via `group_members` + a `principal_roles(group, …,
///    Administrator)` row is DENIED here. Deliberate A2 scope limit (the
///    delivery plan defers `principal_type=group` assignment entirely); this
///    predicate fails closed on that gap rather than silently admitting it.
/// 3. **Service-scoped tokens and engine sessions are structurally denied**,
///    unconditionally, before any I/O, on BOTH surfaces — the same posture
///    `AuthRoutes::require_admin` already carries (auth_routes.cpp) for
///    every other admin-only route. A service-scoped token's authority
///    ceiling is `ITServiceOwner`-equivalent regardless of what the minting
///    human holds; an engine session can never durably resolve `role=admin`
///    or hold `Administrator` (`RbacStore::validate_assignment` bars it
///    structurally), but denying it here too keeps this predicate fail-closed
///    entirely on its own, without relying on that other chokepoint holding.
///    On the REST surface ONLY, an MCP-tier bearer token of ANY tier
///    (`session.mcp_tier` non-empty) is ALSO structurally denied — mirroring
///    `require_admin`'s posture and the platform's #520 rule ("a REST route
///    hit by an MCP token must not bypass the ticket flow"): REST carries no
///    maker-checker approval machinery, so an MCP-tiered credential reaching
///    it would mint/revoke standing Administrator authority with neither
///    REST's MFA step-up nor MCP's approval ticket. The MCP surface applies
///    NO tier rule here — its own ladder (`tier_allows` gating
///    `Security:Write` to the supervised tier only, `requires_approval`'s
///    ticket flow, and the handler's own pre-existing empty-tier deny, the
///    "#4309" guard) already fully governs tier for that surface; duplicating
///    any of it in this predicate would break the existing #4309 tests. This
///    is decided by the caller-supplied `RbacAdminSurface` parameter (below),
///    which has NO default value BY DESIGN — a compile-time forcing function
///    so every caller, present and future, must explicitly declare which
///    transport it is on. Doomgoose external review, PR #4985 (round-2,
///    CRITICAL/BLOCKING): this predicate previously never consulted
///    `session.mcp_tier` at all, so an MCP bearer token minted at ANY tier
///    (even the least-privileged) for a principal who separately held durable
///    Administrator authority could reach the REST route directly, bypassing
///    both controls — independently adjudicated by an enterprise-architect
///    agent, who also designed this surface-parameterized fix (a blanket
///    non-empty-`mcp_tier` deny inside the predicate was considered and
///    REJECTED: it would make `assign_rbac_role`/`unassign_rbac_role`
///    permanently unreachable, since their own dispatch path deliberately
///    gates a supervised-tier caller through to this SAME predicate after the
///    ticket flow).
/// 4. **Pre-provisioning is a caller decision, not this predicate's.** This
///    file answers only "is the CALLING session an administrator" — whether
///    a role may be ASSIGNED to a target username with no `auth.users` row
///    is a separate question the route/tool handler answers (see the A2
///    route's own doc comment).
///
/// Fail-closed on any I/O uncertainty: a `RbacStore`/`AuthDB` degrade that
/// cannot confirm admin authority returns `kUnavailable` (map to 503,
/// retryable) — never silently downgraded to `kDenied` (403), which would
/// let a transient store hiccup masquerade as a permanent policy denial, and
/// never silently upgraded to `kAdmin`, which would be a privilege-escalation
/// bug on every degrade.
namespace yuzu::server {

/// Which transport is calling `is_rbac_administrator`. NO default value, BY
/// DESIGN (decision 3 above) — a deliberate compile-time forcing function so
/// every caller, present and future, must explicitly declare which transport
/// it is on. A NEW caller passing `kMcp` from a REST route, or a future
/// change that adds a default argument, reopens the #520 gap the
/// `kRest`-only tier check (below) exists to close.
enum class RbacAdminSurface {
    kRest, ///< The REST v1 route pair. An MCP-tier bearer token of ANY tier
           ///< is structurally denied here — REST has no maker-checker
           ///< approval flow to fall back on.
    kMcp,  ///< The `assign_rbac_role`/`unassign_rbac_role` MCP tools. NO tier
           ///< rule is applied here — the MCP transport's own ladder
           ///< (`tier_allows`, `requires_approval`'s ticket flow, the
           ///< handler's own #4309 empty-tier deny) already fully governs
           ///< tier for this surface.
};

/// Outcome of `is_rbac_administrator`. Mirrors the shape of
/// `EngineLookupStatus` (`engine_principal_store.hpp`) — a terminal ALLOW, a
/// terminal DENY, and a retryable "could not confirm either way" — rather
/// than collapsing "not admin" and "can't tell" into one boolean.
enum class RbacAdminGate {
    kAdmin,       ///< Confirmed durable Administrator authority. Proceed.
    kDenied,      ///< Confirmed NOT administrator (or structurally excluded
                  ///< — service-scoped token, engine session, or an
                  ///< MCP-tier token presented to the REST surface). Terminal,
                  ///< 403-class.
    kUnavailable, ///< Could not confirm — a required store is null, closed,
                  ///< or a read degraded. Retryable, 503-class. NEVER treat
                  ///< this as either `kAdmin` or `kDenied`.
};

/// Evaluate the RBAC-administrator gate for `session` on the given `surface`.
/// See the file header for the full rule and its four deliberate scope
/// decisions. `rbac_store` and `auth_db` are read-only from this function's
/// perspective (no mutation); both are required — a null pointer for the
/// store the active branch needs is `kUnavailable`, never treated as "assume
/// the other branch".
[[nodiscard]] inline RbacAdminGate is_rbac_administrator(const auth::Session& session,
                                                          AuthDB* auth_db,
                                                          const RbacStore* rbac_store,
                                                          RbacAdminSurface surface) {
    // Structural exclusions first — no I/O, fail-closed, matches
    // AuthRoutes::require_admin's posture for every other admin-only route
    // (decision 3 above) — on BOTH surfaces for engine/service-scope, and
    // ADDITIONALLY on the REST surface for any non-empty mcp_tier (Doomgoose
    // external review, PR #4985 round-2, CRITICAL/BLOCKING — #520).
    if (session.is_engine())
        return RbacAdminGate::kDenied;
    if (!session.token_scope_service.empty())
        return RbacAdminGate::kDenied;
    if (surface == RbacAdminSurface::kRest && !session.mcp_tier.empty())
        return RbacAdminGate::kDenied;

    // Both branches below need to know whether RBAC enforcement is in
    // effect, which itself needs a live `rbac_store` — a null store means
    // we cannot even pick a branch, let alone answer it.
    if (!rbac_store)
        return RbacAdminGate::kUnavailable;

    const RbacEnforcementLabel enforcement = rbac_enforcement_label(rbac_store);
    if (enforcement != RbacEnforcementLabel::kDisabled) {
        auto rows = rbac_store->get_principal_roles_checked("user", session.username);
        if (!rows.has_value())
            return RbacAdminGate::kUnavailable;
        for (const auto& pr : *rows) {
            if (pr.role_name == "Administrator")
                return RbacAdminGate::kAdmin;
        }
        // Doomgoose external review, PR #4985 (IMPORTANT #2): a genuinely
        // absent Administrator row is a confirmed kDenied only when
        // enforcement is GENUINELY enabled. When this branch was reached
        // only because the enabled-flag cache view is DEGRADED
        // (`rbac_enforcement_in_effect`'s own conservative "treat as
        // enabled" fallback — see its #2703 comment), a missing row means
        // "we could not confirm either way", not "confirmed not admin" — map
        // it to kUnavailable so a transient store hiccup can never
        // masquerade as a permanent policy denial (this file's own header
        // invariant, above).
        return enforcement == RbacEnforcementLabel::kDegraded ? RbacAdminGate::kUnavailable
                                                               : RbacAdminGate::kDenied;
    }

    // RBAC-off branch: durable re-read from AuthDB (decision 1 — never the
    // session's own cached role/elevation state).
    if (!auth_db)
        return RbacAdminGate::kUnavailable;
    auto user = auth_db->get_user(session.username);
    if (!user.has_value()) {
        if (is_store_unavailable(user.error()))
            return RbacAdminGate::kUnavailable;
        // UserNotFound / InvalidUsername / etc — a definitive "this session's
        // principal has no durable admin row", not a store problem.
        return RbacAdminGate::kDenied;
    }
    return user->role == auth::Role::admin ? RbacAdminGate::kAdmin : RbacAdminGate::kDenied;
}

/// True when `target_principal` names the CURRENTLY authenticated caller's
/// own stable principal (`session.username`) — the self-target-destruction
/// comparison used at `settings_routes.cpp`'s self-delete
/// (`user.delete`/#397) and self-role-change (`user.role_change`/#403)
/// guards, lifted here per those guards' own doc comment: a third call site
/// (A2's unassign-own-Administrator-grant guard) is exactly the trigger
/// named there. EXTEND this, never fork a second copy of the comparison.
///
/// An EMPTY `session.username` fails closed to `true` (self) — the same
/// defense-in-depth both existing call sites already comment on
/// individually: an unstamped/misconfigured session must never let a bare
/// `"" == ""` comparison read as "not self" and admit a destructive
/// self-target mutation. Both existing call sites already refuse an empty
/// `session.username` with a 500 before ever reaching this comparison, so in
/// practice this fail-closed branch is defense-in-depth, not the primary
/// guard.
[[nodiscard]] inline bool is_self_target(const auth::Session& session,
                                         std::string_view target_principal) {
    if (session.username.empty())
        return true;
    return session.username == target_principal;
}

/// The A2 assign routes' `target_provisioned` answer, as a THREE-state
/// string ("true" / "false" / "unknown") rather than the two-state bool the
/// naive `auth_db->get_user(id).has_value()` collapses to (governance
/// SHOULD #4): a genuine "no such user" (`AuthDBError::UserNotFound`) and a
/// transient/degraded `AuthDB` read (`is_store_unavailable`, e.g. a
/// pool-acquire timeout) both read `false` from `has_value()` alone — an
/// auditor cannot tell "this really is a pre-provisioned grant" from "we
/// could not check" from that single bit. Returns `"unknown"` for a null
/// `auth_db` too (nothing to ask). Shared by both transports so the
/// three-state rule can't drift between them.
///
/// `"false"` is deliberately NOT further split into "never existed" vs.
/// "exists but deactivated" (governance full-pipeline follow-up round):
/// `AuthDB::get_user`'s query is `WHERE username = $1 AND is_active = TRUE`
/// (auth_db.cpp), so `AuthDBError::UserNotFound` fires for BOTH — a
/// currently-non-authenticatable username reads identically either way,
/// which is the exact fact this field exists to report (can whoever holds
/// this username log in right now). Distinguishing the two is a genuine,
/// separate, MORE suspicious-for-an-auditor case (a grant lands on a
/// username with account-lifecycle history) but answering it would need a
/// SECOND, unscoped query against `auth.users` outside `get_user`'s
/// deliberately-active-only contract (every other caller of `get_user`
/// legitimately wants only a live account) — out of scope for this field;
/// track it separately if it becomes a real requirement.
[[nodiscard]] inline std::string_view target_provisioned_state(AuthDB* auth_db,
                                                                const std::string& principal_id) {
    if (!auth_db)
        return "unknown";
    auto user = auth_db->get_user(principal_id);
    if (user.has_value())
        return "true";
    if (is_store_unavailable(user.error()))
        return "unknown";
    // UserNotFound / InvalidUsername / etc — no currently-active account at
    // this username (never existed OR exists-but-deactivated; see the
    // function doc comment above for why those two are not distinguished
    // here).
    return "false";
}

/// The fixed, shared wording every `is_rbac_administrator` call site uses
/// for its two non-admit outcomes. Doomgoose external review, PR #4985
/// MINOR "duplicated gate-denial classification": these strings (and the
/// kUnavailable/kDenied branching that selects between them) were
/// duplicated verbatim across all 4 REST/MCP assign+unassign call sites —
/// EXTEND this, never fork a second copy, matching
/// `authz_topology_floor.hpp`'s own rule.
inline constexpr std::string_view kRbacAdminGateUnavailableMessage =
    "service unavailable — cannot confirm administrator authority";
inline constexpr std::string_view kRbacAdminGateDeniedMessage = "administrator role required";
inline constexpr std::string_view kRbacAdminGateDeniedAuditReason =
    "caller is not a durable RBAC administrator";
/// Doomgoose external review, PR #4985 IMPORTANT finding #2: the `kUnavailable`
/// outcome was previously invisible to operators — all 4 call sites'
/// `on_unavailable` closures only touched the response, with no log line and
/// no audit row, unlike every sibling degraded-store denial in this codebase
/// (e.g. `AuthRoutes::require_permission`'s engine branch, which audits
/// "engine principal denied: RBAC store unavailable" on the identical
/// store-can't-confirm shape). Shared wording for the audit `detail` field —
/// EXTEND this, never fork a second copy, matching
/// `kRbacAdminGateDeniedAuditReason`'s own rule above.
inline constexpr std::string_view kRbacAdminGateUnavailableAuditReason =
    "RBAC admin gate could not confirm administrator authority — store degraded";

/// Shared control-flow chokepoint for the two non-admit `RbacAdminGate`
/// outcomes. Returns `true` (having already invoked exactly one of
/// `on_unavailable`/`on_denied`) when the caller must deny and `return`
/// immediately; returns `false` — invoking neither callback — only for
/// `RbacAdminGate::kAdmin`, when the caller should proceed. Each callback
/// carries ONLY the transport-specific response/audit mechanics (REST's
/// `httplib::Response` + `detail::a4_error`/`emit_behavioral_audit` vs MCP's
/// JSON-RPC `a4_error`/`audit_fn`, which genuinely differ and are not
/// unified here) — the shared wording above is what each callback should
/// use for its message text, so the two transports can never drift apart on
/// what they tell the caller.
template <typename OnUnavailable, typename OnDenied>
[[nodiscard]] inline bool deny_unless_rbac_administrator(RbacAdminGate gate,
                                                          OnUnavailable&& on_unavailable,
                                                          OnDenied&& on_denied) {
    if (gate == RbacAdminGate::kUnavailable) {
        on_unavailable();
        return true;
    }
    if (gate != RbacAdminGate::kAdmin) {
        on_denied();
        return true;
    }
    return false;
}

} // namespace yuzu::server
