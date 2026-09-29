#pragma once

#include <string_view>

/// @file legacy_self_service_allow.hpp
/// The ONE place the legacy (RBAC-off) self-service allowlist is decided
/// (#2963).
///
/// THE DEFECT: RBAC ships OFF by default, and with RBAC off
/// `AuthRoutes::require_permission` / `require_scoped_permission` fall
/// through to the legacy branch, which denies every non-`Read` operation to
/// a non-admin caller. `ApiToken:Rotate` was introduced so a token OWNER
/// could rotate their own credential — self-service credential hygiene —
/// but composed with the legacy admin-only rule it was reachable by nobody
/// except an admin in the shipped default configuration, which is not the
/// population the feature was built for (#2963).
///
/// THE RULE: a (securable, operation) pair on this list is treated like
/// `Read` in the legacy branch ONLY — i.e. it does not by itself require an
/// admin role. This is SAFE ONLY because this gate decides "may attempt",
/// never "may act on resource X": every pair here has its OWN independent,
/// unconditional ownership check downstream in the store the route calls
/// into (for `ApiToken:Rotate`, `ApiTokenStore::rotate_token`/
/// `confirm_token_rotation` refuse any `requesting_user` other than the
/// resolved row's own `principal_id` — no admin override), so admitting a
/// non-admin caller past THIS gate grants them nothing beyond their own
/// resource.
///
/// A pair belongs here iff ALL of:
///   (a) the operation is inherently self-targeted — the caller can only
///       ever act on their OWN principal's own resource, never another's;
///   (b) the backing store enforces that ownership unconditionally, with no
///       admin/service-account override, on every call path that can reach
///       it;
///   (c) admitting a non-admin caller here grants no new AUTHORITY beyond
///       what they already hold over their own resource (rotation, for
///       example, can never mint a credential broader than the one being
///       rotated — see api_token_store.cpp's authority-inheritance guard);
///       and
///   (d) the operation carries no separate, non-authority IMPACT that would
///       justify gating it regardless — irreversibility, availability loss
///       to a third party, or a compliance/audit-evidence requirement.
///       (c) is about AUTHORITY; (d) is about everything else a self-targeted
///       operation could still do damage with. `ApiToken:Rotate` clears (d)
///       because it is explicitly non-destructive (the predecessor survives
///       the overlap window; the sweep, not this gate, is what eventually
///       revokes it) — a hypothetical future `ApiToken:Delete` entry would
///       satisfy (a)-(c) identically but must be independently re-argued
///       against (d), since deleting a token one currently lacks the secret
///       for is irreversible and can break a dependent automation with no
///       audit trail pointing back to why.
///
/// This mirrors `DELETE /api/v1/sessions/me`, which does not go through
/// `require_permission` at all for the identical reason (self-service,
/// ownership-enforced, recoverable) — `ApiToken:Rotate` could not take that
/// same "skip the gate entirely" shape because the RBAC-ON path needs its
/// OWN dedicated `ApiToken:Rotate` grant to stay meaningful (a non-admin
/// role must be explicitly granted it there); this allowlist applies ONLY
/// inside the legacy RBAC-OFF branch, strictly below the live-RBAC check,
/// and never overrides a live RBAC grant or denial.
///
/// EXTEND this set, never fork it — same discipline as
/// `authz_topology_floor.hpp`'s `kTopologyFloor` (which floors the OPPOSITE
/// direction: pairs that must stay admin-only regardless of the toggle).
/// The two lists are deliberately separate: one narrows the legacy
/// fallback, this one widens a single self-targeted exception within it.
namespace yuzu::server {

/// One (securable, operation) pair in the legacy self-service allowlist.
struct LegacySelfServiceEntry {
    std::string_view securable;
    std::string_view operation;
};

/// The legacy self-service allowlist. `ApiToken:Rotate` covers both the
/// rotate and confirm REST routes and their MCP twins (`rotate_api_token`/
/// `confirm_api_token_rotation`), which share this one `(securable,
/// operation)` pair (mcp_server.cpp's tool-to-permission map).
inline constexpr LegacySelfServiceEntry kLegacySelfServiceAllow[] = {
    {"ApiToken", "Rotate"},
};

/// True when `(securable, operation)` is on the legacy self-service
/// allowlist, i.e. the legacy RBAC-off fallback must NOT require an admin
/// role for it (ownership is enforced downstream instead).
[[nodiscard]] inline bool legacy_self_service_allow(std::string_view securable,
                                                     std::string_view operation) noexcept {
    for (const auto& entry : kLegacySelfServiceAllow) {
        if (entry.securable == securable && entry.operation == operation)
            return true;
    }
    return false;
}

} // namespace yuzu::server
