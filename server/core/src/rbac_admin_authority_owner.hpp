#pragma once

/// @file rbac_admin_authority_owner.hpp
/// The single ADR-0012 §3 cross-store query owner for all cross-schema
/// "authenticatable Administrator" logic across `rbac_store` and `auth`. Hosts
/// the A2 last-Administrator guard (`RbacStore::unassign_role` delegates
/// here) and, as of the A1/A2 rebase (Step 2), the A1 RBAC enforcement
/// enable/disable toggle's own cross-schema guard
/// (`RbacStore::set_rbac_enforcement`/`check_caller_authorized_under_current_regime`
/// delegate to `set_enforcement`/`regime_authority` below) — both share ONE
/// copy of `kAuthenticatableAdminGrantsFrom`. Only `RbacStore` constructs it,
/// because only `RbacStore` may apply the local cache generation after a
/// confirmed commit. The fragment that defines "an authenticatable
/// Administrator grant" lives ONLY in rbac_admin_authority_owner.cpp, so every
/// consumer shares one copy. It borrows the pool and issues schema-qualified SQL
/// on ONE lease: bounded acquire, no nested acquire, no external work inside a
/// transaction — `regime_authority`'s own fresh read is the one exception
/// that takes a single lease across two back-to-back autocommit statements
/// rather than a transaction (see the .cpp for why that is a deliberately
/// accepted, already-reviewed residual, not an oversight).
///
/// Lock order (a change that inverts it can deadlock): the `rbac_store.rbac_meta`
/// rbac_enabled row (`set_enforcement` only — `RbacStore::set_rbac_enabled`,
/// the unguarded seed/test primitive, does not take it), then
/// `rbac_store.principal_roles` rows FOR UPDATE OF pr (unassign always;
/// `set_enforcement`'s ENABLE direction only), then one `auth.users` row
/// (unassign only), then the `rbac_meta` write_generation row. A path that
/// holds an `auth.users` row lock and then touches those would invert it.
/// This class never applies the local cache generation: the caller does that
/// only after a confirmed commit.

#include "rbac_store.hpp" // RbacRegimeAuthority

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class RbacStore;

class RbacAdminAuthorityOwner {
public:
    struct UnassignOutcome {
        bool ok{false};
        bool last_admin_reject{false};
        bool removed{false};
        std::optional<std::uint64_t> new_gen;
        std::string err;
    };

    /// Outcome of `set_enforcement`. Carries everything
    /// `RbacStore::set_rbac_enforcement` needs to construct
    /// `RbacEnforcementTransition`/`RbacEnforcementError` (rbac_store.hpp)
    /// without re-deriving anything itself.
    struct EnforcementOutcome {
        enum class RefusalKind {
            kSourceRegime,        ///< caller lacks authority under the regime durably true
                                  ///< RIGHT NOW -> RbacStore maps this to a 403-class error
            kDestinationSurvivor, ///< caller would not remain a durable administrator after
                                  ///< the switch -> RbacStore maps this to a 409-class error
        };
        bool ok{false};      ///< false ONLY on a store-level failure (see `err`) — a
                             ///< business-rule refusal (`refused`) still leaves this
                             ///< true: the transaction ran and rolled back cleanly,
                             ///< it is not a store fault
        bool refused{false}; ///< true iff a business-rule refusal fired; `refusal_kind`/
                             ///< `refusal_message` are meaningful only when this is true
        RefusalKind refusal_kind{RefusalKind::kSourceRegime};
        std::string refusal_message;
        bool changed{false};        ///< false on the idempotent no-op path (no write, no bump)
        bool previous_enabled{false};
        bool enabled{false};
        std::int64_t post_transition_administrators{0};
        /// Present ONLY on a REAL applied transition (`changed == true`) —
        /// absent on the no-op path and on any refusal/failure. Mirrors
        /// `UnassignOutcome::new_gen`'s own optional shape.
        std::optional<std::uint64_t> new_gen;
        std::string err; ///< store-level failure text; empty unless `!ok`
    };

    RbacAdminAuthorityOwner(const RbacAdminAuthorityOwner&) = delete;
    RbacAdminAuthorityOwner& operator=(const RbacAdminAuthorityOwner&) = delete;

    UnassignOutcome unassign_role(const std::string& principal_type,
                                  const std::string& principal_id,
                                  const std::string& role_name) const;

    /// A1: `RbacStore::set_rbac_enforcement`'s entire guarded transition,
    /// moved here (A1/A2 rebase Step 2) so it shares
    /// `kAuthenticatableAdminGrantsFrom` with `unassign_role`'s
    /// last-Administrator guard from ONE definition, never a second copy.
    /// See `RbacStore::set_rbac_enforcement`'s own doc comment
    /// (rbac_store.hpp) for the full behavioural contract this preserves
    /// exactly: the idempotent no-op short-circuit BEFORE either guard
    /// evaluates, the SOURCE-regime check strictly BEFORE the
    /// DESTINATION-survival check on a real transition, and the lock order
    /// documented in this file's header banner above.
    EnforcementOutcome set_enforcement(bool enabled, const std::string& caller_username) const;

    /// A1 Gate 8 HIGH: `RbacStore::check_caller_authorized_under_current_regime`'s
    /// entire body, moved here (A1/A2 rebase Step 2). A fresh, lock-free
    /// two-statement read (NOT one transaction/snapshot — see the .cpp for
    /// why that residual is deliberately accepted, not an oversight) of the
    /// durable `rbac_enabled` flag, then a membership check against
    /// whichever authority set that regime requires.
    [[nodiscard]] RbacRegimeAuthority regime_authority(const std::string& caller_username) const;

private:
    friend class RbacStore;
    explicit RbacAdminAuthorityOwner(pg::PgPool& pool) : pool_(pool) {}

    pg::PgPool& pool_;
};

} // namespace yuzu::server
