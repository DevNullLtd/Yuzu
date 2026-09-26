#pragma once

/// @file rbac_admin_authority_owner.hpp
/// The single ADR-0012 s3 cross-store query owner for all cross-schema
/// "authenticatable Administrator" logic across `rbac_store` and `auth`. Today it
/// hosts the A2 last-Administrator guard (`RbacStore::unassign_role` delegates
/// here); enforcement-toggle and regime-authority operations are expected to be
/// added to this class later. It borrows the pool and issues schema-qualified SQL
/// on ONE lease: bounded acquire, no nested acquire, no external work inside a
/// transaction.
///
/// Lock order (a change that inverts it can deadlock): the `rbac_store.rbac_meta`
/// rbac_enabled row (toggle only, not used yet), then `rbac_store.principal_roles`
/// rows FOR UPDATE OF pr, then one `auth.users` row (unassign only), then the
/// `rbac_meta` write_generation row. A path that holds an `auth.users` row lock
/// and then touches those would invert it. This class never applies the local
/// cache generation: the caller does that only after a confirmed commit.

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class RbacAdminAuthorityOwner {
public:
    struct UnassignOutcome {
        bool ok{false};
        bool last_admin_reject{false};
        bool removed{false};
        std::optional<std::uint64_t> new_gen;
        std::string err;
    };

    explicit RbacAdminAuthorityOwner(pg::PgPool& pool) : pool_(pool) {}
    RbacAdminAuthorityOwner(const RbacAdminAuthorityOwner&) = delete;
    RbacAdminAuthorityOwner& operator=(const RbacAdminAuthorityOwner&) = delete;

    UnassignOutcome unassign_role(const std::string& principal_type,
                                  const std::string& principal_id,
                                  const std::string& role_name) const;

private:
    pg::PgPool& pool_;
};

} // namespace yuzu::server
