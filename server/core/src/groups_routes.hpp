#pragma once

/// @file groups_routes.hpp
/// The Groups and enrolment page (Phase 2 UI).
///
/// Routes (all GET):
///   /groups                       page; 302 /login without a session
///   /static/yuzu-groups.js        the page's client glue
///   /fragments/groups/list        management-group tree      ManagementGroup:Read (perm_fn)
///   /fragments/groups/detail      one group, ?id=            ManagementGroup:Read (perm_fn)
///   /fragments/groups/members     its members, ?id=          ManagementGroup:Read (fleet_read_fn)
///
/// The three fragments are read-only and are gated exactly like their REST twins
/// (`GET /api/v1/management-groups[/{id}]`). The members fragment is gated on `fleet_read_fn`
/// ALONE (admit-then-filter, ADR-0017): rows are narrowed with `authz::in_scope` and neither a
/// count nor any other figure derived from the excluded rows is returned. `perm_fn` is never
/// stacked on it.
///
/// Every fragment handler sets `Cache-Control: no-store` as its first statement, so a gate's
/// 401/403/503 and the 400 for a malformed `id` carry it too. A malformed `id` is a 400 before
/// any gate or read. No fragment writes an audit row (the REST twins write none).
///
/// The page's three enrolment panels re-use the fragments that already exist under
/// `/fragments/settings/{tokens,pending,auto-approve}` (same routes, same `admin_fn_` gate,
/// same mutation routes and audit rows).

#include "authz_gates.hpp"
#include "management_group_store.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstddef>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

namespace groups {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Same shape as `dashboard_api::Deps::PermFn`; on false it has already written the 401/403.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    /// `require_fleet_read` (ADR-0017); on `!admitted` it has already written the 401/403/503.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    /// `list_groups_checked()`: nullopt = the store did not answer.
    using ListGroupsFn = std::function<std::optional<std::vector<ManagementGroup>>()>;
    /// `get_group_checked(id)`: unexpected = the store did not answer, nullopt = no such group.
    using GroupFn = std::function<std::expected<std::optional<ManagementGroup>, std::string>(
        const std::string&)>;
    /// `get_members_checked(id)`: nullopt = the store did not answer.
    using MembersFn =
        std::function<std::optional<std::vector<ManagementGroupMember>>(const std::string&)>;
    /// `count_members_by_group_checked()`: nullopt = the store did not answer.
    using MemberCountsFn =
        std::function<std::optional<std::unordered_map<std::string, std::size_t>>()>;

    // Designated initialisers must follow this order (GCC and MSVC reject a reordered one).
    AuthFn auth_fn;
    PermFn perm_fn;
    FleetReadFn fleet_read_fn;
    ListGroupsFn list_groups_fn;
    GroupFn group_fn;
    MembersFn members_fn;
    MemberCountsFn member_counts_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_groups_routes(HttpRouteSink& sink, Deps deps);

} // namespace groups
} // namespace yuzu::server
