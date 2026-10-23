#pragma once

/// engine_no_admin_audit.hpp - the ONE implementation of the engine-principal
/// "no admin" auditor, shared by the REST route
/// (GET /api/v1/engine-principals/audit/no-admin, rest_api_v1.cpp) and the MCP
/// tool audit_engine_no_admin (mcp_server.cpp). Extend it here; never grow a
/// second copy in either transport (the two hand-copied bodies it replaced had
/// already drifted).
///
/// Why this check is load-bearing. Assignment (RbacStore::validate_assignment /
/// assign_role) refuses the admin and Administrator role NAMES and every
/// built-in (is_system) role for an engine principal. It does NOT refuse a
/// custom role whose permissions happen to cover the whole grid (maintainer
/// ruling 2026-10-23, #2485: a wildcard custom role is PERMITTED and detected
/// afterwards). This auditor is therefore the only control over that class, so
/// it fails CLOSED: any checked read that cannot be answered aborts the run
/// (read_inputs returns the error) and the route answers 503 with no partial
/// violation list and no `success` audit row. It never certifies `ok:true`
/// over data it could not read.
///
/// What `ok:true` means (and does not). It means "at run time, no engine-held
/// role, and no engine principal's union of roles, allows every
/// (securable, operation) pair of the CURRENT grid". Consequently:
///   - a role granting every pair but one is NOT reported (a deliberately
///     bounded definition; the check is not a least-privilege proof);
///   - the grid is read at run time, so a role that covered the grid before a
///     new securable or operation was seeded stops being reported until it is
///     granted the new pair;
///   - `deny` rows are ignored, so a role with a deny row still counts as
///     covering the grid when every pair also has an allow row. Over-reporting
///     is the safe direction for a detective control;
///   - it is point-in-time and pull-only: nothing runs it on a schedule and
///     nothing alerts on a `wildcard_grant`. Cadence is the operator's, and
///     each run's `engine_principal.audit.no_admin` audit row is the evidence
///     the control operated.
///   - roles a principal inherits through group membership are not followed
///     (an `engine:` id cannot be a managed group member today);
///   - the grants, the roles and the role permissions are three separate reads,
///     not one snapshot: a role granted or edited between them is picked up by
///     the next run (a candidate follow-up is a single REPEATABLE READ pass).
///
/// Principal selection is grant-table-driven (access-review clause 3, never a
/// roster walk): every grant whose principal_id starts with `engine:` counts,
/// WHATEVER its principal_type, so a shadow ('user', 'engine:x') row is caught
/// as well as the ('engine', 'engine:x') rows.
///
/// Pure part (`evaluate`) has no I/O and is unit-tested without Postgres;
/// `read_inputs` is the only function that touches the store.

#include "rbac_store.hpp"
#include "web_utils.hpp" // audit_token (CWE-117 neutralisation of the audit detail)

#include <algorithm>
#include <cstddef>
#include <expected>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server::engine_no_admin_audit {

inline constexpr std::string_view kEnginePrincipalPrefix = "engine:";

/// REST 503 / MCP kInternalError message when a checked read failed.
inline constexpr std::string_view kUnavailableMessage = "rbac resolution unavailable - cannot verify";
/// Fixed `failure` audit detail (never the store's own error text).
inline constexpr std::string_view kFailureAuditDetail = "rbac_resolution_failed";
/// How many `principal_id:reason` tokens the success audit row carries.
inline constexpr std::size_t kAuditSampleMax = 10;
/// Per-token cap on the principal id echoed into the audit detail (the id is
/// stored in full in the row's own target columns elsewhere).
inline constexpr std::size_t kAuditIdMax = 100;

struct Violation {
    std::string principal_id;
    std::string role; ///< role name; empty for a union-only wildcard_grant
    std::string reason; ///< admin_role | system_role | wildcard_grant | orphan_grant
};

/// MCP `include_revoked=false`: the roster read that scopes the report. A
/// principal in `revoked` is narrowed out (that is what the flag asks for). A
/// principal in NEITHER set holds a grant with no roster row at all (a shadow
/// or out-of-band row: principal_roles.principal_id has no foreign key to the
/// roster): it is never dropped, it is evaluated normally AND reported as
/// `orphan_grant`, because a roster-walk that silently omits it is the clause-3
/// regression. The grants are read BEFORE the roster (read_inputs, then the
/// roster read), so a principal created between the two reads has no grant in
/// this run: that gap cannot make an orphan, and a read in the other order
/// could.
struct ActiveScope {
    std::unordered_set<std::string> active;
    std::unordered_set<std::string> revoked;
};

/// Build the scope from roster rows (anything with `principal_id` and
/// `lifecycle_state`). ONLY a state of exactly "revoked" narrows a principal
/// out; any other state, including one this code does not know, is evaluated
/// normally. The narrowing flag exists to skip revoked principals, so an
/// unexpected state must never be a reason to stop auditing a grant.
template <class Roster>
[[nodiscard]] ActiveScope make_active_scope(const Roster& roster) {
    ActiveScope scope;
    for (const auto& p : roster)
        (p.lifecycle_state == "revoked" ? scope.revoked : scope.active).insert(p.principal_id);
    return scope;
}

/// The checked reads, taken as vectors so `evaluate` stays pure.
struct Inputs {
    std::vector<PrincipalRole> grants;       ///< list_all_principal_roles_checked()
    std::vector<RbacRole> roles;             ///< list_roles_checked()
    std::vector<Permission> role_permissions; ///< list_all_role_permissions_checked()
};

/// The three AUTHORITATIVE reads. Any failure (closed store, pool timeout,
/// query error) is returned, never swallowed to an empty vector.
[[nodiscard]] inline std::expected<Inputs, std::string> read_inputs(const RbacStore& store) {
    Inputs in;
    auto grants = store.list_all_principal_roles_checked();
    if (!grants)
        return std::unexpected(grants.error());
    auto roles = store.list_roles_checked();
    if (!roles)
        return std::unexpected(roles.error());
    auto perms = store.list_all_role_permissions_checked();
    if (!perms)
        return std::unexpected(perms.error());
    in.grants = std::move(*grants);
    in.roles = std::move(*roles);
    in.role_permissions = std::move(*perms);
    return in;
}

namespace detail {
[[nodiscard]] inline std::string pair_key(const std::string& securable, const std::string& op) {
    return securable + "\x1f" + op;
}
} // namespace detail

/// Pure evaluation. `securables`/`operations` define the current grid.
/// `scope`, when non-null, narrows the report to ACTIVE principals (MCP
/// `include_revoked=false`); see ActiveScope for how a grant with no roster row
/// is handled. Output is ordered by principal id, then role name (a principal's
/// union-only and `orphan_grant` rows, which carry no role, follow its
/// per-role rows), so two runs over the same state are byte-identical.
[[nodiscard]] inline std::vector<Violation>
evaluate(const Inputs& in, const std::vector<std::string>& securables,
         const std::vector<std::string>& operations,
         const ActiveScope* scope = nullptr) {
    std::vector<Violation> out;

    std::unordered_set<std::string> grid;
    for (const auto& s : securables)
        for (const auto& o : operations)
            grid.insert(detail::pair_key(s, o));

    // role name -> allowed pairs that are in the current grid.
    std::map<std::string, std::unordered_set<std::string>> allow_by_role;
    for (const auto& p : in.role_permissions) {
        if (p.effect != "allow")
            continue;
        auto key = detail::pair_key(p.securable_type, p.operation);
        if (grid.contains(key))
            allow_by_role[p.role_name].insert(std::move(key));
    }
    const auto covers_grid = [&](const std::unordered_set<std::string>& allowed) {
        return !grid.empty() && allowed.size() >= grid.size();
    };

    std::set<std::string> system_roles;
    for (const auto& r : in.roles)
        if (r.is_system)
            system_roles.insert(r.name);

    // principal id -> distinct role names, whatever the grant's principal_type.
    std::set<std::string> orphans; // only populated when `scope` is given
    std::map<std::string, std::set<std::string>> roles_by_principal;
    for (const auto& g : in.grants) {
        if (!std::string_view(g.principal_id).starts_with(kEnginePrincipalPrefix))
            continue;
        if (scope && !scope->active.contains(g.principal_id)) {
            if (scope->revoked.contains(g.principal_id))
                continue; // narrowed out on request: a revoked principal
            orphans.insert(g.principal_id);
        }
        roles_by_principal[g.principal_id].insert(g.role_name);
    }

    for (const auto& [principal_id, role_names] : roles_by_principal) {
        std::unordered_set<std::string> union_allowed;
        bool any_role_covers = false;
        for (const auto& role : role_names) {
            const auto it = allow_by_role.find(role);
            const bool covers = it != allow_by_role.end() && covers_grid(it->second);
            if (it != allow_by_role.end())
                union_allowed.insert(it->second.begin(), it->second.end());
            if (covers)
                any_role_covers = true;

            if (role == "admin" || role == "Administrator") {
                out.push_back({principal_id, role, "admin_role"});
                continue;
            }
            if (system_roles.contains(role)) {
                out.push_back({principal_id, role, "system_role"});
                continue;
            }
            if (covers)
                out.push_back({principal_id, role, "wildcard_grant"});
        }
        // No single role covers the grid but together they do.
        if (!any_role_covers && covers_grid(union_allowed))
            out.push_back({principal_id, "", "wildcard_grant"});
        if (orphans.contains(principal_id))
            out.push_back({principal_id, "", "orphan_grant"});
    }
    return out;
}

/// The longest prefix of `s` that is at most `max_bytes` long and does not end
/// inside a UTF-8 multibyte sequence (a continuation byte is 10xxxxxx).
[[nodiscard]] inline std::string_view utf8_prefix(std::string_view s, std::size_t max_bytes) {
    if (s.size() <= max_bytes)
        return s;
    std::size_t n = max_bytes;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0U) == 0x80U)
        --n;
    return s.substr(0, n);
}

/// Success-row audit detail: `violations=N scope=active|all`, plus up to
/// kAuditSampleMax `principal_id:reason` tokens when N > 0. Every principal id is neutralised
/// with audit_token (CWE-117) after being cut to kAuditIdMax bytes at a UTF-8
/// character boundary (never inside a multibyte sequence); reasons are fixed
/// strings. `scope=active` marks a run narrowed to active principals (MCP
/// include_revoked=false), so a narrowed `violations=0` is distinguishable from
/// a full-population one.
[[nodiscard]] inline std::string audit_detail(const std::vector<Violation>& violations,
                                              bool narrowed_to_active = false) {
    std::string d = "violations=" + std::to_string(violations.size());
    d += narrowed_to_active ? " scope=active" : " scope=all";
    if (violations.empty())
        return d;
    d += " sample=";
    const std::size_t n = std::min(violations.size(), kAuditSampleMax);
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0)
            d += ',';
        d += audit_token(utf8_prefix(violations[i].principal_id, kAuditIdMax)) + ":" + violations[i].reason;
    }
    return d;
}

} // namespace yuzu::server::engine_no_admin_audit
