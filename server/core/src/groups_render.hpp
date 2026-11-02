#pragma once

/// @file groups_render.hpp
/// Pure HTML renderers for the management-group panels of `/groups` (Phase 2 UI): the group
/// tree, the selected group's detail and its member list. No I/O, no logging, no store handles:
/// the route reads the stores and hands a finished value in. Read-only: no renderer emits a
/// mutating control (no hx-post/put/delete, no form, no hx-on).
///
/// Four outcomes stay distinct in every panel:
///   * populated,
///   * genuinely empty (`.empty`),
///   * `Unavailable` - the store did NOT answer: a red box with a Retry, never a table, so a
///     degraded read cannot pass for "no groups" or "0 members",
///   * denied (403) - rendered client-side from the panel's `data-denied` attribute,
/// plus `NotFound` on detail and members (the store answered and no such group exists).
///
/// Every Retry is the page's own `[data-gact=reload][data-target=<panel id>]` button; the panel's
/// `data-src` carries the URL, so a failed Retry is an own load and never a toast.
///
/// Group tree: `group_tree` emits EVERY input group exactly once. A group whose parent is not in
/// the list stays a top-level row; a rootless cycle or a descendant beyond `kTreeDepthCap` is
/// swept in as a top-level row rather than dropped.
///
/// Members: `MembersView` carries only the rows the caller may see and a `scoped` flag. No count
/// of excluded rows exists anywhere in the view, so nothing in the output can disclose one
/// (ADR-0017). The heading count is the number of rows the caller can see.
///
/// Every dynamic value reaches the output through `html_escape` (attributes included) and every
/// id in a URL through `url_query_value`.

#include "fragment_states.hpp"
#include "management_group_types.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace yuzu::server::groups {

using access::NotFound;
using access::Unavailable;

/// Rows drawn per fragment. The reads have no LIMIT; the caps only bound the HTML.
inline constexpr std::size_t kGroupsRenderCap = 500;
inline constexpr std::size_t kMembersRenderCap = 200;
/// Deepest indent level `group_tree` emits; a node at this depth is not descended into.
inline constexpr int kTreeDepthCap = 16;

inline constexpr std::string_view kGroupsDenied = "Your account cannot read management groups.";
inline constexpr std::string_view kGroupsUnavailable =
    "Groups could not be read. This is not an empty list.";
inline constexpr std::string_view kDetailUnavailable = "This group could not be read.";
inline constexpr std::string_view kMembersDenied = "Your account cannot read the members of this group.";
inline constexpr std::string_view kMembersUnavailable =
    "The members of this group could not be read. This is not an empty list.";
inline constexpr std::string_view kSelectGroup = "Select a group to see its details.";
inline constexpr std::string_view kNoSuchGroup = "No such group. It may have been removed.";
inline constexpr std::string_view kDynamicNoMembers =
    "No members yet. Membership of a rule-based group is not kept up to date from its rule; "
    "see the manual for how each kind is filled.";
inline constexpr std::string_view kScopedMembers = "Only members within your scope are shown.";
inline constexpr std::string_view kRuleNote =
    "Shown as stored. Membership is not kept up to date from this rule.";

/// True for a group id the routes accept: 1-64 of `[a-f0-9]`.
[[nodiscard]] bool is_group_id(std::string_view id);

struct TreeRow {
    const ManagementGroup* group; ///< points into the vector handed to `group_tree`
    int depth;
};

/// The whole list in display order (see the header comment for the post-condition).
[[nodiscard]] std::vector<TreeRow> group_tree(const std::vector<ManagementGroup>& groups);

struct GroupList {
    std::vector<ManagementGroup> groups;
    /// Rows per group from ONE aggregate read. A group absent from the map has zero members.
    std::unordered_map<std::string, std::size_t> member_counts;
};

struct GroupDetail {
    ManagementGroup group;
    std::optional<std::string> parent_name; ///< nullopt: no parent, or it could not be resolved
};

struct MembersView {
    std::string group_id;
    std::string membership_type;
    std::vector<ManagementGroupMember> rows; ///< the rows the caller may see; nothing else
    bool scoped = false;                     ///< the caller's visibility was narrowed
};

/// The whole `#grp-list` panel interior (`.hd` + body).
std::string render_group_list(const std::variant<GroupList, Unavailable>& state);

/// The whole `#grp-side` interior: the detail panel plus, for a found group, the `#grp-members`
/// loader shell.
std::string render_group_detail(const std::variant<GroupDetail, NotFound, Unavailable>& state);

/// The whole `#grp-members` panel interior.
std::string render_members(const std::variant<MembersView, NotFound, Unavailable>& state);

/// The `#grp-side` interior before any group is selected.
std::string render_select_group();

} // namespace yuzu::server::groups
