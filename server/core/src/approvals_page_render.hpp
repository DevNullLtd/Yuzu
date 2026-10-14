#pragma once

/// @file approvals_page_render.hpp
/// Pure renderer for the Approvals page's request list (`GET /fragments/approvals?view=page`).
///
/// No store, no clock, no request: the route maps `Approval` rows into `ApprovalRowView`s
/// (resolving names, deciding `mine`/`mcp`) and passes `now` in, so everything here is a
/// string function that unit tests drive with plain values. Every value that reaches the
/// markup goes through `html_escape`.
///
/// Markup contract (O2 extends it, the page controller `yuzu-operate.js` reads it):
///   <div class="ops-list" data-state="ok|empty" data-count="N" data-pending="N|N+"
///        data-truncated="0|1">
///     <div class="tw"><table class="ap">... <tr class="row" data-*> ...</table></div>
///     [<div class="ops-foot hint">Showing the 100 most recent. ...</div>]
///   </div>
/// A row carries the whole request in `data-*` so the page's single detail panel is filled
/// from the selected row with no further request: scope and reviewer comment appear in full
/// ONLY there (`data-scope`, `data-comment`); the visible cell shows a clipped copy.

#include "name_lookup_memo.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::operate_pages {

struct ApprovalRowView {
    std::string id;
    std::string definition_id;
    std::string name; ///< display name: definition name, tool name for `mcp.*`, else the id
    std::string status;
    std::string submitted_by;
    std::string scope_expression;
    std::string reviewed_by;
    std::string review_comment;
    int64_t submitted_at{0};
    int64_t reviewed_at{0};
    bool mine{false}; ///< submitted_by == the viewing session's username
    bool mcp{false};  ///< definition_id is in the reserved `mcp.` namespace
};

struct ApprovalListView {
    std::vector<ApprovalRowView> rows; ///< newest first, as the store returned them
    bool truncated{false};             ///< the store's list cap dropped older rows
    std::string status_filter;         ///< "" = every status
    int64_t now{0};                    ///< epoch seconds, for the relative ages
};

/// Display name of a ticket: the tool name for an `mcp.*` ticket (no definition exists, the
/// resolver is not consulted), else the memoised definition name, else the id.
[[nodiscard]] std::string approval_display_name(const std::string& definition_id,
                                                NameLookupMemo& names);

/// The list fragment (see the contract above). `data-pending` is the number of pending rows
/// shown, suffixed `+` when the list was truncated and the filter can include pending rows
/// (a lower bound: older pending requests may exist).
[[nodiscard]] std::string render_approvals_page(const ApprovalListView& v);

inline constexpr std::string_view kApprovalsDegradedNote =
    "Approval store unavailable, retry shortly. This is not an empty queue.";
inline constexpr std::string_view kApprovalsDeniedNote =
    "You do not have permission to view approvals.";
inline constexpr std::string_view kApprovalsUnknownFilterNote = "Unknown filter.";

} // namespace yuzu::server::operate_pages
