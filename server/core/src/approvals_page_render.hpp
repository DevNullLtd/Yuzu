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
///
/// A BOUND ticket (#6062: `request_json` non-empty) also carries `data-request`, a
/// plain-text rendering of what the reviewer is approving (definition name + hash,
/// targets, parameters, any other field), built by `summarize_bound_request` and escaped
/// like every other attribute, and `data-digest`, the frozen SHA-256. The raw JSON is
/// never emitted. `data-excluded="1"` marks a row the viewing session may not approve
/// because it is NAMED in the ticket's excluded roots (an unreadable list names nobody; that
/// row is `unapprovable`, below).
/// A bound row whose stored request cannot be read or bounded (`bound_request_is_readable`)
/// carries `data-unreadable="1"` and a `data-request` that is the fixed "do not approve"
/// notice; the controller offers Reject only.

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
    /// The frozen request (#6062), raw JSON text as stored; EMPTY for an unbound ticket.
    /// Only `summarize_bound_request` ever reads it, and nothing emits it verbatim.
    std::string request_json;
    std::string request_digest; ///< lowercase hex SHA-256 of `request_json`; empty if unbound
    /// The viewing session may not approve this row: it is named in the ticket's excluded
    /// roots (the server refuses the approval either way).
    bool excluded{false};
    /// The stored state is one the store refuses to approve whoever asks (an unreadable or
    /// unverifiable request, unreadable excluded roots): the controller offers Reject only.
    /// Emitted as `data-unreadable="1"`, alongside the same flag derived from the request.
    bool unapprovable{false};
};

/// Plain-text rendering of a bound ticket's frozen request, for the detail panel and the
/// decision dialog. Pure; parses defensively and never throws.
///
/// Shape, one fact per line:
///   Definition: <name>
///   Hash: <hash>
///   Targets (<n>):                    (an array: one value per line, indented)
///     <value>
///   Targets: <expression>             (or a single scope-expression string)
///   Parameters:
///     <key>: <value>
///   Other fields:
///     <key>: <value>
///   Digest: sha256:<hex>
/// `definition` ({name, hash}), `targets` and `params` are the recognised keys; every OTHER
/// top-level key is listed under "Other fields", and every other key inside `definition`
/// under "Definition fields", so no KEY the ticket binds is hidden from the reviewer (a
/// long VALUE is cut, and the summary says so). DISPLAY-SAFE by construction: every string
/// and key is shown JSON-escaped and ASCII-only (a newline prints as `\n`; U+202E, U+2028,
/// U+2066 and every other non-ASCII character print as `\uXXXX`), and each value sits on a
/// line that starts with a fixed label, so a value can neither start a line of its own (a
/// second "Definition:" or "Digest:") nor reorder the text around it. Output is bounded (per
/// value, per section, total); when anything is cut the text says so on a "Shortened:" line
/// before the digest. A request that is not a JSON object yields a fixed "could not be read,
/// do not approve" notice. The summary is for ORIENTATION: the Digest line, over the exact
/// stored bytes, is what identifies the request.
[[nodiscard]] std::string summarize_bound_request(const std::string& request_json,
                                                  const std::string& request_digest);

/// `summarize_bound_request` plus whether the summary was CUT (a value over 512 bytes, a
/// list or section over 40 entries, or the 6000-byte total) and whether the request was
/// readable at all. When `shortened`, the text itself carries a "Shortened:" line above
/// the digest, and the row carries `data-shortened="1"` so the decision dialog does not
/// claim the reviewer saw the whole effect.
struct BoundRequestSummary {
    std::string text;
    bool shortened{false};
    bool readable{false};
};
[[nodiscard]] BoundRequestSummary summarize_bound_request_detail(const std::string& request_json,
                                                                 const std::string& request_digest);

struct ApprovalListView {
    std::vector<ApprovalRowView> rows; ///< newest first, as the store returned them
    bool truncated{false};             ///< the store's list cap dropped older rows
    std::string status_filter;         ///< "" = every status
    int64_t now{0};                    ///< epoch seconds, for the relative ages
    bool can_decide{false};            ///< caller holds Approval:Approve (a render hint, not a gate)
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
