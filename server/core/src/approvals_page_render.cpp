#include "approvals_page_render.hpp"

#include "reserved_definition_id.hpp"
#include "web_utils.hpp" // html_escape, format_relative_time, format_iso_utc, truncate_utf8

#include <cstddef>

namespace yuzu::server::operate_pages {

namespace {

// The visible scope cell is a clipped copy; the full text lives once, in `data-scope`.
constexpr std::size_t kScopeCellBytes = 120;

const char* pill_class(const std::string& status) {
    if (status == "pending")
        return "warn";
    if (status == "approved")
        return "ok";
    if (status == "rejected")
        return "bad";
    return "idle"; // expired, and any status this build does not know
}

void attr(std::string& out, std::string_view name, const std::string& value) {
    out += ' ';
    out += name;
    out += "=\"";
    out += html_escape(value);
    out += '"';
}

void attr_num(std::string& out, std::string_view name, int64_t value) {
    out += ' ';
    out += name;
    out += "=\"";
    out += std::to_string(value);
    out += '"';
}

std::string empty_note(const std::string& filter) {
    if (filter.empty())
        return "No approval requests.";
    if (filter == "pending")
        return "Nothing is waiting for a decision.";
    return "No " + filter + " requests.";
}

void append_row(std::string& out, const ApprovalRowView& r, int64_t now) {
    const std::string age = format_relative_time(r.submitted_at, now);
    const std::string rev_age = r.reviewed_at > 0 ? format_relative_time(r.reviewed_at, now) : "";

    out += R"(<tr class="row" tabindex="0" aria-selected="false")";
    attr(out, "data-id", r.id);
    attr(out, "data-def", r.definition_id);
    attr(out, "data-name", r.name);
    attr(out, "data-by", r.submitted_by);
    attr(out, "data-scope", r.scope_expression);
    attr_num(out, "data-at", r.submitted_at);
    attr(out, "data-age", age);
    attr(out, "data-status", r.status);
    attr(out, "data-rev-by", r.reviewed_by);
    attr_num(out, "data-rev-at", r.reviewed_at);
    attr(out, "data-rev-age", rev_age);
    attr(out, "data-comment", r.review_comment);
    out += r.mine ? R"( data-mine="1")" : R"( data-mine="0")";
    out += r.mcp ? R"( data-mcp="1">)" : R"( data-mcp="0">)";

    // Request: name (+ MCP tag), then the definition id when it adds information.
    out += R"(<td><span class="nm" title=")" + html_escape(r.definition_id) + "\">" +
           html_escape(r.name);
    if (r.mcp)
        out += R"(<span class="tag">MCP</span>)";
    out += "</span>";
    if (r.name != r.definition_id)
        out += R"(<span class="sub mono">)" + html_escape(r.definition_id) + "</span>";
    out += "</td>";

    // Requested by (+ You tag).
    out += R"(<td><span class="clip by" title=")" + html_escape(r.submitted_by) + "\">" +
           html_escape(r.submitted_by) + "</span>";
    if (r.mine)
        out += R"(<span class="tag">You</span>)";
    out += "</td>";

    // Scope: clipped copy, no title (the full text is in data-scope, once).
    if (r.scope_expression.empty())
        out += R"(<td><span class="faint">&mdash;</span></td>)";
    else
        out += R"(<td><code class="clip scope">)" +
               html_escape(truncate_utf8(r.scope_expression, kScopeCellBytes)) + "</code></td>";

    out += R"(<td class="tm" title=")" + html_escape(format_iso_utc(r.submitted_at)) + "\">" +
           html_escape(age) + "</td>";

    out += std::string(R"(<td><span class="pill )") + pill_class(r.status) + "\">" +
           html_escape(r.status) + "</span>";
    if (!r.reviewed_by.empty())
        out += R"(<span class="sub">by )" + html_escape(r.reviewed_by) + "</span>";
    out += "</td></tr>";
}

} // namespace

std::string approval_display_name(const std::string& definition_id, NameLookupMemo& names) {
    if (is_reserved_definition_id(definition_id))
        return definition_id.substr(kMcpDefinitionPrefix.size());
    return names.label(definition_id);
}

std::string render_approvals_page(const ApprovalListView& v) {
    int pending = 0;
    for (const auto& r : v.rows)
        if (r.status == "pending")
            ++pending;
    // A truncated list that can hold pending rows only gives a lower bound on them.
    const bool lower_bound =
        v.truncated && (v.status_filter.empty() || v.status_filter == "pending");
    std::string pending_attr = std::to_string(pending);
    if (lower_bound)
        pending_attr += '+';

    std::string out;
    out.reserve(256 + v.rows.size() * 900);
    out += std::string(R"(<div class="ops-list" data-state=")") + (v.rows.empty() ? "empty" : "ok") +
           R"(" data-count=")" + std::to_string(v.rows.size()) + R"(" data-pending=")" +
           pending_attr + R"(" data-truncated=")" + (v.truncated ? "1" : "0") + "\">";

    if (v.rows.empty()) {
        out += R"(<div class="empty-state">)" + html_escape(empty_note(v.status_filter)) +
               "</div></div>";
        return out;
    }

    out += R"(<div class="tw"><table class="ap"><thead><tr><th>Request</th><th>Requested by</th>)"
           R"(<th>Scope</th><th>Requested</th><th>Status</th></tr></thead><tbody>)";
    for (const auto& r : v.rows)
        append_row(out, r, v.now);
    out += "</tbody></table></div>";
    if (v.truncated)
        out += R"(<div class="ops-foot hint">Showing the )" + std::to_string(v.rows.size()) +
               " most recent. Older requests are not listed.</div>";
    out += "</div>";
    return out;
}

} // namespace yuzu::server::operate_pages
