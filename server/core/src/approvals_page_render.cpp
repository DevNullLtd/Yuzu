#include "approvals_page_render.hpp"

#include "reserved_definition_id.hpp"
#include "web_utils.hpp" // html_escape, format_relative_time, format_iso_utc, truncate_utf8

#include <nlohmann/json.hpp>

#include <cstddef>
#include <exception>

namespace yuzu::server::operate_pages {

namespace {

// Bounds on summarize_bound_request. The stored request is already capped at 16 KiB, so
// these exist to keep the rendered text (and the 100-row fragment that carries it in
// data-request) small and a hostile value from dominating the reviewer's screen.
constexpr std::size_t kSummaryValueBytes = 512;
constexpr std::size_t kSummaryMaxEntries = 40; // per section
constexpr std::size_t kSummaryTotalBytes = 6000;

// A JSON string/number/etc as a reviewer reads it. Strings lose the surrounding quotes
// but KEEP their escapes (`\n`, `\"`, `\u0007`): the output is therefore single-line per
// value and a value cannot start a new "Definition:" line of its own. Non-strings print as
// compact JSON. Invalid UTF-8 cannot occur (the document parsed), but replace anyway so
// dump() never throws.
std::string value_text(const nlohmann::json& v) {
    std::string d = v.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (v.is_string() && d.size() >= 2)
        d = d.substr(1, d.size() - 2);
    return truncate_utf8(d, kSummaryValueBytes);
}

void append_entries(std::string& out, const nlohmann::json& obj, const char* heading,
                    const char* skip_a, const char* skip_b, const char* skip_c) {
    std::size_t shown = 0;
    std::size_t total = 0;
    std::string body;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if ((skip_a && it.key() == skip_a) || (skip_b && it.key() == skip_b) ||
            (skip_c && it.key() == skip_c))
            continue;
        ++total;
        if (shown >= kSummaryMaxEntries)
            continue;
        ++shown;
        body += "  " + value_text(nlohmann::json(it.key())) + ": " + value_text(it.value()) + "\n";
    }
    if (total == 0)
        return;
    out += heading;
    out += '\n';
    out += body;
    if (total > shown)
        out += "  ... and " + std::to_string(total - shown) + " more\n";
}

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
    // Bound ticket (#6062): the reviewer reads the frozen request, not a bare digest.
    // Both go through attr() = html_escape; the raw JSON never reaches the markup.
    if (!r.request_json.empty()) {
        attr(out, "data-request", summarize_bound_request(r.request_json, r.request_digest));
        attr(out, "data-digest", r.request_digest);
    }
    out += r.excluded ? R"( data-excluded="1")" : R"( data-excluded="0")";
    out += r.mine ? R"( data-mine="1")" : R"( data-mine="0")";
    out += r.mcp ? R"( data-mcp="1">)" : R"( data-mcp="0">)";

    // Request: name (+ MCP tag), then the definition id when it adds information.
    out += R"(<td><span class="nm" title=")" + html_escape(r.definition_id) + "\">" +
           html_escape(r.name);
    if (r.mcp)
        out += R"(<span class="tag">MCP</span>)";
    if (!r.request_json.empty())
        out += R"(<span class="tag">Bound</span>)";
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
    if (is_mcp_definition_id(definition_id))
        return definition_id.substr(kMcpDefinitionPrefix.size());
    return names.label(definition_id);
}

std::string summarize_bound_request(const std::string& request_json,
                                    const std::string& request_digest) {
    static const std::string kUnreadable =
        "The stored request could not be read. Do not approve this request.";
    const auto doc = nlohmann::json::parse(request_json, nullptr, /*allow_exceptions=*/false);
    if (!doc.is_object())
        return kUnreadable;

    std::string out;
    try {
        // Definition: name + hash, the identity of what will run.
        out += "Definition: ";
        if (const auto d = doc.find("definition"); d != doc.end() && d->is_object()) {
            const auto name = d->find("name");
            const auto hash = d->find("hash");
            out += name != d->end() ? value_text(*name) : "(no name stated)";
            out += " (hash ";
            out += hash != d->end() ? value_text(*hash) : "not stated";
            out += ")";
        } else if (d != doc.end()) {
            out += value_text(*d);
        } else {
            out += "(not stated in the request)";
        }
        out += '\n';

        // Targets: an array of values, or one scope-expression string.
        if (const auto t = doc.find("targets"); t != doc.end()) {
            if (t->is_array()) {
                out += "Targets (" + std::to_string(t->size()) + "): ";
                std::size_t n = 0;
                for (const auto& e : *t) {
                    if (n == kSummaryMaxEntries) {
                        out += ", ... and " + std::to_string(t->size() - n) + " more";
                        break;
                    }
                    if (n++ > 0)
                        out += ", ";
                    out += value_text(e);
                }
            } else {
                out += "Targets: " + value_text(*t);
            }
            out += '\n';
        } else {
            out += "Targets: (not stated in the request)\n";
        }

        // Parameters: key/value pairs when an object, else the value as-is.
        if (const auto p = doc.find("params"); p != doc.end()) {
            if (p->is_object() && !p->empty())
                append_entries(out, *p, "Parameters:", nullptr, nullptr, nullptr);
            else if (p->is_object())
                out += "Parameters: none\n";
            else
                out += "Parameters: " + value_text(*p) + "\n";
        } else {
            out += "Parameters: none stated\n";
        }

        // Everything else the ticket binds, so nothing is hidden from the reviewer.
        append_entries(out, doc, "Other fields:", "definition", "targets", "params");
    } catch (const std::exception&) {
        return kUnreadable;
    }

    if (!request_digest.empty())
        out += "Digest: sha256:" + request_digest + "\n";
    return out.size() > kSummaryTotalBytes ? truncate_utf8(out, kSummaryTotalBytes) : out;
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
           pending_attr + R"(" data-truncated=")" + (v.truncated ? "1" : "0") +
           R"(" data-can-decide=")" + (v.can_decide ? "1" : "0") + "\">";

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
