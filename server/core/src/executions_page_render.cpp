#include "executions_page_render.hpp"

#include "web_utils.hpp" // html_escape, render_status_sparkbar, format_iso_utc, truncate_utf8

#include <algorithm>
#include <cstddef>

namespace yuzu::server::operate_pages {

namespace {

constexpr std::size_t kPreviewBytes = 80;
constexpr std::size_t kLineageIdChars = 12;

std::string pill(const ExecState& s) {
    return "<span class=\"pill " + s.cls + "\" title=\"" + html_escape(s.title) + "\">" +
           html_escape(s.label) + "</span>";
}

std::string epoch_cell(int64_t secs) {
    const std::string iso = html_escape(format_iso_utc(secs));
    return "<span data-epoch-ms=\"" + std::to_string(secs * 1000) + "\" title=\"" + iso + "\">" +
           iso + "</span>";
}

void append_row(std::string& out, const ExecRow& e) {
    const ExecState st = derive_state(e.status, e.agents_failure, e.agents_responded);
    const int pending = std::max(0, e.agents_targeted - e.agents_responded);
    const std::string iso = html_escape(format_iso_utc(e.dispatched_at));

    out += "<tr class=\"row\" tabindex=\"0\" aria-selected=\"false\" data-execution-id=\"" +
           html_escape(e.id) + "\" data-execution-status=\"" + html_escape(e.status) +
           "\" data-def=\"" + html_escape(e.definition_id) + "\">";
    out += "<td>" + pill(st) + "</td>";
    out += "<td><span class=\"nm\" title=\"" + html_escape(e.definition_id) + "\">" +
           html_escape(e.definition_name) + "</span><span class=\"sub\" title=\"" +
           html_escape(e.dispatched_by) + "\">" + html_escape(e.dispatched_by) + "</span></td>";
    // No blue "running" segment: the row counters carry no running count.
    out += "<td>" + render_status_sparkbar(e.agents_success, e.agents_failure, 0, pending) +
           "<span class=\"sub\">" + std::to_string(e.agents_responded) + " of " +
           std::to_string(e.agents_targeted) + "</span></td>";

    out += "<td>";
    if (e.agents_failure > 0 && !e.last_error_detail.empty())
        out += "<span class=\"pv\" title=\"" + html_escape(e.last_error_detail) + "\">" +
               html_escape(truncate_utf8(e.last_error_detail, kPreviewBytes)) + "</span>";
    else if (e.status == "pending" && !e.rerun_of.empty())
        out += "<span class=\"sub\">Re-run record. Nothing was sent to devices.</span>";
    out += "</td>";

    out += "<td class=\"tm\" data-epoch-ms=\"" + std::to_string(e.dispatched_at * 1000) +
           "\" title=\"" + iso + "\">" + iso + "</td></tr>";
}

std::string kv(std::string_view label, const std::string& value_html) {
    return "<div><span>" + std::string(label) + "</span><b>" + value_html + "</b></div>";
}

std::string stack(std::string_view label, const std::string& code, bool empty) {
    return "<div class=\"stack\"><span>" + std::string(label) + "</span>" +
           (empty ? std::string("<span class=\"faint\">&mdash;</span>")
                  : "<code class=\"blk\">" + html_escape(code) + "</code>") +
           "</div>";
}

} // namespace

ExecState derive_state(std::string_view status, int agents_failure, int agents_responded) {
    const std::string raw = "status=" + std::string(status);
    if (status == "running")
        return {"info", "Running", "Running, " + raw};
    if (status == "succeeded")
        return {"ok", "Succeeded", "Succeeded, " + raw};
    if (status == "cancelled")
        return {"idle", "Cancelled", "Cancelled, " + raw};
    if (status == "pending")
        return {"warn", "Pending", "Pending, " + raw};
    if (status == "completed") {
        if (agents_failure > 0) {
            const std::string n = std::to_string(agents_failure);
            return {agents_failure == agents_responded ? "bad" : "warn", n + " failed",
                    "Completed, " + n + " failed, " + raw};
        }
        return {"ok", "Completed", "Completed, " + raw};
    }
    return {"idle", std::string(status), raw};
}

std::string render_exec_list(const ExecListView& v) {
    std::string out;
    out.reserve(256 + v.rows.size() * 700);
    out += std::string("<div class=\"ops-list\" data-state=\"") + (v.rows.empty() ? "empty" : "ok") +
           "\" data-count=\"" + std::to_string(v.rows.size()) + "\" data-confined=\"" +
           (v.confined ? "1" : "0") + "\" data-truncated=\"" + (v.truncated ? "1" : "0") + "\">";

    if (v.rows.empty()) {
        // A filter that matches nothing must not claim the fleet has no executions, and a
        // confined caller's empty page does not mean none exist outside their scope.
        const std::string_view note = v.filtered   ? kExecutionsFilteredEmptyNote
                                      : v.confined ? kExecutionsConfinedEmptyNote
                                                   : kExecutionsEmptyNote;
        out += "<div class=\"empty-state\">" + html_escape(std::string(note)) + "</div>";
        if (!v.filtered && !v.confined)
            out += "<div class=\"empty-more\"><a class=\"lnk\" href=\"/instructions\">Dispatch an "
                   "instruction from Instructions</a></div>";
        out += "</div>";
        return out;
    }

    out += "<div class=\"tw\"><table class=\"ex\"><thead><tr><th>Status</th><th>Instruction</th>"
           "<th>Responded</th><th>Result preview</th><th>Started</th></tr></thead><tbody>";
    for (const auto& r : v.rows)
        append_row(out, r);
    out += "</tbody></table></div>";
    if (v.truncated)
        out += "<div class=\"ops-foot hint\">Showing the " + std::to_string(v.rows.size()) +
               " most recent. Older executions are not listed.</div>";
    out += "</div>";
    return out;
}

std::string render_exec_selected(const ExecSelectedView& v) {
    const ExecRow& e = v.row;
    const ExecState st = derive_state(e.status, e.agents_failure, e.agents_responded);
    const bool live = e.status == "running" || e.status == "pending";

    std::string out;
    out.reserve(2048);
    out += "<div data-slot=\"selected\" data-execution-id=\"" + html_escape(e.id) +
           "\" data-execution-status=\"" + html_escape(e.status) + "\" data-confined=\"" +
           (v.confined ? "1" : "0") + "\">";
    out += "<div class=\"hd\"><h2>Selected execution</h2>" + pill(st) + "</div>";
    out += "<div class=\"kvl\">";
    out += "<div class=\"stack\"><span>Instruction</span><b class=\"l\">" +
           html_escape(e.definition_name) + "<small class=\"mono faint\">" +
           html_escape(e.definition_id) + "</small></b></div>";
    out += kv("Started by", "<span class=\"clip\" title=\"" + html_escape(e.dispatched_by) + "\">" +
                                html_escape(e.dispatched_by) + "</span>");
    out += kv("Started", epoch_cell(e.dispatched_at));
    out += kv("Finished", v.completed_at > 0 ? epoch_cell(v.completed_at)
                                             : std::string("&mdash;"));
    out += kv("Devices", std::to_string(e.agents_responded) + " of " +
                             std::to_string(e.agents_targeted) + " responded");
    if (!e.rerun_of.empty())
        out += kv("Re-run of", "<a class=\"lnk mono\" href=\"/executions?id=" +
                                   html_escape(e.rerun_of) + "\">" +
                                   html_escape(e.rerun_of.substr(0, kLineageIdChars)) + "</a>");
    out += stack(v.confined ? "Scope (confined)" : "Scope", v.scope_expression,
                 v.scope_expression.empty());
    out += stack("Parameters", v.parameter_values, v.parameter_values.empty());
    out += kv("Execution id", "<span class=\"mono clip\" title=\"" + html_escape(e.id) + "\">" +
                                  html_escape(e.id) + "</span>");
    out += "</div>";

    if (live) {
        const int pct = e.agents_targeted > 0
                            ? std::clamp(e.agents_responded * 100 / e.agents_targeted, 0, 100)
                            : 0;
        out += "<div class=\"prog\"><div class=\"bar\"><i style=\"width:" + std::to_string(pct) +
               "%\"></i></div><span class=\"hint\">" + std::to_string(pct) +
               "% of targeted devices have responded</span></div>";
    }
    out += "<div class=\"btns\"><a class=\"btn\" href=\"/api/v1/executions/" + html_escape(e.id) +
           "/responses?limit=1000\" target=\"_blank\" rel=\"noopener\">Open responses "
           "(JSON)</a><span class=\"hint\">Needs Response:Read.</span></div>";
    out += "</div>";
    return out;
}

} // namespace yuzu::server::operate_pages
