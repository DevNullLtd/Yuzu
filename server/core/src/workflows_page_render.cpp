#include "workflows_page_render.hpp"

#include "web_utils.hpp" // html_escape, format_iso_utc, truncate_utf8

#include <cstddef>

namespace yuzu::server::operate_pages {

namespace {

constexpr std::size_t kDescriptionChars = 90;
constexpr std::size_t kConditionChars = 80;
constexpr std::size_t kScopeChars = 120;

std::string pill(std::string_view cls, std::string_view label) {
    return "<span class=\"pill " + std::string(cls) + "\">" + html_escape(std::string(label)) +
           "</span>";
}

std::string esc(std::string_view s) { return html_escape(std::string(s)); }

std::string plural(int n, std::string_view one, std::string_view many) {
    return std::to_string(n) + " " + std::string(n == 1 ? one : many);
}

// "-" for a missing instant, else the ISO text with the epoch the controller localises.
std::string time_cell(int64_t secs) {
    if (secs <= 0)
        return "<td class=\"tm\">-</td>";
    const std::string iso = esc(format_iso_utc(secs));
    return "<td class=\"tm\" data-epoch-ms=\"" + std::to_string(secs * 1000) + "\" title=\"" + iso +
           "\">" + iso + "</td>";
}

std::string step_subtitle(const WorkflowStepView& s) {
    std::string t = "<span class=\"mono\">" + esc(s.instruction_id) + "</span>";
    if (!s.condition.empty())
        t += " &middot; if " + esc(truncate_utf8(s.condition, kConditionChars));
    if (s.retry_count > 0)
        t += " &middot; up to " + plural(s.retry_count, "retry", "retries") + ", " +
             std::to_string(s.retry_delay_seconds) + " s apart";
    if (!s.foreach_source.empty())
        t += " &middot; for each " + esc(truncate_utf8(s.foreach_source, kConditionChars));
    return t;
}

void append_steps(std::string& out, const WorkflowRowView& w) {
    out += "<div data-steps-for=\"" + esc(w.id) + "\" data-name=\"" + esc(w.name) + "\">";
    if (w.steps.empty()) {
        out += "<div class=\"empty-state\">This workflow has no steps.</div></div>";
        return;
    }
    out += "<ol class=\"ops-steps\">";
    for (const auto& s : w.steps) {
        // The label is the author's own text; the instruction id is the fallback. No
        // instruction-name lookup: that read needs InstructionDefinition:Read, which this
        // page's Workflow:Read gate does not imply.
        const std::string& title = s.label.empty() ? s.instruction_id : s.label;
        const StepPolicy p = step_policy(s.on_failure);
        out += "<li><div class=\"st\"><b class=\"nm\" title=\"" + esc(title) + "\">" +
               std::to_string(s.index + 1) + ". " + esc(title) + "</b><span class=\"sub\">" +
               step_subtitle(s) + "</span></div>" + pill(p.cls, p.label) + "</li>";
    }
    out += "</ol></div>";
}

} // namespace

StepPolicy step_policy(std::string_view on_failure) {
    if (on_failure.empty() || on_failure == "abort")
        return {"idle", "Abort"};
    if (on_failure == "continue")
        return {"idle", "Continue"};
    if (on_failure == "skip_remaining")
        return {"idle", "Skip remaining"};
    return {"idle", std::string(on_failure)};
}

std::string render_workflows_list(const WorkflowListView& v) {
    std::string out;
    out.reserve(256 + v.rows.size() * 900);
    out += std::string("<div class=\"ops-list\" data-state=\"") + (v.rows.empty() ? "empty" : "ok") +
           "\" data-count=\"" + std::to_string(v.rows.size()) + "\" data-truncated=\"" +
           (v.truncated ? "1" : "0") + "\">";
    if (v.rows.empty()) {
        out += "<div class=\"empty-state\">" + esc(kWorkflowsEmptyNote) + "<br>" +
               esc(kWorkflowsEmptyHint) + "</div></div>";
        return out;
    }
    out += "<div class=\"tw\"><table class=\"wf\"><thead><tr><th>Workflow</th><th>Steps</th>"
           "</tr></thead><tbody>";
    for (const auto& w : v.rows) {
        out += "<tr class=\"row\" tabindex=\"0\" aria-selected=\"false\" data-workflow-id=\"" +
               esc(w.id) + "\" data-workflow-name=\"" + esc(w.name) + "\"><td><span class=\"nm\" "
               "title=\"" + esc(w.name) + "\">" + esc(w.name) + "</span>";
        if (!w.description.empty())
            out += "<span class=\"sub\" title=\"" + esc(w.description) + "\">" +
                   esc(truncate_utf8(w.description, kDescriptionChars)) + "</span>";
        out += "</td><td>" + std::to_string(w.steps.size()) + "</td></tr>";
    }
    out += "</tbody></table></div><div class=\"ops-steps-store\" hidden>";
    for (const auto& w : v.rows)
        append_steps(out, w);
    out += "</div>";
    if (v.truncated)
        out += "<div class=\"ops-foot hint\">Showing the first " + std::to_string(v.page_cap) +
               " workflows.</div>";
    out += "</div>";
    return out;
}

std::string cadence_text(std::string_view frequency_type, int interval_minutes) {
    if (frequency_type == "once")
        return "Once";
    if (frequency_type == "interval") {
        if (interval_minutes <= 0)
            return "Repeats on an interval";
        return interval_minutes == 1 ? "Every minute"
                                     : "Every " + std::to_string(interval_minutes) + " minutes";
    }
    if (frequency_type == "daily")
        return "Daily (every 24 hours)";
    if (frequency_type == "weekly")
        return "Weekly (every 7 days)";
    if (frequency_type == "monthly")
        return "Monthly (every 30 days)";
    return std::string(frequency_type);
}

std::string render_schedules_page(const ScheduleListView& v) {
    std::string out;
    out.reserve(256 + v.rows.size() * 700);
    out += std::string("<div class=\"ops-list\" data-state=\"") + (v.rows.empty() ? "empty" : "ok") +
           "\" data-count=\"" + std::to_string(v.rows.size()) + "\" data-truncated=\"" +
           (v.truncated ? "1" : "0") + "\">";
    if (v.truncated)
        out += "<div class=\"note warn\">" + esc(kSchedulesPartialNote) + "</div>";
    if (v.rows.empty()) {
        out += "<div class=\"empty-state\">" + esc(kSchedulesEmptyNote) + "</div></div>";
        return out;
    }
    out += "<div class=\"tw\"><table class=\"sc\"><thead><tr><th>Schedule</th><th>Runs</th>"
           "<th>Next run</th><th>Last run</th><th>Count</th><th>Enabled</th></tr></thead><tbody>";
    for (const auto& s : v.rows) {
        // What a non-owner may learn is the boolean `targeted` and the frequency TYPE: the
        // expression, the interval, the approval flag and the parameters are in no current
        // read that carries a non-owner's schedule, so none is printed for one.
        std::string target;
        if (s.owner && !s.scope_expression.empty())
            target = esc(truncate_utf8(s.scope_expression, kScopeChars));
        else
            target = s.targeted ? "Targeted" : "All devices";
        std::string extra;
        if (s.owner && s.requires_approval)
            extra += " &middot; Approval required";
        if (s.owner && s.parameter_count > 0)
            extra += " &middot; " + plural(s.parameter_count, "parameter", "parameters");

        out += "<tr class=\"row\" data-schedule-id=\"" + esc(s.id) + "\" data-owner=\"" +
               (s.owner ? "1" : "0") + "\"><td><span class=\"nm\" title=\"" + esc(s.name) + "\">" +
               esc(s.name) + "</span><span class=\"sub\"><span class=\"mono\">" +
               esc(s.definition_id) + "</span></span><span class=\"sub\">" + target + extra +
               "</span></td><td>" +
               esc(cadence_text(s.frequency_type, s.owner ? s.interval_minutes : 0)) + "</td>";
        out += time_cell(s.next_execution_at);
        out += time_cell(s.last_executed_at);
        out += "<td>" + std::to_string(s.execution_count) + "</td><td>" +
               (s.enabled ? pill("ok", "Enabled") : pill("idle", "Disabled")) + "</td></tr>";
    }
    out += "</tbody></table></div></div>";
    return out;
}

} // namespace yuzu::server::operate_pages
