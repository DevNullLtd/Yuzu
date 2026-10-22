#include "executions_page_render.hpp"

#include "web_utils.hpp" // html_escape, render_status_sparkbar, format_iso_utc, truncate_utf8

#include <algorithm>
#include <cstddef>
#include <format>

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

bool is_failure(const std::string& s) {
    return s == "failure" || s == "timeout" || s == "rejected";
}

// Wire status -> the DOM/CSS vocabulary shared with the drawer's live-update script.
const char* dom_status(const std::string& s) {
    if (s == "success")
        return "succeeded";
    if (is_failure(s))
        return "failed";
    if (s == "running")
        return "running";
    return "pending";
}

const char* pill_tone(const std::string& s) {
    if (s == "success")
        return "ok";
    if (is_failure(s))
        return "bad";
    if (s == "running")
        return "info";
    return "idle";
}

int64_t duration_ms(const DeviceRow& r) {
    return (r.dispatched_at > 0 && r.completed_at > r.dispatched_at)
               ? (r.completed_at - r.dispatched_at) * 1000
               : 0;
}

std::string fmt_duration(int64_t ms) {
    if (ms < 1000)
        return std::format("{} ms", ms);
    if (ms < 60000)
        return std::format("{:.1f} s", static_cast<double>(ms) / 1000.0);
    return std::format("{}m {}s", ms / 60000, (ms % 60000) / 1000);
}

std::string kpi(const std::string& value, std::string_view label, std::string_view tone = {}) {
    return std::string("<div class=\"ro") + (tone.empty() ? "" : " ") + std::string(tone) +
           "\"><div class=\"v exec-kpi-value\">" + value + "</div><div class=\"l\">" +
           std::string(label) + "</div></div>";
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

std::string render_stats_strip(const StatsStripView& v) {
    auto ro = [](const std::string& value, const char* label, const char* note) {
        return "<div class=\"ro\"><div class=\"v\">" + value + "</div><div class=\"l\">" +
               label + "</div><div class=\"d\">" + note + "</div></div>";
    };
    const auto dur_ms = static_cast<int64_t>(std::max(0.0, v.avg_duration_seconds) * 1000.0);
    // The unit rides in <small>: "41.6 s" / "2m 5s" / "800 ms" share one tone-free shape.
    std::string dur = fmt_duration(dur_ms);
    if (const auto sp = dur.rfind(' '); sp != std::string::npos && dur_ms < 60000)
        dur = dur.substr(0, sp) + "<small> " + dur.substr(sp + 1) + "</small>";
    std::string out = "<section class=\"readout stats\" data-slot=\"stats\" "
                      "aria-label=\"Fleet execution statistics\">";
    out += ro(std::to_string(v.executions_today), "Executions today", "UTC day");
    out += ro(std::to_string(v.total_executions), "Finished, all time",
              "excludes running and pending");
    out += ro(std::format("{:.1f}", v.success_rate_pct) + "<small>%</small>",
              "Device success rate", "all time, per device not per execution");
    out += ro(dur, "Average duration", "finished executions");
    out += "</section>";
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
           (v.confined ? "1" : "0") + "\" data-def-name=\"" + html_escape(e.definition_name) +
           "\" data-by=\"" + html_escape(e.dispatched_by) + "\" data-responded=\"" +
           std::to_string(e.agents_responded) + "\" data-targeted=\"" +
           std::to_string(e.agents_targeted) + "\"";
    if (v.can_cancel >= 0)
        out += std::string(" data-can-cancel=\"") + (v.can_cancel ? "1" : "0") + "\"";
    out += ">";
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
    out += "<div class=\"btns\"><button type=\"button\" class=\"btn danger\" data-act=\"cancel\"";
    if (!live)
        out += " disabled";
    out += ">Cancel execution</button><a class=\"btn\" href=\"/api/v1/executions/" + html_escape(e.id) +
           "/responses?limit=1000\" target=\"_blank\" rel=\"noopener\">Open responses "
           "(JSON)</a><span class=\"hint\">Needs Response:Read.</span></div>";
    out += "</div>";
    return out;
}


std::string render_exec_devices(const ExecDevicesView& v) {
    const std::size_t reported = v.rows.size();
    int succeeded = 0, failed = 0;
    bool any_running = false;
    std::vector<int64_t> durations;
    int64_t max_ms = 0;
    for (const auto& r : v.rows) {
        if (r.status == "success")
            ++succeeded;
        else if (is_failure(r.status))
            ++failed;
        else if (r.status == "running")
            any_running = true;
        if (const int64_t d = duration_ms(r); d > 0) {
            durations.push_back(d);
            max_ms = std::max(max_ms, d);
        }
    }
    // Percentiles are shown only once nothing is running: a partial set would read as final.
    auto pct = [&](double p) -> std::string {
        if (any_running || durations.empty())
            return "&mdash;";
        std::vector<int64_t> sorted = durations;
        std::sort(sorted.begin(), sorted.end());
        auto idx = static_cast<std::size_t>(p * static_cast<double>(sorted.size() - 1));
        return fmt_duration(sorted[std::min(idx, sorted.size() - 1)]);
    };

    const std::string id = html_escape(v.execution_id);
    const std::string total = std::to_string(
        v.targeted ? static_cast<std::size_t>(std::max(0, *v.targeted)) : reported);

    std::string out;
    out.reserve(1024 + reported * 360);
    out += "<div data-slot=\"devices\" data-execution-id=\"" + id + "\">";
    out += "<div class=\"hd\"><h2>Device results</h2><span class=\"sub\">" +
           html_escape(v.definition_name) + "</span><span class=\"end\">"
           "<span class=\"chip\" title=\"Rows exist only for devices that have reported\">" +
           std::to_string(reported) + " reported";
    if (v.targeted && *v.targeted > static_cast<int>(reported))
        out += ", <b>" + std::to_string(*v.targeted - static_cast<int>(reported)) + "</b> not yet";
    out += "</span></span></div>";

    out += "<div class=\"readout kpi\" id=\"exec-kpi-" + id + "\">";
    out += kpi(total, "Total");
    out += kpi(std::to_string(succeeded), "Succeeded", "ok");
    out += kpi(std::to_string(failed), "Failed", failed > 0 ? "bad" : "");
    out += kpi(pct(0.5), "p50 duration");
    out += kpi(pct(0.95), "p95 duration");
    out += "</div>";

    if (v.rows.empty()) {
        out += "<div class=\"empty-state\">No device has reported yet. Rows appear as devices "
               "respond.</div>";
    } else {
        out += "<div class=\"agrid-wrap\"><div class=\"agent-grid\" role=\"list\" "
               "aria-label=\"Device fan-out\" id=\"agent-grid-" + id + "\">";
        if (reported > kDeviceGridBucketThreshold) {
            struct Bucket {
                int ok{0}, bad{0}, run{0}, wait{0};
            } b[10] = {};
            for (std::size_t i = 0; i < reported; ++i) {
                auto& k = b[std::min<std::size_t>(i * 10 / reported, 9)];
                const std::string_view d = dom_status(v.rows[i].status);
                (d == "succeeded" ? k.ok : d == "failed" ? k.bad : d == "running" ? k.run : k.wait)++;
            }
            for (int i = 0; i < 10; ++i) {
                const auto& k = b[i];
                const char* cls = k.bad > 0 ? "failed" : k.run > 0 ? "running"
                                  : k.wait > k.ok ? "pending" : "succeeded";
                const std::string label =
                    std::format("Decile {}: {} succeeded / {} failed / {} running / {} pending",
                                i + 1, k.ok, k.bad, k.run, k.wait);
                out += std::format("<div class=\"agent-cell agent-cell--bucket agent-cell--{}\" "
                                   "role=\"listitem\" title=\"{}\" aria-label=\"{}\">{}</div>",
                                   cls, html_escape(label), html_escape(label),
                                   k.ok + k.bad + k.run + k.wait);
            }
        } else {
            for (const auto& r : v.rows) {
                const std::string label = r.agent_id + " " + r.status;
                out += std::format("<div class=\"agent-cell agent-cell--{}\" role=\"listitem\" "
                                   "title=\"{}\" aria-label=\"{}\" data-agent-id=\"{}\" "
                                   "data-exec-id=\"{}\"></div>",
                                   dom_status(r.status), html_escape(label), html_escape(label),
                                   html_escape(r.agent_id), id);
            }
        }
        out += "</div></div>";

        // Failures first, then running, pending, success; longest first within a class.
        std::vector<const DeviceRow*> sorted;
        sorted.reserve(reported);
        for (const auto& r : v.rows)
            sorted.push_back(&r);
        auto rank = [](const std::string& s) {
            return is_failure(s) ? 0 : s == "running" ? 1 : s == "pending" ? 2 : 3;
        };
        std::stable_sort(sorted.begin(), sorted.end(), [&](const DeviceRow* l, const DeviceRow* r) {
            if (rank(l->status) != rank(r->status))
                return rank(l->status) < rank(r->status);
            return duration_ms(*l) > duration_ms(*r);
        });

        out += "<div class=\"tw\"><table class=\"pa per-agent-table\"><thead><tr><th>Device</th>"
               "<th>Status</th><th class=\"r\">Exit</th><th>Duration</th><th>Error</th></tr></thead>"
               "<tbody>";
        const std::size_t shown = std::min(sorted.size(), kDeviceTableCap);
        for (std::size_t i = 0; i < shown; ++i) {
            const DeviceRow& r = *sorted[i];
            const int64_t ms = duration_ms(r);
            const int w = max_ms > 0 ? static_cast<int>(std::min<int64_t>(100, ms * 100 / max_ms)) : 0;
            const std::string aid = html_escape(r.agent_id);
            out += "<tr id=\"per-agent-row-" + id + "-" + aid + "\" data-exec-id=\"" + id +
                   "\" data-agent-id=\"" + aid + "\"><td><code class=\"clip\" title=\"" + aid +
                   "\">" + aid + "</code></td>";
            out += std::string("<td><span class=\"pill ") + pill_tone(r.status) +
                   " per-agent-status\">" + html_escape(r.status) + "</span></td>";
            out += "<td class=\"r per-agent-exit-code\">" + std::to_string(r.exit_code) + "</td>";
            out += std::string("<td><span class=\"dbar dbar--") + dom_status(r.status) +
                   "\" style=\"width:" + std::to_string(std::max(3, w * 9 / 10)) + "px\"></span>"
                   "<span class=\"dtx\">" +
                   (r.status == "running" ? std::string("running") : fmt_duration(ms)) +
                   "</span></td>";
            out += "<td class=\"er\" title=\"" + html_escape(r.error_detail) + "\">" +
                   html_escape(truncate_utf8(r.error_detail, 120)) + "</td></tr>";
        }
        out += "</tbody></table></div>";
        if (sorted.size() > shown)
            out += "<div class=\"ops-cap-note hint\">Showing " + std::to_string(shown) + " of " +
                   std::to_string(sorted.size()) + " reporting devices, failures first.</div>";
    }

    if (v.responses_state == ResponsesState::kNeedsResponseRead) {
        // #4990: no count either; a count of rows the caller may not read is itself a disclosure.
        out += "<details class=\"resp\"><summary>Responses</summary>"
               "<div class=\"empty-state\">Viewing responses requires the <b>Response:Read</b> "
               "permission.</div></details></div>";
        return out;
    }
    out += "<details class=\"resp\"><summary>Show responses (" +
           std::to_string(v.responses_total) + ")</summary>";
    if (v.responses_state == ResponsesState::kUnavailable) {
        out += "<div class=\"empty-state\">Response store not available.</div>";
    } else if (v.responses_state == ResponsesState::kDegraded) {
        out += "<div class=\"empty-state\"><b>Responses unavailable.</b> The response store could "
               "not be read. This is <b>not</b> &ldquo;no responses&rdquo;; retry shortly.</div>";
    } else if (v.responses.empty()) {
        out += "<div class=\"empty-state\">No responses recorded.</div>";
    } else {
        out += "<div class=\"tw\"><table class=\"pa\"><thead><tr><th>Device</th><th>Time</th>"
               "<th>Status</th><th>Output</th><th>Error</th></tr></thead><tbody>";
        for (const auto& r : v.responses) {
            const int64_t arrived_ms = r.received_ms > 0 ? r.received_ms : r.timestamp * 1000;
            const std::string iso = html_escape(format_iso_utc(r.timestamp));
            out += "<tr><td><code>" + html_escape(r.agent_id) + "</code></td><td data-epoch-ms=\"" +
                   std::to_string(arrived_ms) + "\" title=\"" + iso + "\">" + iso + "</td><td>" +
                   std::to_string(r.status) + "</td><td><details class=\"resp-output\">"
                   "<summary>output</summary><pre>" + html_escape(r.output) + "</pre></details></td>"
                   "<td>" + html_escape(r.error_detail) + "</td></tr>";
        }
        out += "</tbody></table></div>";
        if (v.responses_total > v.responses.size())
            out += "<div class=\"ops-cap-note hint\">Showing " + std::to_string(v.responses.size()) +
                   " of " + std::to_string(v.responses_total) +
                   ". Open responses (JSON) for all of them.</div>";
    }
    out += "</details></div>";
    return out;
}

} // namespace yuzu::server::operate_pages
